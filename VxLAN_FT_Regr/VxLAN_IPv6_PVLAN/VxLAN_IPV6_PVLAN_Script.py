#!/usr/bin/env python

# Author information
__author__ = 'Nexus India VxLAN DevTest Group'
__copyright__ = 'Copyright (c) 2021, Cisco Systems Inc.'
__contact__ = ['group.jdasgupt@cisco.com']
__credits__ = ['havadhut']
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
from tkinter import messagebox
from unicon.eal.dialogs import Statement, Dialog
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
from lib.verify.verify_nve_triggers import verify_show_nve_peers
from lib.triggers.yang_trigger.gnmi_parser import get_underlay

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
# Increment a prefix of a network
def increment_prefix_network(pref, count):
    size = 1 << (pref.network.max_prefixlen - pref.network.prefixlen)
    pref_lst = []
    for i in range(count):
        pref_lst.append(str((pref.ip+size*i)) + "/" + str(pref.network.prefixlen))
    return pref_lst

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
    log.info("==> Wait for 1min for the MSite Scale traffic to populate")
    time.sleep(60)
    
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
            # Ignorning FAIL status for ExtSrc-TRMv6 TI
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
        # Ignorning FAIL status for ExtSrc-TRMv6 TI
        if str(row['Traffic Item']) == 'ExtSrc-TRMv6':
            if row['Loss %'] != '':
                if int(float(row['Loss %'])) < threshold:
                    TrafficItemTable.add_row([str(row['Traffic Item']), str(row['Loss %']), 'PASS', ''])
                else:
                    TrafficItemTable.add_row([str(row['Traffic Item']), str(row['Loss %']), 'FAIL', 'Status IGNORED'])
        elif row['Loss %'] != '':
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
                if abs(int(float(row['Tx Frame Rate']))-int(float(row['Rx Frame Rate']))) in range(0,1001):
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

    # Start all protocols and wait for 60sec
    # ixNetwork.StartAllProtocols(Arg1='sync')
    # time.sleep(60)
    
    # # Apply traffic, start traffic and wait for 60sec
    # ixNetwork.Traffic.Apply()
    # ixNetwork.Traffic.Start()
    time.sleep(90)

    # Clear stats
    ixNetwork.ClearStats()
    time.sleep(20)
    
    # Get Traffic Item Statistics
    trafficItemStatistics = session.StatViewAssistant('Traffic Item Statistics')
    for row in trafficItemStatistics.Rows:
        # Verify loss percentage for Traffic Items
        # Ignorning FAIL status for ExtSrc-TRMv6 TI
        if str(row['Traffic Item']) == 'ExtSrc-TRMv6':
            if row['Loss %'] != '':
                if int(float(row['Loss %'])) < threshold:
                    TrafficItemTable.add_row([str(row['Traffic Item']), str(row['Loss %']), 'PASS', ''])
                else:
                    TrafficItemTable.add_row([str(row['Traffic Item']), str(row['Loss %']), 'FAIL', 'Status IGNORED'])
        elif row['Loss %'] != '':
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
    
    # log.info(TrafficItemTable.draw())
    
    if 0 in fail_flag:
        section.failed("Traffic verification failed")
    else:
        section.passed("Traffic verification Passed")

def VerifyTrafficForLoss(section, testscript, **kwargs):
    
    session     = testscript.parameters['session']
    ixNetwork   = testscript.parameters['ixNetwork']
    threshold   = testscript.parameters['traffic_threshold']

    TrafficItemTable = texttable.Texttable()
    TrafficItemTable.header(['Traffic Item', 'Loss % Observed\nThreshold - '+str(threshold)+' %', 'Status','Remarks'])
    TrafficItemTable.set_cols_width([40,20,20,50])
    fail_flag = []

    # Start all protocols and wait for 60sec
    # ixNetwork.StartAllProtocols(Arg1='sync')
    # time.sleep(60)
    
    # # Apply traffic, start traffic and wait for 60sec
    # ixNetwork.Traffic.Apply()
    # ixNetwork.Traffic.Start()
    # time.sleep(30)

    # Clear stats
    ixNetwork.ClearStats()
    time.sleep(20)
    
    # Get Traffic Item Statistics
    trafficItemStatistics = session.StatViewAssistant('Traffic Item Statistics')
    for row in trafficItemStatistics.Rows:
        # Verify loss percentage for Traffic Items
        # Ignorning FAIL status for ExtSrc-TRMv6 TI
        if str(row['Traffic Item']) == 'ExtSrc-TRMv6':
            if row['Loss %'] != '':
                if int(float(row['Loss %'])) < threshold:
                    TrafficItemTable.add_row([str(row['Traffic Item']), str(row['Loss %']), 'FAIL', ''])
                    fail_flag.append(0)
                else:
                    TrafficItemTable.add_row([str(row['Traffic Item']), str(row['Loss %']), 'PASS', 'Status IGNORED'])
        elif row['Loss %'] != '':
            if int(float(row['Loss %'])) < threshold:
                TrafficItemTable.add_row([str(row['Traffic Item']), str(row['Loss %']), 'FAIL', ''])
                fail_flag.append(0)
            else:
                TrafficItemTable.add_row([str(row['Traffic Item']), str(row['Loss %']), 'PASS', ''])
                # fail_flag.append(0)
        # Verify loss percentage for BUM Traffic Items
        else:
            if 'BUM' in str(row['Traffic Item']):
                # Remote Site VTEPs
                # Verify Tx Rate*256 = Rx Rate for Traffic Items
                if 'DCI_BUM' in str(row['Traffic Item']):
                    if int(float(row['Tx Frame Rate']))*256 == int(float(row['Rx Frame Rate'])):
                        TrafficItemTable.add_row([str(row['Traffic Item']), str(int(float(row['Tx Frame Rate'])))+'-'+str(int(float(row['Rx Frame Rate']))), 'FAIL', 'Receiving 2560 for 256 Remote Site VTEPs'])
                        fail_flag.append(0)
                    else:
                        TrafficItemTable.add_row([str(row['Traffic Item']), str(int(float(row['Tx Frame Rate'])))+'-'+str(int(float(row['Rx Frame Rate']))), 'PASS', 'Not Receiving 2560 for 256 Remote Site VTEPs'])
                        # fail_flag.append(0)
                # Remote Internal Site VTEPs
                # Verify Tx Rate*116 = Rx Rate for Traffic Items
                elif 'INT_BUM' in str(row['Traffic Item']):
                    if int(float(row['Tx Frame Rate']))*117 == int(float(row['Rx Frame Rate'])):
                        TrafficItemTable.add_row([str(row['Traffic Item']), str(int(float(row['Tx Frame Rate'])))+'-'+str(int(float(row['Rx Frame Rate']))), 'FAIL', 'Receiving 1170 for 116 Internal Remote VTEPs + 1 BGW'])
                        fail_flag.append(0)
                    else:
                        TrafficItemTable.add_row([str(row['Traffic Item']), str(int(float(row['Tx Frame Rate'])))+'-'+str(int(float(row['Rx Frame Rate']))), 'PASS', 'Not Receiving 1170 for 116 Internal Remote VTEPs + 1 BGW'])
                        # fail_flag.append(0)
            # Verify Traffic if Loss % is not available
            else:
                if (int(float(row['Tx Frame Rate']))-int(float(row['Rx Frame Rate']))) in range(0,1001):
                    TrafficItemTable.add_row([str(row['Traffic Item']), str(int(float(row['Tx Frame Rate'])))+'-'+str(int(float(row['Rx Frame Rate']))), 'FAIL', ''])
                    fail_flag.append(0)
                else:
                    TrafficItemTable.add_row([str(row['Traffic Item']), str(int(float(row['Tx Frame Rate'])))+'-'+str(int(float(row['Rx Frame Rate']))), 'PASS', ''])
                    #fail_flag.append(0)
    
    # log.info(TrafficItemTable.draw())
    
    if 0 in fail_flag:
        section.failed("Traffic verification failed")
    else:
        section.passed("Traffic verification Passed")        
        

def StopTraffic(section, testscript, **kwargs):
    # To Stop Ixia traffic and wait for the specified number of seconds.
    session     = testscript.parameters['session']
    ixNetwork   = testscript.parameters['ixNetwork']
    threshold   = testscript.parameters['traffic_threshold']

    TrafficItemTable = texttable.Texttable()
    TrafficItemTable.header(['Traffic Item', 'Loss % Observed\nThreshold - '+str(threshold)+' %', 'Status','Remarks'])
    TrafficItemTable.set_cols_width([40,20,20,50])
    fail_flag = []

    # Clear stats and Stop Traffic
    ixNetwork.ClearStats()
    ixNetwork.Traffic.Stop()
    time.sleep(10)

# Verify Error Logs on devices
def VerifyErrLogs(section, steps, **kwargs):
    """ Verify Error Logs """

    exclude_pattern = section.parameters.get("err_log_check_exclude_pattern")
    # Check for skip pattern
    if exclude_pattern != None or exclude_pattern != '':
        skip_pattern = 'ERROR_VLANS_SUSPENDED|ERROR_VLANS_REMOVED|PIM-3-RESTART_REASON|' + str(exclude_pattern)
    else:
        skip_pattern = 'ERROR_VLANS_SUSPENDED|ERROR_VLANS_REMOVED|PIM-3-RESTART_REASON'

    # Verification for failed logs
    fail_flag = []
    validation_msgs = ''
    error_pattern = 'CRASHED|failed|CPU Hog|malloc|core dump|mts_send|redzone|error'

    # Get the VRF list
    for node in section.parameters['testbed'].find_devices(os=Or('NEXUS|NXOS|nxos')):
        device_error_logs_dump = node.execute("show logg logf | egr ig '"+str(error_pattern)+"' | ex ig '"+str(skip_pattern)+"'")
        validation_msgs += "\n\n\nNode : "+str(node.name)+" :\n================================\n\n"
        if device_error_logs_dump != '':
            device_error_log_lst = device_error_logs_dump.split('\n')
            node.configure("clear logging logfile")
            if len(device_error_log_lst) > 0:
                validation_msgs += "\n\n\nError logs found - count : "+\
                                    str(len(device_error_log_lst))+\
                                    str(device_error_logs_dump)+"\n\n"
                fail_flag.append(0)
        else:
            validation_msgs += '\nNo Error Logs seen\n'
    
    # Status Reporting
    log.info(validation_msgs)
    if 0 in fail_flag:
        section.failed()
    else:
        section.passed()

# Verify Consistency Checker
# def VerifyCC(section, **kwargs):
#     """ Verify Consistency Checker """

#     cc_dut_list = kwargs.get('cc_dut_list', 1)
#     log.info(cc_dut_list)
#     fail_flag = []
#     validation_msgs = ''

#     if cc_dut_list == 1:
#         section.skipped('No devices passed as part of cc_dut_list')
    
#     # Build the parameters per node
#     arg_list = []
#     for node in cc_dut_list:
#         log.info(node)
#         # arg_dict parameters per node
#         cc_args_dict = {
#             'dut'                   : section.parameters['testbed'].devices[node],
#             'fnl_flag'              : '0',
#             'random_vlan'           : '1',
#         }
#         arg_list.append(cc_args_dict)

#     # PCALL verify CC
#     iterr = 0
#     vxlanCC_ParallelCall = pcall(infraVerify.verifyBasicVxLANCC, args_dict=arg_list)
#     for result in vxlanCC_ParallelCall:
#         validation_msgs += "\n\nNode : "+str(section.parameters['testbed'].devices[cc_dut_list[iterr]].name)+\
#                             "\n\nConsistency Check Data : "+\
#                             " :\n==========================\n"
#         fail_flag.append(result['status'])
#         validation_msgs += str(result['logs'])
#         iterr+=1
    
#     # Status Reporting
#     log.info(validation_msgs)
#     if 0 in fail_flag:
#         section.failed()
#     else:
#         section.passed()

# # Perform copy r s
# def doCopyRunToStart(section, **kwargs):
#     for node in section.parameters['testbed'].find_devices(os=Or('NEXUS|NXOS|nxos')):
#         execute_copy_run_to_start(node)

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
                testscript.parameters['traffic_threshold'] = 40
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
            forceTakePortOwnership = False

            # LogLevel: none, info, warning, request, request_response, all
            # testscript.parameters['session'] = session = SessionAssistant(IpAddress=ixia_tcl_server, RestPort=None, UserName='admin', Password='admin', SessionName=None, SessionId=None, ApiKey=None, ClearConfig=True, LogLevel='all', LogFilename='restpy.log')
            testscript.parameters['session'] = session = SessionAssistant(IpAddress=ixia_tcl_server, UserName='administrator', Password='nbv_12345', ClearConfig=True, LogLevel='all', LogFilename='restpy.log')
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

# ###################################################################
# ###                  Tc's              ###
# ###################################################################

class rem_add_vlan(nxtest.Testcase):
    # on sumpin remove and add the vlan configs multiple times
    @aetest.test
    def rem_add_vlan(self, testbed,testscript,device_dut,intf_ch, vlan_num, vlan_num1,vlan_string, myvrf,ip_add, vn_segment, vn_segment1, ipv6_add):
        i = 1
        while(i <= 20):

            for node in device_dut:
                testbed.devices[node].configure('''
                    interface {0}
                        switchport
                        switchport private-vlan host-association {1} {2}
                        no switchport private-vlan host-association {1} {2}
                        no vlan {2}
                        no vlan {1}
                    vlan {1}
                        private-vlan primary
                        private-vlan association {3}
                        vn-segment {6}
                    interface Vlan{1}
                        no shutdown
                        private-vlan mapping {3}
                        vrf member {4}
                        ip address {5}
                        ipv6 address {8}
                        fabric forwarding mode anycast-gateway
                    vlan {2}
                        private-vlan community
                        vn-segment {7}
                    interface {0}
                        switchport
                        switchport mode private-vlan host
                        switchport private-vlan host-association {1} {2}
                        no shutdown
                    '''.format(testbed.devices[node].interfaces[intf_ch].name, vlan_num, vlan_num1,vlan_string, myvrf, ip_add, vn_segment, vn_segment1, ipv6_add))
            i = i + 1
        time.sleep(15)

class change_community_vlan(nxtest.Testcase):
    # on sumpin change the community vlan from 100 to 101 and verify the traffic flow
    @aetest.test
    def change_community_vlan(self, testbed,testscript,device_dut, pri_vlan, sec_vlan, sec_vlan1, intf_ch):
        for node in device_dut:
            testbed.devices[node].configure('''
                interface {3}
                    no switchport private-vlan host-association {0} {1}
                    switchport private-vlan host-association {0} {2} 
                '''.format(pri_vlan, sec_vlan, sec_vlan1, testbed.devices[node].interfaces[intf_ch].name))
            time.sleep(2)

class different_vlan(nxtest.Testcase):
    # on tecate-1 check the traffic flowing by using different vlan
    @aetest.test
    def different_vlan(self, testbed,testscript,device_dut, pri_vlan, pri_vlan1, intf_ch):
        for node in device_dut:
            testbed.devices[node].configure('''
                interface {2}
                    switchport access vlan {0} 
                interface {2}
                    switchport access vlan {1}                 
                '''.format(pri_vlan,pri_vlan1, testbed.devices[node].interfaces[intf_ch].name))
            time.sleep(2)


class flap_nve(nxtest.Testcase):
   #on tecate-1 shut the nve 1 interface and verify the traffic loss and no shut it
    @aetest.test
    def flap_nve(self, testbed,testscript,device_dut,nve,vni1,vni2,vni3,vni4,vni5,vni6,vni7,lpbk):
        for node in device_dut:
            testbed.devices[node].configure('''
                no interface nve {0}
                '''.format(nve,vni1,vni2,vni3,vni4,vni5,vni6,vni7,lpbk))
        for node in device_dut:
            testbed.devices[node].configure('''
                interface nve{0}
                    no shutdown
                    host-reachability protocol bgp
                    source-interface loopback{8}
                    member vni {1}
                      ingress-replication protocol bgp
                    member vni {2}
                      ingress-replication protocol bgp
                    member vni {3}
                      ingress-replication protocol bgp
                    member vni {4}
                      ingress-replication protocol bgp
                    member vni {5}
                      ingress-replication protocol bgp
                    member vni {6}
                      ingress-replication protocol bgp
                    member vni {7} associate-vrf
                '''.format(nve,vni1,vni2,vni3,vni4,vni5,vni6,vni7,lpbk))

class flap_bgp(nxtest.Testcase):
    #on tecate-1 shut the bgp router and verify the traffic loss and no shut it
    @aetest.test
    def flap_bgp(self, testbed,testscript,device_dut,asn):
        for node in device_dut:
            testbed.devices[node].configure('''
                router bgp {0}
                    shutdown
                '''.format(asn))
            testbed.devices[node].configure('''
                router bgp {0}
                    no shutdown
                '''.format(asn))
            time.sleep(2)

class flap_nve_loopback(nxtest.Testcase):
    #on tecate-1 shut the nve 1 on loopbacl 1 interface and verify the traffic loss and no shut it
    @aetest.test
    def flap_nve_loopback(self, testbed,testscript,device_dut,nve,lpbk,vni):
        for node in device_dut:
            testbed.devices[node].configure('''
                interface nve {0}
                    no source-interface loopback{1}
                '''.format(nve,lpbk,vni))
            testbed.devices[node].configure('''
                interface nve{0}
                    no shutdown
                    host-reachability protocol bgp
                    source-interface loopback{1}
                    member vni {2}                
                '''.format(nve,lpbk,vni))
            time.sleep(2)

class flap_port(nxtest.Testcase):
    # on teccate-1 shut the ethernet1/1 port and verify the traffic loss and no shut it
    @aetest.test
    def flap_port(self, testbed,testscript,device_dut, intf_ch):
        for node in device_dut:
            testbed.devices[node].configure('''
                interface {0}
                    shutdown
                '''.format(testbed.devices[node].interfaces[intf_ch].name))
            testbed.devices[node].configure('''
                interface {0}
                    no shutdown                
                '''.format(testbed.devices[node].interfaces[intf_ch].name))
            time.sleep(2)
class pvlan_to_normal_trunk(nxtest.Testcase):
    #converting vlan 10 private vlan to normal vlan on tecate and sumpin
    @aetest.test
    def pvlan_to_normal_trunk(self, testbed,testscript,device_dut, intf_ch, pri_vlan, sec_vlan, vlans):
        for node in device_dut:
            testbed.devices[node].configure('''  
                default int {0}
                interface {0}
                        switchport
                        switchport mode private-vlan host
                        switchport private-vlan host-association {1} {2}
                        spanning-tree port type edge
                        no shutdown
                '''.format(testbed.devices[node].interfaces[intf_ch].name, pri_vlan, sec_vlan, vlans))
            testbed.devices[node].configure('''
                default int {0}
                interface {0}
                 switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk {1} {3}
                    no shutdown
                '''.format(testbed.devices[node].interfaces[intf_ch].name, pri_vlan, sec_vlan, vlans))
            time.sleep(2)
class native_vlan_in_pvlantrunk(nxtest.Testcase):
    @aetest.test
    def native_vlan_in_pvlantrunk(self, testbed,testscript,device_dut, intf_ch, pri_vlan):
        for node in device_dut:
            testbed.devices[node].configure('''  
                default int {0}
                interface {0}
                    switchport
                    switchport mode trunk
                    switchport trunk allowed vlan {1}
                    spanning-tree port type edge trunk
                    no shutdown
                '''.format(testbed.devices[node].interfaces[intf_ch].name, pri_vlan))
            time.sleep(2)
            testbed.devices[node].configure('''
                default int {0}
                interface {0}
                    switchport
                    switchport mode trunk
                    switchport trunk native vlan {1}
                    spanning-tree port type edge trunk
                    no shut
                '''.format(testbed.devices[node].interfaces[intf_ch].name, pri_vlan))
            time.sleep(2)
class pvlan_counters(nxtest.Testcase):
    # on tecate-1 checking the counters and verifying the unicast count of in frames out frames by waitnig for 2 seconds
    @aetest.test
    def pvlan_counters(self, testbed,testscript,device_dut, sec_vlan):
        for node in device_dut:
            testbed.devices[node].configure('''
                clear vlan id {0} counters
                show vlan id {0} counters 
                '''.format(sec_vlan))
            time.sleep(2)
            output = testbed.devices[node].configure("show vlan id {0} counters | i i Packets".format(sec_vlan))
        #unicast_pac = re.search("[A-Z]+[a-z]+[a-z]+[a-z]+[a-z]+[a-z]+[a-z] [A-Z]+[a-z]+[a-z]+[a-z]+[a-z]+[a-z]+[a-z] [A-Z]+[a-z]                 .+[0-9]+[0-9]+[0-9]", output)
            unicast_count = re.search("[0-9]+[0-9]+[0-9]", output)
            fin = unicast_count.group()
            fail_flag = []
            if(fin <= '800'):
                print('passed')
            else:
                fail_flag.append(0)
                print('counters verification is failed') 
class no_feature_private_vlan(nxtest.Testcase):
    # removed the pvlan configs on sumpin switch and verify the traffic loss
    @aetest.test
    def no_feature_private_vlan(self, testbed,testscript,device_dut,interface1,interface2,interface3,vlan,vlan1,vlan2,vlan3,vlan_st,vnseg1,vnseg2):
        for node in device_dut:
            testbed.devices[node].configure('''
                default interface {0}
                default interface {1}
                default interface {2}
                vlan {3}
                    no private-vlan primary
                    no private-vlan association {7}
                vlan {4}
                    no private-vlan community
                    no vn-segment {8}
                vlan {5}
                    no private-vlan community
                    no vn-segment {9}
                vlan {6}
                    no private-vlan isolated    
                no feature private-vlan
                '''.format(testbed.devices[node].interfaces[interface1].name,testbed.devices[node].interfaces[interface2].name,testbed.devices[node].interfaces[interface3].name,vlan,vlan1,vlan2,vlan3,vlan_st,vnseg1,vnseg2))
            time.sleep(15)
class pvlan_on_l3vni(nxtest.Testcase):
    # Configured pvlan on l3 vlan 2000 on tecate-1 and verified the traffic
    @aetest.test
    def pvlan_on_l3vni(self, testbed,testscript,device_dut, pri_vlan, sec_vlan, vnseg, vnseg1):
        for node in device_dut:
            testbed.devices[node].configure('''
                vlan {0}
                    private-vlan primary
                    private-vlan association {1}
                    vn-segment {2}
                vlan {1}
                    private-vlan community
                    vn-segment {3}
                '''.format(pri_vlan, sec_vlan, vnseg, vnseg1))

class no_pvlan_mac_learnt(nxtest.Testcase):
    # shut the private vlan configs on tecate-1 and check the mac address table the mac address table should not have nve pvlan entries
    @aetest.test
    def no_pvlan_mac_learnt(self, testbed,testscript,device_dut, pri_vlan, sec_vlan, vnseg):
        for node in device_dut:
            testbed.devices[node].configure('''
                vlan 10
                    show mac address-table dynamic
                    no private-vlan primary
                '''.format(pri_vlan, sec_vlan, vnseg))
            time.sleep(2)
            testbed.devices[node].configure('''
                vlan {0}
                    show mac address-table dynamic
                    private-vlan primary
                    private-vlan association {1}
                    vn-segment {2}
                '''.format(pri_vlan, sec_vlan, vnseg))
class vni_shut_mac_learnt(nxtest.Testcase):
    # shut the vn-segment on tecate-1 and check the mac address table the mac address table should not have nve addresses
    @aetest.test
    def vni_shut_mac_learnt(self, testbed,testscript,device_dut, pri_vlan, sec_vlan, vnseg):
        for node in device_dut:
            testbed.devices[node].configure('''
                vlan {0}
                    show mac address-table dynamic
                    no vn-segment {2}
                '''.format(pri_vlan, sec_vlan, vnseg))
            time.sleep(2)
            output = testbed.devices[node].configure('show mac address-table dynamic')
            nve_search = re.search('[a-z]+[a-z]+[a-z]', output)
            fin = nve_search.group()
            fail_flag = []
            if (nve_search != 'nve'):
                print('passed')
            else:
                fail_flag.append(0)
                print('nve shut is failed') 
            testbed.devices[node].configure('''
                vlan {0}
                    private-vlan primary
                    private-vlan association {1}
                    vn-segment {2}
                '''.format(pri_vlan, sec_vlan, vnseg))
class clear_learnt_mac(nxtest.Testcase):
    # clear the mac address table on TECATE-1 and verify the cleared mac address
    @aetest.test
    def lear_learnt_mac(self, testbed,testscript,device_dut, pri_vlan,vnseg):
        for node in device_dut:
            testbed.devices[node].configure('''
                show mac address-table dynamic
                clear mac address-table dynamic
                '''.format(pri_vlan, vnseg))
            time.sleep(2)
            testbed.devices[node].configure('''
                vlan {0}
                    show mac address-table dynamic
                    vn-segment {1}
                    show mac address-table dynamic
                '''.format(pri_vlan, vnseg))

class pvlan_to_portchannel(nxtest.Testcase):
    # configured port channel 15 on sumpin ethernet e1/48 and verifying the traffic flow
    @aetest.test
    def pvlan_to_portchannel(self, testbed,testscript,device_dut, intf_ch, pri_vlan, port_ch, vlan):
        for node in device_dut:
            testbed.devices[node].configure('''
                default int {0}
                interface port-channel{2}
                    switchport
                    switchport mode private-vlan host
                    switchport private-vlan host-association {1} {3}
                    spanning-tree port type edge
                    no shutdown                
                default int {0}
                interface {0}
                    no shut
                    channel-group {2} force mode active
                default int {0}
                interface {0} 
                    switchport
                    switchport mode private-vlan host
                    switchport private-vlan host-association {1} {3}
                    spanning-tree port type edge
                    no shutdown               
                '''.format(testbed.devices[node].interfaces[intf_ch].name, pri_vlan, port_ch, vlan))
            time.sleep(2)

class L3_uplink_flap(nxtest.Testcase):
    # removing the private vlan(vlan10) configurations on TECATE-1 and check the traffic loss and configure pvlan again
    @aetest.test
    def L3_uplink_flap(self, testbed,testscript,device_dut, nve, vlan_num, vlan_num1,vlan_string, myvrf,ip_add, vn_segment, loopback):
        for node in device_dut:
            testbed.devices[node].configure('''
                no vlan {1}
                '''.format(nve, vlan_num, vlan_num1,vlan_string, myvrf,ip_add, vn_segment, loopback))
            time.sleep(2)
            testbed.devices[node].configure('''
                interface Vlan {1}
                    no shutdown
                    private-vlan mapping {3}
                    vrf member {4}
                    ip address {5}
                    fabric forwarding mode anycast-gateway
                vlan {1}
                    private-vlan primary
                    private-vlan association {3}
                    vn-segment {6}
                interface nve {0}
                    no shutdown
                    host-reachability protocol bgp
                    source-interface loopback {7}
                '''.format(nve, vlan_num, vlan_num1,vlan_string, myvrf,ip_add, vn_segment, loopback))
            time.sleep(2)

class pvlan_to_normal_vlan_mac_learn(nxtest.Testcase):
    # converting pvlan to normal vlan on the sumpin and checking wheather mac is cleared or not
    @aetest.test
    def L3_uplink_flap(self, testbed,testscript,device_dut,nve,vlan_num,vlan_string,loopback,vni):
        for node in device_dut:
            testbed.devices[node].configure('''
                show mac address-table dynamic
                vlan 10
                    no private-vlan primary
                    show mac address-table dynamic
                '''.format(nve,vlan_num,vlan_string,loopback,vni))
            testbed.devices[node].configure('''
                vlan {1}
                    private-vlan primary
                    private-vlan association {2}
                    vn-segment 30010
                interface nve{0}
                    no shutdown
                    host-reachability protocol bgp
                    source-interface loopback{3}
                    member vni {4}
                        ingress-replication protocol bgp
                '''.format(nve,vlan_num,vlan_string,loopback,vni))
            time.sleep(2)

class normal_vlan_to_pvlan_mac_learn(nxtest.Testcase):
    @aetest.test
    # converting pvlan to normal vlan on the sumpin and checking wheather mac is cleared or not
    def pvlan_to_normal_trunk(self, testbed,testscript,device_dut,intf_ch,vlan_num,vlan_num1,vni,nve,vlan_string):
        for node in device_dut:
            testbed.devices[node].configure('''
                default int e1/48
                interface {0}
                    switchport
                    switchport access vlan {1}
                    spanning-tree port type edge
                    no shutdown
                show mac address-table dynamic
                '''.format(testbed.devices[node].interfaces[intf_ch].name,vlan_num,vlan_num1,vni,nve,vlan_string))
            
            testbed.devices[node].configure('''
                vlan {1}
                    private-vlan primary
                    show mac address-table dynamic 
                    private-vlan association {5}
                    vn-segment {3} 
                interface nve {4}
                    no shutdown
                    host-reachability protocol bgp
                    source-interface loopback1
                    member vni {3}
                        ingress-replication protocol bgp  
                default int {0}
                interface {0}
                        switchport
                        switchport mode private-vlan host
                        switchport private-vlan host-association {1} {2}
                        spanning-tree port type edge
                        no shutdown       
                '''.format(testbed.devices[node].interfaces[intf_ch].name,vlan_num,vlan_num1,vni,nve,vlan_string))

class isolated_community_vica_versa(nxtest.Testcase):
    @aetest.test
    # converting community vlan 100 to isolated vlan 102 on sumpin and vica versa and verify traffic flow
    def isolated_community_vica_versa(self, testbed,testscript,device_dut,intf_ch,vlan_num,vlan_num1,vlan_num2):
        for node in device_dut:
            testbed.devices[node].configure('''
                default int {0}
                interface {0}
                    switchport
                    switchport mode private-vlan host
                    switchport private-vlan host-association {1} {3}
                    spanning-tree port type edge
                    no shutdown            
                '''.format(testbed.devices[node].interfaces[intf_ch].name,vlan_num,vlan_num1,vlan_num2))
            time.sleep(2)
            testbed.devices[node].configure('''
                default int {0}
                interface {0}
                    switchport
                    switchport mode private-vlan host
                    switchport private-vlan host-association {1} {2}
                    spanning-tree port type edge
                    no shutdown
                '''.format(testbed.devices[node].interfaces[intf_ch].name,vlan_num,vlan_num1,vlan_num2))
            time.sleep(2)

class isolated_community_isolated(nxtest.Testcase):
    @aetest.test
    # converting isolated vlan 102 to community vlan 100 and then to isolated on sumpin and vica versa and verify traffic loss
    def isolated_community_isolated(self, testbed,testscript,device_dut,intf_ch,vlan_num,vlan_num1,vlan_num2):
        for node in device_dut:
            testbed.devices[node].configure('''
                default int {0}
                interface {0}
                    switchport
                    switchport mode private-vlan host
                    switchport private-vlan host-association {1} {3}
                    spanning-tree port type edge
                    no shutdown
                '''.format(testbed.devices[node].interfaces[intf_ch].name,vlan_num,vlan_num1,vlan_num2))
            time.sleep(2)
            testbed.devices[node].configure('''
                default int {0}
                interface {0}
                    switchport
                    switchport mode private-vlan host
                    switchport private-vlan host-association {1} {2}
                    spanning-tree port type edge
                    no shutdown
                '''.format(testbed.devices[node].interfaces[intf_ch].name,vlan_num,vlan_num1,vlan_num2))
            time.sleep(2)
            testbed.devices[node].configure('''
                default int {0}
                interface {0}
                    switchport
                    switchport mode private-vlan host
                    switchport private-vlan host-association {1} {3}
                    spanning-tree port type edge
                    no shutdown
                '''.format(testbed.devices[node].interfaces[intf_ch].name,vlan_num,vlan_num1,vlan_num2))              
            testbed.devices[node].configure('''
                default int {0}
                interface {0}
                    switchport
                    switchport mode private-vlan host
                    switchport private-vlan host-association {1} {2}
                    spanning-tree port type edge
                    no shutdown
                '''.format(testbed.devices[node].interfaces[intf_ch].name,vlan_num,vlan_num1,vlan_num2))
            time.sleep(2)
class static_mac(nxtest.Testcase):
    @aetest.test
    # checking the static mac address table for pvlan 10 on tecate-1 and sumpin 
    def static_mac(self, testbed,testscript,device_dut):
        for node in device_dut:
            testbed.devices[node].configure('''
                show mac address-table static   
                ''')  

class pvlan_to_trunkport(nxtest.Testcase):
    @aetest.test
    # checking the trunk port on pvlan port after removing pvlan port 
    def pvlan_to_trunport(self, testbed,testscript,device_dut,intf_ch,vlan_num,vlan_num1):
        for node in device_dut:
            testbed.devices[node].configure('''
                default int {0}
                int {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk {1} {2}
                    no shutdown
                '''.format(testbed.devices[node].interfaces[intf_ch].name,vlan_num,vlan_num1))    

class community_to_promiscous(nxtest.Testcase):
    @aetest.test
    # converting ports from community promiscuous and vica versa on sumpin
    def community_to_promiscous(self, testbed,testscript,device_dut,intf_ch,vlan_num,vlan_num1,vlan_string):
        for node in device_dut:
            testbed.devices[node].configure(''' 
            default int {0}           
            interface {0}
                switchport
                switchport mode private-vlan host
                switchport private-vlan host-association {1} {2}
                spanning-tree port type edge
                no shutdown
            default int {0}
            interface {0}
                switchport
                switchport mode private-vlan promiscuous
                switchport private-vlan mapping {1} {3}
                no shutdown
            default int {0} 
            interface {0}
                switchport
                switchport mode private-vlan host
                switchport private-vlan host-association {1} {2}
                spanning-tree port type edge
                no shutdown
            '''.format(testbed.devices[node].interfaces[intf_ch].name,vlan_num,vlan_num1,vlan_string))

class isolated_to_promiscous(nxtest.Testcase):
    @aetest.test
    # converting ports from isolated to promiscuous and vica versa on sumpin
    def isolated_to_promiscous(self, testbed,testscript,device_dut,intf_ch,vlan_num,vlan_num1,vlan_string):
        for node in device_dut:
            testbed.devices[node].configure(''' 
            default int {0} 
            interface {0}
                switchport
                switchport mode private-vlan host
                switchport private-vlan host-association {1} {2}
                spanning-tree port type edge
                no shutdown
            default int {0} 
            interface {0}
                switchport
                switchport mode private-vlan promiscuous
                switchport private-vlan mapping {1} {3}
                no shutdown
            '''.format(testbed.devices[node].interfaces[intf_ch].name,vlan_num,vlan_num1,vlan_string))

# class mac_move_in_same_pvlan(nxtest.Testcase):
#     # checking mac move between same pvlan on tecate-1 and sumpin
#     def mac_move_in_same_pvlan(self, testbed,testscript,device_dut):
#         for node in device_dut:
#             testbed.devices[node].configure('''
#                 default int e1/1
#                 interface Ethernet1/1
#                     switchport
#                     switchport mode private-vlan host
#                     switchport private-vlan host-association 10 101
#                     spanning-tree port type edge
#                     no shutdown
#                 default int e1/48
#                 interface Ethernet1/48
#                     switchport
#                     switchport mode private-vlan host
#                     switchport private-vlan host-association 10 101
#                     spanning-tree port type edge
#                     no shutdown
#                 ''')
#             output = testbed.devices[node].configure('show mac address-table address 0012.0100.0001')
#             mac_search = re.search('[0-9]+[0-9]', output)
#             fin = mac_search.group()
#             fail_flag = []
#             if (mac_search == '10'):
#                 print('passed')
#             else:
#                 fail_flag.append(0)
#                 print('mac move is failed') 

class native_vlan_on_peomiscuous(nxtest.Testcase):
    #on sumpin e1/48 configuring native vlan and verifying the traffic flow
    @aetest.test
    def native_vlan_on_peomiscuous(self, testbed,testscript,device_dut,intf_ch,vlan_num,vlan_num1,vlan_string):
        for node in device_dut:
            testbed.devices[node].configure('''
                default int {0}
                interface {0}
                    switchport
                    switchport mode private-vlan promiscuous
                    switchport private-vlan mapping {1} {3}
                    no shutdown
                default int {0}
                interface {0}
                    switchport
                    switchport mode trunk
                    switchport trunk native vlan {1}
                    spanning-tree port type edge trunk
                    no shutdown
                '''.format(testbed.devices[node].interfaces[intf_ch].name,vlan_num,vlan_num1,vlan_string))
            
class trunk_and_pvlan_traffic(nxtest.Testcase):
    @aetest.test
    #on sumpin e1/48 configuring trunk vlan and verifying the traffic flow
    def trunk_and_pvlan_traffic(self, testbed,testscript,device_dut,intf_ch,vlan_num,vlan_num1,vlan_string):
        for node in device_dut:
            testbed.devices[node].configure('''
                default int {0}
                int {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk {1} {3}
                    no shutdown
                default int {0}
                interface {0}
                    switchport
                    switchport mode private-vlan promiscuous
                    switchport private-vlan mapping {1} {3}
                    no shutdown
                '''.format(testbed.devices[node].interfaces[intf_ch].name,vlan_num,vlan_num1,vlan_string))

class community_port_to_trunk_promiscuous_port(nxtest.Testcase):
    @aetest.test
    #on sumpin e1/48 configuring trunk promiscuous port and verifying the traffic flow
    def community_port_to_trunk_promiscuous_port(self, testbed,testscript,device_dut,intf_ch,vlan_num,vlan_num1,vlan_string):
        for node in device_dut:
            testbed.devices[node].configure('''
                default int {0}           
                interface {0}
                    switchport
                    switchport mode private-vlan host
                    switchport private-vlan host-association {1} {2}
                    spanning-tree port type edge
                    no shutdown                
                default int {0}
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk {1} {3}
                    no shut
                '''.format(testbed.devices[node].interfaces[intf_ch].name,vlan_num,vlan_num1,vlan_string))

# class mac_move_promiscous_vlan(nxtest.Testcase):
#     @aetest.test
#     #on tecate-1 e1/48 and e1/1 configuring promiscuous port and verifying the mac move
#     def mac_move_promiscous_vlan(self, testbed,testscript,device_dut,intf_ch,intf_ch1,vlan_num,vlan_num1,vlan_string,port_ch):
#         i = 1
#         while(i <= 10):
#             for node in device_dut:
#                 testbed.devices[node].configure('''
#                     default int {1}
#                     default int {0}
#                     int port-channel {5}
#                         switchport
#                         switchport mode private-vlan host
#                         switchport private-vlan host-association {2} {3}
#                     interface {1}
#                         switchport
#                         switchport mode private-vlan host
#                         switchport private-vlan host-association {2} {3}
#                         channel-group {5} force mode active
#                     '''.format(intf_ch,intf_ch1,vlan_num,vlan_num1,vlan_string,port_ch))  
#                 output = testbed.devices[node].configure('show mac address-table dynamic')
#                 mac_search = re.search('[A-Z]+[a-z]+[0-9]', output)
#                 fin = mac_search.group()
#                 fail_flag = []
#                 if (fin == 'Po1'):
#                     print('passed')
#                 else:
#                     fail_flag.append(0) 
#                     print('mac move is failed') 

#                 testbed.devices[node].configure('''
#                     default int {0}
#                     interface{0}
#                         switchport
#                         switchport mode private-vlan promiscuous
#                         switchport private-vlan mapping {2} {4}
#                         no shutdown
#                     '''.format(intf_ch,intf_ch1,vlan_num,vlan_num1,vlan_string,port_ch))  
#                 output = testbed.devices[node].configure('show mac address-table dynamic')
#                 mac_search = re.search('[A-Z]+[a-z]+[a-z]+[0-9]+.+[0-9]+[0-9]', output)
#                 fin = mac_search.group()
#                 fail_flag = []
#                 if (fin == 'Eth1/49'):
#                     print('passed')
#                 else:
#                     fail_flag.append(0)  
#                     print('mac move is failed')    
#             i = i + 1
#             time.sleep(10)

# class mac_move_promiscous_trunk(nxtest.Testcase):
#     @aetest.test
#     #on tecate-1 e1/48 and e1/1 configuring promiscuous trunk port and verifying the mac move
#     def mac_move_promiscous_trunk(self, testbed,testscript,device_dut,intf_ch,intf_ch1,vlan_num,vlan_num1,vlan_string,port_ch):
#         for node in device_dut:
#             testbed.devices[node].configure('''
#                 interface port-channel{1}
#                     switchport
#                     switchport mode private-vlan trunk promiscuous
#                     switchport private-vlan mapping trunk {2} {4}
#                 '''.format(intf_ch,intf_ch1,vlan_num,vlan_num1,vlan_string,port_ch))  
#             output = testbed.devices[node].configure('show mac address-table dynamic')
#             mac_search = re.search('[A-Z]+[a-z]+[a-z]+[0-9]+.+[0-9]+[0-9]', output)
#             fin = mac_search.group()
#             fail_flag = []
#             if (fin == 'vPC Peer-Link'):
#                 print('passed')
#             else:
#                 fail_flag.append(0) 
#                 print('mac move is failed') 
 
#             testbed.devices[node].configure('''
#                 interface port-channel{1}
#                     switchport
#                     switchport mode private-vlan promiscuous
#                     switchport private-vlan mapping {2} {4}
#                     no shut
#                 '''.format(intf_ch,intf_ch1,vlan_num,vlan_num1,vlan_string,port_ch))  
#             output = testbed.devices[node].configure('show mac address-table dynamic')
#             mac_search = re.search('[A-Z]+[a-z]+[0-9]', output)
#             fin = mac_search.group()
#             fail_flag = []
#             if (fin == 'Po1'):
#                 print('passed')
#             else:
#                 fail_flag.append(0)  
#                 print('mac move is failed')    

# class mac_move_isolated_trunk(nxtest.Testcase):
#     @aetest.test
#     #on tecate-1 e1/48 and e1/1 configuring isolated trunk port and verifying the mac move
#     def mac_move_isolated_trunk(self, testbed,testscript,device_dut,intf_ch,intf_ch1,vlan_num,vlan_num1,vlan_string,port_ch):
#         for node in device_dut:
#             testbed.devices[node].configure('''
#                 default int {0}
#                 interface {0}
#                     switchport
#                     switchport mode private-vlan trunk secondary
#                     switchport private-vlan association trunk {2} {3}
#                 '''.format(intf_ch,intf_ch1,vlan_num,vlan_num1,vlan_string,port_ch))  
#             output = testbed.devices[node].configure('show mac address-table dynamic')
#             mac_search = re.search('[A-Z]+[a-z]+[a-z]+[0-9]+.+[0-9]+[0-9]', output)
#             fin = mac_search.group()
#             fail_flag = []
#             if (fin == 'Po1'):
#                 print('passed')
#             else:
#                 fail_flag.append(0) 
#                 print('mac move is failed') 
 
#             testbed.devices[node].configure('''
#                 default int {0}
#                 interface {0}
#                     switchport
#                     switchport mode private-vlan promiscuous
#                     switchport private-vlan mapping {2} {4}
#                 '''.format(intf_ch,intf_ch1,vlan_num,vlan_num1,vlan_string,port_ch))  
#             output = testbed.devices[node].configure('show mac address-table dynamic')
#             mac_search = re.search('[A-Z]+[a-z]+[0-9]', output)
#             fin = mac_search.group()
#             fail_flag = []
#             if (fin == 'Eth1/48'):
#                 print('passed')
#             else:
#                 fail_flag.append(0)  
#                 print('mac move is failed')

class promiscuous_to_promiscous_trunk(nxtest.Testcase):
    @aetest.test
    #on sumpin e1/48 configuring promiscous vland and converting to promiscous trunk vlan and verifying the traffic flow
    def promiscuous_to_promiscous_trunk(self, testbed,testscript,device_dut,intf_ch,vlan_num,vlan_string):
        for node in device_dut:
            testbed.devices[node].configure('''
                default int {0}
                interface {0}
                    switchport
                    switchport mode private-vlan promiscuous
                    switchport private-vlan mapping {1} {2}
                    no shutdown
                default int {0}
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk {1} {2}
                    no shut
                '''.format(testbed.devices[node].interfaces[intf_ch].name,vlan_num,vlan_string))        

# class pvlan_with_member_port_not_allowed(nxtest.Testcase):
#     # configured port channel 15 on sumpin ethernet e1/48 and tried to add cli on e1/48, and it should throw error
#     @aetest.test
#     def pvlan_with_member_port_not_allowed(self, testbed,testscript,device_dut):
#         for node in device_dut:
#             testbed.devices[node].configure('''
#                 interface port-channel15
#                     switchport
#                     switchport access vlan 10
#                     spanning-tree port type edge
#                     no shutdown                
#                 interface e1/48
#                     channel-group 15 mode active
#                 ''')
#             output = testbed.devices[node].configure('switchport')
#             mac_search = re.search('[A-Z]+[a-z]+[a-z]+[a-z]+[a-z]+[a-z]+[a-z]', output)
#             fin = mac_search.group()
#             fail_flag = []
#             if (fin == 'Invalid'):
#                 print('passed')
#             else:
#                 fail_flag.append(0)  
#                 print('pvlan with member port channel is allowed')            
#             time.sleep(2)   

class multiple_primary_secondary_ports1(nxtest.Testcase):
    # configured multiple primary and secondary vlans on tecate-1 e1/48
    @aetest.test
    def multiple_primary_secondary_ports1(self, testbed,testscript,device_dut):
        for node in device_dut:

            testbed.devices[node].configure('''
                vlan 20
                    private-vlan primary
                    private-vlan association 200
                    vn-segment 30020
                vlan 200
                    private-vlan community
                    vn-segment 30200
                interface Ethernet1/48
                    switchport
                    switchport mode private-vlan host
                    switchport private-vlan host-association 20 200
                ''')
            time.sleep(2)
            testbed.devices[node].configure('''
                vlan 21
                    private-vlan primary
                    private-vlan association 201
                    vn-segment 30021
                vlan 201
                    private-vlan community
                    vn-segment 30201
                interface Ethernet1/48
                    switchport
                    switchport mode private-vlan host
                    switchport private-vlan host-association 21 201
                ''')
            time.sleep(2)            
            testbed.devices[node].configure('''
                vlan 22
                    private-vlan primary
                    private-vlan association 202
                    vn-segment 30022
                vlan 202
                    private-vlan community
                    vn-segment 30202
                interface Ethernet1/48
                    switchport
                    switchport mode private-vlan host
                    switchport private-vlan host-association 22 202
                ''')
            time.sleep(2)            
            testbed.devices[node].configure('''
                vlan 23
                    private-vlan primary
                    private-vlan association 203
                    vn-segment 30023
                vlan 203
                    private-vlan community
                    vn-segment 30203
                interface Ethernet1/48
                    switchport
                    switchport mode private-vlan host
                    switchport private-vlan host-association 23 203
                ''')
            time.sleep(2)            
            testbed.devices[node].configure('''
                vlan 24
                    private-vlan primary
                    private-vlan association 204
                    vn-segment 30024
                vlan 204
                    private-vlan community
                    vn-segment 30200
                interface Ethernet1/48
                    switchport
                    switchport mode private-vlan host
                    switchport private-vlan host-association 24 204
                ''')
            time.sleep(2)            
            testbed.devices[node].configure('''
                vlan 25
                    private-vlan primary
                    private-vlan association 205
                    vn-segment 30025
                vlan 205
                    private-vlan community
                    vn-segment 30205
                interface Ethernet1/48
                    switchport
                    switchport mode private-vlan host
                    switchport private-vlan host-association 25 205
                ''')
            time.sleep(2)            
            testbed.devices[node].configure('''
                vlan 26
                    private-vlan primary
                    private-vlan association 206
                    vn-segment 30026
                vlan 206
                    private-vlan community
                    vn-segment 30206
                interface Ethernet1/48
                    switchport
                    switchport mode private-vlan host
                    switchport private-vlan host-association 20 206
                ''')
            time.sleep(2)            
            testbed.devices[node].configure('''
                vlan 27
                    private-vlan primary
                    private-vlan association 207
                    vn-segment 30027
                vlan 207
                    private-vlan community
                    vn-segment 30207
                interface Ethernet1/48
                    switchport
                    switchport mode private-vlan host
                    switchport private-vlan host-association 27 207
                ''')
            time.sleep(2)            
            testbed.devices[node].configure('''
                vlan 28
                    private-vlan primary
                    private-vlan association 208
                    vn-segment 30028
                vlan 208
                    private-vlan community
                    vn-segment 30208
                interface Ethernet1/48
                    switchport
                    switchport mode private-vlan host
                    switchport private-vlan host-association 28 208
                ''')
            time.sleep(2)            
            testbed.devices[node].configure('''
                vlan 29
                    private-vlan primary
                    private-vlan association 209
                    vn-segment 30029
                vlan 209
                    private-vlan community
                    vn-segment 30209
                interface Ethernet1/48
                    switchport
                    switchport mode private-vlan host
                    switchport private-vlan host-association 29 209
                ''')
            time.sleep(2)   
            testbed.devices[node].configure('''
                vlan 30
                    private-vlan primary
                    private-vlan association 210
                    vn-segment 30030
                vlan 210
                    private-vlan community
                    vn-segment 30210
                interface Ethernet1/48
                    switchport
                    switchport mode private-vlan host
                    switchport private-vlan host-association 30 210
                ''')
            time.sleep(2)          
            testbed.devices[node].configure('''
                vlan 31
                    private-vlan primary
                    private-vlan association 211
                    vn-segment 30031
                vlan 211
                    private-vlan community
                    vn-segment 30211
                interface Ethernet1/48
                    switchport
                    switchport mode private-vlan host
                    switchport private-vlan host-association 31 211
                ''')
            time.sleep(2)    

            testbed.devices[node].configure('''
                vlan 32
                    private-vlan primary
                    private-vlan association 212
                    vn-segment 30032
                vlan 212
                    private-vlan community
                    vn-segment 30212
                interface Ethernet1/48
                    switchport
                    switchport mode private-vlan host
                    switchport private-vlan host-association 32 212
                ''')
            time.sleep(2) 

            testbed.devices[node].configure('''
                vlan 33
                    private-vlan primary
                    private-vlan association 213
                    vn-segment 30033
                vlan 213
                    private-vlan community
                    vn-segment 30213
                interface Ethernet1/48
                    switchport
                    switchport mode private-vlan host
                    switchport private-vlan host-association 33 213
                ''')
            time.sleep(2) 

            testbed.devices[node].configure('''
                vlan 34
                    private-vlan primary
                    private-vlan association 214
                    vn-segment 30034
                vlan 214
                    private-vlan community
                    vn-segment 30214
                interface Ethernet1/48
                    switchport
                    switchport mode private-vlan host
                    switchport private-vlan host-association 34 214
                ''')
            time.sleep(2)    
            testbed.devices[node].configure('''
                vlan 35
                    private-vlan primary
                    private-vlan association 215
                    vn-segment 30035
                vlan 215
                    private-vlan community
                    vn-segment 30215
                interface Ethernet1/48
                    switchport
                    switchport mode private-vlan host
                    switchport private-vlan host-association 35 215
                ''')
            time.sleep(2) 
            testbed.devices[node].configure('''
                vlan 36
                    private-vlan primary
                    private-vlan association 216
                    vn-segment 30036
                vlan 216
                    private-vlan community
                    vn-segment 30216
                interface Ethernet1/48
                    switchport
                    switchport mode private-vlan host
                    switchport private-vlan host-association 36 216
                ''')
            time.sleep(2)      

class pvlan_in_peerlink_not_allowed(nxtest.Testcase):
    # configured pvlan in peer link not allowed on tecate-2 in channel port 15
    @aetest.test
    def pvlan_in_peerlink_not_allowed(self, testbed,testscript,device_dut,port_ch,vlan,vlan1):
        for node in device_dut:
            testbed.devices[node].configure('''
                interface port-channel{0}
                    switchport
                    switchport mode private-vlan host
                    switchport private-vlan host-association {1} {2}'''.format(port_ch,vlan,vlan1))
            time.sleep(2)
            testbed.devices[node].configure('''
                interface port-channel{0}
                    switchport
                    switchport mode private-vlan host
                    switchport private-vlan host-association {1} {2}'''.format(port_ch,vlan,vlan1))

class pvlan_adding_and_removing_members_from_portchannel(nxtest.Testcase):
    # adding and removing the member from the port channel 1 on tecate-2
    @aetest.test
    def pvlan_adding_and_removing_members_from_portchannel(self, testbed,testscript,device_dut,port_ch,vlan_num,vlan_num1):
        for node in device_dut:
            testbed.devices[node].configure('''
                interface port-channel{0}
                    no switchport private-vlan host-association {1} {2}
                '''.format(port_ch,vlan_num,vlan_num1))
            time.sleep(2)
            testbed.devices[node].configure('''
                interface port-channel{0}
                    switchport private-vlan host-association {1} {2}
                '''.format(port_ch,vlan_num,vlan_num1)) 
                       
class nve_flap_on_primary(nxtest.Testcase):
    # flap the nve on primary tecate-1 and verify the traffic loss and by applying the nve, traffic should come up
    @aetest.test
    def nve_flap_on_primary(self, testbed,testscript,device_dut,vlan_pri,vn_seg):
        for node in device_dut:
            testbed.devices[node].configure('''
                vlan {0}
                    no vn-segment {1}
                '''.format(vlan_pri,vn_seg))
            time.sleep(2)
            testbed.devices[node].configure('''
                vlan {0}
                    vn-segment {1}
                '''.format(vlan_pri,vn_seg))     
            time.sleep(2)

class nve_loopback_flap_on_primary(nxtest.Testcase):
    # flap the nve loopback on primary tecate-1 and verify the traffic loss and by applying the loopback, traffic should come up
    @aetest.test
    def nve_loopback_flap_on_primary(self, testbed,testscript,device_dut,nve,loopbk_1,loopbk_2):
        for node in device_dut:
            testbed.devices[node].configure('''
                int nve {0}
                    no source-interface loopback{1} anycast loopback{2}
                '''.format(nve,loopbk_1,loopbk_2))
            time.sleep(2)
            testbed.devices[node].configure('''
                int nve {0}
                    source-interface loopback{1} anycast loopback{2}
                '''.format(nve,loopbk_1,loopbk_2))         
            time.sleep(2)

class svi_flap(nxtest.Testcase):
    # flap the nve loopback on primary tecate-1 and verify the traffic loss and by applying the loopback, traffic should come up
    @aetest.test
    def svi_flap(self, testbed,testscript,device_dut,pri_vlan):
        for node in device_dut:
            testbed.devices[node].configure('''
                int vlan 10
                    shut
                '''.format(pri_vlan))
            time.sleep(2)
            testbed.devices[node].configure('''
                int vlan 10
                    no shut
                '''.format(pri_vlan))         
            time.sleep(2)

class mac_move_vpc_community_vlan(nxtest.Testcase):
    # shutting the e1/1 on tecate-1 and verifying the mac move
    @aetest.test
    def mac_move_vpc_community_vlan(self, testbed,testscript,device_dut,intf_ch):
        for node in device_dut:
            testbed.devices[node].configure('''
                show mac address-table dynamic
                int {0}
                    shut
                '''.format(testbed.devices[node].interfaces[intf_ch].name))
            time.sleep(2)
            output = testbed.devices[node].configure('show mac address-table dynamic')
            mac_search = re.search('[a-z]+[A-Z]+[A-Z]+.+[A-Z]+[a-z]+[a-z]+[a-z]+.+[A-Z]+[a-z]+[a-z]+[a-z]', output)
            fin = mac_search.group()
            fail_flag = []
            if (fin == 'vPC Peer-Link'):
                print('passed')
            else:
                fail_flag.append(0)  
                print('mac move is failed')            
              
        for node in device_dut:
            testbed.devices[node].configure('''
                int {0}
                    no shut
                '''.format(testbed.devices[node].interfaces[intf_ch].name))
            time.sleep(2)
            
class mac_move_vpc_isolated_vlan(nxtest.Testcase):
    # changing the e1/5 on tecate-2 to isolated vlan and verifying the mac move
    @aetest.test
    def mac_move_vpc_isolated_vlan(self, testbed,testscript,device_dut,pri_vlan,sec_vlan,sec_vlan1,port_ch):
        for node in device_dut:
            testbed.devices[node].configure('''
                show mac address-table dynamic
                int port-channel {3}
                    switchport
                    switchport mode private-vlan host
                    switchport private-vlan host-association {0} {2}
                '''.format(pri_vlan,sec_vlan,sec_vlan1,port_ch))
            time.sleep(2)
            output = testbed.devices[node].configure('show mac address-table dynamic')
            mac_search = re.search('[a-z]+[A-Z]+[A-Z]+.+[A-Z]+[a-z]+[a-z]+[a-z]+.+[A-Z]+[a-z]+[a-z]+[a-z]', output)
            fin = mac_search.group()
            fail_flag = []
            if (fin == 'vPC Peer-Link'):
                print('passed')
            else:
                fail_flag.append(0)  
                print('mac move is failed')            
              
        for node in device_dut:
            testbed.devices[node].configure('''
                int port-channel {3}
                    no switchport private-vlan host-association {0} {2}
                    switchport private-vlan host-association {0} {1}
                '''.format(pri_vlan,sec_vlan,sec_vlan1,port_ch))
            time.sleep(2)


class multiple_primary_secondary_ports(nxtest.Testcase):
    # configured 400 community primary and secondary vlans on tecate-1 and sumpin e1/5
    @aetest.test
    def multiple_primary_secondary_ports(self, testbed,testscript,device_dut,int):
        for node in device_dut:
            testbed.devices[node].configure('''                
                vlan 40
                    private-vlan primary
                    private-vlan association 400
                    vn-segment 30040
                vlan 400
                    private-vlan community
                    vn-segment 30400
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 40 400
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name)) 
            testbed.devices[node].configure('''
                vlan 41
                    private-vlan primary
                    private-vlan association 401
                    vn-segment 30041
                vlan 401
                    private-vlan community
                    vn-segment 30401
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 41 401
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))           
            testbed.devices[node].configure('''
                vlan 42
                    private-vlan primary
                    private-vlan association 402
                    vn-segment 30042
                vlan 402
                    private-vlan community
                    vn-segment 30402
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 42 402
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))          
            testbed.devices[node].configure('''
                vlan 43
                    private-vlan primary
                    private-vlan association 403
                    vn-segment 30043
                vlan 403
                    private-vlan community
                    vn-segment 30403
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 43 403
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))         
            testbed.devices[node].configure('''
                vlan 44
                    private-vlan primary
                    private-vlan association 404
                    vn-segment 30044
                vlan 404
                    private-vlan community
                    vn-segment 30404
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 44 404
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))          
            testbed.devices[node].configure('''
                vlan 45
                    private-vlan primary
                    private-vlan association 405
                    vn-segment 30045
                vlan 405
                    private-vlan community
                    vn-segment 30405
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 45 405
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))         
            testbed.devices[node].configure('''
                vlan 46
                    private-vlan primary
                    private-vlan association 406
                    vn-segment 30046
                vlan 406
                    private-vlan community
                    vn-segment 30406
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 46 406
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))           
            testbed.devices[node].configure('''
                vlan 47
                    private-vlan primary
                    private-vlan association 407
                    vn-segment 30047
                vlan 407
                    private-vlan community
                    vn-segment 30407
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 47 407
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))          
            testbed.devices[node].configure('''
                vlan 48
                    private-vlan primary
                    private-vlan association 408
                    vn-segment 30048
                vlan 408
                    private-vlan community
                    vn-segment 30408
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 48 408
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))          
            testbed.devices[node].configure('''
                vlan 49
                    private-vlan primary
                    private-vlan association 409
                    vn-segment 30049
                vlan 409
                    private-vlan community
                    vn-segment 30409
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 49 409
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name)) 
            testbed.devices[node].configure('''
                vlan 50
                    private-vlan primary
                    private-vlan association 410
                    vn-segment 30050
                vlan 410
                    private-vlan community
                    vn-segment 30410
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 50 410
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))        
            testbed.devices[node].configure('''
                vlan 51
                    private-vlan primary
                    private-vlan association 411
                    vn-segment 30051
                vlan 411
                    private-vlan community
                    vn-segment 30411
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 51 411
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))
            testbed.devices[node].configure('''
                vlan 52
                    private-vlan primary
                    private-vlan association 412
                    vn-segment 30052
                vlan 412
                    private-vlan community
                    vn-segment 30412
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 52 412
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))
            testbed.devices[node].configure('''
                vlan 53
                    private-vlan primary
                    private-vlan association 413
                    vn-segment 30053
                vlan 413
                    private-vlan community
                    vn-segment 30413
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 53 413
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))
            testbed.devices[node].configure('''
                vlan 54
                    private-vlan primary
                    private-vlan association 414
                    vn-segment 30054
                vlan 414
                    private-vlan community
                    vn-segment 30414
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 54 414
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name)) 
            testbed.devices[node].configure('''
                vlan 55
                    private-vlan primary
                    private-vlan association 415
                    vn-segment 30055
                vlan 415
                    private-vlan community
                    vn-segment 30415
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 55 415
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))
            testbed.devices[node].configure('''
                vlan 56
                    private-vlan primary
                    private-vlan association 416
                    vn-segment 30056
                vlan 416
                    private-vlan community
                    vn-segment 30416
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 56 416
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))
            testbed.devices[node].configure('''
                vlan 57
                    private-vlan primary
                    private-vlan association 417
                    vn-segment 30057
                vlan 417
                    private-vlan community
                    vn-segment 30417
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 57 417
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))
            testbed.devices[node].configure('''
                vlan 58
                    private-vlan primary
                    private-vlan association 418
                    vn-segment 30058
                vlan 418
                    private-vlan community
                    vn-segment 30418
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 58 418
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))           
            testbed.devices[node].configure('''
                vlan 59
                    private-vlan primary
                    private-vlan association 419
                    vn-segment 30059
                vlan 419
                    private-vlan community
                    vn-segment 30419
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 59 419
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))          
            testbed.devices[node].configure('''
                vlan 60
                    private-vlan primary
                    private-vlan association 420
                    vn-segment 30060
                vlan 420
                    private-vlan community
                    vn-segment 30420
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 60 420
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))         
            testbed.devices[node].configure('''
                vlan 61
                    private-vlan primary
                    private-vlan association 421
                    vn-segment 30061
                vlan 421
                    private-vlan community
                    vn-segment 30421
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 61 421
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))          
            testbed.devices[node].configure('''
                vlan 62
                    private-vlan primary
                    private-vlan association 422
                    vn-segment 30062
                vlan 422
                    private-vlan community
                    vn-segment 30422
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 62 422
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))         
            testbed.devices[node].configure('''
                vlan 63
                    private-vlan primary
                    private-vlan association 423
                    vn-segment 30063
                vlan 423
                    private-vlan community
                    vn-segment 30423
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 63 423
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))           
            testbed.devices[node].configure('''
                vlan 64
                    private-vlan primary
                    private-vlan association 424
                    vn-segment 30064
                vlan 424
                    private-vlan community
                    vn-segment 30424
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 64 424
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))          
            testbed.devices[node].configure('''
                vlan 65
                    private-vlan primary
                    private-vlan association 425
                    vn-segment 30065
                vlan 425
                    private-vlan community
                    vn-segment 30425
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 65 425
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))          
            testbed.devices[node].configure('''
                vlan 66
                    private-vlan primary
                    private-vlan association 426
                    vn-segment 30066
                vlan 426
                    private-vlan community
                    vn-segment 30426
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 66 426
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name)) 
            testbed.devices[node].configure('''
                vlan 67
                    private-vlan primary
                    private-vlan association 427
                    vn-segment 30067
                vlan 427
                    private-vlan community
                    vn-segment 30427
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 67 427
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))        
            testbed.devices[node].configure('''
                vlan 68
                    private-vlan primary
                    private-vlan association 428
                    vn-segment 30068
                vlan 428
                    private-vlan community
                    vn-segment 30428
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 68 428
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))
            testbed.devices[node].configure('''
                vlan 69
                    private-vlan primary
                    private-vlan association 429
                    vn-segment 30069
                vlan 429
                    private-vlan community
                    vn-segment 30429
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 69 429
                    no shut
                '''.format(testbed.devices[node].interfaces[int].name))
            testbed.devices[node].configure('''
                vlan 70
                    private-vlan primary
                    private-vlan association 430
                    vn-segment 30070
                vlan 430
                    private-vlan community
                    vn-segment 30430
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 70 430
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))
            testbed.devices[node].configure('''
                vlan 71
                    private-vlan primary
                    private-vlan association 431
                    vn-segment 30071
                vlan 431
                    private-vlan community
                    vn-segment 30431
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 71 431
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name)) 
            testbed.devices[node].configure('''
                vlan 72
                    private-vlan primary
                    private-vlan association 432
                    vn-segment 30072
                vlan 432
                    private-vlan community
                    vn-segment 30432
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 72 432
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))
            testbed.devices[node].configure('''
                vlan 73
                    private-vlan primary
                    private-vlan association 433
                    vn-segment 30073
                vlan 433
                    private-vlan community
                    vn-segment 30473
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 73 433
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))     
            testbed.devices[node].configure('''
                vlan 74
                    private-vlan primary
                    private-vlan association 434
                    vn-segment 30074
                vlan 434
                    private-vlan community
                    vn-segment 30434
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 74 434
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))
            testbed.devices[node].configure('''
                vlan 75
                    private-vlan primary
                    private-vlan association 435
                    vn-segment 30075
                vlan 435
                    private-vlan community
                    vn-segment 30435
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 75 435
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))           
            testbed.devices[node].configure('''
                vlan 76
                    private-vlan primary
                    private-vlan association 436
                    vn-segment 30076
                vlan 436
                    private-vlan community
                    vn-segment 30436
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 76 436
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))          
            testbed.devices[node].configure('''
                vlan 77
                    private-vlan primary
                    private-vlan association 437
                    vn-segment 30077
                vlan 437
                    private-vlan community
                    vn-segment 30477
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 77 437
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))         
            testbed.devices[node].configure('''
                vlan 78
                    private-vlan primary
                    private-vlan association 438
                    vn-segment 30078
                vlan 438
                    private-vlan community
                    vn-segment 30438
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 78 438
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))          
            testbed.devices[node].configure('''
                vlan 79
                    private-vlan primary
                    private-vlan association 439
                    vn-segment 30079
                vlan 439
                    private-vlan community
                    vn-segment 30479
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 79 439
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))         
            testbed.devices[node].configure('''
                vlan 80
                    private-vlan primary
                    private-vlan association 440
                    vn-segment 30080
                vlan 440
                    private-vlan community
                    vn-segment 30440
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 80 440
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))           
            testbed.devices[node].configure('''
                vlan 81
                    private-vlan primary
                    private-vlan association 441
                    vn-segment 30047
                vlan 441
                    private-vlan community
                    vn-segment 30441
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 81 441
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))          
            testbed.devices[node].configure('''
                vlan 82
                    private-vlan primary
                    private-vlan association 442
                    vn-segment 30082
                vlan 442
                    private-vlan community
                    vn-segment 3044
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 82 442
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))          
            testbed.devices[node].configure('''
                vlan 83
                    private-vlan primary
                    private-vlan association 443
                    vn-segment 30083
                vlan 443
                    private-vlan community
                    vn-segment 30443
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 83 443
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name)) 
            testbed.devices[node].configure('''
                vlan 84
                    private-vlan primary
                    private-vlan association 444
                    vn-segment 30084
                vlan 444
                    private-vlan community
                    vn-segment 30444
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 84 444
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))        
            testbed.devices[node].configure('''
                vlan 85
                    private-vlan primary
                    private-vlan association 445
                    vn-segment 30085
                vlan 445
                    private-vlan community
                    vn-segment 30445
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 85 445
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))
            testbed.devices[node].configure('''
                vlan 86
                    private-vlan primary
                    private-vlan association 446
                    vn-segment 30086
                vlan 446
                    private-vlan community
                    vn-segment 30446
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 86 446
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))
            testbed.devices[node].configure('''
                vlan 87
                    private-vlan primary
                    private-vlan association 447
                    vn-segment 30087
                vlan 447
                    private-vlan community
                    vn-segment 30447
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 87 447
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))
            testbed.devices[node].configure('''
                vlan 88
                    private-vlan primary
                    private-vlan association 448
                    vn-segment 30088
                vlan 448
                    private-vlan community
                    vn-segment 30448
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 88 448
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name)) 
            testbed.devices[node].configure('''
                vlan 89
                    private-vlan primary
                    private-vlan association 449
                    vn-segment 30089
                vlan 449
                    private-vlan community
                    vn-segment 30449
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 89 449
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))
            testbed.devices[node].configure('''
                vlan 90
                    private-vlan primary
                    private-vlan association 450
                    vn-segment 30090
                vlan 450
                    private-vlan community
                    vn-segment 30450
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 90 450
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))
            testbed.devices[node].configure('''
                vlan 91
                    private-vlan primary
                    private-vlan association 451
                    vn-segment 30091
                vlan 451
                    private-vlan community
                    vn-segment 30451
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 91 451
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))
            testbed.devices[node].configure('''
                vlan 92
                    private-vlan primary
                    private-vlan association 452
                    vn-segment 30092
                vlan 452
                    private-vlan community
                    vn-segment 30452
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 92 452
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))           
            testbed.devices[node].configure('''
                vlan 93
                    private-vlan primary
                    private-vlan association 453
                    vn-segment 30093
                vlan 453
                    private-vlan community
                    vn-segment 30453
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 93 453
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))          
            testbed.devices[node].configure('''
                vlan 94
                    private-vlan primary
                    private-vlan association 454
                    vn-segment 30094
                vlan 454
                    private-vlan community
                    vn-segment 30454
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 94 454
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))         
            testbed.devices[node].configure('''
                vlan 95
                    private-vlan primary
                    private-vlan association 455
                    vn-segment 30095
                vlan 455
                    private-vlan community
                    vn-segment 30455
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 95 455
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))          
            testbed.devices[node].configure('''
                vlan 96
                    private-vlan primary
                    private-vlan association 456
                    vn-segment 30096
                vlan 456
                    private-vlan community
                    vn-segment 30456
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 96 456
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))         
            testbed.devices[node].configure('''
                vlan 97
                    private-vlan primary
                    private-vlan association 457
                    vn-segment 30097
                vlan 457
                    private-vlan community
                    vn-segment 30457
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 97 457
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))           
            testbed.devices[node].configure('''
                vlan 98
                    private-vlan primary
                    private-vlan association 458
                    vn-segment 30098
                vlan 458
                    private-vlan community
                    vn-segment 30458
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 98 458
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))          
            testbed.devices[node].configure('''
                vlan 99
                    private-vlan primary
                    private-vlan association 459
                    vn-segment 30099
                vlan 459
                    private-vlan community
                    vn-segment 30459
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 99 459
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))          
            testbed.devices[node].configure('''
                vlan 100
                    private-vlan primary
                    private-vlan association 460
                    vn-segment 30100
                vlan 460
                    private-vlan community
                    vn-segment 30460
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 100 460
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name)) 
            testbed.devices[node].configure('''
                vlan 101
                    private-vlan primary
                    private-vlan association 461
                    vn-segment 30101
                vlan 461
                    private-vlan community
                    vn-segment 30461
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 101 461
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))        
            testbed.devices[node].configure('''
                vlan 102
                    private-vlan primary
                    private-vlan association 462
                    vn-segment 30102
                vlan 462
                    private-vlan community
                    vn-segment 30462
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 102 462
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))
            testbed.devices[node].configure('''
                vlan 103
                    private-vlan primary
                    private-vlan association 463
                    vn-segment 30103
                vlan 463
                    private-vlan community
                    vn-segment 30463
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 103 463
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))
            testbed.devices[node].configure('''
                vlan 104
                    private-vlan primary
                    private-vlan association 464
                    vn-segment 30104
                vlan 464
                    private-vlan community
                    vn-segment 30464
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 104 464
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))
            testbed.devices[node].configure('''
                vlan 105
                    private-vlan primary
                    private-vlan association 465
                    vn-segment 30105
                vlan 465
                    private-vlan community
                    vn-segment 30465
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 105 465
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name)) 
            testbed.devices[node].configure('''
                vlan 106
                    private-vlan primary
                    private-vlan association 466
                    vn-segment 30106
                vlan 466
                    private-vlan community
                    vn-segment 30466
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 106 466
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))
            testbed.devices[node].configure('''
                vlan 107
                    private-vlan primary
                    private-vlan association 467
                    vn-segment 30107
                vlan 467
                    private-vlan community
                    vn-segment 30467
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 107 467
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))
            testbed.devices[node].configure('''
                vlan 108
                    private-vlan primary
                    private-vlan association 468
                    vn-segment 30108
                vlan 468
                    private-vlan community
                    vn-segment 30468
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 108 468
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name)) 
            testbed.devices[node].configure('''
                vlan 109
                    private-vlan primary
                    private-vlan association 469
                    vn-segment 30109
                vlan 469
                    private-vlan community
                    vn-segment 30469
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 109 469
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))        
            testbed.devices[node].configure('''
                vlan 110
                    private-vlan primary
                    private-vlan association 470
                    vn-segment 30110
                vlan 470
                    private-vlan community
                    vn-segment 30470
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 110 470
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))
            testbed.devices[node].configure('''
                vlan 111
                    private-vlan primary
                    private-vlan association 471
                    vn-segment 30111
                vlan 471
                    private-vlan community
                    vn-segment 30471
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 111 471
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))
            testbed.devices[node].configure('''
                vlan 112
                    private-vlan primary
                    private-vlan association 472
                    vn-segment 30112
                vlan 472
                    private-vlan community
                    vn-segment 30472
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 112 472
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))
            testbed.devices[node].configure('''
                vlan 113
                    private-vlan primary
                    private-vlan association 473
                    vn-segment 30113
                vlan 473
                    private-vlan community
                    vn-segment 30473
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 113 473
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name)) 
            testbed.devices[node].configure('''
                vlan 114
                    private-vlan primary
                    private-vlan association 474
                    vn-segment 30114
                vlan 474
                    private-vlan community
                    vn-segment 30474
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 114 474
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))
            testbed.devices[node].configure('''
                vlan 115
                    private-vlan primary
                    private-vlan association 475
                    vn-segment 30115
                vlan 475
                    private-vlan community
                    vn-segment 30475
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 115 475
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))
            testbed.devices[node].configure('''
                vlan 116
                    private-vlan primary
                    private-vlan association 476
                    vn-segment 30116
                vlan 476
                    private-vlan community
                    vn-segment 30476
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 116 476
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name)) 
            testbed.devices[node].configure('''
                vlan 117
                    private-vlan primary
                    private-vlan association 477
                    vn-segment 30117
                vlan 477
                    private-vlan community
                    vn-segment 30477
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 117 477
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))        
            testbed.devices[node].configure('''
                vlan 118
                    private-vlan primary
                    private-vlan association 478
                    vn-segment 30118
                vlan 478
                    private-vlan community
                    vn-segment 30478
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 118 478
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))
            testbed.devices[node].configure('''
                vlan 119
                    private-vlan primary
                    private-vlan association 479
                    vn-segment 30119
                vlan 479
                    private-vlan community
                    vn-segment 30479
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 119 479
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))
            testbed.devices[node].configure('''
                vlan 120
                    private-vlan primary
                    private-vlan association 480
                    vn-segment 30120
                vlan 480
                    private-vlan community
                    vn-segment 30480
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 120 480
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))
            testbed.devices[node].configure('''
                vlan 121
                    private-vlan primary
                    private-vlan association 481
                    vn-segment 30121
                vlan 481
                    private-vlan community
                    vn-segment 30481
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 121 481
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name)) 
            testbed.devices[node].configure('''
                vlan 122
                    private-vlan primary
                    private-vlan association 482
                    vn-segment 30122
                vlan 482
                    private-vlan community
                    vn-segment 30482
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 122 482
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))
            testbed.devices[node].configure('''
                vlan 123
                    private-vlan primary
                    private-vlan association 483
                    vn-segment 30123
                vlan 483
                    private-vlan community
                    vn-segment 30483
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 123 483
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))
            testbed.devices[node].configure('''
                vlan 124
                    private-vlan primary
                    private-vlan association 484
                    vn-segment 30124
                vlan 484
                    private-vlan community
                    vn-segment 30484
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 124 484
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name)) 
            testbed.devices[node].configure('''
                vlan 125
                    private-vlan primary
                    private-vlan association 485
                    vn-segment 30125
                vlan 485
                    private-vlan community
                    vn-segment 30485
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 125 485
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))        
            testbed.devices[node].configure('''
                vlan 126
                    private-vlan primary
                    private-vlan association 486
                    vn-segment 30126
                vlan 486
                    private-vlan community
                    vn-segment 30426
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 126 486
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))
            testbed.devices[node].configure('''
                vlan 127
                    private-vlan primary
                    private-vlan association 487
                    vn-segment 30127
                vlan 487
                    private-vlan community
                    vn-segment 30487
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 127 487
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))
            testbed.devices[node].configure('''
                vlan 128
                    private-vlan primary
                    private-vlan association 488
                    vn-segment 30128
                vlan 488
                    private-vlan community
                    vn-segment 30488
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 128 488
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))
            testbed.devices[node].configure('''
                vlan 129
                    private-vlan primary
                    private-vlan association 489
                    vn-segment 30129
                vlan 489
                    private-vlan community
                    vn-segment 30489
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 129 489
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name)) 
            testbed.devices[node].configure('''
                vlan 130
                    private-vlan primary
                    private-vlan association 490
                    vn-segment 30130
                vlan 490
                    private-vlan community
                    vn-segment 30490
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 130 490
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))
            testbed.devices[node].configure('''
                vlan 131
                    private-vlan primary
                    private-vlan association 491
                    vn-segment 30131
                vlan 491
                    private-vlan community
                    vn-segment 30491
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 131 491
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))
            testbed.devices[node].configure('''
                vlan 132
                    private-vlan primary
                    private-vlan association 492
                    vn-segment 30132
                vlan 492
                    private-vlan community
                    vn-segment 30492
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 132 492
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))
            testbed.devices[node].configure('''
                vlan 133
                    private-vlan primary
                    private-vlan association 493
                    vn-segment 30133
                vlan 493
                    private-vlan community
                    vn-segment 30493
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 133 493
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name)) 
            testbed.devices[node].configure('''
                vlan 134
                    private-vlan primary
                    private-vlan association 494
                    vn-segment 30134
                vlan 494
                    private-vlan community
                    vn-segment 30494
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 134 494
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))        
            testbed.devices[node].configure('''
                vlan 135
                    private-vlan primary
                    private-vlan association 495
                    vn-segment 30135
                vlan 495
                    private-vlan community
                    vn-segment 30435
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 135 495
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))
            testbed.devices[node].configure('''
                vlan 136
                    private-vlan primary
                    private-vlan association 496
                    vn-segment 30136
                vlan 496
                    private-vlan community
                    vn-segment 30496
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 136 496
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))
            testbed.devices[node].configure('''
                vlan 137
                    private-vlan primary
                    private-vlan association 497
                    vn-segment 30137
                vlan 497
                    private-vlan community
                    vn-segment 30497
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 137 497
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))
            testbed.devices[node].configure('''
                vlan 138
                    private-vlan primary
                    private-vlan association 498
                    vn-segment 30138
                vlan 498
                    private-vlan community
                    vn-segment 30498
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 138 498
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name)) 
            testbed.devices[node].configure('''
                vlan 139
                    private-vlan primary
                    private-vlan association 499
                    vn-segment 30139
                vlan 499
                    private-vlan community
                    vn-segment 30499
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 139 499
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))
            testbed.devices[node].configure('''
                vlan 140
                    private-vlan primary
                    private-vlan association 500
                    vn-segment 30140
                vlan 500
                    private-vlan community
                    vn-segment 30500
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 140 500
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))
            testbed.devices[node].configure('''
                vlan 141
                    private-vlan primary
                    private-vlan association 501
                    vn-segment 30141
                vlan 501
                    private-vlan community
                    vn-segment 30501
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 141 501
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))           
            testbed.devices[node].configure('''
                vlan 142
                    private-vlan primary
                    private-vlan association 502
                    vn-segment 30142
                vlan 502
                    private-vlan community
                    vn-segment 30502
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 142 502
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))          
            testbed.devices[node].configure('''
                vlan 143
                    private-vlan primary
                    private-vlan association 503
                    vn-segment 30143
                vlan 403
                    private-vlan community
                    vn-segment 30503
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 143 503
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))         
            testbed.devices[node].configure('''
                vlan 144
                    private-vlan primary
                    private-vlan association 504
                    vn-segment 30144
                vlan 504
                    private-vlan community
                    vn-segment 30504
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 144 504
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))          
            testbed.devices[node].configure('''
                vlan 145
                    private-vlan primary
                    private-vlan association 505
                    vn-segment 30045
                vlan 505
                    private-vlan community
                    vn-segment 30505
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 145 505
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))         
            testbed.devices[node].configure('''
                vlan 146
                    private-vlan primary
                    private-vlan association 506
                    vn-segment 30146
                vlan 506
                    private-vlan community
                    vn-segment 30506
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 146 506
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))           
            testbed.devices[node].configure('''
                vlan 147
                    private-vlan primary
                    private-vlan association 507
                    vn-segment 30147
                vlan 507
                    private-vlan community
                    vn-segment 30507
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 147 507
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))          
            testbed.devices[node].configure('''
                vlan 148
                    private-vlan primary
                    private-vlan association 508
                    vn-segment 30148
                vlan 508
                    private-vlan community
                    vn-segment 30508
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 148 508
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))          
            testbed.devices[node].configure('''
                vlan 149
                    private-vlan primary
                    private-vlan association 509
                    vn-segment 30149
                vlan 509
                    private-vlan community
                    vn-segment 30509
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 149 509
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name)) 
            testbed.devices[node].configure('''
                vlan 150
                    private-vlan primary
                    private-vlan association 510
                    vn-segment 30150
                vlan 510
                    private-vlan community
                    vn-segment 30510
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 150 510
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))        
            testbed.devices[node].configure('''
                vlan 151
                    private-vlan primary
                    private-vlan association 511
                    vn-segment 30151
                vlan 511
                    private-vlan community
                    vn-segment 30511
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 151 511
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))
            testbed.devices[node].configure('''
                vlan 152
                    private-vlan primary
                    private-vlan association 512
                    vn-segment 30152
                vlan 512
                    private-vlan community
                    vn-segment 30512
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 152 512
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))
            testbed.devices[node].configure('''
                vlan 153
                    private-vlan primary
                    private-vlan association 513
                    vn-segment 30153
                vlan 513
                    private-vlan community
                    vn-segment 30513
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 153 513
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))
            testbed.devices[node].configure('''
                vlan 154
                    private-vlan primary
                    private-vlan association 514
                    vn-segment 30154
                vlan 514
                    private-vlan community
                    vn-segment 30414
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 154 514
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name)) 
            testbed.devices[node].configure('''
                vlan 155
                    private-vlan primary
                    private-vlan association 515
                    vn-segment 30155
                vlan 515
                    private-vlan community
                    vn-segment 30515
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 155 515
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))
            testbed.devices[node].configure('''
                vlan 156
                    private-vlan primary
                    private-vlan association 516
                    vn-segment 30156
                vlan 516
                    private-vlan community
                    vn-segment 30516
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 156 516
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))
            testbed.devices[node].configure('''
                vlan 157
                    private-vlan primary
                    private-vlan association 517
                    vn-segment 30157
                vlan 517
                    private-vlan community
                    vn-segment 30517
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 157 517
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))
            testbed.devices[node].configure('''
                vlan 158
                    private-vlan primary
                    private-vlan association 518
                    vn-segment 30158
                vlan 518
                    private-vlan community
                    vn-segment 30518
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 158 518
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))           
            testbed.devices[node].configure('''
                vlan 159
                    private-vlan primary
                    private-vlan association 519
                    vn-segment 30159
                vlan 519
                    private-vlan community
                    vn-segment 30519
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 159 519
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))          
            testbed.devices[node].configure('''
                vlan 160
                    private-vlan primary
                    private-vlan association 520
                    vn-segment 30160
                vlan 520
                    private-vlan community
                    vn-segment 30520
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 160 520
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))         
            testbed.devices[node].configure('''
                vlan 161
                    private-vlan primary
                    private-vlan association 521
                    vn-segment 30161
                vlan 521
                    private-vlan community
                    vn-segment 30521
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 161 521
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))          
            testbed.devices[node].configure('''
                vlan 162
                    private-vlan primary
                    private-vlan association 522
                    vn-segment 30162
                vlan 522
                    private-vlan community
                    vn-segment 30522
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 162 522
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))         
            testbed.devices[node].configure('''
                vlan 163
                    private-vlan primary
                    private-vlan association 523
                    vn-segment 30163
                vlan 523
                    private-vlan community
                    vn-segment 30523
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 163 523
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))           
            testbed.devices[node].configure('''
                vlan 164
                    private-vlan primary
                    private-vlan association 524
                    vn-segment 30164
                vlan 524
                    private-vlan community
                    vn-segment 30524
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 164 524
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))          
            testbed.devices[node].configure('''
                vlan 165
                    private-vlan primary
                    private-vlan association 525
                    vn-segment 30165
                vlan 525
                    private-vlan community
                    vn-segment 30525
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 165 525
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))          
            testbed.devices[node].configure('''
                vlan 166
                    private-vlan primary
                    private-vlan association 526
                    vn-segment 30166
                vlan 526
                    private-vlan community
                    vn-segment 30526
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 166 526
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name)) 
            testbed.devices[node].configure('''
                vlan 167
                    private-vlan primary
                    private-vlan association 527
                    vn-segment 30167
                vlan 527
                    private-vlan community
                    vn-segment 30527
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 167 527
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))        
            testbed.devices[node].configure('''
                vlan 168
                    private-vlan primary
                    private-vlan association 528
                    vn-segment 30168
                vlan 528
                    private-vlan community
                    vn-segment 30528
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 168 528
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))
            testbed.devices[node].configure('''
                vlan 169
                    private-vlan primary
                    private-vlan association 529
                    vn-segment 30169
                vlan 529
                    private-vlan community
                    vn-segment 30529
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 169 529
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))
            testbed.devices[node].configure('''
                vlan 170
                    private-vlan primary
                    private-vlan association 530
                    vn-segment 30170
                vlan 530
                    private-vlan community
                    vn-segment 30530
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 170 530
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))
            testbed.devices[node].configure('''
                vlan 171
                    private-vlan primary
                    private-vlan association 531
                    vn-segment 30171
                vlan 531
                    private-vlan community
                    vn-segment 30531
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 171 531
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name)) 
            testbed.devices[node].configure('''
                vlan 172
                    private-vlan primary
                    private-vlan association 532
                    vn-segment 30172
                vlan 532
                    private-vlan community
                    vn-segment 30532
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 172 532
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))
            testbed.devices[node].configure('''
                vlan 173
                    private-vlan primary
                    private-vlan association 533
                    vn-segment 30173
                vlan 533
                    private-vlan community
                    vn-segment 30573
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 173 533
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))     
            testbed.devices[node].configure('''
                vlan 174
                    private-vlan primary
                    private-vlan association 534
                    vn-segment 30174
                vlan 534
                    private-vlan community
                    vn-segment 30534
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 174 534
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))
            testbed.devices[node].configure('''
                vlan 175
                    private-vlan primary
                    private-vlan association 535
                    vn-segment 30175
                vlan 535
                    private-vlan community
                    vn-segment 30535
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 175 535
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))           
            testbed.devices[node].configure('''
                vlan 176
                    private-vlan primary
                    private-vlan association 536
                    vn-segment 30176
                vlan 536
                    private-vlan community
                    vn-segment 30536
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 176 536
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))          
            testbed.devices[node].configure('''
                vlan 177
                    private-vlan primary
                    private-vlan association 537
                    vn-segment 30177
                vlan 537
                    private-vlan community
                    vn-segment 30577
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 177 537
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))         
            testbed.devices[node].configure('''
                vlan 178
                    private-vlan primary
                    private-vlan association 538
                    vn-segment 30178
                vlan 538
                    private-vlan community
                    vn-segment 30538
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 178 538
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))          
            testbed.devices[node].configure('''
                vlan 179
                    private-vlan primary
                    private-vlan association 539
                    vn-segment 30179
                vlan 539
                    private-vlan community
                    vn-segment 30539
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 179 539
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))         
            testbed.devices[node].configure('''
                vlan 180
                    private-vlan primary
                    private-vlan association 540
                    vn-segment 30180
                vlan 540
                    private-vlan community
                    vn-segment 30540
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 180 540
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))           
            testbed.devices[node].configure('''
                vlan 181
                    private-vlan primary
                    private-vlan association 541
                    vn-segment 30147
                vlan 541
                    private-vlan community
                    vn-segment 30541
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 181 541
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))          
            testbed.devices[node].configure('''
                vlan 812
                    private-vlan primary
                    private-vlan association 542
                    vn-segment 30182
                vlan 542
                    private-vlan community
                    vn-segment 30542
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 182 542
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))          
            testbed.devices[node].configure('''
                vlan 183
                    private-vlan primary
                    private-vlan association 543
                    vn-segment 30183
                vlan 543
                    private-vlan community
                    vn-segment 30543
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 183 543
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name)) 
            testbed.devices[node].configure('''
                vlan 184
                    private-vlan primary
                    private-vlan association 544
                    vn-segment 30184
                vlan 544
                    private-vlan community
                    vn-segment 30544
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 184 544
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))        
            testbed.devices[node].configure('''
                vlan 185
                    private-vlan primary
                    private-vlan association 545
                    vn-segment 30185
                vlan 545
                    private-vlan community
                    vn-segment 30545
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 185 545
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))
            testbed.devices[node].configure('''
                vlan 186
                    private-vlan primary
                    private-vlan association 546
                    vn-segment 30186
                vlan 546
                    private-vlan community
                    vn-segment 30546
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 186 546
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))
            testbed.devices[node].configure('''
                vlan 187
                    private-vlan primary
                    private-vlan association 547
                    vn-segment 30187
                vlan 547
                    private-vlan community
                    vn-segment 30547
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 187 547
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))
            testbed.devices[node].configure('''
                vlan 188
                    private-vlan primary
                    private-vlan association 548
                    vn-segment 30188
                vlan 548
                    private-vlan community
                    vn-segment 30548
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 188 548
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name)) 
            testbed.devices[node].configure('''
                vlan 189
                    private-vlan primary
                    private-vlan association 549
                    vn-segment 30189
                vlan 549
                    private-vlan community
                    vn-segment 30549
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 189 549
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))
            testbed.devices[node].configure('''
                vlan 190
                    private-vlan primary
                    private-vlan association 550
                    vn-segment 30190
                vlan 550
                    private-vlan community
                    vn-segment 30550
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 190 550
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))
            testbed.devices[node].configure('''
                vlan 191
                    private-vlan primary
                    private-vlan association 551
                    vn-segment 30191
                vlan 551
                    private-vlan community
                    vn-segment 30551
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 191 551
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))
            testbed.devices[node].configure('''
                vlan 192
                    private-vlan primary
                    private-vlan association 552
                    vn-segment 30192
                vlan 552
                    private-vlan community
                    vn-segment 30552
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 192 552
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))           
            testbed.devices[node].configure('''
                vlan 193
                    private-vlan primary
                    private-vlan association 553
                    vn-segment 30093
                vlan 553
                    private-vlan community
                    vn-segment 30553
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 193 553
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))          
            testbed.devices[node].configure('''
                vlan 194
                    private-vlan primary
                    private-vlan association 554
                    vn-segment 30194
                vlan 554
                    private-vlan community
                    vn-segment 30554
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 194 554
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))         
            testbed.devices[node].configure('''
                vlan 195
                    private-vlan primary
                    private-vlan association 555
                    vn-segment 30195
                vlan 555
                    private-vlan community
                    vn-segment 30555
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 195 555
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))          
            testbed.devices[node].configure('''
                vlan 196
                    private-vlan primary
                    private-vlan association 556
                    vn-segment 30196
                vlan 556
                    private-vlan community
                    vn-segment 30556
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 196 556
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))         
            testbed.devices[node].configure('''
                vlan 197
                    private-vlan primary
                    private-vlan association 557
                    vn-segment 30197
                vlan 557
                    private-vlan community
                    vn-segment 30557
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 197 557
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))           
            testbed.devices[node].configure('''
                vlan 198
                    private-vlan primary
                    private-vlan association 558
                    vn-segment 30198
                vlan 558
                    private-vlan community
                    vn-segment 30558
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 198 558
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))          
            testbed.devices[node].configure('''
                vlan 199
                    private-vlan primary
                    private-vlan association 559
                    vn-segment 30099
                vlan 559
                    private-vlan community
                    vn-segment 30559
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 199 559
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))          
            testbed.devices[node].configure('''
                vlan 200
                    private-vlan primary
                    private-vlan association 560
                    vn-segment 30200
                vlan 560
                    private-vlan community
                    vn-segment 30560
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 200 560
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name)) 
            testbed.devices[node].configure('''
                vlan 201
                    private-vlan primary
                    private-vlan association 561
                    vn-segment 30201
                vlan 561
                    private-vlan community
                    vn-segment 30561
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 201 561
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))        
            testbed.devices[node].configure('''
                vlan 202
                    private-vlan primary
                    private-vlan association 562
                    vn-segment 30202
                vlan 562
                    private-vlan community
                    vn-segment 30562
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 202 562
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))
            testbed.devices[node].configure('''
                vlan 203
                    private-vlan primary
                    private-vlan association 563
                    vn-segment 30203
                vlan 563
                    private-vlan community
                    vn-segment 30563
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 203 563
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))
            testbed.devices[node].configure('''
                vlan 204
                    private-vlan primary
                    private-vlan association 564
                    vn-segment 30204
                vlan 564
                    private-vlan community
                    vn-segment 30564
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 204 564
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))
            testbed.devices[node].configure('''
                vlan 205
                    private-vlan primary
                    private-vlan association 565
                    vn-segment 30205
                vlan 565
                    private-vlan community
                    vn-segment 30565
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 205 565
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name)) 
            testbed.devices[node].configure('''
                vlan 206
                    private-vlan primary
                    private-vlan association 566
                    vn-segment 30206
                vlan 566
                    private-vlan community
                    vn-segment 30566
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 206 566
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))
            testbed.devices[node].configure('''
                vlan 207
                    private-vlan primary
                    private-vlan association 567
                    vn-segment 30207
                vlan 567
                    private-vlan community
                    vn-segment 30567
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 207 567
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))
            testbed.devices[node].configure('''
                vlan 208
                    private-vlan primary
                    private-vlan association 568
                    vn-segment 30208
                vlan 568
                    private-vlan community
                    vn-segment 30568
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 208 568
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name)) 
            testbed.devices[node].configure('''
                vlan 209
                    private-vlan primary
                    private-vlan association 569
                    vn-segment 30209
                vlan 569
                    private-vlan community
                    vn-segment 30569
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 209 569
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))        
            testbed.devices[node].configure('''
                vlan 210
                    private-vlan primary
                    private-vlan association 570
                    vn-segment 30210
                vlan 570
                    private-vlan community
                    vn-segment 30570
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 210 570
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))
            testbed.devices[node].configure('''
                vlan 211
                    private-vlan primary
                    private-vlan association 571
                    vn-segment 30211
                vlan 571
                    private-vlan community
                    vn-segment 30571
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 211 571
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))
            testbed.devices[node].configure('''
                vlan 212
                    private-vlan primary
                    private-vlan association 572
                    vn-segment 30212
                vlan 572
                    private-vlan community
                    vn-segment 30572
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 212 572
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))
            testbed.devices[node].configure('''
                vlan 213
                    private-vlan primary
                    private-vlan association 573
                    vn-segment 30213
                vlan 573
                    private-vlan community
                    vn-segment 30573
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 213 573
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name)) 
            testbed.devices[node].configure('''
                vlan 214
                    private-vlan primary
                    private-vlan association 574
                    vn-segment 30214
                vlan 574
                    private-vlan community
                    vn-segment 30574
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 214 574
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))
            testbed.devices[node].configure('''
                vlan 215
                    private-vlan primary
                    private-vlan association 575
                    vn-segment 30215
                vlan 575
                    private-vlan community
                    vn-segment 30575
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 215 575
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))
            testbed.devices[node].configure('''
                vlan 216
                    private-vlan primary
                    private-vlan association 576
                    vn-segment 30216
                vlan 576
                    private-vlan community
                    vn-segment 30576
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 216 576
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name)) 
            testbed.devices[node].configure('''
                vlan 217
                    private-vlan primary
                    private-vlan association 577
                    vn-segment 30217
                vlan 577
                    private-vlan community
                    vn-segment 30577
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 217 577
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))        
            testbed.devices[node].configure('''
                vlan 218
                    private-vlan primary
                    private-vlan association 578
                    vn-segment 30218
                vlan 578
                    private-vlan community
                    vn-segment 30578
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 218 578
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))
            testbed.devices[node].configure('''
                vlan 219
                    private-vlan primary
                    private-vlan association 579
                    vn-segment 30219
                vlan 579
                    private-vlan community
                    vn-segment 30579
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 219 579
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))
            testbed.devices[node].configure('''
                vlan 220
                    private-vlan primary
                    private-vlan association 580
                    vn-segment 30220
                vlan 580
                    private-vlan community
                    vn-segment 30580
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 220 580
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))
            testbed.devices[node].configure('''
                vlan 221
                    private-vlan primary
                    private-vlan association 581
                    vn-segment 30121
                vlan 581
                    private-vlan community
                    vn-segment 30581
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 221 581
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name)) 
            testbed.devices[node].configure('''
                vlan 222
                    private-vlan primary
                    private-vlan association 582
                    vn-segment 30222
                vlan 582
                    private-vlan community
                    vn-segment 30582
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 222 582
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))
            testbed.devices[node].configure('''
                vlan 223
                    private-vlan primary
                    private-vlan association 583
                    vn-segment 30223
                vlan 583
                    private-vlan community
                    vn-segment 30583
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 223 583
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))
            testbed.devices[node].configure('''
                vlan 224
                    private-vlan primary
                    private-vlan association 584
                    vn-segment 30224
                vlan 584
                    private-vlan community
                    vn-segment 30584
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 224 584
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name)) 
            testbed.devices[node].configure('''
                vlan 225
                    private-vlan primary
                    private-vlan association 585
                    vn-segment 30225
                vlan 585
                    private-vlan community
                    vn-segment 30585
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 225 585
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))        
            testbed.devices[node].configure('''
                vlan 226
                    private-vlan primary
                    private-vlan association 586
                    vn-segment 30226
                vlan 586
                    private-vlan community
                    vn-segment 30526
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 226 586
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))
            testbed.devices[node].configure('''
                vlan 227
                    private-vlan primary
                    private-vlan association 587
                    vn-segment 30227
                vlan 587
                    private-vlan community
                    vn-segment 30587
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 227 587
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))
            testbed.devices[node].configure('''
                vlan 228
                    private-vlan primary
                    private-vlan association 588
                    vn-segment 30228
                vlan 588
                    private-vlan community
                    vn-segment 30588
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 228 588
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))
            testbed.devices[node].configure('''
                vlan 229
                    private-vlan primary
                    private-vlan association 589
                    vn-segment 30229
                vlan 589
                    private-vlan community
                    vn-segment 30589
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 229 589
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name)) 
            testbed.devices[node].configure('''
                vlan 230
                    private-vlan primary
                    private-vlan association 590
                    vn-segment 30230
                vlan 590
                    private-vlan community
                    vn-segment 30590
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 230 590
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))
            testbed.devices[node].configure('''
                vlan 231
                    private-vlan primary
                    private-vlan association 591
                    vn-segment 30231
                vlan 591
                    private-vlan community
                    vn-segment 30591
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 231 591
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))
            testbed.devices[node].configure('''
                vlan 232
                    private-vlan primary
                    private-vlan association 592
                    vn-segment 30232
                vlan 592
                    private-vlan community
                    vn-segment 30592
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 232 592
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))
            testbed.devices[node].configure('''
                vlan 233
                    private-vlan primary
                    private-vlan association 593
                    vn-segment 30233
                vlan 593
                    private-vlan community
                    vn-segment 30593
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 233 593
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name)) 
            testbed.devices[node].configure('''
                vlan 234
                    private-vlan primary
                    private-vlan association 594
                    vn-segment 30234
                vlan 594
                    private-vlan community
                    vn-segment 30594
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 234 594
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))        
            testbed.devices[node].configure('''
                vlan 235
                    private-vlan primary
                    private-vlan association 595
                    vn-segment 30235
                vlan 595
                    private-vlan community
                    vn-segment 30535
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 235 595
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))
            testbed.devices[node].configure('''
                vlan 236
                    private-vlan primary
                    private-vlan association 596
                    vn-segment 30236
                vlan 596
                    private-vlan community
                    vn-segment 30596
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 236 596
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))
            testbed.devices[node].configure('''
                vlan 237
                    private-vlan primary
                    private-vlan association 597
                    vn-segment 30237
                vlan 597
                    private-vlan community
                    vn-segment 30597
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 237 597
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))
            testbed.devices[node].configure('''
                vlan 238
                    private-vlan primary
                    private-vlan association 598
                    vn-segment 30238
                vlan 598
                    private-vlan community
                    vn-segment 30598
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 238 598
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name)) 
            testbed.devices[node].configure('''
                vlan 239
                    private-vlan primary
                    private-vlan association 599
                    vn-segment 30239
                vlan 599
                    private-vlan community
                    vn-segment 30599
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 239 599
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))
            testbed.devices[node].configure('''
                vlan 240
                    private-vlan primary
                    private-vlan association 600
                    vn-segment 30240
                vlan 600
                    private-vlan community
                    vn-segment 30600
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 240 600
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))
            testbed.devices[node].configure('''
                vlan 240
                    private-vlan primary
                    private-vlan association 600
                    vn-segment 30240
                vlan 600
                    private-vlan community
                    vn-segment 30600
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 240 600
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))
            testbed.devices[node].configure('''
                vlan 241
                    private-vlan primary
                    private-vlan association 601
                    vn-segment 30241
                vlan 601
                    private-vlan community
                    vn-segment 30601
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 241 601
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))           
            testbed.devices[node].configure('''
                vlan 242
                    private-vlan primary
                    private-vlan association 602
                    vn-segment 30242
                vlan 602
                    private-vlan community
                    vn-segment 30602
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 242 602
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))          
            testbed.devices[node].configure('''
                vlan 243
                    private-vlan primary
                    private-vlan association 603
                    vn-segment 30243
                vlan 403
                    private-vlan community
                    vn-segment 30603
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 243 603
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))         
            testbed.devices[node].configure('''
                vlan 244
                    private-vlan primary
                    private-vlan association 604
                    vn-segment 30244
                vlan 604
                    private-vlan community
                    vn-segment 30604
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 244 604
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))          
            testbed.devices[node].configure('''
                vlan 245
                    private-vlan primary
                    private-vlan association 605
                    vn-segment 30045
                vlan 605
                    private-vlan community
                    vn-segment 30605
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 245 605
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))         
            testbed.devices[node].configure('''
                vlan 246
                    private-vlan primary
                    private-vlan association 606
                    vn-segment 30246
                vlan 606
                    private-vlan community
                    vn-segment 30606
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 246 606
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))           
            testbed.devices[node].configure('''
                vlan 247
                    private-vlan primary
                    private-vlan association 607
                    vn-segment 30247
                vlan 607
                    private-vlan community
                    vn-segment 30607
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 247 607
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))          
            testbed.devices[node].configure('''
                vlan 248
                    private-vlan primary
                    private-vlan association 608
                    vn-segment 30248
                vlan 608
                    private-vlan community
                    vn-segment 30608
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 248 608
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))          
            testbed.devices[node].configure('''
                vlan 249
                    private-vlan primary
                    private-vlan association 609
                    vn-segment 30249
                vlan 609
                    private-vlan community
                    vn-segment 30609
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 249 609
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name)) 
            testbed.devices[node].configure('''
                vlan 250
                    private-vlan primary
                    private-vlan association 610
                    vn-segment 30250
                vlan 610
                    private-vlan community
                    vn-segment 30610
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 250 610
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))        
            testbed.devices[node].configure('''
                vlan 251
                    private-vlan primary
                    private-vlan association 611
                    vn-segment 30251
                vlan 611
                    private-vlan community
                    vn-segment 30611
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 251 611
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))
            testbed.devices[node].configure('''
                vlan 252
                    private-vlan primary
                    private-vlan association 612
                    vn-segment 30252
                vlan 612
                    private-vlan community
                    vn-segment 30612
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 252 612
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))
            testbed.devices[node].configure('''
                vlan 253
                    private-vlan primary
                    private-vlan association 613
                    vn-segment 30253
                vlan 613
                    private-vlan community
                    vn-segment 30613
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 253 613
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))
            testbed.devices[node].configure('''
                vlan 254
                    private-vlan primary
                    private-vlan association 614
                    vn-segment 30254
                vlan 614
                    private-vlan community
                    vn-segment 30414
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 254 614
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name)) 
            testbed.devices[node].configure('''
                vlan 255
                    private-vlan primary
                    private-vlan association 615
                    vn-segment 30255
                vlan 615
                    private-vlan community
                    vn-segment 30615
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 255 615
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))
            testbed.devices[node].configure('''
                vlan 256
                    private-vlan primary
                    private-vlan association 616
                    vn-segment 30256
                vlan 616
                    private-vlan community
                    vn-segment 30616
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 256 616
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))
            testbed.devices[node].configure('''
                vlan 257
                    private-vlan primary
                    private-vlan association 617
                    vn-segment 30257
                vlan 617
                    private-vlan community
                    vn-segment 30617
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 257 617
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))
            testbed.devices[node].configure('''
                vlan 258
                    private-vlan primary
                    private-vlan association 618
                    vn-segment 30258
                vlan 618
                    private-vlan community
                    vn-segment 30618
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 258 618
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))           
            testbed.devices[node].configure('''
                vlan 259
                    private-vlan primary
                    private-vlan association 619
                    vn-segment 30259
                vlan 619
                    private-vlan community
                    vn-segment 30619
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 259 619
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))          
            testbed.devices[node].configure('''
                vlan 260
                    private-vlan primary
                    private-vlan association 620
                    vn-segment 30260
                vlan 620
                    private-vlan community
                    vn-segment 30620
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 260 620
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))         
            testbed.devices[node].configure('''
                vlan 261
                    private-vlan primary
                    private-vlan association 621
                    vn-segment 30261
                vlan 621
                    private-vlan community
                    vn-segment 30621
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 261 621
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))          
            testbed.devices[node].configure('''
                vlan 262
                    private-vlan primary
                    private-vlan association 622
                    vn-segment 30262
                vlan 622
                    private-vlan community
                    vn-segment 30622
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 262 622
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))         
            testbed.devices[node].configure('''
                vlan 263
                    private-vlan primary
                    private-vlan association 623
                    vn-segment 30263
                vlan 623
                    private-vlan community
                    vn-segment 30623
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 263 623
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))           
            testbed.devices[node].configure('''
                vlan 264
                    private-vlan primary
                    private-vlan association 624
                    vn-segment 30264
                vlan 624
                    private-vlan community
                    vn-segment 30624
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 264 624
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))          
            testbed.devices[node].configure('''
                vlan 265
                    private-vlan primary
                    private-vlan association 625
                    vn-segment 30265
                vlan 625
                    private-vlan community
                    vn-segment 30625
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 265 625
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))          
            testbed.devices[node].configure('''
                vlan 266
                    private-vlan primary
                    private-vlan association 626
                    vn-segment 30266
                vlan 626
                    private-vlan community
                    vn-segment 30626
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 266 626
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name)) 
            testbed.devices[node].configure('''
                vlan 267
                    private-vlan primary
                    private-vlan association 627
                    vn-segment 30267
                vlan 627
                    private-vlan community
                    vn-segment 30627
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 267 627
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))        
            testbed.devices[node].configure('''
                vlan 268
                    private-vlan primary
                    private-vlan association 628
                    vn-segment 30268
                vlan 628
                    private-vlan community
                    vn-segment 30628
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 268 628
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))
            testbed.devices[node].configure('''
                vlan 269
                    private-vlan primary
                    private-vlan association 628
                    vn-segment 30269
                vlan 628
                    private-vlan community
                    vn-segment 30628
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 269 628
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))
            testbed.devices[node].configure('''
                vlan 270
                    private-vlan primary
                    private-vlan association 630
                    vn-segment 30270
                vlan 630
                    private-vlan community
                    vn-segment 30630
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 270 630
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))
            testbed.devices[node].configure('''
                vlan 271
                    private-vlan primary
                    private-vlan association 631
                    vn-segment 30271
                vlan 631
                    private-vlan community
                    vn-segment 30631
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 271 631
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name)) 
            testbed.devices[node].configure('''
                vlan 272
                    private-vlan primary
                    private-vlan association 632
                    vn-segment 30272
                vlan 632
                    private-vlan community
                    vn-segment 30632
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 272 632
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))
            testbed.devices[node].configure('''
                vlan 273
                    private-vlan primary
                    private-vlan association 633
                    vn-segment 30273
                vlan 633
                    private-vlan community
                    vn-segment 30673
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 273 633
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))     
            testbed.devices[node].configure('''
                vlan 274
                    private-vlan primary
                    private-vlan association 634
                    vn-segment 30274
                vlan 634
                    private-vlan community
                    vn-segment 30634
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 274 634
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))
            testbed.devices[node].configure('''
                vlan 275
                    private-vlan primary
                    private-vlan association 635
                    vn-segment 30275
                vlan 635
                    private-vlan community
                    vn-segment 30635
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 275 635
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))           
            testbed.devices[node].configure('''
                vlan 276
                    private-vlan primary
                    private-vlan association 636
                    vn-segment 30276
                vlan 636
                    private-vlan community
                    vn-segment 30636
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 276 636
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))          
            testbed.devices[node].configure('''
                vlan 277
                    private-vlan primary
                    private-vlan association 637
                    vn-segment 30277
                vlan 637
                    private-vlan community
                    vn-segment 30677
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 277 637
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))         
            testbed.devices[node].configure('''
                vlan 278
                    private-vlan primary
                    private-vlan association 638
                    vn-segment 30278
                vlan 638
                    private-vlan community
                    vn-segment 30638
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 278 638
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))          
            testbed.devices[node].configure('''
                vlan 279
                    private-vlan primary
                    private-vlan association 639
                    vn-segment 30279
                vlan 639
                    private-vlan community
                    vn-segment 30639
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 279 639
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))         
            testbed.devices[node].configure('''
                vlan 280
                    private-vlan primary
                    private-vlan association 640
                    vn-segment 30280
                vlan 640
                    private-vlan community
                    vn-segment 30640
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 280 640
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))           
            testbed.devices[node].configure('''
                vlan 281
                    private-vlan primary
                    private-vlan association 641
                    vn-segment 30247
                vlan 641
                    private-vlan community
                    vn-segment 30641
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 281 641
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))          
            testbed.devices[node].configure('''
                vlan 812
                    private-vlan primary
                    private-vlan association 642
                    vn-segment 30282
                vlan 642
                    private-vlan community
                    vn-segment 30642
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 282 642
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))          
            testbed.devices[node].configure('''
                vlan 283
                    private-vlan primary
                    private-vlan association 643
                    vn-segment 30283
                vlan 643
                    private-vlan community
                    vn-segment 30643
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 283 643
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name)) 
            testbed.devices[node].configure('''
                vlan 284
                    private-vlan primary
                    private-vlan association 644
                    vn-segment 30284
                vlan 644
                    private-vlan community
                    vn-segment 30644
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 284 644
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))        
            testbed.devices[node].configure('''
                vlan 285
                    private-vlan primary
                    private-vlan association 645
                    vn-segment 30285
                vlan 645
                    private-vlan community
                    vn-segment 30645
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 285 645
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))
            testbed.devices[node].configure('''
                vlan 286
                    private-vlan primary
                    private-vlan association 646
                    vn-segment 30286
                vlan 646
                    private-vlan community
                    vn-segment 30646
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 286 646
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))
            testbed.devices[node].configure('''
                vlan 287
                    private-vlan primary
                    private-vlan association 647
                    vn-segment 30287
                vlan 647
                    private-vlan community
                    vn-segment 30647
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 287 647
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))
            testbed.devices[node].configure('''
                vlan 288
                    private-vlan primary
                    private-vlan association 648
                    vn-segment 30288
                vlan 648
                    private-vlan community
                    vn-segment 30648
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 288 648
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name)) 
            testbed.devices[node].configure('''
                vlan 289
                    private-vlan primary
                    private-vlan association 649
                    vn-segment 30289
                vlan 649
                    private-vlan community
                    vn-segment 30649
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 289 649
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))
            testbed.devices[node].configure('''
                vlan 290
                    private-vlan primary
                    private-vlan association 650
                    vn-segment 30290
                vlan 650
                    private-vlan community
                    vn-segment 30650
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 290 650
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))
            testbed.devices[node].configure('''
                vlan 291
                    private-vlan primary
                    private-vlan association 651
                    vn-segment 30291
                vlan 651
                    private-vlan community
                    vn-segment 30651
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 291 651
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))
            testbed.devices[node].configure('''
                vlan 292
                    private-vlan primary
                    private-vlan association 652
                    vn-segment 30292
                vlan 652
                    private-vlan community
                    vn-segment 30652
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 292 652
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))           
            testbed.devices[node].configure('''
                vlan 293
                    private-vlan primary
                    private-vlan association 653
                    vn-segment 30093
                vlan 653
                    private-vlan community
                    vn-segment 30653
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 293 653
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))          
            testbed.devices[node].configure('''
                vlan 294
                    private-vlan primary
                    private-vlan association 654
                    vn-segment 30294
                vlan 654
                    private-vlan community
                    vn-segment 30654
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 294 654
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))         
            testbed.devices[node].configure('''
                vlan 295
                    private-vlan primary
                    private-vlan association 655
                    vn-segment 30295
                vlan 655
                    private-vlan community
                    vn-segment 30655
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 295 655
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))          
            testbed.devices[node].configure('''
                vlan 296
                    private-vlan primary
                    private-vlan association 656
                    vn-segment 30296
                vlan 656
                    private-vlan community
                    vn-segment 30656
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 296 656
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))         
            testbed.devices[node].configure('''
                vlan 297
                    private-vlan primary
                    private-vlan association 657
                    vn-segment 30297
                vlan 657
                    private-vlan community
                    vn-segment 30657
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 297 657
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))           
            testbed.devices[node].configure('''
                vlan 298
                    private-vlan primary
                    private-vlan association 658
                    vn-segment 30298
                vlan 658
                    private-vlan community
                    vn-segment 30658
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 298 658
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))          
            testbed.devices[node].configure('''
                vlan 299
                    private-vlan primary
                    private-vlan association 659
                    vn-segment 30099
                vlan 659
                    private-vlan community
                    vn-segment 30659
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 299 659
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))          
            testbed.devices[node].configure('''
                vlan 300
                    private-vlan primary
                    private-vlan association 660
                    vn-segment 30300
                vlan 660
                    private-vlan community
                    vn-segment 30660
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 300 660
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name)) 
            testbed.devices[node].configure('''
                vlan 301
                    private-vlan primary
                    private-vlan association 661
                    vn-segment 30301
                vlan 661
                    private-vlan community
                    vn-segment 30661
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 301 661
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))        
            testbed.devices[node].configure('''
                vlan 302
                    private-vlan primary
                    private-vlan association 662
                    vn-segment 30302
                vlan 662
                    private-vlan community
                    vn-segment 30662
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 302 662
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))
            testbed.devices[node].configure('''
                vlan 303
                    private-vlan primary
                    private-vlan association 663
                    vn-segment 30303
                vlan 663
                    private-vlan community
                    vn-segment 30663
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 303 663
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))
            testbed.devices[node].configure('''
                vlan 304
                    private-vlan primary
                    private-vlan association 664
                    vn-segment 30304
                vlan 664
                    private-vlan community
                    vn-segment 30664
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 304 664
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))
            testbed.devices[node].configure('''
                vlan 305
                    private-vlan primary
                    private-vlan association 665
                    vn-segment 30305
                vlan 665
                    private-vlan community
                    vn-segment 30665
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 305 665
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name)) 
            testbed.devices[node].configure('''
                vlan 306
                    private-vlan primary
                    private-vlan association 666
                    vn-segment 30306
                vlan 666
                    private-vlan community
                    vn-segment 30666
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 306 666
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))
            testbed.devices[node].configure('''
                vlan 307
                    private-vlan primary
                    private-vlan association 667
                    vn-segment 30307
                vlan 667
                    private-vlan community
                    vn-segment 30667
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 307 667
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))
            testbed.devices[node].configure('''
                vlan 308
                    private-vlan primary
                    private-vlan association 668
                    vn-segment 30308
                vlan 668
                    private-vlan community
                    vn-segment 30668
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 308 668
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name)) 
            testbed.devices[node].configure('''
                vlan 309
                    private-vlan primary
                    private-vlan association 669
                    vn-segment 30309
                vlan 669
                    private-vlan community
                    vn-segment 30669
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 309 669
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))        
            testbed.devices[node].configure('''
                vlan 310
                    private-vlan primary
                    private-vlan association 670
                    vn-segment 30310
                vlan 670
                    private-vlan community
                    vn-segment 30670
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 310 670
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))
            testbed.devices[node].configure('''
                vlan 311
                    private-vlan primary
                    private-vlan association 671
                    vn-segment 30311
                vlan 671
                    private-vlan community
                    vn-segment 30671
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 311 671
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))
            testbed.devices[node].configure('''
                vlan 312
                    private-vlan primary
                    private-vlan association 672
                    vn-segment 30312
                vlan 672
                    private-vlan community
                    vn-segment 30672
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 312 672
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))
            testbed.devices[node].configure('''
                vlan 313
                    private-vlan primary
                    private-vlan association 673
                    vn-segment 30313
                vlan 673
                    private-vlan community
                    vn-segment 30673
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 313 673
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name)) 
            testbed.devices[node].configure('''
                vlan 314
                    private-vlan primary
                    private-vlan association 674
                    vn-segment 30314
                vlan 674
                    private-vlan community
                    vn-segment 30674
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 314 674
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))
            testbed.devices[node].configure('''
                vlan 315
                    private-vlan primary
                    private-vlan association 675
                    vn-segment 30315
                vlan 675
                    private-vlan community
                    vn-segment 30675
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 315 675
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))
            testbed.devices[node].configure('''
                vlan 316
                    private-vlan primary
                    private-vlan association 676
                    vn-segment 30316
                vlan 676
                    private-vlan community
                    vn-segment 30676
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 316 676
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name)) 
            testbed.devices[node].configure('''
                vlan 317
                    private-vlan primary
                    private-vlan association 677
                    vn-segment 30317
                vlan 677
                    private-vlan community
                    vn-segment 30677
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 317 677
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))        
            testbed.devices[node].configure('''
                vlan 318
                    private-vlan primary
                    private-vlan association 678
                    vn-segment 30318
                vlan 678
                    private-vlan community
                    vn-segment 30678
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 318 678
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))
            testbed.devices[node].configure('''
                vlan 319
                    private-vlan primary
                    private-vlan association 679
                    vn-segment 30319
                vlan 679
                    private-vlan community
                    vn-segment 30679
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 319 679
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))
            testbed.devices[node].configure('''
                vlan 320
                    private-vlan primary
                    private-vlan association 680
                    vn-segment 30320
                vlan 680
                    private-vlan community
                    vn-segment 30680
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 320 680
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))
            testbed.devices[node].configure('''
                vlan 321
                    private-vlan primary
                    private-vlan association 681
                    vn-segment 30121
                vlan 681
                    private-vlan community
                    vn-segment 30681
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 321 681
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name)) 
            testbed.devices[node].configure('''
                vlan 322
                    private-vlan primary
                    private-vlan association 682
                    vn-segment 30322
                vlan 682
                    private-vlan community
                    vn-segment 30682
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 322 682
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))
            testbed.devices[node].configure('''
                vlan 323
                    private-vlan primary
                    private-vlan association 683
                    vn-segment 30323
                vlan 683
                    private-vlan community
                    vn-segment 30683
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 323 683
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))
            testbed.devices[node].configure('''
                vlan 324
                    private-vlan primary
                    private-vlan association 684
                    vn-segment 30324
                vlan 684
                    private-vlan community
                    vn-segment 30684
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 324 684
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name)) 
            testbed.devices[node].configure('''
                vlan 325
                    private-vlan primary
                    private-vlan association 685
                    vn-segment 30325
                vlan 685
                    private-vlan community
                    vn-segment 30685
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 325 685
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))        
            testbed.devices[node].configure('''
                vlan 326
                    private-vlan primary
                    private-vlan association 686
                    vn-segment 30326
                vlan 686
                    private-vlan community
                    vn-segment 30626
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 326 686
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))
            testbed.devices[node].configure('''
                vlan 327
                    private-vlan primary
                    private-vlan association 687
                    vn-segment 30327
                vlan 687
                    private-vlan community
                    vn-segment 30687
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 327 687
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))
            testbed.devices[node].configure('''
                vlan 328
                    private-vlan primary
                    private-vlan association 688
                    vn-segment 30328
                vlan 688
                    private-vlan community
                    vn-segment 30688
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 328 688
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))
            testbed.devices[node].configure('''
                vlan 329
                    private-vlan primary
                    private-vlan association 689
                    vn-segment 30329
                vlan 689
                    private-vlan community
                    vn-segment 30689
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 329 689
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name)) 
            testbed.devices[node].configure('''
                vlan 330
                    private-vlan primary
                    private-vlan association 690
                    vn-segment 30330
                vlan 690
                    private-vlan community
                    vn-segment 30690
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 330 690
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))
            testbed.devices[node].configure('''
                vlan 331
                    private-vlan primary
                    private-vlan association 691
                    vn-segment 30331
                vlan 691
                    private-vlan community
                    vn-segment 30691
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 331 691
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))
            testbed.devices[node].configure('''
                vlan 332
                    private-vlan primary
                    private-vlan association 692
                    vn-segment 30332
                vlan 692
                    private-vlan community
                    vn-segment 30692
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 332 692
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))
            testbed.devices[node].configure('''
                vlan 333
                    private-vlan primary
                    private-vlan association 693
                    vn-segment 30333
                vlan 693
                    private-vlan community
                    vn-segment 30693
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 333 693
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name)) 
            testbed.devices[node].configure('''
                vlan 334
                    private-vlan primary
                    private-vlan association 694
                    vn-segment 30334
                vlan 694
                    private-vlan community
                    vn-segment 30694
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 334 694
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))        
            testbed.devices[node].configure('''
                vlan 335
                    private-vlan primary
                    private-vlan association 695
                    vn-segment 30335
                vlan 695
                    private-vlan community
                    vn-segment 30635
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 335 695
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))
            testbed.devices[node].configure('''
                vlan 336
                    private-vlan primary
                    private-vlan association 696
                    vn-segment 30336
                vlan 696
                    private-vlan community
                    vn-segment 30696
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 336 696
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))
            testbed.devices[node].configure('''
                vlan 337
                    private-vlan primary
                    private-vlan association 697
                    vn-segment 30337
                vlan 697
                    private-vlan community
                    vn-segment 30697
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 337 697
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))
            testbed.devices[node].configure('''
                vlan 338
                    private-vlan primary
                    private-vlan association 698
                    vn-segment 30338
                vlan 698
                    private-vlan community
                    vn-segment 30698
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 338 698
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name)) 
            testbed.devices[node].configure('''
                vlan 339
                    private-vlan primary
                    private-vlan association 699
                    vn-segment 30339
                vlan 699
                    private-vlan community
                    vn-segment 30699
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 339 699
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))
            testbed.devices[node].configure('''
                vlan 340
                    private-vlan primary
                    private-vlan association 700
                    vn-segment 30340
                vlan 700
                    private-vlan community
                    vn-segment 30700
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 340 700
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))
            testbed.devices[node].configure('''
                vlan 341
                    private-vlan primary
                    private-vlan association 701
                    vn-segment 30341
                vlan 701
                    private-vlan community
                    vn-segment 30701
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 341 701
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))           
            testbed.devices[node].configure('''
                vlan 342
                    private-vlan primary
                    private-vlan association 702
                    vn-segment 30342
                vlan 702
                    private-vlan community
                    vn-segment 30702
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 342 702
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))          
            testbed.devices[node].configure('''
                vlan 343
                    private-vlan primary
                    private-vlan association 703
                    vn-segment 30343
                vlan 403
                    private-vlan community
                    vn-segment 30703
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 343 703
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))         
            testbed.devices[node].configure('''
                vlan 344
                    private-vlan primary
                    private-vlan association 704
                    vn-segment 30344
                vlan 704
                    private-vlan community
                    vn-segment 30704
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 344 704
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))          
            testbed.devices[node].configure('''
                vlan 345
                    private-vlan primary
                    private-vlan association 705
                    vn-segment 40045
                vlan 705
                    private-vlan community
                    vn-segment 30705
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 345 705
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))         
            testbed.devices[node].configure('''
                vlan 346
                    private-vlan primary
                    private-vlan association 706
                    vn-segment 30346
                vlan 706
                    private-vlan community
                    vn-segment 30706
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 346 706
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))           
            testbed.devices[node].configure('''
                vlan 347
                    private-vlan primary
                    private-vlan association 707
                    vn-segment 30347
                vlan 707
                    private-vlan community
                    vn-segment 30707
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 347 707
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))          
            testbed.devices[node].configure('''
                vlan 348
                    private-vlan primary
                    private-vlan association 708
                    vn-segment 30348
                vlan 708
                    private-vlan community
                    vn-segment 30708
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 348 708
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))          
            testbed.devices[node].configure('''
                vlan 349
                    private-vlan primary
                    private-vlan association 709
                    vn-segment 30349
                vlan 709
                    private-vlan community
                    vn-segment 30709
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 349 709
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name)) 
            testbed.devices[node].configure('''
                vlan 350
                    private-vlan primary
                    private-vlan association 710
                    vn-segment 30350
                vlan 710
                    private-vlan community
                    vn-segment 30710
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 350 710
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))        
            testbed.devices[node].configure('''
                vlan 351
                    private-vlan primary
                    private-vlan association 711
                    vn-segment 30351
                vlan 711
                    private-vlan community
                    vn-segment 30711
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 351 711
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))
            testbed.devices[node].configure('''
                vlan 352
                    private-vlan primary
                    private-vlan association 712
                    vn-segment 30352
                vlan 712
                    private-vlan community
                    vn-segment 30712
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 352 712
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))
            testbed.devices[node].configure('''
                vlan 353
                    private-vlan primary
                    private-vlan association 713
                    vn-segment 30353
                vlan 713
                    private-vlan community
                    vn-segment 30713
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 353 713
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))
            testbed.devices[node].configure('''
                vlan 354
                    private-vlan primary
                    private-vlan association 714
                    vn-segment 30354
                vlan 714
                    private-vlan community
                    vn-segment 30714
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 354 714
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name)) 
            testbed.devices[node].configure('''
                vlan 355
                    private-vlan primary
                    private-vlan association 715
                    vn-segment 30355
                vlan 715
                    private-vlan community
                    vn-segment 30715
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 355 715
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))
            testbed.devices[node].configure('''
                vlan 356
                    private-vlan primary
                    private-vlan association 716
                    vn-segment 30356
                vlan 716
                    private-vlan community
                    vn-segment 30716
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 356 716
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))
            testbed.devices[node].configure('''
                vlan 357
                    private-vlan primary
                    private-vlan association 717
                    vn-segment 30357
                vlan 717
                    private-vlan community
                    vn-segment 30717
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 357 717
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))
            testbed.devices[node].configure('''
                vlan 358
                    private-vlan primary
                    private-vlan association 718
                    vn-segment 30358
                vlan 718
                    private-vlan community
                    vn-segment 30718
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 358 718
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))           
            testbed.devices[node].configure('''
                vlan 359
                    private-vlan primary
                    private-vlan association 719
                    vn-segment 30359
                vlan 719
                    private-vlan community
                    vn-segment 30719
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 359 719
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))          
            testbed.devices[node].configure('''
                vlan 360
                    private-vlan primary
                    private-vlan association 720
                    vn-segment 30360
                vlan 720
                    private-vlan community
                    vn-segment 30720
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 360 720
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))         
            testbed.devices[node].configure('''
                vlan 361
                    private-vlan primary
                    private-vlan association 721
                    vn-segment 30361
                vlan 721
                    private-vlan community
                    vn-segment 30721
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 361 721
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))          
            testbed.devices[node].configure('''
                vlan 362
                    private-vlan primary
                    private-vlan association 722
                    vn-segment 30362
                vlan 722
                    private-vlan community
                    vn-segment 30722
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 362 722
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))         
            testbed.devices[node].configure('''
                vlan 263
                    private-vlan primary
                    private-vlan association 723
                    vn-segment 40263
                vlan 723
                    private-vlan community
                    vn-segment 30723
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 263 723
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))           
            testbed.devices[node].configure('''
                vlan 364
                    private-vlan primary
                    private-vlan association 724
                    vn-segment 30364
                vlan 724
                    private-vlan community
                    vn-segment 30724
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 364 724
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))          
            testbed.devices[node].configure('''
                vlan 365
                    private-vlan primary
                    private-vlan association 725
                    vn-segment 30365
                vlan 725
                    private-vlan community
                    vn-segment 30725
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 365 725
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))          
            testbed.devices[node].configure('''
                vlan 366
                    private-vlan primary
                    private-vlan association 726
                    vn-segment 30366
                vlan 726
                    private-vlan community
                    vn-segment 30726
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 366 726
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name)) 
            testbed.devices[node].configure('''
                vlan 367
                    private-vlan primary
                    private-vlan association 727
                    vn-segment 30367
                vlan 727
                    private-vlan community
                    vn-segment 30727
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 367 727
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))        
            testbed.devices[node].configure('''
                vlan 368
                    private-vlan primary
                    private-vlan association 728
                    vn-segment 30368
                vlan 728
                    private-vlan community
                    vn-segment 30728
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 368 728
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))
            testbed.devices[node].configure('''
                vlan 369
                    private-vlan primary
                    private-vlan association 728
                    vn-segment 30369
                vlan 728
                    private-vlan community
                    vn-segment 30728
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 369 728
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))
            testbed.devices[node].configure('''
                vlan 370
                    private-vlan primary
                    private-vlan association 730
                    vn-segment 30370
                vlan 730
                    private-vlan community
                    vn-segment 30730
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 370 730
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))
            testbed.devices[node].configure('''
                vlan 371
                    private-vlan primary
                    private-vlan association 731
                    vn-segment 30371
                vlan 731
                    private-vlan community
                    vn-segment 30731
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 371 731
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name)) 
            testbed.devices[node].configure('''
                vlan 372
                    private-vlan primary
                    private-vlan association 732
                    vn-segment 30372
                vlan 732
                    private-vlan community
                    vn-segment 30732
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 372 732
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))
            testbed.devices[node].configure('''
                vlan 373
                    private-vlan primary
                    private-vlan association 733
                    vn-segment 30373
                vlan 733
                    private-vlan community
                    vn-segment 30773
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 373 733
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))     
            testbed.devices[node].configure('''
                vlan 374
                    private-vlan primary
                    private-vlan association 734
                    vn-segment 30374
                vlan 734
                    private-vlan community
                    vn-segment 30734
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 374 734
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))
            testbed.devices[node].configure('''
                vlan 375
                    private-vlan primary
                    private-vlan association 735
                    vn-segment 30375
                vlan 735
                    private-vlan community
                    vn-segment 30735
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 375 735
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))           
            testbed.devices[node].configure('''
                vlan 376
                    private-vlan primary
                    private-vlan association 736
                    vn-segment 30376
                vlan 736
                    private-vlan community
                    vn-segment 30736
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 376 736
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))          
            testbed.devices[node].configure('''
                vlan 377
                    private-vlan primary
                    private-vlan association 737
                    vn-segment 30377
                vlan 737
                    private-vlan community
                    vn-segment 30777
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 377 737
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))         
            testbed.devices[node].configure('''
                vlan 378
                    private-vlan primary
                    private-vlan association 738
                    vn-segment 30378
                vlan 738
                    private-vlan community
                    vn-segment 30738
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 378 738
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))          
            testbed.devices[node].configure('''
                vlan 379
                    private-vlan primary
                    private-vlan association 739
                    vn-segment 30379
                vlan 739
                    private-vlan community
                    vn-segment 30739
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 379 739
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))         
            testbed.devices[node].configure('''
                vlan 380
                    private-vlan primary
                    private-vlan association 740
                    vn-segment 30380
                vlan 740
                    private-vlan community
                    vn-segment 30740
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 380 740
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))           
            testbed.devices[node].configure('''
                vlan 381
                    private-vlan primary
                    private-vlan association 741
                    vn-segment 30381
                vlan 741
                    private-vlan community
                    vn-segment 30741
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 381 741
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))          
            testbed.devices[node].configure('''
                vlan 812
                    private-vlan primary
                    private-vlan association 742
                    vn-segment 30382
                vlan 742
                    private-vlan community
                    vn-segment 30742
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 382 742
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))          
            testbed.devices[node].configure('''
                vlan 383
                    private-vlan primary
                    private-vlan association 743
                    vn-segment 30383
                vlan 743
                    private-vlan community
                    vn-segment 30743
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 383 743
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name)) 
            testbed.devices[node].configure('''
                vlan 384
                    private-vlan primary
                    private-vlan association 744
                    vn-segment 30384
                vlan 744
                    private-vlan community
                    vn-segment 30744
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 384 744
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))        
            testbed.devices[node].configure('''
                vlan 385
                    private-vlan primary
                    private-vlan association 745
                    vn-segment 30385
                vlan 745
                    private-vlan community
                    vn-segment 30745
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 385 745
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))
            testbed.devices[node].configure('''
                vlan 386
                    private-vlan primary
                    private-vlan association 746
                    vn-segment 30386
                vlan 746
                    private-vlan community
                    vn-segment 30746
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 386 746
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))
            testbed.devices[node].configure('''
                vlan 387
                    private-vlan primary
                    private-vlan association 747
                    vn-segment 30387
                vlan 747
                    private-vlan community
                    vn-segment 30747
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 387 747
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))
            testbed.devices[node].configure('''
                vlan 388
                    private-vlan primary
                    private-vlan association 748
                    vn-segment 30388
                vlan 748
                    private-vlan community
                    vn-segment 30748
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 388 748
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name)) 
            testbed.devices[node].configure('''
                vlan 389
                    private-vlan primary
                    private-vlan association 749
                    vn-segment 30389
                vlan 749
                    private-vlan community
                    vn-segment 30749
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 389 749
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))
            testbed.devices[node].configure('''
                vlan 390
                    private-vlan primary
                    private-vlan association 750
                    vn-segment 30390
                vlan 750
                    private-vlan community
                    vn-segment 30750
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 390 750
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))
            testbed.devices[node].configure('''
                vlan 391
                    private-vlan primary
                    private-vlan association 751
                    vn-segment 30391
                vlan 751
                    private-vlan community
                    vn-segment 30751
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 391 751
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))
            testbed.devices[node].configure('''
                vlan 392
                    private-vlan primary
                    private-vlan association 752
                    vn-segment 30392
                vlan 752
                    private-vlan community
                    vn-segment 30752
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 392 752
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))           
            testbed.devices[node].configure('''
                vlan 393
                    private-vlan primary
                    private-vlan association 753
                    vn-segment 30393
                vlan 753
                    private-vlan community
                    vn-segment 30753
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 393 753
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))          
            testbed.devices[node].configure('''
                vlan 394
                    private-vlan primary
                    private-vlan association 754
                    vn-segment 30394
                vlan 754
                    private-vlan community
                    vn-segment 30754
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 394 754
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))         
            testbed.devices[node].configure('''
                vlan 395
                    private-vlan primary
                    private-vlan association 755
                    vn-segment 30395
                vlan 755
                    private-vlan community
                    vn-segment 30755
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 395 755
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))          
            testbed.devices[node].configure('''
                vlan 396
                    private-vlan primary
                    private-vlan association 756
                    vn-segment 30396
                vlan 756
                    private-vlan community
                    vn-segment 30756
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 396 756
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))         
            testbed.devices[node].configure('''
                vlan 397
                    private-vlan primary
                    private-vlan association 757
                    vn-segment 30397
                vlan 757
                    private-vlan community
                    vn-segment 30757
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 397 757
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))           
            testbed.devices[node].configure('''
                vlan 398
                    private-vlan primary
                    private-vlan association 758
                    vn-segment 30398
                vlan 758
                    private-vlan community
                    vn-segment 30758
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 398 758
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))          
            testbed.devices[node].configure('''
                vlan 399
                    private-vlan primary
                    private-vlan association 759
                    vn-segment 30399
                vlan 759
                    private-vlan community
                    vn-segment 30759
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 399 759
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))          
            testbed.devices[node].configure('''
                vlan 400
                    private-vlan primary
                    private-vlan association 760
                    vn-segment 30400
                vlan 760
                    private-vlan community
                    vn-segment 30760
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 400 760
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name)) 
            testbed.devices[node].configure('''
                vlan 401
                    private-vlan primary
                    private-vlan association 761
                    vn-segment 30401
                vlan 761
                    private-vlan community
                    vn-segment 30761
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 401 761
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))        
            testbed.devices[node].configure('''
                vlan 402
                    private-vlan primary
                    private-vlan association 762
                    vn-segment 30402
                vlan 762
                    private-vlan community
                    vn-segment 30762
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 402 762
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))
            testbed.devices[node].configure('''
                vlan 303
                    private-vlan primary
                    private-vlan association 763
                    vn-segment 30303
                vlan 763
                    private-vlan community
                    vn-segment 30763
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 303 763
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))
            testbed.devices[node].configure('''
                vlan 304
                    private-vlan primary
                    private-vlan association 764
                    vn-segment 30304
                vlan 764
                    private-vlan community
                    vn-segment 30764
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 304 764
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))
            testbed.devices[node].configure('''
                vlan 405
                    private-vlan primary
                    private-vlan association 765
                    vn-segment 30305
                vlan 765
                    private-vlan community
                    vn-segment 30765
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 305 765
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name)) 
            testbed.devices[node].configure('''
                vlan 306
                    private-vlan primary
                    private-vlan association 766
                    vn-segment 30306
                vlan 766
                    private-vlan community
                    vn-segment 30766
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 306 766
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))
            testbed.devices[node].configure('''
                vlan 407
                    private-vlan primary
                    private-vlan association 767
                    vn-segment 30407
                vlan 767
                    private-vlan community
                    vn-segment 30767
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 407 767
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))
            testbed.devices[node].configure('''
                vlan 408
                    private-vlan primary
                    private-vlan association 768
                    vn-segment 30408
                vlan 768
                    private-vlan community
                    vn-segment 30768
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 408 768
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name)) 
            testbed.devices[node].configure('''
                vlan 409
                    private-vlan primary
                    private-vlan association 769
                    vn-segment 30409
                vlan 769
                    private-vlan community
                    vn-segment 30769
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 409 769
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))        
            testbed.devices[node].configure('''
                vlan 410
                    private-vlan primary
                    private-vlan association 770
                    vn-segment 30410
                vlan 770
                    private-vlan community
                    vn-segment 30770
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 410 770
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))
            testbed.devices[node].configure('''
                vlan 411
                    private-vlan primary
                    private-vlan association 771
                    vn-segment 30411
                vlan 771
                    private-vlan community
                    vn-segment 30771
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 411 771
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))
            testbed.devices[node].configure('''
                vlan 412
                    private-vlan primary
                    private-vlan association 772
                    vn-segment 30412
                vlan 772
                    private-vlan community
                    vn-segment 30772
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 412 772
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))
            testbed.devices[node].configure('''
                vlan 413
                    private-vlan primary
                    private-vlan association 773
                    vn-segment 30413
                vlan 773
                    private-vlan community
                    vn-segment 30773
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 413 773
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name)) 
            testbed.devices[node].configure('''
                vlan 414
                    private-vlan primary
                    private-vlan association 774
                    vn-segment 30414
                vlan 774
                    private-vlan community
                    vn-segment 30774
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 414 774
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))
            testbed.devices[node].configure('''
                vlan 415
                    private-vlan primary
                    private-vlan association 775
                    vn-segment 30415
                vlan 775
                    private-vlan community
                    vn-segment 30775
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 415 775
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))
            testbed.devices[node].configure('''
                vlan 416
                    private-vlan primary
                    private-vlan association 776
                    vn-segment 30416
                vlan 776
                    private-vlan community
                    vn-segment 30776
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 416 776
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name)) 
            testbed.devices[node].configure('''
                vlan 417
                    private-vlan primary
                    private-vlan association 777
                    vn-segment 30417
                vlan 777
                    private-vlan community
                    vn-segment 30777
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 417 777
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))        
            testbed.devices[node].configure('''
                vlan 418
                    private-vlan primary
                    private-vlan association 778
                    vn-segment 30418
                vlan 778
                    private-vlan community
                    vn-segment 30778
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 418 778
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))
            testbed.devices[node].configure('''
                vlan 419
                    private-vlan primary
                    private-vlan association 779
                    vn-segment 30419
                vlan 779
                    private-vlan community
                    vn-segment 30779
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 419 779
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))
            testbed.devices[node].configure('''
                vlan 420
                    private-vlan primary
                    private-vlan association 780
                    vn-segment 30420
                vlan 780
                    private-vlan community
                    vn-segment 30780
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 420 780
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))
            testbed.devices[node].configure('''
                vlan 421
                    private-vlan primary
                    private-vlan association 781
                    vn-segment 40421
                vlan 781
                    private-vlan community
                    vn-segment 30781
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 421 781
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name)) 
            testbed.devices[node].configure('''
                vlan 422
                    private-vlan primary
                    private-vlan association 782
                    vn-segment 30422
                vlan 782
                    private-vlan community
                    vn-segment 30782
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 422 782
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))
            testbed.devices[node].configure('''
                vlan 423
                    private-vlan primary
                    private-vlan association 783
                    vn-segment 30423
                vlan 783
                    private-vlan community
                    vn-segment 30783
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 423 783
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))
            testbed.devices[node].configure('''
                vlan 424
                    private-vlan primary
                    private-vlan association 784
                    vn-segment 30424
                vlan 784
                    private-vlan community
                    vn-segment 30784
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 424 784
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name)) 
            testbed.devices[node].configure('''
                vlan 425
                    private-vlan primary
                    private-vlan association 785
                    vn-segment 30425
                vlan 785
                    private-vlan community
                    vn-segment 30785
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 425 785
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))        
            testbed.devices[node].configure('''
                vlan 426
                    private-vlan primary
                    private-vlan association 786
                    vn-segment 30426
                vlan 786
                    private-vlan community
                    vn-segment 30726
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 426 786
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))
            testbed.devices[node].configure('''
                vlan 427
                    private-vlan primary
                    private-vlan association 787
                    vn-segment 30427
                vlan 787
                    private-vlan community
                    vn-segment 30787
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 427 787
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))
            testbed.devices[node].configure('''
                vlan 428
                    private-vlan primary
                    private-vlan association 788
                    vn-segment 30428
                vlan 788
                    private-vlan community
                    vn-segment 30788
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 428 788
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))
            testbed.devices[node].configure('''
                vlan 429
                    private-vlan primary
                    private-vlan association 789
                    vn-segment 30429
                vlan 789
                    private-vlan community
                    vn-segment 30789
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 429 789
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name)) 
            testbed.devices[node].configure('''
                vlan 430
                    private-vlan primary
                    private-vlan association 790
                    vn-segment 30430
                vlan 790
                    private-vlan community
                    vn-segment 30790
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 430 790
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))
            testbed.devices[node].configure('''
                vlan 431
                    private-vlan primary
                    private-vlan association 791
                    vn-segment 30431
                vlan 791
                    private-vlan community
                    vn-segment 30791
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 431 791
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))
            testbed.devices[node].configure('''
                vlan 432
                    private-vlan primary
                    private-vlan association 792
                    vn-segment 30432
                vlan 792
                    private-vlan community
                    vn-segment 30792
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 432 792
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))
            testbed.devices[node].configure('''
                vlan 433
                    private-vlan primary
                    private-vlan association 793
                    vn-segment 30433
                vlan 793
                    private-vlan community
                    vn-segment 30793
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 433 793
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name)) 
            testbed.devices[node].configure('''
                vlan 434
                    private-vlan primary
                    private-vlan association 794
                    vn-segment 30434
                vlan 794
                    private-vlan community
                    vn-segment 30794
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 434 794
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))        
            testbed.devices[node].configure('''
                vlan 435
                    private-vlan primary
                    private-vlan association 795
                    vn-segment 30435
                vlan 795
                    private-vlan community
                    vn-segment 30735
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 435 795
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))
            testbed.devices[node].configure('''
                vlan 436
                    private-vlan primary
                    private-vlan association 796
                    vn-segment 30436
                vlan 796
                    private-vlan community
                    vn-segment 30796
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 436 796
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))
            testbed.devices[node].configure('''
                vlan 437
                    private-vlan primary
                    private-vlan association 797
                    vn-segment 30437
                vlan 797
                    private-vlan community
                    vn-segment 30797
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 437 797
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))
            testbed.devices[node].configure('''
                vlan 438
                    private-vlan primary
                    private-vlan association 798
                    vn-segment 30438
                vlan 798
                    private-vlan community
                    vn-segment 30798
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 438 798
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name)) 
            testbed.devices[node].configure('''
                vlan 439
                    private-vlan primary
                    private-vlan association 799
                    vn-segment 30439
                vlan 799
                    private-vlan community
                    vn-segment 30799
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 439 799
                    no shutdown
                default int {0}
                no vlan 40-99
                no vlan 103-440
                '''.format(testbed.devices[node].interfaces[int].name))  

class multiple_primary_secondary_ports_isolated(nxtest.Testcase):
    # configured 400 isolated primary and secondary vlans on tecate-1 and sumpin e1/5
    @aetest.test
    def multiple_primary_secondary_ports_isolated(self, testbed,testscript,device_dut,int):
        for node in device_dut:
            testbed.devices[node].configure('''                
                vlan 40
                    private-vlan primary
                    private-vlan association 400
                    vn-segment 30040
                vlan 400
                    private-vlan isolated
                    vn-segment 30400
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 40 400
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name)) 
            testbed.devices[node].configure('''
                vlan 41
                    private-vlan primary
                    private-vlan association 401
                    vn-segment 30041
                vlan 401
                    private-vlan isolated
                    vn-segment 30401
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 41 401
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))           
            testbed.devices[node].configure('''
                vlan 42
                    private-vlan primary
                    private-vlan association 402
                    vn-segment 30042
                vlan 402
                    private-vlan isolated
                    vn-segment 30402
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 42 402
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))          
            testbed.devices[node].configure('''
                vlan 43
                    private-vlan primary
                    private-vlan association 403
                    vn-segment 30043
                vlan 403
                    private-vlan isolated
                    vn-segment 30403
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 43 403
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))         
            testbed.devices[node].configure('''
                vlan 44
                    private-vlan primary
                    private-vlan association 404
                    vn-segment 30044
                vlan 404
                    private-vlan isolated
                    vn-segment 30404
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 44 404
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))          
            testbed.devices[node].configure('''
                vlan 45
                    private-vlan primary
                    private-vlan association 405
                    vn-segment 30045
                vlan 405
                    private-vlan isolated
                    vn-segment 30405
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 45 405
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))         
            testbed.devices[node].configure('''
                vlan 46
                    private-vlan primary
                    private-vlan association 406
                    vn-segment 30046
                vlan 406
                    private-vlan isolated
                    vn-segment 30406
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 46 406
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))           
            testbed.devices[node].configure('''
                vlan 47
                    private-vlan primary
                    private-vlan association 407
                    vn-segment 30047
                vlan 407
                    private-vlan isolated
                    vn-segment 30407
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 47 407
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))          
            testbed.devices[node].configure('''
                vlan 48
                    private-vlan primary
                    private-vlan association 408
                    vn-segment 30048
                vlan 408
                    private-vlan isolated
                    vn-segment 30408
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 48 408
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))          
            testbed.devices[node].configure('''
                vlan 49
                    private-vlan primary
                    private-vlan association 409
                    vn-segment 30049
                vlan 409
                    private-vlan isolated
                    vn-segment 30409
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 49 409
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name)) 
            testbed.devices[node].configure('''
                vlan 50
                    private-vlan primary
                    private-vlan association 410
                    vn-segment 30050
                vlan 410
                    private-vlan isolated
                    vn-segment 30410
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 50 410
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))        
            testbed.devices[node].configure('''
                vlan 51
                    private-vlan primary
                    private-vlan association 411
                    vn-segment 30051
                vlan 411
                    private-vlan isolated
                    vn-segment 30411
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 51 411
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))
            testbed.devices[node].configure('''
                vlan 52
                    private-vlan primary
                    private-vlan association 412
                    vn-segment 30052
                vlan 412
                    private-vlan isolated
                    vn-segment 30412
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 52 412
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))
            testbed.devices[node].configure('''
                vlan 53
                    private-vlan primary
                    private-vlan association 413
                    vn-segment 30053
                vlan 413
                    private-vlan isolated
                    vn-segment 30413
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 53 413
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))
            testbed.devices[node].configure('''
                vlan 54
                    private-vlan primary
                    private-vlan association 414
                    vn-segment 30054
                vlan 414
                    private-vlan isolated
                    vn-segment 30414
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 54 414
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name)) 
            testbed.devices[node].configure('''
                vlan 55
                    private-vlan primary
                    private-vlan association 415
                    vn-segment 30055
                vlan 415
                    private-vlan isolated
                    vn-segment 30415
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 55 415
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))
            testbed.devices[node].configure('''
                vlan 56
                    private-vlan primary
                    private-vlan association 416
                    vn-segment 30056
                vlan 416
                    private-vlan isolated
                    vn-segment 30416
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 56 416
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))
            testbed.devices[node].configure('''
                vlan 57
                    private-vlan primary
                    private-vlan association 417
                    vn-segment 30057
                vlan 417
                    private-vlan isolated
                    vn-segment 30417
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 57 417
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))
            testbed.devices[node].configure('''
                vlan 58
                    private-vlan primary
                    private-vlan association 418
                    vn-segment 30058
                vlan 418
                    private-vlan isolated
                    vn-segment 30418
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 58 418
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))           
            testbed.devices[node].configure('''
                vlan 59
                    private-vlan primary
                    private-vlan association 419
                    vn-segment 30059
                vlan 419
                    private-vlan isolated
                    vn-segment 30419
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 59 419
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))          
            testbed.devices[node].configure('''
                vlan 60
                    private-vlan primary
                    private-vlan association 420
                    vn-segment 30060
                vlan 420
                    private-vlan isolated
                    vn-segment 30420
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 60 420
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))         
            testbed.devices[node].configure('''
                vlan 61
                    private-vlan primary
                    private-vlan association 421
                    vn-segment 30061
                vlan 421
                    private-vlan isolated
                    vn-segment 30421
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 61 421
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))          
            testbed.devices[node].configure('''
                vlan 62
                    private-vlan primary
                    private-vlan association 422
                    vn-segment 30062
                vlan 422
                    private-vlan isolated
                    vn-segment 30422
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 62 422
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))         
            testbed.devices[node].configure('''
                vlan 63
                    private-vlan primary
                    private-vlan association 423
                    vn-segment 30063
                vlan 423
                    private-vlan isolated
                    vn-segment 30423
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 63 423
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))           
            testbed.devices[node].configure('''
                vlan 64
                    private-vlan primary
                    private-vlan association 424
                    vn-segment 30064
                vlan 424
                    private-vlan isolated
                    vn-segment 30424
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 64 424
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))          
            testbed.devices[node].configure('''
                vlan 65
                    private-vlan primary
                    private-vlan association 425
                    vn-segment 30065
                vlan 425
                    private-vlan isolated
                    vn-segment 30425
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 65 425
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))          
            testbed.devices[node].configure('''
                vlan 66
                    private-vlan primary
                    private-vlan association 426
                    vn-segment 30066
                vlan 426
                    private-vlan isolated
                    vn-segment 30426
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 66 426
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name)) 
            testbed.devices[node].configure('''
                vlan 67
                    private-vlan primary
                    private-vlan association 427
                    vn-segment 30067
                vlan 427
                    private-vlan isolated
                    vn-segment 30427
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 67 427
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))        
            testbed.devices[node].configure('''
                vlan 68
                    private-vlan primary
                    private-vlan association 428
                    vn-segment 30068
                vlan 428
                    private-vlan isolated
                    vn-segment 30428
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 68 428
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))
            testbed.devices[node].configure('''
                vlan 69
                    private-vlan primary
                    private-vlan association 429
                    vn-segment 30069
                vlan 429
                    private-vlan isolated
                    vn-segment 30429
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 69 429
                    no shut
                '''.format(testbed.devices[node].interfaces[int].name))
            testbed.devices[node].configure('''
                vlan 70
                    private-vlan primary
                    private-vlan association 430
                    vn-segment 30070
                vlan 430
                    private-vlan isolated
                    vn-segment 30430
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 70 430
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))
            testbed.devices[node].configure('''
                vlan 71
                    private-vlan primary
                    private-vlan association 431
                    vn-segment 30071
                vlan 431
                    private-vlan isolated
                    vn-segment 30431
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 71 431
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name)) 
            testbed.devices[node].configure('''
                vlan 72
                    private-vlan primary
                    private-vlan association 432
                    vn-segment 30072
                vlan 432
                    private-vlan isolated
                    vn-segment 30432
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 72 432
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))
            testbed.devices[node].configure('''
                vlan 73
                    private-vlan primary
                    private-vlan association 433
                    vn-segment 30073
                vlan 433
                    private-vlan isolated
                    vn-segment 30473
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 73 433
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))     
            testbed.devices[node].configure('''
                vlan 74
                    private-vlan primary
                    private-vlan association 434
                    vn-segment 30074
                vlan 434
                    private-vlan isolated
                    vn-segment 30434
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 74 434
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))
            testbed.devices[node].configure('''
                vlan 75
                    private-vlan primary
                    private-vlan association 435
                    vn-segment 30075
                vlan 435
                    private-vlan isolated
                    vn-segment 30435
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 75 435
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))           
            testbed.devices[node].configure('''
                vlan 76
                    private-vlan primary
                    private-vlan association 436
                    vn-segment 30076
                vlan 436
                    private-vlan isolated
                    vn-segment 30436
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 76 436
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))          
            testbed.devices[node].configure('''
                vlan 77
                    private-vlan primary
                    private-vlan association 437
                    vn-segment 30077
                vlan 437
                    private-vlan isolated
                    vn-segment 30477
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 77 437
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))         
            testbed.devices[node].configure('''
                vlan 78
                    private-vlan primary
                    private-vlan association 438
                    vn-segment 30078
                vlan 438
                    private-vlan isolated
                    vn-segment 30438
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 78 438
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))          
            testbed.devices[node].configure('''
                vlan 79
                    private-vlan primary
                    private-vlan association 439
                    vn-segment 30079
                vlan 439
                    private-vlan isolated
                    vn-segment 30479
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 79 439
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))         
            testbed.devices[node].configure('''
                vlan 80
                    private-vlan primary
                    private-vlan association 440
                    vn-segment 30080
                vlan 440
                    private-vlan isolated
                    vn-segment 30440
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 80 440
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))           
            testbed.devices[node].configure('''
                vlan 81
                    private-vlan primary
                    private-vlan association 441
                    vn-segment 30047
                vlan 441
                    private-vlan isolated
                    vn-segment 30441
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 81 441
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))          
            testbed.devices[node].configure('''
                vlan 82
                    private-vlan primary
                    private-vlan association 442
                    vn-segment 30082
                vlan 442
                    private-vlan isolated
                    vn-segment 3044
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 82 442
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))          
            testbed.devices[node].configure('''
                vlan 83
                    private-vlan primary
                    private-vlan association 443
                    vn-segment 30083
                vlan 443
                    private-vlan isolated
                    vn-segment 30443
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 83 443
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name)) 
            testbed.devices[node].configure('''
                vlan 84
                    private-vlan primary
                    private-vlan association 444
                    vn-segment 30084
                vlan 444
                    private-vlan isolated
                    vn-segment 30444
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 84 444
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))        
            testbed.devices[node].configure('''
                vlan 85
                    private-vlan primary
                    private-vlan association 445
                    vn-segment 30085
                vlan 445
                    private-vlan isolated
                    vn-segment 30445
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 85 445
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))
            testbed.devices[node].configure('''
                vlan 86
                    private-vlan primary
                    private-vlan association 446
                    vn-segment 30086
                vlan 446
                    private-vlan isolated
                    vn-segment 30446
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 86 446
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))
            testbed.devices[node].configure('''
                vlan 87
                    private-vlan primary
                    private-vlan association 447
                    vn-segment 30087
                vlan 447
                    private-vlan isolated
                    vn-segment 30447
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 87 447
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))
            testbed.devices[node].configure('''
                vlan 88
                    private-vlan primary
                    private-vlan association 448
                    vn-segment 30088
                vlan 448
                    private-vlan isolated
                    vn-segment 30448
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 88 448
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name)) 
            testbed.devices[node].configure('''
                vlan 89
                    private-vlan primary
                    private-vlan association 449
                    vn-segment 30089
                vlan 449
                    private-vlan isolated
                    vn-segment 30449
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 89 449
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))
            testbed.devices[node].configure('''
                vlan 90
                    private-vlan primary
                    private-vlan association 450
                    vn-segment 30090
                vlan 450
                    private-vlan isolated
                    vn-segment 30450
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 90 450
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))
            testbed.devices[node].configure('''
                vlan 91
                    private-vlan primary
                    private-vlan association 451
                    vn-segment 30091
                vlan 451
                    private-vlan isolated
                    vn-segment 30451
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 91 451
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))
            testbed.devices[node].configure('''
                vlan 92
                    private-vlan primary
                    private-vlan association 452
                    vn-segment 30092
                vlan 452
                    private-vlan isolated
                    vn-segment 30452
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 92 452
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))           
            testbed.devices[node].configure('''
                vlan 93
                    private-vlan primary
                    private-vlan association 453
                    vn-segment 30093
                vlan 453
                    private-vlan isolated
                    vn-segment 30453
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 93 453
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))          
            testbed.devices[node].configure('''
                vlan 94
                    private-vlan primary
                    private-vlan association 454
                    vn-segment 30094
                vlan 454
                    private-vlan isolated
                    vn-segment 30454
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 94 454
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))         
            testbed.devices[node].configure('''
                vlan 95
                    private-vlan primary
                    private-vlan association 455
                    vn-segment 30095
                vlan 455
                    private-vlan isolated
                    vn-segment 30455
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 95 455
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))          
            testbed.devices[node].configure('''
                vlan 96
                    private-vlan primary
                    private-vlan association 456
                    vn-segment 30096
                vlan 456
                    private-vlan isolated
                    vn-segment 30456
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 96 456
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))         
            testbed.devices[node].configure('''
                vlan 97
                    private-vlan primary
                    private-vlan association 457
                    vn-segment 30097
                vlan 457
                    private-vlan isolated
                    vn-segment 30457
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 97 457
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))           
            testbed.devices[node].configure('''
                vlan 98
                    private-vlan primary
                    private-vlan association 458
                    vn-segment 30098
                vlan 458
                    private-vlan isolated
                    vn-segment 30458
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 98 458
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))          
            testbed.devices[node].configure('''
                vlan 99
                    private-vlan primary
                    private-vlan association 459
                    vn-segment 30099
                vlan 459
                    private-vlan isolated
                    vn-segment 30459
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 99 459
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))          
            testbed.devices[node].configure('''
                vlan 100
                    private-vlan primary
                    private-vlan association 460
                    vn-segment 30100
                vlan 460
                    private-vlan isolated
                    vn-segment 30460
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 100 460
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name)) 
            testbed.devices[node].configure('''
                vlan 101
                    private-vlan primary
                    private-vlan association 461
                    vn-segment 30101
                vlan 461
                    private-vlan isolated
                    vn-segment 30461
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 101 461
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))        
            testbed.devices[node].configure('''
                vlan 102
                    private-vlan primary
                    private-vlan association 462
                    vn-segment 30102
                vlan 462
                    private-vlan isolated
                    vn-segment 30462
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 102 462
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))
            testbed.devices[node].configure('''
                vlan 103
                    private-vlan primary
                    private-vlan association 463
                    vn-segment 30103
                vlan 463
                    private-vlan isolated
                    vn-segment 30463
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 103 463
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))
            testbed.devices[node].configure('''
                vlan 104
                    private-vlan primary
                    private-vlan association 464
                    vn-segment 30104
                vlan 464
                    private-vlan isolated
                    vn-segment 30464
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 104 464
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))
            testbed.devices[node].configure('''
                vlan 105
                    private-vlan primary
                    private-vlan association 465
                    vn-segment 30105
                vlan 465
                    private-vlan isolated
                    vn-segment 30465
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 105 465
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name)) 
            testbed.devices[node].configure('''
                vlan 106
                    private-vlan primary
                    private-vlan association 466
                    vn-segment 30106
                vlan 466
                    private-vlan isolated
                    vn-segment 30466
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 106 466
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))
            testbed.devices[node].configure('''
                vlan 107
                    private-vlan primary
                    private-vlan association 467
                    vn-segment 30107
                vlan 467
                    private-vlan isolated
                    vn-segment 30467
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 107 467
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))
            testbed.devices[node].configure('''
                vlan 108
                    private-vlan primary
                    private-vlan association 468
                    vn-segment 30108
                vlan 468
                    private-vlan isolated
                    vn-segment 30468
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 108 468
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name)) 
            testbed.devices[node].configure('''
                vlan 109
                    private-vlan primary
                    private-vlan association 469
                    vn-segment 30109
                vlan 469
                    private-vlan isolated
                    vn-segment 30469
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 109 469
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))        
            testbed.devices[node].configure('''
                vlan 110
                    private-vlan primary
                    private-vlan association 470
                    vn-segment 30110
                vlan 470
                    private-vlan isolated
                    vn-segment 30470
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 110 470
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))
            testbed.devices[node].configure('''
                vlan 111
                    private-vlan primary
                    private-vlan association 471
                    vn-segment 30111
                vlan 471
                    private-vlan isolated
                    vn-segment 30471
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 111 471
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))
            testbed.devices[node].configure('''
                vlan 112
                    private-vlan primary
                    private-vlan association 472
                    vn-segment 30112
                vlan 472
                    private-vlan isolated
                    vn-segment 30472
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 112 472
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))
            testbed.devices[node].configure('''
                vlan 113
                    private-vlan primary
                    private-vlan association 473
                    vn-segment 30113
                vlan 473
                    private-vlan isolated
                    vn-segment 30473
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 113 473
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name)) 
            testbed.devices[node].configure('''
                vlan 114
                    private-vlan primary
                    private-vlan association 474
                    vn-segment 30114
                vlan 474
                    private-vlan isolated
                    vn-segment 30474
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 114 474
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))
            testbed.devices[node].configure('''
                vlan 115
                    private-vlan primary
                    private-vlan association 475
                    vn-segment 30115
                vlan 475
                    private-vlan isolated
                    vn-segment 30475
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 115 475
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))
            testbed.devices[node].configure('''
                vlan 116
                    private-vlan primary
                    private-vlan association 476
                    vn-segment 30116
                vlan 476
                    private-vlan isolated
                    vn-segment 30476
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 116 476
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name)) 
            testbed.devices[node].configure('''
                vlan 117
                    private-vlan primary
                    private-vlan association 477
                    vn-segment 30117
                vlan 477
                    private-vlan isolated
                    vn-segment 30477
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 117 477
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))        
            testbed.devices[node].configure('''
                vlan 118
                    private-vlan primary
                    private-vlan association 478
                    vn-segment 30118
                vlan 478
                    private-vlan isolated
                    vn-segment 30478
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 118 478
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))
            testbed.devices[node].configure('''
                vlan 119
                    private-vlan primary
                    private-vlan association 479
                    vn-segment 30119
                vlan 479
                    private-vlan isolated
                    vn-segment 30479
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 119 479
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))
            testbed.devices[node].configure('''
                vlan 120
                    private-vlan primary
                    private-vlan association 480
                    vn-segment 30120
                vlan 480
                    private-vlan isolated
                    vn-segment 30480
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 120 480
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))
            testbed.devices[node].configure('''
                vlan 121
                    private-vlan primary
                    private-vlan association 481
                    vn-segment 30121
                vlan 481
                    private-vlan isolated
                    vn-segment 30481
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 121 481
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name)) 
            testbed.devices[node].configure('''
                vlan 122
                    private-vlan primary
                    private-vlan association 482
                    vn-segment 30122
                vlan 482
                    private-vlan isolated
                    vn-segment 30482
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 122 482
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))
            testbed.devices[node].configure('''
                vlan 123
                    private-vlan primary
                    private-vlan association 483
                    vn-segment 30123
                vlan 483
                    private-vlan isolated
                    vn-segment 30483
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 123 483
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))
            testbed.devices[node].configure('''
                vlan 124
                    private-vlan primary
                    private-vlan association 484
                    vn-segment 30124
                vlan 484
                    private-vlan isolated
                    vn-segment 30484
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 124 484
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name)) 
            testbed.devices[node].configure('''
                vlan 125
                    private-vlan primary
                    private-vlan association 485
                    vn-segment 30125
                vlan 485
                    private-vlan isolated
                    vn-segment 30485
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 125 485
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))        
            testbed.devices[node].configure('''
                vlan 126
                    private-vlan primary
                    private-vlan association 486
                    vn-segment 30126
                vlan 486
                    private-vlan isolated
                    vn-segment 30426
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 126 486
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))
            testbed.devices[node].configure('''
                vlan 127
                    private-vlan primary
                    private-vlan association 487
                    vn-segment 30127
                vlan 487
                    private-vlan isolated
                    vn-segment 30487
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 127 487
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))
            testbed.devices[node].configure('''
                vlan 128
                    private-vlan primary
                    private-vlan association 488
                    vn-segment 30128
                vlan 488
                    private-vlan isolated
                    vn-segment 30488
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 128 488
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))
            testbed.devices[node].configure('''
                vlan 129
                    private-vlan primary
                    private-vlan association 489
                    vn-segment 30129
                vlan 489
                    private-vlan isolated
                    vn-segment 30489
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 129 489
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name)) 
            testbed.devices[node].configure('''
                vlan 130
                    private-vlan primary
                    private-vlan association 490
                    vn-segment 30130
                vlan 490
                    private-vlan isolated
                    vn-segment 30490
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 130 490
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))
            testbed.devices[node].configure('''
                vlan 131
                    private-vlan primary
                    private-vlan association 491
                    vn-segment 30131
                vlan 491
                    private-vlan isolated
                    vn-segment 30491
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 131 491
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))
            testbed.devices[node].configure('''
                vlan 132
                    private-vlan primary
                    private-vlan association 492
                    vn-segment 30132
                vlan 492
                    private-vlan isolated
                    vn-segment 30492
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 132 492
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))
            testbed.devices[node].configure('''
                vlan 133
                    private-vlan primary
                    private-vlan association 493
                    vn-segment 30133
                vlan 493
                    private-vlan isolated
                    vn-segment 30493
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 133 493
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name)) 
            testbed.devices[node].configure('''
                vlan 134
                    private-vlan primary
                    private-vlan association 494
                    vn-segment 30134
                vlan 494
                    private-vlan isolated
                    vn-segment 30494
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 134 494
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))        
            testbed.devices[node].configure('''
                vlan 135
                    private-vlan primary
                    private-vlan association 495
                    vn-segment 30135
                vlan 495
                    private-vlan isolated
                    vn-segment 30435
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 135 495
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))
            testbed.devices[node].configure('''
                vlan 136
                    private-vlan primary
                    private-vlan association 496
                    vn-segment 30136
                vlan 496
                    private-vlan isolated
                    vn-segment 30496
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 136 496
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))
            testbed.devices[node].configure('''
                vlan 137
                    private-vlan primary
                    private-vlan association 497
                    vn-segment 30137
                vlan 497
                    private-vlan isolated
                    vn-segment 30497
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 137 497
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))
            testbed.devices[node].configure('''
                vlan 138
                    private-vlan primary
                    private-vlan association 498
                    vn-segment 30138
                vlan 498
                    private-vlan isolated
                    vn-segment 30498
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 138 498
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name)) 
            testbed.devices[node].configure('''
                vlan 139
                    private-vlan primary
                    private-vlan association 499
                    vn-segment 30139
                vlan 499
                    private-vlan isolated
                    vn-segment 30499
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 139 499
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))
            testbed.devices[node].configure('''
                vlan 140
                    private-vlan primary
                    private-vlan association 500
                    vn-segment 30140
                vlan 500
                    private-vlan isolated
                    vn-segment 30500
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 140 500
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))
            testbed.devices[node].configure('''
                vlan 141
                    private-vlan primary
                    private-vlan association 501
                    vn-segment 30141
                vlan 501
                    private-vlan isolated
                    vn-segment 30501
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 141 501
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))           
            testbed.devices[node].configure('''
                vlan 142
                    private-vlan primary
                    private-vlan association 502
                    vn-segment 30142
                vlan 502
                    private-vlan isolated
                    vn-segment 30502
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 142 502
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))          
            testbed.devices[node].configure('''
                vlan 143
                    private-vlan primary
                    private-vlan association 503
                    vn-segment 30143
                vlan 403
                    private-vlan isolated
                    vn-segment 30503
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 143 503
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))         
            testbed.devices[node].configure('''
                vlan 144
                    private-vlan primary
                    private-vlan association 504
                    vn-segment 30144
                vlan 504
                    private-vlan isolated
                    vn-segment 30504
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 144 504
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))          
            testbed.devices[node].configure('''
                vlan 145
                    private-vlan primary
                    private-vlan association 505
                    vn-segment 30045
                vlan 505
                    private-vlan isolated
                    vn-segment 30505
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 145 505
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))         
            testbed.devices[node].configure('''
                vlan 146
                    private-vlan primary
                    private-vlan association 506
                    vn-segment 30146
                vlan 506
                    private-vlan isolated
                    vn-segment 30506
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 146 506
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))           
            testbed.devices[node].configure('''
                vlan 147
                    private-vlan primary
                    private-vlan association 507
                    vn-segment 30147
                vlan 507
                    private-vlan isolated
                    vn-segment 30507
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 147 507
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))          
            testbed.devices[node].configure('''
                vlan 148
                    private-vlan primary
                    private-vlan association 508
                    vn-segment 30148
                vlan 508
                    private-vlan isolated
                    vn-segment 30508
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 148 508
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))          
            testbed.devices[node].configure('''
                vlan 149
                    private-vlan primary
                    private-vlan association 509
                    vn-segment 30149
                vlan 509
                    private-vlan isolated
                    vn-segment 30509
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 149 509
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name)) 
            testbed.devices[node].configure('''
                vlan 150
                    private-vlan primary
                    private-vlan association 510
                    vn-segment 30150
                vlan 510
                    private-vlan isolated
                    vn-segment 30510
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 150 510
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))        
            testbed.devices[node].configure('''
                vlan 151
                    private-vlan primary
                    private-vlan association 511
                    vn-segment 30151
                vlan 511
                    private-vlan isolated
                    vn-segment 30511
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 151 511
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))
            testbed.devices[node].configure('''
                vlan 152
                    private-vlan primary
                    private-vlan association 512
                    vn-segment 30152
                vlan 512
                    private-vlan isolated
                    vn-segment 30512
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 152 512
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))
            testbed.devices[node].configure('''
                vlan 153
                    private-vlan primary
                    private-vlan association 513
                    vn-segment 30153
                vlan 513
                    private-vlan isolated
                    vn-segment 30513
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 153 513
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))
            testbed.devices[node].configure('''
                vlan 154
                    private-vlan primary
                    private-vlan association 514
                    vn-segment 30154
                vlan 514
                    private-vlan isolated
                    vn-segment 30414
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 154 514
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name)) 
            testbed.devices[node].configure('''
                vlan 155
                    private-vlan primary
                    private-vlan association 515
                    vn-segment 30155
                vlan 515
                    private-vlan isolated
                    vn-segment 30515
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 155 515
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))
            testbed.devices[node].configure('''
                vlan 156
                    private-vlan primary
                    private-vlan association 516
                    vn-segment 30156
                vlan 516
                    private-vlan isolated
                    vn-segment 30516
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 156 516
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))
            testbed.devices[node].configure('''
                vlan 157
                    private-vlan primary
                    private-vlan association 517
                    vn-segment 30157
                vlan 517
                    private-vlan isolated
                    vn-segment 30517
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 157 517
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))
            testbed.devices[node].configure('''
                vlan 158
                    private-vlan primary
                    private-vlan association 518
                    vn-segment 30158
                vlan 518
                    private-vlan isolated
                    vn-segment 30518
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 158 518
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))           
            testbed.devices[node].configure('''
                vlan 159
                    private-vlan primary
                    private-vlan association 519
                    vn-segment 30159
                vlan 519
                    private-vlan isolated
                    vn-segment 30519
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 159 519
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))          
            testbed.devices[node].configure('''
                vlan 160
                    private-vlan primary
                    private-vlan association 520
                    vn-segment 30160
                vlan 520
                    private-vlan isolated
                    vn-segment 30520
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 160 520
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))         
            testbed.devices[node].configure('''
                vlan 161
                    private-vlan primary
                    private-vlan association 521
                    vn-segment 30161
                vlan 521
                    private-vlan isolated
                    vn-segment 30521
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 161 521
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))          
            testbed.devices[node].configure('''
                vlan 162
                    private-vlan primary
                    private-vlan association 522
                    vn-segment 30162
                vlan 522
                    private-vlan isolated
                    vn-segment 30522
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 162 522
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))         
            testbed.devices[node].configure('''
                vlan 163
                    private-vlan primary
                    private-vlan association 523
                    vn-segment 30163
                vlan 523
                    private-vlan isolated
                    vn-segment 30523
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 163 523
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))           
            testbed.devices[node].configure('''
                vlan 164
                    private-vlan primary
                    private-vlan association 524
                    vn-segment 30164
                vlan 524
                    private-vlan isolated
                    vn-segment 30524
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 164 524
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))          
            testbed.devices[node].configure('''
                vlan 165
                    private-vlan primary
                    private-vlan association 525
                    vn-segment 30165
                vlan 525
                    private-vlan isolated
                    vn-segment 30525
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 165 525
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))          
            testbed.devices[node].configure('''
                vlan 166
                    private-vlan primary
                    private-vlan association 526
                    vn-segment 30166
                vlan 526
                    private-vlan isolated
                    vn-segment 30526
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 166 526
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name)) 
            testbed.devices[node].configure('''
                vlan 167
                    private-vlan primary
                    private-vlan association 527
                    vn-segment 30167
                vlan 527
                    private-vlan isolated
                    vn-segment 30527
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 167 527
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))        
            testbed.devices[node].configure('''
                vlan 168
                    private-vlan primary
                    private-vlan association 528
                    vn-segment 30168
                vlan 528
                    private-vlan isolated
                    vn-segment 30528
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 168 528
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))
            testbed.devices[node].configure('''
                vlan 169
                    private-vlan primary
                    private-vlan association 529
                    vn-segment 30169
                vlan 529
                    private-vlan isolated
                    vn-segment 30529
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 169 529
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))
            testbed.devices[node].configure('''
                vlan 170
                    private-vlan primary
                    private-vlan association 530
                    vn-segment 30170
                vlan 530
                    private-vlan isolated
                    vn-segment 30530
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 170 530
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))
            testbed.devices[node].configure('''
                vlan 171
                    private-vlan primary
                    private-vlan association 531
                    vn-segment 30171
                vlan 531
                    private-vlan isolated
                    vn-segment 30531
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 171 531
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name)) 
            testbed.devices[node].configure('''
                vlan 172
                    private-vlan primary
                    private-vlan association 532
                    vn-segment 30172
                vlan 532
                    private-vlan isolated
                    vn-segment 30532
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 172 532
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))
            testbed.devices[node].configure('''
                vlan 173
                    private-vlan primary
                    private-vlan association 533
                    vn-segment 30173
                vlan 533
                    private-vlan isolated
                    vn-segment 30573
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 173 533
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))     
            testbed.devices[node].configure('''
                vlan 174
                    private-vlan primary
                    private-vlan association 534
                    vn-segment 30174
                vlan 534
                    private-vlan isolated
                    vn-segment 30534
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 174 534
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))
            testbed.devices[node].configure('''
                vlan 175
                    private-vlan primary
                    private-vlan association 535
                    vn-segment 30175
                vlan 535
                    private-vlan isolated
                    vn-segment 30535
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 175 535
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))           
            testbed.devices[node].configure('''
                vlan 176
                    private-vlan primary
                    private-vlan association 536
                    vn-segment 30176
                vlan 536
                    private-vlan isolated
                    vn-segment 30536
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 176 536
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))          
            testbed.devices[node].configure('''
                vlan 177
                    private-vlan primary
                    private-vlan association 537
                    vn-segment 30177
                vlan 537
                    private-vlan isolated
                    vn-segment 30577
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 177 537
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))         
            testbed.devices[node].configure('''
                vlan 178
                    private-vlan primary
                    private-vlan association 538
                    vn-segment 30178
                vlan 538
                    private-vlan isolated
                    vn-segment 30538
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 178 538
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))          
            testbed.devices[node].configure('''
                vlan 179
                    private-vlan primary
                    private-vlan association 539
                    vn-segment 30179
                vlan 539
                    private-vlan isolated
                    vn-segment 30539
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 179 539
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))         
            testbed.devices[node].configure('''
                vlan 180
                    private-vlan primary
                    private-vlan association 540
                    vn-segment 30180
                vlan 540
                    private-vlan isolated
                    vn-segment 30540
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 180 540
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))           
            testbed.devices[node].configure('''
                vlan 181
                    private-vlan primary
                    private-vlan association 541
                    vn-segment 30147
                vlan 541
                    private-vlan isolated
                    vn-segment 30541
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 181 541
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))          
            testbed.devices[node].configure('''
                vlan 812
                    private-vlan primary
                    private-vlan association 542
                    vn-segment 30182
                vlan 542
                    private-vlan isolated
                    vn-segment 30542
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 182 542
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))          
            testbed.devices[node].configure('''
                vlan 183
                    private-vlan primary
                    private-vlan association 543
                    vn-segment 30183
                vlan 543
                    private-vlan isolated
                    vn-segment 30543
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 183 543
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name)) 
            testbed.devices[node].configure('''
                vlan 184
                    private-vlan primary
                    private-vlan association 544
                    vn-segment 30184
                vlan 544
                    private-vlan isolated
                    vn-segment 30544
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 184 544
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))        
            testbed.devices[node].configure('''
                vlan 185
                    private-vlan primary
                    private-vlan association 545
                    vn-segment 30185
                vlan 545
                    private-vlan isolated
                    vn-segment 30545
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 185 545
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))
            testbed.devices[node].configure('''
                vlan 186
                    private-vlan primary
                    private-vlan association 546
                    vn-segment 30186
                vlan 546
                    private-vlan isolated
                    vn-segment 30546
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 186 546
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))
            testbed.devices[node].configure('''
                vlan 187
                    private-vlan primary
                    private-vlan association 547
                    vn-segment 30187
                vlan 547
                    private-vlan isolated
                    vn-segment 30547
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 187 547
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))
            testbed.devices[node].configure('''
                vlan 188
                    private-vlan primary
                    private-vlan association 548
                    vn-segment 30188
                vlan 548
                    private-vlan isolated
                    vn-segment 30548
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 188 548
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name)) 
            testbed.devices[node].configure('''
                vlan 189
                    private-vlan primary
                    private-vlan association 549
                    vn-segment 30189
                vlan 549
                    private-vlan isolated
                    vn-segment 30549
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 189 549
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))
            testbed.devices[node].configure('''
                vlan 190
                    private-vlan primary
                    private-vlan association 550
                    vn-segment 30190
                vlan 550
                    private-vlan isolated
                    vn-segment 30550
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 190 550
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))
            testbed.devices[node].configure('''
                vlan 191
                    private-vlan primary
                    private-vlan association 551
                    vn-segment 30191
                vlan 551
                    private-vlan isolated
                    vn-segment 30551
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 191 551
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))
            testbed.devices[node].configure('''
                vlan 192
                    private-vlan primary
                    private-vlan association 552
                    vn-segment 30192
                vlan 552
                    private-vlan isolated
                    vn-segment 30552
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 192 552
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))           
            testbed.devices[node].configure('''
                vlan 193
                    private-vlan primary
                    private-vlan association 553
                    vn-segment 30093
                vlan 553
                    private-vlan isolated
                    vn-segment 30553
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 193 553
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))          
            testbed.devices[node].configure('''
                vlan 194
                    private-vlan primary
                    private-vlan association 554
                    vn-segment 30194
                vlan 554
                    private-vlan isolated
                    vn-segment 30554
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 194 554
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))         
            testbed.devices[node].configure('''
                vlan 195
                    private-vlan primary
                    private-vlan association 555
                    vn-segment 30195
                vlan 555
                    private-vlan isolated
                    vn-segment 30555
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 195 555
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))          
            testbed.devices[node].configure('''
                vlan 196
                    private-vlan primary
                    private-vlan association 556
                    vn-segment 30196
                vlan 556
                    private-vlan isolated
                    vn-segment 30556
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 196 556
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))         
            testbed.devices[node].configure('''
                vlan 197
                    private-vlan primary
                    private-vlan association 557
                    vn-segment 30197
                vlan 557
                    private-vlan isolated
                    vn-segment 30557
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 197 557
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))           
            testbed.devices[node].configure('''
                vlan 198
                    private-vlan primary
                    private-vlan association 558
                    vn-segment 30198
                vlan 558
                    private-vlan isolated
                    vn-segment 30558
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 198 558
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))          
            testbed.devices[node].configure('''
                vlan 199
                    private-vlan primary
                    private-vlan association 559
                    vn-segment 30099
                vlan 559
                    private-vlan isolated
                    vn-segment 30559
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 199 559
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))          
            testbed.devices[node].configure('''
                vlan 200
                    private-vlan primary
                    private-vlan association 560
                    vn-segment 30200
                vlan 560
                    private-vlan isolated
                    vn-segment 30560
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 200 560
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name)) 
            testbed.devices[node].configure('''
                vlan 201
                    private-vlan primary
                    private-vlan association 561
                    vn-segment 30201
                vlan 561
                    private-vlan isolated
                    vn-segment 30561
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 201 561
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))        
            testbed.devices[node].configure('''
                vlan 202
                    private-vlan primary
                    private-vlan association 562
                    vn-segment 30202
                vlan 562
                    private-vlan isolated
                    vn-segment 30562
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 202 562
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))
            testbed.devices[node].configure('''
                vlan 203
                    private-vlan primary
                    private-vlan association 563
                    vn-segment 30203
                vlan 563
                    private-vlan isolated
                    vn-segment 30563
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 203 563
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))
            testbed.devices[node].configure('''
                vlan 204
                    private-vlan primary
                    private-vlan association 564
                    vn-segment 30204
                vlan 564
                    private-vlan isolated
                    vn-segment 30564
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 204 564
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))
            testbed.devices[node].configure('''
                vlan 205
                    private-vlan primary
                    private-vlan association 565
                    vn-segment 30205
                vlan 565
                    private-vlan isolated
                    vn-segment 30565
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 205 565
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name)) 
            testbed.devices[node].configure('''
                vlan 206
                    private-vlan primary
                    private-vlan association 566
                    vn-segment 30206
                vlan 566
                    private-vlan isolated
                    vn-segment 30566
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 206 566
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))
            testbed.devices[node].configure('''
                vlan 207
                    private-vlan primary
                    private-vlan association 567
                    vn-segment 30207
                vlan 567
                    private-vlan isolated
                    vn-segment 30567
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 207 567
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))
            testbed.devices[node].configure('''
                vlan 208
                    private-vlan primary
                    private-vlan association 568
                    vn-segment 30208
                vlan 568
                    private-vlan isolated
                    vn-segment 30568
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 208 568
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name)) 
            testbed.devices[node].configure('''
                vlan 209
                    private-vlan primary
                    private-vlan association 569
                    vn-segment 30209
                vlan 569
                    private-vlan isolated
                    vn-segment 30569
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 209 569
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))        
            testbed.devices[node].configure('''
                vlan 210
                    private-vlan primary
                    private-vlan association 570
                    vn-segment 30210
                vlan 570
                    private-vlan isolated
                    vn-segment 30570
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 210 570
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))
            testbed.devices[node].configure('''
                vlan 211
                    private-vlan primary
                    private-vlan association 571
                    vn-segment 30211
                vlan 571
                    private-vlan isolated
                    vn-segment 30571
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 211 571
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))
            testbed.devices[node].configure('''
                vlan 212
                    private-vlan primary
                    private-vlan association 572
                    vn-segment 30212
                vlan 572
                    private-vlan isolated
                    vn-segment 30572
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 212 572
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))
            testbed.devices[node].configure('''
                vlan 213
                    private-vlan primary
                    private-vlan association 573
                    vn-segment 30213
                vlan 573
                    private-vlan isolated
                    vn-segment 30573
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 213 573
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name)) 
            testbed.devices[node].configure('''
                vlan 214
                    private-vlan primary
                    private-vlan association 574
                    vn-segment 30214
                vlan 574
                    private-vlan isolated
                    vn-segment 30574
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 214 574
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))
            testbed.devices[node].configure('''
                vlan 215
                    private-vlan primary
                    private-vlan association 575
                    vn-segment 30215
                vlan 575
                    private-vlan isolated
                    vn-segment 30575
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 215 575
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))
            testbed.devices[node].configure('''
                vlan 216
                    private-vlan primary
                    private-vlan association 576
                    vn-segment 30216
                vlan 576
                    private-vlan isolated
                    vn-segment 30576
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 216 576
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name)) 
            testbed.devices[node].configure('''
                vlan 217
                    private-vlan primary
                    private-vlan association 577
                    vn-segment 30217
                vlan 577
                    private-vlan isolated
                    vn-segment 30577
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 217 577
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))        
            testbed.devices[node].configure('''
                vlan 218
                    private-vlan primary
                    private-vlan association 578
                    vn-segment 30218
                vlan 578
                    private-vlan isolated
                    vn-segment 30578
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 218 578
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))
            testbed.devices[node].configure('''
                vlan 219
                    private-vlan primary
                    private-vlan association 579
                    vn-segment 30219
                vlan 579
                    private-vlan isolated
                    vn-segment 30579
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 219 579
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))
            testbed.devices[node].configure('''
                vlan 220
                    private-vlan primary
                    private-vlan association 580
                    vn-segment 30220
                vlan 580
                    private-vlan isolated
                    vn-segment 30580
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 220 580
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))
            testbed.devices[node].configure('''
                vlan 221
                    private-vlan primary
                    private-vlan association 581
                    vn-segment 30121
                vlan 581
                    private-vlan isolated
                    vn-segment 30581
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 221 581
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name)) 
            testbed.devices[node].configure('''
                vlan 222
                    private-vlan primary
                    private-vlan association 582
                    vn-segment 30222
                vlan 582
                    private-vlan isolated
                    vn-segment 30582
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 222 582
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))
            testbed.devices[node].configure('''
                vlan 223
                    private-vlan primary
                    private-vlan association 583
                    vn-segment 30223
                vlan 583
                    private-vlan isolated
                    vn-segment 30583
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 223 583
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))
            testbed.devices[node].configure('''
                vlan 224
                    private-vlan primary
                    private-vlan association 584
                    vn-segment 30224
                vlan 584
                    private-vlan isolated
                    vn-segment 30584
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 224 584
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name)) 
            testbed.devices[node].configure('''
                vlan 225
                    private-vlan primary
                    private-vlan association 585
                    vn-segment 30225
                vlan 585
                    private-vlan isolated
                    vn-segment 30585
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 225 585
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))        
            testbed.devices[node].configure('''
                vlan 226
                    private-vlan primary
                    private-vlan association 586
                    vn-segment 30226
                vlan 586
                    private-vlan isolated
                    vn-segment 30526
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 226 586
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))
            testbed.devices[node].configure('''
                vlan 227
                    private-vlan primary
                    private-vlan association 587
                    vn-segment 30227
                vlan 587
                    private-vlan isolated
                    vn-segment 30587
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 227 587
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))
            testbed.devices[node].configure('''
                vlan 228
                    private-vlan primary
                    private-vlan association 588
                    vn-segment 30228
                vlan 588
                    private-vlan isolated
                    vn-segment 30588
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 228 588
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))
            testbed.devices[node].configure('''
                vlan 229
                    private-vlan primary
                    private-vlan association 589
                    vn-segment 30229
                vlan 589
                    private-vlan isolated
                    vn-segment 30589
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 229 589
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name)) 
            testbed.devices[node].configure('''
                vlan 230
                    private-vlan primary
                    private-vlan association 590
                    vn-segment 30230
                vlan 590
                    private-vlan isolated
                    vn-segment 30590
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 230 590
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))
            testbed.devices[node].configure('''
                vlan 231
                    private-vlan primary
                    private-vlan association 591
                    vn-segment 30231
                vlan 591
                    private-vlan isolated
                    vn-segment 30591
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 231 591
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))
            testbed.devices[node].configure('''
                vlan 232
                    private-vlan primary
                    private-vlan association 592
                    vn-segment 30232
                vlan 592
                    private-vlan isolated
                    vn-segment 30592
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 232 592
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))
            testbed.devices[node].configure('''
                vlan 233
                    private-vlan primary
                    private-vlan association 593
                    vn-segment 30233
                vlan 593
                    private-vlan isolated
                    vn-segment 30593
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 233 593
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name)) 
            testbed.devices[node].configure('''
                vlan 234
                    private-vlan primary
                    private-vlan association 594
                    vn-segment 30234
                vlan 594
                    private-vlan isolated
                    vn-segment 30594
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 234 594
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))        
            testbed.devices[node].configure('''
                vlan 235
                    private-vlan primary
                    private-vlan association 595
                    vn-segment 30235
                vlan 595
                    private-vlan isolated
                    vn-segment 30535
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 235 595
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))
            testbed.devices[node].configure('''
                vlan 236
                    private-vlan primary
                    private-vlan association 596
                    vn-segment 30236
                vlan 596
                    private-vlan isolated
                    vn-segment 30596
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 236 596
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))
            testbed.devices[node].configure('''
                vlan 237
                    private-vlan primary
                    private-vlan association 597
                    vn-segment 30237
                vlan 597
                    private-vlan isolated
                    vn-segment 30597
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 237 597
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))
            testbed.devices[node].configure('''
                vlan 238
                    private-vlan primary
                    private-vlan association 598
                    vn-segment 30238
                vlan 598
                    private-vlan isolated
                    vn-segment 30598
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 238 598
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name)) 
            testbed.devices[node].configure('''
                vlan 239
                    private-vlan primary
                    private-vlan association 599
                    vn-segment 30239
                vlan 599
                    private-vlan isolated
                    vn-segment 30599
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 239 599
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))
            testbed.devices[node].configure('''
                vlan 240
                    private-vlan primary
                    private-vlan association 600
                    vn-segment 30240
                vlan 600
                    private-vlan isolated
                    vn-segment 30600
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 240 600
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))
            testbed.devices[node].configure('''
                vlan 240
                    private-vlan primary
                    private-vlan association 600
                    vn-segment 30240
                vlan 600
                    private-vlan isolated
                    vn-segment 30600
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 240 600
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))
            testbed.devices[node].configure('''
                vlan 241
                    private-vlan primary
                    private-vlan association 601
                    vn-segment 30241
                vlan 601
                    private-vlan isolated
                    vn-segment 30601
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 241 601
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))           
            testbed.devices[node].configure('''
                vlan 242
                    private-vlan primary
                    private-vlan association 602
                    vn-segment 30242
                vlan 602
                    private-vlan isolated
                    vn-segment 30602
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 242 602
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))          
            testbed.devices[node].configure('''
                vlan 243
                    private-vlan primary
                    private-vlan association 603
                    vn-segment 30243
                vlan 403
                    private-vlan isolated
                    vn-segment 30603
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 243 603
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))         
            testbed.devices[node].configure('''
                vlan 244
                    private-vlan primary
                    private-vlan association 604
                    vn-segment 30244
                vlan 604
                    private-vlan isolated
                    vn-segment 30604
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 244 604
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))          
            testbed.devices[node].configure('''
                vlan 245
                    private-vlan primary
                    private-vlan association 605
                    vn-segment 30045
                vlan 605
                    private-vlan isolated
                    vn-segment 30605
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 245 605
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))         
            testbed.devices[node].configure('''
                vlan 246
                    private-vlan primary
                    private-vlan association 606
                    vn-segment 30246
                vlan 606
                    private-vlan isolated
                    vn-segment 30606
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 246 606
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))           
            testbed.devices[node].configure('''
                vlan 247
                    private-vlan primary
                    private-vlan association 607
                    vn-segment 30247
                vlan 607
                    private-vlan isolated
                    vn-segment 30607
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 247 607
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))          
            testbed.devices[node].configure('''
                vlan 248
                    private-vlan primary
                    private-vlan association 608
                    vn-segment 30248
                vlan 608
                    private-vlan isolated
                    vn-segment 30608
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 248 608
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))          
            testbed.devices[node].configure('''
                vlan 249
                    private-vlan primary
                    private-vlan association 609
                    vn-segment 30249
                vlan 609
                    private-vlan isolated
                    vn-segment 30609
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 249 609
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name)) 
            testbed.devices[node].configure('''
                vlan 250
                    private-vlan primary
                    private-vlan association 610
                    vn-segment 30250
                vlan 610
                    private-vlan isolated
                    vn-segment 30610
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 250 610
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))        
            testbed.devices[node].configure('''
                vlan 251
                    private-vlan primary
                    private-vlan association 611
                    vn-segment 30251
                vlan 611
                    private-vlan isolated
                    vn-segment 30611
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 251 611
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))
            testbed.devices[node].configure('''
                vlan 252
                    private-vlan primary
                    private-vlan association 612
                    vn-segment 30252
                vlan 612
                    private-vlan isolated
                    vn-segment 30612
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 252 612
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))
            testbed.devices[node].configure('''
                vlan 253
                    private-vlan primary
                    private-vlan association 613
                    vn-segment 30253
                vlan 613
                    private-vlan isolated
                    vn-segment 30613
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 253 613
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))
            testbed.devices[node].configure('''
                vlan 254
                    private-vlan primary
                    private-vlan association 614
                    vn-segment 30254
                vlan 614
                    private-vlan isolated
                    vn-segment 30414
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 254 614
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name)) 
            testbed.devices[node].configure('''
                vlan 255
                    private-vlan primary
                    private-vlan association 615
                    vn-segment 30255
                vlan 615
                    private-vlan isolated
                    vn-segment 30615
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 255 615
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))
            testbed.devices[node].configure('''
                vlan 256
                    private-vlan primary
                    private-vlan association 616
                    vn-segment 30256
                vlan 616
                    private-vlan isolated
                    vn-segment 30616
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 256 616
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))
            testbed.devices[node].configure('''
                vlan 257
                    private-vlan primary
                    private-vlan association 617
                    vn-segment 30257
                vlan 617
                    private-vlan isolated
                    vn-segment 30617
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 257 617
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))
            testbed.devices[node].configure('''
                vlan 258
                    private-vlan primary
                    private-vlan association 618
                    vn-segment 30258
                vlan 618
                    private-vlan isolated
                    vn-segment 30618
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 258 618
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))           
            testbed.devices[node].configure('''
                vlan 259
                    private-vlan primary
                    private-vlan association 619
                    vn-segment 30259
                vlan 619
                    private-vlan isolated
                    vn-segment 30619
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 259 619
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))          
            testbed.devices[node].configure('''
                vlan 260
                    private-vlan primary
                    private-vlan association 620
                    vn-segment 30260
                vlan 620
                    private-vlan isolated
                    vn-segment 30620
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 260 620
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))         
            testbed.devices[node].configure('''
                vlan 261
                    private-vlan primary
                    private-vlan association 621
                    vn-segment 30261
                vlan 621
                    private-vlan isolated
                    vn-segment 30621
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 261 621
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))          
            testbed.devices[node].configure('''
                vlan 262
                    private-vlan primary
                    private-vlan association 622
                    vn-segment 30262
                vlan 622
                    private-vlan isolated
                    vn-segment 30622
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 262 622
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))         
            testbed.devices[node].configure('''
                vlan 263
                    private-vlan primary
                    private-vlan association 623
                    vn-segment 30263
                vlan 623
                    private-vlan isolated
                    vn-segment 30623
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 263 623
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))           
            testbed.devices[node].configure('''
                vlan 264
                    private-vlan primary
                    private-vlan association 624
                    vn-segment 30264
                vlan 624
                    private-vlan isolated
                    vn-segment 30624
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 264 624
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))          
            testbed.devices[node].configure('''
                vlan 265
                    private-vlan primary
                    private-vlan association 625
                    vn-segment 30265
                vlan 625
                    private-vlan isolated
                    vn-segment 30625
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 265 625
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))          
            testbed.devices[node].configure('''
                vlan 266
                    private-vlan primary
                    private-vlan association 626
                    vn-segment 30266
                vlan 626
                    private-vlan isolated
                    vn-segment 30626
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 266 626
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name)) 
            testbed.devices[node].configure('''
                vlan 267
                    private-vlan primary
                    private-vlan association 627
                    vn-segment 30267
                vlan 627
                    private-vlan isolated
                    vn-segment 30627
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 267 627
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))        
            testbed.devices[node].configure('''
                vlan 268
                    private-vlan primary
                    private-vlan association 628
                    vn-segment 30268
                vlan 628
                    private-vlan isolated
                    vn-segment 30628
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 268 628
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))
            testbed.devices[node].configure('''
                vlan 269
                    private-vlan primary
                    private-vlan association 628
                    vn-segment 30269
                vlan 628
                    private-vlan isolated
                    vn-segment 30628
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 269 628
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))
            testbed.devices[node].configure('''
                vlan 270
                    private-vlan primary
                    private-vlan association 630
                    vn-segment 30270
                vlan 630
                    private-vlan isolated
                    vn-segment 30630
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 270 630
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))
            testbed.devices[node].configure('''
                vlan 271
                    private-vlan primary
                    private-vlan association 631
                    vn-segment 30271
                vlan 631
                    private-vlan isolated
                    vn-segment 30631
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 271 631
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name)) 
            testbed.devices[node].configure('''
                vlan 272
                    private-vlan primary
                    private-vlan association 632
                    vn-segment 30272
                vlan 632
                    private-vlan isolated
                    vn-segment 30632
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 272 632
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))
            testbed.devices[node].configure('''
                vlan 273
                    private-vlan primary
                    private-vlan association 633
                    vn-segment 30273
                vlan 633
                    private-vlan isolated
                    vn-segment 30673
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 273 633
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))     
            testbed.devices[node].configure('''
                vlan 274
                    private-vlan primary
                    private-vlan association 634
                    vn-segment 30274
                vlan 634
                    private-vlan isolated
                    vn-segment 30634
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 274 634
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))
            testbed.devices[node].configure('''
                vlan 275
                    private-vlan primary
                    private-vlan association 635
                    vn-segment 30275
                vlan 635
                    private-vlan isolated
                    vn-segment 30635
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 275 635
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))           
            testbed.devices[node].configure('''
                vlan 276
                    private-vlan primary
                    private-vlan association 636
                    vn-segment 30276
                vlan 636
                    private-vlan isolated
                    vn-segment 30636
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 276 636
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))          
            testbed.devices[node].configure('''
                vlan 277
                    private-vlan primary
                    private-vlan association 637
                    vn-segment 30277
                vlan 637
                    private-vlan isolated
                    vn-segment 30677
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 277 637
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))         
            testbed.devices[node].configure('''
                vlan 278
                    private-vlan primary
                    private-vlan association 638
                    vn-segment 30278
                vlan 638
                    private-vlan isolated
                    vn-segment 30638
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 278 638
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))          
            testbed.devices[node].configure('''
                vlan 279
                    private-vlan primary
                    private-vlan association 639
                    vn-segment 30279
                vlan 639
                    private-vlan isolated
                    vn-segment 30639
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 279 639
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))         
            testbed.devices[node].configure('''
                vlan 280
                    private-vlan primary
                    private-vlan association 640
                    vn-segment 30280
                vlan 640
                    private-vlan isolated
                    vn-segment 30640
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 280 640
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))           
            testbed.devices[node].configure('''
                vlan 281
                    private-vlan primary
                    private-vlan association 641
                    vn-segment 30247
                vlan 641
                    private-vlan isolated
                    vn-segment 30641
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 281 641
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))          
            testbed.devices[node].configure('''
                vlan 812
                    private-vlan primary
                    private-vlan association 642
                    vn-segment 30282
                vlan 642
                    private-vlan isolated
                    vn-segment 30642
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 282 642
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))          
            testbed.devices[node].configure('''
                vlan 283
                    private-vlan primary
                    private-vlan association 643
                    vn-segment 30283
                vlan 643
                    private-vlan isolated
                    vn-segment 30643
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 283 643
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name)) 
            testbed.devices[node].configure('''
                vlan 284
                    private-vlan primary
                    private-vlan association 644
                    vn-segment 30284
                vlan 644
                    private-vlan isolated
                    vn-segment 30644
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 284 644
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))        
            testbed.devices[node].configure('''
                vlan 285
                    private-vlan primary
                    private-vlan association 645
                    vn-segment 30285
                vlan 645
                    private-vlan isolated
                    vn-segment 30645
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 285 645
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))
            testbed.devices[node].configure('''
                vlan 286
                    private-vlan primary
                    private-vlan association 646
                    vn-segment 30286
                vlan 646
                    private-vlan isolated
                    vn-segment 30646
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 286 646
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))
            testbed.devices[node].configure('''
                vlan 287
                    private-vlan primary
                    private-vlan association 647
                    vn-segment 30287
                vlan 647
                    private-vlan isolated
                    vn-segment 30647
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 287 647
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))
            testbed.devices[node].configure('''
                vlan 288
                    private-vlan primary
                    private-vlan association 648
                    vn-segment 30288
                vlan 648
                    private-vlan isolated
                    vn-segment 30648
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 288 648
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name)) 
            testbed.devices[node].configure('''
                vlan 289
                    private-vlan primary
                    private-vlan association 649
                    vn-segment 30289
                vlan 649
                    private-vlan isolated
                    vn-segment 30649
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 289 649
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))
            testbed.devices[node].configure('''
                vlan 290
                    private-vlan primary
                    private-vlan association 650
                    vn-segment 30290
                vlan 650
                    private-vlan isolated
                    vn-segment 30650
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 290 650
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))
            testbed.devices[node].configure('''
                vlan 291
                    private-vlan primary
                    private-vlan association 651
                    vn-segment 30291
                vlan 651
                    private-vlan isolated
                    vn-segment 30651
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 291 651
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))
            testbed.devices[node].configure('''
                vlan 292
                    private-vlan primary
                    private-vlan association 652
                    vn-segment 30292
                vlan 652
                    private-vlan isolated
                    vn-segment 30652
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 292 652
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))           
            testbed.devices[node].configure('''
                vlan 293
                    private-vlan primary
                    private-vlan association 653
                    vn-segment 30093
                vlan 653
                    private-vlan isolated
                    vn-segment 30653
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 293 653
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))          
            testbed.devices[node].configure('''
                vlan 294
                    private-vlan primary
                    private-vlan association 654
                    vn-segment 30294
                vlan 654
                    private-vlan isolated
                    vn-segment 30654
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 294 654
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))         
            testbed.devices[node].configure('''
                vlan 295
                    private-vlan primary
                    private-vlan association 655
                    vn-segment 30295
                vlan 655
                    private-vlan isolated
                    vn-segment 30655
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 295 655
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))          
            testbed.devices[node].configure('''
                vlan 296
                    private-vlan primary
                    private-vlan association 656
                    vn-segment 30296
                vlan 656
                    private-vlan isolated
                    vn-segment 30656
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 296 656
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))         
            testbed.devices[node].configure('''
                vlan 297
                    private-vlan primary
                    private-vlan association 657
                    vn-segment 30297
                vlan 657
                    private-vlan isolated
                    vn-segment 30657
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 297 657
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))           
            testbed.devices[node].configure('''
                vlan 298
                    private-vlan primary
                    private-vlan association 658
                    vn-segment 30298
                vlan 658
                    private-vlan isolated
                    vn-segment 30658
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 298 658
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))          
            testbed.devices[node].configure('''
                vlan 299
                    private-vlan primary
                    private-vlan association 659
                    vn-segment 30099
                vlan 659
                    private-vlan isolated
                    vn-segment 30659
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 299 659
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))          
            testbed.devices[node].configure('''
                vlan 300
                    private-vlan primary
                    private-vlan association 660
                    vn-segment 30300
                vlan 660
                    private-vlan isolated
                    vn-segment 30660
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 300 660
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name)) 
            testbed.devices[node].configure('''
                vlan 301
                    private-vlan primary
                    private-vlan association 661
                    vn-segment 30301
                vlan 661
                    private-vlan isolated
                    vn-segment 30661
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 301 661
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))        
            testbed.devices[node].configure('''
                vlan 302
                    private-vlan primary
                    private-vlan association 662
                    vn-segment 30302
                vlan 662
                    private-vlan isolated
                    vn-segment 30662
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 302 662
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))
            testbed.devices[node].configure('''
                vlan 303
                    private-vlan primary
                    private-vlan association 663
                    vn-segment 30303
                vlan 663
                    private-vlan isolated
                    vn-segment 30663
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 303 663
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))
            testbed.devices[node].configure('''
                vlan 304
                    private-vlan primary
                    private-vlan association 664
                    vn-segment 30304
                vlan 664
                    private-vlan isolated
                    vn-segment 30664
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 304 664
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))
            testbed.devices[node].configure('''
                vlan 305
                    private-vlan primary
                    private-vlan association 665
                    vn-segment 30305
                vlan 665
                    private-vlan isolated
                    vn-segment 30665
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 305 665
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name)) 
            testbed.devices[node].configure('''
                vlan 306
                    private-vlan primary
                    private-vlan association 666
                    vn-segment 30306
                vlan 666
                    private-vlan isolated
                    vn-segment 30666
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 306 666
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))
            testbed.devices[node].configure('''
                vlan 307
                    private-vlan primary
                    private-vlan association 667
                    vn-segment 30307
                vlan 667
                    private-vlan isolated
                    vn-segment 30667
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 307 667
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))
            testbed.devices[node].configure('''
                vlan 308
                    private-vlan primary
                    private-vlan association 668
                    vn-segment 30308
                vlan 668
                    private-vlan isolated
                    vn-segment 30668
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 308 668
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name)) 
            testbed.devices[node].configure('''
                vlan 309
                    private-vlan primary
                    private-vlan association 669
                    vn-segment 30309
                vlan 669
                    private-vlan isolated
                    vn-segment 30669
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 309 669
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))        
            testbed.devices[node].configure('''
                vlan 310
                    private-vlan primary
                    private-vlan association 670
                    vn-segment 30310
                vlan 670
                    private-vlan isolated
                    vn-segment 30670
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 310 670
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))
            testbed.devices[node].configure('''
                vlan 311
                    private-vlan primary
                    private-vlan association 671
                    vn-segment 30311
                vlan 671
                    private-vlan isolated
                    vn-segment 30671
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 311 671
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))
            testbed.devices[node].configure('''
                vlan 312
                    private-vlan primary
                    private-vlan association 672
                    vn-segment 30312
                vlan 672
                    private-vlan isolated
                    vn-segment 30672
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 312 672
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))
            testbed.devices[node].configure('''
                vlan 313
                    private-vlan primary
                    private-vlan association 673
                    vn-segment 30313
                vlan 673
                    private-vlan isolated
                    vn-segment 30673
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 313 673
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name)) 
            testbed.devices[node].configure('''
                vlan 314
                    private-vlan primary
                    private-vlan association 674
                    vn-segment 30314
                vlan 674
                    private-vlan isolated
                    vn-segment 30674
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 314 674
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))
            testbed.devices[node].configure('''
                vlan 315
                    private-vlan primary
                    private-vlan association 675
                    vn-segment 30315
                vlan 675
                    private-vlan isolated
                    vn-segment 30675
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 315 675
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))
            testbed.devices[node].configure('''
                vlan 316
                    private-vlan primary
                    private-vlan association 676
                    vn-segment 30316
                vlan 676
                    private-vlan isolated
                    vn-segment 30676
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 316 676
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name)) 
            testbed.devices[node].configure('''
                vlan 317
                    private-vlan primary
                    private-vlan association 677
                    vn-segment 30317
                vlan 677
                    private-vlan isolated
                    vn-segment 30677
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 317 677
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))        
            testbed.devices[node].configure('''
                vlan 318
                    private-vlan primary
                    private-vlan association 678
                    vn-segment 30318
                vlan 678
                    private-vlan isolated
                    vn-segment 30678
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 318 678
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))
            testbed.devices[node].configure('''
                vlan 319
                    private-vlan primary
                    private-vlan association 679
                    vn-segment 30319
                vlan 679
                    private-vlan isolated
                    vn-segment 30679
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 319 679
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))
            testbed.devices[node].configure('''
                vlan 320
                    private-vlan primary
                    private-vlan association 680
                    vn-segment 30320
                vlan 680
                    private-vlan isolated
                    vn-segment 30680
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 320 680
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))
            testbed.devices[node].configure('''
                vlan 321
                    private-vlan primary
                    private-vlan association 681
                    vn-segment 30121
                vlan 681
                    private-vlan isolated
                    vn-segment 30681
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 321 681
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name)) 
            testbed.devices[node].configure('''
                vlan 322
                    private-vlan primary
                    private-vlan association 682
                    vn-segment 30322
                vlan 682
                    private-vlan isolated
                    vn-segment 30682
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 322 682
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))
            testbed.devices[node].configure('''
                vlan 323
                    private-vlan primary
                    private-vlan association 683
                    vn-segment 30323
                vlan 683
                    private-vlan isolated
                    vn-segment 30683
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 323 683
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))
            testbed.devices[node].configure('''
                vlan 324
                    private-vlan primary
                    private-vlan association 684
                    vn-segment 30324
                vlan 684
                    private-vlan isolated
                    vn-segment 30684
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 324 684
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name)) 
            testbed.devices[node].configure('''
                vlan 325
                    private-vlan primary
                    private-vlan association 685
                    vn-segment 30325
                vlan 685
                    private-vlan isolated
                    vn-segment 30685
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 325 685
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))        
            testbed.devices[node].configure('''
                vlan 326
                    private-vlan primary
                    private-vlan association 686
                    vn-segment 30326
                vlan 686
                    private-vlan isolated
                    vn-segment 30626
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 326 686
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))
            testbed.devices[node].configure('''
                vlan 327
                    private-vlan primary
                    private-vlan association 687
                    vn-segment 30327
                vlan 687
                    private-vlan isolated
                    vn-segment 30687
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 327 687
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))
            testbed.devices[node].configure('''
                vlan 328
                    private-vlan primary
                    private-vlan association 688
                    vn-segment 30328
                vlan 688
                    private-vlan isolated
                    vn-segment 30688
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 328 688
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))
            testbed.devices[node].configure('''
                vlan 329
                    private-vlan primary
                    private-vlan association 689
                    vn-segment 30329
                vlan 689
                    private-vlan isolated
                    vn-segment 30689
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 329 689
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name)) 
            testbed.devices[node].configure('''
                vlan 330
                    private-vlan primary
                    private-vlan association 690
                    vn-segment 30330
                vlan 690
                    private-vlan isolated
                    vn-segment 30690
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 330 690
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))
            testbed.devices[node].configure('''
                vlan 331
                    private-vlan primary
                    private-vlan association 691
                    vn-segment 30331
                vlan 691
                    private-vlan isolated
                    vn-segment 30691
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 331 691
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))
            testbed.devices[node].configure('''
                vlan 332
                    private-vlan primary
                    private-vlan association 692
                    vn-segment 30332
                vlan 692
                    private-vlan isolated
                    vn-segment 30692
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 332 692
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))
            testbed.devices[node].configure('''
                vlan 333
                    private-vlan primary
                    private-vlan association 693
                    vn-segment 30333
                vlan 693
                    private-vlan isolated
                    vn-segment 30693
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 333 693
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name)) 
            testbed.devices[node].configure('''
                vlan 334
                    private-vlan primary
                    private-vlan association 694
                    vn-segment 30334
                vlan 694
                    private-vlan isolated
                    vn-segment 30694
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 334 694
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))        
            testbed.devices[node].configure('''
                vlan 335
                    private-vlan primary
                    private-vlan association 695
                    vn-segment 30335
                vlan 695
                    private-vlan isolated
                    vn-segment 30635
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 335 695
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))
            testbed.devices[node].configure('''
                vlan 336
                    private-vlan primary
                    private-vlan association 696
                    vn-segment 30336
                vlan 696
                    private-vlan isolated
                    vn-segment 30696
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 336 696
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))
            testbed.devices[node].configure('''
                vlan 337
                    private-vlan primary
                    private-vlan association 697
                    vn-segment 30337
                vlan 697
                    private-vlan isolated
                    vn-segment 30697
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 337 697
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))
            testbed.devices[node].configure('''
                vlan 338
                    private-vlan primary
                    private-vlan association 698
                    vn-segment 30338
                vlan 698
                    private-vlan isolated
                    vn-segment 30698
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 338 698
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name)) 
            testbed.devices[node].configure('''
                vlan 339
                    private-vlan primary
                    private-vlan association 699
                    vn-segment 30339
                vlan 699
                    private-vlan isolated
                    vn-segment 30699
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 339 699
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))
            testbed.devices[node].configure('''
                vlan 340
                    private-vlan primary
                    private-vlan association 700
                    vn-segment 30340
                vlan 700
                    private-vlan isolated
                    vn-segment 30700
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 340 700
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))
            testbed.devices[node].configure('''
                vlan 341
                    private-vlan primary
                    private-vlan association 701
                    vn-segment 30341
                vlan 701
                    private-vlan isolated
                    vn-segment 30701
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 341 701
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))           
            testbed.devices[node].configure('''
                vlan 342
                    private-vlan primary
                    private-vlan association 702
                    vn-segment 30342
                vlan 702
                    private-vlan isolated
                    vn-segment 30702
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 342 702
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))          
            testbed.devices[node].configure('''
                vlan 343
                    private-vlan primary
                    private-vlan association 703
                    vn-segment 30343
                vlan 403
                    private-vlan isolated
                    vn-segment 30703
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 343 703
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))         
            testbed.devices[node].configure('''
                vlan 344
                    private-vlan primary
                    private-vlan association 704
                    vn-segment 30344
                vlan 704
                    private-vlan isolated
                    vn-segment 30704
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 344 704
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))          
            testbed.devices[node].configure('''
                vlan 345
                    private-vlan primary
                    private-vlan association 705
                    vn-segment 40045
                vlan 705
                    private-vlan isolated
                    vn-segment 30705
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 345 705
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))         
            testbed.devices[node].configure('''
                vlan 346
                    private-vlan primary
                    private-vlan association 706
                    vn-segment 30346
                vlan 706
                    private-vlan isolated
                    vn-segment 30706
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 346 706
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))           
            testbed.devices[node].configure('''
                vlan 347
                    private-vlan primary
                    private-vlan association 707
                    vn-segment 30347
                vlan 707
                    private-vlan isolated
                    vn-segment 30707
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 347 707
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))          
            testbed.devices[node].configure('''
                vlan 348
                    private-vlan primary
                    private-vlan association 708
                    vn-segment 30348
                vlan 708
                    private-vlan isolated
                    vn-segment 30708
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 348 708
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))          
            testbed.devices[node].configure('''
                vlan 349
                    private-vlan primary
                    private-vlan association 709
                    vn-segment 30349
                vlan 709
                    private-vlan isolated
                    vn-segment 30709
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 349 709
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name)) 
            testbed.devices[node].configure('''
                vlan 350
                    private-vlan primary
                    private-vlan association 710
                    vn-segment 30350
                vlan 710
                    private-vlan isolated
                    vn-segment 30710
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 350 710
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))        
            testbed.devices[node].configure('''
                vlan 351
                    private-vlan primary
                    private-vlan association 711
                    vn-segment 30351
                vlan 711
                    private-vlan isolated
                    vn-segment 30711
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 351 711
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))
            testbed.devices[node].configure('''
                vlan 352
                    private-vlan primary
                    private-vlan association 712
                    vn-segment 30352
                vlan 712
                    private-vlan isolated
                    vn-segment 30712
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 352 712
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))
            testbed.devices[node].configure('''
                vlan 353
                    private-vlan primary
                    private-vlan association 713
                    vn-segment 30353
                vlan 713
                    private-vlan isolated
                    vn-segment 30713
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 353 713
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))
            testbed.devices[node].configure('''
                vlan 354
                    private-vlan primary
                    private-vlan association 714
                    vn-segment 30354
                vlan 714
                    private-vlan isolated
                    vn-segment 30714
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 354 714
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name)) 
            testbed.devices[node].configure('''
                vlan 355
                    private-vlan primary
                    private-vlan association 715
                    vn-segment 30355
                vlan 715
                    private-vlan isolated
                    vn-segment 30715
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 355 715
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))
            testbed.devices[node].configure('''
                vlan 356
                    private-vlan primary
                    private-vlan association 716
                    vn-segment 30356
                vlan 716
                    private-vlan isolated
                    vn-segment 30716
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 356 716
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))
            testbed.devices[node].configure('''
                vlan 357
                    private-vlan primary
                    private-vlan association 717
                    vn-segment 30357
                vlan 717
                    private-vlan isolated
                    vn-segment 30717
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 357 717
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))
            testbed.devices[node].configure('''
                vlan 358
                    private-vlan primary
                    private-vlan association 718
                    vn-segment 30358
                vlan 718
                    private-vlan isolated
                    vn-segment 30718
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 358 718
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))           
            testbed.devices[node].configure('''
                vlan 359
                    private-vlan primary
                    private-vlan association 719
                    vn-segment 30359
                vlan 719
                    private-vlan isolated
                    vn-segment 30719
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 359 719
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))          
            testbed.devices[node].configure('''
                vlan 360
                    private-vlan primary
                    private-vlan association 720
                    vn-segment 30360
                vlan 720
                    private-vlan isolated
                    vn-segment 30720
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 360 720
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))         
            testbed.devices[node].configure('''
                vlan 361
                    private-vlan primary
                    private-vlan association 721
                    vn-segment 30361
                vlan 721
                    private-vlan isolated
                    vn-segment 30721
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 361 721
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))          
            testbed.devices[node].configure('''
                vlan 362
                    private-vlan primary
                    private-vlan association 722
                    vn-segment 30362
                vlan 722
                    private-vlan isolated
                    vn-segment 30722
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 362 722
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))         
            testbed.devices[node].configure('''
                vlan 263
                    private-vlan primary
                    private-vlan association 723
                    vn-segment 40263
                vlan 723
                    private-vlan isolated
                    vn-segment 30723
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 263 723
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))           
            testbed.devices[node].configure('''
                vlan 364
                    private-vlan primary
                    private-vlan association 724
                    vn-segment 30364
                vlan 724
                    private-vlan isolated
                    vn-segment 30724
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 364 724
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))          
            testbed.devices[node].configure('''
                vlan 365
                    private-vlan primary
                    private-vlan association 725
                    vn-segment 30365
                vlan 725
                    private-vlan isolated
                    vn-segment 30725
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 365 725
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))          
            testbed.devices[node].configure('''
                vlan 366
                    private-vlan primary
                    private-vlan association 726
                    vn-segment 30366
                vlan 726
                    private-vlan isolated
                    vn-segment 30726
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 366 726
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name)) 
            testbed.devices[node].configure('''
                vlan 367
                    private-vlan primary
                    private-vlan association 727
                    vn-segment 30367
                vlan 727
                    private-vlan isolated
                    vn-segment 30727
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 367 727
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))        
            testbed.devices[node].configure('''
                vlan 368
                    private-vlan primary
                    private-vlan association 728
                    vn-segment 30368
                vlan 728
                    private-vlan isolated
                    vn-segment 30728
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 368 728
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))
            testbed.devices[node].configure('''
                vlan 369
                    private-vlan primary
                    private-vlan association 728
                    vn-segment 30369
                vlan 728
                    private-vlan isolated
                    vn-segment 30728
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 369 728
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))
            testbed.devices[node].configure('''
                vlan 370
                    private-vlan primary
                    private-vlan association 730
                    vn-segment 30370
                vlan 730
                    private-vlan isolated
                    vn-segment 30730
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 370 730
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))
            testbed.devices[node].configure('''
                vlan 371
                    private-vlan primary
                    private-vlan association 731
                    vn-segment 30371
                vlan 731
                    private-vlan isolated
                    vn-segment 30731
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 371 731
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name)) 
            testbed.devices[node].configure('''
                vlan 372
                    private-vlan primary
                    private-vlan association 732
                    vn-segment 30372
                vlan 732
                    private-vlan isolated
                    vn-segment 30732
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 372 732
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))
            testbed.devices[node].configure('''
                vlan 373
                    private-vlan primary
                    private-vlan association 733
                    vn-segment 30373
                vlan 733
                    private-vlan isolated
                    vn-segment 30773
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 373 733
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))     
            testbed.devices[node].configure('''
                vlan 374
                    private-vlan primary
                    private-vlan association 734
                    vn-segment 30374
                vlan 734
                    private-vlan isolated
                    vn-segment 30734
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 374 734
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))
            testbed.devices[node].configure('''
                vlan 375
                    private-vlan primary
                    private-vlan association 735
                    vn-segment 30375
                vlan 735
                    private-vlan isolated
                    vn-segment 30735
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 375 735
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))           
            testbed.devices[node].configure('''
                vlan 376
                    private-vlan primary
                    private-vlan association 736
                    vn-segment 30376
                vlan 736
                    private-vlan isolated
                    vn-segment 30736
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 376 736
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))          
            testbed.devices[node].configure('''
                vlan 377
                    private-vlan primary
                    private-vlan association 737
                    vn-segment 30377
                vlan 737
                    private-vlan isolated
                    vn-segment 30777
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 377 737
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))         
            testbed.devices[node].configure('''
                vlan 378
                    private-vlan primary
                    private-vlan association 738
                    vn-segment 30378
                vlan 738
                    private-vlan isolated
                    vn-segment 30738
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 378 738
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))          
            testbed.devices[node].configure('''
                vlan 379
                    private-vlan primary
                    private-vlan association 739
                    vn-segment 30379
                vlan 739
                    private-vlan isolated
                    vn-segment 30739
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 379 739
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))         
            testbed.devices[node].configure('''
                vlan 380
                    private-vlan primary
                    private-vlan association 740
                    vn-segment 30380
                vlan 740
                    private-vlan isolated
                    vn-segment 30740
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 380 740
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))           
            testbed.devices[node].configure('''
                vlan 381
                    private-vlan primary
                    private-vlan association 741
                    vn-segment 30381
                vlan 741
                    private-vlan isolated
                    vn-segment 30741
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 381 741
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))          
            testbed.devices[node].configure('''
                vlan 812
                    private-vlan primary
                    private-vlan association 742
                    vn-segment 30382
                vlan 742
                    private-vlan isolated
                    vn-segment 30742
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 382 742
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))          
            testbed.devices[node].configure('''
                vlan 383
                    private-vlan primary
                    private-vlan association 743
                    vn-segment 30383
                vlan 743
                    private-vlan isolated
                    vn-segment 30743
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 383 743
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name)) 
            testbed.devices[node].configure('''
                vlan 384
                    private-vlan primary
                    private-vlan association 744
                    vn-segment 30384
                vlan 744
                    private-vlan isolated
                    vn-segment 30744
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 384 744
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))        
            testbed.devices[node].configure('''
                vlan 385
                    private-vlan primary
                    private-vlan association 745
                    vn-segment 30385
                vlan 745
                    private-vlan isolated
                    vn-segment 30745
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 385 745
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))
            testbed.devices[node].configure('''
                vlan 386
                    private-vlan primary
                    private-vlan association 746
                    vn-segment 30386
                vlan 746
                    private-vlan isolated
                    vn-segment 30746
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 386 746
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))
            testbed.devices[node].configure('''
                vlan 387
                    private-vlan primary
                    private-vlan association 747
                    vn-segment 30387
                vlan 747
                    private-vlan isolated
                    vn-segment 30747
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 387 747
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))
            testbed.devices[node].configure('''
                vlan 388
                    private-vlan primary
                    private-vlan association 748
                    vn-segment 30388
                vlan 748
                    private-vlan isolated
                    vn-segment 30748
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 388 748
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name)) 
            testbed.devices[node].configure('''
                vlan 389
                    private-vlan primary
                    private-vlan association 749
                    vn-segment 30389
                vlan 749
                    private-vlan isolated
                    vn-segment 30749
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 389 749
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))
            testbed.devices[node].configure('''
                vlan 390
                    private-vlan primary
                    private-vlan association 750
                    vn-segment 30390
                vlan 750
                    private-vlan isolated
                    vn-segment 30750
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 390 750
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))
            testbed.devices[node].configure('''
                vlan 391
                    private-vlan primary
                    private-vlan association 751
                    vn-segment 30391
                vlan 751
                    private-vlan isolated
                    vn-segment 30751
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 391 751
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))
            testbed.devices[node].configure('''
                vlan 392
                    private-vlan primary
                    private-vlan association 752
                    vn-segment 30392
                vlan 752
                    private-vlan isolated
                    vn-segment 30752
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 392 752
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))           
            testbed.devices[node].configure('''
                vlan 393
                    private-vlan primary
                    private-vlan association 753
                    vn-segment 30393
                vlan 753
                    private-vlan isolated
                    vn-segment 30753
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 393 753
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))          
            testbed.devices[node].configure('''
                vlan 394
                    private-vlan primary
                    private-vlan association 754
                    vn-segment 30394
                vlan 754
                    private-vlan isolated
                    vn-segment 30754
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 394 754
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))         
            testbed.devices[node].configure('''
                vlan 395
                    private-vlan primary
                    private-vlan association 755
                    vn-segment 30395
                vlan 755
                    private-vlan isolated
                    vn-segment 30755
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 395 755
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))          
            testbed.devices[node].configure('''
                vlan 396
                    private-vlan primary
                    private-vlan association 756
                    vn-segment 30396
                vlan 756
                    private-vlan isolated
                    vn-segment 30756
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 396 756
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))         
            testbed.devices[node].configure('''
                vlan 397
                    private-vlan primary
                    private-vlan association 757
                    vn-segment 30397
                vlan 757
                    private-vlan isolated
                    vn-segment 30757
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 397 757
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))           
            testbed.devices[node].configure('''
                vlan 398
                    private-vlan primary
                    private-vlan association 758
                    vn-segment 30398
                vlan 758
                    private-vlan isolated
                    vn-segment 30758
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 398 758
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))          
            testbed.devices[node].configure('''
                vlan 399
                    private-vlan primary
                    private-vlan association 759
                    vn-segment 30399
                vlan 759
                    private-vlan isolated
                    vn-segment 30759
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 399 759
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))          
            testbed.devices[node].configure('''
                vlan 400
                    private-vlan primary
                    private-vlan association 760
                    vn-segment 30400
                vlan 760
                    private-vlan isolated
                    vn-segment 30760
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 400 760
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name)) 
            testbed.devices[node].configure('''
                vlan 401
                    private-vlan primary
                    private-vlan association 761
                    vn-segment 30401
                vlan 761
                    private-vlan isolated
                    vn-segment 30761
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 401 761
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))        
            testbed.devices[node].configure('''
                vlan 402
                    private-vlan primary
                    private-vlan association 762
                    vn-segment 30402
                vlan 762
                    private-vlan isolated
                    vn-segment 30762
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 402 762
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))
            testbed.devices[node].configure('''
                vlan 303
                    private-vlan primary
                    private-vlan association 763
                    vn-segment 30303
                vlan 763
                    private-vlan isolated
                    vn-segment 30763
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 303 763
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))
            testbed.devices[node].configure('''
                vlan 304
                    private-vlan primary
                    private-vlan association 764
                    vn-segment 30304
                vlan 764
                    private-vlan isolated
                    vn-segment 30764
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 304 764
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))
            testbed.devices[node].configure('''
                vlan 405
                    private-vlan primary
                    private-vlan association 765
                    vn-segment 30305
                vlan 765
                    private-vlan isolated
                    vn-segment 30765
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 305 765
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name)) 
            testbed.devices[node].configure('''
                vlan 306
                    private-vlan primary
                    private-vlan association 766
                    vn-segment 30306
                vlan 766
                    private-vlan isolated
                    vn-segment 30766
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 306 766
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))
            testbed.devices[node].configure('''
                vlan 407
                    private-vlan primary
                    private-vlan association 767
                    vn-segment 30407
                vlan 767
                    private-vlan isolated
                    vn-segment 30767
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 407 767
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))
            testbed.devices[node].configure('''
                vlan 408
                    private-vlan primary
                    private-vlan association 768
                    vn-segment 30408
                vlan 768
                    private-vlan isolated
                    vn-segment 30768
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 408 768
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name)) 
            testbed.devices[node].configure('''
                vlan 409
                    private-vlan primary
                    private-vlan association 769
                    vn-segment 30409
                vlan 769
                    private-vlan isolated
                    vn-segment 30769
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 409 769
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))        
            testbed.devices[node].configure('''
                vlan 410
                    private-vlan primary
                    private-vlan association 770
                    vn-segment 30410
                vlan 770
                    private-vlan isolated
                    vn-segment 30770
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 410 770
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))
            testbed.devices[node].configure('''
                vlan 411
                    private-vlan primary
                    private-vlan association 771
                    vn-segment 30411
                vlan 771
                    private-vlan isolated
                    vn-segment 30771
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 411 771
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))
            testbed.devices[node].configure('''
                vlan 412
                    private-vlan primary
                    private-vlan association 772
                    vn-segment 30412
                vlan 772
                    private-vlan isolated
                    vn-segment 30772
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 412 772
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))
            testbed.devices[node].configure('''
                vlan 413
                    private-vlan primary
                    private-vlan association 773
                    vn-segment 30413
                vlan 773
                    private-vlan isolated
                    vn-segment 30773
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 413 773
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name)) 
            testbed.devices[node].configure('''
                vlan 414
                    private-vlan primary
                    private-vlan association 774
                    vn-segment 30414
                vlan 774
                    private-vlan isolated
                    vn-segment 30774
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 414 774
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))
            testbed.devices[node].configure('''
                vlan 415
                    private-vlan primary
                    private-vlan association 775
                    vn-segment 30415
                vlan 775
                    private-vlan isolated
                    vn-segment 30775
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 415 775
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))
            testbed.devices[node].configure('''
                vlan 416
                    private-vlan primary
                    private-vlan association 776
                    vn-segment 30416
                vlan 776
                    private-vlan isolated
                    vn-segment 30776
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 416 776
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name)) 
            testbed.devices[node].configure('''
                vlan 417
                    private-vlan primary
                    private-vlan association 777
                    vn-segment 30417
                vlan 777
                    private-vlan isolated
                    vn-segment 30777
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 417 777
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))        
            testbed.devices[node].configure('''
                vlan 418
                    private-vlan primary
                    private-vlan association 778
                    vn-segment 30418
                vlan 778
                    private-vlan isolated
                    vn-segment 30778
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 418 778
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))
            testbed.devices[node].configure('''
                vlan 419
                    private-vlan primary
                    private-vlan association 779
                    vn-segment 30419
                vlan 779
                    private-vlan isolated
                    vn-segment 30779
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 419 779
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))
            testbed.devices[node].configure('''
                vlan 420
                    private-vlan primary
                    private-vlan association 780
                    vn-segment 30420
                vlan 780
                    private-vlan isolated
                    vn-segment 30780
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 420 780
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))
            testbed.devices[node].configure('''
                vlan 421
                    private-vlan primary
                    private-vlan association 781
                    vn-segment 40421
                vlan 781
                    private-vlan isolated
                    vn-segment 30781
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 421 781
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name)) 
            testbed.devices[node].configure('''
                vlan 422
                    private-vlan primary
                    private-vlan association 782
                    vn-segment 30422
                vlan 782
                    private-vlan isolated
                    vn-segment 30782
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 422 782
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))
            testbed.devices[node].configure('''
                vlan 423
                    private-vlan primary
                    private-vlan association 783
                    vn-segment 30423
                vlan 783
                    private-vlan isolated
                    vn-segment 30783
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 423 783
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))
            testbed.devices[node].configure('''
                vlan 424
                    private-vlan primary
                    private-vlan association 784
                    vn-segment 30424
                vlan 784
                    private-vlan isolated
                    vn-segment 30784
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 424 784
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name)) 
            testbed.devices[node].configure('''
                vlan 425
                    private-vlan primary
                    private-vlan association 785
                    vn-segment 30425
                vlan 785
                    private-vlan isolated
                    vn-segment 30785
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 425 785
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))        
            testbed.devices[node].configure('''
                vlan 426
                    private-vlan primary
                    private-vlan association 786
                    vn-segment 30426
                vlan 786
                    private-vlan isolated
                    vn-segment 30726
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 426 786
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))
            testbed.devices[node].configure('''
                vlan 427
                    private-vlan primary
                    private-vlan association 787
                    vn-segment 30427
                vlan 787
                    private-vlan isolated
                    vn-segment 30787
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 427 787
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))
            testbed.devices[node].configure('''
                vlan 428
                    private-vlan primary
                    private-vlan association 788
                    vn-segment 30428
                vlan 788
                    private-vlan isolated
                    vn-segment 30788
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 428 788
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))
            testbed.devices[node].configure('''
                vlan 429
                    private-vlan primary
                    private-vlan association 789
                    vn-segment 30429
                vlan 789
                    private-vlan isolated
                    vn-segment 30789
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 429 789
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name)) 
            testbed.devices[node].configure('''
                vlan 430
                    private-vlan primary
                    private-vlan association 790
                    vn-segment 30430
                vlan 790
                    private-vlan isolated
                    vn-segment 30790
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 430 790
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))
            testbed.devices[node].configure('''
                vlan 431
                    private-vlan primary
                    private-vlan association 791
                    vn-segment 30431
                vlan 791
                    private-vlan isolated
                    vn-segment 30791
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 431 791
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))
            testbed.devices[node].configure('''
                vlan 432
                    private-vlan primary
                    private-vlan association 792
                    vn-segment 30432
                vlan 792
                    private-vlan isolated
                    vn-segment 30792
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 432 792
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))
            testbed.devices[node].configure('''
                vlan 433
                    private-vlan primary
                    private-vlan association 793
                    vn-segment 30433
                vlan 793
                    private-vlan isolated
                    vn-segment 30793
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 433 793
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name)) 
            testbed.devices[node].configure('''
                vlan 434
                    private-vlan primary
                    private-vlan association 794
                    vn-segment 30434
                vlan 794
                    private-vlan isolated
                    vn-segment 30794
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 434 794
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))        
            testbed.devices[node].configure('''
                vlan 435
                    private-vlan primary
                    private-vlan association 795
                    vn-segment 30435
                vlan 795
                    private-vlan isolated
                    vn-segment 30735
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 435 795
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))
            testbed.devices[node].configure('''
                vlan 436
                    private-vlan primary
                    private-vlan association 796
                    vn-segment 30436
                vlan 796
                    private-vlan isolated
                    vn-segment 30796
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 436 796
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))
            testbed.devices[node].configure('''
                vlan 437
                    private-vlan primary
                    private-vlan association 797
                    vn-segment 30437
                vlan 797
                    private-vlan isolated
                    vn-segment 30797
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 437 797
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name))
            testbed.devices[node].configure('''
                vlan 438
                    private-vlan primary
                    private-vlan association 798
                    vn-segment 30438
                vlan 798
                    private-vlan isolated
                    vn-segment 30798
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 438 798
                    no shutdown
                '''.format(testbed.devices[node].interfaces[int].name)) 
            testbed.devices[node].configure('''
                vlan 439
                    private-vlan primary
                    private-vlan association 799
                    vn-segment 30439
                vlan 799
                    private-vlan isolated
                    vn-segment 30799
                interface {0}
                    switchport
                    switchport mode private-vlan trunk promiscuous
                    switchport private-vlan mapping trunk 439 799
                    no shutdown
                default int {0}
                no vlan 40-99
                no vlan 103-440
                '''.format(testbed.devices[node].interfaces[int].name))           
class pvlan_with_system_dot1q_transit(nxtest.Testcase):
    # configure dot1q transit cli on both vpc vteps and verify rhe traffic flow
    @aetest.test
    def pvlan_with_system_dot1q_transit(self, testbed,testscript,device_dut,vlan_l3):
        for node in device_dut:
            testbed.devices[node].configure('''
                system dot1q-tunnel transit vlan {0}
                '''.format(vlan_l3))
            
class vmct_configs_spine(nxtest.Testcase):
    # configure vmct clis on spine
    @aetest.test
    def vmct_configs_spine(self, testbed,testscript,device_dut1,intf_ch,intf_ch1):
        for node in device_dut1:
            testbed.devices[node].configure('''
                class-map type qos match-all CFS
                    match dscp 56
                policy-map type qos CFS
                    class CFS
                        Set qos-group 7
                con t
                interface {0}
                    service-policy type qos input CFS
                con t
                interface {1}
                    service-policy type qos input CFS
                '''.format(testbed.devices[node].interfaces[intf_ch].name,testbed.devices[node].interfaces[intf_ch1].name))
class vmct_configs_tecates(nxtest.Testcase):
    # configure vmct clis on spine
    @aetest.test    
    def vmct_configs_tecates(self, testbed,testscript,device_dut2,device_dut3,loopbk,ip_add1,underlay,ch_grp,vpc,dest_ip1,src_ip1,intf_ch3,intf_ch4,ip_add2,dest_ip2,src_ip2):
        for node in device_dut2:
            testbed.devices[node].configure('''
                hardware access-list tcam region ing-racl 0
                hardware access-list tcam region ing-sup 768
                hardware access-list tcam region ing-flow-redirect 512
                interface loopback{0}
                    ipv6 address {1}
                    ipv6 router ospfv3 {2} area 0.0.0.0
                    no shut
                vpc domain {4}
                    virtual peer-link destination {5} source {6} dscp 56
                '''.format(loopbk,ip_add1,underlay,ch_grp,vpc,dest_ip1,src_ip1,testbed.devices[node].interfaces[intf_ch3].name,testbed.devices[node].interfaces[intf_ch4].name,ip_add2,dest_ip2,src_ip2))
    # configure vmct clis on tecate-2
    def vmct_configs(self, testbed,testscript,device_dut1,device_dut2,device_dut3,loopbk,ip_add1,underlay,ch_grp,vpc,dest_ip1,src_ip1,intf_ch3,intf_ch4,ip_add2,dest_ip2,src_ip2):
        for node in device_dut3:
            testbed.devices[node].configure('''
                hardware access-list tcam region ing-racl 0
                hardware access-list tcam region ing-sup 768
                hardware access-list tcam region ing-flow-redirect 512
                interface loopback{0}
                    ipv6 address {11}
                    ipv6 router ospfv3 {2} area 0.0.0.0
                    no shut
                vpc domain {4}
                    virtual peer-link destination {12} source {13} dscp 56
                '''.format(loopbk,ip_add1,underlay,ch_grp,vpc,dest_ip1,src_ip1,testbed.devices[node].interfaces[intf_ch3].name,testbed.devices[node].interfaces[intf_ch4].name,ip_add2,dest_ip2,src_ip2))   
class isolated_community_promiscuous(nxtest.Testcase):
    # configure isolated, promiscuous and community ports on sumpin
    @aetest.test
    def isolated_community_promiscuous(self, testbed,testscript,device_dut,po_ch,pri_vlan,sec_vlan,vlan_st,sec_vlan1):
        for node in device_dut:
            testbed.devices[node].configure('''
            interface port-channel{0}
                switchport
                switchport mode private-vlan host
                switchport private-vlan host-association {1} {2}
                '''.format(po_ch,pri_vlan,sec_vlan,vlan_st,sec_vlan1))   
            testbed.devices[node].configure('''
            interface port-channel{0}
                switchport
                switchport mode private-vlan host
                switchport private-vlan host-association {1} {4}
                '''.format(po_ch,pri_vlan,sec_vlan,vlan_st,sec_vlan1))              
            testbed.devices[node].configure('''
            interface port-channel{0}
                switchport
                switchport mode private-vlan promiscuous
                switchport private-vlan mapping {1} {3} 
                '''.format(po_ch,pri_vlan,sec_vlan,vlan_st,sec_vlan1))            
class native_vlan_vmct(nxtest.Testcase):
    # on sumpin configured native vlans
    @aetest.test
    def native_vlan_vmct(self, testbed,testscript,device_dut,po_ch,pri_vlan):
        for node in device_dut:
            testbed.devices[node].configure('''
            interface port-channel{0}
                switchport
                switchport mode trunk
                switchport trunk native vlan {1}
                spanning-tree port type edge trunk
                '''.format(po_ch,pri_vlan)) 
class trunk_community_promiscuous(nxtest.Testcase):
    @aetest.test
    #on sumpin e1/48 configuring trunk vlan and verifying the traffic flow
    def trunk_community_promiscuous(self, testbed,testscript,device_dut,po_ch,pri_vlan,sec_vlan,vlan_st,intf_ch):
        for node in device_dut:                    
            testbed.devices[node].configure('''
                default int {4}
                interface {4}
                    switchport
                    switchport mode trunk
                    switchport trunk allowed vlan {1},{2}
                    spanning-tree port type edge trunk
                    no shutdown
                '''.format(po_ch,pri_vlan,sec_vlan,vlan_st,testbed.devices[node].interfaces[intf_ch].name))
            testbed.devices[node].configure('''
            default int port-channel{0}
            interface port-channel1
                switchport
                switchport mode private-vlan host
                switchport private-vlan host-association {1} {2}
                '''.format(po_ch,pri_vlan,sec_vlan,vlan_st,testbed.devices[node].interfaces[intf_ch].name))  
            testbed.devices[node].configure('''
            interface port-channel{0}
                switchport
                switchport mode private-vlan promiscuous
                switchport private-vlan mapping {1} {3}
                '''.format(po_ch,pri_vlan,sec_vlan,vlan_st,testbed.devices[node].interfaces[intf_ch].name))   
class mac_move_vmct_community_vlan(nxtest.Testcase):
    # shutting the e1/1 on tecate-1 and e1/5 on tecate-2 verifying the mac move
    @aetest.test
    def mac_move_vmct_community_vlan(self, testbed,testscript,device_dut,intf_ch):
        for node in device_dut:
            testbed.devices[node].configure('''
                show mac address-table dynamic
                int {0}
                    shut
                '''.format(testbed.devices[node].interfaces[intf_ch].name))
            time.sleep(2)
            output = testbed.devices[node].configure('show mac address-table dynamic')
            mac_search = re.search('[a-z]+[A-Z]+[A-Z]+.+[A-Z]+[a-z]+[a-z]+[a-z]+.+[A-Z]+[a-z]+[a-z]+[a-z]', output)
            fin = mac_search.group()
            fail_flag = []
            if (fin == 'vPC Peer-Link'):
                print('passed')
            else:
                fail_flag.append(0)  
                print('mac move is failed')            
              
        for node in device_dut:
            testbed.devices[node].configure('''
                int {0}
                    no shut
                '''.format(testbed.devices[node].interfaces[intf_ch].name))
            time.sleep(2)
class mac_move_vmct_isolated_vlan(nxtest.Testcase):
    # changing the e1/5 on tecate-2 to isolated vlan and verifying the mac move
    @aetest.test
    def mac_move_vmct_isolated_vlan(self, testbed,testscript,device_dut,po_ch,pri_vlan,sec_vlan,sec_vlan1):
        for node in device_dut:
            testbed.devices[node].configure('''
                show mac address-table dynamic
                int port-channel {0}
                    switchport private-vlan host-association {1} {3}
                '''.format(po_ch,pri_vlan,sec_vlan,sec_vlan1))
            time.sleep(2)           
              
        for node in device_dut:
            testbed.devices[node].configure('''
                int port-channel {0}
                    switchport private-vlan host-association {1} {2}
                '''.format(po_ch,pri_vlan,sec_vlan,sec_vlan1))
            time.sleep(2)
class copy_replace(nxtest.Testcase):
    # copying the file to bootflash and changing the configs, then replacing the old configs
    @aetest.test
    def copy_replace(self, testbed,testscript,device_dut,po_ch,pri_vlan,sec_vlan,vpc):
        for node in device_dut:
            testbed.devices[node].configure('''
                int port-channel {0}
                        switchport
                        switchport mode private-vlan host
                        switchport private-vlan host-association {1} {2}
                        vpc {3}
                configure replace bootflash:vpc_config
                '''.format(po_ch,pri_vlan,sec_vlan,vpc))
            time.sleep(2)
class igmp_snooping_disabled(nxtest.Testcase):
    # disabling igmp snooping on tecate-2 and verifying the traffic flow
    @aetest.test
    def igmp_snooping_disabled(self, testbed,testscript,device_dut):
        for node in device_dut:
            testbed.devices[node].configure('''
                no ip igmp snooping
                ''')
            time.sleep(2)

class NDIssu_StandAloneBGW(nxtest.Testcase):
    @aetest.test
    
    def NDIssu_StandAloneBGW(self, testbed, device_dut,target_image):
        """ VERIFY_ISSU """
        # Establish dialogs for running ISSU command
        dialog = Dialog([
            Statement(pattern=r'Do you want to continue with the installation \(y/n\)\?',
                      action='sendline(y)',
                      loop_continue=True,
                      continue_timer=True),
        ])

        # Create ISSU command
        issu_cmd = 'install all nxos '+str(target_image)+' non-disruptive'

        # Perform ISSU
        # result, output = testscript.parameters['LEAF-2'].reload(reload_command=issu_cmd, prompt_recovery=True, dialog=dialog, timeout=2000, return_output=True)
        for node in device_dut:
            result, output = testbed.devices[node].reload(reload_command=issu_cmd, prompt_recovery=True, dialog=dialog, timeout=2000, return_output=True)
            output_split = list(filter(None, output.split('\n')))
            fail_flag = []
            fail_logs = '\n'

        # Process logs for any failure reasons
        for log_line in output_split:
            if re.search('CRASHED|fail |CPU Hog|malloc|core dump|mts_send|redzone|error', log_line, re.I):
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
class dhcp_snooping_enabled(nxtest.Testcase):
    # enabling dhcp snooping on tecate-2 and verifying the traffic flow
    @aetest.test
    def dhcp_snooping_enabled(self, testbed,testscript,device_dut):
        for node in device_dut:
            testbed.devices[node].configure('''
                ip dhcp snooping
                ''')
            time.sleep(2)
class process_restart(nxtest.Testcase):
    #restarting the bgp process on sumpin and verifying the traffic
    @aetest.test
    def process_restart(self, testbed,testscript,device_dut,bgp_asn):
        for node in device_dut:
            testbed.devices[node].configure('''
                restart bgp {0}
                '''.format(bgp_asn))
            time.sleep(2)  
class clear_trigger(nxtest.Testcase):
    #clearing the trigger on sumpin and checking the cleared triggers
    @aetest.test
    def clear_trigger(self, testbed,testscript,device_dut):
        for node in device_dut:
            testbed.devices[node].configure('''
                clear ipv6 neighbor  force-delete
                clear ip arp force-delete
                clear mac address-table dynamic
                ''')
            output = testbed.devices[node].configure('show ipv6 neighbor')
            mac_search = re.search('[A-Z]+[a-z]+[a-z]+[a-z]+ +[a-z]+[a-z]+[a-z]+[a-z]+[a-z]+[a-z]+ +[a-z]+[a-z]+ +[a-z]+[a-z]+[a-z]+[a-z]+[a-z]+[a-z]+.+ +[0-9]', output)
            fin = mac_search.group()
            fail_flag = []
            if (fin == 'Total number of entries: 0'):
                print('passed')
            else:
                fail_flag.append(0)  
                print('clear trigger is failed')
            time.sleep(2)   
            output = testbed.devices[node].configure('show ip arp')
            mac_search = re.search('[A-Z]+[a-z]+[a-z]+[a-z]+ +[a-z]+[a-z]+[a-z]+[a-z]+[a-z]+[a-z]+ +[a-z]+[a-z]+ +[a-z]+[a-z]+[a-z]+[a-z]+[a-z]+[a-z]+.+ +[0-9]', output)
            fin = mac_search.group()
            fail_flag = []
            if (fin == 'Total number of entries: 0'):
                print('passed')
            else:
                fail_flag.append(0)  
                print('clear trigger is failed')
            time.sleep(2)  
class snmp_stats(nxtest.Testcase):
    #clearing the trigger on sumpin and checking the cleared triggers
    @aetest.test
    def snmp_stats(self, testbed,testscript,device_dut1,device_dut2,intf_ch,ip_addr,ip_addr1,ip_addr2,ip_addr3):
        for node in device_dut1:
            testbed.devices[node].configure('''
                interface {0}
                    ip address {1}
                    no shutdown
                run bash snmpget -v 2c -c public {2} SNMPv2-SMI::enterprises.9.9.820.1.1.1.1.4.1
                '''.format(testbed.devices[node].interfaces[intf_ch].name,ip_addr,ip_addr1,ip_addr2,ip_addr3))
    #clearing the trigger on sumpin and checking the cleared triggers
        for node in device_dut2:
            testbed.devices[node].configure('''
                interface {0}
                    ip address {3}
                    no shutdown
                snmp-server host {4} traps version 2c public
                snmp-server host {4} use-vrf default
                snmp-server community public group network-operator
                '''.format(testbed.devices[node].interfaces[intf_ch].name,ip_addr,ip_addr1,ip_addr2,ip_addr3))
            output = testbed.devices[node].configure('show snmp oid-statistics  | grep iso.3.6.1.4.1.9.9.820.1.1.1.1.4')
            mac_search = re.search('[0-9]+[0-9]', output)
            fin = mac_search.group()
            fail_flag = []
            if (fin == '31'):
                print('passed')
            else:
                fail_flag.append(0)  
                print('snmp stats is failed')
            time.sleep(2)   
class consistency_parameters(nxtest.Testcase):
    #clearing the trigger on sumpin and checking the cleared triggers
    @aetest.test
    def consistency_parameters(self, testbed,testscript,device_dut):
        for node in device_dut:
            testbed.devices[node].configure('''
                show consistency-checker vxlan vlan all
                ''')
class downgrade_image(nxtest.Testcase):
    @aetest.test
    
    def downgrade_image(self, testbed, device_dut,target_image):
        """ VERIFY_ISSU """
        # Establish dialogs for running ISSU command
        dialog = Dialog([
            Statement(pattern=r'Do you want to continue with the installation \(y/n\)\?',
                      action='sendline(y)',
                      loop_continue=True,
                      continue_timer=True),
        ])

        # Create ISSU command
        issu_cmd = 'install all nxos '+str(target_image)

        # Perform ISSU
        # result, output = testscript.parameters['LEAF-2'].reload(reload_command=issu_cmd, prompt_recovery=True, dialog=dialog, timeout=2000, return_output=True)
        for node in device_dut:
            result, output = testbed.devices[node].reload(reload_command=issu_cmd, prompt_recovery=True, dialog=dialog, timeout=2000, return_output=True)
            output_split = list(filter(None, output.split('\n')))
            fail_flag = []
            fail_logs = '\n'

        # Process logs for any failure reasons
        for log_line in output_split:
            if re.search('CRASHED|fail |CPU Hog|malloc|core dump|mts_send|redzone|error', log_line, re.I):
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
###################################################################
###                  Trigger Verifications                      ###
###################################################################

class SampleTest(nxtest.Testcase):
    """ Common Setup """

    @aetest.test
    def SampleTest_1(self, testscript, testbed, steps):
        """ common setup subsection: Initializing Genie Testbed """

        log.info("Just a sample")
