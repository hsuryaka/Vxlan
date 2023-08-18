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

# Verify interface traffic on devices
# def IntTrafficVerify(section, steps, **kwargs):
#     fail_flag = []

#     for node in section.parameters['testbed'].find_devices(os=Or('NEXUS|NXOS|nxos')):
#     # for node in section.parameters['testbed'].find_devices(mod=Or('N7K')):
#         next_hop = node.execute("show ip route 10.3.0.3")
#         if next_hop != '':
#             output = node.configure('show ip route 10.3.0.3')
#             nve_search = re.search('[a-z]+[a-z]+[a-z]+[a-z]+[a-z]+.+[a-z]+[a-z]+[a-z]+[a-z]+[a-z]+.+ +[0-9]+.+[0-9]', output)
#             fin = nve_search.group()
#             if (fin == 'ubest/mbest: 4/0'):
#                 print('passed')
#             else:
#                 fail_flag.append(0)
#     if 0 in fail_flag:
#         section.failed()
#     else:
#         section.passed()

def VerifyTERoute(section, steps, **kwargs):
    """ Verify TE Route """

    with steps.start("Verify TE Routes"):
        device_duts = kwargs.get('vpc_dut_list', 1)
        stand_alone_node = kwargs.get('stdalone_dut_list', 1)
        log.info("Entered VerifyTERoute ##### ##### ##### ")
        # cli_to_parse = kwargs.get('nh_cli_to_parse', 1)
        # te_route_cli = kwargs.get('te_route_cli_to_parse1', 1)
        # stdalone_te_route_cli = kwargs.get('te_route_cli_to_parse2', 1)
        # log.info(te_route_cli)

        # Verification for failed logs
        fail_flag1 = []
        fail_flag2 = []
        fail_flag3 = []
        validation_msgs = ''
        output1 = ''
        output2 = ''
        output3 = ''
        retry_iteration = 1

        # Get the Total IPv6 Neighbor count
        for node in device_duts:
            for retry_iteration in range(4):
                output = section.parameters['testbed'].devices[node].execute('show ip route 10.3.0.3')
                output1 = re.search('10.3.0.3/32, ubest/mbest: 4/0', output, re.IGNORECASE)
                if output1 != None:
                    output = section.parameters['testbed'].devices[node].execute('show ip route 10.3.0.3 vrf egress-loadbalance-resolution-')
                    if (re.search('10.3.0.3/32, ubest/mbest: 8/0', output, re.IGNORECASE)):
                        log.info("NextHop 10.3.0.3 added to egress-loadbalance-resolution- VRF in "+node)
                        # fail_flag1 = []
                        output2 = section.parameters['testbed'].devices[node].execute('show ip arp')
                        output3 = re.search('10.10.40.1', output2, re.IGNORECASE)
                        if output3 != None:
                            section.parameters['testbed'].devices[node].execute('clear counters int e1/19-20,e1/49/1-4,e1/53-54')
                            output4 = section.parameters['testbed'].devices[node].execute('show int e1/19-20,e1/49/1-4,e1/53-54 | i i rate')
                            output5 = re.search('0 packets/sec', output4, re.IGNORECASE)
                            if(output5 != ''):
                                log.info("packets rate is varified "+node)
                    else:
                        fail_flag1.append(0)
                    # else:
                    #     validation_msgs += "NextHop 10.3.0.3 NOT added to egress-loadbalance-resolution- VRF in "
                    #     validation_msgs += node
                    #     log.info("NextHop 10.3.0.3 NOT added to egress-loadbalance-resolution- VRF in "+node)
                    #     fail_flag1.append(0)                
                    break
                else:
                    log.info("Sleeping 15 seconds before retry to check for 10.3.0.3 prefix in standalone VTEP")
                    fail_flag1.append(0)
                    time.sleep(15)   
    log.info(validation_msgs)
    if 0 in fail_flag1:
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
    # on sumpin remove and add the vlan
    @aetest.test
    def rem_add_vlan(self, testbed,testscript,device_dut,vlan_num,ip_add, vn_segment, vrf):
        for node in device_dut:
            testbed.devices[node].configure('''
                no vlan {0}
                '''.format(vlan_num, ip_add, vn_segment, vrf))
        time.sleep(10)
        log.info("Waiting for 10 seconds after SVI shut")
        for node in device_dut:                           
            testbed.devices[node].configure('''
                vlan {0}
                    vn-segment {2}
                interface Vlan{0}
                    no shutdown
                    vrf member {3}
                    no ip redirects
                    ip address {1}
                    no ipv6 redirects
                    fabric forwarding mode anycast-gateway
                '''.format(vlan_num, ip_add, vn_segment, vrf))
        time.sleep(10)

class rem_add_svi(nxtest.Testcase):
    # on sumpin remove and add the vlan interfaces
    @aetest.test
    def rem_add_svi(self, testbed,testscript,device_dut,vlan_num,ip_add, vrf):
        for node in device_dut:
            testbed.devices[node].configure('''
                default int vlan {0}
                '''.format(vlan_num, ip_add, vrf))   
        time.sleep(10)
        log.info("Waiting for 10 seconds after SVI shut")                     
        for node in device_dut:
            testbed.devices[node].configure('''               
                interface Vlan{0}
                    no shutdown
                    vrf member {2}
                    no ip redirects
                    ip address {1}
                    no ipv6 redirects
                    fabric forwarding mode anycast-gateway
                '''.format(vlan_num, ip_add, vrf))
        time.sleep(10)

class rem_add_vni_under_nve(nxtest.Testcase):
    # on sumpin remove and add the vni under nve
    @aetest.test
    def rem_add_vni_under_nve(self, testbed,testscript,device_dut, nve, vni):
        for node in device_dut:
            testbed.devices[node].configure('''
                int nve {0}
                    no member vni {1}
                '''.format(nve, vni))                
        time.sleep(10)
        log.info("Waiting for 30 seconds after SVI shut")
        for node in device_dut:
            testbed.devices[node].configure('''
                int nve {0}
                  no shutdown
                  host-reachability protocol bgp
                  advertise virtual-rmac
                  source-interface loopback1
                  global ingress-replication protocol bgp
                  multisite border-gateway interface loopback101
                  member vni {1}
                    multisite ingress-replication
                    ingress-replication protocol bgp
                '''.format(nve, vni))
        time.sleep(10)

class rem_add_bgp_neighbour(nxtest.Testcase):
    # on sumpin remove and add the bgp neighbor under router bgp
    @aetest.test
    def rem_add_bgp_neighbour(self, testbed,testscript,device_dut, asn, ip_add, intf_ch):
        for node in device_dut:
            testbed.devices[node].configure('''
                router bgp {0}
                    no neighbor {1}
                '''.format(asn, ip_add, testbed.devices[node].interfaces[intf_ch].name))
        time.sleep(10) 
        log.info("Waiting for 10 seconds after SVI shut")           
        for node in device_dut:
            testbed.devices[node].configure('''               
                router bgp {0}
                    neighbor {1}
                        remote-as 4000
                            update-source {2}
                            ebgp-multihop 5
                            address-family ipv4 unicast
                                allowas-in 3
                                soft-reconfiguration inbound always

                '''.format(asn, ip_add, testbed.devices[node].interfaces[intf_ch].name))
        time.sleep(10)

class rem_add_advertise_pip_virtual_rmac(nxtest.Testcase):
    # on tecate-1 remove and add advertise pip bgp router, And remove and add virtual-rmac under nve
    @aetest.test
    def rem_add_advertise_pip_virtual_rmac(self, testbed,testscript,device_dut, asn,nve):
        for node in device_dut:
            testbed.devices[node].configure('''
                router bgp {0}
                    address-family l2vpn evpn
                        no advertise-pip
                int nve {1}
                    no advertise virtual-rmac                 
                '''.format(asn, nve))
        time.sleep(10)
        log.info("Waiting for 10 seconds after SVI shut")
        for node in device_dut:
            testbed.devices[node].configure('''                        
                router bgp {0}
                    address-family l2vpn evpn
                        advertise-pip                
                int nve {1}
                    advertise virtual-rmac 
                '''.format(asn, nve))
        time.sleep(10)

class rem_add_evpn_multisite_dci_tracking(nxtest.Testcase):
    # on tecate-2 remove and add evpn multisite dci-tracking under interfaces
    @aetest.test
    def rem_add_evpn_multisite_dci_tracking(self, testbed,testscript,device_dut, intf_ch):
        for node in device_dut:
            testbed.devices[node].configure('''
                interface {0}
                  no evpn multisite dci-tracking
                '''.format(testbed.devices[node].interfaces[intf_ch].name))
        time.sleep(10)
        log.info("Waiting for 10 seconds after SVI shut")
        for node in device_dut:
            testbed.devices[node].configure('''
                interface {0}
                  mtu 9216
                  ip address 10.10.42.2/24
                  no shutdown
                  evpn multisite dci-tracking             
                '''.format(testbed.devices[node].interfaces[intf_ch].name))
        time.sleep(10)

class rem_add_evpn_multisite_border_gateway(nxtest.Testcase):
    # on sumpin remove and add evpn multisite border-gateway
    @aetest.test
    def rem_add_evpn_multisite_border_gateway(self, testbed,testscript,device_dut, intf_ch1,intf_ch2,intf_ch3,intf_ch4,intf_ch5,intf_ch6,intf_ch7,intf_ch8,intf_ch9):
        for node in device_dut:
            testbed.devices[node].configure('''
                no evpn multisite border-gateway 1
                '''.format(testbed.devices[node].interfaces[intf_ch1].name, testbed.devices[node].interfaces[intf_ch2].name,testbed.devices[node].interfaces[intf_ch3].name,testbed.devices[node].interfaces[intf_ch4].name,testbed.devices[node].interfaces[intf_ch5].name,testbed.devices[node].interfaces[intf_ch6].name,testbed.devices[node].interfaces[intf_ch7].name,testbed.devices[node].interfaces[intf_ch8].name,testbed.devices[node].interfaces[intf_ch9].name,))
            
        for node in device_dut:
            testbed.devices[node].configure('''
                evpn multisite border-gateway 1
                interface nve1
                  no shutdown
                  host-reachability protocol bgp
                  advertise virtual-rmac
                  source-interface loopback1
                  global ingress-replication protocol bgp
                  multisite border-gateway interface loopback101
                  member vni 30000
                    multisite ingress-replication
                    ingress-replication protocol bgp
                  member vni 30001
                    multisite ingress-replication
                    ingress-replication protocol bgp
                  member vni 30002
                    multisite ingress-replication
                    ingress-replication protocol bgp
                  member vni 30010
                    multisite ingress-replication
                    ingress-replication protocol bgp
                  member vni 30100
                    multisite ingress-replication
                    ingress-replication protocol bgp
                  member vni 30101
                    multisite ingress-replication
                    ingress-replication protocol bgp
                  member vni 30102
                    multisite ingress-replication
                    ingress-replication protocol bgp
                  member vni 30300
                    multisite ingress-replication
                    ingress-replication protocol bgp
                  member vni 30301
                    multisite ingress-replication
                    ingress-replication protocol bgp
                  member vni 30302
                    multisite ingress-replication
                    ingress-replication protocol bgp
                  member vni 30303
                    multisite ingress-replication
                    ingress-replication protocol bgp
                  member vni 30403
                    multisite ingress-replication
                    ingress-replication protocol bgp
                  member vni 30503
                    multisite ingress-replication
                    ingress-replication protocol bgp
                  member vni 30603
                    multisite ingress-replication
                    ingress-replication protocol bgp
                  member vni 30703
                    multisite ingress-replication
                    ingress-replication protocol bgp
                  member vni 30803
                    multisite ingress-replication
                    ingress-replication protocol bgp
                  member vni 30903
                    multisite ingress-replication
                    ingress-replication protocol bgp
                  member vni 31003
                    multisite ingress-replication
                    ingress-replication protocol bgp
                  member vni 31103
                    multisite ingress-replication
                    ingress-replication protocol bgp
                  member vni 31203
                    multisite ingress-replication
                    ingress-replication protocol bgp
                  member vni 31303
                    multisite ingress-replication
                    ingress-replication protocol bgp
                  member vni 31403
                    multisite ingress-replication
                    ingress-replication protocol bgp
                  member vni 31503
                    multisite ingress-replication
                    ingress-replication protocol bgp
                  member vni 31603
                    multisite ingress-replication
                    ingress-replication protocol bgp
                  member vni 31703
                    multisite ingress-replication
                    ingress-replication protocol bgp
                  member vni 31803
                    multisite ingress-replication
                    ingress-replication protocol bgp
                  member vni 31903
                    multisite ingress-replication
                    ingress-replication protocol bgp
                  member vni 32003
                    multisite ingress-replication
                    ingress-replication protocol bgp
                  member vni 32103
                    multisite ingress-replication
                    ingress-replication protocol bgp
                  member vni 32203
                    multisite ingress-replication
                    ingress-replication protocol bgp
                  member vni 32303
                    multisite ingress-replication
                    ingress-replication protocol bgp
                  member vni 32403
                    multisite ingress-replication
                    ingress-replication protocol bgp
                  member vni 32503
                    multisite ingress-replication
                    ingress-replication protocol bgp
                  member vni 32603
                    multisite ingress-replication
                    ingress-replication protocol bgp
                  member vni 32703
                    multisite ingress-replication
                    ingress-replication protocol bgp
                  member vni 32803
                    multisite ingress-replication
                    ingress-replication protocol bgp
                  member vni 32903
                    multisite ingress-replication
                    ingress-replication protocol bgp
                  member vni 33003
                    multisite ingress-replication
                    ingress-replication protocol bgp
                  member vni 33103
                    multisite ingress-replication
                    ingress-replication protocol bgp
                  member vni 33203
                    multisite ingress-replication
                    ingress-replication protocol bgp
                  member vni 33303
                    multisite ingress-replication
                    ingress-replication protocol bgp
                  member vni 33403
                    multisite ingress-replication
                    ingress-replication protocol bgp
                  member vni 33503
                    multisite ingress-replication
                    ingress-replication protocol bgp
                  member vni 33603
                    multisite ingress-replication
                    ingress-replication protocol bgp
                  member vni 33703
                    multisite ingress-replication
                    ingress-replication protocol bgp
                  member vni 33803
                    multisite ingress-replication
                    ingress-replication protocol bgp
                  member vni 33903
                    multisite ingress-replication
                    ingress-replication protocol bgp
                  member vni 34003
                    multisite ingress-replication
                    ingress-replication protocol bgp
                  member vni 34103
                    multisite ingress-replication
                    ingress-replication protocol bgp
                  member vni 34203
                    multisite ingress-replication
                    ingress-replication protocol bgp
                  member vni 34303
                    multisite ingress-replication
                    ingress-replication protocol bgp
                  member vni 34403
                    multisite ingress-replication
                    ingress-replication protocol bgp
                  member vni 34503
                    multisite ingress-replication
                    ingress-replication protocol bgp
                  member vni 34603
                    multisite ingress-replication
                    ingress-replication protocol bgp
                  member vni 34703
                    multisite ingress-replication
                    ingress-replication protocol bgp
                  member vni 34803
                    multisite ingress-replication
                    ingress-replication protocol bgp
                  member vni 34903
                    multisite ingress-replication
                    ingress-replication protocol bgp
                  member vni 35003
                    multisite ingress-replication
                    ingress-replication protocol bgp
                  member vni 35103
                    multisite ingress-replication
                    ingress-replication protocol bgp
                  member vni 35203
                    multisite ingress-replication
                    ingress-replication protocol bgp
                  member vni 35303
                    multisite ingress-replication
                    ingress-replication protocol bgp
                  member vni 35403
                    multisite ingress-replication
                    ingress-replication protocol bgp
                  member vni 35503
                    multisite ingress-replication
                    ingress-replication protocol bgp
                  member vni 35603
                    multisite ingress-replication
                    ingress-replication protocol bgp
                  member vni 35803
                    multisite ingress-replication
                    ingress-replication protocol bgp
                  member vni 35903
                    multisite ingress-replication
                    ingress-replication protocol bgp
                  member vni 36003
                    multisite ingress-replication
                    ingress-replication protocol bgp
                  member vni 36103
                    multisite ingress-replication
                    ingress-replication protocol bgp
                  member vni 36203
                    multisite ingress-replication
                    ingress-replication protocol bgp
                  member vni 36303
                    multisite ingress-replication
                    ingress-replication protocol bgp
                  member vni 36403
                    multisite ingress-replication
                    ingress-replication protocol bgp
                  member vni 36503
                    multisite ingress-replication
                    ingress-replication protocol bgp
                  member vni 36603
                    multisite ingress-replication
                    ingress-replication protocol bgp
                  member vni 36703
                    multisite ingress-replication
                    ingress-replication protocol bgp
                  member vni 36803
                    multisite ingress-replication
                    ingress-replication protocol bgp
                  member vni 36903
                    multisite ingress-replication
                    ingress-replication protocol bgp
                  member vni 37003
                    multisite ingress-replication
                    ingress-replication protocol bgp
                  member vni 37103
                    multisite ingress-replication
                    ingress-replication protocol bgp
                  member vni 37203
                    multisite ingress-replication
                    ingress-replication protocol bgp
                  member vni 37303
                    multisite ingress-replication
                    ingress-replication protocol bgp
                  member vni 37403
                    multisite ingress-replication
                    ingress-replication protocol bgp
                  member vni 37503
                    multisite ingress-replication
                    ingress-replication protocol bgp
                  member vni 37603
                    multisite ingress-replication
                    ingress-replication protocol bgp
                  member vni 37703
                    multisite ingress-replication
                    ingress-replication protocol bgp
                  member vni 37803
                    multisite ingress-replication
                    ingress-replication protocol bgp
                  member vni 37903
                    multisite ingress-replication
                    ingress-replication protocol bgp
                  member vni 38003
                    multisite ingress-replication
                    ingress-replication protocol bgp
                  member vni 38103
                    multisite ingress-replication
                    ingress-replication protocol bgp
                  member vni 38203
                    multisite ingress-replication
                    ingress-replication protocol bgp
                  member vni 38303
                    multisite ingress-replication
                    ingress-replication protocol bgp
                  member vni 38403
                    multisite ingress-replication
                    ingress-replication protocol bgp
                  member vni 38503
                    multisite ingress-replication
                    ingress-replication protocol bgp
                  member vni 38603
                    multisite ingress-replication
                    ingress-replication protocol bgp
                  member vni 38703
                    multisite ingress-replication
                    ingress-replication protocol bgp
                  member vni 38803
                    multisite ingress-replication
                    ingress-replication protocol bgp
                  member vni 38903
                    multisite ingress-replication
                    ingress-replication protocol bgp
                  member vni 39003
                    multisite ingress-replication
                    ingress-replication protocol bgp
                  member vni 39103
                    multisite ingress-replication
                    ingress-replication protocol bgp
                  member vni 39203
                    multisite ingress-replication
                    ingress-replication protocol bgp
                  member vni 39303
                    multisite ingress-replication
                    ingress-replication protocol bgp
                  member vni 39403
                    multisite ingress-replication
                    ingress-replication protocol bgp
                  member vni 39503
                    multisite ingress-replication
                    ingress-replication protocol bgp
                  member vni 39603
                    multisite ingress-replication
                    ingress-replication protocol bgp
                  member vni 39703
                    multisite ingress-replication
                    ingress-replication protocol bgp
                  member vni 39803
                    multisite ingress-replication
                    ingress-replication protocol bgp
                  member vni 39903
                    multisite ingress-replication
                    ingress-replication protocol bgp
                  member vni 50000 associate-vrf

                interface {0}
                  mtu 9216
                  ip address 10.10.44.2/24
                  no shutdown
                  evpn multisite dci-tracking

                interface {1}
                  mtu 9216
                  ip address 10.10.45.2/24
                  no shutdown
                  evpn multisite dci-tracking

                interface {2}
                  mtu 9216
                  ip address 10.10.26.2/24
                  no shutdown
                  evpn multisite dci-tracking

                interface {3}
                  mtu 9216
                 ip address 10.10.27.2/24
                  no shutdown
                  evpn multisite dci-tracking

                interface {4}
                  mtu 9216
                  ip address 10.10.28.2/24
                  no shutdown
                  evpn multisite dci-tracking

                interface {5}
                  mtu 9216
                  ip address 10.10.29.2/24
                  no shutdown
                  evpn multisite dci-tracking

                interface {6}
                  mtu 9216
                  ip address 10.10.39.2/24
                  no shutdown
                  evpn multisite dci-tracking

                interface {7}
                  mtu 9216
                  ip address 10.10.38.2/24
                  no shutdown
                  evpn multisite dci-tracking

                interface {8}
                  no shutdown
                  evpn multisite fabric-tracking
                  
                interface loopback0
                  description Routing loopback interface
                  ip address 10.2.0.3/32
                  ip router ospf UNDERLAY area 0.0.0.0

                interface loopback1
                  description VTEP loopback interface
                  ip address 10.3.0.3/32
                  ip router ospf UNDERLAY area 0.0.0.0
                interface loopback101
                  ip address 101.101.101.101/32
                interface loopback501
                  vrf member myvrf_50000
                  ip address 150.150.150.150/32

                router ospf UNDERLAY
                  router-id 10.5.0.3
                router bgp 5000
                  router-id 10.5.0.3
                  graceful-restart-helper
                  bestpath as-path multipath-relax
                  reconnect-interval 1
                  address-family ipv4 unicast
                    network 10.2.0.3/32
                    network 10.3.0.3/32
                    maximum-paths 4
                    maximum-paths ibgp 4
                    load-balance egress filter-policy route-map filterPolicy_Tecate
                    load-balance egress multipath auto-policy route-map autoMultiPath
                  address-family l2vpn evpn
                    maximum-paths ibgp 4
                    nexthop load-balance egress multisite
                  neighbor 10.2.0.2
                    remote-as 4000
                    update-source loopback0
                    ebgp-multihop 5
                    peer-type fabric-external
                    address-family l2vpn evpn
                      allowas-in 3
                      send-community
                      send-community extended
                      rewrite-evpn-rt-asn
                  neighbor 10.2.2.2
                    remote-as 4000
                    update-source loopback0
                    ebgp-multihop 5
                    peer-type fabric-external
                    address-family l2vpn evpn
                      allowas-in 3
                      send-community
                      send-community extended
                      rewrite-evpn-rt-asn
                  neighbor 10.10.26.1
                   remote-as 4000
                    update-source {2}
                    ebgp-multihop 5
                    peer-type fabric-external
                    address-family ipv4 unicast
                      allowas-in 3
                      soft-reconfiguration inbound always
                 neighbor 10.10.27.1
                    remote-as 4000
                    update-source {3}
                    ebgp-multihop 5
                    peer-type fabric-external
                    address-family ipv4 unicast
                      allowas-in 3
                      soft-reconfiguration inbound always
                  neighbor 10.10.28.1
                    remote-as 4000
                    update-source {4}
                    ebgp-multihop 5
                    peer-type fabric-external
                    address-family ipv4 unicast
                      allowas-in 3
                      soft-reconfiguration inbound always
                  neighbor 10.10.29.1
                    remote-as 4000
                    update-source {5}
                    ebgp-multihop 5
                    peer-type fabric-external
                    address-family ipv4 unicast
                      allowas-in 3
                      soft-reconfiguration inbound always
                  neighbor 10.10.38.1
                    remote-as 4000
                    update-source {7}
                    ebgp-multihop 5
                    peer-type fabric-external
                    address-family ipv4 unicast
                      allowas-in 3
                      soft-reconfiguration inbound always
                  neighbor 10.10.39.1
                    remote-as 4000
                    update-source {6}
                    ebgp-multihop 5
                    peer-type fabric-external
                    address-family ipv4 unicast
                      allowas-in 3
                      soft-reconfiguration inbound always
                  neighbor 10.10.44.1
                   remote-as 4000
                    update-source {0}
                    ebgp-multihop 5
                    peer-type fabric-external
                    address-family ipv4 unicast
                      allowas-in 3
                      soft-reconfiguration inbound always
                  neighbor 10.10.45.1
                    remote-as 4000
                    update-source {1}
                    ebgp-multihop 5
                    peer-type fabric-external
                    address-family ipv4 unicast
                      allowas-in 3
                      soft-reconfiguration inbound always
                  vrf myvrf_50000
                    bestpath as-path multipath-relax
                    address-family ipv4 unicast
                      network 150.150.150.150/32
                      maximum-paths 64
                      maximum-paths ibgp 64
                     export-gateway-ip
                '''.format(testbed.devices[node].interfaces[intf_ch1].name, testbed.devices[node].interfaces[intf_ch2].name,testbed.devices[node].interfaces[intf_ch3].name,testbed.devices[node].interfaces[intf_ch4].name,testbed.devices[node].interfaces[intf_ch5].name,testbed.devices[node].interfaces[intf_ch6].name,testbed.devices[node].interfaces[intf_ch7].name,testbed.devices[node].interfaces[intf_ch8].name,testbed.devices[node].interfaces[intf_ch9].name,))

class change_nve_source_interface_ip_address(nxtest.Testcase):
    # change loopback 1 address on tecate-1 and ip prefix-list on spines
    @aetest.test
    def change_nve_source_interface_ip_address(self, testbed,testscript,device_dut1, device_dut2, device_dut3, device_dut4, device_dut5, ip_addr):
        for node in device_dut1:
            testbed.devices[node].configure('''
		            cdp timer 5
                ip prefix-list totecate1 seq 25 permit {0}
                ip prefix-list totecate2 seq 24 permit {0}
                '''.format(ip_addr))

        for node in device_dut2:
            testbed.devices[node].configure('''
                cdp timer 5
                ip prefix-list redist_to_bgp seq 20 permit {0}
                show run int loopback1
                default int loopback1
                interface loopback1
                  description VTEP loopback interface
                  ip address {0}
                  ip address 10.3.0.2/32 secondary
                  ip router ospf UNDERLAY area 0.0.0.0  
                show run int loopback1          
                '''.format(ip_addr))
        time.sleep(10)
        log.info("Waiting for 10 seconds after SVI shut")
        for node in device_dut5:
            testbed.devices[node].configure('''
                  interface loopback1
                  description ### VTEP loopback interface ###
                  ip address 10.3.0.4/32
                  ip address 10.3.0.2/32 secondary
                  ip router ospf UNDERLAY area 0.0.0.0
                '''.format(ip_addr))
        for node in device_dut4:
            testbed.devices[node].configure('''
                cdp timer 5
                ip prefix-list totecate1 seq 25 permit {0}
                ip prefix-list totecate2 seq 24 permit {0}         
                '''.format(ip_addr))
        time.sleep(20)
        log.info("Waiting for 20 seconds after SVI shut")       
        for node in device_dut3:
            testbed.devices[node].configure('''
                cdp timer 5
                ip prefix-list tecate_lo1 seq 25 permit {0}          
                '''.format(ip_addr))
            output = testbed.devices[node].configure('show nve peers')
            nve_search = re.search('[0-9]+[0-9]+.+[0-9]+.[0-9]+.+[0-9]', output)
            fin = nve_search.group()
            fail_flag = []
            if (fin == '10.3.0.6'):
                print('passed')
            else:
                fail_flag.append(0)
                print('nve peer is failed')            
        time.sleep(10)

class change_nve_source_interface_vip_address(nxtest.Testcase):
    # change loopback 1 secondary address on all leafs and ip prefix-list on spines
    @aetest.test
    def change_nve_source_interface_vip_address(self, testbed,testscript,device_dut1, device_dut2, device_dut3, device_dut4, device_dut5, ip_addr, ip_addr1):
        for node in device_dut1:
            testbed.devices[node].configure('''
		            cdp timer 5
                ip prefix-list totecate1 seq 26 permit {0}
                ip prefix-list totecate2 seq 26 permit {0}
                '''.format(ip_addr, ip_addr1))

        for node in device_dut2:
            testbed.devices[node].configure('''
                cdp timer 5
                ip prefix-list redist_to_bgp seq 25 permit {0}
                show run int loopback1
                default int loopback1
                interface loopback1
                  description VTEP loopback interface
                  ip address {1}
                  ip address {0} secondary
                  ip router ospf UNDERLAY area 0.0.0.0  
                show run int loopback1          
                '''.format(ip_addr, ip_addr1))
      
        for node in device_dut4:
            testbed.devices[node].configure('''
                cdp timer 5
                ip prefix-list redist_to_bgp seq 20 permit {0} 
                show run int loopback1
                default int loopback1
                interface loopback1
                  description ### VTEP loopback interface ###
                  ip address 10.3.0.4/32
                  ip address {0} secondary
                  ip router ospf UNDERLAY area 0.0.0.0       
                show run int loopback1
                '''.format(ip_addr, ip_addr1))
        time.sleep(10)    
        log.info("Waiting for 10 seconds after SVI shut")       
        for node in device_dut5:
            testbed.devices[node].configure('''
                cdp timer 5
                ip prefix-list totecate1 seq 26 permit {0}
                ip prefix-list totecate2 seq 26 permit {0}         
                '''.format(ip_addr, ip_addr1))
        time.sleep(20)
        log.info("Waiting for 20 seconds after SVI shut")
        for node in device_dut3:
            testbed.devices[node].configure('''
                cdp timer 5
                ip prefix-list tecate_lo1 seq 20 permit {0}       
                '''.format(ip_addr, ip_addr1))
            output = testbed.devices[node].configure('show nve peers')
            nve_search = re.search('[0-9]+[0-9]+.+[0-9]+.[0-9]+.+[0-9]', output)
            fin = nve_search.group()
            fail_flag = []
            if (fin == '10.3.0.7'):
                print('passed')
            else:
                fail_flag.append(0)
                print('nve peer is failed')  
        time.sleep(10)

class change_multisite_id(nxtest.Testcase):
    # change evpn multisite border-gateway address on all leafs
    @aetest.test
    def change_multisite_id(self, testbed,testscript,device_dut1, device_dut2, device_dut3, id, id1):
        for node in device_dut1:
            testbed.devices[node].configure('''
                evpn multisite border-gateway {0}
                '''.format(id))
        for node in device_dut2:
            testbed.devices[node].configure('''
                evpn multisite border-gateway {0}
                '''.format(id1))
        for node in device_dut3:
            testbed.devices[node].configure('''
                evpn multisite border-gateway {0}
                '''.format(id))
        time.sleep(10)
                    
class Change_Multisite_Loopback_Interface_IP_Address(nxtest.Testcase):
    # change loopback101 address on all leafs
    @aetest.test
    def Change_Multisite_Loopback_Interface_IP_Address(self, testbed,testscript,device_dut1, device_dut2, device_dut3, loopback_ip, loopback_id, loopback_ip1):
        for node in device_dut1:
            testbed.devices[node].configure('''
                show run int loopback{1}
                default int loopback{1}
                interface loopback{1}
                ip address {0}
                show run int loopback{1}
                '''.format(loopback_ip, loopback_id))
        for node in device_dut2:
            testbed.devices[node].configure('''
                show run int loopback{1}
                default int loopback{1}                
                interface loopback{1}
                ip address {0}
                show run int loopback{1}
                '''.format(loopback_ip1, loopback_id))
        for node in device_dut3:
            testbed.devices[node].configure('''
                show run int loopback{1}
                default int loopback{1}
                interface loopback{1}
                ip address {0}
                show run int loopback{1}
                '''.format(loopback_ip, loopback_id))
        time.sleep(120)

class Change_bgp_router_id(nxtest.Testcase):
    # on sumpin change router bgp id
    @aetest.test
    def Change_bgp_router_id(self, testbed,testscript,device_dut, id):
        for node in device_dut:
            testbed.devices[node].configure('''
                show run bgp
                router bgp 5000
                  router-id {0}
                show run bgp
                '''.format(id))
        time.sleep(10)

class shut_no_shut_svi(nxtest.Testcase):
    # on sumpin, shut and no shut the vlan interfaces
    @aetest.test
    def shut_no_shut_svi(self, testbed,testscript,device_dut, vlan):
        for node in device_dut:
            testbed.devices[node].configure('''
                interface vlan{0}
                  shut
                '''.format(vlan))
        time.sleep(30)
        log.info("Waiting for 30 seconds after SVI shut")
        for node in device_dut:
            testbed.devices[node].configure('''
                interface vlan{0}
                  no shut
                '''.format(vlan))
        time.sleep(30)

class shut_no_shut_nve_source_interface(nxtest.Testcase):
    # on all leaf, shut and no shut the nve source interface
    @aetest.test
    def shut_no_shut_nve_source_interface(self, testbed,testscript,device_dut1, device_dut2, device_dut3, loopback):
        for node in device_dut1:
            testbed.devices[node].configure('''
                interface loopback{0}
                  shut
                '''.format(loopback))
        for node in device_dut2:
            testbed.devices[node].configure('''
                interface loopback{0}
                  shut
                '''.format(loopback))
        for node in device_dut3:
            testbed.devices[node].configure('''
                interface loopback{0}
                  shut
                '''.format(loopback))
        time.sleep(30)
        for node in device_dut1:
            testbed.devices[node].configure('''
                interface loopback{0}
                  no shut
                '''.format(loopback))
        for node in device_dut2:
            testbed.devices[node].configure('''
                interface loopback{0}
                  no shut
                '''.format(loopback))
        for node in device_dut3:
            testbed.devices[node].configure('''
                interface loopback{0}
                  no shut
                show nve peers
                '''.format(loopback))
            time.sleep(120)
            output = testbed.devices[node].configure('show nve peers')
            nve_search = re.search('[0-9]+[0-9]+.+[0-9]+.+[0-9]+.+[0-9]', output)
            fin = nve_search.group()
            fail_flag = []
            if (fin == '10.3.0.3'):
                print('passed')
            else:
                fail_flag.append(0)
                print('nve peer is failed')  
        time.sleep(30)

class disable_vn_segment_vlan_based(nxtest.Testcase):
    # on sumpin, disable feature vn-segment-vlan-based 
    @aetest.test
    def disable_vn_segment_vlan_based(self, testbed,testscript,device_dut, intf_ch1,intf_ch2,intf_ch3,intf_ch4,intf_ch5,intf_ch6,intf_ch7,intf_ch8,intf_ch9):
        for node in device_dut:
            testbed.devices[node].configure('''
                no feature nv overlay
                no feature vn-segment-vlan-based
                '''.format(testbed.devices[node].interfaces[intf_ch1].name, testbed.devices[node].interfaces[intf_ch2].name,testbed.devices[node].interfaces[intf_ch3].name,testbed.devices[node].interfaces[intf_ch4].name,testbed.devices[node].interfaces[intf_ch5].name,testbed.devices[node].interfaces[intf_ch6].name,testbed.devices[node].interfaces[intf_ch7].name,testbed.devices[node].interfaces[intf_ch8].name,testbed.devices[node].interfaces[intf_ch9].name,))
        time.sleep(10)  
        log.info("Waiting for 10 seconds after SVI shut")          
        for node in device_dut:
            testbed.devices[node].configure('''
                feature nv overlay
                feature vn-segment-vlan-based
                evpn multisite border-gateway 2
                vlan 1,10-12,100-102,300-399
                vlan 10
                  private-vlan primary
                  private-vlan association 100-102
                  vn-segment 30010
                vlan 11
                  vn-segment 30001
                vlan 12
                  vn-segment 30002
                vlan 100
                  private-vlan community
                  vn-segment 30100
                vlan 101
                  private-vlan community
                  vn-segment 30101
                vlan 102
                  private-vlan isolated
                  vn-segment 30102
                vlan 300
                  vn-segment 30300
                vlan 301
                  vn-segment 30301
                vlan 302
                  vn-segment 30302
                vlan 303
                  vn-segment 30303
                vlan 304
                  vn-segment 30403
                vlan 305
                  vn-segment 30503
                vlan 306
                  vn-segment 30603
                vlan 307
                  vn-segment 30703
                vlan 308
                  vn-segment 30803
                vlan 309
                  vn-segment 30903
                vlan 310
                  vn-segment 31003
                vlan 311
                  vn-segment 31103
                vlan 312
                  vn-segment 31203
                vlan 313
                  vn-segment 31303
                vlan 314
                  vn-segment 31403
                vlan 315
                  vn-segment 31503
                vlan 316
                  vn-segment 31603
                vlan 317
                  vn-segment 31703
                vlan 318
                  vn-segment 31803
                vlan 319
                  vn-segment 31903
                vlan 320
                  vn-segment 32003
                vlan 321
                  vn-segment 32103
                vlan 322
                  vn-segment 32203
                vlan 323
                  vn-segment 32303
                vlan 324
                  vn-segment 32403
                vlan 325
                  vn-segment 32503
                vlan 326
                  vn-segment 32603
                vlan 327
                  vn-segment 32703
                vlan 328
                  vn-segment 32803
                vlan 329
                  vn-segment 32903
                vlan 330
                  vn-segment 33003
                vlan 331
                  vn-segment 33103
                vlan 332
                  vn-segment 33203
                vlan 333
                  vn-segment 33303
                vlan 334
                  vn-segment 33403
                vlan 335
                  vn-segment 33503
                vlan 336
                  vn-segment 33603
                vlan 337
                  vn-segment 33703
                vlan 338
                  vn-segment 33803
                vlan 339
                  vn-segment 33903
                vlan 340
                  vn-segment 34003
                vlan 341
                  vn-segment 34103
                vlan 342
                  vn-segment 34203
                vlan 343
                  vn-segment 34303
                vlan 344
                  vn-segment 34403
                vlan 345
                  vn-segment 34503
                vlan 346
                  vn-segment 34603
                vlan 347
                  vn-segment 34703
                vlan 348
                  vn-segment 34803
                vlan 349
                  vn-segment 34903
                vlan 350
                  vn-segment 35003
                vlan 351
                  vn-segment 35103
                vlan 352
                  vn-segment 35203
                vlan 353
                  vn-segment 35303
                vlan 354
                  vn-segment 35403
                vlan 355
                  vn-segment 35503
                vlan 356
                  vn-segment 35603
                vlan 357
                  vn-segment 35703
                vlan 358
                  vn-segment 35803
                vlan 359
                  vn-segment 35903
                vlan 360
                  vn-segment 36003
                vlan 361
                  vn-segment 36103
                vlan 362
                  vn-segment 36203
                vlan 363
                  vn-segment 36303
                vlan 364
                  vn-segment 36403
                vlan 365
                  vn-segment 36503
                vlan 366
                  vn-segment 36603
                vlan 367
                  vn-segment 36703
                vlan 368
                  vn-segment 36803
                vlan 369
                  vn-segment 36903
                vlan 370
                  vn-segment 37003
                vlan 371
                  vn-segment 37103
                vlan 372
                  vn-segment 37203
                vlan 373
                  vn-segment 37303
                vlan 374
                  vn-segment 37403
                vlan 375
                  vn-segment 37503
                vlan 376
                  vn-segment 37603
                vlan 377
                  vn-segment 37703
                vlan 378
                  vn-segment 37803
                vlan 379
                  vn-segment 37903
                vlan 380
                  vn-segment 38003
                vlan 381
                  vn-segment 38103
                vlan 382
                  vn-segment 38203
                vlan 383
                  vn-segment 38303
                vlan 384
                  vn-segment 38403
                vlan 385
                  vn-segment 38503
                vlan 386
                  vn-segment 38603
                vlan 387
                  vn-segment 38703
                vlan 388
                  vn-segment 38803
                vlan 389
                  vn-segment 38903
                vlan 390
                  vn-segment 39003
                vlan 391
                  vn-segment 39103
                vlan 392
                  vn-segment 39203
                vlan 393
                  vn-segment 39303
                vlan 394
                  vn-segment 39403
                vlan 395
                  vn-segment 39503
                vlan 396
                  vn-segment 39603
                vlan 397
                  vn-segment 39703
                vlan 398
                  vn-segment 39803
                vlan 399
                  vn-segment 39903
                interface nve1
                  no shutdown
                  host-reachability protocol bgp
                  advertise virtual-rmac
                  source-interface loopback1
                  global ingress-replication protocol bgp
                  multisite border-gateway interface loopback101
                  member vni 30000
                    multisite ingress-replication
                    ingress-replication protocol bgp
                  member vni 30001
                    multisite ingress-replication
                    ingress-replication protocol bgp
                  member vni 30002
                    multisite ingress-replication
                    ingress-replication protocol bgp
                  member vni 30010
                    multisite ingress-replication
                    ingress-replication protocol bgp
                  member vni 30100
                    multisite ingress-replication
                    ingress-replication protocol bgp
                  member vni 30101
                    multisite ingress-replication
                    ingress-replication protocol bgp
                  member vni 30102
                    multisite ingress-replication
                    ingress-replication protocol bgp
                  member vni 30300
                    multisite ingress-replication
                    ingress-replication protocol bgp
                  member vni 30301
                    multisite ingress-replication
                    ingress-replication protocol bgp
                  member vni 30302
                    multisite ingress-replication
                    ingress-replication protocol bgp
                  member vni 30303
                    multisite ingress-replication
                    ingress-replication protocol bgp
                  member vni 30403
                    multisite ingress-replication
                    ingress-replication protocol bgp
                  member vni 30503
                    multisite ingress-replication
                    ingress-replication protocol bgp
                  member vni 30603
                    multisite ingress-replication
                    ingress-replication protocol bgp
                  member vni 30703
                    multisite ingress-replication
                    ingress-replication protocol bgp
                  member vni 30803
                    multisite ingress-replication
                    ingress-replication protocol bgp
                  member vni 30903
                    multisite ingress-replication
                    ingress-replication protocol bgp
                  member vni 31003
                    multisite ingress-replication
                    ingress-replication protocol bgp
                  member vni 31103
                    multisite ingress-replication
                    ingress-replication protocol bgp
                  member vni 31203
                    multisite ingress-replication
                    ingress-replication protocol bgp
                  member vni 31303
                    multisite ingress-replication
                    ingress-replication protocol bgp
                  member vni 31403
                    multisite ingress-replication
                    ingress-replication protocol bgp
                  member vni 31503
                    multisite ingress-replication
                    ingress-replication protocol bgp
                  member vni 31603
                    multisite ingress-replication
                    ingress-replication protocol bgp
                  member vni 31703
                    multisite ingress-replication
                    ingress-replication protocol bgp
                  member vni 31803
                    multisite ingress-replication
                    ingress-replication protocol bgp
                  member vni 31903
                    multisite ingress-replication
                    ingress-replication protocol bgp
                  member vni 32003
                    multisite ingress-replication
                    ingress-replication protocol bgp
                  member vni 32103
                    multisite ingress-replication
                    ingress-replication protocol bgp
                  member vni 32203
                    multisite ingress-replication
                    ingress-replication protocol bgp
                  member vni 32303
                    multisite ingress-replication
                    ingress-replication protocol bgp
                  member vni 32403
                    multisite ingress-replication
                    ingress-replication protocol bgp
                  member vni 32503
                    multisite ingress-replication
                    ingress-replication protocol bgp
                  member vni 32603
                    multisite ingress-replication
                    ingress-replication protocol bgp
                  member vni 32703
                    multisite ingress-replication
                    ingress-replication protocol bgp
                  member vni 32803
                    multisite ingress-replication
                    ingress-replication protocol bgp
                  member vni 32903
                    multisite ingress-replication
                    ingress-replication protocol bgp
                  member vni 33003
                    multisite ingress-replication
                    ingress-replication protocol bgp
                  member vni 33103
                    multisite ingress-replication
                    ingress-replication protocol bgp
                  member vni 33203
                    multisite ingress-replication
                    ingress-replication protocol bgp
                  member vni 33303
                    multisite ingress-replication
                    ingress-replication protocol bgp
                  member vni 33403
                    multisite ingress-replication
                    ingress-replication protocol bgp
                  member vni 33503
                    multisite ingress-replication
                    ingress-replication protocol bgp
                  member vni 33603
                    multisite ingress-replication
                    ingress-replication protocol bgp
                  member vni 33703
                    multisite ingress-replication
                    ingress-replication protocol bgp
                  member vni 33803
                    multisite ingress-replication
                    ingress-replication protocol bgp
                  member vni 33903
                    multisite ingress-replication
                    ingress-replication protocol bgp
                  member vni 34003
                    multisite ingress-replication
                    ingress-replication protocol bgp
                  member vni 34103
                    multisite ingress-replication
                    ingress-replication protocol bgp
                  member vni 34203
                    multisite ingress-replication
                    ingress-replication protocol bgp
                  member vni 34303
                    multisite ingress-replication
                    ingress-replication protocol bgp
                  member vni 34403
                    multisite ingress-replication
                    ingress-replication protocol bgp
                  member vni 34503
                    multisite ingress-replication
                    ingress-replication protocol bgp
                  member vni 34603
                    multisite ingress-replication
                    ingress-replication protocol bgp
                  member vni 34703
                    multisite ingress-replication
                    ingress-replication protocol bgp
                  member vni 34803
                    multisite ingress-replication
                    ingress-replication protocol bgp
                  member vni 34903
                    multisite ingress-replication
                    ingress-replication protocol bgp
                  member vni 35003
                    multisite ingress-replication
                    ingress-replication protocol bgp
                  member vni 35103
                    multisite ingress-replication
                    ingress-replication protocol bgp
                  member vni 35203
                    multisite ingress-replication
                    ingress-replication protocol bgp
                  member vni 35303
                    multisite ingress-replication
                    ingress-replication protocol bgp
                  member vni 35403
                    multisite ingress-replication
                    ingress-replication protocol bgp
                  member vni 35503
                    multisite ingress-replication
                    ingress-replication protocol bgp
                  member vni 35603
                    multisite ingress-replication
                    ingress-replication protocol bgp
                  member vni 35803
                    multisite ingress-replication
                    ingress-replication protocol bgp
                  member vni 35903
                    multisite ingress-replication
                    ingress-replication protocol bgp
                  member vni 36003
                    multisite ingress-replication
                    ingress-replication protocol bgp
                  member vni 36103
                    multisite ingress-replication
                    ingress-replication protocol bgp
                  member vni 36203
                    multisite ingress-replication
                    ingress-replication protocol bgp
                  member vni 36303
                    multisite ingress-replication
                    ingress-replication protocol bgp
                  member vni 36403
                    multisite ingress-replication
                    ingress-replication protocol bgp
                  member vni 36503
                    multisite ingress-replication
                    ingress-replication protocol bgp
                  member vni 36603
                    multisite ingress-replication
                    ingress-replication protocol bgp
                  member vni 36703
                    multisite ingress-replication
                    ingress-replication protocol bgp
                  member vni 36803
                    multisite ingress-replication
                    ingress-replication protocol bgp
                  member vni 36903
                    multisite ingress-replication
                    ingress-replication protocol bgp
                  member vni 37003
                    multisite ingress-replication
                    ingress-replication protocol bgp
                  member vni 37103
                    multisite ingress-replication
                    ingress-replication protocol bgp
                  member vni 37203
                    multisite ingress-replication
                    ingress-replication protocol bgp
                  member vni 37303
                    multisite ingress-replication
                    ingress-replication protocol bgp
                  member vni 37403
                    multisite ingress-replication
                    ingress-replication protocol bgp
                  member vni 37503
                    multisite ingress-replication
                    ingress-replication protocol bgp
                  member vni 37603
                    multisite ingress-replication
                    ingress-replication protocol bgp
                  member vni 37703
                    multisite ingress-replication
                    ingress-replication protocol bgp
                  member vni 37803
                    multisite ingress-replication
                    ingress-replication protocol bgp
                  member vni 37903
                    multisite ingress-replication
                    ingress-replication protocol bgp
                  member vni 38003
                    multisite ingress-replication
                    ingress-replication protocol bgp
                  member vni 38103
                    multisite ingress-replication
                    ingress-replication protocol bgp
                  member vni 38203
                    multisite ingress-replication
                    ingress-replication protocol bgp
                  member vni 38303
                    multisite ingress-replication
                    ingress-replication protocol bgp
                  member vni 38403
                    multisite ingress-replication
                    ingress-replication protocol bgp
                  member vni 38503
                    multisite ingress-replication
                    ingress-replication protocol bgp
                  member vni 38603
                    multisite ingress-replication
                    ingress-replication protocol bgp
                  member vni 38703
                    multisite ingress-replication
                    ingress-replication protocol bgp
                  member vni 38803
                    multisite ingress-replication
                    ingress-replication protocol bgp
                  member vni 38903
                    multisite ingress-replication
                    ingress-replication protocol bgp
                  member vni 39003
                    multisite ingress-replication
                    ingress-replication protocol bgp
                  member vni 39103
                    multisite ingress-replication
                    ingress-replication protocol bgp
                  member vni 39203
                    multisite ingress-replication
                    ingress-replication protocol bgp
                  member vni 39303
                    multisite ingress-replication
                    ingress-replication protocol bgp
                  member vni 39403
                    multisite ingress-replication
                    ingress-replication protocol bgp
                  member vni 39503
                    multisite ingress-replication
                    ingress-replication protocol bgp
                  member vni 39603
                    multisite ingress-replication
                    ingress-replication protocol bgp
                  member vni 39703
                    multisite ingress-replication
                    ingress-replication protocol bgp
                  member vni 39803
                    multisite ingress-replication
                    ingress-replication protocol bgp
                  member vni 39903
                    multisite ingress-replication
                    ingress-replication protocol bgp
                  member vni 50000 associate-vrf

                interface {0}
                  mtu 9216
                  ip address 10.10.44.2/24
                  no shutdown
                  evpn multisite dci-tracking

                interface {1}
                  mtu 9216
                  ip address 10.10.45.2/24
                  no shutdown
                  evpn multisite dci-tracking

                interface {2}
                  mtu 9216
                  ip address 10.10.26.2/24
                  no shutdown
                  evpn multisite dci-tracking

                interface {3}
                  mtu 9216
                 ip address 10.10.27.2/24
                  no shutdown
                  evpn multisite dci-tracking

                interface {4}
                  mtu 9216
                  ip address 10.10.28.2/24
                  no shutdown
                  evpn multisite dci-tracking

                interface {5}
                  mtu 9216
                  ip address 10.10.29.2/24
                  no shutdown
                  evpn multisite dci-tracking

                interface {6}
                  mtu 9216
                  ip address 10.10.39.2/24
                  no shutdown
                  evpn multisite dci-tracking

                interface {7}
                  mtu 9216
                  ip address 10.10.38.2/24
                  no shutdown
                  evpn multisite dci-tracking

                interface {8}
                  no shutdown
                  evpn multisite fabric-tracking
                  
                interface loopback0
                  description Routing loopback interface
                  ip address 10.2.0.3/32
                  ip router ospf UNDERLAY area 0.0.0.0

                interface loopback1
                  description VTEP loopback interface
                  ip address 10.3.0.3/32
                  ip router ospf UNDERLAY area 0.0.0.0
                interface loopback101
                  ip address 101.101.101.101/32
                interface loopback501
                  vrf member myvrf_50000
                  ip address 150.150.150.150/32

                router ospf UNDERLAY
                  router-id 10.5.0.3
                router bgp 5000
                  router-id 10.5.0.3
                  graceful-restart-helper
                  bestpath as-path multipath-relax
                  reconnect-interval 1
                  address-family ipv4 unicast
                    network 10.2.0.3/32
                    network 10.3.0.3/32
                    maximum-paths 4
                    maximum-paths ibgp 4
                    load-balance egress filter-policy route-map filterPolicy_Tecate
                    load-balance egress multipath auto-policy route-map autoMultiPath
                  address-family l2vpn evpn
                    maximum-paths ibgp 4
                    nexthop load-balance egress multisite
                  neighbor 10.2.0.2
                    remote-as 4000
                    update-source loopback0
                    ebgp-multihop 5
                    peer-type fabric-external
                    address-family l2vpn evpn
                      allowas-in 3
                      send-community
                      send-community extended
                      rewrite-evpn-rt-asn
                  neighbor 10.2.2.2
                    remote-as 4000
                    update-source loopback0
                    ebgp-multihop 5
                    peer-type fabric-external
                    address-family l2vpn evpn
                      allowas-in 3
                      send-community
                      send-community extended
                      rewrite-evpn-rt-asn
                  neighbor 10.10.26.1
                   remote-as 4000
                    update-source {2}
                    ebgp-multihop 5
                    peer-type fabric-external
                    address-family ipv4 unicast
                      allowas-in 3
                      soft-reconfiguration inbound always
                 neighbor 10.10.27.1
                    remote-as 4000
                    update-source {3}
                    ebgp-multihop 5
                    peer-type fabric-external
                    address-family ipv4 unicast
                      allowas-in 3
                      soft-reconfiguration inbound always
                  neighbor 10.10.28.1
                    remote-as 4000
                    update-source {4}
                    ebgp-multihop 5
                    peer-type fabric-external
                    address-family ipv4 unicast
                      allowas-in 3
                      soft-reconfiguration inbound always
                  neighbor 10.10.29.1
                    remote-as 4000
                    update-source {5}
                    ebgp-multihop 5
                    peer-type fabric-external
                    address-family ipv4 unicast
                      allowas-in 3
                      soft-reconfiguration inbound always
                  neighbor 10.10.38.1
                    remote-as 4000
                    update-source {7}
                    ebgp-multihop 5
                    peer-type fabric-external
                    address-family ipv4 unicast
                      allowas-in 3
                      soft-reconfiguration inbound always
                  neighbor 10.10.39.1
                    remote-as 4000
                    update-source {6}
                    ebgp-multihop 5
                    peer-type fabric-external
                    address-family ipv4 unicast
                      allowas-in 3
                      soft-reconfiguration inbound always
                  neighbor 10.10.44.1
                   remote-as 4000
                    update-source {0}
                    ebgp-multihop 5
                    peer-type fabric-external
                    address-family ipv4 unicast
                      allowas-in 3
                      soft-reconfiguration inbound always
                  neighbor 10.10.45.1
                    remote-as 4000
                    update-source {1}
                    ebgp-multihop 5
                    peer-type fabric-external
                    address-family ipv4 unicast
                      allowas-in 3
                      soft-reconfiguration inbound always
                  vrf myvrf_50000
                    bestpath as-path multipath-relax
                    address-family ipv4 unicast
                      network 150.150.150.150/32
                      maximum-paths 64
                      maximum-paths ibgp 64
                     export-gateway-ip
                '''.format(testbed.devices[node].interfaces[intf_ch1].name, testbed.devices[node].interfaces[intf_ch2].name,testbed.devices[node].interfaces[intf_ch3].name,testbed.devices[node].interfaces[intf_ch4].name,testbed.devices[node].interfaces[intf_ch5].name,testbed.devices[node].interfaces[intf_ch6].name,testbed.devices[node].interfaces[intf_ch7].name,testbed.devices[node].interfaces[intf_ch8].name,testbed.devices[node].interfaces[intf_ch9].name,))
        for node in device_dut:
            testbed.devices[node].configure('''
              configure replace bootflash:multisite
               '''.format())                             

class disable_vn_segment_vlan_based_new(nxtest.Testcase):
    # on sumpin, disable feature vn-segment-vlan-based 
    @aetest.test
    def disable_vn_segment_vlan_based_new(self, testbed,testscript,device_dut1,device_dut2):
        for node in device_dut2:
            testbed.devices[node].configure('''
                terminal dont-ask
                copy r bootflash:multisite
                '''.format()) 
        time.sleep(10)                                                        
        for node in device_dut1:
            testbed.devices[node].configure('''
                no feature nv overlay
                no feature vn-segment-vlan-based
                '''.format())
        time.sleep(10)  
        for node in device_dut2:
            testbed.devices[node].configure('''
                configure replace bootflash:multisite
                '''.format())
        time.sleep(120)  

class config_replace(nxtest.Testcase):
    # on all leaf, config replace
    @aetest.test
    def config_replace(self, testbed,testscript,device_dut1, device_dut2, device_dut3, vlan):
        for node in device_dut1:
            testbed.devices[node].configure('''
                terminal dont-ask
                copy r bootflash:multisite                                            
                vlan {0}
                  no vn-segment 30001
                  vn-segment 3001
                '''.format(vlan))
        time.sleep(30)
        log.info("Waiting for 30 seconds after SVI shut")
        for node in device_dut1:
            testbed.devices[node].configure('''
              configure replace bootflash:multisite             
                '''.format(vlan))                  

        for node in device_dut2:
            testbed.devices[node].configure('''
                terminal dont-ask
                copy r bootflash:multisite                                            
                vlan {0}
                  no vn-segment 30001
                  vn-segment 3001 
                '''.format(vlan))
        time.sleep(30)
        log.info("Waiting for 30 seconds after SVI shut")
        for node in device_dut2:
            testbed.devices[node].configure('''
              configure replace bootflash:multisite             
                '''.format(vlan))

        for node in device_dut3:
            testbed.devices[node].configure('''
                terminal dont-ask
                copy r bootflash:multisite                                            
                vlan {0}
                  no vn-segment 30001
                  vn-segment 3001 
                '''.format(vlan))
        time.sleep(30)
        log.info("Waiting for 30 seconds after SVI shut")
        for node in device_dut3:
            testbed.devices[node].configure('''
              configure replace bootflash:multisite             
                '''.format(vlan))
        time.sleep(10)

class Shut_NoShut_vPC_Primary(nxtest.Testcase):
    # on tecate1, shut and no shut the portchannel 1
    @aetest.test
    def Shut_NoShut_vPC_Primary(self, testbed,testscript,device_dut, port_ch):
        for node in device_dut:
            testbed.devices[node].configure('''
                interface port-channel {0}
                  shut
                '''.format(port_ch))
        time.sleep(30)
        log.info("Waiting for 30 seconds after SVI shut")
        for node in device_dut:
            testbed.devices[node].configure('''
                interface port-channel {0}
                  no shut
                '''.format(port_ch))
            
class configure_bfd(nxtest.Testcase):
    # on tecate1 and spine configure bfd
    @aetest.test
    def configure_bfd(self, testbed,testscript,device_dut1, device_dut2, asn, asn1):
        for node in device_dut1:
            testbed.devices[node].configure('''
                feature bfd
                router bgp {0}
                  neighbor 10.10.10.2
                    bfd
                  neighbor 10.10.11.2
                    bfd
                  neighbor 10.10.12.2
                    bfd                                    
                  neighbor 10.10.13.2
                    bfd
                '''.format(asn))
        time.sleep(30)
        log.info("Waiting for 30 seconds after SVI shut")
        for node in device_dut2:
            testbed.devices[node].configure('''
                feature bfd
                router bgp {0}
                  neighbor 10.10.10.1
                    bfd
                  neighbor 10.10.11.1
                    bfd
                  neighbor 10.10.12.1
                    bfd                                    
                  neighbor 10.10.13.1
                    bfd
                '''.format(asn1))
            time.sleep(30)
            log.info("Waiting for 30 seconds after SVI shut")
            output = testbed.devices[node].configure('show bfd neighbors')
            nve_search = re.search('[0-9]+[0-9]+.+[0-9]+[0-9]+.+[0-9]+[0-9]+.+[0-9]', output)
            fin = nve_search.group()
            fail_flag = []
            if (fin == '10.10.10.2'):
                print('passed')
            else:
                fail_flag.append(0)
                print('failed')  

class host_move(nxtest.Testcase):
    # move the hosts on ixia from vpc to stand alone and vice versa
    @aetest.test
    def host_move(self, testbed,testscript,device_dut1, device_dut2):
        for node in device_dut1:
            testbed.devices[node].configure('''
                  clear mac address-table dynamic
                '''.format())
            time.sleep(10)            
            output = testbed.devices[node].configure('show mac address-table dynamic')
            nve_search = re.search('[a-z]+[a-z]+[a-z]+[0-9]+.+[0-9]+[0-9]+.+[0-9]+.[0-9]+.+[0-9]+.', output)
            fin = nve_search.group()
            fail_flag = []
            if (fin == 'nve1(10.3.0.3)'):
                print('passed')
            else:
                fail_flag.append(0)
                print('host move failed')  
        time.sleep(30)
        for node in device_dut2:
            testbed.devices[node].configure('''
                  clear mac address-table dynamic
                '''.format())
            time.sleep(10)
            output = testbed.devices[node].configure('show mac address-table dynamic')
            nve_search = re.search('[A-Z]+[a-z]+[a-z]+[0-9]+.+[0-9]+[0-9]', output)
            fin = nve_search.group()
            fail_flag = []
            if (fin == 'Eth1/48'):
                print('passed')
            else:
                fail_flag.append(0)
                print('host move failed')  

