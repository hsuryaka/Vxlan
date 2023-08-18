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

from unicon.eal.dialogs import Statement, Dialog

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
    time.sleep(20)
    
    # Apply traffic, start traffic and wait for 30min
    ixNetwork.Traffic.Apply()
    ixNetwork.Traffic.Start()
    # log.info("==> Wait for 2min for the MSite Scale traffic to populate")
    time.sleep(20)
    
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
            # log.info("time ===>")
            # log.info(time.gmtime())
            log.info("time ===>")
            break

    # Collect Data and tabulate it for reporting
    ixNetwork.ClearStats()
    time.sleep(10)
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
    
    # log.info(TrafficItemTable.draw())
    if 0 in fail_flag:
        return 0
    else:
        return 1

# Verify IXIA Traffic (Traffic Item Stats View)
def VerifyTraffic(section, testscript, **kwargs):
    
    session     = testscript.parameters['session']
    ixNetwork   = testscript.parameters['ixNetwork']
    threshold   = testscript.parameters['traffic_threshold']
    # trafficConvTime = testscript.parameters['traffic_convergence_time']

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
    time.sleep(30)

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
    

# Increment a prefix of a network
def increment_prefix_network(pref, count):
    size = 1 << (pref.network.max_prefixlen - pref.network.prefixlen)
    pref_lst = []
    for i in range(count):
        pref_lst.append(str((pref.ip+size*i)) + "/" + str(pref.network.prefixlen))
    return pref_lst

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
    # log.info(validation_msgs)
    if 0 in fail_flag:
        section.failed()
    else:
        section.passed()


def clearIPv6NbrForceDel(section, steps, **kwargs):
    """clear ipv6 neighbor vrf all force-delete """

    device_duts = kwargs.get('nd_supp_cache_dut_list', 1)
    cacheCnt = kwargs.get('cacheCount', 1)
    log.info("Entered VerifyNDSuppCache ##### ##### ##### ")
    log.info("cacheCnt value "+cacheCnt)
    cli_to_parse = kwargs.get('ndSupp_cli_to_parse', 1)
    log.info(cli_to_parse)
    nbrTotalCount = 0
    ndCacheTotalCount = 0

    # Verification for failed logs
    fail_flag = []
    validation_msgs = ''

    # Get the Total IPv6 Neighbor count
    for node in device_duts:
        section.parameters['testbed'].devices[node].execute(cli_to_parse)

# Verify IPv6 ND Suppression cache on devices
def VerifyTERoute(section, steps, **kwargs):
    """ Verify TE Route """

    with steps.start("Verify TE Routes"):
        device_duts = kwargs.get('vpc_dut_list', 1)
        stand_alone_node = kwargs.get('stdalone_dut_list', 1)
        log.info("Entered VerifyTERoute ##### ##### ##### ")
        cli_to_parse = kwargs.get('nh_cli_to_parse', 1)
        te_route_cli = kwargs.get('te_route_cli_to_parse1', 1)
        stdalone_te_route_cli = kwargs.get('te_route_cli_to_parse2', 1)
        log.info(te_route_cli)

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
            for retry_iteration in range(11):
                output = section.parameters['testbed'].devices[node].execute(cli_to_parse)
                output1 = re.search('172.30.30.30/32, ubest/mbest: 9/0', output, re.IGNORECASE)
                if output1 != None:
                    output = section.parameters['testbed'].devices[node].execute(cli_to_parse)
                    if re.search('172.30.30.30/32, ubest/mbest: 9/0', output, re.IGNORECASE):
                        log.info("NextHop 172.30.30.30 added to egress-loadbalance-resolution- VRF in "+node)
                        fail_flag1 = []
                    else:
                        validation_msgs += "NextHop 172.30.30.30 NOT added to egress-loadbalance-resolution- VRF in "
                        validation_msgs += node
                        log.info("NextHop 172.30.30.30 NOT added to egress-loadbalance-resolution- VRF in "+node)
                        fail_flag1.append(1)
                    break
                else:
                    log.info("Sleeping 45 seconds before retry to check for 172.30.30.30 prefix in StandAlone VTEP")
                    fail_flag1.append(1)
                    time.sleep(45)

        for node in device_duts:
            for retry_iteration in range(11):
                output = section.parameters['testbed'].devices[node].execute(te_route_cli)
                output2 = re.search('bgp-100, external, tag 65001, eLB, segid: 300001 tunnelid: 0xac1e1e1e encap: VXLAN', output, re.IGNORECASE)
                if output2 != None:
                    output = section.parameters['testbed'].devices[node].execute(te_route_cli)
                    if re.search("bgp-100, external, tag 65001, eLB, segid: 300001 tunnelid: 0xac1e1e1e encap: VXLAN", output, re.IGNORECASE):
                        log.info("Prefix 101.1.1.102 added as UECMP route in vrf v1 in " + node)
                        fail_flag2 = []
                    else:
                        validation_msgs += "Prefix 101.1.101.102 NOT added as UECMP route in vrf v1 in "
                        validation_msgs += node
                        log.info("Prefix 101.1.1.102 NOT added as UECMP route in vrf v1 in " + node)
                        fail_flag2.append(1)
                    break
                else:
                    log.info("Sleeping 45 seconds before retry to check for 101.1.101.102 prefix in StandAlone VTEP")
                    fail_flag2.append(1)
                    time.sleep(45)

                            
        for node in stand_alone_node:
            for retry_iteration in range(11):
                output = section.parameters['testbed'].devices[node].execute(stdalone_te_route_cli)        
                output1 = re.search("bgp-300, external, tag 65001, eLB, segid: 300001 tunnelid: 0xac0a0a0a encap: VXLAN", output, re.IGNORECASE)
                if output1 != None:
                    output = section.parameters['testbed'].devices[node].execute(stdalone_te_route_cli)        
                    if re.search("bgp-300, external, tag 65001, eLB, segid: 300001 tunnelid: 0xac0a0a0a encap: VXLAN", output, re.IGNORECASE):
                        log.info("Prefix 170.3.1.33 added as UECMP route in vrf v1 in " + node)
                        fail_flag3 = []
                    else:
                        log.info("Prefix 170.3.1.33 NOT added as UECMP route in vrf v1 in " + node)
                        validation_msgs += "Prefix 170.3.1.33 NOT added as UECMP route in vrf v1 in "
                        validation_msgs += node
                        fail_flag3.append(1)
                    break
                else:
                    log.info("Sleeping 45 seconds before retry to check for 170.3.1.33 prefix in StandAlone VTEP")
                    fail_flag3.append(1)
                    time.sleep(45)
    
        # Status Reporting
        log.info(validation_msgs)
        if 1 in fail_flag1 or 1 in fail_flag2 or 1 in fail_flag3:
            section.failed()
        else:
            section.passed()


def VerifyTERouteStandAlone(section, steps, **kwargs):
    """ Verify TE Route """

    device_duts = kwargs.get('stdalone_dut_list', 1)
    stand_alone_node = kwargs.get('stdalone_dut_list', 1)
    log.info("Entered VerifyTERoute ##### ##### ##### ")
    cli_to_parse1 = kwargs.get('nh_cli_to_parse1', 1)
    cli_to_parse2 = kwargs.get('nh_cli_to_parse2', 1)
    te_route_cli = kwargs.get('te_route_cli_to_parse1', 1)
    stdalone_te_route_cli = kwargs.get('te_route_cli_to_parse2', 1)
    log.info(te_route_cli)

    # Verification for failed logs
    fail_flag = []
    validation_msgs = ''
    v_msg = ''

    with steps.start("Verify TE Routes on the StandAlone VTEP"):
        # Get the Total IPv6 Neighbor count
        for node in device_duts:
            output = section.parameters['testbed'].devices[node].execute(cli_to_parse1)
            if re.search('172.10.10.10/32, ubest/mbest: 9/0', output, re.IGNORECASE):
                log.info("NextHop 172.10.10.10 added to egress-loadbalance-resolution- VRF in "+node)
            else:
                log.info("NextHop 172.10.10.10 NOT added to egress-loadbalance-resolution- VRF in "+node)
                fail_flag.append(1)

        for node in device_duts:
            output = section.parameters['testbed'].devices[node].execute(cli_to_parse2)
            if re.search('172.20.20.20/32, ubest/mbest: 9/0', output, re.IGNORECASE):
                log.info("NextHop 172.20.20.20 added to egress-loadbalance-resolution- VRF in "+node)
            else:
                log.info("NextHop 172.20.20.20 NOT added to egress-loadbalance-resolution- VRF in "+node)
                fail_flag.append(1)

        for node in device_duts:
            output = section.parameters['testbed'].devices[node].execute(te_route_cli)        
            if re.search("bgp-300, external, tag 65001, eLB, segid: 300001 tunnelid: 0xa0a1414 encap: VXLAN", output, re.IGNORECASE):
                log.info("Prefix 101.1.102.101 added as UECMP route in vrf v1 in " + node)
            else:
                log.info("Prefix 101.1.102.101 NOT added as UECMP route in vrf v1 in " + node)
                validation_msgs += "Prefix 101.1.102.101 NOT added as UECMP route in vrf v1 in "
                validation_msgs += node
                fail_flag.append(1)
        
        for node in stand_alone_node:
            output = section.parameters['testbed'].devices[node].execute(stdalone_te_route_cli)        
            if re.search("bgp-300, external, tag 65001, eLB, segid: 300001 tunnelid: 0xac0a0a0a encap: VXLAN", output, re.IGNORECASE):
                log.info("Prefix 170.3.1.33 added as UECMP route in vrf v1 in " + node)
            else:
                log.info("Prefix 170.3.1.33 NOT added as UECMP route in vrf v1 in " + node)
                validation_msgs += "Prefix 170.3.1.33 NOT added as UECMP route in vrf v1 in "
                validation_msgs += node
                fail_flag.append(1)
        
        cliToVerify = 'show interface ethernet 1/49/1-4, ethernet 1/53/1-4 | i i rate|^Ether | i "30 seconds output rate" | cut -f 2 -d "," | cut -f 2 -d " "'
        for node in device_duts:
            output = section.parameters['testbed'].devices[node].execute(cliToVerify)
            lines = output.splitlines()
            for line in lines:
                log.info(type(line))
                if line != "0":
                    log.info("Traffic is Load Balanced among all available paths")
                else:
                    # v_msg += "FAIL: Traffic is not Load Balanced among all the available paths "
                    log.info("FAIL: Traffic is not Load Balanced among all the available paths ")
                    v_msg = "FAIL: Traffic is not Load Balanced among all the available paths "
                    fail_flag.append(1)

        cliToVerify = 'show interf port-channel 501 | i i rate | i "30 seconds output rate" | cut -f 2 -d "," | cut -f 2 -d " "'
        for node in device_duts:
            output = section.parameters['testbed'].devices[node].execute(cliToVerify)
            lines = output.splitlines()
            for line in lines:
                if line != "0":
                    log.info("Traffic is Load Balanced among all available paths")
                else:
                    # v_msg += "FAIL: Traffic is not Load Balanced among all the available paths "
                    log.info("FAIL: Traffic is not Load Balanced among all the available paths ")
                    v_msg = "FAIL: Traffic is not Load Balanced among all the available paths "
                    fail_flag.append(1)

        # Status Reporting
        log.info(validation_msgs)
        log.info(v_msg)
        if 1 in fail_flag:
            section.failed()
        else:
            section.passed()
# def VerifyNDSuppCache(section, steps, **kwargs):
#     """ Verify ND Suppression Cache """

#     device_duts = kwargs.get('nd_supp_cache_dut_list', 1)
#     cacheCnt = kwargs.get('cacheCount', 1)
#     log.info("Entered VerifyNDSuppCache ##### ##### ##### ")
#     log.info("cacheCnt value "+cacheCnt)
#     cli_to_parse = kwargs.get('ndSupp_cli_to_parse', 1)
#     log.info(cli_to_parse)
#     nbrTotalCount = 0
#     ndCacheTotalCount = 0

#     # Verification for failed logs
#     fail_flag = []
#     validation_msgs = ''

#     # Get the Total IPv6 Neighbor count
#     for node in device_duts:
#         nbrCount = int(section.parameters['testbed'].devices[node].execute(cli_to_parse))
#         nbrTotalCount += nbrCount 

#     # Compare Nbr count with ND Suppression cache count
#     for node in device_duts:
#         ndCacheTotalCount = int(section.parameters['testbed'].devices[node].execute("show ipv6 nd suppression-cache detail | grep ^2001 | wc -l"))
#         if ndCacheTotalCount != nbrTotalCount:
#             log.info("Cache count check failed, count is not equal to " + str(nbrTotalCount))
#             validation_msgs += '\n Cache count check failed in ' + node + ', cache count is not equal to ' + str(nbrTotalCount) + '. Its '
#             validation_msgs += str(ndCacheTotalCount)
#             fail_flag.append(0)
#         else:
#             validation_msgs += '\n Cache Count check passed \n'

#     # Status Reporting
#     log.info(validation_msgs)
#     if 0 in fail_flag:
#         section.failed()
#     else:
#         section.passed()

def VerifyNDSuppCacheSummary(section, steps, **kwargs):
    """ Verify ND Suppression Cache Summary """
    device_duts = kwargs.get('nd_supp_cache_dut_list', 1)
    cacheCnt = kwargs.get('cacheCount', 1)
    log.info("Entered VerifyNDSuppCacheSummary ##### ##### ##### ")
    log.info("cacheCnt value "+cacheCnt)
    cli_to_parse = kwargs.get('ndSupp_cli_to_parse', 1)
    log.info(cli_to_parse)
    nbrTotalCount = 0
    ndCacheTotalCount = 0
    ndCacheTotalCountPri = 0
    ndCacheTotalCountStandAloneVtep = 0

    # Verification for failed logs
    fail_flag = []
    validation_msgs = ''
    stand_alone_node = kwargs.get('standalone_dut', 1)

    # Get the Total IPv6 Neighbor count
    for node in device_duts:
        nbrCount = int(section.parameters['testbed'].devices[node].execute(cli_to_parse))
        nbrTotalCount += nbrCount 

    # Compare Nbr count with ND Suppression cache count
    for node in device_duts:
        if node == "node2_s1_vpc_1":
            ndCacheTotalCountPri = int(section.parameters['testbed'].devices[node].execute('show ipv6 nd suppression-cache summary | grep Total | cut -f 2 -d ":"'))
        if node == "node4_s1_leaf_1":
            ndCacheTotalCountStandAloneVtep = int(section.parameters['testbed'].devices[node].execute('show ipv6 nd suppression-cache summary | grep Total | cut -f 2 -d ":"'))

    log.info("ndCacheTotalCountPri ### " + str(ndCacheTotalCountPri))
    log.info("ndCacheTotalCountStandAloneVtep ### " + str(ndCacheTotalCountStandAloneVtep))
    if ndCacheTotalCountPri != nbrTotalCount:
        log.info("Cache count check failed, count is not equal to " + str(nbrTotalCount))
        validation_msgs += '\n Cache count Summary check failed in VPC Primary, cache count is not equal to ' + str(ndCacheTotalCountPri) + '. Its '
        validation_msgs += str(ndCacheTotalCount)
        fail_flag.append(0)
    else:
        log.info('\n Cache Count Summary check passed in VPC Primary\n')

    if ndCacheTotalCountStandAloneVtep != nbrTotalCount:
        log.info("Cache count check failed, count is not equal to " + str(nbrTotalCount))
        validation_msgs += '\n Cache count Summary check failed in StandAlone VTEP, cache count is not equal to ' + str(ndCacheTotalCountStandAloneVtep) + '. Its '
        validation_msgs += str(ndCacheTotalCountStandAloneVtep)
        fail_flag.append(0)
    else:
            log.info('\n Cache Count Summary check passed in StandAlone VTEP\n')

    # Status Reporting
    log.info(validation_msgs)
    if 0 in fail_flag:
        section.failed()
    else:
        section.passed()


def VerifyNDSuppCacheSummarLocal(section, steps, **kwargs):
    """ Verify ND Suppression Cache Summary """
    device_duts = kwargs.get('nd_supp_cache_dut_list', 1)
    cacheCnt = kwargs.get('cacheCount', 1)
    log.info("Entered VerifyNDSuppCacheSummary ##### ##### ##### ")
    log.info("cacheCnt value "+cacheCnt)
    cli_to_parse = kwargs.get('ndSupp_cli_to_parse', 1)
    log.info(cli_to_parse)
    nbrTotalCountPri = 0
    nbrTotalCountStandAlone = 0
    ndCacheTotalCount = 0
    ndCacheTotalCountPri = 0
    ndCacheTotalCountStandAloneVtep = 0

    # Verification for failed logs
    fail_flag = []
    validation_msgs = ''
    stand_alone_node = kwargs.get('standalone_dut', 1)

    # Get the Total IPv6 Neighbor count
    for node in device_duts:
        nbrCount = 0
        if node == "node2_s1_vpc_1":
            nbrCount = int(section.parameters['testbed'].devices[node].execute(cli_to_parse))
            nbrTotalCountPri += nbrCount 
        if node == "node4_s1_leaf_1":
            nbrCount = int(section.parameters['testbed'].devices[node].execute(cli_to_parse))
            nbrTotalCountStandAlone += nbrCount 


    # Compare Nbr count with ND Suppression cache count
    for node in device_duts:
        if node == "node2_s1_vpc_1":
            ndCacheTotalCountPri = int(section.parameters['testbed'].devices[node].execute('show ipv6 nd suppression-cache summary | grep Local | cut -f 2 -d ":"'))
        if node == "node4_s1_leaf_1":
            ndCacheTotalCountStandAloneVtep = int(section.parameters['testbed'].devices[node].execute('show ipv6 nd suppression-cache summary | grep Local | cut -f 2 -d ":"'))

    if ndCacheTotalCountPri != nbrTotalCountPri:
        log.info("Cache count check failed, count is not equal to " + str(nbrTotalCountPri))
        validation_msgs += '\n Cache count Summary check failed in VPC Primary, cache count is not equal to ' + str(ndCacheTotalCountPri) + '. Its '
        validation_msgs += str(ndCacheTotalCount)
        fail_flag.append(0)
    else:
        log.info('\n Cache Count Summary check passed in VPC Primary\n')

    if ndCacheTotalCountStandAloneVtep != nbrTotalCountStandAlone:
        log.info("Cache count check failed, count is not equal to " + str(nbrTotalCountStandAlone))
        validation_msgs += '\n Cache count Summary check failed in StandAlone VTEP, cache count is not equal to ' + str(ndCacheTotalCountStandAloneVtep) + '. Its '
        validation_msgs += str(ndCacheTotalCountStandAloneVtep)
        fail_flag.append(0)
    else:
            log.info('\n Cache Count Summary check passed in StandAlone VTEP\n')

    # Status Reporting
    log.info(validation_msgs)
    if 0 in fail_flag:
        section.failed()
    else:
        section.passed()


def VerifyNDSuppCacheSummaryRemote(section, steps, **kwargs):
    """ Verify ND Suppression Cache Summary """
    device_duts = kwargs.get('nd_supp_cache_dut_list', 1)
    cacheCnt = kwargs.get('cacheCount', 1)
    log.info("Entered VerifyNDSuppCacheSummary ##### ##### ##### ")
    log.info("cacheCnt value "+cacheCnt)
    cli_to_parse = kwargs.get('ndSupp_cli_to_parse', 1)
    log.info(cli_to_parse)
    nbrTotalCountPri = 0
    nbrTotalCountStandAlone = 0
    ndCacheTotalCount = 0
    ndCacheRemoteCountPri = 0
    ndCacheRemoteCountStandAloneVtep = 0

    # Verification for failed logs
    fail_flag = []
    validation_msgs = ''
    stand_alone_node = kwargs.get('standalone_dut', 1)

    # Get the Total IPv6 Neighbor count
    for node in device_duts:
        nbrCount = 0
        if node == "node2_s1_vpc_1":
            nbrCount = int(section.parameters['testbed'].devices[node].execute(cli_to_parse))
            nbrTotalCountPri += nbrCount 
        if node == "node4_s1_leaf_1":
            nbrCount = int(section.parameters['testbed'].devices[node].execute(cli_to_parse))
            nbrTotalCountStandAlone += nbrCount 


    # Compare Nbr count with ND Suppression cache count
    for node in device_duts:
        if node == "node2_s1_vpc_1":
            ndCacheRemoteCountPri = int(section.parameters['testbed'].devices[node].execute('show ipv6 nd suppression-cache summary | grep Remote | cut -f 2 -d ":"'))
        if node == "node4_s1_leaf_1":
            ndCacheRemoteCountStandAloneVtep = int(section.parameters['testbed'].devices[node].execute('show ipv6 nd suppression-cache summary | grep Remote | cut -f 2 -d ":"'))

    if ndCacheRemoteCountPri != nbrTotalCountStandAlone:
        log.info("Cache count check failed, count is not equal to " + str(nbrTotalCountStandAlone))
        validation_msgs += '\n Cache count Summary check failed in VPC Primary, Remote cache count is not equal to ' + str(nbrTotalCountStandAlone) + '. Its '
        validation_msgs += str(ndCacheRemoteCountPri)
        fail_flag.append(0)
    else:
        log.info('\n Cache Count Summary check passed in VPC Primary\n')

    if ndCacheRemoteCountStandAloneVtep != nbrTotalCountPri:
        log.info("Cache count check failed, count is not equal to " + str(nbrTotalCountPri))
        validation_msgs += '\n Cache count Summary check failed in StandAlone VTEP, cache count is not equal to ' + str(nbrTotalCountPri) + '. Its '
        validation_msgs += str(ndCacheRemoteCountStandAloneVtep)
        fail_flag.append(0)
    else:
            log.info('\n Cache Count Summary check passed in StandAlone VTEP\n')

    # Status Reporting
    log.info(validation_msgs)
    if 0 in fail_flag:
        section.failed()
    else:
        section.passed()

def VerifyNDSuppCacheSummaryVlan(section, steps, **kwargs):
    """ Verify ND Suppression Cache Summary """
    device_duts = kwargs.get('nd_supp_cache_dut_list', 1)
    cacheCnt = kwargs.get('cacheCount', 1)
    log.info("Entered VerifyNDSuppCacheSummary ##### ##### ##### ")
    log.info("cacheCnt value "+cacheCnt)
    cli_to_parse = kwargs.get('ndSupp_cli_to_parse', 1)
    log.info(cli_to_parse)
    nbrCount = 0
    nbrVlan1002CountTotal = 0
    ndCacheVlan1002CountPri = 0
    ndCacheVlan1002CountStandAloneVtep = 0

    # Verification for failed logs
    fail_flag = []
    validation_msgs = ''
    stand_alone_node = kwargs.get('standalone_dut', 1)

    # Get the Total IPv6 Neighbor count
    for node in device_duts:
            nbrCount = int(section.parameters['testbed'].devices[node].execute(cli_to_parse))
            nbrVlan1002CountTotal += nbrCount 


    # Compare Nbr count with ND Suppression cache count
    for node in device_duts:
        if node == "node2_s1_vpc_1":
            ndCacheVlan1002CountPri = int(section.parameters['testbed'].devices[node].execute('show ipv6 nd suppression-cache vlan 1002 | grep ^2001 | wc -l'))
        if node == "node4_s1_leaf_1":
            ndCacheVlan1002CountStandAloneVtep = int(section.parameters['testbed'].devices[node].execute('show ipv6 nd suppression-cache vlan 1002 | grep ^2001 | wc -l'))


    if ndCacheVlan1002CountPri != nbrVlan1002CountTotal:
        log.info("Cache count check failed, count is not equal to " + str(nbrVlan1002CountTotal))
        validation_msgs += '\n Cache count Summary check failed in VPC Primary, Remote cache count is not equal to ' + str(nbrVlan1002CountTotal) + '. Its '
        validation_msgs += str(ndCacheVlan1002CountPri)
        fail_flag.append(0)
    else:
        log.info('\n Cache Count Summary check passed in VPC Primary\n')

    if ndCacheVlan1002CountStandAloneVtep != nbrVlan1002CountTotal:
        log.info("Cache count check failed, count is not equal to " + str(nbrVlan1002CountTotal))
        validation_msgs += '\n Cache count Summary check failed in StandAlone VTEP, cache count is not equal to ' + str(nbrVlan1002CountTotal) + '. Its '
        validation_msgs += str(ndCacheVlan1002CountStandAloneVtep)
        fail_flag.append(0)
    else:
            log.info('\n Cache Count Summary check passed in StandAlone VTEP\n')

    # Status Reporting
    log.info(validation_msgs)
    if 0 in fail_flag:
        section.failed()
    else:
        section.passed()

def VerifyNDSuppCacheOrphan(section, steps, **kwargs):
    """ Verify ND Suppression Cache after Orphan Flap"""

    device_duts = kwargs.get('nd_supp_cache_dut_list', 1)
    cacheCnt = kwargs.get('cacheCount', 1)
    log.info("Entered VerifyNDSuppCacheOrphan ##### ##### ##### ")
    log.info("cacheCnt value "+cacheCnt)
    cli_to_parse = kwargs.get('ndSupp_cli_to_parse', 1)
    log.info(cli_to_parse)
    nbrTotalCount = 0
    ndCacheTotalCount = 0

    # Verification for failed logs
    fail_flag = []
    validation_msgs = ''

    for node in device_duts:
        nbrCount = int(section.parameters['testbed'].devices[node].execute(cli_to_parse))
        nbrTotalCount += nbrCount 

    # Compare Nbr count with ND Suppression cache count
    for node in device_duts:
        ndCacheTotalCount = int(section.parameters['testbed'].devices[node].execute("show ipv6 nd suppression-cache detail | grep ^2001 | wc -l"))
        if ndCacheTotalCount != nbrTotalCount:
            log.info("Cache count check failed, count is not equal to " + str(nbrTotalCount))
            validation_msgs += '\n Cache count check failed in ' + node + ', cache count is not equal to ' + str(nbrTotalCount) + '. Its '
            validation_msgs += str(ndCacheTotalCount)
            fail_flag.append(0)
        else:
            validation_msgs += '\n Cache Count check passed \n'

    # Status Reporting
    log.info(validation_msgs)
    if 0 in fail_flag:
        section.failed()
    else:
        section.passed()

# Verify Consistency Checker
def VerifyCC(section, **kwargs):
    """ Verify Consistency Checker """

    cc_dut_list = kwargs.get('cc_dut_list', 1)
    log.info(cc_dut_list)
    fail_flag = []
    validation_msgs = ''

    if cc_dut_list == 1:
        section.skipped('No devices passed as part of cc_dut_list')
    
    # Build the parameters per node
    arg_list = []
    for node in cc_dut_list:
        log.info(node)
        # arg_dict parameters per node
        cc_args_dict = {
            'dut'                   : section.parameters['testbed'].devices[node],
            'fnl_flag'              : '0',
            'random_vlan'           : '1',
        }
        arg_list.append(cc_args_dict)

    # PCALL verify CC
    iterr = 0
    vxlanCC_ParallelCall = pcall(infraVerify.verifyBasicVxLANCC, args_dict=arg_list)
    for result in vxlanCC_ParallelCall:
        validation_msgs += "\n\nNode : "+str(section.parameters['testbed'].devices[cc_dut_list[iterr]].name)+\
                            "\n\nConsistency Check Data : "+\
                            " :\n==========================\n"
        fail_flag.append(result['status'])
        validation_msgs += str(result['logs'])
        iterr+=1
    
    # Status Reporting
    log.info(validation_msgs)
    if 0 in fail_flag:
        section.failed()
    else:
        section.passed()

# Perform copy r s
def doCopyRunToStart(section):
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

class ConfigureRollback(nxtest.Testcase):
    @aetest.test
    def config_rollback(self, testbed, verify_dict, trigger_wait_time):
        log.info("Inside config_rollback...")
        config_dict = {
            "testbed": testbed,
            "verify_dict": verify_dict}
        configure_rollback_obj = ConfigRollback(**config_dict)
        log.info("Calling run_trigger..")
        configure_rollback_obj.run_trigger(trigger_wait_time)
        log.info("Calling verify_trigger..")
        configure_rollback_obj.verify_trigger()
        if configure_rollback_obj.result == 'fail':
            log.error("Configure rollback-FAILED")
            self.failed()
        else:
            log.info("Configure rollback-PASSED")

###################################################################
###                  Configuration Adjustments                  ###
###################################################################

class ConfigureScaleMSiteVtepBgpSessionDCI(nxtest.Testcase):
    """ ConfigureScaleMSiteVtepBgpSessionDCI - Configure Scale BGP Sessions for MSite VTEPs """

    @aetest.test
    def ConfigureScaleBgpSessions(self, steps, testbed, testscript, device_dut):
        """ ConfigureScaleBgpSessions - Configure Scale BGP Sessions """

        for node in device_dut:
            # Get router BGP AS number
            bgp_as_data = testbed.devices[node].execute('show run bgp | i i "router bgp"')
            bgp_as_data_processed = re.search('router bgp (\d+)', bgp_as_data, re.I)
            
            # Get CS DCI TGEN Interface Name
            cs_dci_tgen_interface = None
            for interface in testbed.devices[node].interfaces:
                if testbed.devices[node].interfaces[interface].alias == 'nd01_tgen_1_1':
                    cs_dci_tgen_interface = interface
                    log.info("CS DCI - TGEN Interface : "+str(interface))
            
            if bgp_as_data_processed and cs_dci_tgen_interface != None:
                bgp_as = bgp_as_data_processed.groups(0)[0]
                # Configuration to be added
                BgpCfg = '''
                        router bgp '''+str(bgp_as)+'''
                        neighbor 52.100.1.1
                            remote-as 65200
                            description Underlay IXIA Simulation
                            update-source '''+str(cs_dci_tgen_interface)+'''
                            timers 90 270
                            address-family ipv4 unicast
                                send-community
                                send-community extended
                                soft-reconfiguration inbound
                '''
                remote_bgp_as = 65001
                for octect in range(101,229):
                    BgpCfg += '''
                        neighbor 102.'''+str(octect)+'''.1.1
                        remote-as '''+str(remote_bgp_as)+'''
                        update-source loopback0
                        ebgp-multihop 10
                        peer-type fabric-external
                        address-family l2vpn evpn
                            send-community
                            send-community extended
                            route-map RMAP_NH_UNCHANGED out
                            rewrite-evpn-rt-asn
                        neighbor 102.'''+str(octect)+'''.2.1
                        remote-as '''+str(remote_bgp_as)+'''
                        update-source loopback0
                        ebgp-multihop 10
                        peer-type fabric-external
                        address-family l2vpn evpn
                            send-community
                            send-community extended
                            route-map RMAP_NH_UNCHANGED out
                            rewrite-evpn-rt-asn
                    '''
                    remote_bgp_as += 1
                testbed.devices[node].configure(BgpCfg)

class ConfigureScaleInterSiteVtepBgpSessionS1Spine(nxtest.Testcase):
    """ ConfigureScaleInterSiteVtepBgpSessionS1Spine - Configure Scale BGP Sessions for Site Internal VTEPs """

    @aetest.test
    def ConfigureScaleBgpSessions(self, steps, testbed, testscript, device_dut):
        """ ConfigureScaleBgpSessions - Configure Scale BGP Sessions """

        for node in device_dut:
            # Get router BGP AS number
            bgp_as_data = testbed.devices[node].execute('show run bgp | i i "router bgp"')
            bgp_as_data_processed = re.search('router bgp (\d+)', bgp_as_data, re.I)
            if bgp_as_data_processed:
                bgp_as = bgp_as_data_processed.groups(0)[0]
                # Configuration to be added
                BgpCfg = '''
                        router bgp '''+str(bgp_as)+'''
                '''
                for octect in range(101,217):
                    BgpCfg += '''
                        neighbor 150.'''+str(octect)+'''.2.1
                        remote-as '''+str(bgp_as)+'''
                        update-source loopback0
                        timers 90 270
                        address-family l2vpn evpn
                            send-community
                            send-community extended
                            route-reflector-client
                    '''
                testbed.devices[node].configure(BgpCfg)

class ConfigureScaleInterSiteVtepBgpSessionS2Spine(nxtest.Testcase):
    """ ConfigureScaleInterSiteVtepBgpSessionS2Spine - Configure Scale BGP Sessions for Site Internal VTEPs """

    @aetest.test
    def ConfigureScaleBgpSessions(self, steps, testbed, testscript, device_dut):
        """ ConfigureScaleBgpSessions - Configure Scale BGP Sessions """

        for node in device_dut:
            # Get router BGP AS number
            bgp_as_data = testbed.devices[node].execute('show run bgp | i i "router bgp"')
            bgp_as_data_processed = re.search('router bgp (\d+)', bgp_as_data, re.I)
            if bgp_as_data_processed:
                bgp_as = bgp_as_data_processed.groups(0)[0]
                # Configuration to be added
                BgpCfg = '''
                        router bgp '''+str(bgp_as)+'''
                '''
                for octect in range(101,217):
                    BgpCfg += '''
                        neighbor 150.'''+str(octect)+'''.3.1
                        remote-as '''+str(bgp_as)+'''
                        update-source loopback0
                        timers 90 270
                        address-family l2vpn evpn
                            send-community
                            send-community extended
                            route-reflector-client
                    '''
                testbed.devices[node].configure(BgpCfg)

class TriggerConvertL3VNIOld2New(nxtest.Testcase):
    """ TriggerConvertL3VNIOld2New - Convert Old L3VNI into New L3VNI """

    @aetest.test
    def ConvertL3VNIOld2New(self, steps, testbed, testscript, device_dut):
        """ ConvertL3VNIOld2New - Convert Old L3VNI into New L3VNI """

        # Get the VRF list
        with steps.start("Get configured VRFs"):
            for node in device_dut:
                testscript.parameters[node] = {}
                testscript.parameters[node]['vrf_data'] = {}

                log.info("# -- getting VRF Data and parsing it to be in order")
                testscript.parameters[node]['vrf_data'] = {}
                vrf_output = json.loads(testbed.devices[node].execute("sh vrf | json"))["TABLE_vrf"]["ROW_vrf"]
                for item in vrf_output:
                    item['vrf_id'] = int(item['vrf_id'])
                vrf_output = sorted(vrf_output, key=itemgetter('vrf_id'))
                vrf_order = []
                vrf_data = []
                for vrf in vrf_output:
                    if str(vrf['vrf_name']) != 'default' and str(vrf['vrf_name']) != 'management':
                        re_pr = re.search('([a-bA-Z]+[-_])(\d+)',vrf['vrf_name'])
                        if re_pr:
                            vrf_order.append(int(re_pr.groups(0)[1]))
                vrf_order.sort()
                for i in vrf_order:
                    vrf_data.append(str(re_pr.groups(0)[0])+str(i))

                log.info("# -- Get all the VRF's information")
                for vrf in vrf_data:
                    testscript.parameters[node]['vrf_data'][str(vrf)] = {}
                    vrf_run_output = testbed.devices[node].execute(f'show run vrf '+str(vrf)+' | beg i "context" | head line 2')
                    vrf_run_regex = re.search("vni (\\d+)", vrf_run_output,re.M)
                    if vrf_run_regex:
                        testscript.parameters[node]['vrf_data'][str(vrf)]['vni'] = str(vrf_run_regex.groups(0)[0])
                        vni_data = json.loads(testbed.devices[node].execute(f'show nve vni '+str(vrf_run_regex.groups(0)[0])+' detail | json'))["TABLE_nve_vni"]["ROW_nve_vni"]
                        testscript.parameters[node]['vrf_data'][str(vrf)]['vlan'] = str(vni_data['vlan-bd'])

        # Delete the OLD L3 VNI's
        with steps.start("Delete the OLD L3 VNI's"):
            for node in device_dut:
                iter_counter = 1
                configs = ''
                for vrf in testscript.parameters[node]['vrf_data'].keys():
                    if iter_counter%2 != 0:
                        iter_counter+=1
                        continue
                    if 'vni' in testscript.parameters[node]['vrf_data'][str(vrf)].keys():
                        configs += '''
                            vrf context '''+str(vrf)+'''
                                no vni '''+str(testscript.parameters[node]['vrf_data'][str(vrf)]['vni'])+'''
                        '''
                    if 'vlan' in testscript.parameters[node]['vrf_data'][str(vrf)].keys():
                        if int(testscript.parameters[node]['vrf_data'][str(vrf)]['vlan']) < 4000:
                            configs += '''
                                no interface vlan '''+str(testscript.parameters[node]['vrf_data'][str(vrf)]['vlan'])+'''
                                no vlan '''+str(testscript.parameters[node]['vrf_data'][str(vrf)]['vlan'])+'''
                            '''
                    iter_counter+=1
                testbed.devices[node].configure(configs)
            # Wait for 2 minutes post Deleting old L3VNIs
            time.sleep(60)

        # ADD the NEW L3 VNI's under VRF context
        with steps.start("ADD the NEW L3 VNI's"):
            for node in device_dut:
                iter_counter = 1
                configs = ''
                for vrf in testscript.parameters[node]['vrf_data'].keys():
                    if iter_counter%2 != 0:
                        iter_counter+=1
                        continue
                    configs += '''
                        vrf context '''+str(vrf)+'''
                        vni '''+str(testscript.parameters[node]['vrf_data'][str(vrf)]['vni'])+''' l3
                    '''
                    # cli(f'''conf t ; vrf context '''+str(vrf)+''' ; vni '''+str(testscript.parameters[node]['vrf_data'][str(vrf)]['vni'])+''' l3''')
                    iter_counter+=1
                testbed.devices[node].configure(configs)

            # Wait for 2 minutes post adding new L3VNIs
            time.sleep(120)

###################################################################
###                  Trigger Verifications                      ###
###################################################################

class TriggerFabricLinkFlap(nxtest.Testcase):
    """ TriggerFabricLinkFlap - Flap Fabric Facing interfaces """
    
    @aetest.test
    def fabric_link_shut(self, testbed, device_dut, wait_time):
        for node in device_dut:
            link_shut_flag = StimuliInterfaceFlap(node, testbed, converge_sec=int(wait_time))
            log.info('Calling proc fabric_link_shutdown')
            if link_shut_flag.fabric_link_shutdown():
                log.info("Fabric ports shutdown is-SUCCESS")
            else:
                log.error("Fabric ports shutdown-FAILED")
                self.failed()
        # Waiting for 8 min before performing no-shut
        log.info("Waiting for 8 min before performing no-shut")
        time.sleep(500)

    @aetest.test
    def fabric_link_no_shut(self, testbed, device_dut, wait_time):
        for node in device_dut:
            link_shut_flag = StimuliInterfaceFlap(node, testbed, converge_sec=int(wait_time))
            log.info('Calling proc fabric_link_no_shutdown')
            if link_shut_flag.fabric_link_no_shutdown():
                log.info("Fabric ports no-sh is-SUCCESS")
            else:
                log.error("Fabric ports no-sh-FAILED")
                self.failed()
        # Waiting for 8 min before performing no-shut
        log.info("Waiting for 8 min before performing no-shut")
        time.sleep(500)

class TriggerRestartBGPAS(nxtest.Testcase):
    """ TriggerRestartBGPAS - Restart BGP AS CLI """

    @aetest.test
    def restartBGPAS(self, steps, testbed, device_dut):
        
        # Get the BGP AS
        with steps.start("Get BGP AS for devices"):
            bgp_as_cfg = {}
            for node in device_dut:
                # Get router BGP AS number
                bgp_as_data = testbed.devices[node].execute('show run bgp | i i "router bgp"')
                bgp_as_data_processed = re.search('router bgp (\d+)', bgp_as_data, re.I)
                if bgp_as_data_processed:
                    bgp_as = bgp_as_data_processed.groups(0)[0]
                    # Configuration to be added
                    bgp_as_cfg[node] = str(bgp_as)

        # Perform the AS Restart
        with steps.start("Perform Restart of BGP AS"):

            for node in bgp_as_cfg.keys():
                testbed.devices[node].configure('restart bgp '+str(bgp_as_cfg[node]))

        # Wait for convergence
        with steps.start("Post Trigger Sleep"):
            log.info("Waiting for 60 seconds for the BGP AS Restart COnvergence")
            time.sleep(60)


class TriggerShutNoShutBGPAS(nxtest.Testcase):
    """ TriggerShutNoShutBGPAS - Restart BGP AS CLI """

    @aetest.test
    def shutNoShutBGPAS(self, steps, testbed, device_dut):
        
        # Get the BGP AS
        with steps.start("Get BGP AS for devices"):
            bgp_as_cfg = {}
            for node in device_dut:
                # Get router BGP AS number
                bgp_as_data = testbed.devices[node].execute('show run bgp | i i "router bgp"')
                bgp_as_data_processed = re.search('router bgp (\d+)', bgp_as_data, re.I)
                if bgp_as_data_processed:
                    bgp_as = bgp_as_data_processed.groups(0)[0]
                    # Configuration to be added
                    bgp_as_cfg[node] = str(bgp_as)

        # Perform the AS Restart
        with steps.start("Perform Shutdown on router BGP"):
            for node in bgp_as_cfg.keys():
                testbed.devices[node].configure('router bgp '+str(bgp_as_cfg[node]) + ' ; shutdown')
        time.sleep(10)

        with steps.start("Perform no shutdown on router BGP"):
            for node in bgp_as_cfg.keys():
                testbed.devices[node].configure('router bgp '+str(bgp_as_cfg[node]) + ' ; no shutdown')

        # Wait for convergence
        with steps.start("Post Trigger Sleep"):
            log.info("Waiting for 60 seconds for the BGP COnvergence")
            time.sleep(120)

class TriggerKillHMM(nxtest.Testcase):
    """ TriggerKillHMM - Kill HMM Process """
    @aetest.test
    def processHmmKill(self, steps, testbed, device_dut):
        
        # Get the HMM PID and kill the PID
        with steps.start("Get HMM PID"):
            hmmPID = ''
            for node in device_dut:
                # Get HMM Process ID
                hmmPID = testbed.devices[node].execute('show processes cpu sort | grep -i hmm | cut -f 1 -d " "')
                if hmmPID == '':
                    log.info("HMM Process not running")
                    self.failed()
                else:
                    testbed.devices[node].execute('run bash sudo kill -9 ' + str(hmmPID))

        log.info("Waiting for 30 seconds after kill HMM process")
        time.sleep(30)

class TriggerKillNVE(nxtest.Testcase):
    """ TriggerKillNVE - Kill NVE Process """
    @aetest.test
    def processNVEKill(self, steps, testbed, device_dut):
        
        # Get the NVE PID and kill the PID
        with steps.start("Get NVE PID"):
            nvePID = ''
            for node in device_dut:
                # Get NVE Process ID
                nvePID = testbed.devices[node].execute('show processes cpu sort | grep -i NVE | cut -f 1 -d " "')
                if nvePID == '':
                    log.info("NVE Process not running")
                    self.failed()
                else:
                    testbed.devices[node].execute('run bash sudo kill -9 ' + str(nvePID))

        log.info("Waiting for 30 seconds after kill NVE process")
        time.sleep(30)

class ConsistencyChecker(nxtest.Testcase):
    """ ConsistencyChecker """
    @aetest.test
    def consistencyChecker(self, steps, testbed, device_dut):        
        output = ''
        for node in device_dut:
            log.info('Perform CC on VTEP %s', node)
            testbed.devices[node].execute("test consistency-checker forwarding ipv4 vrf all")
            output = testbed.devices[node].execute('show consistency-checker forwarding ipv4 vrf all | sec "^Inconsistent routes:"')
            if re.search('slot(1), vrf(default), prefix(172.30.30.30/32), Route inconsistent in FIB Software', output, re.IGNORECASE):
                log.info("FAIL - The NextHop 172.30.30.30 is flagged as Inconsistent route")
                self.failed()
            else:
                log.info("No Inconsistent Routes found")
                

class ConfigReplace(nxtest.Testcase):
    """ ConfigReplace - Verify Config replace feature """

    @aetest.test
    def config_replace(self, testbed, device_dut):
        for node in device_dut:
            log.info('Remove and readd feature bgp using config replace on %s', node)
            
            cli_to_parse = "show running-config bgp | b version"
            output_before = testbed.devices[node].execute(cli_to_parse)

            testbed.devices[node].execute("delete bootflash:auto_forCR no-prompt")
            testbed.devices[node].configure("copy ru bootflash:auto_forCR")
            log.info('Waiting for 3 seconds before removing the configs')
            time.sleep(3)

            cfg = '''
                  no feature bgp
                  '''
            testbed.devices[node].configure(cfg)
            log.info('Waiting for 60 seconds before re-enabling the configs')
            time.sleep(60)

            cfg = '''
                   configure replace bootflash:auto_forCR verbose verify-and-commit
                  '''
            testbed.devices[node].execute(cfg)
            time.sleep(120)

            cli_to_parse = "show running-config bgp | b version"
            output_after = testbed.devices[node].execute(cli_to_parse)

            if output_before == output_after:
                log.info("BGP Configs are restored properly using config replace")
            else:
                log.info("BGP Configs are NOT restored properly using config replace")
                self.failed()
        
        log.info("Waiting for 90 seconds for protocol Convergence after config changes ")
        time.sleep(90)



class TriggerRemoveAddNewL3VNIUnderVRF(nxtest.Testcase):
    """ TriggerRemoveAddNewL3VNIUnderVRF - Remove and add new CLI L3VNI under VRF """

    @aetest.test
    def remove_add_l3vni_under_vrf(self, testbed, device_dut):
        for node in device_dut:
            log.info('Removing L3 VNI config under VRF v1 on VTEP %s', node)
            
            cli_to_parse = "show running-config vrf v1"
            testbed.devices[node].execute(cli_to_parse)
            testbed.devices[node].execute("delete bootflash:auto_te_cp1 no-prompt")
            testbed.devices[node].configure("checkpoint file bootflash:auto_te_cp1")
            log.info('Waiting for 3 seconds before removing the configs')
            time.sleep(3)

            cfg = '''
                  vrf context v1
                    no vni 300001 l3
                  '''
            testbed.devices[node].configure(cfg)
            log.info('Waiting for 60 seconds before re-enabling the configs')
            time.sleep(60)

            cfg = '''
                   rollback running-config file bootflash:auto_te_cp1 verbose
                  '''
            testbed.devices[node].execute(cfg)
            time.sleep(5)
            # Flap NVE once after reconfiguring the L3 VNI
            cfg = '''
                   interface nve 1 
                   shutdown 
                   sleep 30
                   no shutdown
                  '''
            testbed.devices[node].configure(cfg)
            log.info('Waiting for 30 seconds for convergence after config addition')
            time.sleep(30)
        

class TriggerRemoveAddVNsegmentFeature(nxtest.Testcase):
    """ TriggerRemoveAddVNsegmentFeature - Remove and readd Feature NV overlay and vn segment vlan based """

    @aetest.test
    def remove_add_nvOverlay_and_vnSegmentFeature(self, testbed, device_dut):
        for node in device_dut:
            log.info('Remove and readd Feature NV overlay and vn segment vlan based %s', node)
            
            cli_to_parse = "show running-config nv overlay | b version"
            output_before1 = testbed.devices[node].execute(cli_to_parse)

            cli_to_parse = "show running-config vlan | b version"
            output_before2 = testbed.devices[node].execute(cli_to_parse)

            testbed.devices[node].execute("delete bootflash:auto_te_cp1 no-prompt")
            testbed.devices[node].configure("checkpoint file bootflash:auto_te_cp1")
            log.info('Waiting for 3 seconds before removing the configs')
            time.sleep(3)

            cfg = '''
                  no feature nv overlay
                  no feature vn-segment-vlan-based
                  '''
            testbed.devices[node].configure(cfg)
            log.info('Waiting for 60 seconds before re-enabling the configs')
            time.sleep(60)

            cfg = '''
                   rollback running-config file bootflash:auto_te_cp1 verbose
                  '''
            testbed.devices[node].execute(cfg)
            time.sleep(5)

            cli_to_parse = "show running-config nv overlay | b version"
            output_after1 = testbed.devices[node].execute(cli_to_parse)

            cli_to_parse = "show running-config vlan | b version"
            output_after2 = testbed.devices[node].execute(cli_to_parse)

            if output_before1 == output_after1:
                log.info("NV overylay Configs are restored properly")
            else:
                log.info("NV overlay Configs are NOT restored properly")
                self.failed()

            if output_before2 == output_after2:
                log.info("VN segment Configs are restored properly")
            else:
                log.info("VN segment Configs are NOT restored properly")
                self.failed()
        
        log.info("Waiting for 60 seconds for protocol Convergence after config changes ")
        time.sleep(60)

class TriggerAddEgresLB_no_NVE_Overlay(nxtest.Testcase):
    """ TriggerAddEgresLB_no_NVE_Overlay - Remove feature nv overlay and try to configure egress LB """

    @aetest.test
    def remove_nvOverlay_and_configure_eLB(self, testbed, device_dut):
        for node in device_dut:
            log.info('Remove feature nv overlay and try to configure egress LB %s', node)
            
            cli_to_parse = "show running-config nv overlay"
            testbed.devices[node].execute(cli_to_parse)

            cli_to_parse = "show running-config bgp"
            testbed.devices[node].execute(cli_to_parse)

            testbed.devices[node].execute("delete bootflash:auto_te_noNV_eLB no-prompt")
            testbed.devices[node].configure("checkpoint file bootflash:auto_te_noNV_eLB")
            log.info('Waiting for 3 seconds before removing the configs')
            time.sleep(3)
            fail_flag = []
            fail_flag.append(0)

            cfg = '''
                  router bgp 100 
                    address-family l2vpn evpn 
                  '''
            testbed.devices[node].configure("no feature nv overlay")
            testbed.devices[node].configure("no nv overlay evpn")
            try:
                testbed.devices[node].configure(cfg)
            except:
                log.info("Expected - eLB will not be configurable when nv overlay evpn is not configured")
                fail_flag.append(1)


            log.info('Waiting for 5 seconds before re-enabling configs')
            time.sleep(5)

            cfg = '''
                   rollback running-config file bootflash:auto_te_noNV_eLB verbose
                  '''
            testbed.devices[node].execute(cfg)
        if 0 in fail_flag:
            section.failed()
        else:
            section.passed()

        log.info("Waiting for 90 seconds for protocol Convergence after config changes ")
        # time.sleep(90)


class TriggerRemoveAddNVEinterface(nxtest.Testcase):
    """ TriggerRemoveAddNVEinterface - Remove and readd Feature NVE interface """

    @aetest.test
    def remove_add_nve_interface(self, testbed, device_dut):
        for node in device_dut:
            log.info('Remove and readd NVE interface on %s', node)
            
            cli_to_parse = "show running-config nv overlay | b version"
            output_before = testbed.devices[node].execute(cli_to_parse)

            testbed.devices[node].execute("delete bootflash:auto_te_cp1 no-prompt")
            testbed.devices[node].configure("checkpoint file bootflash:auto_te_cp1")
            log.info('Waiting for 3 seconds before removing the configs')
            time.sleep(3)

            cfg = '''
                  no interface nve 1
                  '''
            testbed.devices[node].configure(cfg)
            log.info('Waiting for 30 seconds before re-enabling the configs')
            time.sleep(30)

            cfg = '''
                   rollback running-config file bootflash:auto_te_cp1 verbose
                  '''
            testbed.devices[node].execute(cfg)
            time.sleep(5)

            cli_to_parse = "show running-config nv overlay | b version"
            output_after = testbed.devices[node].execute(cli_to_parse)

            if output_before == output_after:
                log.info("NVE interface configs restored properly")
            else:
                log.info("NVE interface configs are NOT restored properly")
                self.failed()
        
        log.info("Waiting for 90 seconds for protocol Convergence after config changes ")
        time.sleep(90)



class TriggerRemoveAddNewL3VNIUnderVRF_old(nxtest.Testcase):
    """ TriggerRemoveAddNewL3VNIUnderVRF - Remove and add new CLI L3VNI under VRF """

    @aetest.test
    def remove_add_l3vni_under_vrf(self, testbed, device_dut):
        for node in device_dut:
            vrf_context = None
            vrf_vni_dict = {}
            device = testbed.devices[node]
            log.info("remove_add_l3vni_under_vrf starts on %s", device)
            vrf_dict = ShowVrf(device=device)
            vrf_dict_parse = vrf_dict.parse()

            old_l3vni_vrf   = None
            old_l3vni       = None
            new_l3vni_vrf   = None
            new_l3vni       = None

            for vrf_name in vrf_dict_parse['vrfs'].keys():
                cli_to_parse = "show running-config vrf"
                if re.match(MD_REGEX, vrf_name):
                    log.info("Ignoring %s", vrf_name)
                else:
                    log.info("Starting for vrf %s", vrf_name)
                    cli_to_parse = cli_to_parse + ' ' + vrf_name
                    vrf_out = device.execute(cli_to_parse)
                    for run_vrf in vrf_out.splitlines():
                        line = run_vrf.strip()
                        if 'vrf context' in line:
                            vrf_context = line
                        if 'vni' in line and 'l3' in line:
                            new_l3vni_vrf = vrf_name
                        if 'vni' in line and 'l3' not in line:
                            old_l3vni_vrf = vrf_name
                if new_l3vni_vrf != None and old_l3vni_vrf != None:
                    break
        
            # Delete OLD L3VNI VRF config
            cli_to_parse = "show running-config vrf"
            log.info("Starting for vrf %s", old_l3vni_vrf)
            cli_to_parse = cli_to_parse + ' ' + old_l3vni_vrf
            vrf_out = device.execute(cli_to_parse)
            for run_vrf in vrf_out.splitlines():
                line = run_vrf.strip()
                if 'vrf context' in line:
                    vrf_context = line
                if 'vni' in line and 'l3' not in line:
                    old_l3vni = line.split()[-1]
                    vrf_vni_dict[str(old_l3vni_vrf)] = old_l3vni
                    log.info("Removing L3 Vni--%s for vrf--> %s", old_l3vni, old_l3vni_vrf)
                    old_vni_cmd = "{vrf_context} \n no vni {l3vni}".format(vrf_context=vrf_context, l3vni=old_l3vni)
                    device.configure(old_vni_cmd)
                    log.info("Command executed successfully %s", old_vni_cmd)
                    time.sleep(20)

            # Delete New L3VNI VRF config
            cli_to_parse = "show running-config vrf"
            log.info("Starting for vrf %s", new_l3vni_vrf)
            cli_to_parse = cli_to_parse + ' ' + new_l3vni_vrf
            vrf_out = device.execute(cli_to_parse)
            for run_vrf in vrf_out.splitlines():
                line = run_vrf.strip()
                if 'vrf context' in line:
                    vrf_context = line
                if 'vni' in line and 'l3' in line:
                    new_l3vni = line.split()[-2]
                    vrf_vni_dict[str(new_l3vni_vrf)] = new_l3vni
                    log.info("Removing L3 Vni--%s for vrf--> %s", new_l3vni, new_l3vni_vrf)
                    new_vni_cmd = "{vrf_context} \n no vni {l3vni}".format(vrf_context=vrf_context, l3vni=new_l3vni)
                    device.configure(new_vni_cmd)
                    log.info("Command executed successfully %s", new_vni_cmd)
                    time.sleep(20)
            
            time.sleep(300)

            # Add back the config
            log.info("Adding L3 Vni--%s for vrf--> %s", old_l3vni, old_l3vni_vrf)
            vni_cmd = "vrf context {vrf_cxt} \n vni {l3_vni}".format(vrf_cxt=old_l3vni_vrf, l3_vni=old_l3vni)
            device.configure(vni_cmd)
            log.info("Command executed successfully %s", vni_cmd)
            time.sleep(20)

            # Add back the config
            log.info("Adding L3 Vni--%s for vrf--> %s", new_l3vni, new_l3vni_vrf)
            vni_cmd = "vrf context {vrf_cxt} \n vni {l3_vni} l3".format(vrf_cxt=new_l3vni_vrf, l3_vni=new_l3vni)
            device.configure(vni_cmd)
            log.info("Command executed successfully %s", vni_cmd)
            time.sleep(20)

        time.sleep(500)

class TriggerFabricLinkFlap(nxtest.Testcase):
    @aetest.test
    def fabric_link_shut(self, testbed, device_dut, wait_time):
        for node in device_dut:
            link_shut_flag = StimuliInterfaceFlap(node, testbed, converge_sec=int(wait_time))
            log.info('Calling proc fabric_link_shutdown')
            if link_shut_flag.fabric_link_shutdown():
                log.info("Fabric ports shutdown is-SUCCESS")
            else:
                log.error("Fabric ports shutdown-FAILED")
                self.failed()
        log.info("Waiting "+str(wait_time)+"sec for nve process to catchup...")
        time.sleep(int(wait_time))

    @aetest.test
    def fabric_link_no_shut(self, testbed, device_dut, wait_time):
        for node in device_dut:
            link_shut_flag = StimuliInterfaceFlap(node, testbed, converge_sec=int(wait_time))
            log.info('Calling proc fabric_link_no_shutdown')
            if link_shut_flag.fabric_link_no_shutdown():
                log.info("Fabric ports no-sh is-SUCCESS")
            else:
                log.error("Fabric ports no-sh-FAILED")
                self.failed()
        log.info("Waiting "+str(wait_time)+"sec for nve peers to form and traffic to converge...")
        time.sleep(int(wait_time))

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
        # time.sleep(2 * int(wait_time))
        time.sleep(int(wait_time))

class TriggerMaxPathChange(nxtest.Testcase):
    @aetest.test
    def modify_max_path_autopolicy(self, testbed, device_dut, cli_to_parse, nh1_cli_to_parse, te_route_cli_to_parse3, prefix_count, wait_time):
        # device = testbed.devices[node]
        for node in device_dut:
            log.info('Modifying Max path under autopolicy on VTEP %s', node)
            cli_to_parse = "show running-config rpm"
            nveCfg = testbed.devices[node].execute(cli_to_parse)
        for node in device_dut:
            cfg = '''
                   route-map autoMultiPath permit 10
                   set maximum-paths 2
                  '''
            testbed.devices[node].configure(cfg)
        time.sleep(10)
        output = testbed.devices[node].execute(nh1_cli_to_parse)
        if re.search('172.10.10.10/32, ubest/mbest: 2/0', output, re.IGNORECASE):
            log.info("Maximum paths reduced to 2 from 9")                
        else:
            log.info("Max Paths not reduced to 2")
            self.failed()
        for node in device_dut:
            cfg = '''
                   route-map autoMultiPath permit 10
                   set maximum-paths 9
                  '''
            testbed.devices[node].configure(cfg)
        time.sleep(60)
        output = testbed.devices[node].execute(nh1_cli_to_parse)
        if re.search('172.10.10.10/32, ubest/mbest: 9/0', output, re.IGNORECASE):
            log.info("Maximum paths restored to 9 from 2")                
        else:
            log.info("Max Paths not restored to 9")
            self.failed()
        
        route_count = 0
        route_count = int(testbed.devices[node].execute(te_route_cli_to_parse3))
        if route_count == prefix_count:
            log.info("Routes restored properly")
        else:
            log.info("Not all routes are restored for UECMP")
            self.failed()


class TriggerCreateVrfEgressLoadBalance(nxtest.Testcase):
    @aetest.test
    def modify_vrf_egress_loadbalance(self, testbed, device_dut, cli_to_parse, nh1_cli_to_parse, te_route_cli_to_parse3, prefix_count, wait_time):
        # device = testbed.devices[node]
        for node in device_dut:
            log.info('Try to create vrf egress-loadbalance-resolution- on VTEP %s', node)
            cli_to_parse = "show running-config vrf egress-loadbalance-resolution-"
            testbed.devices[node].execute(cli_to_parse)
        for node in device_dut:
            cfg = '''
                   vrf context egress-loadbalance-resolution-
                  '''
            output = testbed.devices[node].configure(cfg)
        if re.search('ERROR: Configuration of VRF egress-loadbalance-resolution- not allowed', output, re.IGNORECASE):
            log.info("Expected Error thrown: VRF egress-loadbalance-resolution cannot be created or modified by user")                
        else:
            log.info("Fail - VRF egress-loadbalance-resolution- is getting created")
            self.failed()

class TriggerRouterServerLinkFlap(nxtest.Testcase):
    @aetest.test
    def route_server_link_flap(self, testbed, device_dut, cli_to_parse, nh1_cli_to_parse, te_route_cli_to_parse3, prefix_count, route_server_dut, wait_time):
        # device = testbed.devices[node]
        for node in route_server_dut:
            log.info('Performing Route Server Link Flap on VTEP %s', node)
            cli_to_parse = "interface ethernet1/7-8, e1/27-28 ; shutdown"
            testbed.devices[node].configure(cli_to_parse)

        log.info("Waiting for 15 seconds before bringing the link up on route server")
        time.sleep(15)

        for node in route_server_dut:
            log.info('Performing Route Server Link Flap on VTEP %s', node)
            cli_to_parse = "interface ethernet1/7-8, e1/27-28 ; no shutdown"
            testbed.devices[node].configure(cli_to_parse)

        log.info("Waiting for 30 seconds before bringing the link up on route server")
        time.sleep(30)

        for node in device_dut:
            output = testbed.devices[node].execute(nh1_cli_to_parse)
            if re.search('172.10.10.10/32, ubest/mbest: 9/0', output, re.IGNORECASE):
                log.info("Maximum paths restored to 9")                
            else:
                log.info("Max Paths not restored to 9")
                self.failed()
            route_count = 0
            route_count = int(testbed.devices[node].execute(te_route_cli_to_parse3))
            if route_count == prefix_count:
                log.info("Routes restored properly")
            else:
                log.info("Not all routes are restored for UECMP")
                self.failed()

class TriggerDCILinkFlapBGW(nxtest.Testcase):
    @aetest.test
    def dci_link_flap(self, testbed, device_dut, cli_to_parse, nh1_cli_to_parse, te_route_cli_to_parse3, prefix_count, wait_time):
        # device = testbed.devices[node]
        for node in device_dut:
            log.info('Performing DCI Link Flap on VTEP %s', node)
            testbed.devices[node].execute("show nve multisite dci-links")
            cli_to_parse = "interface ethernet1/49/1-4, e1/53/1-4 ; shutdown"
            testbed.devices[node].configure(cli_to_parse)
            cli_to_parse = "interface po501 ; shutdown"
            testbed.devices[node].configure(cli_to_parse)

        log.info("Waiting for 30 seconds before bringing the DCI link up")
        time.sleep(30)

        for node in device_dut:
            cli_to_parse = "interface ethernet1/49/1-4, e1/53/1-4 ; no shutdown"
            testbed.devices[node].configure(cli_to_parse)
            cli_to_parse = "interface po501 ; no shutdown"
            testbed.devices[node].configure(cli_to_parse)

        log.info("Waiting for 30 seconds for protocol convergence")
        time.sleep(30)

        for node in device_dut:
            output = testbed.devices[node].execute(nh1_cli_to_parse)
            if re.search('10.10.20.20/32, ubest/mbest: 9/0', output, re.IGNORECASE):
                log.info("Maximum paths restored to 9")                
            else:
                log.info("Max Paths not restored to 9")
                self.failed()
            route_count = 0
            route_count = int(testbed.devices[node].execute(te_route_cli_to_parse3))
            if route_count == prefix_count:
                log.info("Routes restored properly")
            else:
                log.info("Not all routes are restored for UECMP")
                self.failed()

class TriggerFabricLinkFlapBGW(nxtest.Testcase):
    @aetest.test
    def dci_link_flap(self, testbed, device_dut, cli_to_parse, nh1_cli_to_parse, te_route_cli_to_parse3, prefix_count, wait_time):
        # device = testbed.devices[node]
        for node in device_dut:
            log.info('Performing Fabric Link Flap on VTEP %s', node)
            testbed.devices[node].execute("show nve multisite fabric-links")
            cli_to_parse = "interface ethernet1/50/1 ; shutdown"
            testbed.devices[node].configure(cli_to_parse)

        log.info("Waiting for 30 seconds before bringing the Fabric link up")
        time.sleep(30)

        for node in device_dut:
            cli_to_parse = "interface ethernet1/50/1 ; no shutdown"
            testbed.devices[node].configure(cli_to_parse)

        log.info("Waiting for 30 seconds for protocol convergence")
        time.sleep(30)

        for node in device_dut:
            output = testbed.devices[node].execute(nh1_cli_to_parse)
            if re.search('10.10.20.20/32, ubest/mbest: 9/0', output, re.IGNORECASE):
                log.info("Maximum paths restored to 9")                
            else:
                log.info("Max Paths not restored to 9")
                self.failed()
            route_count = 0
            route_count = int(testbed.devices[node].execute(te_route_cli_to_parse3))
            if route_count == prefix_count:
                log.info("Routes restored properly")
            else:
                log.info("Not all routes are restored for UECMP")
                self.failed()


class TriggerMsiteLoopbackFlapBGW(nxtest.Testcase):
    @aetest.test
    def dci_link_flap(self, testbed, device_dut, cli_to_parse, nh1_cli_to_parse, te_route_cli_to_parse3, prefix_count, wait_time):
        # device = testbed.devices[node]
        for node in device_dut:
            log.info('Performing MSite Loopback 100 Flap on VTEP %s', node)
            testbed.devices[node].execute("show ru interface nve 1")
            cli_to_parse = "interface lo100 ; shutdown"
            testbed.devices[node].configure(cli_to_parse)

        log.info("Waiting for 30 seconds before bringing the Msite Loopback 100 up")
        time.sleep(30)

        for node in device_dut:
            cli_to_parse = "interface lo100 ; no shutdown"
            testbed.devices[node].configure(cli_to_parse)

        log.info("Waiting for 30 seconds for protocol convergence")
        time.sleep(30)

        for node in device_dut:
            output = testbed.devices[node].execute(nh1_cli_to_parse)
            if re.search('10.10.20.20/32, ubest/mbest: 9/0', output, re.IGNORECASE):
                log.info("Maximum paths restored to 9")                
            else:
                log.info("Max Paths not restored to 9")
                self.failed()
            route_count = 0
            route_count = int(testbed.devices[node].execute(te_route_cli_to_parse3))
            if route_count == prefix_count:
                log.info("Routes restored properly")
            else:
                log.info("Not all routes are restored for UECMP")
                self.failed()


class TriggerPeerLinkFlapBGW(nxtest.Testcase):
    @aetest.test
    def peer_link_flap(self, testbed, device_dut):
        # device = testbed.devices[node]
        for node in device_dut:
            log.info('Performing Peer link Flap on VTEP %s', node)
            testbed.devices[node].execute("show ru vpc")
            cli_to_parse = "interface po1 ; shutdown"
            testbed.devices[node].configure(cli_to_parse)

        log.info("Waiting for 10 seconds before bringing the peer link up")
        time.sleep(10)

        for node in device_dut:
            cli_to_parse = "interface po1 ; no shutdown"
            testbed.devices[node].configure(cli_to_parse)

        log.info("Waiting for 30 seconds for protocol convergence")
        time.sleep(30)



class TriggerRemoveReaddNDSuppression(nxtest.Testcase):
    @aetest.test
    def remove_add_NDSupp(self, testbed, device_dut, cli_to_parse, wait_time):
        # device = testbed.devices[node]
        for node in device_dut:
            log.info('Removing suppress nd on VTEP %s', node)
            cli_to_parse = "show running-config interface nve 1"
            nveCfg = testbed.devices[node].execute(cli_to_parse)
            for run_nve in nveCfg.splitlines():
                line = run_nve.strip()
                if 'suppress nd' in line:
                    log.info("Removing suppress nd")
                    cfg = "interface nve 1 ; no suppress nd"
                    testbed.devices[node].configure(cfg)
                    nd_count = testbed.devices[node].execute("show ipv6 nd suppression-cache detail | grep ^2001 | wc -l")
                    time.sleep(10)
                    if nd_count == "0":
                        log.info("ND suppression cache flushed")
                    else:
                        log.info("ND suppression cache not flushed")
                        self.failed()
        for node in device_dut:
            cfg = "interface nve 1 ; suppress nd"
            testbed.devices[node].configure(cfg)
        time.sleep(30)
        nd_count = testbed.devices[node].execute("show ipv6 nd suppression-cache detail | grep ^2001 | wc -l")
        if nd_count == "0":
            log.info("ND suppression cache not restored after suppress nd reconfigured")                
            self.failed()
        else:
            log.info("ND suppression cache restored")
            # log.info('Calling remove_add_NDSupp to remove nd suppression from nve interface for %s', node)
            # time.sleep(20)
    # log.info("Waiting "+str(wait_time)+"sec for nve peers to form...")
    # time.sleep(int(wait_time))
    # log.info("Waiting 2*"+str(wait_time)+"sec before checking traffic...")

class TriggerTEpolicyRemoveReadd(nxtest.Testcase):
    @aetest.test
    def te_policy_remove_readd(self, testbed, device_dut, cli_to_parse, wait_time):
        # device = testbed.devices[node]
        for node in device_dut:
            log.info('Removing TE Policy on VTEP %s', node)
            cli_to_parse = "show running-config bgp"
            nveCfg = testbed.devices[node].execute(cli_to_parse)
            cfg = '''
                  router bgp 100
                    address-family ipv4 unicast
                      no load-balance egress filter-policy route-map filterPolicyTecateNH
                      no load-balance egress multipath auto-policy route-map autoMultiPath
                    address-family l2vpn evpn
                      no nexthop load-balance egress multisite
                  '''
            testbed.devices[node].configure(cfg)
            log.info('Waiting for 30 seconds before re-enabling the configs')
            time.sleep(30)
            cfg = '''
                  router bgp 100
                    address-family ipv4 unicast
                      load-balance egress filter-policy route-map filterPolicyTecateNH
                      load-balance egress multipath auto-policy route-map autoMultiPath
                    address-family l2vpn evpn
                      nexthop load-balance egress multisite
                  '''
            testbed.devices[node].configure(cfg)
        log.info("Waiting for 30 seconds before BGP convergence")
        time.sleep(30)

class TriggerMsiteLoopbackRemoveReadd(nxtest.Testcase):
    @aetest.test
    def msite_loopback_remove_readd(self, testbed, device_dut,vpc_duts, standalone_dut, cli_to_parse, wait_time):
        # device = testbed.devices[node]
        for node in vpc_duts:
            log.info('Removing Multisite Loopback on VTEP %s', node)
            cli_to_parse = "show ru interface nve 1"
            testbed.devices[node].execute(cli_to_parse)
            lo_cli_to_parse = "show ru interface loopback100"
            testbed.devices[node].execute(lo_cli_to_parse)
            cfg = '''
                   no interface loopback 100
                  '''
            testbed.devices[node].configure(cfg)
            log.info('Waiting for 30 seconds before re-enabling the configs')
            time.sleep(30)
            cfg = '''
                  interface loopback 100
                    ip address 172.10.172.20/32
                    ip router ospf 100 area 0.0.0.0
                  '''
            testbed.devices[node].configure(cfg)
        log.info("Waiting for 30 seconds before BGP convergence")
        time.sleep(10)
        for node in standalone_dut:
            log.info('Removing Multisite Loopback on VTEP %s', node)
            cli_to_parse = "show ru interface nve 1"
            testbed.devices[node].execute(cli_to_parse)
            lo_cli_to_parse = "show ru interface loopback100"
            testbed.devices[node].execute(lo_cli_to_parse)
            cfg = '''
                   no interface loopback 100
                  '''
            testbed.devices[node].configure(cfg)
            log.info('Waiting for 30 seconds before re-enabling the configs')
            time.sleep(30)
            cfg = '''
                  interface loopback 100
                    ip address 172.172.30.30/32
                  '''
            testbed.devices[node].configure(cfg)
        log.info("Waiting for 30 seconds before BGP convergence")
        time.sleep(30)


class TriggerNDSupp_MCTFlapPri(nxtest.Testcase):
    @aetest.test
    def ndsupp_MCTFlapPri(self, testbed, device_dut, cli_to_parse, wait_time):
        # device = testbed.devices[node]
        for node in device_dut:
            log.info('Flapping Orphan port on VTEP %s', node)
            cli_to_parse = '''
                           interface po10
                            shutdown
                            sleep 10 
                            no shut
                           '''
            nveCfg = testbed.devices[node].configure(cli_to_parse)
            log.info("Waiting for 60 seconds before checking ND Suppression Cache")
            time.sleep(60)

class TriggerNDSupp_VPCPoFlapPri(nxtest.Testcase):
    @aetest.test
    def ndsupp_VPCPoFlapPri(self, testbed, device_dut, cli_to_parse, wait_time):
        # device = testbed.devices[node]
        for node in device_dut:
            log.info('Flapping Orphan port on VTEP %s', node)
            cli_to_parse = '''
                           interface po100
                            shutdown
                            sleep 10 
                            no shut
                           '''
            nveCfg = testbed.devices[node].configure(cli_to_parse)
            log.info("Waiting for 60 seconds before checking ND Suppression Cache")
            time.sleep(60)


class TriggerNDSupp_OrphanFlapPri(nxtest.Testcase):
    @aetest.test
    def ndsupp_OrphanFlapPri(self, testbed, device_dut, cli_to_parse, wait_time):
        # device = testbed.devices[node]
        for node in device_dut:
            log.info('Flapping Orphan port on VTEP %s', node)
            cli_to_parse = '''
                           interface e1/5
                            shutdown
                            sleep 10 
                            no shut
                           '''
            nveCfg = testbed.devices[node].configure(cli_to_parse)
            log.info("Waiting for 30 seconds before checking ND Suppression Cache")
            time.sleep(30)
            # for run_nve in nveCfg.splitlines():
            #     line = run_nve.strip()
            #     if 'suppress nd' in line:
            #         log.info("Removing suppress nd")
            #         cfg = '''
            #               interface e1/5
            #               shutdown
            #               sleep 10
            #               no shutdown
            #               '''
            #         testbed.devices[node].configure(cfg)
            #         time.sleep(30)
            #         nd_count = testbed.devices[node].execute("show ipv6 nd suppression-cache detail | grep ^2001 | wc -l")
                    # time.sleep(10)
                    # if nd_count == "0":
                    #     log.info("ND suppression cache flushed")
                    # else:
                    #     log.info("ND suppression cache not flushed")
                    #     self.failed()
        # for node in device_dut:
        #     cfg = "interface nve 1 ; suppress nd"
        #     testbed.devices[node].configure(cfg)
        # time.sleep(30)
        # nd_count = testbed.devices[node].execute("show ipv6 nd suppression-cache vlan 1002 | grep ^2001 | wc -l")
        # if nd_count == "300":
        #     log.info("ND suppression cache restored")
        # else:
        #     log.info("ND suppression cache not restored after Orphan Flap")                
        #     self.failed()
    # log.info("Waiting "+str(wait_time)+"sec for nve peers to form...")
    # time.sleep(int(wait_time))
    # log.info("Waiting 2*"+str(wait_time)+"sec before checking traffic...")

class TriggerNDSupp_OrphanFlapSec(nxtest.Testcase):
    @aetest.test
    def ndsupp_OrphanFlapSec(self, testbed, device_dut, cli_to_parse, wait_time):
        # device = testbed.devices[node]
        for node in device_dut:
            log.info('Flapping Orphan port on VTEP %s', node)
            cli_to_parse = '''
                           interface e1/5
                            shutdown
                            sleep 10 
                            no shut
                           '''
            nveCfg = testbed.devices[node].configure(cli_to_parse)
            log.info("Waiting for 30 seconds before checking ND Suppression Cache")
            time.sleep(30)

class TriggerNDSupp_SVI_MultipleV6Addr(nxtest.Testcase):
    @aetest.test
    def add_remove_MultiV6AddressSVI(self, testbed, device_dut, cli_to_parse, wait_time):
        # device = testbed.devices[node]
        # log.info('Add multiple IPv6 address to SVIs in VTEP %s', node)
        log.info('Add multiple IPv6 address to SVIs in VTEP')
        nbrCount = 0
        nbrTotalCount = 0
        nbrCacheCount = 0
        nbrCacheTotalCount = 0
        validationMsg = ''

        for node in device_dut:
            cli_to_parse = "show running-config interface vlan 1001"
            nveCfg = testbed.devices[node].execute(cli_to_parse)
        for node in device_dut:
            cfg = '''
                    interface vlan1001
                    ipv6 address 2101::1/64
                    ipv6 address 2102::1/64
                    ipv6 address 2103::1/64
                  '''
            testbed.devices[node].configure(cfg)
        time.sleep(5)
        for node in device_dut:
            nbrCount = int(testbed.devices[node].execute("show ipv6 neighbor vrf all | grep ^2001 | wc -l"))
            nbrTotalCount += nbrCount
            if node == "node2_s1_vpc_1":
                nbrCacheCount = int(testbed.devices[node].execute("show ipv6 nd suppression-cache detail | grep ^2001 | wc -l"))
                nbrCacheTotalCount += nbrCacheCount
        
        if nbrTotalCount == nbrCacheTotalCount:
            validationMsg = "ND Suppression cache count matches after multiple IPv6 addresses are added"
            log.info(validationMsg)
        else:
            log.info("ND Suppression cache count does not match after multiple IPv6 addresses are added ")
            validationMsg = "Neighor count is " + str(nbrTotalCount) + "ND Supp Cache count is "  + str(nbrCacheTotalCount)
            log.info(validationMsg)
            self.failed()

        log.info('Remove multiple IPv6 address to SVIs in VTEP')
        for node in device_dut:
            cfg = '''
                    interface vlan1001
                    no ipv6 address 2101::1/64
                    no ipv6 address 2102::1/64
                    no ipv6 address 2103::1/64
                  '''
            testbed.devices[node].configure(cfg)
        time.sleep(5)
        for node in device_dut:
            nbrCount = int(testbed.devices[node].execute("show ipv6 neighbor vrf all | grep ^2001 | wc -l"))
            nbrTotalCount += nbrCount
            if node == "node2_s1_vpc_1":
                nbrCacheCount = int(testbed.devices[node].execute("show ipv6 nd suppression-cache detail | grep ^2001 | wc -l"))
                nbrCacheTotalCount += nbrCacheCount
        
        if nbrTotalCount == nbrCacheTotalCount:
            validationMsg = "ND Suppression cache count matches after multiple IPv6 addresses are removed"
            log.info(validationMsg)
        else:
            log.info("ND Suppression cache count does not match after multiple IPv6 addresses are removed ")
            validationMsg = "Neighor count is " + str(nbrTotalCount) + "ND Supp Cache count is "  + str(nbrCacheTotalCount)
            log.info(validationMsg)
            self.failed()


class TriggerNoARPSuppNDSuppression(nxtest.Testcase):
    @aetest.test
    def remove_add_ARPSupp(self, testbed, device_dut, cli_to_parse, wait_time):
        # device = testbed.devices[node]
        for node in device_dut:
            log.info('Removing ARP suppress on VTEP %s', node)
            cli_to_parse = "show running-config interface nve 1"
            nveCfg = testbed.devices[node].execute(cli_to_parse)
            # for run_nve in nveCfg.splitlines():
                # line = run_nve.strip()
            log.info("Removing ARP suppress nd")
            # cfg = "interface nve 1 ;  no global suppress-arp"
            cfg = '''
                        interface nve1
                         no global suppress-arp
                        member vni 2001001-2001005
                            no suppress-arp
                        member vni 2001006-2001010
                            no suppress-arp
                        member vni 2001011-2001015
                            no suppress-arp
                        member vni 2001016-2001020
                            no suppress-arp                
            '''
            testbed.devices[node].configure(cfg)
            time.sleep(10)
            nd_count = testbed.devices[node].execute("show ipv6 nd suppression-cache detail | grep ^2001 | wc -l")
            if nd_count == "0":
                log.info("ARP Suppression removed, ND suppression cache flushed")
            else:
                log.info("ARP Suppression removed, but ND suppression cache not flushed")
                self.failed()
        for node in device_dut:
            cfg = "interface nve 1 ; global suppress-arp"
            testbed.devices[node].configure(cfg)
        time.sleep(30)
        nd_count = testbed.devices[node].execute("show ipv6 nd suppression-cache detail | grep ^2001 | wc -l")
        if nd_count == "0":
            log.info("ND suppression cache not restored after global suppress-arp reconfigured")                
            self.failed()
        else:
            log.info("ND suppression cache restored after global suppress-arp reconfigured")
            # log.info('Calling remove_add_NDSupp to remove nd suppression from nve interface for %s', node)
            # time.sleep(20)
    # log.info("Waiting "+str(wait_time)+"sec for nve peers to form...")
    # time.sleep(int(wait_time))
    # log.info("Waiting 2*"+str(wait_time)+"sec before checking traffic...")

class TriggerVPCPriRemSuppND(nxtest.Testcase):
    @aetest.test
    def remove_ndsupp_vpcPri(self, testbed, device_dut, cli_to_parse, wait_time, vpc_pri, vpc_sec):
        # device = testbed.devices[node]
        for node in device_dut:
            log.info('Removing ND suppression on VPC Pri %s', node)
            log.info("Removing ND suppression on VPC Pri")
            cfg = "interface nve 1 ;  no suppress nd"
            testbed.devices[node].configure(cfg)
            time.sleep(10)
            nd_count = testbed.devices[node].execute("show ipv6 nd suppression-cache detail | grep ^2001 | wc -l")
            if nd_count == "0":
                log.info("ND Suppression removed in VPC Pri, ND suppression cache flushed")
            else:
                log.info("ND Suppression removed in VPC Pri, but ND suppression cache not flushed")
                self.failed()
        time.sleep(60)
        for secNode in vpc_sec:
                vpcSecNdSuppStatus = testbed.devices[secNode].execute('show vpc | grep "Configuration inconsistency reason"')
        if vpcSecNdSuppStatus == "NVE suppress nd cmd does not match":
            log.info("VPC Secondary Down as ND Suppression is removed in VPC Primary")
        else:
            log.info("ND Suppression config mismatch between VPC Pri and Sec, VPC Not down")
            self.failed()
        for node in device_dut:
            cfg = "interface nve 1 ; suppress nd"
            testbed.devices[node].configure(cfg)
        time.sleep(60)
        for priNode in vpc_pri:
            vpc_pri_nd_count = testbed.devices[priNode].execute("show ipv6 nd suppression-cache detail | grep ^2001 | wc -l")
        for secNode in vpc_sec:
            vpc_sec_nd_count = testbed.devices[secNode].execute("show ipv6 nd suppression-cache detail | grep ^2001 | wc -l")
        if vpc_pri_nd_count == "201" and vpc_sec_nd_count == "201":
            log.info("ND suppression cache restored after reconfiguring Supress ND")
        else:
            log.info("ND suppression cache not restored after reconfiguring Suppress ND on Primary")                
            self.failed()

            # log.info('Calling remove_add_NDSupp to remove nd suppression from nve interface for %s', node)
            # time.sleep(20)
    # log.info("Waiting "+str(wait_time)+"sec for nve peers to form...")
    # time.sleep(int(wait_time))
    # log.info("Waiting 2*"+str(wait_time)+"sec before checking traffic...")

# class TriggerHostMoveSuppND(nxtest.Testcase):

class NDIssu_StandAloneBGW(nxtest.Testcase):
    # @aetest.test
    # def CHECK_ISSU_IMPACT(self, testbed, device_dut, target_image):
    #     """ CHECK ISSU IMPACT """

    #     # Prepare the ISSU Impact Check command
    #     tImage = target_image
    #     for node in device_dut:
    #         issu_impact_cmd = 'show install all impact nxos bootflash:'+str(tImage)+' non-disruptive'
    #         # Execute the ISSU Impact command
    #         impact_output = testbed.devices[node].execute(issu_impact_cmd, timeout=1200)
    #         output_split = list(filter(None, impact_output.split('\n')))
    #         fail_flag = []
    #         fail_logs = '\n'

    #     # Process logs for any failure reasons
    #     for log_line in output_split:
    #         if re.search('CRASHED|fail|CPU Hog|malloc|core dump|mts_send|redzone|error', log_line, re.I):
    #             fail_flag.append(0)
    #             fail_logs += str(log_line) + '\n'
    #         if re.search('\\d+\\s+yes\\s+(\\S+)\\s+reset', log_line, re.I):
    #             if not re.search('\\d+\\s+yes\\s+(non-disruptive)\\s+reset', log_line, re.I):
    #                 fail_flag.append(0)
    #                 fail_logs += 'The ISSU Impact is reporting Disruptive, Please check\n'
    @aetest.test
    def LEAF_VERIFY_ISSU(self, testbed, device_dut,target_image):
        """ VERIFY_ISSU """

        # Establish dialogs for running ISSU command
        dialog = Dialog([
            Statement(pattern=r'Do you want to continue with the installation \(y/n\)\?',
                      action='sendline(y)',
                      loop_continue=True,
                      continue_timer=True),
        ])

        # Create ISSU command
        issu_cmd = 'install all nxos bootflash:'+str(target_image)+' non-disruptive'

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




class TriggerSSO(nxtest.Testcase):
    """ TriggerSSO - Perform SSO """
    @aetest.test
    def perform_copy_r_s(self, testbed, device_dut):

        for node in device_dut:
            testbed.devices[node].configure("copy r s", timeout=600)

    @aetest.test
    def perform_SSO(self, testbed, device_dut):

        for node in device_dut:

            # Perform Device Reload
            result = infraEORTrigger.verifyDeviceSSO({'dut':testbed.devices[node]})
            if result:
                log.info("SSO completed Successfully")
            else:
                log.debug("SSO Failed")
                self.failed("SSO Failed", goto=['cleanup'])

            log.info("Waiting for 120 sec for the topology to come UP")
            time.sleep(500)

class CommonCleanUp(nxtest.Testcase):
    @aetest.test
    def common_CleanUp(self, testbed, clean_dut_list,cli_to_parse):
        """ Clean the configs and revert to default configs """

        log.info("Entered Clean the configs and revert to default configs ##### ##### ##### ")
        # cli_to_parse = kwargs.get('cli_to_parse', 1)

        for node in clean_dut_list:
            log.info('Removing TE Policy on VTEP %s', node)
            testbed.devices[node].configure(cli_to_parse)
            log.info('Configurations are removed Successfully')
            # time.sleep(5)

class VersionSample(nxtest.Testcase):
    """ Common Setup """
    @aetest.test
    # # def VersionSample(self, testbed, device_dut, cli_to_parse, wait_time):
    def VersionSample(self, testbed, device_dut):
        """ common setup subsection: Initializing Genie Testbed """
        # for node in testscript.parameters['device_list']:
        log.info("### In VersionSample ### ")
        for node in device_dut:
            version_obj = ShowVersion(device=node)
            log.info(version_obj)
