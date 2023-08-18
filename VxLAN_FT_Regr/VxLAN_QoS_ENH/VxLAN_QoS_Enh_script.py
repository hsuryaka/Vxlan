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
from pyats.utils.secret_strings import to_plaintext, SecretString

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
#from VxLAN_PYlib.ixia_RestAPIlib import *

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

class TC_1(nxtest.Testcase):
    @aetest.test
    def match_default_vxlan_dscp_policy(self, testbed, testscript, device_dut):
        status_flag= []
        status_msgs= '\n'
        for node in device_dut:
            output=testbed.devices[node].execute("show run all | i tnl-dscp-policy")
            if "policy-map type qos default-vxlan-in-tnl-dscp-policy" in output:
                status_msgs += str(testbed.devices[node].alias)+' : Pass : Default tunnel dscp policy found \n'
            else:
                status_msgs += str(testbed.devices[node].alias)+' : Fail : Default tunnel dscp policy not found \n'
                status_flag.append(0)

        if 0 in status_flag:
            self.failed(reason=status_msgs)
        else:
            self.passed(reason=status_msgs)

class TC_2(nxtest.Testcase):
    @aetest.test
    def check_xml(self, testbed, testscript, device_dut):
        status_flag= []
        status_msgs= '\n'
        for node in device_dut:
            output=testbed.devices[node].execute("sh policy-map interface nve 1 type qos | xml | i set_match_dscp")
            if "<cmap-key>set_match_dscp</cmap-key>" in output:
                status_msgs += str(testbed.devices[node].alias)+' : Pass : XML PASS \n'
            else:
                status_msgs += str(testbed.devices[node].alias)+' : Fail : XML FAIL \n'
                status_flag.append(0)

        if 0 in status_flag:
            self.failed(reason=status_msgs)
        else:
            self.passed(reason=status_msgs) 

class TC_3(nxtest.Testcase):
    @aetest.test
    def check_json(self, testbed, testscript, device_dut):
        status_flag= []
        status_msgs= '\n'
        for node in device_dut:
            output=testbed.devices[node].execute("sh policy-map interface nve 1 type qos | json")
            if "set_match_dscp" in output:
                status_msgs += str(testbed.devices[node].alias)+' : Pass : XML PASS \n'
            else:
                status_msgs += str(testbed.devices[node].alias)+' : Fail : XML FAIL \n'
                status_flag.append(0)

        if 0 in status_flag:
            self.failed(reason=status_msgs)
        else:
            self.passed(reason=status_msgs) 

class TC_4(nxtest.Testcase):
    @aetest.test
    def check_egress_TC(self, testbed, testscript, device_dut):
        status_flag= []
        status_msgs= '\n'
        for node in device_dut:
            output=testbed.devices[node].execute("ethanalyzer local interface inband-in limit-captured-frames 1 detail | i Traffic")
            if "DSCP: AF33" in output:
                status_msgs += str(testbed.devices[node].alias)+' : Pass : TC retained PASS \n'
            else:
                status_msgs += str(testbed.devices[node].alias)+' : Fail :  FAIL \n'
                status_flag.append(0)

        if 0 in status_flag:
            self.failed(reason=status_msgs)
        else:
            self.passed(reason=status_msgs)

class TC_5(nxtest.Testcase):
    @aetest.test
    def check_ingress_TC(self, testbed, testscript, device_dut):
        status_flag= []
        status_msgs= '\n'
        for node in device_dut:
            output=testbed.devices[node].execute("ethanalyzer local interface inband-in limit-captured-frames 1 detail | i Traffic")
            if "DSCP: AF21" in output:
                status_msgs += str(testbed.devices[node].alias)+' : Pass : TC retained PASS \n'
            else:
                status_msgs += str(testbed.devices[node].alias)+' : Fail :  FAIL \n'
                status_flag.append(0)

        if 0 in status_flag:
            self.failed(reason=status_msgs)
        else:
            self.passed(reason=status_msgs)

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
    
    log.info(TrafficItemTable.draw())
    
    if 0 in fail_flag:
        section.failed("Traffic verification failed")
    else:
        section.passed("Traffic verification Passed")

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
                    if str(vrf['vrf_name']) != 'default' and str(vrf['vrf_name']) != 'management' \
                        and str(vrf['vrf_name']) != 'peer-keep-alive' and str(vrf['vrf_name']) != 'NBM-1':
                        re_pr = re.search('(VRF-)(\d+)',vrf['vrf_name'])
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

class SampleTest(nxtest.Testcase):
    """ Common Setup """

    @aetest.test
    def SampleTest_1(self, testscript, testbed, steps):
        """ common setup subsection: Initializing Genie Testbed """

        log.info("Just a sample")

#-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-
#                   Traffic Generator Configuration                #
#-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*- 

class Configure_IXIA_Global(nxtest.Testcase):

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
            ses = testscript.parameters['session'] = session = SessionAssistant(IpAddress=ixia_tcl_server, UserName='admin', Password='admin', ClearConfig=True, LogLevel='all', LogFilename='restpy.log')
            testscript.parameters['ixNetwork'] = ixNetwork = testscript.parameters['session'].Ixnetwork

            #######Load a saved config file
            ixNetwork.info('Loading config file: {0}'.format(tgen_cfg_file))
            ixNetwork.LoadConfig(Files(tgen_cfg_file, local_file=True))

            # Assign ports. Map physical ports to the configured vports.
            portMap = testscript.parameters['session'].PortMapAssistant()
            log.info(ses)
            log.info(portMap)
            vport = dict()
            for index,port in enumerate(ixia_int_list):
                # For the port name, get the loaded configuration's port name
                portName = ixNetwork.Vport.find()[index].Name
                portMap.Map(IpAddress=port[0], CardId=port[1], PortId=port[2], Name=portName)
            portMap.Connect(forceTakePortOwnership)

        # with steps.start("Verify Steady State"):

        #     if validateSteadystateTraffic(testscript):
        #         self.passed()
        #     else:
        #         self.failed()

# ========================================================================================================================================================
# ===================================================================================================================================
# ========================================================================================================================================================
class ForkedPdb(pdb.Pdb):
    '''A Pdb subclass that may be used
    from a forked multiprocessing child1
    '''
    def interaction(self, *args, **kwargs):
        _stdin = sys.stdin
        try:
            sys.stdin = open('/dev/stdin')
            pdb.Pdb.interaction(self, *args, **kwargs)
        finally:
            sys.stdin = _stdin
#class jasim_test(nxtest.Testcase):
    # qinvni_dut_dict = {
    #             'node02_vpcVtep1' : {
    #                     'interface'     : ['nd02_tgen_1_1', 'po100'], 
    #                     'global_cfgs'   : 'system dot1q-tunnel transit 1001-1008',
    #                     'intf_configs'       : 'switchport ; switchport mode dot1q-tunnel ; \
    #                                         switchport access vlan 1001 ; \
    #                                         no shut'
    #                     },
    #             'node03_vpcVtep2' : {
    #                     'interface'     : ['nd03_tgen_1_1', 'po100'], 
    #                     'global_cfgs'   : 'system dot1q-tunnel transit 1001-1008',
    #                     'intf_configs'       : 'switchport ; switchport mode dot1q-tunnel ; \
    #                                         switchport access vlan 1001 ; \
    #                                         no shut'
    #                     },
    #             'node04_stdVtep3' : {
    #                     'interface'     : ['nd04_tgen_1_1'], 
    #                     'global_cfgs'   : 'system dot1q-tunnel transit 1001-1008',
    #                     'intf_configs'       : 'switchport ; switchport mode dot1q-tunnel ; \
    #                                         switchport access vlan 1001 ; \
    #                                         no shut'
    #                     }
    #             }

    # qinq_qinvni_dut_dict = {
    #             'node02_vpcVtep1' : {
    #                     'interface'     : ['nd02_tgen_1_1', 'po100'], 
    #                     'global_cfgs'   : 'system dot1q-tunnel transit 1001-1008',
    #                     'intf_configs'       : 'switchport ; switchport mode trunk ; \
    #                                         swithport trunk native-vlan 20 ; \
    #                                         switchport trunk allowed-vlan 1001-1008 ; \
    #                                         switchprot trunk allow-multi-tag ; \
    #                                         no shut'
    #                     },
    #             'node03_vpcVtep2' : {
    #                     'interface'     : ['nd03_tgen_1_1', 'po100'], 
    #                     'global_cfgs'   : 'system dot1q-tunnel transit 1001-1008',
    #                     'intf_configs'       : 'switchport ; switchport mode trunk ; \
    #                                         swithport trunk native-vlan 20 ; \
    #                                         switchport trunk allowed-vlan 1001-1008 ; \
    #                                         switchprot trunk allow-multi-tag ; \
    #                                         no shut'
    #                     },
    #             'node04_stdVtep3' : {
    #                     'interface'     : ['nd04_tgen_1_1'], 
    #                     'global_cfgs'   : 'system dot1q-tunnel transit 1001-1008',
    #                     'intf_configs'       : 'switchport ; switchport mode trunk ; \
    #                                         swithport trunk native-vlan 20 ; \
    #                                         switchport trunk allowed-vlan 1001-1008 ; \
    #                                         switchprot trunk allow-multi-tag ; \
    #                                         no shut'
    #                     }
    #             }
    
    qinvni_dut_dict = kwargs.get('qinvni_dut_dict', 1)
    log.info(qinvni_dut_dict)

    for dut in qinvni_dut_dict.keys():
        
        # Get the details from the dict passed
        interfaceList = qinvni_dut_dict[dut]['interfaces']
        globalCfgs = qinvni_dut_dict[dut]['global_cfgs']
        interfaceCfgs = qinvni_dut_dict[dut]['intf_configs']

        # This is to apply the gloabl configs on the device
        if globalCfgs != '':
            section.parameters['testbed'].devices[dut].configure(globalCfgs)

        # This is to apply the qinvni configs per interface level
        for interface in interfaceList:
            if re.search('po',interface,re.I):
                for cfg in interfaceCfgs:
                    section.parameters['testbed'].devices[dut].configure('interface {0} ; {1}'.format(interface,cfg))
            else:
                # Need to get interface name from TB yaml file and then perform configs
                pass
        
class SampleTest(nxtest.Testcase):
    """ Common Setup """

    @aetest.test
    def SampleTest_1(self, testscript, testbed, steps):
        """ common setup subsection: Initializing Genie Testbed """

        for node in testscript.parameters['device_list']:
            version_obj = ShowVersion(device=node)
            log.info(version_obj)

    @aetest.test
    def SampleTest_2(self, testscript, testbed, steps):
        """ common setup subsection: Initializing Genie Testbed """

        for node in testscript.parameters['device_list']:
            node.execute("show ver in bu")

    @aetest.test
    def SampleTest_3(self, testscript, testbed, steps):
        """ common setup subsection: Initializing Genie Testbed """

        log.info(testscript.parameters['node_list'].keys())
        for node in testscript.parameters['node_list']:
            log.info(node)