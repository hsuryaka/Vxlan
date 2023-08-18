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

class TriggerRemoveAddNewL3VNIUnderVRF(nxtest.Testcase):
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
        time.sleep(2 * int(wait_time))

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

class SampleTest(nxtest.Testcase):
    """ Common Setup """

    @aetest.test
    def SampleTest_1(self, testscript, testbed, steps):
        """ common setup subsection: Initializing Genie Testbed """

        log.info("Just a sample")