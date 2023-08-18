#!/usr/bin/env python

# Author information
__author__ = 'Nexus India VxLAN DevTest Group'
__copyright__ = 'Copyright (c) 2021, Cisco Systems Inc.'
__contact__ = ['group.jdasgupt@cisco.com']
__credits__ = ['hsuryaka']
__version__ = 1.0

###################################################################
###                  Importing Libraries                        ###
###################################################################
import pdb
class ForkedPdb(pdb.Pdb):
    '''A Pdb subclass that may be used
    from a forked multiprocessing child
    '''
    def interaction(self, *args, **kwargs):
        _stdin = sys.stdin
        try:
            sys.stdin = open('/dev/stdin')
            pdb.Pdb.interaction(self, *args, **kwargs)
        finally:
            sys.stdin = _stdin

# ------------------------------------------------------
# Import generic python libraries
# ------------------------------------------------------
from distutils.log import Log
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
# from tkinter import dialog
from unicon import Connection
import unicon.statemachine.statemachine
from unicon.eal.dialogs import Statement, Dialog
from genie.libs.parser.nxos.show_vpc import ShowVpc
from genie.libs.parser.nxos.show_vxlan import ShowNveMultisiteFabricLinks, ShowNveInterfaceDetail, \
    ShowNveMultisiteDciLinks
from genie.libs.parser.nxos.show_platform import ShowModule
from genie.libs.parser.nxos.show_interface import ShowInterfaceStatus
from genie.libs.parser.nxos.show_ospf import ShowIpOspfNeighborDetail
from lib.utils.nve_utils import get_nve_interface, modify_nve_loopback, revert_nve_loopback
from lib.utils.string_utils import str_to_expanded_list
from lib.utils.vxlan_utils import get_vtep_nhop_list
from lib.utils.intf_utils import get_req_intf_from_device
from lib.stimuli.stimuli_vrf_lib import StimuliFlapVrfs
from unicon import Connection

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
LOG = logging.getLogger()
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
# import ixiaPyats_absr_lib
# ixLib = ixiaPyats_absr_lib.ixiaPyats_lib()
from ixnetwork_restpy import *

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
from lib.utils.config_utils import get_running_config
from lib.utils.intf_utils import increment_ipv4_address
from lib.stimuli.stimuli_port_lib import StimuliPortFlap, StimuliInterfaceFlap, StimuliFabricAndDCIFlap

# Metaparser
from genie.metaparser import MetaParser
from genie.metaparser.util.schemaengine import Schema, Any, Optional

# parser utils
from genie.libs.parser.utils.common import Common
from lib.verify.verify_parser_output import verify_parser_output


# Testing cnfigure pki

import logging
import time
import os
import paramiko
import contextlib
import json
import stat
import operator

from genie.libs.parser.nxos.show_vxlan import ShowNveInterfaceDetail
from genie.libs.sdk.apis.execute import execute_copy_run_to_start
from pyats.utils.secret_strings import to_plaintext
from scp import SCPClient
from pyats import aetest
from lib import nxtest
from unicon.eal.dialogs import Statement, Dialog

from lib.verify.verify_parser_output import verify_parser_output
from lib.utils.find_path import get_full_with_script_path
# from lib.verify.verify_tunnel_encryption import ShowTunnelEncryptionSession

###################################################################
###                  User Library Methods                       ###
###################################################################
# verify tunnel-encryption session
def verify_Peer_Ip(testbed,device_dut):
    for node in device_dut:
        output = json.loads(testbed.devices[node].execute('sh tunnel-encryption session | json'))
        item = output["TABLE_tem_session"]["ROW_tem_session"]
        for i in enumerate(item):
            peerip = item['PeerAddr']
            if re.match('.*^\d.\d\d.\d\d.\d\d', peerip):
                log.info(peerip)
                return True
            else:
                return False

def Verify_TunnelRXstatus(section,testbed):
    node=["node3_s1_bgw_1", "node4_s1_bgw_2"]
    i=0
    for i in range(len(node)):
        output1 = json.loads(testbed.devices[node[i]].execute('sh tunnel-encryption session | json'))
        log.info(output1)
        if(output1 == ''):
            section.failed(reason='No tunnel-encryption session')
        a = json.loads(testbed.devices[node[i]].execute('sh tunnel-encryption session | json'))
        item = a["TABLE_tem_session"]["ROW_tem_session"]
        for i in range(len(item)):
            str(item)
            RxStatus = item['RxStatus']
            if not re.search('Secure\s\(AN:\s\d\)', RxStatus):
                log.info('The tunnel session {0} is not secure. state is {1}'.format(ns.PeerAddr,RxStatus))
                section.failed(reason="status is not secure")
    output2 = json.loads(testbed.devices['node7_s2_bgw_1'].execute('sh tunnel-encryption session | json'))
    log.info(output2)
    if(output2 == ''):
        section.failed(reason='No tunnel-encryption session')
    a = json.loads(testbed.devices['node7_s2_bgw_1'].execute('sh tunnel-encryption session | json'))
    item = a["TABLE_tem_session"]["ROW_tem_session"]
    for i in range(len(item)):
        str(item)
        RxStatus = item[i]['RxStatus']
        if not re.search('Secure\s\(AN:\s\d\)', RxStatus):
            log.info('The tunnel session {0} is not secure. state is {1}'.format(ns.PeerAddr,RxStatus))
            section.failed(reason="status is not secure")

def Verify_TunnelTXstatus(section,testbed):
        node=["node3_s1_bgw_1", "node4_s1_bgw_2"]
        i=0
        for i in range(len(node)):
            output1 = json.loads(testbed.devices[node[i]].execute('sh tunnel-encryption session | json'))
            log.info(output1)
            if(output1 == ''):
                section.failed(reason='No tunnel-encryption session')
            a = json.loads(testbed.devices[node[i]].execute('sh tunnel-encryption session | json'))
            item = a["TABLE_tem_session"]["ROW_tem_session"]
            for i in range(len(item)):
                str(item)
                TxStatus = item['TxStatus']
                if not re.search('Secure\s\(AN:\s\d\)', TxStatus):
                    log.info('The tunnel session is not secured')
                    section.failed(reason="status is not secure") 
        output2 = json.loads(testbed.devices['node7_s2_bgw_1'].execute('sh tunnel-encryption session | json'))
        log.info(output2)
        if(output2 == ''):
            section.failed(reason='No tunnel-encryption session')
        a = json.loads(testbed.devices['node7_s2_bgw_1'].execute('sh tunnel-encryption session | json'))
        item = a["TABLE_tem_session"]["ROW_tem_session"]
        for i in range(len(item)):
            str(item)
            TxStatus = item[i]['TxStatus']
            if not re.search('Secure\s\(AN:\s\d\)', TxStatus):
                log.info('The tunnel session is not secure.')
                section.failed(reason="status is not secure")

def verify_RxStatus(testbed,device_dut):
    for node in device_dut:
        output1 = json.loads(testbed.devices[node].execute('sh tunnel-encryption session | json'))
        log.info(output1)
        if(output1 == ''):
            return False
        a = json.loads(testbed.devices[node].execute('sh tunnel-encryption session | json'))
        item = a["TABLE_tem_session"]["ROW_tem_session"]
        for i in range(len(item)):
            RxStatus = item['RxStatus']
            if not re.search('Secure\s\(AN:\s\d\)', RxStatus):
                log.info('The tunnel session {0} is not secure. state is {1}'.format(ns.PeerAddr,RxStatus))
                return False

def verify_RxStatusS2(testbed,device_dut):
    for node in device_dut:
        output1 = json.loads(testbed.devices[node].execute('sh tunnel-encryption session | json'))
        log.info(output1)
        if(output1 == ''):
            return False
        a = json.loads(testbed.devices[node].execute('sh tunnel-encryption session | json'))
        item = a["TABLE_tem_session"]["ROW_tem_session"]
        for i in range(len(item)):
            RxStatus = item[i]['RxStatus']
            if not re.search('Secure\s\(AN:\s\d\)', RxStatus):
                log.info('The tunnel session {0} is not secure. state is {1}'.format(ns.PeerAddr,RxStatus))
                return False

   
def verify_Txstatus(testbed,device_dut):
    for node in device_dut:
        output1 = json.loads(testbed.devices[node].execute('sh tunnel-encryption session | json'))
        log.info(output1)
        if(output1 == ''):
            return False
        a = json.loads(testbed.devices[node].execute('sh tunnel-encryption session | json'))
        item = a["TABLE_tem_session"]["ROW_tem_session"]
        for i in range(len(item)):
            TxStatus = item['TxStatus']
            if not re.search('Secure\s\(AN:\s\d\)', TxStatus):
                log.info('The tunnel session {0} is not secure. state is {1}'.format(ns.PeerAddr,TxStatus))
                return False

def verify_TxstatusS2(testbed,device_dut):
    for node in device_dut:
        output1 = json.loads(testbed.devices[node].execute('sh tunnel-encryption session | json'))
        log.info(output1)
        if(output1 == ''):
            return False
        a = json.loads(testbed.devices[node].execute('sh tunnel-encryption session | json'))
        item = a["TABLE_tem_session"]["ROW_tem_session"]
        for i in range(len(item)):
            TxStatus = item[i]['TxStatus']
            if not re.search('Secure\s\(AN:\s\d\)', TxStatus):
                log.info('The tunnel session {0} is not secure. state is {1}'.format(ns.PeerAddr,TxStatus))
                return False

#verify tunnel-encryption statistics
def verify_dycerypted(self,testbed,device_dut):
    for node in device_dut:
        output1 = json.loads(testbed.devices[node].execute('sh tunnel-encryption session | json'))
        item1 = output1["TABLE_tem_session"]["ROW_tem_session"]
        i=0
        for i in range(len(item1)):
            Rxstatus = item1['RxStatus']
            ANnum=re.findall('\d',Rxstatus)
            ANno = (int("".join(map(str,ANnum))))
            log.info(ANno)
        output2 = json.loads(testbed.devices[node].execute('sh tunnel-encryption statistics | json'))
        item2 = output2["TABLE_statistics"]["ROW_statistics"]
        for i in range(len(item2)):
            TBwAN = item2["TABLE_rx_sa_an"]
            RowAn = TBwAN["ROW_tx_sa_an"]
            AN = TBwAN["rx_sa_an"]
            for i in range (len(RowAn)):
                if AN==ANno:
                    decrypt=RowAn["in_pkts_decrypted"]
                    log.info(decrypt)
                else:
                    self.failed()


def verify_encerypted(testbed,device_dut):
    for node in device_dut:
        output = json.loads(testbed.devices[node].execute('sh tunnel-encryption statistics | json'))
        item = output["TABLE_statistics"]["ROW_statistics"]
        for i in range(len(item)):
            Peerip = item["PeerAddr"]
            if re.match('.*^\d.\d\d.\d\d.\d\d', Peerip):
                log.info(Peerip)
                RowAN = item["TABLE_tx_sa_an"]
                AN = RowAN["ROW_tx_sa_an"]
                n=0
                for n in range (len(AN)):
                    encrypt=AN["out_pkts_encrypted_protected"]
                    if (encrypt != 0):
                        log.info(encrypt)
                        return True
                    else:
                        n=n+1

def modify_PKIsrc_loopback(device: Device, device_dut, converge_time, new_loopback):
    for node in device_dut:
        cmd = '''sh run tunnel-encryption'''
        output=device.configure(cmd)  
        tunnel_lo= re.findall('loopback0', output)
        tun_lo = tunnel_lo[0]
        log.info(tun_lo)
        obj=cmd = ''' sh interface ''' + str(tun_lo)
        device.execute(cmd)
        lo_intf = obj.parse(interface='loopback 0')
        lo_config = get_running_config(node, interface=tun_lo)
        lo_ip_addr = tun_lo['loopback0'].get('ip_address')
        new_loopconfig = lo_config
        primary_ip = increment_ipv4_address(lo_ip_addr, '1.1.1.0')
        if re.search(r'interface (lo(opback)?\d+)', new_loopconfig, re.I).group(1):
            new_loopconfig = re.sub(tun_lo, new_loopback, new_loopconfig)
        if re.search(r'ip address ([0-255\.]+)', new_loopconfig, re.I).group(1):
            new_loopconfig = re.sub(lo_ip_addr, primary_ip, new_loopconfig)
        device.configure(new_loopconfig)
        time.sleep(converge_time)
        cmd = '''no tunnel-encryption source-interface {0} \n tunnel-encryption source-interface {1}'''.format(tun_lo,
                                                                                                new_loopback)
        device.configure(cmd)
        time.sleep(converge_time)

class RemoveAddPKITunnelNvePeerIP(nxtest.Testcase):
    @aetest.test
    def remove_add_tunnel_peer_ip(self, testbed, device_dut, trigger_wait_time, convergence_wait_time ):
        from lib.utils.vxlan_utils import get_tunnel_params, verify_tunnel_sessions
        for node in device_dut:
            device = testbed.devices[node]
            tunnel_session_out = []
            tunnel_out = get_tunnel_params(device)
            if not tunnel_out:
                LOG.error("tunnel output is empty.check tunnel sessions and show json-pretty output")
                self.failed()
            if type(tunnel_out) is dict:
                tunnel_session_out.append(tunnel_out)
            if type(tunnel_out) is list:
                tunnel_session_out = tunnel_out
            if tunnel_session_out:
                for tunnel_params in tunnel_session_out:
                    device.configure("no tunnel-encryption peer-ip {0}".format(tunnel_params['PeerAddr']))
                    time.sleep(trigger_wait_time)
                    tunnel_encryption_cmd = "tunnel-encryption peer-ip {0} \n pki policy {1}".format(tunnel_params['PeerAddr'], tunnel_params['PolicyName'])
                    device.configure(tunnel_encryption_cmd)
                    # device.configure("tunnel-encryption peer-ip {0}".format(tunnel_params['PeerAddr']))
                    # device.configure("keychain {0} policy {1}".format(tunnel_params['KCName'], tunnel_params['PolicyName']))
                    time.sleep(trigger_wait_time)
                    tunnel_session = verify_tunnel_sessions(device,tunnel_params['PeerAddr'] )
                    if tunnel_session:
                        LOG.error("tunnel session is in pending state for peer {0}".format(tunnel_params['PeerAddr']))
                        self.failed()
            else:
                LOG.error("tunnel output is empty.check tunnel sessions and show json-pretty output")
                self.failed()

        time.sleep(convergence_wait_time )
         


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

class verify_tunnel_encryption_session(nxtest.Testcase):
    @aetest.test
    def Verify_TunnelRXstatus(self,testbed,device_dut):
        try:
            if verify_RxStatus(testbed,device_dut):
                log.info(' verified RxStatus status is secure')   
            else:
                log.info('VErification Rxstatus is failed')
                self.failed('Failed to verify')
        except Exception as error:
            log.debug("unable verify tunnel-encryption sestion "+ str(error))
            self.errored('Exception occured while verifying tunnel-encryption session', goto=['verify_RxStatusS2'])

class ModifyPKILoopbackFlap(nxtest.Testcase):
    @aetest.test
    def modify_PKIsrc_loopback(self, testbed, device_dut, new_loopback, tunnel_loopback, converge_time=60):
        for node in device_dut:
            device = testbed.devices[node]
            LOG.info("modifying the nve  loopback on node %s", node)
            ret_dict = modify_PKIsrc_loopback(device, device_dut,converge_time, new_loopback=new_loopback)
        for node in device_dut:
            LOG.info("vpc peer link flap on node %s", node)
            LOG.info("Starting VMCT loopback - Peerlink flap trigger")
            device = testbed.devices[node]
            obj = StimuliPortFlap(device, tunnel_loopback)
            obj.pre_check()
            obj.action()
            time.sleep(converge_time)

class RemoveaddPKILoopback(nxtest.Testcase):
    @aetest.test
    def removeaddloopback(self,testbed,device_dut,converge_time=60):
        for node in device_dut:
            device = testbed.devices[node]
            cmd = '''sh run tunnel-encryption'''
            obj=device.configure(cmd)  
            tun_lo= re.findall('lo\w+\d', obj)
            tunnel_lo = tun_lo[0]
            log.info(tunnel_lo)
            cmd = ''' checkpoint chk1 '''
            device.configure(cmd)
            cmd = ''' no interface ''' + str(tunnel_lo)
            device.configure(cmd)
            time.sleep(converge_time)
            cmd = ''' rollback running-config checkpoint chk1 '''
            device.configure(cmd)
            time.sleep(converge_time)
            cmd = ''' no checkpoint chk1 '''
            device.configure(cmd)

class ModifyPKI_Loopback_Ipaddress(nxtest.Testcase):
    @aetest.test
    def Modify_Loopback_IP(self,testbed,device_dut, new_ip,converge_time=60):
        for node in device_dut:
            device = testbed.devices[node]
            cmd = '''sh run tunnel-encryption'''
            obj=device.configure(cmd)  
            tun_lo= re.findall('lo\w+\d', obj)
            tunnel_lo = tun_lo[0]
            log.info(tunnel_lo)
            run_config = get_running_config(device, interface = tunnel_lo )
            log.info(run_config)
            cmd = ''' interface {0} \n no ip address \n ip address {1}/32 tag 54321'''.format(tunnel_lo, new_ip) 
            device.configure(cmd)
            time.sleep(converge_time)

def replace_oldconfig(testbed,device_dut):
    for node in device_dut:
        device = testbed.devices[node]
        cmd = ''' sh run tunnel-encryption '''
        obj = device.configure(cmd)
        tun_lo=re.findall('lo\w+\d', obj)
        tunnel_lo = tun_lo[0]
        log.info(tunnel_lo)
        run_config = get_running_config(device, interface = tunnel_lo)
        log.info(run_config)
        cmd = ''' interface {0} \n no ip address \n ip address 2.21.1.1/32 tag 54321'''.format(tunnel_lo) 
        device.configure(cmd)
        replace_config = get_running_config(device, interface = tunnel_lo)
        log.info(replace_config)

def do_copy_run_start(testbed,device_dut):
    for node in device_dut:
            interation = 0
            # modify testbed object
            testbed.devices['uut'] = testbed.devices[node]
            uut = testbed.devices['uut']
            abstract = Lookup.from_device(
                uut,
                packages={
                    'sdk': sdk,
                    'conf': conf,
                    'ops': ops,
                    'parser': parser})
            execute_copy_run_to_start(uut)
            credentials = ['default']

def verify_show_nve_peers(section, testbed, device_dut):
        for node in device_dut:
            output = testbed.devices[node].execute('show nve peers')
            log.info(output)
            if(output == ''):
                section.failed(reason='No Nve Peers')
            a = json.loads(testbed.devices[node].execute('sh nve peers | json'))
            for item in a['TABLE_nve_peers']['ROW_nve_peers']:
                peer_state = item['peer-state']
                if not re.search('Up', peer_state):
                    log.info('The Nve Peer {0} is not up. state is {1}'.format(ns.peer_ip,peer_state))
                    section.failed(reason="status is down")
# ====================================================
#  schema for show tunnel-encryption policy
# ====================================================
class ShowTunnelEncryptionPolicySchema(MetaParser):
    """Schema for:
        show tunnel-encryption policy"""

    schema = {
        'policy':{
            Any(): {
                'cipher': str,
                'window': str,
                Optional('sak_rekey_time'): str,
            },
        },
    }


# ====================================================
#  parser for show tunnel-encryption policy
# ====================================================
class ShowTunnelEncryptionPolicy(ShowTunnelEncryptionPolicySchema):
    """Parser for :
       show tunnel-encryption policy"""

    cli_command = 'show tunnel-encryption policy'

    def cli(self, output=None):
        # excute command to get output
        if output is None:
            out = self.device.execute(self.cli_command)
        else:
            out = output

        result_dict = {}

        # Tunnel-Encryption Policy         Cipher           Window       SAK Rekey time
        # -------------------------------- ---------------- ------------ --------------
        # p1                               GCM-AES-XPN-256  148809600
        # p2                               GCM-AES-XPN-256  148809600
        # system-default-tunenc-policy     GCM-AES-XPN-256  148809600


        p1 = re.compile(r'^(?P<policy_name>[\S]+)\s+(?P<cipher>[\S]+)\s+(?P<window>[\d]+)\s*(?P<sak_rekey_time>[\d]+)?\s*')

        for line in out.splitlines():
            line = line.strip()
            m = p1.match(line)
            if m:
                group = m.groupdict()
                policy_dict = result_dict.setdefault('policy', {})
                policy_name_dict = policy_dict.setdefault(group['policy_name'], {})
                policy_name_dict['cipher'] = group['cipher']
                policy_name_dict['window'] = group['window']
                if group['sak_rekey_time']:
                    policy_name_dict['sak_rekey_time'] = group['sak_rekey_time']
                continue
        return result_dict



# ====================================================
#  schema for show tunnel-encryption session
# ====================================================
class ShowTunnelEncryptionSessionSchema(MetaParser):
    """Schema for:
        show tunnel-encryption session"""

    schema = {
        'peer':{
            Any(): {
                'policy': str,
                'keychain': str,
                'rxstatus': str,
                'txstatus': str,
            },
        },
    }


# ====================================================
#  parser for show tunnel-encryption session
# ====================================================
class ShowTunnelEncryptionSession(ShowTunnelEncryptionSessionSchema):
    """Parser for :
       show tunnel-encryption session"""

    cli_command = 'show tunnel-encryption session'

    def cli(self, output=None):
        # excute command to get output
        if output is None:
            out = self.device.execute(self.cli_command)
        else:
            out = output

        result_dict = {}


        # Tunnel-Encryption Peer           Policy           Keychain                       RxStatus            TxStatus
        # -------------------------------- ---------------- ------------------------------ -------------------- --------------------
        # 201.2.0.51                       p1               kc51                           Secure (AN: 0)       Secure (AN: 0)
        # 201.2.0.52                       p2               kc52                           Secure (AN: 0)       Secure (AN: 0)


        #Tunnel-Encryption Peer   Policy                                   Keychain                                 RxStatus         TxStatus
        #100.100.100.1            kc1                                      PKI: myCA (RSA)                          Secure (AN: 0)    Secure (AN: 0)
        #100.100.100.4            kc2                                      PKI: myCA (RSA)                          Secure (AN: 0)    Secure (AN: 0)


        cli_command_pki = 'show tunnel-encryption session |grep PKI'
        pki_out = self.device.execute(cli_command_pki)
        if str(pki_out).strip()=="":
            LOG.info("======Condition met for NON PKI===")
            p1 = re.compile(r'^(?P<peer_ip>[\S]+)\s+(?P<policy>[\S]+)\s+(?P<keychain>[\S]+)\s+(?P<rxstatus>Secure) +\(AN: \d+\)\s+(?P<txstatus>Secure) +\(AN: \d+\)')
        else:
            LOG.info("======Condition met for PKI===")
            first_ln_str = "FNR == 1"
            trust_point_cli = 'show crypto ca trustpoints'
            trust_point_cli_cmd = trust_point_cli + " |begin " + 'trustpoint ' + "|awk " + '"' + first_ln_str + '"'
            trust_point_out = self.device.execute(trust_point_cli_cmd)
            trust_point_name = (trust_point_out.split(";")[0].split(":")[-1]).strip()
            LOG.info("===trust_point_name===>%s",trust_point_name)

            cli_command_sudi = 'show tunnel-encryption session |grep SUDI'
            sudi_out = self.device.execute(cli_command_sudi)
            if str(sudi_out).strip() == "":
                LOG.info("==Condition met for custom certificate==")
                p1 = re.compile(r'^(?P<peer_ip>[\S]+)\s+(?P<policy>[\S]+)\s+(?P<keychain>PKI)+(:)+\s+'+trust_point_name+'\s+\(RSA\)\s+(?P<rxstatus>Secure) +\(AN: \d+\)\s+(?P<txstatus>Secure) +\(AN: \d+\)')
            else:
                LOG.info("==Condition met for SUDI==")
                p1 = re.compile(r'^(?P<peer_ip>[\S]+)\s+(?P<policy>[\S]+)\s+(?P<keychain>PKI)+(:)+\s+Cisco\s+SUDI\s+(?P<rxstatus>Secure) +\(AN: \d+\)\s+(?P<txstatus>Secure) +\(AN: \d+\)')

        for line in out.splitlines():
            line = line.strip()
            m = p1.match(line)
            if m:
                group = m.groupdict()
                peer_dict = result_dict.setdefault('peer', {})
                peer_ip_dict = peer_dict.setdefault(group['peer_ip'], {})
                peer_ip_dict['policy'] = group['policy']
                peer_ip_dict['keychain'] = group['keychain']
                peer_ip_dict['rxstatus'] = group['rxstatus']
                peer_ip_dict['txstatus'] = group['txstatus']
                continue
        return result_dict

# ====================================================
#  schema for show tunnel-encryption statistics
# ====================================================
class ShowTunnelEncryptionStatisticSchema(MetaParser):
    """Schema for:
        show tunnel-encryption statistic"""

    schema = {
        'peer':{
            Any(): {
                'sak_rx_stats_an': {
                    Any():{
                        'unchecked_pkts': str,
                        'delayed_pkts': str,
                        'late_pkts': str,
                        'invalid_pkts': str,
                        'not_valid_pkts': str,
                        'not_using_sa_pkts': str,
                        'unused_sa_pkts': str,
                    }
                },
                'sak_tx_stats_an': {
                    Any(): {
                        'too_long_pkts': str,
                        'untagged_pkts': str,
                    }
                },
            },
        },
    }

# ====================================================
#  parser for show tunnel-encryption statistics
# ====================================================
class ShowTunnelEncryptionStatistic(ShowTunnelEncryptionStatisticSchema):
    """Parser for :
       show tunnel-encryption statistic"""

    cli_command = ['show tunnel-encryption statistics',
                   'show tunnel-encryption statistics peer-ip {peer_ip}']

    def cli(self, output=None, peer_ip=None):
        # excute command to get output
        if output is None:
            if peer_ip:
                cmd = self.cli_command[1].format(peer_ip=peer_ip)
            else:
                cmd = self.cli_command[0]
            out = self.device.execute(cmd, timeout=180)
        else:
            out = output

        result_dict = {}

        # Peer 201.2.0.51 SecY Statistics:
        #
        # SAK Rx Statistics for AN [0]:
        #    Unchecked Pkts: 0
        #    Delayed Pkts: 0
        #    Late Pkts: 0
        #    OK Pkts: 138668563
        #    Invalid Pkts: 0
        #    Not Valid Pkts: 0
        #    Not-Using-SA Pkts: 0
        #    Unused-SA Pkts: 0
        #    Decrypted In-Pkts: 138668563
        #    Decrypted In-Octets: 35498755274 bytes
        #    Validated In-Octets: 0 bytes
        #
        # SAK Rx Statistics for AN [1]:
        #    Unchecked Pkts: 0
        #    Delayed Pkts: 0
        #    Late Pkts: 0
        #       ----
        #
        # SAK Tx Statistics for AN [0]:
        #    Encrypted Protected Pkts: 77
        #    Too Long Pkts: 0
        #    Untagged Pkts: 0
        #    Encrypted Protected Out-Octets: 5366 bytes

        p1 = re.compile(r'^Peer +(?P<peer_ip>[\S]+)\s+')
        p2 = re.compile(r'SAK Rx Statistics for AN \[(?P<rx_an>[\d]+)\]:')
        p3 = re.compile(r'Unchecked Pkts: +(?P<unchecked_pkts>[\d]+)')
        p4 = re.compile(r'Delayed Pkts: +(?P<delayed_pkts>[\d]+)')
        p5 = re.compile(r'Late Pkts: +(?P<late_pkts>[\d]+)')
        p6 = re.compile(r'Invalid Pkts: +(?P<invalid_pkts>[\d]+)')
        p7 = re.compile(r'Not Valid Pkts: +(?P<not_valid_pkts>[\d]+)')
        p8 = re.compile(r'Not-Using-SA Pkts: +(?P<not_using_sa_pkts>[\d]+)')
        p9 = re.compile(r'Unused-SA Pkts: +(?P<unused_sa_pkts>[\d]+)')
        p10 = re.compile(r'SAK Tx Statistics for AN \[(?P<tx_an>[\d]+)\]:')
        p11 = re.compile(r'Too Long Pkts: +(?P<too_long_pkts>[\d]+)')
        p12 = re.compile(r'Untagged Pkts: +(?P<untagged_pkts>[\d]+)')

        sak_rx_an_dict = {}
        sak_tx_an_dict = {}
        for line in out.splitlines():
            line = line.strip()

            m = p1.match(line)
            if m:
                group = m.groupdict()
                peer_dict = result_dict.setdefault('peer', {})
                peer_ip_dict = peer_dict.setdefault(group['peer_ip'], {})
                continue

            m = p2.match(line)
            if m:
                group = m.groupdict()
                rx_an = group['rx_an']
                sak_rx_dict = peer_ip_dict.setdefault('sak_rx_stats_an', {})
                sak_rx_an_dict = sak_rx_dict.setdefault(rx_an, {})
                continue

            m = p3.match(line)
            if m:
                group = m.groupdict()
                sak_rx_an_dict['unchecked_pkts'] = group['unchecked_pkts']
                continue

            m = p4.match(line)
            if m:
                group = m.groupdict()
                sak_rx_an_dict['delayed_pkts'] = group['delayed_pkts']
                continue

            m = p5.match(line)
            if m:
                group = m.groupdict()
                sak_rx_an_dict['late_pkts'] = group['late_pkts']
                continue

            m = p6.match(line)
            if m:
                group = m.groupdict()
                sak_rx_an_dict['invalid_pkts'] = group['invalid_pkts']
                continue

            m = p7.match(line)
            if m:
                group = m.groupdict()
                sak_rx_an_dict['not_valid_pkts'] = group['not_valid_pkts']
                continue

            m = p8.match(line)
            if m:
                group = m.groupdict()
                sak_rx_an_dict['not_using_sa_pkts'] = group['not_using_sa_pkts']
                continue

            m = p9.match(line)
            if m:
                group = m.groupdict()
                sak_rx_an_dict['unused_sa_pkts'] = group['unused_sa_pkts']
                continue

            m = p10.match(line)
            if m:
                group = m.groupdict()
                tx_an = group['tx_an']
                sak_tx_dict = peer_ip_dict.setdefault('sak_tx_stats_an', {})
                sak_tx_an_dict = sak_tx_dict.setdefault(tx_an, {})
                continue

            m = p11.match(line)
            if m:
                group = m.groupdict()
                sak_tx_an_dict['too_long_pkts'] = group['too_long_pkts']
                continue
            m = p12.match(line)
            if m:
                group = m.groupdict()
                sak_tx_an_dict['untagged_pkts'] = group['untagged_pkts']
                continue
        return result_dict

def verify_cloudsec_tunnel_encryption_session(testbed, cloudsec_tunnel_encryption_session, interface_logical_map):
    """
        Verification of show tunnel-encryption session on the node
        Args:
            testbed:
            cloudsec_tunnel_encryption_session:
            interface_logical_map:
        Returns:
            verify_stats
        Sample Output in datafile for parsing the cloudsec session
        cloudsec_tunnel_encryption_session:
            node02:
                peer:
                    100.100.100.1:
                        policy: kc1
                        keychain: kc1
                        rxstatus: Secure
                        txtstatus: Secure
                    100.100.100.4:
                        policy: kc1
                        keychain: kc1
                        rxstatus: Secure
                        txtstatus: Secure
        """
    verify_cloudsec_tunnel = False
    print(f'Cloud_dict is {cloudsec_tunnel_encryption_session}')
    for node, _value in cloudsec_tunnel_encryption_session.items():
        req_cloudsec_tunnel_encryption_session = ShowTunnelEncryptionSession(testbed.devices[node]).cli()
        if req_cloudsec_tunnel_encryption_session:
            new_dict = req_cloudsec_tunnel_encryption_session
            old_dict = cloudsec_tunnel_encryption_session[node]
            old_dict = json.loads(json.dumps(old_dict))
            LOG.info(f'Converting the ordered dict to unordered dict and old dict is {old_dict}')
            # print(f'json changed Old dict is {old_dict}')
            output = verify_parser_output(new_dict, old_dict, interface_logical_map)
            if output:
                verify_cloudsec_tunnel = True
                LOG.error("Cloudsec Tunnel Encryption Session verification failed for node:%s", node)
            else:
                LOG.info("Cloudsec Tunnel Encryption Session verification passed for node:%s", node)
        else:
            assert not verify_cloudsec_tunnel, f'Cloudsec Tunnels are not up on Node:{node}'
    assert not verify_cloudsec_tunnel, 'Cloudsec Tunnel verification failed'

def verify_cloudsec_tunnel_policy(testbed, cloudsec_tunnel_policy, interface_logical_map):
    """
        Verification of show tunnel-encryption policy on the node
        Args:
            testbed:
            cloudsec_tunnel_policy:
            interface_logical_map:
        Returns:
            verify_stats
        Sample Output in datafile for parsing the cloudsec tunnel policy
        cloudsec_tunnel_policy:
            node02:
                policy:
                    kc1:
                        cipher: 'GCM-AES-XPN-128'
                        window: 268435456
                        sak_rekey_time: 2500000
                    kc2:
                        cipher: 'GCM-AES-XPN-128'
                        window: 268435456
                        sak_rekey_time: 2500000
                    system-default-tunenc-policy:
                        cipher: 'GCM-AES-XPN-256'
                        window: 268435456
        """
    verify_cloudsec_policy = False
    print(f'Cloud_dict is {cloudsec_tunnel_policy}')
    for node, _value in cloudsec_tunnel_policy.items():
        req_cloudsec_tunnel_policy = ShowTunnelEncryptionPolicy(testbed.devices[node]).cli()
        if req_cloudsec_tunnel_policy:
            new_dict = req_cloudsec_tunnel_policy
            old_dict = cloudsec_tunnel_policy[node]
            old_dict = json.loads(json.dumps(old_dict))
            LOG.info(f'Converting the ordered dict to unordered dict and old dict is {old_dict}')
            # print(f'json changed Old dict is {old_dict}')
            output = verify_parser_output(new_dict, old_dict, interface_logical_map)
            if output:
                verify_cloudsec_policy = True
                LOG.error("Cloudsec Tunnel Policy verification failed for node:%s", node)
            else:
                LOG.info("Cloudsec Tunnel Polcicy verification passed for node:%s", node)
        else:
            assert not verify_cloudsec_policy, f'Cloudsec Tunnel Policies are not up on Node:{node}'
    assert not verify_cloudsec_policy, 'Cloudsec Tunnel Policy verification failed'

def verify_remove_certificate(section,testbed,device_dut,remove_trust_point,cmd_wait_time,sudi_flag = False):
    LOG.info("Inside remove_certificate...")
    pki_trust_point_str = 'tunnel-encryption pki trustpoint'
    pki_trust_point_cli = 'no tunnel-encryption pki trustpoint {tp_name}'.format(tp_name=remove_trust_point)
    crypto_cli = 'no crypto ca trustpoint {tp_name}'.format(tp_name=remove_trust_point)
    for node in device_dut:
        device = testbed.devices[node]
        pki_trust_point_out = device.execute("show running-config tunnel-encryption " + "|grep " + '"' + pki_trust_point_str + '"')
        LOG.info("===Removing pki trust point in %s===>", node)
        device.configure(pki_trust_point_cli)
        LOG.info("===waiting===%s seconds",cmd_wait_time)
        time.sleep(cmd_wait_time)
        if not sudi_flag:
            device.configure(crypto_cli)
            time.sleep(cmd_wait_time)
        pki_trust_point_out = device.execute("show running-config tunnel-encryption " + "|grep " + '"' + pki_trust_point_str + '"')
        if str(pki_trust_point_out).strip() != "":
            LOG.error("===Unable to remove pki trust point on %s, returned %s===>",node, pki_trust_point_out)
            section.failed()
        else:
            LOG.info("===pki trust point removed successfully on %s===>", node)
    time.sleep(cmd_wait_time)

def verify_cloudsec_tunnel_encryption_statistics(testbed, cloudsec_tunnel_encryption_statistics, interface_logical_map):
    """
        Verification of show tunnel-encryption statistics on the node
        Args:
            testbed:
            cloudsec_tunnel_encryption_statistics:
            interface_logical_map:
        Returns:
            verify_stats
        Sample Output in datafile for parsing the cloudsec session
        cloudsec_tunnel_encryption_statistics:
            node01:
                peer:
                    100.100.100.2:
                        sak_rx_stats_an:
                            unchecked_pkts: 0
                            delayed_pkts: 0
                            late_pkts: 0
                            invalid_pkts: 0
                            not_valid_pkts: 0
                            not_using_sa_pkts: 0
                            unused_sa_pkts: 0
                        sak_tx_stats_an:
                            too_long_pkts: 0
                            untagged_pkts: 0
        """
    verify_cloudsec_tunnel = False
    print(f'Cloud_dict is {cloudsec_tunnel_encryption_statistics}')
    for node, _value in cloudsec_tunnel_encryption_statistics.items():
        testbed.devices[node].configure('clear tunnel-encryption statistics')
        req_cloudsec_tunnel_encryption_statistics = ShowTunnelEncryptionStatistic(testbed.devices[node]).cli()
        if req_cloudsec_tunnel_encryption_statistics:
            new_dict = req_cloudsec_tunnel_encryption_statistics
            old_dict = cloudsec_tunnel_encryption_statistics[node]
            old_dict = json.loads(json.dumps(old_dict))
            LOG.info(f'Converting the ordered dict to unordered dict and old dict is {old_dict}')
            # print(f'json changed Old dict is {old_dict}')
            output = verify_parser_output(new_dict, old_dict, interface_logical_map)
            if output:
                verify_cloudsec_tunnel = True
                LOG.error("Cloudsec Tunnel encryption statistics verification failed for node:%s", node)
            else:
                LOG.info("CloudsecTunnel encryption statistics verification passed for node:%s", node)
        else:
            assert not verify_cloudsec_tunnel, f'Cloudsec Tunnel encryption statistics verification failed on Node:{node}'
    assert not verify_cloudsec_tunnel, 'Cloudsec Tunnel encryption statistics verification failed'

def verify_remove_pki_dme_config(section,testbed,device_dut,source_interface,peer_ip_lst):
    LOG.info("===verify_remove_pki_config===")
    pki_trust_point_str = 'tunnel-encryption pki trustpoint'
    pki_src_loopback_str = 'pki source-interface '
    tunnel_encry_peer_ip_str ='tunnel-encryption peer-ip'
    for node in device_dut:
        device = testbed.devices[node]
        pki_trust_point_out = device.execute("show running-config tunnel-encryption " + "|grep " + '"' + pki_trust_point_str + '"')
        trust_point_name = str(pki_trust_point_out).split(" ")[-1].strip()
        LOG.info("==-pki trust point name===%s",trust_point_name)
        pki_trust_point_cli = 'no tunnel-encryption pki trustpoint {tp_name}'.format(tp_name=trust_point_name)
        pki_src_int_loopback_cli = 'no tunnel-encryption pki source-interface {src_loopback}'.format(src_loopback=source_interface)

        LOG.info("==Removing pki trust point, pki source int loopback and peer-ip")
        device.configure(pki_trust_point_cli)
        device.configure(pki_src_int_loopback_cli)
        for peer in peer_ip_lst:
            peer_ip_cli = 'no tunnel-encryption peer-ip {peer_ip}'.format(peer_ip=peer)
            device.configure(peer_ip_cli)

        time.sleep(2)
        pki_trust_point_out = device.execute("show running-config tunnel-encryption " + "|grep " + '"' + pki_trust_point_str + '"')
        if str(pki_trust_point_out).strip() != "":
            LOG.error("===Unable to remove pki trust point on %s, returned %s===>",node, pki_trust_point_out)
            section.failed()
        else:
            LOG.info("===pki trust point removed successfully on %s===>", node)
        pki_src_int_out = device.execute("show running-config tunnel-encryption " + "|grep " + '"' + pki_src_loopback_str + '"')
        if str(pki_src_int_out).strip() != "":
            LOG.error("===Unable to remove pki source-interface on %s, returned %s===>",node, pki_src_loopback_str)
            section.failed()
        else:
            LOG.info("===pki source-interface removed successfully on %s===>", node)
        pki_peer_ip_out = device.execute("show running-config tunnel-encryption " + "|grep " + '"' + tunnel_encry_peer_ip_str + '"')
        if str(pki_peer_ip_out).strip() != "":
            LOG.error("===Unable to remove tunnel-encryption peer-ip on %s, returned %s===>",node, tunnel_encry_peer_ip_str)
            section.failed()
        else:
            LOG.info("===pki tunnel-encryption peer-ip removed successfully on %s===>", node)





            
            



    # @aetest.test
    # def verify_RxStatus(self,testbed,device_dut):
    #     for node in device_dut:
    #         output1 = json.loads(testbed.devices[node].execute('sh tunnel-encryption session | json'))
    #         log.info(output1)
    #         if(output1 == ''):
    #             self.failed(reason='No tunnel-encryption session')
    #         a = json.loads(testbed.devices[node].execute('sh tunnel-encryption session | json'))
    #         item = a["TABLE_tem_session"]["ROW_tem_session"]
    #         for i in range(len(item)):
    #             RxStatus = item['RxStatus']
    #             if not re.search('Secure\s\(AN:\s\d\)', RxStatus):
    #                 log.info('The tunnel session {0} is not secure. state is {1}'.format(ns.PeerAddr,RxStatus))
    #                 self.failed(reason="status is not secure")
    
    # @aetest.test
    # def verify_Txstatus(self,testbed,device_dut):
    #     for node in device_dut:
    #         output1 = json.loads(testbed.devices[node].execute('sh tunnel-encryption session | json'))
    #         log.info(output1)
    #         if(output1 == ''):
    #             self.failed(reason='No tunnel-encryption session')
    #         a = json.loads(testbed.devices[node].execute('sh tunnel-encryption session | json'))
    #         item = a["TABLE_tem_session"]["ROW_tem_session"]
    #         for i in range(len(item)):
    #             TxStatus = item['TxStatus']
    #             if not re.search('Secure\s\(AN:\s\d\)', TxStatus):
    #                 log.info('The tunnel session {0} is not secure. state is {1}'.format(ns.PeerAddr,TxStatus))
    #                 self.failed(reason="status is not secure") 


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
        
# #======================================================#
# #      PKI with RSA Certificate Installation           #
# #======================================================#
class PKI_certificate_installation(nxtest.Testcase):
    #"TC_001_PKI_certificate_installation"
    
    ##-- 1.The CA pem file can be obtained from a 3rd party or Create one of your own self-signed certificate using openssl---#
    @aetest.test
    def Creating_CAFile_S1_BGW1(self,testbed):
        dev = Connection(hostname='swadmin@n3k-qa-image:', start=['telnet 10.127.63.241'],credentials={'default': {'username': 'swadmin', 'password': 'password'}},os='linux')
        dev.connect()
        # unicon_state.restore_state_pattern() 
        ret_dialog = Dialog([
            Statement(pattern=r'.*Country Name \(2 letter code\) \[GB\]:',
                    action='sendline(IN)',
                    loop_continue=True,
                    continue_timer=True),
            Statement(pattern=r'.*State or Province Name \(full name\) \[Berkshire\]:',
                    action='sendline(Karnataka)',
                    loop_continue=True,
                    continue_timer=True),
            Statement(pattern=r'.*Locality Name \(eg\, city\) \[Newbury\]:',
                    action='sendline(Bangalore)',
                    loop_continue=True,
                    continue_timer=True),
            Statement(pattern=r'.*Organization Name \(eg\, company\) \[My Company Ltd\]:',
                    action='sendline(Cisco)',
                    loop_continue=True,
                    continue_timer=True),
            Statement(pattern=r'.*Organizational Unit Name \(eg\, section\) \[\]:',
                    action='sendline(DCBU)',
                    loop_continue=True,
                    continue_timer=True),
            Statement(pattern=r'.*Common Name \(eg\, your name or your server\'s hostname\) \[\]:',
                    action='sendline(Server)',
                    loop_continue=True,
                    continue_timer=True),
            Statement(pattern=r'.*Email Address \[\]:',
                    action='sendline(hsuryaka@cisco.com)',
                    loop_continue=True,
                    continue_timer=True),
            ])
        dev.execute('mkdir cloudsec')
        dev.execute('cd cloudsec')
        dev.execute('mkdir rsa')
        dev.execute('cd rsa')
        dev.execute('openssl genrsa -out CAPrivate.key 2048')
        dev.execute('openssl req -x509 -new -nodes -key CAPrivate.key -sha256 -days 365 -out CAPrivate.pem', reply=ret_dialog)
        output = dev.execute('ls')
        match = ('CAPrivate.key  CAPrivate.pem')
        if re.search(match,output):
            self.passed('CA Files are created')
        else:
            log.info('CA file are not created.Creating CA File went worng')
            self.failed('failed to create CA File')

    @aetest.test
    def coping_certificate_onDevices(self,testbed):
        node=["node3_s1_bgw_1", "node4_s1_bgw_2", "node7_s2_bgw_1"]
        # node=["node4_s1_bgw_2"]
        i=0
        for i in range(len(node)):
            ret_dialog = Dialog([
                Statement(pattern=r'.*Are you sure you want to continue connecting \(yes\/no\/\[fingerprint\]\)\?',
                        action='sendline(yes)',
                        loop_continue=True,
                        continue_timer=True),
                Statement(pattern=r'.*swadmin\@10\.127\.63\.241\'s password:',
                        action='sendline(password)',
                        loop_continue=True,
                        continue_timer=True),
                        ])
            testbed.devices[node[i]].execute("copy scp://swadmin@10.127.63.241/home/swadmin/cloudsec/CAPrivate.key bootflash: vrf management", reply=ret_dialog)
            testbed.devices[node[i]].execute("copy scp://swadmin@10.127.63.241/home/swadmin/cloudsec/CAPrivate.pem bootflash: vrf management", reply=ret_dialog)
            
    
    '''Create a trust point'''
    @aetest.test
    def create_trust_point(self, testbed, device_dut, cmd_wait_time, trust_point_name):
        LOG.info("===Calling add_trust_point===")
        if add_trust_point(testbed, device_dut,cmd_wait_time,trust_point_name):
            LOG.info("===Trust point created and verified successfully===")
        else:
            LOG.error("===Error in creating/verifying trust point===")
            self.failed()

    '''Create an RSA and ECC key pair for the device'''
    @aetest.test
    def create_rsa_ecc_key_pair(self, testbed, device_dut, cmd_wait_time, rsa_label,cert_size):
        LOG.info("===Calling add_rsa_ecc_pair===")
        if add_rsa_ecc_pair(testbed, device_dut,cmd_wait_time,rsa_label,cert_size):
            LOG.info("===RSA/ECC key pair created and verified successfully===")
        else:
            LOG.error("===Error in creating/verifying RSA/ECC key pair===")
            self.failed()

    '''Associate the RSA/ECC key pair to the trust point.'''
    @aetest.test
    def associate_rsa_ecc_key_pair_to_trust_point(self, testbed, device_dut, cmd_wait_time, trust_point_name, rsa_label):
        LOG.info("===Calling add_rsa_key_pair_to_trust_point===")
        if add_rsa_key_pair_to_trust_point(testbed, device_dut,cmd_wait_time,trust_point_name,rsa_label):
            LOG.info("===RSA/ECC key pair added to trust point successfully===")
        else:
            LOG.error("===Error in associating/verifying RSA/ECC key pair to trust point===")
            self.failed()

    # '''Download CA pem and key file and'''
    # @aetest.test
    # def download_ca_certificate(self, testbed, device_dut, cmd_wait_time):
    #     LOG.info("===Calling ca_files_download_and_check===")
    #     if ca_files_download_and_check(testbed, device_dut,cmd_wait_time):
    #         LOG.info("===CA pem,key file found in bootflash of all switches===")
    #     else:
    #         LOG.error("===CA pem,key file not found in bootflash of all switches===")
    #         self.failed()

    '''Authenticate the CA that want to enroll to the trust point'''
    @aetest.test
    def authenticate_ca(self, testbed, device_dut, cmd_wait_time, trust_point_name):
        LOG.info("===Calling insert_and_authenticate_ca_cert===")
        if insert_and_authenticate_ca_cert(testbed, device_dut,cmd_wait_time,trust_point_name):
            LOG.info("===Authenticated the CA enrolled to the trust point successfully===")
        else:
            LOG.error("===Authentication for the CA enrolled to the trust point failed===")
            self.failed()

    # #--- 3.Create a trust point --#
    # @aetest.test
    # def create_Trustpoint(self,testbed):
    #     node=["node3_s1_bgw_1", "node4_s1_bgw_2", "node7_s2_bgw_1"]
    #     i=0
    #     for i in range (len(node)):
    #         testbed.devices[node[i]].execute("exit", allow_state_change="True")
    #         testbed.devices[node[i]].execute("exit", allow_state_change="True")
    #         testbed.devices[node[i]].configure(''' 
    #             crypto ca trustpoint myCA
    #             exit
    #             ''')
    #         output=testbed.devices[node[i]].execute(' show crypto ca trustpoints ')
    #         match = ('trustpoint: myCA;')
    #         if re.search(match,output):
    #             self.passed('trustpoint created')
    #         else:
    #             log.info('No trustpoint find.failed to create Trustpoint')
    #             self.failed('failed to create trustpoint')
    
    # #-- 4. Create an RSA key pair for the device. (Needed only if you are not using a pkcs file) --#
    # @aetest.test
    # def Create_RSA_Keypair(self,testbed):
    #     node=["node3_s1_bgw_1", "node4_s1_bgw_2", "node7_s2_bgw_1"]
    #     i=0
    #     for i in range (len(node)):
    #         testbed.devices[node[i]].configure(''' 
    #             crypto key generate rsa label myKey exportable modulus 1024
    #             ''')
    #         output=testbed.devices[node[i]].execute('show crypto key mypubkey rsa')
    #         match=('''key label: myKey''')
    #         if re.search(match,output):
    #             self.passed('key pair created')
    #         else:
    #             log.info('No key label is present')
    #             self.failed('failed to create key label')

    # #-- 5. Associate the RSA key pair to the trust point. --#
    # @aetest.test
    # def Associate_RSA_keypair_to_Trustpair(self,testbed):
    #     node=["node3_s1_bgw_1", "node4_s1_bgw_2", "node7_s2_bgw_1"]
    #     i=0
    #     for i in range (len(node)):
    #         testbed.devices[node[i]].configure(''' 
    #             crypto ca trustpoint myCA
    #                 rsakeypair myKey
    #                 exit
    #         ''')
    #         output=testbed.devices[node[i]].execute('show crypto ca trustpoints')
    #         match = ('trustpoint: myCA; key-pair: myKey')
    #         if re.search(match,output):
    #             self.passed('Trustpoint and key pair are associated')
    #         else:
    #             log.info('Exepted values not present')
    #             self.failed('failed to associate rsa keypair to trustpoint')
    
    #-- 7. Authenticate the CA that you want to enroll to the trust point. --#
    # @aetest.test
    # def Authenticate_CA_to_enroll_Trustpoint(self,testbed):
    #     node=["node3_s1_bgw_1", "node4_s1_bgw_2", "node7_s2_bgw_1"]
    #     i=0
    #     for i in range (len(node)):
    #         testbed.devices[node[i]].configure(''' crypto ca authenticate myCA pemfile bootflash:/CAPrivate.pem ''')
    #         output=testbed.devices[node[i]].execute('show crypto ca certificates')
    #         match=('CA certificate 0:')
    #         if re.search(match,output):
    #             self.passed('enrolled authenticate the CA to trustpoint')
    #         else:
    #             log.info('failed to enroll CA to Trustpoint')
    #             self.failed('failed to enroll CA to Trustpoint')
    
    '''Generate a request certificate (CSR) to use to enroll with a trust point'''
    @aetest.test
    def generate_csr_certificate(self, testbed, device_dut, cmd_wait_time, trust_point_name):
        LOG.info("===Calling create_csr_certificate_request===")
        create_csr_certificate_request(testbed, device_dut,cmd_wait_time,trust_point_name)
    
    '''Create .csr files'''
    @aetest.test
    def download_csr_file(self, testbed, device_dut, cmd_wait_time):
        LOG.info("===Calling create_csr_certificate_files===")
        if create_csr_certificate_files(testbed, device_dut,cmd_wait_time):
            LOG.info("===.CSR files created successfully===")
        else:
            LOG.error("===CSR files failed to create===")
            self.failed()

    '''Request an identity certificate from 3rd party using the CSR file'''
    @aetest.test
    def request_identity_certificate(self, testbed, device_dut, cmd_wait_time, openssl_flag):
        LOG.info("===Calling create_identity_certificate_files===")
        if create_identity_certificate_files(testbed, device_dut,cmd_wait_time,openssl_flag):
            LOG.info("===Identity certificate created successfully and saved into bootflash===")
        else:
            LOG.error("===Identity certificate creation failed===")
            self.failed()

    # '''Configure pki trustpoint cli into switches'''
    # @aetest.test
    # def add_pki_trust_point_cli(self, testbed, device_dut, cmd_wait_time, trust_point_name):
    #     LOG.info("===Calling pki_trust_point_cli===")
    #     if pki_trust_point_cli(testbed, device_dut,cmd_wait_time,trust_point_name):
    #         LOG.info("===pki trust point added successfully and verified==")
    #     else:
    #         LOG.error("===Failed to add pki trust point===")
    #         self.failed()

    '''Import Identity certificate'''
    @aetest.test
    def import_identity_certificate(self, testbed, device_dut, cmd_wait_time, trust_point_name, rsa_label):
        LOG.info("===Calling insert_identity_certificate===")
        if insert_identity_certificate(testbed, device_dut,cmd_wait_time,trust_point_name,rsa_label):
            LOG.info("===Identity certificate imported successfully===")
        else:
            LOG.error("===Import identity certificate failed===")
            self.failed()

    '''Verify tunnel encryption session'''
    @aetest.test
    def verify_pki_tunnel_encryption_session(self, device_dut, cmd_wait_time, testbed, cloudsec_tunnel_encryption_session):
        LOG.info("===Calling test_verify_pki_tunnel_encryption===")
        interface_logical_map = self.parameters.get('interface_logical_map')
        if test_verify_pki_tunnel_encryption(testbed,cloudsec_tunnel_encryption_session,interface_logical_map):
            LOG.info("===PKI tunnel encryption session formed===")
            for node in device_dut:
                execute_copy_run_to_start(testbed.devices[node])
            time.sleep(cmd_wait_time)
        else:
            LOG.error("===PKI tunnel encryption session not formed===")
            self.failed()
        
    #-- 8. Generate a request certificate (CSR) to use to enroll with a trust point. (Not needed for PKCS import) --#
    # @aetest.test
    # def Generate_request_certificate_CSR(self,testbed):
    #     # dev = Connection(hostname='Elysian1', start=['telnet 10.225.127.41'],credentials={'default': {'username': 'admin', 'password': 'nbv123'}},os='nxos')
    #     node=["node4_s1_bgw_2"]#, "node4_s1_bgw_2", "node7_s2_bgw_1"]
    #     i=0
    #     for i in range (len(node)):
    #         # dev = testbed.devices['node4_s1_bgw_2']
    #         # dev.connect()

    #         unicon_state = unicon.statemachine.statemachine.State(name='enable', pattern=r'^.*|%N#')
    #         unicon_state.add_state_pattern(pattern_list="r'bash-*$'")

    #         testbed.devices[node[i]].configure("feature bash-shell")
    #         # pid_data = testbed.devices[node[i]].execute("show system internal sysmgr service name bgp | i i PID")
    #         # pid_regex = re.search("PID = (\\d+)", pid_data, re.I)
    #         # if pid_regex is not 0:
    #         #     pid = pid_regex.group(1)
            
    #         list=['10.10.1.1', '10.10.2.1', '10.10.3.1']
    #         i=0
    #         for i in range (len(list)):

                
    #     # Preparing the dialog
    #             dialog=Dialog([
    #                     Statement(pattern=r'^.*word:.*$',
    #                             action='sendline(nbv12345)',
    #                             loop_continue=True,
    #                             continue_timer=True),
    #                     Statement(pattern=r'^.*certificate will be:.*$',
    #                             action='sendline(S1_BGW1)',
    #                             loop_continue=True,
    #                             continue_timer=True),
    #                     Statement(pattern=r'^.*number in the subject name\? \[yes\/no\]:.*$',
    #                             action='sendline(no)',
    #                             loop_continue=True,
    #                             continue_timer=True),
    #                     Statement(pattern=r'^.*address in the subject name \[yes\/no\]:.*$',
    #                             action='sendline(yes)',
    #                             loop_continue=True,
    #                             continue_timer=True),
    #                     Statement(pattern=r'^.*ip address:.*$',
    #                             action='sendline(10.10.1.1)',
    #                             loop_continue=True,
    #                             continue_timer=True),
    #                     Statement(pattern=r'^.*Alternate Subject Name \? \[yes\/no\]:.*$',
    #                             action='sendline(no)',
    #                             loop_continue=True,
    #                             continue_timer=True),
    #                     ])
    #             testbed.devices[node[i]].configure('crypto ca enroll myCA', reply=dialog)
                # # indx = output.index('-----BEGIN CERTIFICATE REQUEST-----')
                # # b = output[indx:]
                # # c = b.split('\r\n')
                # testbed.devices[node[i]].execute('run bash', allow_state_change="True")
                # testbed.devices[node[i]].execute('touch /bootflash/RSA/text.csr', allow_state_change="True")
                # for line in c:
                #     testbed.devices[node[i]].execute('echo '+str(line)+' >> /bootflash/RSA/text.csr', allow_state_change="True")
                # testbed.devices[node[i]].execute('more /bootflash/RSA/text.csr', allow_state_change="True")
                # testbed.devices[node[i]].execute("exit", allow_state_change="True")
                # unicon_state.restore_state_pattern() 
                
    # #-- 9. Copy the above output to a file (CSR file). Request an identity certificate from 3rd party using this CSR --#
    # @aetest.test
    # def Copy_CSR_file_certificate(self,testbed):
    #     node=["node3_s1_bgw_1", "node4_s1_bgw_2", "node7_s2_bgw_1"]
    #     i=0
    #     for i in range (len(node)):
    #         # dev = testbed.devices['node4_s1_bgw_2']
    #         # dev.connect()

    #         unicon_state = unicon.statemachine.statemachine.State(name='enable', pattern=r'^.*|%N#')
    #         unicon_state.add_state_pattern(pattern_list="r'bash-*$'")

    #         # testbed.devices[node[i]].configure("feature bash-shell")
    #         pid_data = testbed.devices[node[i]].execute("show system internal sysmgr service name bgp | i i PID")
    #         pid_regex = re.search("PID = (\\d+)", pid_data, re.I)
    #         if pid_regex is not 0:
    #             pid = pid_regex.group(1)
    #         testbed.devices[node[i]].execute("run bash", allow_state_change="True")
    #         testbed.devices[node[i]].execute("sudo su", allow_state_change="True")
    #         testbed.devices[node[i]].execute("kill -9 " + str(pid), allow_state_change="True")

    #         # testbed.devices['node4_s1_bgw_2'].execute('run bash')
    #         testbed.devices[node[i]].execute('openssl x509 -req -in /bootflash/rsa/S1_BGW1.csr -CA /bootflash/rsa/CAPrivate.pem -CAkey /bootflash/rsa/CAPrivate.key -CAcreateserial -out /bootflash/rsa/S1_BGW1.pem -days 500')
    #         testbed.devices[node[i]].execute("exit", allow_state_change="True")
    #         testbed.devices[node[i]].execute("exit", allow_state_change="True")
    
    # # #-- 10. Import the identity certificate --#
    # @aetest.test
    # def Import_identity_certificate(self,testbed):
        
    #     # unicon_state = unicon.statemachine.statemachine.State(name='enable', pattern=r'^.*|%N#')
    #     # unicon_state.add_state_pattern(pattern_list="r'bash-*$'")
    #     node=["node3_s1_bgw_1", "node4_s1_bgw_2", "node7_s2_bgw_1"]
    #     i=0
    #     for i in range (len(node)):
    #         # dev = testbed.devices['node4_s1_bgw_2']
    #         # dev.connect()

    #         unicon_state = unicon.statemachine.statemachine.State(name='enable', pattern=r'^.*|%N#')
    #         unicon_state.add_state_pattern(pattern_list="r'bash-*$'")

    #         # testbed.devices[node[i]].configure("feature bash-shell")
    #         pid_data = testbed.devices[node[i]].execute("show system internal sysmgr service name bgp | i i PID")
    #         pid_regex = re.search("PID = (\\d+)", pid_data, re.I)
    #         if pid_regex is not 0:
    #             pid = pid_regex.group(1)
    #         testbed.devices[node[i]].execute("run bash", allow_state_change="True")
    #         testbed.devices[node[i]].execute("sudo su", allow_state_change="True")
    #         testbed.devices[node[i]].execute("kill -9 " + str(pid), allow_state_change="True")
    #         testbed.devices[node[i]].execute('cd /bootflash/rsa')
    #         output=testbed.devices[node[i]].execute('more S1_BGW1.pem')
    #         testbed.devices[node[i]].execute("exit", allow_state_change="True")
    #         testbed.devices[node[i]].execute("exit", allow_state_change="True")
    #         testbed.devices[node[i]].configure(''' 
    #             crypto ca import myCA certificate
    #         ''')
    #         # inpt="input (cut & paste) certificate in PEM format:"
    #         log.info(output)
        # output=testbed.devices[node[i]].execute('show crypto ca certificates')
        # match=(''' 
        # Trustpoint: myCA
        # CA certificate 0:
        # ''')
        # if re.search(match,output):
        #     self.passed('enrolled authenticate the CA to trustpoint')
        # else:
        #     log.info('failed to enroll CA to Trustpoint')
        #     self.failed('failed to enroll CA to Trustpoint')

class Migration_ECC_to_RSA_Certificate(nxtest.Testcase):
    @aetest.test
    def MigrationPKIfromPSKcertificatevPC(self,testbed):
        node=["node3_s1_bgw_1", "node4_s1_bgw_2"]
        i=0
        for i in range(len(node)):
            # trust_point_name = ["node3_s1_bgw_1_ecc_ca", "node4_s1_bgw_2_ecc_ca"]
            # i=0
            # for i in range (len(trust_point_name)):
            testbed.devices[node[i]].configure('''
                no tunnel-encryption must-secure-policy 
                tunnel-encryption peer-ip 3.21.21.21
                    no pki policy system-default-tunenc-policy 
                no tunnel-encryption pki trustpoint starcher7_ECC_CA1
                tunnel-encryption icv
                tunnel-encryption pki trustpoint myCA1
                tunnel-encryption pki source-interface cloudsec-loopback
                tunnel-encryption source-interface loopback0
                tunnel-encryption policy p1
                    sak-rekey-time 1800
                tunnel-encryption peer-ip 3.21.21.21
                    pki policy system-default-tunenc-policy

                ''')
            time.sleep(60)
      
    @aetest.test
    def MigrationPKIfromPSKcertificateStdalone(self,testbed):
        testbed.devices['node7_s2_bgw_1'].configure('''
            no tunnel-encryption must-secure-policy 
            tunnel-encryption peer-ip 2.21.21.21
                no pki policy system-default-tunenc-policy
            tunnel-encryption peer-ip 2.22.22.22
                no pki policy system-default-tunenc-policy 
            no tunnel-encryption pki trustpoint starcher7_ECC_CA1
            tunnel-encryption icv
            tunnel-encryption pki trustpoint myCA1
            tunnel-encryption pki source-interface cloudsec-loopback
            tunnel-encryption source-interface loopback0
            tunnel-encryption policy p1
                sak-rekey-time 1800
            tunnel-encryption peer-ip 2.21.21.21
                pki policy system-default-tunenc-policy
            tunnel-encryption peer-ip 2.22.22.22
                pki policy system-default-tunenc-policy 
            ''')
        time.sleep(120)
    
    @aetest.test
    def verify_RxStatus(self,testbed):
        node=["node3_s1_bgw_1", "node4_s1_bgw_2"]
        i=0
        for i in range(len(node)):
            output1 = json.loads(testbed.devices[node[i]].execute('sh tunnel-encryption session | json'))
            log.info(output1)
            if(output1 == ''):
                self.failed(reason='No tunnel-encryption session')
            a = json.loads(testbed.devices[node[i]].execute('sh tunnel-encryption session | json'))
            item = a["TABLE_tem_session"]["ROW_tem_session"]
            for i in range(len(item)):
                str(item)
                RxStatus = item['RxStatus']
                if not re.search('Secure\s\(AN:\s\d\)', RxStatus):
                    log.info('The tunnel session {0} is not secure. state is {1}'.format(ns.PeerAddr,RxStatus))
                    self.failed(reason="status is not secure")
    @aetest.test
    def verify_RxStatus_S2_BGW1(self,testbed):
        output1 = json.loads(testbed.devices['node7_s2_bgw_1'].execute('sh tunnel-encryption session | json'))
        log.info(output1)
        if(output1 == ''):
            self.failed(reason='No tunnel-encryption session')
        a = json.loads(testbed.devices['node7_s2_bgw_1'].execute('sh tunnel-encryption session | json'))
        item = a["TABLE_tem_session"]["ROW_tem_session"]
        for i in range(len(item)):
            str(item)
            RxStatus = item[i]['RxStatus']
            if not re.search('Secure\s\(AN:\s\d\)', RxStatus):
                log.info('The tunnel session {0} is not secure. state is {1}'.format(ns.PeerAddr,RxStatus))
                self.failed(reason="status is not secure")

    @aetest.test
    def verify_Txstatus(self,testbed):
        node=["node3_s1_bgw_1", "node4_s1_bgw_2"]
        i=0
        for i in range(len(node)):
            output1 = json.loads(testbed.devices[node[i]].execute('sh tunnel-encryption session | json'))
            log.info(output1)
            if(output1 == ''):
                self.failed(reason='No tunnel-encryption session')
            a = json.loads(testbed.devices[node[i]].execute('sh tunnel-encryption session | json'))
            item = a["TABLE_tem_session"]["ROW_tem_session"]
            for i in range(len(item)):
                str(item)
                TxStatus = item['TxStatus']
                if not re.search('Secure\s\(AN:\s\d\)', TxStatus):
                    log.info('The tunnel session {0} is not secure. state is {1}'.format(ns.PeerAddr,TxStatus))
                    self.failed(reason="status is not secure") 
    
    @aetest.test
    def verify_Txstatus_S2_BGW1(self,testbed):
        output1 = json.loads(testbed.devices['node7_s2_bgw_1'].execute('sh tunnel-encryption session | json'))
        log.info(output1)
        if(output1 == ''):
            self.failed(reason='No tunnel-encryption session')
        a = json.loads(testbed.devices['node7_s2_bgw_1'].execute('sh tunnel-encryption session | json'))
        item = a["TABLE_tem_session"]["ROW_tem_session"]
        for i in range(len(item)):
            str(item)
            TxStatus = item[i]['TxStatus']
            if not re.search('Secure\s\(AN:\s\d\)', TxStatus):
                log.info('The tunnel session {0} is not secure. state is {1}'.format(ns.PeerAddr,TxStatus))
                self.failed(reason="status is not secure") 
    
    @aetest.test
    def verify_policy(self,testbed):
        node=["node3_s1_bgw_1", "node4_s1_bgw_2"]
        i=0
        for i in range(len(node)):
            output1 = json.loads(testbed.devices[node[i]].execute('sh tunnel-encryption session | json'))
            log.info(output1)
            if(output1 == ''):
                self.failed(reason='No tunnel-encryption session')
            a = json.loads(testbed.devices[node[i]].execute('sh tunnel-encryption session | json'))
            item = a["TABLE_tem_session"]["ROW_tem_session"]
            for i in range(len(item)):
                str(item)
                PolicyName = item['PolicyName']
                if not re.search('system-default-tunenc-policy', PolicyName):
                    log.info(PolicyName)
                    self.failed(reason="tunnel-encryption policy is not verified")

    @aetest.test
    def verify_policy(self,testbed):
        output1 = json.loads(testbed.devices['node7_s2_bgw_1'].execute('sh tunnel-encryption session | json'))
        log.info(output1)
        if(output1 == ''):
            self.failed(reason='No tunnel-encryption session')
        a = json.loads(testbed.devices['node7_s2_bgw_1'].execute('sh tunnel-encryption session | json'))
        item = a["TABLE_tem_session"]["ROW_tem_session"]
        for i in range(len(item)):
            str(item)
            PolicyName = item[i]['PolicyName']
            if not re.search('system-default-tunenc-policy', PolicyName):
                log.info(PolicyName)
                self.failed(reason="tunnel-encryption policy is not verified")
    
    @aetest.test
    def adding_must_secury_policy(self,testbed):
        node=["node3_s1_bgw_1", "node4_s1_bgw_2", "node7_s2_bgw_1"]
        i=0
        for i in range(len(node)):
            testbed.devices[node[i]].configure("tunnel-encryption must-secure-policy")
            time.sleep(30)
        

    @aetest.test
    def verify_traffic(self,testscript,section):

            if VerifyTraffic(section, testscript):
                self.passed()
            else:
                self.failed()

class Migration_PSK_from_RSA_Certificate(nxtest.Testcase):
    @aetest.test
    def MigrationPKIfromPSKcertificatevPC(self,testbed):
        node=["node3_s1_bgw_1", "node4_s1_bgw_2"]
        i=0
        for i in range(len(node)):
            # trust_point_name = ["node3_s1_bgw_1_ecc_ca", "node4_s1_bgw_2_ecc_ca"]
            # i=0
            # for i in range (len(trust_point_name)):
            testbed.devices[node[i]].configure('''
                no tunnel-encryption must-secure-policy 
                tunnel-encryption peer-ip 3.21.21.21
                    no keychain KC1 policy p1 
                tunnel-encryption icv
                tunnel-encryption pki trustpoint myCA1
                tunnel-encryption pki source-interface cloudsec-loopback
                tunnel-encryption source-interface loopback0
                tunnel-encryption policy p1
                    sak-rekey-time 1800
                tunnel-encryption peer-ip 3.21.21.21
                    pki policy system-default-tunenc-policy

                ''')
            time.sleep(60)
      
    @aetest.test
    def MigrationPKIfromPSKcertificateStdalone(self,testbed):
        testbed.devices['node7_s2_bgw_1'].configure('''
            no tunnel-encryption must-secure-policy 
            tunnel-encryption peer-ip 2.21.21.21
                no keychain KC1 policy p1
            tunnel-encryption peer-ip 2.22.22.22
                no keychain KC1 policy p1 
            tunnel-encryption icv
            tunnel-encryption pki trustpoint myCA1
            tunnel-encryption pki source-interface cloudsec-loopback
            tunnel-encryption source-interface loopback0
            tunnel-encryption policy p1
                sak-rekey-time 1800
            tunnel-encryption peer-ip 2.21.21.21
                pki policy system-default-tunenc-policy
            tunnel-encryption peer-ip 2.22.22.22
                pki policy system-default-tunenc-policy 
            ''')
        time.sleep(120)
    
    @aetest.test
    def verify_RxStatus(self,testbed):
        node=["node3_s1_bgw_1", "node4_s1_bgw_2"]
        i=0
        for i in range(len(node)):
            output1 = json.loads(testbed.devices[node[i]].execute('sh tunnel-encryption session | json'))
            log.info(output1)
            if(output1 == ''):
                self.failed(reason='No tunnel-encryption session')
            a = json.loads(testbed.devices[node[i]].execute('sh tunnel-encryption session | json'))
            item = a["TABLE_tem_session"]["ROW_tem_session"]
            for i in range(len(item)):
                str(item)
                RxStatus = item['RxStatus']
                if not re.search('Secure\s\(AN:\s\d\)', RxStatus):
                    log.info('The tunnel session {0} is not secure. state is {1}'.format(ns.PeerAddr,RxStatus))
                    self.failed(reason="status is not secure")
    @aetest.test
    def verify_RxStatus_S2_BGW1(self,testbed):
        output1 = json.loads(testbed.devices['node7_s2_bgw_1'].execute('sh tunnel-encryption session | json'))
        log.info(output1)
        if(output1 == ''):
            self.failed(reason='No tunnel-encryption session')
        a = json.loads(testbed.devices['node7_s2_bgw_1'].execute('sh tunnel-encryption session | json'))
        item = a["TABLE_tem_session"]["ROW_tem_session"]
        for i in range(len(item)):
            str(item)
            RxStatus = item[i]['RxStatus']
            if not re.search('Secure\s\(AN:\s\d\)', RxStatus):
                log.info('The tunnel session {0} is not secure. state is {1}'.format(ns.PeerAddr,RxStatus))
                self.failed(reason="status is not secure")

    @aetest.test
    def verify_Txstatus(self,testbed):
        node=["node3_s1_bgw_1", "node4_s1_bgw_2"]
        i=0
        for i in range(len(node)):
            output1 = json.loads(testbed.devices[node[i]].execute('sh tunnel-encryption session | json'))
            log.info(output1)
            if(output1 == ''):
                self.failed(reason='No tunnel-encryption session')
            a = json.loads(testbed.devices[node[i]].execute('sh tunnel-encryption session | json'))
            item = a["TABLE_tem_session"]["ROW_tem_session"]
            for i in range(len(item)):
                str(item)
                TxStatus = item['TxStatus']
                if not re.search('Secure\s\(AN:\s\d\)', TxStatus):
                    log.info('The tunnel session {0} is not secure. state is {1}'.format(ns.PeerAddr,TxStatus))
                    self.failed(reason="status is not secure") 
    
    @aetest.test
    def verify_Txstatus_S2_BGW1(self,testbed):
        output1 = json.loads(testbed.devices['node7_s2_bgw_1'].execute('sh tunnel-encryption session | json'))
        log.info(output1)
        if(output1 == ''):
            self.failed(reason='No tunnel-encryption session')
        a = json.loads(testbed.devices['node7_s2_bgw_1'].execute('sh tunnel-encryption session | json'))
        item = a["TABLE_tem_session"]["ROW_tem_session"]
        for i in range(len(item)):
            str(item)
            TxStatus = item[i]['TxStatus']
            if not re.search('Secure\s\(AN:\s\d\)', TxStatus):
                log.info('The tunnel session {0} is not secure. state is {1}'.format(ns.PeerAddr,TxStatus))
                self.failed(reason="status is not secure") 
    
    @aetest.test
    def verify_policy(self,testbed):
        node=["node3_s1_bgw_1", "node4_s1_bgw_2"]
        i=0
        for i in range(len(node)):
            output1 = json.loads(testbed.devices[node[i]].execute('sh tunnel-encryption session | json'))
            log.info(output1)
            if(output1 == ''):
                self.failed(reason='No tunnel-encryption session')
            a = json.loads(testbed.devices[node[i]].execute('sh tunnel-encryption session | json'))
            item = a["TABLE_tem_session"]["ROW_tem_session"]
            for i in range(len(item)):
                str(item)
                PolicyName = item['PolicyName']
                if not re.search('system-default-tunenc-policy', PolicyName):
                    log.info(PolicyName)
                    self.failed(reason="tunnel-encryption policy is not verified")

    @aetest.test
    def verify_policy(self,testbed):
        output1 = json.loads(testbed.devices['node7_s2_bgw_1'].execute('sh tunnel-encryption session | json'))
        log.info(output1)
        if(output1 == ''):
            self.failed(reason='No tunnel-encryption session')
        a = json.loads(testbed.devices['node7_s2_bgw_1'].execute('sh tunnel-encryption session | json'))
        item = a["TABLE_tem_session"]["ROW_tem_session"]
        for i in range(len(item)):
            str(item)
            PolicyName = item[i]['PolicyName']
            if not re.search('system-default-tunenc-policy', PolicyName):
                log.info(PolicyName)
                self.failed(reason="tunnel-encryption policy is not verified")
    
    @aetest.test
    def adding_must_secury_policy(self,testbed):
        node=["node3_s1_bgw_1", "node4_s1_bgw_2", "node7_s2_bgw_1"]
        i=0
        for i in range(len(node)):
            testbed.devices[node[i]].configure("tunnel-encryption must-secure-policy")
            time.sleep(60)
        

    @aetest.test
    def verify_traffic(self,testscript,section):

            if VerifyTraffic(section, testscript):
                self.passed()
            else:
                self.failed()


class ConfigureReplace(nxtest.Testcase):
    @aetest.test
    def config_replace(self, testbed, verify_dict, trigger_wait_time=40):
        LOG.info("Inside config_replace...")
        config_dict = {
            "testbed": testbed,
            "verify_dict": verify_dict}
        configure_replace_obj = ConfigReplace(**config_dict)
        LOG.info("Calling run_trigger..")
        configure_replace_obj.run_trigger(trigger_wait_time=trigger_wait_time)
        LOG.info("Calling verify_trigger..")
        configure_replace_obj.verify_trigger()
        if configure_replace_obj.result == 'fail':
            LOG.error("Configure replace-FAILED")
            self.failed()
        else:
            LOG.info("Configure replace-PASSED")

    # @aetest.test
    # def verify_nve_peers_after_config_replace(self, testbed, trigger_wait_time):
    #     time.sleep(6*trigger_wait_time)
    #     interface_logical_map = self.parameters.get('interface_logical_map')
    #     verify_show_nve_peers(testbed, self.parameters['nve_peers'], interface_logical_map)

class TriggerFlapNve(nxtest.Testcase):
    #"""TC019"""
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

class ProcessRestart(nxtest.Testcase):
    @aetest.test
    def TRIGGER_verify_BGP_process_restart(self, device_dut,testscript,testbed):
        """ ACLQOS_PROCESS_KILL_VERIFICATION subsection: Verify killing process ACLQOS """
        process = ['tun_enc_mgr', 'nve', 'bgp', 'netstack', 'l2fm', 'l2rib', 'arp', 'interface-vlan']
        for node in device_dut:
            device = testbed.devices[node]
            i=0
            for i in range (len(process)):

                if infraTrig.verifyProcessRestart(device, process[i]):
                    log.info("Successfully restarted process ")
                else:
                    log.debug("Failed to restarted process ")
                    self.failed("Failed to restarted process " )
                time.sleep(120)

class ProcessRestart1(nxtest.Testcase):
    @aetest.test
    def TRIGGER_verify_BGP_process_restart(self, device_dut,testscript,testbed):
        """ ACLQOS_PROCESS_KILL_VERIFICATION subsection: Verify killing process ACLQOS """
        process = ['pktmgr', 'l3vm', 'urib', 'u6rib', 'vlan_mgr', 'ipqosmgr', 'aclmgr']
        for node in device_dut:
            device = testbed.devices[node]
            i=0
            for i in range (len(process)):

                if infraTrig.verifyProcessRestart(device, process[i]):
                    log.info("Successfully restarted process ")
                else:
                    log.debug("Failed to restarted process ")
                    self.failed("Failed to restarted process " )
                time.sleep(120)

class ProcessRestart2(nxtest.Testcase):
    @aetest.test
    def TRIGGER_verify_BGP_process_restart(self, device_dut,testscript,testbed):
        """ ACLQOS_PROCESS_KILL_VERIFICATION subsection: Verify killing process ACLQOS """
        process = ['vpc', 'stp', 'otm', 'ifmgr', 'rpm']
        for node in device_dut:
            device = testbed.devices[node]
            i=0
            for i in range (len(process)):

                if infraTrig.verifyProcessRestart(device, process[i]):
                    log.info("Successfully restarted process ")
                else:
                    log.debug("Failed to restarted process ")
                    self.failed("Failed to restarted process " )
                time.sleep(120)

class Block_ISSD_NR2F(nxtest.Testcase):
    @aetest.test
    def verify_ISSD_error(self,testbed):
        msg = '''Service "tun_enc_mgr" in vdc 1: Tunnel Encryption PKI CLIs aren't supported in target image, please un-configure 'pki' from all Tunnel-Encryption peers'''
        output=testbed.devices['node4_s1_bgw_2'].execute(''' install all nxos bootflash:nxos64-cs.10.3.2.F.bin ''')
        time.sleep(60)
        m = re.findall('\w+\s\"tun_enc_mgr"\s\w+\s\w+\s\d:\s\w+\s+\w+\s\w+\s\w+\s\w+\'t\s\w+\s\w+\s\w+\s\w+\,\s\w+\s\w+\-\w+\s\'\w+\'\s\w+\s\w+\s\w+\-\w+\s\w+', output)
        error=(''.join(map(str, m)))
        if msg==error:
            self.passed('Verified ISSD error')
        else:
            self.failed('failed')    

class FabricOspfLinkFlap(nxtest.Testcase):
    @aetest.test
    def fabric_ospf_link_shut(self, testbed, device_dut, wait_time=30):
        flag = True
        for node in device_dut:
            ospf_neighbors_obj = ShowIpOspfNeighborDetail(device=testbed.devices[node])
            ospf_neighbors_dict = ospf_neighbors_obj.parse()
            LOG.info('Calling proc fabric_link_shutdown')
            if ospf_neighbors_dict:
                for ospf_int in \
                        ospf_neighbors_dict['vrf']['default']['address_family']['ipv4']['instance']['p2']['areas'][
                            '0.0.0.0'][
                            'interfaces'].keys():
                    obj = StimuliPortFlap(testbed.devices[node], ospf_int)
                    if obj.pre_check():
                        if obj.action():
                            LOG.info("Ospf Link Flap {} flap -PASSED".format(ospf_int))
                        else:
                            flag = False
                            LOG.error("Ospf Link Flap {} -FAILED".format(ospf_int))
                            break
                    else:
                        LOG.error("Ospf flap -FAILED -precheck coditions FAILED")
                        flag = False
                        break
            else:
                flag = False
            if not flag:
                self.failed("Ospf flap - FAILED")
            time.sleep(int(wait_time))            
    

class Migration_RSA_to_ECC_Certificate(nxtest.Testcase):
    @aetest.test
    def MigrationPKIfromPSKcertificatevPC(self,testbed):
        node=["node3_s1_bgw_1", "node4_s1_bgw_2"]
        i=0
        for i in range(len(node)):
            # trust_point_name = ["node3_s1_bgw_1_ecc_ca", "node4_s1_bgw_2_ecc_ca"]
            # i=0
            # for i in range (len(trust_point_name)):
            testbed.devices[node[i]].configure('''
                no tunnel-encryption must-secure-policy 
                tunnel-encryption peer-ip 3.21.21.21
                    no pki policy system-default-tunenc-policy
                no tunnel-encryption pki trustpoint myCA1
                tunnel-encryption icv
                tunnel-encryption pki trustpoint starcher7_ECC_CA1
                tunnel-encryption pki source-interface cloudsec-loopback        
                tunnel-encryption source-interface loopback0
                tunnel-encryption policy p1
                    sak-rekey-time 1800
                tunnel-encryption peer-ip 3.21.21.21
                    pki policy system-default-tunenc-policy
                ''')
            time.sleep(60)
      
    @aetest.test
    def MigrationPKIfromPSKcertificateStdalone(self,testbed):
        testbed.devices['node7_s2_bgw_1'].configure('''
            no tunnel-encryption must-secure-policy
            tunnel-encryption peer-ip 2.21.21.21
                no pki policy system-default-tunenc-policy
            tunnel-encryption peer-ip 2.22.22.22
                no pki policy system-default-tunenc-policy 
            no tunnel-encryption pki trustpoint myCA1
            tunnel-encryption icv
            tunnel-encryption pki trustpoint starcher7_ECC_CA1
            tunnel-encryption pki source-interface cloudsec-loopback
            tunnel-encryption source-interface loopback0
            tunnel-encryption policy p1
                sak-rekey-time 1800
            tunnel-encryption peer-ip 2.21.21.21
                pki policy system-default-tunenc-policy
            tunnel-encryption peer-ip 2.22.22.22
                pki policy system-default-tunenc-policy 
            ''')
    time.sleep(120)
    
    @aetest.test
    def verify_RxStatus(self,testbed):
        node=["node3_s1_bgw_1", "node4_s1_bgw_2"]
        i=0
        for i in range(len(node)):
            output1 = json.loads(testbed.devices[node[i]].execute('sh tunnel-encryption session | json'))
            log.info(output1)
            if(output1 == ''):
                self.failed(reason='No tunnel-encryption session')
            a = json.loads(testbed.devices[node[i]].execute('sh tunnel-encryption session | json'))
            item = a["TABLE_tem_session"]["ROW_tem_session"]
            for i in range(len(item)):
                str(item)
                RxStatus = item['RxStatus']
                if not re.search('Secure\s\(AN:\s\d\)', RxStatus):
                    log.info('The tunnel session {0} is not secure. state is {1}'.format(ns.PeerAddr,RxStatus))
                    self.failed(reason="status is not secure")
    @aetest.test
    def verify_RxStatus_S2_BGW1(self,testbed):
        output1 = json.loads(testbed.devices['node7_s2_bgw_1'].execute('sh tunnel-encryption session | json'))
        log.info(output1)
        if(output1 == ''):
            self.failed(reason='No tunnel-encryption session')
        a = json.loads(testbed.devices['node7_s2_bgw_1'].execute('sh tunnel-encryption session | json'))
        item = a["TABLE_tem_session"]["ROW_tem_session"]
        for i in range(len(item)):
            str(item)
            RxStatus = item[i]['RxStatus']
            if not re.search('Secure\s\(AN:\s\d\)', RxStatus):
                log.info('The tunnel session {0} is not secure. state is {1}'.format(ns.PeerAddr,RxStatus))
                self.failed(reason="status is not secure")

    @aetest.test
    def verify_Txstatus(self,testbed):
        node=["node3_s1_bgw_1", "node4_s1_bgw_2"]
        i=0
        for i in range(len(node)):
            output1 = json.loads(testbed.devices[node[i]].execute('sh tunnel-encryption session | json'))
            log.info(output1)
            if(output1 == ''):
                self.failed(reason='No tunnel-encryption session')
            a = json.loads(testbed.devices[node[i]].execute('sh tunnel-encryption session | json'))
            item = a["TABLE_tem_session"]["ROW_tem_session"]
            for i in range(len(item)):
                str(item)
                TxStatus = item['TxStatus']
                if not re.search('Secure\s\(AN:\s\d\)', TxStatus):
                    log.info('The tunnel session {0} is not secure. state is {1}'.format(ns.PeerAddr,TxStatus))
                    self.failed(reason="status is not secure") 
    
    @aetest.test
    def verify_Txstatus_S2_BGW1(self,testbed):
        output1 = json.loads(testbed.devices['node7_s2_bgw_1'].execute('sh tunnel-encryption session | json'))
        log.info(output1)
        if(output1 == ''):
            self.failed(reason='No tunnel-encryption session')
        a = json.loads(testbed.devices['node7_s2_bgw_1'].execute('sh tunnel-encryption session | json'))
        item = a["TABLE_tem_session"]["ROW_tem_session"]
        for i in range(len(item)):
            str(item)
            TxStatus = item[i]['TxStatus']
            if not re.search('Secure\s\(AN:\s\d\)', TxStatus):
                log.info('The tunnel session {0} is not secure. state is {1}'.format(ns.PeerAddr,TxStatus))
                self.failed(reason="status is not secure") 
    
    @aetest.test
    def verify_policy(self,testbed):
        node=["node3_s1_bgw_1", "node4_s1_bgw_2"]
        i=0
        for i in range(len(node)):
            output1 = json.loads(testbed.devices[node[i]].execute('sh tunnel-encryption session | json'))
            log.info(output1)
            if(output1 == ''):
                self.failed(reason='No tunnel-encryption session')
            a = json.loads(testbed.devices[node[i]].execute('sh tunnel-encryption session | json'))
            item = a["TABLE_tem_session"]["ROW_tem_session"]
            for i in range(len(item)):
                str(item)
                PolicyName = item['PolicyName']
                if not re.search('system-default-tunenc-policy', PolicyName):
                    log.info(PolicyName)
                    self.failed(reason="tunnel-encryption policy is not verified")

    @aetest.test
    def verify_policy(self,testbed):
        output1 = json.loads(testbed.devices['node7_s2_bgw_1'].execute('sh tunnel-encryption session | json'))
        log.info(output1)
        if(output1 == ''):
            self.failed(reason='No tunnel-encryption session')
        a = json.loads(testbed.devices['node7_s2_bgw_1'].execute('sh tunnel-encryption session | json'))
        item = a["TABLE_tem_session"]["ROW_tem_session"]
        for i in range(len(item)):
            str(item)
            PolicyName = item[i]['PolicyName']
            if not re.search('system-default-tunenc-policy', PolicyName):
                log.info(PolicyName)
                self.failed(reason="tunnel-encryption policy is not verified")

    @aetest.test
    def adding_must_secury_policy(self,testbed):
        node=["node3_s1_bgw_1", "node4_s1_bgw_2", "node7_s2_bgw_1"]
        i=0
        for i in range(len(node)):
            testbed.devices[node[i]].configure("tunnel-encryption must-secure-policy")
            time.sleep(30)
        

    @aetest.test
    def verify_traffic(self,testscript,section):

            if VerifyTraffic(section, testscript):
                self.passed()
            else:
                self.failed()

class Migration_PSK_to_PKI_with_ECC_Certificate(nxtest.Testcase):
    @aetest.test
    def convertingPSK_certificatevPC(self,testbed):
        node=["node3_s1_bgw_1", "node4_s1_bgw_2"]
        i=0
        for i in range(len(node)):
            # trust_point_name = ["node3_s1_bgw_1_ecc_ca", "node4_s1_bgw_2_ecc_ca"]
            # i=0
            # for i in range (len(trust_point_name)):
            testbed.devices[node[i]].configure('''
                no tunnel-encryption must-secure-policy 
                tunnel-encryption peer-ip 3.21.21.21
                    no pki policy system-default-tunenc-policy
                no tunnel-encryption pki trustpoint myCA1
                tunnel-encryption icv
                tunnel-encryption pki source-interface cloudsec-loopback        
                tunnel-encryption source-interface loopback0
                tunnel-encryption policy p1
                    sak-rekey-time 1800
                tunnel-encryption peer-ip 3.21.21.21
                    keychain KC1 policy p1
                ''')
            time.sleep(60)
      
    @aetest.test
    def convertingPKSstandalonecertificateStdalone(self,testbed):
        testbed.devices['node7_s2_bgw_1'].configure('''
            no tunnel-encryption must-secure-policy
            tunnel-encryption peer-ip 2.21.21.21
                no pki policy system-default-tunenc-policy
            tunnel-encryption peer-ip 2.22.22.22
                no pki policy system-default-tunenc-policy 
            no tunnel-encryption pki trustpoint myCA1
            tunnel-encryption icv
            tunnel-encryption pki source-interface cloudsec-loopback
            tunnel-encryption source-interface loopback0
            tunnel-encryption policy p1
                sak-rekey-time 1800
            tunnel-encryption peer-ip 2.21.21.21
                keychain KC1 policy p1
            tunnel-encryption peer-ip 2.22.22.22
                keychain KC1 policy p1
            ''')
    time.sleep(120)
    @aetest.test
    def verify_RxStatus1(self,testbed):
        node=["node3_s1_bgw_1", "node4_s1_bgw_2"]
        i=0
        for i in range(len(node)):
            output1 = json.loads(testbed.devices[node[i]].execute('sh tunnel-encryption session | json'))
            log.info(output1)
            if(output1 == ''):
                self.failed(reason='No tunnel-encryption session')
            a = json.loads(testbed.devices[node[i]].execute('sh tunnel-encryption session | json'))
            item = a["TABLE_tem_session"]["ROW_tem_session"]
            for i in range(len(item)):
                str(item)
                RxStatus = item['RxStatus']
                if not re.search('Secure\s\(AN:\s\d\)', RxStatus):
                    log.info('The tunnel session {0} is not secure. state is {1}'.format(ns.PeerAddr,RxStatus))
                    self.failed(reason="status is not secure")
    @aetest.test
    def verify_RxStatus1_S2_BGW1(self,testbed):
        output1 = json.loads(testbed.devices['node7_s2_bgw_1'].execute('sh tunnel-encryption session | json'))
        log.info(output1)
        if(output1 == ''):
            self.failed(reason='No tunnel-encryption session')
        a = json.loads(testbed.devices['node7_s2_bgw_1'].execute('sh tunnel-encryption session | json'))
        item = a["TABLE_tem_session"]["ROW_tem_session"]
        for i in range(len(item)):
            str(item)
            RxStatus = item[i]['RxStatus']
            if not re.search('Secure\s\(AN:\s\d\)', RxStatus):
                log.info('The tunnel session {0} is not secure. state is {1}'.format(ns.PeerAddr,RxStatus))
                self.failed(reason="status is not secure")

    @aetest.test
    def verify_Txstatus2(self,testbed):
        node=["node3_s1_bgw_1", "node4_s1_bgw_2"]
        i=0
        for i in range(len(node)):
            output1 = json.loads(testbed.devices[node[i]].execute('sh tunnel-encryption session | json'))
            log.info(output1)
            if(output1 == ''):
                self.failed(reason='No tunnel-encryption session')
            a = json.loads(testbed.devices[node[i]].execute('sh tunnel-encryption session | json'))
            item = a["TABLE_tem_session"]["ROW_tem_session"]
            for i in range(len(item)):
                str(item)
                TxStatus = item['TxStatus']
                if not re.search('Secure\s\(AN:\s\d\)', TxStatus):
                    log.info('The tunnel session {0} is not secure. state is {1}'.format(ns.PeerAddr,TxStatus))
                    self.failed(reason="status is not secure") 
    
    @aetest.test
    def verify_Txstatus2_S2_BGW1(self,testbed):
        output1 = json.loads(testbed.devices['node7_s2_bgw_1'].execute('sh tunnel-encryption session | json'))
        log.info(output1)
        if(output1 == ''):
            self.failed(reason='No tunnel-encryption session')
        a = json.loads(testbed.devices['node7_s2_bgw_1'].execute('sh tunnel-encryption session | json'))
        item = a["TABLE_tem_session"]["ROW_tem_session"]
        for i in range(len(item)):
            str(item)
            TxStatus = item[i]['TxStatus']
            if not re.search('Secure\s\(AN:\s\d\)', TxStatus):
                log.info('The tunnel session {0} is not secure. state is {1}'.format(ns.PeerAddr,TxStatus))
                self.failed(reason="status is not secure") 
    @aetest.test
    def MigrationPSkwithPKIECCcertificatevPC(self,testbed):
        node=["node3_s1_bgw_1", "node4_s1_bgw_2"]
        i=0
        for i in range(len(node)):
            # trust_point_name = ["node3_s1_bgw_1_ecc_ca", "node4_s1_bgw_2_ecc_ca"]
            # i=0
            # for i in range (len(trust_point_name)):
            testbed.devices[node[i]].configure('''
                no tunnel-encryption must-secure-policy 
                tunnel-encryption peer-ip 3.21.21.21
                    no keychain KC1 policy p1
                tunnel-encryption icv
                tunnel-encryption pki trustpoint starcher7_ECC_CA1
                tunnel-encryption pki source-interface cloudsec-loopback        
                tunnel-encryption source-interface loopback0
                tunnel-encryption policy p1
                    sak-rekey-time 1800
                tunnel-encryption peer-ip 3.21.21.21
                    pki policy system-default-tunenc-policy
                ''')
            time.sleep(60)
      
    @aetest.test
    def MigrationPKIfromPSKcertificateStdalone(self,testbed):
        testbed.devices['node7_s2_bgw_1'].configure('''
            no tunnel-encryption must-secure-policy
            tunnel-encryption peer-ip 2.21.21.21
                no keychain KC1 policy p1
            tunnel-encryption peer-ip 2.22.22.22
                no keychain KC1 policy p1 
            tunnel-encryption icv
            tunnel-encryption pki trustpoint starcher7_ECC_CA1
            tunnel-encryption pki source-interface cloudsec-loopback
            tunnel-encryption source-interface loopback0
            tunnel-encryption policy p1
                sak-rekey-time 1800
            tunnel-encryption peer-ip 2.21.21.21
                pki policy system-default-tunenc-policy
            tunnel-encryption peer-ip 2.22.22.22
                pki policy system-default-tunenc-policy 
            ''')
    time.sleep(120)
    
    @aetest.test
    def verify_RxStatus(self,testbed):
        node=["node3_s1_bgw_1", "node4_s1_bgw_2"]
        i=0
        for i in range(len(node)):
            output1 = json.loads(testbed.devices[node[i]].execute('sh tunnel-encryption session | json'))
            log.info(output1)
            if(output1 == ''):
                self.failed(reason='No tunnel-encryption session')
            a = json.loads(testbed.devices[node[i]].execute('sh tunnel-encryption session | json'))
            item = a["TABLE_tem_session"]["ROW_tem_session"]
            for i in range(len(item)):
                str(item)
                RxStatus = item['RxStatus']
                if not re.search('Secure\s\(AN:\s\d\)', RxStatus):
                    log.info('The tunnel session {0} is not secure. state is {1}'.format(ns.PeerAddr,RxStatus))
                    self.failed(reason="status is not secure")
    @aetest.test
    def verify_RxStatus_S2_BGW1(self,testbed):
        output1 = json.loads(testbed.devices['node7_s2_bgw_1'].execute('sh tunnel-encryption session | json'))
        log.info(output1)
        if(output1 == ''):
            self.failed(reason='No tunnel-encryption session')
        a = json.loads(testbed.devices['node7_s2_bgw_1'].execute('sh tunnel-encryption session | json'))
        item = a["TABLE_tem_session"]["ROW_tem_session"]
        for i in range(len(item)):
            str(item)
            RxStatus = item[i]['RxStatus']
            if not re.search('Secure\s\(AN:\s\d\)', RxStatus):
                log.info('The tunnel session {0} is not secure. state is {1}'.format(ns.PeerAddr,RxStatus))
                self.failed(reason="status is not secure")

    @aetest.test
    def verify_Txstatus(self,testbed):
        node=["node3_s1_bgw_1", "node4_s1_bgw_2"]
        i=0
        for i in range(len(node)):
            output1 = json.loads(testbed.devices[node[i]].execute('sh tunnel-encryption session | json'))
            log.info(output1)
            if(output1 == ''):
                self.failed(reason='No tunnel-encryption session')
            a = json.loads(testbed.devices[node[i]].execute('sh tunnel-encryption session | json'))
            item = a["TABLE_tem_session"]["ROW_tem_session"]
            for i in range(len(item)):
                str(item)
                TxStatus = item['TxStatus']
                if not re.search('Secure\s\(AN:\s\d\)', TxStatus):
                    log.info('The tunnel session {0} is not secure. state is {1}'.format(ns.PeerAddr,TxStatus))
                    self.failed(reason="status is not secure") 
    
    @aetest.test
    def verify_Txstatus_S2_BGW1(self,testbed):
        output1 = json.loads(testbed.devices['node7_s2_bgw_1'].execute('sh tunnel-encryption session | json'))
        log.info(output1)
        if(output1 == ''):
            self.failed(reason='No tunnel-encryption session')
        a = json.loads(testbed.devices['node7_s2_bgw_1'].execute('sh tunnel-encryption session | json'))
        item = a["TABLE_tem_session"]["ROW_tem_session"]
        for i in range(len(item)):
            str(item)
            TxStatus = item[i]['TxStatus']
            if not re.search('Secure\s\(AN:\s\d\)', TxStatus):
                log.info('The tunnel session {0} is not secure. state is {1}'.format(ns.PeerAddr,TxStatus))
                self.failed(reason="status is not secure") 
    
    @aetest.test
    def verify_policy(self,testbed):
        node=["node3_s1_bgw_1", "node4_s1_bgw_2"]
        i=0
        for i in range(len(node)):
            output1 = json.loads(testbed.devices[node[i]].execute('sh tunnel-encryption session | json'))
            log.info(output1)
            if(output1 == ''):
                self.failed(reason='No tunnel-encryption session')
            a = json.loads(testbed.devices[node[i]].execute('sh tunnel-encryption session | json'))
            item = a["TABLE_tem_session"]["ROW_tem_session"]
            for i in range(len(item)):
                str(item)
                PolicyName = item['PolicyName']
                if not re.search('system-default-tunenc-policy', PolicyName):
                    log.info(PolicyName)
                    self.failed(reason="tunnel-encryption policy is not verified")

    @aetest.test
    def verify_policy(self,testbed):
        output1 = json.loads(testbed.devices['node7_s2_bgw_1'].execute('sh tunnel-encryption session | json'))
        log.info(output1)
        if(output1 == ''):
            self.failed(reason='No tunnel-encryption session')
        a = json.loads(testbed.devices['node7_s2_bgw_1'].execute('sh tunnel-encryption session | json'))
        item = a["TABLE_tem_session"]["ROW_tem_session"]
        for i in range(len(item)):
            str(item)
            PolicyName = item[i]['PolicyName']
            if not re.search('system-default-tunenc-policy', PolicyName):
                log.info(PolicyName)
                self.failed(reason="tunnel-encryption policy is not verified")

    @aetest.test
    def adding_must_secury_policy(self,testbed):
        node=["node3_s1_bgw_1", "node4_s1_bgw_2", "node7_s2_bgw_1"]
        i=0
        for i in range(len(node)):
            testbed.devices[node[i]].configure("tunnel-encryption must-secure-policy")
            time.sleep(30)
        

    @aetest.test
    def verify_traffic(self,testscript,section):

            if VerifyTraffic(section, testscript):
                self.passed()
            else:
                self.failed()


class RestartTEM(nxtest.Testcase):
    @aetest.test
    def TRIGGER_verify_BGP_process_restart(self, device_dut,testscript,testbed):
        """ ACLQOS_PROCESS_KILL_VERIFICATION subsection: Verify killing process ACLQOS """
        process = ['tun_enc_mgr']
        for node in device_dut:
            device = testbed.devices[node]
            i=0
            for i in range (len(process)):

                if infraTrig.verifyProcessRestart(device, process[i]):
                    log.info("Successfully restarted process ")
                else:
                    log.debug("Failed to restarted process ")
                    self.failed("Failed to restarted process " )
                time.sleep(120)


class ChangePKITunnelPolicy(nxtest.Testcase):
    @aetest.test
    def change_tunnel_policy(self, testbed, device_dut, policy_dict, trigger_wait_time):
        from lib.utils.vxlan_utils import get_tunnel_params, verify_tunnel_sessions
        LOG.info("Starting the trigger")
        for node in device_dut.keys():
            device = testbed.devices[node]
            policy_name = policy_dict.get('policy_name')
            cipher_suite = policy_dict.get('cipher_suite')
            rekey_time =  policy_dict.get('rekey_time')
            device.configure("tunnel-encryption policy {0} \n cipher-suite {1} \n sak-rekey-time {2}".format(policy_name,cipher_suite,rekey_time))

        device1 = testbed.devices[list(device_dut.keys())[0]]
        tunnel_session_out = []
        tunnel_out = get_tunnel_params(device1)
        if not tunnel_out:
            LOG.error("tunnel output is empty.check tunnel sessions and show json-pretty output")
            self.failed()
        if type(tunnel_out) is dict:
            tunnel_session_out.append(tunnel_out)
        if type(tunnel_out) is list:
            tunnel_session_out = tunnel_out
        if tunnel_session_out:
            for tunnel_params in tunnel_session_out:
                for node, peerip in device_dut.items():
                    device = testbed.devices[node]
                    device.configure(
                        "tunnel-encryption peer-ip {0} \n no pki policy {1}".format(peerip,
                                                                                    tunnel_params[
                                                                                    'PolicyName']))
                for node, peerip in device_dut.items():
                    device = testbed.devices[node]
                    device.configure(
                        "tunnel-encryption peer-ip {0} \n pki policy {1}".format(peerip,
                                                                                             policy_name))
                    device.execute('copy running-config startup-config')
        time.sleep(trigger_wait_time)
        tunnel_session = verify_tunnel_sessions(device1, tunnel_params['PeerAddr'])
        if tunnel_session:
            LOG.error("tunnel session is in pending state for peer {0}".format(tunnel_params['PeerAddr']))
            self.failed()

class VpcPeerlinkFlap(nxtest.Testcase):
    @aetest.test
    def trigger_peerLink_flap(self, testbed, device_dut, converge_time=360, eor=False):
        for node in device_dut:
            if eor:
                device = testbed.devices[node]
                obj = ShowModule(device=device)
                mod_dict = obj.parse()
                if not mod_dict['slot'].get('lc'):
                    LOG.error("The device provided is not EOR, so skipping the trigger")
                    #self.failed()
                    self.skipped("The device is not EOR, trigger is not valid", goto=['next_tc'])
            perform_mct_port_flap(testbed, node)
            LOG.info("Sleeping for 60 seconds")
            time.sleep(converge_time)

class FlapInterface(nxtest.Testcase):

    @aetest.test
    def trigger_Interface_flap(self, testbed, device_dut, interface , converge_time=360):
        for node in device_dut:
            device = testbed.devices[node]
            LOG.info("Starting interface flap trigger")
            device = testbed.devices[node]
            obj = StimuliPortFlap(device, interface)
            time.sleep(converge_time)
            obj.pre_check()
            time.sleep(converge_time)
            obj.action()
            time.sleep(converge_time)

class TriggerFlapVrf(nxtest.Testcase):
    @aetest.test
    def flap_vrf(self, steps, testbed, device_dut, vrfs, shut = True, trigger_wait_time=300, unshut = True,):
        for node in device_dut:
            LOG.info('Flap vrf on node %s', node)
            device = testbed.devices[node]
            obj = StimuliFlapVrfs(device, vrfs, shut, unshut)
            time.sleep(trigger_wait_time)
            obj.pre_check()
            time.sleep(trigger_wait_time)
            obj.action()
            time.sleep(trigger_wait_time)

def perform_mct_port_flap(testbed, node):
    device = testbed.devices[node]
    obj = ShowVpc(device=device)
    vpc_dict = obj.parse()
    peer_link_dict = vpc_dict.get('peer_link')
    peer_link_info = list(peer_link_dict.values())
    mct_po = peer_link_info[0].get('peer_link_ifindex')
    obj = ShowInterfaceStatus(device=device)
    intf_parsed_output = obj.parse(interface=mct_po)
    assert 'connected' in intf_parsed_output['interfaces'].get(mct_po).get(
            'status'), "The vpc peer link is not up, cannot proceed with the trigger"
    obj = StimuliPortFlap(device, mct_po)
    obj.pre_check()
    obj.action()
    return device







'''self-signed certificate using openssl.
   Generating public key(.pem) and private key(.key) using openssl.
   Same ca(.pem and .key) for all switches.
'''
def openssl_sign_certificate_request(testbed, device_dut,cmd_wait_time):
    LOG.info("===In openssl_sign_certificate_request===")
    ca_file_flag = False
    ca_cert_lst = ['CAPrivate.pem', 'CAPrivate.key']
    LOG.info("===In openssl_sign_certificate_request===")
    openssl_key_cmd ="openssl genrsa -out CAPrivate.key 2048"
    openssl_pem = 'openssl req -x509 -new -nodes -key CAPrivate.key -sha256 -days 365 -out CAPrivate.pem '
    openssl_pem_cmd = openssl_pem+ "-subj " + '"/C=US/ST=CA/L=Earth/O=Cisco/OU=IT/CN=www.example.com/emailAddress=jolickal@cisco.com"'

    device = testbed.devices[device_dut[0]]
    with device.bash_console() as bash:
        bash.execute('cd /bootflash/')
        bash.execute(openssl_key_cmd)
        bash.execute(openssl_pem_cmd)
    time.sleep(cmd_wait_time)

    '''Checking .key and pem generated or not and also file size'''
    node = device_dut[0]
    for ca_cert in ca_cert_lst:
        ca_key_out = device.execute("dir " + "|grep " + '"' +ca_cert+'"')
        if str(ca_key_out).strip():
            LOG.info("===%s file found in bootflash for node %s===",ca_cert,node)
            file_size = str(ca_key_out).strip().split(" ")[0]
            if int(file_size) > 300:
                LOG.info("===%s file size in bootflash is greater than 300 bytes===>%s",ca_cert,file_size)
                ca_file_flag = True
            else:
                LOG.error("===%s file size in bootflash is less than 300 bytes===>%s",ca_cert,file_size)
                ca_file_flag = False
                return ca_file_flag
        else:
            LOG.error("===%s file not found in bootflash for node %s===",ca_cert,node)
            ca_file_flag = False
            return ca_file_flag
        time.sleep(2)

    return ca_file_flag

'''Create a trust point and verifying trust point'''
def add_trust_point(testbed, device_dut,cmd_wait_time,trust_point_name):
    LOG.info("===In add_trust_point===")
    trust_flag =  False
    for node in device_dut:
        device = testbed.devices[node]
        device.configure('crypto ca trustpoint {}'.format(str(trust_point_name)))
        time.sleep(5)


    time.sleep(cmd_wait_time)
    for node in device_dut:
        device = testbed.devices[node]
        trust_point_out = device.execute('show crypto ca trustpoints |grep trustpoint')
        if str(trust_point_out.split(";")[0].split(":")[-1]).strip() ==trust_point_name:
            LOG.info("===trust point created for node %s===>",device)
            trust_flag = True
        else:
            LOG.error("===trust point not created for node %s===>",device)
            trust_flag =  False
    return trust_flag

'''Create a RSA/ECC key pair and verifying it'''
def add_rsa_ecc_pair(testbed, device_dut,cmd_wait_time,rsa_label,cert_size):
    LOG.info("===In add_rsa_ecc_pair===")
    rsa_ecc_flag =  False
    key_search_str = 'key label'


    '''RSA key pair for the device'''
    for node in device_dut:
        device = testbed.devices[node]
        device.configure('crypto key generate rsa label {rsa_label} exportable modulus {cer_size}'.format(rsa_label=rsa_label,
                                                                                             cer_size=cert_size))

    time.sleep(cmd_wait_time)

    '''Verification of RSA key pair for the device'''
    LOG.info("===Verifying RSA key pair===")
    for node in device_dut:
        device = testbed.devices[node]
        key_label_out = device.execute("show crypto key mypubkey rsa "+ "|grep " +'"'+key_search_str+'"')
        if str(key_label_out.split(":")[-1]).strip() ==rsa_label:
            LOG.info("===rsa key pair created for node %s===>",device)
            rsa_ecc_flag = True
        else:
            LOG.error("===rsa key pair not created for node %s===>",device)
            rsa_ecc_flag =  False
            return rsa_ecc_flag


    '''ECC key pair'''
    for node in device_dut:
        ecc_key_name = "{node_name}_ecc_ca".format(node_name=node)
        device = testbed.devices[node]
        device.configure('crypto key generate ecc label {ecc_ca_node_name} exportable modulus 224'.format(ecc_ca_node_name=ecc_key_name))

    time.sleep(cmd_wait_time)
    '''Verification of ECC key pair for the device'''
    LOG.info("===Verifying ECC key pair===")
    for node in device_dut:
        device = testbed.devices[node]
        ecc_key_name = "{node_name}_ecc_ca".format(node_name=node)
        key_label_out = device.execute("show crypto key mypubkey ecc "+ "|grep " +'"'+key_search_str+'"')
        if str(key_label_out.split(":")[-1]).strip() ==ecc_key_name:
            LOG.info("===ecc key pair created for node %s===>",device)
            rsa_ecc_flag = True
        else:
            LOG.error("===ecc key pair not created for node %s===>",device)
            rsa_ecc_flag =  False
            return rsa_ecc_flag

    return rsa_ecc_flag

'''Associate the RSA/ECC key pair to the trust point and verifying it'''
def add_rsa_key_pair_to_trust_point(testbed, device_dut,cmd_wait_time,trust_point_name,rsa_label):
    LOG.info("===In add_rsa_key_pair_to_trust_point===")
    rsa_cmd_list = []
    rsa_cmd_list.append('crypto ca trustpoint {}'.format(str(trust_point_name)))
    rsa_cmd_list.append("rsakeypair {}".format(str(rsa_label)))
    for node in device_dut:
        device = testbed.devices[node]
        device.configure(rsa_cmd_list)
        time.sleep(2)
    time.sleep(cmd_wait_time)

    # time.sleep(cmd_wait_time)
    # for node in device_dut:
    #     key_pair = False
    #     device = testbed.devices[node]
    #     rsa_key_pair_out = device.execute('show crypto ca trustpoints |grep key-pair')
    #     if str(rsa_key_pair_out.split(";")[1].split(":")[-1]).strip() ==rsa_label:
    #         LOG.info("===RSA key pair to the trust point added %s===>",device)
    #         key_pair = True
    #     else:
    #         LOG.error("===RSA key pair to the trust point not added %s===>",device)
    #         rsa_key_pair = False
    #         return key_pair
    #     time.sleep(2)

    for node in device_dut:
        device = testbed.devices[node]
        ecc_ca_name = "{node_name}_ecc_ca".format(node_name=node)
        device.configure('crypto ca trustpoint  {ecc_name} \n ecckeypair {ecc_key_pair}'.format(ecc_name=ecc_ca_name,ecc_key_pair=ecc_ca_name))
        time.sleep(2)

    time.sleep(cmd_wait_time)


    for node in device_dut:
        key_pair = False
        lst_key_pair = []
        lst_key_pair = [rsa_label]
        device = testbed.devices[node]
        ecc_ca_name = "{node_name}_ecc_ca".format(node_name=node)
        lst_key_pair.append(ecc_ca_name)
        rsa_key_pair_out = device.execute('show crypto ca trustpoints |grep key-pair')
        cnt_key_pair = 0
        for rsa_out in rsa_key_pair_out.splitlines():
            rsa_out = rsa_out.strip()
            if str(rsa_out.split(";")[1].split(":")[-1]).strip() ==lst_key_pair[cnt_key_pair]:
                LOG.info("===key-pair to the trust point added %s===>",device)
                key_pair = True
            else:
                LOG.error("===key-pair to the trust point not added %s===>",device)
                key_pair = False
            cnt_key_pair = cnt_key_pair + 1

    return key_pair

'''Checking ca pem and key file in bootflash of all switches'''
def ca_files_download_and_check(testbed, device_dut,cmd_wait_time):
    LOG.info("===In ca_files_download_and_check===")
    '''Since certificate is common for all switches(CAPrivate.pem & CAPrivate.key), taking content from first switch,
       and copy the ca certificate(.pem,.key) content from bootflash and save it into a file in cloudsec_pki folder
    '''
    LOG.info("===In ca_files_download_and_check===")
    ca_cert_lst = ['CAPrivate.pem', 'CAPrivate.key']
    ca_file_check = False
    for ca_cert in ca_cert_lst:
        pem_node = device_dut[0]
        device_pem = testbed.devices[pem_node]
        pem_out = device_pem.execute('show file bootflash:'+ca_cert)
        cloud_sec_file_path_ca = "/tmp/{}".format(ca_cert)
        pem_config_file = open(cloud_sec_file_path_ca, "w")
        pem_config_file.write(pem_out)
        pem_config_file.close()
        time.sleep(2)
    time.sleep(cmd_wait_time)

    '''copy CAPrivate.pem file from cloudec_pki folder to bootflash for remaining two switches'''
    for pem_node in device_dut[1:]:
        LOG.info("===Start copying %s to bootflash for node===%s",ca_cert_lst[0],pem_node)
        device = testbed.devices[pem_node]
        device.configure('feature scp-server')
        directory = os.getcwd()
        paramiko.common.logging.basicConfig(level=paramiko.common.DEBUG)
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        username=device.credentials['default'].get('username')
        password=to_plaintext(device.credentials['default'].get('password'))
        hostname=str(device.connections.get('vty').get('ip'))
        log.info(username)
        log.info(password)
        log.info(hostname)
        ssh.connect(username='admin',password='nbv12345',hostname='10.197.127.57',allow_agent=False,look_for_keys=False,port=22,timeout=600)

        path = '/bootflash/' + ca_cert_lst[0]
        LOG.info("===path===>%s and on node %s===>",path,pem_node)
        with SCPClient(ssh.get_transport()) as scp:
            scp.get(path)
            LOG.info("===%s file copied to bootflash for node %s===",ca_cert_lst[0],pem_node)
        ssh.close()
        time.sleep(5)


    '''copy CAPrivate.key file from cloudec_pki folder to bootflash for remaining two switches'''
    for key_node in device_dut[1:]:
        LOG.info("===Start copying %s to bootflash for node===%s",ca_cert_lst[1],pem_node)
        device = testbed.devices[key_node]
        device.configure('feature scp-server')
        directory = os.getcwd()
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh.connect(username='admin',password='nbv12345',hostname='10.197.127.57',allow_agent=False,look_for_keys=False,port=22,timeout=600)
        # ssh.connect(username=str(device.credentials['default'].get('username')),password=str(to_plaintext(device.credentials['default'].get('password'))),hostname=str(device.connections.get('vty').get('ip')),allow_agent=False,look_for_keys=False,port=22,timeout=600)

        path = '/bootflash/' + ca_cert_lst[1]
        LOG.info("===path===>%s and on node %s===>",path,key_node)
        with SCPClient(ssh.get_transport()) as scp:
            scp.get(path)
            LOG.info("===%s file copied to bootflash for node %s===",ca_cert_lst[1],key_node)
        ssh.close()
        time.sleep(5)

    '''Checking .key,.pem file copied into bootflash of all switches'''
    for node in device_dut:
        device = testbed.devices[node]
        for ca_cert in ca_cert_lst:
            ca_key_out = device.execute("dir " + "|grep " + '"' +ca_cert+'"')
            if str(ca_key_out).strip():
                LOG.info("===%s file found in bootflash for node %s===",ca_cert,node)
                ca_file_check = True
            else:
                LOG.error("===%s file not found in bootflash for node %s===",ca_cert,node)
                ca_file_check = False
                return ca_file_check
            time.sleep(2)

    time.sleep(cmd_wait_time)
    return ca_file_check

'''Authenticate the CA that want to enroll to the trust point'''
def insert_and_authenticate_ca_cert(testbed, device_dut,cmd_wait_time,trust_point_name):
    LOG.info("===In insert_and_authenticate_ca_cert===")
    end_of_input_str = "END OF INPUT"
    crypto_cert_flag = False
    ca_cert_lst = ['CAPrivate.pem', 'CAPrivate.key']

    '''Reading the ca .pem file from cloudsec_pki folder and inserting the certificate for authentication'''
    cloud_sec_file_path_pem = "/bootflash/{}".format(ca_cert_lst[0])
    for node in device_dut:
        device = testbed.devices[node]
        authenticate_cmd = "crypto ca authenticate {0} pemfile bootflash:{1}".format(trust_point_name, ca_cert_lst[0])
        try:
            '''Step2 '''
            def insert_certificate(spawn):
                begin_flag = False
                with open(cloud_sec_file_path_pem) as fp:
                    line = fp.readline()
                    if 'BEGIN CERTIFICATE' in line:
                        spawn.sendline(line.strip())
                        begin_flag = True
                    while line:
                        line = fp.readline()
                        if begin_flag:
                            spawn.sendline(line.strip())
                        if 'BEGIN CERTIFICATE' in line:
                            spawn.sendline(line.strip())
                            begin_flag = True
                        if 'END CERTIFICATE' in line:
                            break
                fp.close()
                '''Step3 dialog'''
                reply_dialog = Dialog([
                    Statement(pattern=r'Do you accept this certificate'.strip(),
                              action='sendline(yes)',
                              loop_continue=False,
                              continue_timer=False)
                ])
                device.configure(end_of_input_str,timeout=cmd_wait_time, reply=reply_dialog)

            '''Step1 dialog'''
            dialog = Dialog([
                Statement(pattern=r'end the input with a line containing only END OF INPUT :',
                          action=insert_certificate,
                          loop_continue=False,
                          continue_timer=False)
            ])
            device.configure(authenticate_cmd,timeout=cmd_wait_time, reply=dialog)

        except Exception:
            LOG.error('Fail: Exception found ', exc_info=True)

    time.sleep(cmd_wait_time)

    '''Verifying crypto ca certificates'''
    for node in device_dut:
        crypto_cert_flag = False
        device = testbed.devices[node]
        trust_point_lst = []
        trust_cnt = 0
        ecc_ca_name = "{node_name}_ecc_ca".format(node_name=node)
        trust_point_lst = [trust_point_name]
        trust_point_lst.append(ecc_ca_name)
        trust_point_out = device.execute('show crypto ca certificates |i i Trustpoint')
        for trust_out in trust_point_out.splitlines():
            trust_out = trust_out.strip()
            if str(trust_out.split(":")[-1]).strip() == trust_point_lst[trust_cnt]:
                LOG.info("===rsa/ecc trust point found in ca certificates for node %s===>",device)
                crypto_cert_flag = True
            else:
                LOG.error("===rsa/ecc trust point not found in ca certificates for node %s===>",device)
                crypto_cert_flag =  False
                return crypto_cert_flag
            trust_cnt = trust_cnt + 1

    return crypto_cert_flag

'''Create csr certificate request'''
def create_csr_certificate_request(testbed, device_dut,cmd_wait_time,trust_point_name):
    LOG.info("===In create_csr_certificate_request===")
    csr_certificate_cmd = "crypto ca enroll {}".format(trust_point_name)

    for node in device_dut:
        csr_out_file_name = "CSR_Response{node}".format(node=node)
        csr_out_response_path = "/bootflash/{}".format(csr_out_file_name)
        # csr_out_response_path = "/tmp/{}".format(csr_out_file_name)
        device = testbed.devices[node]
        nve_interface_detail = ShowNveInterfaceDetail(testbed.devices[node]).cli()
        csr_ip = nve_interface_detail['nve1'].get('primary_ip')
        LOG.info("===Ip address returned is===>%s",csr_ip)
        try:
            '''Step2 dialog'''
            def csr_certificate_inputs(spawn):
                spawn.sendline('nbv123')
                switch_serial = Dialog([
                    Statement(pattern=r'IP address in the subject name'.strip(),
                              action=csr_ip_addr,
                              loop_continue=False,
                              continue_timer=False)
                ])
                device.configure('no',timeout=cmd_wait_time, reply=switch_serial)
            '''Step3 dialog'''
            def csr_ip_addr(spawn):
                spawn.sendline('yes')
                switch_ip_addr = Dialog([
                    Statement(pattern=r'Alternate Subject Name'.strip(),
                              action='sendline(no)',
                              loop_continue=False,
                              continue_timer=False)
                ])
                '''Step4 dialog Saving csr request certificate into /cloudsec_pki folder'''

                with open(csr_out_response_path, "w") as f, contextlib.redirect_stdout(f):
                    device.config(csr_ip,timeout=cmd_wait_time, reply=switch_ip_addr)
                f.close()
                # with open(csr_out_response_path, 'w') as f:
                #     with contextlib.redirect_stdout(f):
                #         device.config(csr_ip,timeout=cmd_wait_time, reply=switch_ip_addr)
                # f.close()
            '''Step1 dialog'''
            dialog = Dialog([
                Statement(pattern=r'Password',
                          action=csr_certificate_inputs,
                          loop_continue=False,
                          continue_timer=False)
            ])
            device.configure(csr_certificate_cmd,timeout=cmd_wait_time, reply=dialog)

        except Exception:
            LOG.error('Fail: Exception found ', exc_info=True)

    time.sleep(5)

'''Genertaing csr certificate files'''
def create_csr_certificate_files(testbed, device_dut,cmd_wait_time):

    LOG.info("===In create_csr_certificate_files===")
    '''Create .csr files and saving it into external location'''
    for node in device_dut:
        csr_file_flag = False
        csr_out_file_name = "CSR_Response{node}".format(node=node)
        csr_out_response_path = "/bootflash/{}".format(csr_out_file_name)
        # csr_out_response_path = "/tmp/{}".format(csr_out_file_name)
        csr_certificate_name = "{node}.csr".format(node=node)
        csr_certificate_path = "/bootflash/{}".format(csr_certificate_name)
        # csr_certificate_path = "/tmp/{}".format(csr_certificate_name)
        LOG.info("===csr_out_response_path===>%s",csr_out_response_path)
        LOG.info("===csr_certificate_path===>%s",csr_certificate_path)

        '''Reading certificate from CSR Response file and creating a .csr file'''
        read_begin_flag = False

        with open(csr_out_response_path,'r') as rfp:
            with open(csr_certificate_path,"w") as wfp:
                next_line = rfp.readline()
                while next_line:
                    next_line = rfp.readline()
                    if read_begin_flag:
                        wfp.write(next_line)
                    if 'BEGIN CERTIFICATE' in next_line:
                        wfp.write(next_line)
                        read_begin_flag = True
                    if 'END CERTIFICATE' in next_line:
                        csr_file_flag = True
                        break
            wfp.close()
        rfp.close()
    time.sleep(cmd_wait_time)

    if csr_file_flag:
        '''copy csr files from cloudec_pki folder to bootflash'''
        for node in device_dut:
            csr_file_flag = False
            LOG.info("===Start copying csr files to bootflash for node===%s",node)
            csr_certificate_name = "{node}.csr".format(node=node)
            device = testbed.devices[node]
            device.configure('feature scp-server')
            ssh = paramiko.SSHClient()
            ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            ssh.connect(username=device.credentials['default'].get('username'),password=to_plaintext(device.credentials['default'].get('password')),hostname=str(device.connections.get('vty').get('ip')),timeout=600)

            path = '/tmp/' + csr_certificate_name
            with SCPClient(ssh.get_transport()) as scp:
                scp.put(path)
                LOG.info("===CSR file copied to bootflash for node %s===",node)
            ssh.close()
            time.sleep(5)

            '''Checking .csr file copied into bootflash '''
            csr_boot_flash_file_name = "{node_name}.csr".format(node_name=node)
            csr_boot_out = device.execute("dir " + "|grep " + '"' +csr_boot_flash_file_name+'"')
            if str(csr_boot_out).strip():
                LOG.info("===.csr file found in bootflash===>%s", csr_boot_out)
                csr_file_size = str(csr_boot_out).strip().split(" ")[0]
                if int(csr_file_size) > 300:
                    LOG.info("===%s file size in bootflash is greater than 300 bytes===>%s",csr_boot_flash_file_name,csr_file_size)
                    csr_file_flag = True
                else:
                    LOG.error("===%s file size in bootflash is less than 300 bytes===>%s",csr_boot_flash_file_name,csr_file_size)
                    ca_file_flag = False
                    return ca_file_flag
            else:
                LOG.error("===.csr file found not found in bootflash===>%s", csr_boot_out)
                csr_file_flag = False
                return csr_file_flag

            time.sleep(5)
        time.sleep(cmd_wait_time)

    return csr_file_flag

'''Create identity certificate files'''
def create_identity_certificate_files(testbed, device_dut,cmd_wait_time,openssl_flag):
    LOG.info("===In create_identity_certificate_files===")
    '''creating identity certificate and copy to bootflash'''
    identity_file_flag = False
    if openssl_flag:
        for node in device_dut:
            identity_file_flag = False
            LOG.info("===Start creating identity certificate for node===%s",node)
            csr_file_name = "/bootflash/{node_name}.csr".format(node_name=node)
            identity_out_file_name = "/bootflash/{node_name}.pem".format(node_name=node)
            openssl_identity_cmd = "openssl x509 -req -in "+csr_file_name+" -CA /bootflash/CAPrivate.pem -CAkey /bootflash/CAPrivate.key -CAcreateserial -out " +identity_out_file_name+" -days 500"
            device = testbed.devices[node]
            with device.bash_console() as bash:
                bash.execute(openssl_identity_cmd)
                time.sleep(cmd_wait_time)
                LOG.info("===Identity certificate created and copied to bootflash for node===%s",node)
            time.sleep(2)
            '''Checking identity certificate(.pem) copied into bootflash '''
            identity_cert_boot_flash_file_name = "{node_name}.pem".format(node_name=node)
            identity_cert_boot_out = device.execute("dir " + "|grep " + '"' +identity_cert_boot_flash_file_name+'"')
            if str(identity_cert_boot_out).strip():
                LOG.info("===Identity certificate found in bootflash===>%s", identity_cert_boot_out)
                identity_file_flag = True
            else:
                LOG.error("===Identity certificate not found in bootflash===>%s", identity_cert_boot_out)
                identity_file_flag = False

        time.sleep(cmd_wait_time)
    else:
        LOG.info("===TODO other form of creating  identity files===")

    return identity_file_flag

'''Configuring pki trust point cli'''
def pki_trust_point_cli(testbed, device_dut,cmd_wait_time,trust_point_name):
    LOG.info("===In pki_trust_point_cli===")

    for node in device_dut:
        pki_trust_point_flag = False
        pki_trust_point_str = 'tunnel-encryption pki trustpoint'
        device = testbed.devices[node]
        trust_point_cmd = 'tunnel-encryption pki trustpoint {trust_point}'.format(trust_point=trust_point_name)
        device.configure(trust_point_cmd)
        time.sleep(cmd_wait_time)

        pki_trust_point_out = device.execute("show running-config tunnel-encryption " + "|grep " +'"'+pki_trust_point_str+'"')
        if str(pki_trust_point_out).strip()=='tunnel-encryption pki trustpoint {}'.format(trust_point_name).strip():
            LOG.info("===tunnel-encryption pki trustpoint added successfully")
            pki_trust_point_flag = True
        else:
            LOG.error("===tunnel-encryption pki trustpoint failed to add===")
            pki_trust_point_flag = False

    return pki_trust_point_flag

'''Inserting identity certificate'''
def insert_identity_certificate(testbed, device_dut,cmd_wait_time,trust_point_name,rsa_label):
    LOG.info("===In insert_identity_certificate===")

    '''Copy identity certificate content from bootflash and save it into a file in cloudsec_pki folder
       '''
    for node1 in device_dut:
        identity_certificate_name = "{node_name}.pem".format(node_name=node1)
        show_identity_certificate = 'show file bootflash:{identity_file_name}'.format(identity_file_name=identity_certificate_name)
        LOG.info("===copying identity certificate from bootflash to cloudsec_pki for node===%s",node1)
        device_pem = testbed.devices[node1]
        pem_out = device_pem.execute(show_identity_certificate)
        cloud_sec_file_path = "/bootflash/{}".format(identity_certificate_name)
        LOG.info("===cloud_sec_file_path for writing===%s",cloud_sec_file_path)
        pem_config_file = open(cloud_sec_file_path, "w")
        pem_config_file.write(pem_out)
        pem_config_file.close()
        time.sleep(5)

    time.sleep(cmd_wait_time)

    '''Reading the identity .pem file from cloudsec_pki folder and importing the content'''
    for dev in device_dut:
        time.sleep(5)
        identity_certificate_name = "{node_name}.pem".format(node_name=dev)
        import_file_path = "/bootflash/{}".format(identity_certificate_name)
        LOG.info("===import_file_path===%s",import_file_path)
        device = testbed.devices[dev]
        import_certificate_cmd = "crypto ca import {} certificate".format(trust_point_name)
        try:
            '''Step2 importing'''
            def import_certificate(spawn):
                import_flag = False
                with open(import_file_path) as ifp:
                    line_id = ifp.readline()
                    if 'BEGIN CERTIFICATE' in line_id:
                        spawn.sendline(line_id.strip())
                        import_flag = True
                    while line_id:
                        line_id = ifp.readline()
                        if import_flag:
                            spawn.sendline(line_id.strip())
                        if 'BEGIN CERTIFICATE' in line_id:
                            spawn.sendline(line_id.strip())
                            import_flag = True
                        if 'END CERTIFICATE' in line_id:
                            break
                ifp.close()
            '''Step1 dialog'''
            import_dialog = Dialog([
                Statement(pattern=r'.*',
                          action=import_certificate,
                          loop_continue=False,
                          continue_timer=False)
            ])
            device.configure(import_certificate_cmd,timeout=5, reply=import_dialog)

        except Exception:
            LOG.error('Fail: Exception found ', exc_info=True)

    '''Verifying ca import identity certificate '''

    for node in device_dut:
        import_identity_flag = False
        lst_key_pair = []
        lst_key_pair = [rsa_label]
        device = testbed.devices[node]
        ecc_ca_name = "{node_name}_ecc_ca".format(node_name=node)
        lst_key_pair.append(ecc_ca_name)
        rsa_key_pair_out = device.execute('show crypto ca trustpoints |grep key-pair')
        cnt_key_pair = 0
        for rsa_out in rsa_key_pair_out.splitlines():
            rsa_out = rsa_out.strip()
            if str(rsa_out.split(";")[1].split(":")[-1]).strip() ==lst_key_pair[cnt_key_pair]:
                LOG.info("===key-pair to the trust point added %s===>",device)
                import_identity_flag = True
            else:
                LOG.error("===key-pair to the trust point not added %s===>",device)
                import_identity_flag = False
            cnt_key_pair = cnt_key_pair + 1

    time.sleep(cmd_wait_time)
    return import_identity_flag

'''Veirfying pki tunnel encryption session'''
def test_verify_pki_tunnel_encryption(testbed,cloudsec_pki_tunnel_encryption_session,interface_logical_map):
    LOG.info("===In test_verify_pki_tunnel_encryption===")
    for node, _value in cloudsec_pki_tunnel_encryption_session.items():
        verify_cloudsec_tunnel = False
        req_cloudsec_tunnel_encryption_session = ShowTunnelEncryptionSession(testbed.devices[node]).cli()
        if req_cloudsec_tunnel_encryption_session:
            new_dict = req_cloudsec_tunnel_encryption_session
            old_dict = cloudsec_pki_tunnel_encryption_session[node]
            old_dict = json.loads(json.dumps(old_dict))
            LOG.info(f'Converting the ordered dict to unordered dict and old dict is {old_dict}')
            output = verify_parser_output(new_dict, old_dict, interface_logical_map)
            if output:
                LOG.error("===Cloudsec pki Tunnel Encryption Session verification failed for node:%s===", node)
                verify_cloudsec_tunnel = False
            else:
                verify_cloudsec_tunnel = True
                LOG.info("===Cloudsec pki Tunnel Encryption Session verification passed for node:%s===", node)
        else:
            assert not verify_cloudsec_tunnel, f'Cloudsec Tunnels are not up on Node:{node}'

    return verify_cloudsec_tunnel

'''Deleting .pem,.csr,.key and other temp files'''
def delete_pki_files(testbed, device_dut,invalid_or_expired_certificate_lst):
    pki_file_check_flag = False
    LOG.info("===In delete_pki_files===")
    current_directory = "/tmp"
    files_in_directory = os.listdir(current_directory)
    pem_files = [file for file in files_in_directory if file.endswith(".pem")]
    key_files = [file for file in files_in_directory if file.endswith(".key")]
    csr_files = [file for file in files_in_directory if file.endswith(".csr")]
    csr_res_files = [file for file in files_in_directory if file.startswith("CSR_")]

    for file in pem_files:
        path_to_file = os.path.join(current_directory, file)
        LOG.info("===Removing pem files==>%s from==>%s",pem_files,current_directory)
        if file in invalid_or_expired_certificate_lst:
            LOG.info("%s found not removing",file)
        else:
            LOG.info("===Removing===%s",file)
            os.remove(path_to_file)
        time.sleep(2)

    for file in key_files:
        path_to_file = os.path.join(current_directory, file)
        LOG.info("===Removing key files==>%s from==>%s",key_files,current_directory)
        os.remove(path_to_file)
        time.sleep(2)

    for file in csr_files:
        path_to_file = os.path.join(current_directory, file)
        LOG.info("===Removing csr files==>%s from==>%s",csr_files,current_directory)
        os.remove(path_to_file)
        time.sleep(2)

    for file in csr_res_files:
        path_to_file = os.path.join(current_directory, file)
        LOG.info("===Removing CSR_ files==>%s from==>%s",csr_res_files,current_directory)
        os.remove(path_to_file)
        time.sleep(2)

    '''Deleting .key,.pem and .csr files from bootflash of all switches'''
    file_type_bootflash = ['.pem','.key','.csr']
    for node in device_dut:
        device = testbed.devices[node]
        device.execute('del *.pem* no-prompt ')
        device.execute('del *.key* no-prompt ')
        device.execute('del *.csr* no-prompt ')
        time.sleep(2)
        for file_in_boot in file_type_bootflash:
            boot_fl_out = device.execute("dir " + "|grep " + '"' +file_in_boot+'"')
            if str(boot_fl_out).strip() == "":
                LOG.info("===%s type file not found in bootflash on node %s===",file_in_boot,node)
                pki_file_check_flag = True
            else:
                LOG.error("===%s type file found in bootflash on node %s===",file_in_boot,node)
                pki_file_check_flag = False
            time.sleep(1)

    return pki_file_check_flag

class InvalidAndExpiredCA(nxtest.Testcase):
    '''Create a trust point'''
    @aetest.test
    def invalid_or_expired_ca_trust_point_add(self, testbed, device_dut, cmd_wait_time,rsa_label, trust_point_name,cert_size):
        '''Create trust point'''

        device = testbed.devices[device_dut[0]]
        device.configure('crypto ca trustpoint {}'.format(str(trust_point_name)))
        time.sleep(5)
        '''RSA key pair for the device'''

        device.configure('crypto key generate rsa label {rsa_label} exportable modulus {cer_size}'.format(rsa_label=rsa_label,
                                                                                             cer_size=cert_size))
        time.sleep(cmd_wait_time)
        '''ECC key pair'''

        ecc_key_name = "{node_name}_ecc_ca".format(node_name=device_dut[0])
        device.configure('crypto key generate ecc label {ecc_ca_node_name} exportable modulus 224'.format(ecc_ca_node_name=ecc_key_name))

        '''Associate the RSA/ECC key pair to the trust point.'''
        rsa_cmd_list = []
        rsa_cmd_list.append('crypto ca trustpoint {}'.format(str(trust_point_name)))
        rsa_cmd_list.append("rsakeypair {}".format(str(rsa_label)))

        device.configure(rsa_cmd_list)
        time.sleep(2)

        ecc_ca_name = "{node_name}_ecc_ca".format(node_name=device_dut[0])
        device.configure('crypto ca trustpoint  {ecc_name} \n ecckeypair {ecc_key_pair}'.format(ecc_name=ecc_ca_name,ecc_key_pair=ecc_ca_name))
        time.sleep(2)

        time.sleep(cmd_wait_time)

    '''Authenticate the CA that want to enroll to the trust point'''
    @aetest.test
    def authenticate_invalid_expired_ca(self, testbed, device_dut, cmd_wait_time, trust_point_name,invalid_or_expired_certificate,invalid_expired_msg):
        LOG.info("===Calling insert_and_authenticate_ca_cert===")
        if insert_and_authenticate_invalid_ca_cert(testbed, device_dut, cmd_wait_time, trust_point_name,
                                                   invalid_or_expired_certificate,invalid_expired_msg):
            LOG.info("===Authentication failed for Invalid/expired certificate..testcase passed===")
        else:
            LOG.error("===Authentication passed for Invalid/expired certificate..testcase failed===")
            self.failed()


def insert_and_authenticate_invalid_ca_cert(testbed, device_dut,cmd_wait_time,trust_point_name,invalid_or_expired_certificate,invalid_expired_msg):
        LOG.info("===In insert_and_authenticate_invalid_ca_cert===")
        end_of_input_str = "END OF INPUT"
        authenticate_flag = False
        '''Reading the ca .pem file from cloudsec_pki folder and inserting the certificate for authentication'''
        cloud_sec_file_path_pem = get_full_with_script_path(invalid_or_expired_certificate)
        LOG.info("===cloud_sec_file_path_pem===>%s",cloud_sec_file_path_pem)

        device = testbed.devices[device_dut[0]]
        authenticate_cmd = "crypto ca authenticate {}".format(trust_point_name)

        def insert_certificate(spawn):
            begin_flag = False
            with open(cloud_sec_file_path_pem) as fp:
                line = fp.readline()
                if 'BEGIN CERTIFICATE' in line:
                    spawn.sendline(line.strip())
                    begin_flag = True
                while line:
                    line = fp.readline()
                    if begin_flag:
                        spawn.sendline(line.strip())
                    if 'BEGIN CERTIFICATE' in line:
                        spawn.sendline(line.strip())
                        begin_flag = True
                    if 'END CERTIFICATE' in line:
                        break
            fp.close()
            '''Step3 dialog'''
            reply_dialog = Dialog([
                Statement(pattern=r'Do you accept this certificate'.strip(),
                          action='sendline(yes)',
                          loop_continue=False,
                          continue_timer=False)
            ])
            device.configure(end_of_input_str,timeout=cmd_wait_time, reply=reply_dialog)
            time.sleep(2)

        '''Step1 dialog'''
        dialog = Dialog([
            Statement(pattern=r'end the input with a line containing only END OF INPUT :',
                      action=insert_certificate,
                      loop_continue=False,
                      continue_timer=False)
        ])
        authenticate_out = device.configure(authenticate_cmd,timeout=cmd_wait_time, reply=dialog)
        if authenticate_out.find(invalid_expired_msg) != -1:
            authenticate_flag = True
        else:
            authenticate_flag = False
        time.sleep(cmd_wait_time)
        LOG.info("====authenticate_flag====>%s",authenticate_flag)
        return authenticate_flag


class AddRemoveSudi(nxtest.Testcase):
    @aetest.test
    def add_remove_sudi(self, testbed, device_dut, cmd_wait_time,trust_point_name,sudi_flag):
        pki_sudi_str = 'tunnel-encryption pki sudi'
        pki_trust_point_str = 'tunnel-encryption pki trustpoint'
        for node in device_dut:
            device = testbed.devices[node]
            if sudi_flag:
                device.configure(pki_sudi_str)
            else:
                device.configure('no '+pki_sudi_str)
                device.configure(pki_trust_point_str+" "+trust_point_name)
            time.sleep(5)
        time.sleep(cmd_wait_time)

        for node in device_dut:
            device = testbed.devices[node]
            pki_sudi_out = device.execute("show running-config tunnel-encryption " + "|grep " + '"' + pki_sudi_str + '"')
            if sudi_flag:
                if str(pki_sudi_out).strip() != "":
                    LOG.info("===pki sudi added successfully on node===>%s", node)
                else:
                    LOG.error("===Unable to add pki sudi on node===>%s", node)
                    self.failed()
            else:
                if str(pki_sudi_out).strip() == "":
                    LOG.info("===pki sudi removed successfully on node===>%s", node)
                else:
                    LOG.error("===Unable to remove pki sudi on node===>%s", node)
                    self.failed()
                pki_trust_point_out = device.execute(
                    "show running-config tunnel-encryption " + "|grep " + '"' + pki_trust_point_str + '"')
                if str(pki_trust_point_out).strip() != "":
                    LOG.info("===pki trust point %s added on node %s===>",trust_point_name,node)
                else:
                    LOG.error("===Unable to add pki trust point %s on node %s===>", trust_point_name, node)
                    self.failed()

        time.sleep(cmd_wait_time)




class Certificate_Installation(nxtest.Testcase):
    #"TC_001_PKI_certificate_installation"
    
    #-- 1.The CA pem file can be obtained from a 3rd party or Create one of your own self-signed certificate using openssl---#
    # @aetest.test
    # def Creating_CAFile_S1_BGW1(self,testbed):
    #     dev = Connection(hostname='S1_BGW1:', start=['telnet 10.197.127.34'],credentials={'default': {'username': 'admin', 'password': 'nbv12345'}},os='nxos')
    #     dev.connect()
    #     # unicon_state.restore_state_pattern() 
    #     ret_dialog = Dialog([
    #         Statement(pattern=r'.*Country Name \(2 letter code\) \[GB\]:',
    #                 action='sendline(IN)',
    #                 loop_continue=True,
    #                 continue_timer=True),
    #         Statement(pattern=r'.*State or Province Name \(full name\) \[Berkshire\]:',
    #                 action='sendline(Karnataka)',
    #                 loop_continue=True,
    #                 continue_timer=True),
    #         Statement(pattern=r'.*Locality Name \(eg\, city\) \[Newbury\]:',
    #                 action='sendline(Bangalore)',
    #                 loop_continue=True,
    #                 continue_timer=True),
    #         Statement(pattern=r'.*Organization Name \(eg\, company\) \[My Company Ltd\]:',
    #                 action='sendline(Cisco)',
    #                 loop_continue=True,
    #                 continue_timer=True),
    #         Statement(pattern=r'.*Organizational Unit Name \(eg\, section\) \[\]:',
    #                 action='sendline(DCBU)',
    #                 loop_continue=True,
    #                 continue_timer=True),
    #         Statement(pattern=r'.*Common Name \(eg\, your name or your server\'s hostname\) \[\]:',
    #                 action='sendline(Server)',
    #                 loop_continue=True,
    #                 continue_timer=True),
    #         Statement(pattern=r'.*Email Address \[\]:',
    #                 action='sendline(hsuryaka@cisco.com)',
    #                 loop_continue=True,
    #                 continue_timer=True),
    #         ])
    #     dev.configure('feature bash-shell')
    #     dev.execute('run bash')
    #     dev.execute('cd /bootflash')
    #     dev.execute('openssl genrsa -out CAPrivate.key 2048')
    #     dev.execute('openssl req -x509 -new -nodes -key CAPrivate.key -sha256 -days 365 -out CAPrivate.pem', reply=ret_dialog)
    #     output = dev.execute('ls | grep CAPrivate')
    #     match = ('CAPrivate.key  CAPrivate.pem')
    #     if re.search(match,output):
    #         self.passed('CA Files are created')
        #     else:
        #         log.info('CA file are not created.Creating CA File went worng')
        #         self.failed('failed to create CA File')

    #=============
    @aetest.test
    def create_self_signed_ca_certificate(self, testbed, device_dut, cmd_wait_time, openssl_flag):
        if openssl_flag:
            LOG.info("===Calling openssl_sign_certificate_request===")
            if openssl_sign_certificate_request(testbed, device_dut,cmd_wait_time):
                LOG.info("===openssl command executed successfully===")
            else:
                LOG.error("===error while executing openssl command===")
        else:
            LOG.info("===TO DO--Other way of creating self signed certificate===")
    
    @aetest.test
    def enabling_feature_scp(self, testbed):
        node = ["node3_s1_bgw_1", "node4_s1_bgw_2","node7_s2_bgw_1"]
        i=0
        for i in range(len(node)):
            testbed.devices[node[i]].configure('feature scp-server')

    @aetest.test
    def coping_certificate_onDevices(self,testbed):
        node=["node4_s1_bgw_2", "node7_s2_bgw_1"]
        # node=["node4_s1_bgw_2"]
        i=0
        for i in range(len(node)):
            ret_dialog = Dialog([
                Statement(pattern=r'.*Are you sure you want to continue connecting \(yes\/no\/\[fingerprint\]\)\?',
                        action='sendline(yes)',
                        loop_continue=True,
                        continue_timer=True),
                Statement(pattern=r'Password',
                        action='sendline(nbv12345)',
                        loop_continue=True,
                        continue_timer=True),
                        ])
            testbed.devices[node[i]].execute("copy scp://admin@10.197.127.57/CAPrivate.key bootflash: vrf management", reply=ret_dialog)
            testbed.devices[node[i]].execute("copy scp://admin@10.197.127.57/CAPrivate.pem bootflash: vrf management", reply=ret_dialog)
            
    @aetest.test
    def create_trust_point(self, testbed, device_dut, cmd_wait_time, trust_point_name):
        LOG.info("===Calling add_trust_point===")
        if add_trust_point(testbed, device_dut,cmd_wait_time,trust_point_name):
            LOG.info("===Trust point created and verified successfully===")
        else:
            LOG.error("===Error in creating/verifying trust point===")
            self.failed()
    
    '''Create an RSA and ECC key pair for the device'''
    @aetest.test
    def create_rsa_ecc_key_pair(self, testbed, device_dut, cmd_wait_time, rsa_label,cert_size):
        LOG.info("===Calling add_rsa_ecc_pair===")
        if add_rsa_ecc_pair(testbed, device_dut,cmd_wait_time,rsa_label,cert_size):
            LOG.info("===RSA/ECC key pair created and verified successfully===")
        else:
            LOG.error("===Error in creating/verifying RSA/ECC key pair===")
            self.failed()

    '''Associate the RSA/ECC key pair to the trust point.'''
    @aetest.test
    def associate_rsa_ecc_key_pair_to_trust_point(self, testbed, device_dut, cmd_wait_time, trust_point_name, rsa_label):
        LOG.info("===Calling add_rsa_key_pair_to_trust_point===")
        if add_rsa_key_pair_to_trust_point(testbed, device_dut,cmd_wait_time,trust_point_name,rsa_label):
            LOG.info("===RSA/ECC key pair added to trust point successfully===")
        else:
            LOG.error("===Error in associating/verifying RSA/ECC key pair to trust point===")
            self.failed()
    
    '''Authenticate the CA that want to enroll to the trust point'''
    @aetest.test
    def authenticate_ca(self, testbed, device_dut, cmd_wait_time, trust_point_name):
        LOG.info("===Calling insert_and_authenticate_ca_cert===")
        if insert_and_authenticate_ca_cert(testbed, device_dut,cmd_wait_time,trust_point_name):
            LOG.info("===Authenticated the CA enrolled to the trust point successfully===")
        else:
            LOG.error("===Authentication for the CA enrolled to the trust point failed===")
            self.failed()
        
   #========================= 

    # #--- 3.Create a trust point --#
    # @aetest.test
    # def create_Trustpoint(self,testbed, device_dut):
    #     for node in device_dut:
    #         # testbed.devices[node[i]].execute("exit", allow_state_change="True")
    #         # testbed.devices[node[i]].execute("exit", allow_state_change="True")
    #         testbed.devices[node].configure(''' 
    #             crypto ca trustpoint myCA1
    #             exit
    #             ''')
    #         output=testbed.devices[node].execute(' show crypto ca trustpoints ')
    #         match = ('trustpoint: myCA1')
    #         if re.search(match,output):
    #             self.passed('trustpoint created')
    #         else:
    #             log.info('No trustpoint find.failed to create Trustpoint')
    #             self.failed('failed to create trustpoint')
    
    #-- 4. Create an RSA key pair for the device. (Needed only if you are not using a pkcs file) --#
    # @aetest.test
    # def Create_RSA_Keypair(self,testbed,device_dut):
    #     for node in device_dut:
    #         testbed.devices[node].configure(''' 
    #             crypto key generate rsa label myKey1 exportable modulus 1024
    #             ''')
    #         output=testbed.devices[node].execute('show crypto key mypubkey rsa')
    #         match=('''key label: myKey''')
    #         if re.search(match,output):
    #             self.passed('key pair created')
    #         else:
    #             log.info('No key label is present')
    #             self.failed('failed to create key label')

    # #-- 5. Associate the RSA key pair to the trust point. --#
    # @aetest.test
    # def Associate_RSA_keypair_to_Trustpair(self,testbed,device_dut):
    #     for node in device_dut:
    #         testbed.devices[node].configure(''' 
    #             crypto ca trustpoint myCA1
    #                 rsakeypair myKey1
    #                 exit
    #         ''')
    #         output=testbed.devices[node].execute('show crypto ca trustpoints')
    #         match = ('trustpoint: myCA1; key-pair: myKey1')
    #         if re.search(match,output):
    #             self.passed('Trustpoint and key pair are associated')
    #         else:
    #             log.info('Exepted values not present')
    #             self.failed('failed to associate rsa keypair to trustpoint')
    
    #-- 7. Authenticate the CA that you want to enroll to the trust point. --#
    # @aetest.test
    # def Authenticate_CA_to_enroll_Trustpoint(self,testbed, device_dut):
    #     for node in device_dut:
    #         testbed.devices[node].configure(''' crypto ca authenticate myCA1 pemfile bootflash:CAPrivate.pem ''')
    #         output=testbed.devices[node].execute('show crypto ca certificates')
    #         match=('CA certificate 0:')
    #         if re.search(match,output):
    #             self.passed('enrolled authenticate the CA to trustpoint')
    #         else:
    #             log.info('failed to enroll CA to Trustpoint')
    #             self.failed('failed to enroll CA to Trustpoint')

        
    #-- 8. Generate a request certificate (CSR) to use to enroll with a trust point. (Not needed for PKCS import) --#
    @aetest.test
    def Generate_request_certificate_CSR_node03(self, testbed,trust_point_name):
        # dev = Connection(hostname='Elysian1', start=['telnet 10.225.127.41'],credentials={'default': {'username': 'admin', 'password': 'nbv123'}},os='nxos')
        csr_certificate_cmd = "crypto ca enroll {}".format(trust_point_name)
        node = ['node3_s1_bgw_1', 'node4_s1_bgw_2', 'node7_s2_bgw_1']
        i=0
        for i in range(len(node)):
            csr_out_file_name = "CSR_Response{node}".format(node=node[i])
            csr_out_response_path = "/bootflash/{}".format(csr_out_file_name)
            device = testbed.devices[node[i]]
            nve_interface_detail = ShowNveInterfaceDetail(testbed.devices[node[i]]).cli()
            csr_ip = nve_interface_detail['nve1'].get('primary_ip')
            
            #'''Step2 dialog'''
            def csr_certificate_inputs(spawn):
                spawn.sendline('nbv123')
                switch_serial = Dialog([
                    Statement(pattern=r'IP address in the subject name \[yes\/no\]:'.strip(),
                            action=csr_ip_addr,
                            loop_continue=False,
                            continue_timer=False),
                ])
                device.configure('no',timeout=60, reply=switch_serial)
            # '''Step3 dialog'''
            def csr_ip_addr(spawn):
                spawn.sendline('yes')
                switch_ip_addr = Dialog([
                    Statement(pattern=r'Alternate Subject Name'.strip(),
                            action='sendline(no)',
                            loop_continue=False,
                            continue_timer=False)
                ])

                with open(csr_out_response_path, "w") as f, contextlib.redirect_stdout(f):
                    device.config(csr_ip,timeout=60, reply=switch_ip_addr)
                f.close()
            
            dialog = Dialog([
                    Statement(pattern=r'Password',
                            action=csr_certificate_inputs,
                            loop_continue=True,
                            continue_timer=True),
                    # Statement(pattern=r'in the subject name\? \[yes\/no\]:',
                    #         action='sendline(no)',
                    #         loop_continue=True,
                    #         continue_timer=True),
                    # Statement(pattern=r'IP address in the subject name \[yes\/no\]:'.strip(),
                    #         action='sendline(yes)',
                    #         loop_continue=False,
                    #         continue_timer=False)
                    # Statement(pattern=r'ip address:'.strip(),
                    #         action='sendline(10.10.1.1)',
                    #         loop_continue=True,
                    #         continue_timer=True),
                    # Statement(pattern=r'Alternate Subject Name'.strip(),
                    #         action='sendline(no)',
                    #         loop_continue=True,
                    #         continue_timer=True),
            ])
            device.configure(csr_certificate_cmd,timeout=60, reply=dialog)
        time.sleep(15)
        
        
            # except Exception:
            #     LOG.error('Fail: Exception found ', exc_info=True)
    
    # @aetest.test
    # def Generate_request_certificate_CSR_node04(self, testbed,trust_point_name):
    #     # dev = Connection(hostname='Elysian1', start=['telnet 10.225.127.41'],credentials={'default': {'username': 'admin', 'password': 'nbv123'}},os='nxos')
    #     csr_certificate_cmd = "crypto ca enroll {}".format(trust_point_name)
    #     node = ['node4_s1_bgw_2']
    #     i=0
    #     for i in range(len(node)):
    #         device = testbed.devices[node[i]]

    #         dialog = Dialog([
    #                 # Statement(pattern=r'Password',
    #                 #         action='sendline(nbv123)',
    #                 #         loop_continue=True,
    #                 #         continue_timer=True),
    #                 Statement(pattern=r'in the subject name\? \[yes\/no\]:',
    #                         action='sendline(no)',
    #                         loop_continue=True,
    #                         continue_timer=True),
    #                 Statement(pattern=r'IP address in the subject name \[yes\/no\]:'.strip(),
    #                         action='sendline(yes)',
    #                         loop_continue=True,
    #                         continue_timer=True),
    #                 Statement(pattern=r'ip address:'.strip(),
    #                         action='sendline(10.10.1.2)',
    #                         loop_continue=True,
    #                         continue_timer=True),
    #                 Statement(pattern=r'Alternate Subject Name'.strip(),
    #                         action='sendline(no)',
    #                         loop_continue=True,
    #                         continue_timer=True),
    #         ])
    #         device.configure(csr_certificate_cmd,timeout=60, reply=dialog)
    #     time.sleep(15)
    
    # @aetest.test
    # def Generate_request_certificate_CSR_node07(self, testbed,trust_point_name):
    #     # dev = Connection(hostname='Elysian1', start=['telnet 10.225.127.41'],credentials={'default': {'username': 'admin', 'password': 'nbv123'}},os='nxos')
    #     csr_certificate_cmd = "crypto ca enroll {}".format(trust_point_name)
    #     node = ['node7_s2_bgw_1']
    #     i=0
    #     for i in range(len(node)):
    #         device = testbed.devices[node[i]]

    #         dialog = Dialog([
    #                 # Statement(pattern=r'Password',
    #                 #         action='sendline(nbv123)',
    #                 #         loop_continue=True,
    #                 #         continue_timer=True),
    #                 Statement(pattern=r'in the subject name\? \[yes\/no\]:',
    #                         action='sendline(no)',
    #                         loop_continue=True,
    #                         continue_timer=True),
    #                 Statement(pattern=r'IP address in the subject name \[yes\/no\]:'.strip(),
    #                         action='sendline(yes)',
    #                         loop_continue=True,
    #                         continue_timer=True),
    #                 Statement(pattern=r'ip address:'.strip(),
    #                         action='sendline(10.10.1.3)',
    #                         loop_continue=True,
    #                         continue_timer=True),
    #                 Statement(pattern=r'Alternate Subject Name'.strip(),
    #                         action='sendline(no)',
    #                         loop_continue=True,
    #                         continue_timer=True),
    #         ])
    #         device.configure(csr_certificate_cmd,timeout=60, reply=dialog)
    #     time.sleep(15)
    
    @aetest.test
    def create_csr_certificateFile(testbed, device_dut, cmd_wait_time):
        for node in device_dut:
            csr_file_flag = False
            csr_out_file_name = "CSR_Response{node}".format(node=node)
            csr_out_response_path = "/bootflash/{}".format(csr_out_file_name)
            csr_certificate_name = "{node}.csr".format(node=node)
            csr_certificate_path = "/bootflash/{}".format(csr_certificate_name)
            LOG.info("===csr_out_response_path===>%s",csr_out_response_path)
            LOG.info("===csr_certificate_path===>%s",csr_certificate_path)

            with open(csr_out_response_path,'r') as rfp:
                with open(csr_certificate_path,"w") as wfp:
                    next_line = rfp.readline()
                    while next_line:
                        next_line = rfp.readline()
                        if read_begin_flag:
                            wfp.write(next_line)
                        if 'BEGIN CERTIFICATE' in next_line:
                            wfp.write(next_line)
                            read_begin_flag = True
                        if 'END CERTIFICATE' in next_line:
                            csr_file_flag = True
                            break
                wfp.close()
            rfp.close()
        time.sleep(60)

        if csr_file_flag:
        #'''copy csr files from cloudec_pki folder to bootflash'''
            for i in range (len(node)):
                csr_file_flag = False
                LOG.info("===Start copying csr files to bootflash for node===%s",node)
                csr_certificate_name = "{node}.csr".format(node=node)
                device = testbed.devices[node]
                device.configure('feature scp-server')
                ssh = paramiko.SSHClient()
                ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                ssh.connect(username=device.credentials['default'].get('username'),
                            password=to_plaintext(device.credentials['default'].get('password')),
                            hostname=str(device.connections.get('vty').get('ip')),timeout=600)

                path = '/bootflash/' + csr_certificate_name
                with SCPClient(ssh.get_transport()) as scp:
                    scp.put(path)
                    LOG.info("===CSR file copied to bootflash for node %s===",node)
                ssh.close()
                time.sleep(5)

                '''Checking .csr file copied into bootflash '''
                csr_boot_flash_file_name = "{node_name}.csr".format(node_name=node)
                csr_boot_out = device.execute("dir " + "|grep " + '"' +csr_boot_flash_file_name+'"')
                if str(csr_boot_out).strip():
                    LOG.info("===.csr file found in bootflash===>%s", csr_boot_out)
                    csr_file_size = str(csr_boot_out).strip().split(" ")[0]
                    if int(csr_file_size) > 300:
                        LOG.info("===%s file size in bootflash is greater than 300 bytes===>%s",csr_boot_flash_file_name,csr_file_size)
                        csr_file_flag = True
                    else:
                        LOG.error("===%s file size in bootflash is less than 300 bytes===>%s",csr_boot_flash_file_name,csr_file_size)
                        ca_file_flag = False
                        return ca_file_flag
                else:
                    LOG.error("===.csr file found not found in bootflash===>%s", csr_boot_out)
                    csr_file_flag = False
                    return csr_file_flag

                time.sleep(5)
            time.sleep(60)

        return csr_file_flag


    @aetest.test
    def create_identity_certificate_files(self, testbed, device_dut,openssl_flag):
        LOG.info("===In create_identity_certificate_files===")
        '''creating identity certificate and copy to bootflash'''
        identity_file_flag = False
        if openssl_flag:
            for node in device_dut:
                identity_file_flag = False
                LOG.info("===Start creating identity certificate for node===%s",node)
                csr_file_name = "/bootflash/{node_name}.csr".format(node_name=node)
                identity_out_file_name = "/bootflash/{node_name}.pem".format(node_name=node)
                openssl_identity_cmd = "openssl x509 -req -in "+csr_file_name+" -CA /bootflash/CAPrivate.pem -CAkey /bootflash/CAPrivate.key -CAcreateserial -out " +identity_out_file_name+" -days 500"
                device = testbed.devices[node]
                with device.bash_console() as bash:
                    bash.execute(openssl_identity_cmd)
                    time.sleep(60)
                    LOG.info("===Identity certificate created and copied to bootflash for node===%s",node)
                time.sleep(2)
                '''Checking identity certificate(.pem) copied into bootflash '''
                identity_cert_boot_flash_file_name = "{node_name}.pem".format(node_name=node)
                identity_cert_boot_out = device.execute("dir " + "|grep " + '"' +identity_cert_boot_flash_file_name+'"')
                if str(identity_cert_boot_out).strip():
                    LOG.info("===Identity certificate found in bootflash===>%s", identity_cert_boot_out)
                    identity_file_flag = True
                else:
                    LOG.error("===Identity certificate not found in bootflash===>%s", identity_cert_boot_out)
                    identity_file_flag = False

            time.sleep(60)
        else:
            LOG.info("===TODO other form of creating  identity files===")

        return identity_file_flag

    @aetest.test
    def insert_identity_certificate(self, testbed, device_dut,cmd_wait_time,trust_point_name,rsa_label):
        LOG.info("===In insert_identity_certificate===")

        '''Copy identity certificate content from bootflash and save it into a file in cloudsec_pki folder
        '''
        for node1 in device_dut:
            identity_certificate_name = "{node_name}.pem".format(node_name=node1)
            show_identity_certificate = 'show file bootflash:{identity_file_name}'.format(identity_file_name=identity_certificate_name)
            LOG.info("===copying identity certificate from bootflash to cloudsec_pki for node===%s",node1)
            device_pem = testbed.devices[node1]
            pem_out = device_pem.execute(show_identity_certificate)
            cloud_sec_file_path = "/bootflash/{}".format(identity_certificate_name)
            LOG.info("===cloud_sec_file_path for writing===%s",cloud_sec_file_path)
            pem_config_file = open(cloud_sec_file_path, "w")
            pem_config_file.write(pem_out)
            pem_config_file.close()
            time.sleep(5)

        time.sleep(cmd_wait_time)

        '''Reading the identity .pem file from cloudsec_pki folder and importing the content'''
        for dev in device_dut:
            time.sleep(5)
            identity_certificate_name = "{node_name}.pem".format(node_name=dev)
            import_file_path = "/bootflash/{}".format(identity_certificate_name)
            LOG.info("===import_file_path===%s",import_file_path)
            device = testbed.devices[dev]
            import_certificate_cmd = "crypto ca import {} certificate".format(trust_point_name)
            try:
                '''Step2 importing'''
                def import_certificate(spawn):
                    import_flag = False
                    with open(import_file_path) as ifp:
                        line_id = ifp.readline()
                        if 'BEGIN CERTIFICATE' in line_id:
                            spawn.sendline(line_id.strip())
                            import_flag = True
                        while line_id:
                            line_id = ifp.readline()
                            if import_flag:
                                spawn.sendline(line_id.strip())
                            if 'BEGIN CERTIFICATE' in line_id:
                                spawn.sendline(line_id.strip())
                                import_flag = True
                            if 'END CERTIFICATE' in line_id:
                                break
                    ifp.close()
                '''Step1 dialog'''
                import_dialog = Dialog([
                    Statement(pattern=r'.*',
                            action=import_certificate,
                            loop_continue=False,
                            continue_timer=False)
                ])
                device.configure(import_certificate_cmd,timeout=5, reply=import_dialog)

            except Exception:
                LOG.error('Fail: Exception found ', exc_info=True)

        '''Verifying ca import identity certificate '''

        for node in device_dut:
            import_identity_flag = False
            lst_key_pair = []
            lst_key_pair = [rsa_label]
            device = testbed.devices[node]
            ecc_ca_name = "{node_name}_ecc_ca".format(node_name=node)
            lst_key_pair.append(ecc_ca_name)
            rsa_key_pair_out = device.execute('show crypto ca trustpoints |grep key-pair')
            cnt_key_pair = 0
            for rsa_out in rsa_key_pair_out.splitlines():
                rsa_out = rsa_out.strip()
                if str(rsa_out.split(";")[1].split(":")[-1]).strip() ==lst_key_pair[cnt_key_pair]:
                    LOG.info("===key-pair to the trust point added %s===>",device)
                    import_identity_flag = True
                else:
                    LOG.error("===key-pair to the trust point not added %s===>",device)
                    import_identity_flag = False
                cnt_key_pair = cnt_key_pair + 1

        time.sleep(cmd_wait_time)
        return import_identity_flag


        


                           
    # #-- 9. Copy the above output to a file (CSR file). Request an identity certificate from 3rd party using this CSR --#
    # @aetest.test
    # def Copy_CSR_file_certificate(self,testbed):
    #     node=["node3_s1_bgw_1", "node4_s1_bgw_2", "node7_s2_bgw_1"]
    #     i=0
    #     for i in range (len(node)):
    #         # dev = testbed.devices['node4_s1_bgw_2']
    #         # dev.connect()

    #         unicon_state = unicon.statemachine.statemachine.State(name='enable', pattern=r'^.*|%N#')
    #         unicon_state.add_state_pattern(pattern_list="r'bash-*$'")

    #         # testbed.devices[node[i]].configure("feature bash-shell")
    #         pid_data = testbed.devices[node[i]].execute("show system internal sysmgr service name bgp | i i PID")
    #         pid_regex = re.search("PID = (\\d+)", pid_data, re.I)
    #         if pid_regex is not 0:
    #             pid = pid_regex.group(1)
    #         testbed.devices[node[i]].execute("run bash", allow_state_change="True")
    #         testbed.devices[node[i]].execute("sudo su", allow_state_change="True")
    #         testbed.devices[node[i]].execute("kill -9 " + str(pid), allow_state_change="True")

    #         # testbed.devices['node4_s1_bgw_2'].execute('run bash')
    #         testbed.devices[node[i]].execute('openssl x509 -req -in /bootflash/rsa/S1_BGW1.csr -CA /bootflash/rsa/CAPrivate.pem -CAkey /bootflash/rsa/CAPrivate.key -CAcreateserial -out /bootflash/rsa/S1_BGW1.pem -days 500')
    #         testbed.devices[node[i]].execute("exit", allow_state_change="True")
    #         testbed.devices[node[i]].execute("exit", allow_state_change="True")
    
    # # #-- 10. Import the identity certificate --#
    # @aetest.test
    # def Import_identity_certificate(self,testbed):
        
    #     # unicon_state = unicon.statemachine.statemachine.State(name='enable', pattern=r'^.*|%N#')
    #     # unicon_state.add_state_pattern(pattern_list="r'bash-*$'")
    #     node=["node3_s1_bgw_1", "node4_s1_bgw_2", "node7_s2_bgw_1"]
    #     i=0
    #     for i in range (len(node)):
    #         # dev = testbed.devices['node4_s1_bgw_2']
    #         # dev.connect()

    #         unicon_state = unicon.statemachine.statemachine.State(name='enable', pattern=r'^.*|%N#')
    #         unicon_state.add_state_pattern(pattern_list="r'bash-*$'")

    #         # testbed.devices[node[i]].configure("feature bash-shell")
    #         pid_data = testbed.devices[node[i]].execute("show system internal sysmgr service name bgp | i i PID")
    #         pid_regex = re.search("PID = (\\d+)", pid_data, re.I)
    #         if pid_regex is not 0:
    #             pid = pid_regex.group(1)
    #         testbed.devices[node[i]].execute("run bash", allow_state_change="True")
    #         testbed.devices[node[i]].execute("sudo su", allow_state_change="True")
    #         testbed.devices[node[i]].execute("kill -9 " + str(pid), allow_state_change="True")
    #         testbed.devices[node[i]].execute('cd /bootflash/rsa')
    #         output=testbed.devices[node[i]].execute('more S1_BGW1.pem')
    #         testbed.devices[node[i]].execute("exit", allow_state_change="True")
    #         testbed.devices[node[i]].execute("exit", allow_state_change="True")
    #         testbed.devices[node[i]].configure(''' 
    #             crypto ca import myCA certificate
    #         ''')
    #         # inpt="input (cut & paste) certificate in PEM format:"
    #         log.info(output)
        # output=testbed.devices[node[i]].execute('show crypto ca certificates')
        # match=(''' 
        # Trustpoint: myCA
        # CA certificate 0:
        # ''')
        # if re.search(match,output):
        #     self.passed('enrolled authenticate the CA to trustpoint')
        # else:
        #     log.info('failed to enroll CA to Trustpoint')
        #     self.failed('failed to enroll CA to Trustpoint')





class Migration_PSK_to_PKI_with_RSA_Test265_Certificate(nxtest.Testcase):
    @aetest.test
    def convertingPSK_certificatevPC(self,testbed):
        node=["node3_s1_bgw_1", "node4_s1_bgw_2"]
        i=0
        for i in range(len(node)):
            # trust_point_name = ["node3_s1_bgw_1_ecc_ca", "node4_s1_bgw_2_ecc_ca"]
            # i=0
            # for i in range (len(trust_point_name)):
            testbed.devices[node[i]].configure('''
                no tunnel-encryption must-secure-policy 
                tunnel-encryption peer-ip 3.21.21.21
                    no pki policy system-default-tunenc-policy
                no tunnel-encryption pki trustpoint myCA1
                tunnel-encryption icv
                tunnel-encryption pki source-interface cloudsec-loopback        
                tunnel-encryption source-interface loopback0
                tunnel-encryption policy p1
                    sak-rekey-time 1800
                tunnel-encryption peer-ip 3.21.21.21
                    keychain KC1 policy p1
                ''')
            time.sleep(60)
      
    @aetest.test
    def convertingPKSstandalonecertificateStdalone(self,testbed):
        testbed.devices['node7_s2_bgw_1'].configure('''
            no tunnel-encryption must-secure-policy
            tunnel-encryption peer-ip 2.21.21.21
                no pki policy system-default-tunenc-policy
            tunnel-encryption peer-ip 2.22.22.22
                no pki policy system-default-tunenc-policy 
            no tunnel-encryption pki trustpoint myCA1
            tunnel-encryption icv
            tunnel-encryption pki source-interface cloudsec-loopback
            tunnel-encryption source-interface loopback0
            tunnel-encryption policy p1
                sak-rekey-time 1800
            tunnel-encryption peer-ip 2.21.21.21
                keychain KC1 policy p1
            tunnel-encryption peer-ip 2.22.22.22
                keychain KC1 policy p1
            ''')
    time.sleep(120)
    @aetest.test
    def verify_RxStatus1(self,testbed):
        node=["node3_s1_bgw_1", "node4_s1_bgw_2"]
        i=0
        for i in range(len(node)):
            output1 = json.loads(testbed.devices[node[i]].execute('sh tunnel-encryption session | json'))
            log.info(output1)
            if(output1 == ''):
                self.failed(reason='No tunnel-encryption session')
            a = json.loads(testbed.devices[node[i]].execute('sh tunnel-encryption session | json'))
            item = a["TABLE_tem_session"]["ROW_tem_session"]
            for i in range(len(item)):
                str(item)
                RxStatus = item['RxStatus']
                if not re.search('Secure\s\(AN:\s\d\)', RxStatus):
                    log.info('The tunnel session {0} is not secure. state is {1}'.format(ns.PeerAddr,RxStatus))
                    self.failed(reason="status is not secure")
    @aetest.test
    def verify_RxStatus1_S2_BGW1(self,testbed):
        output1 = json.loads(testbed.devices['node7_s2_bgw_1'].execute('sh tunnel-encryption session | json'))
        log.info(output1)
        if(output1 == ''):
            self.failed(reason='No tunnel-encryption session')
        a = json.loads(testbed.devices['node7_s2_bgw_1'].execute('sh tunnel-encryption session | json'))
        item = a["TABLE_tem_session"]["ROW_tem_session"]
        for i in range(len(item)):
            str(item)
            RxStatus = item[i]['RxStatus']
            if not re.search('Secure\s\(AN:\s\d\)', RxStatus):
                log.info('The tunnel session {0} is not secure. state is {1}'.format(ns.PeerAddr,RxStatus))
                self.failed(reason="status is not secure")

    @aetest.test
    def verify_Txstatus2(self,testbed):
        node=["node3_s1_bgw_1", "node4_s1_bgw_2"]
        i=0
        for i in range(len(node)):
            output1 = json.loads(testbed.devices[node[i]].execute('sh tunnel-encryption session | json'))
            log.info(output1)
            if(output1 == ''):
                self.failed(reason='No tunnel-encryption session')
            a = json.loads(testbed.devices[node[i]].execute('sh tunnel-encryption session | json'))
            item = a["TABLE_tem_session"]["ROW_tem_session"]
            for i in range(len(item)):
                str(item)
                TxStatus = item['TxStatus']
                if not re.search('Secure\s\(AN:\s\d\)', TxStatus):
                    log.info('The tunnel session {0} is not secure. state is {1}'.format(ns.PeerAddr,TxStatus))
                    self.failed(reason="status is not secure") 
    
    @aetest.test
    def verify_Txstatus2_S2_BGW1(self,testbed):
        output1 = json.loads(testbed.devices['node7_s2_bgw_1'].execute('sh tunnel-encryption session | json'))
        log.info(output1)
        if(output1 == ''):
            self.failed(reason='No tunnel-encryption session')
        a = json.loads(testbed.devices['node7_s2_bgw_1'].execute('sh tunnel-encryption session | json'))
        item = a["TABLE_tem_session"]["ROW_tem_session"]
        for i in range(len(item)):
            str(item)
            TxStatus = item[i]['TxStatus']
            if not re.search('Secure\s\(AN:\s\d\)', TxStatus):
                log.info('The tunnel session {0} is not secure. state is {1}'.format(ns.PeerAddr,TxStatus))
                self.failed(reason="status is not secure") 
    @aetest.test
    def MigrationPSkwithPKIECCcertificatevPC(self,testbed):
        node=["node3_s1_bgw_1", "node4_s1_bgw_2"]
        i=0
        for i in range(len(node)):
            # trust_point_name = ["node3_s1_bgw_1_ecc_ca", "node4_s1_bgw_2_ecc_ca"]
            # i=0
            # for i in range (len(trust_point_name)):
            testbed.devices[node[i]].configure('''
                no tunnel-encryption must-secure-policy 
                tunnel-encryption peer-ip 3.21.21.21
                    no keychain KC1 policy p1
                tunnel-encryption icv
                tunnel-encryption pki trustpoint myCA1
                tunnel-encryption pki source-interface cloudsec-loopback        
                tunnel-encryption source-interface loopback0
                tunnel-encryption policy p1
                    sak-rekey-time 1800
                tunnel-encryption peer-ip 3.21.21.21
                    pki policy system-default-tunenc-policy
                ''')
            time.sleep(60)
      
    @aetest.test
    def MigrationPKIfromPSKcertificateStdalone(self,testbed):
        testbed.devices['node7_s2_bgw_1'].configure('''
            no tunnel-encryption must-secure-policy
            tunnel-encryption peer-ip 2.21.21.21
                no keychain KC1 policy p1
            tunnel-encryption peer-ip 2.22.22.22
                no keychain KC1 policy p1 
            tunnel-encryption icv
            tunnel-encryption pki trustpoint myCA1
            tunnel-encryption pki source-interface cloudsec-loopback
            tunnel-encryption source-interface loopback0
            tunnel-encryption policy p1
                sak-rekey-time 1800
            tunnel-encryption peer-ip 2.21.21.21
                pki policy system-default-tunenc-policy
            tunnel-encryption peer-ip 2.22.22.22
                pki policy system-default-tunenc-policy 
            ''')
    time.sleep(120)
    
    @aetest.test
    def verify_RxStatus(self,testbed):
        node=["node3_s1_bgw_1", "node4_s1_bgw_2"]
        i=0
        for i in range(len(node)):
            output1 = json.loads(testbed.devices[node[i]].execute('sh tunnel-encryption session | json'))
            log.info(output1)
            if(output1 == ''):
                self.failed(reason='No tunnel-encryption session')
            a = json.loads(testbed.devices[node[i]].execute('sh tunnel-encryption session | json'))
            item = a["TABLE_tem_session"]["ROW_tem_session"]
            for i in range(len(item)):
                str(item)
                RxStatus = item['RxStatus']
                if not re.search('Secure\s\(AN:\s\d\)', RxStatus):
                    log.info('The tunnel session {0} is not secure. state is {1}'.format(ns.PeerAddr,RxStatus))
                    self.failed(reason="status is not secure")
    @aetest.test
    def verify_RxStatus_S2_BGW1(self,testbed):
        output1 = json.loads(testbed.devices['node7_s2_bgw_1'].execute('sh tunnel-encryption session | json'))
        log.info(output1)
        if(output1 == ''):
            self.failed(reason='No tunnel-encryption session')
        a = json.loads(testbed.devices['node7_s2_bgw_1'].execute('sh tunnel-encryption session | json'))
        item = a["TABLE_tem_session"]["ROW_tem_session"]
        for i in range(len(item)):
            str(item)
            RxStatus = item[i]['RxStatus']
            if not re.search('Secure\s\(AN:\s\d\)', RxStatus):
                log.info('The tunnel session {0} is not secure. state is {1}'.format(ns.PeerAddr,RxStatus))
                self.failed(reason="status is not secure")

    @aetest.test
    def verify_Txstatus(self,testbed):
        node=["node3_s1_bgw_1", "node4_s1_bgw_2"]
        i=0
        for i in range(len(node)):
            output1 = json.loads(testbed.devices[node[i]].execute('sh tunnel-encryption session | json'))
            log.info(output1)
            if(output1 == ''):
                self.failed(reason='No tunnel-encryption session')
            a = json.loads(testbed.devices[node[i]].execute('sh tunnel-encryption session | json'))
            item = a["TABLE_tem_session"]["ROW_tem_session"]
            for i in range(len(item)):
                str(item)
                TxStatus = item['TxStatus']
                if not re.search('Secure\s\(AN:\s\d\)', TxStatus):
                    log.info('The tunnel session {0} is not secure. state is {1}'.format(ns.PeerAddr,TxStatus))
                    self.failed(reason="status is not secure") 
    
    @aetest.test
    def verify_Txstatus_S2_BGW1(self,testbed):
        output1 = json.loads(testbed.devices['node7_s2_bgw_1'].execute('sh tunnel-encryption session | json'))
        log.info(output1)
        if(output1 == ''):
            self.failed(reason='No tunnel-encryption session')
        a = json.loads(testbed.devices['node7_s2_bgw_1'].execute('sh tunnel-encryption session | json'))
        item = a["TABLE_tem_session"]["ROW_tem_session"]
        for i in range(len(item)):
            str(item)
            TxStatus = item[i]['TxStatus']
            if not re.search('Secure\s\(AN:\s\d\)', TxStatus):
                log.info('The tunnel session {0} is not secure. state is {1}'.format(ns.PeerAddr,TxStatus))
                self.failed(reason="status is not secure") 
    
    @aetest.test
    def verify_policy(self,testbed):
        node=["node3_s1_bgw_1", "node4_s1_bgw_2"]
        i=0
        for i in range(len(node)):
            output1 = json.loads(testbed.devices[node[i]].execute('sh tunnel-encryption session | json'))
            log.info(output1)
            if(output1 == ''):
                self.failed(reason='No tunnel-encryption session')
            a = json.loads(testbed.devices[node[i]].execute('sh tunnel-encryption session | json'))
            item = a["TABLE_tem_session"]["ROW_tem_session"]
            for i in range(len(item)):
                str(item)
                PolicyName = item['PolicyName']
                if not re.search('system-default-tunenc-policy', PolicyName):
                    log.info(PolicyName)
                    self.failed(reason="tunnel-encryption policy is not verified")

    @aetest.test
    def verify_policy(self,testbed):
        output1 = json.loads(testbed.devices['node7_s2_bgw_1'].execute('sh tunnel-encryption session | json'))
        log.info(output1)
        if(output1 == ''):
            self.failed(reason='No tunnel-encryption session')
        a = json.loads(testbed.devices['node7_s2_bgw_1'].execute('sh tunnel-encryption session | json'))
        item = a["TABLE_tem_session"]["ROW_tem_session"]
        for i in range(len(item)):
            str(item)
            PolicyName = item[i]['PolicyName']
            if not re.search('system-default-tunenc-policy', PolicyName):
                log.info(PolicyName)
                self.failed(reason="tunnel-encryption policy is not verified")

    @aetest.test
    def adding_must_secury_policy(self,testbed):
        node=["node3_s1_bgw_1", "node4_s1_bgw_2", "node7_s2_bgw_1"]
        i=0
        for i in range(len(node)):
            testbed.devices[node[i]].configure("tunnel-encryption must-secure-policy")
            time.sleep(30)
        

    @aetest.test
    def verify_traffic(self,testscript,section):

            if VerifyTraffic(section, testscript):
                self.passed()
            else:
                self.failed()