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

# Metaparser
from genie.metaparser import MetaParser
from genie.metaparser.util.schemaengine import Schema, Any, Optional

# parser utils
from genie.libs.parser.utils.common import Common
from lib.verify.verify_parser_output import verify_parser_output

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
#/auto/dc3-india/absr/automation/vxlan/custom_libs/ixiaPyats_absr_lib.py
import ixiaPyats_absr_lib
ixLib = ixiaPyats_absr_lib.ixiaPyats_lib()
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
from genie.libs.parser.nxos.show_interface import ShowInterface
from lib.verify.verify_nve_triggers import verify_show_nve_peers

#==========================================================================================================#


from genie.libs.parser.nxos.show_vxlan import ShowL2routeMacAllDetail
from lib.utils.mac_utils import incrementmacaddress, threedotmacformat
import logging

LOG = logging.getLogger()

###############Jasim imports################################################################################
from csccon.functions import add_state_pattern
import collections
response = collections.OrderedDict()
response[r'Do you want to overwrite \(y/n\)\?\[n\]'] = 'econ_send "y\r" ; exp_continue' 

from lib.verify.verify_parser_output import verify_parser_output
#==========================================================================================================#

#######################Ixia Config Builder(For stop_start_Protocols##############
from lib.config.traffic.tgen_ixia_restpy_api.ixia_config_builder import IxiaConfigBuilder
#=========================================================================================

req_tgen = 0

def verifyl2routetype(section,testbed,device_dut, vlan, vlan_range, mac, macincr, type):
    device = testbed.devices[device_dut[0]]
    
    vlan_list=str(vlan_range).split(',')
    if len(vlan_list)==1:
        vlan_range=int(vlan_list[0])
    else:
        vlan_range=len(vlan_list)
    for i in range(vlan_range):
        verify_stats = False
        poutput = ShowL2routeMacAllDetail(device).cli(evi=vlan, mac=mac)
        LOG.info(poutput)
        if bool(poutput):
            if poutput['topology']['topo_id'][vlan]['mac'][mac]['rte_res'] == type:
                LOG.info("MAC verification successful for the mac {0} of type {1}".format(mac, type))
                verify_stats = True
            else:
                LOG.error("MAC verification failure for the mac {0} of type {1}".format(mac, type))
                verify_stats = False
        else:
            LOG.error("MAC address {0} not found in L2rib".format(mac))
            verify_stats = False

        vlan += 1
        mac = threedotmacformat(incrementmacaddress(mac,macincr))
        # assert verify_stats, 'MAC verification failed on l2rib'
        if not verify_stats:
            section.failed('Mac verification is failed')
            break
        else:
            continue
    if verify_stats:
        section.passed('MAC verification is passed')
    else:
        section.failed('Mac verification is failed') 
            

def verifyl2fm_mac(section,testbed,device_dut, vlan, vlan_range, mac, macincr):
    device = testbed.devices[device_dut[0]]

    vlan_list=str(vlan_range).split(',')
    if len(vlan_list)==1:
        vlan_range=int(vlan_list[0])
    else:
        vlan_range=len(vlan_list)

    for i in range(vlan_range):
        verify_stats = False
        output=device.execute(f"sh mac address-table vlan {vlan} address {mac} | i {mac}")
        m=re.search('.*nve1\(A:([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)\sS:([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)\)',output)
        if m:
            A_NH=m.group(1)
            S_NH=m.group(2)
            LOG.info("MAC verification successful for the mac {0} ".format(mac))
            verify_stats = True
        else:
            LOG.error("MAC address {0} not found in L2fm".format(mac))
            verify_stats = False
        
        vlan += 1
        mac = threedotmacformat(incrementmacaddress(mac,macincr))
        # assert verify_stats, 'MAC verification failed on l2fm'
        if not verify_stats:
            section.failed('Mac verification is failed')
            break
        else:
            continue
    if verify_stats:
        section.passed('MAC verification is passed')
    else:
        section.failed('Mac verification is failed') 

class verify_mac_address(nxtest.Testcase):

    @aetest.test
    def verify_mac_address(self,testbed,device_dut, vlan, mac):
        device = testbed.devices[device_dut[0]]

        #for i in range(vlan_range):
        verify_stats = False
        output=device.execute(f"sh mac address-table vlan {vlan} address {mac} | i {mac}")
        m=re.search('^C\s+[0-9]+\s+[0-9a-f]+\.[0-9a-f]+\.[0-9a-f]+\s+dynamic.*(nve1\([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+\))',output)
        if m:
            LOG.info("MAC verification successful for the mac {0} on interface {1}".format(mac,m.group(1)))
            verify_stats = True
        else:
            LOG.error("MAC address {0} not found in L2fm".format(mac))
            verify_stats = False
            
            # vlan += 1
            # mac = threedotmacformat(incrementmacaddress(mac,macincr))
            # assert verify_stats, 'MAC verification failed on l2fm'
            
        if verify_stats:
            self.passed('MAC verification is passed')
        else:
            self.failed('Mac verification is failed') 

def verify_nve_res_path(section,testbed,device_dut):
    device = testbed.devices[device_dut[0]]
    NH=[]
    output=device.execute('''sh forwarding internal nve res-pathlist''')
    lst=output.split('\n')
    for line in lst:
        verify_stats = False
        m=re.search('.*peers:\s+([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)\s+([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+).*type\:\s+single-active',line)
        if m:
            NH.append(m.group(1))
            NH.append(m.group(2))
        
    if NH[0]==NH[2]:
        LOG.info("NVE Resultant path verification failed")
        verify_stats = False
    else:
        LOG.info("NVE Resultant path verification passed")
        verify_stats = True
    # assert verify_stats, 'MAC verification failed on l2fm'
    if verify_stats:
        section.passed('NVE Resultant path verification passed')
    else:
        section.failed('NVE Resultant path verification failed')
    
def verify_fwd_es_path(section,testbed,device_dut):
    device = testbed.devices[device_dut[0]]
    verify_stats = False
    output=device.execute('''sh forwarding distribution internal es-pathlist 1''')
    lst=output.split('\n')
    peerlist=0
    for line in lst:
        m=re.search('.*Peer\s+Cnt:\s+2\,\s+Peer-list:\s+\(\s+([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)\s+([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)\s+\),\s+Type:\s+single-active.*',line)
        if m:
            peerlist+=1
    if peerlist==2:
        LOG.info("ES path-list verification passed")
        verify_stats = True
    else:
        LOG.info("ES path-list verification failed")
        verify_stats = False

    if verify_stats:
        section.passed('ES path-list verification passed')
    else:
        section.failed('ES path-list verification failed')

def verify_evpn_ead(section,testbed,device_dut,Next_Hops):
    import json
    device = testbed.devices[device_dut[0]]
    verify_stats = False
    output=device.execute(f"sh l2route evpn ead es detail | json-pretty")
    a=json.loads(output)
    if a["TABLE_l2route_evpn_ead_all"]["ROW_l2route_evpn_ead_all"][1]['flags']=='Si':
        if a["TABLE_l2route_evpn_ead_all"]["ROW_l2route_evpn_ead_all"][1]['next-hop']==Next_Hops:
            LOG.info("Evpn EAD verification Passed")
            verify_stats = True
    else:
        LOG.info("Evpn EAD verification failed")
        verify_stats = False

    if verify_stats:
        section.passed('Evpn EAD verification passed')
    else:
        section.failed('Evpn EAD verification failed')

def verify_bgp_route_type1(section,testbed,device_dut):
    device = testbed.devices[device_dut[0]]
    verify_stats = []
    output=device.execute("show bgp l2vpn evpn route-type 1 | i ESI")
    for line in output.split('\n'):
        m=re.search('.*ESI:(1)\:',line)
        if m:
            verify_stats.append(m.group(1))
            LOG.info("BGP route-type1 verification Passed")
        else:
            verify_stats.append(0)
            LOG.info("BGP route-type1 verification Failed")
    if 0 in verify_stats:
        section.failed('BGP route-type1 verification Failed')
    else:
        section.passed('BGP route-type1 verification passed')
        

def verify_l2rib_pathlist(section,testbed,device_dut,ESI,NH_1,NH_2):
    import json
    device = testbed.devices[device_dut[0]]
    verify_stats = False
    output=device.execute(f"sh l2route evpn path-list esi {ESI} detail | json-pretty")
    a=json.loads(output)
    for i in range (0,10,2):
        if NH_2=='':
            if a["TABLE_l2route_evpn_pathlist_all"]["ROW_l2route_evpn_pathlist_all"][i]['evpn-flags']=='Si' and a["TABLE_l2route_evpn_pathlist_all"]["ROW_l2route_evpn_pathlist_all"][i]['res-next-hop']== NH_1:
                verify_stats = True
                continue
            else:
                verify_stats = False
                log.info(a["TABLE_l2route_evpn_pathlist_all"]["ROW_l2route_evpn_pathlist_all"][i]['evpn-flags'])
                log.info(a["TABLE_l2route_evpn_pathlist_all"]["ROW_l2route_evpn_pathlist_all"][i]['res-next-hop'])
                break
        else:
            if a["TABLE_l2route_evpn_pathlist_all"]["ROW_l2route_evpn_pathlist_all"][i]['evpn-flags']=='Si' and a["TABLE_l2route_evpn_pathlist_all"]["ROW_l2route_evpn_pathlist_all"][i]['res-next-hop']== NH_1 and a["TABLE_l2route_evpn_pathlist_all"]["ROW_l2route_evpn_pathlist_all"][i]['bkp-next-hop']== NH_2:
                verify_stats = True
            else:
                verify_stats = False
                log.info(a["TABLE_l2route_evpn_pathlist_all"]["ROW_l2route_evpn_pathlist_all"][i]['evpn-flags'])
                log.info(a["TABLE_l2route_evpn_pathlist_all"]["ROW_l2route_evpn_pathlist_all"][i]['res-next-hop'])
                log.info(a["TABLE_l2route_evpn_pathlist_all"]["ROW_l2route_evpn_pathlist_all"][i]['res-next-hop'])
                break
        b=NH_1
        NH_1=NH_2
        NH_2=b
    if verify_stats:
        section.passed('l2route pathlist verification passed')
    else:
        section.failed('l2route pathlist verification failed')

def perform_copy_r_s(section,testbed,device_dut):
    device = testbed.devices[device_dut[0]]
    verify_stats = False
    try:
        log.info("Performing copy r s")
        device.execute(f"copy r s")
        verify_stats= True
    except Exception as error:
        log.info(f"Failed to perform copy r s because of error: {error}")
    # if verify_stats:
    #     section.passed('Performing copy r s passed')
    # else:
    #     section.failed(f"Failed to perform copy r s because of error: {error}")

class Removeadd_Bgp_MAX_Paths(nxtest.Testcase):
    
    @aetest.test
    def removeadd_maxpaths_bgp(self,testbed,device_dut,bgp_AS):
        verify_stats= True
        # dev=[]
        # for device in device_dut:
        #     dev.append(testbed.devices(device))
        device = testbed.devices[device_dut[0]]
        #for dut in dev:
        #for device in testbed.devices[device_dut]:
        #device.execute("no checkpoint chpt1")
        try:
            
            device.execute("checkpoint chpt1")
            device.configure(f"""router bgp {bgp_AS}
                                address-family l2vpn evpn
                                no maximum-paths
                                no maximum-paths ibgp""")
        except Exception as error:
            verify_stats= False
            self.failed(reason=f"error occured while removing maximum paths under bgp on dut {device} with error : {error}.")
                
        
        time.sleep(30)

        #for device in device_dut:
        try:
            device.execute("rollback running-config checkpoint chpt1")
            device.execute("no checkpoint chpt1")
        except Exception as error:
            verify_stats= False
            self.failed(reason=f"error occured while adding back maximum paths under bgp on dut {device} with error: {error}.")
        
        log.info("waiting 60s before continuing further")
        time.sleep(60)

        if verify_stats:
            self.passed('Remove_Add maximum paths under bgp successful')
        else:
            self.failed('Remove_Add maximum paths under bgp failed')
    


class Delete_NVE_Loopback_ip(nxtest.Testcase):
    
    @aetest.test
    def delete_loopback_ip(self,testbed,device_dut,loopback):
        verify_stats= True
        
        device = testbed.devices[device_dut[0]]
        try:
            
            device.execute("checkpoint chpt2")
            log.info("shutting the nve interface before loopback ip change")
            device.configure(f"""interface nve 1
                                   shut
                                interface loopback{loopback}
                                  no ip address
                            """)
        except Exception as error:
            verify_stats= False
            self.failed(reason=f"error occured while removing loopback ip on dut {device} with error : {error}.")
                
        
        time.sleep(30)

        #for device in device_dut:
        try:
            device.execute("rollback running-config checkpoint chpt2")
            device.execute("no checkpoint chpt2")
        except Exception as error:
            verify_stats= False
            self.failed(reason=f"error occured while adding back NVE loopback ip on dut {device} with error: {error}.")
        
        log.info("waiting 180s before continuing further")
        time.sleep(180)


    @aetest.test
    def verify_nve_peers_after_rollback_nve_loopback_ip(self, testbed):
        interface_logical_map = self.parameters.get('interface_logical_map')
        verify_show_nve_peers(testbed, self.parameters['nve_peers'], interface_logical_map)

    
#from ats.connections.csccon.functions import add_state_pattern


class xml_validation(nxtest.Testcase):

    """ XML Validation for ESI RX Single-Active """

    # XML version - configuration
    @aetest.test
    def configureXmlTerminal(self, testbed, device_dut, xml_build):
        """ Configure the XML Terminal Version """
        for node in device_dut:
            log.info(banner("Configuring the terminal XML version in device {0}".format(testbed.devices[node].name)))
            log.info("The XML Terminal Version to be set is {0}.".format(xml_build))
            testbed.devices[node].execute("terminal output xml {0}".format(xml_build))

    # XML version - Verification
    @aetest.test
    def verifyXmlTerminal(self, testbed, device_dut, xml_build):
        """ Verify the XML Terminal Version """
        
        # Status parameters
        status_falgs = []
        status_msgs = '\n'

        try:
            for node in device_dut:
                log.info(banner("Verifying the terminal XML version in device {0}".format(testbed.devices[node].name)))
                xml_terminal = testbed.devices[node].execute('show terminal output xml version | grep version')
                if xml_build in xml_terminal:
                    status_falgs.append(1)
                    status_msgs+="XML version in device {0} is Passed.".format(testbed.devices[node].name)
                else:
                    status_falgs.append(0)
                    status_msgs+="XML version in device {0} is Failed.".format(testbed.devices[node].name)
        except:
            self.failed(reason="Terminal XML verification is Failed.")

        #staus-flags-verification
        if 0 in status_falgs:
            self.failed(reason=status_msgs)
        else:
            self.passed(reason=status_msgs)

    # XML validation - L2Rib all
    @aetest.test
    def verifyXmlL2RibAll(self, testbed, device_dut):
        """ XML Validation for L2Rib All """
        
        # Status parameters
        status_falgs = []
        status_msgs = '\n'

        try:
            for node in device_dut:
                log.info(banner("Verifying the XML L2Rib All verification in device {0}".format(testbed.devices[node].name)))
                xml_op = testbed.devices[node].execute('show l2route mac all detail | validate-xml | grep valid')
                if "The output is valid." in xml_op:
                    status_falgs.append(1)
                    status_msgs+="The L2Rib all XML output is valid on the device {0}.".format(testbed.devices[node].name)
                else:
                    status_falgs.append(0)
                    status_msgs+="The L2Rib all XML output is in-valid on the device {0}.".format(testbed.devices[node].name)
        except:
            self.failed(reason="The XML L2Rib All verification is failed.".format(testbed.devices[node].name))

        #staus-flags-verification
        if 0 in status_falgs:
            self.failed(reason=status_msgs)
        else:
            self.passed(reason=status_msgs)

    # XML validation - L2fm with mac
    @aetest.test
    def verifyXmlL2fmMac(self, testbed, device_dut, vlan, mac, intf):
        """ XML Validation for L2fm mac """
        
        # Status parameters
        status_falgs = []
        status_msgs = '\n'

        try:
            for node in device_dut:
                log.info(banner("Verifying the XML L2fm with mac verification in device {0}".format(testbed.devices[node].name)))
                xml_op = testbed.devices[node].execute('show mac address-table vlan {0} address {1} interface {2} | validate-xml | grep valid'.format(vlan, mac, intf))
                if "The output is valid." in xml_op:
                    status_falgs.append(1)
                    status_msgs+="The L2fm with mac XML output is valid on the device {0}.".format(testbed.devices[node].name)
                else:
                    status_falgs.append(0)
                    status_msgs+="The L2fm with mac XML output is in-valid on the device {0}.".format(testbed.devices[node].name)
        except:
            self.failed(reason="The XML L2fm mac verification is failed.".format(testbed.devices[node].name))

        #staus-flags-verification
        if 0 in status_falgs:
            self.failed(reason=status_msgs)
        else:
            self.passed(reason=status_msgs)

    # XML validation - evpn ead
    @aetest.test
    def verifyXmlEvpnEad(self, testbed, device_dut):
        """ XML Validation for evpn ead """
        
        # Status parameters
        status_falgs = []
        status_msgs = '\n'

        try:
            for node in device_dut:
                log.info(banner("Verifying the XML evpn ead in device {0}".format(testbed.devices[node].name)))
                xml_op = testbed.devices[node].execute('show l2route evpn ead es detail | validate-xml | grep valid')
                if "The output is valid." in xml_op:
                    status_falgs.append(1)
                    status_msgs+="The evpn ead XML output is valid on the device {0}.".format(testbed.devices[node].name)
                else:
                    status_falgs.append(0)
                    status_msgs+="The evpn ead XML output is in-valid on the device {0}.".format(testbed.devices[node].name)
        except:
            self.failed(reason="The XML evpn ead verification is failed.".format(testbed.devices[node].name))

        #staus-flags-verification
        if 0 in status_falgs:
            self.failed(reason=status_msgs)
        else:
            self.passed(reason=status_msgs)

    # XML validation - l2rib path-list
    @aetest.test
    def verifyXmlL2ribPathList(self, testbed, device_dut, ESI):
        """ XML Validation for l2rib path-list """
        
        # Status parameters
        status_falgs = []
        status_msgs = '\n'

        try:
            for node in device_dut:
                log.info(banner("Verifying the XML l2rib path-list in device {0}".format(testbed.devices[node].name)))
                xml_op = testbed.devices[node].execute('show l2route evpn path-list esi {0} detail | validate-xml | grep valid'.format(ESI))
                if "The output is valid." in xml_op:
                    status_falgs.append(1)
                    status_msgs+="The L2rib Path-List XML output is valid on the device {0}.".format(testbed.devices[node].name)
                else:
                    status_falgs.append(0)
                    status_msgs+="The L2rib Path-List XML output is in-valid on the device {0}.".format(testbed.devices[node].name)
        except:
            self.failed(reason="The XML L2rib Path-List verification is failed.".format(testbed.devices[node].name))

        #staus-flags-verification
        if 0 in status_falgs:
            self.failed(reason=status_msgs)
        else:
            self.passed(reason=status_msgs)


class Config_Replace(nxtest.Testcase):
    """
    Triggers config replace
    """
    @aetest.test
    def configurereplace(self, testbed, device_dut,cmd,trigger_wait_time = 120):
        # Status parameters
        status_falgs = []
        status_msgs = '\n'

        device = testbed.devices[device_dut[0]]
        device.execute("copy r s")
        device.execute('delete bootflash:base-cfg no-prompt')
        device.execute('copy running-config bootflash:base-cfg')
        time.sleep(trigger_wait_time)
        # Execute the commands before replace
        #for c in cmd:
        device.configure(cmd)
        time.sleep(trigger_wait_time)
        
        replace_out = device.execute(
            'configure replace bootflash:base-cfg verbose')
        time.sleep(trigger_wait_time)

        mat = re.search(
            r'Configure.+replace.+completed.+successfully',
            replace_out)

        if mat:
            status_falgs.append(1)
            status_msgs+=f"Config Replace Successful on {device}."
        else:
            status_falgs.append(0)
            status_msgs+=f"Config Replace Successful on {device}."

        ##Verify config is matching before and after config_replace
        after_out = device.execute('sh run diff')
        out = re.search('\!|\-',after_out)
        if not out:
            status_falgs.append(1)
            status_msgs+="Configs matched after Config Replace"
        else:
            status_falgs.append(0)
            status_msgs+=f"Config not matched after Config Replace"
        
        #staus-flags-verification
        if 0 in status_falgs:
            self.failed(reason=status_msgs)
        else:
            self.passed(reason=status_msgs)


class Config_New_L2VNI(nxtest.Testcase):
    """
    Configures new L2VNI
    """
    @aetest.test
    def configurel2vni(self, testbed,device_dut, cmd ,trigger_wait_time = 60):
        # Status parameters
        status_falgs = []
        status_msgs = '\n'
        for dut in device_dut:
            dev = testbed.devices[dut]
            dev.execute("copy r s")
            dev.execute('delete bootflash:base-cfg no-prompt')
            dev.execute('copy running-config bootflash:base-cfg')
            time.sleep(trigger_wait_time)
            # Execute the commands before replace
            #for c in cmd:
            dev.configure(cmd)
        time.sleep(trigger_wait_time)

class StopAndStartTopology(nxtest.Testcase):
    
    @aetest.test
    def Stop_and_start_topology(self, testbed, testscript, apiServerIp, ixChassisIpList, topology_name):
        ################################################################################
        # Connect to IxNet client
        ################################################################################

        #ixNet = IxNet(py.ixTclServer, int(py.ixTclPort)+3000)
        #ixNet.connect()
        #root = ixNet.getRoot()

        #apiServerIp = testscript.parameters['ixnetwork_api_server_ip']
        #ixChassisIpList = [testscript.parameters['ixia_chassis_ip']]
        # LogLevel: none, info, warning, request, request_response, all
        testscript.parameters['session'] = session = SessionAssistant(IpAddress=apiServerIp, RestPort=None, UserName='admin', Password='admin', 
                            SessionName=None, SessionId=None, ApiKey=None,
                            ClearConfig=False, LogLevel='all', LogFilename='restpy.log')

        testscript.parameters['ixNetwork'] = ixNetwork = session.Ixnetwork
        ################################################################################
        # Stop Topology
        ################################################################################
        # print ("Stop Topology")
        ixNetwork.Topology.find(Name=topology_name).Stop()
        time.sleep(60)
        # ################################################################################
        # # Start Topology
        # ################################################################################
        # print ("Starting Topology")
        ixNetwork.Topology.find(Name=topology_name).Start()
        #ixNetwork.StopTopology('node07_tgn01')
        time.sleep(60)
        #ixNetwork.StartTopology('node07_tgn01')
        #time.sleep(60)
        
