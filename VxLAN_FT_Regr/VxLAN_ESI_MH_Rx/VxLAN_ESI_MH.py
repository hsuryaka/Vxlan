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

#==========================================================================================================#


from genie.libs.parser.nxos.show_vxlan import ShowL2routeMacAllDetail
from lib.utils.mac_utils import incrementmacaddress, threedotmacformat
import logging

LOG = logging.getLogger()

#==========================================================================================================#



def verifyl2routetype(section,testbed,device_dut, vlan, vlan_range, mac, macincr, type):
    device = testbed.devices[device_dut[0]]
    
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
        if verify_stats:
            section.passed('MAC verification is passed')
        else:
            section.failed('Mac verification is failed')