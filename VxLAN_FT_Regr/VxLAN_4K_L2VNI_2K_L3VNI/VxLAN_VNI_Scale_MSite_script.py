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
import yaml
import json
from time import sleep
from yaml import Loader
import chevron
import pdb
import sys
import re
import ipaddress as ip
import numpy as np

# ------------------------------------------------------
# Import pyats aetest libraries
# ------------------------------------------------------
import logging
from pyats import aetest
from pyats.datastructures.logic import Not
from pyats.log.utils import banner
from pyats.async_ import pcall
from pyats.aereport.utils.argsvalidator import ArgsValidator
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
from VxLAN_PYlib import vxlanEVPN_FNL_lib

evpnLib = vxlanEVPN_FNL_lib.configure39KVxlanEvpn()
verifyEvpn = vxlanEVPN_FNL_lib.verifyEVPNconfiguration()

# ------------------------------------------------------
# Import and initialize IXIA specific libraries
# ------------------------------------------------------
from VxLAN_PYlib import ixiaPyats_lib

ixLib = ixiaPyats_lib.ixiaPyats_lib()

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

###################################################################
###                  User Library Methods                       ###
###################################################################

def VerifyTraffic(section, steps, **kwargs):
    """ IXIA_CONFIGURATION subsection: Verify IXIA Traffic """
    ixLib.verify_traffic(3)
    if ixLib.verify_traffic(3) == 0:
        log.debug("Traffic Verification failed")
        section.failed("Traffic verification failed")
    else:
        log.info("Traffic Verification Passed")
        section.passed("Traffic verification Passed")

def increment_prefix_network(pref, count):
    size = 1 << (pref.network.max_prefixlen - pref.network.prefixlen)
    pref_lst = []
    for i in range(count):
        pref_lst.append(str((pref.ip+size*i)) + "/" + str(pref.network.prefixlen))
    return pref_lst

def generateScaleNVEConfigs(nve_dict, bgp_as, rmap, dut, msite_flag):

    log.info("== Inside the generateScaleNVEConfigs ==")
    
    # --------------------------------------------
    # Parameters to be used in the following proc
    # --------------------------------------------
    vlan_vni_config     = []
    vlan_svi_config     = []
    bgp_config          = []
    evpn_config         = []
    vrf_config          = []
    nve_int_config      = []
    # leaf_config     = []
    # nve_int_config  = []

    # Building vni per mcast group parameters for MCast
    if 'l3_mcast_grp_ip' in nve_dict.keys():
        if 'l3vni_per_mcast_grp' not in nve_dict:
            nve_dict['l3vni_per_mcast_grp'] = '1'
    if 'l2vni_per_mcast_grp' not in nve_dict:
        nve_dict['l2vni_per_mcast_grp'] = '1'

    # ----------------------------------------------------
    # Build Incremental configs for VRF, VNI, L2/L3 VLANs
    # Building for MCast Underlay
    # ----------------------------------------------------
    log.info(banner("Building MCast Underlay VNI Data"))

    total_vlans = int(nve_dict['VRF_count']) * int(nve_dict['VLAN_PER_VRF_count'])
    # Build the MCast GRP IP's needed for L2VNI
    if 'l2_mcast_grp_ip' in nve_dict.keys():
        l2_mcast_grp_ip_count  = round(float(total_vlans) / int(nve_dict['l2vni_per_mcast_grp']))
        l2_mcast_grp_ips = increment_prefix_network(ip.IPv4Interface(str(nve_dict['l2_mcast_grp_ip'])),l2_mcast_grp_ip_count+1)
        # log.info("l2_mcast_grp_ips => "+str(l2_mcast_grp_ips))

    if 'l2_vlan_ipv4_start' in nve_dict.keys():
        # Build the IPv4's needed for L2VNI-SVI
        l2vni_svi_ipv4s = increment_prefix_network(ip.IPv4Interface(str(nve_dict['l2_vlan_ipv4_start']) + str(nve_dict['l2_vlan_ipv4_mask'])), total_vlans)
        # log.info("l2vni_svi_ipv4s => "+str(l2vni_svi_ipv4s))
        if 'l2_vlan_ipv6_start' in nve_dict.keys():
            l2vni_svi_ipv6s = increment_prefix_network(ip.IPv6Interface(str(nve_dict['l2_vlan_ipv6_start']) + str(nve_dict['l2_vlan_ipv6_mask'])), total_vlans)
            # log.info("l2vni_svi_ipv6s => "+str(l2vni_svi_ipv6s))

    # VNI / SVI / VLAN counter Variables
    vrf_id              = nve_dict['VRF_id_start']
    l3_vn_seg_id        = nve_dict['l3_vni_start']
    l2_vlan_id          = nve_dict['l2_vlan_start']
    start_l2_vlan_id    = nve_dict['l2_vlan_start']
    middle_l2_vlan_id   = int(start_l2_vlan_id)+round(int(total_vlans)/2)
    l2_vn_seg_id        = nve_dict['l2_vni_start']

    # ---------------------------------------
    # Looping for L3VNI NVE configs
    start_l3_vni = l3_vn_seg_id
    end_l3_vni = int(l3_vn_seg_id) + int(nve_dict['VRF_count']) - 1
    log.info("start_l3_vni is - "+str(start_l3_vni))
    log.info("end_l3_vni is - "+str(end_l3_vni))
    dut.configure("int nve 1 ; member vni " + str(start_l3_vni) + "-" + str(end_l3_vni) + " associate-vrf")

    # ---------------------------------------
    # Looping for L2VNI NVE configs
    start_l2_vni = l2_vn_seg_id
    end_l2_vni = ''
    l2_mcast_grp_ip_indx    = 0
    break_flag = 0

    total_vlans = int(nve_dict['VRF_count']) * int(nve_dict['VLAN_PER_VRF_count'])
    last_l2_vni = start_l2_vni + total_vlans
    l2_mcast_grp_ip_count  = round(float(total_vlans) / int(nve_dict['l2vni_per_mcast_grp']))
    
    log.info("start_l2_vni is - "+str(start_l2_vni))
    log.info("total_vlans is - "+str(total_vlans))
    log.info("last_l2_vni is - "+str(last_l2_vni))
    log.info("l2_mcast_grp_ip_count is - "+str(l2_mcast_grp_ip_count))
    
    for iteration in range(0,l2_mcast_grp_ip_count):
        end_l2_vni = start_l2_vni + int(nve_dict['l2vni_per_mcast_grp']) - 1
        if end_l2_vni > last_l2_vni:
            log.info("Iteration - "+str(iteration))
            log.info("Last L3VNI going beyond, resetting to total_l2_vni")
            end_l2_vni = last_l2_vni - 1
            break_flag = 1

        if msite_flag:
            dut.configure('''
                interface nve 1
                member vni ''' + str(start_l2_vni) + '''-''' + str(end_l2_vni) + '''
                    mcast-group ''' + str(str(l2_mcast_grp_ips[l2_mcast_grp_ip_indx]).replace("/32",'')) + '''
                    suppress-arp
                    multisite ingress-replication
            ''')
        else:
            dut.configure('''
                interface nve 1
                member vni ''' + str(start_l2_vni) + '''-''' + str(end_l2_vni) + '''
                    mcast-group ''' + str(str(l2_mcast_grp_ips[l2_mcast_grp_ip_indx]).replace("/32",'')) + '''
                    suppress-arp
            ''')
        if break_flag:
            break
        start_l2_vni = end_l2_vni + 1
        end_l2_vni = ''
        l2_mcast_grp_ip_indx+=1

    # ---------------------------------------
    # Looping for L3VNI / VRF configurations
    ip_index                = 0
    l3_mcast_grp_ip_indx    = 0
    l2_mcast_grp_ip_indx    = 0
    l3_mcast_grp_ip_ctr     = 0
    l2_mcast_grp_ip_ctr     = 0
    l3_vrf_count_iter       = 0
    vrf_id                  = nve_dict['VRF_id_start']
    l3_vn_seg_id            = nve_dict['l3_vni_start']
    l2_vlan_id              = nve_dict['l2_vlan_start']
    start_l2_vlan_id        = nve_dict['l2_vlan_start']
    l2_vn_seg_id            = nve_dict['l2_vni_start']
    start_l3_vni = l3_vn_seg_id
    end_l3_vni = int(l3_vn_seg_id) + int(nve_dict['VRF_count']) - 1
    log.info("start_l3_vni is - "+str(start_l3_vni))
    log.info("end_l3_vni is - "+str(end_l3_vni))
    
    while l3_vrf_count_iter < nve_dict['VRF_count']:
        
        # vrf_config.append('''
        dut.configure('''
        vrf context ''' + str(nve_dict['VRF_string']) + str(vrf_id) + '''
            vni ''' + str(l3_vn_seg_id) + ''' l3
            ip pim ssm range 232.0.0.0/8
            rd auto
        ''')

        dut.configure('''
        vrf context ''' + str(nve_dict['VRF_string']) + str(vrf_id) + '''
            address-family ipv4 unicast ; route-target both auto ; route-target both auto evpn
            export map ''' + str(rmap) + '''
        ''')

        dut.configure('''
        vrf context ''' + str(nve_dict['VRF_string']) + str(vrf_id) + '''
            address-family ipv6 unicast ; route-target both auto ; route-target both auto evpn
            export map ''' + str(rmap) + '''
        ''')
        
        # Incrementing L3 VRF Iteration counters
        l3_mcast_grp_ip_ctr += 1
        if 'l3vni_per_mcast_grp' in nve_dict.keys():
            if l3_mcast_grp_ip_ctr == int(nve_dict['l3vni_per_mcast_grp']):
                l3_mcast_grp_ip_indx += 1
                l3_mcast_grp_ip_ctr = 0
        l3_vrf_count_iter += 1
        l3_vn_seg_id += 1
        vrf_id += 1
    
    # ---------------------------------------
    # Looping for L3VNI / VRF configurations
    ip_index                = 0
    l3_mcast_grp_ip_indx    = 0
    l2_mcast_grp_ip_indx    = 0
    l3_mcast_grp_ip_ctr     = 0
    l2_mcast_grp_ip_ctr     = 0
    l3_vrf_count_iter       = 0
    vrf_id                  = nve_dict['VRF_id_start']
    l3_vn_seg_id            = nve_dict['l3_vni_start']
    l2_vlan_id              = nve_dict['l2_vlan_start']
    start_l2_vlan_id        = nve_dict['l2_vlan_start']
    l2_vn_seg_id            = nve_dict['l2_vni_start']
    start_l3_vni = l3_vn_seg_id
    end_l3_vni = int(l3_vn_seg_id) + int(nve_dict['VRF_count']) - 1
    log.info("start_l3_vni is - "+str(start_l3_vni))
    log.info("end_l3_vni is - "+str(end_l3_vni))
    
    while l3_vrf_count_iter < nve_dict['VRF_count']:
        
        # bgp_config.append('''
        dut.configure('''
                router bgp ''' + str(bgp_as) + '''
                vrf ''' + str(nve_dict['VRF_string']) + str(vrf_id) + '''
                    address-family ipv4 unicast ; advertise l2vpn evpn ; wait-igp-convergence
                    redistribute direct route-map ''' + str(rmap) + '''
        ''')

        dut.configure('''
                router bgp ''' + str(bgp_as) + '''
                vrf ''' + str(nve_dict['VRF_string']) + str(vrf_id) + '''
                    address-family ipv6 unicast ; advertise l2vpn evpn ; wait-igp-convergence
                    redistribute direct route-map ''' + str(rmap) + '''
        ''')

        # Incrementing L3 VRF Iteration counters
        l3_mcast_grp_ip_ctr += 1
        if 'l3vni_per_mcast_grp' in nve_dict.keys():
            if l3_mcast_grp_ip_ctr == int(nve_dict['l3vni_per_mcast_grp']):
                l3_mcast_grp_ip_indx += 1
                l3_mcast_grp_ip_ctr = 0
        l3_vrf_count_iter += 1
        l3_vn_seg_id += 1
        vrf_id += 1

    # ---------------------------------------
    # Looping for L3VNI / VRF configurations
    ip_index                = 0
    l3_mcast_grp_ip_indx    = 0
    l2_mcast_grp_ip_indx    = 0
    l3_mcast_grp_ip_ctr     = 0
    l2_mcast_grp_ip_ctr     = 0
    l3_vrf_count_iter       = 0
    l2_vlan_count_iter      = 0
    vrf_id                  = nve_dict['VRF_id_start']
    l3_vn_seg_id            = nve_dict['l3_vni_start']
    l2_vlan_id              = nve_dict['l2_vlan_start']
    start_l2_vlan_id        = nve_dict['l2_vlan_start']
    l2_vn_seg_id            = nve_dict['l2_vni_start']
    start_l3_vni = l3_vn_seg_id
    end_l3_vni = int(l3_vn_seg_id) + int(nve_dict['VRF_count']) - 1
    log.info("start_l3_vni is - "+str(start_l3_vni))
    log.info("end_l3_vni is - "+str(end_l3_vni))
    
    while l3_vrf_count_iter < nve_dict['VRF_count']:

        while l2_vlan_count_iter < nve_dict['VLAN_PER_VRF_count']:
            
            if 'l2_vlan_ipv4_start' in nve_dict.keys():
                    
                # vlan_vni_config.append('''
                dut.configure('''
                vlan ''' + str(l2_vlan_id) + '''
                    vn-segment ''' + str(l2_vn_seg_id) + '''
                    state active
                    no shut
                ''')
                
                vlan_svi_config.append('''
                interface vlan ''' + str(l2_vlan_id) + '''
                    no shutdown
                    vrf member ''' + str(nve_dict['VRF_string']) + str(vrf_id) + '''
                    no ip redirects
                    ip address ''' + str(l2vni_svi_ipv4s[ip_index]) + '''
                    no ipv6 redirects
                    fabric forwarding mode anycast-gateway
                ''')
                
                if 'l2_vlan_ipv6_start' in nve_dict.keys():
                    vlan_svi_config.append('''
                    ipv6 address ''' + str(l2vni_svi_ipv6s[ip_index]) + '''
                    ''')

                if 'l2_vlan_ipv6_start' in nve_dict.keys():
                    dut.configure('''
                    interface vlan ''' + str(l2_vlan_id) + '''
                        no shutdown
                        vrf member ''' + str(nve_dict['VRF_string']) + str(vrf_id) + '''
                        no ip redirects
                        ip address ''' + str(l2vni_svi_ipv4s[ip_index]) + '''
                        ipv6 address ''' + str(l2vni_svi_ipv6s[ip_index]) + '''
                        no ipv6 redirects
                        fabric forwarding mode anycast-gateway
                    ''')
                else:
                    dut.configure('''
                    interface vlan ''' + str(l2_vlan_id) + '''
                        no shutdown
                        vrf member ''' + str(nve_dict['VRF_string']) + str(vrf_id) + '''
                        no ip redirects
                        ip address ''' + str(l2vni_svi_ipv4s[ip_index]) + '''
                        no ipv6 redirects
                        fabric forwarding mode anycast-gateway
                    ''')

            else:
                # vlan_vni_config.append('''
                dut.configure('''
                vlan ''' + str(l2_vlan_id) + '''
                    vn-segment ''' + str(l2_vn_seg_id) + '''
                    state active
                    no shut
                ''')

            # evpn_config.append('''
            dut.configure('''
                evpn
                    vni ''' + str(l2_vn_seg_id) + ''' l2
                        rd auto
                        route-target import auto
                        route-target export auto
            ''')

            # Incrementing L2 VLAN Iteration counters
            l2_mcast_grp_ip_ctr += 1
            if l2_mcast_grp_ip_ctr == int(nve_dict['l2vni_per_mcast_grp']):
                l2_mcast_grp_ip_indx += 1
                l2_mcast_grp_ip_ctr = 0
            l2_vlan_count_iter += 1
            l2_vlan_id += 1
            l2_vn_seg_id += 1
            ip_index += 1

        # Incrementing L3 VRF Iteration counters
        l3_mcast_grp_ip_ctr += 1
        if 'l3vni_per_mcast_grp' in nve_dict.keys():
            if l3_mcast_grp_ip_ctr == int(nve_dict['l3vni_per_mcast_grp']):
                l3_mcast_grp_ip_indx += 1
                l3_mcast_grp_ip_ctr = 0
        l3_vrf_count_iter += 1
        l3_vn_seg_id += 1
        vrf_id += 1

    # --------------------------------------------
    # Apply the configuration on the SPINEs.
    # --------------------------------------------
    # log.info("=========== Configuring LEAF num "+str(dut)+" ===========")
    # split_level     = 4
    # vrf_split_level = 10
    # log.info("=========== Applying VLAN VNI configs ===========")
    # splits = np.array_split(vlan_vni_config, split_level)
    # for array in splits:
    #     # log.info(array)
    #     dut.configure(list(array), prompt_recovery=True, timeout=3000)
    #     sleep(10)
    # log.info("=========== Applying VRF configs ===========")
    # splits = np.array_split(vrf_config, vrf_split_level)
    # for array in splits:
    #     # log.info(array)
    #     dut.configure(list(array), prompt_recovery=True, timeout=3000)
    #     sleep(10)
    # log.info("=========== Applying INT NVE configs ===========")
    # splits = np.array_split(nve_int_config, split_level)
    # for array in splits:
    #     nve_int_arr = list(array)
    #     nve_int_arr.insert(0,'interface nve1')
    #     # log.info(nve_int_arr)
    #     dut.configure(nve_int_arr, prompt_recovery=True, timeout=3000)
    #     sleep(10)
    # log.info("=========== Applying BGP configs ===========")
    # splits = np.array_split(bgp_config, split_level)
    # for array in splits:
    #     bgp_arr = list(array)
    #     bgp_arr.insert(0,'router bgp ' + str(bgp_as))
    #     # log.info(bgp_arr)
    #     dut.configure(bgp_arr, prompt_recovery=True, timeout=3000)
    #     sleep(10)
    # log.info("=========== Applying EVPN configs ===========")
    # splits = np.array_split(evpn_config, split_level)
    # for array in splits:
    #     evpn_arr = list(array)
    #     evpn_arr.insert(0,'evpn')
    #     # log.info(evpn_arr)
    #     dut.configure(evpn_arr, prompt_recovery=True, timeout=3000)
    #     sleep(10)
    # log.info("=========== Applying VLAN SVI configs ===========")
    # splits = np.array_split(vlan_svi_config, split_level)
    # for array in splits:
    #     # log.info(array)
    #     dut.configure(list(array), prompt_recovery=True, timeout=3000)
    #     sleep(10)
    # sleep(120)

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
###                  COMMON SETUP SECTION                       ###
###################################################################

class ConfigureIxia(nxtest.Testcase):
    """ Configuring IXIA """

    @aetest.test
    def InitializeIxia(self, testscript, testbed, steps):
        """ Initializing IXIA Testbed """

        with steps.start("Get the IXIA details from testbed YAML file"):
            
            if "ixia" in testbed.devices:

                ixia_chassis_ip = testbed.devices['ixia'].connections.tgn.ixia_chassis_ip
                ixia_tcl_server = testbed.devices['ixia'].connections.tgn.ixnetwork_api_server_ip
                ixia_tcl_port   = str(testbed.devices['ixia'].connections.tgn.ixnetwork_tcl_port)
                ixia_int_list   = testbed.devices['ixia'].connections.tgn.ixia_port_list
                ixia_port_list  = testbed.devices['ixia'].connections.tgn.ixia_port_list
                ixia_int_list   = ""
                for intPort in ixia_port_list:
                    ixia_int_list += str(intPort)+" "

            else:
                log.info("IXIA details not provided in testbed file")

        with steps.start("Connect to IXIA Chassis"):

            ixiaArgDict = {
                'chassis_ip': ixia_chassis_ip,
                'port_list': ixia_int_list,
                'tcl_server': ixia_tcl_server,
                'tcl_port': ixia_tcl_port,
            }

            log.info("Ixia Args Dict is:")
            log.info(ixiaArgDict)

            result = ixLib.connect_to_ixia(ixiaArgDict)
            if result == 0:
                log.debug("Connecting to ixia failed")
                self.failed("Connecting to ixia failed", goto=['next_tc'])

            testscript.parameters['ixia_connect_result'] = result

            log.info(result)
            log.info(testscript.parameters['ixia_connect_result'])

            ch_key = result['port_handle']
            for ch_p in ixia_chassis_ip.split('.'):
                ch_key = ch_key[ch_p]

            log.info("Port Handles are:")
            log.info(ch_key)

            testscript.parameters['s2_bgw_1_port_handle_1']     = ch_key[ixia_port_list[0]]
            testscript.parameters['s2_bgw_2_port_handle_1']     = ch_key[ixia_port_list[1]]
            testscript.parameters['s2_leaf_1_port_handle_1']    = ch_key[ixia_port_list[2]]
            testscript.parameters['s3_bgw_1_port_handle_1']     = ch_key[ixia_port_list[3]]
            testscript.parameters['s3_bgw_2_port_handle_1']     = ch_key[ixia_port_list[4]]
            testscript.parameters['s3_leaf_1_port_handle_1']    = ch_key[ixia_port_list[5]]
            
            for intPort in testbed.interfaces:
                if intPort.name == ixia_port_list[0]:
                    testscript.parameters['s2_bgw_1_port_handle_1_phyMode'] = str(intPort.type)
                if intPort.name == ixia_port_list[1]:
                    testscript.parameters['s2_bgw_2_port_handle_1_phyMode'] = str(intPort.type)
                if intPort.name == ixia_port_list[2]:
                    testscript.parameters['s2_leaf_1_port_handle_1_phyMode'] = str(intPort.type)
                if intPort.name == ixia_port_list[3]:
                    testscript.parameters['s3_bgw_1_port_handle_1_phyMode'] = str(intPort.type)
                if intPort.name == ixia_port_list[4]:
                    testscript.parameters['s3_bgw_2_port_handle_1_phyMode'] = str(intPort.type)
                if intPort.name == ixia_port_list[5]:
                    testscript.parameters['s3_leaf_1_port_handle_1_phyMode'] = str(intPort.type)

        with steps.start("Change Interfaces PhyMode"):
            fail_flag = []
            for intPort in testbed.interfaces:
                if intPort.name in ch_key.keys():
                    fail_flag.append(ixLib.change_phymode(ch_key[intPort.name], intPort.type))
            
            if 0 in fail_flag:
                self.failed(reason="Could not change the PhyMode of interfaces")
            else:
                self.passed(reason="Changed the PhyMode of interfaces")

    @aetest.test
    def ConfigureDeviceGrpTopology(self, testscript, steps):
        """ Configure IXIA Device Groups and Topologies """

        with steps.start("Generate needed parameters"):
        
            TOPO_1_dict = {'topology_name': 'TP-S2-BGW-1',
                        'device_grp_name': 'DG-S2-BGW-1',
                        'port_handle': testscript.parameters['s2_bgw_1_port_handle_1']}

            TOPO_2_dict = {'topology_name': 'TP-S2-BGW-2',
                        'device_grp_name': 'DG-S2-BGW-2',
                        'port_handle': testscript.parameters['s2_bgw_2_port_handle_1']}

            TOPO_3_dict = {'topology_name': 'TP-S2-LEAF-1',
                        'device_grp_name': 'DG-S2-LEAF-1',
                        'port_handle': testscript.parameters['s2_leaf_1_port_handle_1']}

            TOPO_4_dict = {'topology_name': 'TP-S3-BGW-1',
                        'device_grp_name': 'DG-S3-BGW-1',
                        'port_handle': testscript.parameters['s3_bgw_1_port_handle_1']}

            TOPO_5_dict = {'topology_name': 'TP-S3-BGW-2',
                        'device_grp_name': 'DG-S3-BGW-2',
                        'port_handle': testscript.parameters['s3_bgw_2_port_handle_1']}

            TOPO_6_dict = {'topology_name': 'TP-S3-LEAF-1',
                        'device_grp_name': 'DG-S3-LEAF-1',
                        'port_handle': testscript.parameters['s3_leaf_1_port_handle_1']}

        with steps.start("Push and configure Topology and Device Groups on IXIA"):

            testscript.parameters['IX_TP_S2_BGW_1'] = ixLib.create_topo_device_grp(TOPO_1_dict)
            if testscript.parameters['IX_TP_S2_BGW_1'] == 0:
                log.debug("Creating Topology failed")
                self.errored("Creating Topology failed", goto=['next_tc'])
            else:
                log.info("Created IX_TP_S2_BGW_1 Topology Successfully")

            testscript.parameters['IX_TP_S2_BGW_2'] = ixLib.create_topo_device_grp(TOPO_2_dict)
            if testscript.parameters['IX_TP_S2_BGW_2'] == 0:
                log.debug("Creating Topology failed")
                self.errored("Creating Topology failed", goto=['next_tc'])
            else:
                log.info("Created IX_TP_S2_BGW_2 Topology Successfully")

            testscript.parameters['IX_TP_S2_LEAF_1'] = ixLib.create_topo_device_grp(TOPO_3_dict)
            if testscript.parameters['IX_TP_S2_LEAF_1'] == 0:
                log.debug("Creating Topology failed")
                self.errored("Creating Topology failed", goto=['next_tc'])
            else:
                log.info("Created IX_TP_S2_LEAF_1 Topology Successfully")

            testscript.parameters['IX_TP_S3_BGW_1'] = ixLib.create_topo_device_grp(TOPO_4_dict)
            if testscript.parameters['IX_TP_S3_BGW_1'] == 0:
                log.debug("Creating Topology failed")
                self.errored("Creating Topology failed", goto=['next_tc'])
            else:
                log.info("Created IX_TP_S3_BGW_1 Topology Successfully")

            testscript.parameters['IX_TP_S3_BGW_2'] = ixLib.create_topo_device_grp(TOPO_5_dict)
            if testscript.parameters['IX_TP_S3_BGW_2'] == 0:
                log.debug("Creating Topology failed")
                self.errored("Creating Topology failed", goto=['next_tc'])
            else:
                log.info("Created IX_TP_S3_BGW_2 Topology Successfully")

            testscript.parameters['IX_TP_S3_LEAF_1'] = ixLib.create_topo_device_grp(TOPO_6_dict)
            if testscript.parameters['IX_TP_S3_LEAF_1'] == 0:
                log.debug("Creating Topology failed")
                self.errored("Creating Topology failed", goto=['next_tc'])
            else:
                log.info("Created IX_TP_S3_LEAF_1 Topology Successfully")

            testscript.parameters['IX_TP_S2_BGW_1']['port_handle']     = testscript.parameters['s2_bgw_1_port_handle_1']
            testscript.parameters['IX_TP_S2_BGW_2']['port_handle']     = testscript.parameters['s2_bgw_2_port_handle_1']
            testscript.parameters['IX_TP_S2_LEAF_1']['port_handle']    = testscript.parameters['s2_leaf_1_port_handle_1']
            testscript.parameters['IX_TP_S3_BGW_1']['port_handle']     = testscript.parameters['s3_bgw_1_port_handle_1']
            testscript.parameters['IX_TP_S3_BGW_2']['port_handle']     = testscript.parameters['s3_bgw_2_port_handle_1']
            testscript.parameters['IX_TP_S3_LEAF_1']['port_handle']    = testscript.parameters['s3_leaf_1_port_handle_1']

    @aetest.test
    def ConfigureInterfaces(self, testscript, steps):
        """ Configure IXIA Device Groups and Topologies """

        with steps.start("Generate needed parameters"):

            P1 = testscript.parameters['s2_leaf_1_port_handle_1']
            P2 = testscript.parameters['s3_leaf_1_port_handle_1']

            TGEN_data = self.parameters.get('IXIA_TGEN_data', {})
            log.info(TGEN_data)

            P1_dict = TGEN_data['LEAF_1_TGEN_data']
            P2_dict = TGEN_data['LEAF_2_TGEN_data']

            P1_int_dict_1 = {
                            'dev_grp_hndl'      : testscript.parameters['IX_TP_S2_LEAF_1']['dev_grp_hndl'],
                            'port_hndl'         : P1,
                            'no_of_ints'        : P1_dict['no_of_ints'],
                            'phy_mode'          : testscript.parameters['s2_leaf_1_port_handle_1_phyMode'],
                            'mac'               : P1_dict['mac'],
                            'mac_step'          : P1_dict['mac_step'],
                            'protocol'          : P1_dict['protocol'],
                            'v4_addr'           : P1_dict['v4_addr'],
                            'v4_addr_step'      : P1_dict['v4_addr_step'],
                            'v4_gateway'        : P1_dict['v4_gateway'],
                            'v4_gateway_step'   : P1_dict['v4_gateway_step'],
                            'v4_netmask'        : P1_dict['v4_netmask'],
                            'v6_addr'           : P1_dict['v6_addr'],
                            'v6_addr_step'      : P1_dict['v6_addr_step'],
                            'v6_gateway'        : P1_dict['v6_gateway'],
                            'v6_gateway_step'   : P1_dict['v6_gateway_step'],
                            'v6_netmask'        : P1_dict['v6_netmask'],
                            'vlan_id'           : P1_dict['vlan_id'],
                            'vlan_id_step'      : P1_dict['vlan_id_step']}

            P2_int_dict_1 = {
                            'dev_grp_hndl'      : testscript.parameters['IX_TP_S3_LEAF_1']['dev_grp_hndl'],
                            'port_hndl'         : P2,
                            'no_of_ints'        : P2_dict['no_of_ints'],
                            'phy_mode'          : testscript.parameters['s3_leaf_1_port_handle_1_phyMode'],
                            'mac'               : P2_dict['mac'],
                            'mac_step'          : P2_dict['mac_step'],
                            'protocol'          : P2_dict['protocol'],
                            'v4_addr'           : P2_dict['v4_addr'],
                            'v4_addr_step'      : P2_dict['v4_addr_step'],
                            'v4_gateway'        : P2_dict['v4_gateway'],
                            'v4_gateway_step'   : P2_dict['v4_gateway_step'],
                            'v4_netmask'        : P2_dict['v4_netmask'],
                            'v6_addr'           : P2_dict['v6_addr'],
                            'v6_addr_step'      : P2_dict['v6_addr_step'],
                            'v6_gateway'        : P2_dict['v6_gateway'],
                            'v6_gateway_step'   : P2_dict['v6_gateway_step'],
                            'v6_netmask'        : P2_dict['v6_netmask'],
                            'vlan_id'           : P1_dict['vlan_id'],
                            'vlan_id_step'      : P1_dict['vlan_id_step']}

        with steps.start("Push and Configure Ixia Interfaces"):

            P1_IX_int_data = ixLib.configure_multi_ixia_interface(P1_int_dict_1)
            P2_IX_int_data = ixLib.configure_multi_ixia_interface(P2_int_dict_1)
            log.info(P1_IX_int_data)
            log.info(P2_IX_int_data)

            if P1_IX_int_data == 0 or P2_IX_int_data == 0:
                log.debug("Configuring IXIA Interface failed")
                self.errored("Configuring IXIA Interface failed", goto=['next_tc'])
            else:
                log.info("Configured IXIA Interface Successfully")

            testscript.parameters['IX_TP_S2_LEAF_1']['eth_handle'] = P1_IX_int_data['eth_handle']
            testscript.parameters['IX_TP_S2_LEAF_1']['ipv4_handle'] = P1_IX_int_data['ipv4_handle']
            testscript.parameters['IX_TP_S2_LEAF_1']['ipv6_handle'] = P1_IX_int_data['ipv6_handle']
            testscript.parameters['IX_TP_S2_LEAF_1']['topo_int_handle'] = P1_IX_int_data['topo_int_handle'].split(" ")

            testscript.parameters['IX_TP_S3_LEAF_1']['eth_handle'] = P2_IX_int_data['eth_handle']
            testscript.parameters['IX_TP_S3_LEAF_1']['ipv4_handle'] = P2_IX_int_data['ipv4_handle']
            testscript.parameters['IX_TP_S3_LEAF_1']['ipv6_handle'] = P2_IX_int_data['ipv6_handle']
            testscript.parameters['IX_TP_S3_LEAF_1']['topo_int_handle'] = P2_IX_int_data['topo_int_handle'].split(" ")

            log.info("IXIA Port 1 Handles")
            log.info(testscript.parameters['IX_TP_S2_LEAF_1'])
            log.info("IXIA Port 2 Handles")
            log.info(testscript.parameters['IX_TP_S3_LEAF_1'])

    @aetest.test
    def initiateIxiaProtocols(self, steps):
        """ IXIA_CONFIGURATION subsection: Configure IXIA IGMP Groups """

        with steps.start("Start Protocols and wait"):
            # _result_ = ixiahlt.test_control(action='configure_all')
            # print(_result_)
            proto_result = ixLib.start_protocols()
            if proto_result == 0:
                log.debug("Starting Protocols failed")
                self.errored("Starting Protocols failed", goto=['next_tc'])
            else:
                log.info("Started Protocols Successfully")

            sleep(60)

        with steps.start("Stop Protocols and wait"):
            proto_result = ixLib.stop_protocols()
            if proto_result == 0:
                log.debug("Stopped Protocols failed")
                self.errored("Stopped Protocols failed", goto=['next_tc'])
            else:
                log.info("Stopped Protocols Successfully")

            sleep(30)

        with steps.start("Start the Protocols"):
            proto_result = ixLib.start_protocols()
            if proto_result == 0:
                log.debug("Starting Protocols failed")
                self.errored("Starting Protocols failed", goto=['next_tc'])
            else:
                log.info("Started Protocols Successfully")

    @aetest.test
    def configureIxiaIPv4TrafficItem(self, testscript, steps):
        """ Configure IXIA IPv4 Traffic Items """

        with steps.start("Generate needed parameters"):

            IX_TP1 = testscript.parameters['IX_TP_S2_LEAF_1']
            IX_TP2 = testscript.parameters['IX_TP_S3_LEAF_1']

            L2KUC_v4_dict_1 = {'src_hndl'   : IX_TP1['ipv4_handle'],
                                'dst_hndl'  : IX_TP2['ipv4_handle'],
                                'circuit'   : 'ipv4',
                                'TI_name'   : "L2KUC_S1_S2_V4",
                                'rate_pps'  : "100000",
                                'bi_dir'    : 1
                                }

        with steps.start("Push and Configure Ixia Traffic Items"):
            
            L2KUC_v4_TI_1 = ixLib.configure_ixia_traffic_item(L2KUC_v4_dict_1)
            if L2KUC_v4_TI_1 == 0:
                log.debug("Configuring IPv4 L2 KUC failed")
                self.errored("Configuring IPv4 L2 KUC failed", goto=['next_tc'])

    @aetest.test
    def configureIxiaIPv6TrafficItem(self, testscript, steps):
        """ Configure IXIA IPv6 Traffic Items """

        with steps.start("Generate needed parameters"):

            IX_TP1 = testscript.parameters['IX_TP_S2_LEAF_1']
            IX_TP2 = testscript.parameters['IX_TP_S3_LEAF_1']

            L2KUC_v6_dict_1 = {'src_hndl'   : IX_TP1['ipv6_handle'],
                                'dst_hndl'  : IX_TP2['ipv6_handle'],
                                'circuit'   : 'ipv6',
                                'TI_name'   : "L2KUC_S1_S2_V6",
                                'rate_pps'  : "100000",
                                'bi_dir'    : 1
                                }

        with steps.start("Push and Configure Ixia Traffic Items"):
            
            L2KUC_v6_TI_1 = ixLib.configure_ixia_traffic_item(L2KUC_v6_dict_1)
            if L2KUC_v6_TI_1 == 0:
                log.debug("Configuring IPv6 L2 KUC failed")
                self.errored("Configuring IPv6 L2 KUC failed", goto=['next_tc'])

    @aetest.test
    def CONFIGURE_BUM_BCAST_IXIA_TRAFFIC(self, testscript):
        """ Configure IXIA BUM - BCast Traffic Items """

        IX_TP1 = testscript.parameters['IX_TP_S2_BGW_1']
        IX_TP2 = testscript.parameters['IX_TP_S2_BGW_2']
        IX_TP3 = testscript.parameters['IX_TP_S2_LEAF_1']
        IX_TP4 = testscript.parameters['IX_TP_S3_BGW_1']
        IX_TP5 = testscript.parameters['IX_TP_S3_BGW_2']
        IX_TP6 = testscript.parameters['IX_TP_S3_LEAF_1']
        
        TGEN_data = self.parameters.get('IXIA_TGEN_data', {})
        log.info(TGEN_data)
        P1_dict = TGEN_data['LEAF_1_TGEN_data']

        BCAST_SRC_S1_L1_dict = {
                            'src_hndl'      : IX_TP3['port_handle'],
                            'dst_hndl'      : [IX_TP1['port_handle'],IX_TP2['port_handle'],IX_TP4['port_handle'], IX_TP5['port_handle'], IX_TP6['port_handle']],
                            'TI_name'       : "BCAST_SRC_S1_L1",
                            'frame_size'    : "70",
                            'rate_pps'      : "1000",
                            'src_mac'       : "00:20:21:00:00:01",
                            'srcmac_step'   : "00:00:00:00:00:01",
                            'srcmac_count'  : str(P1_dict['no_of_ints']),
                            'vlan_id'       : P1_dict['vlan_id'],
                            'vlanid_step'   : "1",
                            'vlanid_count'  : P1_dict['no_of_ints'],
                            'ip_src_addrs'  : "21.1.1.10",
                            'ip_step'       : "0.0.1.0",
                      }

        BCAST_SRC_S1_L1_TI = ixLib.configure_ixia_BCAST_traffic_item(BCAST_SRC_S1_L1_dict)

        if BCAST_SRC_S1_L1_TI == 0:
            log.debug("Configuring BCast from Site-1 LEAF-1 failed")
            self.errored("Configuring BCast from Site-1 LEAF-1 failed", goto=['next_tc'])

    @aetest.test
    def CONFIGURE_BUM_Unknown_UCAST_IXIA_TRAFFIC(self, testscript):
        """ Configure IXIA BUM - Unknown UCast Traffic Items """

        IX_TP1 = testscript.parameters['IX_TP_S2_BGW_1']
        IX_TP2 = testscript.parameters['IX_TP_S2_BGW_2']
        IX_TP3 = testscript.parameters['IX_TP_S2_LEAF_1']
        IX_TP4 = testscript.parameters['IX_TP_S3_BGW_1']
        IX_TP5 = testscript.parameters['IX_TP_S3_BGW_2']
        IX_TP6 = testscript.parameters['IX_TP_S3_LEAF_1']
        
        TGEN_data = self.parameters.get('IXIA_TGEN_data', {})
        log.info(TGEN_data)
        P1_dict = TGEN_data['LEAF_1_TGEN_data']

        UnknUCAST_SA_2_vPC_dict = {
                            'src_hndl'      : IX_TP3['port_handle'],
                            'dst_hndl'      : [IX_TP1['port_handle'],IX_TP2['port_handle'],IX_TP4['port_handle'], IX_TP5['port_handle'], IX_TP6['port_handle']],
                            'TI_name'       : "UnknUCAST_SA_2_vPC",
                            'frame_size'    : "70",
                            'rate_pps'      : "1000",
                            'src_mac'       : "00:20:31:00:00:01",
                            'srcmac_step'   : "00:00:00:00:00:01",
                            'srcmac_count'  : "100",
                            'vlan_id'       : P1_dict['vlan_id'],
                            'vlanid_step'   : "1",
                            'vlanid_count'  : P1_dict['no_of_ints'],
                            'ip_src_addrs'  : "22.1.1.10",
                            'ip_step'       : "0.0.1.0",
                      }

        UnknUCAST_SA_2_vPC_TI = ixLib.configure_ixia_BCAST_traffic_item(UnknUCAST_SA_2_vPC_dict)

        if UnknUCAST_SA_2_vPC_TI == 0:
            log.debug("Configuring Unknown Ucast from Site-1 LEAF-1 failed")
            self.errored("Configuring Unknown Ucast from Site-1 LEAF-1 failed", goto=['next_tc'])

    @aetest.test
    def applyTrafficItems(self, steps):
        """ Configure IXIA Device Groups and Topologies """

        with steps.start("Apply Traffic Items on Ixia"):
            if ixLib.apply_traffic() == 1:
                log.info("Applying IXIA TI Passed")
            else:
                self.errored("Applying IXIA TI failed", goto=['next_tc'])

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

class ConfigureAdjustIPV6L2VNI(nxtest.Testcase):
    """ ConfigureAdjustIPV6L2VNI - Adjust the IPv6 increment of L2VNIs """

    @aetest.test
    def AdjustIPV6L2VNI(self, testbed, device_dut, start_vlan, start_ipv6, ipv6_mask, vlan_count):
        """ ConfigureAdjustIPV6L2VNI - Adjust the IPv6 increment of L2VNIs """

        # Build the IPV6 addresses
        l2_ipv6s = increment_prefix_network(ip.IPv6Interface(str(start_ipv6) + str(ipv6_mask)), int(vlan_count))

        # Build the configuration
        configs = ''
        ip_counter = 0
        for vlan in range(start_vlan,int(start_vlan)+int(vlan_count)):
            configs += '''
            interface vlan '''+str(vlan)+'''
                no ipv6 address
                ipv6 address '''+str(l2_ipv6s[ip_counter])+'''
                no shutdown
            '''
            ip_counter+=1

        # Apply the configuration on devices
        for node in device_dut:
            testbed.devices[node].configure(configs,timeout=300)

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
                vrf_output = json.loads(testbed.devices[node].execute("sh vrf | json"))["TABLE_vrf"]["ROW_vrf"]
                for vrf in vrf_output:
                    if str(vrf['vrf_name']) != 'default' and str(vrf['vrf_name']) != 'management':
                        testscript.parameters[node]['vrf_data'][str(vrf['vrf_name'])] = {}
                        vrf_run_output = testbed.devices[node].execute('show run vrf '+str(vrf['vrf_name'])+' | beg i "context" | head line 2')
                        vrf_run_regex = re.search("vni (\\d+)", vrf_run_output,re.M)
                        if vrf_run_regex:
                            testscript.parameters[node]['vrf_data'][str(vrf['vrf_name'])]['vni'] = str(vrf_run_regex.groups(0)[0])
                            vni_data = json.loads(testbed.devices[node].execute('show nve vni '+str(vrf_run_regex.groups(0)[0])+' detail | json'))["TABLE_nve_vni"]["ROW_nve_vni"]
                            testscript.parameters[node]['vrf_data'][str(vrf['vrf_name'])]['vlan'] = str(vni_data['vlan-bd'])
                log.info(testscript.parameters[node]['vrf_data'])

        # Delete the OLD L3 VNI's
        with steps.start("Delete the OLD L3 VNI's"):
            for node in device_dut:
                configs = ''
                for vrf in testscript.parameters[node]['vrf_data'].keys():
                    configs += '''
                        vrf context '''+str(vrf)+'''
                            no vni '''+str(testscript.parameters[node]['vrf_data'][str(vrf)]['vni'])
                    if int(testscript.parameters[node]['vrf_data'][str(vrf)]['vlan']) < 4000:
                        configs += '''
                            no interface vlan '''+str(testscript.parameters[node]['vrf_data'][str(vrf)]['vlan'])+'''

                            no vlan '''+str(testscript.parameters[node]['vrf_data'][str(vrf)]['vlan'])+'''
                        '''
                testbed.devices[node].configure(configs)
            # Wait for 2 minutes post Deleting old L3VNIs
            sleep(60)

        # ADD the NEW L3 VNI's
        with steps.start("ADD the NEW L3 VNI's"):
            for node in device_dut:
                configs = ''
                for vrf in testscript.parameters[node]['vrf_data'].keys():
                    configs += '''
                        vrf context '''+str(vrf)+'''
                            vni '''+str(testscript.parameters[node]['vrf_data'][str(vrf)]['vni'])+''' l3
                    '''
                testbed.devices[node].configure(configs)
            # Wait for 2 minutes post adding new L3VNIs
            sleep(120)

class TriggerDeleteSVINoFeatureInterfaceVlanfromBGW(nxtest.Testcase):
    """ TriggerDeleteSVIfromBGW - Delete SVI's from BGW """

    @aetest.test
    def RemoveFeatureInterfaceVLAN(self, steps, testbed, device_dut):
        """ DeleteSVIfromBGW - Deleting the SVI's from BGW """

        # Remove the feature interface VLAN
        with steps.start("Removing the feature interface VLAN from BGWs"):
            for node in device_dut:
                testbed.devices[node].configure('no feature interface-vlan')
            # Wait for 60 seconds post feature removal
            sleep(60)

        with steps.start("Verify Feature Interface VLAN removed"):
            fail_flag = []
            fail_msgs = ''
            for node in device_dut:
                featureOutput = testbed.devices[node].execute('show run | i i interface-vlan')
                if "interface-vlan" in featureOutput:
                    fail_flag.append(0)
                    fail_msgs += str(node)+" : Removing feature interface-vlan Failed\n"
            if 0 in fail_flag:
                self.failed(reason=fail_msgs)

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
                        if 'vni' in line:
                            l3_vni = line.split()[-2]
                            vrf_vni_dict[str(vrf_name)] = l3_vni
                            log.info("Removing L3 Vni--%s for vrf--> %s", l3_vni, vrf_name)
                            vni_cmd = "{vrf_context} \n no vni {l3vni}".format(vrf_context=vrf_context, l3vni=l3_vni)
                            device.configure(vni_cmd)
                            log.info("Command executed successfully %s", vni_cmd)
                            sleep(2)
            for vrf, vni in vrf_vni_dict.items():
                log.info("Adding L3 Vni--%s for vrf--> %s", vni, vrf)
                vni_cmd = "vrf context {vrf_cxt} \n vni {l3_vni} l3".format(vrf_cxt=vrf, l3_vni=vni)
                device.configure(vni_cmd)
                log.info("Command executed successfully %s", vni_cmd)
                sleep(2)

class ConfigureVNIScaleIncrease(nxtest.Testcase):
    """ ConfigureVNIScaleIncrease - Increase the Scale to 1976 L3VNI and 9352 L2VNI """

    @aetest.test
    def scaleIncreaseBGWs(self, steps, testbed, bgw_device_dut):
        BGP_data        = self.parameters.get('bgp_config', {})
        BGW_VNI_data    = self.parameters.get('BGW_MCAST_VNI_data', {})
        
        # Create Lists
        RMAP                = ''
        BGW_VNI_data_lst    = []
        BGP_AS_lst          = []
        RMAP_lst            = []
        devices_lst         = []
        msite_flag          = []

        with steps.start("clean Older L3VNI data"):
            for node in bgw_device_dut:
                testbed.devices[node].configure('''
                    no vlan 101-110
                ''')
        
        with steps.start("clean NVE interface"):
            for node in bgw_device_dut:
                nve_output = testbed.devices[node].execute('show run int nve 1 | i i "member vni"')
                for run_line in nve_output.splitlines():
                    if "member vni" in run_line:
                        testbed.devices[node].configure('''
                            interface nve 1
                                no '''+str(run_line)+'''
                        ''')
        
        with steps.start("ADD the NEW L3 VNI's"):
            # Poluate the Lists
            for node in bgw_device_dut:
                for af in BGP_data[node]['default']['address_family_attr']:
                    if af['af_name'] == 'ipv4 unicast':
                        RMAP = str(af['af_redist_connected_route_policy'])
                BGW_VNI_data_lst.append(BGW_VNI_data)
                BGP_AS_lst.append(str(BGP_data[node]['default']['bgp_id']))
                RMAP_lst.append(RMAP)
                devices_lst.append(testbed.devices[node])
                msite_flag.append(1)
            
            pcall(generateScaleNVEConfigs,
                    nve_dict=tuple(BGW_VNI_data_lst), 
                    bgp_as=tuple(BGP_AS_lst), 
                    rmap=tuple(RMAP_lst), 
                    dut=tuple(devices_lst),
                    msite_flag=tuple(msite_flag)
                )

    @aetest.test
    def scaleIncreaseLEAFs(self, steps, testbed, leaf_device_dut):
        BGP_data        = self.parameters.get('bgp_config', {})
        LEAF_VNI_data   = self.parameters.get('LEAF_MCAST_VNI_data', {})

        # Create Lists
        RMAP                = ''
        LEAF_VNI_data_lst   = []
        BGP_AS_lst          = []
        RMAP_lst            = []
        devices_lst         = []
        msite_flag          = []

        with steps.start("clean Older L3VNI data"):
            for node in leaf_device_dut:
                testbed.devices[node].configure('''
                    no vlan 101-110
                ''')
        
        with steps.start("clean NVE interface"):
            for node in leaf_device_dut:
                nve_output = testbed.devices[node].execute('show run int nve 1 | i i "member vni"')
                for run_line in nve_output.splitlines():
                    if "member vni" in run_line:
                        testbed.devices[node].configure('''
                            interface nve 1
                                no '''+str(run_line)+'''
                        ''')

        with steps.start("ADD the NEW L3 VNI's"):
            # Poluate the Lists
            for node in leaf_device_dut:
                for af in BGP_data[node]['default']['address_family_attr']:
                    if af['af_name'] == 'ipv4 unicast':
                        RMAP = str(af['af_redist_connected_route_policy'])
                LEAF_VNI_data_lst.append(LEAF_VNI_data)
                BGP_AS_lst.append(str(BGP_data[node]['default']['bgp_id']))
                RMAP_lst.append(RMAP)
                devices_lst.append(testbed.devices[node])
                msite_flag.append(0)

            pcall(generateScaleNVEConfigs,
                    nve_dict=tuple(LEAF_VNI_data_lst), 
                    bgp_as=tuple(BGP_AS_lst), 
                    rmap=tuple(RMAP_lst), 
                    dut=tuple(devices_lst),
                    msite_flag=tuple(msite_flag)
                )

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
