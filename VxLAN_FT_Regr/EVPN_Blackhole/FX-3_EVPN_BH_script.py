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
from tkinter import dialog
from unicon.eal.dialogs import Statement,Dialog

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
import ixiaPyats_lib
ixLib = ixiaPyats_lib.ixiaPyats_lib()
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

FWD_SYS_dict = {
    'VRF_string'              : 'EVPN-BH-',
    'VRF_id_start'            : 1,
    'VRF_count'               : 10,
    'VLAN_PER_VRF_count'      : 5,
    'SPINE_COUNT'             : 1,
}

S1_BGW1_dict = {
    'loop0_ip'                            : "2.213.1.1",
    'vlans'                             : 1001,
    'vni'                               : 2001001,
    'vlan_step'                         : 75,
    'S1_BGW1_UPLINK_PO' : { 
        'po_id'                         : 221,
        'peer_link'                     : 15

    }
}



S2_BGW1_dict = {
    'loop0_ip'                            : "2.213.1.1",
    'S2_BGW1_UPLINK_PO' : { 
        'po_id'                         : 31,

    }
}

S1_Leaf_dict = {
    'loop0_ip'                            : "2.214.1.1",
    'S1_Leaf_UPLINK_PO' : {
        'po_id'                           : 211,
    }
}


S1_SPINE_dict={
    'S1_Leaf_UPLINK_PO':{
        'po_id'               : 211
    },
     'S1_BGW1_UPLINK_PO':{
        'po_id'               : 221
    },
     'S1_BGW2_UPLINK_PO':{
        'po_id'               : 222
    }}

AcceSW_dict={
    'Acc_to_vpc_PO':{
        'po_id'               : 1
    }}

S2_Leaf_dict={
    'loop0_ip'                            : "2.215.1.1",
    'S2_Leaf_UPLINK_PO':{
        'po_id'                           : 3211,
}
}

S1_BGW1_TGEN_data = {
    'no_of_ints'                    : "2",
    'phy_mode'                      : 'fiber',
    'mac'                           : '0011.9000.0010', 
    'mac_step'                      : '0000.0000.0001',
    'protocol'                      : 'ipv46',
    'v4_addr'                       : '10.1.0.10',
    'v4_addr_step'                  : '0.75.0.0',
    'v4_gateway'                    : '10.1.0.1',
    'v4_gateway_step'               : '0.75.0.0',
    'v4_netmask'                    : '255.255.0.0',
    'v6_addr'                       : '2001:10:1::10',
    'v6_addr_step'                  : '0:0:75:0::0',
    'v6_gateway'                    : '2001:10:1::1',
    'v6_gateway_step'               : '0:0:75:0::0',
    'v6_netmask'                    : '64',
    'netmask'                       : '255.255.0.0',
    'vlan_id'                       : '1001',
    'vlan_user_priority'            : '3',
    'vlan_id_step'                  : '75',
    'frame_size'                    : '128',
    'ip_dscp'                       : 20,
    'ipv6_traffic_class'            : 80,
    #'data_tos'                     : 40
    'ip_precedence'                 : 5,
    'enable_data_integrity'         : 1,
    'L3_dst_addr'                   : '10.76.0.10',
    'L3_v6_dst_addr'                : '2001:10:76::10',
    'vrfname'                       : 1,
    'igmp_ver'                      : 'v3',
    'mcast_grp_ip'                  : '225.1.1.1',
    'mcast_grp_ip_step'             : '0.0.1.0',
    'no_of_grps'                    : '1',
    'no_of_mcast_sources'           : '1'
}

S1_Leaf_TGEN_data={
    'no_of_ints'                    : "2",
    'phy_mode'                      : 'fiber',
    'mac'                           : '0012.9200.0020',
    'mac_step'                      : '0000.0000.0001',
    'protocol'                      : 'ipv46',
    'v4_addr'                       : '10.1.0.20',
    'v4_addr_step'                  : '0.75.0.0',
    'v4_gateway'                    : '10.1.0.1',
    'v4_gateway_step'               : '0.75.0.0',
    'v4_netmask'                    : '255.255.0.0',
    'v6_addr'                       : '2001:10:1::20',
    'v6_addr_step'                  : '0:0:75:0::0',
    'v6_gateway'                    : ' 2001:10:1::1',
    'v6_gateway_step'               : '0:0:75:0::0',
    'v6_netmask'                    : '64',
    'netmask'                       : '255.255.0.0',
    'vlan_id'                       : '1001',
    'vlan_user_priority'            : '3',
    'vlan_id_step'                  : '75',
    'frame_size'                    : '128',
    'ip_dscp'                       : 20,
    'ipv6_traffic_class'            : 80,
    #'data_tos'                     : 40
    'ip_precedence'                 : 5,
    'enable_data_integrity'         : 1,
    'L3_dst_addr'                   : '10.76.0.20',
    'L3_v6_dst_addr'                : '2001:10:76::20',
    'igmp_ver'                      : 'v3',
    'mcast_grp_ip'                  : '225.1.1.1',
    'mcast_grp_ip_step'             : '0.0.1.0',
    'no_of_grps'                    : '1',
    'no_of_mcast_sources'           : '1'
}

AcceSW_TGEN_data={
    'no_of_ints'                    : "2",
    'phy_mode'                      : 'fiber',
    'mac'                           : '0013.6022.0030',
    'mac_step'                      : '0000.0000.0001',
    'protocol'                      : 'ipv46',
    'v4_addr'                       : '10.1.0.30',
    'v4_addr_step'                  : '0.75.0.0',
    'v4_gateway'                    : '10.1.0.1',
    'v4_gateway_step'               : '0.75.0.0',
    'v4_netmask'                    : '255.255.0.0',
    'v6_addr'                       : '2001:10:1::30',
    'v6_addr_step'                  : '0:0:75:0::0',
    'v6_gateway'                    : '2001:10:1::1',
    'v6_gateway_step'               : '0:0:75:0::0',
    'v6_netmask'                    : '64',
    'netmask'                       : '255.255.0.0',
    'vlan_id'                       : '1001',
    'vlan_user_priority'            : '3',
    'vlan_id_step'                  : '75',
    'frame_size'                    : '128',
    'ip_dscp'                       : 20,
    'ipv6_traffic_class'            : 80,
    'ip_precedence'                 : 5,
    'enable_data_integrity'         : 1,
    'L3_dst_addr'                   : '10.76.0.30',
    'L3_v6_dst_addr'                : '2001:10:76::30',
    'igmp_ver'                      : 'v3',
    'mcast_grp_ip'                  : '225.1.1.1',
    'mcast_grp_ip_step'             : '0.0.1.0',
    'no_of_grps'                    : '1',
    'no_of_mcast_sources'           : '1'
}

S2_Leaf_TGEN_data = {
    'no_of_ints'                    : "2",
    'phy_mode'                      : 'fiber',
    'mac'                           : '0014.d018.0040',
    'mac_step'                      : '0000.0000.0001',
    'protocol'                      : 'ipv46',
    'v4_addr'                       : '10.1.0.40',
    'v4_addr_step'                  : '0.75.0.0',
    'v4_gateway'                    : '10.1.0.1',
    'v4_gateway_step'               : '0.75.0.0',
    'v4_netmask'                    : '255.255.0.0',
    'v6_addr'                       : '2001:10:1::40',
    'v6_addr_step'                  : '0:0:75:0::0',
    'v6_gateway'                    : '2001:10:1::1',
    'v6_gateway_step'               : '0:0:75:0::0',
    'v6_netmask'                    : '64',
    'netmask'                       : '255.255.0.0',
    'vlan_id'                       : '1001',
    'vlan_user_priority'            : '3',
    'vlan_id_step'                  : '75',
    'frame_size'                    : '128',
    'ip_dscp'                       : 20,
    'ipv6_traffic_class'            : 80,
    #'data_tos'                     : 40
    'ip_precedence'                 : 5,
    'enable_data_integrity'         : 1,
    'L3_dst_addr'                   : '10.76.0.40',
    'L3_v6_dst_addr'                : '2001:10:76::40',
    'igmp_ver'                      : 'v3',
    'mcast_grp_ip'                  : '225.1.1.1',
    'mcast_grp_ip_step'             : '0.0.1.0',
    'no_of_grps'                    : '1',
    'no_of_mcast_sources'           : '1'
}

## Unknow unicast traffic details

Access_TGEN_DATA_1={
    'no_of_ints'                    : "10",
    'phy_mode'                      : 'fiber',
    'mac'                           : '0022.0022.1010',
    'mac_step'                      : '0000.0000.0001',
    'vlan_id'                       : '1001',
    'vlan_user_priority'            : '3',
    'vlan_id_step'                  : '75',
}

global copy_cores
copy_cores = False
MD_REGEX = '(^default|management|external)'

###################################################################
###                  User Library Methods                       ###
###################################################################
def verify_traffic_drop(dut,interface):
    output=dut.execute('''show int Po ''' + str(interface) + ''' | i rate | i "30 seconds output"''')
    m=re.search('.*([0-9]+) packets\/sec',output)
    if m:
        if int(m.group(1))<=100:
            return True
    return False

def verify_BH_route_in_L2FM(dut,vlan_id,mac):
    output=dut.execute('''sh mac address-table vlan ''' + str(vlan_id) + ''' address ''' + str(mac) + ''' | i ''' + str(vlan_id))
    m=re.search(re.escape(str(vlan_id))+ '.*(Drop)',output)
    if m:
        return True
    return False

def verify_L2rib_output(dut,vlan,mac):
    output=dut.execute('''sh l2route mac topology ''' + str(vlan) + ''' | i ''' +mac)
    m=re.search(re.escape(mac)+'\s+.*Stt,Bh',output)
    if m:
        return True
    return False

def verify_L2rib_mac_ip_output(dut,vlan,mac):
    output=dut.execute('''sh l2route mac-ip topology ''' + str(vlan) + ''' | i ''' +mac)
    m=re.search(re.escape(mac)+'\s+.*Stt,Bh',output)
    if m:
        return True
    return False

def verify_L2rib_staticmac_output(dut,vlan,mac):
    output=dut.execute('''sh l2route mac topology ''' + str(vlan) + ''' | i ''' +mac)
    m=re.search(re.escape(mac)+'\s+.*Stt',output)
    if m:
        return True
    return False

def verify_BH_in_Remote_ARP(dut,vlan,mac):
    output=json.loads(dut.execute('''sh ip arp static remote vlan '''+ str(vlan) + ''' vrf  vrf-1 | json'''))
    m=output['TABLE_vrf']['ROW_vrf']['TABLE_ip_arp_static_remote']['ROW_ip_arp_static_remote']['ip_arp_static_remote_flags']
    log.info(output)
    log.info(m)
    if (m == "Bh"):
        print(m)
        return True
    return False

def verify_BH_in_local_ARP(dut,vlan,mac):
    output=dut.execute('''sh ip arp static vrf vrf-1 | i ''' +mac)
    m=re.search('.*'+re.escape(mac)+'\s+Vlan' + re.escape(str(vlan))+'\s+(-)',output)
    if m:
        print(m)
        return True
    return False


def verify_BH_in_Remote_BGP(dut,addr):
    output=dut.execute('''sh bgp l2vpn evpn '''+ addr + ''' |i "Community" ''' )
    m = re.search('Community: blackhole', output)
    if m[0] == "Community: blackhole":
        return True
    else:
        return False

def verify_BH_in_AM(dut,vlan,mac,v4_addr):
    output=dut.execute(''' sh ip adjacency  ''' + v4_addr +  '''  vrf  vrf-1 | i ''' + v4_addr)
    m= re.search("D",output)
    if m[0]:
        print(m[0])
        return True
    return False

def verify_Ipv6_BH_in_AM(dut,vlan,mac,v6_addr):
    output=dut.execute(''' sh ipv6 adjacency  ''' + v6_addr +  '''  vrf  vrf-1 | i ''' + v6_addr)
    m= re.search("D",output)
    if m[0]:
        print(m[0])
        return True
    return False

def verify_BH_in_HMM(dut,v4_addr):
    output=dut.execute(''' sh fabric forwarding ip local-host-db vrf vrf-1  ''' + v4_addr + '''/32''')
    if output != '':
        return True
    return False

def verify_Ipv6_BH_in_HMM(dut,v6_addr):
    output=dut.execute(''' sh fabric forwarding ipv6 local-host-db vrf vrf-1  ''' + v6_addr + '''/128''')
    if output != '':
        return True
    return False
    # def verify_BH_in_Remote_BGP(dut,addr,Community):
#     output=dut.execute('''sh bgp l2vpn evpn ''' +addr)
#     m=re.search(str(Community)+ ',*(blackhole)',output)
#     if m:
#         return True
#     return False

def verify_dynamic_mac(dut,mac,vlan_id):
    a = json.loads(dut.execute('''sh mac address-table vlan ''' + str(vlan_id) + ''' address '''+ mac + ''' | json '''  ))
    if a['TABLE_mac_address']['ROW_mac_address']['disp_type']=="dynamic":
        return True
    else:
    	return False

def verify_static_mac(dut,mac,vlan_id):
    a = json.loads(dut.execute('''sh mac address-table vlan ''' + str(vlan_id) + ''' address '''+ mac + ''' | json '''  ))
    if a['TABLE_mac_address']['ROW_mac_address']['disp_type']=="static":
        return True
    else:
    	return False

def Verify_ipv6_local_neighbor(dut,mac,vlan_id):
    output=dut.execute('''  sh ipv6 neighbor vlan ''' + str(vlan_id) + ''' vrf vrf-1 |i ''' + mac )
    a=re.search("D", output)
    if a==None:
        return False
    else:
        return True

def verify_icmp_static_remote_neighbor(dut,mac,):
    output=dut.execute('''sh ipv6 icmp neighbor static remote vrf vrf-1 |json ''')
    a=re.search("Bh", output)
    print(a)
    if a==None:
        return False
    else:
        return True

ret_dialog = Dialog([
                       Statement(pattern=r'.*This command will reboot the system\. \(y\/n\)\?  \[n\]',
                                 action='sendline(y)',
                                 loop_continue=True,
                                 continue_timer=True)
                ])

def incr_mac(mac):
    #mac="0000.3c1e.08f0"
    last=mac.split('.')
    #print("***"+last[2])
    dec=int(last[2],16)
    dec=dec+1
    lasthex=hex(dec)[2:]
    while len(lasthex)<4:
       lasthex='0'+lasthex
    return lasthex

def  incr_ip(ip,octet):
    ip_list=ip.split('.')
    #print(ip_list)
    ip1=ip_list[octet]
    ip2=int(ip1)+75
    #print(ip2)
    if ip2==100:
        ip1='0'
        ip2=int(ip_list[octet-1]) + 1
        ip_list[octet-1]=str(ip2)
        ip_list[octet]=str(ip1)
    else:
        ip_list[octet]=str(ip2)
    new_ip = '.'.join(ip_list)
    return new_ip

def  incr_ipv6(ipv6,octet):
    ip_list=ipv6.split(':')
    #print(ip_list)
    ip1=ip_list[octet]
    ip2=int(ip1)+75
    #print(ip2)
    if ip2==100:
        ip1='0'
        ip2=int(ip_list[octet-1]) + 1
        ip_list[octet-1]=str(ip2)
        ip_list[octet]=str(ip1)
    else:
        ip_list[octet]=str(ip2)
    new_ipv6 = ':'.join(ip_list)
    return new_ipv6

def increment_mac(mac):
    #if ':' in mac:
    #    lst1=mac.split(':')
    #    mac='.'.join(lst1)   
    
    lst1=mac.split('.')
    last=int(lst1[2],16)
    last+=1
    last_hex=hex(last)
    buffer=str(last_hex)[2:]
    if len(buffer)<4:
        diff=4-len(buffer)
        buffer=(diff*'0')+str(last_hex)[2:]    
    lst1[2]=buffer   
    new_mac= '.'.join(lst1)
    log.info(new_mac)
    return new_mac

def increment_ipv4(v4_addr,index):
    ip_split=v4_addr.split('.')
    third=int(ip_split[index-1])+1
    ip_split[index-1]=str(third)
    v4_addr='.'.join(ip_split) 
    return v4_addr   
def verify_Static_route_in_L2FM(dut,vlan_id,mac):
    output=dut.execute('''sh mac address-table vlan ''' + str(vlan_id) + ''' address ''' + str(mac) + ''' | i ''' + str(vlan_id))
    m=re.search('.*'+re.escape(mac)+ '\s+static.*',output)
    if m:
        return True
    return False
def increment_prefix_network(pref, count):
    size = 1 << (pref.network.max_prefixlen - pref.network.prefixlen)
    pref_lst = []
    for i in range(count):
        pref_lst.append(str((pref.ip+size*i)) + "/" + str(pref.network.prefixlen))
    return pref_lst


# Verify IXIA Traffic (Traffic Item Stats View)
def validateSteadystateTraffic(testscript,session):
    
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
    log.info("==> Wait for 30min for the MSite Scale traffic to populate")
    time.sleep(1800)
    
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
    stream_id_1=''
    @aetest.test
    def CONFIGURE_UCAST_IXIA_TRAFFIC_L2IPv4(self, testscript):
        """ IXIA_CONFIGURATION subsection: Configure MCAST Traffic Item """

        # Do not perform configurations if skip_tgen_config flag is set
        #if not testscript.parameters['script_flags']['skip_tgen_config']:

        IX_TP1 = testscript.parameters['IX_TP1']
        IX_TP2 = testscript.parameters['IX_TP2']
        IX_TP3 = testscript.parameters['IX_TP3']
        IX_TP4 = testscript.parameters['IX_TP4']
        P1_dict = S1_BGW1_TGEN_data
        P2_dict = S1_Leaf_TGEN_data
        P3_dict = AcceSW_TGEN_data
        P4_dict = S2_Leaf_TGEN_data
        # P1_dict = S1_BGW1_TGEN_data
        # P4_dict = testscript.parameters['S2_BGW1_TGEN_dict']

        UCAST_v4_dict = {   'src_hndl'  : IX_TP4['ipv4_handle'],
                            'dst_hndl'  : IX_TP3['ipv4_handle'],
                            'circuit'   : 'ipv4',
                            'TI_name'   : "UCAST_V4",
                            'rate_pps'  : "10000",
                            'bi_dir'    : 1,
                            'bidirectional': '0'
                        }

        UCAST_v4_TI = ixLib.configure_ixia_traffic_item_v46(UCAST_v4_dict)
            
        if UCAST_v4_TI == 0:
            log.debug("Configuring UCast L2 TI failed")
            self.errored("Configuring UCast L2 TI failed", goto=['next_tc'])
        else:
            global stream_id_1
            stream_id_1 = UCAST_v4_TI
            log.info('stream_id='+stream_id_1)
            log.info(type(stream_id_1))
        # else:
        #     self.passed(reason="Skipped TGEN Configurations as per request")

        # Verify loss percentage for BUM Traffic Items
    stream_id_2=''
    @aetest.test
    def CONFIGURE_L2_UCAST_IXIA_TRAFFIC_With_IPv6_H4_to_H1(self, testscript):
        """ IXIA_CONFIGURATION subsection: Configure MCAST Traffic Item """

        # Do not perform configurations if skip_tgen_config flag is set
        #if not testscript.parameters['script_flags']['skip_tgen_config']:

        IX_TP1 = testscript.parameters['IX_TP1']
        IX_TP2 = testscript.parameters['IX_TP2']
        IX_TP3 = testscript.parameters['IX_TP3']
        IX_TP4 = testscript.parameters['IX_TP4']
        P1_dict = S1_BGW1_TGEN_data
        P2_dict = S1_Leaf_TGEN_data
        P3_dict = AcceSW_TGEN_data
        P4_dict = S2_Leaf_TGEN_data


        UCAST_v6_dict = {   'src_hndl'  : IX_TP4['ipv6_handle'],
                            'dst_hndl'  : IX_TP3['ipv6_handle'],
                            'circuit'   : 'ipv6',
                            'TI_name'   : "UCAST_v6",
                            'rate_pps'  : "1000",
                            'bi_dir'    : 1,
                            'bidirectional': '0'
                        }

        UCAST_v6_TI = ixLib.configure_ixia_traffic_item_v46(UCAST_v6_dict)

        if UCAST_v6_TI == 0:
            log.debug("Configuring UCast TI failed")
            self.errored("Configuring UCast TI failed", goto=['next_tc'])   
        
        else:
            global stream_id_2
            stream_id_2 = UCAST_v6_TI
            log.info('stream_id='+stream_id_2)
            log.info(type(stream_id_2))
        # else:
        #     self.passed(reason="Skipped TGEN Configurations as per request")
    
    @aetest.test
    def APPLY_TRAFFIC(self):
        """ IXIA_CONFIGURATION subsection: Verify IXIA Traffic """

        # Apply IXIA Traffic
        if ixLib.apply_traffic() == 1:
            log.info("Applying IXIA TI Passed")
        else:
            self.errored("Applying IXIA TI failed")
    
    @aetest.test
    def VERIFY_IXIA_TRAFFIC(self, testscript):
        """ IXIA_CONFIGURATION subsection: Verify IXIA Traffic """

        # Do not perform configurations if skip_tgen_config flag is set
        #if not testscript.parameters['script_flags']['skip_tgen_config']:

        time.sleep(20)

        if ixLib.verify_traffic(99) == 0:
            log.debug("Traffic Verification Passed.") 
        else:
            log.info("Traffic Verification Failed.")
            self.failed("Traffic Verification failed")
        # else:
        #     self.passed(reason="Skipped TGEN Configurations as per request")

def remove_Traffic_stream(testbed):
    node3_s1_bgw_1 = testbed.devices['node3_s1_bgw_1']
    node5_s1_leaf_1 = testbed.devices['node5_s1_leaf_1']
    node10_s1_AccessSW =testbed.devices['node10_s1_AccessSW']
    node7_s2_bgw_1 =testbed.devices['node7_s2_bgw_1']
    @aetest.test   
    def cleanup(testbed, self):
        """Unconfigure qos policies"""
        node3_s1_bgw_1 = testbed.devices['node3_s1_bgw_1']
        node5_s1_leaf_1 = testbed.devices['node5_s1_leaf_1']
        node10_s1_AccessSW =testbed.devices['node10_s1_AccessSW']
        node7_s2_bgw_1 =testbed.devices['node7_s2_bgw_1']
        P3_dict = AcceSW_TGEN_data
        forwardingSysDict = FWD_SYS_dict
        
        # Stop Traffic from ixia
        log.info("--- Stopping Traffic ---- \n")
        log.info("Stopping Traffic")
        traffic_run_status = ixLib.stop_traffic()
        
        if traffic_run_status is not 1:
            log.info("Failed: To Stop traffic")
            return 0
        else:
            log.info("\nTraffic Stopped successfully\n")
        time.sleep(10)
        ####Remove traffic item configured
        UCAST_v4_dict = {
                        'mode'        : 'remove',
                        'stream_id'   : stream_id_1,
                    }
        if (ixLib.delete_traffic_item(UCAST_v4_dict))==0:
            log.debug("Traffic Remove failed")
            self.failed("Traffic Remove failed")
        else:
            log.info("Traffic Remove Passed")
        UCAST_v6_dict = {
                        'mode'        : 'remove',
                        'stream_id'   : stream_id_2,
                    }
        if (ixLib.delete_traffic_item(UCAST_v6_dict))==0:
            log.debug("Traffic Remove failed")
            self.failed("Traffic Remove failed")
        else:
            log.info("Traffic Remove Passed")
            ###LEAF_1_MAC_BH_ROUTE
       

def config_mac_BH(testbed):
    node3_s1_bgw_1 = testbed.devices['node3_s1_bgw_1']
    node4_s1_bgw_2 =  testbed.devices['node4_s1_bgw_2']
    P3_dict = AcceSW_TGEN_data
    

    ###LEAF_3_MAC_BH_ROUTE
    testbed.devices['node3_s1_bgw_1'].configure('''
        mac address-table static ''' + str(P3_dict['mac']) + ''' vlan '''+ str(P3_dict['vlan_id']) + ''' drop

        interface vlan ''' + str(P3_dict['vlan_id']) + '''
            ipv6 neighbor ''' + str(P3_dict['v6_addr']) + ''' ''' + str(P3_dict['mac']) + '''
            ip arp ''' + str(P3_dict['v4_addr']) + ''' ''' + str(P3_dict['mac']) + '''
    ''')
    testbed.devices['node4_s1_bgw_2'].configure('''
        mac address-table static ''' + str(P3_dict['mac']) + ''' vlan '''+ str(P3_dict['vlan_id']) + ''' drop

        interface vlan ''' + str(P3_dict['vlan_id']) + '''
            ipv6 neighbor ''' + str(P3_dict['v6_addr']) + ''' ''' + str(P3_dict['mac']) + '''
            ip arp ''' + str(P3_dict['v4_addr']) + ''' ''' + str(P3_dict['mac']) + '''
    ''')

def Unconfig_mac_BH(testbed):
    node3_s1_bgw_1 = testbed.devices['node3_s1_bgw_1']
    node4_s1_bgw_2 =  testbed.devices['node4_s1_bgw_2']
    P3_dict = AcceSW_TGEN_data
    

    ###LEAF_3_MAC_BH_ROUTE
    testbed.devices['node3_s1_bgw_1'].configure('''
        no mac address-table static ''' + str(P3_dict['mac']) + ''' vlan '''+ str(P3_dict['vlan_id']) + ''' drop

        interface vlan ''' + str(P3_dict['vlan_id']) + '''
            no ipv6 neighbor ''' + str(P3_dict['v6_addr']) + ''' ''' + str(P3_dict['mac']) + '''
            no ip arp ''' + str(P3_dict['v4_addr']) + ''' ''' + str(P3_dict['mac']) + '''
    ''')
    testbed.devices['node4_s1_bgw_2'].configure('''
        no mac address-table static ''' + str(P3_dict['mac']) + ''' vlan '''+ str(P3_dict['vlan_id']) + ''' drop

        interface vlan ''' + str(P3_dict['vlan_id']) + '''
            no ipv6 neighbor ''' + str(P3_dict['v6_addr']) + ''' ''' + str(P3_dict['mac']) + '''
            no ip arp ''' + str(P3_dict['v4_addr']) + ''' ''' + str(P3_dict['mac']) + '''
    ''')

def BH_route_verification(testbed):
    @aetest.test
    def Verify_BH_states_in_HMM(self,testbed):
        node3_s1_bgw_1 =testbed.devices['node3_s1_bgw_1']
        node4_s1_bgw_2 = testbed.devices['node4_s1_bgw_2']
        node7_s2_bgw_1 = testbed.devices['node7_s2_bgw_1']
        P3_dict = AcceSW_TGEN_data

        try:
            if verify_BH_in_HMM(node4_s1_bgw_2,str(P3_dict['v4_addr'])):
                log.info('Mac BH route is proper in HMM on  S1_BGW1')
            else:
                log.info('Mac BH route is improper in HMM on  S1_BGW1')
                self.failed('Mac BH route is improper in HMM on  S1_BGW1')
        
         
        except Exception as error:
            log.debug("Unable to configure static BH mac route on Remote Vtep- Encountered Exception " + str(error))
            self.errored('Exception occurred while configuring static BH mac route on Remote Vtep', goto=['cleanup'])
    @aetest.test
    def Verify_BH_states_in_AM(self,testbed):
        node3_s1_bgw_1 = testbed.devices['node3_s1_bgw_1']
        node4_s1_bgw_2 = testbed.devices['node4_s1_bgw_2']
        node7_s2_bgw_1 = testbed.devices['node7_s2_bgw_1']
        P1_dict = S1_BGW1_TGEN_data
        P2_dict = S1_Leaf_TGEN_data
        P3_dict = AcceSW_TGEN_data
        P4_dict = S2_Leaf_TGEN_data

        try:        
            if verify_BH_in_AM(node4_s1_bgw_2,str(P3_dict['mac']),str(P3_dict['vlan_id']),str(P3_dict['v4_addr'])):
                log.info('Mac BH route is proper in AM on  S1_BGW1')
            else:
                log.info('Mac BH route is improper in AM on  S1_BGW1')
                self.failed('Mac BH route is improper in AM on  S1_BGW1')
                   
        
        except Exception as error:
            log.debug("Unable to configure static BH mac route on Remote Vtep- Encountered Exception " + str(error))
            self.errored('Exception occurred while configuring static BH mac route on Remote Vtep', goto=['cleanup'])
    @aetest.test
    def Verify_BH_states_in_remote_ARP(self,testbed):
        node3_s1_bgw_1 =testbed.devices['node3_s1_bgw_1']
        node7_s2_bgw_1 = testbed.devices['node7_s2_bgw_1']
        P3_dict = AcceSW_TGEN_data

        try: 

            if verify_BH_in_Remote_ARP(node7_s2_bgw_1,str(P3_dict['vlan_id']),str(P3_dict['mac'])):
               log.info('Mac BH route is proper in Remote ARP on  S2_BGW1')
            else:
                log.info('Mac BH route is improper in Remote ARP on  S2_BGW1')
                self.failed('Mac BH route is improper in Remote ARP on  S2_BGW1')

        except Exception as error:
            log.debug("Unable to configure static BH mac route on Remote Vtep- Encountered Exception " + str(error))
            self.errored('Exception occurred while configuring static BH mac route on Remote Vtep')        
    @aetest.test
    def Verify_BH_states_in_local_ARP(self,testbed):
        node3_s1_bgw_1 = testbed.devices['node3_s1_bgw_1']
        node7_s2_bgw_1 = testbed.devices['node7_s2_bgw_1']
        P1_dict = S1_BGW1_TGEN_data
        P2_dict = S1_Leaf_TGEN_data
        P3_dict = AcceSW_TGEN_data
        P4_dict = S2_Leaf_TGEN_data
        try:        
            if verify_BH_in_local_ARP(node3_s1_bgw_1,str(P3_dict['vlan_id']),str(P3_dict['mac'])):
                log.info('Mac BH route is proper in Local ARP on  S1_BGW1')
            else:
                log.info('Mac BH route is improper in Local ARP on  S1_BGW1')
                self.failed('Mac BH route is improper in Local ARP on  S1_BGW1')
        
        except Exception as error:
            log.debug("Unable to configure static BH mac route on Remote Vtep- Encountered Exception " + str(error))
            self.errored('Exception occurred while configuring static BH mac route on Remote Vtep')
    @aetest.test  
    def Verify_Mac_BH_Route_on_L2FM_BGP_L2RIB(self,testbed):
        node3_s1_bgw_1 = testbed.devices['node3_s1_bgw_1']
        node7_s2_bgw_1 = testbed.devices['node7_s2_bgw_1']
        P3_dict = AcceSW_TGEN_data
        
        # Verifying L2FM

        try:
            ###S1_BGW1_MAC_BH_ROUTE
            if verify_BH_route_in_L2FM(node3_s1_bgw_1,str(P3_dict['vlan_id']),str(P3_dict['mac'])):
                log.info('Mac BH route is proper in L2FM on  S1_BGw1')
            else:
                log.info('Mac BH route is improper in L2FM on  S1_BGw1')
                self.failed('Mac BH route is improper in L2FM on  S1_BGw1')

            ###S2_BGW1_MAC_BH_ROUTE Remote Vtep
            if verify_BH_route_in_L2FM(node7_s2_bgw_1,str(P3_dict['vlan_id']),str(P3_dict['mac'])):
                log.info('Mac BH route is proper in L2FM on  S2_BGw1')
            else:
                log.info('Mac BH route is improper in L2FM on  S2_BGw1')
                self.failed('Mac BH route is improper in L2FM on  S2_BGw1')

        except Exception as error:
            log.debug("Unable to verify BH mac route in L2FM - Encountered Exception " + str(error))
            self.errored('Exception occurred while verifying BH mac route in L2FM')        

        #Verifying L2RIB
        try:
            #S1_Leaf_Mac_BH_route
            if verify_L2rib_mac_ip_output(node3_s1_bgw_1,str(P3_dict['vlan_id']),str(P3_dict['mac'])):
                log.info('Mac BH route is proper in L2RIB on S1_Leaf')
            else:
                log.debug('Mac BH route is improper in L2RIB on  S1_Leaf')
                self.failed('Mac BH route is improper in L2RIB on  S1_Leaf')

            #S2_BGW1_Mac_BH_route
            if verify_L2rib_mac_ip_output(node7_s2_bgw_1,str(P3_dict['vlan_id']),str(P3_dict['mac'])):
                log.info('Mac BH route is proper in L2RIB on S2_BGW1')
            else:
                log.debug('Mac BH route is improper in L2RIB on  S2_BGW1')
                self.errored('Mac BH route is improper in L2RIB on  S2_BGW1')
        
        except Exception as error:
            log.debug("Unable to verify BH mac route in L2RIB - Encountered Exception " + str(error))
            self.errored('Exception occurred while verifying BH mac route in L2RIB')
        
        #Verifying BGP
        try:
            #S2_BGW1_Mac_BH_route
            if verify_BH_in_Remote_BGP(node7_s2_bgw_1,str(P3_dict['mac'])):
                log.info('Mac BH route is proper in BGP on S2_BGW1')
            else:
                log.debug('Mac BH route is improper in BGP on  S2_BGW1')
                self.errored('Mac BH route is improper in BGP on  S2_BGW1')

            #Access_Mac_BH_route
            if verify_BH_in_Remote_BGP(node3_s1_bgw_1,str(P3_dict['mac'])):
                log.info('Mac BH route is proper in BGP on Access')
            else:
                log.debug('Mac BH route is improper in BGP on  Access')
                self.errored('Mac BH route is improper in BGP on  Access')
        
        except Exception as error:
            log.debug("Unable to verify BH mac route in BGP - Encountered Exception " + str(error))
            self.errored('Exception occurred while verifying BH mac route in BGP', )



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
def doCopyRunToStart(section):
    for node in section.parameters['testbed'].find_devices(os=Or('NEXUS|NXOS|nxos')):
        execute_copy_run_to_start(node)

###################################################################
###                  Traffic Generator Configurations           ###
###################################################################
class IXIA_CONFIGURATION(nxtest.Testcase):
    
    @aetest.test
    def CONNECT_IXIA_CHASSIS(self, testscript, testbed):

        # Get IXIA paraameters
        ixia_chassis_ip = testbed.devices['ixia'].connections.tgn.ixia_chassis_ip
        ixia_tcl_server = testbed.devices['ixia'].connections.tgn.ixnetwork_api_server_ip
        ixia_tcl_port = '8009'

        ixia_port_list  = testbed.devices['ixia'].connections.tgn.ixia_port_list
        #ixia_int_list   = []
        #for intPort in ixia_port_list:
        #    intPort_split = intPort.split('/')
        #    ixia_int_list.append([ixia_chassis_ip, intPort_split[0], intPort_split[1]])
        
        Ixia = testscript.parameters['ixia']=testbed.devices['ixia']
        print(Ixia)
        for interface in testbed.devices['ixia'].interfaces:
            if testbed.devices['ixia'].interfaces[interface].alias == Ixia.interfaces['tgen_nd03_1_1'].intf:
                tgen_nd03_1_1 = interface.name
            if testbed.devices['ixia'].interfaces[interface].alias == Ixia.interfaces['tgen_nd05_1_1'].intf:
                tgen_nd05_1_1 = interface.name
            if testbed.devices['ixia'].interfaces[interface].alias == Ixia.interfaces['tgen_nd10_1_1'].intf:
                tgen_nd10_1_1 = interface.name
            if testbed.devices['ixia'].interfaces[interface].alias == Ixia.interfaces['tgen_nd09_1_1'].intf:
                tgen_nd09_1_1 = interface.name

        ix_int_1 = Ixia.interfaces['tgen_nd03_1_1'].intf
        ix_int_2 =  Ixia.interfaces['tgen_nd05_1_1'].intf
        ix_int_3 = Ixia.interfaces['tgen_nd10_1_1'].intf
        ix_int_4 = Ixia.interfaces['tgen_nd09_1_1'].intf
        ixia_int_list= str(ix_int_1) + " " + str(ix_int_2) + " " + str(ix_int_3) + " " + str(ix_int_4)
        ixiaArgDict = {
                        'chassis_ip'    : ixia_chassis_ip,
                        'port_list'     : ixia_int_list,
                        'tcl_server'    : ixia_tcl_server,
                        'tcl_port'      : ixia_tcl_port
        }

        log.info("Ixia Args Dict is:")
        log.info(ixiaArgDict)

        result = ixLib.connect_to_ixia(ixiaArgDict)
        #print('result:'+result)
        if result == 0:
            log.debug("Connecting to ixia failed")
            self.errored("Connecting to ixia failed", goto=['next_tc'])

        ch_key = result['port_handle']
        for ch_p in ixia_chassis_ip.split('.'):
            ch_key = ch_key[ch_p]

        log.info("Port Handles are:")
        log.info(ch_key)

        testscript.parameters['port_handle_1'] = ch_key[ix_int_1]
        testscript.parameters['port_handle_2'] = ch_key[ix_int_2]
        testscript.parameters['port_handle_3'] = ch_key[ix_int_3]
        testscript.parameters['port_handle_4'] = ch_key[ix_int_4]
    @aetest.test
    def CREATE_IXIA_TOPOLOGIES(self, testscript):

        TOPO_1_dict = {'topology_name': 'S1_BGW1-TG',
                        'device_grp_name': 'S1_BGW1-TG',
                        'port_handle': testscript.parameters['port_handle_1']}

        TOPO_2_dict = {'topology_name': 'S1_Leaf-TG',
                        'device_grp_name': 'S1_Leaf-TG',
                        'port_handle': testscript.parameters['port_handle_2']}

        TOPO_3_dict = {'topology_name': 'AcceSW-TG',
                        'device_grp_name': 'AcceSW-TG',
                        'port_handle': testscript.parameters['port_handle_3']}

        TOPO_4_dict = {'topology_name': 'S2_Leaf-TG',
                        'device_grp_name': 'S2_Leaf-TG',
                        'port_handle': testscript.parameters['port_handle_4']}

        testscript.parameters['IX_TP1'] = ixLib.create_topo_device_grp(TOPO_1_dict)
        if testscript.parameters['IX_TP1'] == 0:
            log.debug("Creating Topology failed")
            self.errored("Creating Topology failed", goto=['next_tc'])
        else:
            log.info("Created topo1-TG Topology Successfully")

        testscript.parameters['IX_TP2'] = ixLib.create_topo_device_grp(TOPO_2_dict)
        if testscript.parameters['IX_TP2'] == 0:
            log.debug("Creating Topology failed")
            self.errored("Creating Topology failed", goto=['next_tc'])
        else:
            log.info("Created topo2-TG Topology Successfully")

        testscript.parameters['IX_TP3'] = ixLib.create_topo_device_grp(TOPO_3_dict)
        if testscript.parameters['IX_TP3'] == 0:
            log.debug("Creating Topology failed")
            self.errored("Creating Topology failed", goto=['next_tc'])
        else:
            log.info("Created topo3 -TG Topology Successfully")
        
        testscript.parameters['IX_TP4'] = ixLib.create_topo_device_grp(TOPO_4_dict)
        if testscript.parameters['IX_TP4'] == 0:
            log.debug("Creating Topology failed")
            self.errored("Creating Topology failed", goto=['next_tc'])
        else:
            log.info("Created topo4 -TG Topology Successfully")

        testscript.parameters['IX_TP1']['port_handle'] = testscript.parameters['port_handle_1']
        testscript.parameters['IX_TP2']['port_handle'] = testscript.parameters['port_handle_2']
        testscript.parameters['IX_TP3']['port_handle'] = testscript.parameters['port_handle_3']
        testscript.parameters['IX_TP4']['port_handle'] = testscript.parameters['port_handle_4']

    @aetest.test
    def CONFIGURE_IXIA_INTERFACES(self, testscript):

        P1 = testscript.parameters['port_handle_1']
        P2 = testscript.parameters['port_handle_2']
        P3 = testscript.parameters['port_handle_3']
        P4 = testscript.parameters['port_handle_4']

        P1_dict = S1_BGW1_TGEN_data
        P2_dict = S1_Leaf_TGEN_data
        P3_dict = AcceSW_TGEN_data
        P4_dict = S2_Leaf_TGEN_data


        P1_int_dict_1 = {'dev_grp_hndl': testscript.parameters['IX_TP1']['dev_grp_hndl'],
                             'port_hndl': P1,
                             'no_of_ints' :  P1_dict['no_of_ints'],
                             'phy_mode':  P1_dict['phy_mode'],
                             'mac':  P1_dict['mac'],
                             'mac_step': P1_dict['mac_step'],
                             'protocol': P1_dict['protocol'],
                             'v4_addr':  P1_dict['v4_addr'],
                             'v4_addr_step': P1_dict['v4_addr_step'],
                             'v4_gateway': P1_dict['v4_gateway'],
                             'v4_gateway_step':  P1_dict['v4_gateway_step'],
                             'v4_netmask': P1_dict['netmask'],
                             'v6_addr':  P1_dict['v6_addr'],
                             'v6_addr_step': P1_dict['v6_addr_step'],
                             'v6_gateway': P1_dict['v6_gateway'],
                             'v6_gateway_step':  P1_dict['v6_gateway_step'],
                             'v6_netmask':  P1_dict['v6_netmask'],
                             'vlan_id':  P1_dict['vlan_id'],
                             'vlan_user_priority': P1_dict['vlan_user_priority'],
                             'vlan_id_step': P1_dict['vlan_id_step'],
                             'frame_size': P1_dict['frame_size'],
                             'L3_dst_addr': P1_dict['L3_dst_addr']}

        P2_int_dict_1 = {'dev_grp_hndl': testscript.parameters['IX_TP2']['dev_grp_hndl'],
                             'port_hndl': P2,
                             'no_of_ints': P2_dict['no_of_ints'],
                             'phy_mode': P2_dict['phy_mode'],
                             'mac': P2_dict['mac'],
                             'mac_step': P2_dict['mac_step'],
                             'protocol': P2_dict['protocol'],
                             'v4_addr': P2_dict['v4_addr'],
                             'v4_addr_step': P2_dict['v4_addr_step'],
                             'v4_gateway': P2_dict['v4_gateway'],
                             'v4_gateway_step': P2_dict['v4_gateway_step'],
                             'v4_netmask': P2_dict['netmask'],
                             'v6_addr': P2_dict['v6_addr'],
                             'v6_addr_step': P2_dict['v6_addr_step'],
                             'v6_gateway': P2_dict['v6_gateway'],
                             'v6_gateway_step': P2_dict['v6_gateway_step'],
                             'v6_netmask': P2_dict['v6_netmask'],
                             'vlan_id': P2_dict['vlan_id'],
                             'vlan_user_priority': P1_dict['vlan_user_priority'],
                             'vlan_id_step': P2_dict['vlan_id_step'],
                             'frame_size': P2_dict['frame_size'],
                             'L3_dst_addr': P2_dict['L3_dst_addr']}
            
        P3_int_dict_1 = {'dev_grp_hndl': testscript.parameters['IX_TP3']['dev_grp_hndl'],
                             'port_hndl': P3,
                             'no_of_ints': P3_dict['no_of_ints'],
                             'phy_mode': P3_dict['phy_mode'],
                             'mac': P3_dict['mac'],
                             'mac_step': P3_dict['mac_step'],
                             'protocol': P3_dict['protocol'],
                             'v4_addr': P3_dict['v4_addr'],
                             'v4_addr_step': P3_dict['v4_addr_step'],
                             'v4_gateway': P3_dict['v4_gateway'],
                             'v4_gateway_step': P3_dict['v4_gateway_step'],
                             'v4_netmask': P3_dict['netmask'],
                             'v6_addr': P3_dict['v6_addr'],
                             'v6_addr_step': P3_dict['v6_addr_step'],
                             'v6_gateway': P3_dict['v6_gateway'],
                             'v6_gateway_step': P3_dict['v6_gateway_step'],
                             'v6_netmask': P3_dict['v6_netmask'],
                             'vlan_id': P3_dict['vlan_id'],
                             'vlan_user_priority': P3_dict['vlan_user_priority'],
                             'vlan_id_step': P3_dict['vlan_id_step'],
                             'frame_size': P3_dict['frame_size'],
                             'L3_dst_addr': P3_dict['L3_dst_addr']}
            
        P4_int_dict_1 = {'dev_grp_hndl': testscript.parameters['IX_TP4']['dev_grp_hndl'],
                             'port_hndl': P4,
                             'no_of_ints': P4_dict['no_of_ints'],
                             'phy_mode': P4_dict['phy_mode'],
                             'mac': P4_dict['mac'],
                             'mac_step': P4_dict['mac_step'],
                             'protocol': P4_dict['protocol'],
                             'v4_addr': P4_dict['v4_addr'],
                             'v4_addr_step': P4_dict['v4_addr_step'],
                             'v4_gateway': P4_dict['v4_gateway'],
                             'v4_gateway_step': P4_dict['v4_gateway_step'],
                             'v4_netmask': P4_dict['netmask'],
                             'v6_addr': P4_dict['v6_addr'],
                             'v6_addr_step': P4_dict['v6_addr_step'],
                             'v6_gateway': P4_dict['v6_gateway'],
                             'v6_gateway_step': P4_dict['v6_gateway_step'],
                             'v6_netmask': P4_dict['v6_netmask'],
                             'vlan_id': P4_dict['vlan_id'],
                             'vlan_user_priority': P4_dict['vlan_user_priority'],
                             'vlan_id_step': P4_dict['vlan_id_step'],
                             'frame_size': P4_dict['frame_size'],
                             'L3_dst_addr': P4_dict['L3_dst_addr']}

        P1_IX_int_data = ixLib.configure_multi_ixia_interface(P1_int_dict_1)
        P2_IX_int_data = ixLib.configure_multi_ixia_interface(P2_int_dict_1)
        P3_IX_int_data = ixLib.configure_multi_ixia_interface(P3_int_dict_1)
        P4_IX_int_data = ixLib.configure_multi_ixia_interface(P4_int_dict_1)


        if P1_IX_int_data == 0 or P2_IX_int_data == 0 or P3_IX_int_data == 0 or P4_IX_int_data == 0:
            log.debug("Configuring IXIA Interface failed")
            self.errored("Configuring IXIA Interface failed", goto=['next_tc'])
        else:
            log.info("Configured IXIA Interface Successfully")

        testscript.parameters['IX_TP1']['eth_handle'] = P1_IX_int_data['eth_handle']
        testscript.parameters['IX_TP1']['ipv4_handle'] = P1_IX_int_data['ipv4_handle']
        testscript.parameters['IX_TP1']['ipv6_handle'] = P1_IX_int_data['ipv6_handle']
        #testscript.parameters['IX_TP1']['port_handle'] = P1_IX_int_data['port_hndl']
        testscript.parameters['IX_TP1']['topo_int_handle'] = P1_IX_int_data['topo_int_handle'].split(" ")

        testscript.parameters['IX_TP2']['eth_handle'] = P2_IX_int_data['eth_handle']
        testscript.parameters['IX_TP2']['ipv4_handle'] = P2_IX_int_data['ipv4_handle']
        testscript.parameters['IX_TP2']['ipv6_handle'] = P2_IX_int_data['ipv6_handle']
        #testscript.parameters['IX_TP2']['port_handle'] = P2_IX_int_data['port_hndl']
        testscript.parameters['IX_TP2']['topo_int_handle'] = P2_IX_int_data['topo_int_handle'].split(" ")

        testscript.parameters['IX_TP3']['eth_handle'] = P3_IX_int_data['eth_handle']
        testscript.parameters['IX_TP3']['ipv4_handle'] = P3_IX_int_data['ipv4_handle']
        testscript.parameters['IX_TP3']['ipv6_handle'] = P3_IX_int_data['ipv6_handle']
        #testscript.parameters['IX_TP3']['port_handle'] = P3_IX_int_data['port_hndl']
        testscript.parameters['IX_TP3']['topo_int_handle'] = P3_IX_int_data['topo_int_handle'].split(" ")

        testscript.parameters['IX_TP4']['eth_handle'] = P4_IX_int_data['eth_handle']
        testscript.parameters['IX_TP4']['ipv4_handle'] = P4_IX_int_data['ipv4_handle']
        testscript.parameters['IX_TP4']['ipv6_handle'] = P4_IX_int_data['ipv6_handle']
        #testscript.parameters['IX_TP4']['port_handle'] = P4_IX_int_data['port_hndl']
        testscript.parameters['IX_TP4']['topo_int_handle'] = P4_IX_int_data['topo_int_handle'].split(" ")



        log.info("IXIA Port 1 Handles")
        log.info(testscript.parameters['IX_TP1'])
        log.info("IXIA Port 2 Handles")
        log.info(testscript.parameters['IX_TP2'])
        log.info("IXIA Port 2 Handles")
        log.info(testscript.parameters['IX_TP3'])
        log.info("IXIA Port 2 Handles")
        log.info(testscript.parameters['IX_TP4'])
    
#     @aetest.test
#     def CONFIGURE_IXIA_IGMP_GROUPS(self, testscript):
#         """ IXIA_CONFIGURATION subsection: Configure IXIA IGMP Groups """

# #       
#         IX_TP1 = testscript.parameters['IX_TP1']
#         IX_TP2 = testscript.parameters['IX_TP2']
#         IX_TP3 = testscript.parameters['IX_TP3']
#         IX_TP4 = testscript.parameters['IX_TP4']
#         P1_dict = S1_BGW1_TGEN_data
#         P2_dict = S1_Leaf_TGEN_data
#         P3_dict = AcceSW_TGEN_data
#         P4_dict = S2_Leaf_TGEN_data

#         IGMP_dict_1 = {'ipv4_hndl': IX_TP2['ipv4_handle'],
#                         'igmp_ver': P4_dict['igmp_ver'],
#                         'mcast_grp_ip': P4_dict['mcast_grp_ip'],
#                         'mcast_grp_ip_step': P4_dict['mcast_grp_ip_step'],
#                         'no_of_grps': P4_dict['no_of_grps'],
#                         'mcast_src_ip': P1_dict['v4_addr'],
#                         'mcast_src_ip_step': P4_dict['v4_addr_step'],
#                         'mcast_src_ip_step_per_port': P4_dict['v4_addr_step'],
#                         'mcast_grp_ip_step_per_port': P4_dict['v4_addr_step'],
#                         'mcast_no_of_srcs': P4_dict['no_of_mcast_sources'],
#                         'topology_handle': IX_TP2['topo_hndl']
#                         }

#         IGMP_EML = ixLib.emulate_igmp_groupHost(IGMP_dict_1)

#         if IGMP_EML == 0:
#             log.debug("Configuring IGMP failed")
#             self.errored("Configuring IGMP failed")
#         else:
#             log.info("Configured IGMP Successfully")

#         testscript.parameters['IX_TP2']['igmpHost_handle'] = []
#         testscript.parameters['IX_TP2']['igmp_group_handle'] = []
#         testscript.parameters['IX_TP2']['igmp_source_handle'] = []
#         testscript.parameters['IX_TP2']['igmpMcastGrpList'] = []

#         testscript.parameters['IX_TP2']['igmpHost_handle'].append(IGMP_EML['igmpHost_handle'])
#         testscript.parameters['IX_TP2']['igmp_group_handle'].append(IGMP_EML['igmp_group_handle'])
#         testscript.parameters['IX_TP2']['igmp_source_handle'].append(IGMP_EML['igmp_source_handle'])
#         testscript.parameters['IX_TP2']['igmpMcastGrpList'].append(IGMP_EML['igmpMcastGrpList'])

    @aetest.test
    def START_IXIA_PROTOCOLS(self):
        """ IXIA_CONFIGURATION subsection: Configure IXIA IGMP Groups """

        # _result_ = ixiahlt.test_control(action='configure_all')
        # print(_result_)
        proto_result = ixLib.start_protocols()
        if proto_result == 0:
            log.debug("Starting Protocols failed")
            self.errored("Starting Protocols failed", goto=['next_tc'])
        else:
            log.info("Started Protocols Successfully")

        time.sleep(60)

        proto_result = ixLib.stop_protocols()
        if proto_result == 0:
            log.debug("Stopped Protocols failed")
            self.errored("Stopped Protocols failed", goto=['next_tc'])
        else:
            log.info("Stopped Protocols Successfully")

        time.sleep(30)

        proto_result = ixLib.start_protocols()
        if proto_result == 0:
            log.debug("Starting Protocols failed")
            self.errored("Starting Protocols failed", goto=['next_tc'])
        else:
            log.info("Started Protocols Successfully")

        time.sleep(120)


    # @aetest.test
    # def CONFIGURE_L2_UCAST_IXIA_TRAFFIC(self, testscript):
    #     """ IXIA_CONFIGURATION subsection: Configure MCAST Traffic Item """

    #     # Do not perform configurations if skip_tgen_config flag is set
    #     #if not testscript.parameters['script_flags']['skip_tgen_config']:

    #     IX_TP1 = testscript.parameters['IX_TP1']
    #     IX_TP2 = testscript.parameters['IX_TP2']
    #     IX_TP3 = testscript.parameters['IX_TP3']
    #     IX_TP4 = testscript.parameters['IX_TP4']

    #     P1_dict = S1_BGW1_TGEN_data
    #     P2_dict = S1_Leaf_TGEN_data
    #     P3_dict = AcceSW_TGEN_data
    #     P4_dict = S2_Leaf_TGEN_data


    #     UCAST_L2_dict = {   'src_hndl'  : IX_TP4['port_handle'],
    #                         'dst_hndl'  : IX_TP3['port_handle'],
    #                         'circuit'   : 'raw',
    #                         'TI_name'   : "UCAST_L2",
    #                         'rate_pps'  : "9000",
    #                         'bi_dir'    : 0,
    #                         'frame_size': '128',
    #                         'src_mac'   : P4_dict['mac'],
    #                         'dst_mac'   : P3_dict['mac'],
    #                         'srcmac_step': P4_dict['mac_step'],
    #                         'dstmac_step': P3_dict['mac_step'],
    #                         'srcmac_count': '1',
    #                         'dstmac_count': '1',
    #                         'vlan_id'    : P4_dict['vlan_id'],
    #                         'vlanid_step': P4_dict['vlan_id_step'],
    #                         'vlanid_count': '1',
    #                         'vlan_user_priority': P4_dict['vlan_user_priority']

    #                       }

    #     UCAST_L2_TI = ixLib.configure_ixia_L2_UCAST_traffic_item(UCAST_L2_dict)
            
    #     if UCAST_L2_TI == 0:
    #         log.debug("Configuring UCast L2 TI failed")
    #         self.errored("Configuring UCast L2 TI failed", goto=['cleanup'])
    #     else:
    #         global stream_id
    #         stream_id = UCAST_L2_TI
    #         log.info('stream_id='+stream_id)
    #         log.info(type(stream_id))

    # @aetest.test
    # def APPLY_TRAFFIC(self):
    #     """ IXIA_CONFIGURATION subsection: Verify IXIA Traffic """

    #     # Apply IXIA Traffic
    #     if ixLib.apply_traffic() == 1:
    #         log.info("Applying IXIA TI Passed")
    #     else:
    #         self.errored("Applying IXIA TI failed")

    # @aetest.test
    # def VERIFY_IXIA_TRAFFIC(self, testscript):
    #     """ IXIA_CONFIGURATION subsection: Verify IXIA Traffic """

    #     time.sleep(30)
    #     if ixLib.verify_traffic(2, 3) == 0:
    #         log.debug("Traffic Verification failed")
    #         self.failed("Traffic Verification failed")
    #     else:
    #         log.info("Traffic Verification Passed")
    
    # @aetest.test
    # def Cleanupsesion(self, testbed):
    #     P3_dict = AcceSW_TGEN_data
    #     forwardingSysDict = FWD_SYS_dict
    # 	# Stop Traffic from ixia
    #     log.info("--- Stopping Traffic ---- \n")
    #     log.info("Stopping Traffic")
    #     traffic_run_status = ixLib.stop_traffic()
    
    #     if traffic_run_status is not 1:
    #         log.info("Failed: To Stop traffic")
    #         self.failed("Traffic Stop failed", goto=['next_tc'])
    #     else:
    #         log.info("\nTraffic Stopped successfully\n")
    #         time.sleep(10)
    # 	####Remove traffic item configured
    #     UCAST_L2_dict = {
    #                 'mode'        : 'remove',
    #                 'stream_id'   : stream_id,
    #           }
    #     if (ixLib.delete_traffic_item(UCAST_L2_dict))==0:
    #         log.debug("Traffic Remove failed")
    #         self.failed("Traffic Remove failed", goto=['next_tc'])
    #     else:
    #         log.info("Traffic Remove Passed")


###################################################################
###               L2 Ucast  Test-cases                          ###
###################################################################
class Config_MAC_BH_on_VPC_Vtep(nxtest.Testcase):
    #"""TC_0020_Config_MAC_BH_on_VPC_Vtep"""

    stream_id=''
    @aetest.test
    def CONFIGURE_L2_UCAST_IXIA_TRAFFIC_H2_to_H1(self, testscript):
        """ IXIA_CONFIGURATION subsection: Configure MCAST Traffic Item """

        # Do not perform configurations if skip_tgen_config flag is set
        #if not testscript.parameters['script_flags']['skip_tgen_config']:

        IX_TP1 = testscript.parameters['IX_TP1']
        IX_TP2 = testscript.parameters['IX_TP2']
        IX_TP3 = testscript.parameters['IX_TP3']
        IX_TP4 = testscript.parameters['IX_TP4']

        P1_dict = S1_BGW1_TGEN_data
        P2_dict = S1_Leaf_TGEN_data
        P3_dict = AcceSW_TGEN_data
        P4_dict = S2_Leaf_TGEN_data

        #sending traffic P2 = Host2 to P3 = Host1
        UCAST_L2_dict_1 = {   'src_hndl'  : IX_TP2['port_handle'],
                            'dst_hndl'  : IX_TP3['port_handle'],
                            'circuit'   : 'raw',
                            'TI_name'   : "UCAST_L2",
                            'rate_pps'  : "9000",
                            'bi_dir'    : 0,
                            'frame_size': '128',
                            'src_mac'   : P2_dict['mac'],
                            'dst_mac'   : P3_dict['mac'],
                            'srcmac_step': P2_dict['mac_step'],
                            'dstmac_step': P3_dict['mac_step'],
                            'srcmac_count': '1',
                            'dstmac_count': '1',
                            'vlan_id'    : P2_dict['vlan_id'],
                            'vlanid_step': P2_dict['vlan_id_step'],
                            'vlanid_count': '1',
                            'vlan_user_priority': P2_dict['vlan_user_priority']

                        }

        UCAST_L2_TI = ixLib.configure_ixia_L2_UCAST_traffic_item(UCAST_L2_dict_1)

        if UCAST_L2_TI == 0:
            log.debug("Configuring UCast L2 TI failed")
            self.errored("Configuring UCast L2 TI failed", goto=['cleanup'])
        else:
            global stream_id
            stream_id = UCAST_L2_TI
            

        # else:
        # self.passed(reason="Skipped TGEN Configurations as per request")
    stream_id_1=''
    @aetest.test
    def CONFIGURE_L2_UCAST_IXIA_TRAFFIC_H3_to_H1(self, testscript):
        """ IXIA_CONFIGURATION subsection: Configure MCAST Traffic Item """

        # Do not perform configurations if skip_tgen_config flag is set
        #if not testscript.parameters['script_flags']['skip_tgen_config']:

        IX_TP1 = testscript.parameters['IX_TP1']
        IX_TP2 = testscript.parameters['IX_TP2']
        IX_TP3 = testscript.parameters['IX_TP3']
        IX_TP4 = testscript.parameters['IX_TP4']

        P1_dict = S1_BGW1_TGEN_data
        P2_dict = S1_Leaf_TGEN_data
        P3_dict = AcceSW_TGEN_data
        P4_dict = S2_Leaf_TGEN_data

        #sending traffic to P1= Host3 to P3 = Host 1
        UCAST_L2_dict_2 = {   'src_hndl'  : IX_TP1['port_handle'],
                            'dst_hndl'  : IX_TP3['port_handle'],
                            'circuit'   : 'raw',
                            'TI_name'   : "UCAST_L2",
                            'rate_pps'  : "9000",
                            'bi_dir'    : 0,
                            'frame_size': '128',
                            'src_mac'   : P1_dict['mac'],
                            'dst_mac'   : P3_dict['mac'],
                            'srcmac_step': P1_dict['mac_step'],
                            'dstmac_step': P3_dict['mac_step'],
                            'srcmac_count': '1',
                            'dstmac_count': '1',
                            'vlan_id'    : P1_dict['vlan_id'],
                            'vlanid_step': P1_dict['vlan_id_step'],
                            'vlanid_count': '1',
	                    'vlan_user_priority': P1_dict['vlan_user_priority']

                        }

        UCAST_L2_TI_1 = ixLib.configure_ixia_L2_UCAST_traffic_item(UCAST_L2_dict_2)

        if UCAST_L2_TI_1 == 0:
            log.debug("Configuring UCast L2 TI failed")
            self.errored("Configuring UCast L2 TI failed", goto=['cleanup'])
        else:
            global stream_id_1
            stream_id_1 = UCAST_L2_TI_1
            

        # else:
        #     self.passed(reason="Skipped TGEN Configurations as per request")
    stream_id_2=''
    @aetest.test
    def CONFIGURE_L2_UCAST_IXIA_TRAFFIC_H4_to_H1(self, testscript):
        """ IXIA_CONFIGURATION subsection: Configure MCAST Traffic Item """

        # Do not perform configurations if skip_tgen_config flag is set
        #if not testscript.parameters['script_flags']['skip_tgen_config']:

        IX_TP1 = testscript.parameters['IX_TP1']
        IX_TP2 = testscript.parameters['IX_TP2']
        IX_TP3 = testscript.parameters['IX_TP3']
        IX_TP4 = testscript.parameters['IX_TP4']

        P1_dict = S1_BGW1_TGEN_data
        P2_dict = S1_Leaf_TGEN_data
        P3_dict = AcceSW_TGEN_data
        P4_dict = S2_Leaf_TGEN_data

        #sending traffic to P4= Host4 to P3 = Host 1
        UCAST_L2_dict_3 = {   'src_hndl'  : IX_TP4['port_handle'],
                            'dst_hndl'  : IX_TP3['port_handle'],
                            'circuit'   : 'raw',
                            'TI_name'   : "UCAST_L2",
                            'rate_pps'  : "9000",
                            'bi_dir'    : 0,
                            'frame_size': '128',
                            'src_mac'   : P4_dict['mac'],
                            'dst_mac'   : P3_dict['mac'],
                            'srcmac_step': P4_dict['mac_step'],
                            'dstmac_step': P3_dict['mac_step'],
                            'srcmac_count': '1',
                            'dstmac_count': '1',
                            'vlan_id'    : P4_dict['vlan_id'],
                            'vlanid_step': P4_dict['vlan_id_step'],
                            'vlanid_count': '1',
                            'vlan_user_priority': P4_dict['vlan_user_priority']

                        }

        UCAST_L2_TI_2 = ixLib.configure_ixia_L2_UCAST_traffic_item(UCAST_L2_dict_3)

        if UCAST_L2_TI_2 == 0:
            log.debug("Configuring UCast L2 TI failed")
            self.errored("Configuring UCast L2 TI failed", goto=['cleanup'])
        else:
            global stream_id_2
            stream_id_2 = UCAST_L2_TI_2
            

        # else:
        #     self.passed(reason="Skipped TGEN Configurations as per request")

    @aetest.test
    def verify_dynamic_mac_states(self, testscript,testbed):
        node3_s1_bgw_1 = testbed.devices['node3_s1_bgw_1']
        node7_s2_bgw_1 = testbed.devices['node7_s2_bgw_1']
        P3_dict = AcceSW_TGEN_data
        if verify_dynamic_mac(node3_s1_bgw_1,str(P3_dict['mac']),str(P3_dict['vlan_id'])):
            log.info('proper dynaic mac learnt on S1_BGw1')
        else:
            log.info('improper dynamic mac learnt on  S1_BGw1')
            self.failed('improper dynamic mac learnt on  S1_BGw1')

        if verify_dynamic_mac(node3_s1_bgw_1,str(P3_dict['mac']),str(P3_dict['vlan_id'])):
            log.info('proper dynaic mac learnt on  S2_BGw1')
        else:
            log.info('improper dynamic mac learnt on S2_BGw1')
            self.failed('improper dynamic mac learnt on  S2_BGw1')


    @aetest.test
    def APPLY_TRAFFIC(self):
        """ IXIA_CONFIGURATION subsection: Verify IXIA Traffic """

        # Apply IXIA Traffic
        if ixLib.apply_traffic() == 1:
            log.info("Applying IXIA TI Passed")
        else:
            self.errored("Applying IXIA TI failed")
    @aetest.test
    def VERIFY_IXIA_TRAFFIC_Without_BH_config(self, testscript):
        """ IXIA_CONFIGURATION subsection: Verify IXIA Traffic """

        # Do not perform configurations if skip_tgen_config flag is set
        #if not testscript.parameters['script_flags']['skip_tgen_config']:

        time.sleep(20)

        if ixLib.verify_traffic(1) == 1:
            log.debug("Traffic Verification Passed..")
            # ForkedPdb().set_trace() 
        else:
            log.info("Traffic Verification Failed. ")
            # ForkedPdb().set_trace()
            self.failed("Traffic Verification failed")
        # else:
        #     self.passed(reason="Skipped TGEN Configurations as per request")
    
    
    @aetest.test
    def Config_Mac_BH_Route_On_vpc(self,testscript,testbed):
        node3_s1_bgw_1 = testbed.devices['node3_s1_bgw_1']
        node4_s1_bgw_2 = testbed.devices['node4_s1_bgw_2']
        P3_dict = AcceSW_TGEN_data
        
        try:
            ###S1_BGw1_MAC_BH_ROUTE
            testbed.devices['node3_s1_bgw_1'].configure('''

                mac address-table static ''' + P3_dict['mac'] + ''' vlan '''+ P3_dict['vlan_id'] + ''' drop

            ''')
            testbed.devices['node4_s1_bgw_2'].configure('''

                mac address-table static ''' + P3_dict['mac'] + ''' vlan '''+ P3_dict['vlan_id'] + ''' drop

            ''')
        except Exception as error:
            log.debug("Unable to configure static BH mac route - Encountered Exception " + str(error))
            self.errored('Exception occurred while configuring static BH mac route')

    @aetest.test
    def VERIFY_IXIA_TRAFFIC_With_BH_Route(self, testscript):
        """ IXIA_CONFIGURATION subsection: Verify IXIA Traffic """

        # Do not perform configurations if skip_tgen_config flag is set
        #if not testscript.parameters['script_flags']['skip_tgen_config']:

        time.sleep(20)

        if ixLib.verify_traffic(99) == 0:
            log.debug("Traffic Verification Passed.") 
        else:
            log.info("Traffic Verification Failed.")
            # ForkedPdb().set_trace()
            self.failed("Traffic Verification failed")
        # else:
        #     self.passed(reason="Skipped TGEN Configurations as per request")
    
    @aetest.test
    def Verify_Traffic_Drop_on_Remote_Vtep_After_rmBH(self,testscript,testbed):
        node5_s1_leaf_1 = testbed.devices['node5_s1_leaf_1']
        node7_s2_bgw_1 = testbed.devices['node7_s2_bgw_1']
        node9_s2_leaf_1 = testbed.devices['node9_s2_leaf_1']
        P3_dict = AcceSW_TGEN_data
        uplink_PO=S1_Leaf_dict['S1_Leaf_UPLINK_PO']['po_id']
        if verify_traffic_drop(node5_s1_leaf_1,uplink_PO):
            log.info('Traffic correctly dropped on  S1_Leaf')
        else:
            log.info('Traffic NOT dropped on  S1_Leaf')
            self.failed('Traffic NOT dropped on  S1_Leaf')

        uplink_PO=S2_BGW1_dict['S2_BGW1_UPLINK_PO']['po_id']
        if verify_traffic_drop(node7_s2_bgw_1,uplink_PO):
            log.info('Traffic correctly dropped on  S2_BGW1')
        else:
            log.info('Traffic NOT dropped on  S2_BGW1')
            self.failed('Traffic NOT dropped on  S2_BGW1')
        
        uplink_PO=S2_Leaf_dict['S2_Leaf_UPLINK_PO']['po_id']
        if verify_traffic_drop(node9_s2_leaf_1,uplink_PO):
            log.info('Traffic correctly dropped on  S2_Leaf')
        else:
            log.info('Traffic NOT dropped on  S2_Leaf')
            self.failed('Traffic NOT dropped on  S2_Leaf')

    @aetest.test
    def Verify_Mac_BH_Route_states(self,testscript,testbed):
        node3_s1_bgw_1 = testbed.devices['node3_s1_bgw_1']
        node5_s1_leaf_1 = testbed.devices['node5_s1_leaf_1']
        node7_s2_bgw_1 = testbed.devices['node7_s2_bgw_1']
        P3_dict = AcceSW_TGEN_data
        
        #==============================================================================================#
        #Verify the BH route is installed in VPC vtep and transmitted to Standalone remote vtep
        #==============================================================================================#

        #Verifying L2FM

        try:
            ###S1_BGW1_MAC_BH_ROUTE
            if verify_BH_route_in_L2FM(node3_s1_bgw_1,str(P3_dict['vlan_id']),str(P3_dict['mac'])):
                log.info('Mac BH route is proper in L2FM on  S1_BGw1')
            else:
                log.info('Mac BH route is improper in L2FM on  S1_BGw1')
                self.failed('Mac BH route is improper in L2FM on  S1_BGw1')

            ###S1_Leaf_MAC_BH_ROUTE
            if verify_BH_route_in_L2FM(node5_s1_leaf_1,str(P3_dict['vlan_id']),str(P3_dict['mac'])):
                log.info('Mac BH route is proper in L2FM on  S1_Leaf')
            else:
                log.info('Mac BH route is improper in L2FM on  S1_Leaf')
                self.failed('Mac BH route is improper in L2FM on  S1_Leaf')

            ###S2_BGW1_MAC_BH_ROUTE Remote Vtep
            if verify_BH_route_in_L2FM(node7_s2_bgw_1,str(P3_dict['vlan_id']),str(P3_dict['mac'])):
                log.info('Mac BH route is proper in L2FM on  S2_BGw1')
            else:
                log.info('Mac BH route is improper in L2FM on  S2_BGw1')
                self.failed('Mac BH route is improper in L2FM on  S2_BGw1')

        except Exception as error:
            log.debug("Unable to verify BH mac route in L2FM - Encountered Exception " + str(error))
            self.errored('Exception occurred while verifying BH mac route in L2FM', goto=['cleanup'])        

        #Verifying L2RIB
        try:
            #S1_Leaf_Mac_BH_route
            if verify_L2rib_output(node3_s1_bgw_1,str(P3_dict['vlan_id']),str(P3_dict['mac'])):
                log.info('Mac BH route is proper in L2RIB on S1_Leaf')
            else:
                log.debug('Mac BH route is improper in L2RIB on  S1_Leaf')
                self.failed('Mac BH route is improper in L2RIB on  S1_Leaf')

            #S2_BGW1_Mac_BH_route
            if verify_L2rib_output(node7_s2_bgw_1,str(P3_dict['vlan_id']),str(P3_dict['mac'])):
                log.info('Mac BH route is proper in L2RIB on S2_BGW1')
            else:
                log.debug('Mac BH route is improper in L2RIB on  S2_BGW1')
                self.errored('Mac BH route is improper in L2RIB on  S2_BGW1')

            #s1_leaf_1 _ BH _Route
            if verify_L2rib_output(node5_s1_leaf_1,str(P3_dict['vlan_id']),str(P3_dict['mac'])):
                log.info('Mac BH route is proper in L2RIB on Access')
            else:
                log.debug('Mac BH route is improper in L2RIB on  Access')
                self.errored('Mac BH route is improper in L2RIB on  Access')
        
        except Exception as error:
            log.debug("Unable to verify BH mac route in L2RIB - Encountered Exception " + str(error))
            self.errored('Exception occurred while verifying BH mac route in L2RIB')
        
        #Verifying BGP
        try:
            #S1_Leaf_Mac_BH_route
            if verify_BH_in_Remote_BGP(node5_s1_leaf_1,str(P3_dict['mac'])):
                log.info('Mac BH route is proper in BGP on S1_Leaf')
            else:
                log.debug('Mac BH route is improper in BGP on  S1_Leaf')
                self.failed('Mac BH route is improper in BGP on  S1_Leaf')

            #S2_BGW1_Mac_BH_route
            if verify_BH_in_Remote_BGP(node7_s2_bgw_1,str(P3_dict['mac'])):
                log.info('Mac BH route is proper in BGP on S2_BGW1')
            else:
                log.debug('Mac BH route is improper in BGP on  S2_BGW1')
                self.errored('Mac BH route is improper in BGP on  S2_BGW1')

            #Access_Mac_BH_route
            if verify_BH_in_Remote_BGP(node3_s1_bgw_1,str(P3_dict['mac'])):
                log.info('Mac BH route is proper in BGP on Access')
            else:
                log.debug('Mac BH route is improper in BGP on  Access')
                self.errored('Mac BH route is improper in BGP on  Access')
        
        except Exception as error:
            log.debug("Unable to verify BH mac route in BGP - Encountered Exception " + str(error))
            self.errored('Exception occurred while verifying BH mac route in BGP')

    @aetest.test
    def Unconfig_Mac_BH_route(self,testbed):
        node3_s1_bgw_1 =testbed.devices['node3_s1_bgw_1']
        P3_dict = AcceSW_TGEN_data
        testbed.devices['node3_s1_bgw_1'].configure('''

                no mac address-table static ''' + str(P3_dict['mac']) + ''' vlan '''+ str(P3_dict['vlan_id']) + ''' drop

            ''')

        testbed.devices['node4_s1_bgw_2'].configure('''

                no mac address-table static ''' + P3_dict['mac'] + ''' vlan '''+ P3_dict['vlan_id'] + ''' drop

            ''')
  
    @aetest.test
    def VERIFY_IXIA_TRAFFIC_After_rmBH_Route(self, testscript):
        """ IXIA_CONFIGURATION subsection: Verify IXIA Traffic """

        # Do not perform configurations if skip_tgen_config flag is set
        #if not testscript.parameters['script_flags']['skip_tgen_config']:

        time.sleep(20)

        if ixLib.verify_traffic(1) == 1:
            log.debug("Traffic Verification Passed.") 
        else:
            log.info("Traffic Verification Failed.")
            # ForkedPdb().set_trace()
            self.failed("Traffic Verification failed")
        # else:
        #     self.passed(reason="Skipped TGEN Configurations as per request")

    @aetest.test
    def cleanup(self,testscript,testbed):
        """Unconfigure Evpn policies"""
        node3_s1_bgw_1 =testbed.devices['node3_s1_bgw_1']
        node5_s1_leaf_1 = testbed.devices['node5_s1_leaf_1']
        node10_s1_AccessSW = testbed.devices['node10_s1_AccessSW']
        node7_s2_bgw_1 = testbed.devices['node7_s2_bgw_1']
        P3_dict = AcceSW_TGEN_data
        forwardingSysDict = FWD_SYS_dict
    	# Stop Traffic from ixia
        log.info("--- Stopping Traffic ---- \n")
        log.info("Stopping Traffic")
        traffic_run_status = ixLib.stop_traffic()
    
        if traffic_run_status is not 1:
            log.info("Failed: To Stop traffic")
            return 0
        else:
            log.info("\nTraffic Stopped successfully\n")
            time.sleep(10)
    	####Remove traffic item configured
        UCAST_L2_dict_1 = {
                    'mode'        : 'remove',
                    'stream_id'   : stream_id,
                    
              }
        if (ixLib.delete_traffic_item(UCAST_L2_dict_1))==0:
            log.debug("Traffic Remove failed")
            self.failed("Traffic Remove failed", goto=['next_tc'])
        else:
            log.info("Traffic Remove Passed")
        UCAST_L2_dict_2 = {
                    'mode'        : 'remove',
                    'stream_id'   : stream_id_1,
                    
              }
        if (ixLib.delete_traffic_item(UCAST_L2_dict_2))==0:
            log.debug("Traffic Remove failed")
            self.failed("Traffic Remove failed", goto=['next_tc'])
        else:
            log.info("Traffic Remove Passed")
        UCAST_L2_dict_3 = {
                    'mode'        : 'remove',
                    'stream_id'   : stream_id_2,
                    
              }
        if (ixLib.delete_traffic_item(UCAST_L2_dict_3))==0:
            log.debug("Traffic Remove failed")
            self.failed("Traffic Remove failed", goto=['next_tc'])
        else:
            log.info("Traffic Remove Passed")
    	###LEAF_1_MAC_BH_ROUTE
        testbed.devices['node3_s1_bgw_1'].configure('''

        	no mac address-table static ''' + str(P3_dict['mac']) + ''' vlan '''+ str(P3_dict['vlan_id']) + ''' drop

    	''')
  
    
class Mac_BH_route_on_Standalone_Vtep(nxtest.Testcase):
    #""""TC_0022_Mac_BH_route_on_Standalone_Vtep"""""

    stream_id=''
    @aetest.test
    def CONFIGURE_L2_UCAST_IXIA_TRAFFIC_H2_to_H1(self, testscript):
        """ IXIA_CONFIGURATION subsection: Configure MCAST Traffic Item """

        # Do not perform configurations if skip_tgen_config flag is set
        #if not testscript.parameters['script_flags']['skip_tgen_config']:

        IX_TP1 = testscript.parameters['IX_TP1']
        IX_TP2 = testscript.parameters['IX_TP2']
        IX_TP3 = testscript.parameters['IX_TP3']
        IX_TP4 = testscript.parameters['IX_TP4']

        P1_dict = S1_BGW1_TGEN_data
        P2_dict = S1_Leaf_TGEN_data
        P3_dict = AcceSW_TGEN_data
        P4_dict = S2_Leaf_TGEN_data

        #sending traffic P2 = Host2 to P3 = Host1
        UCAST_L2_dict_1 = {   'src_hndl'  : IX_TP2['port_handle'],
                            'dst_hndl'  : IX_TP3['port_handle'],
                            'circuit'   : 'raw',
                            'TI_name'   : "UCAST_L2",
                            'rate_pps'  : "9000",
                            'bi_dir'    : 0,
                            'frame_size': '128',
                            'src_mac'   : P2_dict['mac'],
                            'dst_mac'   : P3_dict['mac'],
                            'srcmac_step': P2_dict['mac_step'],
                            'dstmac_step': P3_dict['mac_step'],
                            'srcmac_count': '1',
                            'dstmac_count': '1',
                            'vlan_id'    : P2_dict['vlan_id'],
                            'vlanid_step': P2_dict['vlan_id_step'],
                            'vlanid_count': '1',
                            'vlan_user_priority': P2_dict['vlan_user_priority']

                        }

        UCAST_L2_TI = ixLib.configure_ixia_L2_UCAST_traffic_item(UCAST_L2_dict_1)

        if UCAST_L2_TI == 0:
            log.debug("Configuring UCast L2 TI failed")
            self.errored("Configuring UCast L2 TI failed", goto=['cleanup'])
        else:
            global stream_id
            stream_id = UCAST_L2_TI
            

        # else:
        # self.passed(reason="Skipped TGEN Configurations as per request")
    stream_id_1=''
    @aetest.test
    def CONFIGURE_L2_UCAST_IXIA_TRAFFIC_H3_to_H1(self, testscript):
        """ IXIA_CONFIGURATION subsection: Configure MCAST Traffic Item """

        # Do not perform configurations if skip_tgen_config flag is set
        #if not testscript.parameters['script_flags']['skip_tgen_config']:

        IX_TP1 = testscript.parameters['IX_TP1']
        IX_TP2 = testscript.parameters['IX_TP2']
        IX_TP3 = testscript.parameters['IX_TP3']
        IX_TP4 = testscript.parameters['IX_TP4']

        P1_dict = S1_BGW1_TGEN_data
        P2_dict = S1_Leaf_TGEN_data
        P3_dict = AcceSW_TGEN_data
        P4_dict = S2_Leaf_TGEN_data

        #sending traffic to P1= Host3 to P3 = Host 1
        UCAST_L2_dict_2 = {   'src_hndl'  : IX_TP1['port_handle'],
                            'dst_hndl'  : IX_TP3['port_handle'],
                            'circuit'   : 'raw',
                            'TI_name'   : "UCAST_L2",
                            'rate_pps'  : "9000",
                            'bi_dir'    : 0,
                            'frame_size': '128',
                            'src_mac'   : P1_dict['mac'],
                            'dst_mac'   : P3_dict['mac'],
                            'srcmac_step': P1_dict['mac_step'],
                            'dstmac_step': P3_dict['mac_step'],
                            'srcmac_count': '1',
                            'dstmac_count': '1',
                            'vlan_id'    : P1_dict['vlan_id'],
                            'vlanid_step': P1_dict['vlan_id_step'],
                            'vlanid_count': '1',
	                    'vlan_user_priority': P1_dict['vlan_user_priority']

                        }

        UCAST_L2_TI_1 = ixLib.configure_ixia_L2_UCAST_traffic_item(UCAST_L2_dict_2)

        if UCAST_L2_TI_1 == 0:
            log.debug("Configuring UCast L2 TI failed")
            self.errored("Configuring UCast L2 TI failed", goto=['cleanup'])
        else:
            global stream_id_1
            stream_id_1 = UCAST_L2_TI_1
            

        # else:
        #     self.passed(reason="Skipped TGEN Configurations as per request")
    stream_id_2=''
    @aetest.test
    def CONFIGURE_L2_UCAST_IXIA_TRAFFIC_H4_to_H1(self, testscript):
        """ IXIA_CONFIGURATION subsection: Configure MCAST Traffic Item """

        # Do not perform configurations if skip_tgen_config flag is set
        #if not testscript.parameters['script_flags']['skip_tgen_config']:

        IX_TP1 = testscript.parameters['IX_TP1']
        IX_TP2 = testscript.parameters['IX_TP2']
        IX_TP3 = testscript.parameters['IX_TP3']
        IX_TP4 = testscript.parameters['IX_TP4']

        P1_dict = S1_BGW1_TGEN_data
        P2_dict = S1_Leaf_TGEN_data
        P3_dict = AcceSW_TGEN_data
        P4_dict = S2_Leaf_TGEN_data

        #sending traffic to P4= Host4 to P3 = Host 1
        UCAST_L2_dict_3 = {   'src_hndl'  : IX_TP4['port_handle'],
                            'dst_hndl'  : IX_TP3['port_handle'],
                            'circuit'   : 'raw',
                            'TI_name'   : "UCAST_L2",
                            'rate_pps'  : "9000",
                            'bi_dir'    : 0,
                            'frame_size': '128',
                            'src_mac'   : P4_dict['mac'],
                            'dst_mac'   : P3_dict['mac'],
                            'srcmac_step': P4_dict['mac_step'],
                            'dstmac_step': P3_dict['mac_step'],
                            'srcmac_count': '1',
                            'dstmac_count': '1',
                            'vlan_id'    : P4_dict['vlan_id'],
                            'vlanid_step': P4_dict['vlan_id_step'],
                            'vlanid_count': '1',
                            'vlan_user_priority': P4_dict['vlan_user_priority']

                        }

        UCAST_L2_TI_2 = ixLib.configure_ixia_L2_UCAST_traffic_item(UCAST_L2_dict_3)

        if UCAST_L2_TI_2 == 0:
            log.debug("Configuring UCast L2 TI failed")
            self.errored("Configuring UCast L2 TI failed", goto=['cleanup'])
        else:
            global stream_id_2
            stream_id_2 = UCAST_L2_TI_2
            

        # else:
        #     self.passed(reason="Skipped TGEN Configurations as per request")

    @aetest.test
    def APPLY_TRAFFIC(self):
        """ IXIA_CONFIGURATION subsection: Verify IXIA Traffic """

        # Apply IXIA Traffic
        if ixLib.apply_traffic() == 1:
            log.info("Applying IXIA TI Passed")
        else:
            self.errored("Applying IXIA TI failed")

    @aetest.test
    def VERIFY_IXIA_TRAFFIC_Without_BH_Route(self, testscript):
        """ IXIA_CONFIGURATION subsection: Verify IXIA Traffic """

        # Do not perform configurations if skip_tgen_config flag is set
        #if not testscript.parameters['script_flags']['skip_tgen_config']:

        time.sleep(20)

        if ixLib.verify_traffic(1) == 1:
            log.debug("Traffic Verification Passed.Expecting traffic loss here.") 
        else:
            log.info("Traffic Verification Failed. Expecting traffic loss here.")
            self.failed("Traffic Verification failed")
        # else:
        #     self.passed(reason="Skipped TGEN Configurations as per request")
    

    @aetest.test
    def Config_Mac_BH_on_remote_vtep(self, testscript,testbed):
        node7_s2_bgw_1 = testbed.devices['node7_s2_bgw_1']
        P3_dict = AcceSW_TGEN_data

        try:
            ###S1_BGw1_MAC_BH_ROUTE
            testbed.devices['node7_s2_bgw_1'].configure('''

                mac address-table static ''' + str(P3_dict['mac']) + ''' vlan '''+ str(P3_dict['vlan_id']) + ''' drop

            ''')

        except Exception as error:
            log.debug("Unable to configure static BH mac route - Encountered Exception " + str(error))
            self.errored('Exception occurred while configuring static BH mac route', goto=['cleanup'])

    @aetest.test
    def VERIFY_IXIA_TRAFFIC_With_BH_Route(self, testscript):
        """ IXIA_CONFIGURATION subsection: Verify IXIA Traffic """

        # Do not perform configurations if skip_tgen_config flag is set
        #if not testscript.parameters['script_flags']['skip_tgen_config']:

        time.sleep(30)

        if ixLib.verify_traffic(99) == 0:
            log.debug("Traffic Verification Passed.") 
        else:
            log.info("Traffic Verification Failed.")
            self.failed("Traffic Verification failed")
        # else:
        #     self.passed(reason="Skipped TGEN Configurations as per request")
    
    @aetest.test
    def Verify_Traffic_Drop_on_Remote_Vtep(self,testscript,testbed):
        node5_s1_leaf_1 = testbed.devices['node5_s1_leaf_1']
        node3_s1_bgw_1 = testbed.devices['node3_s1_bgw_1']
        node9_s2_leaf_1 = testbed.devices['node9_s2_leaf_1']
        P3_dict = AcceSW_TGEN_data
        uplink_PO=S1_Leaf_dict['S1_Leaf_UPLINK_PO']['po_id']
        if verify_traffic_drop(node5_s1_leaf_1,uplink_PO):
            log.info('Traffic correctly dropped on  S1_Leaf')
        else:
            log.info('Traffic NOT dropped on  S1_Leaf')
            self.failed('Traffic NOT dropped on  S1_Leaf')

        uplink_PO=S1_BGW1_dict['S1_BGW1_UPLINK_PO']['po_id']
        if verify_traffic_drop(node3_s1_bgw_1,uplink_PO):
            log.info('Traffic correctly dropped on  S1_BGW1')
        else:
            log.info('Traffic NOT dropped on  S1_BGW1')
            self.failed('Traffic NOT dropped on  S1_BGW1')
        
        uplink_PO=S2_Leaf_dict['S2_Leaf_UPLINK_PO']['po_id']
        if verify_traffic_drop(node9_s2_leaf_1,uplink_PO):
            log.info('Traffic correctly dropped on  S2_Leaf')
        else:
            log.info('Traffic NOT dropped on  S2_Leaf')
            self.failed('Traffic NOT dropped on  S2_Leaf')

    @aetest.test
    def verify_BH_route_remote_standalone_Vtep(self, testscript,testbed):
        node7_s2_bgw_1 = testbed.devices['node7_s2_bgw_1']
        node3_s1_bgw_1 = testbed.devices['node3_s1_bgw_1']
        P3_dict = AcceSW_TGEN_data

        try:
            ###LEAF_2_MAC_BH_ROUTE
            if verify_BH_route_in_L2FM(node7_s2_bgw_1,str(P3_dict['vlan_id']),str(P3_dict['mac'])):
                log.info('Mac BH route is proper in L2FM on  S2_BGW1')
            else:
                log.info('Mac BH route is improper in L2FM on  S2_BGW1')
                self.failed('Mac BH route is improper in L2FM on  S2_BGW1', goto=['cleanup'])

            ###LEAF_3_MAC_BH_ROUTE
            if verify_BH_route_in_L2FM(node3_s1_bgw_1,str(P3_dict['vlan_id']),str(P3_dict['mac'])):
                log.info('Mac BH route is proper in L2FM on  Access')
            else:
                log.info('Mac BH route is improper in L2FM on  Access')
                self.failed('Mac BH route is improper in L2FM on  Access', goto=['cleanup'])

        except Exception as error:
            log.debug("Unable to verify BH mac route in L2FM - Encountered Exception " + str(error))
            self.errored('Exception occurred while verifying BH mac route in L2FM', goto=['cleanup'])


        try:
            #S1_Leaf_Mac_BH_route
            if verify_L2rib_output(node3_s1_bgw_1,str(P3_dict['vlan_id']),str(P3_dict['mac'])):
                log.info('Mac BH route is proper in L2RIB on S1_Leaf')
            else:
                log.debug('Mac BH route is improper in L2RIB on  S1_Leaf')
                self.failed('Mac BH route is improper in L2RIB on  S1_Leaf', goto=['cleanup'])

            #S2_BGW1_Mac_BH_route
            if verify_L2rib_output(node7_s2_bgw_1,str(P3_dict['vlan_id']),str(P3_dict['mac'])):
                log.info('Mac BH route is proper in L2RIB on S2_BGW1')
            else:
                log.debug('Mac BH route is improper in L2RIB on  S2_BGW1')
                self.errored('Mac BH route is improper in L2RIB on  S2_BGW1', goto=['cleanup'])
        
        except Exception as error:
            log.debug("Unable to verify BH mac route in L2RIB - Encountered Exception " + str(error))
            self.errored('Exception occurred while verifying BH mac route in L2RIB', goto=['cleanup'])
        

        try:
            #S1_Leaf_Mac_BH_route
            if verify_BH_in_Remote_BGP(node3_s1_bgw_1,str(P3_dict['mac'])):
                log.info('Mac BH route is proper in BGP on S1_Leaf')
            else:
                log.debug('Mac BH route is improper in BGP on  S1_Leaf')
                self.failed('Mac BH route is improper in BGP on  S1_Leaf', goto=['cleanup'])

            #S2_BGW1_Mac_BH_route
            if verify_BH_in_Remote_BGP(node7_s2_bgw_1,str(P3_dict['mac'])):
                log.info('Mac BH route is proper in BGP on S2_BGW1')
            else:
                log.debug('Mac BH route is improper in BGP on  S2_BGW1')
                self.errored('Mac BH route is improper in BGP on  S2_BGW1', goto=['cleanup'])
        
        except Exception as error:
            log.debug("Unable to verify BH mac route in BGP - Encountered Exception " + str(error))
            self.errored('Exception occurred while verifying BH mac route in BGP', goto=['cleanup'])

    @aetest.test
    def Unconfig_Mac_BH_route(self,testbed):
        node3_s1_bgw_1 =testbed.devices['node7_s2_bgw_1']
        P3_dict = AcceSW_TGEN_data
        testbed.devices['node7_s2_bgw_1'].configure('''

                no mac address-table static ''' + str(P3_dict['mac']) + ''' vlan '''+ str(P3_dict['vlan_id']) + ''' drop

            ''')
    
   
    @aetest.test
    def VERIFY_IXIA_TRAFFIC_after_rmBH_Route(self, testscript):
        """ IXIA_CONFIGURATION subsection: Verify IXIA Traffic """

        # Do not perform configurations if skip_tgen_config flag is set
        #if not testscript.parameters['script_flags']['skip_tgen_config']:

        time.sleep(30)

        if ixLib.verify_traffic(1) == 1:
            log.debug("Traffic Verification Passed.") 
        else:
            log.info("Traffic Verification Failed.")
            self.failed("Traffic Verification failed")
        # else:
        #     self.passed(reason="Skipped TGEN Configurations as per request")
    

    @aetest.cleanup
    def cleanup(self,testscript,testbed):
        """Unconfigure qos policies"""
        node3_s1_bgw_1 = testbed.devices['node3_s1_bgw_1']
        node5_s1_leaf_1 = testbed.devices['node5_s1_leaf_1']
        node10_s1_AccessSW = testbed.devices['node10_s1_AccessSW']
        node7_s2_bgw_1 = testbed.devices['node7_s2_bgw_1']
        P3_dict = AcceSW_TGEN_data
        forwardingSysDict = FWD_SYS_dict
    	# Stop Traffic from ixia
        log.info("--- Stopping Traffic ---- \n")
        log.info("Stopping Traffic")
        traffic_run_status = ixLib.stop_traffic()
    
        if traffic_run_status is not 1:
            log.info("Failed: To Stop traffic")
            return 0
        else:
            log.info("\nTraffic Stopped successfully\n")
            time.sleep(10)
    	####Remove traffic item configured
        UCAST_L2_dict_1 = {
                    'mode'        : 'remove',
                    'stream_id'   : stream_id,
              }
        if (ixLib.delete_traffic_item(UCAST_L2_dict_1))==0:
            log.debug("Traffic Remove failed")
            self.failed("Traffic Remove failed", goto=['next_tc'])
        else:
            log.info("Traffic Remove Passed")
        UCAST_L2_dict_2 = {
                    'mode'        : 'remove',
                    'stream_id'   : stream_id_1,
              }
        if (ixLib.delete_traffic_item(UCAST_L2_dict_2))==0:
            log.debug("Traffic Remove failed")
            self.failed("Traffic Remove failed", goto=['next_tc'])
        else:
            log.info("Traffic Remove Passed")
        UCAST_L2_dict_3 = {
                    'mode'        : 'remove',
                    'stream_id'   : stream_id_2,
              }
        if (ixLib.delete_traffic_item(UCAST_L2_dict_3))==0:
            log.debug("Traffic Remove failed")
            self.failed("Traffic Remove failed", goto=['next_tc'])
        else:
            log.info("Traffic Remove Passed")
   	 ###LEAF_1_MAC_BH_ROUTE
        testbed.devices['node7_s2_bgw_1'].configure('''

             no mac address-table static ''' + str(P3_dict['mac']) + ''' vlan '''+ str(P3_dict['vlan_id']) + ''' drop

    	''')
    
    #==================================================================================================================#
class Mac_BH_on_VPC_start_Traffic(nxtest.Testcase):
    #"""""TC_0024_Mac_BH_on_VPC_start_Traffic"""""
    stream_id=''
    @aetest.test
    def CONFIGURE_L2_UCAST_IXIA_TRAFFIC_H2_to_H1(self, testscript):
        """ IXIA_CONFIGURATION subsection: Configure MCAST Traffic Item """

        # Do not perform configurations if skip_tgen_config flag is set
        #if not testscript.parameters['script_flags']['skip_tgen_config']:

        IX_TP1 = testscript.parameters['IX_TP1']
        IX_TP2 = testscript.parameters['IX_TP2']
        IX_TP3 = testscript.parameters['IX_TP3']
        IX_TP4 = testscript.parameters['IX_TP4']

        P1_dict = S1_BGW1_TGEN_data
        P2_dict = S1_Leaf_TGEN_data
        P3_dict = AcceSW_TGEN_data
        P4_dict = S2_Leaf_TGEN_data

        #sending traffic P2 = Host2 to P3 = Host1
        UCAST_L2_dict_1 = {   'src_hndl'  : IX_TP2['port_handle'],
                            'dst_hndl'  : IX_TP3['port_handle'],
                            'circuit'   : 'raw',
                            'TI_name'   : "UCAST_L2",
                            'rate_pps'  : "9000",
                            'bi_dir'    : 0,
                            'frame_size': '128',
                            'src_mac'   : P2_dict['mac'],
                            'dst_mac'   : P3_dict['mac'],
                            'srcmac_step': P2_dict['mac_step'],
                            'dstmac_step': P3_dict['mac_step'],
                            'srcmac_count': '1',
                            'dstmac_count': '1',
                            'vlan_id'    : P2_dict['vlan_id'],
                            'vlanid_step': P2_dict['vlan_id_step'],
                            'vlanid_count': '1',
                            'vlan_user_priority': P2_dict['vlan_user_priority']

                        }

        UCAST_L2_TI = ixLib.configure_ixia_L2_UCAST_traffic_item(UCAST_L2_dict_1)

        if UCAST_L2_TI == 0:
            log.debug("Configuring UCast L2 TI failed")
            self.errored("Configuring UCast L2 TI failed", goto=['cleanup'])
        else:
            global stream_id
            stream_id = UCAST_L2_TI
            

        # else:
        # self.passed(reason="Skipped TGEN Configurations as per request")
    stream_id_1=''
    @aetest.test
    def CONFIGURE_L2_UCAST_IXIA_TRAFFIC_H3_to_H1(self, testscript):
        """ IXIA_CONFIGURATION subsection: Configure MCAST Traffic Item """

        # Do not perform configurations if skip_tgen_config flag is set
        #if not testscript.parameters['script_flags']['skip_tgen_config']:

        IX_TP1 = testscript.parameters['IX_TP1']
        IX_TP2 = testscript.parameters['IX_TP2']
        IX_TP3 = testscript.parameters['IX_TP3']
        IX_TP4 = testscript.parameters['IX_TP4']

        P1_dict = S1_BGW1_TGEN_data
        P2_dict = S1_Leaf_TGEN_data
        P3_dict = AcceSW_TGEN_data
        P4_dict = S2_Leaf_TGEN_data

        #sending traffic to P1= Host3 to P3 = Host 1
        UCAST_L2_dict_2 = {   'src_hndl'  : IX_TP1['port_handle'],
                            'dst_hndl'  : IX_TP3['port_handle'],
                            'circuit'   : 'raw',
                            'TI_name'   : "UCAST_L2",
                            'rate_pps'  : "9000",
                            'bi_dir'    : 0,
                            'frame_size': '128',
                            'src_mac'   : P1_dict['mac'],
                            'dst_mac'   : P3_dict['mac'],
                            'srcmac_step': P1_dict['mac_step'],
                            'dstmac_step': P3_dict['mac_step'],
                            'srcmac_count': '1',
                            'dstmac_count': '1',
                            'vlan_id'    : P1_dict['vlan_id'],
                            'vlanid_step': P1_dict['vlan_id_step'],
                            'vlanid_count': '1',
	                    'vlan_user_priority': P1_dict['vlan_user_priority']

                        }

        UCAST_L2_TI_1 = ixLib.configure_ixia_L2_UCAST_traffic_item(UCAST_L2_dict_2)

        if UCAST_L2_TI_1 == 0:
            log.debug("Configuring UCast L2 TI failed")
            self.errored("Configuring UCast L2 TI failed", goto=['cleanup'])
        else:
            global stream_id_1
            stream_id_1 = UCAST_L2_TI_1
            

        # else:
        #     self.passed(reason="Skipped TGEN Configurations as per request")
    stream_id_2=''
    @aetest.test
    def CONFIGURE_L2_UCAST_IXIA_TRAFFIC_H4_to_H1(self, testscript):
        """ IXIA_CONFIGURATION subsection: Configure MCAST Traffic Item """

        # Do not perform configurations if skip_tgen_config flag is set
        #if not testscript.parameters['script_flags']['skip_tgen_config']:

        IX_TP1 = testscript.parameters['IX_TP1']
        IX_TP2 = testscript.parameters['IX_TP2']
        IX_TP3 = testscript.parameters['IX_TP3']
        IX_TP4 = testscript.parameters['IX_TP4']

        P1_dict = S1_BGW1_TGEN_data
        P2_dict = S1_Leaf_TGEN_data
        P3_dict = AcceSW_TGEN_data
        P4_dict = S2_Leaf_TGEN_data

        #sending traffic to P4= Host4 to P3 = Host 1
        UCAST_L2_dict_3 = {   'src_hndl'  : IX_TP4['port_handle'],
                            'dst_hndl'  : IX_TP3['port_handle'],
                            'circuit'   : 'raw',
                            'TI_name'   : "UCAST_L2",
                            'rate_pps'  : "9000",
                            'bi_dir'    : 0,
                            'frame_size': '128',
                            'src_mac'   : P4_dict['mac'],
                            'dst_mac'   : P3_dict['mac'],
                            'srcmac_step': P4_dict['mac_step'],
                            'dstmac_step': P3_dict['mac_step'],
                            'srcmac_count': '1',
                            'dstmac_count': '1',
                            'vlan_id'    : P4_dict['vlan_id'],
                            'vlanid_step': P4_dict['vlan_id_step'],
                            'vlanid_count': '1',
                            'vlan_user_priority': P4_dict['vlan_user_priority']

                        }

        UCAST_L2_TI_2 = ixLib.configure_ixia_L2_UCAST_traffic_item(UCAST_L2_dict_3)

        if UCAST_L2_TI_2 == 0:
            log.debug("Configuring UCast L2 TI failed")
            self.errored("Configuring UCast L2 TI failed", goto=['cleanup'])
        else:
            global stream_id_2
            stream_id_2 = UCAST_L2_TI_2
            

        # else:
        #     self.passed(reason="Skipped TGEN Configurations as per request")

        #======================================================================================================#
    @aetest.test
    def APPLY_TRAFFIC(self):
        """ IXIA_CONFIGURATION subsection: Verify IXIA Traffic """

        # Apply IXIA Traffic
        if ixLib.apply_traffic() == 1:
            log.info("Applying IXIA TI Passed")
        else:
            self.errored("Applying IXIA TI failed", goto=['next_tc'])

    #==========================================================================================================================#
    @aetest.test
    def VERIFY_IXIA_TRAFFIC_Without_BH_Route(self, testscript):
        """ IXIA_CONFIGURATION subsection: Verify IXIA Traffic """

        # Do not perform configurations if skip_tgen_config flag is set
        #if not testscript.parameters['script_flags']['skip_tgen_config']:

        time.sleep(30)

        if ixLib.verify_traffic(1) == 1:
            log.debug("Traffic Verification Passed.Expecting traffic loss here.") 
        else:
            log.info("Traffic Verification Failed. Expecting traffic loss here.")
            self.failed("Traffic Verification failed")
        # else:
        #     self.passed(reason="Skipped TGEN Configurations as per request")

    @aetest.test
    def Config_Mac_BH_Route_On_vpc(self,testscript,testbed):
        node3_s1_bgw_1 = testbed.devices['node3_s1_bgw_1']
        P3_dict = AcceSW_TGEN_data
        
        try:
            ###S1_BGw1_MAC_BH_ROUTE
            testbed.devices['node3_s1_bgw_1'].configure('''

                mac address-table static ''' + str(P3_dict['mac']) + ''' vlan '''+ str(P3_dict['vlan_id']) + ''' drop

            ''')
            testbed.devices['node4_s1_bgw_2'].configure('''

                mac address-table static ''' + P3_dict['mac'] + ''' vlan '''+ P3_dict['vlan_id'] + ''' drop

            ''')
        except Exception as error:
            log.debug("Unable to configure static BH mac route - Encountered Exception " + str(error))
            self.errored('Exception occurred while configuring static BH mac route') 
    
    @aetest.test
    def VERIFY_IXIA_TRAFFIC_With_BH_Route(self, testscript):
        """ IXIA_CONFIGURATION subsection: Verify IXIA Traffic """

        # Do not perform configurations if skip_tgen_config flag is set
        #if not testscript.parameters['script_flags']['skip_tgen_config']:

        time.sleep(30)

        if ixLib.verify_traffic(99) == 0:
            log.debug("Traffic Verification Passed.Expecting traffic loss here.") 
        else:
            log.info("Traffic Verification Failed. Expecting traffic loss here.")
            self.failed("Traffic Verification failed")
        # else:
        #     self.passed(reason="Skipped TGEN Configurations as per request")


    @aetest.test
    def Verify_Traffic_Drop_on_Remote_Vtep(self,testscript,testbed):
        node5_s1_leaf_1 = testbed.devices['node5_s1_leaf_1']
        node7_s2_bgw_1 = testbed.devices['node7_s2_bgw_1']
        node9_s2_leaf_1 = testbed.devices['node9_s2_leaf_1']
        P3_dict = AcceSW_TGEN_data
        uplink_PO=S1_Leaf_dict['S1_Leaf_UPLINK_PO']['po_id']
        if verify_traffic_drop(node5_s1_leaf_1,uplink_PO):
            log.info('Traffic correctly dropped on  S1_Leaf')
        else:
            log.info('Traffic NOT dropped on  S1_Leaf')
            self.failed('Traffic NOT dropped on  S1_Leaf')

        uplink_PO=S2_BGW1_dict['S2_BGW1_UPLINK_PO']['po_id']
        if verify_traffic_drop(node7_s2_bgw_1,uplink_PO):
            log.info('Traffic correctly dropped on  S2_BGW1')
        else:
            log.info('Traffic NOT dropped on  S2_BGW1')
            self.failed('Traffic NOT dropped on  S2_BGW1')
        
        uplink_PO=S2_Leaf_dict['S2_Leaf_UPLINK_PO']['po_id']
        if verify_traffic_drop(node9_s2_leaf_1,uplink_PO):
            log.info('Traffic correctly dropped on  S2_Leaf')
        else:
            log.info('Traffic NOT dropped on  S2_Leaf')
            self.failed('Traffic NOT dropped on  S2_Leaf')

    @aetest.test
    def verify_static_mac_states(self, testscript,testbed):
        node3_s1_bgw_1 = testbed.devices['node3_s1_bgw_1']
        node7_s2_bgw_1 = testbed.devices['node7_s2_bgw_1']
        P3_dict = AcceSW_TGEN_data
        if verify_static_mac(node3_s1_bgw_1,str(P3_dict['mac']),str(P3_dict['vlan_id'])):
            log.info('proper dynaic mac learnt as static on S1_BGw1')
        else:
            log.info('improper dynamic mac learnt on  S1_BGw1')
            self.failed('improper dynamic mac learnt on  S1_BGw1')

        if verify_static_mac(node7_s2_bgw_1,str(P3_dict['mac']),str(P3_dict['vlan_id'])):
            log.info('proper dynaic mac learnt on  S2_BGw1')
        else:
            log.info('improper dynamic mac learnt on S2_BGw1')
            self.failed('improper dynamic mac learnt on  S2_BGw1')
    
    @aetest.test
    def verify_BH_route_remote_standalone_Vtep(self, testscript,testbed):
        node7_s2_bgw_1 = testbed.devices['node7_s2_bgw_1']
        node3_s1_bgw_1 = testbed.devices['node3_s1_bgw_1']
        P3_dict = AcceSW_TGEN_data

        try:
            ###LEAF_2_MAC_BH_ROUTE
            if verify_BH_route_in_L2FM(node7_s2_bgw_1,str(P3_dict['vlan_id']),str(P3_dict['mac'])):
                log.info('Mac BH route is proper in L2FM on  S2_BGW1')
            else:
                log.info('Mac BH route is improper in L2FM on  S2_BGW1')
                self.failed('Mac BH route is improper in L2FM on  S2_BGW1', goto=['cleanup'])

            ###LEAF_3_MAC_BH_ROUTE
            if verify_BH_route_in_L2FM(node3_s1_bgw_1,str(P3_dict['vlan_id']),str(P3_dict['mac'])):
                log.info('Mac BH route is proper in L2FM on  Access')
            else:
                log.info('Mac BH route is improper in L2FM on  Access')
                self.failed('Mac BH route is improper in L2FM on  Access', goto=['cleanup'])

        except Exception as error:
            log.debug("Unable to verify BH mac route in L2FM - Encountered Exception " + str(error))
            self.errored('Exception occurred while verifying BH mac route in L2FM', goto=['cleanup'])


        try:
            #S1_Leaf_Mac_BH_route
            if verify_L2rib_output(node3_s1_bgw_1,str(P3_dict['vlan_id']),str(P3_dict['mac'])):
                log.info('Mac BH route is proper in L2RIB on S1_Leaf')
            else:
                log.debug('Mac BH route is improper in L2RIB on  S1_Leaf')
                self.failed('Mac BH route is improper in L2RIB on  S1_Leaf', goto=['cleanup'])

            #S2_BGW1_Mac_BH_route
            if verify_L2rib_output(node7_s2_bgw_1,str(P3_dict['vlan_id']),str(P3_dict['mac'])):
                log.info('Mac BH route is proper in L2RIB on S2_BGW1')
            else:
                log.debug('Mac BH route is improper in L2RIB on  S2_BGW1')
                self.errored('Mac BH route is improper in L2RIB on  S2_BGW1', goto=['cleanup'])
        
        except Exception as error:
            log.debug("Unable to verify BH mac route in L2RIB - Encountered Exception " + str(error))
            self.errored('Exception occurred while verifying BH mac route in L2RIB', goto=['cleanup'])
        

        try:
            #S1_Leaf_Mac_BH_route
            if verify_BH_in_Remote_BGP(node3_s1_bgw_1,str(P3_dict['mac'])):
                log.info('Mac BH route is proper in BGP on S1_Leaf')
            else:
                log.debug('Mac BH route is improper in BGP on  S1_Leaf')
                self.failed('Mac BH route is improper in BGP on  S1_Leaf', goto=['cleanup'])

            #S2_BGW1_Mac_BH_route
            if verify_BH_in_Remote_BGP(node7_s2_bgw_1,str(P3_dict['mac'])):
                log.info('Mac BH route is proper in BGP on S2_BGW1')
            else:
                log.debug('Mac BH route is improper in BGP on  S2_BGW1')
                self.errored('Mac BH route is improper in BGP on  S2_BGW1', goto=['cleanup'])
        
        except Exception as error:
            log.debug("Unable to verify BH mac route in BGP - Encountered Exception " + str(error))
            self.errored('Exception occurred while verifying BH mac route in BGP', goto=['cleanup'])
    
    @aetest.test
    def Unconfig_Mac_BH_route(self,testbed):
        node3_s1_bgw_1 =testbed.devices['node3_s1_bgw_1']
        P3_dict = AcceSW_TGEN_data
        testbed.devices['node3_s1_bgw_1'].configure('''

                no mac address-table static ''' + str(P3_dict['mac']) + ''' vlan '''+ str(P3_dict['vlan_id']) + ''' drop

            ''')
        testbed.devices['node4_s1_bgw_2'].configure('''

                no mac address-table static ''' + P3_dict['mac'] + ''' vlan '''+ P3_dict['vlan_id'] + ''' drop

            ''')

    @aetest.test
    def VERIFY_IXIA_TRAFFIC_after_rmBH_Route(self, testscript):
        """ IXIA_CONFIGURATION subsection: Verify IXIA Traffic """

        # Do not perform configurations if skip_tgen_config flag is set
        #if not testscript.parameters['script_flags']['skip_tgen_config']:

        time.sleep(30)

        if ixLib.verify_traffic(1) == 1:
            log.debug("Traffic Verification Passed.Expecting traffic loss here.") 
        else:
            log.info("Traffic Verification Failed. Expecting traffic loss here.")
            self.failed("Traffic Verification failed")
        # else:
        #     self.passed(reason="Skipped TGEN Configurations as per request")

    
    @aetest.test
    def cleanup(self,testscript,testbed):
        """Unconfigure qos policies"""
        node3_s1_bgw_1 = testbed.devices['node3_s1_bgw_1']
        node5_s1_leaf_1 = testbed.devices['node5_s1_leaf_1']
        node10_s1_AccessSW =testbed.devices['node10_s1_AccessSW']
        node7_s2_bgw_1 = testbed.devices['node7_s2_bgw_1']
        P3_dict = AcceSW_TGEN_data
        forwardingSysDict = FWD_SYS_dict
        try:
            # Stop Traffic from ixia
            log.info("--- Stopping Traffic ---- \n")
            log.info("Stopping Traffic")
            traffic_run_status = ixLib.stop_traffic()
            
            if traffic_run_status is not 1:
               log.info("Failed: To Stop traffic")
               return 0
            else:
                log.info("\nTraffic Stopped successfully\n")
            time.sleep(10)
            ####Remove traffic item configured
            UCAST_L2_dict_1 = {
                    'mode'        : 'remove',
                    'stream_id'   : stream_id,
                    
              }
            if (ixLib.delete_traffic_item(UCAST_L2_dict_1))==0:
                log.debug("Traffic Remove failed")
                self.failed("Traffic Remove failed", goto=['next_tc'])
            else:
                log.info("Traffic Remove Passed")
            UCAST_L2_dict_2 = {
                        'mode'        : 'remove',
                        'stream_id'   : stream_id_1,
                    
              }
            if (ixLib.delete_traffic_item(UCAST_L2_dict_2))==0:
                log.debug("Traffic Remove failed")
                self.failed("Traffic Remove failed", goto=['next_tc'])
            else:
                log.info("Traffic Remove Passed")
            UCAST_L2_dict_3 = {
                        'mode'        : 'remove',
                        'stream_id'   : stream_id_2,
                    
              }
            if (ixLib.delete_traffic_item(UCAST_L2_dict_3))==0:
                log.debug("Traffic Remove failed")
                self.failed("Traffic Remove failed", goto=['next_tc'])
            else:
                log.info("Traffic Remove Passed")

            ###LEAF_1_MAC_BH_ROUTE
            testbed.devices['node3_s1_bgw_1'].configure('''

                no mac address-table static ''' + str(P3_dict['mac']) + ''' vlan '''+ str(P3_dict['vlan_id']) + ''' drop

            ''')

        except Exception as error:
            log.debug("Unable to do cleanup " + str(error))
            self.errored('Exception occurred during cleanup', goto=['next_tc'])   

class Config_Mac_BH_onRemoteVtep_Start_traffic(nxtest.Testcase):
    #"TC_0025_Config_Mac_BH_onRemoteVtep_Start_traffic"

    stream_id=''
    @aetest.test
    def CONFIGURE_L2_UCAST_IXIA_TRAFFIC_H2_to_H1(self, testscript):
        """ IXIA_CONFIGURATION subsection: Configure MCAST Traffic Item """

        # Do not perform configurations if skip_tgen_config flag is set
        #if not testscript.parameters['script_flags']['skip_tgen_config']:

        IX_TP1 = testscript.parameters['IX_TP1']
        IX_TP2 = testscript.parameters['IX_TP2']
        IX_TP3 = testscript.parameters['IX_TP3']
        IX_TP4 = testscript.parameters['IX_TP4']

        P1_dict = S1_BGW1_TGEN_data
        P2_dict = S1_Leaf_TGEN_data
        P3_dict = AcceSW_TGEN_data
        P4_dict = S2_Leaf_TGEN_data

        #sending traffic P2 = Host2 to P3 = Host1
        UCAST_L2_dict_1 = {   'src_hndl'  : IX_TP2['port_handle'],
                            'dst_hndl'  : IX_TP3['port_handle'],
                            'circuit'   : 'raw',
                            'TI_name'   : "UCAST_L2",
                            'rate_pps'  : "9000",
                            'bi_dir'    : 0,
                            'frame_size': '128',
                            'src_mac'   : P2_dict['mac'],
                            'dst_mac'   : P3_dict['mac'],
                            'srcmac_step': P2_dict['mac_step'],
                            'dstmac_step': P3_dict['mac_step'],
                            'srcmac_count': '1',
                            'dstmac_count': '1',
                            'vlan_id'    : P2_dict['vlan_id'],
                            'vlanid_step': P2_dict['vlan_id_step'],
                            'vlanid_count': '1',
                            'vlan_user_priority': P2_dict['vlan_user_priority']

                        }

        UCAST_L2_TI = ixLib.configure_ixia_L2_UCAST_traffic_item(UCAST_L2_dict_1)

        if UCAST_L2_TI == 0:
            log.debug("Configuring UCast L2 TI failed")
            self.errored("Configuring UCast L2 TI failed", goto=['cleanup'])
        else:
            global stream_id
            stream_id = UCAST_L2_TI
            

        # else:
        # self.passed(reason="Skipped TGEN Configurations as per request")
    stream_id_1=''
    @aetest.test
    def CONFIGURE_L2_UCAST_IXIA_TRAFFIC_H3_to_H1(self, testscript):
        """ IXIA_CONFIGURATION subsection: Configure MCAST Traffic Item """

        # Do not perform configurations if skip_tgen_config flag is set
        #if not testscript.parameters['script_flags']['skip_tgen_config']:

        IX_TP1 = testscript.parameters['IX_TP1']
        IX_TP2 = testscript.parameters['IX_TP2']
        IX_TP3 = testscript.parameters['IX_TP3']
        IX_TP4 = testscript.parameters['IX_TP4']

        P1_dict = S1_BGW1_TGEN_data
        P2_dict = S1_Leaf_TGEN_data
        P3_dict = AcceSW_TGEN_data
        P4_dict = S2_Leaf_TGEN_data

        #sending traffic to P1= Host3 to P3 = Host 1
        UCAST_L2_dict_2 = {   'src_hndl'  : IX_TP1['port_handle'],
                            'dst_hndl'  : IX_TP3['port_handle'],
                            'circuit'   : 'raw',
                            'TI_name'   : "UCAST_L2",
                            'rate_pps'  : "9000",
                            'bi_dir'    : 0,
                            'frame_size': '128',
                            'src_mac'   : P1_dict['mac'],
                            'dst_mac'   : P3_dict['mac'],
                            'srcmac_step': P1_dict['mac_step'],
                            'dstmac_step': P3_dict['mac_step'],
                            'srcmac_count': '1',
                            'dstmac_count': '1',
                            'vlan_id'    : P1_dict['vlan_id'],
                            'vlanid_step': P1_dict['vlan_id_step'],
                            'vlanid_count': '1',
	                    'vlan_user_priority': P1_dict['vlan_user_priority']

                        }

        UCAST_L2_TI_1 = ixLib.configure_ixia_L2_UCAST_traffic_item(UCAST_L2_dict_2)

        if UCAST_L2_TI_1 == 0:
            log.debug("Configuring UCast L2 TI failed")
            self.errored("Configuring UCast L2 TI failed", goto=['cleanup'])
        else:
            global stream_id_1
            stream_id_1 = UCAST_L2_TI_1
            

        # else:
        #     self.passed(reason="Skipped TGEN Configurations as per request")
    stream_id_2=''
    @aetest.test
    def CONFIGURE_L2_UCAST_IXIA_TRAFFIC_H4_to_H1(self, testscript):
        """ IXIA_CONFIGURATION subsection: Configure MCAST Traffic Item """

        # Do not perform configurations if skip_tgen_config flag is set
        #if not testscript.parameters['script_flags']['skip_tgen_config']:

        IX_TP1 = testscript.parameters['IX_TP1']
        IX_TP2 = testscript.parameters['IX_TP2']
        IX_TP3 = testscript.parameters['IX_TP3']
        IX_TP4 = testscript.parameters['IX_TP4']

        P1_dict = S1_BGW1_TGEN_data
        P2_dict = S1_Leaf_TGEN_data
        P3_dict = AcceSW_TGEN_data
        P4_dict = S2_Leaf_TGEN_data

        #sending traffic to P4= Host4 to P3 = Host 1
        UCAST_L2_dict_3 = {   'src_hndl'  : IX_TP4['port_handle'],
                            'dst_hndl'  : IX_TP3['port_handle'],
                            'circuit'   : 'raw',
                            'TI_name'   : "UCAST_L2",
                            'rate_pps'  : "9000",
                            'bi_dir'    : 0,
                            'frame_size': '128',
                            'src_mac'   : P4_dict['mac'],
                            'dst_mac'   : P3_dict['mac'],
                            'srcmac_step': P4_dict['mac_step'],
                            'dstmac_step': P3_dict['mac_step'],
                            'srcmac_count': '1',
                            'dstmac_count': '1',
                            'vlan_id'    : P4_dict['vlan_id'],
                            'vlanid_step': P4_dict['vlan_id_step'],
                            'vlanid_count': '1',
                            'vlan_user_priority': P4_dict['vlan_user_priority']

                        }

        UCAST_L2_TI_2 = ixLib.configure_ixia_L2_UCAST_traffic_item(UCAST_L2_dict_3)

        if UCAST_L2_TI_2 == 0:
            log.debug("Configuring UCast L2 TI failed")
            self.errored("Configuring UCast L2 TI failed", goto=['cleanup'])
        else:
            global stream_id_2
            stream_id_2 = UCAST_L2_TI_2
            

        # else:
        #     self.passed(reason="Skipped TGEN Configurations as per request")

    @aetest.test
    def APPLY_TRAFFIC(self):
        """ IXIA_CONFIGURATION subsection: Verify IXIA Traffic """

        # Apply IXIA Traffic
        if ixLib.apply_traffic() == 1:
            log.info("Applying IXIA TI Passed")
        else:
            self.errored("Applying IXIA TI failed")
    @aetest.test
    def VERIFY_IXIA_TRAFFIC_Without_BH_Route(self, testscript):
        """ IXIA_CONFIGURATION subsection: Verify IXIA Traffic """

        # Do not perform configurations if skip_tgen_config flag is set
        #if not testscript.parameters['script_flags']['skip_tgen_config']:

        time.sleep(20)

        if ixLib.verify_traffic(1) == 1:
            log.debug("Traffic Verification Passed.Expecting traffic loss here.") 
        else:
            log.info("Traffic Verification Failed. Expecting traffic loss here.")
            self.failed("Traffic Verification failed")
        # else:
        #     self.passed(reason="Skipped TGEN Configurations as per request")
    

    @aetest.test
    def config_BH_on_RemoteVtep(self, testscript, testbed):
        node7_s2_bgw_1 =testbed.devices['node7_s2_bgw_1']
        P3_dict = AcceSW_TGEN_data
        try:
            ###S1_BGw1_MAC_BH_ROUTE
           testbed.devices['node7_s2_bgw_1'].configure('''

                mac address-table static ''' + str(P3_dict['mac']) + ''' vlan '''+ str(P3_dict['vlan_id']) + ''' drop

            ''')
        except Exception as error:
            log.debug("Unable to configure static BH mac route on Remote Vtep- Encountered Exception " + str(error))
            self.errored('Exception occurred while configuring static BH mac route on Remote Vtep')
   
    @aetest.test
    def APPLY_TRAFFIC(self):
        """ IXIA_CONFIGURATION subsection: Verify IXIA Traffic """

        # Apply IXIA Traffic
        if ixLib.apply_traffic() == 1:
            log.info("Applying IXIA TI Passed")
        else:
            self.errored("Applying IXIA TI failed", goto=['next_tc'])

    #==========================================================================================================================#
    @aetest.test
    def VERIFY_IXIA_TRAFFIC_With_BH_Route(self, testscript):
        """ IXIA_CONFIGURATION subsection: Verify IXIA Traffic """

        # Do not perform configurations if skip_tgen_config flag is set
        #if not testscript.parameters['script_flags']['skip_tgen_config']:

        time.sleep(30)

        if ixLib.verify_traffic(99) == 0:
            log.debug("Traffic Verification Passed.Expecting traffic loss here.") 
        else:
            log.info("Traffic Verification Failed. Expecting traffic loss here.")
            self.failed("Traffic Verification failed")
        # else:
        #     self.passed(reason="Skipped TGEN Configurations as per request")
    @aetest.test 
    def Verify_Traffic_Drop_on_Remote_Vtep(self,testscript,testbed):
        node5_s1_leaf_1 = testbed.devices['node5_s1_leaf_1']
        node3_s1_bgw_1 = testbed.devices['node3_s1_bgw_1']
        node9_s2_leaf_1 =testbed.devices['node9_s2_leaf_1']
        P3_dict = AcceSW_TGEN_data
        uplink_PO=S1_Leaf_dict['S1_Leaf_UPLINK_PO']['po_id']
        if verify_traffic_drop(node5_s1_leaf_1,uplink_PO):
            log.info('Traffic correctly dropped on  S1_Leaf')
        else:
            log.info('Traffic NOT dropped on  S1_Leaf')
            self.failed('Traffic NOT dropped on  S1_Leaf')

        uplink_PO=S1_BGW1_dict['S1_BGW1_UPLINK_PO']['po_id']
        if verify_traffic_drop(node3_s1_bgw_1,uplink_PO):
            log.info('Traffic correctly dropped on  S1_BGW1')
        else:
            log.info('Traffic NOT dropped on  S1_BGW1')
            self.failed('Traffic NOT dropped on  S1_BGW1')
        
        uplink_PO=S2_Leaf_dict['S2_Leaf_UPLINK_PO']['po_id']
        if verify_traffic_drop(node9_s2_leaf_1,uplink_PO):
            log.info('Traffic correctly dropped on  S2_Leaf')
        else:
            log.info('Traffic NOT dropped on  S2_Leaf')
            self.failed('Traffic NOT dropped on  S2_Leaf')

    @aetest.test
    def verify_static_mac_states(self, testscript,testbed):
        node3_s1_bgw_1 = testbed.devices['node3_s1_bgw_1']
        node7_s2_bgw_1 = testbed.devices['node7_s2_bgw_1']
        P3_dict = AcceSW_TGEN_data
        if verify_static_mac(node3_s1_bgw_1,str(P3_dict['mac']),str(P3_dict['vlan_id'])):
            log.info('proper dynaic mac learnt as static on S1_BGw1')
        else:
            log.info('improper dynamic mac learnt on  S1_BGw1')
            self.failed('improper dynamic mac learnt on  S1_BGw1')

        if verify_static_mac(node7_s2_bgw_1,str(P3_dict['mac']),str(P3_dict['vlan_id'])):
            log.info('proper dynaic mac learnt on  S2_BGw1')
        else:
            log.info('improper dynamic mac learnt on S2_BGw1')
            self.failed('improper dynamic mac learnt on  S2_BGw1')
    
    @aetest.test
    def verify_BH_route_remote_standalone_Vtep(self, testscript,testbed):
        node7_s2_bgw_1 = testbed.devices['node7_s2_bgw_1']
        node3_s1_bgw_1 = testbed.devices['node3_s1_bgw_1']
        P3_dict = AcceSW_TGEN_data

        try:
            ###LEAF_2_MAC_BH_ROUTE
            if verify_BH_route_in_L2FM(node7_s2_bgw_1,str(P3_dict['vlan_id']),str(P3_dict['mac'])):
                log.info('Mac BH route is proper in L2FM on  S2_BGW1')
            else:
                log.info('Mac BH route is improper in L2FM on  S2_BGW1')
                self.failed('Mac BH route is improper in L2FM on  S2_BGW1', goto=['cleanup'])

            ###LEAF_3_MAC_BH_ROUTE
            if verify_BH_route_in_L2FM(node3_s1_bgw_1,str(P3_dict['vlan_id']),str(P3_dict['mac'])):
                log.info('Mac BH route is proper in L2FM on  Access')
            else:
                log.info('Mac BH route is improper in L2FM on  Access')
                self.failed('Mac BH route is improper in L2FM on  Access', goto=['cleanup'])

        except Exception as error:
            log.debug("Unable to verify BH mac route in L2FM - Encountered Exception " + str(error))
            self.errored('Exception occurred while verifying BH mac route in L2FM', goto=['cleanup'])


        try:
            #S1_Leaf_Mac_BH_route
            if verify_L2rib_output(node3_s1_bgw_1,str(P3_dict['vlan_id']),str(P3_dict['mac'])):
                log.info('Mac BH route is proper in L2RIB on S1_Leaf')
            else:
                log.debug('Mac BH route is improper in L2RIB on  S1_Leaf')
                self.failed('Mac BH route is improper in L2RIB on  S1_Leaf', goto=['cleanup'])

            #S2_BGW1_Mac_BH_route
            if verify_L2rib_output(node7_s2_bgw_1,str(P3_dict['vlan_id']),str(P3_dict['mac'])):
                log.info('Mac BH route is proper in L2RIB on S2_BGW1')
            else:
                log.debug('Mac BH route is improper in L2RIB on  S2_BGW1')
                self.errored('Mac BH route is improper in L2RIB on  S2_BGW1', goto=['cleanup'])
        
        except Exception as error:
            log.debug("Unable to verify BH mac route in L2RIB - Encountered Exception " + str(error))
            self.errored('Exception occurred while verifying BH mac route in L2RIB', goto=['cleanup'])
        

        try:
            #S1_Leaf_Mac_BH_route
            if verify_BH_in_Remote_BGP(node3_s1_bgw_1,str(P3_dict['mac'])):
                log.info('Mac BH route is proper in BGP on S1_Leaf')
            else:
                log.debug('Mac BH route is improper in BGP on  S1_Leaf')
                self.failed('Mac BH route is improper in BGP on  S1_Leaf', goto=['cleanup'])

            #S2_BGW1_Mac_BH_route
            if verify_BH_in_Remote_BGP(node7_s2_bgw_1,str(P3_dict['mac'])):
                log.info('Mac BH route is proper in BGP on S2_BGW1')
            else:
                log.debug('Mac BH route is improper in BGP on  S2_BGW1')
                self.errored('Mac BH route is improper in BGP on  S2_BGW1', goto=['cleanup'])
        
        except Exception as error:
            log.debug("Unable to verify BH mac route in BGP - Encountered Exception " + str(error))
            self.errored('Exception occurred while verifying BH mac route in BGP', goto=['cleanup'])

    @aetest.test
    def unconfig_BH_on_RemoteVtep(self, testscript, testbed):
        node7_s2_bgw_1 =testbed.devices['node7_s2_bgw_1']
        P3_dict = AcceSW_TGEN_data
        try:
            ###S1_BGw1_MAC_BH_ROUTE
           testbed.devices['node7_s2_bgw_1'].configure('''

                no mac address-table static ''' + str(P3_dict['mac']) + ''' vlan '''+ str(P3_dict['vlan_id']) + ''' drop

            ''')
        except Exception as error:
            log.debug("Unable to configure static BH mac route on Remote Vtep- Encountered Exception " + str(error))
            self.errored('Exception occurred while configuring static BH mac route on Remote Vtep')

    @aetest.test
    def VERIFY_IXIA_TRAFFIC_after_rmBH_Route(self, testscript):
        """ IXIA_CONFIGURATION subsection: Verify IXIA Traffic """

        # Do not perform configurations if skip_tgen_config flag is set
        #if not testscript.parameters['script_flags']['skip_tgen_config']:

        time.sleep(30)

        if ixLib.verify_traffic(1) == 1:
            log.debug("Traffic Verification Passed.Expecting traffic loss here.") 
        else:
            log.info("Traffic Verification Failed. Expecting traffic loss here.")
            self.failed("Traffic Verification failed")
        # else:
        #     self.passed(reason="Skipped TGEN Configurations as per request")

    @aetest.test
    def cleanup(self,testscript,testbed):
        """Unconfigure qos policies"""
        node3_s1_bgw_1 = testbed.devices['node3_s1_bgw_1']
        node5_s1_leaf_1 = testbed.devices['node5_s1_leaf_1']
        node10_s1_AccessSW = testbed.devices['node10_s1_AccessSW']
        node9_s2_leaf_1 = testbed.devices['node9_s2_leaf_1']
        P3_dict = AcceSW_TGEN_data
        forwardingSysDict = FWD_SYS_dict
        try:
            # Stop Traffic from ixia
            log.info("--- Stopping Traffic ---- \n")
            log.info("Stopping Traffic")
            traffic_run_status = ixLib.stop_traffic()
            
            if traffic_run_status is not 1:
               log.info("Failed: To Stop traffic")
               return 0
            else:
                log.info("\nTraffic Stopped successfully\n")
            time.sleep(10)
            ####Remove traffic item configured
            UCAST_L2_dict_1 = {
                    'mode'        : 'remove',
                    'stream_id'   : stream_id,
                    
                }
            if (ixLib.delete_traffic_item(UCAST_L2_dict_1))==0:
                log.debug("Traffic Remove failed")
                self.failed("Traffic Remove failed", goto=['next_tc'])
            else:
                log.info("Traffic Remove Passed")
            UCAST_L2_dict_2 = {
                        'mode'        : 'remove',
                        'stream_id'   : stream_id_1,
                    
                }
            if (ixLib.delete_traffic_item(UCAST_L2_dict_2))==0:
                log.debug("Traffic Remove failed")
                self.failed("Traffic Remove failed", goto=['next_tc'])
            else:
                log.info("Traffic Remove Passed")
            UCAST_L2_dict_3 = {
                        'mode'        : 'remove',
                        'stream_id'   : stream_id_2,
                    
                 }
            if (ixLib.delete_traffic_item(UCAST_L2_dict_3))==0:
                log.debug("Traffic Remove failed")
                self.failed("Traffic Remove failed", goto=['next_tc'])
            else:
                log.info("Traffic Remove Passed")

            ###LEAF_1_MAC_BH_ROUTE
            testbed.devices['node7_s2_bgw_1'].configure('''

                no mac address-table static ''' + str(P3_dict['mac']) + ''' vlan '''+ str(P3_dict['vlan_id']) + ''' drop

            ''')

        except Exception as error:
            log.debug("Unable to do cleanup " + str(error))
            self.errored('Exception occurred during cleanup', goto=['next_tc']) 


###################################################################
###              L2 Ucast with IPv4 header  Test-cases          ###
###################################################################
class Configure_BH_route_static_arp_on_vpcvtep(nxtest.Testcase):
    # """TC_0026_Configure_BH_route_static_arp_on_vpcvtep"""
    # stream_id=''
    # @aetest.test
    # def CONFIGURE_L2_UCAST_IXIA_TRAFFIC_H2_to_H1(self, testscript):
    #     """ IXIA_CONFIGURATION subsection: Configure MCAST Traffic Item """

    #     # Do not perform configurations if skip_tgen_config flag is set
    #     #if not testscript.parameters['script_flags']['skip_tgen_config']:

    #     IX_TP1 = testscript.parameters['IX_TP1']
    #     IX_TP2 = testscript.parameters['IX_TP2']
    #     IX_TP3 = testscript.parameters['IX_TP3']
    #     P1_dict = S1_BGW1_TGEN_data
    #     P2_dict = S1_Leaf_TGEN_data
    #     P3_dict = AcceSW_TGEN_data
    #     P4_dict = S2_Leaf_TGEN_data
    #     # P1_dict = S1_BGW1_TGEN_data
    #     # P4_dict = testscript.parameters['S2_BGW1_TGEN_dict']

    #     UCAST_v4_dict_1 = {   
    #                            'src_hndl'  : IX_TP1['ipv4_handle'],
    #                            'dst_hndl'  : IX_TP3['ipv4_handle'],
    #                            'circuit'   : 'ipv4',
    #                            'TI_name'   : "UCAST_V4",
    #                            'rate_pps'  : "1000",
    #                            'bi_dir'    : 1,
    #                            'bidirectional': '0'
    #                     }


    #     UCAST_v4_TI = ixLib.configure_ixia_traffic_item_v46(UCAST_v4_dict_1)
            
    #     if UCAST_v4_TI == 0:
    #         log.debug("Configuring UCast L2 TI failed")
    #         self.errored("Configuring UCast L2 TI failed", goto=['next_tc'])
    #     else:
    #         global stream_id
    #         stream_id = UCAST_v4_TI
    #     # else:
        #     self.passed(reason="Skipped TGEN Configurations as per request")
    stream_id_1=''
    @aetest.test
    def CONFIGURE_L2_UCAST_IXIA_TRAFFIC_H3_to_H1(self, testscript):
        """ IXIA_CONFIGURATION subsection: Configure MCAST Traffic Item """

        # Do not perform configurations if skip_tgen_config flag is set
        #if not testscript.parameters['script_flags']['skip_tgen_config']:

        IX_TP1 = testscript.parameters['IX_TP1']
        IX_TP2 = testscript.parameters['IX_TP2']
        IX_TP3 = testscript.parameters['IX_TP3']
        P1_dict = S1_BGW1_TGEN_data
        P2_dict = S1_Leaf_TGEN_data
        P3_dict = AcceSW_TGEN_data
        P4_dict = S2_Leaf_TGEN_data
        # P1_dict = S1_BGW1_TGEN_data
        # P4_dict = testscript.parameters['S2_BGW1_TGEN_dict']

        UCAST_v4_dict_2 = {   'src_hndl'  : IX_TP2['ipv4_handle'],
                            'dst_hndl'  : IX_TP3['ipv4_handle'],
                            'circuit'   : 'ipv4',
                            'TI_name'   : "UCAST_V4",
                            'rate_pps'  : "10000",
                            'bi_dir'    : 1,
                            'bidirectional': '0'
                        }

        UCAST_v4_TI_1 = ixLib.configure_ixia_traffic_item_v46(UCAST_v4_dict_2)
            
        if UCAST_v4_TI_1 == 0:
            log.debug("Configuring UCast L2 TI failed")
            self.errored("Configuring UCast L2 TI failed", goto=['next_tc'])
        else:
            global stream_id_1
            stream_id_1 = UCAST_v4_TI_1
        # else:
        #     self.passed(reason="Skipped TGEN Configurations as per request")
    stream_id_2=''
    @aetest.test
    def CONFIGURE_L2_UCAST_IXIA_TRAFFIC_H4_to_H1(self, testscript):
        """ IXIA_CONFIGURATION subsection: Configure MCAST Traffic Item """

        # Do not perform configurations if skip_tgen_config flag is set
        #if not testscript.parameters['script_flags']['skip_tgen_config']:

        IX_TP1 = testscript.parameters['IX_TP1']
        IX_TP2 = testscript.parameters['IX_TP2']
        IX_TP3 = testscript.parameters['IX_TP3']
        IX_TP4 = testscript.parameters['IX_TP4']
        P1_dict = S1_BGW1_TGEN_data
        P2_dict = S1_Leaf_TGEN_data
        P3_dict = AcceSW_TGEN_data
        P4_dict = S2_Leaf_TGEN_data
        # P1_dict = S1_BGW1_TGEN_data
        # P4_dict = testscript.parameters['S2_BGW1_TGEN_dict']

        UCAST_v4_dict_3 = {   'src_hndl'  : IX_TP4['ipv4_handle'],
                            'dst_hndl'  : IX_TP3['ipv4_handle'],
                            'circuit'   : 'ipv4',
                            'TI_name'   : "UCAST_V4",
                            'rate_pps'  : "10000",
                            'bi_dir'    : 1,
                            'bidirectional': '0'
                        }

        UCAST_v4_TI_2 = ixLib.configure_ixia_traffic_item_v46(UCAST_v4_dict_3)
            
        if UCAST_v4_TI_2 == 0:
            log.debug("Configuring UCast L2 TI failed")
            self.errored("Configuring UCast L2 TI failed", goto=['next_tc'])
        else:
            global stream_id_2
            stream_id_2 = UCAST_v4_TI_2
            
        # else:
        #     self.passed(reason="Skipped TGEN Configurations as per request")

    @aetest.test
    def APPLY_TRAFFIC(self):
        """ IXIA_CONFIGURATION subsection: Verify IXIA Traffic """

        # Apply IXIA Traffic
        if ixLib.apply_traffic() == 1:
            log.info("Applying IXIA TI Passed")
            
        else:
            self.errored("Applying IXIA TI failed")
    
    @aetest.test
    def VERIFY_IXIA_TRAFFIC_Without_BH_Route(self, testscript):
        """ IXIA_CONFIGURATION subsection: Verify IXIA Traffic """

        # Do not perform configurations if skip_tgen_config flag is set
        #if not testscript.parameters['script_flags']['skip_tgen_config']:

        time.sleep(20)

        if ixLib.verify_traffic(1) == 1:
            log.debug("Traffic Verification Passed.Expecting traffic loss here.") 
            #ForkedPdb().set_trace()
        else:
            log.info("Traffic Verification Failed. Expecting traffic loss here.")
            self.failed("Traffic Verification failed")
        # else:
        #     self.passed(reason="Skipped TGEN Configurations as per request")

    @aetest.test
    def verify_dynamic_mac_states(self, testscript,testbed):
        node3_s1_bgw_1 = testbed.devices['node3_s1_bgw_1']
        node7_s2_bgw_1 = testbed.devices['node7_s2_bgw_1']
        P3_dict = AcceSW_TGEN_data
        if verify_dynamic_mac(node3_s1_bgw_1,str(P3_dict['mac']),str(P3_dict['vlan_id'])):
            log.info('proper dynaic mac learnt on S1_BGw1')
        else:
            log.info('improper dynamic mac learnt on  S1_BGw1')
            self.failed('improper dynamic mac learnt on  S1_BGw1')

        if verify_dynamic_mac(node7_s2_bgw_1,str(P3_dict['mac']),str(P3_dict['vlan_id'])):
            log.info('proper dynaic mac learnt on  S2_BGw1')
        else:
            log.info('improper dynamic mac learnt on S2_BGw1')
            self.failed('improper dynamic mac learnt on  S2_BGw1')

    @aetest.test
    def Config_Mac_BH_on_Vpc_Vtep(self, testscript,testbed):
        node3_s1_bgw_1 =  testbed.devices['node3_s1_bgw_1']
        node4_s1_bgw_2 = testbed.devices['node4_s1_bgw_2']
        P3_dict = AcceSW_TGEN_data
        mac= str(P3_dict['mac'])
        vlan= str(P3_dict['vlan_id'])
        ip=str(P3_dict['v4_addr'])
        octet = 1
        no_int= int(P3_dict['no_of_ints'])
        
        for i in range (0,no_int):
            ###LEAF_3_MAC_BH_ROUTE
            testbed.devices['node3_s1_bgw_1'].configure('''
                mac address-table static ''' + str(mac) + ''' vlan '''+ str(vlan) + ''' drop

                interface vlan ''' + str(vlan) + '''
                  ip arp ''' + str(ip) + ''' ''' + str(mac) + '''
            ''')
            testbed.devices['node4_s1_bgw_2'].configure('''
                mac address-table static ''' + str(mac) + ''' vlan '''+ str(vlan) + ''' drop

                interface vlan ''' + str(vlan) + '''
                  ip arp ''' + str(ip) + ''' ''' + str(mac) + '''
            ''')
            lasthex=incr_mac(mac)
            mac=mac[0:10]+lasthex
            vlan= int(vlan)+int(P3_dict['vlan_id_step'])
            ip=incr_ip(ip,octet)

            
        # except Exception as error:
        #     log.debug("Unable to configure static BH mac route - Encountered Exception " + str(error))
        #     self.errored('Exception occurred while configuring static BH mac route') 

    @aetest.test
    def APPLY_TRAFFIC(self):
        """ IXIA_CONFIGURATION subsection: Verify IXIA Traffic """

        # Apply IXIA Traffic
        if ixLib.apply_traffic() == 1:
            log.info("Applying IXIA TI Passed")
        else:
            self.errored("Applying IXIA TI failed")
    
    @aetest.test
    def VERIFY_IXIA_TRAFFIC_With_BH_Route(self, testscript):
        """ IXIA_CONFIGURATION subsection: Verify IXIA Traffic """

        # Do not perform configurations if skip_tgen_config flag is set
        #if not testscript.parameters['script_flags']['skip_tgen_config']:

        time.sleep(20)

        if ixLib.verify_traffic(99) == 0:
            log.debug("Traffic Verification Passed.Expecting traffic loss here.") 
        else:
            log.info("Traffic Verification Failed. Expecting traffic loss here.")
            self.failed("Traffic Verification failed")
            
        # else:
        #     self.passed(reason="Skipped TGEN Configurations as per request")
    
    @aetest.test
    def Verify_Traffic_Drop_on_Remote_Vtep(self,testscript,testbed):
        node5_s1_leaf_1 = testbed.devices['node5_s1_leaf_1']
        node7_s2_bgw_1 = testbed.devices['node7_s2_bgw_1']
        node9_s2_leaf_1 = testbed.devices['node9_s2_leaf_1']
        P3_dict = AcceSW_TGEN_data
        uplink_PO=S1_Leaf_dict['S1_Leaf_UPLINK_PO']['po_id']
        if verify_traffic_drop(node5_s1_leaf_1,uplink_PO):
            log.info('Traffic correctly dropped on  S1_Leaf')
        else:
            log.info('Traffic NOT dropped on  S1_Leaf')
            self.failed('Traffic NOT dropped on  S1_Leaf')

        uplink_PO=S2_BGW1_dict['S2_BGW1_UPLINK_PO']['po_id']
        if verify_traffic_drop(node7_s2_bgw_1,uplink_PO):
            log.info('Traffic correctly dropped on  S2_BGW1')
        else:
            log.info('Traffic NOT dropped on  S2_BGW1')
            self.failed('Traffic NOT dropped on  S2_BGW1')
        
        uplink_PO=S2_Leaf_dict['S2_Leaf_UPLINK_PO']['po_id']
        if verify_traffic_drop(node9_s2_leaf_1,uplink_PO):
            log.info('Traffic correctly dropped on  S1_Leaf')
        else:
            log.info('Traffic NOT dropped on  S1_Leaf')
            self.failed('Traffic NOT dropped on  S1_Leaf')


    #verifing BGP, ARP, L2FM, L2RIB, AM, HMM
    @aetest.test
    def Verify_BH_states_in_HMM(self, testscript,testbed):
        node3_s1_bgw_1 =testbed.devices['node3_s1_bgw_1']
        node4_s1_bgw_2 = testbed.devices['node4_s1_bgw_2']
        node7_s2_bgw_1 = testbed.devices['node7_s2_bgw_1']
        P3_dict = AcceSW_TGEN_data

        try:
            if verify_BH_in_HMM(node4_s1_bgw_2,str(P3_dict['v4_addr'])):
                log.info('Mac BH route is proper in HMM on  S1_BGW1')
            else:
                log.info('Mac BH route is improper in HMM on  S1_BGW1')
                self.failed('Mac BH route is improper in HMM on  S1_BGW1')
        
         
        except Exception as error:
            log.debug("Unable to configure static BH mac route on Remote Vtep- Encountered Exception " + str(error))
            self.errored('Exception occurred while configuring static BH mac route on Remote Vtep', goto=['cleanup'])
    @aetest.test
    def Verify_BH_states_in_AM(self, testscript,testbed):
        node3_s1_bgw_1 = testbed.devices['node3_s1_bgw_1']
        node4_s1_bgw_2 = testbed.devices['node4_s1_bgw_2']
        node7_s2_bgw_1 = testbed.devices['node7_s2_bgw_1']
        P1_dict = S1_BGW1_TGEN_data
        P2_dict = S1_Leaf_TGEN_data
        P3_dict = AcceSW_TGEN_data
        P4_dict = S2_Leaf_TGEN_data

        try:        
            if verify_BH_in_AM(node4_s1_bgw_2,str(P3_dict['mac']),str(P3_dict['vlan_id']),str(P3_dict['v4_addr'])):
                log.info('Mac BH route is proper in AM on  S1_BGW1')
            else:
                log.info('Mac BH route is improper in AM on  S1_BGW1')
                self.failed('Mac BH route is improper in AM on  S1_BGW1')
                   
        
        except Exception as error:
            log.debug("Unable to configure static BH mac route on Remote Vtep- Encountered Exception " + str(error))
            self.errored('Exception occurred while configuring static BH mac route on Remote Vtep', goto=['cleanup'])
    @aetest.test
    def Verify_BH_states_in_remote_ARP(self, testscript,testbed):
        node3_s1_bgw_1 =testbed.devices['node3_s1_bgw_1']
        node7_s2_bgw_1 = testbed.devices['node7_s2_bgw_1']
        P3_dict = AcceSW_TGEN_data

        try: 

            if verify_BH_in_Remote_ARP(node7_s2_bgw_1,str(P3_dict['vlan_id']),str(P3_dict['mac'])):
               log.info('Mac BH route is proper in Remote ARP on  S2_BGW1')
            else:
                log.info('Mac BH route is improper in Remote ARP on  S2_BGW1')
                self.failed('Mac BH route is improper in Remote ARP on  S2_BGW1')

        except Exception as error:
            log.debug("Unable to configure static BH mac route on Remote Vtep- Encountered Exception " + str(error))
            self.errored('Exception occurred while configuring static BH mac route on Remote Vtep')        
    @aetest.test
    def Verify_BH_states_in_local_ARP(self, testscript,testbed):
        node3_s1_bgw_1 = testbed.devices['node3_s1_bgw_1']
        node7_s2_bgw_1 = testbed.devices['node7_s2_bgw_1']
        P1_dict = S1_BGW1_TGEN_data
        P2_dict = S1_Leaf_TGEN_data
        P3_dict = AcceSW_TGEN_data
        P4_dict = S2_Leaf_TGEN_data
        try:        
            if verify_BH_in_local_ARP(node3_s1_bgw_1,str(P3_dict['vlan_id']),str(P3_dict['mac'])):
                log.info('Mac BH route is proper in Local ARP on  S1_BGW1')
            else:
                log.info('Mac BH route is improper in Local ARP on  S1_BGW1')
                self.failed('Mac BH route is improper in Local ARP on  S1_BGW1')
        
        except Exception as error:
            log.debug("Unable to configure static BH mac route on Remote Vtep- Encountered Exception " + str(error))
            self.errored('Exception occurred while configuring static BH mac route on Remote Vtep')
    @aetest.test    
    def Verify_Mac_BH_Route_on_L2FM_BGP_L2RIB(self,testscript,testbed):
        node3_s1_bgw_1 = testbed.devices['node3_s1_bgw_1']
        node7_s2_bgw_1 = testbed.devices['node7_s2_bgw_1']
        P3_dict = AcceSW_TGEN_data
        
        # Verifying L2FM

        try:
            ###S1_BGW1_MAC_BH_ROUTE
            if verify_BH_route_in_L2FM(node3_s1_bgw_1,str(P3_dict['vlan_id']),str(P3_dict['mac'])):
                log.info('Mac BH route is proper in L2FM on  S1_BGw1')
            else:
                log.info('Mac BH route is improper in L2FM on  S1_BGw1')
                self.failed('Mac BH route is improper in L2FM on  S1_BGw1')

            ###S2_BGW1_MAC_BH_ROUTE Remote Vtep
            if verify_BH_route_in_L2FM(node7_s2_bgw_1,str(P3_dict['vlan_id']),str(P3_dict['mac'])):
                log.info('Mac BH route is proper in L2FM on  S2_BGw1')
            else:
                log.info('Mac BH route is improper in L2FM on  S2_BGw1')
                self.failed('Mac BH route is improper in L2FM on  S2_BGw1')

        except Exception as error:
            log.debug("Unable to verify BH mac route in L2FM - Encountered Exception " + str(error))
            self.errored('Exception occurred while verifying BH mac route in L2FM')        

        #Verifying L2RIB
        try:
            #S1_Leaf_Mac_BH_route
            if verify_L2rib_mac_ip_output(node3_s1_bgw_1,str(P3_dict['vlan_id']),str(P3_dict['mac'])):
                log.info('Mac BH route is proper in L2RIB on S1_Leaf')
            else:
                log.debug('Mac BH route is improper in L2RIB on  S1_Leaf')
                self.failed('Mac BH route is improper in L2RIB on  S1_Leaf')

            #S2_BGW1_Mac_BH_route
            if verify_L2rib_mac_ip_output(node7_s2_bgw_1,str(P3_dict['vlan_id']),str(P3_dict['mac'])):
                log.info('Mac BH route is proper in L2RIB on S2_BGW1')
            else:
                log.debug('Mac BH route is improper in L2RIB on  S2_BGW1')
                self.errored('Mac BH route is improper in L2RIB on  S2_BGW1')
        
        except Exception as error:
            log.debug("Unable to verify BH mac route in L2RIB - Encountered Exception " + str(error))
            self.errored('Exception occurred while verifying BH mac route in L2RIB')
        
        #Verifying BGP
        try:
            #S2_BGW1_Mac_BH_route
            if verify_BH_in_Remote_BGP(node7_s2_bgw_1,str(P3_dict['mac'])):
                log.info('Mac BH route is proper in BGP on S2_BGW1')
            else:
                log.debug('Mac BH route is improper in BGP on  S2_BGW1')
                self.errored('Mac BH route is improper in BGP on  S2_BGW1')

            #Access_Mac_BH_route
            if verify_BH_in_Remote_BGP(node3_s1_bgw_1,str(P3_dict['mac'])):
                log.info('Mac BH route is proper in BGP on Access')
            else:
                log.debug('Mac BH route is improper in BGP on  Access')
                self.errored('Mac BH route is improper in BGP on  Access')
        
        except Exception as error:
            log.debug("Unable to verify BH mac route in BGP - Encountered Exception " + str(error))
            self.errored('Exception occurred while verifying BH mac route in BGP', )
    
    @aetest.test
    def remove_add_vnsegment(self,testscript,testbed):
        node3_s1_bgw_1 =  testbed.devices['node3_s1_bgw_1']
        node4_s1_bgw_2 =  testbed.devices['node4_s1_bgw_2']
        P3_dict = AcceSW_TGEN_data
        no_int= int(P3_dict['no_of_ints'])
        vlans= S1_BGW1_dict['vlans']
        vn_segment=S1_BGW1_dict['vni']

        for i in range (0,no_int):

            testbed.devices['node3_s1_bgw_1'].configure('''
              vlan ''' + str(vlans) + '''
              no vn-segment ''' + str(vn_segment)
             )
            testbed.devices['node4_s1_bgw_2'].configure('''
              vlan ''' + str(vlans) + '''
              no vn-segment ''' + str(vn_segment)
             )
            vlans=S1_BGW1_dict['vlans'] + S1_BGW1_dict['vlan_step']
            vn_segment= S1_BGW1_dict['vni'] + S1_BGW1_dict['vlan_step']
        time.sleep(10)
        #Add vn_segment_back
        vlans= S1_BGW1_dict['vlans']
        vn_segment=S1_BGW1_dict['vni']

        for i in range (0,no_int):

            testbed.devices['node3_s1_bgw_1'].configure('''
              vlan ''' + str(vlans) + '''
              vn-segment ''' + str(vn_segment)
             )
            testbed.devices['node4_s1_bgw_2'].configure('''
              vlan ''' + str(vlans) + '''
              vn-segment ''' + str(vn_segment)
             )
            vlans=S1_BGW1_dict['vlans'] + S1_BGW1_dict['vlan_step']
            vn_segment= S1_BGW1_dict['vni'] + S1_BGW1_dict['vlan_step']
        time.sleep(30)

    @aetest.test
    def VERIFY_IXIA_TRAFFIC_after_novnseg(self, testscript):
        """ IXIA_CONFIGURATION subsection: Verify IXIA Traffic """

        # Do not perform configurations if skip_tgen_config flag is set
        #if not testscript.parameters['script_flags']['skip_tgen_config']:

        time.sleep(20)

        if ixLib.verify_traffic(99) == 0:
            log.debug("Traffic Verification Passed.") 
        else:
            log.info("Traffic Verification Failed. ")
            self.failed("Traffic Verification failed")

    #verifing BGP, ARP, L2FM, L2RIB, AM, HMM
    @aetest.test
    def Verify_BH_states_in_HMM_after_novnseg(self, testscript,testbed):
        node3_s1_bgw_1 =testbed.devices['node3_s1_bgw_1']
        node4_s1_bgw_2 = testbed.devices['node4_s1_bgw_2']
        node7_s2_bgw_1 = testbed.devices['node7_s2_bgw_1']
        P3_dict = AcceSW_TGEN_data

        try:
            if verify_BH_in_HMM(node4_s1_bgw_2,str(P3_dict['v4_addr'])):
                log.info('Mac BH route is proper in HMM on  S1_BGW1')
            else:
                log.info('Mac BH route is improper in HMM on  S1_BGW1')
                self.failed('Mac BH route is improper in HMM on  S1_BGW1')
        
         
        except Exception as error:
            log.debug("Unable to configure static BH mac route on Remote Vtep- Encountered Exception " + str(error))
            self.errored('Exception occurred while configuring static BH mac route on Remote Vtep', goto=['cleanup'])
    @aetest.test
    def Verify_BH_states_in_AM_after_novnseg(self, testscript,testbed):
        node3_s1_bgw_1 = testbed.devices['node3_s1_bgw_1']
        node4_s1_bgw_2 = testbed.devices['node4_s1_bgw_2']
        node7_s2_bgw_1 = testbed.devices['node7_s2_bgw_1']
        P1_dict = S1_BGW1_TGEN_data
        P2_dict = S1_Leaf_TGEN_data
        P3_dict = AcceSW_TGEN_data
        P4_dict = S2_Leaf_TGEN_data

        try:        
            if verify_BH_in_AM(node4_s1_bgw_2,str(P3_dict['mac']),str(P3_dict['vlan_id']),str(P3_dict['v4_addr'])):
                log.info('Mac BH route is proper in AM on  S1_BGW1')
            else:
                log.info('Mac BH route is improper in AM on  S1_BGW1')
                self.failed('Mac BH route is improper in AM on  S1_BGW1')
                   
        
        except Exception as error:
            log.debug("Unable to configure static BH mac route on Remote Vtep- Encountered Exception " + str(error))
            self.errored('Exception occurred while configuring static BH mac route on Remote Vtep', goto=['cleanup'])
    @aetest.test
    def Verify_BH_states_in_remote_ARP_after_novnseg(self, testscript,testbed):
        node3_s1_bgw_1 =testbed.devices['node3_s1_bgw_1']
        node7_s2_bgw_1 = testbed.devices['node7_s2_bgw_1']
        P3_dict = AcceSW_TGEN_data

        try: 

            if verify_BH_in_Remote_ARP(node7_s2_bgw_1,str(P3_dict['vlan_id']),str(P3_dict['mac'])):
               log.info('Mac BH route is proper in Remote ARP on  S2_BGW1')
            else:
                log.info('Mac BH route is improper in Remote ARP on  S2_BGW1')
                self.failed('Mac BH route is improper in Remote ARP on  S2_BGW1')

        except Exception as error:
            log.debug("Unable to configure static BH mac route on Remote Vtep- Encountered Exception " + str(error))
            self.errored('Exception occurred while configuring static BH mac route on Remote Vtep')        
    @aetest.test
    def Verify_BH_states_in_local_ARP_after_novnseg(self, testscript,testbed):
        node3_s1_bgw_1 = testbed.devices['node3_s1_bgw_1']
        node7_s2_bgw_1 = testbed.devices['node7_s2_bgw_1']
        P1_dict = S1_BGW1_TGEN_data
        P2_dict = S1_Leaf_TGEN_data
        P3_dict = AcceSW_TGEN_data
        P4_dict = S2_Leaf_TGEN_data
        try:        
            if verify_BH_in_local_ARP(node3_s1_bgw_1,str(P3_dict['vlan_id']),str(P3_dict['mac'])):
                log.info('Mac BH route is proper in Local ARP on  S1_BGW1')
            else:
                log.info('Mac BH route is improper in Local ARP on  S1_BGW1')
                self.failed('Mac BH route is improper in Local ARP on  S1_BGW1')
        
        except Exception as error:
            log.debug("Unable to configure static BH mac route on Remote Vtep- Encountered Exception " + str(error))
            self.errored('Exception occurred while configuring static BH mac route on Remote Vtep')
    @aetest.test   
    def Verify_Mac_BH_Route_on_L2FM_BGP_L2RIB_after_novnseg(self,testscript,testbed):
        node3_s1_bgw_1 = testbed.devices['node3_s1_bgw_1']
        node7_s2_bgw_1 = testbed.devices['node7_s2_bgw_1']
        P3_dict = AcceSW_TGEN_data
        
        # Verifying L2FM

        try:
            ###S1_BGW1_MAC_BH_ROUTE
            if verify_BH_route_in_L2FM(node3_s1_bgw_1,str(P3_dict['vlan_id']),str(P3_dict['mac'])):
                log.info('Mac BH route is proper in L2FM on  S1_BGw1')
            else:
                log.info('Mac BH route is improper in L2FM on  S1_BGw1')
                self.failed('Mac BH route is improper in L2FM on  S1_BGw1')

            ###S2_BGW1_MAC_BH_ROUTE Remote Vtep
            if verify_BH_route_in_L2FM(node7_s2_bgw_1,str(P3_dict['vlan_id']),str(P3_dict['mac'])):
                log.info('Mac BH route is proper in L2FM on  S2_BGw1')
            else:
                log.info('Mac BH route is improper in L2FM on  S2_BGw1')
                self.failed('Mac BH route is improper in L2FM on  S2_BGw1')

        except Exception as error:
            log.debug("Unable to verify BH mac route in L2FM - Encountered Exception " + str(error))
            self.errored('Exception occurred while verifying BH mac route in L2FM')        

        #Verifying L2RIB
        try:
            #S1_Leaf_Mac_BH_route
            if verify_L2rib_mac_ip_output(node3_s1_bgw_1,str(P3_dict['vlan_id']),str(P3_dict['mac'])):
                log.info('Mac BH route is proper in L2RIB on S1_Leaf')
            else:
                log.debug('Mac BH route is improper in L2RIB on  S1_Leaf')
                self.failed('Mac BH route is improper in L2RIB on  S1_Leaf')

            #S2_BGW1_Mac_BH_route
            if verify_L2rib_mac_ip_output(node7_s2_bgw_1,str(P3_dict['vlan_id']),str(P3_dict['mac'])):
                log.info('Mac BH route is proper in L2RIB on S2_BGW1')
            else:
                log.debug('Mac BH route is improper in L2RIB on  S2_BGW1')
                self.errored('Mac BH route is improper in L2RIB on  S2_BGW1')
        
        except Exception as error:
            log.debug("Unable to verify BH mac route in L2RIB - Encountered Exception " + str(error))
            self.errored('Exception occurred while verifying BH mac route in L2RIB')
        
        #Verifying BGP
        try:
            #S2_BGW1_Mac_BH_route
            if verify_BH_in_Remote_BGP(node7_s2_bgw_1,str(P3_dict['mac'])):
                log.info('Mac BH route is proper in BGP on S2_BGW1')
            else:
                log.debug('Mac BH route is improper in BGP on  S2_BGW1')
                self.errored('Mac BH route is improper in BGP on  S2_BGW1')

            #Access_Mac_BH_route
            if verify_BH_in_Remote_BGP(node3_s1_bgw_1,str(P3_dict['mac'])):
                log.info('Mac BH route is proper in BGP on Access')
            else:
                log.debug('Mac BH route is improper in BGP on  Access')
                self.errored('Mac BH route is improper in BGP on  Access')
        
        except Exception as error:
            log.debug("Unable to verify BH mac route in BGP - Encountered Exception " + str(error))
            self.errored('Exception occurred while verifying BH mac route in BGP', )

    @aetest.test
    def unConfig_Mac_BH_on_Vpc_Vtep(self, testscript,testbed):

        node3_s1_bgw_1 =  testbed.devices['node3_s1_bgw_1']
        P3_dict = AcceSW_TGEN_data
        mac= str(P3_dict['mac'])
        vlan= str(P3_dict['vlan_id'])
        ip=str(P3_dict['v4_addr'])
        octet = 1
        no_int= int(P3_dict['no_of_ints'])
        
        for i in range (0,no_int):
            ###LEAF_3_MAC_BH_ROUTE
            testbed.devices['node3_s1_bgw_1'].configure('''
                no mac address-table static ''' + str(mac) + ''' vlan '''+ str(vlan) + ''' drop

                interface vlan ''' + str(vlan) + '''
                  no ip arp ''' + str(ip) + ''' ''' + str(mac) + '''
            ''')
            testbed.devices['node4_s1_bgw_2'].configure('''
                no mac address-table static ''' + str(mac) + ''' vlan '''+ str(vlan) + ''' drop

                interface vlan ''' + str(vlan) + '''
                  no ip arp ''' + str(ip) + ''' ''' + str(mac) + '''
            ''')
            lasthex=incr_mac(mac)
            mac=mac[0:10]+lasthex
            vlan= int(vlan)+int(P3_dict['vlan_id_step'])
            ip=incr_ip(ip,octet)
 

    @aetest.test
    def VERIFY_IXIA_TRAFFIC_after_rmBH_Route(self, testscript):
        """ IXIA_CONFIGURATION subsection: Verify IXIA Traffic """

        # Do not perform configurations if skip_tgen_config flag is set
        #if not testscript.parameters['script_flags']['skip_tgen_config']:

        time.sleep(20)

        if ixLib.verify_traffic(1) == 1:
            log.debug("Traffic Verification Passed.") 
        else:
            log.info("Traffic Verification Failed. ")
            self.failed("Traffic Verification failed")
        # else:
    
    @aetest.test
    def cleanup(self,testscript, testbed):
        """Unconfigure qos policies"""
        node3_s1_bgw_1 =  testbed.devices['node3_s1_bgw_1']
        node5_s1_leaf_1 =  testbed.devices['node5_s1_leaf_1']
        node10_s1_AccessSW =  testbed.devices['node10_s1_AccessSW']
        node7_s2_bgw_1 =  testbed.devices['node7_s2_bgw_1']
        P3_dict = AcceSW_TGEN_data
        forwardingSysDict = FWD_SYS_dict
        # Stop Traffic from ixia
        log.info("--- Stopping Traffic ---- \n")
        log.info("Stopping Traffic")
        traffic_run_status = ixLib.stop_traffic()
        
        if traffic_run_status is not 1:
            log.info("Failed: To Stop traffic")
            return 0
        else:
            log.info("\nTraffic Stopped successfully\n")
        time.sleep(10)
        ####Remove traffic item configured
        # UCAST_v4_dict_1 = {
        #                 'mode'        : 'remove',
        #                 'stream_id'   : stream_id,
        #             }
        # if (ixLib.delete_traffic_item(UCAST_v4_dict_1))==0:
        #     log.debug("Traffic Remove failed")
        #     self.failed("Traffic Remove failed", goto=['next_tc'])
        # else:
        #     log.info("Traffic Remove Passed")
        UCAST_v4_dict_2 = {
                        'mode'        : 'remove',
                        'stream_id'   : stream_id_1,
                    }
        if (ixLib.delete_traffic_item(UCAST_v4_dict_2))==0:
            log.debug("Traffic Remove failed")
            self.failed("Traffic Remove failed", goto=['next_tc'])
        else:
            log.info("Traffic Remove Passed")
        UCAST_v4_dict_3 = {
                        'mode'        : 'remove',
                        'stream_id'   : stream_id_2,
                    }
        if (ixLib.delete_traffic_item(UCAST_v4_dict_3))==0:
            log.debug("Traffic Remove failed")
            self.failed("Traffic Remove failed", goto=['next_tc'])
        else:
            log.info("Traffic Remove Passed")
        ###LEAF_1_MAC_BH_ROUTE
    

class Mac_BH_route_static_ARP_on_standalonevtep(nxtest.Testcase):
    #"""TC_0029_Mac_BH_route_static_ARP_on_standalonevtep"""
    stream_id=''
    @aetest.test
    def CONFIGURE_L2_UCAST_IXIA_TRAFFIC_H2_to_H1(self, testscript):
        """ IXIA_CONFIGURATION subsection: Configure MCAST Traffic Item """

        # Do not perform configurations if skip_tgen_config flag is set
        #if not testscript.parameters['script_flags']['skip_tgen_config']:

        IX_TP1 = testscript.parameters['IX_TP1']
        IX_TP2 = testscript.parameters['IX_TP2']
        IX_TP3 = testscript.parameters['IX_TP3']
        P1_dict = S1_BGW1_TGEN_data
        P2_dict = S1_Leaf_TGEN_data
        P3_dict = AcceSW_TGEN_data
        P4_dict = S2_Leaf_TGEN_data
        # P1_dict = S1_BGW1_TGEN_data
        # P4_dict = testscript.parameters['S2_BGW1_TGEN_dict']

        UCAST_v4_dict_1 = {   'src_hndl'  : IX_TP1['ipv4_handle'],
                            'dst_hndl'  : IX_TP3['ipv4_handle'],
                            'circuit'   : 'ipv4',
                            'TI_name'   : "UCAST_V4",
                            'rate_pps'  : "10000",
                            'bi_dir'    : 1,
                            'bidirectional': '0'
                        }

        UCAST_v4_TI = ixLib.configure_ixia_traffic_item_v46(UCAST_v4_dict_1)
            
        if UCAST_v4_TI == 0:
            log.debug("Configuring UCast L2 TI failed")
            self.errored("Configuring UCast L2 TI failed", goto=['next_tc'])
        else:
            global stream_id
            stream_id = UCAST_v4_TI
        # else:
        #     self.passed(reason="Skipped TGEN Configurations as per request")
    stream_id_1=''
    @aetest.test
    def CONFIGURE_L2_UCAST_IXIA_TRAFFIC_H3_to_H1(self, testscript):
        """ IXIA_CONFIGURATION subsection: Configure MCAST Traffic Item """

        # Do not perform configurations if skip_tgen_config flag is set
        #if not testscript.parameters['script_flags']['skip_tgen_config']:

        IX_TP1 = testscript.parameters['IX_TP1']
        IX_TP2 = testscript.parameters['IX_TP2']
        IX_TP3 = testscript.parameters['IX_TP3']
        P1_dict = S1_BGW1_TGEN_data
        P2_dict = S1_Leaf_TGEN_data
        P3_dict = AcceSW_TGEN_data
        P4_dict = S2_Leaf_TGEN_data
        # P1_dict = S1_BGW1_TGEN_data
        # P4_dict = testscript.parameters['S2_BGW1_TGEN_dict']

        UCAST_v4_dict_2 = {   'src_hndl'  : IX_TP2['ipv4_handle'],
                            'dst_hndl'  : IX_TP3['ipv4_handle'],
                            'circuit'   : 'ipv4',
                            'TI_name'   : "UCAST_V4",
                            'rate_pps'  : "10000",
                            'bi_dir'    : 1,
                            'bidirectional': '0'
                        }

        UCAST_v4_TI_1 = ixLib.configure_ixia_traffic_item_v46(UCAST_v4_dict_2)
            
        if UCAST_v4_TI_1 == 0:
            log.debug("Configuring UCast L2 TI failed")
            self.errored("Configuring UCast L2 TI failed", goto=['next_tc'])
        else:
            global stream_id_1
            stream_id_1 = UCAST_v4_TI_1
        # else:
        #     self.passed(reason="Skipped TGEN Configurations as per request")
    stream_id_2=''
    @aetest.test
    def CONFIGURE_L2_UCAST_IXIA_TRAFFIC_H4_to_H1(self, testscript):
        """ IXIA_CONFIGURATION subsection: Configure MCAST Traffic Item """

        # Do not perform configurations if skip_tgen_config flag is set
        #if not testscript.parameters['script_flags']['skip_tgen_config']:

        IX_TP1 = testscript.parameters['IX_TP1']
        IX_TP2 = testscript.parameters['IX_TP2']
        IX_TP3 = testscript.parameters['IX_TP3']
        IX_TP4 = testscript.parameters['IX_TP4']
        P1_dict = S1_BGW1_TGEN_data
        P2_dict = S1_Leaf_TGEN_data
        P3_dict = AcceSW_TGEN_data
        P4_dict = S2_Leaf_TGEN_data
        # P1_dict = S1_BGW1_TGEN_data
        # P4_dict = testscript.parameters['S2_BGW1_TGEN_dict']

        UCAST_v4_dict_3 = {   'src_hndl'  : IX_TP4['ipv4_handle'],
                            'dst_hndl'  : IX_TP3['ipv4_handle'],
                            'circuit'   : 'ipv4',
                            'TI_name'   : "UCAST_V4",
                            'rate_pps'  : "10000",
                            'bi_dir'    : 1,
                            'bidirectional': '0'
                        }

        UCAST_v4_TI_2 = ixLib.configure_ixia_traffic_item_v46(UCAST_v4_dict_3)
            
        if UCAST_v4_TI_2 == 0:
            log.debug("Configuring UCast L2 TI failed")
            self.errored("Configuring UCast L2 TI failed", goto=['next_tc'])
        else:
            global stream_id_2
            stream_id_2 = UCAST_v4_TI_2
        # else:
        #     self.passed(reason="Skipped TGEN Configurations as per request")

    @aetest.test
    def APPLY_TRAFFIC(self):
        """ IXIA_CONFIGURATION subsection: Verify IXIA Traffic """

        # Apply IXIA Traffic
        if ixLib.apply_traffic() == 1:
            log.info("Applying IXIA TI Passed")
        else:
            self.errored("Applying IXIA TI failed")
    
    @aetest.test
    def VERIFY_IXIA_TRAFFIC_Without_BH_Route(self, testscript):
        """ IXIA_CONFIGURATION subsection: Verify IXIA Traffic """

        # Do not perform configurations if skip_tgen_config flag is set
        #if not testscript.parameters['script_flags']['skip_tgen_config']:

        time.sleep(20)

        if ixLib.verify_traffic(1) == 1:
            log.debug("Traffic Verification Passed.") 
        else:
            log.info("Traffic Verification Failed")
            self.failed("Traffic Verification failed")
        # else:
        #     self.passed(reason="Skipped TGEN Configurations as per request")
    
    @aetest.test
    def Config_BH_route_static_arp_on_remotevtep(self, testscript,testbed):
        node7_s2_bgw_1 = testbed.devices['node7_s2_bgw_1']
        P3_dict = AcceSW_TGEN_data
        mac= str(P3_dict['mac'])
        vlan= str(P3_dict['vlan_id'])
        ip=str(P3_dict['v4_addr'])
        octet = 1
        no_int= int(P3_dict['no_of_ints'])
        
        for i in range (0,no_int):
            ###LEAF_3_MAC_BH_ROUTE
            testbed.devices['node7_s2_bgw_1'].configure('''
                mac address-table static ''' + str(mac) + ''' vlan '''+ str(vlan) + ''' drop

                interface vlan ''' + str(vlan) + '''
                  ip arp ''' + str(ip) + ''' ''' + str(mac) + '''
            ''')
            lasthex=incr_mac(mac)
            mac=mac[0:10]+lasthex
            vlan= int(vlan)+int(P3_dict['vlan_id_step'])
            ip=incr_ip(ip,octet)

            
        # except Exception as error:
        #     log.debug("Unable to configure static BH mac route - Encountered Exception " + str(error))
        #     self.errored('Exception occurred while configuring static BH mac route') 

    @aetest.test
    def APPLY_TRAFFIC(self):
        """ IXIA_CONFIGURATION subsection: Verify IXIA Traffic """

        # Apply IXIA Traffic
        if ixLib.apply_traffic() == 1:
            log.info("Applying IXIA TI Passed")
        else:
            self.errored("Applying IXIA TI failed", goto=['next_tc'])

     
    @aetest.test
    def VERIFY_IXIA_TRAFFIC_With_BH_Route(self, testscript):
        """ IXIA_CONFIGURATION subsection: Verify IXIA Traffic """

        # Do not perform configurations if skip_tgen_config flag is set
        #if not testscript.parameters['script_flags']['skip_tgen_config']:

        time.sleep(20)

        if ixLib.verify_traffic(99) == 0:
            log.debug("Traffic Verification Passed.Expecting traffic loss here.") 
        else:
            log.info("Traffic Verification Failed. Expecting traffic loss here.")
            self.failed("Traffic Verification failed")
        # else:
        #     self.passed(reason="Skipped TGEN Configurations as per request")
    
    @aetest.test
    def Verify_Traffic_Drop_on_Remote_Vtep(self,testscript,testbed):
        node5_s1_leaf_1 = testbed.devices['node5_s1_leaf_1']
        node3_s1_bgw_1 = testbed.devices['node3_s1_bgw_1']
        node9_s2_leaf_1 = testbed.devices['node9_s2_leaf_1']
        P3_dict = AcceSW_TGEN_data
        uplink_PO=S1_Leaf_dict['S1_Leaf_UPLINK_PO']['po_id']
        if verify_traffic_drop(node5_s1_leaf_1,uplink_PO):
            log.info('Traffic correctly dropped on  S1_Leaf')
        else:
            log.info('Traffic NOT dropped on  S1_Leaf')
            self.failed('Traffic NOT dropped on  S1_Leaf')

        uplink_PO=S1_BGW1_dict['S1_BGW1_UPLINK_PO']['po_id']
        if verify_traffic_drop(node3_s1_bgw_1,uplink_PO):
            log.info('Traffic correctly dropped on  S1_BGW1')
        else:
            log.info('Traffic NOT dropped on  S1_BGW1')
            self.failed('Traffic NOT dropped on  S1_BGW1')
        
        uplink_PO=S2_Leaf_dict['S2_Leaf_UPLINK_PO']['po_id']
        if verify_traffic_drop(node9_s2_leaf_1,uplink_PO):
            log.info('Traffic correctly dropped on  S2_Leaf')
        else:
            log.info('Traffic NOT dropped on  S2_Leaf')
            self.failed('Traffic NOT dropped on  S2_Leaf')
    
    @aetest.test
    def Verify_BH_states_in_HMM(self, testscript,testbed):
        node3_s1_bgw_1 = testbed.devices['node3_s1_bgw_1']
        node7_s2_bgw_1 = testbed.devices['node7_s2_bgw_1']
        P3_dict = AcceSW_TGEN_data

        try:
            if verify_BH_in_HMM(node7_s2_bgw_1,str(P3_dict['v4_addr'])):
                log.info('Mac BH route is proper in HMM on  S1_BGW1')
            else:
                log.info('Mac BH route is improper in HMM on  S1_BGW1')
                self.failed('Mac BH route is improper in HMM on  S1_BGW1')
        
         
        except Exception as error:
            log.debug("Unable to configure static BH mac route on Remote Vtep- Encountered Exception " + str(error))
            self.errored('Exception occurred while configuring static BH mac route on Remote Vtep')
    @aetest.test
    def Verify_BH_states_in_AM(self, testscript,testbed):
        node3_s1_bgw_1 = testbed.devices['node3_s1_bgw_1']
        node7_s2_bgw_1 = testbed.devices['node7_s2_bgw_1']
        P3_dict = AcceSW_TGEN_data

        try:        
            if verify_BH_in_AM(node7_s2_bgw_1,str(P3_dict['mac']),str(P3_dict['vlan_id']),str(P3_dict['v4_addr'])):
                log.info('Mac BH route is proper in AM on  S1_BGW1')
            else:
                log.info('Mac BH route is improper in AM on  S1_BGW1')
                self.failed('Mac BH route is improper in AM on  S1_BGW1')
        
        except Exception as error:
            log.debug("Unable to configure static BH mac route on Remote Vtep- Encountered Exception " + str(error))
            self.errored('Exception occurred while configuring static BH mac route on Remote Vtep')
    @aetest.test 
    def Verify_BH_states_in_remote_ARP(self, testscript, testbed):
        node3_s1_bgw_1 =  testbed.devices['node3_s1_bgw_1']
        node7_s2_bgw_1 = testbed.devices['node7_s2_bgw_1']
        P3_dict = AcceSW_TGEN_data

        try: 

            if verify_BH_in_Remote_ARP(node3_s1_bgw_1,str(P3_dict['vlan_id']),str(P3_dict['mac'])):
               log.info('Mac BH route is proper in Remote ARP on  S2_BGW1')
            else:
                log.info('Mac BH route is improper in Remote ARP on  S2_BGW1')
                self.failed('Mac BH route is improper in Remote ARP on  S2_BGW1')

        except Exception as error:
            log.debug("Unable to configure static BH mac route on Remote Vtep- Encountered Exception " + str(error))
            self.errored('Exception occurred while configuring static BH mac route on Remote Vtep')        
    
    def Verify_BH_states_in_local_ARP(self, testscript, testbed):
        node3_s1_bgw_1 =  testbed.devices['node3_s1_bgw_1']
        node7_s2_bgw_1 =  testbed.devices['node7_s2_bgw_1']
        P3_dict = AcceSW_TGEN_data

        try:        
            if verify_BH_in_local_ARP(node7_s2_bgw_1,str(P3_dict['vlan_id']),str(P3_dict['mac'])):
                log.info('Mac BH route is proper in Local ARP on  S1_BGW1')
            else:
                log.info('Mac BH route is improper in Local ARP on  S1_BGW1')
                self.failed('Mac BH route is improper in Local ARP on  S1_BGW1')
        
        except Exception as error:
            log.debug("Unable to configure static BH mac route on Remote Vtep- Encountered Exception " + str(error))
            self.errored('Exception occurred while configuring static BH mac route on Remote Vtep')
        
    def Verify_Mac_BH_Route_on_L2FM_BGP_L2RIB(self,testscript,testbed):
        node3_s1_bgw_1 =testbed.devices['node3_s1_bgw_1']
        node7_s2_bgw_1 = testbed.devices['node7_s2_bgw_1']
        P3_dict = AcceSW_TGEN_data
        
        # Verifying L2FM

        try:
            ###S1_BGW1_MAC_BH_ROUTE
            if verify_BH_route_in_L2FM(node3_s1_bgw_1,str(P3_dict['vlan_id']),str(P3_dict['mac'])):
                log.info('Mac BH route is proper in L2FM on  S1_BGw1')
            else:
                log.info('Mac BH route is improper in L2FM on  S1_BGw1')
                self.failed('Mac BH route is improper in L2FM on  S1_BGw1')

            ###S2_BGW1_MAC_BH_ROUTE Remote Vtep
            if verify_BH_route_in_L2FM(node7_s2_bgw_1,str(P3_dict['vlan_id']),str(P3_dict['mac'])):
                log.info('Mac BH route is proper in L2FM on  S2_BGw1')
            else:
                log.info('Mac BH route is improper in L2FM on  S2_BGw1')
                self.failed('Mac BH route is improper in L2FM on  S2_BGw1')

        except Exception as error:
            log.debug("Unable to verify BH mac route in L2FM - Encountered Exception " + str(error))
            self.errored('Exception occurred while verifying BH mac route in L2FM')        

        #Verifying L2RIB
        try:
            #S1_Leaf_Mac_BH_route
            if verify_L2rib_mac_ip_output(node3_s1_bgw_1,str(P3_dict['vlan_id']),str(P3_dict['mac'])):
                log.info('Mac BH route is proper in L2RIB on S1_Leaf')
            else:
                log.debug('Mac BH route is improper in L2RIB on  S1_Leaf')
                self.failed('Mac BH route is improper in L2RIB on  S1_Leaf')

            #S2_BGW1_Mac_BH_route
            if verify_L2rib_mac_ip_output(node7_s2_bgw_1,str(P3_dict['vlan_id']),str(P3_dict['mac'])):
                log.info('Mac BH route is proper in L2RIB on S2_BGW1')
            else:
                log.debug('Mac BH route is improper in L2RIB on  S2_BGW1')
                self.errored('Mac BH route is improper in L2RIB on  S2_BGW1')
        
        except Exception as error:
            log.debug("Unable to verify BH mac route in L2RIB - Encountered Exception " + str(error))
            self.errored('Exception occurred while verifying BH mac route in L2RIB')
        
        #Verifying BGP
        try:
            #S2_BGW1_Mac_BH_route
            if verify_BH_in_Remote_BGP(node7_s2_bgw_1,str(P3_dict['mac'])):
                log.info('Mac BH route is proper in BGP on S2_BGW1')
            else:
                log.debug('Mac BH route is improper in BGP on  S2_BGW1')
                self.errored('Mac BH route is improper in BGP on  S2_BGW1')

            #Access_Mac_BH_route
            if verify_BH_in_Remote_BGP(node3_s1_bgw_1,str(P3_dict['mac'])):
                log.info('Mac BH route is proper in BGP on Access')
            else:
                log.debug('Mac BH route is improper in BGP on  Access')
                self.errored('Mac BH route is improper in BGP on  Access')
        
        except Exception as error:
            log.debug("Unable to verify BH mac route in BGP - Encountered Exception " + str(error))
            self.errored('Exception occurred while verifying BH mac route in BGP')

    @aetest.test
    def unConfig_BH_route_static_arp_on_remotevtep(self, testscript,testbed):
        node7_s2_bgw_1 = testbed.devices['node7_s2_bgw_1']
        P3_dict = AcceSW_TGEN_data
        mac= str(P3_dict['mac'])
        vlan= str(P3_dict['vlan_id'])
        ip=str(P3_dict['v4_addr'])
        octet = 1
        no_int= int(P3_dict['no_of_ints'])
        
        for i in range (0,no_int):
            ###LEAF_3_MAC_BH_ROUTE
            testbed.devices['node7_s2_bgw_1'].configure('''
                no mac address-table static ''' + str(mac) + ''' vlan '''+ str(vlan) + ''' drop

                interface vlan ''' + str(vlan) + '''
                  no ip arp ''' + str(ip) + ''' ''' + str(mac) + '''
            ''')
            lasthex=incr_mac(mac)
            mac=mac[0:10]+lasthex
            vlan= int(vlan)+int(P3_dict['vlan_id_step'])
            ip=incr_ip(ip,octet)


            
        # except Exception as error:
        #     log.debug("Unable to configure static BH mac route - Encountered Exception " + str(error))
        #     self.errored('Exception occurred while configuring static BH mac route') 

    @aetest.test
    def VERIFY_IXIA_TRAFFIC_after_rmBH_Route(self, testscript):
        """ IXIA_CONFIGURATION subsection: Verify IXIA Traffic """

        # Do not perform configurations if skip_tgen_config flag is set
        #if not testscript.parameters['script_flags']['skip_tgen_config']:

        time.sleep(20)

        if ixLib.verify_traffic(1) == 1:
            log.debug("Traffic Verification Passed.Expecting traffic loss here.") 
        else:
            log.info("Traffic Verification Failed. Expecting traffic loss here.")
            self.failed("Traffic Verification failed")
        # else:
        #     self.passed(reason="Skipped TGEN Configurations as per request")
    
    @aetest.test
    def cleanup(self,testscript,testbed):
        """Unconfigure qos policies"""
        node3_s1_bgw_1 = testbed.devices['node3_s1_bgw_1']
        node5_s1_leaf_1 = testbed.devices['node5_s1_leaf_1']
        node10_s1_AccessSW = testbed.devices['node10_s1_AccessSW']
        node7_s2_bgw_1 =testbed.devices['node7_s2_bgw_1']
        P3_dict = AcceSW_TGEN_data
        forwardingSysDict = FWD_SYS_dict
      
        # Stop Traffic from ixia
        log.info("--- Stopping Traffic ---- \n")
        log.info("Stopping Traffic")
        traffic_run_status = ixLib.stop_traffic()
        
        if traffic_run_status is not 1:
            log.info("Failed: To Stop traffic")
            return 0
        else:
            log.info("\nTraffic Stopped successfully\n")
        time.sleep(10)
        ####Remove traffic item configured
        UCAST_v4_dict_1 = {
                        'mode'        : 'remove',
                        'stream_id'   : stream_id,
                    }
        if (ixLib.delete_traffic_item(UCAST_v4_dict_1))==0:
            log.debug("Traffic Remove failed")
            self.failed("Traffic Remove failed", goto=['next_tc'])
        else:
            log.info("Traffic Remove Passed")
        UCAST_v4_dict_2 = {
                        'mode'        : 'remove',
                        'stream_id'   : stream_id_1,
                    }
        if (ixLib.delete_traffic_item(UCAST_v4_dict_2))==0:
            log.debug("Traffic Remove failed")
            self.failed("Traffic Remove failed", goto=['next_tc'])
        else:
            log.info("Traffic Remove Passed")
        UCAST_v4_dict_3 = {
                        'mode'        : 'remove',
                        'stream_id'   : stream_id_2,
                    }
        if (ixLib.delete_traffic_item(UCAST_v4_dict_3))==0:
            log.debug("Traffic Remove failed")
            self.failed("Traffic Remove failed", goto=['next_tc'])
        else:
            log.info("Traffic Remove Passed")
        ###LEAF_1_MAC_BH_ROUTE
        testbed.devices['node7_s2_bgw_1'].configure('''
        
            no mac address-table static ''' + str(P3_dict['mac']) + ''' vlan '''+ str(P3_dict['vlan_id']) + ''' drop

            interface vlan ''' + str(P3_dict['vlan_id']) + '''
                no ip arp ''' + str(P3_dict['v4_addr']) + ''' ''' + str(P3_dict['mac']) + '''
        ''')
    
class MAC_BH_route_on_vpc_vtep_start_traffic(nxtest.Testcase):
     #"""TC_0031_MAC_BH_route_on_vpc_vtep_start_traffic"""
    stream_id=''
    @aetest.test
    def CONFIGURE_L2_UCAST_IXIA_TRAFFIC_H2_to_H1(self, testscript):
        """ IXIA_CONFIGURATION subsection: Configure MCAST Traffic Item """

        # Do not perform configurations if skip_tgen_config flag is set
        #if not testscript.parameters['script_flags']['skip_tgen_config']:

        IX_TP1 = testscript.parameters['IX_TP1']
        IX_TP2 = testscript.parameters['IX_TP2']
        IX_TP3 = testscript.parameters['IX_TP3']
        P1_dict = S1_BGW1_TGEN_data
        P2_dict = S1_Leaf_TGEN_data
        P3_dict = AcceSW_TGEN_data
        P4_dict = S2_Leaf_TGEN_data
        # P1_dict = S1_BGW1_TGEN_data
        # P4_dict = testscript.parameters['S2_BGW1_TGEN_dict']

        UCAST_v4_dict_1 = {   'src_hndl'  : IX_TP1['ipv4_handle'],
                            'dst_hndl'  : IX_TP3['ipv4_handle'],
                            'circuit'   : 'ipv4',
                            'TI_name'   : "UCAST_V4",
                            'rate_pps'  : "10000",
                            'bi_dir'    : 1,
                            'bidirectional': '0'
                        }

        UCAST_v4_TI = ixLib.configure_ixia_traffic_item_v46(UCAST_v4_dict_1)
            
        if UCAST_v4_TI == 0:
            log.debug("Configuring UCast L2 TI failed")
            self.errored("Configuring UCast L2 TI failed", goto=['next_tc'])
        else:
            global stream_id
            stream_id = UCAST_v4_TI
        # else:
        #     self.passed(reason="Skipped TGEN Configurations as per request")
    stream_id_1=''
    @aetest.test
    def CONFIGURE_L2_UCAST_IXIA_TRAFFIC_H3_to_H1(self, testscript):
        """ IXIA_CONFIGURATION subsection: Configure MCAST Traffic Item """

        # Do not perform configurations if skip_tgen_config flag is set
        #if not testscript.parameters['script_flags']['skip_tgen_config']:

        IX_TP1 = testscript.parameters['IX_TP1']
        IX_TP2 = testscript.parameters['IX_TP2']
        IX_TP3 = testscript.parameters['IX_TP3']
        P1_dict = S1_BGW1_TGEN_data
        P2_dict = S1_Leaf_TGEN_data
        P3_dict = AcceSW_TGEN_data
        P4_dict = S2_Leaf_TGEN_data
        # P1_dict = S1_BGW1_TGEN_data
        # P4_dict = testscript.parameters['S2_BGW1_TGEN_dict']

        UCAST_v4_dict_2 = {   'src_hndl'  : IX_TP2['ipv4_handle'],
                            'dst_hndl'  : IX_TP3['ipv4_handle'],
                            'circuit'   : 'ipv4',
                            'TI_name'   : "UCAST_V4",
                            'rate_pps'  : "10000",
                            'bi_dir'    : 1,
                            'bidirectional': '0'
                        }

        UCAST_v4_TI_1 = ixLib.configure_ixia_traffic_item_v46(UCAST_v4_dict_2)
            
        if UCAST_v4_TI_1 == 0:
            log.debug("Configuring UCast L2 TI failed")
            self.errored("Configuring UCast L2 TI failed", goto=['next_tc'])
        else:
            global stream_id_1
            stream_id_1 = UCAST_v4_TI_1
        # else:
        #     self.passed(reason="Skipped TGEN Configurations as per request")
    stream_id_2=''
    @aetest.test
    def CONFIGURE_L2_UCAST_IXIA_TRAFFIC_H4_to_H1(self, testscript):
        """ IXIA_CONFIGURATION subsection: Configure MCAST Traffic Item """

        # Do not perform configurations if skip_tgen_config flag is set
        #if not testscript.parameters['script_flags']['skip_tgen_config']:

        IX_TP1 = testscript.parameters['IX_TP1']
        IX_TP2 = testscript.parameters['IX_TP2']
        IX_TP3 = testscript.parameters['IX_TP3']
        IX_TP4 = testscript.parameters['IX_TP4']
        P1_dict = S1_BGW1_TGEN_data
        P2_dict = S1_Leaf_TGEN_data
        P3_dict = AcceSW_TGEN_data
        P4_dict = S2_Leaf_TGEN_data
        # P1_dict = S1_BGW1_TGEN_data
        # P4_dict = testscript.parameters['S2_BGW1_TGEN_dict']

        UCAST_v4_dict_3 = {   'src_hndl'  : IX_TP4['ipv4_handle'],
                            'dst_hndl'  : IX_TP3['ipv4_handle'],
                            'circuit'   : 'ipv4',
                            'TI_name'   : "UCAST_V4",
                            'rate_pps'  : "10000",
                            'bi_dir'    : 1,
                            'bidirectional': '0'
                        }

        UCAST_v4_TI_2 = ixLib.configure_ixia_traffic_item_v46(UCAST_v4_dict_3)
            
        if UCAST_v4_TI_2 == 0:
            log.debug("Configuring UCast L2 TI failed")
            self.errored("Configuring UCast L2 TI failed", goto=['next_tc'])
        else:
            global stream_id_2
            stream_id_2 = UCAST_v4_TI_2
        # else:
        #     self.passed(reason="Skipped TGEN Configurations as per request

    @aetest.test
    def APPLY_TRAFFIC(self):
        """ IXIA_CONFIGURATION subsection: Verify IXIA Traffic """

        # Apply IXIA Traffic
        if ixLib.apply_traffic() == 1:
            log.info("Applying IXIA TI Passed")
        else:
            self.errored("Applying IXIA TI failed")
    
    @aetest.test
    def VERIFY_IXIA_TRAFFIC_Without_BH_Route(self, testscript):
        """ IXIA_CONFIGURATION subsection: Verify IXIA Traffic """

        # Do not perform configurations if skip_tgen_config flag is set
        #if not testscript.parameters['script_flags']['skip_tgen_config']:

        time.sleep(20)

        if ixLib.verify_traffic(1) == 1:
            log.debug("Traffic Verification Passed.Expecting traffic loss here.") 
        else:
            log.info("Traffic Verification Failed. Expecting traffic loss here.")
            self.failed("Traffic Verification failed")
        # else:
        #     self.passed(reason="Skipped TGEN Configurations as per request")
    
    @aetest.test
    def Config_MAC_BH_route_on_vpc_vtep_start_traffic(self, testscript,testbed):
        node3_s1_bgw_1 = testbed.devices['node3_s1_bgw_1']
        P3_dict = AcceSW_TGEN_data
        mac= str(P3_dict['mac'])
        vlan= str(P3_dict['vlan_id'])
        ip=str(P3_dict['v4_addr'])
        octet = 1
        no_int= int(P3_dict['no_of_ints'])
        
        for i in range (0,no_int):
            ###LEAF_3_MAC_BH_ROUTE
            testbed.devices['node3_s1_bgw_1'].configure('''
              mac address-table static ''' + str(mac) + ''' vlan '''+ str(vlan) + ''' drop

                interface vlan ''' + str(vlan) + '''
                  ip arp ''' + str(ip) + ''' ''' + str(mac) + '''
            ''')
            testbed.devices['node4_s1_bgw_2'].configure('''
              mac address-table static ''' + str(mac) + ''' vlan '''+ str(vlan) + ''' drop

                interface vlan ''' + str(vlan) + '''
                  ip arp ''' + str(ip) + ''' ''' + str(mac) + '''
            ''')
            lasthex=incr_mac(mac)
            mac=mac[0:10]+lasthex
            vlan= int(vlan)+int(P3_dict['vlan_id_step'])
            ip=incr_ip(ip,octet)


            
        # except Exception as error:
        #     log.debug("Unable to configure static BH mac route - Encountered Exception " + str(error))
        #     self.errored('Exception occurred while configuring static BH mac route') 
    @aetest.test
    def APPLY_TRAFFIC(self):
        """ IXIA_CONFIGURATION subsection: Verify IXIA Traffic """

        # Apply IXIA Traffic
        if ixLib.apply_traffic() == 1:
            log.info("Applying IXIA TI Passed")
        else:
            self.errored("Applying IXIA TI failed", goto=['next_tc'])

    
    @aetest.test
    def VERIFY_IXIA_TRAFFIC_With_BH_Route(self, testscript):
        """ IXIA_CONFIGURATION subsection: Verify IXIA Traffic """

        # Do not perform configurations if skip_tgen_config flag is set
        #if not testscript.parameters['script_flags']['skip_tgen_config']:

        time.sleep(20)

        if ixLib.verify_traffic(99) == 0:
            log.debug("Traffic Verification Passed.Expecting traffic loss here.") 
        else:
            log.info("Traffic Verification Failed. Expecting traffic loss here.")
            self.failed("Traffic Verification failed")
        # else:
        #     self.passed(reason="Skipped TGEN Configurations as per request")
    
    @aetest.test
    def Verify_Traffic_Drop_on_Remote_Vtep(self,testscript,testbed):
        node5_s1_leaf_1 = testbed.devices['node5_s1_leaf_1']
        node7_s2_bgw_1 = testbed.devices['node7_s2_bgw_1']
        node9_s2_leaf_1 = testbed.devices['node9_s2_leaf_1']
        P3_dict = AcceSW_TGEN_data
        uplink_PO=S1_Leaf_dict['S1_Leaf_UPLINK_PO']['po_id']
        if verify_traffic_drop(node5_s1_leaf_1,uplink_PO):
            log.info('Traffic correctly dropped on  S1_Leaf')
        else:
            log.info('Traffic NOT dropped on  S1_Leaf')
            self.failed('Traffic NOT dropped on  S1_Leaf')

        uplink_PO=S2_BGW1_dict['S2_BGW1_UPLINK_PO']['po_id']
        if verify_traffic_drop(node7_s2_bgw_1,uplink_PO):
            log.info('Traffic correctly dropped on  S2_BGW1')
        else:
            log.info('Traffic NOT dropped on  S2_BGW1')
            self.failed('Traffic NOT dropped on  S2_BGW1')
        
        uplink_PO=S2_Leaf_dict['S2_Leaf_UPLINK_PO']['po_id']
        if verify_traffic_drop(node9_s2_leaf_1,uplink_PO):
            log.info('Traffic correctly dropped on  S2_Leaf')
        else:
            log.info('Traffic NOT dropped on  S2_Leaf')
            self.failed('Traffic NOT dropped on  S2_Leaf')

    @aetest.test
    def verify_static_mac_states(self, testscript,testbed):
        node3_s1_bgw_1 = testbed.devices['node3_s1_bgw_1']
        node7_s2_bgw_1 = testbed.devices['node7_s2_bgw_1']
        P3_dict = AcceSW_TGEN_data
        if verify_static_mac(node3_s1_bgw_1,str(P3_dict['mac']),str(P3_dict['vlan_id'])):
            log.info('proper dynaic mac learnt as static on S1_BGw1')
        else:
            log.info('improper dynamic mac learnt on  S1_BGw1')
            self.failed('improper dynamic mac learnt on  S1_BGw1')

        if verify_static_mac(node7_s2_bgw_1,str(P3_dict['mac']),str(P3_dict['vlan_id'])):
            log.info('proper dynaic mac learnt on  S2_BGw1')
        else:
            log.info('improper dynamic mac learnt on S2_BGw1')
            self.failed('improper dynamic mac learnt on  S2_BGw1')

    @aetest.test
    def Verify_BH_states_in_HMM(self, testscript,testbed):
        node3_s1_bgw_1 = testbed.devices['node3_s1_bgw_1']
        node7_s2_bgw_1 = testbed.devices['node7_s2_bgw_1']
        P3_dict = AcceSW_TGEN_data

        try:
            if verify_BH_in_HMM(node3_s1_bgw_1,str(P3_dict['v4_addr'])):
                log.info('Mac BH route is proper in HMM on  S1_BGW1')
            else:
                log.info('Mac BH route is improper in HMM on  S1_BGW1')
                self.failed('Mac BH route is improper in HMM on  S1_BGW1')
        
         
        except Exception as error:
            log.debug("Unable to configure static BH mac route on Remote Vtep- Encountered Exception " + str(error))
            self.errored('Exception occurred while configuring static BH mac route on Remote Vtep')
    @aetest.test
    def Verify_BH_states_in_AM(self, testscript,testbed):
        node3_s1_bgw_1 = testbed.devices['node3_s1_bgw_1']
        node7_s2_bgw_1 = testbed.devices['node7_s2_bgw_1']
        P3_dict = AcceSW_TGEN_data

        try:        
            if verify_BH_in_AM(node3_s1_bgw_1,str(P3_dict['mac']),str(P3_dict['vlan_id']),str(P3_dict['v4_addr'])):
                log.info('Mac BH route is proper in AM on  S1_BGW1')
            else:
                log.info('Mac BH route is improper in AM on  S1_BGW1')
                self.failed('Mac BH route is improper in AM on  S1_BGW1')
        
        except Exception as error:
            log.debug("Unable to configure static BH mac route on Remote Vtep- Encountered Exception " + str(error))
            self.errored('Exception occurred while configuring static BH mac route on Remote Vtep')
    @aetest.test 
    def Verify_BH_states_in_remote_ARP(self, testscript, testbed):
        node3_s1_bgw_1 =  testbed.devices['node3_s1_bgw_1']
        node7_s2_bgw_1 = testbed.devices['node7_s2_bgw_1']
        P3_dict = AcceSW_TGEN_data

        try: 

            if verify_BH_in_Remote_ARP(node7_s2_bgw_1,str(P3_dict['vlan_id']),str(P3_dict['mac'])):
               log.info('Mac BH route is proper in Remote ARP on  S2_BGW1')
            else:
                log.info('Mac BH route is improper in Remote ARP on  S2_BGW1')
                self.failed('Mac BH route is improper in Remote ARP on  S2_BGW1')

        except Exception as error:
            log.debug("Unable to configure static BH mac route on Remote Vtep- Encountered Exception " + str(error))
            self.errored('Exception occurred while configuring static BH mac route on Remote Vtep')        
    
    def Verify_BH_states_in_local_ARP(self, testscript, testbed):
        node3_s1_bgw_1 =  testbed.devices['node3_s1_bgw_1']
        node7_s2_bgw_1 =  testbed.devices['node7_s2_bgw_1']
        P3_dict = AcceSW_TGEN_data

        try:        
            if verify_BH_in_local_ARP(node3_s1_bgw_1,str(P3_dict['vlan_id']),str(P3_dict['mac'])):
                log.info('Mac BH route is proper in Local ARP on  S1_BGW1')
            else:
                log.info('Mac BH route is improper in Local ARP on  S1_BGW1')
                self.failed('Mac BH route is improper in Local ARP on  S1_BGW1')
        
        except Exception as error:
            log.debug("Unable to configure static BH mac route on Remote Vtep- Encountered Exception " + str(error))
            self.errored('Exception occurred while configuring static BH mac route on Remote Vtep')
        
    def Verify_Mac_BH_Route_on_L2FM_BGP_L2RIB(self,testscript,testbed):
        node3_s1_bgw_1 =testbed.devices['node3_s1_bgw_1']
        node7_s2_bgw_1 = testbed.devices['node7_s2_bgw_1']
        P3_dict = AcceSW_TGEN_data
        
        # Verifying L2FM

        try:
            ###S1_BGW1_MAC_BH_ROUTE
            if verify_BH_route_in_L2FM(node3_s1_bgw_1,str(P3_dict['vlan_id']),str(P3_dict['mac'])):
                log.info('Mac BH route is proper in L2FM on  S1_BGw1')
            else:
                log.info('Mac BH route is improper in L2FM on  S1_BGw1')
                self.failed('Mac BH route is improper in L2FM on  S1_BGw1')

            ###S2_BGW1_MAC_BH_ROUTE Remote Vtep
            if verify_BH_route_in_L2FM(node7_s2_bgw_1,str(P3_dict['vlan_id']),str(P3_dict['mac'])):
                log.info('Mac BH route is proper in L2FM on  S2_BGw1')
            else:
                log.info('Mac BH route is improper in L2FM on  S2_BGw1')
                self.failed('Mac BH route is improper in L2FM on  S2_BGw1')

        except Exception as error:
            log.debug("Unable to verify BH mac route in L2FM - Encountered Exception " + str(error))
            self.errored('Exception occurred while verifying BH mac route in L2FM')        

        #Verifying L2RIB
        try:
            #S1_Leaf_Mac_BH_route
            if verify_L2rib_mac_ip_output(node3_s1_bgw_1,str(P3_dict['vlan_id']),str(P3_dict['mac'])):
                log.info('Mac BH route is proper in L2RIB on S1_Leaf')
            else:
                log.debug('Mac BH route is improper in L2RIB on  S1_Leaf')
                self.failed('Mac BH route is improper in L2RIB on  S1_Leaf')

            #S2_BGW1_Mac_BH_route
            if verify_L2rib_mac_ip_output(node7_s2_bgw_1,str(P3_dict['vlan_id']),str(P3_dict['mac'])):
                log.info('Mac BH route is proper in L2RIB on S2_BGW1')
            else:
                log.debug('Mac BH route is improper in L2RIB on  S2_BGW1')
                self.errored('Mac BH route is improper in L2RIB on  S2_BGW1')
        
        except Exception as error:
            log.debug("Unable to verify BH mac route in L2RIB - Encountered Exception " + str(error))
            self.errored('Exception occurred while verifying BH mac route in L2RIB')
        
        #Verifying BGP
        try:
            #S2_BGW1_Mac_BH_route
            if verify_BH_in_Remote_BGP(node7_s2_bgw_1,str(P3_dict['mac'])):
                log.info('Mac BH route is proper in BGP on S2_BGW1')
            else:
                log.debug('Mac BH route is improper in BGP on  S2_BGW1')
                self.errored('Mac BH route is improper in BGP on  S2_BGW1')

            #Access_Mac_BH_route
            if verify_BH_in_Remote_BGP(node3_s1_bgw_1,str(P3_dict['mac'])):
                log.info('Mac BH route is proper in BGP on Access')
            else:
                log.debug('Mac BH route is improper in BGP on  Access')
                self.errored('Mac BH route is improper in BGP on  Access')
        
        except Exception as error:
            log.debug("Unable to verify BH mac route in BGP - Encountered Exception " + str(error))
            self.errored('Exception occurred while verifying BH mac route in BGP')

    @aetest.test
    def UnConfig_MAC_BH_route_on_vpc_vtep_start_traffic(self, testscript,testbed):
        node3_s1_bgw_1 = testbed.devices['node3_s1_bgw_1']
        P3_dict = AcceSW_TGEN_data
        mac= str(P3_dict['mac'])
        vlan= str(P3_dict['vlan_id'])
        ip=str(P3_dict['v4_addr'])
        octet = 1
        no_int= int(P3_dict['no_of_ints'])
        
        for i in range (0,no_int):
            ###LEAF_3_MAC_BH_ROUTE
            testbed.devices['node3_s1_bgw_1'].configure('''
              no mac address-table static ''' + str(mac) + ''' vlan '''+ str(vlan) + ''' drop

                interface vlan ''' + str(vlan) + '''
                  no ip arp ''' + str(ip) + ''' ''' + str(mac) + '''
            ''')
            testbed.devices['node4_s1_bgw_2'].configure('''
              no mac address-table static ''' + str(mac) + ''' vlan '''+ str(vlan) + ''' drop

                interface vlan ''' + str(vlan) + '''
                  no ip arp ''' + str(ip) + ''' ''' + str(mac) + '''
            ''')
            lasthex=incr_mac(mac)
            mac=mac[0:10]+lasthex
            vlan= int(vlan)+int(P3_dict['vlan_id_step'])
            ip=incr_ip(ip,octet)


    @aetest.test
    def VERIFY_IXIA_TRAFFIC_after_rmBH_Route(self, testscript):
        """ IXIA_CONFIGURATION subsection: Verify IXIA Traffic """

        # Do not perform configurations if skip_tgen_config flag is set
        #if not testscript.parameters['script_flags']['skip_tgen_config']:

        time.sleep(20)

        if ixLib.verify_traffic(1) == 1:
            log.debug("Traffic Verification Passed.Expecting traffic loss here.") 
        else:
            log.info("Traffic Verification Failed. Expecting traffic loss here.")
            self.failed("Traffic Verification failed")
        # else:
        #     self.passed(reason="Skipped TGEN Configurations as per request")


    @aetest.test
    def cleanup(self,testscript,testbed):
        """Unconfigure qos policies"""
        node3_s1_bgw_1 =  testbed.devices['node3_s1_bgw_1']
        node5_s1_leaf_1 =  testbed.devices['node5_s1_leaf_1']
        node10_s1_AccessSW =  testbed.devices['node10_s1_AccessSW']
        node7_s2_bgw_1 =  testbed.devices['node7_s2_bgw_1']
        P3_dict = AcceSW_TGEN_data
        forwardingSysDict = FWD_SYS_dict
    
        # Stop Traffic from ixia
        log.info("--- Stopping Traffic ---- \n")
        log.info("Stopping Traffic")
        traffic_run_status = ixLib.stop_traffic()
        
        if traffic_run_status is not 1:
            log.info("Failed: To Stop traffic")
            return 0
        else:
            log.info("\nTraffic Stopped successfully\n")
        time.sleep(10)
        ####Remove traffic item configured
        UCAST_v4_dict_1 = {
                        'mode'        : 'remove',
                        'stream_id'   : stream_id,
                    }
        if (ixLib.delete_traffic_item(UCAST_v4_dict_1))==0:
            log.debug("Traffic Remove failed")
            self.failed("Traffic Remove failed", goto=['next_tc'])
        else:
            log.info("Traffic Remove Passed")
        UCAST_v4_dict_2 = {
                        'mode'        : 'remove',
                        'stream_id'   : stream_id_1,
                    }
        if (ixLib.delete_traffic_item(UCAST_v4_dict_2))==0:
            log.debug("Traffic Remove failed")
            self.failed("Traffic Remove failed", goto=['next_tc'])
        else:
            log.info("Traffic Remove Passed")
        UCAST_v4_dict_3 = {
                        'mode'        : 'remove',
                        'stream_id'   : stream_id_2,
                    }
        if (ixLib.delete_traffic_item(UCAST_v4_dict_3))==0:
            log.debug("Traffic Remove failed")
            self.failed("Traffic Remove failed", goto=['next_tc'])
        else:
            log.info("Traffic Remove Passed")
        ###LEAF_1_MAC_BH_ROUTE


class MAC_BH_route_on_Standalone_vtep_start_traffic(nxtest.Testcase):
    #"""TC_0032_MAC_BH_route_on_Standalone_vtep_start_traffic"""
    stream_id=''
    @aetest.test
    def CONFIGURE_L2_UCAST_IXIA_TRAFFIC_H2_to_H1(self, testscript):
        """ IXIA_CONFIGURATION subsection: Configure MCAST Traffic Item """

        # Do not perform configurations if skip_tgen_config flag is set
        #if not testscript.parameters['script_flags']['skip_tgen_config']:

        IX_TP1 = testscript.parameters['IX_TP1']
        IX_TP2 = testscript.parameters['IX_TP2']
        IX_TP3 = testscript.parameters['IX_TP3']
        P1_dict = S1_BGW1_TGEN_data
        P2_dict = S1_Leaf_TGEN_data
        P3_dict = AcceSW_TGEN_data
        P4_dict = S2_Leaf_TGEN_data
        # P1_dict = S1_BGW1_TGEN_data
        # P4_dict = testscript.parameters['S2_BGW1_TGEN_dict']

        UCAST_v4_dict_1 = {   'src_hndl'  : IX_TP1['ipv4_handle'],
                            'dst_hndl'  : IX_TP3['ipv4_handle'],
                            'circuit'   : 'ipv4',
                            'TI_name'   : "UCAST_V4",
                            'rate_pps'  : "10000",
                            'bi_dir'    : 1,
                            'bidirectional': '0'
                        }

        UCAST_v4_TI = ixLib.configure_ixia_traffic_item_v46(UCAST_v4_dict_1)
            
        if UCAST_v4_TI == 0:
            log.debug("Configuring UCast L2 TI failed")
            self.errored("Configuring UCast L2 TI failed", goto=['next_tc'])
        else:
            global stream_id
            stream_id = UCAST_v4_TI
        # else:
        #     self.passed(reason="Skipped TGEN Configurations as per request")
    stream_id_1=''
    @aetest.test
    def CONFIGURE_L2_UCAST_IXIA_TRAFFIC_H3_to_H1(self, testscript):
        """ IXIA_CONFIGURATION subsection: Configure MCAST Traffic Item """

        # Do not perform configurations if skip_tgen_config flag is set
        #if not testscript.parameters['script_flags']['skip_tgen_config']:

        IX_TP1 = testscript.parameters['IX_TP1']
        IX_TP2 = testscript.parameters['IX_TP2']
        IX_TP3 = testscript.parameters['IX_TP3']
        P1_dict = S1_BGW1_TGEN_data
        P2_dict = S1_Leaf_TGEN_data
        P3_dict = AcceSW_TGEN_data
        P4_dict = S2_Leaf_TGEN_data
        # P1_dict = S1_BGW1_TGEN_data
        # P4_dict = testscript.parameters['S2_BGW1_TGEN_dict']

        UCAST_v4_dict_2 = {   'src_hndl'  : IX_TP2['ipv4_handle'],
                            'dst_hndl'  : IX_TP3['ipv4_handle'],
                            'circuit'   : 'ipv4',
                            'TI_name'   : "UCAST_V4",
                            'rate_pps'  : "10000",
                            'bi_dir'    : 1,
                            'bidirectional': '0'
                        }

        UCAST_v4_TI_1 = ixLib.configure_ixia_traffic_item_v46(UCAST_v4_dict_2)
            
        if UCAST_v4_TI_1 == 0:
            log.debug("Configuring UCast L2 TI failed")
            self.errored("Configuring UCast L2 TI failed", goto=['next_tc'])
        else:
            global stream_id_1
            stream_id_1 = UCAST_v4_TI_1
        # else:
        #     self.passed(reason="Skipped TGEN Configurations as per request")
    stream_id_2=''
    @aetest.test
    def CONFIGURE_L2_UCAST_IXIA_TRAFFIC_H4_to_H1(self, testscript):
        """ IXIA_CONFIGURATION subsection: Configure MCAST Traffic Item """

        # Do not perform configurations if skip_tgen_config flag is set
        #if not testscript.parameters['script_flags']['skip_tgen_config']:

        IX_TP1 = testscript.parameters['IX_TP1']
        IX_TP2 = testscript.parameters['IX_TP2']
        IX_TP3 = testscript.parameters['IX_TP3']
        IX_TP4 = testscript.parameters['IX_TP4']
        P1_dict = S1_BGW1_TGEN_data
        P2_dict = S1_Leaf_TGEN_data
        P3_dict = AcceSW_TGEN_data
        P4_dict = S2_Leaf_TGEN_data
        # P1_dict = S1_BGW1_TGEN_data
        # P4_dict = testscript.parameters['S2_BGW1_TGEN_dict']

        UCAST_v4_dict_3 = {   'src_hndl'  : IX_TP4['ipv4_handle'],
                            'dst_hndl'  : IX_TP3['ipv4_handle'],
                            'circuit'   : 'ipv4',
                            'TI_name'   : "UCAST_V4",
                            'rate_pps'  : "10000",
                            'bi_dir'    : 1,
                            'bidirectional': '0'
                        }

        UCAST_v4_TI_2 = ixLib.configure_ixia_traffic_item_v46(UCAST_v4_dict_3)
            
        if UCAST_v4_TI_2 == 0:
            log.debug("Configuring UCast L2 TI failed")
            self.errored("Configuring UCast L2 TI failed", goto=['next_tc'])
        else:
            global stream_id_2
            stream_id_2 = UCAST_v4_TI_2
        # else:
        #     self.passed(reason="Skipped TGEN Configurations as per request

    @aetest.test
    def APPLY_TRAFFIC(self):
        """ IXIA_CONFIGURATION subsection: Verify IXIA Traffic """

        # Apply IXIA Traffic
        if ixLib.apply_traffic() == 1:
            log.info("Applying IXIA TI Passed")
        else:
            self.errored("Applying IXIA TI failed")
    
    @aetest.test
    def VERIFY_IXIA_TRAFFIC_Without_BH_Route(self, testscript):
        """ IXIA_CONFIGURATION subsection: Verify IXIA Traffic """

        # Do not perform configurations if skip_tgen_config flag is set
        #if not testscript.parameters['script_flags']['skip_tgen_config']:

        time.sleep(20)

        if ixLib.verify_traffic(1) == 1:
            log.debug("Traffic Verification Passed.") 
        else:
            log.info("Traffic Verification Failed.")
            self.failed("Traffic Verification failed")
        # else:
        #     self.passed(reason="Skipped TGEN Configurations as per request")
    
    
    @aetest.test
    def Config_MAC_BH_route_on_vpc_vtep_start_traffic(self, testscript,testbed):
        node7_s2_bgw_1 = testbed.devices['node7_s2_bgw_1']
        P3_dict = AcceSW_TGEN_data
        mac= str(P3_dict['mac'])
        vlan= str(P3_dict['vlan_id'])
        ip=str(P3_dict['v4_addr'])
        octet = 1
        no_int= int(P3_dict['no_of_ints'])
        
        for i in range (0,no_int):
            ###LEAF_3_MAC_BH_ROUTE
            testbed.devices['node7_s2_bgw_1'].configure('''
                mac address-table static ''' + str(mac) + ''' vlan '''+ str(vlan) + ''' drop

                interface vlan ''' + str(vlan) + '''
                  ip arp ''' + str(ip) + ''' ''' + str(mac) + '''

            ''')
        
        mac= str(P3_dict['mac'])
        vlan= str(P3_dict['vlan_id'])
        ip=str(P3_dict['v4_addr'])
        no_int= int(P3_dict['no_of_ints'])
    
        # except Exception as error:
        #     log.debug("Unable to configure static BH mac route - Encountered Exception " + str(error))
        #     self.errored('Exception occurred while configuring static BH mac route') 
    
    @aetest.test
    def APPLY_TRAFFIC(self):
        """ IXIA_CONFIGURATION subsection: Verify IXIA Traffic """

        # Apply IXIA Traffic
        if ixLib.apply_traffic() == 1:
            log.info("Applying IXIA TI Passed")
        else:
            self.errored("Applying IXIA TI failed", goto=['next_tc'])

   
    @aetest.test
    def VERIFY_IXIA_TRAFFIC_with_Route(self, testscript):
        """ IXIA_CONFIGURATION subsection: Verify IXIA Traffic """

        # Do not perform configurations if skip_tgen_config flag is set
        #if not testscript.parameters['script_flags']['skip_tgen_config']:

        time.sleep(20)

        if ixLib.verify_traffic(99) == 0:
            log.debug("Traffic Verification Passed.Expecting traffic loss here.") 
        else:
            log.info("Traffic Verification Failed. Expecting traffic loss here.")
            self.failed("Traffic Verification failed")
        # else:
        #     self.passed(reason="Skipped TGEN Configurations as per request")
    
    @aetest.test
    def Verify_Traffic_Drop_on_Remote_Vtep(self,testscript,testbed):
        node5_s1_leaf_1 = testbed.devices['node5_s1_leaf_1']
        node3_s1_bgw_1 = testbed.devices['node3_s1_bgw_1']
        node9_s2_leaf_1 = testbed.devices['node9_s2_leaf_1']
        P3_dict = AcceSW_TGEN_data
        uplink_PO=S1_Leaf_dict['S1_Leaf_UPLINK_PO']['po_id']
        if verify_traffic_drop(node5_s1_leaf_1,uplink_PO):
            log.info('Traffic correctly dropped on  S1_Leaf')
        else:
            log.info('Traffic NOT dropped on  S1_Leaf')
            self.failed('Traffic NOT dropped on  S1_Leaf')

        uplink_PO=S1_BGW1_dict['S1_BGW1_UPLINK_PO']['po_id']
        if verify_traffic_drop(node3_s1_bgw_1,uplink_PO):
            log.info('Traffic correctly dropped on  S1_BGW1')
        else:
            log.info('Traffic NOT dropped on  S1_BGW1')
            self.failed('Traffic NOT dropped on  S1_BGW1')
        
        uplink_PO=S2_Leaf_dict['S2_Leaf_UPLINK_PO']['po_id']
        if verify_traffic_drop(node9_s2_leaf_1,uplink_PO):
            log.info('Traffic correctly dropped on  S2_Leaf')
        else:
            log.info('Traffic NOT dropped on  S2_Leaf')
            self.failed('Traffic NOT dropped on  S2_Leaf')
    
    @aetest.test
    def verify_static_mac_states(self, testscript,testbed):
        node3_s1_bgw_1 = testbed.devices['node3_s1_bgw_1']
        node7_s2_bgw_1 = testbed.devices['node7_s2_bgw_1']
        P3_dict = AcceSW_TGEN_data
        if verify_static_mac(node3_s1_bgw_1,str(P3_dict['mac']),str(P3_dict['vlan_id'])):
            log.info('proper dynaic mac learnt as static on S1_BGw1')
        else:
            log.info('improper dynamic mac learnt on  S1_BGw1')
            self.failed('improper dynamic mac learnt on  S1_BGw1')

        if verify_static_mac(node7_s2_bgw_1,str(P3_dict['mac']),str(P3_dict['vlan_id'])):
            log.info('proper dynaic mac learnt on  S2_BGw1')
        else:
            log.info('improper dynamic mac learnt on S2_BGw1')
            self.failed('improper dynamic mac learnt on  S2_BGw1')

    @aetest.test
    def Verify_BH_states_in_HMM(self, testscript,testbed):
        node3_s1_bgw_1 = testbed.devices['node3_s1_bgw_1']
        node7_s2_bgw_1 = testbed.devices['node7_s2_bgw_1']
        P3_dict = AcceSW_TGEN_data

        try:
            if verify_BH_in_HMM(node7_s2_bgw_1,str(P3_dict['v4_addr'])):
                log.info('Mac BH route is proper in HMM on  S1_BGW1')
            else:
                log.info('Mac BH route is improper in HMM on  S1_BGW1')
                self.failed('Mac BH route is improper in HMM on  S1_BGW1')
        
         
        except Exception as error:
            log.debug("Unable to configure static BH mac route on Remote Vtep- Encountered Exception " + str(error))
            self.errored('Exception occurred while configuring static BH mac route on Remote Vtep')
    @aetest.test
    def Verify_BH_states_in_AM(self, testscript,testbed):
        node3_s1_bgw_1 = testbed.devices['node3_s1_bgw_1']
        node7_s2_bgw_1 = testbed.devices['node7_s2_bgw_1']
        P3_dict = AcceSW_TGEN_data

        try:        
            if verify_BH_in_AM(node7_s2_bgw_1,str(P3_dict['mac']),str(P3_dict['vlan_id']),str(P3_dict['v4_addr'])):
                log.info('Mac BH route is proper in AM on  S1_BGW1')
            else:
                log.info('Mac BH route is improper in AM on  S1_BGW1')
                self.failed('Mac BH route is improper in AM on  S1_BGW1')
        
        except Exception as error:
            log.debug("Unable to configure static BH mac route on Remote Vtep- Encountered Exception " + str(error))
            self.errored('Exception occurred while configuring static BH mac route on Remote Vtep')
    @aetest.test 
    def Verify_BH_states_in_remote_ARP(self, testscript, testbed):
        node3_s1_bgw_1 =  testbed.devices['node3_s1_bgw_1']
        node7_s2_bgw_1 = testbed.devices['node7_s2_bgw_1']
        P3_dict = AcceSW_TGEN_data

        try: 

            if verify_BH_in_Remote_ARP(node3_s1_bgw_1,str(P3_dict['vlan_id']),str(P3_dict['mac'])):
               log.info('Mac BH route is proper in Remote ARP on  S2_BGW1')
            else:
                log.info('Mac BH route is improper in Remote ARP on  S2_BGW1')
                self.failed('Mac BH route is improper in Remote ARP on  S2_BGW1')

        except Exception as error:
            log.debug("Unable to configure static BH mac route on Remote Vtep- Encountered Exception " + str(error))
            self.errored('Exception occurred while configuring static BH mac route on Remote Vtep')        
    
    def Verify_BH_states_in_local_ARP(self, testscript, testbed):
        node3_s1_bgw_1 =  testbed.devices['node3_s1_bgw_1']
        node7_s2_bgw_1 =  testbed.devices['node7_s2_bgw_1']
        P3_dict = AcceSW_TGEN_data

        try:        
            if verify_BH_in_local_ARP(node7_s2_bgw_1,str(P3_dict['vlan_id']),str(P3_dict['mac'])):
                log.info('Mac BH route is proper in Local ARP on  S1_BGW1')
            else:
                log.info('Mac BH route is improper in Local ARP on  S1_BGW1')
                self.failed('Mac BH route is improper in Local ARP on  S1_BGW1')
        
        except Exception as error:
            log.debug("Unable to configure static BH mac route on Remote Vtep- Encountered Exception " + str(error))
            self.errored('Exception occurred while configuring static BH mac route on Remote Vtep')
        
    def Verify_Mac_BH_Route_on_L2FM_BGP_L2RIB(self,testscript,testbed):
        node3_s1_bgw_1 =testbed.devices['node3_s1_bgw_1']
        node7_s2_bgw_1 = testbed.devices['node7_s2_bgw_1']
        P3_dict = AcceSW_TGEN_data
        
        # Verifying L2FM

        try:
            ###S1_BGW1_MAC_BH_ROUTE
            if verify_BH_route_in_L2FM(node3_s1_bgw_1,str(P3_dict['vlan_id']),str(P3_dict['mac'])):
                log.info('Mac BH route is proper in L2FM on  S1_BGw1')
            else:
                log.info('Mac BH route is improper in L2FM on  S1_BGw1')
                self.failed('Mac BH route is improper in L2FM on  S1_BGw1')

            ###S2_BGW1_MAC_BH_ROUTE Remote Vtep
            if verify_BH_route_in_L2FM(node7_s2_bgw_1,str(P3_dict['vlan_id']),str(P3_dict['mac'])):
                log.info('Mac BH route is proper in L2FM on  S2_BGw1')
            else:
                log.info('Mac BH route is improper in L2FM on  S2_BGw1')
                self.failed('Mac BH route is improper in L2FM on  S2_BGw1')

        except Exception as error:
            log.debug("Unable to verify BH mac route in L2FM - Encountered Exception " + str(error))
            self.errored('Exception occurred while verifying BH mac route in L2FM')        

        #Verifying L2RIB
        try:
            #S1_Leaf_Mac_BH_route
            if verify_L2rib_mac_ip_output(node3_s1_bgw_1,str(P3_dict['vlan_id']),str(P3_dict['mac'])):
                log.info('Mac BH route is proper in L2RIB on S1_Leaf')
            else:
                log.debug('Mac BH route is improper in L2RIB on  S1_Leaf')
                self.failed('Mac BH route is improper in L2RIB on  S1_Leaf')

            #S2_BGW1_Mac_BH_route
            if verify_L2rib_mac_ip_output(node7_s2_bgw_1,str(P3_dict['vlan_id']),str(P3_dict['mac'])):
                log.info('Mac BH route is proper in L2RIB on S2_BGW1')
            else:
                log.debug('Mac BH route is improper in L2RIB on  S2_BGW1')
                self.errored('Mac BH route is improper in L2RIB on  S2_BGW1')
        
        except Exception as error:
            log.debug("Unable to verify BH mac route in L2RIB - Encountered Exception " + str(error))
            self.errored('Exception occurred while verifying BH mac route in L2RIB')
        
        #Verifying BGP
        try:
            #S2_BGW1_Mac_BH_route
            if verify_BH_in_Remote_BGP(node7_s2_bgw_1,str(P3_dict['mac'])):
                log.info('Mac BH route is proper in BGP on S2_BGW1')
            else:
                log.debug('Mac BH route is improper in BGP on  S2_BGW1')
                self.errored('Mac BH route is improper in BGP on  S2_BGW1')

            #Access_Mac_BH_route
            if verify_BH_in_Remote_BGP(node3_s1_bgw_1,str(P3_dict['mac'])):
                log.info('Mac BH route is proper in BGP on Access')
            else:
                log.debug('Mac BH route is improper in BGP on  Access')
                self.errored('Mac BH route is improper in BGP on  Access')
        
        except Exception as error:
            log.debug("Unable to verify BH mac route in BGP - Encountered Exception " + str(error))
            self.errored('Exception occurred while verifying BH mac route in BGP')

    @aetest.test
    def UnConfig_MAC_BH_route_on_vpc_vtep_start_traffic(self, testscript,testbed):
        node7_s2_bgw_1 = testbed.devices['node7_s2_bgw_1']
        P3_dict = AcceSW_TGEN_data
        mac= str(P3_dict['mac'])
        vlan= str(P3_dict['vlan_id'])
        ip=str(P3_dict['v4_addr'])
        octet = 1
        no_int= int(P3_dict['no_of_ints'])
        
        for i in range (0,no_int):
            ###LEAF_3_MAC_BH_ROUTE
            testbed.devices['node7_s2_bgw_1'].configure('''
                no mac address-table static ''' + str(mac) + ''' vlan '''+ str(vlan) + ''' drop

                interface vlan ''' + str(vlan) + '''
                  no ip arp ''' + str(ip) + ''' ''' + str(mac) + '''

            ''')
        
        mac= str(P3_dict['mac'])
        vlan= str(P3_dict['vlan_id'])
        ip=str(P3_dict['v4_addr'])
        no_int= int(P3_dict['no_of_ints'])
            
        # except Exception as error:
        #     log.debug("Unable to configure static BH mac route - Encountered Exception " + str(error))
        #     self.errored('Exception occurred while configuring static BH mac route') 

    @aetest.test
    def VERIFY_IXIA_TRAFFIC_after_rmBH_Route(self, testscript):
        """ IXIA_CONFIGURATION subsection: Verify IXIA Traffic """

        # Do not perform configurations if skip_tgen_config flag is set
        #if not testscript.parameters['script_flags']['skip_tgen_config']:

        time.sleep(20)

        if ixLib.verify_traffic(1) == 1:
            log.debug("Traffic Verification Passed.Expecting traffic loss here.") 
        else:
            log.info("Traffic Verification Failed. Expecting traffic loss here.")
            self.failed("Traffic Verification failed")
        # else:
        #     self.passed(reason="Skipped TGEN Configurations as per request")
   
    @aetest.test
    def cleanup(self,testscript,testbed):
        """Unconfigure qos policies"""
        node3_s1_bgw_1 = testbed.devices['node3_s1_bgw_1']
        node5_s1_leaf_1 = testbed.devices['node5_s1_leaf_1']
        node10_s1_AccessSW = testbed.devices['node10_s1_AccessSW']
        node7_s2_bgw_1 =testbed.devices['node7_s2_bgw_1']
        P3_dict = AcceSW_TGEN_data
        forwardingSysDict = FWD_SYS_dict
    
        # Stop Traffic from ixia
        log.info("--- Stopping Traffic ---- \n")
        log.info("Stopping Traffic")
        traffic_run_status = ixLib.stop_traffic()
        
        if traffic_run_status is not 1:
            log.info("Failed: To Stop traffic")
            return 0
        else:
            log.info("\nTraffic Stopped successfully\n")
        time.sleep(10)
        ####Remove traffic item configured
        UCAST_v4_dict_1 = {
                        'mode'        : 'remove',
                        'stream_id'   : stream_id,
                    }
        if (ixLib.delete_traffic_item(UCAST_v4_dict_1))==0:
            log.debug("Traffic Remove failed")
            self.failed("Traffic Remove failed", goto=['next_tc'])
        else:
            log.info("Traffic Remove Passed")
        UCAST_v4_dict_2 = {
                        'mode'        : 'remove',
                        'stream_id'   : stream_id_1,
                    }
        if (ixLib.delete_traffic_item(UCAST_v4_dict_2))==0:
            log.debug("Traffic Remove failed")
            self.failed("Traffic Remove failed", goto=['next_tc'])
        else:
            log.info("Traffic Remove Passed")
        UCAST_v4_dict_3 = {
                        'mode'        : 'remove',
                        'stream_id'   : stream_id_2,
                    }
        if (ixLib.delete_traffic_item(UCAST_v4_dict_3))==0:
            log.debug("Traffic Remove failed")
            self.failed("Traffic Remove failed", goto=['next_tc'])
        else:
            log.info("Traffic Remove Passed")

        ###LEAF_1_MAC_BH_ROUTE
        testbed.devices['node7_s2_bgw_1'].configure('''
        
            no mac address-table static ''' + str(P3_dict['mac']) + ''' vlan '''+ str(P3_dict['vlan_id']) + ''' drop

            interface vlan ''' + str(P3_dict['vlan_id']) + '''
                no ip arp ''' + str(P3_dict['v4_addr']) + ''' ''' + str(P3_dict['mac']) + '''
        ''')


###################################################################
###              L2 Ucast with IPv6 header  Test-cases          ###
###################################################################

class Mac_BH_route_static_ND_on_VPC_vtep(nxtest.Testcase):
     #"""TC_0034_Mac_BH_route_static_ND_on_VPC_vtep"""
    stream_id=''
    @aetest.test
    def CONFIGURE_L2_UCAST_IXIA_TRAFFIC_With_IPv6_H2_to_H1(self, testscript):
        """ IXIA_CONFIGURATION subsection: Configure MCAST Traffic Item """

        # Do not perform configurations if skip_tgen_config flag is set
        #if not testscript.parameters['script_flags']['skip_tgen_config']:

        IX_TP1 = testscript.parameters['IX_TP1']
        IX_TP2 = testscript.parameters['IX_TP2']
        IX_TP3 = testscript.parameters['IX_TP3']
        IX_TP4 = testscript.parameters['IX_TP4']
        P1_dict = S1_BGW1_TGEN_data
        P2_dict = S1_Leaf_TGEN_data
        P3_dict = AcceSW_TGEN_data
        P4_dict = S2_Leaf_TGEN_data


        UCAST_v6_dict_1 = {  'src_hndl'  : IX_TP1['ipv6_handle'],
                            'dst_hndl'  : IX_TP3['ipv6_handle'],
                            'circuit'   : 'ipv6',
                            'TI_name'   : "UCAST_v6",
                            'rate_pps'  : "1000",
                            'bi_dir'    : 1,
                            'bidirectional': '0'
                        }

        UCAST_v6_TI = ixLib.configure_ixia_traffic_item_v46(UCAST_v6_dict_1)

        if UCAST_v6_TI == 0:
            log.debug("Configuring UCast TI failed")
            self.errored("Configuring UCast TI failed", goto=['next_tc'])   
        
        else:
            global stream_id
            stream_id = UCAST_v6_TI
           
        # else:
        #     self.passed(reason="Skipped TGEN Configurations as per request")
    stream_id_1=''
    @aetest.test
    def CONFIGURE_L2_UCAST_IXIA_TRAFFIC_With_IPv6_H3_to_H1(self, testscript):
        """ IXIA_CONFIGURATION subsection: Configure MCAST Traffic Item """

        # Do not perform configurations if skip_tgen_config flag is set
        #if not testscript.parameters['script_flags']['skip_tgen_config']:

        IX_TP1 = testscript.parameters['IX_TP1']
        IX_TP2 = testscript.parameters['IX_TP2']
        IX_TP3 = testscript.parameters['IX_TP3']
        IX_TP4 = testscript.parameters['IX_TP4']
        P1_dict = S1_BGW1_TGEN_data
        P2_dict = S1_Leaf_TGEN_data
        P3_dict = AcceSW_TGEN_data
        P4_dict = S2_Leaf_TGEN_data

        UCAST_v6_dict_2 = {   'src_hndl'  : IX_TP2['ipv6_handle'],
                            'dst_hndl'  : IX_TP3['ipv6_handle'],
                            'circuit'   : 'ipv6',
                            'TI_name'   : "UCAST_v6",
                            'rate_pps'  : "1000",
                            'bi_dir'    : 1,
                            'bidirectional': '0'
                        }

        UCAST_v6_TI_1 = ixLib.configure_ixia_traffic_item_v46(UCAST_v6_dict_2)

        if UCAST_v6_TI_1 == 0:
            log.debug("Configuring UCast TI failed")
            self.errored("Configuring UCast TI failed", goto=['next_tc'])   
        
        else:
            global stream_id_1
            stream_id_1 = UCAST_v6_TI_1
            
        # else:
        #     self.passed(reason="Skipped TGEN Configurations as per request")
    stream_id_2=''
    @aetest.test
    def CONFIGURE_L2_UCAST_IXIA_TRAFFIC_With_IPv6_H4_to_H1(self, testscript):
        """ IXIA_CONFIGURATION subsection: Configure MCAST Traffic Item """

        # Do not perform configurations if skip_tgen_config flag is set
        #if not testscript.parameters['script_flags']['skip_tgen_config']:

        IX_TP1 = testscript.parameters['IX_TP1']
        IX_TP2 = testscript.parameters['IX_TP2']
        IX_TP3 = testscript.parameters['IX_TP3']
        IX_TP4 = testscript.parameters['IX_TP4']
        P1_dict = S1_BGW1_TGEN_data
        P2_dict = S1_Leaf_TGEN_data
        P3_dict = AcceSW_TGEN_data
        P4_dict = S2_Leaf_TGEN_data


        UCAST_v6_dict_3 = {   'src_hndl'  : IX_TP4['ipv6_handle'],
                            'dst_hndl'  : IX_TP3['ipv6_handle'],
                            'circuit'   : 'ipv6',
                            'TI_name'   : "UCAST_v6",
                            'rate_pps'  : "1000",
                            'bi_dir'    : 1,
                            'bidirectional': '0'
                        }

        UCAST_v6_TI_2 = ixLib.configure_ixia_traffic_item_v46(UCAST_v6_dict_3)

        if UCAST_v6_TI_2 == 0:
            log.debug("Configuring UCast TI failed")
            self.errored("Configuring UCast TI failed", goto=['next_tc'])   
        
        else:
            global stream_id_2
            stream_id_2 = UCAST_v6_TI_2
            
        # else:
        #     self.passed(reason="Skipped TGEN Configurations as per request")
    
    @aetest.test
    def APPLY_TRAFFIC(self):
        """ IXIA_CONFIGURATION subsection: Verify IXIA Traffic """

        # Apply IXIA Traffic
        if ixLib.apply_traffic() == 1:
            log.info("Applying IXIA TI Passed")
            # ForkedPdb().set_trace()
        else:
            self.errored("Applying IXIA TI failed")
    
    @aetest.test
    def VERIFY_IXIA_TRAFFIC_Without_BH_Route(self, testscript):
        """ IXIA_CONFIGURATION subsection: Verify IXIA Traffic """

        # Do not perform configurations if skip_tgen_config flag is set
        #if not testscript.parameters['script_flags']['skip_tgen_config']:

        time.sleep(20)

        if ixLib.verify_traffic(1) == 1:
            log.debug("Traffic Verification Passed.Expecting traffic loss here.") 
        else:
            log.info("Traffic Verification Failed. Expecting traffic loss here.")
            self.failed("Traffic Verification failed")
        # else:
        #     self.passed(reason="Skipped TGEN Configurations as per request")
 
    
    @aetest.test
    def verify_dynamic_mac_states(self, testscript,testbed):
        node3_s1_bgw_1 = testbed.devices['node3_s1_bgw_1']
        node7_s2_bgw_1 = testbed.devices['node7_s2_bgw_1']
        P3_dict = AcceSW_TGEN_data
        if verify_dynamic_mac(node3_s1_bgw_1,str(P3_dict['mac']),str(P3_dict['vlan_id'])):
            log.info('proper dynaic mac learnt on S1_BGw1')
        else:
            log.info('improper dynamic mac learnt on  S1_BGw1')
            self.failed('improper dynamic mac learnt on  S1_BGw1')

        if verify_dynamic_mac(node7_s2_bgw_1,str(P3_dict['mac']),str(P3_dict['vlan_id'])):
            log.info('proper dynaic mac learnt on  S2_BGw1')
        else:
            log.info('improper dynamic mac learnt on S2_BGw1')
            self.failed('improper dynamic mac learnt on  S2_BGw1')  

    @aetest.test
    def Config_Mac_BH_Static_ND_on_VPC(self,testscript,testbed):
        node3_s1_bgw_1 = testbed.devices['node3_s1_bgw_1']
        P3_dict = AcceSW_TGEN_data
        mac= str(P3_dict['mac'])
        vlan= str(P3_dict['vlan_id'])
        ipv6=str(P3_dict['v6_addr'])
        octet = 2
        no_int= int(P3_dict['no_of_ints'])
        
        for i in range (0,no_int):
            ###LEAF_3_MAC_BH_ROUTE
            testbed.devices['node3_s1_bgw_1'].configure('''
                mac address-table static ''' + str(mac) + ''' vlan '''+ str(vlan) + ''' drop

                interface vlan ''' + str(vlan) + '''
                    ipv6 neighbor ''' + str(ipv6) + ''' ''' + str(mac) + '''
            ''')
        
            testbed.devices['node4_s1_bgw_2'].configure('''
                mac address-table static ''' + str(mac) + ''' vlan '''+ str(vlan) + ''' drop

                interface vlan ''' + str(vlan) + '''
                    ipv6 neighbor ''' + str(ipv6) + ''' ''' + str(mac) + '''
            ''')
            lasthex=incr_mac(mac)
            mac=mac[0:10]+lasthex
            vlan= int(vlan)+int(P3_dict['vlan_id_step'])
            ipv6=incr_ipv6(ipv6,octet) 


    @aetest.test
    def APPLY_TRAFFIC(self):
        """ IXIA_CONFIGURATION subsection: Verify IXIA Traffic """

        # Apply IXIA Traffic
        if ixLib.apply_traffic() == 1:
            log.info("Applying IXIA TI Passed")
        else:
            self.errored("Applying IXIA TI failed", goto=['next_tc'])

    @aetest.test
    def VERIFY_IXIA_TRAFFIC_With_BH_Route(self, testscript):
        """ IXIA_CONFIGURATION subsection: Verify IXIA Traffic """

        # Do not perform configurations if skip_tgen_config flag is set
        #if not testscript.parameters['script_flags']['skip_tgen_config']:

        time.sleep(30)

        if ixLib.verify_traffic(99) == 0:
            log.debug("Traffic Verification Passed.Expecting traffic loss here.") 
        else:
            log.info("Traffic Verification Failed. Expecting traffic loss here.")
            self.failed("Traffic Verification failed")
        # else:
        #     self.passed(reason="Skipped TGEN Configurations as per request")
    
    @aetest.test
    def Verify_Traffic_Drop_on_Remote_Vtep(self,testscript,testbed):
        node5_s1_leaf_1 = testbed.devices['node5_s1_leaf_1']
        node7_s2_bgw_1 = testbed.devices['node7_s2_bgw_1']
        node9_s2_leaf_1 = testbed.devices['node9_s2_leaf_1']
        P3_dict = AcceSW_TGEN_data
        uplink_PO=S1_Leaf_dict['S1_Leaf_UPLINK_PO']['po_id']
        if verify_traffic_drop(node5_s1_leaf_1,uplink_PO):
            log.info('Traffic correctly dropped on  S1_Leaf')
        else:
            log.info('Traffic NOT dropped on  S1_Leaf')
            self.failed('Traffic NOT dropped on  S1_Leaf')

        uplink_PO=S2_BGW1_dict['S2_BGW1_UPLINK_PO']['po_id']
        if verify_traffic_drop(node7_s2_bgw_1,uplink_PO):
            log.info('Traffic correctly dropped on  S1_Leaf')
        else:
            log.info('Traffic NOT dropped on  S1_Leaf')
            self.failed('Traffic NOT dropped on  S1_Leaf')
        
        uplink_PO=S2_Leaf_dict['S2_Leaf_UPLINK_PO']['po_id']
        if verify_traffic_drop(node9_s2_leaf_1,uplink_PO):
            log.info('Traffic correctly dropped on  S1_Leaf')
        else:
            log.info('Traffic NOT dropped on  S1_Leaf')
            self.failed('Traffic NOT dropped on  S1_Leaf')
    
    @aetest.test
    def Verify_BH_states_in_HMM(self, testscript,testbed):
        node3_s1_bgw_1 = testbed.devices['node3_s1_bgw_1']
        node7_s2_bgw_1 = testbed.devices['node7_s2_bgw_1']
        P3_dict = AcceSW_TGEN_data

        try:
            if verify_Ipv6_BH_in_HMM(node3_s1_bgw_1,str(P3_dict['v6_addr'])):
                log.info('Mac BH route is proper in HMM on  S1_BGW1')
            else:
                log.info('Mac BH route is improper in HMM on  S1_BGW1')
                self.failed('Mac BH route is improper in HMM on  S1_BGW1')
        
         
        except Exception as error:
            log.debug("Unable to configure static BH mac route on Remote Vtep- Encountered Exception " + str(error))
            self.errored('Exception occurred while configuring static BH mac route on Remote Vtep')

    @aetest.test
    def Verify_BH_states_in_AM(self, testscript,testbed):
        node3_s1_bgw_1 = testbed.devices['node3_s1_bgw_1']
        node7_s2_bgw_1 = testbed.devices['node7_s2_bgw_1']
        P3_dict = AcceSW_TGEN_data

        try:        
            if verify_Ipv6_BH_in_AM(node3_s1_bgw_1,str(P3_dict['mac']),str(P3_dict['vlan_id']),str(P3_dict['v6_addr'])):
                log.info('Mac BH route is proper in AM on  S1_BGW1')
            else:
                log.info('Mac BH route is improper in AM on  S1_BGW1')
                self.failed('Mac BH route is improper in AM on  S1_BGW1')
        
        except Exception as error:
            log.debug("Unable to configure static BH mac route on Remote Vtep- Encountered Exception " + str(error))
            self.errored('Exception occurred while configuring static BH mac route on Remote Vtep')
    
    @aetest.test
    def Verify_Mac_BH_Route_on_L2FM_BGP_L2RIB(self,testscript,testbed):
        node3_s1_bgw_1 = testbed.devices['node3_s1_bgw_1']
        node7_s2_bgw_1 = testbed.devices['node7_s2_bgw_1']
        P3_dict = AcceSW_TGEN_data
        
        # Verifying L2FM

        try:
            ###S1_BGW1_MAC_BH_ROUTE
            if verify_BH_route_in_L2FM(node3_s1_bgw_1,str(P3_dict['vlan_id']),str(P3_dict['mac'])):
                log.info('Mac BH route is proper in L2FM on  S1_BGw1')
            else:
                log.info('Mac BH route is improper in L2FM on  S1_BGw1')
                self.failed('Mac BH route is improper in L2FM on  S1_BGw1')

            ###S2_BGW1_MAC_BH_ROUTE Remote Vtep
            if verify_BH_route_in_L2FM(node7_s2_bgw_1,str(P3_dict['vlan_id']),str(P3_dict['mac'])):
                log.info('Mac BH route is proper in L2FM on  S2_BGw1')
            else:
                log.info('Mac BH route is improper in L2FM on  S2_BGw1')
                self.failed('Mac BH route is improper in L2FM on  S2_BGw1')

        except Exception as error:
            log.debug("Unable to verify BH mac route in L2FM - Encountered Exception " + str(error))
            self.errored('Exception occurred while verifying BH mac route in L2FM')        

        #Verifying L2RIB
        try:
            #S1_Leaf_Mac_BH_route
            if verify_L2rib_mac_ip_output(node3_s1_bgw_1,str(P3_dict['vlan_id']),str(P3_dict['mac'])):
                log.info('Mac BH route is proper in L2RIB on S1_BGw1')
            else:
                log.debug('Mac BH route is improper in L2RIB on  S1_BGw1')
                self.failed('Mac BH route is improper in L2RIB on  S1_BGw1')
            #S2_BGW1_Mac_BH_route
            if verify_L2rib_mac_ip_output(node7_s2_bgw_1,str(P3_dict['vlan_id']),str(P3_dict['mac'])):
                log.info('Mac BH route is proper in L2RIB on S2_BGW1')
            else:
                log.debug('Mac BH route is improper in L2RIB on  S2_BGW1')
                self.errored('Mac BH route is improper in L2RIB on  S2_BGW1')
        
        except Exception as error:
            log.debug("Unable to verify BH mac route in L2RIB - Encountered Exception " + str(error))
            self.errored('Exception occurred while verifying BH mac route in L2RIB')
        
        #Verifying BGP
        try:
            #S2_BGW1_Mac_BH_route
            if verify_BH_in_Remote_BGP(node7_s2_bgw_1,str(P3_dict['mac'])):
                log.info('Mac BH route is proper in BGP on S2_BGW1')
            else:
                log.debug('Mac BH route is improper in BGP on  S2_BGW1')
                self.errored('Mac BH route is improper in BGP on  S2_BGW1')

            #Access_Mac_BH_route
            if verify_BH_in_Remote_BGP(node3_s1_bgw_1,str(P3_dict['mac'])):
                log.info('Mac BH route is proper in BGP on Access')
            else:
                log.debug('Mac BH route is improper in BGP on  Access')
                self.errored('Mac BH route is improper in BGP on  Access')
        
        except Exception as error:
            log.debug("Unable to verify BH mac route in BGP - Encountered Exception " + str(error))
            self.errored('Exception occurred while verifying BH mac route in BGP')
    
    @aetest.test
    def Verify_Ipv6_icmp_neighbor(self,testbed):
        node3_s1_bgw_1 = testbed.devices['node3_s1_bgw_1']
        node7_s2_bgw_1 = testbed.devices['node7_s2_bgw_1']
        P3_dict = AcceSW_TGEN_data
    
        ###S1_BGW1_MAC_BH_ROUTE
        if Verify_ipv6_local_neighbor(node3_s1_bgw_1,str(P3_dict['mac']),str(P3_dict['vlan_id'])):
            log.info('Mac BH route is proper in ICMP neighbor on  S1_BGw1')
        else:
            log.info('Mac BH route is improper in ICMP neighbor on  S1_BGw1')
            self.failed('Mac BH route is improper in ICMP neighbor on  S1_BGw1')

        if verify_icmp_static_remote_neighbor(node7_s2_bgw_1,str(P3_dict['mac'])):
            log.info('Mac BH route is proper in ICMP neighbor on  S1_BGw1')
        else:
            log.info('Mac BH route is improper in ICMP neighbor on  S1_BGw1')
            self.failed('Mac BH route is improper in ICMP neighbor on  S1_BGw1')
    
    @aetest.test
    def remove_add_vnsegment(self,testscript,testbed):
        node3_s1_bgw_1 =  testbed.devices['node3_s1_bgw_1']
        node4_s1_bgw_2 =  testbed.devices['node4_s1_bgw_2']
        P3_dict = AcceSW_TGEN_data
        no_int= int(P3_dict['no_of_ints'])
        vlans= S1_BGW1_dict['vlans']
        vn_segment=S1_BGW1_dict['vni']

        for i in range (0,no_int):

            testbed.devices['node3_s1_bgw_1'].configure('''
              vlan ''' + str(vlans) + '''
              no vn-segment ''' + str(vn_segment)
             )
            testbed.devices['node4_s1_bgw_2'].configure('''
              vlan ''' + str(vlans) + '''
              no vn-segment ''' + str(vn_segment)
             )
            vlans=S1_BGW1_dict['vlans'] + S1_BGW1_dict['vlan_step']
            vn_segment= S1_BGW1_dict['vni'] + S1_BGW1_dict['vlan_step']
        time.sleep(10)
        #Add vn_segment_back
        vlans= S1_BGW1_dict['vlans']
        vn_segment=S1_BGW1_dict['vni']

        for i in range (0,no_int):

            testbed.devices['node3_s1_bgw_1'].configure('''
              vlan ''' + str(vlans) + '''
              vn-segment ''' + str(vn_segment)
             )
            testbed.devices['node4_s1_bgw_2'].configure('''
              vlan ''' + str(vlans) + '''
              vn-segment ''' + str(vn_segment)
             )
            vlans=S1_BGW1_dict['vlans'] + S1_BGW1_dict['vlan_step']
            vn_segment= S1_BGW1_dict['vni'] + S1_BGW1_dict['vlan_step']
        time.sleep(30)

    @aetest.test
    def Verify_BH_states_in_HMM(self, testscript,testbed):
        node3_s1_bgw_1 = testbed.devices['node3_s1_bgw_1']
        node7_s2_bgw_1 = testbed.devices['node7_s2_bgw_1']
        P3_dict = AcceSW_TGEN_data

        try:
            if verify_Ipv6_BH_in_HMM(node3_s1_bgw_1,str(P3_dict['v6_addr'])):
                log.info('Mac BH route is proper in HMM on  S1_BGW1')
            else:
                log.info('Mac BH route is improper in HMM on  S1_BGW1')
                self.failed('Mac BH route is improper in HMM on  S1_BGW1')
        
         
        except Exception as error:
            log.debug("Unable to configure static BH mac route on Remote Vtep- Encountered Exception " + str(error))
            self.errored('Exception occurred while configuring static BH mac route on Remote Vtep')

    @aetest.test
    def Verify_BH_states_in_AM(self, testscript,testbed):
        node3_s1_bgw_1 = testbed.devices['node3_s1_bgw_1']
        node7_s2_bgw_1 = testbed.devices['node7_s2_bgw_1']
        P3_dict = AcceSW_TGEN_data

        try:        
            if verify_Ipv6_BH_in_AM(node3_s1_bgw_1,str(P3_dict['mac']),str(P3_dict['vlan_id']),str(P3_dict['v6_addr'])):
                log.info('Mac BH route is proper in AM on  S1_BGW1')
            else:
                log.info('Mac BH route is improper in AM on  S1_BGW1')
                self.failed('Mac BH route is improper in AM on  S1_BGW1')
        
        except Exception as error:
            log.debug("Unable to configure static BH mac route on Remote Vtep- Encountered Exception " + str(error))
            self.errored('Exception occurred while configuring static BH mac route on Remote Vtep')
    
    @aetest.test
    def Verify_Mac_BH_Route_on_L2FM_BGP_L2RIB(self,testscript,testbed):
        node3_s1_bgw_1 = testbed.devices['node3_s1_bgw_1']
        node7_s2_bgw_1 = testbed.devices['node7_s2_bgw_1']
        P3_dict = AcceSW_TGEN_data
        
        # Verifying L2FM

        try:
            ###S1_BGW1_MAC_BH_ROUTE
            if verify_BH_route_in_L2FM(node3_s1_bgw_1,str(P3_dict['vlan_id']),str(P3_dict['mac'])):
                log.info('Mac BH route is proper in L2FM on  S1_BGw1')
            else:
                log.info('Mac BH route is improper in L2FM on  S1_BGw1')
                self.failed('Mac BH route is improper in L2FM on  S1_BGw1')

            ###S2_BGW1_MAC_BH_ROUTE Remote Vtep
            if verify_BH_route_in_L2FM(node7_s2_bgw_1,str(P3_dict['vlan_id']),str(P3_dict['mac'])):
                log.info('Mac BH route is proper in L2FM on  S2_BGw1')
            else:
                log.info('Mac BH route is improper in L2FM on  S2_BGw1')
                self.failed('Mac BH route is improper in L2FM on  S2_BGw1')

        except Exception as error:
            log.debug("Unable to verify BH mac route in L2FM - Encountered Exception " + str(error))
            self.errored('Exception occurred while verifying BH mac route in L2FM')        

        #Verifying L2RIB
        try:
            #S1_Leaf_Mac_BH_route
            if verify_L2rib_mac_ip_output(node3_s1_bgw_1,str(P3_dict['vlan_id']),str(P3_dict['mac'])):
                log.info('Mac BH route is proper in L2RIB on S1_BGw1')
            else:
                log.debug('Mac BH route is improper in L2RIB on  S1_BGw1')
                self.failed('Mac BH route is improper in L2RIB on  S1_BGw1')
            #S2_BGW1_Mac_BH_route
            if verify_L2rib_mac_ip_output(node7_s2_bgw_1,str(P3_dict['vlan_id']),str(P3_dict['mac'])):
                log.info('Mac BH route is proper in L2RIB on S2_BGW1')
            else:
                log.debug('Mac BH route is improper in L2RIB on  S2_BGW1')
                self.errored('Mac BH route is improper in L2RIB on  S2_BGW1')
        
        except Exception as error:
            log.debug("Unable to verify BH mac route in L2RIB - Encountered Exception " + str(error))
            self.errored('Exception occurred while verifying BH mac route in L2RIB')
        
        #Verifying BGP
        try:
            #S2_BGW1_Mac_BH_route
            if verify_BH_in_Remote_BGP(node7_s2_bgw_1,str(P3_dict['mac'])):
                log.info('Mac BH route is proper in BGP on S2_BGW1')
            else:
                log.debug('Mac BH route is improper in BGP on  S2_BGW1')
                self.errored('Mac BH route is improper in BGP on  S2_BGW1')

            #Access_Mac_BH_route
            if verify_BH_in_Remote_BGP(node3_s1_bgw_1,str(P3_dict['mac'])):
                log.info('Mac BH route is proper in BGP on Access')
            else:
                log.debug('Mac BH route is improper in BGP on  Access')
                self.errored('Mac BH route is improper in BGP on  Access')
        
        except Exception as error:
            log.debug("Unable to verify BH mac route in BGP - Encountered Exception " + str(error))
            self.errored('Exception occurred while verifying BH mac route in BGP')
    
    @aetest.test
    def Verify_Ipv6_icmp_neighbor(self,testbed):
        node3_s1_bgw_1 = testbed.devices['node3_s1_bgw_1']
        node7_s2_bgw_1 = testbed.devices['node7_s2_bgw_1']
        P3_dict = AcceSW_TGEN_data
    
        ###S1_BGW1_MAC_BH_ROUTE
        if Verify_ipv6_local_neighbor(node3_s1_bgw_1,str(P3_dict['mac']),str(P3_dict['vlan_id'])):
            log.info('Mac BH route is proper in ICMP neighbor on  S1_BGw1')
        else:
            log.info('Mac BH route is improper in ICMP neighbor on  S1_BGw1')
            self.failed('Mac BH route is improper in ICMP neighbor on  S1_BGw1')

        if verify_icmp_static_remote_neighbor(node7_s2_bgw_1,str(P3_dict['mac'])):
            log.info('Mac BH route is proper in ICMP neighbor on  S1_BGw1')
        else:
            log.info('Mac BH route is improper in ICMP neighbor on  S1_BGw1')
            self.failed('Mac BH route is improper in ICMP neighbor on  S1_BGw1')
    
    @aetest.test
    def VERIFY_IXIA_TRAFFIC_after_rmBH_Route(self, testscript):
        """ IXIA_CONFIGURATION subsection: Verify IXIA Traffic """

        # Do not perform configurations if skip_tgen_config flag is set
        #if not testscript.parameters['script_flags']['skip_tgen_config']:

        time.sleep(30)

        if ixLib.verify_traffic(99) == 0:
            log.debug("Traffic Verification Passed.Expecting traffic loss here.") 
        else:
            log.info("Traffic Verification Failed. Expecting traffic loss here.")
            self.failed("Traffic Verification failed")

    @aetest.test
    def UnConfig_Mac_BH_Static_ND_on_VPC(self,testscript,testbed):
        node3_s1_bgw_1 = testbed.devices['node3_s1_bgw_1']
        P3_dict = AcceSW_TGEN_data
        mac= str(P3_dict['mac'])
        vlan= str(P3_dict['vlan_id'])
        ipv6=str(P3_dict['v6_addr'])
        octet = 2
        no_int= int(P3_dict['no_of_ints'])
        
        for i in range (0,no_int):
            ###LEAF_3_MAC_BH_ROUTE
            testbed.devices['node3_s1_bgw_1'].configure('''
                no mac address-table static ''' + str(mac) + ''' vlan '''+ str(vlan) + ''' drop

                interface vlan ''' + str(vlan) + '''
                    no ipv6 neighbor ''' + str(ipv6) + ''' ''' + str(mac) + '''
            ''')
        
            testbed.devices['node4_s1_bgw_2'].configure('''
                no mac address-table static ''' + str(mac) + ''' vlan '''+ str(vlan) + ''' drop

                interface vlan ''' + str(vlan) + '''
                    no ipv6 neighbor ''' + str(ipv6) + ''' ''' + str(mac) + '''
            ''')
            lasthex=incr_mac(mac)
            mac=mac[0:10]+lasthex
            vlan= int(vlan)+int(P3_dict['vlan_id_step'])
            ipv6=incr_ipv6(ipv6,octet) 


    @aetest.test
    def APPLY_TRAFFIC(self):
        """ IXIA_CONFIGURATION subsection: Verify IXIA Traffic """

        # Apply IXIA Traffic
        if ixLib.apply_traffic() == 1:
            log.info("Applying IXIA TI Passed")
        else:
            self.errored("Applying IXIA TI failed", goto=['next_tc'])
     
    @aetest.test
    def VERIFY_IXIA_TRAFFIC_after_rmBH_Route(self, testscript):
        """ IXIA_CONFIGURATION subsection: Verify IXIA Traffic """

        # Do not perform configurations if skip_tgen_config flag is set
        #if not testscript.parameters['script_flags']['skip_tgen_config']:

        time.sleep(30)

        if ixLib.verify_traffic(1) == 1:
            log.debug("Traffic Verification Passed.Expecting traffic loss here.") 
        else:
            log.info("Traffic Verification Failed. Expecting traffic loss here.")
            self.failed("Traffic Verification failed")
        # else:
        #     self.passed(reason="Skipped TGEN Configurations as per request")

    
    @aetest.cleanup
    def cleanup(self,testscript,testbed):
        """Unconfigure qos policies"""
        node3_s1_bgw_1 =testbed.devices['node3_s1_bgw_1']
        node5_s1_leaf_1 = testbed.devices['node5_s1_leaf_1']
        node10_s1_AccessSW = testbed.devices['node10_s1_AccessSW']
        node7_s2_bgw_1 = testbed.devices['node7_s2_bgw_1']
        P3_dict = AcceSW_TGEN_data
        forwardingSysDict = FWD_SYS_dict
        try:
            # Stop Traffic from ixia
            log.info("--- Stopping Traffic ---- \n")
            log.info("Stopping Traffic")
            traffic_run_status = ixLib.stop_traffic()
            
            if traffic_run_status is not 1:
               log.info("Failed: To Stop traffic")
               return 0
            else:
                log.info("\nTraffic Stopped successfully\n")
            time.sleep(10)
            ####Remove traffic item configured
            UCAST_v6_dict_1 = {
                            'mode'        : 'remove',
                            'stream_id'   : stream_id,
                      }
            if (ixLib.delete_traffic_item(UCAST_v6_dict_1))==0:
                log.debug("Traffic Remove failed")
                self.failed("Traffic Remove failed", goto=['next_tc'])
            else:
                log.info("Traffic Remove Passed")
            UCAST_v6_dict_2 = {
                            'mode'        : 'remove',
                            'stream_id'   : stream_id_1,
                      }
            if (ixLib.delete_traffic_item(UCAST_v6_dict_2))==0:
                log.debug("Traffic Remove failed")
                self.failed("Traffic Remove failed", goto=['next_tc'])
            else:
                log.info("Traffic Remove Passed")
            UCAST_v6_dict_3 = {
                            'mode'        : 'remove',
                            'stream_id'   : stream_id_2,
                      }
            if (ixLib.delete_traffic_item(UCAST_v6_dict_3))==0:
                log.debug("Traffic Remove failed")
                self.failed("Traffic Remove failed", goto=['next_tc'])
            else:
                log.info("Traffic Remove Passed")
            ###LEAF_1_MAC_BH_ROUTE
            testbed.devices['node3_s1_bgw_1'].configure('''
            
               no mac address-table static ''' + str(P3_dict['mac']) + ''' vlan '''+ str(P3_dict['vlan_id']) + ''' drop

                interface vlan ''' + str(P3_dict['vlan_id']) + '''
                  no ipv6 neighbor ''' + str(P3_dict['v6_addr']) + ''' ''' + str(P3_dict['mac']) + '''
                
            ''')

        except Exception as error:
            log.debug("Unable to do cleanup " + str(error))
            self.errored('Exception occurred during cleanup', goto=['next_tc'])   


    #======================================================================================================================#
class Mac_BH_route_static_ND_on_RemoteVtep(nxtest.Testcase):
     #"""TC_0036_Mac_BH_route_static_ND_on_RemoteVtep"""
    stream_id=''
    @aetest.test
    def CONFIGURE_L2_UCAST_IXIA_TRAFFIC_With_IPv6_H2_to_H1(self, testscript):
        """ IXIA_CONFIGURATION subsection: Configure MCAST Traffic Item """

        # Do not perform configurations if skip_tgen_config flag is set
        #if not testscript.parameters['script_flags']['skip_tgen_config']:

        IX_TP1 = testscript.parameters['IX_TP1']
        IX_TP2 = testscript.parameters['IX_TP2']
        IX_TP3 = testscript.parameters['IX_TP3']
        IX_TP4 = testscript.parameters['IX_TP4']
        P1_dict = S1_BGW1_TGEN_data
        P2_dict = S1_Leaf_TGEN_data
        P3_dict = AcceSW_TGEN_data
        P4_dict = S2_Leaf_TGEN_data


        UCAST_v6_dict_1 = {   'src_hndl'  : IX_TP1['ipv6_handle'],
                            'dst_hndl'  : IX_TP3['ipv6_handle'],
                            'circuit'   : 'ipv6',
                            'TI_name'   : "UCAST_v6",
                            'rate_pps'  : "1000",
                            'bi_dir'    : 1,
                            'bidirectional': '0'
                        }

        UCAST_v6_TI = ixLib.configure_ixia_traffic_item_v46(UCAST_v6_dict_1)

        if UCAST_v6_TI == 0:
            log.debug("Configuring UCast TI failed")
            self.errored("Configuring UCast TI failed", goto=['next_tc'])   
        
        else:
            global stream_id
            stream_id = UCAST_v6_TI
           
        # else:
        #     self.passed(reason="Skipped TGEN Configurations as per request")
    stream_id_1=''
    @aetest.test
    def CONFIGURE_L2_UCAST_IXIA_TRAFFIC_With_IPv6_H3_to_H1(self, testscript):
        """ IXIA_CONFIGURATION subsection: Configure MCAST Traffic Item """

        # Do not perform configurations if skip_tgen_config flag is set
        #if not testscript.parameters['script_flags']['skip_tgen_config']:

        IX_TP1 = testscript.parameters['IX_TP1']
        IX_TP2 = testscript.parameters['IX_TP2']
        IX_TP3 = testscript.parameters['IX_TP3']
        IX_TP4 = testscript.parameters['IX_TP4']
        P1_dict = S1_BGW1_TGEN_data
        P2_dict = S1_Leaf_TGEN_data
        P3_dict = AcceSW_TGEN_data
        P4_dict = S2_Leaf_TGEN_data

        UCAST_v6_dict_2 = {   'src_hndl'  : IX_TP2['ipv6_handle'],
                            'dst_hndl'  : IX_TP3['ipv6_handle'],
                            'circuit'   : 'ipv6',
                            'TI_name'   : "UCAST_v6",
                            'rate_pps'  : "1000",
                            'bi_dir'    : 1,
                            'bidirectional': '0'
                        }

        UCAST_v6_TI_1 = ixLib.configure_ixia_traffic_item_v46(UCAST_v6_dict_2)

        if UCAST_v6_TI_1 == 0:
            log.debug("Configuring UCast TI failed")
            self.errored("Configuring UCast TI failed", goto=['next_tc'])   
        
        else:
            global stream_id_1
            stream_id_1 = UCAST_v6_TI_1
            
        # else:
        #     self.passed(reason="Skipped TGEN Configurations as per request")
    stream_id_2=''
    @aetest.test
    def CONFIGURE_L2_UCAST_IXIA_TRAFFIC_With_IPv6_H4_to_H1(self, testscript):
        """ IXIA_CONFIGURATION subsection: Configure MCAST Traffic Item """

        # Do not perform configurations if skip_tgen_config flag is set
        #if not testscript.parameters['script_flags']['skip_tgen_config']:

        IX_TP1 = testscript.parameters['IX_TP1']
        IX_TP2 = testscript.parameters['IX_TP2']
        IX_TP3 = testscript.parameters['IX_TP3']
        IX_TP4 = testscript.parameters['IX_TP4']
        P1_dict = S1_BGW1_TGEN_data
        P2_dict = S1_Leaf_TGEN_data
        P3_dict = AcceSW_TGEN_data
        P4_dict = S2_Leaf_TGEN_data


        UCAST_v6_dict_3 = {   'src_hndl'  : IX_TP4['ipv6_handle'],
                            'dst_hndl'  : IX_TP3['ipv6_handle'],
                            'circuit'   : 'ipv6',
                            'TI_name'   : "UCAST_v6",
                            'rate_pps'  : "1000",
                            'bi_dir'    : 1,
                            'bidirectional': '0'
                        }

        UCAST_v6_TI_2 = ixLib.configure_ixia_traffic_item_v46(UCAST_v6_dict_3)

        if UCAST_v6_TI_2 == 0:
            log.debug("Configuring UCast TI failed")
            self.errored("Configuring UCast TI failed", goto=['next_tc'])   
        
        else:
            global stream_id_2
            stream_id_2 = UCAST_v6_TI_2
            
        # else:
        #     self.passed(reason="Skipped TGEN Configurations as per request")
    @aetest.test
    def APPLY_TRAFFIC(self):
        """ IXIA_CONFIGURATION subsection: Verify IXIA Traffic """

        # Apply IXIA Traffic
        if ixLib.apply_traffic() == 1:
            log.info("Applying IXIA TI Passed")
        else:
            self.errored("Applying IXIA TI failed")
    
    @aetest.test
    def VERIFY_IXIA_TRAFFIC_Without_BH_Route(self, testscript):
        """ IXIA_CONFIGURATION subsection: Verify IXIA Traffic """

        # Do not perform configurations if skip_tgen_config flag is set
        #if not testscript.parameters['script_flags']['skip_tgen_config']:

        time.sleep(20)

        if ixLib.verify_traffic(1) == 1:
            log.debug("Traffic Verification Passed.Expecting traffic loss here.") 
        else:
            log.info("Traffic Verification Failed. Expecting traffic loss here.")
            self.failed("Traffic Verification failed")
        # else:
        #     self.passed(reason="Skipped TGEN Configurations as per request")
    
    @aetest.test
    def Config_Mac_BH_Static_ND_on_RemoteVtep(self,testscript,testbed):
        node7_s2_bgw_1 = testbed.devices['node7_s2_bgw_1']
        P3_dict = AcceSW_TGEN_data
        mac= str(P3_dict['mac'])
        vlan= str(P3_dict['vlan_id'])
        ipv6=str(P3_dict['v6_addr'])
        octet = 2
        no_int= int(P3_dict['no_of_ints'])
        
        for i in range (0,no_int):
            ###LEAF_3_MAC_BH_ROUTE
            testbed.devices['node7_s2_bgw_1'].configure('''
               mac address-table static ''' + str(mac) + ''' vlan '''+ str(vlan) + ''' drop

                interface vlan ''' + str(vlan) + '''
                  ipv6 neighbor ''' + str(ipv6) + ''' ''' + str(mac) + '''
            ''')
            lasthex=incr_mac(mac)
            mac=mac[0:10]+lasthex
            vlan= int(vlan)+int(P3_dict['vlan_id_step'])
            ipv6=incr_ipv6(ipv6,octet) 

            
        # except Exception as error:
        #     log.debug("Unable to configure static BH mac route - Encountered Exception " + str(error))
        #     self.errored('Exception occurred while configuring static BH mac route') 

    @aetest.test
    def APPLY_TRAFFIC(self):
        """ IXIA_CONFIGURATION subsection: Verify IXIA Traffic """

        # Apply IXIA Traffic
        if ixLib.apply_traffic() == 1:
            log.info("Applying IXIA TI Passed")
        else:
            self.errored("Applying IXIA TI failed", goto=['next_tc'])

    @aetest.test
    def VERIFY_IXIA_TRAFFIC_With_BH_Route(self, testscript):
        """ IXIA_CONFIGURATION subsection: Verify IXIA Traffic """

        # Do not perform configurations if skip_tgen_config flag is set
        #if not testscript.parameters['script_flags']['skip_tgen_config']:

        time.sleep(30)

        if ixLib.verify_traffic(99) == 0:
            log.debug("Traffic Verification Passed.Expecting traffic loss here.") 
        else:
            log.info("Traffic Verification Failed. Expecting traffic loss here.")
            self.failed("Traffic Verification failed")
        # else:
        #     self.passed(reason="Skipped TGEN Configurations as per request")
    
    @aetest.test
    def Verify_Traffic_Drop_on_Remote_Vtep(self,testscript,testbed):
        node5_s1_leaf_1 = testbed.devices['node5_s1_leaf_1']
        node3_s1_bgw_1 = testbed.devices['node3_s1_bgw_1']
        node9_s2_leaf_1 = testbed.devices['node9_s2_leaf_1']
        P3_dict = AcceSW_TGEN_data
        uplink_PO=S1_Leaf_dict['S1_Leaf_UPLINK_PO']['po_id']
        if verify_traffic_drop(node5_s1_leaf_1,uplink_PO):
            log.info('Traffic correctly dropped on  S1_Leaf')
        else:
            log.info('Traffic NOT dropped on  S1_Leaf')
            self.failed('Traffic NOT dropped on  S1_Leaf')

        uplink_PO=S1_BGW1_dict['S1_BGW1_UPLINK_PO']['po_id']
        if verify_traffic_drop(node3_s1_bgw_1,uplink_PO):
            log.info('Traffic correctly dropped on  S1_Leaf')
        else:
            log.info('Traffic NOT dropped on  S1_Leaf')
            self.failed('Traffic NOT dropped on  S1_Leaf')
        
        uplink_PO=S2_Leaf_dict['S2_Leaf_UPLINK_PO']['po_id']
        if verify_traffic_drop(node9_s2_leaf_1,uplink_PO):
            log.info('Traffic correctly dropped on  S1_Leaf')
        else:
            log.info('Traffic NOT dropped on  S1_Leaf')
            self.failed('Traffic NOT dropped on  S1_Leaf')
    
    @aetest.test
    def Verify_BH_states_in_HMM(self, testscript,testbed):
        node3_s1_bgw_1 =testbed.devices['node3_s1_bgw_1']
        node7_s2_bgw_1 = testbed.devices['node7_s2_bgw_1']
        P3_dict = AcceSW_TGEN_data
        try:
            if verify_Ipv6_BH_in_HMM(node7_s2_bgw_1,str(P3_dict['v6_addr'])):
                log.info('Mac BH route is proper in HMM on  S1_BGW1')
            else:
                log.info('Mac BH route is improper in HMM on  S1_BGW1')
                self.failed('Mac BH route is improper in HMM on  S1_BGW1')
        
         
        except Exception as error:
            log.debug("Unable to configure static BH mac route on Remote Vtep- Encountered Exception " + str(error))
            self.errored('Exception occurred while configuring static BH mac route on Remote Vtep')

    @aetest.test
    def Verify_BH_states_in_AM(self, testscript,testbed):
        node3_s1_bgw_1 = testbed.devices['node3_s1_bgw_1']
        node7_s2_bgw_1 = testbed.devices['node7_s2_bgw_1']
        P3_dict = AcceSW_TGEN_data

        try:        
            if verify_Ipv6_BH_in_AM(node7_s2_bgw_1,str(P3_dict['mac']),str(P3_dict['vlan_id']),str(P3_dict['v6_addr'])):
                log.info('Mac BH route is proper in AM on  S1_BGW1')
            else:
                log.info('Mac BH route is improper in AM on  S1_BGW1')
                self.failed('Mac BH route is improper in AM on  S1_BGW1')
        
        except Exception as error:
            log.debug("Unable to configure static BH mac route on Remote Vtep- Encountered Exception " + str(error))
            self.errored('Exception occurred while configuring static BH mac route on Remote Vtep')
    
        
    @aetest.test
    def Verify_Mac_BH_Route_on_L2FM_BGP_L2RIB(self,testscript,testbed):
        node3_s1_bgw_1 =testbed.devices['node3_s1_bgw_1']
        node7_s2_bgw_1 = testbed.devices['node7_s2_bgw_1']
        P3_dict = AcceSW_TGEN_data      
        # Verifying L2FM

        try:
            ###S1_BGW1_MAC_BH_ROUTE
            if verify_BH_route_in_L2FM(node3_s1_bgw_1,str(P3_dict['vlan_id']),str(P3_dict['mac'])):
                log.info('Mac BH route is proper in L2FM on  S1_BGw1')
            else:
                log.info('Mac BH route is improper in L2FM on  S1_BGw1')
                self.failed('Mac BH route is improper in L2FM on  S1_BGw1')

            ###S2_BGW1_MAC_BH_ROUTE Remote Vtep
            if verify_BH_route_in_L2FM(node7_s2_bgw_1,str(P3_dict['vlan_id']),str(P3_dict['mac'])):
                log.info('Mac BH route is proper in L2FM on  S2_BGw1')
            else:
                log.info('Mac BH route is improper in L2FM on  S2_BGw1')
                self.failed('Mac BH route is improper in L2FM on  S2_BGw1')

        except Exception as error:
            log.debug("Unable to verify BH mac route in L2FM - Encountered Exception " + str(error))
            self.errored('Exception occurred while verifying BH mac route in L2FM')        

        #Verifying L2RIB
        try:
            #S1_Leaf_Mac_BH_route
            if verify_L2rib_mac_ip_output(node3_s1_bgw_1,str(P3_dict['vlan_id']),str(P3_dict['mac'])):
                log.info('Mac BH route is proper in L2RIB on S1_Leaf')
            else:
                log.debug('Mac BH route is improper in L2RIB on  S1_Leaf')
                self.failed('Mac BH route is improper in L2RIB on  S1_Leaf')

            #S2_BGW1_Mac_BH_route
            if verify_L2rib_mac_ip_output(node7_s2_bgw_1,str(P3_dict['vlan_id']),str(P3_dict['mac'])):
                log.info('Mac BH route is proper in L2RIB on S2_BGW1')
            else:
                log.debug('Mac BH route is improper in L2RIB on  S2_BGW1')
                self.errored('Mac BH route is improper in L2RIB on  S2_BGW1')
        
        except Exception as error:
            log.debug("Unable to verify BH mac route in L2RIB - Encountered Exception " + str(error))
            self.errored('Exception occurred while verifying BH mac route in L2RIB')
        
        #Verifying BGP
        try:
            #S2_BGW1_Mac_BH_route
            if verify_BH_in_Remote_BGP(node7_s2_bgw_1,str(P3_dict['mac'])):
                log.info('Mac BH route is proper in BGP on S2_BGW1')
            else:
                log.debug('Mac BH route is improper in BGP on  S2_BGW1')
                self.errored('Mac BH route is improper in BGP on  S2_BGW1')

            #Access_Mac_BH_route
            if verify_BH_in_Remote_BGP(node3_s1_bgw_1,str(P3_dict['mac'])):
                log.info('Mac BH route is proper in BGP on Access')
            else:
                log.debug('Mac BH route is improper in BGP on  Access')
                self.errored('Mac BH route is improper in BGP on  Access')
        
        except Exception as error:
            log.debug("Unable to verify BH mac route in BGP - Encountered Exception " + str(error))
            self.errored('Exception occurred while verifying BH mac route in BGP')

    @aetest.test
    def Verify_Ipv6_icmp_neighbor(self,testbed):
        node3_s1_bgw_1 = testbed.devices['node3_s1_bgw_1']
        node7_s2_bgw_1 = testbed.devices['node7_s2_bgw_1']
        P3_dict = AcceSW_TGEN_data
        
        try:
            ###S1_BGW1_MAC_BH_ROUTE
            if Verify_ipv6_local_neighbor(node7_s2_bgw_1,str(P3_dict['mac']),str(P3_dict['vlan_id'])):
                log.info('Mac BH route is proper in ICMP neighbor on  S1_BGw1')
            else:
                log.info('Mac BH route is improper in ICMP neighbor on  S1_BGw1')
                self.failed('Mac BH route is improper in ICMP neighbor on  S1_BGw1')

            if verify_icmp_static_remote_neighbor(node3_s1_bgw_1,str(P3_dict['mac'])):
                log.info('Mac BH route is proper in ICMP neighbor on  S1_BGw1')
            else:
                log.info('Mac BH route is improper in ICMP neighbor on  S1_BGw1')
                self.failed('Mac BH route is improper in ICMP neighbor on  S1_BGw1')
        
        except Exception as error:
            log.debug("Unable to verify BH mac route in ICMP neighbor - Encountered Exception " + str(error))
            self.errored('Exception occurred while verifying BH mac route in ICMP neighbor')   

    @aetest.test
    def UnConfig_Mac_BH_Static_ND_on_RemoteVtep(self,testscript,testbed):
        node7_s2_bgw_1 = testbed.devices['node7_s2_bgw_1']
        P3_dict = AcceSW_TGEN_data
        mac= str(P3_dict['mac'])
        vlan= str(P3_dict['vlan_id'])
        ipv6=str(P3_dict['v6_addr'])
        octet = 2
        no_int= int(P3_dict['no_of_ints'])
        
        for i in range (0,no_int):
            ###LEAF_3_MAC_BH_ROUTE
            testbed.devices['node7_s2_bgw_1'].configure('''
                no mac address-table static ''' + str(mac) + ''' vlan '''+ str(vlan) + ''' drop

                interface vlan ''' + str(vlan) + '''
                  no ipv6 neighbor ''' + str(ipv6) + ''' ''' + str(mac) + '''
            ''')
            lasthex=incr_mac(mac)
            mac=mac[0:10]+lasthex
            vlan= int(vlan)+int(P3_dict['vlan_id_step'])
            ipv6=incr_ipv6(ipv6,octet) 

    @aetest.test
    def VERIFY_IXIA_TRAFFIC_after_rmBH_Route(self, testscript):
        """ IXIA_CONFIGURATION subsection: Verify IXIA Traffic """

        # Do not perform configurations if skip_tgen_config flag is set
        #if not testscript.parameters['script_flags']['skip_tgen_config']:

        time.sleep(30)

        if ixLib.verify_traffic(1) == 1:
            log.debug("Traffic Verification Passed.Expecting traffic loss here.") 
        else:
            log.info("Traffic Verification Failed. Expecting traffic loss here.")
            self.failed("Traffic Verification failed")
        # else:
        #     self.passed(reason="Skipped TGEN Configurations as per request")
    
    @aetest.cleanup
    def cleanup(self,testscript,testbed):
        """Unconfigure qos policies"""
        node3_s1_bgw_1 = testbed.devices['node3_s1_bgw_1']
        node5_s1_leaf_1 = testbed.devices['node5_s1_leaf_1']
        node10_s1_AccessSW =testbed.devices['node10_s1_AccessSW']
        node7_s2_bgw_1 =testbed.devices['node7_s2_bgw_1']
        P3_dict = AcceSW_TGEN_data
        forwardingSysDict = FWD_SYS_dict
        try:
            # Stop Traffic from ixia
            log.info("--- Stopping Traffic ---- \n")
            log.info("Stopping Traffic")
            traffic_run_status = ixLib.stop_traffic()
            
            if traffic_run_status is not 1:
               log.info("Failed: To Stop traffic")
               return 0
            else:
                log.info("\nTraffic Stopped successfully\n")
            time.sleep(10)
            ####Remove traffic item configured
            UCAST_v6_dict_1 = {
                            'mode'        : 'remove',
                            'stream_id'   : stream_id,
                      }
            if (ixLib.delete_traffic_item(UCAST_v6_dict_1))==0:
                log.debug("Traffic Remove failed")
                self.failed("Traffic Remove failed", goto=['next_tc'])
            else:
                log.info("Traffic Remove Passed")
            UCAST_v6_dict_2 = {
                            'mode'        : 'remove',
                            'stream_id'   : stream_id_1,
                      }
            if (ixLib.delete_traffic_item(UCAST_v6_dict_2))==0:
                log.debug("Traffic Remove failed")
                self.failed("Traffic Remove failed", goto=['next_tc'])
            else:
                log.info("Traffic Remove Passed")
            UCAST_v6_dict_3 = {
                            'mode'        : 'remove',
                            'stream_id'   : stream_id_2,
                      }
            if (ixLib.delete_traffic_item(UCAST_v6_dict_3))==0:
                log.debug("Traffic Remove failed")
                self.failed("Traffic Remove failed", goto=['next_tc'])
            else:
                log.info("Traffic Remove Passed")
            ###LEAF_1_MAC_BH_ROUTE
            testbed.devices['node7_s2_bgw_1'].configure(''' 
            
               no mac address-table static ''' + str(P3_dict['mac']) + ''' vlan '''+ str(P3_dict['vlan_id']) + ''' drop

                interface vlan ''' + str(P3_dict['vlan_id']) + '''
                  no ipv6 neighbor ''' + str(P3_dict['v6_addr']) + ''' ''' + str(P3_dict['mac']) + '''
                
            ''')
        except Exception as error:
            log.debug("Unable to do cleanup " + str(error))
            self.errored('Exception occurred during cleanup', goto=['next_tc'])    

    
class ND_MAC_BH_route_on_vpc_vtep_then_start_traffic(nxtest.Testcase):
    #"TC_0038_ND_MAC_BH_route_on_vpc_vtep_then_start_traffic",
    stream_id=''
    @aetest.test
    def CONFIGURE_L2_UCAST_IXIA_TRAFFIC_With_IPv6_H2_to_H1(self, testscript):
        """ IXIA_CONFIGURATION subsection: Configure MCAST Traffic Item """

        # Do not perform configurations if skip_tgen_config flag is set
        #if not testscript.parameters['script_flags']['skip_tgen_config']:

        IX_TP1 = testscript.parameters['IX_TP1']
        IX_TP2 = testscript.parameters['IX_TP2']
        IX_TP3 = testscript.parameters['IX_TP3']
        IX_TP4 = testscript.parameters['IX_TP4']
        P1_dict = S1_BGW1_TGEN_data
        P2_dict = S1_Leaf_TGEN_data
        P3_dict = AcceSW_TGEN_data
        P4_dict = S2_Leaf_TGEN_data


        UCAST_v6_dict_1 = {   'src_hndl'  : IX_TP1['ipv6_handle'],
                            'dst_hndl'  : IX_TP3['ipv6_handle'],
                            'circuit'   : 'ipv6',
                            'TI_name'   : "UCAST_v6",
                            'rate_pps'  : "1000",
                            'bi_dir'    : 1,
                            'bidirectional': '0'
                        }

        UCAST_v6_TI = ixLib.configure_ixia_traffic_item_v46(UCAST_v6_dict_1)

        if UCAST_v6_TI == 0:
            log.debug("Configuring UCast TI failed")
            self.errored("Configuring UCast TI failed", goto=['next_tc'])   
        
        else:
            global stream_id
            stream_id = UCAST_v6_TI
           
        # else:
        #     self.passed(reason="Skipped TGEN Configurations as per request")
    stream_id_1=''
    @aetest.test
    def CONFIGURE_L2_UCAST_IXIA_TRAFFIC_With_IPv6_H3_to_H1(self, testscript):
        """ IXIA_CONFIGURATION subsection: Configure MCAST Traffic Item """

        # Do not perform configurations if skip_tgen_config flag is set
        #if not testscript.parameters['script_flags']['skip_tgen_config']:

        IX_TP1 = testscript.parameters['IX_TP1']
        IX_TP2 = testscript.parameters['IX_TP2']
        IX_TP3 = testscript.parameters['IX_TP3']
        IX_TP4 = testscript.parameters['IX_TP4']
        P1_dict = S1_BGW1_TGEN_data
        P2_dict = S1_Leaf_TGEN_data
        P3_dict = AcceSW_TGEN_data
        P4_dict = S2_Leaf_TGEN_data

        UCAST_v6_dict_2 = {   'src_hndl'  : IX_TP2['ipv6_handle'],
                            'dst_hndl'  : IX_TP3['ipv6_handle'],
                            'circuit'   : 'ipv6',
                            'TI_name'   : "UCAST_v6",
                            'rate_pps'  : "1000",
                            'bi_dir'    : 1,
                            'bidirectional': '0'
                        }

        UCAST_v6_TI_1 = ixLib.configure_ixia_traffic_item_v46(UCAST_v6_dict_2)

        if UCAST_v6_TI_1 == 0:
            log.debug("Configuring UCast TI failed")
            self.errored("Configuring UCast TI failed", goto=['next_tc'])   
        
        else:
            global stream_id_1
            stream_id_1 = UCAST_v6_TI_1
            
        # else:
        #     self.passed(reason="Skipped TGEN Configurations as per request")
    stream_id_2=''
    @aetest.test
    def CONFIGURE_L2_UCAST_IXIA_TRAFFIC_With_IPv6_H4_to_H1(self, testscript):
        """ IXIA_CONFIGURATION subsection: Configure MCAST Traffic Item """

        # Do not perform configurations if skip_tgen_config flag is set
        #if not testscript.parameters['script_flags']['skip_tgen_config']:

        IX_TP1 = testscript.parameters['IX_TP1']
        IX_TP2 = testscript.parameters['IX_TP2']
        IX_TP3 = testscript.parameters['IX_TP3']
        IX_TP4 = testscript.parameters['IX_TP4']
        P1_dict = S1_BGW1_TGEN_data
        P2_dict = S1_Leaf_TGEN_data
        P3_dict = AcceSW_TGEN_data
        P4_dict = S2_Leaf_TGEN_data


        UCAST_v6_dict_3 = {   'src_hndl'  : IX_TP4['ipv6_handle'],
                            'dst_hndl'  : IX_TP3['ipv6_handle'],
                            'circuit'   : 'ipv6',
                            'TI_name'   : "UCAST_v6",
                            'rate_pps'  : "1000",
                            'bi_dir'    : 1,
                            'bidirectional': '0'
                        }

        UCAST_v6_TI_2 = ixLib.configure_ixia_traffic_item_v46(UCAST_v6_dict_3)

        if UCAST_v6_TI_2 == 0:
            log.debug("Configuring UCast TI failed")
            self.errored("Configuring UCast TI failed", goto=['next_tc'])   
        
        else:
            global stream_id_2
            stream_id_2 = UCAST_v6_TI_2
            
        # else:
        #     self.passed(reason="Skipped TGEN Configurations as per request")

    @aetest.test
    def APPLY_TRAFFIC(self):
        """ IXIA_CONFIGURATION subsection: Verify IXIA Traffic """

        # Apply IXIA Traffic
        if ixLib.apply_traffic() == 1:
            log.info("Applying IXIA TI Passed")
        else:
            self.errored("Applying IXIA TI failed")
    
    @aetest.test
    def VERIFY_IXIA_TRAFFIC_Without_BH_Route(self, testscript):
        """ IXIA_CONFIGURATION subsection: Verify IXIA Traffic """

        # Do not perform configurations if skip_tgen_config flag is set
        #if not testscript.parameters['script_flags']['skip_tgen_config']:

        time.sleep(20)

        if ixLib.verify_traffic(1) == 1:
            log.debug("Traffic Verification Passed.Expecting traffic loss here.") 
        else:
            log.info("Traffic Verification Failed. Expecting traffic loss here.")
            self.failed("Traffic Verification failed")
        # else:
        #     self.passed(reason="Skipped TGEN Configurations as per request")

    @aetest.test
    def Config_Mac_BH_Static_ND_on_vPC_Vtep(self,testscript,testbed):
        node3_s1_bgw_1 = testbed.devices['node3_s1_bgw_1']
        P3_dict = AcceSW_TGEN_data
        mac= str(P3_dict['mac'])
        vlan= str(P3_dict['vlan_id'])
        ipv6=str(P3_dict['v6_addr'])
        octet = 2
        no_int= int(P3_dict['no_of_ints'])
        
        for i in range (0,no_int):
            ###LEAF_3_MAC_BH_ROUTE
            testbed.devices['node3_s1_bgw_1'].configure('''
                mac address-table static ''' + str(mac) + ''' vlan '''+ str(vlan) + ''' drop

                interface vlan ''' + str(vlan) + '''
                    ipv6 neighbor ''' + str(ipv6) + ''' ''' + str(mac) + '''
            ''')
        
            testbed.devices['node4_s1_bgw_2'].configure('''
                mac address-table static ''' + str(mac) + ''' vlan '''+ str(vlan) + ''' drop

                interface vlan ''' + str(vlan) + '''
                    ipv6 neighbor ''' + str(ipv6) + ''' ''' + str(mac) + '''
            ''')
            lasthex=incr_mac(mac)
            mac=mac[0:10]+lasthex
            vlan= int(vlan)+int(P3_dict['vlan_id_step'])
            ipv6=incr_ipv6(ipv6,octet) 

    @aetest.test
    def APPLY_TRAFFIC(self):
        """ IXIA_CONFIGURATION subsection: Verify IXIA Traffic """

        # Apply IXIA Traffic
        if ixLib.apply_traffic() == 1:
            log.info("Applying IXIA TI Passed")
        else:
            self.errored("Applying IXIA TI failed")
    
    @aetest.test
    def VERIFY_IXIA_TRAFFIC_With_BH_Route(self, testscript):
        """ IXIA_CONFIGURATION subsection: Verify IXIA Traffic """

        # Do not perform configurations if skip_tgen_config flag is set
        #if not testscript.parameters['script_flags']['skip_tgen_config']:

        time.sleep(20)

        if ixLib.verify_traffic(99) == 0:
            log.debug("Traffic Verification Passed.Expecting traffic loss here.") 
        else:
            log.info("Traffic Verification Failed. Expecting traffic loss here.")
            self.failed("Traffic Verification failed")
        # else:
        #     self.passed(reason="Skipped TGEN Configurations as per request")
    
    @aetest.test
    def Verify_Traffic_Drop_on_Remote_Vtep(self,testscript,testbed):
        node5_s1_leaf_1 = testbed.devices['node5_s1_leaf_1']
        node9_s2_leaf_1 = testbed.devices['node9_s2_leaf_1']
        node7_s2_bgw_1 = testbed.devices['node7_s2_bgw_1']
        P3_dict = AcceSW_TGEN_data
        uplink_PO=S1_Leaf_dict['S1_Leaf_UPLINK_PO']['po_id']
        if verify_traffic_drop(node5_s1_leaf_1,uplink_PO):
            log.info('Traffic correctly dropped on  S1_Leaf')
        else:
            log.info('Traffic NOT dropped on  S1_Leaf')
            self.failed('Traffic NOT dropped on  S1_Leaf')
        
        uplink_PO=S2_Leaf_dict['S2_Leaf_UPLINK_PO']['po_id']
        if verify_traffic_drop(node9_s2_leaf_1,uplink_PO):
            log.info('Traffic correctly dropped on  S2_Leaf')
        else:
            log.info('Traffic NOT dropped on  S2_Leaf')
            self.failed('Traffic NOT dropped on  S2_Leaf')

        uplink_PO=S2_BGW1_dict['S2_BGW1_UPLINK_PO']['po_id']
        if verify_traffic_drop(node7_s2_bgw_1,uplink_PO):
            log.info('Traffic correctly dropped on  S2_BGW1')
        else:
            log.info('Traffic NOT dropped on  S2_BGW1')
            self.failed('Traffic NOT dropped on  S2_BGW1')

    @aetest.test
    def verify_static_mac_states(self, testscript,testbed):
        node3_s1_bgw_1 = testbed.devices['node3_s1_bgw_1']
        node7_s2_bgw_1 = testbed.devices['node7_s2_bgw_1']
        P3_dict = AcceSW_TGEN_data
        if verify_static_mac(node3_s1_bgw_1,str(P3_dict['mac']),str(P3_dict['vlan_id'])):
            log.info('proper dynaic mac learnt as static on S1_BGw1')
        else:
            log.info('improper dynamic mac learnt on  S1_BGw1')
            self.failed('improper dynamic mac learnt on  S1_BGw1')

        if verify_static_mac(node7_s2_bgw_1,str(P3_dict['mac']),str(P3_dict['vlan_id'])):
            log.info('proper dynaic mac learnt on  S2_BGw1')
        else:
            log.info('improper dynamic mac learnt on S2_BGw1')
            self.failed('improper dynamic mac learnt on  S2_BGw1')
    
    
    @aetest.test
    def Verify_BH_states_in_HMM(self, testscript,testbed):
        node3_s1_bgw_1 =testbed.devices['node3_s1_bgw_1']
        node7_s2_bgw_1 = testbed.devices['node7_s2_bgw_1']
        P3_dict = AcceSW_TGEN_data
        try:
            if verify_Ipv6_BH_in_HMM(node3_s1_bgw_1,str(P3_dict['v6_addr'])):
                log.info('Mac BH route is proper in HMM on  S1_BGW1')
            else:
                log.info('Mac BH route is improper in HMM on  S1_BGW1')
                self.failed('Mac BH route is improper in HMM on  S1_BGW1')
        
         
        except Exception as error:
            log.debug("Unable to configure static BH mac route on Remote Vtep- Encountered Exception " + str(error))
            self.errored('Exception occurred while configuring static BH mac route on Remote Vtep')

    @aetest.test
    def Verify_BH_states_in_AM(self, testscript,testbed):
        node3_s1_bgw_1 = testbed.devices['node3_s1_bgw_1']
        node7_s2_bgw_1 = testbed.devices['node7_s2_bgw_1']
        P3_dict = AcceSW_TGEN_data

        try:        
            if verify_Ipv6_BH_in_AM(node3_s1_bgw_1,str(P3_dict['mac']),str(P3_dict['vlan_id']),str(P3_dict['v6_addr'])):
                log.info('Mac BH route is proper in AM on  S1_BGW1')
            else:
                log.info('Mac BH route is improper in AM on  S1_BGW1')
                self.failed('Mac BH route is improper in AM on  S1_BGW1')
        
        except Exception as error:
            log.debug("Unable to configure static BH mac route on Remote Vtep- Encountered Exception " + str(error))
            self.errored('Exception occurred while configuring static BH mac route on Remote Vtep')
        
    @aetest.test
    def Verify_Mac_BH_Route_on_L2FM_BGP_L2RIB(self,testscript,testbed):
        node3_s1_bgw_1 =testbed.devices['node3_s1_bgw_1']
        node7_s2_bgw_1 = testbed.devices['node7_s2_bgw_1']
        P3_dict = AcceSW_TGEN_data      
        # Verifying L2FM

        try:
            ###S1_BGW1_MAC_BH_ROUTE
            if verify_BH_route_in_L2FM(node3_s1_bgw_1,str(P3_dict['vlan_id']),str(P3_dict['mac'])):
                log.info('Mac BH route is proper in L2FM on  S1_BGw1')
            else:
                log.info('Mac BH route is improper in L2FM on  S1_BGw1')
                self.failed('Mac BH route is improper in L2FM on  S1_BGw1')

            ###S2_BGW1_MAC_BH_ROUTE Remote Vtep
            if verify_BH_route_in_L2FM(node7_s2_bgw_1,str(P3_dict['vlan_id']),str(P3_dict['mac'])):
                log.info('Mac BH route is proper in L2FM on  S2_BGw1')
            else:
                log.info('Mac BH route is improper in L2FM on  S2_BGw1')
                self.failed('Mac BH route is improper in L2FM on  S2_BGw1')

        except Exception as error:
            log.debug("Unable to verify BH mac route in L2FM - Encountered Exception " + str(error))
            self.errored('Exception occurred while verifying BH mac route in L2FM')        

        #Verifying L2RIB
        try:
            #S1_Leaf_Mac_BH_route
            if verify_L2rib_mac_ip_output(node3_s1_bgw_1,str(P3_dict['vlan_id']),str(P3_dict['mac'])):
                log.info('Mac BH route is proper in L2RIB on S1_Leaf')
            else:
                log.debug('Mac BH route is improper in L2RIB on  S1_Leaf')
                self.failed('Mac BH route is improper in L2RIB on  S1_Leaf')

            #S2_BGW1_Mac_BH_route
            if verify_L2rib_mac_ip_output(node7_s2_bgw_1,str(P3_dict['vlan_id']),str(P3_dict['mac'])):
                log.info('Mac BH route is proper in L2RIB on S2_BGW1')
            else:
                log.debug('Mac BH route is improper in L2RIB on  S2_BGW1')
                self.errored('Mac BH route is improper in L2RIB on  S2_BGW1')
        
        except Exception as error:
            log.debug("Unable to verify BH mac route in L2RIB - Encountered Exception " + str(error))
            self.errored('Exception occurred while verifying BH mac route in L2RIB')
        
        #Verifying BGP
        try:
            #S2_BGW1_Mac_BH_route
            if verify_BH_in_Remote_BGP(node7_s2_bgw_1,str(P3_dict['mac'])):
                log.info('Mac BH route is proper in BGP on S2_BGW1')
            else:
                log.debug('Mac BH route is improper in BGP on  S2_BGW1')
                self.errored('Mac BH route is improper in BGP on  S2_BGW1')

            #Access_Mac_BH_route
            if verify_BH_in_Remote_BGP(node3_s1_bgw_1,str(P3_dict['mac'])):
                log.info('Mac BH route is proper in BGP on Access')
            else:
                log.debug('Mac BH route is improper in BGP on  Access')
                self.errored('Mac BH route is improper in BGP on  Access')
        
        except Exception as error:
            log.debug("Unable to verify BH mac route in BGP - Encountered Exception " + str(error))
            self.errored('Exception occurred while verifying BH mac route in BGP')
    
    @aetest.test
    def Verify_Ipv6_icmp_neighbor(self,testbed):
        node3_s1_bgw_1 = testbed.devices['node3_s1_bgw_1']
        node7_s2_bgw_1 = testbed.devices['node7_s2_bgw_1']
        P3_dict = AcceSW_TGEN_data
        
        try:
            ###S1_BGW1_MAC_BH_ROUTE
            if Verify_ipv6_local_neighbor(node3_s1_bgw_1,str(P3_dict['mac']),str(P3_dict['vlan_id'])):
                log.info('Mac BH route is proper in ICMP neighbor on  S1_BGw1')
            else:
                log.info('Mac BH route is improper in ICMP neighbor on  S1_BGw1')
                self.failed('Mac BH route is improper in ICMP neighbor on  S1_BGw1')

            if verify_icmp_static_remote_neighbor(node7_s2_bgw_1,str(P3_dict['mac'])):
                log.info('Mac BH route is proper in ICMP neighbor on  S1_BGw1')
            else:
                log.info('Mac BH route is improper in ICMP neighbor on  S1_BGw1')
                self.failed('Mac BH route is improper in ICMP neighbor on  S1_BGw1')
        
        except Exception as error:
            log.debug("Unable to verify BH mac route in ICMP neighbor - Encountered Exception " + str(error))
            self.errored('Exception occurred while verifying BH mac route in ICMP neighbor')   

    @aetest.test
    def UnConfig_Mac_BH_Static_ND_on_vPC_Vtep(self,testscript,testbed):
        node3_s1_bgw_1 = testbed.devices['node3_s1_bgw_1']
        P3_dict = AcceSW_TGEN_data
        mac= str(P3_dict['mac'])
        vlan= str(P3_dict['vlan_id'])
        ipv6=str(P3_dict['v6_addr'])
        octet = 2
        no_int= int(P3_dict['no_of_ints'])
        
        for i in range (0,no_int):
            ###LEAF_3_MAC_BH_ROUTE
            testbed.devices['node3_s1_bgw_1'].configure('''
                no mac address-table static ''' + str(mac) + ''' vlan '''+ str(vlan) + ''' drop

                interface vlan ''' + str(vlan) + '''
                    no ipv6 neighbor ''' + str(ipv6) + ''' ''' + str(mac) + '''
            ''')
        
            testbed.devices['node4_s1_bgw_2'].configure('''
                no mac address-table static ''' + str(mac) + ''' vlan '''+ str(vlan) + ''' drop

                interface vlan ''' + str(vlan) + '''
                    no ipv6 neighbor ''' + str(ipv6) + ''' ''' + str(mac) + '''
            ''')
            lasthex=incr_mac(mac)
            mac=mac[0:10]+lasthex
            vlan= int(vlan)+int(P3_dict['vlan_id_step'])
            ipv6=incr_ipv6(ipv6,octet) 


    @aetest.test
    def VERIFY_IXIA_TRAFFIC_after_rmBH_Route(self, testscript):
        """ IXIA_CONFIGURATION subsection: Verify IXIA Traffic """

        # Do not perform configurations if skip_tgen_config flag is set
        #if not testscript.parameters['script_flags']['skip_tgen_config']:

        time.sleep(20)

        if ixLib.verify_traffic(1) == 1:
            log.debug("Traffic Verification Passed.Expecting traffic loss here.") 
        else:
            log.info("Traffic Verification Failed. Expecting traffic loss here.")
            self.failed("Traffic Verification failed")
        # else:
        #     self.passed(reason="Skipped TGEN Configurations as per request")
    
    @aetest.cleanup
    def cleanup(self,testscript,testbed):
        """Unconfigure qos policies"""
        node3_s1_bgw_1 = testbed.devices['node3_s1_bgw_1']
        node5_s1_leaf_1 = testbed.devices['node5_s1_leaf_1']
        node10_s1_AccessSW =testbed.devices['node10_s1_AccessSW']
        node7_s2_bgw_1 =testbed.devices['node7_s2_bgw_1']
        P3_dict = AcceSW_TGEN_data
        forwardingSysDict = FWD_SYS_dict
        try:
            # Stop Traffic from ixia
            log.info("--- Stopping Traffic ---- \n")
            log.info("Stopping Traffic")
            traffic_run_status = ixLib.stop_traffic()
            
            if traffic_run_status is not 1:
               log.info("Failed: To Stop traffic")
               return 0
            else:
                log.info("\nTraffic Stopped successfully\n")
            time.sleep(10)
            ####Remove traffic item configured
            UCAST_v6_dict_1 = {
                            'mode'        : 'remove',
                            'stream_id'   : stream_id,
                      }
            if (ixLib.delete_traffic_item(UCAST_v6_dict_1))==0:
                log.debug("Traffic Remove failed")
                self.failed("Traffic Remove failed", goto=['next_tc'])
            else:
                log.info("Traffic Remove Passed")
            UCAST_v6_dict_2 = {
                            'mode'        : 'remove',
                            'stream_id'   : stream_id_1,
                      }
            if (ixLib.delete_traffic_item(UCAST_v6_dict_2))==0:
                log.debug("Traffic Remove failed")
                self.failed("Traffic Remove failed", goto=['next_tc'])
            else:
                log.info("Traffic Remove Passed")
            UCAST_v6_dict_3 = {
                            'mode'        : 'remove',
                            'stream_id'   : stream_id_2,
                      }
            if (ixLib.delete_traffic_item(UCAST_v6_dict_3))==0:
                log.debug("Traffic Remove failed")
                self.failed("Traffic Remove failed", goto=['next_tc'])
            else:
                log.info("Traffic Remove Passed")
            ###LEAF_1_MAC_BH_ROUTE
            testbed.devices['node3_s1_bgw_1'].configure(''' 
            
               no mac address-table static ''' + str(P3_dict['mac']) + ''' vlan '''+ str(P3_dict['vlan_id']) + ''' drop

                interface vlan ''' + str(P3_dict['vlan_id']) + '''
                  no ipv6 neighbor ''' + str(P3_dict['v6_addr']) + ''' ''' + str(P3_dict['mac']) + '''
                
            ''')
        except Exception as error:
            log.debug("Unable to do cleanup " + str(error))
            self.errored('Exception occurred during cleanup', goto=['next_tc'])   

class ND_Mac_BH_route_on_standalone_vtep_then_start_traffic(nxtest.Testcase):
    #"TC_0039_ND_Mac_BH_route_on_standalone_vtep_then_start_traffic"
    stream_id=''
    @aetest.test
    def CONFIGURE_L2_UCAST_IXIA_TRAFFIC_With_IPv6_H2_to_H1(self, testscript):
        """ IXIA_CONFIGURATION subsection: Configure MCAST Traffic Item """

        # Do not perform configurations if skip_tgen_config flag is set
        #if not testscript.parameters['script_flags']['skip_tgen_config']:

        IX_TP1 = testscript.parameters['IX_TP1']
        IX_TP2 = testscript.parameters['IX_TP2']
        IX_TP3 = testscript.parameters['IX_TP3']
        IX_TP4 = testscript.parameters['IX_TP4']
        P1_dict = S1_BGW1_TGEN_data
        P2_dict = S1_Leaf_TGEN_data
        P3_dict = AcceSW_TGEN_data
        P4_dict = S2_Leaf_TGEN_data


        UCAST_v6_dict_1 = {   'src_hndl'  : IX_TP1['ipv6_handle'],
                            'dst_hndl'  : IX_TP3['ipv6_handle'],
                            'circuit'   : 'ipv6',
                            'TI_name'   : "UCAST_v6",
                            'rate_pps'  : "1000",
                            'bi_dir'    : 1,
                            'bidirectional': '0'
                        }

        UCAST_v6_TI = ixLib.configure_ixia_traffic_item_v46(UCAST_v6_dict_1)

        if UCAST_v6_TI == 0:
            log.debug("Configuring UCast TI failed")
            self.errored("Configuring UCast TI failed", goto=['next_tc'])   
        
        else:
            global stream_id
            stream_id = UCAST_v6_TI
           
        # else:
        #     self.passed(reason="Skipped TGEN Configurations as per request")
    stream_id_1=''
    @aetest.test
    def CONFIGURE_L2_UCAST_IXIA_TRAFFIC_With_IPv6_H3_to_H1(self, testscript):
        """ IXIA_CONFIGURATION subsection: Configure MCAST Traffic Item """

        # Do not perform configurations if skip_tgen_config flag is set
        #if not testscript.parameters['script_flags']['skip_tgen_config']:

        IX_TP1 = testscript.parameters['IX_TP1']
        IX_TP2 = testscript.parameters['IX_TP2']
        IX_TP3 = testscript.parameters['IX_TP3']
        IX_TP4 = testscript.parameters['IX_TP4']
        P1_dict = S1_BGW1_TGEN_data
        P2_dict = S1_Leaf_TGEN_data
        P3_dict = AcceSW_TGEN_data
        P4_dict = S2_Leaf_TGEN_data

        UCAST_v6_dict_2 = {   'src_hndl'  : IX_TP2['ipv6_handle'],
                            'dst_hndl'  : IX_TP3['ipv6_handle'],
                            'circuit'   : 'ipv6',
                            'TI_name'   : "UCAST_v6",
                            'rate_pps'  : "1000",
                            'bi_dir'    : 1,
                            'bidirectional': '0'
                        }

        UCAST_v6_TI_1 = ixLib.configure_ixia_traffic_item_v46(UCAST_v6_dict_2)

        if UCAST_v6_TI_1 == 0:
            log.debug("Configuring UCast TI failed")
            self.errored("Configuring UCast TI failed", goto=['next_tc'])   
        
        else:
            global stream_id_1
            stream_id_1 = UCAST_v6_TI_1
            
        # else:
        #     self.passed(reason="Skipped TGEN Configurations as per request")
    stream_id_2=''
    @aetest.test
    def CONFIGURE_L2_UCAST_IXIA_TRAFFIC_With_IPv6_H4_to_H1(self, testscript):
        """ IXIA_CONFIGURATION subsection: Configure MCAST Traffic Item """

        # Do not perform configurations if skip_tgen_config flag is set
        #if not testscript.parameters['script_flags']['skip_tgen_config']:

        IX_TP1 = testscript.parameters['IX_TP1']
        IX_TP2 = testscript.parameters['IX_TP2']
        IX_TP3 = testscript.parameters['IX_TP3']
        IX_TP4 = testscript.parameters['IX_TP4']
        P1_dict = S1_BGW1_TGEN_data
        P2_dict = S1_Leaf_TGEN_data
        P3_dict = AcceSW_TGEN_data
        P4_dict = S2_Leaf_TGEN_data


        UCAST_v6_dict_3 = {   'src_hndl'  : IX_TP4['ipv6_handle'],
                            'dst_hndl'  : IX_TP3['ipv6_handle'],
                            'circuit'   : 'ipv6',
                            'TI_name'   : "UCAST_v6",
                            'rate_pps'  : "1000",
                            'bi_dir'    : 1,
                            'bidirectional': '0'
                        }

        UCAST_v6_TI_2 = ixLib.configure_ixia_traffic_item_v46(UCAST_v6_dict_3)

        if UCAST_v6_TI_2 == 0:
            log.debug("Configuring UCast TI failed")
            self.errored("Configuring UCast TI failed", goto=['next_tc'])   
        
        else:
            global stream_id_2
            stream_id_2 = UCAST_v6_TI_2
            
        # else:
        #     self.passed(reason="Skipped TGEN Configurations as per request")

    @aetest.test
    def APPLY_TRAFFIC(self):
        """ IXIA_CONFIGURATION subsection: Verify IXIA Traffic """

        # Apply IXIA Traffic
        if ixLib.apply_traffic() == 1:
            log.info("Applying IXIA TI Passed")
        else:
            self.errored("Applying IXIA TI failed")
    
    @aetest.test
    def VERIFY_IXIA_TRAFFIC_Without_BH_Route(self, testscript):
        """ IXIA_CONFIGURATION subsection: Verify IXIA Traffic """

        # Do not perform configurations if skip_tgen_config flag is set
        #if not testscript.parameters['script_flags']['skip_tgen_config']:

        time.sleep(20)

        if ixLib.verify_traffic(1) == 1:
            log.debug("Traffic Verification Passed.Expecting traffic loss here.") 
        else:
            log.info("Traffic Verification Failed. Expecting traffic loss here.")
            self.failed("Traffic Verification failed")
        # else:
        #     self.passed(reason="Skipped TGEN Configurations as per request")

    @aetest.test
    def Config_Mac_BH_Static_ND_on_RemoteVtep(self,testscript,testbed):
        node7_s2_bgw_1 = testbed.devices['node7_s2_bgw_1']
        P3_dict = AcceSW_TGEN_data
        mac= str(P3_dict['mac'])
        vlan= str(P3_dict['vlan_id'])
        ipv6=str(P3_dict['v6_addr'])
        octet = 2
        no_int= int(P3_dict['no_of_ints'])
        
        for i in range (0,no_int):
            ###LEAF_3_MAC_BH_ROUTE
            testbed.devices['node7_s2_bgw_1'].configure('''
               mac address-table static ''' + str(mac) + ''' vlan '''+ str(vlan) + ''' drop

                interface vlan ''' + str(vlan) + '''
                  ipv6 neighbor ''' + str(ipv6) + ''' ''' + str(mac) + '''
            ''')
            lasthex=incr_mac(mac)
            mac=mac[0:10]+lasthex
            vlan= int(vlan)+int(P3_dict['vlan_id_step'])
            ipv6=incr_ipv6(ipv6,octet)  

    @aetest.test
    def APPLY_TRAFFIC(self):
        """ IXIA_CONFIGURATION subsection: Verify IXIA Traffic """

        # Apply IXIA Traffic
        if ixLib.apply_traffic() == 1:
            log.info("Applying IXIA TI Passed")
        else:
            self.errored("Applying IXIA TI failed")
    
    @aetest.test
    def VERIFY_IXIA_TRAFFIC_With_BH_Route(self, testscript):
        """ IXIA_CONFIGURATION subsection: Verify IXIA Traffic """

        # Do not perform configurations if skip_tgen_config flag is set
        #if not testscript.parameters['script_flags']['skip_tgen_config']:

        time.sleep(20)

        if ixLib.verify_traffic(99) == 0:
            log.debug("Traffic Verification Passed.Expecting traffic loss here.") 
        else:
            log.info("Traffic Verification Failed. Expecting traffic loss here.")
            self.failed("Traffic Verification failed")
        # else:
        #     self.passed(reason="Skipped TGEN Configurations as per request")
    
    @aetest.test
    def Verify_Traffic_Drop_on_Remote_Vtep(self,testscript,testbed):
        node5_s1_leaf_1 = testbed.devices['node5_s1_leaf_1']
        node9_s2_leaf_1 = testbed.devices['node9_s2_leaf_1']
        node3_s1_bgw_1 = testbed.devices['node3_s1_bgw_1']
        P3_dict = AcceSW_TGEN_data
        uplink_PO=S1_Leaf_dict['S1_Leaf_UPLINK_PO']['po_id']
        if verify_traffic_drop(node5_s1_leaf_1,uplink_PO):
            log.info('Traffic correctly dropped on  S1_Leaf')
        else:
            log.info('Traffic NOT dropped on  S1_Leaf')
            self.failed('Traffic NOT dropped on  S1_Leaf')
        
        uplink_PO=S2_Leaf_dict['S2_Leaf_UPLINK_PO']['po_id']
        if verify_traffic_drop(node9_s2_leaf_1,uplink_PO):
            log.info('Traffic correctly dropped on  S2_Leaf')
        else:
            log.info('Traffic NOT dropped on  S2_Leaf')
            self.failed('Traffic NOT dropped on  S2_Leaf')

        uplink_PO=S1_BGW1_dict['S1_BGW1_UPLINK_PO']['po_id']
        if verify_traffic_drop(node3_s1_bgw_1,uplink_PO):
            log.info('Traffic correctly dropped on  S1_BGW1')
        else:
            log.info('Traffic NOT dropped on  S1_BGW1')
            self.failed('Traffic NOT dropped on  S1_BGW1')

    @aetest.test
    def verify_static_mac_states(self, testscript,testbed):
        node3_s1_bgw_1 = testbed.devices['node3_s1_bgw_1']
        node7_s2_bgw_1 = testbed.devices['node7_s2_bgw_1']
        P3_dict = AcceSW_TGEN_data
        if verify_static_mac(node3_s1_bgw_1,str(P3_dict['mac']),str(P3_dict['vlan_id'])):
            log.info('proper dynaic mac learnt as static on S1_BGw1')
        else:
            log.info('improper dynamic mac learnt on  S1_BGw1')
            self.failed('improper dynamic mac learnt on  S1_BGw1')

        if verify_static_mac(node7_s2_bgw_1,str(P3_dict['mac']),str(P3_dict['vlan_id'])):
            log.info('proper dynaic mac learnt on  S2_BGw1')
        else:
            log.info('improper dynamic mac learnt on S2_BGw1')
            self.failed('improper dynamic mac learnt on  S2_BGw1')

    
    @aetest.test
    def Verify_BH_states_in_HMM(self, testscript,testbed):
        node3_s1_bgw_1 =testbed.devices['node3_s1_bgw_1']
        node7_s2_bgw_1 = testbed.devices['node7_s2_bgw_1']
        P3_dict = AcceSW_TGEN_data
        try:
            if verify_Ipv6_BH_in_HMM(node7_s2_bgw_1,str(P3_dict['v6_addr'])):
                log.info('Mac BH route is proper in HMM on  S1_BGW1')
            else:
                log.info('Mac BH route is improper in HMM on  S1_BGW1')
                self.failed('Mac BH route is improper in HMM on  S1_BGW1')
        
         
        except Exception as error:
            log.debug("Unable to configure static BH mac route on Remote Vtep- Encountered Exception " + str(error))
            self.errored('Exception occurred while configuring static BH mac route on Remote Vtep')

    @aetest.test
    def Verify_BH_states_in_AM(self, testscript,testbed):
        node3_s1_bgw_1 = testbed.devices['node3_s1_bgw_1']
        node7_s2_bgw_1 = testbed.devices['node7_s2_bgw_1']
        P3_dict = AcceSW_TGEN_data

        try:        
            if verify_Ipv6_BH_in_AM(node7_s2_bgw_1,str(P3_dict['mac']),str(P3_dict['vlan_id']),str(P3_dict['v6_addr'])):
                log.info('Mac BH route is proper in AM on  S1_BGW1')
            else:
                log.info('Mac BH route is improper in AM on  S1_BGW1')
                self.failed('Mac BH route is improper in AM on  S1_BGW1')
        
        except Exception as error:
            log.debug("Unable to configure static BH mac route on Remote Vtep- Encountered Exception " + str(error))
            self.errored('Exception occurred while configuring static BH mac route on Remote Vtep')
        
    @aetest.test
    def Verify_Mac_BH_Route_on_L2FM_BGP_L2RIB(self,testscript,testbed):
        node3_s1_bgw_1 =testbed.devices['node3_s1_bgw_1']
        node7_s2_bgw_1 = testbed.devices['node7_s2_bgw_1']
        P3_dict = AcceSW_TGEN_data      
        # Verifying L2FM

        try:
            ###S1_BGW1_MAC_BH_ROUTE
            if verify_BH_route_in_L2FM(node3_s1_bgw_1,str(P3_dict['vlan_id']),str(P3_dict['mac'])):
                log.info('Mac BH route is proper in L2FM on  S1_BGw1')
            else:
                log.info('Mac BH route is improper in L2FM on  S1_BGw1')
                self.failed('Mac BH route is improper in L2FM on  S1_BGw1')

            ###S2_BGW1_MAC_BH_ROUTE Remote Vtep
            if verify_BH_route_in_L2FM(node7_s2_bgw_1,str(P3_dict['vlan_id']),str(P3_dict['mac'])):
                log.info('Mac BH route is proper in L2FM on  S2_BGw1')
            else:
                log.info('Mac BH route is improper in L2FM on  S2_BGw1')
                self.failed('Mac BH route is improper in L2FM on  S2_BGw1')

        except Exception as error:
            log.debug("Unable to verify BH mac route in L2FM - Encountered Exception " + str(error))
            self.errored('Exception occurred while verifying BH mac route in L2FM')        

        #Verifying L2RIB
        try:
            #S1_Leaf_Mac_BH_route
            if verify_L2rib_mac_ip_output(node3_s1_bgw_1,str(P3_dict['vlan_id']),str(P3_dict['mac'])):
                log.info('Mac BH route is proper in L2RIB on S1_Leaf')
            else:
                log.debug('Mac BH route is improper in L2RIB on  S1_Leaf')
                self.failed('Mac BH route is improper in L2RIB on  S1_Leaf')

            #S2_BGW1_Mac_BH_route
            if verify_L2rib_mac_ip_output(node7_s2_bgw_1,str(P3_dict['vlan_id']),str(P3_dict['mac'])):
                log.info('Mac BH route is proper in L2RIB on S2_BGW1')
            else:
                log.debug('Mac BH route is improper in L2RIB on  S2_BGW1')
                self.errored('Mac BH route is improper in L2RIB on  S2_BGW1')
        
        except Exception as error:
            log.debug("Unable to verify BH mac route in L2RIB - Encountered Exception " + str(error))
            self.errored('Exception occurred while verifying BH mac route in L2RIB')
        
        #Verifying BGP
        try:
            #S2_BGW1_Mac_BH_route
            if verify_BH_in_Remote_BGP(node7_s2_bgw_1,str(P3_dict['mac'])):
                log.info('Mac BH route is proper in BGP on S2_BGW1')
            else:
                log.debug('Mac BH route is improper in BGP on  S2_BGW1')
                self.errored('Mac BH route is improper in BGP on  S2_BGW1')

            #Access_Mac_BH_route
            if verify_BH_in_Remote_BGP(node3_s1_bgw_1,str(P3_dict['mac'])):
                log.info('Mac BH route is proper in BGP on Access')
            else:
                log.debug('Mac BH route is improper in BGP on  Access')
                self.errored('Mac BH route is improper in BGP on  Access')
        
        except Exception as error:
            log.debug("Unable to verify BH mac route in BGP - Encountered Exception " + str(error))
            self.errored('Exception occurred while verifying BH mac route in BGP')
        
    @aetest.test
    def Verify_Ipv6_icmp_neighbor(self,testbed):
        node3_s1_bgw_1 = testbed.devices['node3_s1_bgw_1']
        node7_s2_bgw_1 = testbed.devices['node7_s2_bgw_1']
        P3_dict = AcceSW_TGEN_data
        
        try:
            ###S1_BGW1_MAC_BH_ROUTE
            if Verify_ipv6_local_neighbor(node7_s2_bgw_1,str(P3_dict['mac']),str(P3_dict['vlan_id'])):
                log.info('Mac BH route is proper in ICMP neighbor on  S1_BGw1')
            else:
                log.info('Mac BH route is improper in ICMP neighbor on  S1_BGw1')
                self.failed('Mac BH route is improper in ICMP neighbor on  S1_BGw1')

            if verify_icmp_static_remote_neighbor(node3_s1_bgw_1,str(P3_dict['mac'])):
                log.info('Mac BH route is proper in ICMP neighbor on  S1_BGw1')
            else:
                log.info('Mac BH route is improper in ICMP neighbor on  S1_BGw1')
                self.failed('Mac BH route is improper in ICMP neighbor on  S1_BGw1')
        
        except Exception as error:
            log.debug("Unable to verify BH mac route in ICMP neighbor - Encountered Exception " + str(error))
            self.errored('Exception occurred while verifying BH mac route in ICMP neighbor')   

    @aetest.test
    def UnConfig_Mac_BH_Static_ND_on_RemoteVtep(self,testscript,testbed):
        node7_s2_bgw_1 = testbed.devices['node7_s2_bgw_1']
        P3_dict = AcceSW_TGEN_data
        mac= str(P3_dict['mac'])
        vlan= str(P3_dict['vlan_id'])
        ipv6=str(P3_dict['v6_addr'])
        octet = 2
        no_int= int(P3_dict['no_of_ints'])
        
        for i in range (0,no_int):
            ###LEAF_3_MAC_BH_ROUTE
            testbed.devices['node7_s2_bgw_1'].configure('''
               no mac address-table static ''' + str(mac) + ''' vlan '''+ str(vlan) + ''' drop

                interface vlan ''' + str(vlan) + '''
                  no ipv6 neighbor ''' + str(ipv6) + ''' ''' + str(mac) + '''
            ''')
            lasthex=incr_mac(mac)
            mac=mac[0:10]+lasthex
            vlan= int(vlan)+int(P3_dict['vlan_id_step'])
            ipv6=incr_ipv6(ipv6,octet)  

    @aetest.test
    def VERIFY_IXIA_TRAFFIC_after_rmBH_Route(self, testscript):
        """ IXIA_CONFIGURATION subsection: Verify IXIA Traffic """

        # Do not perform configurations if skip_tgen_config flag is set
        #if not testscript.parameters['script_flags']['skip_tgen_config']:

        time.sleep(20)

        if ixLib.verify_traffic(1) == 1:
            log.debug("Traffic Verification Passed.Expecting traffic loss here.") 
        else:
            log.info("Traffic Verification Failed. Expecting traffic loss here.")
            self.failed("Traffic Verification failed")
        # else:
        #     self.passed(reason="Skipped TGEN Configurations as per request")
    

    @aetest.cleanup
    def cleanup(self,testscript,testbed):
        """Unconfigure qos policies"""
        node3_s1_bgw_1 = testbed.devices['node3_s1_bgw_1']
        node5_s1_leaf_1 = testbed.devices['node5_s1_leaf_1']
        node10_s1_AccessSW =testbed.devices['node10_s1_AccessSW']
        node7_s2_bgw_1 =testbed.devices['node7_s2_bgw_1']
        P3_dict = AcceSW_TGEN_data
        forwardingSysDict = FWD_SYS_dict
        try:
            # Stop Traffic from ixia
            log.info("--- Stopping Traffic ---- \n")
            log.info("Stopping Traffic")
            traffic_run_status = ixLib.stop_traffic()
            
            if traffic_run_status is not 1:
               log.info("Failed: To Stop traffic")
               return 0
            else:
                log.info("\nTraffic Stopped successfully\n")
            time.sleep(10)
            ####Remove traffic item configured
            UCAST_v6_dict_1 = {
                            'mode'        : 'remove',
                            'stream_id'   : stream_id,
                      }
            if (ixLib.delete_traffic_item(UCAST_v6_dict_1))==0:
                log.debug("Traffic Remove failed")
                self.failed("Traffic Remove failed", goto=['next_tc'])
            else:
                log.info("Traffic Remove Passed")
            UCAST_v6_dict_2 = {
                            'mode'        : 'remove',
                            'stream_id'   : stream_id_1,
                      }
            if (ixLib.delete_traffic_item(UCAST_v6_dict_2))==0:
                log.debug("Traffic Remove failed")
                self.failed("Traffic Remove failed", goto=['next_tc'])
            else:
                log.info("Traffic Remove Passed")
            UCAST_v6_dict_3 = {
                            'mode'        : 'remove',
                            'stream_id'   : stream_id_2,
                      }
            if (ixLib.delete_traffic_item(UCAST_v6_dict_3))==0:
                log.debug("Traffic Remove failed")
                self.failed("Traffic Remove failed", goto=['next_tc'])
            else:
                log.info("Traffic Remove Passed")
            ###LEAF_1_MAC_BH_ROUTE
            testbed.devices['node7_s2_bgw_1'].configure(''' 
            
               no mac address-table static ''' + str(P3_dict['mac']) + ''' vlan '''+ str(P3_dict['vlan_id']) + ''' drop

                interface vlan ''' + str(P3_dict['vlan_id']) + '''
                  no ipv6 neighbor ''' + str(P3_dict['v6_addr']) + ''' ''' + str(P3_dict['mac']) + '''
                
            ''')
        except Exception as error:
            log.debug("Unable to do cleanup " + str(error))
            self.errored('Exception occurred during cleanup', goto=['next_tc'])   

###################################################################
###              L3 Ucast with IPv4 header  Test-cases          ###
###################################################################

class Mac_BH_route_static_arp_on_vpc_ctep_with_L3_traffic(nxtest.Testcase):
    #"TC_0041_Mac_BH_route_static_arp_on_vpc_vtep_with_L3_traffic"
    stream_id=''
    @aetest.test
    def CONFIGURE_UCAST_L3_IXIA_TRAFFIC_H2_to_H1_(self, testscript):
        """ IXIA_CONFIGURATION subsection: Configure MCAST Traffic Item """

        # Do not perform configurations if skip_tgen_config flag is set
        #if not testscript.parameters['script_flags']['skip_tgen_config']:

        IX_TP1 = testscript.parameters['IX_TP1']
        IX_TP2 = testscript.parameters['IX_TP2']
        IX_TP3 = testscript.parameters['IX_TP3']
        IX_TP4 = testscript.parameters['IX_TP4']
        P1_dict = S1_BGW1_TGEN_data
        P2_dict = S1_Leaf_TGEN_data
        P3_dict = AcceSW_TGEN_data
        P4_dict = S2_Leaf_TGEN_data


        UCAST_v4_dict_1 = {   'src_hndl'  : IX_TP1['port_handle'],
                            'dst_hndl'  : IX_TP3['port_handle'],
                            'circuit'   : 'raw',
                            'TI_name'   : "UCAST_v4",
                            'rate_pps'  : "9000",
                            'bi_dir'    : 0,
                            'frame_size': '128',
                            'src_mac'   : P1_dict['mac'],
                            'dst_mac'   : '0000.000a.aaaa',
                            'srcmac_step': '00:00:00:00:00:00',
                            'dstmac_step': '00:00:00:00:00:00',
                            'srcmac_count': '1',
                            'dstmac_count': '1',
                            'vlan_id'    : P1_dict['vlan_id'],
                            'vlanid_step': '0',
                            'vlanid_count': '1',
                            'vlan_user_priority': P1_dict['vlan_user_priority'],
                            'ip_src_addrs' : P1_dict['v4_addr'],
                            'ip_dst_addrs' : P3_dict['L3_dst_addr'],
                            'ip_src_step' : '0.0.0.0',
                            'ip_dscp'     : P1_dict['ip_dscp'],
                            'ip_dst_step' : '0.0.0.0',
#                                'ip_step'    : P1_dict['v4_addr_step'],
                        }

        UCAST_v4_TI = ixLib.configure_ixia_l3_traffic_item(UCAST_v4_dict_1)
            
        if UCAST_v4_TI == 0:
            log.debug("Configuring UCast TI failed")
            self.errored("Configuring UCast TI failed")
        else:
            global stream_id
            stream_id = UCAST_v4_TI

        # else:
        #     self.passed(reason="Skipped TGEN Configurations as per request")
    stream_id_1=''
    @aetest.test
    def CONFIGURE_UCAST_L3_IXIA_TRAFFIC_H3_to_H1_(self, testscript):
        """ IXIA_CONFIGURATION subsection: Configure MCAST Traffic Item """

        # Do not perform configurations if skip_tgen_config flag is set
        #if not testscript.parameters['script_flags']['skip_tgen_config']:

        IX_TP1 = testscript.parameters['IX_TP1']
        IX_TP2 = testscript.parameters['IX_TP2']
        IX_TP3 = testscript.parameters['IX_TP3']
        IX_TP4 = testscript.parameters['IX_TP4']
        P1_dict = S1_BGW1_TGEN_data
        P2_dict = S1_Leaf_TGEN_data
        P3_dict = AcceSW_TGEN_data
        P4_dict = S2_Leaf_TGEN_data


        UCAST_v4_dict_2 = {   'src_hndl'  : IX_TP2['port_handle'],
                            'dst_hndl'  : IX_TP3['port_handle'],
                            'circuit'   : 'raw',
                            'TI_name'   : "UCAST_v4",
                            'rate_pps'  : "9000",
                            'bi_dir'    : 0,
                            'frame_size': '128',
                            'src_mac'   : P2_dict['mac'],
                            'dst_mac'   : '0000.000a.aaaa',
                            'srcmac_step': '00:00:00:00:00:00',
                            'dstmac_step': '00:00:00:00:00:00',
                            'srcmac_count': '1',
                            'dstmac_count': '1',
                            'vlan_id'    : P2_dict['vlan_id'],
                            'vlanid_step': '0',
                            'vlanid_count': '2',
                            'vlan_user_priority': P2_dict['vlan_user_priority'],
                            'ip_src_addrs' : P2_dict['v4_addr'],
                            'ip_dst_addrs' : P3_dict['L3_dst_addr'],
                            'ip_src_step' : '0.0.0.0',
                            'ip_dscp'     : P2_dict['ip_dscp'],
                            'ip_dst_step' : '0.0.0.0',
#                                'ip_step'    : P1_dict['v4_addr_step'],
                        }

        UCAST_v4_TI_1 = ixLib.configure_ixia_l3_traffic_item(UCAST_v4_dict_2)
            
        if UCAST_v4_TI_1 == 0:
            log.debug("Configuring UCast TI failed")
            self.errored("Configuring UCast TI failed", goto=['cleanup'])
        else:
            global stream_id_1
            stream_id_1 = UCAST_v4_TI_1

        # else:
        #     self.passed(reason="Skipped TGEN Configurations as per request")
    stream_id_2=''
    @aetest.test
    def CONFIGURE_UCAST_L3_IXIA_TRAFFIC_H4_to_H1_(self, testscript):
        """ IXIA_CONFIGURATION subsection: Configure MCAST Traffic Item """

        # Do not perform configurations if skip_tgen_config flag is set
        #if not testscript.parameters['script_flags']['skip_tgen_config']:

        IX_TP1 = testscript.parameters['IX_TP1']
        IX_TP2 = testscript.parameters['IX_TP2']
        IX_TP3 = testscript.parameters['IX_TP3']
        IX_TP4 = testscript.parameters['IX_TP4']
        P1_dict = S1_BGW1_TGEN_data
        P2_dict = S1_Leaf_TGEN_data
        P3_dict = AcceSW_TGEN_data
        P4_dict = S2_Leaf_TGEN_data


        UCAST_v4_dict_3 = {   'src_hndl'  : IX_TP4['port_handle'],
                            'dst_hndl'  : IX_TP3['port_handle'],
                            'circuit'   : 'raw',
                            'TI_name'   : "UCAST_v4",
                            'rate_pps'  : "9000",
                            'bi_dir'    : 0,
                            'frame_size': '128',
                            'src_mac'   : P4_dict['mac'],
                            'dst_mac'   : '0000.000a.aaaa',
                            'srcmac_step': '00:00:00:00:00:00',
                            'dstmac_step': '00:00:00:00:00:00',
                            'srcmac_count': '1',
                            'dstmac_count': '1',
                            'vlan_id'    : P4_dict['vlan_id'],
                            'vlanid_step': '0',
                            'vlanid_count': '2',
                            'vlan_user_priority': P4_dict['vlan_user_priority'],
                            'ip_src_addrs' : P4_dict['v4_addr'],
                            'ip_dst_addrs' : P3_dict['L3_dst_addr'],
                            'ip_src_step' : '0.0.0.0',
                            'ip_dst_step' : '0.0.0.0',
                            'ip_dscp'     : P4_dict['ip_dscp'],
#                                'ip_step'    : P1_dict['v4_addr_step'],
                        }

        UCAST_v4_TI_2 = ixLib.configure_ixia_l3_traffic_item(UCAST_v4_dict_3)
            
        if UCAST_v4_TI_2 == 0:
            log.debug("Configuring UCast TI failed")
            self.errored("Configuring UCast TI failed", goto=['cleanup'])
        else:
            global stream_id_2
            stream_id_2 = UCAST_v4_TI_2

        # else:
        #     self.passed(reason="Skipped TGEN Configurations as per request")
    
    stream_id_3=''
    @aetest.test
    def CONFIGURE_UCAST_L3_IXIA_TRAFFIC_H1_to_H2_(self, testscript):
        """ IXIA_CONFIGURATION subsection: Configure MCAST Traffic Item """

        # Do not perform configurations if skip_tgen_config flag is set
        #if not testscript.parameters['script_flags']['skip_tgen_config']:

        IX_TP1 = testscript.parameters['IX_TP1']
        IX_TP2 = testscript.parameters['IX_TP2']
        IX_TP3 = testscript.parameters['IX_TP3']
        IX_TP4 = testscript.parameters['IX_TP4']
        P1_dict = S1_BGW1_TGEN_data
        P2_dict = S1_Leaf_TGEN_data
        P3_dict = AcceSW_TGEN_data
        P4_dict = S2_Leaf_TGEN_data


        UCAST_v4_dict_4 = {   'src_hndl'  : IX_TP3['port_handle'],
                            'dst_hndl'  : IX_TP1['port_handle'],
                            'circuit'   : 'raw',
                            'TI_name'   : "UCAST_v4",
                            'rate_pps'  : "9000",
                            'bi_dir'    : 0,
                            'frame_size': '128',
                            'src_mac'   : P3_dict['mac'],
                            'dst_mac'   : '0000.000a.aaaa',
                            'srcmac_step': '00:00:00:00:00:00',
                            'dstmac_step': '00:00:00:00:00:00',
                            'srcmac_count': '1',
                            'dstmac_count': '1',
                            'vlan_id'    : P3_dict['vlan_id'],
                            'vlanid_step': '0',
                            'vlanid_count': '1',
                            'vlan_user_priority': P3_dict['vlan_user_priority'],
                            'ip_src_addrs' : P3_dict['v4_addr'],
                            'ip_dst_addrs' : P1_dict['L3_dst_addr'],
                            'ip_src_step' : '0.0.0.0',
                            'ip_dscp'     : P3_dict['ip_dscp'],
                            'ip_dst_step' : '0.0.0.0',
#                                'ip_step'    : P1_dict['v4_addr_step'],
                        }

        UCAST_v4_TI_3 = ixLib.configure_ixia_l3_traffic_item(UCAST_v4_dict_4)
            
        if UCAST_v4_TI_3 == 0:
            log.debug("Configuring UCast TI failed")
            self.errored("Configuring UCast TI failed")
        else:
            global stream_id_3
            stream_id_3 = UCAST_v4_TI_3

        # else:
        #     self.passed(reason="Skipped TGEN Configurations as per request")

    @aetest.test
    def APPLY_TRAFFIC(self):
        """ IXIA_CONFIGURATION subsection: Verify IXIA Traffic """

        # Apply IXIA Traffic
        if ixLib.apply_traffic() == 1:
            log.info("Applying IXIA TI Passed")
        else:
            self.errored("Applying IXIA TI failed")

    @aetest.test
    def VERIFY_IXIA_TRAFFIC_Without_BH_Route(self, testscript):
        """ IXIA_CONFIGURATION subsection: Verify IXIA Traffic """

        # Do not perform configurations if skip_tgen_config flag is set
        #if not testscript.parameters['script_flags']['skip_tgen_config']:

        time.sleep(20)

        if ixLib.verify_traffic(10) == 1:
            log.debug("Traffic Verification Passed.Expecting traffic loss here.") 
        else:
            log.info("Traffic Verification Failed. Expecting traffic loss here.")
            self.failed("Traffic Verification failed")
        # else:
        #     self.passed(reason="Skipped TGEN Configurations as per request")

    @aetest.test
    def verify_dynamic_mac_states(self, testscript,testbed):
        node3_s1_bgw_1 = testbed.devices['node3_s1_bgw_1']
        node7_s2_bgw_1 = testbed.devices['node7_s2_bgw_1']
        P3_dict = AcceSW_TGEN_data
        if verify_dynamic_mac(node3_s1_bgw_1,str(P3_dict['mac']),str(P3_dict['vlan_id'])):
            log.info('proper dynaic mac learnt on S1_BGw1')
        else:
            log.info('improper dynamic mac learnt on  S1_BGw1')
            self.failed('improper dynamic mac learnt on  S1_BGw1')

        if verify_dynamic_mac(node7_s2_bgw_1,str(P3_dict['mac']),str(P3_dict['vlan_id'])):
            log.info('proper dynaic mac learnt on  S2_BGw1')
        else:
            log.info('improper dynamic mac learnt on S2_BGw1')
            self.failed('improper dynamic mac learnt on  S2_BGw1')  
    
    @aetest.test
    def delete_unwanted_traffic_stream(self,testbed):
        node3_s1_bgw_1 = testbed.devices['node3_s1_bgw_1']
        node5_s1_leaf_1 = testbed.devices['node5_s1_leaf_1']
        node10_s1_AccessSW =testbed.devices['node10_s1_AccessSW']
        node7_s2_bgw_1 =testbed.devices['node7_s2_bgw_1']
        P3_dict = AcceSW_TGEN_data
        forwardingSysDict = FWD_SYS_dict
     
        # Stop Traffic from ixia
        log.info("--- Stopping Traffic ---- \n")
        log.info("Stopping Traffic")
        traffic_run_status = ixLib.stop_traffic()
        
        if traffic_run_status is not 1:
            log.info("Failed: To Stop traffic")
            return 0
        else:
            log.info("\nTraffic Stopped successfully\n")
        time.sleep(10)
        ####Remove traffic item configured
        UCAST_v4_dict_4 = {
                        'mode'        : 'remove',
                        'stream_id'   : stream_id_3,
                    }
        if (ixLib.delete_traffic_item(UCAST_v4_dict_4))==0:
            log.debug("Traffic Remove failed")
            self.failed("Traffic Remove failed", goto=['next_tc'])


    @aetest.test
    def Config_Mac_BH_on_Vpc_Vtep(self, testscript,testbed):
        node3_s1_bgw_1 = testbed.devices['node3_s1_bgw_1']
        P3_dict = AcceSW_TGEN_data
        mac= str(P3_dict['mac'])
        vlan= str(P3_dict['vlan_id'])
        ip=str(P3_dict['v4_addr'])
        octet = 1
        no_int= int(P3_dict['no_of_ints'])
        
        for i in range (0,no_int):
            ###LEAF_3_MAC_BH_ROUTE
            testbed.devices['node3_s1_bgw_1'].configure('''
              mac address-table static ''' + str(mac) + ''' vlan '''+ str(vlan) + ''' drop

                interface vlan ''' + str(vlan) + '''
                  ip arp ''' + str(ip) + ''' ''' + str(mac) + '''
            ''')
            testbed.devices['node4_s1_bgw_2'].configure('''
               mac address-table static ''' + str(mac) + ''' vlan '''+ str(vlan) + ''' drop

                interface vlan ''' + str(vlan) + '''
                  ip arp ''' + str(ip) + ''' ''' + str(P3_dict['mac']) + '''
            ''')
            lasthex=incr_mac(mac)
            mac=mac[0:10]+lasthex
            vlan= int(vlan)+int(P3_dict['vlan_id_step'])
            ip=incr_ip(ip,octet) 

            
        # except Exception as error:
        #     log.debug("Unable to configure static BH mac route - Encountered Exception " + str(error))
        #     self.errored('Exception occurred while configuring static BH mac route', goto=['cleanup']) 
    
    @aetest.test
    def APPLY_TRAFFIC(self):
        """ IXIA_CONFIGURATION subsection: Verify IXIA Traffic """

        # Apply IXIA Traffic
        if ixLib.apply_traffic() == 1:
            log.info("Applying IXIA TI Passed")
        else:
            self.errored("Applying IXIA TI failed")
    
    @aetest.test
    def VERIFY_IXIA_TRAFFIC_With_BH_Route(self, testscript):
        """ IXIA_CONFIGURATION subsection: Verify IXIA Traffic """

        # Do not perform configurations if skip_tgen_config flag is set
        #if not testscript.parameters['script_flags']['skip_tgen_config']:

        time.sleep(20)

        if ixLib.verify_traffic(99) == 0:
            log.debug("Traffic Verification Passed.Expecting traffic loss here.") 
        else:
            log.info("Traffic Verification Failed. Expecting traffic loss here.")
            self.failed("Traffic Verification failed")
        # else:
        #     self.passed(reason="Skipped TGEN Configurations as per request")
    
    @aetest.test
    def Verify_Traffic_Drop_on_Remote_Vtep(self,testscript,testbed):
        node5_s1_leaf_1 = testbed.devices['node5_s1_leaf_1']
        node9_s2_leaf_1 = testbed.devices['node9_s2_leaf_1']
        node7_s2_bgw_1 = testbed.devices['node7_s2_bgw_1']
        P3_dict = AcceSW_TGEN_data
        uplink_PO=S1_Leaf_dict['S1_Leaf_UPLINK_PO']['po_id']
        if verify_traffic_drop(node5_s1_leaf_1,uplink_PO):
            log.info('Traffic correctly dropped on  S1_Leaf')
        else:
            log.info('Traffic NOT dropped on  S1_Leaf')
            self.failed('Traffic NOT dropped on  S1_Leaf')
        
        uplink_PO=S2_Leaf_dict['S2_Leaf_UPLINK_PO']['po_id']
        if verify_traffic_drop(node9_s2_leaf_1,uplink_PO):
            log.info('Traffic correctly dropped on  S2_Leaf')
        else:
            log.info('Traffic NOT dropped on  S2_Leaf')
            self.failed('Traffic NOT dropped on  S2_Leaf')

        uplink_PO=S2_BGW1_dict['S2_BGW1_UPLINK_PO']['po_id']
        if verify_traffic_drop(node7_s2_bgw_1,uplink_PO):
            log.info('Traffic correctly dropped on  S2_BGW1')
        else:
            log.info('Traffic NOT dropped on  S2_BGW1')
            self.failed('Traffic NOT dropped on  S2_BGW1')
    
    @aetest.test
    def Verify_BH_states_in_HMM(self, testscript,testbed):
        node3_s1_bgw_1 =testbed.devices['node3_s1_bgw_1']
        node7_s2_bgw_1 = testbed.devices['node7_s2_bgw_1']
        P3_dict = AcceSW_TGEN_data
        try:
            if verify_BH_in_HMM(node3_s1_bgw_1,str(P3_dict['v4_addr'])):
                log.info('Mac BH route is proper in HMM on  S1_BGW1')
            else:
                log.info('Mac BH route is improper in HMM on  S1_BGW1')
                self.failed('Mac BH route is improper in HMM on  S1_BGW1')
        
         
        except Exception as error:
            log.debug("Unable to configure static BH mac route on Remote Vtep- Encountered Exception " + str(error))
            self.errored('Exception occurred while configuring static BH mac route on Remote Vtep')

    @aetest.test
    def Verify_BH_states_in_AM(self, testscript,testbed):
        node3_s1_bgw_1 = testbed.devices['node3_s1_bgw_1']
        node7_s2_bgw_1 = testbed.devices['node7_s2_bgw_1']
        P3_dict = AcceSW_TGEN_data

        try:        
            if verify_BH_in_AM(node3_s1_bgw_1,str(P3_dict['mac']),str(P3_dict['vlan_id']),str(P3_dict['v4_addr'])):
                log.info('Mac BH route is proper in AM on  S1_BGW1')
            else:
                log.info('Mac BH route is improper in AM on  S1_BGW1')
                self.failed('Mac BH route is improper in AM on  S1_BGW1')
        
        except Exception as error:
            log.debug("Unable to configure static BH mac route on Remote Vtep- Encountered Exception " + str(error))
            self.errored('Exception occurred while configuring static BH mac route on Remote Vtep')
        
    @aetest.test
    def Verify_Mac_BH_Route_on_L2FM_BGP_L2RIB(self,testscript,testbed):
        node3_s1_bgw_1 =testbed.devices['node3_s1_bgw_1']
        node7_s2_bgw_1 = testbed.devices['node7_s2_bgw_1']
        P3_dict = AcceSW_TGEN_data      
        # Verifying L2FM

        try:
            ###S1_BGW1_MAC_BH_ROUTE
            if verify_BH_route_in_L2FM(node3_s1_bgw_1,str(P3_dict['vlan_id']),str(P3_dict['mac'])):
                log.info('Mac BH route is proper in L2FM on  S1_BGw1')
            else:
                log.info('Mac BH route is improper in L2FM on  S1_BGw1')
                self.failed('Mac BH route is improper in L2FM on  S1_BGw1')

            ###S2_BGW1_MAC_BH_ROUTE Remote Vtep
            if verify_BH_route_in_L2FM(node7_s2_bgw_1,str(P3_dict['vlan_id']),str(P3_dict['mac'])):
                log.info('Mac BH route is proper in L2FM on  S2_BGw1')
            else:
                log.info('Mac BH route is improper in L2FM on  S2_BGw1')
                self.failed('Mac BH route is improper in L2FM on  S2_BGw1')

        except Exception as error:
            log.debug("Unable to verify BH mac route in L2FM - Encountered Exception " + str(error))
            self.errored('Exception occurred while verifying BH mac route in L2FM')        

        #Verifying L2RIB
        try:
            #S1_Leaf_Mac_BH_route
            if verify_L2rib_mac_ip_output(node3_s1_bgw_1,str(P3_dict['vlan_id']),str(P3_dict['mac'])):
                log.info('Mac BH route is proper in L2RIB on S1_Leaf')
            else:
                log.debug('Mac BH route is improper in L2RIB on  S1_Leaf')
                self.failed('Mac BH route is improper in L2RIB on  S1_Leaf')

            #S2_BGW1_Mac_BH_route
            if verify_L2rib_mac_ip_output(node7_s2_bgw_1,str(P3_dict['vlan_id']),str(P3_dict['mac'])):
                log.info('Mac BH route is proper in L2RIB on S2_BGW1')
            else:
                log.debug('Mac BH route is improper in L2RIB on  S2_BGW1')
                self.errored('Mac BH route is improper in L2RIB on  S2_BGW1')
        
        except Exception as error:
            log.debug("Unable to verify BH mac route in L2RIB - Encountered Exception " + str(error))
            self.errored('Exception occurred while verifying BH mac route in L2RIB')
        
        #Verifying BGP
        try:
            #S2_BGW1_Mac_BH_route
            if verify_BH_in_Remote_BGP(node7_s2_bgw_1,str(P3_dict['mac'])):
                log.info('Mac BH route is proper in BGP on S2_BGW1')
            else:
                log.debug('Mac BH route is improper in BGP on  S2_BGW1')
                self.errored('Mac BH route is improper in BGP on  S2_BGW1')

            #Access_Mac_BH_route
            if verify_BH_in_Remote_BGP(node3_s1_bgw_1,str(P3_dict['mac'])):
                log.info('Mac BH route is proper in BGP on Access')
            else:
                log.debug('Mac BH route is improper in BGP on  Access')
                self.errored('Mac BH route is improper in BGP on  Access')
        
        except Exception as error:
            log.debug("Unable to verify BH mac route in BGP - Encountered Exception " + str(error))
            self.errored('Exception occurred while verifying BH mac route in BGP')

    @aetest.test
    def Verify_BH_states_in_remote_ARP(self, testscript,testbed):
        node3_s1_bgw_1 = testbed.devices['node3_s1_bgw_1']
        node7_s2_bgw_1 = testbed.devices['node7_s2_bgw_1']
        P3_dict = AcceSW_TGEN_data

        try: 

            if verify_BH_in_Remote_ARP(node7_s2_bgw_1,str(P3_dict['vlan_id']),str(P3_dict['mac'])):
               log.info('Mac BH route is proper in Remote ARP on  S2_BGW1')
            else:
                log.info('Mac BH route is improper in Remote ARP on  S2_BGW1')
                self.failed('Mac BH route is improper in Remote ARP on  S2_BGW1')

        except Exception as error:
            log.debug("Unable to configure static BH mac route on Remote Vtep- Encountered Exception " + str(error))
            self.errored('Exception occurred while configuring static BH mac route on Remote Vtep')        
    
    @aetest.test
    def Verify_BH_states_in_local_ARP(self, testscript,testbed):
        node3_s1_bgw_1 = testbed.devices['node3_s1_bgw_1']
        node7_s2_bgw_1 = testbed.devices['node7_s2_bgw_1']
        P3_dict = AcceSW_TGEN_data

        try:        
            if verify_BH_in_local_ARP(node3_s1_bgw_1,str(P3_dict['vlan_id']),str(P3_dict['mac'])):
                log.info('Mac BH route is proper in Local ARP on  S1_BGW1')
            else:
                log.info('Mac BH route is improper in Local ARP on  S1_BGW1')
                self.failed('Mac BH route is improper in Local ARP on  S1_BGW1')
        
        except Exception as error:
            log.debug("Unable to configure static BH mac route on Remote Vtep- Encountered Exception " + str(error))
            self.errored('Exception occurred while configuring static BH mac route on Remote Vtep')

    @aetest.test
    def UnConfig_Mac_BH_on_Vpc_Vtep(self, testscript,testbed):
        node3_s1_bgw_1 = testbed.devices['node3_s1_bgw_1']
        P3_dict = AcceSW_TGEN_data
        mac= str(P3_dict['mac'])
        vlan= str(P3_dict['vlan_id'])
        ip=str(P3_dict['v4_addr'])
        octet = 1
        no_int= int(P3_dict['no_of_ints'])
        
        for i in range (0,no_int):
            ###LEAF_3_MAC_BH_ROUTE
            testbed.devices['node3_s1_bgw_1'].configure('''
              no mac address-table static ''' + str(mac) + ''' vlan '''+ str(vlan) + ''' drop

                interface vlan ''' + str(vlan) + '''
                  no ip arp ''' + str(ip) + ''' ''' + str(mac) + '''
            ''')
            testbed.devices['node4_s1_bgw_2'].configure('''
               no mac address-table static ''' + str(mac) + ''' vlan '''+ str(vlan) + ''' drop

                interface vlan ''' + str(vlan) + '''
                  no ip arp ''' + str(ip) + ''' ''' + str(P3_dict['mac']) + '''
            ''')
            lasthex=incr_mac(mac)
            mac=mac[0:10]+lasthex
            vlan= int(vlan)+int(P3_dict['vlan_id_step'])
            ip=incr_ip(ip,octet) 

            
        # except Exception as error:
        #     log.debug("Unable to configure static BH mac route - Encountered Exception " + str(error))
        #     self.errored('Exception occurred while configuring static BH mac route', goto=['cleanup']) 
      
    @aetest.test
    def VERIFY_IXIA_TRAFFIC_after_rmBH_Route(self, testscript):
        """ IXIA_CONFIGURATION subsection: Verify IXIA Traffic """

        # Do not perform configurations if skip_tgen_config flag is set
        #if not testscript.parameters['script_flags']['skip_tgen_config']:

        time.sleep(20)

        if ixLib.verify_traffic(10) == 1:
            log.debug("Traffic Verification Passed.Expecting traffic loss here.") 
        else:
            log.info("Traffic Verification Failed. Expecting traffic loss here.")
            self.failed("Traffic Verification failed")
        # else:
        #     self.passed(reason="Skipped TGEN Configurations as per request")


    @aetest.cleanup
    def cleanup(self,testscript,testbed):
        """Unconfigure qos policies"""
        node3_s1_bgw_1 = testbed.devices['node3_s1_bgw_1']
        node5_s1_leaf_1 = testbed.devices['node5_s1_leaf_1']
        node10_s1_AccessSW =testbed.devices['node10_s1_AccessSW']
        node7_s2_bgw_1 =testbed.devices['node7_s2_bgw_1']
        P3_dict = AcceSW_TGEN_data
        forwardingSysDict = FWD_SYS_dict
        try:
            # Stop Traffic from ixia
            log.info("--- Stopping Traffic ---- \n")
            log.info("Stopping Traffic")
            traffic_run_status = ixLib.stop_traffic()
            
            if traffic_run_status is not 1:
               log.info("Failed: To Stop traffic")
               return 0
            else:
                log.info("\nTraffic Stopped successfully\n")
            time.sleep(10)
            ####Remove traffic item configured
            UCAST_v4_dict_1 = {
                            'mode'        : 'remove',
                            'stream_id'   : stream_id,
                      }
            if (ixLib.delete_traffic_item(UCAST_v4_dict_1))==0:
                log.debug("Traffic Remove failed")
                self.failed("Traffic Remove failed", goto=['next_tc'])
            else:
                log.info("Traffic Remove Passed")
            UCAST_v4_dict_2 = {
                            'mode'        : 'remove',
                            'stream_id'   : stream_id_1,
                      }
            if (ixLib.delete_traffic_item(UCAST_v4_dict_2))==0:
                log.debug("Traffic Remove failed")
                self.failed("Traffic Remove failed", goto=['next_tc'])
            else:
                log.info("Traffic Remove Passed")
            UCAST_v4_dict_3 = {
                            'mode'        : 'remove',
                            'stream_id'   : stream_id_2,
                      }
            if (ixLib.delete_traffic_item(UCAST_v4_dict_3))==0:
                log.debug("Traffic Remove failed")
                self.failed("Traffic Remove failed", goto=['next_tc'])
            else:
                log.info("Traffic Remove Passed")
            ###LEAF_1_MAC_BH_ROUTE
            testbed.devices['node3_s1_bgw_1'].configure(''' 
            
               no mac address-table static ''' + str(P3_dict['mac']) + ''' vlan '''+ str(P3_dict['vlan_id']) + ''' drop

                interface vlan ''' + str(P3_dict['vlan_id']) + '''
                  no ipv6 neighbor ''' + str(P3_dict['v6_addr']) + ''' ''' + str(P3_dict['mac']) + '''
                
            ''')
        except Exception as error:
            log.debug("Unable to do cleanup " + str(error))
            self.errored('Exception occurred during cleanup', goto=['next_tc'])   

class Mac_BH_route_Static_arp_on_standalone_Vtep_with_l3_traffic(nxtest.Testcase):
    #"TC_0043_Mac_BH_route_Static_arp_on_standalone_Vtep_with_l3_traffic"
    stream_id=''
    @aetest.test
    def CONFIGURE_UCAST_L3_IXIA_TRAFFIC_H2_to_H1_(self, testscript):
        """ IXIA_CONFIGURATION subsection: Configure MCAST Traffic Item """

        # Do not perform configurations if skip_tgen_config flag is set
        #if not testscript.parameters['script_flags']['skip_tgen_config']:

        IX_TP1 = testscript.parameters['IX_TP1']
        IX_TP2 = testscript.parameters['IX_TP2']
        IX_TP3 = testscript.parameters['IX_TP3']
        IX_TP4 = testscript.parameters['IX_TP4']
        P1_dict = S1_BGW1_TGEN_data
        P2_dict = S1_Leaf_TGEN_data
        P3_dict = AcceSW_TGEN_data
        P4_dict = S2_Leaf_TGEN_data


        UCAST_v4_dict_1 = {   'src_hndl'  : IX_TP3['port_handle'],
                            'dst_hndl'  : IX_TP1['port_handle'],
                            'circuit'   : 'raw',
                            'TI_name'   : "UCAST_v4",
                            'rate_pps'  : "9000",
                            'bi_dir'    : 0,
                            'frame_size': '128',
                            'src_mac'   : P3_dict['mac'],
                            'dst_mac'   : '0000.000a.aaaa',
                            'srcmac_step': '00:00:00:00:00:00',
                            'dstmac_step': '00:00:00:00:00:00',
                            'srcmac_count': '1',
                            'dstmac_count': '1',
                            'vlan_id'    : P3_dict['vlan_id'],
                            'vlanid_step': '0',
                            'vlanid_count': '1',
                            'vlan_user_priority': P3_dict['vlan_user_priority'],
                            'ip_src_addrs' : P3_dict['v4_addr'],
                            'ip_dst_addrs' : P1_dict['L3_dst_addr'],
                            'ip_src_step' : '0.0.0.0',
                            'ip_dscp'     : P3_dict['ip_dscp'],
                            'ip_dst_step' : '0.0.0.0',
#                                'ip_step'    : P1_dict['v4_addr_step'],
                        }

        UCAST_v4_TI = ixLib.configure_ixia_l3_traffic_item(UCAST_v4_dict_1)
            
        if UCAST_v4_TI == 0:
            log.debug("Configuring UCast TI failed")
            self.errored("Configuring UCast TI failed")
        else:
            global stream_id
            stream_id = UCAST_v4_TI

        # else:
        #     self.passed(reason="Skipped TGEN Configurations as per request")
    stream_id_1=''
    @aetest.test
    def CONFIGURE_UCAST_L3_IXIA_TRAFFIC_H3_to_H1_(self, testscript):
        """ IXIA_CONFIGURATION subsection: Configure MCAST Traffic Item """

        # Do not perform configurations if skip_tgen_config flag is set
        #if not testscript.parameters['script_flags']['skip_tgen_config']:

        IX_TP1 = testscript.parameters['IX_TP1']
        IX_TP2 = testscript.parameters['IX_TP2']
        IX_TP3 = testscript.parameters['IX_TP3']
        IX_TP4 = testscript.parameters['IX_TP4']
        P1_dict = S1_BGW1_TGEN_data
        P2_dict = S1_Leaf_TGEN_data
        P3_dict = AcceSW_TGEN_data
        P4_dict = S2_Leaf_TGEN_data


        UCAST_v4_dict_2 = {   'src_hndl'  : IX_TP2['port_handle'],
                            'dst_hndl'  : IX_TP3['port_handle'],
                            'circuit'   : 'raw',
                            'TI_name'   : "UCAST_v4",
                            'rate_pps'  : "9000",
                            'bi_dir'    : 0,
                            'frame_size': '128',
                            'src_mac'   : P2_dict['mac'],
                            'dst_mac'   : '0000.000a.aaaa',
                            'srcmac_step': '00:00:00:00:00:00',
                            'dstmac_step': '00:00:00:00:00:00',
                            'srcmac_count': '1',
                            'dstmac_count': '1',
                            'vlan_id'    : P2_dict['vlan_id'],
                            'vlanid_step': '0',
                            'vlanid_count': '2',
                            'vlan_user_priority': P2_dict['vlan_user_priority'],
                            'ip_src_addrs' : P2_dict['v4_addr'],
                            'ip_dst_addrs' : P3_dict['L3_dst_addr'],
                            'ip_src_step' : '0.0.0.0',
                            'ip_dscp'     : P2_dict['ip_dscp'],
                            'ip_dst_step' : '0.0.0.0',
#                                'ip_step'    : P1_dict['v4_addr_step'],
                        }

        UCAST_v4_TI_1 = ixLib.configure_ixia_l3_traffic_item(UCAST_v4_dict_2)
            
        if UCAST_v4_TI_1 == 0:
            log.debug("Configuring UCast TI failed")
            self.errored("Configuring UCast TI failed", goto=['cleanup'])
        else:
            global stream_id_1
            stream_id_1 = UCAST_v4_TI_1

        # else:
        #     self.passed(reason="Skipped TGEN Configurations as per request")
    
    stream_id_2=''
    @aetest.test
    def CONFIGURE_UCAST_L3_IXIA_TRAFFIC_H4_to_H1_(self, testscript):
        """ IXIA_CONFIGURATION subsection: Configure MCAST Traffic Item """

        # Do not perform configurations if skip_tgen_config flag is set
        #if not testscript.parameters['script_flags']['skip_tgen_config']:

        IX_TP1 = testscript.parameters['IX_TP1']
        IX_TP2 = testscript.parameters['IX_TP2']
        IX_TP3 = testscript.parameters['IX_TP3']
        IX_TP4 = testscript.parameters['IX_TP4']
        P1_dict = S1_BGW1_TGEN_data
        P2_dict = S1_Leaf_TGEN_data
        P3_dict = AcceSW_TGEN_data
        P4_dict = S2_Leaf_TGEN_data


        UCAST_v4_dict_3 = {   'src_hndl'  : IX_TP4['port_handle'],
                            'dst_hndl'  : IX_TP3['port_handle'],
                            'circuit'   : 'raw',
                            'TI_name'   : "UCAST_v4",
                            'rate_pps'  : "9000",
                            'bi_dir'    : 0,
                            'frame_size': '128',
                            'src_mac'   : P4_dict['mac'],
                            'dst_mac'   : '0000.000a.aaaa',
                            'srcmac_step': '00:00:00:00:00:00',
                            'dstmac_step': '00:00:00:00:00:00',
                            'srcmac_count': '1',
                            'dstmac_count': '1',
                            'vlan_id'    : P4_dict['vlan_id'],
                            'vlanid_step': '0',
                            'vlanid_count': '2',
                            'vlan_user_priority': P4_dict['vlan_user_priority'],
                            'ip_src_addrs' : P4_dict['v4_addr'],
                            'ip_dst_addrs' : P3_dict['L3_dst_addr'],
                            'ip_src_step' : '0.0.0.0',
                            'ip_dst_step' : '0.0.0.0',
                            'ip_dscp'     : P4_dict['ip_dscp'],
#                                'ip_step'    : P1_dict['v4_addr_step'],
                        }

        UCAST_v4_TI_2 = ixLib.configure_ixia_l3_traffic_item(UCAST_v4_dict_3)
            
        if UCAST_v4_TI_2 == 0:
            log.debug("Configuring UCast TI failed")
            self.errored("Configuring UCast TI failed", goto=['cleanup'])
        else:
            global stream_id_2
            stream_id_2 = UCAST_v4_TI_2

        # else:
        #     self.passed(reason="Skipped TGEN Configurations as per request")


    @aetest.test
    def APPLY_TRAFFIC(self):
        """ IXIA_CONFIGURATION subsection: Verify IXIA Traffic """

        # Apply IXIA Traffic
        if ixLib.apply_traffic() == 1:
            log.info("Applying IXIA TI Passed")
        else:
            self.errored("Applying IXIA TI failed")

    @aetest.test
    def VERIFY_IXIA_TRAFFIC_Without_BH_Route(self, testscript):
        """ IXIA_CONFIGURATION subsection: Verify IXIA Traffic """

        # Do not perform configurations if skip_tgen_config flag is set
        #if not testscript.parameters['script_flags']['skip_tgen_config']:

        log.info('waiting 40 sec before verifing traffic')
        time.sleep(40)

        if ixLib.verify_traffic(10) == 1:
            log.debug("Traffic Verification Passed.Expecting traffic loss here.")
            # ForkedPdb().set_trace() 
        else:
            log.info("Traffic Verification Failed. Expecting traffic loss here.")
            # ForkedPdb().set_trace()
            self.failed("Traffic Verification failed")
        # else:
        #     self.passed(reason="Skipped TGEN Configurations as per request")

    @aetest.test
    def verify_dynamic_mac_states(self, testscript,testbed):
        node3_s1_bgw_1 = testbed.devices['node3_s1_bgw_1']
        node7_s2_bgw_1 = testbed.devices['node7_s2_bgw_1']
        P3_dict = AcceSW_TGEN_data
        if verify_dynamic_mac(node3_s1_bgw_1,str(P3_dict['mac']),str(P3_dict['vlan_id'])):
            log.info('proper dynaic mac learnt on S1_BGw1')
        else:
            log.info('improper dynamic mac learnt on  S1_BGw1')
            self.failed('improper dynamic mac learnt on  S1_BGw1')

        if verify_dynamic_mac(node7_s2_bgw_1,str(P3_dict['mac']),str(P3_dict['vlan_id'])):
            log.info('proper dynaic mac learnt on  S2_BGw1')
        else:
            log.info('improper dynamic mac learnt on S2_BGw1')
            self.failed('improper dynamic mac learnt on  S2_BGw1')  
    
     
    @aetest.test
    def delete_unwanted_traffic_stream(self,testbed):
        node3_s1_bgw_1 = testbed.devices['node3_s1_bgw_1']
        node5_s1_leaf_1 = testbed.devices['node5_s1_leaf_1']
        node10_s1_AccessSW =testbed.devices['node10_s1_AccessSW']
        node7_s2_bgw_1 =testbed.devices['node7_s2_bgw_1']
        P3_dict = AcceSW_TGEN_data
        forwardingSysDict = FWD_SYS_dict
     
        # Stop Traffic from ixia
        log.info("--- Stopping Traffic ---- \n")
        log.info("Stopping Traffic")
        traffic_run_status = ixLib.stop_traffic()
        
        if traffic_run_status is not 1:
            log.info("Failed: To Stop traffic")
            return 0
        else:
            log.info("\nTraffic Stopped successfully\n")
        time.sleep(10)
        ####Remove traffic item configured
        UCAST_v4_dict_1 = {
                            'mode'        : 'remove',
                            'stream_id'   : stream_id,
                      }
        if (ixLib.delete_traffic_item(UCAST_v4_dict_1))==0:
            log.debug("Traffic Remove failed")
            self.failed("Traffic Remove failed", goto=['next_tc'])
        else:
            log.info("Traffic Remove Passed")
    

    @aetest.test
    def Config_Mac_BH_on_Vpc_Vtep(self, testscript,testbed):
        node7_s2_bgw_1 = testbed.devices['node7_s2_bgw_1']
        P3_dict = AcceSW_TGEN_data
        mac= str(P3_dict['mac'])
        vlan= str(P3_dict['vlan_id'])
        ip=str(P3_dict['v4_addr'])
        octet = 1
        no_int= int(P3_dict['no_of_ints'])
        
        for i in range (0,no_int):
            ###LEAF_3_MAC_BH_ROUTE
            testbed.devices['node7_s2_bgw_1'].configure('''
                mac address-table static ''' + str(mac) + ''' vlan '''+ str(vlan) + ''' drop

                interface vlan ''' + str(vlan) + '''
                  ip arp ''' + str(ip) + ''' ''' + str(mac) + '''
            ''')
            lasthex=incr_mac(mac)
            mac=mac[0:10]+lasthex
            vlan= int(vlan)+int(P3_dict['vlan_id_step'])
            ip=incr_ip(ip,octet) 

            
        # except Exception as error:
        #     log.debug("Unable to configure static BH mac route - Encountered Exception " + str(error))
        #     self.errored('Exception occurred while configuring static BH mac route', goto=['cleanup']) 
    
    @aetest.test
    def APPLY_TRAFFIC(self):
        """ IXIA_CONFIGURATION subsection: Verify IXIA Traffic """

        # Apply IXIA Traffic
        if ixLib.apply_traffic() == 1:
            log.info("Applying IXIA TI Passed")
        else:
            self.errored("Applying IXIA TI failed")
    
    @aetest.test
    def VERIFY_IXIA_TRAFFIC_With_BH_Route(self, testscript):
        """ IXIA_CONFIGURATION subsection: Verify IXIA Traffic """

        # Do not perform configurations if skip_tgen_config flag is set
        #if not testscript.parameters['script_flags']['skip_tgen_config']:

        time.sleep(20)

        if ixLib.verify_traffic(99) == 0:
            log.debug("Traffic Verification Passed.Expecting traffic loss here.") 
        else:
            log.info("Traffic Verification Failed. Expecting traffic loss here.")
            self.failed("Traffic Verification failed")
        # else:
        #     self.passed(reason="Skipped TGEN Configurations as per request")
    
    @aetest.test
    def Verify_Traffic_Drop_on_Remote_Vtep(self,testscript,testbed):
        node5_s1_leaf_1 = testbed.devices['node5_s1_leaf_1']
        node9_s2_leaf_1 = testbed.devices['node9_s2_leaf_1']
        node3_s1_bgw_1 = testbed.devices['node3_s1_bgw_1']
        P3_dict = AcceSW_TGEN_data
        uplink_PO=S1_Leaf_dict['S1_Leaf_UPLINK_PO']['po_id']
        if verify_traffic_drop(node5_s1_leaf_1,uplink_PO):
            log.info('Traffic correctly dropped on  S1_Leaf')
        else:
            log.info('Traffic NOT dropped on  S1_Leaf')
            self.failed('Traffic NOT dropped on  S1_Leaf')
        
        uplink_PO=S2_Leaf_dict['S2_Leaf_UPLINK_PO']['po_id']
        if verify_traffic_drop(node9_s2_leaf_1,uplink_PO):
            log.info('Traffic correctly dropped on  S2_Leaf')
        else:
            log.info('Traffic NOT dropped on  S2_Leaf')
            self.failed('Traffic NOT dropped on  S2_Leaf')

        uplink_PO=S1_BGW1_dict['S1_BGW1_UPLINK_PO']['po_id']
        if verify_traffic_drop(node3_s1_bgw_1,uplink_PO):
            log.info('Traffic correctly dropped on  S1_BGW1')
        else:
            log.info('Traffic NOT dropped on  S1_BGW1')
            self.failed('Traffic NOT dropped on  S1_BGW1')

    @aetest.test
    def Verify_BH_states_in_HMM(self, testscript,testbed):
        node3_s1_bgw_1 =testbed.devices['node3_s1_bgw_1']
        node7_s2_bgw_1 = testbed.devices['node7_s2_bgw_1']
        P3_dict = AcceSW_TGEN_data
        try:
            if verify_BH_in_HMM(node7_s2_bgw_1,str(P3_dict['v4_addr'])):
                log.info('Mac BH route is proper in HMM on  S1_BGW1')
            else:
                log.info('Mac BH route is improper in HMM on  S1_BGW1')
                self.failed('Mac BH route is improper in HMM on  S1_BGW1')
        
         
        except Exception as error:
            log.debug("Unable to configure static BH mac route on Remote Vtep- Encountered Exception " + str(error))
            self.errored('Exception occurred while configuring static BH mac route on Remote Vtep')

    @aetest.test
    def Verify_BH_states_in_AM(self, testscript,testbed):
        node3_s1_bgw_1 = testbed.devices['node3_s1_bgw_1']
        node7_s2_bgw_1 = testbed.devices['node7_s2_bgw_1']
        P3_dict = AcceSW_TGEN_data

        try:        
            if verify_BH_in_AM(node7_s2_bgw_1,str(P3_dict['mac']),str(P3_dict['vlan_id']),str(P3_dict['v4_addr'])):
                log.info('Mac BH route is proper in AM on  S1_BGW1')
            else:
                log.info('Mac BH route is improper in AM on  S1_BGW1')
                self.failed('Mac BH route is improper in AM on  S1_BGW1')
        
        except Exception as error:
            log.debug("Unable to configure static BH mac route on Remote Vtep- Encountered Exception " + str(error))
            self.errored('Exception occurred while configuring static BH mac route on Remote Vtep')
    
    @aetest.test
    def Verify_BH_states_in_remote_ARP(self, testscript,testbed):
        node3_s1_bgw_1 = testbed.devices['node3_s1_bgw_1']
        node7_s2_bgw_1 = testbed.devices['node7_s2_bgw_1']
        P3_dict = AcceSW_TGEN_data

        try: 

            if verify_BH_in_Remote_ARP(node3_s1_bgw_1,str(P3_dict['vlan_id']),str(P3_dict['mac'])):
               log.info('Mac BH route is proper in Remote ARP on  S2_BGW1')
            else:
                log.info('Mac BH route is improper in Remote ARP on  S2_BGW1')
                self.failed('Mac BH route is improper in Remote ARP on  S2_BGW1')

        except Exception as error:
            log.debug("Unable to configure static BH mac route on Remote Vtep- Encountered Exception " + str(error))
            self.errored('Exception occurred while configuring static BH mac route on Remote Vtep')        
    
    @aetest.test
    def Verify_BH_states_in_local_ARP(self, testscript,testbed):
        node3_s1_bgw_1 = testbed.devices['node3_s1_bgw_1']
        node7_s2_bgw_1 = testbed.devices['node7_s2_bgw_1']
        P3_dict = AcceSW_TGEN_data

        try:        
            if verify_BH_in_local_ARP(node7_s2_bgw_1,str(P3_dict['vlan_id']),str(P3_dict['mac'])):
                log.info('Mac BH route is proper in Local ARP on  S1_BGW1')
            else:
                log.info('Mac BH route is improper in Local ARP on  S1_BGW1')
                self.failed('Mac BH route is improper in Local ARP on  S1_BGW1')
        
        except Exception as error:
            log.debug("Unable to configure static BH mac route on Remote Vtep- Encountered Exception " + str(error))
            self.errored('Exception occurred while configuring static BH mac route on Remote Vtep')
        
    @aetest.test
    def Verify_Mac_BH_Route_on_L2FM_BGP_L2RIB(self,testscript,testbed):
        node3_s1_bgw_1 =testbed.devices['node3_s1_bgw_1']
        node7_s2_bgw_1 = testbed.devices['node7_s2_bgw_1']
        P3_dict = AcceSW_TGEN_data      
        # Verifying L2FM

        try:
            ###S1_BGW1_MAC_BH_ROUTE
            if verify_BH_route_in_L2FM(node3_s1_bgw_1,str(P3_dict['vlan_id']),str(P3_dict['mac'])):
                log.info('Mac BH route is proper in L2FM on  S1_BGw1')
            else:
                log.info('Mac BH route is improper in L2FM on  S1_BGw1')
                self.failed('Mac BH route is improper in L2FM on  S1_BGw1')

            ###S2_BGW1_MAC_BH_ROUTE Remote Vtep
            if verify_BH_route_in_L2FM(node7_s2_bgw_1,str(P3_dict['vlan_id']),str(P3_dict['mac'])):
                log.info('Mac BH route is proper in L2FM on  S2_BGw1')
            else:
                log.info('Mac BH route is improper in L2FM on  S2_BGw1')
                self.failed('Mac BH route is improper in L2FM on  S2_BGw1')

        except Exception as error:
            log.debug("Unable to verify BH mac route in L2FM - Encountered Exception " + str(error))
            self.errored('Exception occurred while verifying BH mac route in L2FM')        

        #Verifying L2RIB
        try:
            #S1_Leaf_Mac_BH_route
            if verify_L2rib_mac_ip_output(node3_s1_bgw_1,str(P3_dict['vlan_id']),str(P3_dict['mac'])):
                log.info('Mac BH route is proper in L2RIB on S1_Leaf')
            else:
                log.debug('Mac BH route is improper in L2RIB on  S1_Leaf')
                self.failed('Mac BH route is improper in L2RIB on  S1_Leaf')

            #S2_BGW1_Mac_BH_route
            if verify_L2rib_mac_ip_output(node7_s2_bgw_1,str(P3_dict['vlan_id']),str(P3_dict['mac'])):
                log.info('Mac BH route is proper in L2RIB on S2_BGW1')
            else:
                log.debug('Mac BH route is improper in L2RIB on  S2_BGW1')
                self.errored('Mac BH route is improper in L2RIB on  S2_BGW1')
        
        except Exception as error:
            log.debug("Unable to verify BH mac route in L2RIB - Encountered Exception " + str(error))
            self.errored('Exception occurred while verifying BH mac route in L2RIB')
        
        #Verifying BGP
        try:
            #S2_BGW1_Mac_BH_route
            if verify_BH_in_Remote_BGP(node7_s2_bgw_1,str(P3_dict['mac'])):
                log.info('Mac BH route is proper in BGP on S2_BGW1')
            else:
                log.debug('Mac BH route is improper in BGP on  S2_BGW1')
                self.errored('Mac BH route is improper in BGP on  S2_BGW1')

            #Access_Mac_BH_route
            if verify_BH_in_Remote_BGP(node3_s1_bgw_1,str(P3_dict['mac'])):
                log.info('Mac BH route is proper in BGP on Access')
            else:
                log.debug('Mac BH route is improper in BGP on  Access')
                self.errored('Mac BH route is improper in BGP on  Access')
        
        except Exception as error:
            log.debug("Unable to verify BH mac route in BGP - Encountered Exception " + str(error))
            self.errored('Exception occurred while verifying BH mac route in BGP')

    @aetest.test
    def UnConfig_Mac_BH_on_Vpc_Vtep(self, testscript,testbed):
        node7_s2_bgw_1 = testbed.devices['node7_s2_bgw_1']
        P3_dict = AcceSW_TGEN_data
        mac= str(P3_dict['mac'])
        vlan= str(P3_dict['vlan_id'])
        ip=str(P3_dict['v4_addr'])
        octet = 1
        no_int= int(P3_dict['no_of_ints'])
        
        for i in range (0,no_int):
            ###LEAF_3_MAC_BH_ROUTE
            testbed.devices['node7_s2_bgw_1'].configure('''
                no mac address-table static ''' + str(mac) + ''' vlan '''+ str(vlan) + ''' drop

                interface vlan ''' + str(vlan) + '''
                  no ip arp ''' + str(ip) + ''' ''' + str(mac) + '''
            ''')
            lasthex=incr_mac(mac)
            mac=mac[0:10]+lasthex
            vlan= int(vlan)+int(P3_dict['vlan_id_step'])
            ip=incr_ip(ip,octet)
            
        # except Exception as error:
        #     log.debug("Unable to configure static BH mac route - Encountered Exception " + str(error))
        #     self.errored('Exception occurred while configuring static BH mac route', goto=['cleanup'])

    @aetest.test
    def VERIFY_IXIA_TRAFFIC_after_rmBH_Route(self, testscript):
        """ IXIA_CONFIGURATION subsection: Verify IXIA Traffic """

        # Do not perform configurations if skip_tgen_config flag is set
        #if not testscript.parameters['script_flags']['skip_tgen_config']:

        log.info('waiting 40 sec before verifing traffic')
        time.sleep(40)

        if ixLib.verify_traffic(10) == 1:
            log.debug("Traffic Verification Passed.Expecting traffic loss here.") 
        else:
            log.info("Traffic Verification Failed. Expecting traffic loss here.")
            self.failed("Traffic Verification failed")
        # else:
        #     self.passed(reason="Skipped TGEN Configurations as per request")
 

    @aetest.cleanup
    def cleanup(self,testscript,testbed):
        """Unconfigure qos policies"""
        node3_s1_bgw_1 = testbed.devices['node3_s1_bgw_1']
        node5_s1_leaf_1 = testbed.devices['node5_s1_leaf_1']
        node10_s1_AccessSW =testbed.devices['node10_s1_AccessSW']
        node7_s2_bgw_1 =testbed.devices['node7_s2_bgw_1']
        P3_dict = AcceSW_TGEN_data
        forwardingSysDict = FWD_SYS_dict
        try:
            # Stop Traffic from ixia
            log.info("--- Stopping Traffic ---- \n")
            log.info("Stopping Traffic")
            traffic_run_status = ixLib.stop_traffic()
            
            if traffic_run_status is not 1:
               log.info("Failed: To Stop traffic")
               return 0
            else:
                log.info("\nTraffic Stopped successfully\n")
            time.sleep(10)
            ####Remove traffic item configured
            UCAST_v4_dict_2 = {
                            'mode'        : 'remove',
                            'stream_id'   : stream_id_1,
                      }
            if (ixLib.delete_traffic_item(UCAST_v4_dict_2))==0:
                log.debug("Traffic Remove failed")
                self.failed("Traffic Remove failed", goto=['next_tc'])
            else:
                log.info("Traffic Remove Passed")
            UCAST_v4_dict_3 = {
                            'mode'        : 'remove',
                            'stream_id'   : stream_id_2,
                      }
            if (ixLib.delete_traffic_item(UCAST_v4_dict_3))==0:
                log.debug("Traffic Remove failed")
                self.failed("Traffic Remove failed", goto=['next_tc'])
            else:
                log.info("Traffic Remove Passed")
            ###LEAF_1_MAC_BH_ROUTE
            testbed.devices['node7_s2_bgw_1'].configure(''' 
            
               no mac address-table static ''' + str(P3_dict['mac']) + ''' vlan '''+ str(P3_dict['vlan_id']) + ''' drop

                interface vlan ''' + str(P3_dict['vlan_id']) + '''
                  no ipv6 neighbor ''' + str(P3_dict['v6_addr']) + ''' ''' + str(P3_dict['mac']) + '''
                
            ''')
        except Exception as error:
            log.debug("Unable to do cleanup " + str(error))
            self.errored('Exception occurred during cleanup', goto=['next_tc'])   

class Mac_BH_route_on_vpc_vtep_start_L3_traffic(nxtest.Testcase):
    # "TC_0045_Mac_BH_route_on_vpc_vtep_start_L3_traffic"
    stream_id=''
    @aetest.test
    def CONFIGURE_UCAST_L3_IXIA_TRAFFIC_H2_to_H1_(self, testscript):
        """ IXIA_CONFIGURATION subsection: Configure MCAST Traffic Item """

        # Do not perform configurations if skip_tgen_config flag is set
        #if not testscript.parameters['script_flags']['skip_tgen_config']:

        IX_TP1 = testscript.parameters['IX_TP1']
        IX_TP2 = testscript.parameters['IX_TP2']
        IX_TP3 = testscript.parameters['IX_TP3']
        IX_TP4 = testscript.parameters['IX_TP4']
        P1_dict = S1_BGW1_TGEN_data
        P2_dict = S1_Leaf_TGEN_data
        P3_dict = AcceSW_TGEN_data
        P4_dict = S2_Leaf_TGEN_data


        UCAST_v4_dict_1 = {   'src_hndl'  : IX_TP1['port_handle'],
                            'dst_hndl'  : IX_TP3['port_handle'],
                            'circuit'   : 'raw',
                            'TI_name'   : "UCAST_v4",
                            'rate_pps'  : "9000",
                            'bi_dir'    : 0,
                            'frame_size': '128',
                            'src_mac'   : P1_dict['mac'],
                            'dst_mac'   : '0000.000a.aaaa',
                            'srcmac_step': '00:00:00:00:00:00',
                            'dstmac_step': '00:00:00:00:00:00',
                            'srcmac_count': '1',
                            'dstmac_count': '1',
                            'vlan_id'    : P1_dict['vlan_id'],
                            'vlanid_step': '0',
                            'vlanid_count': '1',
                            'vlan_user_priority': P1_dict['vlan_user_priority'],
                            'ip_src_addrs' : P1_dict['v4_addr'],
                            'ip_dst_addrs' : P3_dict['L3_dst_addr'],
                            'ip_src_step' : '0.0.0.0',
                            'ip_dscp'     : P1_dict['ip_dscp'],
                            'ip_dst_step' : '0.0.0.0',
#                                'ip_step'    : P1_dict['v4_addr_step'],
                        }

        UCAST_v4_TI = ixLib.configure_ixia_l3_traffic_item(UCAST_v4_dict_1)
            
        if UCAST_v4_TI == 0:
            log.debug("Configuring UCast TI failed")
            self.errored("Configuring UCast TI failed")
        else:
            global stream_id
            stream_id = UCAST_v4_TI

        # else:
        #     self.passed(reason="Skipped TGEN Configurations as per request")
    stream_id_1=''
    @aetest.test
    def CONFIGURE_UCAST_L3_IXIA_TRAFFIC_H3_to_H1_(self, testscript):
        """ IXIA_CONFIGURATION subsection: Configure MCAST Traffic Item """

        # Do not perform configurations if skip_tgen_config flag is set
        #if not testscript.parameters['script_flags']['skip_tgen_config']:

        IX_TP1 = testscript.parameters['IX_TP1']
        IX_TP2 = testscript.parameters['IX_TP2']
        IX_TP3 = testscript.parameters['IX_TP3']
        IX_TP4 = testscript.parameters['IX_TP4']
        P1_dict = S1_BGW1_TGEN_data
        P2_dict = S1_Leaf_TGEN_data
        P3_dict = AcceSW_TGEN_data
        P4_dict = S2_Leaf_TGEN_data


        UCAST_v4_dict_2 = {   'src_hndl'  : IX_TP2['port_handle'],
                            'dst_hndl'  : IX_TP3['port_handle'],
                            'circuit'   : 'raw',
                            'TI_name'   : "UCAST_v4",
                            'rate_pps'  : "9000",
                            'bi_dir'    : 0,
                            'frame_size': '128',
                            'src_mac'   : P2_dict['mac'],
                            'dst_mac'   : '0000.000a.aaaa',
                            'srcmac_step': '00:00:00:00:00:00',
                            'dstmac_step': '00:00:00:00:00:00',
                            'srcmac_count': '1',
                            'dstmac_count': '1',
                            'vlan_id'    : P2_dict['vlan_id'],
                            'vlanid_step': '0',
                            'vlanid_count': '2',
                            'vlan_user_priority': P2_dict['vlan_user_priority'],
                            'ip_src_addrs' : P2_dict['v4_addr'],
                            'ip_dst_addrs' : P3_dict['L3_dst_addr'],
                            'ip_src_step' : '0.0.0.0',
                            'ip_dscp'     : P2_dict['ip_dscp'],
                            'ip_dst_step' : '0.0.0.0',
#                                'ip_step'    : P1_dict['v4_addr_step'],
                        }

        UCAST_v4_TI_1 = ixLib.configure_ixia_l3_traffic_item(UCAST_v4_dict_2)
            
        if UCAST_v4_TI_1 == 0:
            log.debug("Configuring UCast TI failed")
            self.errored("Configuring UCast TI failed", goto=['cleanup'])
        else:
            global stream_id_1
            stream_id_1 = UCAST_v4_TI_1

        # else:
        #     self.passed(reason="Skipped TGEN Configurations as per request")
    stream_id_2=''
    @aetest.test
    def CONFIGURE_UCAST_L3_IXIA_TRAFFIC_H4_to_H1_(self, testscript):
        """ IXIA_CONFIGURATION subsection: Configure MCAST Traffic Item """

        # Do not perform configurations if skip_tgen_config flag is set
        #if not testscript.parameters['script_flags']['skip_tgen_config']:

        IX_TP1 = testscript.parameters['IX_TP1']
        IX_TP2 = testscript.parameters['IX_TP2']
        IX_TP3 = testscript.parameters['IX_TP3']
        IX_TP4 = testscript.parameters['IX_TP4']
        P1_dict = S1_BGW1_TGEN_data
        P2_dict = S1_Leaf_TGEN_data
        P3_dict = AcceSW_TGEN_data
        P4_dict = S2_Leaf_TGEN_data


        UCAST_v4_dict_3 = {   'src_hndl'  : IX_TP4['port_handle'],
                            'dst_hndl'  : IX_TP3['port_handle'],
                            'circuit'   : 'raw',
                            'TI_name'   : "UCAST_v4",
                            'rate_pps'  : "9000",
                            'bi_dir'    : 0,
                            'frame_size': '128',
                            'src_mac'   : P4_dict['mac'],
                            'dst_mac'   : '0000.000a.aaaa',
                            'srcmac_step': '00:00:00:00:00:00',
                            'dstmac_step': '00:00:00:00:00:00',
                            'srcmac_count': '1',
                            'dstmac_count': '1',
                            'vlan_id'    : P4_dict['vlan_id'],
                            'vlanid_step': '0',
                            'vlanid_count': '2',
                            'vlan_user_priority': P4_dict['vlan_user_priority'],
                            'ip_src_addrs' : P4_dict['v4_addr'],
                            'ip_dst_addrs' : P3_dict['L3_dst_addr'],
                            'ip_src_step' : '0.0.0.0',
                            'ip_dst_step' : '0.0.0.0',
                            'ip_dscp'     : P4_dict['ip_dscp'],
#                                'ip_step'    : P1_dict['v4_addr_step'],
                        }

        UCAST_v4_TI_2 = ixLib.configure_ixia_l3_traffic_item(UCAST_v4_dict_3)
            
        if UCAST_v4_TI_2 == 0:
            log.debug("Configuring UCast TI failed")
            self.errored("Configuring UCast TI failed", goto=['cleanup'])
        else:
            global stream_id_2
            stream_id_2 = UCAST_v4_TI_2

        # else:
        #     self.passed(reason="Skipped TGEN Configurations as per request")
    @aetest.test
    def APPLY_TRAFFIC(self):
        """ IXIA_CONFIGURATION subsection: Verify IXIA Traffic """

        # Apply IXIA Traffic
        if ixLib.apply_traffic() == 1:
            log.info("Applying IXIA TI Passed")
        else:
            self.errored("Applying IXIA TI failed")

    @aetest.test
    def VERIFY_IXIA_TRAFFIC_Without_BH_Route(self, testscript):
        """ IXIA_CONFIGURATION subsection: Verify IXIA Traffic """

        # Do not perform configurations if skip_tgen_config flag is set
        #if not testscript.parameters['script_flags']['skip_tgen_config']:

        time.sleep(20)

        if ixLib.verify_traffic(10) == 1:
            log.debug("Traffic Verification Passed.Expecting traffic loss here.") 
        else:
            log.info("Traffic Verification Failed. Expecting traffic loss here.")
            self.failed("Traffic Verification failed")
        # else:
        #     self.passed(reason="Skipped TGEN Configurations as per request")

    
    @aetest.test
    def Config_Mac_BH_on_Vpc_Vtep(self, testscript,testbed):
        node3_s1_bgw_1 = testbed.devices['node3_s1_bgw_1']
        P3_dict = AcceSW_TGEN_data
        mac= str(P3_dict['mac'])
        vlan= str(P3_dict['vlan_id'])
        ip=str(P3_dict['v4_addr'])
        octet = 1
        no_int= int(P3_dict['no_of_ints'])
        
        for i in range (0,no_int):
            ###LEAF_3_MAC_BH_ROUTE
            testbed.devices['node3_s1_bgw_1'].configure('''
                mac address-table static ''' + str(mac) + ''' vlan '''+ str(vlan) + ''' drop

                interface vlan ''' + str(vlan) + '''
                  ip arp ''' + str(ip) + ''' ''' + str(mac) + '''
            ''')
            testbed.devices['node4_s1_bgw_2'].configure('''
                mac address-table static ''' + str(mac) + ''' vlan '''+ str(vlan) + ''' drop

                interface vlan ''' + str(vlan) + '''
                  ip arp ''' + str(ip) + ''' ''' + str(mac) + '''
            ''')
            lasthex=incr_mac(mac)
            mac=mac[0:10]+lasthex
            vlan= int(vlan)+int(P3_dict['vlan_id_step'])
            ip=incr_ip(ip,octet) 

            
        # except Exception as error:
        #     log.debug("Unable to configure static BH mac route - Encountered Exception " + str(error))
        #     self.errored('Exception occurred while configuring static BH mac route', goto=['cleanup']) 

    @aetest.test
    def APPLY_TRAFFIC(self):
        """ IXIA_CONFIGURATION subsection: Verify IXIA Traffic """

        # Apply IXIA Traffic
        if ixLib.apply_traffic() == 1:
            log.info("Applying IXIA TI Passed")
        else:
            self.errored("Applying IXIA TI failed")

    @aetest.test
    def VERIFY_IXIA_TRAFFIC_With_BH_Route(self, testscript):
        """ IXIA_CONFIGURATION subsection: Verify IXIA Traffic """

        # Do not perform configurations if skip_tgen_config flag is set
        #if not testscript.parameters['script_flags']['skip_tgen_config']:

        time.sleep(20)

        if ixLib.verify_traffic(99) == 0:
            log.debug("Traffic Verification Passed.Expecting traffic loss here.") 
        else:
            log.info("Traffic Verification Failed. Expecting traffic loss here.")
            self.failed("Traffic Verification failed")
        # else:
        #     self.passed(reason="Skipped TGEN Configurations as per request")
    
    @aetest.test
    def Verify_Traffic_Drop_on_Remote_Vtep(self,testscript,testbed):
        node5_s1_leaf_1 = testbed.devices['node5_s1_leaf_1']
        node9_s2_leaf_1 = testbed.devices['node9_s2_leaf_1']
        node7_s2_bgw_1 = testbed.devices['node7_s2_bgw_1']
        P3_dict = AcceSW_TGEN_data
        uplink_PO=S1_Leaf_dict['S1_Leaf_UPLINK_PO']['po_id']
        if verify_traffic_drop(node5_s1_leaf_1,uplink_PO):
            log.info('Traffic correctly dropped on  S1_Leaf')
        else:
            log.info('Traffic NOT dropped on  S1_Leaf')
            self.failed('Traffic NOT dropped on  S1_Leaf')
        
        uplink_PO=S2_Leaf_dict['S2_Leaf_UPLINK_PO']['po_id']
        if verify_traffic_drop(node9_s2_leaf_1,uplink_PO):
            log.info('Traffic correctly dropped on  S2_Leaf')
        else:
            log.info('Traffic NOT dropped on  S2_Leaf')
            self.failed('Traffic NOT dropped on  S2_Leaf')

        uplink_PO=S2_BGW1_dict['S2_BGW1_UPLINK_PO']['po_id']
        if verify_traffic_drop(node7_s2_bgw_1,uplink_PO):
            log.info('Traffic correctly dropped on  S2_BGW1')
        else:
            log.info('Traffic NOT dropped on  S2_BGW1')
            self.failed('Traffic NOT dropped on  S2_BGW1')

    @aetest.test
    def verify_static_mac_states(self, testscript,testbed):
        node3_s1_bgw_1 = testbed.devices['node3_s1_bgw_1']
        node7_s2_bgw_1 = testbed.devices['node7_s2_bgw_1']
        P3_dict = AcceSW_TGEN_data
        if verify_static_mac(node3_s1_bgw_1,str(P3_dict['mac']),str(P3_dict['vlan_id'])):
            log.info('proper static mac learnt on S1_BGw1')
        else:
            log.info('improper static mac learnt on  S1_BGw1')
            self.failed('improper static mac learnt on  S1_BGw1')

        if verify_static_mac(node7_s2_bgw_1,str(P3_dict['mac']),str(P3_dict['vlan_id'])):
            log.info('proper static mac learnt on  S2_BGw1')
        else:
            log.info('improper static mac learnt on S2_BGw1')
            self.failed('improper static mac learnt on  S2_BGw1')  
    
    
    @aetest.test
    def Verify_BH_states_in_HMM(self, testscript,testbed):
        node3_s1_bgw_1 =testbed.devices['node3_s1_bgw_1']
        node7_s2_bgw_1 = testbed.devices['node7_s2_bgw_1']
        P3_dict = AcceSW_TGEN_data
        try:
            if verify_BH_in_HMM(node3_s1_bgw_1,str(P3_dict['v4_addr'])):
                log.info('Mac BH route is proper in HMM on  S1_BGW1')
            else:
                log.info('Mac BH route is improper in HMM on  S1_BGW1')
                self.failed('Mac BH route is improper in HMM on  S1_BGW1')
        
         
        except Exception as error:
            log.debug("Unable to configure static BH mac route on Remote Vtep- Encountered Exception " + str(error))
            self.errored('Exception occurred while configuring static BH mac route on Remote Vtep')

    @aetest.test
    def Verify_BH_states_in_AM(self, testscript,testbed):
        node3_s1_bgw_1 = testbed.devices['node3_s1_bgw_1']
        node7_s2_bgw_1 = testbed.devices['node7_s2_bgw_1']
        P3_dict = AcceSW_TGEN_data

        try:        
            if verify_BH_in_AM(node3_s1_bgw_1,str(P3_dict['mac']),str(P3_dict['vlan_id']),str(P3_dict['v4_addr'])):
                log.info('Mac BH route is proper in AM on  S1_BGW1')
            else:
                log.info('Mac BH route is improper in AM on  S1_BGW1')
                self.failed('Mac BH route is improper in AM on  S1_BGW1')
        
        except Exception as error:
            log.debug("Unable to configure static BH mac route on Remote Vtep- Encountered Exception " + str(error))
            self.errored('Exception occurred while configuring static BH mac route on Remote Vtep')
    
    @aetest.test
    def Verify_BH_states_in_remote_ARP(self, testscript,testbed):
        node3_s1_bgw_1 = testbed.devices['node3_s1_bgw_1']
        node7_s2_bgw_1 = testbed.devices['node7_s2_bgw_1']
        P3_dict = AcceSW_TGEN_data

        try: 

            if verify_BH_in_Remote_ARP(node7_s2_bgw_1,str(P3_dict['vlan_id']),str(P3_dict['mac'])):
               log.info('Mac BH route is proper in Remote ARP on  S2_BGW1')
            else:
                log.info('Mac BH route is improper in Remote ARP on  S2_BGW1')
                self.failed('Mac BH route is improper in Remote ARP on  S2_BGW1')

        except Exception as error:
            log.debug("Unable to configure static BH mac route on Remote Vtep- Encountered Exception " + str(error))
            self.errored('Exception occurred while configuring static BH mac route on Remote Vtep')        
    
    @aetest.test
    def Verify_BH_states_in_local_ARP(self, testscript,testbed):
        node3_s1_bgw_1 = testbed.devices['node3_s1_bgw_1']
        node7_s2_bgw_1 = testbed.devices['node7_s2_bgw_1']
        P3_dict = AcceSW_TGEN_data

        try:        
            if verify_BH_in_local_ARP(node3_s1_bgw_1,str(P3_dict['vlan_id']),str(P3_dict['mac'])):
                log.info('Mac BH route is proper in Local ARP on  S1_BGW1')
            else:
                log.info('Mac BH route is improper in Local ARP on  S1_BGW1')
                self.failed('Mac BH route is improper in Local ARP on  S1_BGW1')
        
        except Exception as error:
            log.debug("Unable to configure static BH mac route on Remote Vtep- Encountered Exception " + str(error))
            self.errored('Exception occurred while configuring static BH mac route on Remote Vtep')
        
    @aetest.test
    def Verify_Mac_BH_Route_on_L2FM_BGP_L2RIB(self,testscript,testbed):
        node3_s1_bgw_1 =testbed.devices['node3_s1_bgw_1']
        node7_s2_bgw_1 = testbed.devices['node7_s2_bgw_1']
        P3_dict = AcceSW_TGEN_data      
        # Verifying L2FM

        try:
            ###S1_BGW1_MAC_BH_ROUTE
            if verify_BH_route_in_L2FM(node3_s1_bgw_1,str(P3_dict['vlan_id']),str(P3_dict['mac'])):
                log.info('Mac BH route is proper in L2FM on  S1_BGw1')
            else:
                log.info('Mac BH route is improper in L2FM on  S1_BGw1')
                self.failed('Mac BH route is improper in L2FM on  S1_BGw1')

            ###S2_BGW1_MAC_BH_ROUTE Remote Vtep
            if verify_BH_route_in_L2FM(node7_s2_bgw_1,str(P3_dict['vlan_id']),str(P3_dict['mac'])):
                log.info('Mac BH route is proper in L2FM on  S2_BGw1')
            else:
                log.info('Mac BH route is improper in L2FM on  S2_BGw1')
                self.failed('Mac BH route is improper in L2FM on  S2_BGw1')

        except Exception as error:
            log.debug("Unable to verify BH mac route in L2FM - Encountered Exception " + str(error))
            self.errored('Exception occurred while verifying BH mac route in L2FM')        

        #Verifying L2RIB
        try:
            #S1_Leaf_Mac_BH_route
            if verify_L2rib_mac_ip_output(node3_s1_bgw_1,str(P3_dict['vlan_id']),str(P3_dict['mac'])):
                log.info('Mac BH route is proper in L2RIB on S1_Leaf')
            else:
                log.debug('Mac BH route is improper in L2RIB on  S1_Leaf')
                self.failed('Mac BH route is improper in L2RIB on  S1_Leaf')

            #S2_BGW1_Mac_BH_route
            if verify_L2rib_mac_ip_output(node7_s2_bgw_1,str(P3_dict['vlan_id']),str(P3_dict['mac'])):
                log.info('Mac BH route is proper in L2RIB on S2_BGW1')
            else:
                log.debug('Mac BH route is improper in L2RIB on  S2_BGW1')
                self.errored('Mac BH route is improper in L2RIB on  S2_BGW1')
        
        except Exception as error:
            log.debug("Unable to verify BH mac route in L2RIB - Encountered Exception " + str(error))
            self.errored('Exception occurred while verifying BH mac route in L2RIB')
        
        #Verifying BGP
        try:
            #S2_BGW1_Mac_BH_route
            if verify_BH_in_Remote_BGP(node7_s2_bgw_1,str(P3_dict['mac'])):
                log.info('Mac BH route is proper in BGP on S2_BGW1')
            else:
                log.debug('Mac BH route is improper in BGP on  S2_BGW1')
                self.errored('Mac BH route is improper in BGP on  S2_BGW1')

            #Access_Mac_BH_route
            if verify_BH_in_Remote_BGP(node3_s1_bgw_1,str(P3_dict['mac'])):
                log.info('Mac BH route is proper in BGP on Access')
            else:
                log.debug('Mac BH route is improper in BGP on  Access')
                self.errored('Mac BH route is improper in BGP on  Access')
        
        except Exception as error:
            log.debug("Unable to verify BH mac route in BGP - Encountered Exception " + str(error))
            self.errored('Exception occurred while verifying BH mac route in BGP')

    @aetest.test
    def UnConfig_Mac_BH_on_Vpc_Vtep(self, testscript,testbed):
        node3_s1_bgw_1 = testbed.devices['node3_s1_bgw_1']
        P3_dict = AcceSW_TGEN_data
        mac= str(P3_dict['mac'])
        vlan= str(P3_dict['vlan_id'])
        ip=str(P3_dict['v4_addr'])
        octet = 1
        no_int= int(P3_dict['no_of_ints'])
        
        for i in range (0,no_int):
            ###LEAF_3_MAC_BH_ROUTE
            testbed.devices['node3_s1_bgw_1'].configure('''
                no mac address-table static ''' + str(mac) + ''' vlan '''+ str(vlan) + ''' drop

                interface vlan ''' + str(vlan) + '''
                  no ip arp ''' + str(ip) + ''' ''' + str(mac) + '''
            ''')
            testbed.devices['node4_s1_bgw_2'].configure('''
                no mac address-table static ''' + str(mac) + ''' vlan '''+ str(vlan) + ''' drop

                interface vlan ''' + str(vlan) + '''
                  no ip arp ''' + str(ip) + ''' ''' + str(mac) + '''
            ''')
            lasthex=incr_mac(mac)
            mac=mac[0:10]+lasthex
            vlan= int(vlan)+int(P3_dict['vlan_id_step'])
            ip=incr_ip(ip,octet)
    @aetest.test
    def APPLY_TRAFFIC(self):
        """ IXIA_CONFIGURATION subsection: Verify IXIA Traffic """

        # Apply IXIA Traffic
        if ixLib.apply_traffic() == 1:
            log.info("Applying IXIA TI Passed")
        else:
            self.errored("Applying IXIA TI failed")

    @aetest.test
    def VERIFY_IXIA_TRAFFIC_after_rmBH_Route(self, testscript):
        """ IXIA_CONFIGURATION subsection: Verify IXIA Traffic """

        # Do not perform configurations if skip_tgen_config flag is set
        #if not testscript.parameters['script_flags']['skip_tgen_config']:

        time.sleep(20)

        if ixLib.verify_traffic(10) == 1:
            log.debug("Traffic Verification Passed.Expecting traffic loss here.") 
        else:
            log.info("Traffic Verification Failed. Expecting traffic loss here.")
            self.failed("Traffic Verification failed")
        # else:
        #     self.passed(reason="Skipped TGEN Configurations as per request")
    
    @aetest.cleanup
    def cleanup(self,testscript,testbed):
        """Unconfigure qos policies"""
        node3_s1_bgw_1 = testbed.devices['node3_s1_bgw_1']
        node5_s1_leaf_1 = testbed.devices['node5_s1_leaf_1']
        node10_s1_AccessSW =testbed.devices['node10_s1_AccessSW']
        node7_s2_bgw_1 =testbed.devices['node7_s2_bgw_1']
        P3_dict = AcceSW_TGEN_data
        forwardingSysDict = FWD_SYS_dict
        try:
            # Stop Traffic from ixia
            log.info("--- Stopping Traffic ---- \n")
            log.info("Stopping Traffic")
            traffic_run_status = ixLib.stop_traffic()
            
            if traffic_run_status is not 1:
               log.info("Failed: To Stop traffic")
               return 0
            else:
                log.info("\nTraffic Stopped successfully\n")
            time.sleep(10)
            ####Remove traffic item configured
            UCAST_v4_dict_1 = {
                            'mode'        : 'remove',
                            'stream_id'   : stream_id,
                      }
            if (ixLib.delete_traffic_item(UCAST_v4_dict_1))==0:
                log.debug("Traffic Remove failed")
                self.failed("Traffic Remove failed", goto=['next_tc'])
            else:
                log.info("Traffic Remove Passed")
            UCAST_v4_dict_2 = {
                            'mode'        : 'remove',
                            'stream_id'   : stream_id_1,
                      }
            if (ixLib.delete_traffic_item(UCAST_v4_dict_2))==0:
                log.debug("Traffic Remove failed")
                self.failed("Traffic Remove failed", goto=['next_tc'])
            else:
                log.info("Traffic Remove Passed")
            UCAST_v4_dict_3 = {
                            'mode'        : 'remove',
                            'stream_id'   : stream_id_2,
                      }
            if (ixLib.delete_traffic_item(UCAST_v4_dict_3))==0:
                log.debug("Traffic Remove failed")
                self.failed("Traffic Remove failed", goto=['next_tc'])
            else:
                log.info("Traffic Remove Passed")
            ###LEAF_1_MAC_BH_ROUTE
            testbed.devices['node3_s1_bgw_1'].configure(''' 
            
               no mac address-table static ''' + str(P3_dict['mac']) + ''' vlan '''+ str(P3_dict['vlan_id']) + ''' drop

                interface vlan ''' + str(P3_dict['vlan_id']) + '''
                  no ipv6 neighbor ''' + str(P3_dict['v6_addr']) + ''' ''' + str(P3_dict['mac']) + '''
                
            ''')
        except Exception as error:
            log.debug("Unable to do cleanup " + str(error))
            self.errored('Exception occurred during cleanup', goto=['next_tc'])   

class Mac_BH_route_on_standalone_vtep_start_L3_traffic(nxtest.Testcase):
    #"TC_0046_Mac_BH_route_on_standalone_vtep_start_L3_traffic"
    stream_id=''
    @aetest.test
    def CONFIGURE_UCAST_L3_IXIA_TRAFFIC_H2_to_H1_(self, testscript):
        """ IXIA_CONFIGURATION subsection: Configure MCAST Traffic Item """

        # Do not perform configurations if skip_tgen_config flag is set
        #if not testscript.parameters['script_flags']['skip_tgen_config']:

        IX_TP1 = testscript.parameters['IX_TP1']
        IX_TP2 = testscript.parameters['IX_TP2']
        IX_TP3 = testscript.parameters['IX_TP3']
        IX_TP4 = testscript.parameters['IX_TP4']
        P1_dict = S1_BGW1_TGEN_data
        P2_dict = S1_Leaf_TGEN_data
        P3_dict = AcceSW_TGEN_data
        P4_dict = S2_Leaf_TGEN_data


        UCAST_v4_dict_1 = {   'src_hndl'  : IX_TP1['port_handle'],
                            'dst_hndl'  : IX_TP3['port_handle'],
                            'circuit'   : 'raw',
                            'TI_name'   : "UCAST_v4",
                            'rate_pps'  : "9000",
                            'bi_dir'    : 0,
                            'frame_size': '128',
                            'src_mac'   : P1_dict['mac'],
                            'dst_mac'   : '0000.000a.aaaa',
                            'srcmac_step': '00:00:00:00:00:00',
                            'dstmac_step': '00:00:00:00:00:00',
                            'srcmac_count': '1',
                            'dstmac_count': '1',
                            'vlan_id'    : P1_dict['vlan_id'],
                            'vlanid_step': '0',
                            'vlanid_count': '1',
                            'vlan_user_priority': P1_dict['vlan_user_priority'],
                            'ip_src_addrs' : P1_dict['v4_addr'],
                            'ip_dst_addrs' : P3_dict['L3_dst_addr'],
                            'ip_src_step' : '0.0.0.0',
                            'ip_dscp'     : P1_dict['ip_dscp'],
                            'ip_dst_step' : '0.0.0.0',
#                                'ip_step'    : P1_dict['v4_addr_step'],
                        }

        UCAST_v4_TI = ixLib.configure_ixia_l3_traffic_item(UCAST_v4_dict_1)
            
        if UCAST_v4_TI == 0:
            log.debug("Configuring UCast TI failed")
            self.errored("Configuring UCast TI failed")
        else:
            global stream_id
            stream_id = UCAST_v4_TI

        # else:
        #     self.passed(reason="Skipped TGEN Configurations as per request")
    stream_id_1=''
    @aetest.test
    def CONFIGURE_UCAST_L3_IXIA_TRAFFIC_H3_to_H1_(self, testscript):
        """ IXIA_CONFIGURATION subsection: Configure MCAST Traffic Item """

        # Do not perform configurations if skip_tgen_config flag is set
        #if not testscript.parameters['script_flags']['skip_tgen_config']:

        IX_TP1 = testscript.parameters['IX_TP1']
        IX_TP2 = testscript.parameters['IX_TP2']
        IX_TP3 = testscript.parameters['IX_TP3']
        IX_TP4 = testscript.parameters['IX_TP4']
        P1_dict = S1_BGW1_TGEN_data
        P2_dict = S1_Leaf_TGEN_data
        P3_dict = AcceSW_TGEN_data
        P4_dict = S2_Leaf_TGEN_data


        UCAST_v4_dict_2 = {   'src_hndl'  : IX_TP2['port_handle'],
                            'dst_hndl'  : IX_TP3['port_handle'],
                            'circuit'   : 'raw',
                            'TI_name'   : "UCAST_v4",
                            'rate_pps'  : "9000",
                            'bi_dir'    : 0,
                            'frame_size': '128',
                            'src_mac'   : P2_dict['mac'],
                            'dst_mac'   : '0000.000a.aaaa',
                            'srcmac_step': '00:00:00:00:00:00',
                            'dstmac_step': '00:00:00:00:00:00',
                            'srcmac_count': '1',
                            'dstmac_count': '1',
                            'vlan_id'    : P2_dict['vlan_id'],
                            'vlanid_step': '0',
                            'vlanid_count': '2',
                            'vlan_user_priority': P2_dict['vlan_user_priority'],
                            'ip_src_addrs' : P2_dict['v4_addr'],
                            'ip_dst_addrs' : P3_dict['L3_dst_addr'],
                            'ip_src_step' : '0.0.0.0',
                            'ip_dscp'     : P2_dict['ip_dscp'],
                            'ip_dst_step' : '0.0.0.0',
#                                'ip_step'    : P1_dict['v4_addr_step'],
                        }

        UCAST_v4_TI_1 = ixLib.configure_ixia_l3_traffic_item(UCAST_v4_dict_2)
            
        if UCAST_v4_TI_1 == 0:
            log.debug("Configuring UCast TI failed")
            self.errored("Configuring UCast TI failed", goto=['cleanup'])
        else:
            global stream_id_1
            stream_id_1 = UCAST_v4_TI_1

        # else:
        #     self.passed(reason="Skipped TGEN Configurations as per request")
    stream_id_2=''
    @aetest.test
    def CONFIGURE_UCAST_L3_IXIA_TRAFFIC_H4_to_H1_(self, testscript):
        """ IXIA_CONFIGURATION subsection: Configure MCAST Traffic Item """

        # Do not perform configurations if skip_tgen_config flag is set
        #if not testscript.parameters['script_flags']['skip_tgen_config']:

        IX_TP1 = testscript.parameters['IX_TP1']
        IX_TP2 = testscript.parameters['IX_TP2']
        IX_TP3 = testscript.parameters['IX_TP3']
        IX_TP4 = testscript.parameters['IX_TP4']
        P1_dict = S1_BGW1_TGEN_data
        P2_dict = S1_Leaf_TGEN_data
        P3_dict = AcceSW_TGEN_data
        P4_dict = S2_Leaf_TGEN_data


        UCAST_v4_dict_3 = {   'src_hndl'  : IX_TP4['port_handle'],
                            'dst_hndl'  : IX_TP3['port_handle'],
                            'circuit'   : 'raw',
                            'TI_name'   : "UCAST_v4",
                            'rate_pps'  : "9000",
                            'bi_dir'    : 0,
                            'frame_size': '128',
                            'src_mac'   : P4_dict['mac'],
                            'dst_mac'   : '0000.000a.aaaa',
                            'srcmac_step': '00:00:00:00:00:00',
                            'dstmac_step': '00:00:00:00:00:00',
                            'srcmac_count': '1',
                            'dstmac_count': '1',
                            'vlan_id'    : P4_dict['vlan_id'],
                            'vlanid_step': '0',
                            'vlanid_count': '2',
                            'vlan_user_priority': P4_dict['vlan_user_priority'],
                            'ip_src_addrs' : P4_dict['v4_addr'],
                            'ip_dst_addrs' : P3_dict['L3_dst_addr'],
                            'ip_src_step' : '0.0.0.0',
                            'ip_dst_step' : '0.0.0.0',
                            'ip_dscp'     : P4_dict['ip_dscp'],
#                                'ip_step'    : P1_dict['v4_addr_step'],
                        }

        UCAST_v4_TI_2 = ixLib.configure_ixia_l3_traffic_item(UCAST_v4_dict_3)
            
        if UCAST_v4_TI_2 == 0:
            log.debug("Configuring UCast TI failed")
            self.errored("Configuring UCast TI failed", goto=['cleanup'])
        else:
            global stream_id_2
            stream_id_2 = UCAST_v4_TI_2

        # else:
        #     self.passed(reason="Skipped TGEN Configurations as per request")

    @aetest.test
    def APPLY_TRAFFIC(self):
        """ IXIA_CONFIGURATION subsection: Verify IXIA Traffic """

        # Apply IXIA Traffic
        if ixLib.apply_traffic() == 1:
            log.info("Applying IXIA TI Passed")
        else:
            self.errored("Applying IXIA TI failed")

    @aetest.test
    def VERIFY_IXIA_TRAFFIC_Without_BH_Route(self, testscript):
        """ IXIA_CONFIGURATION subsection: Verify IXIA Traffic """

        # Do not perform configurations if skip_tgen_config flag is set
        #if not testscript.parameters['script_flags']['skip_tgen_config']:

        time.sleep(20)

        if ixLib.verify_traffic(10) == 1:
            log.debug("Traffic Verification Passed.Expecting traffic loss here.") 
        else:
            log.info("Traffic Verification Failed. Expecting traffic loss here.")
            self.failed("Traffic Verification failed")
        # else:
        #     self.passed(reason="Skipped TGEN Configurations as per request")

    
    @aetest.test
    def Config_Mac_BH_on_Vpc_Vtep(self, testscript,testbed):
        node7_s2_bgw_1 = testbed.devices['node7_s2_bgw_1']
        P3_dict = AcceSW_TGEN_data
        mac= str(P3_dict['mac'])
        vlan= str(P3_dict['vlan_id'])
        ip=str(P3_dict['v4_addr'])
        octet = 2
        no_int= int(P3_dict['no_of_ints'])

        for i in range (0,no_int):
            ###LEAF_3_MAC_BH_ROUTE
            testbed.devices['node7_s2_bgw_1'].configure('''
                mac address-table static ''' + str(mac) + ''' vlan '''+ str(vlan) + ''' drop

                interface vlan ''' + str(vlan) + '''
                  ip arp ''' + str(ip) + ''' ''' + str(mac) + '''
            ''')
            lasthex=incr_mac(mac)
            mac=mac[0:10]+lasthex
            vlan= int(vlan)+int(P3_dict['vlan_id_step'])
            ip=incr_ip(ip,octet) 

            
        # except Exception as error:
        #     log.debug("Unable to configure static BH mac route - Encountered Exception " + str(error))
        #     self.errored('Exception occurred while configuring static BH mac route', goto=['cleanup']) 

    @aetest.test
    def APPLY_TRAFFIC(self):
        """ IXIA_CONFIGURATION subsection: Verify IXIA Traffic """

        # Apply IXIA Traffic
        if ixLib.apply_traffic() == 1:
            log.info("Applying IXIA TI Passed")
        else:
            self.errored("Applying IXIA TI failed")

    @aetest.test
    def VERIFY_IXIA_TRAFFIC_With_BH_Route(self, testscript):
        """ IXIA_CONFIGURATION subsection: Verify IXIA Traffic """

        # Do not perform configurations if skip_tgen_config flag is set
        #if not testscript.parameters['script_flags']['skip_tgen_config']:

        time.sleep(20)

        if ixLib.verify_traffic(99) == 0:
            log.debug("Traffic Verification Passed.Expecting traffic loss here.") 
        else:
            log.info("Traffic Verification Failed. Expecting traffic loss here.")
            self.failed("Traffic Verification failed")
        # else:
        #     self.passed(reason="Skipped TGEN Configurations as per request")

    @aetest.test
    def Verify_Traffic_Drop_on_Remote_Vtep(self,testscript,testbed):
        node5_s1_leaf_1 = testbed.devices['node5_s1_leaf_1']
        node9_s2_leaf_1 = testbed.devices['node9_s2_leaf_1']
        node3_s1_bgw_1 = testbed.devices['node3_s1_bgw_1']
        P3_dict = AcceSW_TGEN_data
        uplink_PO=S1_Leaf_dict['S1_Leaf_UPLINK_PO']['po_id']
        if verify_traffic_drop(node5_s1_leaf_1,uplink_PO):
            log.info('Traffic correctly dropped on  S1_Leaf')
        else:
            log.info('Traffic NOT dropped on  S1_Leaf')
            self.failed('Traffic NOT dropped on  S1_Leaf')
        
        uplink_PO=S2_Leaf_dict['S2_Leaf_UPLINK_PO']['po_id']
        if verify_traffic_drop(node9_s2_leaf_1,uplink_PO):
            log.info('Traffic correctly dropped on  S2_Leaf')
        else:
            log.info('Traffic NOT dropped on  S2_Leaf')
            self.failed('Traffic NOT dropped on  S2_Leaf')

        uplink_PO=S1_BGW1_dict['S1_BGW1_UPLINK_PO']['po_id']
        if verify_traffic_drop(node3_s1_bgw_1,uplink_PO):
            log.info('Traffic correctly dropped on  S1_BGW1')
        else:
            log.info('Traffic NOT dropped on  S1_BGW1')
            self.failed('Traffic NOT dropped on  S1_BGW1')

    @aetest.test
    def verify_static_mac_states(self, testscript,testbed):
        node3_s1_bgw_1 = testbed.devices['node3_s1_bgw_1']
        node7_s2_bgw_1 = testbed.devices['node7_s2_bgw_1']
        P3_dict = AcceSW_TGEN_data
        if verify_static_mac(node3_s1_bgw_1,str(P3_dict['mac']),str(P3_dict['vlan_id'])):
            log.info('proper static mac learnt on S1_BGw1')
        else:
            log.info('improper static mac learnt on  S1_BGw1')
            self.failed('improper static mac learnt on  S1_BGw1')

        if verify_static_mac(node7_s2_bgw_1,str(P3_dict['mac']),str(P3_dict['vlan_id'])):
            log.info('proper static mac learnt on  S2_BGw1')
        else:
            log.info('improper static mac learnt on S2_BGw1')
            self.failed('improper static mac learnt on  S2_BGw1')   
    
    
    @aetest.test
    def Verify_BH_states_in_HMM(self, testscript,testbed):
        node3_s1_bgw_1 =testbed.devices['node3_s1_bgw_1']
        node7_s2_bgw_1 = testbed.devices['node7_s2_bgw_1']
        P3_dict = AcceSW_TGEN_data
        try:
            if verify_BH_in_HMM(node7_s2_bgw_1,str(P3_dict['v4_addr'])):
                log.info('Mac BH route is proper in HMM on  S1_BGW1')
            else:
                log.info('Mac BH route is improper in HMM on  S1_BGW1')
                self.failed('Mac BH route is improper in HMM on  S1_BGW1')
        
         
        except Exception as error:
            log.debug("Unable to configure static BH mac route on Remote Vtep- Encountered Exception " + str(error))
            self.errored('Exception occurred while configuring static BH mac route on Remote Vtep')

    @aetest.test
    def Verify_BH_states_in_AM(self, testscript,testbed):
        node3_s1_bgw_1 = testbed.devices['node3_s1_bgw_1']
        node7_s2_bgw_1 = testbed.devices['node7_s2_bgw_1']
        P3_dict = AcceSW_TGEN_data

        try:        
            if verify_BH_in_AM(node7_s2_bgw_1,str(P3_dict['mac']),str(P3_dict['vlan_id']),str(P3_dict['v4_addr'])):
                log.info('Mac BH route is proper in AM on  S1_BGW1')
            else:
                log.info('Mac BH route is improper in AM on  S1_BGW1')
                self.failed('Mac BH route is improper in AM on  S1_BGW1')
        
        except Exception as error:
            log.debug("Unable to configure static BH mac route on Remote Vtep- Encountered Exception " + str(error))
            self.errored('Exception occurred while configuring static BH mac route on Remote Vtep')
    
    @aetest.test
    def Verify_BH_states_in_remote_ARP(self, testscript,testbed):
        node3_s1_bgw_1 = testbed.devices['node3_s1_bgw_1']
        node7_s2_bgw_1 = testbed.devices['node7_s2_bgw_1']
        P3_dict = AcceSW_TGEN_data

        try: 

            if verify_BH_in_Remote_ARP(node3_s1_bgw_1,str(P3_dict['vlan_id']),str(P3_dict['mac'])):
               log.info('Mac BH route is proper in Remote ARP on  S2_BGW1')
            else:
                log.info('Mac BH route is improper in Remote ARP on  S2_BGW1')
                self.failed('Mac BH route is improper in Remote ARP on  S2_BGW1')

        except Exception as error:
            log.debug("Unable to configure static BH mac route on Remote Vtep- Encountered Exception " + str(error))
            self.errored('Exception occurred while configuring static BH mac route on Remote Vtep')        
    
    @aetest.test
    def Verify_BH_states_in_local_ARP(self, testscript,testbed):
        node3_s1_bgw_1 = testbed.devices['node3_s1_bgw_1']
        node7_s2_bgw_1 = testbed.devices['node7_s2_bgw_1']
        P3_dict = AcceSW_TGEN_data

        try:        
            if verify_BH_in_local_ARP(node7_s2_bgw_1,str(P3_dict['vlan_id']),str(P3_dict['mac'])):
                log.info('Mac BH route is proper in Local ARP on  S1_BGW1')
            else:
                log.info('Mac BH route is improper in Local ARP on  S1_BGW1')
                self.failed('Mac BH route is improper in Local ARP on  S1_BGW1')
        
        except Exception as error:
            log.debug("Unable to configure static BH mac route on Remote Vtep- Encountered Exception " + str(error))
            self.errored('Exception occurred while configuring static BH mac route on Remote Vtep')
        
    @aetest.test
    def Verify_Mac_BH_Route_on_L2FM_BGP_L2RIB(self,testscript,testbed):
        node3_s1_bgw_1 =testbed.devices['node3_s1_bgw_1']
        node7_s2_bgw_1 = testbed.devices['node7_s2_bgw_1']
        P3_dict = AcceSW_TGEN_data      
        # Verifying L2FM

        try:
            ###S1_BGW1_MAC_BH_ROUTE
            if verify_BH_route_in_L2FM(node3_s1_bgw_1,str(P3_dict['vlan_id']),str(P3_dict['mac'])):
                log.info('Mac BH route is proper in L2FM on  S1_BGw1')
            else:
                log.info('Mac BH route is improper in L2FM on  S1_BGw1')
                self.failed('Mac BH route is improper in L2FM on  S1_BGw1')

            ###S2_BGW1_MAC_BH_ROUTE Remote Vtep
            if verify_BH_route_in_L2FM(node7_s2_bgw_1,str(P3_dict['vlan_id']),str(P3_dict['mac'])):
                log.info('Mac BH route is proper in L2FM on  S2_BGw1')
            else:
                log.info('Mac BH route is improper in L2FM on  S2_BGw1')
                self.failed('Mac BH route is improper in L2FM on  S2_BGw1')

        except Exception as error:
            log.debug("Unable to verify BH mac route in L2FM - Encountered Exception " + str(error))
            self.errored('Exception occurred while verifying BH mac route in L2FM')        

        #Verifying L2RIB
        try:
            #S1_Leaf_Mac_BH_route
            if verify_L2rib_mac_ip_output(node3_s1_bgw_1,str(P3_dict['vlan_id']),str(P3_dict['mac'])):
                log.info('Mac BH route is proper in L2RIB on S1_Leaf')
            else:
                log.debug('Mac BH route is improper in L2RIB on  S1_Leaf')
                self.failed('Mac BH route is improper in L2RIB on  S1_Leaf')

            #S2_BGW1_Mac_BH_route
            if verify_L2rib_mac_ip_output(node7_s2_bgw_1,str(P3_dict['vlan_id']),str(P3_dict['mac'])):
                log.info('Mac BH route is proper in L2RIB on S2_BGW1')
            else:
                log.debug('Mac BH route is improper in L2RIB on  S2_BGW1')
                self.errored('Mac BH route is improper in L2RIB on  S2_BGW1')
        
        except Exception as error:
            log.debug("Unable to verify BH mac route in L2RIB - Encountered Exception " + str(error))
            self.errored('Exception occurred while verifying BH mac route in L2RIB')
        
        #Verifying BGP
        try:
            #S2_BGW1_Mac_BH_route
            if verify_BH_in_Remote_BGP(node7_s2_bgw_1,str(P3_dict['mac'])):
                log.info('Mac BH route is proper in BGP on S2_BGW1')
            else:
                log.debug('Mac BH route is improper in BGP on  S2_BGW1')
                self.errored('Mac BH route is improper in BGP on  S2_BGW1')

            #Access_Mac_BH_route
            if verify_BH_in_Remote_BGP(node3_s1_bgw_1,str(P3_dict['mac'])):
                log.info('Mac BH route is proper in BGP on Access')
            else:
                log.debug('Mac BH route is improper in BGP on  Access')
                self.errored('Mac BH route is improper in BGP on  Access')
        
        except Exception as error:
            log.debug("Unable to verify BH mac route in BGP - Encountered Exception " + str(error))
            self.errored('Exception occurred while verifying BH mac route in BGP')

    @aetest.test
    def UnConfig_Mac_BH_on_Vpc_Vtep(self, testscript,testbed):
        node7_s2_bgw_1 = testbed.devices['node7_s2_bgw_1']
        P3_dict = AcceSW_TGEN_data
        mac= str(P3_dict['mac'])
        vlan= str(P3_dict['vlan_id'])
        ip=str(P3_dict['v4_addr'])
        octet = 2
        no_int= int(P3_dict['no_of_ints'])

        for i in range (0,no_int):
            ###LEAF_3_MAC_BH_ROUTE
            testbed.devices['node7_s2_bgw_1'].configure('''
                no mac address-table static ''' + str(mac) + ''' vlan '''+ str(vlan) + ''' drop

                interface vlan ''' + str(vlan) + '''
                  no ip arp ''' + str(ip) + ''' ''' + str(mac) + '''
            ''')
            lasthex=incr_mac(mac)
            mac=mac[0:10]+lasthex
            vlan= int(vlan)+int(P3_dict['vlan_id_step'])
            ip=incr_ip(ip,octet) 
       
        # except Exception as error:
        #     log.debug("Unable to configure static BH mac route - Encountered Exception " + str(error))
        #     self.errored('Exception occurred while configuring static BH mac route', goto=['cleanup']) 

    @aetest.test
    def VERIFY_IXIA_TRAFFIC_after_rmBH_Route(self, testscript):
        """ IXIA_CONFIGURATION subsection: Verify IXIA Traffic """

        # Do not perform configurations if skip_tgen_config flag is set
        #if not testscript.parameters['script_flags']['skip_tgen_config']:

        time.sleep(20)

        if ixLib.verify_traffic(10) == 1:
            log.debug("Traffic Verification Passed.Expecting traffic loss here.") 
        else:
            log.info("Traffic Verification Failed. Expecting traffic loss here.")
            self.failed("Traffic Verification failed")
        # else:
        #     self.passed(reason="Skipped TGEN Configurations as per request")
    
    @aetest.cleanup
    def cleanup(self,testscript,testbed):
        """Unconfigure qos policies"""
        node3_s1_bgw_1 = testbed.devices['node3_s1_bgw_1']
        node5_s1_leaf_1 = testbed.devices['node5_s1_leaf_1']
        node10_s1_AccessSW =testbed.devices['node10_s1_AccessSW']
        node7_s2_bgw_1 =testbed.devices['node7_s2_bgw_1']
        P3_dict = AcceSW_TGEN_data
        forwardingSysDict = FWD_SYS_dict
        try:
            # Stop Traffic from ixia
            log.info("--- Stopping Traffic ---- \n")
            log.info("Stopping Traffic")
            traffic_run_status = ixLib.stop_traffic()
            
            if traffic_run_status is not 1:
               log.info("Failed: To Stop traffic")
               return 0
            else:
                log.info("\nTraffic Stopped successfully\n")
            time.sleep(10)
            ####Remove traffic item configured
            UCAST_v4_dict_1 = {
                            'mode'        : 'remove',
                            'stream_id'   : stream_id,
                      }
            if (ixLib.delete_traffic_item(UCAST_v4_dict_1))==0:
                log.debug("Traffic Remove failed")
                self.failed("Traffic Remove failed", goto=['next_tc'])
            else:
                log.info("Traffic Remove Passed")
            UCAST_v4_dict_2 = {
                            'mode'        : 'remove',
                            'stream_id'   : stream_id_1,
                      }
            if (ixLib.delete_traffic_item(UCAST_v4_dict_2))==0:
                log.debug("Traffic Remove failed")
                self.failed("Traffic Remove failed", goto=['next_tc'])
            else:
                log.info("Traffic Remove Passed")
            UCAST_v4_dict_3 = {
                            'mode'        : 'remove',
                            'stream_id'   : stream_id_2,
                      }
            if (ixLib.delete_traffic_item(UCAST_v4_dict_3))==0:
                log.debug("Traffic Remove failed")
                self.failed("Traffic Remove failed", goto=['next_tc'])
            else:
                log.info("Traffic Remove Passed")
            ###LEAF_1_MAC_BH_ROUTE
            testbed.devices['node7_s2_bgw_1'].configure(''' 
            
               no mac address-table static ''' + str(P3_dict['mac']) + ''' vlan '''+ str(P3_dict['vlan_id']) + ''' drop

                interface vlan ''' + str(P3_dict['vlan_id']) + '''
                  no ipv6 neighbor ''' + str(P3_dict['v6_addr']) + ''' ''' + str(P3_dict['mac']) + '''
                
            ''')
        except Exception as error:
            log.debug("Unable to do cleanup " + str(error))
            self.errored('Exception occurred during cleanup', goto=['next_tc'])   
    

###################################################################
###              L3 Ucast with IPv6header  Test-cases          ###
###################################################################

class Mac_BH_route_static_arp_on_VPC_vtep_with_L3_ipv6_traffic(nxtest.Testcase):
    #"TC_0048_Mac_BH_route_static_arp_on_VPC_vtep_with_L3_ipv6_traffic"
    stream_id=''
    @aetest.test
    def CONFIGURE_UCAST_L3_IXIA_TRAFFIC_H2_to_H1(self, testscript):
        """ IXIA_CONFIGURATION subsection: Configure MCAST Traffic Item """

        # Do not perform configurations if skip_tgen_config flag is set
        #if not testscript.parameters['script_flags']['skip_tgen_config']:

        IX_TP1 = testscript.parameters['IX_TP1']
        IX_TP2 = testscript.parameters['IX_TP2']
        IX_TP3 = testscript.parameters['IX_TP3']
        IX_TP4 = testscript.parameters['IX_TP4']
        P1_dict = S1_BGW1_TGEN_data
        P2_dict = S1_Leaf_TGEN_data
        P3_dict = AcceSW_TGEN_data
        P4_dict = S2_Leaf_TGEN_data


        UCAST_v6_dict_1 = {   'src_hndl'  : testscript.parameters['port_handle_1'],
                            'dst_hndl'  : testscript.parameters['port_handle_3'],
                            'circuit'   : 'raw',
                            'TI_name'   : "UCAST_v6",
                            'rate_pps'  : "9000",
                            'bi_dir'    : 0,
                            'frame_size': '128',
                            'src_mac'   : P1_dict['mac'],
                            'dst_mac'   : '0000.000a.aaaa',
                            'srcmac_step': '00:00:00:00:00:00',
                            'dstmac_step': '00:00:00:00:00:00',
                            'srcmac_count': '1',
                            'dstmac_count': '1',
                            'vlan_id'    : P1_dict['vlan_id'],
                            'vlanid_step': '0',
                            'vlanid_count': '1',
                            'vlan_user_priority': P1_dict['vlan_user_priority'],
                            'ipv6_src_addrs' : P1_dict['v6_addr'],
                            'ipv6_dst_addrs' : P3_dict['L3_v6_dst_addr'],
                            'ipv6_src_step' : '0:0:0:0::0',
                            'ipv6_dst_step' : '0:0:0:0::0',
                            #'ip_dscp'     : P1_dict['ip_dscp'],
#                                'ip_step'    : P1_dict['v4_addr_step'],
                        }
        
        # UCAST_v6_dict = {   'src_hndl'  : IX_TP1['ipv6_handle'],
        #                        'dst_hndl'  : IX_TP3['ipv6_handle'],
        #                        'circuit'   : 'ipv6',
        #                        'TI_name'   : "UCAST_V6",
        #                        'rate_pps'  : "9000",
        #                        'bi_dir'    : 1,
        #                        'frame_size': '128',
        #                  }


        

        UCAST_v6_TI = ixLib.configure_ixia_l3_traffic_item_ipv6(UCAST_v6_dict_1)
            
        if UCAST_v6_TI == 0:
            log.debug("Configuring UCast TI failed")
            self.errored("Configuring UCast TI failed", goto=['cleanup'])
        else:
            global stream_id
            stream_id = UCAST_v6_TI

        # else:
        #     self.passed(reason="Skipped TGEN Configurations as per request")
    
    stream_id_1=''
    @aetest.test
    def CONFIGURE_UCAST_L3_IXIA_TRAFFIC_H3_to_H1(self, testscript):
        """ IXIA_CONFIGURATION subsection: Configure MCAST Traffic Item """

        # Do not perform configurations if skip_tgen_config flag is set
        #if not testscript.parameters['script_flags']['skip_tgen_config']:

        IX_TP1 = testscript.parameters['IX_TP1']
        IX_TP2 = testscript.parameters['IX_TP2']
        IX_TP3 = testscript.parameters['IX_TP3']
        IX_TP4 = testscript.parameters['IX_TP4']
        P1_dict = S1_BGW1_TGEN_data
        P2_dict = S1_Leaf_TGEN_data
        P3_dict = AcceSW_TGEN_data
        P4_dict = S2_Leaf_TGEN_data


        UCAST_v6_dict_2 = {   'src_hndl'  : testscript.parameters['port_handle_2'],
                            'dst_hndl'  : testscript.parameters['port_handle_3'],
                            'circuit'   : 'raw',
                            'TI_name'   : "UCAST_v6",
                            'rate_pps'  : "9000",
                            'bi_dir'    : 0,
                            'frame_size': '128',
                            'src_mac'   : P2_dict['mac'],
                            'dst_mac'   : '0000.000a.aaaa',
                            'srcmac_step': '00:00:00:00:00:00',
                            'dstmac_step': '00:00:00:00:00:00',
                            'srcmac_count': '1',
                            'dstmac_count': '1',
                            'vlan_id'    : P2_dict['vlan_id'],
                            'vlanid_step': '0',
                            'vlanid_count': '1',
                            'vlan_user_priority': P2_dict['vlan_user_priority'],
                            'ipv6_src_addrs' : P2_dict['v6_addr'],
                            'ipv6_dst_addrs' : P3_dict['L3_v6_dst_addr'],
                            'ipv6_src_step' :  '0:0:0:0::0',
                            'ipv6_dst_step' :  '0:0:0:0::0',
                            #'ip_dscp'     : P2_dict['ip_dscp'],
#                                'ip_step'    : P1_dict['v4_addr_step'],
                        }
        
        # UCAST_v6_dict = {   'src_hndl'  : IX_TP2['ipv6_handle'],
        #                        'dst_hndl'  : IX_TP3['ipv6_handle'],
        #                        'circuit'   : 'ipv6',
        #                        'TI_name'   : "UCAST_V6",
        #                        'rate_pps'  : "9000",
        #                        'bi_dir'    : 1
        #                  }


        UCAST_v6_TI_1 = ixLib.configure_ixia_l3_traffic_item_ipv6(UCAST_v6_dict_2)
            
        if UCAST_v6_TI_1 == 0:
            log.debug("Configuring UCast TI failed")
            self.errored("Configuring UCast TI failed", goto=['cleanup'])
        else:
            global stream_id_1
            stream_id_1 = UCAST_v6_TI_1

        # else:
        #     self.passed(reason="Skipped TGEN Configurations as per request")
    
    stream_id_2=''
    @aetest.test
    def CONFIGURE_UCAST_L3_IXIA_TRAFFIC_H4_to_H1(self, testscript):
        """ IXIA_CONFIGURATION subsection: Configure MCAST Traffic Item """

        # Do not perform configurations if skip_tgen_config flag is set
        #if not testscript.parameters['script_flags']['skip_tgen_config']:

        IX_TP1 = testscript.parameters['IX_TP1']
        IX_TP2 = testscript.parameters['IX_TP2']
        IX_TP3 = testscript.parameters['IX_TP3']
        IX_TP4 = testscript.parameters['IX_TP4']
        P1_dict = S1_BGW1_TGEN_data
        P2_dict = S1_Leaf_TGEN_data
        P3_dict = AcceSW_TGEN_data
        P4_dict = S2_Leaf_TGEN_data


        UCAST_v6_dict_3 = {   'src_hndl'  : testscript.parameters['port_handle_4'],
                            'dst_hndl'  : testscript.parameters['port_handle_3'],
                            'circuit'   : 'raw',
                            'TI_name'   : "UCAST_v6",
                            'rate_pps'  : "9000",
                            'bi_dir'    : 1,
                            'frame_size': '128',
                            'src_mac'   : P4_dict['mac'],
                            'dst_mac'   : '0000.000a.aaaa',
                            'srcmac_step': '00:00:00:00:00:00',
                            'dstmac_step': '00:00:00:00:00:00',
                            'srcmac_count': '1',
                            'dstmac_count': '1',
                            'vlan_id'    : P4_dict['vlan_id'],
                            'vlanid_step': '0',
                            'vlanid_count': '1',
                            'vlan_user_priority': P4_dict['vlan_user_priority'],
                            'ipv6_src_addrs' : P4_dict['v6_addr'],
                            'ipv6_dst_addrs' : P3_dict['L3_v6_dst_addr'],
                            'ipv6_src_step' : '0:0:0:0::0',
                            'ipv6_dst_step' : '0:0:0:0::0',
                            #'ip_dscp'     : P4_dict['ip_dscp'],
#                                'ip_step'    : P1_dict['v4_addr_step'],
                        }

        # UCAST_v6_dict = {   'src_hndl'  : IX_TP4['ipv6_handle'],
        #                        'dst_hndl'  : IX_TP3['ipv6_handle'],
        #                        'circuit'   : 'ipv6',
        #                        'TI_name'   : "UCAST_V6",
        #                        'rate_pps'  : "9000",
        #                        'bi_dir'    : 1
        #                  }

        UCAST_v6_TI_2 = ixLib.configure_ixia_l3_traffic_item_ipv6(UCAST_v6_dict_3)
            
        if UCAST_v6_TI_2 == 0:
            log.debug("Configuring UCast TI failed")
            self.errored("Configuring UCast TI failed", goto=['cleanup'])
        else:
            global stream_id_2
            stream_id_2 = UCAST_v6_TI_2

        # else:
        #     self.passed(reason="Skipped TGEN Configurations as per request")
    
    @aetest.test
    def APPLY_TRAFFIC(self):
        """ IXIA_CONFIGURATION subsection: Verify IXIA Traffic """

        # Apply IXIA Traffic
        if ixLib.apply_traffic() == 1:
            log.info("Applying IXIA TI Passed")
        else:
            self.errored("Applying IXIA TI failed")

    @aetest.test
    def VERIFY_IXIA_TRAFFIC_Without_BH_Route(self, testscript):
        """ IXIA_CONFIGURATION subsection: Verify IXIA Traffic """

        # Do not perform configurations if skip_tgen_config flag is set
        #if not testscript.parameters['script_flags']['skip_tgen_config']:

        time.sleep(20)

        if ixLib.verify_traffic(10) == 1:
            log.debug("Traffic Verification Passed.") 
        else:
            log.info("Traffic Verification Failed.")
            self.failed("Traffic Verification failed")
        # else:
        #     self.passed(reason="Skipped TGEN Configurations as per request")

    @aetest.test
    def Config_Mac_BH_Static_ND_on_VPC(self,testscript,testbed):
        node3_s1_bgw_1 = testbed.devices['node3_s1_bgw_1']
        node4_s1_bgw_2 = testbed.devices['node4_s1_bgw_2']
        P3_dict = AcceSW_TGEN_data
        mac= str(P3_dict['mac'])
        vlan= str(P3_dict['vlan_id'])
        ipv6=str(P3_dict['v6_addr'])
        octet = 2
        no_int= int(P3_dict['no_of_ints'])
        
        for i in range (0,no_int):
            ###LEAF_3_MAC_BH_ROUTE
            testbed.devices['node3_s1_bgw_1'].configure('''
                mac address-table static ''' + str(mac) + ''' vlan '''+ str(vlan) + ''' drop

                interface vlan ''' + str(vlan) + '''
                    ipv6 neighbor ''' + str(ipv6) + ''' ''' + str(mac) + '''
            ''')
        
            testbed.devices['node4_s1_bgw_2'].configure('''
                mac address-table static ''' + str(mac) + ''' vlan '''+ str(vlan) + ''' drop

                interface vlan ''' + str(vlan) + '''
                    ipv6 neighbor ''' + str(ipv6) + ''' ''' + str(mac) + '''
            ''')
            lasthex=incr_mac(mac)
            mac=mac[0:10]+lasthex
            vlan= int(vlan)+int(P3_dict['vlan_id_step'])
            ipv6=incr_ipv6(ipv6,octet) 

    

    @aetest.test
    def APPLY_TRAFFIC(self):
        """ IXIA_CONFIGURATION subsection: Verify IXIA Traffic """

        # Apply IXIA Traffic
        if ixLib.apply_traffic() == 1:
            log.info("Applying IXIA TI Passed")
        else:
            self.errored("Applying IXIA TI failed")

    @aetest.test
    def VERIFY_IXIA_TRAFFIC_With_BH_Route(self, testscript):
        """ IXIA_CONFIGURATION subsection: Verify IXIA Traffic """

        # Do not perform configurations if skip_tgen_config flag is set
        #if not testscript.parameters['script_flags']['skip_tgen_config']:

        time.sleep(20)

        if ixLib.verify_traffic(99) == 0:
            log.debug("Traffic Verification Passed.")
            # ForkedPdb().set_trace() 
        else:
            log.info("Traffic Verification Failed.")
            self.failed("Traffic Verification failed")
            # ForkedPdb().set_trace()
        # else:
        #     self.passed(reason="Skipped TGEN Configurations as per request")
    @aetest.test
    def Verify_Traffic_Drop_on_Remote_Vtep(self,testscript,testbed):
        node5_s1_leaf_1 = testbed.devices['node5_s1_leaf_1']
        node9_s2_leaf_1 = testbed.devices['node9_s2_leaf_1']
        node7_s2_bgw_1 = testbed.devices['node7_s2_bgw_1']
        P3_dict = AcceSW_TGEN_data
        uplink_PO=S1_Leaf_dict['S1_Leaf_UPLINK_PO']['po_id']
        if verify_traffic_drop(node5_s1_leaf_1,uplink_PO):
            log.info('Traffic correctly dropped on  S1_Leaf')
        else:
            log.info('Traffic NOT dropped on  S1_Leaf')
            self.failed('Traffic NOT dropped on  S1_Leaf')
        
        uplink_PO=S2_Leaf_dict['S2_Leaf_UPLINK_PO']['po_id']
        if verify_traffic_drop(node9_s2_leaf_1,uplink_PO):
            log.info('Traffic correctly dropped on  S2_Leaf')
        else:
            log.info('Traffic NOT dropped on  S2_Leaf')
            self.failed('Traffic NOT dropped on  S2_Leaf')

        uplink_PO=S2_BGW1_dict['S2_BGW1_UPLINK_PO']['po_id']
        if verify_traffic_drop(node7_s2_bgw_1,uplink_PO):
            log.info('Traffic correctly dropped on  S2_BGW1')
            #ForkedPdb().set_trace()
        else:
            log.info('Traffic NOT dropped on  S2_BGW1')
            self.failed('Traffic NOT dropped on  S2_BGW1')
            #ForkedPdb().set_trace() 
    
    
    @aetest.test
    def Verify_BH_states_in_HMM(self, testscript,testbed):
        node3_s1_bgw_1 =testbed.devices['node3_s1_bgw_1']
        node7_s2_bgw_1 = testbed.devices['node7_s2_bgw_1']
        P3_dict = AcceSW_TGEN_data
        try:
            if verify_Ipv6_BH_in_HMM(node3_s1_bgw_1,str(P3_dict['v6_addr'])):
                log.info('Mac BH route is proper in HMM on  S1_BGW1')
            else:
                log.info('Mac BH route is improper in HMM on  S1_BGW1')
                self.failed('Mac BH route is improper in HMM on  S1_BGW1')
        
         
        except Exception as error:
            log.debug("Unable to configure static BH mac route on Remote Vtep- Encountered Exception " + str(error))
            self.errored('Exception occurred while configuring static BH mac route on Remote Vtep')

    @aetest.test
    def Verify_BH_states_in_AM(self, testscript,testbed):
        node3_s1_bgw_1 = testbed.devices['node3_s1_bgw_1']
        node7_s2_bgw_1 = testbed.devices['node7_s2_bgw_1']
        P3_dict = AcceSW_TGEN_data

        try:        
            if verify_Ipv6_BH_in_AM(node3_s1_bgw_1,str(P3_dict['mac']),str(P3_dict['vlan_id']),str(P3_dict['v6_addr'])):
                log.info('Mac BH route is proper in AM on  S1_BGW1')
            else:
                log.info('Mac BH route is improper in AM on  S1_BGW1')
                self.failed('Mac BH route is improper in AM on  S1_BGW1')
        
        except Exception as error:
            log.debug("Unable to configure static BH mac route on Remote Vtep- Encountered Exception " + str(error))
            self.errored('Exception occurred while configuring static BH mac route on Remote Vtep')
        
    @aetest.test
    def Verify_Mac_BH_Route_on_L2FM_BGP_L2RIB(self,testscript,testbed):
        node3_s1_bgw_1 =testbed.devices['node3_s1_bgw_1']
        node7_s2_bgw_1 = testbed.devices['node7_s2_bgw_1']
        P3_dict = AcceSW_TGEN_data      
        # Verifying L2FM

        try:
            ###S1_BGW1_MAC_BH_ROUTE
            if verify_BH_route_in_L2FM(node3_s1_bgw_1,str(P3_dict['vlan_id']),str(P3_dict['mac'])):
                log.info('Mac BH route is proper in L2FM on  S1_BGw1')
            else:
                log.info('Mac BH route is improper in L2FM on  S1_BGw1')
                self.failed('Mac BH route is improper in L2FM on  S1_BGw1')

            ###S2_BGW1_MAC_BH_ROUTE Remote Vtep
            if verify_BH_route_in_L2FM(node7_s2_bgw_1,str(P3_dict['vlan_id']),str(P3_dict['mac'])):
                log.info('Mac BH route is proper in L2FM on  S2_BGw1')
            else:
                log.info('Mac BH route is improper in L2FM on  S2_BGw1')
                self.failed('Mac BH route is improper in L2FM on  S2_BGw1')

        except Exception as error:
            log.debug("Unable to verify BH mac route in L2FM - Encountered Exception " + str(error))
            self.errored('Exception occurred while verifying BH mac route in L2FM')        

        #Verifying L2RIB
        try:
            #S1_Leaf_Mac_BH_route
            if verify_L2rib_mac_ip_output(node3_s1_bgw_1,str(P3_dict['vlan_id']),str(P3_dict['mac'])):
                log.info('Mac BH route is proper in L2RIB on S1_Leaf')
            else:
                log.debug('Mac BH route is improper in L2RIB on  S1_Leaf')
                self.failed('Mac BH route is improper in L2RIB on  S1_Leaf')

            #S2_BGW1_Mac_BH_route
            if verify_L2rib_mac_ip_output(node7_s2_bgw_1,str(P3_dict['vlan_id']),str(P3_dict['mac'])):
                log.info('Mac BH route is proper in L2RIB on S2_BGW1')
            else:
                log.debug('Mac BH route is improper in L2RIB on  S2_BGW1')
                self.errored('Mac BH route is improper in L2RIB on  S2_BGW1')
        
        except Exception as error:
            log.debug("Unable to verify BH mac route in L2RIB - Encountered Exception " + str(error))
            self.errored('Exception occurred while verifying BH mac route in L2RIB')
        
        #Verifying BGP
        try:
            #S2_BGW1_Mac_BH_route
            if verify_BH_in_Remote_BGP(node7_s2_bgw_1,str(P3_dict['mac'])):
                log.info('Mac BH route is proper in BGP on S2_BGW1')
            else:
                log.debug('Mac BH route is improper in BGP on  S2_BGW1')
                self.errored('Mac BH route is improper in BGP on  S2_BGW1')

            #Access_Mac_BH_route
            if verify_BH_in_Remote_BGP(node3_s1_bgw_1,str(P3_dict['mac'])):
                log.info('Mac BH route is proper in BGP on Access')
            else:
                log.debug('Mac BH route is improper in BGP on  Access')
                self.errored('Mac BH route is improper in BGP on  Access')
        
        except Exception as error:
            log.debug("Unable to verify BH mac route in BGP - Encountered Exception " + str(error))
            self.errored('Exception occurred while verifying BH mac route in BGP')
    
    @aetest.test
    def Verify_Ipv6_icmp_neighbor(self,testbed):
        node3_s1_bgw_1 = testbed.devices['node3_s1_bgw_1']
        node7_s2_bgw_1 = testbed.devices['node7_s2_bgw_1']
        P3_dict = AcceSW_TGEN_data
        
        try:
            ###S1_BGW1_MAC_BH_ROUTE
            if Verify_ipv6_local_neighbor(node3_s1_bgw_1,str(P3_dict['mac']),str(P3_dict['vlan_id'])):
                log.info('Mac BH route is proper in ICMP neighbor on  S1_BGw1')
            else:
                log.info('Mac BH route is improper in ICMP neighbor on  S1_BGw1')
                self.failed('Mac BH route is improper in ICMP neighbor on  S1_BGw1')

            if verify_icmp_static_remote_neighbor(node7_s2_bgw_1,str(P3_dict['mac'])):
                log.info('Mac BH route is proper in ICMP neighbor on  S1_BGw1')
            else:
                log.info('Mac BH route is improper in ICMP neighbor on  S1_BGw1')
                self.failed('Mac BH route is improper in ICMP neighbor on  S1_BGw1')
        
        except Exception as error:
            log.debug("Unable to verify BH mac route in ICMP neighbor - Encountered Exception " + str(error))
            self.errored('Exception occurred while verifying BH mac route in ICMP neighbor')  

    @aetest.test
    def UnConfig_Mac_BH_Static_ND_on_VPC(self,testscript,testbed):
        node3_s1_bgw_1 = testbed.devices['node3_s1_bgw_1']
        node4_s1_bgw_2 = testbed.devices['node4_s1_bgw_2']
        P3_dict = AcceSW_TGEN_data
        mac= str(P3_dict['mac'])
        vlan= str(P3_dict['vlan_id'])
        ipv6=str(P3_dict['v6_addr'])
        octet = 2
        no_int= int(P3_dict['no_of_ints'])
        
        for i in range (0,no_int):
            ###LEAF_3_MAC_BH_ROUTE
            testbed.devices['node3_s1_bgw_1'].configure('''
                no mac address-table static ''' + str(mac) + ''' vlan '''+ str(vlan) + ''' drop

                interface vlan ''' + str(vlan) + '''
                    no ipv6 neighbor ''' + str(ipv6) + ''' ''' + str(mac) + '''
            ''')
        
            testbed.devices['node4_s1_bgw_2'].configure('''
                no mac address-table static ''' + str(mac) + ''' vlan '''+ str(vlan) + ''' drop

                interface vlan ''' + str(vlan) + '''
                    no ipv6 neighbor ''' + str(ipv6) + ''' ''' + str(mac) + '''
            ''')
            lasthex=incr_mac(mac)
            mac=mac[0:10]+lasthex
            vlan= int(vlan)+int(P3_dict['vlan_id_step'])
            ipv6=incr_ipv6(ipv6,octet) 

    # @aetest.test
    # def APPLY_TRAFFIC(self):
    #     """ IXIA_CONFIGURATION subsection: Verify IXIA Traffic """

    #     # Apply IXIA Traffic
    #     if ixLib.apply_traffic() == 1:
    #         log.info("Applying IXIA TI Passed")
    #     else:
    #         self.errored("Applying IXIA TI failed")

    @aetest.test
    def VERIFY_IXIA_TRAFFIC_after_rmBH_Route(self, testscript):
        """ IXIA_CONFIGURATION subsection: Verify IXIA Traffic """

        # Do not perform configurations if skip_tgen_config flag is set
        #if not testscript.parameters['script_flags']['skip_tgen_config']:

        time.sleep(20)

        if ixLib.verify_traffic(10) == 1:
            log.debug("Traffic Verification Passed.") 
            #ForkedPdb().set_trace() 
        else:
            log.info("Traffic Verification Failed.")
            self.failed("Traffic Verification failed")
            #ForkedPdb().set_trace() 
        # else:
        #     self.passed(reason="Skipped TGEN Configurations as per request")
    
    @aetest.cleanup
    def cleanup(self,testscript,testbed):
        """Unconfigure qos policies"""
        node3_s1_bgw_1 = testbed.devices['node3_s1_bgw_1']
        node5_s1_leaf_1 = testbed.devices['node5_s1_leaf_1']
        node10_s1_AccessSW =testbed.devices['node10_s1_AccessSW']
        node7_s2_bgw_1 =testbed.devices['node7_s2_bgw_1']
        P3_dict = AcceSW_TGEN_data
        forwardingSysDict = FWD_SYS_dict
        try:
            # Stop Traffic from ixia
            log.info("--- Stopping Traffic ---- \n")
            log.info("Stopping Traffic")
            traffic_run_status = ixLib.stop_traffic()
            
            if traffic_run_status is not 1:
               log.info("Failed: To Stop traffic")
               return 0
            else:
                log.info("\nTraffic Stopped successfully\n")
            time.sleep(10)
            ####Remove traffic item configured
            UCAST_v6_dict_1 = {
                            'mode'        : 'remove',
                            'stream_id'   : stream_id,
                      }
            if (ixLib.delete_traffic_item(UCAST_v6_dict_1))==0:
                log.debug("Traffic Remove failed")
                self.failed("Traffic Remove failed", goto=['next_tc'])
            else:
                log.info("Traffic Remove Passed")
            UCAST_v6_dict_2 = {
                            'mode'        : 'remove',
                            'stream_id'   : stream_id_1,
                      }
            if (ixLib.delete_traffic_item(UCAST_v6_dict_2))==0:
                log.debug("Traffic Remove failed")
                self.failed("Traffic Remove failed", goto=['next_tc'])
            else:
                log.info("Traffic Remove Passed")
            UCAST_v6_dict_3 = {
                            'mode'        : 'remove',
                            'stream_id'   : stream_id_2,
                      }
            if (ixLib.delete_traffic_item(UCAST_v6_dict_3))==0:
                log.debug("Traffic Remove failed")
                self.failed("Traffic Remove failed", goto=['next_tc'])
            else:
                log.info("Traffic Remove Passed")
            ###LEAF_1_MAC_BH_ROUTE
        except Exception as error:
            log.debug("Unable to do cleanup " + str(error))
            self.errored('Exception occurred during cleanup', goto=['next_tc']) 

class Mac_BH_route_static_arp_on_remote_vtep_with_L3_traffic_ipv6header(nxtest.Testcase):
    #"TC_0050_Mac_BH_route_static_arp_on_remote_vtep_with_L3_traffic_ipv6header"
    stream_id=''
    @aetest.test
    def CONFIGURE_UCAST_L3_IXIA_TRAFFIC_H2_to_H1(self, testscript):
        """ IXIA_CONFIGURATION subsection: Configure MCAST Traffic Item """

        # Do not perform configurations if skip_tgen_config flag is set
        #if not testscript.parameters['script_flags']['skip_tgen_config']:

        IX_TP1 = testscript.parameters['IX_TP1']
        IX_TP2 = testscript.parameters['IX_TP2']
        IX_TP3 = testscript.parameters['IX_TP3']
        IX_TP4 = testscript.parameters['IX_TP4']
        P1_dict = S1_BGW1_TGEN_data
        P2_dict = S1_Leaf_TGEN_data
        P3_dict = AcceSW_TGEN_data
        P4_dict = S2_Leaf_TGEN_data


        UCAST_v6_dict_1 = {   'src_hndl'  : testscript.parameters['port_handle_1'],
                            'dst_hndl'  : testscript.parameters['port_handle_3'],
                            'circuit'   : 'raw',
                            'TI_name'   : "UCAST_v6",
                            'rate_pps'  : "9000",
                            'bi_dir'    : 0,
                            'frame_size': '128',
                            'src_mac'   : P1_dict['mac'],
                            'dst_mac'   : '0000.000a.aaaa',
                            'srcmac_step': '00:00:00:00:00:00',
                            'dstmac_step': '00:00:00:00:00:00',
                            'srcmac_count': '1',
                            'dstmac_count': '1',
                            'vlan_id'    : P1_dict['vlan_id'],
                            'vlanid_step': '0',
                            'vlanid_count': '1',
                            'vlan_user_priority': P1_dict['vlan_user_priority'],
                            'ipv6_src_addrs' : P1_dict['v6_addr'],
                            'ipv6_dst_addrs' : P3_dict['L3_v6_dst_addr'],
                            'ipv6_src_step' : '0:0:0:0::0',
                            'ipv6_dst_step' : '0:0:0:0::0',
                            #'ip_dscp'     : P1_dict['ip_dscp'],
#                                'ip_step'    : P1_dict['v4_addr_step'],
                        }
        
        # UCAST_v6_dict = {   'src_hndl'  : IX_TP1['ipv6_handle'],
        #                        'dst_hndl'  : IX_TP3['ipv6_handle'],
        #                        'circuit'   : 'ipv6',
        #                        'TI_name'   : "UCAST_V6",
        #                        'rate_pps'  : "9000",
        #                        'bi_dir'    : 1,
        #                        'frame_size': '128',
        #                  }


        

        UCAST_v6_TI = ixLib.configure_ixia_l3_traffic_item_ipv6(UCAST_v6_dict_1)
            
        if UCAST_v6_TI == 0:
            log.debug("Configuring UCast TI failed")
            self.errored("Configuring UCast TI failed", goto=['cleanup'])
        else:
            global stream_id
            stream_id = UCAST_v6_TI

        # else:
        #     self.passed(reason="Skipped TGEN Configurations as per request")
    
    stream_id_1=''
    @aetest.test
    def CONFIGURE_UCAST_L3_IXIA_TRAFFIC_H3_to_H1(self, testscript):
        """ IXIA_CONFIGURATION subsection: Configure MCAST Traffic Item """

        # Do not perform configurations if skip_tgen_config flag is set
        #if not testscript.parameters['script_flags']['skip_tgen_config']:

        IX_TP1 = testscript.parameters['IX_TP1']
        IX_TP2 = testscript.parameters['IX_TP2']
        IX_TP3 = testscript.parameters['IX_TP3']
        IX_TP4 = testscript.parameters['IX_TP4']
        P1_dict = S1_BGW1_TGEN_data
        P2_dict = S1_Leaf_TGEN_data
        P3_dict = AcceSW_TGEN_data
        P4_dict = S2_Leaf_TGEN_data


        UCAST_v6_dict_2 = {   'src_hndl'  : testscript.parameters['port_handle_2'],
                            'dst_hndl'  : testscript.parameters['port_handle_3'],
                            'circuit'   : 'raw',
                            'TI_name'   : "UCAST_v6",
                            'rate_pps'  : "9000",
                            'bi_dir'    : 0,
                            'frame_size': '128',
                            'src_mac'   : P2_dict['mac'],
                            'dst_mac'   : '0000.000a.aaaa',
                            'srcmac_step': '00:00:00:00:00:00',
                            'dstmac_step': '00:00:00:00:00:00',
                            'srcmac_count': '1',
                            'dstmac_count': '1',
                            'vlan_id'    : P2_dict['vlan_id'],
                            'vlanid_step': '0',
                            'vlanid_count': '1',
                            'vlan_user_priority': P2_dict['vlan_user_priority'],
                            'ipv6_src_addrs' : P2_dict['v6_addr'],
                            'ipv6_dst_addrs' : P3_dict['L3_v6_dst_addr'],
                            'ipv6_src_step' :  '0:0:0:0::0',
                            'ipv6_dst_step' :  '0:0:0:0::0',
                            #'ip_dscp'     : P2_dict['ip_dscp'],
#                                'ip_step'    : P1_dict['v4_addr_step'],
                        }
        
        # UCAST_v6_dict = {   'src_hndl'  : IX_TP2['ipv6_handle'],
        #                        'dst_hndl'  : IX_TP3['ipv6_handle'],
        #                        'circuit'   : 'ipv6',
        #                        'TI_name'   : "UCAST_V6",
        #                        'rate_pps'  : "9000",
        #                        'bi_dir'    : 1
        #                  }


        UCAST_v6_TI_1 = ixLib.configure_ixia_l3_traffic_item_ipv6(UCAST_v6_dict_2)
            
        if UCAST_v6_TI_1 == 0:
            log.debug("Configuring UCast TI failed")
            self.errored("Configuring UCast TI failed", goto=['cleanup'])
        else:
            global stream_id_1
            stream_id_1 = UCAST_v6_TI_1

        # else:
        #     self.passed(reason="Skipped TGEN Configurations as per request")
    
    stream_id_2=''
    @aetest.test
    def CONFIGURE_UCAST_L3_IXIA_TRAFFIC_H4_to_H1(self, testscript):
        """ IXIA_CONFIGURATION subsection: Configure MCAST Traffic Item """

        # Do not perform configurations if skip_tgen_config flag is set
        #if not testscript.parameters['script_flags']['skip_tgen_config']:

        IX_TP1 = testscript.parameters['IX_TP1']
        IX_TP2 = testscript.parameters['IX_TP2']
        IX_TP3 = testscript.parameters['IX_TP3']
        IX_TP4 = testscript.parameters['IX_TP4']
        P1_dict = S1_BGW1_TGEN_data
        P2_dict = S1_Leaf_TGEN_data
        P3_dict = AcceSW_TGEN_data
        P4_dict = S2_Leaf_TGEN_data


        UCAST_v6_dict_3 = {   'src_hndl'  : testscript.parameters['port_handle_4'],
                            'dst_hndl'  : testscript.parameters['port_handle_3'],
                            'circuit'   : 'raw',
                            'TI_name'   : "UCAST_v6",
                            'rate_pps'  : "9000",
                            'bi_dir'    : 1,
                            'frame_size': '128',
                            'src_mac'   : P4_dict['mac'],
                            'dst_mac'   : '0000.000a.aaaa',
                            'srcmac_step': '00:00:00:00:00:00',
                            'dstmac_step': '00:00:00:00:00:00',
                            'srcmac_count': '1',
                            'dstmac_count': '1',
                            'vlan_id'    : P4_dict['vlan_id'],
                            'vlanid_step': '0',
                            'vlanid_count': '1',
                            'vlan_user_priority': P4_dict['vlan_user_priority'],
                            'ipv6_src_addrs' : P4_dict['v6_addr'],
                            'ipv6_dst_addrs' : P3_dict['L3_v6_dst_addr'],
                            'ipv6_src_step' : '0:0:0:0::0',
                            'ipv6_dst_step' : '0:0:0:0::0',
                            #'ip_dscp'     : P4_dict['ip_dscp'],
#                                'ip_step'    : P1_dict['v4_addr_step'],
                        }

        # UCAST_v6_dict = {   'src_hndl'  : IX_TP4['ipv6_handle'],
        #                        'dst_hndl'  : IX_TP3['ipv6_handle'],
        #                        'circuit'   : 'ipv6',
        #                        'TI_name'   : "UCAST_V6",
        #                        'rate_pps'  : "9000",
        #                        'bi_dir'    : 1
        #                  }

        UCAST_v6_TI_2 = ixLib.configure_ixia_l3_traffic_item_ipv6(UCAST_v6_dict_3)
            
        if UCAST_v6_TI_2 == 0:
            log.debug("Configuring UCast TI failed")
            self.errored("Configuring UCast TI failed", goto=['cleanup'])
        else:
            global stream_id_2
            stream_id_2 = UCAST_v6_TI_2

        # else:
        #     self.passed(reason="Skipped TGEN Configurations as per request")

    
    @aetest.test
    def APPLY_TRAFFIC(self):
        """ IXIA_CONFIGURATION subsection: Verify IXIA Traffic """

        # Apply IXIA Traffic
        if ixLib.apply_traffic() == 1:
            log.info("Applying IXIA TI Passed")
        else:
            self.errored("Applying IXIA TI failed")

    @aetest.test
    def VERIFY_IXIA_TRAFFIC_Without_BH_Route(self, testscript):
        """ IXIA_CONFIGURATION subsection: Verify IXIA Traffic """

        # Do not perform configurations if skip_tgen_config flag is set
        #if not testscript.parameters['script_flags']['skip_tgen_config']:

        time.sleep(20)

        if ixLib.verify_traffic(1) == 1:
            log.debug("Traffic Verification Passed.Expecting traffic loss here.") 
        else:
            log.info("Traffic Verification Failed. Expecting traffic loss here.")
            self.failed("Traffic Verification failed")
        # else:
        #     self.passed(reason="Skipped TGEN Configurations as per request")

    @aetest.test
    def Config_Mac_BH_Static_ND_on_VPC(self,testscript,testbed):
        node7_s2_bgw_1 = testbed.devices['node7_s2_bgw_1']
        P3_dict = AcceSW_TGEN_data
        mac= str(P3_dict['mac'])
        vlan= str(P3_dict['vlan_id'])
        ipv6=str(P3_dict['v6_addr'])
        octet = 2
        no_int= int(P3_dict['no_of_ints'])
        
        for i in range (0,no_int):
            ###LEAF_3_MAC_BH_ROUTE
            testbed.devices['node7_s2_bgw_1'].configure('''
                mac address-table static ''' + str(mac) + ''' vlan '''+ str(vlan) + ''' drop

                interface vlan ''' + str(vlan) + '''
                  ipv6 neighbor ''' + str(ipv6) + ''' ''' + str(mac) + '''
            ''')
            lasthex=incr_mac(mac)
            mac=mac[0:10]+lasthex
            vlan= int(vlan)+int(P3_dict['vlan_id_step'])
            ipv6=incr_ipv6(ipv6,octet) 

    @aetest.test
    def APPLY_TRAFFIC(self):
        """ IXIA_CONFIGURATION subsection: Verify IXIA Traffic """

        # Apply IXIA Traffic
        if ixLib.apply_traffic() == 1:
            log.info("Applying IXIA TI Passed")
        else:
            self.errored("Applying IXIA TI failed")

    @aetest.test
    def VERIFY_IXIA_TRAFFIC_With_BH_Route(self, testscript):
        """ IXIA_CONFIGURATION subsection: Verify IXIA Traffic """

        # Do not perform configurations if skip_tgen_config flag is set
        #if not testscript.parameters['script_flags']['skip_tgen_config']:

        time.sleep(20)

        if ixLib.verify_traffic(99) == 0:
            log.debug("Traffic Verification Passed.Expecting traffic loss here.") 
        else:
            log.info("Traffic Verification Failed. Expecting traffic loss here.")
            self.failed("Traffic Verification failed")
        # else:
        #     self.passed(reason="Skipped TGEN Configurations as per request")

    @aetest.test
    def Verify_Traffic_Drop_on_Remote_Vtep(self,testscript,testbed):
        node5_s1_leaf_1 = testbed.devices['node5_s1_leaf_1']
        node3_s1_bgw_1 = testbed.devices['node3_s1_bgw_1']
        node9_s2_leaf_1 = testbed.devices['node9_s2_leaf_1']
        P3_dict = AcceSW_TGEN_data
        uplink_PO=S1_Leaf_dict['S1_Leaf_UPLINK_PO']['po_id']
        if verify_traffic_drop(node5_s1_leaf_1,uplink_PO):
            log.info('Traffic correctly dropped on  S1_Leaf')
        else:
            log.info('Traffic NOT dropped on  S1_Leaf')
            self.failed('Traffic NOT dropped on  S1_Leaf')
        
        uplink_PO=S2_Leaf_dict['S2_Leaf_UPLINK_PO']['po_id']
        if verify_traffic_drop(node9_s2_leaf_1,uplink_PO):
            log.info('Traffic correctly dropped on  S2_Leaf')
        else:
            log.info('Traffic NOT dropped on  S2_Leaf')
            self.failed('Traffic NOT dropped on  S2_Leaf')

        uplink_PO=S1_BGW1_dict['S1_BGW1_UPLINK_PO']['po_id']
        if verify_traffic_drop(node3_s1_bgw_1,uplink_PO):
            log.info('Traffic correctly dropped on  S1_BGW1')
        else:
            log.info('Traffic NOT dropped on  S1_BGW1')
            self.failed('Traffic NOT dropped on  S1_BGW1')
    
    
    @aetest.test
    def Verify_BH_states_in_HMM(self, testscript,testbed):
        node3_s1_bgw_1 =testbed.devices['node3_s1_bgw_1']
        node7_s2_bgw_1 = testbed.devices['node7_s2_bgw_1']
        P3_dict = AcceSW_TGEN_data
        try:
            if verify_Ipv6_BH_in_HMM(node7_s2_bgw_1,str(P3_dict['v6_addr'])):
                log.info('Mac BH route is proper in HMM on  S1_BGW1')
            else:
                log.info('Mac BH route is improper in HMM on  S1_BGW1')
                self.failed('Mac BH route is improper in HMM on  S1_BGW1')
        
         
        except Exception as error:
            log.debug("Unable to configure static BH mac route on Remote Vtep- Encountered Exception " + str(error))
            self.errored('Exception occurred while configuring static BH mac route on Remote Vtep')

    @aetest.test
    def Verify_BH_states_in_AM(self, testscript,testbed):
        node3_s1_bgw_1 = testbed.devices['node3_s1_bgw_1']
        node7_s2_bgw_1 = testbed.devices['node7_s2_bgw_1']
        P3_dict = AcceSW_TGEN_data

        try:        
            if verify_Ipv6_BH_in_AM(node7_s2_bgw_1,str(P3_dict['mac']),str(P3_dict['vlan_id']),str(P3_dict['v6_addr'])):
                log.info('Mac BH route is proper in AM on  S1_BGW1')
            else:
                log.info('Mac BH route is improper in AM on  S1_BGW1')
                self.failed('Mac BH route is improper in AM on  S1_BGW1')
        
        except Exception as error:
            log.debug("Unable to configure static BH mac route on Remote Vtep- Encountered Exception " + str(error))
            self.errored('Exception occurred while configuring static BH mac route on Remote Vtep')
        
    @aetest.test
    def Verify_Mac_BH_Route_on_L2FM_BGP_L2RIB(self,testscript,testbed):
        node3_s1_bgw_1 =testbed.devices['node3_s1_bgw_1']
        node7_s2_bgw_1 = testbed.devices['node7_s2_bgw_1']
        P3_dict = AcceSW_TGEN_data      
        # Verifying L2FM

        try:
            ###S1_BGW1_MAC_BH_ROUTE
            if verify_BH_route_in_L2FM(node3_s1_bgw_1,str(P3_dict['vlan_id']),str(P3_dict['mac'])):
                log.info('Mac BH route is proper in L2FM on  S1_BGw1')
            else:
                log.info('Mac BH route is improper in L2FM on  S1_BGw1')
                self.failed('Mac BH route is improper in L2FM on  S1_BGw1')

            ###S2_BGW1_MAC_BH_ROUTE Remote Vtep
            if verify_BH_route_in_L2FM(node7_s2_bgw_1,str(P3_dict['vlan_id']),str(P3_dict['mac'])):
                log.info('Mac BH route is proper in L2FM on  S2_BGw1')
            else:
                log.info('Mac BH route is improper in L2FM on  S2_BGw1')
                self.failed('Mac BH route is improper in L2FM on  S2_BGw1')

        except Exception as error:
            log.debug("Unable to verify BH mac route in L2FM - Encountered Exception " + str(error))
            self.errored('Exception occurred while verifying BH mac route in L2FM')        

        #Verifying L2RIB
        try:
            #S1_Leaf_Mac_BH_route
            if verify_L2rib_mac_ip_output(node3_s1_bgw_1,str(P3_dict['vlan_id']),str(P3_dict['mac'])):
                log.info('Mac BH route is proper in L2RIB on S1_Leaf')
            else:
                log.debug('Mac BH route is improper in L2RIB on  S1_Leaf')
                self.failed('Mac BH route is improper in L2RIB on  S1_Leaf')

            #S2_BGW1_Mac_BH_route
            if verify_L2rib_mac_ip_output(node7_s2_bgw_1,str(P3_dict['vlan_id']),str(P3_dict['mac'])):
                log.info('Mac BH route is proper in L2RIB on S2_BGW1')
            else:
                log.debug('Mac BH route is improper in L2RIB on  S2_BGW1')
                self.errored('Mac BH route is improper in L2RIB on  S2_BGW1')
        
        except Exception as error:
            log.debug("Unable to verify BH mac route in L2RIB - Encountered Exception " + str(error))
            self.errored('Exception occurred while verifying BH mac route in L2RIB')
        
        #Verifying BGP
        try:
            #S2_BGW1_Mac_BH_route
            if verify_BH_in_Remote_BGP(node7_s2_bgw_1,str(P3_dict['mac'])):
                log.info('Mac BH route is proper in BGP on S2_BGW1')
            else:
                log.debug('Mac BH route is improper in BGP on  S2_BGW1')
                self.errored('Mac BH route is improper in BGP on  S2_BGW1')

            #Access_Mac_BH_route
            if verify_BH_in_Remote_BGP(node3_s1_bgw_1,str(P3_dict['mac'])):
                log.info('Mac BH route is proper in BGP on Access')
            else:
                log.debug('Mac BH route is improper in BGP on  Access')
                self.errored('Mac BH route is improper in BGP on  Access')
        
        except Exception as error:
            log.debug("Unable to verify BH mac route in BGP - Encountered Exception " + str(error))
            self.errored('Exception occurred while verifying BH mac route in BGP')
        
    @aetest.test
    def Verify_Ipv6_icmp_neighbor(self,testbed):
        node3_s1_bgw_1 = testbed.devices['node3_s1_bgw_1']
        node7_s2_bgw_1 = testbed.devices['node7_s2_bgw_1']
        P3_dict = AcceSW_TGEN_data
        
        try:
            ###S1_BGW1_MAC_BH_ROUTE
            if Verify_ipv6_local_neighbor(node7_s2_bgw_1,str(P3_dict['mac']),str(P3_dict['vlan_id'])):
                log.info('Mac BH route is proper in ICMP neighbor on  S1_BGw1')
            else:
                log.info('Mac BH route is improper in ICMP neighbor on  S1_BGw1')
                self.failed('Mac BH route is improper in ICMP neighbor on  S1_BGw1')

            if verify_icmp_static_remote_neighbor(node3_s1_bgw_1,str(P3_dict['mac'])):
                log.info('Mac BH route is proper in ICMP neighbor on  S1_BGw1')
            else:
                log.info('Mac BH route is improper in ICMP neighbor on  S1_BGw1')
                self.failed('Mac BH route is improper in ICMP neighbor on  S1_BGw1')
        
        except Exception as error:
            log.debug("Unable to verify BH mac route in ICMP neighbor - Encountered Exception " + str(error))
            self.errored('Exception occurred while verifying BH mac route in ICMP neighbor')  
    
    @aetest.test
    def UnConfig_Mac_BH_Static_ND_on_VPC(self,testscript,testbed):
        node7_s2_bgw_1 = testbed.devices['node7_s2_bgw_1']
        P3_dict = AcceSW_TGEN_data
        mac= str(P3_dict['mac'])
        vlan= str(P3_dict['vlan_id'])
        ipv6=str(P3_dict['v6_addr'])
        octet = 2
        no_int= int(P3_dict['no_of_ints'])
        
        for i in range (0,no_int):
            ###LEAF_3_MAC_BH_ROUTE
            testbed.devices['node7_s2_bgw_1'].configure('''
                no mac address-table static ''' + str(mac) + ''' vlan '''+ str(vlan) + ''' drop

                interface vlan ''' + str(vlan) + '''
                  no ipv6 neighbor ''' + str(ipv6) + ''' ''' + str(mac) + '''
            ''')
            lasthex=incr_mac(mac)
            mac=mac[0:10]+lasthex
            vlan= int(vlan)+int(P3_dict['vlan_id_step'])
            ipv6=incr_ipv6(ipv6,octet) 

    @aetest.test
    def APPLY_TRAFFIC(self):
        """ IXIA_CONFIGURATION subsection: Verify IXIA Traffic """

        # Apply IXIA Traffic
        if ixLib.apply_traffic() == 1:
            log.info("Applying IXIA TI Passed")
        else:
            self.errored("Applying IXIA TI failed")

    @aetest.test
    def VERIFY_IXIA_TRAFFIC_after_rmBH_Route(self, testscript):
        """ IXIA_CONFIGURATION subsection: Verify IXIA Traffic """

        # Do not perform configurations if skip_tgen_config flag is set
        #if not testscript.parameters['script_flags']['skip_tgen_config']:

        time.sleep(20)

        if ixLib.verify_traffic(10) == 1:
            log.debug("Traffic Verification Passed.Expecting traffic loss here.") 
        else:
            log.info("Traffic Verification Failed. Expecting traffic loss here.")
            self.failed("Traffic Verification failed")
        # else:
        #     self.passed(reason="Skipped TGEN Configurations as per request")
    
    @aetest.cleanup
    def cleanup(self,testscript,testbed):
        """Unconfigure qos policies"""
        node3_s1_bgw_1 = testbed.devices['node3_s1_bgw_1']
        node5_s1_leaf_1 = testbed.devices['node5_s1_leaf_1']
        node10_s1_AccessSW =testbed.devices['node10_s1_AccessSW']
        node7_s2_bgw_1 =testbed.devices['node7_s2_bgw_1']
        P3_dict = AcceSW_TGEN_data
        forwardingSysDict = FWD_SYS_dict
        try:
            # Stop Traffic from ixia
            log.info("--- Stopping Traffic ---- \n")
            log.info("Stopping Traffic")
            traffic_run_status = ixLib.stop_traffic()
            
            if traffic_run_status is not 1:
               log.info("Failed: To Stop traffic")
               return 0
            else:
                log.info("\nTraffic Stopped successfully\n")
            time.sleep(10)
            ####Remove traffic item configured
            UCAST_v6_dict_1= {
                            'mode'        : 'remove',
                            'stream_id'   : stream_id,
                      }
            if (ixLib.delete_traffic_item(UCAST_v6_dict_1))==0:
                log.debug("Traffic Remove failed")
                self.failed("Traffic Remove failed", goto=['next_tc'])
            else:
                log.info("Traffic Remove Passed")
            UCAST_v6_dict_2= {
                            'mode'        : 'remove',
                            'stream_id'   : stream_id_1,
                      }
            if (ixLib.delete_traffic_item(UCAST_v6_dict_2))==0:
                log.debug("Traffic Remove failed")
                self.failed("Traffic Remove failed", goto=['next_tc'])
            else:
                log.info("Traffic Remove Passed")
            UCAST_v6_dict_3 = {
                            'mode'        : 'remove',
                            'stream_id'   : stream_id_2,
                      }
            if (ixLib.delete_traffic_item(UCAST_v6_dict_3))==0:
                log.debug("Traffic Remove failed")
                self.failed("Traffic Remove failed", goto=['next_tc'])
            else:
                log.info("Traffic Remove Passed")
            
            ###LEAF_1_MAC_BH_ROUTE
        except Exception as error:
            log.debug("Unable to do cleanup " + str(error))
            self.errored('Exception occurred during cleanup', goto=['next_tc']) 

class Mac_BH_route_on_vpc_vtep_Start_L3_traffic_with_ipv6_header(nxtest.Testcase):
    #"TC_0052_Mac_BH_route_on_vpc_vtep_Start_L3_traffic_with_ipv6_header"
    stream_id=''
    @aetest.test
    def CONFIGURE_UCAST_L3_IXIA_TRAFFIC_H2_to_H1(self, testscript):
        """ IXIA_CONFIGURATION subsection: Configure MCAST Traffic Item """

        # Do not perform configurations if skip_tgen_config flag is set
        #if not testscript.parameters['script_flags']['skip_tgen_config']:

        IX_TP1 = testscript.parameters['IX_TP1']
        IX_TP2 = testscript.parameters['IX_TP2']
        IX_TP3 = testscript.parameters['IX_TP3']
        IX_TP4 = testscript.parameters['IX_TP4']
        P1_dict = S1_BGW1_TGEN_data
        P2_dict = S1_Leaf_TGEN_data
        P3_dict = AcceSW_TGEN_data
        P4_dict = S2_Leaf_TGEN_data


        UCAST_v6_dict_1 = {   'src_hndl'  : testscript.parameters['port_handle_1'],
                            'dst_hndl'  : testscript.parameters['port_handle_3'],
                            'circuit'   : 'raw',
                            'TI_name'   : "UCAST_v6",
                            'rate_pps'  : "9000",
                            'bi_dir'    : 0,
                            'frame_size': '128',
                            'src_mac'   : P1_dict['mac'],
                            'dst_mac'   : '0000.000a.aaaa',
                            'srcmac_step': '00:00:00:00:00:00',
                            'dstmac_step': '00:00:00:00:00:00',
                            'srcmac_count': '1',
                            'dstmac_count': '1',
                            'vlan_id'    : P1_dict['vlan_id'],
                            'vlanid_step': '0',
                            'vlanid_count': '1',
                            'vlan_user_priority': P1_dict['vlan_user_priority'],
                            'ipv6_src_addrs' : P1_dict['v6_addr'],
                            'ipv6_dst_addrs' : P3_dict['L3_v6_dst_addr'],
                            'ipv6_src_step' : '0:0:0:0::0',
                            'ipv6_dst_step' : '0:0:0:0::0',
                            #'ip_dscp'     : P1_dict['ip_dscp'],
#                                'ip_step'    : P1_dict['v4_addr_step'],
                        }
        
        # UCAST_v6_dict = {   'src_hndl'  : IX_TP1['ipv6_handle'],
        #                        'dst_hndl'  : IX_TP3['ipv6_handle'],
        #                        'circuit'   : 'ipv6',
        #                        'TI_name'   : "UCAST_V6",
        #                        'rate_pps'  : "9000",
        #                        'bi_dir'    : 1,
        #                        'frame_size': '128',
        #                  }


        

        UCAST_v6_TI = ixLib.configure_ixia_l3_traffic_item_ipv6(UCAST_v6_dict_1)
            
        if UCAST_v6_TI == 0:
            log.debug("Configuring UCast TI failed")
            self.errored("Configuring UCast TI failed", goto=['cleanup'])
        else:
            global stream_id
            stream_id = UCAST_v6_TI

        # else:
        #     self.passed(reason="Skipped TGEN Configurations as per request")
    
    stream_id_1=''
    @aetest.test
    def CONFIGURE_UCAST_L3_IXIA_TRAFFIC_H3_to_H1(self, testscript):
        """ IXIA_CONFIGURATION subsection: Configure MCAST Traffic Item """

        # Do not perform configurations if skip_tgen_config flag is set
        #if not testscript.parameters['script_flags']['skip_tgen_config']:

        IX_TP1 = testscript.parameters['IX_TP1']
        IX_TP2 = testscript.parameters['IX_TP2']
        IX_TP3 = testscript.parameters['IX_TP3']
        IX_TP4 = testscript.parameters['IX_TP4']
        P1_dict = S1_BGW1_TGEN_data
        P2_dict = S1_Leaf_TGEN_data
        P3_dict = AcceSW_TGEN_data
        P4_dict = S2_Leaf_TGEN_data


        UCAST_v6_dict_2 = {   'src_hndl'  : testscript.parameters['port_handle_2'],
                            'dst_hndl'  : testscript.parameters['port_handle_3'],
                            'circuit'   : 'raw',
                            'TI_name'   : "UCAST_v6",
                            'rate_pps'  : "9000",
                            'bi_dir'    : 0,
                            'frame_size': '128',
                            'src_mac'   : P2_dict['mac'],
                            'dst_mac'   : '0000.000a.aaaa',
                            'srcmac_step': '00:00:00:00:00:00',
                            'dstmac_step': '00:00:00:00:00:00',
                            'srcmac_count': '1',
                            'dstmac_count': '1',
                            'vlan_id'    : P2_dict['vlan_id'],
                            'vlanid_step': '0',
                            'vlanid_count': '1',
                            'vlan_user_priority': P2_dict['vlan_user_priority'],
                            'ipv6_src_addrs' : P2_dict['v6_addr'],
                            'ipv6_dst_addrs' : P3_dict['L3_v6_dst_addr'],
                            'ipv6_src_step' :  '0:0:0:0::0',
                            'ipv6_dst_step' :  '0:0:0:0::0',
                            #'ip_dscp'     : P2_dict['ip_dscp'],
#                                'ip_step'    : P1_dict['v4_addr_step'],
                        }
        
        # UCAST_v6_dict = {   'src_hndl'  : IX_TP2['ipv6_handle'],
        #                        'dst_hndl'  : IX_TP3['ipv6_handle'],
        #                        'circuit'   : 'ipv6',
        #                        'TI_name'   : "UCAST_V6",
        #                        'rate_pps'  : "9000",
        #                        'bi_dir'    : 1
        #                  }


        UCAST_v6_TI_1 = ixLib.configure_ixia_l3_traffic_item_ipv6(UCAST_v6_dict_2)
            
        if UCAST_v6_TI_1 == 0:
            log.debug("Configuring UCast TI failed")
            self.errored("Configuring UCast TI failed", goto=['cleanup'])
        else:
            global stream_id_1
            stream_id_1 = UCAST_v6_TI_1

        # else:
        #     self.passed(reason="Skipped TGEN Configurations as per request")
    
    stream_id_2=''
    @aetest.test
    def CONFIGURE_UCAST_L3_IXIA_TRAFFIC_H4_to_H1(self, testscript):
        """ IXIA_CONFIGURATION subsection: Configure MCAST Traffic Item """

        # Do not perform configurations if skip_tgen_config flag is set
        #if not testscript.parameters['script_flags']['skip_tgen_config']:

        IX_TP1 = testscript.parameters['IX_TP1']
        IX_TP2 = testscript.parameters['IX_TP2']
        IX_TP3 = testscript.parameters['IX_TP3']
        IX_TP4 = testscript.parameters['IX_TP4']
        P1_dict = S1_BGW1_TGEN_data
        P2_dict = S1_Leaf_TGEN_data
        P3_dict = AcceSW_TGEN_data
        P4_dict = S2_Leaf_TGEN_data


        UCAST_v6_dict_3 = {   'src_hndl'  : testscript.parameters['port_handle_4'],
                            'dst_hndl'  : testscript.parameters['port_handle_3'],
                            'circuit'   : 'raw',
                            'TI_name'   : "UCAST_v6",
                            'rate_pps'  : "9000",
                            'bi_dir'    : 1,
                            'frame_size': '128',
                            'src_mac'   : P4_dict['mac'],
                            'dst_mac'   : '0000.000a.aaaa',
                            'srcmac_step': '00:00:00:00:00:00',
                            'dstmac_step': '00:00:00:00:00:00',
                            'srcmac_count': '1',
                            'dstmac_count': '1',
                            'vlan_id'    : P4_dict['vlan_id'],
                            'vlanid_step': '0',
                            'vlanid_count': '1',
                            'vlan_user_priority': P4_dict['vlan_user_priority'],
                            'ipv6_src_addrs' : P4_dict['v6_addr'],
                            'ipv6_dst_addrs' : P3_dict['L3_v6_dst_addr'],
                            'ipv6_src_step' : '0:0:0:0::0',
                            'ipv6_dst_step' : '0:0:0:0::0',
                            #'ip_dscp'     : P4_dict['ip_dscp'],
#                                'ip_step'    : P1_dict['v4_addr_step'],
                        }

        # UCAST_v6_dict = {   'src_hndl'  : IX_TP4['ipv6_handle'],
        #                        'dst_hndl'  : IX_TP3['ipv6_handle'],
        #                        'circuit'   : 'ipv6',
        #                        'TI_name'   : "UCAST_V6",
        #                        'rate_pps'  : "9000",
        #                        'bi_dir'    : 1
        #                  }

        UCAST_v6_TI_2 = ixLib.configure_ixia_l3_traffic_item_ipv6(UCAST_v6_dict_3)
            
        if UCAST_v6_TI_2 == 0:
            log.debug("Configuring UCast TI failed")
            self.errored("Configuring UCast TI failed", goto=['cleanup'])
        else:
            global stream_id_2
            stream_id_2 = UCAST_v6_TI_2

        # else:
        #     self.passed(reason="Skipped TGEN Configurations as per request")
    
    @aetest.test
    def APPLY_TRAFFIC(self):
        """ IXIA_CONFIGURATION subsection: Verify IXIA Traffic """

        # Apply IXIA Traffic
        if ixLib.apply_traffic() == 1:
            log.info("Applying IXIA TI Passed")
        else:
            self.errored("Applying IXIA TI failed")

    @aetest.test
    def VERIFY_IXIA_TRAFFIC_Without_BH_Route(self, testscript):
        """ IXIA_CONFIGURATION subsection: Verify IXIA Traffic """

        # Do not perform configurations if skip_tgen_config flag is set
        #if not testscript.parameters['script_flags']['skip_tgen_config']:

        time.sleep(20)

        if ixLib.verify_traffic(1) == 1:
            log.debug("Traffic Verification Passed.Expecting traffic loss here.") 
        else:
            log.info("Traffic Verification Failed. Expecting traffic loss here.")
            self.failed("Traffic Verification failed")
        # else:
        #     self.passed(reason="Skipped TGEN Configurations as per request")
        
    @aetest.test
    def Configure_Mac_BH_Static_ND_on_VPC(self,testscript,testbed):
        node3_s1_bgw_1 = testbed.devices['node3_s1_bgw_1']
        node4_s1_bgw_2 = testbed.devices['node4_s1_bgw_2']
        P3_dict = AcceSW_TGEN_data
        mac= str(P3_dict['mac'])
        vlan= str(P3_dict['vlan_id'])
        ipv6=str(P3_dict['v6_addr'])
        octet = 2
        no_int= int(P3_dict['no_of_ints'])
        
        for i in range (0,no_int):
            ###LEAF_3_MAC_BH_ROUTE
            testbed.devices['node3_s1_bgw_1'].configure('''
                mac address-table static ''' + str(mac) + ''' vlan '''+ str(vlan) + ''' drop

                interface vlan ''' + str(vlan) + '''
                    ipv6 neighbor ''' + str(ipv6) + ''' ''' + str(mac) + '''
            ''')
        
            testbed.devices['node4_s1_bgw_2'].configure('''
                mac address-table static ''' + str(mac) + ''' vlan '''+ str(vlan) + ''' drop

                interface vlan ''' + str(vlan) + '''
                    ipv6 neighbor ''' + str(ipv6) + ''' ''' + str(mac) + '''
            ''')
            lasthex=incr_mac(mac)
            mac=mac[0:10]+lasthex
            vlan= int(vlan)+int(P3_dict['vlan_id_step'])
            ipv6=incr_ipv6(ipv6,octet) 

    @aetest.test
    def APPLY_TRAFFIC(self):
        """ IXIA_CONFIGURATION subsection: Verify IXIA Traffic """

        # Apply IXIA Traffic
        if ixLib.apply_traffic() == 1:
            log.info("Applying IXIA TI Passed")
        else:
            self.errored("Applying IXIA TI failed")

    @aetest.test
    def VERIFY_IXIA_TRAFFIC_With_BH_Route(self, testscript):
        """ IXIA_CONFIGURATION subsection: Verify IXIA Traffic """

        # Do not perform configurations if skip_tgen_config flag is set
        #if not testscript.parameters['script_flags']['skip_tgen_config']:

        time.sleep(20)

        if ixLib.verify_traffic(99) == 0:
            log.debug("Traffic Verification Passed.Expecting traffic loss here.") 
        else:
            log.info("Traffic Verification Failed. Expecting traffic loss here.")
            self.failed("Traffic Verification failed")
        # else:
        #     self.passed(reason="Skipped TGEN Configurations as per request")

    @aetest.test
    def Verify_Traffic_Drop_on_Remote_Vtep(self,testscript,testbed):
        node5_s1_leaf_1 = testbed.devices['node5_s1_leaf_1']
        node9_s2_leaf_1 = testbed.devices['node9_s2_leaf_1']
        node7_s2_bgw_1 =testbed.devices['node7_s2_bgw_1']
        P3_dict = AcceSW_TGEN_data
        uplink_PO=S1_Leaf_dict['S1_Leaf_UPLINK_PO']['po_id']
        if verify_traffic_drop(node5_s1_leaf_1,uplink_PO):
            log.info('Traffic correctly dropped on  S1_Leaf')
        else:
            log.info('Traffic NOT dropped on  S1_Leaf')
            self.failed('Traffic NOT dropped on  S1_Leaf')
        
        uplink_PO=S2_Leaf_dict['S2_Leaf_UPLINK_PO']['po_id']
        if verify_traffic_drop(node9_s2_leaf_1,uplink_PO):
            log.info('Traffic correctly dropped on  S2_Leaf')
        else:
            log.info('Traffic NOT dropped on  S2_Leaf')
            self.failed('Traffic NOT dropped on  S2_Leaf')

        uplink_PO=S2_BGW1_dict['S2_BGW1_UPLINK_PO']['po_id']
        if verify_traffic_drop(node7_s2_bgw_1,uplink_PO):
            log.info('Traffic correctly dropped on  S2_BGW1')
        else:
            log.info('Traffic NOT dropped on  S2_BGW1')
            self.failed('Traffic NOT dropped on  S2_BGW1')
          
    
    @aetest.test
    def verify_static_mac_states(self, testscript,testbed):
        node3_s1_bgw_1 = testbed.devices['node3_s1_bgw_1']
        node7_s2_bgw_1 = testbed.devices['node7_s2_bgw_1']
        P3_dict = AcceSW_TGEN_data
        if verify_static_mac(node3_s1_bgw_1,str(P3_dict['mac']),str(P3_dict['vlan_id'])):
            log.info('proper dynaic mac learnt on S1_BGw1')
        else:
            log.info('improper dynamic mac learnt on  S1_BGw1')
            self.failed('improper dynamic mac learnt on  S1_BGw1')

        if verify_static_mac(node7_s2_bgw_1,str(P3_dict['mac']),str(P3_dict['vlan_id'])):
            log.info('proper dynaic mac learnt on  S2_BGw1')
        else:
            log.info('improper dynamic mac learnt on S2_BGw1')
            self.failed('improper dynamic mac learnt on  S2_BGw1')  
    
    @aetest.test
    def Verify_BH_states_in_HMM(self, testscript,testbed):
        node3_s1_bgw_1 =testbed.devices['node3_s1_bgw_1']
        node7_s2_bgw_1 = testbed.devices['node7_s2_bgw_1']
        P3_dict = AcceSW_TGEN_data
        try:
            if verify_Ipv6_BH_in_HMM(node3_s1_bgw_1,str(P3_dict['v6_addr'])):
                log.info('Mac BH route is proper in HMM on  S1_BGW1')
            else:
                log.info('Mac BH route is improper in HMM on  S1_BGW1')
                self.failed('Mac BH route is improper in HMM on  S1_BGW1')
        
         
        except Exception as error:
            log.debug("Unable to configure static BH mac route on Remote Vtep- Encountered Exception " + str(error))
            self.errored('Exception occurred while configuring static BH mac route on Remote Vtep')

    @aetest.test
    def Verify_BH_states_in_AM(self, testscript,testbed):
        node3_s1_bgw_1 = testbed.devices['node3_s1_bgw_1']
        node7_s2_bgw_1 = testbed.devices['node7_s2_bgw_1']
        P3_dict = AcceSW_TGEN_data

        try:        
            if verify_Ipv6_BH_in_AM(node3_s1_bgw_1,str(P3_dict['mac']),str(P3_dict['vlan_id']),str(P3_dict['v6_addr'])):
                log.info('Mac BH route is proper in AM on  S1_BGW1')
            else:
                log.info('Mac BH route is improper in AM on  S1_BGW1')
                self.failed('Mac BH route is improper in AM on  S1_BGW1')
        
        except Exception as error:
            log.debug("Unable to configure static BH mac route on Remote Vtep- Encountered Exception " + str(error))
            self.errored('Exception occurred while configuring static BH mac route on Remote Vtep')
        
    @aetest.test
    def Verify_Mac_BH_Route_on_L2FM_BGP_L2RIB(self,testscript,testbed):
        node3_s1_bgw_1 =testbed.devices['node3_s1_bgw_1']
        node7_s2_bgw_1 = testbed.devices['node7_s2_bgw_1']
        P3_dict = AcceSW_TGEN_data      
        # Verifying L2FM

        try:
            ###S1_BGW1_MAC_BH_ROUTE
            if verify_BH_route_in_L2FM(node3_s1_bgw_1,str(P3_dict['vlan_id']),str(P3_dict['mac'])):
                log.info('Mac BH route is proper in L2FM on  S1_BGw1')
            else:
                log.info('Mac BH route is improper in L2FM on  S1_BGw1')
                self.failed('Mac BH route is improper in L2FM on  S1_BGw1')

            ###S2_BGW1_MAC_BH_ROUTE Remote Vtep
            if verify_BH_route_in_L2FM(node7_s2_bgw_1,str(P3_dict['vlan_id']),str(P3_dict['mac'])):
                log.info('Mac BH route is proper in L2FM on  S2_BGw1')
            else:
                log.info('Mac BH route is improper in L2FM on  S2_BGw1')
                self.failed('Mac BH route is improper in L2FM on  S2_BGw1')

        except Exception as error:
            log.debug("Unable to verify BH mac route in L2FM - Encountered Exception " + str(error))
            self.errored('Exception occurred while verifying BH mac route in L2FM')        

        #Verifying L2RIB
        try:
            #S1_Leaf_Mac_BH_route
            if verify_L2rib_mac_ip_output(node3_s1_bgw_1,str(P3_dict['vlan_id']),str(P3_dict['mac'])):
                log.info('Mac BH route is proper in L2RIB on S1_Leaf')
            else:
                log.debug('Mac BH route is improper in L2RIB on  S1_Leaf')
                self.failed('Mac BH route is improper in L2RIB on  S1_Leaf')

            #S2_BGW1_Mac_BH_route
            if verify_L2rib_mac_ip_output(node7_s2_bgw_1,str(P3_dict['vlan_id']),str(P3_dict['mac'])):
                log.info('Mac BH route is proper in L2RIB on S2_BGW1')
            else:
                log.debug('Mac BH route is improper in L2RIB on  S2_BGW1')
                self.errored('Mac BH route is improper in L2RIB on  S2_BGW1')
        
        except Exception as error:
            log.debug("Unable to verify BH mac route in L2RIB - Encountered Exception " + str(error))
            self.errored('Exception occurred while verifying BH mac route in L2RIB')
        
        #Verifying BGP
        try:
            #S2_BGW1_Mac_BH_route
            if verify_BH_in_Remote_BGP(node7_s2_bgw_1,str(P3_dict['mac'])):
                log.info('Mac BH route is proper in BGP on S2_BGW1')
            else:
                log.debug('Mac BH route is improper in BGP on  S2_BGW1')
                self.errored('Mac BH route is improper in BGP on  S2_BGW1')

            #Access_Mac_BH_route
            if verify_BH_in_Remote_BGP(node3_s1_bgw_1,str(P3_dict['mac'])):
                log.info('Mac BH route is proper in BGP on Access')
            else:
                log.debug('Mac BH route is improper in BGP on  Access')
                self.errored('Mac BH route is improper in BGP on  Access')
        
        except Exception as error:
            log.debug("Unable to verify BH mac route in BGP - Encountered Exception " + str(error))
            self.errored('Exception occurred while verifying BH mac route in BGP')
    
    @aetest.test
    def Verify_Ipv6_icmp_neighbor(self,testbed):
        node3_s1_bgw_1 = testbed.devices['node3_s1_bgw_1']
        node7_s2_bgw_1 = testbed.devices['node7_s2_bgw_1']
        P3_dict = AcceSW_TGEN_data
        
        try:
            ###S1_BGW1_MAC_BH_ROUTE
            if Verify_ipv6_local_neighbor(node3_s1_bgw_1,str(P3_dict['mac']),str(P3_dict['vlan_id'])):
                log.info('Mac BH route is proper in ICMP neighbor on  S1_BGw1')
            else:
                log.info('Mac BH route is improper in ICMP neighbor on  S1_BGw1')
                self.failed('Mac BH route is improper in ICMP neighbor on  S1_BGw1')

            if verify_icmp_static_remote_neighbor(node7_s2_bgw_1,str(P3_dict['mac'])):
                log.info('Mac BH route is proper in ICMP neighbor on  S1_BGw1')
            else:
                log.info('Mac BH route is improper in ICMP neighbor on  S1_BGw1')
                self.failed('Mac BH route is improper in ICMP neighbor on  S1_BGw1')
        
        except Exception as error:
            log.debug("Unable to verify BH mac route in ICMP neighbor - Encountered Exception " + str(error))
            self.errored('Exception occurred while verifying BH mac route in ICMP neighbor')  


    @aetest.test
    def UnConfig_Mac_BH_Static_ND_on_VPC(self,testscript,testbed):
        node3_s1_bgw_1 = testbed.devices['node3_s1_bgw_1']
        node4_s1_bgw_2 = testbed.devices['node4_s1_bgw_2']
        P3_dict = AcceSW_TGEN_data
        mac= str(P3_dict['mac'])
        vlan= str(P3_dict['vlan_id'])
        ipv6=str(P3_dict['v6_addr'])
        octet = 2
        no_int= int(P3_dict['no_of_ints'])
        
        for i in range (0,no_int):
            ###LEAF_3_MAC_BH_ROUTE
            testbed.devices['node3_s1_bgw_1'].configure('''
                no mac address-table static ''' + str(mac) + ''' vlan '''+ str(vlan) + ''' drop

                interface vlan ''' + str(vlan) + '''
                    no ipv6 neighbor ''' + str(ipv6) + ''' ''' + str(mac) + '''
            ''')
        
            testbed.devices['node4_s1_bgw_2'].configure('''
                no mac address-table static ''' + str(mac) + ''' vlan '''+ str(vlan) + ''' drop

                interface vlan ''' + str(vlan) + '''
                    no ipv6 neighbor ''' + str(ipv6) + ''' ''' + str(mac) + '''
            ''')
            lasthex=incr_mac(mac)
            mac=mac[0:10]+lasthex
            vlan= int(vlan)+int(P3_dict['vlan_id_step'])
            ipv6=incr_ipv6(ipv6,octet) 

    @aetest.test
    def APPLY_TRAFFIC(self):
        """ IXIA_CONFIGURATION subsection: Verify IXIA Traffic """

        # Apply IXIA Traffic
        if ixLib.apply_traffic() == 1:
            log.info("Applying IXIA TI Passed")
        else:
            self.errored("Applying IXIA TI failed")

    @aetest.test
    def VERIFY_IXIA_TRAFFIC_after_rmBH_Route(self, testscript):
        """ IXIA_CONFIGURATION subsection: Verify IXIA Traffic """

        # Do not perform configurations if skip_tgen_config flag is set
        #if not testscript.parameters['script_flags']['skip_tgen_config']:

        time.sleep(20)

        if ixLib.verify_traffic(10) == 1:
            log.debug("Traffic Verification Passed.Expecting traffic loss here.") 
        else:
            log.info("Traffic Verification Failed. Expecting traffic loss here.")
            self.failed("Traffic Verification failed")
        # else:
        #     self.passed(reason="Skipped TGEN Configurations as per request")

    
    @aetest.cleanup
    def cleanup(self,testscript,testbed):
        """Unconfigure qos policies"""
        node3_s1_bgw_1 = testbed.devices['node3_s1_bgw_1']
        node5_s1_leaf_1 = testbed.devices['node5_s1_leaf_1']
        node10_s1_AccessSW =testbed.devices['node10_s1_AccessSW']
        node7_s2_bgw_1 =testbed.devices['node7_s2_bgw_1']
        P3_dict = AcceSW_TGEN_data
        forwardingSysDict = FWD_SYS_dict
        try:
            # Stop Traffic from ixia
            log.info("--- Stopping Traffic ---- \n")
            log.info("Stopping Traffic")
            traffic_run_status = ixLib.stop_traffic()
            
            if traffic_run_status is not 1:
               log.info("Failed: To Stop traffic")
               return 0
            else:
                log.info("\nTraffic Stopped successfully\n")
            time.sleep(10)
            ####Remove traffic item configured
            UCAST_v6_dict_1 = {
                            'mode'        : 'remove',
                            'stream_id'   : stream_id,
                      }
            if (ixLib.delete_traffic_item(UCAST_v6_dict_1))==0:
                log.debug("Traffic Remove failed")
                self.failed("Traffic Remove failed", goto=['next_tc'])
            else:
                log.info("Traffic Remove Passed")
            UCAST_v6_dict_2 = {
                            'mode'        : 'remove',
                            'stream_id'   : stream_id_1,
                      }
            if (ixLib.delete_traffic_item(UCAST_v6_dict_2))==0:
                log.debug("Traffic Remove failed")
                self.failed("Traffic Remove failed", goto=['next_tc'])
            else:
                log.info("Traffic Remove Passed")
            UCAST_v6_dict_3 = {
                            'mode'        : 'remove',
                            'stream_id'   : stream_id_2,
                      }
            if (ixLib.delete_traffic_item(UCAST_v6_dict_3))==0:
                log.debug("Traffic Remove failed")
                self.failed("Traffic Remove failed", goto=['next_tc'])
            else:
                log.info("Traffic Remove Passed")
            
            ###LEAF_1_MAC_BH_ROUTE
        except Exception as error:
            log.debug("Unable to do cleanup " + str(error))
            self.errored('Exception occurred during cleanup', goto=['next_tc']) 

class Mac_BH_route_on_remote_vtep_start_traffic_with_ipv6_header(nxtest.Testcase):
    # "TC_0053_Mac_BH_route_on_remote_vtep_start_traffic_with_ipv6_header"
    stream_id=''
    @aetest.test
    def CONFIGURE_UCAST_L3_IXIA_TRAFFIC_H2_to_H1(self, testscript):
        """ IXIA_CONFIGURATION subsection: Configure MCAST Traffic Item """

        # Do not perform configurations if skip_tgen_config flag is set
        #if not testscript.parameters['script_flags']['skip_tgen_config']:

        IX_TP1 = testscript.parameters['IX_TP1']
        IX_TP2 = testscript.parameters['IX_TP2']
        IX_TP3 = testscript.parameters['IX_TP3']
        IX_TP4 = testscript.parameters['IX_TP4']
        P1_dict = S1_BGW1_TGEN_data
        P2_dict = S1_Leaf_TGEN_data
        P3_dict = AcceSW_TGEN_data
        P4_dict = S2_Leaf_TGEN_data


        UCAST_v6_dict_1 = {   'src_hndl'  : testscript.parameters['port_handle_1'],
                            'dst_hndl'  : testscript.parameters['port_handle_3'],
                            'circuit'   : 'raw',
                            'TI_name'   : "UCAST_v6",
                            'rate_pps'  : "9000",
                            'bi_dir'    : 0,
                            'frame_size': '128',
                            'src_mac'   : P1_dict['mac'],
                            'dst_mac'   : '0000.000a.aaaa',
                            'srcmac_step': '00:00:00:00:00:00',
                            'dstmac_step': '00:00:00:00:00:00',
                            'srcmac_count': '1',
                            'dstmac_count': '1',
                            'vlan_id'    : P1_dict['vlan_id'],
                            'vlanid_step': '0',
                            'vlanid_count': '1',
                            'vlan_user_priority': P1_dict['vlan_user_priority'],
                            'ipv6_src_addrs' : P1_dict['v6_addr'],
                            'ipv6_dst_addrs' : P3_dict['L3_v6_dst_addr'],
                            'ipv6_src_step' : '0:0:0:0::0',
                            'ipv6_dst_step' : '0:0:0:0::0',
                            #'ip_dscp'     : P1_dict['ip_dscp'],
#                                'ip_step'    : P1_dict['v4_addr_step'],
                        }
        
        # UCAST_v6_dict = {   'src_hndl'  : IX_TP1['ipv6_handle'],
        #                        'dst_hndl'  : IX_TP3['ipv6_handle'],
        #                        'circuit'   : 'ipv6',
        #                        'TI_name'   : "UCAST_V6",
        #                        'rate_pps'  : "9000",
        #                        'bi_dir'    : 1,
        #                        'frame_size': '128',
        #                  }


        

        UCAST_v6_TI = ixLib.configure_ixia_l3_traffic_item_ipv6(UCAST_v6_dict_1)
            
        if UCAST_v6_TI == 0:
            log.debug("Configuring UCast TI failed")
            self.errored("Configuring UCast TI failed", goto=['cleanup'])
        else:
            global stream_id
            stream_id = UCAST_v6_TI

        # else:
        #     self.passed(reason="Skipped TGEN Configurations as per request")
    
    stream_id_1=''
    @aetest.test
    def CONFIGURE_UCAST_L3_IXIA_TRAFFIC_H3_to_H1(self, testscript):
        """ IXIA_CONFIGURATION subsection: Configure MCAST Traffic Item """

        # Do not perform configurations if skip_tgen_config flag is set
        #if not testscript.parameters['script_flags']['skip_tgen_config']:

        IX_TP1 = testscript.parameters['IX_TP1']
        IX_TP2 = testscript.parameters['IX_TP2']
        IX_TP3 = testscript.parameters['IX_TP3']
        IX_TP4 = testscript.parameters['IX_TP4']
        P1_dict = S1_BGW1_TGEN_data
        P2_dict = S1_Leaf_TGEN_data
        P3_dict = AcceSW_TGEN_data
        P4_dict = S2_Leaf_TGEN_data


        UCAST_v6_dict_2 = {   'src_hndl'  : testscript.parameters['port_handle_2'],
                            'dst_hndl'  : testscript.parameters['port_handle_3'],
                            'circuit'   : 'raw',
                            'TI_name'   : "UCAST_v6",
                            'rate_pps'  : "9000",
                            'bi_dir'    : 0,
                            'frame_size': '128',
                            'src_mac'   : P2_dict['mac'],
                            'dst_mac'   : '0000.000a.aaaa',
                            'srcmac_step': '00:00:00:00:00:00',
                            'dstmac_step': '00:00:00:00:00:00',
                            'srcmac_count': '1',
                            'dstmac_count': '1',
                            'vlan_id'    : P2_dict['vlan_id'],
                            'vlanid_step': '0',
                            'vlanid_count': '1',
                            'vlan_user_priority': P2_dict['vlan_user_priority'],
                            'ipv6_src_addrs' : P2_dict['v6_addr'],
                            'ipv6_dst_addrs' : P3_dict['L3_v6_dst_addr'],
                            'ipv6_src_step' :  '0:0:0:0::0',
                            'ipv6_dst_step' :  '0:0:0:0::0',
                            #'ip_dscp'     : P2_dict['ip_dscp'],
#                                'ip_step'    : P1_dict['v4_addr_step'],
                        }
        
        # UCAST_v6_dict = {   'src_hndl'  : IX_TP2['ipv6_handle'],
        #                        'dst_hndl'  : IX_TP3['ipv6_handle'],
        #                        'circuit'   : 'ipv6',
        #                        'TI_name'   : "UCAST_V6",
        #                        'rate_pps'  : "9000",
        #                        'bi_dir'    : 1
        #                  }


        UCAST_v6_TI_1 = ixLib.configure_ixia_l3_traffic_item_ipv6(UCAST_v6_dict_2)
            
        if UCAST_v6_TI_1 == 0:
            log.debug("Configuring UCast TI failed")
            self.errored("Configuring UCast TI failed", goto=['cleanup'])
        else:
            global stream_id_1
            stream_id_1 = UCAST_v6_TI_1

        # else:
        #     self.passed(reason="Skipped TGEN Configurations as per request")
    
    stream_id_2=''
    @aetest.test
    def CONFIGURE_UCAST_L3_IXIA_TRAFFIC_H4_to_H1(self, testscript):
        """ IXIA_CONFIGURATION subsection: Configure MCAST Traffic Item """

        # Do not perform configurations if skip_tgen_config flag is set
        #if not testscript.parameters['script_flags']['skip_tgen_config']:

        IX_TP1 = testscript.parameters['IX_TP1']
        IX_TP2 = testscript.parameters['IX_TP2']
        IX_TP3 = testscript.parameters['IX_TP3']
        IX_TP4 = testscript.parameters['IX_TP4']
        P1_dict = S1_BGW1_TGEN_data
        P2_dict = S1_Leaf_TGEN_data
        P3_dict = AcceSW_TGEN_data
        P4_dict = S2_Leaf_TGEN_data


        UCAST_v6_dict_3 = {   'src_hndl'  : testscript.parameters['port_handle_4'],
                            'dst_hndl'  : testscript.parameters['port_handle_3'],
                            'circuit'   : 'raw',
                            'TI_name'   : "UCAST_v6",
                            'rate_pps'  : "9000",
                            'bi_dir'    : 1,
                            'frame_size': '128',
                            'src_mac'   : P4_dict['mac'],
                            'dst_mac'   : '0000.000a.aaaa',
                            'srcmac_step': '00:00:00:00:00:00',
                            'dstmac_step': '00:00:00:00:00:00',
                            'srcmac_count': '1',
                            'dstmac_count': '1',
                            'vlan_id'    : P4_dict['vlan_id'],
                            'vlanid_step': '0',
                            'vlanid_count': '1',
                            'vlan_user_priority': P4_dict['vlan_user_priority'],
                            'ipv6_src_addrs' : P4_dict['v6_addr'],
                            'ipv6_dst_addrs' : P3_dict['L3_v6_dst_addr'],
                            'ipv6_src_step' : '0:0:0:0::0',
                            'ipv6_dst_step' : '0:0:0:0::0',
                            #'ip_dscp'     : P4_dict['ip_dscp'],
#                                'ip_step'    : P1_dict['v4_addr_step'],
                        }

        # UCAST_v6_dict = {   'src_hndl'  : IX_TP4['ipv6_handle'],
        #                        'dst_hndl'  : IX_TP3['ipv6_handle'],
        #                        'circuit'   : 'ipv6',
        #                        'TI_name'   : "UCAST_V6",
        #                        'rate_pps'  : "9000",
        #                        'bi_dir'    : 1
        #                  }

        UCAST_v6_TI_2 = ixLib.configure_ixia_l3_traffic_item_ipv6(UCAST_v6_dict_3)
            
        if UCAST_v6_TI_2 == 0:
            log.debug("Configuring UCast TI failed")
            self.errored("Configuring UCast TI failed", goto=['cleanup'])
        else:
            global stream_id_2
            stream_id_2 = UCAST_v6_TI_2

        # else:
        #     self.passed(reason="Skipped TGEN Configurations as per request")

    
    @aetest.test
    def APPLY_TRAFFIC(self):
        """ IXIA_CONFIGURATION subsection: Verify IXIA Traffic """

        # Apply IXIA Traffic
        if ixLib.apply_traffic() == 1:
            log.info("Applying IXIA TI Passed")
        else:
            self.errored("Applying IXIA TI failed")

    @aetest.test
    def VERIFY_IXIA_TRAFFIC_Without_BH_Route(self, testscript):
        """ IXIA_CONFIGURATION subsection: Verify IXIA Traffic """

        # Do not perform configurations if skip_tgen_config flag is set
        #if not testscript.parameters['script_flags']['skip_tgen_config']:

        time.sleep(20)

        if ixLib.verify_traffic(1) == 1:
            log.debug("Traffic Verification Passed.Expecting traffic loss here.") 
        else:
            log.info("Traffic Verification Failed. Expecting traffic loss here.")
            self.failed("Traffic Verification failed")
        # else:
        #     self.passed(reason="Skipped TGEN Configurations as per request")

    @aetest.test
    def Config_Mac_BH_Static_ND_on_VPC(self,testscript,testbed):
        node7_s2_bgw_1 = testbed.devices['node7_s2_bgw_1']
        P3_dict = AcceSW_TGEN_data
        mac= str(P3_dict['mac'])
        vlan= str(P3_dict['vlan_id'])
        ipv6=str(P3_dict['v6_addr'])
        octet = 2
        no_int= int(P3_dict['no_of_ints'])
        
        for i in range (0,no_int):
            ###LEAF_3_MAC_BH_ROUTE
            testbed.devices['node7_s2_bgw_1'].configure('''
                mac address-table static ''' + str(mac) + ''' vlan '''+ str(vlan) + ''' drop

                interface vlan ''' + str(vlan) + '''
                  ipv6 neighbor ''' + str(ipv6) + ''' ''' + str(mac) + '''
            ''')
            lasthex=incr_mac(mac)
            mac=mac[0:10]+lasthex
            vlan= int(vlan)+int(P3_dict['vlan_id_step'])
            ipv6=incr_ipv6(ipv6,octet) 
          
        
    @aetest.test
    def APPLY_TRAFFIC(self):
        """ IXIA_CONFIGURATION subsection: Verify IXIA Traffic """

        # Apply IXIA Traffic
        if ixLib.apply_traffic() == 1:
            log.info("Applying IXIA TI Passed")
        else:
            self.errored("Applying IXIA TI failed")

    @aetest.test
    def VERIFY_IXIA_TRAFFIC_With_BH_Route(self, testscript):
        """ IXIA_CONFIGURATION subsection: Verify IXIA Traffic """

        # Do not perform configurations if skip_tgen_config flag is set
        #if not testscript.parameters['script_flags']['skip_tgen_config']:

        time.sleep(20)

        if ixLib.verify_traffic(99) == 0:
            log.debug("Traffic Verification Passed.Expecting traffic loss here.") 
        else:
            log.info("Traffic Verification Failed. Expecting traffic loss here.")
            self.failed("Traffic Verification failed")
        # else:
        #     self.passed(reason="Skipped TGEN Configurations as per request")

    @aetest.test
    def Verify_Traffic_Drop_on_Remote_Vtep(self,testscript,testbed):
        node5_s1_leaf_1 = testbed.devices['node5_s1_leaf_1']
        node3_s1_bgw_1 = testbed.devices['node3_s1_bgw_1']
        node9_s2_leaf_1 = testbed.devices['node9_s2_leaf_1']
        node7_s2_bgw_1 =testbed.devices['node7_s2_bgw_1']
        P3_dict = AcceSW_TGEN_data
        uplink_PO=S1_Leaf_dict['S1_Leaf_UPLINK_PO']['po_id']
        if verify_traffic_drop(node5_s1_leaf_1,uplink_PO):
            log.info('Traffic correctly dropped on  S1_Leaf')
        else:
            log.info('Traffic NOT dropped on  S1_Leaf')
            self.failed('Traffic NOT dropped on  S1_Leaf')

        uplink_PO=S1_BGW1_dict['S1_BGW1_UPLINK_PO']['po_id']
        if verify_traffic_drop(node3_s1_bgw_1,uplink_PO):
            log.info('Traffic correctly dropped on  S1_BGW1')
        else:
            log.info('Traffic NOT dropped on  S1_BGW1')
            self.failed('Traffic NOT dropped on  S1_BGW1')
        
        uplink_PO=S2_Leaf_dict['S2_Leaf_UPLINK_PO']['po_id']
        if verify_traffic_drop(node9_s2_leaf_1,uplink_PO):
            log.info('Traffic correctly dropped on  S2_Leaf')
        else:
            log.info('Traffic NOT dropped on  S2_Leaf')
            self.failed('Traffic NOT dropped on  S2_Leaf')  
    
    @aetest.test
    def verify_static_mac_states(self, testscript,testbed):
        node3_s1_bgw_1 = testbed.devices['node3_s1_bgw_1']
        node7_s2_bgw_1 = testbed.devices['node7_s2_bgw_1']
        P3_dict = AcceSW_TGEN_data
        if verify_static_mac(node3_s1_bgw_1,str(P3_dict['mac']),str(P3_dict['vlan_id'])):
            log.info('proper static mac learnt on S1_BGw1')
        else:
            log.info('improper static mac learnt on  S1_BGw1')
            self.failed('improper static mac learnt on  S1_BGw1')

        if verify_static_mac(node7_s2_bgw_1,str(P3_dict['mac']),str(P3_dict['vlan_id'])):
            log.info('proper static mac learnt on  S2_BGw1')
        else:
            log.info('improper static mac learnt on S2_BGw1')
            self.failed('improper static mac learnt on  S2_BGw1') 
    
    @aetest.test
    def Verify_BH_states_in_HMM(self, testscript,testbed):
        node3_s1_bgw_1 =testbed.devices['node3_s1_bgw_1']
        node7_s2_bgw_1 = testbed.devices['node7_s2_bgw_1']
        P3_dict = AcceSW_TGEN_data
        try:
            if verify_Ipv6_BH_in_HMM(node7_s2_bgw_1,str(P3_dict['v6_addr'])):
                log.info('Mac BH route is proper in HMM on  S1_BGW1')
            else:
                log.info('Mac BH route is improper in HMM on  S1_BGW1')
                self.failed('Mac BH route is improper in HMM on  S1_BGW1')
        
         
        except Exception as error:
            log.debug("Unable to configure static BH mac route on Remote Vtep- Encountered Exception " + str(error))
            self.errored('Exception occurred while configuring static BH mac route on Remote Vtep')

    @aetest.test
    def Verify_BH_states_in_AM(self, testscript,testbed):
        node3_s1_bgw_1 = testbed.devices['node3_s1_bgw_1']
        node7_s2_bgw_1 = testbed.devices['node7_s2_bgw_1']
        P3_dict = AcceSW_TGEN_data

        try:        
            if verify_Ipv6_BH_in_AM(node7_s2_bgw_1,str(P3_dict['mac']),str(P3_dict['vlan_id']),str(P3_dict['v6_addr'])):
                log.info('Mac BH route is proper in AM on  S1_BGW1')
            else:
                log.info('Mac BH route is improper in AM on  S1_BGW1')
                self.failed('Mac BH route is improper in AM on  S1_BGW1')
        
        except Exception as error:
            log.debug("Unable to configure static BH mac route on Remote Vtep- Encountered Exception " + str(error))
            self.errored('Exception occurred while configuring static BH mac route on Remote Vtep')
    
        
    @aetest.test
    def Verify_Mac_BH_Route_on_L2FM_BGP_L2RIB(self,testscript,testbed):
        node3_s1_bgw_1 =testbed.devices['node3_s1_bgw_1']
        node7_s2_bgw_1 = testbed.devices['node7_s2_bgw_1']
        P3_dict = AcceSW_TGEN_data      
        # Verifying L2FM

        try:
            ###S1_BGW1_MAC_BH_ROUTE
            if verify_BH_route_in_L2FM(node3_s1_bgw_1,str(P3_dict['vlan_id']),str(P3_dict['mac'])):
                log.info('Mac BH route is proper in L2FM on  S1_BGw1')
            else:
                log.info('Mac BH route is improper in L2FM on  S1_BGw1')
                self.failed('Mac BH route is improper in L2FM on  S1_BGw1')

            ###S2_BGW1_MAC_BH_ROUTE Remote Vtep
            if verify_BH_route_in_L2FM(node7_s2_bgw_1,str(P3_dict['vlan_id']),str(P3_dict['mac'])):
                log.info('Mac BH route is proper in L2FM on  S2_BGw1')
            else:
                log.info('Mac BH route is improper in L2FM on  S2_BGw1')
                self.failed('Mac BH route is improper in L2FM on  S2_BGw1')

        except Exception as error:
            log.debug("Unable to verify BH mac route in L2FM - Encountered Exception " + str(error))
            self.errored('Exception occurred while verifying BH mac route in L2FM')        

        #Verifying L2RIB
        try:
            #S1_Leaf_Mac_BH_route
            if verify_L2rib_mac_ip_output(node3_s1_bgw_1,str(P3_dict['vlan_id']),str(P3_dict['mac'])):
                log.info('Mac BH route is proper in L2RIB on S1_Leaf')
            else:
                log.debug('Mac BH route is improper in L2RIB on  S1_Leaf')
                self.failed('Mac BH route is improper in L2RIB on  S1_Leaf')

            #S2_BGW1_Mac_BH_route
            if verify_L2rib_mac_ip_output(node7_s2_bgw_1,str(P3_dict['vlan_id']),str(P3_dict['mac'])):
                log.info('Mac BH route is proper in L2RIB on S2_BGW1')
            else:
                log.debug('Mac BH route is improper in L2RIB on  S2_BGW1')
                self.errored('Mac BH route is improper in L2RIB on  S2_BGW1')
        
        except Exception as error:
            log.debug("Unable to verify BH mac route in L2RIB - Encountered Exception " + str(error))
            self.errored('Exception occurred while verifying BH mac route in L2RIB')
        
        #Verifying BGP
        try:
            #S2_BGW1_Mac_BH_route
            if verify_BH_in_Remote_BGP(node7_s2_bgw_1,str(P3_dict['mac'])):
                log.info('Mac BH route is proper in BGP on S2_BGW1')
            else:
                log.debug('Mac BH route is improper in BGP on  S2_BGW1')
                self.errored('Mac BH route is improper in BGP on  S2_BGW1')

            #Access_Mac_BH_route
            if verify_BH_in_Remote_BGP(node3_s1_bgw_1,str(P3_dict['mac'])):
                log.info('Mac BH route is proper in BGP on Access')
            else:
                log.debug('Mac BH route is improper in BGP on  Access')
                self.errored('Mac BH route is improper in BGP on  Access')
        
        except Exception as error:
            log.debug("Unable to verify BH mac route in BGP - Encountered Exception " + str(error))
            self.errored('Exception occurred while verifying BH mac route in BGP')

    @aetest.test
    def Verify_Ipv6_icmp_neighbor(self,testbed):
        node3_s1_bgw_1 = testbed.devices['node3_s1_bgw_1']
        node7_s2_bgw_1 = testbed.devices['node7_s2_bgw_1']
        P3_dict = AcceSW_TGEN_data
        
        try:
            ###S1_BGW1_MAC_BH_ROUTE
            if Verify_ipv6_local_neighbor(node7_s2_bgw_1,str(P3_dict['mac']),str(P3_dict['vlan_id'])):
                log.info('Mac BH route is proper in ICMP neighbor on  S1_BGw1')
            else:
                log.info('Mac BH route is improper in ICMP neighbor on  S1_BGw1')
                self.failed('Mac BH route is improper in ICMP neighbor on  S1_BGw1')

            if verify_icmp_static_remote_neighbor(node3_s1_bgw_1,str(P3_dict['mac'])):
                log.info('Mac BH route is proper in ICMP neighbor on  S1_BGw1')
            else:
                log.info('Mac BH route is improper in ICMP neighbor on  S1_BGw1')
                self.failed('Mac BH route is improper in ICMP neighbor on  S1_BGw1')
        
        except Exception as error:
            log.debug("Unable to verify BH mac route in ICMP neighbor - Encountered Exception " + str(error))
            self.errored('Exception occurred while verifying BH mac route in ICMP neighbor') 
             

    @aetest.test
    def UnConfig_Mac_BH_Static_ND_on_VPC(self,testscript,testbed):
        node7_s2_bgw_1 = testbed.devices['node7_s2_bgw_1']
        P3_dict = AcceSW_TGEN_data
        mac= str(P3_dict['mac'])
        vlan= str(P3_dict['vlan_id'])
        ipv6=str(P3_dict['v6_addr'])
        octet = 2
        no_int= int(P3_dict['no_of_ints'])
        
        for i in range (0,no_int):
            ###LEAF_3_MAC_BH_ROUTE
            testbed.devices['node7_s2_bgw_1'].configure('''
                no mac address-table static ''' + str(mac) + ''' vlan '''+ str(vlan) + ''' drop

                interface vlan ''' + str(vlan) + '''
                  no ipv6 neighbor ''' + str(ipv6) + ''' ''' + str(mac) + '''
            ''')
            lasthex=incr_mac(mac)
            mac=mac[0:10]+lasthex
            vlan= int(vlan)+int(P3_dict['vlan_id_step'])
            ipv6=incr_ipv6(ipv6,octet) 

    @aetest.test
    def APPLY_TRAFFIC(self):
        """ IXIA_CONFIGURATION subsection: Verify IXIA Traffic """

        # Apply IXIA Traffic
        if ixLib.apply_traffic() == 1:
            log.info("Applying IXIA TI Passed")
        else:
            self.errored("Applying IXIA TI failed")

    @aetest.test
    def VERIFY_IXIA_TRAFFIC_after_rmBH_Route(self, testscript):
        """ IXIA_CONFIGURATION subsection: Verify IXIA Traffic """

        # Do not perform configurations if skip_tgen_config flag is set
        #if not testscript.parameters['script_flags']['skip_tgen_config']:

        time.sleep(20)

        if ixLib.verify_traffic(10) == 1:
            log.debug("Traffic Verification Passed.Expecting traffic loss here.") 
        else:
            log.info("Traffic Verification Failed. Expecting traffic loss here.")
            self.failed("Traffic Verification failed")
        # else:
        #     self.passed(reason="Skipped TGEN Configurations as per request")
    
    @aetest.cleanup
    def cleanup(self,testscript,testbed):
        """Unconfigure qos policies"""
        node3_s1_bgw_1 = testbed.devices['node3_s1_bgw_1']
        node5_s1_leaf_1 = testbed.devices['node5_s1_leaf_1']
        node10_s1_AccessSW =testbed.devices['node10_s1_AccessSW']
        node7_s2_bgw_1 =testbed.devices['node7_s2_bgw_1']
        P3_dict = AcceSW_TGEN_data
        forwardingSysDict = FWD_SYS_dict
        try:
            # Stop Traffic from ixia
            log.info("--- Stopping Traffic ---- \n")
            log.info("Stopping Traffic")
            traffic_run_status = ixLib.stop_traffic()
            
            if traffic_run_status is not 1:
               log.info("Failed: To Stop traffic")
               return 0
            else:
                log.info("\nTraffic Stopped successfully\n")
            time.sleep(10)
            ####Remove traffic item configured
            UCAST_v6_dict_1 = {
                            'mode'        : 'remove',
                            'stream_id'   : stream_id,
                      }
            if (ixLib.delete_traffic_item(UCAST_v6_dict_1))==0:
                log.debug("Traffic Remove failed")
                self.failed("Traffic Remove failed", goto=['next_tc'])
            else:
                log.info("Traffic Remove Passed")
            UCAST_v6_dict_2 = {
                            'mode'        : 'remove',
                            'stream_id'   : stream_id_1,
                      }
            if (ixLib.delete_traffic_item(UCAST_v6_dict_2))==0:
                log.debug("Traffic Remove failed")
                self.failed("Traffic Remove failed", goto=['next_tc'])
            else:
                log.info("Traffic Remove Passed")
            UCAST_v6_dict_3 = {
                            'mode'        : 'remove',
                            'stream_id'   : stream_id_2,
                      }
            if (ixLib.delete_traffic_item(UCAST_v6_dict_3))==0:
                log.debug("Traffic Remove failed")
                self.failed("Traffic Remove failed", goto=['next_tc'])
            else:
                log.info("Traffic Remove Passed")
            ###LEAF_1_MAC_BH_ROUTE
        except Exception as error:
            log.debug("Unable to do cleanup " + str(error))
            self.errored('Exception occurred during cleanup', goto=['next_tc']) 
    
class Type5_route_with_Null_NH(nxtest.Testcase):
    #"TC_0054_Type5_route_with_Null_NH"   
    stream_id=''
    @aetest.test
    def CONFIGURE_UCAST_L3_IXIA_TRAFFIC_H2_to_H1(self, testscript):
        """ IXIA_CONFIGURATION subsection: Configure MCAST Traffic Item """

        # Do not perform configurations if skip_tgen_config flag is set
        #if not testscript.parameters['script_flags']['skip_tgen_config']:

        IX_TP1 = testscript.parameters['IX_TP1']
        IX_TP2 = testscript.parameters['IX_TP2']
        IX_TP3 = testscript.parameters['IX_TP3']
        IX_TP4 = testscript.parameters['IX_TP4']
        P1_dict = S1_BGW1_TGEN_data
        P2_dict = S1_Leaf_TGEN_data
        P3_dict = AcceSW_TGEN_data
        P4_dict = S2_Leaf_TGEN_data


        UCAST_v4_dict_1 = {   'src_hndl'  : IX_TP1['port_handle'],
                            'dst_hndl'  : IX_TP3['port_handle'],
                            'circuit'   : 'raw',
                            'TI_name'   : "UCAST_v4",
                            'rate_pps'  : "9000",
                            'bi_dir'    : 0,
                            'frame_size': '128',
                            'src_mac'   : P1_dict['mac'],
                            'dst_mac'   : '0000.000a.aaaa',
                            'srcmac_step': '00:00:00:00:00:00',
                            'dstmac_step': '00:00:00:00:00:00',
                            'srcmac_count': '1',
                            'dstmac_count': '1',
                            'vlan_id'    : P1_dict['vlan_id'],
                            'vlanid_step': '0',
                            'vlanid_count': '2',
                            'vlan_user_priority': P1_dict['vlan_user_priority'],
                            'ip_src_addrs' : P1_dict['v4_addr'],
                            'ip_dst_addrs' : P3_dict['L3_dst_addr'],
                            'ip_src_step' : '0.0.0.0',
                            'ip_dscp'     : P1_dict['ip_dscp'],
                            'ip_dst_step' : '0.0.0.0',
#                                'ip_step'    : P1_dict['v4_addr_step'],
                        }

        UCAST_v4_TI = ixLib.configure_ixia_l3_traffic_item(UCAST_v4_dict_1)
            
        if UCAST_v4_TI == 0:
            log.debug("Configuring UCast TI failed")
            self.errored("Configuring UCast TI failed", goto=['cleanup'])
        else:
            global stream_id
            stream_id = UCAST_v4_TI

        # else:
        #     self.passed(reason="Skipped TGEN Configurations as per request")
    stream_id_1=''
    @aetest.test
    def CONFIGURE_UCAST_L3_IXIA_TRAFFIC_H3_to_H1(self, testscript):
        """ IXIA_CONFIGURATION subsection: Configure MCAST Traffic Item """

        # Do not perform configurations if skip_tgen_config flag is set
        #if not testscript.parameters['script_flags']['skip_tgen_config']:

        IX_TP1 = testscript.parameters['IX_TP1']
        IX_TP2 = testscript.parameters['IX_TP2']
        IX_TP3 = testscript.parameters['IX_TP3']
        IX_TP4 = testscript.parameters['IX_TP4']
        P1_dict = S1_BGW1_TGEN_data
        P2_dict = S1_Leaf_TGEN_data
        P3_dict = AcceSW_TGEN_data
        P4_dict = S2_Leaf_TGEN_data


        UCAST_v4_dict_2 = {   'src_hndl'  : IX_TP2['port_handle'],
                            'dst_hndl'  : IX_TP3['port_handle'],
                            'circuit'   : 'raw',
                            'TI_name'   : "UCAST_v4",
                            'rate_pps'  : "9000",
                            'bi_dir'    : 0,
                            'frame_size': '128',
                            'src_mac'   : P2_dict['mac'],
                            'dst_mac'   : '0000.000a.aaaa',
                            'srcmac_step': '00:00:00:00:00:00',
                            'dstmac_step': '00:00:00:00:00:00',
                            'srcmac_count': '1',
                            'dstmac_count': '1',
                            'vlan_id'    : P2_dict['vlan_id'],
                            'vlanid_step': '0',
                            'vlanid_count': '2',
                            'vlan_user_priority': P2_dict['vlan_user_priority'],
                            'ip_src_addrs' : P2_dict['v4_addr'],
                            'ip_dst_addrs' : P3_dict['L3_dst_addr'],
                            'ip_src_step' : '0.0.0.0',
                            'ip_dst_step' : '0.0.0.0',
                            'ip_dscp'     : P2_dict['ip_dscp'],
#                                'ip_step'    : P1_dict['v4_addr_step'],
                        }

        UCAST_v4_TI_1 = ixLib.configure_ixia_l3_traffic_item(UCAST_v4_dict_2)
            
        if UCAST_v4_TI_1 == 0:
            log.debug("Configuring UCast TI failed")
            self.errored("Configuring UCast TI failed", goto=['cleanup'])
        else:
            global stream_id_1
            stream_id_1 = UCAST_v4_TI_1

        # else:
        #     self.passed(reason="Skipped TGEN Configurations as per request")
    stream_id_2=''
    @aetest.test
    def CONFIGURE_UCAST_L3_IXIA_TRAFFIC_H4_to_H1(self, testscript):
        """ IXIA_CONFIGURATION subsection: Configure MCAST Traffic Item """

        # Do not perform configurations if skip_tgen_config flag is set
        #if not testscript.parameters['script_flags']['skip_tgen_config']:

        IX_TP1 = testscript.parameters['IX_TP1']
        IX_TP2 = testscript.parameters['IX_TP2']
        IX_TP3 = testscript.parameters['IX_TP3']
        IX_TP4 = testscript.parameters['IX_TP4']
        P1_dict = S1_BGW1_TGEN_data
        P2_dict = S1_Leaf_TGEN_data
        P3_dict = AcceSW_TGEN_data
        P4_dict = S2_Leaf_TGEN_data


        UCAST_v4_dict_3 = {   'src_hndl'  : IX_TP4['port_handle'],
                            'dst_hndl'  : IX_TP3['port_handle'],
                            'circuit'   : 'raw',
                            'TI_name'   : "UCAST_v4",
                            'rate_pps'  : "9000",
                            'bi_dir'    : 0,
                            'frame_size': '128',
                            'src_mac'   : P4_dict['mac'],
                            'dst_mac'   : '0000.000a.aaaa',
                            'srcmac_step': '00:00:00:00:00:00',
                            'dstmac_step': '00:00:00:00:00:00',
                            'srcmac_count': '1',
                            'dstmac_count': '1',
                            'vlan_id'    : P4_dict['vlan_id'],
                            'vlanid_step': '0',
                            'vlanid_count': '2',
                            'vlan_user_priority': P4_dict['vlan_user_priority'],
                            'ip_src_addrs' : P4_dict['v4_addr'],
                            'ip_dst_addrs' : P3_dict['L3_dst_addr'],
                            'ip_src_step' : '0.0.0.0',
                            'ip_dst_step' : '0.0.0.0',
                            'ip_dscp'     : P4_dict['ip_dscp'],
#                                'ip_step'    : P1_dict['v4_addr_step'],
                        }

        UCAST_v4_TI_2 = ixLib.configure_ixia_l3_traffic_item(UCAST_v4_dict_3)
            
        if UCAST_v4_TI_2 == 0:
            log.debug("Configuring UCast TI failed")
            self.errored("Configuring UCast TI failed", goto=['cleanup'])
        else:
            global stream_id_2
            stream_id_2 = UCAST_v4_TI_2

        # else:
        #     self.passed(reason="Skipped TGEN Configurations as per request")

    @aetest.test
    def APPLY_TRAFFIC(self):
        """ IXIA_CONFIGURATION subsection: Verify IXIA Traffic """

        # Apply IXIA Traffic
        if ixLib.apply_traffic() == 1:
            log.info("Applying IXIA TI Passed")
        else:
            self.errored("Applying IXIA TI failed")

    @aetest.test
    def VERIFY_IXIA_TRAFFIC_Without_BH_Route(self, testscript):
        """ IXIA_CONFIGURATION subsection: Verify IXIA Traffic """

        # Do not perform configurations if skip_tgen_config flag is set
        #if not testscript.parameters['script_flags']['skip_tgen_config']:

        time.sleep(20)

        if ixLib.verify_traffic(1) == 1:
            log.debug("Traffic Verification Passed.Expecting traffic loss here.") 
        else:
            log.info("Traffic Verification Failed. Expecting traffic loss here.")
            self.failed("Traffic Verification failed")
        # else:
        #     self.passed(reason="Skipped TGEN Configurations as per request")


    @aetest.test
    def Configure_Type5_route_with_Null_NH(self,testbed):
        node3_s1_bgw_1 = testbed.devices['node3_s1_bgw_1']
        node7_s2_bgw_1 =testbed.devices['node7_s2_bgw_1']
        node10_s1_AccessSW = testbed.devices['node10_s1_AccessSW']
        P3_dict = AcceSW_TGEN_data
        P1_dict = S1_BGW1_TGEN_data
          # Get CS DCI TGEN Interface Name
        # Acess_tgen_interface = None
        # for interface in testbed.devices[node10_s1_AccessSW].interfaces:
        #     if testbed.devices[node10_s1_AccessSW].interfaces[interface].alias == 'nd10_tgen_1_1':
        #         Acess_tgen_interface = interface
        #         log.info("Access - TGEN Interface : "+str(interface)) 

        testbed.devices['node3_s1_bgw_1'].configure(''' 
            
            mac address-table static ''' + str(P1_dict['mac']) + ''' vlan '''+ str(P1_dict['vlan_id']) + ''' drop

            interface eth ''' + testbed.devices['node3_s1_bgw_1'].interfaces['Ethernet1/20'].intf + 
            '''
                no switchport
                ip address ''' + str(P1_dict['v4_addr']) +'''/16
            
            vrf context vrf-1
                vni 3003001
                ip route ''' + str(P1_dict['v4_addr']) +'''/16 Null0 tag 12345
                ip pim ssm range 232.0.0.0/8
                rd auto
                address-family ipv4 unicast
                    route-target both auto
                    route-target both auto evpn

            route-map BH-Evpn-tx permit 10
                match tag 12345
                set community blackhole
        
            router bgp 200
                vrf vrf-1
                    address-family ipv4 unicast
                    advertise l2vpn evpn
                    redistribute direct route-map connect
                    redistribute static route-map  BH-Evpn-tx     
                
            ''')
        
        testbed.devices['node7_s2_bgw_1'].configure(''' 

            ip community-list standard BH-Evpn-Tx seq 10 permit blackhole 
        
            route-map rx-BH-Evpn-rt permit 10
                match community Blackhole 
                set weight 65535 

            route-map rx-BH-Evpn-rt permit 20

            router bgp 300
                neighbor 50.50.50.50
                    address-family l2vpn evpn
                    send-community
                    send-community extended
                    route-map rx-BH-Evpn-rt in
            ''')


    @aetest.test
    def APPLY_TRAFFIC(self):
        """ IXIA_CONFIGURATION subsection: Verify IXIA Traffic """

        # Apply IXIA Traffic
        if ixLib.apply_traffic() == 1:
            log.info("Applying IXIA TI Passed")
        else:
            self.errored("Applying IXIA TI failed")

    @aetest.test
    def VERIFY_IXIA_TRAFFIC_Without_BH_Route(self, testscript):
        """ IXIA_CONFIGURATION subsection: Verify IXIA Traffic """

        # Do not perform configurations if skip_tgen_config flag is set
        #if not testscript.parameters['script_flags']['skip_tgen_config']:

        time.sleep(20)

        if ixLib.verify_traffic(99) == 0:
            log.debug("Traffic Verification Passed.Expecting traffic loss here.") 
        else:
            log.info("Traffic Verification Failed. Expecting traffic loss here.")
            self.failed("Traffic Verification failed")
        # else:
        #     self.passed(reason="Skipped TGEN Configurations as per request")

    @aetest.test
    def Verify_Traffic_Drop_on_Remote_Vtep(self,testscript,testbed):
        node5_s1_leaf_1 = testbed.devices['node5_s1_leaf_1']
        node9_s2_leaf_1 = testbed.devices['node9_s2_leaf_1']
        node3_s1_bgw_1 = testbed.devices['node3_s1_bgw_1']
        P3_dict = AcceSW_TGEN_data
        uplink_PO=S1_Leaf_dict['S1_Leaf_UPLINK_PO']['po_id']
        if verify_traffic_drop(node5_s1_leaf_1,uplink_PO):
            log.info('Traffic correctly dropped on  S1_Leaf')
        else:
            log.info('Traffic NOT dropped on  S1_Leaf')
            self.failed('Traffic NOT dropped on  S1_Leaf')
        
        uplink_PO=S2_Leaf_dict['S2_Leaf_UPLINK_PO']['po_id']
        if verify_traffic_drop(node9_s2_leaf_1,uplink_PO):
            log.info('Traffic correctly dropped on  S2_Leaf')
        else:
            log.info('Traffic NOT dropped on  S2_Leaf')
            self.failed('Traffic NOT dropped on  S2_Leaf')

        uplink_PO=S1_BGW1_dict['S1_BGW1_UPLINK_PO']['po_id']
        if verify_traffic_drop(node3_s1_bgw_1,uplink_PO):
            log.info('Traffic correctly dropped on  S1_BGW1')
        else:
            log.info('Traffic NOT dropped on  S1_BGW1')
            self.failed('Traffic NOT dropped on  S1_BGW1')
            
    @aetest.test
    def verify_prefix_route(self,testbed):
        node7_s2_bgw_1 =testbed.devices['node7_s2_bgw_1']
        P3_dict = AcceSW_TGEN_data 
        P1_dict = S1_BGW1_TGEN_data
        output=node7_s2_bgw_1.execute(''' sh bgp l2vpn evpn ''' + P1_dict['v4_addr'] )
        m = re.search('Community: blackhole', output)
        if m[0] == "Community: blackhole":
            log.info('verified blackhole on S2_BGW1')
            # ForkedPdb().set_trace()
            self.passed('verified blackhole on S2_BGW1')
        else:
            # ForkedPdb().set_trace()
            self.failed('not verified blackhole on S2_BGW1')

    @aetest.test
    def Withdraw_Prefix_Null_route(self,testbed):
        node3_s1_bgw_1 = testbed.devices['node3_s1_bgw_1']
        node7_s2_bgw_1 =testbed.devices['node7_s2_bgw_1']
        P3_dict = AcceSW_TGEN_data
        P1_dict = S1_BGW1_TGEN_data
        # Acess_tgen_interface = None
        # for interface in testbed.devices[node3_s1_bgw_1].interfaces:
        #     if testbed.devices[node3_s1_bgw_1].interfaces[interface].alias == 'nd10_tgen_1_1':
        #         Acess_tgen_interface = interface
        #         log.info("Access - TGEN Interface : "+str(interface)) 

        testbed.devices['node3_s1_bgw_1'].configure(''' 
            
            no mac address-table static ''' + str(P1_dict['mac']) + ''' vlan '''+ str(P1_dict['vlan_id']) + ''' drop

            interface eth''' + testbed.devices['node3_s1_bgw_1'].interfaces['Ethernet1/20'].intf + '''
               no ip address ''' + str(P1_dict['v4_addr'])+'''/16
               switchport
               switchport mode trunk
               switchport trunk allowed vlan 1001,1076
               spanning-tree port type edge trunk
               spanning-tree bpdufilter enable
            
            vrf context vrf-1
                vni 3003001
               no ip route ''' + str(P1_dict['v4_addr'])+'''/16 Null0 tag 12345
               no ip pim ssm range 232.0.0.0/8
                rd auto
                address-family ipv4 unicast
                    route-target both auto
                    route-target both auto evpn

            no route-map BH-Evpn-tx permit 10
        
            router bgp 200
                vrf vrf-1
                    address-family ipv4 unicast
                    advertise l2vpn evpn
                    no redistribute direct route-map connect
                    no redistribute static route-map  BH-Evpn-tx     
                
            ''')
        
        testbed.devices['node7_s2_bgw_1'].configure(''' 

            no ip community-list standard BH-Evpn-Tx seq 10 permit blackhole 
        
            no route-map rx-BH-Evpn-rt permit 10 

            no route-map rx-BH-Evpn-rt permit 20

            router bgp 300
                neighbor 50.50.50.50
                    address-family l2vpn evpn
                    send-community
                    send-community extended
                   no route-map rx-BH-Evpn-rt in
            ''')
        
    @aetest.test
    def APPLY_TRAFFIC(self):
        """ IXIA_CONFIGURATION subsection: Verify IXIA Traffic """

        # Apply IXIA Traffic
        if ixLib.apply_traffic() == 1:
            log.info("Applying IXIA TI Passed")
        else:
            self.errored("Applying IXIA TI failed")

    @aetest.test
    def VERIFY_IXIA_TRAFFIC_Without_BH_Route(self, testscript):
        """ IXIA_CONFIGURATION subsection: Verify IXIA Traffic """

        # Do not perform configurations if skip_tgen_config flag is set
        #if not testscript.parameters['script_flags']['skip_tgen_config']:

        time.sleep(20)

        if ixLib.verify_traffic(10) == 1:
            log.debug("Traffic Verification Passed.Expecting traffic loss here.") 
        else:
            log.info("Traffic Verification Failed. Expecting traffic loss here.")
            self.failed("Traffic Verification failed")
        # else:
        #     self.passed(reason="Skipped TGEN Configurations as per request")

    @aetest.cleanup
    def cleanup(self,testscript,testbed):
        """Unconfigure qos policies"""
        node3_s1_bgw_1 = testbed.devices['node3_s1_bgw_1']
        node5_s1_leaf_1 = testbed.devices['node5_s1_leaf_1']
        node10_s1_AccessSW =testbed.devices['node10_s1_AccessSW']
        node7_s2_bgw_1 =testbed.devices['node7_s2_bgw_1']
        P3_dict = AcceSW_TGEN_data
        forwardingSysDict = FWD_SYS_dict
        try:
            # Stop Traffic from ixia
            log.info("--- Stopping Traffic ---- \n")
            log.info("Stopping Traffic")
            traffic_run_status = ixLib.stop_traffic()
            
            if traffic_run_status is not 1:
               log.info("Failed: To Stop traffic")
               return 0
            else:
                log.info("\nTraffic Stopped successfully\n")
            time.sleep(10)
            ####Remove traffic item configured
            UCAST_v4_dict_1 = {
                            'mode'        : 'remove',
                            'stream_id'   : stream_id,
                      }
            if (ixLib.delete_traffic_item(UCAST_v4_dict_1))==0:
                log.debug("Traffic Remove failed")
                self.failed("Traffic Remove failed", goto=['next_tc'])
            else:
                log.info("Traffic Remove Passed")
            UCAST_v4_dict_2 = {
                            'mode'        : 'remove',
                            'stream_id'   : stream_id_1,
                      }
            if (ixLib.delete_traffic_item(UCAST_v4_dict_2))==0:
                log.debug("Traffic Remove failed")
                self.failed("Traffic Remove failed", goto=['next_tc'])
            else:
                log.info("Traffic Remove Passed")
            UCAST_v4_dict_3 = {
                            'mode'        : 'remove',
                            'stream_id'   : stream_id_2,
                      }
            if (ixLib.delete_traffic_item(UCAST_v4_dict_3))==0:
                log.debug("Traffic Remove failed")
                self.failed("Traffic Remove failed", goto=['next_tc'])
            else:
                log.info("Traffic Remove Passed")
            ###LEAF_1_MAC_BH_ROUTE
        except Exception as error:
            log.debug("Unable to do cleanup " + str(error))
            self.errored('Exception occurred during cleanup', goto=['next_tc']) 

class NS_to_BH_ipv6_host(nxtest.Testcase):
    stream_id=''
    @aetest.test
    def CONFIGURE_UCAST_L3_IXIA_TRAFFIC_H4_to_H1(self, testscript):
        """ IXIA_CONFIGURATION subsection: Configure MCAST Traffic Item """

        # Do not perform configurations if skip_tgen_config flag is set
        #if not testscript.parameters['script_flags']['skip_tgen_config']:

        IX_TP1 = testscript.parameters['IX_TP1']
        IX_TP2 = testscript.parameters['IX_TP2']
        IX_TP3 = testscript.parameters['IX_TP3']
        IX_TP4 = testscript.parameters['IX_TP4']
        P1_dict = S1_BGW1_TGEN_data
        P2_dict = S1_Leaf_TGEN_data
        P3_dict = AcceSW_TGEN_data
        P4_dict = S2_Leaf_TGEN_data

        UCAST_v6_dict = {   'src_hndl'  : IX_TP4['ipv6_handle'],
                            'dst_hndl'  : IX_TP3['ipv6_handle'],
                            'circuit'   : 'ipv6',
                            'TI_name'   : "UCAST_v6",
                            'rate_pps'  : "1000",
                            'bi_dir'    : 1
                        }

        UCAST_v6_TI = ixLib.configure_ixia_l3_traffic_item(UCAST_v6_dict)
            
        if UCAST_v6_TI == 0:
            log.debug("Configuring UCast TI failed")
            self.errored("Configuring UCast TI failed", goto=['cleanup'])
        else:
            global stream_id
            stream_id = UCAST_v6_TI
    
    @aetest.test
    def APPLY_TRAFFIC(self):
        """ IXIA_CONFIGURATION subsection: Verify IXIA Traffic """

        # Apply IXIA Traffic
        if ixLib.apply_traffic() == 1:
            log.info("Applying IXIA TI Passed")
        else:
            self.errored("Applying IXIA TI failed")

    @aetest.test
    def VERIFY_IXIA_TRAFFIC_With_BH_Route(self, testscript):
        """ IXIA_CONFIGURATION subsection: Verify IXIA Traffic """

        # Do not perform configurations if skip_tgen_config flag is set
        #if not testscript.parameters['script_flags']['skip_tgen_config']:

        time.sleep(20)

        if ixLib.verify_traffic(99) == 1:
            log.debug("Traffic Verification Passed.Expecting traffic loss here.") 
        else:
            log.info("Traffic Verification Failed. Expecting traffic loss here.")
            self.failed("Traffic Verification failed")
        # else:
        #     self.passed(reason="Skipped TGEN Configurations as per request")
    
    @aetest.test
    def Config_Mac_BH_Static_ND_on_VPC(self,testscript,testbed):
        node3_s1_bgw_1 = testbed.devices['node3_s1_bgw_1']
        P3_dict = AcceSW_TGEN_data
        
        try:
            ###LEAF_3_MAC_BH_ROUTE
            testscript.parameters['node3_s1_bgw_1'].configure('''
                mac address-table static ''' + str(P3_dict['mac']) + ''' vlan '''+ str(P3_dict['vlan_id']) + ''' drop

                interface vlan ''' + str(P3_dict['vlan_id']) + '''
                  ipv6 neighbor ''' + str(P3_dict['v6_addr']) + ''' ''' + str(P3_dict['mac']) + '''
            ''')

        except Exception as error:
            log.debug("Unable to configure static BH mac route - Encountered Exception " + str(error))
            self.errored('Exception occurred while configuring static BH mac route') 

    @aetest.test
    def APPLY_TRAFFIC(self):
        """ IXIA_CONFIGURATION subsection: Verify IXIA Traffic """

        # Apply IXIA Traffic
        if ixLib.apply_traffic() == 1:
            log.info("Applying IXIA TI Passed")
        else:
            self.errored("Applying IXIA TI failed")

    @aetest.test
    def VERIFY_IXIA_TRAFFIC_With_BH_Route(self, testscript):
        """ IXIA_CONFIGURATION subsection: Verify IXIA Traffic """

        # Do not perform configurations if skip_tgen_config flag is set
        #if not testscript.parameters['script_flags']['skip_tgen_config']:

        time.sleep(20)

        if ixLib.verify_traffic(99) == 0:
            log.debug("Traffic Verification Passed.Expecting traffic loss here.") 
        else:
            log.info("Traffic Verification Failed. Expecting traffic loss here.")
            self.failed("Traffic Verification failed")
        # else:
        #     self.passed(reason="Skipped TGEN Configurations as per request")

    @aetest.test
    def Verify_Traffic_Drop_on_Remote_Vtep(self,testscript,testbed):
        node5_s1_leaf_1 = testbed.devices['node5_s1_leaf_1']
        node9_s2_leaf_1 = testbed.devices['node9_s2_leaf_1']
        node7_s2_bgw_1 = testbed.devices['node7_s2_bgw_1']
        P3_dict = AcceSW_TGEN_data
        
        uplink_PO=S2_Leaf_dict['S2_Leaf_UPLINK_PO']['po_id']
        if verify_traffic_drop(node9_s2_leaf_1,uplink_PO):
            log.info('Traffic correctly dropped on  S2_Leaf')
        else:
            log.info('Traffic NOT dropped on  S2_Leaf')
            self.failed('Traffic NOT dropped on  S2_Leaf')
    
    @aetest.test
    def Verify_Ipv6_icmp_neighbor(self,testbed):
        node3_s1_bgw_1 = testbed.devices['node3_s1_bgw_1']
        node7_s2_bgw_1 = testbed.devices['node7_s2_bgw_1']
        P3_dict = AcceSW_TGEN_data
        
        try:
            ###S1_BGW1_MAC_BH_ROUTE
            if Verify_ipv6_local_neighbor(node3_s1_bgw_1,str(P3_dict['vlan_id']),str(P3_dict['mac'])):
                log.info('Mac BH route is proper in ICMP neighbor on  S1_BGw1')
            else:
                log.info('Mac BH route is improper in ICMP neighbor on  S1_BGw1')
                self.failed('Mac BH route is improper in ICMP neighbor on  S1_BGw1')

            if verify_icmp_static_remote_neighbor(node7_s2_bgw_1,str(P3_dict['vlan_id']),str(P3_dict['mac'])):
                log.info('Mac BH route is proper in ICMP neighbor on  S1_BGw1')
            else:
                log.info('Mac BH route is improper in ICMP neighbor on  S1_BGw1')
                self.failed('Mac BH route is improper in ICMP neighbor on  S1_BGw1')
        
        except Exception as error:
            log.debug("Unable to verify BH mac route in ICMP neighbor - Encountered Exception " + str(error))
            self.errored('Exception occurred while verifying BH mac route in ICMP neighbor')  
    
    @aetest.test
    def UnConfig_Mac_BH_Static_ND_on_VPC(self,testscript,testbed):
        node3_s1_bgw_1 = testbed.devices['node3_s1_bgw_1']
        P3_dict = AcceSW_TGEN_data
        
        try:
            ###LEAF_3_MAC_BH_ROUTE
            testscript.parameters['node3_s1_bgw_1'].configure('''
                no mac address-table static ''' + str(P3_dict['mac']) + ''' vlan '''+ str(P3_dict['vlan_id']) + ''' drop

                interface vlan ''' + str(P3_dict['vlan_id']) + '''
                  no ipv6 neighbor ''' + str(P3_dict['v6_addr']) + ''' ''' + str(P3_dict['mac']) + '''
            ''')

        except Exception as error:
            log.debug("Unable to configure static BH mac route - Encountered Exception " + str(error))
            self.errored('Exception occurred while configuring static BH mac route') 

    @aetest.test
    def VERIFY_IXIA_TRAFFIC_With_BH_Route(self, testscript):
        """ IXIA_CONFIGURATION subsection: Verify IXIA Traffic """

        # Do not perform configurations if skip_tgen_config flag is set
        #if not testscript.parameters['script_flags']['skip_tgen_config']:

        time.sleep(20)

        if ixLib.verify_traffic(99) == 1:
            log.debug("Traffic Verification Passed.Expecting traffic loss here.") 
        else:
            log.info("Traffic Verification Failed. Expecting traffic loss here.")
            self.failed("Traffic Verification failed")
        # else:
        #     self.passed(reason="Skipped TGEN Configurations as per request")
    
    @aetest.cleanup
    def cleanup(self,testscript,testbed):
        """Unconfigure qos policies"""
        node3_s1_bgw_1 = testbed.devices['node3_s1_bgw_1']
        node5_s1_leaf_1 = testbed.devices['node5_s1_leaf_1']
        node10_s1_AccessSW =testbed.devices['node10_s1_AccessSW']
        node7_s2_bgw_1 =testbed.devices['node7_s2_bgw_1']
        P3_dict = AcceSW_TGEN_data
        forwardingSysDict = FWD_SYS_dict
        try:
            # Stop Traffic from ixia
            log.info("--- Stopping Traffic ---- \n")
            log.info("Stopping Traffic")
            traffic_run_status = ixLib.stop_traffic()
            
            if traffic_run_status is not 1:
               log.info("Failed: To Stop traffic")
               return 0
            else:
                log.info("\nTraffic Stopped successfully\n")
            time.sleep(10)
            ####Remove traffic item configured
            UCAST_v6_dict = {
                            'mode'        : 'remove',
                            'stream_id'   : stream_id,
                      }
            if (ixLib.delete_traffic_item(UCAST_v6_dict))==0:
                log.debug("Traffic Remove failed")
                self.failed("Traffic Remove failed", goto=['next_tc'])
            else:
                log.info("Traffic Remove Passed")
            ###LEAF_1_MAC_BH_ROUTE
            testbed.devices['node3_s1_bgw_1'].configure(''' 
            
               no mac address-table static ''' + str(P3_dict['mac']) + ''' vlan '''+ str(P3_dict['vlan_id']) + ''' drop

                interface vlan ''' + str(P3_dict['vlan_id']) + '''
                  no ipv6 neighbor ''' + str(P3_dict['v6_addr']) + ''' ''' + str(P3_dict['mac']) + '''
                
            ''')
        except Exception as error:
            log.debug("Unable to do cleanup " + str(error))
            self.errored('Exception occurred during cleanup', goto=['next_tc']) 

class CLI_verification(nxtest.Testcase):
    ## "TC_0016_CLI_verification"
    @aetest.test
    def verifing_L2route_Mac_show_BH_flags(self,testbed):
        node3_s1_bgw_1 = testbed.devices['node3_s1_bgw_1']
        node7_s2_bgw_1 = testbed.devices['node7_s2_bgw_1']
        P3_dict = AcceSW_TGEN_data
        testbed.devices['node3_s1_bgw_1'].configure(''' 
            mac address-table static ''' + str(P3_dict['mac']) + ''' vlan '''+ str(P3_dict['vlan_id']) + ''' drop

            interface vlan ''' + str(P3_dict['vlan_id']) + '''
                ip arp ''' + str(P3_dict['v4_addr']) + ''' ''' + str(P3_dict['mac']) + '''
                ipv6 neighbor ''' + str(P3_dict['v6_addr']) + ''' ''' + str(P3_dict['mac']) + '''
         
         ''')
        
        a=testbed.devices['node3_s1_bgw_1'].execute('''  sh ip route  ''' + str(P3_dict['v4_addr']) +'''  vrf vrf-1 ''')
        m = re.search("blackhole",a)
        if m[0]:
            log.info(m[0])
        else:
            self.failed('Blackhole not found')

        b=testbed.devices['node3_s1_bgw_1'].execute(''' sh ipv6 route  ''' + str(P3_dict['v6_addr']) + '''  vrf vrf-1 ''')
        m = re.search("blackhole",b)
        if m[0]:
            log.info(m[0])
        else:
            self.failed('Blackhole not found')

        output = testbed.devices['node3_s1_bgw_1'].execute(''' sh l2route mac topology 1001 | xml |b ''' + P3_dict['mac'] +''' |en Ifindex ''')
        m= re.search("Bh",output)
        if m[0]:
            log.info(m[0])
        else:
            self.failed('Bh not fount')
        

    @aetest.test
    def Unconfig_mac_bh(self,testbed):
        node3_s1_bgw_1 = testbed.devices['node3_s1_bgw_1']
        P3_dict = AcceSW_TGEN_data
        testbed.devices['node3_s1_bgw_1'].configure(''' 
            no mac address-table static ''' + str(P3_dict['mac']) + ''' vlan '''+ str(P3_dict['vlan_id']) + ''' drop

            interface vlan ''' + str(P3_dict['vlan_id']) + '''
               no ip arp ''' + str(P3_dict['v4_addr']) + ''' ''' + str(P3_dict['mac']) + '''
               no ipv6 neighbor ''' + str(P3_dict['v6_addr']) + ''' ''' + str(P3_dict['mac']) + '''
         
         ''')

class MAC_BH_static_ARP_for_Orphan_vpc_Host_with_L2Ipv4(nxtest.Testcase):
     #"TC_0075_MAC_BH_static_ARP_for_Orphan_vpc_Host_with_L2Ipv4",
    stream_id=''
    @aetest.test
    def CONFIGURE_L2_UCAST_IXIA_TRAFFIC_H4_to_H1(self, testscript):
        """ IXIA_CONFIGURATION subsection: Configure MCAST Traffic Item """

        # Do not perform configurations if skip_tgen_config flag is set
        #if not testscript.parameters['script_flags']['skip_tgen_config']:

        IX_TP1 = testscript.parameters['IX_TP1']
        IX_TP2 = testscript.parameters['IX_TP2']
        IX_TP3 = testscript.parameters['IX_TP3']
        IX_TP4 = testscript.parameters['IX_TP4']
        P1_dict = S1_BGW1_TGEN_data
        P2_dict = S1_Leaf_TGEN_data
        P3_dict = AcceSW_TGEN_data
        P4_dict = S2_Leaf_TGEN_data
        # P1_dict = S1_BGW1_TGEN_data
        # P4_dict = testscript.parameters['S2_BGW1_TGEN_dict']

        UCAST_v4_dict = {   'src_hndl'  : IX_TP4['ipv4_handle'],
                            'dst_hndl'  : IX_TP1['ipv4_handle'],
                            'circuit'   : 'ipv4',
                            'TI_name'   : "UCAST_v4",
                            'rate_pps'  : "10000",
                            'bi_dir'    : 1,
                            'bidirectional': '0'
                        }

        UCAST_v4_TI = ixLib.configure_ixia_traffic_item_v46(UCAST_v4_dict)
            
        if UCAST_v4_TI == 0:
            log.debug("Configuring UCast L2 TI failed")
            self.errored("Configuring UCast L2 TI failed", goto=['next_tc'])
        else:
            global stream_id
            stream_id = UCAST_v4_TI
            log.info('stream_id='+stream_id)
            log.info(type(stream_id))
        # else:
        #     self.passed(reason="Skipped TGEN Configurations as per request")

    @aetest.test
    def APPLY_TTRAFFIC(self):
        """ IXIA_CONFIGURATION subsection: Verify IXIA Traffic """

        # Apply IXIA Traffic
        if ixLib.apply_traffic() == 1:
            log.info("Applying IXIA TI Passed")
        else:
            self.errored("Applying IXIA TI failed")

    
    @aetest.test
    def VERIFY_IXIA_TRAFFIC_Without_BH_Route(self, testscript):
        """ IXIA_CONFIGURATION subsection: Verify IXIA Traffic """

        # Do not perform configurations if skip_tgen_config flag is set
        #if not testscript.parameters['script_flags']['skip_tgen_config']:

        time.sleep(20)
        a=1
        for i in range (a):
            if ixLib.verify_traffic(1) == a:
                log.debug("Traffic Verification Passed.Expecting traffic loss here.") 
            else:
                log.info("Traffic Verification Failed. Expecting traffic loss here.")
                self.failed("Traffic Verification failed")
        # else:
        #     self.passed(reason="Skipped TGEN Configurations as per request")

    @aetest.test
    def Config_Mac_BH_on_Vpc_Vtep(self, testscript,testbed):
        node3_s1_bgw_1 =  testbed.devices['node3_s1_bgw_1']
        P1_dict = S1_BGW1_TGEN_data
        mac= str(P1_dict['mac'])
        vlan= str(P1_dict['vlan_id'])
        ip=str(P1_dict['v4_addr'])
        octet = 1
        no_int= int(P1_dict['no_of_ints'])
        #try:
            ###LEAF_3_MAC_BH_ROUTE
        for i in range (0,no_int):

            testbed.devices['node3_s1_bgw_1'].configure('''
            mac address-table static ''' + str(mac) + ''' vlan '''+ str(vlan) + ''' drop

            interface vlan ''' + str(vlan) + '''
                ip arp ''' + str(ip) + ''' ''' + str(mac) + '''
            ''')
            lasthex=incr_mac(mac)
            mac=mac[0:10]+lasthex
            vlan= int(vlan)+int(P1_dict['vlan_id_step'])
            ip=incr_ip(ip,octet) 

                
            
        # except Exception as error:
        #     log.debug("Unable to configure static BH mac route - Encountered Exception " + str(error))
        #     self.errored('Exception occurred while configuring static BH mac route') 

    @aetest.test
    def APPLY_TRAFFIC(self):
        """ IXIA_CONFIGURATION subsection: Verify IXIA Traffic """

        # Apply IXIA Traffic
        if ixLib.apply_traffic() == 1:
            log.info("Applying IXIA TI Passed")
        else:
            self.errored("Applying IXIA TI failed")
    
    @aetest.test
    def VERIFY_IXIA_TRAFFIC_With_BH_Route(self, testscript):
        """ IXIA_CONFIGURATION subsection: Verify IXIA Traffic """

        # Do not perform configurations if skip_tgen_config flag is set
        #if not testscript.parameters['script_flags']['skip_tgen_config']:

        time.sleep(20)
        b=0
        for i in range (b):
            if ixLib.verify_traffic(49.9) == b:
                log.debug("Traffic Verification Passed.Expecting traffic loss here.") 
                # ForkedPdb().set_trace()
            else:
                log.info("Traffic Verification Failed. ")
                self.failed("Traffic Verification failed")
            # ForkedPdb().set_trace()
            
        # else:
        #     self.passed(reason="Skipped TGEN Configurations as per request")
    
    @aetest.test
    def Verify_Traffic_Drop_on_Remote_Vtep(self,testscript,testbed):
        node5_s1_leaf_1 = testbed.devices['node5_s1_leaf_1']
        node7_s2_bgw_1 = testbed.devices['node7_s2_bgw_1']
        node9_s2_leaf_1 = testbed.devices['node9_s2_leaf_1']
        P1_dict = S1_BGW1_TGEN_data
        uplink_PO=S2_Leaf_dict['S2_Leaf_UPLINK_PO']['po_id']
        if verify_traffic_drop(node9_s2_leaf_1,uplink_PO):
            log.info('Traffic correctly dropped on  S1_Leaf')
        else:
            log.info('Traffic NOT dropped on  S1_Leaf')
            self.failed('Traffic NOT dropped on  S1_Leaf')
    
     #verifing BGP, ARP, L2FM, L2RIB, AM, HMM
    
    @aetest.test
    def Verify_BH_states_in_HMM(self, testscript,testbed):
        node3_s1_bgw_1 =testbed.devices['node3_s1_bgw_1']
        node7_s2_bgw_1 = testbed.devices['node7_s2_bgw_1']
        P1_dict = S1_BGW1_TGEN_data

        try:
            if verify_BH_in_HMM(node3_s1_bgw_1,str(P1_dict['v4_addr'])):
                log.info('Mac BH route is proper in HMM on  S1_BGW1')
            else:
                log.info('Mac BH route is improper in HMM on  S1_BGW1')
                self.failed('Mac BH route is improper in HMM on  S1_BGW1')
        
         
        except Exception as error:
            log.debug("Unable to configure static BH mac route on Remote Vtep- Encountered Exception " + str(error))
            self.errored('Exception occurred while configuring static BH mac route on Remote Vtep', goto=['cleanup'])
    @aetest.test
    def Verify_BH_states_in_AM(self, testscript,testbed):
        node3_s1_bgw_1 = testbed.devices['node3_s1_bgw_1']
        node7_s2_bgw_1 = testbed.devices['node7_s2_bgw_1']
        P1_dict = S1_BGW1_TGEN_data
        P2_dict = S1_Leaf_TGEN_data
        P3_dict = AcceSW_TGEN_data
        P4_dict = S2_Leaf_TGEN_data

        try:        
            if verify_BH_in_AM(node3_s1_bgw_1,str(P1_dict['mac']),str(P1_dict['vlan_id']),str(P1_dict['v4_addr'])):
                log.info('Mac BH route is proper in AM on  S1_BGW1')
            else:
                log.info('Mac BH route is improper in AM on  S1_BGW1')
                self.failed('Mac BH route is improper in AM on  S1_BGW1')
                   
        
        except Exception as error:
            log.debug("Unable to configure static BH mac route on Remote Vtep- Encountered Exception " + str(error))
            self.errored('Exception occurred while configuring static BH mac route on Remote Vtep', goto=['cleanup'])
    
    @aetest.test
    def Verify_BH_states_in_remote_ARP(self, testscript,testbed):
        node3_s1_bgw_1 =testbed.devices['node3_s1_bgw_1']
        node7_s2_bgw_1 = testbed.devices['node7_s2_bgw_1']
        P1_dict = S1_BGW1_TGEN_data
        try: 

            if verify_BH_in_Remote_ARP(node7_s2_bgw_1,str(P1_dict['vlan_id']),str(P1_dict['mac'])):
               log.info('Mac BH route is proper in Remote ARP on  S2_BGW1')
            else:
                log.info('Mac BH route is improper in Remote ARP on  S2_BGW1')
                self.failed('Mac BH route is improper in Remote ARP on  S2_BGW1')

        except Exception as error:
            log.debug("Unable to configure static BH mac route on Remote Vtep- Encountered Exception " + str(error))
            self.errored('Exception occurred while configuring static BH mac route on Remote Vtep')        
    @aetest.test
    def Verify_BH_states_in_local_ARP(self, testscript,testbed):
        node3_s1_bgw_1 = testbed.devices['node3_s1_bgw_1']
        node7_s2_bgw_1 = testbed.devices['node7_s2_bgw_1']
        P1_dict = S1_BGW1_TGEN_data
        P2_dict = S1_Leaf_TGEN_data
        P3_dict = AcceSW_TGEN_data
        P4_dict = S2_Leaf_TGEN_data
        try:        
            if verify_BH_in_local_ARP(node3_s1_bgw_1,str(P1_dict['vlan_id']),str(P1_dict['mac'])):
                log.info('Mac BH route is proper in Local ARP on  S1_BGW1')
            else:
                log.info('Mac BH route is improper in Local ARP on  S1_BGW1')
                self.failed('Mac BH route is improper in Local ARP on  S1_BGW1')
        
        except Exception as error:
            log.debug("Unable to configure static BH mac route on Remote Vtep- Encountered Exception " + str(error))
            self.errored('Exception occurred while configuring static BH mac route on Remote Vtep')
        
    def Verify_Mac_BH_Route_on_L2FM_BGP_L2RIB(self,testscript,testbed):
        node3_s1_bgw_1 = testbed.devices['node3_s1_bgw_1']
        node7_s2_bgw_1 = testbed.devices['node7_s2_bgw_1']
        P1_dict = S1_BGW1_TGEN_data
        
        # Verifying L2FM

        try:
            ###S1_BGW1_MAC_BH_ROUTE
            if verify_BH_route_in_L2FM(node3_s1_bgw_1,str(P1_dict['vlan_id']),str(P1_dict['mac'])):
                log.info('Mac BH route is proper in L2FM on  S1_BGw1')
            else:
                log.info('Mac BH route is improper in L2FM on  S1_BGw1')
                self.failed('Mac BH route is improper in L2FM on  S1_BGw1')

            ###S2_BGW1_MAC_BH_ROUTE Remote Vtep
            if verify_BH_route_in_L2FM(node7_s2_bgw_1,str(P1_dict['vlan_id']),str(P1_dict['mac'])):
                log.info('Mac BH route is proper in L2FM on  S2_BGw1')
            else:
                log.info('Mac BH route is improper in L2FM on  S2_BGw1')
                self.failed('Mac BH route is improper in L2FM on  S2_BGw1')

        except Exception as error:
            log.debug("Unable to verify BH mac route in L2FM - Encountered Exception " + str(error))
            self.errored('Exception occurred while verifying BH mac route in L2FM')        

        #Verifying L2RIB
        try:
            #S1_Leaf_Mac_BH_route
            if verify_L2rib_mac_ip_output(node3_s1_bgw_1,str(P1_dict['vlan_id']),str(P1_dict['mac'])):
                log.info('Mac BH route is proper in L2RIB on S1_Leaf')
            else:
                log.debug('Mac BH route is improper in L2RIB on  S1_Leaf')
                self.failed('Mac BH route is improper in L2RIB on  S1_Leaf')

            #S2_BGW1_Mac_BH_route
            if verify_L2rib_mac_ip_output(node7_s2_bgw_1,str(P1_dict['vlan_id']),str(P1_dict['mac'])):
                log.info('Mac BH route is proper in L2RIB on S2_BGW1')
            else:
                log.debug('Mac BH route is improper in L2RIB on  S2_BGW1')
                self.errored('Mac BH route is improper in L2RIB on  S2_BGW1')
        
        except Exception as error:
            log.debug("Unable to verify BH mac route in L2RIB - Encountered Exception " + str(error))
            self.errored('Exception occurred while verifying BH mac route in L2RIB')
        
        #Verifying BGP
        try:
            #S2_BGW1_Mac_BH_route
            if verify_BH_in_Remote_BGP(node7_s2_bgw_1,str(P1_dict['mac'])):
                log.info('Mac BH route is proper in BGP on S2_BGW1')
            else:
                log.debug('Mac BH route is improper in BGP on  S2_BGW1')
                self.errored('Mac BH route is improper in BGP on  S2_BGW1')

            #Access_Mac_BH_route
            if verify_BH_in_Remote_BGP(node3_s1_bgw_1,str(P1_dict['mac'])):
                log.info('Mac BH route is proper in BGP on Access')
            else:
                log.debug('Mac BH route is improper in BGP on  Access')
                self.errored('Mac BH route is improper in BGP on  Access')
        
        except Exception as error:
            log.debug("Unable to verify BH mac route in BGP - Encountered Exception " + str(error))
            self.errored('Exception occurred while verifying BH mac route in BGP', )

    @aetest.test
    def unConfig_Mac_BH_on_Vpc_Vtep(self, testscript,testbed):
        node3_s1_bgw_1 =  testbed.devices['node3_s1_bgw_1']
        P1_dict = S1_BGW1_TGEN_data
        mac= str(P1_dict['mac'])
        vlan= str(P1_dict['vlan_id'])
        ip=str(P1_dict['v4_addr'])
        octet = 1
        no_int= int(P1_dict['no_of_ints'])
        #try:
            ###LEAF_3_MAC_BH_ROUTE
        for i in range (0,no_int):

            testbed.devices['node3_s1_bgw_1'].configure('''
            no mac address-table static ''' + str(mac) + ''' vlan '''+ str(vlan) + ''' drop

            interface vlan ''' + str(vlan) + '''
                no ip arp ''' + str(ip) + ''' ''' + str(mac) + '''
            ''')
            lasthex=incr_mac(mac)
            mac=mac[0:10]+lasthex
            vlan= int(vlan)+int(P1_dict['vlan_id_step'])
            ip=incr_ip(ip,octet)   

    @aetest.test
    def VERIFY_IXIA_TRAFFIC_after_rmBH_Route(self, testscript):
        """ IXIA_CONFIGURATION subsection: Verify IXIA Traffic """

        # Do not perform configurations if skip_tgen_config flag is set
        #if not testscript.parameters['script_flags']['skip_tgen_config']:

        time.sleep(20)
        a=1
        for i in range (a):
            if ixLib.verify_traffic(1) == a:
                log.debug("Traffic Verification Passed.") 
            else:
                log.info("Traffic Verification Failed. ")
                self.failed("Traffic Verification failed")
        # else:
    
    @aetest.test
    def cleanup(self,testscript, testbed):
        """Unconfigure qos policies"""
        node3_s1_bgw_1 =  testbed.devices['node3_s1_bgw_1']
        node5_s1_leaf_1 =  testbed.devices['node5_s1_leaf_1']
        node10_s1_AccessSW =  testbed.devices['node10_s1_AccessSW']
        node7_s2_bgw_1 =  testbed.devices['node7_s2_bgw_1']
        P1_dict = S1_BGW1_TGEN_data
        forwardingSysDict = FWD_SYS_dict
        # Stop Traffic from ixia
        log.info("--- Stopping Traffic ---- \n")
        log.info("Stopping Traffic")
        traffic_run_status = ixLib.stop_traffic()
        
        if traffic_run_status is not 1:
            log.info("Failed: To Stop traffic")
            return 0
        else:
            log.info("\nTraffic Stopped successfully\n")
        time.sleep(10)
        ####Remove traffic item configured
        UCAST_v4_dict = {
                        'mode'        : 'remove',
                        'stream_id'   : stream_id,
                    }
        if (ixLib.delete_traffic_item(UCAST_v4_dict))==0:
            log.debug("Traffic Remove failed")
            self.failed("Traffic Remove failed", goto=['next_tc'])
        else:
            log.info("Traffic Remove Passed")

class MAC_BH_static_ND_for_Orphan_vpc_Host_with_L3Ipv6(nxtest.Testcase):
     #"TC_0077_MAC_BH_static_ND_for_Orphan_vpc_Host_with_L3Ipv6"
    stream_id=''
    @aetest.test
    def CONFIGURE_UCAST_L3_IXIA_TRAFFIC_H4_to_H1(self, testscript):
        """ IXIA_CONFIGURATION subsection: Configure MCAST Traffic Item """

        # Do not perform configurations if skip_tgen_config flag is set
        #if not testscript.parameters['script_flags']['skip_tgen_config']:

        IX_TP1 = testscript.parameters['IX_TP1']
        IX_TP2 = testscript.parameters['IX_TP2']
        IX_TP3 = testscript.parameters['IX_TP3']
        IX_TP4 = testscript.parameters['IX_TP4']
        P1_dict = S1_BGW1_TGEN_data
        P2_dict = S1_Leaf_TGEN_data
        P3_dict = AcceSW_TGEN_data
        P4_dict = S2_Leaf_TGEN_data


        UCAST_v6_dict = {   'src_hndl'  : testscript.parameters['port_handle_4'],
                            'dst_hndl'  : testscript.parameters['port_handle_1'],
                            'circuit'   : 'raw',
                            'TI_name'   : "UCAST_v6",
                            'rate_pps'  : "9000",
                            'bi_dir'    : 0,
                            'frame_size': '128',
                            'src_mac'   : P4_dict['mac'],
                            'dst_mac'   : '0000.000a.aaaa',
                            'srcmac_step': '00:00:00:00:00:00',
                            'dstmac_step': '00:00:00:00:00:00',
                            'srcmac_count': '1',
                            'dstmac_count': '1',
                            'vlan_id'    : P4_dict['vlan_id'],
                            'vlanid_step': '0',
                            'vlanid_count': '1',
                            'vlan_user_priority': P4_dict['vlan_user_priority'],
                            'ipv6_src_addrs' : P4_dict['v6_addr'],
                            'ipv6_dst_addrs' : P1_dict['L3_v6_dst_addr'],
                            'ipv6_src_step' : '0:0:0:0::0',
                            'ipv6_dst_step' : '0:0:0:0::0',
                            #'ip_dscp'     : P1_dict['ip_dscp'],
#                                'ip_step'    : P1_dict['v4_addr_step'],
                        }
        
        # UCAST_v6_dict = {   'src_hndl'  : IX_TP1['ipv6_handle'],
        #                        'dst_hndl'  : IX_TP3['ipv6_handle'],
        #                        'circuit'   : 'ipv6',
        #                        'TI_name'   : "UCAST_V6",
        #                        'rate_pps'  : "9000",
        #                        'bi_dir'    : 1,
        #                        'frame_size': '128',
        #                  }


        

        UCAST_v6_TI = ixLib.configure_ixia_l3_traffic_item_ipv6(UCAST_v6_dict)
            
        if UCAST_v6_TI == 0:
            log.debug("Configuring UCast TI failed")
            self.errored("Configuring UCast TI failed", goto=['cleanup'])
        else:
            global stream_id
            stream_id = UCAST_v6_TI

        # else:
        #     self.passed(reason="Skipped TGEN Configurations as per request")

    @aetest.test
    def APPLY_TRAFFIC(self):
        """ IXIA_CONFIGURATION subsection: Verify IXIA Traffic """

        # Apply IXIA Traffic
        if ixLib.apply_traffic() == 1:
            log.info("Applying IXIA TI Passed")
        else:
            self.errored("Applying IXIA TI failed")
    
    @aetest.test
    def VERIFY_IXIA_TRAFFIC_Without_BH_Route(self, testscript):
        """ IXIA_CONFIGURATION subsection: Verify IXIA Traffic """

        # Do not perform configurations if skip_tgen_config flag is set
        #if not testscript.parameters['script_flags']['skip_tgen_config']:

        time.sleep(20)
        
        a=1
        for i in range (a):
            if ixLib.verify_traffic(2) == a:
                log.debug("Traffic Verification Passed.") 
            else:
                log.info("Traffic Verification Failed.")
                # ForkedPdb().set_trace()
                self.failed("Traffic Verification failed")
        # else:
        #     self.passed(reason="Skipped TGEN Configurations as per request")

    @aetest.test
    def Config_Mac_BH_on_Vpc_Vtep(self, testscript,testbed):
        node3_s1_bgw_1 =  testbed.devices['node3_s1_bgw_1']
        P1_dict = S1_BGW1_TGEN_data
        mac= str(P1_dict['mac'])
        vlan= str(P1_dict['vlan_id'])
        ipv6=str(P1_dict['v6_addr'])
        octet = 2
        no_int= int(P1_dict['no_of_ints'])
        
        for i in range (0,no_int):
            ###LEAF_3_MAC_BH_ROUTE
            testbed.devices['node3_s1_bgw_1'].configure('''
                mac address-table static ''' + str(mac) + ''' vlan '''+ str(vlan) + ''' drop

                interface vlan ''' + str(vlan) + '''
                  ipv6 neighbor ''' + str(ipv6) + ''' ''' + str(mac) + '''
            ''')
            
            lasthex=incr_mac(mac)
            mac=mac[0:10]+lasthex
            vlan= int(vlan)+int(P1_dict['vlan_id_step'])
            ipv6=incr_ipv6(ipv6,octet) 

    @aetest.test
    def APPLY_TRAFFIC(self):
        """ IXIA_CONFIGURATION subsection: Verify IXIA Traffic """

        # Apply IXIA Traffic
        if ixLib.apply_traffic() == 1:
            log.info("Applying IXIA TI Passed")
        else:
            self.errored("Applying IXIA TI failed")
    
    @aetest.test
    def VERIFY_IXIA_TRAFFIC_With_BH_Route(self, testscript):
        """ IXIA_CONFIGURATION subsection: Verify IXIA Traffic """

        # Do not perform configurations if skip_tgen_config flag is set
        #if not testscript.parameters['script_flags']['skip_tgen_config']:

        time.sleep(20)

        b=0
        for i in range (b):
            if ixLib.verify_traffic(99) == b:
                log.debug("Traffic Verification Passed.") 
            else:
                log.info("Traffic Verification Failed.")
                # ForkedPdb().set_trace()
                self.failed("Traffic Verification failed")
        # else:
        #     self.passed(reason="Skipped TGEN Configurations as per request")
    
    @aetest.test
    def Verify_Traffic_Drop_on_Remote_Vtep(self,testscript,testbed):
        node5_s1_leaf_1 = testbed.devices['node5_s1_leaf_1']
        node7_s2_bgw_1 = testbed.devices['node7_s2_bgw_1']
        node9_s2_leaf_1 = testbed.devices['node9_s2_leaf_1']
        P1_dict = S1_BGW1_TGEN_data
        uplink_PO=S2_Leaf_dict['S2_Leaf_UPLINK_PO']['po_id']
        if verify_traffic_drop(node9_s2_leaf_1,uplink_PO):
            log.info('Traffic correctly dropped on  S1_Leaf')
        else:
            log.info('Traffic NOT dropped on  S1_Leaf')
            self.failed('Traffic NOT dropped on  S1_Leaf')
    
     #verifing BGP, ARP, L2FM, L2RIB, AM, HMM
    
    @aetest.test
    def Verify_BH_states_in_HMM(self, testscript,testbed):
        node3_s1_bgw_1 =testbed.devices['node3_s1_bgw_1']
        node4_s1_bgw_2 = testbed.devices['node4_s1_bgw_2']
        node7_s2_bgw_1 = testbed.devices['node7_s2_bgw_1']
        P1_dict = S1_BGW1_TGEN_data

        try:
            if verify_Ipv6_BH_in_HMM(node3_s1_bgw_1,str(P1_dict['v6_addr'])):
                log.info('Mac BH route is proper in HMM on  S1_BGW1')
            else:
                log.info('Mac BH route is improper in HMM on  S1_BGW1')
                self.failed('Mac BH route is improper in HMM on  S1_BGW1')
        
         
        except Exception as error:
            log.debug("Unable to configure static BH mac route on Remote Vtep- Encountered Exception " + str(error))
            self.errored('Exception occurred while configuring static BH mac route on Remote Vtep', goto=['cleanup'])
    @aetest.test
    def Verify_BH_states_in_AM(self, testscript,testbed):
        node3_s1_bgw_1 = testbed.devices['node3_s1_bgw_1']
        node4_s1_bgw_2 = testbed.devices['node4_s1_bgw_2']
        node7_s2_bgw_1 = testbed.devices['node7_s2_bgw_1']
        P1_dict = S1_BGW1_TGEN_data
        P2_dict = S1_Leaf_TGEN_data
        P3_dict = AcceSW_TGEN_data
        P4_dict = S2_Leaf_TGEN_data

        try:        
            if verify_Ipv6_BH_in_AM(node3_s1_bgw_1,str(P1_dict['mac']),str(P1_dict['vlan_id']),str(P1_dict['v6_addr'])):
                log.info('Mac BH route is proper in AM on  S1_BGW1')
            else:
                log.info('Mac BH route is improper in AM on  S1_BGW1')
                self.failed('Mac BH route is improper in AM on  S1_BGW1')
                   
        
        except Exception as error:
            log.debug("Unable to configure static BH mac route on Remote Vtep- Encountered Exception " + str(error))
            self.errored('Exception occurred while configuring static BH mac route on Remote Vtep', goto=['cleanup'])
    @aetest.test
    def Verify_Mac_BH_Route_on_L2FM_BGP_L2RIB(self,testscript,testbed):
        node3_s1_bgw_1 =testbed.devices['node3_s1_bgw_1']
        node7_s2_bgw_1 = testbed.devices['node7_s2_bgw_1']
        P1_dict = S1_BGW1_TGEN_data   
        # Verifying L2FM

        try:
            ###S1_BGW1_MAC_BH_ROUTE
            if verify_BH_route_in_L2FM(node3_s1_bgw_1,str(P1_dict['vlan_id']),str(P1_dict['mac'])):
                log.info('Mac BH route is proper in L2FM on  S1_BGw1')
            else:
                log.info('Mac BH route is improper in L2FM on  S1_BGw1')
                self.failed('Mac BH route is improper in L2FM on  S1_BGw1')

            ###S2_BGW1_MAC_BH_ROUTE Remote Vtep
            if verify_BH_route_in_L2FM(node7_s2_bgw_1,str(P1_dict['vlan_id']),str(P1_dict['mac'])):
                log.info('Mac BH route is proper in L2FM on  S2_BGw1')
            else:
                log.info('Mac BH route is improper in L2FM on  S2_BGw1')
                self.failed('Mac BH route is improper in L2FM on  S2_BGw1')

        except Exception as error:
            log.debug("Unable to verify BH mac route in L2FM - Encountered Exception " + str(error))
            self.errored('Exception occurred while verifying BH mac route in L2FM')        

        #Verifying L2RIB
        try:
            #S1_Leaf_Mac_BH_route
            if verify_L2rib_mac_ip_output(node3_s1_bgw_1,str(P1_dict['vlan_id']),str(P1_dict['mac'])):
                log.info('Mac BH route is proper in L2RIB on S1_Leaf')
            else:
                log.debug('Mac BH route is improper in L2RIB on  S1_Leaf')
                self.failed('Mac BH route is improper in L2RIB on  S1_Leaf')

            #S2_BGW1_Mac_BH_route
            if verify_L2rib_mac_ip_output(node7_s2_bgw_1,str(P1_dict['vlan_id']),str(P1_dict['mac'])):
                log.info('Mac BH route is proper in L2RIB on S2_BGW1')
            else:
                log.debug('Mac BH route is improper in L2RIB on  S2_BGW1')
                self.errored('Mac BH route is improper in L2RIB on  S2_BGW1')
        
        except Exception as error:
            log.debug("Unable to verify BH mac route in L2RIB - Encountered Exception " + str(error))
            self.errored('Exception occurred while verifying BH mac route in L2RIB')
        
        #Verifying BGP
        try:
            #S2_BGW1_Mac_BH_route
            if verify_BH_in_Remote_BGP(node7_s2_bgw_1,str(P1_dict['mac'])):
                log.info('Mac BH route is proper in BGP on S2_BGW1')
            else:
                log.debug('Mac BH route is improper in BGP on  S2_BGW1')
                self.errored('Mac BH route is improper in BGP on  S2_BGW1')

            #Access_Mac_BH_route
            if verify_BH_in_Remote_BGP(node3_s1_bgw_1,str(P1_dict['mac'])):
                log.info('Mac BH route is proper in BGP on Access')
            else:
                log.debug('Mac BH route is improper in BGP on  Access')
                self.errored('Mac BH route is improper in BGP on  Access')
        
        except Exception as error:
            log.debug("Unable to verify BH mac route in BGP - Encountered Exception " + str(error))
            self.errored('Exception occurred while verifying BH mac route in BGP')
    
    @aetest.test
    def Verify_Ipv6_icmp_neighbor(self,testbed):
        node3_s1_bgw_1 = testbed.devices['node3_s1_bgw_1']
        node7_s2_bgw_1 = testbed.devices['node7_s2_bgw_1']
        P1_dict = S1_BGW1_TGEN_data
        
        try:
            ###S1_BGW1_MAC_BH_ROUTE
            if Verify_ipv6_local_neighbor(node3_s1_bgw_1,str(P1_dict['mac']),str(P1_dict['vlan_id'])):
                log.info('Mac BH route is proper in ICMP neighbor on  S1_BGw1')
            else:
                log.info('Mac BH route is improper in ICMP neighbor on  S1_BGw1')
                self.failed('Mac BH route is improper in ICMP neighbor on  S1_BGw1')

            if verify_icmp_static_remote_neighbor(node7_s2_bgw_1,str(P1_dict['mac'])):
                log.info('Mac BH route is proper in ICMP neighbor on  S1_BGw1')
            else:
                log.info('Mac BH route is improper in ICMP neighbor on  S1_BGw1')
                self.failed('Mac BH route is improper in ICMP neighbor on  S1_BGw1')
        
        except Exception as error:
            log.debug("Unable to verify BH mac route in ICMP neighbor - Encountered Exception " + str(error))
            self.errored('Exception occurred while verifying BH mac route in ICMP neighbor')  

    @aetest.test
    def UnConfig_Mac_BH_on_Vpc_Vtep(self, testscript,testbed):
        node3_s1_bgw_1 =  testbed.devices['node3_s1_bgw_1']
        P1_dict = S1_BGW1_TGEN_data
        mac= str(P1_dict['mac'])
        vlan= str(P1_dict['vlan_id'])
        ipv6=str(P1_dict['v6_addr'])
        octet = 2
        no_int= int(P1_dict['no_of_ints'])
        
        for i in range (0,no_int):
            ###LEAF_3_MAC_BH_ROUTE
            testbed.devices['node3_s1_bgw_1'].configure('''
                no mac address-table static ''' + str(mac) + ''' vlan '''+ str(vlan) + ''' drop

                interface vlan ''' + str(vlan) + '''
                  no ipv6 neighbor ''' + str(ipv6) + ''' ''' + str(mac) + '''
            ''')
            lasthex=incr_mac(mac)
            mac=mac[0:10]+lasthex
            vlan= int(vlan)+int(P1_dict['vlan_id_step'])
            ipv6=incr_ipv6(ipv6,octet) 

    # @aetest.test
    # def APPLY_TRAFFIC(self):
    #     """ IXIA_CONFIGURATION subsection: Verify IXIA Traffic """

    #     # Apply IXIA Traffic
    #     if ixLib.apply_traffic() == 1:
    #         log.info("Applying IXIA TI Passed")
    #     else:
    #         self.errored("Applying IXIA TI failed")

    @aetest.test
    def VERIFY_IXIA_TRAFFIC_after_rmBH_Route(self, testscript):
        """ IXIA_CONFIGURATION subsection: Verify IXIA Traffic """

        # Do not perform configurations if skip_tgen_config flag is set
        #if not testscript.parameters['script_flags']['skip_tgen_config']:

        time.sleep(20)

        a=1
        for i in range (a):
            if ixLib.verify_traffic(2) == a:
                log.debug("Traffic Verification Passed.") 
            else:
                log.info("Traffic Verification Failed.")
                # ForkedPdb().set_trace()
                self.failed("Traffic Verification failed")
             
        # else:
        #     self.passed(reason="Skipped TGEN Configurations as per request")
    
    @aetest.cleanup
    def cleanup(self,testscript,testbed):
        """Unconfigure qos policies"""
        node3_s1_bgw_1 = testbed.devices['node3_s1_bgw_1']
        node5_s1_leaf_1 = testbed.devices['node5_s1_leaf_1']
        node10_s1_AccessSW =testbed.devices['node10_s1_AccessSW']
        node7_s2_bgw_1 =testbed.devices['node7_s2_bgw_1']
        P1_dict = S1_BGW1_TGEN_data
        forwardingSysDict = FWD_SYS_dict
        try:
            # Stop Traffic from ixia
            log.info("--- Stopping Traffic ---- \n")
            log.info("Stopping Traffic")
            traffic_run_status = ixLib.stop_traffic()
            
            if traffic_run_status is not 1:
               log.info("Failed: To Stop traffic")
               return 0
            else:
                log.info("\nTraffic Stopped successfully\n")
            time.sleep(10)
            ####Remove traffic item configured
            UCAST_v6_dict = {
                            'mode'        : 'remove',
                            'stream_id'   : stream_id,
                      }
            if (ixLib.delete_traffic_item(UCAST_v6_dict))==0:
                log.debug("Traffic Remove failed")
                self.failed("Traffic Remove failed", goto=['next_tc'])
            else:
                log.info("Traffic Remove Passed")
            ###LEAF_1_MAC_BH_ROUTE
            testbed.devices['node3_s1_bgw_1'].configure(''' 
            
               no mac address-table static ''' + str(P1_dict['mac']) + ''' vlan '''+ str(P1_dict['vlan_id']) + ''' drop

                interface vlan ''' + str(P1_dict['vlan_id']) + '''
                  no ipv6 neighbor ''' + str(P1_dict['v6_addr']) + ''' ''' + str(P1_dict['mac']) + '''
                
            ''')
        except Exception as error:
            log.debug("Unable to do cleanup " + str(error))
            self.errored('Exception occurred during cleanup', goto=['next_tc']) 

class Prefix_BH_route_for_Orphan_vpc_Host_with_L3Ipv4(nxtest.Testcase):
    #"TC_0076_Prefix_BH_route_for_Orphan_vpc_Host_with_L3Ipv4"
    stream_id=''
    @aetest.test
    def CONFIGURE_UCAST_L3_IXIA_TRAFFIC_H4_to_H2(self, testscript):
        """ IXIA_CONFIGURATION subsection: Configure MCAST Traffic Item """

        # Do not perform configurations if skip_tgen_config flag is set
        #if not testscript.parameters['script_flags']['skip_tgen_config']:

        IX_TP1 = testscript.parameters['IX_TP1']
        IX_TP2 = testscript.parameters['IX_TP2']
        IX_TP3 = testscript.parameters['IX_TP3']
        IX_TP4 = testscript.parameters['IX_TP4']
        P1_dict = S1_BGW1_TGEN_data
        P2_dict = S1_Leaf_TGEN_data
        P3_dict = AcceSW_TGEN_data
        P4_dict = S2_Leaf_TGEN_data


        UCAST_v4_dict = {   'src_hndl'  : IX_TP4['port_handle'],
                            'dst_hndl'  : IX_TP1['port_handle'],
                            'circuit'   : 'raw',
                            'TI_name'   : "UCAST_v4",
                            'rate_pps'  : "9000",
                            'bi_dir'    : 0,
                            'frame_size': '128',
                            'src_mac'   : P4_dict['mac'],
                            'dst_mac'   : '0000.000a.aaaa',
                            'srcmac_step': '00:00:00:00:00:00',
                            'dstmac_step': '00:00:00:00:00:00',
                            'srcmac_count': '1',
                            'dstmac_count': '1',
                            'vlan_id'    : P4_dict['vlan_id'],
                            'vlanid_step': '0',
                            'vlanid_count': '2',
                            'vlan_user_priority': P4_dict['vlan_user_priority'],
                            'ip_src_addrs' : P4_dict['v4_addr'],
                            'ip_dst_addrs' : P1_dict['L3_dst_addr'],
                            'ip_src_step' : '0.0.0.0',
                            'ip_dscp'     : P4_dict['ip_dscp'],
                            'ip_dst_step' : '0.0.0.0',
#                                'ip_step'    : P1_dict['v4_addr_step'],
                        }

        UCAST_v4_TI = ixLib.configure_ixia_l3_traffic_item(UCAST_v4_dict)
            
        if UCAST_v4_TI == 0:
            log.debug("Configuring UCast TI failed")
            self.errored("Configuring UCast TI failed", goto=['cleanup'])
        else:
            global stream_id
            stream_id = UCAST_v4_TI

        # else:
        #     self.passed(reason="Skipped TGEN Configurations as per request")
    @aetest.test
    def APPLY_TRAFFIC(self):
        """ IXIA_CONFIGURATION subsection: Verify IXIA Traffic """

        # Apply IXIA Traffic
        if ixLib.apply_traffic() == 1:
            log.info("Applying IXIA TI Passed")
        else:
            self.errored("Applying IXIA TI failed")

    @aetest.test
    def VERIFY_IXIA_TRAFFIC_Without_BH_Route(self, testscript):
        """ IXIA_CONFIGURATION subsection: Verify IXIA Traffic """

        # Do not perform configurations if skip_tgen_config flag is set
        #if not testscript.parameters['script_flags']['skip_tgen_config']:

        time.sleep(20)
        a=1
        for i in range (a):
            if ixLib.verify_traffic(1) == a:
                log.debug("Traffic Verification Passed.Expecting traffic loss here.") 
            else:
                log.info("Traffic Verification Failed.")
                # ForkedPdb().set_trace()
                self.failed("Traffic Verification failed")
        # else:
        #     self.passed(reason="Skipped TGEN Configurations as per request")


    @aetest.test
    def Configure_Type5_route_with_Null_NH(self,testbed):
        node3_s1_bgw_1 = testbed.devices['node3_s1_bgw_1']
        node7_s2_bgw_1 =testbed.devices['node7_s2_bgw_1']
        P1_dict = S1_BGW1_TGEN_data
        mac= str(P1_dict['mac'])
        vlan= str(P1_dict['vlan_id'])
        ip=str(P1_dict['v4_addr'])
        octet = 1
        no_int= int(P1_dict['no_of_ints'])
          # Get CS DCI TGEN Interface Name
        # node3_tgen_interface = None
        # for interface in testbed.devices[node3_s1_bgw_1].interfaces:
        #     if testbed.devices[node3_s1_bgw_1].interfaces[interface].alias == 'nd03_tgen_1_1':
        #         node3_tgen_interface = interface
        #         log.info("S1_bgw1 - TGEN Interface : "+str(interface)) 

        testbed.devices['node3_s1_bgw_1'].configure(''' 
            
            mac address-table static ''' + str(mac) + ''' vlan '''+ str(vlan) + ''' drop

            interface eth''' + testbed.devices['node3_s1_bgw_1'].interfaces['Ethernet1/20'].intf + '''
                no switchport
                ip address ''' + str(ip) +'''/16
            
            vrf context vrf-1
                vni 3003001
                ip route ''' + str(ip) +'''/32 Null0 tag 12345
                ip pim ssm range 232.0.0.0/8
                rd auto
                address-family ipv4 unicast
                    route-target both auto
                    route-target both auto evpn

            route-map BH-Evpn-tx permit 10
                match tag 12345
                set community blackhole
        
            router bgp 200
                vrf vrf-1
                    address-family ipv4 unicast
                    advertise l2vpn evpn
                    redistribute direct route-map connect
                    redistribute static route-map  BH-Evpn-tx     
                
        ''')
        
        
        testbed.devices['node7_s2_bgw_1'].configure(''' 

            ip community-list standard BH-Evpn-Tx seq 10 permit blackhole 
        
            route-map rx-BH-Evpn-rt permit 10
                match community Blackhole 
                set weight 65535 

            route-map rx-BH-Evpn-rt permit 20

            router bgp 300
                neighbor 50.50.50.50
                    address-family l2vpn evpn
                    send-community
                    send-community extended
                    route-map rx-BH-Evpn-rt in
        ''')
       


    @aetest.test
    def APPLY_TRAFFIC(self):
        """ IXIA_CONFIGURATION subsection: Verify IXIA Traffic """

        # Apply IXIA Traffic
        if ixLib.apply_traffic() == 1:
            log.info("Applying IXIA TI Passed")
        else:
            self.errored("Applying IXIA TI failed")

    @aetest.test
    def VERIFY_IXIA_TRAFFIC_With_BH_Route(self, testscript):
        """ IXIA_CONFIGURATION subsection: Verify IXIA Traffic """

        # Do not perform configurations if skip_tgen_config flag is set
        #if not testscript.parameters['script_flags']['skip_tgen_config']:

        time.sleep(20)
        b=0
        for i in range (b):
            if ixLib.verify_traffic(99) == b:
                log.debug("Traffic Verification Passed.Expecting traffic loss here.")
                #ForkedPdb().set_trace()  
            else:
                log.info("Traffic Verification Failed.")
                # ForkedPdb().set_trace()
                self.failed("Traffic Verification failed")
        # else:
        #     self.passed(reason="Skipped TGEN Configurations as per request")

    @aetest.test
    def Verify_Traffic_Drop_on_Remote_Vtep(self,testscript,testbed):
        node5_s1_leaf_1 = testbed.devices['node5_s1_leaf_1']
        node9_s2_leaf_1 = testbed.devices['node9_s2_leaf_1']
        node3_s1_bgw_1 = testbed.devices['node3_s1_bgw_1']
        P1_dict = S1_BGW1_TGEN_data
        
        uplink_PO=S2_Leaf_dict['S2_Leaf_UPLINK_PO']['po_id']
        if verify_traffic_drop(node9_s2_leaf_1,uplink_PO):
            log.info('Traffic correctly dropped on  S2_Leaf')
            #ForkedPdb().set_trace() 
        else:
            log.info('Traffic NOT dropped on  S2_Leaf')
            self.failed('Traffic NOT dropped on  S2_Leaf')   
            
    @aetest.test
    def verify_prefix_route(self,testbed):
        node7_s2_bgw_1 =testbed.devices['node7_s2_bgw_1']
        P1_dict = S1_BGW1_TGEN_data
        output=node7_s2_bgw_1.execute(''' sh bgp l2vpn evpn ''' + P1_dict['v4_addr'] )
        a = re.search('Community: blackhole', output)
        if a[0] == "Community: blackhole":
            log.info('verified blackhole on S2_BGW1')
            self.passed('verified blackhole on S2_BGW1')
        else:
            self.failed('not verified blackhole on S2_BGW1')

    @aetest.test
    def Withdraw_Prefix_Null_route(self,testbed):
        node3_s1_bgw_1 = testbed.devices['node3_s1_bgw_1']
        node7_s2_bgw_1 =testbed.devices['node7_s2_bgw_1']
        P1_dict = S1_BGW1_TGEN_data
        mac= str(P1_dict['mac'])
        vlan= str(P1_dict['vlan_id'])
        ip=str(P1_dict['v4_addr'])
        octet = 1
        no_int= int(P1_dict['no_of_ints'])
          # Get CS DCI TGEN Interface Name
        # node3_tgen_interface = None
        # for interface in testbed.devices[node3_s1_bgw_1].interfaces:
        #     if testbed.devices[node3_s1_bgw_1].interfaces[interface].alias == 'nd03_tgen_1_1':
        #         node3_tgen_interface = interface
        #         log.info("S1_bgw1 - TGEN Interface : "+str(interface)) 
        
        testbed.devices['node3_s1_bgw_1'].configure(''' 
            
            no mac address-table static ''' + str(mac) + ''' vlan '''+ str(vlan) + ''' drop

            interface eth''' + testbed.devices['node3_s1_bgw_1'].interfaces['Ethernet1/20'].intf + '''
               no ip address ''' + str(ip)+'''/16
               switchport
               switchport mode trunk
               switchport trunk allowed vlan 1001,1076
               spanning-tree port type edge trunk
               spanning-tree bpdufilter enable
            
            vrf context vrf-1
                vni 3003001
               no ip route ''' + str(ip)+'''/32 Null0 tag 12345
               no ip pim ssm range 232.0.0.0/8
                rd auto
                address-family ipv4 unicast
                    route-target both auto
                    route-target both auto evpn

            no route-map BH-Evpn-tx permit 10
        
            router bgp 200
                vrf vrf-1
                    address-family ipv4 unicast
                    advertise l2vpn evpn
                    no redistribute direct route-map connect
                    no redistribute static route-map  BH-Evpn-tx     
                
        ''')
       
        
        testbed.devices['node7_s2_bgw_1'].configure(''' 

            no ip community-list standard BH-Evpn-Tx seq 10 permit blackhole 
        
            no route-map rx-BH-Evpn-rt permit 10

            no route-map rx-BH-Evpn-rt permit 20

            router bgp 300
                neighbor 50.50.50.50
                    address-family l2vpn evpn
                    send-community
                    send-community extended
                   no route-map rx-BH-Evpn-rt in
        ''')
        
        
    @aetest.test
    def APPLY_TRAFFIC(self):
        """ IXIA_CONFIGURATION subsection: Verify IXIA Traffic """

        # Apply IXIA Traffic
        if ixLib.apply_traffic() == 1:
            log.info("Applying IXIA TI Passed")
        else:
            self.errored("Applying IXIA TI failed")

    @aetest.test
    def VERIFY_IXIA_TRAFFIC_Without_BH_Route(self, testscript):
        """ IXIA_CONFIGURATION subsection: Verify IXIA Traffic """

        # Do not perform configurations if skip_tgen_config flag is set
        #if not testscript.parameters['script_flags']['skip_tgen_config']:

        time.sleep(20)
        a=1
        for i in range (a):
            if ixLib.verify_traffic(1) == a:
                log.debug("Traffic Verification Passed.Expecting traffic loss here.") 
            else:
                log.info("Traffic Verification Failed.")
                # ForkedPdb().set_trace()
                self.failed("Traffic Verification failed")
        # else:
        #     self.passed(reason="Skipped TGEN Configurations as per request")

    @aetest.cleanup
    def cleanup(self,testscript,testbed):
        """Unconfigure qos policies"""
        node3_s1_bgw_1 = testbed.devices['node3_s1_bgw_1']
        node5_s1_leaf_1 = testbed.devices['node5_s1_leaf_1']
        node10_s1_AccessSW =testbed.devices['node10_s1_AccessSW']
        node7_s2_bgw_1 =testbed.devices['node7_s2_bgw_1']
        P1_dict = S1_BGW1_TGEN_data
        forwardingSysDict = FWD_SYS_dict
        try:
            # Stop Traffic from ixia
            log.info("--- Stopping Traffic ---- \n")
            log.info("Stopping Traffic")
            traffic_run_status = ixLib.stop_traffic()
            
            if traffic_run_status is not 1:
               log.info("Failed: To Stop traffic")
               return 0
            else:
                log.info("\nTraffic Stopped successfully\n")
            time.sleep(10)
            ####Remove traffic item configured
            UCAST_v4_dict = {
                            'mode'        : 'remove',
                            'stream_id'   : stream_id,
                      }
            if (ixLib.delete_traffic_item(UCAST_v4_dict))==0:
                log.debug("Traffic Remove failed")
                self.failed("Traffic Remove failed", goto=['next_tc'])
            else:
                log.info("Traffic Remove Passed")
            ###LEAF_1_MAC_BH_ROUTE
        except Exception as error:
            log.debug("Unable to do cleanup " + str(error))
            self.errored('Exception occurred during cleanup', goto=['next_tc']) 

class Prefix_BH_route_for_Orphan_vpc_Host_with_L3Ipv6(nxtest.Testcase):
    #"TC_0078_Prefix_BH_route_for_Orphan_vpc_Host_with_L3Ipv6"
    stream_id=''
    @aetest.test
    def CONFIGURE_UCAST_L3_IXIA_TRAFFIC_H4_to_H2(self, testscript):
        """ IXIA_CONFIGURATION subsection: Configure MCAST Traffic Item """

        # Do not perform configurations if skip_tgen_config flag is set
        #if not testscript.parameters['script_flags']['skip_tgen_config']:

        IX_TP1 = testscript.parameters['IX_TP1']
        IX_TP2 = testscript.parameters['IX_TP2']
        IX_TP3 = testscript.parameters['IX_TP3']
        IX_TP4 = testscript.parameters['IX_TP4']
        P1_dict = S1_BGW1_TGEN_data
        P2_dict = S1_Leaf_TGEN_data
        P3_dict = AcceSW_TGEN_data
        P4_dict = S2_Leaf_TGEN_data


        UCAST_v6_dict = {   'src_hndl'  : testscript.parameters['port_handle_4'],
                            'dst_hndl'  : testscript.parameters['port_handle_1'],
                            'circuit'   : 'raw',
                            'TI_name'   : "UCAST_v6",
                            'rate_pps'  : "9000",
                            'bi_dir'    : 0,
                            'frame_size': '128',
                            'src_mac'   : P4_dict['mac'],
                            'dst_mac'   : '0000.000a.aaaa',
                            'srcmac_step': '00:00:00:00:00:00',
                            'dstmac_step': '00:00:00:00:00:00',
                            'srcmac_count': '1',
                            'dstmac_count': '1',
                            'vlan_id'    : P4_dict['vlan_id'],
                            'vlanid_step': '0',
                            'vlanid_count': '1',
                            'vlan_user_priority': P4_dict['vlan_user_priority'],
                            'ipv6_src_addrs' : P4_dict['v6_addr'],
                            'ipv6_dst_addrs' : P1_dict['L3_v6_dst_addr'],
                            'ipv6_src_step' : '0:0:0:0::0',
                            'ipv6_dst_step' : '0:0:0:0::0',
                            #'ip_dscp'     : P1_dict['ip_dscp'],
#                                'ip_step'    : P1_dict['v4_addr_step'],
                        }
        
        # UCAST_v6_dict = {   'src_hndl'  : IX_TP1['ipv6_handle'],
        #                        'dst_hndl'  : IX_TP3['ipv6_handle'],
        #                        'circuit'   : 'ipv6',
        #                        'TI_name'   : "UCAST_V6",
        #                        'rate_pps'  : "9000",
        #                        'bi_dir'    : 1,
        #                        'frame_size': '128',
        #                  }


        

        UCAST_v6_TI = ixLib.configure_ixia_l3_traffic_item_ipv6(UCAST_v6_dict)
            
        if UCAST_v6_TI == 0:
            log.debug("Configuring UCast TI failed")
            self.errored("Configuring UCast TI failed", goto=['cleanup'])
        else:
            global stream_id
            stream_id = UCAST_v6_TI

        # else:
        #     self.passed(reason="Skipped TGEN Configurations as per request")
    @aetest.test
    def APPLY_TRAFFIC(self):
        """ IXIA_CONFIGURATION subsection: Verify IXIA Traffic """

        # Apply IXIA Traffic
        if ixLib.apply_traffic() == 1:
            log.info("Applying IXIA TI Passed")
        else:
            self.errored("Applying IXIA TI failed")

    @aetest.test
    def VERIFY_IXIA_TRAFFIC_Without_BH_Route(self, testscript):
        """ IXIA_CONFIGURATION subsection: Verify IXIA Traffic """

        # Do not perform configurations if skip_tgen_config flag is set
        #if not testscript.parameters['script_flags']['skip_tgen_config']:

        time.sleep(20)
        a=1
        for i in range (a):
            if ixLib.verify_traffic(1) == a:
                log.debug("Traffic Verification Passed.Expecting traffic loss here.") 
            else:
                log.info("Traffic Verification Failed.")
                # ForkedPdb().set_trace()
                self.failed("Traffic Verification failed")
        # else:
        #     self.passed(reason="Skipped TGEN Configurations as per request")
    
    @aetest.test
    def Configure_Type5_route_with_Null_NH(self,testbed):
        node3_s1_bgw_1 = testbed.devices['node3_s1_bgw_1']
        node7_s2_bgw_1 =testbed.devices['node7_s2_bgw_1']
        P1_dict = S1_BGW1_TGEN_data
        mac= str(P1_dict['mac'])
        vlan= str(P1_dict['vlan_id'])
        ipv6=str(P1_dict['v6_addr'])
        octet = 1
        no_int= int(P1_dict['no_of_ints'])
          # Get CS DCI TGEN Interface Name
        # node3_tgen_interface = None
        # for interface in testbed.devices[node3_s1_bgw_1].interfaces:
        #     if testbed.devices[node3_s1_bgw_1].interfaces[interface].alias == 'nd03_tgen_1_1':
        #         node3_tgen_interface = interface
        #         log.info("S1_bgw1 - TGEN Interface : "+str(interface)) 

        testbed.devices['node3_s1_bgw_1'].configure(''' 
            
            mac address-table static ''' + str(mac) + ''' vlan '''+ str(vlan) + ''' drop

            interface eth''' + testbed.devices['node3_s1_bgw_1'].interfaces['Ethernet1/20'].intf + '''
                no switchport
                ipv6 address ''' + str(ipv6) +'''/64 tag 12345
            
            vrf context vrf-1
                vni 3003001
                ipv6 route ''' + str(ipv6) +'''/128 Null0 tag 12345
                rd auto
                address-family ipv6 unicast
                    route-target both auto
                    route-target both auto evpn

            route-map BH-Evpn-tx permit 10
                match tag 12345
                set community blackhole
        
            router bgp 200
                vrf vrf-1
                    address-family ipv6 unicast
                    advertise l2vpn evpn
                    redistribute direct route-map connect
                    redistribute static route-map  BH-Evpn-tx     
                
        ''')
        
        
        testbed.devices['node7_s2_bgw_1'].configure(''' 

            ip community-list standard BH-Evpn-Tx seq 10 permit blackhole 
        
            route-map rx-BH-Evpn-rt permit 10
                match community Blackhole 
                set weight 65535 

            route-map rx-BH-Evpn-rt permit 20

            router bgp 300
                neighbor 50.50.50.50
                    address-family l2vpn evpn
                    send-community
                    send-community extended
                    route-map rx-BH-Evpn-rt in
        ''')
        


    @aetest.test
    def APPLY_TRAFFIC(self):
        """ IXIA_CONFIGURATION subsection: Verify IXIA Traffic """

        # Apply IXIA Traffic
        if ixLib.apply_traffic() == 1:
            log.info("Applying IXIA TI Passed")
        else:
            self.errored("Applying IXIA TI failed")

    @aetest.test
    def VERIFY_IXIA_TRAFFIC_With_BH_Route(self, testscript):
        """ IXIA_CONFIGURATION subsection: Verify IXIA Traffic """

        # Do not perform configurations if skip_tgen_config flag is set
        #if not testscript.parameters['script_flags']['skip_tgen_config']:

        time.sleep(20)
        b=0
        for i in range (b):
            if ixLib.verify_traffic(99) == b:
                log.debug("Traffic Verification Passed.Expecting traffic loss here.")  
            else:
                log.info("Traffic Verification Failed.")
                # ForkedPdb().set_trace()
                self.failed("Traffic Verification failed")
        # else:
        #     self.passed(reason="Skipped TGEN Configurations as per request")

    @aetest.test
    def Verify_Traffic_Drop_on_Remote_Vtep(self,testscript,testbed):
        node5_s1_leaf_1 = testbed.devices['node5_s1_leaf_1']
        node9_s2_leaf_1 = testbed.devices['node9_s2_leaf_1']
        node3_s1_bgw_1 = testbed.devices['node3_s1_bgw_1']
        P1_dict = S1_BGW1_TGEN_data
        
        uplink_PO=S2_Leaf_dict['S2_Leaf_UPLINK_PO']['po_id']
        if verify_traffic_drop(node9_s2_leaf_1,uplink_PO):
            log.info('Traffic correctly dropped on  S2_Leaf')
            #ForkedPdb().set_trace() 
        else:
            log.info('Traffic NOT dropped on  S2_Leaf')
            self.failed('Traffic NOT dropped on  S2_Leaf')   
            
    @aetest.test
    def verify_prefix_route(self,testbed):
        node7_s2_bgw_1 =testbed.devices['node7_s2_bgw_1']
        P1_dict = S1_BGW1_TGEN_data
        output=node7_s2_bgw_1.execute(''' sh bgp l2vpn evpn ''' + P1_dict['v6_addr'] )
        m = re.search('Community: blackhole', output)
        if m[0] == "Community: blackhole":
            log.info('verified blackhole on S2_BGW1')
            self.passed('verified blackhole on S2_BGW1')
        else:
            self.failed('not verified blackhole on S2_BGW1')

    @aetest.test
    def Withdraw_Prefix_Null_route(self,testbed):
        node3_s1_bgw_1 = testbed.devices['node3_s1_bgw_1']
        node7_s2_bgw_1 =testbed.devices['node7_s2_bgw_1']
        P1_dict = S1_BGW1_TGEN_data
        mac= str(P1_dict['mac'])
        vlan= str(P1_dict['vlan_id'])
        ipv6=str(P1_dict['v6_addr'])
        octet = 1
        no_int= int(P1_dict['no_of_ints'])
          # Get CS DCI TGEN Interface Name
        # node3_tgen_interface = None
        # for interface in testbed.devices[node3_s1_bgw_1].interfaces:
        #     if testbed.devices[node3_s1_bgw_1].interfaces[interface].alias == 'nd03_tgen_1_1':
        #         node3_tgen_interface = interface
        #         log.info("S1_bgw1 - TGEN Interface : "+str(interface)) 
        
        testbed.devices['node3_s1_bgw_1'].configure(''' 
            
            no mac address-table static ''' + str(mac) + ''' vlan '''+ str(vlan) + ''' drop

            interface eth''' + testbed.devices['node3_s1_bgw_1'].interfaces['Ethernet1/20'].intf + '''
               no ipv6 address ''' + str(ipv6)+'''/64
               switchport
               switchport mode trunk
               switchport trunk allowed vlan 1001,1076
               spanning-tree port type edge trunk
               spanning-tree bpdufilter enable
            
            vrf context vrf-1
                vni 3003001
               no ipv6 route ''' + str(ipv6)+'''/128 Null0 tag 12345
                rd auto
                address-family ipv4 unicast
                    route-target both auto
                    route-target both auto evpn

            no route-map BH-Evpn-tx permit 10
        
            router bgp 200
                vrf vrf-1
                    address-family ipv4 unicast
                    advertise l2vpn evpn
                    no redistribute direct route-map connect
                    no redistribute static route-map  BH-Evpn-tx     
                
            ''')
      
        
        testbed.devices['node7_s2_bgw_1'].configure(''' 

            no ip community-list standard BH-Evpn-Tx seq 10 permit blackhole 
        
            no route-map rx-BH-Evpn-rt permit 10

            no route-map rx-BH-Evpn-rt permit 20

            router bgp 300
                neighbor 50.50.50.50
                    address-family l2vpn evpn
                    send-community
                    send-community extended
                   no route-map rx-BH-Evpn-rt in
            ''')
       
        
    @aetest.test
    def APPLY_TRAFFIC(self):
        """ IXIA_CONFIGURATION subsection: Verify IXIA Traffic """

        # Apply IXIA Traffic
        if ixLib.apply_traffic() == 1:
            log.info("Applying IXIA TI Passed")
        else:
            self.errored("Applying IXIA TI failed")

    @aetest.test
    def VERIFY_IXIA_TRAFFIC_Without_BH_Route(self, testscript):
        """ IXIA_CONFIGURATION subsection: Verify IXIA Traffic """

        # Do not perform configurations if skip_tgen_config flag is set
        #if not testscript.parameters['script_flags']['skip_tgen_config']:

        time.sleep(20)
        a=1
        for i in range (a):
            if ixLib.verify_traffic(1) == a:
                log.debug("Traffic Verification Passed.Expecting traffic loss here.") 
            else:
                log.info("Traffic Verification Failed. ")
                # ForkedPdb().set_trace()
                self.failed("Traffic Verification failed")
        # else:
        #     self.passed(reason="Skipped TGEN Configurations as per request")

    @aetest.cleanup
    def cleanup(self,testscript,testbed):
        """Unconfigure qos policies"""
        node3_s1_bgw_1 = testbed.devices['node3_s1_bgw_1']
        node5_s1_leaf_1 = testbed.devices['node5_s1_leaf_1']
        node10_s1_AccessSW =testbed.devices['node10_s1_AccessSW']
        node7_s2_bgw_1 =testbed.devices['node7_s2_bgw_1']
        P1_dict = S1_BGW1_TGEN_data
        forwardingSysDict = FWD_SYS_dict
        try:
            # Stop Traffic from ixia
            log.info("--- Stopping Traffic ---- \n")
            log.info("Stopping Traffic")
            traffic_run_status = ixLib.stop_traffic()
            
            if traffic_run_status is not 1:
               log.info("Failed: To Stop traffic")
               return 0
            else:
                log.info("\nTraffic Stopped successfully\n")
            time.sleep(10)
            ####Remove traffic item configured
            UCAST_v4_dict = {
                            'mode'        : 'remove',
                            'stream_id'   : stream_id,
                      }
            if (ixLib.delete_traffic_item(UCAST_v4_dict))==0:
                log.debug("Traffic Remove failed")
                self.failed("Traffic Remove failed", goto=['next_tc'])
            else:
                log.info("Traffic Remove Passed")
            ###LEAF_1_MAC_BH_ROUTE
        except Exception as error:
            log.debug("Unable to do cleanup " + str(error))
            self.errored('Exception occurred during cleanup', goto=['next_tc']) 

# class Cmds_ouputs(nxtest.Testcase):
#     @aetest.test
#     def Verify_New_icmpv6_CLIs(self,testbed):
#         node3_s1_bgw_1 = testbed.devices['node3_s1_bgw_1']
#         node5_s1_leaf_1 = testbed.devices['node5_s1_leaf_1']
#         node10_s1_AccessSW =testbed.devices['node10_s1_AccessSW']
#         node7_s2_bgw_1 =testbed.devices['node7_s2_bgw_1']
#         P3_dict = AcceSW_TGEN_data

#         testbed.devices['node3_s1_bgw_1'].configure('''
#          mac address-table static ''' + str(P3_dict['mac']) + ''' vlan '''+ str(P3_dict['vlan_id']) + ''' drop

#                 interface vlan ''' + str(P3_dict['vlan_id']) + '''
#                   ip arp ''' + str(P3_dict['v4_addr']) + ''' ''' + str(P3_dict['mac']) + '''
#                   ipv6 neighbor ''' + str(P3_dict['v6_addr']) + ''' ''' + str(P3_dict['mac']) + '''
#          ''')

#         a = testbed.devices['node5_s1_leaf_1'].execute(''' sh ipv6 icmp neighbor static remote ''')
#         print(a)

#         a = testbed.devices['node5_s1_leaf_1'].execute(''' sh ipv6 icmp neighbor static remote | json''')
#         print(a)

#         a = testbed.devices['node5_s1_leaf_1'].execute(''' sh ipv6 icmp neighbor static remote | xml''')
#         print(a)
        
#         b = testbed.devices['node5_s1_leaf_1'].execute(''' show ipv6 icmp global traffic ''')
#         print(b)

#         b = testbed.devices['node3_s1_bgw_1'].execute(''' show ipv6 icmp global traffic ''')
#         print(b)

#         b = testbed.devices['node3_s1_bgw_1'].execute(''' show ipv6 icmp global traffic |json''')
#         print(b)

#         b = testbed.devices['node3_s1_bgw_1'].execute(''' show ipv6 icmp global traffic | xml ''')
#         print(b)

#         c = testbed.devices['node5_s1_leaf_1'].execute(''' show ip arp static remote vrf all ''')
#         print(c)

#         c = testbed.devices['node5_s1_leaf_1'].execute(''' show ip arp static remote vrf all |json''')
#         print(c)
        
#         c = testbed.devices['node5_s1_leaf_1'].execute(''' show ip arp static remote vrf all |xml ''')
#         print(c)

class Arp_cli_should_show_BH_flags(nxtest.Testcase):

    #"TC_0073_Arp_cli_should_show_BH_flags"
    @aetest.test
    def vrify_arp_cli(self,testbed):
        node3_s1_bgw_1 = testbed.devices['node3_s1_bgw_1']
        node7_s2_bgw_1 =testbed.devices['node7_s2_bgw_1']
        node4_s1_bgw_2 =testbed.devices['node4_s1_bgw_2']
        P3_dict = AcceSW_TGEN_data

        testbed.devices['node3_s1_bgw_1'].configure('''
            mac address-table static ''' + str(P3_dict['mac']) + ''' vlan '''+ str(P3_dict['vlan_id']) + ''' drop

                interface vlan ''' + str(P3_dict['vlan_id']) + '''
                  ip arp ''' + str(P3_dict['v4_addr']) + ''' ''' + str(P3_dict['mac']) + '''
         ''')
        testbed.devices['node4_s1_bgw_2'].configure('''
            mac address-table static ''' + str(P3_dict['mac']) + ''' vlan '''+ str(P3_dict['vlan_id']) + ''' drop

                interface vlan ''' + str(P3_dict['vlan_id']) + '''
                  ip arp ''' + str(P3_dict['v4_addr']) + ''' ''' + str(P3_dict['mac']) + '''
         ''')

        try:
            c = testbed.devices['node5_s1_leaf_1'].execute(''' show ip arp static remote vrf all ''')
            if re.search("Bh",c):
                log.info('Arp cli showing Bh route')
                self.passed('Arp cli verified')
            else:
                self.failed('Arp cli not verified')

        except Exception as error:
            log.debug("Unable to do cleanup " + str(error))
            self.errored('Exception occurred vrifying Arp CLI') 

    @aetest.test
    def Verify_Arp_cli_in_json(self,testbed):
        try:
            
            a = testbed.devices['node5_s1_leaf_1'].execute(''' show ip arp static remote vrf all |json''')
            if re.search("Bh",a):
                log.info('Arp cli showing Bh route')
                self.passed('Arp cli verified')
            else:
                self.failed('Arp cli not verified')
        except Exception as error:
            log.debug("Unable to do cleanup " + str(error))
            self.errored('Exception occurred verifing Arp CLI') 

    @aetest.test
    def Verify_Arp_cli_in_xml(self,testbed):
        try:
        
            b = testbed.devices['node5_s1_leaf_1'].execute(''' show ip arp static remote vrf all |xml''')
            if re.search("Bh",b):
                log.info('Arp cli showing Bh route')
                self.passed('Arp cli verified')
            else:
                self.failed('Arp cli not verified')
        
        except Exception as error:
            log.debug("Unable to do cleanup " + str(error))
            self.errored('Exception occurred verifing Arp CLI') 

    
    @aetest.test
    def Unconfig_verify_arp_cli(self,testbed):
        node3_s1_bgw_1 = testbed.devices['node3_s1_bgw_1']
        node7_s2_bgw_1 =testbed.devices['node7_s2_bgw_1']
        P3_dict = AcceSW_TGEN_data

        testbed.devices['node3_s1_bgw_1'].configure('''
            no mac address-table static ''' + str(P3_dict['mac']) + ''' vlan '''+ str(P3_dict['vlan_id']) + ''' drop

                interface vlan ''' + str(P3_dict['vlan_id']) + '''
                  no ip arp ''' + str(P3_dict['v4_addr']) + ''' ''' + str(P3_dict['mac']) + '''
         ''')
        testbed.devices['node4_s1_bgw_2'].configure('''
            no mac address-table static ''' + str(P3_dict['mac']) + ''' vlan '''+ str(P3_dict['vlan_id']) + ''' drop

                interface vlan ''' + str(P3_dict['vlan_id']) + '''
                  no ip arp ''' + str(P3_dict['v4_addr']) + ''' ''' + str(P3_dict['mac']) + '''
         ''')

class Verify_New_icmpv6_CLIs(nxtest.Testcase):

    #"TC_0063_ Verify_New_icmpv6_CLIs"
    @aetest.test
    def Verify_ICMPv6_CLIs(self,testbed):
        node3_s1_bgw_1 = testbed.devices['node3_s1_bgw_1']
        node7_s2_bgw_1 =testbed.devices['node7_s2_bgw_1']
        node4_s1_bgw_2 =testbed.devices['node4_s1_bgw_2']
        P3_dict = AcceSW_TGEN_data

        testbed.devices['node3_s1_bgw_1'].configure('''
            mac address-table static ''' + str(P3_dict['mac']) + ''' vlan '''+ str(P3_dict['vlan_id']) + ''' drop

                interface vlan ''' + str(P3_dict['vlan_id']) + '''
                  ipv6 neighbor ''' + str(P3_dict['v6_addr']) + ''' ''' + str(P3_dict['mac']) + '''
         ''')
        testbed.devices['node4_s1_bgw_2'].configure('''
            mac address-table static ''' + str(P3_dict['mac']) + ''' vlan '''+ str(P3_dict['vlan_id']) + ''' drop

                interface vlan ''' + str(P3_dict['vlan_id']) + '''
                    ipv6 neighbor ''' + str(P3_dict['v6_addr']) + ''' ''' + str(P3_dict['mac']) + '''
         ''')

        try:
            
            a = testbed.devices['node7_s2_bgw_1'].execute(''' sh ipv6 icmp neighbor static remote vrf vrf-1 '''  )
            if re.search("Bh",a):
                log.info('icmpv6 cli showing Bh route')
                self.passed('icmpv6 cli verified')
            else:
                self.failed('icmpv6 cli not verified')
        except Exception as error:
            log.debug("Unable to do cleanup " + str(error))
            self.errored('Exception occurred verifing icmpv6 CLI') 
        
    @aetest.test
    def Verify_ICMPv6_CLIs_with_json(self,testbed):
        node7_s2_bgw_1 =testbed.devices['node7_s2_bgw_1'] 
        P3_dict = AcceSW_TGEN_data 
        try:
            
            a = testbed.devices['node7_s2_bgw_1'].execute(''' sh ipv6 icmp neighbor static remote vrf vrf-1  | json ''')
            if re.search("Bh",a):
                log.info('icmpv6 cli showing Bh route')
                self.passed('icmpv6 cli verified')
            else:
                self.failed('icmpv6 cli not verified')
        except Exception as error:
            log.debug("Unable to do cleanup " + str(error))
            self.errored('Exception occurred verifing icmpv6 CLI')

    @aetest.test
    def Verify_ICMPv6_CLIs_with_xml(self,testbed):  
        node7_s2_bgw_1 =testbed.devices['node7_s2_bgw_1'] 
        P3_dict = AcceSW_TGEN_data 
        try:
            
            a = testbed.devices['node7_s2_bgw_1'].execute(''' sh ipv6 icmp neighbor static remote vrf vrf-1   | xml ''')
            if re.search("Bh",a):
                log.info('icmpv6 cli showing Bh route')
                self.passed('icmpv6 cli verified')
            else:
                self.failed('icmpv6 cli not verified')
        except Exception as error:
            log.debug("Unable to do cleanup " + str(error))
            self.errored('Exception occurred verifing icmpv6 CLI')

    @aetest.test
    def unconfig_Verify_ICMPv6_CLIs(self,testbed):
        node3_s1_bgw_1 = testbed.devices['node3_s1_bgw_1']
        node7_s2_bgw_1 =testbed.devices['node7_s2_bgw_1']
        node4_s1_bgw_2 =testbed.devices['node4_s1_bgw_2']
        P3_dict = AcceSW_TGEN_data

        testbed.devices['node3_s1_bgw_1'].configure('''
            no mac address-table static ''' + str(P3_dict['mac']) + ''' vlan '''+ str(P3_dict['vlan_id']) + ''' drop

                interface vlan ''' + str(P3_dict['vlan_id']) + '''
                  no ipv6 neighbor ''' + str(P3_dict['v6_addr']) + ''' ''' + str(P3_dict['mac']) + '''
         ''')
        testbed.devices['node4_s1_bgw_2'].configure('''
            no mac address-table static ''' + str(P3_dict['mac']) + ''' vlan '''+ str(P3_dict['vlan_id']) + ''' drop

                interface vlan ''' + str(P3_dict['vlan_id']) + '''
                  no ipv6 neighbor ''' + str(P3_dict['v6_addr']) + ''' ''' + str(P3_dict['mac']) + '''
         ''')

class Static_Arp_with_BH_mac_route_Without_suppress_ARP(nxtest.Testcase):
    #"TC_0070_Static_Arp_with_BH_mac_route_Without_suppress_ARP"
    @aetest.test
    def Unconfig_supperss_ARP(self,testbed):
        node3_s1_bgw_1 =  testbed.devices['node3_s1_bgw_1']
        node4_s1_bgw_2 =  testbed.devices['node4_s1_bgw_2']
        node1_cs_dci =  testbed.devices['node1_cs_dci']
        node2_s1_spine =  testbed.devices['node2_s1_spine']
        node5_s1_leaf_1 =  testbed.devices['node5_s1_leaf_1']
        node10_s1_AccessSW =  testbed.devices['node10_s1_AccessSW']
        node7_s2_bgw_1 =  testbed.devices['node7_s2_bgw_1']
        node9_s2_leaf_1 =  testbed.devices['node9_s2_leaf_1']
        try:
            testbed.devices['node3_s1_bgw_1'].configure(''' 
                interface nve 1
                    no global suppress-arp
            ''')
            testbed.devices['node4_s1_bgw_2'].configure(''' 
                interface nve 1
                    no global suppress-arp
            ''')
            testbed.devices['node1_cs_dci'].configure(''' 
                interface nve 1
                    no global suppress-arp
            ''')
            testbed.devices['node2_s1_spine'].configure(''' 
                interface nve 1
                    no global suppress-arp
            ''')
            testbed.devices['node5_s1_leaf_1'].configure(''' 
                interface nve 1
                    no global suppress-arp
            ''')
            testbed.devices['node7_s2_bgw_1'].configure(''' 
                interface nve 1
                    no global suppress-arp
            ''')
            testbed.devices['node9_s2_leaf_1'].configure(''' 
                interface nve 1
                    no global suppress-arp
            ''')

        except Exception as error:
            log.debug("Unable to configure suppress arp - Encountered Exception " + str(error))
            self.errored('Exception occurred while configuring suppress arp') 
        
    @aetest.test
    def S1_bgw1_status_check(self, testscript,testbed):
        time.sleep(40)
        output = json.loads(testbed.devices['node3_s1_bgw_1'].execute('sh nve peers | json'))
        log.info(output)
        if(output == ''):
            self.failed(reason='No Nve Peers')
        a = json.loads(testbed.devices['node3_s1_bgw_1'].execute('sh nve peers | json'))
        for item in a['TABLE_nve_peers']['ROW_nve_peers']:
            peer_state = item['peer-state']
            if not re.search('Up', peer_state):
                log.info('The Nve Peer {0} is not up. state is {1}'.format(ns.peer_ip,peer_state))
                self.failed(reason="status is down")
                time.sleep(60)

    @aetest.test
    def S1_bgw2_status_check(self, testscript,testbed):
        time.sleep(40)
        output = json.loads(testbed.devices['node4_s1_bgw_2'].execute('sh nve peers | json'))
        log.info(output)
        if(output == ''):
            self.failed(reason='No Nve Peers')
        a = json.loads(testbed.devices['node4_s1_bgw_2'].execute('sh nve peers | json'))
        for item in a['TABLE_nve_peers']['ROW_nve_peers']:
            peer_state = item['peer-state']
            if not re.search('Up', peer_state):
                log.info('The Nve Peer {0} is not up. state is {1}'.format(ns.peer_ip,peer_state))
                self.failed(reason="status is down")
                time.sleep(60)

    @aetest.test
    def S1_leaf_status_check(self, testscript,testbed):
        time.sleep(40)
        output = json.loads(testbed.devices['node5_s1_leaf_1'].execute('sh nve peers | json'))
        log.info(output)
        if(output == ''):
            self.failed(reason='No Nve Peers')
        a = json.loads(testbed.devices['node5_s1_leaf_1'].execute('sh nve peers | json'))
        for item in a['TABLE_nve_peers']['ROW_nve_peers']:
            peer_state = item['peer-state']
            if not re.search('Up', peer_state):
                log.info('The Nve Peer {0} is not up. state is {1}'.format(ns.peer_ip,peer_state))
                self.failed(reason="status is down")
                time.sleep(60)

    @aetest.test
    def S2_bgw1_status_check(self, testscript,testbed):
        time.sleep(40)
        output = json.loads(testbed.devices['node7_s2_bgw_1'].execute('sh nve peers | json'))
        log.info(output)
        if(output == ''):
            self.failed(reason='No Nve Peers')
        a = json.loads(testbed.devices['node7_s2_bgw_1'].execute('sh nve peers | json'))
        for item in a['TABLE_nve_peers']['ROW_nve_peers']:
            peer_state = item['peer-state']
            if not re.search('Up', peer_state):
                log.info('The Nve Peer {0} is not up. state is {1}'.format(ns.peer_ip,peer_state))
                self.failed(reason="status is down")
                time.sleep(60)

    @aetest.test
    def S2_leaf_status_check(self, testscript,testbed):
        time.sleep(40)
        output = json.loads(testbed.devices['node9_s2_leaf_1'].execute('sh nve peers | json'))
        log.info(output)
        if(output == ''):
            self.failed(reason='No Nve Peers')
        a = json.loads(testbed.devices['node9_s2_leaf_1'].execute('sh nve peers | json'))
        for item in a['TABLE_nve_peers']['ROW_nve_peers']:
            peer_state = item['peer-state']
            if not re.search('Up', peer_state):
                log.info('The Nve Peer {0} is not up. state is {1}'.format(ns.peer_ip,peer_state))
                self.failed(reason="status is down")
                time.sleep(60)

    stream_id=''
    @aetest.test
    def CONFIGURE_L2_UCAST_IXIA_TRAFFIC_H2_to_H1(self, testscript):
        """ IXIA_CONFIGURATION subsection: Configure MCAST Traffic Item """

        # Do not perform configurations if skip_tgen_config flag is set
        #if not testscript.parameters['script_flags']['skip_tgen_config']:

        IX_TP1 = testscript.parameters['IX_TP1']
        IX_TP2 = testscript.parameters['IX_TP2']
        IX_TP3 = testscript.parameters['IX_TP3']
        P1_dict = S1_BGW1_TGEN_data
        P2_dict = S1_Leaf_TGEN_data
        P3_dict = AcceSW_TGEN_data
        P4_dict = S2_Leaf_TGEN_data
        # P1_dict = S1_BGW1_TGEN_data
        # P4_dict = testscript.parameters['S2_BGW1_TGEN_dict']

        UCAST_v4_dict = {   'src_hndl'  : IX_TP1['ipv4_handle'],
                            'dst_hndl'  : IX_TP3['ipv4_handle'],
                            'circuit'   : 'ipv4',
                            'TI_name'   : "UCAST_V4",
                            'rate_pps'  : "10000",
                            'bi_dir'    : 1,
                            'bidirectional': '0'
                        }

        UCAST_v4_TI = ixLib.configure_ixia_traffic_item_v46(UCAST_v4_dict)
            
        if UCAST_v4_TI == 0:
            log.debug("Configuring UCast L2 TI failed")
            self.errored("Configuring UCast L2 TI failed", goto=['next_tc'])
        else:
            global stream_id
            stream_id = UCAST_v4_TI
            log.info('stream_id='+stream_id)
            log.info(type(stream_id))
        # else:
        #     self.passed(reason="Skipped TGEN Configurations as per request")
    stream_id=''
    @aetest.test
    def CONFIGURE_L2_UCAST_IXIA_TRAFFIC_H3_to_H1(self, testscript):
        """ IXIA_CONFIGURATION subsection: Configure MCAST Traffic Item """

        # Do not perform configurations if skip_tgen_config flag is set
        #if not testscript.parameters['script_flags']['skip_tgen_config']:

        IX_TP1 = testscript.parameters['IX_TP1']
        IX_TP2 = testscript.parameters['IX_TP2']
        IX_TP3 = testscript.parameters['IX_TP3']
        P1_dict = S1_BGW1_TGEN_data
        P2_dict = S1_Leaf_TGEN_data
        P3_dict = AcceSW_TGEN_data
        P4_dict = S2_Leaf_TGEN_data
        # P1_dict = S1_BGW1_TGEN_data
        # P4_dict = testscript.parameters['S2_BGW1_TGEN_dict']

        UCAST_v4_dict = {   'src_hndl'  : IX_TP2['ipv4_handle'],
                            'dst_hndl'  : IX_TP3['ipv4_handle'],
                            'circuit'   : 'ipv4',
                            'TI_name'   : "UCAST_V4",
                            'rate_pps'  : "10000",
                            'bi_dir'    : 1,
                            'bidirectional': '0'
                        }

        UCAST_v4_TI = ixLib.configure_ixia_traffic_item_v46(UCAST_v4_dict)
            
        if UCAST_v4_TI == 0:
            log.debug("Configuring UCast L2 TI failed")
            self.errored("Configuring UCast L2 TI failed", goto=['next_tc'])
        else:
            global stream_id
            stream_id = UCAST_v4_TI
            log.info('stream_id='+stream_id)
            log.info(type(stream_id))
        # else:
        #     self.passed(reason="Skipped TGEN Configurations as per request")
    stream_id=''
    @aetest.test
    def CONFIGURE_L2_UCAST_IXIA_TRAFFIC_H4_to_H1(self, testscript):
        """ IXIA_CONFIGURATION subsection: Configure MCAST Traffic Item """

        # Do not perform configurations if skip_tgen_config flag is set
        #if not testscript.parameters['script_flags']['skip_tgen_config']:

        IX_TP1 = testscript.parameters['IX_TP1']
        IX_TP2 = testscript.parameters['IX_TP2']
        IX_TP3 = testscript.parameters['IX_TP3']
        IX_TP4 = testscript.parameters['IX_TP4']
        P1_dict = S1_BGW1_TGEN_data
        P2_dict = S1_Leaf_TGEN_data
        P3_dict = AcceSW_TGEN_data
        P4_dict = S2_Leaf_TGEN_data
        # P1_dict = S1_BGW1_TGEN_data
        # P4_dict = testscript.parameters['S2_BGW1_TGEN_dict']

        UCAST_v4_dict = {   'src_hndl'  : IX_TP4['ipv4_handle'],
                            'dst_hndl'  : IX_TP3['ipv4_handle'],
                            'circuit'   : 'ipv4',
                            'TI_name'   : "UCAST_V4",
                            'rate_pps'  : "10000",
                            'bi_dir'    : 1,
                            'bidirectional': '0'
                        }

        UCAST_v4_TI = ixLib.configure_ixia_traffic_item_v46(UCAST_v4_dict)
            
        if UCAST_v4_TI == 0:
            log.debug("Configuring UCast L2 TI failed")
            self.errored("Configuring UCast L2 TI failed", goto=['next_tc'])
        else:
            global stream_id
            stream_id = UCAST_v4_TI
            log.info('stream_id='+stream_id)
            log.info(type(stream_id))
        # else:
        #     self.passed(reason="Skipped TGEN Configurations as per request")

    @aetest.test
    def APPLY_TRAFFIC(self):
        """ IXIA_CONFIGURATION subsection: Verify IXIA Traffic """

        # Apply IXIA Traffic
        if ixLib.apply_traffic() == 1:
            log.info("Applying IXIA TI Passed")
        else:
            self.errored("Applying IXIA TI failed")
    
    @aetest.test
    def VERIFY_IXIA_TRAFFIC_Without_BH_Route(self, testscript):
        """ IXIA_CONFIGURATION subsection: Verify IXIA Traffic """

        # Do not perform configurations if skip_tgen_config flag is set
        #if not testscript.parameters['script_flags']['skip_tgen_config']:

        time.sleep(20)
        a=1
        for i in range (a):
            if ixLib.verify_traffic(1) == a:
                log.debug("Traffic Verification Passed.") 
            else:
                log.info("Traffic Verification Failed.")
                # ForkedPdb().set_trace()
                self.failed("Traffic Verification failed")
        # else:
        #     self.passed(reason="Skipped TGEN Configurations as per request")
    
    @aetest.test
    def Config_Mac_BH_on_Vpc_Vtep_without_suppress_arp(self, testscript,testbed):
        node3_s1_bgw_1 =  testbed.devices['node3_s1_bgw_1']
        node4_s1_bgw_2 = testbed.devices['node4_s1_bgw_2']
        P3_dict = AcceSW_TGEN_data
        mac= str(P3_dict['mac'])
        vlan= str(P3_dict['vlan_id'])
        ip=str(P3_dict['v4_addr'])
        octet = 1
        no_int= int(P3_dict['no_of_ints'])
        
        for i in range (0,no_int):
            ###LEAF_3_MAC_BH_ROUTE
            testbed.devices['node3_s1_bgw_1'].configure('''
                mac address-table static ''' + str(mac) + ''' vlan '''+ str(vlan) + ''' drop

                interface vlan ''' + str(P3_dict['vlan_id']) + '''
                  ip arp ''' + str(ip) + ''' ''' + str(mac) + '''
            ''')
            testbed.devices['node4_s1_bgw_2'].configure('''
                mac address-table static ''' + str(mac) + ''' vlan '''+ str(vlan) + ''' drop

                interface vlan ''' + str(vlan) + '''
                  ip arp ''' + str(ip) + ''' ''' + str(mac) + '''
            ''')
            lasthex=incr_mac(mac)
            mac=mac[0:10]+lasthex
            vlan= int(vlan)+int(P3_dict['vlan_id_step'])
            ip=incr_ip(ip,octet) 

           
    @aetest.test
    def VERIFY_IXIA_TRAFFIC_With_BH_Route(self, testscript):
        """ IXIA_CONFIGURATION subsection: Verify IXIA Traffic """

        # Do not perform configurations if skip_tgen_config flag is set
        #if not testscript.parameters['script_flags']['skip_tgen_config']:

        time.sleep(20)
        b=0
        for i in range (b):
            if ixLib.verify_traffic(99) == b:
                log.debug("Traffic Verification Passed.Expecting traffic loss here.") 
            else:
                log.info("Traffic Verification Failed. Expecting traffic loss here.")
                # ForkedPdb().set_trace() 
                self.failed("Traffic Verification failed")
        # else:
        #     self.passed(reason="Skipped TGEN Configurations as per request")
    
    @aetest.test
    def Verify_Traffic_Drop_on_Remote_Vtep(self,testscript,testbed):
        node5_s1_leaf_1 = testbed.devices['node5_s1_leaf_1']
        node7_s2_bgw_1 = testbed.devices['node7_s2_bgw_1']
        node9_s2_leaf_1 = testbed.devices['node9_s2_leaf_1']
        P3_dict = AcceSW_TGEN_data
        uplink_PO=S1_Leaf_dict['S1_Leaf_UPLINK_PO']['po_id']
        if verify_traffic_drop(node5_s1_leaf_1,uplink_PO):
            log.info('Traffic correctly dropped on  S1_Leaf')
        else:
            log.info('Traffic NOT dropped on  S1_Leaf')
            self.failed('Traffic NOT dropped on  S1_Leaf')

        uplink_PO=S2_BGW1_dict['S2_BGW1_UPLINK_PO']['po_id']
        if verify_traffic_drop(node7_s2_bgw_1,uplink_PO):
            log.info('Traffic correctly dropped on  S2_BGW1')
        else:
            log.info('Traffic NOT dropped on  S2_BGW1')
            self.failed('Traffic NOT dropped on  S2_BGW1')
        
        uplink_PO=S2_Leaf_dict['S2_Leaf_UPLINK_PO']['po_id']
        if verify_traffic_drop(node9_s2_leaf_1,uplink_PO):
            log.info('Traffic correctly dropped on  S1_Leaf')
        else:
            log.info('Traffic NOT dropped on  S1_Leaf')
            self.failed('Traffic NOT dropped on  S1_Leaf')


    #verifing BGP, ARP, L2FM, L2RIB, AM, HMM
    @aetest.test
    def Verify_BH_states_in_HMM(self, testscript,testbed):
        node4_s1_bgw_2 =testbed.devices['node4_s1_bgw_2']
        node7_s2_bgw_1 = testbed.devices['node7_s2_bgw_1']
        P3_dict = AcceSW_TGEN_data

        try:
            if verify_BH_in_HMM(node4_s1_bgw_2,str(P3_dict['v4_addr'])):
                log.info('Mac BH route is proper in HMM on  S1_BGW1')
            else:
                log.info('Mac BH route is improper in HMM on  S1_BGW1')
                # ForkedPdb().set_trace()
                self.failed('Mac BH route is improper in HMM on  S1_BGW1')
        
         
        except Exception as error:
            log.debug("Unable to configure static BH mac route on Remote Vtep- Encountered Exception " + str(error))
            self.errored('Exception occurred while configuring static BH mac route on Remote Vtep', goto=['cleanup'])
    @aetest.test
    def Verify_BH_states_in_AM(self, testscript,testbed):
        node4_s1_bgw_2 = testbed.devices['node4_s1_bgw_2']
        node7_s2_bgw_1 = testbed.devices['node7_s2_bgw_1']
        P1_dict = S1_BGW1_TGEN_data
        P2_dict = S1_Leaf_TGEN_data
        P3_dict = AcceSW_TGEN_data
        P4_dict = S2_Leaf_TGEN_data

        try:        
            if verify_BH_in_AM(node4_s1_bgw_2,str(P3_dict['mac']),str(P3_dict['vlan_id']),str(P3_dict['v4_addr'])):
                log.info('Mac BH route is proper in AM on  S1_BGW1')
            else:
                log.info('Mac BH route is improper in AM on  S1_BGW1')
                self.failed('Mac BH route is improper in AM on  S1_BGW1')
                   
        
        except Exception as error:
            log.debug("Unable to configure static BH mac route on Remote Vtep- Encountered Exception " + str(error))
            self.errored('Exception occurred while configuring static BH mac route on Remote Vtep', goto=['cleanup'])
    @aetest.test
    def Verify_BH_states_in_remote_ARP(self, testscript,testbed):
        node3_s1_bgw_1 =testbed.devices['node3_s1_bgw_1']
        node7_s2_bgw_1 = testbed.devices['node7_s2_bgw_1']
        P3_dict = AcceSW_TGEN_data

        try: 

            if verify_BH_in_Remote_ARP(node7_s2_bgw_1,str(P3_dict['vlan_id']),str(P3_dict['mac'])):
               log.info('Mac BH route is proper in Remote ARP on  S2_BGW1')
            else:
                log.info('Mac BH route is improper in Remote ARP on  S2_BGW1')
                self.failed('Mac BH route is improper in Remote ARP on  S2_BGW1')

        except Exception as error:
            log.debug("Unable to configure static BH mac route on Remote Vtep- Encountered Exception " + str(error))
            self.errored('Exception occurred while configuring static BH mac route on Remote Vtep')        
    @aetest.test
    def Verify_BH_states_in_local_ARP(self, testscript,testbed):
        node3_s1_bgw_1 = testbed.devices['node3_s1_bgw_1']
        node7_s2_bgw_1 = testbed.devices['node7_s2_bgw_1']
        P1_dict = S1_BGW1_TGEN_data
        P2_dict = S1_Leaf_TGEN_data
        P3_dict = AcceSW_TGEN_data
        P4_dict = S2_Leaf_TGEN_data
        try:        
            if verify_BH_in_local_ARP(node3_s1_bgw_1,str(P3_dict['vlan_id']),str(P3_dict['mac'])):
                log.info('Mac BH route is proper in Local ARP on  S1_BGW1')
            else:
                log.info('Mac BH route is improper in Local ARP on  S1_BGW1')
                self.failed('Mac BH route is improper in Local ARP on  S1_BGW1')
        
        except Exception as error:
            log.debug("Unable to configure static BH mac route on Remote Vtep- Encountered Exception " + str(error))
            self.errored('Exception occurred while configuring static BH mac route on Remote Vtep')
        
    def Verify_Mac_BH_Route_on_L2FM_BGP_L2RIB(self,testscript,testbed):
        node3_s1_bgw_1 = testbed.devices['node3_s1_bgw_1']
        node7_s2_bgw_1 = testbed.devices['node7_s2_bgw_1']
        P3_dict = AcceSW_TGEN_data
        
        # Verifying L2FM

        try:
            ###S1_BGW1_MAC_BH_ROUTE
            if verify_BH_route_in_L2FM(node3_s1_bgw_1,str(P3_dict['vlan_id']),str(P3_dict['mac'])):
                log.info('Mac BH route is proper in L2FM on  S1_BGw1')
            else:
                log.info('Mac BH route is improper in L2FM on  S1_BGw1')
                self.failed('Mac BH route is improper in L2FM on  S1_BGw1')

            ###S2_BGW1_MAC_BH_ROUTE Remote Vtep
            if verify_BH_route_in_L2FM(node7_s2_bgw_1,str(P3_dict['vlan_id']),str(P3_dict['mac'])):
                log.info('Mac BH route is proper in L2FM on  S2_BGw1')
            else:
                log.info('Mac BH route is improper in L2FM on  S2_BGw1')
                self.failed('Mac BH route is improper in L2FM on  S2_BGw1')

        except Exception as error:
            log.debug("Unable to verify BH mac route in L2FM - Encountered Exception " + str(error))
            self.errored('Exception occurred while verifying BH mac route in L2FM')        

        #Verifying L2RIB
        try:
            #S1_Leaf_Mac_BH_route
            if verify_L2rib_mac_ip_output(node3_s1_bgw_1,str(P3_dict['vlan_id']),str(P3_dict['mac'])):
                log.info('Mac BH route is proper in L2RIB on S1_Leaf')
            else:
                log.debug('Mac BH route is improper in L2RIB on  S1_Leaf')
                self.failed('Mac BH route is improper in L2RIB on  S1_Leaf')

            #S2_BGW1_Mac_BH_route
            if verify_L2rib_mac_ip_output(node7_s2_bgw_1,str(P3_dict['vlan_id']),str(P3_dict['mac'])):
                log.info('Mac BH route is proper in L2RIB on S2_BGW1')
            else:
                log.debug('Mac BH route is improper in L2RIB on  S2_BGW1')
                self.errored('Mac BH route is improper in L2RIB on  S2_BGW1')
        
        except Exception as error:
            log.debug("Unable to verify BH mac route in L2RIB - Encountered Exception " + str(error))
            self.errored('Exception occurred while verifying BH mac route in L2RIB')
        
        #Verifying BGP
        try:
            #S2_BGW1_Mac_BH_route
            if verify_BH_in_Remote_BGP(node7_s2_bgw_1,str(P3_dict['mac'])):
                log.info('Mac BH route is proper in BGP on S2_BGW1')
            else:
                log.debug('Mac BH route is improper in BGP on  S2_BGW1')
                self.errored('Mac BH route is improper in BGP on  S2_BGW1')

            #Access_Mac_BH_route
            if verify_BH_in_Remote_BGP(node3_s1_bgw_1,str(P3_dict['mac'])):
                log.info('Mac BH route is proper in BGP on Access')
            else:
                log.debug('Mac BH route is improper in BGP on  Access')
                self.errored('Mac BH route is improper in BGP on  Access')
        
        except Exception as error:
            log.debug("Unable to verify BH mac route in BGP - Encountered Exception " + str(error))
            self.errored('Exception occurred while verifying BH mac route in BGP', )

    @aetest.test
    def unConfig_Mac_BH_on_Vpc_Vtep(self, testscript,testbed):
        node3_s1_bgw_1 =  testbed.devices['node3_s1_bgw_1']
        P3_dict = AcceSW_TGEN_data
        mac= str(P3_dict['mac'])
        vlan= str(P3_dict['vlan_id'])
        ip=str(P3_dict['v4_addr'])
        octet = 1
        no_int= int(P3_dict['no_of_ints'])
        
        for i in range (0,no_int):
            ###LEAF_3_MAC_BH_ROUTE
            testbed.devices['node3_s1_bgw_1'].configure('''
                no mac address-table static ''' + str(mac) + ''' vlan '''+ str(vlan) + ''' drop

                interface vlan ''' + str(P3_dict['vlan_id']) + '''
                  no ip arp ''' + str(ip) + ''' ''' + str(mac) + '''

                interface nve 1
                    global suppress-arp
            ''')
            testbed.devices['node4_s1_bgw_2'].configure('''
                no mac address-table static ''' + str(mac) + ''' vlan '''+ str(vlan) + ''' drop

                interface vlan ''' + str(vlan) + '''
                  no ip arp ''' + str(ip) + ''' ''' + str(mac) + '''
                
                interface nve 1
                    global suppress-arp
            ''')
            lasthex=incr_mac(mac)
            mac=mac[0:10]+lasthex
            vlan= int(vlan)+int(P3_dict['vlan_id_step'])
            ip=incr_ip(ip,octet) 

            testbed.devices['node1_cs_dci'].configure(''' 
                interface nve 1
                    global suppress-arp
            ''')
            testbed.devices['node2_s1_spine'].configure(''' 
                interface nve 1
                    global suppress-arp
            ''')
            testbed.devices['node5_s1_leaf_1'].configure(''' 
                interface nve 1
                    global suppress-arp
            ''')
            testbed.devices['node7_s2_bgw_1'].configure(''' 
                interface nve 1
                    global suppress-arp
            ''')
            testbed.devices['node9_s2_leaf_1'].configure(''' 
                interface nve 1
                    global suppress-arp
            ''')

            
        # except Exception as error:
        #     log.debug("Unable to configure static BH mac route - Encountered Exception " + str(error))
        #     self.errored('Exception occurred while configuring static BH mac route') 

    @aetest.test
    def VERIFY_IXIA_TRAFFIC_after_rmBH_Route(self, testscript):
        """ IXIA_CONFIGURATION subsection: Verify IXIA Traffic """

        # Do not perform configurations if skip_tgen_config flag is set
        #if not testscript.parameters['script_flags']['skip_tgen_config']:

        time.sleep(20)
        a=1
        for i in range (a):
            if ixLib.verify_traffic(1) == a:
                log.debug("Traffic Verification Passed.") 
            else:
                log.info("Traffic Verification Failed. ")
                # ForkedPdb().set_trace()
                self.failed("Traffic Verification failed")
        # else:
    
    @aetest.test
    def cleanup(self,testscript, testbed):
        """Unconfigure qos policies"""
        node3_s1_bgw_1 =  testbed.devices['node3_s1_bgw_1']
        node5_s1_leaf_1 =  testbed.devices['node5_s1_leaf_1']
        node10_s1_AccessSW =  testbed.devices['node10_s1_AccessSW']
        node7_s2_bgw_1 =  testbed.devices['node7_s2_bgw_1']
        P3_dict = AcceSW_TGEN_data
        forwardingSysDict = FWD_SYS_dict
        # Stop Traffic from ixia
        log.info("--- Stopping Traffic ---- \n")
        log.info("Stopping Traffic")
        traffic_run_status = ixLib.stop_traffic()
        
        if traffic_run_status is not 1:
            log.info("Failed: To Stop traffic")
            return 0
        else:
            log.info("\nTraffic Stopped successfully\n")
        time.sleep(10)
        ####Remove traffic item configured
        UCAST_v4_dict = {
                        'mode'        : 'remove',
                        'stream_id'   : stream_id,
                        'stream_id'   : stream_id,
                        'stream_id'   : stream_id,
                    }
        if (ixLib.delete_traffic_item(UCAST_v4_dict))==0:
            log.debug("Traffic Remove failed")
            self.failed("Traffic Remove failed", goto=['next_tc'])
        else:
            log.info("Traffic Remove Passed")

class Static_ND_with_BH_mac_route_with_Suppress_ND(nxtest.Testcase):
    #"TC_0072_Static_ND_with_BH_mac_route_with_Suppress_ND"

    stream_id=''
    @aetest.test
    def CONFIGURE_L2_UCAST_IXIA_TRAFFIC_With_IPv6_H2_to_H1(self, testscript):
        """ IXIA_CONFIGURATION subsection: Configure MCAST Traffic Item """

        # Do not perform configurations if skip_tgen_config flag is set
        #if not testscript.parameters['script_flags']['skip_tgen_config']:

        IX_TP1 = testscript.parameters['IX_TP1']
        IX_TP2 = testscript.parameters['IX_TP2']
        IX_TP3 = testscript.parameters['IX_TP3']
        IX_TP4 = testscript.parameters['IX_TP4']
        P1_dict = S1_BGW1_TGEN_data
        P2_dict = S1_Leaf_TGEN_data
        P3_dict = AcceSW_TGEN_data
        P4_dict = S2_Leaf_TGEN_data


        UCAST_v6_dict = {   'src_hndl'  : IX_TP1['ipv6_handle'],
                            'dst_hndl'  : IX_TP3['ipv6_handle'],
                            'circuit'   : 'ipv6',
                            'TI_name'   : "UCAST_v6",
                            'rate_pps'  : "1000",
                            'bi_dir'    : 1,
                            'bidirectional': '0'
                        }

        UCAST_v6_TI = ixLib.configure_ixia_traffic_item_v46(UCAST_v6_dict)

        if UCAST_v6_TI == 0:
            log.debug("Configuring UCast TI failed")
            self.errored("Configuring UCast TI failed", goto=['next_tc'])   
        
        else:
            global stream_id
            stream_id = UCAST_v6_TI
            log.info('stream_id='+stream_id)
            log.info(type(stream_id))
        # else:
    
        #     self.passed(reason="Skipped TGEN Configurations as per request")
    stream_id=''
    @aetest.test
    def CONFIGURE_L2_UCAST_IXIA_TRAFFIC_With_IPv6_H3_to_H1(self, testscript):
        """ IXIA_CONFIGURATION subsection: Configure MCAST Traffic Item """

        # Do not perform configurations if skip_tgen_config flag is set
        #if not testscript.parameters['script_flags']['skip_tgen_config']:

        IX_TP1 = testscript.parameters['IX_TP1']
        IX_TP2 = testscript.parameters['IX_TP2']
        IX_TP3 = testscript.parameters['IX_TP3']
        IX_TP4 = testscript.parameters['IX_TP4']
        P1_dict = S1_BGW1_TGEN_data
        P2_dict = S1_Leaf_TGEN_data
        P3_dict = AcceSW_TGEN_data
        P4_dict = S2_Leaf_TGEN_data

        UCAST_v6_dict = {   'src_hndl'  : IX_TP2['ipv6_handle'],
                            'dst_hndl'  : IX_TP3['ipv6_handle'],
                            'circuit'   : 'ipv6',
                            'TI_name'   : "UCAST_v6",
                            'rate_pps'  : "1000",
                            'bi_dir'    : 1,
                            'bidirectional': '0'
                        }

        UCAST_v6_TI = ixLib.configure_ixia_traffic_item_v46(UCAST_v6_dict)

        if UCAST_v6_TI == 0:
            log.debug("Configuring UCast TI failed")
            self.errored("Configuring UCast TI failed", goto=['next_tc'])   
        
        else:
            global stream_id
            stream_id = UCAST_v6_TI
            log.info('stream_id='+stream_id)
            log.info(type(stream_id))
        # else:
        #     self.passed(reason="Skipped TGEN Configurations as per request")
    stream_id=''
    @aetest.test
    def CONFIGURE_L2_UCAST_IXIA_TRAFFIC_With_IPv6_H4_to_H1(self, testscript):
        """ IXIA_CONFIGURATION subsection: Configure MCAST Traffic Item """

        # Do not perform configurations if skip_tgen_config flag is set
        #if not testscript.parameters['script_flags']['skip_tgen_config']:

        IX_TP1 = testscript.parameters['IX_TP1']
        IX_TP2 = testscript.parameters['IX_TP2']
        IX_TP3 = testscript.parameters['IX_TP3']
        IX_TP4 = testscript.parameters['IX_TP4']
        P1_dict = S1_BGW1_TGEN_data
        P2_dict = S1_Leaf_TGEN_data
        P3_dict = AcceSW_TGEN_data
        P4_dict = S2_Leaf_TGEN_data


        UCAST_v6_dict = {   'src_hndl'  : IX_TP4['ipv6_handle'],
                            'dst_hndl'  : IX_TP3['ipv6_handle'],
                            'circuit'   : 'ipv6',
                            'TI_name'   : "UCAST_v6",
                            'rate_pps'  : "1000",
                            'bi_dir'    : 1,
                            'bidirectional': '0'
                        }

        UCAST_v6_TI = ixLib.configure_ixia_traffic_item_v46(UCAST_v6_dict)

        if UCAST_v6_TI == 0:
            log.debug("Configuring UCast TI failed")
            self.errored("Configuring UCast TI failed", goto=['next_tc'])   
        
        else:
            global stream_id
            stream_id = UCAST_v6_TI
            log.info('stream_id='+stream_id)
            log.info(type(stream_id))
        # else:
        #     self.passed(reason="Skipped TGEN Configurations as per request")

    @aetest.test
    def APPLY_TRAFFIC(self):
        """ IXIA_CONFIGURATION subsection: Verify IXIA Traffic """

        # Apply IXIA Traffic
        if ixLib.apply_traffic() == 1:
            log.info("Applying IXIA TI Passed")
        else:
            self.errored("Applying IXIA TI failed")
    
    @aetest.test
    def VERIFY_IXIA_TRAFFIC_Without_BH_Route(self, testscript):
        """ IXIA_CONFIGURATION subsection: Verify IXIA Traffic """

        # Do not perform configurations if skip_tgen_config flag is set
        #if not testscript.parameters['script_flags']['skip_tgen_config']:

        time.sleep(20)
        a=1
        for i in range (a):
            if ixLib.verify_traffic(1) == a:
                log.debug("Traffic Verification Passed.Expecting traffic loss here.") 
            else:
                log.info("Traffic Verification Failed. Expecting traffic loss here.")
                self.failed("Traffic Verification failed")
        # else:
        #     self.passed(reason="Skipped TGEN Configurations as per request")

    @aetest.test
    def Config_Mac_BH_Static_ND_on_VPC(self,testscript,testbed):
        node3_s1_bgw_1 = testbed.devices['node3_s1_bgw_1']
        P3_dict = AcceSW_TGEN_data

        testbed.devices['node3_s1_bgw_1'].configure(''' 
        interface nve 1
            suppress nd
        ''')
        
        testbed.devices['node4_s1_bgw_2'].configure(''' 
        interface nve 1
            suppress nd
        ''')

        testbed.devices['node7_s2_bgw_1'].configure(''' 
        interface nve 1
            suppress nd
        ''')

        testbed.devices['node5_s1_leaf_1'].configure(''' 
        interface nve 1
            suppress nd
        ''')
        testbed.devices['node9_s2_leaf_1'].configure(''' 
        interface nve 1
            suppress nd
        ''')
        mac= str(P3_dict['mac'])
        vlan= str(P3_dict['vlan_id'])
        ipv6=str(P3_dict['v6_addr'])
        octet = 2
        no_int= int(P3_dict['no_of_ints'])
        
        for i in range (0,no_int):
            ###LEAF_3_MAC_BH_ROUTE
            testbed.devices['node3_s1_bgw_1'].configure('''
                mac address-table static ''' + str(mac) + ''' vlan '''+ str(vlan) + ''' drop

                interface vlan ''' + str(vlan) + '''
                    ipv6 neighbor ''' + str(ipv6) + ''' ''' + str(mac) + '''
            ''')
        
            testbed.devices['node4_s1_bgw_2'].configure('''
                mac address-table static ''' + str(mac) + ''' vlan '''+ str(vlan) + ''' drop

                interface vlan ''' + str(vlan) + '''
                    ipv6 neighbor ''' + str(ipv6) + ''' ''' + str(mac) + '''
            ''')
            lasthex=incr_mac(mac)
            mac=mac[0:10]+lasthex
            vlan= int(vlan)+int(P3_dict['vlan_id_step'])
            ipv6=incr_ipv6(ipv6,octet)     

    @aetest.test
    def VERIFY_IXIA_TRAFFIC_With_BH_Route(self, testscript):
        """ IXIA_CONFIGURATION subsection: Verify IXIA Traffic """

        # Do not perform configurations if skip_tgen_config flag is set
        #if not testscript.parameters['script_flags']['skip_tgen_config']:

        time.sleep(30)
        b=0
        for i in range (b):
            if ixLib.verify_traffic(99) == b:
                log.debug("Traffic Verification Passed.Expecting traffic loss here.") 
            else:
                log.info("Traffic Verification Failed. Expecting traffic loss here.")
                self.failed("Traffic Verification failed")
        # else:
        #     self.passed(reason="Skipped TGEN Configurations as per request")
    
    @aetest.test
    def Verify_Traffic_Drop_on_Remote_Vtep(self,testscript,testbed):
        node5_s1_leaf_1 = testbed.devices['node5_s1_leaf_1']
        node7_s2_bgw_1 = testbed.devices['node7_s2_bgw_1']
        node9_s2_leaf_1 = testbed.devices['node9_s2_leaf_1']
        P3_dict = AcceSW_TGEN_data
        uplink_PO=S1_Leaf_dict['S1_Leaf_UPLINK_PO']['po_id']
        if verify_traffic_drop(node5_s1_leaf_1,uplink_PO):
            log.info('Traffic correctly dropped on  S1_Leaf')
        else:
            log.info('Traffic NOT dropped on  S1_Leaf')
            self.failed('Traffic NOT dropped on  S1_Leaf')

        uplink_PO=S2_BGW1_dict['S2_BGW1_UPLINK_PO']['po_id']
        if verify_traffic_drop(node7_s2_bgw_1,uplink_PO):
            log.info('Traffic correctly dropped on  S1_Leaf')
        else:
            log.info('Traffic NOT dropped on  S1_Leaf')
            self.failed('Traffic NOT dropped on  S1_Leaf')
        
        uplink_PO=S2_Leaf_dict['S2_Leaf_UPLINK_PO']['po_id']
        if verify_traffic_drop(node9_s2_leaf_1,uplink_PO):
            log.info('Traffic correctly dropped on  S1_Leaf')
        else:
            log.info('Traffic NOT dropped on  S1_Leaf')
            self.failed('Traffic NOT dropped on  S1_Leaf')
    
    @aetest.test
    def Verify_BH_states_in_HMM(self, testscript,testbed):
        node4_s1_bgw_2 = testbed.devices['node4_s1_bgw_2']
        node7_s2_bgw_1 = testbed.devices['node7_s2_bgw_1']
        P3_dict = AcceSW_TGEN_data

        try:
            if verify_Ipv6_BH_in_HMM(node4_s1_bgw_2,str(P3_dict['v6_addr'])):
                log.info('Mac BH route is proper in HMM on  S1_BGW1')
            else:
                log.info('Mac BH route is improper in HMM on  S1_BGW1')
                self.failed('Mac BH route is improper in HMM on  S1_BGW1')
        
         
        except Exception as error:
            log.debug("Unable to configure static BH mac route on Remote Vtep- Encountered Exception " + str(error))
            self.errored('Exception occurred while configuring static BH mac route on Remote Vtep')

    @aetest.test
    def Verify_BH_states_in_AM(self, testscript,testbed):
        node4_s1_bgw_2 = testbed.devices['node4_s1_bgw_2']
        node7_s2_bgw_1 = testbed.devices['node7_s2_bgw_1']
        P3_dict = AcceSW_TGEN_data

        try:        
            if verify_Ipv6_BH_in_AM(node4_s1_bgw_2,str(P3_dict['mac']),str(P3_dict['vlan_id']),str(P3_dict['v6_addr'])):
                log.info('Mac BH route is proper in AM on  S1_BGW1')
            else:
                log.info('Mac BH route is improper in AM on  S1_BGW1')
                self.failed('Mac BH route is improper in AM on  S1_BGW1')
        
        except Exception as error:
            log.debug("Unable to configure static BH mac route on Remote Vtep- Encountered Exception " + str(error))
            self.errored('Exception occurred while configuring static BH mac route on Remote Vtep')
    
    @aetest.test
    def Verify_Mac_BH_Route_on_L2FM_BGP_L2RIB(self,testscript,testbed):
        node3_s1_bgw_1 = testbed.devices['node3_s1_bgw_1']
        node7_s2_bgw_1 = testbed.devices['node7_s2_bgw_1']
        P3_dict = AcceSW_TGEN_data
        
        # Verifying L2FM

        try:
            ###S1_BGW1_MAC_BH_ROUTE
            if verify_BH_route_in_L2FM(node3_s1_bgw_1,str(P3_dict['vlan_id']),str(P3_dict['mac'])):
                log.info('Mac BH route is proper in L2FM on  S1_BGw1')
            else:
                log.info('Mac BH route is improper in L2FM on  S1_BGw1')
                self.failed('Mac BH route is improper in L2FM on  S1_BGw1')

            ###S2_BGW1_MAC_BH_ROUTE Remote Vtep
            if verify_BH_route_in_L2FM(node7_s2_bgw_1,str(P3_dict['vlan_id']),str(P3_dict['mac'])):
                log.info('Mac BH route is proper in L2FM on  S2_BGw1')
            else:
                log.info('Mac BH route is improper in L2FM on  S2_BGw1')
                self.failed('Mac BH route is improper in L2FM on  S2_BGw1')

        except Exception as error:
            log.debug("Unable to verify BH mac route in L2FM - Encountered Exception " + str(error))
            self.errored('Exception occurred while verifying BH mac route in L2FM')        

        #Verifying L2RIB
        try:
            #S1_Leaf_Mac_BH_route
            if verify_L2rib_mac_ip_output(node3_s1_bgw_1,str(P3_dict['vlan_id']),str(P3_dict['mac'])):
                log.info('Mac BH route is proper in L2RIB on S1_Leaf')
            else:
                log.debug('Mac BH route is improper in L2RIB on  S1_Leaf')
                self.failed('Mac BH route is improper in L2RIB on  S1_Leaf')
            #S2_BGW1_Mac_BH_route
            if verify_L2rib_mac_ip_output(node7_s2_bgw_1,str(P3_dict['vlan_id']),str(P3_dict['mac'])):
                log.info('Mac BH route is proper in L2RIB on S2_BGW1')
            else:
                log.debug('Mac BH route is improper in L2RIB on  S2_BGW1')
                self.errored('Mac BH route is improper in L2RIB on  S2_BGW1')
        
        except Exception as error:
            log.debug("Unable to verify BH mac route in L2RIB - Encountered Exception " + str(error))
            self.errored('Exception occurred while verifying BH mac route in L2RIB')
        
        #Verifying BGP
        try:
            #S2_BGW1_Mac_BH_route
            if verify_BH_in_Remote_BGP(node7_s2_bgw_1,str(P3_dict['mac'])):
                log.info('Mac BH route is proper in BGP on S2_BGW1')
            else:
                log.debug('Mac BH route is improper in BGP on  S2_BGW1')
                self.errored('Mac BH route is improper in BGP on  S2_BGW1')

            #Access_Mac_BH_route
            if verify_BH_in_Remote_BGP(node3_s1_bgw_1,str(P3_dict['mac'])):
                log.info('Mac BH route is proper in BGP on Access')
            else:
                log.debug('Mac BH route is improper in BGP on  Access')
                self.errored('Mac BH route is improper in BGP on  Access')
        
        except Exception as error:
            log.debug("Unable to verify BH mac route in BGP - Encountered Exception " + str(error))
            self.errored('Exception occurred while verifying BH mac route in BGP')
    
    @aetest.test
    def Verify_Ipv6_icmp_neighbor(self,testbed):
        node3_s1_bgw_1 = testbed.devices['node3_s1_bgw_1']
        node7_s2_bgw_1 = testbed.devices['node7_s2_bgw_1']
        P3_dict = AcceSW_TGEN_data
    
        ###S1_BGW1_MAC_BH_ROUTE
        if Verify_ipv6_local_neighbor(node3_s1_bgw_1,str(P3_dict['mac']),str(P3_dict['vlan_id'])):
            log.info('Mac BH route is proper in ICMP neighbor on  S1_BGw1')
        else:
            log.info('Mac BH route is improper in ICMP neighbor on  S1_BGw1')
            self.failed('Mac BH route is improper in ICMP neighbor on  S1_BGw1')

        if verify_icmp_static_remote_neighbor(node7_s2_bgw_1,str(P3_dict['mac'])):
            log.info('Mac BH route is proper in ICMP neighbor on  S2_BGw1')
        else:
            log.info('Mac BH route is improper in ICMP neighbor on  S2_BGw1')
            self.failed('Mac BH route is improper in ICMP neighbor on  S1_BGw1')
 

    @aetest.test
    def UnConfig_Mac_BH_Static_ND_on_VPC(self,testscript,testbed):
        node3_s1_bgw_1 = testbed.devices['node3_s1_bgw_1']
        P3_dict = AcceSW_TGEN_data
        
        mac= str(P3_dict['mac'])
        vlan= str(P3_dict['vlan_id'])
        ipv6=str(P3_dict['v6_addr'])
        octet = 2
        no_int= int(P3_dict['no_of_ints'])
        
        for i in range (0,no_int):
            ###LEAF_3_MAC_BH_ROUTE
            testbed.devices['node3_s1_bgw_1'].configure('''
                no mac address-table static ''' + str(mac) + ''' vlan '''+ str(vlan) + ''' drop

                interface vlan ''' + str(vlan) + '''
                    no ipv6 neighbor ''' + str(ipv6) + ''' ''' + str(mac) + '''
            ''')
        
            testbed.devices['node4_s1_bgw_2'].configure('''
                no mac address-table static ''' + str(mac) + ''' vlan '''+ str(vlan) + ''' drop

                interface vlan ''' + str(vlan) + '''
                    no ipv6 neighbor ''' + str(ipv6) + ''' ''' + str(mac) + '''
            ''')
            lasthex=incr_mac(mac)
            mac=mac[0:10]+lasthex
            vlan= int(vlan)+int(P3_dict['vlan_id_step'])
            ipv6=incr_ipv6(ipv6,octet) 


            testbed.devices['node7_s2_bgw_1'].configure(''' 
                interface nve 1
                    no suppress nd 
                
               
            ''')
            
            testbed.devices['node5_s1_leaf_1'].configure(''' 
                interface nve 1
                    no suppress nd
            ''')
            testbed.devices['node9_s2_leaf_1'].configure(''' 
                interface nve 1
                    no suppress nd
            ''')
       
    @aetest.test
    def APPLY_TRAFFIC(self):
        """ IXIA_CONFIGURATION subsection: Verify IXIA Traffic """

        # Apply IXIA Traffic
        if ixLib.apply_traffic() == 1:
            log.info("Applying IXIA TI Passed")
        else:
            self.errored("Applying IXIA TI failed", goto=['next_tc'])
     
    @aetest.test
    def VERIFY_IXIA_TRAFFIC_after_rmBH_Route(self, testscript):
        """ IXIA_CONFIGURATION subsection: Verify IXIA Traffic """

        # Do not perform configurations if skip_tgen_config flag is set
        #if not testscript.parameters['script_flags']['skip_tgen_config']:

        time.sleep(30)
        a=1
        for i in range (a):
            if ixLib.verify_traffic(1) == a:
                log.debug("Traffic Verification Passed.Expecting traffic loss here.") 
            else:
                log.info("Traffic Verification Failed. Expecting traffic loss here.")
                self.failed("Traffic Verification failed")
        # else:
        #     self.passed(reason="Skipped TGEN Configurations as per request")

    
    @aetest.cleanup
    def cleanup(self,testscript,testbed):
        """Unconfigure qos policies"""
        node3_s1_bgw_1 =testbed.devices['node3_s1_bgw_1']
        node5_s1_leaf_1 = testbed.devices['node5_s1_leaf_1']
        node10_s1_AccessSW = testbed.devices['node10_s1_AccessSW']
        node7_s2_bgw_1 = testbed.devices['node7_s2_bgw_1']
        P3_dict = AcceSW_TGEN_data
        forwardingSysDict = FWD_SYS_dict
        # Stop Traffic from ixia
        log.info("--- Stopping Traffic ---- \n")
        log.info("Stopping Traffic")
        traffic_run_status = ixLib.stop_traffic()
        
        if traffic_run_status is not 1:
            log.info("Failed: To Stop traffic")
            return 0
        else:
            log.info("\nTraffic Stopped successfully\n")
        time.sleep(10)
        ####Remove traffic item configured
        UCAST_v6_dict = {
                        'mode'        : 'remove',
                        'stream_id'   : stream_id,
                        'stream_id'   : stream_id,
                        'stream_id'   : stream_id,
                    }
        if (ixLib.delete_traffic_item(UCAST_v6_dict))==0:
            log.debug("Traffic Remove failed")
            self.failed("Traffic Remove failed", goto=['next_tc'])
        else:
            log.info("Traffic Remove Passed")

class Configure_Same_static_ARP_on_2_vteps(nxtest.Testcase):
        #"TC_0068_Configure_Same_static_ARP_on_2_vteps"
    @aetest.test
    def Config_mac_bh_on_vpc_vtep(self,testbed):
        node3_s1_bgw_1 =testbed.devices['node7_s2_bgw_1']
        node4_s1_bgw_2 = testbed.devices['node4_s1_bgw_2']  
        node3_s1_bgw_1 =  testbed.devices['node3_s1_bgw_1']
        P3_dict = AcceSW_TGEN_data

        testbed.devices['node3_s1_bgw_1'].configure('''
            logging console 5
            mac address-table static ''' + str(P3_dict['mac']) + ''' vlan '''+ str(P3_dict['vlan_id']) + ''' drop

            interface vlan ''' + str(P3_dict['vlan_id']) + '''
                ip arp ''' + str(P3_dict['v4_addr']) + ''' ''' + str(P3_dict['mac']) + '''
        ''')
        testbed.devices['node4_s1_bgw_2'].configure('''
            logging console 5
            mac address-table static ''' + str(P3_dict['mac']) + ''' vlan '''+ str(P3_dict['vlan_id']) + ''' drop

            interface vlan ''' + str(P3_dict['vlan_id']) + '''
                ip arp ''' + str(P3_dict['v4_addr']) + ''' ''' + str(P3_dict['mac']) + '''
        ''')
    @aetest.test
    def Config_mac_bh_on_remote_vtep(self,testbed):
        node3_s1_bgw_1 =testbed.devices['node7_s2_bgw_1']
        node4_s1_bgw_2 = testbed.devices['node4_s1_bgw_2']  
        node3_s1_bgw_1 =  testbed.devices['node3_s1_bgw_1']
        P3_dict = AcceSW_TGEN_data

        testbed.devices['node7_s2_bgw_1'].configure(''' clear logging logfile ''')
        testbed.devices['node7_s2_bgw_1'].configure('''
            logging console 5
            mac address-table static ''' + str(P3_dict['mac']) + ''' vlan '''+ str(P3_dict['vlan_id']) + ''' drop

            interface vlan ''' + str(P3_dict['vlan_id']) + '''
                ip arp ''' + str(P3_dict['v4_addr']) + ''' ''' + str(P3_dict['mac']) + '''
        ''')
    @aetest.test
    def capture_syslog(self,testbed):
        output=testbed.devices['node7_s2_bgw_1'].configure(''' 
        sh logging logfile
        ''')
        log = 'Locally configured static MAC 0013.6022.0030 in topology: 1001 already present as remote static'
        if re.search(log,output):
            self.passed('Given static mac already present as remote static')
        else:
            self.failed('Locally configred static mac should be present as remote static,failed to learning as remote static')
    @aetest.test
    def Unconfig_mac_bh(self,testbed):
        node3_s1_bgw_1 =testbed.devices['node7_s2_bgw_1']
        node4_s1_bgw_2 = testbed.devices['node4_s1_bgw_2']  
        node3_s1_bgw_1 =  testbed.devices['node3_s1_bgw_1']
        P3_dict = AcceSW_TGEN_data

        testbed.devices['node3_s1_bgw_1'].configure('''
            no logging console 5
            no mac address-table static ''' + str(P3_dict['mac']) + ''' vlan '''+ str(P3_dict['vlan_id']) + ''' drop

            interface vlan ''' + str(P3_dict['vlan_id']) + '''
                no ip arp ''' + str(P3_dict['v4_addr']) + ''' ''' + str(P3_dict['mac']) + '''
        ''')
        testbed.devices['node4_s1_bgw_2'].configure('''
            no logging console 5
            no mac address-table static ''' + str(P3_dict['mac']) + ''' vlan '''+ str(P3_dict['vlan_id']) + ''' drop

            interface vlan ''' + str(P3_dict['vlan_id']) + '''
                no ip arp ''' + str(P3_dict['v4_addr']) + ''' ''' + str(P3_dict['mac']) + '''
        ''')
        testbed.devices['node7_s2_bgw_1'].configure('''
            no logging console 5
            no mac address-table static ''' + str(P3_dict['mac']) + ''' vlan '''+ str(P3_dict['vlan_id']) + ''' drop

            interface vlan ''' + str(P3_dict['vlan_id']) + '''
                no ip arp ''' + str(P3_dict['v4_addr']) + ''' ''' + str(P3_dict['mac']) + '''
        ''')  

class L2_mcast_traffic_to_and_from_BH_hosts(nxtest.Testcase):
    #"TC_0013_L2_mcast_traffic_to_and_from_BH_hosts"

    @aetest.test
    def CONNECT_IXIA_CHASSIS(self, testscript, testbed):

        # Get IXIA paraameters
        ixia_chassis_ip = testbed.devices['ixia'].connections.tgn.ixia_chassis_ip
        ixia_tcl_server = testbed.devices['ixia'].connections.tgn.ixnetwork_api_server_ip
        ixia_tcl_port = '8009'

        ixia_port_list  = testbed.devices['ixia'].connections.tgn.ixia_port_list
        #ixia_int_list   = []
        #for intPort in ixia_port_list:
        #    intPort_split = intPort.split('/')
        #    ixia_int_list.append([ixia_chassis_ip, intPort_split[0], intPort_split[1]])
        
        Ixia = testscript.parameters['ixia']=testbed.devices['ixia']
        print(Ixia)
        for interface in testbed.devices['ixia'].interfaces:
            if testbed.devices['ixia'].interfaces[interface].alias == Ixia.interfaces['6/29'].intf:
                tgen_nd03_1_1 = interface.name
            if testbed.devices['ixia'].interfaces[interface].alias == Ixia.interfaces['6/30'].intf:
                tgen_nd05_1_1 = interface.name
            if testbed.devices['ixia'].interfaces[interface].alias == Ixia.interfaces['6/31'].intf:
                tgen_nd10_1_1 = interface.name
            if testbed.devices['ixia'].interfaces[interface].alias == Ixia.interfaces['6/32'].intf:
                tgen_nd09_1_1 = interface.name

        ix_int_1 = Ixia.interfaces['6/31'].intf
        ix_int_2 =  Ixia.interfaces['6/30'].intf
        ix_int_3 = Ixia.interfaces['6/32'].intf
        ix_int_4 = Ixia.interfaces['6/29'].intf
        ixia_int_list= str(ix_int_1) + " " + str(ix_int_2) + " " + str(ix_int_3) + " " + str(ix_int_4)
        ixiaArgDict = {
                        'chassis_ip'    : ixia_chassis_ip,
                        'port_list'     : ixia_int_list,
                        'tcl_server'    : ixia_tcl_server,
                        'tcl_port'      : ixia_tcl_port
        }

        log.info("Ixia Args Dict is:")
        log.info(ixiaArgDict)

        result = ixLib.connect_to_ixia(ixiaArgDict)
        #print('result:'+result)
        if result == 0:
            log.debug("Connecting to ixia failed")
            self.errored("Connecting to ixia failed", goto=['next_tc'])

        ch_key = result['port_handle']
        for ch_p in ixia_chassis_ip.split('.'):
            ch_key = ch_key[ch_p]

        log.info("Port Handles are:")
        log.info(ch_key)

        testscript.parameters['port_handle_1'] = ch_key[ix_int_1]
        testscript.parameters['port_handle_2'] = ch_key[ix_int_2]
        testscript.parameters['port_handle_3'] = ch_key[ix_int_3]
        testscript.parameters['port_handle_4'] = ch_key[ix_int_4]
    @aetest.test
    def CREATE_IXIA_TOPOLOGIES(self, testscript):

        TOPO_1_dict = {'topology_name': 'S1_BGW1-TG',
                        'device_grp_name': 'S1_BGW1-TG',
                        'port_handle': testscript.parameters['port_handle_1']}

        TOPO_2_dict = {'topology_name': 'S1_Leaf-TG',
                        'device_grp_name': 'S1_Leaf-TG',
                        'port_handle': testscript.parameters['port_handle_2']}

        TOPO_3_dict = {'topology_name': 'AcceSW-TG',
                        'device_grp_name': 'AcceSW-TG',
                        'port_handle': testscript.parameters['port_handle_3']}

        TOPO_4_dict = {'topology_name': 'S2_Leaf-TG',
                        'device_grp_name': 'S2_Leaf-TG',
                        'port_handle': testscript.parameters['port_handle_4']}

        testscript.parameters['IX_TP1'] = ixLib.create_topo_device_grp(TOPO_1_dict)
        if testscript.parameters['IX_TP1'] == 0:
            log.debug("Creating Topology failed")
            self.errored("Creating Topology failed", goto=['next_tc'])
        else:
            log.info("Created topo1-TG Topology Successfully")

        testscript.parameters['IX_TP2'] = ixLib.create_topo_device_grp(TOPO_2_dict)
        if testscript.parameters['IX_TP2'] == 0:
            log.debug("Creating Topology failed")
            self.errored("Creating Topology failed", goto=['next_tc'])
        else:
            log.info("Created topo2-TG Topology Successfully")

        testscript.parameters['IX_TP3'] = ixLib.create_topo_device_grp(TOPO_3_dict)
        if testscript.parameters['IX_TP3'] == 0:
            log.debug("Creating Topology failed")
            self.errored("Creating Topology failed", goto=['next_tc'])
        else:
            log.info("Created topo3 -TG Topology Successfully")
        
        testscript.parameters['IX_TP4'] = ixLib.create_topo_device_grp(TOPO_4_dict)
        if testscript.parameters['IX_TP4'] == 0:
            log.debug("Creating Topology failed")
            self.errored("Creating Topology failed", goto=['next_tc'])
        else:
            log.info("Created topo4 -TG Topology Successfully")

        testscript.parameters['IX_TP1']['port_handle'] = testscript.parameters['port_handle_1']
        testscript.parameters['IX_TP2']['port_handle'] = testscript.parameters['port_handle_2']
        testscript.parameters['IX_TP3']['port_handle'] = testscript.parameters['port_handle_3']
        testscript.parameters['IX_TP4']['port_handle'] = testscript.parameters['port_handle_4']

    @aetest.test
    def CONFIGURE_IXIA_INTERFACES(self, testscript):

        P1 = testscript.parameters['port_handle_1']
        P2 = testscript.parameters['port_handle_2']
        P3 = testscript.parameters['port_handle_3']
        P4 = testscript.parameters['port_handle_4']

        P1_dict = S1_BGW1_TGEN_data
        P2_dict = S1_Leaf_TGEN_data
        P3_dict = AcceSW_TGEN_data
        P4_dict = S2_Leaf_TGEN_data


        P1_int_dict_1 = {'dev_grp_hndl': testscript.parameters['IX_TP1']['dev_grp_hndl'],
                             'port_hndl': P1,
                             'no_of_ints' :  P1_dict['no_of_ints'],
                             'phy_mode':  P1_dict['phy_mode'],
                             'mac':  P1_dict['mac'],
                             'mac_step': P1_dict['mac_step'],
                             'protocol': P1_dict['protocol'],
                             'v4_addr':  P1_dict['v4_addr'],
                             'v4_addr_step': P1_dict['v4_addr_step'],
                             'v4_gateway': P1_dict['v4_gateway'],
                             'v4_gateway_step':  P1_dict['v4_gateway_step'],
                             'v4_netmask': P1_dict['netmask'],
                             'v6_addr':  P1_dict['v6_addr'],
                             'v6_addr_step': P1_dict['v6_addr_step'],
                             'v6_gateway': P1_dict['v6_gateway'],
                             'v6_gateway_step':  P1_dict['v6_gateway_step'],
                             'v6_netmask':  P1_dict['v6_netmask'],
                             'vlan_id':  P1_dict['vlan_id'],
                             'vlan_user_priority': P1_dict['vlan_user_priority'],
                             'vlan_id_step': P1_dict['vlan_id_step'],
                             'frame_size': P1_dict['frame_size'],
                             'L3_dst_addr': P1_dict['L3_dst_addr']}

        P2_int_dict_1 = {'dev_grp_hndl': testscript.parameters['IX_TP2']['dev_grp_hndl'],
                             'port_hndl': P2,
                             'no_of_ints': P2_dict['no_of_ints'],
                             'phy_mode': P2_dict['phy_mode'],
                             'mac': P2_dict['mac'],
                             'mac_step': P2_dict['mac_step'],
                             'protocol': P2_dict['protocol'],
                             'v4_addr': P2_dict['v4_addr'],
                             'v4_addr_step': P2_dict['v4_addr_step'],
                             'v4_gateway': P2_dict['v4_gateway'],
                             'v4_gateway_step': P2_dict['v4_gateway_step'],
                             'v4_netmask': P2_dict['netmask'],
                             'v6_addr': P2_dict['v6_addr'],
                             'v6_addr_step': P2_dict['v6_addr_step'],
                             'v6_gateway': P2_dict['v6_gateway'],
                             'v6_gateway_step': P2_dict['v6_gateway_step'],
                             'v6_netmask': P2_dict['v6_netmask'],
                             'vlan_id': P2_dict['vlan_id'],
                             'vlan_user_priority': P1_dict['vlan_user_priority'],
                             'vlan_id_step': P2_dict['vlan_id_step'],
                             'frame_size': P2_dict['frame_size'],
                             'L3_dst_addr': P2_dict['L3_dst_addr']}
            
        P3_int_dict_1 = {'dev_grp_hndl': testscript.parameters['IX_TP3']['dev_grp_hndl'],
                             'port_hndl': P3,
                             'no_of_ints': P3_dict['no_of_ints'],
                             'phy_mode': P3_dict['phy_mode'],
                             'mac': P3_dict['mac'],
                             'mac_step': P3_dict['mac_step'],
                             'protocol': P3_dict['protocol'],
                             'v4_addr': P3_dict['v4_addr'],
                             'v4_addr_step': P3_dict['v4_addr_step'],
                             'v4_gateway': P3_dict['v4_gateway'],
                             'v4_gateway_step': P3_dict['v4_gateway_step'],
                             'v4_netmask': P3_dict['netmask'],
                             'v6_addr': P3_dict['v6_addr'],
                             'v6_addr_step': P3_dict['v6_addr_step'],
                             'v6_gateway': P3_dict['v6_gateway'],
                             'v6_gateway_step': P3_dict['v6_gateway_step'],
                             'v6_netmask': P3_dict['v6_netmask'],
                             'vlan_id': P3_dict['vlan_id'],
                             'vlan_user_priority': P3_dict['vlan_user_priority'],
                             'vlan_id_step': P3_dict['vlan_id_step'],
                             'frame_size': P3_dict['frame_size'],
                             'L3_dst_addr': P3_dict['L3_dst_addr']}
            
        P4_int_dict_1 = {'dev_grp_hndl': testscript.parameters['IX_TP4']['dev_grp_hndl'],
                             'port_hndl': P4,
                             'no_of_ints': P4_dict['no_of_ints'],
                             'phy_mode': P4_dict['phy_mode'],
                             'mac': P4_dict['mac'],
                             'mac_step': P4_dict['mac_step'],
                             'protocol': P4_dict['protocol'],
                             'v4_addr': P4_dict['v4_addr'],
                             'v4_addr_step': P4_dict['v4_addr_step'],
                             'v4_gateway': P4_dict['v4_gateway'],
                             'v4_gateway_step': P4_dict['v4_gateway_step'],
                             'v4_netmask': P4_dict['netmask'],
                             'v6_addr': P4_dict['v6_addr'],
                             'v6_addr_step': P4_dict['v6_addr_step'],
                             'v6_gateway': P4_dict['v6_gateway'],
                             'v6_gateway_step': P4_dict['v6_gateway_step'],
                             'v6_netmask': P4_dict['v6_netmask'],
                             'vlan_id': P4_dict['vlan_id'],
                             'vlan_user_priority': P4_dict['vlan_user_priority'],
                             'vlan_id_step': P4_dict['vlan_id_step'],
                             'frame_size': P4_dict['frame_size'],
                             'L3_dst_addr': P4_dict['L3_dst_addr']}

        P1_IX_int_data = ixLib.configure_multi_ixia_interface(P1_int_dict_1)
        P2_IX_int_data = ixLib.configure_multi_ixia_interface(P2_int_dict_1)
        P3_IX_int_data = ixLib.configure_multi_ixia_interface(P3_int_dict_1)
        P4_IX_int_data = ixLib.configure_multi_ixia_interface(P4_int_dict_1)


        if P1_IX_int_data == 0 or P2_IX_int_data == 0 or P3_IX_int_data == 0 or P4_IX_int_data == 0:
            log.debug("Configuring IXIA Interface failed")
            self.errored("Configuring IXIA Interface failed", goto=['next_tc'])
        else:
            log.info("Configured IXIA Interface Successfully")

        testscript.parameters['IX_TP1']['eth_handle'] = P1_IX_int_data['eth_handle']
        testscript.parameters['IX_TP1']['ipv4_handle'] = P1_IX_int_data['ipv4_handle']
        testscript.parameters['IX_TP1']['ipv6_handle'] = P1_IX_int_data['ipv6_handle']
        #testscript.parameters['IX_TP1']['port_handle'] = P1_IX_int_data['port_hndl']
        testscript.parameters['IX_TP1']['topo_int_handle'] = P1_IX_int_data['topo_int_handle'].split(" ")

        testscript.parameters['IX_TP2']['eth_handle'] = P2_IX_int_data['eth_handle']
        testscript.parameters['IX_TP2']['ipv4_handle'] = P2_IX_int_data['ipv4_handle']
        testscript.parameters['IX_TP2']['ipv6_handle'] = P2_IX_int_data['ipv6_handle']
        #testscript.parameters['IX_TP2']['port_handle'] = P2_IX_int_data['port_hndl']
        testscript.parameters['IX_TP2']['topo_int_handle'] = P2_IX_int_data['topo_int_handle'].split(" ")

        testscript.parameters['IX_TP3']['eth_handle'] = P3_IX_int_data['eth_handle']
        testscript.parameters['IX_TP3']['ipv4_handle'] = P3_IX_int_data['ipv4_handle']
        testscript.parameters['IX_TP3']['ipv6_handle'] = P3_IX_int_data['ipv6_handle']
        #testscript.parameters['IX_TP3']['port_handle'] = P3_IX_int_data['port_hndl']
        testscript.parameters['IX_TP3']['topo_int_handle'] = P3_IX_int_data['topo_int_handle'].split(" ")

        testscript.parameters['IX_TP4']['eth_handle'] = P4_IX_int_data['eth_handle']
        testscript.parameters['IX_TP4']['ipv4_handle'] = P4_IX_int_data['ipv4_handle']
        testscript.parameters['IX_TP4']['ipv6_handle'] = P4_IX_int_data['ipv6_handle']
        #testscript.parameters['IX_TP4']['port_handle'] = P4_IX_int_data['port_hndl']
        testscript.parameters['IX_TP4']['topo_int_handle'] = P4_IX_int_data['topo_int_handle'].split(" ")



        log.info("IXIA Port 1 Handles")
        log.info(testscript.parameters['IX_TP1'])
        log.info("IXIA Port 2 Handles")
        log.info(testscript.parameters['IX_TP2'])
        log.info("IXIA Port 2 Handles")
        log.info(testscript.parameters['IX_TP3'])
        log.info("IXIA Port 2 Handles")
        log.info(testscript.parameters['IX_TP4'])

    stream_id=''
    @aetest.test
    def Configure_Mcast_Ixia_traffic_stream(self,testbed,testscript):

        IX_TP4 = testscript.parameters['IX_TP4']
        P1_dict = S1_BGW1_TGEN_data
        P2_dict = S1_Leaf_TGEN_data
        P3_dict = AcceSW_TGEN_data
        P4_dict = S2_Leaf_TGEN_data

        IGMP_dict_1 = {
                        'ipv4_hndl'          : IX_TP4['ipv4_handle'],
                        'igmp_ver'          : P4_dict['igmp_ver'],
                        'mcast_grp_ip'      : P4_dict['mcast_grp_ip'],
                        'mcast_grp_ip_step' : P4_dict['mcast_grp_ip_step'],
                        'no_of_grps'        : P4_dict['no_of_grps'],
                        'mcast_src_ip'      : P3_dict['v4_addr'],
                        'mcast_src_ip_step' : P4_dict['v4_addr_step'],
                        'mcast_src_ip_step_per_port': P4_dict['v4_addr_step'],
                        'mcast_grp_ip_step_per_port': P4_dict['v4_addr_step'],
                        'mcast_no_of_srcs'  : P4_dict['no_of_mcast_sources'],
                        'topology_handle'   : IX_TP4['topo_hndl']
                        }

        IGMP_EML = ixLib.emulate_igmp_groupHost(IGMP_dict_1)

        if IGMP_EML == 0:
            log.debug("Configuring IGMP failed")
            self.errored("Configuring IGMP failed")
        else:
            log.info("Configured IGMP Successfully")
            global stream_id
            stream_id = IGMP_EML

        
        
        testscript.parameters['IX_TP4']['igmpHost_handle'] = []
        testscript.parameters['IX_TP4']['igmp_group_handle'] = []
        testscript.parameters['IX_TP4']['igmp_source_handle'] = []
        testscript.parameters['IX_TP4']['igmpMcastGrpList'] = []

        testscript.parameters['IX_TP4']['igmpHost_handle'].append(IGMP_EML['igmpHost_handle'])
        testscript.parameters['IX_TP4']['igmp_group_handle'].append(IGMP_EML['igmp_group_handle'])
        testscript.parameters['IX_TP4']['igmp_source_handle'].append(IGMP_EML['igmp_source_handle'])
        testscript.parameters['IX_TP4']['igmpMcastGrpList'].append(IGMP_EML['igmpMcastGrpList'])
            

    @aetest.test
    def START_IXIA_PROTOCOLS(self):
        """ IXIA_CONFIGURATION subsection: Configure IXIA IGMP Groups """

        # _result_ = ixiahlt.test_control(action='configure_all')
        # print(_result_)
        proto_result = ixLib.start_protocols()
        if proto_result == 0:
            log.debug("Starting Protocols failed")
            self.errored("Starting Protocols failed", goto=['cleanup'])
        else:
            log.info("Started Protocols Successfully")

        time.sleep(60)

        proto_result = ixLib.stop_protocols()
        if proto_result == 0:
            log.debug("Stopped Protocols failed")
            self.errored("Stopped Protocols failed", goto=['cleanup'])
        else:
            log.info("Stopped Protocols Successfully")

        time.sleep(30)

        proto_result = ixLib.start_protocols()
        if proto_result == 0:
            log.debug("Starting Protocols failed")
            self.errored("Starting Protocols failed", goto=['cleanup'])
        else:
            log.info("Started Protocols Successfully")

        time.sleep(120)

    @aetest.test
    def VERIFY_IXIA_TRAFFIC_With_BH_Route(self, testscript):
        """ IXIA_CONFIGURATION subsection: Verify IXIA Traffic """

        # Do not perform configurations if skip_tgen_config flag is set
        #if not testscript.parameters['script_flags']['skip_tgen_config']:

        time.sleep(20)

        if ixLib.verify_traffic(99) == 1:
            log.debug("Traffic Verification Passed.")
            # ForkedPdb().set_trace() 
        else:
            log.info("Traffic Verification Failed.")
            self.failed("Traffic Verification failed")
    
    @aetest.test
    def Configure_Mac_BH_route_For_Hosts(self,testbed):
        node3_s1_bgw_1 = testbed.devices['node3_s1_bgw_1']
        node7_s2_bgw_1 =testbed.devices['node7_s2_bgw_1']
        P3_dict = AcceSW_TGEN_data
        mac= str(P3_dict['mac'])
        vlan= str(P3_dict['vlan_id'])
        ip=str(P3_dict['v4_addr'])
        octet = 1
        no_int= int(P3_dict['no_of_ints'])
        
        for i in range (0,no_int):
            ###LEAF_3_MAC_BH_ROUTE
            testbed.devices['node3_s1_bgw_1'].configure('''
                mac address-table static ''' + str(mac) + ''' vlan '''+ str(vlan) + ''' drop

                interface vlan ''' + str(vlan) + '''
                  ip arp ''' + str(ip) + ''' ''' + str(mac) + '''
            ''')
            lasthex=incr_mac(mac)
            mac=mac[0:10]+lasthex
            vlan= int(vlan)+int(P3_dict['vlan_id_step'])
            ip=incr_ip(ip,octet)


    @aetest.test
    def VERIFY_IXIA_TRAFFIC_With_BH_Route(self, testscript):
        """ IXIA_CONFIGURATION subsection: Verify IXIA Traffic """

        # Do not perform configurations if skip_tgen_config flag is set
        #if not testscript.parameters['script_flags']['skip_tgen_config']:

        time.sleep(20)

        if ixLib.verify_traffic(99) == 0:
            log.debug("Traffic Verification Passed.")
            # ForkedPdb().set_trace() 
        else:
            log.info("Traffic Verification Failed.")
            self.failed("Traffic Verification failed") 
    
    @aetest.test
    def UnConfigure_Mac_BH_route_For_Hosts(self,testbed):
        node3_s1_bgw_1 = testbed.devices['node3_s1_bgw_1']
        node7_s2_bgw_1 =testbed.devices['node7_s2_bgw_1']
        P3_dict = AcceSW_TGEN_data
        mac= str(P3_dict['mac'])
        vlan= str(P3_dict['vlan_id'])
        ip=str(P3_dict['v4_addr'])
        octet = 1
        no_int= int(P3_dict['no_of_ints'])
        
        for i in range (0,no_int):
            ###LEAF_3_MAC_BH_ROUTE
            testbed.devices['node3_s1_bgw_1'].configure('''
                
                no mac address-table static ''' + str(mac) + ''' vlan '''+ str(vlan) + ''' drop

                interface vlan ''' + str(vlan) + '''
                  no ip arp ''' + str(ip) + ''' ''' + str(mac) + '''
            ''')
            lasthex=incr_mac(mac)
            mac=mac[0:10]+lasthex
            vlan= int(vlan)+int(P3_dict['vlan_id_step'])
            ip=incr_ip(ip,octet)

           

    @aetest.test
    def cleanup(self,testscript, testbed):
        """Unconfigure qos policies"""
        node3_s1_bgw_1 =  testbed.devices['node3_s1_bgw_1']  
        node7_s2_bgw_1 =  testbed.devices['node7_s2_bgw_1']
        P1_dict = S1_BGW1_TGEN_data
        forwardingSysDict = FWD_SYS_dict
        # Stop Traffic from ixia
        log.info("--- Stopping Traffic ---- \n")
        log.info("Stopping Traffic")
        traffic_run_status = ixLib.stop_traffic()
        
        if traffic_run_status is not 1:
            log.info("Failed: To Stop traffic")
            return 0
        else:
            log.info("\nTraffic Stopped successfully\n")
        time.sleep(10)

class Remote_Static_ARP_entry(nxtest.Testcase):
    #"TC_0065_Remote_Static_ARP_entry"
    stream_id=''
    @aetest.test
    def CONFIGURE_L2_UCAST_IXIA_TRAFFIC_H2_to_H1(self, testscript):
        """ IXIA_CONFIGURATION subsection: Configure MCAST Traffic Item """

        # Do not perform configurations if skip_tgen_config flag is set
        #if not testscript.parameters['script_flags']['skip_tgen_config']:

        IX_TP1 = testscript.parameters['IX_TP1']
        IX_TP2 = testscript.parameters['IX_TP2']
        IX_TP3 = testscript.parameters['IX_TP3']
        P1_dict = S1_BGW1_TGEN_data
        P2_dict = S1_Leaf_TGEN_data
        P3_dict = AcceSW_TGEN_data
        P4_dict = S2_Leaf_TGEN_data
        # P1_dict = S1_BGW1_TGEN_data
        # P4_dict = testscript.parameters['S2_BGW1_TGEN_dict']

        UCAST_v4_dict = {   'src_hndl'  : IX_TP3['ipv4_handle'],
                            'dst_hndl'  : IX_TP1['ipv4_handle'],
                            'circuit'   : 'ipv4',
                            'TI_name'   : "UCAST_V4",
                            'rate_pps'  : "10000",
                            'bi_dir'    : 1,
                            'bidirectional': '0'
                        }

        UCAST_v4_TI = ixLib.configure_ixia_traffic_item_v46(UCAST_v4_dict)
            
        if UCAST_v4_TI == 0:
            log.debug("Configuring UCast L2 TI failed")
            self.errored("Configuring UCast L2 TI failed", goto=['next_tc'])
        else:
            global stream_id
            stream_id = UCAST_v4_TI
            log.info('stream_id='+stream_id)
            log.info(type(stream_id))
        # else:
        #     self.passed(reason="Skipped TGEN Configurations as per request")
    
    @aetest.test
    def APPLY_TRAFFIC(self):
        """ IXIA_CONFIGURATION subsection: Verify IXIA Traffic """

        # Apply IXIA Traffic
        if ixLib.apply_traffic() == 1:
            log.info("Applying IXIA TI Passed")
        else:
            self.errored("Applying IXIA TI failed")
    
    @aetest.test
    def VERIFY_IXIA_TRAFFIC_Without_BH_Route(self, testscript):
        """ IXIA_CONFIGURATION subsection: Verify IXIA Traffic """

        # Do not perform configurations if skip_tgen_config flag is set
        #if not testscript.parameters['script_flags']['skip_tgen_config']:

        time.sleep(20)

        if ixLib.verify_traffic(1) == 1:
            log.debug("Traffic Verification Passed.Expecting traffic loss here.") 
            #ForkedPdb().set_trace()
        else:
            log.info("Traffic Verification Failed. Expecting traffic loss here.")
            self.failed("Traffic Verification failed")
    
    @aetest.test
    def verify_arp_database(self,testbed,v4_addr,Age,vlan,mac):
        node3_s1_bgw_1 =testbed.devices['node3_s1_bgw_1']
        node4_s1_bgw_2 = testbed.devices['node4_s1_bgw_2']
        P3_dict = AcceSW_TGEN_data
        P1_dict = S1_BGW1_TGEN_data

        output=json.loads(testbed.devices['node3_s1_bgw_1'].execute(''' Sh ip arp ''' + P1_dict['v4_addr'] + ''' vrf vrf-1 '''))
        m=re.search(re.escape(str(v4_addr))+'\s+Age'+ re.escape(str(Age))+ '\s+' +re.search(str(mac))+'\s+vlan' + re.escape(str(vlan))+'\s+ ' ' ')
        if m:
            self.passed('route is present without BH')
        else:
            self.failed('failed to learn route')
    
    @aetest.test
    def Config_mac_bh_on_remote_vtep(self,testbed):
        node3_s1_bgw_1 =testbed.devices['node7_s2_bgw_1']
        node4_s1_bgw_2 = testbed.devices['node4_s1_bgw_2']  
        node3_s1_bgw_1 =  testbed.devices['node3_s1_bgw_1']
        P3_dict = AcceSW_TGEN_data
        P1_dict = S1_BGW1_TGEN_data

        testbed.devices['node7_s2_bgw_1'].configure('''
            
            mac address-table static ''' + str(P1_dict['mac']) + ''' vlan '''+ str(P1_dict['vlan_id']) + ''' drop

            interface vlan ''' + str(P1_dict['vlan_id']) + '''
                ip arp ''' + str(P1_dict['v4_addr']) + ''' ''' + str(P1_dict['mac']) + '''
        ''')

    
    @aetest.test
    def APPLY_TRAFFIC(self):
        """ IXIA_CONFIGURATION subsection: Verify IXIA Traffic """

        # Apply IXIA Traffic
        if ixLib.apply_traffic() == 1:
            log.info("Applying IXIA TI Passed")
        else:
            self.errored("Applying IXIA TI failed")
    
    @aetest.test
    def VERIFY_IXIA_TRAFFIC_With_BH_Route(self, testscript):
        """ IXIA_CONFIGURATION subsection: Verify IXIA Traffic """

        # Do not perform configurations if skip_tgen_config flag is set
        #if not testscript.parameters['script_flags']['skip_tgen_config']:

        time.sleep(20)

        if ixLib.verify_traffic(99) == 0:
            log.debug("Traffic Verification Passed.Expecting traffic loss here.") 
            #ForkedPdb().set_trace()
        else:
            log.info("Traffic Verification Failed. Expecting traffic loss here.")
            self.failed("Traffic Verification failed")
    
    @aetest.test
    def Verify_BH_states_in_remote_ARP(self, testscript,testbed):
        node3_s1_bgw_1 =testbed.devices['node3_s1_bgw_1']
        node7_s2_bgw_1 = testbed.devices['node7_s2_bgw_1']
        P3_dict = AcceSW_TGEN_data
        P1_dict = S1_BGW1_TGEN_data

        try: 

            if verify_BH_in_Remote_ARP(node3_s1_bgw_1,str(P1_dict['vlan_id']),str(P1_dict['mac'])):
               log.info('Mac BH route is proper in Remote ARP on  S2_BGW1')
            else:
                log.info('Mac BH route is improper in Remote ARP on  S2_BGW1')
                self.failed('Mac BH route is improper in Remote ARP on  S2_BGW1')

        except Exception as error:
            log.debug("Unable to configure static BH mac route on Remote Vtep- Encountered Exception " + str(error))
            self.errored('Exception occurred while configuring static BH mac route on Remote Vtep')        
    @aetest.test
    def Verify_BH_states_in_local_ARP(self, testscript,testbed):
        node3_s1_bgw_1 = testbed.devices['node3_s1_bgw_1']
        node7_s2_bgw_1 = testbed.devices['node7_s2_bgw_1']
        P1_dict = S1_BGW1_TGEN_data
        P2_dict = S1_Leaf_TGEN_data
        P3_dict = AcceSW_TGEN_data
        P4_dict = S2_Leaf_TGEN_data
        try:        
            if verify_BH_in_local_ARP(node7_s2_bgw_1,str(P1_dict['vlan_id']),str(P1_dict['mac'])):
                log.info('Mac BH route is proper in Local ARP on  S1_BGW1')
            else:
                log.info('Mac BH route is improper in Local ARP on  S1_BGW1')
                self.failed('Mac BH route is improper in Local ARP on  S1_BGW1')
        
        except Exception as error:
            log.debug("Unable to configure static BH mac route on Remote Vtep- Encountered Exception " + str(error))
            self.errored('Exception occurred while configuring static BH mac route on Remote Vtep')

    @aetest.test
    def UnConfig_mac_bh_on_remote_vtep(self,testbed):
        node3_s1_bgw_1 =testbed.devices['node7_s2_bgw_1']
        node4_s1_bgw_2 = testbed.devices['node4_s1_bgw_2']  
        node3_s1_bgw_1 =  testbed.devices['node3_s1_bgw_1']
        P3_dict = AcceSW_TGEN_data
        P1_dict = S1_BGW1_TGEN_data

        testbed.devices['node7_s2_bgw_1'].configure('''
            
            no mac address-table static ''' + str(P1_dict['mac']) + ''' vlan '''+ str(P1_dict['vlan_id']) + ''' drop

            interface vlan ''' + str(P1_dict['vlan_id']) + '''
                no ip arp ''' + str(P1_dict['v4_addr']) + ''' ''' + str(P1_dict['mac']) + '''
        ''')

    @aetest.test
    def cleanup(self,testscript, testbed):
        """Unconfigure qos policies"""
        node3_s1_bgw_1 =  testbed.devices['node3_s1_bgw_1']
        node5_s1_leaf_1 =  testbed.devices['node5_s1_leaf_1']
        node10_s1_AccessSW =  testbed.devices['node10_s1_AccessSW']
        node7_s2_bgw_1 =  testbed.devices['node7_s2_bgw_1']
        P3_dict = AcceSW_TGEN_data
        forwardingSysDict = FWD_SYS_dict
        # Stop Traffic from ixia
        log.info("--- Stopping Traffic ---- \n")
        log.info("Stopping Traffic")
        traffic_run_status = ixLib.stop_traffic()
        
        if traffic_run_status is not 1:
            log.info("Failed: To Stop traffic")
            return 0
        else:
            log.info("\nTraffic Stopped successfully\n")
        time.sleep(10)
        ####Remove traffic item configured
        UCAST_v4_dict = {
                        'mode'        : 'remove',
                        'stream_id'   : stream_id,
                    }
        if (ixLib.delete_traffic_item(UCAST_v4_dict))==0:
            log.debug("Traffic Remove failed")
            self.failed("Traffic Remove failed", goto=['next_tc'])
        else:
            log.info("Traffic Remove Passed")
        ###LEAF_1_MAC_BH_ROUTE

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

class TriggerMCTFlap(nxtest.Testcase):
    @aetest.test
    def MCTFlap(self, testbed):
        P1 = S1_BGW1_dict
        # device = testbed.devices[node]
        a=testbed.devices['node3_s1_bgw_1'].execute(''' show interface port-channel ''' + str(P1['S1_BGW1_UPLINK_PO']['peer_link']) + ''' brief''')
        if re.search("up",a):
            log.info('peer link is up')
            testbed.devices['node3_s1_bgw_1'].configure(''' 
                interface port-channel ''' + str(P1['S1_BGW1_UPLINK_PO']['peer_link']) + '''
                    shutdown
            ''')
            time.sleep(20)
            b=testbed.devices['node3_s1_bgw_1'].execute(''' show interface port-channel ''' + str(P1['S1_BGW1_UPLINK_PO']['peer_link']) + ''' brief''')
            if re.search("down",b):
                log.info('peer link is down,Expected peer link should down')
            else:
                log.info('configuration not working')
                self.failed('flaping peer link is failed')
            time.sleep(60)
            testbed.devices['node3_s1_bgw_1'].configure(''' 
                interface port-channel''' + str(P1['S1_BGW1_UPLINK_PO']['peer_link']) + '''
                    no shutdown
            ''')
            time.sleep(20)
            a=testbed.devices['node3_s1_bgw_1'].execute(''' show interface port-channel ''' + str(P1['S1_BGW1_UPLINK_PO']['peer_link']) + ''' brief''')
            if re.search("up",a):
                log.info('peer link is up')
            else:
                self.failed('peer link is down')
        else:
            log.info('peer link is down,it should be up')
            self.failed('peer link is down')
        

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

class BGP_PROCESS_RESTART(nxtest.Testcase):
    #"TC_0087_BGP_PROCESS_RESTART",
   

    stream_id_2=''
    @aetest.test
    def CONFIGURE_L2_UCAST_IXIA_TRAFFIC_H4_to_H1(self, testscript):
        """ IXIA_CONFIGURATION subsection: Configure MCAST Traffic Item """

        # Do not perform configurations if skip_tgen_config flag is set
        #if not testscript.parameters['script_flags']['skip_tgen_config']:

        IX_TP1 = testscript.parameters['IX_TP1']
        IX_TP2 = testscript.parameters['IX_TP2']
        IX_TP3 = testscript.parameters['IX_TP3']
        IX_TP4 = testscript.parameters['IX_TP4']
        P1_dict = S1_BGW1_TGEN_data
        P2_dict = S1_Leaf_TGEN_data
        P3_dict = AcceSW_TGEN_data
        P4_dict = S2_Leaf_TGEN_data
        # P1_dict = S1_BGW1_TGEN_data
        # P4_dict = testscript.parameters['S2_BGW1_TGEN_dict']

        UCAST_v4_dict_3 = {   'src_hndl'  : IX_TP4['ipv4_handle'],
                            'dst_hndl'  : IX_TP3['ipv4_handle'],
                            'circuit'   : 'ipv4',
                            'TI_name'   : "UCAST_V4",
                            'rate_pps'  : "10000",
                            'bi_dir'    : 1,
                            'bidirectional': '0'
                        }

        UCAST_v4_TI_2 = ixLib.configure_ixia_traffic_item_v46(UCAST_v4_dict_3)
            
        if UCAST_v4_TI_2 == 0:
            log.debug("Configuring UCast L2 TI failed")
            self.errored("Configuring UCast L2 TI failed", goto=['next_tc'])
        else:
            global stream_id_2
            stream_id_2 = UCAST_v4_TI_2
    
    # =============================================================================================================================#
    @aetest.test
    def APPLY_TRAFFIC(self):
        """ IXIA_CONFIGURATION subsection: Verify IXIA Traffic """

        # Apply IXIA Traffic
        if ixLib.apply_traffic() == 1:
            log.info("Applying IXIA TI Passed")
        else:
            self.errored("Applying IXIA TI failed", goto=['cleanup'])
            
        # =============================================================================================================================#
    @aetest.test
    def VERIFY_IXIA_TRAFFIC_before_restart(self, testscript):
        """ IXIA_CONFIGURATION subsection: Verify IXIA Traffic """

        # Do not perform configurations if skip_tgen_config flag is set
    

        time.sleep(20)

        if ixLib.verify_traffic(2) == 0:
            log.debug("Traffic Verification failed")
            self.failed("Traffic Verification failed", goto=['cleanup'])
        else:
            log.info("Traffic Verification Passed")
    
    #--------------------------------------------------------------------------------#
        # Start traffic from ixia
        log.info("--- Populating the statistics --- \n")
        log.info("---- Running Traffic --- \n")
        log.info("Starting Traffic")

        traffic_run_status  = ixLib.start_traffic()

        if traffic_run_status is not 1:
           log.info("Failed: To start traffic")
           return 0
        else:
            log.info("\nTraffic started successfully\n")

        time.sleep(10)
        
    # =============================================================================================================================#
    # def config_mac_BH_route(testbed):
    #     node3_s1_bgw_1 = testbed.devices['node3_s1_bgw_1']
    #     node4_s1_bgw_2 =  testbed.devices['node4_s1_bgw_2']
    #     P3_dict = AcceSW_TGEN_data
    

    
    #     testbed.devices['node3_s1_bgw_1'].configure('''
    #         mac address-table static ''' + str(P3_dict['mac']) + ''' vlan '''+ str(P3_dict['vlan_id']) + ''' drop

    #         interface vlan ''' + str(P3_dict['vlan_id']) + '''
    #             ipv6 neighbor ''' + str(P3_dict['v6_addr']) + ''' ''' + str(P3_dict['mac']) + '''
    #             ip arp ''' + str(P3_dict['v4_addr']) + ''' ''' + str(P3_dict['mac']) + '''
    #     ''')
    #     testbed.devices['node4_s1_bgw_2'].configure('''
    #         mac address-table static ''' + str(P3_dict['mac']) + ''' vlan '''+ str(P3_dict['vlan_id']) + ''' drop

    #         interface vlan ''' + str(P3_dict['vlan_id']) + '''
    #             ipv6 neighbor ''' + str(P3_dict['v6_addr']) + ''' ''' + str(P3_dict['mac']) + '''
    #             ip arp ''' + str(P3_dict['v4_addr']) + ''' ''' + str(P3_dict['mac']) + '''
    #     ''')

    @aetest.test
    def TRIGGER_verify_BGP_process_restart(self, testscript,testbed):
        """ ACLQOS_PROCESS_KILL_VERIFICATION subsection: Verify killing process ACLQOS """

        node3_s1_bgw_1 = testbed.devices['node3_s1_bgw_1']
        node5_s1_leaf_1 = testbed.devices['node5_s1_leaf_1']
        node4_s1_bgw_2 = testbed.devices['node4_s1_bgw_2']
        node7_s2_bgw_1 = testbed.devices['node7_s2_bgw_1']
        node9_s2_leaf_1 = testbed.devices['node9_s2_leaf_1']
        P3_dict = AcceSW_TGEN_data

        mac= str(P3_dict['mac'])
        vlan= str(P3_dict['vlan_id'])
        ip=str(P3_dict['v4_addr'])
        octet = 1
        no_int= int(P3_dict['no_of_ints'])
        
        for i in range (0,no_int):
            ###LEAF_3_MAC_BH_ROUTE
            testbed.devices['node3_s1_bgw_1'].configure('''
                mac address-table static ''' + str(mac) + ''' vlan '''+ str(vlan) + ''' drop

                interface vlan ''' + str(vlan) + '''
                  ip arp ''' + str(ip) + ''' ''' + str(mac) + '''
            ''')
            testbed.devices['node4_s1_bgw_2'].configure('''
                mac address-table static ''' + str(mac) + ''' vlan '''+ str(vlan) + ''' drop

                interface vlan ''' + str(vlan) + '''
                  ip arp ''' + str(ip) + ''' ''' + str(mac) + '''
            ''')
            lasthex=incr_mac(mac)
            mac=mac[0:10]+lasthex
            vlan= int(vlan)+int(P3_dict['vlan_id_step'])
            ip=incr_ip(ip,octet)

        if infraTrig.verifyProcessRestart(node3_s1_bgw_1,"bgp"):
            log.info("Successfully restarted process BGP")
        else:
            log.debug("Failed to restarted process BGP")
            self.failed("Failed to restarted process BGP", goto=['cleanup'])
        time.sleep(120)

        if infraTrig.verifyProcessRestart(node4_s1_bgw_2,"bgp"):
            log.info("Successfully restarted process BGP")
        else:
            log.debug("Failed to restarted process BGP")
            self.failed("Failed to restarted process BGP", goto=['cleanup'])
        time.sleep(120)

        if infraTrig.verifyProcessRestart(node7_s2_bgw_1,"bgp"):
            log.info("Successfully restarted process BGP")
        else:
            log.debug("Failed to restarted process BGP")
            self.failed("Failed to restarted process BGP", goto=['cleanup'])
        time.sleep(120)

    # =============================================================================================================================#  
    
    @aetest.test
    def VERIFY_IXIA_TRAFFIC(self, testscript):
        """ IXIA_CONFIGURATION subsection: Verify IXIA Traffic """

        # Do not perform configurations if skip_tgen_config flag is set
       

        time.sleep(20)

        if ixLib.verify_traffic(2) == 1:
            log.debug("Traffic Verification failed")
            self.failed("Traffic Verification failed", goto=['cleanup'])
        else:
            log.info("Traffic Verification Passed")

    
    @aetest.test
    def Verify_BH_states_in_HMM(self, testscript,testbed):
        node3_s1_bgw_1 =testbed.devices['node3_s1_bgw_1']
        node4_s1_bgw_2 = testbed.devices['node4_s1_bgw_2']
        node7_s2_bgw_1 = testbed.devices['node7_s2_bgw_1']
        P3_dict = AcceSW_TGEN_data

        try:
            if verify_BH_in_HMM(node4_s1_bgw_2,str(P3_dict['v4_addr'])):
                log.info('Mac BH route is proper in HMM on  S1_BGW1')
            else:
                log.info('Mac BH route is improper in HMM on  S1_BGW1')
                self.failed('Mac BH route is improper in HMM on  S1_BGW1')
        
         
        except Exception as error:
            log.debug("Unable to configure static BH mac route on Remote Vtep- Encountered Exception " + str(error))
            self.errored('Exception occurred while configuring static BH mac route on Remote Vtep', goto=['cleanup'])
    @aetest.test
    def Verify_BH_states_in_AM(self, testscript,testbed):
        node3_s1_bgw_1 = testbed.devices['node3_s1_bgw_1']
        node4_s1_bgw_2 = testbed.devices['node4_s1_bgw_2']
        node7_s2_bgw_1 = testbed.devices['node7_s2_bgw_1']
        P1_dict = S1_BGW1_TGEN_data
        P2_dict = S1_Leaf_TGEN_data
        P3_dict = AcceSW_TGEN_data
        P4_dict = S2_Leaf_TGEN_data

        try:        
            if verify_BH_in_AM(node4_s1_bgw_2,str(P3_dict['mac']),str(P3_dict['vlan_id']),str(P3_dict['v4_addr'])):
                log.info('Mac BH route is proper in AM on  S1_BGW1')
            else:
                log.info('Mac BH route is improper in AM on  S1_BGW1')
                self.failed('Mac BH route is improper in AM on  S1_BGW1')
                   
        
        except Exception as error:
            log.debug("Unable to configure static BH mac route on Remote Vtep- Encountered Exception " + str(error))
            self.errored('Exception occurred while configuring static BH mac route on Remote Vtep', goto=['cleanup'])
    @aetest.test
    def Verify_BH_states_in_remote_ARP(self, testscript,testbed):
        node3_s1_bgw_1 =testbed.devices['node3_s1_bgw_1']
        node7_s2_bgw_1 = testbed.devices['node7_s2_bgw_1']
        P3_dict = AcceSW_TGEN_data

        try: 

            if verify_BH_in_Remote_ARP(node7_s2_bgw_1,str(P3_dict['vlan_id']),str(P3_dict['mac'])):
               log.info('Mac BH route is proper in Remote ARP on  S2_BGW1')
            else:
                log.info('Mac BH route is improper in Remote ARP on  S2_BGW1')
                self.failed('Mac BH route is improper in Remote ARP on  S2_BGW1')

        except Exception as error:
            log.debug("Unable to configure static BH mac route on Remote Vtep- Encountered Exception " + str(error))
            self.errored('Exception occurred while configuring static BH mac route on Remote Vtep')        
    @aetest.test
    def Verify_BH_states_in_local_ARP(self, testscript,testbed):
        node3_s1_bgw_1 = testbed.devices['node3_s1_bgw_1']
        node7_s2_bgw_1 = testbed.devices['node7_s2_bgw_1']
        P1_dict = S1_BGW1_TGEN_data
        P2_dict = S1_Leaf_TGEN_data
        P3_dict = AcceSW_TGEN_data
        P4_dict = S2_Leaf_TGEN_data
        try:        
            if verify_BH_in_local_ARP(node3_s1_bgw_1,str(P3_dict['vlan_id']),str(P3_dict['mac'])):
                log.info('Mac BH route is proper in Local ARP on  S1_BGW1')
            else:
                log.info('Mac BH route is improper in Local ARP on  S1_BGW1')
                self.failed('Mac BH route is improper in Local ARP on  S1_BGW1')
        
        except Exception as error:
            log.debug("Unable to configure static BH mac route on Remote Vtep- Encountered Exception " + str(error))
            self.errored('Exception occurred while configuring static BH mac route on Remote Vtep')
        
    def Verify_Mac_BH_Route_on_L2FM_BGP_L2RIB(self,testscript,testbed):
        node3_s1_bgw_1 = testbed.devices['node3_s1_bgw_1']
        node7_s2_bgw_1 = testbed.devices['node7_s2_bgw_1']
        P3_dict = AcceSW_TGEN_data
        
        # Verifying L2FM

        try:
            ###S1_BGW1_MAC_BH_ROUTE
            if verify_BH_route_in_L2FM(node3_s1_bgw_1,str(P3_dict['vlan_id']),str(P3_dict['mac'])):
                log.info('Mac BH route is proper in L2FM on  S1_BGw1')
            else:
                log.info('Mac BH route is improper in L2FM on  S1_BGw1')
                self.failed('Mac BH route is improper in L2FM on  S1_BGw1')

            ###S2_BGW1_MAC_BH_ROUTE Remote Vtep
            if verify_BH_route_in_L2FM(node7_s2_bgw_1,str(P3_dict['vlan_id']),str(P3_dict['mac'])):
                log.info('Mac BH route is proper in L2FM on  S2_BGw1')
            else:
                log.info('Mac BH route is improper in L2FM on  S2_BGw1')
                self.failed('Mac BH route is improper in L2FM on  S2_BGw1')

        except Exception as error:
            log.debug("Unable to verify BH mac route in L2FM - Encountered Exception " + str(error))
            self.errored('Exception occurred while verifying BH mac route in L2FM')        

        #Verifying L2RIB
        try:
            #S1_Leaf_Mac_BH_route
            if verify_L2rib_mac_ip_output(node3_s1_bgw_1,str(P3_dict['vlan_id']),str(P3_dict['mac'])):
                log.info('Mac BH route is proper in L2RIB on S1_Leaf')
            else:
                log.debug('Mac BH route is improper in L2RIB on  S1_Leaf')
                self.failed('Mac BH route is improper in L2RIB on  S1_Leaf')

            #S2_BGW1_Mac_BH_route
            if verify_L2rib_mac_ip_output(node7_s2_bgw_1,str(P3_dict['vlan_id']),str(P3_dict['mac'])):
                log.info('Mac BH route is proper in L2RIB on S2_BGW1')
            else:
                log.debug('Mac BH route is improper in L2RIB on  S2_BGW1')
                self.errored('Mac BH route is improper in L2RIB on  S2_BGW1')
        
        except Exception as error:
            log.debug("Unable to verify BH mac route in L2RIB - Encountered Exception " + str(error))
            self.errored('Exception occurred while verifying BH mac route in L2RIB')
        
        #Verifying BGP
        try:
            #S2_BGW1_Mac_BH_route
            if verify_BH_in_Remote_BGP(node7_s2_bgw_1,str(P3_dict['mac'])):
                log.info('Mac BH route is proper in BGP on S2_BGW1')
            else:
                log.debug('Mac BH route is improper in BGP on  S2_BGW1')
                self.errored('Mac BH route is improper in BGP on  S2_BGW1')

            #Access_Mac_BH_route
            if verify_BH_in_Remote_BGP(node3_s1_bgw_1,str(P3_dict['mac'])):
                log.info('Mac BH route is proper in BGP on Access')
            else:
                log.debug('Mac BH route is improper in BGP on  Access')
                self.errored('Mac BH route is improper in BGP on  Access')
        
        except Exception as error:
            log.debug("Unable to verify BH mac route in BGP - Encountered Exception " + str(error))
            self.errored('Exception occurred while verifying BH mac route in BGP', )
 
    
      

    @aetest.cleanup
    def cleanup(self,testscript,testbed):
        """Unconfigure qos policies"""
        node3_s1_bgw_1 = testbed.devices['node3_s1_bgw_1']
        node5_s1_leaf_1 = testbed.devices['node5_s1_leaf_1']
        node4_s1_bgw_2 = testbed.devices['node4_s1_bgw_2']
        node7_s2_bgw_1 = testbed.devices['node7_s2_bgw_1']
        node9_s2_leaf_1 = testbed.devices['node9_s2_leaf_1']
        forwardingSysDict = FWD_SYS_dict
        P3_dict = AcceSW_TGEN_data
        post_test_process_dict = {
            'dut_list'                       : [node3_s1_bgw_1, node4_s1_bgw_2,node7_s2_bgw_1],
            'cc_check'                  : 0,
            'cores_check'               : 1,
            'logs_check'                : 1,
            'fnl_flag'                  : 0,
            'exclude_log_check_pattern' : 'ERROR_VLANS_SUSPENDED|ERROR_VLANS_REMOVED|SYSMGR-2-SERVICE_CRASHED',
            }
        try:
            # Stop Traffic from ixia
            log.info("--- Stopping Traffic ---- \n")
            log.info("Stopping Traffic")
            traffic_run_status = ixLib.stop_traffic()
            
            if traffic_run_status is not 1:
               log.info("Failed: To Stop traffic")
               return 0
            else:
                log.info("\nTraffic Stopped successfully\n")
            time.sleep(10)
            
            ####Remove traffic item configured
            UCAST_v4_dict_3 = {
                            'mode'        : 'remove',
                            'stream_id'   : stream_id_2,
                      }
            if (ixLib.delete_traffic_item(UCAST_v4_dict_3))==0:
                log.debug("Traffic Remove failed")
                self.failed("Traffic Remove failed", goto=['next_tc'])
            else:
                log.info("Traffic Remove Passed")
            
            mac= str(P3_dict['mac'])
            vlan= str(P3_dict['vlan_id'])
            ip=str(P3_dict['v4_addr'])
            octet = 1
            no_int= int(P3_dict['no_of_ints'])
        
            for i in range (0,no_int):
            ###LEAF_3_MAC_BH_ROUTE
                testbed.devices['node3_s1_bgw_1'].configure('''
                    no mac address-table static ''' + str(mac) + ''' vlan '''+ str(vlan) + ''' drop

                    interface vlan ''' + str(vlan) + '''
                        no ip arp ''' + str(ip) + ''' ''' + str(mac) + '''
                ''')
                testbed.devices['node4_s1_bgw_2'].configure('''
                    no mac address-table static ''' + str(mac) + ''' vlan '''+ str(vlan) + ''' drop

                    interface vlan ''' + str(vlan) + '''
                        no ip arp ''' + str(ip) + ''' ''' + str(mac) + '''
                ''')
                lasthex=incr_mac(mac)
                mac=mac[0:10]+lasthex
                vlan= int(vlan)+int(P3_dict['vlan_id_step'])
                ip=incr_ip(ip,octet)
                
            ##check for cores,cc,errors
            status = infraVerify.postTestVerification(post_test_process_dict)
            if status['status'] == 0:
                self.failed(reason=status['logs'])
            else:
                self.passed(reason=status['logs'])
        except Exception as error:
            log.debug("Unable to do cleanup " + str(error))
            self.errored('Exception occurred during cleanup', goto=['next_tc'])
    

class ARP_PROCESS_RESTART(nxtest.Testcase):
    ##"TC_0088_ARP_PROCESS_RESTART"
    stream_id_2=''
    @aetest.test
    def CONFIGURE_L2_UCAST_IXIA_TRAFFIC_H4_to_H1(self, testscript):
        """ IXIA_CONFIGURATION subsection: Configure MCAST Traffic Item """

        # Do not perform configurations if skip_tgen_config flag is set
        #if not testscript.parameters['script_flags']['skip_tgen_config']:

        IX_TP1 = testscript.parameters['IX_TP1']
        IX_TP2 = testscript.parameters['IX_TP2']
        IX_TP3 = testscript.parameters['IX_TP3']
        IX_TP4 = testscript.parameters['IX_TP4']
        P1_dict = S1_BGW1_TGEN_data
        P2_dict = S1_Leaf_TGEN_data
        P3_dict = AcceSW_TGEN_data
        P4_dict = S2_Leaf_TGEN_data
        # P1_dict = S1_BGW1_TGEN_data
        # P4_dict = testscript.parameters['S2_BGW1_TGEN_dict']

        UCAST_v4_dict_3 = { 'src_hndl'  : IX_TP4['ipv4_handle'],
                            'dst_hndl'  : IX_TP3['ipv4_handle'],
                            'circuit'   : 'ipv4',
                            'TI_name'   : "UCAST_V4",
                            'rate_pps'  : "10000",
                            'bi_dir'    : 1,
                            'bidirectional': '0'
                        }

        UCAST_v4_TI_2 = ixLib.configure_ixia_traffic_item_v46(UCAST_v4_dict_3)
            
        if UCAST_v4_TI_2 == 0:
            log.debug("Configuring UCast L2 TI failed")
            self.errored("Configuring UCast L2 TI failed", goto=['next_tc'])
        else:
            global stream_id_2
            stream_id_2 = UCAST_v4_TI_2
            
        # else:
        #     self.passed(reason="Skipped TGEN Configurations as per request")


    # =============================================================================================================================#
    @aetest.test
    def APPLY_TRAFFIC(self):
        """ IXIA_CONFIGURATION subsection: Verify IXIA Traffic """

        # Apply IXIA Traffic
        if ixLib.apply_traffic() == 1:
            log.info("Applying IXIA TI Passed")
            
        else:
            self.errored("Applying IXIA TI failed")
            
        # =============================================================================================================================#
    @aetest.test
    def VERIFY_IXIA_TRAFFIC_before_ARP_Restart(self, testscript):
        """ IXIA_CONFIGURATION subsection: Verify IXIA Traffic """

        # Do not perform configurations if skip_tgen_config flag is set
        #if not testscript.parameters['script_flags']['skip_tgen_config']:

        time.sleep(20)

        if ixLib.verify_traffic(1) == 1:
            log.debug("Traffic Verification Passed.Expecting traffic loss here.") 
            #ForkedPdb().set_trace()
        else:
            log.info("Traffic Verification Failed.")
            self.failed("Traffic Verification failed")
       
    
    #--------------------------------------------------------------------------------#
        # Start traffic from ixia
        log.info("--- Populating the statistics --- \n")
        log.info("---- Running Traffic --- \n")
        log.info("Starting Traffic")

        traffic_run_status  = ixLib.start_traffic()

        if traffic_run_status is not 1:
           log.info("Failed: To start traffic")
           return 0
        else:
            log.info("\nTraffic started successfully\n")

        time.sleep(10)
        
    # =============================================================================================================================#
    # def config_mac_BH_route(testbed):
    #     node3_s1_bgw_1 = testbed.devices['node3_s1_bgw_1']
    #     node4_s1_bgw_2 =  testbed.devices['node4_s1_bgw_2']
    #     P3_dict = AcceSW_TGEN_data
    

    
    #     testbed.devices['node3_s1_bgw_1'].configure('''
    #         mac address-table static ''' + str(P3_dict['mac']) + ''' vlan '''+ str(P3_dict['vlan_id']) + ''' drop

    #         interface vlan ''' + str(P3_dict['vlan_id']) + '''
    #             ipv6 neighbor ''' + str(P3_dict['v6_addr']) + ''' ''' + str(P3_dict['mac']) + '''
    #             ip arp ''' + str(P3_dict['v4_addr']) + ''' ''' + str(P3_dict['mac']) + '''
    #     ''')
    #     testbed.devices['node4_s1_bgw_2'].configure('''
    #         mac address-table static ''' + str(P3_dict['mac']) + ''' vlan '''+ str(P3_dict['vlan_id']) + ''' drop

    #         interface vlan ''' + str(P3_dict['vlan_id']) + '''
    #             ipv6 neighbor ''' + str(P3_dict['v6_addr']) + ''' ''' + str(P3_dict['mac']) + '''
    #             ip arp ''' + str(P3_dict['v4_addr']) + ''' ''' + str(P3_dict['mac']) + '''
    #     ''')

    @aetest.test
    def TRIGGER_verify_ARP_process_restart(self, testscript,testbed):
        """ ACLQOS_PROCESS_KILL_VERIFICATION subsection: Verify killing process ACLQOS """

        node3_s1_bgw_1 = testbed.devices['node3_s1_bgw_1']
        node5_s1_leaf_1 = testbed.devices['node5_s1_leaf_1']
        node4_s1_bgw_2 = testbed.devices['node4_s1_bgw_2']
        node7_s2_bgw_1 = testbed.devices['node7_s2_bgw_1']
        node9_s2_leaf_1 = testbed.devices['node9_s2_leaf_1']
        P3_dict = AcceSW_TGEN_data

        mac= str(P3_dict['mac'])
        vlan= str(P3_dict['vlan_id'])
        ip=str(P3_dict['v4_addr'])
        octet = 1
        no_int= int(P3_dict['no_of_ints'])
        
        for i in range (0,no_int):
            ###LEAF_3_MAC_BH_ROUTE
            testbed.devices['node3_s1_bgw_1'].configure('''
                mac address-table static ''' + str(mac) + ''' vlan '''+ str(vlan) + ''' drop

                interface vlan ''' + str(vlan) + '''
                  ip arp ''' + str(ip) + ''' ''' + str(mac) + '''
            ''')
            testbed.devices['node4_s1_bgw_2'].configure('''
                mac address-table static ''' + str(mac) + ''' vlan '''+ str(vlan) + ''' drop

                interface vlan ''' + str(vlan) + '''
                  ip arp ''' + str(ip) + ''' ''' + str(mac) + '''
            ''')
            lasthex=incr_mac(mac)
            mac=mac[0:10]+lasthex
            vlan= int(vlan)+int(P3_dict['vlan_id_step'])
            ip=incr_ip(ip,octet)

        if infraTrig.verifyProcessRestart(node3_s1_bgw_1,"arp"):
            log.info("Successfully restarted process ARP")
        else:
            log.debug("Failed to restarted process ARP")
            self.failed("Failed to restarted process ARP", goto=['cleanup'])
        time.sleep(120)

        if infraTrig.verifyProcessRestart(node4_s1_bgw_2,"arp"):
            log.info("Successfully restarted process ARP")
        else:
            log.debug("Failed to restarted process ARP")
            self.failed("Failed to restarted process ARP", goto=['cleanup'])
        time.sleep(120)

        if infraTrig.verifyProcessRestart(node7_s2_bgw_1,"arp"):
            log.info("Successfully restarted process ARP")
        else:
            log.debug("Failed to restarted process ARP")
            self.failed("Failed to restarted process ARP", goto=['cleanup'])
        time.sleep(120)


      

    # =============================================================================================================================#  
    
    @aetest.test
    def VERIFY_IXIA_TRAFFIC(self, testscript):
        """ IXIA_CONFIGURATION subsection: Verify IXIA Traffic """

        # Do not perform configurations if skip_tgen_config flag is set
    
        time.sleep(20)

        if ixLib.verify_traffic(2) == 1:
            log.debug("Traffic Verification failed")
            # ForkedPdb().set_trace()
            self.failed("Traffic Verification failed", goto=['cleanup'])
        else:
            log.info("Traffic Verification Passed")
   
    # def Unconfig_mac_BH_route(testbed):
    #     node3_s1_bgw_1 = testbed.devices['node3_s1_bgw_1']
    #     node4_s1_bgw_2 =  testbed.devices['node4_s1_bgw_2']
    #     P3_dict = AcceSW_TGEN_data
    

    
    #     testbed.devices['node3_s1_bgw_1'].configure('''
    #         no mac address-table static ''' + str(P3_dict['mac']) + ''' vlan '''+ str(P3_dict['vlan_id']) + ''' drop

    #         interface vlan ''' + str(P3_dict['vlan_id']) + '''
    #             no ipv6 neighbor ''' + str(P3_dict['v6_addr']) + ''' ''' + str(P3_dict['mac']) + '''
    #             no ip arp ''' + str(P3_dict['v4_addr']) + ''' ''' + str(P3_dict['mac']) + '''
    #     ''')
    #     testbed.devices['node4_s1_bgw_2'].configure('''
    #         no mac address-table static ''' + str(P3_dict['mac']) + ''' vlan '''+ str(P3_dict['vlan_id']) + ''' drop

    #         interface vlan ''' + str(P3_dict['vlan_id']) + '''
    #             no ipv6 neighbor ''' + str(P3_dict['v6_addr']) + ''' ''' + str(P3_dict['mac']) + '''
    #             no ip arp ''' + str(P3_dict['v4_addr']) + ''' ''' + str(P3_dict['mac']) + '''
    #     ''')
    @aetest.test
    def Verify_BH_states_in_HMM(self, testscript,testbed):
        node3_s1_bgw_1 =testbed.devices['node3_s1_bgw_1']
        node4_s1_bgw_2 = testbed.devices['node4_s1_bgw_2']
        node7_s2_bgw_1 = testbed.devices['node7_s2_bgw_1']
        P3_dict = AcceSW_TGEN_data

        try:
            if verify_BH_in_HMM(node4_s1_bgw_2,str(P3_dict['v4_addr'])):
                log.info('Mac BH route is proper in HMM on  S1_BGW1')
            else:
                log.info('Mac BH route is improper in HMM on  S1_BGW1')
                self.failed('Mac BH route is improper in HMM on  S1_BGW1')
        
         
        except Exception as error:
            log.debug("Unable to configure static BH mac route on Remote Vtep- Encountered Exception " + str(error))
            self.errored('Exception occurred while configuring static BH mac route on Remote Vtep', goto=['cleanup'])
    @aetest.test
    def Verify_BH_states_in_AM(self, testscript,testbed):
        node3_s1_bgw_1 = testbed.devices['node3_s1_bgw_1']
        node4_s1_bgw_2 = testbed.devices['node4_s1_bgw_2']
        node7_s2_bgw_1 = testbed.devices['node7_s2_bgw_1']
        P1_dict = S1_BGW1_TGEN_data
        P2_dict = S1_Leaf_TGEN_data
        P3_dict = AcceSW_TGEN_data
        P4_dict = S2_Leaf_TGEN_data

        try:        
            if verify_BH_in_AM(node4_s1_bgw_2,str(P3_dict['mac']),str(P3_dict['vlan_id']),str(P3_dict['v4_addr'])):
                log.info('Mac BH route is proper in AM on  S1_BGW1')
            else:
                log.info('Mac BH route is improper in AM on  S1_BGW1')
                self.failed('Mac BH route is improper in AM on  S1_BGW1')
                   
        
        except Exception as error:
            log.debug("Unable to configure static BH mac route on Remote Vtep- Encountered Exception " + str(error))
            self.errored('Exception occurred while configuring static BH mac route on Remote Vtep', goto=['cleanup'])
    @aetest.test
    def Verify_BH_states_in_remote_ARP(self, testscript,testbed):
        node3_s1_bgw_1 =testbed.devices['node3_s1_bgw_1']
        node7_s2_bgw_1 = testbed.devices['node7_s2_bgw_1']
        P3_dict = AcceSW_TGEN_data

        try: 

            if verify_BH_in_Remote_ARP(node7_s2_bgw_1,str(P3_dict['vlan_id']),str(P3_dict['mac'])):
               log.info('Mac BH route is proper in Remote ARP on  S2_BGW1')
            else:
                log.info('Mac BH route is improper in Remote ARP on  S2_BGW1')
                self.failed('Mac BH route is improper in Remote ARP on  S2_BGW1')

        except Exception as error:
            log.debug("Unable to configure static BH mac route on Remote Vtep- Encountered Exception " + str(error))
            self.errored('Exception occurred while configuring static BH mac route on Remote Vtep')        
    @aetest.test
    def Verify_BH_states_in_local_ARP(self, testscript,testbed):
        node3_s1_bgw_1 = testbed.devices['node3_s1_bgw_1']
        node7_s2_bgw_1 = testbed.devices['node7_s2_bgw_1']
        P1_dict = S1_BGW1_TGEN_data
        P2_dict = S1_Leaf_TGEN_data
        P3_dict = AcceSW_TGEN_data
        P4_dict = S2_Leaf_TGEN_data
        try:        
            if verify_BH_in_local_ARP(node3_s1_bgw_1,str(P3_dict['vlan_id']),str(P3_dict['mac'])):
                log.info('Mac BH route is proper in Local ARP on  S1_BGW1')
            else:
                log.info('Mac BH route is improper in Local ARP on  S1_BGW1')
                self.failed('Mac BH route is improper in Local ARP on  S1_BGW1')
        
        except Exception as error:
            log.debug("Unable to configure static BH mac route on Remote Vtep- Encountered Exception " + str(error))
            self.errored('Exception occurred while configuring static BH mac route on Remote Vtep')
    
    @aetest.test   
    def Verify_Mac_BH_Route_on_L2FM_BGP_L2RIB(self,testscript,testbed):
        node3_s1_bgw_1 = testbed.devices['node3_s1_bgw_1']
        node7_s2_bgw_1 = testbed.devices['node7_s2_bgw_1']
        P3_dict = AcceSW_TGEN_data
        
        # Verifying L2FM

        try:
            ###S1_BGW1_MAC_BH_ROUTE
            if verify_BH_route_in_L2FM(node3_s1_bgw_1,str(P3_dict['vlan_id']),str(P3_dict['mac'])):
                log.info('Mac BH route is proper in L2FM on  S1_BGw1')
            else:
                log.info('Mac BH route is improper in L2FM on  S1_BGw1')
                self.failed('Mac BH route is improper in L2FM on  S1_BGw1')

            ###S2_BGW1_MAC_BH_ROUTE Remote Vtep
            if verify_BH_route_in_L2FM(node7_s2_bgw_1,str(P3_dict['vlan_id']),str(P3_dict['mac'])):
                log.info('Mac BH route is proper in L2FM on  S2_BGw1')
            else:
                log.info('Mac BH route is improper in L2FM on  S2_BGw1')
                self.failed('Mac BH route is improper in L2FM on  S2_BGw1')

        except Exception as error:
            log.debug("Unable to verify BH mac route in L2FM - Encountered Exception " + str(error))
            self.errored('Exception occurred while verifying BH mac route in L2FM')        

        #Verifying L2RIB
        try:
            #S1_Leaf_Mac_BH_route
            if verify_L2rib_mac_ip_output(node3_s1_bgw_1,str(P3_dict['vlan_id']),str(P3_dict['mac'])):
                log.info('Mac BH route is proper in L2RIB on S1_Leaf')
            else:
                log.debug('Mac BH route is improper in L2RIB on  S1_Leaf')
                self.failed('Mac BH route is improper in L2RIB on  S1_Leaf')

            #S2_BGW1_Mac_BH_route
            if verify_L2rib_mac_ip_output(node7_s2_bgw_1,str(P3_dict['vlan_id']),str(P3_dict['mac'])):
                log.info('Mac BH route is proper in L2RIB on S2_BGW1')
            else:
                log.debug('Mac BH route is improper in L2RIB on  S2_BGW1')
                self.errored('Mac BH route is improper in L2RIB on  S2_BGW1')
        
        except Exception as error:
            log.debug("Unable to verify BH mac route in L2RIB - Encountered Exception " + str(error))
            self.errored('Exception occurred while verifying BH mac route in L2RIB')
        
        #Verifying BGP
        try:
            #S2_BGW1_Mac_BH_route
            if verify_BH_in_Remote_BGP(node7_s2_bgw_1,str(P3_dict['mac'])):
                log.info('Mac BH route is proper in BGP on S2_BGW1')
            else:
                log.debug('Mac BH route is improper in BGP on  S2_BGW1')
                self.errored('Mac BH route is improper in BGP on  S2_BGW1')

            #Access_Mac_BH_route
            if verify_BH_in_Remote_BGP(node3_s1_bgw_1,str(P3_dict['mac'])):
                log.info('Mac BH route is proper in BGP on Access')
            else:
                log.debug('Mac BH route is improper in BGP on  Access')
                self.errored('Mac BH route is improper in BGP on  Access')
        
        except Exception as error:
            log.debug("Unable to verify BH mac route in BGP - Encountered Exception " + str(error))
            self.errored('Exception occurred while verifying BH mac route in BGP', )
 

    @aetest.cleanup
    def cleanup(self,testscript,testbed):
        """Unconfigure qos policies"""
        node3_s1_bgw_1 = testbed.devices['node3_s1_bgw_1']
        node5_s1_leaf_1 = testbed.devices['node5_s1_leaf_1']
        node4_s1_bgw_2 = testbed.devices['node4_s1_bgw_2']
        node7_s2_bgw_1 = testbed.devices['node7_s2_bgw_1']
        node9_s2_leaf_1 = testbed.devices['node9_s2_leaf_1']
        forwardingSysDict = FWD_SYS_dict
        P3_dict = AcceSW_TGEN_data
        post_test_process_dict = {
            'dut_list'                       : [node3_s1_bgw_1,node4_s1_bgw_2,node7_s2_bgw_1],
            'cc_check'                  : 0,
            'cores_check'               : 1,
            'logs_check'                : 1,
            'fnl_flag'                  : 0,
            'exclude_log_check_pattern' : 'ERROR_VLANS_SUSPENDED|ERROR_VLANS_REMOVED|SYSMGR-2-SERVICE_CRASHED',
            }
        try:
            # Stop Traffic from ixia
            log.info("--- Stopping Traffic ---- \n")
            log.info("Stopping Traffic")
            traffic_run_status = ixLib.stop_traffic()
            
            if traffic_run_status is not 1:
               log.info("Failed: To Stop traffic")
               return 0
            else:
                log.info("\nTraffic Stopped successfully\n")
            time.sleep(10)
            
            ####Remove traffic item configured
            UCAST_v4_dict_3 = {
                            'mode'        : 'remove',
                            'stream_id'   : stream_id_2,
                      }
            if (ixLib.delete_traffic_item(UCAST_v4_dict_3))==0:
                log.debug("Traffic Remove failed")
                self.failed("Traffic Remove failed", goto=['next_tc'])
            else:
                log.info("Traffic Remove Passed")
            
            mac= str(P3_dict['mac'])
            vlan= str(P3_dict['vlan_id'])
            ip=str(P3_dict['v4_addr'])
            octet = 1
            no_int= int(P3_dict['no_of_ints'])
        
            for i in range (0,no_int):
            ###LEAF_3_MAC_BH_ROUTE
                testbed.devices['node3_s1_bgw_1'].configure('''
                    no mac address-table static ''' + str(mac) + ''' vlan '''+ str(vlan) + ''' drop

                    interface vlan ''' + str(vlan) + '''
                        no ip arp ''' + str(ip) + ''' ''' + str(mac) + '''
                ''')
                testbed.devices['node4_s1_bgw_2'].configure('''
                    no mac address-table static ''' + str(mac) + ''' vlan '''+ str(vlan) + ''' drop

                    interface vlan ''' + str(vlan) + '''
                        no ip arp ''' + str(ip) + ''' ''' + str(mac) + '''
                ''')
                lasthex=incr_mac(mac)
                mac=mac[0:10]+lasthex
                vlan= int(vlan)+int(P3_dict['vlan_id_step'])
                ip=incr_ip(ip,octet)
                
            ##check for cores,cc,errors
            status = infraVerify.postTestVerification(post_test_process_dict)
            if status['status'] == 0:
                self.failed(reason=status['logs'])
            else:
                self.passed(reason=status['logs'])
        except Exception as error:
            log.debug("Unable to do cleanup " + str(error))
            self.errored('Exception occurred during cleanup', goto=['next_tc'])
    
class icmpv6_PROCESS_RESTART(nxtest.Testcase):
    #"TC_0089icmpv6_PROCESS_RESTART"
 
    stream_id_2=''
    @aetest.test
    def CONFIGURE_L2_UCAST_IXIA_TRAFFIC_With_IPv6_H4_to_H1(self, testscript):
        """ IXIA_CONFIGURATION subsection: Configure MCAST Traffic Item """

        # Do not perform configurations if skip_tgen_config flag is set
        #if not testscript.parameters['script_flags']['skip_tgen_config']:

        IX_TP1 = testscript.parameters['IX_TP1']
        IX_TP2 = testscript.parameters['IX_TP2']
        IX_TP3 = testscript.parameters['IX_TP3']
        IX_TP4 = testscript.parameters['IX_TP4']
        P1_dict = S1_BGW1_TGEN_data
        P2_dict = S1_Leaf_TGEN_data
        P3_dict = AcceSW_TGEN_data
        P4_dict = S2_Leaf_TGEN_data


        UCAST_v6_dict_3 = {   
                            'src_hndl'  : IX_TP4['ipv6_handle'],
                            'dst_hndl'  : IX_TP3['ipv6_handle'],
                            'circuit'   : 'ipv6',
                            'TI_name'   : "UCAST_v6",
                            'rate_pps'  : "1000",
                            'bi_dir'    : 1,
                            'bidirectional': '0'
                        }

        UCAST_v6_TI_2 = ixLib.configure_ixia_traffic_item_v46(UCAST_v6_dict_3)

        if UCAST_v6_TI_2 == 0:
            log.debug("Configuring UCast TI failed")
            self.errored("Configuring UCast TI failed", goto=['next_tc'])   
        
        else:
            global stream_id_2
            stream_id_2 = UCAST_v6_TI_2
    # =============================================================================================================================#
    @aetest.test
    def APPLY_TRAFFIC(self):
        """ IXIA_CONFIGURATION subsection: Verify IXIA Traffic """

        # Apply IXIA Traffic
        if ixLib.apply_traffic() == 1:
            log.info("Applying IXIA TI Passed")
        else:
            self.errored("Applying IXIA TI failed", goto=['cleanup'])
            
        # =============================================================================================================================#
    @aetest.test
    def VERIFY_IXIA_TRAFFIC_Before_Restart(self, testscript):
        """ IXIA_CONFIGURATION subsection: Verify IXIA Traffic """

        # Do not perform configurations if skip_tgen_config flag is set
       
        time.sleep(20)

        if ixLib.verify_traffic(2) == 0:
            log.debug("Traffic Verification failed")
            # ForkedPdb().set_trace()
            self.failed("Traffic Verification failed", goto=['cleanup'])
        else:
            log.info("Traffic Verification Passed")
      
    
    
    #--------------------------------------------------------------------------------#
        # Start traffic from ixia
        log.info("--- Populating the statistics --- \n")
        log.info("---- Running Traffic --- \n")
        log.info("Starting Traffic")

        traffic_run_status  = ixLib.start_traffic()

        if traffic_run_status is not 1:
           log.info("Failed: To start traffic")
           return 0
        else:
            log.info("\nTraffic started successfully\n")

        time.sleep(10)
        
    # =============================================================================================================================#
    # @aetest.test
    # def config_mac_BH_route(testbed):
    #     node3_s1_bgw_1 = testbed.devices['node3_s1_bgw_1']
    #     node4_s1_bgw_2 =  testbed.devices['node4_s1_bgw_2']
    #     P3_dict = AcceSW_TGEN_data
    

    
    #     testbed.devices['node3_s1_bgw_1'].configure('''
    #         mac address-table static ''' + str(P3_dict['mac']) + ''' vlan '''+ str(P3_dict['vlan_id']) + ''' drop

    #         interface vlan ''' + str(P3_dict['vlan_id']) + '''
    #             ipv6 neighbor ''' + str(P3_dict['v6_addr']) + ''' ''' + str(P3_dict['mac']) + '''
    #             ip arp ''' + str(P3_dict['v4_addr']) + ''' ''' + str(P3_dict['mac']) + '''
    #     ''')
    #     testbed.devices['node4_s1_bgw_2'].configure('''
    #         mac address-table static ''' + str(P3_dict['mac']) + ''' vlan '''+ str(P3_dict['vlan_id']) + ''' drop

    #         interface vlan ''' + str(P3_dict['vlan_id']) + '''
    #             ipv6 neighbor ''' + str(P3_dict['v6_addr']) + ''' ''' + str(P3_dict['mac']) + '''
    #             ip arp ''' + str(P3_dict['v4_addr']) + ''' ''' + str(P3_dict['mac']) + '''
    #     ''')


    @aetest.test
    def TRIGGER_verify_icmpv6_process_restart(self, testscript,testbed):
        """ ACLQOS_PROCESS_KILL_VERIFICATION subsection: Verify killing process ACLQOS """

        node3_s1_bgw_1 = testbed.devices['node3_s1_bgw_1']
        node5_s1_leaf_1 = testbed.devices['node5_s1_leaf_1']
        node4_s1_bgw_2 = testbed.devices['node4_s1_bgw_2']
        node7_s2_bgw_1 = testbed.devices['node7_s2_bgw_1']
        node9_s2_leaf_1 = testbed.devices['node9_s2_leaf_1']
        P3_dict = AcceSW_TGEN_data

        mac= str(P3_dict['mac'])
        vlan= str(P3_dict['vlan_id'])
        ip=str(P3_dict['v4_addr'])
        octet = 1
        no_int= int(P3_dict['no_of_ints'])
        
        for i in range (0,no_int):
            ###LEAF_3_MAC_BH_ROUTE
            testbed.devices['node3_s1_bgw_1'].configure('''
                mac address-table static ''' + str(mac) + ''' vlan '''+ str(vlan) + ''' drop

                interface vlan ''' + str(vlan) + '''
                  ip arp ''' + str(ip) + ''' ''' + str(mac) + '''
            ''')
            testbed.devices['node4_s1_bgw_2'].configure('''
                mac address-table static ''' + str(mac) + ''' vlan '''+ str(vlan) + ''' drop

                interface vlan ''' + str(vlan) + '''
                  ip arp ''' + str(ip) + ''' ''' + str(mac) + '''
            ''')
            lasthex=incr_mac(mac)
            mac=mac[0:10]+lasthex
            vlan= int(vlan)+int(P3_dict['vlan_id_step'])
            ip=incr_ip(ip,octet)

        if infraTrig.verifyProcessRestart(node3_s1_bgw_1,"icmpv6"):
            log.info("Successfully restarted process icmpv6")
        else:
            log.debug("Failed to restarted process icmpv6")
            self.failed("Failed to restarted process icmpv6", goto=['cleanup'])
        time.sleep(120)

        if infraTrig.verifyProcessRestart(node4_s1_bgw_2,"icmpv6"):
            log.info("Successfully restarted process icmpv6")
        else:
            log.debug("Failed to restarted process icmpv6")
            self.failed("Failed to restarted process icmpv6", goto=['cleanup'])
        time.sleep(120)

        if infraTrig.verifyProcessRestart(node7_s2_bgw_1,"icmpv6"):
            log.info("Successfully restarted process icmpv6")
        else:
            log.debug("Failed to restarted process icmpv6")
            self.failed("Failed to restarted process icmpv6", goto=['cleanup'])
        time.sleep(120)

    

    # =============================================================================================================================#  
    
    @aetest.test
    def VERIFY_IXIA_TRAFFIC(self, testscript):
        """ IXIA_CONFIGURATION subsection: Verify IXIA Traffic """

        # Do not perform configurations if skip_tgen_config flag is set
       

        time.sleep(20)

        if ixLib.verify_traffic(2) == 1:
            log.debug("Traffic Verification failed")
            # ForkedPdb().set_trace()
            self.failed("Traffic Verification failed", goto=['cleanup'])
        else:
            log.info("Traffic Verification Passed")
    
    # @aetest.test
    # def Unconfig_mac_BH_route(testbed):
    #     node3_s1_bgw_1 = testbed.devices['node3_s1_bgw_1']
    #     node4_s1_bgw_2 =  testbed.devices['node4_s1_bgw_2']
    #     P3_dict = AcceSW_TGEN_data
    

    
    #     testbed.devices['node3_s1_bgw_1'].configure('''
    #         no mac address-table static ''' + str(P3_dict['mac']) + ''' vlan '''+ str(P3_dict['vlan_id']) + ''' drop

    #         interface vlan ''' + str(P3_dict['vlan_id']) + '''
    #             no ipv6 neighbor ''' + str(P3_dict['v6_addr']) + ''' ''' + str(P3_dict['mac']) + '''
    #             no ip arp ''' + str(P3_dict['v4_addr']) + ''' ''' + str(P3_dict['mac']) + '''
    #     ''')
    #     testbed.devices['node4_s1_bgw_2'].configure('''
    #         no mac address-table static ''' + str(P3_dict['mac']) + ''' vlan '''+ str(P3_dict['vlan_id']) + ''' drop

    #         interface vlan ''' + str(P3_dict['vlan_id']) + '''
    #             no ipv6 neighbor ''' + str(P3_dict['v6_addr']) + ''' ''' + str(P3_dict['mac']) + '''
    #             no ip arp ''' + str(P3_dict['v4_addr']) + ''' ''' + str(P3_dict['mac']) + '''
    #     ''')
    @aetest.test
    def Verify_BH_states_in_HMM(self, testscript,testbed):
        node3_s1_bgw_1 =testbed.devices['node3_s1_bgw_1']
        node4_s1_bgw_2 = testbed.devices['node4_s1_bgw_2']
        node7_s2_bgw_1 = testbed.devices['node7_s2_bgw_1']
        P3_dict = AcceSW_TGEN_data

        try:
            if verify_BH_in_HMM(node4_s1_bgw_2,str(P3_dict['v4_addr'])):
                log.info('Mac BH route is proper in HMM on  S1_BGW1')
            else:
                log.info('Mac BH route is improper in HMM on  S1_BGW1')
                self.failed('Mac BH route is improper in HMM on  S1_BGW1')
        
         
        except Exception as error:
            log.debug("Unable to configure static BH mac route on Remote Vtep- Encountered Exception " + str(error))
            self.errored('Exception occurred while configuring static BH mac route on Remote Vtep', goto=['cleanup'])
    @aetest.test
    def Verify_BH_states_in_AM(self, testscript,testbed):
        node3_s1_bgw_1 = testbed.devices['node3_s1_bgw_1']
        node4_s1_bgw_2 = testbed.devices['node4_s1_bgw_2']
        node7_s2_bgw_1 = testbed.devices['node7_s2_bgw_1']
        P1_dict = S1_BGW1_TGEN_data
        P2_dict = S1_Leaf_TGEN_data
        P3_dict = AcceSW_TGEN_data
        P4_dict = S2_Leaf_TGEN_data

        try:        
            if verify_BH_in_AM(node4_s1_bgw_2,str(P3_dict['mac']),str(P3_dict['vlan_id']),str(P3_dict['v4_addr'])):
                log.info('Mac BH route is proper in AM on  S1_BGW1')
            else:
                log.info('Mac BH route is improper in AM on  S1_BGW1')
                self.failed('Mac BH route is improper in AM on  S1_BGW1')
                   
        
        except Exception as error:
            log.debug("Unable to configure static BH mac route on Remote Vtep- Encountered Exception " + str(error))
            self.errored('Exception occurred while configuring static BH mac route on Remote Vtep', goto=['cleanup'])
    @aetest.test
    def Verify_BH_states_in_remote_ARP(self, testscript,testbed):
        node3_s1_bgw_1 =testbed.devices['node3_s1_bgw_1']
        node7_s2_bgw_1 = testbed.devices['node7_s2_bgw_1']
        P3_dict = AcceSW_TGEN_data

        try: 

            if verify_BH_in_Remote_ARP(node7_s2_bgw_1,str(P3_dict['vlan_id']),str(P3_dict['mac'])):
               log.info('Mac BH route is proper in Remote ARP on  S2_BGW1')
            else:
                log.info('Mac BH route is improper in Remote ARP on  S2_BGW1')
                self.failed('Mac BH route is improper in Remote ARP on  S2_BGW1')

        except Exception as error:
            log.debug("Unable to configure static BH mac route on Remote Vtep- Encountered Exception " + str(error))
            self.errored('Exception occurred while configuring static BH mac route on Remote Vtep')        
    @aetest.test
    def Verify_BH_states_in_local_ARP(self, testscript,testbed):
        node3_s1_bgw_1 = testbed.devices['node3_s1_bgw_1']
        node7_s2_bgw_1 = testbed.devices['node7_s2_bgw_1']
        P1_dict = S1_BGW1_TGEN_data
        P2_dict = S1_Leaf_TGEN_data
        P3_dict = AcceSW_TGEN_data
        P4_dict = S2_Leaf_TGEN_data
        try:        
            if verify_BH_in_local_ARP(node3_s1_bgw_1,str(P3_dict['vlan_id']),str(P3_dict['mac'])):
                log.info('Mac BH route is proper in Local ARP on  S1_BGW1')
            else:
                log.info('Mac BH route is improper in Local ARP on  S1_BGW1')
                self.failed('Mac BH route is improper in Local ARP on  S1_BGW1')
        
        except Exception as error:
            log.debug("Unable to configure static BH mac route on Remote Vtep- Encountered Exception " + str(error))
            self.errored('Exception occurred while configuring static BH mac route on Remote Vtep')
    @aetest.test  
    def Verify_Mac_BH_Route_on_L2FM_BGP_L2RIB(self,testscript,testbed):
        node3_s1_bgw_1 = testbed.devices['node3_s1_bgw_1']
        node7_s2_bgw_1 = testbed.devices['node7_s2_bgw_1']
        P3_dict = AcceSW_TGEN_data
        
        # Verifying L2FM

        try:
            ###S1_BGW1_MAC_BH_ROUTE
            if verify_BH_route_in_L2FM(node3_s1_bgw_1,str(P3_dict['vlan_id']),str(P3_dict['mac'])):
                log.info('Mac BH route is proper in L2FM on  S1_BGw1')
            else:
                log.info('Mac BH route is improper in L2FM on  S1_BGw1')
                # ForkedPdb().set_trace()
                self.failed('Mac BH route is improper in L2FM on  S1_BGw1')

            ###S2_BGW1_MAC_BH_ROUTE Remote Vtep
            if verify_BH_route_in_L2FM(node7_s2_bgw_1,str(P3_dict['vlan_id']),str(P3_dict['mac'])):
                log.info('Mac BH route is proper in L2FM on  S2_BGw1')
            else:
                log.info('Mac BH route is improper in L2FM on  S2_BGw1')
                # ForkedPdb().set_trace()
                self.failed('Mac BH route is improper in L2FM on  S2_BGw1')

        except Exception as error:
            log.debug("Unable to verify BH mac route in L2FM - Encountered Exception " + str(error))
            self.errored('Exception occurred while verifying BH mac route in L2FM')        

        #Verifying L2RIB
        try:
            #S1_Leaf_Mac_BH_route
            if verify_L2rib_mac_ip_output(node3_s1_bgw_1,str(P3_dict['vlan_id']),str(P3_dict['mac'])):
                log.info('Mac BH route is proper in L2RIB on S1_Leaf')
            else:
                log.debug('Mac BH route is improper in L2RIB on  S1_Leaf')
                self.failed('Mac BH route is improper in L2RIB on  S1_Leaf')

            #S2_BGW1_Mac_BH_route
            if verify_L2rib_mac_ip_output(node7_s2_bgw_1,str(P3_dict['vlan_id']),str(P3_dict['mac'])):
                log.info('Mac BH route is proper in L2RIB on S2_BGW1')
            else:
                log.debug('Mac BH route is improper in L2RIB on  S2_BGW1')
                self.errored('Mac BH route is improper in L2RIB on  S2_BGW1')
        
        except Exception as error:
            log.debug("Unable to verify BH mac route in L2RIB - Encountered Exception " + str(error))
            self.errored('Exception occurred while verifying BH mac route in L2RIB')
        
        #Verifying BGP
        try:
            #S2_BGW1_Mac_BH_route
            if verify_BH_in_Remote_BGP(node7_s2_bgw_1,str(P3_dict['mac'])):
                log.info('Mac BH route is proper in BGP on S2_BGW1')
            else:
                log.debug('Mac BH route is improper in BGP on  S2_BGW1')
                self.errored('Mac BH route is improper in BGP on  S2_BGW1')

            #Access_Mac_BH_route
            if verify_BH_in_Remote_BGP(node3_s1_bgw_1,str(P3_dict['mac'])):
                log.info('Mac BH route is proper in BGP on Access')
            else:
                log.debug('Mac BH route is improper in BGP on  Access')
                self.errored('Mac BH route is improper in BGP on  Access')
        
        except Exception as error:
            log.debug("Unable to verify BH mac route in BGP - Encountered Exception " + str(error))
            self.errored('Exception occurred while verifying BH mac route in BGP', )

       
    @aetest.cleanup
    def cleanup(self,testscript,testbed):
        """Unconfigure qos policies"""
        node3_s1_bgw_1 = testbed.devices['node3_s1_bgw_1']
        node5_s1_leaf_1 = testbed.devices['node5_s1_leaf_1']
        node4_s1_bgw_2 = testbed.devices['node4_s1_bgw_2']
        node7_s2_bgw_1 = testbed.devices['node7_s2_bgw_1']
        node9_s2_leaf_1 = testbed.devices['node9_s2_leaf_1']
        forwardingSysDict = FWD_SYS_dict
        P3_dict = AcceSW_TGEN_data
        post_test_process_dict = {
            'dut_list'                       : [node3_s1_bgw_1, node4_s1_bgw_2,node7_s2_bgw_1],
            'cc_check'                  : 0,
            'cores_check'               : 1,
            'logs_check'                : 1,
            'fnl_flag'                  : 0,
            'exclude_log_check_pattern' : 'ERROR_VLANS_SUSPENDED|ERROR_VLANS_REMOVED|SYSMGR-2-SERVICE_CRASHED',
            }
        try:
            # Stop Traffic from ixia
            log.info("--- Stopping Traffic ---- \n")
            log.info("Stopping Traffic")
            traffic_run_status = ixLib.stop_traffic()
            
            if traffic_run_status is not 1:
               log.info("Failed: To Stop traffic")
               return 0
            else:
                log.info("\nTraffic Stopped successfully\n")
            time.sleep(10)
            ####Remove traffic item configured
            UCAST_v6_dict_3 = {
                            'mode'        : 'remove',
                            'stream_id'   : stream_id_2,
                      }
            if (ixLib.delete_traffic_item(UCAST_v6_dict_3))==0:
                log.debug("Traffic Remove failed")
                self.failed("Traffic Remove failed", goto=['next_tc'])
            else:
                log.info("Traffic Remove Passed")

            mac= str(P3_dict['mac'])
            vlan= str(P3_dict['vlan_id'])
            ip=str(P3_dict['v4_addr'])
            octet = 1
            no_int= int(P3_dict['no_of_ints'])
        
            for i in range (0,no_int):
            ###LEAF_3_MAC_BH_ROUTE
                testbed.devices['node3_s1_bgw_1'].configure('''
                    no mac address-table static ''' + str(mac) + ''' vlan '''+ str(vlan) + ''' drop

                    interface vlan ''' + str(vlan) + '''
                        no ip arp ''' + str(ip) + ''' ''' + str(mac) + '''
                ''')
                testbed.devices['node4_s1_bgw_2'].configure('''
                    no mac address-table static ''' + str(mac) + ''' vlan '''+ str(vlan) + ''' drop

                    interface vlan ''' + str(vlan) + '''
                        no ip arp ''' + str(ip) + ''' ''' + str(mac) + '''
                ''')
                lasthex=incr_mac(mac)
                mac=mac[0:10]+lasthex
                vlan= int(vlan)+int(P3_dict['vlan_id_step'])
                ip=incr_ip(ip,octet)
                
            ##check for cores,cc,errors
            status = infraVerify.postTestVerification(post_test_process_dict)
            if status['status'] == 0:
                self.failed(reason=status['logs'])
            else:
                self.passed(reason=status['logs'])
        except Exception as error:
            log.debug("Unable to do cleanup " + str(error))
            self.errored('Exception occurred during cleanup', goto=['next_tc'])

class L2FM_PROCESS_RESTART(nxtest.Testcase):
    #"TC_0090_L2FM_PROCESS_RESTART",

    stream_id_2=''
    @aetest.test
    def CONFIGURE_L2_UCAST_IXIA_TRAFFIC_H4_to_H1(self, testscript):
        """ IXIA_CONFIGURATION subsection: Configure MCAST Traffic Item """

        # Do not perform configurations if skip_tgen_config flag is set
        #if not testscript.parameters['script_flags']['skip_tgen_config']:

        IX_TP1 = testscript.parameters['IX_TP1']
        IX_TP2 = testscript.parameters['IX_TP2']
        IX_TP3 = testscript.parameters['IX_TP3']
        IX_TP4 = testscript.parameters['IX_TP4']
        P1_dict = S1_BGW1_TGEN_data
        P2_dict = S1_Leaf_TGEN_data
        P3_dict = AcceSW_TGEN_data
        P4_dict = S2_Leaf_TGEN_data
        # P1_dict = S1_BGW1_TGEN_data
        # P4_dict = testscript.parameters['S2_BGW1_TGEN_dict']

        UCAST_v4_dict_3 = {   'src_hndl'  : IX_TP4['ipv4_handle'],
                            'dst_hndl'  : IX_TP3['ipv4_handle'],
                            'circuit'   : 'ipv4',
                            'TI_name'   : "UCAST_V4",
                            'rate_pps'  : "10000",
                            'bi_dir'    : 1,
                            'bidirectional': '0'
                        }

        UCAST_v4_TI_2 = ixLib.configure_ixia_traffic_item_v46(UCAST_v4_dict_3)
            
        if UCAST_v4_TI_2 == 0:
            log.debug("Configuring UCast L2 TI failed")
            self.errored("Configuring UCast L2 TI failed", goto=['next_tc'])
        else:
            global stream_id_2
            stream_id_2 = UCAST_v4_TI_2

        

    # =============================================================================================================================#
    @aetest.test
    def APPLY_TRAFFIC(self):
        """ IXIA_CONFIGURATION subsection: Verify IXIA Traffic """

        # Apply IXIA Traffic
        if ixLib.apply_traffic() == 1:
            log.info("Applying IXIA TI Passed")
        else:
            self.errored("Applying IXIA TI failed", goto=['cleanup'])
            
        # =============================================================================================================================#
    @aetest.test
    def VERIFY_IXIA_TRAFFIC_Before_restart(self, testscript):
        """ IXIA_CONFIGURATION subsection: Verify IXIA Traffic """

        # Do not perform configurations if skip_tgen_config flag is set
    
        time.sleep(20)

        if ixLib.verify_traffic(2) == 0:
            log.debug("Traffic Verification failed")
            self.failed("Traffic Verification failed", goto=['cleanup'])
        else:
            log.info("Traffic Verification Passed")
      
    
    
    #--------------------------------------------------------------------------------#
        # Start traffic from ixia
        log.info("--- Populating the statistics --- \n")
        log.info("---- Running Traffic --- \n")
        log.info("Starting Traffic")

        traffic_run_status  = ixLib.start_traffic()

        if traffic_run_status is not 1:
           log.info("Failed: To start traffic")
           return 0
        else:
            log.info("\nTraffic started successfully\n")

        time.sleep(10)
        
    # =============================================================================================================================#
    # def config_mac_BH_route(testbed):
    #     node3_s1_bgw_1 = testbed.devices['node3_s1_bgw_1']
    #     node4_s1_bgw_2 =  testbed.devices['node4_s1_bgw_2']
    #     P3_dict = AcceSW_TGEN_data
    

    
    #     testbed.devices['node3_s1_bgw_1'].configure('''
    #         mac address-table static ''' + str(P3_dict['mac']) + ''' vlan '''+ str(P3_dict['vlan_id']) + ''' drop

    #         interface vlan ''' + str(P3_dict['vlan_id']) + '''
    #             ipv6 neighbor ''' + str(P3_dict['v6_addr']) + ''' ''' + str(P3_dict['mac']) + '''
    #             ip arp ''' + str(P3_dict['v4_addr']) + ''' ''' + str(P3_dict['mac']) + '''
    #     ''')
    #     testbed.devices['node4_s1_bgw_2'].configure('''
    #         mac address-table static ''' + str(P3_dict['mac']) + ''' vlan '''+ str(P3_dict['vlan_id']) + ''' drop

    #         interface vlan ''' + str(P3_dict['vlan_id']) + '''
    #             ipv6 neighbor ''' + str(P3_dict['v6_addr']) + ''' ''' + str(P3_dict['mac']) + '''
    #             ip arp ''' + str(P3_dict['v4_addr']) + ''' ''' + str(P3_dict['mac']) + '''
    #     ''')

    @aetest.test
    def TRIGGER_verify_L2FM_process_restart(self, testscript,testbed):
        """ ACLQOS_PROCESS_KILL_VERIFICATION subsection: Verify killing process ACLQOS """

        node3_s1_bgw_1 = testbed.devices['node3_s1_bgw_1']
        node5_s1_leaf_1 = testbed.devices['node5_s1_leaf_1']
        node4_s1_bgw_2 = testbed.devices['node4_s1_bgw_2']
        node7_s2_bgw_1 = testbed.devices['node7_s2_bgw_1']
        node9_s2_leaf_1 = testbed.devices['node9_s2_leaf_1']
        P3_dict = AcceSW_TGEN_data

        mac= str(P3_dict['mac'])
        vlan= str(P3_dict['vlan_id'])
        ip=str(P3_dict['v4_addr'])
        octet = 1
        no_int= int(P3_dict['no_of_ints'])
        
        for i in range (0,no_int):
            ###LEAF_3_MAC_BH_ROUTE
            testbed.devices['node3_s1_bgw_1'].configure('''
                mac address-table static ''' + str(mac) + ''' vlan '''+ str(vlan) + ''' drop

                interface vlan ''' + str(vlan) + '''
                  ip arp ''' + str(ip) + ''' ''' + str(mac) + '''
            ''')
            testbed.devices['node4_s1_bgw_2'].configure('''
                mac address-table static ''' + str(mac) + ''' vlan '''+ str(vlan) + ''' drop

                interface vlan ''' + str(vlan) + '''
                  ip arp ''' + str(ip) + ''' ''' + str(mac) + '''
            ''')
            lasthex=incr_mac(mac)
            mac=mac[0:10]+lasthex
            vlan= int(vlan)+int(P3_dict['vlan_id_step'])
            ip=incr_ip(ip,octet)

        if infraTrig.verifyProcessRestart(node3_s1_bgw_1,"l2fm"):
            log.info("Successfully restarted process L2FM")
        else:
            log.debug("Failed to restarted process L2FM")
            self.failed("Failed to restarted process L2FM", goto=['cleanup'])
        time.sleep(120)

        if infraTrig.verifyProcessRestart(node4_s1_bgw_2,"l2fm"):
            log.info("Successfully restarted process L2FM")
        else:
            log.debug("Failed to restarted process L2FM")
            self.failed("Failed to restarted process L2FM", goto=['cleanup'])
        time.sleep(120)

        if infraTrig.verifyProcessRestart(node7_s2_bgw_1,"l2fm"):
            log.info("Successfully restarted process L2FM")
        else:
            log.debug("Failed to restarted process L2FM")
            self.failed("Failed to restarted process L2FM", goto=['cleanup'])
        time.sleep(120)

    # =============================================================================================================================#  
    
    @aetest.test
    def VERIFY_IXIA_TRAFFIC(self, testscript):
        """ IXIA_CONFIGURATION subsection: Verify IXIA Traffic """

        # Do not perform configurations if skip_tgen_config flag is set
       

        time.sleep(20)

        if ixLib.verify_traffic(2) == 1:
            log.debug("Traffic Verification failed")
            self.failed("Traffic Verification failed", goto=['cleanup'])
        else:
            log.info("Traffic Verification Passed")
    
    # @aetest.test
    # def Unconfig_mac_BH_route(testbed):
    #     node3_s1_bgw_1 = testbed.devices['node3_s1_bgw_1']
    #     node4_s1_bgw_2 =  testbed.devices['node4_s1_bgw_2']
    #     P3_dict = AcceSW_TGEN_data
    
    #     testbed.devices['node3_s1_bgw_1'].configure('''
    #         no mac address-table static ''' + str(P3_dict['mac']) + ''' vlan '''+ str(P3_dict['vlan_id']) + ''' drop

    #         interface vlan ''' + str(P3_dict['vlan_id']) + '''
    #             no ipv6 neighbor ''' + str(P3_dict['v6_addr']) + ''' ''' + str(P3_dict['mac']) + '''
    #             no ip arp ''' + str(P3_dict['v4_addr']) + ''' ''' + str(P3_dict['mac']) + '''
    #     ''')
    #     testbed.devices['node4_s1_bgw_2'].configure('''
    #         no mac address-table static ''' + str(P3_dict['mac']) + ''' vlan '''+ str(P3_dict['vlan_id']) + ''' drop

    #         interface vlan ''' + str(P3_dict['vlan_id']) + '''
    #   ClouD$5678%
    #             no ipv6 neighbor ''' + str(P3_dict['v6_addr']) + ''' ''' + str(P3_dict['mac']) + '''
    #             no ip arp ''' + str(P3_dict['v4_addr']) + ''' ''' + str(P3_dict['mac']) + '''
    #     ''')
    @aetest.test
    def Verify_BH_states_in_HMM(self, testscript,testbed):
        node3_s1_bgw_1 =testbed.devices['node3_s1_bgw_1']
        node4_s1_bgw_2 = testbed.devices['node4_s1_bgw_2']
        node7_s2_bgw_1 = testbed.devices['node7_s2_bgw_1']
        P3_dict = AcceSW_TGEN_data

        try:
            if verify_BH_in_HMM(node4_s1_bgw_2,str(P3_dict['v4_addr'])):
                log.info('Mac BH route is proper in HMM on  S1_BGW1')
            else:
                log.info('Mac BH route is improper in HMM on  S1_BGW1')
                self.failed('Mac BH route is improper in HMM on  S1_BGW1')
        
         
        except Exception as error:
            log.debug("Unable to configure static BH mac route on Remote Vtep- Encountered Exception " + str(error))
            self.errored('Exception occurred while configuring static BH mac route on Remote Vtep', goto=['cleanup'])
    @aetest.test
    def Verify_BH_states_in_AM(self, testscript,testbed):
        node3_s1_bgw_1 = testbed.devices['node3_s1_bgw_1']
        node4_s1_bgw_2 = testbed.devices['node4_s1_bgw_2']
        node7_s2_bgw_1 = testbed.devices['node7_s2_bgw_1']
        P1_dict = S1_BGW1_TGEN_data
        P2_dict = S1_Leaf_TGEN_data
        P3_dict = AcceSW_TGEN_data
        P4_dict = S2_Leaf_TGEN_data

        try:        
            if verify_BH_in_AM(node4_s1_bgw_2,str(P3_dict['mac']),str(P3_dict['vlan_id']),str(P3_dict['v4_addr'])):
                log.info('Mac BH route is proper in AM on  S1_BGW1')
            else:
                log.info('Mac BH route is improper in AM on  S1_BGW1')
                self.failed('Mac BH route is improper in AM on  S1_BGW1')
                   
        
        except Exception as error:
            log.debug("Unable to configure static BH mac route on Remote Vtep- Encountered Exception " + str(error))
            self.errored('Exception occurred while configuring static BH mac route on Remote Vtep', goto=['cleanup'])
    @aetest.test
    def Verify_BH_states_in_remote_ARP(self, testscript,testbed):
        node3_s1_bgw_1 =testbed.devices['node3_s1_bgw_1']
        node7_s2_bgw_1 = testbed.devices['node7_s2_bgw_1']
        P3_dict = AcceSW_TGEN_data

        try: 

            if verify_BH_in_Remote_ARP(node7_s2_bgw_1,str(P3_dict['vlan_id']),str(P3_dict['mac'])):
               log.info('Mac BH route is proper in Remote ARP on  S2_BGW1')
            else:
                log.info('Mac BH route is improper in Remote ARP on  S2_BGW1')
                self.failed('Mac BH route is improper in Remote ARP on  S2_BGW1')

        except Exception as error:
            log.debug("Unable to configure static BH mac route on Remote Vtep- Encountered Exception " + str(error))
            self.errored('Exception occurred while configuring static BH mac route on Remote Vtep')        
    @aetest.test
    def Verify_BH_states_in_local_ARP(self, testscript,testbed):
        node3_s1_bgw_1 = testbed.devices['node3_s1_bgw_1']
        node7_s2_bgw_1 = testbed.devices['node7_s2_bgw_1']
        P1_dict = S1_BGW1_TGEN_data
        P2_dict = S1_Leaf_TGEN_data
        P3_dict = AcceSW_TGEN_data
        P4_dict = S2_Leaf_TGEN_data
        try:        
            if verify_BH_in_local_ARP(node3_s1_bgw_1,str(P3_dict['vlan_id']),str(P3_dict['mac'])):
                log.info('Mac BH route is proper in Local ARP on  S1_BGW1')
            else:
                log.info('Mac BH route is improper in Local ARP on  S1_BGW1')
                self.failed('Mac BH route is improper in Local ARP on  S1_BGW1')
        
        except Exception as error:
            log.debug("Unable to configure static BH mac route on Remote Vtep- Encountered Exception " + str(error))
            self.errored('Exception occurred while configuring static BH mac route on Remote Vtep')
    @aetest.test   
    def Verify_Mac_BH_Route_on_L2FM_BGP_L2RIB(self,testscript,testbed):
        node3_s1_bgw_1 = testbed.devices['node3_s1_bgw_1']
        node7_s2_bgw_1 = testbed.devices['node7_s2_bgw_1']
        P3_dict = AcceSW_TGEN_data
        
        # Verifying L2FM

        try:
            ###S1_BGW1_MAC_BH_ROUTE
            if verify_BH_route_in_L2FM(node3_s1_bgw_1,str(P3_dict['vlan_id']),str(P3_dict['mac'])):
                log.info('Mac BH route is proper in L2FM on  S1_BGw1')
            else:
                log.info('Mac BH route is improper in L2FM on  S1_BGw1')
                self.failed('Mac BH route is improper in L2FM on  S1_BGw1')

            ###S2_BGW1_MAC_BH_ROUTE Remote Vtep
            if verify_BH_route_in_L2FM(node7_s2_bgw_1,str(P3_dict['vlan_id']),str(P3_dict['mac'])):
                log.info('Mac BH route is proper in L2FM on  S2_BGw1')
            else:
                log.info('Mac BH route is improper in L2FM on  S2_BGw1')
                self.failed('Mac BH route is improper in L2FM on  S2_BGw1')

        except Exception as error:
            log.debug("Unable to verify BH mac route in L2FM - Encountered Exception " + str(error))
            self.errored('Exception occurred while verifying BH mac route in L2FM')        

        #Verifying L2RIB
        try:
            #S1_Leaf_Mac_BH_route
            if verify_L2rib_mac_ip_output(node3_s1_bgw_1,str(P3_dict['vlan_id']),str(P3_dict['mac'])):
                log.info('Mac BH route is proper in L2RIB on S1_Leaf')
            else:
                log.debug('Mac BH route is improper in L2RIB on  S1_Leaf')
                self.failed('Mac BH route is improper in L2RIB on  S1_Leaf')

            #S2_BGW1_Mac_BH_route
            if verify_L2rib_mac_ip_output(node7_s2_bgw_1,str(P3_dict['vlan_id']),str(P3_dict['mac'])):
                log.info('Mac BH route is proper in L2RIB on S2_BGW1')
            else:
                log.debug('Mac BH route is improper in L2RIB on  S2_BGW1')
                self.errored('Mac BH route is improper in L2RIB on  S2_BGW1')
        
        except Exception as error:
            log.debug("Unable to verify BH mac route in L2RIB - Encountered Exception " + str(error))
            self.errored('Exception occurred while verifying BH mac route in L2RIB')
        
        #Verifying BGP
        try:
            #S2_BGW1_Mac_BH_route
            if verify_BH_in_Remote_BGP(node7_s2_bgw_1,str(P3_dict['mac'])):
                log.info('Mac BH route is proper in BGP on S2_BGW1')
            else:
                log.debug('Mac BH route is improper in BGP on  S2_BGW1')
                self.errored('Mac BH route is improper in BGP on  S2_BGW1')

            #Access_Mac_BH_route
            if verify_BH_in_Remote_BGP(node3_s1_bgw_1,str(P3_dict['mac'])):
                log.info('Mac BH route is proper in BGP on Access')
            else:
                log.debug('Mac BH route is improper in BGP on  Access')
                self.errored('Mac BH route is improper in BGP on  Access')
        
        except Exception as error:
            log.debug("Unable to verify BH mac route in BGP - Encountered Exception " + str(error))
            self.errored('Exception occurred while verifying BH mac route in BGP', )


    @aetest.cleanup
    def cleanup(self,testscript,testbed):
        """Unconfigure qos policies"""
        node3_s1_bgw_1 = testbed.devices['node3_s1_bgw_1']
        node5_s1_leaf_1 = testbed.devices['node5_s1_leaf_1']
        node4_s1_bgw_2 = testbed.devices['node4_s1_bgw_2']
        node7_s2_bgw_1 = testbed.devices['node7_s2_bgw_1']
        node9_s2_leaf_1 = testbed.devices['node9_s2_leaf_1']
        P3_dict = AcceSW_TGEN_data
        forwardingSysDict = FWD_SYS_dict
        post_test_process_dict = {
            'dut_list'                       : [node3_s1_bgw_1,node4_s1_bgw_2,node7_s2_bgw_1],
            'cc_check'                  : 0,
            'cores_check'               : 1,
            'logs_check'                : 1,
            'fnl_flag'                  : 0,
            'exclude_log_check_pattern' : 'ERROR_VLANS_SUSPENDED|ERROR_VLANS_REMOVED|SYSMGR-2-SERVICE_CRASHED',
            }
        try:
            # Stop Traffic from ixia
            log.info("--- Stopping Traffic ---- \n")
            log.info("Stopping Traffic")
            traffic_run_status = ixLib.stop_traffic()
            
            if traffic_run_status is not 1:
               log.info("Failed: To Stop traffic")
               return 0
            else:
                log.info("\nTraffic Stopped successfully\n")
            time.sleep(10)
            ####Remove traffic item configured
            UCAST_v4_dict_3 = {
                            'mode'        : 'remove',
                            'stream_id'   : stream_id_2,
                      }
            if (ixLib.delete_traffic_item(UCAST_v4_dict_3))==0:
                log.debug("Traffic Remove failed")
                self.failed("Traffic Remove failed", goto=['next_tc'])
            else:
                log.info("Traffic Remove Passed")
                
            ##check for cores,cc,error
            mac= str(P3_dict['mac'])
            vlan= str(P3_dict['vlan_id'])
            ip=str(P3_dict['v4_addr'])
            octet = 1
            no_int= int(P3_dict['no_of_ints'])
        
            for i in range (0,no_int):
            ###LEAF_3_MAC_BH_ROUTE
                testbed.devices['node3_s1_bgw_1'].configure('''
                    no mac address-table static ''' + str(mac) + ''' vlan '''+ str(vlan) + ''' drop

                    interface vlan ''' + str(vlan) + '''
                        no ip arp ''' + str(ip) + ''' ''' + str(mac) + '''
                ''')
                testbed.devices['node4_s1_bgw_2'].configure('''
                    no mac address-table static ''' + str(mac) + ''' vlan '''+ str(vlan) + ''' drop

                    interface vlan ''' + str(vlan) + '''
                        no ip arp ''' + str(ip) + ''' ''' + str(mac) + '''
                ''')
                lasthex=incr_mac(mac)
                mac=mac[0:10]+lasthex
                vlan= int(vlan)+int(P3_dict['vlan_id_step'])
                ip=incr_ip(ip,octet)

            status = infraVerify.postTestVerification(post_test_process_dict)
            if status['status'] == 0:
                self.failed(reason=status['logs'])
            else:
                self.passed(reason=status['logs'])
        except Exception as error:
            log.debug("Unable to do cleanup " + str(error))
            self.errored('Exception occurred during cleanup', goto=['next_tc'])

class L2rib_PROCESS_RESTART(nxtest.Testcase):
    #"TC_0091_L2rib_PROCESS_RESTART",
   

    stream_id=''
    @aetest.test
    def CONFIGURE_UCAST_IXIA_TRAFFIC(self, testscript):
        """ IXIA_CONFIGURATION subsection: Configure MCAST Traffic Item """

        # Do not perform configurations if skip_tgen_config flag is set
      
        IX_TP1 = testscript.parameters['IX_TP1']
        IX_TP2 = testscript.parameters['IX_TP2']
        IX_TP3 = testscript.parameters['IX_TP3']
        IX_TP4 = testscript.parameters['IX_TP4']
        P1_dict = S1_BGW1_TGEN_data
        P2_dict = S1_Leaf_TGEN_data
        P3_dict = AcceSW_TGEN_data
        P4_dict = S2_Leaf_TGEN_data
        # P1_dict = S1_BGW1_TGEN_data
        # P4_dict = testscript.parameters['S2_BGW1_TGEN_dict']

        UCAST_v4_dict = {   'src_hndl'  : IX_TP4['ipv4_handle'],
                            'dst_hndl'  : IX_TP3['ipv4_handle'],
                            'circuit'   : 'ipv4',
                            'TI_name'   : "UCAST_V4",
                            'rate_pps'  : "10000",
                            'bi_dir'    : 1,
                            'bidirectional': '0'
                        }


        #UCAST_v6_dict = {   'src_hndl'  : IX_TP1['ipv6_handle'],
        #                    'dst_hndl'  : IX_TP2['ipv6_handle'],
        #                    'circuit'   : 'ipv6',
        #                    'TI_name'   : "UCAST_V6",
        #                    'rate_pps'  : "1000",
        #                    'bi_dir'    : 1
        #              }

        UCAST_v4_TI = ixLib.configure_ixia_traffic_item_v46(UCAST_v4_dict)
        #UCAST_v6_TI = ixLib.configure_ixia_traffic_item_v46(UCAST_v6_dict)

        #if UCAST_v4_TI == 0 or UCAST_v6_TI == 0:
        #    log.debug("Configuring UCast TI failed")
        #    self.errored("Configuring UCast TI failed", goto=['next_tc'])
            
        if UCAST_v4_TI == 0:
            log.debug("Configuring UCast L2 TI failed")
            self.errored("Configuring UCast L2 TI failed", goto=['cleanup'])
        else:
            global stream_id
            stream_id = UCAST_v4_TI
            log.info('stream_id='+stream_id)
            log.info(type(stream_id))


    # =============================================================================================================================#
    @aetest.test
    def APPLY_TRAFFIC(self):
        """ IXIA_CONFIGURATION subsection: Verify IXIA Traffic """

        # Apply IXIA Traffic
        if ixLib.apply_traffic() == 1:
            log.info("Applying IXIA TI Passed")
        else:
            self.errored("Applying IXIA TI failed", goto=['cleanup'])
            
        # =============================================================================================================================#
    @aetest.test
    def VERIFY_IXIA_TRAFFIC_before_restart(self, testscript):
        """ IXIA_CONFIGURATION subsection: Verify IXIA Traffic """

        # Do not perform configurations if skip_tgen_config flag is set
       

        time.sleep(20)

        if ixLib.verify_traffic(2) == 0:
            log.debug("Traffic Verification failed")
            self.failed("Traffic Verification failed", goto=['cleanup'])
        else:
            log.info("Traffic Verification Passed")
       
    
    
    #--------------------------------------------------------------------------------#
        # Start traffic from ixia
        log.info("--- Populating the statistics --- \n")
        log.info("---- Running Traffic --- \n")
        log.info("Starting Traffic")

        traffic_run_status  = ixLib.start_traffic()

        if traffic_run_status is not 1:
           log.info("Failed: To start traffic")
           return 0
        else:
            log.info("\nTraffic started successfully\n")

        time.sleep(10)
        
    # =============================================================================================================================#
    # def config_mac_BH_route(testbed):
    #     node3_s1_bgw_1 = testbed.devices['node3_s1_bgw_1']
    #     node4_s1_bgw_2 =  testbed.devices['node4_s1_bgw_2']
    #     P3_dict = AcceSW_TGEN_data
    

    
    #     testbed.devices['node3_s1_bgw_1'].configure('''
    #         mac address-table static ''' + str(P3_dict['mac']) + ''' vlan '''+ str(P3_dict['vlan_id']) + ''' drop

    #         interface vlan ''' + str(P3_dict['vlan_id']) + '''
    #             ipv6 neighbor ''' + str(P3_dict['v6_addr']) + ''' ''' + str(P3_dict['mac']) + '''
    #             ip arp ''' + str(P3_dict['v4_addr']) + ''' ''' + str(P3_dict['mac']) + '''
    #     ''')
    #     testbed.devices['node4_s1_bgw_2'].configure('''
    #         mac address-table static ''' + str(P3_dict['mac']) + ''' vlan '''+ str(P3_dict['vlan_id']) + ''' drop

    #         interface vlan ''' + str(P3_dict['vlan_id']) + '''
    #             ipv6 neighbor ''' + str(P3_dict['v6_addr']) + ''' ''' + str(P3_dict['mac']) + '''
    #             ip arp ''' + str(P3_dict['v4_addr']) + ''' ''' + str(P3_dict['mac']) + '''
        # ''')

    @aetest.test
    def TRIGGER_verify_L2rib_process_restart(self, testscript,testbed):
        """ ACLQOS_PROCESS_KILL_VERIFICATION subsection: Verify killing process ACLQOS """

        node3_s1_bgw_1 = testbed.devices['node3_s1_bgw_1']
        node5_s1_leaf_1 = testbed.devices['node5_s1_leaf_1']
        node4_s1_bgw_2 = testbed.devices['node4_s1_bgw_2']
        node7_s2_bgw_1 = testbed.devices['node7_s2_bgw_1']
        node9_s2_leaf_1 = testbed.devices['node9_s2_leaf_1']
        P3_dict = AcceSW_TGEN_data

        mac= str(P3_dict['mac'])
        vlan= str(P3_dict['vlan_id'])
        ip=str(P3_dict['v4_addr'])
        octet = 1
        no_int= int(P3_dict['no_of_ints'])
        
        for i in range (0,no_int):
            ###LEAF_3_MAC_BH_ROUTE
            testbed.devices['node3_s1_bgw_1'].configure('''
                mac address-table static ''' + str(mac) + ''' vlan '''+ str(vlan) + ''' drop

                interface vlan ''' + str(vlan) + '''
                  ip arp ''' + str(ip) + ''' ''' + str(mac) + '''
            ''')
            testbed.devices['node4_s1_bgw_2'].configure('''
                mac address-table static ''' + str(mac) + ''' vlan '''+ str(vlan) + ''' drop

                interface vlan ''' + str(vlan) + '''
                  ip arp ''' + str(ip) + ''' ''' + str(mac) + '''
            ''')
            lasthex=incr_mac(mac)
            mac=mac[0:10]+lasthex
            vlan= int(vlan)+int(P3_dict['vlan_id_step'])
            ip=incr_ip(ip,octet)

        if infraTrig.verifyProcessRestart(node3_s1_bgw_1,"l2rib"):
            log.info("Successfully restarted process L2rib")
        else:
            log.debug("Failed to restarted process L2rib")
            self.failed("Failed to restarted process L2rib", goto=['cleanup'])
        time.sleep(120)

        if infraTrig.verifyProcessRestart(node4_s1_bgw_2,"l2rib"):
            log.info("Successfully restarted process L2rib")
        else:
            log.debug("Failed to restarted process L2rib")
            self.failed("Failed to restarted process L2rib", goto=['cleanup'])
        time.sleep(120)

        if infraTrig.verifyProcessRestart(node7_s2_bgw_1,"l2rib"):
            log.info("Successfully restarted process L2rib")
        else:
            log.debug("Failed to restarted process L2rib")
            self.failed("Failed to restarted process L2rib", goto=['cleanup'])
        time.sleep(120)

    # =============================================================================================================================#  
    
    @aetest.test
    def VERIFY_IXIA_TRAFFIC(self, testscript):
        """ IXIA_CONFIGURATION subsection: Verify IXIA Traffic """

        # Do not perform configurations if skip_tgen_config flag is set
       

        time.sleep(20)

        if ixLib.verify_traffic(2) == 1:
            log.debug("Traffic Verification failed")
            self.failed("Traffic Verification failed", goto=['cleanup'])
        else:
            log.info("Traffic Verification Passed")
       
    # @aetest.test
    # def Unconfig_mac_BH_route(testbed):
    #     node3_s1_bgw_1 = testbed.devices['node3_s1_bgw_1']
    #     node4_s1_bgw_2 =  testbed.devices['node4_s1_bgw_2']
    #     P3_dict = AcceSW_TGEN_data
    

    
    #     testbed.devices['node3_s1_bgw_1'].configure('''
    #         no mac address-table static ''' + str(P3_dict['mac']) + ''' vlan '''+ str(P3_dict['vlan_id']) + ''' drop

    #         interface vlan ''' + str(P3_dict['vlan_id']) + '''
    #             no ipv6 neighbor ''' + str(P3_dict['v6_addr']) + ''' ''' + str(P3_dict['mac']) + '''
    #             no ip arp ''' + str(P3_dict['v4_addr']) + ''' ''' + str(P3_dict['mac']) + '''
    #     ''')
    #     testbed.devices['node4_s1_bgw_2'].configure('''
    #         no mac address-table static ''' + str(P3_dict['mac']) + ''' vlan '''+ str(P3_dict['vlan_id']) + ''' drop

    #         interface vlan ''' + str(P3_dict['vlan_id']) + '''
    #             no ipv6 neighbor ''' + str(P3_dict['v6_addr']) + ''' ''' + str(P3_dict['mac']) + '''
    #             no ip arp ''' + str(P3_dict['v4_addr']) + ''' ''' + str(P3_dict['mac']) + '''
    #     ''')

    @aetest.test
    def Verify_BH_states_in_HMM(self, testscript,testbed):
        node3_s1_bgw_1 =testbed.devices['node3_s1_bgw_1']
        node4_s1_bgw_2 = testbed.devices['node4_s1_bgw_2']
        node7_s2_bgw_1 = testbed.devices['node7_s2_bgw_1']
        P3_dict = AcceSW_TGEN_data

        try:
            if verify_BH_in_HMM(node4_s1_bgw_2,str(P3_dict['v4_addr'])):
                log.info('Mac BH route is proper in HMM on  S1_BGW1')
            else:
                log.info('Mac BH route is improper in HMM on  S1_BGW1')
                self.failed('Mac BH route is improper in HMM on  S1_BGW1')
        
         
        except Exception as error:
            log.debug("Unable to configure static BH mac route on Remote Vtep- Encountered Exception " + str(error))
            self.errored('Exception occurred while configuring static BH mac route on Remote Vtep', goto=['cleanup'])
    @aetest.test
    def Verify_BH_states_in_AM(self, testscript,testbed):
        node3_s1_bgw_1 = testbed.devices['node3_s1_bgw_1']
        node4_s1_bgw_2 = testbed.devices['node4_s1_bgw_2']
        node7_s2_bgw_1 = testbed.devices['node7_s2_bgw_1']
        P1_dict = S1_BGW1_TGEN_data
        P2_dict = S1_Leaf_TGEN_data
        P3_dict = AcceSW_TGEN_data
        P4_dict = S2_Leaf_TGEN_data

        try:        
            if verify_BH_in_AM(node4_s1_bgw_2,str(P3_dict['mac']),str(P3_dict['vlan_id']),str(P3_dict['v4_addr'])):
                log.info('Mac BH route is proper in AM on  S1_BGW1')
            else:
                log.info('Mac BH route is improper in AM on  S1_BGW1')
                self.failed('Mac BH route is improper in AM on  S1_BGW1')
                   
        
        except Exception as error:
            log.debug("Unable to configure static BH mac route on Remote Vtep- Encountered Exception " + str(error))
            self.errored('Exception occurred while configuring static BH mac route on Remote Vtep', goto=['cleanup'])
    @aetest.test
    def Verify_BH_states_in_remote_ARP(self, testscript,testbed):
        node3_s1_bgw_1 =testbed.devices['node3_s1_bgw_1']
        node7_s2_bgw_1 = testbed.devices['node7_s2_bgw_1']
        P3_dict = AcceSW_TGEN_data

        try: 

            if verify_BH_in_Remote_ARP(node7_s2_bgw_1,str(P3_dict['vlan_id']),str(P3_dict['mac'])):
               log.info('Mac BH route is proper in Remote ARP on  S2_BGW1')
            else:
                log.info('Mac BH route is improper in Remote ARP on  S2_BGW1')
                self.failed('Mac BH route is improper in Remote ARP on  S2_BGW1')

        except Exception as error:
            log.debug("Unable to configure static BH mac route on Remote Vtep- Encountered Exception " + str(error))
            self.errored('Exception occurred while configuring static BH mac route on Remote Vtep')        
    @aetest.test
    def Verify_BH_states_in_local_ARP(self, testscript,testbed):
        node3_s1_bgw_1 = testbed.devices['node3_s1_bgw_1']
        node7_s2_bgw_1 = testbed.devices['node7_s2_bgw_1']
        P1_dict = S1_BGW1_TGEN_data
        P2_dict = S1_Leaf_TGEN_data
        P3_dict = AcceSW_TGEN_data
        P4_dict = S2_Leaf_TGEN_data
        try:        
            if verify_BH_in_local_ARP(node3_s1_bgw_1,str(P3_dict['vlan_id']),str(P3_dict['mac'])):
                log.info('Mac BH route is proper in Local ARP on  S1_BGW1')
            else:
                log.info('Mac BH route is improper in Local ARP on  S1_BGW1')
                self.failed('Mac BH route is improper in Local ARP on  S1_BGW1')
        
        except Exception as error:
            log.debug("Unable to configure static BH mac route on Remote Vtep- Encountered Exception " + str(error))
            self.errored('Exception occurred while configuring static BH mac route on Remote Vtep')
    @aetest.test    
    def Verify_Mac_BH_Route_on_L2FM_BGP_L2RIB(self,testscript,testbed):
        node3_s1_bgw_1 = testbed.devices['node3_s1_bgw_1']
        node7_s2_bgw_1 = testbed.devices['node7_s2_bgw_1']
        P3_dict = AcceSW_TGEN_data
        
        # Verifying L2FM

        try:
            ###S1_BGW1_MAC_BH_ROUTE
            if verify_BH_route_in_L2FM(node3_s1_bgw_1,str(P3_dict['vlan_id']),str(P3_dict['mac'])):
                log.info('Mac BH route is proper in L2FM on  S1_BGw1')
            else:
                log.info('Mac BH route is improper in L2FM on  S1_BGw1')
                self.failed('Mac BH route is improper in L2FM on  S1_BGw1')

            ###S2_BGW1_MAC_BH_ROUTE Remote Vtep
            if verify_BH_route_in_L2FM(node7_s2_bgw_1,str(P3_dict['vlan_id']),str(P3_dict['mac'])):
                log.info('Mac BH route is proper in L2FM on  S2_BGw1')
            else:
                log.info('Mac BH route is improper in L2FM on  S2_BGw1')
                self.failed('Mac BH route is improper in L2FM on  S2_BGw1')

        except Exception as error:
            log.debug("Unable to verify BH mac route in L2FM - Encountered Exception " + str(error))
            self.errored('Exception occurred while verifying BH mac route in L2FM')        

        #Verifying L2RIB
        try:
            #S1_Leaf_Mac_BH_route
            if verify_L2rib_mac_ip_output(node3_s1_bgw_1,str(P3_dict['vlan_id']),str(P3_dict['mac'])):
                log.info('Mac BH route is proper in L2RIB on S1_Leaf')
            else:
                log.debug('Mac BH route is improper in L2RIB on  S1_Leaf')
                self.failed('Mac BH route is improper in L2RIB on  S1_Leaf')

            #S2_BGW1_Mac_BH_route
            if verify_L2rib_mac_ip_output(node7_s2_bgw_1,str(P3_dict['vlan_id']),str(P3_dict['mac'])):
                log.info('Mac BH route is proper in L2RIB on S2_BGW1')
            else:
                log.debug('Mac BH route is improper in L2RIB on  S2_BGW1')
                self.errored('Mac BH route is improper in L2RIB on  S2_BGW1')
        
        except Exception as error:
            log.debug("Unable to verify BH mac route in L2RIB - Encountered Exception " + str(error))
            self.errored('Exception occurred while verifying BH mac route in L2RIB')
        
        #Verifying BGP
        try:
            #S2_BGW1_Mac_BH_route
            if verify_BH_in_Remote_BGP(node7_s2_bgw_1,str(P3_dict['mac'])):
                log.info('Mac BH route is proper in BGP on S2_BGW1')
            else:
                log.debug('Mac BH route is improper in BGP on  S2_BGW1')
                self.errored('Mac BH route is improper in BGP on  S2_BGW1')

            #Access_Mac_BH_route
            if verify_BH_in_Remote_BGP(node3_s1_bgw_1,str(P3_dict['mac'])):
                log.info('Mac BH route is proper in BGP on Access')
            else:
                log.debug('Mac BH route is improper in BGP on  Access')
                self.errored('Mac BH route is improper in BGP on  Access')
        
        except Exception as error:
            log.debug("Unable to verify BH mac route in BGP - Encountered Exception " + str(error))
            self.errored('Exception occurred while verifying BH mac route in BGP', )


    @aetest.cleanup
    def cleanup(self,testscript,testbed):
        """Unconfigure qos policies"""
        node3_s1_bgw_1 = testbed.devices['node3_s1_bgw_1']
        node5_s1_leaf_1 = testbed.devices['node5_s1_leaf_1']
        node4_s1_bgw_2 = testbed.devices['node4_s1_bgw_2']
        node7_s2_bgw_1 = testbed.devices['node7_s2_bgw_1']
        node9_s2_leaf_1 = testbed.devices['node9_s2_leaf_1']
        forwardingSysDict = FWD_SYS_dict
        P3_dict = AcceSW_TGEN_data
        post_test_process_dict = {
            'dut_list'                       : [node3_s1_bgw_1,node4_s1_bgw_2,node7_s2_bgw_1],
            'cc_check'                  : 0,
            'cores_check'               : 1,
            'logs_check'                : 1,
            'fnl_flag'                  : 0,
            'exclude_log_check_pattern' : 'ERROR_VLANS_SUSPENDED|ERROR_VLANS_REMOVED|SYSMGR-2-SERVICE_CRASHED',
            }
        try:
            # Stop Traffic from ixia
            log.info("--- Stopping Traffic ---- \n")
            log.info("Stopping Traffic")
            traffic_run_status = ixLib.stop_traffic()
            
            if traffic_run_status is not 1:
               log.info("Failed: To Stop traffic")
               return 0
            else:
                log.info("\nTraffic Stopped successfully\n")
            time.sleep(10)
            ####Remove traffic item configured
            UCAST_L2_dict = {
                            'mode'        : 'remove',
                            'stream_id'   : stream_id,
                      }
            if (ixLib.delete_traffic_item(UCAST_L2_dict))==0:
                log.debug("Traffic Remove failed")
                self.failed("Traffic Remove failed", goto=['next_tc'])
            else:
                log.info("Traffic Remove Passed")
            
            mac= str(P3_dict['mac'])
            vlan= str(P3_dict['vlan_id'])
            ip=str(P3_dict['v4_addr'])
            octet = 1
            no_int= int(P3_dict['no_of_ints'])
        
            for i in range (0,no_int):
            ###LEAF_3_MAC_BH_ROUTE
                testbed.devices['node3_s1_bgw_1'].configure('''
                    no mac address-table static ''' + str(mac) + ''' vlan '''+ str(vlan) + ''' drop

                    interface vlan ''' + str(vlan) + '''
                        no ip arp ''' + str(ip) + ''' ''' + str(mac) + '''
                ''')
                testbed.devices['node4_s1_bgw_2'].configure('''
                    no mac address-table static ''' + str(mac) + ''' vlan '''+ str(vlan) + ''' drop

                    interface vlan ''' + str(vlan) + '''
                        no ip arp ''' + str(ip) + ''' ''' + str(mac) + '''
                ''')
                lasthex=incr_mac(mac)
                mac=mac[0:10]+lasthex
                vlan= int(vlan)+int(P3_dict['vlan_id_step'])
                ip=incr_ip(ip,octet)

            ##check for cores,cc,errors
            status = infraVerify.postTestVerification(post_test_process_dict)
            if status['status'] == 0:
                self.failed(reason=status['logs'])
            else:
                self.passed(reason=status['logs'])
        except Exception as error:
            log.debug("Unable to do cleanup " + str(error))
            self.errored('Exception occurred during cleanup', goto=['next_tc'])


class HMM_PROCESS_RESTART(nxtest.Testcase):
    #"TC_0092_HMM_PROCESS_RESTART"
   

    stream_id=''
    @aetest.test
    def CONFIGURE_UCAST_IXIA_TRAFFIC(self, testscript):
        """ IXIA_CONFIGURATION subsection: Configure MCAST Traffic Item """

        # Do not perform configurations if skip_tgen_config flag is set
      
        IX_TP1 = testscript.parameters['IX_TP1']
        IX_TP2 = testscript.parameters['IX_TP2']
        IX_TP3 = testscript.parameters['IX_TP3']
        IX_TP4 = testscript.parameters['IX_TP4']
        P1_dict = S1_BGW1_TGEN_data
        P2_dict = S1_Leaf_TGEN_data
        P3_dict = AcceSW_TGEN_data
        P4_dict = S2_Leaf_TGEN_data
        # P1_dict = S1_BGW1_TGEN_data
        # P4_dict = testscript.parameters['S2_BGW1_TGEN_dict']

        UCAST_v4_dict = {   'src_hndl'  : IX_TP4['ipv4_handle'],
                            'dst_hndl'  : IX_TP3['ipv4_handle'],
                            'circuit'   : 'ipv4',
                            'TI_name'   : "UCAST_V4",
                            'rate_pps'  : "10000",
                            'bi_dir'    : 1,
                            'bidirectional': '0'
                        }


        #UCAST_v6_dict = {   'src_hndl'  : IX_TP1['ipv6_handle'],
        #                    'dst_hndl'  : IX_TP2['ipv6_handle'],
        #                    'circuit'   : 'ipv6',
        #                    'TI_name'   : "UCAST_V6",
        #                    'rate_pps'  : "1000",
        #                    'bi_dir'    : 1
        #              }

        UCAST_v4_TI = ixLib.configure_ixia_traffic_item_v46(UCAST_v4_dict)
        #UCAST_v6_TI = ixLib.configure_ixia_traffic_item_v46(UCAST_v6_dict)

        #if UCAST_v4_TI == 0 or UCAST_v6_TI == 0:
        #    log.debug("Configuring UCast TI failed")
        #    self.errored("Configuring UCast TI failed", goto=['next_tc'])
            
        if UCAST_v4_TI == 0:
            log.debug("Configuring UCast L2 TI failed")
            self.errored("Configuring UCast L2 TI failed", goto=['cleanup'])
        else:
            global stream_id
            stream_id = UCAST_v4_TI
            log.info('stream_id='+stream_id)
            log.info(type(stream_id))


    # =============================================================================================================================#
    @aetest.test
    def APPLY_TRAFFIC(self):
        """ IXIA_CONFIGURATION subsection: Verify IXIA Traffic """

        # Apply IXIA Traffic
        if ixLib.apply_traffic() == 1:
            log.info("Applying IXIA TI Passed")
        else:
            self.errored("Applying IXIA TI failed", goto=['cleanup'])
            
        # =============================================================================================================================#
    @aetest.test
    def VERIFY_IXIA_TRAFFIC_before_restart(self, testscript):
        """ IXIA_CONFIGURATION subsection: Verify IXIA Traffic """

        # Do not perform configurations if skip_tgen_config flag is set
       

        time.sleep(20)

        if ixLib.verify_traffic(2) == 0:
            log.debug("Traffic Verification failed")
            self.failed("Traffic Verification failed", goto=['cleanup'])
        else:
            log.info("Traffic Verification Passed")
       
    
    
    #--------------------------------------------------------------------------------#
        # Start traffic from ixia
        log.info("--- Populating the statistics --- \n")
        log.info("---- Running Traffic --- \n")
        log.info("Starting Traffic")

        traffic_run_status  = ixLib.start_traffic()

        if traffic_run_status is not 1:
           log.info("Failed: To start traffic")
           return 0
        else:
            log.info("\nTraffic started successfully\n")

        time.sleep(10)
        
    # =============================================================================================================================#
    # def config_mac_BH_route(testbed):
    #     node3_s1_bgw_1 = testbed.devices['node3_s1_bgw_1']
    #     node4_s1_bgw_2 =  testbed.devices['node4_s1_bgw_2']
    #     P3_dict = AcceSW_TGEN_data
    

    
    #     testbed.devices['node3_s1_bgw_1'].configure('''
    #         mac address-table static ''' + str(P3_dict['mac']) + ''' vlan '''+ str(P3_dict['vlan_id']) + ''' drop

    #         interface vlan ''' + str(P3_dict['vlan_id']) + '''
    #             ipv6 neighbor ''' + str(P3_dict['v6_addr']) + ''' ''' + str(P3_dict['mac']) + '''
    #             ip arp ''' + str(P3_dict['v4_addr']) + ''' ''' + str(P3_dict['mac']) + '''
    #     ''')
    #     testbed.devices['node4_s1_bgw_2'].configure('''
    #         mac address-table static ''' + str(P3_dict['mac']) + ''' vlan '''+ str(P3_dict['vlan_id']) + ''' drop

    #         interface vlan ''' + str(P3_dict['vlan_id']) + '''
    #             ipv6 neighbor ''' + str(P3_dict['v6_addr']) + ''' ''' + str(P3_dict['mac']) + '''
    #             ip arp ''' + str(P3_dict['v4_addr']) + ''' ''' + str(P3_dict['mac']) + '''
    #     ''')

    @aetest.test
    def TRIGGER_verify_HMM_process_restart(self, testscript,testbed):
        """ ACLQOS_PROCESS_KILL_VERIFICATION subsection: Verify killing process ACLQOS """

        node3_s1_bgw_1 = testbed.devices['node3_s1_bgw_1']
        node5_s1_leaf_1 = testbed.devices['node5_s1_leaf_1']
        node4_s1_bgw_2 = testbed.devices['node4_s1_bgw_2']
        node7_s2_bgw_1 = testbed.devices['node7_s2_bgw_1']
        node9_s2_leaf_1 = testbed.devices['node9_s2_leaf_1']
        P3_dict = AcceSW_TGEN_data

        mac= str(P3_dict['mac'])
        vlan= str(P3_dict['vlan_id'])
        ip=str(P3_dict['v4_addr'])
        octet = 1
        no_int= int(P3_dict['no_of_ints'])
        
        for i in range (0,no_int):
            ###LEAF_3_MAC_BH_ROUTE
            testbed.devices['node3_s1_bgw_1'].configure('''
                mac address-table static ''' + str(mac) + ''' vlan '''+ str(vlan) + ''' drop

                interface vlan ''' + str(vlan) + '''
                  ip arp ''' + str(ip) + ''' ''' + str(mac) + '''
            ''')
            testbed.devices['node4_s1_bgw_2'].configure('''
                mac address-table static ''' + str(mac) + ''' vlan '''+ str(vlan) + ''' drop

                interface vlan ''' + str(vlan) + '''
                  ip arp ''' + str(ip) + ''' ''' + str(mac) + '''
            ''')
            lasthex=incr_mac(mac)
            mac=mac[0:10]+lasthex
            vlan= int(vlan)+int(P3_dict['vlan_id_step'])
            ip=incr_ip(ip,octet)

        if infraTrig.verifyProcessRestart(node3_s1_bgw_1,"hmm"):
            log.info("Successfully restarted process hmm")
        else:
            log.debug("Failed to restarted process hmm")
            self.failed("Failed to restarted process hmm", goto=['cleanup'])
        time.sleep(120)

        if infraTrig.verifyProcessRestart(node4_s1_bgw_2,"hmm"):
            log.info("Successfully restarted process hmm")
        else:
            log.debug("Failed to restarted process hmm")
            self.failed("Failed to restarted process hmm", goto=['cleanup'])
        time.sleep(120)

        if infraTrig.verifyProcessRestart(node7_s2_bgw_1,"hmm"):
            log.info("Successfully restarted process hmm")
        else:
            log.debug("Failed to restarted process hmm")
            self.failed("Failed to restarted process hmm", goto=['cleanup'])
        time.sleep(120)

    # =============================================================================================================================#  
    
    @aetest.test
    def VERIFY_IXIA_TRAFFIC(self, testscript):
        """ IXIA_CONFIGURATION subsection: Verify IXIA Traffic """

        # Do not perform configurations if skip_tgen_config flag is set
       

        time.sleep(20)

        if ixLib.verify_traffic(2) == 1:
            log.debug("Traffic Verification failed")
            self.failed("Traffic Verification failed", goto=['cleanup'])
        else:
            log.info("Traffic Verification Passed")
    
    # @aetest.test
    # def Unconfig_mac_BH_route(testbed):
    #     node3_s1_bgw_1 = testbed.devices['node3_s1_bgw_1']
    #     node4_s1_bgw_2 =  testbed.devices['node4_s1_bgw_2']
    #     P3_dict = AcceSW_TGEN_data
    

    
    #     testbed.devices['node3_s1_bgw_1'].configure('''
    #         no mac address-table static ''' + str(P3_dict['mac']) + ''' vlan '''+ str(P3_dict['vlan_id']) + ''' drop

    #         interface vlan ''' + str(P3_dict['vlan_id']) + '''
    #             no ipv6 neighbor ''' + str(P3_dict['v6_addr']) + ''' ''' + str(P3_dict['mac']) + '''
    #             no ip arp ''' + str(P3_dict['v4_addr']) + ''' ''' + str(P3_dict['mac']) + '''
    #     ''')
    #     testbed.devices['node4_s1_bgw_2'].configure('''
    #         no mac address-table static ''' + str(P3_dict['mac']) + ''' vlan '''+ str(P3_dict['vlan_id']) + ''' drop

    #         interface vlan ''' + str(P3_dict['vlan_id']) + '''
    #             no ipv6 neighbor ''' + str(P3_dict['v6_addr']) + ''' ''' + str(P3_dict['mac']) + '''
    #             no ip arp ''' + str(P3_dict['v4_addr']) + ''' ''' + str(P3_dict['mac']) + '''
    #     ''')
    @aetest.test
    def Verify_BH_states_in_HMM(self, testscript,testbed):
        node3_s1_bgw_1 =testbed.devices['node3_s1_bgw_1']
        node4_s1_bgw_2 = testbed.devices['node4_s1_bgw_2']
        node7_s2_bgw_1 = testbed.devices['node7_s2_bgw_1']
        P3_dict = AcceSW_TGEN_data

        try:
            if verify_BH_in_HMM(node4_s1_bgw_2,str(P3_dict['v4_addr'])):
                log.info('Mac BH route is proper in HMM on  S1_BGW1')
            else:
                log.info('Mac BH route is improper in HMM on  S1_BGW1')
                self.failed('Mac BH route is improper in HMM on  S1_BGW1')
        
         
        except Exception as error:
            log.debug("Unable to configure static BH mac route on Remote Vtep- Encountered Exception " + str(error))
            self.errored('Exception occurred while configuring static BH mac route on Remote Vtep', goto=['cleanup'])
    @aetest.test
    def Verify_BH_states_in_AM(self, testscript,testbed):
        node3_s1_bgw_1 = testbed.devices['node3_s1_bgw_1']
        node4_s1_bgw_2 = testbed.devices['node4_s1_bgw_2']
        node7_s2_bgw_1 = testbed.devices['node7_s2_bgw_1']
        P1_dict = S1_BGW1_TGEN_data
        P2_dict = S1_Leaf_TGEN_data
        P3_dict = AcceSW_TGEN_data
        P4_dict = S2_Leaf_TGEN_data

        try:        
            if verify_BH_in_AM(node4_s1_bgw_2,str(P3_dict['mac']),str(P3_dict['vlan_id']),str(P3_dict['v4_addr'])):
                log.info('Mac BH route is proper in AM on  S1_BGW1')
            else:
                log.info('Mac BH route is improper in AM on  S1_BGW1')
                self.failed('Mac BH route is improper in AM on  S1_BGW1')
                   
        
        except Exception as error:
            log.debug("Unable to configure static BH mac route on Remote Vtep- Encountered Exception " + str(error))
            self.errored('Exception occurred while configuring static BH mac route on Remote Vtep', goto=['cleanup'])
    @aetest.test
    def Verify_BH_states_in_remote_ARP(self, testscript,testbed):
        node3_s1_bgw_1 =testbed.devices['node3_s1_bgw_1']
        node7_s2_bgw_1 = testbed.devices['node7_s2_bgw_1']
        P3_dict = AcceSW_TGEN_data

        try: 

            if verify_BH_in_Remote_ARP(node7_s2_bgw_1,str(P3_dict['vlan_id']),str(P3_dict['mac'])):
               log.info('Mac BH route is proper in Remote ARP on  S2_BGW1')
            else:
                log.info('Mac BH route is improper in Remote ARP on  S2_BGW1')
                self.failed('Mac BH route is improper in Remote ARP on  S2_BGW1')

        except Exception as error:
            log.debug("Unable to configure static BH mac route on Remote Vtep- Encountered Exception " + str(error))
            self.errored('Exception occurred while configuring static BH mac route on Remote Vtep')        
    @aetest.test
    def Verify_BH_states_in_local_ARP(self, testscript,testbed):
        node3_s1_bgw_1 = testbed.devices['node3_s1_bgw_1']
        node7_s2_bgw_1 = testbed.devices['node7_s2_bgw_1']
        P1_dict = S1_BGW1_TGEN_data
        P2_dict = S1_Leaf_TGEN_data
        P3_dict = AcceSW_TGEN_data
        P4_dict = S2_Leaf_TGEN_data
        try:        
            if verify_BH_in_local_ARP(node3_s1_bgw_1,str(P3_dict['vlan_id']),str(P3_dict['mac'])):
                log.info('Mac BH route is proper in Local ARP on  S1_BGW1')
            else:
                log.info('Mac BH route is improper in Local ARP on  S1_BGW1')
                self.failed('Mac BH route is improper in Local ARP on  S1_BGW1')
        
        except Exception as error:
            log.debug("Unable to configure static BH mac route on Remote Vtep- Encountered Exception " + str(error))
            self.errored('Exception occurred while configuring static BH mac route on Remote Vtep')
    @aetest.test  
    def Verify_Mac_BH_Route_on_L2FM_BGP_L2RIB(self,testscript,testbed):
        node3_s1_bgw_1 = testbed.devices['node3_s1_bgw_1']
        node7_s2_bgw_1 = testbed.devices['node7_s2_bgw_1']
        P3_dict = AcceSW_TGEN_data
        
        # Verifying L2FM

        try:
            ###S1_BGW1_MAC_BH_ROUTE
            if verify_BH_route_in_L2FM(node3_s1_bgw_1,str(P3_dict['vlan_id']),str(P3_dict['mac'])):
                log.info('Mac BH route is proper in L2FM on  S1_BGw1')
            else:
                log.info('Mac BH route is improper in L2FM on  S1_BGw1')
                self.failed('Mac BH route is improper in L2FM on  S1_BGw1')

            ###S2_BGW1_MAC_BH_ROUTE Remote Vtep
            if verify_BH_route_in_L2FM(node7_s2_bgw_1,str(P3_dict['vlan_id']),str(P3_dict['mac'])):
                log.info('Mac BH route is proper in L2FM on  S2_BGw1')
            else:
                log.info('Mac BH route is improper in L2FM on  S2_BGw1')
                self.failed('Mac BH route is improper in L2FM on  S2_BGw1')

        except Exception as error:
            log.debug("Unable to verify BH mac route in L2FM - Encountered Exception " + str(error))
            self.errored('Exception occurred while verifying BH mac route in L2FM')        

        #Verifying L2RIB
        try:
            #S1_Leaf_Mac_BH_route
            if verify_L2rib_mac_ip_output(node3_s1_bgw_1,str(P3_dict['vlan_id']),str(P3_dict['mac'])):
                log.info('Mac BH route is proper in L2RIB on S1_Leaf')
            else:
                log.debug('Mac BH route is improper in L2RIB on  S1_Leaf')
                self.failed('Mac BH route is improper in L2RIB on  S1_Leaf')

            #S2_BGW1_Mac_BH_route
            if verify_L2rib_mac_ip_output(node7_s2_bgw_1,str(P3_dict['vlan_id']),str(P3_dict['mac'])):
                log.info('Mac BH route is proper in L2RIB on S2_BGW1')
            else:
                log.debug('Mac BH route is improper in L2RIB on  S2_BGW1')
                self.errored('Mac BH route is improper in L2RIB on  S2_BGW1')
        
        except Exception as error:
            log.debug("Unable to verify BH mac route in L2RIB - Encountered Exception " + str(error))
            self.errored('Exception occurred while verifying BH mac route in L2RIB')
        
        #Verifying BGP
        try:
            #S2_BGW1_Mac_BH_route
            if verify_BH_in_Remote_BGP(node7_s2_bgw_1,str(P3_dict['mac'])):
                log.info('Mac BH route is proper in BGP on S2_BGW1')
            else:
                log.debug('Mac BH route is improper in BGP on  S2_BGW1')
                self.errored('Mac BH route is improper in BGP on  S2_BGW1')

            #Access_Mac_BH_route
            if verify_BH_in_Remote_BGP(node3_s1_bgw_1,str(P3_dict['mac'])):
                log.info('Mac BH route is proper in BGP on Access')
            else:
                log.debug('Mac BH route is improper in BGP on  Access')
                self.errored('Mac BH route is improper in BGP on  Access')
        
        except Exception as error:
            log.debug("Unable to verify BH mac route in BGP - Encountered Exception " + str(error))
            self.errored('Exception occurred while verifying BH mac route in BGP', )
 

    @aetest.cleanup
    def cleanup(self,testscript,testbed):
        """Unconfigure qos policies"""
        node3_s1_bgw_1 = testbed.devices['node3_s1_bgw_1']
        node5_s1_leaf_1 = testbed.devices['node5_s1_leaf_1']
        node4_s1_bgw_2 = testbed.devices['node4_s1_bgw_2']
        node7_s2_bgw_1 = testbed.devices['node7_s2_bgw_1']
        node9_s2_leaf_1 = testbed.devices['node9_s2_leaf_1']
        forwardingSysDict = FWD_SYS_dict
        P3_dict = AcceSW_TGEN_data
        post_test_process_dict = {
            'dut_list'                       : [node3_s1_bgw_1,node4_s1_bgw_2,node7_s2_bgw_1],
            'cc_check'                  : 0,
            'cores_check'               : 1,
            'logs_check'                : 1,
            'fnl_flag'                  : 0,
            'exclude_log_check_pattern' : 'ERROR_VLANS_SUSPENDED|ERROR_VLANS_REMOVED|SYSMGR-2-SERVICE_CRASHED',
            }
        try:
            # Stop Traffic from ixia
            log.info("--- Stopping Traffic ---- \n")
            log.info("Stopping Traffic")
            traffic_run_status = ixLib.stop_traffic()
            
            if traffic_run_status is not 1:
               log.info("Failed: To Stop traffic")
               return 0
            else:
                log.info("\nTraffic Stopped successfully\n")
            time.sleep(10)
            ####Remove traffic item configured
            UCAST_L2_dict = {
                            'mode'        : 'remove',
                            'stream_id'   : stream_id,
                      }
            if (ixLib.delete_traffic_item(UCAST_L2_dict))==0:
                log.debug("Traffic Remove failed")
                self.failed("Traffic Remove failed", goto=['next_tc'])
            else:
                log.info("Traffic Remove Passed")

            mac= str(P3_dict['mac'])
            vlan= str(P3_dict['vlan_id'])
            ip=str(P3_dict['v4_addr'])
            octet = 1
            no_int= int(P3_dict['no_of_ints'])
        
            for i in range (0,no_int):
            ###LEAF_3_MAC_BH_ROUTE
                testbed.devices['node3_s1_bgw_1'].configure('''
                    no mac address-table static ''' + str(mac) + ''' vlan '''+ str(vlan) + ''' drop

                    interface vlan ''' + str(vlan) + '''
                        no ip arp ''' + str(ip) + ''' ''' + str(mac) + '''
                ''')
                testbed.devices['node4_s1_bgw_2'].configure('''
                    no mac address-table static ''' + str(mac) + ''' vlan '''+ str(vlan) + ''' drop

                    interface vlan ''' + str(vlan) + '''
                        no ip arp ''' + str(ip) + ''' ''' + str(mac) + '''
                ''')
                lasthex=incr_mac(mac)
                mac=mac[0:10]+lasthex
                vlan= int(vlan)+int(P3_dict['vlan_id_step'])
                ip=incr_ip(ip,octet)
            ##check for cores,cc,errors
            status = infraVerify.postTestVerification(post_test_process_dict)
            if status['status'] == 0:
                self.failed(reason=status['logs'])
            else:
                self.passed(reason=status['logs'])
        except Exception as error:
            log.debug("Unable to do cleanup " + str(error))
            self.errored('Exception occurred during cleanup', goto=['next_tc'])

class RPM_PROCESS_RESTART(nxtest.Testcase):
    #"TC_0093_RPM_PROCESS_RESTART"
   

    stream_id_2=''
    @aetest.test
    def CONFIGURE_L2_UCAST_IXIA_TRAFFIC_H4_to_H1(self, testscript):
        """ IXIA_CONFIGURATION subsection: Configure MCAST Traffic Item """

        # Do not perform configurations if skip_tgen_config flag is set
        #if not testscript.parameters['script_flags']['skip_tgen_config']:

        IX_TP1 = testscript.parameters['IX_TP1']
        IX_TP2 = testscript.parameters['IX_TP2']
        IX_TP3 = testscript.parameters['IX_TP3']
        IX_TP4 = testscript.parameters['IX_TP4']
        P1_dict = S1_BGW1_TGEN_data
        P2_dict = S1_Leaf_TGEN_data
        P3_dict = AcceSW_TGEN_data
        P4_dict = S2_Leaf_TGEN_data
        # P1_dict = S1_BGW1_TGEN_data
        # P4_dict = testscript.parameters['S2_BGW1_TGEN_dict']

        UCAST_v4_dict_3 = {   'src_hndl'  : IX_TP4['ipv4_handle'],
                            'dst_hndl'  : IX_TP3['ipv4_handle'],
                            'circuit'   : 'ipv4',
                            'TI_name'   : "UCAST_V4",
                            'rate_pps'  : "10000",
                            'bi_dir'    : 1,
                            'bidirectional': '0'
                        }

        UCAST_v4_TI_2 = ixLib.configure_ixia_traffic_item_v46(UCAST_v4_dict_3)
            
        if UCAST_v4_TI_2 == 0:
            log.debug("Configuring UCast L2 TI failed")
            self.errored("Configuring UCast L2 TI failed", goto=['next_tc'])
        else:
            global stream_id_2
            stream_id_2 = UCAST_v4_TI_2


    # =============================================================================================================================#
    @aetest.test
    def APPLY_TRAFFIC(self):
        """ IXIA_CONFIGURATION subsection: Verify IXIA Traffic """

        # Apply IXIA Traffic
        if ixLib.apply_traffic() == 1:
            log.info("Applying IXIA TI Passed")
        else:
            self.errored("Applying IXIA TI failed", goto=['cleanup'])
            
        # =============================================================================================================================#
    @aetest.test
    def VERIFY_IXIA_TRAFFIC_before_restart(self, testscript):
        """ IXIA_CONFIGURATION subsection: Verify IXIA Traffic """

        # Do not perform configurations if skip_tgen_config flag is set
       

        time.sleep(20)

        if ixLib.verify_traffic(2) == 0:
            log.debug("Traffic Verification failed")
            self.failed("Traffic Verification failed", goto=['cleanup'])
        else:
            log.info("Traffic Verification Passed")
       
    
    
    #--------------------------------------------------------------------------------#
        # Start traffic from ixia
        log.info("--- Populating the statistics --- \n")
        log.info("---- Running Traffic --- \n")
        log.info("Starting Traffic")

        traffic_run_status  = ixLib.start_traffic()

        if traffic_run_status is not 1:
           log.info("Failed: To start traffic")
           return 0
        else:
            log.info("\nTraffic started successfully\n")

        time.sleep(10)
        
    # =============================================================================================================================#
    # def config_mac_BH_route(testbed):
    #     node3_s1_bgw_1 = testbed.devices['node3_s1_bgw_1']
    #     node4_s1_bgw_2 =  testbed.devices['node4_s1_bgw_2']
    #     P3_dict = AcceSW_TGEN_data
    

    
    #     testbed.devices['node3_s1_bgw_1'].configure('''
    #         mac address-table static ''' + str(P3_dict['mac']) + ''' vlan '''+ str(P3_dict['vlan_id']) + ''' drop

    #         interface vlan ''' + str(P3_dict['vlan_id']) + '''
    #             ipv6 neighbor ''' + str(P3_dict['v6_addr']) + ''' ''' + str(P3_dict['mac']) + '''
    #             ip arp ''' + str(P3_dict['v4_addr']) + ''' ''' + str(P3_dict['mac']) + '''
    #     ''')
    #     testbed.devices['node4_s1_bgw_2'].configure('''
    #         mac address-table static ''' + str(P3_dict['mac']) + ''' vlan '''+ str(P3_dict['vlan_id']) + ''' drop

    #         interface vlan ''' + str(P3_dict['vlan_id']) + '''
    #             ipv6 neighbor ''' + str(P3_dict['v6_addr']) + ''' ''' + str(P3_dict['mac']) + '''
    #             ip arp ''' + str(P3_dict['v4_addr']) + ''' ''' + str(P3_dict['mac']) + '''
    #     ''')

    @aetest.test
    def TRIGGER_verify_RPM_process_restart(self, testscript,testbed):
        """ ACLQOS_PROCESS_KILL_VERIFICATION subsection: Verify killing process ACLQOS """

        node3_s1_bgw_1 = testbed.devices['node3_s1_bgw_1']
        node5_s1_leaf_1 = testbed.devices['node5_s1_leaf_1']
        node4_s1_bgw_2 = testbed.devices['node4_s1_bgw_2']
        node7_s2_bgw_1 = testbed.devices['node7_s2_bgw_1']
        node9_s2_leaf_1 = testbed.devices['node9_s2_leaf_1']
        P3_dict = AcceSW_TGEN_data

        mac= str(P3_dict['mac'])
        vlan= str(P3_dict['vlan_id'])
        ip=str(P3_dict['v4_addr'])
        octet = 1
        no_int= int(P3_dict['no_of_ints'])
        
        for i in range (0,no_int):
            ###LEAF_3_MAC_BH_ROUTE
            testbed.devices['node3_s1_bgw_1'].configure('''
                mac address-table static ''' + str(mac) + ''' vlan '''+ str(vlan) + ''' drop

                interface vlan ''' + str(vlan) + '''
                  ip arp ''' + str(ip) + ''' ''' + str(mac) + '''
            ''')
            testbed.devices['node4_s1_bgw_2'].configure('''
                mac address-table static ''' + str(mac) + ''' vlan '''+ str(vlan) + ''' drop

                interface vlan ''' + str(vlan) + '''
                  ip arp ''' + str(ip) + ''' ''' + str(mac) + '''
            ''')
            lasthex=incr_mac(mac)
            mac=mac[0:10]+lasthex
            vlan= int(vlan)+int(P3_dict['vlan_id_step'])
            ip=incr_ip(ip,octet)

        if infraTrig.verifyProcessRestart(node3_s1_bgw_1,"rpm"):
            log.info("Successfully restarted process rpm")
        else:
            log.debug("Failed to restarted process rpm")
            self.failed("Failed to restarted process rpm", goto=['cleanup'])
        time.sleep(120)

        if infraTrig.verifyProcessRestart(node4_s1_bgw_2,"rpm"):
            log.info("Successfully restarted process rpm")
        else:
            log.debug("Failed to restarted process rpm")
            self.failed("Failed to restarted process rpm", goto=['cleanup'])
        time.sleep(120)

        if infraTrig.verifyProcessRestart(node7_s2_bgw_1,"rpm"):
            log.info("Successfully restarted process rpm")
        else:
            log.debug("Failed to restarted process rpm")
            self.failed("Failed to restarted process rpm", goto=['cleanup'])
        time.sleep(120)


    # =============================================================================================================================#  
    
    @aetest.test
    def VERIFY_IXIA_TRAFFIC(self, testscript):
        """ IXIA_CONFIGURATION subsection: Verify IXIA Traffic """

        # Do not perform configurations if skip_tgen_config flag is set
       

        time.sleep(20)

        if ixLib.verify_traffic(2) == 1:
            log.debug("Traffic Verification failed")
            self.failed("Traffic Verification failed", goto=['cleanup'])
        else:
            log.info("Traffic Verification Passed")
    
    # @aetest.test
    # def Unconfig_mac_BH_route(testbed):
    #     node3_s1_bgw_1 = testbed.devices['node3_s1_bgw_1']
    #     node4_s1_bgw_2 =  testbed.devices['node4_s1_bgw_2']
    #     P3_dict = AcceSW_TGEN_data
    

    
    #     testbed.devices['node3_s1_bgw_1'].configure('''
    #         no mac address-table static ''' + str(P3_dict['mac']) + ''' vlan '''+ str(P3_dict['vlan_id']) + ''' drop

    #         interface vlan ''' + str(P3_dict['vlan_id']) + '''
    #             no ipv6 neighbor ''' + str(P3_dict['v6_addr']) + ''' ''' + str(P3_dict['mac']) + '''
    #             no ip arp ''' + str(P3_dict['v4_addr']) + ''' ''' + str(P3_dict['mac']) + '''
    #     ''')
    #     testbed.devices['node4_s1_bgw_2'].configure('''
    #         no mac address-table static ''' + str(P3_dict['mac']) + ''' vlan '''+ str(P3_dict['vlan_id']) + ''' drop

    #         interface vlan ''' + str(P3_dict['vlan_id']) + '''
    #             no ipv6 neighbor ''' + str(P3_dict['v6_addr']) + ''' ''' + str(P3_dict['mac']) + '''
    #             no ip arp ''' + str(P3_dict['v4_addr']) + ''' ''' + str(P3_dict['mac']) + '''
    #     ''')
    @aetest.test
    def Verify_BH_states_in_HMM(self, testscript,testbed):
        node3_s1_bgw_1 =testbed.devices['node3_s1_bgw_1']
        node4_s1_bgw_2 = testbed.devices['node4_s1_bgw_2']
        node7_s2_bgw_1 = testbed.devices['node7_s2_bgw_1']
        P3_dict = AcceSW_TGEN_data

        try:
            if verify_BH_in_HMM(node4_s1_bgw_2,str(P3_dict['v4_addr'])):
                log.info('Mac BH route is proper in HMM on  S1_BGW1')
            else:
                log.info('Mac BH route is improper in HMM on  S1_BGW1')
                self.failed('Mac BH route is improper in HMM on  S1_BGW1')
        
         
        except Exception as error:
            log.debug("Unable to configure static BH mac route on Remote Vtep- Encountered Exception " + str(error))
            self.errored('Exception occurred while configuring static BH mac route on Remote Vtep', goto=['cleanup'])
    @aetest.test
    def Verify_BH_states_in_AM(self, testscript,testbed):
        node3_s1_bgw_1 = testbed.devices['node3_s1_bgw_1']
        node4_s1_bgw_2 = testbed.devices['node4_s1_bgw_2']
        node7_s2_bgw_1 = testbed.devices['node7_s2_bgw_1']
        P1_dict = S1_BGW1_TGEN_data
        P2_dict = S1_Leaf_TGEN_data
        P3_dict = AcceSW_TGEN_data
        P4_dict = S2_Leaf_TGEN_data

        try:        
            if verify_BH_in_AM(node4_s1_bgw_2,str(P3_dict['mac']),str(P3_dict['vlan_id']),str(P3_dict['v4_addr'])):
                log.info('Mac BH route is proper in AM on  S1_BGW1')
            else:
                log.info('Mac BH route is improper in AM on  S1_BGW1')
                self.failed('Mac BH route is improper in AM on  S1_BGW1')
                   
        
        except Exception as error:
            log.debug("Unable to configure static BH mac route on Remote Vtep- Encountered Exception " + str(error))
            self.errored('Exception occurred while configuring static BH mac route on Remote Vtep', goto=['cleanup'])
    @aetest.test
    def Verify_BH_states_in_remote_ARP(self, testscript,testbed):
        node3_s1_bgw_1 =testbed.devices['node3_s1_bgw_1']
        node7_s2_bgw_1 = testbed.devices['node7_s2_bgw_1']
        P3_dict = AcceSW_TGEN_data

        try: 

            if verify_BH_in_Remote_ARP(node7_s2_bgw_1,str(P3_dict['vlan_id']),str(P3_dict['mac'])):
               log.info('Mac BH route is proper in Remote ARP on  S2_BGW1')
            else:
                log.info('Mac BH route is improper in Remote ARP on  S2_BGW1')
                self.failed('Mac BH route is improper in Remote ARP on  S2_BGW1')

        except Exception as error:
            log.debug("Unable to configure static BH mac route on Remote Vtep- Encountered Exception " + str(error))
            self.errored('Exception occurred while configuring static BH mac route on Remote Vtep')        
    @aetest.test
    def Verify_BH_states_in_local_ARP(self, testscript,testbed):
        node3_s1_bgw_1 = testbed.devices['node3_s1_bgw_1']
        node7_s2_bgw_1 = testbed.devices['node7_s2_bgw_1']
        P1_dict = S1_BGW1_TGEN_data
        P2_dict = S1_Leaf_TGEN_data
        P3_dict = AcceSW_TGEN_data
        P4_dict = S2_Leaf_TGEN_data
        try:        
            if verify_BH_in_local_ARP(node3_s1_bgw_1,str(P3_dict['vlan_id']),str(P3_dict['mac'])):
                log.info('Mac BH route is proper in Local ARP on  S1_BGW1')
            else:
                log.info('Mac BH route is improper in Local ARP on  S1_BGW1')
                self.failed('Mac BH route is improper in Local ARP on  S1_BGW1')
        
        except Exception as error:
            log.debug("Unable to configure static BH mac route on Remote Vtep- Encountered Exception " + str(error))
            self.errored('Exception occurred while configuring static BH mac route on Remote Vtep')
    @aetest.test  
    def Verify_Mac_BH_Route_on_L2FM_BGP_L2RIB(self,testscript,testbed):
        node3_s1_bgw_1 = testbed.devices['node3_s1_bgw_1']
        node7_s2_bgw_1 = testbed.devices['node7_s2_bgw_1']
        P3_dict = AcceSW_TGEN_data
        
        # Verifying L2FM

        try:
            ###S1_BGW1_MAC_BH_ROUTE
            if verify_BH_route_in_L2FM(node3_s1_bgw_1,str(P3_dict['vlan_id']),str(P3_dict['mac'])):
                log.info('Mac BH route is proper in L2FM on  S1_BGw1')
            else:
                log.info('Mac BH route is improper in L2FM on  S1_BGw1')
                self.failed('Mac BH route is improper in L2FM on  S1_BGw1')

            ###S2_BGW1_MAC_BH_ROUTE Remote Vtep
            if verify_BH_route_in_L2FM(node7_s2_bgw_1,str(P3_dict['vlan_id']),str(P3_dict['mac'])):
                log.info('Mac BH route is proper in L2FM on  S2_BGw1')
            else:
                log.info('Mac BH route is improper in L2FM on  S2_BGw1')
                self.failed('Mac BH route is improper in L2FM on  S2_BGw1')

        except Exception as error:
            log.debug("Unable to verify BH mac route in L2FM - Encountered Exception " + str(error))
            self.errored('Exception occurred while verifying BH mac route in L2FM')        

        #Verifying L2RIB
        try:
            #S1_Leaf_Mac_BH_route
            if verify_L2rib_mac_ip_output(node3_s1_bgw_1,str(P3_dict['vlan_id']),str(P3_dict['mac'])):
                log.info('Mac BH route is proper in L2RIB on S1_Leaf')
            else:
                log.debug('Mac BH route is improper in L2RIB on  S1_Leaf')
                self.failed('Mac BH route is improper in L2RIB on  S1_Leaf')

            #S2_BGW1_Mac_BH_route
            if verify_L2rib_mac_ip_output(node7_s2_bgw_1,str(P3_dict['vlan_id']),str(P3_dict['mac'])):
                log.info('Mac BH route is proper in L2RIB on S2_BGW1')
            else:
                log.debug('Mac BH route is improper in L2RIB on  S2_BGW1')
                self.errored('Mac BH route is improper in L2RIB on  S2_BGW1')
        
        except Exception as error:
            log.debug("Unable to verify BH mac route in L2RIB - Encountered Exception " + str(error))
            self.errored('Exception occurred while verifying BH mac route in L2RIB')
        
        #Verifying BGP
        try:
            #S2_BGW1_Mac_BH_route
            if verify_BH_in_Remote_BGP(node7_s2_bgw_1,str(P3_dict['mac'])):
                log.info('Mac BH route is proper in BGP on S2_BGW1')
            else:
                log.debug('Mac BH route is improper in BGP on  S2_BGW1')
                self.errored('Mac BH route is improper in BGP on  S2_BGW1')

            #Access_Mac_BH_route
            if verify_BH_in_Remote_BGP(node3_s1_bgw_1,str(P3_dict['mac'])):
                log.info('Mac BH route is proper in BGP on Access')
            else:
                log.debug('Mac BH route is improper in BGP on  Access')
                self.errored('Mac BH route is improper in BGP on  Access')
        
        except Exception as error:
            log.debug("Unable to verify BH mac route in BGP - Encountered Exception " + str(error))
            self.errored('Exception occurred while verifying BH mac route in BGP', )


    @aetest.cleanup
    def cleanup(self,testscript,testbed):
        """Unconfigure qos policies"""
        node3_s1_bgw_1 = testbed.devices['node3_s1_bgw_1']
        node5_s1_leaf_1 = testbed.devices['node5_s1_leaf_1']
        node4_s1_bgw_2 = testbed.devices['node4_s1_bgw_2']
        node7_s2_bgw_1 = testbed.devices['node7_s2_bgw_1']
        node9_s2_leaf_1 = testbed.devices['node9_s2_leaf_1']
        forwardingSysDict = FWD_SYS_dict
        P3_dict = AcceSW_TGEN_data
        post_test_process_dict = {
            'dut_list'                       : [node3_s1_bgw_1,node4_s1_bgw_2,node7_s2_bgw_1],
            'cc_check'                  : 0,
            'cores_check'               : 1,
            'logs_check'                : 1,
            'fnl_flag'                  : 0,
            'exclude_log_check_pattern' : 'ERROR_VLANS_SUSPENDED|ERROR_VLANS_REMOVED|SYSMGR-2-SERVICE_CRASHED',
            }
        try:
            # Stop Traffic from ixia
            log.info("--- Stopping Traffic ---- \n")
            log.info("Stopping Traffic")
            traffic_run_status = ixLib.stop_traffic()
            
            if traffic_run_status is not 1:
               log.info("Failed: To Stop traffic")
               return 0
            else:
                log.info("\nTraffic Stopped successfully\n")
            time.sleep(10)
            ####Remove traffic item configured
            UCAST_v4_dict_3 = {
                            'mode'        : 'remove',
                            'stream_id'   : stream_id_2,
                      }
            if (ixLib.delete_traffic_item(UCAST_v4_dict_3))==0:
                log.debug("Traffic Remove failed")
                self.failed("Traffic Remove failed", goto=['next_tc'])
            else:
                log.info("Traffic Remove Passed")
            
            mac= str(P3_dict['mac'])
            vlan= str(P3_dict['vlan_id'])
            ip=str(P3_dict['v4_addr'])
            octet = 1
            no_int= int(P3_dict['no_of_ints'])
        
            for i in range (0,no_int):
            ###LEAF_3_MAC_BH_ROUTE
                testbed.devices['node3_s1_bgw_1'].configure('''
                    no mac address-table static ''' + str(mac) + ''' vlan '''+ str(vlan) + ''' drop

                    interface vlan ''' + str(vlan) + '''
                        no ip arp ''' + str(ip) + ''' ''' + str(mac) + '''
                ''')
                testbed.devices['node4_s1_bgw_2'].configure('''
                    no mac address-table static ''' + str(mac) + ''' vlan '''+ str(vlan) + ''' drop

                    interface vlan ''' + str(vlan) + '''
                        no ip arp ''' + str(ip) + ''' ''' + str(mac) + '''
                ''')
                lasthex=incr_mac(mac)
                mac=mac[0:10]+lasthex
                vlan= int(vlan)+int(P3_dict['vlan_id_step'])
                ip=incr_ip(ip,octet)
            ##check for cores,cc,errors
            status = infraVerify.postTestVerification(post_test_process_dict)
            if status['status'] == 0:
                self.failed(reason=status['logs'])
            else:
                self.passed(reason=status['logs'])
        except Exception as error:
            log.debug("Unable to do cleanup " + str(error))
            self.errored('Exception occurred during cleanup', goto=['next_tc'])

class adjmgr_PROCESS_RESTART(nxtest.Testcase):
    #"TC_0094_adjmgr_PROCESS_RESTART"
   

    stream_id_2=''
    @aetest.test
    def CONFIGURE_L2_UCAST_IXIA_TRAFFIC_H4_to_H1(self, testscript):
        """ IXIA_CONFIGURATION subsection: Configure MCAST Traffic Item """

        # Do not perform configurations if skip_tgen_config flag is set
        #if not testscript.parameters['script_flags']['skip_tgen_config']:

        IX_TP1 = testscript.parameters['IX_TP1']
        IX_TP2 = testscript.parameters['IX_TP2']
        IX_TP3 = testscript.parameters['IX_TP3']
        IX_TP4 = testscript.parameters['IX_TP4']
        P1_dict = S1_BGW1_TGEN_data
        P2_dict = S1_Leaf_TGEN_data
        P3_dict = AcceSW_TGEN_data
        P4_dict = S2_Leaf_TGEN_data
        # P1_dict = S1_BGW1_TGEN_data
        # P4_dict = testscript.parameters['S2_BGW1_TGEN_dict']

        UCAST_v4_dict_3 = {   'src_hndl'  : IX_TP4['ipv4_handle'],
                            'dst_hndl'  : IX_TP3['ipv4_handle'],
                            'circuit'   : 'ipv4',
                            'TI_name'   : "UCAST_V4",
                            'rate_pps'  : "10000",
                            'bi_dir'    : 1,
                            'bidirectional': '0'
                        }

        UCAST_v4_TI_2 = ixLib.configure_ixia_traffic_item_v46(UCAST_v4_dict_3)
            
        if UCAST_v4_TI_2 == 0:
            log.debug("Configuring UCast L2 TI failed")
            self.errored("Configuring UCast L2 TI failed", goto=['next_tc'])
        else:
            global stream_id_2
            stream_id_2 = UCAST_v4_TI_2


    # =============================================================================================================================#
    @aetest.test
    def APPLY_TRAFFIC(self):
        """ IXIA_CONFIGURATION subsection: Verify IXIA Traffic """

        # Apply IXIA Traffic
        if ixLib.apply_traffic() == 1:
            log.info("Applying IXIA TI Passed")
        else:
            self.errored("Applying IXIA TI failed", goto=['cleanup'])
            
        # =============================================================================================================================#
    @aetest.test
    def VERIFY_IXIA_TRAFFIC_before_restart(self, testscript):
        """ IXIA_CONFIGURATION subsection: Verify IXIA Traffic """

        # Do not perform configurations if skip_tgen_config flag is set
       

        time.sleep(20)

        if ixLib.verify_traffic(2) == 0:
            log.debug("Traffic Verification failed")
            self.failed("Traffic Verification failed", goto=['cleanup'])
        else:
            log.info("Traffic Verification Passed")
       
    
    
    #--------------------------------------------------------------------------------#
        # Start traffic from ixia
        log.info("--- Populating the statistics --- \n")
        log.info("---- Running Traffic --- \n")
        log.info("Starting Traffic")

        traffic_run_status  = ixLib.start_traffic()

        if traffic_run_status is not 1:
           log.info("Failed: To start traffic")
           return 0
        else:
            log.info("\nTraffic started successfully\n")

        time.sleep(10)
        
    # =============================================================================================================================#
    # def config_mac_BH_route(testbed):
    #     node3_s1_bgw_1 = testbed.devices['node3_s1_bgw_1']
    #     node4_s1_bgw_2 =  testbed.devices['node4_s1_bgw_2']
    #     P3_dict = AcceSW_TGEN_data
    

    
    #     testbed.devices['node3_s1_bgw_1'].configure('''
    #         mac address-table static ''' + str(P3_dict['mac']) + ''' vlan '''+ str(P3_dict['vlan_id']) + ''' drop

    #         interface vlan ''' + str(P3_dict['vlan_id']) + '''
    #             ipv6 neighbor ''' + str(P3_dict['v6_addr']) + ''' ''' + str(P3_dict['mac']) + '''
    #             ip arp ''' + str(P3_dict['v4_addr']) + ''' ''' + str(P3_dict['mac']) + '''
    #     ''')
    #     testbed.devices['node4_s1_bgw_2'].configure('''
    #         mac address-table static ''' + str(P3_dict['mac']) + ''' vlan '''+ str(P3_dict['vlan_id']) + ''' drop

    #         interface vlan ''' + str(P3_dict['vlan_id']) + '''
    #             ipv6 neighbor ''' + str(P3_dict['v6_addr']) + ''' ''' + str(P3_dict['mac']) + '''
    #             ip arp ''' + str(P3_dict['v4_addr']) + ''' ''' + str(P3_dict['mac']) + '''
    #     ''')

    @aetest.test
    def TRIGGER_verify_adjmgr_process_restart(self, testscript,testbed):
        """ ACLQOS_PROCESS_KILL_VERIFICATION subsection: Verify killing process ACLQOS """

        node3_s1_bgw_1 = testbed.devices['node3_s1_bgw_1']
        node5_s1_leaf_1 = testbed.devices['node5_s1_leaf_1']
        node4_s1_bgw_2 = testbed.devices['node4_s1_bgw_2']
        node7_s2_bgw_1 = testbed.devices['node7_s2_bgw_1']
        node9_s2_leaf_1 = testbed.devices['node9_s2_leaf_1']
        P3_dict = AcceSW_TGEN_data

        mac= str(P3_dict['mac'])
        vlan= str(P3_dict['vlan_id'])
        ip=str(P3_dict['v4_addr'])
        octet = 1
        no_int= int(P3_dict['no_of_ints'])
        
        for i in range (0,no_int):
            ###LEAF_3_MAC_BH_ROUTE
            testbed.devices['node3_s1_bgw_1'].configure('''
                mac address-table static ''' + str(mac) + ''' vlan '''+ str(vlan) + ''' drop

                interface vlan ''' + str(vlan) + '''
                  ip arp ''' + str(ip) + ''' ''' + str(mac) + '''
            ''')
            testbed.devices['node4_s1_bgw_2'].configure('''
                mac address-table static ''' + str(mac) + ''' vlan '''+ str(vlan) + ''' drop

                interface vlan ''' + str(vlan) + '''
                  ip arp ''' + str(ip) + ''' ''' + str(mac) + '''
            ''')
            lasthex=incr_mac(mac)
            mac=mac[0:10]+lasthex
            vlan= int(vlan)+int(P3_dict['vlan_id_step'])
            ip=incr_ip(ip,octet)

        if infraTrig.verifyProcessRestart(node3_s1_bgw_1,"adjmgr"):
            log.info("Successfully restarted process adjmgr")
        else:
            log.debug("Failed to restarted process adjmgr")
            self.failed("Failed to restarted process adjmgr", goto=['cleanup'])
        time.sleep(120)

        if infraTrig.verifyProcessRestart(node4_s1_bgw_2,"adjmgr"):
            log.info("Successfully restarted process adjmgr")
        else:
            log.debug("Failed to restarted process adjmgr")
            self.failed("Failed to restarted process adjmgr", goto=['cleanup'])
        time.sleep(120)

        if infraTrig.verifyProcessRestart(node7_s2_bgw_1,"adjmgr"):
            log.info("Successfully restarted process adjmgr")
        else:
            log.debug("Failed to restarted process adjmgr")
            self.failed("Failed to restarted process adjmgr", goto=['cleanup'])
        time.sleep(120)

    # =============================================================================================================================#  
    
    @aetest.test
    def VERIFY_IXIA_TRAFFIC(self, testscript):
        """ IXIA_CONFIGURATION subsection: Verify IXIA Traffic """

        # Do not perform configurations if skip_tgen_config flag is set
       

        time.sleep(20)

        if ixLib.verify_traffic(2) == 1:
            log.debug("Traffic Verification failed")
            self.failed("Traffic Verification failed", goto=['cleanup'])
        else:
            log.info("Traffic Verification Passed")
    
    # @aetest.test
    # def Unconfig_mac_BH_route(testbed):
    #     node3_s1_bgw_1 = testbed.devices['node3_s1_bgw_1']
    #     node4_s1_bgw_2 = testbed.devices['node4_s1_bgw_2']
        
    
    #     testbed.devices['node3_s1_bgw_1'].configure('''
    #         no mac address-table static ''' + str(P3_dict['mac']) + ''' vlan '''+ str(P3_dict['vlan_id']) + ''' drop

    #         interface vlan ''' + str(P3_dict['vlan_id']) + '''
    #             no ipv6 neighbor ''' + str(P3_dict['v6_addr']) + ''' ''' + str(P3_dict['mac']) + '''
    #             no ip arp ''' + str(P3_dict['v4_addr']) + ''' ''' + str(P3_dict['mac']) + '''
    #     ''')
    #     testbed.devices['node4_s1_bgw_2'].configure('''
    #         no mac address-table static ''' + str(P3_dict['mac']) + ''' vlan '''+ str(P3_dict['vlan_id']) + ''' drop

    #         interface vlan ''' + str(P3_dict['vlan_id']) + '''
    #             no ipv6 neighbor ''' + str(P3_dict['v6_addr']) + ''' ''' + str(P3_dict['mac']) + '''
    #             no ip arp ''' + str(P3_dict['v4_addr']) + ''' ''' + str(P3_dict['mac']) + '''
    #     ''')
    @aetest.test
    def Verify_BH_states_in_HMM(self, testscript,testbed):
        node3_s1_bgw_1 =testbed.devices['node3_s1_bgw_1']
        node4_s1_bgw_2 = testbed.devices['node4_s1_bgw_2']
        node7_s2_bgw_1 = testbed.devices['node7_s2_bgw_1']
        P3_dict = AcceSW_TGEN_data

        try:
            if verify_BH_in_HMM(node4_s1_bgw_2,str(P3_dict['v4_addr'])):
                log.info('Mac BH route is proper in HMM on  S1_BGW1')
            else:
                log.info('Mac BH route is improper in HMM on  S1_BGW1')
                self.failed('Mac BH route is improper in HMM on  S1_BGW1')
        
         
        except Exception as error:
            log.debug("Unable to configure static BH mac route on Remote Vtep- Encountered Exception " + str(error))
            self.errored('Exception occurred while configuring static BH mac route on Remote Vtep', goto=['cleanup'])
    @aetest.test
    def Verify_BH_states_in_AM(self, testscript,testbed):
        node3_s1_bgw_1 = testbed.devices['node3_s1_bgw_1']
        node4_s1_bgw_2 = testbed.devices['node4_s1_bgw_2']
        node7_s2_bgw_1 = testbed.devices['node7_s2_bgw_1']
        P1_dict = S1_BGW1_TGEN_data
        P2_dict = S1_Leaf_TGEN_data
        P3_dict = AcceSW_TGEN_data
        P4_dict = S2_Leaf_TGEN_data

        try:        
            if verify_BH_in_AM(node4_s1_bgw_2,str(P3_dict['mac']),str(P3_dict['vlan_id']),str(P3_dict['v4_addr'])):
                log.info('Mac BH route is proper in AM on  S1_BGW1')
            else:
                log.info('Mac BH route is improper in AM on  S1_BGW1')
                self.failed('Mac BH route is improper in AM on  S1_BGW1')
                   
        
        except Exception as error:
            log.debug("Unable to configure static BH mac route on Remote Vtep- Encountered Exception " + str(error))
            self.errored('Exception occurred while configuring static BH mac route on Remote Vtep', goto=['cleanup'])
    @aetest.test
    def Verify_BH_states_in_remote_ARP(self, testscript,testbed):
        node3_s1_bgw_1 =testbed.devices['node3_s1_bgw_1']
        node7_s2_bgw_1 = testbed.devices['node7_s2_bgw_1']
        P3_dict = AcceSW_TGEN_data

        try: 

            if verify_BH_in_Remote_ARP(node7_s2_bgw_1,str(P3_dict['vlan_id']),str(P3_dict['mac'])):
               log.info('Mac BH route is proper in Remote ARP on  S2_BGW1')
            else:
                log.info('Mac BH route is improper in Remote ARP on  S2_BGW1')
                self.failed('Mac BH route is improper in Remote ARP on  S2_BGW1')

        except Exception as error:
            log.debug("Unable to configure static BH mac route on Remote Vtep- Encountered Exception " + str(error))
            self.errored('Exception occurred while configuring static BH mac route on Remote Vtep')        
    @aetest.test
    def Verify_BH_states_in_local_ARP(self, testscript,testbed):
        node3_s1_bgw_1 = testbed.devices['node3_s1_bgw_1']
        node7_s2_bgw_1 = testbed.devices['node7_s2_bgw_1']
        P1_dict = S1_BGW1_TGEN_data
        P2_dict = S1_Leaf_TGEN_data
        P3_dict = AcceSW_TGEN_data
        P4_dict = S2_Leaf_TGEN_data
        try:        
            if verify_BH_in_local_ARP(node3_s1_bgw_1,str(P3_dict['vlan_id']),str(P3_dict['mac'])):
                log.info('Mac BH route is proper in Local ARP on  S1_BGW1')
            else:
                log.info('Mac BH route is improper in Local ARP on  S1_BGW1')
                self.failed('Mac BH route is improper in Local ARP on  S1_BGW1')
        
        except Exception as error:
            log.debug("Unable to configure static BH mac route on Remote Vtep- Encountered Exception " + str(error))
            self.errored('Exception occurred while configuring static BH mac route on Remote Vtep')
    @aetest.test 
    def Verify_Mac_BH_Route_on_L2FM_BGP_L2RIB(self,testscript,testbed):
        node3_s1_bgw_1 = testbed.devices['node3_s1_bgw_1']
        node7_s2_bgw_1 = testbed.devices['node7_s2_bgw_1']
        P3_dict = AcceSW_TGEN_data
        
        # Verifying L2FM

        try:
            ###S1_BGW1_MAC_BH_ROUTE
            if verify_BH_route_in_L2FM(node3_s1_bgw_1,str(P3_dict['vlan_id']),str(P3_dict['mac'])):
                log.info('Mac BH route is proper in L2FM on  S1_BGw1')
            else:
                log.info('Mac BH route is improper in L2FM on  S1_BGw1')
                self.failed('Mac BH route is improper in L2FM on  S1_BGw1')

            ###S2_BGW1_MAC_BH_ROUTE Remote Vtep
            if verify_BH_route_in_L2FM(node7_s2_bgw_1,str(P3_dict['vlan_id']),str(P3_dict['mac'])):
                log.info('Mac BH route is proper in L2FM on  S2_BGw1')
            else:
                log.info('Mac BH route is improper in L2FM on  S2_BGw1')
                self.failed('Mac BH route is improper in L2FM on  S2_BGw1')

        except Exception as error:
            log.debug("Unable to verify BH mac route in L2FM - Encountered Exception " + str(error))
            self.errored('Exception occurred while verifying BH mac route in L2FM')        

        #Verifying L2RIB
        try:
            #S1_Leaf_Mac_BH_route
            if verify_L2rib_mac_ip_output(node3_s1_bgw_1,str(P3_dict['vlan_id']),str(P3_dict['mac'])):
                log.info('Mac BH route is proper in L2RIB on S1_Leaf')
            else:
                log.debug('Mac BH route is improper in L2RIB on  S1_Leaf')
                self.failed('Mac BH route is improper in L2RIB on  S1_Leaf')

            #S2_BGW1_Mac_BH_route
            if verify_L2rib_mac_ip_output(node7_s2_bgw_1,str(P3_dict['vlan_id']),str(P3_dict['mac'])):
                log.info('Mac BH route is proper in L2RIB on S2_BGW1')
            else:
                log.debug('Mac BH route is improper in L2RIB on  S2_BGW1')
                self.errored('Mac BH route is improper in L2RIB on  S2_BGW1')
        
        except Exception as error:
            log.debug("Unable to verify BH mac route in L2RIB - Encountered Exception " + str(error))
            self.errored('Exception occurred while verifying BH mac route in L2RIB')
        
        #Verifying BGP
        try:
            #S2_BGW1_Mac_BH_route
            if verify_BH_in_Remote_BGP(node7_s2_bgw_1,str(P3_dict['mac'])):
                log.info('Mac BH route is proper in BGP on S2_BGW1')
            else:
                log.debug('Mac BH route is improper in BGP on  S2_BGW1')
                self.errored('Mac BH route is improper in BGP on  S2_BGW1')

            #Access_Mac_BH_route
            if verify_BH_in_Remote_BGP(node3_s1_bgw_1,str(P3_dict['mac'])):
                log.info('Mac BH route is proper in BGP on Access')
            else:
                log.debug('Mac BH route is improper in BGP on  Access')
                self.errored('Mac BH route is improper in BGP on  Access')
        
        except Exception as error:
            log.debug("Unable to verify BH mac route in BGP - Encountered Exception " + str(error))
            self.errored('Exception occurred while verifying BH mac route in BGP', )


    @aetest.cleanup
    def cleanup(self,testscript,testbed):
        """Unconfigure qos policies"""
        node3_s1_bgw_1 = testbed.devices['node3_s1_bgw_1']
        node5_s1_leaf_1 = testbed.devices['node5_s1_leaf_1']
        node4_s1_bgw_2 = testbed.devices['node4_s1_bgw_2']
        node7_s2_bgw_1 = testbed.devices['node7_s2_bgw_1']
        node9_s2_leaf_1 = testbed.devices['node9_s2_leaf_1']
        forwardingSysDict = FWD_SYS_dict
        P3_dict = AcceSW_TGEN_data
        post_test_process_dict = {
            'dut_list'                       : [node3_s1_bgw_1,node4_s1_bgw_2,node7_s2_bgw_1],
            'cc_check'                  : 0,
            'cores_check'               : 1,
            'logs_check'                : 1,
            'fnl_flag'                  : 0,
            'exclude_log_check_pattern' : 'ERROR_VLANS_SUSPENDED|ERROR_VLANS_REMOVED|SYSMGR-2-SERVICE_CRASHED',
            }
        try:
            # Stop Traffic from ixia
            log.info("--- Stopping Traffic ---- \n")
            log.info("Stopping Traffic")
            traffic_run_status = ixLib.stop_traffic()
            
            if traffic_run_status is not 1:
               log.info("Failed: To Stop traffic")
               return 0
            else:
                log.info("\nTraffic Stopped successfully\n")
            time.sleep(10)
            ####Remove traffic item configured
            UCAST_v4_dict_3 = {
                            'mode'        : 'remove',
                            'stream_id'   : stream_id_2,
                      }
            if (ixLib.delete_traffic_item(UCAST_v4_dict_3))==0:
                log.debug("Traffic Remove failed")
                self.failed("Traffic Remove failed", goto=['next_tc'])
            else:
                log.info("Traffic Remove Passed")

            mac= str(P3_dict['mac'])
            vlan= str(P3_dict['vlan_id'])
            ip=str(P3_dict['v4_addr'])
            octet = 1
            no_int= int(P3_dict['no_of_ints'])
        
            for i in range (0,no_int):
            ###LEAF_3_MAC_BH_ROUTE
                testbed.devices['node3_s1_bgw_1'].configure('''
                    no mac address-table static ''' + str(mac) + ''' vlan '''+ str(vlan) + ''' drop

                    interface vlan ''' + str(vlan) + '''
                        no ip arp ''' + str(ip) + ''' ''' + str(mac) + '''
                ''')
                testbed.devices['node4_s1_bgw_2'].configure('''
                    no mac address-table static ''' + str(mac) + ''' vlan '''+ str(vlan) + ''' drop

                    interface vlan ''' + str(vlan) + '''
                        no ip arp ''' + str(ip) + ''' ''' + str(mac) + '''
                ''')
                lasthex=incr_mac(mac)
                mac=mac[0:10]+lasthex
                vlan= int(vlan)+int(P3_dict['vlan_id_step'])
                ip=incr_ip(ip,octet)
            ##check for cores,cc,errors
            status = infraVerify.postTestVerification(post_test_process_dict)
            if status['status'] == 0:
                self.failed(reason=status['logs'])
            else:
                self.passed(reason=status['logs'])
        except Exception as error:
            log.debug("Unable to do cleanup " + str(error))
            self.errored('Exception occurred during cleanup', goto=['next_tc'])

class NVE_PROCESS_RESTART(nxtest.Testcase):
    #TC_0097_NVE_PROCESS_RESTART
   

    stream_id=''
    @aetest.test
    def CONFIGURE_UCAST_IXIA_TRAFFIC(self, testscript):
        """ IXIA_CONFIGURATION subsection: Configure MCAST Traffic Item """

        # Do not perform configurations if skip_tgen_config flag is set
      
        IX_TP1 = testscript.parameters['IX_TP1']
        IX_TP2 = testscript.parameters['IX_TP2']
        IX_TP3 = testscript.parameters['IX_TP3']
        IX_TP4 = testscript.parameters['IX_TP4']
        P1_dict = S1_BGW1_TGEN_data
        P2_dict = S1_Leaf_TGEN_data
        P3_dict = AcceSW_TGEN_data
        P4_dict = S2_Leaf_TGEN_data
        # P1_dict = S1_BGW1_TGEN_data
        # P4_dict = testscript.parameters['S2_BGW1_TGEN_dict']

        UCAST_v4_dict= {   'src_hndl'  : IX_TP4['ipv4_handle'],
                            'dst_hndl'  : IX_TP3['ipv4_handle'],
                            'circuit'   : 'ipv4',
                            'TI_name'   : "UCAST_V4",
                            'rate_pps'  : "10000",
                            'bi_dir'    : 1,
                            'bidirectional': '0'
                        }


        #UCAST_v6_dict = {   'src_hndl'  : IX_TP1['ipv6_handle'],
        #                    'dst_hndl'  : IX_TP2['ipv6_handle'],
        #                    'circuit'   : 'ipv6',
        #                    'TI_name'   : "UCAST_V6",
        #                    'rate_pps'  : "1000",
        #                    'bi_dir'    : 1
        #              }

        UCAST_v4_TI = ixLib.configure_ixia_traffic_item_v46(UCAST_v4_dict)
        #UCAST_v6_TI = ixLib.configure_ixia_traffic_item_v46(UCAST_v6_dict)

        #if UCAST_v4_TI == 0 or UCAST_v6_TI == 0:
        #    log.debug("Configuring UCast TI failed")
        #    self.errored("Configuring UCast TI failed", goto=['next_tc'])
            
        if UCAST_v4_TI == 0:
            log.debug("Configuring UCast L2 TI failed")
            self.errored("Configuring UCast L2 TI failed", goto=['cleanup'])
        else:
            global stream_id
            stream_id = UCAST_v4_TI
            log.info('stream_id='+stream_id)
            log.info(type(stream_id))


    # =============================================================================================================================#
    @aetest.test
    def APPLY_TRAFFIC(self):
        """ IXIA_CONFIGURATION subsection: Verify IXIA Traffic """

        # Apply IXIA Traffic
        if ixLib.apply_traffic() == 1:
            log.info("Applying IXIA TI Passed")
        else:
            self.errored("Applying IXIA TI failed", goto=['cleanup'])
            
        # =============================================================================================================================#
    @aetest.test
    def VERIFY_IXIA_TRAFFIC_before_restart(self, testscript):
        """ IXIA_CONFIGURATION subsection: Verify IXIA Traffic """

        # Do not perform configurations if skip_tgen_config flag is set
       

        time.sleep(20)

        if ixLib.verify_traffic(2) == 0:
            log.debug("Traffic Verification failed")
            self.failed("Traffic Verification failed", goto=['cleanup'])
        else:
            log.info("Traffic Verification Passed")
       
    
    
    #--------------------------------------------------------------------------------#
        # Start traffic from ixia
        log.info("--- Populating the statistics --- \n")
        log.info("---- Running Traffic --- \n")
        log.info("Starting Traffic")

        traffic_run_status  = ixLib.start_traffic()

        if traffic_run_status is not 1:
           log.info("Failed: To start traffic")
           return 0
        else:
            log.info("\nTraffic started successfully\n")

        time.sleep(10)
        
    # =============================================================================================================================#
    # @aetest.test
    # def config_mac_BH_route(testbed):
    #     node3_s1_bgw_1 = testbed.devices['node3_s1_bgw_1']
    #     node4_s1_bgw_2 =  testbed.devices['node4_s1_bgw_2']
    #     P3_dict = AcceSW_TGEN_data
    

    
    #     testbed.devices['node3_s1_bgw_1'].configure('''
    #         mac address-table static ''' + str(P3_dict['mac']) + ''' vlan '''+ str(P3_dict['vlan_id']) + ''' drop

    #         interface vlan ''' + str(P3_dict['vlan_id']) + '''
    #             ipv6 neighbor ''' + str(P3_dict['v6_addr']) + ''' ''' + str(P3_dict['mac']) + '''
    #             ip arp ''' + str(P3_dict['v4_addr']) + ''' ''' + str(P3_dict['mac']) + '''
    #     ''')
    #     testbed.devices['node4_s1_bgw_2'].configure('''
    #         mac address-table static ''' + str(P3_dict['mac']) + ''' vlan '''+ str(P3_dict['vlan_id']) + ''' drop

    #         interface vlan ''' + str(P3_dict['vlan_id']) + '''
    #             ipv6 neighbor ''' + str(P3_dict['v6_addr']) + ''' ''' + str(P3_dict['mac']) + '''
    #             ip arp ''' + str(P3_dict['v4_addr']) + ''' ''' + str(P3_dict['mac']) + '''
    #     ''')

    @aetest.test
    def TRIGGER_verify_NVE_process_restart(self, testscript,testbed):
        """ ACLQOS_PROCESS_KILL_VERIFICATION subsection: Verify killing process ACLQOS """

        node3_s1_bgw_1 = testbed.devices['node3_s1_bgw_1']
        node5_s1_leaf_1 = testbed.devices['node5_s1_leaf_1']
        node4_s1_bgw_2 = testbed.devices['node4_s1_bgw_2']
        node7_s2_bgw_1 = testbed.devices['node7_s2_bgw_1']
        node9_s2_leaf_1 = testbed.devices['node9_s2_leaf_1']
        P3_dict = AcceSW_TGEN_data

        mac= str(P3_dict['mac'])
        vlan= str(P3_dict['vlan_id'])
        ip=str(P3_dict['v4_addr'])
        octet = 1
        no_int= int(P3_dict['no_of_ints'])
        
        for i in range (0,no_int):
            ###LEAF_3_MAC_BH_ROUTE
            testbed.devices['node3_s1_bgw_1'].configure('''
                mac address-table static ''' + str(mac) + ''' vlan '''+ str(vlan) + ''' drop

                interface vlan ''' + str(vlan) + '''
                  ip arp ''' + str(ip) + ''' ''' + str(mac) + '''
            ''')
            testbed.devices['node4_s1_bgw_2'].configure('''
                mac address-table static ''' + str(mac) + ''' vlan '''+ str(vlan) + ''' drop

                interface vlan ''' + str(vlan) + '''
                  ip arp ''' + str(ip) + ''' ''' + str(mac) + '''
            ''')
            lasthex=incr_mac(mac)
            mac=mac[0:10]+lasthex
            vlan= int(vlan)+int(P3_dict['vlan_id_step'])
            ip=incr_ip(ip,octet)

        if infraTrig.verifyProcessRestart(node3_s1_bgw_1,"nve"):
            log.info("Successfully restarted process nve")
        else:
            log.debug("Failed to restarted process nve")
            self.failed("Failed to restarted process nve", goto=['cleanup'])
        time.sleep(120)

        if infraTrig.verifyProcessRestart(node4_s1_bgw_2,"nve"):
            log.info("Successfully restarted process nve")
        else:
            log.debug("Failed to restarted process nve")
            self.failed("Failed to restarted process nve", goto=['cleanup'])
        time.sleep(120)

        if infraTrig.verifyProcessRestart(node7_s2_bgw_1,"nve"):
            log.info("Successfully restarted process nve")
        else:
            log.debug("Failed to restarted process nve")
            self.failed("Failed to restarted process nve", goto=['cleanup'])
        time.sleep(120)

    # =============================================================================================================================#  
    
    @aetest.test
    def VERIFY_IXIA_TRAFFIC(self, testscript):
        """ IXIA_CONFIGURATION subsection: Verify IXIA Traffic """

        # Do not perform configurations if skip_tgen_config flag is set
       

        time.sleep(20)

        if ixLib.verify_traffic(2) == 1:
            log.debug("Traffic Verification failed")
            self.failed("Traffic Verification failed", goto=['cleanup'])
        else:
            log.info("Traffic Verification Passed")
    
    # @aetest.test
    # def Unconfig_mac_BH_route(testbed):
    #     node3_s1_bgw_1 = testbed.devices['node3_s1_bgw_1']
    #     node4_s1_bgw_2 =  testbed.devices['node4_s1_bgw_2']
    #     P3_dict = AcceSW_TGEN_data
    

    
    #     testbed.devices['node3_s1_bgw_1'].configure('''
    #         no mac address-table static ''' + str(P3_dict['mac']) + ''' vlan '''+ str(P3_dict['vlan_id']) + ''' drop

    #         interface vlan ''' + str(P3_dict['vlan_id']) + '''
    #             no ipv6 neighbor ''' + str(P3_dict['v6_addr']) + ''' ''' + str(P3_dict['mac']) + '''
    #             no ip arp ''' + str(P3_dict['v4_addr']) + ''' ''' + str(P3_dict['mac']) + '''
    #     ''')
    #     testbed.devices['node4_s1_bgw_2'].configure('''
    #         no mac address-table static ''' + str(P3_dict['mac']) + ''' vlan '''+ str(P3_dict['vlan_id']) + ''' drop

    #         interface vlan ''' + str(P3_dict['vlan_id']) + '''
    #             no ipv6 neighbor ''' + str(P3_dict['v6_addr']) + ''' ''' + str(P3_dict['mac']) + '''
    #             no ip arp ''' + str(P3_dict['v4_addr']) + ''' ''' + str(P3_dict['mac']) + '''
    #     ''')
       
    @aetest.test
    def Verify_BH_states_in_HMM(self, testscript,testbed):
        node3_s1_bgw_1 =testbed.devices['node3_s1_bgw_1']
        node4_s1_bgw_2 = testbed.devices['node4_s1_bgw_2']
        node7_s2_bgw_1 = testbed.devices['node7_s2_bgw_1']
        P3_dict = AcceSW_TGEN_data

        try:
            if verify_BH_in_HMM(node4_s1_bgw_2,str(P3_dict['v4_addr'])):
                log.info('Mac BH route is proper in HMM on  S1_BGW1')
            else:
                log.info('Mac BH route is improper in HMM on  S1_BGW1')
                self.failed('Mac BH route is improper in HMM on  S1_BGW1')
        
         
        except Exception as error:
            log.debug("Unable to configure static BH mac route on Remote Vtep- Encountered Exception " + str(error))
            self.errored('Exception occurred while configuring static BH mac route on Remote Vtep', goto=['cleanup'])
    @aetest.test
    def Verify_BH_states_in_AM(self, testscript,testbed):
        node3_s1_bgw_1 = testbed.devices['node3_s1_bgw_1']
        node4_s1_bgw_2 = testbed.devices['node4_s1_bgw_2']
        node7_s2_bgw_1 = testbed.devices['node7_s2_bgw_1']
        P1_dict = S1_BGW1_TGEN_data
        P2_dict = S1_Leaf_TGEN_data
        P3_dict = AcceSW_TGEN_data
        P4_dict = S2_Leaf_TGEN_data

        try:        
            if verify_BH_in_AM(node4_s1_bgw_2,str(P3_dict['mac']),str(P3_dict['vlan_id']),str(P3_dict['v4_addr'])):
                log.info('Mac BH route is proper in AM on  S1_BGW1')
            else:
                log.info('Mac BH route is improper in AM on  S1_BGW1')
                self.failed('Mac BH route is improper in AM on  S1_BGW1')
                   
        
        except Exception as error:
            log.debug("Unable to configure static BH mac route on Remote Vtep- Encountered Exception " + str(error))
            self.errored('Exception occurred while configuring static BH mac route on Remote Vtep', goto=['cleanup'])
    @aetest.test
    def Verify_BH_states_in_remote_ARP(self, testscript,testbed):
        node3_s1_bgw_1 =testbed.devices['node3_s1_bgw_1']
        node7_s2_bgw_1 = testbed.devices['node7_s2_bgw_1']
        P3_dict = AcceSW_TGEN_data

        try: 

            if verify_BH_in_Remote_ARP(node7_s2_bgw_1,str(P3_dict['vlan_id']),str(P3_dict['mac'])):
               log.info('Mac BH route is proper in Remote ARP on  S2_BGW1')
            else:
                log.info('Mac BH route is improper in Remote ARP on  S2_BGW1')
                self.failed('Mac BH route is improper in Remote ARP on  S2_BGW1')

        except Exception as error:
            log.debug("Unable to configure static BH mac route on Remote Vtep- Encountered Exception " + str(error))
            self.errored('Exception occurred while configuring static BH mac route on Remote Vtep')        
    @aetest.test
    def Verify_BH_states_in_local_ARP(self, testscript,testbed):
        node3_s1_bgw_1 = testbed.devices['node3_s1_bgw_1']
        node7_s2_bgw_1 = testbed.devices['node7_s2_bgw_1']
        P1_dict = S1_BGW1_TGEN_data
        P2_dict = S1_Leaf_TGEN_data
        P3_dict = AcceSW_TGEN_data
        P4_dict = S2_Leaf_TGEN_data
        try:        
            if verify_BH_in_local_ARP(node3_s1_bgw_1,str(P3_dict['vlan_id']),str(P3_dict['mac'])):
                log.info('Mac BH route is proper in Local ARP on  S1_BGW1')
            else:
                log.info('Mac BH route is improper in Local ARP on  S1_BGW1')
                self.failed('Mac BH route is improper in Local ARP on  S1_BGW1')
        
        except Exception as error:
            log.debug("Unable to configure static BH mac route on Remote Vtep- Encountered Exception " + str(error))
            self.errored('Exception occurred while configuring static BH mac route on Remote Vtep')
    @aetest.test  
    def Verify_Mac_BH_Route_on_L2FM_BGP_L2RIB(self,testscript,testbed):
        node3_s1_bgw_1 = testbed.devices['node3_s1_bgw_1']
        node7_s2_bgw_1 = testbed.devices['node7_s2_bgw_1']
        P3_dict = AcceSW_TGEN_data
        
        # Verifying L2FM

        try:
            ###S1_BGW1_MAC_BH_ROUTE
            if verify_BH_route_in_L2FM(node3_s1_bgw_1,str(P3_dict['vlan_id']),str(P3_dict['mac'])):
                log.info('Mac BH route is proper in L2FM on  S1_BGw1')
            else:
                log.info('Mac BH route is improper in L2FM on  S1_BGw1')
                self.failed('Mac BH route is improper in L2FM on  S1_BGw1')

            ###S2_BGW1_MAC_BH_ROUTE Remote Vtep
            if verify_BH_route_in_L2FM(node7_s2_bgw_1,str(P3_dict['vlan_id']),str(P3_dict['mac'])):
                log.info('Mac BH route is proper in L2FM on  S2_BGw1')
            else:
                log.info('Mac BH route is improper in L2FM on  S2_BGw1')
                self.failed('Mac BH route is improper in L2FM on  S2_BGw1')

        except Exception as error:
            log.debug("Unable to verify BH mac route in L2FM - Encountered Exception " + str(error))
            self.errored('Exception occurred while verifying BH mac route in L2FM')        

        #Verifying L2RIB
        try:
            #S1_Leaf_Mac_BH_route
            if verify_L2rib_mac_ip_output(node3_s1_bgw_1,str(P3_dict['vlan_id']),str(P3_dict['mac'])):
                log.info('Mac BH route is proper in L2RIB on S1_Leaf')
            else:
                log.debug('Mac BH route is improper in L2RIB on  S1_Leaf')
                self.failed('Mac BH route is improper in L2RIB on  S1_Leaf')

            #S2_BGW1_Mac_BH_route
            if verify_L2rib_mac_ip_output(node7_s2_bgw_1,str(P3_dict['vlan_id']),str(P3_dict['mac'])):
                log.info('Mac BH route is proper in L2RIB on S2_BGW1')
            else:
                log.debug('Mac BH route is improper in L2RIB on  S2_BGW1')
                self.errored('Mac BH route is improper in L2RIB on  S2_BGW1')
        
        except Exception as error:
            log.debug("Unable to verify BH mac route in L2RIB - Encountered Exception " + str(error))
            self.errored('Exception occurred while verifying BH mac route in L2RIB')
        
        #Verifying BGP
        try:
            #S2_BGW1_Mac_BH_route
            if verify_BH_in_Remote_BGP(node7_s2_bgw_1,str(P3_dict['mac'])):
                log.info('Mac BH route is proper in BGP on S2_BGW1')
            else:
                log.debug('Mac BH route is improper in BGP on  S2_BGW1')
                self.errored('Mac BH route is improper in BGP on  S2_BGW1')

            #Access_Mac_BH_route
            if verify_BH_in_Remote_BGP(node3_s1_bgw_1,str(P3_dict['mac'])):
                log.info('Mac BH route is proper in BGP on Access')
            else:
                log.debug('Mac BH route is improper in BGP on  Access')
                self.errored('Mac BH route is improper in BGP on  Access')
        
        except Exception as error:
            log.debug("Unable to verify BH mac route in BGP - Encountered Exception " + str(error))
            self.errored('Exception occurred while verifying BH mac route in BGP', )

    @aetest.cleanup
    def cleanup(self,testscript,testbed):
        """Unconfigure qos policies"""
        node3_s1_bgw_1 = testbed.devices['node3_s1_bgw_1']
        node5_s1_leaf_1 = testbed.devices['node5_s1_leaf_1']
        node4_s1_bgw_2 = testbed.devices['node4_s1_bgw_2']
        node7_s2_bgw_1 = testbed.devices['node7_s2_bgw_1']
        node9_s2_leaf_1 = testbed.devices['node9_s2_leaf_1']
        forwardingSysDict = FWD_SYS_dict
        P3_dict = AcceSW_TGEN_data
        post_test_process_dict = {
            'dut_list'                       : [node3_s1_bgw_1,node4_s1_bgw_2,node7_s2_bgw_1],
            'cc_check'                  : 0,
            'cores_check'               : 1,
            'logs_check'                : 1,
            'fnl_flag'                  : 0,
            'exclude_log_check_pattern' : 'ERROR_VLANS_SUSPENDED|ERROR_VLANS_REMOVED|SYSMGR-2-SERVICE_CRASHED',
            }
        try:
            # Stop Traffic from ixia
            log.info("--- Stopping Traffic ---- \n")
            log.info("Stopping Traffic")
            traffic_run_status = ixLib.stop_traffic()
            
            if traffic_run_status is not 1:
               log.info("Failed: To Stop traffic")
               return 0
            else:
                log.info("\nTraffic Stopped successfully\n")
            time.sleep(10)
            ####Remove traffic item configured
            UCAST_L2_dict = {
                            'mode'        : 'remove',
                            'stream_id'   : stream_id,
                      }
            if (ixLib.delete_traffic_item(UCAST_L2_dict))==0:
                log.debug("Traffic Remove failed")
                self.failed("Traffic Remove failed", goto=['next_tc'])
            else:
                log.info("Traffic Remove Passed")

            mac= str(P3_dict['mac'])
            vlan= str(P3_dict['vlan_id'])
            ip=str(P3_dict['v4_addr'])
            octet = 1
            no_int= int(P3_dict['no_of_ints'])
        
            for i in range (0,no_int):
            ###LEAF_3_MAC_BH_ROUTE
                testbed.devices['node3_s1_bgw_1'].configure('''
                    no mac address-table static ''' + str(mac) + ''' vlan '''+ str(vlan) + ''' drop

                    interface vlan ''' + str(vlan) + '''
                        no ip arp ''' + str(ip) + ''' ''' + str(mac) + '''
                ''')
                testbed.devices['node4_s1_bgw_2'].configure('''
                    no mac address-table static ''' + str(mac) + ''' vlan '''+ str(vlan) + ''' drop

                    interface vlan ''' + str(vlan) + '''
                        no ip arp ''' + str(ip) + ''' ''' + str(mac) + '''
                ''')
                lasthex=incr_mac(mac)
                mac=mac[0:10]+lasthex
                vlan= int(vlan)+int(P3_dict['vlan_id_step'])
                ip=incr_ip(ip,octet)
            ##check for cores,cc,errors
            status = infraVerify.postTestVerification(post_test_process_dict)
            if status['status'] == 0:
                self.failed(reason=status['logs'])
            else:
                self.passed(reason=status['logs'])
        except Exception as error:
            log.debug("Unable to do cleanup " + str(error))
            self.errored('Exception occurred during cleanup', goto=['next_tc'])


###################################################################
###                Port-security  Test-cases                   ###
###################################################################   

class Configure_Static_mac_on_vpc_vtep_pointing_to_an_interface_on_the_vpc_vtep(nxtest.Testcase):
    #"TC_0124_Configure_Static_mac_on_vpc_vtep_pointing_to_an_interface_on_the_vpc_vtep"
    stream_id=''
    @aetest.test
    def CONFIGURE_L2_UCAST_IXIA_TRAFFIC_H2_to_H1(self, testscript):
        """ IXIA_CONFIGURATION subsection: Configure MCAST Traffic Item """

        # Do not perform configurations if skip_tgen_config flag is set
        #if not testscript.parameters['script_flags']['skip_tgen_config']:

        IX_TP1 = testscript.parameters['IX_TP1']
        IX_TP2 = testscript.parameters['IX_TP2']
        IX_TP3 = testscript.parameters['IX_TP3']
        IX_TP4 = testscript.parameters['IX_TP4']

        P1_dict = S1_BGW1_TGEN_data
        P2_dict = S1_Leaf_TGEN_data
        P3_dict = AcceSW_TGEN_data
        P4_dict = S2_Leaf_TGEN_data

        #sending traffic P2 = Host2 to P3 = Host1
        UCAST_L2_dict = {   'src_hndl'  : IX_TP4['port_handle'],
                            'dst_hndl'  : IX_TP1['port_handle'],
                            'circuit'   : 'raw',
                            'TI_name'   : "UCAST_L2",
                            'rate_pps'  : "9000",
                            'bi_dir'    : 0,
                            'frame_size': '128',
                            'src_mac'   : P4_dict['mac'],
                            'dst_mac'   : P1_dict['mac'],
                            'srcmac_step': P4_dict['mac_step'],
                            'dstmac_step': P1_dict['mac_step'],
                            'srcmac_count': '1',
                            'dstmac_count': '1',
                            'vlan_id'    : P4_dict['vlan_id'],
                            'vlanid_step': P4_dict['vlan_id_step'],
                            'vlanid_count': '1',
                            'vlan_user_priority': P4_dict['vlan_user_priority']

                        }

        UCAST_L2_TI = ixLib.configure_ixia_L2_UCAST_traffic_item(UCAST_L2_dict)

        if UCAST_L2_TI == 0:
            log.debug("Configuring UCast L2 TI failed")
            self.errored("Configuring UCast L2 TI failed", goto=['cleanup'])
        else:
            global stream_id
            stream_id = UCAST_L2_TI
            log.info('stream_id='+stream_id)
            log.info(type(stream_id))

        # else:
        # self.passed(reason="Skipped TGEN Configurations as per request")
    @aetest.test
    def APPLY_TRAFFIC(self):
        """ IXIA_CONFIGURATION subsection: Verify IXIA Traffic """

        # Apply IXIA Traffic
        if ixLib.apply_traffic() == 1:
            log.info("Applying IXIA TI Passed")
        else:
            self.errored("Applying IXIA TI failed")

    @aetest.test
    def config_static_mac_on_vpc(self,testbed):
        node3_s1_bgw_1 = testbed.devices['node3_s1_bgw_1']
        node7_s2_bgw_1 = testbed.devices['node7_s2_bgw_1']
        P1_dict = S1_BGW1_TGEN_data


        testbed.devices['node3_s1_bgw_1'].configure('''
            mac address-table static ''' + str(P1_dict['mac']) + ''' vlan '''+ str(P1_dict['vlan_id']) + ''' interface eth''' + testbed.devices['node3_s1_bgw_1'].interfaces['Ethernet1/20'].intf + ''' 
        ''')
        #ForkedPdb().set_trace() 

    time.sleep(20)
    @aetest.test
    def verify_static_mac_states(self, testscript,testbed):
        node3_s1_bgw_1 = testbed.devices['node3_s1_bgw_1']
        node7_s2_bgw_1 = testbed.devices['node7_s2_bgw_1']
        P1_dict = S1_BGW1_TGEN_data
        if verify_static_mac(node3_s1_bgw_1,str(P1_dict['mac']),str(P1_dict['vlan_id'])):
            log.info('proper dynaic mac learnt as static on S1_BGw1')
        else:
            log.info('improper dynamic mac learnt on  S1_BGw1')
            self.failed('improper dynamic mac learnt on  S1_BGw1')

        time.sleep(20)
        if verify_static_mac(node7_s2_bgw_1,str(P1_dict['mac']),str(P1_dict['vlan_id'])):
            log.info('proper dynaic mac learnt on  S2_BGw1')
        else:
            log.info('improper dynamic mac learnt on S2_BGw1')
            self.failed('improper dynamic mac learnt on  S2_BGw1')
    
    @aetest.test
    def VERIFY_IXIA_TRAFFIC_With_BH_Route(self, testscript):
        """ IXIA_CONFIGURATION subsection: Verify IXIA Traffic """

        # Do not perform configurations if skip_tgen_config flag is set
        #if not testscript.parameters['script_flags']['skip_tgen_config']:

        log.info('waiting 40 seconds before verifying traffic')
        time.sleep(40)
    
        if ixLib.verify_traffic(99) == 1:
            # ForkedPdb().set_trace()
            log.debug("Traffic Verification Passed.")
        
        else:
            log.info("Traffic Verification Failed.")
            # ForkedPdb().set_trace()
            self.failed("Traffic Verification failed")


    @aetest.test
    def Unconfig_static_mac_on_vpc(self,testbed):
        node3_s1_bgw_1 = testbed.devices['node3_s1_bgw_1']
        node7_s2_bgw_1 = testbed.devices['node7_s2_bgw_1']
        P1_dict = S1_BGW1_TGEN_data


        testbed.devices['node3_s1_bgw_1'].configure('''
            no mac address-table static ''' + str(P1_dict['mac']) + ''' vlan '''+ str(P1_dict['vlan_id']) + ''' interface eth''' + testbed.devices['node3_s1_bgw_1'].interfaces['Ethernet1/20'].intf + ''' 
        ''')
   
    @aetest.cleanup
    def cleanup(self,testscript,testbed):
        """Unconfigure qos policies"""
        node3_s1_bgw_1 = testbed.devices['node3_s1_bgw_1']
        node5_s1_leaf_1 = testbed.devices['node5_s1_leaf_1']
        node4_s1_bgw_2 = testbed.devices['node4_s1_bgw_2']
        node7_s2_bgw_1 = testbed.devices['node7_s2_bgw_1']
        node9_s2_leaf_1 = testbed.devices['node9_s2_leaf_1']
        forwardingSysDict = FWD_SYS_dict
        P3_dict = AcceSW_TGEN_data
    
        try:
            # Stop Traffic from ixia
            log.info("--- Stopping Traffic ---- \n")
            log.info("Stopping Traffic")
            traffic_run_status = ixLib.stop_traffic()
            
            if traffic_run_status is not 1:
               log.info("Failed: To Stop traffic")
               return 0
            else:
                log.info("\nTraffic Stopped successfully\n")
            time.sleep(10)
            ####Remove traffic item configured
            UCAST_L2_dict = {
                            'mode'        : 'remove',
                            'stream_id'   : stream_id,
                      }
            if (ixLib.delete_traffic_item(UCAST_L2_dict))==0:
                log.debug("Traffic Remove failed")
                self.failed("Traffic Remove failed", goto=['next_tc'])
            else:
                log.info("Traffic Remove Passed")

            ##check for cores,cc,errors
        except Exception as error:
            log.debug("Unable to do cleanup " + str(error))
            self.errored('Exception occurred during cleanup', goto=['next_tc'])


class Static_mac_move(nxtest.Testcase):
    @aetest.test
    def config_static_mac_on_vpc(self,testbed):
        node3_s1_bgw_1 = testbed.devices['node3_s1_bgw_1']
        node7_s2_bgw_1 = testbed.devices['node7_s2_bgw_1']
        P1_dict = S1_BGW1_TGEN_data


        testbed.devices['node3_s1_bgw_1'].configure('''
            mac address-table static ''' + str(P1_dict['mac']) + ''' vlan '''+ str(P1_dict['vlan_id']) + ''' interface eth''' + testbed.devices['node3_s1_bgw_1'].interfaces['Ethernet1/7'].intf + ''' 
        ''')
        #ForkedPdb().set_trace() 
        
    time.sleep(20)
    @aetest.test
    def verify_static_mac_states(self, testscript,testbed):
        node3_s1_bgw_1 = testbed.devices['node3_s1_bgw_1']
        node7_s2_bgw_1 = testbed.devices['node7_s2_bgw_1']
        P1_dict = S1_BGW1_TGEN_data
        if verify_static_mac(node3_s1_bgw_1,str(P1_dict['mac']),str(P1_dict['vlan_id'])):
            log.info('proper dynaic mac learnt as static on S1_BGw1')
        else:
            log.info('improper dynamic mac learnt on  S1_BGw1')
            self.failed('improper dynamic mac learnt on  S1_BGw1')

        if verify_static_mac(node7_s2_bgw_1,str(P1_dict['mac']),str(P1_dict['vlan_id'])):
            log.info('proper dynaic mac learnt on  S2_BGw1')
        else:
            log.info('improper dynamic mac learnt on S2_BGw1')
            self.failed('improper dynamic mac learnt on  S2_BGw1')


    @aetest.test
    def Unconfig_static_mac_on_vpc(self,testbed):
        node3_s1_bgw_1 = testbed.devices['node3_s1_bgw_1']
        node7_s2_bgw_1 = testbed.devices['node7_s2_bgw_1']
        P1_dict = S1_BGW1_TGEN_data


        testbed.devices['node3_s1_bgw_1'].configure('''
            no mac address-table static ''' + str(P1_dict['mac']) + ''' vlan '''+ str(P1_dict['vlan_id']) + ''' interface eth''' + testbed.devices['node3_s1_bgw_1'].interfaces['Ethernet1/7'].intf + ''' 
        ''')


###################################################################
###                Negative  Test-cases                         ###
################################################################### 

class Unknown_Unicast_traffic_Configure_BH_mac_route_to_this_Destmac(nxtest.Testcase):
    stream_id=''
    @aetest.test
    def CONFIGURE_L2_UCAST_IXIA_TRAFFIC_H2_to_H1(self, testscript):
        """ IXIA_CONFIGURATION subsection: Configure MCAST Traffic Item """

        # Do not perform configurations if skip_tgen_config flag is set
        #if not testscript.parameters['script_flags']['skip_tgen_config']:

        IX_TP1 = testscript.parameters['IX_TP1']
        IX_TP2 = testscript.parameters['IX_TP2']
        IX_TP3 = testscript.parameters['IX_TP3']
        IX_TP4 = testscript.parameters['IX_TP4']

        
        P3 = Access_TGEN_DATA_1
        P3_dict = AcceSW_TGEN_data
        P4_dict = S2_Leaf_TGEN_data

        #sending traffic P2 = Host2 to P3 = Host1
        UCAST_L2_dict = {   'src_hndl'  : IX_TP4['port_handle'],
                            'dst_hndl'  : IX_TP3['port_handle'],
                            'circuit'   : 'raw',
                            'TI_name'   : "UCAST_L2",
                            'rate_pps'  : "9000",
                            'frame_size': '128',
                            'src_mac'   : P4_dict['mac'],
                            'dst_mac'   : P3['mac'],
                            'srcmac_step': P4_dict['mac_step'],
                            'dstmac_step': P3['mac_step'],
                            'srcmac_count': '1',
                            'dstmac_count': '10',
                            'vlan_id'    : P4_dict['vlan_id'],
                            'vlanid_step': '0',
                            'vlanid_count': '1',
                            'vlan_user_priority': P4_dict['vlan_user_priority']

                        }

        UCAST_L2_TI = ixLib.configure_ixia_L2_UCAST_traffic_item(UCAST_L2_dict)

        if UCAST_L2_TI == 0:
            log.debug("Configuring UCast L2 TI failed")
            self.errored("Configuring UCast L2 TI failed", goto=['cleanup'])
        else:
            global stream_id
            stream_id = UCAST_L2_TI
            log.info('stream_id='+stream_id)
            log.info(type(stream_id))
        
    @aetest.test
    def Config_Mac_BH_on_Vpc_Vtep(self, testscript,testbed):
        node3_s1_bgw_1 =  testbed.devices['node3_s1_bgw_1']
        P3 = Access_TGEN_DATA_1
        mac= str(P3['mac'])
        vlan= str(P3['vlan_id'])
        no_int= int(P3['no_of_ints'])
        
        for i in range (0,no_int):
            ###LEAF_3_MAC_BH_ROUTE
            testbed.devices['node3_s1_bgw_1'].configure('''
                mac address-table static ''' + str(mac) + ''' vlan '''+ str(vlan) + ''' drop
            ''')
            lasthex=incr_mac(mac)
            mac=mac[0:10]+lasthex

    @aetest.test
    def APPLY_TRAFFIC(self):
        """ IXIA_CONFIGURATION subsection: Verify IXIA Traffic """

        # Apply IXIA Traffic
        if ixLib.apply_traffic() == 1:
            log.info("Applying IXIA TI Passed")
        else:
            self.errored("Applying IXIA TI failed")
    
    @aetest.test
    def VERIFY_IXIA_TRAFFIC_With_BH_Route(self, testscript):
        """ IXIA_CONFIGURATION subsection: Verify IXIA Traffic """

        # Do not perform configurations if skip_tgen_config flag is set
        #if not testscript.parameters['script_flags']['skip_tgen_config']:

        time.sleep(20)
        b=0
        for i in range (b):
            if ixLib.verify_traffic(99) == 0:
                log.debug("Traffic Verification Passed.") 
            else:
                log.info("Traffic Verification Failed.")
                self.failed("Traffic Verification failed")
        # else:
        #     self.passed(reason="Skipped TGEN Configurations as per request")

    @aetest.test
    def UnConfig_Mac_BH_on_Vpc_Vtep(self, testscript,testbed):
        node3_s1_bgw_1 =  testbed.devices['node3_s1_bgw_1']
        P3 = Access_TGEN_DATA_1
        mac= str(P3['mac'])
        vlan= str(P3['vlan_id'])
        no_int= int(P3['no_of_ints'])
        
        for i in range (0,no_int):
            ###LEAF_3_MAC_BH_ROUTE
            testbed.devices['node3_s1_bgw_1'].configure('''
                no mac address-table static ''' + str(mac) + ''' vlan '''+ str(vlan) + ''' drop
            ''')
            lasthex=incr_mac(mac)
            mac=mac[0:10]+lasthex
    
    @aetest.test
    def cleanup(self,testscript,testbed):
        """Unconfigure Evpn policies"""
        node3_s1_bgw_1 =testbed.devices['node3_s1_bgw_1']
        node5_s1_leaf_1 = testbed.devices['node5_s1_leaf_1']
        node10_s1_AccessSW = testbed.devices['node10_s1_AccessSW']
        node7_s2_bgw_1 = testbed.devices['node7_s2_bgw_1']
        P3_dict = AcceSW_TGEN_data
        forwardingSysDict = FWD_SYS_dict
    	# Stop Traffic from ixia
        log.info("--- Stopping Traffic ---- \n")
        log.info("Stopping Traffic")
        traffic_run_status = ixLib.stop_traffic()
    
        if traffic_run_status is not 1:
            log.info("Failed: To Stop traffic")
            return 0
        else:
            log.info("\nTraffic Stopped successfully\n")
            time.sleep(10)
    	####Remove traffic item configured
        UCAST_L2_dict = {
                    'mode'        : 'remove',
                    'stream_id'   : stream_id,
              }
        if (ixLib.delete_traffic_item(UCAST_L2_dict))==0:
            log.debug("Traffic Remove failed")
            self.failed("Traffic Remove failed", goto=['next_tc'])
        else:
            log.info("Traffic Remove Passed")

# class TriggerSSO(nxtest.Testcase):
#     """ TriggerSSO - Perform SSO """

#     @aetest.test
#     def perform_copy_r_s(self, testbed, device_dut):

#         for node in device_dut:
#             testbed.devices[node].configure("copy r s", timeout=600)

#     @aetest.test
#     def perform_SSO(self, testbed, device_dut):

#         for node in device_dut:

#             # Perform Device Reload
#             result = infraEORTrigger.verifyDeviceSSO({'dut':testbed.devices[node]})
#             if result:
#                 log.info("SSO completed Successfully")
#             else:
#                 log.debug("SSO Failed")
#                 self.failed("SSO Failed")

#             log.info("Waiting for 120 sec for the topology to come UP")
#             time.sleep(500)
    
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
                self.failed("SSO Failed")

            log.info("Waiting for 120 sec for the topology to come UP")
            time.sleep(500) 

    # @aetest.test
    # def perform_copy_r_s(self, testbed, device_dut):

    #     for node in device_dut:
    #         testbed.devices[node].configure("copy r s", timeout=600)

    # @aetest.test
    # def perform_SSO(self, testbed, device_dut):
    #     fail_flag = []
    #     validation_msgs = ''
    #     for node in device_dut:

    #         # Perform Device Reload
    #         # Perform the SSO
    #         SSO_status =  testbed.devices[node].switchover(timeout=1200, sync_standby=True, prompt_recovery=True)

    #         if SSO_status:
    #             log.info("System Switchover is Successful")
    #             print("System Switchover is Successful")
    #             validation_msgs += "\n\n ==> System Switchover is Successful <== \n"
    #         else:
    #             fail_flag.append(0)
    #             log.info("System Switchover has Failed")
    #             print("System Switchover has Failed")
    #             validation_msgs += "\n\n ==> System Switchover has failed <== \n"
        
    #     # Check the fail_flag and report accordingly
    #     if 0 in fail_flag:
    #         log.debug("SSO Failed")
    #         self.failed(reason=validation_msgs)
            
    #     else:
    #         log.info("SSO completed Successfully")


class TriggerLCReload(nxtest.Testcase):
    """ TriggerLCReload - Perform all LC Reload from interface """
    
    @aetest.test
    def perform_copy_r_s(self, testbed, device_dut):
        
        for node in device_dut:
            testbed.devices[node].configure("copy r s", timeout=600)
        
    @aetest.test
    def perform_LC_sequential_reload(self, testbed, device_dut):
        
        fail_flag = []
        node_mod_list = []
        status_msgs = ''
        
        for node in device_dut:
            
            # for interface in testbed.devices[node].interfaces:
            node_mod_list = infraVerify.getModuleFromInt(node, testbed.devices[node].interfaces)
            
            log.info("Extracted module list is :")
            log.info(node_mod_list)
            for module in node_mod_list:
                mod_arg_dict = {
                    'dut'                       : testbed.devices[node],
                    'mod_num'                   : module,
                    'exclude_log_check_pattern' : 'ERROR_VLANS_SUSPENDED|ERROR_VLANS_REMOVED|IF_DOWN_INTERFACE_REMOVED|LOG_SMART_LIC_COMM_FAILED|PEER_KEEP_ALIVE_RECV_FAIL|BGP-5-ADJCHANG'
                }

                reload_status = infraEORTrigger.verifyModuleReload(mod_arg_dict)
                if reload_status['status']:
                    status_msgs += '''
                    Reload of module ''' + str(module) + ''' : PASS
                    ===========================================
                    ''' + str(reload_status['logs'])
                else:
                    fail_flag.append(0)
                    status_msgs += '''
                    Reload of module ''' + str(module) + ''' : FAIL
                    ===========================================
                    ''' + str(reload_status['logs'])

                time.sleep(300)
                status_msgs += '''
                        Traffic Check after Reload of module ''' + str(module) + '''
                        --------------------------------------------------------
                '''
            
            if 0 in fail_flag:
                log.debug("FM Reload Failed")
                log.info(status_msgs)
                self.failed("FM Reload Failed")
            else:
                log.info("FM Reload Successfully")
            
            log.info("Waiting for 240 sec for the topology to come UP")
            time.sleep(240)

class TriggerFMReload(nxtest.Testcase):
    """ TriggerFMReload - Perform FM sequentially """
    
    @aetest.test
    def perform_copy_r_s(self, testbed, device_dut):
    
        for node in device_dut:
            testbed.devices[node].configure("copy r s", timeout=600)
    
    @aetest.test
    def perform_all_FMs_sequential_reload(self, testbed, device_dut):
        
        for node in device_dut:
            
            fail_flag = []
            status_msgs = ''
            node_fm_mod_list = []
            fabric_mod_out = json.loads(testbed.devices[node].execute("show mod fabric | json"))['TABLE_modinfo']['ROW_modinfo']
            for fm_data in fabric_mod_out:
                node_fm_mod_list.append(fm_data['modinf'])
            
            for module in node_fm_mod_list:
                
                mod_arg_dict = {
                    'dut'                       : testbed.devices[node],
                    'mod_num'                   : module,
                    'exclude_log_check_pattern' : 'ERROR_VLANS_SUSPENDED|ERROR_VLANS_REMOVED|IF_DOWN_INTERFACE_REMOVED|LOG_SMART_LIC_COMM_FAILED'
                }
                
                reload_status = infraEORTrigger.verifyModuleReload(mod_arg_dict)
                if reload_status['status']:
                    status_msgs += '''
                    Reload of FM ''' + str(module) + ''' : PASS
                    ===========================================
                    ''' + str(reload_status['logs'])
                else:
                    fail_flag.append(0)
                    status_msgs += '''
                    Reload of FM ''' + str(module) + ''' : FAIL
                    ===========================================
                    ''' + str(reload_status['logs'])
            
            if 0 in fail_flag:
                log.debug("FM Reload Failed")
                log.info(status_msgs)
                self.failed("FM Reload Failed")
            else:
                log.info("FM Reload Successfully")
            
            log.info("Waiting for 240 sec for the topology to come UP")
            time.sleep(240)

class TriggerSCReload(nxtest.Testcase):
    """ TriggerSCReload - Perform SC Reload sequentially """
    
    @aetest.test
    def perform_copy_r_s(self, testbed, device_dut):
        
        for node in device_dut:
            testbed.devices[node].configure("copy r s", timeout=600)
        
    @aetest.test
    def perform_all_SCs_sequential_reload(self, testbed, device_dut):
        
        fail_flag = []
        status_msgs = ''
        
        for node in device_dut:
        
            node_sc_mod_list = []
            sc_mod_out = json.loads(testbed.devices[node].execute("show mod | json"))['TABLE_modwwninfo']['ROW_modwwninfo']
            for sc_data in sc_mod_out:
                if "SC" in sc_data['slottype']:
                    node_sc_mod_list.append(sc_data['modwwn'])
            
            for module in node_sc_mod_list:
                mod_arg_dict = {
                    'dut'                       : testbed.devices[node],
                    'mod_num'                   : module,
                    'exclude_log_check_pattern' : 'ERROR_VLANS_SUSPENDED|ERROR_VLANS_REMOVED|IF_DOWN_INTERFACE_REMOVED|LOG_SMART_LIC_COMM_FAILED'
                }
                
                reload_status = infraEORTrigger.verifyModuleReload(mod_arg_dict)
                if reload_status['status']:
                    status_msgs += '''
                    Reload of FM ''' + str(module) + ''' : PASS
                    ===========================================
                    ''' + str(reload_status['logs'])
                else:
                    fail_flag.append(0)
                    status_msgs += '''
                    Reload of FM ''' + str(module) + ''' : FAIL
                    ===========================================
                    ''' + str(reload_status['logs'])
                
            if 0 in fail_flag:
                log.debug("FM Reload Failed")
                log.info(status_msgs)
                self.failed("FM Reload Failed")
            else:
                log.info("FM Reload Successfully")
            
            log.info("Waiting for 240 sec for the topology to come UP")
            time.sleep(240)




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
            time.sleep(12)

