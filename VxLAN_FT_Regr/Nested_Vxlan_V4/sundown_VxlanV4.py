#
#   Demo script file for setup bring

# python generic imports
import yaml
import logging
import argparse
import re
import time
from common_lib import utils
from common_lib.utils import *
import MyLib
from MyLib import my_utils
from MyLib import my_config_utils
from MyLib import my_trigger_utils

from pyats import aetest
from common_lib import config_bringup
from common_lib import config_bringup_test
import yaml
import logging
from pyats.topology import loader
import argparse

# pyATS imports

from unicon import Connection
from ats import aetest
from ats.log.utils import banner
from ats.datastructures.logic import Not, And, Or
from ats.easypy import run
from ats.log.utils import banner
from common_lib import bringup_lib
#import evpn_lib
from feature_lib.vxlan import vxlan_lib
from feature_lib.l3 import ospfv2_lib
from feature_lib.l3 import ospfv3_lib
from feature_lib.l3 import bgp_lib
from feature_lib.vxlan import evpn_lib
from common_lib import tcam_lib
from feature_lib.l3 import pim_lib
from feature_lib.l2 import vpc_lib
#import oam_lib
from pyats.async_ import pcall
from pyats.async_ import Pcall

import threading

#Ixia Libraries
from common_lib import ixia_lib_new
from common_lib.ixia_lib_new import *

# N39k Library imports
from common_lib import config_bringup
# import config_bringup_test
from common_lib import config_bringup_test_vijay
from common_lib import interface_lib
import ipaddress

from itertools import chain
from collections import OrderedDict
from itertools import permutations
import json
from bs4 import BeautifulSoup
from prettytable import PrettyTable
import random
from _ast import alias
import threading

import unicon.statemachine.statemachine
from unicon.eal.dialogs import Statement, Dialog




def expandTrafficItemList(a):
    skip_list = []
    pat = re.compile(r'([A-Za-z]+)(\d+)-[A-Za-z]+(\d+)', flags=re.I)
    if a:
        log.info(banner('The Value of a is : {0}'.format(a)))
        c = a.split(',')
        log.info(banner('The Value of c is : {0}'.format(c)))
        for items in c:
            b = pat.search(items)
            [skip_list.append(b.group(1) + str("{:03d}".format(i))) for i in range(int(b.group(2)), int(b.group(3))+1)]
            
    return skip_list

def parseL3IntfParams(log,args):
    arggrammar={}
    arggrammar['mode']='-type str'
    arggrammar['ipv4_addr']='-type str'
    arggrammar['ipv6_addr']='-type str'
    ns = utils.parserutils_lib.argsToCommandOptions(args,arggrammar,log)
    return ns



def countDownTimer(a):
    for i in range(a):
        log.info('seconds remaining is: {0}'.format(int(a-i)))
        time.sleep(1)
    return 1

def getOspfInterfaceV4AndV6Dict(log,cfg_dict):
    intf_cfg_dict = cfg_dict['interface_config_dict']
    ospf_duts = list(cfg_dict['ospfv2_config_dict'].keys())
    osfp_interface_dict = {}
    for dut in ospf_duts:
        osfp_interface_dict[dut] = {}
        ip_addr_list = []
        ipv6_addr_list = []
        for intf in intf_cfg_dict['ethernet'][dut]:
            if isEmpty(osfp_interface_dict[dut]):
                osfp_interface_dict[dut]['v4_interface'] = {}
                osfp_interface_dict[dut]['v6_interface'] = {}
            ns = parseL3IntfParams(log,intf_cfg_dict['ethernet'][dut][intf])
            if ns.mode == 'no switchport':
                ip_addr_list.append(ns.ipv4_addr)
                ipv6_addr_list.append(ns.ipv6_addr)
        osfp_interface_dict[dut]['v4_interface']= ip_addr_list
        osfp_interface_dict[dut]['v6_interface']= ipv6_addr_list
    return osfp_interface_dict


def verifyOSPFv4Neighorship(log,ospf_interface_dict,node_dict):
    log.info(banner('The value of node_dict is {0}'.format(node_dict)))
    log.info(banner('The value of ospf_neighbor_dict is {0}'.format(ospf_interface_dict)))
    ospf_neighbor_dict = {}
    pat = re.compile(r'(?P<Neighbor>(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}))\s+')
    pat1 = re.compile(r"\s+\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\s+\d+\s+(\w+)")
    for dut in ospf_interface_dict:
        hdl=node_dict['all_dut'][dut]
        for ip in ospf_interface_dict[dut]['v4_interface']:
            new_ip = ".".join(ip.split('.')[0:3])
            cfg = 'show ip arp detail | grep {0}'.format(new_ip)
            out = hdl.configure(cfg)
            out1 = "".join([x for x in out.splitlines()[1:] if x])
            if not out1:
                log.info('The Adjacency entry is not formed for the peer {0}. Hence Exiting...'.format(ip))
                return 0
            filter = pat.match(out1)
            neighbor = filter.group('Neighbor').strip()
            cfg = 'show ip ospf neighbor | grep {0}'.format(neighbor)
            out2 = hdl.configure(cfg)
            out3 = "".join([x for x in out2.splitlines()[1:] if x])
            log.info('The Value of out3 is : {0}'.format(out3))
            filter1 = pat1.match("".join([x for x in out2.splitlines()[1:] if x]))
            log.info(banner('The value if filter1 is : {0}'.format(filter1)))
            if not filter1:
                log.info('Neighbor entry not found for the IP {0}'.format(neighbor))
                ospf_neighbor_dict[neighbor] = None
            else:
                ospf_neighbor_dict[neighbor] = filter1.group(1)
    
    log.info('The value of ospf_neighbor_dict is : {0}'.format(ospf_neighbor_dict))
    for k,v in ospf_neighbor_dict.items():
        if v != 'FULL':
            log.info('Neighborship is not established with ip {0} and is in {1} State'.format(k,v))
            return 0
    return 1


def verifyOSPFv6Neighorship(log,ospfv3_config_dict,node_dict,alias_intf_mapping_dict):
    log.info(banner('The value of node_dict is {0}'.format(node_dict)))
    log.info(banner('The value of ospf_neighbor_dict is {0}'.format(ospfv3_config_dict)))
    
    for dut in ospfv3_config_dict.keys():
        log.info('The duts are : {0}'.format(dut))
        hdl = node_dict['all_dut'][dut]
        for intf in ospfv3_config_dict[dut]['interface_config']:
            if re.search('uut',intf,re.I):
                log.info('The interfaces are : {0}'.format(intf))
                actual_interface = alias_intf_mapping_dict[intf]
                log.info(banner('The value of actual_interface is {0}'.format(actual_interface)))
                cfg = 'sh ipv6 ospfv3 neighbors {0} | xml'.format(actual_interface)
                out = hdl.execute(cfg)
                if out:
                    s = BeautifulSoup(out)
                    ospf_state = s.find('state').string
                    log.info(banner('The value of ospf_state is : {0}'.format(ospf_state)))
                    if not re.search('FULL',ospf_state,re.I):
                        log.info('OSPF Neighbor is not established in the interface {0}').format(actual_interface)
                        return 0
    return 1


def combineV4AndV6Neighbor(neighbors):
    v4v6neighborlist = []
    for nei in neighbors:
        for n in nei:
            v4v6neighborlist.append(n)
    return v4v6neighborlist
    
    
def verifyBGPL2EVPNNeighbor(log,bgp_config_dict,node_dict):
    log.info(banner('The value of node_dict is {0}'.format(node_dict)))
    log.info(banner('The value of bgp_config_dict is {0}'.format(bgp_config_dict)))
    for dut in bgp_config_dict.keys():
        hdl = node_dict['all_dut'][dut]
        for as_no in bgp_config_dict[dut]:
            for neighbor in combineV4AndV6Neighbor((bgp_config_dict[dut][as_no]['default']['neighbors']['ipv4'].keys(),bgp_config_dict[dut][as_no]['default']['neighbors']['ipv6'].keys())) :
                log.info(banner('The value of neighbor is : {0}'.format(neighbor)))
                cfg =  'sh bgp l2vpn evpn neighbors {0} | xml'.format(neighbor)
                out = hdl.execute(cfg)
                s = BeautifulSoup(out)
                bgp_state = s.find('state').string
                log.info('The value of BGP State is : {0}'.format(bgp_state))
                if not re.search('Established',bgp_state,re.I):
                    log.info('BGP L2EVPN Session did not come wup with neighbor {0}'.format(neighbor))
                    return 0
                log.info(banner('DUT -> {0} , Neighbor -> {1},  State :  {2}'.format(dut,neighbor,bgp_state)))
    return 1
    

def isEmpty(evpn_config_dict):
    for element in evpn_config_dict:
        if element:
            return True
        return False

def getTrafficStats(tg_hdl='', port_hdl='', mode=''):
    log.info('The value of tg_hdl is = %r', tg_hdl)
    log.info('The value of port_hdl is  = %r', port_hdl)
    log.info('The value of mode is  = %r', mode)
    if isinstance(port_hdl, list):
        for i in port_hdl:
            stat = tg_hdl.traffic_stats(port_handle=port_hdl, mode=mode)
    if isinstance(port_hdl, str):
        stat = tg_hdl.traffic_stats(port_handle=port_hdl, mode=mode)
    log.info('The value of stat is  = %r', stat)
    return(stat)

def getTrafficItemStatisticsBreakup(tgn_hdl,traffic_stream_dict,trf_stream,port_handle_dict):
    total_tx = {}
    total_rx = {}
    traffic_stream_stats = {}
    stream_id =  traffic_stream_dict[trf_stream]['stream_id']     
    source = traffic_stream_dict[trf_stream]['source']
    receiver = traffic_stream_dict[trf_stream]['destination']
    sender_port = []
    receiver_port = []
    if isinstance(source, list):
        for i in  source:
            sender_port.append(port_handle_dict[i])
    if isinstance(receiver, list):
        for i in receiver:
            receiver_port.append(port_handle_dict[i])
    try:
        stat_breakup = tgn_hdl.traffic_stats(stream = stream_id, mode = 'streams')
        log.info(banner('Inside Breakup .. The value of stat_breakup is : {0}'.format(stat_breakup)))
    except:
        log.info('Some Exception Occured.. ')
        log.info(banner('Inside Breakup .. The value of stat_breakup is : {0}'.format(stat_breakup)))
    for i in stat_breakup:
        log.info('The value of i is  :{0}'.format(i))
        if i in sender_port:
            log.info('sender_port: The value of is : {0}'.format(i))
            tx = stat_breakup[ii]['stream'][stream_id]['tx']['total_pkt_rate']
            total_tx[i] = tx
        if i in receiver_port:
            log.info('rcv_port: The value of is : {0}'.format(i))
            rx = stat_breakup[i]['stream'][stream_id]['rx']['total_pkt_rate']
            total_rx[i] = rx
    log.info('The value of total_tx is : {0}'.format(total_tx))
    log.info('The value of total_rx is : {0}'.format(total_rx))
    traffic_stream_stats['tx'] = total_tx
    traffic_stream_stats['rx'] = total_rx

    return traffic_stream_stats

def getTrafficItemStatistics(tgn_hdl,configured_stream,traffic_stream_dict,threshold,port_handle_dict):
    
    traffic_item_stats = {}
    for trf_item in configured_stream:
        log.info(banner('The value of trf_item is : {0}'.format(trf_item)))
        stream_name = traffic_stream_dict[trf_item]['stream_id']
        log.info(banner('The value of stream_name is : {0}'.format(stream_name)))
        traffic_item_stats[trf_item] = {}
        log.info(banner('The Value of traffic_stream_dict is : {0}'.format(traffic_stream_dict)))
        stats = tgn_hdl.traffic_stats(stream = stream_name, mode = 'traffic_item')
        log.info(banner('The Value of stats is : {0}'.format(stats)))
        traffic_item_stats[trf_item]['tx_stat'] = stats.traffic_item[stream_name]['tx'].total_pkt_rate
        traffic_item_stats[trf_item]['rx_stat'] = stats.traffic_item[stream_name]['rx'].total_pkt_rate
        if not abs(traffic_item_stats[trf_item]['rx_stat']-traffic_item_stats[trf_item]['tx_stat']) <=threshold:
            traffic_item_stats[trf_item]['status'] = 0
#            traffic_item_stats[trf_item]['break_up'] = getTrafficItemStatisticsBreakup(tgn_hdl,traffic_stream_dict,trf_item,port_handle_dict)
            log.error(banner('Traffic condition did not pass on the stream {0} before start of the test '.format(stream_name)))
        else:
            log.info(banner('Traffic flow is as expected.. Getting The breakup'))
            traffic_item_stats[trf_item]['status'] = 1
#            traffic_item_stats[trf_item]['break_up'] = getTrafficItemStatisticsBreakup(tgn_hdl,traffic_stream_dict,trf_item,port_handle_dict)
                        
    log.info(banner('The value of traffic_item_stats is : {0}'.format(traffic_item_stats)))
    
    flag = True
    
    for trf_item in traffic_item_stats:
        if not traffic_item_stats[trf_item]['status']:
            flag = False
    
    if flag:
        return 1
    else:
        log.info(banner('The following streams failed {0}'.format(traffic_item_stats)))
        return 0
        

def get_v4_mask_len(i):
    switcher={
            '24':256,
            '25':128,
            '26':64,
            '27':32,
            '28':15,
            '29':8,
            '30':4,
            '31':2,
            '32':1
             }
    return switcher.get(i,"Invalid Mask")


def get_v6_mask_len(i):
    switcher={
            '64':2**64,
            '65':2**65,
            '66':2**66,
            '67':2**67,
            '68':2**68,
            '69':2**69,
            '70':2**70,
            '71':2**71,
            '72':2**72
             }
    return switcher.get(i,"Invalid Mask")

def ipaddrgen(no_of_ip_address,start_ip,mask):
    return [(ipaddress.IPv4Address(start_ip) + i*get_v4_mask_len(str(mask))).exploded for i in range(no_of_ip_address)]

def ipv6addrgen(no_of_ip_address,start_ip,mask):
    return [(ipaddress.IPv6Address(start_ip) + i*get_v6_mask_len(str(mask))).exploded for i in range(no_of_ip_address)]

def generateVRFlist(vrf_name,no):
    return [vrf_name.split('-')[0] + '-' + str("{:03d}".format(int(vrf_name.split('-')[-1])+i)) for i in range(no)]

def mychain(spans):
    for start, no , vni_start in spans:
        for count,i in enumerate(range(start, start+no)):
            vni = vni_start + count
            cfg = ''' vlan {0}
                      no vn-segment
                      vn-segment {1}
                  '''.format(i,vni)
            yield cfg
       
def parseScaleSVIParams(log,args):

    arggrammar = {}
    arggrammar['no_of_l2_vni_svi'] = '-type int'
    arggrammar['l2_vni_svi_start'] = '-type int'
    arggrammar['l2_vni_svi_ipv4_start'] = '-type str'
    arggrammar['l2_vni_svi_ipv4_mask'] = '-type int'
    arggrammar['l2_vni_svi_ipv6_start'] = '-type str'
    arggrammar['l2_vni_svi_ipv6_mask'] = '-type int'
    arggrammar['no_of_l3_vni_svi'] = '-type int'
    arggrammar['l3_vni_svi_start'] = '-type int'
    arggrammar['l3_vni_svi_ipv4_start'] = '-type str'
    arggrammar['l3_vni_svi_ipv6_start'] = '-type str'                
    arggrammar['mtu'] = '-type int'
    arggrammar['anycast_gw'] = '-type bool'
    arggrammar['no_of_l2_vni_svi_per_vrf'] = '-type int'
    arggrammar['shutdown'] = '-type bool -default no shut'
    arggrammar['vrf_start_name'] = '-type str'
    ns = utils.parserutils_lib.argsToCommandOptions(args,arggrammar,log)
    return ns

def configureSVIs(hdl,dut,log,config_dict):
    cfg = 'feature interface-vlan \n'
    hdl.configure(cfg)
    ns = parseScaleSVIParams(log,config_dict)
    log.info(banner('The value of ns is {0}'.format(ns)))
    vrf_count = int(ns.no_of_l2_vni_svi / ns.no_of_l2_vni_svi_per_vrf)
    ip_addr_list = ipaddrgen(ns.no_of_l2_vni_svi,ns.l2_vni_svi_ipv4_start,ns.l2_vni_svi_ipv4_mask)
    ipv6_addr_list = ipv6addrgen(ns.no_of_l2_vni_svi,ns.l2_vni_svi_ipv6_start,ns.l2_vni_svi_ipv6_mask)
    vrf_name_list = generateVRFlist(ns.vrf_start_name,vrf_count)
    log.info(banner('The value of ip_addr_list is : {0}'.format(ip_addr_list)))
    log.info(banner('The value of ipv6_addr_list is : {0}'.format(ipv6_addr_list)))
    log.info(banner('The value of vrf_name_list is : {0}'.format(vrf_name_list)))
    k = 0
    l = 1
    for i,j in enumerate(range(ns.l2_vni_svi_start,ns.l2_vni_svi_start+ns.no_of_l2_vni_svi)):
        log.info('The value of k is {0}'.format(k))
        log.info('The value of vrf_name_list[k] is : {0}'.format(vrf_name_list[k]))
        if(l<=ns.no_of_l2_vni_svi_per_vrf):
            cfg =  '''int vlan {0}
                      vrf member {1}
                      ip address {2}/{3}
                      ipv6 address {4}/{5}
                    '''.format(j,vrf_name_list[k],ip_addr_list[i],ns.l2_vni_svi_ipv4_mask,ipv6_addr_list[i],ns.l2_vni_svi_ipv6_mask)
            if not ns.shutdown:
                cfg += 'no shutdown \n'
            if ns.mtu:
                cfg += 'mtu {0} \n'.format(ns.mtu)
            if ns.anycast_gw:
                cfg += 'fabric forwarding mode anycast-gateway \n'
        if(l == ns.no_of_l2_vni_svi_per_vrf):
            k += 1
            l = 0
        l = l + 1
        hdl.configure(cfg)
        
    for i,j in enumerate(range(ns.l3_vni_svi_start,ns.l3_vni_svi_start+ns.no_of_l3_vni_svi)):
        cfg = '''int vlan {0}
                 vrf member {1}
                 '''.format(j,vrf_name_list[i])
        if not ns.shutdown:
            cfg += 'no shutdown \n'
        if ns.l3_vni_svi_ipv4_start:
            cfg += 'ip forward \n'
        if ns.l3_vni_svi_ipv6_start:
            cfg += 'ipv6 forward \n'
        if ns.mtu:
            cfg += 'mtu {0} \n'.format(ns.mtu)
        hdl.configure(cfg)
    return 1


def parseScaleVlanParms(log,args):
    """Method to configure config under vpc domain"""
    log.info('Inside the parseScaleVlanParms function()')
    arggrammar = {}
    arggrammar['no_of_l2_vlans'] = '-type int'
    arggrammar['l2_vlan_start'] = '-type int'
    arggrammar['l2_vni_start'] = '-type int'
    arggrammar['no_of_l3_vlans'] = '-type int'
    arggrammar['l3_vlan_start'] = '-type int'
    arggrammar['l3_vni_start'] = '-type int'
    arggrammar['l2_vlan_name'] = '-type str'
    arggrammar['l2_vlan_shutdown'] = '-type bool -default False'
    arggrammar['l3_vlan_name'] = '-type str'
    arggrammar['l3_vlan_shutdown'] = '-type bool -default False'
    
    ns = utils.parserutils_lib.argsToCommandOptions(args,arggrammar,log)
    return ns
          
def configureVlans(hdl,dut,log,config_dict):
    
    ns = parseScaleVlanParms(log,config_dict)
    log.info('The value of ns here is : {0}'.format(ns))   
    cfg = 'feature vn-segment-vlan-based \n'
    if ns.no_of_l3_vlans and ns.no_of_l2_vlans:
        for i in mychain(((ns.l2_vlan_start,ns.no_of_l2_vlans,ns.l2_vni_start),(ns.l3_vlan_start,ns.no_of_l3_vlans,ns.l3_vni_start))):
            cfg = i
            cfg += 'exit \n'
            hdl.configure(cfg)
    elif ns.no_of_l2_vlans:
        log.info('Inside the ELIF block')
        if ns.l2_vni_start:
            for i,j in enumerate(range(ns.l2_vlan_start,ns.no_of_l2_vlans+ns.l2_vlan_start)):
                vni = ns.l2_vni_start + i
                cfg = '''vlan {0}
                         no vn-segment
                         vn-segment {1}
                         exit'''.format(j,vni)
                hdl.configure(cfg)
        else:
            for i in range(ns.l2_vlan_start,ns.no_of_l2_vlans+ns.l2_vlan_start):
                cfg = '''vlan {0}
                      exit'''.format(i)
                hdl.configure(cfg)
    return 1

def parseScaleVRFParams(log,args):
    log.info('Inside the parseScaleVRFParams function()')
    log.info('Inside parseScaleVRFParams.. the value of args is : {0}'.format(args))
    arggrammar = {}
    arggrammar['no_of_vrf'] = '-type int'
    arggrammar['vrf_start'] = '-type str'
    arggrammar['vrf_vni_start'] = '-type int '
    arggrammar['rd'] = '-type str'
    arggrammar['v4_af'] = '-type bool'
    arggrammar['v4_af_rt_both'] = '-type str'
    arggrammar['v4_af_rt_both_evpn'] = '-type str'
    arggrammar['v6_af'] = '-type bool'
    arggrammar['v6_af_rt_both'] = '-type str'
    arggrammar['v6_af_rt_both_evpn'] = '-type str'
    ns = utils.parserutils_lib.argsToCommandOptions(args,arggrammar,log)
    return ns

def configureVRFs(hdl,dut,log,config_dict):
    ns = parseScaleVRFParams(log,config_dict)
    for i in range(0,ns.no_of_vrf):
        cfg = ''
        if hasattr (ns,'vrf_start') and ns.vrf_start:
            cfg = 'vrf context {0}'.format(ns.vrf_start.split('-')[0])+ '-' + "{:03d}".format(int(ns.vrf_start.split('-')[-1])+i) + '\n'
        if ns.vrf_vni_start:
            cfg += 'vni' + ' ' + str(ns.vrf_vni_start+i) + '\n'
        if hasattr (ns,'rd') and ns.rd:
            cfg += 'rd '+ ns.rd + '\n'
        if hasattr (ns,'v4_af') and ns.v4_af:
            cfg += 'address-family ipv4 unicast' + '\n'
        if hasattr (ns,'v4_af_rt_both') and ns.v4_af_rt_both:
            cfg += 'route-target both ' + ns.v4_af_rt_both + '\n'
        if hasattr (ns,'v4_af_rt_both_evpn') and ns.v4_af_rt_both_evpn:
            cfg += 'route-target both ' + ns.v4_af_rt_both_evpn + ' evpn' + '\n' 
        if hasattr (ns,'v6_af') and ns.v6_af:
            cfg += 'address-family ipv6 unicast' + '\n'
        if hasattr (ns,'v6_af_rt_both') and ns.v6_af_rt_both:
            cfg += 'route-target both ' + ns.v6_af_rt_both + '\n'
        if hasattr (ns,'v6_af_rt_both_evpn') and ns.v6_af_rt_both_evpn:
            cfg += 'route-target both ' + ns.v6_af_rt_both_evpn + ' evpn' + '\n'      
        hdl.configure(cfg)    
    return 1        


def parseScaleEVPNConfigs(log,args):
    log.info('Inside the parseScaleEVPNConfigs function()')
    log.info('Inside parseScaleEVPNConfigs.. the value of args is : {0}'.format(args))
    arggrammar = {}
    arggrammar['no_of_vnis'] = '-type int'
    arggrammar['l2_vni_start'] = '-type int'
    arggrammar['rd'] = '-type str'
    arggrammar['route_target_import_list'] = '-type str'
    arggrammar['route_target_export_list'] = '-type str' 
    
    ns = utils.parserutils_lib.argsToCommandOptions(args,arggrammar,log)
    return ns

def generateEvpnDict(log,config_dict,vtep_dict):
    evpn_config_dict = {}
    for dut in vtep_dict:
        evpn_config_dict[dut] = {}
        args = config_dict[dut]['evpn']
        ns = parseScaleEVPNConfigs(log,args)
        log.info('The value of ns is : {0}'.format(ns))
        for i in range(0,ns.no_of_vnis):
            if not isEmpty(evpn_config_dict[dut]):
                evpn_config_dict[dut]['vni'] = {}
            v = ns.l2_vni_start + i
            evpn_config_dict[dut]['vni'][v]={}
            evpn_config_dict[dut]['vni'][v]['layer']='l2'
            evpn_config_dict[dut]['vni'][v]['rd'] = ns.rd
            evpn_config_dict[dut]['vni'][v]['route_target_import_list'] = ns.route_target_import_list
            evpn_config_dict[dut]['vni'][v]['route_target_export_list'] =   ns.route_target_export_list
            a = " ".join(['-{} {}'.format(k, v) for k,v in evpn_config_dict[dut]['vni'][v].items()])
            evpn_config_dict[dut]['vni'][v] = a
        
    return evpn_config_dict

                
def parseNVEParams(logs,args):
    log.info('Inside the parseNVEParams function()')
    log.info('Inside parseNVEParams.. the value of args is : {0}'.format(args))
    arggrammar = {}
    arggrammar['host_reachability_protocol_bgp'] = '-type bool'
    arggrammar['shutdown'] = '-type bool -default no shut'
    arggrammar['advertise_virtual_rmac'] = '-type bool'
    arggrammar['source_interface'] = '-type str'
    arggrammar['anycast'] = '-type str'
    arggrammar['source_interface_hold_down_time'] = '-type int'
    arggrammar['no_of_l2_vni'] = '-type int'
    arggrammar['l2_vni_start'] = '-type int'
    arggrammar['evpn_ir'] = '-type bool'
    arggrammar['no_of_l3_vni'] = '-type int'
    arggrammar['l3_vni_start'] = '-type int'        
    ns = utils.parserutils_lib.argsToCommandOptions(args,arggrammar,log)
    return ns

def configureNveGlobal(dut,hdl,config_dict,log):
    ns = parseNVEParams(log,config_dict)
    log.info(banner('The value of ns is : {0}'.format(ns)))
    cfg = 'feature nv overlay' + '\n'
    hdl.configure(cfg)
    cfg = ''
    if hasattr(ns,'host_reachability_protocol_bgp') and ns.host_reachability_protocol_bgp:
        cfg += '''interface nve1
                  no shutdown
                  host-reachability protocol bgp''' + '\n'
    if hasattr(ns, 'shutdown') and ns.shutdown:
        cfg += 'shutdown' + '\n'
    if hasattr(ns, 'advertise_virtual_rmac') and ns.advertise_virtual_rmac:
        cfg += 'advertise virtual-rmac' + '\n'
    if hasattr(ns, 'source_interface_hold_down_time') and ns.source_interface_hold_down_time:
        cfg += 'source-interface hold-down-time {0}'.format(ns.source_interface_hold_down_time) + '\n'
    if hasattr(ns, 'source_interface') and hasattr(ns, 'anycast') and ns.anycast:
            cfg += 'source-interface {0} anycast {1}'.format(ns.source_interface,ns.anycast) + '\n'
    if not ns.anycast:
            cfg += 'source-interface {0}'.format(ns.source_interface) + '\n'
    hdl.configure(cfg)
    
    return 1
    

def configureL2VNIOnNve(dut,hdl,config_dict,log):
    ns = parseNVEParams(log,config_dict)
    log.info(banner('The value of ns is : {0}'.format(ns)))
    for i in range(ns.no_of_l2_vni):
        if hasattr(ns, 'evpn_ir') and ns.evpn_ir:
            cfg = '''interface nve 1
                      member vni {0}
                      ingress-replication protocol bgp'''.format(ns.l2_vni_start+i) + '\n'

        elif hasattr(ns,'static_ir') and ns.static_ir:
            cfg = '''interface nve1
                     member vni {0}
                     ingress-replication protocol static
                     peer-ip {1}'''.format(ns.l2_vni_start+i,ns.peer_ip) + '\n'
        elif hasattr(ns,'evpn_mcast') and ns.evpn_mcast:
            if hasattr(ns, 'l2_vni_mcast') and ns.l2_vni_mcast:
                mcast_grp_list = ipaddrgen(ns.no_of_l2_vni, ns.l2_vni_mcast, ns.l2_vni_mcast_mask)
                cfg = '''interface nve1
                         member vni {0}
                         mcast-group {1}'''.format(int(ns.l2_vni_start+i),mcast_grp_list[i])
        hdl.configure(cfg)
        
    return 1
        
def configureL3VNIOnNve(dut,hdl,config_dict,log):
    ns = parseNVEParams(log,config_dict)
    log.info(banner('The value of ns is : {0}'.format(ns)))
    for i in range(ns.no_of_l3_vni):
        if hasattr(ns, 'evpn_ir') and ns.evpn_ir:
            cfg = '''interface nve 1
                      member vni {0} associate-vrf'''.format(ns.l3_vni_start+i) + '\n'
        hdl.configure(cfg)
    return 1
        

def parseGlobalVxlanConfigs(log,args):
    arggrammar = {}
    arggrammar['anycast_gateway_mac'] = '-type str'
    ns = utils.parserutils_lib.argsToCommandOptions(args,arggrammar,log)
    return ns 

def configureGlobalVxlanParams(dut,hdl,config_dict,log):
    ns = parseGlobalVxlanConfigs(log,config_dict) 
    cfg = ''
    if hasattr(ns, 'anycast_gateway_mac') and ns.anycast_gateway_mac:
        cfg += 'fabric forwarding anycast-gateway-mac 0000.1234.5678'   
    hdl.configure(cfg)
    return 1


def parseGlobalBGPconfigs(log, args):
    arggrammar = {}
    arggrammar['no_of_vrf'] = '-type int'
    arggrammar['vrf_start'] = '-type str'
    arggrammar['af_v4_enable'] = '-type str'
    arggrammar['af_v6_enable'] = '-type str'
    arggrammar['advertise_l2vpn_evpn'] = '-type bool'
    arggrammar['max_path_ebgp'] = '-type int'
    arggrammar['max_path_ibgp'] = '-type int'
    ns = utils.parserutils_lib.argsToCommandOptions(args,arggrammar,log)
    return ns 
    
def configureGlobalBGPParams(dut,hdl,config_dict,log,as_no):
    ns = parseGlobalBGPconfigs(log,config_dict)

    if hasattr(ns,'vrf_start') and ns.vrf_start:
        vrf_name_list = generateVRFlist(ns.vrf_start,ns.no_of_vrf)
        log.info('the value of vrf_name_list is : {0}'.format(vrf_name_list))
    for i in range(0,ns.no_of_vrf):
        cfg = ''
        cfg += '''router bgp {0}
                  vrf {1}'''.format(as_no,vrf_name_list[i]) + '\n'
        if hasattr(ns, 'af_v4_enable') and ns.af_v4_enable:
            cfg += 'address-family ipv4 unicast' + '\n'
            if hasattr(ns, 'advertise_l2vpn_evpn') and ns.advertise_l2vpn_evpn:
                cfg += 'advertise l2vpn evpn' + '\n'
                if hasattr(ns, 'max_path_ebgp') and ns.max_path_ebgp:
                    cfg += 'maximum-paths {0}'.format(ns.max_path_ebgp) + '\n'
                if hasattr(ns, 'max_path_ibgp') and ns.max_path_ibgp:
                     cfg += 'maximum-paths ibgp {0}'.format(ns.max_path_ebgp) + '\n'
        if hasattr(ns, 'af_v6_enable') and ns.af_v6_enable:
            cfg += 'address-family ipv6 unicast' + '\n'
            if hasattr(ns, 'advertise_l2vpn_evpn') and ns.advertise_l2vpn_evpn:
                cfg += 'advertise l2vpn evpn' + '\n'
                if hasattr(ns, 'max_path_ebgp') and ns.max_path_ebgp:
                    cfg += 'maximum-paths {0}'.format(ns.max_path_ebgp) + '\n'
                if hasattr(ns, 'max_path_ibgp') and ns.max_path_ibgp:
                     cfg += 'maximum-paths ibgp {0}'.format(ns.max_path_ebgp) + '\n'  
        hdl.configure(cfg)
    
    return 1   

        


def parseScaleTGParams(log,args):
    arggrammar = {}
    arggrammar['no_of_intf'] = '-type int'
    arggrammar['no_of_vlans'] = '-type int'
    arggrammar['vlan_start'] = '-type int'
    arggrammar['ip_addr_start'] = '-type str'
    arggrammar['netmask'] = '-type str'
    arggrammar['ip_addr_step'] = '-type str'
    arggrammar['ipv4_network_step'] = '-type str'
    arggrammar['gateway'] = '-type str'
    arggrammar['mode'] = '-type str'
    arggrammar['vlan'] = '-type int'
    ns = utils.parserutils_lib.argsToCommandOptions(args,arggrammar,log)
    return ns


def generateTrafficGenIntfConfigs(log,args):
    intf_list = []
    count = 1
    ns = parseScaleTGParams(log,args)
    no_of_intf_per_vlan = ns.no_of_intf / ns.no_of_vlans
    print('The value of no_of_intf_per_vlan is : {0}'.format(no_of_intf_per_vlan))
    ip_addr = ipaddress.IPv4Address(ns.ip_addr_start)
    gw = ipaddress.IPv4Address(ns.gateway)
    v = ns.vlan_start
    ip_addr_step = '0.0.0.1'
    gw_addr_step = '0.0.0.0'
    vlan_step = 0
    for i in range(0,ns.no_of_intf):
        if(count <= int(no_of_intf_per_vlan)): 
            if(count == 1):
                a = "".join('-mode {0} -connected_count {1} -intf_ip_addr {2} -intf_ip_addr_step {3} -netmask {4} -gateway {5} -gateway_step {6} -vlan {7} -vlan_id {8} -vlan_id_step {9}'.format(ns.mode,int(no_of_intf_per_vlan),ip_addr,ip_addr_step,ns.netmask,gw,gw_addr_step,ns.vlan,v,vlan_step))
                intf_list.append(a)
            ip_addr = ipaddress.IPv4Address(ip_addr) + int(ipaddress.IPv4Address(ns.ip_addr_step))
            count = count+1
        if(count > no_of_intf_per_vlan):
            ns.ip_addr_start = ipaddress.IPv4Address(ns.ip_addr_start)+int(ipaddress.IPv4Address(ns.ipv4_network_step))
            ip_addr = ns.ip_addr_start
            gw = ipaddress.IPv4Address(gw) + int(ipaddress.IPv4Address(ns.ipv4_network_step))
            v = v + 1
            count = 1
            
    return intf_list



def verifyVNIStatus(log,config_dict,node_dict):
    log.info(banner('The value of config_dict is {0}'.format(config_dict)))   
    log.info(banner('The value of node_dict is {0}'.format(node_dict)))     
    for dut in node_dict:
        hdl=node_dict[dut]
        cfg = 'show nve vni | json'
        out = hdl.execute(cfg)
        json_out = json.loads(out)
        output_parse = json_out['TABLE_nve_vni']['ROW_nve_vni']
        d={}
        for items in output_parse:
            log.info('The value of items is : {0}'.format(items))
            if re.search('L2', items['type']):
                d.setdefault('L2',{})
                d['L2'][items['vni']] = items['vni-state']
            if re.search('L3',items['type']):
                d.setdefault('L3',{})
                d['L3'][items['vni']] = items['vni-state']
        log.info('The Value of VNI_status_dict is {0}'.format(d))
        args = config_dict['scale_config_dict'][dut]['global']['vlan']
        ns = parseScaleVlanParms(log, args)
        log.info('No.of L2 VNIs to be configured  is : {0}'.format(ns.no_of_l2_vlans))
        if not len(d['L2'].keys()) == ns.no_of_l2_vlans:
            log.info('One or more L2 VNI is not configured... Kindly check...The VNIs configured are {0}'.format(list(d.keys())))
            return 0
        if not len(d['L3'].keys()) == ns.no_of_l3_vlans:
            log.info('One or more L2 VNI is not configured... Kindly check...The VNIs configured are {0}'.format(list(d.keys())))
            return 0        
        flag = True
        for k,v in d['L2'].items():
            log.info('The value of k is {0} and value of v is : {1}'.format(k,v))
            if not re.search('Up',v):
                log.info(banner('The following L2 VNis are not up {0}'.format(k)))
                flag = False
        for k,v in d['L3'].items():
            log.info('The value of k is {0} and value of v is : {1}'.format(k,v))
            if not re.search('Up',v):
                log.info(banner('The following L3 VNis are not up {0}'.format(k)))
                flag = False
        if not flag:
            return 0
        if flag:
            return 1
        
def verifyNVEStatus(log,config_dict,node_dict):
    log.info(banner('The value of node_dict is {0}'.format(node_dict)))
    for dut in node_dict:
        ns = parseNVEParams(log,config_dict['scale_config_dict'][dut]['interface']['nve'])
        hdl=node_dict[dut]
        cfg = 'show nve peers | json'
        out =hdl.execute(cfg)
        json_out = json.loads(out)
        peer_state = json_out['TABLE_nve_peers']['ROW_nve_peers']['peer-state']
        if not re.search('Up',peer_state):
            log.info('The Nve Peer {0} is not up. state is {0}',format(ns.peer_ip,peer_state))
            return 0
    
    return 1


def parseChangeVlanStateTrigger(log,args):
    arggrammar = {}
    arggrammar['no_of_vlans_to_shut'] = '-type int'
    arggrammar['vlan_start'] = '-type int'
    ns = utils.parserutils_lib.argsToCommandOptions(args,arggrammar,log)
    return ns

def displayConnectedLinksAndAliases(args):
    pat = 'Interface\s([a-z]{3}\d\/\d+\/?\d?)\s\(alias=(\w+)'
    pass
        

class CommonSetup(aetest.CommonSetup):
    

    '''
    Setup :
        **********

    '''
    
    uid = 'common_setup'
    @aetest.subsection
    def initialize_logging(self, testscript):
        """ Common setup section to initialize logging for script"""

        log = logging.getLogger(__name__)
        log.setLevel(logging.DEBUG)
        testscript.parameters['log'] = log


    @aetest.subsection
    def check_topology(self, testbed, testscript,log,traffic_threshold='', tgn_connect = '', **kwargs):
        """ common setup subsection: connecting devices """

        testscript.parameters['traffic_threshold'] = traffic_threshold
        testscript.parameters['tgn_connect'] = tgn_connect
        
        log.info(banner('The value of tgn_connect is : {0}'.format(tgn_connect)))   
        log.info(banner('The value of kwargs is : {0}'.format(kwargs)))
        testscript.parameters['config_interface'] = kwargs['config_interface']
        testscript.parameters['config_ospf'] = kwargs['config_ospf']
        testscript.parameters['config_ospfv3'] = kwargs['config_ospfv3']
        testscript.parameters['config_bgp'] = kwargs['config_bgp']
        testscript.parameters['config_vpc'] = kwargs['config_vpc']
        testscript.parameters['config_vxlan_global'] = kwargs['config_vxlan_global']
        testscript.parameters['config_bgp_global'] = kwargs['config_bgp_global']
        testscript.parameters['config_vlan'] = kwargs['config_vlan']
        testscript.parameters['config_vrf'] = kwargs['config_vrf']
        testscript.parameters['config_svi'] = kwargs['config_svi']
        testscript.parameters['config_evpn'] = kwargs['config_evpn']
        testscript.parameters['config_nve_global'] = kwargs['config_nve_global'] 
        testscript.parameters['config_nve_l2vni'] = kwargs['config_nve_l2vni']
        testscript.parameters['config_nve_l3vni'] = kwargs['config_nve_l3vni']
        testscript.parameters['config_tgn_conn'] = kwargs['config_tgn_conn']
        testscript.parameters['config_tgn_interface'] = kwargs['config_tgn_interface']
        
                                 
        parser = argparse.ArgumentParser()
        parser.add_argument('--config-file',dest='config_file',type=str)
        args = parser.parse_args()
        config_file = args.config_file
        fp = open(config_file)
        configdict=yaml.safe_load(fp)
        fp.close()        
        fail_result=0
        log.info('Getting testbed objects from the testbed file')
        testbed_obj = testbed

        # Way to get password and login from Testbed file
        passw = testbed_obj.passwords['tacacs']
        login = testbed_obj.tacacs['username']

        log.info(banner('The Devices in Testbed File are : \n {0}'.format("\n".join(list(testbed_obj.devices.keys())))))

        duts = list(filter(lambda x: 'TG' not in x, list(testbed_obj.devices.aliases)))
        TGs = list(filter(lambda x: 'uut' not in x , list (testbed_obj.devices.aliases)))

        log.info('{0} are the available duts in the testbed'.format(duts))
        log.info('{0} are the available TGs in the testbed'.format(TGs))   
                
        duts.sort()
        TGs.sort()

        # As per Testbed File following links are present.
        
        alias_intf_mapping = {}
        for dut in list(testbed_obj.devices.keys()):
            a = testbed_obj.devices[dut].alias
            log.info(banner('the value of a is : {0}'.format(a)))
            alias_intf_mapping[a] = {}
            if 'ixia' not in dut:
                log.info(banner('DUT is {0}'.format(dut)))
            else:
                log.info(banner('TRAFFIC GENERATOR is: {0}'.format(dut)))
            intf = [x for x in testbed_obj.devices[dut].interfaces.keys()]
            alias = [testbed_obj.devices[dut].interfaces[x].alias for x in testbed_obj.devices[dut].interfaces.keys()]
            res = list(zip(intf,alias))
            alias_intf_mapping.update(dict(zip(alias,intf)))
            alias_intf_mapping[a].update(dict(zip(alias,intf)))
            alias_intf_mapping.setdefault('all_intf',{})
            alias_intf_mapping['all_intf'].update(dict(zip(alias,intf)))
            log.info(banner('The interfaces and alias are \n {0}'.format("\n".join(["->".join(x) for x in res]))))

        # Way to take variable to other section
        testscript.parameters['testbed_obj'] = testbed_obj
        testscript.parameters['configdict'] = configdict
        testscript.parameters['fail_result'] = fail_result
        testscript.parameters['alias_intf_mapping'] = alias_intf_mapping
       
    @aetest.subsection
    def configBringUp(self,testscript,log,steps):
        
        testbed_obj = testscript.parameters['testbed_obj']

        # DUTs required to test this feature 
        dutList_config_file = list(testscript.parameters['configdict']['dut'].keys())
        log.info('{0} are the duts required for VxlanV6 tests'.format(dutList_config_file))
        
        # TGNs required for this CFD
        TGList_config_file = list(testscript.parameters['configdict']['TG'].keys())
        log.info('{0} are the TGNs required for VxlanV6 tests'.format(TGList_config_file))
        
        # Create obj for each node from config file
        dutList_obj_config_file = []
        for dut_config_file in dutList_config_file:
            dutList_obj_config_file.append(testscript.parameters['testbed_obj'].devices[dut_config_file])
            
        # declaring vtep list
        node_dict = {}
    
        for node in list(testbed_obj.devices.keys()):
            log.info('The Value of node is : {0}'.format(node))
            log.info('The value of node.type is : {0}'.format(testbed_obj.devices[node].type))
            if re.search('VPC',testbed_obj.devices[node].type):
                node_dict.setdefault('vpc_vteps',{})
                node_dict.setdefault('all_vteps',{})
                node_dict['vpc_vteps'][testbed_obj.devices[node].alias] = testbed_obj.devices[node]
                node_dict['all_vteps'][testbed_obj.devices[node].alias] = testbed_obj.devices[node]
            elif re.search('STAND',testbed_obj.devices[node].type):
                node_dict.setdefault('stand_vteps',{})
                node_dict.setdefault('all_vteps',{})
                node_dict['stand_vteps'][testbed_obj.devices[node].alias] = testbed_obj.devices[node]
                node_dict['all_vteps'][testbed_obj.devices[node].alias] = testbed_obj.devices[node]
            elif re.search('SPINE',testbed_obj.devices[node].type):
                node_dict.setdefault('spines',{})
                node_dict['spines'][testbed_obj.devices[node].alias] = testbed_obj.devices[node]
            elif re.search('L2',testbed_obj.devices[node].type):
                node_dict.setdefault('l2_switch',{})
                node_dict['l2_switch'][testbed_obj.devices[node].alias] = testbed_obj.devices[node]
            elif re.search('ixia',testbed_obj.devices[node].type):
                node_dict.setdefault('trf_gen',{})
                node_dict['trf_gen'][testbed_obj.devices[node].alias] = testbed_obj.devices[node]
            node_dict.setdefault('all_dut',{})
            node_dict['all_dut'][testbed_obj.devices[node].alias] = testbed_obj.devices[node]
            

        log.info(banner('Value of Node dict is : {0}'.format(node_dict)))  
                
        for dut in node_dict['all_dut']:
            if not re.search(r'TG',dut,re.I):
                node_dict['all_dut'][dut].connect()
        
        testscript.parameters['node_dict'] = node_dict
        testscript.parameters['TGList'] = TGList_config_file
                            
    @aetest.subsection
    def configureInterfaces(self,testscript,log):
        
        config_interface = testscript.parameters['config_interface']
        
        if config_interface:
            #interface config dict 
            config_dict = testscript.parameters['configdict']
            node_dict = testscript.parameters['node_dict']
            testbed_obj = testscript.parameters['testbed_obj']
            
            intf_config_dict = testscript.parameters['configdict']['interface_config_dict']
    
            log.info(banner('The value of interface_config_dict is {0} '.format(intf_config_dict)))
            
            log.info(banner('The value of node_dict is {0} '.format(node_dict)))
            
            #intf_obj = config_bringup.configSetup(config_dict,testbed_obj,log,[x for x in node_dict['all_dut'].keys() if not re.search(r'TG',x,re.I)])
            intf_obj = config_bringup_test_vijay.configSetup(config_dict,testbed_obj,log)

            
            if not intf_obj:
                self.failed()
        else:
            pass


    @aetest.subsection
    def configureUnderlayOSPF(self,testscript,log):

        config_ospf = testscript.parameters['config_ospf']
        if config_ospf:
            #ospf_config_dict
            ospf_config_dict = testscript.parameters['configdict']['ospfv2_config_dict']
            node_dict = testscript.parameters['node_dict']
            
            obj_ospf=ospfv2_lib.configOspfv2(node_dict['all_dut'],ospf_config_dict,log)
            
            if not obj_ospf:
                self.failed()
        else:
            pass

    @aetest.subsection
    def configureUnderlayOSPFv3(self,testscript,log):
        
        config_ospfv3 = testscript.parameters['config_ospfv3']
        
        if config_ospfv3:
            #ospf_config_dict
            ospfv3_config_dict = testscript.parameters['configdict']['ospfv3_config_dict']
            node_dict = testscript.parameters['node_dict']
            
            obj_ospf=ospfv3_lib.configOspfv3(node_dict['all_dut'],ospfv3_config_dict,log)
            
            if not obj_ospf:
                self.failed()
        else:
            pass
            

    @aetest.subsection       
    def configureBGPNeighbors(self,testscript,log):

        config_bgp = testscript.parameters['config_bgp']
        
        if config_bgp:
        
            #BGP_config_dict 
            bgp_config_dict = testscript.parameters['configdict']['bgp_config_dict']
    
            node_dict = testscript.parameters['node_dict']
            
            for dut in bgp_config_dict.keys():
                obj_bgp=bgp_lib.configBgp(bgp_config_dict,node_dict['all_dut'],log)
                if not obj_bgp.Nodes(dut):
                    self.failed()
        else:
            pass
    
    @aetest.subsection       
    def configureVPCParams(self,testscript,log):
        
        config_vpc = testscript.parameters['config_vpc']
        
        if config_vpc:
            node_dict = testscript.parameters['node_dict']
            config_dict = testscript.parameters['configdict']
            
            for dut in node_dict['vpc_vteps'].keys():
                hdl = node_dict['vpc_vteps'][dut]
                d = config_bringup.setupConfigVpc(hdl,dut,log,config_dict)
        else:
            pass
    

    @aetest.subsection                     
    def configureGlobalVxlan(self,testscript,log):    
        
        config_vxlan_global = testscript.parameters['config_vxlan_global'] 
        
        if config_vxlan_global:
            #SCALE_Config_dict
            scale_config_dict = testscript.parameters['configdict']['scale_config_dict']
            
            node_dict = testscript.parameters['node_dict']
    
            res = {k : v for k,v in node_dict.items() if 'vtep' in k}
            
            vtep_dict = {}
            for k, v in res.items():
                vtep_dict.update(v)
                
            log.info(banner('The value of vtep_dict is : {0}'.format(vtep_dict))) 
    
            hdl_list = []
            configdict_list = []
            dut_list = []
            log_list = []
    
            for dut in vtep_dict:
                hdl_list.append(vtep_dict[dut])
                dut_list.append(vtep_dict.keys())
                log_list.append(log)
                configdict_list.append(scale_config_dict[dut]['global']['vxlan'])
            
            res = pcall(configureGlobalVxlanParams,dut=dut_list,hdl=hdl_list,config_dict=configdict_list,log=log_list)
            
            if not res:
                self.failed()
        else:
            pass

    @aetest.subsection                     
    def configureGlobalBGP(self,testscript,log):    
        
        config_bgp_global = testscript.parameters['config_bgp_global'] 
        
        if config_bgp_global:
            #SCALE_Config_dict
            scale_config_dict = testscript.parameters['configdict']['scale_config_dict']
            
            node_dict = testscript.parameters['node_dict']
    
            res = {k : v for k,v in node_dict.items() if 'vtep' in k}
            
            vtep_dict = {}
            for k, v in res.items():
                vtep_dict.update(v)
                
            log.info(banner('The value of vtep_dict is : {0}'.format(vtep_dict))) 
            
            
            
            for dut in vtep_dict:
                for s in list(testscript.parameters['configdict']['bgp_config_dict'][dut].keys()):
                    as_no = s
                    log.info('The value of as Number is : {0}'.format(as_no))
                config_dict = scale_config_dict[dut]['global']['bgp']
                res = configureGlobalBGPParams(dut,vtep_dict[dut],config_dict,log,as_no)
            
            if not res:
                self.failed()
        else:
            pass


    @aetest.subsection       
    def configureScaleVlan(self,testscript,log):
        
        config_vlan = testscript.parameters['config_vlan']
        
        if config_vlan:
            #SCALE_Config_dict
            scale_config_dict = testscript.parameters['configdict']['scale_config_dict']
            
            node_dict = testscript.parameters['node_dict']
            
            res = {k : v for k,v in node_dict.items() if k in ('vpc_vteps','l2_switch','stand_vteps')}
            
            dut_dict = {}
            for k, v in res.items():
                dut_dict.update(v)
                
            log.info(banner('The value of dut_dict is : {0}'.format(dut_dict)))
    
            hdl_list = []
            configdict_list = []
            dut_list = []
            log_list = []
            
            for dut in dut_dict:
                hdl_list.append(dut_dict[dut])
                dut_list.append(dut_dict.keys())
                log_list.append(log)
                configdict_list.append(scale_config_dict[dut]['global']['vlan'])
                
            res = pcall(configureVlans,hdl=hdl_list,dut = dut_list,log=log_list,config_dict=configdict_list)
    
            if not res:
                self.failed()
        else:
            pass
    
    @aetest.subsection  
    def configureScaleVRF(self,testscript,log):
        
        config_vrf = testscript.parameters['config_vrf']
        
        if config_vrf:

            #SCALE_Config_dict
            scale_config_dict = testscript.parameters['configdict']['scale_config_dict']
            
            node_dict = testscript.parameters['node_dict']
    
            res = {k : v for k,v in node_dict.items() if 'vtep' in k}
            
            vtep_dict = {}
            for k, v in res.items():
                vtep_dict.update(v)
                
            log.info(banner('The value of vtep_dict is : {0}'.format(vtep_dict)))
            
            
    
            hdl_list = []
            configdict_list = []
            dut_list = []
            log_list = []
    
            for dut in vtep_dict:
                hdl_list.append(vtep_dict[dut])
                dut_list.append(vtep_dict.keys())
                log_list.append(log)
                configdict_list.append(scale_config_dict[dut]['global']['vrf'])
    
            res = pcall(configureVRFs,hdl=hdl_list,dut = dut_list,log=log_list,config_dict=configdict_list)
            
            if not res:
                self.failed()
        else:
            pass

    @aetest.subsection       
    def configureScaleSVI(self,testscript,log):            
        
        config_svi = testscript.parameters['config_svi']
        
        if config_svi:

            #SCALE_Config_dict
            scale_config_dict = testscript.parameters['configdict']['scale_config_dict']
            
            node_dict = testscript.parameters['node_dict']
    
            res = {k : v for k,v in node_dict.items() if 'vtep' in k}
            
            vtep_dict = {}
            for k, v in res.items():
                vtep_dict.update(v)
                
            log.info(banner('The value of vtep_dict is : {0}'.format(vtep_dict)))
    
            hdl_list = []
            configdict_list = []
            dut_list = []
            log_list = []
    
            for dut in vtep_dict:
                hdl_list.append(vtep_dict[dut])
                dut_list.append(vtep_dict.keys())
                log_list.append(log)
                configdict_list.append(scale_config_dict[dut]['interface']['svi'])
    
            res = pcall(configureSVIs,hdl=hdl_list,dut = dut_list,log=log_list,config_dict=configdict_list)
            
            if not res:
                self.failed()
         
        else:
            pass
    
    @aetest.subsection                     
    def configureScaleEvpn(self,testscript,log):  
        
        config_evpn = testscript.parameters['config_evpn']
        
        if config_evpn:
    
            #SCALE_Config_dict
            scale_config_dict = testscript.parameters['configdict']['scale_config_dict']
            
            node_dict = testscript.parameters['node_dict']
    
            res = {k : v for k,v in node_dict.items() if 'vtep' in k}
            
            vtep_dict = {}
            for k, v in res.items():
                vtep_dict.update(v)
                
            log.info(banner('The value of vtep_dict is : {0}'.format(vtep_dict)))
    
            hdl_list = []
            configdict_list = []
            dut_list = []
            log_list = []
    
            evpn_config_dict = generateEvpnDict(log,scale_config_dict,vtep_dict)
            
            
            for dut in vtep_dict:
                hdl_list.append(vtep_dict[dut])
                dut_list.append(vtep_dict.keys())
                log_list.append(log)
                configdict_list.append(evpn_config_dict[dut])
            
            res = pcall(evpn_lib.configEvpn,dut=dut_list,hdl=hdl_list,config_dict=configdict_list,log=log_list)
            
        else:
            pass
    
    @aetest.subsection                     
    def configureNveInterfaceGlobals(self,testscript,log):  
        
        config_nve_global = testscript.parameters['config_nve_global']   
        
        if config_nve_global:
            
            #SCALE_Config_dict
            scale_config_dict = testscript.parameters['configdict']['scale_config_dict']
            
            node_dict = testscript.parameters['node_dict']
    
            res = {k : v for k,v in node_dict.items() if 'vtep' in k}
            
            vtep_dict = {}
            for k, v in res.items():
                vtep_dict.update(v)
                
            log.info(banner('The value of vtep_dict is : {0}'.format(vtep_dict)))
    
            hdl_list = []
            configdict_list = []
            dut_list = []
            log_list = []
            
            for dut in vtep_dict:
                hdl_list.append(vtep_dict[dut])
                dut_list.append(vtep_dict.keys())
                log_list.append(log)
                configdict_list.append(scale_config_dict[dut]['interface']['nve'])
            
            res = pcall(configureNveGlobal,dut=dut_list,hdl=hdl_list,config_dict=configdict_list,log=log_list)
            
            if not res:
                self.failed()
                
        else:
            pass

    @aetest.subsection                     
    def configureL2VNIOnNveInterface(self,testscript,log):     
        
        config_nve_l2vni = testscript.parameters['config_nve_l2vni']
        
        if config_nve_l2vni:
        
            #SCALE_Config_dict
            scale_config_dict = testscript.parameters['configdict']['scale_config_dict']
            
            node_dict = testscript.parameters['node_dict']
    
            res = {k : v for k,v in node_dict.items() if 'vtep' in k}
            
            vtep_dict = {}
            for k, v in res.items():
                vtep_dict.update(v)
                
            log.info(banner('The value of vtep_dict is : {0}'.format(vtep_dict)))
    
            hdl_list = []
            configdict_list = []
            dut_list = []
            log_list = []
            
            for dut in vtep_dict:
                hdl_list.append(vtep_dict[dut])
                dut_list.append(vtep_dict.keys())
                log_list.append(log)
                configdict_list.append(scale_config_dict[dut]['interface']['nve'])
            
            res = pcall(configureL2VNIOnNve,dut=dut_list,hdl=hdl_list,config_dict=configdict_list,log=log_list)
    
            if not res:
                self.failed()
        else:
            pass
    
    @aetest.subsection                     
    def configureL3VNIOnNveInterface(self,testscript,log):     
        
        config_nve_l3vni = testscript.parameters['config_nve_l3vni']
        
        if config_nve_l3vni:
    
            #SCALE_Config_dict
            scale_config_dict = testscript.parameters['configdict']['scale_config_dict']
            
            node_dict = testscript.parameters['node_dict']
    
            res = {k : v for k,v in node_dict.items() if 'vtep' in k}
            
            vtep_dict = {}
            for k, v in res.items():
                vtep_dict.update(v)
                
            log.info(banner('The value of vtep_dict is : {0}'.format(vtep_dict)))
    
            hdl_list = []
            configdict_list = []
            dut_list = []
            log_list = []
            
            for dut in vtep_dict:
                hdl_list.append(vtep_dict[dut])
                dut_list.append(vtep_dict.keys())
                log_list.append(log)
                configdict_list.append(scale_config_dict[dut]['interface']['nve'])
            
            res = pcall(configureL3VNIOnNve,dut=dut_list,hdl=hdl_list,config_dict=configdict_list,log=log_list)
    
            if not res:
                self.failed()
        else:
            pass

    
    @aetest.subsection                     
    def connectionToTrafficGenerator(self,testscript,log): 


        config_tgn_conn =  testscript.parameters['config_tgn_conn']
        
        if config_tgn_conn:
            # Connect and confiure TG
    
            log.info('Connecting and configuring TG as per config dict...')
            # Get physical interface from logical interface of config file for TG
             
            config_dict = testscript.parameters['configdict']
            testbed_obj = testscript.parameters['testbed_obj']
     
            TGList_config_file = testscript.parameters['TGList']
            ix_port_list = []
            ix_port_list_alias = []
            tgn_port_dut_mapping={}
            for TG in TGList_config_file:
                d = testscript.parameters['testbed_obj'].devices[TG]
                log.info('The value of d is : {0}'.format(d))
                TGIntList = testscript.parameters['configdict']['TG'][TG]['global']['ports'].keys()
                for port in TGIntList:
                    a = d.interfaces[port].alias
                    b = re.search('(uut[\d]+)',a)
                    if b:
                        dut = b.group(1)
                        tgn_port_dut_mapping[port] = dut
                
                
                for TGInt in TGIntList:
                    log.info('The value of TGint is : {0}'.format(TGInt))
                    ix_port_list.append(d.interfaces[TGInt].name)
                    ix_port_list_alias.append(d.interfaces[TGInt].alias)
                    # Connect to TG
                ix_port_list.sort(key=lambda x: '{0:0>8}'.format(x).lower())
                log.info('The value of ix_port_list is : {0}'.format(ix_port_list))
                log.info('The value of ix_port_list_alias is : {0}'.format(ix_port_list_alias))
                ixia_connect = connectToIxNetwork(self, tg_hdl = d, port_list = ix_port_list)
                     
                # Get port handles
                port_handle_list = []
                for port_handle in ixia_connect['vport_list'].split():
                    port_handle_list.append(port_handle)
                 
                port_handle_list.sort(key=lambda x: '{0:0>8}'.format(x).lower())
                 
                port_handle_dict = dict(zip(ix_port_list,port_handle_list))
                log.info("Port handles are {0}".format(port_handle_list))
                log.info('The Value of port_handle_dict is: {0}'.format(port_handle_dict))
                testscript.parameters['port_handle_dict'] = port_handle_dict
                log.info('The value of tgn_port_dut_mapping is : {0}'.format(tgn_port_dut_mapping))
                testscript.parameters['tgn_port_dut_mapping'] = tgn_port_dut_mapping

        
    @aetest.subsection      
    def configuringInterfacesOnTrafficGenerator(self,testscript,log):
        
        config_tgn_interface = testscript.parameters['config_tgn_interface']

        if config_tgn_interface:
            tg_interface_hdl_dict = {}
            port_handle_dict = testscript.parameters['port_handle_dict']
     
                #interface_handle_list = []
            TGList_config_file = testscript.parameters['TGList']
            for TG in TGList_config_file:
                tg_interface_hdl_dict[TG] = {}
                d = testscript.parameters['testbed_obj'].devices[TG]
                traffic_item_skip_list = expandTrafficItemList(testscript.parameters['configdict']['TG'][TG]['skip_traffic_items'])
                log.info('The value of traffic_item_skip_list is : {0}'.format(traffic_item_skip_list))       
                configured_stream  = []
                skipped_stream = []     
                for trf_stream in testscript.parameters['configdict']['TG'][TG]:
                    if(re.search('TRF',trf_stream)):
                        if trf_stream not in traffic_item_skip_list:
                            configured_stream.append(trf_stream)
                            tg_interface_hdl_dict[TG][trf_stream] = {}
                            TGIntList = testscript.parameters['configdict']['TG'][TG][trf_stream]['tg_interface_config_dict'].keys()
                            for TGInt in TGIntList:
                                log.info('The value of TGInt is : {0}'.format(TGInt))
                                ixia_intf_ip_list=[]
                                tg_interface_hdl_dict[TG][trf_stream][TGInt] = {}
                                intf_args = generateTrafficGenIntfConfigs(log,testscript.parameters['configdict']['TG'][TG][trf_stream]['tg_interface_config_dict'][TGInt]) 
                                log.info('The value of intf_args is : {0}'.format(intf_args))
                                for j,k  in enumerate(intf_args):
                                    a = intf_args[j]
                                    ixia_interface_config = configureMultiIxNetworkInterface(self,a,tg_hdl=d,port_handle=port_handle_dict[TGInt])
                                    log.info('the value of ixia_interface_config is : {0}'.format(ixia_interface_config))
                                    for b in ixia_interface_config:
                                        ixia_intf_ip_list.append(b)
                                        tg_interface_hdl_dict[TG][trf_stream][TGInt][b]={}
                                        tg_interface_hdl_dict[TG][trf_stream][TGInt][b]['handle']=ixia_interface_config[b]
                                    tg_interface_hdl_dict[TG][trf_stream][TGInt]['ip_list']=ixia_intf_ip_list
                        else:
                            skipped_stream.append(trf_stream)

                    elif(re.search('RAW',trf_stream)):
                        if trf_stream not in traffic_item_skip_list:
                            configured_stream.append(trf_stream)
                        else:
                            skipped_stream.append(trf_stream)
            
            log.info(banner('The following traffic stream  %s is skipped from configuring ... ' % skipped_stream))
                        
            c = yaml.dump(tg_interface_hdl_dict)
            log.info('The value of a is : {0}'.format(c))
            testscript.parameters['tg_interface_hdl_dict'] = tg_interface_hdl_dict
            testscript.parameters['configured_stream'] = configured_stream
            log.info(banner('The value of configured_stream is : {0}'.format(configured_stream)))

    @aetest.subsection                     
    def verifyConfiguationsBeforeStartOfTest(self,testscript,log,steps):
        
        config_dict = testscript.parameters['configdict']
        node_dict = testscript.parameters['node_dict']
        alias_intf_mapping = testscript.parameters['alias_intf_mapping']
        
        scale_config_obj = MyLib.my_config_utils.ScaleConfig(log,node_dict,config_dict,alias_intf_mapping)
        vtep_dict = scale_config_obj.getDeviceDict('all_vtep')
        
        verify_obj = MyLib.my_config_utils.VerifyConfigs(log,config_dict,node_dict,alias_intf_mapping)
        
        with steps.start('Verify OSPFv2 Neighborship on all duts') as s:
            log.info('Verifying the OSPFv2 Neighborship on all duts ......')
            res = verify_obj.verifyOSPFv4Neighorship()
            if not res:
                self.failed()

#         with steps.start('Verify OSPFv3 Neighborship on all duts') as s:
#             log.info('Verifying the OSPFv3 Neighborship on all duts ......')
#             res = verifyOSPFv6Neighorship(log,cfg_dict['ospfv3_config_dict'],node_dict,alias_intf_mapping_dict)
#             
#             if not res:
#                 self.failed()

        with steps.start('Verify BGP L2EVPN Neighborship on all duts') as s:
            log.info('Verify BGP L2EVPN Neighborship on all duts ......')
            res = verify_obj.verifyBGPL2EVPNNeighbor()
            if not res:
                self.failed()

        with steps.start('Verify BGP mVPN Neighborship on all duts') as s:
            log.info('Verify BGP mVPN Neighborship on all duts ......')
            res = verify_obj.verifyBGPL2MVPNNeighbor()
            if not res:
                self.failed()
                        
        with steps.start('Verify L2 and L3 VNI Status on all VTEPS') as s:
            log.info('Verifying L2 and L3 VNI status on all VTEPs ......')
            res = verify_obj.verifyVNIStatus(vtep_dict)
            if not res:
                self.failed()

#         with steps.start('Verify Nve Peers in VTEPs') as s:
#             log.info('VVerify Nve Peers in VTEPs ......')
#             res = verify_obj.verifyNVEStatus(vtep_dict)
#             if not res:
#                 self.failed()  
        
        log.info(banner('Waiting for 30 seconds before Configuring the Traffic ... {0}'.format(countDownTimer(30))))
            
    @aetest.subsection     
    def configureTrafficStreams(self,testscript,log):
        
#         '''
        tg_interface_hdl_dict = testscript.parameters['tg_interface_hdl_dict'] 
        log.info('the value of tg_interface_hdl_dict is : {0}'.format(tg_interface_hdl_dict))
        configured_stream = testscript.parameters['configured_stream']
        
        log.info(banner('The value of configured_stream is : {0}'.format(configured_stream)))
        port_handle_dict = testscript.parameters['port_handle_dict']
        log.info('the value of port_handle_dict is : {0}'.format(port_handle_dict))
         
        TGList_config_file = testscript.parameters['TGList']
         
        traffic_stream_dict = {}
        for TG in TGList_config_file:
            d = testscript.parameters['testbed_obj'].devices[TG]
            for trf_stream in testscript.parameters['configdict']['TG'][TG]:
                log.info(banner('The value of trf_stream is : {0}'.format(trf_stream)))
                if(re.search('TRF',trf_stream)):
                    if trf_stream in configured_stream:
                        TGIgmpIntList = testscript.parameters['configdict']['TG'][TG][trf_stream]['traffic_config_dict'].keys()
                        src_handle = []
                        dest_handle = []
                        traffic_stream_dict[trf_stream] = {}
                        source_port = testscript.parameters['configdict']['TG'][TG][trf_stream]['traffic_config_dict']['source']
                        receiver_port = testscript.parameters['configdict']['TG'][TG][trf_stream]['traffic_config_dict']['receivers']
                        traffic_args=testscript.parameters['configdict']['TG'][TG][trf_stream]['traffic_config_dict']['params']
                        if isinstance(source_port, list):
                            for i in source_port:
                                log.info('src: The value of i is : {0}'.format(i))
                                for port in tg_interface_hdl_dict[TG][trf_stream]:
                                    log.info('src: The value of port is : {0}'.format(port))
                                    if(port == i):
                                        pat = re.compile("^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$")
                                        for ip in tg_interface_hdl_dict[TG][trf_stream][port]:
                                            test=pat.match(ip)
                                            if test:
                                                log.info('src: The value of i is : {0}'.format(i))
                                                log.info('src: The value of port is : {0}'.format(port))
                                                log.info('src: The value of ip is : {0}'.format(ip))
                                                log.info('src: The value of trf_stream is : {0}'.format(trf_stream))
                                                handle = tg_interface_hdl_dict[TG][trf_stream][port][ip]['handle']
                                                src_handle.append(handle)
                     
                        if isinstance(receiver_port,list):
                            for i in receiver_port:
                                log.info('rcv:The value of i is : {0}'.format(i))
                                for port in tg_interface_hdl_dict[TG][trf_stream]:
                                    log.info('rcv: The value of port is : {0}'.format(port))
                                    if(port == i):
                                        pat = re.compile("^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$")
                                        for ip in tg_interface_hdl_dict[TG][trf_stream][port]:
                                            test=pat.match(ip)
                                            if test:
                                                log.info('rcv: The value of i is : {0}'.format(i))
                                                log.info('rcv: The value of port is : {0}'.format(port))
                                                log.info('rcv: The value of ip is : {0}'.format(ip))
                                                log.info('rcv: The value of trf_stream is : {0}'.format(trf_stream))
                                                handle = tg_interface_hdl_dict[TG][trf_stream][port][ip]['handle']
                                                dest_handle.append(handle)
                        traffic_stream_dict[trf_stream]['source'] = source_port
                        traffic_stream_dict[trf_stream]['destination'] = receiver_port
                     
                        log.info('The value of src_handle is : {0}'.format(src_handle))
                        log.info('The value of dest_handle is : {0}'.format(dest_handle))
                         
                        ixia_traffic_config = configureIxNetworkTraffic(self, traffic_args, tg_hdl=d, emulation_src_handle=src_handle, emulation_dst_handle=dest_handle)
                        log.info('The value of ixia_traffic_config is : {0}'.format(ixia_traffic_config))
                    
                        traffic_stream_dict[trf_stream]['stream_id'] = ixia_traffic_config.stream_id
                        traffic_stream_dict[trf_stream]['traffic_item'] = ixia_traffic_config.traffic_item
                        traffic_stream_dict[trf_stream]['status'] = ixia_traffic_config.status
                        
                elif(re.search('RAW',trf_stream)):
                    log.info(banner('Inside RAW Stream Configuration : '))
                    if trf_stream in configured_stream:
                        TGIgmpIntList = testscript.parameters['configdict']['TG'][TG][trf_stream]['traffic_config_dict'].keys()
                        traffic_stream_dict[trf_stream] = {}
                        source_port = testscript.parameters['configdict']['TG'][TG][trf_stream]['traffic_config_dict']['source']
                        receiver_port = testscript.parameters['configdict']['TG'][TG][trf_stream]['traffic_config_dict']['receivers']
                        traffic_args=testscript.parameters['configdict']['TG'][TG][trf_stream]['traffic_config_dict']['params']

                        traffic_stream_dict[trf_stream]['source'] = source_port
                        traffic_stream_dict[trf_stream]['destination'] = receiver_port
                         
                        src_port = [port_handle_dict[x] for x in source_port]
                        dst_port = [port_handle_dict[x] for x in receiver_port]
                        log.info('The value of src_port is : {0}'.format(src_port))
                        log.info('The value of dst_port is : {0}'.format(dst_port))
                        
                        ixia_traffic_config = configureIxNetworkRawTrafficL2(self, traffic_args, tg_hdl=d, emulation_src_handle=src_port, emulation_dst_handle=dst_port)
                        log.info('The value of ixia_traffic_config is : {0}'.format(ixia_traffic_config))
                    
                        traffic_stream_dict[trf_stream]['stream_id'] = ixia_traffic_config.stream_id
                        traffic_stream_dict[trf_stream]['traffic_item'] = ixia_traffic_config.traffic_item
                        traffic_stream_dict[trf_stream]['status'] = ixia_traffic_config.status
                    
 
        log.info('The value of traffic_stream_dict is : {0}'.format(traffic_stream_dict))
        testscript.parameters['traffic_stream_dict']  = traffic_stream_dict 
        
        
#     @aetest.subsection     
#     def startAllTrafficStreams(self,testscript,log):  
#    
#         tg_interface_hdl_dict = testscript.parameters['tg_interface_hdl_dict'] 
#         traffic_stream_dict = testscript.parameters['traffic_stream_dict'] 
#         port_handle_dict = testscript.parameters['port_handle_dict']
#         TGList_config_file = testscript.parameters['TGList']
#         configdict = testscript.parameters['configdict'] 
#         tgn_config_dict = configdict['TG']
#         threshold = testscript.parameters['traffic_threshold'] 
#            
#         for TG in tgn_config_dict.keys():
#             log.info('The value of TG is = %r', TG)
#             tgn_hdl = testscript.parameters['testbed_obj'].devices[TG]
#             flag = 1
#             failed_traffic_stream_stats = {}
#             for trf_stream in traffic_stream_dict:
#                 if traffic_stream_dict[trf_stream]['status']:
#                     stream_handle = traffic_stream_dict[trf_stream]['traffic_item']
#                     x = tgn_hdl.traffic_control(action='run', handle = stream_handle)
#                     log.info('The Value of x is : {0}'.format(x))
#                     if not x.status:
#                         self.failed()
#                      
#                     stream_id =  traffic_stream_dict[trf_stream]['stream_id'] 
#                     source = traffic_stream_dict[trf_stream]['source']
#                     receiver = traffic_stream_dict[trf_stream]['destination']
#                     sender_port = []
#                     receiver_port = []
#                     if isinstance(source, list):
#                         for i in  source:
#                             sender_port.append(port_handle_dict[i])
#                     if isinstance(receiver, list):
#                         for i in receiver:
#                             receiver_port.append(port_handle_dict[i])
#                     log.info('The value of source Port is : {0}'.format(sender_port))
#                     log.info('The value of rcv Port is : {0}'.format(receiver_port))
#                     countDownTimer(10)
#                     stats = tgn_hdl.traffic_stats(stream = stream_id, mode = 'traffic_item')
#                     log.info('the value of stats is : {0}'.format(stats))
#                     tx_stat = stats.traffic_item[stream_id]['tx'].total_pkt_rate
#                     log.info('The value of tx_stat is: {0}'.format(tx_stat))
#                     rx_stat = stats.traffic_item[stream_id]['rx'].total_pkt_rate
#                     log.info('The value of rx_stat is: {0}'.format(rx_stat))
#                     if abs(rx_stat-tx_stat) <=threshold:
#                         log.info('The traffic test on stream {0} is pass as expected ...'.format(trf_stream))
#                     else:
#                         log.info('The traffic pass criteria on stream {0} does not mactch as  expected ...'.format(trf_stream))
#                         total_tx = {}
#                         total_rx = {}
#                         stat_breakup = tgn_hdl.traffic_stats(stream = stream_id, mode = 'streams')
#                         for i in stat_breakup:
#                             if i in sender_port:
#                                 log.info('sender_port: The value of is : {0}'.format(i))
#                                 tx = stat_breakup[i]['stream'][stream_id]['tx']['total_pkt_rate']
#                                 total_tx[i] = tx
#                             if i in receiver_port:
#                                 log.info('rcv_port: The value of is : {0}'.format(i))
#                                 rx = stat_breakup[i]['stream'][stream_id]['rx']['total_pkt_rate']
#                                 total_rx[i] = rx
#                         log.info('The value of total_tx is : {0}'.format(total_tx))
#                         log.info('The value of total_rx is : {0}'.format(total_rx))
#                         flag = 0
#                         failed_traffic_stream_stats[trf_stream] = {}
#                         failed_traffic_stream_stats[trf_stream]['tx'] = total_tx
#                         failed_traffic_stream_stats[trf_stream]['rx'] = total_rx
#             if flag:
#                 log.info('Traffic test on all streams are okay !!!')
#                 return 1
#             if not flag:
#                 log.info('Pass Criteria on some streams did not pass. !!!')
#                 self.failed()
#                 return failed_traffic_stream_stats




# 2883:  Starting subsection startAllTrafficStreams
# 2884:  +------------------------------------------------------------------------------+
# 2885:  |    The value of traffic_stream_dict is : {'TRF002': {'source': ['1/7'], '    |
# 2886:  |    stream_id': 'TI0-VRF-V6-002', 'traffic_item': '::ixNet::OBJ-/traffic/t    |
# 2887:  |    rafficItem:1/configElement:1', 'destination': ['1/2', '1/4', '1/5'], '    |
# 2888:  |    status': 1}, 'TRF001': {'source': ['1/7'], 'stream_id': 'TI1-VRF-V6-00    |
# 2889:  |    1', 'traffic_item': '::ixNet::OBJ-/traffic/trafficItem:2/configElement    |
# 2890:  |           :1', 'destination': ['1/2', '1/4', '1/5'], 'status': 1}}           |
# 2891:  +------------------------------------------------------------------------------+
# 2892:  The value of TG is = 'TG1'
# 2893:  Calling: ixia::traffic_control -handle ::ixNet::OBJ-/traffic/trafficItem:1/configElement:1 -action run
# 2894:  The Value of x is : KeyedList({'stopped': 1, 'status': 1})
# 2895:  Calling: ixia::traffic_control -handle ::ixNet::OBJ-/traffic/trafficItem:2/configElement:1 -action run
# 2896:  The Value of x is : KeyedList({'stopped': 0, 'status': 1})
# 2897:  The result of subsection startAllTrafficStreams is => PASSED



    @aetest.subsection     
    def startAllTrafficStreams(self,testscript,log):  
   
        tg_interface_hdl_dict = testscript.parameters['tg_interface_hdl_dict'] 
        traffic_stream_dict = testscript.parameters['traffic_stream_dict'] 
        port_handle_dict = testscript.parameters['port_handle_dict']
        TGList_config_file = testscript.parameters['TGList']
        configdict = testscript.parameters['configdict'] 
        tgn_config_dict = configdict['TG']
        threshold = testscript.parameters['traffic_threshold'] 
        
        log.info(banner('The value of traffic_stream_dict is : {0}'.format(traffic_stream_dict)))
           
        unstarted_stream = []
        for TG in tgn_config_dict.keys():
            log.info('The value of TG is = %r', TG)
            tgn_hdl = testscript.parameters['testbed_obj'].devices[TG]
            flag = 1
            failed_traffic_stream_stats = {}
            for trf_stream in traffic_stream_dict:
                if traffic_stream_dict[trf_stream]['status']:
                    stream_handle = traffic_stream_dict[trf_stream]['traffic_item']
                    x = tgn_hdl.traffic_control(action='run', handle = stream_handle, max_wait_timer=60)
                    stream_id = traffic_stream_dict[trf_stream]['stream_id']
                    if not x.status:
                        log.error(banner('The Stream {0} could not be started as expected '.format(stream_id)))
                        unstarted_stream.append(stream_id)
                        
        if unstarted_stream:
            log.error(banner('The Following Strams could not be started..{0}'.format(unstarted_stream)))
            self.failed()

    @aetest.subsection     
    def checkAllTrafficStreamsStats(self,testscript,log):  
   
        tg_interface_hdl_dict = testscript.parameters['tg_interface_hdl_dict'] 
        traffic_stream_dict = testscript.parameters['traffic_stream_dict'] 
        port_handle_dict = testscript.parameters['port_handle_dict']
        TGList_config_file = testscript.parameters['TGList']
        configdict = testscript.parameters['configdict'] 
        tgn_config_dict = configdict['TG']
        threshold = testscript.parameters['traffic_threshold'] 
        
        log.info(banner('The value of traffic_stream_dict is : {0}'.format(traffic_stream_dict)))
           
        failed_stream_list = []
        for TG in tgn_config_dict.keys():
            log.info('The value of TG is = %r', TG)
            tgn_hdl = testscript.parameters['testbed_obj'].devices[TG]
            for trf_stream in traffic_stream_dict:
                if traffic_stream_dict[trf_stream]['status']:
                    stream_handle = traffic_stream_dict[trf_stream]['traffic_item']
                    countDownTimer(20)
                    x = tgn_hdl.traffic_control(action='clear_stats', handle = stream_handle, max_wait_timer=80)
                    stream_id = traffic_stream_dict[trf_stream]['stream_id']
                    countDownTimer(20)
                    y = tgn_hdl.traffic_stats(stream=stream_id,mode='traffic_item')
                    log.info(banner('The value of y is : {0}'.format(y)))
                    for i in y['traffic_item']:
                        if i == stream_id:
                            loss_percent= y['traffic_item'][i]['rx']['loss_percent']
                            log.info(banner('The value of loss_percent is : {0}'.format(loss_percent)))
                            if loss_percent > 1.0:
                                failed_stream_list.append(stream_id)
               
        
        if failed_stream_list:
            log.error(banner('The Initial Traffic Pass Criteria is not met for the following streams..{0}'.format(failed_stream_list)))
            self.failed()
            
    @aetest.subsection     
    def initializeFewThingsForTest(self,testscript,log):
        node_dict = testscript.parameters['node_dict']
        configdict = testscript.parameters['configdict']
        traffic_stream_dict = testscript.parameters['traffic_stream_dict']
        port_handle_dict = testscript.parameters['port_handle_dict']
        threshold = testscript.parameters['traffic_threshold']
        alias_intf_mapping = testscript.parameters['alias_intf_mapping']
        configured_stream = testscript.parameters['configured_stream']
        
        
        trigger_obj = MyLib.my_utils.TriggerItems(log,node_dict,configdict,traffic_stream_dict,port_handle_dict,threshold,alias_intf_mapping,configured_stream)
        testscript.parameters['trigger_obj'] = trigger_obj
        
        
class VXLANVxlanV6FUNC001(aetest.Testcase):

    """ Verify CLI To Configure Ingress Replication """

    uid = 'VXLAN-L3-VxlanV6-FUNC-001'
    
    @aetest.test
    def verifyIRConfigCli(self,log,testscript,testbed):
        
        node_dict = testscript.parameters['node_dict']
        tg_interface_hdl_dict = testscript.parameters['tg_interface_hdl_dict'] 
        traffic_stream_dict = testscript.parameters['traffic_stream_dict'] 
        port_handle_dict = testscript.parameters['port_handle_dict']
        TGList_config_file = testscript.parameters['TGList']
        configdict = testscript.parameters['configdict'] 
        tgn_config_dict = configdict['TG']
        threshold = testscript.parameters['traffic_threshold'] 
        tgn_port_dut_mapping = testscript.parameters['tgn_port_dut_mapping']
        alias_intf_mapping_dict = testscript.parameters['alias_intf_mapping']
        configured_stream = testscript.parameters['configured_stream']
        trigger_obj = testscript.parameters['trigger_obj']
        
        log.info(banner('The value of configured stream is : {0}'.format(configured_stream))) 
        
        res = trigger_obj.getDeviceDict('all_vtep')
#        res = MyLib.my_utils.TriggerItems(log,node_dict,configdict).getDeviceDict('all_vtep')

        login = [node_dict['all_dut'][dut].execute('show version') for dut in node_dict['all_dut'] if re.search('uut', dut)]
        
        for TG in tgn_config_dict.keys():
            tgn_hdl = testscript.parameters['testbed_obj'].devices[TG]
            out = trigger_obj.checkAllStreamStats(tgn_hdl)

            if out:
                l2Vni_config_on_nve = trigger_obj.configUnconfigL2VNIOnNVE(mode='UnConfig')
                countDownTimer(50)
                l2Vni_config_on_nve = trigger_obj.configUnconfigL2VNIOnNVE(mode='Config')
        
                for dut in res:
                    hdl = res[dut]
                    cfg = 'sh nve vni | grep L2 | wc'
                    cfg1 = 'sh run int nve 1 | grep "ingress-repli" | wc'
                    out = hdl.execute(cfg)
                    out1 = hdl.execute(cfg1)
                    ns = MyLib.my_utils.parseScaleVlanParms(log,configdict['scale_config_dict'][dut]['global']['vlan'])
                    if not out == ns.no_of_l2_vlans and out1 == ns.no_of_l2_vlans:
                        log.error(banner('The Member VNI config / Ingress Replication Config failed...\
                                          The Number of member VNI is {0} and No. of Ingress replication config is {1}'.format(out,out1)))
                        self.failed()
                
                countDownTimer(300)
                
                new_out = trigger_obj.checkAllStreamStats(tgn_hdl)
                if not new_out:
                    log.error(banner('Traffic did not recover after the trigger... Kindly check'))
                    self.failed()

class VXLANVxlanV6FUNC002(aetest.Testcase):

    """ Verify Show Commands for Ingress Replication """

    uid = 'VXLAN-L3-VxlanV6-FUNC-002'
    
    @aetest.test
    def verifyShowCommandsforIR(self,log,testscript,testbed):
        
        node_dict = testscript.parameters['node_dict']
        tg_interface_hdl_dict = testscript.parameters['tg_interface_hdl_dict'] 
        traffic_stream_dict = testscript.parameters['traffic_stream_dict'] 
        port_handle_dict = testscript.parameters['port_handle_dict']
        TGList_config_file = testscript.parameters['TGList']
        configdict = testscript.parameters['configdict'] 
        tgn_config_dict = configdict['TG']
        threshold = testscript.parameters['traffic_threshold'] 
        tgn_port_dut_mapping = testscript.parameters['tgn_port_dut_mapping']
        alias_intf_mapping_dict = testscript.parameters['alias_intf_mapping']
        configured_stream = testscript.parameters['configured_stream']
        trigger_obj = testscript.parameters['trigger_obj']
        
        log.info(banner('The value of configured stream is : {0}'.format(configured_stream))) 
        
        traffic_to_consider = 'TRF001-TRF025'
        traffic_item_list = expandTrafficItemList(traffic_to_consider)
        
        
        res = trigger_obj.getDeviceDict('all_vtep')
#        res = MyLib.my_utils.TriggerItems(log,node_dict,configdict).getDeviceDict('all_vtep')

        login = [node_dict['all_dut'][dut].execute('show version') for dut in node_dict['all_dut'] if re.search('uut', dut)]
        
        for TG in tgn_config_dict.keys():
            tgn_hdl = testscript.parameters['testbed_obj'].devices[TG]
            out = trigger_obj.checkAllStreamStats(tgn_hdl)
            
            if out:   
                pat  = re.compile(r'\s+(\d+)\s+(\d+)\s+(\d+)')
                for dut in res:
                    hdl = res[dut]
                    cfg = ' sh nve vni ingress-replication interface nve 1 | grep nve | wc'
                    no_of_ir = hdl.execute(cfg)
                    regex_match = pat.search(no_of_ir)
                    log.info(banner('The value of regex_match is  {0}'.format(regex_match)))
                    ns = parseNVEParams(log,configdict['scale_config_dict'][dut]['interface']['nve'])
                    log.info(banner('The value of ns is : {0}'.format(ns)))
                    log.info(banner('The value of no_of_l2_vni is {0}'.format(ns.no_of_l2_vni)))
                    log.info(banner('The value of regex_match is {0}'.format(regex_match.group(1))))
                    if not int(regex_match.group(1)) == int(ns.no_of_l2_vni):
                        log.info(banner('The no. of l2 member vni on dut {1} does it match as expected. Conigured value is {0}'.format(regex_match.group(1),dut)))
                        self.failed()


class VXLANVxlanV6FUNC003(aetest.Testcase):

    """ BUM TRAFFIC - INGRESS ON ACCESS PORT """

    uid = 'VXLAN-L3-VxlanV6-FUNC-003'
    
    @aetest.test
    def bumTrafficIngressOnAccessPort(self,log,testscript,testbed):
        
        node_dict = testscript.parameters['node_dict']
        tg_interface_hdl_dict = testscript.parameters['tg_interface_hdl_dict'] 
        traffic_stream_dict = testscript.parameters['traffic_stream_dict'] 
        port_handle_dict = testscript.parameters['port_handle_dict']
        TGList_config_file = testscript.parameters['TGList']
        configdict = testscript.parameters['configdict'] 
        tgn_config_dict = configdict['TG']
        threshold = testscript.parameters['traffic_threshold'] 
        tgn_port_dut_mapping = testscript.parameters['tgn_port_dut_mapping']
        alias_intf_mapping_dict = testscript.parameters['alias_intf_mapping']
        configured_stream = testscript.parameters['configured_stream']
        trigger_obj = testscript.parameters['trigger_obj']

        log.info(banner('The value of configured stream is : {0}'.format(configured_stream))) 
        
        login = [node_dict['all_dut'][dut].execute('show version') for dut in node_dict['all_dut'] if re.search('uut', dut)]
        
        trf = configdict['trigger_dict']['TEST-003']['traffic_to_consider']
        traffic_item_list = expandTrafficItemList(trf)
        
        log.info(banner('The value of traffic_item_list is : {0}'.format(traffic_item_list)))
        
        devices = configdict['trigger_dict']['TEST-003']['trigger_dut']
        dev_len  = len(devices)
        interfaces = configdict['trigger_dict']['TEST-003']['interfaces'].split()
        
        log.info('The value of interfaces is : {0}'.format(interfaces))
        
        trigger_type = 'access_port'
        
        for dut in devices:
            ns = parseScaleVlanParms(log, configdict['scale_config_dict'][dut]['global']['vlan'])
            break

        log.info(banner('The value of ns is : {0}'.format(ns)))
        
        for TG in tgn_config_dict.keys():
            tgn_hdl = testscript.parameters['testbed_obj'].devices[TG]
            out = trigger_obj.checkAllStreamStats(tgn_hdl)
        
            if out:
                for i in range(0,1):
                    vlan = random.randint(ns.l2_vlan_start,(ns.l2_vlan_start+ns.no_of_l2_vlans-1))
                    allowed_vlan = str(ns.l2_vlan_start) + '-' + str(ns.l2_vlan_start+ns.no_of_l2_vlans-1)
                    log.info(banner('Iteration {1} ... The Choosen Vlan is : {0}'.format(vlan,i)))
#                     for j in devices:
#                         hdl = node_dict['all_dut'][j]
#                         for intf in interfaces:
#                             if j in intf:
#                                 res = trigger_obj.changeInterfaceSwitchPortMode(hdl,intf,vlan,mode='access')

                    res = [trigger_obj.changeInterfaceSwitchPortMode(node_dict['all_dut'][x],intf,vlan,mode='access') for x in devices for intf in interfaces if x in intf]
                    countDownTimer(150)
                    new_out = trigger_obj.checkAllRawStreamStatsTrigger(tgn_hdl,dev_len,trigger_type,ns.no_of_l2_vlans)
                    if not new_out['status']:
                        log.error(banner('The following stream {1} has failed in Vlan {1} '.format(vlan,new_out['streams'])))
                        res = [trigger_obj.changeInterfaceSwitchPortMode(node_dict['all_dut'][x],intf,allowed_vlan,mode='trunk') for x in devices for intf in interfaces]
                        self.failed()
                
                log.info(banner('The RAW Stream traffic stats are fine.. Reverting back the configs:'))
                res = [trigger_obj.changeInterfaceSwitchPortMode(node_dict['all_dut'][x],intf,allowed_vlan,mode='trunk') for x in devices for intf in interfaces]
                
                countDownTimer(150)
                log.info(banner('Checking Traffic stats on all the configured streams.:'))
                out = trigger_obj.checkAllStreamStats(tgn_hdl)
                if not out:
                    log.error(banner('Traffic has not recovered on some of the streams.. '))
                    self.failed()                    
            else:
                log.error('The Initial Traffic Condition did not pass :')
                self.failed()
                
class VXLANVxlanV6FUNC004(aetest.Testcase):

    """ BUM TRAFFIC - INGRESS ON TRUNK PORT ALLOWED VLAN : """

    uid = 'VXLAN-L3-VxlanV6-FUNC-004'
    
    @aetest.test
    def bumTrafficIngressOnTrunkPortWithAllowedVlan(self,log,testscript,testbed):
        
        node_dict = testscript.parameters['node_dict']
        tg_interface_hdl_dict = testscript.parameters['tg_interface_hdl_dict'] 
        traffic_stream_dict = testscript.parameters['traffic_stream_dict'] 
        port_handle_dict = testscript.parameters['port_handle_dict']
        TGList_config_file = testscript.parameters['TGList']
        configdict = testscript.parameters['configdict'] 
        tgn_config_dict = configdict['TG']
        threshold = testscript.parameters['traffic_threshold'] 
        tgn_port_dut_mapping = testscript.parameters['tgn_port_dut_mapping']
        alias_intf_mapping_dict = testscript.parameters['alias_intf_mapping']
        configured_stream = testscript.parameters['configured_stream']
        trigger_obj = testscript.parameters['trigger_obj']

        log.info(banner('The value of configured stream is : {0}'.format(configured_stream))) 
        
        login = [node_dict['all_dut'][dut].execute('show version') for dut in node_dict['all_dut'] if re.search('uut', dut)]
        
        trf = configdict['trigger_dict']['TEST-004']['traffic_to_consider']
        traffic_item_list = expandTrafficItemList(trf)
        
        log.info(banner('The value of traffic_item_list is : {0}'.format(traffic_item_list)))
        
        devices = configdict['trigger_dict']['TEST-004']['trigger_dut']
        dev_len  = len(devices)
        interfaces = configdict['trigger_dict']['TEST-004']['interfaces'].split()
        allowed_no_of_vlans = configdict['trigger_dict']['TEST-004']['no_of_vlans']
        
        trigger_type = 'trunk_port_allowed_vlan'
        
        for dut in devices:
            ns = parseScaleVlanParms(log, configdict['scale_config_dict'][dut]['global']['vlan'])
            break

        log.info(banner('The value of ns is : {0}'.format(ns)))
        
        for TG in tgn_config_dict.keys():
            tgn_hdl = testscript.parameters['testbed_obj'].devices[TG]
            out = trigger_obj.checkAllStreamStats(tgn_hdl)
            no_of_iterations = 1
            if out:
                for _ in range(0,no_of_iterations):
                    vlan = [random.randint(ns.l2_vlan_start,(ns.l2_vlan_start+ns.no_of_l2_vlans-1)) for _ in range(0, allowed_no_of_vlans)]
                    allowed_vlan = str(ns.l2_vlan_start) + '-' + str(ns.l2_vlan_start+ns.no_of_l2_vlans-1)
                    log.info(banner('The value of allowed_vlan_list is : {0}'.format(vlan)))
                    res = [trigger_obj.changeInterfaceSwitchPortMode(node_dict['all_dut'][x],intf,vlan,mode='trunk') for x in devices for intf in interfaces if x in intf]
                    countDownTimer(150)
                    new_out = trigger_obj.checkAllRawStreamStatsTrigger(tgn_hdl,dev_len,trigger_type,ns.no_of_l2_vlans,allowed_vlan=vlan)
                    if not new_out['status']:
                        log.error(banner('The following stream {1} has failed in Vlan {1} '.format(vlan,new_out['streams'])))
                        res = [trigger_obj.changeInterfaceSwitchPortMode(node_dict['all_dut'][x],intf,allowed_vlan,mode='trunk') for x in devices for intf in interfaces]
                        self.failed()
                    
                    log.info(banner('The RAW Stream traffic stats are fine.. Reverting back the configs:'))
                    res = [trigger_obj.changeInterfaceSwitchPortMode(node_dict['all_dut'][x],intf,allowed_vlan,mode='trunk') for x in devices for intf in interfaces]
                    
                    countDownTimer(150)
                    log.info(banner('Checking Traffic stats on all the configured streams.:'))
                    out = trigger_obj.checkAllStreamStats(tgn_hdl)
                    if not out:
                        log.error(banner('Traffic has not recovered on some of the streams.. '))
                        self.failed()                    
            else:
                log.error('The Initial Traffic Condition did not pass :')
                self.failed()
            
class VXLANVxlanV6FUNC005(aetest.Testcase):

    """ BUM TRAFFIC - INGRESS ON ACCESS VPC PORT """

    uid = 'VXLAN-L3-VxlanV6-FUNC-005'
    
    @aetest.test
    def bumTrafficOnIngressVPCPort(self,log,testscript,testbed):
        
        node_dict = testscript.parameters['node_dict']
        tg_interface_hdl_dict = testscript.parameters['tg_interface_hdl_dict'] 
        traffic_stream_dict = testscript.parameters['traffic_stream_dict'] 
        port_handle_dict = testscript.parameters['port_handle_dict']
        TGList_config_file = testscript.parameters['TGList']
        configdict = testscript.parameters['configdict'] 
        tgn_config_dict = configdict['TG']
        threshold = testscript.parameters['traffic_threshold'] 
        tgn_port_dut_mapping = testscript.parameters['tgn_port_dut_mapping']
        alias_intf_mapping_dict = testscript.parameters['alias_intf_mapping']
        configured_stream = testscript.parameters['configured_stream']
        trigger_obj = testscript.parameters['trigger_obj']

        log.info(banner('The value of configured stream is : {0}'.format(configured_stream))) 
        
        login = [node_dict['all_dut'][dut].execute('show version') for dut in node_dict['all_dut'] if re.search('uut', dut)]
        
        trf = configdict['trigger_dict']['TEST-005']['traffic_to_consider']
        traffic_item_list = expandTrafficItemList(trf)
        
        log.info(banner('The value of traffic_item_list is : {0}'.format(traffic_item_list)))
        
        devices = configdict['trigger_dict']['TEST-005']['trigger_dut']
        interfaces = list(configdict['interface_config_dict']['portchannel']['uut3'].keys())
        log.info('The value of len of interfaces is: {0}'.format(len(interfaces)))
        
        log.info(banner('the Value of interfaces is  {0} and type is : {1}'.format(interfaces,type(interfaces))))
        
        trigger_type = 'access_vpc_port'
        
        for dut in devices:
            ns = parseScaleVlanParms(log, configdict['scale_config_dict'][dut]['global']['vlan'])
            break

        log.info(banner('The value of ns is : {0}'.format(ns)))
        
        for TG in tgn_config_dict.keys():
            tgn_hdl = testscript.parameters['testbed_obj'].devices[TG]
            out = trigger_obj.checkAllStreamStats(tgn_hdl)
        
            if out:
                for i in range(0,1):
                    vlan = random.randint(ns.l2_vlan_start,(ns.l2_vlan_start+ns.no_of_l2_vlans-1))
                    allowed_vlan = str(ns.l2_vlan_start) + '-' + str(ns.l2_vlan_start+ns.no_of_l2_vlans-1)
                    log.info(banner('The Choosen Vlan is : {0}'.format(vlan)))
                    for j in devices:
                        hdl = node_dict['all_dut'][j]
                        res = trigger_obj.changeInterfaceSwitchPortMode(hdl,"".join(interfaces),vlan,mode='access')
                    countDownTimer(150)
                    new_out = trigger_obj.checkAllRawStreamStatsTrigger(tgn_hdl,len(interfaces),trigger_type,ns.no_of_l2_vlans)
                    if not new_out['status']:
                        log.error(banner('The following stream {1} has failed in Vlan {1} '.format(vlan,new_out['streams'])))
                        res = [trigger_obj.changeInterfaceSwitchPortMode(node_dict['all_dut'][x],"".join(interfaces),allowed_vlan,mode='trunk') for x in devices]
                        self.failed()
                
                log.info(banner('The RAW Stream traffic stats are fine.. Reverting back the configs:'))
                res = [trigger_obj.changeInterfaceSwitchPortMode(node_dict['all_dut'][x],"".join(interfaces),allowed_vlan,mode='trunk') for x in devices]
                
                countDownTimer(150)
                log.info(banner('Checking Traffic stats on all the configured streams.:'))
                out = trigger_obj.checkAllStreamStats(tgn_hdl)
                if not out:
                    log.error(banner('Traffic has not recovered on some of the streams.. '))
                    self.failed()                    
            else:
                log.error('The Initial Traffic Condition did not pass :')
                self.failed()


class VXLANVxlanV6FUNC006(aetest.Testcase):

    """ BUM TRAFFIC - INGRESS ON ACCESS VPC PORT WITH VPC LEG Primary DOWN """

    uid = 'VXLAN-L3-VxlanV6-FUNC-006'
    
    @aetest.test
    def bumTrafficOnIngressAccessVPCPortPrimaryVPCLegDown(self,log,testscript,testbed):
        
        node_dict = testscript.parameters['node_dict']
        tg_interface_hdl_dict = testscript.parameters['tg_interface_hdl_dict'] 
        traffic_stream_dict = testscript.parameters['traffic_stream_dict'] 
        port_handle_dict = testscript.parameters['port_handle_dict']
        TGList_config_file = testscript.parameters['TGList']
        configdict = testscript.parameters['configdict'] 
        tgn_config_dict = configdict['TG']
        threshold = testscript.parameters['traffic_threshold'] 
        tgn_port_dut_mapping = testscript.parameters['tgn_port_dut_mapping']
        alias_intf_mapping_dict = testscript.parameters['alias_intf_mapping']
        configured_stream = testscript.parameters['configured_stream']
        trigger_obj = testscript.parameters['trigger_obj']

        log.info(banner('The value of configured stream is : {0}'.format(configured_stream))) 
        
        login = [node_dict['all_dut'][dut].execute('show version') for dut in node_dict['all_dut'] if re.search('uut', dut)]
        
        trf = configdict['trigger_dict']['TEST-005']['traffic_to_consider']
        traffic_item_list = expandTrafficItemList(trf)
        
        log.info(banner('The value of traffic_item_list is : {0}'.format(traffic_item_list)))
        
        devices = configdict['trigger_dict']['TEST-005']['trigger_dut']
        interfaces = list(configdict['interface_config_dict']['portchannel']['uut3'].keys())
        log.info('The value of len of interfaces is: {0}'.format(len(interfaces)))
        
        log.info(banner('the Value of interfaces is  {0} and type is : {1}'.format(interfaces,type(interfaces))))
        
        trigger_type = 'access_vpc_port_shut'
        
        for dut in devices:
            ns = parseScaleVlanParms(log, configdict['scale_config_dict'][dut]['global']['vlan'])
            break

        log.info(banner('The value of ns is : {0}'.format(ns)))
        
        for TG in tgn_config_dict.keys():
            tgn_hdl = testscript.parameters['testbed_obj'].devices[TG]
            out = trigger_obj.checkAllStreamStats(tgn_hdl)
        
            if out:
                for i in range(0,1):
                    vlan = random.randint(ns.l2_vlan_start,ns.l2_vlan_start+ns.no_of_l2_vlans-1)
                    allowed_vlan = str(ns.l2_vlan_start) + '-' + str(ns.l2_vlan_start+ns.no_of_l2_vlans-1)
                    log.info(banner('Iteration {1} ... The Choosen Vlan is : {0}'.format(vlan,i)))
                    for j in devices:
                        hdl = node_dict['all_dut'][j]
                        res = trigger_obj.changeInterfaceSwitchPortMode(hdl,"".join(interfaces),vlan,mode='access')
                    vpc_primary_hdl = trigger_obj.getVPCSwitchhdl('primary')
                    cfg = '''interface {0}
                             shutdown'''.format(interfaces[0])
                    vpc_primary_hdl.configure(cfg)
                    countDownTimer(150)
                    new_out = trigger_obj.checkAllRawStreamStatsTrigger(tgn_hdl,len(interfaces),trigger_type,ns.no_of_l2_vlans)
                    if not new_out['status']:
                        log.error(banner('The following stream {1} has failed in Vlan {1} '.format(vlan,new_out['streams'])))
                        res = [trigger_obj.changeInterfaceSwitchPortMode(node_dict['all_dut'][x],"".join(interfaces),allowed_vlan,mode='trunk') for x in devices]
                        self.failed()
                    cfg1 = '''interface {0}
                              no shutdown'''.format(interfaces[0])
                    vpc_primary_hdl.configure(cfg1)
                    countDownTimer(150)
                    new_out1 = trigger_obj.checkAllRawStreamStatsTrigger(tgn_hdl,len(interfaces),trigger_type,ns.no_of_l2_vlans)
                    if not new_out1['status']:
                        log.error(banner('The following stream {1} has failed in Vlan {1} '.format(vlan,new_out['streams'])))
                        res = [trigger_obj.changeInterfaceSwitchPortMode(node_dict['all_dut'][x],"".join(interfaces),allowed_vlan,mode='trunk') for x in devices]
                        self.failed()
                log.info(banner('The RAW Stream traffic stats are fine.. Reverting back the configs:'))
                res = [trigger_obj.changeInterfaceSwitchPortMode(node_dict['all_dut'][x],interfaces[0],allowed_vlan,mode='trunk') for x in devices]
                
                countDownTimer(150)
                log.info(banner('Checking Traffic stats on all the configured streams.:'))
                out = trigger_obj.checkAllStreamStats(tgn_hdl)
                if not out:
                    log.error(banner('Traffic has not recovered on some of the streams.. '))
                    self.failed()                    
            else:
                log.error('The Initial Traffic Condition did not pass :')
                self.failed()
                                
                
class VXLANVxlanV6FUNC007(aetest.Testcase):

    """ BUM TRAFFIC - INGRESS ON ACCESS VPC PORT WITH VPC LEG Secondary DOWN """

    uid = 'VXLAN-L3-VxlanV6-FUNC-007'
    
    @aetest.test
    def bumTrafficOnIngressAccessVPCPortSecondaryVPCLegDown(self,log,testscript,testbed):
        
        node_dict = testscript.parameters['node_dict']
        tg_interface_hdl_dict = testscript.parameters['tg_interface_hdl_dict'] 
        traffic_stream_dict = testscript.parameters['traffic_stream_dict'] 
        port_handle_dict = testscript.parameters['port_handle_dict']
        TGList_config_file = testscript.parameters['TGList']
        configdict = testscript.parameters['configdict'] 
        tgn_config_dict = configdict['TG']
        threshold = testscript.parameters['traffic_threshold'] 
        tgn_port_dut_mapping = testscript.parameters['tgn_port_dut_mapping']
        alias_intf_mapping_dict = testscript.parameters['alias_intf_mapping']
        configured_stream = testscript.parameters['configured_stream']
        trigger_obj = testscript.parameters['trigger_obj']

        log.info(banner('The value of configured stream is : {0}'.format(configured_stream))) 
        
        login = [node_dict['all_dut'][dut].execute('show version') for dut in node_dict['all_dut'] if re.search('uut', dut)]
        
        trf = configdict['trigger_dict']['TEST-005']['traffic_to_consider']
        traffic_item_list = expandTrafficItemList(trf)
        
        log.info(banner('The value of traffic_item_list is : {0}'.format(traffic_item_list)))
        
        devices = configdict['trigger_dict']['TEST-005']['trigger_dut']
        interfaces = list(configdict['interface_config_dict']['portchannel']['uut3'].keys())
        log.info('The value of len of interfaces is: {0}'.format(len(interfaces)))
        
        log.info(banner('the Value of interfaces is  {0} and type is : {1}'.format(interfaces,type(interfaces))))
        
        trigger_type = 'access_vpc_port_shut'
        
        for dut in devices:
            ns = parseScaleVlanParms(log, configdict['scale_config_dict'][dut]['global']['vlan'])
            break

        log.info(banner('The value of ns is : {0}'.format(ns)))
        
        for TG in tgn_config_dict.keys():
            tgn_hdl = testscript.parameters['testbed_obj'].devices[TG]
            out = trigger_obj.checkAllStreamStats(tgn_hdl)
        
            if out:
                for i in range(0,1):
                    vlan = random.randint(ns.l2_vlan_start,ns.l2_vlan_start+ns.no_of_l2_vlans-1)
                    allowed_vlan = str(ns.l2_vlan_start) + '-' + str(ns.l2_vlan_start+ns.no_of_l2_vlans-1)
                    log.info(banner('Iteration {1} ... The Choosen Vlan is : {0}'.format(vlan,i)))
                    for j in devices:
                        hdl = node_dict['all_dut'][j]
                        res = trigger_obj.changeInterfaceSwitchPortMode(hdl,"".join(interfaces),vlan,mode='access')
                    vpc_secondary_hdl = trigger_obj.getVPCSwitchhdl('secondary')
                    cfg = '''interface {0}
                             shutdown'''.format(interfaces[0])
                    vpc_secondary_hdl.configure(cfg)
                    countDownTimer(150)
                    new_out = trigger_obj.checkAllRawStreamStatsTrigger(tgn_hdl,len(interfaces),trigger_type,ns.no_of_l2_vlans)
                    if not new_out['status']:
                        log.error(banner('The following stream {1} has failed in Vlan {1} '.format(vlan,new_out['streams'])))
                        res = [trigger_obj.changeInterfaceSwitchPortMode(node_dict['all_dut'][x],"".join(interfaces),allowed_vlan,mode='trunk') for x in devices]
                        self.failed()
                    cfg1 = '''interface {0}
                              no shutdown'''.format(interfaces[0])
                    vpc_secondary_hdl.configure(cfg1)
                    countDownTimer(150)
                    new_out1 = trigger_obj.checkAllRawStreamStatsTrigger(tgn_hdl,len(interfaces),trigger_type,ns.no_of_l2_vlans)
                    if not new_out1['status']:
                        log.error(banner('The following stream {1} has failed in Vlan {1} '.format(vlan,new_out['streams'])))
                        res = [trigger_obj.changeInterfaceSwitchPortMode(node_dict['all_dut'][x],"".join(interfaces),allowed_vlan,mode='trunk') for x in devices]
                        self.failed()
                log.info(banner('The RAW Stream traffic stats are fine.. Reverting back the configs:'))
                res = [trigger_obj.changeInterfaceSwitchPortMode(node_dict['all_dut'][x],interfaces[0],allowed_vlan,mode='trunk') for x in devices]
                
                countDownTimer(150)
                log.info(banner('Checking Traffic stats on all the configured streams.:'))
                out = trigger_obj.checkAllStreamStats(tgn_hdl)
                if not out:
                    log.error(banner('Traffic has not recovered on some of the streams.. '))
                    self.failed()                    
            else:
                log.error('The Initial Traffic Condition did not pass :')
                self.failed()
                
class VXLANVxlanV6FUNC008(aetest.Testcase):

    """ BUM TRAFFIC - INGRESS ON TRUNK VPC PORT """

    uid = 'VXLAN-L3-VxlanV6-FUNC-008'
    
    @aetest.test
    def bumTrafficOnIngressTrunkVPCPort(self,log,testscript,testbed):
        
        node_dict = testscript.parameters['node_dict']
        tg_interface_hdl_dict = testscript.parameters['tg_interface_hdl_dict'] 
        traffic_stream_dict = testscript.parameters['traffic_stream_dict'] 
        port_handle_dict = testscript.parameters['port_handle_dict']
        TGList_config_file = testscript.parameters['TGList']
        configdict = testscript.parameters['configdict'] 
        tgn_config_dict = configdict['TG']
        threshold = testscript.parameters['traffic_threshold'] 
        tgn_port_dut_mapping = testscript.parameters['tgn_port_dut_mapping']
        alias_intf_mapping_dict = testscript.parameters['alias_intf_mapping']
        configured_stream = testscript.parameters['configured_stream']
        trigger_obj = testscript.parameters['trigger_obj']

        log.info(banner('The value of configured stream is : {0}'.format(configured_stream))) 
        
        login = [node_dict['all_dut'][dut].execute('show version') for dut in node_dict['all_dut'] if re.search('uut', dut)]
        
        trf = configdict['trigger_dict']['TEST-005']['traffic_to_consider']
        traffic_item_list = expandTrafficItemList(trf)
        
        log.info(banner('The value of traffic_item_list is : {0}'.format(traffic_item_list)))
        
        devices = configdict['trigger_dict']['TEST-005']['trigger_dut']
        interfaces = list(configdict['interface_config_dict']['portchannel']['uut3'].keys())
        log.info('The value of len of interfaces is: {0}'.format(len(interfaces)))
        allowed_no_of_vlans = configdict['trigger_dict']['TEST-008']['no_of_vlans']
        
        log.info(banner('the Value of interfaces is  {0} and type is : {1}'.format(interfaces,type(interfaces))))
        
        trigger_type = 'trunk_port_allowed_vlan'
        
        for dut in devices:
            ns = parseScaleVlanParms(log, configdict['scale_config_dict'][dut]['global']['vlan'])
            break

        log.info(banner('The value of ns is : {0}'.format(ns)))
        
        for TG in tgn_config_dict.keys():
            tgn_hdl = testscript.parameters['testbed_obj'].devices[TG]
            out = trigger_obj.checkAllStreamStats(tgn_hdl)
        
            if out:
                for i in range(0,1):
                    vlan = [random.randint(ns.l2_vlan_start,(ns.l2_vlan_start+ns.no_of_l2_vlans-1)) for _ in range(0, allowed_no_of_vlans)]
                    log.info(banner('Iteration : {1} The value of allowed_vlan_list is : {0}'.format(vlan,i)))
                    default_allowed_vlan = str(ns.l2_vlan_start) + '-' + str(ns.l2_vlan_start+ns.no_of_l2_vlans-1)
                    for j in devices:
                        hdl = node_dict['all_dut'][j]
                        res = trigger_obj.changeInterfaceSwitchPortMode(hdl,"".join(interfaces),vlan,mode='trunk')
                    countDownTimer(150)
                    new_out = trigger_obj.checkAllRawStreamStatsTrigger(tgn_hdl,len(interfaces),trigger_type,ns.no_of_l2_vlans,allowed_vlan=vlan)
                    if not new_out['status']:
                        log.error(banner('The following stream {1} has failed in Vlan {1} '.format(vlan,new_out['streams'])))
                        res = [trigger_obj.changeInterfaceSwitchPortMode(node_dict['all_dut'][x],"".join(interfaces),default_allowed_vlan,mode='trunk') for x in devices]
                        self.failed()
                
                log.info(banner('The RAW Stream traffic stats are fine.. Reverting back the configs:'))
                res = [trigger_obj.changeInterfaceSwitchPortMode(node_dict['all_dut'][x],"".join(interfaces),default_allowed_vlan,mode='trunk') for x in devices]
                
                countDownTimer(150)
                log.info(banner('Checking Traffic stats on all the configured streams.:'))
                out = trigger_obj.checkAllStreamStats(tgn_hdl)
                if not out:
                    log.error(banner('Traffic has not recovered on some of the streams.. '))
                    self.failed()                    
            else:
                log.error('The Initial Traffic Condition did not pass :')
                self.failed()


class VXLANVxlanV6FUNC009(aetest.Testcase):

    """ BUM TRAFFIC - INGRESS ON TRUNK VPC PORT WITH VPC PRIMARY LEEG DOWN """

    uid = 'VXLAN-L3-VxlanV6-FUNC-009'
    
    @aetest.test
    def bumTrafficOnIngressTrunkVPCPortPrimaryVPCLegDown(self,log,testscript,testbed):
        
        node_dict = testscript.parameters['node_dict']
        tg_interface_hdl_dict = testscript.parameters['tg_interface_hdl_dict'] 
        traffic_stream_dict = testscript.parameters['traffic_stream_dict'] 
        port_handle_dict = testscript.parameters['port_handle_dict']
        TGList_config_file = testscript.parameters['TGList']
        configdict = testscript.parameters['configdict'] 
        tgn_config_dict = configdict['TG']
        threshold = testscript.parameters['traffic_threshold'] 
        tgn_port_dut_mapping = testscript.parameters['tgn_port_dut_mapping']
        alias_intf_mapping_dict = testscript.parameters['alias_intf_mapping']
        configured_stream = testscript.parameters['configured_stream']
        trigger_obj = testscript.parameters['trigger_obj']

        log.info(banner('The value of configured stream is : {0}'.format(configured_stream))) 
        
        login = [node_dict['all_dut'][dut].execute('show version') for dut in node_dict['all_dut'] if re.search('uut', dut)]
        
        trf = configdict['trigger_dict']['TEST-005']['traffic_to_consider']
        traffic_item_list = expandTrafficItemList(trf)
        
        log.info(banner('The value of traffic_item_list is : {0}'.format(traffic_item_list)))
        
        devices = configdict['trigger_dict']['TEST-005']['trigger_dut']
        interfaces = list(configdict['interface_config_dict']['portchannel']['uut3'].keys())
        log.info('The value of len of interfaces is: {0}'.format(len(interfaces)))
        allowed_no_of_vlans = configdict['trigger_dict']['TEST-008']['no_of_vlans']
        
        log.info(banner('the Value of interfaces is  {0} and type is : {1}'.format(interfaces,type(interfaces))))
        
        trigger_type = 'trunk_port_allowed_vlan'
        
        for dut in devices:
            ns = parseScaleVlanParms(log, configdict['scale_config_dict'][dut]['global']['vlan'])
            break

        log.info(banner('The value of ns is : {0}'.format(ns)))
        
        for TG in tgn_config_dict.keys():
            tgn_hdl = testscript.parameters['testbed_obj'].devices[TG]
            out = trigger_obj.checkAllStreamStats(tgn_hdl)
        
            if out:
                for i in range(0,1):
                    vlan = [random.randint(ns.l2_vlan_start,(ns.l2_vlan_start+ns.no_of_l2_vlans-1)) for _ in range(0, allowed_no_of_vlans)]
                    log.info(banner('Iteration : {1} The value of allowed_vlan_list is : {0}'.format(vlan,i)))
                    default_allowed_vlan = str(ns.l2_vlan_start) + '-' + str(ns.l2_vlan_start+ns.no_of_l2_vlans-1)
                    log.info(banner('Iteration {1} ... The Choosen Vlan is : {0}'.format(vlan,i)))
                    for j in devices:
                        hdl = node_dict['all_dut'][j]
                        res = trigger_obj.changeInterfaceSwitchPortMode(hdl,"".join(interfaces),vlan,mode='trunk')
                    vpc_primary_hdl = trigger_obj.getVPCSwitchhdl('primary')
                    cfg = '''interface {0}
                             shutdown'''.format(interfaces[0])
                    vpc_primary_hdl.configure(cfg)
                    countDownTimer(150)
                    new_out = trigger_obj.checkAllRawStreamStatsTrigger(tgn_hdl,len(interfaces),trigger_type,ns.no_of_l2_vlans,allowed_vlan=vlan)
                    if not new_out['status']:
                        log.error(banner('The following stream {1} has failed in Vlan {1} '.format(vlan,new_out['streams'])))
                        res = [trigger_obj.changeInterfaceSwitchPortMode(node_dict['all_dut'][x],"".join(interfaces),default_allowed_vlan,mode='trunk') for x in devices]
                        self.failed()
                    cfg1 = '''interface {0}
                              no shutdown'''.format(interfaces[0])
                    vpc_primary_hdl.configure(cfg1)
                    countDownTimer(150)
                    new_out1 = trigger_obj.checkAllRawStreamStatsTrigger(tgn_hdl,len(interfaces),trigger_type,ns.no_of_l2_vlans,allowed_vlan=vlan)
                    if not new_out1['status']:
                        log.error(banner('The following stream {1} has failed in Vlan {1} '.format(vlan,new_out['streams'])))
                        res = [trigger_obj.changeInterfaceSwitchPortMode(node_dict['all_dut'][x],interfaces[0],default_allowed_vlan,mode='trunk') for x in devices]
                        self.failed()
                log.info(banner('The RAW Stream traffic stats are fine.. Reverting back the configs:'))
                res = [trigger_obj.changeInterfaceSwitchPortMode(node_dict['all_dut'][x],interfaces[0],default_allowed_vlan,mode='trunk') for x in devices]
                
                countDownTimer(150)
                log.info(banner('Checking Traffic stats on all the configured streams.:'))
                out = trigger_obj.checkAllStreamStats(tgn_hdl)
                if not out:
                    log.error(banner('Traffic has not recovered on some of the streams.. '))
                    self.failed()                    
            else:
                log.error('The Initial Traffic Condition did not pass :')
                self.failed()
                                
                
class VXLANVxlanV6FUNC010(aetest.Testcase):

    """ BUM TRAFFIC - INGRESS ON Trunk VPC PORT WITH VPC Secondary LEG  DOWN """

    uid = 'VXLAN-L3-VxlanV6-FUNC-010'
    
    @aetest.test
    def bumTrafficOnIngressTrunkVPCPortSecondaryVPCLegDown(self,log,testscript,testbed):
        
        node_dict = testscript.parameters['node_dict']
        tg_interface_hdl_dict = testscript.parameters['tg_interface_hdl_dict'] 
        traffic_stream_dict = testscript.parameters['traffic_stream_dict'] 
        port_handle_dict = testscript.parameters['port_handle_dict']
        TGList_config_file = testscript.parameters['TGList']
        configdict = testscript.parameters['configdict'] 
        tgn_config_dict = configdict['TG']
        threshold = testscript.parameters['traffic_threshold'] 
        tgn_port_dut_mapping = testscript.parameters['tgn_port_dut_mapping']
        alias_intf_mapping_dict = testscript.parameters['alias_intf_mapping']
        configured_stream = testscript.parameters['configured_stream']
        trigger_obj = testscript.parameters['trigger_obj']

        log.info(banner('The value of configured stream is : {0}'.format(configured_stream))) 
        
        login = [node_dict['all_dut'][dut].execute('show version') for dut in node_dict['all_dut'] if re.search('uut', dut)]
        
        trf = configdict['trigger_dict']['TEST-005']['traffic_to_consider']
        traffic_item_list = expandTrafficItemList(trf)
        
        log.info(banner('The value of traffic_item_list is : {0}'.format(traffic_item_list)))
        
        devices = configdict['trigger_dict']['TEST-005']['trigger_dut']
        interfaces = list(configdict['interface_config_dict']['portchannel']['uut3'].keys())
        log.info('The value of len of interfaces is: {0}'.format(len(interfaces)))
        allowed_no_of_vlans = configdict['trigger_dict']['TEST-008']['no_of_vlans']
        
        log.info(banner('the Value of interfaces is  {0} and type is : {1}'.format(interfaces,type(interfaces))))
        
        trigger_type = 'trunk_port_allowed_vlan'
        
        for dut in devices:
            ns = parseScaleVlanParms(log, configdict['scale_config_dict'][dut]['global']['vlan'])
            break

        log.info(banner('The value of ns is : {0}'.format(ns)))
        
        for TG in tgn_config_dict.keys():
            tgn_hdl = testscript.parameters['testbed_obj'].devices[TG]
            out = trigger_obj.checkAllStreamStats(tgn_hdl)
        
            if out:
                for i in range(0,1):
                    vlan = [random.randint(ns.l2_vlan_start,(ns.l2_vlan_start+ns.no_of_l2_vlans-1)) for _ in range(0, allowed_no_of_vlans)]
                    log.info(banner('Iteration : {1} The value of allowed_vlan_list is : {0}'.format(vlan,i)))
                    default_allowed_vlan = str(ns.l2_vlan_start) + '-' + str(ns.l2_vlan_start+ns.no_of_l2_vlans-1)
                    log.info(banner('Iteration {1} ... The Choosen Vlan is : {0}'.format(vlan,i)))
                    for j in devices:
                        hdl = node_dict['all_dut'][j]
                        res = trigger_obj.changeInterfaceSwitchPortMode(hdl,interfaces[0],vlan,mode='trunk')
                    vpc_secondary_hdl = trigger_obj.getVPCSwitchhdl('secondary')
                    cfg = '''interface {0}
                             shutdown'''.format(interfaces[0])
                    vpc_secondary_hdl.configure(cfg)
                    countDownTimer(150)
                    new_out = trigger_obj.checkAllRawStreamStatsTrigger(tgn_hdl,len(interfaces),trigger_type,ns.no_of_l2_vlans,allowed_vlan=vlan)
                    if not new_out['status']:
                        log.error(banner('The following stream {1} has failed in Vlan {1} '.format(vlan,new_out['streams'])))
                        res = [trigger_obj.changeInterfaceSwitchPortMode(node_dict['all_dut'][x],interfaces[0],default_allowed_vlan,mode='trunk') for x in devices]
                        self.failed()
                    cfg1 = '''interface {0}
                              no shutdown'''.format(interfaces[0])
                    vpc_secondary_hdl.configure(cfg1)
                    countDownTimer(150)
                    new_out1 = trigger_obj.checkAllRawStreamStatsTrigger(tgn_hdl,len(interfaces),trigger_type,ns.no_of_l2_vlans,allowed_vlan=vlan)
                    if not new_out1['status']:
                        log.error(banner('The following stream {1} has failed in Vlan {1} '.format(vlan,new_out['streams'])))
                        res = [trigger_obj.changeInterfaceSwitchPortMode(node_dict['all_dut'][x],interfaces[0],default_allowed_vlan,mode='trunk') for x in devices]
                        self.failed()
                log.info(banner('The RAW Stream traffic stats are fine.. Reverting back the configs:'))
                res = [trigger_obj.changeInterfaceSwitchPortMode(node_dict['all_dut'][x],interfaces[0],default_allowed_vlan,mode='trunk') for x in devices]
                
                countDownTimer(150)
                log.info(banner('Checking Traffic stats on all the configured streams.:'))
                out = trigger_obj.checkAllStreamStats(tgn_hdl)
                if not out:
                    log.error(banner('Traffic has not recovered on some of the streams.. '))
                    self.failed()                    
            else:
                log.error('The Initial Traffic Condition did not pass :')
                self.failed()
                

class VXLANVxlanV6FUNC011(aetest.Testcase):

    """ BUM TRAFFIC - Uplink as Physical Port """

    uid = 'VXLAN-L3-VxlanV6-FUNC-011'
    
    @aetest.test
    def bumTrafficUplinkAsPhysicalPort(self,log,testscript,testbed):
        
        node_dict = testscript.parameters['node_dict']
        tg_interface_hdl_dict = testscript.parameters['tg_interface_hdl_dict'] 
        traffic_stream_dict = testscript.parameters['traffic_stream_dict'] 
        port_handle_dict = testscript.parameters['port_handle_dict']
        TGList_config_file = testscript.parameters['TGList']
        configdict = testscript.parameters['configdict'] 
        tgn_config_dict = configdict['TG']
        threshold = testscript.parameters['traffic_threshold'] 
        tgn_port_dut_mapping = testscript.parameters['tgn_port_dut_mapping']
        alias_intf_mapping_dict = testscript.parameters['alias_intf_mapping']
        configured_stream = testscript.parameters['configured_stream']
        trigger_obj = testscript.parameters['trigger_obj']

        log.info(banner('The value of configured stream is : {0}'.format(configured_stream))) 
        
        login = [node_dict['all_dut'][dut].execute('show version') for dut in node_dict['all_dut'] if re.search('uut', dut)]
        
        trf = configdict['trigger_dict']['TEST-011']['traffic_to_consider']
        traffic_item_list = expandTrafficItemList(trf)
        
        log.info(banner('The value of traffic_item_list is : {0}'.format(traffic_item_list)))
        
        devices = configdict['trigger_dict']['TEST-011']['trigger_dut']
        interfaces = configdict['trigger_dict']['TEST-011']['interfaces'].split()

        
        log.info(banner('the Value of interfaces is  {0} and type is : {1}'.format(interfaces,type(interfaces))))
        
        
        for TG in tgn_config_dict.keys():
            tgn_hdl = testscript.parameters['testbed_obj'].devices[TG]
            out = trigger_obj.checkAllStreamStats(tgn_hdl)
        
            if out:
                res = trigger_obj.backUpAndRestoreConfigs(devices,'backup')
                for intf in interfaces:
                    log.info('The value of intf is : {0}'.format(intf))
                    dev = intf.split('_')[0]
                    log.info('The value of dev is : {0}'.format(dev))
                    hdl = node_dict['all_dut'][dev]
                    cfg = 'default interface {0}'.format(alias_intf_mapping_dict[intf])
                    hdl.configure(cfg)
                
                res = trigger_obj.backUpAndRestoreConfigs(devices,'restore')
                
                log.info(banner('Waiting for Traffic to converge post trigger..Waiting for 100 secs'))
                countDownTimer(150)
            
                out = trigger_obj.checkAllStreamStats(tgn_hdl)
                
                if not out:
                    log.error(banner('Traffic has not recovered on some of the streams.. Collecting the individual STream stats:'))
                    res = trigger_obj.backUpAndRestoreConfigs(devices,'backup')
                    self.failed()
                else:
                    log.info(banner('Traffic has receoverd post changing the configs to L3 Physical Interface'))
                    res = trigger_obj.backUpAndRestoreConfigs(devices,'cleanup')                   
            else:
                log.error('The Initial Traffic Condition did not pass:')
                self.failed()
 
class VXLANVxlanV6FUNC012(aetest.Testcase):

    """ BUM TRAFFIC - Uplink as Port-Channel Port """

    uid = 'VXLAN-L3-VxlanV6-FUNC-012'
    
    @aetest.test
    def bumTrafficUplinkAsPortChannel(self,log,testscript,testbed):
        
        node_dict = testscript.parameters['node_dict']
        tg_interface_hdl_dict = testscript.parameters['tg_interface_hdl_dict'] 
        traffic_stream_dict = testscript.parameters['traffic_stream_dict'] 
        port_handle_dict = testscript.parameters['port_handle_dict']
        TGList_config_file = testscript.parameters['TGList']
        configdict = testscript.parameters['configdict'] 
        tgn_config_dict = configdict['TG']
        threshold = testscript.parameters['traffic_threshold'] 
        tgn_port_dut_mapping = testscript.parameters['tgn_port_dut_mapping']
        alias_intf_mapping_dict = testscript.parameters['alias_intf_mapping']
        configured_stream = testscript.parameters['configured_stream']
        trigger_obj = testscript.parameters['trigger_obj']

        log.info(banner('The value of configured stream is : {0}'.format(configured_stream))) 
        
        login = [node_dict['all_dut'][dut].execute('show version') for dut in node_dict['all_dut'] if re.search('uut', dut)]
        
        trf = configdict['trigger_dict']['TEST-012']['traffic_to_consider']
        traffic_item_list = expandTrafficItemList(trf)
        
        log.info(banner('The value of traffic_item_list is : {0}'.format(traffic_item_list)))
        
        devices = configdict['trigger_dict']['TEST-012']['trigger_dut']
        interfaces = configdict['trigger_dict']['TEST-012']['interfaces'].split()
        port_channel_dict = configdict['trigger_dict']['TEST-012']['portchannel']

        
        log.info(banner('the Value of interfaces is  {0} and type is : {1}'.format(interfaces,type(interfaces))))
        
        
        for TG in tgn_config_dict.keys():
            tgn_hdl = testscript.parameters['testbed_obj'].devices[TG]
            out = trigger_obj.checkAllStreamStats(tgn_hdl)
        
            if out:
                res = trigger_obj.backUpAndRestoreConfigs(devices,'backup')
                log.info(banner('Defaulting the interfaces : {0}'.format([alias_intf_mapping_dict[intf] for intf in interfaces])))
                default_res = trigger_obj.defaultSetOfInterfaces(interfaces)
                
                for dut in port_channel_dict:
                    log.info('the value of dut  inside scripts is : {0}'.format(dut))
                    hdl = node_dict['all_dut'][dut]
                    for intf in port_channel_dict[dut].keys():
                        log.info('the value of intf  inside scripts is : {0}'.format(intf))
                        args = port_channel_dict[dut][intf]
                        log.info('the value of args  inside scripts is : {0}'.format(args))
                        res = trigger_obj.configurePo(hdl,intf,args)
                        
                log.info('Waiting for the traffic to converge After changing the configs to Port-channel.. sleeping for 100 seconds ')
                countDownTimer(150)
                
                out = trigger_obj.checkAllStreamStats(tgn_hdl)
                
                if not out:
                    log.error(banner('Traffic has not recovered on some of the streams.. Collecting the individual STream stats:'))
                    res = trigger_obj.backUpAndRestoreConfigs(devices,'restore')
                    self.failed()
                else:
                    log.info(banner('Traffic has receoverd post changing the configs to L3 Physical Interface'))
                    res = trigger_obj.backUpAndRestoreConfigs(devices,'restore')
                    res1 = trigger_obj.backUpAndRestoreConfigs(devices,'cleanup')                
                    
                log.info('Waiting for the traffic to converge After revering the changing to Physical interface after changing to port-channel.. sleeping for 100 seconds ')
                countDownTimer(150)
                
                out = trigger_obj.checkAllStreamStats(tgn_hdl)
                
                if not out:
                    log.error(banner('Traffic has not recovered on some of the streams Even after restoring the Original Configs.. Collecting the individual STream stats:'))
                    self.failed()
            else:
                log.error('The Initial Traffic Condition did not pass:')
                self.failed()
                                
                                
class VXLANVxlanV6FUNC013(aetest.Testcase):

    """ BUM TRAFFIC - Uplink as SVI """

    uid = 'VXLAN-L3-VxlanV6-FUNC-013'
    
    @aetest.test
    def bumTrafficUplinkAsSVI(self,log,testscript,testbed):
        
        node_dict = testscript.parameters['node_dict']
        tg_interface_hdl_dict = testscript.parameters['tg_interface_hdl_dict'] 
        traffic_stream_dict = testscript.parameters['traffic_stream_dict'] 
        port_handle_dict = testscript.parameters['port_handle_dict']
        TGList_config_file = testscript.parameters['TGList']
        configdict = testscript.parameters['configdict'] 
        tgn_config_dict = configdict['TG']
        threshold = testscript.parameters['traffic_threshold'] 
        tgn_port_dut_mapping = testscript.parameters['tgn_port_dut_mapping']
        alias_intf_mapping_dict = testscript.parameters['alias_intf_mapping']
        configured_stream = testscript.parameters['configured_stream']
        trigger_obj = testscript.parameters['trigger_obj']

        log.info(banner('The value of configured stream is : {0}'.format(configured_stream)))
        
        login = [node_dict['all_dut'][dut].execute('show version') for dut in node_dict['all_dut'] if re.search('uut', dut)] 
        
        trf = configdict['trigger_dict']['TEST-013']['traffic_to_consider']
        traffic_item_list = expandTrafficItemList(trf)
        
        log.info(banner('The value of traffic_item_list is : {0}'.format(traffic_item_list)))
        
        devices = configdict['trigger_dict']['TEST-013']['trigger_dut']
        interfaces = configdict['trigger_dict']['TEST-013']['interfaces'].split()
        port_channel_dict = configdict['trigger_dict']['TEST-013']['svi']

        
        log.info(banner('the Value of interfaces is  {0} and type is : {1}'.format(interfaces,type(interfaces))))
        
        
        for TG in tgn_config_dict.keys():
            tgn_hdl = testscript.parameters['testbed_obj'].devices[TG]
            out = trigger_obj.checkAllStreamStats(tgn_hdl)
        
            if out:
                res = trigger_obj.backUpAndRestoreConfigs(devices,'backup')
                log.info(banner('Defaulting the interfaces : {0}'.format([alias_intf_mapping_dict[intf] for intf in interfaces])))
                default_res = trigger_obj.defaultSetOfInterfaces(interfaces)
                
                for dut in port_channel_dict:
                    log.info('the value of dut  inside scripts is : {0}'.format(dut))
                    hdl = node_dict['all_dut'][dut]
                    for intf in port_channel_dict[dut].keys():
                        log.info('the value of intf  inside scripts is : {0}'.format(intf))
                        args = port_channel_dict[dut][intf]
                        log.info('the value of args  inside scripts is : {0}'.format(args))
                        res = trigger_obj.configureSVI(hdl,intf,args)
                        
                log.info('Waiting for the traffic to converge After changing the configs to Port-channel.. sleeping for 100 seconds ')
                countDownTimer(150)
                
                out = trigger_obj.checkAllStreamStats(tgn_hdl)
                
                if not out:
                    log.error(banner('Traffic has not recovered on some of the streams.. Collecting the individual STream stats:'))
                    res = trigger_obj.backUpAndRestoreConfigs(devices,'restore')
                    self.failed()
                else:
                    log.info(banner('Traffic has receoverd post changing the configs to L3 Physical Interface'))
                    res = trigger_obj.backUpAndRestoreConfigs(devices,'restore')
                    res1 = trigger_obj.backUpAndRestoreConfigs(devices,'cleanup')                
                    
                log.info('Waiting for the traffic to converge After revering the changing to Physical interface after changing to port-channel.. sleeping for 100 seconds ')
                countDownTimer(150)
                
                out = trigger_obj.checkAllStreamStats(tgn_hdl)
                
                if not out:
                    log.error(banner('Traffic has not recovered on some of the streams Even after restoring the Original Configs.. Collecting the individual STream stats:'))
                    self.failed()
            else:
                log.error('The Initial Traffic Condition did not pass:')
                self.failed()                               

class VXLANVxlanV6FUNC014(aetest.Testcase):

    """ STatic MAC Propogation in EVPN Environment """

    uid = 'VXLAN-L3-VxlanV6-FUNC-014'
    
    @aetest.test
    def staticMACPropogationInEVPN(self,log,testscript,testbed):
        
        node_dict = testscript.parameters['node_dict']
        tg_interface_hdl_dict = testscript.parameters['tg_interface_hdl_dict'] 
        traffic_stream_dict = testscript.parameters['traffic_stream_dict'] 
        port_handle_dict = testscript.parameters['port_handle_dict']
        TGList_config_file = testscript.parameters['TGList']
        configdict = testscript.parameters['configdict'] 
        tgn_config_dict = configdict['TG']
        threshold = testscript.parameters['traffic_threshold'] 
        tgn_port_dut_mapping = testscript.parameters['tgn_port_dut_mapping']
        alias_intf_mapping_dict = testscript.parameters['alias_intf_mapping']
        configured_stream = testscript.parameters['configured_stream']
        trigger_obj = testscript.parameters['trigger_obj']

        log.info(banner('The value of configured stream is : {0}'.format(configured_stream))) 
        
        login = [node_dict['all_dut'][dut].execute('show version') for dut in node_dict['all_dut'] if re.search('uut', dut)]
        
        trf = configdict['trigger_dict']['TEST-014']['traffic_to_consider']
        traffic_item_list = expandTrafficItemList(trf)
        
        log.info(banner('The value of traffic_item_list is : {0}'.format(traffic_item_list)))
        
        devices = configdict['trigger_dict']['TEST-014']['trigger_dut']
        static_mac = configdict['trigger_dict']['TEST-014']['mac_to_add']
        interface = configdict['trigger_dict']['TEST-014']['interface']
        
        
        for TG in tgn_config_dict.keys():
            tgn_hdl = testscript.parameters['testbed_obj'].devices[TG]
            out = trigger_obj.checkAllStreamStats(tgn_hdl)
        
            if out:
                for dut in devices:
                    hdl = node_dict['all_dut'][dut]
                
                    cfg = 'mac address-table static {0} vlan 701 interface {1}'.format(static_mac,alias_intf_mapping_dict[interface])
                
                    hdl.configure(cfg)
                
                vpc_dict = trigger_obj.getDeviceDict('vpc_vtep')
                log.info('The value of vpc_dict is : {0}'.format(vpc_dict))
                
                show_cfg =  'sh mac address-table | grep 0000.0000.7654 | xml'
                
                for dut in vpc_dict:
                    hdl = node_dict['all_dut'][dut]
                    out = hdl.execute(show_cfg)
                    if out:
                        s = BeautifulSoup(out)
                        mac = s.find('disp_mac_addr').string
                        log.info('The value of mac is : {0}'.format(mac))
                        if not mac == static_mac:
                            log.error('The MAC is not programmed ')
                            self.failed()
                        
                    else:
                        log.error('the Mac is not programmed')
                        self.failed()
                
                for dut in devices:
                    hdl = node_dict['all_dut'][dut]
                    cfg = 'no mac address-table static {0} vlan 701 interface {1}'.format(static_mac,alias_intf_mapping_dict[interface])
                    hdl.configure(cfg)
                    
                countDownTimer(50)
                    
                for dut in vpc_dict:
                    hdl = node_dict['all_dut'][dut]
                    out = hdl.configure(show_cfg)
                    log.info(banner('The value of out is : {0}'.format(out)))
                    if out:
                        s = BeautifulSoup(out)
                        try:
                            mac = s.find('disp_mac_addr').string
                            log.error('MAC Is not removed from software .. The value of MAC is : {0}'.format(mac))
                            self.failed()
                        except:
                            log.info('MAC is removed from the software. Hence the test case is passed.')                           
            else:
                log.error('The Initial Traffic Condition did not pass:')
                self.failed()                   


class VXLANVxlanV6FUNC015(aetest.Testcase):

    """ Jumbo BUM TRAFFIC """

    uid = 'VXLAN-L3-VxlanV6-FUNC-015'
    
    @aetest.test
    def jumboBUMTraffic(self,log,testscript,testbed):
        
        node_dict = testscript.parameters['node_dict']
        tg_interface_hdl_dict = testscript.parameters['tg_interface_hdl_dict'] 
        traffic_stream_dict = testscript.parameters['traffic_stream_dict'] 
        port_handle_dict = testscript.parameters['port_handle_dict']
        TGList_config_file = testscript.parameters['TGList']
        configdict = testscript.parameters['configdict'] 
        tgn_config_dict = configdict['TG']
        threshold = testscript.parameters['traffic_threshold'] 
        tgn_port_dut_mapping = testscript.parameters['tgn_port_dut_mapping']
        alias_intf_mapping_dict = testscript.parameters['alias_intf_mapping']
        configured_stream = testscript.parameters['configured_stream']
        trigger_obj = testscript.parameters['trigger_obj']

        log.info(banner('The value of configured stream is : {0}'.format(configured_stream))) 
        
        login = [node_dict['all_dut'][dut].execute('show version') for dut in node_dict['all_dut'] if re.search('uut', dut)]
        
        trf = configdict['trigger_dict']['TEST-015']['traffic_to_consider']
        traffic_item_list = expandTrafficItemList(trf)
        
        log.info(banner('The value of traffic_item_list is : {0}'.format(traffic_item_list)))
        
        devices = configdict['trigger_dict']['TEST-015']['trigger_dut']
        interfaces = configdict['trigger_dict']['TEST-015']['interfaces'].split()
        
        
        for TG in tgn_config_dict.keys():
            tgn_hdl = testscript.parameters['testbed_obj'].devices[TG]
            out = trigger_obj.checkAllStreamStats(tgn_hdl)
        
            if out:
                res = trigger_obj.backUpAndRestoreConfigs(devices,'backup')
                
                for dut in devices:
                    hdl = node_dict['all_dut'][dut]
                    hdl.configure('system jumbomtu 9100')
                
                log.info(banner('Configuring System Jumbo MTU on the following interfaces {0}'.format([alias_intf_mapping_dict[intf] for intf in interfaces])))
                
                for intf in interfaces:
                    dut = intf.split('_')[0]
                    hdl = node_dict['all_dut'][dut]
                    cfg = '''interface {0}
                             mtu 9100'''.format(alias_intf_mapping_dict[intf])
                    hdl.configure(cfg)
                    if dut not in ['uut33','uut4']:
                        cfg = '''interface port-channel1
                                 mtu 9100'''
                        hdl.configure(cfg)
                    
                source_port = testscript.parameters['configdict']['TG'][TG]['JUMBO001']['traffic_config_dict']['source']
                receiver_port = testscript.parameters['configdict']['TG'][TG]['JUMBO001']['traffic_config_dict']['receivers']
                traffic_args=testscript.parameters['configdict']['TG'][TG]['JUMBO001']['traffic_config_dict']['params']
                 
                src_port = [port_handle_dict[x] for x in source_port]
                dst_port = [port_handle_dict[x] for x in receiver_port]
                log.info('The value of src_port is : {0}'.format(src_port))
                log.info('The value of dst_port is : {0}'.format(dst_port))
                
                jumbo_traffic_config = configureIxNetworkRawTrafficL2(self, traffic_args, tg_hdl=tgn_hdl, emulation_src_handle=src_port, emulation_dst_handle=dst_port)
                log.info('The value of ixia_traffic_config is : {0}'.format(jumbo_traffic_config))
                
                
                log.info('Starting the JumboMTU Traffic Item... Sleeping for 30 seeconds after starting the stream')
                countDownTimer(30)
                
                stream_hdl = jumbo_traffic_config['traffic_item']
                stream_id = jumbo_traffic_config['stream_id']
                
                x = tgn_hdl.traffic_control(action='run', handle = stream_hdl,max_wait_timer=60)
                log.info('The value of x is : {0}'.format(x))
                
                if not x.status:
                    log.error(banner('The Stream {0} could not be started as expected '.format(jumbo_traffic_config.stream_id)))
    
                stats = tgn_hdl.traffic_stats(stream = jumbo_traffic_config['stream_id'], mode = 'traffic_item')
                log.info(banner('The Value of stats is : {0}'.format(stats)))
                tx_stat = stats.traffic_item[jumbo_traffic_config['stream_id']]['tx'].total_pkt_rate
                rx_stat = stats.traffic_item[jumbo_traffic_config['stream_id']]['rx'].total_pkt_rate
                
                log.info('The value of tx_stat is : {0}'.format(tx_stat))
                log.info('The value of rx_stat is : {0}'.format(rx_stat))
                
                if abs(tx_stat-rx_stat < threshold):
                    log.info('Jumbo Frames traffic is as expected.... Deleting the Created stream and re-starting the other streams:')
                    
                else:
                    log.info('Jumbo Frames Traffic item is not as expected. The value of tx and rx is : {0} and {1}'.format(tx_stat,rx_stat))
                    self.failed()
                    
                log.info('Stopping the Jumbo stream:')
                x1 = tgn_hdl.traffic_control(action='stop', handle = stream_hdl,max_wait_timer=60)
                
                countDownTimer(30)

                log.info('Removing the stream:')
                y = tgn_hdl.traffic_config(mode='remove',stream_id=stream_id)
                        
                log.info('STarting all the other streams')
                z = tgn_hdl.traffic_control(action='run',max_wait_timer=60)
                
                res = trigger_obj.backUpAndRestoreConfigs(devices,'restore')
                
                log.info('waiting for 30 seconds before collecting the stats:')
                countDownTimer(30)
                out = trigger_obj.checkAllStreamStats(tgn_hdl)
                
                if not out:
                        log.error(banner('Traffic has not recovered on some of the streams Even after restoring the Original Configs.. Collecting the individual STream stats:'))
                        self.failed()
            else:
                log.error('The Initial Traffic Condition did not pass:')
                self.failed()    



class VXLANVxlanV6FUNC016(aetest.Testcase):

    """ Verify UnderLay ECMP """

    uid = 'VXLAN-L3-VxlanV6-FUNC-016'
    
    @aetest.test
    def verifyUnderlayECMPonPhysicalInterface(self,log,testscript,testbed):
        
        node_dict = testscript.parameters['node_dict']
        tg_interface_hdl_dict = testscript.parameters['tg_interface_hdl_dict'] 
        traffic_stream_dict = testscript.parameters['traffic_stream_dict'] 
        port_handle_dict = testscript.parameters['port_handle_dict']
        TGList_config_file = testscript.parameters['TGList']
        configdict = testscript.parameters['configdict'] 
        tgn_config_dict = configdict['TG']
        threshold = testscript.parameters['traffic_threshold'] 
        tgn_port_dut_mapping = testscript.parameters['tgn_port_dut_mapping']
        alias_intf_mapping_dict = testscript.parameters['alias_intf_mapping']
        configured_stream = testscript.parameters['configured_stream']
        trigger_obj = testscript.parameters['trigger_obj']

        log.info(banner('The value of traffic_stream_dict is : {0}'.format(traffic_stream_dict)))
        
        login = [node_dict['all_dut'][dut].execute('show version') for dut in node_dict['all_dut'] if re.search('uut', dut)]
        
        log.info(banner('The value of configured stream is : {0}'.format(configured_stream))) 
        
        trf = configdict['trigger_dict']['TEST-016']['traffic_to_consider']
        log.info('The value of trf is : {0}'.format(trf))
        if '-' in trf:
            traffic_item_list = expandTrafficItemList(trf)
        else:
            traffic_item_list = trf
        
        log.info(banner('The value of traffic_item_list is : {0}'.format(traffic_item_list)))
        
        devices = configdict['trigger_dict']['TEST-016']['trigger_dut']
        interfaces = configdict['trigger_dict']['TEST-016']['interfaces'].split()
        
        
        for TG in tgn_config_dict.keys():
            tgn_hdl = testscript.parameters['testbed_obj'].devices[TG]
            out = trigger_obj.checkAllStreamStats(tgn_hdl)
        
            if out:
                res = trigger_obj.backUpAndRestoreConfigs(devices,'backup')
                
                log.info(banner('Stopping all the streams:'))
                
                x1 = tgn_hdl.traffic_control(action='stop', max_wait_timer=60)
                
                log.info(banner('starting One Stream to check for UnderLay ECMP.. The stream is : {0}'.format(traffic_item_list)))
                
                for trf_stream in traffic_stream_dict:
                    if trf_stream == traffic_item_list:
                        stream_handle = traffic_stream_dict[trf_stream]['traffic_item']
                        x = tgn_hdl.traffic_control(action='run', handle = stream_handle, max_wait_timer=60)
                        
                log.info(banner('Waiting for 30 seconds for the traffic to settle down.. time Remaining 30 sec'))
                countDownTimer(30)
                
                for intf in interfaces:
                    dut = intf.split('_')[0]
                    hdl = node_dict['all_dut'][dut]
                    cfg = 'show interface {0} counters  brief | xml '.format(alias_intf_mapping_dict[intf])
                    out = hdl.execute(cfg)
                    s = BeautifulSoup(out)
                    count = s.find('eth_outframes1').string
                    log.info('The value of count in dut {1} and interface {0} is  {2}: '.format(alias_intf_mapping_dict[intf],dut, count))
                    if not int(count) >=100:
                        log.error(banner('The following link  {0} on {1} is underutilized..Packet Count is : {2}'.format(alias_intf_mapping_dict[intf],dut,count)))
                        self.failed()
                        
                log.info('ECMP of Underlay is as expected..starting all the streams')

                x2 = tgn_hdl.traffic_control(action='run', max_wait_timer=60)
                    
                countDownTimer(30)
                out = trigger_obj.checkAllStreamStats(tgn_hdl)
                if not out:
                    log.error(banner('Traffic has not recovered on some of the streams Even after restoring the Original Configs.. Collecting the individual STream stats:'))
                    self.failed()
            else:
                log.error('The Initial Traffic Condition did not pass:')
                self.failed()   




class VXLANVxlanV6FUNC017(aetest.Testcase):

    """ BOUND TRAFFIC - Uplink as Port-Channel Port - TESTING ECMP """

    uid = 'VXLAN-L3-VxlanV6-FUNC-017'
    
    @aetest.test
    def verifyUnderlayECMPonPortChannelInterface(self,log,testscript,testbed):
        
        node_dict = testscript.parameters['node_dict']
        tg_interface_hdl_dict = testscript.parameters['tg_interface_hdl_dict'] 
        traffic_stream_dict = testscript.parameters['traffic_stream_dict'] 
        port_handle_dict = testscript.parameters['port_handle_dict']
        TGList_config_file = testscript.parameters['TGList']
        configdict = testscript.parameters['configdict'] 
        tgn_config_dict = configdict['TG']
        threshold = testscript.parameters['traffic_threshold'] 
        tgn_port_dut_mapping = testscript.parameters['tgn_port_dut_mapping']
        alias_intf_mapping_dict = testscript.parameters['alias_intf_mapping']
        configured_stream = testscript.parameters['configured_stream']
        trigger_obj = testscript.parameters['trigger_obj']

        log.info(banner('The value of configured stream is : {0}'.format(configured_stream))) 
        
        login = [node_dict['all_dut'][dut].execute('show version') for dut in node_dict['all_dut'] if re.search('uut', dut)]
        
        trf = configdict['trigger_dict']['TEST-017']['traffic_to_consider']
        if '-' in trf:
            traffic_item_list = expandTrafficItemList(trf)
        else:
            traffic_item_list = trf
        
        log.info(banner('The value of traffic_item_list is : {0}'.format(traffic_item_list)))
        
        devices = configdict['trigger_dict']['TEST-017']['trigger_dut']
        interfaces = configdict['trigger_dict']['TEST-017']['interfaces'].split()
        port_channel_dict = configdict['trigger_dict']['TEST-017']['portchannel']

        
        log.info(banner('the Value of interfaces is  {0} and type is : {1}'.format(interfaces,type(interfaces))))
        
        
        for TG in tgn_config_dict.keys():
            tgn_hdl = testscript.parameters['testbed_obj'].devices[TG]
            out = trigger_obj.checkAllStreamStats(tgn_hdl)
        
            if out:
                res = trigger_obj.backUpAndRestoreConfigs(devices,'backup')
                log.info(banner('Defaulting the interfaces : {0}'.format([alias_intf_mapping_dict[intf] for intf in interfaces])))
                default_res = trigger_obj.defaultSetOfInterfaces(interfaces)
                
                for dut in port_channel_dict:
                    log.info('the value of dut  inside scripts is : {0}'.format(dut))
                    hdl = node_dict['all_dut'][dut]
                    for intf in port_channel_dict[dut].keys():
                        log.info('the value of intf  inside scripts is : {0}'.format(intf))
                        args = port_channel_dict[dut][intf]
                        log.info('the value of args  inside scripts is : {0}'.format(args))
                        res = trigger_obj.configurePo(hdl,intf,args)
                        
                log.info('Waiting for the traffic to converge After changing the configs to Port-channel.. sleeping for 100 seconds ')
                countDownTimer(150)
                
                out = trigger_obj.checkAllStreamStats(tgn_hdl)
                
                if not out:
                    log.error(banner('Traffic has not recovered on some of the streams.. Collecting the individual STream stats:'))
                    res = trigger_obj.backUpAndRestoreConfigs(devices,'restore')
                    self.failed()
                else:
                    log.info(banner('Traffic has receoverd post changing the configs to L3 Physical Interface'))
                    log.info(banner('STopping all the streams except one...'))
                    for trf_stream in traffic_stream_dict:
                        if not trf_stream == traffic_item_list:
                            stream_handle = traffic_stream_dict[trf_stream]['traffic_item']
                            x = tgn_hdl.traffic_control(action='stop', handle = stream_handle, max_wait_timer=60)
                            
                    port_channel_intf = list(configdict['trigger_dict']['TEST-017']['portchannel']['uut1'].keys())
                    log.info('The value of port_channel_intf is : {0}'.format(port_channel_intf))
                    
                    for intf in port_channel_intf:
                        cfg = 'show interface {0} counters  brief | xml '.format(intf)
                        hdl=node_dict['all_dut']['uut1']
                        out = hdl.execute(cfg)
                        s = BeautifulSoup(out)
                        count = s.find('eth_outframes1').string
                        log.info('The value of count of port-channel {0} in dut UUT1  is  {1}: '.format(intf,count))
                        if not int(count) >=100:
                            log.error(banner('The following port-channel {0} on dut UUT1 is underutilized..Packet Count is : {1}'.format(intf,count)))
                            res = trigger_obj.backUpAndRestoreConfigs(devices,'restore')
                            res1 = trigger_obj.backUpAndRestoreConfigs(devices,'cleanup')
                            self.failed()
                    
                    res = trigger_obj.backUpAndRestoreConfigs(devices,'restore')
                    res1 = trigger_obj.backUpAndRestoreConfigs(devices,'cleanup')
                    
                    for trf_stream in traffic_stream_dict:
                            stream_handle = traffic_stream_dict[trf_stream]['traffic_item']
                            x = tgn_hdl.traffic_control(action='run', handle = stream_handle, max_wait_timer=60)                
                    
                log.info('Waiting for the traffic to converge After revering the changing to Physical interface after changing to port-channel.. sleeping for 100 seconds ')
                countDownTimer(150)
                
                out = trigger_obj.checkAllStreamStats(tgn_hdl)
                
                if not out:
                    log.error(banner('Traffic has not recovered on some of the streams Even after restoring the Original Configs.. Collecting the individual STream stats:'))
                    self.failed()
            else:
                log.error('The Initial Traffic Condition did not pass:')
                self.failed()                


class VXLANVxlanV6FUNC018(aetest.Testcase):

    """ Verify Overlay ECMP with TYpe 5 Route """

    uid = 'VXLAN-L3-VxlanV6-FUNC-018'
    
    @aetest.test
    def verifyOverlayECMPWithTYpe5Route(self,log,testscript,testbed):
        
        node_dict = testscript.parameters['node_dict']
        tg_interface_hdl_dict = testscript.parameters['tg_interface_hdl_dict'] 
        traffic_stream_dict = testscript.parameters['traffic_stream_dict'] 
        port_handle_dict = testscript.parameters['port_handle_dict']
        TGList_config_file = testscript.parameters['TGList']
        configdict = testscript.parameters['configdict'] 
        tgn_config_dict = configdict['TG']
        threshold = testscript.parameters['traffic_threshold'] 
        tgn_port_dut_mapping = testscript.parameters['tgn_port_dut_mapping']
        alias_intf_mapping_dict = testscript.parameters['alias_intf_mapping']
        configured_stream = testscript.parameters['configured_stream']
        trigger_obj = testscript.parameters['trigger_obj']

        log.info(banner('The value of configured stream is : {0}'.format(configured_stream)))   
        
        login = [node_dict['all_dut'][dut].execute('show version') for dut in node_dict['all_dut'] if re.search('uut', dut)]
        
        devices = ['uut4']
        
        for TG in tgn_config_dict.keys():
            tgn_hdl = testscript.parameters['testbed_obj'].devices[TG]
            out = trigger_obj.checkAllStreamStats(tgn_hdl) 
            
            res = trigger_obj.backUpAndRestoreConfigs(devices,'backup')
            
            if out: 
        
                hdl = node_dict['all_dut']['uut4']
                cfg = '''vlan 999
                         exit
                         interface vlan 999
                         no shut
                         vrf member V6-001
                         ip address 99.99.99.1/24
                         '''
                hdl.configure(cfg)
                cfg1 = '''router bgp 65100
                          vrf V6-001
                          address-family ipv4 unicast
                          network 99.99.99.0/24
                          advertise l2vpn evpn
                          maximum-paths 64
                          maximum-paths ibgp 64
                          address-family ipv6 unicast
                          advertise l2vpn evpn
                          maximum-paths 64
                          maximum-paths ibgp 64'''
                hdl.configure(cfg1)
        
                dut_hdl = node_dict['all_dut']['uut1']
                
                cfg2 =  'sh bgp l2vpn evpn  | grep 99.99.99'
                
                out = dut_hdl.execute(cfg2)
        
                match = re.findall('\[5\]',out)
                if match:
                    log.info('Type 5 Routes is getting advertised')
            
                    source_port = testscript.parameters['configdict']['TG'][TG]['TEST-001']['traffic_config_dict']['source']
                    receiver_port = testscript.parameters['configdict']['TG'][TG]['TEST-001']['traffic_config_dict']['receivers']
                    traffic_args=testscript.parameters['configdict']['TG'][TG]['TEST-001']['traffic_config_dict']['params']
                     
                    src_port = [port_handle_dict[x] for x in source_port]
                    dst_port = [port_handle_dict[x] for x in receiver_port]
                    log.info('The value of src_port is : {0}'.format(src_port))
                    log.info('The value of dst_port is : {0}'.format(dst_port))
                    
                    Type5_traffic_config = configureIxNetworkRawTrafficL3New(self, traffic_args, tg_hdl=tgn_hdl, emulation_src_handle=src_port, emulation_dst_handle=dst_port)
                    log.info('The value of ixia_traffic_config is : {0}'.format(Type5_traffic_config))
                    
                    log.info('Starting the TYpe 5 Route Stream... Sleeping for 30 seeconds after starting the stream')
                    countDownTimer(30)
                    
                    stream_hdl = Type5_traffic_config['traffic_item']
                    stream_id = Type5_traffic_config['stream_id']
                    
                    x = tgn_hdl.traffic_control(action='run', handle = stream_hdl, max_wait_timer=60)
                    log.info('The value of x is : {0}'.format(x))
                    
                    if not x.status:
                        log.error(banner('The Stream {0} could not be started as expected '.format(jumbo_traffic_config.stream_id)))
                        
                    log.info(banner('Waiting for 40 seconds before collecting the stats').format(countDownTimer(40)))
        
                    stats = tgn_hdl.traffic_stats(stream = Type5_traffic_config['stream_id'], mode = 'traffic_item')
                    log.info(banner('The Value of stats is : {0}'.format(stats)))
                    tx_stat = stats.traffic_item[Type5_traffic_config['stream_id']]['tx'].total_pkt_rate
                    rx_stat = stats.traffic_item[Type5_traffic_config['stream_id']]['rx'].total_pkt_rate
                    
                    log.info('The value of tx_stat is : {0}'.format(tx_stat))
                    log.info('The value of rx_stat is : {0}'.format(rx_stat))
                    
                        
                    link_list = ['uut1_uut33_1','uut1_uut33_2']
                    
                    for intf in link_list:
                        cfg = 'show interface {0} counters  brief | xml '.format(alias_intf_mapping_dict[intf])
                        hdl=node_dict['all_dut']['uut1']
                        out = hdl.execute(cfg)
                        s = BeautifulSoup(out)
                        count = s.find('eth_outframes1').string
                        log.info('The value of count of port-channel {0} in dut UUT1  is  {1}: '.format(intf,count))
                        if not int(count) >=100:
                            log.error(banner('The following port-channel {0} on dut UUT1 is underutilized..Packet Count is : {1}'.format(alias_intf_mapping_dict[intf],count)))
                
                    log.info('Stopping the stream:')
                    x1 = tgn_hdl.traffic_control(action='stop', handle = stream_hdl,max_wait_timer=60)
                    
                    countDownTimer(30)

                    log.info('Removing the stream:')
                    y = tgn_hdl.traffic_config(mode='remove',stream_id=stream_id)
                    
                    log.info('STarting all the other streams')
                    z = tgn_hdl.traffic_control(action='run',max_wait_timer=60)
                    
                    

                res = trigger_obj.backUpAndRestoreConfigs(devices,'restore')
                
                out = trigger_obj.checkAllStreamStats(tgn_hdl) 
                
                if not out:
                    log.error('The stream has not recovered.')
                    
                    
class VXLANVxlanV6FUNC019(aetest.Testcase):

    """ L2-TRAFFIC WITHOUT ANY PAYLOAD """

    uid = 'VXLAN-L3-VxlanV6-FUNC-019'
    
    @aetest.test
    def l2TrafficWithoutAnyPayload(self,log,testscript,testbed):
        
        node_dict = testscript.parameters['node_dict']
        tg_interface_hdl_dict = testscript.parameters['tg_interface_hdl_dict'] 
        traffic_stream_dict = testscript.parameters['traffic_stream_dict'] 
        port_handle_dict = testscript.parameters['port_handle_dict']
        TGList_config_file = testscript.parameters['TGList']
        configdict = testscript.parameters['configdict'] 
        tgn_config_dict = configdict['TG']
        threshold = testscript.parameters['traffic_threshold'] 
        tgn_port_dut_mapping = testscript.parameters['tgn_port_dut_mapping']
        alias_intf_mapping_dict = testscript.parameters['alias_intf_mapping']
        configured_stream = testscript.parameters['configured_stream']
        trigger_obj = testscript.parameters['trigger_obj']

        log.info(banner('The value of configured stream is : {0}'.format(configured_stream))) 
        
        login = [node_dict['all_dut'][dut].execute('show version') for dut in node_dict['all_dut'] if re.search('uut', dut)]
                
        for TG in tgn_config_dict.keys():
            tgn_hdl = testscript.parameters['testbed_obj'].devices[TG]
            out = trigger_obj.checkAllStreamStats(tgn_hdl)
            
            devices = ['uut1','uut2','uut3','uut4','uut33',]
            if out:
                res = trigger_obj.backUpAndRestoreConfigs(devices,'backup')
                
                dst_hdl = node_dict['all_dut']['uut4']
                src_hdl = node_dict['all_dut']['uut3']
                
                cfg = 'mac address-table static 0000.0065.6565 vlan 701 interface {0}'.format(alias_intf_mapping_dict['uut4_TG1_1'])
                dst_hdl.configure(cfg)
                
                log.info(banner('Waiting for 30 seconds to start the traffic : {0}'.format(countDownTimer(30))))
                
                source_port = testscript.parameters['configdict']['TG'][TG]['TEST-002']['traffic_config_dict']['source']
                receiver_port = testscript.parameters['configdict']['TG'][TG]['TEST-002']['traffic_config_dict']['receivers']
                traffic_args=testscript.parameters['configdict']['TG'][TG]['TEST-002']['traffic_config_dict']['params']
                 
                src_port = [port_handle_dict[x] for x in source_port]
                dst_port = [port_handle_dict[x] for x in receiver_port]
                log.info('The value of src_port is : {0}'.format(src_port))
                log.info('The value of dst_port is : {0}'.format(dst_port))
                
                jumbo_traffic_config = configureIxNetworkRawTrafficL2(self, traffic_args, tg_hdl=tgn_hdl, emulation_src_handle=src_port, emulation_dst_handle=dst_port)
                log.info('The value of ixia_traffic_config is : {0}'.format(jumbo_traffic_config))
                
                
                log.info('Starting the Traffic Item without any Payload... Sleeping for 30 seeconds after starting the stream')
                countDownTimer(30)
                
                stream_hdl = jumbo_traffic_config['traffic_item']
                stream_id = jumbo_traffic_config['stream_id']
                
                x = tgn_hdl.traffic_control(action='run', handle = stream_hdl,max_wait_timer=60)
                log.info('The value of x is : {0}'.format(x))
                
                if not x.status:
                    log.error(banner('The Stream {0} could not be started as expected '.format(jumbo_traffic_config.stream_id)))
    
                stats = tgn_hdl.traffic_stats(stream = jumbo_traffic_config['stream_id'], mode = 'traffic_item')
                log.info(banner('The Value of stats is : {0}'.format(stats)))
                tx_stat = stats.traffic_item[jumbo_traffic_config['stream_id']]['tx'].total_pkt_rate
                rx_stat = stats.traffic_item[jumbo_traffic_config['stream_id']]['rx'].total_pkt_rate
                
                log.info('The value of tx_stat is : {0}'.format(tx_stat))
                log.info('The value of rx_stat is : {0}'.format(rx_stat))
                
                if abs(tx_stat-rx_stat < threshold):
                    log.info('L2 Frames W/o Payload works as expected ..... Deleting the Created stream and re-starting the other streams:')
                    
                else:
                    log.info('Jumbo Frames Traffic item is not as expected. The value of tx and rx is : {0} and {1}'.format(tx_stat,rx_stat))
                    self.failed()
                    
                log.info('Stopping the Jumbo stream:')
                x1 = tgn_hdl.traffic_control(action='stop', handle = stream_hdl,max_wait_timer=60)
                
                countDownTimer(30)

                log.info('Removing the stream:')
                y = tgn_hdl.traffic_config(mode='remove',stream_id=stream_id)
                        
                log.info('STarting all the other streams')
                z = tgn_hdl.traffic_control(action='run',max_wait_timer=60)
                
                res = trigger_obj.backUpAndRestoreConfigs(devices,'restore')
                
                log.info('waiting for 30 seconds before collecting the stats:')
                countDownTimer(30)
                out = trigger_obj.checkAllStreamStats(tgn_hdl)
                
                if not out:
                        log.error(banner('Traffic has not recovered on some of the streams Even after restoring the Original Configs.. Collecting the individual STream stats:'))
                        self.failed()
            else:
                log.error('The Initial Traffic Condition did not pass:')
                self.failed()    
                      
class VXLANVxlanV6FUNC020(aetest.Testcase):

    """ L2-TRAFFIC WITH IPv4 PAYLOAD """

    uid = 'VXLAN-L3-VxlanV6-FUNC-020'
    
    @aetest.test
    def l2TrafficWithIPv4Payload(self,log,testscript,testbed):
        
        node_dict = testscript.parameters['node_dict']
        tg_interface_hdl_dict = testscript.parameters['tg_interface_hdl_dict'] 
        traffic_stream_dict = testscript.parameters['traffic_stream_dict'] 
        port_handle_dict = testscript.parameters['port_handle_dict']
        TGList_config_file = testscript.parameters['TGList']
        configdict = testscript.parameters['configdict'] 
        tgn_config_dict = configdict['TG']
        threshold = testscript.parameters['traffic_threshold'] 
        tgn_port_dut_mapping = testscript.parameters['tgn_port_dut_mapping']
        alias_intf_mapping_dict = testscript.parameters['alias_intf_mapping']
        configured_stream = testscript.parameters['configured_stream']
        trigger_obj = testscript.parameters['trigger_obj']

        log.info(banner('The value of configured stream is : {0}'.format(configured_stream))) 
        
        login = [node_dict['all_dut'][dut].execute('show version') for dut in node_dict['all_dut'] if re.search('uut', dut)]
                
        for TG in tgn_config_dict.keys():
            tgn_hdl = testscript.parameters['testbed_obj'].devices[TG]
            out = trigger_obj.checkAllStreamStats(tgn_hdl)
            
            devices = ['uut1','uut2','uut3','uut4','uut33',]
            if out:
                res = trigger_obj.backUpAndRestoreConfigs(devices,'backup')
                
                dst_hdl = node_dict['all_dut']['uut4']
                src_hdl = node_dict['all_dut']['uut3']
                cfg1='''interface vlan 701
                        ip arp 195.100.1.55 0000.0054.5454'''
                cfg2 = 'mac address-table static 0000.0054.5454 vlan 701 interface {0}'.format(alias_intf_mapping_dict['uut4_TG1_1'])
                dst_hdl.configure(cfg1)
                dst_hdl.configure(cfg2)
                
                log.info(banner('Waiting for 30 seconds to start the traffic : {0}'.format(countDownTimer(30))))
                
                source_port = testscript.parameters['configdict']['TG'][TG]['TEST-003']['traffic_config_dict']['source']
                receiver_port = testscript.parameters['configdict']['TG'][TG]['TEST-003']['traffic_config_dict']['receivers']
                traffic_args=testscript.parameters['configdict']['TG'][TG]['TEST-003']['traffic_config_dict']['params']
                 
                src_port = [port_handle_dict[x] for x in source_port]
                dst_port = [port_handle_dict[x] for x in receiver_port]
                log.info('The value of src_port is : {0}'.format(src_port))
                log.info('The value of dst_port is : {0}'.format(dst_port))
                
                jumbo_traffic_config = configureIxNetworkRawTrafficL2(self, traffic_args, tg_hdl=tgn_hdl, emulation_src_handle=src_port, emulation_dst_handle=dst_port)
                log.info('The value of ixia_traffic_config is : {0}'.format(jumbo_traffic_config))
                
                
                log.info('Starting the Traffic Item with Ipv4 Payload... Sleeping for 30 seeconds after starting the stream')
                countDownTimer(30)
                
                stream_hdl = jumbo_traffic_config['traffic_item']
                stream_id = jumbo_traffic_config['stream_id']
                
                x = tgn_hdl.traffic_control(action='run', handle = stream_hdl,max_wait_timer=60)
                log.info('The value of x is : {0}'.format(x))
                
                if not x.status:
                    log.error(banner('The Stream {0} could not be started as expected '.format(jumbo_traffic_config.stream_id)))
    
                stats = tgn_hdl.traffic_stats(stream = jumbo_traffic_config['stream_id'], mode = 'traffic_item')
                log.info(banner('The Value of stats is : {0}'.format(stats)))
                tx_stat = stats.traffic_item[jumbo_traffic_config['stream_id']]['tx'].total_pkt_rate
                rx_stat = stats.traffic_item[jumbo_traffic_config['stream_id']]['rx'].total_pkt_rate
                
                log.info('The value of tx_stat is : {0}'.format(tx_stat))
                log.info('The value of rx_stat is : {0}'.format(rx_stat))
                
                if abs(tx_stat-rx_stat < threshold):
                    log.info('L2 Frames With IPv4  Payload works as expected ..... Deleting the Created stream and re-starting the other streams:')
                    
                else:
                    log.info('L2 Frames with IPV4  Payload Traffic item is not as expected. The value of tx and rx is : {0} and {1}'.format(tx_stat,rx_stat))
                    self.failed()
                    
                log.info('Stopping the L2 stream with IPv4 Payload:')
                x1 = tgn_hdl.traffic_control(action='stop', handle = stream_hdl,max_wait_timer=60)
                
                countDownTimer(30)

                log.info('Removing the stream:')
                y = tgn_hdl.traffic_config(mode='remove',stream_id=stream_id)
                        
                log.info('STarting all the other streams')
                z = tgn_hdl.traffic_control(action='run',max_wait_timer=60)
                
                res = trigger_obj.backUpAndRestoreConfigs(devices,'restore')
                
                log.info('waiting for 30 seconds before collecting the stats:')
                countDownTimer(30)
                out = trigger_obj.checkAllStreamStats(tgn_hdl)
                
                if not out:
                        log.error(banner('Traffic has not recovered on some of the streams Even after restoring the Original Configs.. Collecting the individual STream stats:'))
                        self.failed()
            else:
                log.error('The Initial Traffic Condition did not pass:')
                self.failed()    

class VXLANVxlanV6FUNC021(aetest.Testcase):

    """ L2-TRAFFIC WITH IPv6 PAYLOAD """

    uid = 'VXLAN-L3-VxlanV6-FUNC-021'
    
    @aetest.test
    def l2TrafficWithIPv6Payload(self,log,testscript,testbed):
        
        node_dict = testscript.parameters['node_dict']
        tg_interface_hdl_dict = testscript.parameters['tg_interface_hdl_dict'] 
        traffic_stream_dict = testscript.parameters['traffic_stream_dict'] 
        port_handle_dict = testscript.parameters['port_handle_dict']
        TGList_config_file = testscript.parameters['TGList']
        configdict = testscript.parameters['configdict'] 
        tgn_config_dict = configdict['TG']
        threshold = testscript.parameters['traffic_threshold'] 
        tgn_port_dut_mapping = testscript.parameters['tgn_port_dut_mapping']
        alias_intf_mapping_dict = testscript.parameters['alias_intf_mapping']
        configured_stream = testscript.parameters['configured_stream']
        trigger_obj = testscript.parameters['trigger_obj']

        log.info(banner('The value of configured stream is : {0}'.format(configured_stream))) 
        
        login = [node_dict['all_dut'][dut].execute('show version') for dut in node_dict['all_dut'] if re.search('uut', dut)]
                
        for TG in tgn_config_dict.keys():
            tgn_hdl = testscript.parameters['testbed_obj'].devices[TG]
            out = trigger_obj.checkAllStreamStats(tgn_hdl)
            
            devices = ['uut1','uut2','uut3','uut4','uut33',]
            if out:
                res = trigger_obj.backUpAndRestoreConfigs(devices,'backup')
                
                dst_hdl = node_dict['all_dut']['uut4']
                src_hdl = node_dict['all_dut']['uut3']
                cfg = 'mac address-table static 0000.0054.5454 vlan 701 interface {0}'.format(alias_intf_mapping_dict['uut4_TG1_1'])
                dst_hdl.configure(cfg)
                
                log.info(banner('Waiting for 30 seconds to start the traffic : {0}'.format(countDownTimer(30))))
                
                source_port = testscript.parameters['configdict']['TG'][TG]['TEST-004']['traffic_config_dict']['source']
                receiver_port = testscript.parameters['configdict']['TG'][TG]['TEST-004']['traffic_config_dict']['receivers']
                traffic_args=testscript.parameters['configdict']['TG'][TG]['TEST-004']['traffic_config_dict']['params']
                 
                src_port = [port_handle_dict[x] for x in source_port]
                dst_port = [port_handle_dict[x] for x in receiver_port]
                log.info('The value of src_port is : {0}'.format(src_port))
                log.info('The value of dst_port is : {0}'.format(dst_port))
                
                jumbo_traffic_config = configureIxNetworkRawTrafficL2(self, traffic_args, tg_hdl=tgn_hdl, emulation_src_handle=src_port, emulation_dst_handle=dst_port)
                log.info('The value of ixia_traffic_config is : {0}'.format(jumbo_traffic_config))
                
                
                log.info('Starting the Traffic Item with Ipv6 Payload... Sleeping for 30 seeconds after starting the stream')
                countDownTimer(30)
                
                stream_hdl = jumbo_traffic_config['traffic_item']
                stream_id = jumbo_traffic_config['stream_id']
                
                x = tgn_hdl.traffic_control(action='run', handle = stream_hdl,max_wait_timer=60)
                log.info('The value of x is : {0}'.format(x))
                
                if not x.status:
                    log.error(banner('The Stream {0} could not be started as expected '.format(jumbo_traffic_config.stream_id)))
    
                stats = tgn_hdl.traffic_stats(stream = jumbo_traffic_config['stream_id'], mode = 'traffic_item')
                log.info(banner('The Value of stats is : {0}'.format(stats)))
                tx_stat = stats.traffic_item[jumbo_traffic_config['stream_id']]['tx'].total_pkt_rate
                rx_stat = stats.traffic_item[jumbo_traffic_config['stream_id']]['rx'].total_pkt_rate
                
                log.info('The value of tx_stat is : {0}'.format(tx_stat))
                log.info('The value of rx_stat is : {0}'.format(rx_stat))
                
                if abs(tx_stat-rx_stat < threshold):
                    log.info('L2 Frames With IPv6  Payload works as expected ..... Deleting the Created stream and re-starting the other streams:')
                    
                else:
                    log.info('L2 Frames with IPV6  Payload Traffic item is not as expected. The value of tx and rx is : {0} and {1}'.format(tx_stat,rx_stat))
                    self.failed()
                    
                log.info('Stopping the L2 stream with IPv4 Payload:')
                x1 = tgn_hdl.traffic_control(action='stop', handle = stream_hdl,max_wait_timer=60)
                
                countDownTimer(30)

                log.info('Removing the stream:')
                y = tgn_hdl.traffic_config(mode='remove',stream_id=stream_id)
                        
                log.info('STarting all the other streams')
                z = tgn_hdl.traffic_control(action='run',max_wait_timer=60)
                
                res = trigger_obj.backUpAndRestoreConfigs(devices,'restore')
                
                log.info('waiting for 30 seconds before collecting the stats:')
                countDownTimer(30)
                out = trigger_obj.checkAllStreamStats(tgn_hdl)
                
                if not out:
                        log.error(banner('Traffic has not recovered on some of the streams Even after restoring the Original Configs.. Collecting the individual STream stats:'))
                        self.failed()
            else:
                log.error('The Initial Traffic Condition did not pass:')
                self.failed()    

class VXLANVxlanV6FUNC022(aetest.Testcase):

    """ Show TechSupport Vxlan - Check for Cores"""

    uid = 'VXLAN-L3-VxlanV6-FUNC-022'
    
    @aetest.test
    def showTechSupportVxlanAndCheckCore(self,log,testscript,testbed):
        
        node_dict = testscript.parameters['node_dict']
        tg_interface_hdl_dict = testscript.parameters['tg_interface_hdl_dict'] 
        traffic_stream_dict = testscript.parameters['traffic_stream_dict'] 
        port_handle_dict = testscript.parameters['port_handle_dict']
        TGList_config_file = testscript.parameters['TGList']
        configdict = testscript.parameters['configdict'] 
        tgn_config_dict = configdict['TG']
        threshold = testscript.parameters['traffic_threshold'] 
        tgn_port_dut_mapping = testscript.parameters['tgn_port_dut_mapping']
        alias_intf_mapping_dict = testscript.parameters['alias_intf_mapping']
        configured_stream = testscript.parameters['configured_stream']
        trigger_obj = testscript.parameters['trigger_obj']

        log.info(banner('The value of configured stream is : {0}'.format(configured_stream))) 
        
        login = [node_dict['all_dut'][dut].execute('show version') for dut in node_dict['all_dut'] if re.search('uut', dut)]
                
        for TG in tgn_config_dict.keys():
            tgn_hdl = testscript.parameters['testbed_obj'].devices[TG]
            out = trigger_obj.checkAllStreamStats(tgn_hdl)
            
            if out:
                
                dev_hdl = node_dict['all_dut']['uut1']
                cfg1 = 'delete bootflash:sh_ts_vxlan no-prompt'
                cfg2 = 'clear logging logfile'
                cfg3 = 'show tech-support vxlan > sh_ts_vxlan'
                dev_hdl.configure(cfg1)
                dev_hdl.execute(cfg2)
                log.info(banner('Waiting for 600 seconds to collect the show techsupport :'))
                out1 = dev_hdl.configure(cfg3,timeout=600)
                
                log.info(banner('Checking for any Syntax Error in the output of show-tech-support vxlan'))
                
                out2 = dev_hdl.execute('show logging logfile')
                
                for items in [out1,out2]:
                    for line in items:
                        match1 = re.findall('syntax',line,re.I)
                        match2 = re.findall('Error',line,re.I)
                        match3 = re.findall('Fail',line,re.I)
                        if match1:
                            log.info('The following lines has syntax in it : {0}'.format(line))
                        elif match2:
                            log.info('The following lines has syntax in it : {0}'.format(line))
                        elif match3:
                            log.info('The following lines has syntax in it : {0}'.format(line))       
                    else:
                        log.info(banner('No Errors / Failures / Syntax Errors found in file {0}...'.format(items)))
                            
                log.info(banner('checking for Show tech support stored in bootflash:'))
                
                out3 = dev_hdl.execute('dir | grep sh_ts_vxlan | xml')
                s = BeautifulSoup(out3)
                if out3:
                    filename = s.find('fname').string
                    if filename == 'sh_ts_vxlan':
                        log.info(banner('The Show tech is stored in bootflash:...'))
                    
                log.info(banner('checking for Core:'))
                
                out4 = dev_hdl.execute('show core')
                for line in out4:
                    match4 = re.findall('\d+',line)
                    if match4:
                        log.info('Some Core is found : {0}'.line)
                        self.failed()
                
            else:
                log.error('The Initial Traffic Condition did not pass:')
                self.failed()  

class VXLANVxlanV6FUNC023(aetest.Testcase):

    """ Checking Vxlan CC - config-check"""

    uid = 'VXLAN-L3-VxlanV6-FUNC-023'
    
    @aetest.test
    def vxlanConfigCheckConsistencyChecker(self,log,testscript,testbed):
        
        node_dict = testscript.parameters['node_dict']
        tg_interface_hdl_dict = testscript.parameters['tg_interface_hdl_dict'] 
        traffic_stream_dict = testscript.parameters['traffic_stream_dict'] 
        port_handle_dict = testscript.parameters['port_handle_dict']
        TGList_config_file = testscript.parameters['TGList']
        configdict = testscript.parameters['configdict'] 
        tgn_config_dict = configdict['TG']
        threshold = testscript.parameters['traffic_threshold'] 
        tgn_port_dut_mapping = testscript.parameters['tgn_port_dut_mapping']
        alias_intf_mapping_dict = testscript.parameters['alias_intf_mapping']
        configured_stream = testscript.parameters['configured_stream']
        trigger_obj = testscript.parameters['trigger_obj']

        log.info(banner('The value of configured stream is : {0}'.format(configured_stream))) 
        
        login = [node_dict['all_dut'][dut].execute('show version') for dut in node_dict['all_dut'] if re.search('uut', dut)]
                
        for TG in tgn_config_dict.keys():
            tgn_hdl = testscript.parameters['testbed_obj'].devices[TG]
            out = trigger_obj.checkAllStreamStats(tgn_hdl)
            
            devices = trigger_obj.getDeviceDict('all_vtep')
            flag =0
            if out:
                for dut in devices:
                    dev_hdl = node_dict['all_dut'][dut]
                    cfg1 = 'sh consistency-checker vxlan config-check'
                    out1 = dev_hdl.execute(cfg1,timeout=600)
                    log.info(banner('The Vxlan consistency Check config-check Output is : {0}'.format(out1)))
                    for line in out1.splitlines():
                        match = re.search(('error|fail'),line,re.I)
                        if match:
                            log.error(banner('The following Error / Failure occurred {0} on dut {2} and the whole output is : {1}'.format(line,out1,dut)))
                            flag = 1
                            
                if flag:
                    log.error(banner('The Vxlan CC config-Check Faield.. '))
                    self.failed()
                    
            else:
                log.error('The Initial Traffic Condition did not pass:')
                self.failed()  
                
class VXLANVxlanV6FUNC024(aetest.Testcase):

    """ Checking Vxlan CC - config-check Brief"""

    uid = 'VXLAN-L3-VxlanV6-FUNC-024'
    
    @aetest.test
    def vxlanConfigCheckConsistencyCheckerBrief(self,log,testscript,testbed):
        
        node_dict = testscript.parameters['node_dict']
        tg_interface_hdl_dict = testscript.parameters['tg_interface_hdl_dict'] 
        traffic_stream_dict = testscript.parameters['traffic_stream_dict'] 
        port_handle_dict = testscript.parameters['port_handle_dict']
        TGList_config_file = testscript.parameters['TGList']
        configdict = testscript.parameters['configdict'] 
        tgn_config_dict = configdict['TG']
        threshold = testscript.parameters['traffic_threshold'] 
        tgn_port_dut_mapping = testscript.parameters['tgn_port_dut_mapping']
        alias_intf_mapping_dict = testscript.parameters['alias_intf_mapping']
        configured_stream = testscript.parameters['configured_stream']
        trigger_obj = testscript.parameters['trigger_obj']

        log.info(banner('The value of configured stream is : {0}'.format(configured_stream))) 
        
        login = [node_dict['all_dut'][dut].execute('show version') for dut in node_dict['all_dut'] if re.search('uut', dut)]
                
        for TG in tgn_config_dict.keys():
            tgn_hdl = testscript.parameters['testbed_obj'].devices[TG]
            out = trigger_obj.checkAllStreamStats(tgn_hdl)
            
            devices = trigger_obj.getDeviceDict('all_vtep')
            flag =0
            if out:
                for dut in devices:
                    dev_hdl = node_dict['all_dut'][dut]
                    cfg1 = 'sh consistency-checker vxlan config-check brief'
                    out1 = dev_hdl.execute(cfg1,timeout=600)
                    log.info(banner('The Vxlan consistency Check config-check Brief Output is : {0}'.format(out1)))
                    match=re.findall('CC_STATUS_OK',out1,re.M)
                    if match:
                        if not len(match) == 2:
                            log.error(banner('The Vxlan consistency Check config-check Brief output is not as expected on dut {0} the whole output is : {1} and occurance of CC_STATUS_OK is : {2}'.format(dut,out1,len(match))))
                            flag = 1
                            
                if flag:
                    log.error(banner('The Vxlan CC config-Check Brief output.. '))
                    self.failed()
                    
            else:
                log.error('The Initial Traffic Condition did not pass:')
                self.failed()  

class VXLANVxlanV6FUNC025(aetest.Testcase):

    """ Checking Vxlan CC - config-check Detail"""

    uid = 'VXLAN-L3-VxlanV6-FUNC-025'
    
    @aetest.test
    def vxlanConfigCheckConsistencyCheckerDetail(self,log,testscript,testbed):
        
        node_dict = testscript.parameters['node_dict']
        tg_interface_hdl_dict = testscript.parameters['tg_interface_hdl_dict'] 
        traffic_stream_dict = testscript.parameters['traffic_stream_dict'] 
        port_handle_dict = testscript.parameters['port_handle_dict']
        TGList_config_file = testscript.parameters['TGList']
        configdict = testscript.parameters['configdict'] 
        tgn_config_dict = configdict['TG']
        threshold = testscript.parameters['traffic_threshold'] 
        tgn_port_dut_mapping = testscript.parameters['tgn_port_dut_mapping']
        alias_intf_mapping_dict = testscript.parameters['alias_intf_mapping']
        configured_stream = testscript.parameters['configured_stream']
        trigger_obj = testscript.parameters['trigger_obj']

        log.info(banner('The value of configured stream is : {0}'.format(configured_stream))) 
        
        
        login = [node_dict['all_dut'][dut].execute('show version') for dut in node_dict['all_dut'] if re.search('uut', dut)]
                
        for TG in tgn_config_dict.keys():
            tgn_hdl = testscript.parameters['testbed_obj'].devices[TG]
            out = trigger_obj.checkAllStreamStats(tgn_hdl)
            
            devices = trigger_obj.getDeviceDict('all_vtep')
            flag =0
            if out:
                for dut in devices:
                    dev_hdl = node_dict['all_dut'][dut]
                    cfg1 = 'sh consistency-checker vxlan config-check detail'
                    cfg2 = ''
                    out1 = dev_hdl.execute(cfg1,timeout=600)
                    log.info(banner('The Vxlan consistency Check config-check Brief Output is : {0}'.format(out1)))
                    match=re.findall('CC_STATUS_OK',out1,re.M)
                    if match:
                        if not len(match) == 2:
                            log.error(banner('The Vxlan consistency Check config-check Brief output is not as expected on dut {0} the whole output is : {1} and occurance of CC_STATUS_OK is : {2}'.format(dut,out1,len(match))))
                            flag = 1
                            
                if flag:
                    log.error(banner('The Vxlan CC config-Check Brief output.. '))
                    self.failed()
                    
            else:
                log.error('The Initial Traffic Condition did not pass:')
                self.failed()  

class VXLANVxlanV6FUNC026(aetest.Testcase):

    """ Checking Vxlan CC - config-check Verbose"""

    uid = 'VXLAN-L3-VxlanV6-FUNC-026'
    
    @aetest.test
    def vxlanConfigCheckConsistencyCheckerVerbose(self,log,testscript,testbed):
        
        node_dict = testscript.parameters['node_dict']
        tg_interface_hdl_dict = testscript.parameters['tg_interface_hdl_dict'] 
        traffic_stream_dict = testscript.parameters['traffic_stream_dict'] 
        port_handle_dict = testscript.parameters['port_handle_dict']
        TGList_config_file = testscript.parameters['TGList']
        configdict = testscript.parameters['configdict'] 
        tgn_config_dict = configdict['TG']
        threshold = testscript.parameters['traffic_threshold'] 
        tgn_port_dut_mapping = testscript.parameters['tgn_port_dut_mapping']
        alias_intf_mapping_dict = testscript.parameters['alias_intf_mapping']
        configured_stream = testscript.parameters['configured_stream']
        trigger_obj = testscript.parameters['trigger_obj']

        log.info(banner('The value of configured stream is : {0}'.format(configured_stream))) 
        
        login = [node_dict['all_dut'][dut].execute('show version') for dut in node_dict['all_dut'] if re.search('uut', dut)]
                
        for TG in tgn_config_dict.keys():
            tgn_hdl = testscript.parameters['testbed_obj'].devices[TG]
            out = trigger_obj.checkAllStreamStats(tgn_hdl)
            
            devices = trigger_obj.getDeviceDict('all_vtep')
            flag =0
            if out:
                for dut in devices:
                    dev_hdl = node_dict['all_dut'][dut]
                    cfg1 = 'sh consistency-checker vxlan config-check verbose-mode'
                    out1 = dev_hdl.execute(cfg1,timeout=600)
                    log.info(banner('The Vxlan consistency Check config-check Verbose Output is : {0}'.format(out1)))
                    match=re.findall('No Config Issues',out1,re.M)
                    if not match:
                        log.error(banner('The Vxlan consistency Check config-check Verbose-mode output is not as expected on dut {0} the whole output is : {1} and occurance of "No Config Issues" is : {2}'.format(dut,out1,match)))
                        flag = 1
                        
                    cfg2 = 'sh consistency-checker vxlan config-check verbose-mode brief'
                    out2 = dev_hdl.execute(cfg2,timeout=600)
                    match=re.findall('CC_STATUS_OK',out2,re.M)
                    if match:
                        if not len(match) == 2:
                            log.error(banner('The Vxlan consistency Check config-check Brief output is not as expected on dut {0} the whole output is : {1} and occurance of CC_STATUS_OK is : {2}'.format(dut,out2,len(match))))
                            flag = 1               
                            
                    cfg3 = 'sh consistency-checker vxlan config-check verbose-mode detail '
                    out3 = dev_hdl.execute(cfg3,timeout=600)
                    match=re.findall('CC_STATUS_OK',out3,re.M)
                    if match:
                        if not len(match) == 2:
                            log.error(banner('The Vxlan consistency Check config-check Brief output is not as expected on dut {0} the whole output is : {1} and occurance of CC_STATUS_OK is : {2}'.format(dut,out3,len(match))))
                            flag = 1             
                              
                if flag:
                    log.error(banner('The Vxlan CC config-Check Brief output.. '))
                    self.failed()
                    
            else:
                log.error('The Initial Traffic Condition did not pass:')
                self.failed()  
                
                
class VXLANVxlanV6FUNC027(aetest.Testcase):

    """ Checking Vxlan CC - Infra"""

    uid = 'VXLAN-L3-VxlanV6-FUNC-027'
    
    @aetest.test
    def vxlanConsistencyCheckInfra(self,log,testscript,testbed):
        
        node_dict = testscript.parameters['node_dict']
        tg_interface_hdl_dict = testscript.parameters['tg_interface_hdl_dict'] 
        traffic_stream_dict = testscript.parameters['traffic_stream_dict'] 
        port_handle_dict = testscript.parameters['port_handle_dict']
        TGList_config_file = testscript.parameters['TGList']
        configdict = testscript.parameters['configdict'] 
        tgn_config_dict = configdict['TG']
        threshold = testscript.parameters['traffic_threshold'] 
        tgn_port_dut_mapping = testscript.parameters['tgn_port_dut_mapping']
        alias_intf_mapping_dict = testscript.parameters['alias_intf_mapping']
        configured_stream = testscript.parameters['configured_stream']
        trigger_obj = testscript.parameters['trigger_obj']

        log.info(banner('The value of configured stream is : {0}'.format(configured_stream))) 
        
        login = [node_dict['all_dut'][dut].execute('show version') for dut in node_dict['all_dut'] if re.search('uut', dut)]
                
        for TG in tgn_config_dict.keys():
            tgn_hdl = testscript.parameters['testbed_obj'].devices[TG]
            out = trigger_obj.checkAllStreamStats(tgn_hdl)
            
            devices = trigger_obj.getDeviceDict('all_vtep')
            flag =0
            if out:
                for dut in devices:
                    dev_hdl = node_dict['all_dut'][dut]
                    cfg1 = 'sh consistency-checker vxlan infra '
                    out1 = dev_hdl.execute(cfg1,timeout=600)
                    log.info(banner('The Vxlan consistency Check Infra  Output is : {0}'.format(out1)))
                    for line in out1.splitlines():
                        match = re.search(('traceback|error|fail'),line,re.I)
                        if match:
                            log.error(banner('The following Error / Failure occurred {0} on dut {2} and the whole output is : {1}'.format(line,out1,dut)))
                            flag = 1
                            
                if flag:
                    log.error(banner('The Vxlan CC config-Check Brief output.. '))
                    self.failed()
                    
            else:
                log.error('The Initial Traffic Condition did not pass:')
                self.failed()  
                
class VXLANVxlanV6FUNC028(aetest.Testcase):

    """ Checking Vxlan CC - Infra Brief"""

    uid = 'VXLAN-L3-VxlanV6-FUNC-028'
    
    @aetest.test
    def vxlanInfraConsistencyCheckerBrief(self,log,testscript,testbed):
        
        node_dict = testscript.parameters['node_dict']
        tg_interface_hdl_dict = testscript.parameters['tg_interface_hdl_dict'] 
        traffic_stream_dict = testscript.parameters['traffic_stream_dict'] 
        port_handle_dict = testscript.parameters['port_handle_dict']
        TGList_config_file = testscript.parameters['TGList']
        configdict = testscript.parameters['configdict'] 
        tgn_config_dict = configdict['TG']
        threshold = testscript.parameters['traffic_threshold'] 
        tgn_port_dut_mapping = testscript.parameters['tgn_port_dut_mapping']
        alias_intf_mapping_dict = testscript.parameters['alias_intf_mapping']
        configured_stream = testscript.parameters['configured_stream']
        trigger_obj = testscript.parameters['trigger_obj']

        log.info(banner('The value of configured stream is : {0}'.format(configured_stream))) 
        
        login = [node_dict['all_dut'][dut].execute('show version') for dut in node_dict['all_dut'] if re.search('uut', dut)]
                
        for TG in tgn_config_dict.keys():
            tgn_hdl = testscript.parameters['testbed_obj'].devices[TG]
            out = trigger_obj.checkAllStreamStats(tgn_hdl)
            
            devices = trigger_obj.getDeviceDict('all_vtep')
            flag =0
            if out:
                for dut in devices:
                    dev_hdl = node_dict['all_dut'][dut]
                    cfg1 = 'sh consistency-checker vxlan infra brief'
                    out1 = dev_hdl.execute(cfg1,timeout=600)
                    log.info(banner('The Vxlan consistency Check config-check Brief Output is : {0}'.format(out1)))
                    match=re.findall('CC_STATUS_OK',out1,re.M)
                    if match:
                        if not len(match) == 2:
                            log.error(banner('The Vxlan consistency Check config-check Brief output is not as expected on dut {0} the whole output is : {1} and occurance of CC_STATUS_OK is : {2}'.format(dut,out1,len(match))))
                            flag = 1
                            
                if flag:
                    log.error(banner('The Vxlan CC config-Check Brief output.. '))
                    self.failed()
                    
            else:
                log.error('The Initial Traffic Condition did not pass:')
                self.failed()  
                
class VXLANVxlanV6FUNC029(aetest.Testcase):

    """ Checking Vxlan CC - Infra Detail"""

    uid = 'VXLAN-L3-VxlanV6-FUNC-029'
    
    @aetest.test
    def vxlanInfraConsistencyCheckerDetail(self,log,testscript,testbed):
        
        node_dict = testscript.parameters['node_dict']
        tg_interface_hdl_dict = testscript.parameters['tg_interface_hdl_dict'] 
        traffic_stream_dict = testscript.parameters['traffic_stream_dict'] 
        port_handle_dict = testscript.parameters['port_handle_dict']
        TGList_config_file = testscript.parameters['TGList']
        configdict = testscript.parameters['configdict'] 
        tgn_config_dict = configdict['TG']
        threshold = testscript.parameters['traffic_threshold'] 
        tgn_port_dut_mapping = testscript.parameters['tgn_port_dut_mapping']
        alias_intf_mapping_dict = testscript.parameters['alias_intf_mapping']
        configured_stream = testscript.parameters['configured_stream']
        trigger_obj = testscript.parameters['trigger_obj']

        log.info(banner('The value of configured stream is : {0}'.format(configured_stream))) 
        
        login = [node_dict['all_dut'][dut].execute('show version') for dut in node_dict['all_dut'] if re.search('uut', dut)]
                
        for TG in tgn_config_dict.keys():
            tgn_hdl = testscript.parameters['testbed_obj'].devices[TG]
            out = trigger_obj.checkAllStreamStats(tgn_hdl)
            
            devices = trigger_obj.getDeviceDict('all_vtep')
            flag =0
            if out:
                for dut in devices:
                    dev_hdl = node_dict['all_dut'][dut]
                    cfg1 = 'sh consistency-checker vxlan infra detail'
                    cfg2 = ''
                    out1 = dev_hdl.execute(cfg1,timeout=600)
                    log.info(banner('The Vxlan consistency Check config-check Brief Output is : {0}'.format(out1)))
                    match=re.findall('CC_STATUS_OK',out1,re.M)
                    if match:
                        if not len(match) == 2:
                            log.error(banner('The Vxlan consistency Check config-check Brief output is not as expected on dut {0} the whole output is : {1} and occurance of CC_STATUS_OK is : {2}'.format(dut,out1,len(match))))
                            flag = 1
                            
                if flag:
                    log.error(banner('The Vxlan CC config-Check Brief output.. '))
                    self.failed()
                    
            else:
                log.error('The Initial Traffic Condition did not pass:')
                self.failed()  


class VXLANVxlanV6FUNC030(aetest.Testcase):

    """ Checking Vxlan CC - Infra Verbose"""

    uid = 'VXLAN-L3-VxlanV6-FUNC-030'
    
    @aetest.test
    def vxlanInfraConsistencyCheckerVerbose(self,log,testscript,testbed):
        
        node_dict = testscript.parameters['node_dict']
        tg_interface_hdl_dict = testscript.parameters['tg_interface_hdl_dict'] 
        traffic_stream_dict = testscript.parameters['traffic_stream_dict'] 
        port_handle_dict = testscript.parameters['port_handle_dict']
        TGList_config_file = testscript.parameters['TGList']
        configdict = testscript.parameters['configdict'] 
        tgn_config_dict = configdict['TG']
        threshold = testscript.parameters['traffic_threshold'] 
        tgn_port_dut_mapping = testscript.parameters['tgn_port_dut_mapping']
        alias_intf_mapping_dict = testscript.parameters['alias_intf_mapping']
        configured_stream = testscript.parameters['configured_stream']
        trigger_obj = testscript.parameters['trigger_obj']

        log.info(banner('The value of configured stream is : {0}'.format(configured_stream))) 
        
        login = [node_dict['all_dut'][dut].execute('show version') for dut in node_dict['all_dut'] if re.search('uut', dut)]
                
        for TG in tgn_config_dict.keys():
            tgn_hdl = testscript.parameters['testbed_obj'].devices[TG]
            out = trigger_obj.checkAllStreamStats(tgn_hdl)
            
            devices = trigger_obj.getDeviceDict('all_vtep')
            flag =0
            if out:
                for dut in devices:
                    dev_hdl = node_dict['all_dut'][dut]
                    cfg1 = 'sh consistency-checker vxlan infra verbose-mode'
                    out1 = dev_hdl.execute(cfg1,timeout=600)
                    log.info(banner('The Vxlan consistency Check config-check Verbose Output is : {0}'.format(out1)))
                    for line in out1.splitlines():
                        match = re.search(('traceback|error|fail'),line,re.I)
                        if match:
                            log.error(banner('The following Error / Failure occurred {0} on dut {2} and the whole output is : {1}'.format(line,out1,dut)))
                            flag = 1
                            
                        
                    cfg2 = 'sh consistency-checker vxlan infra verbose-mode brief'
                    out2 = dev_hdl.execute(cfg2,timeout=600)
                    match=re.findall('CC_STATUS_OK',out2,re.M)
                    if match:
                        if not len(match) == 2:
                            log.error(banner('The Vxlan consistency Check config-check Brief output is not as expected on dut {0} the whole output is : {1} and occurance of CC_STATUS_OK is : {2}'.format(dut,out2,len(match))))
                            flag = 1               
                            
                    cfg3 = 'sh consistency-checker vxlan infra verbose-mode detail '
                    out3 = dev_hdl.execute(cfg3,timeout=600)
                    match=re.findall('CC_STATUS_OK',out3,re.M)
                    if match:
                        if not len(match) == 2:
                            log.error(banner('The Vxlan consistency Check config-check Brief output is not as expected on dut {0} the whole output is : {1} and occurance of CC_STATUS_OK is : {2}'.format(dut,out3,len(match))))
                            flag = 1             
                              
                if flag:
                    log.error(banner('The Vxlan CC config-Check Brief output.. '))
                    self.failed()
                    
            else:
                log.error('The Initial Traffic Condition did not pass:')
                self.failed()  

class VXLANVxlanV6FUNC031(aetest.Testcase):

    """ Checking Vxlan CC - L2 Brief"""

    uid = 'VXLAN-L3-VxlanV6-FUNC-031'
    
    @aetest.test
    def vxlanL2ConsistencyCheckerAll(self,log,testscript,testbed):
        
        node_dict = testscript.parameters['node_dict']
        tg_interface_hdl_dict = testscript.parameters['tg_interface_hdl_dict'] 
        traffic_stream_dict = testscript.parameters['traffic_stream_dict'] 
        port_handle_dict = testscript.parameters['port_handle_dict']
        TGList_config_file = testscript.parameters['TGList']
        configdict = testscript.parameters['configdict'] 
        tgn_config_dict = configdict['TG']
        threshold = testscript.parameters['traffic_threshold'] 
        tgn_port_dut_mapping = testscript.parameters['tgn_port_dut_mapping']
        alias_intf_mapping_dict = testscript.parameters['alias_intf_mapping']
        configured_stream = testscript.parameters['configured_stream']
        trigger_obj = testscript.parameters['trigger_obj']

        log.info(banner('The value of configured stream is : {0}'.format(configured_stream))) 
        login = [node_dict['all_dut'][dut].execute('show version') for dut in node_dict['all_dut'] if re.search('uut', dut)]
                
        for TG in tgn_config_dict.keys():
            tgn_hdl = testscript.parameters['testbed_obj'].devices[TG]
            out = trigger_obj.checkAllStreamStats(tgn_hdl)
            
            devices = trigger_obj.getDeviceDict('all_vtep')
            flag =0
            if out:
                for dut in devices:
                    dev_hdl = node_dict['all_dut'][dut]
                    cfg1 = 'sh consistency-checker vxlan l2 module 1'
                    out1 = dev_hdl.execute(cfg1,timeout=600)
                    log.info(banner('The Vxlan consistency Check l2 module 1 Output is : {0}'.format(out1)))
                    for line in out1.splitlines():
                        match = re.search(('traceback|error|fail'),line,re.I)
                        if match:
                            log.error(banner('The following Error / Failure occurred {0} on dut {2} and the whole output is : {1}'.format(line,out1,dut)))
                            flag = 1
                            
                        
                    cfg2 = 'sh consistency-checker vxlan l2 module 1 brief'
                    out2 = dev_hdl.execute(cfg2,timeout=600)
                    match=re.findall('CC_STATUS_OK',out2,re.M)
                    if match:
                        if not len(match) == 2:
                            log.error(banner('The Vxlan consistency Check l2 module 1 Brief output is not as expected on dut {0} the whole output is : {1} and occurance of CC_STATUS_OK is : {2}'.format(dut,out2,len(match))))
                            flag = 1               
                            
                    cfg3 = 'sh consistency-checker vxlan l2 module 1 detail '
                    out3 = dev_hdl.execute(cfg3,timeout=600)
                    match=re.findall('CC_STATUS_OK',out3,re.M)
                    if match:
                        if not len(match) == 2:
                            log.error(banner('The Vxlan consistency Check l2 module 1 detail output is not as expected on dut {0} the whole output is : {1} and occurance of CC_STATUS_OK is : {2}'.format(dut,out3,len(match))))
                            flag = 1             
                              
                if flag:
                    log.error(banner('The Vxlan CC config-Check Brief output.. '))
                    self.failed()
                    
            else:
                log.error('The Initial Traffic Condition did not pass:')
                self.failed()  


class VXLANVxlanV6FUNC032(aetest.Testcase):

    """ Checking Vxlan CC - L2 MAC ADDRSS """

    uid = 'VXLAN-L3-VxlanV6-FUNC-032'
    
    @aetest.test
    def vxlanL2MacAddressConsistencyChecker(self,log,testscript,testbed):
        
        node_dict = testscript.parameters['node_dict']
        tg_interface_hdl_dict = testscript.parameters['tg_interface_hdl_dict'] 
        traffic_stream_dict = testscript.parameters['traffic_stream_dict'] 
        port_handle_dict = testscript.parameters['port_handle_dict']
        TGList_config_file = testscript.parameters['TGList']
        configdict = testscript.parameters['configdict'] 
        tgn_config_dict = configdict['TG']
        threshold = testscript.parameters['traffic_threshold'] 
        tgn_port_dut_mapping = testscript.parameters['tgn_port_dut_mapping']
        alias_intf_mapping_dict = testscript.parameters['alias_intf_mapping']
        configured_stream = testscript.parameters['configured_stream']
        trigger_obj = testscript.parameters['trigger_obj']

        log.info(banner('The value of configured stream is : {0}'.format(configured_stream))) 
        
        login = [node_dict['all_dut'][dut].execute('show version') for dut in node_dict['all_dut'] if re.search('uut', dut)]
                
        for TG in tgn_config_dict.keys():
            tgn_hdl = testscript.parameters['testbed_obj'].devices[TG]
            out = trigger_obj.checkAllStreamStats(tgn_hdl)
            
            devices = trigger_obj.getDeviceDict('all_vtep')
            flag =0
            if out:
                for dut in devices:
                    dev_hdl = node_dict['all_dut'][dut]
                    
                    cfg0 = 'sh mac address-table  | xml  | grep disp_mac_addr'
                    mac_add_list = []
                    out0 = dev_hdl.execute(cfg0,timeout=600)
                    for line in out0.splitlines():
                        s=BeautifulSoup(line)
                        try:
                            b = s.find('disp_mac_addr').string
                            if b:
                                mac_add_list.append(b)
                        except:
                            log.info(banner('No Match found. The line is : {0}'.format(line)))
                    
                    log.info(banner('The value of mac_add_list is  : {0}'.format(mac_add_list)))
                    for i in range(0,1):
                        log.info(banner('************* ITERATION {0} ***************'.format(i+1)))
                        c = random.randint(0,len(mac_add_list)-2)
                        mac = mac_add_list[c]
                        log.info(banner('The value of mac is : {0}'.format(mac)))
                        cfg1 = 'sh consistency-checker vxlan l2 mac-address {0} module 1'.format(mac)
                        out1 = dev_hdl.execute(cfg1,timeout=600)
                        log.info(banner('The Vxlan consistency Check l2 module 1 Output is : {0}'.format(out1)))
                        for line in out1.splitlines():
                            match = re.search(('traceback|error|fail'),line,re.I)
                            if match:
                                log.error(banner('The following Error / Failure occurred {0} on dut {2} and the whole output is : {1}'.format(line,out1,dut)))
                                flag = 1
                                
                            
                        cfg2 = 'sh consistency-checker vxlan l2 mac-address {0} module 1 brief'.format(mac)
                        out2 = dev_hdl.execute(cfg2,timeout=600)
                        match=re.findall('CC_STATUS_OK',out2,re.M)
                        if match:
                            if not len(match) == 2:
                                log.error(banner('The Vxlan consistency Check l2 module 1 Brief output is not as expected on dut {0} the whole output is : {1} and occurance of CC_STATUS_OK is : {2}'.format(dut,out2,len(match))))
                                flag = 1               
                                
                        cfg3 = 'sh consistency-checker vxlan l2 mac-address {0} module 1 detail'.format(mac)
                        out3 = dev_hdl.execute(cfg3,timeout=600)
                        match=re.findall('CC_STATUS_OK',out3,re.M)
                        if match:
                            if not len(match) == 2:
                                log.error(banner('The Vxlan consistency Check l2 module 1 detail output is not as expected on dut {0} the whole output is : {1} and occurance of CC_STATUS_OK is : {2}'.format(dut,out3,len(match))))
                                flag = 1             
                                  
                    if flag:
                        log.error(banner('The Vxlan CC L2 MAC is Failed ... Check logs for details '))
                        self.failed()
                    
            else:
                log.error('The Initial Traffic Condition did not pass:')
                self.failed()



class VXLANVxlanV6FUNC033(aetest.Testcase):

    """ Checking Vxlan CC - L3 """

    uid = 'VXLAN-L3-VxlanV6-FUNC-033'
    
    @aetest.test
    def vxlanL3ConsistencyChecker(self,log,testscript,testbed):
        
        node_dict = testscript.parameters['node_dict']
        tg_interface_hdl_dict = testscript.parameters['tg_interface_hdl_dict'] 
        traffic_stream_dict = testscript.parameters['traffic_stream_dict'] 
        port_handle_dict = testscript.parameters['port_handle_dict']
        TGList_config_file = testscript.parameters['TGList']
        configdict = testscript.parameters['configdict'] 
        tgn_config_dict = configdict['TG']
        threshold = testscript.parameters['traffic_threshold'] 
        tgn_port_dut_mapping = testscript.parameters['tgn_port_dut_mapping']
        alias_intf_mapping_dict = testscript.parameters['alias_intf_mapping']
        configured_stream = testscript.parameters['configured_stream']
        trigger_obj = testscript.parameters['trigger_obj']

        log.info(banner('The value of configured stream is : {0}'.format(configured_stream))) 
        
        login = [node_dict['all_dut'][dut].execute('show version') for dut in node_dict['all_dut'] if re.search('uut', dut)]
                
        for TG in tgn_config_dict.keys():
            tgn_hdl = testscript.parameters['testbed_obj'].devices[TG]
            out = trigger_obj.checkAllStreamStats(tgn_hdl)
            
            devices = trigger_obj.getDeviceDict('all_vtep')
            flag =0
            if out:
                for dut in devices:
                    dev_hdl = node_dict['all_dut'][dut]
                    cfg1 = 'test consistency-checker forwarding ipv4 vrf all module all'
                    cfg2 = 'test consistency-checker forwarding ipv6 vrf all module all'
                    
                    dev_hdl.execute(cfg1)
                    dev_hdl.execute(cfg2)
                    
                    list_cfg = ['sh consistency-checker vxlan l3  vrf all report','sh consistency-checker vxlan l3  vrf all start-scan']

                    for cfg in list_cfg:
                        log.info(banner('The Config Chosen is : {0}'.format(cfg)))

                        out1 = dev_hdl.execute(cfg  ,timeout=600)
                        log.info(banner('The cfg Output is : {0}'.format(cfg)))
                        for line in out1.splitlines():
                            match = re.search(('traceback|error|fail'),line,re.I)
                            if match:
                                log.error(banner('The following Error / Failure occurred {0} on dut {2} and the whole output is : {1}'.format(line,out1,dut)))
                                flag = 1 
                                  
                    if flag:
                        log.error(banner('The Vxlan CC L2 MAC is Failed ... Check logs for details '))
                        self.failed()
                    
            else:
                log.error('The Initial Traffic Condition did not pass:')
                self.failed()  

class VXLANVxlanV6FUNC034(aetest.Testcase):

    """ Checking Vxlan CC - L3 Singke Route """

    uid = 'VXLAN-L3-VxlanV6-FUNC-034'
    
    @aetest.test
    def vxlanL3SingleRouteConsistencyChecker(self,log,testscript,testbed):
        
        node_dict = testscript.parameters['node_dict']
        tg_interface_hdl_dict = testscript.parameters['tg_interface_hdl_dict'] 
        traffic_stream_dict = testscript.parameters['traffic_stream_dict'] 
        port_handle_dict = testscript.parameters['port_handle_dict']
        TGList_config_file = testscript.parameters['TGList']
        configdict = testscript.parameters['configdict'] 
        tgn_config_dict = configdict['TG']
        threshold = testscript.parameters['traffic_threshold'] 
        tgn_port_dut_mapping = testscript.parameters['tgn_port_dut_mapping']
        alias_intf_mapping_dict = testscript.parameters['alias_intf_mapping']
        configured_stream = testscript.parameters['configured_stream']
        trigger_obj = testscript.parameters['trigger_obj']

        log.info(banner('The value of configured stream is : {0}'.format(configured_stream))) 
        
        login = [node_dict['all_dut'][dut].execute('show version') for dut in node_dict['all_dut'] if re.search('uut', dut)]
                
        for TG in tgn_config_dict.keys():
            tgn_hdl = testscript.parameters['testbed_obj'].devices[TG]
            out = trigger_obj.checkAllStreamStats(tgn_hdl)
            
            devices = trigger_obj.getDeviceDict('all_vtep')
            flag =0
            if out:
                for dut in devices:
                    dev_hdl = node_dict['all_dut'][dut]
                    cfg1 = 'test consistency-checker forwarding ipv4 vrf all module all'
                    cfg2 = 'test consistency-checker forwarding ipv6 vrf all module all'
                    
                    dev_hdl.execute(cfg1)
                    dev_hdl.execute(cfg2)
                    
                    cfg3 = 'sh ip route bgp-65100 all vrf V6-001 | xml | grep ipprefix'
                    ip_list = []
                    out3 = dev_hdl.execute(cfg3,timeout=600)
                    for line in out3.splitlines():
                        s=BeautifulSoup(line)
                        try:
                            b = s.find('ipprefix').string
                            if b:
                                ip_list.append(b)
                        except:
                            log.info(banner('No Match found. The line is : {0}'.format(line)))
                    
                    log.info(banner('The value of ip_list is  : {0}'.format(ip_list)))
                    for i in range(0,1):
                        log.info(banner('************* ITERATION {0} ***************'.format(i+1)))
                        c = random.randint(0,len(ip_list)-2)
                        ip = ip_list[c]
                        log.info(banner('The value of ip is : {0}'.format(ip)))
                        cfg4 = 'sh consistency-checker vxlan l3 single-route ipv4 {0} vrf V6-001'.format(ip)
                        out4 = dev_hdl.execute(cfg4,timeout=600)
                        log.info(banner('The Vxlan consistency Check l3 Single Route module all Output is : {0}'.format(out4)))
                        for line in out4.splitlines():
                            match = re.search(('traceback|error|fail'),line,re.I)
                            if match:
                                log.error(banner('The following Error / Failure occurred {0} on dut {2} and the whole output is : {1}'.format(line,out4,dut)))
                                flag = 1
                        
                        match=re.findall('Consistency checking PASSED',out4,re.M)
                        if not match:
                            log.error(banner('The Vxlan consistency Check L3 Single Route is not as expected on dut {0} the whole output is : {1} '.format(dut,out4)))
                            flag = 1
                                
                    if flag:
                        log.error(banner('The Vxlan CC L3 Single Route MAC is Failed ... Check logs for details '))
                        self.failed()
                    
            else:
                log.error('The Initial Traffic Condition did not pass:')
                self.failed()



class VXLANVxlanV6FUNC035(aetest.Testcase):

    """ Checking Vxlan CC - L3 Singke Route """

    uid = 'VXLAN-L3-VxlanV6-FUNC-035'
    
    @aetest.test
    def vxlanVlanConsistencyChecker(self,log,testscript,testbed):
        
        node_dict = testscript.parameters['node_dict']
        tg_interface_hdl_dict = testscript.parameters['tg_interface_hdl_dict'] 
        traffic_stream_dict = testscript.parameters['traffic_stream_dict'] 
        port_handle_dict = testscript.parameters['port_handle_dict']
        TGList_config_file = testscript.parameters['TGList']
        configdict = testscript.parameters['configdict'] 
        tgn_config_dict = configdict['TG']
        threshold = testscript.parameters['traffic_threshold'] 
        tgn_port_dut_mapping = testscript.parameters['tgn_port_dut_mapping']
        alias_intf_mapping_dict = testscript.parameters['alias_intf_mapping']
        configured_stream = testscript.parameters['configured_stream']
        trigger_obj = testscript.parameters['trigger_obj']

        log.info(banner('The value of configured stream is : {0}'.format(configured_stream))) 
        
        login = [node_dict['all_dut'][dut].execute('show version') for dut in node_dict['all_dut'] if re.search('uut', dut)]
                
        for TG in tgn_config_dict.keys():
            tgn_hdl = testscript.parameters['testbed_obj'].devices[TG]
            out = trigger_obj.checkAllStreamStats(tgn_hdl)
            
            devices = trigger_obj.getDeviceDict('all_vtep')
            flag =0
            if out:
                for dut in devices:
                    dev_hdl = node_dict['all_dut'][dut]
                    cfg1 = 'sh consistency-checker vxlan vlan all '
                    out1 = dev_hdl.execute(cfg1,timeout=600)
                    log.info(banner('The Vxlan consistency Check Vlan  Output is : {0}'.format(out1)))
                    for line in out1.splitlines():
                        match = re.search(('traceback|error|fail'),line,re.I)
                        if match:
                            log.error(banner('The following Error / Failure occurred {0} on dut {2} and the whole output is : {1}'.format(line,out1,dut)))
                            flag = 1
                            
                if flag:
                    log.error(banner('The Vxlan CC config-Check Brief output.. '))
                    self.failed()
                    
            else:
                log.error('The Initial Traffic Condition did not pass:')
                self.failed()       
                
class VXLANVxlanV6FUNC036(aetest.Testcase):

    """ Checking Vxlan CC - config-check Brief"""

    uid = 'VXLAN-L3-VxlanV6-FUNC-036'
    
    @aetest.test
    def vxlanVlanConsistencyCheckerBrief(self,log,testscript,testbed):
        
        node_dict = testscript.parameters['node_dict']
        tg_interface_hdl_dict = testscript.parameters['tg_interface_hdl_dict'] 
        traffic_stream_dict = testscript.parameters['traffic_stream_dict'] 
        port_handle_dict = testscript.parameters['port_handle_dict']
        TGList_config_file = testscript.parameters['TGList']
        configdict = testscript.parameters['configdict'] 
        tgn_config_dict = configdict['TG']
        threshold = testscript.parameters['traffic_threshold'] 
        tgn_port_dut_mapping = testscript.parameters['tgn_port_dut_mapping']
        alias_intf_mapping_dict = testscript.parameters['alias_intf_mapping']
        configured_stream = testscript.parameters['configured_stream']
        trigger_obj = testscript.parameters['trigger_obj']

        log.info(banner('The value of configured stream is : {0}'.format(configured_stream)))
        
        login = [node_dict['all_dut'][dut].execute('show version') for dut in node_dict['all_dut'] if re.search('uut', dut)] 
                
        for TG in tgn_config_dict.keys():
            tgn_hdl = testscript.parameters['testbed_obj'].devices[TG]
            out = trigger_obj.checkAllStreamStats(tgn_hdl)
            
            devices = trigger_obj.getDeviceDict('all_vtep')
            flag =0
            if out:
                for dut in devices:
                    dev_hdl = node_dict['all_dut'][dut]
                    cfg1 = 'sh consistency-checker vxlan vlan all brief'
                    out1 = dev_hdl.execute(cfg1,timeout=600)
                    log.info(banner('The Vxlan consistency Check Vlan Brief Output is : {0}'.format(out1)))
                    match=re.findall('CC_STATUS_OK',out1,re.M)
                    if match:
                        if not len(match) == 2:
                            log.error(banner('The Vxlan consistency Check Vlan Brief output is not as expected on dut {0} the whole output is : {1} and occurance of CC_STATUS_OK is : {2}'.format(dut,out1,len(match))))
                            flag = 1
                            
                if flag:
                    log.error(banner('The Vxlan CC VLan all Brief output.. '))
                    self.failed()
                    
            else:
                log.error('The Initial Traffic Condition did not pass:')
                self.failed()  

class VXLANVxlanV6FUNC037(aetest.Testcase):

    """ Checking Vxlan CC - config-check Detail"""

    uid = 'VXLAN-L3-VxlanV6-FUNC-037'
    
    @aetest.test
    def vxlanVlanAllConsistencyCheckerDetail(self,log,testscript,testbed):
        
        node_dict = testscript.parameters['node_dict']
        tg_interface_hdl_dict = testscript.parameters['tg_interface_hdl_dict'] 
        traffic_stream_dict = testscript.parameters['traffic_stream_dict'] 
        port_handle_dict = testscript.parameters['port_handle_dict']
        TGList_config_file = testscript.parameters['TGList']
        configdict = testscript.parameters['configdict'] 
        tgn_config_dict = configdict['TG']
        threshold = testscript.parameters['traffic_threshold'] 
        tgn_port_dut_mapping = testscript.parameters['tgn_port_dut_mapping']
        alias_intf_mapping_dict = testscript.parameters['alias_intf_mapping']
        configured_stream = testscript.parameters['configured_stream']
        trigger_obj = testscript.parameters['trigger_obj']

        log.info(banner('The value of configured stream is : {0}'.format(configured_stream))) 
                
        login = [node_dict['all_dut'][dut].execute('show version') for dut in node_dict['all_dut'] if re.search('uut', dut)]
        
        for TG in tgn_config_dict.keys():
            tgn_hdl = testscript.parameters['testbed_obj'].devices[TG]
            out = trigger_obj.checkAllStreamStats(tgn_hdl)
            
            devices = trigger_obj.getDeviceDict('all_vtep')
            flag =0
            if out:
                for dut in devices:
                    dev_hdl = node_dict['all_dut'][dut]
                    cfg1 = 'sh consistency-checker vxlan vlan all detail'
                    out1 = dev_hdl.execute(cfg1,timeout=600)
                    log.info(banner('The Vxlan consistency Check Vlan all Detail Output is : {0}'.format(out1)))
                    match=re.findall('CC_STATUS_OK',out1,re.M)
                    if match:
                        if not len(match) == 2:
                            log.error(banner('The Vxlan consistency Check Vlan all Detail output is not as expected on dut {0} the whole output is : {1} and occurance of CC_STATUS_OK is : {2}'.format(dut,out1,len(match))))
                            flag = 1
                            
                if flag:
                    log.error(banner('The Vxlan CC config-Check Brief output.. '))
                    self.failed()
                    
            else:
                log.error('The Initial Traffic Condition did not pass:')
                self.failed()  

class VXLANVxlanV6FUNC038(aetest.Testcase):

    """ Checking Vxlan CC - Vxlan Vlan all Verbose"""

    uid = 'VXLAN-L3-VxlanV6-FUNC-038'
    
    @aetest.test
    def vxlanVlanAllConsistencyCheckerVerbose(self,log,testscript,testbed):
        
        node_dict = testscript.parameters['node_dict']
        tg_interface_hdl_dict = testscript.parameters['tg_interface_hdl_dict'] 
        traffic_stream_dict = testscript.parameters['traffic_stream_dict'] 
        port_handle_dict = testscript.parameters['port_handle_dict']
        TGList_config_file = testscript.parameters['TGList']
        configdict = testscript.parameters['configdict'] 
        tgn_config_dict = configdict['TG']
        threshold = testscript.parameters['traffic_threshold'] 
        tgn_port_dut_mapping = testscript.parameters['tgn_port_dut_mapping']
        alias_intf_mapping_dict = testscript.parameters['alias_intf_mapping']
        configured_stream = testscript.parameters['configured_stream']
        trigger_obj = testscript.parameters['trigger_obj']

        log.info(banner('The value of configured stream is : {0}'.format(configured_stream))) 
        
        login = [node_dict['all_dut'][dut].execute('show version') for dut in node_dict['all_dut'] if re.search('uut', dut)]
                
        for TG in tgn_config_dict.keys():
            tgn_hdl = testscript.parameters['testbed_obj'].devices[TG]
            out = trigger_obj.checkAllStreamStats(tgn_hdl)
            
            devices = trigger_obj.getDeviceDict('all_vtep')
            flag =0
            if out:
                for dut in devices:
                    dev_hdl = node_dict['all_dut'][dut]
                    cfg1 = 'sh consistency-checker vxlan vlan all verbose-mode'
                    out1 = dev_hdl.execute(cfg1,timeout=600)
                    log.info(banner('The Vxlan consistency Check config-check Verbose Output is : {0}'.format(out1)))
                    for line in out1.splitlines():
                        match = re.search(('traceback|error|fail'),line,re.I)
                        if match:
                            log.error(banner('The following Error / Failure occurred {0} on dut {2} and the whole output is : {1}'.format(line,out1,dut)))
                            flag = 1
                        
                    cfg2 = 'sh consistency-checker vxlan vlan all verbose-mode brief'
                    out2 = dev_hdl.execute(cfg2,timeout=600)
                    match=re.findall('CC_STATUS_OK',out2,re.M)
                    if match:
                        if not len(match) == 2:
                            log.error(banner('The Vxlan consistency Vlan All-check Brief output is not as expected on dut {0} the whole output is : {1} and occurance of CC_STATUS_OK is : {2}'.format(dut,out2,len(match))))
                            flag = 1               
                            
                    cfg3 = 'sh consistency-checker vxlan vlan all verbose-mode detail'
                    out3 = dev_hdl.execute(cfg3,timeout=600)
                    match=re.findall('CC_STATUS_OK',out3,re.M)
                    if match:
                        if not len(match) == 2:
                            log.error(banner('The Vxlan consistency Check Vlan All Detail output is not as expected on dut {0} the whole output is : {1} and occurance of CC_STATUS_OK is : {2}'.format(dut,out3,len(match))))
                            flag = 1             
                              
                if flag:
                    log.error(banner('The Vxlan CC config-Check Brief output.. '))
                    self.failed()
                    
            else:
                log.error('The Initial Traffic Condition did not pass:')
                self.failed()  
 
class VXLANVxlanV6FUNC039(aetest.Testcase):

    """ Checking Vxlan L3 Re-Routes"""

    uid = 'VXLAN-L3-VxlanV6-FUNC-039'
    
    @aetest.test
    def vxlanCheckL3ReRoutes(self,log,testscript,testbed):
        
        node_dict = testscript.parameters['node_dict']
        tg_interface_hdl_dict = testscript.parameters['tg_interface_hdl_dict'] 
        traffic_stream_dict = testscript.parameters['traffic_stream_dict'] 
        port_handle_dict = testscript.parameters['port_handle_dict']
        TGList_config_file = testscript.parameters['TGList']
        configdict = testscript.parameters['configdict'] 
        tgn_config_dict = configdict['TG']
        threshold = testscript.parameters['traffic_threshold'] 
        tgn_port_dut_mapping = testscript.parameters['tgn_port_dut_mapping']
        alias_intf_mapping_dict = testscript.parameters['alias_intf_mapping']
        configured_stream = testscript.parameters['configured_stream']
        trigger_obj = testscript.parameters['trigger_obj']

        log.info(banner('The value of configured stream is : {0}'.format(configured_stream))) 
        
        login = [node_dict['all_dut'][dut].execute('show version') for dut in node_dict['all_dut'] if re.search('uut', dut)]
                
        for TG in tgn_config_dict.keys():
            tgn_hdl = testscript.parameters['testbed_obj'].devices[TG]
            out = trigger_obj.checkAllStreamStats(tgn_hdl)

            devices = ['uut1','uut2']
            if out:
                res = trigger_obj.backUpAndRestoreConfigs(devices,'backup')
                log.info(banner('Routing the packets through the VPC secondary -- Uplinks in Primary is being Shut'))
                
                vpc_primary_hdl = trigger_obj.getVPCSwitchhdl('primary')
                
                for intf in [alias_intf_mapping_dict['uut1_uut33_1'],alias_intf_mapping_dict['uut1_uut33_2']]:
                    cfg = '''interface {0}
                             shutdown'''.format(intf)
                    vpc_primary_hdl.configure(cfg)
                    
                log.info(banner('Sleeping for 100 seconds for the traffic to converge {0}'.format(countDownTimer(100))))
                
                out1 = trigger_obj.checkAllStreamStats(tgn_hdl)
                
                if out1:
                    log.info(banner('Traffic Flow is as expected after re-routing the traffic through the VPC secondary'))
                    
                    
                    for intf in [alias_intf_mapping_dict['uut1_uut33_1'],alias_intf_mapping_dict['uut1_uut33_2']]:
                        cfg = '''interface {0}
                                 no shutdown'''.format(intf)
                        vpc_primary_hdl.configure(cfg)
                        
                    log.info(banner('Now Re-routing the traffic through the VPC Primary .. .'))
                    
                    vpc_secondary_hdl = trigger_obj.getVPCSwitchhdl('secondary')
                    
                    for intf in [alias_intf_mapping_dict['uut2_uut33_1'],alias_intf_mapping_dict['uut2_uut33_2']]:
                        cfg = '''interface {0}
                                 shutdown'''.format(intf)
                        vpc_secondary_hdl.configure(cfg)
                        
                    log.info(banner('Sleeping for 100 seconds for the traffic to converge {0}'.format(countDownTimer(100))))
                    
                    out2 = trigger_obj.checkAllStreamStats(tgn_hdl)
                    
                    if out2:
                        log.info(banner('Traffic Flow is as expected after re-routing the traffic through the VPC Primary'))
                        log.info('Reverting the configs')
                        res = trigger_obj.backUpAndRestoreConfigs(devices,'restore')
                        
                    else:
                        log.error(banner('Traffic flow through the VPC Primary is not as expected.. '))
                        log.info('Getting the individual traffic stats...')
                        res = trigger_obj.backUpAndRestoreConfigs(devices,'restore')
                        self.failed()

                else:
                    log.error(banner('Traffic Flow is not as expected after re-routing the traffic through the VPC Secondary....'))
                    log.info('Getting the individual traffic stats...')
                    res = trigger_obj.backUpAndRestoreConfigs(devices,'restore')
                    self.failed()
            else:
                log.error('The Initial Traffic Condition did not pass:')
                log.info('Getting the individual traffic stats...')
                self.failed()            
                
class VXLANVxlanV6FUNC040(aetest.Testcase):

    """ Checking Vxlan NVE Stats"""

    uid = 'VXLAN-L3-VxlanV6-FUNC-040'
    
    @aetest.test
    def vxlanCheckNVEStats(self,log,testscript,testbed):
        
        node_dict = testscript.parameters['node_dict']
        tg_interface_hdl_dict = testscript.parameters['tg_interface_hdl_dict'] 
        traffic_stream_dict = testscript.parameters['traffic_stream_dict'] 
        port_handle_dict = testscript.parameters['port_handle_dict']
        TGList_config_file = testscript.parameters['TGList']
        configdict = testscript.parameters['configdict'] 
        tgn_config_dict = configdict['TG']
        threshold = testscript.parameters['traffic_threshold'] 
        tgn_port_dut_mapping = testscript.parameters['tgn_port_dut_mapping']
        alias_intf_mapping_dict = testscript.parameters['alias_intf_mapping']
        configured_stream = testscript.parameters['configured_stream']
        trigger_obj = testscript.parameters['trigger_obj']

        log.info(banner('The value of configured stream is : {0}'.format(configured_stream))) 
        
        login = [node_dict['all_dut'][dut].execute('show version') for dut in node_dict['all_dut'] if re.search('uut', dut)]
                
        for TG in tgn_config_dict.keys():
            tgn_hdl = testscript.parameters['testbed_obj'].devices[TG]
            out = trigger_obj.checkAllStreamStats(tgn_hdl)
            
            stream_to_consider = 'RAW001'
            
            flag = 0
            if out:
                                
                log.info(banner('Stopping all the streams:'))
                
                x1 = tgn_hdl.traffic_control(action='stop', max_wait_timer=60)
                
                log.info(banner('starting One Stream to check for Nve Stats.. The stream is : {0}'.format(stream_to_consider)))
                
#                log.info(banner('The value of traffic_stream_dict is : {0}'.format(traffic_stream_dict)))
                
                x2 = tgn_hdl.traffic_control(action='run', handle = traffic_stream_dict[stream_to_consider]['traffic_item'], max_wait_timer=60)
                
                vtep_dict = trigger_obj.getDeviceDict('all_vtep')
                
                log.info(banner('Clearing counters on all VTEPS'))
                
                cfg = 'clear counters'
                for dut in vtep_dict:
                    vtep_dict[dut].execute(cfg)
 
                log.info(banner('Getting the Nve stats on the Tx Side'))
                
                for dut , tx_hdl in trigger_obj.getDeviceDict('stand_vtep').items() : pass
                
                log.info(banner('Waiting for 30 seconds before collecting the Tx stats on dut {0} '.format(dut)))
                countDownTimer(30)
                
                stats = tgn_hdl.traffic_stats(stream = traffic_stream_dict[stream_to_consider]['stream_id'], mode = 'traffic_item')
                tx_stat = stats.traffic_item[traffic_stream_dict[stream_to_consider]['stream_id']]['tx'].total_pkt_rate
                
                exp_pkt = int(tx_stat*30)
                log.info('The value of exp_pkt is : {0}'.format(exp_pkt))

                cfg1 = 'sh int nve 1 | xml'
                out1 = tx_hdl.execute(cfg1)
                s = BeautifulSoup(out1)
                tx_actual = int(s.find('nve_tx_mcastpkts').string)
                log.info('The value of tx_actual is : {0}'.format(tx_actual))
                
                if tx_actual > exp_pkt-1000:
                    log.info(banner('Tx Packet counter is working as expected .. The actual Tx values is : {0}'.format(tx_actual)))
                else:
                    log.info(banner('The Tx packet counters is not as expected.... The Exp Pkt and Actual Pkt are : {0} and {1}'.format(exp_pkt,tx_actual)))
                    flag = 1
                    
                log.info(banner('Chckecing the Traffic stats at the Rx side .......'))
                
                vpc_vtep = trigger_obj.getDeviceDict('vpc_vtep')
                rx_actual = 0
                for dut in vpc_vtep:
                    out = vpc_vtep[dut].execute('sh int nve 1 | xml')
                    s = BeautifulSoup(out)
                    rx_actual += int(s.find('nve_rx_mcastpkts').string)
                
                log.info(banner('The Value of Rx_actual is : {0}'.format(rx_actual)))
                
                if rx_actual > tx_actual - 100:
                    log.info('The Rx counters are as expected... The value of Tx actual and Rx Actual are : {0} and {1}'.format(tx_actual,rx_actual))
                else:
                    log.error('The Rx counters are Not as expected... The value of Tx actual and Rx Actual are : {0} and {1}'.format(tx_actual,rx_actual))
                    flag = 1
                    
            if flag:
                log.error('The Counters are not working as expected. Refer the script logs for details..')
                self.failed()
                
                                
            log.info('Stopping All the stream:')
            x1 = tgn_hdl.traffic_control(action='stop',max_wait_timer=60)
                
            log.info(banner('Starting all the streams now:'))
            
            x3 = tgn_hdl.traffic_control(action='run', max_wait_timer=60)
            log.info(banner('Waiting for 30 seconds for the streams to stabilize.. {0}'.format(countDownTimer(30))))
            
            out3 = trigger_obj.checkAllStreamStats(tgn_hdl)
            
            if out3:
                log.info(banner('Traffic has started successfully and the Stream stats are okay.'))
            else:
                log.error(banner('Traffic stream stats are incorrect. pls debug.'))
                self.failed()

class VXLANVxlanV6FUNC041(aetest.Testcase):

    """ Checking Vxlan NVE Per Peer Stats"""

    uid = 'VXLAN-L3-VxlanV6-FUNC-041'
    
    @aetest.test
    def vxlanCheckNVEPerPeerStats(self,log,testscript,testbed):
        
        node_dict = testscript.parameters['node_dict']
        tg_interface_hdl_dict = testscript.parameters['tg_interface_hdl_dict'] 
        traffic_stream_dict = testscript.parameters['traffic_stream_dict'] 
        port_handle_dict = testscript.parameters['port_handle_dict']
        TGList_config_file = testscript.parameters['TGList']
        configdict = testscript.parameters['configdict'] 
        tgn_config_dict = configdict['TG']
        threshold = testscript.parameters['traffic_threshold'] 
        tgn_port_dut_mapping = testscript.parameters['tgn_port_dut_mapping']
        alias_intf_mapping_dict = testscript.parameters['alias_intf_mapping']
        configured_stream = testscript.parameters['configured_stream']
        trigger_obj = testscript.parameters['trigger_obj']

        log.info(banner('The value of configured stream is : {0}'.format(configured_stream)))
        
        login = [node_dict['all_dut'][dut].execute('show version') for dut in node_dict['all_dut'] if re.search('uut', dut)] 
                
        for TG in tgn_config_dict.keys():
            tgn_hdl = testscript.parameters['testbed_obj'].devices[TG]
            out = trigger_obj.checkAllStreamStats(tgn_hdl)
            
            stream_to_consider = 'RAW001'
            
            flag = 0
            if out:
                                
                log.info(banner('Stopping all the streams:'))
                
                x1 = tgn_hdl.traffic_control(action='stop', max_wait_timer=60)
                
                log.info(banner('starting One Stream to check for Nve Stats.. The stream is : {0}'.format(stream_to_consider)))
                
#                log.info(banner('The value of traffic_stream_dict is : {0}'.format(traffic_stream_dict)))
                
                x2 = tgn_hdl.traffic_control(action='run', handle = traffic_stream_dict[stream_to_consider]['traffic_item'], max_wait_timer=60)
                
                vtep_dict = trigger_obj.getDeviceDict('all_vtep')
 
                log.info(banner('Getting the Nve stats on the Tx Side'))
                
                for dut , tx_hdl in trigger_obj.getDeviceDict('stand_vtep').items() : pass
                
                stats = tgn_hdl.traffic_stats(stream = traffic_stream_dict[stream_to_consider]['stream_id'], mode = 'traffic_item')
                tx_stat = stats.traffic_item[traffic_stream_dict[stream_to_consider]['stream_id']]['tx'].total_pkt_rate
                
                exp_pkt = int(tx_stat*30)
                log.info('The value of exp_pkt is : {0}'.format(exp_pkt))

                cfg1 = 'sh nve peers | xml'
                out1 = tx_hdl.execute(cfg1)
                s = BeautifulSoup(out1)
                peer_ip6_tx = s.find('peer-ipv6').string
                log.info('The value of peer_ip6_tx is : {0}'.format(peer_ip6_tx))
                
                cfg2 = 'clear nve peers {0} interface nve 1 counters'.format(peer_ip6_tx)
                tx_hdl.execute(cfg2)
                
                log.info(banner('Waiting for 30 seconds before collecting the Tx stats on dut {0} '.format(dut)))
                countDownTimer(30)
                
                cfg3 = 'sh nve peers {0} interface nve 1 counters | xml'.format(peer_ip6_tx)
                out3 = tx_hdl.execute(cfg3)
                s = BeautifulSoup(out3)
                tx_actual = int(s.find('tx_mcastpkts').string)
                log.info('The value of tx_actual is : {0}'.format(tx_actual))                
                
                if tx_actual > exp_pkt:
                    log.info(banner('Tx Packet counter is working as expected .. The actual Tx values is : {0}'.format(tx_actual)))
                else:
                    log.info(banner('The Tx packet counters is not as expected.... The Exp Pkt and Actual Pkt are : {0} and {1}'.format(exp_pkt,tx_actual)))
                    flag = 1
                    
                log.info(banner('Chekecing the Traffic stats at the Rx side .......'))
                
                vpc_vtep = trigger_obj.getDeviceDict('vpc_vtep')
                rx_actual = 0
                peer_ip6_rx = ''
                for dut in vpc_vtep:
                    out = vpc_vtep[dut].execute(cfg1)
                    s = BeautifulSoup(out)
                    peer_ip6_rx = s.find('peer-ipv6').string
                    cfg2 = 'clear nve peers {0} interface nve 1 counters'.format(peer_ip6_rx)
                    vpc_vtep[dut].execute(cfg2)
                
                cfg3 = 'sh nve peers {0} interface nve 1 counters | xml'.format(peer_ip6_rx)
                
                for dut in vpc_vtep:
                    out = vpc_vtep[dut].execute(cfg3)
                    s = BeautifulSoup(out)
                    rx_actual += int(s.find('rx_mcastpkts').string)
                
                log.info(banner('The Value of Rx_actual is : {0}'.format(rx_actual)))
                
                if rx_actual > tx_actual - 100:
                    log.info('The Rx counters are as expected... The value of Tx actual and Rx Actual are : {0} and {1}'.format(tx_actual,rx_actual))
                else:
                    log.error('The Rx counters are Not as expected... The value of Tx actual and Rx Actual are : {0} and {1}'.format(tx_actual,rx_actual))
                    flag = 1
                    
            if flag:
                log.error('The Counters are not working as expected. Refer the script logs for details..')
                self.failed()
                
            log.info('Stopping All the stream:')
            x1 = tgn_hdl.traffic_control(action='stop',max_wait_timer=60)
                
            log.info(banner('Starting all the streams now:'))
            
            x3 = tgn_hdl.traffic_control(action='run', max_wait_timer=60)
            log.info(banner('Waiting for 30 seconds for the streams to stabilize.. {0}'.format(countDownTimer(30))))
            
            out4 = trigger_obj.checkAllStreamStats(tgn_hdl)
            
            if out4:
                log.info(banner('Traffic has started successfully and the Stream stats are okay.'))
            else:
                log.error(banner('Traffic stream stats are incorrect. pls debug.'))
                self.failed()

class VXLANVxlanV6FUNC042(aetest.Testcase):

    """ Checking Vxlan Per-VNI Stats"""

    uid = 'VXLAN-L3-VxlanV6-FUNC-042'
    
    @aetest.test
    def vxlanCheckVNIStats(self,log,testscript,testbed):
        
        node_dict = testscript.parameters['node_dict']
        tg_interface_hdl_dict = testscript.parameters['tg_interface_hdl_dict'] 
        traffic_stream_dict = testscript.parameters['traffic_stream_dict'] 
        port_handle_dict = testscript.parameters['port_handle_dict']
        TGList_config_file = testscript.parameters['TGList']
        configdict = testscript.parameters['configdict'] 
        tgn_config_dict = configdict['TG']
        threshold = testscript.parameters['traffic_threshold'] 
        tgn_port_dut_mapping = testscript.parameters['tgn_port_dut_mapping']
        alias_intf_mapping_dict = testscript.parameters['alias_intf_mapping']
        configured_stream = testscript.parameters['configured_stream']
        trigger_obj = testscript.parameters['trigger_obj']

        log.info(banner('The value of configured stream is : {0}'.format(configured_stream)))
        
        login = [node_dict['all_dut'][dut].execute('show version') for dut in node_dict['all_dut'] if re.search('uut', dut)] 
                
        for TG in tgn_config_dict.keys():
            tgn_hdl = testscript.parameters['testbed_obj'].devices[TG]
            out = trigger_obj.checkAllStreamStats(tgn_hdl)
            
            stream_to_consider = 'RAW001'
            
            flag = 0
            if out:
                                
                log.info(banner('Stopping all the streams:'))
                
                x1 = tgn_hdl.traffic_control(action='stop', max_wait_timer=60)
                
                log.info(banner('starting One Stream to check for VNI Stats.. The stream is : {0}'.format(stream_to_consider)))
                
                x2 = tgn_hdl.traffic_control(action='run', handle = traffic_stream_dict[stream_to_consider]['traffic_item'], max_wait_timer=60)
                
                vtep_dict = trigger_obj.getDeviceDict('all_vtep')

                for dut , tx_hdl in trigger_obj.getDeviceDict('stand_vtep').items() : pass
                
                stats = tgn_hdl.traffic_stats(stream = traffic_stream_dict[stream_to_consider]['stream_id'], mode = 'traffic_item')
                tx_stat = stats.traffic_item[traffic_stream_dict[stream_to_consider]['stream_id']]['tx'].total_pkt_rate
                
                exp_pkt = int(tx_stat*30)/100
                log.info('The value of exp_pkt is : {0}'.format(exp_pkt))
                
                for dut in vtep_dict:
                    vtep_dict[dut].execute('clear nve vni 1701 counters')
                
                log.info(banner('Waiting for 30 seconds before collecting the Tx stats on dut {0} '.format(dut)))
                countDownTimer(30)
                
                log.info(banner('Getting the Nve stats on the Tx Side'))
                
                cfg2 = 'sh nve vni 1701 counters | xml'
                out2 = tx_hdl.execute(cfg2)
                s = BeautifulSoup(out2)
                tx_actual = int(s.find('tx_mcastpkts').string)
                log.info('The value of tx_actual is : {0}'.format(tx_actual))           
                
                if abs(tx_actual - exp_pkt) < 300:
                    log.info(banner('Tx Packet counter is working as expected .. The actual Tx values is : {0}'.format(tx_actual)))
                else:
                    log.info(banner('The Tx packet counters is not as expected.... The Exp Pkt and Actual Pkt are : {0} and {1}'.format(exp_pkt,tx_actual)))
                    flag = 1
                    
                log.info(banner('Chekecing the Traffic stats at the Rx side .......'))
                
                vpc_vtep = trigger_obj.getDeviceDict('vpc_vtep')
                rx_actual = 0
                for dut in vpc_vtep:
                    out = vpc_vtep[dut].execute(cfg2)
                    s = BeautifulSoup(out)
                    rx_actual += int(s.find('tx_mcastpkts').string)
                
                log.info(banner('The Value of Rx_actual is : {0}'.format(rx_actual)))
                
                if abs(tx_actual - rx_actual) < 100:
                    log.info('The Rx counters are as expected... The value of Tx actual and Rx Actual are : {0} and {1}'.format(tx_actual,rx_actual))
                else:
                    log.error('The Rx counters are Not as expected... The value of Tx actual and Rx Actual are : {0} and {1}'.format(tx_actual,rx_actual))
                    flag = 1
                    
            if flag:
                log.error('The Counters are not working as expected. Refer the script logs for details..')
                self.failed()
                
            log.info('Stopping All the stream:')
            x1 = tgn_hdl.traffic_control(action='stop',max_wait_timer=60)
                
            log.info(banner('Starting all the streams now:'))
            
            x3 = tgn_hdl.traffic_control(action='run', max_wait_timer=60)
            log.info(banner('Waiting for 30 seconds for the streams to stabilize.. {0}'.format(countDownTimer(30))))
            
            out4 = trigger_obj.checkAllStreamStats(tgn_hdl)
            
            if out4:
                log.info(banner('Traffic has started successfully and the Stream stats are okay.'))
            else:
                log.error(banner('Traffic stream stats are incorrect. pls debug.'))
                self.failed()
                
                
class VXLANVxlanV6FUNC043(aetest.Testcase):

    """ Vxlan TRIGGERS - L2 ACCESS PORT FLAP"""

    uid = 'VXLAN-L3-VxlanV6-FUNC-043'
    
    @aetest.test
    def vxlanTrafficL2AccessPortFlap(self,log,testscript,testbed):
        
        node_dict = testscript.parameters['node_dict']
        tg_interface_hdl_dict = testscript.parameters['tg_interface_hdl_dict'] 
        traffic_stream_dict = testscript.parameters['traffic_stream_dict'] 
        port_handle_dict = testscript.parameters['port_handle_dict']
        TGList_config_file = testscript.parameters['TGList']
        configdict = testscript.parameters['configdict'] 
        tgn_config_dict = configdict['TG']
        threshold = testscript.parameters['traffic_threshold'] 
        tgn_port_dut_mapping = testscript.parameters['tgn_port_dut_mapping']
        alias_intf_mapping_dict = testscript.parameters['alias_intf_mapping']
        configured_stream = testscript.parameters['configured_stream']
        trigger_obj = testscript.parameters['trigger_obj']

        log.info(banner('The value of configured stream is : {0}'.format(configured_stream))) 
        
        login = [node_dict['all_dut'][dut].execute('show version') for dut in node_dict['all_dut'] if re.search('uut', dut)]
        
        trf = configdict['trigger_dict']['TEST-043']['traffic_to_consider']
        traffic_item_list = expandTrafficItemList(trf)
        
        log.info(banner('The value of traffic_item_list is : {0}'.format(traffic_item_list)))
        
        devices = configdict['trigger_dict']['TEST-043']['trigger_dut']
        dev_len  = len(devices)
        interfaces = configdict['trigger_dict']['TEST-043']['interfaces'].split()
        
        log.info('The value of interfaces is : {0}'.format(interfaces))
        
        trigger_type = 'access_port'
        
        for dut in devices:
            ns = parseScaleVlanParms(log, configdict['scale_config_dict'][dut]['global']['vlan'])
            break

        log.info(banner('The value of ns is : {0}'.format(ns)))
        
        for TG in tgn_config_dict.keys():
            tgn_hdl = testscript.parameters['testbed_obj'].devices[TG]
            out = trigger_obj.checkAllStreamStats(tgn_hdl)
        
            if out:
                for i in range(0,1):
                    vlan = random.randint(ns.l2_vlan_start,(ns.l2_vlan_start+ns.no_of_l2_vlans-1))
                    allowed_vlan = str(ns.l2_vlan_start) + '-' + str(ns.l2_vlan_start+ns.no_of_l2_vlans-1)
                    log.info(banner('Iteration {1} ... The Choosen Vlan is : {0}'.format(vlan,i)))
                    res = [trigger_obj.changeInterfaceSwitchPortMode(node_dict['all_dut'][x],intf,vlan,mode='access') for x in devices for intf in interfaces if x in intf]
                    countDownTimer(150)
                    new_out = trigger_obj.checkAllRawStreamStatsTrigger(tgn_hdl,dev_len,trigger_type,ns.no_of_l2_vlans)
                    if not new_out['status']:
                        log.error(banner('The following stream {1} has failed in Vlan {1} '.format(vlan,new_out['streams'])))
                        res = [trigger_obj.changeInterfaceSwitchPortMode(node_dict['all_dut'][x],intf,allowed_vlan,mode='trunk') for x in devices for intf in interfaces]
                        self.failed()
                
                    log.info(banner('The RAW Stream traffic stats are fine.. Flapping the access Ports :'))
                    
                    for intf in interfaces:
                        dut = intf.split('_')[0]
                        hdl = node_dict['all_dut'][dut]
                        cfg1 = '''interface {0}
                                 shutdown'''.format(alias_intf_mapping_dict[intf])
                        hdl.configure(cfg1)
                        log.info(banner('Sleeping for 5 seconds before bringing up the port on dut {1} and interface {2} {0}'.format(countDownTimer(5),dut,alias_intf_mapping_dict[intf])))
                        cfg2 = '''interface {0}
                                  no shutdown'''.format(alias_intf_mapping_dict[intf])
                        hdl.configure(cfg2)
                        log.info(banner('Waiting for 30 seconds before Measureing the Traffic stats .. {0}'.format(countDownTimer(30))))
                        new_out1 = trigger_obj.checkAllRawStreamStatsTrigger(tgn_hdl,dev_len,trigger_type,ns.no_of_l2_vlans)
                        if not new_out1['status']:
                            log.error(banner('The following stream {1} has failed in Vlan {1} '.format(vlan,new_out1['streams'])))
                            res = [trigger_obj.changeInterfaceSwitchPortMode(node_dict['all_dut'][x],intf,allowed_vlan,mode='trunk') for x in devices for intf in interfaces]
                            self.failed()

                res = [trigger_obj.changeInterfaceSwitchPortMode(node_dict['all_dut'][x],intf,allowed_vlan,mode='trunk') for x in devices for intf in interfaces]
                
                countDownTimer(150)
                log.info(banner('Checking Traffic stats on all the configured streams.:'))
                out = trigger_obj.checkAllStreamStats(tgn_hdl)
                if not out:
                    log.error(banner('Traffic has not recovered on some of the streams.. '))
                    self.failed()                    
            else:
                log.error('The Initial Traffic Condition did not pass :')
                self.failed()
                
class VXLANVxlanV6FUNC044(aetest.Testcase):

    """ Vxlan TRIGGERS - L2 TRUNK PORT FLAP"""

    uid = 'VXLAN-L3-VxlanV6-FUNC-044'
    
    @aetest.test
    def vxlanTrafficL2TrunkPortFlap(self,log,testscript,testbed):
        
        node_dict = testscript.parameters['node_dict']
        tg_interface_hdl_dict = testscript.parameters['tg_interface_hdl_dict'] 
        traffic_stream_dict = testscript.parameters['traffic_stream_dict'] 
        port_handle_dict = testscript.parameters['port_handle_dict']
        TGList_config_file = testscript.parameters['TGList']
        configdict = testscript.parameters['configdict'] 
        tgn_config_dict = configdict['TG']
        threshold = testscript.parameters['traffic_threshold'] 
        tgn_port_dut_mapping = testscript.parameters['tgn_port_dut_mapping']
        alias_intf_mapping_dict = testscript.parameters['alias_intf_mapping']
        configured_stream = testscript.parameters['configured_stream']
        trigger_obj = testscript.parameters['trigger_obj']

        log.info(banner('The value of configured stream is : {0}'.format(configured_stream))) 
        login = [node_dict['all_dut'][dut].execute('show version') for dut in node_dict['all_dut'] if re.search('uut', dut)]
        
        trf = configdict['trigger_dict']['TEST-044']['traffic_to_consider']
        traffic_item_list = expandTrafficItemList(trf)
        
        log.info(banner('The value of traffic_item_list is : {0}'.format(traffic_item_list)))
        
        devices = configdict['trigger_dict']['TEST-044']['trigger_dut']
        no_of_iterations = configdict['trigger_dict']['TEST-044']['no_of_iterations']
        interfaces = configdict['trigger_dict']['TEST-044']['interfaces'].split()
        
        log.info('The value of interfaces is : {0}'.format(interfaces))
        
        for TG in tgn_config_dict.keys():
            tgn_hdl = testscript.parameters['testbed_obj'].devices[TG]
            out = trigger_obj.checkAllStreamStats(tgn_hdl)
        
            if out:
                for i in range(0,no_of_iterations):
                    log.info(banner('************* ITERATION - {0} ***********'.format(i)))
                    for intf in interfaces:
                        dut = intf.split('_')[0]
                        hdl = node_dict['all_dut'][dut]
                        cfg1 = '''interface {0}
                                 shutdown'''.format(alias_intf_mapping_dict[intf])
                        hdl.configure(cfg1)
                        log.info(banner('Sleeping for 5 seconds before bringing up the port on dut {1} and interface {2} {0}'.format(countDownTimer(5),dut,alias_intf_mapping_dict[intf])))
                        cfg2 = '''interface {0}
                                  no shutdown'''.format(alias_intf_mapping_dict[intf])
                        hdl.configure(cfg2)
                        log.info(banner('Waiting for 30 seconds before Measureing the Traffic stats .. {0}'.format(countDownTimer(30))))
                        out1 = trigger_obj.checkAllStreamStats(tgn_hdl)
                        if out1:
                            log.info(banner('Traffic has recovered After Interface flap {0} on dut {1}'.format(alias_intf_mapping_dict[intf],dut)))
                        else:
                            log.info(banner('Traffic has Not recovered After Interface flap {0} on dut {1}'.format(alias_intf_mapping_dict[intf],dut)))
                            self.failed()

                log.info(banner('Waiting for 150 seconds for the System to be in steady state.'))
                
                countDownTimer(150)
                log.info(banner('Checking Traffic stats on all the configured streams.:'))
                out = trigger_obj.checkAllStreamStats(tgn_hdl)
                if not out:
                    log.error(banner('Traffic has not recovered on some of the streams.. '))
                    self.failed()                    
            else:
                log.error('The Initial Traffic Condition did not pass :')
                self.failed()

class VXLANVxlanV6FUNC045(aetest.Testcase):

    """ Vxlan Trigger - ACCESS VPC PORT Flap - Primary"""

    uid = 'VXLAN-L3-VxlanV6-FUNC-045'
    
    @aetest.test
    def vxlanL2VPCPrimaryAccessPoFlap(self,log,testscript,testbed):
        
        node_dict = testscript.parameters['node_dict']
        tg_interface_hdl_dict = testscript.parameters['tg_interface_hdl_dict'] 
        traffic_stream_dict = testscript.parameters['traffic_stream_dict'] 
        port_handle_dict = testscript.parameters['port_handle_dict']
        TGList_config_file = testscript.parameters['TGList']
        configdict = testscript.parameters['configdict'] 
        tgn_config_dict = configdict['TG']
        threshold = testscript.parameters['traffic_threshold'] 
        tgn_port_dut_mapping = testscript.parameters['tgn_port_dut_mapping']
        alias_intf_mapping_dict = testscript.parameters['alias_intf_mapping']
        configured_stream = testscript.parameters['configured_stream']
        trigger_obj = testscript.parameters['trigger_obj']

        log.info(banner('The value of configured stream is : {0}'.format(configured_stream))) 
        
        login = [node_dict['all_dut'][dut].execute('show version') for dut in node_dict['all_dut'] if re.search('uut', dut)]
        
        trf = configdict['trigger_dict']['TEST-045']['traffic_to_consider']
        traffic_item_list = expandTrafficItemList(trf)
        
        log.info(banner('The value of traffic_item_list is : {0}'.format(traffic_item_list)))
        
        devices = configdict['trigger_dict']['TEST-045']['trigger_dut']
        interfaces = list(configdict['interface_config_dict']['portchannel']['uut3'].keys())
        log.info('The value of len of interfaces is: {0}'.format(len(interfaces)))
        
        log.info(banner('the Value of interfaces is  {0} and type is : {1}'.format(interfaces,type(interfaces))))
        
        trigger_type = 'access_vpc_port'
        
        for dut in devices:
            ns = parseScaleVlanParms(log, configdict['scale_config_dict'][dut]['global']['vlan'])
            break

        log.info(banner('The value of ns is : {0}'.format(ns)))
        
        for TG in tgn_config_dict.keys():
            tgn_hdl = testscript.parameters['testbed_obj'].devices[TG]
            out = trigger_obj.checkAllStreamStats(tgn_hdl)
        
            if out:
                for i in range(0,1):
                    vlan = random.randint(ns.l2_vlan_start,(ns.l2_vlan_start+ns.no_of_l2_vlans-1))
                    allowed_vlan = str(ns.l2_vlan_start) + '-' + str(ns.l2_vlan_start+ns.no_of_l2_vlans-1)
                    log.info(banner('The Choosen Vlan is : {0}'.format(vlan)))
                    res = [trigger_obj.changeInterfaceSwitchPortMode(node_dict['all_dut'][x],intf,vlan,mode='access') for x in devices for intf in interfaces]
                    countDownTimer(150)
                    new_out = trigger_obj.checkAllRawStreamStatsTrigger(tgn_hdl,len(interfaces),trigger_type,ns.no_of_l2_vlans)
                    if not new_out['status']:
                        log.error(banner('The following stream {1} has failed in Vlan {1} '.format(vlan,new_out['streams'])))
                        res = [trigger_obj.changeInterfaceSwitchPortMode(node_dict['all_dut'][x],intf,allowed_vlan,mode='trunk') for x in devices for intf in interfaces]
                        self.failed()
                
                log.info(banner('The RAW Stream traffic stats are fine.. FLapping the Access Side PO:'))
                
                
                vpc_primary_hdl = trigger_obj.getVPCSwitchhdl('primary')
                cfg1 = '''interface {0}
                         shutdown'''.format("".join(interfaces))
                vpc_primary_hdl.configure(cfg1)
                log.info(banner('Sleeping for 5 seconds before bringing up the port on dut {1} and interface {2} {0}'.format(countDownTimer(5),dut,interfaces)))
                cfg2 = '''interface {0}
                          no shutdown'''.format("".join(interfaces))
                vpc_primary_hdl.configure(cfg2)
                log.info(banner('Waiting for 30 seconds before Measureing the Traffic stats .. {0}'.format(countDownTimer(30))))
                new_out1 = trigger_obj.checkAllRawStreamStatsTrigger(tgn_hdl,len(interfaces),trigger_type,ns.no_of_l2_vlans)
                if not new_out1['status']:
                    log.error(banner('The following stream {1} has failed in Vlan {1} '.format(vlan,new_out1['streams'])))
                    res = [trigger_obj.changeInterfaceSwitchPortMode(node_dict['all_dut'][x],intf,allowed_vlan,mode='trunk') for x in devices for intf in interfaces]
                        
                res = [trigger_obj.changeInterfaceSwitchPortMode(node_dict['all_dut'][x],intf,allowed_vlan,mode='trunk') for x in devices for intf in interfaces]
                
                countDownTimer(150)
                log.info(banner('Checking Traffic stats on all the configured streams.:'))
                out = trigger_obj.checkAllStreamStats(tgn_hdl)
                if not out:
                    log.error(banner('Traffic has not recovered on some of the streams.. '))
                    self.failed()                    
            else:
                log.error('The Initial Traffic Condition did not pass :')
                self.failed()


class VXLANVxlanV6FUNC046(aetest.Testcase):

    """ Vxlan Trigger - ACCESS VPC PORT Flap - Secondary"""

    uid = 'VXLAN-L3-VxlanV6-FUNC-046'
    
    @aetest.test
    def vxlanL2VPCSecondaryAccessPoFlap(self,log,testscript,testbed):
        
        node_dict = testscript.parameters['node_dict']
        tg_interface_hdl_dict = testscript.parameters['tg_interface_hdl_dict'] 
        traffic_stream_dict = testscript.parameters['traffic_stream_dict'] 
        port_handle_dict = testscript.parameters['port_handle_dict']
        TGList_config_file = testscript.parameters['TGList']
        configdict = testscript.parameters['configdict'] 
        tgn_config_dict = configdict['TG']
        threshold = testscript.parameters['traffic_threshold'] 
        tgn_port_dut_mapping = testscript.parameters['tgn_port_dut_mapping']
        alias_intf_mapping_dict = testscript.parameters['alias_intf_mapping']
        configured_stream = testscript.parameters['configured_stream']
        trigger_obj = testscript.parameters['trigger_obj']

        log.info(banner('The value of configured stream is : {0}'.format(configured_stream))) 
        
        login = [node_dict['all_dut'][dut].execute('show version') for dut in node_dict['all_dut'] if re.search('uut', dut)]
        
        trf = configdict['trigger_dict']['TEST-046']['traffic_to_consider']
        traffic_item_list = expandTrafficItemList(trf)
        
        log.info(banner('The value of traffic_item_list is : {0}'.format(traffic_item_list)))
        
        devices = configdict['trigger_dict']['TEST-046']['trigger_dut']
        interfaces = list(configdict['interface_config_dict']['portchannel']['uut3'].keys())
        log.info('The value of len of interfaces is: {0}'.format(len(interfaces)))
        
        log.info(banner('the Value of interfaces is  {0} and type is : {1}'.format(interfaces,type(interfaces))))
        
        trigger_type = 'access_vpc_port'
        
        for dut in devices:
            ns = parseScaleVlanParms(log, configdict['scale_config_dict'][dut]['global']['vlan'])
            break

        log.info(banner('The value of ns is : {0}'.format(ns)))
        
        for TG in tgn_config_dict.keys():
            tgn_hdl = testscript.parameters['testbed_obj'].devices[TG]
            out = trigger_obj.checkAllStreamStats(tgn_hdl)
        
            if out:
                for i in range(0,1):
                    vlan = random.randint(ns.l2_vlan_start,(ns.l2_vlan_start+ns.no_of_l2_vlans-1))
                    allowed_vlan = str(ns.l2_vlan_start) + '-' + str(ns.l2_vlan_start+ns.no_of_l2_vlans-1)
                    log.info(banner('The Choosen Vlan is : {0}'.format(vlan)))
                    res = [trigger_obj.changeInterfaceSwitchPortMode(node_dict['all_dut'][x],intf,vlan,mode='access') for x in devices for intf in interfaces]
                    countDownTimer(150)
                    new_out = trigger_obj.checkAllRawStreamStatsTrigger(tgn_hdl,len(interfaces),trigger_type,ns.no_of_l2_vlans)
                    if not new_out['status']:
                        log.error(banner('The following stream {1} has failed in Vlan {1} '.format(vlan,new_out['streams'])))
                        res = [trigger_obj.changeInterfaceSwitchPortMode(node_dict['all_dut'][x],intf,allowed_vlan,mode='trunk') for x in devices for intf in interfaces]
                        self.failed()
                
                log.info(banner('The RAW Stream traffic stats are fine.. FLapping the Access Side PO:'))
                
                
                vpc_secondary_hdl = trigger_obj.getVPCSwitchhdl('secondary')
                cfg1 = '''interface {0}
                         shutdown'''.format("".join(interfaces))
                vpc_secondary_hdl.configure(cfg1)
                log.info(banner('Sleeping for 5 seconds before bringing up the port on dut {1} and interface {2} {0}'.format(countDownTimer(5),dut,interfaces)))
                cfg2 = '''interface {0}
                          no shutdown'''.format("".join(interfaces))
                vpc_secondary_hdl.configure(cfg2)
                log.info(banner('Waiting for 30 seconds before Measureing the Traffic stats .. {0}'.format(countDownTimer(30))))
                new_out1 = trigger_obj.checkAllRawStreamStatsTrigger(tgn_hdl,len(interfaces),trigger_type,ns.no_of_l2_vlans)
                if not new_out1['status']:
                    log.error(banner('The following stream {1} has failed in Vlan {1} '.format(vlan,new_out1['streams'])))
                    res = [trigger_obj.changeInterfaceSwitchPortMode(node_dict['all_dut'][x],intf,allowed_vlan,mode='trunk') for x in devices for intf in interfaces]
                        
                res = [trigger_obj.changeInterfaceSwitchPortMode(node_dict['all_dut'][x],intf,allowed_vlan,mode='trunk') for x in devices for intf in interfaces]
                
                countDownTimer(150)
                log.info(banner('Checking Traffic stats on all the configured streams.:'))
                out = trigger_obj.checkAllStreamStats(tgn_hdl)
                if not out:
                    log.error(banner('Traffic has not recovered on some of the streams.. '))
                    self.failed()                    
            else:
                log.error('The Initial Traffic Condition did not pass :')
                self.failed()


class VXLANVxlanV6FUNC047(aetest.Testcase):

    """ Vxlan Trigger - ACCESS VPC PORT Flap - L2 Switch"""

    uid = 'VXLAN-L3-VxlanV6-FUNC-047'
    
    @aetest.test
    def vxlanL2SwitchAccessPoFlap(self,log,testscript,testbed):
        
        node_dict = testscript.parameters['node_dict']
        tg_interface_hdl_dict = testscript.parameters['tg_interface_hdl_dict'] 
        traffic_stream_dict = testscript.parameters['traffic_stream_dict'] 
        port_handle_dict = testscript.parameters['port_handle_dict']
        TGList_config_file = testscript.parameters['TGList']
        configdict = testscript.parameters['configdict'] 
        tgn_config_dict = configdict['TG']
        threshold = testscript.parameters['traffic_threshold'] 
        tgn_port_dut_mapping = testscript.parameters['tgn_port_dut_mapping']
        alias_intf_mapping_dict = testscript.parameters['alias_intf_mapping']
        configured_stream = testscript.parameters['configured_stream']
        trigger_obj = testscript.parameters['trigger_obj']

        log.info(banner('The value of configured stream is : {0}'.format(configured_stream))) 
        
        login = [node_dict['all_dut'][dut].execute('show version') for dut in node_dict['all_dut'] if re.search('uut', dut)]
        
        trf = configdict['trigger_dict']['TEST-047']['traffic_to_consider']
        traffic_item_list = expandTrafficItemList(trf)
        
        log.info(banner('The value of traffic_item_list is : {0}'.format(traffic_item_list)))
        
        devices = configdict['trigger_dict']['TEST-047']['trigger_dut']
        interfaces = list(configdict['interface_config_dict']['portchannel']['uut3'].keys())
        log.info('The value of len of interfaces is: {0}'.format(len(interfaces)))
        
        log.info(banner('the Value of interfaces is  {0} and type is : {1}'.format(interfaces,type(interfaces))))
        
        trigger_type = 'access_vpc_port'
        
        for dut in devices:
            ns = parseScaleVlanParms(log, configdict['scale_config_dict'][dut]['global']['vlan'])
            break

        log.info(banner('The value of ns is : {0}'.format(ns)))
        
        for TG in tgn_config_dict.keys():
            tgn_hdl = testscript.parameters['testbed_obj'].devices[TG]
            out = trigger_obj.checkAllStreamStats(tgn_hdl)
        
            if out:
                for i in range(0,1):
                    vlan = random.randint(ns.l2_vlan_start,(ns.l2_vlan_start+ns.no_of_l2_vlans-1))
                    allowed_vlan = str(ns.l2_vlan_start) + '-' + str(ns.l2_vlan_start+ns.no_of_l2_vlans-1)
                    log.info(banner('The Choosen Vlan is : {0}'.format(vlan)))
                    res = [trigger_obj.changeInterfaceSwitchPortMode(node_dict['all_dut'][x],intf,vlan,mode='access') for x in devices for intf in interfaces]
                    countDownTimer(150)
                    new_out = trigger_obj.checkAllRawStreamStatsTrigger(tgn_hdl,len(interfaces),trigger_type,ns.no_of_l2_vlans)
                    if not new_out['status']:
                        log.error(banner('The following stream {1} has failed in Vlan {1} '.format(vlan,new_out['streams'])))
                        res = [trigger_obj.changeInterfaceSwitchPortMode(node_dict['all_dut'][x],intf,allowed_vlan,mode='trunk') for x in devices for intf in interfaces]
                        self.failed()
                
                log.info(banner('The RAW Stream traffic stats are fine.. FLapping the Access Side PO:'))
                
                res = trigger_obj.getDeviceDict('l2_switch')
                log.info(banner('The value of res is : {0}'.format(res)))
                
                for dut, l2_switch_hdl in trigger_obj.getDeviceDict('l2_switch').items(): pass
                
                cfg1 = '''interface {0}
                         shutdown'''.format("".join(interfaces))
                l2_switch_hdl.configure(cfg1)
                log.info(banner('Sleeping for 5 seconds before bringing up the port on dut {1} and interface {2} {0}'.format(countDownTimer(5),dut,interfaces)))
                cfg2 = '''interface {0}
                          no shutdown'''.format("".join(interfaces))
                l2_switch_hdl.configure(cfg2)
                log.info(banner('Waiting for 30 seconds before Measureing the Traffic stats .. {0}'.format(countDownTimer(90))))
                new_out1 = trigger_obj.checkAllRawStreamStatsTrigger(tgn_hdl,len(interfaces),trigger_type,ns.no_of_l2_vlans)
                if not new_out1['status']:
                    log.error(banner('The following stream {1} has failed in Vlan {1} '.format(vlan,new_out1['streams'])))
                    res = [trigger_obj.changeInterfaceSwitchPortMode(node_dict['all_dut'][x],intf,allowed_vlan,mode='trunk') for x in devices for intf in interfaces]
                        
                res = [trigger_obj.changeInterfaceSwitchPortMode(node_dict['all_dut'][x],intf,allowed_vlan,mode='trunk') for x in devices for intf in interfaces]
                
                countDownTimer(150)
                log.info(banner('Checking Traffic stats on all the configured streams.:'))
                out = trigger_obj.checkAllStreamStats(tgn_hdl)
                if not out:
                    log.error(banner('Traffic has not recovered on some of the streams.. '))
                    self.failed()                    
            else:
                log.error('The Initial Traffic Condition did not pass :')
                self.failed()


class VXLANVxlanV6FUNC048(aetest.Testcase):

    """ Vxlan Trigger - ACCESS VPC PORT Member Flap - Primary"""

    uid = 'VXLAN-L3-VxlanV6-FUNC-048'
    
    @aetest.test
    def vxlanL2VPCPrimaryAccessPoMemberFlap(self,log,testscript,testbed):
        
        node_dict = testscript.parameters['node_dict']
        tg_interface_hdl_dict = testscript.parameters['tg_interface_hdl_dict'] 
        traffic_stream_dict = testscript.parameters['traffic_stream_dict'] 
        port_handle_dict = testscript.parameters['port_handle_dict']
        TGList_config_file = testscript.parameters['TGList']
        configdict = testscript.parameters['configdict'] 
        tgn_config_dict = configdict['TG']
        threshold = testscript.parameters['traffic_threshold'] 
        tgn_port_dut_mapping = testscript.parameters['tgn_port_dut_mapping']
        alias_intf_mapping_dict = testscript.parameters['alias_intf_mapping']
        configured_stream = testscript.parameters['configured_stream']
        trigger_obj = testscript.parameters['trigger_obj']

        log.info(banner('The value of configured stream is : {0}'.format(configured_stream))) 
        
        login = [node_dict['all_dut'][dut].execute('show version') for dut in node_dict['all_dut'] if re.search('uut', dut)]
        
        trf = configdict['trigger_dict']['TEST-048']['traffic_to_consider']
        traffic_item_list = expandTrafficItemList(trf)
        
        log.info(banner('The value of traffic_item_list is : {0}'.format(traffic_item_list)))
        
        devices = configdict['trigger_dict']['TEST-048']['trigger_dut']
        interfaces = list(configdict['interface_config_dict']['portchannel']['uut3'].keys())
        log.info('The value of len of interfaces is: {0}'.format(len(interfaces)))
        
        log.info(banner('the Value of interfaces is  {0} and type is : {1}'.format(interfaces,type(interfaces))))
        
        trigger_type = 'access_vpc_port'
        
        for dut in devices:
            ns = parseScaleVlanParms(log, configdict['scale_config_dict'][dut]['global']['vlan'])
            break

        log.info(banner('The value of ns is : {0}'.format(ns)))
        
        for TG in tgn_config_dict.keys():
            tgn_hdl = testscript.parameters['testbed_obj'].devices[TG]
            out = trigger_obj.checkAllStreamStats(tgn_hdl)
        
            if out:
                for i in range(0,1):
                    vlan = random.randint(ns.l2_vlan_start,(ns.l2_vlan_start+ns.no_of_l2_vlans-1))
                    allowed_vlan = str(ns.l2_vlan_start) + '-' + str(ns.l2_vlan_start+ns.no_of_l2_vlans-1)
                    log.info(banner('The Choosen Vlan is : {0}'.format(vlan)))
                    res = [trigger_obj.changeInterfaceSwitchPortMode(node_dict['all_dut'][x],intf,vlan,mode='access') for x in devices for intf in interfaces]
                    countDownTimer(150)
                    new_out = trigger_obj.checkAllRawStreamStatsTrigger(tgn_hdl,len(interfaces),trigger_type,ns.no_of_l2_vlans)
                    if not new_out['status']:
                        log.error(banner('The following stream {1} has failed in Vlan {1} '.format(vlan,new_out['streams'])))
                        res = [trigger_obj.changeInterfaceSwitchPortMode(node_dict['all_dut'][x],intf,allowed_vlan,mode='trunk') for x in devices for intf in interfaces]
                        self.failed()
                 
                log.info(banner('The RAW Stream traffic stats are fine.. FLapping the PO Memboer ports:'))
                
                
                switch_details = trigger_obj.getVPCSwitchhdl('details')
                
                dut = switch_details['primary']['dut']
                
                for po in configdict['vpc_config_dict'][dut]['vpc_port_channels'].keys():
                    res = MyLib.my_utils.parseVPCPortChannelParams(log,configdict['vpc_config_dict'][dut]['vpc_port_channels'][po])
                    log.info('the value of res is : {0}'.format(res))
                
                member_ports = res.members.split(',')
                log.info('The value of member_ports is {0}'.format(member_ports))
                
                for intf in member_ports:
                    cfg1 = '''interface {0}
                              shutdown'''.format(alias_intf_mapping_dict[intf])
                    node_dict['all_dut'][dut].configure(cfg1)
                
                log.info(banner('Waiting for 30 seconds before Measureing the Traffic stats .. {0}'.format(countDownTimer(30))))
                new_out1 = trigger_obj.checkAllRawStreamStatsTrigger(tgn_hdl,len(interfaces),trigger_type,ns.no_of_l2_vlans)
                if not new_out1['status']:
                    log.error(banner('The following stream {1} has failed in Vlan {1} '.format(vlan,new_out1['streams'])))
                    res = [trigger_obj.changeInterfaceSwitchPortMode(node_dict['all_dut'][x],intf,allowed_vlan,mode='trunk') for x in devices for intf in interfaces]
                    
                log.info(banner('Sleeping for 5 seconds before bringing up the member ports on dut {1} and interface {0}'.format(countDownTimer(5),dut)))
                for intf in member_ports:
                    cfg2 = '''interface {0}
                              no shutdown'''.format(alias_intf_mapping_dict[intf])
                    node_dict['all_dut'][dut].configure(cfg2)                    
                
                log.info(banner('Waiting for 30 seconds before Measureing the Traffic stats .. {0}'.format(countDownTimer(30))))
                new_out2 = trigger_obj.checkAllRawStreamStatsTrigger(tgn_hdl,len(interfaces),trigger_type,ns.no_of_l2_vlans)
                if not new_out2['status']:
                    log.error(banner('The following stream {1} has failed in Vlan {1} '.format(vlan,new_out2['streams'])))
                    res = [trigger_obj.changeInterfaceSwitchPortMode(node_dict['all_dut'][x],intf,allowed_vlan,mode='trunk') for x in devices for intf in interfaces]
                    
                res = [trigger_obj.changeInterfaceSwitchPortMode(node_dict['all_dut'][x],intf,allowed_vlan,mode='trunk') for x in devices for intf in interfaces]
                
                countDownTimer(150)
                log.info(banner('Checking Traffic stats on all the configured streams.:'))
                out = trigger_obj.checkAllStreamStats(tgn_hdl)
                if not out:
                    log.error(banner('Traffic has not recovered on some of the streams.. '))
                    self.failed()                    
            else:
                log.error('The Initial Traffic Condition did not pass :')
                self.failed()

class VXLANVxlanV6FUNC049(aetest.Testcase):

    """ Vxlan Trigger - ACCESS VPC PORT Member Flap - Secondary"""

    uid = 'VXLAN-L3-VxlanV6-FUNC-049'
    
    @aetest.test
    def vxlanL2VPCSecondaryAccessPoMemberFlap(self,log,testscript,testbed):
        
        node_dict = testscript.parameters['node_dict']
        tg_interface_hdl_dict = testscript.parameters['tg_interface_hdl_dict'] 
        traffic_stream_dict = testscript.parameters['traffic_stream_dict'] 
        port_handle_dict = testscript.parameters['port_handle_dict']
        TGList_config_file = testscript.parameters['TGList']
        configdict = testscript.parameters['configdict'] 
        tgn_config_dict = configdict['TG']
        threshold = testscript.parameters['traffic_threshold'] 
        tgn_port_dut_mapping = testscript.parameters['tgn_port_dut_mapping']
        alias_intf_mapping_dict = testscript.parameters['alias_intf_mapping']
        configured_stream = testscript.parameters['configured_stream']
        trigger_obj = testscript.parameters['trigger_obj']

        log.info(banner('The value of configured stream is : {0}'.format(configured_stream))) 
        
        login = [node_dict['all_dut'][dut].execute('show version') for dut in node_dict['all_dut'] if re.search('uut', dut)]
        
        trf = configdict['trigger_dict']['TEST-049']['traffic_to_consider']
        traffic_item_list = expandTrafficItemList(trf)
        
        log.info(banner('The value of traffic_item_list is : {0}'.format(traffic_item_list)))
        
        devices = configdict['trigger_dict']['TEST-049']['trigger_dut']
        interfaces = list(configdict['interface_config_dict']['portchannel']['uut3'].keys())
        log.info('The value of len of interfaces is: {0}'.format(len(interfaces)))
        
        log.info(banner('the Value of interfaces is  {0} and type is : {1}'.format(interfaces,type(interfaces))))
        
        trigger_type = 'access_vpc_port'
        
        for dut in devices:
            ns = parseScaleVlanParms(log, configdict['scale_config_dict'][dut]['global']['vlan'])
            break

        log.info(banner('The value of ns is : {0}'.format(ns)))
        
        for TG in tgn_config_dict.keys():
            tgn_hdl = testscript.parameters['testbed_obj'].devices[TG]
            out = trigger_obj.checkAllStreamStats(tgn_hdl)
        
            if out:
                for i in range(0,1):
                    vlan = random.randint(ns.l2_vlan_start,(ns.l2_vlan_start+ns.no_of_l2_vlans-1))
                    allowed_vlan = str(ns.l2_vlan_start) + '-' + str(ns.l2_vlan_start+ns.no_of_l2_vlans-1)
                    log.info(banner('The Choosen Vlan is : {0}'.format(vlan)))
                    res = [trigger_obj.changeInterfaceSwitchPortMode(node_dict['all_dut'][x],intf,vlan,mode='access') for x in devices for intf in interfaces]
                    countDownTimer(150)
                    new_out = trigger_obj.checkAllRawStreamStatsTrigger(tgn_hdl,len(interfaces),trigger_type,ns.no_of_l2_vlans)
                    if not new_out['status']:
                        log.error(banner('The following stream {1} has failed in Vlan {1} '.format(vlan,new_out['streams'])))
                        res = [trigger_obj.changeInterfaceSwitchPortMode(node_dict['all_dut'][x],intf,allowed_vlan,mode='trunk') for x in devices for intf in interfaces]
                        self.failed()
                 
                log.info(banner('The RAW Stream traffic stats are fine.. FLapping the PO Memboer ports:'))
                
                
                switch_details = trigger_obj.getVPCSwitchhdl('details')
                
                dut = switch_details['secondary']['dut']
                
                for po in configdict['vpc_config_dict'][dut]['vpc_port_channels'].keys():
                    res = MyLib.my_utils.parseVPCPortChannelParams(log,configdict['vpc_config_dict'][dut]['vpc_port_channels'][po])
                    log.info('the value of res is : {0}'.format(res))
                
                member_ports = res.members.split(',')
                log.info('The value of member_ports is {0}'.format(member_ports))
                
                for intf in member_ports:
                    cfg1 = '''interface {0}
                              shutdown'''.format(alias_intf_mapping_dict[intf])
                    node_dict['all_dut'][dut].configure(cfg1)
                
                log.info(banner('Waiting for 30 seconds before Measureing the Traffic stats .. {0}'.format(countDownTimer(30))))
                new_out1 = trigger_obj.checkAllRawStreamStatsTrigger(tgn_hdl,len(interfaces),trigger_type,ns.no_of_l2_vlans)
                if not new_out1['status']:
                    log.error(banner('The following stream {1} has failed in Vlan {1} '.format(vlan,new_out1['streams'])))
                    res = [trigger_obj.changeInterfaceSwitchPortMode(node_dict['all_dut'][x],intf,allowed_vlan,mode='trunk') for x in devices for intf in interfaces]
                    
                log.info(banner('Sleeping for 5 seconds before bringing up the member ports on dut {1} and interface {0}'.format(countDownTimer(5),dut)))
                for intf in member_ports:
                    cfg2 = '''interface {0}
                              no shutdown'''.format(alias_intf_mapping_dict[intf])
                    node_dict['all_dut'][dut].configure(cfg2)                    
                
                log.info(banner('Waiting for 30 seconds before Measureing the Traffic stats .. {0}'.format(countDownTimer(30))))
                new_out2 = trigger_obj.checkAllRawStreamStatsTrigger(tgn_hdl,len(interfaces),trigger_type,ns.no_of_l2_vlans)
                if not new_out2['status']:
                    log.error(banner('The following stream {1} has failed in Vlan {1} '.format(vlan,new_out2['streams'])))
                    res = [trigger_obj.changeInterfaceSwitchPortMode(node_dict['all_dut'][x],intf,allowed_vlan,mode='trunk') for x in devices for intf in interfaces]
                    
                res = [trigger_obj.changeInterfaceSwitchPortMode(node_dict['all_dut'][x],intf,allowed_vlan,mode='trunk') for x in devices for intf in interfaces]
                
                countDownTimer(150)
                log.info(banner('Checking Traffic stats on all the configured streams.:'))
                out = trigger_obj.checkAllStreamStats(tgn_hdl)
                if not out:
                    log.error(banner('Traffic has not recovered on some of the streams.. '))
                    self.failed()                    
            else:
                log.error('The Initial Traffic Condition did not pass :')
                self.failed()


class VXLANVxlanV6FUNC050(aetest.Testcase):

    """ Vxlan Trigger - ACCESS VPC PORT Member Flap - L2 Switch"""

    uid = 'VXLAN-L3-VxlanV6-FUNC-050'
    
    @aetest.test
    def vxlanL2SwitchAccessPoMemberFlap(self,log,testscript,testbed):
        
        node_dict = testscript.parameters['node_dict']
        tg_interface_hdl_dict = testscript.parameters['tg_interface_hdl_dict'] 
        traffic_stream_dict = testscript.parameters['traffic_stream_dict'] 
        port_handle_dict = testscript.parameters['port_handle_dict']
        TGList_config_file = testscript.parameters['TGList']
        configdict = testscript.parameters['configdict'] 
        tgn_config_dict = configdict['TG']
        threshold = testscript.parameters['traffic_threshold'] 
        tgn_port_dut_mapping = testscript.parameters['tgn_port_dut_mapping']
        alias_intf_mapping_dict = testscript.parameters['alias_intf_mapping']
        configured_stream = testscript.parameters['configured_stream']
        trigger_obj = testscript.parameters['trigger_obj']

        log.info(banner('The value of configured stream is : {0}'.format(configured_stream))) 
        
        login = [node_dict['all_dut'][dut].execute('show version') for dut in node_dict['all_dut'] if re.search('uut', dut)]
        
        trf = configdict['trigger_dict']['TEST-048']['traffic_to_consider']
        traffic_item_list = expandTrafficItemList(trf)
        
        log.info(banner('The value of traffic_item_list is : {0}'.format(traffic_item_list)))
        
        devices = configdict['trigger_dict']['TEST-048']['trigger_dut']
        interfaces = list(configdict['interface_config_dict']['portchannel']['uut3'].keys())
        log.info('The value of len of interfaces is: {0}'.format(len(interfaces)))
        
        log.info(banner('the Value of interfaces is  {0} and type is : {1}'.format(interfaces,type(interfaces))))
        
        trigger_type = 'access_vpc_port'
        
        for dut in devices:
            ns = parseScaleVlanParms(log, configdict['scale_config_dict'][dut]['global']['vlan'])
            break

        log.info(banner('The value of ns is : {0}'.format(ns)))
        
        for TG in tgn_config_dict.keys():
            tgn_hdl = testscript.parameters['testbed_obj'].devices[TG]
            out = trigger_obj.checkAllStreamStats(tgn_hdl)
        
            if out:
                for i in range(0,1):
                    vlan = random.randint(ns.l2_vlan_start,(ns.l2_vlan_start+ns.no_of_l2_vlans-1))
                    allowed_vlan = str(ns.l2_vlan_start) + '-' + str(ns.l2_vlan_start+ns.no_of_l2_vlans-1)
                    log.info(banner('The Choosen Vlan is : {0}'.format(vlan)))
                    res = [trigger_obj.changeInterfaceSwitchPortMode(node_dict['all_dut'][x],intf,vlan,mode='access') for x in devices for intf in interfaces]
                    countDownTimer(150)
                    new_out = trigger_obj.checkAllRawStreamStatsTrigger(tgn_hdl,len(interfaces),trigger_type,ns.no_of_l2_vlans)
                    if not new_out['status']:
                        log.error(banner('The following stream {1} has failed in Vlan {1} '.format(vlan,new_out['streams'])))
                        res = [trigger_obj.changeInterfaceSwitchPortMode(node_dict['all_dut'][x],intf,allowed_vlan,mode='trunk') for x in devices for intf in interfaces]
                        self.failed()
                 
                log.info(banner('The RAW Stream traffic stats are fine.. FLapping the PO Memboer ports:'))
                
                
                switch_details = trigger_obj.getDeviceDict('l2_switch')
                for dut, hdl in switch_details.items(): pass

                for intf in configdict['interface_config_dict']['ethernet'][dut].keys():
                    if 'TG' not in intf:
                        cfg1 = '''interface {0}
                                  shutdown'''.format(alias_intf_mapping_dict[intf])
                        hdl.configure(cfg1)
                
                log.info(banner('Waiting for 30 seconds before Unshutting the interfaces .. {0}'.format(countDownTimer(30))))
                    
                for intf in configdict['interface_config_dict']['ethernet'][dut].keys():
                    if 'TG' not in intf:
                        cfg2 = '''interface {0}
                                  no shutdown'''.format(alias_intf_mapping_dict[intf])
                        hdl.configure(cfg2)                 
                
                log.info(banner('Waiting for 30 seconds before Measureing the Traffic stats .. {0}'.format(countDownTimer(90))))
                new_out2 = trigger_obj.checkAllRawStreamStatsTrigger(tgn_hdl,len(interfaces),trigger_type,ns.no_of_l2_vlans)
                if not new_out2['status']:
                    log.error(banner('The following stream {1} has failed in Vlan {1} '.format(vlan,new_out2['streams'])))
                    res = [trigger_obj.changeInterfaceSwitchPortMode(node_dict['all_dut'][x],intf,allowed_vlan,mode='trunk') for x in devices for intf in interfaces]
                    
                res = [trigger_obj.changeInterfaceSwitchPortMode(node_dict['all_dut'][x],intf,allowed_vlan,mode='trunk') for x in devices for intf in interfaces]
                
                countDownTimer(150)
                log.info(banner('Checking Traffic stats on all the configured streams.:'))
                out = trigger_obj.checkAllStreamStats(tgn_hdl)
                if not out:
                    log.error(banner('Traffic has not recovered on some of the streams.. '))
                    self.failed()                    
            else:
                log.error('The Initial Traffic Condition did not pass :')
                self.failed()

class VXLANVxlanV6FUNC051(aetest.Testcase):

    """ Vxlan Trigger - L2 Trunk VPC PORT Flap - Primary"""

    uid = 'VXLAN-L3-VxlanV6-FUNC-051'
    
    @aetest.test
    def vxlanL2VPCPrimaryTrunkPoFlap(self,log,testscript,testbed):
        
        node_dict = testscript.parameters['node_dict']
        tg_interface_hdl_dict = testscript.parameters['tg_interface_hdl_dict'] 
        traffic_stream_dict = testscript.parameters['traffic_stream_dict'] 
        port_handle_dict = testscript.parameters['port_handle_dict']
        TGList_config_file = testscript.parameters['TGList']
        configdict = testscript.parameters['configdict'] 
        tgn_config_dict = configdict['TG']
        threshold = testscript.parameters['traffic_threshold'] 
        tgn_port_dut_mapping = testscript.parameters['tgn_port_dut_mapping']
        alias_intf_mapping_dict = testscript.parameters['alias_intf_mapping']
        configured_stream = testscript.parameters['configured_stream']
        trigger_obj = testscript.parameters['trigger_obj']

        log.info(banner('The value of configured stream is : {0}'.format(configured_stream))) 
        
        login = [node_dict['all_dut'][dut].execute('show version') for dut in node_dict['all_dut'] if re.search('uut', dut)]
        
        trf = configdict['trigger_dict']['TEST-051']['traffic_to_consider']
        traffic_item_list = expandTrafficItemList(trf)
        
        log.info(banner('The value of traffic_item_list is : {0}'.format(traffic_item_list)))
        
        devices = configdict['trigger_dict']['TEST-051']['trigger_dut']
        interfaces = list(configdict['interface_config_dict']['portchannel']['uut3'].keys())
        log.info('The value of len of interfaces is: {0}'.format(len(interfaces)))
        
        log.info(banner('the Value of interfaces is  {0} and type is : {1}'.format(interfaces,type(interfaces))))
        
        trigger_type = 'trunk_vpc_port_shut'
        
        for dut in devices:
            ns = parseScaleVlanParms(log, configdict['scale_config_dict'][dut]['global']['vlan'])
            break

        log.info(banner('The value of ns is : {0}'.format(ns)))
        
        for TG in tgn_config_dict.keys():
            tgn_hdl = testscript.parameters['testbed_obj'].devices[TG]
            out = trigger_obj.checkAllStreamStats(tgn_hdl)
        
            if out:
                for i in range(0,1):
                    vlan = random.randint(ns.l2_vlan_start,(ns.l2_vlan_start+ns.no_of_l2_vlans-1))
                    allowed_vlan = str(ns.l2_vlan_start) + '-' + str(ns.l2_vlan_start+ns.no_of_l2_vlans-1)
                    log.info(banner('The Choosen Vlan is : {0}'.format(vlan)))
                    res = [trigger_obj.changeInterfaceSwitchPortMode(node_dict['all_dut'][x],intf,vlan,mode='access') for x in devices for intf in interfaces]
                    countDownTimer(150)
                    new_out = trigger_obj.checkAllRawStreamStatsTrigger(tgn_hdl,len(interfaces),trigger_type,ns.no_of_l2_vlans)
                    if not new_out['status']:
                        log.error(banner('The following stream {1} has failed in Vlan {1} '.format(vlan,new_out['streams'])))
                        res = [trigger_obj.changeInterfaceSwitchPortMode(node_dict['all_dut'][x],intf,allowed_vlan,mode='trunk') for x in devices for intf in interfaces]
                        self.failed()
                
                log.info(banner('The RAW Stream traffic stats are fine.. FLapping the Access Side PO:'))
                
                
                vpc_primary_hdl = trigger_obj.getVPCSwitchhdl('primary')
                cfg1 = '''interface {0}
                         shutdown'''.format("".join(interfaces))
                vpc_primary_hdl.configure(cfg1)
                log.info(banner('Sleeping for 5 seconds before bringing up the port on dut {1} and interface {2} {0}'.format(countDownTimer(5),dut,interfaces)))
                cfg2 = '''interface {0}
                          no shutdown'''.format("".join(interfaces))
                vpc_primary_hdl.configure(cfg2)
                log.info(banner('Waiting for 30 seconds before Measureing the Traffic stats .. {0}'.format(countDownTimer(30))))
                new_out1 = trigger_obj.checkAllRawStreamStatsTrigger(tgn_hdl,len(interfaces),trigger_type,ns.no_of_l2_vlans)
                if not new_out1['status']:
                    log.error(banner('The following stream {1} has failed in Vlan {1} '.format(vlan,new_out1['streams'])))
                    res = [trigger_obj.changeInterfaceSwitchPortMode(node_dict['all_dut'][x],intf,allowed_vlan,mode='trunk') for x in devices for intf in interfaces]
                        
                res = [trigger_obj.changeInterfaceSwitchPortMode(node_dict['all_dut'][x],intf,allowed_vlan,mode='trunk') for x in devices for intf in interfaces]
                
                countDownTimer(150)
                log.info(banner('Checking Traffic stats on all the configured streams.:'))
                out = trigger_obj.checkAllStreamStats(tgn_hdl)
                if not out:
                    log.error(banner('Traffic has not recovered on some of the streams.. '))
                    self.failed()                    
            else:
                log.error('The Initial Traffic Condition did not pass :')
                self.failed()


class VXLANVxlanV6FUNC052(aetest.Testcase):

    """ Vxlan Trigger - Trunk VPC PORT Flap - Secondary"""

    uid = 'VXLAN-L3-VxlanV6-FUNC-052'
    
    @aetest.test
    def vxlanL2VPCSecondaryTrunkPoFlap(self,log,testscript,testbed):
        
        node_dict = testscript.parameters['node_dict']
        tg_interface_hdl_dict = testscript.parameters['tg_interface_hdl_dict'] 
        traffic_stream_dict = testscript.parameters['traffic_stream_dict'] 
        port_handle_dict = testscript.parameters['port_handle_dict']
        TGList_config_file = testscript.parameters['TGList']
        configdict = testscript.parameters['configdict'] 
        tgn_config_dict = configdict['TG']
        threshold = testscript.parameters['traffic_threshold'] 
        tgn_port_dut_mapping = testscript.parameters['tgn_port_dut_mapping']
        alias_intf_mapping_dict = testscript.parameters['alias_intf_mapping']
        configured_stream = testscript.parameters['configured_stream']
        trigger_obj = testscript.parameters['trigger_obj']

        log.info(banner('The value of configured stream is : {0}'.format(configured_stream))) 
        
        login = [node_dict['all_dut'][dut].execute('show version') for dut in node_dict['all_dut'] if re.search('uut', dut)]
        
        trf = configdict['trigger_dict']['TEST-052']['traffic_to_consider']
        traffic_item_list = expandTrafficItemList(trf)
        
        log.info(banner('The value of traffic_item_list is : {0}'.format(traffic_item_list)))
        
        devices = configdict['trigger_dict']['TEST-052']['trigger_dut']
        interfaces = list(configdict['interface_config_dict']['portchannel']['uut3'].keys())
        log.info('The value of len of interfaces is: {0}'.format(len(interfaces)))
        
        log.info(banner('the Value of interfaces is  {0} and type is : {1}'.format(interfaces,type(interfaces))))
        
        trigger_type = 'trunk_vpc_port_shut'
        
        for dut in devices:
            ns = parseScaleVlanParms(log, configdict['scale_config_dict'][dut]['global']['vlan'])
            break

        log.info(banner('The value of ns is : {0}'.format(ns)))
        
        for TG in tgn_config_dict.keys():
            tgn_hdl = testscript.parameters['testbed_obj'].devices[TG]
            out = trigger_obj.checkAllStreamStats(tgn_hdl)
        
            if out:
                for i in range(0,1):
                    vlan = random.randint(ns.l2_vlan_start,(ns.l2_vlan_start+ns.no_of_l2_vlans-1))
                    allowed_vlan = str(ns.l2_vlan_start) + '-' + str(ns.l2_vlan_start+ns.no_of_l2_vlans-1)
                    log.info(banner('The Choosen Vlan is : {0}'.format(vlan)))
                    res = [trigger_obj.changeInterfaceSwitchPortMode(node_dict['all_dut'][x],intf,vlan,mode='access') for x in devices for intf in interfaces]
                    countDownTimer(150)
                    new_out = trigger_obj.checkAllRawStreamStatsTrigger(tgn_hdl,len(interfaces),trigger_type,ns.no_of_l2_vlans)
                    if not new_out['status']:
                        log.error(banner('The following stream {1} has failed in Vlan {1} '.format(vlan,new_out['streams'])))
                        res = [trigger_obj.changeInterfaceSwitchPortMode(node_dict['all_dut'][x],intf,allowed_vlan,mode='trunk') for x in devices for intf in interfaces]
                        self.failed()
                
                log.info(banner('The RAW Stream traffic stats are fine.. FLapping the TRunk Side PO:'))
                
                
                vpc_secondary_hdl = trigger_obj.getVPCSwitchhdl('secondary')
                cfg1 = '''interface {0}
                         shutdown'''.format("".join(interfaces))
                vpc_secondary_hdl.configure(cfg1)
                log.info(banner('Sleeping for 5 seconds before bringing up the port on dut {1} and interface {2} {0}'.format(countDownTimer(5),dut,interfaces)))
                cfg2 = '''interface {0}
                          no shutdown'''.format("".join(interfaces))
                vpc_secondary_hdl.configure(cfg2)
                log.info(banner('Waiting for 30 seconds before Measureing the Traffic stats .. {0}'.format(countDownTimer(30))))
                new_out1 = trigger_obj.checkAllRawStreamStatsTrigger(tgn_hdl,len(interfaces),trigger_type,ns.no_of_l2_vlans)
                if not new_out1['status']:
                    log.error(banner('The following stream {1} has failed in Vlan {1} '.format(vlan,new_out1['streams'])))
                    res = [trigger_obj.changeInterfaceSwitchPortMode(node_dict['all_dut'][x],intf,allowed_vlan,mode='trunk') for x in devices for intf in interfaces]
                        
                res = [trigger_obj.changeInterfaceSwitchPortMode(node_dict['all_dut'][x],intf,allowed_vlan,mode='trunk') for x in devices for intf in interfaces]
                
                countDownTimer(150)
                log.info(banner('Checking Traffic stats on all the configured streams.:'))
                out = trigger_obj.checkAllStreamStats(tgn_hdl)
                if not out:
                    log.error(banner('Traffic has not recovered on some of the streams.. '))
                    self.failed()                    
            else:
                log.error('The Initial Traffic Condition did not pass :')
                self.failed()


class VXLANVxlanV6FUNC053(aetest.Testcase):

    """ Vxlan Trigger - Trunk VPC PORT Flap - L2 Switch"""

    uid = 'VXLAN-L3-VxlanV6-FUNC-053'
    
    @aetest.test
    def vxlanL2SwitchTrunkPoFlap(self,log,testscript,testbed):
        
        node_dict = testscript.parameters['node_dict']
        tg_interface_hdl_dict = testscript.parameters['tg_interface_hdl_dict'] 
        traffic_stream_dict = testscript.parameters['traffic_stream_dict'] 
        port_handle_dict = testscript.parameters['port_handle_dict']
        TGList_config_file = testscript.parameters['TGList']
        configdict = testscript.parameters['configdict'] 
        tgn_config_dict = configdict['TG']
        threshold = testscript.parameters['traffic_threshold'] 
        tgn_port_dut_mapping = testscript.parameters['tgn_port_dut_mapping']
        alias_intf_mapping_dict = testscript.parameters['alias_intf_mapping']
        configured_stream = testscript.parameters['configured_stream']
        trigger_obj = testscript.parameters['trigger_obj']

        log.info(banner('The value of configured stream is : {0}'.format(configured_stream))) 
        
        login = [node_dict['all_dut'][dut].execute('show version') for dut in node_dict['all_dut'] if re.search('uut', dut)]
        
        trf = configdict['trigger_dict']['TEST-053']['traffic_to_consider']
        traffic_item_list = expandTrafficItemList(trf)
        
        log.info(banner('The value of traffic_item_list is : {0}'.format(traffic_item_list)))
        
        devices = configdict['trigger_dict']['TEST-053']['trigger_dut']
        interfaces = list(configdict['interface_config_dict']['portchannel']['uut3'].keys())
        log.info('The value of len of interfaces is: {0}'.format(len(interfaces)))
        
        log.info(banner('the Value of interfaces is  {0} and type is : {1}'.format(interfaces,type(interfaces))))
        
        trigger_type = 'trunk_vpc_port_shut'
        
        for dut in devices:
            ns = parseScaleVlanParms(log, configdict['scale_config_dict'][dut]['global']['vlan'])
            break

        log.info(banner('The value of ns is : {0}'.format(ns)))
        
        for TG in tgn_config_dict.keys():
            tgn_hdl = testscript.parameters['testbed_obj'].devices[TG]
            out = trigger_obj.checkAllStreamStats(tgn_hdl)
        
            if out:
                for i in range(0,1):
                    vlan = random.randint(ns.l2_vlan_start,(ns.l2_vlan_start+ns.no_of_l2_vlans-1))
                    allowed_vlan = str(ns.l2_vlan_start) + '-' + str(ns.l2_vlan_start+ns.no_of_l2_vlans-1)
                    log.info(banner('The Choosen Vlan is : {0}'.format(vlan)))
                    res = [trigger_obj.changeInterfaceSwitchPortMode(node_dict['all_dut'][x],intf,vlan,mode='access') for x in devices for intf in interfaces]
                    countDownTimer(150)
                    new_out = trigger_obj.checkAllRawStreamStatsTrigger(tgn_hdl,len(interfaces),trigger_type,ns.no_of_l2_vlans)
                    if not new_out['status']:
                        log.error(banner('The following stream {1} has failed in Vlan {1} '.format(vlan,new_out['streams'])))
                        res = [trigger_obj.changeInterfaceSwitchPortMode(node_dict['all_dut'][x],intf,allowed_vlan,mode='trunk') for x in devices for intf in interfaces]
                        self.failed()
                
                log.info(banner('The RAW Stream traffic stats are fine.. FLapping the Access Side PO:'))
                
                res = trigger_obj.getDeviceDict('l2_switch')
                log.info(banner('The value of res is : {0}'.format(res)))
                
                for dut, l2_switch_hdl in trigger_obj.getDeviceDict('l2_switch').items(): pass
                
                cfg1 = '''interface {0}
                         shutdown'''.format("".join(interfaces))
                l2_switch_hdl.configure(cfg1)
                log.info(banner('Sleeping for 5 seconds before bringing up the port on dut {1} and interface {2} {0}'.format(countDownTimer(5),dut,interfaces)))
                cfg2 = '''interface {0}
                          no shutdown'''.format("".join(interfaces))
                l2_switch_hdl.configure(cfg2)
                log.info(banner('Waiting for 30 seconds before Measureing the Traffic stats .. {0}'.format(countDownTimer(90))))
                new_out1 = trigger_obj.checkAllRawStreamStatsTrigger(tgn_hdl,len(interfaces),trigger_type,ns.no_of_l2_vlans)
                if not new_out1['status']:
                    log.error(banner('The following stream {1} has failed in Vlan {1} '.format(vlan,new_out1['streams'])))
                    res = [trigger_obj.changeInterfaceSwitchPortMode(node_dict['all_dut'][x],intf,allowed_vlan,mode='trunk') for x in devices for intf in interfaces]
                        
                res = [trigger_obj.changeInterfaceSwitchPortMode(node_dict['all_dut'][x],intf,allowed_vlan,mode='trunk') for x in devices for intf in interfaces]
                
                countDownTimer(150)
                log.info(banner('Checking Traffic stats on all the configured streams.:'))
                out = trigger_obj.checkAllStreamStats(tgn_hdl)
                if not out:
                    log.error(banner('Traffic has not recovered on some of the streams.. '))
                    self.failed()                    
            else:
                log.error('The Initial Traffic Condition did not pass :')
                self.failed()


class VXLANVxlanV6FUNC054(aetest.Testcase):

    """ Vxlan Trigger - Trunk VPC PORT Member Flap - Primary"""

    uid = 'VXLAN-L3-VxlanV6-FUNC-054'
    
    @aetest.test
    def vxlanL2VPCPrimaryTrunkPoMemberFlap(self,log,testscript,testbed):
        
        node_dict = testscript.parameters['node_dict']
        tg_interface_hdl_dict = testscript.parameters['tg_interface_hdl_dict'] 
        traffic_stream_dict = testscript.parameters['traffic_stream_dict'] 
        port_handle_dict = testscript.parameters['port_handle_dict']
        TGList_config_file = testscript.parameters['TGList']
        configdict = testscript.parameters['configdict'] 
        tgn_config_dict = configdict['TG']
        threshold = testscript.parameters['traffic_threshold'] 
        tgn_port_dut_mapping = testscript.parameters['tgn_port_dut_mapping']
        alias_intf_mapping_dict = testscript.parameters['alias_intf_mapping']
        configured_stream = testscript.parameters['configured_stream']
        trigger_obj = testscript.parameters['trigger_obj']

        log.info(banner('The value of configured stream is : {0}'.format(configured_stream))) 
        
        login = [node_dict['all_dut'][dut].execute('show version') for dut in node_dict['all_dut'] if re.search('uut', dut)]
        
        trf = configdict['trigger_dict']['TEST-054']['traffic_to_consider']
        traffic_item_list = expandTrafficItemList(trf)
        
        log.info(banner('The value of traffic_item_list is : {0}'.format(traffic_item_list)))
        
        devices = configdict['trigger_dict']['TEST-054']['trigger_dut']
        interfaces = list(configdict['interface_config_dict']['portchannel']['uut3'].keys())
        log.info('The value of len of interfaces is: {0}'.format(len(interfaces)))
        
        log.info(banner('the Value of interfaces is  {0} and type is : {1}'.format(interfaces,type(interfaces))))
        
        trigger_type = 'trunk_vpc_port_shut'
        
        for dut in devices:
            ns = parseScaleVlanParms(log, configdict['scale_config_dict'][dut]['global']['vlan'])
            break

        log.info(banner('The value of ns is : {0}'.format(ns)))
        
        for TG in tgn_config_dict.keys():
            tgn_hdl = testscript.parameters['testbed_obj'].devices[TG]
            out = trigger_obj.checkAllStreamStats(tgn_hdl)
        
            if out:
                for i in range(0,1):
                    vlan = random.randint(ns.l2_vlan_start,(ns.l2_vlan_start+ns.no_of_l2_vlans-1))
                    allowed_vlan = str(ns.l2_vlan_start) + '-' + str(ns.l2_vlan_start+ns.no_of_l2_vlans-1)
                    log.info(banner('The Choosen Vlan is : {0}'.format(vlan)))
                    res = [trigger_obj.changeInterfaceSwitchPortMode(node_dict['all_dut'][x],intf,vlan,mode='access') for x in devices for intf in interfaces]
                    countDownTimer(150)
                    new_out = trigger_obj.checkAllRawStreamStatsTrigger(tgn_hdl,len(interfaces),trigger_type,ns.no_of_l2_vlans)
                    if not new_out['status']:
                        log.error(banner('The following stream {1} has failed in Vlan {1} '.format(vlan,new_out['streams'])))
                        res = [trigger_obj.changeInterfaceSwitchPortMode(node_dict['all_dut'][x],intf,allowed_vlan,mode='trunk') for x in devices for intf in interfaces]
                        self.failed()
                 
                log.info(banner('The RAW Stream traffic stats are fine.. FLapping the PO Memboer ports:'))
                
                
                switch_details = trigger_obj.getVPCSwitchhdl('details')
                
                dut = switch_details['primary']['dut']
                
                for po in configdict['vpc_config_dict'][dut]['vpc_port_channels'].keys():
                    res = MyLib.my_utils.parseVPCPortChannelParams(log,configdict['vpc_config_dict'][dut]['vpc_port_channels'][po])
                    log.info('the value of res is : {0}'.format(res))
                
                member_ports = res.members.split(',')
                log.info('The value of member_ports is {0}'.format(member_ports))
                
                for intf in member_ports:
                    cfg1 = '''interface {0}
                              shutdown'''.format(alias_intf_mapping_dict[intf])
                    node_dict['all_dut'][dut].configure(cfg1)
                
                log.info(banner('Waiting for 30 seconds before Measureing the Traffic stats .. {0}'.format(countDownTimer(30))))
                new_out1 = trigger_obj.checkAllRawStreamStatsTrigger(tgn_hdl,len(interfaces),trigger_type,ns.no_of_l2_vlans)
                if not new_out1['status']:
                    log.error(banner('The following stream {1} has failed in Vlan {1} '.format(vlan,new_out1['streams'])))
                    res = [trigger_obj.changeInterfaceSwitchPortMode(node_dict['all_dut'][x],intf,allowed_vlan,mode='trunk') for x in devices for intf in interfaces]
                    
                log.info(banner('Sleeping for 5 seconds before bringing up the member ports on dut {1} and interface {0}'.format(countDownTimer(5),dut)))
                for intf in member_ports:
                    cfg2 = '''interface {0}
                              no shutdown'''.format(alias_intf_mapping_dict[intf])
                    node_dict['all_dut'][dut].configure(cfg2)                    
                
                log.info(banner('Waiting for 30 seconds before Measureing the Traffic stats .. {0}'.format(countDownTimer(30))))
                new_out2 = trigger_obj.checkAllRawStreamStatsTrigger(tgn_hdl,len(interfaces),trigger_type,ns.no_of_l2_vlans)
                if not new_out2['status']:
                    log.error(banner('The following stream {1} has failed in Vlan {1} '.format(vlan,new_out2['streams'])))
                    res = [trigger_obj.changeInterfaceSwitchPortMode(node_dict['all_dut'][x],intf,allowed_vlan,mode='trunk') for x in devices for intf in interfaces]
                    
                res = [trigger_obj.changeInterfaceSwitchPortMode(node_dict['all_dut'][x],intf,allowed_vlan,mode='trunk') for x in devices for intf in interfaces]
                
                countDownTimer(150)
                log.info(banner('Checking Traffic stats on all the configured streams.:'))
                out = trigger_obj.checkAllStreamStats(tgn_hdl)
                if not out:
                    log.error(banner('Traffic has not recovered on some of the streams.. '))
                    self.failed()                    
            else:
                log.error('The Initial Traffic Condition did not pass :')
                self.failed()

class VXLANVxlanV6FUNC055(aetest.Testcase):

    """ Vxlan Trigger - Trunk VPC PORT Member Flap - Secondary"""

    uid = 'VXLAN-L3-VxlanV6-FUNC-055'
    
    @aetest.test
    def vxlanL2VPCSecondaryAccessPoMemberFlap(self,log,testscript,testbed):
        
        node_dict = testscript.parameters['node_dict']
        tg_interface_hdl_dict = testscript.parameters['tg_interface_hdl_dict'] 
        traffic_stream_dict = testscript.parameters['traffic_stream_dict'] 
        port_handle_dict = testscript.parameters['port_handle_dict']
        TGList_config_file = testscript.parameters['TGList']
        configdict = testscript.parameters['configdict'] 
        tgn_config_dict = configdict['TG']
        threshold = testscript.parameters['traffic_threshold'] 
        tgn_port_dut_mapping = testscript.parameters['tgn_port_dut_mapping']
        alias_intf_mapping_dict = testscript.parameters['alias_intf_mapping']
        configured_stream = testscript.parameters['configured_stream']
        trigger_obj = testscript.parameters['trigger_obj']

        log.info(banner('The value of configured stream is : {0}'.format(configured_stream))) 
        
        login = [node_dict['all_dut'][dut].execute('show version') for dut in node_dict['all_dut'] if re.search('uut', dut)]
        
        trf = configdict['trigger_dict']['TEST-049']['traffic_to_consider']
        traffic_item_list = expandTrafficItemList(trf)
        
        log.info(banner('The value of traffic_item_list is : {0}'.format(traffic_item_list)))
        
        devices = configdict['trigger_dict']['TEST-055']['trigger_dut']
        interfaces = list(configdict['interface_config_dict']['portchannel']['uut3'].keys())
        log.info('The value of len of interfaces is: {0}'.format(len(interfaces)))
        
        log.info(banner('the Value of interfaces is  {0} and type is : {1}'.format(interfaces,type(interfaces))))
        
        trigger_type = 'trunk_vpc_port_shut'
        
        for dut in devices:
            ns = parseScaleVlanParms(log, configdict['scale_config_dict'][dut]['global']['vlan'])
            break

        log.info(banner('The value of ns is : {0}'.format(ns)))
        
        for TG in tgn_config_dict.keys():
            tgn_hdl = testscript.parameters['testbed_obj'].devices[TG]
            out = trigger_obj.checkAllStreamStats(tgn_hdl)
        
            if out:
                for i in range(0,1):
                    vlan = random.randint(ns.l2_vlan_start,(ns.l2_vlan_start+ns.no_of_l2_vlans-1))
                    allowed_vlan = str(ns.l2_vlan_start) + '-' + str(ns.l2_vlan_start+ns.no_of_l2_vlans-1)
                    log.info(banner('The Choosen Vlan is : {0}'.format(vlan)))
                    res = [trigger_obj.changeInterfaceSwitchPortMode(node_dict['all_dut'][x],intf,vlan,mode='access') for x in devices for intf in interfaces]
                    countDownTimer(150)
                    new_out = trigger_obj.checkAllRawStreamStatsTrigger(tgn_hdl,len(interfaces),trigger_type,ns.no_of_l2_vlans)
                    if not new_out['status']:
                        log.error(banner('The following stream {1} has failed in Vlan {1} '.format(vlan,new_out['streams'])))
                        res = [trigger_obj.changeInterfaceSwitchPortMode(node_dict['all_dut'][x],intf,allowed_vlan,mode='trunk') for x in devices for intf in interfaces]
                        self.failed()
                 
                log.info(banner('The RAW Stream traffic stats are fine.. FLapping the PO Memboer ports:'))
                
                
                switch_details = trigger_obj.getVPCSwitchhdl('details')
                
                dut = switch_details['secondary']['dut']
                
                for po in configdict['vpc_config_dict'][dut]['vpc_port_channels'].keys():
                    res = MyLib.my_utils.parseVPCPortChannelParams(log,configdict['vpc_config_dict'][dut]['vpc_port_channels'][po])
                    log.info('the value of res is : {0}'.format(res))
                
                member_ports = res.members.split(',')
                log.info('The value of member_ports is {0}'.format(member_ports))
                
                for intf in member_ports:
                    cfg1 = '''interface {0}
                              shutdown'''.format(alias_intf_mapping_dict[intf])
                    node_dict['all_dut'][dut].configure(cfg1)
                
                log.info(banner('Waiting for 30 seconds before Measureing the Traffic stats .. {0}'.format(countDownTimer(30))))
                new_out1 = trigger_obj.checkAllRawStreamStatsTrigger(tgn_hdl,len(interfaces),trigger_type,ns.no_of_l2_vlans)
                if not new_out1['status']:
                    log.error(banner('The following stream {1} has failed in Vlan {1} '.format(vlan,new_out1['streams'])))
                    res = [trigger_obj.changeInterfaceSwitchPortMode(node_dict['all_dut'][x],intf,allowed_vlan,mode='trunk') for x in devices for intf in interfaces]
                    
                log.info(banner('Sleeping for 5 seconds before bringing up the member ports on dut {1} and interface {0}'.format(countDownTimer(5),dut)))
                for intf in member_ports:
                    cfg2 = '''interface {0}
                              no shutdown'''.format(alias_intf_mapping_dict[intf])
                    node_dict['all_dut'][dut].configure(cfg2)                    
                
                log.info(banner('Waiting for 30 seconds before Measureing the Traffic stats .. {0}'.format(countDownTimer(30))))
                new_out2 = trigger_obj.checkAllRawStreamStatsTrigger(tgn_hdl,len(interfaces),trigger_type,ns.no_of_l2_vlans)
                if not new_out2['status']:
                    log.error(banner('The following stream {1} has failed in Vlan {1} '.format(vlan,new_out2['streams'])))
                    res = [trigger_obj.changeInterfaceSwitchPortMode(node_dict['all_dut'][x],intf,allowed_vlan,mode='trunk') for x in devices for intf in interfaces]
                    
                res = [trigger_obj.changeInterfaceSwitchPortMode(node_dict['all_dut'][x],intf,allowed_vlan,mode='trunk') for x in devices for intf in interfaces]
                
                countDownTimer(150)
                log.info(banner('Checking Traffic stats on all the configured streams.:'))
                out = trigger_obj.checkAllStreamStats(tgn_hdl)
                if not out:
                    log.error(banner('Traffic has not recovered on some of the streams.. '))
                    self.failed()                    
            else:
                log.error('The Initial Traffic Condition did not pass :')
                self.failed()


class VXLANVxlanV6FUNC056(aetest.Testcase):

    """ Vxlan Trigger - Trunk VPC PORT Member Flap - L2 Switch"""

    uid = 'VXLAN-L3-VxlanV6-FUNC-056'
    
    @aetest.test
    def vxlanL2SwitchTrunkPoMemberFlap(self,log,testscript,testbed):
        
        node_dict = testscript.parameters['node_dict']
        tg_interface_hdl_dict = testscript.parameters['tg_interface_hdl_dict'] 
        traffic_stream_dict = testscript.parameters['traffic_stream_dict'] 
        port_handle_dict = testscript.parameters['port_handle_dict']
        TGList_config_file = testscript.parameters['TGList']
        configdict = testscript.parameters['configdict'] 
        tgn_config_dict = configdict['TG']
        threshold = testscript.parameters['traffic_threshold'] 
        tgn_port_dut_mapping = testscript.parameters['tgn_port_dut_mapping']
        alias_intf_mapping_dict = testscript.parameters['alias_intf_mapping']
        configured_stream = testscript.parameters['configured_stream']
        trigger_obj = testscript.parameters['trigger_obj']

        log.info(banner('The value of configured stream is : {0}'.format(configured_stream))) 
        
        login = [node_dict['all_dut'][dut].execute('show version') for dut in node_dict['all_dut'] if re.search('uut', dut)]
        
        trf = configdict['trigger_dict']['TEST-056']['traffic_to_consider']
        traffic_item_list = expandTrafficItemList(trf)
        
        log.info(banner('The value of traffic_item_list is : {0}'.format(traffic_item_list)))
        
        devices = configdict['trigger_dict']['TEST-056']['trigger_dut']
        interfaces = list(configdict['interface_config_dict']['portchannel']['uut3'].keys())
        log.info('The value of len of interfaces is: {0}'.format(len(interfaces)))
        
        log.info(banner('the Value of interfaces is  {0} and type is : {1}'.format(interfaces,type(interfaces))))
        
        trigger_type = 'trunk_vpc_port_shut'
        
        for dut in devices:
            ns = parseScaleVlanParms(log, configdict['scale_config_dict'][dut]['global']['vlan'])
            break

        log.info(banner('The value of ns is : {0}'.format(ns)))
        
        for TG in tgn_config_dict.keys():
            tgn_hdl = testscript.parameters['testbed_obj'].devices[TG]
            out = trigger_obj.checkAllStreamStats(tgn_hdl)
        
            if out:
                for i in range(0,1):
                    vlan = random.randint(ns.l2_vlan_start,(ns.l2_vlan_start+ns.no_of_l2_vlans-1))
                    allowed_vlan = str(ns.l2_vlan_start) + '-' + str(ns.l2_vlan_start+ns.no_of_l2_vlans-1)
                    log.info(banner('The Choosen Vlan is : {0}'.format(vlan)))
                    res = [trigger_obj.changeInterfaceSwitchPortMode(node_dict['all_dut'][x],intf,vlan,mode='access') for x in devices for intf in interfaces]
                    countDownTimer(150)
                    new_out = trigger_obj.checkAllRawStreamStatsTrigger(tgn_hdl,len(interfaces),trigger_type,ns.no_of_l2_vlans)
                    if not new_out['status']:
                        log.error(banner('The following stream {1} has failed in Vlan {1} '.format(vlan,new_out['streams'])))
                        res = [trigger_obj.changeInterfaceSwitchPortMode(node_dict['all_dut'][x],intf,allowed_vlan,mode='trunk') for x in devices for intf in interfaces]
                        self.failed()
                 
                log.info(banner('The RAW Stream traffic stats are fine.. FLapping the PO Memboer ports:'))
                
                
                switch_details = trigger_obj.getDeviceDict('l2_switch')
                for dut, hdl in switch_details.items(): pass

                for intf in configdict['interface_config_dict']['ethernet'][dut].keys():
                    if 'TG' not in intf:
                        cfg1 = '''interface {0}
                                  shutdown'''.format(alias_intf_mapping_dict[intf])
                        hdl.configure(cfg1)
                
                log.info(banner('Waiting for 30 seconds before Unshutting the interfaces .. {0}'.format(countDownTimer(30))))
                    
                for intf in configdict['interface_config_dict']['ethernet'][dut].keys():
                    if 'TG' not in intf:
                        cfg2 = '''interface {0}
                                  no shutdown'''.format(alias_intf_mapping_dict[intf])
                        hdl.configure(cfg2)                 
                
                log.info(banner('Waiting for 30 seconds before Measureing the Traffic stats .. {0}'.format(countDownTimer(90))))
                new_out2 = trigger_obj.checkAllRawStreamStatsTrigger(tgn_hdl,len(interfaces),trigger_type,ns.no_of_l2_vlans)
                if not new_out2['status']:
                    log.error(banner('The following stream {1} has failed in Vlan {1} '.format(vlan,new_out2['streams'])))
                    res = [trigger_obj.changeInterfaceSwitchPortMode(node_dict['all_dut'][x],intf,allowed_vlan,mode='trunk') for x in devices for intf in interfaces]
                    
                res = [trigger_obj.changeInterfaceSwitchPortMode(node_dict['all_dut'][x],intf,allowed_vlan,mode='trunk') for x in devices for intf in interfaces]
                
                countDownTimer(150)
                log.info(banner('Checking Traffic stats on all the configured streams.:'))
                out = trigger_obj.checkAllStreamStats(tgn_hdl)
                if not out:
                    log.error(banner('Traffic has not recovered on some of the streams.. '))
                    self.failed()                    
            else:
                log.error('The Initial Traffic Condition did not pass :')
                self.failed()



class VXLANVxlanV6FUNC057(aetest.Testcase):

    """ Vxlan Trigger - GIR on VPC PRimary"""

    uid = 'VXLAN-L3-VxlanV6-FUNC-057'
    
    @aetest.test
    def vxlanGIROnVPCPrimary(self,log,testscript,testbed):
        
        node_dict = testscript.parameters['node_dict']
        tg_interface_hdl_dict = testscript.parameters['tg_interface_hdl_dict'] 
        traffic_stream_dict = testscript.parameters['traffic_stream_dict'] 
        port_handle_dict = testscript.parameters['port_handle_dict']
        TGList_config_file = testscript.parameters['TGList']
        configdict = testscript.parameters['configdict'] 
        tgn_config_dict = configdict['TG']
        threshold = testscript.parameters['traffic_threshold'] 
        tgn_port_dut_mapping = testscript.parameters['tgn_port_dut_mapping']
        alias_intf_mapping_dict = testscript.parameters['alias_intf_mapping']
        configured_stream = testscript.parameters['configured_stream']
        trigger_obj = testscript.parameters['trigger_obj']

        log.info(banner('The value of configured stream is : {0}'.format(configured_stream))) 
        
        login = [node_dict['all_dut'][dut].execute('show version') for dut in node_dict['all_dut'] if re.search('uut', dut)]
        
        for TG in tgn_config_dict.keys():
            tgn_hdl = testscript.parameters['testbed_obj'].devices[TG]
            out = trigger_obj.checkAllStreamStats(tgn_hdl)
        
            if out:
                vpc_primary_hdl = trigger_obj.getVPCSwitchhdl('primary')
                cfg = 'system mode maintenance'
                vpc_primary_hdl.configure(cfg, timeout = 300)
                time.sleep(30)
                vpc_primary_hdl.expect('\[no\]')
                vpc_primary_hdl.sendline('yes')
                vpc_primary_hdl.expect('# $')
                
                log.info(banner('Sleeping for 320 seconds for the GIR.. Countdown Starts {0}'.format(countDownTimer(320))))
                
                vpc_primary_hdl.configure('no' + cfg)
                vpc_primary_hdl.iexpect('Do you want to continue \(yes/no\)\? \[no\]')
                vpc_primary_hdl.isendline('yes')
                vpc_primary_hdl.iexpect('#')
                
                log.info(banner('Sleeping for 300 seconds for the traffic to converge after GIR.. Countdown Starts {0}'.format(countDownTimer(300))))
                out1 = trigger_obj.checkAllStreamStats(tgn_hdl)
                if out1:
                    log.info(banner('Traffic has recovered post GIR Trigger.. '))
                else:
                    log.info(banner('Traffic has not recovered post GIR Trigger..... Getting the individual stats.'))
                    self.failed()
            else:
                log.error('The Initial Traffic Condition did not pass :')
                self.failed()


class VXLANVxlanV6FUNC058(aetest.Testcase):

    """ Vxlan Trigger - GIR on VPC Secondary"""

    uid = 'VXLAN-L3-VxlanV6-FUNC-058'
    
    @aetest.test
    def vxlanGIROnVPCSecondary(self,log,testscript,testbed):
        
        node_dict = testscript.parameters['node_dict']
        tg_interface_hdl_dict = testscript.parameters['tg_interface_hdl_dict'] 
        traffic_stream_dict = testscript.parameters['traffic_stream_dict'] 
        port_handle_dict = testscript.parameters['port_handle_dict']
        TGList_config_file = testscript.parameters['TGList']
        configdict = testscript.parameters['configdict'] 
        tgn_config_dict = configdict['TG']
        threshold = testscript.parameters['traffic_threshold'] 
        tgn_port_dut_mapping = testscript.parameters['tgn_port_dut_mapping']
        alias_intf_mapping_dict = testscript.parameters['alias_intf_mapping']
        configured_stream = testscript.parameters['configured_stream']
        trigger_obj = testscript.parameters['trigger_obj']

        log.info(banner('The value of configured stream is : {0}'.format(configured_stream))) 
        
        login = [node_dict['all_dut'][dut].execute('show version') for dut in node_dict['all_dut'] if re.search('uut', dut)]
        
        for TG in tgn_config_dict.keys():
            tgn_hdl = testscript.parameters['testbed_obj'].devices[TG]
            out = trigger_obj.checkAllStreamStats(tgn_hdl)
        
            if out:
                vpc_secnodary_hdl = trigger_obj.getVPCSwitchhdl('secondary')
                
                dialog = Dialog([
                         Statement(pattern=r'.*Do you want to continue (yes/no)? [no].*',
                         action='sendline(yes)')
                              ])
                result = vpc_secnodary_hdl.configure(cmd="system mode maintenance", dialog=dialog, timeout=300)
                log.info(banner('Sleeping for 320 seconds for the GIR.. Countdown Starts {0}'.format(countDownTimer(320))))
                result = vpc_secnodary_hdl.configure(cmd="no system mode maintenance", dialog=dialog, timeout=300)

                log.info(banner('Sleeping for 300 seconds for the traffic to converge after GIR.. Countdown Starts {0}'.format(countDownTimer(300))))
                out1 = trigger_obj.checkAllStreamStats(tgn_hdl)
                if out1:
                    log.info(banner('Traffic has recovered post GIR Trigger.. '))
                else:
                    log.info(banner('Traffic has not recovered post GIR Trigger..... Getting the individual stats.'))
                    self.failed()
            else:
                log.error('The Initial Traffic Condition did not pass :')
                self.failed()
                
                
class VXLANVxlanV6FUNC059(aetest.Testcase):

    """ Vxlan Trigger - VPC Role Change"""

    uid = 'VXLAN-L3-VxlanV6-FUNC-059'
    
    @aetest.test
    def vxlanVPCRoleChange(self,log,testscript,testbed):
        
        node_dict = testscript.parameters['node_dict']
        tg_interface_hdl_dict = testscript.parameters['tg_interface_hdl_dict'] 
        traffic_stream_dict = testscript.parameters['traffic_stream_dict'] 
        port_handle_dict = testscript.parameters['port_handle_dict']
        TGList_config_file = testscript.parameters['TGList']
        configdict = testscript.parameters['configdict'] 
        tgn_config_dict = configdict['TG']
        threshold = testscript.parameters['traffic_threshold'] 
        tgn_port_dut_mapping = testscript.parameters['tgn_port_dut_mapping']
        alias_intf_mapping_dict = testscript.parameters['alias_intf_mapping']
        configured_stream = testscript.parameters['configured_stream']
        trigger_obj = testscript.parameters['trigger_obj']

        log.info(banner('The value of configured stream is : {0}'.format(configured_stream))) 
        login = [node_dict['all_dut'][dut].execute('show version') for dut in node_dict['all_dut'] if re.search('uut', dut)]
        
        for TG in tgn_config_dict.keys():
            tgn_hdl = testscript.parameters['testbed_obj'].devices[TG]
            out = trigger_obj.checkAllStreamStats(tgn_hdl)
        
            if out:
                vpc_primary_hdl = trigger_obj.getVPCSwitchhdl('primary')
                out = vpc_primary_hdl.execute('show vpc role | xml')
                s = BeautifulSoup(out)
                role = s.find('vpc-current-role').string
                if '-' in role:
                    vpc_primary_hdl.configure('vpc role preempt')
                else:
                    cfg1 = '''vpc domain 1
                             shutdown'''
                    vpc_primary_hdl.configure(cfg1)
                    countDownTimer(30)
                    cfg2 = '''vpc domain 1
                             no shutdown'''
                    vpc_primary_hdl.configure(cfg2)

                log.info(banner('Sleeping for 300 seconds for the traffic to converge after GIR.. Countdown Starts {0}'.format(countDownTimer(300))))
                out1 = trigger_obj.checkAllStreamStats(tgn_hdl)
                if out1:
                    log.info(banner('Traffic has recovered post VPC Roke Change Trigger.. '))
                else:
                    log.info(banner('Traffic has not recovered post  VPC Roke Change Trigger..... Getting the individual stats.'))
                    self.failed()
            else:
                log.error('The Initial Traffic Condition did not pass :')
                self.failed()
                
class VXLANVxlanV6FUNC060(aetest.Testcase):

    """ Vxlan Trigger- Uplink PO member Flap"""

    uid = 'VXLAN-L3-VxlanV6-FUNC-060'
    
    @aetest.test
    def VxlanUplinkPOMemberFlap(self,log,testscript,testbed):
        
        node_dict = testscript.parameters['node_dict']
        tg_interface_hdl_dict = testscript.parameters['tg_interface_hdl_dict'] 
        traffic_stream_dict = testscript.parameters['traffic_stream_dict'] 
        port_handle_dict = testscript.parameters['port_handle_dict']
        TGList_config_file = testscript.parameters['TGList']
        configdict = testscript.parameters['configdict'] 
        tgn_config_dict = configdict['TG']
        threshold = testscript.parameters['traffic_threshold'] 
        tgn_port_dut_mapping = testscript.parameters['tgn_port_dut_mapping']
        alias_intf_mapping_dict = testscript.parameters['alias_intf_mapping']
        configured_stream = testscript.parameters['configured_stream']
        trigger_obj = testscript.parameters['trigger_obj']

        log.info(banner('The value of configured stream is : {0}'.format(configured_stream))) 
        
        login = [node_dict['all_dut'][dut].execute('show version') for dut in node_dict['all_dut'] if re.search('uut', dut)]
        
        trf = configdict['trigger_dict']['TEST-060']['traffic_to_consider']
        traffic_item_list = expandTrafficItemList(trf)
        
        log.info(banner('The value of traffic_item_list is : {0}'.format(traffic_item_list)))
        
        devices = configdict['trigger_dict']['TEST-060']['trigger_dut']
        interfaces = configdict['trigger_dict']['TEST-060']['interfaces'].split()
        port_channel_dict = configdict['trigger_dict']['TEST-060']['portchannel']

        
        log.info(banner('the Value of interfaces is  {0} and type is : {1}'.format(interfaces,type(interfaces))))
        
        
        for TG in tgn_config_dict.keys():
            tgn_hdl = testscript.parameters['testbed_obj'].devices[TG]
            out = trigger_obj.checkAllStreamStats(tgn_hdl)
        
            if out:
                res = trigger_obj.backUpAndRestoreConfigs(devices,'backup')
                log.info(banner('Defaulting the interfaces : {0}'.format([alias_intf_mapping_dict[intf] for intf in interfaces])))
                default_res = trigger_obj.defaultSetOfInterfaces(interfaces)
                
                for dut in port_channel_dict:
                    log.info('the value of dut  inside scripts is : {0}'.format(dut))
                    hdl = node_dict['all_dut'][dut]
                    for intf in port_channel_dict[dut].keys():
                        log.info('the value of intf  inside scripts is : {0}'.format(intf))
                        args = port_channel_dict[dut][intf]
                        log.info('the value of args  inside scripts is : {0}'.format(args))
                        res = trigger_obj.configurePo(hdl,intf,args)
                        
                log.info('Waiting for the traffic to converge After changing the configs to Port-channel.. sleeping for 100 seconds ')
                countDownTimer(150)
                
                out = trigger_obj.checkAllStreamStats(tgn_hdl)
                
                if not out:
                    log.error(banner('Traffic has not recovered on some of the streams.. Collecting the individual STream stats:'))
                    res = trigger_obj.backUpAndRestoreConfigs(devices,'restore')
                    res1 = trigger_obj.backUpAndRestoreConfigs(devices,'cleanup')  
                    self.failed()
                else:
                    log.info(banner('Traffic has receoverd post changing the configs to Prot-channel Interface'))
#                     res = trigger_obj.backUpAndRestoreConfigs(devices,'restore')
#                     res1 = trigger_obj.backUpAndRestoreConfigs(devices,'cleanup')                
                
                log.info(banner('Flapping the member ports of the port-channel in all the duts:'))
                
            
#                 res = [trigger_obj.my_utils.parsePortChannelParams(log,args) for dut in port_channel_dict for intf,args in port_channel_dict[dut].items()].memberlist
                
                for dut in port_channel_dict:
                    hdl = node_dict['all_dut'][dut]
                    for intf in port_channel_dict[dut]:
                        args = port_channel_dict[dut][intf]
                        ns = MyLib.my_utils.parsePortChannelParams(log,args)
                        log.info('the Value of ns is : {0}'.format(ns))
                        res = [MyLib.my_utils.flapInterface(log,hdl,alias_intf_mapping_dict[member],dut) for member in ns.memberlist.split()]
                        
                log.info('Waiting for the traffic to converge After flapping the Member Ports of the Port-channel.. sleeping for 100 seconds ')
                countDownTimer(100)
                
                out = trigger_obj.checkAllStreamStats(tgn_hdl)
                
                if out:
                    log.info(banner('Traffic has receoverd post flapping the Member ports of Prot-channel '))
                    res = trigger_obj.backUpAndRestoreConfigs(devices,'restore')
                    res1 = trigger_obj.backUpAndRestoreConfigs(devices,'cleanup')  
                                    
                    log.info('Waiting for the traffic to converge After flapping the Member Ports of the Port-channel.. sleeping for 100 seconds ')
                    countDownTimer(100)
                    
                    out3 = trigger_obj.checkAllStreamStats(tgn_hdl)
                    
                    if out3:
                        log.info(banner('Traffic is okay after 1. port-channel change 2. Member port flap 3. reverting the configs to Phy. Intf...'))
                    else:
                        log.info(banner('Traffic was okay after 1. port-channel change 2.  member Port-lap but not after 3. Reverting cfg to phy. Intf.'))
                        self.failed()
                    
                else:
                    log.info(banner('Traffic hasnot recovered after flapping the member ports of the port-channel.. Getting the individual stats'))                    
                    res = trigger_obj.backUpAndRestoreConfigs(devices,'restore')
                    res1 = trigger_obj.backUpAndRestoreConfigs(devices,'cleanup')   
                    self.failed()
                
                log.info('Waiting for the traffic to converge After revering the changing to Physical interface after changing to port-channel.. sleeping for 100 seconds ')
                countDownTimer(100)
                

            else:
                log.error('The Initial Traffic Condition did not pass:')
                self.failed()



class VXLANVxlanV6FUNC061(aetest.Testcase):

    """ Vxlan Trigger- Uplink PO Member Port SHut .. Complete Loss"""

    uid = 'VXLAN-L3-VxlanV6-FUNC-061'
    
    @aetest.test
    def VxlanUplinkPOMemberPortShutCompleteLoss(self,log,testscript,testbed):

        node_dict = testscript.parameters['node_dict']
        tg_interface_hdl_dict = testscript.parameters['tg_interface_hdl_dict'] 
        traffic_stream_dict = testscript.parameters['traffic_stream_dict'] 
        port_handle_dict = testscript.parameters['port_handle_dict']
        TGList_config_file = testscript.parameters['TGList']
        configdict = testscript.parameters['configdict'] 
        tgn_config_dict = configdict['TG']
        threshold = testscript.parameters['traffic_threshold'] 
        tgn_port_dut_mapping = testscript.parameters['tgn_port_dut_mapping']
        alias_intf_mapping_dict = testscript.parameters['alias_intf_mapping']
        configured_stream = testscript.parameters['configured_stream']
        trigger_obj = testscript.parameters['trigger_obj']

        log.info(banner('The value of configured stream is : {0}'.format(configured_stream))) 
        
        login = [node_dict['all_dut'][dut].execute('show version') for dut in node_dict['all_dut'] if re.search('uut', dut)]        

        trf = configdict['trigger_dict']['TEST-060']['traffic_to_consider']
        traffic_item_list = expandTrafficItemList(trf)
        
        log.info(banner('The value of traffic_item_list is : {0}'.format(traffic_item_list)))
        
        devices = configdict['trigger_dict']['TEST-060']['trigger_dut']
        interfaces = configdict['trigger_dict']['TEST-060']['interfaces'].split()
        port_channel_dict = configdict['trigger_dict']['TEST-060']['portchannel']

        
        log.info(banner('the Value of interfaces is  {0} and type is : {1}'.format(interfaces,type(interfaces))))
        
        
        for TG in tgn_config_dict.keys():
            tgn_hdl = testscript.parameters['testbed_obj'].devices[TG]
            out = trigger_obj.checkAllStreamStats(tgn_hdl)
        
            if out:
                res = trigger_obj.backUpAndRestoreConfigs(devices,'backup')
                log.info(banner('Defaulting the interfaces : {0}'.format([alias_intf_mapping_dict[intf] for intf in interfaces])))
                default_res = trigger_obj.defaultSetOfInterfaces(interfaces)
                
                for dut in port_channel_dict:
                    log.info('the value of dut  inside scripts is : {0}'.format(dut))
                    hdl = node_dict['all_dut'][dut]
                    for intf in port_channel_dict[dut].keys():
                        log.info('the value of intf  inside scripts is : {0}'.format(intf))
                        args = port_channel_dict[dut][intf]
                        log.info('the value of args  inside scripts is : {0}'.format(args))
                        res = trigger_obj.configurePo(hdl,intf,args)
                        
                log.info('Waiting for the traffic to converge After changing the configs to Port-channel.. sleeping for 100 seconds ')
                countDownTimer(150)
                
                out = trigger_obj.checkAllStreamStats(tgn_hdl)
                
                if not out:
                    log.error(banner('Traffic has not recovered on some of the streams.. Collecting the individual STream stats:'))
                    res = trigger_obj.backUpAndRestoreConfigs(devices,'restore')
                    res1 = trigger_obj.backUpAndRestoreConfigs(devices,'cleanup')  
                    self.failed()
                else:
                    log.info(banner('Traffic has receoverd post changing the configs to Prot-channel Interface'))
#                     res = trigger_obj.backUpAndRestoreConfigs(devices,'restore')
#                     res1 = trigger_obj.backUpAndRestoreConfigs(devices,'cleanup')                
                
                log.info(banner('Flapping the member ports of the port-channel in all the duts:'))
                
            
#                 res = [trigger_obj.my_utils.parsePortChannelParams(log,args) for dut in port_channel_dict for intf,args in port_channel_dict[dut].items()].memberlist
                
                for dut in port_channel_dict:
                    hdl = node_dict['all_dut'][dut]
                    for intf in port_channel_dict[dut]:
                        args = port_channel_dict[dut][intf]
                        ns = MyLib.my_utils.parsePortChannelParams(log,args)
                        log.info('the Value of ns is : {0}'.format(ns))
                        res = [MyLib.my_utils.shutDownInterface(log,hdl,alias_intf_mapping_dict[member],dut) for member in ns.memberlist.split()]
                        
                log.info('Waiting for the traffic to converge After Shutting down the Member Ports of the Port-channel.. sleeping for 60 seconds ')
                countDownTimer(60)
                
                for dut in port_channel_dict:
                    hdl = node_dict['all_dut'][dut]
                    for intf in port_channel_dict[dut]:
                        args = port_channel_dict[dut][intf]
                        ns = MyLib.my_utils.parsePortChannelParams(log,args)
                        log.info('the Value of ns is : {0}'.format(ns))
                        res = [MyLib.my_utils.unshutDownInterface(log,hdl,alias_intf_mapping_dict[member],dut) for member in ns.memberlist.split()]
                        
                log.info('Waiting for the traffic to converge After UnShutting down the Member Ports of the Port-channel.. sleeping for 60 seconds ')
                countDownTimer(60)
                
                
                out = trigger_obj.checkAllStreamStats(tgn_hdl)
                
                if out:
                    log.info(banner('Traffic has receoverd post flapping the Member ports of Prot-channel (complete LosS) '))
                    res = trigger_obj.backUpAndRestoreConfigs(devices,'restore')
                    res1 = trigger_obj.backUpAndRestoreConfigs(devices,'cleanup')  
                                    
                    log.info('Waiting for the traffic to converge After flapping the Member Ports of the Port-channel.. sleeping for 100 seconds ')
                    countDownTimer(100)
                    
                    out3 = trigger_obj.checkAllStreamStats(tgn_hdl)
                    
                    if out3:
                        log.info(banner('Traffic is okay after 1. port-channel change 2. Member port flap 3. reverting the configs to Phy. Intf...'))
                    else:
                        log.info(banner('Traffic was okay after 1. port-channel change 2.  member Port-lap but not after 3. Reverting cfg to phy. Intf.'))
                        self.failed()
                    
                else:
                    log.info(banner('Traffic hasnot recovered after flapping the member ports of the port-channel.. Getting the individual stats'))                    
                    res = trigger_obj.backUpAndRestoreConfigs(devices,'restore')
                    res1 = trigger_obj.backUpAndRestoreConfigs(devices,'cleanup')   
                    self.failed()
                
                log.info('Waiting for the traffic to converge After revering the changing to Physical interface after changing to port-channel.. sleeping for 100 seconds ')
                countDownTimer(100)
                

            else:
                log.error('The Initial Traffic Condition did not pass:')
                self.failed()

class VXLANVxlanV6FUNC062(aetest.Testcase):

    """ Vxlan Trigger- Uplink PO Shut Complete Loss"""

    uid = 'VXLAN-L3-VxlanV6-FUNC-062'
    
    @aetest.test
    def VxlanUplinkPOPortShutCompleteLoss(self,log,testscript,testbed):

        node_dict = testscript.parameters['node_dict']
        tg_interface_hdl_dict = testscript.parameters['tg_interface_hdl_dict'] 
        traffic_stream_dict = testscript.parameters['traffic_stream_dict'] 
        port_handle_dict = testscript.parameters['port_handle_dict']
        TGList_config_file = testscript.parameters['TGList']
        configdict = testscript.parameters['configdict'] 
        tgn_config_dict = configdict['TG']
        threshold = testscript.parameters['traffic_threshold'] 
        tgn_port_dut_mapping = testscript.parameters['tgn_port_dut_mapping']
        alias_intf_mapping_dict = testscript.parameters['alias_intf_mapping']
        configured_stream = testscript.parameters['configured_stream']
        trigger_obj = testscript.parameters['trigger_obj']

        log.info(banner('The value of configured stream is : {0}'.format(configured_stream))) 
        login = [node_dict['all_dut'][dut].execute('show version') for dut in node_dict['all_dut'] if re.search('uut', dut)]
        
        trf = configdict['trigger_dict']['TEST-062']['traffic_to_consider']
        traffic_item_list = expandTrafficItemList(trf)
        
        log.info(banner('The value of traffic_item_list is : {0}'.format(traffic_item_list)))
        
        devices = configdict['trigger_dict']['TEST-062']['trigger_dut']
        interfaces = configdict['trigger_dict']['TEST-062']['interfaces'].split()
        port_channel_dict = configdict['trigger_dict']['TEST-062']['portchannel']

        
        log.info(banner('the Value of interfaces is  {0} and type is : {1}'.format(interfaces,type(interfaces))))
        
        
        for TG in tgn_config_dict.keys():
            tgn_hdl = testscript.parameters['testbed_obj'].devices[TG]
            out = trigger_obj.checkAllStreamStats(tgn_hdl)
        
            if out:
                res = trigger_obj.backUpAndRestoreConfigs(devices,'backup')
                log.info(banner('Defaulting the interfaces : {0}'.format([alias_intf_mapping_dict[intf] for intf in interfaces])))
                default_res = trigger_obj.defaultSetOfInterfaces(interfaces)
                
                for dut in port_channel_dict:
                    log.info('the value of dut  inside scripts is : {0}'.format(dut))
                    hdl = node_dict['all_dut'][dut]
                    for intf in port_channel_dict[dut].keys():
                        log.info('the value of intf  inside scripts is : {0}'.format(intf))
                        args = port_channel_dict[dut][intf]
                        log.info('the value of args  inside scripts is : {0}'.format(args))
                        res = trigger_obj.configurePo(hdl,intf,args)
                        
                log.info('Waiting for the traffic to converge After changing the configs to Port-channel.. sleeping for 100 seconds ')
                countDownTimer(150)
                
                out = trigger_obj.checkAllStreamStats(tgn_hdl)
                
                if not out:
                    log.error(banner('Traffic has not recovered on some of the streams.. Collecting the individual STream stats:'))
                    res = trigger_obj.backUpAndRestoreConfigs(devices,'restore')
                    res1 = trigger_obj.backUpAndRestoreConfigs(devices,'cleanup')  
                    self.failed()
                else:
                    log.info(banner('Traffic has receoverd post changing the configs to Prot-channel Interface'))
#                     res = trigger_obj.backUpAndRestoreConfigs(devices,'restore')
#                     res1 = trigger_obj.backUpAndRestoreConfigs(devices,'cleanup')                
                
                log.info(banner('Flapping the member ports of the port-channel in all the duts:'))
                
            
#                 res = [trigger_obj.my_utils.parsePortChannelParams(log,args) for dut in port_channel_dict for intf,args in port_channel_dict[dut].items()].memberlist
                
                for dut in port_channel_dict:
                    hdl = node_dict['all_dut'][dut]
                    for intf in port_channel_dict[dut]:
                        res = [MyLib.my_utils.shutDownInterface(log,hdl,intf,dut)]
                        
                
                for dut in port_channel_dict:
                    hdl = node_dict['all_dut'][dut]
                    for intf in port_channel_dict[dut]:
                        res = [MyLib.my_utils.unshutDownInterface(log,hdl,intf,dut)]
                        
                log.info('Waiting for the traffic to converge After UnShutting down the Member Ports of the Port-channel.. sleeping for 60 seconds ')
                countDownTimer(60)
                
                
                out = trigger_obj.checkAllStreamStats(tgn_hdl)
                
                if out:
                    log.info(banner('Traffic has receoverd post flapping the Member ports of Prot-channel (complete LosS) '))
                    res = trigger_obj.backUpAndRestoreConfigs(devices,'restore')
                    res1 = trigger_obj.backUpAndRestoreConfigs(devices,'cleanup')  
                                    
                    log.info('Waiting for the traffic to converge After flapping the Member Ports of the Port-channel.. sleeping for 100 seconds ')
                    countDownTimer(100)
                    
                    out3 = trigger_obj.checkAllStreamStats(tgn_hdl)
                    
                    if out3:
                        log.info(banner('Traffic is okay after 1. port-channel change 2. Member port flap 3. reverting the configs to Phy. Intf...'))
                    else:
                        log.info(banner('Traffic was okay after 1. port-channel change 2.  member Port-lap but not after 3. Reverting cfg to phy. Intf.'))
                        self.failed()
                    
                else:
                    log.info(banner('Traffic hasnot recovered after flapping the member ports of the port-channel.. Getting the individual stats'))                    
                    res = trigger_obj.backUpAndRestoreConfigs(devices,'restore')
                    res1 = trigger_obj.backUpAndRestoreConfigs(devices,'cleanup')   
                    self.failed()
                
                log.info('Waiting for the traffic to converge After revering the changing to Physical interface after changing to port-channel.. sleeping for 100 seconds ')
                countDownTimer(100)
                

            else:
                log.error('The Initial Traffic Condition did not pass:')
                self.failed()


class VXLANVxlanV6FUNC063(aetest.Testcase):

    """ Vxlan Trigger- Uplink ECMP to NON-ECMP"""

    uid = 'VXLAN-L3-VxlanV6-FUNC-063'
    
    @aetest.test
    def VxlanECMPToNonECMP(self,log,testscript,testbed):

        node_dict = testscript.parameters['node_dict']
        tg_interface_hdl_dict = testscript.parameters['tg_interface_hdl_dict'] 
        traffic_stream_dict = testscript.parameters['traffic_stream_dict'] 
        port_handle_dict = testscript.parameters['port_handle_dict']
        TGList_config_file = testscript.parameters['TGList']
        configdict = testscript.parameters['configdict'] 
        tgn_config_dict = configdict['TG']
        threshold = testscript.parameters['traffic_threshold'] 
        tgn_port_dut_mapping = testscript.parameters['tgn_port_dut_mapping']
        alias_intf_mapping_dict = testscript.parameters['alias_intf_mapping']
        configured_stream = testscript.parameters['configured_stream']
        trigger_obj = testscript.parameters['trigger_obj']

        login = [node_dict['all_dut'][dut].execute('show version') for dut in node_dict['all_dut'] if re.search('uut', dut)]
        
        log.info(banner('The value of configured stream is : {0}'.format(configured_stream))) 
        interfaces_to_shut = ['uut1_uut33_2','uut2_uut33_2','uut4_uut33_2']
        
        devices = list(node_dict['all_vteps'].keys())
        log.info('The value of devices is : {0}'.format(devices))
        
        for TG in tgn_config_dict.keys():
            tgn_hdl = testscript.parameters['testbed_obj'].devices[TG]
            out = trigger_obj.checkAllStreamStats(tgn_hdl)
        
            if out:
                res = trigger_obj.backUpAndRestoreConfigs(devices,'backup')
                for intf in interfaces_to_shut:
                    dut = intf.split('_')[0]
                    hdl = node_dict['all_dut'][dut]
                    out = MyLib.my_utils.shutDownInterface(log,hdl,alias_intf_mapping_dict[intf],dut)
                

                log.info('Waiting for the traffic to converge After Shutting down the interfaces to go from ECMP - NON-ECMP')
                countDownTimer(60)
                

                out = trigger_obj.checkAllStreamStats(tgn_hdl)
                
                if out:
                    log.info(banner('Traffic has receoverd post shutting down the interfaces and is operating it Non-ECMP Mode. '))
                    
                    log.info('reverting the configs to go into ECMP mode:')
                    
                    for intf in interfaces_to_shut:
                        dut = intf.split('_')[0]
                        hdl = node_dict['all_dut'][dut]
                        out = MyLib.my_utils.unshutDownInterface(log,hdl,alias_intf_mapping_dict[intf],dut)
                                    
                    log.info('Waiting for the traffic to converge After bringing up the ports and to operate in ECMP Mode. .. sleeping for 100 seconds ')
                    countDownTimer(100)
                    
                    out3 = trigger_obj.checkAllStreamStats(tgn_hdl)
                    
                    if out3:
                        log.info(banner('Traffic is okay on the following trigger.  1. Non ECMP 2. ECMP'))
                    else:
                        log.info(banner('Traffic was okay after 1. ECMP - NON-ECMP but not okay from ECMP - NON-ECMP '))
                        log.info('Refer to the traffic stats for details')
                        self.failed()
                    
                else:
                    log.info(banner('Traffic has not receoverd post shutting down the interfaces when operating it Non-ECMP Mode. '))                    
                    res = trigger_obj.backUpAndRestoreConfigs(devices,'restore')
                    res1 = trigger_obj.backUpAndRestoreConfigs(devices,'cleanup')   
                    self.failed()
                

            else:
                log.error('The Initial Traffic Condition did not pass:')
                self.failed()


class VXLANVxlanV6FUNC064(aetest.Testcase):

    """ Vxlan Trigger- NVE SHut Primary"""

    uid = 'VXLAN-L3-VxlanV6-FUNC-064'
    
    @aetest.test
    def VxlanNVEShutPrimary(self,log,testscript,testbed):

        node_dict = testscript.parameters['node_dict']
        tg_interface_hdl_dict = testscript.parameters['tg_interface_hdl_dict'] 
        traffic_stream_dict = testscript.parameters['traffic_stream_dict'] 
        port_handle_dict = testscript.parameters['port_handle_dict']
        TGList_config_file = testscript.parameters['TGList']
        configdict = testscript.parameters['configdict'] 
        tgn_config_dict = configdict['TG']
        threshold = testscript.parameters['traffic_threshold'] 
        tgn_port_dut_mapping = testscript.parameters['tgn_port_dut_mapping']
        alias_intf_mapping_dict = testscript.parameters['alias_intf_mapping']
        configured_stream = testscript.parameters['configured_stream']
        trigger_obj = testscript.parameters['trigger_obj']

        log.info(banner('The value of configured stream is : {0}'.format(configured_stream))) 
        
        login = [node_dict['all_dut'][dut].execute('show version') for dut in node_dict['all_dut'] if re.search('uut', dut)]

        devices = list(node_dict['all_vteps'].keys())
        
        for TG in tgn_config_dict.keys():
            tgn_hdl = testscript.parameters['testbed_obj'].devices[TG]
            out = trigger_obj.checkAllStreamStats(tgn_hdl)
        
            if out:
                res = trigger_obj.backUpAndRestoreConfigs(devices,'backup')

                vpc_dict = trigger_obj.getVPCSwitchhdl('details')
                vpc_primary_hdl = vpc_dict['primary']['hdl']
                vpc_primary_dut = vpc_dict['primary']['dut']
                log.info(banner('Shutting down the nve Interface on the VPC Primary :'))
                
                res = MyLib.my_utils.shutDownInterface(log,vpc_primary_hdl,'nve 1',vpc_primary_dut)
                
                log.info('Waiting for the traffic to converge After Shutting down the NVe Interface on VPC PRimary.')
                countDownTimer(60)
                
                res = MyLib.my_utils.unshutDownInterface(log,vpc_primary_hdl,'nve 1',vpc_primary_dut)
                
                log.info('Waiting for the traffic to converge After bringing up the NVE POrt on VPC PRimary.. .. sleeping for 100 seconds ')
                countDownTimer(100)
                    
                out3 = trigger_obj.checkAllStreamStats(tgn_hdl) 
                if out3:
                    log.info(banner('Traffic is okay on the following trigger.  Flapping the NVE interface on primary'))
                else:
                    log.info(banner('Traffic is not as expected after the trigger: Flapping the Nve interface on primary '))
                    log.info('Refer to the traffic stats for details')
                    self.failed()

            else:
                log.error('The Initial Traffic Condition did not pass:')
                self.failed()

class VXLANVxlanV6FUNC065(aetest.Testcase):

    """ Vxlan Trigger- NVE SHut Secondary"""

    uid = 'VXLAN-L3-VxlanV6-FUNC-065'
    
    @aetest.test
    def VxlanNVEShutSecondary(self,log,testscript,testbed):

        node_dict = testscript.parameters['node_dict']
        tg_interface_hdl_dict = testscript.parameters['tg_interface_hdl_dict'] 
        traffic_stream_dict = testscript.parameters['traffic_stream_dict'] 
        port_handle_dict = testscript.parameters['port_handle_dict']
        TGList_config_file = testscript.parameters['TGList']
        configdict = testscript.parameters['configdict'] 
        tgn_config_dict = configdict['TG']
        threshold = testscript.parameters['traffic_threshold'] 
        tgn_port_dut_mapping = testscript.parameters['tgn_port_dut_mapping']
        alias_intf_mapping_dict = testscript.parameters['alias_intf_mapping']
        configured_stream = testscript.parameters['configured_stream']
        trigger_obj = testscript.parameters['trigger_obj']

        log.info(banner('The value of configured stream is : {0}'.format(configured_stream))) 
        
        login = [node_dict['all_dut'][dut].execute('show version') for dut in node_dict['all_dut'] if re.search('uut', dut)]
        
        devices = list(node_dict['all_vteps'].keys())
        
        for TG in tgn_config_dict.keys():
            tgn_hdl = testscript.parameters['testbed_obj'].devices[TG]
            out = trigger_obj.checkAllStreamStats(tgn_hdl)
        
            if out:
                res = trigger_obj.backUpAndRestoreConfigs(devices,'backup')

                vpc_dict = trigger_obj.getVPCSwitchhdl('details')
                vpc_primary_hdl = vpc_dict['secondary']['hdl']
                vpc_primary_dut = vpc_dict['secondary']['dut']
                log.info(banner('Shutting down the nve Interface on the VPC Primary :'))
                
                res = MyLib.my_utils.shutDownInterface(log,vpc_primary_hdl,'nve 1',vpc_primary_dut)
                
                log.info('Waiting for the traffic to converge After Shutting down NVE Interface on VPC Secondary.')
                countDownTimer(60)
                
                res = MyLib.my_utils.unshutDownInterface(log,vpc_primary_hdl,'nve 1',vpc_primary_dut)
                
                log.info('Waiting for the traffic to converge After bringing up NVE Port on VPC Secondary. .. sleeping for 100 seconds ')
                countDownTimer(100)
                    
                out3 = trigger_obj.checkAllStreamStats(tgn_hdl) 
                if out3:
                    log.info(banner('Traffic is okay on the following trigger.  Flapping the NVE interface on primary'))
                else:
                    log.info(banner('Traffic is not as expected after the trigger: Flapping the Nve interface on primary '))
                    log.info('Refer to the traffic stats for details')
                    self.failed()

            else:
                log.error('The Initial Traffic Condition did not pass:')
                self.failed()


class VXLANVxlanV6FUNC066(aetest.Testcase):

    """ Vxlan Trigger- NVE SHut Standalone VTEP"""

    uid = 'VXLAN-L3-VxlanV6-FUNC-066'
    
    @aetest.test
    def VxlanNVEShutStandalone(self,log,testscript,testbed):

        node_dict = testscript.parameters['node_dict']
        tg_interface_hdl_dict = testscript.parameters['tg_interface_hdl_dict'] 
        traffic_stream_dict = testscript.parameters['traffic_stream_dict'] 
        port_handle_dict = testscript.parameters['port_handle_dict']
        TGList_config_file = testscript.parameters['TGList']
        configdict = testscript.parameters['configdict'] 
        tgn_config_dict = configdict['TG']
        threshold = testscript.parameters['traffic_threshold'] 
        tgn_port_dut_mapping = testscript.parameters['tgn_port_dut_mapping']
        alias_intf_mapping_dict = testscript.parameters['alias_intf_mapping']
        configured_stream = testscript.parameters['configured_stream']
        trigger_obj = testscript.parameters['trigger_obj']

        log.info(banner('The value of configured stream is : {0}'.format(configured_stream))) 

        login = [node_dict['all_dut'][dut].execute('show version') for dut in node_dict['all_dut'] if re.search('uut', dut)]
        
        devices = list(node_dict['all_vteps'].keys())
        
        for TG in tgn_config_dict.keys():
            tgn_hdl = testscript.parameters['testbed_obj'].devices[TG]
            out = trigger_obj.checkAllStreamStats(tgn_hdl)
        
            if out:
                res = trigger_obj.backUpAndRestoreConfigs(devices,'backup')

                for dut , hdl in node_dict['stand_vteps'].items(): pass
                
                log.info(banner('Shutting down the nve Interface on the STandalone VTEP: {0} :'.format(dut)))
                
                res = MyLib.my_utils.shutDownInterface(log,hdl,'nve 1',dut)
                
                log.info('Waiting for the traffic to converge After Shutting down the interfaces to go from ECMP - NON-ECMP')
                countDownTimer(60)
                
                res = MyLib.my_utils.unshutDownInterface(log,hdl,'nve 1',dut)
                
                log.info('Waiting for the traffic to converge After bringing up the ports and to operate in ECMP Mode. .. sleeping for 100 seconds ')
                countDownTimer(100)
                    
                out3 = trigger_obj.checkAllStreamStats(tgn_hdl) 
                if out3:
                    log.info(banner('Traffic is okay on the following trigger.  Flapping the NVE interface on primary'))
                else:
                    log.info(banner('Traffic is not as expected after the trigger: Flapping the Nve interface on primary '))
                    log.info('Refer to the traffic stats for details')
                    self.failed()

            else:
                log.error('The Initial Traffic Condition did not pass:')
                self.failed()


class VXLANVxlanV6FUNC067(aetest.Testcase):

    """ Vxlan Trigger- Z-Traffic"""

    uid = 'VXLAN-L3-VxlanV6-FUNC-067'
    
    @aetest.test
    def VxlanZTraffic(self,log,testscript,testbed):

        node_dict = testscript.parameters['node_dict']
        tg_interface_hdl_dict = testscript.parameters['tg_interface_hdl_dict'] 
        traffic_stream_dict = testscript.parameters['traffic_stream_dict'] 
        port_handle_dict = testscript.parameters['port_handle_dict']
        TGList_config_file = testscript.parameters['TGList']
        configdict = testscript.parameters['configdict'] 
        tgn_config_dict = configdict['TG']
        threshold = testscript.parameters['traffic_threshold'] 
        tgn_port_dut_mapping = testscript.parameters['tgn_port_dut_mapping']
        alias_intf_mapping_dict = testscript.parameters['alias_intf_mapping']
        configured_stream = testscript.parameters['configured_stream']
        trigger_obj = testscript.parameters['trigger_obj']

        login = [node_dict['all_dut'][dut].execute('show version') for dut in node_dict['all_dut'] if re.search('uut', dut)]
        
        log.info(banner('The value of configured stream is : {0}'.format(configured_stream))) 
        interfaces_to_shut = ['uut2_uut33_1','uut2_uut33_2','uut1_uut3_1','uut1_uut3_2']
        
        devices = list(node_dict['all_vteps'].keys())
        log.info('The value of devices is : {0}'.format(devices))
        
        for TG in tgn_config_dict.keys():
            tgn_hdl = testscript.parameters['testbed_obj'].devices[TG]
            out = trigger_obj.checkAllStreamStats(tgn_hdl)
        
            if out:
                res = trigger_obj.backUpAndRestoreConfigs(devices,'backup')
                for intf in interfaces_to_shut:
                    dut = intf.split('_')[0]
                    hdl = node_dict['all_dut'][dut]
                    out = MyLib.my_utils.shutDownInterface(log,hdl,alias_intf_mapping_dict[intf],dut)
                

                log.info('Waiting for the traffic to converge After Shutting down the interfaces to simulate the Z-TRaffic')
                countDownTimer(60)
                

                out = trigger_obj.checkAllStreamStats(tgn_hdl)
                
                if out:
                    log.info(banner('Traffic has receoverd after Forcing the Z-Traffic.. '))
                    
                    log.info('Unshutting the interfaces...:')
                    
                    for intf in interfaces_to_shut:
                        dut = intf.split('_')[0]
                        hdl = node_dict['all_dut'][dut]
                        out = MyLib.my_utils.unshutDownInterface(log,hdl,alias_intf_mapping_dict[intf],dut)
                                    
                    log.info('Waiting for the traffic to converge After bringing up the ports and to bring to normal mode.')
                    countDownTimer(100)
                    
                    out3 = trigger_obj.checkAllStreamStats(tgn_hdl)
                    
                    if out3:
                        log.info(banner('Traffic is okay on the following trigger.  1. Z Traffic 2. Normal Topology.'))
                    else:
                        log.info(banner('Traffic was okay after 1. Z Traffic but not okay on 2 . Normal Topology.'))
                        log.info('Refer to the traffic stats for details')
                        self.failed()
                    
                else:
                    log.info(banner('Traffic has not receoverd post shutting down the interfaces when operating it Non-ECMP Mode. '))                    
                    res = trigger_obj.backUpAndRestoreConfigs(devices,'restore')
                    res1 = trigger_obj.backUpAndRestoreConfigs(devices,'cleanup')   
                    self.failed()
                

            else:
                log.error('The Initial Traffic Condition did not pass:')
                self.failed()
                
                
class VXLANVxlanV6FUNC068(aetest.Testcase):

    """ Vxlan Trigger- Primary/Secondary NVE Loopback Flap on Primary"""

    uid = 'VXLAN-L3-VxlanV6-FUNC-068'
    
    @aetest.test
    def VxlanPrimarySecondaryNVELoopbackFlapPrimary(self,log,testscript,testbed):

        node_dict = testscript.parameters['node_dict']
        tg_interface_hdl_dict = testscript.parameters['tg_interface_hdl_dict'] 
        traffic_stream_dict = testscript.parameters['traffic_stream_dict'] 
        port_handle_dict = testscript.parameters['port_handle_dict']
        TGList_config_file = testscript.parameters['TGList']
        configdict = testscript.parameters['configdict'] 
        tgn_config_dict = configdict['TG']
        threshold = testscript.parameters['traffic_threshold'] 
        tgn_port_dut_mapping = testscript.parameters['tgn_port_dut_mapping']
        alias_intf_mapping_dict = testscript.parameters['alias_intf_mapping']
        configured_stream = testscript.parameters['configured_stream']
        trigger_obj = testscript.parameters['trigger_obj']

        log.info(banner('The value of configured stream is : {0}'.format(configured_stream))) 
        
        login = [node_dict['all_dut'][dut].execute('show version') for dut in node_dict['all_dut'] if re.search('uut', dut)]

        devices = list(node_dict['all_vteps'].keys())
        
        for TG in tgn_config_dict.keys():
            tgn_hdl = testscript.parameters['testbed_obj'].devices[TG]
            out = trigger_obj.checkAllStreamStats(tgn_hdl)
        
            if out:
                res = trigger_obj.backUpAndRestoreConfigs(devices,'backup')

                vpc_dict = trigger_obj.getVPCSwitchhdl('details')
                vpc_primary_hdl = vpc_dict['primary']['hdl']
                vpc_primary_dut = vpc_dict['primary']['dut']
                log.info(banner('Shutting down the Primary and Secondary Loopback Interface on the VPC Primary :'))
                
                args = configdict['scale_config_dict'][vpc_primary_dut]['interface']['nve']
                ns = parseNVEParams(log,args)
                
                log.info('The value of ns is : {0}'.format(ns))
                
                for intf in [ns.source_interface, ns.anycast]:
                    res = MyLib.my_utils.shutDownInterface(log,vpc_primary_hdl,intf,vpc_primary_dut)
                
                log.info('Waiting for the traffic to converge After UnShutting down the Primary and Secondary Loopback Interface')
                countDownTimer(60)
                
                for intf in [ns.source_interface, ns.anycast]:
                    res = MyLib.my_utils.unshutDownInterface(log,vpc_primary_hdl,intf,vpc_primary_dut)
                
                log.info('Waiting for the traffic to converge After bringing up Primary and Secondary Loopback Interface. .. sleeping for 100 seconds ')
                countDownTimer(100)
                    
                out3 = trigger_obj.checkAllStreamStats(tgn_hdl) 
                if out3:
                    log.info(banner('Traffic is okay on the following trigger.  Flapping the NVE interface on primary'))
                else:
                    log.info(banner('Traffic is not as expected after the trigger: Flapping the Nve interface on primary '))
                    log.info('Refer to the traffic stats for details')
                    self.failed()

            else:
                log.error('The Initial Traffic Condition did not pass:')
                self.failed()

class VXLANVxlanV6FUNC069(aetest.Testcase):

    """ Vxlan Trigger- Primary/Secondary NVE Loopback Flap on secondary"""

    uid = 'VXLAN-L3-VxlanV6-FUNC-069'
    
    @aetest.test
    def VxlanPrimarySecondaryNVELoopbackFlapSecondary(self,log,testscript,testbed):

        node_dict = testscript.parameters['node_dict']
        tg_interface_hdl_dict = testscript.parameters['tg_interface_hdl_dict'] 
        traffic_stream_dict = testscript.parameters['traffic_stream_dict'] 
        port_handle_dict = testscript.parameters['port_handle_dict']
        TGList_config_file = testscript.parameters['TGList']
        configdict = testscript.parameters['configdict'] 
        tgn_config_dict = configdict['TG']
        threshold = testscript.parameters['traffic_threshold'] 
        tgn_port_dut_mapping = testscript.parameters['tgn_port_dut_mapping']
        alias_intf_mapping_dict = testscript.parameters['alias_intf_mapping']
        configured_stream = testscript.parameters['configured_stream']
        trigger_obj = testscript.parameters['trigger_obj']

        log.info(banner('The value of configured stream is : {0}'.format(configured_stream))) 
        
        login = [node_dict['all_dut'][dut].execute('show version') for dut in node_dict['all_dut'] if re.search('uut', dut)]

        devices = list(node_dict['all_vteps'].keys())
        
        for TG in tgn_config_dict.keys():
            tgn_hdl = testscript.parameters['testbed_obj'].devices[TG]
            out = trigger_obj.checkAllStreamStats(tgn_hdl)
        
            if out:
                res = trigger_obj.backUpAndRestoreConfigs(devices,'backup')

                vpc_dict = trigger_obj.getVPCSwitchhdl('details')
                vpc_secondary_hdl = vpc_dict['secondary']['hdl']
                vpc_secondary_dut = vpc_dict['secondary']['dut']
                log.info(banner('Shutting down the Primary and Secondary Loopback Interface on the VPC Primary :'))
                
                args = configdict['scale_config_dict'][vpc_secondary_dut]['interface']['nve']
                ns = parseNVEParams(log,args)
                
                log.info('The value of ns is : {0}'.format(ns))
                
                for intf in [ns.source_interface, ns.anycast]:
                    res = MyLib.my_utils.shutDownInterface(log,vpc_secondary_hdl,intf,vpc_secondary_dut)
                
                log.info('Waiting for the traffic to converge After UnShutting down Primary and Secondary Loopback Interface...')
                countDownTimer(60)
                
                for intf in [ns.source_interface, ns.anycast]:
                    res = MyLib.my_utils.unshutDownInterface(log,vpc_secondary_hdl,intf,vpc_secondary_dut)
                
                log.info('Waiting for the traffic to converge After bringing up Primary and Secondary Loopback Interface. .. sleeping for 100 seconds ')
                countDownTimer(100)
                    
                out3 = trigger_obj.checkAllStreamStats(tgn_hdl) 
                if out3:
                    log.info(banner('Traffic is okay on the following trigger.  Flapping the NVE interface on primary'))
                else:
                    log.info(banner('Traffic is not as expected after the trigger: Flapping the Nve interface on primary '))
                    log.info('Refer to the traffic stats for details')
                    self.failed()

            else:
                log.error('The Initial Traffic Condition did not pass:')
                self.failed()

class VXLANVxlanV6FUNC070(aetest.Testcase):

    """ Vxlan Trigger- SourceInterfacePrimary removal and re-add on VPC Primary"""

    uid = 'VXLAN-L3-VxlanV6-FUNC-070'
    
    @aetest.test
    def vxlanSourceInterfacePrimaryRemovalAddVPCPrimary(self,log,testscript,testbed):

        node_dict = testscript.parameters['node_dict']
        tg_interface_hdl_dict = testscript.parameters['tg_interface_hdl_dict'] 
        traffic_stream_dict = testscript.parameters['traffic_stream_dict'] 
        port_handle_dict = testscript.parameters['port_handle_dict']
        TGList_config_file = testscript.parameters['TGList']
        configdict = testscript.parameters['configdict'] 
        tgn_config_dict = configdict['TG']
        threshold = testscript.parameters['traffic_threshold'] 
        tgn_port_dut_mapping = testscript.parameters['tgn_port_dut_mapping']
        alias_intf_mapping_dict = testscript.parameters['alias_intf_mapping']
        configured_stream = testscript.parameters['configured_stream']
        trigger_obj = testscript.parameters['trigger_obj']

        log.info(banner('The value of configured stream is : {0}'.format(configured_stream))) 
        
        login = [node_dict['all_dut'][dut].execute('show version') for dut in node_dict['all_dut'] if re.search('uut', dut)]
        
        devices = list(node_dict['all_vteps'].keys())
        
        for TG in tgn_config_dict.keys():
            tgn_hdl = testscript.parameters['testbed_obj'].devices[TG]
            out = trigger_obj.checkAllStreamStats(tgn_hdl)
        
            if out:
                res = trigger_obj.backUpAndRestoreConfigs(devices,'backup')

                vpc_dict = trigger_obj.getVPCSwitchhdl('details')
                vpc_primary_hdl = vpc_dict['primary']['hdl']
                vpc_primary_dut = vpc_dict['primary']['dut']
                log.info(banner('Removing the source interface Primary Loopback Interface on the VPC Primary :'))
                
                args = configdict['scale_config_dict'][vpc_primary_dut]['interface']['nve']
                ns = parseNVEParams(log,args)
                
                log.info('The value of ns is : {0}'.format(ns))
                
                cfg = 'show run interface  {0} > bootflash:script_use'.format(ns.source_interface)
                vpc_primary_hdl.execute('delete bootflash:script_use* no-prompt')
                vpc_primary_hdl.execute(cfg)
                vpc_primary_hdl.configure('no interface {0}'.format(ns.source_interface))
                
                log.info(banner('Waiting for 100 seconds before re-adding the Source interface on dut {0}'.format(vpc_primary_dut)))
                
                vpc_primary_hdl.configure('copy bootflash:script_use running-config')
                
                
                log.info('Waiting for the traffic to converge After re-adding the Source interface on VPC Primary ')
                countDownTimer(60)
                    
                out3 = trigger_obj.checkAllStreamStats(tgn_hdl) 
                if out3:
                    log.info(banner('Traffic is okay on the following trigger.  Removing and re-adding the Source Interface on primary'))
                else:
                    log.info(banner('Traffic is NOT okay on the following trigger.  Removing and re-adding the Source Interface on primary '))
                    log.info('Refer to the traffic stats for details')
                    self.failed()

            else:
                log.error('The Initial Traffic Condition did not pass:')
                self.failed()


class VXLANVxlanV6FUNC071(aetest.Testcase):

    """ Vxlan Trigger- primarySourceInterface removal and re-add on VPC Secondary"""

    uid = 'VXLAN-L3-VxlanV6-FUNC-071'
    
    @aetest.test
    def vxlanSourceInterfaceprimaryRemovalAddVPCsecondary(self,log,testscript,testbed):

        node_dict = testscript.parameters['node_dict']
        tg_interface_hdl_dict = testscript.parameters['tg_interface_hdl_dict'] 
        traffic_stream_dict = testscript.parameters['traffic_stream_dict'] 
        port_handle_dict = testscript.parameters['port_handle_dict']
        TGList_config_file = testscript.parameters['TGList']
        configdict = testscript.parameters['configdict'] 
        tgn_config_dict = configdict['TG']
        threshold = testscript.parameters['traffic_threshold'] 
        tgn_port_dut_mapping = testscript.parameters['tgn_port_dut_mapping']
        alias_intf_mapping_dict = testscript.parameters['alias_intf_mapping']
        configured_stream = testscript.parameters['configured_stream']
        trigger_obj = testscript.parameters['trigger_obj']

        log.info(banner('The value of configured stream is : {0}'.format(configured_stream))) 
        
        login = [node_dict['all_dut'][dut].execute('show version') for dut in node_dict['all_dut'] if re.search('uut', dut)]

        devices = list(node_dict['all_vteps'].keys())
        
        for TG in tgn_config_dict.keys():
            tgn_hdl = testscript.parameters['testbed_obj'].devices[TG]
            out = trigger_obj.checkAllStreamStats(tgn_hdl)
        
            if out:
                res = trigger_obj.backUpAndRestoreConfigs(devices,'backup')

                vpc_dict = trigger_obj.getVPCSwitchhdl('details')
                vpc_secondary_hdl = vpc_dict['secondary']['hdl']
                vpc_secondary_dut = vpc_dict['secondary']['dut']
                log.info(banner('Removing the source interface Primary Loopback Interface on the VPC secondary :'))
                
                args = configdict['scale_config_dict'][vpc_secondary_dut]['interface']['nve']
                ns = parseNVEParams(log,args)
                
                log.info('The value of ns is : {0}'.format(ns))
                
                cfg = 'show run interface  {0} > bootflash:script_use'.format(ns.source_interface)
                vpc_secondary_hdl.execute('delete bootflash:script_use* no-prompt')
                vpc_secondary_hdl.execute(cfg)
                vpc_secondary_hdl.configure('no interface {0}'.format(ns.source_interface))
                
                log.info(banner('Waiting for 100 seconds before re-adding the Source interface on dut {0}'.format(vpc_secondary_dut)))
                
                vpc_secondary_hdl.configure('copy bootflash:script_use running-config')
                
                
                log.info('Waiting for the traffic to converge After re-adding the Source interface on VPC secondary ')
                countDownTimer(60)
                    
                out3 = trigger_obj.checkAllStreamStats(tgn_hdl) 
                if out3:
                    log.info(banner('Traffic is okay on the following trigger.  Removing and re-adding the Source Interface on secondary'))
                else:
                    log.info(banner('Traffic is NOT okay on the following trigger.  Removing and re-adding the Source Interface on secondary '))
                    log.info('Refer to the traffic stats for details')
                    self.failed()

            else:
                log.error('The Initial Traffic Condition did not pass:')
                self.failed()


class VXLANVxlanV6FUNC072(aetest.Testcase):

    """ Vxlan Trigger- Primary/Secondary NVE Loopback delete on Primary"""

    uid = 'VXLAN-L3-VxlanV6-FUNC-072'
    
    @aetest.test
    def VxlanPrimarySecondaryNVELoopbackDeletePrimary(self,log,testscript,testbed):

        node_dict = testscript.parameters['node_dict']
        tg_interface_hdl_dict = testscript.parameters['tg_interface_hdl_dict'] 
        traffic_stream_dict = testscript.parameters['traffic_stream_dict'] 
        port_handle_dict = testscript.parameters['port_handle_dict']
        TGList_config_file = testscript.parameters['TGList']
        configdict = testscript.parameters['configdict'] 
        tgn_config_dict = configdict['TG']
        threshold = testscript.parameters['traffic_threshold'] 
        tgn_port_dut_mapping = testscript.parameters['tgn_port_dut_mapping']
        alias_intf_mapping_dict = testscript.parameters['alias_intf_mapping']
        configured_stream = testscript.parameters['configured_stream']
        trigger_obj = testscript.parameters['trigger_obj']

        log.info(banner('The value of configured stream is : {0}'.format(configured_stream))) 

        login = [node_dict['all_dut'][dut].execute('show version') for dut in node_dict['all_dut'] if re.search('uut', dut)]
        
        devices = list(node_dict['all_vteps'].keys())
        
        for TG in tgn_config_dict.keys():
            tgn_hdl = testscript.parameters['testbed_obj'].devices[TG]
            out = trigger_obj.checkAllStreamStats(tgn_hdl)
        
            if out:
                res = trigger_obj.backUpAndRestoreConfigs(devices,'backup')

                vpc_dict = trigger_obj.getVPCSwitchhdl('details')
                vpc_primary_hdl = vpc_dict['primary']['hdl']
                vpc_primary_dut = vpc_dict['primary']['dut']
                log.info(banner('Shutting down the Primary and Secondary Loopback Interface on the VPC Primary :'))
                
                args = configdict['scale_config_dict'][vpc_primary_dut]['interface']['nve']
                ns = parseNVEParams(log,args)
                
                log.info('The value of ns is : {0}'.format(ns))
                
                log.info(banner('Deleting the PRimary and SEcondary Loopback on the VPC PRimary...'))
                log.info(banner('Primary is {0} and secondary is : {1}...'.format(ns.source_interface,ns.anycast)))
                
                cfg = 'sh run int {0} , {1} > bootflash:script_use'.format(ns.source_interface,ns.anycast)
                
                vpc_primary_hdl.execute('delete bootflash:script_use* no-prompt')
                vpc_primary_hdl.execute(cfg)
                
                cfg1='no interface {0}, {1}'.format(ns.source_interface,ns.anycast)
                
                log.info('Waiting for 60 seconds before adding back the primary and Secondary Loopback interaces on the VPC Primary.')
                countDownTimer(60)
                

                
                log.info('Waiting for the traffic to converge After bringing up Primary and Secondary Loopback Interface. .. sleeping for 100 seconds ')
                countDownTimer(100)
                    
                out3 = trigger_obj.checkAllStreamStats(tgn_hdl) 
                if out3:
                    log.info(banner('Traffic is okay on the following trigger.  Flapping the NVE interface on primary'))
                else:
                    log.info(banner('Traffic is not as expected after the trigger: Flapping the Nve interface on primary '))
                    log.info('Refer to the traffic stats for details')
                    self.failed()

            else:
                log.error('The Initial Traffic Condition did not pass:')
                self.failed()

class VXLANVxlanV6FUNC073(aetest.Testcase):

    """ Vxlan Trigger- Primary/Secondary NVE Loopback Delete on secondary"""

    uid = 'VXLAN-L3-VxlanV6-FUNC-073'
    
    @aetest.test
    def VxlanPrimarySecondaryNVELoopbackDeleteSecondary(self,log,testscript,testbed):

        node_dict = testscript.parameters['node_dict']
        tg_interface_hdl_dict = testscript.parameters['tg_interface_hdl_dict'] 
        traffic_stream_dict = testscript.parameters['traffic_stream_dict'] 
        port_handle_dict = testscript.parameters['port_handle_dict']
        TGList_config_file = testscript.parameters['TGList']
        configdict = testscript.parameters['configdict'] 
        tgn_config_dict = configdict['TG']
        threshold = testscript.parameters['traffic_threshold'] 
        tgn_port_dut_mapping = testscript.parameters['tgn_port_dut_mapping']
        alias_intf_mapping_dict = testscript.parameters['alias_intf_mapping']
        configured_stream = testscript.parameters['configured_stream']
        trigger_obj = testscript.parameters['trigger_obj']

        log.info(banner('The value of configured stream is : {0}'.format(configured_stream))) 
        
        login = [node_dict['all_dut'][dut].execute('show version') for dut in node_dict['all_dut'] if re.search('uut', dut)]

        devices = list(node_dict['all_vteps'].keys())
        
        for TG in tgn_config_dict.keys():
            tgn_hdl = testscript.parameters['testbed_obj'].devices[TG]
            out = trigger_obj.checkAllStreamStats(tgn_hdl)
        
            if out:
                res = trigger_obj.backUpAndRestoreConfigs(devices,'backup')

                vpc_dict = trigger_obj.getVPCSwitchhdl('details')
                vpc_secondary_hdl = vpc_dict['secondary']['hdl']
                vpc_secondary_dut = vpc_dict['secondary']['dut']
                log.info(banner('Shutting down the Primary and Secondary Loopback Interface on the VPC secondary :'))
                
                args = configdict['scale_config_dict'][vpc_secondary_dut]['interface']['nve']
                ns = parseNVEParams(log,args)
                
                log.info('The value of ns is : {0}'.format(ns))
                
                log.info(banner('Deleting the PRimary and SEcondary Loopback on the VPC PRimary...'))
                log.info(banner('Primary is {0} and secondary is : {1}...'.format(ns.source_interface,ns.anycast)))
                
                cfg = 'sh run int {0} , {1} > bootflash:script_use'.format(ns.source_interface,ns.anycast)
                
                vpc_secondary_hdl.execute('delete bootflash:script_use* no-prompt')
                vpc_secondary_hdl.execute(cfg)
                
                cfg1='no interface {0}, {1}'.format(ns.source_interface,ns.anycast)
                
                log.info('Waiting for 60 seconds before adding back the primary and Secondary Loopback interaces on the VPC Primary.')
                countDownTimer(60)
                

                
                log.info('Waiting for the traffic to converge After bringing up Primary and Secondary Loopback Interface. .. sleeping for 100 seconds ')
                countDownTimer(100)
                    
                out3 = trigger_obj.checkAllStreamStats(tgn_hdl) 
                if out3:
                    log.info(banner('Traffic is okay on the following trigger.  Flapping the NVE interface on primary'))
                else:
                    log.info(banner('Traffic is not as expected after the trigger: Flapping the Nve interface on primary '))
                    log.info('Refer to the traffic stats for details')
                    self.failed()

            else:
                log.error('The Initial Traffic Condition did not pass:')
                self.failed()
                
                
class VXLANVxlanV6FUNC074(aetest.Testcase):

    """ Vxlan Trigger- Primary NVE Loopback delete on Primary"""

    uid = 'VXLAN-L3-VxlanV6-FUNC-074'
    
    @aetest.test
    def VxlanPrimaryNveLoopbackDeleteReaddOnVPCPrimary(self,log,testscript,testbed):

        node_dict = testscript.parameters['node_dict']
        tg_interface_hdl_dict = testscript.parameters['tg_interface_hdl_dict'] 
        traffic_stream_dict = testscript.parameters['traffic_stream_dict'] 
        port_handle_dict = testscript.parameters['port_handle_dict']
        TGList_config_file = testscript.parameters['TGList']
        configdict = testscript.parameters['configdict'] 
        tgn_config_dict = configdict['TG']
        threshold = testscript.parameters['traffic_threshold'] 
        tgn_port_dut_mapping = testscript.parameters['tgn_port_dut_mapping']
        alias_intf_mapping_dict = testscript.parameters['alias_intf_mapping']
        configured_stream = testscript.parameters['configured_stream']
        trigger_obj = testscript.parameters['trigger_obj']

        log.info(banner('The value of configured stream is : {0}'.format(configured_stream))) 

        devices = list(node_dict['all_vteps'].keys())
        
        for TG in tgn_config_dict.keys():
            tgn_hdl = testscript.parameters['testbed_obj'].devices[TG]
            out = trigger_obj.checkAllStreamStats(tgn_hdl)
        
            if out:
                res = trigger_obj.backUpAndRestoreConfigs(devices,'backup')

                vpc_dict = trigger_obj.getVPCSwitchhdl('details')
                vpc_primary_hdl = vpc_dict['primary']['hdl']
                vpc_primary_dut = vpc_dict['primary']['dut']
                log.info(banner('Deleting the Primary NVE Loopback Interface on the VPC Primary :'))
                
                args = configdict['scale_config_dict'][vpc_primary_dut]['interface']['nve']
                ns = parseNVEParams(log,args)
                
                log.info('The value of ns is : {0}'.format(ns))
                
                log.info(banner('Deleting the PRimary Nve Loopback on the VPC PRimary...'))
                log.info(banner('Primary NVE Loopback is  : {0}...'.format(ns.source_interface)))
                
                cfg = 'sh run int {0} > bootflash:script_use'.format(ns.source_interface)
                
                vpc_primary_hdl.execute('delete bootflash:script_use* no-prompt')
                vpc_primary_hdl.execute(cfg)
                
                cfg1='no interface {0}'.format(ns.source_interface)
                vpc_primary_hdl.configure(cfg1)
                
                log.info('Waiting for 60 seconds before adding back the primary and Secondary Loopback interaces on the VPC Primary.')
                countDownTimer(60)
                
                cfg2 = 'copy bootflash:script_use running-config echo-commands'
                vpc_primary_hdl.execute(cfg2)
                
                log.info('Waiting for the traffic to converge After bringing up Primary and Secondary Loopback Interface. .. sleeping for 100 seconds ')
                countDownTimer(100)
                    
                out3 = trigger_obj.checkAllStreamStats(tgn_hdl) 
                if out3:
                    log.info(banner('Traffic is okay on the following trigger.  Flapping the NVE interface on primary'))
                else:
                    log.info(banner('Traffic is not as expected after the trigger: Flapping the Nve interface on primary '))
                    log.info('Refer to the traffic stats for details')
                    self.failed()

            else:
                log.error('The Initial Traffic Condition did not pass:')
                self.failed()
                
class VXLANVxlanV6FUNC075(aetest.Testcase):

    """ Vxlan Trigger- Primary NVE Loopback delete on Secondary"""

    uid = 'VXLAN-L3-VxlanV6-FUNC-075'
    
    @aetest.test
    def VxlanPrimaryNveLoopbackDeleteReaddOnVPCPrimary(self,log,testscript,testbed):

        node_dict = testscript.parameters['node_dict']
        tg_interface_hdl_dict = testscript.parameters['tg_interface_hdl_dict'] 
        traffic_stream_dict = testscript.parameters['traffic_stream_dict'] 
        port_handle_dict = testscript.parameters['port_handle_dict']
        TGList_config_file = testscript.parameters['TGList']
        configdict = testscript.parameters['configdict'] 
        tgn_config_dict = configdict['TG']
        threshold = testscript.parameters['traffic_threshold'] 
        tgn_port_dut_mapping = testscript.parameters['tgn_port_dut_mapping']
        alias_intf_mapping_dict = testscript.parameters['alias_intf_mapping']
        configured_stream = testscript.parameters['configured_stream']
        trigger_obj = testscript.parameters['trigger_obj']

        log.info(banner('The value of configured stream is : {0}'.format(configured_stream))) 

        devices = list(node_dict['all_vteps'].keys())
        
        for TG in tgn_config_dict.keys():
            tgn_hdl = testscript.parameters['testbed_obj'].devices[TG]
            out = trigger_obj.checkAllStreamStats(tgn_hdl)
        
            if out:
                res = trigger_obj.backUpAndRestoreConfigs(devices,'backup')

                vpc_dict = trigger_obj.getVPCSwitchhdl('details')
                vpc_secondary_hdl = vpc_dict['secondary']['hdl']
                vpc_secondary_dut = vpc_dict['secondary']['dut']
                log.info(banner('Deleting the NVE Primary Loopback Interface on the VPC secondary :'))
                
                args = configdict['scale_config_dict'][vpc_secondary_dut]['interface']['nve']
                ns = parseNVEParams(log,args)
                
                log.info('The value of ns is : {0}'.format(ns))
                
                log.info(banner('Deleting the PRimary Nve Loopback on the VPC Secondary...'))
                log.info(banner('Primary NVE Loopback is  : {0}...'.format(ns.source_interface)))
                
                cfg = 'sh run int {0} > bootflash:script_use'.format(ns.source_interface)
                
                vpc_secondary_hdl.execute('delete bootflash:script_use* no-prompt')
                vpc_secondary_hdl.execute(cfg)
                
                cfg1='no interface {0}'.format(ns.source_interface)
                vpc_secondary_hdl.configure(cfg1)
                
                log.info('Waiting for 60 seconds before adding back the primary and Secondary Loopback interaces on the VPC Primary.')
                countDownTimer(60)
                
                cfg2 = 'copy bootflash:script_use running-config echo-commands'
                vpc_secondary_hdl.execute(cfg2)
                
                log.info('Waiting for the traffic to converge After bringing up Primary and Secondary Loopback Interface. .. sleeping for 100 seconds ')
                countDownTimer(100)
                    
                out3 = trigger_obj.checkAllStreamStats(tgn_hdl) 
                if out3:
                    log.info(banner('Traffic is okay on the following trigger.  Flapping the NVE interface on primary'))
                else:
                    log.info(banner('Traffic is not as expected after the trigger: Flapping the Nve interface on primary '))
                    log.info('Refer to the traffic stats for details')
                    self.failed()

            else:
                log.error('The Initial Traffic Condition did not pass:')
                self.failed()

class VXLANVxlanV6FUNC076(aetest.Testcase):

    """ Vxlan Trigger- SEcondary NVE Loopback delete on Primary"""

    uid = 'VXLAN-L3-VxlanV6-FUNC-076'
    
    @aetest.test
    def VxlanSecondaryNveLoopbackDeleteReaddOnVPCPrimary(self,log,testscript,testbed):

        node_dict = testscript.parameters['node_dict']
        tg_interface_hdl_dict = testscript.parameters['tg_interface_hdl_dict'] 
        traffic_stream_dict = testscript.parameters['traffic_stream_dict'] 
        port_handle_dict = testscript.parameters['port_handle_dict']
        TGList_config_file = testscript.parameters['TGList']
        configdict = testscript.parameters['configdict'] 
        tgn_config_dict = configdict['TG']
        threshold = testscript.parameters['traffic_threshold'] 
        tgn_port_dut_mapping = testscript.parameters['tgn_port_dut_mapping']
        alias_intf_mapping_dict = testscript.parameters['alias_intf_mapping']
        configured_stream = testscript.parameters['configured_stream']
        trigger_obj = testscript.parameters['trigger_obj']

        log.info(banner('The value of configured stream is : {0}'.format(configured_stream))) 

        devices = list(node_dict['all_vteps'].keys())
        
        for TG in tgn_config_dict.keys():
            tgn_hdl = testscript.parameters['testbed_obj'].devices[TG]
            out = trigger_obj.checkAllStreamStats(tgn_hdl)
        
            if out:
                res = trigger_obj.backUpAndRestoreConfigs(devices,'backup')

                vpc_dict = trigger_obj.getVPCSwitchhdl('details')
                vpc_primary_hdl = vpc_dict['primary']['hdl']
                vpc_primary_dut = vpc_dict['primary']['dut']
                log.info(banner('Deleting the Primary NVE Loopback Interface on the VPC Primary :'))
                
                args = configdict['scale_config_dict'][vpc_primary_dut]['interface']['nve']
                ns = parseNVEParams(log,args)
                
                log.info('The value of ns is : {0}'.format(ns))
                
                log.info(banner('Deleting the Secondary Nve Loopback on the VPC PRimary...'))
                log.info(banner('SEcondary NVE Loopback is  : {0}...'.format(ns.anycast)))
                
                cfg = 'sh run int {0} > bootflash:script_use'.format(ns.anycast)
                
                vpc_primary_hdl.execute('delete bootflash:script_use* no-prompt')
                vpc_primary_hdl.execute(cfg)
                
                cfg1='no interface {0}'.format(ns.anycast)
                vpc_primary_hdl.configure(cfg1)
                
                log.info('Waiting for 60 seconds before adding back the primary and Secondary Loopback interaces on the VPC Primary.')
                countDownTimer(60)
                
                cfg2 = 'copy bootflash:script_use running-config echo-commands'
                vpc_primary_hdl.execute(cfg2)
                
                log.info('Waiting for the traffic to converge After bringing up Primary and Secondary Loopback Interface. .. sleeping for 100 seconds ')
                countDownTimer(100)
                    
                out3 = trigger_obj.checkAllStreamStats(tgn_hdl) 
                if out3:
                    log.info(banner('Traffic is okay on the following trigger.  Flapping the NVE interface on primary'))
                else:
                    log.info(banner('Traffic is not as expected after the trigger: Flapping the Nve interface on primary '))
                    log.info('Refer to the traffic stats for details ... Restoring the Configs....')
                    res = trigger_obj.backUpAndRestoreConfigs(devices,'restore')
                    countDownTimer(50)
                    self.failed()

            else:
                log.error('The Initial Traffic Condition did not pass:')
                self.failed()
                
class VXLANVxlanV6FUNC077(aetest.Testcase):

    """ Vxlan Trigger- Secondary NVE Loopback delete on Secondary"""

    uid = 'VXLAN-L3-VxlanV6-FUNC-077'
    
    @aetest.test
    def VxlanSecondaryNveLoopbackDeleteReaddOnVPCPrimary(self,log,testscript,testbed):

        node_dict = testscript.parameters['node_dict']
        tg_interface_hdl_dict = testscript.parameters['tg_interface_hdl_dict'] 
        traffic_stream_dict = testscript.parameters['traffic_stream_dict'] 
        port_handle_dict = testscript.parameters['port_handle_dict']
        TGList_config_file = testscript.parameters['TGList']
        configdict = testscript.parameters['configdict'] 
        tgn_config_dict = configdict['TG']
        threshold = testscript.parameters['traffic_threshold'] 
        tgn_port_dut_mapping = testscript.parameters['tgn_port_dut_mapping']
        alias_intf_mapping_dict = testscript.parameters['alias_intf_mapping']
        configured_stream = testscript.parameters['configured_stream']
        trigger_obj = testscript.parameters['trigger_obj']

        log.info(banner('The value of configured stream is : {0}'.format(configured_stream))) 

        devices = list(node_dict['all_vteps'].keys())
        
        for TG in tgn_config_dict.keys():
            tgn_hdl = testscript.parameters['testbed_obj'].devices[TG]
            out = trigger_obj.checkAllStreamStats(tgn_hdl)
        
            if out:
                res = trigger_obj.backUpAndRestoreConfigs(devices,'backup')

                vpc_dict = trigger_obj.getVPCSwitchhdl('details')
                vpc_secondary_hdl = vpc_dict['secondary']['hdl']
                vpc_secondary_dut = vpc_dict['secondary']['dut']
                log.info(banner('Deleting the NVE Secondary Loopback Interface on the VPC secondary :'))
                
                args = configdict['scale_config_dict'][vpc_secondary_dut]['interface']['nve']
                ns = parseNVEParams(log,args)
                
                log.info('The value of ns is : {0}'.format(ns))
                
                log.info(banner('Deleting the SEcondary Nve Loopback on the VPC Secondary...'))
                log.info(banner('Primary NVE Loopback is  : {0}...'.format(ns.anycast)))
                
                cfg = 'sh run int {0} > bootflash:script_use'.format(ns.anycast)
                
                vpc_secondary_hdl.execute('delete bootflash:script_use* no-prompt')
                vpc_secondary_hdl.execute(cfg)
                
                cfg1='no interface {0}'.format(ns.source_interface)
                vpc_secondary_hdl.configure(cfg1)
                
                log.info('Waiting for 60 seconds before adding back the primary and Secondary Loopback interaces on the VPC Primary.')
                countDownTimer(60)
                
                cfg2 = 'copy bootflash:script_use running-config echo-commands'
                vpc_secondary_hdl.execute(cfg2)
                
                log.info('Waiting for the traffic to converge After bringing up Primary and Secondary Loopback Interface. .. sleeping for 100 seconds ')
                countDownTimer(100)
                    
                out3 = trigger_obj.checkAllStreamStats(tgn_hdl) 
                if out3:
                    log.info(banner('Traffic is okay on the following trigger.  Flapping the NVE interface on primary'))
                else:
                    log.info(banner('Traffic is not as expected after the trigger: Flapping the Nve interface on primary '))
                    log.info('Refer to the traffic stats for details')
                    res = trigger_obj.backUpAndRestoreConfigs(devices,'restore')
                    countDownTimer(50)
                    self.failed()

            else:
                log.error('The Initial Traffic Condition did not pass:')
                self.failed()

class VXLANVxlanV6FUNC078(aetest.Testcase):

    """ Vxlan Trigger-  NVE Loopback Flap on Standalone"""

    uid = 'VXLAN-L3-VxlanV6-FUNC-078'
    
    @aetest.test
    def VxlanNveLoopbackFlapOnStandAlone(self,log,testscript,testbed):

        node_dict = testscript.parameters['node_dict']
        tg_interface_hdl_dict = testscript.parameters['tg_interface_hdl_dict'] 
        traffic_stream_dict = testscript.parameters['traffic_stream_dict'] 
        port_handle_dict = testscript.parameters['port_handle_dict']
        TGList_config_file = testscript.parameters['TGList']
        configdict = testscript.parameters['configdict'] 
        tgn_config_dict = configdict['TG']
        threshold = testscript.parameters['traffic_threshold'] 
        tgn_port_dut_mapping = testscript.parameters['tgn_port_dut_mapping']
        alias_intf_mapping_dict = testscript.parameters['alias_intf_mapping']
        configured_stream = testscript.parameters['configured_stream']
        trigger_obj = testscript.parameters['trigger_obj']

        log.info(banner('The value of configured stream is : {0}'.format(configured_stream))) 

        devices = list(node_dict['all_vteps'].keys())
        
        for TG in tgn_config_dict.keys():
            tgn_hdl = testscript.parameters['testbed_obj'].devices[TG]
            out = trigger_obj.checkAllStreamStats(tgn_hdl)
        
            if out:
                res = trigger_obj.backUpAndRestoreConfigs(devices,'backup')

                stand_vtep_dict = trigger_obj.getDeviceDict('stand_vtep')
                for dut, hdl in stand_vtep_dict.items(): pass
                
                log.info(banner('1. Dut is : {0} 2. hdl is : {1}'.format(dut,hdl)))
                
                log.info(banner('Shutting down the NVE Loopback on StandAlone VTEP :'))
                
                args = configdict['scale_config_dict'][dut]['interface']['nve']
                ns = parseNVEParams(log,args)
                
                log.info('The value of ns is : {0}'.format(ns))
                
                for intf in [ns.source_interface]:
                    res = MyLib.my_utils.flapInterface(log,hdl,intf,dut,t=30)
                
                log.info('Waiting for the traffic to converge After Shutting down Primary and Secondary Loopback Interface...')
                countDownTimer(150)
                    
                out3 = trigger_obj.checkAllStreamStats(tgn_hdl) 
                if out3:
                    log.info(banner('Traffic is okay on the following trigger.  Flapping the NVE interface on primary'))
                else:
                    log.info(banner('Traffic is not as expected after the trigger: Flapping the Nve interface on primary '))
                    log.info('Refer to the traffic stats for details')
                    res = trigger_obj.backUpAndRestoreConfigs(devices,'restore')
                    countDownTimer(50)
                    self.failed()

            else:
                log.error('The Initial Traffic Condition did not pass:')
                self.failed()



class VXLANVxlanV6FUNC079(aetest.Testcase):

    """ Vxlan Trigger-  NVE Loopback Delete/Readd on Standalone"""

    uid = 'VXLAN-L3-VxlanV6-FUNC-079'
    
    @aetest.test
    def VxlanNveLoopbackDeleteReAddOnStandAlone(self,log,testscript,testbed):

        node_dict = testscript.parameters['node_dict']
        tg_interface_hdl_dict = testscript.parameters['tg_interface_hdl_dict'] 
        traffic_stream_dict = testscript.parameters['traffic_stream_dict'] 
        port_handle_dict = testscript.parameters['port_handle_dict']
        TGList_config_file = testscript.parameters['TGList']
        configdict = testscript.parameters['configdict'] 
        tgn_config_dict = configdict['TG']
        threshold = testscript.parameters['traffic_threshold'] 
        tgn_port_dut_mapping = testscript.parameters['tgn_port_dut_mapping']
        alias_intf_mapping_dict = testscript.parameters['alias_intf_mapping']
        configured_stream = testscript.parameters['configured_stream']
        trigger_obj = testscript.parameters['trigger_obj']

        log.info(banner('The value of configured stream is : {0}'.format(configured_stream))) 

        devices = list(node_dict['all_vteps'].keys())
        
        for TG in tgn_config_dict.keys():
            tgn_hdl = testscript.parameters['testbed_obj'].devices[TG]
            out = trigger_obj.checkAllStreamStats(tgn_hdl)
        
            if out:
                res = trigger_obj.backUpAndRestoreConfigs(devices,'backup')

                stand_vtep_dict = trigger_obj.getDeviceDict('stand_vtep')
                for dut, hdl in stand_vtep_dict.items(): pass
                
                log.info(banner('1. Dut is : {0} 2. hdl is : {1}'.format(dut,hdl)))
                
                log.info(banner('Removnig down the NVE Loopback on StandAlone VTEP :'))
                
                args = configdict['scale_config_dict'][dut]['interface']['nve']
                ns = parseNVEParams(log,args)
                
                log.info('The value of ns is : {0}'.format(ns))
                
                cfg = 'sh run int {0} > bootflash:script_use'.format(ns.source_interface)
                
                hdl.execute('delete bootflash:script_use* no-prompt')
                hdl.execute(cfg)
                
                cfg1='no interface {0}'.format(ns.source_interface)
                hdl.configure(cfg1)
                
                log.info('Waiting for 60 seconds before adding back the NVe source Interaface Loopback interaces on the STandaloneVTEP.')
                countDownTimer(60)
                
                cfg2 = 'copy bootflash:script_use running-config echo-commands'
                hdl.execute(cfg2)
                
                log.info('Waiting for the traffic to converge After bringing up Primary and Secondary Loopback Interface. .. sleeping for 100 seconds ')
                countDownTimer(150)
                
                    
                out3 = trigger_obj.checkAllStreamStats(tgn_hdl) 
                if out3:
                    log.info(banner('Traffic is okay on the following trigger.  Flapping the NVE interface on primary'))
                else:
                    log.info(banner('Traffic is not as expected after the trigger: Flapping the Nve interface on primary '))
                    log.info('Refer to the traffic stats for details')
                    res = trigger_obj.backUpAndRestoreConfigs(devices,'restore')
                    countDownTimer(50)
                    self.failed()

            else:
                log.error('The Initial Traffic Condition did not pass:')
                self.failed()


class VXLANVxlanV6FUNC080(aetest.Testcase):

    """ Vxlan Trigger-  NVE Loopback PrimaryIP Change - VPC Primary"""

    uid = 'VXLAN-L3-VxlanV6-FUNC-080'
    
    @aetest.test
    def VxlanNveLoopbackPIPChangeVPCPrimary(self,log,testscript,testbed):

        node_dict = testscript.parameters['node_dict']
        tg_interface_hdl_dict = testscript.parameters['tg_interface_hdl_dict'] 
        traffic_stream_dict = testscript.parameters['traffic_stream_dict'] 
        port_handle_dict = testscript.parameters['port_handle_dict']
        TGList_config_file = testscript.parameters['TGList']
        configdict = testscript.parameters['configdict'] 
        tgn_config_dict = configdict['TG']
        threshold = testscript.parameters['traffic_threshold'] 
        tgn_port_dut_mapping = testscript.parameters['tgn_port_dut_mapping']
        alias_intf_mapping_dict = testscript.parameters['alias_intf_mapping']
        configured_stream = testscript.parameters['configured_stream']
        trigger_obj = testscript.parameters['trigger_obj']

        log.info(banner('The value of configured stream is : {0}'.format(configured_stream))) 

        devices = list(node_dict['all_vteps'].keys())
        
        for TG in tgn_config_dict.keys():
            tgn_hdl = testscript.parameters['testbed_obj'].devices[TG]
            out = trigger_obj.checkAllStreamStats(tgn_hdl)
        
            if out:
                res = trigger_obj.backUpAndRestoreConfigs(devices,'backup')

                vpc_dict = trigger_obj.getVPCSwitchhdl('details')
                vpc_primary_hdl = vpc_dict['primary']['hdl']
                vpc_primary_dut = vpc_dict['primary']['dut']
                log.info(banner('Changing the primary IP on the NVE Source Interface :'))
                
                args = configdict['scale_config_dict'][vpc_primary_dut]['interface']['nve']
                ns = parseNVEParams(log,args)
                
                log.info('The value of ns is : {0}'.format(ns))
                
                log.info(banner('Primary NVE Loopback is  : {0}...'.format(ns.source_interface)))
                
                cfg = 'sh run int {0} > bootflash:script_use'.format(ns.source_interface)
                
                vpc_primary_hdl.execute('delete bootflash:script_use* no-prompt')
                vpc_primary_hdl.execute(cfg)
                
                cfg1='no interface {0}'.format(ns.source_interface)
                vpc_primary_hdl.configure(cfg1)
                
                cfg2 = '''interface {0}
                          ipv6 address 1000:1000:1000:1000:1000:1000:1000:1000/128
                          ospfv3 dead-interval 4
                          ospfv3 hello-interval 1
                          ipv6 router ospfv3 vxlan area 0.0.0.0'''.format(ns.source_interface)
                    
                vpc_primary_hdl.configure(cfg2)
                
                log.info(banner('Waiting for 60 seconds for the traffic to converge.'))
                countDownTimer(60)
                
                out2 = trigger_obj.checkAllStreamStats(tgn_hdl) 
                
                if not out2:
                    log.info(banner('The Traffic has not restored after changing the primary Loopback addrsss in VPC Primary.'))
                    log.info('reverting back the configs...')
                    res = trigger_obj.backUpAndRestoreConfigs(devices,'restore')
                    res1 = trigger_obj.backUpAndRestoreConfigs(devices,'cleanup')
                    self.failed()
                    
                log.info(banner('Reverting back the configs:....'))
                vpc_primary_hdl.configure('no interface {0}'.format(ns.source_interface))
                
                cfg3 = 'copy bootflash:script_use running-config echo-commands'
                vpc_primary_hdl.execute(cfg3)
                
                log.info('Waiting for 60 seconds before adding back the NVe source Interaface Loopback interaces on the VPC Primary.')
                countDownTimer(60)
                
                    
                out3 = trigger_obj.checkAllStreamStats(tgn_hdl) 
                if out3:
                    log.info(banner('Traffic is okay on the following trigger.  Flapping the NVE interface on primary'))
                else:
                    log.info(banner('Traffic is not as expected after the trigger: Flapping the Nve interface on primary '))
                    log.info('Refer to the traffic stats for details')
                    res = trigger_obj.backUpAndRestoreConfigs(devices,'restore')
                    self.failed()

            else:
                log.error('The Initial Traffic Condition did not pass:')
                self.failed()

class VXLANVxlanV6FUNC081(aetest.Testcase):

    """ Vxlan Trigger-  NVE Loopback PrimaryIP Change - VPC Secondary"""

    uid = 'VXLAN-L3-VxlanV6-FUNC-081'
    
    @aetest.test
    def VxlanNveLoopbackPIPChangeVPCSecondary(self,log,testscript,testbed):

        node_dict = testscript.parameters['node_dict']
        tg_interface_hdl_dict = testscript.parameters['tg_interface_hdl_dict'] 
        traffic_stream_dict = testscript.parameters['traffic_stream_dict'] 
        port_handle_dict = testscript.parameters['port_handle_dict']
        TGList_config_file = testscript.parameters['TGList']
        configdict = testscript.parameters['configdict'] 
        tgn_config_dict = configdict['TG']
        threshold = testscript.parameters['traffic_threshold'] 
        tgn_port_dut_mapping = testscript.parameters['tgn_port_dut_mapping']
        alias_intf_mapping_dict = testscript.parameters['alias_intf_mapping']
        configured_stream = testscript.parameters['configured_stream']
        trigger_obj = testscript.parameters['trigger_obj']

        log.info(banner('The value of configured stream is : {0}'.format(configured_stream))) 

        devices = list(node_dict['all_vteps'].keys())
        
        for TG in tgn_config_dict.keys():
            tgn_hdl = testscript.parameters['testbed_obj'].devices[TG]
            out = trigger_obj.checkAllStreamStats(tgn_hdl)
        
            if out:
                res = trigger_obj.backUpAndRestoreConfigs(devices,'backup')

                vpc_dict = trigger_obj.getVPCSwitchhdl('details')
                vpc_secondary_hdl = vpc_dict['secondary']['hdl']
                vpc_secondary_dut = vpc_dict['secondary']['dut']
                log.info(banner('Changing the primary IP on the NVE Source Interface :'))
                
                args = configdict['scale_config_dict'][vpc_secondary_dut]['interface']['nve']
                ns = parseNVEParams(log,args)
                
                log.info('The value of ns is : {0}'.format(ns))
                
                log.info(banner('Primary NVE Loopback is  : {0}...'.format(ns.source_interface)))
                
                cfg = 'sh run int {0} > bootflash:script_use'.format(ns.source_interface)
                
                vpc_secondary_hdl.execute('delete bootflash:script_use* no-prompt')
                vpc_secondary_hdl.execute(cfg)
                
                cfg1='no interface {0}'.format(ns.source_interface)
                vpc_secondary_hdl.configure(cfg1)
                
                cfg2 = '''interface {0}
                          ipv6 address 2000:2000:2000:2000:2000:2000:2000:2000/128
                          ospfv3 dead-interval 4
                          ospfv3 hello-interval 1
                          ipv6 router ospfv3 vxlan area 0.0.0.0'''.format(ns.source_interface)
                    
                vpc_secondary_hdl.configure(cfg2)
                
                log.info(banner('Waiting for 60 seconds for the traffic to converge.'))
                countDownTimer(60)
                
                out2 = trigger_obj.checkAllStreamStats(tgn_hdl) 
                
                if not out2:
                    log.info(banner('The Traffic has not restored after changing the primary Loopback addrsss in VPC Primary.'))
                    log.info('reverting back the configs...')
                    res = trigger_obj.backUpAndRestoreConfigs(devices,'restore')
                    res1 = trigger_obj.backUpAndRestoreConfigs(devices,'cleanup')
                    self.failed()
                    
                log.info(banner('Reverting back the configs:....'))
                vpc_secondary_hdl.configure('no interface {0}'.format(ns.source_interface))
                
                cfg3 = 'copy bootflash:script_use running-config echo-commands'
                vpc_secondary_hdl.execute(cfg3)
                
                log.info('Waiting for 60 seconds before adding back the NVe source Interaface Loopback interaces on the VPC Primary.')
                countDownTimer(60)
                
                    
                out3 = trigger_obj.checkAllStreamStats(tgn_hdl) 
                if out3:
                    log.info(banner('Traffic is okay on the following trigger.  Flapping the NVE interface on primary'))
                else:
                    log.info(banner('Traffic is not as expected after the trigger: Flapping the Nve interface on primary '))
                    log.info('Refer to the traffic stats for details')
                    res = trigger_obj.backUpAndRestoreConfigs(devices,'restore')
                    self.failed()

            else:
                log.error('The Initial Traffic Condition did not pass:')
                self.failed()
    
#    [node_dict['all_dut'][dut].execute('show version') for dut in node_dict['all_dut']]

class VXLANVxlanV6FUNC082(aetest.Testcase):

    """ Vxlan Trigger-  NVE Loopback VIP Change - VPC Primary and Secondary"""

    uid = 'VXLAN-L3-VxlanV6-FUNC-082'
    
    @aetest.test
    def VxlanNveLoopbackVIPChangeVPCPrimaryAndSecondary(self,log,testscript,testbed):

        node_dict = testscript.parameters['node_dict']
        tg_interface_hdl_dict = testscript.parameters['tg_interface_hdl_dict'] 
        traffic_stream_dict = testscript.parameters['traffic_stream_dict'] 
        port_handle_dict = testscript.parameters['port_handle_dict']
        TGList_config_file = testscript.parameters['TGList']
        configdict = testscript.parameters['configdict'] 
        tgn_config_dict = configdict['TG']
        threshold = testscript.parameters['traffic_threshold'] 
        tgn_port_dut_mapping = testscript.parameters['tgn_port_dut_mapping']
        alias_intf_mapping_dict = testscript.parameters['alias_intf_mapping']
        configured_stream = testscript.parameters['configured_stream']
        trigger_obj = testscript.parameters['trigger_obj']

        log.info(banner('The value of configured stream is : {0}'.format(configured_stream))) 

        devices = list(node_dict['all_vteps'].keys())
        
        for TG in tgn_config_dict.keys():
            tgn_hdl = testscript.parameters['testbed_obj'].devices[TG]
            out = trigger_obj.checkAllStreamStats(tgn_hdl)
        
            if out:
                res = trigger_obj.backUpAndRestoreConfigs(devices,'backup')
                
                vpc_dict = trigger_obj.getDeviceDict('vpc_vtep')
                old_ipv6 = '1212:1212:1212:1212:1212:1212:1212:1212/128'

                for dut in vpc_dict:
                    hdl = node_dict['all_dut'][dut]
                    
                    log.info(banner('Changing the VIP on the both VPC Primary and SEcondary :'))
                    
                    args = configdict['scale_config_dict'][dut]['interface']['nve']
                    ns = parseNVEParams(log,args)
                    
                    log.info('The value of ns is : {0}'.format(ns))
                    
                    log.info(banner('VIP Loopback Interface is  : {0}...'.format(ns.anycast)))
                    
                    cfg2 = '''interface {0}
                             shutdown
                             no ipv6 address
                             ipv6 add 2121:2121:2121:2121:2121:2121:2121:2121/128
                             no shutdown'''.format(ns.anycast)
                    
                    hdl.configure(cfg2)
                    
                log.info(banner('Waiting for 100 seconds for the traffic to converge {0}'.format(countDownTimer(100))))
                
                out2 = trigger_obj.checkAllStreamStats(tgn_hdl)  

                if not out2:
                    log.info(banner('Traffic flow is not as expected after changing the VIP on both Primary and Secondary.'))  
                    log.info('Getting the invidual stats')
                    res = trigger_obj.backUpAndRestoreConfigs(devices,'restrore')
                    res = trigger_obj.backUpAndRestoreConfigs(devices,'cleanup')
                    self.failed()
                    
                for dut in vpc_dict:
                    hdl = node_dict['all_dut'][dut]
                    args = configdict['scale_config_dict'][dut]['interface']['nve']
                    ns = parseNVEParams(log,args)
                    cfg3 = '''{0}
                              shutdown
                              no ipv6 address
                              ipv6 address {1}
                              no shutdown'''.format(ns.anycast,old_ipv6)
                    hdl.configure(cfg3)
                
                
                log.info(banner('Waiting for 100 seconds for the traffic to converge {0}'.format(countDownTimer(100))))
                
                out3 = trigger_obj.checkAllStreamStats(tgn_hdl) 
                
                if not out3:
                    log.info(banner('Traffic flow is not as expected after reverting the VIP on both Primary and Secondary.'))  
                    log.info('Getting the invidual stats')
                    res = trigger_obj.backUpAndRestoreConfigs(devices,'restrore')
                    res = trigger_obj.backUpAndRestoreConfigs(devices,'cleanup')
                    self.failed()
                
                
                log.info(banner('Reverting back the configs to Original configs:'))
                res = trigger_obj.backUpAndRestoreConfigs(devices,'restrore')
                res = trigger_obj.backUpAndRestoreConfigs(devices,'cleanup')
                    
                log.info(banner('Waiting for 100 seconds for the traffic to converge {0}'.format(countDownTimer(100))))
                
                out4 = trigger_obj.checkAllStreamStats(tgn_hdl) 
                
                if not out4:
                    log.info(banner('Traffic flow is not as expected after reverting the VIP on both Primary and Secondary.'))  
                    log.info('Getting the invidual stats')
                    res = trigger_obj.backUpAndRestoreConfigs(devices,'restrore')
                    res = trigger_obj.backUpAndRestoreConfigs(devices,'cleanup') 
                    self.failed()                
            else:
                log.error('The Initial Traffic Condition did not pass:')
                self.failed()
                

class VXLANVxlanV6FUNC083(aetest.Testcase):

    """ Vxlan Trigger-  NVE Loopback PIP & VIP Change - VPC Primary and Secondary"""

    uid = 'VXLAN-L3-VxlanV6-FUNC-083'
    
    @aetest.test
    def VxlanNveLoopbackPIPAndVIPChangeVPCPrimaryAndSecondary(self,log,testscript,testbed):

        node_dict = testscript.parameters['node_dict']
        tg_interface_hdl_dict = testscript.parameters['tg_interface_hdl_dict'] 
        traffic_stream_dict = testscript.parameters['traffic_stream_dict'] 
        port_handle_dict = testscript.parameters['port_handle_dict']
        TGList_config_file = testscript.parameters['TGList']
        configdict = testscript.parameters['configdict'] 
        tgn_config_dict = configdict['TG']
        threshold = testscript.parameters['traffic_threshold'] 
        tgn_port_dut_mapping = testscript.parameters['tgn_port_dut_mapping']
        alias_intf_mapping_dict = testscript.parameters['alias_intf_mapping']
        configured_stream = testscript.parameters['configured_stream']
        trigger_obj = testscript.parameters['trigger_obj']

        log.info(banner('The value of configured stream is : {0}'.format(configured_stream))) 

        devices = list(node_dict['all_vteps'].keys())
        old_dut_ip_dict = {'uut1':'1111:1111:1111:1111:1111:1111:1111:1111/128','uut2':'2222:2222:2222:2222:2222:2222:2222:2222/128'}
        new_dut_ip_dict = {'uut1':'1000:1000:1000:1000:1000:1000:1000:1000/128','uut2':'2000:2000:2000:2000:2000:2000:2000:2000/128'}
        for TG in tgn_config_dict.keys():
            tgn_hdl = testscript.parameters['testbed_obj'].devices[TG]
            out = trigger_obj.checkAllStreamStats(tgn_hdl)
        
            if out:
                res = trigger_obj.backUpAndRestoreConfigs(devices,'backup')
                
                vpc_dict = trigger_obj.getDeviceDict('vpc_vtep')
                pip_vip_list = []

                for dut in vpc_dict:
                    hdl = node_dict['all_dut'][dut]
                    
                    log.info(banner('Changing the PIP&VIP on the both VPC Primary and SEcondary :'))
                    
                    args = configdict['scale_config_dict'][dut]['interface']['nve']
                    ns = parseNVEParams(log,args)
                    
                    log.info('The value of ns is : {0}'.format(ns))
                    
                    log.info(banner('PIP Loopback is : {0} and VIP Loopback  is  : {1}...'.format(ns.source_interface,ns.anycast)))
                    
                    cfg1 = '''interface {0}
                             shutdown
                             no ipv6 address
                             ipv6 address {1}
                             no shutdown'''.format(ns.source_interface,new_dut_ip_dict[dut])
                             
                    cfg2 = '''interface {0}
                             shutdown
                             no ipv6 address
                             ipv6 add 2121:2121:2121:2121:2121:2121:2121:2121/128
                             no shutdown'''.format(ns.anycast)
                             
                    hdl.configure(cfg1)
                    hdl.configure(cfg2)
                    
                log.info(banner('Waiting for 100 seconds for the traffic to converge {0}'.format(countDownTimer(100))))
                
                out2 = trigger_obj.checkAllStreamStats(tgn_hdl)  

                if not out2:
                    log.info(banner('Traffic flow is not as expected after changing the VIP on both Primary and Secondary.'))  
                    log.info('Getting the invidual stats')
                    res = trigger_obj.backUpAndRestoreConfigs(devices,'restrore')
                    res = trigger_obj.backUpAndRestoreConfigs(devices,'cleanup')
                    self.failed()
                    
                for dut in vpc_dict:
                    hdl = node_dict['all_dut'][dut]
                    args = configdict['scale_config_dict'][dut]['interface']['nve']
                    ns = parseNVEParams(log,args)
                    cfg3 = '''interface {0}
                              shutdown
                              no ipv6 address
                              ipv6 address {1}
                              no shutdown'''.format(ns.anycast,old_dut_ip_dict[dut])
                    cfg4 = '''interface {0}
                              shutdown
                              no ipv6 address
                              ipv6 address 1212:1212:1212:1212:1212:1212:1212:1212/128
                              no shutdown'''.format(ns.anycast,old_dut_ip_dict[dut])
                    hdl.configure(cfg3)
                    hdl.configure(cfg4)
                
                log.info(banner('Waiting for 100 seconds for the traffic to converge {0}'.format(countDownTimer(100))))
                
                out3 = trigger_obj.checkAllStreamStats(tgn_hdl) 
                
                if not out3:
                    log.info(banner('Traffic flow is not as expected after reverting the VIP on both Primary and Secondary.'))  
                    log.info('Getting the invidual stats')
                    res = trigger_obj.backUpAndRestoreConfigs(devices,'restrore')
                    res = trigger_obj.backUpAndRestoreConfigs(devices,'cleanup')
                    self.failed()
                    
            else:
                log.error('The Initial Traffic Condition did not pass:')
                self.failed()
                
class VXLANVxlanV6FUNC084(aetest.Testcase):

    """ Vxlan Trigger-  PIP Change on the StandAlone VTEP"""

    uid = 'VXLAN-L3-VxlanV6-FUNC-084'
    
    @aetest.test
    def VxlanNveLoopbackPIPChangeOnStandAloneVTEP(self,log,testscript,testbed):

        node_dict = testscript.parameters['node_dict']
        tg_interface_hdl_dict = testscript.parameters['tg_interface_hdl_dict'] 
        traffic_stream_dict = testscript.parameters['traffic_stream_dict'] 
        port_handle_dict = testscript.parameters['port_handle_dict']
        TGList_config_file = testscript.parameters['TGList']
        configdict = testscript.parameters['configdict'] 
        tgn_config_dict = configdict['TG']
        threshold = testscript.parameters['traffic_threshold'] 
        tgn_port_dut_mapping = testscript.parameters['tgn_port_dut_mapping']
        alias_intf_mapping_dict = testscript.parameters['alias_intf_mapping']
        configured_stream = testscript.parameters['configured_stream']
        trigger_obj = testscript.parameters['trigger_obj']

        log.info(banner('The value of configured stream is : {0}'.format(configured_stream))) 

        devices = list(node_dict['all_vteps'].keys())

        for TG in tgn_config_dict.keys():
            tgn_hdl = testscript.parameters['testbed_obj'].devices[TG]
            out = trigger_obj.checkAllStreamStats(tgn_hdl)
        
            if out:
                res = trigger_obj.backUpAndRestoreConfigs(devices,'backup')
                
                stand_dict = trigger_obj.getDeviceDict('stand_vtep')
                
                for dut , hdl in stand_dict.items(): pass

                hdl = node_dict['all_dut'][dut]
                
                log.info(banner('Changing the PIP on the StandAlone VTEP :'))
                
                args = configdict['scale_config_dict'][dut]['interface']['nve']
                ns = parseNVEParams(log,args)
                
                log.info('The value of ns is : {0}'.format(ns))
                
                log.info(banner('PIP Loopback is : {0} ...'.format(ns.source_interface)))
                
                cfg1 = '''interface {0}
                         shutdown
                         no ipv6 address
                         ipv6 address 4444:4444:4444:4444:4444:4444:4444:4444/128
                         no shutdown'''.format(ns.source_interface)
                         
                hdl.configure(cfg1)
                
                log.info(banner('Waiting for 100 seconds for the traffic to converge {0}'.format(countDownTimer(100))))
                
                out2 = trigger_obj.checkAllStreamStats(tgn_hdl)  
    
                if not out2:
                    log.info(banner('Traffic flow is not as expected after changing the VIP on both Primary and Secondary.'))  
                    log.info('Getting the invidual stats')
                    res = trigger_obj.backUpAndRestoreConfigs(devices,'restrore')
                    res = trigger_obj.backUpAndRestoreConfigs(devices,'cleanup')
                    self.failed()
                    

                cfg3 = '''interface {0}
                          shutdown
                          no ipv6 address
                          ipv6 address 3333:3333:3333:3333:3333:3333:3333:3333/128
                          no shutdown'''.format(ns.source_interface)

                hdl.configure(cfg3)
    
                
                log.info(banner('Waiting for 100 seconds for the traffic to converge {0}'.format(countDownTimer(100))))
                
                out3 = trigger_obj.checkAllStreamStats(tgn_hdl) 
                
                if not out3:
                    log.info(banner('Traffic flow is not as expected after reverting the VIP on both Primary and Secondary.'))  
                    log.info('Getting the invidual stats')
                    res = trigger_obj.backUpAndRestoreConfigs(devices,'restrore')
                    res = trigger_obj.backUpAndRestoreConfigs(devices,'cleanup')
                    self.failed()
                    
            else:
                log.error('The Initial Traffic Condition did not pass:')
                self.failed()
                
class VXLANVxlanV6FUNC085(aetest.Testcase):

    """ Vxlan Trigger-  Clear ipv6 route * """

    uid = 'VXLAN-L3-VxlanV6-FUNC-085'
    
    @aetest.test
    def VxlanClearIPv6Route(self,log,testscript,testbed):

        node_dict = testscript.parameters['node_dict']
        tg_interface_hdl_dict = testscript.parameters['tg_interface_hdl_dict'] 
        traffic_stream_dict = testscript.parameters['traffic_stream_dict'] 
        port_handle_dict = testscript.parameters['port_handle_dict']
        TGList_config_file = testscript.parameters['TGList']
        configdict = testscript.parameters['configdict'] 
        tgn_config_dict = configdict['TG']
        threshold = testscript.parameters['traffic_threshold'] 
        tgn_port_dut_mapping = testscript.parameters['tgn_port_dut_mapping']
        alias_intf_mapping_dict = testscript.parameters['alias_intf_mapping']
        configured_stream = testscript.parameters['configured_stream']
        trigger_obj = testscript.parameters['trigger_obj']

        log.info(banner('The value of configured stream is : {0}'.format(configured_stream))) 

        devices = list(node_dict['all_vteps'].keys())

        for TG in tgn_config_dict.keys():
            tgn_hdl = testscript.parameters['testbed_obj'].devices[TG]
            out = trigger_obj.checkAllStreamStats(tgn_hdl)
        
            if out:
                res = trigger_obj.backUpAndRestoreConfigs(devices,'backup')
                
                log.info(banner('Clearing the ipv6 routes on all the devices'))
                for dut in devices:
                    
                    log.info(banner('Clearing ipv6 route on dut {0}'.format(dut)))
                    hdl = node_dict['all_dut'][dut]
                    cfg = 'clear ipv6 route *'
                    hdl.configure(cfg)
                    log.info('sleeping for 10 seconds before issuing the command on the other VTEPs .. {0}'.format(countDownTimer(10)))
                    
                log.info(banner('Waiting for 100 seconds before collecting the Stats {0}'.format(countDownTimer(100))))
                
                out2 = trigger_obj.checkAllStreamStats(tgn_hdl)  
    
                if not out2:
                    log.info(banner('Traffic flow is not as expected after changing the VIP on both Primary and Secondary.'))  
                    log.info('Getting the invidual stats')
                    res = trigger_obj.backUpAndRestoreConfigs(devices,'restrore')
                    res = trigger_obj.backUpAndRestoreConfigs(devices,'cleanup')
                    self.failed()
                    
            else:
                log.error('The Initial Traffic Condition did not pass:')
                self.failed()
 
class VXLANVxlanV6FUNC086(aetest.Testcase):

    """ Vxlan Trigger-  Clear ipv6 neighbor vrf all force-delete """

    uid = 'VXLAN-L3-VxlanV6-FUNC-086'
    
    @aetest.test
    def VxlanClearIPv6NeighborVRFAllForceDelete(self,log,testscript,testbed):

        node_dict = testscript.parameters['node_dict']
        tg_interface_hdl_dict = testscript.parameters['tg_interface_hdl_dict'] 
        traffic_stream_dict = testscript.parameters['traffic_stream_dict'] 
        port_handle_dict = testscript.parameters['port_handle_dict']
        TGList_config_file = testscript.parameters['TGList']
        configdict = testscript.parameters['configdict'] 
        tgn_config_dict = configdict['TG']
        threshold = testscript.parameters['traffic_threshold'] 
        tgn_port_dut_mapping = testscript.parameters['tgn_port_dut_mapping']
        alias_intf_mapping_dict = testscript.parameters['alias_intf_mapping']
        configured_stream = testscript.parameters['configured_stream']
        trigger_obj = testscript.parameters['trigger_obj']

        log.info(banner('The value of configured stream is : {0}'.format(configured_stream))) 

        devices = list(node_dict['all_vteps'].keys())

        for TG in tgn_config_dict.keys():
            tgn_hdl = testscript.parameters['testbed_obj'].devices[TG]
            out = trigger_obj.checkAllStreamStats(tgn_hdl)
        
            if out:
                res = trigger_obj.backUpAndRestoreConfigs(devices,'backup')
                
                log.info(banner('Clearing the ipv6 routes on all the devices'))
                for dut in devices:
                    
                    log.info(banner('Clearing ipv6 route on dut {0}'.format(dut)))
                    hdl = node_dict['all_dut'][dut]
                    cfg = 'clear ipv6 neighbor vrf all force-delete'
                    hdl.configure(cfg)
                    log.info('sleeping for 10 seconds before issuing the command on the other VTEPs .. {0}'.format(countDownTimer(10)))
                    
                log.info(banner('Waiting for 100 seconds before collecting the Stats {0}'.format(countDownTimer(100))))
                
                out2 = trigger_obj.checkAllStreamStats(tgn_hdl)  
    
                if not out2:
                    log.info(banner('Traffic flow is not as expected after changing the VIP on both Primary and Secondary.'))  
                    log.info('Getting the invidual stats')
                    res = trigger_obj.backUpAndRestoreConfigs(devices,'restrore')
                    res = trigger_obj.backUpAndRestoreConfigs(devices,'cleanup')
                    self.failed()
                    
            else:
                log.error('The Initial Traffic Condition did not pass:')
                self.failed()
                

class VXLANVxlanV6FUNC087(aetest.Testcase):

    """ Vxlan Trigger-  Clear ipv6 neighbor vrf all force-delete """

    uid = 'VXLAN-L3-VxlanV6-FUNC-087'
    
    @aetest.test
    def VxlanClearIPv4IPv6OverlayRoutes(self,log,testscript,testbed):

        node_dict = testscript.parameters['node_dict']
        tg_interface_hdl_dict = testscript.parameters['tg_interface_hdl_dict'] 
        traffic_stream_dict = testscript.parameters['traffic_stream_dict'] 
        port_handle_dict = testscript.parameters['port_handle_dict']
        TGList_config_file = testscript.parameters['TGList']
        configdict = testscript.parameters['configdict'] 
        tgn_config_dict = configdict['TG']
        threshold = testscript.parameters['traffic_threshold'] 
        tgn_port_dut_mapping = testscript.parameters['tgn_port_dut_mapping']
        alias_intf_mapping_dict = testscript.parameters['alias_intf_mapping']
        configured_stream = testscript.parameters['configured_stream']
        trigger_obj = testscript.parameters['trigger_obj']

        log.info(banner('The value of configured stream is : {0}'.format(configured_stream))) 

        devices = list(node_dict['all_vteps'].keys())

        for TG in tgn_config_dict.keys():
            tgn_hdl = testscript.parameters['testbed_obj'].devices[TG]
            out = trigger_obj.checkAllStreamStats(tgn_hdl)
        
            if out:
                res = trigger_obj.backUpAndRestoreConfigs(devices,'backup')
                
                log.info(banner('Clearing the ipv6 routes on all the devices'))
                for dut in devices:
                    
                    log.info(banner('Clearing ipv6 route on dut {0}'.format(dut)))
                    hdl = node_dict['all_dut'][dut]
                    cfg1 = 'clear ip route vrf all *'
                    hdl.configure(cfg1)
                    cfg2 = 'clear ipv6 route vrf all *'
                    hdl.configure(cfg2)
                    log.info('sleeping for 10 seconds before issuing the command on the other VTEPs .. {0}'.format(countDownTimer(10)))
                    
                log.info(banner('Waiting for 100 seconds before collecting the Stats {0}'.format(countDownTimer(100))))
                
                out2 = trigger_obj.checkAllStreamStats(tgn_hdl)  
    
                if not out2:
                    log.info(banner('Traffic flow is not as expected after changing the VIP on both Primary and Secondary.'))  
                    log.info('Getting the invidual stats')
                    res = trigger_obj.backUpAndRestoreConfigs(devices,'restrore')
                    res = trigger_obj.backUpAndRestoreConfigs(devices,'cleanup')
                    self.failed()
                    
            else:
                log.error('The Initial Traffic Condition did not pass:')
                self.failed()
                 
 
class VXLANVxlanV6FUNC088(aetest.Testcase):

    """ Vxlan Trigger-  clear forwarding ipv4 route *  """

    uid = 'VXLAN-L3-VxlanV6-FUNC-088'
    
    @aetest.test
    def VxlanClearForwardingIP4RouteAll(self,log,testscript,testbed):

        node_dict = testscript.parameters['node_dict']
        tg_interface_hdl_dict = testscript.parameters['tg_interface_hdl_dict'] 
        traffic_stream_dict = testscript.parameters['traffic_stream_dict'] 
        port_handle_dict = testscript.parameters['port_handle_dict']
        TGList_config_file = testscript.parameters['TGList']
        configdict = testscript.parameters['configdict'] 
        tgn_config_dict = configdict['TG']
        threshold = testscript.parameters['traffic_threshold'] 
        tgn_port_dut_mapping = testscript.parameters['tgn_port_dut_mapping']
        alias_intf_mapping_dict = testscript.parameters['alias_intf_mapping']
        configured_stream = testscript.parameters['configured_stream']
        trigger_obj = testscript.parameters['trigger_obj']

        log.info(banner('The value of configured stream is : {0}'.format(configured_stream))) 

        devices = list(node_dict['all_vteps'].keys())

        for TG in tgn_config_dict.keys():
            tgn_hdl = testscript.parameters['testbed_obj'].devices[TG]
            out = trigger_obj.checkAllStreamStats(tgn_hdl)
        
            if out:
                res = trigger_obj.backUpAndRestoreConfigs(devices,'backup')
                
                log.info(banner('Executing Clear forwarding IPv4 route * module all on all the devices'))
                for dut in devices:
                    
                    log.info(banner('Clearing ipv6 route on dut {0}'.format(dut)))
                    hdl = node_dict['all_dut'][dut]
                    cfg1 = 'Clear forwarding IPv4 route * module all'
                    hdl.configure(cfg1)
                    log.info('sleeping for 10 seconds before issuing the command on the other VTEPs .. {0}'.format(countDownTimer(10)))
                    
                log.info(banner('Waiting for 100 seconds before collecting the Stats {0}'.format(countDownTimer(100))))
                
                out2 = trigger_obj.checkAllStreamStats(tgn_hdl)  
    
                if not out2:
                    log.info(banner('Traffic flow is not as expected after changing the VIP on both Primary and Secondary.'))  
                    log.info('Getting the invidual stats')
                    res = trigger_obj.backUpAndRestoreConfigs(devices,'restrore')
                    res = trigger_obj.backUpAndRestoreConfigs(devices,'cleanup')
                    self.failed()
                    
            else:
                log.error('The Initial Traffic Condition did not pass:')
                self.failed()
 
 
  
class VXLANVxlanV6FUNC089(aetest.Testcase):

    """ Vxlan Trigger-  clear forwarding ipv6 route *  """

    uid = 'VXLAN-L3-VxlanV6-FUNC-089'
    
    @aetest.test
    def VxlanClearForwardingIPv6RouteAll(self,log,testscript,testbed):

        node_dict = testscript.parameters['node_dict']
        tg_interface_hdl_dict = testscript.parameters['tg_interface_hdl_dict'] 
        traffic_stream_dict = testscript.parameters['traffic_stream_dict'] 
        port_handle_dict = testscript.parameters['port_handle_dict']
        TGList_config_file = testscript.parameters['TGList']
        configdict = testscript.parameters['configdict'] 
        tgn_config_dict = configdict['TG']
        threshold = testscript.parameters['traffic_threshold'] 
        tgn_port_dut_mapping = testscript.parameters['tgn_port_dut_mapping']
        alias_intf_mapping_dict = testscript.parameters['alias_intf_mapping']
        configured_stream = testscript.parameters['configured_stream']
        trigger_obj = testscript.parameters['trigger_obj']

        log.info(banner('The value of configured stream is : {0}'.format(configured_stream))) 

        devices = list(node_dict['all_vteps'].keys())

        for TG in tgn_config_dict.keys():
            tgn_hdl = testscript.parameters['testbed_obj'].devices[TG]
            out = trigger_obj.checkAllStreamStats(tgn_hdl)
        
            if out:
                res = trigger_obj.backUpAndRestoreConfigs(devices,'backup')
                
                log.info(banner('Executing Clear forwarding IPv6 route * module all on all the devices'))
                for dut in devices:
                    
                    log.info(banner('Executing "Clear forwarding ipv6 route * module all"  on dut {0}'.format(dut)))
                    hdl = node_dict['all_dut'][dut]
                    cfg1 = 'Clear forwarding IPv6 route * module all'
                    hdl.configure(cfg1)
                    log.info('sleeping for 10 seconds before issuing the command on the other VTEPs .. {0}'.format(countDownTimer(10)))
                    
                log.info(banner('Waiting for 100 seconds before collecting the Stats {0}'.format(countDownTimer(100))))
                
                out2 = trigger_obj.checkAllStreamStats(tgn_hdl)  
    
                if not out2:
                    log.info(banner('Traffic flow is not as expected after changing the VIP on both Primary and Secondary.'))  
                    log.info('Getting the invidual stats')
                    res = trigger_obj.backUpAndRestoreConfigs(devices,'restrore')
                    res = trigger_obj.backUpAndRestoreConfigs(devices,'cleanup')
                    self.failed()
                    
            else:
                log.error('The Initial Traffic Condition did not pass:')
                self.failed()                
 

class VXLANVxlanV6FUNC090(aetest.Testcase):

    """ Vxlan Trigger- clear bgp l2vpn evpn * """

    uid = 'VXLAN-L3-VxlanV6-FUNC-090'
    
    @aetest.test
    def VxlanClearBGPL2VPNEvpn(self,log,testscript,testbed):

        node_dict = testscript.parameters['node_dict']
        tg_interface_hdl_dict = testscript.parameters['tg_interface_hdl_dict'] 
        traffic_stream_dict = testscript.parameters['traffic_stream_dict'] 
        port_handle_dict = testscript.parameters['port_handle_dict']
        TGList_config_file = testscript.parameters['TGList']
        configdict = testscript.parameters['configdict'] 
        tgn_config_dict = configdict['TG']
        threshold = testscript.parameters['traffic_threshold'] 
        tgn_port_dut_mapping = testscript.parameters['tgn_port_dut_mapping']
        alias_intf_mapping_dict = testscript.parameters['alias_intf_mapping']
        configured_stream = testscript.parameters['configured_stream']
        trigger_obj = testscript.parameters['trigger_obj']

        log.info(banner('The value of configured stream is : {0}'.format(configured_stream))) 

        devices = list(node_dict['all_vteps'].keys())

        for TG in tgn_config_dict.keys():
            tgn_hdl = testscript.parameters['testbed_obj'].devices[TG]
            out = trigger_obj.checkAllStreamStats(tgn_hdl)
        
            if out:
                res = trigger_obj.backUpAndRestoreConfigs(devices,'backup')
                
                log.info(banner('Executing Cleari forwarding IPv4 route * module all on all the devices'))
                for dut in devices:
                    
                    log.info(banner('Executing the command "Clear bgp l2vpn evpn *" on dut {0}'.format(dut)))
                    hdl = node_dict['all_dut'][dut]
                    cfg1 = 'clear bgp l2vpn evpn *'
                    hdl.configure(cfg1)
                    log.info('sleeping for 10 seconds before issuing the command on the other VTEPs .. {0}'.format(countDownTimer(10)))
                    
                log.info(banner('Waiting for 100 seconds before collecting the Stats {0}'.format(countDownTimer(100))))
                
                out2 = trigger_obj.checkAllStreamStats(tgn_hdl)  
    
                if not out2:
                    log.info(banner('Traffic flow is not as expected after changing the VIP on both Primary and Secondary.'))  
                    log.info('Getting the invidual stats')
                    res = trigger_obj.backUpAndRestoreConfigs(devices,'restrore')
                    res = trigger_obj.backUpAndRestoreConfigs(devices,'cleanup')
                    self.failed()
                    
            else:
                log.error('The Initial Traffic Condition did not pass:')
                self.failed()     
 
class VXLANVxlanV6FUNC091(aetest.Testcase):

    """ Vxlan Trigger- clear bgp l2vpn evpn * """

    uid = 'VXLAN-L3-VxlanV6-FUNC-091'
    
    @aetest.test
    def VxlanClearMACAddressTableDynamic(self,log,testscript,testbed):

        node_dict = testscript.parameters['node_dict']
        tg_interface_hdl_dict = testscript.parameters['tg_interface_hdl_dict'] 
        traffic_stream_dict = testscript.parameters['traffic_stream_dict'] 
        port_handle_dict = testscript.parameters['port_handle_dict']
        TGList_config_file = testscript.parameters['TGList']
        configdict = testscript.parameters['configdict'] 
        tgn_config_dict = configdict['TG']
        threshold = testscript.parameters['traffic_threshold'] 
        tgn_port_dut_mapping = testscript.parameters['tgn_port_dut_mapping']
        alias_intf_mapping_dict = testscript.parameters['alias_intf_mapping']
        configured_stream = testscript.parameters['configured_stream']
        trigger_obj = testscript.parameters['trigger_obj']

        log.info(banner('The value of configured stream is : {0}'.format(configured_stream))) 

        devices = list(node_dict['all_vteps'].keys())

        for TG in tgn_config_dict.keys():
            tgn_hdl = testscript.parameters['testbed_obj'].devices[TG]
            out = trigger_obj.checkAllStreamStats(tgn_hdl)
        
            if out:
                res = trigger_obj.backUpAndRestoreConfigs(devices,'backup')
                
                log.info(banner('Executing Cleari forwarding IPv4 route * module all on all the devices'))
                for dut in devices:
                    
                    log.info(banner('Executing the command "clear mac address-table dynamic" on the dut {0}'.format(dut)))
                    hdl = node_dict['all_dut'][dut]
                    cfg1 = 'clear mac address-table dynamic'
                    hdl.configure(cfg1)
                    log.info('sleeping for 10 seconds before issuing the command on the other VTEPs .. {0}'.format(countDownTimer(10)))
                    
                log.info(banner('Waiting for 100 seconds before collecting the Stats {0}'.format(countDownTimer(100))))
                
                out2 = trigger_obj.checkAllStreamStats(tgn_hdl)  
    
                if not out2:
                    log.info(banner('Traffic flow is not as expected after changing the VIP on both Primary and Secondary.'))  
                    log.info('Getting the invidual stats')
                    res = trigger_obj.backUpAndRestoreConfigs(devices,'restrore')
                    res = trigger_obj.backUpAndRestoreConfigs(devices,'cleanup')
                    self.failed()
                    
            else:
                log.error('The Initial Traffic Condition did not pass:')
                self.failed()    
 
 
class VXLANVxlanV6FUNC092(aetest.Testcase):

    """ Vxlan Trigger- clear ip bgp *  """

    uid = 'VXLAN-L3-VxlanV6-FUNC-092'
    
    @aetest.test
    def VxlanClearIPBGPAll(self,log,testscript,testbed):

        node_dict = testscript.parameters['node_dict']
        tg_interface_hdl_dict = testscript.parameters['tg_interface_hdl_dict'] 
        traffic_stream_dict = testscript.parameters['traffic_stream_dict'] 
        port_handle_dict = testscript.parameters['port_handle_dict']
        TGList_config_file = testscript.parameters['TGList']
        configdict = testscript.parameters['configdict'] 
        tgn_config_dict = configdict['TG']
        threshold = testscript.parameters['traffic_threshold'] 
        tgn_port_dut_mapping = testscript.parameters['tgn_port_dut_mapping']
        alias_intf_mapping_dict = testscript.parameters['alias_intf_mapping']
        configured_stream = testscript.parameters['configured_stream']
        trigger_obj = testscript.parameters['trigger_obj']

        log.info(banner('The value of configured stream is : {0}'.format(configured_stream))) 

        devices = list(node_dict['all_vteps'].keys())

        for TG in tgn_config_dict.keys():
            tgn_hdl = testscript.parameters['testbed_obj'].devices[TG]
            out = trigger_obj.checkAllStreamStats(tgn_hdl)
        
            if out:
                res = trigger_obj.backUpAndRestoreConfigs(devices,'backup')
                
                log.info(banner('Executing Clear ip bgp  * module all on all the devices'))
                for dut in devices:
                    
                    log.info(banner('Executing the command "clear ip bgp * " on the dut {0}'.format(dut)))
                    hdl = node_dict['all_dut'][dut]
                    cfg1 = 'clear ip bgp * vrf all'
                    hdl.configure(cfg1)
                    log.info('sleeping for 10 seconds before issuing the command on the other VTEPs .. {0}'.format(countDownTimer(10)))
                    
                log.info(banner('Waiting for 100 seconds before collecting the Stats {0}'.format(countDownTimer(100))))
                
                out2 = trigger_obj.checkAllStreamStats(tgn_hdl)  
    
                if not out2:
                    log.info(banner('Traffic flow is not as expected after changing the VIP on both Primary and Secondary.'))  
                    log.info('Getting the invidual stats')
                    res = trigger_obj.backUpAndRestoreConfigs(devices,'restrore')
                    res = trigger_obj.backUpAndRestoreConfigs(devices,'cleanup')
                    self.failed()
                    
            else:
                log.error('The Initial Traffic Condition did not pass:')
                self.failed()    

class VXLANVxlanV6FUNC093(aetest.Testcase):

    """ Vxlan Trigger- clear ip ospf neighbor * vrf all """

    uid = 'VXLAN-L3-VxlanV6-FUNC-093'
    
    @aetest.test
    def VxlanClearIPOSPFNeighborAll(self,log,testscript,testbed):

        node_dict = testscript.parameters['node_dict']
        tg_interface_hdl_dict = testscript.parameters['tg_interface_hdl_dict'] 
        traffic_stream_dict = testscript.parameters['traffic_stream_dict'] 
        port_handle_dict = testscript.parameters['port_handle_dict']
        TGList_config_file = testscript.parameters['TGList']
        configdict = testscript.parameters['configdict'] 
        tgn_config_dict = configdict['TG']
        threshold = testscript.parameters['traffic_threshold'] 
        tgn_port_dut_mapping = testscript.parameters['tgn_port_dut_mapping']
        alias_intf_mapping_dict = testscript.parameters['alias_intf_mapping']
        configured_stream = testscript.parameters['configured_stream']
        trigger_obj = testscript.parameters['trigger_obj']

        log.info(banner('The value of configured stream is : {0}'.format(configured_stream))) 

        devices = list(node_dict['all_vteps'].keys())

        for TG in tgn_config_dict.keys():
            tgn_hdl = testscript.parameters['testbed_obj'].devices[TG]
            out = trigger_obj.checkAllStreamStats(tgn_hdl)
        
            if out:
                res = trigger_obj.backUpAndRestoreConfigs(devices,'backup')
                
                log.info(banner('Executing Clear ip ospf  * module all on all the devices'))
                for dut in devices:
                    
                    log.info(banner('Executing the command "clear ip bgp * " on the dut {0}'.format(dut)))
                    hdl = node_dict['all_dut'][dut]
                    cfg1 = 'clear ip ospf neighbor * vrf all'
                    hdl.configure(cfg1)
                    log.info('sleeping for 10 seconds before issuing the command on the other VTEPs .. {0}'.format(countDownTimer(10)))
                    
                log.info(banner('Waiting for 100 seconds before collecting the Stats {0}'.format(countDownTimer(100))))
                
                out2 = trigger_obj.checkAllStreamStats(tgn_hdl)  
    
                if not out2:
                    log.info(banner('Traffic flow is not as expected after changing the VIP on both Primary and Secondary.'))  
                    log.info('Getting the invidual stats')
                    res = trigger_obj.backUpAndRestoreConfigs(devices,'restrore')
                    res = trigger_obj.backUpAndRestoreConfigs(devices,'cleanup')
                    self.failed()
                    
            else:
                log.error('The Initial Traffic Condition did not pass:')
                self.failed()    
                                

class VXLANVxlanV6FUNC094(aetest.Testcase):

    """ Vxlan Trigger- clear ip ospf neighbor * vrf all """

    uid = 'VXLAN-L3-VxlanV6-FUNC-094'
    
    @aetest.test
    def VxlanClearIPv6OSPFNeighborAll(self,log,testscript,testbed):

        node_dict = testscript.parameters['node_dict']
        tg_interface_hdl_dict = testscript.parameters['tg_interface_hdl_dict'] 
        traffic_stream_dict = testscript.parameters['traffic_stream_dict'] 
        port_handle_dict = testscript.parameters['port_handle_dict']
        TGList_config_file = testscript.parameters['TGList']
        configdict = testscript.parameters['configdict'] 
        tgn_config_dict = configdict['TG']
        threshold = testscript.parameters['traffic_threshold'] 
        tgn_port_dut_mapping = testscript.parameters['tgn_port_dut_mapping']
        alias_intf_mapping_dict = testscript.parameters['alias_intf_mapping']
        configured_stream = testscript.parameters['configured_stream']
        trigger_obj = testscript.parameters['trigger_obj']

        log.info(banner('The value of configured stream is : {0}'.format(configured_stream))) 

        devices = list(node_dict['all_vteps'].keys())

        for TG in tgn_config_dict.keys():
            tgn_hdl = testscript.parameters['testbed_obj'].devices[TG]
            out = trigger_obj.checkAllStreamStats(tgn_hdl)
        
            if out:
                res = trigger_obj.backUpAndRestoreConfigs(devices,'backup')
                
                log.info(banner('Executing clear ospfv3 neighbor * vrf all module all on all the devices'))
                for dut in devices:
                    
                    log.info(banner('Executing the command "clear ospfv3 neighbor * vrf all" on the dut {0}'.format(dut)))
                    hdl = node_dict['all_dut'][dut]
                    cfg1 = 'clear ospfv3 neighbor * vrf all'
                    hdl.configure(cfg1)
                    log.info('sleeping for 10 seconds before issuing the command on the other VTEPs .. {0}'.format(countDownTimer(10)))
                    
                log.info(banner('Waiting for 100 seconds before collecting the Stats {0}'.format(countDownTimer(100))))
                
                out2 = trigger_obj.checkAllStreamStats(tgn_hdl)  
    
                if not out2:
                    log.info(banner('Traffic flow is not as expected after changing the VIP on both Primary and Secondary.'))  
                    log.info('Getting the invidual stats')
                    res = trigger_obj.backUpAndRestoreConfigs(devices,'restrore')
                    res = trigger_obj.backUpAndRestoreConfigs(devices,'cleanup')
                    self.failed()
                    
            else:
                log.error('The Initial Traffic Condition did not pass:')
                self.failed()    


class VXLANVxlanV6FUNC095(aetest.Testcase):

    """ Vxlan Trigger- clear ip arp vrf all force-delete """

    uid = 'VXLAN-L3-VxlanV6-FUNC-095'
    
    @aetest.test
    def VxlanClearIPARPVRFAllForceDelete(self,log,testscript,testbed):

        node_dict = testscript.parameters['node_dict']
        tg_interface_hdl_dict = testscript.parameters['tg_interface_hdl_dict'] 
        traffic_stream_dict = testscript.parameters['traffic_stream_dict'] 
        port_handle_dict = testscript.parameters['port_handle_dict']
        TGList_config_file = testscript.parameters['TGList']
        configdict = testscript.parameters['configdict'] 
        tgn_config_dict = configdict['TG']
        threshold = testscript.parameters['traffic_threshold'] 
        tgn_port_dut_mapping = testscript.parameters['tgn_port_dut_mapping']
        alias_intf_mapping_dict = testscript.parameters['alias_intf_mapping']
        configured_stream = testscript.parameters['configured_stream']
        trigger_obj = testscript.parameters['trigger_obj']

        log.info(banner('The value of configured stream is : {0}'.format(configured_stream))) 

        devices = list(node_dict['all_vteps'].keys())

        for TG in tgn_config_dict.keys():
            tgn_hdl = testscript.parameters['testbed_obj'].devices[TG]
            out = trigger_obj.checkAllStreamStats(tgn_hdl)
        
            if out:
                res = trigger_obj.backUpAndRestoreConfigs(devices,'backup')
                
                log.info(banner('Executing clear ip arp vrf all force-delete on all the devices'))
                for dut in devices:
                    
                    log.info(banner('Executing the command "clear ip arp vrf all force-delete" on the dut {0}'.format(dut)))
                    hdl = node_dict['all_dut'][dut]
                    cfg1 = 'clear ip arp vrf all force-delete'
                    hdl.configure(cfg1)
                    log.info('sleeping for 10 seconds before issuing the command on the other VTEPs .. {0}'.format(countDownTimer(10)))
                    
                log.info(banner('Waiting for 100 seconds before collecting the Stats {0}'.format(countDownTimer(100))))
                
                out2 = trigger_obj.checkAllStreamStats(tgn_hdl)  
    
                if not out2:
                    log.info(banner('Traffic flow is not as expected after changing the VIP on both Primary and Secondary.'))  
                    log.info('Getting the invidual stats')
                    res = trigger_obj.backUpAndRestoreConfigs(devices,'restrore')
                    res = trigger_obj.backUpAndRestoreConfigs(devices,'cleanup')
                    self.failed()
                    
            else:
                log.error('The Initial Traffic Condition did not pass:')
                self.failed()                                    
 
class VXLANVxlanV6FUNC096(aetest.Testcase):

    """ Vxlan Trigger- restart BGP """

    uid = 'VXLAN-L3-VxlanV6-FUNC-096'
    
    @aetest.test
    def VxlanRestartBGP(self,log,testscript,testbed):

        node_dict = testscript.parameters['node_dict']
        tg_interface_hdl_dict = testscript.parameters['tg_interface_hdl_dict'] 
        traffic_stream_dict = testscript.parameters['traffic_stream_dict'] 
        port_handle_dict = testscript.parameters['port_handle_dict']
        TGList_config_file = testscript.parameters['TGList']
        configdict = testscript.parameters['configdict'] 
        tgn_config_dict = configdict['TG']
        threshold = testscript.parameters['traffic_threshold'] 
        tgn_port_dut_mapping = testscript.parameters['tgn_port_dut_mapping']
        alias_intf_mapping_dict = testscript.parameters['alias_intf_mapping']
        configured_stream = testscript.parameters['configured_stream']
        trigger_obj = testscript.parameters['trigger_obj']

        log.info(banner('The value of configured stream is : {0}'.format(configured_stream))) 

        devices = list(node_dict['all_vteps'].keys())

        for TG in tgn_config_dict.keys():
            tgn_hdl = testscript.parameters['testbed_obj'].devices[TG]
            out = trigger_obj.checkAllStreamStats(tgn_hdl)
        
            if out:
                res = trigger_obj.backUpAndRestoreConfigs(devices,'backup')
                
                log.info(banner('restart BGP on all the devices'))
                for dut in devices:
                    
                    log.info(banner('Executing the command "restart BGP " on the dut {0}'.format(dut)))
                    hdl = node_dict['all_dut'][dut]
                    res = MyLib.my_utils.verifyProcessRestart(log,hdl,'bgp')
                    log.info('sleeping for 10 seconds before issuing the command on the other VTEPs .. {0}'.format(countDownTimer(10)))
                    
                log.info(banner('Waiting for 100 seconds before collecting the Stats {0}'.format(countDownTimer(100))))
                
                out2 = trigger_obj.checkAllStreamStats(tgn_hdl)  
    
                if not out2:
                    log.info(banner('Traffic flow is not as expected after changing the VIP on both Primary and Secondary.'))  
                    log.info('Getting the invidual stats')
                    res = trigger_obj.backUpAndRestoreConfigs(devices,'restrore')
                    res = trigger_obj.backUpAndRestoreConfigs(devices,'cleanup')
                    self.failed()
                    
            else:
                log.error('The Initial Traffic Condition did not pass:')
                self.failed()    


class VXLANVxlanV6FUNC097(aetest.Testcase):

    """ Vxlan Trigger- restart ospf """

    uid = 'VXLAN-L3-VxlanV6-FUNC-097'
    
    @aetest.test
    def VxlanRestartOSPF(self,log,testscript,testbed):

        node_dict = testscript.parameters['node_dict']
        tg_interface_hdl_dict = testscript.parameters['tg_interface_hdl_dict'] 
        traffic_stream_dict = testscript.parameters['traffic_stream_dict'] 
        port_handle_dict = testscript.parameters['port_handle_dict']
        TGList_config_file = testscript.parameters['TGList']
        configdict = testscript.parameters['configdict'] 
        tgn_config_dict = configdict['TG']
        threshold = testscript.parameters['traffic_threshold'] 
        tgn_port_dut_mapping = testscript.parameters['tgn_port_dut_mapping']
        alias_intf_mapping_dict = testscript.parameters['alias_intf_mapping']
        configured_stream = testscript.parameters['configured_stream']
        trigger_obj = testscript.parameters['trigger_obj']

        log.info(banner('The value of configured stream is : {0}'.format(configured_stream))) 

        devices = list(node_dict['all_vteps'].keys())

        for TG in tgn_config_dict.keys():
            tgn_hdl = testscript.parameters['testbed_obj'].devices[TG]
            out = trigger_obj.checkAllStreamStats(tgn_hdl)
        
            if out:
                res = trigger_obj.backUpAndRestoreConfigs(devices,'backup')
                
                log.info(banner('restart OSPF on all the devices'))
                for dut in devices:
                    
                    log.info(banner('Executing the command "restart OSPF " on the dut {0}'.format(dut)))
                    hdl = node_dict['all_dut'][dut]
                    res = MyLib.my_utils.verifyProcessRestart(log,hdl,'ospf')
                    log.info('sleeping for 10 seconds before issuing the command on the other VTEPs .. {0}'.format(countDownTimer(10)))
                    
                log.info(banner('Waiting for 100 seconds before collecting the Stats {0}'.format(countDownTimer(100))))
                
                out2 = trigger_obj.checkAllStreamStats(tgn_hdl)  
    
                if not out2:
                    log.info(banner('Traffic flow is not as expected after changing the VIP on both Primary and Secondary.'))  
                    log.info('Getting the invidual stats')
                    res = trigger_obj.backUpAndRestoreConfigs(devices,'restrore')
                    res = trigger_obj.backUpAndRestoreConfigs(devices,'cleanup')
                    self.failed()
                    
            else:
                log.error('The Initial Traffic Condition did not pass:')
                self.failed()     

class VXLANVxlanV6FUNC098(aetest.Testcase):

    """ Vxlan Trigger- restart ospfv3 """

    uid = 'VXLAN-L3-VxlanV6-FUNC-098'
    
    @aetest.test
    def VxlanRestartOSPF(self,log,testscript,testbed):

        node_dict = testscript.parameters['node_dict']
        tg_interface_hdl_dict = testscript.parameters['tg_interface_hdl_dict'] 
        traffic_stream_dict = testscript.parameters['traffic_stream_dict'] 
        port_handle_dict = testscript.parameters['port_handle_dict']
        TGList_config_file = testscript.parameters['TGList']
        configdict = testscript.parameters['configdict'] 
        tgn_config_dict = configdict['TG']
        threshold = testscript.parameters['traffic_threshold'] 
        tgn_port_dut_mapping = testscript.parameters['tgn_port_dut_mapping']
        alias_intf_mapping_dict = testscript.parameters['alias_intf_mapping']
        configured_stream = testscript.parameters['configured_stream']
        trigger_obj = testscript.parameters['trigger_obj']

        log.info(banner('The value of configured stream is : {0}'.format(configured_stream))) 

        devices = list(node_dict['all_vteps'].keys())

        for TG in tgn_config_dict.keys():
            tgn_hdl = testscript.parameters['testbed_obj'].devices[TG]
            out = trigger_obj.checkAllStreamStats(tgn_hdl)
        
            if out:
                res = trigger_obj.backUpAndRestoreConfigs(devices,'backup')
                
                log.info(banner('restart OSPFv3 on all the devices'))
                for dut in devices:
                    
                    log.info(banner('Executing the command "restart OSPFv3 " on the dut {0}'.format(dut)))
                    hdl = node_dict['all_dut'][dut]
                    res = MyLib.my_utils.verifyProcessRestart(log,hdl,'ospfv3')
                    log.info('sleeping for 10 seconds before issuing the command on the other VTEPs .. {0}'.format(countDownTimer(10)))
                    
                log.info(banner('Waiting for 100 seconds before collecting the Stats {0}'.format(countDownTimer(100))))
                
                out2 = trigger_obj.checkAllStreamStats(tgn_hdl)  
    
                if not out2:
                    log.info(banner('Traffic flow is not as expected after changing the VIP on both Primary and Secondary.'))  
                    log.info('Getting the invidual stats')
                    res = trigger_obj.backUpAndRestoreConfigs(devices,'restrore')
                    res = trigger_obj.backUpAndRestoreConfigs(devices,'cleanup')
                    self.failed()
                    
            else:
                log.error('The Initial Traffic Condition did not pass:')
                self.failed()     
                                

class VXLANVxlanV6FUNC098(aetest.Testcase):

    """ Vxlan Trigger- restart VPC """

    uid = 'VXLAN-L3-VxlanV6-FUNC-098'
    
    @aetest.test
    def VxlanRestartVPC(self,log,testscript,testbed):

        node_dict = testscript.parameters['node_dict']
        tg_interface_hdl_dict = testscript.parameters['tg_interface_hdl_dict'] 
        traffic_stream_dict = testscript.parameters['traffic_stream_dict'] 
        port_handle_dict = testscript.parameters['port_handle_dict']
        TGList_config_file = testscript.parameters['TGList']
        configdict = testscript.parameters['configdict'] 
        tgn_config_dict = configdict['TG']
        threshold = testscript.parameters['traffic_threshold'] 
        tgn_port_dut_mapping = testscript.parameters['tgn_port_dut_mapping']
        alias_intf_mapping_dict = testscript.parameters['alias_intf_mapping']
        configured_stream = testscript.parameters['configured_stream']
        trigger_obj = testscript.parameters['trigger_obj']

        log.info(banner('The value of configured stream is : {0}'.format(configured_stream))) 

        devices = list(node_dict['all_vteps'].keys())

        for TG in tgn_config_dict.keys():
            tgn_hdl = testscript.parameters['testbed_obj'].devices[TG]
            out = trigger_obj.checkAllStreamStats(tgn_hdl)
        
            if out:
                res = trigger_obj.backUpAndRestoreConfigs(devices,'backup')
                
                log.info(banner('restart VPC on all the devices'))
                for dut in devices:
                    
                    log.info(banner('Executing the command "restart VPC " on the dut {0}'.format(dut)))
                    hdl = node_dict['all_dut'][dut]
                    res = MyLib.my_utils.verifyProcessRestart(log,hdl,'vpc')
                    log.info('sleeping for 10 seconds before issuing the command on the other VTEPs .. {0}'.format(countDownTimer(10)))
                    
                log.info(banner('Waiting for 100 seconds before collecting the Stats {0}'.format(countDownTimer(100))))
                
                out2 = trigger_obj.checkAllStreamStats(tgn_hdl)  
    
                if not out2:
                    log.info(banner('Traffic flow is not as expected after changing the VIP on both Primary and Secondary.'))  
                    log.info('Getting the invidual stats')
                    res = trigger_obj.backUpAndRestoreConfigs(devices,'restrore')
                    res = trigger_obj.backUpAndRestoreConfigs(devices,'cleanup')
                    self.failed()
                    
            else:
                log.error('The Initial Traffic Condition did not pass:')
                self.failed()     
                
                                              
class VXLANVxlanV6FUNC099(aetest.Testcase):

    """ Vxlan Trigger- restart NVE """

    uid = 'VXLAN-L3-VxlanV6-FUNC-099'
    
    @aetest.test
    def VxlanRestartNVE(self,log,testscript,testbed):

        node_dict = testscript.parameters['node_dict']
        tg_interface_hdl_dict = testscript.parameters['tg_interface_hdl_dict'] 
        traffic_stream_dict = testscript.parameters['traffic_stream_dict'] 
        port_handle_dict = testscript.parameters['port_handle_dict']
        TGList_config_file = testscript.parameters['TGList']
        configdict = testscript.parameters['configdict'] 
        tgn_config_dict = configdict['TG']
        threshold = testscript.parameters['traffic_threshold'] 
        tgn_port_dut_mapping = testscript.parameters['tgn_port_dut_mapping']
        alias_intf_mapping_dict = testscript.parameters['alias_intf_mapping']
        configured_stream = testscript.parameters['configured_stream']
        trigger_obj = testscript.parameters['trigger_obj']

        log.info(banner('The value of configured stream is : {0}'.format(configured_stream))) 

        devices = list(node_dict['all_vteps'].keys())

        for TG in tgn_config_dict.keys():
            tgn_hdl = testscript.parameters['testbed_obj'].devices[TG]
            out = trigger_obj.checkAllStreamStats(tgn_hdl)
        
            if out:
                res = trigger_obj.backUpAndRestoreConfigs(devices,'backup')
                
                log.info(banner('restart NVE on all the devices'))
                for dut in devices:
                    
                    log.info(banner('Executing the command "restart NVE " on the dut {0}'.format(dut)))
                    hdl = node_dict['all_dut'][dut]
                    res = MyLib.my_utils.verifyProcessRestart(log,hdl,'nve')
                    log.info('sleeping for 10 seconds before issuing the command on the other VTEPs .. {0}'.format(countDownTimer(10)))
                    
                log.info(banner('Waiting for 100 seconds before collecting the Stats {0}'.format(countDownTimer(100))))
                
                out2 = trigger_obj.checkAllStreamStats(tgn_hdl)  
    
                if not out2:
                    log.info(banner('Traffic flow is not as expected after changing the VIP on both Primary and Secondary.'))  
                    log.info('Getting the invidual stats')
                    res = trigger_obj.backUpAndRestoreConfigs(devices,'restrore')
                    res = trigger_obj.backUpAndRestoreConfigs(devices,'cleanup')
                    self.failed()
                    
            else:
                log.error('The Initial Traffic Condition did not pass:')
                self.failed()      


class VXLANVxlanV6FUNC100(aetest.Testcase):

    """ Vxlan Trigger- restart HMM """

    uid = 'VXLAN-L3-VxlanV6-FUNC-100'
    
    @aetest.test
    def VxlanRestartHMM(self,log,testscript,testbed):

        node_dict = testscript.parameters['node_dict']
        tg_interface_hdl_dict = testscript.parameters['tg_interface_hdl_dict'] 
        traffic_stream_dict = testscript.parameters['traffic_stream_dict'] 
        port_handle_dict = testscript.parameters['port_handle_dict']
        TGList_config_file = testscript.parameters['TGList']
        configdict = testscript.parameters['configdict'] 
        tgn_config_dict = configdict['TG']
        threshold = testscript.parameters['traffic_threshold'] 
        tgn_port_dut_mapping = testscript.parameters['tgn_port_dut_mapping']
        alias_intf_mapping_dict = testscript.parameters['alias_intf_mapping']
        configured_stream = testscript.parameters['configured_stream']
        trigger_obj = testscript.parameters['trigger_obj']

        log.info(banner('The value of configured stream is : {0}'.format(configured_stream))) 

        devices = list(node_dict['all_vteps'].keys())

        for TG in tgn_config_dict.keys():
            tgn_hdl = testscript.parameters['testbed_obj'].devices[TG]
            out = trigger_obj.checkAllStreamStats(tgn_hdl)
        
            if out:
                res = trigger_obj.backUpAndRestoreConfigs(devices,'backup')
                
                log.info(banner('restart HMM on all the devices'))
                for dut in devices:
                    
                    log.info(banner('Executing the command "restart HMM " on the dut {0}'.format(dut)))
                    hdl = node_dict['all_dut'][dut]
                    res = MyLib.my_utils.verifyProcessRestart(log,hdl,'hmm')
                    log.info('sleeping for 10 seconds before issuing the command on the other VTEPs .. {0}'.format(countDownTimer(10)))
                    
                log.info(banner('Waiting for 100 seconds before collecting the Stats {0}'.format(countDownTimer(100))))
                
                out2 = trigger_obj.checkAllStreamStats(tgn_hdl)  
    
                if not out2:
                    log.info(banner('Traffic flow is not as expected after changing the VIP on both Primary and Secondary.'))  
                    log.info('Getting the invidual stats')
                    res = trigger_obj.backUpAndRestoreConfigs(devices,'restrore')
                    res = trigger_obj.backUpAndRestoreConfigs(devices,'cleanup')
                    self.failed()
                    
            else:
                log.error('The Initial Traffic Condition did not pass:')
                self.failed()      


class VXLANVxlanV6FUNC101(aetest.Testcase):

    """ Vxlan Trigger- restart L2FM """

    uid = 'VXLAN-L3-VxlanV6-FUNC-101'
    
    @aetest.test
    def VxlanRestartL2FM(self,log,testscript,testbed):

        node_dict = testscript.parameters['node_dict']
        tg_interface_hdl_dict = testscript.parameters['tg_interface_hdl_dict'] 
        traffic_stream_dict = testscript.parameters['traffic_stream_dict'] 
        port_handle_dict = testscript.parameters['port_handle_dict']
        TGList_config_file = testscript.parameters['TGList']
        configdict = testscript.parameters['configdict'] 
        tgn_config_dict = configdict['TG']
        threshold = testscript.parameters['traffic_threshold'] 
        tgn_port_dut_mapping = testscript.parameters['tgn_port_dut_mapping']
        alias_intf_mapping_dict = testscript.parameters['alias_intf_mapping']
        configured_stream = testscript.parameters['configured_stream']
        trigger_obj = testscript.parameters['trigger_obj']

        log.info(banner('The value of configured stream is : {0}'.format(configured_stream))) 

        devices = list(node_dict['all_vteps'].keys())

        for TG in tgn_config_dict.keys():
            tgn_hdl = testscript.parameters['testbed_obj'].devices[TG]
            out = trigger_obj.checkAllStreamStats(tgn_hdl)
        
            if out:
                res = trigger_obj.backUpAndRestoreConfigs(devices,'backup')
                
                log.info(banner('restart L2FM on all the devices'))
                for dut in devices:
                    
                    log.info(banner('Executing the command "restart L2FM " on the dut {0}'.format(dut)))
                    hdl = node_dict['all_dut'][dut]
                    res = MyLib.my_utils.verifyProcessRestart(log,hdl,'L2FM')
                    log.info('sleeping for 10 seconds before issuing the command on the other VTEPs .. {0}'.format(countDownTimer(10)))
                    
                log.info(banner('Waiting for 100 seconds before collecting the Stats {0}'.format(countDownTimer(100))))
                
                out2 = trigger_obj.checkAllStreamStats(tgn_hdl)  
    
                if not out2:
                    log.info(banner('Traffic flow is not as expected after changing the VIP on both Primary and Secondary.'))  
                    log.info('Getting the invidual stats')
                    res = trigger_obj.backUpAndRestoreConfigs(devices,'restrore')
                    res = trigger_obj.backUpAndRestoreConfigs(devices,'cleanup')
                    self.failed()
                    
            else:
                log.error('The Initial Traffic Condition did not pass:')
                self.failed()      

class VXLANVxlanV6FUNC102(aetest.Testcase):

    """ Vxlan Trigger- restart ARP"""

    uid = 'VXLAN-L3-VxlanV6-FUNC-102'
    
    @aetest.test
    def VxlanRestartARP(self,log,testscript,testbed):

        node_dict = testscript.parameters['node_dict']
        tg_interface_hdl_dict = testscript.parameters['tg_interface_hdl_dict'] 
        traffic_stream_dict = testscript.parameters['traffic_stream_dict'] 
        port_handle_dict = testscript.parameters['port_handle_dict']
        TGList_config_file = testscript.parameters['TGList']
        configdict = testscript.parameters['configdict'] 
        tgn_config_dict = configdict['TG']
        threshold = testscript.parameters['traffic_threshold'] 
        tgn_port_dut_mapping = testscript.parameters['tgn_port_dut_mapping']
        alias_intf_mapping_dict = testscript.parameters['alias_intf_mapping']
        configured_stream = testscript.parameters['configured_stream']
        trigger_obj = testscript.parameters['trigger_obj']

        log.info(banner('The value of configured stream is : {0}'.format(configured_stream))) 

        devices = list(node_dict['all_vteps'].keys())

        for TG in tgn_config_dict.keys():
            tgn_hdl = testscript.parameters['testbed_obj'].devices[TG]
            out = trigger_obj.checkAllStreamStats(tgn_hdl)
        
            if out:
                res = trigger_obj.backUpAndRestoreConfigs(devices,'backup')
                
                log.info(banner('restart ARP on all the devices'))
                for dut in devices:
                    
                    log.info(banner('Executing the command "restart ARP " on the dut {0}'.format(dut)))
                    hdl = node_dict['all_dut'][dut]
                    res = MyLib.my_utils.verifyProcessRestart(log,hdl,'arp')
                    log.info('sleeping for 10 seconds before issuing the command on the other VTEPs .. {0}'.format(countDownTimer(10)))
                    
                log.info(banner('Waiting for 100 seconds before collecting the Stats {0}'.format(countDownTimer(100))))
                
                out2 = trigger_obj.checkAllStreamStats(tgn_hdl)  
    
                if not out2:
                    log.info(banner('Traffic flow is not as expected after changing the VIP on both Primary and Secondary.'))  
                    log.info('Getting the invidual stats')
                    res = trigger_obj.backUpAndRestoreConfigs(devices,'restrore')
                    res = trigger_obj.backUpAndRestoreConfigs(devices,'cleanup')
                    self.failed()
                    
            else:
                log.error('The Initial Traffic Condition did not pass:')
                self.failed()      

class VXLANVxlanV6FUNC103(aetest.Testcase):

    """ Vxlan Trigger- restart UFDM """

    uid = 'VXLAN-L3-VxlanV6-FUNC-103'
    
    @aetest.test
    def VxlanRestartL2FM(self,log,testscript,testbed):

        node_dict = testscript.parameters['node_dict']
        tg_interface_hdl_dict = testscript.parameters['tg_interface_hdl_dict'] 
        traffic_stream_dict = testscript.parameters['traffic_stream_dict'] 
        port_handle_dict = testscript.parameters['port_handle_dict']
        TGList_config_file = testscript.parameters['TGList']
        configdict = testscript.parameters['configdict'] 
        tgn_config_dict = configdict['TG']
        threshold = testscript.parameters['traffic_threshold'] 
        tgn_port_dut_mapping = testscript.parameters['tgn_port_dut_mapping']
        alias_intf_mapping_dict = testscript.parameters['alias_intf_mapping']
        configured_stream = testscript.parameters['configured_stream']
        trigger_obj = testscript.parameters['trigger_obj']

        log.info(banner('The value of configured stream is : {0}'.format(configured_stream))) 

        devices = list(node_dict['all_vteps'].keys())

        for TG in tgn_config_dict.keys():
            tgn_hdl = testscript.parameters['testbed_obj'].devices[TG]
            out = trigger_obj.checkAllStreamStats(tgn_hdl)
        
            if out:
                res = trigger_obj.backUpAndRestoreConfigs(devices,'backup')
                
                log.info(banner('restart UFDM on all the devices'))
                for dut in devices:
                    
                    log.info(banner('Executing the command "restart UFDM " on the dut {0}'.format(dut)))
                    hdl = node_dict['all_dut'][dut]
                    res = MyLib.my_utils.verifyProcessRestart(log,hdl,'ufdm')
                    log.info('sleeping for 10 seconds before issuing the command on the other VTEPs .. {0}'.format(countDownTimer(10)))
                    
                log.info(banner('Waiting for 100 seconds before collecting the Stats {0}'.format(countDownTimer(100))))
                
                out2 = trigger_obj.checkAllStreamStats(tgn_hdl)  
    
                if not out2:
                    log.info(banner('Traffic flow is not as expected after changing the VIP on both Primary and Secondary.'))  
                    log.info('Getting the invidual stats')
                    res = trigger_obj.backUpAndRestoreConfigs(devices,'restrore')
                    res = trigger_obj.backUpAndRestoreConfigs(devices,'cleanup')
                    self.failed()
                    
            else:
                log.error('The Initial Traffic Condition did not pass:')
                self.failed()      
                
class VXLANVxlanV6FUNC104(aetest.Testcase):

    """ Vxlan Trigger- restart L2RIB """

    uid = 'VXLAN-L3-VxlanV6-FUNC-104'
    
    @aetest.test
    def VxlanRestartL2RIB(self,log,testscript,testbed):

        node_dict = testscript.parameters['node_dict']
        tg_interface_hdl_dict = testscript.parameters['tg_interface_hdl_dict'] 
        traffic_stream_dict = testscript.parameters['traffic_stream_dict'] 
        port_handle_dict = testscript.parameters['port_handle_dict']
        TGList_config_file = testscript.parameters['TGList']
        configdict = testscript.parameters['configdict'] 
        tgn_config_dict = configdict['TG']
        threshold = testscript.parameters['traffic_threshold'] 
        tgn_port_dut_mapping = testscript.parameters['tgn_port_dut_mapping']
        alias_intf_mapping_dict = testscript.parameters['alias_intf_mapping']
        configured_stream = testscript.parameters['configured_stream']
        trigger_obj = testscript.parameters['trigger_obj']

        log.info(banner('The value of configured stream is : {0}'.format(configured_stream))) 

        devices = list(node_dict['all_vteps'].keys())

        for TG in tgn_config_dict.keys():
            tgn_hdl = testscript.parameters['testbed_obj'].devices[TG]
            out = trigger_obj.checkAllStreamStats(tgn_hdl)
        
            if out:
                res = trigger_obj.backUpAndRestoreConfigs(devices,'backup')
                
                log.info(banner('restart L2RIB on all the devices'))
                for dut in devices:
                    
                    log.info(banner('Executing the command "restart L2RIB " on the dut {0}'.format(dut)))
                    hdl = node_dict['all_dut'][dut]
                    res = MyLib.my_utils.verifyProcessRestart(log,hdl,'l2rib')
                    log.info('sleeping for 10 seconds before issuing the command on the other VTEPs .. {0}'.format(countDownTimer(10)))
                    
                log.info(banner('Waiting for 100 seconds before collecting the Stats {0}'.format(countDownTimer(100))))
                
                out2 = trigger_obj.checkAllStreamStats(tgn_hdl)  
    
                if not out2:
                    log.info(banner('Traffic flow is not as expected after changing the VIP on both Primary and Secondary.'))  
                    log.info('Getting the invidual stats')
                    res = trigger_obj.backUpAndRestoreConfigs(devices,'restrore')
                    res = trigger_obj.backUpAndRestoreConfigs(devices,'cleanup')
                    self.failed()
                    
            else:
                log.error('The Initial Traffic Condition did not pass:')
                self.failed()  
                
class VXLANVxlanV6FUNC105(aetest.Testcase):

    """ Vxlan Trigger- restart netstack """

    uid = 'VXLAN-L3-VxlanV6-FUNC-105'
    
    @aetest.test
    def VxlanRestartnetstack(self,log,testscript,testbed):

        node_dict = testscript.parameters['node_dict']
        tg_interface_hdl_dict = testscript.parameters['tg_interface_hdl_dict'] 
        traffic_stream_dict = testscript.parameters['traffic_stream_dict'] 
        port_handle_dict = testscript.parameters['port_handle_dict']
        TGList_config_file = testscript.parameters['TGList']
        configdict = testscript.parameters['configdict'] 
        tgn_config_dict = configdict['TG']
        threshold = testscript.parameters['traffic_threshold'] 
        tgn_port_dut_mapping = testscript.parameters['tgn_port_dut_mapping']
        alias_intf_mapping_dict = testscript.parameters['alias_intf_mapping']
        configured_stream = testscript.parameters['configured_stream']
        trigger_obj = testscript.parameters['trigger_obj']

        log.info(banner('The value of configured stream is : {0}'.format(configured_stream))) 

        devices = list(node_dict['all_vteps'].keys())

        for TG in tgn_config_dict.keys():
            tgn_hdl = testscript.parameters['testbed_obj'].devices[TG]
            out = trigger_obj.checkAllStreamStats(tgn_hdl)
        
            if out:
                res = trigger_obj.backUpAndRestoreConfigs(devices,'backup')
                
                log.info(banner('restart nestack on all the devices'))
                for dut in devices:
                    
                    log.info(banner('Executing the command "restart netstack " on the dut {0}'.format(dut)))
                    hdl = node_dict['all_dut'][dut]
                    res = MyLib.my_utils.verifyProcessRestart(log,hdl,'netstack')
                    log.info('sleeping for 10 seconds before issuing the command on the other VTEPs .. {0}'.format(countDownTimer(10)))
                    
                log.info(banner('Waiting for 100 seconds before collecting the Stats {0}'.format(countDownTimer(100))))
                
                out2 = trigger_obj.checkAllStreamStats(tgn_hdl)  
    
                if not out2:
                    log.info(banner('Traffic flow is not as expected after changing the VIP on both Primary and Secondary.'))  
                    log.info('Getting the invidual stats')
                    res = trigger_obj.backUpAndRestoreConfigs(devices,'restrore')
                    res = trigger_obj.backUpAndRestoreConfigs(devices,'cleanup')
                    self.failed()
                    
            else:
                log.error('The Initial Traffic Condition did not pass:')
                self.failed()          
 
class VXLANVxlanV6FUNC106(aetest.Testcase):

    """ Vxlan Trigger- VlanShut/UnShut """

    uid = 'VXLAN-L3-VxlanV6-FUNC-106'
    
    @aetest.test
    def VxlanVlanShutUnShut(self,log,testscript,testbed):

        node_dict = testscript.parameters['node_dict']
        tg_interface_hdl_dict = testscript.parameters['tg_interface_hdl_dict'] 
        traffic_stream_dict = testscript.parameters['traffic_stream_dict'] 
        port_handle_dict = testscript.parameters['port_handle_dict']
        TGList_config_file = testscript.parameters['TGList']
        configdict = testscript.parameters['configdict'] 
        tgn_config_dict = configdict['TG']
        threshold = testscript.parameters['traffic_threshold'] 
        tgn_port_dut_mapping = testscript.parameters['tgn_port_dut_mapping']
        alias_intf_mapping_dict = testscript.parameters['alias_intf_mapping']
        configured_stream = testscript.parameters['configured_stream']
        trigger_obj = testscript.parameters['trigger_obj']

        log.info(banner('The value of configured stream is : {0}'.format(configured_stream))) 

        devices = list(node_dict['all_vteps'].keys())
        
        for dut in devices:
            ns = parseScaleVlanParms(log, configdict['scale_config_dict'][dut]['global']['vlan'])
            break

        for TG in tgn_config_dict.keys():
            tgn_hdl = testscript.parameters['testbed_obj'].devices[TG]
            out = trigger_obj.checkAllStreamStats(tgn_hdl)
        
            if out:
                res = trigger_obj.backUpAndRestoreConfigs(devices,'backup')
                
                log.info(banner('Shutting down Vlan on all the VTEPs'))
                no_of_vlan_to_shut = 10 
                vlan_list=[]
                for _ in range(0,no_of_vlan_to_shut):
                    vlan_list.append(random.randint(ns.l2_vlan_start,(ns.l2_vlan_start+ns.no_of_l2_vlans-1)))
                
                
                res = [MyLib.my_utils.vlanOperations(log,node_dict['all_dut'][dut],dut,vlan,operation='shut') for dut in devices for vlan in vlan_list]
                
                log.info(banner('Waiting for 100 seconds before collecting the Stats {0}'.format(countDownTimer(100))))
                
                res = [MyLib.my_utils.vlanOperations(log,node_dict['all_dut'][dut],dut,vlan,operation='unshut') for dut in devices for vlan in vlan_list]
                    
                log.info(banner('Waiting for 100 seconds before collecting the Stats {0}'.format(countDownTimer(100))))
                
                out2 = trigger_obj.checkAllStreamStats(tgn_hdl)  
    
                if not out2:
                    log.info(banner('Traffic flow is not as expected after changing the VIP on both Primary and Secondary.'))  
                    log.info('Getting the invidual stats')
                    res = trigger_obj.backUpAndRestoreConfigs(devices,'restrore')
                    res = trigger_obj.backUpAndRestoreConfigs(devices,'cleanup')
                    self.failed()
                    
            else:
                log.error('The Initial Traffic Condition did not pass:')
                self.failed()           


class VXLANVxlanV6FUNC107(aetest.Testcase):

    """ Vxlan Trigger- VRF Shut/Unshut """

    uid = 'VXLAN-L3-VxlanV6-FUNC-107'
    
    @aetest.test
    def VxlanVRFShutUnShut(self,log,testscript,testbed):

        node_dict = testscript.parameters['node_dict']
        tg_interface_hdl_dict = testscript.parameters['tg_interface_hdl_dict'] 
        traffic_stream_dict = testscript.parameters['traffic_stream_dict'] 
        port_handle_dict = testscript.parameters['port_handle_dict']
        TGList_config_file = testscript.parameters['TGList']
        configdict = testscript.parameters['configdict'] 
        tgn_config_dict = configdict['TG']
        threshold = testscript.parameters['traffic_threshold'] 
        tgn_port_dut_mapping = testscript.parameters['tgn_port_dut_mapping']
        alias_intf_mapping_dict = testscript.parameters['alias_intf_mapping']
        configured_stream = testscript.parameters['configured_stream']
        trigger_obj = testscript.parameters['trigger_obj']

        log.info(banner('The value of configured stream is : {0}'.format(configured_stream))) 
        
        res = [node_dict['all_dut'][dut].execute('show version') for dut in node_dict['all_dut'] if re.search('uut', dut)]

        devices = list(node_dict['all_vteps'].keys())
        
        for dut in devices:
            ns = parseScaleVlanParms(log, configdict['scale_config_dict'][dut]['global']['vlan'])
            break

        for TG in tgn_config_dict.keys():
            tgn_hdl = testscript.parameters['testbed_obj'].devices[TG]
            out = trigger_obj.checkAllStreamStats(tgn_hdl)
        
            if out:
                res = trigger_obj.backUpAndRestoreConfigs(devices,'backup')
                
                log.info(banner('Removing the VRF on all the DUTS'))
                
                vrf_list= ['V6-001','V6-002','V6-003','V6-004','V6-005','V6-006','V6-007','V6-008','V6-009','V6-010']
                
                for dut in devices:
                    hdl = node_dict['all_dut'][dut]
                    hdl.execute('delete bootflash:script_use* no-prompt')
                    for i,vrf in enumerate(vrf_list, start = 1):
                        cfg = 'show run vrf {0} > bootflash:script_use'.format(vrf) + '_' + str(i)
                        hdl.execute(cfg)
                        countDownTimer(20)
                        res = MyLib.my_utils.vrfOperations(log,hdl,dut,vrf,'delete')

                log.info(banner('Waiting for 100 seconds before collecting the Stats {0}'.format(countDownTimer(100))))
                

                for dut in devices:
                    hdl = node_dict['all_dut'][dut]
                    cfg = 'dir | xml | grep fname | grep script_use_'
                    out = hdl.execute(cfg)
                    
                    log.info('The value of out is : {0}'.format(out))
                    
                    for lines in out.splitlines():
                        log.info('The value of lines is : {0}'.format(lines))
                        s = BeautifulSoup(lines)
                        log.info('the value of s is : {0}'.format(s))
                        try:
                            file_name = s.find('fname').string
                            log.info('the vealue of file_name is : {0}'.format(file_name))
                            if file_name:
                                cfg = 'copy bootflash:{0} running-config echo-commands'.format(file_name)
                                hdl.configure(cfg)
                        except:
                            log.info('Match not found')
                        
                
                    
                log.info(banner('Waiting for 100 seconds before collecting the Stats {0}'.format(countDownTimer(100))))
                
                out2 = trigger_obj.checkAllStreamStats(tgn_hdl)  
    
                if not out2:
                    log.info(banner('Traffic flow is not as expected after changing the VIP on both Primary and Secondary.'))  
                    log.info('Getting the invidual stats')
                    res = trigger_obj.backUpAndRestoreConfigs(devices,'restore')
                    res = trigger_obj.backUpAndRestoreConfigs(devices,'cleanup')
                    self.failed()
                    
            else:
                log.error('The Initial Traffic Condition did not pass:')
                self.failed()           

class VXLANVxlanV6FUNC108(aetest.Testcase):

    """ Vxlan Trigger- L2 Tenant SVI Shut / Unshut """

    uid = 'VXLAN-L3-VxlanV6-FUNC-108'
    
    @aetest.test
    def VxlanL2TenantSVIShutUnShut(self,log,testscript,testbed):

        node_dict = testscript.parameters['node_dict']
        tg_interface_hdl_dict = testscript.parameters['tg_interface_hdl_dict'] 
        traffic_stream_dict = testscript.parameters['traffic_stream_dict'] 
        port_handle_dict = testscript.parameters['port_handle_dict']
        TGList_config_file = testscript.parameters['TGList']
        configdict = testscript.parameters['configdict'] 
        tgn_config_dict = configdict['TG']
        threshold = testscript.parameters['traffic_threshold'] 
        tgn_port_dut_mapping = testscript.parameters['tgn_port_dut_mapping']
        alias_intf_mapping_dict = testscript.parameters['alias_intf_mapping']
        configured_stream = testscript.parameters['configured_stream']
        trigger_obj = testscript.parameters['trigger_obj']

        log.info(banner('The value of configured stream is : {0}'.format(configured_stream))) 
        
        res = [node_dict['all_dut'][dut].execute('show version') for dut in node_dict['all_dut'] if re.search('uut', dut)]

        devices = list(node_dict['all_vteps'].keys())
        
        for dut in devices:
            ns = parseScaleVlanParms(log, configdict['scale_config_dict'][dut]['global']['vlan'])
            break

        for TG in tgn_config_dict.keys():
            tgn_hdl = testscript.parameters['testbed_obj'].devices[TG]
            out = trigger_obj.checkAllStreamStats(tgn_hdl)
        
            if out:
                res = trigger_obj.backUpAndRestoreConfigs(devices,'backup')
                
                log.info(banner('Shutting down Tenant SVIs on all the VTEPs'))
                
                res = [MyLib.my_utils.shutDownSVIInterface(log,node_dict['all_dut'][dut],dut, svi) for dut in devices for svi in range(ns.l2_vlan_start, ns.l2_vlan_start + ns.no_of_l2_vlans)]
                
                log.info(banner('Waiting for 100 seconds before Unshutting the Tenant SVIs {0}'.format(countDownTimer(100))))
                
                res = [MyLib.my_utils.unShutDownSVIInterface(log,node_dict['all_dut'][dut],dut, svi) for dut in devices for svi in range(ns.l2_vlan_start, ns.l2_vlan_start + ns.no_of_l2_vlans)]
                    
                log.info(banner('Waiting for 100 seconds before collecting the Stats {0}'.format(countDownTimer(100))))
                
                out2 = trigger_obj.checkAllStreamStats(tgn_hdl)  
    
                if not out2:
                    log.info(banner('Traffic flow is not as expected after changing the VIP on both Primary and Secondary.'))  
                    log.info('Getting the invidual stats')
                    res = trigger_obj.backUpAndRestoreConfigs(devices,'restore')
                    res = trigger_obj.backUpAndRestoreConfigs(devices,'cleanup')
                    self.failed()
                    
            else:
                log.error('The Initial Traffic Condition did not pass:')
                self.failed()   

class VXLANVxlanV6FUNC109(aetest.Testcase):

    """ Vxlan Trigger- L3 VNI SVI Shut / Unshut """

    uid = 'VXLAN-L3-VxlanV6-FUNC-109'
    
    @aetest.test
    def VxlanL3VNIShutUnshut(self,log,testscript,testbed):

        node_dict = testscript.parameters['node_dict']
        tg_interface_hdl_dict = testscript.parameters['tg_interface_hdl_dict'] 
        traffic_stream_dict = testscript.parameters['traffic_stream_dict'] 
        port_handle_dict = testscript.parameters['port_handle_dict']
        TGList_config_file = testscript.parameters['TGList']
        configdict = testscript.parameters['configdict'] 
        tgn_config_dict = configdict['TG']
        threshold = testscript.parameters['traffic_threshold'] 
        tgn_port_dut_mapping = testscript.parameters['tgn_port_dut_mapping']
        alias_intf_mapping_dict = testscript.parameters['alias_intf_mapping']
        configured_stream = testscript.parameters['configured_stream']
        trigger_obj = testscript.parameters['trigger_obj']

        log.info(banner('The value of configured stream is : {0}'.format(configured_stream))) 
        
        res = [node_dict['all_dut'][dut].execute('show version') for dut in node_dict['all_dut'] if re.search('uut', dut)]

        devices = list(node_dict['all_vteps'].keys())
        
        for dut in devices:
            ns = parseScaleVlanParms(log, configdict['scale_config_dict'][dut]['global']['vlan'])
            break

        for TG in tgn_config_dict.keys():
            tgn_hdl = testscript.parameters['testbed_obj'].devices[TG]
            out = trigger_obj.checkAllStreamStats(tgn_hdl)
        
            if out:
                res = trigger_obj.backUpAndRestoreConfigs(devices,'backup')
                
                log.info(banner('Shutting down Tenant SVIs on all the VTEPs'))
                
                res = [MyLib.my_utils.shutDownSVIInterface(log,node_dict['all_dut'][dut],dut, svi) for dut in devices for svi in range(ns.l3_vlan_start, ns.l3_vlan_start + ns.no_of_l3_vlans)]
                
                log.info(banner('Waiting for 100 seconds before Unshutting the Tenant SVIs {0}'.format(countDownTimer(100))))
                
                res = [MyLib.my_utils.unShutDownSVIInterface(log,node_dict['all_dut'][dut],dut, svi) for dut in devices for svi in range(ns.l3_vlan_start, ns.l3_vlan_start + ns.no_of_l3_vlans)]
                    
                log.info(banner('Waiting for 100 seconds before collecting the Stats {0}'.format(countDownTimer(100))))
                
                out2 = trigger_obj.checkAllStreamStats(tgn_hdl)  
    
                if not out2:
                    log.info(banner('Traffic flow is not as expected after changing the VIP on both Primary and Secondary.'))  
                    log.info('Getting the invidual stats')
                    res = trigger_obj.backUpAndRestoreConfigs(devices,'restore')
                    res = trigger_obj.backUpAndRestoreConfigs(devices,'cleanup')
                    self.failed()
                    
            else:
                log.error('The Initial Traffic Condition did not pass:')
                self.failed()   

class VXLANVxlanV6FUNC110(aetest.Testcase):

    """ Vxlan Trigger- L2 VNI SVI Delete/Readd """

    uid = 'VXLAN-L3-VxlanV6-FUNC-110'
    
    @aetest.test
    def VxlanL2VNIDeleteReadd(self,log,testscript,testbed):

        node_dict = testscript.parameters['node_dict']
        tg_interface_hdl_dict = testscript.parameters['tg_interface_hdl_dict'] 
        traffic_stream_dict = testscript.parameters['traffic_stream_dict'] 
        port_handle_dict = testscript.parameters['port_handle_dict']
        TGList_config_file = testscript.parameters['TGList']
        configdict = testscript.parameters['configdict'] 
        tgn_config_dict = configdict['TG']
        threshold = testscript.parameters['traffic_threshold'] 
        tgn_port_dut_mapping = testscript.parameters['tgn_port_dut_mapping']
        alias_intf_mapping_dict = testscript.parameters['alias_intf_mapping']
        configured_stream = testscript.parameters['configured_stream']
        trigger_obj = testscript.parameters['trigger_obj']

        log.info(banner('The value of configured stream is : {0}'.format(configured_stream))) 
        
        res = [node_dict['all_dut'][dut].execute('show version') for dut in node_dict['all_dut'] if re.search('uut', dut)]

        devices = list(node_dict['all_vteps'].keys())
        
        for dut in devices:
            ns = parseScaleVlanParms(log, configdict['scale_config_dict'][dut]['global']['vlan'])
            break

        for TG in tgn_config_dict.keys():
            tgn_hdl = testscript.parameters['testbed_obj'].devices[TG]
            out = trigger_obj.checkAllStreamStats(tgn_hdl)
        
            if out:
                res = trigger_obj.backUpAndRestoreConfigs(devices,'backup')
                
                log.info(banner('Backing up the L2 VNI SVI configs'))
                
                res = [MyLib.my_utils.deleteScriptBackUpFiles(log,node_dict['all_dut'][dut]) for dut in devices if re.search('uut',dut)]
                
                cfg = 'show run interface vlan {0}-{1} > bootflash:script_use'.format(ns.l2_vlan_start,ns.l2_vlan_start+ns.no_of_l2_vlans)
                
                log.info(banner('Deleting Tenant L2 VNI SVIs on all the VTEPs'))
                
                res = [MyLib.my_utils.sviOperations(log,node_dict['all_dut'][dut],dut, svi,operation = 'delete') for dut in devices for svi in range(ns.l2_vlan_start, ns.l2_vlan_start + ns.no_of_l2_vlans)]
                
                log.info(banner('Waiting for 100 seconds before adding bak the L2VNI  Tenant SVIs configs {0}'.format(countDownTimer(100))))
                
                cfg1='copy bootflash:script_use running-config echo-commands'
                
                res = [node_dict['all_dut'][dut].configure(cfg1, timeout = 600) for dut in devices if re.search('uut',dut)]
                                    
                log.info(banner('Waiting for 100 seconds before collecting the Stats {0}'.format(countDownTimer(100))))
                
                out2 = trigger_obj.checkAllStreamStats(tgn_hdl)  
    
                if not out2:
                    log.info(banner('Traffic flow is not as expected after changing the VIP on both Primary and Secondary.'))  
                    log.info('Getting the invidual stats')
                    res = trigger_obj.backUpAndRestoreConfigs(devices,'restore')
                    res = trigger_obj.backUpAndRestoreConfigs(devices,'cleanup')
                    self.failed()
                    
            else:
                log.error('The Initial Traffic Condition did not pass:')
                self.failed()   

class VXLANVxlanV6FUNC111(aetest.Testcase):

    """ Vxlan Trigger- L3 VNI SVI Delete/Readd """

    uid = 'VXLAN-L3-VxlanV6-FUNC-111'
    
    @aetest.test
    def VxlanL2VNIDeleteReadd(self,log,testscript,testbed):

        node_dict = testscript.parameters['node_dict']
        tg_interface_hdl_dict = testscript.parameters['tg_interface_hdl_dict'] 
        traffic_stream_dict = testscript.parameters['traffic_stream_dict'] 
        port_handle_dict = testscript.parameters['port_handle_dict']
        TGList_config_file = testscript.parameters['TGList']
        configdict = testscript.parameters['configdict'] 
        tgn_config_dict = configdict['TG']
        threshold = testscript.parameters['traffic_threshold'] 
        tgn_port_dut_mapping = testscript.parameters['tgn_port_dut_mapping']
        alias_intf_mapping_dict = testscript.parameters['alias_intf_mapping']
        configured_stream = testscript.parameters['configured_stream']
        trigger_obj = testscript.parameters['trigger_obj']

        log.info(banner('The value of configured stream is : {0}'.format(configured_stream))) 
        
        res = [node_dict['all_dut'][dut].execute('show version') for dut in node_dict['all_dut'] if re.search('uut', dut)]

        devices = list(node_dict['all_vteps'].keys())
        
        for dut in devices:
            ns = parseScaleVlanParms(log, configdict['scale_config_dict'][dut]['global']['vlan'])
            break

        for TG in tgn_config_dict.keys():
            tgn_hdl = testscript.parameters['testbed_obj'].devices[TG]
            out = trigger_obj.checkAllStreamStats(tgn_hdl)
        
            if out:
                res = trigger_obj.backUpAndRestoreConfigs(devices,'backup')
                
                log.info(banner('Backing up the L3 VNI SVI configs'))
                
                res = [MyLib.my_utils.deleteScriptBackUpFiles(log,node_dict['all_dut'][dut]) for dut in devices if re.search('uut',dut)]
                
                cfg = 'show run interface vlan {0}-{1} > bootflash:script_use'.format(ns.l3_vlan_start,ns.l3_vlan_start+ns.no_of_l3_vlans)
                
                log.info(banner('Deleting Tenant L2 VNI SVIs on all the VTEPs'))
                
                res = [MyLib.my_utils.sviOperations(log,node_dict['all_dut'][dut],dut, svi,operation = 'delete') for dut in devices for svi in range(ns.l3_vlan_start, ns.l3_vlan_start + ns.no_of_l3_vlans)]
                
                log.info(banner('Waiting for 100 seconds before adding bak the L2VNI  Tenant SVIs configs {0}'.format(countDownTimer(100))))
                
                cfg1='copy bootflash:script_use running-config echo-commands'
                
                res = [node_dict['all_dut'][dut].configure(cfg1, timeout = 600) for dut in devices if re.search('uut',dut)]
                                    
                log.info(banner('Waiting for 100 seconds before collecting the Stats {0}'.format(countDownTimer(100))))
                
                out2 = trigger_obj.checkAllStreamStats(tgn_hdl)  
    
                if not out2:
                    log.info(banner('Traffic flow is not as expected after changing the VIP on both Primary and Secondary.'))  
                    log.info('Getting the invidual stats')
                    res = trigger_obj.backUpAndRestoreConfigs(devices,'restore')
                    res = trigger_obj.backUpAndRestoreConfigs(devices,'cleanup')
                    self.failed()
                    
            else:
                log.error('The Initial Traffic Condition did not pass:')
                self.failed()  
                                                                
class VXLANVxlanV6FUNC112(aetest.Testcase):

    """ Nested Vxlan - Orphan to Orphan """

    uid = 'VXLAN-L3-VxlanV6-FUNC-112'
    
    @aetest.test
    def NestedVxlanOrphanToOrphanV6Payload(self,log,testscript,testbed):
        
        node_dict = testscript.parameters['node_dict']
        tg_interface_hdl_dict = testscript.parameters['tg_interface_hdl_dict'] 
        traffic_stream_dict = testscript.parameters['traffic_stream_dict'] 
        port_handle_dict = testscript.parameters['port_handle_dict']
        TGList_config_file = testscript.parameters['TGList']
        configdict = testscript.parameters['configdict'] 
        tgn_config_dict = configdict['TG']
        threshold = testscript.parameters['traffic_threshold'] 
        tgn_port_dut_mapping = testscript.parameters['tgn_port_dut_mapping']
        alias_intf_mapping_dict = testscript.parameters['alias_intf_mapping']
        configured_stream = testscript.parameters['configured_stream']
        trigger_obj = testscript.parameters['trigger_obj']
        testbed_obj = testscript.parameters['testbed_obj']

        log.info(banner('The value of configured stream is : {0}'.format(configured_stream))) 
        
        res = [node_dict['all_dut'][dut].execute('show version') for dut in node_dict['all_dut'] if re.search('uut', dut)]
        
        for TG in tgn_config_dict.keys():
            tgn_hdl = testscript.parameters['testbed_obj'].devices[TG]
            out = trigger_obj.checkAllStreamStats(tgn_hdl)
            flag = 0
            if out:
                
                log.info(banner('Stopping all the Traffic:'))
                
                a = tgn_hdl.traffic_control(action='stop',max_wait_timer=60)
                
                log.info(banner('Waiting for 30 seconds before Creating the Nested Vxlan traffic : '))
                countDownTimer(30)
                
                log.info(banner('Creating Nested Vxlan Traffic:'))
                    
                source_port = testscript.parameters['configdict']['TG'][TG]['TEST-005']['traffic_config_dict']['source']
                receiver_port = testscript.parameters['configdict']['TG'][TG]['TEST-005']['traffic_config_dict']['capable_receivers']
                traffic_args=testscript.parameters['configdict']['TG'][TG]['TEST-005']['traffic_config_dict']['params']
                 
                src_port = [port_handle_dict[x] for x in source_port]
                dst_port = [port_handle_dict[x] for x in receiver_port]
                log.info('The value of src_port is : {0}'.format(src_port))
                log.info('The value of dst_port is : {0}'.format(dst_port))
                
                traffic_gen_object = MyLib.my_config_utils.IxiaRawTrafficGeneration(log,tgn_hdl,configdict,port_handle_dict)
                
                end_point_args = traffic_args['Traffic_End_points']
                log.info(banner('The value of end_point_args is : {0}'.format(end_point_args)))
                
                nested_vxlan_traffic_config = traffic_gen_object.configureTrafficEndPoints(end_point_args,emulation_src_handle=src_port, emulation_dst_handle=dst_port)
                log.info('The value of ixia_traffic_config is : {0}'.format(nested_vxlan_traffic_config))
                
                if nested_vxlan_traffic_config['status'] == 1:
                    log.info(banner('Traffic End points is configured as expected.. configuring the STream params'))
                    trf_hdl = nested_vxlan_traffic_config['traffic_item']
                    traffic_stream_args  = traffic_args['StreamParameters']
                    nested_vxlan_traffic_config1 = traffic_gen_object.configureTrafficStreamParameters(trf_hdl,traffic_stream_args)
                    if nested_vxlan_traffic_config1['status'] == 1:
                        log.info(banner('Configuring the Ethernet Header -- Stack 1 '))
                        ethernet1_header_args = traffic_args['EthernetHeader1']
                        nested_vxlan_traffic_config2 = traffic_gen_object.configureEthernetHeader(trf_hdl,ethernet1_header_args)
                        if nested_vxlan_traffic_config2['status'] == 1:
                            log.info(banner('Configuring the Vlan Header -- Stack 2 '))
                            vlan_header_args = traffic_args['VlanHeader']
                            nested_vxlan_traffic_config3 = traffic_gen_object.configureVlanHeader(trf_hdl,vlan_header_args)
                            if nested_vxlan_traffic_config3['status'] == 1:
                                log.info(banner('Configuring the inner IPv6 Header -- Stack 3'))
                                ip1_header_args = traffic_args['IPHeader1']
                                nested_vxlan_traffic_config4 = traffic_gen_object.configureIPv6ProtocolHeader(trf_hdl,ip1_header_args)
                                if nested_vxlan_traffic_config4['status'] == 1:
                                    log.info(banner('Configuring the UDP Header -- Stack 4'))
                                    udp_header_args = traffic_args['UDPHeader']
                                    nested_vxlan_traffic_config5 = traffic_gen_object.configureUDPHeader(trf_hdl,udp_header_args)
                                    if nested_vxlan_traffic_config5['status'] == 1:
                                        log.info(banner('Configuring the Inner Vxlan Header -- Stack 5'))
                                        vxlan_header_args = traffic_args['VxlanHeader']
                                        nested_vxlan_traffic_config6 = traffic_gen_object.configureVxlanHeader(trf_hdl,vxlan_header_args)
                                        ls = nested_vxlan_traffic_config6['last_stack']
                                        if nested_vxlan_traffic_config6['status'] == 1:
                                            log.info(banner('Configuring the Inner VNI header - Stack 5a'))
                                            vni_header_args = traffic_args['VNIHeader']
                                            nested_vxlan_traffic_config7 = traffic_gen_object.configureVxlanVNIHeader(trf_hdl,vni_header_args,ls)
                                            if nested_vxlan_traffic_config7['status'] == 1:
                                                log.info(banner('Configuring the Ethernet Header 2- Stack 6'))
                                                ethernet2_header_args = traffic_args['EthernetHeader2']
                                                nested_vxlan_traffic_config8 = traffic_gen_object.configureEthernetHeader(trf_hdl,ethernet2_header_args)                
                                                if nested_vxlan_traffic_config8['status'] == 1:
                                                    log.info(banner('Configuring the IP Header 2- Stack 7'))
                                                    ip2_header_args = traffic_args['IPHeader2']
                                                    nested_vxlan_traffic_config8 = traffic_gen_object.configureIPv6ProtocolHeader(trf_hdl,ip2_header_args)
                
                
                
                log.info('The value of nested_vxlan_traffic_config is : {0}'.format(nested_vxlan_traffic_config8))
                ethernet_args = traffic_args['EthernetHeader1']                                   
                ns = MyLib.my_config_utils.parseEthernetHeaderArgs(log,ethernet_args)
                dmac = ns.mac_dst
                actual_receiver = testscript.parameters['configdict']['TG'][TG]['TEST-005']['traffic_config_dict']['actual_receiver'][0]
                
                dut_to_configure_static_mac = tgn_port_dut_mapping[actual_receiver]
                log.info('the value of dut_to_configure is : {0}'.format(dut_to_configure_static_mac))
                            
                for item in testbed_obj.devices.aliases:
                    log.info('The value of item is : {0}'.format(item))
                    if re.search(dut_to_configure_static_mac,item):
                        for i in testbed_obj.devices[item].interfaces.keys():
                            log.info('The value if i is : {0}'.format(i))
                            if re.search('TG',testbed_obj.devices[item].interfaces[i].alias):
                                port = i
                                log.info('The value of port is : {0}'.format(port))
                        
                
                cfg = 'mac address-table static {0} vlan 701 interface {1}'.format(dmac,port)
                node_dict['all_dut'][dut_to_configure_static_mac].configure(cfg)
                log.info(banner('Waiting for 20 seconds before collecting the stats'))
                countDownTimer(20)
                b = tgn_hdl.traffic_control(action='run', handle = trf_hdl, max_wait_timer=60)
                
                stream_dict = {}
                stream_dict.setdefault('TEST-005',{})
                stream_dict['TEST-005']['stream_id'] = nested_vxlan_traffic_config8['stream_id']
                
                res = MyLib.my_config_utils.getTrafficItemStatistics(log,tgn_hdl,stream_dict,'TEST-005')
                
                if abs(res['tx']-res['rx'] < threshold):
                    log.info('Traffic flow is as expected..The value of tx and Rx is : {0} and {1}'.format(res['tx'],res['rx']))
                else:
                    log.info('Traffic Flow is not as expected. The value of tx and Rx is : {0} and {1}'.format(res['tx'],res['rx']))
                    flag = 1 
                
                log.info('Deleting the Created Stream for this test: ')

                x1 = tgn_hdl.traffic_control(action='stop', handle = trf_hdl,max_wait_timer=60)
                
                countDownTimer(30)

                log.info('Removing the stream:')
                y = tgn_hdl.traffic_config(mode='remove',stream_id=nested_vxlan_traffic_config8['stream_id'])
                
                node_dict['all_dut'][dut_to_configure_static_mac].configure('no '+cfg)
                        
                log.info('STarting all the other streams')
                z = tgn_hdl.traffic_control(action='run',max_wait_timer=60)
                
                log.info('waiting for 30 seconds before collecting the stats:')
                countDownTimer(30)
                out = trigger_obj.checkAllStreamStats(tgn_hdl)
                
                if not out:
                    log.error(banner('Traffic has not recovered on some of the streams after starting the Original Streams.. Collecting the individual STream stats:'))
                    self.failed()
                        
                if flag:
                    log.error(banner('Nested Traffic Flow was not as expected. Hence failing'))
                    self.failed()
            else:
                log.error('The Initial Traffic Condition did not pass:')
                self.failed()                                   

class VXLANVxlanV6FUNC113(aetest.Testcase):

    """ Nested Vxlan - Orphan to VPC Port """

    uid = 'VXLAN-L3-VxlanV6-FUNC-113'
    
    @aetest.test
    def NestedVxlanOrphanToVPCPortV6Payload(self,log,testscript,testbed):
        
        node_dict = testscript.parameters['node_dict']
        tg_interface_hdl_dict = testscript.parameters['tg_interface_hdl_dict'] 
        traffic_stream_dict = testscript.parameters['traffic_stream_dict'] 
        port_handle_dict = testscript.parameters['port_handle_dict']
        TGList_config_file = testscript.parameters['TGList']
        configdict = testscript.parameters['configdict'] 
        tgn_config_dict = configdict['TG']
        threshold = testscript.parameters['traffic_threshold'] 
        tgn_port_dut_mapping = testscript.parameters['tgn_port_dut_mapping']
        alias_intf_mapping_dict = testscript.parameters['alias_intf_mapping']
        configured_stream = testscript.parameters['configured_stream']
        trigger_obj = testscript.parameters['trigger_obj']
        testbed_obj = testscript.parameters['testbed_obj']

        log.info(banner('The value of configured stream is : {0}'.format(configured_stream))) 
        
        res = [node_dict['all_dut'][dut].execute('show version') for dut in node_dict['all_dut'] if re.search('uut', dut)]
        
        for TG in tgn_config_dict.keys():
            tgn_hdl = testscript.parameters['testbed_obj'].devices[TG]
            out = trigger_obj.checkAllStreamStats(tgn_hdl)
            flag = 0
            if out:
                
                log.info(banner('Stopping all the Traffic:'))
                
                a = tgn_hdl.traffic_control(action='stop',max_wait_timer=60)
                
                log.info(banner('Waiting for 30 seconds before Creating the Nested Vxlan traffic : '))
                countDownTimer(30)
                
                log.info(banner('Creating Nested Vxlan Traffic:'))
                    
                source_port = testscript.parameters['configdict']['TG'][TG]['TEST-006']['traffic_config_dict']['source']
                receiver_port = testscript.parameters['configdict']['TG'][TG]['TEST-006']['traffic_config_dict']['capable_receivers']
                traffic_args=testscript.parameters['configdict']['TG'][TG]['TEST-006']['traffic_config_dict']['params']
                 
                src_port = [port_handle_dict[x] for x in source_port]
                dst_port = [port_handle_dict[x] for x in receiver_port]
                log.info('The value of src_port is : {0}'.format(src_port))
                log.info('The value of dst_port is : {0}'.format(dst_port))
                
                traffic_gen_object = MyLib.my_config_utils.IxiaRawTrafficGeneration(log,tgn_hdl,configdict,port_handle_dict)
                
                end_point_args = traffic_args['Traffic_End_points']
                log.info(banner('The value of end_point_args is : {0}'.format(end_point_args)))
                
                nested_vxlan_traffic_config = traffic_gen_object.configureTrafficEndPoints(end_point_args,emulation_src_handle=src_port, emulation_dst_handle=dst_port)
                log.info('The value of ixia_traffic_config is : {0}'.format(nested_vxlan_traffic_config))
                
                if nested_vxlan_traffic_config['status'] == 1:
                    log.info(banner('Traffic End points is configured as expected.. configuring the STream params'))
                    trf_hdl = nested_vxlan_traffic_config['traffic_item']
                    traffic_stream_args  = traffic_args['StreamParameters']
                    nested_vxlan_traffic_config1 = traffic_gen_object.configureTrafficStreamParameters(trf_hdl,traffic_stream_args)
                    if nested_vxlan_traffic_config1['status'] == 1:
                        log.info(banner('Configuring the Ethernet Header -- Stack 1 '))
                        ethernet1_header_args = traffic_args['EthernetHeader1']
                        nested_vxlan_traffic_config2 = traffic_gen_object.configureEthernetHeader(trf_hdl,ethernet1_header_args)
                        if nested_vxlan_traffic_config2['status'] == 1:
                            log.info(banner('Configuring the Vlan Header -- Stack 2 '))
                            vlan_header_args = traffic_args['VlanHeader']
                            nested_vxlan_traffic_config3 = traffic_gen_object.configureVlanHeader(trf_hdl,vlan_header_args)
                            if nested_vxlan_traffic_config3['status'] == 1:
                                log.info(banner('Configuring the inner IPv6 Header -- Stack 3'))
                                ip1_header_args = traffic_args['IPHeader1']
                                nested_vxlan_traffic_config4 = traffic_gen_object.configureIPv6ProtocolHeader(trf_hdl,ip1_header_args)
                                if nested_vxlan_traffic_config4['status'] == 1:
                                    log.info(banner('Configuring the UDP Header -- Stack 4'))
                                    udp_header_args = traffic_args['UDPHeader']
                                    nested_vxlan_traffic_config5 = traffic_gen_object.configureUDPHeader(trf_hdl,udp_header_args)
                                    if nested_vxlan_traffic_config5['status'] == 1:
                                        log.info(banner('Configuring the Inner Vxlan Header -- Stack 5'))
                                        vxlan_header_args = traffic_args['VxlanHeader']
                                        nested_vxlan_traffic_config6 = traffic_gen_object.configureVxlanHeader(trf_hdl,vxlan_header_args)
                                        ls = nested_vxlan_traffic_config6['last_stack']
                                        if nested_vxlan_traffic_config6['status'] == 1:
                                            log.info(banner('Configuring the Inner VNI header - Stack 5a'))
                                            vni_header_args = traffic_args['VNIHeader']
                                            nested_vxlan_traffic_config7 = traffic_gen_object.configureVxlanVNIHeader(trf_hdl,vni_header_args,ls)
                                            if nested_vxlan_traffic_config7['status'] == 1:
                                                log.info(banner('Configuring the Ethernet Header 2- Stack 6'))
                                                ethernet2_header_args = traffic_args['EthernetHeader2']
                                                nested_vxlan_traffic_config8 = traffic_gen_object.configureEthernetHeader(trf_hdl,ethernet2_header_args)                
                                                if nested_vxlan_traffic_config8['status'] == 1:
                                                    log.info(banner('Configuring the IP Header 2- Stack 7'))
                                                    ip2_header_args = traffic_args['IPHeader2']
                                                    nested_vxlan_traffic_config8 = traffic_gen_object.configureIPv6ProtocolHeader(trf_hdl,ip2_header_args)
                
                
                
                log.info('The value of nested_vxlan_traffic_config is : {0}'.format(nested_vxlan_traffic_config8))
                ethernet_args = traffic_args['EthernetHeader1']                                   
                ns = MyLib.my_config_utils.parseEthernetHeaderArgs(log,ethernet_args)
                dmac = ns.mac_dst
                actual_receiver = testscript.parameters['configdict']['TG'][TG]['TEST-006']['traffic_config_dict']['actual_receiver'][0]
                
                dut_to_configure_static_mac = tgn_port_dut_mapping[actual_receiver]
                log.info('the value of dut_to_configure is : {0}'.format(dut_to_configure_static_mac))
                            
                for item in testbed_obj.devices.aliases:
                    log.info('The value of item is : {0}'.format(item))
                    if re.search(dut_to_configure_static_mac,item):
                        for i in testbed_obj.devices[item].interfaces.keys():
                            log.info('The value if i is : {0}'.format(i))
                            if re.search('TG',testbed_obj.devices[item].interfaces[i].alias):
                                port = i
                                log.info('The value of port is : {0}'.format(port))
                        
                
                cfg = 'mac address-table static {0} vlan 701 interface {1}'.format(dmac,port)
                node_dict['all_dut'][dut_to_configure_static_mac].configure(cfg)
                log.info(banner('Waiting for 20 seconds before collecting the stats'))
                countDownTimer(20)
                b = tgn_hdl.traffic_control(action='run', handle = trf_hdl, max_wait_timer=60)
                
                stream_dict = {}
                stream_dict.setdefault('TEST-006',{})
                stream_dict['TEST-006']['stream_id'] = nested_vxlan_traffic_config8['stream_id']
                
                res = MyLib.my_config_utils.getTrafficItemStatistics(log,tgn_hdl,stream_dict,'TEST-006')
                
                if abs(res['tx']-res['rx'] < threshold):
                    log.info('Traffic flow is as expected..The value of tx and Rx is : {0} and {1}'.format(res['tx'],res['rx']))
                else:
                    log.info('Traffic Flow is not as expected. The value of tx and Rx is : {0} and {1}'.format(res['tx'],res['rx']))
                    flag = 1 
                
                log.info('Deleting the Created Stream for this test: ')

                x1 = tgn_hdl.traffic_control(action='stop', handle = trf_hdl,max_wait_timer=60)
                
                countDownTimer(30)

                # log.info('Removing the stream:')
                # y = tgn_hdl.traffic_config(mode='remove',stream_id=nested_vxlan_traffic_config8['stream_id'])
                
                node_dict['all_dut'][dut_to_configure_static_mac].configure('no '+cfg)
                        
                log.info('STarting all the other streams')
                z = tgn_hdl.traffic_control(action='run',max_wait_timer=60)
                
                log.info('waiting for 30 seconds before collecting the stats:')
                countDownTimer(30)
                out = trigger_obj.checkAllStreamStats(tgn_hdl)
                
                if not out:
                    log.error(banner('Traffic has not recovered on some of the streams after starting the Original Streams.. Collecting the individual STream stats:'))
                    self.failed()
                        
                if flag:
                    log.error(banner('Nested Traffic Flow was not as expected. Hence failing'))
                    self.failed()
            else:
                log.error('The Initial Traffic Condition did not pass:')
                self.failed()                                   

class VXLANVxlanV6FUNC114(aetest.Testcase):

    """ Nested Vxlan - Orphan to Remote VTEP """

    uid = 'VXLAN-L3-VxlanV6-FUNC-114'
    
    @aetest.test
    def NestedVxlanOrphanToremoteVTEPV6Payload(self,log,testscript,testbed):
        
        node_dict = testscript.parameters['node_dict']
        tg_interface_hdl_dict = testscript.parameters['tg_interface_hdl_dict'] 
        traffic_stream_dict = testscript.parameters['traffic_stream_dict'] 
        port_handle_dict = testscript.parameters['port_handle_dict']
        TGList_config_file = testscript.parameters['TGList']
        configdict = testscript.parameters['configdict'] 
        tgn_config_dict = configdict['TG']
        threshold = testscript.parameters['traffic_threshold'] 
        tgn_port_dut_mapping = testscript.parameters['tgn_port_dut_mapping']
        alias_intf_mapping_dict = testscript.parameters['alias_intf_mapping']
        configured_stream = testscript.parameters['configured_stream']
        trigger_obj = testscript.parameters['trigger_obj']
        testbed_obj = testscript.parameters['testbed_obj']

        log.info(banner('The value of configured stream is : {0}'.format(configured_stream))) 
        
        res = [node_dict['all_dut'][dut].execute('show version') for dut in node_dict['all_dut'] if re.search('uut', dut)]
        
        for TG in tgn_config_dict.keys():
            tgn_hdl = testscript.parameters['testbed_obj'].devices[TG]
            out = trigger_obj.checkAllStreamStats(tgn_hdl)
            flag = 0
            if out:
                
                log.info(banner('Stopping all the Traffic:'))
                
                a = tgn_hdl.traffic_control(action='stop',max_wait_timer=60)
                
                log.info(banner('Waiting for 30 seconds before Creating the Nested Vxlan traffic : '))
                countDownTimer(30)
                
                log.info(banner('Creating Nested Vxlan Traffic:'))
                    
                source_port = testscript.parameters['configdict']['TG'][TG]['TEST-007']['traffic_config_dict']['source']
                receiver_port = testscript.parameters['configdict']['TG'][TG]['TEST-007']['traffic_config_dict']['capable_receivers']
                traffic_args=testscript.parameters['configdict']['TG'][TG]['TEST-007']['traffic_config_dict']['params']
                 
                src_port = [port_handle_dict[x] for x in source_port]
                dst_port = [port_handle_dict[x] for x in receiver_port]
                log.info('The value of src_port is : {0}'.format(src_port))
                log.info('The value of dst_port is : {0}'.format(dst_port))
                
                traffic_gen_object = MyLib.my_config_utils.IxiaRawTrafficGeneration(log,tgn_hdl,configdict,port_handle_dict)
                
                end_point_args = traffic_args['Traffic_End_points']
                log.info(banner('The value of end_point_args is : {0}'.format(end_point_args)))
                
                nested_vxlan_traffic_config = traffic_gen_object.configureTrafficEndPoints(end_point_args,emulation_src_handle=src_port, emulation_dst_handle=dst_port)
                log.info('The value of ixia_traffic_config is : {0}'.format(nested_vxlan_traffic_config))
                
                if nested_vxlan_traffic_config['status'] == 1:
                    log.info(banner('Traffic End points is configured as expected.. configuring the STream params'))
                    trf_hdl = nested_vxlan_traffic_config['traffic_item']
                    traffic_stream_args  = traffic_args['StreamParameters']
                    nested_vxlan_traffic_config1 = traffic_gen_object.configureTrafficStreamParameters(trf_hdl,traffic_stream_args)
                    if nested_vxlan_traffic_config1['status'] == 1:
                        log.info(banner('Configuring the Ethernet Header -- Stack 1 '))
                        ethernet1_header_args = traffic_args['EthernetHeader1']
                        nested_vxlan_traffic_config2 = traffic_gen_object.configureEthernetHeader(trf_hdl,ethernet1_header_args)
                        if nested_vxlan_traffic_config2['status'] == 1:
                            log.info(banner('Configuring the Vlan Header -- Stack 2 '))
                            vlan_header_args = traffic_args['VlanHeader']
                            nested_vxlan_traffic_config3 = traffic_gen_object.configureVlanHeader(trf_hdl,vlan_header_args)
                            if nested_vxlan_traffic_config3['status'] == 1:
                                log.info(banner('Configuring the inner IPv6 Header -- Stack 3'))
                                ip1_header_args = traffic_args['IPHeader1']
                                nested_vxlan_traffic_config4 = traffic_gen_object.configureIPv6ProtocolHeader(trf_hdl,ip1_header_args)
                                if nested_vxlan_traffic_config4['status'] == 1:
                                    log.info(banner('Configuring the UDP Header -- Stack 4'))
                                    udp_header_args = traffic_args['UDPHeader']
                                    nested_vxlan_traffic_config5 = traffic_gen_object.configureUDPHeader(trf_hdl,udp_header_args)
                                    if nested_vxlan_traffic_config5['status'] == 1:
                                        log.info(banner('Configuring the Inner Vxlan Header -- Stack 5'))
                                        vxlan_header_args = traffic_args['VxlanHeader']
                                        nested_vxlan_traffic_config6 = traffic_gen_object.configureVxlanHeader(trf_hdl,vxlan_header_args)
                                        ls = nested_vxlan_traffic_config6['last_stack']
                                        if nested_vxlan_traffic_config6['status'] == 1:
                                            log.info(banner('Configuring the Inner VNI header - Stack 5a'))
                                            vni_header_args = traffic_args['VNIHeader']
                                            nested_vxlan_traffic_config7 = traffic_gen_object.configureVxlanVNIHeader(trf_hdl,vni_header_args,ls)
                                            if nested_vxlan_traffic_config7['status'] == 1:
                                                log.info(banner('Configuring the Ethernet Header 2- Stack 6'))
                                                ethernet2_header_args = traffic_args['EthernetHeader2']
                                                nested_vxlan_traffic_config8 = traffic_gen_object.configureEthernetHeader(trf_hdl,ethernet2_header_args)                
                                                if nested_vxlan_traffic_config8['status'] == 1:
                                                    log.info(banner('Configuring the IP Header 2- Stack 7'))
                                                    ip2_header_args = traffic_args['IPHeader2']
                                                    nested_vxlan_traffic_config8 = traffic_gen_object.configureIPv6ProtocolHeader(trf_hdl,ip2_header_args)
                
                
                
                log.info('The value of nested_vxlan_traffic_config is : {0}'.format(nested_vxlan_traffic_config8))
                ethernet_args = traffic_args['EthernetHeader1']                                   
                ns = MyLib.my_config_utils.parseEthernetHeaderArgs(log,ethernet_args)
                dmac = ns.mac_dst
                actual_receiver = testscript.parameters['configdict']['TG'][TG]['TEST-007']['traffic_config_dict']['actual_receiver'][0]
                
                dut_to_configure_static_mac = tgn_port_dut_mapping[actual_receiver]
                log.info('the value of dut_to_configure is : {0}'.format(dut_to_configure_static_mac))
                            
                for item in testbed_obj.devices.aliases:
                    log.info('The value of item is : {0}'.format(item))
                    if re.search(dut_to_configure_static_mac,item):
                        for i in testbed_obj.devices[item].interfaces.keys():
                            log.info('The value if i is : {0}'.format(i))
                            if re.search('TG',testbed_obj.devices[item].interfaces[i].alias):
                                port = i
                                log.info('The value of port is : {0}'.format(port))
                        
                
                cfg = 'mac address-table static {0} vlan 701 interface {1}'.format(dmac,port)
                node_dict['all_dut'][dut_to_configure_static_mac].configure(cfg)
                log.info(banner('Waiting for 20 seconds before collecting the stats'))
                countDownTimer(20)
                b = tgn_hdl.traffic_control(action='run', handle = trf_hdl, max_wait_timer=60)
                
                stream_dict = {}
                stream_dict.setdefault('TEST-007',{})
                stream_dict['TEST-007']['stream_id'] = nested_vxlan_traffic_config8['stream_id']
                
                res = MyLib.my_config_utils.getTrafficItemStatistics(log,tgn_hdl,stream_dict,'TEST-007')
                
                if abs(res['tx']-res['rx'] < threshold):
                    log.info('Traffic flow is as expected..The value of tx and Rx is : {0} and {1}'.format(res['tx'],res['rx']))
                else:
                    log.info('Traffic Flow is not as expected. The value of tx and Rx is : {0} and {1}'.format(res['tx'],res['rx']))
                    flag = 1 
                
                log.info('Deleting the Created Stream for this test: ')

                x1 = tgn_hdl.traffic_control(action='stop', handle = trf_hdl,max_wait_timer=60)
                
                countDownTimer(30)

                log.info('Removing the stream:')
                y = tgn_hdl.traffic_config(mode='remove',stream_id=nested_vxlan_traffic_config8['stream_id'])
                
                node_dict['all_dut'][dut_to_configure_static_mac].configure('no '+cfg)
                        
                log.info('STarting all the other streams')
                z = tgn_hdl.traffic_control(action='run',max_wait_timer=60)
                
                log.info('waiting for 30 seconds before collecting the stats:')
                countDownTimer(30)
                out = trigger_obj.checkAllStreamStats(tgn_hdl)
                
                if not out:
                    log.error(banner('Traffic has not recovered on some of the streams after starting the Original Streams.. Collecting the individual STream stats:'))
                    self.failed()
                        
                if flag:
                    log.error(banner('Nested Traffic Flow was not as expected. Hence failing'))
                    self.failed()
            else:
                log.error('The Initial Traffic Condition did not pass:')
                self.failed()                                   

class VXLANVxlanV6FUNC115(aetest.Testcase):

    """ Nested Vxlan - VPC Port to Remote VTEP """

    uid = 'VXLAN-L3-VxlanV6-FUNC-115'
    
    @aetest.test
    def NestedVxlanVPCPortToRemoteVTEPV6Payload(self,log,testscript,testbed):
        
        node_dict = testscript.parameters['node_dict']
        tg_interface_hdl_dict = testscript.parameters['tg_interface_hdl_dict'] 
        traffic_stream_dict = testscript.parameters['traffic_stream_dict'] 
        port_handle_dict = testscript.parameters['port_handle_dict']
        TGList_config_file = testscript.parameters['TGList']
        configdict = testscript.parameters['configdict'] 
        tgn_config_dict = configdict['TG']
        threshold = testscript.parameters['traffic_threshold'] 
        tgn_port_dut_mapping = testscript.parameters['tgn_port_dut_mapping']
        alias_intf_mapping_dict = testscript.parameters['alias_intf_mapping']
        configured_stream = testscript.parameters['configured_stream']
        trigger_obj = testscript.parameters['trigger_obj']
        testbed_obj = testscript.parameters['testbed_obj']

        log.info(banner('The value of configured stream is : {0}'.format(configured_stream))) 
        
        res = [node_dict['all_dut'][dut].execute('show version') for dut in node_dict['all_dut'] if re.search('uut', dut)]
        
        for TG in tgn_config_dict.keys():
            tgn_hdl = testscript.parameters['testbed_obj'].devices[TG]
            out = trigger_obj.checkAllStreamStats(tgn_hdl)
            flag = 0
            if out:
                
                log.info(banner('Stopping all the Traffic:'))
                
                a = tgn_hdl.traffic_control(action='stop',max_wait_timer=60)
                
                log.info(banner('Waiting for 30 seconds before Creating the Nested Vxlan traffic : '))
                countDownTimer(30)
                
                log.info(banner('Creating Nested Vxlan Traffic:'))
                    
                source_port = testscript.parameters['configdict']['TG'][TG]['TEST-008']['traffic_config_dict']['source']
                receiver_port = testscript.parameters['configdict']['TG'][TG]['TEST-008']['traffic_config_dict']['capable_receivers']
                traffic_args=testscript.parameters['configdict']['TG'][TG]['TEST-008']['traffic_config_dict']['params']
                 
                src_port = [port_handle_dict[x] for x in source_port]
                dst_port = [port_handle_dict[x] for x in receiver_port]
                log.info('The value of src_port is : {0}'.format(src_port))
                log.info('The value of dst_port is : {0}'.format(dst_port))
                
                traffic_gen_object = MyLib.my_config_utils.IxiaRawTrafficGeneration(log,tgn_hdl,configdict,port_handle_dict)
                
                end_point_args = traffic_args['Traffic_End_points']
                log.info(banner('The value of end_point_args is : {0}'.format(end_point_args)))
                
                nested_vxlan_traffic_config = traffic_gen_object.configureTrafficEndPoints(end_point_args,emulation_src_handle=src_port, emulation_dst_handle=dst_port)
                log.info('The value of ixia_traffic_config is : {0}'.format(nested_vxlan_traffic_config))
                
                if nested_vxlan_traffic_config['status'] == 1:
                    log.info(banner('Traffic End points is configured as expected.. configuring the STream params'))
                    trf_hdl = nested_vxlan_traffic_config['traffic_item']
                    traffic_stream_args  = traffic_args['StreamParameters']
                    nested_vxlan_traffic_config1 = traffic_gen_object.configureTrafficStreamParameters(trf_hdl,traffic_stream_args)
                    if nested_vxlan_traffic_config1['status'] == 1:
                        log.info(banner('Configuring the Ethernet Header -- Stack 1 '))
                        ethernet1_header_args = traffic_args['EthernetHeader1']
                        nested_vxlan_traffic_config2 = traffic_gen_object.configureEthernetHeader(trf_hdl,ethernet1_header_args)
                        if nested_vxlan_traffic_config2['status'] == 1:
                            log.info(banner('Configuring the Vlan Header -- Stack 2 '))
                            vlan_header_args = traffic_args['VlanHeader']
                            nested_vxlan_traffic_config3 = traffic_gen_object.configureVlanHeader(trf_hdl,vlan_header_args)
                            if nested_vxlan_traffic_config3['status'] == 1:
                                log.info(banner('Configuring the inner IPv6 Header -- Stack 3'))
                                ip1_header_args = traffic_args['IPHeader1']
                                nested_vxlan_traffic_config4 = traffic_gen_object.configureIPv6ProtocolHeader(trf_hdl,ip1_header_args)
                                if nested_vxlan_traffic_config4['status'] == 1:
                                    log.info(banner('Configuring the UDP Header -- Stack 4'))
                                    udp_header_args = traffic_args['UDPHeader']
                                    nested_vxlan_traffic_config5 = traffic_gen_object.configureUDPHeader(trf_hdl,udp_header_args)
                                    if nested_vxlan_traffic_config5['status'] == 1:
                                        log.info(banner('Configuring the Inner Vxlan Header -- Stack 5'))
                                        vxlan_header_args = traffic_args['VxlanHeader']
                                        nested_vxlan_traffic_config6 = traffic_gen_object.configureVxlanHeader(trf_hdl,vxlan_header_args)
                                        ls = nested_vxlan_traffic_config6['last_stack']
                                        if nested_vxlan_traffic_config6['status'] == 1:
                                            log.info(banner('Configuring the Inner VNI header - Stack 5a'))
                                            vni_header_args = traffic_args['VNIHeader']
                                            nested_vxlan_traffic_config7 = traffic_gen_object.configureVxlanVNIHeader(trf_hdl,vni_header_args,ls)
                                            if nested_vxlan_traffic_config7['status'] == 1:
                                                log.info(banner('Configuring the Ethernet Header 2- Stack 6'))
                                                ethernet2_header_args = traffic_args['EthernetHeader2']
                                                nested_vxlan_traffic_config8 = traffic_gen_object.configureEthernetHeader(trf_hdl,ethernet2_header_args)                
                                                if nested_vxlan_traffic_config8['status'] == 1:
                                                    log.info(banner('Configuring the IP Header 2- Stack 7'))
                                                    ip2_header_args = traffic_args['IPHeader2']
                                                    nested_vxlan_traffic_config8 = traffic_gen_object.configureIPv6ProtocolHeader(trf_hdl,ip2_header_args)
                
                
                
                log.info('The value of nested_vxlan_traffic_config is : {0}'.format(nested_vxlan_traffic_config8))
                ethernet_args = traffic_args['EthernetHeader1']                                   
                ns = MyLib.my_config_utils.parseEthernetHeaderArgs(log,ethernet_args)
                dmac = ns.mac_dst
                actual_receiver = testscript.parameters['configdict']['TG'][TG]['TEST-008']['traffic_config_dict']['actual_receiver'][0]
                
                dut_to_configure_static_mac = tgn_port_dut_mapping[actual_receiver]
                log.info('the value of dut_to_configure is : {0}'.format(dut_to_configure_static_mac))
                            
                for item in testbed_obj.devices.aliases:
                    log.info('The value of item is : {0}'.format(item))
                    if re.search(dut_to_configure_static_mac,item):
                        for i in testbed_obj.devices[item].interfaces.keys():
                            log.info('The value if i is : {0}'.format(i))
                            if re.search('TG',testbed_obj.devices[item].interfaces[i].alias):
                                port = i
                                log.info('The value of port is : {0}'.format(port))
                        
                
                cfg = 'mac address-table static {0} vlan 701 interface {1}'.format(dmac,port)
                node_dict['all_dut'][dut_to_configure_static_mac].configure(cfg)
                log.info(banner('Waiting for 20 seconds before collecting the stats'))
                countDownTimer(20)
                b = tgn_hdl.traffic_control(action='run', handle = trf_hdl, max_wait_timer=60)
                
                stream_dict = {}
                stream_dict.setdefault('TEST-008',{})
                stream_dict['TEST-008']['stream_id'] = nested_vxlan_traffic_config8['stream_id']
                
                res = MyLib.my_config_utils.getTrafficItemStatistics(log,tgn_hdl,stream_dict,'TEST-008')
                
                if abs(res['tx']-res['rx'] < threshold):
                    log.info('Traffic flow is as expected..The value of tx and Rx is : {0} and {1}'.format(res['tx'],res['rx']))
                else:
                    log.info('Traffic Flow is not as expected. The value of tx and Rx is : {0} and {1}'.format(res['tx'],res['rx']))
                    flag = 1 
                
                log.info('Deleting the Created Stream for this test: ')

                x1 = tgn_hdl.traffic_control(action='stop', handle = trf_hdl,max_wait_timer=60)
                
                countDownTimer(30)

                log.info('Removing the stream:')
                y = tgn_hdl.traffic_config(mode='remove',stream_id=nested_vxlan_traffic_config8['stream_id'])
                
                node_dict['all_dut'][dut_to_configure_static_mac].configure('no '+cfg)
                        
                log.info('STarting all the other streams')
                z = tgn_hdl.traffic_control(action='run',max_wait_timer=60)
                
                log.info('waiting for 30 seconds before collecting the stats:')
                countDownTimer(30)
                out = trigger_obj.checkAllStreamStats(tgn_hdl)
                
                if not out:
                    log.error(banner('Traffic has not recovered on some of the streams after starting the Original Streams.. Collecting the individual STream stats:'))
                    self.failed()
                        
                if flag:
                    log.error(banner('Nested Traffic Flow was not as expected. Hence failing'))
                    self.failed()
            else:
                log.error('The Initial Traffic Condition did not pass:')
                self.failed()                                   

class VXLANVxlanV6FUNC116(aetest.Testcase):

    """ Nested Vxlan - VPC Port To Everywhere - UUC """

    uid = 'VXLAN-L3-VxlanV6-FUNC-116'
    
    @aetest.test
    def NestedVxlanVPCPortToEveryWhereUUCV6Payload(self,log,testscript,testbed):
        
        node_dict = testscript.parameters['node_dict']
        tg_interface_hdl_dict = testscript.parameters['tg_interface_hdl_dict'] 
        traffic_stream_dict = testscript.parameters['traffic_stream_dict'] 
        port_handle_dict = testscript.parameters['port_handle_dict']
        TGList_config_file = testscript.parameters['TGList']
        configdict = testscript.parameters['configdict'] 
        tgn_config_dict = configdict['TG']
        threshold = testscript.parameters['traffic_threshold'] 
        tgn_port_dut_mapping = testscript.parameters['tgn_port_dut_mapping']
        alias_intf_mapping_dict = testscript.parameters['alias_intf_mapping']
        configured_stream = testscript.parameters['configured_stream']
        trigger_obj = testscript.parameters['trigger_obj']
        testbed_obj = testscript.parameters['testbed_obj']

        log.info(banner('The value of configured stream is : {0}'.format(configured_stream))) 
        
        res = [node_dict['all_dut'][dut].execute('show version') for dut in node_dict['all_dut'] if re.search('uut', dut)]
        
        for TG in tgn_config_dict.keys():
            tgn_hdl = testscript.parameters['testbed_obj'].devices[TG]
            out = trigger_obj.checkAllStreamStats(tgn_hdl)
            flag = 0
            if out:
                
                log.info(banner('Stopping all the Traffic:'))
                
                a = tgn_hdl.traffic_control(action='stop',max_wait_timer=60)
                
                log.info(banner('Waiting for 30 seconds before Creating the Nested Vxlan traffic : '))
                countDownTimer(30)
                
                log.info(banner('Creating Nested Vxlan Traffic:'))
                    
                source_port = testscript.parameters['configdict']['TG'][TG]['TEST-009']['traffic_config_dict']['source']
                receiver_port = testscript.parameters['configdict']['TG'][TG]['TEST-009']['traffic_config_dict']['capable_receivers']
                traffic_args=testscript.parameters['configdict']['TG'][TG]['TEST-009']['traffic_config_dict']['params']
                 
                src_port = [port_handle_dict[x] for x in source_port]
                dst_port = [port_handle_dict[x] for x in receiver_port]
                log.info('The value of src_port is : {0}'.format(src_port))
                log.info('The value of dst_port is : {0}'.format(dst_port))
                
                traffic_gen_object = MyLib.my_config_utils.IxiaRawTrafficGeneration(log,tgn_hdl,configdict,port_handle_dict)
                
                end_point_args = traffic_args['Traffic_End_points']
                log.info(banner('The value of end_point_args is : {0}'.format(end_point_args)))
                
                nested_vxlan_traffic_config = traffic_gen_object.configureTrafficEndPoints(end_point_args,emulation_src_handle=src_port, emulation_dst_handle=dst_port)
                log.info('The value of ixia_traffic_config is : {0}'.format(nested_vxlan_traffic_config))
                
                if nested_vxlan_traffic_config['status'] == 1:
                    log.info(banner('Traffic End points is configured as expected.. configuring the STream params'))
                    trf_hdl = nested_vxlan_traffic_config['traffic_item']
                    traffic_stream_args  = traffic_args['StreamParameters']
                    nested_vxlan_traffic_config1 = traffic_gen_object.configureTrafficStreamParameters(trf_hdl,traffic_stream_args)
                    if nested_vxlan_traffic_config1['status'] == 1:
                        log.info(banner('Configuring the Ethernet Header -- Stack 1 '))
                        ethernet1_header_args = traffic_args['EthernetHeader1']
                        nested_vxlan_traffic_config2 = traffic_gen_object.configureEthernetHeader(trf_hdl,ethernet1_header_args)
                        if nested_vxlan_traffic_config2['status'] == 1:
                            log.info(banner('Configuring the Vlan Header -- Stack 2 '))
                            vlan_header_args = traffic_args['VlanHeader']
                            nested_vxlan_traffic_config3 = traffic_gen_object.configureVlanHeader(trf_hdl,vlan_header_args)
                            if nested_vxlan_traffic_config3['status'] == 1:
                                log.info(banner('Configuring the inner IPv6 Header -- Stack 3'))
                                ip1_header_args = traffic_args['IPHeader1']
                                nested_vxlan_traffic_config4 = traffic_gen_object.configureIPv6ProtocolHeader(trf_hdl,ip1_header_args)
                                if nested_vxlan_traffic_config4['status'] == 1:
                                    log.info(banner('Configuring the UDP Header -- Stack 4'))
                                    udp_header_args = traffic_args['UDPHeader']
                                    nested_vxlan_traffic_config5 = traffic_gen_object.configureUDPHeader(trf_hdl,udp_header_args)
                                    if nested_vxlan_traffic_config5['status'] == 1:
                                        log.info(banner('Configuring the Inner Vxlan Header -- Stack 5'))
                                        vxlan_header_args = traffic_args['VxlanHeader']
                                        nested_vxlan_traffic_config6 = traffic_gen_object.configureVxlanHeader(trf_hdl,vxlan_header_args)
                                        ls = nested_vxlan_traffic_config6['last_stack']
                                        if nested_vxlan_traffic_config6['status'] == 1:
                                            log.info(banner('Configuring the Inner VNI header - Stack 5a'))
                                            vni_header_args = traffic_args['VNIHeader']
                                            nested_vxlan_traffic_config7 = traffic_gen_object.configureVxlanVNIHeader(trf_hdl,vni_header_args,ls)
                                            if nested_vxlan_traffic_config7['status'] == 1:
                                                log.info(banner('Configuring the Ethernet Header 2- Stack 6'))
                                                ethernet2_header_args = traffic_args['EthernetHeader2']
                                                nested_vxlan_traffic_config8 = traffic_gen_object.configureEthernetHeader(trf_hdl,ethernet2_header_args)                
                                                if nested_vxlan_traffic_config8['status'] == 1:
                                                    log.info(banner('Configuring the IP Header 2- Stack 7'))
                                                    ip2_header_args = traffic_args['IPHeader2']
                                                    nested_vxlan_traffic_config8 = traffic_gen_object.configureIPv6ProtocolHeader(trf_hdl,ip2_header_args)
                
                                
                actual_receiver = testscript.parameters['configdict']['TG'][TG]['TEST-009']['traffic_config_dict']['actual_receiver']
                log.info('The value of actual_receiver is : {0}'.format(actual_receiver))

                log.info(banner('Waiting for 20 seconds before collecting the stats'))
                countDownTimer(20)
                b = tgn_hdl.traffic_control(action='run', handle = trf_hdl, max_wait_timer=60)
                
                stream_dict = {}
                stream_dict.setdefault('TEST-009',{})
                stream_dict['TEST-009']['stream_id'] = nested_vxlan_traffic_config8['stream_id']
                
                res = MyLib.my_config_utils.getTrafficItemStatistics(log,tgn_hdl,stream_dict,'TEST-009')
                exp_trf = len(actual_receiver) * res['tx']
                log.info('The value of expected Traffic is : {0}'.format(exp_trf))
                
                if abs(exp_trf-res['rx'] < threshold):
                    log.info('Traffic flow is as expected..The value of tx and Rx is : {0} and {1}'.format(res['tx'],res['rx']))
                else:
                    log.error('Traffic Flow is not as expected. The value of tx and Rx is : {0} and {1}'.format(res['tx'],res['rx']))
                    flag = 1 
                
                log.info('Deleting the Created Stream for this test: ')

                x1 = tgn_hdl.traffic_control(action='stop', handle = trf_hdl,max_wait_timer=60)
                
                countDownTimer(30)

                log.info('Removing the stream:')
                y = tgn_hdl.traffic_config(mode='remove',stream_id=nested_vxlan_traffic_config8['stream_id'])
                        
                log.info('STarting all the other streams')
                z = tgn_hdl.traffic_control(action='run',max_wait_timer=60)
                
                log.info('waiting for 30 seconds before collecting the stats:')
                countDownTimer(30)
                out = trigger_obj.checkAllStreamStats(tgn_hdl)
                
                if not out:
                    log.error(banner('Traffic has not recovered on some of the streams after starting the Original Streams.. Collecting the individual STream stats:'))
                    self.failed()
                        
                if flag:
                    log.error(banner('Nested Traffic Flow was not as expected. Hence failing'))
                    self.failed()
            else:
                log.error('The Initial Traffic Condition did not pass:')
                self.failed()                                   

class VXLANVxlanV6FUNC117(aetest.Testcase):

    """ Nested Vxlan - VPC Port To Everywhere - BroadCast """

    uid = 'VXLAN-L3-VxlanV6-FUNC-117'
    
    @aetest.test
    def NestedVxlanVPCPortToEveryWhereBroadCastV6Payload(self,log,testscript,testbed):
        
        node_dict = testscript.parameters['node_dict']
        tg_interface_hdl_dict = testscript.parameters['tg_interface_hdl_dict'] 
        traffic_stream_dict = testscript.parameters['traffic_stream_dict'] 
        port_handle_dict = testscript.parameters['port_handle_dict']
        TGList_config_file = testscript.parameters['TGList']
        configdict = testscript.parameters['configdict'] 
        tgn_config_dict = configdict['TG']
        threshold = testscript.parameters['traffic_threshold'] 
        tgn_port_dut_mapping = testscript.parameters['tgn_port_dut_mapping']
        alias_intf_mapping_dict = testscript.parameters['alias_intf_mapping']
        configured_stream = testscript.parameters['configured_stream']
        trigger_obj = testscript.parameters['trigger_obj']
        testbed_obj = testscript.parameters['testbed_obj']

        log.info(banner('The value of configured stream is : {0}'.format(configured_stream))) 
        
        res = [node_dict['all_dut'][dut].execute('show version') for dut in node_dict['all_dut'] if re.search('uut', dut)]
        
        for TG in tgn_config_dict.keys():
            tgn_hdl = testscript.parameters['testbed_obj'].devices[TG]
            out = trigger_obj.checkAllStreamStats(tgn_hdl)
            flag = 0
            if out:
                
                log.info(banner('Stopping all the Traffic:'))
                
                a = tgn_hdl.traffic_control(action='stop',max_wait_timer=60)
                
                log.info(banner('Waiting for 30 seconds before Creating the Nested Vxlan traffic : '))
                countDownTimer(30)
                
                log.info(banner('Creating Nested Vxlan Traffic:'))
                    
                source_port = testscript.parameters['configdict']['TG'][TG]['TEST-010']['traffic_config_dict']['source']
                receiver_port = testscript.parameters['configdict']['TG'][TG]['TEST-010']['traffic_config_dict']['capable_receivers']
                traffic_args=testscript.parameters['configdict']['TG'][TG]['TEST-010']['traffic_config_dict']['params']
                 
                src_port = [port_handle_dict[x] for x in source_port]
                dst_port = [port_handle_dict[x] for x in receiver_port]
                log.info('The value of src_port is : {0}'.format(src_port))
                log.info('The value of dst_port is : {0}'.format(dst_port))
                
                traffic_gen_object = MyLib.my_config_utils.IxiaRawTrafficGeneration(log,tgn_hdl,configdict,port_handle_dict)
                
                end_point_args = traffic_args['Traffic_End_points']
                log.info(banner('The value of end_point_args is : {0}'.format(end_point_args)))
                
                nested_vxlan_traffic_config = traffic_gen_object.configureTrafficEndPoints(end_point_args,emulation_src_handle=src_port, emulation_dst_handle=dst_port)
                log.info('The value of ixia_traffic_config is : {0}'.format(nested_vxlan_traffic_config))
                
                if nested_vxlan_traffic_config['status'] == 1:
                    log.info(banner('Traffic End points is configured as expected.. configuring the STream params'))
                    trf_hdl = nested_vxlan_traffic_config['traffic_item']
                    traffic_stream_args  = traffic_args['StreamParameters']
                    nested_vxlan_traffic_config1 = traffic_gen_object.configureTrafficStreamParameters(trf_hdl,traffic_stream_args)
                    if nested_vxlan_traffic_config1['status'] == 1:
                        log.info(banner('Configuring the Ethernet Header -- Stack 1 '))
                        ethernet1_header_args = traffic_args['EthernetHeader1']
                        nested_vxlan_traffic_config2 = traffic_gen_object.configureEthernetHeader(trf_hdl,ethernet1_header_args)
                        if nested_vxlan_traffic_config2['status'] == 1:
                            log.info(banner('Configuring the Vlan Header -- Stack 2 '))
                            vlan_header_args = traffic_args['VlanHeader']
                            nested_vxlan_traffic_config3 = traffic_gen_object.configureVlanHeader(trf_hdl,vlan_header_args)
                            if nested_vxlan_traffic_config3['status'] == 1:
                                log.info(banner('Configuring the inner IPv6 Header -- Stack 3'))
                                ip1_header_args = traffic_args['IPHeader1']
                                nested_vxlan_traffic_config4 = traffic_gen_object.configureIPv6ProtocolHeader(trf_hdl,ip1_header_args)
                                if nested_vxlan_traffic_config4['status'] == 1:
                                    log.info(banner('Configuring the UDP Header -- Stack 4'))
                                    udp_header_args = traffic_args['UDPHeader']
                                    nested_vxlan_traffic_config5 = traffic_gen_object.configureUDPHeader(trf_hdl,udp_header_args)
                                    if nested_vxlan_traffic_config5['status'] == 1:
                                        log.info(banner('Configuring the Inner Vxlan Header -- Stack 5'))
                                        vxlan_header_args = traffic_args['VxlanHeader']
                                        nested_vxlan_traffic_config6 = traffic_gen_object.configureVxlanHeader(trf_hdl,vxlan_header_args)
                                        ls = nested_vxlan_traffic_config6['last_stack']
                                        if nested_vxlan_traffic_config6['status'] == 1:
                                            log.info(banner('Configuring the Inner VNI header - Stack 5a'))
                                            vni_header_args = traffic_args['VNIHeader']
                                            nested_vxlan_traffic_config7 = traffic_gen_object.configureVxlanVNIHeader(trf_hdl,vni_header_args,ls)
                                            if nested_vxlan_traffic_config7['status'] == 1:
                                                log.info(banner('Configuring the Ethernet Header 2- Stack 6'))
                                                ethernet2_header_args = traffic_args['EthernetHeader2']
                                                nested_vxlan_traffic_config8 = traffic_gen_object.configureEthernetHeader(trf_hdl,ethernet2_header_args)                
                                                if nested_vxlan_traffic_config8['status'] == 1:
                                                    log.info(banner('Configuring the IP Header 2- Stack 7'))
                                                    ip2_header_args = traffic_args['IPHeader2']
                                                    nested_vxlan_traffic_config8 = traffic_gen_object.configureIPv6ProtocolHeader(trf_hdl,ip2_header_args)
                
                                
                actual_receiver = testscript.parameters['configdict']['TG'][TG]['TEST-010']['traffic_config_dict']['actual_receiver']
                log.info('The value of actual_receiver is : {0}'.format(actual_receiver))

                log.info(banner('Waiting for 20 seconds before collecting the stats'))
                countDownTimer(20)
                b = tgn_hdl.traffic_control(action='run', handle = trf_hdl, max_wait_timer=60)
                
                stream_dict = {}
                stream_dict.setdefault('TEST-010',{})
                stream_dict['TEST-010']['stream_id'] = nested_vxlan_traffic_config8['stream_id']
                
                res = MyLib.my_config_utils.getTrafficItemStatistics(log,tgn_hdl,stream_dict,'TEST-010')
                exp_trf = len(actual_receiver) * res['tx']
                log.info('The value of expected Traffic is : {0}'.format(exp_trf))
                
                if abs(exp_trf-res['rx'] < threshold):
                    log.info('Traffic flow is as expected..The value of tx and Rx is : {0} and {1}'.format(res['tx'],res['rx']))
                else:
                    log.error('Traffic Flow is not as expected. The value of tx and Rx is : {0} and {1}'.format(res['tx'],res['rx']))
                    flag = 1 
                
                log.info('Deleting the Created Stream for this test: ')

                x1 = tgn_hdl.traffic_control(action='stop', handle = trf_hdl,max_wait_timer=60)
                
                countDownTimer(30)

                log.info('Removing the stream:')
                y = tgn_hdl.traffic_config(mode='remove',stream_id=nested_vxlan_traffic_config8['stream_id'])
                        
                log.info('STarting all the other streams')
                z = tgn_hdl.traffic_control(action='run',max_wait_timer=60)
                
                log.info('waiting for 30 seconds before collecting the stats:')
                countDownTimer(30)
                out = trigger_obj.checkAllStreamStats(tgn_hdl)
                
                if not out:
                    log.error(banner('Traffic has not recovered on some of the streams after starting the Original Streams.. Collecting the individual STream stats:'))
                    self.failed()
                        
                if flag:
                    log.error(banner('Nested Traffic Flow was not as expected. Hence failing'))
                    self.failed()
            else:
                log.error('The Initial Traffic Condition did not pass:')
                self.failed()                                   

class VXLANVxlanV6FUNC118(aetest.Testcase):

    """ Nested Vxlan - VPC Port To Everywhere - Multicast """

    uid = 'VXLAN-L3-VxlanV6-FUNC-118'
    
    @aetest.test
    def NestedVxlanVPCPortToEveryWhereMultiCastV6Payload(self,log,testscript,testbed):
        
        node_dict = testscript.parameters['node_dict']
        tg_interface_hdl_dict = testscript.parameters['tg_interface_hdl_dict'] 
        traffic_stream_dict = testscript.parameters['traffic_stream_dict'] 
        port_handle_dict = testscript.parameters['port_handle_dict']
        TGList_config_file = testscript.parameters['TGList']
        configdict = testscript.parameters['configdict'] 
        tgn_config_dict = configdict['TG']
        threshold = testscript.parameters['traffic_threshold'] 
        tgn_port_dut_mapping = testscript.parameters['tgn_port_dut_mapping']
        alias_intf_mapping_dict = testscript.parameters['alias_intf_mapping']
        configured_stream = testscript.parameters['configured_stream']
        trigger_obj = testscript.parameters['trigger_obj']
        testbed_obj = testscript.parameters['testbed_obj']

        log.info(banner('The value of configured stream is : {0}'.format(configured_stream))) 
        
        res = [node_dict['all_dut'][dut].execute('show version') for dut in node_dict['all_dut'] if re.search('uut', dut)]
        
        for TG in tgn_config_dict.keys():
            tgn_hdl = testscript.parameters['testbed_obj'].devices[TG]
            out = trigger_obj.checkAllStreamStats(tgn_hdl)
            flag = 0
            if out:
                
                log.info(banner('Stopping all the Traffic:'))
                
                a = tgn_hdl.traffic_control(action='stop',max_wait_timer=60)
                
                log.info(banner('Waiting for 30 seconds before Creating the Nested Vxlan traffic : '))
                countDownTimer(30)
                
                log.info(banner('Creating Nested Vxlan Traffic:'))
                    
                source_port = testscript.parameters['configdict']['TG'][TG]['TEST-011']['traffic_config_dict']['source']
                receiver_port = testscript.parameters['configdict']['TG'][TG]['TEST-011']['traffic_config_dict']['capable_receivers']
                traffic_args=testscript.parameters['configdict']['TG'][TG]['TEST-011']['traffic_config_dict']['params']
                 
                src_port = [port_handle_dict[x] for x in source_port]
                dst_port = [port_handle_dict[x] for x in receiver_port]
                log.info('The value of src_port is : {0}'.format(src_port))
                log.info('The value of dst_port is : {0}'.format(dst_port))
                
                traffic_gen_object = MyLib.my_config_utils.IxiaRawTrafficGeneration(log,tgn_hdl,configdict,port_handle_dict)
                
                end_point_args = traffic_args['Traffic_End_points']
                log.info(banner('The value of end_point_args is : {0}'.format(end_point_args)))
                
                nested_vxlan_traffic_config = traffic_gen_object.configureTrafficEndPoints(end_point_args,emulation_src_handle=src_port, emulation_dst_handle=dst_port)
                log.info('The value of ixia_traffic_config is : {0}'.format(nested_vxlan_traffic_config))
                
                if nested_vxlan_traffic_config['status'] == 1:
                    log.info(banner('Traffic End points is configured as expected.. configuring the STream params'))
                    trf_hdl = nested_vxlan_traffic_config['traffic_item']
                    traffic_stream_args  = traffic_args['StreamParameters']
                    nested_vxlan_traffic_config1 = traffic_gen_object.configureTrafficStreamParameters(trf_hdl,traffic_stream_args)
                    if nested_vxlan_traffic_config1['status'] == 1:
                        log.info(banner('Configuring the Ethernet Header -- Stack 1 '))
                        ethernet1_header_args = traffic_args['EthernetHeader1']
                        nested_vxlan_traffic_config2 = traffic_gen_object.configureEthernetHeader(trf_hdl,ethernet1_header_args)
                        if nested_vxlan_traffic_config2['status'] == 1:
                            log.info(banner('Configuring the Vlan Header -- Stack 2 '))
                            vlan_header_args = traffic_args['VlanHeader']
                            ns = MyLib.my_config_utils.parseVlanHeaderArgs(log,vlan_header_args)
                            log.info(banner('The value of ns is : {0}'.format(ns)))
                            igmp_vlan = ns.vlan_id
                            log.info(banner('The value of vlan is: {0}'.format(igmp_vlan)))
                            nested_vxlan_traffic_config3 = traffic_gen_object.configureVlanHeader(trf_hdl,vlan_header_args)
                            if nested_vxlan_traffic_config3['status'] == 1:
                                log.info(banner('Configuring the inner IPv6 Header -- Stack 3'))
                                ip1_header_args = traffic_args['IPHeader1']
                                nested_vxlan_traffic_config4 = traffic_gen_object.configureIPv6ProtocolHeader(trf_hdl,ip1_header_args)
                                if nested_vxlan_traffic_config4['status'] == 1:
                                    log.info(banner('Configuring the UDP Header -- Stack 4'))
                                    udp_header_args = traffic_args['UDPHeader']
                                    nested_vxlan_traffic_config5 = traffic_gen_object.configureUDPHeader(trf_hdl,udp_header_args)
                                    if nested_vxlan_traffic_config5['status'] == 1:
                                        log.info(banner('Configuring the Inner Vxlan Header -- Stack 5'))
                                        vxlan_header_args = traffic_args['VxlanHeader']
                                        nested_vxlan_traffic_config6 = traffic_gen_object.configureVxlanHeader(trf_hdl,vxlan_header_args)
                                        ls = nested_vxlan_traffic_config6['last_stack']
                                        if nested_vxlan_traffic_config6['status'] == 1:
                                            log.info(banner('Configuring the Inner VNI header - Stack 5a'))
                                            vni_header_args = traffic_args['VNIHeader']
                                            nested_vxlan_traffic_config7 = traffic_gen_object.configureVxlanVNIHeader(trf_hdl,vni_header_args,ls)
                                            if nested_vxlan_traffic_config7['status'] == 1:
                                                log.info(banner('Configuring the Ethernet Header 2- Stack 6'))
                                                ethernet2_header_args = traffic_args['EthernetHeader2']
                                                nested_vxlan_traffic_config8 = traffic_gen_object.configureEthernetHeader(trf_hdl,ethernet2_header_args)                
                                                if nested_vxlan_traffic_config8['status'] == 1:
                                                    log.info(banner('Configuring the IP Header 2- Stack 7'))
                                                    ip2_header_args = traffic_args['IPHeader2']
                                                    nested_vxlan_traffic_config8 = traffic_gen_object.configureIPv6ProtocolHeader(trf_hdl,ip2_header_args)
                
                                
                actual_receiver = testscript.parameters['configdict']['TG'][TG]['TEST-011']['traffic_config_dict']['actual_receiver']
                log.info('The value of actual_receiver is : {0}'.format(actual_receiver))
                
                for device, sw_hdl in trigger_obj.getDeviceDict('l2_switch').items(): pass
                
                cfg1 = '''vlan configuration {0}
                          no ip igmp snooping'''.format(igmp_vlan)
                
                sw_hdl.configure(cfg1) 

                log.info(banner('Waiting for 20 seconds before collecting the stats'))
                countDownTimer(20)
                b = tgn_hdl.traffic_control(action='run', handle = trf_hdl, max_wait_timer=60)
                
                stream_dict = {}
                stream_dict.setdefault('TEST-011',{})
                stream_dict['TEST-011']['stream_id'] = nested_vxlan_traffic_config8['stream_id']
                
                res = MyLib.my_config_utils.getTrafficItemStatistics(log,tgn_hdl,stream_dict,'TEST-011')
                exp_trf = len(actual_receiver) * res['tx']
                log.info('The value of expected Traffic is : {0}'.format(exp_trf))
                
                if abs(exp_trf-res['rx'] < threshold):
                    log.info('Traffic flow is as expected..The value of tx and Rx is : {0} and {1}'.format(res['tx'],res['rx']))
                else:
                    log.error('Traffic Flow is not as expected. The value of tx and Rx is : {0} and {1}'.format(res['tx'],res['rx']))
                    flag = 1 
                
                log.info('Deleting the Created Stream for this test: ')

                x1 = tgn_hdl.traffic_control(action='stop', handle = trf_hdl,max_wait_timer=60)
                
                countDownTimer(30)
                
                sw_hdl.configure('no vlan configuration {0}'.format(igmp_vlan))

                # log.info('Removing the stream:')
                # y = tgn_hdl.traffic_config(mode='remove',stream_id=nested_vxlan_traffic_config8['stream_id'])
                   
                log.info('STarting all the other streams')
                z = tgn_hdl.traffic_control(action='run',max_wait_timer=60)
                
                log.info('waiting for 30 seconds before collecting the stats:')
                countDownTimer(30)
                out = trigger_obj.checkAllStreamStats(tgn_hdl)
                
                if not out:
                    log.error(banner('Traffic has not recovered on some of the streams after starting the Original Streams.. Collecting the individual STream stats:'))
                    self.failed()
                        
                if flag:
                    log.error(banner('Nested Traffic Flow was not as expected. Hence failing'))
                    self.failed()
            else:
                log.error('The Initial Traffic Condition did not pass:')
                self.failed()     


class VXLANVxlanV6FUNC119(aetest.Testcase):

    """ Nested Vxlan - Orphan to Orphan """

    uid = 'VXLAN-L3-VxlanV6-FUNC-119'
    
    @aetest.test
    def NestedVxlanOrphanToOrphanV4Payload(self,log,testscript,testbed):
        
        node_dict = testscript.parameters['node_dict']
        tg_interface_hdl_dict = testscript.parameters['tg_interface_hdl_dict'] 
        traffic_stream_dict = testscript.parameters['traffic_stream_dict'] 
        port_handle_dict = testscript.parameters['port_handle_dict']
        TGList_config_file = testscript.parameters['TGList']
        configdict = testscript.parameters['configdict'] 
        tgn_config_dict = configdict['TG']
        threshold = testscript.parameters['traffic_threshold'] 
        tgn_port_dut_mapping = testscript.parameters['tgn_port_dut_mapping']
        alias_intf_mapping_dict = testscript.parameters['alias_intf_mapping']
        configured_stream = testscript.parameters['configured_stream']
        trigger_obj = testscript.parameters['trigger_obj']
        testbed_obj = testscript.parameters['testbed_obj']

        log.info(banner('The value of configured stream is : {0}'.format(configured_stream))) 
        
        res = [node_dict['all_dut'][dut].execute('show version') for dut in node_dict['all_dut'] if re.search('uut', dut)]
        
        for TG in tgn_config_dict.keys():
            tgn_hdl = testscript.parameters['testbed_obj'].devices[TG]
            out = trigger_obj.checkAllStreamStats(tgn_hdl)
            flag = 0
            if out:
                
                log.info(banner('Stopping all the Traffic:'))
                
                a = tgn_hdl.traffic_control(action='stop',max_wait_timer=60)
                
                log.info(banner('Waiting for 30 seconds before Creating the Nested Vxlan traffic : '))
                countDownTimer(30)
                
                log.info(banner('Creating Nested Vxlan Traffic:'))
                    
                source_port = testscript.parameters['configdict']['TG'][TG]['TEST-012']['traffic_config_dict']['source']
                receiver_port = testscript.parameters['configdict']['TG'][TG]['TEST-012']['traffic_config_dict']['capable_receivers']
                traffic_args=testscript.parameters['configdict']['TG'][TG]['TEST-012']['traffic_config_dict']['params']
                 
                src_port = [port_handle_dict[x] for x in source_port]
                dst_port = [port_handle_dict[x] for x in receiver_port]
                log.info('The value of src_port is : {0}'.format(src_port))
                log.info('The value of dst_port is : {0}'.format(dst_port))
                
                traffic_gen_object = MyLib.my_config_utils.IxiaRawTrafficGeneration(log,tgn_hdl,configdict,port_handle_dict)
                
                end_point_args = traffic_args['Traffic_End_points']
                log.info(banner('The value of end_point_args is : {0}'.format(end_point_args)))
                
                nested_vxlan_traffic_config = traffic_gen_object.configureTrafficEndPoints(end_point_args,emulation_src_handle=src_port, emulation_dst_handle=dst_port)
                log.info('The value of ixia_traffic_config is : {0}'.format(nested_vxlan_traffic_config))
                
                if nested_vxlan_traffic_config['status'] == 1:
                    log.info(banner('Traffic End points is configured as expected.. configuring the STream params'))
                    trf_hdl = nested_vxlan_traffic_config['traffic_item']
                    traffic_stream_args  = traffic_args['StreamParameters']
                    nested_vxlan_traffic_config1 = traffic_gen_object.configureTrafficStreamParameters(trf_hdl,traffic_stream_args)
                    if nested_vxlan_traffic_config1['status'] == 1:
                        log.info(banner('Configuring the Ethernet Header -- Stack 1 '))
                        ethernet1_header_args = traffic_args['EthernetHeader1']
                        nested_vxlan_traffic_config2 = traffic_gen_object.configureEthernetHeader(trf_hdl,ethernet1_header_args)
                        if nested_vxlan_traffic_config2['status'] == 1:
                            log.info(banner('Configuring the Vlan Header -- Stack 2 '))
                            vlan_header_args = traffic_args['VlanHeader']
                            nested_vxlan_traffic_config3 = traffic_gen_object.configureVlanHeader(trf_hdl,vlan_header_args)
                            if nested_vxlan_traffic_config3['status'] == 1:
                                log.info(banner('Configuring the inner IPv6 Header -- Stack 3'))
                                ip1_header_args = traffic_args['IPHeader1']
                                nested_vxlan_traffic_config4 = traffic_gen_object.configureIPv6ProtocolHeader(trf_hdl,ip1_header_args)
                                if nested_vxlan_traffic_config4['status'] == 1:
                                    log.info(banner('Configuring the UDP Header -- Stack 4'))
                                    udp_header_args = traffic_args['UDPHeader']
                                    nested_vxlan_traffic_config5 = traffic_gen_object.configureUDPHeader(trf_hdl,udp_header_args)
                                    if nested_vxlan_traffic_config5['status'] == 1:
                                        log.info(banner('Configuring the Inner Vxlan Header -- Stack 5'))
                                        vxlan_header_args = traffic_args['VxlanHeader']
                                        nested_vxlan_traffic_config6 = traffic_gen_object.configureVxlanHeader(trf_hdl,vxlan_header_args)
                                        ls = nested_vxlan_traffic_config6['last_stack']
                                        if nested_vxlan_traffic_config6['status'] == 1:
                                            log.info(banner('Configuring the Inner VNI header - Stack 5a'))
                                            vni_header_args = traffic_args['VNIHeader']
                                            nested_vxlan_traffic_config7 = traffic_gen_object.configureVxlanVNIHeader(trf_hdl,vni_header_args,ls)
                                            if nested_vxlan_traffic_config7['status'] == 1:
                                                log.info(banner('Configuring the Ethernet Header 2- Stack 6'))
                                                ethernet2_header_args = traffic_args['EthernetHeader2']
                                                nested_vxlan_traffic_config8 = traffic_gen_object.configureEthernetHeader(trf_hdl,ethernet2_header_args)                
                                                if nested_vxlan_traffic_config8['status'] == 1:
                                                    log.info(banner('Configuring the IP Header 2- Stack 7'))
                                                    ip2_header_args = traffic_args['IPHeader2']
                                                    nested_vxlan_traffic_config8 = traffic_gen_object.configureIPv4ProtocolHeader(trf_hdl,ip2_header_args)
                
                
                
                log.info('The value of nested_vxlan_traffic_config is : {0}'.format(nested_vxlan_traffic_config8))
                ethernet_args = traffic_args['EthernetHeader1']                                   
                ns = MyLib.my_config_utils.parseEthernetHeaderArgs(log,ethernet_args)
                dmac = ns.mac_dst
                actual_receiver = testscript.parameters['configdict']['TG'][TG]['TEST-012']['traffic_config_dict']['actual_receiver'][0]
                
                dut_to_configure_static_mac = tgn_port_dut_mapping[actual_receiver]
                log.info('the value of dut_to_configure is : {0}'.format(dut_to_configure_static_mac))
                            
                for item in testbed_obj.devices.aliases:
                    log.info('The value of item is : {0}'.format(item))
                    if re.search(dut_to_configure_static_mac,item):
                        for i in testbed_obj.devices[item].interfaces.keys():
                            log.info('The value if i is : {0}'.format(i))
                            if re.search('TG',testbed_obj.devices[item].interfaces[i].alias):
                                port = i
                                log.info('The value of port is : {0}'.format(port))
                        
                
                cfg = 'mac address-table static {0} vlan 701 interface {1}'.format(dmac,port)
                node_dict['all_dut'][dut_to_configure_static_mac].configure(cfg)
                log.info(banner('Waiting for 20 seconds before collecting the stats'))
                countDownTimer(20)
                b = tgn_hdl.traffic_control(action='run', handle = trf_hdl, max_wait_timer=60)
                
                stream_dict = {}
                stream_dict.setdefault('TEST-012',{})
                stream_dict['TEST-012']['stream_id'] = nested_vxlan_traffic_config8['stream_id']
                
                res = MyLib.my_config_utils.getTrafficItemStatistics(log,tgn_hdl,stream_dict,'TEST-012')
                
                if abs(res['tx']-res['rx'] < threshold):
                    log.info('Traffic flow is as expected..The value of tx and Rx is : {0} and {1}'.format(res['tx'],res['rx']))
                else:
                    log.info('Traffic Flow is not as expected. The value of tx and Rx is : {0} and {1}'.format(res['tx'],res['rx']))
                    flag = 1 
                
                log.info('Deleting the Created Stream for this test: ')

                x1 = tgn_hdl.traffic_control(action='stop', handle = trf_hdl,max_wait_timer=60)
                
                countDownTimer(30)

                log.info('Removing the stream:')
                y = tgn_hdl.traffic_config(mode='remove',stream_id=nested_vxlan_traffic_config8['stream_id'])
                
                node_dict['all_dut'][dut_to_configure_static_mac].configure('no '+cfg)
                        
                log.info('STarting all the other streams')
                z = tgn_hdl.traffic_control(action='run',max_wait_timer=60)
                
                log.info('waiting for 30 seconds before collecting the stats:')
                countDownTimer(30)
                out = trigger_obj.checkAllStreamStats(tgn_hdl)
                
                if not out:
                    log.error(banner('Traffic has not recovered on some of the streams after starting the Original Streams.. Collecting the individual STream stats:'))
                    self.failed()
                        
                if flag:
                    log.error(banner('Nested Traffic Flow was not as expected. Hence failing'))
                    self.failed()
            else:
                log.error('The Initial Traffic Condition did not pass:')
                self.failed()                                   

class VXLANVxlanV6FUNC120(aetest.Testcase):

    """ Nested Vxlan - Orphan to VPC Port """

    uid = 'VXLAN-L3-VxlanV6-FUNC-120'
    
    @aetest.test
    def NestedVxlanOrphanToVPCPortV4Payload(self,log,testscript,testbed):
        
        node_dict = testscript.parameters['node_dict']
        tg_interface_hdl_dict = testscript.parameters['tg_interface_hdl_dict'] 
        traffic_stream_dict = testscript.parameters['traffic_stream_dict'] 
        port_handle_dict = testscript.parameters['port_handle_dict']
        TGList_config_file = testscript.parameters['TGList']
        configdict = testscript.parameters['configdict'] 
        tgn_config_dict = configdict['TG']
        threshold = testscript.parameters['traffic_threshold'] 
        tgn_port_dut_mapping = testscript.parameters['tgn_port_dut_mapping']
        alias_intf_mapping_dict = testscript.parameters['alias_intf_mapping']
        configured_stream = testscript.parameters['configured_stream']
        trigger_obj = testscript.parameters['trigger_obj']
        testbed_obj = testscript.parameters['testbed_obj']

        log.info(banner('The value of configured stream is : {0}'.format(configured_stream))) 
        
        res = [node_dict['all_dut'][dut].execute('show version') for dut in node_dict['all_dut'] if re.search('uut', dut)]
        
        for TG in tgn_config_dict.keys():
            tgn_hdl = testscript.parameters['testbed_obj'].devices[TG]
            out = trigger_obj.checkAllStreamStats(tgn_hdl)
            flag = 0
            if out:
                
                log.info(banner('Stopping all the Traffic:'))
                
                a = tgn_hdl.traffic_control(action='stop',max_wait_timer=60)
                
                log.info(banner('Waiting for 30 seconds before Creating the Nested Vxlan traffic : '))
                countDownTimer(30)
                
                log.info(banner('Creating Nested Vxlan Traffic:'))
                    
                source_port = testscript.parameters['configdict']['TG'][TG]['TEST-013']['traffic_config_dict']['source']
                receiver_port = testscript.parameters['configdict']['TG'][TG]['TEST-013']['traffic_config_dict']['capable_receivers']
                traffic_args=testscript.parameters['configdict']['TG'][TG]['TEST-013']['traffic_config_dict']['params']
                 
                src_port = [port_handle_dict[x] for x in source_port]
                dst_port = [port_handle_dict[x] for x in receiver_port]
                log.info('The value of src_port is : {0}'.format(src_port))
                log.info('The value of dst_port is : {0}'.format(dst_port))
                
                traffic_gen_object = MyLib.my_config_utils.IxiaRawTrafficGeneration(log,tgn_hdl,configdict,port_handle_dict)
                
                end_point_args = traffic_args['Traffic_End_points']
                log.info(banner('The value of end_point_args is : {0}'.format(end_point_args)))
                
                nested_vxlan_traffic_config = traffic_gen_object.configureTrafficEndPoints(end_point_args,emulation_src_handle=src_port, emulation_dst_handle=dst_port)
                log.info('The value of ixia_traffic_config is : {0}'.format(nested_vxlan_traffic_config))
                
                if nested_vxlan_traffic_config['status'] == 1:
                    log.info(banner('Traffic End points is configured as expected.. configuring the STream params'))
                    trf_hdl = nested_vxlan_traffic_config['traffic_item']
                    traffic_stream_args  = traffic_args['StreamParameters']
                    nested_vxlan_traffic_config1 = traffic_gen_object.configureTrafficStreamParameters(trf_hdl,traffic_stream_args)
                    if nested_vxlan_traffic_config1['status'] == 1:
                        log.info(banner('Configuring the Ethernet Header -- Stack 1 '))
                        ethernet1_header_args = traffic_args['EthernetHeader1']
                        nested_vxlan_traffic_config2 = traffic_gen_object.configureEthernetHeader(trf_hdl,ethernet1_header_args)
                        if nested_vxlan_traffic_config2['status'] == 1:
                            log.info(banner('Configuring the Vlan Header -- Stack 2 '))
                            vlan_header_args = traffic_args['VlanHeader']
                            nested_vxlan_traffic_config3 = traffic_gen_object.configureVlanHeader(trf_hdl,vlan_header_args)
                            if nested_vxlan_traffic_config3['status'] == 1:
                                log.info(banner('Configuring the inner IPv6 Header -- Stack 3'))
                                ip1_header_args = traffic_args['IPHeader1']
                                nested_vxlan_traffic_config4 = traffic_gen_object.configureIPv6ProtocolHeader(trf_hdl,ip1_header_args)
                                if nested_vxlan_traffic_config4['status'] == 1:
                                    log.info(banner('Configuring the UDP Header -- Stack 4'))
                                    udp_header_args = traffic_args['UDPHeader']
                                    nested_vxlan_traffic_config5 = traffic_gen_object.configureUDPHeader(trf_hdl,udp_header_args)
                                    if nested_vxlan_traffic_config5['status'] == 1:
                                        log.info(banner('Configuring the Inner Vxlan Header -- Stack 5'))
                                        vxlan_header_args = traffic_args['VxlanHeader']
                                        nested_vxlan_traffic_config6 = traffic_gen_object.configureVxlanHeader(trf_hdl,vxlan_header_args)
                                        ls = nested_vxlan_traffic_config6['last_stack']
                                        if nested_vxlan_traffic_config6['status'] == 1:
                                            log.info(banner('Configuring the Inner VNI header - Stack 5a'))
                                            vni_header_args = traffic_args['VNIHeader']
                                            nested_vxlan_traffic_config7 = traffic_gen_object.configureVxlanVNIHeader(trf_hdl,vni_header_args,ls)
                                            if nested_vxlan_traffic_config7['status'] == 1:
                                                log.info(banner('Configuring the Ethernet Header 2- Stack 6'))
                                                ethernet2_header_args = traffic_args['EthernetHeader2']
                                                nested_vxlan_traffic_config8 = traffic_gen_object.configureEthernetHeader(trf_hdl,ethernet2_header_args)                
                                                if nested_vxlan_traffic_config8['status'] == 1:
                                                    log.info(banner('Configuring the IP Header 2- Stack 7'))
                                                    ip2_header_args = traffic_args['IPHeader2']
                                                    nested_vxlan_traffic_config8 = traffic_gen_object.configureIPv4ProtocolHeader(trf_hdl,ip2_header_args)
                
                
                
                log.info('The value of nested_vxlan_traffic_config is : {0}'.format(nested_vxlan_traffic_config8))
                ethernet_args = traffic_args['EthernetHeader1']                                   
                ns = MyLib.my_config_utils.parseEthernetHeaderArgs(log,ethernet_args)
                dmac = ns.mac_dst
                actual_receiver = testscript.parameters['configdict']['TG'][TG]['TEST-013']['traffic_config_dict']['actual_receiver'][0]
                
                dut_to_configure_static_mac = tgn_port_dut_mapping[actual_receiver]
                log.info('the value of dut_to_configure is : {0}'.format(dut_to_configure_static_mac))
                            
                for item in testbed_obj.devices.aliases:
                    log.info('The value of item is : {0}'.format(item))
                    if re.search(dut_to_configure_static_mac,item):
                        for i in testbed_obj.devices[item].interfaces.keys():
                            log.info('The value if i is : {0}'.format(i))
                            if re.search('TG',testbed_obj.devices[item].interfaces[i].alias):
                                port = i
                                log.info('The value of port is : {0}'.format(port))
                        
                
                cfg = 'mac address-table static {0} vlan 701 interface {1}'.format(dmac,port)
                node_dict['all_dut'][dut_to_configure_static_mac].configure(cfg)
                log.info(banner('Waiting for 20 seconds before collecting the stats'))
                countDownTimer(20)
                b = tgn_hdl.traffic_control(action='run', handle = trf_hdl, max_wait_timer=60)
                
                stream_dict = {}
                stream_dict.setdefault('TEST-013',{})
                stream_dict['TEST-013']['stream_id'] = nested_vxlan_traffic_config8['stream_id']
                
                res = MyLib.my_config_utils.getTrafficItemStatistics(log,tgn_hdl,stream_dict,'TEST-013')
                
                if abs(res['tx']-res['rx'] < threshold):
                    log.info('Traffic flow is as expected..The value of tx and Rx is : {0} and {1}'.format(res['tx'],res['rx']))
                else:
                    log.error('Traffic Flow is not as expected. The value of tx and Rx is : {0} and {1}'.format(res['tx'],res['rx']))
                    flag = 1 
                
                log.info('Deleting the Created Stream for this test: ')

                x1 = tgn_hdl.traffic_control(action='stop', handle = trf_hdl,max_wait_timer=60)
                
                countDownTimer(30)

                log.info('Removing the stream:')
                y = tgn_hdl.traffic_config(mode='remove',stream_id=nested_vxlan_traffic_config8['stream_id'])
                
                node_dict['all_dut'][dut_to_configure_static_mac].configure('no '+cfg)
                        
                log.info('STarting all the other streams')
                z = tgn_hdl.traffic_control(action='run',max_wait_timer=60)
                
                log.info('waiting for 30 seconds before collecting the stats:')
                countDownTimer(30)
                out = trigger_obj.checkAllStreamStats(tgn_hdl)
                
                if not out:
                    log.error(banner('Traffic has not recovered on some of the streams after starting the Original Streams.. Collecting the individual STream stats:'))
                    self.failed()
                        
                if flag:
                    log.error(banner('Nested Traffic Flow was not as expected. Hence failing'))
                    self.failed()
            else:
                log.error('The Initial Traffic Condition did not pass:')
                self.failed()                                   

class VXLANVxlanV6FUNC121(aetest.Testcase):

    """ Nested Vxlan - Orphan to Remote VTEP """

    uid = 'VXLAN-L3-VxlanV6-FUNC-121'
    
    @aetest.test
    def NestedVxlanOrphanToremoteVTEPV4Payload(self,log,testscript,testbed):
        
        node_dict = testscript.parameters['node_dict']
        tg_interface_hdl_dict = testscript.parameters['tg_interface_hdl_dict'] 
        traffic_stream_dict = testscript.parameters['traffic_stream_dict'] 
        port_handle_dict = testscript.parameters['port_handle_dict']
        TGList_config_file = testscript.parameters['TGList']
        configdict = testscript.parameters['configdict'] 
        tgn_config_dict = configdict['TG']
        threshold = testscript.parameters['traffic_threshold'] 
        tgn_port_dut_mapping = testscript.parameters['tgn_port_dut_mapping']
        alias_intf_mapping_dict = testscript.parameters['alias_intf_mapping']
        configured_stream = testscript.parameters['configured_stream']
        trigger_obj = testscript.parameters['trigger_obj']
        testbed_obj = testscript.parameters['testbed_obj']

        log.info(banner('The value of configured stream is : {0}'.format(configured_stream))) 
        
        res = [node_dict['all_dut'][dut].execute('show version') for dut in node_dict['all_dut'] if re.search('uut', dut)]
        
        for TG in tgn_config_dict.keys():
            tgn_hdl = testscript.parameters['testbed_obj'].devices[TG]
            out = trigger_obj.checkAllStreamStats(tgn_hdl)
            flag = 0
            if out:
                
                log.info(banner('Stopping all the Traffic:'))
                
                a = tgn_hdl.traffic_control(action='stop',max_wait_timer=60)
                
                log.info(banner('Waiting for 30 seconds before Creating the Nested Vxlan traffic : '))
                countDownTimer(30)
                
                log.info(banner('Creating Nested Vxlan Traffic:'))
                    
                source_port = testscript.parameters['configdict']['TG'][TG]['TEST-014']['traffic_config_dict']['source']
                receiver_port = testscript.parameters['configdict']['TG'][TG]['TEST-014']['traffic_config_dict']['capable_receivers']
                traffic_args=testscript.parameters['configdict']['TG'][TG]['TEST-014']['traffic_config_dict']['params']
                 
                src_port = [port_handle_dict[x] for x in source_port]
                dst_port = [port_handle_dict[x] for x in receiver_port]
                log.info('The value of src_port is : {0}'.format(src_port))
                log.info('The value of dst_port is : {0}'.format(dst_port))
                
                traffic_gen_object = MyLib.my_config_utils.IxiaRawTrafficGeneration(log,tgn_hdl,configdict,port_handle_dict)
                
                end_point_args = traffic_args['Traffic_End_points']
                log.info(banner('The value of end_point_args is : {0}'.format(end_point_args)))
                
                nested_vxlan_traffic_config = traffic_gen_object.configureTrafficEndPoints(end_point_args,emulation_src_handle=src_port, emulation_dst_handle=dst_port)
                log.info('The value of ixia_traffic_config is : {0}'.format(nested_vxlan_traffic_config))
                
                if nested_vxlan_traffic_config['status'] == 1:
                    log.info(banner('Traffic End points is configured as expected.. configuring the STream params'))
                    trf_hdl = nested_vxlan_traffic_config['traffic_item']
                    traffic_stream_args  = traffic_args['StreamParameters']
                    nested_vxlan_traffic_config1 = traffic_gen_object.configureTrafficStreamParameters(trf_hdl,traffic_stream_args)
                    if nested_vxlan_traffic_config1['status'] == 1:
                        log.info(banner('Configuring the Ethernet Header -- Stack 1 '))
                        ethernet1_header_args = traffic_args['EthernetHeader1']
                        nested_vxlan_traffic_config2 = traffic_gen_object.configureEthernetHeader(trf_hdl,ethernet1_header_args)
                        if nested_vxlan_traffic_config2['status'] == 1:
                            log.info(banner('Configuring the Vlan Header -- Stack 2 '))
                            vlan_header_args = traffic_args['VlanHeader']
                            nested_vxlan_traffic_config3 = traffic_gen_object.configureVlanHeader(trf_hdl,vlan_header_args)
                            if nested_vxlan_traffic_config3['status'] == 1:
                                log.info(banner('Configuring the inner IPv6 Header -- Stack 3'))
                                ip1_header_args = traffic_args['IPHeader1']
                                nested_vxlan_traffic_config4 = traffic_gen_object.configureIPv6ProtocolHeader(trf_hdl,ip1_header_args)
                                if nested_vxlan_traffic_config4['status'] == 1:
                                    log.info(banner('Configuring the UDP Header -- Stack 4'))
                                    udp_header_args = traffic_args['UDPHeader']
                                    nested_vxlan_traffic_config5 = traffic_gen_object.configureUDPHeader(trf_hdl,udp_header_args)
                                    if nested_vxlan_traffic_config5['status'] == 1:
                                        log.info(banner('Configuring the Inner Vxlan Header -- Stack 5'))
                                        vxlan_header_args = traffic_args['VxlanHeader']
                                        nested_vxlan_traffic_config6 = traffic_gen_object.configureVxlanHeader(trf_hdl,vxlan_header_args)
                                        ls = nested_vxlan_traffic_config6['last_stack']
                                        if nested_vxlan_traffic_config6['status'] == 1:
                                            log.info(banner('Configuring the Inner VNI header - Stack 5a'))
                                            vni_header_args = traffic_args['VNIHeader']
                                            nested_vxlan_traffic_config7 = traffic_gen_object.configureVxlanVNIHeader(trf_hdl,vni_header_args,ls)
                                            if nested_vxlan_traffic_config7['status'] == 1:
                                                log.info(banner('Configuring the Ethernet Header 2- Stack 6'))
                                                ethernet2_header_args = traffic_args['EthernetHeader2']
                                                nested_vxlan_traffic_config8 = traffic_gen_object.configureEthernetHeader(trf_hdl,ethernet2_header_args)                
                                                if nested_vxlan_traffic_config8['status'] == 1:
                                                    log.info(banner('Configuring the IP Header 2- Stack 7'))
                                                    ip2_header_args = traffic_args['IPHeader2']
                                                    nested_vxlan_traffic_config8 = traffic_gen_object.configureIPv4ProtocolHeader(trf_hdl,ip2_header_args)
                
                
                
                log.info('The value of nested_vxlan_traffic_config is : {0}'.format(nested_vxlan_traffic_config8))
                ethernet_args = traffic_args['EthernetHeader1']                                   
                ns = MyLib.my_config_utils.parseEthernetHeaderArgs(log,ethernet_args)
                dmac = ns.mac_dst
                actual_receiver = testscript.parameters['configdict']['TG'][TG]['TEST-014']['traffic_config_dict']['actual_receiver'][0]
                
                dut_to_configure_static_mac = tgn_port_dut_mapping[actual_receiver]
                log.info('the value of dut_to_configure is : {0}'.format(dut_to_configure_static_mac))
                            
                for item in testbed_obj.devices.aliases:
                    log.info('The value of item is : {0}'.format(item))
                    if re.search(dut_to_configure_static_mac,item):
                        for i in testbed_obj.devices[item].interfaces.keys():
                            log.info('The value if i is : {0}'.format(i))
                            if re.search('TG',testbed_obj.devices[item].interfaces[i].alias):
                                port = i
                                log.info('The value of port is : {0}'.format(port))
                        
                
                cfg = 'mac address-table static {0} vlan 701 interface {1}'.format(dmac,port)
                node_dict['all_dut'][dut_to_configure_static_mac].configure(cfg)
                log.info(banner('Waiting for 20 seconds before collecting the stats'))
                countDownTimer(20)
                b = tgn_hdl.traffic_control(action='run', handle = trf_hdl, max_wait_timer=60)
                
                stream_dict = {}
                stream_dict.setdefault('TEST-014',{})
                stream_dict['TEST-014']['stream_id'] = nested_vxlan_traffic_config8['stream_id']
                
                res = MyLib.my_config_utils.getTrafficItemStatistics(log,tgn_hdl,stream_dict,'TEST-014')
                
                if abs(res['tx']-res['rx'] < threshold):
                    log.info('Traffic flow is as expected..The value of tx and Rx is : {0} and {1}'.format(res['tx'],res['rx']))
                else:
                    log.info('Traffic Flow is not as expected. The value of tx and Rx is : {0} and {1}'.format(res['tx'],res['rx']))
                    flag = 1 
                
                log.info('Deleting the Created Stream for this test: ')

                x1 = tgn_hdl.traffic_control(action='stop', handle = trf_hdl,max_wait_timer=60)
                
                countDownTimer(30)

                log.info('Removing the stream:')
                y = tgn_hdl.traffic_config(mode='remove',stream_id=nested_vxlan_traffic_config8['stream_id'])
                
                node_dict['all_dut'][dut_to_configure_static_mac].configure('no '+cfg)
                        
                log.info('STarting all the other streams')
                z = tgn_hdl.traffic_control(action='run',max_wait_timer=60)
                
                log.info('waiting for 30 seconds before collecting the stats:')
                countDownTimer(30)
                out = trigger_obj.checkAllStreamStats(tgn_hdl)
                
                if not out:
                    log.error(banner('Traffic has not recovered on some of the streams after starting the Original Streams.. Collecting the individual STream stats:'))
                    self.failed()
                        
                if flag:
                    log.error(banner('Nested Traffic Flow was not as expected. Hence failing'))
                    self.failed()
            else:
                log.error('The Initial Traffic Condition did not pass:')
                self.failed()                                   

class VXLANVxlanV6FUNC122(aetest.Testcase):

    """ Nested Vxlan - VPC Port to Remote VTEP """

    uid = 'VXLAN-L3-VxlanV6-FUNC-122'
    
    @aetest.test
    def NestedVxlanVPCPortToRemoteVTEPV4Payload(self,log,testscript,testbed):
        
        node_dict = testscript.parameters['node_dict']
        tg_interface_hdl_dict = testscript.parameters['tg_interface_hdl_dict'] 
        traffic_stream_dict = testscript.parameters['traffic_stream_dict'] 
        port_handle_dict = testscript.parameters['port_handle_dict']
        TGList_config_file = testscript.parameters['TGList']
        configdict = testscript.parameters['configdict'] 
        tgn_config_dict = configdict['TG']
        threshold = testscript.parameters['traffic_threshold'] 
        tgn_port_dut_mapping = testscript.parameters['tgn_port_dut_mapping']
        alias_intf_mapping_dict = testscript.parameters['alias_intf_mapping']
        configured_stream = testscript.parameters['configured_stream']
        trigger_obj = testscript.parameters['trigger_obj']
        testbed_obj = testscript.parameters['testbed_obj']

        log.info(banner('The value of configured stream is : {0}'.format(configured_stream))) 
        
        res = [node_dict['all_dut'][dut].execute('show version') for dut in node_dict['all_dut'] if re.search('uut', dut)]
        
        for TG in tgn_config_dict.keys():
            tgn_hdl = testscript.parameters['testbed_obj'].devices[TG]
            out = trigger_obj.checkAllStreamStats(tgn_hdl)
            flag = 0
            if out:
                
                log.info(banner('Stopping all the Traffic:'))
                
                a = tgn_hdl.traffic_control(action='stop',max_wait_timer=60)
                
                log.info(banner('Waiting for 30 seconds before Creating the Nested Vxlan traffic : '))
                countDownTimer(30)
                
                log.info(banner('Creating Nested Vxlan Traffic:'))
                    
                source_port = testscript.parameters['configdict']['TG'][TG]['TEST-015']['traffic_config_dict']['source']
                receiver_port = testscript.parameters['configdict']['TG'][TG]['TEST-015']['traffic_config_dict']['capable_receivers']
                traffic_args=testscript.parameters['configdict']['TG'][TG]['TEST-015']['traffic_config_dict']['params']
                 
                src_port = [port_handle_dict[x] for x in source_port]
                dst_port = [port_handle_dict[x] for x in receiver_port]
                log.info('The value of src_port is : {0}'.format(src_port))
                log.info('The value of dst_port is : {0}'.format(dst_port))
                
                traffic_gen_object = MyLib.my_config_utils.IxiaRawTrafficGeneration(log,tgn_hdl,configdict,port_handle_dict)
                
                end_point_args = traffic_args['Traffic_End_points']
                log.info(banner('The value of end_point_args is : {0}'.format(end_point_args)))
                
                nested_vxlan_traffic_config = traffic_gen_object.configureTrafficEndPoints(end_point_args,emulation_src_handle=src_port, emulation_dst_handle=dst_port)
                log.info('The value of ixia_traffic_config is : {0}'.format(nested_vxlan_traffic_config))
                
                if nested_vxlan_traffic_config['status'] == 1:
                    log.info(banner('Traffic End points is configured as expected.. configuring the STream params'))
                    trf_hdl = nested_vxlan_traffic_config['traffic_item']
                    traffic_stream_args  = traffic_args['StreamParameters']
                    nested_vxlan_traffic_config1 = traffic_gen_object.configureTrafficStreamParameters(trf_hdl,traffic_stream_args)
                    if nested_vxlan_traffic_config1['status'] == 1:
                        log.info(banner('Configuring the Ethernet Header -- Stack 1 '))
                        ethernet1_header_args = traffic_args['EthernetHeader1']
                        nested_vxlan_traffic_config2 = traffic_gen_object.configureEthernetHeader(trf_hdl,ethernet1_header_args)
                        if nested_vxlan_traffic_config2['status'] == 1:
                            log.info(banner('Configuring the Vlan Header -- Stack 2 '))
                            vlan_header_args = traffic_args['VlanHeader']
                            nested_vxlan_traffic_config3 = traffic_gen_object.configureVlanHeader(trf_hdl,vlan_header_args)
                            if nested_vxlan_traffic_config3['status'] == 1:
                                log.info(banner('Configuring the inner IPv6 Header -- Stack 3'))
                                ip1_header_args = traffic_args['IPHeader1']
                                nested_vxlan_traffic_config4 = traffic_gen_object.configureIPv6ProtocolHeader(trf_hdl,ip1_header_args)
                                if nested_vxlan_traffic_config4['status'] == 1:
                                    log.info(banner('Configuring the UDP Header -- Stack 4'))
                                    udp_header_args = traffic_args['UDPHeader']
                                    nested_vxlan_traffic_config5 = traffic_gen_object.configureUDPHeader(trf_hdl,udp_header_args)
                                    if nested_vxlan_traffic_config5['status'] == 1:
                                        log.info(banner('Configuring the Inner Vxlan Header -- Stack 5'))
                                        vxlan_header_args = traffic_args['VxlanHeader']
                                        nested_vxlan_traffic_config6 = traffic_gen_object.configureVxlanHeader(trf_hdl,vxlan_header_args)
                                        ls = nested_vxlan_traffic_config6['last_stack']
                                        if nested_vxlan_traffic_config6['status'] == 1:
                                            log.info(banner('Configuring the Inner VNI header - Stack 5a'))
                                            vni_header_args = traffic_args['VNIHeader']
                                            nested_vxlan_traffic_config7 = traffic_gen_object.configureVxlanVNIHeader(trf_hdl,vni_header_args,ls)
                                            if nested_vxlan_traffic_config7['status'] == 1:
                                                log.info(banner('Configuring the Ethernet Header 2- Stack 6'))
                                                ethernet2_header_args = traffic_args['EthernetHeader2']
                                                nested_vxlan_traffic_config8 = traffic_gen_object.configureEthernetHeader(trf_hdl,ethernet2_header_args)                
                                                if nested_vxlan_traffic_config8['status'] == 1:
                                                    log.info(banner('Configuring the IP Header 2- Stack 7'))
                                                    ip2_header_args = traffic_args['IPHeader2']
                                                    nested_vxlan_traffic_config8 = traffic_gen_object.configureIPv4ProtocolHeader(trf_hdl,ip2_header_args)
                
                
                
                log.info('The value of nested_vxlan_traffic_config is : {0}'.format(nested_vxlan_traffic_config8))
                ethernet_args = traffic_args['EthernetHeader1']                                   
                ns = MyLib.my_config_utils.parseEthernetHeaderArgs(log,ethernet_args)
                dmac = ns.mac_dst
                actual_receiver = testscript.parameters['configdict']['TG'][TG]['TEST-015']['traffic_config_dict']['actual_receiver'][0]
                
                dut_to_configure_static_mac = tgn_port_dut_mapping[actual_receiver]
                log.info('the value of dut_to_configure is : {0}'.format(dut_to_configure_static_mac))
                            
                for item in testbed_obj.devices.aliases:
                    log.info('The value of item is : {0}'.format(item))
                    if re.search(dut_to_configure_static_mac,item):
                        for i in testbed_obj.devices[item].interfaces.keys():
                            log.info('The value if i is : {0}'.format(i))
                            if re.search('TG',testbed_obj.devices[item].interfaces[i].alias):
                                port = i
                                log.info('The value of port is : {0}'.format(port))
                        
                
                cfg = 'mac address-table static {0} vlan 701 interface {1}'.format(dmac,port)
                node_dict['all_dut'][dut_to_configure_static_mac].configure(cfg)
                log.info(banner('Waiting for 20 seconds before collecting the stats'))
                countDownTimer(20)
                b = tgn_hdl.traffic_control(action='run', handle = trf_hdl, max_wait_timer=60)
                
                stream_dict = {}
                stream_dict.setdefault('TEST-015',{})
                stream_dict['TEST-015']['stream_id'] = nested_vxlan_traffic_config8['stream_id']
                
                res = MyLib.my_config_utils.getTrafficItemStatistics(log,tgn_hdl,stream_dict,'TEST-015')
                
                if abs(res['tx']-res['rx'] < threshold):
                    log.info('Traffic flow is as expected..The value of tx and Rx is : {0} and {1}'.format(res['tx'],res['rx']))
                else:
                    log.info('Traffic Flow is not as expected. The value of tx and Rx is : {0} and {1}'.format(res['tx'],res['rx']))
                    flag = 1 
                
                log.info('Deleting the Created Stream for this test: ')

                x1 = tgn_hdl.traffic_control(action='stop', handle = trf_hdl,max_wait_timer=60)
                
                countDownTimer(30)

                log.info('Removing the stream:')
                y = tgn_hdl.traffic_config(mode='remove',stream_id=nested_vxlan_traffic_config8['stream_id'])
                
                node_dict['all_dut'][dut_to_configure_static_mac].configure('no '+cfg)
                        
                log.info('STarting all the other streams')
                z = tgn_hdl.traffic_control(action='run',max_wait_timer=60)
                
                log.info('waiting for 30 seconds before collecting the stats:')
                countDownTimer(30)
                out = trigger_obj.checkAllStreamStats(tgn_hdl)
                
                if not out:
                    log.error(banner('Traffic has not recovered on some of the streams after starting the Original Streams.. Collecting the individual STream stats:'))
                    self.failed()
                        
                if flag:
                    log.error(banner('Nested Traffic Flow was not as expected. Hence failing'))
                    self.failed()
            else:
                log.error('The Initial Traffic Condition did not pass:')
                self.failed()                                   

class VXLANVxlanV6FUNC123(aetest.Testcase):

    """ Nested Vxlan - VPC Port To Everywhere - UUC """

    uid = 'VXLAN-L3-VxlanV6-FUNC-123'
    
    @aetest.test
    def NestedVxlanVPCPortToEveryWhereUUCV4Payload(self,log,testscript,testbed):
        
        node_dict = testscript.parameters['node_dict']
        tg_interface_hdl_dict = testscript.parameters['tg_interface_hdl_dict'] 
        traffic_stream_dict = testscript.parameters['traffic_stream_dict'] 
        port_handle_dict = testscript.parameters['port_handle_dict']
        TGList_config_file = testscript.parameters['TGList']
        configdict = testscript.parameters['configdict'] 
        tgn_config_dict = configdict['TG']
        threshold = testscript.parameters['traffic_threshold'] 
        tgn_port_dut_mapping = testscript.parameters['tgn_port_dut_mapping']
        alias_intf_mapping_dict = testscript.parameters['alias_intf_mapping']
        configured_stream = testscript.parameters['configured_stream']
        trigger_obj = testscript.parameters['trigger_obj']
        testbed_obj = testscript.parameters['testbed_obj']

        log.info(banner('The value of configured stream is : {0}'.format(configured_stream))) 
        
        res = [node_dict['all_dut'][dut].execute('show version') for dut in node_dict['all_dut'] if re.search('uut', dut)]
        
        for TG in tgn_config_dict.keys():
            tgn_hdl = testscript.parameters['testbed_obj'].devices[TG]
            out = trigger_obj.checkAllStreamStats(tgn_hdl)
            flag = 0
            if out:
                
                log.info(banner('Stopping all the Traffic:'))
                
                a = tgn_hdl.traffic_control(action='stop',max_wait_timer=60)
                
                log.info(banner('Waiting for 30 seconds before Creating the Nested Vxlan traffic : '))
                countDownTimer(30)
                
                log.info(banner('Creating Nested Vxlan Traffic:'))
                    
                source_port = testscript.parameters['configdict']['TG'][TG]['TEST-016']['traffic_config_dict']['source']
                receiver_port = testscript.parameters['configdict']['TG'][TG]['TEST-016']['traffic_config_dict']['capable_receivers']
                traffic_args=testscript.parameters['configdict']['TG'][TG]['TEST-016']['traffic_config_dict']['params']
                 
                src_port = [port_handle_dict[x] for x in source_port]
                dst_port = [port_handle_dict[x] for x in receiver_port]
                log.info('The value of src_port is : {0}'.format(src_port))
                log.info('The value of dst_port is : {0}'.format(dst_port))
                
                traffic_gen_object = MyLib.my_config_utils.IxiaRawTrafficGeneration(log,tgn_hdl,configdict,port_handle_dict)
                
                end_point_args = traffic_args['Traffic_End_points']
                log.info(banner('The value of end_point_args is : {0}'.format(end_point_args)))
                
                nested_vxlan_traffic_config = traffic_gen_object.configureTrafficEndPoints(end_point_args,emulation_src_handle=src_port, emulation_dst_handle=dst_port)
                log.info('The value of ixia_traffic_config is : {0}'.format(nested_vxlan_traffic_config))
                
                if nested_vxlan_traffic_config['status'] == 1:
                    log.info(banner('Traffic End points is configured as expected.. configuring the STream params'))
                    trf_hdl = nested_vxlan_traffic_config['traffic_item']
                    traffic_stream_args  = traffic_args['StreamParameters']
                    nested_vxlan_traffic_config1 = traffic_gen_object.configureTrafficStreamParameters(trf_hdl,traffic_stream_args)
                    if nested_vxlan_traffic_config1['status'] == 1:
                        log.info(banner('Configuring the Ethernet Header -- Stack 1 '))
                        ethernet1_header_args = traffic_args['EthernetHeader1']
                        nested_vxlan_traffic_config2 = traffic_gen_object.configureEthernetHeader(trf_hdl,ethernet1_header_args)
                        if nested_vxlan_traffic_config2['status'] == 1:
                            log.info(banner('Configuring the Vlan Header -- Stack 2 '))
                            vlan_header_args = traffic_args['VlanHeader']
                            nested_vxlan_traffic_config3 = traffic_gen_object.configureVlanHeader(trf_hdl,vlan_header_args)
                            if nested_vxlan_traffic_config3['status'] == 1:
                                log.info(banner('Configuring the inner IPv6 Header -- Stack 3'))
                                ip1_header_args = traffic_args['IPHeader1']
                                nested_vxlan_traffic_config4 = traffic_gen_object.configureIPv6ProtocolHeader(trf_hdl,ip1_header_args)
                                if nested_vxlan_traffic_config4['status'] == 1:
                                    log.info(banner('Configuring the UDP Header -- Stack 4'))
                                    udp_header_args = traffic_args['UDPHeader']
                                    nested_vxlan_traffic_config5 = traffic_gen_object.configureUDPHeader(trf_hdl,udp_header_args)
                                    if nested_vxlan_traffic_config5['status'] == 1:
                                        log.info(banner('Configuring the Inner Vxlan Header -- Stack 5'))
                                        vxlan_header_args = traffic_args['VxlanHeader']
                                        nested_vxlan_traffic_config6 = traffic_gen_object.configureVxlanHeader(trf_hdl,vxlan_header_args)
                                        ls = nested_vxlan_traffic_config6['last_stack']
                                        if nested_vxlan_traffic_config6['status'] == 1:
                                            log.info(banner('Configuring the Inner VNI header - Stack 5a'))
                                            vni_header_args = traffic_args['VNIHeader']
                                            nested_vxlan_traffic_config7 = traffic_gen_object.configureVxlanVNIHeader(trf_hdl,vni_header_args,ls)
                                            if nested_vxlan_traffic_config7['status'] == 1:
                                                log.info(banner('Configuring the Ethernet Header 2- Stack 6'))
                                                ethernet2_header_args = traffic_args['EthernetHeader2']
                                                nested_vxlan_traffic_config8 = traffic_gen_object.configureEthernetHeader(trf_hdl,ethernet2_header_args)                
                                                if nested_vxlan_traffic_config8['status'] == 1:
                                                    log.info(banner('Configuring the IP Header 2- Stack 7'))
                                                    ip2_header_args = traffic_args['IPHeader2']
                                                    nested_vxlan_traffic_config8 = traffic_gen_object.configureIPv4ProtocolHeader(trf_hdl,ip2_header_args)
                
                                
                actual_receiver = testscript.parameters['configdict']['TG'][TG]['TEST-009']['traffic_config_dict']['actual_receiver']
                log.info('The value of actual_receiver is : {0}'.format(actual_receiver))

                log.info(banner('Waiting for 20 seconds before collecting the stats'))
                countDownTimer(20)
                b = tgn_hdl.traffic_control(action='run', handle = trf_hdl, max_wait_timer=60)
                
                stream_dict = {}
                stream_dict.setdefault('TEST-016',{})
                stream_dict['TEST-016']['stream_id'] = nested_vxlan_traffic_config8['stream_id']
                
                res = MyLib.my_config_utils.getTrafficItemStatistics(log,tgn_hdl,stream_dict,'TEST-016')
                exp_trf = len(actual_receiver) * res['tx']
                log.info('The value of expected Traffic is : {0}'.format(exp_trf))
                
                if abs(exp_trf-res['rx'] < threshold):
                    log.info('Traffic flow is as expected..The value of tx and Rx is : {0} and {1}'.format(res['tx'],res['rx']))
                else:
                    log.error('Traffic Flow is not as expected. The value of tx and Rx is : {0} and {1}'.format(res['tx'],res['rx']))
                    flag = 1 
                
                log.info('Deleting the Created Stream for this test: ')

                x1 = tgn_hdl.traffic_control(action='stop', handle = trf_hdl,max_wait_timer=60)
                
                countDownTimer(30)

                log.info('Removing the stream:')
                y = tgn_hdl.traffic_config(mode='remove',stream_id=nested_vxlan_traffic_config8['stream_id'])
                        
                log.info('STarting all the other streams')
                z = tgn_hdl.traffic_control(action='run',max_wait_timer=60)
                
                log.info('waiting for 30 seconds before collecting the stats:')
                countDownTimer(30)
                out = trigger_obj.checkAllStreamStats(tgn_hdl)
                
                if not out:
                    log.error(banner('Traffic has not recovered on some of the streams after starting the Original Streams.. Collecting the individual STream stats:'))
                    self.failed()
                        
                if flag:
                    log.error(banner('Nested Traffic Flow was not as expected. Hence failing'))
                    self.failed()
            else:
                log.error('The Initial Traffic Condition did not pass:')
                self.failed()                                   

class VXLANVxlanV6FUNC124(aetest.Testcase):

    """ Nested Vxlan - VPC Port To Everywhere - BroadCast """

    uid = 'VXLAN-L3-VxlanV6-FUNC-124'
    
    @aetest.test
    def NestedVxlanVPCPortToEveryWhereBroadCastV6Payload(self,log,testscript,testbed):
        
        node_dict = testscript.parameters['node_dict']
        tg_interface_hdl_dict = testscript.parameters['tg_interface_hdl_dict'] 
        traffic_stream_dict = testscript.parameters['traffic_stream_dict'] 
        port_handle_dict = testscript.parameters['port_handle_dict']
        TGList_config_file = testscript.parameters['TGList']
        configdict = testscript.parameters['configdict'] 
        tgn_config_dict = configdict['TG']
        threshold = testscript.parameters['traffic_threshold'] 
        tgn_port_dut_mapping = testscript.parameters['tgn_port_dut_mapping']
        alias_intf_mapping_dict = testscript.parameters['alias_intf_mapping']
        configured_stream = testscript.parameters['configured_stream']
        trigger_obj = testscript.parameters['trigger_obj']
        testbed_obj = testscript.parameters['testbed_obj']

        log.info(banner('The value of configured stream is : {0}'.format(configured_stream))) 
        
        res = [node_dict['all_dut'][dut].execute('show version') for dut in node_dict['all_dut'] if re.search('uut', dut)]
        
        for TG in tgn_config_dict.keys():
            tgn_hdl = testscript.parameters['testbed_obj'].devices[TG]
            out = trigger_obj.checkAllStreamStats(tgn_hdl)
            flag = 0
            if out:
                
                log.info(banner('Stopping all the Traffic:'))
                
                a = tgn_hdl.traffic_control(action='stop',max_wait_timer=60)
                
                log.info(banner('Waiting for 30 seconds before Creating the Nested Vxlan traffic : '))
                countDownTimer(30)
                
                log.info(banner('Creating Nested Vxlan Traffic:'))
                    
                source_port = testscript.parameters['configdict']['TG'][TG]['TEST-017']['traffic_config_dict']['source']
                receiver_port = testscript.parameters['configdict']['TG'][TG]['TEST-017']['traffic_config_dict']['capable_receivers']
                traffic_args=testscript.parameters['configdict']['TG'][TG]['TEST-017']['traffic_config_dict']['params']
                 
                src_port = [port_handle_dict[x] for x in source_port]
                dst_port = [port_handle_dict[x] for x in receiver_port]
                log.info('The value of src_port is : {0}'.format(src_port))
                log.info('The value of dst_port is : {0}'.format(dst_port))
                
                traffic_gen_object = MyLib.my_config_utils.IxiaRawTrafficGeneration(log,tgn_hdl,configdict,port_handle_dict)
                
                end_point_args = traffic_args['Traffic_End_points']
                log.info(banner('The value of end_point_args is : {0}'.format(end_point_args)))
                
                nested_vxlan_traffic_config = traffic_gen_object.configureTrafficEndPoints(end_point_args,emulation_src_handle=src_port, emulation_dst_handle=dst_port)
                log.info('The value of ixia_traffic_config is : {0}'.format(nested_vxlan_traffic_config))
                
                if nested_vxlan_traffic_config['status'] == 1:
                    log.info(banner('Traffic End points is configured as expected.. configuring the STream params'))
                    trf_hdl = nested_vxlan_traffic_config['traffic_item']
                    traffic_stream_args  = traffic_args['StreamParameters']
                    nested_vxlan_traffic_config1 = traffic_gen_object.configureTrafficStreamParameters(trf_hdl,traffic_stream_args)
                    if nested_vxlan_traffic_config1['status'] == 1:
                        log.info(banner('Configuring the Ethernet Header -- Stack 1 '))
                        ethernet1_header_args = traffic_args['EthernetHeader1']
                        nested_vxlan_traffic_config2 = traffic_gen_object.configureEthernetHeader(trf_hdl,ethernet1_header_args)
                        if nested_vxlan_traffic_config2['status'] == 1:
                            log.info(banner('Configuring the Vlan Header -- Stack 2 '))
                            vlan_header_args = traffic_args['VlanHeader']
                            nested_vxlan_traffic_config3 = traffic_gen_object.configureVlanHeader(trf_hdl,vlan_header_args)
                            if nested_vxlan_traffic_config3['status'] == 1:
                                log.info(banner('Configuring the inner IPv6 Header -- Stack 3'))
                                ip1_header_args = traffic_args['IPHeader1']
                                nested_vxlan_traffic_config4 = traffic_gen_object.configureIPv6ProtocolHeader(trf_hdl,ip1_header_args)
                                if nested_vxlan_traffic_config4['status'] == 1:
                                    log.info(banner('Configuring the UDP Header -- Stack 4'))
                                    udp_header_args = traffic_args['UDPHeader']
                                    nested_vxlan_traffic_config5 = traffic_gen_object.configureUDPHeader(trf_hdl,udp_header_args)
                                    if nested_vxlan_traffic_config5['status'] == 1:
                                        log.info(banner('Configuring the Inner Vxlan Header -- Stack 5'))
                                        vxlan_header_args = traffic_args['VxlanHeader']
                                        nested_vxlan_traffic_config6 = traffic_gen_object.configureVxlanHeader(trf_hdl,vxlan_header_args)
                                        ls = nested_vxlan_traffic_config6['last_stack']
                                        if nested_vxlan_traffic_config6['status'] == 1:
                                            log.info(banner('Configuring the Inner VNI header - Stack 5a'))
                                            vni_header_args = traffic_args['VNIHeader']
                                            nested_vxlan_traffic_config7 = traffic_gen_object.configureVxlanVNIHeader(trf_hdl,vni_header_args,ls)
                                            if nested_vxlan_traffic_config7['status'] == 1:
                                                log.info(banner('Configuring the Ethernet Header 2- Stack 6'))
                                                ethernet2_header_args = traffic_args['EthernetHeader2']
                                                nested_vxlan_traffic_config8 = traffic_gen_object.configureEthernetHeader(trf_hdl,ethernet2_header_args)                
                                                if nested_vxlan_traffic_config8['status'] == 1:
                                                    log.info(banner('Configuring the IP Header 2- Stack 7'))
                                                    ip2_header_args = traffic_args['IPHeader2']
                                                    nested_vxlan_traffic_config8 = traffic_gen_object.configureIPv4ProtocolHeader(trf_hdl,ip2_header_args)
                
                                
                actual_receiver = testscript.parameters['configdict']['TG'][TG]['TEST-017']['traffic_config_dict']['actual_receiver']
                log.info('The value of actual_receiver is : {0}'.format(actual_receiver))

                log.info(banner('Waiting for 20 seconds before collecting the stats'))
                countDownTimer(20)
                b = tgn_hdl.traffic_control(action='run', handle = trf_hdl, max_wait_timer=60)
                
                stream_dict = {}
                stream_dict.setdefault('TEST-017',{})
                stream_dict['TEST-017']['stream_id'] = nested_vxlan_traffic_config8['stream_id']
                
                res = MyLib.my_config_utils.getTrafficItemStatistics(log,tgn_hdl,stream_dict,'TEST-017')
                exp_trf = len(actual_receiver) * res['tx']
                log.info('The value of expected Traffic is : {0}'.format(exp_trf))
                
                if abs(exp_trf-res['rx'] < threshold):
                    log.info('Traffic flow is as expected..The value of tx and Rx is : {0} and {1}'.format(res['tx'],res['rx']))
                else:
                    log.error('Traffic Flow is not as expected. The value of tx and Rx is : {0} and {1}'.format(res['tx'],res['rx']))
                    flag = 1 
                
                log.info('Deleting the Created Stream for this test: ')

                x1 = tgn_hdl.traffic_control(action='stop', handle = trf_hdl,max_wait_timer=60)
                
                countDownTimer(30)

                log.info('Removing the stream:')
                y = tgn_hdl.traffic_config(mode='remove',stream_id=nested_vxlan_traffic_config8['stream_id'])
                        
                log.info('STarting all the other streams')
                z = tgn_hdl.traffic_control(action='run',max_wait_timer=60)
                
                log.info('waiting for 30 seconds before collecting the stats:')
                countDownTimer(30)
                out = trigger_obj.checkAllStreamStats(tgn_hdl)
                
                if not out:
                    log.error(banner('Traffic has not recovered on some of the streams after starting the Original Streams.. Collecting the individual STream stats:'))
                    self.failed()
                        
                if flag:
                    log.error(banner('Nested Traffic Flow was not as expected. Hence failing'))
                    self.failed()
            else:
                log.error('The Initial Traffic Condition did not pass:')
                self.failed()                                   

class VXLANVxlanV6FUNC125(aetest.Testcase):

    """ Nested Vxlan - VPC Port To Everywhere - Multicast """

    uid = 'VXLAN-L3-VxlanV6-FUNC-125'
    
    @aetest.test
    def NestedVxlanVPCPortToEveryWhereMultiCastV4Payload(self,log,testscript,testbed):
        
        node_dict = testscript.parameters['node_dict']
        tg_interface_hdl_dict = testscript.parameters['tg_interface_hdl_dict'] 
        traffic_stream_dict = testscript.parameters['traffic_stream_dict'] 
        port_handle_dict = testscript.parameters['port_handle_dict']
        TGList_config_file = testscript.parameters['TGList']
        configdict = testscript.parameters['configdict'] 
        tgn_config_dict = configdict['TG']
        threshold = testscript.parameters['traffic_threshold'] 
        tgn_port_dut_mapping = testscript.parameters['tgn_port_dut_mapping']
        alias_intf_mapping_dict = testscript.parameters['alias_intf_mapping']
        configured_stream = testscript.parameters['configured_stream']
        trigger_obj = testscript.parameters['trigger_obj']
        testbed_obj = testscript.parameters['testbed_obj']

        log.info(banner('The value of configured stream is : {0}'.format(configured_stream))) 
        
        res = [node_dict['all_dut'][dut].execute('show version') for dut in node_dict['all_dut'] if re.search('uut', dut)]
        
        for TG in tgn_config_dict.keys():
            tgn_hdl = testscript.parameters['testbed_obj'].devices[TG]
            out = trigger_obj.checkAllStreamStats(tgn_hdl)
            flag = 0
            if out:
                
                log.info(banner('Stopping all the Traffic:'))
                
                a = tgn_hdl.traffic_control(action='stop',max_wait_timer=60)
                
                log.info(banner('Waiting for 30 seconds before Creating the Nested Vxlan traffic : '))
                countDownTimer(30)
                
                log.info(banner('Creating Nested Vxlan Traffic:'))
                    
                source_port = testscript.parameters['configdict']['TG'][TG]['TEST-018']['traffic_config_dict']['source']
                receiver_port = testscript.parameters['configdict']['TG'][TG]['TEST-018']['traffic_config_dict']['capable_receivers']
                traffic_args=testscript.parameters['configdict']['TG'][TG]['TEST-018']['traffic_config_dict']['params']
                 
                src_port = [port_handle_dict[x] for x in source_port]
                dst_port = [port_handle_dict[x] for x in receiver_port]
                log.info('The value of src_port is : {0}'.format(src_port))
                log.info('The value of dst_port is : {0}'.format(dst_port))
                
                traffic_gen_object = MyLib.my_config_utils.IxiaRawTrafficGeneration(log,tgn_hdl,configdict,port_handle_dict)
                
                end_point_args = traffic_args['Traffic_End_points']
                log.info(banner('The value of end_point_args is : {0}'.format(end_point_args)))
                
                nested_vxlan_traffic_config = traffic_gen_object.configureTrafficEndPoints(end_point_args,emulation_src_handle=src_port, emulation_dst_handle=dst_port)
                log.info('The value of ixia_traffic_config is : {0}'.format(nested_vxlan_traffic_config))
                
                if nested_vxlan_traffic_config['status'] == 1:
                    log.info(banner('Traffic End points is configured as expected.. configuring the STream params'))
                    trf_hdl = nested_vxlan_traffic_config['traffic_item']
                    traffic_stream_args  = traffic_args['StreamParameters']
                    nested_vxlan_traffic_config1 = traffic_gen_object.configureTrafficStreamParameters(trf_hdl,traffic_stream_args)
                    if nested_vxlan_traffic_config1['status'] == 1:
                        log.info(banner('Configuring the Ethernet Header -- Stack 1 '))
                        ethernet1_header_args = traffic_args['EthernetHeader1']
                        nested_vxlan_traffic_config2 = traffic_gen_object.configureEthernetHeader(trf_hdl,ethernet1_header_args)
                        if nested_vxlan_traffic_config2['status'] == 1:
                            log.info(banner('Configuring the Vlan Header -- Stack 2 '))
                            vlan_header_args = traffic_args['VlanHeader']
                            ns = MyLib.my_config_utils.parseVlanHeaderArgs(log,vlan_header_args)
                            igmp_vlan = ns.vlan_id
                            nested_vxlan_traffic_config3 = traffic_gen_object.configureVlanHeader(trf_hdl,vlan_header_args)
                            if nested_vxlan_traffic_config3['status'] == 1:
                                log.info(banner('Configuring the inner IPv6 Header -- Stack 3'))
                                ip1_header_args = traffic_args['IPHeader1']
                                nested_vxlan_traffic_config4 = traffic_gen_object.configureIPv6ProtocolHeader(trf_hdl,ip1_header_args)
                                if nested_vxlan_traffic_config4['status'] == 1:
                                    log.info(banner('Configuring the UDP Header -- Stack 4'))
                                    udp_header_args = traffic_args['UDPHeader']
                                    nested_vxlan_traffic_config5 = traffic_gen_object.configureUDPHeader(trf_hdl,udp_header_args)
                                    if nested_vxlan_traffic_config5['status'] == 1:
                                        log.info(banner('Configuring the Inner Vxlan Header -- Stack 5'))
                                        vxlan_header_args = traffic_args['VxlanHeader']
                                        nested_vxlan_traffic_config6 = traffic_gen_object.configureVxlanHeader(trf_hdl,vxlan_header_args)
                                        ls = nested_vxlan_traffic_config6['last_stack']
                                        if nested_vxlan_traffic_config6['status'] == 1:
                                            log.info(banner('Configuring the Inner VNI header - Stack 5a'))
                                            vni_header_args = traffic_args['VNIHeader']
                                            nested_vxlan_traffic_config7 = traffic_gen_object.configureVxlanVNIHeader(trf_hdl,vni_header_args,ls)
                                            if nested_vxlan_traffic_config7['status'] == 1:
                                                log.info(banner('Configuring the Ethernet Header 2- Stack 6'))
                                                ethernet2_header_args = traffic_args['EthernetHeader2']
                                                nested_vxlan_traffic_config8 = traffic_gen_object.configureEthernetHeader(trf_hdl,ethernet2_header_args)                
                                                if nested_vxlan_traffic_config8['status'] == 1:
                                                    log.info(banner('Configuring the IP Header 2- Stack 7'))
                                                    ip2_header_args = traffic_args['IPHeader2']
                                                    nested_vxlan_traffic_config8 = traffic_gen_object.configureIPv4ProtocolHeader(trf_hdl,ip2_header_args)
                
                                
                actual_receiver = testscript.parameters['configdict']['TG'][TG]['TEST-018']['traffic_config_dict']['actual_receiver']
                log.info('The value of actual_receiver is : {0}'.format(actual_receiver))
                
                for device, sw_hdl in trigger_obj.getDeviceDict('l2_switch').items(): pass
                
                cfg1 = '''vlan configuration {0}
                          no ip igmp snooping'''.format(igmp_vlan)
                          
                sw_hdl.configure(cfg1)

                log.info(banner('Waiting for 20 seconds before collecting the stats'))
                countDownTimer(20)
                b = tgn_hdl.traffic_control(action='run', handle = trf_hdl, max_wait_timer=60)
                
                stream_dict = {}
                stream_dict.setdefault('TEST-018',{})
                stream_dict['TEST-018']['stream_id'] = nested_vxlan_traffic_config8['stream_id']
                
                res = MyLib.my_config_utils.getTrafficItemStatistics(log,tgn_hdl,stream_dict,'TEST-018')
                exp_trf = len(actual_receiver) * res['tx']
                log.info('The value of expected Traffic is : {0}'.format(exp_trf))
                
                if abs(exp_trf-res['rx'] < threshold):
                    log.info('Traffic flow is as expected..The value of tx and Rx is : {0} and {1}'.format(res['tx'],res['rx']))
                else:
                    log.error('Traffic Flow is not as expected. The value of tx and Rx is : {0} and {1}'.format(res['tx'],res['rx']))
                    flag = 1 
                
                log.info('Deleting the Created Stream for this test: ')

                x1 = tgn_hdl.traffic_control(action='stop', handle = trf_hdl,max_wait_timer=60)
                
                countDownTimer(30)
                
                sw_hdl.configure('no vlan configuration {0}'.format(igmp_vlan))

                log.info('Removing the stream:')
                y = tgn_hdl.traffic_config(mode='remove',stream_id=nested_vxlan_traffic_config8['stream_id'])
                        
                log.info('STarting all the other streams')
                z = tgn_hdl.traffic_control(action='run',max_wait_timer=60)
                
                log.info('waiting for 30 seconds before collecting the stats:')
                countDownTimer(30)
                out = trigger_obj.checkAllStreamStats(tgn_hdl)
                
                if not out:
                    log.error(banner('Traffic has not recovered on some of the streams after starting the Original Streams.. Collecting the individual STream stats:'))
                    self.failed()
                        
                if flag:
                    log.error(banner('Nested Traffic Flow was not as expected. Hence failing'))
                    self.failed()
            else:
                log.error('The Initial Traffic Condition did not pass:')
                self.failed()     

class VXLANVxlanV6FUNC126(aetest.Testcase):

    """ Nested Vxlan V4 InnerVxlan Header- Orphan to Orphan """

    uid = 'VXLAN-L3-VxlanV6-FUNC-126'
    
    @aetest.test
    def NestedVxlanOrphanToOrphanV6PayloadV4InnerVxlanHeader(self,log,testscript,testbed):
        
        node_dict = testscript.parameters['node_dict']
        tg_interface_hdl_dict = testscript.parameters['tg_interface_hdl_dict'] 
        traffic_stream_dict = testscript.parameters['traffic_stream_dict'] 
        port_handle_dict = testscript.parameters['port_handle_dict']
        TGList_config_file = testscript.parameters['TGList']
        configdict = testscript.parameters['configdict'] 
        tgn_config_dict = configdict['TG']
        threshold = testscript.parameters['traffic_threshold'] 
        tgn_port_dut_mapping = testscript.parameters['tgn_port_dut_mapping']
        alias_intf_mapping_dict = testscript.parameters['alias_intf_mapping']
        configured_stream = testscript.parameters['configured_stream']
        trigger_obj = testscript.parameters['trigger_obj']
        testbed_obj = testscript.parameters['testbed_obj']

        log.info(banner('The value of configured stream is : {0}'.format(configured_stream))) 
        
        res = [node_dict['all_dut'][dut].execute('show version') for dut in node_dict['all_dut'] if re.search('uut', dut)]
        
        for TG in tgn_config_dict.keys():
            tgn_hdl = testscript.parameters['testbed_obj'].devices[TG]
            out = trigger_obj.checkAllStreamStats(tgn_hdl)
            flag = 0
            if out:
                
                log.info(banner('Stopping all the Traffic:'))
                
                a = tgn_hdl.traffic_control(action='stop',max_wait_timer=60)
                
                source_port = testscript.parameters['configdict']['TG'][TG]['TEST-019']['traffic_config_dict']['source']
                receiver_port = testscript.parameters['configdict']['TG'][TG]['TEST-019']['traffic_config_dict']['capable_receivers']
                actual_receiver = testscript.parameters['configdict']['TG'][TG]['TEST-019']['traffic_config_dict']['actual_receiver'][0]
                traffic_args=testscript.parameters['configdict']['TG'][TG]['TEST-019']['traffic_config_dict']['params']
                
                log.info(banner('The value of actual Receiver is : {0}'.format(actual_receiver)))
                
                src_port = [port_handle_dict[x] for x in source_port]
                dst_port = [port_handle_dict[x] for x in receiver_port]
                log.info('The value of src_port is : {0}'.format(src_port))
                log.info('The value of dst_port is : {0}'.format(dst_port))                
                
                log.info(banner('Creating an Host Interface on Ixia:'))
                intf_params = traffic_args['host_params']
                ixia_intf_conf = configureIxNetworkInterface(self,intf_params,tg_hdl = tgn_hdl,port_handle = port_handle_dict[actual_receiver])
                traffic_config_obj = MyLib.my_config_utils.TrafficConfiguration(log,testscript,configdict,port_handle_dict)
                i =0
                log.info(banner('Sending ARP Requets for the created hosts:'))
                while (i < 5):
                    log.info(banner('Iteration # {0}'.format(i+1)))
                    res = traffic_config_obj.sendArpRequest(tg_hdl=tgn_hdl,port_handle=port_handle_dict[actual_receiver])
                    countDownTimer(1)
                    i+=1
#                 dut = tgn_port_dut_mapping[actual_receiver]
#                 node_dict['all_dut'][dut].execute('ping 195.100.1.150 vrf all')
                log.info(banner('Waiting for 30 seconds before Creating the Nested Vxlan traffic : '))
                countDownTimer(30)
                
                log.info(banner('Creating Nested Vxlan Traffic:'))

                traffic_gen_object = MyLib.my_config_utils.IxiaRawTrafficGeneration(log,tgn_hdl,configdict,port_handle_dict)
                
                end_point_args = traffic_args['Traffic_End_points']
                log.info(banner('The value of end_point_args is : {0}'.format(end_point_args)))
                
                nested_vxlan_traffic_config = traffic_gen_object.configureTrafficEndPoints(end_point_args,emulation_src_handle=src_port, emulation_dst_handle=dst_port)
                log.info('The value of ixia_traffic_config is : {0}'.format(nested_vxlan_traffic_config))
                
                if nested_vxlan_traffic_config['status'] == 1:
                    log.info(banner('Traffic End points is configured as expected.. configuring the STream params'))
                    trf_hdl = nested_vxlan_traffic_config['traffic_item']
                    traffic_stream_args  = traffic_args['StreamParameters']
                    nested_vxlan_traffic_config1 = traffic_gen_object.configureTrafficStreamParameters(trf_hdl,traffic_stream_args)
                    if nested_vxlan_traffic_config1['status'] == 1:
                        log.info(banner('Configuring the Ethernet Header -- Stack 1 '))
                        ethernet1_header_args = traffic_args['EthernetHeader1']
                        nested_vxlan_traffic_config2 = traffic_gen_object.configureEthernetHeader(trf_hdl,ethernet1_header_args)
                        if nested_vxlan_traffic_config2['status'] == 1:
                            log.info(banner('Configuring the Vlan Header -- Stack 2 '))
                            vlan_header_args = traffic_args['VlanHeader']
                            nested_vxlan_traffic_config3 = traffic_gen_object.configureVlanHeader(trf_hdl,vlan_header_args)
                            if nested_vxlan_traffic_config3['status'] == 1:
                                log.info(banner('Configuring the inner IPv6 Header -- Stack 3'))
                                ip1_header_args = traffic_args['IPHeader1']
                                nested_vxlan_traffic_config4 = traffic_gen_object.configureIPv4ProtocolHeader(trf_hdl,ip1_header_args)
                                if nested_vxlan_traffic_config4['status'] == 1:
                                    log.info(banner('Configuring the UDP Header -- Stack 4'))
                                    udp_header_args = traffic_args['UDPHeader']
                                    nested_vxlan_traffic_config5 = traffic_gen_object.configureUDPHeader(trf_hdl,udp_header_args)
                                    if nested_vxlan_traffic_config5['status'] == 1:
                                        log.info(banner('Configuring the Inner Vxlan Header -- Stack 5'))
                                        vxlan_header_args = traffic_args['VxlanHeader']
                                        nested_vxlan_traffic_config6 = traffic_gen_object.configureVxlanHeader(trf_hdl,vxlan_header_args)
                                        ls = nested_vxlan_traffic_config6['last_stack']
                                        if nested_vxlan_traffic_config6['status'] == 1:
                                            log.info(banner('Configuring the Inner VNI header - Stack 5a'))
                                            vni_header_args = traffic_args['VNIHeader']
                                            nested_vxlan_traffic_config7 = traffic_gen_object.configureVxlanVNIHeader(trf_hdl,vni_header_args,ls)
                                            if nested_vxlan_traffic_config7['status'] == 1:
                                                log.info(banner('Configuring the Ethernet Header 2- Stack 6'))
                                                ethernet2_header_args = traffic_args['EthernetHeader2']
                                                nested_vxlan_traffic_config8 = traffic_gen_object.configureEthernetHeader(trf_hdl,ethernet2_header_args)                
                                                if nested_vxlan_traffic_config8['status'] == 1:
                                                    log.info(banner('Configuring the IP Header 2- Stack 7'))
                                                    ip2_header_args = traffic_args['IPHeader2']
                                                    nested_vxlan_traffic_config8 = traffic_gen_object.configureIPv6ProtocolHeader(trf_hdl,ip2_header_args)
                
                
                
                log.info('The value of nested_vxlan_traffic_config is : {0}'.format(nested_vxlan_traffic_config8))

                log.info(banner('Waiting for 20 seconds before collecting the stats'))
                countDownTimer(20)
                b = tgn_hdl.traffic_control(action='run', handle = trf_hdl, max_wait_timer=60)
                
                stream_dict = {}
                stream_dict.setdefault('TEST-019',{})
                stream_dict['TEST-019']['stream_id'] = nested_vxlan_traffic_config8['stream_id']
                
                res = MyLib.my_config_utils.getTrafficItemStatistics(log,tgn_hdl,stream_dict,'TEST-019')
                
                if abs(res['tx']-res['rx']) < threshold:
                    log.info('Traffic flow is as expected..The value of tx and Rx is : {0} and {1}'.format(res['tx'],res['rx']))
                else:
                    log.error('Traffic Flow is not as expected. The value of tx and Rx is : {0} and {1}'.format(res['tx'],res['rx']))
                    flag = 1 
                
                log.info('Deleting the Created Stream for this test: ')

                x1 = tgn_hdl.traffic_control(action='stop', handle = trf_hdl,max_wait_timer=60)
                
                countDownTimer(30)

#                 log.info('Removing the stream:')
#                 y = tgn_hdl.traffic_config(mode='remove',stream_id=nested_vxlan_traffic_config8['stream_id'])
                
                        
                log.info('STarting all the other streams')
                z = tgn_hdl.traffic_control(action='run',max_wait_timer=60)
                
                log.info('waiting for 30 seconds before collecting the stats:')
                countDownTimer(30)
                out = trigger_obj.checkAllStreamStats(tgn_hdl)
                
                if not out:
                    log.error(banner('Traffic has not recovered on some of the streams after starting the Original Streams.. Collecting the individual STream stats:'))
                    self.failed()
                        
                if flag:
                    log.error(banner('Nested Traffic Flow was not as expected. Hence failing'))
                    self.failed()
            else:
                log.error('The Initial Traffic Condition did not pass:')
                self.failed()                                   

class VXLANVxlanV6FUNC127(aetest.Testcase):

    """ Nested Vxlan V4 InnerVxlan Header- Orphan to VPC Port """

    uid = 'VXLAN-L3-VxlanV6-FUNC-127'
    
    @aetest.test
    def NestedVxlanOrphanToVPCPortV6PayloadV4InnerVxlanHeader(self,log,testscript,testbed):
        
        node_dict = testscript.parameters['node_dict']
        tg_interface_hdl_dict = testscript.parameters['tg_interface_hdl_dict'] 
        traffic_stream_dict = testscript.parameters['traffic_stream_dict'] 
        port_handle_dict = testscript.parameters['port_handle_dict']
        TGList_config_file = testscript.parameters['TGList']
        configdict = testscript.parameters['configdict'] 
        tgn_config_dict = configdict['TG']
        threshold = testscript.parameters['traffic_threshold'] 
        tgn_port_dut_mapping = testscript.parameters['tgn_port_dut_mapping']
        alias_intf_mapping_dict = testscript.parameters['alias_intf_mapping']
        configured_stream = testscript.parameters['configured_stream']
        trigger_obj = testscript.parameters['trigger_obj']
        testbed_obj = testscript.parameters['testbed_obj']

        log.info(banner('The value of configured stream is : {0}'.format(configured_stream))) 
        
        res = [node_dict['all_dut'][dut].execute('show version') for dut in node_dict['all_dut'] if re.search('uut', dut)]
        
        for TG in tgn_config_dict.keys():
            tgn_hdl = testscript.parameters['testbed_obj'].devices[TG]
            out = trigger_obj.checkAllStreamStats(tgn_hdl)
            flag = 0
            if out:
                
                log.info(banner('Stopping all the Traffic:'))
                
                a = tgn_hdl.traffic_control(action='stop',max_wait_timer=60)
                
                source_port = testscript.parameters['configdict']['TG'][TG]['TEST-020']['traffic_config_dict']['source']
                receiver_port = testscript.parameters['configdict']['TG'][TG]['TEST-020']['traffic_config_dict']['capable_receivers']
                actual_receiver = testscript.parameters['configdict']['TG'][TG]['TEST-020']['traffic_config_dict']['actual_receiver'][0]
                traffic_args=testscript.parameters['configdict']['TG'][TG]['TEST-020']['traffic_config_dict']['params']
                
                src_port = [port_handle_dict[x] for x in source_port]
                dst_port = [port_handle_dict[x] for x in receiver_port]
                log.info('The value of src_port is : {0}'.format(src_port))
                log.info('The value of dst_port is : {0}'.format(dst_port))                
                
                log.info(banner('Creating an Host Interface on Ixia:'))
                intf_params = traffic_args['host_params']
                ixia_intf_conf = configureIxNetworkInterface(self,intf_params,tg_hdl = tgn_hdl,port_handle = port_handle_dict[actual_receiver])
                traffic_config_obj = MyLib.my_config_utils.TrafficConfiguration(log,testscript,configdict,port_handle_dict)
                i = 0
                log.info(banner('Sending ARP Requets for the created hosts:'))
                while (i < 5):
                    log.info(banner('Iteration # {0}'.format(i+1)))
                    res = traffic_config_obj.sendArpRequest(tg_hdl=tgn_hdl,port_handle=port_handle_dict[actual_receiver])
                    countDownTimer(1)
                    i+=1
#                 dut = tgn_port_dut_mapping[actual_receiver]
#                 node_dict['all_dut'][dut].execute('ping 195.100.1.150 vrf all')
                log.info(banner('Waiting for 30 seconds before Creating the Nested Vxlan traffic : '))
                countDownTimer(30)
                
                log.info(banner('Creating Nested Vxlan Traffic:'))

                traffic_gen_object = MyLib.my_config_utils.IxiaRawTrafficGeneration(log,tgn_hdl,configdict,port_handle_dict)
                
                end_point_args = traffic_args['Traffic_End_points']
                log.info(banner('The value of end_point_args is : {0}'.format(end_point_args)))
                
                nested_vxlan_traffic_config = traffic_gen_object.configureTrafficEndPoints(end_point_args,emulation_src_handle=src_port, emulation_dst_handle=dst_port)
                log.info('The value of ixia_traffic_config is : {0}'.format(nested_vxlan_traffic_config))
                
                if nested_vxlan_traffic_config['status'] == 1:
                    log.info(banner('Traffic End points is configured as expected.. configuring the STream params'))
                    trf_hdl = nested_vxlan_traffic_config['traffic_item']
                    traffic_stream_args  = traffic_args['StreamParameters']
                    nested_vxlan_traffic_config1 = traffic_gen_object.configureTrafficStreamParameters(trf_hdl,traffic_stream_args)
                    if nested_vxlan_traffic_config1['status'] == 1:
                        log.info(banner('Configuring the Ethernet Header -- Stack 1 '))
                        ethernet1_header_args = traffic_args['EthernetHeader1']
                        nested_vxlan_traffic_config2 = traffic_gen_object.configureEthernetHeader(trf_hdl,ethernet1_header_args)
                        if nested_vxlan_traffic_config2['status'] == 1:
                            log.info(banner('Configuring the Vlan Header -- Stack 2 '))
                            vlan_header_args = traffic_args['VlanHeader']
                            nested_vxlan_traffic_config3 = traffic_gen_object.configureVlanHeader(trf_hdl,vlan_header_args)
                            if nested_vxlan_traffic_config3['status'] == 1:
                                log.info(banner('Configuring the inner IPv6 Header -- Stack 3'))
                                ip1_header_args = traffic_args['IPHeader1']
                                nested_vxlan_traffic_config4 = traffic_gen_object.configureIPv4ProtocolHeader(trf_hdl,ip1_header_args)
                                if nested_vxlan_traffic_config4['status'] == 1:
                                    log.info(banner('Configuring the UDP Header -- Stack 4'))
                                    udp_header_args = traffic_args['UDPHeader']
                                    nested_vxlan_traffic_config5 = traffic_gen_object.configureUDPHeader(trf_hdl,udp_header_args)
                                    if nested_vxlan_traffic_config5['status'] == 1:
                                        log.info(banner('Configuring the Inner Vxlan Header -- Stack 5'))
                                        vxlan_header_args = traffic_args['VxlanHeader']
                                        nested_vxlan_traffic_config6 = traffic_gen_object.configureVxlanHeader(trf_hdl,vxlan_header_args)
                                        ls = nested_vxlan_traffic_config6['last_stack']
                                        if nested_vxlan_traffic_config6['status'] == 1:
                                            log.info(banner('Configuring the Inner VNI header - Stack 5a'))
                                            vni_header_args = traffic_args['VNIHeader']
                                            nested_vxlan_traffic_config7 = traffic_gen_object.configureVxlanVNIHeader(trf_hdl,vni_header_args,ls)
                                            if nested_vxlan_traffic_config7['status'] == 1:
                                                log.info(banner('Configuring the Ethernet Header 2- Stack 6'))
                                                ethernet2_header_args = traffic_args['EthernetHeader2']
                                                nested_vxlan_traffic_config8 = traffic_gen_object.configureEthernetHeader(trf_hdl,ethernet2_header_args)                
                                                if nested_vxlan_traffic_config8['status'] == 1:
                                                    log.info(banner('Configuring the IP Header 2- Stack 7'))
                                                    ip2_header_args = traffic_args['IPHeader2']
                                                    nested_vxlan_traffic_config8 = traffic_gen_object.configureIPv6ProtocolHeader(trf_hdl,ip2_header_args)
                
                
                
                log.info('The value of nested_vxlan_traffic_config is : {0}'.format(nested_vxlan_traffic_config8))

                log.info(banner('Waiting for 20 seconds before collecting the stats'))
                countDownTimer(20)
                b = tgn_hdl.traffic_control(action='run', handle = trf_hdl, max_wait_timer=60)
                
                stream_dict = {}
                stream_dict.setdefault('TEST-020',{})
                stream_dict['TEST-020']['stream_id'] = nested_vxlan_traffic_config8['stream_id']
                
                res = MyLib.my_config_utils.getTrafficItemStatistics(log,tgn_hdl,stream_dict,'TEST-020')
                
                if abs(res['tx']-res['rx']) < threshold:
                    log.info('Traffic flow is as expected..The value of tx and Rx is : {0} and {1}'.format(res['tx'],res['rx']))
                else:
                    log.error('Traffic Flow is not as expected. The value of tx and Rx is : {0} and {1}'.format(res['tx'],res['rx']))
                    flag = 1 
                
                log.info('Deleting the Created Stream for this test: ')

                x1 = tgn_hdl.traffic_control(action='stop', handle = trf_hdl,max_wait_timer=60)
                
                countDownTimer(30)

                log.info('Removing the stream:')
                y = tgn_hdl.traffic_config(mode='remove',stream_id=nested_vxlan_traffic_config8['stream_id'])
                
                        
                log.info('STarting all the other streams')
                z = tgn_hdl.traffic_control(action='run',max_wait_timer=60)
                
                log.info('waiting for 30 seconds before collecting the stats:')
                countDownTimer(30)
                out = trigger_obj.checkAllStreamStats(tgn_hdl)
                
                if not out:
                    log.error(banner('Traffic has not recovered on some of the streams after starting the Original Streams.. Collecting the individual STream stats:'))
                    self.failed()
                        
                if flag:
                    log.error(banner('Nested Traffic Flow was not as expected. Hence failing'))
                    self.failed()
            else:
                log.error('The Initial Traffic Condition did not pass:')
                self.failed() 

class VXLANVxlanV6FUNC128(aetest.Testcase):

    """ Nested Vxlan V4 InnerVxlan Header- Orphan to Remote VTEP   """

    uid = 'VXLAN-L3-VxlanV6-FUNC-128'
    
    @aetest.test
    def NestedVxlanOrphanToremoteVTEPV6PayloadV4InnerVxlanHeader(self,log,testscript,testbed):
        
        node_dict = testscript.parameters['node_dict']
        tg_interface_hdl_dict = testscript.parameters['tg_interface_hdl_dict'] 
        traffic_stream_dict = testscript.parameters['traffic_stream_dict'] 
        port_handle_dict = testscript.parameters['port_handle_dict']
        TGList_config_file = testscript.parameters['TGList']
        configdict = testscript.parameters['configdict'] 
        tgn_config_dict = configdict['TG']
        threshold = testscript.parameters['traffic_threshold'] 
        tgn_port_dut_mapping = testscript.parameters['tgn_port_dut_mapping']
        alias_intf_mapping_dict = testscript.parameters['alias_intf_mapping']
        configured_stream = testscript.parameters['configured_stream']
        trigger_obj = testscript.parameters['trigger_obj']
        testbed_obj = testscript.parameters['testbed_obj']

        log.info(banner('The value of configured stream is : {0}'.format(configured_stream))) 
        
        res = [node_dict['all_dut'][dut].execute('show version') for dut in node_dict['all_dut'] if re.search('uut', dut)]
        
        for TG in tgn_config_dict.keys():
            tgn_hdl = testscript.parameters['testbed_obj'].devices[TG]
            out = trigger_obj.checkAllStreamStats(tgn_hdl)
            flag = 0
            if out:
                
                log.info(banner('Stopping all the Traffic:'))
                
                a = tgn_hdl.traffic_control(action='stop',max_wait_timer=60)
                
                log.info(banner('Waiting for 30 seconds before Creating the Nested Vxlan traffic : '))
                countDownTimer(30)
                
                log.info(banner('Creating Nested Vxlan Traffic:'))
                    
                source_port = testscript.parameters['configdict']['TG'][TG]['TEST-021']['traffic_config_dict']['source']
                receiver_port = testscript.parameters['configdict']['TG'][TG]['TEST-021']['traffic_config_dict']['capable_receivers']
                traffic_args=testscript.parameters['configdict']['TG'][TG]['TEST-021']['traffic_config_dict']['params']
                 
                src_port = [port_handle_dict[x] for x in source_port]
                dst_port = [port_handle_dict[x] for x in receiver_port]
                log.info('The value of src_port is : {0}'.format(src_port))
                log.info('The value of dst_port is : {0}'.format(dst_port))
                
                traffic_gen_object = MyLib.my_config_utils.IxiaRawTrafficGeneration(log,tgn_hdl,configdict,port_handle_dict)
                
                end_point_args = traffic_args['Traffic_End_points']
                log.info(banner('The value of end_point_args is : {0}'.format(end_point_args)))
                
                nested_vxlan_traffic_config = traffic_gen_object.configureTrafficEndPoints(end_point_args,emulation_src_handle=src_port, emulation_dst_handle=dst_port)
                log.info('The value of ixia_traffic_config is : {0}'.format(nested_vxlan_traffic_config))
                
                if nested_vxlan_traffic_config['status'] == 1:
                    log.info(banner('Traffic End points is configured as expected.. configuring the STream params'))
                    trf_hdl = nested_vxlan_traffic_config['traffic_item']
                    traffic_stream_args  = traffic_args['StreamParameters']
                    nested_vxlan_traffic_config1 = traffic_gen_object.configureTrafficStreamParameters(trf_hdl,traffic_stream_args)
                    if nested_vxlan_traffic_config1['status'] == 1:
                        log.info(banner('Configuring the Ethernet Header -- Stack 1 '))
                        ethernet1_header_args = traffic_args['EthernetHeader1']
                        nested_vxlan_traffic_config2 = traffic_gen_object.configureEthernetHeader(trf_hdl,ethernet1_header_args)
                        if nested_vxlan_traffic_config2['status'] == 1:
                            log.info(banner('Configuring the Vlan Header -- Stack 2 '))
                            vlan_header_args = traffic_args['VlanHeader']
                            nested_vxlan_traffic_config3 = traffic_gen_object.configureVlanHeader(trf_hdl,vlan_header_args)
                            if nested_vxlan_traffic_config3['status'] == 1:
                                log.info(banner('Configuring the inner IPv6 Header -- Stack 3'))
                                ip1_header_args = traffic_args['IPHeader1']
                                nested_vxlan_traffic_config4 = traffic_gen_object.configureIPv4ProtocolHeader(trf_hdl,ip1_header_args)
                                if nested_vxlan_traffic_config4['status'] == 1:
                                    log.info(banner('Configuring the UDP Header -- Stack 4'))
                                    udp_header_args = traffic_args['UDPHeader']
                                    nested_vxlan_traffic_config5 = traffic_gen_object.configureUDPHeader(trf_hdl,udp_header_args)
                                    if nested_vxlan_traffic_config5['status'] == 1:
                                        log.info(banner('Configuring the Inner Vxlan Header -- Stack 5'))
                                        vxlan_header_args = traffic_args['VxlanHeader']
                                        nested_vxlan_traffic_config6 = traffic_gen_object.configureVxlanHeader(trf_hdl,vxlan_header_args)
                                        ls = nested_vxlan_traffic_config6['last_stack']
                                        if nested_vxlan_traffic_config6['status'] == 1:
                                            log.info(banner('Configuring the Inner VNI header - Stack 5a'))
                                            vni_header_args = traffic_args['VNIHeader']
                                            nested_vxlan_traffic_config7 = traffic_gen_object.configureVxlanVNIHeader(trf_hdl,vni_header_args,ls)
                                            if nested_vxlan_traffic_config7['status'] == 1:
                                                log.info(banner('Configuring the Ethernet Header 2- Stack 6'))
                                                ethernet2_header_args = traffic_args['EthernetHeader2']
                                                nested_vxlan_traffic_config8 = traffic_gen_object.configureEthernetHeader(trf_hdl,ethernet2_header_args)                
                                                if nested_vxlan_traffic_config8['status'] == 1:
                                                    log.info(banner('Configuring the IP Header 2- Stack 7'))
                                                    ip2_header_args = traffic_args['IPHeader2']
                                                    nested_vxlan_traffic_config8 = traffic_gen_object.configureIPv6ProtocolHeader(trf_hdl,ip2_header_args)
                
                
                
                log.info('The value of nested_vxlan_traffic_config is : {0}'.format(nested_vxlan_traffic_config8))
                ethernet_args = traffic_args['EthernetHeader1']                                   
                ns = MyLib.my_config_utils.parseEthernetHeaderArgs(log,ethernet_args)
                dmac = ns.mac_dst
                actual_receiver = testscript.parameters['configdict']['TG'][TG]['TEST-021']['traffic_config_dict']['actual_receiver'][0]
                
                dut_to_configure_static_mac = tgn_port_dut_mapping[actual_receiver]
                log.info('the value of dut_to_configure is : {0}'.format(dut_to_configure_static_mac))
                            
                for item in testbed_obj.devices.aliases:
                    log.info('The value of item is : {0}'.format(item))
                    if re.search(dut_to_configure_static_mac,item):
                        for i in testbed_obj.devices[item].interfaces.keys():
                            log.info('The value if i is : {0}'.format(i))
                            if re.search('TG',testbed_obj.devices[item].interfaces[i].alias):
                                port = i
                                log.info('The value of port is : {0}'.format(port))
                        
                
                cfg = 'mac address-table static {0} vlan 701 interface {1}'.format(dmac,port)
                node_dict['all_dut'][dut_to_configure_static_mac].configure(cfg)
                log.info(banner('Waiting for 20 seconds before collecting the stats'))
                countDownTimer(20)
                b = tgn_hdl.traffic_control(action='run', handle = trf_hdl, max_wait_timer=60)
                
                stream_dict = {}
                stream_dict.setdefault('TEST-021',{})
                stream_dict['TEST-021']['stream_id'] = nested_vxlan_traffic_config8['stream_id']
                
                res = MyLib.my_config_utils.getTrafficItemStatistics(log,tgn_hdl,stream_dict,'TEST-021')
                
                if abs(res['tx']-res['rx'] < threshold):
                    log.info('Traffic flow is as expected..The value of tx and Rx is : {0} and {1}'.format(res['tx'],res['rx']))
                else:
                    log.info('Traffic Flow is not as expected. The value of tx and Rx is : {0} and {1}'.format(res['tx'],res['rx']))
                    flag = 1 
                
                log.info('Deleting the Created Stream for this test: ')

                x1 = tgn_hdl.traffic_control(action='stop', handle = trf_hdl,max_wait_timer=60)
                
                countDownTimer(30)

                log.info('Removing the stream:')
                y = tgn_hdl.traffic_config(mode='remove',stream_id=nested_vxlan_traffic_config8['stream_id'])
                
                node_dict['all_dut'][dut_to_configure_static_mac].configure('no '+cfg)
                        
                log.info('STarting all the other streams')
                z = tgn_hdl.traffic_control(action='run',max_wait_timer=60)
                
                log.info('waiting for 30 seconds before collecting the stats:')
                countDownTimer(30)
                out = trigger_obj.checkAllStreamStats(tgn_hdl)
                
                if not out:
                    log.error(banner('Traffic has not recovered on some of the streams after starting the Original Streams.. Collecting the individual STream stats:'))
                    self.failed()
                        
                if flag:
                    log.error(banner('Nested Traffic Flow was not as expected. Hence failing'))
                    self.failed()
            else:
                log.error('The Initial Traffic Condition did not pass:')
                self.failed()                                   

class VXLANVxlanV6FUNC129(aetest.Testcase):

    """ Nested Vxlan - VPC Port to Remote VTEP """

    uid = 'VXLAN-L3-VxlanV6-FUNC-129'
    
    @aetest.test
    def NestedVxlanVPCPortToRemoteVTEPV6PayloadV4InnerVxlanHeader(self,log,testscript,testbed):
        
        node_dict = testscript.parameters['node_dict']
        tg_interface_hdl_dict = testscript.parameters['tg_interface_hdl_dict'] 
        traffic_stream_dict = testscript.parameters['traffic_stream_dict'] 
        port_handle_dict = testscript.parameters['port_handle_dict']
        TGList_config_file = testscript.parameters['TGList']
        configdict = testscript.parameters['configdict'] 
        tgn_config_dict = configdict['TG']
        threshold = testscript.parameters['traffic_threshold'] 
        tgn_port_dut_mapping = testscript.parameters['tgn_port_dut_mapping']
        alias_intf_mapping_dict = testscript.parameters['alias_intf_mapping']
        configured_stream = testscript.parameters['configured_stream']
        trigger_obj = testscript.parameters['trigger_obj']
        testbed_obj = testscript.parameters['testbed_obj']

        log.info(banner('The value of configured stream is : {0}'.format(configured_stream))) 
        
        res = [node_dict['all_dut'][dut].execute('show version') for dut in node_dict['all_dut'] if re.search('uut', dut)]
        
        for TG in tgn_config_dict.keys():
            tgn_hdl = testscript.parameters['testbed_obj'].devices[TG]
            out = trigger_obj.checkAllStreamStats(tgn_hdl)
            flag = 0
            if out:
                
                log.info(banner('Stopping all the Traffic:'))
                
                a = tgn_hdl.traffic_control(action='stop',max_wait_timer=60)
                
                log.info(banner('Waiting for 30 seconds before Creating the Nested Vxlan traffic : '))
                countDownTimer(30)
                
                log.info(banner('Creating Nested Vxlan Traffic:'))
                    
                source_port = testscript.parameters['configdict']['TG'][TG]['TEST-022']['traffic_config_dict']['source']
                receiver_port = testscript.parameters['configdict']['TG'][TG]['TEST-022']['traffic_config_dict']['capable_receivers']
                traffic_args=testscript.parameters['configdict']['TG'][TG]['TEST-022']['traffic_config_dict']['params']
                 
                src_port = [port_handle_dict[x] for x in source_port]
                dst_port = [port_handle_dict[x] for x in receiver_port]
                log.info('The value of src_port is : {0}'.format(src_port))
                log.info('The value of dst_port is : {0}'.format(dst_port))
                
                traffic_gen_object = MyLib.my_config_utils.IxiaRawTrafficGeneration(log,tgn_hdl,configdict,port_handle_dict)
                
                end_point_args = traffic_args['Traffic_End_points']
                log.info(banner('The value of end_point_args is : {0}'.format(end_point_args)))
                
                nested_vxlan_traffic_config = traffic_gen_object.configureTrafficEndPoints(end_point_args,emulation_src_handle=src_port, emulation_dst_handle=dst_port)
                log.info('The value of ixia_traffic_config is : {0}'.format(nested_vxlan_traffic_config))
                
                if nested_vxlan_traffic_config['status'] == 1:
                    log.info(banner('Traffic End points is configured as expected.. configuring the STream params'))
                    trf_hdl = nested_vxlan_traffic_config['traffic_item']
                    traffic_stream_args  = traffic_args['StreamParameters']
                    nested_vxlan_traffic_config1 = traffic_gen_object.configureTrafficStreamParameters(trf_hdl,traffic_stream_args)
                    if nested_vxlan_traffic_config1['status'] == 1:
                        log.info(banner('Configuring the Ethernet Header -- Stack 1 '))
                        ethernet1_header_args = traffic_args['EthernetHeader1']
                        nested_vxlan_traffic_config2 = traffic_gen_object.configureEthernetHeader(trf_hdl,ethernet1_header_args)
                        if nested_vxlan_traffic_config2['status'] == 1:
                            log.info(banner('Configuring the Vlan Header -- Stack 2 '))
                            vlan_header_args = traffic_args['VlanHeader']
                            nested_vxlan_traffic_config3 = traffic_gen_object.configureVlanHeader(trf_hdl,vlan_header_args)
                            if nested_vxlan_traffic_config3['status'] == 1:
                                log.info(banner('Configuring the inner IPv6 Header -- Stack 3'))
                                ip1_header_args = traffic_args['IPHeader1']
                                nested_vxlan_traffic_config4 = traffic_gen_object.configureIPv4ProtocolHeader(trf_hdl,ip1_header_args)
                                if nested_vxlan_traffic_config4['status'] == 1:
                                    log.info(banner('Configuring the UDP Header -- Stack 4'))
                                    udp_header_args = traffic_args['UDPHeader']
                                    nested_vxlan_traffic_config5 = traffic_gen_object.configureUDPHeader(trf_hdl,udp_header_args)
                                    if nested_vxlan_traffic_config5['status'] == 1:
                                        log.info(banner('Configuring the Inner Vxlan Header -- Stack 5'))
                                        vxlan_header_args = traffic_args['VxlanHeader']
                                        nested_vxlan_traffic_config6 = traffic_gen_object.configureVxlanHeader(trf_hdl,vxlan_header_args)
                                        ls = nested_vxlan_traffic_config6['last_stack']
                                        if nested_vxlan_traffic_config6['status'] == 1:
                                            log.info(banner('Configuring the Inner VNI header - Stack 5a'))
                                            vni_header_args = traffic_args['VNIHeader']
                                            nested_vxlan_traffic_config7 = traffic_gen_object.configureVxlanVNIHeader(trf_hdl,vni_header_args,ls)
                                            if nested_vxlan_traffic_config7['status'] == 1:
                                                log.info(banner('Configuring the Ethernet Header 2- Stack 6'))
                                                ethernet2_header_args = traffic_args['EthernetHeader2']
                                                nested_vxlan_traffic_config8 = traffic_gen_object.configureEthernetHeader(trf_hdl,ethernet2_header_args)                
                                                if nested_vxlan_traffic_config8['status'] == 1:
                                                    log.info(banner('Configuring the IP Header 2- Stack 7'))
                                                    ip2_header_args = traffic_args['IPHeader2']
                                                    nested_vxlan_traffic_config8 = traffic_gen_object.configureIPv6ProtocolHeader(trf_hdl,ip2_header_args)
                
                
                
                log.info('The value of nested_vxlan_traffic_config is : {0}'.format(nested_vxlan_traffic_config8))
                ethernet_args = traffic_args['EthernetHeader1']                                   
                ns = MyLib.my_config_utils.parseEthernetHeaderArgs(log,ethernet_args)
                dmac = ns.mac_dst
                actual_receiver = testscript.parameters['configdict']['TG'][TG]['TEST-022']['traffic_config_dict']['actual_receiver'][0]
                
                dut_to_configure_static_mac = tgn_port_dut_mapping[actual_receiver]
                log.info('the value of dut_to_configure is : {0}'.format(dut_to_configure_static_mac))
                            
                for item in testbed_obj.devices.aliases:
                    log.info('The value of item is : {0}'.format(item))
                    if re.search(dut_to_configure_static_mac,item):
                        for i in testbed_obj.devices[item].interfaces.keys():
                            log.info('The value if i is : {0}'.format(i))
                            if re.search('TG',testbed_obj.devices[item].interfaces[i].alias):
                                port = i
                                log.info('The value of port is : {0}'.format(port))
                        
                
                cfg = 'mac address-table static {0} vlan 701 interface {1}'.format(dmac,port)
                node_dict['all_dut'][dut_to_configure_static_mac].configure(cfg)
                log.info(banner('Waiting for 20 seconds before collecting the stats'))
                countDownTimer(20)
                b = tgn_hdl.traffic_control(action='run', handle = trf_hdl, max_wait_timer=60)
                
                stream_dict = {}
                stream_dict.setdefault('TEST-022',{})
                stream_dict['TEST-022']['stream_id'] = nested_vxlan_traffic_config8['stream_id']
                
                res = MyLib.my_config_utils.getTrafficItemStatistics(log,tgn_hdl,stream_dict,'TEST-022')
                
                if abs(res['tx']-res['rx'] < threshold):
                    log.info('Traffic flow is as expected..The value of tx and Rx is : {0} and {1}'.format(res['tx'],res['rx']))
                else:
                    log.info('Traffic Flow is not as expected. The value of tx and Rx is : {0} and {1}'.format(res['tx'],res['rx']))
                    flag = 1 
                
                log.info('Deleting the Created Stream for this test: ')

                x1 = tgn_hdl.traffic_control(action='stop', handle = trf_hdl,max_wait_timer=60)
                
                countDownTimer(30)

                log.info('Removing the stream:')
                y = tgn_hdl.traffic_config(mode='remove',stream_id=nested_vxlan_traffic_config8['stream_id'])
                
                node_dict['all_dut'][dut_to_configure_static_mac].configure('no '+cfg)
                        
                log.info('STarting all the other streams')
                z = tgn_hdl.traffic_control(action='run',max_wait_timer=60)
                
                log.info('waiting for 30 seconds before collecting the stats:')
                countDownTimer(30)
                out = trigger_obj.checkAllStreamStats(tgn_hdl)
                
                if not out:
                    log.error(banner('Traffic has not recovered on some of the streams after starting the Original Streams.. Collecting the individual STream stats:'))
                    self.failed()
                        
                if flag:
                    log.error(banner('Nested Traffic Flow was not as expected. Hence failing'))
                    self.failed()
            else:
                log.error('The Initial Traffic Condition did not pass:')
                self.failed()                                   

class VXLANVxlanV6FUNC130(aetest.Testcase):

    """ Nested Vxlan - VPC Port To Everywhere - UUC """

    uid = 'VXLAN-L3-VxlanV6-FUNC-130'
    
    @aetest.test
    def NestedVxlanVPCPortToEveryWhereUUCV6PayloadV4InnerVxlanHeader(self,log,testscript,testbed):
        
        node_dict = testscript.parameters['node_dict']
        tg_interface_hdl_dict = testscript.parameters['tg_interface_hdl_dict'] 
        traffic_stream_dict = testscript.parameters['traffic_stream_dict'] 
        port_handle_dict = testscript.parameters['port_handle_dict']
        TGList_config_file = testscript.parameters['TGList']
        configdict = testscript.parameters['configdict'] 
        tgn_config_dict = configdict['TG']
        threshold = testscript.parameters['traffic_threshold'] 
        tgn_port_dut_mapping = testscript.parameters['tgn_port_dut_mapping']
        alias_intf_mapping_dict = testscript.parameters['alias_intf_mapping']
        configured_stream = testscript.parameters['configured_stream']
        trigger_obj = testscript.parameters['trigger_obj']
        testbed_obj = testscript.parameters['testbed_obj']

        log.info(banner('The value of configured stream is : {0}'.format(configured_stream))) 
        
        res = [node_dict['all_dut'][dut].execute('show version') for dut in node_dict['all_dut'] if re.search('uut', dut)]
        
        for TG in tgn_config_dict.keys():
            tgn_hdl = testscript.parameters['testbed_obj'].devices[TG]
            out = trigger_obj.checkAllStreamStats(tgn_hdl)
            flag = 0
            if out:
                
                log.info(banner('Stopping all the Traffic:'))
                
                a = tgn_hdl.traffic_control(action='stop',max_wait_timer=60)
                
                log.info(banner('Waiting for 30 seconds before Creating the Nested Vxlan traffic : '))
                countDownTimer(30)
                
                log.info(banner('Creating Nested Vxlan Traffic:'))
                    
                source_port = testscript.parameters['configdict']['TG'][TG]['TEST-023']['traffic_config_dict']['source']
                receiver_port = testscript.parameters['configdict']['TG'][TG]['TEST-023']['traffic_config_dict']['capable_receivers']
                traffic_args=testscript.parameters['configdict']['TG'][TG]['TEST-023']['traffic_config_dict']['params']
                 
                src_port = [port_handle_dict[x] for x in source_port]
                dst_port = [port_handle_dict[x] for x in receiver_port]
                log.info('The value of src_port is : {0}'.format(src_port))
                log.info('The value of dst_port is : {0}'.format(dst_port))
                
                traffic_gen_object = MyLib.my_config_utils.IxiaRawTrafficGeneration(log,tgn_hdl,configdict,port_handle_dict)
                
                end_point_args = traffic_args['Traffic_End_points']
                log.info(banner('The value of end_point_args is : {0}'.format(end_point_args)))
                
                nested_vxlan_traffic_config = traffic_gen_object.configureTrafficEndPoints(end_point_args,emulation_src_handle=src_port, emulation_dst_handle=dst_port)
                log.info('The value of ixia_traffic_config is : {0}'.format(nested_vxlan_traffic_config))
                
                if nested_vxlan_traffic_config['status'] == 1:
                    log.info(banner('Traffic End points is configured as expected.. configuring the STream params'))
                    trf_hdl = nested_vxlan_traffic_config['traffic_item']
                    traffic_stream_args  = traffic_args['StreamParameters']
                    nested_vxlan_traffic_config1 = traffic_gen_object.configureTrafficStreamParameters(trf_hdl,traffic_stream_args)
                    if nested_vxlan_traffic_config1['status'] == 1:
                        log.info(banner('Configuring the Ethernet Header -- Stack 1 '))
                        ethernet1_header_args = traffic_args['EthernetHeader1']
                        nested_vxlan_traffic_config2 = traffic_gen_object.configureEthernetHeader(trf_hdl,ethernet1_header_args)
                        if nested_vxlan_traffic_config2['status'] == 1:
                            log.info(banner('Configuring the Vlan Header -- Stack 2 '))
                            vlan_header_args = traffic_args['VlanHeader']
                            nested_vxlan_traffic_config3 = traffic_gen_object.configureVlanHeader(trf_hdl,vlan_header_args)
                            if nested_vxlan_traffic_config3['status'] == 1:
                                log.info(banner('Configuring the inner IPv6 Header -- Stack 3'))
                                ip1_header_args = traffic_args['IPHeader1']
                                nested_vxlan_traffic_config4 = traffic_gen_object.configureIPv4ProtocolHeader(trf_hdl,ip1_header_args)
                                if nested_vxlan_traffic_config4['status'] == 1:
                                    log.info(banner('Configuring the UDP Header -- Stack 4'))
                                    udp_header_args = traffic_args['UDPHeader']
                                    nested_vxlan_traffic_config5 = traffic_gen_object.configureUDPHeader(trf_hdl,udp_header_args)
                                    if nested_vxlan_traffic_config5['status'] == 1:
                                        log.info(banner('Configuring the Inner Vxlan Header -- Stack 5'))
                                        vxlan_header_args = traffic_args['VxlanHeader']
                                        nested_vxlan_traffic_config6 = traffic_gen_object.configureVxlanHeader(trf_hdl,vxlan_header_args)
                                        ls = nested_vxlan_traffic_config6['last_stack']
                                        if nested_vxlan_traffic_config6['status'] == 1:
                                            log.info(banner('Configuring the Inner VNI header - Stack 5a'))
                                            vni_header_args = traffic_args['VNIHeader']
                                            nested_vxlan_traffic_config7 = traffic_gen_object.configureVxlanVNIHeader(trf_hdl,vni_header_args,ls)
                                            if nested_vxlan_traffic_config7['status'] == 1:
                                                log.info(banner('Configuring the Ethernet Header 2- Stack 6'))
                                                ethernet2_header_args = traffic_args['EthernetHeader2']
                                                nested_vxlan_traffic_config8 = traffic_gen_object.configureEthernetHeader(trf_hdl,ethernet2_header_args)                
                                                if nested_vxlan_traffic_config8['status'] == 1:
                                                    log.info(banner('Configuring the IP Header 2- Stack 7'))
                                                    ip2_header_args = traffic_args['IPHeader2']
                                                    nested_vxlan_traffic_config8 = traffic_gen_object.configureIPv6ProtocolHeader(trf_hdl,ip2_header_args)
                
                                
                actual_receiver = testscript.parameters['configdict']['TG'][TG]['TEST-023']['traffic_config_dict']['actual_receiver']
                log.info('The value of actual_receiver is : {0}'.format(actual_receiver))

                log.info(banner('Waiting for 20 seconds before collecting the stats'))
                countDownTimer(20)
                b = tgn_hdl.traffic_control(action='run', handle = trf_hdl, max_wait_timer=60)
                
                stream_dict = {}
                stream_dict.setdefault('TEST-023',{})
                stream_dict['TEST-023']['stream_id'] = nested_vxlan_traffic_config8['stream_id']
                
                res = MyLib.my_config_utils.getTrafficItemStatistics(log,tgn_hdl,stream_dict,'TEST-023')
                exp_trf = len(actual_receiver) * res['tx']
                log.info('The value of expected Traffic is : {0}'.format(exp_trf))
                
                if abs(exp_trf-res['rx'] < threshold):
                    log.info('Traffic flow is as expected..The value of tx and Rx is : {0} and {1}'.format(res['tx'],res['rx']))
                else:
                    log.error('Traffic Flow is not as expected. The value of tx and Rx is : {0} and {1}'.format(res['tx'],res['rx']))
                    flag = 1 
                
                log.info('Deleting the Created Stream for this test: ')

                x1 = tgn_hdl.traffic_control(action='stop', handle = trf_hdl,max_wait_timer=60)
                
                countDownTimer(30)

                log.info('Removing the stream:')
                y = tgn_hdl.traffic_config(mode='remove',stream_id=nested_vxlan_traffic_config8['stream_id'])
                        
                log.info('STarting all the other streams')
                z = tgn_hdl.traffic_control(action='run',max_wait_timer=60)
                
                log.info('waiting for 30 seconds before collecting the stats:')
                countDownTimer(30)
                out = trigger_obj.checkAllStreamStats(tgn_hdl)
                
                if not out:
                    log.error(banner('Traffic has not recovered on some of the streams after starting the Original Streams.. Collecting the individual STream stats:'))
                    self.failed()
                        
                if flag:
                    log.error(banner('Nested Traffic Flow was not as expected. Hence failing'))
                    self.failed()
            else:
                log.error('The Initial Traffic Condition did not pass:')
                self.failed()                                   

class VXLANVxlanV6FUNC131(aetest.Testcase):

    """ Nested Vxlan - VPC Port To Everywhere - BroadCast """

    uid = 'VXLAN-L3-VxlanV6-FUNC-131'
    
    @aetest.test
    def NestedVxlanVPCPortToEveryWhereBroadCastV6PayloadV4InnerVxlanHeader(self,log,testscript,testbed):
        
        node_dict = testscript.parameters['node_dict']
        tg_interface_hdl_dict = testscript.parameters['tg_interface_hdl_dict'] 
        traffic_stream_dict = testscript.parameters['traffic_stream_dict'] 
        port_handle_dict = testscript.parameters['port_handle_dict']
        TGList_config_file = testscript.parameters['TGList']
        configdict = testscript.parameters['configdict'] 
        tgn_config_dict = configdict['TG']
        threshold = testscript.parameters['traffic_threshold'] 
        tgn_port_dut_mapping = testscript.parameters['tgn_port_dut_mapping']
        alias_intf_mapping_dict = testscript.parameters['alias_intf_mapping']
        configured_stream = testscript.parameters['configured_stream']
        trigger_obj = testscript.parameters['trigger_obj']
        testbed_obj = testscript.parameters['testbed_obj']

        log.info(banner('The value of configured stream is : {0}'.format(configured_stream))) 
        
        res = [node_dict['all_dut'][dut].execute('show version') for dut in node_dict['all_dut'] if re.search('uut', dut)]
        
        for TG in tgn_config_dict.keys():
            tgn_hdl = testscript.parameters['testbed_obj'].devices[TG]
            out = trigger_obj.checkAllStreamStats(tgn_hdl)
            flag = 0
            if out:
                
                log.info(banner('Stopping all the Traffic:'))
                
                a = tgn_hdl.traffic_control(action='stop',max_wait_timer=60)
                
                log.info(banner('Waiting for 30 seconds before Creating the Nested Vxlan traffic : '))
                countDownTimer(30)
                
                log.info(banner('Creating Nested Vxlan Traffic:'))
                    
                source_port = testscript.parameters['configdict']['TG'][TG]['TEST-024']['traffic_config_dict']['source']
                receiver_port = testscript.parameters['configdict']['TG'][TG]['TEST-024']['traffic_config_dict']['capable_receivers']
                traffic_args=testscript.parameters['configdict']['TG'][TG]['TEST-024']['traffic_config_dict']['params']
                 
                src_port = [port_handle_dict[x] for x in source_port]
                dst_port = [port_handle_dict[x] for x in receiver_port]
                log.info('The value of src_port is : {0}'.format(src_port))
                log.info('The value of dst_port is : {0}'.format(dst_port))
                
                traffic_gen_object = MyLib.my_config_utils.IxiaRawTrafficGeneration(log,tgn_hdl,configdict,port_handle_dict)
                
                end_point_args = traffic_args['Traffic_End_points']
                log.info(banner('The value of end_point_args is : {0}'.format(end_point_args)))
                
                nested_vxlan_traffic_config = traffic_gen_object.configureTrafficEndPoints(end_point_args,emulation_src_handle=src_port, emulation_dst_handle=dst_port)
                log.info('The value of ixia_traffic_config is : {0}'.format(nested_vxlan_traffic_config))
                
                if nested_vxlan_traffic_config['status'] == 1:
                    log.info(banner('Traffic End points is configured as expected.. configuring the STream params'))
                    trf_hdl = nested_vxlan_traffic_config['traffic_item']
                    traffic_stream_args  = traffic_args['StreamParameters']
                    nested_vxlan_traffic_config1 = traffic_gen_object.configureTrafficStreamParameters(trf_hdl,traffic_stream_args)
                    if nested_vxlan_traffic_config1['status'] == 1:
                        log.info(banner('Configuring the Ethernet Header -- Stack 1 '))
                        ethernet1_header_args = traffic_args['EthernetHeader1']
                        nested_vxlan_traffic_config2 = traffic_gen_object.configureEthernetHeader(trf_hdl,ethernet1_header_args)
                        if nested_vxlan_traffic_config2['status'] == 1:
                            log.info(banner('Configuring the Vlan Header -- Stack 2 '))
                            vlan_header_args = traffic_args['VlanHeader']
                            nested_vxlan_traffic_config3 = traffic_gen_object.configureVlanHeader(trf_hdl,vlan_header_args)
                            if nested_vxlan_traffic_config3['status'] == 1:
                                log.info(banner('Configuring the inner IPv6 Header -- Stack 3'))
                                ip1_header_args = traffic_args['IPHeader1']
                                nested_vxlan_traffic_config4 = traffic_gen_object.configureIPv4ProtocolHeader(trf_hdl,ip1_header_args)
                                if nested_vxlan_traffic_config4['status'] == 1:
                                    log.info(banner('Configuring the UDP Header -- Stack 4'))
                                    udp_header_args = traffic_args['UDPHeader']
                                    nested_vxlan_traffic_config5 = traffic_gen_object.configureUDPHeader(trf_hdl,udp_header_args)
                                    if nested_vxlan_traffic_config5['status'] == 1:
                                        log.info(banner('Configuring the Inner Vxlan Header -- Stack 5'))
                                        vxlan_header_args = traffic_args['VxlanHeader']
                                        nested_vxlan_traffic_config6 = traffic_gen_object.configureVxlanHeader(trf_hdl,vxlan_header_args)
                                        ls = nested_vxlan_traffic_config6['last_stack']
                                        if nested_vxlan_traffic_config6['status'] == 1:
                                            log.info(banner('Configuring the Inner VNI header - Stack 5a'))
                                            vni_header_args = traffic_args['VNIHeader']
                                            nested_vxlan_traffic_config7 = traffic_gen_object.configureVxlanVNIHeader(trf_hdl,vni_header_args,ls)
                                            if nested_vxlan_traffic_config7['status'] == 1:
                                                log.info(banner('Configuring the Ethernet Header 2- Stack 6'))
                                                ethernet2_header_args = traffic_args['EthernetHeader2']
                                                nested_vxlan_traffic_config8 = traffic_gen_object.configureEthernetHeader(trf_hdl,ethernet2_header_args)                
                                                if nested_vxlan_traffic_config8['status'] == 1:
                                                    log.info(banner('Configuring the IP Header 2- Stack 7'))
                                                    ip2_header_args = traffic_args['IPHeader2']
                                                    nested_vxlan_traffic_config8 = traffic_gen_object.configureIPv6ProtocolHeader(trf_hdl,ip2_header_args)
                
                                
                actual_receiver = testscript.parameters['configdict']['TG'][TG]['TEST-010']['traffic_config_dict']['actual_receiver']
                log.info('The value of actual_receiver is : {0}'.format(actual_receiver))

                log.info(banner('Waiting for 20 seconds before collecting the stats'))
                countDownTimer(20)
                b = tgn_hdl.traffic_control(action='run', handle = trf_hdl, max_wait_timer=60)
                
                stream_dict = {}
                stream_dict.setdefault('TEST-024',{})
                stream_dict['TEST-024']['stream_id'] = nested_vxlan_traffic_config8['stream_id']
                
                res = MyLib.my_config_utils.getTrafficItemStatistics(log,tgn_hdl,stream_dict,'TEST-024')
                exp_trf = len(actual_receiver) * res['tx']
                log.info('The value of expected Traffic is : {0}'.format(exp_trf))
                
                if abs(exp_trf-res['rx'] < threshold):
                    log.info('Traffic flow is as expected..The value of tx and Rx is : {0} and {1}'.format(res['tx'],res['rx']))
                else:
                    log.error('Traffic Flow is not as expected. The value of tx and Rx is : {0} and {1}'.format(res['tx'],res['rx']))
                    flag = 1 
                
                log.info('Deleting the Created Stream for this test: ')

                x1 = tgn_hdl.traffic_control(action='stop', handle = trf_hdl,max_wait_timer=60)
                
                countDownTimer(30)

                log.info('Removing the stream:')
                y = tgn_hdl.traffic_config(mode='remove',stream_id=nested_vxlan_traffic_config8['stream_id'])
                        
                log.info('STarting all the other streams')
                z = tgn_hdl.traffic_control(action='run',max_wait_timer=60)
                
                log.info('waiting for 30 seconds before collecting the stats:')
                countDownTimer(30)
                out = trigger_obj.checkAllStreamStats(tgn_hdl)
                
                if not out:
                    log.error(banner('Traffic has not recovered on some of the streams after starting the Original Streams.. Collecting the individual STream stats:'))
                    self.failed()
                        
                if flag:
                    log.error(banner('Nested Traffic Flow was not as expected. Hence failing'))
                    self.failed()
            else:
                log.error('The Initial Traffic Condition did not pass:')
                self.failed()                                   

class VXLANVxlanV6FUNC132(aetest.Testcase):

    """ Nested Vxlan - VPC Port To Everywhere - Multicast """

    uid = 'VXLAN-L3-VxlanV6-FUNC-132'
    
    @aetest.test
    def NestedVxlanVPCPortToEveryWhereMultiCastV6PayloadV4InnerVxlanHeader(self,log,testscript,testbed):
        
        node_dict = testscript.parameters['node_dict']
        tg_interface_hdl_dict = testscript.parameters['tg_interface_hdl_dict'] 
        traffic_stream_dict = testscript.parameters['traffic_stream_dict'] 
        port_handle_dict = testscript.parameters['port_handle_dict']
        TGList_config_file = testscript.parameters['TGList']
        configdict = testscript.parameters['configdict'] 
        tgn_config_dict = configdict['TG']
        threshold = testscript.parameters['traffic_threshold'] 
        tgn_port_dut_mapping = testscript.parameters['tgn_port_dut_mapping']
        alias_intf_mapping_dict = testscript.parameters['alias_intf_mapping']
        configured_stream = testscript.parameters['configured_stream']
        trigger_obj = testscript.parameters['trigger_obj']
        testbed_obj = testscript.parameters['testbed_obj']

        log.info(banner('The value of configured stream is : {0}'.format(configured_stream))) 
        
        res = [node_dict['all_dut'][dut].execute('show version') for dut in node_dict['all_dut'] if re.search('uut', dut)]
        
        for TG in tgn_config_dict.keys():
            tgn_hdl = testscript.parameters['testbed_obj'].devices[TG]
            out = trigger_obj.checkAllStreamStats(tgn_hdl)
            flag = 0
            if out:
                
                log.info(banner('Stopping all the Traffic:'))
                
                a = tgn_hdl.traffic_control(action='stop',max_wait_timer=60)
                
                log.info(banner('Waiting for 30 seconds before Creating the Nested Vxlan traffic : '))
                countDownTimer(30)
                
                log.info(banner('Creating Nested Vxlan Traffic:'))
                    
                source_port = testscript.parameters['configdict']['TG'][TG]['TEST-025']['traffic_config_dict']['source']
                receiver_port = testscript.parameters['configdict']['TG'][TG]['TEST-025']['traffic_config_dict']['capable_receivers']
                traffic_args=testscript.parameters['configdict']['TG'][TG]['TEST-025']['traffic_config_dict']['params']
                 
                src_port = [port_handle_dict[x] for x in source_port]
                dst_port = [port_handle_dict[x] for x in receiver_port]
                log.info('The value of src_port is : {0}'.format(src_port))
                log.info('The value of dst_port is : {0}'.format(dst_port))
                
                traffic_gen_object = MyLib.my_config_utils.IxiaRawTrafficGeneration(log,tgn_hdl,configdict,port_handle_dict)
                
                end_point_args = traffic_args['Traffic_End_points']
                log.info(banner('The value of end_point_args is : {0}'.format(end_point_args)))
                
                nested_vxlan_traffic_config = traffic_gen_object.configureTrafficEndPoints(end_point_args,emulation_src_handle=src_port, emulation_dst_handle=dst_port)
                log.info('The value of ixia_traffic_config is : {0}'.format(nested_vxlan_traffic_config))
                
                if nested_vxlan_traffic_config['status'] == 1:
                    log.info(banner('Traffic End points is configured as expected.. configuring the STream params'))
                    trf_hdl = nested_vxlan_traffic_config['traffic_item']
                    traffic_stream_args  = traffic_args['StreamParameters']
                    nested_vxlan_traffic_config1 = traffic_gen_object.configureTrafficStreamParameters(trf_hdl,traffic_stream_args)
                    if nested_vxlan_traffic_config1['status'] == 1:
                        log.info(banner('Configuring the Ethernet Header -- Stack 1 '))
                        ethernet1_header_args = traffic_args['EthernetHeader1']
                        nested_vxlan_traffic_config2 = traffic_gen_object.configureEthernetHeader(trf_hdl,ethernet1_header_args)
                        if nested_vxlan_traffic_config2['status'] == 1:
                            log.info(banner('Configuring the Vlan Header -- Stack 2 '))
                            vlan_header_args = traffic_args['VlanHeader']
                            ns = MyLib.my_config_utils.parseVlanHeaderArgs(log,vlan_header_args)
                            igmp_vlan = ns.vlan_id
                            nested_vxlan_traffic_config3 = traffic_gen_object.configureVlanHeader(trf_hdl,vlan_header_args)
                            if nested_vxlan_traffic_config3['status'] == 1:
                                log.info(banner('Configuring the inner IPv6 Header -- Stack 3'))
                                ip1_header_args = traffic_args['IPHeader1']
                                nested_vxlan_traffic_config4 = traffic_gen_object.configureIPv4ProtocolHeader(trf_hdl,ip1_header_args)
                                if nested_vxlan_traffic_config4['status'] == 1:
                                    log.info(banner('Configuring the UDP Header -- Stack 4'))
                                    udp_header_args = traffic_args['UDPHeader']
                                    nested_vxlan_traffic_config5 = traffic_gen_object.configureUDPHeader(trf_hdl,udp_header_args)
                                    if nested_vxlan_traffic_config5['status'] == 1:
                                        log.info(banner('Configuring the Inner Vxlan Header -- Stack 5'))
                                        vxlan_header_args = traffic_args['VxlanHeader']
                                        nested_vxlan_traffic_config6 = traffic_gen_object.configureVxlanHeader(trf_hdl,vxlan_header_args)
                                        ls = nested_vxlan_traffic_config6['last_stack']
                                        if nested_vxlan_traffic_config6['status'] == 1:
                                            log.info(banner('Configuring the Inner VNI header - Stack 5a'))
                                            vni_header_args = traffic_args['VNIHeader']
                                            nested_vxlan_traffic_config7 = traffic_gen_object.configureVxlanVNIHeader(trf_hdl,vni_header_args,ls)
                                            if nested_vxlan_traffic_config7['status'] == 1:
                                                log.info(banner('Configuring the Ethernet Header 2- Stack 6'))
                                                ethernet2_header_args = traffic_args['EthernetHeader2']
                                                nested_vxlan_traffic_config8 = traffic_gen_object.configureEthernetHeader(trf_hdl,ethernet2_header_args)                
                                                if nested_vxlan_traffic_config8['status'] == 1:
                                                    log.info(banner('Configuring the IP Header 2- Stack 7'))
                                                    ip2_header_args = traffic_args['IPHeader2']
                                                    nested_vxlan_traffic_config8 = traffic_gen_object.configureIPv6ProtocolHeader(trf_hdl,ip2_header_args)
                
                                
                actual_receiver = testscript.parameters['configdict']['TG'][TG]['TEST-011']['traffic_config_dict']['actual_receiver']
                log.info('The value of actual_receiver is : {0}'.format(actual_receiver))
                
                for device, sw_hdl in trigger_obj.getDeviceDict('l2_switch').items(): pass
                cfg1 = '''vlan configuration {0}
                          no ip igmp snooping'''.format(igmp_vlan)
                sw_hdl.configure(cfg1)
                log.info(banner('Waiting for 20 seconds before collecting the stats'))
                countDownTimer(20)
                b = tgn_hdl.traffic_control(action='run', handle = trf_hdl, max_wait_timer=60)
                
                stream_dict = {}
                stream_dict.setdefault('TEST-025',{})
                stream_dict['TEST-025']['stream_id'] = nested_vxlan_traffic_config8['stream_id']
                
                res = MyLib.my_config_utils.getTrafficItemStatistics(log,tgn_hdl,stream_dict,'TEST-025')
                exp_trf = len(actual_receiver) * res['tx']
                log.info('The value of expected Traffic is : {0}'.format(exp_trf))
                
                if abs(exp_trf-res['rx'] < threshold):
                    log.info('Traffic flow is as expected..The value of tx and Rx is : {0} and {1}'.format(res['tx'],res['rx']))
                else:
                    log.error('Traffic Flow is not as expected. The value of tx and Rx is : {0} and {1}'.format(res['tx'],res['rx']))
                    flag = 1 
                
                log.info('Deleting the Created Stream for this test: ')

                x1 = tgn_hdl.traffic_control(action='stop', handle = trf_hdl,max_wait_timer=60)
                sw_hdl.configure('no vlan configuration {0}'.format(igmp_vlan))
                
                countDownTimer(30)

                log.info('Removing the stream:')
                y = tgn_hdl.traffic_config(mode='remove',stream_id=nested_vxlan_traffic_config8['stream_id'])
                        
                log.info('STarting all the other streams')
                z = tgn_hdl.traffic_control(action='run',max_wait_timer=60)
                
                log.info('waiting for 30 seconds before collecting the stats:')
                countDownTimer(30)
                out = trigger_obj.checkAllStreamStats(tgn_hdl)
                
                if not out:
                    log.error(banner('Traffic has not recovered on some of the streams after starting the Original Streams.. Collecting the individual STream stats:'))
                    self.failed()
                        
                if flag:
                    log.error(banner('Nested Traffic Flow was not as expected. Hence failing'))
                    self.failed()
            else:
                log.error('The Initial Traffic Condition did not pass:')
                self.failed()     
                                
                                
class VXLANVxlanV6FUNC133(aetest.Testcase):

    """ Nested Vxlan V4 InnerVxlan Header- Orphan to Orphan """

    uid = 'VXLAN-L3-VxlanV6-FUNC-133'
    
    @aetest.test
    def NestedVxlanOrphanToOrphanV4PayloadV4InnerVxlanHeader(self,log,testscript,testbed):
        
        node_dict = testscript.parameters['node_dict']
        tg_interface_hdl_dict = testscript.parameters['tg_interface_hdl_dict'] 
        traffic_stream_dict = testscript.parameters['traffic_stream_dict'] 
        port_handle_dict = testscript.parameters['port_handle_dict']
        TGList_config_file = testscript.parameters['TGList']
        configdict = testscript.parameters['configdict'] 
        tgn_config_dict = configdict['TG']
        threshold = testscript.parameters['traffic_threshold'] 
        tgn_port_dut_mapping = testscript.parameters['tgn_port_dut_mapping']
        alias_intf_mapping_dict = testscript.parameters['alias_intf_mapping']
        configured_stream = testscript.parameters['configured_stream']
        trigger_obj = testscript.parameters['trigger_obj']
        testbed_obj = testscript.parameters['testbed_obj']

        log.info(banner('The value of configured stream is : {0}'.format(configured_stream))) 
        
        res = [node_dict['all_dut'][dut].execute('show version') for dut in node_dict['all_dut'] if re.search('uut', dut)]
        
        for TG in tgn_config_dict.keys():
            tgn_hdl = testscript.parameters['testbed_obj'].devices[TG]
            out = trigger_obj.checkAllStreamStats(tgn_hdl)
            flag = 0
            if out:
                
                log.info(banner('Stopping all the Traffic:'))
                
                a = tgn_hdl.traffic_control(action='stop',max_wait_timer=60)
                
                source_port = testscript.parameters['configdict']['TG'][TG]['TEST-026']['traffic_config_dict']['source']
                receiver_port = testscript.parameters['configdict']['TG'][TG]['TEST-026']['traffic_config_dict']['capable_receivers']
                actual_receiver = testscript.parameters['configdict']['TG'][TG]['TEST-026']['traffic_config_dict']['actual_receiver'][0]
                traffic_args=testscript.parameters['configdict']['TG'][TG]['TEST-026']['traffic_config_dict']['params']
                
                src_port = [port_handle_dict[x] for x in source_port]
                dst_port = [port_handle_dict[x] for x in receiver_port]
                log.info('The value of src_port is : {0}'.format(src_port))
                log.info('The value of dst_port is : {0}'.format(dst_port))                
                
                log.info(banner('Creating an Host Interface on Ixia:'))
                intf_params = traffic_args['host_params']
                ixia_intf_conf = configureIxNetworkInterface(self,intf_params,tg_hdl = tgn_hdl,port_handle = port_handle_dict[actual_receiver])
                traffic_config_obj = MyLib.my_config_utils.TrafficConfiguration(log,testscript,configdict,port_handle_dict)
                i = 0
                log.info(banner('Sending ARP Requets for the created hosts:'))
                while (i < 5):
                    log.info(banner('Iteration # {0}'.format(i+1)))
                    res = traffic_config_obj.sendArpRequest(tg_hdl=tgn_hdl,port_handle=port_handle_dict[actual_receiver])
                    countDownTimer(1)
                    i+=1
#                 dut = tgn_port_dut_mapping[actual_receiver]
#                 node_dict['all_dut'][dut].execute('ping 195.100.1.150 vrf all')
                log.info(banner('Waiting for 30 seconds before Creating the Nested Vxlan traffic : '))
                countDownTimer(30)
                
                log.info(banner('Creating Nested Vxlan Traffic:'))

                traffic_gen_object = MyLib.my_config_utils.IxiaRawTrafficGeneration(log,tgn_hdl,configdict,port_handle_dict)
                
                end_point_args = traffic_args['Traffic_End_points']
                log.info(banner('The value of end_point_args is : {0}'.format(end_point_args)))
                
                nested_vxlan_traffic_config = traffic_gen_object.configureTrafficEndPoints(end_point_args,emulation_src_handle=src_port, emulation_dst_handle=dst_port)
                log.info('The value of ixia_traffic_config is : {0}'.format(nested_vxlan_traffic_config))
                
                if nested_vxlan_traffic_config['status'] == 1:
                    log.info(banner('Traffic End points is configured as expected.. configuring the STream params'))
                    trf_hdl = nested_vxlan_traffic_config['traffic_item']
                    traffic_stream_args  = traffic_args['StreamParameters']
                    nested_vxlan_traffic_config1 = traffic_gen_object.configureTrafficStreamParameters(trf_hdl,traffic_stream_args)
                    if nested_vxlan_traffic_config1['status'] == 1:
                        log.info(banner('Configuring the Ethernet Header -- Stack 1 '))
                        ethernet1_header_args = traffic_args['EthernetHeader1']
                        nested_vxlan_traffic_config2 = traffic_gen_object.configureEthernetHeader(trf_hdl,ethernet1_header_args)
                        if nested_vxlan_traffic_config2['status'] == 1:
                            log.info(banner('Configuring the Vlan Header -- Stack 2 '))
                            vlan_header_args = traffic_args['VlanHeader']
                            nested_vxlan_traffic_config3 = traffic_gen_object.configureVlanHeader(trf_hdl,vlan_header_args)
                            if nested_vxlan_traffic_config3['status'] == 1:
                                log.info(banner('Configuring the inner IPv6 Header -- Stack 3'))
                                ip1_header_args = traffic_args['IPHeader1']
                                nested_vxlan_traffic_config4 = traffic_gen_object.configureIPv4ProtocolHeader(trf_hdl,ip1_header_args)
                                if nested_vxlan_traffic_config4['status'] == 1:
                                    log.info(banner('Configuring the UDP Header -- Stack 4'))
                                    udp_header_args = traffic_args['UDPHeader']
                                    nested_vxlan_traffic_config5 = traffic_gen_object.configureUDPHeader(trf_hdl,udp_header_args)
                                    if nested_vxlan_traffic_config5['status'] == 1:
                                        log.info(banner('Configuring the Inner Vxlan Header -- Stack 5'))
                                        vxlan_header_args = traffic_args['VxlanHeader']
                                        nested_vxlan_traffic_config6 = traffic_gen_object.configureVxlanHeader(trf_hdl,vxlan_header_args)
                                        ls = nested_vxlan_traffic_config6['last_stack']
                                        if nested_vxlan_traffic_config6['status'] == 1:
                                            log.info(banner('Configuring the Inner VNI header - Stack 5a'))
                                            vni_header_args = traffic_args['VNIHeader']
                                            nested_vxlan_traffic_config7 = traffic_gen_object.configureVxlanVNIHeader(trf_hdl,vni_header_args,ls)
                                            if nested_vxlan_traffic_config7['status'] == 1:
                                                log.info(banner('Configuring the Ethernet Header 2- Stack 6'))
                                                ethernet2_header_args = traffic_args['EthernetHeader2']
                                                nested_vxlan_traffic_config8 = traffic_gen_object.configureEthernetHeader(trf_hdl,ethernet2_header_args)                
                                                if nested_vxlan_traffic_config8['status'] == 1:
                                                    log.info(banner('Configuring the IP Header 2- Stack 7'))
                                                    ip2_header_args = traffic_args['IPHeader2']
                                                    nested_vxlan_traffic_config8 = traffic_gen_object.configureIPv4ProtocolHeader(trf_hdl,ip2_header_args)
                
                
                
                log.info('The value of nested_vxlan_traffic_config is : {0}'.format(nested_vxlan_traffic_config8))

                log.info(banner('Waiting for 20 seconds before collecting the stats'))
                countDownTimer(20)
                b = tgn_hdl.traffic_control(action='run', handle = trf_hdl, max_wait_timer=60)
                
                stream_dict = {}
                stream_dict.setdefault('TEST-026',{})
                stream_dict['TEST-026']['stream_id'] = nested_vxlan_traffic_config8['stream_id']
                
                res = MyLib.my_config_utils.getTrafficItemStatistics(log,tgn_hdl,stream_dict,'TEST-026')
                
                if abs(res['tx']-res['rx']) < threshold:
                    log.info('Traffic flow is as expected..The value of tx and Rx is : {0} and {1}'.format(res['tx'],res['rx']))
                else:
                    log.error('Traffic Flow is not as expected. The value of tx and Rx is : {0} and {1}'.format(res['tx'],res['rx']))
                    flag = 1 
                
                log.info('Deleting the Created Stream for this test: ')

                x1 = tgn_hdl.traffic_control(action='stop', handle = trf_hdl,max_wait_timer=60)
                
                countDownTimer(30)

                log.info('Removing the stream:')
                y = tgn_hdl.traffic_config(mode='remove',stream_id=nested_vxlan_traffic_config8['stream_id'])
                
                        
                log.info('STarting all the other streams')
                z = tgn_hdl.traffic_control(action='run',max_wait_timer=60)
                
                log.info('waiting for 30 seconds before collecting the stats:')
                countDownTimer(30)
                out = trigger_obj.checkAllStreamStats(tgn_hdl)
                
                if not out:
                    log.error(banner('Traffic has not recovered on some of the streams after starting the Original Streams.. Collecting the individual STream stats:'))
                    self.failed()
                        
                if flag:
                    log.error(banner('Nested Traffic Flow was not as expected. Hence failing'))
                    self.failed()
            else:
                log.error('The Initial Traffic Condition did not pass:')
                self.failed()                                   

class VXLANVxlanV6FUNC134(aetest.Testcase):

    """ Nested Vxlan V4 InnerVxlan Header- Orphan to VPC Port """

    uid = 'VXLAN-L3-VxlanV6-FUNC-134'
    
    @aetest.test
    def NestedVxlanOrphanToVPCPortV4PayloadV4InnerVxlanHeader(self,log,testscript,testbed):
        
        node_dict = testscript.parameters['node_dict']
        tg_interface_hdl_dict = testscript.parameters['tg_interface_hdl_dict'] 
        traffic_stream_dict = testscript.parameters['traffic_stream_dict'] 
        port_handle_dict = testscript.parameters['port_handle_dict']
        TGList_config_file = testscript.parameters['TGList']
        configdict = testscript.parameters['configdict'] 
        tgn_config_dict = configdict['TG']
        threshold = testscript.parameters['traffic_threshold'] 
        tgn_port_dut_mapping = testscript.parameters['tgn_port_dut_mapping']
        alias_intf_mapping_dict = testscript.parameters['alias_intf_mapping']
        configured_stream = testscript.parameters['configured_stream']
        trigger_obj = testscript.parameters['trigger_obj']
        testbed_obj = testscript.parameters['testbed_obj']

        log.info(banner('The value of configured stream is : {0}'.format(configured_stream))) 
        
        res = [node_dict['all_dut'][dut].execute('show version') for dut in node_dict['all_dut'] if re.search('uut', dut)]
        
        for TG in tgn_config_dict.keys():
            tgn_hdl = testscript.parameters['testbed_obj'].devices[TG]
            out = trigger_obj.checkAllStreamStats(tgn_hdl)
            flag = 0
            if out:
                
                log.info(banner('Stopping all the Traffic:'))
                
                a = tgn_hdl.traffic_control(action='stop',max_wait_timer=60)
                
                source_port = testscript.parameters['configdict']['TG'][TG]['TEST-027']['traffic_config_dict']['source']
                receiver_port = testscript.parameters['configdict']['TG'][TG]['TEST-027']['traffic_config_dict']['capable_receivers']
                actual_receiver = testscript.parameters['configdict']['TG'][TG]['TEST-027']['traffic_config_dict']['actual_receiver'][0]
                traffic_args=testscript.parameters['configdict']['TG'][TG]['TEST-027']['traffic_config_dict']['params']
                
                src_port = [port_handle_dict[x] for x in source_port]
                dst_port = [port_handle_dict[x] for x in receiver_port]
                log.info('The value of src_port is : {0}'.format(src_port))
                log.info('The value of dst_port is : {0}'.format(dst_port))                
                
                log.info(banner('Creating an Host Interface on Ixia:'))
                intf_params = traffic_args['host_params']
                ixia_intf_conf = configureIxNetworkInterface(self,intf_params,tg_hdl = tgn_hdl,port_handle = port_handle_dict[actual_receiver])
                traffic_config_obj = MyLib.my_config_utils.TrafficConfiguration(log,testscript,configdict,port_handle_dict)
                i = 0
                log.info(banner('Sending ARP Requets for the created hosts:'))
                while (i < 5):
                    log.info(banner('Iteration # {0}'.format(i+1)))
                    res = traffic_config_obj.sendArpRequest(tg_hdl=tgn_hdl,port_handle=port_handle_dict[actual_receiver])
                    countDownTimer(1)
                    i+=1
#                 dut = tgn_port_dut_mapping[actual_receiver]
#                 node_dict['all_dut'][dut].execute('ping 195.100.1.150 vrf all')
                log.info(banner('Waiting for 30 seconds before Creating the Nested Vxlan traffic : '))
                countDownTimer(30)
                
                log.info(banner('Creating Nested Vxlan Traffic:'))

                traffic_gen_object = MyLib.my_config_utils.IxiaRawTrafficGeneration(log,tgn_hdl,configdict,port_handle_dict)
                
                end_point_args = traffic_args['Traffic_End_points']
                log.info(banner('The value of end_point_args is : {0}'.format(end_point_args)))
                
                nested_vxlan_traffic_config = traffic_gen_object.configureTrafficEndPoints(end_point_args,emulation_src_handle=src_port, emulation_dst_handle=dst_port)
                log.info('The value of ixia_traffic_config is : {0}'.format(nested_vxlan_traffic_config))
                
                if nested_vxlan_traffic_config['status'] == 1:
                    log.info(banner('Traffic End points is configured as expected.. configuring the STream params'))
                    trf_hdl = nested_vxlan_traffic_config['traffic_item']
                    traffic_stream_args  = traffic_args['StreamParameters']
                    nested_vxlan_traffic_config1 = traffic_gen_object.configureTrafficStreamParameters(trf_hdl,traffic_stream_args)
                    if nested_vxlan_traffic_config1['status'] == 1:
                        log.info(banner('Configuring the Ethernet Header -- Stack 1 '))
                        ethernet1_header_args = traffic_args['EthernetHeader1']
                        nested_vxlan_traffic_config2 = traffic_gen_object.configureEthernetHeader(trf_hdl,ethernet1_header_args)
                        if nested_vxlan_traffic_config2['status'] == 1:
                            log.info(banner('Configuring the Vlan Header -- Stack 2 '))
                            vlan_header_args = traffic_args['VlanHeader']
                            nested_vxlan_traffic_config3 = traffic_gen_object.configureVlanHeader(trf_hdl,vlan_header_args)
                            if nested_vxlan_traffic_config3['status'] == 1:
                                log.info(banner('Configuring the inner IPv6 Header -- Stack 3'))
                                ip1_header_args = traffic_args['IPHeader1']
                                nested_vxlan_traffic_config4 = traffic_gen_object.configureIPv4ProtocolHeader(trf_hdl,ip1_header_args)
                                if nested_vxlan_traffic_config4['status'] == 1:
                                    log.info(banner('Configuring the UDP Header -- Stack 4'))
                                    udp_header_args = traffic_args['UDPHeader']
                                    nested_vxlan_traffic_config5 = traffic_gen_object.configureUDPHeader(trf_hdl,udp_header_args)
                                    if nested_vxlan_traffic_config5['status'] == 1:
                                        log.info(banner('Configuring the Inner Vxlan Header -- Stack 5'))
                                        vxlan_header_args = traffic_args['VxlanHeader']
                                        nested_vxlan_traffic_config6 = traffic_gen_object.configureVxlanHeader(trf_hdl,vxlan_header_args)
                                        ls = nested_vxlan_traffic_config6['last_stack']
                                        if nested_vxlan_traffic_config6['status'] == 1:
                                            log.info(banner('Configuring the Inner VNI header - Stack 5a'))
                                            vni_header_args = traffic_args['VNIHeader']
                                            nested_vxlan_traffic_config7 = traffic_gen_object.configureVxlanVNIHeader(trf_hdl,vni_header_args,ls)
                                            if nested_vxlan_traffic_config7['status'] == 1:
                                                log.info(banner('Configuring the Ethernet Header 2- Stack 6'))
                                                ethernet2_header_args = traffic_args['EthernetHeader2']
                                                nested_vxlan_traffic_config8 = traffic_gen_object.configureEthernetHeader(trf_hdl,ethernet2_header_args)                
                                                if nested_vxlan_traffic_config8['status'] == 1:
                                                    log.info(banner('Configuring the IP Header 2- Stack 7'))
                                                    ip2_header_args = traffic_args['IPHeader2']
                                                    nested_vxlan_traffic_config8 = traffic_gen_object.configureIPv4ProtocolHeader(trf_hdl,ip2_header_args)
                
                
                
                log.info('The value of nested_vxlan_traffic_config is : {0}'.format(nested_vxlan_traffic_config8))

                log.info(banner('Waiting for 20 seconds before collecting the stats'))
                countDownTimer(20)
                b = tgn_hdl.traffic_control(action='run', handle = trf_hdl, max_wait_timer=60)
                
                stream_dict = {}
                stream_dict.setdefault('TEST-027',{})
                stream_dict['TEST-027']['stream_id'] = nested_vxlan_traffic_config8['stream_id']
                
                res = MyLib.my_config_utils.getTrafficItemStatistics(log,tgn_hdl,stream_dict,'TEST-027')
                
                if abs(res['tx']-res['rx']) < threshold:
                    log.info('Traffic flow is as expected..The value of tx and Rx is : {0} and {1}'.format(res['tx'],res['rx']))
                else:
                    log.error('Traffic Flow is not as expected. The value of tx and Rx is : {0} and {1}'.format(res['tx'],res['rx']))
                    flag = 1 
                
                log.info('Deleting the Created Stream for this test: ')

                x1 = tgn_hdl.traffic_control(action='stop', handle = trf_hdl,max_wait_timer=60)
                
                countDownTimer(30)

                log.info('Removing the stream:')
                y = tgn_hdl.traffic_config(mode='remove',stream_id=nested_vxlan_traffic_config8['stream_id'])
                
                        
                log.info('STarting all the other streams')
                z = tgn_hdl.traffic_control(action='run',max_wait_timer=60)
                
                log.info('waiting for 30 seconds before collecting the stats:')
                countDownTimer(30)
                out = trigger_obj.checkAllStreamStats(tgn_hdl)
                
                if not out:
                    log.error(banner('Traffic has not recovered on some of the streams after starting the Original Streams.. Collecting the individual STream stats:'))
                    self.failed()
                        
                if flag:
                    log.error(banner('Nested Traffic Flow was not as expected. Hence failing'))
                    self.failed()
            else:
                log.error('The Initial Traffic Condition did not pass:')
                self.failed() 

class VXLANVxlanV6FUNC135(aetest.Testcase):

    """ Nested Vxlan V4 InnerVxlan Header- Orphan to Remote VTEP   """

    uid = 'VXLAN-L3-VxlanV6-FUNC-135'
    
    @aetest.test
    def NestedVxlanOrphanToremoteVTEPV4PayloadV4InnerVxlanHeader(self,log,testscript,testbed):
        
        node_dict = testscript.parameters['node_dict']
        tg_interface_hdl_dict = testscript.parameters['tg_interface_hdl_dict'] 
        traffic_stream_dict = testscript.parameters['traffic_stream_dict'] 
        port_handle_dict = testscript.parameters['port_handle_dict']
        TGList_config_file = testscript.parameters['TGList']
        configdict = testscript.parameters['configdict'] 
        tgn_config_dict = configdict['TG']
        threshold = testscript.parameters['traffic_threshold'] 
        tgn_port_dut_mapping = testscript.parameters['tgn_port_dut_mapping']
        alias_intf_mapping_dict = testscript.parameters['alias_intf_mapping']
        configured_stream = testscript.parameters['configured_stream']
        trigger_obj = testscript.parameters['trigger_obj']
        testbed_obj = testscript.parameters['testbed_obj']

        log.info(banner('The value of configured stream is : {0}'.format(configured_stream))) 
        
        res = [node_dict['all_dut'][dut].execute('show version') for dut in node_dict['all_dut'] if re.search('uut', dut)]
        
        for TG in tgn_config_dict.keys():
            tgn_hdl = testscript.parameters['testbed_obj'].devices[TG]
            out = trigger_obj.checkAllStreamStats(tgn_hdl)
            flag = 0
            if out:
                
                log.info(banner('Stopping all the Traffic:'))
                
                a = tgn_hdl.traffic_control(action='stop',max_wait_timer=60)
                
                log.info(banner('Waiting for 30 seconds before Creating the Nested Vxlan traffic : '))
                countDownTimer(30)
                
                log.info(banner('Creating Nested Vxlan Traffic:'))
                    
                source_port = testscript.parameters['configdict']['TG'][TG]['TEST-028']['traffic_config_dict']['source']
                receiver_port = testscript.parameters['configdict']['TG'][TG]['TEST-028']['traffic_config_dict']['capable_receivers']
                traffic_args=testscript.parameters['configdict']['TG'][TG]['TEST-028']['traffic_config_dict']['params']
                 
                src_port = [port_handle_dict[x] for x in source_port]
                dst_port = [port_handle_dict[x] for x in receiver_port]
                log.info('The value of src_port is : {0}'.format(src_port))
                log.info('The value of dst_port is : {0}'.format(dst_port))
                
                traffic_gen_object = MyLib.my_config_utils.IxiaRawTrafficGeneration(log,tgn_hdl,configdict,port_handle_dict)
                
                end_point_args = traffic_args['Traffic_End_points']
                log.info(banner('The value of end_point_args is : {0}'.format(end_point_args)))
                
                nested_vxlan_traffic_config = traffic_gen_object.configureTrafficEndPoints(end_point_args,emulation_src_handle=src_port, emulation_dst_handle=dst_port)
                log.info('The value of ixia_traffic_config is : {0}'.format(nested_vxlan_traffic_config))
                
                if nested_vxlan_traffic_config['status'] == 1:
                    log.info(banner('Traffic End points is configured as expected.. configuring the STream params'))
                    trf_hdl = nested_vxlan_traffic_config['traffic_item']
                    traffic_stream_args  = traffic_args['StreamParameters']
                    nested_vxlan_traffic_config1 = traffic_gen_object.configureTrafficStreamParameters(trf_hdl,traffic_stream_args)
                    if nested_vxlan_traffic_config1['status'] == 1:
                        log.info(banner('Configuring the Ethernet Header -- Stack 1 '))
                        ethernet1_header_args = traffic_args['EthernetHeader1']
                        nested_vxlan_traffic_config2 = traffic_gen_object.configureEthernetHeader(trf_hdl,ethernet1_header_args)
                        if nested_vxlan_traffic_config2['status'] == 1:
                            log.info(banner('Configuring the Vlan Header -- Stack 2 '))
                            vlan_header_args = traffic_args['VlanHeader']
                            nested_vxlan_traffic_config3 = traffic_gen_object.configureVlanHeader(trf_hdl,vlan_header_args)
                            if nested_vxlan_traffic_config3['status'] == 1:
                                log.info(banner('Configuring the inner IPv6 Header -- Stack 3'))
                                ip1_header_args = traffic_args['IPHeader1']
                                nested_vxlan_traffic_config4 = traffic_gen_object.configureIPv4ProtocolHeader(trf_hdl,ip1_header_args)
                                if nested_vxlan_traffic_config4['status'] == 1:
                                    log.info(banner('Configuring the UDP Header -- Stack 4'))
                                    udp_header_args = traffic_args['UDPHeader']
                                    nested_vxlan_traffic_config5 = traffic_gen_object.configureUDPHeader(trf_hdl,udp_header_args)
                                    if nested_vxlan_traffic_config5['status'] == 1:
                                        log.info(banner('Configuring the Inner Vxlan Header -- Stack 5'))
                                        vxlan_header_args = traffic_args['VxlanHeader']
                                        nested_vxlan_traffic_config6 = traffic_gen_object.configureVxlanHeader(trf_hdl,vxlan_header_args)
                                        ls = nested_vxlan_traffic_config6['last_stack']
                                        if nested_vxlan_traffic_config6['status'] == 1:
                                            log.info(banner('Configuring the Inner VNI header - Stack 5a'))
                                            vni_header_args = traffic_args['VNIHeader']
                                            nested_vxlan_traffic_config7 = traffic_gen_object.configureVxlanVNIHeader(trf_hdl,vni_header_args,ls)
                                            if nested_vxlan_traffic_config7['status'] == 1:
                                                log.info(banner('Configuring the Ethernet Header 2- Stack 6'))
                                                ethernet2_header_args = traffic_args['EthernetHeader2']
                                                nested_vxlan_traffic_config8 = traffic_gen_object.configureEthernetHeader(trf_hdl,ethernet2_header_args)                
                                                if nested_vxlan_traffic_config8['status'] == 1:
                                                    log.info(banner('Configuring the IP Header 2- Stack 7'))
                                                    ip2_header_args = traffic_args['IPHeader2']
                                                    nested_vxlan_traffic_config8 = traffic_gen_object.configureIPv4ProtocolHeader(trf_hdl,ip2_header_args)
                
                
                
                log.info('The value of nested_vxlan_traffic_config is : {0}'.format(nested_vxlan_traffic_config8))
                ethernet_args = traffic_args['EthernetHeader1']                                   
                ns = MyLib.my_config_utils.parseEthernetHeaderArgs(log,ethernet_args)
                dmac = ns.mac_dst
                actual_receiver = testscript.parameters['configdict']['TG'][TG]['TEST-028']['traffic_config_dict']['actual_receiver'][0]
                
                dut_to_configure_static_mac = tgn_port_dut_mapping[actual_receiver]
                log.info('the value of dut_to_configure is : {0}'.format(dut_to_configure_static_mac))
                            
                for item in testbed_obj.devices.aliases:
                    log.info('The value of item is : {0}'.format(item))
                    if re.search(dut_to_configure_static_mac,item):
                        for i in testbed_obj.devices[item].interfaces.keys():
                            log.info('The value if i is : {0}'.format(i))
                            if re.search('TG',testbed_obj.devices[item].interfaces[i].alias):
                                port = i
                                log.info('The value of port is : {0}'.format(port))
                        
                
                cfg = 'mac address-table static {0} vlan 701 interface {1}'.format(dmac,port)
                node_dict['all_dut'][dut_to_configure_static_mac].configure(cfg)
                log.info(banner('Waiting for 20 seconds before collecting the stats'))
                countDownTimer(20)
                b = tgn_hdl.traffic_control(action='run', handle = trf_hdl, max_wait_timer=60)
                
                stream_dict = {}
                stream_dict.setdefault('TEST-028',{})
                stream_dict['TEST-028']['stream_id'] = nested_vxlan_traffic_config8['stream_id']
                
                res = MyLib.my_config_utils.getTrafficItemStatistics(log,tgn_hdl,stream_dict,'TEST-028')
                
                if abs(res['tx']-res['rx'] < threshold):
                    log.info('Traffic flow is as expected..The value of tx and Rx is : {0} and {1}'.format(res['tx'],res['rx']))
                else:
                    log.info('Traffic Flow is not as expected. The value of tx and Rx is : {0} and {1}'.format(res['tx'],res['rx']))
                    flag = 1 
                
                log.info('Deleting the Created Stream for this test: ')

                x1 = tgn_hdl.traffic_control(action='stop', handle = trf_hdl,max_wait_timer=60)
                
                countDownTimer(30)

                log.info('Removing the stream:')
                y = tgn_hdl.traffic_config(mode='remove',stream_id=nested_vxlan_traffic_config8['stream_id'])
                
                node_dict['all_dut'][dut_to_configure_static_mac].configure('no '+cfg)
                        
                log.info('STarting all the other streams')
                z = tgn_hdl.traffic_control(action='run',max_wait_timer=60)
                
                log.info('waiting for 30 seconds before collecting the stats:')
                countDownTimer(30)
                out = trigger_obj.checkAllStreamStats(tgn_hdl)
                
                if not out:
                    log.error(banner('Traffic has not recovered on some of the streams after starting the Original Streams.. Collecting the individual STream stats:'))
                    self.failed()
                        
                if flag:
                    log.error(banner('Nested Traffic Flow was not as expected. Hence failing'))
                    self.failed()
            else:
                log.error('The Initial Traffic Condition did not pass:')
                self.failed()                                   

class VXLANVxlanV6FUNC136(aetest.Testcase):

    """ Nested Vxlan - VPC Port to Remote VTEP """

    uid = 'VXLAN-L3-VxlanV6-FUNC-136'
    
    @aetest.test
    def NestedVxlanVPCPortToRemoteVTEPV4PayloadV4InnerVxlanHeader(self,log,testscript,testbed):
        
        node_dict = testscript.parameters['node_dict']
        tg_interface_hdl_dict = testscript.parameters['tg_interface_hdl_dict'] 
        traffic_stream_dict = testscript.parameters['traffic_stream_dict'] 
        port_handle_dict = testscript.parameters['port_handle_dict']
        TGList_config_file = testscript.parameters['TGList']
        configdict = testscript.parameters['configdict'] 
        tgn_config_dict = configdict['TG']
        threshold = testscript.parameters['traffic_threshold'] 
        tgn_port_dut_mapping = testscript.parameters['tgn_port_dut_mapping']
        alias_intf_mapping_dict = testscript.parameters['alias_intf_mapping']
        configured_stream = testscript.parameters['configured_stream']
        trigger_obj = testscript.parameters['trigger_obj']
        testbed_obj = testscript.parameters['testbed_obj']

        log.info(banner('The value of configured stream is : {0}'.format(configured_stream))) 
        
        res = [node_dict['all_dut'][dut].execute('show version') for dut in node_dict['all_dut'] if re.search('uut', dut)]
        
        for TG in tgn_config_dict.keys():
            tgn_hdl = testscript.parameters['testbed_obj'].devices[TG]
            out = trigger_obj.checkAllStreamStats(tgn_hdl)
            flag = 0
            if out:
                
                log.info(banner('Stopping all the Traffic:'))
                
                a = tgn_hdl.traffic_control(action='stop',max_wait_timer=60)
                
                log.info(banner('Waiting for 30 seconds before Creating the Nested Vxlan traffic : '))
                countDownTimer(30)
                
                log.info(banner('Creating Nested Vxlan Traffic:'))
                    
                source_port = testscript.parameters['configdict']['TG'][TG]['TEST-029']['traffic_config_dict']['source']
                receiver_port = testscript.parameters['configdict']['TG'][TG]['TEST-029']['traffic_config_dict']['capable_receivers']
                traffic_args=testscript.parameters['configdict']['TG'][TG]['TEST-029']['traffic_config_dict']['params']
                 
                src_port = [port_handle_dict[x] for x in source_port]
                dst_port = [port_handle_dict[x] for x in receiver_port]
                log.info('The value of src_port is : {0}'.format(src_port))
                log.info('The value of dst_port is : {0}'.format(dst_port))
                
                traffic_gen_object = MyLib.my_config_utils.IxiaRawTrafficGeneration(log,tgn_hdl,configdict,port_handle_dict)
                
                end_point_args = traffic_args['Traffic_End_points']
                log.info(banner('The value of end_point_args is : {0}'.format(end_point_args)))
                
                nested_vxlan_traffic_config = traffic_gen_object.configureTrafficEndPoints(end_point_args,emulation_src_handle=src_port, emulation_dst_handle=dst_port)
                log.info('The value of ixia_traffic_config is : {0}'.format(nested_vxlan_traffic_config))
                
                if nested_vxlan_traffic_config['status'] == 1:
                    log.info(banner('Traffic End points is configured as expected.. configuring the STream params'))
                    trf_hdl = nested_vxlan_traffic_config['traffic_item']
                    traffic_stream_args  = traffic_args['StreamParameters']
                    nested_vxlan_traffic_config1 = traffic_gen_object.configureTrafficStreamParameters(trf_hdl,traffic_stream_args)
                    if nested_vxlan_traffic_config1['status'] == 1:
                        log.info(banner('Configuring the Ethernet Header -- Stack 1 '))
                        ethernet1_header_args = traffic_args['EthernetHeader1']
                        nested_vxlan_traffic_config2 = traffic_gen_object.configureEthernetHeader(trf_hdl,ethernet1_header_args)
                        if nested_vxlan_traffic_config2['status'] == 1:
                            log.info(banner('Configuring the Vlan Header -- Stack 2 '))
                            vlan_header_args = traffic_args['VlanHeader']
                            nested_vxlan_traffic_config3 = traffic_gen_object.configureVlanHeader(trf_hdl,vlan_header_args)
                            if nested_vxlan_traffic_config3['status'] == 1:
                                log.info(banner('Configuring the inner IPv6 Header -- Stack 3'))
                                ip1_header_args = traffic_args['IPHeader1']
                                nested_vxlan_traffic_config4 = traffic_gen_object.configureIPv4ProtocolHeader(trf_hdl,ip1_header_args)
                                if nested_vxlan_traffic_config4['status'] == 1:
                                    log.info(banner('Configuring the UDP Header -- Stack 4'))
                                    udp_header_args = traffic_args['UDPHeader']
                                    nested_vxlan_traffic_config5 = traffic_gen_object.configureUDPHeader(trf_hdl,udp_header_args)
                                    if nested_vxlan_traffic_config5['status'] == 1:
                                        log.info(banner('Configuring the Inner Vxlan Header -- Stack 5'))
                                        vxlan_header_args = traffic_args['VxlanHeader']
                                        nested_vxlan_traffic_config6 = traffic_gen_object.configureVxlanHeader(trf_hdl,vxlan_header_args)
                                        ls = nested_vxlan_traffic_config6['last_stack']
                                        if nested_vxlan_traffic_config6['status'] == 1:
                                            log.info(banner('Configuring the Inner VNI header - Stack 5a'))
                                            vni_header_args = traffic_args['VNIHeader']
                                            nested_vxlan_traffic_config7 = traffic_gen_object.configureVxlanVNIHeader(trf_hdl,vni_header_args,ls)
                                            if nested_vxlan_traffic_config7['status'] == 1:
                                                log.info(banner('Configuring the Ethernet Header 2- Stack 6'))
                                                ethernet2_header_args = traffic_args['EthernetHeader2']
                                                nested_vxlan_traffic_config8 = traffic_gen_object.configureEthernetHeader(trf_hdl,ethernet2_header_args)                
                                                if nested_vxlan_traffic_config8['status'] == 1:
                                                    log.info(banner('Configuring the IP Header 2- Stack 7'))
                                                    ip2_header_args = traffic_args['IPHeader2']
                                                    nested_vxlan_traffic_config8 = traffic_gen_object.configureIPv4ProtocolHeader(trf_hdl,ip2_header_args)
                
                
                
                log.info('The value of nested_vxlan_traffic_config is : {0}'.format(nested_vxlan_traffic_config8))
                ethernet_args = traffic_args['EthernetHeader1']                                   
                ns = MyLib.my_config_utils.parseEthernetHeaderArgs(log,ethernet_args)
                dmac = ns.mac_dst
                actual_receiver = testscript.parameters['configdict']['TG'][TG]['TEST-029']['traffic_config_dict']['actual_receiver'][0]
                
                dut_to_configure_static_mac = tgn_port_dut_mapping[actual_receiver]
                log.info('the value of dut_to_configure is : {0}'.format(dut_to_configure_static_mac))
                            
                for item in testbed_obj.devices.aliases:
                    log.info('The value of item is : {0}'.format(item))
                    if re.search(dut_to_configure_static_mac,item):
                        for i in testbed_obj.devices[item].interfaces.keys():
                            log.info('The value if i is : {0}'.format(i))
                            if re.search('TG',testbed_obj.devices[item].interfaces[i].alias):
                                port = i
                                log.info('The value of port is : {0}'.format(port))
                        
                
                cfg = 'mac address-table static {0} vlan 701 interface {1}'.format(dmac,port)
                node_dict['all_dut'][dut_to_configure_static_mac].configure(cfg)
                log.info(banner('Waiting for 20 seconds before collecting the stats'))
                countDownTimer(20)
                b = tgn_hdl.traffic_control(action='run', handle = trf_hdl, max_wait_timer=60)
                
                stream_dict = {}
                stream_dict.setdefault('TEST-029',{})
                stream_dict['TEST-029']['stream_id'] = nested_vxlan_traffic_config8['stream_id']
                
                res = MyLib.my_config_utils.getTrafficItemStatistics(log,tgn_hdl,stream_dict,'TEST-029')
                
                if abs(res['tx']-res['rx'] < threshold):
                    log.info('Traffic flow is as expected..The value of tx and Rx is : {0} and {1}'.format(res['tx'],res['rx']))
                else:
                    log.info('Traffic Flow is not as expected. The value of tx and Rx is : {0} and {1}'.format(res['tx'],res['rx']))
                    flag = 1 
                
                log.info('Deleting the Created Stream for this test: ')

                x1 = tgn_hdl.traffic_control(action='stop', handle = trf_hdl,max_wait_timer=60)
                
                countDownTimer(30)

                log.info('Removing the stream:')
                y = tgn_hdl.traffic_config(mode='remove',stream_id=nested_vxlan_traffic_config8['stream_id'])
                
                node_dict['all_dut'][dut_to_configure_static_mac].configure('no '+cfg)
                        
                log.info('STarting all the other streams')
                z = tgn_hdl.traffic_control(action='run',max_wait_timer=60)
                
                log.info('waiting for 30 seconds before collecting the stats:')
                countDownTimer(30)
                out = trigger_obj.checkAllStreamStats(tgn_hdl)
                
                if not out:
                    log.error(banner('Traffic has not recovered on some of the streams after starting the Original Streams.. Collecting the individual STream stats:'))
                    self.failed()
                        
                if flag:
                    log.error(banner('Nested Traffic Flow was not as expected. Hence failing'))
                    self.failed()
            else:
                log.error('The Initial Traffic Condition did not pass:')
                self.failed()                                   

class VXLANVxlanV6FUNC137(aetest.Testcase):

    """ Nested Vxlan - VPC Port To Everywhere - UUC """

    uid = 'VXLAN-L3-VxlanV6-FUNC-137'
    
    @aetest.test
    def NestedVxlanVPCPortToEveryWhereUUCV4PayloadV4InnerVxlanHeader(self,log,testscript,testbed):
        
        node_dict = testscript.parameters['node_dict']
        tg_interface_hdl_dict = testscript.parameters['tg_interface_hdl_dict'] 
        traffic_stream_dict = testscript.parameters['traffic_stream_dict'] 
        port_handle_dict = testscript.parameters['port_handle_dict']
        TGList_config_file = testscript.parameters['TGList']
        configdict = testscript.parameters['configdict'] 
        tgn_config_dict = configdict['TG']
        threshold = testscript.parameters['traffic_threshold'] 
        tgn_port_dut_mapping = testscript.parameters['tgn_port_dut_mapping']
        alias_intf_mapping_dict = testscript.parameters['alias_intf_mapping']
        configured_stream = testscript.parameters['configured_stream']
        trigger_obj = testscript.parameters['trigger_obj']
        testbed_obj = testscript.parameters['testbed_obj']

        log.info(banner('The value of configured stream is : {0}'.format(configured_stream))) 
        
        res = [node_dict['all_dut'][dut].execute('show version') for dut in node_dict['all_dut'] if re.search('uut', dut)]
        
        for TG in tgn_config_dict.keys():
            tgn_hdl = testscript.parameters['testbed_obj'].devices[TG]
            out = trigger_obj.checkAllStreamStats(tgn_hdl)
            flag = 0
            if out:
                
                log.info(banner('Stopping all the Traffic:'))
                
                a = tgn_hdl.traffic_control(action='stop',max_wait_timer=60)
                
                log.info(banner('Waiting for 30 seconds before Creating the Nested Vxlan traffic : '))
                countDownTimer(30)
                
                log.info(banner('Creating Nested Vxlan Traffic:'))
                    
                source_port = testscript.parameters['configdict']['TG'][TG]['TEST-030']['traffic_config_dict']['source']
                receiver_port = testscript.parameters['configdict']['TG'][TG]['TEST-030']['traffic_config_dict']['capable_receivers']
                traffic_args=testscript.parameters['configdict']['TG'][TG]['TEST-030']['traffic_config_dict']['params']
                 
                src_port = [port_handle_dict[x] for x in source_port]
                dst_port = [port_handle_dict[x] for x in receiver_port]
                log.info('The value of src_port is : {0}'.format(src_port))
                log.info('The value of dst_port is : {0}'.format(dst_port))
                
                traffic_gen_object = MyLib.my_config_utils.IxiaRawTrafficGeneration(log,tgn_hdl,configdict,port_handle_dict)
                
                end_point_args = traffic_args['Traffic_End_points']
                log.info(banner('The value of end_point_args is : {0}'.format(end_point_args)))
                
                nested_vxlan_traffic_config = traffic_gen_object.configureTrafficEndPoints(end_point_args,emulation_src_handle=src_port, emulation_dst_handle=dst_port)
                log.info('The value of ixia_traffic_config is : {0}'.format(nested_vxlan_traffic_config))
                
                if nested_vxlan_traffic_config['status'] == 1:
                    log.info(banner('Traffic End points is configured as expected.. configuring the STream params'))
                    trf_hdl = nested_vxlan_traffic_config['traffic_item']
                    traffic_stream_args  = traffic_args['StreamParameters']
                    nested_vxlan_traffic_config1 = traffic_gen_object.configureTrafficStreamParameters(trf_hdl,traffic_stream_args)
                    if nested_vxlan_traffic_config1['status'] == 1:
                        log.info(banner('Configuring the Ethernet Header -- Stack 1 '))
                        ethernet1_header_args = traffic_args['EthernetHeader1']
                        nested_vxlan_traffic_config2 = traffic_gen_object.configureEthernetHeader(trf_hdl,ethernet1_header_args)
                        if nested_vxlan_traffic_config2['status'] == 1:
                            log.info(banner('Configuring the Vlan Header -- Stack 2 '))
                            vlan_header_args = traffic_args['VlanHeader']
                            nested_vxlan_traffic_config3 = traffic_gen_object.configureVlanHeader(trf_hdl,vlan_header_args)
                            if nested_vxlan_traffic_config3['status'] == 1:
                                log.info(banner('Configuring the inner IPv6 Header -- Stack 3'))
                                ip1_header_args = traffic_args['IPHeader1']
                                nested_vxlan_traffic_config4 = traffic_gen_object.configureIPv4ProtocolHeader(trf_hdl,ip1_header_args)
                                if nested_vxlan_traffic_config4['status'] == 1:
                                    log.info(banner('Configuring the UDP Header -- Stack 4'))
                                    udp_header_args = traffic_args['UDPHeader']
                                    nested_vxlan_traffic_config5 = traffic_gen_object.configureUDPHeader(trf_hdl,udp_header_args)
                                    if nested_vxlan_traffic_config5['status'] == 1:
                                        log.info(banner('Configuring the Inner Vxlan Header -- Stack 5'))
                                        vxlan_header_args = traffic_args['VxlanHeader']
                                        nested_vxlan_traffic_config6 = traffic_gen_object.configureVxlanHeader(trf_hdl,vxlan_header_args)
                                        ls = nested_vxlan_traffic_config6['last_stack']
                                        if nested_vxlan_traffic_config6['status'] == 1:
                                            log.info(banner('Configuring the Inner VNI header - Stack 5a'))
                                            vni_header_args = traffic_args['VNIHeader']
                                            nested_vxlan_traffic_config7 = traffic_gen_object.configureVxlanVNIHeader(trf_hdl,vni_header_args,ls)
                                            if nested_vxlan_traffic_config7['status'] == 1:
                                                log.info(banner('Configuring the Ethernet Header 2- Stack 6'))
                                                ethernet2_header_args = traffic_args['EthernetHeader2']
                                                nested_vxlan_traffic_config8 = traffic_gen_object.configureEthernetHeader(trf_hdl,ethernet2_header_args)                
                                                if nested_vxlan_traffic_config8['status'] == 1:
                                                    log.info(banner('Configuring the IP Header 2- Stack 7'))
                                                    ip2_header_args = traffic_args['IPHeader2']
                                                    nested_vxlan_traffic_config8 = traffic_gen_object.configureIPv4ProtocolHeader(trf_hdl,ip2_header_args)
                
                                
                actual_receiver = testscript.parameters['configdict']['TG'][TG]['TEST-023']['traffic_config_dict']['actual_receiver']
                log.info('The value of actual_receiver is : {0}'.format(actual_receiver))

                log.info(banner('Waiting for 20 seconds before collecting the stats'))
                countDownTimer(20)
                b = tgn_hdl.traffic_control(action='run', handle = trf_hdl, max_wait_timer=60)
                
                stream_dict = {}
                stream_dict.setdefault('TEST-030',{})
                stream_dict['TEST-030']['stream_id'] = nested_vxlan_traffic_config8['stream_id']
                
                res = MyLib.my_config_utils.getTrafficItemStatistics(log,tgn_hdl,stream_dict,'TEST-030')
                exp_trf = len(actual_receiver) * res['tx']
                log.info('The value of expected Traffic is : {0}'.format(exp_trf))
                
                if abs(exp_trf-res['rx'] < threshold):
                    log.info('Traffic flow is as expected..The value of tx and Rx is : {0} and {1}'.format(res['tx'],res['rx']))
                else:
                    log.error('Traffic Flow is not as expected. The value of tx and Rx is : {0} and {1}'.format(res['tx'],res['rx']))
                    flag = 1 
                
                log.info('Deleting the Created Stream for this test: ')

                x1 = tgn_hdl.traffic_control(action='stop', handle = trf_hdl,max_wait_timer=60)
                
                countDownTimer(30)

                log.info('Removing the stream:')
                y = tgn_hdl.traffic_config(mode='remove',stream_id=nested_vxlan_traffic_config8['stream_id'])
                        
                log.info('STarting all the other streams')
                z = tgn_hdl.traffic_control(action='run',max_wait_timer=60)
                
                log.info('waiting for 30 seconds before collecting the stats:')
                countDownTimer(30)
                out = trigger_obj.checkAllStreamStats(tgn_hdl)
                
                if not out:
                    log.error(banner('Traffic has not recovered on some of the streams after starting the Original Streams.. Collecting the individual STream stats:'))
                    self.failed()
                        
                if flag:
                    log.error(banner('Nested Traffic Flow was not as expected. Hence failing'))
                    self.failed()
            else:
                log.error('The Initial Traffic Condition did not pass:')
                self.failed()                                   

class VXLANVxlanV6FUNC138(aetest.Testcase):

    """ Nested Vxlan - VPC Port To Everywhere - BroadCast """

    uid = 'VXLAN-L3-VxlanV6-FUNC-138'
    
    @aetest.test
    def NestedVxlanVPCPortToEveryWhereBroadCastV4PayloadV4InnerVxlanHeader(self,log,testscript,testbed):
        
        node_dict = testscript.parameters['node_dict']
        tg_interface_hdl_dict = testscript.parameters['tg_interface_hdl_dict'] 
        traffic_stream_dict = testscript.parameters['traffic_stream_dict'] 
        port_handle_dict = testscript.parameters['port_handle_dict']
        TGList_config_file = testscript.parameters['TGList']
        configdict = testscript.parameters['configdict'] 
        tgn_config_dict = configdict['TG']
        threshold = testscript.parameters['traffic_threshold'] 
        tgn_port_dut_mapping = testscript.parameters['tgn_port_dut_mapping']
        alias_intf_mapping_dict = testscript.parameters['alias_intf_mapping']
        configured_stream = testscript.parameters['configured_stream']
        trigger_obj = testscript.parameters['trigger_obj']
        testbed_obj = testscript.parameters['testbed_obj']

        log.info(banner('The value of configured stream is : {0}'.format(configured_stream))) 
        
        res = [node_dict['all_dut'][dut].execute('show version') for dut in node_dict['all_dut'] if re.search('uut', dut)]
        
        for TG in tgn_config_dict.keys():
            tgn_hdl = testscript.parameters['testbed_obj'].devices[TG]
            out = trigger_obj.checkAllStreamStats(tgn_hdl)
            flag = 0
            if out:
                
                log.info(banner('Stopping all the Traffic:'))
                
                a = tgn_hdl.traffic_control(action='stop',max_wait_timer=60)
                
                log.info(banner('Waiting for 30 seconds before Creating the Nested Vxlan traffic : '))
                countDownTimer(30)
                
                log.info(banner('Creating Nested Vxlan Traffic:'))
                    
                source_port = testscript.parameters['configdict']['TG'][TG]['TEST-031']['traffic_config_dict']['source']
                receiver_port = testscript.parameters['configdict']['TG'][TG]['TEST-031']['traffic_config_dict']['capable_receivers']
                traffic_args=testscript.parameters['configdict']['TG'][TG]['TEST-031']['traffic_config_dict']['params']
                 
                src_port = [port_handle_dict[x] for x in source_port]
                dst_port = [port_handle_dict[x] for x in receiver_port]
                log.info('The value of src_port is : {0}'.format(src_port))
                log.info('The value of dst_port is : {0}'.format(dst_port))
                
                traffic_gen_object = MyLib.my_config_utils.IxiaRawTrafficGeneration(log,tgn_hdl,configdict,port_handle_dict)
                
                end_point_args = traffic_args['Traffic_End_points']
                log.info(banner('The value of end_point_args is : {0}'.format(end_point_args)))
                
                nested_vxlan_traffic_config = traffic_gen_object.configureTrafficEndPoints(end_point_args,emulation_src_handle=src_port, emulation_dst_handle=dst_port)
                log.info('The value of ixia_traffic_config is : {0}'.format(nested_vxlan_traffic_config))
                
                if nested_vxlan_traffic_config['status'] == 1:
                    log.info(banner('Traffic End points is configured as expected.. configuring the STream params'))
                    trf_hdl = nested_vxlan_traffic_config['traffic_item']
                    traffic_stream_args  = traffic_args['StreamParameters']
                    nested_vxlan_traffic_config1 = traffic_gen_object.configureTrafficStreamParameters(trf_hdl,traffic_stream_args)
                    if nested_vxlan_traffic_config1['status'] == 1:
                        log.info(banner('Configuring the Ethernet Header -- Stack 1 '))
                        ethernet1_header_args = traffic_args['EthernetHeader1']
                        nested_vxlan_traffic_config2 = traffic_gen_object.configureEthernetHeader(trf_hdl,ethernet1_header_args)
                        if nested_vxlan_traffic_config2['status'] == 1:
                            log.info(banner('Configuring the Vlan Header -- Stack 2 '))
                            vlan_header_args = traffic_args['VlanHeader']
                            nested_vxlan_traffic_config3 = traffic_gen_object.configureVlanHeader(trf_hdl,vlan_header_args)
                            if nested_vxlan_traffic_config3['status'] == 1:
                                log.info(banner('Configuring the inner IPv6 Header -- Stack 3'))
                                ip1_header_args = traffic_args['IPHeader1']
                                nested_vxlan_traffic_config4 = traffic_gen_object.configureIPv4ProtocolHeader(trf_hdl,ip1_header_args)
                                if nested_vxlan_traffic_config4['status'] == 1:
                                    log.info(banner('Configuring the UDP Header -- Stack 4'))
                                    udp_header_args = traffic_args['UDPHeader']
                                    nested_vxlan_traffic_config5 = traffic_gen_object.configureUDPHeader(trf_hdl,udp_header_args)
                                    if nested_vxlan_traffic_config5['status'] == 1:
                                        log.info(banner('Configuring the Inner Vxlan Header -- Stack 5'))
                                        vxlan_header_args = traffic_args['VxlanHeader']
                                        nested_vxlan_traffic_config6 = traffic_gen_object.configureVxlanHeader(trf_hdl,vxlan_header_args)
                                        ls = nested_vxlan_traffic_config6['last_stack']
                                        if nested_vxlan_traffic_config6['status'] == 1:
                                            log.info(banner('Configuring the Inner VNI header - Stack 5a'))
                                            vni_header_args = traffic_args['VNIHeader']
                                            nested_vxlan_traffic_config7 = traffic_gen_object.configureVxlanVNIHeader(trf_hdl,vni_header_args,ls)
                                            if nested_vxlan_traffic_config7['status'] == 1:
                                                log.info(banner('Configuring the Ethernet Header 2- Stack 6'))
                                                ethernet2_header_args = traffic_args['EthernetHeader2']
                                                nested_vxlan_traffic_config8 = traffic_gen_object.configureEthernetHeader(trf_hdl,ethernet2_header_args)                
                                                if nested_vxlan_traffic_config8['status'] == 1:
                                                    log.info(banner('Configuring the IP Header 2- Stack 7'))
                                                    ip2_header_args = traffic_args['IPHeader2']
                                                    nested_vxlan_traffic_config8 = traffic_gen_object.configureIPv4ProtocolHeader(trf_hdl,ip2_header_args)
                
                                
                actual_receiver = testscript.parameters['configdict']['TG'][TG]['TEST-010']['traffic_config_dict']['actual_receiver']
                log.info('The value of actual_receiver is : {0}'.format(actual_receiver))

                log.info(banner('Waiting for 20 seconds before collecting the stats'))
                countDownTimer(20)
                b = tgn_hdl.traffic_control(action='run', handle = trf_hdl, max_wait_timer=60)
                
                stream_dict = {}
                stream_dict.setdefault('TEST-031',{})
                stream_dict['TEST-031']['stream_id'] = nested_vxlan_traffic_config8['stream_id']
                
                res = MyLib.my_config_utils.getTrafficItemStatistics(log,tgn_hdl,stream_dict,'TEST-031')
                exp_trf = len(actual_receiver) * res['tx']
                log.info('The value of expected Traffic is : {0}'.format(exp_trf))
                
                if abs(exp_trf-res['rx'] < threshold):
                    log.info('Traffic flow is as expected..The value of tx and Rx is : {0} and {1}'.format(res['tx'],res['rx']))
                else:
                    log.error('Traffic Flow is not as expected. The value of tx and Rx is : {0} and {1}'.format(res['tx'],res['rx']))
                    flag = 1 
                
                log.info('Deleting the Created Stream for this test: ')

                x1 = tgn_hdl.traffic_control(action='stop', handle = trf_hdl,max_wait_timer=60)
                
                countDownTimer(30)

                log.info('Removing the stream:')
                y = tgn_hdl.traffic_config(mode='remove',stream_id=nested_vxlan_traffic_config8['stream_id'])
                        
                log.info('STarting all the other streams')
                z = tgn_hdl.traffic_control(action='run',max_wait_timer=60)
                
                log.info('waiting for 30 seconds before collecting the stats:')
                countDownTimer(30)
                out = trigger_obj.checkAllStreamStats(tgn_hdl)
                
                if not out:
                    log.error(banner('Traffic has not recovered on some of the streams after starting the Original Streams.. Collecting the individual STream stats:'))
                    self.failed()
                        
                if flag:
                    log.error(banner('Nested Traffic Flow was not as expected. Hence failing'))
                    self.failed()
            else:
                log.error('The Initial Traffic Condition did not pass:')
                self.failed()                                   

class VXLANVxlanV6FUNC139(aetest.Testcase):

    """ Nested Vxlan - VPC Port To Everywhere - Multicast """

    uid = 'VXLAN-L3-VxlanV6-FUNC-139'
    
    @aetest.test
    def NestedVxlanVPCPortToEveryWhereMultiCastV4PayloadV4InnerVxlanHeader(self,log,testscript,testbed):
        
        node_dict = testscript.parameters['node_dict']
        tg_interface_hdl_dict = testscript.parameters['tg_interface_hdl_dict'] 
        traffic_stream_dict = testscript.parameters['traffic_stream_dict'] 
        port_handle_dict = testscript.parameters['port_handle_dict']
        TGList_config_file = testscript.parameters['TGList']
        configdict = testscript.parameters['configdict'] 
        tgn_config_dict = configdict['TG']
        threshold = testscript.parameters['traffic_threshold'] 
        tgn_port_dut_mapping = testscript.parameters['tgn_port_dut_mapping']
        alias_intf_mapping_dict = testscript.parameters['alias_intf_mapping']
        configured_stream = testscript.parameters['configured_stream']
        trigger_obj = testscript.parameters['trigger_obj']
        testbed_obj = testscript.parameters['testbed_obj']

        log.info(banner('The value of configured stream is : {0}'.format(configured_stream))) 
        
        res = [node_dict['all_dut'][dut].execute('show version') for dut in node_dict['all_dut'] if re.search('uut', dut)]
        
        for TG in tgn_config_dict.keys():
            tgn_hdl = testscript.parameters['testbed_obj'].devices[TG]
            out = trigger_obj.checkAllStreamStats(tgn_hdl)
            flag = 0
            if out:
                
                log.info(banner('Stopping all the Traffic:'))
                
                a = tgn_hdl.traffic_control(action='stop',max_wait_timer=60)
                
                log.info(banner('Waiting for 30 seconds before Creating the Nested Vxlan traffic : '))
                countDownTimer(30)
                
                log.info(banner('Creating Nested Vxlan Traffic:'))
                    
                source_port = testscript.parameters['configdict']['TG'][TG]['TEST-025']['traffic_config_dict']['source']
                receiver_port = testscript.parameters['configdict']['TG'][TG]['TEST-025']['traffic_config_dict']['capable_receivers']
                traffic_args=testscript.parameters['configdict']['TG'][TG]['TEST-025']['traffic_config_dict']['params']
                 
                src_port = [port_handle_dict[x] for x in source_port]
                dst_port = [port_handle_dict[x] for x in receiver_port]
                log.info('The value of src_port is : {0}'.format(src_port))
                log.info('The value of dst_port is : {0}'.format(dst_port))
                
                traffic_gen_object = MyLib.my_config_utils.IxiaRawTrafficGeneration(log,tgn_hdl,configdict,port_handle_dict)
                
                end_point_args = traffic_args['Traffic_End_points']
                log.info(banner('The value of end_point_args is : {0}'.format(end_point_args)))
                
                nested_vxlan_traffic_config = traffic_gen_object.configureTrafficEndPoints(end_point_args,emulation_src_handle=src_port, emulation_dst_handle=dst_port)
                log.info('The value of ixia_traffic_config is : {0}'.format(nested_vxlan_traffic_config))
                
                if nested_vxlan_traffic_config['status'] == 1:
                    log.info(banner('Traffic End points is configured as expected.. configuring the STream params'))
                    trf_hdl = nested_vxlan_traffic_config['traffic_item']
                    traffic_stream_args  = traffic_args['StreamParameters']
                    nested_vxlan_traffic_config1 = traffic_gen_object.configureTrafficStreamParameters(trf_hdl,traffic_stream_args)
                    if nested_vxlan_traffic_config1['status'] == 1:
                        log.info(banner('Configuring the Ethernet Header -- Stack 1 '))
                        ethernet1_header_args = traffic_args['EthernetHeader1']
                        nested_vxlan_traffic_config2 = traffic_gen_object.configureEthernetHeader(trf_hdl,ethernet1_header_args)
                        if nested_vxlan_traffic_config2['status'] == 1:
                            log.info(banner('Configuring the Vlan Header -- Stack 2 '))
                            vlan_header_args = traffic_args['VlanHeader']
                            ns = MyLib.my_config_utils.parseVlanHeaderArgs(log,vlan_header_args)
                            igmp_vlan = ns.vlan_id
                            nested_vxlan_traffic_config3 = traffic_gen_object.configureVlanHeader(trf_hdl,vlan_header_args)
                            if nested_vxlan_traffic_config3['status'] == 1:
                                log.info(banner('Configuring the inner IPv6 Header -- Stack 3'))
                                ip1_header_args = traffic_args['IPHeader1']
                                nested_vxlan_traffic_config4 = traffic_gen_object.configureIPv4ProtocolHeader(trf_hdl,ip1_header_args)
                                if nested_vxlan_traffic_config4['status'] == 1:
                                    log.info(banner('Configuring the UDP Header -- Stack 4'))
                                    udp_header_args = traffic_args['UDPHeader']
                                    nested_vxlan_traffic_config5 = traffic_gen_object.configureUDPHeader(trf_hdl,udp_header_args)
                                    if nested_vxlan_traffic_config5['status'] == 1:
                                        log.info(banner('Configuring the Inner Vxlan Header -- Stack 5'))
                                        vxlan_header_args = traffic_args['VxlanHeader']
                                        nested_vxlan_traffic_config6 = traffic_gen_object.configureVxlanHeader(trf_hdl,vxlan_header_args)
                                        ls = nested_vxlan_traffic_config6['last_stack']
                                        if nested_vxlan_traffic_config6['status'] == 1:
                                            log.info(banner('Configuring the Inner VNI header - Stack 5a'))
                                            vni_header_args = traffic_args['VNIHeader']
                                            nested_vxlan_traffic_config7 = traffic_gen_object.configureVxlanVNIHeader(trf_hdl,vni_header_args,ls)
                                            if nested_vxlan_traffic_config7['status'] == 1:
                                                log.info(banner('Configuring the Ethernet Header 2- Stack 6'))
                                                ethernet2_header_args = traffic_args['EthernetHeader2']
                                                nested_vxlan_traffic_config8 = traffic_gen_object.configureEthernetHeader(trf_hdl,ethernet2_header_args)                
                                                if nested_vxlan_traffic_config8['status'] == 1:
                                                    log.info(banner('Configuring the IP Header 2- Stack 7'))
                                                    ip2_header_args = traffic_args['IPHeader2']
                                                    nested_vxlan_traffic_config8 = traffic_gen_object.configureIPv4ProtocolHeader(trf_hdl,ip2_header_args)
                
                                
                actual_receiver = testscript.parameters['configdict']['TG'][TG]['TEST-011']['traffic_config_dict']['actual_receiver']
                log.info('The value of actual_receiver is : {0}'.format(actual_receiver))
                
                for device, sw_hdl in trigger_obj.getDeviceDict('l2_switch').items(): pass
                cfg1 = '''vlan configuration {0}
                          no ip igmp snooping'''.format(igmp_vlan)
                
                sw_hdl.configure(cfg1)

                log.info(banner('Waiting for 20 seconds before collecting the stats'))
                countDownTimer(20)
                b = tgn_hdl.traffic_control(action='run', handle = trf_hdl, max_wait_timer=60)
                
                stream_dict = {}
                stream_dict.setdefault('TEST-025',{})
                stream_dict['TEST-025']['stream_id'] = nested_vxlan_traffic_config8['stream_id']
                
                res = MyLib.my_config_utils.getTrafficItemStatistics(log,tgn_hdl,stream_dict,'TEST-025')
                exp_trf = len(actual_receiver) * res['tx']
                log.info('The value of expected Traffic is : {0}'.format(exp_trf))
                
                if abs(exp_trf-res['rx'] < threshold):
                    log.info('Traffic flow is as expected..The value of tx and Rx is : {0} and {1}'.format(res['tx'],res['rx']))
                else:
                    log.error('Traffic Flow is not as expected. The value of tx and Rx is : {0} and {1}'.format(res['tx'],res['rx']))
                    flag = 1 
                
                log.info('Deleting the Created Stream for this test: ')

                x1 = tgn_hdl.traffic_control(action='stop', handle = trf_hdl,max_wait_timer=60)
                sw_hdl.configure('no vlan configuration {0}'.format(igmp_vlan))
                
                countDownTimer(30)

                log.info('Removing the stream:')
                y = tgn_hdl.traffic_config(mode='remove',stream_id=nested_vxlan_traffic_config8['stream_id'])
                        
                log.info('STarting all the other streams')
                z = tgn_hdl.traffic_control(action='run',max_wait_timer=60)
                
                log.info('waiting for 30 seconds before collecting the stats:')
                countDownTimer(30)
                out = trigger_obj.checkAllStreamStats(tgn_hdl)
                
                if not out:
                    log.error(banner('Traffic has not recovered on some of the streams after starting the Original Streams.. Collecting the individual STream stats:'))
                    self.failed()
                        
                if flag:
                    log.error(banner('Nested Traffic Flow was not as expected. Hence failing'))
                    self.failed()
            else:
                log.error('The Initial Traffic Condition did not pass:')
                self.failed()     

class VXLANVxlanV6FUNC140(aetest.Testcase):

    """ Host Mobility  - Moving Host from Orphan to Orphan """

    uid = 'VXLAN-L3-VxlanV6-FUNC-140'
    
    @aetest.test
    def HostMobilityOrphanToOrphan(self,log,testscript,testbed):
        
        node_dict = testscript.parameters['node_dict']
        tg_interface_hdl_dict = testscript.parameters['tg_interface_hdl_dict'] 
        traffic_stream_dict = testscript.parameters['traffic_stream_dict'] 
        port_handle_dict = testscript.parameters['port_handle_dict']
        TGList_config_file = testscript.parameters['TGList']
        configdict = testscript.parameters['configdict'] 
        tgn_config_dict = configdict['TG']
        threshold = testscript.parameters['traffic_threshold'] 
        tgn_port_dut_mapping = testscript.parameters['tgn_port_dut_mapping']
        alias_intf_mapping_dict = testscript.parameters['alias_intf_mapping']
        configured_stream = testscript.parameters['configured_stream']
        trigger_obj = testscript.parameters['trigger_obj']
        testbed_obj = testscript.parameters['testbed_obj']

        log.info(banner('The value of configured stream is : {0}'.format(configured_stream))) 
        
        res = [node_dict['all_dut'][dut].execute('show version') for dut in node_dict['all_dut'] if re.search('uut', dut)]
        
        for TG in tgn_config_dict.keys():
            tgn_hdl = testscript.parameters['testbed_obj'].devices[TG]
            out = trigger_obj.checkAllStreamStats(tgn_hdl)
            flag = 0
            if out:
                log.info(banner('Stopping all the Traffic:'))
                
                a = tgn_hdl.traffic_control(action='stop',max_wait_timer=60)
                
                log.info(banner('Waiting for 30 seconds before sending Fresh ARP Request from host on Ixia: '))
                countDownTimer(30)
                

                source_port = testscript.parameters['configdict']['TG'][TG]['TEST-034']['traffic_config_dict']['source']
                receiver_port = testscript.parameters['configdict']['TG'][TG]['TEST-034']['traffic_config_dict']['receivers']
                traffic_args=testscript.parameters['configdict']['TG'][TG]['TEST-034']['traffic_config_dict']['params']
                 
                src_port = [port_handle_dict[x] for x in source_port]
                dst_port = [port_handle_dict[x] for x in receiver_port]
                log.info('The value of src_port is : {0}'.format(src_port))
                log.info('The value of dst_port is : {0}'.format(dst_port))
                
                log.info(banner('Creating The Host Interfaces on the Traffic Gen'))
                intf_hdl_dict = {}
                for port in testscript.parameters['configdict']['TG'][TG]['TEST-034']['tg_interface_config_dict'].keys():
                    intf_args = testscript.parameters['configdict']['TG'][TG]['TEST-034']['tg_interface_config_dict'][port]
                    intf_config = configureIxNetworkInterface(log,intf_args,tg_hdl = tgn_hdl,port_handle = port_handle_dict[port])
                    intf_hdl_dict[port] = intf_config['interface_handle']
                
                log.info(banner('sending ARP Request from the Initial Receiver...'))
                
                host_mac_args = testscript.parameters['configdict']['TG'][TG]['TEST-034']['tg_interface_config_dict'][receiver_port[0]]
                log.info(banner('The value of host_mac_args is : {0}'.format(host_mac_args)))
                ns = MyLib.my_config_utils.parseHostInterfaceArg(log,host_mac_args)
                log.info(banner('The value of ns is :{0}'.format(ns)))
                src_mac = ns.src_mac_addr
                traffic_config_obj = MyLib.my_config_utils.TrafficConfiguration(log,testscript,configdict,port_handle_dict)
                i = 0
                while (i < 5):
                    log.info(banner('Iteration # {0}'.format(i+1)))
                    res = traffic_config_obj.sendArpRequest(tg_hdl=tgn_hdl,port_handle=port_handle_dict[receiver_port[0]])
                    i+=1
                
                if res:
                    cfg = 'sh mac address-table address {0} | xml'.format(src_mac)
                    hdl = node_dict['all_dut'][tgn_port_dut_mapping[receiver_port[0]]]
                    out = hdl.execute(cfg)
                    s = BeautifulSoup(out)
                    port_info = s.find('disp_port').string
                    if re.search('Eth',port_info):
                        log.info(banner('Configuring the Traffic Stream:'))
                        ixia_traffic_config = configureIxNetworkTraffic(self, traffic_args, tg_hdl=tgn_hdl, emulation_src_handle=intf_hdl_dict[source_port[0]],
                                                                        emulation_dst_handle=intf_hdl_dict[receiver_port[0]])
                        if not ixia_traffic_config['status']:
                            log.error(banner('Traffic Creation is not succesful...'))
                            self.failed()
                        
                        stream_dict = {}
                        stream_dict.setdefault('TEST-034',{})
                        stream_dict['TEST-034']['stream_id'] = ixia_traffic_config['stream_id']
                        
                        log.info(banner('Waiting for 10 seconds before starting the traffic after traffic creation'))
                        countDownTimer(10)
                        
                        log.info(banner('Starting the Traffic Stream: {0}'.format(ixia_traffic_config['stream_id'])))
                        b = tgn_hdl.traffic_control(action='run', handle = ixia_traffic_config['traffic_item'], max_wait_timer=60)

                        log.info(banner('Waiting for 30 seconds before collecting the traffic stats'))
                        countDownTimer(30)

                        res = MyLib.my_config_utils.getTrafficItemStatistics(log,tgn_hdl,stream_dict,'TEST-034')
                        
                        if abs(res['tx']-res['rx']) < threshold:
                            log.info('Traffic flow is as expected..The value of tx and Rx is : {0} and {1}'.format(res['tx'],res['rx']))
                            
                            log.info(banner('Simulating MAC Move.. Sending ARP from the Host on the other Port'))
                            total_ports = list(testscript.parameters['configdict']['TG'][TG]['TEST-034']['tg_interface_config_dict'].keys())
                            log.info('The Value to Total Port is : {0}'.format(total_ports))
                            for port in source_port[0],receiver_port[0]:
                                total_ports.remove(port)
                            log.info(banner('The Vale of total_ports now is : {0}'.format(total_ports)))
                            i=0
                            while (i < 5):
                                log.info(banner('Iteration # {0}'.format(i+1)))
                                res = traffic_config_obj.sendArpRequest(tg_hdl=tgn_hdl,port_handle=port_handle_dict[total_ports[0]])
                                i+=1
                                
                            log.info(banner('Checking the Host Move'))
                            out = hdl.execute(cfg)
                            s = BeautifulSoup(out)
                            new_port = s.find('disp_port').string
                            
                            if re.search('Peer-Link', new_port):
                                log.info(banner('The host got moved from {0} to {1}'.format(port_info,new_port)))
                                log.info('Checking The Traffic stats:')
 
                                log.info(banner('Waiting for 30 seconds before collecting the traffic stats'))
                                countDownTimer(30)
    
                                res = MyLib.my_config_utils.getTrafficItemStatistics(log,tgn_hdl,stream_dict,'TEST-034')
                                
                                if not abs(res['tx'] - res['rx']) < threshold:
                                    log.info('Traffic loss is as expected..Moving the host Back to the Original Port')
                                    log.info(banner('Sending ARP Request from the Original Port '))
                                    i = 0
                                    while (i < 5):
                                        log.info(banner('Iteration # {0}'.format(i+1)))
                                        res = traffic_config_obj.sendArpRequest(tg_hdl=tgn_hdl,port_handle=port_handle_dict[receiver_port[0]])
                                        i+=1
                                    log.info(banner('Checking for The movement of host back to Original Port'))
                                    out = hdl.execute(cfg)
                                    s = BeautifulSoup(out)
                                    new1_port = s.find('disp_port').string
                                    
                                    if re.search('Eth', new1_port):
                                        log.info(banner('The host got moved from {0} to {1}'.format(new1_port,port_info)))
                                        log.info('Checking The Traffic stats:')
         
                                        log.info(banner('Waiting for 30 seconds before collecting the traffic stats'))
                                        countDownTimer(30)
    
                                        res = MyLib.my_config_utils.getTrafficItemStatistics(log,tgn_hdl,stream_dict,'TEST-034')
                                        
                                        if abs(res['tx'] - res['rx']) < threshold:
                                            log.info('Traffic has recovered to the Original POrt as expected.. The value of tx and Rx is : {0} and {1}'.format(res['tx'],res['rx']))
                                        else:
                                            log.error('Traffic has not recovered after moving the host back to Original dut: The value of tx and Rx is : {0} and {1}'.format(res['tx'],res['rx']))
                                            flag = 1
                                            
                                    else:
                                        log.error(banner('The Host should have got moved to {0}'.format(port_info)))
                                        flag = 1
                                        
                                else:
                                    log.error('Traffic loss was expected after host Movement ... Traffic should now be recieved on the new Port')
                                    flag = 1
                            else:
                                log.error('Host move was Expected. But Hasnot happened. The host is at {0}'.format(new_port))
                                flag = 1
                        else:
                            log.error('Traffic Flow is not as expected. The value of tx and Rx is : {0} and {1}'.format(res['tx'],res['rx']))
                            flag = 1 
                        
                        
                        log.info('Deleting the Created Stream for this test: ')
        
                        x1 = tgn_hdl.traffic_control(action='stop', handle = ixia_traffic_config['traffic_item'],max_wait_timer=60)
                        
                        countDownTimer(30)
        
                        log.info('Removing the stream:')
                        y = tgn_hdl.traffic_config(mode='remove',stream_id=ixia_traffic_config['stream_id'])
                                
                        log.info('STarting all the other streams')
                        z = tgn_hdl.traffic_control(action='run',max_wait_timer=60)
                        
                        log.info('waiting for 30 seconds before collecting the stats:')
                        countDownTimer(30)
                        out = trigger_obj.checkAllStreamStats(tgn_hdl)
                        
                        if not out:
                            log.error(banner('Traffic has not recovered on some of the streams after starting the Original Streams.. Collecting the individual STream stats:'))
                            self.failed()
                                
                        if flag:
                            log.error(banner('The Traffic Flow was not as expected in one of the Steps.. Pls check logs.'))
                            self.failed()
                    else:
                        log.error('The Initial Traffic Condition did not pass:')
                        self.failed()     

class VXLANVxlanV6FUNC141(aetest.Testcase):

    """ Host Mobility  - Moving Host from Orphan to VPC Port """

    uid = 'VXLAN-L3-VxlanV6-FUNC-141'
    
    @aetest.test
    def HostMobilityOrphanToVPCPort(self,log,testscript,testbed):
        
        node_dict = testscript.parameters['node_dict']
        tg_interface_hdl_dict = testscript.parameters['tg_interface_hdl_dict'] 
        traffic_stream_dict = testscript.parameters['traffic_stream_dict'] 
        port_handle_dict = testscript.parameters['port_handle_dict']
        TGList_config_file = testscript.parameters['TGList']
        configdict = testscript.parameters['configdict'] 
        tgn_config_dict = configdict['TG']
        threshold = testscript.parameters['traffic_threshold'] 
        tgn_port_dut_mapping = testscript.parameters['tgn_port_dut_mapping']
        alias_intf_mapping_dict = testscript.parameters['alias_intf_mapping']
        configured_stream = testscript.parameters['configured_stream']
        trigger_obj = testscript.parameters['trigger_obj']
        testbed_obj = testscript.parameters['testbed_obj']

        log.info(banner('The value of configured stream is : {0}'.format(configured_stream))) 
        
        res = [node_dict['all_dut'][dut].execute('show version') for dut in node_dict['all_dut'] if re.search('uut', dut)]
        
        for TG in tgn_config_dict.keys():
            tgn_hdl = testscript.parameters['testbed_obj'].devices[TG]
            out = trigger_obj.checkAllStreamStats(tgn_hdl)
            flag = 0
            if out:
                log.info(banner('Stopping all the Traffic:'))
                
                a = tgn_hdl.traffic_control(action='stop',max_wait_timer=60)
                
                log.info(banner('Waiting for 30 seconds before sending Fresh ARP Request from host on Ixia: '))
                countDownTimer(30)
                

                source_port = testscript.parameters['configdict']['TG'][TG]['TEST-035']['traffic_config_dict']['source']
                receiver_port = testscript.parameters['configdict']['TG'][TG]['TEST-035']['traffic_config_dict']['receivers']
                traffic_args=testscript.parameters['configdict']['TG'][TG]['TEST-035']['traffic_config_dict']['params']
                 
                src_port = [port_handle_dict[x] for x in source_port]
                dst_port = [port_handle_dict[x] for x in receiver_port]
                log.info('The value of src_port is : {0}'.format(src_port))
                log.info('The value of dst_port is : {0}'.format(dst_port))
                
                log.info(banner('Creating The Host Interfaces on the Traffic Gen'))
                intf_hdl_dict = {}
                for port in testscript.parameters['configdict']['TG'][TG]['TEST-035']['tg_interface_config_dict'].keys():
                    intf_args = testscript.parameters['configdict']['TG'][TG]['TEST-035']['tg_interface_config_dict'][port]
                    intf_config = configureIxNetworkInterface(log,intf_args,tg_hdl = tgn_hdl,port_handle = port_handle_dict[port])
                    intf_hdl_dict[port] = intf_config['interface_handle']
                
                log.info(banner('sending ARP Request from the Initial Receiver...'))
                
                host_mac_args = testscript.parameters['configdict']['TG'][TG]['TEST-035']['tg_interface_config_dict'][receiver_port[0]]
                log.info(banner('The value of host_mac_args is : {0}'.format(host_mac_args)))
                ns = MyLib.my_config_utils.parseHostInterfaceArg(log,host_mac_args)
                log.info(banner('The value of ns is :{0}'.format(ns)))
                src_mac = ns.src_mac_addr
                traffic_config_obj = MyLib.my_config_utils.TrafficConfiguration(log,testscript,configdict,port_handle_dict)
                i = 0
                while (i < 5):
                    log.info(banner('Iteration # {0}'.format(i+1)))
                    res = traffic_config_obj.sendArpRequest(tg_hdl=tgn_hdl,port_handle=port_handle_dict[receiver_port[0]])
                    i+=1
                
                if res:
                    cfg = 'sh mac address-table address {0} | xml'.format(src_mac)
                    hdl = node_dict['all_dut'][tgn_port_dut_mapping[receiver_port[0]]]
                    out = hdl.execute(cfg)
                    s = BeautifulSoup(out)
                    port_info = s.find('disp_port').string
                    if re.search('Eth',port_info):
                        log.info(banner('Configuring the Traffic Stream:'))
                        ixia_traffic_config = configureIxNetworkTraffic(self, traffic_args, tg_hdl=tgn_hdl, emulation_src_handle=intf_hdl_dict[source_port[0]],
                                                                        emulation_dst_handle=intf_hdl_dict[receiver_port[0]])
                        if not ixia_traffic_config['status']:
                            log.error(banner('Traffic Creation is not succesful...'))
                            self.failed()
                        
                        stream_dict = {}
                        stream_dict.setdefault('TEST-035',{})
                        stream_dict['TEST-035']['stream_id'] = ixia_traffic_config['stream_id']
                        
                        log.info(banner('Waiting for 10 seconds before starting the traffic after traffic creation'))
                        countDownTimer(10)
                        
                        log.info(banner('Starting the Traffic Stream: {0}'.format(ixia_traffic_config['stream_id'])))
                        b = tgn_hdl.traffic_control(action='run', handle = ixia_traffic_config['traffic_item'], max_wait_timer=60)

                        log.info(banner('Waiting for 30 seconds before collecting the traffic stats'))
                        countDownTimer(30)

                        res = MyLib.my_config_utils.getTrafficItemStatistics(log,tgn_hdl,stream_dict,'TEST-035')
                        
                        if abs(res['tx']-res['rx']) < threshold:
                            log.info('Traffic flow is as expected..The value of tx and Rx is : {0} and {1}'.format(res['tx'],res['rx']))
                            
                            log.info(banner('Simulating MAC Move.. Sending ARP from the Host on the other Port'))
                            total_ports = list(testscript.parameters['configdict']['TG'][TG]['TEST-035']['tg_interface_config_dict'].keys())
                            log.info('The Value to Total Port is : {0}'.format(total_ports))
                            for port in source_port[0],receiver_port[0]:
                                total_ports.remove(port)
                            log.info(banner('The Vale of total_ports now is : {0}'.format(total_ports)))
                            i=0
                            while (i < 5):
                                log.info(banner('Iteration # {0}'.format(i+1)))
                                res = traffic_config_obj.sendArpRequest(tg_hdl=tgn_hdl,port_handle=port_handle_dict[total_ports[0]])
                                i+=1
                                
                            log.info(banner('Checking the Host Move'))
                            out = hdl.execute(cfg)
                            s = BeautifulSoup(out)
                            new_port = s.find('disp_port').string
                            log.info(banner('The value of new_port is : {0}'.format(new_port)))
#                             dut_info = tgn_port_dut_mapping[total_ports[0]]
#                             log.info('The value of dut_info is : {0}'.format(dut_info))
#                             tgn_interfaces = list(tgn_hdl.interfaces.aliases)
#                             for i in tgn_interfaces:
#                                 if re.search(dut_info,i):
#                                     new_port_info = i
#                             log.info(banner('The value of NEw Port Info is : {0}'.format(alias_intf_mapping_dict[new_port_info])))
                            
                            if re.search('Po', new_port):
                                log.info(banner('The host got moved from {0} to {1}'.format(port_info,new_port)))
                                log.info('Checking The Traffic stats:')
 
                                log.info(banner('Waiting for 30 seconds before collecting the traffic stats'))
                                countDownTimer(30)
    
                                res = MyLib.my_config_utils.getTrafficItemStatistics(log,tgn_hdl,stream_dict,'TEST-035')
                                
                                if not abs(res['tx'] - res['rx']) < threshold:
                                    log.info('Traffic loss is as expected..Moving the host Back to the Original Port')
                                    log.info(banner('Sending ARP Request from the Original Port '))
                                    i = 0
                                    while (i < 5):
                                        log.info(banner('Iteration # {0}'.format(i+1)))
                                        res = traffic_config_obj.sendArpRequest(tg_hdl=tgn_hdl,port_handle=port_handle_dict[receiver_port[0]])
                                        i+=1
                                    log.info(banner('Checking for The movement of host back to Original Port'))
                                    out = hdl.execute(cfg)
                                    s = BeautifulSoup(out)
                                    new1_port = s.find('disp_port').string
                                    
                                    if re.search('Eth', new1_port):
                                        log.info(banner('The host got moved from {0} to {1}'.format(new_port,new1_port)))
                                        log.info('Checking The Traffic stats:')
         
                                        log.info(banner('Waiting for 30 seconds before collecting the traffic stats'))
                                        countDownTimer(30)
    
                                        res = MyLib.my_config_utils.getTrafficItemStatistics(log,tgn_hdl,stream_dict,'TEST-035')
                                        
                                        if abs(res['tx'] - res['rx']) < threshold:
                                            log.info('Traffic has recovered to the Original POrt as expected.. The value of tx and Rx is : {0} and {1}'.format(res['tx'],res['rx']))
                                        else:
                                            log.error('Traffic has not recovered after moving the host back to Original dut: The value of tx and Rx is : {0} and {1}'.format(res['tx'],res['rx']))
                                            flag = 1
                                            
                                    else:
                                        log.error(banner('The Host should have got moved to {0}'.format(port_info)))
                                        flag = 1
                                        
                                else:
                                    log.error('Traffic loss was expected after host Movement ... Traffic should now be recieved on the new Port')
                                    flag = 1
                            else:
                                log.error('Host move was Expected. But Hasnot happened. The host is at {0}'.format(new_port))
                                flag = 1
                        else:
                            log.error('Traffic Flow is not as expected. The value of tx and Rx is : {0} and {1}'.format(res['tx'],res['rx']))
                            flag = 1 
                        
                        
                        log.info('Deleting the Created Stream for this test: ')
        
                        x1 = tgn_hdl.traffic_control(action='stop', handle = ixia_traffic_config['traffic_item'],max_wait_timer=60)
                        
                        countDownTimer(30)
        
                        log.info('Removing the stream:')
                        y = tgn_hdl.traffic_config(mode='remove',stream_id=ixia_traffic_config['stream_id'])
                                
                        log.info('STarting all the other streams')
                        z = tgn_hdl.traffic_control(action='run',max_wait_timer=60)
                        
                        log.info('waiting for 30 seconds before collecting the stats:')
                        countDownTimer(30)
                        out = trigger_obj.checkAllStreamStats(tgn_hdl)
                        
                        if not out:
                            log.error(banner('Traffic has not recovered on some of the streams after starting the Original Streams.. Collecting the individual STream stats:'))
                            self.failed()
                                
                        if flag:
                            log.error(banner('The Traffic Flow was not as expected in one of the Steps.. Pls check logs.'))
                            self.failed()
                    else:
                        log.error('The Initial Traffic Condition did not pass:')
                        self.failed()     

class VXLANVxlanV6FUNC142(aetest.Testcase):

    """ Host Mobility  - Moving Host from Orphan to Remote VTEP """

    uid = 'VXLAN-L3-VxlanV6-FUNC-142'
    
    @aetest.test
    def HostMobilityOrphanToRemoteVtep(self,log,testscript,testbed):
        
        node_dict = testscript.parameters['node_dict']
        tg_interface_hdl_dict = testscript.parameters['tg_interface_hdl_dict'] 
        traffic_stream_dict = testscript.parameters['traffic_stream_dict'] 
        port_handle_dict = testscript.parameters['port_handle_dict']
        TGList_config_file = testscript.parameters['TGList']
        configdict = testscript.parameters['configdict'] 
        tgn_config_dict = configdict['TG']
        threshold = testscript.parameters['traffic_threshold'] 
        tgn_port_dut_mapping = testscript.parameters['tgn_port_dut_mapping']
        alias_intf_mapping_dict = testscript.parameters['alias_intf_mapping']
        configured_stream = testscript.parameters['configured_stream']
        trigger_obj = testscript.parameters['trigger_obj']
        testbed_obj = testscript.parameters['testbed_obj']

        log.info(banner('The value of configured stream is : {0}'.format(configured_stream))) 
        
        res = [node_dict['all_dut'][dut].execute('show version') for dut in node_dict['all_dut'] if re.search('uut', dut)]
        
        for TG in tgn_config_dict.keys():
            tgn_hdl = testscript.parameters['testbed_obj'].devices[TG]
            out = trigger_obj.checkAllStreamStats(tgn_hdl)
            flag = 0
            if out:
                log.info(banner('Stopping all the Traffic:'))
                
                a = tgn_hdl.traffic_control(action='stop',max_wait_timer=60)
                
                log.info(banner('Waiting for 30 seconds before sending Fresh ARP Request from host on Ixia: '))
                countDownTimer(30)
                

                source_port = testscript.parameters['configdict']['TG'][TG]['TEST-036']['traffic_config_dict']['source']
                receiver_port = testscript.parameters['configdict']['TG'][TG]['TEST-036']['traffic_config_dict']['receivers']
                traffic_args=testscript.parameters['configdict']['TG'][TG]['TEST-036']['traffic_config_dict']['params']
                 
                src_port = [port_handle_dict[x] for x in source_port]
                dst_port = [port_handle_dict[x] for x in receiver_port]
                log.info('The value of src_port is : {0}'.format(src_port))
                log.info('The value of dst_port is : {0}'.format(dst_port))
                
                log.info(banner('Creating The Host Interfaces on the Traffic Gen'))
                intf_hdl_dict = {}
                for port in testscript.parameters['configdict']['TG'][TG]['TEST-036']['tg_interface_config_dict'].keys():
                    intf_args = testscript.parameters['configdict']['TG'][TG]['TEST-036']['tg_interface_config_dict'][port]
                    intf_config = configureIxNetworkInterface(log,intf_args,tg_hdl = tgn_hdl,port_handle = port_handle_dict[port])
                    intf_hdl_dict[port] = intf_config['interface_handle']
                
                log.info(banner('sending ARP Request from the Initial Receiver...'))
                
                host_mac_args = testscript.parameters['configdict']['TG'][TG]['TEST-036']['tg_interface_config_dict'][receiver_port[0]]
                log.info(banner('The value of host_mac_args is : {0}'.format(host_mac_args)))
                ns = MyLib.my_config_utils.parseHostInterfaceArg(log,host_mac_args)
                log.info(banner('The value of ns is :{0}'.format(ns)))
                src_mac = ns.src_mac_addr
                traffic_config_obj = MyLib.my_config_utils.TrafficConfiguration(log,testscript,configdict,port_handle_dict)
                all_vtep_dict = trigger_obj.getDeviceDict('all_vtep')
                log.info(banner('Clearing the ARP entries before sending ARP Requets.'))
                for dut in all_vtep_dict.keys():
                    hdl1 = node_dict['all_dut'][dut]
                    hdl1.execute('clear ip arp vrf all force-delete ; clear mac add dynamic')        
                i = 0
                while (i < 1):
                    log.info(banner('Iteration # {0}'.format(i+1)))
                    res = traffic_config_obj.sendArpRequest(tg_hdl=tgn_hdl,port_handle=port_handle_dict[receiver_port[0]])
                    i+=1
                    countDownTimer(5)
                log.info(banner('Waiting for 10 seconds before checking the MAC Table'))
                countDownTimer(10)
                if res:
                    cfg = 'sh mac address-table address {0} | xml'.format(src_mac)
                    hdl = node_dict['all_dut'][tgn_port_dut_mapping[receiver_port[0]]]
                    out = hdl.execute(cfg)
                    s = BeautifulSoup(out)
                    try:
                        port_info = s.find('disp_port').string
                    except:
                        log.info(banner('The Port information is not found. Resending the ARP Request:'))
                        res = traffic_config_obj.sendArpRequest(tg_hdl=tgn_hdl,port_handle=port_handle_dict[receiver_port[0]])
                        countDownTimer(2)
                    if re.search('Eth',port_info):
                        log.info(banner('Configuring the Traffic Stream:'))
                        ixia_traffic_config = configureIxNetworkTraffic(self, traffic_args, tg_hdl=tgn_hdl, emulation_src_handle=intf_hdl_dict[source_port[0]],
                                                                        emulation_dst_handle=intf_hdl_dict[receiver_port[0]])
                        if not ixia_traffic_config['status']:
                            log.error(banner('Traffic Creation is not succesful...'))
                            self.failed()
                    
                        stream_dict = {}
                        stream_dict.setdefault('TEST-036',{})
                        stream_dict['TEST-036']['stream_id'] = ixia_traffic_config['stream_id']
                        
                        log.info(banner('Waiting for 10 seconds before starting the traffic after traffic creation'))
                        countDownTimer(10)
                        
                        log.info(banner('Starting the Traffic Stream: {0}'.format(ixia_traffic_config['stream_id'])))
                        b = tgn_hdl.traffic_control(action='run', handle = ixia_traffic_config['traffic_item'], max_wait_timer=60)

                        log.info(banner('Waiting for 30 seconds before collecting the traffic stats'))
                        countDownTimer(30)

                        res = MyLib.my_config_utils.getTrafficItemStatistics(log,tgn_hdl,stream_dict,'TEST-036')
                        
                        if abs(res['tx']-res['rx']) < threshold:
                            log.info('Traffic flow is as expected..The value of tx and Rx is : {0} and {1}'.format(res['tx'],res['rx']))
                            b = tgn_hdl.traffic_control(action='stop',handle = ixia_traffic_config['traffic_item'], max_wait_timer=60)
                            countDownTimer(15)
                            log.info(banner('Simulating MAC Move.. Sending ARP from the Host on the Remote VTEP'))
                            total_ports = list(testscript.parameters['configdict']['TG'][TG]['TEST-036']['tg_interface_config_dict'].keys())
                            log.info('The Value to Total Port is : {0}'.format(total_ports))
                            for port in source_port[0],receiver_port[0]:
                                total_ports.remove(port)
                            log.info(banner('The Value of total_ports now is : {0}'.format(total_ports)))
                            log.info(banner('Clearing the ARP entries before sending ARP Requets.'))
                            for dut in all_vtep_dict.keys():
                                hdl1 = node_dict['all_dut'][dut]
                                hdl1.execute('clear ip arp vrf all force-delete ; clear mac add dynamic')  
                            i=0
                            while (i < 1):
                                log.info(banner('Iteration # {0}'.format(i+1)))
                                res = traffic_config_obj.sendArpRequest(tg_hdl=tgn_hdl,port_handle=port_handle_dict[total_ports[0]])
                                i+=1
                                countDownTimer(5)
                            log.info(banner('Waiting for 30 seconds before checking the MAC Move'))
                            countDownTimer(30)
                            log.info(banner('Checking the Host Move'))
                            out = hdl.execute(cfg)
                            s = BeautifulSoup(out)
                            try:
                                new_port = s.find('disp_port').string
                            except:
                                log.info(banner('The port information is not found ... Sending ARP REquest again'))
                                res = traffic_config_obj.sendArpRequest(tg_hdl=tgn_hdl,port_handle=port_handle_dict[total_ports[0]])
                                countDownTimer(2)
                            log.info(banner('The value of new_port is : {0}'.format(new_port)))
#                             dut_info = tgn_port_dut_mapping[total_ports[0]]
#                             log.info('The value of dut_info is : {0}'.format(dut_info))
#                             tgn_interfaces = list(tgn_hdl.interfaces.aliases)
#                             for i in tgn_interfaces:
#                                 if re.search(dut_info,i):
#                                     new_port_info = i
#                             log.info(banner('The value of NEw Port Info is : {0}'.format(alias_intf_mapping_dict[new_port_info])))
                            
                            if re.search('nve', new_port):
                                log.info(banner('The host got moved from {0} to {1}'.format(port_info,new_port)))
                                log.info('Checking The Traffic stats:')
                                c = tgn_hdl.traffic_control(action='run',handle = ixia_traffic_config['traffic_item'], max_wait_timer=60)
                                log.info(banner('Waiting for 30 seconds before collecting the traffic stats'))
                                countDownTimer(30)
    
                                res = MyLib.my_config_utils.getTrafficItemStatistics(log,tgn_hdl,stream_dict,'TEST-036')
                                
                                if not abs(res['tx'] - res['rx']) < threshold:
                                    log.info('Traffic loss is as expected..The value of tx and Rx is : {0} and {1}'.format(res['tx'],res['rx']))
                                    log.info(banner('Moving the host back to its Original Port'))
                                    d = tgn_hdl.traffic_control(action='stop',handle = ixia_traffic_config['traffic_item'], max_wait_timer=60)
                                    countDownTimer(15)
                                    log.info(banner('CLearing the ARP Entries before sending Fresh ARP Requests'))

                                    for dut in all_vtep_dict.keys():
                                        hdl1 = node_dict['all_dut'][dut]
                                        hdl1.execute('clear ip arp vrf all force-delete ; clear mac add dynamic')  
                                    log.info(banner('Sending ARP Request from the Original Port '))
                                    i = 0
                                    while (i < 1):
                                        log.info(banner('Iteration # {0}'.format(i+1)))
                                        res = traffic_config_obj.sendArpRequest(tg_hdl=tgn_hdl,port_handle=port_handle_dict[receiver_port[0]])
                                        i+=1
                                        countDownTimer(60)
                                    log.info(banner('Checking for The movement of host back to Original Port'))
                                    out = hdl.execute(cfg)
                                    s = BeautifulSoup(out)
                                    try:
                                        new1_port = s.find('disp_port').string
                                    except:
                                        log.info(banner('The port information is not found ... Sending ARP REquest again'))
                                        res = traffic_config_obj.sendArpRequest(tg_hdl=tgn_hdl,port_handle=port_handle_dict[receiver_port[0]])
                                        countDownTimer(5)
                                    
                                    if re.search('Eth', new1_port):
                                        log.info(banner('The host got moved from {0} to {1}'.format(new_port,new1_port)))
                                        log.info('Checking The Traffic stats:')
                                        b = tgn_hdl.traffic_control(action='run',handle = ixia_traffic_config['traffic_item'], max_wait_timer=60)
                                        countDownTimer(15)
                                        log.info(banner('Waiting for 30 seconds before collecting the traffic stats'))
                                        countDownTimer(30)
    
                                        res = MyLib.my_config_utils.getTrafficItemStatistics(log,tgn_hdl,stream_dict,'TEST-036')
                                        
                                        if abs(res['tx'] - res['rx']) < threshold:
                                            log.info('Traffic has recovered to the Original POrt as expected.. The value of tx and Rx is : {0} and {1}'.format(res['tx'],res['rx']))
                                        else:
                                            log.error('Traffic has not recovered after moving the host back to Original dut: The value of tx and Rx is : {0} and {1}'.format(res['tx'],res['rx']))
                                            flag = 1
                                            
                                    else:
                                        log.error(banner('The Host should have got moved to {0} but points to {1}'.format(port_info,new1_port)))
                                        flag = 1
                                        
                                else:
                                    log.error('Traffic loss was expected after host Movement ... Traffic should now be recieved on the new Port')
                                    flag = 1
                            else:
                                log.error('Host move was Expected. But Has not happened. The host is at {0}'.format(new_port))
                                flag = 1
                        else:
                            log.error('Traffic Flow is not as expected. The value of tx and Rx is : {0} and {1}'.format(res['tx'],res['rx']))
                            flag = 1 
                        
                        
                        log.info('Deleting the Created Stream for this test: ')
        
                        x1 = tgn_hdl.traffic_control(action='stop', handle = ixia_traffic_config['traffic_item'],max_wait_timer=60)
                        
                        countDownTimer(30)
        
                        log.info('Removing the stream:')
                        y = tgn_hdl.traffic_config(mode='remove',stream_id=ixia_traffic_config['stream_id'])
                                
                        log.info('STarting all the other streams')
                        z = tgn_hdl.traffic_control(action='run',max_wait_timer=60)
                        
                        log.info('waiting for 30 seconds before collecting the stats:')
                        countDownTimer(30)
                        out = trigger_obj.checkAllStreamStats(tgn_hdl)
                        
                        if not out:
                            log.error(banner('Traffic has not recovered on some of the streams after starting the Original Streams.. Collecting the individual STream stats:'))
                            self.failed()
                                
                        if flag:
                            log.error(banner('The Traffic Flow was not as expected in one of the Steps.. Pls check logs.'))
                            self.failed()
                    else:
                        log.error('The Initial Traffic Condition did not pass:')
                        self.failed()     

class VXLANVxlanV6FUNC143(aetest.Testcase):

    """ Host Mobility  - Moving Host from VPC Port to Orphan """

    uid = 'VXLAN-L3-VxlanV6-FUNC-143'
    
    @aetest.test
    def HostMobilityVPCToOrphan(self,log,testscript,testbed):
        
        node_dict = testscript.parameters['node_dict']
        tg_interface_hdl_dict = testscript.parameters['tg_interface_hdl_dict'] 
        traffic_stream_dict = testscript.parameters['traffic_stream_dict'] 
        port_handle_dict = testscript.parameters['port_handle_dict']
        TGList_config_file = testscript.parameters['TGList']
        configdict = testscript.parameters['configdict'] 
        tgn_config_dict = configdict['TG']
        threshold = testscript.parameters['traffic_threshold'] 
        tgn_port_dut_mapping = testscript.parameters['tgn_port_dut_mapping']
        alias_intf_mapping_dict = testscript.parameters['alias_intf_mapping']
        configured_stream = testscript.parameters['configured_stream']
        trigger_obj = testscript.parameters['trigger_obj']
        testbed_obj = testscript.parameters['testbed_obj']

        log.info(banner('The value of configured stream is : {0}'.format(configured_stream))) 
        
        res = [node_dict['all_dut'][dut].execute('show version') for dut in node_dict['all_dut'] if re.search('uut', dut)]
        
        for TG in tgn_config_dict.keys():
            tgn_hdl = testscript.parameters['testbed_obj'].devices[TG]
            out = trigger_obj.checkAllStreamStats(tgn_hdl)
            flag = 0
            if out:
                log.info(banner('Stopping all the Traffic:'))
                
                a = tgn_hdl.traffic_control(action='stop',max_wait_timer=60)
                
                log.info(banner('Waiting for 30 seconds before sending Fresh ARP Request from host on Ixia: '))
                countDownTimer(30)
                

                source_port = testscript.parameters['configdict']['TG'][TG]['TEST-037']['traffic_config_dict']['source']
                receiver_port = testscript.parameters['configdict']['TG'][TG]['TEST-037']['traffic_config_dict']['receivers']
                traffic_args=testscript.parameters['configdict']['TG'][TG]['TEST-037']['traffic_config_dict']['params']
                 
                src_port = [port_handle_dict[x] for x in source_port]
                dst_port = [port_handle_dict[x] for x in receiver_port]
                log.info('The value of src_port is : {0}'.format(src_port))
                log.info('The value of dst_port is : {0}'.format(dst_port))
                
                log.info(banner('Creating The Host Interfaces on the Traffic Gen'))
                intf_hdl_dict = {}
                for port in testscript.parameters['configdict']['TG'][TG]['TEST-037']['tg_interface_config_dict'].keys():
                    intf_args = testscript.parameters['configdict']['TG'][TG]['TEST-037']['tg_interface_config_dict'][port]
                    intf_config = configureIxNetworkInterface(log,intf_args,tg_hdl = tgn_hdl,port_handle = port_handle_dict[port])
                    intf_hdl_dict[port] = intf_config['interface_handle']
                
                log.info(banner('sending ARP Request from the Initial Receiver...'))
                
                host_mac_args = testscript.parameters['configdict']['TG'][TG]['TEST-037']['tg_interface_config_dict'][receiver_port[0]]
                log.info(banner('The value of host_mac_args is : {0}'.format(host_mac_args)))
                ns = MyLib.my_config_utils.parseHostInterfaceArg(log,host_mac_args)
                log.info(banner('The value of ns is :{0}'.format(ns)))
                src_mac = ns.src_mac_addr
                traffic_config_obj = MyLib.my_config_utils.TrafficConfiguration(log,testscript,configdict,port_handle_dict)
                all_vtep_dict = trigger_obj.getDeviceDict('all_vtep')
                log.info(banner('Clearing the ARP entries before sending ARP Requets.'))
                for dut in all_vtep_dict.keys():
                    hdl1 = node_dict['all_dut'][dut]
                    hdl1.execute('clear ip arp vrf all force-delete ; clear mac add dynamic')        
                i = 0
                while (i < 1):
                    log.info(banner('Iteration # {0}'.format(i+1)))
                    res = traffic_config_obj.sendArpRequest(tg_hdl=tgn_hdl,port_handle=port_handle_dict[receiver_port[0]])
                    i+=1
                    countDownTimer(5)
                log.info(banner('Waiting for 10 seconds before checking the MAC Table'))
                countDownTimer(10)
                if res:
                    cfg = 'sh mac address-table address {0} | xml'.format(src_mac)
                    vpc_vtep_dict = trigger_obj.getDeviceDict('vpc_vtep')
                    for device in vpc_vtep_dict:
                        hdl = node_dict['all_dut'][device]
                        break
#                     hdl = node_dict['all_dut'][tgn_port_dut_mapping[receiver_port[0]]]
                    out = hdl.execute(cfg)
                    s = BeautifulSoup(out)
                    try:
                        port_info = s.find('disp_port').string
                    except:
                        log.info(banner('The Port information is not found. Resending the ARP Request:'))
                        res = traffic_config_obj.sendArpRequest(tg_hdl=tgn_hdl,port_handle=port_handle_dict[receiver_port[0]])
                        countDownTimer(2)
                    if re.search('Po',port_info):
                        log.info(banner('Configuring the Traffic Stream:'))
                        ixia_traffic_config = configureIxNetworkTraffic(self, traffic_args, tg_hdl=tgn_hdl, emulation_src_handle=intf_hdl_dict[source_port[0]],
                                                                        emulation_dst_handle=intf_hdl_dict[receiver_port[0]])
                        if not ixia_traffic_config['status']:
                            log.error(banner('Traffic Creation is not succesful...'))
                            self.failed()
                    
                        stream_dict = {}
                        stream_dict.setdefault('TEST-037',{})
                        stream_dict['TEST-037']['stream_id'] = ixia_traffic_config['stream_id']
                        
                        log.info(banner('Waiting for 10 seconds before starting the traffic after traffic creation'))
                        countDownTimer(10)
                        
                        log.info(banner('Starting the Traffic Stream: {0}'.format(ixia_traffic_config['stream_id'])))
                        b = tgn_hdl.traffic_control(action='run', handle = ixia_traffic_config['traffic_item'], max_wait_timer=60)

                        log.info(banner('Waiting for 30 seconds before collecting the traffic stats'))
                        countDownTimer(30)

                        res = MyLib.my_config_utils.getTrafficItemStatistics(log,tgn_hdl,stream_dict,'TEST-037')
                        
                        if abs(res['tx']-res['rx']) < threshold:
                            log.info('Traffic flow is as expected..The value of tx and Rx is : {0} and {1}'.format(res['tx'],res['rx']))
                            b = tgn_hdl.traffic_control(action='stop',handle = ixia_traffic_config['traffic_item'], max_wait_timer=60)
                            countDownTimer(15)
                            log.info(banner('Simulating MAC Move.. Sending ARP from the Host on the Remote VTEP'))
                            total_ports = list(testscript.parameters['configdict']['TG'][TG]['TEST-037']['tg_interface_config_dict'].keys())
                            log.info('The Value to Total Port is : {0}'.format(total_ports))
                            for port in source_port[0],receiver_port[0]:
                                total_ports.remove(port)
                            log.info(banner('The Value of total_ports now is : {0}'.format(total_ports)))
                            log.info(banner('Clearing the ARP entries before sending ARP Requets.'))
                            for dut in all_vtep_dict.keys():
                                hdl1 = node_dict['all_dut'][dut]
                                hdl1.execute('clear ip arp vrf all force-delete ; clear mac add dynamic')  
                            i=0
                            while (i < 3):
                                log.info(banner('Iteration # {0}'.format(i+1)))
                                res = traffic_config_obj.sendArpRequest(tg_hdl=tgn_hdl,port_handle=port_handle_dict[total_ports[0]])
                                i+=1
                                countDownTimer(5)
                            log.info(banner('Waiting for 30 seconds before checking the MAC Move'))
                            countDownTimer(30)
                            log.info(banner('Checking the Host Move'))
                            out = hdl.execute(cfg)
                            s = BeautifulSoup(out)
                            try:
                                new_port = s.find('disp_port').string
                            except:
                                log.info(banner('The port information is not found ... Sending ARP REquest again'))
                                res = traffic_config_obj.sendArpRequest(tg_hdl=tgn_hdl,port_handle=port_handle_dict[total_ports[0]])
                                countDownTimer(2)
                            log.info(banner('The value of new_port is : {0}'.format(new_port)))
#                             dut_info = tgn_port_dut_mapping[total_ports[0]]
#                             log.info('The value of dut_info is : {0}'.format(dut_info))
#                             tgn_interfaces = list(tgn_hdl.interfaces.aliases)
#                             for i in tgn_interfaces:
#                                 if re.search(dut_info,i):
#                                     new_port_info = i
#                             log.info(banner('The value of NEw Port Info is : {0}'.format(alias_intf_mapping_dict[new_port_info])))
                            
                            if re.search('Eth|Peer-Link', new_port):
                                log.info(banner('The host got moved from {0} to {1}'.format(port_info,new_port)))
                                log.info('Checking The Traffic stats:')
                                c = tgn_hdl.traffic_control(action='run',handle = ixia_traffic_config['traffic_item'], max_wait_timer=60)
                                log.info(banner('Waiting for 30 seconds before collecting the traffic stats'))
                                countDownTimer(30)
    
                                res = MyLib.my_config_utils.getTrafficItemStatistics(log,tgn_hdl,stream_dict,'TEST-037')
                                
                                if not abs(res['tx'] - res['rx']) < threshold:
                                    log.info('Traffic loss is as expected..The value of tx and Rx is : {0} and {1}'.format(res['tx'],res['rx']))
                                    log.info(banner('Moving the host back to its Original Port'))
                                    d = tgn_hdl.traffic_control(action='stop',handle = ixia_traffic_config['traffic_item'], max_wait_timer=60)
                                    countDownTimer(15)
                                    log.info(banner('CLearing the ARP Entries before sending Fresh ARP Requests'))

                                    for dut in all_vtep_dict.keys():
                                        hdl1 = node_dict['all_dut'][dut]
                                        hdl1.execute('clear ip arp vrf all force-delete ; clear mac add dynamic')  
                                    log.info(banner('Sending ARP Request from the Original Port '))
                                    i = 0
                                    while (i < 1):
                                        log.info(banner('Iteration # {0}'.format(i+1)))
                                        res = traffic_config_obj.sendArpRequest(tg_hdl=tgn_hdl,port_handle=port_handle_dict[receiver_port[0]])
                                        i+=1
                                        countDownTimer(60)
                                    log.info(banner('Checking for The movement of host back to Original Port'))
                                    out = hdl.execute(cfg)
                                    s = BeautifulSoup(out)
                                    try:
                                        new1_port = s.find('disp_port').string
                                    except:
                                        log.info(banner('The port information is not found ... Sending ARP REquest again'))
                                        res = traffic_config_obj.sendArpRequest(tg_hdl=tgn_hdl,port_handle=port_handle_dict[receiver_port[0]])
                                        countDownTimer(5)
                                    
                                    if re.search('Po', new1_port):
                                        log.info(banner('The host got moved from {0} to {1}'.format(new_port,new1_port)))
                                        log.info('Checking The Traffic stats:')
                                        b = tgn_hdl.traffic_control(action='run',handle = ixia_traffic_config['traffic_item'], max_wait_timer=60)
                                        countDownTimer(15)
                                        log.info(banner('Waiting for 30 seconds before collecting the traffic stats'))
                                        countDownTimer(30)
    
                                        res = MyLib.my_config_utils.getTrafficItemStatistics(log,tgn_hdl,stream_dict,'TEST-037')
                                        
                                        if abs(res['tx'] - res['rx']) < threshold:
                                            log.info('Traffic has recovered to the Original POrt as expected.. The value of tx and Rx is : {0} and {1}'.format(res['tx'],res['rx']))
                                        else:
                                            log.error('Traffic has not recovered after moving the host back to Original dut: The value of tx and Rx is : {0} and {1}'.format(res['tx'],res['rx']))
                                            flag = 1
                                            
                                    else:
                                        log.error(banner('The Host should have got moved to {0} but points to {1}'.format(port_info,new1_port)))
                                        flag = 1
                                        
                                else:
                                    log.error('Traffic loss was expected after host Movement ... Traffic should now be recieved on the new Port')
                                    flag = 1
                            else:
                                log.error('Host move was Expected. But Has not happened. The host is at {0}'.format(new_port))
                                flag = 1
                        else:
                            log.error('Traffic Flow is not as expected. The value of tx and Rx is : {0} and {1}'.format(res['tx'],res['rx']))
                            flag = 1 
                        
                        
                        log.info('Deleting the Created Stream for this test: ')
        
                        x1 = tgn_hdl.traffic_control(action='stop', handle = ixia_traffic_config['traffic_item'],max_wait_timer=60)
                        
                        countDownTimer(30)
        
                        log.info('Removing the stream:')
                        y = tgn_hdl.traffic_config(mode='remove',stream_id=ixia_traffic_config['stream_id'])
                                
                        log.info('STarting all the other streams')
                        z = tgn_hdl.traffic_control(action='run',max_wait_timer=60)
                        
                        log.info('waiting for 30 seconds before collecting the stats:')
                        countDownTimer(30)
                        out = trigger_obj.checkAllStreamStats(tgn_hdl)
                        
                        if not out:
                            log.error(banner('Traffic has not recovered on some of the streams after starting the Original Streams.. Collecting the individual STream stats:'))
                            self.failed()
                                
                        if flag:
                            log.error(banner('The Traffic Flow was not as expected in one of the Steps.. Pls check logs.'))
                            self.failed()
                    else:
                        log.error('The Initial Traffic Condition did not pass:')
                        self.failed()     

class VXLANVxlanV6FUNC144(aetest.Testcase):

    """ Host Mobility  - Moving Host from VPC TO Orphan -2 """

    uid = 'VXLAN-L3-VxlanV6-FUNC-144'
    
    @aetest.test
    def HostMobilityVPCToOrphan2(self,log,testscript,testbed):
        
        node_dict = testscript.parameters['node_dict']
        tg_interface_hdl_dict = testscript.parameters['tg_interface_hdl_dict'] 
        traffic_stream_dict = testscript.parameters['traffic_stream_dict'] 
        port_handle_dict = testscript.parameters['port_handle_dict']
        TGList_config_file = testscript.parameters['TGList']
        configdict = testscript.parameters['configdict'] 
        tgn_config_dict = configdict['TG']
        threshold = testscript.parameters['traffic_threshold'] 
        tgn_port_dut_mapping = testscript.parameters['tgn_port_dut_mapping']
        alias_intf_mapping_dict = testscript.parameters['alias_intf_mapping']
        configured_stream = testscript.parameters['configured_stream']
        trigger_obj = testscript.parameters['trigger_obj']
        testbed_obj = testscript.parameters['testbed_obj']

        log.info(banner('The value of configured stream is : {0}'.format(configured_stream))) 
        
        res = [node_dict['all_dut'][dut].execute('show version') for dut in node_dict['all_dut'] if re.search('uut', dut)]
        
        for TG in tgn_config_dict.keys():
            tgn_hdl = testscript.parameters['testbed_obj'].devices[TG]
            out = trigger_obj.checkAllStreamStats(tgn_hdl)
            flag = 0
            if out:
                log.info(banner('Stopping all the Traffic:'))
                
                a = tgn_hdl.traffic_control(action='stop',max_wait_timer=60)
                
                log.info(banner('Waiting for 30 seconds before sending Fresh ARP Request from host on Ixia: '))
                countDownTimer(30)
                

                source_port = testscript.parameters['configdict']['TG'][TG]['TEST-038']['traffic_config_dict']['source']
                receiver_port = testscript.parameters['configdict']['TG'][TG]['TEST-038']['traffic_config_dict']['receivers']
                traffic_args=testscript.parameters['configdict']['TG'][TG]['TEST-038']['traffic_config_dict']['params']
                 
                src_port = [port_handle_dict[x] for x in source_port]
                dst_port = [port_handle_dict[x] for x in receiver_port]
                log.info('The value of src_port is : {0}'.format(src_port))
                log.info('The value of dst_port is : {0}'.format(dst_port))
                
                log.info(banner('Creating The Host Interfaces on the Traffic Gen'))
                intf_hdl_dict = {}
                for port in testscript.parameters['configdict']['TG'][TG]['TEST-038']['tg_interface_config_dict'].keys():
                    intf_args = testscript.parameters['configdict']['TG'][TG]['TEST-038']['tg_interface_config_dict'][port]
                    intf_config = configureIxNetworkInterface(log,intf_args,tg_hdl = tgn_hdl,port_handle = port_handle_dict[port])
                    intf_hdl_dict[port] = intf_config['interface_handle']
                
                log.info(banner('sending ARP Request from the Initial Receiver...'))
                
                host_mac_args = testscript.parameters['configdict']['TG'][TG]['TEST-038']['tg_interface_config_dict'][receiver_port[0]]
                log.info(banner('The value of host_mac_args is : {0}'.format(host_mac_args)))
                ns = MyLib.my_config_utils.parseHostInterfaceArg(log,host_mac_args)
                log.info(banner('The value of ns is :{0}'.format(ns)))
                src_mac = ns.src_mac_addr
                traffic_config_obj = MyLib.my_config_utils.TrafficConfiguration(log,testscript,configdict,port_handle_dict)
                i = 0
                while (i < 1):
                    log.info(banner('Iteration # {0}'.format(i+1)))
                    res = traffic_config_obj.sendArpRequest(tg_hdl=tgn_hdl,port_handle=port_handle_dict[receiver_port[0]])
                    countDownTimer(5)
                    i+=1
                
                if res:
                    cfg = 'sh mac address-table address {0} | xml'.format(src_mac)
                    hdl = node_dict['all_dut'][tgn_port_dut_mapping[receiver_port[0]]]
                    out = hdl.execute(cfg)
                    s = BeautifulSoup(out)
                    port_info = s.find('disp_port').string
                    if re.search('Po',port_info):
                        log.info(banner('Configuring the Traffic Stream:'))
                        ixia_traffic_config = configureIxNetworkTraffic(self, traffic_args, tg_hdl=tgn_hdl, emulation_src_handle=intf_hdl_dict[source_port[0]],
                                                                        emulation_dst_handle=intf_hdl_dict[receiver_port[0]])
                        if not ixia_traffic_config['status']:
                            log.error(banner('Traffic Creation is not succesful...'))
                            self.failed()
                    
                        stream_dict = {}
                        stream_dict.setdefault('TEST-038',{})
                        stream_dict['TEST-038']['stream_id'] = ixia_traffic_config['stream_id']
                        
                        log.info(banner('Waiting for 10 seconds before starting the traffic after traffic creation'))
                        countDownTimer(10)
                        
                        log.info(banner('Starting the Traffic Stream: {0}'.format(ixia_traffic_config['stream_id'])))
                        b = tgn_hdl.traffic_control(action='run', handle = ixia_traffic_config['traffic_item'], max_wait_timer=60)

                        log.info(banner('Waiting for 30 seconds before collecting the traffic stats'))
                        countDownTimer(30)

                        res = MyLib.my_config_utils.getTrafficItemStatistics(log,tgn_hdl,stream_dict,'TEST-038')
                        
                        if abs(res['tx']-res['rx']) < threshold:
                            log.info('Traffic flow is as expected..The value of tx and Rx is : {0} and {1}'.format(res['tx'],res['rx']))
                            
                            log.info(banner('Simulating MAC Move.. Sending ARP from the Host on the Remote VTEP'))
                            total_ports = list(testscript.parameters['configdict']['TG'][TG]['TEST-038']['tg_interface_config_dict'].keys())
                            log.info('The Value to Total Port is : {0}'.format(total_ports))
                            for port in source_port[0],receiver_port[0]:
                                total_ports.remove(port)
                            log.info(banner('The Vale of total_ports now is : {0}'.format(total_ports)))
                            i=0
                            while (i < 5):
                                log.info(banner('Iteration # {0}'.format(i+1)))
                                res = traffic_config_obj.sendArpRequest(tg_hdl=tgn_hdl,port_handle=port_handle_dict[total_ports[0]])
                                i+=1
                                
                            log.info(banner('Checking the Host Move'))
                            out = hdl.execute(cfg)
                            s = BeautifulSoup(out)
                            new_port = s.find('disp_port').string
                            log.info(banner('The value of new_port is : {0}'.format(new_port)))
#                             dut_info = tgn_port_dut_mapping[total_ports[0]]
#                             log.info('The value of dut_info is : {0}'.format(dut_info))
#                             tgn_interfaces = list(tgn_hdl.interfaces.aliases)
#                             for i in tgn_interfaces:
#                                 if re.search(dut_info,i):
#                                     new_port_info = i
#                             log.info(banner('The value of NEw Port Info is : {0}'.format(alias_intf_mapping_dict[new_port_info])))
                            
                            if re.search('Eth', new_port):
                                log.info(banner('The host got moved from {0} to {1}'.format(port_info,new_port)))
                                log.info('Checking The Traffic stats:')
 
                                log.info(banner('Waiting for 30 seconds before collecting the traffic stats'))
                                countDownTimer(30)
    
                                res = MyLib.my_config_utils.getTrafficItemStatistics(log,tgn_hdl,stream_dict,'TEST-038')
                                
                                if not abs(res['tx'] - res['rx']) < threshold:
                                    log.info('Traffic loss is as expected..Moving the host Back to the Original Port')
                                    log.info(banner('Sending ARP Request from the Original Port '))
                                    i = 0
                                    while (i < 5):
                                        log.info(banner('Iteration # {0}'.format(i+1)))
                                        res = traffic_config_obj.sendArpRequest(tg_hdl=tgn_hdl,port_handle=port_handle_dict[receiver_port[0]])
                                        i+=1
                                    log.info(banner('Checking for The movement of host back to Original Port'))
                                    out = hdl.execute(cfg)
                                    s = BeautifulSoup(out)
                                    new1_port = s.find('disp_port').string
                                    
                                    if re.search('Eth', new1_port):
                                        log.info(banner('The host got moved from {0} to {1}'.format(new_port,new1_port)))
                                        log.info('Checking The Traffic stats:')
         
                                        log.info(banner('Waiting for 30 seconds before collecting the traffic stats'))
                                        countDownTimer(30)
    
                                        res = MyLib.my_config_utils.getTrafficItemStatistics(log,tgn_hdl,stream_dict,'TEST-038')
                                        
                                        if abs(res['tx'] - res['rx']) < threshold:
                                            log.info('Traffic has recovered to the Original POrt as expected.. The value of tx and Rx is : {0} and {1}'.format(res['tx'],res['rx']))
                                        else:
                                            log.error('Traffic has not recovered after moving the host back to Original dut: The value of tx and Rx is : {0} and {1}'.format(res['tx'],res['rx']))
                                            flag = 1
                                            
                                    else:
                                        log.error(banner('The Host should have got moved to {0}'.format(port_info)))
                                        flag = 1
                                        
                                else:
                                    log.error('Traffic loss was expected after host Movement ... Traffic should now be recieved on the new Port')
                                    flag = 1
                            else:
                                log.error('Host move was Expected. But Hasnot happened. The host is at {0}'.format(new_port))
                                flag = 1
                        else:
                            log.error('Traffic Flow is not as expected. The value of tx and Rx is : {0} and {1}'.format(res['tx'],res['rx']))
                            flag = 1 
                        
                        
                        log.info('Deleting the Created Stream for this test: ')
        
                        x1 = tgn_hdl.traffic_control(action='stop', handle = ixia_traffic_config['traffic_item'],max_wait_timer=60)
                        
                        countDownTimer(30)
        
                        log.info('Removing the stream:')
                        y = tgn_hdl.traffic_config(mode='remove',stream_id=ixia_traffic_config['stream_id'])
                                
                        log.info('STarting all the other streams')
                        z = tgn_hdl.traffic_control(action='run',max_wait_timer=60)
                        
                        log.info('waiting for 30 seconds before collecting the stats:')
                        countDownTimer(30)
                        out = trigger_obj.checkAllStreamStats(tgn_hdl)
                        
                        if not out:
                            log.error(banner('Traffic has not recovered on some of the streams after starting the Original Streams.. Collecting the individual STream stats:'))
                            self.failed()
                                
                        if flag:
                            log.error(banner('The Traffic Flow was not as expected in one of the Steps.. Pls check logs.'))
                            self.failed()
                    else:
                        log.error('The Initial Traffic Condition did not pass:')
                        self.failed()     


class VXLANVxlanV6FUNC144(aetest.Testcase):

    """ Host Mobility  - Moving Host from VPC to Remove VTEP """

    uid = 'VXLAN-L3-VxlanV6-FUNC-144'
    
    @aetest.test
    def HostMobilityVPCToRemoteVtep(self,log,testscript,testbed):
        
        node_dict = testscript.parameters['node_dict']
        tg_interface_hdl_dict = testscript.parameters['tg_interface_hdl_dict'] 
        traffic_stream_dict = testscript.parameters['traffic_stream_dict'] 
        port_handle_dict = testscript.parameters['port_handle_dict']
        TGList_config_file = testscript.parameters['TGList']
        configdict = testscript.parameters['configdict'] 
        tgn_config_dict = configdict['TG']
        threshold = testscript.parameters['traffic_threshold'] 
        tgn_port_dut_mapping = testscript.parameters['tgn_port_dut_mapping']
        alias_intf_mapping_dict = testscript.parameters['alias_intf_mapping']
        configured_stream = testscript.parameters['configured_stream']
        trigger_obj = testscript.parameters['trigger_obj']
        testbed_obj = testscript.parameters['testbed_obj']

        log.info(banner('The value of configured stream is : {0}'.format(configured_stream))) 
        
        res = [node_dict['all_dut'][dut].execute('show version') for dut in node_dict['all_dut'] if re.search('uut', dut)]
        
        for TG in tgn_config_dict.keys():
            tgn_hdl = testscript.parameters['testbed_obj'].devices[TG]
            out = trigger_obj.checkAllStreamStats(tgn_hdl)
            flag = 0
            if out:
                log.info(banner('Stopping all the Traffic:'))
                
                a = tgn_hdl.traffic_control(action='stop',max_wait_timer=60)
                
                log.info(banner('Waiting for 30 seconds before sending Fresh ARP Request from host on Ixia: '))
                countDownTimer(30)
                

                source_port = testscript.parameters['configdict']['TG'][TG]['TEST-038']['traffic_config_dict']['source']
                receiver_port = testscript.parameters['configdict']['TG'][TG]['TEST-038']['traffic_config_dict']['receivers']
                traffic_args=testscript.parameters['configdict']['TG'][TG]['TEST-038']['traffic_config_dict']['params']
                 
                src_port = [port_handle_dict[x] for x in source_port]
                dst_port = [port_handle_dict[x] for x in receiver_port]
                log.info('The value of src_port is : {0}'.format(src_port))
                log.info('The value of dst_port is : {0}'.format(dst_port))
                
                log.info(banner('Creating The Host Interfaces on the Traffic Gen'))
                intf_hdl_dict = {}
                for port in testscript.parameters['configdict']['TG'][TG]['TEST-038']['tg_interface_config_dict'].keys():
                    intf_args = testscript.parameters['configdict']['TG'][TG]['TEST-038']['tg_interface_config_dict'][port]
                    intf_config = configureIxNetworkInterface(log,intf_args,tg_hdl = tgn_hdl,port_handle = port_handle_dict[port])
                    intf_hdl_dict[port] = intf_config['interface_handle']
                
                log.info(banner('sending ARP Request from the Initial Receiver...'))
                
                host_mac_args = testscript.parameters['configdict']['TG'][TG]['TEST-038']['tg_interface_config_dict'][receiver_port[0]]
                log.info(banner('The value of host_mac_args is : {0}'.format(host_mac_args)))
                ns = MyLib.my_config_utils.parseHostInterfaceArg(log,host_mac_args)
                log.info(banner('The value of ns is :{0}'.format(ns)))
                src_mac = ns.src_mac_addr
                traffic_config_obj = MyLib.my_config_utils.TrafficConfiguration(log,testscript,configdict,port_handle_dict)
                all_vtep_dict = trigger_obj.getDeviceDict('all_vtep')
                log.info(banner('Clearing the ARP entries before sending ARP Requets.'))
                for dut in all_vtep_dict.keys():
                    hdl1 = node_dict['all_dut'][dut]
                    hdl1.execute('clear ip arp vrf all force-delete ; clear mac add dynamic')        
                i = 0
                while (i < 1):
                    log.info(banner('Iteration # {0}'.format(i+1)))
                    res = traffic_config_obj.sendArpRequest(tg_hdl=tgn_hdl,port_handle=port_handle_dict[receiver_port[0]])
                    i+=1
                    countDownTimer(5)
                log.info(banner('Waiting for 10 seconds before checking the MAC Table'))
                countDownTimer(10)
                if res:
                    cfg = 'sh mac address-table address {0} | xml'.format(src_mac)
                    vpc_vtep_dict = trigger_obj.getDeviceDict('vpc_vtep')
                    for device in vpc_vtep_dict:
                        hdl = node_dict['all_dut'][device]
                        break
#                     hdl = node_dict['all_dut'][tgn_port_dut_mapping[receiver_port[0]]]
                    out = hdl.execute(cfg)
                    s = BeautifulSoup(out)
                    try:
                        port_info = s.find('disp_port').string
                    except:
                        log.info(banner('The Port information is not found. Resending the ARP Request:'))
                        res = traffic_config_obj.sendArpRequest(tg_hdl=tgn_hdl,port_handle=port_handle_dict[receiver_port[0]])
                        countDownTimer(2)
                    if re.search('Po',port_info):
                        log.info(banner('Configuring the Traffic Stream:'))
                        ixia_traffic_config = configureIxNetworkTraffic(self, traffic_args, tg_hdl=tgn_hdl, emulation_src_handle=intf_hdl_dict[source_port[0]],
                                                                        emulation_dst_handle=intf_hdl_dict[receiver_port[0]])
                        if not ixia_traffic_config['status']:
                            log.error(banner('Traffic Creation is not succesful...'))
                            self.failed()
                    
                        stream_dict = {}
                        stream_dict.setdefault('TEST-038',{})
                        stream_dict['TEST-038']['stream_id'] = ixia_traffic_config['stream_id']
                        
                        log.info(banner('Waiting for 10 seconds before starting the traffic after traffic creation'))
                        countDownTimer(10)
                        
                        log.info(banner('Starting the Traffic Stream: {0}'.format(ixia_traffic_config['stream_id'])))
                        b = tgn_hdl.traffic_control(action='run', handle = ixia_traffic_config['traffic_item'], max_wait_timer=60)

                        log.info(banner('Waiting for 30 seconds before collecting the traffic stats'))
                        countDownTimer(30)

                        res = MyLib.my_config_utils.getTrafficItemStatistics(log,tgn_hdl,stream_dict,'TEST-038')
                        
                        if abs(res['tx']-res['rx']) < threshold:
                            log.info('Traffic flow is as expected..The value of tx and Rx is : {0} and {1}'.format(res['tx'],res['rx']))
                            b = tgn_hdl.traffic_control(action='stop',handle = ixia_traffic_config['traffic_item'], max_wait_timer=60)
                            countDownTimer(15)
                            log.info(banner('Simulating MAC Move.. Sending ARP from the Host on the Remote VTEP'))
                            total_ports = list(testscript.parameters['configdict']['TG'][TG]['TEST-038']['tg_interface_config_dict'].keys())
                            log.info('The Value to Total Port is : {0}'.format(total_ports))
                            for port in source_port[0],receiver_port[0]:
                                total_ports.remove(port)
                            log.info(banner('The Value of total_ports now is : {0}'.format(total_ports)))
                            log.info(banner('Clearing the ARP entries before sending ARP Requets.'))
                            for dut in all_vtep_dict.keys():
                                hdl1 = node_dict['all_dut'][dut]
                                hdl1.execute('clear ip arp vrf all force-delete ; clear mac add dynamic')  
                            i=0
                            while (i < 1):
                                log.info(banner('Iteration # {0}'.format(i+1)))
                                res = traffic_config_obj.sendArpRequest(tg_hdl=tgn_hdl,port_handle=port_handle_dict[total_ports[0]])
                                i+=1
                                countDownTimer(5)
                            log.info(banner('Waiting for 30 seconds before checking the MAC Move'))
                            countDownTimer(30)
                            log.info(banner('Checking the Host Move'))
                            out = hdl.execute(cfg)
                            s = BeautifulSoup(out)
                            try:
                                new_port = s.find('disp_port').string
                            except:
                                log.info(banner('The port information is not found ... Sending ARP REquest again'))
                                res = traffic_config_obj.sendArpRequest(tg_hdl=tgn_hdl,port_handle=port_handle_dict[total_ports[0]])
                                countDownTimer(2)
                            log.info(banner('The value of new_port is : {0}'.format(new_port)))
#                             dut_info = tgn_port_dut_mapping[total_ports[0]]
#                             log.info('The value of dut_info is : {0}'.format(dut_info))
#                             tgn_interfaces = list(tgn_hdl.interfaces.aliases)
#                             for i in tgn_interfaces:
#                                 if re.search(dut_info,i):
#                                     new_port_info = i
#                             log.info(banner('The value of NEw Port Info is : {0}'.format(alias_intf_mapping_dict[new_port_info])))
                            
                            if re.search('nve', new_port):
                                log.info(banner('The host got moved from {0} to {1}'.format(port_info,new_port)))
                                log.info('Checking The Traffic stats:')
                                c = tgn_hdl.traffic_control(action='run',handle = ixia_traffic_config['traffic_item'], max_wait_timer=60)
                                log.info(banner('Waiting for 30 seconds before collecting the traffic stats'))
                                countDownTimer(30)
    
                                res = MyLib.my_config_utils.getTrafficItemStatistics(log,tgn_hdl,stream_dict,'TEST-038')
                                
                                if not abs(res['tx'] - res['rx']) < threshold:
                                    log.info('Traffic loss is as expected..The value of tx and Rx is : {0} and {1}'.format(res['tx'],res['rx']))
                                    log.info(banner('Moving the host back to its Original Port'))
                                    d = tgn_hdl.traffic_control(action='stop',handle = ixia_traffic_config['traffic_item'], max_wait_timer=60)
                                    countDownTimer(15)
                                    log.info(banner('CLearing the ARP Entries before sending Fresh ARP Requests'))

                                    for dut in all_vtep_dict.keys():
                                        hdl1 = node_dict['all_dut'][dut]
                                        hdl1.execute('clear ip arp vrf all force-delete ; clear mac add dynamic')  
                                    log.info(banner('Sending ARP Request from the Original Port '))
                                    i = 0
                                    while (i < 1):
                                        log.info(banner('Iteration # {0}'.format(i+1)))
                                        res = traffic_config_obj.sendArpRequest(tg_hdl=tgn_hdl,port_handle=port_handle_dict[receiver_port[0]])
                                        i+=1
                                        countDownTimer(60)
                                    log.info(banner('Checking for The movement of host back to Original Port'))
                                    out = hdl.execute(cfg)
                                    s = BeautifulSoup(out)
                                    try:
                                        new1_port = s.find('disp_port').string
                                    except:
                                        log.info(banner('The port information is not found ... Sending ARP REquest again'))
                                        res = traffic_config_obj.sendArpRequest(tg_hdl=tgn_hdl,port_handle=port_handle_dict[receiver_port[0]])
                                        countDownTimer(5)
                                    
                                    if re.search('Po', new1_port):
                                        log.info(banner('The host got moved from {0} to {1}'.format(new_port,new1_port)))
                                        log.info('Checking The Traffic stats:')
                                        b = tgn_hdl.traffic_control(action='run',handle = ixia_traffic_config['traffic_item'], max_wait_timer=60)
                                        countDownTimer(15)
                                        log.info(banner('Waiting for 30 seconds before collecting the traffic stats'))
                                        countDownTimer(30)
    
                                        res = MyLib.my_config_utils.getTrafficItemStatistics(log,tgn_hdl,stream_dict,'TEST-038')
                                        
                                        if abs(res['tx'] - res['rx']) < threshold:
                                            log.info('Traffic has recovered to the Original POrt as expected.. The value of tx and Rx is : {0} and {1}'.format(res['tx'],res['rx']))
                                        else:
                                            log.error('Traffic has not recovered after moving the host back to Original dut: The value of tx and Rx is : {0} and {1}'.format(res['tx'],res['rx']))
                                            flag = 1
                                            
                                    else:
                                        log.error(banner('The Host should have got moved to {0} but points to {1}'.format(port_info,new1_port)))
                                        flag = 1
                                        
                                else:
                                    log.error('Traffic loss was expected after host Movement ... Traffic should now be recieved on the new Port')
                                    flag = 1
                            else:
                                log.error('Host move was Expected. But Has not happened. The host is at {0}'.format(new_port))
                                flag = 1
                        else:
                            log.error('Traffic Flow is not as expected. The value of tx and Rx is : {0} and {1}'.format(res['tx'],res['rx']))
                            flag = 1 
                        
                        
                        log.info('Deleting the Created Stream for this test: ')
        
                        x1 = tgn_hdl.traffic_control(action='stop', handle = ixia_traffic_config['traffic_item'],max_wait_timer=60)
                        
                        countDownTimer(30)
        
                        log.info('Removing the stream:')
                        y = tgn_hdl.traffic_config(mode='remove',stream_id=ixia_traffic_config['stream_id'])
                                
                        log.info('STarting all the other streams')
                        z = tgn_hdl.traffic_control(action='run',max_wait_timer=60)
                        
                        log.info('waiting for 30 seconds before collecting the stats:')
                        countDownTimer(30)
                        out = trigger_obj.checkAllStreamStats(tgn_hdl)
                        
                        if not out:
                            log.error(banner('Traffic has not recovered on some of the streams after starting the Original Streams.. Collecting the individual STream stats:'))
                            self.failed()
                                
                        if flag:
                            log.error(banner('The Traffic Flow was not as expected in one of the Steps.. Pls check logs.'))
                            self.failed()
                    else:
                        log.error('The Initial Traffic Condition did not pass:')
                        self.failed()     

class VXLANVxlanV6FUNC145(aetest.Testcase):

    """ Host Mobility  - Moving Host from RemoteVTEP to VPC VTEP """

    uid = 'VXLAN-L3-VxlanV6-FUNC-145'
    
    @aetest.test
    def HostMobilityRemoteVTEPToVPCVtep(self,log,testscript,testbed):
        
        node_dict = testscript.parameters['node_dict']
        tg_interface_hdl_dict = testscript.parameters['tg_interface_hdl_dict'] 
        traffic_stream_dict = testscript.parameters['traffic_stream_dict'] 
        port_handle_dict = testscript.parameters['port_handle_dict']
        TGList_config_file = testscript.parameters['TGList']
        configdict = testscript.parameters['configdict'] 
        tgn_config_dict = configdict['TG']
        threshold = testscript.parameters['traffic_threshold'] 
        tgn_port_dut_mapping = testscript.parameters['tgn_port_dut_mapping']
        alias_intf_mapping_dict = testscript.parameters['alias_intf_mapping']
        configured_stream = testscript.parameters['configured_stream']
        trigger_obj = testscript.parameters['trigger_obj']
        testbed_obj = testscript.parameters['testbed_obj']

        log.info(banner('The value of configured stream is : {0}'.format(configured_stream))) 
        
        res = [node_dict['all_dut'][dut].execute('show version') for dut in node_dict['all_dut'] if re.search('uut', dut)]
        
        for TG in tgn_config_dict.keys():
            tgn_hdl = testscript.parameters['testbed_obj'].devices[TG]
            out = trigger_obj.checkAllStreamStats(tgn_hdl)
            flag = 0
            if out:
                log.info(banner('Stopping all the Traffic:'))
                
                a = tgn_hdl.traffic_control(action='stop',max_wait_timer=60)
                
                log.info(banner('Waiting for 30 seconds before sending Fresh ARP Request from host on Ixia: '))
                countDownTimer(30)
                

                source_port = testscript.parameters['configdict']['TG'][TG]['TEST-039']['traffic_config_dict']['source']
                receiver_port = testscript.parameters['configdict']['TG'][TG]['TEST-039']['traffic_config_dict']['receivers']
                traffic_args=testscript.parameters['configdict']['TG'][TG]['TEST-039']['traffic_config_dict']['params']
                 
                src_port = [port_handle_dict[x] for x in source_port]
                dst_port = [port_handle_dict[x] for x in receiver_port]
                log.info('The value of src_port is : {0}'.format(src_port))
                log.info('The value of dst_port is : {0}'.format(dst_port))
                
                log.info(banner('Creating The Host Interfaces on the Traffic Gen'))
                intf_hdl_dict = {}
                for port in testscript.parameters['configdict']['TG'][TG]['TEST-039']['tg_interface_config_dict'].keys():
                    intf_args = testscript.parameters['configdict']['TG'][TG]['TEST-039']['tg_interface_config_dict'][port]
                    intf_config = configureIxNetworkInterface(log,intf_args,tg_hdl = tgn_hdl,port_handle = port_handle_dict[port])
                    intf_hdl_dict[port] = intf_config['interface_handle']
                
                log.info(banner('sending ARP Request from the Initial Receiver...'))
                
                host_mac_args = testscript.parameters['configdict']['TG'][TG]['TEST-039']['tg_interface_config_dict'][receiver_port[0]]
                log.info(banner('The value of host_mac_args is : {0}'.format(host_mac_args)))
                ns = MyLib.my_config_utils.parseHostInterfaceArg(log,host_mac_args)
                log.info(banner('The value of ns is :{0}'.format(ns)))
                src_mac = ns.src_mac_addr
                traffic_config_obj = MyLib.my_config_utils.TrafficConfiguration(log,testscript,configdict,port_handle_dict)
                all_vtep_dict = trigger_obj.getDeviceDict('all_vtep')
                log.info(banner('Clearing the ARP entries before sending ARP Requets.'))
                for dut in all_vtep_dict.keys():
                    hdl1 = node_dict['all_dut'][dut]
                    hdl1.execute('clear ip arp vrf all force-delete ; clear mac add dynamic')        
                i = 0
                while (i < 1):
                    log.info(banner('Iteration # {0}'.format(i+1)))
                    res = traffic_config_obj.sendArpRequest(tg_hdl=tgn_hdl,port_handle=port_handle_dict[receiver_port[0]])
                    i+=1
                    countDownTimer(5)
                log.info(banner('Waiting for 10 seconds before checking the MAC Table'))
                countDownTimer(10)
                if res:
                    cfg = 'sh mac address-table address {0} | xml'.format(src_mac)
                    vpc_vtep_dict = trigger_obj.getDeviceDict('vpc_vtep')
                    for device in vpc_vtep_dict:
                        hdl = node_dict['all_dut'][device]
                        break
#                     hdl = node_dict['all_dut'][tgn_port_dut_mapping[receiver_port[0]]]
                    out = hdl.execute(cfg)
                    s = BeautifulSoup(out)
                    try:
                        port_info = s.find('disp_port').string
                    except:
                        log.info(banner('The Port information is not found. Resending the ARP Request:'))
                        res = traffic_config_obj.sendArpRequest(tg_hdl=tgn_hdl,port_handle=port_handle_dict[receiver_port[0]])
                        countDownTimer(2)
                    if re.search('nve',port_info):
                        log.info(banner('Configuring the Traffic Stream:'))
                        ixia_traffic_config = configureIxNetworkTraffic(self, traffic_args, tg_hdl=tgn_hdl, emulation_src_handle=intf_hdl_dict[source_port[0]],
                                                                        emulation_dst_handle=intf_hdl_dict[receiver_port[0]])
                        if not ixia_traffic_config['status']:
                            log.error(banner('Traffic Creation is not succesful...'))
                            self.failed()
                    
                        stream_dict = {}
                        stream_dict.setdefault('TEST-039',{})
                        stream_dict['TEST-039']['stream_id'] = ixia_traffic_config['stream_id']
                        
                        log.info(banner('Waiting for 10 seconds before starting the traffic after traffic creation'))
                        countDownTimer(10)
                        
                        log.info(banner('Starting the Traffic Stream: {0}'.format(ixia_traffic_config['stream_id'])))
                        b = tgn_hdl.traffic_control(action='run', handle = ixia_traffic_config['traffic_item'], max_wait_timer=60)

                        log.info(banner('Waiting for 30 seconds before collecting the traffic stats'))
                        countDownTimer(30)

                        res = MyLib.my_config_utils.getTrafficItemStatistics(log,tgn_hdl,stream_dict,'TEST-039')
                        
                        if abs(res['tx']-res['rx']) < threshold:
                            log.info('Traffic flow is as expected..The value of tx and Rx is : {0} and {1}'.format(res['tx'],res['rx']))
                            b = tgn_hdl.traffic_control(action='stop',handle = ixia_traffic_config['traffic_item'], max_wait_timer=60)
                            countDownTimer(15)
                            log.info(banner('Simulating MAC Move.. Sending ARP from the Host on the Remote VTEP'))
                            total_ports = list(testscript.parameters['configdict']['TG'][TG]['TEST-039']['tg_interface_config_dict'].keys())
                            log.info('The Value to Total Port is : {0}'.format(total_ports))
                            for port in source_port[0],receiver_port[0]:
                                total_ports.remove(port)
                            log.info(banner('The Value of total_ports now is : {0}'.format(total_ports)))
                            log.info(banner('Clearing the ARP entries before sending ARP Requets.'))
                            for dut in all_vtep_dict.keys():
                                hdl1 = node_dict['all_dut'][dut]
                                hdl1.execute('clear ip arp vrf all force-delete ; clear mac add dynamic')  
                            i=0
                            while (i < 1):
                                log.info(banner('Iteration # {0}'.format(i+1)))
                                res = traffic_config_obj.sendArpRequest(tg_hdl=tgn_hdl,port_handle=port_handle_dict[total_ports[0]])
                                i+=1
                                countDownTimer(5)
                            log.info(banner('Waiting for 30 seconds before checking the MAC Move'))
                            countDownTimer(30)
                            log.info(banner('Checking the Host Move'))
                            out = hdl.execute(cfg)
                            s = BeautifulSoup(out)
                            try:
                                new_port = s.find('disp_port').string
                            except:
                                log.info(banner('The port information is not found ... Sending ARP REquest again'))
                                res = traffic_config_obj.sendArpRequest(tg_hdl=tgn_hdl,port_handle=port_handle_dict[total_ports[0]])
                                countDownTimer(2)
                            log.info(banner('The value of new_port is : {0}'.format(new_port)))
#                             dut_info = tgn_port_dut_mapping[total_ports[0]]
#                             log.info('The value of dut_info is : {0}'.format(dut_info))
#                             tgn_interfaces = list(tgn_hdl.interfaces.aliases)
#                             for i in tgn_interfaces:
#                                 if re.search(dut_info,i):
#                                     new_port_info = i
#                             log.info(banner('The value of NEw Port Info is : {0}'.format(alias_intf_mapping_dict[new_port_info])))
                            
                            if re.search('Po', new_port):
                                log.info(banner('The host got moved from {0} to {1}'.format(port_info,new_port)))
                                log.info('Checking The Traffic stats:')
                                c = tgn_hdl.traffic_control(action='run',handle = ixia_traffic_config['traffic_item'], max_wait_timer=60)
                                log.info(banner('Waiting for 30 seconds before collecting the traffic stats'))
                                countDownTimer(30)
    
                                res = MyLib.my_config_utils.getTrafficItemStatistics(log,tgn_hdl,stream_dict,'TEST-039')
                                
                                if not abs(res['tx'] - res['rx']) < threshold:
                                    log.info('Traffic loss is as expected..The value of tx and Rx is : {0} and {1}'.format(res['tx'],res['rx']))
                                    log.info(banner('Moving the host back to its Original Port'))
                                    d = tgn_hdl.traffic_control(action='stop',handle = ixia_traffic_config['traffic_item'], max_wait_timer=60)
                                    countDownTimer(15)
                                    log.info(banner('CLearing the ARP Entries before sending Fresh ARP Requests'))

                                    for dut in all_vtep_dict.keys():
                                        hdl1 = node_dict['all_dut'][dut]
                                        hdl1.execute('clear ip arp vrf all force-delete ; clear mac add dynamic')  
                                    log.info(banner('Sending ARP Request from the Original Port '))
                                    i = 0
                                    while (i < 1):
                                        log.info(banner('Iteration # {0}'.format(i+1)))
                                        res = traffic_config_obj.sendArpRequest(tg_hdl=tgn_hdl,port_handle=port_handle_dict[receiver_port[0]])
                                        i+=1
                                        countDownTimer(60)
                                    log.info(banner('Checking for The movement of host back to Original Port'))
                                    out = hdl.execute(cfg)
                                    s = BeautifulSoup(out)
                                    try:
                                        new1_port = s.find('disp_port').string
                                    except:
                                        log.info(banner('The port information is not found ... Sending ARP REquest again'))
                                        res = traffic_config_obj.sendArpRequest(tg_hdl=tgn_hdl,port_handle=port_handle_dict[receiver_port[0]])
                                        countDownTimer(5)
                                    
                                    if re.search('nve', new1_port):
                                        log.info(banner('The host got moved from {0} to {1}'.format(new_port,new1_port)))
                                        log.info('Checking The Traffic stats:')
                                        b = tgn_hdl.traffic_control(action='run',handle = ixia_traffic_config['traffic_item'], max_wait_timer=60)
                                        countDownTimer(15)
                                        log.info(banner('Waiting for 30 seconds before collecting the traffic stats'))
                                        countDownTimer(30)
    
                                        res = MyLib.my_config_utils.getTrafficItemStatistics(log,tgn_hdl,stream_dict,'TEST-039')
                                        
                                        if abs(res['tx'] - res['rx']) < threshold:
                                            log.info('Traffic has recovered to the Original POrt as expected.. The value of tx and Rx is : {0} and {1}'.format(res['tx'],res['rx']))
                                        else:
                                            log.error('Traffic has not recovered after moving the host back to Original dut: The value of tx and Rx is : {0} and {1}'.format(res['tx'],res['rx']))
                                            flag = 1
                                            
                                    else:
                                        log.error(banner('The Host should have got moved to {0} but points to {1}'.format(port_info,new1_port)))
                                        flag = 1
                                        
                                else:
                                    log.error('Traffic loss was expected after host Movement ... Traffic should now be recieved on the new Port')
                                    flag = 1
                            else:
                                log.error('Host move was Expected. But Has not happened. The host is at {0}'.format(new_port))
                                flag = 1
                        else:
                            log.error('Traffic Flow is not as expected. The value of tx and Rx is : {0} and {1}'.format(res['tx'],res['rx']))
                            flag = 1 
                        
                        
                        log.info('Deleting the Created Stream for this test: ')
        
                        x1 = tgn_hdl.traffic_control(action='stop', handle = ixia_traffic_config['traffic_item'],max_wait_timer=60)
                        
                        countDownTimer(30)
        
                        log.info('Removing the stream:')
                        y = tgn_hdl.traffic_config(mode='remove',stream_id=ixia_traffic_config['stream_id'])
                                
                        log.info('STarting all the other streams')
                        z = tgn_hdl.traffic_control(action='run',max_wait_timer=60)
                        
                        log.info('waiting for 30 seconds before collecting the stats:')
                        countDownTimer(30)
                        out = trigger_obj.checkAllStreamStats(tgn_hdl)
                        
                        if not out:
                            log.error(banner('Traffic has not recovered on some of the streams after starting the Original Streams.. Collecting the individual STream stats:'))
                            self.failed()
                                
                        if flag:
                            log.error(banner('The Traffic Flow was not as expected in one of the Steps.. Pls check logs.'))
                            self.failed()
                    else:
                        log.error('The Initial Traffic Condition did not pass:')
                        self.failed()     

class VXLANVxlanV6FUNC146(aetest.Testcase):

    """ Host Mobility  - Moving Host from RemoteVTEP to VPC Orphan """

    uid = 'VXLAN-L3-VxlanV6-FUNC-146'
    
    @aetest.test
    def HostMobilityRemoteVTEPToVPCOrphan(self,log,testscript,testbed):
        
        node_dict = testscript.parameters['node_dict']
        tg_interface_hdl_dict = testscript.parameters['tg_interface_hdl_dict'] 
        traffic_stream_dict = testscript.parameters['traffic_stream_dict'] 
        port_handle_dict = testscript.parameters['port_handle_dict']
        TGList_config_file = testscript.parameters['TGList']
        configdict = testscript.parameters['configdict'] 
        tgn_config_dict = configdict['TG']
        threshold = testscript.parameters['traffic_threshold'] 
        tgn_port_dut_mapping = testscript.parameters['tgn_port_dut_mapping']
        alias_intf_mapping_dict = testscript.parameters['alias_intf_mapping']
        configured_stream = testscript.parameters['configured_stream']
        trigger_obj = testscript.parameters['trigger_obj']
        testbed_obj = testscript.parameters['testbed_obj']

        log.info(banner('The value of configured stream is : {0}'.format(configured_stream))) 
        
        res = [node_dict['all_dut'][dut].execute('show version') for dut in node_dict['all_dut'] if re.search('uut', dut)]
        
        for TG in tgn_config_dict.keys():
            tgn_hdl = testscript.parameters['testbed_obj'].devices[TG]
            out = trigger_obj.checkAllStreamStats(tgn_hdl)
            flag = 0
            if out:
                log.info(banner('Stopping all the Traffic:'))
                
                a = tgn_hdl.traffic_control(action='stop',max_wait_timer=60)
                
                log.info(banner('Waiting for 30 seconds before sending Fresh ARP Request from host on Ixia: '))
                countDownTimer(30)
                

                source_port = testscript.parameters['configdict']['TG'][TG]['TEST-040']['traffic_config_dict']['source']
                receiver_port = testscript.parameters['configdict']['TG'][TG]['TEST-040']['traffic_config_dict']['receivers']
                traffic_args=testscript.parameters['configdict']['TG'][TG]['TEST-040']['traffic_config_dict']['params']
                 
                src_port = [port_handle_dict[x] for x in source_port]
                dst_port = [port_handle_dict[x] for x in receiver_port]
                log.info('The value of src_port is : {0}'.format(src_port))
                log.info('The value of dst_port is : {0}'.format(dst_port))
                
                log.info(banner('Creating The Host Interfaces on the Traffic Gen'))
                intf_hdl_dict = {}
                for port in testscript.parameters['configdict']['TG'][TG]['TEST-040']['tg_interface_config_dict'].keys():
                    intf_args = testscript.parameters['configdict']['TG'][TG]['TEST-040']['tg_interface_config_dict'][port]
                    intf_config = configureIxNetworkInterface(log,intf_args,tg_hdl = tgn_hdl,port_handle = port_handle_dict[port])
                    intf_hdl_dict[port] = intf_config['interface_handle']
                
                log.info(banner('sending ARP Request from the Initial Receiver...'))
                
                host_mac_args = testscript.parameters['configdict']['TG'][TG]['TEST-040']['tg_interface_config_dict'][receiver_port[0]]
                log.info(banner('The value of host_mac_args is : {0}'.format(host_mac_args)))
                ns = MyLib.my_config_utils.parseHostInterfaceArg(log,host_mac_args)
                log.info(banner('The value of ns is :{0}'.format(ns)))
                src_mac = ns.src_mac_addr
                traffic_config_obj = MyLib.my_config_utils.TrafficConfiguration(log,testscript,configdict,port_handle_dict)
                all_vtep_dict = trigger_obj.getDeviceDict('all_vtep')
                log.info(banner('Clearing the ARP entries before sending ARP Requets.'))
                for dut in all_vtep_dict.keys():
                    hdl1 = node_dict['all_dut'][dut]
                    hdl1.execute('clear ip arp vrf all force-delete ; clear mac add dynamic')        
                i = 0
                while (i < 1):
                    log.info(banner('Iteration # {0}'.format(i+1)))
                    res = traffic_config_obj.sendArpRequest(tg_hdl=tgn_hdl,port_handle=port_handle_dict[receiver_port[0]])
                    i+=1
                    countDownTimer(5)
                log.info(banner('Waiting for 10 seconds before checking the MAC Table'))
                countDownTimer(10)
                if res:
                    cfg = 'sh mac address-table address {0} | xml'.format(src_mac)
                    vpc_vtep_dict = trigger_obj.getDeviceDict('vpc_vtep')
                    for device in vpc_vtep_dict:
                        hdl = node_dict['all_dut'][device]
                        break
#                     hdl = node_dict['all_dut'][tgn_port_dut_mapping[receiver_port[0]]]
                    out = hdl.execute(cfg)
                    s = BeautifulSoup(out)
                    try:
                        port_info = s.find('disp_port').string
                    except:
                        log.info(banner('The Port information is not found. Resending the ARP Request:'))
                        res = traffic_config_obj.sendArpRequest(tg_hdl=tgn_hdl,port_handle=port_handle_dict[receiver_port[0]])
                        countDownTimer(2)
                    if re.search('nve',port_info):
                        log.info(banner('Configuring the Traffic Stream:'))
                        ixia_traffic_config = configureIxNetworkTraffic(self, traffic_args, tg_hdl=tgn_hdl, emulation_src_handle=intf_hdl_dict[source_port[0]],
                                                                        emulation_dst_handle=intf_hdl_dict[receiver_port[0]])
                        if not ixia_traffic_config['status']:
                            log.error(banner('Traffic Creation is not succesful...'))
                            self.failed()
                    
                        stream_dict = {}
                        stream_dict.setdefault('TEST-040',{})
                        stream_dict['TEST-040']['stream_id'] = ixia_traffic_config['stream_id']
                        
                        log.info(banner('Waiting for 10 seconds before starting the traffic after traffic creation'))
                        countDownTimer(10)
                        
                        log.info(banner('Starting the Traffic Stream: {0}'.format(ixia_traffic_config['stream_id'])))
                        b = tgn_hdl.traffic_control(action='run', handle = ixia_traffic_config['traffic_item'], max_wait_timer=60)

                        log.info(banner('Waiting for 30 seconds before collecting the traffic stats'))
                        countDownTimer(30)

                        res = MyLib.my_config_utils.getTrafficItemStatistics(log,tgn_hdl,stream_dict,'TEST-040')
                        
                        if abs(res['tx']-res['rx']) < threshold:
                            log.info('Traffic flow is as expected..The value of tx and Rx is : {0} and {1}'.format(res['tx'],res['rx']))
                            b = tgn_hdl.traffic_control(action='stop',handle = ixia_traffic_config['traffic_item'], max_wait_timer=60)
                            countDownTimer(15)
                            log.info(banner('Simulating MAC Move.. Sending ARP from the Host on the Remote VTEP'))
                            total_ports = list(testscript.parameters['configdict']['TG'][TG]['TEST-040']['tg_interface_config_dict'].keys())
                            log.info('The Value to Total Port is : {0}'.format(total_ports))
                            for port in source_port[0],receiver_port[0]:
                                total_ports.remove(port)
                            log.info(banner('The Value of total_ports now is : {0}'.format(total_ports)))
                            log.info(banner('Clearing the ARP entries before sending ARP Requets.'))
                            for dut in all_vtep_dict.keys():
                                hdl1 = node_dict['all_dut'][dut]
                                hdl1.execute('clear ip arp vrf all force-delete ; clear mac add dynamic')  
                            i=0
                            while (i < 1):
                                log.info(banner('Iteration # {0}'.format(i+1)))
                                res = traffic_config_obj.sendArpRequest(tg_hdl=tgn_hdl,port_handle=port_handle_dict[total_ports[0]])
                                i+=1
                                countDownTimer(5)
                            log.info(banner('Waiting for 30 seconds before checking the MAC Move'))
                            countDownTimer(30)
                            log.info(banner('Checking the Host Move'))
                            out = hdl.execute(cfg)
                            s = BeautifulSoup(out)
                            try:
                                new_port = s.find('disp_port').string
                            except:
                                log.info(banner('The port information is not found ... Sending ARP REquest again'))
                                res = traffic_config_obj.sendArpRequest(tg_hdl=tgn_hdl,port_handle=port_handle_dict[total_ports[0]])
                                countDownTimer(2)
                            log.info(banner('The value of new_port is : {0}'.format(new_port)))
#                             dut_info = tgn_port_dut_mapping[total_ports[0]]
#                             log.info('The value of dut_info is : {0}'.format(dut_info))
#                             tgn_interfaces = list(tgn_hdl.interfaces.aliases)
#                             for i in tgn_interfaces:
#                                 if re.search(dut_info,i):
#                                     new_port_info = i
#                             log.info(banner('The value of NEw Port Info is : {0}'.format(alias_intf_mapping_dict[new_port_info])))
                            
                            if re.search('Eth|Peer-link', new_port):
                                log.info(banner('The host got moved from {0} to {1}'.format(port_info,new_port)))
                                log.info('Checking The Traffic stats:')
                                c = tgn_hdl.traffic_control(action='run',handle = ixia_traffic_config['traffic_item'], max_wait_timer=60)
                                log.info(banner('Waiting for 30 seconds before collecting the traffic stats'))
                                countDownTimer(30)
    
                                res = MyLib.my_config_utils.getTrafficItemStatistics(log,tgn_hdl,stream_dict,'TEST-040')
                                
                                if not abs(res['tx'] - res['rx']) < threshold:
                                    log.info('Traffic loss is as expected..The value of tx and Rx is : {0} and {1}'.format(res['tx'],res['rx']))
                                    log.info(banner('Moving the host back to its Original Port'))
                                    d = tgn_hdl.traffic_control(action='stop',handle = ixia_traffic_config['traffic_item'], max_wait_timer=60)
                                    countDownTimer(15)
                                    log.info(banner('CLearing the ARP Entries before sending Fresh ARP Requests'))

                                    for dut in all_vtep_dict.keys():
                                        hdl1 = node_dict['all_dut'][dut]
                                        hdl1.execute('clear ip arp vrf all force-delete ; clear mac add dynamic')  
                                    log.info(banner('Sending ARP Request from the Original Port '))
                                    i = 0
                                    while (i < 1):
                                        log.info(banner('Iteration # {0}'.format(i+1)))
                                        res = traffic_config_obj.sendArpRequest(tg_hdl=tgn_hdl,port_handle=port_handle_dict[receiver_port[0]])
                                        i+=1
                                        countDownTimer(60)
                                    log.info(banner('Checking for The movement of host back to Original Port'))
                                    out = hdl.execute(cfg)
                                    s = BeautifulSoup(out)
                                    try:
                                        new1_port = s.find('disp_port').string
                                    except:
                                        log.info(banner('The port information is not found ... Sending ARP REquest again'))
                                        res = traffic_config_obj.sendArpRequest(tg_hdl=tgn_hdl,port_handle=port_handle_dict[receiver_port[0]])
                                        countDownTimer(5)
                                    
                                    if re.search('nve', new1_port):
                                        log.info(banner('The host got moved from {0} to {1}'.format(new_port,new1_port)))
                                        log.info('Checking The Traffic stats:')
                                        b = tgn_hdl.traffic_control(action='run',handle = ixia_traffic_config['traffic_item'], max_wait_timer=60)
                                        countDownTimer(15)
                                        log.info(banner('Waiting for 30 seconds before collecting the traffic stats'))
                                        countDownTimer(30)
    
                                        res = MyLib.my_config_utils.getTrafficItemStatistics(log,tgn_hdl,stream_dict,'TEST-040')
                                        
                                        if abs(res['tx'] - res['rx']) < threshold:
                                            log.info('Traffic has recovered to the Original POrt as expected.. The value of tx and Rx is : {0} and {1}'.format(res['tx'],res['rx']))
                                        else:
                                            log.error('Traffic has not recovered after moving the host back to Original dut: The value of tx and Rx is : {0} and {1}'.format(res['tx'],res['rx']))
                                            flag = 1
                                            
                                    else:
                                        log.error(banner('The Host should have got moved to {0} but points to {1}'.format(port_info,new1_port)))
                                        flag = 1
                                        
                                else:
                                    log.error('Traffic loss was expected after host Movement ... Traffic should now be recieved on the new Port')
                                    flag = 1
                            else:
                                log.error('Host move was Expected. But Has not happened. The host is at {0}'.format(new_port))
                                flag = 1
                        else:
                            log.error('Traffic Flow is not as expected. The value of tx and Rx is : {0} and {1}'.format(res['tx'],res['rx']))
                            flag = 1 
                        
                        
                        log.info('Deleting the Created Stream for this test: ')
        
                        x1 = tgn_hdl.traffic_control(action='stop', handle = ixia_traffic_config['traffic_item'],max_wait_timer=60)
                        
                        countDownTimer(30)
        
                        log.info('Removing the stream:')
                        y = tgn_hdl.traffic_config(mode='remove',stream_id=ixia_traffic_config['stream_id'])
                                
                        log.info('STarting all the other streams')
                        z = tgn_hdl.traffic_control(action='run',max_wait_timer=60)
                        
                        log.info('waiting for 30 seconds before collecting the stats:')
                        countDownTimer(30)
                        out = trigger_obj.checkAllStreamStats(tgn_hdl)
                        
                        if not out:
                            log.error(banner('Traffic has not recovered on some of the streams after starting the Original Streams.. Collecting the individual STream stats:'))
                            self.failed()
                                
                        if flag:
                            log.error(banner('The Traffic Flow was not as expected in one of the Steps.. Pls check logs.'))
                            self.failed()
                    else:
                        log.error('The Initial Traffic Condition did not pass:')
                        self.failed()     

class VXLANVxlanV6FUNC0147(aetest.Testcase):

    """ Multicast Traffic To Test IGMP SNooping """

    uid = 'VXLAN-L3-VxlanV6-FUNC-147'
    
    @aetest.test
    def VxlanV6IGMPSnoopingTest(self,log,testscript,testbed):
        
        node_dict = testscript.parameters['node_dict']
        tg_interface_hdl_dict = testscript.parameters['tg_interface_hdl_dict'] 
        traffic_stream_dict = testscript.parameters['traffic_stream_dict'] 
        port_handle_dict = testscript.parameters['port_handle_dict']
        TGList_config_file = testscript.parameters['TGList']
        configdict = testscript.parameters['configdict'] 
        tgn_config_dict = configdict['TG']
        threshold = testscript.parameters['traffic_threshold'] 
        tgn_port_dut_mapping = testscript.parameters['tgn_port_dut_mapping']
        alias_intf_mapping_dict = testscript.parameters['alias_intf_mapping']
        configured_stream = testscript.parameters['configured_stream']
        trigger_obj = testscript.parameters['trigger_obj']

        log.info(banner('The value of configured stream is : {0}'.format(configured_stream))) 
        
        login = [node_dict['all_dut'][dut].execute('show version') for dut in node_dict['all_dut'] if re.search('uut', dut)]
                
        for TG in tgn_config_dict.keys():
            tgn_hdl = testscript.parameters['testbed_obj'].devices[TG]
            out = trigger_obj.checkAllStreamStats(tgn_hdl)
        
            if out:
                devices = []
                for i in ['vpc_vtep','l2_switch']:
                    for j in list(trigger_obj.getDeviceDict(i)):
                        devices.append(j)
                        
                log.info(banner('The value of devices are : {0}'.format(devices)))
                
                res = trigger_obj.backUpAndRestoreConfigs(devices,'backup')

                source_port = testscript.parameters['configdict']['TG'][TG]['TEST-041']['traffic_config_dict']['source']
                receiver_port = testscript.parameters['configdict']['TG'][TG]['TEST-041']['traffic_config_dict']['receivers']
                traffic_args=testscript.parameters['configdict']['TG'][TG]['TEST-041']['traffic_config_dict']['params']
                 
                src_port = [port_handle_dict[x] for x in source_port]
                dst_port = [port_handle_dict[x] for x in receiver_port]
                log.info('The value of src_port is : {0}'.format(src_port))
                log.info('The value of dst_port is : {0}'.format(dst_port))
                
                flag = 0
                ixia_traffic_config =  configureIxNetworkRawTrafficL3New(self, traffic_args, tg_hdl=tgn_hdl, emulation_src_handle=src_port, emulation_dst_handle=dst_port)
                log.info('The value of ixia_traffic_config is : {0}'.format(ixia_traffic_config))
                
                l2_switch_hdl = trigger_obj.getDeviceDict('l2_switch')
                for dut, hdl1 in l2_switch_hdl.items(): pass
                
                hdl1.configure('no ip igmp snooping')
                
                log.info('Starting the Multicast Traffic Item... Sleeping for 30 seeconds after starting the stream')
                countDownTimer(30)
                
                stream_hdl = ixia_traffic_config['traffic_item']
                stream_id = ixia_traffic_config['stream_id']
                
                x = tgn_hdl.traffic_control(action='run', handle = stream_hdl,max_wait_timer=60)
                log.info('The value of x is : {0}'.format(x))
                
                if not x.status:
                    log.error(banner('The Stream {0} could not be started as expected '.format(ixia_traffic_config.stream_id)))
                    self.failed()
    
                stats = tgn_hdl.traffic_stats(stream = ixia_traffic_config['stream_id'], mode = 'traffic_item')
                log.info(banner('The Value of stats is : {0}'.format(stats)))
                tx_stat = stats.traffic_item[ixia_traffic_config['stream_id']]['tx'].total_pkt_rate
                rx_stat = stats.traffic_item[ixia_traffic_config['stream_id']]['rx'].total_pkt_rate
                
                log.info('The value of tx_stat is : {0}'.format(tx_stat))
                log.info('The value of rx_stat is : {0}'.format(rx_stat))
                
                exp_traffic = len(receiver_port) * tx_stat
                
                if abs(exp_traffic-rx_stat) < threshold:
                    log.info('Initial Traffic Flow is as expected. Tx and Rx is : {0} and {1}:'.format(tx_stat,rx_stat))
                    log.info(banner('Enabling IGMP Snoopoing on the VPC VTEPs'))
                    vpc_vtep_dict = trigger_obj.getDeviceDict('vpc_vtep')
                    for dut in vpc_vtep_dict:
                        hdl = vpc_vtep_dict[dut]
                        log.info(banner('Enabling Vxlan IGMP Snooping on dut {0}'.format(dut)))
                        hdl.configure('ip igmp snooping vxlan')
                    
                    log.info(banner('Waiting for 30 seconds before measuring the Traffic stats'))
                    countDownTimer(30)
                    stats = tgn_hdl.traffic_stats(stream = ixia_traffic_config['stream_id'], mode = 'traffic_item')
                    log.info(banner('The Value of stats is : {0}'.format(stats)))
                    tx_stat = stats.traffic_item[ixia_traffic_config['stream_id']]['tx'].total_pkt_rate
                    rx_stat = stats.traffic_item[ixia_traffic_config['stream_id']]['rx'].total_pkt_rate
                    
                    if rx_stat < threshold:
                        log.info(banner('Traffic drop is as expected After enabling Vxlan IGMP Snooping...Rx and Tx is : {0} and {1}'.format(tx_stat,rx_stat)))    
                        log.info(banner('Disabling IGMP Snooping on the VPC Switches:'))
                        for dut in vpc_vtep_dict:
                            hdl = vpc_vtep_dict[dut]
                            log.info(banner('Disabling Vxlan IGMP Snooping on dut {0}'.format(dut)))
                            hdl.configure('no ip igmp snooping vxlan')
                        
                        log.info(banner('Waiting for 30 seconds before measuring the Traffic stats'))
                        countDownTimer(30)
                        stats = tgn_hdl.traffic_stats(stream = ixia_traffic_config['stream_id'], mode = 'traffic_item')
                        log.info(banner('The Value of stats is : {0}'.format(stats)))
                        tx_stat = stats.traffic_item[ixia_traffic_config['stream_id']]['tx'].total_pkt_rate
                        rx_stat = stats.traffic_item[ixia_traffic_config['stream_id']]['rx'].total_pkt_rate   
                        
                        if abs(exp_traffic - rx_stat) < threshold:
                            log.info(banner('Traffic has recovered as expected after disabling Snooping.. Rx and Trx is : {0} and {1}'.format(tx_stat,rx_stat)))    
                        else:
                            log.error(banner('Traffic ha not recovered after disabling Vxlan IGMP Snooping, Rx and tx is : {0} and {1}'.format(tx_stat,rx_stat)))
                            flag = 1
                    
                    else:
                        log.error(banner('Traffic drop was expected after enabling Vxlan IGMP Snooping. Rx and Tx is: {0} and {1}'.format(tx_stat, rx_stat)))
                        flag = 1       
                    
                else:
                    log.info('Initial Multicast Traffic Flow is not as expected. The value of tx and rx is : {0} and {1}'.format(tx_stat,rx_stat))
                    flag = 1
                    
                log.info('Stopping the Multicast stream:')
                x1 = tgn_hdl.traffic_control(action='stop', handle = stream_hdl,max_wait_timer=60)
                
                countDownTimer(30)

                log.info('Removing the stream:')
                y = tgn_hdl.traffic_config(mode='remove',stream_id=stream_id)
                        
                log.info('STarting all the other streams')
                z = tgn_hdl.traffic_control(action='run',max_wait_timer=60)
                
                res = trigger_obj.backUpAndRestoreConfigs(devices,'restore')
                
                log.info('waiting for 30 seconds before collecting the stats:')
                countDownTimer(30)
                out = trigger_obj.checkAllStreamStats(tgn_hdl)
                
                if flag:
                    log.error(banner('Traffic condition on one of the step is not passed. Refer Log.'))
                    self.failed()
                if not out:
                        log.error(banner('Traffic has not recovered on some of the streams Even after restoring the Original Configs.. Collecting the individual STream stats:'))
                        self.failed()
                        
            else:
                log.error('The Initial Traffic Condition did not pass:')
                self.failed()    

class VXLANVxlanV6FUNC0148(aetest.Testcase):

    """ VRF Delete / add"""

    uid = 'VXLAN-L3-VxlanV6-FUNC-148'
    
    @aetest.test
    def VxlanV6VRFDeleteAdd(self,log,testscript,testbed):
        
        node_dict = testscript.parameters['node_dict']
        tg_interface_hdl_dict = testscript.parameters['tg_interface_hdl_dict'] 
        traffic_stream_dict = testscript.parameters['traffic_stream_dict'] 
        port_handle_dict = testscript.parameters['port_handle_dict']
        TGList_config_file = testscript.parameters['TGList']
        configdict = testscript.parameters['configdict'] 
        tgn_config_dict = configdict['TG']
        threshold = testscript.parameters['traffic_threshold'] 
        tgn_port_dut_mapping = testscript.parameters['tgn_port_dut_mapping']
        alias_intf_mapping_dict = testscript.parameters['alias_intf_mapping']
        configured_stream = testscript.parameters['configured_stream']
        trigger_obj = testscript.parameters['trigger_obj']

        log.info(banner('The value of configured stream is : {0}'.format(configured_stream))) 
        
        login = [node_dict['all_dut'][dut].execute('show version') for dut in node_dict['all_dut'] if re.search('uut', dut)]
                
        for TG in tgn_config_dict.keys():
            tgn_hdl = testscript.parameters['testbed_obj'].devices[TG]
            out = trigger_obj.checkAllStreamStats(tgn_hdl)
        
            flag = 0
            if out:
                devices = list(trigger_obj.getDeviceDict('all_vtep').keys())
                        
                log.info(banner('The value of devices are : {0}'.format(devices)))
                
                res = trigger_obj.backUpAndRestoreConfigs(devices,'backup')
                
                for dut in devices:
                    hdl = node_dict['all_dut'][dut]
                    log.info('Getting the VRF From the box {0}'.format(dut))
                    res = MyLib.my_config_utils.getVRFConfigured(log,dut,node_dict)
                    log.info(banner('The value of VRF_list is : {0}'.format(res)))
                    
                    for vrf in res:
                        cfg = 'no vrf context {0}'.format(vrf)
                        hdl.configure(cfg)
                
                log.info(banner('Waiting for 60 seconds before configuring back the VRF on all VTEPs'))
                countDownTimer(60)
                            
                res = trigger_obj.backUpAndRestoreConfigs(devices,'restore')
                
                log.info('waiting for 100 seconds before collecting the stats:')
                countDownTimer(100)
                out = trigger_obj.checkAllStreamStats(tgn_hdl)

                traffic_stats_obj = MyLib.my_config_utils.TrafficStatistics(log,tg_interface_hdl_dict,traffic_stream_dict,port_handle_dict,
                                                            threshold,node_dict,alias_intf_mapping_dict,configured_stream)
                
                if out:
                    log.info('Traffic recovery was successful after the triigger:')
                
                    log.info(banner('Bound Stream Traffic stats:'))
                    res = traffic_stats_obj.getAllBoundStreamStatistics(tgn_hdl)
                    log.info(banner('Raw Stream Traffic stats:'))
                    res = traffic_stats_obj.getAllRawStreamStatistics(tgn_hdl)                

                if not out:
                        log.error(banner('Traffic has not recovered on some of the streams Even after restoring the Original Configs.. Collecting the individual STream stats:'))
                        flag = 1
                        log.info(banner('Bound Stream Traffic stats:'))
                        res = traffic_stats_obj.getAllBoundStreamStatistics(tgn_hdl)
                        log.info(banner('Raw Stream Traffic stats:'))
                        res = traffic_stats_obj.getAllRawStreamStatistics(tgn_hdl)
                        
                if flag:
                    log.error(banner('Traffic Recovery after the Trigger was not succesful'))
                    self.failed()
            else:
                log.error('The Initial Traffic Condition did not pass:')
                self.failed()    

class VXLANVxlanV6FUNC0149(aetest.Testcase):

    """ VLan-VNI MApping Change - L2 VNI"""

    uid = 'VXLAN-L3-VxlanV6-FUNC-149'
    
    @aetest.test
    def VxlanV6L2VlanVNIMappingChange(self,log,testscript,testbed):
        
        node_dict = testscript.parameters['node_dict']
        tg_interface_hdl_dict = testscript.parameters['tg_interface_hdl_dict'] 
        traffic_stream_dict = testscript.parameters['traffic_stream_dict'] 
        port_handle_dict = testscript.parameters['port_handle_dict']
        TGList_config_file = testscript.parameters['TGList']
        configdict = testscript.parameters['configdict'] 
        tgn_config_dict = configdict['TG']
        threshold = testscript.parameters['traffic_threshold'] 
        tgn_port_dut_mapping = testscript.parameters['tgn_port_dut_mapping']
        alias_intf_mapping_dict = testscript.parameters['alias_intf_mapping']
        configured_stream = testscript.parameters['configured_stream']
        trigger_obj = testscript.parameters['trigger_obj']

        log.info(banner('The value of configured stream is : {0}'.format(configured_stream))) 
        
        login = [node_dict['all_dut'][dut].execute('show version') for dut in node_dict['all_dut'] if re.search('uut', dut)]
                
        for TG in tgn_config_dict.keys():
            tgn_hdl = testscript.parameters['testbed_obj'].devices[TG]
            out = trigger_obj.checkAllStreamStats(tgn_hdl)
        
            flag = 0
            if out:
                devices = list(trigger_obj.getDeviceDict('all_vtep').keys())
                        
                log.info(banner('The value of devices are : {0}'.format(devices)))
                
                res = trigger_obj.backUpAndRestoreConfigs(devices,'backup')
                
                vlan_args = '-no_of_l2_vlans 100 -l2_vlan_start 701 -l2_vni_start 10701'
                nve_args = '-no_of_l2_vni 100 -l2_vni_start 10701 -evpn_ir True -shutdown False'
                evpn_args = '-no_of_vnis 100 -l2_vni_start 10701 -rd auto -route_target_import_list auto -route_target_export_list auto'
                try:
                    
                    evpn_config_dict= {}
                    for dut in trigger_obj.getDeviceDict('all_vtep'):
                        evpn_config_dict[dut]={}
                        evpn_config_dict[dut]['evpn'] = evpn_args
                    evpn_cfg_dict = MyLib.my_config_utils.generateEvpnDict(log,evpn_config_dict,trigger_obj.getDeviceDict('all_vtep'))
    
                    log.info('The value of evpn_cfg_dict is : {0}'.format(evpn_cfg_dict))
                    
                    for dut in devices:
                        
                        hdl = node_dict['all_dut'][dut]
#                         log.info(banner('Changing the L2 VLan-VNI Mapping on the vtep {0}'.format(dut)))
# #                         scale_config_obj = MyLib.my_config_utils.ScaleConfig(log,node_dict,configdict,alias_intf_mapping)
#                         MyLib.my_config_utils.configureVlans(log,hdl,vlan_args)
#                         log.info(banner('Configuring the NVE interfaces configs on the VTEP {0}'.format(dut)))
#                         MyLib.my_config_utils.cfgL2VNIOnNVeIntf(dut,hdl,nve_args,log)
#                         log.info(banner('Configuring the EVPN related config on the VTEP {0}'.format(dut)))
#                         MyLib.my_config_utils.evpn_lib.configEvpn(dut,hdl,evpn_cfg_dict[dut],log)
    
                        log.info(banner('Changing the L2 VNI , NVE configs & EVPN configs...'))
                        
                        threads = []
                        t1 = threading.Thread(target = MyLib.my_config_utils.configureVlans, 
                                              args = [log,hdl,vlan_args])
                        t2 = threading.Thread(target = MyLib.my_config_utils.cfgL2VNIOnNVeIntf,
                                              args = [dut,hdl,nve_args,log])
                        t3 = threading.Thread(target = MyLib.my_config_utils.evpn_lib.configEvpn,
                                              args = [dut,hdl,evpn_cfg_dict[dut],log])
                        
#                         t1.daemon(True)
#                         t2.daemon(True)
#                         t3.daemon(True)
                        
                        t1.start()
                        t2.start()
                        t3.start()
                        
                        threads.append(t1)
                        threads.append(t2)
                        threads.append(t3)
                        
                        for t in threads:
                            t.join()

                except Exception as e:
                    log.error('some Exception Occured. Exception is : {0}'.format(e))
                    res = trigger_obj.backUpAndRestoreConfigs(devices,'restore')
                    self.failed()
                
                log.info(banner('Waiting for 60 seconds before reverting back the configs.'))
                countDownTimer(60)
                            
                res = trigger_obj.backUpAndRestoreConfigs(devices,'restore')
                
                log.info('waiting for 100 seconds before collecting the stats:')
                countDownTimer(100)
                out = trigger_obj.checkAllStreamStats(tgn_hdl)

                traffic_stats_obj = MyLib.my_config_utils.TrafficStatistics(log,tg_interface_hdl_dict,traffic_stream_dict,port_handle_dict,
                                                            threshold,node_dict,alias_intf_mapping_dict,configured_stream)
                
                if out:
                    log.info('Traffic recovery was successful after the triigger:')
                
                    log.info(banner('Bound Stream Traffic stats:'))
                    res = traffic_stats_obj.getAllBoundStreamStatistics(tgn_hdl)
                    log.info(banner('Raw Stream Traffic stats:'))
                    res = traffic_stats_obj.getAllRawStreamStatistics(tgn_hdl)                

                if not out:
                        log.error(banner('Traffic has not recovered on some of the streams Even after restoring the Original Configs.. Collecting the individual STream stats:'))
                        flag = 1
                        log.info(banner('Bound Stream Traffic stats:'))
                        res = traffic_stats_obj.getAllBoundStreamStatistics(tgn_hdl)
                        log.info(banner('Raw Stream Traffic stats:'))
                        res = traffic_stats_obj.getAllRawStreamStatistics(tgn_hdl)
                        
                if flag:
                    log.error(banner('Traffic Recovery after the Trigger was not succesful'))
                    self.failed()
            else:
                log.error('The Initial Traffic Condition did not pass:')
                self.failed()                    
    
                                
class CommonCleanup(aetest.Testcase):
    
    """ VLan State Change on Both the DUTS """

    uid = 'VXLAN-L3-TRM-FUNC-001'

    @aetest.subsection
    def checkTopo(self):
        pass
        
        
class CommonCleanup(aetest.CommonCleanup):

    @aetest.subsection
    def disconnect(self):
        pass

