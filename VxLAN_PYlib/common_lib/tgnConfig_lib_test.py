
import re
import time
import logging
import collections
import yaml
import ipaddress
import copy
import os
#import parsergen
from common_lib import utils
from common_lib import parserutils_lib

import getpass
import sys
import copy
import random
import inspect
import threading
import bisect
import struct
import socket
import ipaddr
import netaddr
import re

from ats import aetest
from ats import topology
from ats.log.utils import banner
from ats.async_ import pcall

log = logging.getLogger(__name__)
log.setLevel(logging.DEBUG)


def parseTgDeviceConfigs(log, args):

    arggrammar={}
    arggrammar['port_handle']='-type str'
    arggrammar['mode']='-type str'
    arggrammar['router_id']='-type str'
    arggrammar['enable_ping_response']='-type int -default 0'
    arggrammar['ipv4_start']='-type str'
    arggrammar['ipv4Mask']='-type str'
    arggrammar['ipv4Gw']='-type str'
    arggrammar['ipv4_start_step']='-type str'
    arggrammar['ipv4Gw_step']='-type str'
    arggrammar['deviceip_step']='-type str'
    arggrammar['devicemac_step']='-type str'
    arggrammar['macaddr_start']='-type str'
    arggrammar['macaddr_start_step']='-type str'
    arggrammar['vlan_id_start']='-type int'
    arggrammar['vlan_count']='-type int'
    arggrammar['device_count']='-type int'
    arggrammar['netmask']='-type str'
 
    device_parse=parserutils_lib.argsToCommandOptions( args, arggrammar, log )
    return device_parse

def parseTrafficConfigs(log,args):
 
    arggrammar={}
    arggrammar['srcPort']='-type str' 
    arggrammar['dstPort']='-type str'
    arggrammar['l3Proto']='-type str'
    arggrammar['name']='-type str'
    arggrammar['rate_pps']='-type int'
    arggrammar['transmit_mode']='-type str'
    arggrammar['frame_size']='-type int'
    arggrammar['mode']='-type str'
    arggrammar['mac_gw']='-type str'
    arggrammar['host_profile']='-type str'

    traffic_parse=parserutils_lib.argsToCommandOptions( args, arggrammar, log )
    return traffic_parse

def configureDevicesPerVlan(log, tgn_hdl, traffic_config_dict):

    handleDict={}
    handleDictPerVlan={}
    handleListPerPort=[]
    for profile in traffic_config_dict['host_config']:
      handleDict[profile]={}
      handleDictPerVlan[profile]={}
      for port in traffic_config_dict['host_config'][profile]:
         port_hdl=tgn_hdl.interfaces[port].tgen_port_handle
         handleListPerPort=[]
         handleDict[profile][port]={}
         handleDictPerVlan[profile][port]={}
         ns=parseTgDeviceConfigs(log,traffic_config_dict['host_config'][profile][port])
         for vlan in range(ns.vlan_id_start,ns.vlan_count+ns.vlan_id_start):
                   #handleDict[port]['vlan{0}'.format(vlan)]={}
                   if vlan == ns.vlan_id_start:
                         ipv4_start= ns.ipv4_start
                         mac_start= ns.macaddr_start
                         ipv4Gw=ns.ipv4Gw
                   else:
                         ipv4_start=utils.incrementIpv4Address(ipv4_start,ns.ipv4_start_step)
                         mac_start=utils.incrementMacAddress(mac_start,ns.macaddr_start_step)
                         ipv4Gw=utils.incrementIpv4Address(ipv4Gw,ns.ipv4Gw_step)

                   ipadd_list=utils.getIPv4AddressesList(ipv4_start,ns.deviceip_step,ns.device_count)
                   macadd_list=utils.getMacAddressList(mac_start,ns.devicemac_step,ns.device_count)

                   handleListPerVlan=[]
                   for dev in range(0,ns.device_count):
                           if re.search('spirent',tgn_hdl.type,re.I):
                                 result=tgn_hdl.emulation_device_config(mode=ns.mode, port_handle = port_hdl,encapsulation = 'ethernet_ii_vlan',count = 1, enable_ping_response=ns.enable_ping_response,ip_version ='ipv4',intf_ip_addr = ipadd_list[dev], intf_prefix_len = ns.ipv4Mask, intf_ip_addr_step = '0.0.0.1', mac_addr = macadd_list[dev] ,mac_addr_step = '00:00:00:00:00:01',vlan_id = vlan, gateway_ip_addr = ipv4Gw)
                                 if result.status:
                                    handleListPerPort.append(result.handle)
                                    handleListPerVlan.append(result.handle)
                                 else:
                                    log.error('The device config on port {0} failed for {1}'.format(port,vlan))
                                    return 0
                              
                           elif re.search('ixia',tgn_hdl.type,re.I):
                                 result=tgn_hdl.interface_config(mode='config', port_handle = port_hdl,vlan = 1, arp_send_req=ns.enable_ping_response,intf_ip_addr = ipadd_list[dev], netmask = ns.netmask, intf_ip_addr_step = '0.0.0.1', src_mac_addr = macadd_list[dev] ,src_mac_addr_step = '00:00:00:00:00:01',vlan_id = vlan, gateway = ipv4Gw)
                                 if result.status:
                                   handleListPerPort.append(result.interface_handle)
                                   handleListPerVlan.append(result.interface_handle)
                                 else:
                                    log.error('The device config on port {0} failed for {1}'.format(port,vlan))
                                    return 0

                   handleDictPerVlan[profile][port]['vlan{0}'.format(vlan)]=handleListPerVlan
         handleDict[profile][port]=handleListPerPort
    return 1,handleDict,handleDictPerVlan

def tgn_arp(log,tgn_hdl, traffic_config_dict,traffic_handle_dict):

          retVal=1
          port_hdl_list=[]
          
          for profile in traffic_config_dict:
                ts=parseTrafficConfigs(log,traffic_config_dict[profile])
                port_hdl_list.append(tgn_hdl.interfaces[ts.srcPort].tgen_port_handle)
          port_hdl_list=list(set(port_hdl_list))
          result_arp=tgn_hdl.arp_control(arp_target = 'port', port_handle = port_hdl_list)
          if result_arp.status:
                     log.info('ARP started sucessfully')
          else:
                     log.error('ARP not started')
                     retVal=0
          if retVal:
                  return 1
          else:
                  return 0
          
def tgn_traffic(log,tgn_hdl, traffic_config_dict,traffic_handle_dict,action):
          retVal=1
          port_hdl_list=[]
          
          for profile in traffic_config_dict:
                ts=parseTrafficConfigs(log,traffic_config_dict[profile])
                port_hdl_list.append(tgn_hdl.interfaces[ts.srcPort].tgen_port_handle)
          port_hdl_list=list(set(port_hdl_list))
          if action =='start':
                '''
                result_arp=tgn_hdl.arp_control(arp_target = 'port', port_handle = port_hdl_list)
                time.sleep(60)
                if result_arp.status:
                     log.info('ARP started sucessfully')
                else:
                     log.error('ARP not started')
                     retVal=0
                '''
                result_traffic=tgn_hdl.traffic_control (port_handle = port_hdl_list, action = 'run')
                if result_traffic.status:
                     log.info('Traffic started sucessfully')
                else:
                     log.error('Traffic not started')
                     retVal=0
                time.sleep(30)
          if action == 'stop':
               result_traffic=tgn_hdl.traffic_control (port_handle = port_hdl_list, action = 'stop')
               if result_traffic.status:
                    log.info('Traffic stopped sucessfully')
               else:
                    log.error('Traffic not stopped')
               time.sleep(30)
          if retVal:
                  return 1
          else:
                  return 0
          
                           

def configV4PortBoundTraffic (log,tgn_hdl, traffic_config_dict, handleDict):
           traffic_handle_dict={}
           retVal=1
           for profile in traffic_config_dict:
                   traffic_handle_dict[profile]={}
                   ts=parseTrafficConfigs(log,traffic_config_dict[profile])
                   port_hdl=tgn_hdl.interfaces[ts.srcPort].tgen_port_handle
                   dst_port_hdl=tgn_hdl.interfaces[ts.dstPort].tgen_port_handle
                   if re.search('spirent',tgn_hdl.type,re.I):
                       result = tgn_hdl.traffic_config (mode = ts.mode, port_handle = port_hdl, emulation_src_handle = handleDict[ts.host_profile][ts.srcPort],emulation_dst_handle = handleDict[ts.host_profile][ts.dstPort],dest_port_list=dst_port_hdl, l3_protocol = 'ipv4', ip_id = '0', ip_ttl = '255',ip_hdr_length = '5', ip_protocol = '253', ip_fragment_offset = '0', ip_mbz = '0',ip_precedence = '0', ip_tos_field = '0', enable_control_plane = '0',l3_length = ts.frame_size, name = ts.name, fill_type = 'constant', fcs_error = '0',fill_value = '0', frame_size = ts.frame_size, traffic_state = '1',traffic_pattern='pair',high_speed_result_analysis = '1', length_mode = 'fixed',tx_port_sending_traffic_to_self_en = 'false', disable_signature = '0',enable_stream_only_gen = '1', endpoint_map = 'one_to_one', pkts_per_burst = '1',inter_stream_gap_unit = 'bytes', burst_loop_count = '30', transmit_mode = ts.transmit_mode,inter_stream_gap = '12', rate_pps = ts.rate_pps,mac_discovery_gw=ts.mac_gw)
                   elif re.search('ixia',tgn_hdl.type,re.I):
                       result = tgn_hdl.traffic_config (mode = ts.mode, port_handle = port_hdl, emulation_src_handle = handleDict[ts.host_profile][ts.srcPort],emulation_dst_handle = handleDict[ts.host_profile][ts.dstPort], l3_protocol = 'ipv4', ip_id = '0', ip_ttl = '255',ip_hdr_length = '5', ip_protocol = '253', ip_fragment_offset = '0',ip_precedence = '0',l3_length = ts.frame_size, name = ts.name, frame_size = ts.frame_size, length_mode = 'fixed', pkts_per_burst = '1', burst_loop_count = '30', transmit_mode = ts.transmit_mode,inter_stream_gap = '12', rate_pps = ts.rate_pps,track_by="endpoint_pair traffic_item")
                   
                   if result.status:
                        traffic_handle_dict[profile]=result.stream_id
                   else:
                        retVal=0
                        log.error('The traffic profile config on port {0} failed for stream {1}'.format(ts.srcPort,ts.name))
           if retVal:
                  return 1,traffic_handle_dict
           else:
                  return 0
                   
def configRawTraffic (log,tgn_hdl, traffic_config_dict):
 
                   ts=parseTrafficConfigs(log,traffic_config_dict['traffic_config'][profile])
                   port_hdl=tgn_hdl.interfaces[ts.srcPort].tgen_port_handle

                   result = tgn_hdl.traffic_config (mode = ts.mode, port_handle = port_hdl,dest_port_list=ts.dst_port,l2_encap = ethernet_ii_vlan,mac_src_count=ts.mac_src_count, mac_src_mode=ts.mac_src_mode,mac_src_repeat_count='0',vlan_id_count=ts.vlan_id_count,vlan_id_mode=ts.vlan_id_mode,vlan_id_repeat='0',vlan_id_step=ts.vlan_id_step,mac_src=ts.mac_src,mac_dst=ts.mac_dst,vlan_id=ts.vlan_id,enable_control_plane= '0',name=ts.name,length_mode='fixed',endpoint_map= 'one_to_one',traffic_pattern='pair',l3_length = ts.frame_size,fill_type = 'constant', fcs_error = '0',fill_value = '0', frame_size = ts.frame_size, traffic_state = '1',high_speed_result_analysis = '1',tx_port_sending_traffic_to_self_en = 'false', disable_signature = '0',enable_stream_only_gen = '1', pkts_per_burst = '1',inter_stream_gap_unit = 'bytes', burst_loop_count = '30', transmit_mode = ts.transmit_mode,inter_stream_gap = '12', rate_pps = ts.rate_pps,enable_stream='false')
                   if result.status:
                        return result.stream_id
                   else:
                        log.error('The Raw traffic profile config on port {0} failed for stream {1}'.format(ts.srcPort,ts.name))
                        return 0 
 
def verifyTrafficDrop(log,tgn_hdl,traffic_config_dict,stream_handle_dict,*args):
         arggrammar={}
         arggrammar['testType'] = '-type str -choices ["positive","negative"] -default positive'
         retVal=1         
         for profile in traffic_config_dict:
             ns = parserutils_lib.argsToCommandOptions(args,arggrammar,log)
             ts=parseTrafficConfigs(log,traffic_config_dict[profile])
             port_hdl=tgn_hdl.interfaces[ts.srcPort].tgen_port_handle
             dst_port_hdl=tgn_hdl.interfaces[ts.dstPort].tgen_port_handle

             if re.search('spirent',tgn_hdl.type,re.I):
               #traffic_results_ret=tgn_hdl.traffic_stats(port_handle=port_hdl,mode='streams',rx_port_handle=dst_port_hdl,scale_mode = 1)
               traffic_results_ret=tgn_hdl.traffic_stats(port_handle=port_hdl,mode='all')
               print(traffic_results_ret)
               for item in traffic_results_ret[port_hdl]['stream']:
                    if re.search('streamblock[\d]+',item):
                       if traffic_results_ret[port_hdl]['stream'][item]['tx'].name == profile:
                            tx=traffic_results_ret[port_hdl]['stream'][item]['tx'].total_pkt_rate
                            rx=traffic_results_ret[port_hdl]['stream'][item]['rx'].total_pkt_rate
               log.info(f'The Tx for traffic stream {ts.name} is : {tx}')
               log.info(f'The rx for traffic stream {ts.name} is : {rx}')

               if ns.testType == 'positive':
                  if (tx-rx) > 200:
                    log.error(f'The Traffic Drop is more then expected for {ts.name}')
                    retVal=0
                  else:
                    log.info(f'The traffic drop is not seen for traffic stream {ts.name}')
               else:
                    if (tx-rx) == 0:
                       log.info(f'The traffic drop is seen for {ts.name} as expected')
                    else:
                       log.error(f'The Traffic Drop is not seen for {ts.name} as expected')
                       retVal=0
             if re.search('ixia',tgn_hdl.type,re.I):
               #traffic_results_ret=tgn_hdl.traffic_stats(port_handle=port_hdl,mode='streams',rx_port_handle=dst_port_hdl,scale_mode = 1)
               traffic_results_ret=tgn_hdl.traffic_stats(port_handle=port_hdl,mode='streams')
               print(traffic_results_ret)
               for item in traffic_results_ret[dst_port_hdl]['stream']:
                    print(f'### The Item is {item}')
                    if re.search(f'\S+{profile}',item):
                            print('###Debug: {0}'.format(traffic_results_ret[dst_port_hdl]['stream'][item]))
                            loss_percent=traffic_results_ret[dst_port_hdl]['stream'][item]['rx'].loss_percent
               log.info(f'The Loss for traffic stream {ts.name} is : {loss_percent}')

               if ns.testType == 'positive':
                  if loss_percent > 20:
                    log.error(f'The Traffic Drop is more then expected for {ts.name}')
                    retVal=0
                  else:
                    log.info(f'The traffic drop is not seen for traffic stream {ts.name}')
               else:
                    if loss_percent == 100:
                       log.info(f'The traffic drop is seen for {ts.name} as expected')
                    else:
                       log.error(f'The Traffic Drop is not seen for {ts.name} as expected')
                       retVal=0


         if retVal:
                  return 1
         else:
                  return 0
         

          

