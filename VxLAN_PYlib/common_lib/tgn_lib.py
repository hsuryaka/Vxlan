#!/bin/env python
###################################################################
# Author: Manas Kumar Dash (mdash)
# This lib contain various library functions for configuring
# traffic Generators. It takes tgn type and configures IXIA or STC
###################################################################

import re
import time
import logging
import collections
import yaml
import ipaddress
import copy
import os
#import parsergen

from ats import aetest
from ats import topology
from ats.log.utils import banner
from ats.async_ import pcall
from common_lib.utility_lib import *

log = logging.getLogger(__name__)
log.setLevel(logging.DEBUG)

# Its recommended to use following dict format to be used for traffic verification 
'''
tgn_traffic_dict:
   src_ports:
     src_port_1:
        physical_intf:
        port_hdl:
        streams:
           streams_present:
           stream_1:
               name: 
               id :
               dst_port_hdl_list:    
           stream_2:
               name: 
               id :
               dst_port_hdl_list:    
     src_port_2:
        physical_intf:
        port_hdl:
        streams:
           streams_present:
           stream_1:
               name:
               id :
               dst_port_hdl_list:
           stream_2:
               name:
               id :
               dst_port_hdl_list:

'''
def add_stream_to_traffic_dict(traffic_dict = {}, stream_src_intf = '', stream_src_intf_hdl = '', stream_name = '', \
                        stream_hdl = '', stream_dst_port_hdl_list = []):
    if not isinstance(traffic_dict, dict):
       log.info('traffic_dict argument is not instance of dict')
       return 0
    if not stream_src_intf:
       log.info('Stream source interface specified as null')
       return 0
    if not stream_src_intf_hdl:
       log.info('Stream source interface handle specified as null')
       return 0
    if not stream_name:
       log.info('Stream name is specified as null')
       return 0
    if not stream_hdl:
       log.info('Stream handle is specified as null')
       return 0
    if not stream_dst_port_hdl_list:
       log.info('Stream dest port handle list is specified as null')
       return 0
    if not 'src_ports' in traffic_dict.keys():
       traffic_dict['src_ports'] = {}
    #If this is the first stream is being added to data structure
    if not traffic_dict['src_ports'].keys():
       traffic_dict['src_ports']['src_port_1'] = {}
       traffic_dict['src_ports']['src_port_1']['physical_intf'] = stream_src_intf
       traffic_dict['src_ports']['src_port_1']['port_hdl'] = stream_src_intf_hdl
       traffic_dict['src_ports']['src_port_1']['streams'] = {}
       traffic_dict['src_ports']['src_port_1']['streams']['streams_present'] = 1
       traffic_dict['src_ports']['src_port_1']['streams']['stream_1'] = {}
       traffic_dict['src_ports']['src_port_1']['streams']['stream_1']['name'] = stream_name
       traffic_dict['src_ports']['src_port_1']['streams']['stream_1']['id'] = stream_hdl
       traffic_dict['src_ports']['src_port_1']['streams']['stream_1']['dst_port_hdl_list'] = stream_dst_port_hdl_list
       return 1
    count = 0
    for src_port_index in traffic_dict['src_ports'].keys(): 
       count += 1
       #If streams are already created under ports, need to add stream to the source port
       if traffic_dict['src_ports'][src_port_index]['port_hdl'] == stream_src_intf_hdl:
          i = 1 
          #Check if stream is already added return 0
          while i <= traffic_dict['src_ports'][src_port_index]['streams']['streams_present']:
             if traffic_dict['src_ports'][src_port_index]['streams']['stream_' + str(i)]['name'] == stream_name:
                log.info('Stream %r is already added to traffic dict', stream_name)
                return 0
             i += 1
          #Add stream to the dictionary
          strm_count = traffic_dict['src_ports'][src_port_index]['streams']['streams_present']
          strm_count += 1
          str_index = 'stream_' + str(strm_count)
          traffic_dict['src_ports'][src_port_index]['streams']['streams_present'] = strm_count
          traffic_dict['src_ports'][src_port_index]['streams'][str_index] = {}
          traffic_dict['src_ports'][src_port_index]['streams'][str_index]['name'] = stream_name
          traffic_dict['src_ports'][src_port_index]['streams'][str_index]['id'] = stream_hdl
          traffic_dict['src_ports'][src_port_index]['streams'][str_index]['dst_port_hdl_list'] = stream_dst_port_hdl_list
          return 1
    #If this is a new source port
    src_port_index = 'src_port_' + str(count +1)
    traffic_dict['src_ports'][src_port_index] = {}
    traffic_dict['src_ports'][src_port_index]['physical_intf'] = stream_src_intf
    traffic_dict['src_ports'][src_port_index]['port_hdl'] = stream_src_intf_hdl
    traffic_dict['src_ports'][src_port_index]['streams'] = {}
    traffic_dict['src_ports'][src_port_index]['streams']['streams_present'] = 1
    traffic_dict['src_ports'][src_port_index]['streams']['stream_1'] = {}
    traffic_dict['src_ports'][src_port_index]['streams']['stream_1']['name'] = stream_name
    traffic_dict['src_ports'][src_port_index]['streams']['stream_1']['id'] = stream_hdl
    traffic_dict['src_ports'][src_port_index]['streams']['stream_1']['dst_port_hdl_list'] = stream_dst_port_hdl_list
    return 1

def tgn_verify_traffic(tgn_hdl, tgn_traffic_dict, traffic_results, src_port_hdl_list = [], strm_name_list = []):
    if re.search('ixia', tgn_hdl.type, re.I):
       fail_flag = 0
       stream_found = 0
       for src_port_hdl in src_port_hdl_list:
         for src_port_index in tgn_traffic_dict['src_ports'].keys():
           if tgn_traffic_dict['src_ports'][src_port_index]['port_hdl'] == src_port_hdl:
             for each_key in tgn_traffic_dict['src_ports'][src_port_index]['streams'].keys():
               if re.search('stream_(\d+)', each_key, re.I):
                  strm_index = each_key
               else:
                  continue
               strm_id = tgn_traffic_dict['src_ports'][src_port_index]['streams'][strm_index]['id']
               strm_name = tgn_traffic_dict['src_ports'][src_port_index]['streams'][strm_index]['name']
               if strm_name_list:
                  if not strm_name in strm_name_list:
                     continue
                  else:
                     stream_found += 1
               result_dict = traffic_results[src_port_hdl]['stream'][strm_id]
               tx_total_pkts = result_dict['tx']['total_pkts']
               dst_port_hdl = tgn_traffic_dict['src_ports'][src_port_index]['streams'][strm_index]['dst_port_hdl_list'][0]
               result_dict_rx = traffic_results[dst_port_hdl]['stream'][strm_id]
               rx_total_pkts = result_dict_rx['rx']['total_pkts']
               tx_rate = result_dict['tx']['total_pkt_rate']
               rx_rate = result_dict_rx['rx']['total_pkt_rate']
               rx_dropped_pkt = result_dict_rx['rx']['loss_pkts']
               log.info('For %r Transmitted Pkts = %r', strm_name, tx_total_pkts)
               log.info('For %r Transmitted, received Pkts = %r', strm_name, rx_total_pkts)
               log.info('For %r Transmitted, dropped_pkts = %r', strm_name, rx_dropped_pkt)
               log.info('For %r Transmitted, transmit rate = %r', strm_name, tx_rate)
               log.info('For %r Transmitted, received rate = %r', strm_name, rx_rate)
               if int(rx_dropped_pkt) > 10:
                  log.info ('Pkt Drop is seen for stream %r', strm_name)
                  fail_flag = 1
               else:
                  if (int(tx_total_pkts) - int(rx_total_pkts)) > 20:
                     log.info ('TX and RX Frame count difference is greater than 20')
                     fail_flag = 1
       if fail_flag:
          return 0
       if strm_name_list:
          if len(strm_name_list) != stream_found:
             log.info('All streams are not found in Results')
             return 0
       return 1
    if re.search('spirent', tgn_hdl.type, re.I):
       fail_flag = 0
       stream_found = 0
       for src_port_hdl in src_port_hdl_list:
         for src_port_index in tgn_traffic_dict['src_ports'].keys():
           if tgn_traffic_dict['src_ports'][src_port_index]['port_hdl'] == src_port_hdl:
             for each_key in tgn_traffic_dict['src_ports'][src_port_index]['streams'].keys():
               if re.search('stream_(\d+)', each_key, re.I):
                  strm_index = each_key
               else:
                  continue
               strm_id = tgn_traffic_dict['src_ports'][src_port_index]['streams'][strm_index]['id']
               strm_name = tgn_traffic_dict['src_ports'][src_port_index]['streams'][strm_index]['name']
               if strm_name_list:
                  if not strm_name in strm_name_list:
                     continue
                  else:
                     stream_found += 1
               result_dict = traffic_results[src_port_hdl]['stream'][strm_id]
               tx_total_pkts = result_dict['tx']['total_pkts']
               rx_total_pkts = result_dict['rx']['total_pkts']
               rx_port = result_dict['rx']['rx_port']
               if not rx_port:
                  rx_port = ''
               rx_sig_count = result_dict['rx']['rx_sig_count']
               tx_rate = result_dict['tx']['total_pkt_rate']
               rx_rate = result_dict['rx']['total_pkt_rate']
               rx_sig_rate = result_dict['rx']['rx_sig_rate']
               rx_dropped_pkt = result_dict['rx']['dropped_pkts']
               log.info('For %r Transmitted Pkts = %r', strm_name, tx_total_pkts)
               log.info('For %r Transmitted, received Pkts = %r', strm_name, rx_total_pkts)
               log.info('For %r Transmitted, Rx Port = %r', strm_name, rx_port)
               log.info('For %r Transmitted, Received SigCount = %r', strm_name, rx_sig_count)
               log.info('For %r Transmitted, dropped_pkts = %r', strm_name, rx_dropped_pkt)
               log.info('For %r Transmitted, transmit rate = %r', strm_name, tx_rate)
               log.info('For %r Transmitted, received rate = %r', strm_name, rx_rate)
               log.info('For %r Transmitted, received Sig rate = %r', strm_name, rx_sig_rate)
               if int(rx_dropped_pkt) > 10:
                  log.info ('Pkt Drop is seen for stream %r', strm_name)
                  fail_flag = 1
               else:
                  exp_rx_port_hdl_list = tgn_traffic_dict['src_ports'][src_port_index]['streams'][strm_index]['dst_port_hdl_list']
                  for exp_rx_port_hdl in exp_rx_port_hdl_list:
                     port_name = get_tgn_port_name_from_hdl(tgn_traffic_dict, exp_rx_port_hdl)
                     if not re.search(r'{0}'.format(port_name), rx_port, re.I):
                        log.info ('For %r Expected RX Port %r not same as traffic being received on', strm_name, port_name)
                        fail_flag = 1
                  if (int(tx_total_pkts) - int(rx_total_pkts)) > 20:
                     log.info ('TX and RX Frame count difference is greater than 20')
                     fail_flag = 1
       if fail_flag:
          return 0
       if strm_name_list:
          if len(strm_name_list) != stream_found:
             log.info('All streams are not found in Results')
             return 0
       return 1

def get_tgn_port_handle_from_name(tgn_traffic_dict, port_name):
   port_hdl = ''
   for src_port_index in tgn_traffic_dict['src_ports'].keys():
      if re.search(r'{0}'.format(port_name), tgn_traffic_dict['src_ports'][src_port_index]['physical_intf'], re.I):
         port_hdl = tgn_traffic_dict['src_ports'][src_port_index]['port_hdl']
   return port_hdl

def get_tgn_port_name_from_hdl(tgn_traffic_dict, port_hdl):
   port_name = ''
   for src_port_index in tgn_traffic_dict['src_ports'].keys():
      if re.search(r'{0}'.format(port_hdl), tgn_traffic_dict['src_ports'][src_port_index]['port_hdl'], re.I):
         port_name = tgn_traffic_dict['src_ports'][src_port_index]['physical_intf']
   return port_name

def get_tgn_port_hdl_list_from_strm_name_list(tgn_traffic_dict, strm_name_list = []):
   port_hdl_list = []
   if not strm_name_list:
      return port_hdl_list   
   strm_name_list_copy = list(strm_name_list)
   for src_port_index in tgn_traffic_dict['src_ports'].keys():
      for each_key in tgn_traffic_dict['src_ports'][src_port_index]['streams'].keys():
         if re.search('stream_(\d+)', each_key, re.I):
            strm_index = each_key
         else:
            continue
         strm_name1 = tgn_traffic_dict['src_ports'][src_port_index]['streams'][strm_index]['name']
         if strm_name1 in strm_name_list:
            port_hdl = tgn_traffic_dict['src_ports'][src_port_index]['port_hdl']
            if not port_hdl in port_hdl_list:
               port_hdl_list.append(port_hdl)
            strm_name_list_copy.remove(strm_name1)
   if strm_name_list_copy: 
      log.info("All Streams are not found in Dict")
      return []
   return port_hdl_list

def get_tgn_strm_id_from_name(tgn_traffic_dict, strm_name = ''):
   if not strm_name:
      return ''
   for src_port_index in tgn_traffic_dict['src_ports'].keys():
      i = 1
      while i <= tgn_traffic_dict['src_ports'][src_port_index]['streams']['streams_present']: 
         stream_name = tgn_traffic_dict['src_ports'][src_port_index]['streams']['stream_' + str(i)]['name']
         if stream_name == strm_name:
            return tgn_traffic_dict['src_ports'][src_port_index]['streams']['stream_' + str(i)]['id']
         i += 1
   return ''

def get_tgn_strm_id_list_from_name_list(tgn_traffic_dict, strm_name_list = []):
   str_id_list = []
   if not strm_name_list:
      return str_id_list   
   strm_name_list_copy = list(strm_name_list)
   for each_strm_name in strm_name_list:
      str_id = get_tgn_strm_id_from_name(tgn_traffic_dict, strm_name = each_strm_name)
      if not str_id:
         log.info('Not able to get strm id for stream name %r', each_strm_name)
         return []
      str_id_list.append(str_id)
   return str_id_list
'''
def get_traffic_src_port_hdl_list(tgn_traffic_dict):
   port_hdl_list = []
   str_id_list = []
   for src_port_index in tgn_traffic_dict['src_ports'].keys():
      src_port_hdl_list.append(tgn_traffic_dict['src_ports'][src_port_index]['port_hdl'])
      for each_key in tgn_traffic_dict['src_ports'][src_port_index]['streams'].keys():
         if re.search('stream_(\d+)', each_key, re.I):
            strm_index = each_key
         else:
            continue
         str_id_list.append(tgn_traffic_dict['src_ports'][src_port_index]['streams'][strm_index]['id'])
   return(port_hdl_list, str_id_list)
   
'''
def tgn_apply_config (tgn_hdl = ''):
   if re.search('spirent', tgn_hdl.type, re.I):
      tgn_hdl.stc_apply()
   return 1

def tgn_stop_devices (tgn_hdl = ''):
   log.info('Stopping all devices on TGN')
   if re.search('spirent', tgn_hdl.type, re.I):
      tgn_hdl.stop_devices()
   if re.search('ixia', tgn_hdl.type, re.I):
       ret_val = tgn_hdl.test_control(action = 'stop_all_protocols')
       return ret_val['status']
   time.sleep(5)
   return 1

def tgn_start_devices (tgn_hdl = '', all_device_handle = [], sleep_time = 30):
   if re.search('spirent', tgn_hdl.type, re.I):
      tgn_hdl.start_devices()
      log.info('Sleeping for %r seconds so that TGN sessions to be UP', sleep_time)
      time.sleep(sleep_time)
   if re.search('ixia', tgn_hdl.type, re.I):
      #tgn_stop_devices(tgn_type = tgn_type)
      time.sleep(10)
      if sleep_time == 30:
         sleep_time = 120
      ret_val = tgn_hdl.test_control(action = 'start_all_protocols')
      log.info('Sleeping for %r seconds so that TGN sessions to be UP', sleep_time)
      time.sleep(sleep_time)
      return ret_val['status']
   return 1

def tgn_disable_bgp_devices (tgn_hdl = '', bgp_handle_list = []):
   if re.search('ixia', tgn_hdl.type, re.I):
      for bgp_handle in bgp_handle_list:
         ret_val = tgn_hdl.emulation_bgp_config(mode = 'disable', handle = bgp_handle)
   return 1

def tgn_get_traffic_stats_for_port (tgn_hdl = '', port_hdl = ''):
   if re.search('spirent', tgn_hdl.type, re.I):
     return tgn_hdl.traffic_stats (port_handle = port_hdl, mode = 'streams', scale_mode = 1)
   if re.search('ixia', tgn_hdl.type, re.I):
     return tgn_hdl.traffic_stats (port_handle = port_hdl, mode = 'streams')
def tgn_get_rx_traffic_stats_for_port (tgn_hdl = '', port_hdl = ''):
    '''
    returns Following dictionary
    
    for RX: 
     {'aggregate': {'rx': {'total_pkts': '5', 'total_pkt_bytes': '848', 'pkt_byte_count': '848', 'tcp_checksum_errors': '0',
     'pkt_rate': '0', 'ip_pkts': '0', 'fcoe_frame_count': '0', 'pfc_frame_count': '0', 'tcp_pkts': '0', 'total_pkt_rate': '0',
     'pkt_bit_rate': '0', 'fcoe_frame_rate': '0', 'pkt_count': '0', 'raw_pkt_count': '5', 'udp_pkts': '0', 'pfc_frame_rate': '0'},
     'tx': {'total_pkts': '37060', 'total_pkt_bytes': '47434368', 'pkt_byte_count': '47434368', 'elapsed_time': '123',
     'pkt_rate': '300', 'ip_pkts': '37058', 'pfc_frame_count': '0', 'total_pkt_rate': '300', 'pkt_bit_rate': '3072056', 
     'pkt_count': '37058', 'raw_pkt_count': '37060', 'raw_pkt_rate': '300'}}, 
     'stream': {'streamblock1': {'rx': {'total_pkts': '12210', 'ipv4_outer_present': '0', 'rx_sig_count': '12210', 
     'misinserted_pkt_rate': '0', 'misinserted_pkts': '0', 'out_of_sequence_pkts': '0', 'prbs_bit_errors': '0', 
     'rx_port': '10.127.63.251-11-3 //11/3', 'min_pkt_length': '1280', 'dropped_pkts': '0', 'max_pkt_length': '1280', 
     'total_pkt_rate': '101', 'Min': '1280', 'udp_present': '1', 'ipv6_outer_present': '0', 'total_pkt_bit_rate': '1029512', 
     'total_pkt_bytes': '15628800', 'last_tstamp': '0', 'prbs_bit_error_rate': '0', 'ipv4_present': '1', 'duplicate_pkts': '0', 
     'Max': '1280', 'avg_delay': '1.909', 'tcp_present': '0', 'pkt_byte_rate': '128689', 'min_delay': '1.778', 
     'out_of_pkt_frame_rate': '0', 'rx_sig_rate': '101', 'max_delay': '223.448', 'ipv6_present': '0', 'first_tstamp': '0'}, 
     'tx': {'ipv4_outer_present': '0', 'total_pkt_bytes': '15799040', 'tcp_present': '0', 'elapsed_time': '123', 
     'total_pkts': '12343', 'ipv4_present': '1', 'ipv6_outer_present': '0', 'total_pkt_rate': '100', 'udp_present': '1', 
     'total_pkt_bit_rate': '1023664', 'ipv6_present': '0'}}, 'unknown': {'rx': {'total_pkts': '5', 'total_pkt_bytes': '848', 
     'max_pkt_length': '240', 'good_pkt_bit_rate': '0', 'total_pkt_rate': '0', 'min_pkt_length': '64'}}, 
     'streamblock2': {'rx': {'total_pkts': '24420', 'ipv4_outer_present': '0', 'rx_sig_count': '24420', 
     'misinserted_pkt_rate': '0', 'misinserted_pkts': '0', 'out_of_sequence_pkts': '0', 'prbs_bit_errors': '0', 
     'rx_port': '10.127.63.251-11-3 //11/3', 'min_pkt_length': '1280', 'dropped_pkts': '0', 'max_pkt_length': '1280', 
     'total_pkt_rate': '199', 'Min': '1280', 'udp_present': '1', 'ipv6_outer_present': '0', 'total_pkt_bit_rate': '2039408', 
     'total_pkt_bytes': '31257600', 'last_tstamp': '0', 'prbs_bit_error_rate': '0', 'ipv4_present': '1', 
     'duplicate_pkts': '0', 'Max': '1280', 'avg_delay': '1.929', 'tcp_present': '0', 'pkt_byte_rate': '254926', 
     'min_delay': '1.778', 'out_of_pkt_frame_rate': '0', 'rx_sig_rate': '199', 'max_delay': '499.768', 'ipv6_present': '0', 
     'first_tstamp': '0'}, 'tx': {'ipv4_outer_present': '0', 'total_pkt_bytes': '31598080', 'tcp_present': '0', 
     'elapsed_time': '122', 'total_pkts': '24686', 'ipv4_present': '1', 'ipv6_outer_present': '0', 'total_pkt_rate': '201', 
     'udp_present': '1', 'total_pkt_bit_rate': '2052504', 'ipv6_present': '0'}}}}

    for RX: 
    {'total_pkts': '38163', 'total_pkt_bytes': '48844301', 'pkt_byte_count': '48844301', 'tcp_checksum_errors': '0', 
    'pkt_rate': '300', 'ip_pkts': '38159', 'fcoe_frame_count': '0', 'pfc_frame_count': '0', 'tcp_pkts': '0', 
    'total_pkt_rate': '300', 'pkt_bit_rate': '3074280', 'fcoe_frame_rate': '0', 'pkt_count': '38159', 
    'raw_pkt_count': '38163', 'udp_pkts': '38159', 'pfc_frame_rate': '0'}

    for TX: 
    {'total_pkts': '1', 'total_pkt_bytes': '64', 'pkt_byte_count': '64', 'elapsed_time': '0', 'pkt_rate': '0', 
    'ip_pkts': '0', 'pfc_frame_count': '0', 'total_pkt_rate': '0', 'pkt_bit_rate': '0', 'pkt_count': '0', 
    'raw_pkt_count': '1', 'raw_pkt_rate': '0'} 
    '''

    traffic_results_ret1 = tgn_hdl.traffic_stats ( port_handle = [port_hdl], mode = 'all');
    return (traffic_results_ret1[port_hdl]['aggregate']['rx'])
   
def tgn_get_tx_traffic_stats_for_port (tgn_hdl = '', port_hdl = ''):
    '''
    returns Following dictionary
    for aggregate: 
     {'aggregate': {'rx': {'total_pkts': '5', 'total_pkt_bytes': '848', 'pkt_byte_count': '848', 'tcp_checksum_errors': '0',
     'pkt_rate': '0', 'ip_pkts': '0', 'fcoe_frame_count': '0', 'pfc_frame_count': '0', 'tcp_pkts': '0', 'total_pkt_rate': '0',
     'pkt_bit_rate': '0', 'fcoe_frame_rate': '0', 'pkt_count': '0', 'raw_pkt_count': '5', 'udp_pkts': '0', 'pfc_frame_rate': '0'},
     'tx': {'total_pkts': '37060', 'total_pkt_bytes': '47434368', 'pkt_byte_count': '47434368', 'elapsed_time': '123',
     'pkt_rate': '300', 'ip_pkts': '37058', 'pfc_frame_count': '0', 'total_pkt_rate': '300', 'pkt_bit_rate': '3072056', 
     'pkt_count': '37058', 'raw_pkt_count': '37060', 'raw_pkt_rate': '300'}}, 
     'stream': {'streamblock1': {'rx': {'total_pkts': '12210', 'ipv4_outer_present': '0', 'rx_sig_count': '12210', 
     'misinserted_pkt_rate': '0', 'misinserted_pkts': '0', 'out_of_sequence_pkts': '0', 'prbs_bit_errors': '0', 
     'rx_port': '10.127.63.251-11-3 //11/3', 'min_pkt_length': '1280', 'dropped_pkts': '0', 'max_pkt_length': '1280', 
     'total_pkt_rate': '101', 'Min': '1280', 'udp_present': '1', 'ipv6_outer_present': '0', 'total_pkt_bit_rate': '1029512', 
     'total_pkt_bytes': '15628800', 'last_tstamp': '0', 'prbs_bit_error_rate': '0', 'ipv4_present': '1', 'duplicate_pkts': '0', 
     'Max': '1280', 'avg_delay': '1.909', 'tcp_present': '0', 'pkt_byte_rate': '128689', 'min_delay': '1.778', 
     'out_of_pkt_frame_rate': '0', 'rx_sig_rate': '101', 'max_delay': '223.448', 'ipv6_present': '0', 'first_tstamp': '0'}, 
     'tx': {'ipv4_outer_present': '0', 'total_pkt_bytes': '15799040', 'tcp_present': '0', 'elapsed_time': '123', 
     'total_pkts': '12343', 'ipv4_present': '1', 'ipv6_outer_present': '0', 'total_pkt_rate': '100', 'udp_present': '1', 
     'total_pkt_bit_rate': '1023664', 'ipv6_present': '0'}}, 'unknown': {'rx': {'total_pkts': '5', 'total_pkt_bytes': '848', 
     'max_pkt_length': '240', 'good_pkt_bit_rate': '0', 'total_pkt_rate': '0', 'min_pkt_length': '64'}}, 
     'streamblock2': {'rx': {'total_pkts': '24420', 'ipv4_outer_present': '0', 'rx_sig_count': '24420', 
     'misinserted_pkt_rate': '0', 'misinserted_pkts': '0', 'out_of_sequence_pkts': '0', 'prbs_bit_errors': '0', 
     'rx_port': '10.127.63.251-11-3 //11/3', 'min_pkt_length': '1280', 'dropped_pkts': '0', 'max_pkt_length': '1280', 
     'total_pkt_rate': '199', 'Min': '1280', 'udp_present': '1', 'ipv6_outer_present': '0', 'total_pkt_bit_rate': '2039408', 
     'total_pkt_bytes': '31257600', 'last_tstamp': '0', 'prbs_bit_error_rate': '0', 'ipv4_present': '1', 
     'duplicate_pkts': '0', 'Max': '1280', 'avg_delay': '1.929', 'tcp_present': '0', 'pkt_byte_rate': '254926', 
     'min_delay': '1.778', 'out_of_pkt_frame_rate': '0', 'rx_sig_rate': '199', 'max_delay': '499.768', 'ipv6_present': '0', 
     'first_tstamp': '0'}, 'tx': {'ipv4_outer_present': '0', 'total_pkt_bytes': '31598080', 'tcp_present': '0', 
     'elapsed_time': '122', 'total_pkts': '24686', 'ipv4_present': '1', 'ipv6_outer_present': '0', 'total_pkt_rate': '201', 
     'udp_present': '1', 'total_pkt_bit_rate': '2052504', 'ipv6_present': '0'}}}}
    
    for RX: 
    {'total_pkts': '38163', 'total_pkt_bytes': '48844301', 'pkt_byte_count': '48844301', 'tcp_checksum_errors': '0', 
    'pkt_rate': '300', 'ip_pkts': '38159', 'fcoe_frame_count': '0', 'pfc_frame_count': '0', 'tcp_pkts': '0', 
    'total_pkt_rate': '300', 'pkt_bit_rate': '3074280', 'fcoe_frame_rate': '0', 'pkt_count': '38159', 
    'raw_pkt_count': '38163', 'udp_pkts': '38159', 'pfc_frame_rate': '0'}

    for TX: 
    {'total_pkts': '1', 'total_pkt_bytes': '64', 'pkt_byte_count': '64', 'elapsed_time': '0', 'pkt_rate': '0', 
    'ip_pkts': '0', 'pfc_frame_count': '0', 'total_pkt_rate': '0', 'pkt_bit_rate': '0', 'pkt_count': '0', 
    'raw_pkt_count': '1', 'raw_pkt_rate': '0'} 
    '''
    traffic_results_ret1 = tgn_hdl.traffic_stats ( port_handle = [port_hdl], mode = 'all');
    return (traffic_results_ret1[port_hdl]['aggregate']['tx'])
   
def tgn_disable_streams (tgn_hdl = '', stream_list = '', port_hdl_list = ''):
   # First stop traffic on stream then disable it.
   if re.search('spirent', tgn_hdl.type, re.I):
     for stream_elm in stream_list:
       tgn_stop_traffic_on_ports(tgn_hdl = tgn_hdl, stream_list = stream_list) 
       strm_blk_ret = tgn_hdl.traffic_config ( mode = 'disable', stream_id = stream_elm)
   if re.search('ixia', tgn_hdl.type, re.I):
     for stream_elm in stream_list:
       tgn_stop_traffic_on_ports(tgn_hdl = tgn_hdl, port_hdl_list = port_hdl_list) 
       strm_blk_ret = tgn_hdl.traffic_config ( mode = 'disable', port_handle = port_hdl_list, stream_id = stream_list)
   return 1


def tgn_stop_traffic_on_ports (tgn_hdl = '', port_hdl_list = '', stream_list = ''):
   if re.search('spirent', tgn_hdl.type, re.I):
      if port_hdl_list:
         if not stream_list:
            traffic_ctrl_ret = tgn_hdl.traffic_control (port_handle = port_hdl_list, action = 'stop')
         else:
            log.info('Need to specify either port_list or stream_list')
            return 0
      if stream_list:
         for stream_elm in stream_list:
            traffic_ctrl_ret = tgn_hdl.traffic_control (stream_handle = stream_elm, action = 'stop')
   if re.search('ixia', tgn_hdl.type, re.I):
      if port_hdl_list:
         if not stream_list:
            for each_p_hdl in port_hdl_list:
                if tgn_hdl.traffic_control (port_handle = each_p_hdl, action = 'poll'):
                   traffic_ctrl_ret = tgn_hdl.traffic_control (port_handle = each_p_hdl, action = 'stop')
                   time.sleep(5)
         else:
            log.info('Need to specify either port_list or stream_list')
            return 0
      if stream_list:
         for stream_elm in stream_list:
             if tgn_hdl.traffic_control (stream_handle = stream_elm, action = 'poll'):
                traffic_ctrl_ret = tgn_hdl.traffic_control (stream_handle = stream_elm, action = 'stop')
                time.sleep(5)
   return 1

def tgn_start_traffic (tgn_hdl = '', port_hdl_list = '', duration = '', clear_stats = 1, stream_list = ''):
   if re.search('spirent', tgn_hdl.type, re.I):
      if port_hdl_list:
         tgn_stop_traffic_on_ports(tgn_hdl = tgn_hdl, port_hdl_list = port_hdl_list)
         tgn_hdl.arp_control(arp_target = 'port', port_handle = port_hdl_list)
      else:
         if stream_list:
            tgn_stop_traffic_on_ports(tgn_hdl = tgn_hdl, stream_list = stream_list)
            tgn_hdl.arp_control(arp_target = 'stream', handle = stream_list)
      if port_hdl_list:
        if clear_stats:
           traffic_ctrl_ret = tgn_hdl.traffic_control (port_handle = port_hdl_list, action = 'clear_stats')
        if duration:
           log.info('Running Traffic for %r seconds', duration)
           traffic_ctrl_ret = tgn_hdl.traffic_control (port_handle = port_hdl_list, action = 'run',\
                                    traffic_start_mode = 'async',  duration = duration)  
           time.sleep(duration)
        else:
           log.info('Running Continuous Traffic\n')
           traffic_ctrl_ret = tgn_hdl.traffic_control (port_handle = port_hdl_list, action = 'run', \
                                                   traffic_start_mode = 'async')
        time.sleep(5)
   if re.search('ixia', tgn_hdl.type, re.I):
      if port_hdl_list:
         log.info('Stopping traffic ..')
         tgn_stop_traffic_on_ports(tgn_hdl = tgn_hdl, port_hdl_list = port_hdl_list)
      if port_hdl_list:
        if duration:
           log.info('Running Traffic for %r seconds', duration)
           traffic_ctrl_ret = tgn_hdl.traffic_control (port_handle = port_hdl_list, action = 'run',\
                                    duration = duration)  
           time.sleep(duration)
        else:
           log.info('Running Continuous Traffic')
           for stream_elm in stream_list:
               strm_blk_ret = tgn_hdl.traffic_config (mode = 'modify', stream_id = stream_elm,
                                       transmit_mode = 'continuous')
           traffic_ctrl_ret = tgn_hdl.traffic_control (port_handle = port_hdl_list, action = 'sync_run')
        time.sleep(5)
   return 1

class lab_svr:
    flag = 0
    username = ''

def connect_and_initialise_tgn_ports (tgn_hdl = '', port_list = [], schedule_mode = 'PRIORITY_BASED'): 
   # For Spirent
   if re.search('spirent', tgn_hdl.type, re.I):
       if not lab_svr.username:
          username = tgn_hdl.connections.hltapi.username
          a = time.time()
          a = int(a)
          username = username + str(a)  
          lab_svr.username = username
       if not lab_svr.flag:
          lab_svr.flag = 1
          tgn_hdl.connections.hltapi.username = lab_svr.username
          tgn_hdl.connect(port_list = port_list)
       else:
          tgn_hdl.connections.hltapi.username = lab_svr.username
          delattr(tgn_hdl.connections['hltapi'], 'stc_session_manager') 
          tgn_hdl.connect(port_list = port_list)
       for each_port in port_list:
          port_hdl = tgn_hdl.interfaces[each_port].tgen_port_handle
          speed = tgn_hdl.interfaces[each_port].speed
          phy_mode = tgn_hdl.interfaces[each_port].phy
          if re.search(r'10gig', speed, re.I): 
             speed_tgn = 'ether10000'
             int_ret = tgn_hdl.interface_config ( mode = 'config', port_handle = port_hdl, create_host  = 'false', 
                                        intf_mode = 'ethernet', phy_mode  = phy_mode, scheduling_mode = schedule_mode,
                                        port_loadunit = 'PERCENT_LINE_RATE', port_load = '10', enable_ping_response = '0',
                                        control_plane_mtu = '1500', flow_control = 'false',
                                        deficit_idle_count = 'false', pfc_negotiate_by_dcbx = '0', speed = speed_tgn,
                                        data_path_mode = 'normal', port_mode = 'LAN', autonegotiation = '1', duplex = 'full');
          if re.search(r'40gig', speed, re.I):
             speed_tgn = 'ether40Gig'
             int_ret = tgn_hdl.interface_config ( mode = 'config', port_handle = port_hdl, create_host  = 'false',
                                        intf_mode = 'ethernet', phy_mode  = phy_mode, scheduling_mode = schedule_mode,
                                        port_loadunit = 'PERCENT_LINE_RATE', port_load = '10', enable_ping_response = '0',
                                        control_plane_mtu = '1500', flow_control = 'false',
                                        deficit_idle_count = 'true', pfc_negotiate_by_dcbx = '0', speed = speed_tgn,
                                        data_path_mode = 'normal', autonegotiation = '1', duplex = 'full');
          if re.search(r'100gig', speed, re.I):
             speed_tgn = 'ether100Gig'
             int_ret = tgn_hdl.interface_config ( mode = 'config', port_handle = port_hdl, create_host  = 'false', 
                                        intf_mode = 'ethernet', phy_mode  = phy_mode, scheduling_mode = 'RATE_BASED',
                                        port_loadunit = 'PERCENT_LINE_RATE', port_load = '10', enable_ping_response = '0',
                                        control_plane_mtu = '1500', transmit_clock_source = 'internal', flow_control = 'false',
                                        deficit_idle_count = 'true', speed = speed_tgn, tx_preemphasis_main_tap = '21',
                                        data_path_mode = 'normal', autonegotiation = '0', duplex = 'full',
                                        forward_error_correct = 'true', collision_exponent = '10',
					internal_ppm_adjust = '0', rx_equalization = '8', tx_preemphasis_post_tap = '8');
          status = int_ret['status']
          if (status == '0'): 
              log.info("run spirent.interface_config failed %r ", int_ret)
              return 0
   # For IXIA
   if re.search('ixia', tgn_hdl.type, re.I):
       intStatus = tgn_hdl.connect(port_list = port_list)
       for each_port in port_list:
          port_hdl = tgn_hdl.interfaces[each_port].tgen_port_handle
          speed = tgn_hdl.interfaces[each_port].speed
          phy_mode = tgn_hdl.interfaces[each_port].phy
          if re.search(r'10gig', speed, re.I):
             int_ret = tgn_hdl.interface_config ( mode = 'config', port_handle = port_hdl,\
                          intf_mode = 'ethernet', phy_mode  = 'fiber',\
                          speed = 'ether10000lan', autonegotiation = '1', \
                          duplex = 'full');
          status = int_ret['status']
          if (status == '0'): 
             log.info("run ixia.interface_config failed %r ", int_ret)
             return 0
   return 1

def configure_tgn_simulated_device (tgn_hdl = '', port_hdl = '', netmask = '24', addr = '', gw_add = '', 
                            no_of_device = 1, mac_addr = '', vlan = '', ip_stack_ver = '', router_id = '192.1.1.1'):
   if re.search('spirent', tgn_hdl.type, re.I):
      hdl_list = []
      if vlan:
         encaps = 'ethernet_ii_vlan'
         if ip_stack_ver == 4 :
            ip_ver = 'ipv4'
            device_ret0 = tgn_hdl.emulation_device_config ( mode = 'create', port_handle = port_hdl,\
                  encapsulation = encaps, ip_version = ip_ver, intf_ip_addr = addr,\
                  intf_prefix_len = netmask, mac_addr = mac_addr, vlan_id = vlan,\
                  gateway_ip_addr = gw_add, router_id = router_id, count = no_of_device)
         else:
            ip_ver = 'ipv6'
            device_ret0 = tgn_hdl.emulation_device_config ( mode = 'create', port_handle = port_hdl,\
                  encapsulation = encaps, ip_version = ip_ver, intf_ipv6_addr = addr,\
                  intf_ipv6_prefix_len = netmask, mac_addr = mac_addr, vlan_id = vlan,\
                  gateway_ipv6_addr = gw_add , router_id = router_id, count = no_of_device)
      else:
         encaps = 'ethernet_ii'
         if ip_stack_ver == 4 :
            ip_ver = 'ipv4'
            device_ret0 = tgn_hdl.emulation_device_config ( mode = 'create', port_handle = port_hdl,\
                  encapsulation = encaps, ip_version = ip_ver, intf_ip_addr = addr,\
                  intf_prefix_len = netmask, mac_addr = mac_addr,\
                  gateway_ip_addr = gw_add, router_id = router_id, count = no_of_device)
         else:
            ip_ver = 'ipv6'
            device_ret0 = tgn_hdl.emulation_device_config ( mode = 'create', port_handle = port_hdl,\
                  encapsulation = encaps, ip_version = ip_ver, intf_ipv6_addr = addr,\
                  intf_ipv6_prefix_len = netmask, mac_addr = mac_addr,\
                  gateway_ipv6_addr = gw_add , router_id = router_id, count = no_of_device)
      status = device_ret0['status']
      if (status == '0') :
         log.info('run spirent.emulation_device_config failed %r', device_ret0)
         return (0, hdl_list)
      else:
         dev_hdl = device_ret0['handle'].split()[0]
         return (1, dev_hdl)
   # For IXIA
   if re.search('ixia', tgn_hdl.type, re.I):
      hdl_list = []
      if vlan:
         if ip_stack_ver == 4 :
            ip_ver = 'ipv4'
            device_ret0 = tgn_hdl.interface_config ( mode = 'modify', port_handle = port_hdl,\
                  vlan = 1, intf_ip_addr = addr,\
                  netmask = netmask, src_mac_addr = mac_addr, vlan_id = vlan,\
                  gateway = gw_add)
         else:
            ip_ver = 'ipv6'
            device_ret0 = tgn_hdl.interface_config ( mode = 'modify', port_handle = port_hdl,\
                  vlan = 1, intf_ipv6_addr = addr,\
                  intf_ipv6_prefix_len = netmask, src_mac_addr = mac_addr, vlan_id = vlan,\
                  gateway_ipv6_addr = gw_add)
      else:
         if ip_stack_ver == 4 :
            ip_ver = 'ipv4'
            device_ret0 = tgn_hdl.interface_config ( mode = 'modify', port_handle = port_hdl,\
                  intf_ip_addr = addr,\
                  netmask = netmask, src_mac_addr = mac_addr,\
                  gateway = gw_add)
         else:
            ip_ver = 'ipv6'
            device_ret0 = tgn_hdl.interface_config ( mode = 'modify', port_handle = port_hdl,\
                  intf_ipv6_addr = addr,\
                  intf_ipv6_prefix_len = netmask, src_mac_addr = mac_addr,\
                  gateway_ipv6_addr = gw_add)
      status = device_ret0['status']
      if (status == '0') :
         log.info('run spirent.emulation_device_config failed %r', device_ret0)
         return (0, hdl_list)
      else:
         dev_hdl = device_ret0['handle'].split()[0]
         return (1, dev_hdl)

def configure_tgn_simulated_bgp_device (tgn_hdl = '', port_hdl = '', netmask = '24', addr = '', remote_add = '', 
                                        mac_addr = '', vlan = '', ip_stack_ver = '', local_as ='', remote_as = '',
                                        num_routes = '', start_pfx_ip = '', pfx_mask = '', handle = 'ANY', apply_config = 0):
   hdl_list = []
   # For Spirent
   if re.search('spirent', tgn_hdl.type, re.I):
      if ip_stack_ver == 4 :
         if vlan:
            device_ret0 = tgn_hdl.emulation_bgp_config (mode = 'enable', retries = '100',
                              vpls_version = 'VERSION_00', routes_per_msg = '2000', staggered_start_time  = '100',
                              update_interval = '60', retry_time = '30', staggered_start_enable = '1', 
                              md5_key_id = '1', md5_key = 'Spirent', md5_enable = '0', ipv4_unicast_nlri = '1',
                              ip_stack_version  = str(ip_stack_ver), port_handle = port_hdl, view_routes = '0', 
                              bgp_session_ip_addr = 'interface_ip', remote_ip_addr = remote_add,
                              ip_version = str(ip_stack_ver), remote_as = str(remote_as), hold_time = '180',
                              restart_time = '120', route_refresh = '0', local_as = str(local_as),
                              active_connect_enable = '1', stale_time = '90', graceful_restart_enable = '1', 
                              vlan_cfi = '0',vlan_id = str(vlan), vlan_user_priority = '7',
                              local_router_id = '192.0.0.39', mac_address_start = mac_addr, 
                              next_hop_ip = remote_add, local_ip_addr = addr, netmask = str(netmask));
         else:
            device_ret0 = tgn_hdl.emulation_bgp_config (mode = 'enable', retries = '100', 
                              vpls_version = 'VERSION_00', routes_per_msg = '2000', staggered_start_time  = '100',
                              update_interval = '60', retry_time = '30', staggered_start_enable = '1', 
                              md5_key_id = '1', md5_key = 'Spirent', md5_enable = '0', ipv4_unicast_nlri = '1',
                              ip_stack_version  = str(ip_stack_ver), port_handle = port_hdl, view_routes = '0', 
                              bgp_session_ip_addr = 'interface_ip', remote_ip_addr = remote_add,
                              ip_version = str(ip_stack_ver), remote_as = str(remote_as), hold_time = '180', 
                              restart_time = '120', route_refresh = '0', local_as = str(local_as),
                              active_connect_enable = '1', stale_time = '90', graceful_restart_enable = '1', 
                              local_router_id = '192.0.0.39', mac_address_start = mac_addr, 
                              next_hop_ip = remote_add, local_ip_addr = addr, netmask = str(netmask));
      if ip_stack_ver == 6 :
         if vlan:
            device_ret0 = tgn_hdl.emulation_bgp_config(mode = 'enable', retries = '100', vpls_version = 'VERSION_00',
                           routes_per_msg = '2000', staggered_start_time  = '100',
                           update_interval = '60', retry_time = '30', staggered_start_enable = '1', 
                           md5_key_id = '1', md5_key = 'Spirent', md5_enable = '0', ipv6_unicast_nlri = '1',
                           ip_stack_version  = str(ip_stack_ver), port_handle = port_hdl, 
                           bgp_session_ip_addr = 'interface_ip', remote_ipv6_addr = remote_add,
                           ip_version = str(ip_stack_ver),view_routes = '0', remote_as = str(remote_as),
                           hold_time = '180', restart_time = '120', route_refresh = '0', local_as = str(local_as),
                           active_connect_enable = '1', stale_time = '90', graceful_restart_enable = '1', 
                           vlan_cfi = '0',vlan_id = str(vlan), vlan_user_priority = '7',
                           local_router_id = '192.0.0.39', mac_address_start = mac_addr, 
                           next_hop_ipv6 = remote_add, local_ipv6_addr = addr, netmask_ipv6 = str(netmask));
         else:
            device_ret0 = tgn_hdl.emulation_bgp_config(mode = 'enable', retries = '100', vpls_version = 'VERSION_00',
                           routes_per_msg = '2000', staggered_start_time  = '100',
                           update_interval = '60', retry_time = '30', staggered_start_enable = '1', 
                           md5_key_id = '1', md5_key = 'Spirent', md5_enable = '0', ipv6_unicast_nlri = '1',
                           ip_stack_version  = str(ip_stack_ver), port_handle = port_hdl, 
                           bgp_session_ip_addr = 'interface_ip', remote_ipv6_addr = remote_add,
                           ip_version = str(ip_stack_ver),view_routes = '0', remote_as = str(remote_as),
                           hold_time = '180', restart_time = '120', route_refresh = '0', local_as = str(local_as),
                           active_connect_enable = '1', stale_time = '90', graceful_restart_enable = '1', 
                           local_router_id = '192.0.0.39', mac_address_start = mac_addr, 
                           next_hop_ipv6 = remote_add, local_ipv6_addr = addr, netmask_ipv6 = str(netmask));

      status = device_ret0['status']
      if (status == '0') :
         log.info('run spirent.emulation_bgp_config failed %r', device_ret0)
         return (0, hdl_list)

      bgp_rtr_hdl = device_ret0['handle'].split()[0]
      if str(pfx_mask) == '24':
         mask = '255.255.255.0'
      if str(pfx_mask) == '32':
         mask = '255.255.255.255'
      if int(num_routes):
         if ip_stack_ver == 4 :
            device_ret0_route1 = tgn_hdl.emulation_bgp_route_config (handle = bgp_rtr_hdl,\
                                      mode = 'add', ip_version = str(ip_stack_ver), as_path = 'as_seq:'+ str(local_as), \
                                      target_type = 'as', target = '100', target_assign = '1', rd_type = '0', \
                                      rd_admin_step = '0', rd_admin_value = '100', rd_assign_step = '1', rd_assign_value = '1',\
                                      next_hop_ip_version = str(ip_stack_ver), next_hop_set_mode = 'manual',\
                                      ipv4_unicast_nlri = '1', prefix = start_pfx_ip, netmask = mask, prefix_step = '1',\
                                      num_routes = num_routes, next_hop = addr, atomic_aggregate = '0', local_pref = '10',\
                                      route_category = 'unique', label_incr_mode = 'none', origin = 'igp'); 
         if ip_stack_ver == 6 :
            device_ret0_route1 = tgn_hdl.emulation_bgp_route_config (handle = bgp_rtr_hdl, mode = 'add',\
                                     ip_version = str(ip_stack_ver), as_path = 'as_seq:'+ str(local_as), target_type = 'as',\
                                     target = '100', target_assign = '1', rd_type = '0', rd_admin_step = '0', \
                                     rd_admin_value = '100', rd_assign_step = '1', rd_assign_value = '1', \
                                     next_hop_ip_version = str(ip_stack_ver), next_hop_set_mode = 'manual',\
                                     ipv6_unicast_nlri = '1', prefix = start_pfx_ip, ipv6_prefix_length = pfx_mask,\
                                     prefix_step = '1', num_routes = num_routes, next_hop = addr, atomic_aggregate = '0',\
                                     local_pref = '10', route_category = 'unique', label_incr_mode = 'none', origin = 'igp'); 
         status = device_ret0_route1['status']
         if (status == '0') :
            log.info('run spirent.emulation_bgp_route_config failed %r',device_ret0_route1)
            return (0, hdl_list)
         bgp_route_hdl = device_ret0_route1['handles'].split()[0]
         hdl_list.append(bgp_rtr_hdl)
         hdl_list.append(bgp_route_hdl)
      else:
         return (1, [bgp_rtr_hdl, ''])
   # For IXIA
   if re.search('ixia', tgn_hdl.type, re.I):
      if local_as != remote_as:
         nbr_type = 'external'
      else:
         nbr_type = 'internal' 
      if ip_stack_ver == 4 :
         if vlan:
            device_ret0 = tgn_hdl.emulation_bgp_config ( mode = 'enable', retries = '100', staggered_start_time  = '100',
                                   update_interval = '60', retry_time = '30', staggered_start_enable = '1', 
                                   ipv4_unicast_nlri = '1', port_handle = port_hdl, remote_ip_addr = remote_add,
                                   ip_version = str(ip_stack_ver), remote_as = str(remote_as),
                                   hold_time = '180', restart_time = '120', local_as = str(local_as),
                                   active_connect_enable = '1', stale_time = '90', graceful_restart_enable = '1', 
                                   vlan_id = str(vlan), vlan_user_priority = '7', local_router_id = '192.0.0.39', 
                                   next_hop_ip = remote_add, local_ip_addr = addr, neighbor_type = nbr_type, 
                                   netmask = str(netmask));
         else:
            device_ret0 = tgn_hdl.emulation_bgp_config ( mode = 'enable', retries = '100', staggered_start_time  = '100',
                                   update_interval = '60', retry_time = '30', staggered_start_enable = '1', 
                                   ipv4_unicast_nlri = '1', port_handle = port_hdl, remote_ip_addr = remote_add,
                                   ip_version = str(ip_stack_ver), remote_as = str(remote_as),
                                   hold_time = '180', restart_time = '120', local_as = str(local_as),
                                   active_connect_enable = '1', stale_time = '90', graceful_restart_enable = '1', 
                                   local_router_id = '192.0.0.39', next_hop_ip = remote_add, 
                                   local_ip_addr = addr, neighbor_type = nbr_type, netmask = str(netmask));
      if ip_stack_ver == 6 :
         if vlan:
            device_ret0 = tgn_hdl.emulation_bgp_config ( mode = 'enable', retries = '100', staggered_start_time  = '100',
                                   update_interval = '60', retry_time = '30', staggered_start_enable = '1', 
                                   ipv6_unicast_nlri = '1', port_handle = port_hdl, remote_ipv6_addr = remote_add,
                                   ip_version = str(ip_stack_ver), remote_as = str(remote_as),
                                   hold_time = '180', restart_time = '120', local_as = str(local_as),
                                   active_connect_enable = '1', stale_time = '90', graceful_restart_enable = '1', 
                                   vlan_id = str(vlan), vlan_user_priority = '7', local_router_id = '192.0.0.39', 
                                   local_ipv6_addr = addr, neighbor_type = nbr_type); 
         else:
            device_ret0 = tgn_hdl.emulation_bgp_config ( mode = 'enable', retries = '100', staggered_start_time  = '100',
                                   update_interval = '60', retry_time = '30', staggered_start_enable = '1', 
                                   ipv6_unicast_nlri = '1', port_handle = port_hdl, remote_ipv6_addr = remote_add,
                                   ip_version = str(ip_stack_ver), remote_as = str(remote_as),
                                   hold_time = '180', restart_time = '120', local_as = str(local_as),
                                   active_connect_enable = '1', stale_time = '90', graceful_restart_enable = '1', 
                                   local_router_id = '192.0.0.39', local_ipv6_addr = addr, neighbor_type = nbr_type); 
      status = device_ret0['status']
      if (status == '0') :
         log.info('run ixia.emulation_bgp_config failed %r', device_ret0)
         return (0, hdl_list)
      bgp_rtr_hdl = device_ret0['handles'].split()[0]
      if str(pfx_mask) == '24':
         mask = '255.255.255.0'
      if str(pfx_mask) == '32':
         mask = '255.255.255.255'
      if ip_stack_ver == 4 :
        device_ret0_route1 = tgn_hdl.emulation_bgp_route_config (handle = bgp_rtr_hdl, mode = 'add', ip_version = str(ip_stack_ver),
                                      as_path = 'as_seq:'+ str(local_as), target_type = 'as', target = '100',
                                      target_assign = '1', rd_type = '0', rd_admin_step = '0', 
                                      rd_admin_value = '100', rd_assign_step = '1', rd_assign_value = '1',
                                      next_hop_ip_version = str(ip_stack_ver), next_hop_set_mode = 'manual',
                                      ipv4_unicast_nlri = '1', prefix = start_pfx_ip, netmask = mask,
                                      prefix_step = '1', num_routes = num_routes, next_hop = addr, 
                                      atomic_aggregate = '0', local_pref = '10', origin = 'igp'); 
      if ip_stack_ver == 6 :
        device_ret0_route1 = tgn_hdl.emulation_bgp_route_config (handle = bgp_rtr_hdl, mode = 'add', ip_version = str(ip_stack_ver),
                                      as_path = 'as_seq:'+ str(local_as), target_type = 'as', target = '100',
                                      target_assign = '1', rd_type = '0', rd_admin_step = '0', 
                                      rd_admin_value = '100', rd_assign_step = '1', rd_assign_value = '1',
                                      next_hop_ip_version = str(ip_stack_ver), next_hop_set_mode = 'manual',
                                      ipv6_unicast_nlri = '1', prefix = start_pfx_ip, ipv6_prefix_length = pfx_mask,
                                      prefix_step = '1', num_routes = num_routes, next_hop = addr, 
                                      atomic_aggregate = '0', local_pref = '10', origin = 'igp'); 
      status = device_ret0_route1['status']
      if (status == '0') :
        log.info('run spirent.emulation_bgp_route_config failed %r',device_ret0_route1)
        return (0, hdl_list)
      bgp_route_hdl = device_ret0_route1['bgp_routes'].split()[0]
      hdl_list.append(bgp_rtr_hdl)
      hdl_list.append(bgp_route_hdl)
   return (1, hdl_list)

def configure_traffic_stream (tgn_hdl = '', stream_name = '', port_hdl = '', route_src_hdl = '', route_dst_hdl = '',
                                        frame_size = '', traffic_gw = '', traffic_type = '', rate_percent = '',
                                        rate_pps = ''):
   if re.search('spirent', tgn_hdl.type, re.I):
      if len(str(rate_pps)) & len(str(rate_percent)):
          log.info('Both rates percentage and pps can not be used')
          return 0
      stream_id = ''
      if traffic_type == 6:
          if rate_percent:
             strm_blk_ret = tgn_hdl.traffic_config ( mode = 'create', port_handle = port_hdl, emulation_src_handle = route_src_hdl,
                                      emulation_dst_handle = route_dst_hdl, l3_protocol = 'ipv6', 
                                      ipv6_traffic_class  = '0', ipv6_next_header = '59', ipv6_length = '0',
                                      ipv6_flow_label = '7', ipv6_hop_limit = '255', enable_control_plane = '0',
                                      l3_length = str(frame_size), name = stream_name, fill_type = 'constant', fcs_error = '0',
                                      fill_value  = '0', frame_size = str(frame_size), traffic_state = '1',
                                      high_speed_result_analysis = '1', length_mode = 'fixed',
                                      tx_port_sending_traffic_to_self_en = 'false', disable_signature = '0',
                                      enable_stream_only_gen = '0', endpoint_map = 'one_to_one', pkts_per_burst = '1',
                                      inter_stream_gap_unit = 'bytes', burst_loop_count = '30', transmit_mode = 'continuous',
                                      inter_stream_gap = '12', rate_percent = str(rate_percent), mac_discovery_gw = traffic_gw);
          if rate_pps:
             strm_blk_ret = tgn_hdl.traffic_config ( mode = 'create', port_handle = port_hdl, emulation_src_handle = route_src_hdl,
                                      emulation_dst_handle = route_dst_hdl, l3_protocol = 'ipv6', 
                                      ipv6_traffic_class  = '0', ipv6_next_header = '59', ipv6_length = '0',
                                      ipv6_flow_label = '7', ipv6_hop_limit = '255', enable_control_plane = '0',
                                      l3_length = str(frame_size), name = stream_name, fill_type = 'constant', fcs_error = '0',
                                      fill_value  = '0', frame_size = str(frame_size), traffic_state = '1',
                                      high_speed_result_analysis = '1', length_mode = 'fixed',
                                      tx_port_sending_traffic_to_self_en = 'false', disable_signature = '0',
                                      enable_stream_only_gen = '0', endpoint_map = 'one_to_one', pkts_per_burst = '1',
                                      inter_stream_gap_unit = 'bytes', burst_loop_count = '30', transmit_mode = 'continuous',
                                      inter_stream_gap = '12', rate_pps = str(rate_pps), mac_discovery_gw = traffic_gw);
          status = strm_blk_ret['status']
          if (status == '0') :
               log.info('run spirent.traffic_config failed for V6 %r', strm_blk_ret)
               return stream_id
          else:
               stream_id = strm_blk_ret['stream_id']
               return stream_id
      if traffic_type == 4:
          if rate_percent:
             strm_blk_ret = tgn_hdl.traffic_config (mode = 'create', port_handle = port_hdl, emulation_src_handle = route_src_hdl, 
                                      emulation_dst_handle = route_dst_hdl, l3_protocol = 'ipv4', ip_id = '0', ip_ttl = '255',
                                      ip_hdr_length = '5', ip_protocol = '253', ip_fragment_offset = '0', ip_mbz = '0',
                                      ip_precedence = '0', ip_tos_field = '0', enable_control_plane = '0', 
                                      l3_length = str(frame_size), name = stream_name, fill_type = 'constant', fcs_error = '0',
                                      fill_value = '0', frame_size = str(frame_size), traffic_state = '1',
                                      high_speed_result_analysis = '1', length_mode = 'fixed',
                                      tx_port_sending_traffic_to_self_en = 'false', disable_signature = '0',
                                      enable_stream_only_gen = '0', endpoint_map = 'one_to_one', pkts_per_burst = '1',
                                      inter_stream_gap_unit = 'bytes', burst_loop_count = '30', transmit_mode = 'continuous',
                                      inter_stream_gap = '12', rate_percent = str(rate_percent), mac_discovery_gw = traffic_gw);
          if rate_pps:
             strm_blk_ret = tgn_hdl.traffic_config (mode = 'create', port_handle = port_hdl, emulation_src_handle = route_src_hdl, 
                                      emulation_dst_handle = route_dst_hdl, l3_protocol = 'ipv4', ip_id = '0', ip_ttl = '255',
                                      ip_hdr_length = '5', ip_protocol = '253', ip_fragment_offset = '0', ip_mbz = '0',
                                      ip_precedence = '0', ip_tos_field = '0', enable_control_plane = '0', 
                                      l3_length = str(frame_size), name = stream_name, fill_type = 'constant', fcs_error = '0',
                                      fill_value = '0', frame_size = str(frame_size), traffic_state = '1',
                                      high_speed_result_analysis = '1', length_mode = 'fixed',
                                      tx_port_sending_traffic_to_self_en = 'false', disable_signature = '0',
                                      enable_stream_only_gen = '0', endpoint_map = 'one_to_one', pkts_per_burst = '1',
                                      inter_stream_gap_unit = 'bytes', burst_loop_count = '30', transmit_mode = 'continuous',
                                      inter_stream_gap = '12', rate_pps = str(rate_pps), mac_discovery_gw = traffic_gw);
          status = strm_blk_ret['status']
          if (status == '0') :
               log.info('run spirent.traffic_config failed for V4 %r', strm_blk_ret)
               return stream_id
          else:
               stream_id = strm_blk_ret['stream_id']
               return stream_id
   if re.search('ixia', tgn_hdl.type, re.I):
      if len(str(rate_pps)) & len(str(rate_percent)):
          log.info('Both rates percentage and pps can not be used')
          return 0
      stream_id = ''
      if traffic_type == 6:
          if rate_percent:
             strm_blk_ret = tgn_hdl.traffic_config ( mode = 'create', port_handle = port_hdl, circuit_endpoint_type = 'ipv6',
                                   emulation_src_handle = route_src_hdl, emulation_dst_handle = route_dst_hdl, 
                                   l3_protocol = 'ipv6', ipv6_traffic_class  = '0', ipv6_next_header = '59', length_mode = 'fixed', 
                                   ipv6_flow_label = '7', ipv6_hop_limit = '255', l3_length = str(frame_size), 
                                   name = stream_name, frame_size = str(frame_size), pkts_per_burst = '1', 
                                   burst_loop_count = '30', transmit_mode = 'continuous', inter_stream_gap = '12', 
                                   rate_percent = str(rate_percent), track_by = 'endpoint_pair traffic_item')
          if rate_pps:
             strm_blk_ret = tgn_hdl.traffic_config ( mode = 'create', port_handle = port_hdl, circuit_endpoint_type = 'ipv6',
                                   emulation_src_handle = route_src_hdl, emulation_dst_handle = route_dst_hdl,
                                   l3_protocol = 'ipv6', ipv6_traffic_class  = '0', ipv6_next_header = '59', length_mode = 'fixed',
                                   ipv6_flow_label = '7', ipv6_hop_limit = '255', l3_length = str(frame_size), name = stream_name, 
                                   frame_size = str(frame_size), pkts_per_burst = '1', burst_loop_count = '30', 
                                   transmit_mode = 'continuous', inter_stream_gap = '12', rate_pps = str(rate_pps), 
                                   track_by="endpoint_pair traffic_item")
          status = strm_blk_ret['status']
          if (status == '0') :
               log.info('run ixia.traffic_config failed for V6 %r', strm_blk_ret)
               return stream_id
          else:
               stream_id = strm_blk_ret['stream_id']
               return stream_id
      if traffic_type == 4:
          if rate_percent:
             strm_blk_ret = tgn_hdl.traffic_config (mode = 'create', port_handle = port_hdl,
                                    emulation_src_handle = route_src_hdl, emulation_dst_handle = route_dst_hdl,
                                    l3_protocol = 'ipv4', ip_id = '0', ip_ttl = '255', ip_precedence = '0', ip_hdr_length = '5', 
                                    ip_protocol = '253', ip_fragment_offset = '0', l3_length = str(frame_size), 
                                    name = stream_name, frame_size = str(frame_size), length_mode = 'fixed', 
                                    pkts_per_burst = '1', burst_loop_count = '30', transmit_mode = 'continuous', 
                                    inter_stream_gap = '12', rate_percent = str(rate_percent), track_by="endpoint_pair traffic_item")
          if rate_pps:
             strm_blk_ret = tgn_hdl.traffic_config (mode = 'create', port_handle = port_hdl, 
                                    emulation_src_handle = route_src_hdl, emulation_dst_handle = route_dst_hdl,
                                    l3_protocol = 'ipv4', ip_id = '0', ip_ttl = '255', ip_precedence = '0', ip_hdr_length = '5', 
                                    ip_protocol = '253', ip_fragment_offset = '0', l3_length = str(frame_size), 
                                    name = stream_name, frame_size = str(frame_size), length_mode = 'fixed', 
                                    pkts_per_burst = '1', burst_loop_count = '30', transmit_mode = 'continuous', 
                                    inter_stream_gap = '12', rate_pps = str(rate_pps), track_by="endpoint_pair traffic_item")
          status = strm_blk_ret['status']
          if (status == '0') :
               log.info('run ixia.traffic_config failed for V4 %r', strm_blk_ret)
               return stream_id
          else:
               stream_id = strm_blk_ret['stream_id']
               return stream_id

def run_traffic_get_stats (tgn_hdl, port_hdl_list, stream_id_list, tr_time):
    tgn_start_traffic (tgn_hdl = tgn_hdl, port_hdl_list = port_hdl_list, stream_list = stream_id_list, duration = tr_time)
    log.info('Collecting Stream Results ....')
    time.sleep(5)
    return tgn_get_traffic_stats_for_port(tgn_hdl = tgn_hdl, port_hdl = port_hdl_list)

# ##########################################
# Adding DHCP related APIs here [SPIRENT]
# ##########################################
def configure_dhcp_server (tgn_hdl, port_handle, mode = 'create', ip_version = '4', encapsulation = 'ETHERNET_II', ip_count = '1',                                      ip_pool_start = '10.1.1.10', ip_incr = '1', lease_time = '3600', ip_repeat = '0', 
                                     remote_mac = '00:00:01:00:00:01', ip_address= '10.1.1.1', netmask = '24', 
                                     gateway = '10.1.1.1', ip_step = '0.0.0.1', local_mac = '00:10:94:00:00:02', count = '1') :
    if re.search('spirent', tgn_hdl.type, re.I):
        ret = tgn_hdl.emulation_dhcp_server_config(
            mode                                             = mode,
            ip_version                                       = ip_version,
            encapsulation                                    = encapsulation,
            ipaddress_count                                  = ip_count,
            ipaddress_pool                                   = ip_pool_start,
            ipaddress_increment                              = ip_incr,
            port_handle                                      = port_handle,
            lease_time                                       = lease_time,
            ip_repeat                                        = ip_repeat,
            remote_mac                                       = remote_mac,
            ip_address                                       = ip_address,
            ip_prefix_length                                 = netmask,
            ip_gateway                                       = gateway,
            ip_step                                          = ip_step,
            local_mac                                        = local_mac,
            count                                            = count);
            
        status = ret['status']
        if (status == '0') :
            log.info( 'ERROR!!! configure_dhcp_server failed ERROR!!!')
            return 0
        else:
            log.info("***** configure_dhcp_server executed successfully *****")
            return 1

def configure_dhcp_host (tgn_hdl, port_handle, mode = 'create', ip_version = '4', starting_xid = '0', lease_time = '60', 
                                   session_count = '1000', request_rate = '100', msg_timeout = '60000', retry_count = '4', 
                                   max_dhcp_msg_size = '576', release_rate = '100' ) :
    if re.search('spirent', tgn_hdl.type, re.I):
        host_ret = tgn_hdl.emulation_dhcp_config (
            mode                                             = mode,
            ip_version                                       = ip_version,
            port_handle                                      = port_handle,
            starting_xid                                     = starting_xid,
            lease_time                                       = lease_time,
            outstanding_session_count                        = session_count,
            request_rate                                     = request_rate,
            msg_timeout                                      = msg_timeout,
            retry_count                                      = retry_count,
            max_dhcp_msg_size                                = max_dhcp_msg_size,
            release_rate                                     = release_rate);

        status = host_ret['status']
        if (status == '0') :
            log.info("ERROR!!! configure_dhcp_host failed ERROR!!!")
        else:
            log.info("***** configure_dhcp_host executed successfully *****")
            dhcp_handle = host_ret['handles']
            status = host_ret['handles']
    return status
    
def configure_dhcp_group (tgn_hdl, dhcp_handle, mode = 'create', ip_type = '4', encap = 'ethernet_ii', 
                                    opt_list = ['1', '6', '15', '33', '44'], host_name = 'client_@p-@b-@s', 
                                    gateway = '192.85.2.1', mac_addr = '00:10:94:00:00:01', 
                                    mac_addr_step = '00:00:00:00:00:01', num_sessions = '1') :
    if re.search('spirent', tgn_hdl.type, re.I):
        device_ret1 = tgn_hdl.emulation_dhcp_group_config (
        mode                                             = mode,
        dhcp_range_ip_type                               = ip_type,
        encap                                            = encap,
        handle                                           = dhcp_handle,
        opt_list                                         = opt_list,
        host_name                                        = host_name,
        ipv4_gateway_address                             = gateway,
        enable_custom_pool                               = 'true',
        mac_addr                                         = mac_addr,
        mac_addr_step                                    = mac_addr_step,
        num_sessions                                     = num_sessions);
        status = device_ret1['status']
    if (status == '0') :
        log.info("ERROR!!! configure_dhcp_group failed ERROR!!!")
        return device_ret1
    else: 
        log.info("***** configure_dhcp_group executed successfully *****")
        dev_hdl = device_ret1['handle'].split()[0]
        return (1, dev_hdl)


##############################################################
# Start/Stop DHCP server and Bind DHCP device on DHCP client
##############################################################

def dhcp_server_control (tgn_hdl, port_handle, action = 'connect', ip_version = '4') :
    if re.search('spirent', tgn_hdl.type, re.I) :
        ctrl_ret1 = tgn_hdl.emulation_dhcp_server_control (
        port_handle                                      = port_handle,
        action                                           = action,
        ip_version                                       = ip_version);
        status = ctrl_ret1['status']
    if (status == '0') :
        log.info('ERROR!!! dhcp_server_control failed ERROR!!!')
        return 0
    else :
        log.info('***** dhcp_server_control executed successfully *****')
        return 1

def dhcp_host_control (tgn_hdl, port_handle, action = 'bind', ip_version = '4') :
    if re.search('spirent', tgn_hdl.type, re.I):
        ctrl_ret = tgn_hdl.emulation_dhcp_control (
        port_handle                                      = port_handle,
        action                                           = action,
        ip_version                                       = ip_version);

        status = ctrl_ret['status']
        if (status == '0') :
            print('ERROR!!! dhcp_host_control failed ERROR!!!')
            return 0
        else:
            log.info( "***** dhcp_host_control executed successfully *****")
            return 1

def collect_dhcp_server_stats (tgn_hdl, port_handle, action = 'COLLECT', ip_version = '4') :
    if re.search('spirent', tgn_hdl.type, re.I):
        results_ret1 = tgn_hdl.emulation_dhcp_server_stats (
            port_handle                                      = port_handle,
            action                                           = action,
            ip_version                                       = ip_version);

        status = results_ret1['status']
        if (status == '0') :
            log.info("ERROR!!! collect_dhcp_server_stats failed ERROR!!!")
            return 0
        else:
            log.info("***** collect_dhcp_server_stats executed successfully *****")
        return results_ret1;

def collect_dhcp_host_stats (tgn_hdl, port_handle, action = 'collect', mode = 'detailed_session', ip_version = '4') :
    if re.search('spirent', tgn_hdl.type, re.I):
        results_ret2 = tgn_hdl.emulation_dhcp_stats (
        port_handle                                      = port_handle,
        action                                           = action,
        mode                                             = mode,
        ip_version                                       = ip_version);

    status = results_ret2['status']
    if (status == '0') :
        log.info("ERROR!!! collect_dhcp_host_stats failed ERROR!!!")
        return 0
    else:
        log.info("***** collect_dhcp_host_stats executed successfully *****")
    return results_ret2;
