#!/bin/env python
###################################################################
# connection_example.py : A test script example which includes:
#     common_seup section - device connection, configuration
#     Tescase section with testcase setup and teardown (cleanup)
#     common_cleanup section - device cleanup
# The purpose of this sample test script is to show how to connect the
# devices/UUT in the common setup section. How to run few simple testcases
# And finally, recover the test units in
# the common cleanup section. Script also provides an example on how to invoke
# TCL interpreter to call existing TCL functionalities.
###################################################################
import re
import time
import logging
import collections
import yaml
import ipaddress
#import sth

from ats import aetest
from ats import topology
#from csccon.exceptions import InvalidCliError
#from csccon import disable_prompt_check
#from csccon import enable_prompt_check
#from ats.log.utils import banner
#import parsergen

from ats.async import pcall
#from sth import StcPython

log = logging.getLogger(__name__)
log.setLevel(logging.DEBUG)

class class_common_device():
   def __init__(self):
       self.topo_dict = ""
       self.topo_name = ""
       self.tb_obj = ""
       self.login = ""
       self.passw = ""
       self.as_nu = ""
       self.ospf_id = ""
       self.start_loop_bk = ""
       self.loop_bk_start_ip = ""
       self.run_conf_str = ""
       self.all_intf_list = []
       self.write_erase_done = 0

   def device_breakout_interfaces (self):
       #Breakout interfaces
       for intf in self.all_intf_list:
          for ind_intf in self.tb_obj:
             if ind_intf.name.lower() == intf.lower():
               speed = ind_intf.type
               breakout_intf(self.tb_obj, intf, speed)

   def device_clean (self):
       if not self.write_erase_done:
          clean_all_configs(self.tb_obj, self.tb_obj.mgmt)

def get_sw_version(device):
   oput = device.execute('show version')

def whether_xl_platform (device):
   output = device.mgmt.execute('show version')
   found = 0
   lines = output.splitlines()
   for line in lines:
      match = re.search('CPU.*with (\d+) kB of memory', line, re.IGNORECASE)
      if match:
         found = 1
         mem = match.group(1)
         if int(mem) < 5000000:
            return 0
   if found:
     return 1
   else:
     return 0

def check_bfd_neighbors(device, nbr_ip_list):
   output = device.mgmt.execute('show bfd neighbors')
   lines = output.splitlines()
   fail_flag = 1
   for nbr_ip in nbr_ip_list:
       found = 0
       for line in lines:
          words = get_words_list_from_line(line)
          if len(words) > 6:
            if words[1] == nbr_ip:
               if words[3] == 'Up':
                  if words[5] == 'Up':
                     found = 1
       if not found:
          log.info('BFD Nbr %r is not there or not Up', nbr_ip)
          fail_flag = 0
   return fail_flag

def get_bgp_nbr_session_status (device, vrf = 'default'):
   output = device.mgmt.execute('show bgp sessions vrf ' + vrf)
   lines = output.splitlines()
   nbr_dict = {}
   for line in lines:
       words = get_words_list_from_line(line)
       addr = words[0]
       if string_is_ip_address(addr):
          if words[4] == 'E':
             nbr_dict[addr] = 1
          else:
             nbr_dict[addr] = 0
   return nbr_dict

def check_hardware_forwarding_table_utilisation(device, module = 1, v4_lpm = 0, v4_host = 0, v6_lpm = 0, v6_host = 0):
   output = device.mgmt.execute('show hardware internal forwarding table utilization module ' + str(module))
   lines = output.splitlines()
   negative_flag = 0
   label_list = []
   v4_lpm_greater = 0
   v6_lpm_greater = 0
   v6_host_greater = 0
   v4_host_greater = 0
   for line in lines:
      if re.search('[=|:] -', line):
         log.info ('Found Negative Number for %r', line)
         negative_flag = 1
      else:
        match = re.search('IPv4 hosts used count.*: (\d+)', line)
        if match:
           v4_host_used = match.group(1)
           if int(v4_host_used) >= int(v4_host):
              v4_host_greater = 1
        match = re.search('IPv6 hosts used count.*: (\d+)', line)
        if match:
           v6_host_used = match.group(1)
           if int(v6_host_used) >= int(v6_host):
              v6_host_greater = 1
        match = re.search('IPv4 routes used count.*: (\d+)', line)
        if match:
           v4_lpm_used = match.group(1)
           if int(v4_lpm_used) >= int(v4_lpm):
              v4_lpm_greater = 1
        match = re.search('IPv6.*routes used count.*: (\d+)', line)
        if match:
           v6_lpm_used = match.group(1)
           if int(v6_lpm_used) >= int(v6_lpm):
              v6_lpm_greater = 1

   fail_flag = 0
   if not v4_lpm_greater:
      log.info('V4 LPMs %r are not of expected number in hardware', v4_lpm)
      fail_flag = 1
   if not v6_lpm_greater:
      log.info('V6 LPMs %r are not of expected number in hardware', v6_lpm)
      fail_flag = 1
   if not v4_host_greater:
      log.info('V4 Hosts %r are not of expected number in hardware', v4_host)
      fail_flag = 1
   if not v6_host_greater:
      log.info('V6 Hosts %r are not of expected number in hardware', v6_host)
      fail_flag = 1
   if fail_flag:
      return 0
   if negative_flag:
      return 0
   return 1

def get_all_non_default_vrf_label_list(device):
   output = device.mgmt.execute('show mpls switching')
   lines = output.splitlines()
   found = 0
   start_append = 0
   label_list = []
   for line in lines:
      if found:
         if start_append:
            words = get_words_list_from_line(line)
            try:
               rowPos = int(words[0])
               label_list.append(words[0])
            except ValueError:
               i = 1
         start_append = 1
      if re.search('In-Label.*VRF', line, re.IGNORECASE):
         found = 1
   return label_list


def get_vpn_label_stats (device, label, module = 1):
   stats = 0
   output = device.mgmt.execute('show forwarding mpls label ' + str(label) + ' stats module ' + str(module))
   lines = output.splitlines()
   found = 0
   for line in lines:
      if re.search('Input Pkts', line, re.IGNORECASE):
         found = 1
         words = get_words_list_from_line(line)
         stats = words[3]
         return stats
   return stats

def get_local_vrf_label (device, vrf_name):
   oput = device.mgmt.execute('show mpls switching vrf ' + vrf_name)
   lines = oput.splitlines()
   i = 0
   v4_line_no = 0
   v6_line_no = 0
   label_dict = {}
   label_dict['v4'] = ''
   label_dict['v6'] = ''
   for line in lines:
      match = re.search(r'Aggregate Labels', line, re.IGNORECASE)
      if match:
         if re.search('4', line, re.IGNORECASE):
            v4_line_no = i
         if re.search('6', line, re.IGNORECASE):
            v6_line_no = i
      i += 1
   if v4_line_no:
     line = lines[v4_line_no+1]
     words = get_words_list_from_line(line)
     label_dict['v4'] = words[0]
   if v6_line_no:
     line = lines[v6_line_no+1]
     words = get_words_list_from_line(line)
     label_dict['v6'] = words[0]

   return label_dict

def check_correct_forwarding_vpn_label_for_vrf (pe_device, remote_pe, vrf_name, check_v4, check_v6, module = 1):
    label_dict = get_local_vrf_label(remote_pe, vrf_name)
    if check_v4:
      if label_dict['v4']:
         found = 0
         output = pe_device.mgmt.execute('show forwarding ipv4 route vrf ' + vrf_name + ' module ' + str(module))
         lines = output.splitlines()
         for line in lines:
            if re.search('PUSH', line, re.IGNORECASE):
               found = 1
               words = get_words_list_from_line(line)
               vpn_label = words[len(words)-1]
               if int(vpn_label) != int(label_dict['v4']):
                  log.info('Correct VPN V4 label %r is not in forwarding table for VRF %r', label_dict['v4'], vrf_name)
                  return 0
         if not found:
            log.info('No forwarding V4 route found with VPN label')
            return 0
      else:
         log.info('V4 VRF labels are not generated in remote PE')
         return 0
    if check_v6:
      if label_dict['v6']:
         found = 0
         output = pe_device.mgmt.execute('show forwarding ipv6 route vrf ' + vrf_name + ' module ' + str(module))
         lines = output.splitlines()
         for line in lines:
            if re.search('PUSH', line, re.IGNORECASE):
               found = 1
               words = get_words_list_from_line(line)
               vpn_label = words[len(words)-1]
               if int(vpn_label) != int(label_dict['v6']):
                  log.info('Correct VPN V6 label %r is not in forwarding table for VRF %r', label_dict['v6'], vrf_name)
                  return 0
         if not found:
            log.info('No forwarding V6 route found with VPN label')
            return 0

      else:
         log.info('V4 VRF labels are not generated in remote PE')
         return 0
    return 1

def get_bgp_l2vpn_evpn_neighbor (device):
   output = parsergen.oper_fill_tabular(\
             device=device,
             show_command='show bgp l2vpn evpn summary',
             header_fields=['Neighbor', 'V', 'AS', 'MsgRcvd', 'MsgSent', 'TblVer', 'InQ', 'OutQ', 'Up/Down', 'State/PfxRcd'],
             index=[0],
             table_title_pattern=None)
   return output.entries

def get_words_list_from_line(line):
    line = re.sub(' +',' ',line)
    line = line.strip()
    words = line.split(" ")
    entry_lst = []
    for word in words:
       entry_lst.append(word)
    return entry_lst

def get_bgp_lu_labels_dict (device):
   if device.is_connected(alias = 'mgmt'):
      hdl = device.mgmt
   else:
     hdl = device
   oput = hdl.execute("show bgp ipv4 labeled-unicast labels")
   lines = oput.splitlines()
   start_indx = 0
   for line in lines:
      if re.search('Network.* Next Hop.*In label', line, re.IGNORECASE):
         break
      start_indx += 1
   lines = oput.splitlines()
   index1 = start_indx + 1
   pfxcount = 1
   pfx_dict = {}
   pfx_count = 1
   while index1 < len(lines):
      if not lines[index1]:
         break
      entry_lst = get_words_list_from_line(lines[index1])
      index1 += 1
      match = re.search(r'(\d+.\d+.\d+.\d+/\d+)', entry_lst[0] , re.IGNORECASE)
      if match:
         if re.search(r'(0.0.0.0)', entry_lst[1] , re.IGNORECASE):
            continue
         pfx_dict[pfx_count] = dict()
         pfx_dict[pfx_count]['pfx_ip'] = match.group(1)
         match1 = re.search(r'(\d+)/(\d+)', entry_lst[2], re.IGNORECASE)
         if match1:
            local_label = match1.group(1)
            out_label = match1.group(2)
            nh_count = 1
            pfx_dict[pfx_count]['nexthop'] = dict()
            pfx_dict[pfx_count]['nexthop'][nh_count] = dict()
            pfx_dict[pfx_count]['nexthop'][nh_count]['ip'] = entry_lst[1]
            pfx_dict[pfx_count]['nexthop'][nh_count]['locallabel'] = local_label
            pfx_dict[pfx_count]['nexthop'][nh_count]['outlabel'] = out_label
            nh_count += 1
            index2 = index1
            while index2 < len(lines):
               if not lines[index2]:
                  break
               entry_lst = get_words_list_from_line(lines[index2])
               index2 += 1
               match = re.search(r'(\d+.\d+.\d+.\d+/\d+)', entry_lst[0] , re.IGNORECASE)
               if match:
                  break
               if re.search(r'(0.0.0.0)', entry_lst[1] , re.IGNORECASE):
                  break
               match2 = re.search(r'(\d+)/(\d+)', entry_lst[2], re.IGNORECASE)
               if match2:
                  local_label = match2.group(1)
                  out_label = match2.group(2)
                  pfx_dict[pfx_count]['nexthop'][nh_count] = dict()
                  pfx_dict[pfx_count]['nexthop'][nh_count]['ip'] = entry_lst[1]
                  pfx_dict[pfx_count]['nexthop'][nh_count]['locallabel'] = local_label
                  pfx_dict[pfx_count]['nexthop'][nh_count]['outlabel'] = out_label
                  nh_count += 1
            pfx_count += 1

   return pfx_dict

def tgn_apply_config (tgn_type = ''):
   if tgn_type == 'stc':
     stc = StcPython()
     stc.apply()
   return 1

def tgn_start_devices (tgn_type = ''):
   if tgn_type == 'stc':
      sth.start_devices()
   return 1

def tgn_get_rx_traffic_stats_for_port (tgn_type = '', port_hdl = ''):
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

    traffic_results_ret1 = sth.traffic_stats ( port_handle = [port_hdl], mode = 'all');
    return (traffic_results_ret1[port_hdl]['aggregate']['rx'])

def tgn_get_tx_traffic_stats_for_port (tgn_type = '', port_hdl = ''):
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
    traffic_results_ret1 = sth.traffic_stats ( port_handle = [port_hdl], mode = 'all');
    return (traffic_results_ret1[port_hdl]['aggregate']['tx'])

def tgn_disable_streams (tgn_type = '', stream_list = ''):
   # First stop traffic on stream then disable it.
   if tgn_type == 'stc':
     for stream_elm in stream_list:
       traffic_ctrl_ret = sth.traffic_control (stream_handle = stream_elm, action = 'stop')
       strm_blk_ret = sth.traffic_config ( mode = 'disable', stream_id = stream_elm)
   return 1


def tgn_stop_traffic_on_ports (tgn_type = '', port_hdl_list = '', stream_list = ''):
   if tgn_type == 'stc':
      if port_hdl_list:
         if not stream_list:
            traffic_ctrl_ret = sth.traffic_control (port_handle = port_hdl_list, action = 'stop')
         else:
            log.info('Need to specify either port_list or stream_list')
            return 0
      if stream_list:
         for stream_elm in stream_list:
            traffic_ctrl_ret = sth.traffic_control (stream_handle = stream_elm, action = 'stop')
   return 1

def tgn_start_traffic (tgn_type = '', port_hdl_list = '', duration = '', clear_stats = 1):
   if tgn_type == 'stc':
      if port_hdl_list:
        if clear_stats:
           traffic_ctrl_ret = sth.traffic_control (port_handle = port_hdl_list, action = 'clear_stats')
        if duration:
           traffic_ctrl_ret = sth.traffic_control (port_handle = port_hdl_list, action = 'run',\
                                    traffic_start_mode = 'sync',  duration = duration)
           log.info('Running Traffic for %r seconds', duration)
           time.sleep(duration)
        else:
           traffic_ctrl_ret = sth.traffic_control (port_handle = port_hdl_list, action = 'run', \
                                                   traffic_start_mode = 'sync')
   return 1

def reserve_tgn_ports (tgn_type = '', tgn_ip = '', tgn_lab_svr_ip = '', \
                       port_list = [], create_new_lab_svr_session = 1):
   tgn_port_dict = {}
   if tgn_type == 'stc':
       test_sta = sth.test_config (log = '1', logfile = 'boundstream_logfile',
                                   vendorlogfile  = 'boundstream_stcExport',
                                   vendorlog = '1', hltlog = '1',
                                   hltlogfile = 'boundstream_hltExport',
                                   hlt2stcmappingfile  = 'boundstream_hlt2StcMapping',
                                   hlt2stcmapping = '1', log_level = '7');
       status = test_sta['status']
       if (status == '0') :
          log.info ('run sth.test_config failed - %r', test_sta)
          return (0, tgn_port_dict)
       test_ctrl_sta = sth.test_control ( action = 'enable')
       status = test_ctrl_sta['status']
       if (status == '0') :
          log.info('run sth.test_control failed, status = %r', test_ctrl_sta)
          return (0, tgn_port_dict)

       # If lab server is there connect it
       if tgn_lab_svr_ip:
          user_n = "labuser"
          session_name = "Stc"
          if create_new_lab_svr_session:
             lab_svr_sess = sth.labserver_connect(server_ip = tgn_lab_svr_ip,
                                  create_new_session = 1, session_name = session_name,
                                  user_name = user_n)
       device = tgn_ip
       intStatus = sth.connect ( device = tgn_ip, port_list = port_list,
                                 break_locks = 1, offline = 0 )
       status = intStatus['status']
       if (status == '1') :
          for port in port_list :
             port_handle = intStatus['port_handle'][device][port]
             tgn_port_dict[port] = dict()
             tgn_port_dict[port]['hdl'] = port_handle
       else :
          log.info('\nFailed to retrieve port handle!\n')
          return (0, tgn_port_dict)
   else:
     i = 1
     # For Ixia

   return (1, tgn_port_dict)

def configure_tgn_port (tgn_type = '', port_hdl = '', phy_mode = 'fiber', schedule_mode = 'PORT_BASED', speed = ''):
   '''
   [-phy_mode {copper|fiber}]
   [-port_loadunit {PERCENT_LINE_RATE|FRAMES_PER_SECOND|INTER_BURST_GAP|BITS_PER_SECOND|KILOBITS_PER_SECOND|MEGABITS_PER_SECOND}]
   [-scheduling_mode {RATE_BASED | PORT_BASED | PRIORITY_BASED | MANUAL_BASED}]
   [-speed {ether10|ether100|ether1000|ether2500|ether10000|ether5Gig|ether40Gig|ether100Gig}]
   '''

   if tgn_type == 'stc':
       speed_tgn = ''
       if re.search(r'10gig', speed, re.IGNORECASE):
          speed_tgn = 'ether10000'
          int_ret = sth.interface_config ( mode = 'config', port_handle = port_hdl, create_host  = 'false',
                                        intf_mode = 'ethernet', phy_mode  = phy_mode, scheduling_mode = schedule_mode,
                                        port_loadunit = 'PERCENT_LINE_RATE', port_load = '10', enable_ping_response = '0',
                                        control_plane_mtu = '1500', flow_control = 'false',
                                        deficit_idle_count = 'false', pfc_negotiate_by_dcbx = '0', speed = speed_tgn,
                                        data_path_mode = 'normal', port_mode = 'LAN', autonegotiation = '1', duplex = 'full');
       if re.search(r'40gig', speed, re.IGNORECASE):
          speed_tgn = 'ether40Gig'
          int_ret = sth.interface_config ( mode = 'config', port_handle = port_hdl, create_host  = 'false',
                                        intf_mode = 'ethernet', phy_mode  = phy_mode, scheduling_mode = schedule_mode,
                                        port_loadunit = 'PERCENT_LINE_RATE', port_load = '10', enable_ping_response = '0',
                                        control_plane_mtu = '1500', flow_control = 'false',
                                        deficit_idle_count = 'true', pfc_negotiate_by_dcbx = '0', speed = speed_tgn,
                                        data_path_mode = 'normal', autonegotiation = '1', duplex = 'full');
       if re.search(r'100gig', speed, re.IGNORECASE):
          speed_tgn = 'ether100Gig'
          int_ret = sth.interface_config ( mode = 'config', port_handle = port_hdl, create_host  = 'false',
                                        intf_mode = 'ethernet', phy_mode  = phy_mode, scheduling_mode = 'RATE_BASED',
                                        port_loadunit = 'PERCENT_LINE_RATE', port_load = '10', enable_ping_response = '0',
                                        control_plane_mtu = '1500', transmit_clock_source = 'internal', flow_control = 'false',
                                        deficit_idle_count = 'true', speed = speed_tgn, tx_preemphasis_main_tap = '21',
                                        data_path_mode = 'normal', autonegotiation = '0', duplex = 'full',
                                        forward_error_correct = 'true', collision_exponent = '10',
					internal_ppm_adjust = '0', rx_equalization = '8', tx_preemphasis_post_tap = '8');
       status = int_ret['status']
       if (status == '0'):
           log.info("run sth.interface_config failed %r ", int_ret)
           return 0
   return 1

def configure_tgn_simulated_device (tgn_type = '', port_hdl = '', netmask = '24', addr = '', gw_add = '',
                            no_of_device = 1, mac_addr = '', vlan = '', ip_stack_ver = '', router_id = '192.1.1.1'):
   if tgn_type == 'stc':
      hdl_list = []
      if vlan:
         encaps = 'ethernet_ii_vlan'
         if ip_stack_ver == 4 :
            ip_ver = 'ipv4'
            device_ret0 = sth.emulation_device_config ( mode = 'create', port_handle = port_hdl,\
                  encapsulation = encaps, ip_version = ip_ver, intf_ip_addr = addr,\
                  intf_prefix_len = netmask, mac_addr = mac_addr, vlan_id = vlan,\
                  gateway_ip_addr = gw_add, router_id = router_id, count = no_of_device)
         else:
            ip_ver = 'ipv6'
            device_ret0 = sth.emulation_device_config ( mode = 'create', port_handle = port_hdl,\
                  encapsulation = encaps, ip_version = ip_ver, intf_ipv6_addr = addr,\
                  intf_ipv6_prefix_len = netmask, mac_addr = mac_addr, vlan_id = vlan,\
                  gateway_ipv6_addr = gw_add , router_id = router_id, count = no_of_device)
      else:
         encaps = 'ethernet_ii'
         if ip_stack_ver == 4 :
            ip_ver = 'ipv4'
            device_ret0 = sth.emulation_device_config ( mode = 'create', port_handle = port_hdl,\
                  encapsulation = encaps, ip_version = ip_ver, intf_ip_addr = addr,\
                  intf_prefix_len = netmask, mac_addr = mac_addr,\
                  gateway_ip_addr = gw_add, router_id = router_id, count = no_of_device)
         else:
            ip_ver = 'ipv6'
            device_ret0 = sth.emulation_device_config ( mode = 'create', port_handle = port_hdl,\
                  encapsulation = encaps, ip_version = ip_ver, intf_ipv6_addr = addr,\
                  intf_ipv6_prefix_len = netmask, mac_addr = mac_addr,\
                  gateway_ipv6_addr = gw_add , router_id = router_id, count = no_of_device)
      status = device_ret0['status']
      if (status == '0') :
         log.info('run sth.emulation_device_config failed %r', device_ret0)
         return (0, hdl_list)
      else:
         dev_hdl = device_ret0['handle'].split()[0]
         return (1, dev_hdl)


def configure_tgn_simulated_bgp_device (tgn_type = '', port_hdl = '', netmask = '24', addr = '', remote_add = '',
                                        mac_addr = '', vlan = '', ip_stack_ver = '', local_as ='', remote_as = '',
                                        num_routes = '', start_pfx_ip = '', pfx_mask = ''):
   #start to create the device:
   if tgn_type == 'stc':
      hdl_list = []
      if ip_stack_ver == 4 :
         device_ret0 = sth.emulation_bgp_config ( mode = 'enable', retries = '100', vpls_version = 'VERSION_00',
                                            routes_per_msg = '2000', staggered_start_time  = '100',
                                            update_interval = '60', retry_time = '30', staggered_start_enable = '1',
                                            md5_key_id = '1', md5_key = 'Spirent', md5_enable = '0', ipv4_unicast_nlri = '1',
                                            ip_stack_version  = str(ip_stack_ver), port_handle = port_hdl,
                                            bgp_session_ip_addr = 'interface_ip',
                                            remote_ip_addr = remote_add,ip_version = str(ip_stack_ver),view_routes = '0',
                                            remote_as = str(remote_as), hold_time = '180', restart_time = '120', route_refresh = '0',                                             local_as = str(local_as), active_connect_enable = '1', stale_time = '90',
                                            graceful_restart_enable = '1', vlan_cfi = '0',vlan_id = str(vlan),
                                            vlan_user_priority = '7',local_router_id = '192.0.0.39', mac_address_start = mac_addr,
                                            next_hop_ip = remote_add, local_ip_addr = addr, netmask = str(netmask));
      if ip_stack_ver == 6 :
         device_ret0 = sth.emulation_bgp_config ( mode = 'enable', retries = '100', vpls_version = 'VERSION_00',
                                            routes_per_msg = '2000', staggered_start_time  = '100',
                                            update_interval = '60', retry_time = '30', staggered_start_enable = '1',
                                            md5_key_id = '1', md5_key = 'Spirent', md5_enable = '0', ipv6_unicast_nlri = '1',
                                            ip_stack_version  = str(ip_stack_ver), port_handle = port_hdl,
                                            bgp_session_ip_addr = 'interface_ip',
                                            remote_ipv6_addr = remote_add,ip_version = str(ip_stack_ver),view_routes = '0',
                                            remote_as = str(remote_as), hold_time = '180', restart_time = '120', route_refresh = '0',                                             local_as = str(local_as), active_connect_enable = '1', stale_time = '90',
                                            graceful_restart_enable = '1', vlan_cfi = '0',vlan_id = str(vlan),
                                            vlan_user_priority = '7',local_router_id = '192.0.0.39', mac_address_start = mac_addr,
                                            next_hop_ipv6 = remote_add, local_ipv6_addr = addr, netmask_ipv6 = str(netmask));

      status = device_ret0['status']
      if (status == '0') :
         log.info('run sth.emulation_bgp_config failed %r', device_ret0)
         return (0, hdl_list)

      bgp_rtr_hdl = device_ret0['handle'].split()[0]
      if str(pfx_mask) == '24':
         mask = '255.255.255.0'
      if str(pfx_mask) == '32':
         mask = '255.255.255.255'
      if ip_stack_ver == 4 :
         device_ret0_route1 = sth.emulation_bgp_route_config (handle = bgp_rtr_hdl, mode = 'add', ip_version = str(ip_stack_ver),
                                                           as_path = 'as_seq:'+ str(local_as), target_type = 'as', target = '100',
                                                           target_assign = '1', rd_type = '0', rd_admin_step = '0',
                                                           rd_admin_value = '100', rd_assign_step = '1', rd_assign_value = '1',
                                                           next_hop_ip_version = str(ip_stack_ver), next_hop_set_mode = 'manual',
                                                           ipv4_unicast_nlri = '1', prefix = start_pfx_ip, netmask = mask,
                                                           prefix_step = '1', num_routes = num_routes, next_hop = addr,
                                                           atomic_aggregate = '0', local_pref = '10', route_category = 'unique',
                                                           label_incr_mode = 'none', origin = 'igp');
      if ip_stack_ver == 6 :
         device_ret0_route1 = sth.emulation_bgp_route_config (handle = bgp_rtr_hdl, mode = 'add', ip_version = str(ip_stack_ver),
                                                     as_path = 'as_seq:'+ str(local_as), target_type = 'as', target = '100',
                                                     target_assign = '1', rd_type = '0', rd_admin_step = '0',
                                                     rd_admin_value = '100', rd_assign_step = '1', rd_assign_value = '1',
                                                     next_hop_ip_version = str(ip_stack_ver), next_hop_set_mode = 'manual',
                                                     ipv6_unicast_nlri = '1', prefix = start_pfx_ip, ipv6_prefix_length = pfx_mask,
                                                     prefix_step = '1', num_routes = num_routes, next_hop = addr,
                                                     atomic_aggregate = '0', local_pref = '10', route_category = 'unique',
                                                     label_incr_mode = 'none', origin = 'igp');



      if (status == '0') :
        log.info('run sth.emulation_bgp_route_config failed %r',device_ret0_route1)
        return (0, hdl_list)
      bgp_route_hdl = device_ret0_route1['handles'].split()[0]
      hdl_list.append(bgp_rtr_hdl)
      hdl_list.append(bgp_route_hdl)

   return (1, hdl_list)

def configure_traffic_stream (tgn_type = '', stream_name = '', port_hdl = '', route_src_hdl = '', route_dst_hdl = '',
                                        frame_size = '', traffic_gw = '', traffic_type = '', rate_percent = '',
                                        rate_pps = ''):
   if len(str(rate_pps)) & len(str(rate_percent)):
       log.info('Both rates percentage and pps can not be used')
       return 0
   stream_id = ''
   if traffic_type == 6:
       if rate_percent:
          strm_blk_ret = sth.traffic_config ( mode = 'create', port_handle = port_hdl, emulation_src_handle = route_src_hdl,
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
          strm_blk_ret = sth.traffic_config ( mode = 'create', port_handle = port_hdl, emulation_src_handle = route_src_hdl,
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
            log.info('run sth.traffic_config failed for V6 %r', strm_blk_ret)
            return stream_id
       else:
            stream_id = strm_blk_ret['stream_id']
            return stream_id
   if traffic_type == 4:
       if rate_percent:
          strm_blk_ret = sth.traffic_config (mode = 'create', port_handle = port_hdl, emulation_src_handle = route_src_hdl,
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
          strm_blk_ret = sth.traffic_config (mode = 'create', port_handle = port_hdl, emulation_src_handle = route_src_hdl,
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
            log.info('run sth.traffic_config failed for V4 %r', strm_blk_ret)
            return stream_id
       else:
            stream_id = strm_blk_ret['stream_id']
            return stream_id

def device_connect_mgmt (device_list):
   for tb_device in device_list:
      tb_device.connect(alias = 'mgmt', via = 'mgmt')
      if not tb_device.is_connected(alias = 'mgmt'):
         log.info('Unable to connect %r', tb_device.name)
         return 0
   return 1

def device_connect (device_list):
   disable_prompt_check('exec')
   disable_prompt_check('config')
   for tb_device in device_list:
      tb_device.connect()
      if not tb_device.is_connected():
         log.info('Unable to connect %r', tb_device.name)
         return 0
      tb_device.transmit('configure \n')
      tb_device.receive(r"# $", timeout=5)
      tb_device.transmit('hostname ' + tb_device.name + '\n')
      tb_device.receive(r"# $", timeout=5)
   enable_prompt_check('exec')
   enable_prompt_check('config')
   for tb_device in device_list:
      tb_device.configure('feature telnet\n')
      if not device_connect_mgmt([tb_device]):
         return 0
   return 1

def make_interface_default (device_handle, interface):
    conf_str = 'default interface ' + interface + '\n'
    device_handle.mgmt.configure(conf_str)

def breakout_intf (device_handle, interface_nu, speed):
   match = re.search(r'(\d+)/(\d+)/(\d+)', interface_nu, re.IGNORECASE)
   conf_str = ""
   if match:
      if re.search(r'10gig', speed, re.IGNORECASE):
         conf_s = 'interface breakout module ' + str(match.group(1)) +\
              ' port ' + str(match.group(2)) + ' map 10g\n'
         device_handle.configure(conf_s)
      if re.search(r'25gig', speed, re.IGNORECASE):
         conf_s = 'interface breakout module ' + str(match.group(1)) +\
              ' port ' + str(match.group(2)) + ' map 25g\n'
         device_handle.configure(conf_s)
      if re.search(r'50gig', speed, re.IGNORECASE):
         conf_s = 'interface breakout module ' + str(match.group(1)) +\
              ' port ' + str(match.group(2)) + ' map 50g\n'
         device_handle.configure(conf_s)
      make_interface_default (device_handle, interface_nu)
      conf_str += 'interface ethernet ' + str(match.group(1)) + '/' + str(match.group(2)) + '/' + str(match.group(3)) + '\n'
      conf_str += 'no shut\n'
   else:
      match = re.search(r'(\d+)/(\d+)', interface_nu, re.IGNORECASE)
      make_interface_default (device_handle, interface_nu)
      conf_str += 'interface ethernet ' + str(match.group(1)) + '/' + str(match.group(2)) + '\n'
      conf_str += 'no shut\n'
   device_handle.mgmt.configure(conf_str)

def create_po (device_handle, po_nu, port_list):

   conf_str = ""

   for port1 in port_list:
     conf_str += 'interface ' + port1 + '\n'
     conf_str += 'channel-group ' + str(po_nu) + ' mode active\n'
   return conf_str

def get_next_mac (mac_add):
   new_mac = ''
   match_list = re.split(r':', mac_add)
   if match_list:
     m_1 = match_list[0]
     m_2 = match_list[1]
     m_3 = match_list[2]
     m_4 = match_list[3]
     m_5 = match_list[4]
     m_6 = match_list[5]
     d_m_6 = int(m_6, 16) + 1
     match = re.search(r'0x(.*)', hex(d_m_6))
     m_6 =  match.group(1)
     if d_m_6 > 255:
        m_6 = '0'
        d_m_5 = int(m_5, 16) + 1
        match = re.search(r'0x(.*)', hex(d_m_5))
        m_5 =  match.group(1)
        if d_m_5 > 255:
           m_5 = '0'
           d_m_4 = int(m_4, 16) + 1
           match = re.search(r'0x(.*)', hex(d_m_4))
           m_4 =  match.group(1)
           if d_m_4 > 255:
              m_4 = '0'
              d_m_3 = int(m_3, 16) + 1
              match = re.search(r'0x(.*)', hex(d_m_3))
              m_3 =  match.group(1)
              if d_m_3 > 255:
                 m_3 = '0'
                 d_m_2 = int(m_2, 16) + 1
                 match = re.search(r'0x(.*)', hex(d_m_2))
                 m_2 =  match.group(1)
                 if d_m_2 > 255:
                    m_2 = '0'
                    d_m_1 = int(m_1, 16) + 1
                    match = re.search(r'0x(.*)', hex(d_m_1))
                    m_1 =  match.group(1)
     new_mac = str(m_1)+':'+str(m_2)+':'+str(m_3)+':'+str(m_4)+':'+str(m_5)+':'+str(m_6)
     return new_mac

def string_is_ip_address (validate_string):
   try:
      rowPos = ipaddress.ip_address(validate_string)
   except ValueError:
      return 0
   return 1

def get_next_lpm_ipv6 (start_ipv6):
   '''
     Increments /64
   '''
   try:
      rowPos = ipaddress.ip_address(start_ipv6)
   except ValueError:
      log.info ('%r is not a valid IPV6 Address', start_ipv6)
      return 0
   ipv6_expanded = ipaddress.ip_address(start_ipv6).exploded
   match_list = re.split(r':', ipv6_expanded)
   if match_list:
     m_1 = match_list[0]
     m_2 = match_list[1]
     m_3 = match_list[2]
     m_4 = match_list[3]
     m_5 = match_list[4]
     m_6 = match_list[5]
     m_7 = match_list[6]
     m_8 = match_list[7]

   d_m_4 = int(m_4, 16) + 1
   match = re.search(r'0x(.*)', hex(d_m_4))
   m_4 =  match.group(1)
   if d_m_4 > 65535:
      d_m_4 = 0
      d_m_3 = int(m_3, 16) + 1
      m_4 = '0'
      match = re.search(r'0x(.*)', hex(d_m_3))
      m_3 = match.group(1)
      if d_m_3 > 65535:
         d_m_3 = 0
         d_m_2 = int(m_2, 16) + 1
         m_3 = '0'
         match = re.search(r'0x(.*)', hex(d_m_2))
         m_2 = match.group(1)
         if d_m_2 > 65535:
            d_m_2 = 0
            d_m_1 = int(m_1, 16) + 1
            m_2 = '0'
            match = re.search(r'0x(.*)', hex(d_m_1))
            m_1 = match.group(1)
   new_ipv6 = str(m_1)+':'+str(m_2)+':'+str(m_3)+':'+str(m_4)+':'+str(m_5)+':'+str(m_6)+':'+str(m_7)+':'+str(m_8)
   new_ipv6 = ipaddress.ip_address(new_ipv6).compressed

   try:
      rowPos = ipaddress.ip_address(new_ipv6)
   except ValueError:
      log.info ('Unable get next host ipv6 for %r', start_ipv6)
      return 0
   return new_ipv6

def get_next_host_ipv6 (start_ipv6):
   '''
     Increments 3rd octect and returns next IP
   '''
   try:
      rowPos = ipaddress.ip_address(start_ipv6)
   except ValueError:
      log.info ('%r is not a valid IPV6 Address', start_ipv6)
      return 0
   ipv6_expanded = ipaddress.ip_address(start_ipv6).exploded
   match_list = re.split(r':', ipv6_expanded)
   if match_list:
     m_1 = match_list[0]
     m_2 = match_list[1]
     m_3 = match_list[2]
     m_4 = match_list[3]
     m_5 = match_list[4]
     m_6 = match_list[5]
     m_7 = match_list[6]
     m_8 = match_list[7]
   d_m_8 = int(m_8, 16) + 1
   match = re.search(r'0x(.*)', hex(d_m_8))
   m_8 =  match.group(1)
   if d_m_8 > 65535:
      d_m_8 = 0
      d_m_7 = int(m_7, 16) + 1
      m_8 = '0'
      match = re.search(r'0x(.*)', hex(d_m_7))
      m_7 = match.group(1)
      if d_m_7 > 65535:
         d_m_7 = 0
         d_m_6 = int(m_6, 16) + 1
         m_7 = '0'
         match = re.search(r'0x(.*)', hex(d_m_6))
         m_6 = match.group(1)
         if d_m_6 > 65535:
            d_m_6 = 0
            d_m_5 = int(m_5, 16) + 1
            m_6 = '0'
            match = re.search(r'0x(.*)', hex(d_m_5))
            m_5 = match.group(1)
   new_ipv6 = str(m_1)+':'+str(m_2)+':'+str(m_3)+':'+str(m_4)+':'+str(m_5)+':'+str(m_6)+':'+str(m_7)+':'+str(m_8)
   new_ipv6 = ipaddress.ip_address(new_ipv6).compressed

   try:
      rowPos = ipaddress.ip_address(new_ipv6)
   except ValueError:
      log.info ('Unable get next host ipv6 for %r', start_ipv6)
      return 0
   return new_ipv6

def get_next_host_ip (start_ip):
   '''
     Increments 3rd octect and returns next IP
   '''
   try:
      rowPos = ipaddress.ip_address(start_ip)
   except ValueError:
      log.info ('%r is not a valid IP Address', start_ip)
      return 0
   match = re.search(r'(\d+).(\d+).(\d+).(\d+)', start_ip)
   if match:
     first_o = match.group(1)
     second_o = match.group(2)
     third_o = match.group(3)
     fourth_o = match.group(4)
   first_o = int(first_o)
   second_o = int(second_o)
   third_o = int(third_o)
   fourth_o = int(fourth_o)
   fourth_o += 1
   if fourth_o > 255:
      fourth_o = 0
      third_o += 1
      if third_o > 255:
         third_o = 0
         second_o += 1
         if second_o > 255:
            second_o = 0
            first_o += 1
   new_ip = str(first_o) + '.' + str(second_o) + '.' + str(third_o) + '.' + str(fourth_o)

   try:
      rowPos = ipaddress.ip_address(new_ip)
   except ValueError:
      log.info ('Unable get next host ip for %r', start_ip)
      return 0
   return new_ip

def get_next_lpm_ip (start_ip):
   '''
     Increments 3rd octect and returns next IP
   '''
   try:
      rowPos = ipaddress.ip_address(start_ip)
   except ValueError:
      log.info ('%r is not a valid IP Address', start_ip)
      return 0
   match = re.search(r'(\d+).(\d+).(\d+).(\d+)', start_ip)
   if match:
     first_o = match.group(1)
     second_o = match.group(2)
     third_o = match.group(3)
     fourth_o = match.group(4)
   first_o = int(first_o)
   second_o = int(second_o)
   third_o = int(third_o)
   fourth_o = int(fourth_o)
   third_o += 1
   if third_o > 255:
      third_o = 0
      second_o += 1
      if second_o > 255:
         second_o = 0
         first_o += 1

   temp = str(first_o) + '.' + str(second_o) + '.' + str(third_o)
   ip_net = temp + str('.0/24')
   next_ip = temp + '.' + str(fourth_o)
   try:
      rowPos = ipaddress.ip_network(ip_net)
   except ValueError:
      log.info ('Unable get next lpm ip for %r', start_ip)
      return ""
   return next_ip

def delete_all_rpm_entries(device):
    oput = device.execute("show run rpm")
    lines = oput.splitlines()
    config_str = ""
    for line in lines:
       if re.search('route-map( )|ip prefix-list|ip community-list', line, re.IGNORECASE):
         config_str = config_str + 'no ' + line + '\n'
    if config_str:
       device.configure(config_str)

def delete_all_tcam_entries(device):
    oput = device.execute("show run | i 'tcam'")
    lines = oput.splitlines()
    config_str = ""
    for line in lines:
       if re.search('hardware access-list tcam', line, re.IGNORECASE):
          config_str = config_str + 'no ' + line + '\n'
       if re.search('ref-template|service-template', line, re.IGNORECASE):
          config_str = config_str + 'no ' + line + '\n'
    if config_str:
       device.configure(config_str)

def reload_device (device, save_config = 1):
   # Check if we have connected throgh management
   # If so after reload we need to make sure its connected through management,
   if save_config:
     device.configure('copy running start\n')
   mgmt_connected = 0
   if device.is_connected(alias = 'mgmt'):
      mgmt_connected = 1
      device.disconnect(alias = 'mgmt')

   device.reload()
   log.info('\nSleeping for 2 minutes so that system can come to ready state\n')
   time.sleep(120)
   if mgmt_connected:
     device.connect(alias = 'mgmt', via = 'mgmt')
     if not device.is_connected(alias = 'mgmt'):
       log.info('Unable to connect to device %r through mgmt after reload', device)
       return 0
   return 1

def reload_devices_parallel(device_list):
   mgmt_connected_list = []
   for device in device_list:
      if device.is_connected(alias = 'mgmt'):
         mgmt_connected_list.append(1)
         device.disconnect(alias = 'mgmt')
      else:
         mgmt_connected_list.append(0)
   pcall (reload_device, device = device_list)
   i = 0
   for device in device_list:
      if mgmt_connected_list[i]:
         device.connect(alias = 'mgmt', via = 'mgmt')
      i += 1
   return 1

def delete_all_static_routes(device):
    oput = device.execute("show run | i 'ip route '")
    lines = oput.splitlines()
    config_str = ""
    for line in lines:
       match = re.search(r'^ip route', line)
       if match:
         config_str = config_str + 'no ' + line + '\n'
    oput = device.execute("show run | i 'ipv6 route '")
    lines = oput.splitlines()
    for line in lines:
       match = re.search(r'^ipv6 route', line)
       if match:
         config_str = config_str + 'no ' + line + '\n'
    if config_str:
       device.configure(config_str)

def delete_all_L3_address(device):
    oput = device.execute("show interface brief")
    lines = oput.splitlines()
    config_str = ""
    for line in lines:
       match = re.search(r'Eth', line)
       if match:
           words = get_words_list_from_line(line)
           sub_int = words[0]
           if re.search(r'Eth(.*)\.', line):
             config_str = config_str + 'no interface ' + sub_int + '\n'
    if config_str:
       device.configure(config_str)

    oput = device.execute("show ipv6 interface brief vrf all")
    lines = oput.splitlines()
    config_str = ""
    for line in lines:
       match = re.search(r'Eth', line)
       if match:
           words = get_words_list_from_line(line)
           sub_int = words[0]
           if re.search(r'Eth(.*)\.', line):
             config_str = config_str + 'no interface ' + sub_int + '\n'
    if config_str:
       device.configure(config_str)

    oput = device.execute("show ip interface brief vrf all")
    lines = oput.splitlines()
    config_str = ""
    for line in lines:
       match = re.search(r'Eth', line)
       if match:
           words = get_words_list_from_line(line)
           intf = words[0]
           config_str = config_str + 'interface ' + intf + '\n'
           config_str = config_str + 'no ip address \n'
       else:
           match = re.search(r'Po', line)
           if match:
               words = get_words_list_from_line(line)
               intf = words[0]
               config_str = config_str + 'interface ' + intf + '\n'
               config_str = config_str + 'no ip address \n'
               config_str = config_str + 'no interface ' + intf + '\n'
    if config_str:
       device.configure(config_str)

    oput = device.execute("show ipv6 interface brief vrf all")
    lines = oput.splitlines()
    config_str = ""
    for line in lines:
       match = re.search(r'Eth', line)
       if match:
           words = get_words_list_from_line(line)
           intf = words[0]
           config_str = config_str + 'interface ' + intf + '\n'
           config_str = config_str + 'no ipv6 address \n'
       else:
           match = re.search(r'Po', line)
           if match:
               words = get_words_list_from_line(line)
               intf = words[0]
               config_str = config_str + 'interface ' + intf + '\n'
               config_str = config_str + 'no ipv6 address \n'
               config_str = config_str + 'no interface ' + intf + '\n'
    if config_str:
       device.configure(config_str)

def set_swithcmode_old (device, sw_mode, login_name, password):
    oput = device.execute("show system switch-mode")
    write_erase_done = 0
    if re.search('Switch mode configuration is not applicable', oput, re.IGNORECASE):
      return (1, write_erase_done)
    lines = oput.splitlines()
    config_str = ""
    mode_as_required = 0
    write_erase_req = 0
    for line in lines:
       match = re.search('system switch-mode ([a-zA-Z0-9]+)', oput, re.IGNORECASE)
       if sw_mode.lower() == match.group(1).lower():
         mode_as_required = 1
       if re.search('write erase.*is required', oput, re.IGNORECASE):
         write_erase_req = 1
    write_erase = 0
    if mode_as_required:
       if write_erase_req:
          write_erase_switch(device, login_name, password)
          write_erase_done = 1
       return (1, write_erase_done)
    else:
       device.configure('system switch-mode ' + sw_mode + ' \n')
       if write_erase_req:
          return (1, write_erase_done)
       else:
          write_erase_switch(device, login_name, password)
          write_erase_done = 1
          return (1, write_erase_done)

    return (0, write_erase_done)

def if_n9k_only_platform (device):
    if re.search(r'9k|T2P|TH', device.type, re.IGNORECASE):
       return 1
    return 0

def set_swithcmode_and_reload_parallel (device_list, sw_mode, login_name, password):
    write_erase_device_list = []
    mgmt_connected_list = []
    login_name_list = []
    passwd_list = []
    disconnect_list_yes = []
    for device in device_list:
      if set_swithcmode (device, sw_mode):
         write_erase_device_list.append(device)
         login_name_list.append(login_name)
         passwd_list.append(password)
         disconnect_list_yes.append(0)
    if len(write_erase_device_list):
      for device in write_erase_device_list:
         if device.is_connected(alias = 'mgmt'):
            mgmt_connected_list.append(device)
            device.disconnect(alias = 'mgmt')
      pcall (write_erase_switch, device = write_erase_device_list, login_name = login_name_list, password = passwd_list,\
                   mgmt_disconnect_required = disconnect_list_yes)
      for device in mgmt_connected_list:
         device.connect(alias = 'mgmt', via = 'mgmt')
    return 1

def set_swithcmode_and_reload (device, sw_mode, login_name, password):
    if set_swithcmode(device, sw_mode):
       write_erase_switch(device, login_name, password)
    return 1

def set_swithcmode (device, sw_mode):
    oput = device.execute("show system switch-mode")
    write_erase_done = 0
    write_erase_req = 0
    if re.search('Switch mode configuration is not applicable', oput, re.IGNORECASE):
      return write_erase_req
    lines = oput.splitlines()
    mode_as_required = 0
    for line in lines:
       match = re.search('system switch-mode ([a-zA-Z0-9]+)', oput, re.IGNORECASE)
       if sw_mode.lower() == match.group(1).lower():
         mode_as_required = 1
       if re.search('write erase.*is required', oput, re.IGNORECASE):
         write_erase_req = 1
    if not mode_as_required:
       if re.search(r'9k', sw_mode, re.IGNORECASE):
          device.configure('system switch-mode n9k \n')
       else:
          device.configure('system switch-mode n3k \n')
       write_erase_req = 1
    return write_erase_req

def create_l3_intf_config_string (main_inf = '', sub_intf_nu = '', ipv4_add = '', ipv6_add = '', \
                                  ipv4_mask = '', ipv6_mask = '', vrf_name = '', dot1q_vlan = '',\
                                  mpls_fw = '', mtu = 9216, ospf_id = '', ospf_area = '', ospf_cost = 0,\
                                  ipv6_ospf = 0):
   config_str = ''
   if not sub_intf_nu:
      config_str += 'interface ' + main_inf + '\n'
      if not re.search(r'vlan|loop', main_inf, re.IGNORECASE):
         config_str += 'no switchport\n'
      if mpls_fw:
         config_str += 'mpls ip forwarding\n'
   else:
      config_str += 'interface ' + main_inf + '.' + str(sub_intf_nu) + '\n'
      config_str += 'encapsulation dot1q ' + str(dot1q_vlan) + '\n'
   if vrf_name:
      config_str += 'vrf member ' + str(vrf_name) + '\n'
   if mtu > 1500:
      if not re.search(r'loop', main_inf, re.IGNORECASE):
         config_str += 'mtu 9216 \n'
   if ipv4_add:
      if ipv4_mask:
        if re.search(r'/', ipv4_mask):
           config_str += 'ip address ' + ipv4_add + ipv4_mask + '\n'
        else:
           config_str += 'ip address ' + ipv4_add + ' ' + ipv4_mask + '\n'
      else:
        config_str += 'ip address ' + ipv4_add + '/24\n'
   if ipv6_add:
      if ipv6_mask:
        if re.search(r'/', ipv6_mask):
           config_str += 'ipv6 address ' + ipv6_add + ipv6_mask + '\n'
        else:
           config_str += 'ipv6 address ' + ipv6_add + ' ' + ipv6_mask + '\n'
      else:
        config_str += 'ipv6 address ' + ipv6_add + '/64\n'
   if ospf_id:
      if ospf_area:
        config_str += 'ip router ospf ' + str(ospf_id) + ' area ' + str(ospf_area) + '\n'
      else:
        log.info('OSPF Area id is not specified, unable to configure OSPF on interface')
        return ''
      if ipv6_ospf:
        if ospf_area:
          config_str += 'ipv6 router ospfv3 ' + str(ospf_id) + ' area ' + str(ospf_area) + '\n'
        else:
          log.info('OSPF Area id is not specified, unable to configure OSPFV3 on interface')
          return ''
      if ospf_cost:
          config_str += 'ip ospf cost ' + str(ospf_cost) + '\n'

   config_str += 'no shut \n'
   return config_str

def create_evpn_vrf_config_string (vrf_name = '', rd_name = 'auto', rt_import = '', rt_export = '', afi_v4 = 1, afi_v6 = 1):
   config_str = ""
   config_str += 'vrf context ' + vrf_name + '\n'
   config_str += 'rd ' + str(rd_name) + '\n'
   if afi_v4:
      config_str += 'address-family ipv4 unicast' + '\n'
      config_str += 'route-target import ' + rt_import  + '\n'
      config_str += 'route-target import ' + rt_import  + ' evpn\n'
      config_str += 'route-target export ' + rt_export  + '\n'
      config_str += 'route-target export ' + rt_export  + ' evpn\n'
   if afi_v6:
      config_str += 'address-family ipv6 unicast' + '\n'
      config_str += 'route-target import ' + rt_import  + '\n'
      config_str += 'route-target import ' + rt_import  + ' evpn\n'
      config_str += 'route-target export ' + rt_export  + '\n'
      config_str += 'route-target export ' + rt_export  + ' evpn\n'
   return config_str

def create_bgp_nbr_conf_string (vrf_name = '', vrf_afi_list = ['ipv4 unicast'], vrf_afi_adv_l2vpn = '',\
                                nbr_address = '', nbr_as = '', nbr_afi_list = ['ipv4 unicast'],\
                                nbr_as_rr_client = '', if_next_hop_self = '',ebgp_multihop = '',\
                                update_src_int = '', l2vpn_encap = '', in_rmap = '', out_rmap = '', \
                                enable_bfd = '', epe_pset_str = '', disable_peer_as_check = 0, \
                                allowas_in = 0, send_community = 0 ):
   '''
    afi = should be specified as "ipv4 unicast" or "ipv4 labeled-unicast" and so on
   '''
   config_str = ""
   if vrf_name:
     config_str += 'vrf ' + str(vrf_name) + '\n'
     for afi in vrf_afi_list:
        if not re.search(r'v4|v6', afi, re.IGNORECASE):
           log.info ('address-family %r is not supported under vlan', afi)
           return config_str
        config_str += 'address-family ' + str(afi) + '\n'
        if vrf_afi_adv_l2vpn:
           config_str += 'advertise l2vpn evpn\n'

   if nbr_address:
      config_str += 'neighbor ' + str(nbr_address) + ' remote-as ' + str(nbr_as) + '\n'
   if enable_bfd:
      config_str += 'bfd\n'
   if ebgp_multihop:
      config_str += 'ebgp-multihop ' + str(ebgp_multihop) + '\n'
   if update_src_int:
     config_str += 'update-source ' + str(update_src_int) + '\n'
   if epe_pset_str:
     config_str += 'egress-engineering peer-set ' + epe_pset_str + '\n'

   for afi in nbr_afi_list:
      config_str += 'address-family ' + str(afi) + '\n'
      if nbr_as_rr_client:
        config_str += 'route-reflector-client\n'
      if if_next_hop_self:
        config_str += 'next-hop-self\n'
      if re.search(r'l2vpn', afi, re.IGNORECASE):
        config_str += 'send-community\n'
        config_str += 'send-community extended\n'
      if l2vpn_encap:
        config_str += 'encapsulation mpls\n'
      if in_rmap:
        config_str += 'route-map ' + str(in_rmap) + ' in\n'
      if out_rmap:
        config_str += 'route-map ' + str(out_rmap) + ' out\n'
      if disable_peer_as_check:
        config_str += 'disable-peer-as-check\n'
      if allowas_in:
        config_str += 'allowas-in\n'
      if send_community:
        config_str += 'send-community\n'

   return config_str

def clean_all_configs (device, device_mgmt):
    unconfigure_features_for_clean(device_mgmt)
    delete_all_vrfs_for_clean(device_mgmt)
    unconfigure_breakout_for_clean(device_mgmt)
    delete_all_Loopbacks(device_mgmt)
    delete_all_pos(device_mgmt)
    delete_all_L3_address(device_mgmt)
    delete_all_tcam_entries(device_mgmt)
    delete_all_rpm_entries(device_mgmt)
    unconfig_ports_from_vlan(device_mgmt)
    delete_all_static_routes(device_mgmt)

def delete_all_pos (device):
    po_list = get_all_pos_configured (device)
    for po_no in po_list:
      conf_str = 'no interface ' + po_no + '\n'
      device.configure(conf_str)

def get_all_pos_configured (device):
    po_list = []
    oput = device.execute("show port-channel database")
    lines = oput.splitlines()
    for line in lines:
      match = re.search(r'port-channel(\d+)', line, re.IGNORECASE)
      if match:
        po_list.append(match.group(0))
    return po_list

def do_non_disrutive_issu (device, issu_image):
    oput = device.execute("show spanning-tree issu-impact")
    lines = oput.splitlines()
    vlan_list = []
    for line in lines:
       if re.search(r'ISSU Cannot Proceed', line, re.IGNORECASE):
           log.info('ISSU can not proceed due to Spanning tree check Failure')
           return 0
    device.transmit('install all nxos bootflash:' + issu_image + ' non-disruptive non-interruptive\n')
    device.receive(r"Do you want to enforce secure password standard.*:", timeout=240)
    output = device_obj.receive_buffer()
    return vlan_list

def get_all_configured_vlan_list(device):
    #oput = device.execute("show vlan all-ports")
    oput = device.execute("show vlan | end Vlan-mode")
    lines = oput.splitlines()
    port_list = []
    vlan_no = ""
    vlan_list = []
    for line in lines:
       match = re.search(r'(\d+).*VLAN', line, re.IGNORECASE)
       if match:
          vlan_no = match.group(1)
          vlan_list.append(vlan_no)
    return vlan_list

def unconfig_ports_from_vlan(device):
    port_list = []
    vlan_list = get_all_configured_vlan_list(device)
    conf_str = ""
    for vlan in vlan_list:
       oput = device.execute('show vlan id ' + vlan)
       lines = oput.splitlines()
       conf_str += 'no vlan ' + str(vlan) + '\n'
       for line in lines:
          words = get_words_list_from_line(line)
          for each_word in words:
             if re.search(r'Eth', each_word, re.IGNORECASE):
                each_word = each_word.strip(',')
                if not each_word in port_list:
                  port_list.append(each_word)
    for port in port_list:
       conf_str += 'default interface ' + port + '\n'
    if conf_str:
       device.configure(conf_str)

def delete_all_vrfs_for_clean(device):
    oput = device.execute("show run | i 'vrf context'")
    lines = oput.splitlines()
    config_str = ""
    for line in lines:
      if re.search('vrf context', line, re.IGNORECASE):
         if not re.search('vrf context management', line, re.IGNORECASE):
            config_str += 'no ' + line + '\n'
    if config_str:
       device.configure(config_str)

def delete_all_Loopbacks(device):
    oput = device.execute("show ip interface brief | i 'Lo'")
    lines = oput.splitlines()
    config_str = ""
    for line in lines:
       match = re.search(r'(Lo\d+)', line)
       if match:
         config_str += 'no interface ' + match.group(1) + '\n'
    if config_str:
       device.configure(config_str)

def unconfigure_breakout_for_clean(device):
    oput = device.execute("sh run | i 'interface breakout'")
    lines = oput.splitlines()
    config_str = ""
    for line in lines:
      if re.search('interface breakout', line, re.IGNORECASE):
         config_str += 'no ' + line + '\n'
    if config_str:
       device.configure(config_str)


def unconfigure_features_for_clean(device):
    device.transmit('config terminal\n')
    device.receive(r"# $", timeout=5)
    device.transmit('no feature vpc\n')
    device.receive(r"# $")
    device.transmit('no feature lacp\n')
    device.receive(r"# $")
    device.transmit('no feature interface-vlan\n')
    device.receive(r"# $")
    device.transmit('no feature bgp\n')
    device.receive(r"# $")
    device.transmit('no feature ospf\n')
    device.receive(r"# $")
    device.transmit('no feature ospfv3\n')
    device.receive(r"# $")
    device.transmit('no feature mpls static\n')
    device.receive(r"# $")
    device.transmit('no feature mpls evpn\n')
    device.receive(r"# $")
    device.transmit('no feature mpls segment-routing\n')
    device.receive(r"# $")
    device.transmit('no feature-set mpls\n')
    device.receive(r"# $")
    device.transmit('no install feature-set mpls\n')
    device.receive(r"# $")
    device.transmit('exit\n')
    device.receive(r"# $")

def write_erase_switch_parallel(device, login_name, password):
    '''
     Function to do write erase of switch
     called for parallely doing write erase on multiple switches.
    '''
    mgmt_ip = str(device.connections['mgmt']['ip'])
    mgmt_mask = device.connections['mgmt']['mask']
    mgmt_gw = device.connections['mgmt']['gw']
    log.info ('\nsaving config as \"config_before_write_erase\" to bootflash\n')
    device.transmit('copy running config_before_write_erase\n')
    if device.receive(r"Warning.*overwrite.*", timeout=10):
       device.transmit('y\n')
       device.receive(r"# $", timeout=30)
    response = collections.OrderedDict()
    response[r"Do you wish to proceed anyway"] = "econ_sendline y; exp_continue"
    device.execute('show clock')
    device.execute('write erase', reply=response)
    device.transmit('reload \n')
    device.receive("This command will reboot the system", timeout=120)
    device.transmit('y\n')
    time_out = 660
    if not device.receive(r"Abort.*Provisioning.*", timeout=time_out):
       log.warning ("\nDid not get Abort POAP message even after %r seconds\n", time_out)
       return -1
    device.transmit('yes\n')
    device.receive(r"Do you want to enforce secure password standard.*:", timeout=120)
    device.transmit('no\n')
    device.receive(r"Enter the password for.*", timeout=20)
    device.transmit(password + '\n')
    device.receive(r"Confirm the password for.*", timeout=20)
    device.transmit(password + '\n')
    device.receive(r"Would you like to enter the basic configuration dialog.*:", timeout=60)
    device.transmit('no\n')
    if not device.receive(r"login:", timeout=60):
       log.warning ("\nDid not get login prompt after poap\n", time_out)
       return -1
    device.transmit(login_name + '\n')
    device.receive(r"assword:", timeout=30)
    device.transmit(password + '\n')
    device.receive(r"# $", timeout=10)
    device.transmit('terminal length 0\n')
    device.receive(r"# $", timeout=5)
    device.transmit('terminal session-timeout 0\n')
    device.receive(r"# $", timeout=5)
    device.transmit('configure\n')
    device.receive(r"# $", timeout=5)
    device.transmit('no logging console\n')
    device.receive(r"# $", timeout=5)
    device.transmit('hostname ' + device.name + '\n')
    device.receive(r"# $", timeout=5)
    device.transmit('line console\n')
    device.receive(r"# $", timeout=5)
    device.transmit('exec-timeout 0\n')
    device.receive(r"# $", timeout=5)
    device.transmit('terminal width 511\n')
    device.receive(r"# $", timeout=5)
    device.transmit('feature telnet\n')
    device.receive(r"# $", timeout=5)
    conf_str = 'interface mgmt0\n'
    conf_str += 'ip address ' +  mgmt_ip + ' ' + mgmt_mask + '\n'
    conf_str += 'no shut\n'
    conf_str += 'vrf context management\n'
    conf_str += 'ip route 0/0 ' + mgmt_gw + '\n'
    device.configure(conf_str)
    device.execute('copy run start')
    return 1
def write_erase_switch(device, login_name, password, mgmt_disconnect_required = 1):
    """ Function to do write erase of switch """
    mgmt_connected = 0
    mgmt_ip = str(device.connections['mgmt']['ip'])
    mgmt_mask = device.connections['mgmt']['mask']
    mgmt_gw = device.connections['mgmt']['gw']
    if device.is_connected(alias = 'mgmt'):
       mgmt_connected = 1
       if mgmt_disconnect_required:
          device.disconnect(alias = 'mgmt')
    log.info ('\nsaving config as \"config_before_write_erase\" to bootflash\n')
    device.transmit('copy running config_before_write_erase\n')
    if device.receive(r"Warning.*overwrite.*", timeout=10):
       device.transmit('y\n')
       device.receive(r"# $", timeout=30)
    response = collections.OrderedDict()
    response[r"Do you wish to proceed anyway"] = "econ_sendline y; exp_continue"
    device.execute('show clock')
    device.execute('write erase', reply=response)
    device.transmit('reload \n')
    device.receive("This command will reboot the system", timeout=120)
    device.transmit('y\n')
    time_out = 460
    if not device.receive(r"Abort.*Provisioning.*", timeout=time_out):
       log.warning ("\nDid not get Abort POAP message even after %r seconds\n", time_out)
       return -1
    device.transmit('yes\n')
    device.receive(r"Do you want to enforce secure password standard.*:", timeout=120)
    device.transmit('no\n')
    device.receive(r"Enter the password for.*", timeout=20)
    device.transmit(password + '\n')
    device.receive(r"Confirm the password for.*", timeout=20)
    device.transmit(password + '\n')
    device.receive(r"Would you like to enter the basic configuration dialog.*:", timeout=60)
    device.transmit('no\n')
    if not device.receive(r"login:", timeout=60):
       log.warning ("\nDid not get login prompt after poap\n", time_out)
       return -1
    device.transmit(login_name + '\n')
    device.receive(r"assword:", timeout=30)
    device.transmit(password + '\n')
    device.receive(r"# $", timeout=10)
    device.transmit('terminal length 0\n')
    device.receive(r"# $", timeout=5)
    device.transmit('terminal session-timeout 0\n')
    device.receive(r"# $", timeout=5)
    device.transmit('configure\n')
    device.receive(r"# $", timeout=5)
    device.transmit('no logging console\n')
    device.receive(r"# $", timeout=5)
    device.transmit('hostname ' + device.name + '\n')
    device.receive(r"# $", timeout=5)
    device.transmit('line console\n')
    device.receive(r"# $", timeout=5)
    device.transmit('exec-timeout 0\n')
    device.receive(r"# $", timeout=5)
    device.transmit('terminal width 511\n')
    device.receive(r"# $", timeout=5)
    device.transmit('feature telnet\n')
    device.receive(r"# $", timeout=5)
    conf_str = 'interface mgmt0\n'
    conf_str += 'ip address ' +  mgmt_ip + ' ' + mgmt_mask + '\n'
    conf_str += 'no shut\n'
    conf_str += 'vrf context management\n'
    conf_str += 'ip route 0/0 ' + mgmt_gw + '\n'
    device.configure(conf_str)
    device.execute('copy run start')
    if mgmt_connected:
       if mgmt_disconnect_required:
          device.connect(alias = 'mgmt', via = 'mgmt')
          if not device.is_connected(alias = 'mgmt'):
            log.info('Unable to connect to device %r through mgmt after reload', device)
            return 0
    return 1

###################################################################
###                  COMMON SETUP SECTION                       ###
###################################################################
def get_remote_interface (device1_intf = "", device1_tb_obj = ""):
    for intf in device1_tb_obj:
       if intf.name.lower() == device1_intf.lower():
          intf_remote = intf.remote_interfaces.pop().name.lower()
          return intf_remote
    return ""

# Configure and setup all devices and test equipment in this section.
# This should represent the BASE CONFIGURATION that is applicable
# for the bunch of test cases that would follow.
def find_Connecting_interfaces(topo_dict = "", device1 = "", device2 = "", device1_tb_obj = "", device2_tb_obj = ""):
    '''
    devices:
     PE1:
        Peer_Device:
           CE1:
             Links:
                Link_1:
                   physical_interface: "auto select"
                   speed: 10Gig
           P1:
             Links:
                Link_1:
                   physical_interface: "auto select"
                   speed: 10Gig
                Link_2:
                   physical_interface: "auto select"
                   speed: 10Gig
                Link_3:
                   physical_interface: "auto select"
                   speed: 10Gig
                Link_4:
                   physical_interface: "auto select"
                   speed: "auto select"
                Link_5:
                   physical_interface: "auto select"
                   speed: 10Gig
             port-channels:
                port-channel 10:
                   members: [Link_3, Link_4, Link_5]
    '''

    pass_flag = 1
    used_interfaces = []
    device1_2_device2_dict = topo_dict['devices'][device1]['Peer_Device'][device2]
    device2_2_device1_dict = topo_dict['devices'][device2]['Peer_Device'][device1]

    intf_dict_tb = {}
    intf_dict_tb[device1] = dict()
    intf_dict_tb[device2] = dict()
    intf_dict_tb[device1]['intf'] = dict()
    intf_dict_tb[device2]['intf'] = dict()
    intf_dict_tb[device1]['intf_detail'] = dict()
    intf_dict_tb[device2]['intf_detail'] = dict()
    intf_dict_tb[device1]['tb_name'] = device1_tb_obj.name
    intf_dict_tb[device2]['tb_name'] = device2_tb_obj.name
    no_of_links_present = 0
    for intf in device1_tb_obj:
        if device2_tb_obj in intf.remote_devices:
           intf_name = intf.name.lower()
           intf_type = intf.type.lower()
           intf_remote = intf.remote_interfaces.pop().name.lower()
           intf_remote_speed = intf.remote_interfaces.pop().type.lower()
           intf_dict_tb[device1]['intf'][intf_name] = intf_type
           intf_dict_tb[device2]['intf'][intf_remote] = intf_remote_speed
           intf_dict_tb[device1]['intf_detail'][intf_name] = dict()
           intf_dict_tb[device1]['intf_detail'][intf_name]['speed'] = intf_type
           intf_dict_tb[device1]['intf_detail'][intf_name]['remote_int'] = intf_remote
           intf_dict_tb[device2]['intf_detail'][intf_remote] = dict()
           intf_dict_tb[device2]['intf_detail'][intf_remote]['speed'] = intf_remote_speed
           intf_dict_tb[device2]['intf_detail'][intf_remote]['remote_int'] = intf_name

           no_of_links_present += 1
           #Check if Peer interfaces are of same speed on Testbed file
           if not intf.type.lower() == intf.remote_interfaces.pop().type.lower():
              log.info('\nInterface %r of %r and Interface %r of %r are in same Link but of different speed in testbed file\n', \
                          intf.name, device1_tb_obj.name, intf.remote_interfaces.pop().name, device2_tb_obj.name )
              return 0
    intf_dict_tb['no_of_links_defined'] = no_of_links_present

    flag = 0
    #Check whether links defined in device1 exists in device2
    if not check_link_preset_in_neighbor_in_topo(topo_dict, device1, device2):
        pass_flag = 0
        flag = 1
    #Check whether links defined in device2 exists in device1
    if not check_link_preset_in_neighbor_in_topo(topo_dict, device2, device1):
        pass_flag = 0
        flag = 1
    #Check whether Link Speed is same in peer device
    if flag:
       if not check_link_speed_as_neighbor_in_topo(topo_dict, device1, device2):
           pass_flag = 0

    if not pass_flag:
       return 0

    # Check if port-channels are there, if exists member ports should be of same speed
    po_defined_flag = 1
    if 'port-channels' in device1_2_device2_dict.keys():
        if not 'port-channels' in device2_2_device1_dict.keys():
          log.info ('\nport-channels to %r are not defined in %r \n',device1, device2)
          pass_flag = 0
          po_defined_flag = 0
    else:
        po_defined_flag = 0
        if 'port-channels' in device2_2_device1_dict.keys():
          log.info ('\nport-channels to %r are not defined in %r \n',device2, device1)
          pass_flag = 0
          po_defined_flag = 0

    # Check If same Port-channels are defined in both devices
    same_pos_defined_flag = 1
    if po_defined_flag:
        for po_no in device1_2_device2_dict['port-channels'].keys():
           if not po_no in device2_2_device1_dict['port-channels'].keys():
               log.info ('\nPo Link %r of %r Connecting to %r is not defined\n', po_no, device1, device2)
               pass_flag = 0
               same_pos_defined_flag = 0
        for po_no in device2_2_device1_dict['port-channels'].keys():
           if not po_no in device1_2_device2_dict['port-channels'].keys():
               log.info ('\nPo Link %r of %r Connecting to %r is not defined\n', po_no, device2, device1)
               pass_flag = 0
               same_pos_defined_flag = 0

    # Check If same Links are defined in all Pos
    # Check if the links are there as Links key in device
    if same_pos_defined_flag and po_defined_flag:
        for po_no in device1_2_device2_dict['port-channels'].keys():
            links_list_1 = device1_2_device2_dict['port-channels'][po_no]['members']
            links_list_2 = device2_2_device1_dict['port-channels'][po_no]['members']
            if len(links_list_1) == len(links_list_2):
               for elm in links_list_1:
                   # If link element of PO is there in Links list for device1
                   if not elm in device1_2_device2_dict['Links'].keys():
                       log.info ('\n %r is not there in %r Links list to %r \n', elm, device1, device2)
                       pass_flag = 0
                       break
                   if not elm in links_list_2:
                       log.info ('\n %r is not there in %r po %r \n', elm, device1, po_no)
                       pass_flag = 0
                       break
            else:
              log.info ('\n Same number of Links are not defined in %r for %r and %r\n', po_no, device1, device2)
              pass_flag = 0
              break
    if not pass_flag:
       return 0
    # Check If speed are same for all link members of PO
    if same_pos_defined_flag and po_defined_flag:
        for po_no in device1_2_device2_dict['port-channels'].keys():
            links_list_1 = device1_2_device2_dict['port-channels'][po_no]['members']
            links_list_2 = device2_2_device1_dict['port-channels'][po_no]['members']
            reference_speed = get_po_member_speed (topo_dict, po_no, device1, device2, intf_dict_tb)
            if not reference_speed:
               for elm in links_list_1:
                  speed = device1_2_device2_dict['Links'][elm]['speed']
                  if not reference_speed.lower() == speed.lower():
                      if not re.search('auto', speed, re.IGNORECASE):
                         log.info ('\n All Links of PO %r between %r and %r are not of same speed\n', po_no, device1, device2)
                         pass_flag = 0
                         break

    # Check if same member links are not used in multiple Pos
    if same_pos_defined_flag and po_defined_flag:
        for po_no in device1_2_device2_dict['port-channels'].keys():
           links_list_1 = device1_2_device2_dict['port-channels'][po_no]['members']
           for elm in links_list_1:
              for po_no1 in device1_2_device2_dict['port-channels'].keys():
                 if po_no == po_no1:
                    continue
                 links_list_2 = device1_2_device2_dict['port-channels'][po_no1]['members']
                 for elm1 in links_list_2:
                    if elm1 == elm:
                        log.info ('\n %r and %r between %r and %r has same member links', po_no, po_no1, device1, device2)
                        return 0

    if not pass_flag:
       return 0
    #Check if physical interfaces are specified they are not specified in some otherlink
    #Check already specified Link is present in Testbed file
    #Check if physical interfaces are specified its speed is as per testbed file
    #If physical interface specified, check other end if its present check they are neighbors
    for elm in device1_2_device2_dict['Links'].keys():
        physical_intf_dev1 = device1_2_device2_dict['Links'][elm]['physical_interface']
        physical_intf_dev1_speed = device1_2_device2_dict['Links'][elm]['speed']
        physical_intf_dev2 = device2_2_device1_dict['Links'][elm]['physical_interface']
        physical_intf_dev2_speed = device2_2_device1_dict['Links'][elm]['speed']
        flag1 = 0
        flag2 = 0
        if not re.search('auto', physical_intf_dev1, re.IGNORECASE):
           flag1 = 1
           if not check_physicalintf_duplicate_in_topology(topo_dict, device1, device2):
               return 0
           if not check_physicalintf_present_in_testbed(physical_intf_dev1, device1, device1_tb_obj):
               return 0
           if not check_physicalintf_speed_in_testbed (device1, physical_intf_dev1, physical_intf_dev1_speed, device1_tb_obj):
               return 0
        if not re.search('auto', physical_intf_dev2, re.IGNORECASE):
           flag2 = 1
           if not check_physicalintf_duplicate_in_topology(topo_dict, device2, device1):
               return 0
           if not check_physicalintf_present_in_testbed(physical_intf_dev2, device2, device2_tb_obj):
               return 0
           if not check_physicalintf_speed_in_testbed (device2, physical_intf_dev2, physical_intf_dev2_speed, device2_tb_obj):
               return 0
        #Check they are peers in testbed file
        if flag1 and flag2:
           for intf in device1_tb_obj:
              if physical_intf_dev1.lower() == intf.name.lower():
                 remote_intf = intf.remote_interfaces.pop().name
                 if physical_intf_dev2.lower() != remote_intf.lower():
                    log.info('%r interface %r peer interface %r are not peers in testbed file', \
                         device1, physical_intf_dev1, physical_intf_dev2)
                    pass_flag = 0
    if not pass_flag:
       return 0

    ####### Now Compute for Physical Links
    # Check whether number of required Links present in testbed between devices
    no_of_links_required = len(device1_2_device2_dict['Links'].keys())
    if no_of_links_present < no_of_links_required:
       log.info ('Required number of Links between %r and %r are not present in testbed file', device1, device2)
       return 0
    #Now update topo dict for interface and peer interface if physical intf or speed is hardcode
    if not update_topo_dict_for_hard_coded_physical_intf_or_speed(topo_dict, device1, device2, intf_dict_tb):
       return 0
    if not update_topo_dict_for_hard_coded_physical_intf_or_speed(topo_dict, device2, device1, intf_dict_tb):
       return 0

    # First fill Po members with physical interface
    # check reference speed as non-auto and fill them first
    if po_defined_flag:
      for po_no in device1_2_device2_dict['port-channels'].keys():
        links_list_1 = device1_2_device2_dict['port-channels'][po_no]['members']
        reference_speed = get_po_member_speed (topo_dict, po_no, device1, device2, intf_dict_tb)
        if reference_speed:
           device1_2_device2_dict['port-channels'][po_no]['members_filled'] = 1
           device2_2_device1_dict['port-channels'][po_no]['members_filled'] = 1
           for link in links_list_1:
              device1_physical_intf =  device1_2_device2_dict['Links'][link]['physical_interface']
              if re.search('auto', device1_physical_intf, re.IGNORECASE):
                 filled = 0
                 for intf in intf_dict_tb[device1]['intf'].keys():
                    intf_remote = intf_dict_tb[device1]['intf_detail'][intf]['remote_int']
                    if reference_speed.lower() == intf_dict_tb[device1]['intf'][intf].lower():
                        device1_2_device2_dict['Links'][link]['physical_interface'] = intf
                        device2_2_device1_dict['Links'][link]['physical_interface'] = intf_remote
                        intf_dict_tb[device1]['intf'].pop(intf)
                        intf_dict_tb[device2]['intf'].pop(intf_remote)
                        filled = 1
                        break
                 if not filled:
                    log.info('Required number of links are not found for Po %r in Testbed for Po \
                        with speed %r', po_no, reference_speed)
                    return 0

    # Fill po members with reference speed as auto
    # Fill Po with highest number of member links first and least number of members at last
    # while filling Po, get speed with highest number of interfaces from testbed and fill.
    dict_of_pos = {}
    if po_defined_flag:
      for po_no in device1_2_device2_dict['port-channels'].keys():
        links_count = len(device1_2_device2_dict['port-channels'][po_no]['members'])
        if not 'members_filled' in device1_2_device2_dict['port-channels'][po_no]:
          dict_of_pos[po_no] = links_count
      val_sorted = sorted(dict_of_pos.values(), reverse=True)
    my_list1 = []
    po_list_count_high_2_low = []
    if po_defined_flag:
      for elm_frm_sorted in val_sorted:
        for po_no in dict_of_pos.keys():
          if elm_frm_sorted == dict_of_pos[po_no]:
            if not po_no in po_list_count_high_2_low:
               po_list_count_high_2_low.append(po_no)

    if po_defined_flag:
      for po_no in po_list_count_high_2_low:
        links_list_1 = device1_2_device2_dict['port-channels'][po_no]['members']
        if not 'members_filled' in device1_2_device2_dict['port-channels'][po_no]:
           device1_2_device2_dict['port-channels'][po_no]['members_filled'] = 1
           no_of_members = len(device1_2_device2_dict['port-channels'][po_no]['members'])
           (highest_key, highest_count) = get_highest_no_for_value_in_dict(intf_dict_tb[device1]['intf'])
           if highest_count < no_of_members:
              log.info('Po %r does not have %r no of links of same speed left in TB for %r refered as %r',\
                        po_no, no_of_members, intf_dict_tb[device1]['tb_name'], device1)
              return 0
           else:
              for link in links_list_1:
                 for intf in intf_dict_tb[device1]['intf'].keys():
                    intf_remote = intf_dict_tb[device1]['intf_detail'][intf]['remote_int']
                    intf_speed = intf_dict_tb[device1]['intf'][intf]
                    if highest_key == intf_speed:
                       device1_2_device2_dict['Links'][link]['physical_interface'] = intf
                       device2_2_device1_dict['Links'][link]['physical_interface'] = intf_remote
                       intf_dict_tb[device1]['intf'].pop(intf)
                       intf_dict_tb[device2]['intf'].pop(intf_remote)
                       break

    # Finally Update Links which are not part of PO and speed is auto
    for link in device1_2_device2_dict['Links'].keys():
       physical_intf =  device1_2_device2_dict['Links'][link]['physical_interface'].lower()
       if re.search('auto', physical_intf, re.IGNORECASE):
          filled = 0
          for intf in intf_dict_tb[device1]['intf'].keys():
             intf_remote = intf_dict_tb[device1]['intf_detail'][intf]['remote_int']
             device1_2_device2_dict['Links'][link]['physical_interface'] = intf
             device2_2_device1_dict['Links'][link]['physical_interface'] = intf_remote
             intf_dict_tb[device1]['intf'].pop(intf)
             intf_dict_tb[device2]['intf'].pop(intf_remote)
             filled = 1
             break
          if not filled:
             log.info('Not able to assign interface for link %r between %r and %r',\
                          link, device1, device2)
             return 0

    print_links_info(topo_dict, device1, device2, intf_dict_tb)
    return 1

def get_no_of_occurence_of_value_from_dict_as_dict(dict_ref):
    '''
    Takes key value as input
    returns key list of number of occurence of values
    '''
    my_list = dict_ref.values()
    myd = {}
    for elm in my_list:
       my_count = 0
       for elm1 in my_list:
          if elm == elm1:
             my_count += 1
       myd[elm] = my_count
    return myd

def get_highest_no_for_value_in_dict(dict_ref):
    my_list = dict_ref.values()
    myd = get_no_of_occurence_of_value_from_dict_as_dict(dict_ref)
    highest_count = 0
    highest_key = ""
    for elm in myd.keys():
       if myd[elm] > highest_count:
         highest_count = myd[elm]
         highest_key = elm
    return (highest_key, highest_count)

def get_po_with_highest_number_of_links_with_member_elm_speed_auto(topo_info, device1, device2, intf_dict_tb):
    device1_2_device2_dict = topo_info['devices'][device1]['Peer_Device'][device2]
    device2_2_device1_dict = topo_info['devices'][device2]['Peer_Device'][device1]
    max_links = 0
    max_po_name = ""
    for po_no in device1_2_device2_dict['port-channels'].keys():
       reference_speed = get_po_member_speed (topo_info, po_no, device1, device2, intf_dict_tb)
       if not reference_speed:
           no_of_links = len(device1_2_device2_dict['port-channels'][po_no]['members'])
           if no_of_links > max_links:
              max_links = no_of_links
              max_po_name = po_no
    return max_po_name

def print_links_info(topo_info, device1, device2,intf_dict_tb):
    device1_2_device2_dict = topo_info['devices'][device1]['Peer_Device'][device2]
    device2_2_device1_dict = topo_info['devices'][device2]['Peer_Device'][device1]
    for link in device1_2_device2_dict['Links'].keys():
       physical_int = device1_2_device2_dict['Links'][link]['physical_interface'].lower()
       remote_int = device2_2_device1_dict['Links'][link]['physical_interface'].lower()
       dev1_name = intf_dict_tb[device1]['tb_name']
       dev2_name = intf_dict_tb[device2]['tb_name']
       log.info('%r[%r] %r <----> %r %r[%r] <-- %r',dev1_name, device1,\
           physical_int, remote_int, dev2_name, device2,link)

def check_no_of_po_members_with_speed_in_testbed(topo_info, device1, device2, intf_dict_tb):
    device1_2_device2_dict = topo_info['devices'][device1]['Peer_Device'][device2]
    for po_no in device1_2_device2_dict['port-channels'].keys():
        links_list_1 = device1_2_device2_dict['port-channels'][po_no]['members']
        reference_speed = get_po_member_speed (topo_info, po_no, device1, device2, intf_dict_tb)
        if not reference_speed:
           continue
        #Get count of interfaces and pop elements having reference speed
        no_of_elms = len(links_list_1)
        for link in links_list_1:
           found = 0
           for intf in intf_dict_tb[device1]['intf'].keys():
              if reference_speed.lower() == intf_dict_tb[device1]['intf'][intf].lower():
                 intf_dict_tb[device1]['intf'].pop(intf)
                 found = 1
                 break
           if not found:
              log.info('Required number of links are not found for Po %r in Testbed for Po with speed %r', po_no, reference_speed)
              return 0
    return 1

def update_topo_dict_for_hard_coded_physical_intf_or_speed(topo_info, device1, device2, intf_dict_tb):
    device1_2_device2_dict = topo_info['devices'][device1]['Peer_Device'][device2]
    device2_2_device1_dict = topo_info['devices'][device2]['Peer_Device'][device1]
    for link in device1_2_device2_dict['Links'].keys():
       device1_physical_intf =  device1_2_device2_dict['Links'][link]['physical_interface'].lower()
       device2_physical_intf =  device2_2_device1_dict['Links'][link]['physical_interface'].lower()
       device1_physical_intf_speed =  device1_2_device2_dict['Links'][link]['speed'].lower()
       device2_physical_intf_speed =  device2_2_device1_dict['Links'][link]['speed'].lower()
       #If Physical interface is specified by user pop it from List and Fill Peer Link Physical interface
       if not re.search('auto', device1_physical_intf, re.IGNORECASE):
          if device1_physical_intf in intf_dict_tb[device1]['intf'].keys():
             intf_dict_tb[device1]['intf'].pop(device1_physical_intf)
          intf_remote = intf_dict_tb[device1]['intf_detail'][device1_physical_intf]['remote_int']
          if re.search('auto', device2_physical_intf, re.IGNORECASE):
             device2_2_device1_dict['Links'][link]['physical_interface'] = intf_remote
          if intf_remote in intf_dict_tb[device2]['intf'].keys():
             intf_dict_tb[device2]['intf'].pop(intf_remote)
       else:
          #if speed is there match one and assign it update peer also
          if not re.search('auto', device1_physical_intf_speed, re.IGNORECASE):
             filled = 0
             for intf1 in intf_dict_tb[device1]['intf'].keys():
                intf_remote = intf_dict_tb[device1]['intf_detail'][intf1]['remote_int']
                if device1_physical_intf_speed == intf_dict_tb[device1]['intf'][intf1]:
                   device1_2_device2_dict['Links'][link]['physical_interface'] = intf1
                   if intf1 in intf_dict_tb[device1]['intf'].keys():
                      intf_dict_tb[device1]['intf'].pop(intf1)
                   device2_2_device1_dict['Links'][link]['physical_interface'] = intf_remote
                   if intf_remote in intf_dict_tb[device2]['intf'].keys():
                      intf_dict_tb[device2]['intf'].pop(intf_remote)
                   filled = 1
                   break
             if not filled:
                sp = device1_physical_intf_speed
                dev1_name = intf_dict_tb[device1]['tb_name']
                dev2_name = intf_dict_tb[device2]['tb_name']
                log.info('Not able to find %r interface between %r and %r in testbed', sp, dev1_name, dev2_name)
                return 0

    return 1

def get_po_member_speed (topo_info, po_no, device1, device2, intf_dict_tb):
    device1_2_device2_dict = topo_info['devices'][device1]['Peer_Device'][device2]
    device2_2_device1_dict = topo_info['devices'][device2]['Peer_Device'][device1]
    links_list_1 = device1_2_device2_dict['port-channels'][po_no]['members']
    reference_speed = ""
    for elm in links_list_1:
        speed = device1_2_device2_dict['Links'][elm]['speed']
        if re.search('gig', speed, re.IGNORECASE):
           return speed
    for elm in links_list_1:
        speed = device2_2_device1_dict['Links'][elm]['speed']
        if re.search('gig', speed, re.IGNORECASE):
           return speed
    for elm in links_list_1:
        device1_physical_intf =  device1_2_device2_dict['Links'][elm]['physical_interface']
        if not re.search('auto', device1_physical_intf, re.IGNORECASE):
           return intf_dict_tb[device1]['intf_detail'][device1_physical_intf.lower()]['speed']
        device2_physical_intf =  device2_2_device1_dict['Links'][elm]['physical_interface']
        if not re.search('auto', device2_physical_intf, re.IGNORECASE):
           return intf_dict_tb[device2]['intf_detail'][device2_physical_intf.lower()]['speed']
    return reference_speed

def check_link_preset_in_neighbor_in_topo(topo_info, device1, device2):
    device1_2_device2_dict = topo_info['devices'][device1]['Peer_Device'][device2]
    device2_2_device1_dict = topo_info['devices'][device2]['Peer_Device'][device1]
    return_flag = 1
    for link in device1_2_device2_dict['Links'].keys():
       if not link in device2_2_device1_dict['Links'].keys():
          log.info ('\nLink %r of %r Connecting to %r is not defined\n', link, device1, device2)
          return_flag = 0
    return return_flag

def check_link_speed_as_neighbor_in_topo(topo_info, device1, device2):
    device1_2_device2_dict = topo_info['devices'][device1]['Peer_Device'][device2]
    device2_2_device1_dict = topo_info['devices'][device2]['Peer_Device'][device1]
    return_flag = 1
    for link in device1_2_device2_dict['Links'].keys():
        device1_link_speed = device1_2_device2_dict['Links'][link]['speed']
        device2_link_speed = device2_2_device1_dict['Links'][link]['speed']
        if not re.search('auto', device1_link_speed, re.IGNORECASE):
           if not re.search('auto', device2_link_speed, re.IGNORECASE):
              if not device1_link_speed.lower() == device2_link_speed.lower():
                 log.info ('\nLink %r between %r and %r are not of same speed\n', link, device1, device2)
                 return_flag = 0
    return return_flag

def check_physicalintf_speed_in_testbed (topo_device, physical_intf, physical_intf_speed, device_obj):
    if not re.search('auto', physical_intf_speed, re.IGNORECASE):
        for intf in device_obj:
            if physical_intf.lower() == intf.name.lower():
                if physical_intf_speed.lower() != intf.type.lower():
                    log.info('\n %r Intf %r speed specified in topololgy is not same as testbed device %r', topo_device,\
                          physical_intf, device_obj.name)
                    return 0
    return 1

def check_physicalintf_present_in_testbed (physical_intf, topo_device, device_obj):
    for intf in device_obj:
        if physical_intf.lower() == intf.name.lower():
          return 1
    log.info('%r is not there in testbed file for %r refered as %r', physical_intf, device_obj.name, topo_device)
    return 0

def get_cdp_neighbor (device_obj, intf):
    device_obj.transmit('show cdp neighbors interface ' + intf + '\n')
    device_obj.receive(r"# $", timeout=5)
    oput = device_obj.receive_buffer()
    neighbor = ""
    nei_int = ""
    if re.search('CDP Neighbor entry not found', oput, re.IGNORECASE):
       return (neighbor, nei_int)
    i = 0
    lines = oput.splitlines()
    flag = 0
    for line in lines:
       i += 1
       if re.search('Device-ID', line, re.IGNORECASE):
          flag = 1
          break
    if flag:
       line = lines[i]
    else:
       log.info('CDP failed for %r for interface %r', device_obj.name, intf)
       return (neighbor, nei_int)
    match = re.search(r'(.*)\(', line)
    if match:
       neighbor = match.group(1)
    i += 1
    line = lines[i]
    words = get_words_list_from_line(line)
    nei_int = words[len(words) -1]
    return (neighbor, nei_int)

def check_peering_links (topo_info, device1, device2, device1_obj, device2_obj):
    device1_2_device2_dict = topo_info['devices'][device1]['Peer_Device'][device2]
    device2_2_device1_dict = topo_info['devices'][device2]['Peer_Device'][device1]
    for link in device1_2_device2_dict['Links'].keys():
      local_intf = device1_2_device2_dict['Links'][link]['physical_interface']
      remote_intf = device2_2_device1_dict['Links'][link]['physical_interface']
      local_hostname = device1_obj.name
      remote_hostname = device2_obj.name
      (remote, remote_cdp_int) = get_cdp_neighbor(device1_obj, local_intf)
      match = re.search(r'{0}'.format(remote_hostname) , remote, re.IGNORECASE)
      if not match:
         log.info('%r interface %r is not connected to %r interface %r\n',\
                  device1, local_intf, device2, remote_intf)
         return 0
      remote_cdp_int = re.sub('[a-zA-Z]+', '', remote_cdp_int)
      remote_intf = re.sub('[a-zA-Z]+', '', remote_intf)
      match = re.search(r'{0}'.format(remote_intf) , remote_cdp_int, re.IGNORECASE)
      if not match:
         log.info('%r interface %r is not connected to %r interface %r\n',\
                  device1, local_intf, device2, remote_intf)
         return 0

    return 1

def get_all_device_intf_from_topo (topo_dict, device):
    all_intf_list = []
    device_dict = topo_dict['devices'][device]['Peer_Device']
    for peer_device in device_dict.keys():
        for link in device_dict[peer_device]['Links'].keys():
           all_intf_list.append(device_dict[peer_device]['Links'][link]['physical_interface'])
    return all_intf_list

def get_non_po_Links_from_topology (topo_info, device, remote_device):
    '''
    Get List of Links which are not part of Po
    '''
    device1_2_device2_dict = topo_info['devices'][device]['Peer_Device'][remote_device]
    device_links_dict = device1_2_device2_dict['Links']
    all_links_list = list(device_links_dict.keys())
    non_po_links_list = []
    if 'port-channels' in device1_2_device2_dict.keys():
      for elm in device_links_dict.keys():
        found = 0
        for po_no in device1_2_device2_dict['port-channels'].keys():
          links_list_1 = device1_2_device2_dict['port-channels'][po_no]['members']
          if elm in links_list_1:
            found = 1
            break
        if not found:
          non_po_links_list.append(elm)
    if non_po_links_list:
      return sorted(non_po_links_list)
    else:
      return sorted(all_links_list)

def check_physicalintf_duplicate_in_topology (topo_info, device, remote_device):
    device_links_dict = topo_info['devices'][device]['Peer_Device'][remote_device]['Links']
    all_links_dict = {}
    for elm in device_links_dict.keys():
       all_links_dict[elm] = device_links_dict[elm]['physical_interface']
    myd = get_no_of_occurence_of_value_from_dict_as_dict(all_links_dict)

    for elm in myd.keys():
      if not re.search('auto', elm, re.IGNORECASE):
        if myd[elm] > 1:
           log.info ('\n%r is used multiple times as link between %r and %r\n', elm , device, remote_device)
           return 0
    return 1
