#!/bin/env python
###################################################################
# Author: Manas Kumar Dash (mdash)
# This lib contain various library functions to configure devices
# Also some generic utility functions
###################################################################

import re
import time
import logging
import collections
import yaml
import copy
import os
import parsergen

from ats.log.utils import banner
from ats.async_ import pcall
from unicon.eal.dialogs import Dialog
from unicon.eal.dialogs import Statement

from common_lib.utility_lib import *
from common_lib.infra_lib import *

log = logging.getLogger(__name__)
log.setLevel(logging.DEBUG)

def create_mpls_tcam_config_string (device = '', double_wide_mpls = 1):
    conf_str = ''
    tcam_prof_name = 'sr_mpls_tcam_profile'
    switch_plat = get_switch_platform(device)
    if switch_plat == '9200-TOR':
       return conf_str
    if re.search(r'TH-TOR|TH2-TOR|T3-TOR', switch_plat, re.I):
        conf_str += 'hardware access-list tcam region vpc-convergence 0\n'
        conf_str += 'hardware access-list tcam region racl-lite 0\n'
        conf_str += 'hardware access-list tcam region l3qos-intra-lite 0\n'
        if double_wide_mpls:
          conf_str += 'hardware access-list tcam region mpls 512 double-wide\n'
        else:
          conf_str += 'hardware access-list tcam region mpls 512\n'
    else: 
        if switch_plat == 'TH-EOR':
           conf_str += 'hardware profile tcam resource template ' + tcam_prof_name + ' ref-template nfe2\n'
           conf_str += 'vpc-convergence 0\n'
           conf_str += 'racl-lite 0\n'
           conf_str += 'l3qos-intra-lite 0\n'
           conf_str += 'mpls 256\n'
           conf_str += 'hardware profile tcam resource service-template ' + tcam_prof_name + '\n'
        else :
           #conf_str += 'hardware access-list tcam region racl 512\n'
           #conf_str += 'hardware access-list tcam region vpc-convergence 0\n'
           conf_str += 'hardware access-list tcam region vacl 0\n'
           conf_str += 'hardware access-list tcam region racl 256\n'
           conf_str += 'hardware access-list tcam region vpc-convergence 0\n'
           if double_wide_mpls:
             conf_str += 'hardware access-list tcam region mpls 512 double-wide\n'
           else:
             conf_str += 'hardware access-list tcam region mpls 512\n'
    return conf_str

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

def get_ospf_segment_routing_sid (device):
   output = device.mgmt.execute('show ip ospf segment-routing sid-database')
   lines = output.splitlines()
   sid_db = {}
   start_flag = 0
   for line in lines:
       if start_flag:
          words = get_words_list_from_line(line)
          if len(words) > 1:
             sid_db[words[1]] = words[0]
       if re.search('SID.*Prefix.*Flags', line):
          start_flag = 1
   return sid_db
def get_isis_segment_routing_sid (device):
   output = device.mgmt.execute('show isis segment-routing sids')
   lines = output.splitlines()
   adj_sid = {}
   start_flag = 0
   for line in lines:
       if start_flag:
          words = get_words_list_from_line(line)
          adj_sid[words[1]] = words[0]
       if re.search('SID.*Prefix.*Flags', line):
          start_flag = 1
   return adj_sid

def get_ospf_nbr_status (device, vrf = 'default', intf_name = None, ip_ver = 'v4'):
   if intf_name is None:
      log.info('interface name has to be specified')
      return 0
   intf_name = re.sub(' +','',intf_name)
   intf_name = intf_name.strip()
   nbr_dict = {}
   if re.search('4', ip_ver):
      output = device.mgmt.execute('show ip ospf neighbors ' + intf_name)
   else:
      if re.search('6', ip_ver):
         output = device.mgmt.execute('show ip ospf neighbors ' + intf_name)
      else:
         log.info('Incorrect IP version specified')
         return nbr_dict
   lines = output.splitlines()
   found = 0
   for line in lines:
       if found:
          words = []
          words = get_words_list_from_line(line)
          if len(words) >= 5:
             nbr_dict['status'] = words[2]
       if re.search('Neighbor ID', line, re.I):
          found = 1
   return nbr_dict

def get_isis_adjacency_status (device, vrf = 'default', intf_name = None):
   if intf_name is None:
      log.info('interface name has to be specified')
      return 0
   intf_name = re.sub(' +','',intf_name)
   intf_name = intf_name.strip()
   output = device.mgmt.execute('show isis adjacency ' + intf_name + ' detail vrf ' + vrf)
   lines = output.splitlines()
   adj_dict = {}
   found = 0
   for line in lines:
       if found:
          if re.search('IPv4 Address', line):  
             words = get_words_list_from_line(line)
             adj_dict['v4_add'] = words[2]
          if re.search('IPv6 Address', line):  
             words = get_words_list_from_line(line)
             adj_dict['v6_add'] = words[2]
          match = re.search('IPv4 Adj-SID: (\d+)', line)  
          if match:
             adj_dict['v4_adj_sid'] = match.group(1)
       if re.search(intf_name, line, re.I):
          found = 1
          words = get_words_list_from_line(line)
          adj_dict['status'] = words[3] 
          adj_dict['label'] = words[2] 
       
   return adj_dict
    
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
      if re.search('Block.*Label-Range', line, re.I):
         found = 0
      if re.search('ADJ_SID:', line, re.I):
         found = 0
      if re.search('Local.*Out-Label.*Out-Interface', line, re.I):
         found = 0
      if found:
         if start_append:
            words = get_words_list_from_line(line)
            try:
               rowPos = int(words[0])
               label_list.append(words[0])
            except ValueError:
               #i = 1
               pass
         start_append = 1
      if re.search('In-Label.*VRF', line, re.I):
         found = 1
   return label_list
      
     
def get_vpn_label_stats (device, label, module = 1):
   stats = 0
   output = device.mgmt.execute('show forwarding mpls label ' + str(label) + ' stats module ' + str(module))
   lines = output.splitlines()
   found = 0
   for line in lines:
      if re.search('Input Pkts', line, re.I):
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
      match = re.search(r'Aggregate Labels', line, re.I)
      if match:
         if re.search('4', line, re.I):
            v4_line_no = i
         if re.search('6', line, re.I):
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
            if re.search('PUSH', line, re.I):
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
            if re.search('PUSH', line, re.I):
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

def bgp_neighbor_delete_readd (device, as_nu, neighbor_add):
   output = device.execute('show run bgp | sec ' + neighbor_add)
   lines = output.splitlines()
   conf_str = ''
   unconf_str = ''
   conf_str = 'router bgp ' + str(as_nu) + '\n'
   unconf_str = conf_str + 'no neighbor ' + neighbor_add + '\n'
   j = 0
   while j < len(lines):
       conf_str += lines[j] + '\n'
       j += 1
   device.configure(unconf_str)
   time.sleep(10)
   device.configure(conf_str)
   return 1

def get_bgp_vpn_neighbor_detail (device, vpn_type):
   if device.is_connected(alias = 'mgmt'):
      hdl = device.mgmt
   else:
     hdl = device
   if vpn_type == 'sr-evpn':
      oput = hdl.execute('show bgp l2vpn evpn summary')
   if vpn_type == 'vpnv4':
      oput = hdl.execute('show bgp vpnv4 unicast summary')
   if vpn_type == 'vpnv6':
      oput = hdl.execute('show bgp vpnv6 unicast summary')
   lines = oput.splitlines()
   flag = 0
   index_val = 1
   output = {}
   for line in lines:
      if line:
        if flag:
           output[index_val] = dict()
           words = get_words_list_from_line(line)
           output[index_val]['Neighbor'] = words[0]
           output[index_val]['V'] = words[1]
           output[index_val]['AS'] = words[2]
           output[index_val]['MsgRcvd'] = words[3]
           output[index_val]['MsgSent'] = words[4]
           output[index_val]['TblVer'] = words[5]
           output[index_val]['InQ'] = words[6]
           output[index_val]['OutQ'] = words[7]
           output[index_val]['Up/Down'] = words[8]
           output[index_val]['State/PfxRcd'] = words[9]
           index_val += 1
        if re.search('Neighbor.*V.*AS.*MsgRcvd.*MsgSent', line, re.I):
            flag = 1
   return output

def get_epe_label (device_hdl = '', node_ip = '', pset_id = ''):
    if node_ip:
       command_line = 'show bgp internal epe | i ' + node_ip
    else:
       command_line = 'show bgp internal epe | i \"Set  ' + pset_id + '\"'
    oput = device_hdl.execute(command_line)
    lines = oput.splitlines()
    found = 0
    for line1 in lines:
       if re.search(r'Set|Node', line1, re.I):
          words_list = get_words_list_from_line(line1)
          label = words_list[len(words_list) - 1]
          found = 1
          break
    if found:
      return label
    else:
      return 0

def get_mpls_labels_dict (device):
   if device.is_connected(alias = 'mgmt'):
      hdl = device.mgmt
   else:
     hdl = device
   oput = hdl.execute("show mpls switching")
   lines = oput.splitlines()
   start_indx = 0
   for line in lines:
      if re.search('VRF default', line, re.I):
         break
      start_indx += 1 
   lines = oput.splitlines()
   index1 = start_indx + 1
   pfxcount = 1
   pfx_dict = {}
   pfx_count = 0
   while index1 < len(lines):
      if not lines[index1]:
         break
      if re.search(r'In-Label', lines[index1], re.I):
         break
      entry_lst = get_words_list_from_line(lines[index1])
      if re.search(r'Pop Label', lines[index1], re.I):
         pfx_ip = entry_lst[3]
         nhop = entry_lst[5]
         local_lbl = entry_lst[0]
         out_lbl = 0
      else:
         pfx_ip = entry_lst[2]
         nhop = entry_lst[4]
         local_lbl = entry_lst[0]
         out_lbl = entry_lst[1]
      index1 += 1
      pfx_found = 0
      for each_pfx_cnt in pfx_dict.keys():
         if pfx_dict[each_pfx_cnt]['pfx_ip'] == pfx_ip:
            pfx_found = 1
            pfx_index = each_pfx_cnt
            break
      if pfx_found:
          nh_count += 1
      else:
          nh_count = 1
          pfx_count += 1
          pfx_dict[pfx_count] = dict()
          pfx_dict[pfx_count]['pfx_ip'] = pfx_ip
          pfx_dict[pfx_count]['nexthop'] = dict()
      pfx_dict[pfx_count]['nexthop'][nh_count] = dict()
      pfx_dict[pfx_count]['nexthop'][nh_count]['ip'] = nhop
      pfx_dict[pfx_count]['nexthop'][nh_count]['locallabel'] = local_lbl
      pfx_dict[pfx_count]['nexthop'][nh_count]['outlabel'] = out_lbl
   return pfx_dict

def get_bgp_lu_labels_dict (device):
   if device.is_connected(alias = 'mgmt'):
      hdl = device.mgmt
   else:
     hdl = device
   oput = hdl.execute("show bgp ipv4 labeled-unicast labels")
   lines = oput.splitlines()
   start_indx = 0
   for line in lines:
      if re.search('Network.* Next Hop.*In label', line, re.I):
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
      match = re.search(r'(\d+.\d+.\d+.\d+/\d+)', entry_lst[0] , re.I)
      if match:
         if re.search(r'(0.0.0.0)', entry_lst[1] , re.I):
            continue
         pfx_dict[pfx_count] = dict()
         pfx_dict[pfx_count]['pfx_ip'] = match.group(1) 
         match1 = re.search(r'(\d+)/(\d+)', entry_lst[2], re.I)
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
               match = re.search(r'(\d+.\d+.\d+.\d+/\d+)', entry_lst[0] , re.I)
               if match:
                  break
               if re.search(r'(0.0.0.0)', entry_lst[1] , re.I):
                  break
               match2 = re.search(r'(\d+)/(\d+)', entry_lst[2], re.I)
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

def create_po (device_handle, po_nu, port_list):
   conf_str = ""
   for port1 in port_list:
     conf_str += 'default interface ' + port1 + '\n' 
     conf_str += 'interface ' + port1 + '\n'
     conf_str += 'no shut \n'
     conf_str += 'channel-group ' + str(po_nu) + ' mode active\n'
   return conf_str

def create_isis_id (isis_id = 1, isis_net = '', vrf = '', isis_ckt_level = '', ip_ver = 'v4', v4_sr = 0,\
                    static_redist_route_map = '',  max_paths = 64, distribute_link_state = ''):
   config_str = ''
   if re.search('v4', ip_ver, re.I):
      config_str += 'feature isis\n'
      config_str += 'router isis ' + str(isis_id) + '\n'
   if vrf:
      config_str += 'vrf ' + vrf + '\n'
   config_str += 'net ' + isis_net + '\n'
   if isis_ckt_level:
      config_str += 'is-type ' + isis_ckt_level + '\n'
   if distribute_link_state:
      config_str += 'distribute link-state\n'
   config_str += 'address-family ipv4 unicast' + '\n'
   config_str += 'maximum-paths ' + str(max_paths) + '\n'
   if v4_sr:
      config_str += 'segment-routing mpls\n'
   if static_redist_route_map:
      config_str += 'redistribute static route-map ' + static_redist_route_map +'\n'
      
   return config_str

def create_ospf_id (ospf_id = 1, router_id = '', ip_ver = 'v4', v4_sr = 0, max_paths = 64):
   config_str = ''
   if re.search('v4', ip_ver, re.I):
      config_str += 'feature ospf\n'
      config_str += 'router ospf ' + str(ospf_id) + '\n'
      config_str += 'maximum-paths ' + str(max_paths) + '\n'
   if router_id:
      config_str += 'router-id ' + router_id + '\n'
   if v4_sr:
      config_str += 'segment-routing mpls\n'
   if re.search('v6', ip_ver, re.I):
      config_str += 'feature ospfv3\n'
      config_str += 'router ospfv3 ' + str(ospf_id) + '\n'
      config_str += 'address-family ipv6 unicast' + '\n'
      config_str += 'maximum-paths ' + str(max_paths) + '\n'
      config_str += 'exit\n'
   if router_id:
      config_str += 'router-id ' + router_id + '\n'
   return config_str

def create_l3_intf_config_string (main_inf = '', sub_intf_nu = '', ipv4_add = '', ipv6_add = '', \
                                  ipv4_mask = '', ipv6_mask = '', vrf_name = '', dot1q_vlan = '',\
                                  mpls_fw = '', mtu = 9216, ospf_id = '', ospf_area = '', ospf_cost = 0,\
                                  ipv6_ospf = 0, isis_id = '', isis_ckt_level = '', isis_metric = 1, \
                                  ospf_hello = 10, ospf_dead = 40, ipv6_isis = 0, isis_nwk_p2_p = ''):
   config_str = ''
   if not sub_intf_nu: 
      if not re.search(r'vlan|loop', main_inf, re.I):
         if not re.search(r'po', main_inf, re.I):
           config_str += 'default interface ' + main_inf + '\n' 
         config_str += 'interface ' + main_inf + '\n'
         config_str += 'no switchport\n'
      else:
         config_str += 'interface ' + main_inf + '\n'
      if mpls_fw:
         config_str += 'mpls ip forwarding\n'
   else:
      config_str += 'interface ' + main_inf + '\n'
      config_str += 'no switchport\n'
      config_str += 'no shut\n'
      config_str += 'interface ' + main_inf + '.' + str(sub_intf_nu) + '\n'
      config_str += 'encapsulation dot1q ' + str(dot1q_vlan) + '\n'
   if vrf_name:
      config_str += 'vrf member ' + str(vrf_name) + '\n'
   if mtu > 1500:
      if not re.search(r'loop', main_inf, re.I):
         config_str += 'mtu 9216 \n'
   if ipv4_add:
      if ipv4_mask: 
        if re.search(r'/', str(ipv4_mask)):
           config_str += 'ip address ' + ipv4_add + ipv4_mask + '\n'
        else:
           config_str += 'ip address ' + ipv4_add + ' ' + ipv4_mask + '\n'
      else:
        config_str += 'ip address ' + ipv4_add + '/24\n'
   if ipv6_add:
      if ipv6_mask: 
        if re.search(r'/', str(ipv6_mask)):
           config_str += 'ipv6 address ' + ipv6_add + ipv6_mask + '\n'
        else:
           config_str += 'ipv6 address ' + ipv6_add + ' ' + ipv6_mask + '\n'
      else:
        config_str += 'ipv6 address ' + ipv6_add + '/64\n'
   if ospf_id:
      if str(ospf_area): 
        config_str += 'ip router ospf ' + str(ospf_id) + ' area ' + str(ospf_area) + '\n'
      else:
        log.info('OSPF Area id is not specified, unable to configure OSPF on interface')
        return ''
      if ipv6_ospf:
        if str(ospf_area): 
          config_str += 'ipv6 router ospfv3 ' + str(ospf_id) + ' area ' + str(ospf_area) + '\n'
        else:
          log.info('OSPF Area id is not specified, unable to configure OSPFV3 on interface')
          return ''
      if ospf_cost: 
          config_str += 'ip ospf cost ' + str(ospf_cost) + '\n'
      if ospf_hello: 
          config_str += 'ip ospf hello ' + str(ospf_hello) + '\n'
      if ospf_dead: 
          config_str += 'ip ospf dead ' + str(ospf_dead) + '\n'
   if isis_id:
      config_str += 'ip router isis ' + str(isis_id) + '\n'
      config_str += 'isis circuit-type ' + isis_ckt_level + '\n'
      config_str += 'isis metric ' + str(isis_metric) + ' ' + isis_ckt_level + '\n'
      if isis_nwk_p2_p:
         config_str += 'isis network point-to-point\n'
      if ipv6_isis:
         config_str += 'ipv6 router isis ' + str(isis_id) + '\n'
      
   config_str += 'no shut \n'
   return config_str

def create_vpn_vrf_config_string (vrf_name = '', rd_name = 'auto', rt_import_list = '', rt_export_list = '', afi_v4 = 1, \
                                  afi_v6 = 1, vpn_type = 'sr-evpn'):
   config_str = ""
   config_str += 'vrf context ' + vrf_name + '\n'
   config_str += 'rd ' + str(rd_name) + '\n'
   if afi_v4:
      config_str += 'address-family ipv4 unicast' + '\n'
      for rt_import in rt_import_list: 
         config_str += 'route-target import ' + rt_import  + '\n'
         if vpn_type == 'sr-evpn':
            config_str += 'route-target import ' + rt_import  + ' evpn\n'
      for rt_export in rt_export_list: 
         config_str += 'route-target export ' + rt_export  + '\n'
         if vpn_type == 'sr-evpn':
            config_str += 'route-target export ' + rt_export  + ' evpn\n'
   if afi_v6:
      config_str += 'address-family ipv6 unicast' + '\n'
      for rt_import in rt_import_list: 
         config_str += 'route-target import ' + rt_import  + '\n'
         if vpn_type == 'sr-evpn':
           config_str += 'route-target import ' + rt_import  + ' evpn\n'
      for rt_export in rt_export_list: 
         config_str += 'route-target export ' + rt_export  + '\n'
         if vpn_type == 'sr-evpn':
            config_str += 'route-target export ' + rt_export  + ' evpn\n'    
   return config_str

def create_bgp_nbr_conf_string (vrf_name = '', vrf_afi_list = ['ipv4 unicast'], vrf_afi_adv_l2vpn = '',\
                                nbr_address = '', nbr_as = '', nbr_afi_list = ['ipv4 unicast'],\
                                nbr_as_rr_client = '', if_next_hop_self = '',ebgp_multihop = '',\
                                update_src_int = '', l2vpn_encap = '', in_rmap = '', out_rmap = '', \
                                enable_bfd = '', epe_pset_str = '', disable_peer_as_check = 0, \
                                allowas_in = 0, send_community = 0 , if_next_hop_self_all = 0, dci_reoriginate = 0):
   '''
    afi = should be specified as "ipv4 unicast" or "ipv4 labeled-unicast" and so on
   '''
   config_str = ""
   if vrf_name:
     config_str += 'vrf ' + str(vrf_name) + '\n'
     for afi in vrf_afi_list:
        if not re.search(r'v4|v6', afi, re.I):
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
     update_src_int = re.sub('_','-',update_src_int)
     config_str += 'update-source ' + str(update_src_int) + '\n'
   if epe_pset_str:
     config_str += 'egress-engineering peer-set ' + epe_pset_str + '\n'

   for afi in nbr_afi_list:
      config_str += 'address-family ' + str(afi) + '\n'
      if dci_reoriginate:
         if re.search(r'l2vpn', afi, re.I):
            config_str += 'import vpn unicast reoriginate\n'
         if re.search(r'vpnv4', afi, re.I):
            config_str += 'import l2vpn evpn reoriginate\n'
         if re.search(r'vpnv6', afi, re.I):
            config_str += 'import l2vpn evpn reoriginate\n'
      if nbr_as_rr_client:
        config_str += 'route-reflector-client\n'
      if if_next_hop_self:
        config_str += 'next-hop-self\n'
      if if_next_hop_self_all:
        config_str += 'next-hop-self all\n'
      if re.search(r'l2vpn|vpnv4|vpnv6', afi, re.I):
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

def check_all_ports_up_in_po (device, po_nu, port_list):
    oput = device.execute('show port-c database interface port-channel ' + po_nu, timeout=240)
    if re.search('Invalid command', oput, re.I):
       return 0
    port_list_cpy = list(port_list)
    lines = oput.splitlines() 
    for line in lines:
      if re.search('Ethernet', line, re.I):
         if re.search('\[up\]', line, re.I):
            match = re.search('(Ethernet.* )', line, re.I)
            try:
               port_list_cpy.remove(match.group(0))
            except:
               pass
    if port_list_cpy:     
      return 0
    return 1

def interface_flap (device , nu_of_times_to_flap = 3, intf_list = [], sleep_time_after_shut = 10, \
                             sleep_time_after_no_shut = 20):
    command_list_shut = ''
    command_list_noshut = ''
    for intf in intf_list:
       command_list_shut += 'interface  '+ intf + '\n'
       command_list_shut += 'shut \n'
       command_list_noshut += 'interface  '+ intf + '\n'
       command_list_noshut += 'no shut \n'
    i = 1
    if command_list_shut:
      while i <= nu_of_times_to_flap:
        i += 1
        device.configure(command_list_shut, timeout = 60)
        time.sleep(sleep_time_after_shut)
        device.configure(command_list_noshut, timeout = 60)
        time.sleep(sleep_time_after_no_shut)
    return 1

def loopbk_int_flap (device , nu_of_times_to_flap = 3, loopbk_intf_list = [], sleep_time_after_shut = 10,
                     sleep_time_after_no_shut = 30):
    if not len(loopbk_intf_list):
       oput = device.execute("show ip interface brief | i 'Lo'")
       lines = oput.splitlines()
       for line in lines:
          match = re.search(r'(Lo\d+)', line)
          if match:
             loopbk_intf_list.append(match.group(1))
    interface_flap(device, nu_of_times_to_flap = nu_of_times_to_flap, intf_list = loopbk_intf_list,\
                   sleep_time_after_shut = sleep_time_after_shut, \
                   sleep_time_after_no_shut = sleep_time_after_no_shut) 
    return 1

def get_bgp_as_nu (device):
    oput = device.execute("show run bgp | i 'router bgp'")
    match = re.search(r'router bgp (\d+)', oput)
    if match:
       as_nu = match.group(1)
    else:
       as_nu = 0
    return as_nu

def bgp_nbr_flap (device , vrf_name = 'default', nu_of_times_to_flap = 3, nbr_list = [], \
                        sleep_time_after_shut = 10, sleep_time_after_no_shut = 30):

   nbr_dict = get_bgp_nbr_session_status(device,  vrf = vrf_name)
   as_nu = get_bgp_as_nu(device)
   if as_nu:
      command_list_shut = 'router bgp ' + as_nu + '\n'
      command_list_noshut = 'router bgp ' + as_nu + '\n'
      j = 1
      if not len(nbr_list):
        for nbr_add in get_bgp_nbr_session_status(device, vrf = vrf_name):
          nbr_list.append(nbr_add)
      for nbr_add in nbr_list:
        if not re.search('default', vrf_name, re.I):
           command_list_shut += 'vrf ' + vrf_name + '\n'
        command_list_shut += 'neighbor ' + nbr_add + '\n'
        command_list_noshut += 'neighbor ' + nbr_add + '\n'
        command_list_shut += 'shut \n'
        command_list_noshut += 'no shut \n'
      i = 1
      while i <= nu_of_times_to_flap:
        i += 1
        device.configure(command_list_shut, timeout = 60)
        time.sleep(sleep_time_after_shut)
        device.configure(command_list_noshut, timeout = 60)
        time.sleep(sleep_time_after_no_shut)
      return 1
   else:
      return 0

def get_isis_id (device, interface = '', ip_ver = 4):
   output = device.mgmt.execute('show run interface ' + interface)
   if re.search('4', str(ip_ver), re.I):
      match = re.search(r'ip router isis (\d+)', output)
      if match:
         return match.group(1)
      else:
         return C0(0, 0)
   if re.search('6', str(ip_ver), re.I):
      match = re.search(r'ipv6 router isis (\d+)', output)
      if match:
         return match.group(1)
      else:
         return 0
      
def get_ospf_id_n_area (device, interface = '', ip_ver = 4):
   output = device.mgmt.execute('show run interface ' + interface)
   if re.search('4', str(ip_ver), re.I):
      match = re.search(r'ip router ospf (\d+) area (\d+)', output)
      if match:
         return (match.group(1), match.group(2))
      else:
         return (0, 0)
   if re.search('6', str(ip_ver), re.I):
      match = re.search(r'ipv6 router ospfv3 (\d+) area (\d+)', output)
      if match:
         return (match.group(1), match.group(2))
      else:
         return (0, 0)
      
def interface_protocol_flap (device , nu_of_times_to_flap = 3, intf_list = [], sleep_time_after_shut = 10, \
                             sleep_time_after_no_shut = 20, proto_name = 'ospf' , ip_ver = '4'):
    command_list_shut = ''
    command_list_noshut = ''
    for intf in intf_list:
       command_list_shut += 'interface  '+ intf + '\n'
       command_list_noshut += 'interface  '+ intf + '\n'
       if re.search('4', str(ip_ver), re.I):
          if re.search('ospf', proto_name, re.I):
             (id, area) = get_ospf_id_n_area (device, interface = intf, ip_ver = 4)
             if not id:
                return 0
             command_list_shut += 'no ip router ospf ' + str(id) + ' area ' + str(area) + '\n'
             command_list_noshut += 'ip router ospf ' + str(id) + ' area ' + str(area) + '\n'
          if re.search('isis', proto_name, re.I):
             id = get_isis_id (device, interface = intf, ip_ver = 4)
             if not id:
                return 0
             command_list_shut += 'no ip router isis ' + str(id) + '\n'
             command_list_noshut += 'ip router isis ' + str(id) + '\n'
       if re.search('6', str(ip_ver), re.I):
          if re.search('ospf', proto_name, re.I):
             (id, area) = get_ospf_id_n_area (device, interface = intf, ip_ver = 6)
             if not id:
                return 0
             command_list_shut += 'no ipv6 router ospfv3 ' + str(id) + ' area ' + str(area) + '\n'
             command_list_noshut += 'ipv6 router ospfv3 ' + str(id) + ' area ' + str(area) + '\n'
          if re.search('isis', proto_name, re.I):
             id = get_isis_id (device, interface = intf, ip_ver = 6)
             if not id:
                return 0
             command_list_shut += 'no ipv6 router isis ' + str(id) + '\n'
             command_list_noshut += 'ipv6 router isis ' + str(id) + '\n'
    i = 1
    while i <= nu_of_times_to_flap:
      i += 1
      device.configure(command_list_shut, timeout = 60)
      time.sleep(sleep_time_after_shut)
      device.configure(command_list_noshut, timeout = 60)
      time.sleep(sleep_time_after_no_shut)
    return 1

def get_interface_counters (device, interface_nu):
   output = device.execute('show interface ' + interface_nu + ' counters | no')
   stats_dict = {}
   if re.search('Invalid range', output, re.I):
      log.info('Invalid interface %r is specified', interface_nu)
      return stats_dict 
   lines = output.splitlines()
   i = 0
   while i < len(lines):
     if re.search('InUcastPkts', lines[i], re.I):
        line = lines[i + 2]
        i += 1
        words = get_words_list_from_line(line)
        stats_dict['InUcastPkts'] = words[2]
     if re.search('InBcastPkts', lines[i], re.I):
        line = lines[i + 2]
        i += 1
        words = get_words_list_from_line(line)
        stats_dict['InBcastPkts'] = words[2]
     if re.search('OutUcastPkts', lines[i], re.I):
        line = lines[i + 2]
        i += 1
        words = get_words_list_from_line(line)
        stats_dict['OutUcastPkts'] = words[2]
     if re.search('OutBcastPkts', lines[i], re.I):
        line = lines[i + 2]
        i += 1
        words = get_words_list_from_line(line)
        stats_dict['OutBcastPkts'] = words[2]
     i += 1
   return stats_dict

def bgp_neighbor_del_readd (device, as_nu, nbr_ip, sleep_time_after_del = 10, sleep_time_after_add = 20, vrf_name = 'default'):
    output = device.mgmt.execute('show run bgp | sec ' + nbr_ip)
    lines = output.splitlines()
    conf_str = ''
    unconf_str = ''
    conf_str = 'router bgp ' + str(as_nu) + '\n'
    if not re.search('default', vrf_name, re.I):
      conf_str = conf_str + 'vrf ' + vrf_name + '\n'
    unconf_str = conf_str + 'no neighbor ' + nbr_ip + '\n'
    j = 0
    while j < len(lines):
        conf_str += lines[j] + '\n'
        j += 1
    device.mgmt.configure(unconf_str)
    time.sleep(sleep_time_after_del)
    device.mgmt.configure(conf_str)
    time.sleep(sleep_time_after_add)
    return 1 

def get_sap_recv_q_val (device, sap_name):
    output = device.mgmt.execute('show system internal mts buffers summary')
    lines = output.splitlines()
    sap_recv_q = 0
    for line in lines:
       if re.search(r'{0}'.format(sap_name), line, re.I):
          words = get_words_list_from_line(line)
          sap_recv_q = words[2]
          break
    return sap_recv_q

def get_vpc_config_str(domain_id = '', auto_recovery = '' , auto_recovery_reload_delay = '', delay_restore = '', \
                       delay_restore_interface_vlan = '' , delay_restore_orphan_port = '', \
                       dual_active_exclude_interface_vlan = [], fast_convergence = '', \
                       graceful_consistency_check = '', ip_arp_sync = '' , ipv6_nd_sync = '', \
                       layer3_peer_router = '' , layer3_peer_router_syslog = '', layer3_peer_router_syslog_interval = '', \
                       mac_add_bpdu_version_source = '' , peer_gateway = '' , peer_gateway_exclude_vlan = '', \
                       peer_keepalive_params = {} , peer_switch = '' , role_priority = '', \
                       system_mac = '', system_priority = '', track_object = ''):
    config_str = ''
    config_str += 'feature vpc ' + '\n'
    if str(domain_id):
        config_str += 'vpc domain ' + str(domain_id) + '\n'
    else:
        log.info('Vpc domain Id is not specified. Unable to configure VPC .. Exiting .. ')
        return ''
    if str(auto_recovery):
        config_str += 'auto-recovery ' + '\n'
    if str(auto_recovery_reload_delay):
        if int(auto_recovery_reload_delay) >= 60 :
            config_str += 'auto-recovery reload-delay ' + str(auto_recovery_reload_delay) + '\n'
        else:
            log.info('Invalid Value of auto-recovery reload-delay is specified . proceding without configuring auto-recovery-reload-delay')
    if str(delay_restore):
        if int(delay_restore) >= 60 :
            config_str += 'delay restore ' + str(delay_restore) + '\n'
        else:
            log.info('Invalid Value of delay_restore is specified . proceeding without configuring delay restore')
    if str(delay_restore_interface_vlan):
        if int(delay_restore_interface_vlan) >= 60 :
            config_str += 'delay restore interface-vlan ' + str(delay_restore_interface_vlan) + '\n'
        else:
            log.info('Invalid Value of delay_restore interface-vlan is specified . proceeding without configuring delay restore interface-vlan config')
    if str(delay_restore_orphan_port):
        if int(delay_restore_orphan_port) >= 60 :
            config_str += 'delay restore orphan-port ' + str(delay_restore_orphan_port) + '\n'
        else:
            log.info('Invalid Value of delay_restore orphan-port is specified . proceeding without configuring delay restore orphan-port config')
    if dual_active_exclude_interface_vlan:
        print('The value of dual_active_exclude_interface_vlan is : ', dual_active_exclude_interface_vlan)
        vlan_string = expand_list_into_string(dual_active_exclude_interface_vlan)
        config_str += 'dual-active excluded interface-vlan ' + vlan_string + '\n'
    if str(graceful_consistency_check):
        config_str += 'graceful consistency-check ' + '\n'
    if str(ip_arp_sync):
        config_str += 'ip arp synchronize ' + '\n'
    if str(ipv6_nd_sync):
        config_str += 'ipv6 nd synchronize ' + '\n'
    if str(layer3_peer_router):
        config_str += 'layer3 peer-router ' + '\n'
    if str(layer3_peer_router_syslog):
        config_str += 'layer3 peer-router syslog ' + '\n'
    if str(layer3_peer_router_syslog_interval):
        if int(layer3_peer_router_syslog_interval) >= 60 :
            config_str += 'auto-recovery reload-delay ' + str(layer3_peer_router_syslog_interval) + '\n'
        else:
            log.info('Invalid Value of layer3 peer-router syslog interval is specified . proceeding without configuring layer3 peer-router syslog interval')
    if str(mac_add_bpdu_version_source):
        config_str += 'mac-address bpdu source version 2 ' + '\n'
    if str(peer_gateway):
        config_str += 'peer-gateway ' + '\n'
    if peer_gateway_exclude_vlan:
        vlan_string = expand_list_into_string(peer_gateway_exclude_vlan)
        config_str += 'peer-gateway exclude-vlan ' + vlan_string + '\n' 
    if  peer_keepalive_params:
        print('The value of peer_keepalive_params is : ', peer_keepalive_params)
        peer_keepalive_cfg_str = ''
        if peer_keepalive_params['destination']:
            peer_keepalive_cfg_str+= 'peer-keepalive destination ' + peer_keepalive_params['destination']
        else:
            log.info('peer-keepalive destination is not specified. VPC Configuration is incomplete. Exiting')
            return ''
        if peer_keepalive_params['source']:
            peer_keepalive_cfg_str+= ' source ' + peer_keepalive_params['source']
        else:
            log.info('peer-keepalive source is not specified. VPC Configuration is incomplete. Exiting')
            return ''
        if peer_keepalive_params['vrf']:
            peer_keepalive_cfg_str+=  ' vrf ' + peer_keepalive_params['vrf']
        if not peer_keepalive_params['vrf']:
            peer_keepalive_cfg_str+=  ' vrf management \n'
        config_str += peer_keepalive_cfg_str + '\n'
    if str(peer_switch):
        config_str += 'peer-switch ' + '\n'
    if str(role_priority):
        config_str += 'role priority ' + role_priority +  '\n'
    if str(system_mac):
        config_str += 'system-mac ' + system_mac +  '\n'
    if str(system_priority):
        config_str += 'system-priority ' + system_priority +  '\n'
    if str(track_object):
        config_str += 'track-object ' + track_object +  '\n'

    return config_str

def create_l2_intf_config_string (main_inf = '', switchport = '', switchport_mode = '', switchport_allowed_vlan = [], \
                                  switchport_allowed_vlan_add = '', swithcport_allowed_vlan_remove = '', \
                                  switchport_allowed_vlan_all = '' , switchport_allowed_vlan_except = '',\
                                  switchport_access_vlan = '', mut = '', load_interval_counter_1 = 30,\
                                  load_interval_counter_2 = 60, load_interval_counter_3 = 300, vpc = '', \
                                  mtu = 9100, channel_group = '', vpc_peerlink = ''\
                                  ):

   config_str = ''
   if switchport:
       config_str += 'interface ' + main_inf + '\n'
       config_str += 'switchport' + '\n'
   if switchport_mode == 'access':
       config_str+= 'switchport mode access ' + '\n'
       if switchport_access_vlan:
           config_str+= 'switchport access vlan ' + switchport_access_vlan + '\n'
       else:
           config_str+= 'switchport access vlan 1'
           log.info('Access vlan is not configured. Proceeding with vlan 1')
   if switchport_mode == 'dot1q-tunnel':
       config_str+= 'switchport mode dot1q-tunnel ' + '\n'
   if switchport_mode == 'fex-fabric':
       config_str+= 'switchport mode dot1q-tunnel ' + '\n'
   if switchport_mode == 'trunk':
       config_str+= 'switchport mode trunk ' + '\n'
       if switchport_allowed_vlan:
           config_str += 'switchport trunk allowed vlan ' + expand_list_with_ranges(switchport_allowed_vlan) + '\n'
   if mtu > 1500:
       config_str += 'mtu ' + str(mtu) + '\n'
   if load_interval_counter_1 >= 5:
       config_str += 'load-interval counter 1 ' + str(load_interval_counter_1) + '\n'
   if load_interval_counter_2 >= 5:
       config_str += 'load-interval counter 2 ' + str(load_interval_counter_2) + '\n'
   if load_interval_counter_3 >= 5:
       config_str += 'load-interval counter 3 ' + str(load_interval_counter_3) + '\n'
   if channel_group:
       config_str += 'channel-group ' + str(channel_group) + ' force mode active ' + '\n'
   if vpc:
       config_str += 'vpc ' + str(vpc) + '\n'
   if vpc_peerlink:
       config_str += 'vpc peer-link ' + '\n'

   config_str += 'no shut ' + '\n'

   return config_str
