#!/bin/env python
###################################################################
# Author: Manas Kumar Dash (mdash)
# This lib contain various library functions for finding topology
# as per topology_yaml file
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
import parsergen
import pdb


from ats.log.utils import banner
from ats.async_ import pcall

log = logging.getLogger(__name__)
log.setLevel(logging.DEBUG)
ch = logging.StreamHandler()
log.addHandler(ch)

def find_Connecting_interfaces(topo_dict = "", device1 = "", device2 = "", device1_tb_obj = "", \
                               device2_tb_obj = "", print_fail = 1):
    '''
    Keys are "type", "node_name", "platform", "if_dut", "peer_device", "nu_of_links"
             "links", "port_channels", "members", "speed", "physical_interface"
    devices:
     PE1:
        node_name : "node17" or "auto select"
        platform : "T2-9300-TOR" or "auto select"
        type : 'switch' or 'TGN'
        if_dut : 1
        peer_device:
          P1:
            nu_of_links: 4
            links:
            port_channels:
              port_channel 10:
                members:  ['link_3', 'link_4']
          CE1:
            nu_of_links: 3
            links:
              link_1: {physical_interface: "auto select", speed: "auto select"}
          P2:
            links:
              link_1: 
    '''

    pass_flag = 1
    used_interfaces = []
    device1_2_device2_dict = topo_dict['devices'][device1]['peer_device'][device2]
    device2_2_device1_dict = topo_dict['devices'][device2]['peer_device'][device1]

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
           intf_type = intf.speed.lower()
           intf_remote = intf.remote_interfaces.pop().name.lower()
           intf_remote_speed = intf.remote_interfaces.pop().speed.lower()
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
           if not intf.speed.lower() == intf.remote_interfaces.pop().speed.lower():
              if print_fail:
                log.info('\nInterface %r of %r & Interface %r of %r are in same Link but of different speed in testbed file\n', \
                          intf.name, device1_tb_obj.name, intf.remote_interfaces.pop().name, device2_tb_obj.name )
              return 0 
    intf_dict_tb['no_of_links_defined'] = no_of_links_present

    flag = 0
    #Check whether links defined in device1 exists in device2
    if not check_link_preset_in_neighbor_in_topo(topo_dict, device1, device2, print_fail):
        pass_flag = 0
        flag = 1
    #Check whether links defined in device2 exists in device1
    if not check_link_preset_in_neighbor_in_topo(topo_dict, device2, device1, print_fail):
        pass_flag = 0
        flag = 1
    #Check whether Link Speed is same in peer device
    if flag:
       if not check_link_speed_as_neighbor_in_topo(topo_dict, device1, device2, print_fail):
           pass_flag = 0

    if not pass_flag:
       return 0      
    
    # Check if port_channels are there, if exists member ports should be of same speed
    po_defined_flag = 1
    if 'port_channels' in device1_2_device2_dict.keys():
        if not 'port_channels' in device2_2_device1_dict.keys():
          if print_fail:
            log.info ('\nport_channels to %r are not defined in %r \n',device1, device2)
          pass_flag = 0
          po_defined_flag = 0
    else:
        po_defined_flag = 0
        if 'port_channels' in device2_2_device1_dict.keys():
          if print_fail:
            log.info ('\nport_channels to %r are not defined in %r \n',device2, device1)
          pass_flag = 0
          po_defined_flag = 0

    # Check If same Port-channels are defined in both devices
    same_pos_defined_flag = 1
    if po_defined_flag:    
        for po_no in device1_2_device2_dict['port_channels'].keys():
           if not po_no in device2_2_device1_dict['port_channels'].keys():
               if print_fail:
                 log.info ('\nPo Link %r of %r Connecting to %r is not defined\n', po_no, device1, device2)
               pass_flag = 0
               same_pos_defined_flag = 0
        for po_no in device2_2_device1_dict['port_channels'].keys():
           if not po_no in device1_2_device2_dict['port_channels'].keys():
               if print_fail:
                 log.info ('\nPo Link %r of %r Connecting to %r is not defined\n', po_no, device2, device1)
               pass_flag = 0
               same_pos_defined_flag = 0

    # Check If same Links are defined in all Pos
    # Check if the links are there as Links key in device
    if same_pos_defined_flag and po_defined_flag:    
        for po_no in device1_2_device2_dict['port_channels'].keys():
            links_list_1 = device1_2_device2_dict['port_channels'][po_no]['members']
            links_list_2 = device2_2_device1_dict['port_channels'][po_no]['members']
            if len(links_list_1) == len(links_list_2):
               for elm in links_list_1:
                   # If link element of PO is there in Links list for device1
                   if not elm in device1_2_device2_dict['links'].keys():
                       if print_fail:
                         log.info ('\n %r is not there in %r Links list to %r \n', elm, device1, device2)
                       pass_flag = 0
                       break
                   if not elm in links_list_2:
                       if print_fail:
                         log.info ('\n %r is not there in %r po %r \n', elm, device1, po_no)
                       pass_flag = 0
                       break
            else:
              if print_fail:
                log.info ('\n Same number of Links are not defined in %r for %r and %r\n', po_no, device1, device2)
              pass_flag = 0
              break
    if not pass_flag:
       return 0      
    #Check if physical interfaces are specified they are not specified in some otherlink
    #Check already specified Link is present in Testbed file
    #Check if physical interfaces are specified its speed is as per testbed file
    #If physical interface specified, check other end if its present check they are neighbors
    for elm in device1_2_device2_dict['links'].keys():
        physical_intf_dev1 = device1_2_device2_dict['links'][elm]['physical_interface'] 
        physical_intf_dev1_speed = device1_2_device2_dict['links'][elm]['speed'] 
        physical_intf_dev2 = device2_2_device1_dict['links'][elm]['physical_interface'] 
        physical_intf_dev2_speed = device2_2_device1_dict['links'][elm]['speed'] 
        flag1 = 0
        flag2 = 0
        if not re.search('auto', physical_intf_dev1, re.I):
           flag1 = 1
           if not check_physicalintf_duplicate_in_topology(topo_dict, device1, device2, print_fail):
               return 0
           if not check_physicalintf_present_in_testbed(physical_intf_dev1, device1, intf_dict_tb, print_fail):
               return 0
           if not check_physicalintf_speed_in_testbed (device1, physical_intf_dev1, physical_intf_dev1_speed, \
                         device1_tb_obj, print_fail):
               return 0
        if not re.search('auto', physical_intf_dev2, re.I):
           flag2 = 1
           if not check_physicalintf_duplicate_in_topology(topo_dict, device2, device1, print_fail):
               return 0
           if not check_physicalintf_present_in_testbed(physical_intf_dev2, device2, intf_dict_tb, print_fail):
               return 0
           if not check_physicalintf_speed_in_testbed (device2, physical_intf_dev2, physical_intf_dev2_speed, \
                         device2_tb_obj, print_fail):
               return 0
        
        #Check they are peers in testbed file
        if flag1 and flag2:
           for intf in device1_tb_obj:    
              if physical_intf_dev1.lower() == intf.name.lower():
                 remote_intf = intf.remote_interfaces.pop().name  
                 if physical_intf_dev2.lower() != remote_intf.lower():
                    if print_fail:
                       log.info('%r interface %r peer interface %r are not peers in testbed file', \
                         device1, physical_intf_dev1, physical_intf_dev2)
                    pass_flag = 0
    if not pass_flag:
       return 0      
    # Check If speed are same for all link members of PO
    if same_pos_defined_flag and po_defined_flag:    
        for po_no in device1_2_device2_dict['port_channels'].keys():
            links_list_1 = device1_2_device2_dict['port_channels'][po_no]['members']
            links_list_2 = device2_2_device1_dict['port_channels'][po_no]['members']
            reference_speed = get_po_member_speed (topo_dict, po_no, device1, device2, intf_dict_tb)
            if not reference_speed:
               for elm in links_list_1:
                  speed = device1_2_device2_dict['links'][elm]['speed']
                  if not reference_speed.lower() == speed.lower():
                      if not re.search('auto', speed, re.I):
                         if print_fail:
                           log.info ('\n All Links of PO %r between %r & %r are not of same speed\n', po_no, device1, device2)
                         pass_flag = 0
                         break

    # Check if same member links are not used in multiple Pos
    if same_pos_defined_flag and po_defined_flag:    
        for po_no in device1_2_device2_dict['port_channels'].keys():
           links_list_1 = device1_2_device2_dict['port_channels'][po_no]['members']
           for elm in links_list_1:
              for po_no1 in device1_2_device2_dict['port_channels'].keys():
                 if po_no == po_no1:
                    continue
                 links_list_2 = device1_2_device2_dict['port_channels'][po_no1]['members']
                 for elm1 in links_list_2:
                    if elm1 == elm:
                        if print_fail:
                           log.info ('\n %r and %r between %r and %r has same member links', po_no, po_no1, device1, device2)
                        return 0
                  
    if not pass_flag:
       return 0      

    ####### Now Compute for Physical Links
    # Check whether number of required Links present in testbed between devices
    no_of_links_required = len(device1_2_device2_dict['links'].keys())
    if no_of_links_present < no_of_links_required:
       if print_fail:
         log.info ('Required number of Links between %r[%r] and %r[%r] are not present in testbed file', \
                     device1, device1_tb_obj.name, device2, device2_tb_obj.name)
       return 0
    #Now update topo dict for interface and peer interface if physical intf or speed is hardcode
    if not update_topo_dict_for_hard_coded_physical_intf_or_speed(topo_dict, device1, device2, intf_dict_tb, print_fail):
       return 0
    if not update_topo_dict_for_hard_coded_physical_intf_or_speed(topo_dict, device2, device1, intf_dict_tb, print_fail):
       return 0

    # First fill Po members with physical interface
    # check reference speed as non-auto and fill them first
    if po_defined_flag:
      for po_no in device1_2_device2_dict['port_channels'].keys():
        links_list_1 = device1_2_device2_dict['port_channels'][po_no]['members']
        reference_speed = get_po_member_speed (topo_dict, po_no, device1, device2, intf_dict_tb)
        if reference_speed:
           device1_2_device2_dict['port_channels'][po_no]['members_filled'] = 1   
           device2_2_device1_dict['port_channels'][po_no]['members_filled'] = 1   
           for link in links_list_1:
              device1_physical_intf =  device1_2_device2_dict['links'][link]['physical_interface']
              if re.search('auto', device1_physical_intf, re.I):
                 filled = 0
                 for intf in intf_dict_tb[device1]['intf'].keys():
                    intf_remote = intf_dict_tb[device1]['intf_detail'][intf]['remote_int'] 
                    if reference_speed.lower() == intf_dict_tb[device1]['intf'][intf].lower():
                        device1_2_device2_dict['links'][link]['physical_interface'] = intf
                        device2_2_device1_dict['links'][link]['physical_interface'] = intf_remote
                        intf_dict_tb[device1]['intf'].pop(intf)
                        intf_dict_tb[device2]['intf'].pop(intf_remote)
                        filled = 1
                        break
                 if not filled:
                    if print_fail:
                       log.info('Required number of links are not found for Po %r in Testbed for Po \
                           with speed %r', po_no, reference_speed)  
                    return 0   

    # Fill po members with reference speed as auto
    # Fill Po with highest number of member links first and least number of members at last
    # while filling Po, get speed with highest number of interfaces from testbed and fill. 
    dict_of_pos = {}
    if po_defined_flag:
      for po_no in device1_2_device2_dict['port_channels'].keys():
        links_count = len(device1_2_device2_dict['port_channels'][po_no]['members'])
        if not 'members_filled' in device1_2_device2_dict['port_channels'][po_no]:
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
        links_list_1 = device1_2_device2_dict['port_channels'][po_no]['members']
        if not 'members_filled' in device1_2_device2_dict['port_channels'][po_no]:
           device1_2_device2_dict['port_channels'][po_no]['members_filled'] = 1   
           no_of_members = len(device1_2_device2_dict['port_channels'][po_no]['members'])
           (highest_key, highest_count) = get_highest_no_for_value_in_dict(intf_dict_tb[device1]['intf'])
           if highest_count < no_of_members: 
              if print_fail:
                 log.info('Po %r does not have %r no of links of same speed left in TB for %r refered as %r',\
                        po_no, no_of_members, intf_dict_tb[device1]['tb_name'], device1)
              return 0
           else:
              for link in links_list_1:
                 for intf in intf_dict_tb[device1]['intf'].keys():
                    intf_remote = intf_dict_tb[device1]['intf_detail'][intf]['remote_int'] 
                    intf_speed = intf_dict_tb[device1]['intf'][intf]
                    if highest_key == intf_speed:
                       device1_2_device2_dict['links'][link]['physical_interface'] = intf
                       device2_2_device1_dict['links'][link]['physical_interface'] = intf_remote
                       intf_dict_tb[device1]['intf'].pop(intf)
                       intf_dict_tb[device2]['intf'].pop(intf_remote)
                       break

    # Finally Update Links which are not part of PO and speed is auto
    for link in device1_2_device2_dict['links'].keys():
       physical_intf =  device1_2_device2_dict['links'][link]['physical_interface'].lower()
       if re.search('auto', physical_intf, re.I):
          filled = 0
          for intf in intf_dict_tb[device1]['intf'].keys():
             intf_remote = intf_dict_tb[device1]['intf_detail'][intf]['remote_int'] 
             device1_2_device2_dict['links'][link]['physical_interface'] = intf
             device2_2_device1_dict['links'][link]['physical_interface'] = intf_remote
             intf_dict_tb[device1]['intf'].pop(intf)
             intf_dict_tb[device2]['intf'].pop(intf_remote)
             filled = 1
             break
          if not filled:
             if print_fail:
                log.info('Not able to assign interface for link %r between %r and %r',\
                          link, device1, device2)
             return 0
    if print_fail:
      print_links_info(topo_dict, device1, device2, intf_dict_tb)
    return 1

def get_all_device_intf_from_topo (topo_dict, topo_name):
    all_intf_list = []
    device_dict = topo_dict['devices'][topo_name]['peer_device']
    for peer_device in device_dict.keys():
        for link in device_dict[peer_device]['links'].keys():
           all_intf_list.append(device_dict[peer_device]['links'][link]['physical_interface'])
    return all_intf_list

def get_non_po_Links_from_topology (topo_info, device, remote_device):
    '''
    Get List of Links which are not part of Po
    '''
    device1_2_device2_dict = topo_info['devices'][device]['peer_device'][remote_device]
    device_links_dict = device1_2_device2_dict['links']
    all_links_list = list(device_links_dict.keys())
    non_po_links_list = []
    if 'port_channels' in device1_2_device2_dict.keys():
      for elm in device_links_dict.keys():
        found = 0
        for po_no in device1_2_device2_dict['port_channels'].keys():
          links_list_1 = device1_2_device2_dict['port_channels'][po_no]['members']
          if elm in links_list_1:
            found = 1
            break
        if not found:
          non_po_links_list.append(elm)
    if non_po_links_list:
      return sorted(non_po_links_list)
    else:
      return sorted(all_links_list)

def get_po_with_highest_number_of_links_with_member_elm_speed_auto(topo_info, device1, device2, intf_dict_tb):
    device1_2_device2_dict = topo_info['devices'][device1]['peer_device'][device2]
    device2_2_device1_dict = topo_info['devices'][device2]['peer_device'][device1]
    max_links = 0
    max_po_name = ""
    for po_no in device1_2_device2_dict['port_channels'].keys():
       reference_speed = get_po_member_speed (topo_info, po_no, device1, device2, intf_dict_tb)
       if not reference_speed:
           no_of_links = len(device1_2_device2_dict['port_channels'][po_no]['members'])
           if no_of_links > max_links:
              max_links = no_of_links
              max_po_name = po_no
    return max_po_name
   
def print_links_info(topo_info, device1, device2,intf_dict_tb):
    device1_2_device2_dict = topo_info['devices'][device1]['peer_device'][device2]
    device2_2_device1_dict = topo_info['devices'][device2]['peer_device'][device1]
    for link in device1_2_device2_dict['links'].keys():
       physical_int = device1_2_device2_dict['links'][link]['physical_interface'].lower() 
       remote_int = device2_2_device1_dict['links'][link]['physical_interface'].lower() 
       dev1_name = intf_dict_tb[device1]['tb_name']
       dev2_name = intf_dict_tb[device2]['tb_name']
       log.info('%r[%r] %r <----> %r %r[%r] <-- %r',dev1_name, device1,\
           physical_int, remote_int, dev2_name, device2,link)

def check_no_of_po_members_with_speed_in_testbed(topo_info, device1, device2, intf_dict_tb, print_fail):
    device1_2_device2_dict = topo_info['devices'][device1]['peer_device'][device2]
    for po_no in device1_2_device2_dict['port_channels'].keys():
        links_list_1 = device1_2_device2_dict['port_channels'][po_no]['members']
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
              if print_fail:
                 log.info('Required number of links are not found for Po %r in Testbed for Po with speed %r',\
                            po_no, reference_speed)  
              return 0
    return 1

def update_topo_dict_for_hard_coded_physical_intf_or_speed(topo_info, device1, device2, intf_dict_tb, print_fail):
    device1_2_device2_dict = topo_info['devices'][device1]['peer_device'][device2]
    device2_2_device1_dict = topo_info['devices'][device2]['peer_device'][device1]
    for link in device1_2_device2_dict['links'].keys():
       device1_physical_intf =  device1_2_device2_dict['links'][link]['physical_interface'].lower()
       device2_physical_intf =  device2_2_device1_dict['links'][link]['physical_interface'].lower()
       device1_physical_intf_speed =  device1_2_device2_dict['links'][link]['speed'].lower()
       device2_physical_intf_speed =  device2_2_device1_dict['links'][link]['speed'].lower()
       #If Physical interface is specified by user pop it from List and Fill Peer Link Physical interface
       if not re.search('auto', device1_physical_intf, re.I):
          if device1_physical_intf in intf_dict_tb[device1]['intf'].keys():
             intf_dict_tb[device1]['intf'].pop(device1_physical_intf)
          intf_remote = intf_dict_tb[device1]['intf_detail'][device1_physical_intf]['remote_int'] 
          if re.search('auto', device2_physical_intf, re.I):
             device2_2_device1_dict['links'][link]['physical_interface'] = intf_remote 
          if intf_remote in intf_dict_tb[device2]['intf'].keys():
             intf_dict_tb[device2]['intf'].pop(intf_remote)
       else:
          #if speed is there match one and assign it update peer also
          if not re.search('auto', device1_physical_intf_speed, re.I):
             filled = 0
             for intf1 in intf_dict_tb[device1]['intf'].keys():
                intf_remote = intf_dict_tb[device1]['intf_detail'][intf1]['remote_int'] 
                if device1_physical_intf_speed == intf_dict_tb[device1]['intf'][intf1]:
                   device1_2_device2_dict['links'][link]['physical_interface'] = intf1
                   if intf1 in intf_dict_tb[device1]['intf'].keys():
                      intf_dict_tb[device1]['intf'].pop(intf1)
                   device2_2_device1_dict['links'][link]['physical_interface'] = intf_remote 
                   if intf_remote in intf_dict_tb[device2]['intf'].keys():
                      intf_dict_tb[device2]['intf'].pop(intf_remote)
                   filled = 1
                   break
             if not filled:
                sp = device1_physical_intf_speed
                dev1_name = intf_dict_tb[device1]['tb_name']
                dev2_name = intf_dict_tb[device2]['tb_name']
                if print_fail:
                  log.info('Not able to find %r interface between %r and %r in testbed', sp, dev1_name, dev2_name)
                return 0
                   
    return 1

def get_po_member_speed (topo_info, po_no, device1, device2, intf_dict_tb):
    device1_2_device2_dict = topo_info['devices'][device1]['peer_device'][device2]
    device2_2_device1_dict = topo_info['devices'][device2]['peer_device'][device1]
    links_list_1 = device1_2_device2_dict['port_channels'][po_no]['members']
    reference_speed = ""
    for elm in links_list_1:
        speed = device1_2_device2_dict['links'][elm]['speed']
        if re.search('gig', speed, re.I):
           return speed
    for elm in links_list_1:
        speed = device2_2_device1_dict['links'][elm]['speed']
        if re.search('gig', speed, re.I):
           return speed
    for elm in links_list_1:
        device1_physical_intf =  device1_2_device2_dict['links'][elm]['physical_interface']
        if not re.search('auto', device1_physical_intf, re.I):
           return intf_dict_tb[device1]['intf_detail'][device1_physical_intf.lower()]['speed']
        device2_physical_intf =  device2_2_device1_dict['links'][elm]['physical_interface']
        if not re.search('auto', device2_physical_intf, re.I):
           return intf_dict_tb[device2]['intf_detail'][device2_physical_intf.lower()]['speed']
    return reference_speed

def check_link_preset_in_neighbor_in_topo(topo_info, device1, device2, print_fail):
    device1_2_device2_dict = topo_info['devices'][device1]['peer_device'][device2]
    device2_2_device1_dict = topo_info['devices'][device2]['peer_device'][device1]
    return_flag = 1
    for link in device1_2_device2_dict['links'].keys():
       if not link in device2_2_device1_dict['links'].keys():
          if print_fail:
            log.info ('\nLink %r of %r Connecting to %r is not defined\n', link, device1, device2)
          return_flag = 0
    return return_flag 

def check_link_speed_as_neighbor_in_topo(topo_info, device1, device2, print_fail):
    device1_2_device2_dict = topo_info['devices'][device1]['peer_device'][device2]
    device2_2_device1_dict = topo_info['devices'][device2]['peer_device'][device1]
    return_flag = 1
    for link in device1_2_device2_dict['links'].keys():
        device1_link_speed = device1_2_device2_dict['links'][link]['speed']
        device2_link_speed = device2_2_device1_dict['links'][link]['speed']
        if not re.search('auto', device1_link_speed, re.I):
           if not re.search('auto', device2_link_speed, re.I):
              if not device1_link_speed.lower() == device2_link_speed.lower():
                 if print_fail:
                     log.info ('\nLink %r between %r and %r are not of same speed\n', link, device1, device2)
                 return_flag = 0
    return return_flag 

def check_physicalintf_speed_in_testbed (topo_device, physical_intf, physical_intf_speed, device_obj, print_fail):
    if not re.search('auto', physical_intf_speed, re.I):
        for intf in device_obj:
            if physical_intf.lower() == intf.name.lower():
                if physical_intf_speed.lower() != intf.speed.lower():
                    if print_fail:
                      log.info('\n %r Intf %r speed specified in topololgy is not same as testbed device %r', topo_device,\
                          physical_intf, device_obj.name)
                    return 0
    return 1
def check_physicalintf_present_in_testbed (physical_intf, topo_device, intf_dict_tb, print_fail):
    if not re.search('auto', physical_intf, re.I):
       if not physical_intf in intf_dict_tb[topo_device]['intf_detail'].keys():
          nbr = list(intf_dict_tb.keys())
          nbr.remove('no_of_links_defined')
          nbr.remove(topo_device)
          nbr = nbr[0]
          nb_name = intf_dict_tb[nbr]['tb_name']
          self_name = intf_dict_tb[topo_device]['tb_name']
          if print_fail:
             log.info('%r[%r] %r <----> %r[%r] <-- Link is not there',topo_device, self_name,\
                  physical_intf, nbr, nb_name)
          return 0
    return 1

def check_physicalintf_duplicate_in_topology (topo_info, device, remote_device, print_fail):
    device_links_dict = topo_info['devices'][device]['peer_device'][remote_device]['links']
    all_links_dict = {}
    for elm in device_links_dict.keys():
       all_links_dict[elm] = device_links_dict[elm]['physical_interface']
    myd = get_no_of_occurence_of_value_from_dict_as_dict(all_links_dict)

    for elm in myd.keys():
      if not re.search('auto', elm, re.I):
        if myd[elm] > 1:
           if print_fail: 
              log.info ('\n%r is used multiple times as link between %r and %r\n', elm , device, remote_device)
           return 0
    return 1

def check_if_node_can_be_used_for_device (testbed = '', device_topo_name = '', tb_node_name = '', individual_node_trees = {}):
    for each_device in individual_node_trees.keys():
       dev_type = individual_node_trees[each_device]['type']
       if (individual_node_trees[each_device]['temp_node_name'] == tb_node_name) | \
          (individual_node_trees[each_device]['tb_node_name'] == tb_node_name):
          if re.search('spirent|ixia', dev_type, re.I):
             #Can be Used
             return 1
          if device_topo_name == each_device:
             #Can be used
             return 1
          else:
             # Can not be Used
             return 0
    dev_type = individual_node_trees[device_topo_name]['type']
    ## If any of previuos device is selected as 'ixia or spirent'
    ## make sure same type is selected for this tgn also
    if re.search('spirent|ixia', dev_type, re.I):
       for each_device in individual_node_trees.keys():
          if device_topo_name == each_device:
             continue
          if re.search('spirent|ixia', individual_node_trees[each_device]['type'], re.I):
             if individual_node_trees[each_device]['temp_node_name']:
                tgn_type = testbed.devices[individual_node_trees[each_device]['temp_node_name']].type
                tgn_type1 = testbed.devices[tb_node_name].type
                if tgn_type != tgn_type1:
                   return 0
             if individual_node_trees[each_device]['tb_node_name']:
                if not re.search('auto', individual_node_trees[each_device]['tb_node_name'], re.I):
                   tgn_type = testbed.devices[individual_node_trees[each_device]['tb_node_name']].type
                   tgn_type1 = testbed.devices[tb_node_name].type
                   if tgn_type != tgn_type1:
                      return 0
    return 1

def get_eligible_node_list_matching_links (testbed = {}, topo_dict = {}, parent_topo_name = '', individual_node_trees = {},\
                                           dev_topo_name = '', unused_node_list = [], match_link = 1, print_fail = 0):
    '''
     0. Get nodelist
     1.     matching type(switch, tgn etc) in unused_nodes_list.
     2.     matching platform type(T2P-TOR, T2-TOR etc)
     3.     if temp_node_name or tb_node_name is specified list will have only that
     4. from matching links, if parent is specified, finds whether it matches link requiremnet between nodes
     5.   if link doesn't match return empty link
    '''
    all_eligible_nodes_list = []
    required_node_type = individual_node_trees[dev_topo_name]['type']
    required_platform = individual_node_trees[dev_topo_name]['platform']
    if re.search('auto', required_node_type, re.I):
      log.info('Device type has to be specified for %r in topology file', dev_topo_name)
      return all_eligible_nodes_list
    ##If hardcode device return the list with that
    if not re.search('auto', individual_node_trees[dev_topo_name]['tb_node_name'], re.I):
       all_eligible_nodes_list.append(individual_node_trees[dev_topo_name]['tb_node_name'])
    ##If temp_node_name is filled, return the list with that 
    if individual_node_trees[dev_topo_name]['temp_node_name']:
       all_eligible_nodes_list.append(individual_node_trees[dev_topo_name]['temp_node_name'])
    ##Need to find from unsed List
    if not all_eligible_nodes_list:
       ## for each node in unused list
       for each_eligible_node in unused_node_list:
          eligible_node_type = testbed.devices[each_eligible_node].type
          eligible_platform = testbed.devices[each_eligible_node].custom['platform']
          ## if node type matches
          node_type_matched = 0
          if re.search('spirent|ixia', eligible_node_type, re.I):
             if re.search(eligible_node_type, required_node_type, re.I):
                node_type_matched = 1
          else:
             if re.search(required_node_type, eligible_node_type, re.I):
                node_type_matched = 1
          if node_type_matched:
             ## if platform type matches or if platform type auto add to all_eligible_nodes_list
             if re.search(required_platform, eligible_platform, re.I):
               all_eligible_nodes_list.append(each_eligible_node)
             else:
               if re.search('auto', required_platform, re.I):
                  all_eligible_nodes_list.append(each_eligible_node)
    ## nothing found as eligible return
    if not all_eligible_nodes_list:
       return all_eligible_nodes_list

    eligible_node_list = [] 
    if parent_topo_name:
       if not re.search('auto', individual_node_trees[parent_topo_name]['tb_node_name'], re.I):
          parent_node = individual_node_trees[parent_topo_name]['tb_node_name']
       else:
          parent_node = individual_node_trees[parent_topo_name]['temp_node_name']
       parent_tb_obj = testbed.devices[parent_node]
       for each_eligible_node in all_eligible_nodes_list:
          if not check_if_node_can_be_used_for_device(testbed = testbed, device_topo_name = dev_topo_name, \
                                      tb_node_name = each_eligible_node, individual_node_trees = individual_node_trees):
             continue
          dev_tb_obj = testbed.devices[each_eligible_node]   
          topo_dict_temp = {}
          topo_dict_temp = copy.deepcopy(topo_dict)
          if find_Connecting_interfaces (topo_dict = topo_dict_temp, device1 = parent_topo_name,\
                    device2 = dev_topo_name, device1_tb_obj = parent_tb_obj, \
                    device2_tb_obj = dev_tb_obj, print_fail = print_fail):
             eligible_node_list.append(each_eligible_node)
       return eligible_node_list
    else:
       return all_eligible_nodes_list

    
def update_used_status (testbed = {}, individual_node_trees = {}, node_name = '', dev_topo_name = '', add_yes = 1):
    if add_yes:
       for each_device in individual_node_trees.keys():
          temp_node_name = individual_node_trees[each_device]['temp_node_name'] 
          if temp_node_name == node_name:
             if each_device == dev_topo_name:
                return 2
             else:
                if not re.search('ixia|spirent', testbed.devices[node_name].type, re.I):      
                   return 0
       if not individual_node_trees[dev_topo_name]['temp_node_name']:
          individual_node_trees[dev_topo_name]['temp_node_name'] = node_name
          return 1 
       else:
          return 0
    else:
       individual_node_trees[dev_topo_name]['temp_node_name'] = ''
    return 0

def verify_n_expand_topology_dict (topo_dict):
    for dev_name in topo_dict['devices'].keys():
       #default device type is switch, Fill it if not filled
       if not 'type' in topo_dict['devices'][dev_name].keys():
          topo_dict['devices'][dev_name]['type'] = 'switch'
       else:
          if not topo_dict['devices'][dev_name]['type']:
             topo_dict['devices'][dev_name]['type'] = 'switch'
       if not 'platform' in topo_dict['devices'][dev_name].keys():
          topo_dict['devices'][dev_name]['platform'] = 'auto select'
       else:
          if not topo_dict['devices'][dev_name]['platform']:
             topo_dict['devices'][dev_name]['platform'] = 'auto select'
       if not 'node_name' in topo_dict['devices'][dev_name].keys():
          topo_dict['devices'][dev_name]['node_name'] = 'auto select'
       else:
          if not topo_dict['devices'][dev_name]['node_name']:
             topo_dict['devices'][dev_name]['node_name'] = 'auto select'
       for peer_device in topo_dict['devices'][dev_name]['peer_device'].keys():
          device1_2_device2_dict = topo_dict['devices'][dev_name]['peer_device'][peer_device]
          device2_2_device1_dict = topo_dict['devices'][peer_device]['peer_device'][dev_name]
          nu_of_links = 0
          nu_of_links_1 = 0
          nu_of_links_2 = 0
          #If nu of links between pairs is incorrect fail it
          nu_of_linksdefined_1 = 0
          nu_of_linksdefined_2 = 0
          if isinstance(device1_2_device2_dict, dict):
             nu_of_linksdefined_1 = 1
             if not 'nu_of_links' in device1_2_device2_dict.keys():
                nu_of_links_1 = 0
             else:
                nu_of_links_1 = int(device1_2_device2_dict['nu_of_links'])
          if isinstance(device2_2_device1_dict, dict):
             nu_of_linksdefined_2 = 1
             if not 'nu_of_links' in device2_2_device1_dict.keys():
                nu_of_links_2 = 0
             else:
                nu_of_links_2 = int(device2_2_device1_dict['nu_of_links'])
          if nu_of_linksdefined_1 == 0 and nu_of_linksdefined_2 == 0:
             print('Number of links not defined for ' + dev_name + peer_device)
             log.info('Number of links not defined between peers  %r and %r', dev_name, peer_device)
             return 0
          if nu_of_links_1 > 0 and nu_of_links_2 > 0:
             if nu_of_links_1 != nu_of_links_2: 
                log.info('Number of links specified between %r and %r are not same', dev_name, peer_device)
                return 0
          else:
             if not nu_of_links_1:
                nu_of_links_1 = nu_of_links_2 
             if not nu_of_links_2:
                nu_of_links_2 = nu_of_links_1 
          if nu_of_links_1 == 0 and nu_of_links_2 == 0:
             print('Number of links not defined for ' + dev_name + peer_device)
             log.info('Number of links not defined between peers  %r and %r', dev_name, peer_device)
             return 0
          if not nu_of_linksdefined_1:
             topo_dict['devices'][dev_name]['peer_device'][peer_device] = dict()
             topo_dict['devices'][dev_name]['peer_device'][peer_device]['nu_of_links'] = nu_of_links_1
             device1_2_device2_dict = topo_dict['devices'][dev_name]['peer_device'][peer_device]
          else:
             device1_2_device2_dict['nu_of_links'] = nu_of_links_1
          if not nu_of_linksdefined_2:
             topo_dict['devices'][peer_device]['peer_device'][dev_name] = dict()
             topo_dict['devices'][peer_device]['peer_device'][dev_name]['nu_of_links'] = nu_of_links_2
             device2_2_device1_dict = topo_dict['devices'][peer_device]['peer_device'][dev_name]
          else:
             device2_2_device1_dict['nu_of_links'] = nu_of_links_2
             
          # If port channels defined member links should be same
          dev1_po_defined = 0
          dev2_po_defined = 0
          if 'port_channels' in device1_2_device2_dict.keys(): 
             dev1_po_defined = 1
          if 'port_channels' in device2_2_device1_dict.keys(): 
             dev2_po_defined = 1
          if dev1_po_defined or dev2_po_defined:
             if dev1_po_defined and dev2_po_defined: # Po in both devices defined
                pos_1 = []
                pos_2 = []
                if isinstance(device1_2_device2_dict['port_channels'], dict):
                   pos_1 = device1_2_device2_dict['port_channels'].keys()
                if isinstance(device2_2_device1_dict['port_channels'], dict):
                   pos_2 = device2_2_device1_dict['port_channels'].keys()
                if pos_1 or pos_2: # Po content key is present in one or both devices 
                   if pos_1 and pos_2: # Po content key is present in both devices 
                      if sorted(pos_1) != sorted(pos_2): # Pos defined are not same, so Fail
                         print('PO elemets are not same' + dev_name + peer_device) 
                         log.info('Same Pos are not defined for %r and %r', dev_name, peer_device)
                         return 0 
                      else: # Pos same but check links same in each po
                         for po_no in device1_2_device2_dict['port_channels'].keys():
                            po_name = device1_2_device2_dict['port_channels'][po_no]
                            po_members_1 = 0
                            po_members_2 = 0
                            if isinstance(device1_2_device2_dict['port_channels'][po_no], dict):
                               po_members_1 = 1
                            if isinstance(device2_2_device1_dict['port_channels'][po_no], dict):
                               po_members_2 = 1
                            if po_members_1 and po_members_2:
                               mem_list_1 = device1_2_device2_dict['port_channels'][po_no]['members']
                               mem_list_2 = device2_2_device1_dict['port_channels'][po_no]['members']
                               if sorted(mem_list_1) != sorted(mem_list_2):
                                  print('PO members not same for device pair' + dev_name + peer_device) 
                                  log.info('PO members not same for device pair %r and %r' + dev_name + peer_device) 
                                  return 0
                            else:
                               print('PO members not defined properly for device pair' + dev_name + peer_device) 
                               log.info('PO members not defined properly for device pair %r and %r' + dev_name + peer_device) 
                               return 0
                   else: # If only one has port_channels defined
                      if pos_1: 
                         device2_2_device1_dict['port_channels'] = dict()
                         for po_no in device1_2_device2_dict['port_channels'].keys():
                            po_mem_list = device1_2_device2_dict['port_channels'][po_no]['members']
                            device2_2_device1_dict['port_channels'][po_no] = dict()
                            device2_2_device1_dict['port_channels'][po_no]['members'] = dict()
                            device2_2_device1_dict['port_channels'][po_no]['members'] = po_mem_list
                      if pos_2: 
                         device1_2_device2_dict['port_channels'] = dict()
                         for po_no in device1_2_device2_dict['port_channels'].keys():
                            po_mem_list = device2_2_device1_dict['port_channels'][po_no]['members']
                            device1_2_device2_dict['port_channels'][po_no] = dict()
                            device1_2_device2_dict['port_channels'][po_no]['members'] = dict()
                            device1_2_device2_dict['port_channels'][po_no]['members'] = po_mem_list
             else: # Po in one of the device defined
                if dev1_po_defined: # For Device1 po defined so copy to Device2
                   if isinstance(device1_2_device2_dict['port_channels'], dict):
                      pos = device1_2_device2_dict['port_channels'].keys()
                      device2_2_device1_dict['port_channels'] = dict()
                      for each_po in pos:
                          member_list = device1_2_device2_dict['port_channels'][each_po]['members']
                          device2_2_device1_dict['port_channels'][each_po] = dict()
                          device2_2_device1_dict['port_channels'][each_po]['members'] = member_list
                else: # For Device2 po defined so copy to Device1
                   if isinstance(device2_2_device1_dict['port_channels'], dict):
                      pos = device2_2_device1_dict['port_channels'].keys()
                      device1_2_device2_dict['port_channels'] = dict()
                      for each_po in pos:
                          member_list = device2_2_device1_dict['port_channels'][each_po]['members']
                          device1_2_device2_dict['port_channels'][each_po] = dict()
                          device1_2_device2_dict['port_channels'][each_po]['members'] = member_list
          nu_of_links = int(device1_2_device2_dict['nu_of_links'])
          if not 'links' in device1_2_device2_dict.keys():
             if nu_of_links:
                i = 1
                device1_2_device2_dict['links'] = dict()
                while i <= int(nu_of_links):
                  link_name = 'link_' + str(i)
                  device1_2_device2_dict['links'][link_name] = dict()
                  device1_2_device2_dict['links'][link_name]['physical_interface'] = "auto select"
                  device1_2_device2_dict['links'][link_name]['speed'] = "auto select"
                  i += 1
             else:
                log.info('For %r and % as peers nu_of_links or Links keys are not defined', dev_name, peer_device)
                return 0
          else: # 'Links' Key is present
             if nu_of_links:
                i = 1
                while i <= int(nu_of_links):
                  link_name = 'link_' + str(i)
                  if isinstance(device1_2_device2_dict['links'], dict):
                     if link_name in device1_2_device2_dict['links'].keys():
                        if not isinstance(device1_2_device2_dict['links'][link_name], dict):
                           device1_2_device2_dict['links'][link_name] = dict()
                        keys = device1_2_device2_dict['links'][link_name].keys()
                        if not 'physical_interface' in keys: 
                           device1_2_device2_dict['links'][link_name]['physical_interface'] = "auto select"
                        if not 'speed' in keys: 
                           device1_2_device2_dict['links'][link_name]['speed'] = "auto select"
                     else:
                        device1_2_device2_dict['links'][link_name] = dict()
                        device1_2_device2_dict['links'][link_name]['physical_interface'] = "auto select"
                        device1_2_device2_dict['links'][link_name]['speed'] = "auto select"
                  else:
                     device1_2_device2_dict['links'] = dict()
                     device1_2_device2_dict['links'][link_name] = dict()
                     device1_2_device2_dict['links'][link_name]['physical_interface'] = "auto select"
                     device1_2_device2_dict['links'][link_name]['speed'] = "auto select"
                  i += 1
             else:
                for link_name in device1_2_device2_dict['links'].keys():
                   keys = device1_2_device2_dict['links'][link_name].keys()
                   if not 'physical_interface' in keys: 
                      device1_2_device2_dict['links'][link_name]['physical_interface'] = "auto select"
                   if not 'speed' in keys: 
                      device1_2_device2_dict['links'][link_name]['speed'] = "auto select"
    return 1

def get_device_list (line):
    line = re.sub(' +',' ',line)
    line = line.strip()
    words = line.split(" ")
    return words                   

def find_topology_devices_and_links (testbed = {}, topo_dict = {}, print_fail = 0):

   if not verify_n_expand_topology_dict (topo_dict):
      log.info('Expanding topology parameters Failed')
      return 0
   devices = ''
   all_eligible_nodes_list = []
   try:  
     devices = os.environ["DEVICE_LIST"]
   except KeyError:
      log.info('Environment variable \"DEVICE_LIST\" is not set')
   devices = re.sub(',',' ',devices) 
   ## Create Eligible nodes List from 'DEVICE_LIST' environment variable 
   if devices:
      all_eligible_nodes_list = get_device_list(devices) 
   ## If 'DEVICE_LIST' env is not set get all deives from testbed as eligible
   if not all_eligible_nodes_list:
      all_eligible_nodes_list = list(testbed.devices.keys())
   x_devices = ''
   try:  
     x_devices = os.environ["X_DEVICE_LIST"]
   except KeyError:
      log.info('Environment variable \"X_DEVICE_LIST\" is not set')
   x_devices = re.sub(',',' ',x_devices) 
   x_device_list = ''
   ## Create not eligible nodes List from 'X_DEVICE_LIST' environment variable 
   if x_devices:
      x_device_list = get_device_list(x_devices) 
      log.info('Xclude Device List -> %r',x_device_list)
   log.info('Device List -> %r',all_eligible_nodes_list)
   ## Remove all not eligible nodes from all_eligible_nodes_list
   for each_x_dev in x_device_list:
       if each_x_dev in all_eligible_nodes_list:
          all_eligible_nodes_list.remove(each_x_dev)
   log.info('Final Device List -> %r',all_eligible_nodes_list)
   nu_of_switches_req = 0 
   nu_of_switches_in_list = 0 
   nu_of_tgns_in_list = 0 
   nu_of_tgns_req = 0 
   ##Get nu of switches and TGNs required as per TOPOLOGY
   for each_topo_device in topo_dict['devices'].keys():
       if not 'type' in topo_dict['devices'][each_topo_device].keys():
          log.info('Device type is not specified for %r', each_topo_device)
          return 0
       if re.search('switch', topo_dict['devices'][each_topo_device]['type'], re.I):
          nu_of_switches_req += 1
       #if re.search('tgn', topo_dict['devices'][each_topo_device]['type'], re.I):
       if re.search('spirent|ixia', topo_dict['devices'][each_topo_device]['type'], re.I):
          nu_of_tgns_req += 1
   ##Get nu of switches and TGNs from eligible devices
   for each_node in all_eligible_nodes_list:
       if re.search('switch', testbed.devices[each_node].type, re.I):
          nu_of_switches_in_list += 1
       if re.search('ixia|spirent', testbed.devices[each_node].type, re.I):
          nu_of_tgns_in_list += 1
   ## Check if TGN required and there is TGN in eligible nodes list
   if nu_of_tgns_req:
      if not nu_of_tgns_in_list:
          log.info ('There is no TGN specified in Device list to choose')
          return 0
   ## Check if nu of switches required is there in eligible nodes list
   if nu_of_switches_req > nu_of_switches_in_list:
       log.info ('Number of switches specified are less than required nu of switches in topology')
       return 0
   ## check if_dut is specified for any device, mark it as root
   for device in topo_dict['devices'].keys():
      if 'if_dut' in topo_dict['devices'][device].keys(): 
          root_device = device
          break
   ## 1. if root_device is not selected mark one hard coded as root
   ## 2. Also remove all hardcoded device from eligible list
   for topo_name in topo_dict['devices'].keys():
     ##if its not \'auto select\' device
     if not re.search('auto', topo_dict['devices'][topo_name]['node_name'], re.I):
        #TGN is not selected as root device also its not removed from eligible list
        #Same TGN device can also be selected as non hardcoded traffic device so its not removed
        if not re.search('ixia|spirent', topo_dict['devices'][topo_name]['type'], re.I):    
           if not root_device:
              root_device = topo_name
           if not topo_dict['devices'][topo_name]['node_name'] in testbed.devices.keys():
              log.info('Device hardcoded as %r is not found in testbed file', \
                                           topo_dict['devices'][topo_name]['node_name'])
              return 0
           if all_eligible_nodes_list:
              if not topo_dict['devices'][topo_name]['node_name'] in all_eligible_nodes_list:
                 log.info('Hard coded device %r is not there in list to choose from', \
                                           topo_dict['devices'][topo_name]['node_name'])
                 return 0
           all_eligible_nodes_list.remove(topo_dict['devices'][topo_name]['node_name'])

   ## If root device can not be found retun 0
   if not root_device:
      log.info ('No device is marked as \'if_dut\' or all of the devices are marked as auto select' )
      return 0

   ## Create Topology Tree
   individual_node_trees = {} 
   topo_dict_tree = create_topology_tree (individual_node_trees = individual_node_trees, root_device = root_device,\
                       topo_dict = topo_dict)
   if not topo_dict_tree:
      log.info ('Topology Device Tree formation Failed')
      return 0

   #Fill root node and traverse tree to fill other nodes
   dev_topo_name = topo_dict_tree['children']['child1']['name'] 
   root_eligible_node_list = get_eligible_node_list_matching_links(testbed = testbed, topo_dict = topo_dict, \
                               individual_node_trees = individual_node_trees, dev_topo_name = dev_topo_name,\
                               unused_node_list = all_eligible_nodes_list, print_fail = print_fail)
   if not root_eligible_node_list:
      log.info('Not able to find suitable node for %r', dev_topo_name)
      return 0
   success = 0
   for root_eligible_node in root_eligible_node_list:
      update_used_status (testbed = testbed, individual_node_trees = individual_node_trees, \
                          node_name = root_eligible_node, dev_topo_name = dev_topo_name, add_yes = 1)
      temp_topo_dict = topo_dict_tree['children']['child1']
      #remove it from eligible list
      node_removed = 0
      if root_eligible_node in all_eligible_nodes_list:
         all_eligible_nodes_list.remove(root_eligible_node)
         node_removed = 1
      (status, return_dict) = fill_tb_devices_in_topo(testbed = testbed, topo_dict = topo_dict, \
                                 individual_node_trees = individual_node_trees, topo_dict_tree = temp_topo_dict, \
                                 unused_nodes_list = all_eligible_nodes_list,  parent_dev = dev_topo_name, \
                                 parent_node = root_eligible_node, root_node = 1, print_fail = print_fail)   
      if status:
         success = 1
         break
      else:
        update_used_status (testbed = testbed, individual_node_trees = individual_node_trees, node_name = root_eligible_node,\
                            dev_topo_name = dev_topo_name, add_yes = 0)
        #failure case so add it back
        if node_removed:
           all_eligible_nodes_list.append(root_eligible_node)
   if not success:
      log.info('Matching Devices for Topology is not found in testbed')
      return 0

   #Fill temp_node_name as finalnode name and return
   log.info('Matching Devices for Topology is found in testbed')
   
   fail_flag = 0
   for each_topo_device in topo_dict['devices'].keys():
       if not re.search('auto', return_dict[each_topo_device]['tb_node_name'], re.I):
          node_name = return_dict[each_topo_device]['tb_node_name']
          topo_dict['devices'][each_topo_device]['node_name'] = node_name
       else:
          if not re.search('auto', return_dict[each_topo_device]['temp_node_name'], re.I):
             node_name = return_dict[each_topo_device]['temp_node_name']
             topo_dict['devices'][each_topo_device]['node_name'] = node_name
          else:
             fail_flag = 1
             log.info('Matching Topology for %r is not found')
   if fail_flag:
      return 0

   node_pair_dict = get_topo_node_pair_dict (topo_dict)
   for each_perm_no in node_pair_dict.keys():
     device1 = node_pair_dict[each_perm_no]['value'][0]
     device2 = node_pair_dict[each_perm_no]['value'][1]
     device1_node = topo_dict['devices'][device1]['node_name']
     device2_node = topo_dict['devices'][device2]['node_name']
     device1_tb_obj = testbed.devices[device1_node] 
     device2_tb_obj = testbed.devices[device2_node] 
     if not find_Connecting_interfaces (topo_dict = topo_dict, device1 = device1,\
                    device2 = device2, device1_tb_obj = device1_tb_obj, \
                    device2_tb_obj = device2_tb_obj):
        return 0

   #dir_name, file_name = os.path.split(topo_yaml)
   new_file = os.environ['HOME'] + '/topology_resolved.yaml'
   f = open (new_file, "w")
   print_topo_yaml(topo_dict, file_name = f)
   f.close()
   return 1

def print_topo_yaml(d, file_name = '', depth=0):
    for k,v in sorted(d.items(),key=lambda x: x[0], reverse=True):
       if isinstance(v, dict):
          str_p = "  "*depth
          str_p += str(k) + ":"
          log.info('%r',str_p)
          if file_name:
             file_name.write(str_p + '\n')
          print_topo_yaml(v, file_name = file_name, depth = depth+1)
       else:
          if re.search('^\[', str(v), re.I):
             str_p = "  "*depth + k + ':  ' + str(v)
          else:
             str_p = "  "*depth + k + ':  \"' + str(v) + '\"'
          if not re.search('members_filled', str_p, re.I):      
             log.info ('%r',str_p)
             if file_name:
                file_name.write(str_p + '\n')

def create_permutation_of_node_pair (node_pair_dict = {}, node_list = []):
    i = 1
    if len(node_list) < 2:
       return 1
    while i < len(node_list):
       node_pair_dict['perm_no'] += 1
       perm_no = 'perm' + str(node_pair_dict['perm_no'])
       node_pair_dict[perm_no] = dict()
       node_pair_dict[perm_no]['value'] = [node_list[0], node_list[i]]
       i += 1
    node_list.remove(node_list[0])
    create_permutation_of_node_pair(node_pair_dict = node_pair_dict, node_list = node_list)
    return 1

def get_topo_node_pair_dict (topo_dict):
   node_list = list(topo_dict['devices'].keys())
   node_pair_dict = {}
   node_pair_dict['perm_no'] = 0
   create_permutation_of_node_pair(node_pair_dict = node_pair_dict, node_list = node_list)
   node_pair_dict.pop('perm_no')
   all_perm_list = list(node_pair_dict.keys())
   for each_perm_no in all_perm_list:
     device1 = node_pair_dict[each_perm_no]['value'][0]
     device2 = node_pair_dict[each_perm_no]['value'][1]
     if not device2 in topo_dict['devices'][device1]['peer_device'].keys():
        node_pair_dict.pop(each_perm_no)
   return node_pair_dict
    
def fill_tb_devices_in_topo (testbed = {}, topo_dict = {}, individual_node_trees = {}, topo_dict_tree = {},\
                             unused_nodes_list = [], parent_dev = '', parent_node = '', root_node = 0, print_fail = 0):
   if not 'children' in topo_dict_tree.keys():
      return (1, individual_node_trees)
   all_child_no_list_sorted = []
   no_of_children = 0 
   for each_child in topo_dict_tree['children'].keys():
     if re.search('child\d+', each_child, re.I):      
        all_child_no_list_sorted.append(each_child)
        no_of_children += 1
   all_child_no_list_sorted = sorted(all_child_no_list_sorted, key = lambda x: (int(re.findall("\d+$", x)[0])))
   #Create Link List of all children for creating combination
   child_serial_link_dict = {}
   temp_dict = child_serial_link_dict
   for each_child in all_child_no_list_sorted:
     dev_topo_name = topo_dict_tree['children'][each_child]['name'] 
     temp_dict['child'] = dict()
     temp_dict['child']['name'] = dev_topo_name
     temp_dict = temp_dict['child']
   #Create combination of nodes for all children
   combination_dict = {}
   combination_dict['combination_no'] = 1
   combination_dict['list1'] = dict()
   combination_dict['list1']['value'] = []
   create_combination_of_nodes(testbed = testbed, topo_dict = topo_dict, combination_dict = combination_dict,\
                             serial_link_dict = child_serial_link_dict, unused_nodes_list = unused_nodes_list,\
                             parent_dev = parent_dev, parent_node = parent_node, 
                             individual_node_trees = individual_node_trees, print_fail = print_fail)
   #Last combination is empty. Delete that.
   #if last combination indices is list1 and empty its a failure
   last_combination_nu = combination_dict['combination_no']
   last_list = 'list' + str(last_combination_nu)
   if last_combination_nu == 1:
      if not len(combination_dict[last_list]['value']):
         return (0, {})
   else:
      combination_dict['combination_no'] -= 1
      combination_dict.pop(last_list) 
   for each_combination_index in combination_dict.keys():
      if each_combination_index == 'combination_no':
         continue
      if not no_of_children == len(combination_dict[each_combination_index]['value']):
         log.info('Number of combinations exepected is wrong')
         return (0, {})
   #Now For each combination try to find out which combination is success.
   for each_combination_index in combination_dict.keys():
       if each_combination_index == 'combination_no':
         continue
       combi_list = combination_dict[each_combination_index]['value']
       device_updated_list = []
       i = 0
       node_update_failed = 0
       all_trees_copy = copy.deepcopy(individual_node_trees)
       for each_child_dev_index in all_child_no_list_sorted:
          each_child_dev_name = topo_dict_tree['children'][each_child_dev_index]['name'] 
          each_child_node_name = combi_list[i]
          i += 1
          node_updated = update_used_status (testbed = testbed, individual_node_trees = all_trees_copy, \
                                            node_name = each_child_node_name, dev_topo_name = each_child_dev_name, add_yes = 1)
          if not node_updated:
             node_update_failed = 1
             break
          else:
             if node_updated == 1:
                device_updated_list.append(each_child_dev_name)
       if node_update_failed:
          continue
       any_failed = 0
       i = 0
       return_dict = all_trees_copy
       for each_child_dev_index in all_child_no_list_sorted:
          each_child_dev_name = topo_dict_tree['children'][each_child_dev_index]['name'] 
          each_child_node_name = combi_list[i]
          i += 1
          temp_topo_dict = topo_dict_tree['children'][each_child_dev_index]
          (status, return_dict) =  fill_tb_devices_in_topo (testbed = testbed, topo_dict = topo_dict,\
                                   individual_node_trees = return_dict, topo_dict_tree = temp_topo_dict,\
                                   unused_nodes_list = unused_nodes_list, parent_dev = each_child_dev_name,\
                                   parent_node = each_child_node_name, print_fail = print_fail)
          if not status:
             any_failed = 1
             break
       if any_failed:
          for each_updated_device in device_updated_list:
              update_used_status (testbed = testbed, individual_node_trees = all_trees_copy, \
                                  node_name = each_child_node_name, dev_topo_name = each_updated_device, add_yes = 0)
       else:
          return (1, return_dict)
   return (0, {}) 

def create_combination_of_nodes (testbed = {}, topo_dict = {}, combination_dict = {}, serial_link_dict = {},\
                                 unused_nodes_list = [], parent_dev = '', parent_node = '', 
                                 individual_node_trees = {}, print_fail = 0):
    if not 'child' in serial_link_dict.keys():
       return 0
    eligible_node_found = 0

    child_dev_name = serial_link_dict['child']['name']  
    eligible_node_list = get_eligible_node_list_matching_links(testbed = testbed, topo_dict = topo_dict,\
                                 parent_topo_name = parent_dev, individual_node_trees = individual_node_trees, 
                                 dev_topo_name = child_dev_name, unused_node_list = unused_nodes_list, 
                                 print_fail = print_fail)
    if not eligible_node_list:
        return 1
    for each_node in eligible_node_list:
       combination_no = combination_dict['combination_no']
       list_name = 'list' + str(combination_no)
       combination_dict[list_name]['value'].append(each_node)
       unused_nodes_list_copy = list(unused_nodes_list)
       if each_node in unused_nodes_list_copy:
          unused_nodes_list_copy.remove(each_node)
       ret_val = create_combination_of_nodes(testbed = testbed, topo_dict = topo_dict, combination_dict = combination_dict,\
                             serial_link_dict = serial_link_dict['child'], unused_nodes_list = unused_nodes_list_copy,\
                             parent_dev = parent_dev, parent_node = parent_node, individual_node_trees = individual_node_trees,\
                             print_fail = print_fail)
       if not ret_val:
          previous_list = list(combination_dict[list_name]['value'])
          previous_list.pop()
          combination_dict['combination_no'] += 1
          combination_no = combination_dict['combination_no']
          list_name = 'list' + str(combination_no)
          combination_dict[list_name] = dict()
          combination_dict[list_name]['value'] = previous_list
       else:
          combination_no = combination_dict['combination_no']
          list_name = 'list' + str(combination_no)
          combination_dict[list_name]['value'].pop()
    return 1

def create_topology_tree (individual_node_trees = {}, root_device = '', topo_dict = {}):
   topo_dict_tree = {}
   #Create Individual node Tree
   for each_node in topo_dict['devices'].keys():
      individual_node_trees[each_node] = dict()
      individual_node_trees[each_node]['tb_node_name'] = topo_dict['devices'][each_node]['node_name']
      individual_node_trees[each_node]['temp_node_name'] = ''
      individual_node_trees[each_node]['type'] = topo_dict['devices'][each_node]['type']
      if 'platform' in topo_dict['devices'][each_node].keys():
        individual_node_trees[each_node]['platform'] = topo_dict['devices'][each_node]['platform']
      else:
        individual_node_trees[each_node]['platform'] = 'auto'
      if 'peer_device' in topo_dict['devices'][each_node].keys():
         individual_node_trees[each_node]['children'] = dict()
         i = 1
         for node in topo_dict['devices'][each_node]['peer_device'].keys():
            chld_no = 'child' + str(i)
            individual_node_trees[each_node]['children'][chld_no] = dict()
            individual_node_trees[each_node]['children'][chld_no]['name'] = node
            i += 1
   #First form Root_node
   topo_dict_tree['children'] = dict()
   topo_dict_tree['children']['parent_node'] = 'root'
   topo_dict_tree['children']['next_child_no'] = 2
   topo_dict_tree['children']['child1'] = dict()
   topo_dict_tree['children']['child1']['name'] = root_device

   #Now add nodes to topodict tree
   add_nodes_to_topo_dict_tree(topo_dict_tree = topo_dict_tree, individual_node_trees = individual_node_trees)
   return topo_dict_tree

def add_nodes_to_topo_dict_tree(topo_dict_tree = {}, individual_node_trees = {}):
   ## If topo_dict has children
   if 'children' in topo_dict_tree.keys(): 
      topo_dict_all_child_index_list = []
      #get list of all child_index
      for each_child_index in topo_dict_tree['children'].keys():
         if re.search('child\d+', each_child_index, re.I):      
            topo_dict_all_child_index_list.append(each_child_index)
      ## for each child index node create child for it 
      ## mark this node as parnet for its child
      for each_child_index in topo_dict_all_child_index_list:
         parent_node = topo_dict_tree['children'][each_child_index]['name'] 
         parent_all_children_index_list = []
         ## Create list of children index for current parent node
         for each_child in individual_node_trees[parent_node]['children'].keys():
            if re.search('child\d+', each_child, re.I):      
               parent_all_children_index_list.append(each_child)
         ## if still childens are there for parent node as found from individual_node_trees
         ## Create Children for it and mark it as prent
         if parent_all_children_index_list:
            topo_dict_tree['children'][each_child_index]['children'] = dict()
            topo_dict_tree['children'][each_child_index]['children']['parent_node'] = parent_node
         i = 1
         for each_child in parent_all_children_index_list:
            child_name = individual_node_trees[parent_node]['children'][each_child]['name']
            child_no = 'child' + str(i)
            i += 1
            topo_dict_tree['children'][each_child_index]['children']['next_child_no'] = i
            topo_dict_tree['children'][each_child_index]['children'][child_no] = dict()
            topo_dict_tree['children'][each_child_index]['children'][child_no]['name'] = child_name
            #delete link in individual_node_trees dict once its added to topo_dict_tree dictionary
            # 1. child to parent
            # 2. parent to child
            delete_key_to_root_from_child (individual_node_trees = individual_node_trees, node = child_name, \
                                           parent_node = parent_node)
      for each_child_index in topo_dict_all_child_index_list:
         nxt_lvl_dict = topo_dict_tree['children'][each_child_index]
         add_nodes_to_topo_dict_tree(topo_dict_tree = nxt_lvl_dict, individual_node_trees = individual_node_trees)
   return 1
       
def delete_key_to_root_from_child (individual_node_trees = {}, node = '', parent_node = ''):
   del_yes = 0
   ## For the given \'node\' find its child which is same as given \'parent_node\' 
   ## and delete it from \'individual_node_trees\' dict 
   for child_index in individual_node_trees[node]['children'].keys():
      if individual_node_trees[node]['children'][child_index]['name'] == parent_node:
         del_yes = 1
         break
   if del_yes:
      individual_node_trees[node]['children'].pop(child_index)
   del_yes = 0
   ## For the given \'parent_node\' find its child which is same as given \'node\' 
   ## and delete it from \'individual_node_trees\' dict 
   for child_index in individual_node_trees[parent_node]['children'].keys():
      if individual_node_trees[parent_node]['children'][child_index]['name'] == node:
         del_yes = 1
         break
   if del_yes:
      individual_node_trees[parent_node]['children'].pop(child_index)
   return 1
def get_no_of_occurence_of_value_from_dict_as_dict(dict_ref):
    #Takes key value as input
    #returns key list of number of occurence of values
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
def get_topology_dict (topo_info):
   a = time.time()
   file_name = 'temp' + str(a)
   dir_name = os.getcwd()
   file_name = dir_name + '/' + file_name
   f = open (file_name , "w")
   f.write(topo_info)
   f.close()
   with open(file_name) as stream:
      try:
        topo_info1 =yaml.load(stream)
      except yaml.YAMLError as exc:
        os.remove(file_name)
        return 0
   os.remove(file_name)
   return topo_info1
