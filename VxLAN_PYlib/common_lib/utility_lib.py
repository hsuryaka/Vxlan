#!/bin/env python
###################################################################
# Author: Manas Kumar Dash (mdash)
# This lib contain various utility library functions 
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

from ats.log.utils import banner
from ats.async_ import pcall

from common_lib.infra_lib import *

log = logging.getLogger(__name__)
log.setLevel(logging.DEBUG)
def check_stop_criteria(file_name):
    f = open (file_name, "r")
    content = f.read()
    f.close()
    flag = 0
    match = re.search('(\d+)', content, re.IGNORECASE)
    if match:
       flag = match.group(1)
    if not int(flag):
      return 0
    else:
      return 1
    
def sleep_till_interrupted(device_list = []):
   i = 1
   f = open ("/ws/mdash-bgl/pyats/users/mdash/jobs/temp.txt", "w")
   f.write("0")
   f.close()
   while True:
      if not i % 5:
         send_keep_alive_to_devices(device_list)
      content = ''
      f = open ("/ws/mdash-bgl/pyats/users/mdash/jobs/temp.txt", "r")
      content = f.read()
      f.close()
      flag = 0
      match = re.search('(\d+)', content, re.IGNORECASE)
      if match:
         flag = match.group(1)
      if not int(flag):
        log.info ('Continueing Sleep for 30 Secs')
        time.sleep(30)
      else:
        break
      i += 1

def get_value_from_command_arg (arg_list, arg_name = 'issu_image'):
   #User passess --issu_image "nxos.9.2.2.17.bin.upg"
   arg_value = ''
   i = 0 
   index_found = 0
   arg_name = '--' + arg_name
   while i < len(arg_list):
       if arg_name == arg_list[i]:
          index_found = 1
          break
       i += 1
   if index_found:
       try:
          arg_value = arg_list[i+1]
       except IndexError:
          arg_value = ''
   return arg_value

def get_words_list_from_line(line):
    line = line.strip()
    words = re.split(r'\s+', line)
    return words

def check_any_zero_val_in_list(list_str):
    for elm in list_str:
       if not elm:
          return 1
    return 0

def string_is_ip_address (validate_string):
   try:
      rowPos = ipaddress.ip_address(validate_string)
   except ValueError:
      return 0 
   return 1

def correct_octet(octect_val_list, oct_no = 3, base_int = 10, max_val = 255):
   if not base_int == 10:
      if not base_int == 16:
         log.info('Base_int val should be 10 or 16')
         return 0
   for i in range(oct_no - 1, -1, -1):
     if base_int == 10:
        oct_val = octect_val_list[i]
        if int(str(oct_val)) > max_val:
           octect_val_list[i] = 0
           if i > 0:
              oct_val = octect_val_list[i - 1]
              octect_val_list[i-1] = int(str(oct_val)) + 1
     if base_int == 16:
        oct_val = octect_val_list[i]
        if int(str(oct_val), 16) > max_val:
           octect_val_list[i] = '0'
           if i > 0:
              oct_val = octect_val_list[i - 1]
              octect_val_list[i-1] = hex(int(str(oct_val), 16) + 1).lstrip('0x')
   return 1
def get_next_mac (mac_add):
   mac_add_oct_list = re.split(r':', mac_add)
   oct_no = 6
   mac_add_oct_list[oct_no - 1] = hex(int(str(mac_add_oct_list[oct_no - 1]), 16) + 1).lstrip('0x')
   correct_octet(mac_add_oct_list, oct_no = oct_no, base_int = 16, max_val = 255)
   new_mac = ''
   for oct_val in mac_add_oct_list:
      new_mac = new_mac + str(oct_val) + ':'
   new_mac = new_mac.strip(':')
   return new_mac  

def check_ip_address(func_name):
   def inner_func(*args, **kwargs):
      ret_val = string_is_ip_address(args[0])
      if not ret_val:
         log.info('%r is not a valid IPV4/V6 Address', args[0])
         return 0
      return func_name(*args, **kwargs)
   return inner_func

@check_ip_address
def get_next_lpm_ip (start_ip, oct_no = 3): 
   if oct_no > 4 or oct_no < 1:
      return 0
   incr_nu = pow(256, 4 - oct_no)
   return (str(ipaddress.IPv4Address(start_ip) + incr_nu))

@check_ip_address
def get_next_host_ip (start_ip): 
   return (str(ipaddress.IPv4Address(start_ip) + 1))

@check_ip_address
def get_next_lpm_ipv6 (start_ipv6, oct_no = 4):
   if oct_no > 8 or oct_no < 1:
      return 0
   incr_nu = pow(65536, 8 - oct_no)
   return (str(ipaddress.IPv6Address(start_ipv6) + incr_nu))

@check_ip_address
def get_next_host_ipv6 (start_ipv6):
   return (str(ipaddress.IPv6Address(start_ipv6) + 1))

def get_test_case_list(tclist_str):
    se = set(tclist_str)
    l = list(se)
    l.remove(',')
    return l

def print_dict_in_file (d, file_name = ''):
    f = open (os.environ['HOME'] + "temp.txt", "w")
    print_dict(d, file_name = f)
    f.close()

def print_dict(d, file_name = '', depth=0, print_yes = 0):
    for k,v in sorted(d.items(),key=lambda x: x[0], reverse=True):
       if isinstance(v, dict):
          str_p = "  "*depth
          str_p += str(k) + ":"
          log.info('%r',str_p)
          if print_yes:
             print(str_p)
          if file_name:
            file_name.write(str_p + '\n')
          print_dict(v, file_name = file_name, depth = depth+1, print_yes = print_yes)
       else:
          str_p = "  "*depth + k + ":" + '  ' + str(v)
          log.info('%r',str_p)
          if print_yes:
            print(str_p)
          if file_name:
            file_name.write(str_p + '\n')
