#!/bin/env python
###################################################################
# Author: Manas Kumar Dash (mdash)
# This lib contain various infra library functions
###################################################################

import re
import time
import logging
import collections
import copy
import os
import parsergen
import pdb
import unicon
import json

from ats.log.utils import banner
from ats.async_ import pcall
from unicon.eal.dialogs import Dialog
from unicon.eal.dialogs import Statement

from common_lib.utility_lib import *
from common_lib.tgn_lib import *

log = logging.getLogger(__name__)
log.setLevel(logging.DEBUG)
#ch = logging.StreamHandler()
#log.addHandler(ch)

class Class_common_device():
   def __init__(self, topo_dict = '', topo_name = '', pyats_dev_obj = '',  switch_mode = 'n9k', as_nu = '', \
                      tcam_config = '', write_erased_setup = 1, sw_version = '', issu_sw_version = ''):
       self.topo_dict = topo_dict
       self.topo_name = topo_name
       self.pyats_dev_obj = pyats_dev_obj
       self.as_nu = as_nu
       self.ospf_id = ""
       self.start_loop_bk = ""
       self.loop_bk_start_ip = ""
       self.run_conf_str = ""
       self.all_intf_list = []
       self.write_erase_done = 0
       self.switch_mode = switch_mode
       self.tcam_config = tcam_config
       self.sw_version = sw_version
       self.issu_sw_version = issu_sw_version
       self.write_erased_setup = write_erased_setup
       device_dict = topo_dict['devices'][topo_name]['peer_device']
       for peer_device in device_dict.keys():
         for link in device_dict[peer_device]['links'].keys():
            self.all_intf_list.append(device_dict[peer_device]['links'][link]['physical_interface'])

   def device_breakout_interfaces (self):
       pass_flag = 1
       for intf in self.all_intf_list:
          for ind_intf in self.pyats_dev_obj:
             if ind_intf.name.lower() == intf.lower():
                speed = ind_intf.speed
                if not breakout_intf(self.pyats_dev_obj, intf, speed):
                   pass_flag = 0
       return pass_flag

   def device_clean (self):
       if not self.write_erase_done:
          clean_all_configs(self.pyats_dev_obj)

def setup_testbed (device_obj_list, write_erase_flag = 0):

    log.info ('************Starting Test bed setup**************')
    all_pyats_device_list = []
    image_load_device_list = []
    switch_mode_list = []
    topo_dict = ''
    testbed = ''

    #Get all Pyats device list
    sw_version_list = []
    for device_obj in device_obj_list:
       all_pyats_device_list.append(device_obj.pyats_dev_obj)
       switch_mode_list.append(device_obj.switch_mode)
       topo_dict = device_obj.topo_dict
       testbed = device_obj.pyats_dev_obj.testbed
       if device_obj.sw_version:
          write_erase_flag = 1
          device_obj.write_erase_done = write_erase_flag
          image_load_device_list.append(device_obj.pyats_dev_obj)
          sw_version_list.append(device_obj.sw_version)

    # Connect All devices
    log.info('*********** Connecting all devices ***********')
    if not device_connect(all_pyats_device_list):
       log.info('One or more device connect Failed')
       return 0

    # If image is specified copy Image to switches
    if image_load_device_list:
       log.info('*********** Image copy to all devices ***********')
       if not download_image_to_switches(image_load_device_list, sw_version_list):
          log.info('Image copy Failed in one of switches during setup')
          return 0

    # Write erase testbed if required
    if write_erase_flag:
       log.info('*********** write erase switches ***********')
       write_erase_switches(all_pyats_device_list)
    else:
       #Clean config if write erased it will be skipped
       log.info('*********** Cleaning config on non write erased switches ***********')
       result = pcall(clean_config, device_class_obj = device_obj_list)

    log.info('*********** setting switch mode(3k or 9k) on devices ***********')
    set_switchmode_and_reload(all_pyats_device_list, switch_mode_list)

    # Configure Tcam
    log.info('*********** Configuring Tcam on switches ***********')
    for device_obj in device_obj_list:
        device_obj.pyats_dev_obj.configure(device_obj.tcam_config)
        op = device_obj.pyats_dev_obj.execute('show run | grep tcam')
        #Output check has to be done Accordingly Fail

    # set portmode if required
    log.info('*********** Setting portmode on switches and reloading ***********')
    set_portmode_reload_devices_parallel (all_pyats_device_list)

    #log.info('Sleeping for 60 Seconds, so that interfaces are UP......')
    time.sleep(60)

    # Breakout_all interfaces
    log.info('*********** Breaking out required interfaces **************')
    result = pcall(break_out_intf, device_class_obj = device_obj_list)
    if not result:
       log.info('Interface breakout Failed during setup')
       return 0

    # Check peering Links up
    log.info('Sleeping for 60 Seconds, so that CDP neighboring is populated ......')
    time.sleep(60)
    if not check_links_up(topo_dict, testbed):
       return 0

    return 1

def check_instance_of_Class_common_device(func_name):
   def inner_func(device_class_obj):
      if not isinstance(device_class_obj, Class_common_device):
        log.info ('Specified object is not derived from \'Class_common_device\' class')
        return 0
      return func_name(device_class_obj)
   return inner_func

@check_instance_of_Class_common_device
def clean_config (device_class_obj):
    device_class_obj.device_clean()
    return 1

@check_instance_of_Class_common_device
def load_config (device_class_obj):
    if len(device_class_obj.run_conf_str.splitlines()) > 100:
       load_config_string(device_class_obj.pyats_dev_obj.mgmt, device_class_obj.run_conf_str)
    else:
       load_config_string(device_class_obj.pyats_dev_obj, device_class_obj.run_conf_str)
    return 1

def load_config_string (device, conf_str, copy_r_s = 1, timeout_val = 120):
    if not conf_str:
       return 1
    dir_name = os.getcwd()
    file_name = dir_name + '/' + device.device.name + "_config"
    try:
       if device.device.custom['config_file_present']:
          f = open (file_name , "a+")
    except:
       device.device.custom['config_file_present'] = 1
       f = open (file_name , "w")
    f.write(conf_str)
    f.close()
    if timeout_val == 120:
       device.configure(conf_str)
    else:
       device.configure(conf_str, timeout = timeout_val)
    if copy_r_s:
       copy_run_to_startup(device)
    return 1

def break_out_intf (device_class_obj):
    return device_class_obj.device_breakout_interfaces()

def breakout_interfaces(device, intf_list):
    for intf in intf_list:
       for ind_intf in device:
          if ind_intf.name.lower() == intf.lower():
            speed = ind_intf.speed
            if not breakout_intf(device, intf, speed):
               return 0
    return 1

def get_running_bootflashimage(device):
    ab = get_sw_version(device)
    nx_os_file = ab['kick_file_name']
    match = re.search('bootflash:///(.*)', nx_os_file)
    if match:
       return match.group(1)
    else:
       log.info('Not able to find image filename form bootflash')
       return ''

def get_sw_version(device):
   oput = device.execute('show version | json')
   joput = json.loads(oput)
   show_ver_dict = {}
   show_ver_dict['kick_file_name'] = joput['kick_file_name']
   show_ver_dict['rr_sys_ver'] = joput['rr_sys_ver']
   return show_ver_dict

def get_remote_interface_name(device = '', intf_name = ''):
   for intf in device:
      if intf.name.lower() == intf_name.lower():
         intf_remote = intf.remote_interfaces.pop().name.lower()
         return intf_remote
   return ''

def check_fex_online (device, fex_number):
   i = 0
   while i <= 30:
     output = device.mgmt.execute('show fex ' + str(fex_number))
     lines = output.splitlines()
     for line in lines:
        if re.search('state: Online', line, re.I):
           return 1
     time.sleep(30)
     i += 1 
   log.info('Fex %r is not online even after 900 seconds', fex_number)
   return 0
     
def whether_xl_platform (device):
   output = device.execute('show version')
   found = 0
   lines = output.splitlines()
   for line in lines:
      match = re.search('CPU.*with (\d+) kB of memory', line, re.I)
      if match:
         found = 1
         mem = match.group(1) 
         if int(mem) < 5000000:
            return 0
   return found

def send_keep_alive_to_devices(device_list):
    for device in device_list:
       try:
         device.mgmt.sendline()
         device.mgmt.expect(r"# $", timeout=15)
         device.sendline()
         device.expect(r"# $", timeout=15)
       except:
         device_disconnect_mgmt([device])
         device.disconnect() 
         device_connect([device])

def device_disconnect(device_list):
   for device in device_list:
      if device.is_connected():
         device.disconnect()
   device_disconnect_mgmt(device_list)

def device_disconnect_mgmt (device_list):
   disconnected_list = []
   for device in device_list:
      if device.is_connected(alias = 'mgmt'):
         device.disconnect(alias = 'mgmt')
         disconnected_list.append(device)
   return disconnected_list

def delete_aa_config(func_name):
   def inner_func(device_list):
      for tb_device in device_list:
         conf_str = ''
         try:
           if tb_device.custom['del_aa_config']:
              tacacs_info = get_tacacs_svr_grps_configured(tb_device)
              for each_grp in tacacs_info.keys():
                 conf_str += 'aaa group server tacacs+ ' + str(each_grp) + '\n'
                 for each_svr in tacacs_info[each_grp]['svr_list']:
                    conf_str += 'no server ' + each_svr + '\n'
           load_config_string(tb_device, conf_str)
         except:
           return func_name(device_list)
      return func_name(device_list)
   return inner_func

@delete_aa_config
def device_connect_mgmt (device_list):
   for tb_device in device_list:
      try:  
         mgmt_ip = tb_device.connections['mgmt']['ip']
      except KeyError:
         continue 
      try:
         log.info('\nConnecting %r through mgmt\n', tb_device.name)
         tb_device.connect(alias = 'mgmt', via = 'mgmt')
      except:
         log.info('Unable to connect mgmt %r', tb_device.name)
         return 0
      if not tb_device.is_connected(alias = 'mgmt'):
         log.info('Unable to connect %r', tb_device.name)
         return 0
   return 1

def clear_line (device):   
   ts_ip = str(device.connections['a']['ip'])
   try:
     ts_port = device.connections['a']['port']
   except:
     return 1
   ts_line = ts_port - 2000
   try:
     ts_port1 = device.connections['b']['port']
     ts_line1 = ts_port1 - 2000
   except KeyError:
     ts_line1 = 0 #Line for sup-2
   ts_dev = ''
   for each_dev in device.testbed.devices.keys():
       if 'mgmt' in device.testbed.devices[each_dev].connections.keys():
          mgmt_ip = str(device.testbed.devices[each_dev].connections['mgmt']['ip'])
          if mgmt_ip == ts_ip:
              ts_dev = each_dev
              ts_tb_dev = device.testbed.devices[each_dev]
              break
   if ts_dev:
      if not ts_tb_dev.is_connected(alias = 'mgmt'):
         ret = device_connect_mgmt([ts_tb_dev])
         if not ret:
            log.info('Terminal server connection Failed')
            return 0
      else:
         try:
            ts_tb_dev.mgmt.sendline()
            ts_tb_dev.mgmt.expect(r'.*#$', timeout = 10)
         except:
            ts_tb_dev.disconnect(alias = 'mgmt')
            ret = device_connect_mgmt([ts_tb_dev])
            if not ret:
               log.info('Terminal server connection Failed')
               return 0
      i = 1
      try:
         max_iter = ts_tb_dev.custom['no_of_times_clear_line']
      except:
         max_iter = 2
      while (i <= int(max_iter)):
         dialog = Dialog ([
              [r'confirm', lambda spawn: spawn.sendline('y'), None, False, False],
         ])
         op = ts_tb_dev.mgmt.execute('clear counters', service_dialog=dialog, timeout=30) 
         time.sleep(2)
         op = ts_tb_dev.mgmt.execute('clear line ' + str(ts_line), service_dialog=dialog, timeout=30) 
         if ts_line1:
            op = ts_tb_dev.mgmt.execute('clear line ' + str(ts_line1), service_dialog=dialog, timeout=30) 
            time.sleep(2)
         i += 1
   else:
      log.info('Terminal server IP for %s is not defined in testbed', device.name)
      return 0

def device_connect (device_list, connect_mgmt = 1, save_mgmt_vrf_config = 1):
   for tb_device in device_list:
      try:
         port_mode = tb_device.custom['portmode']
      except:
         tb_device.custom['portmode'] = 'default'
      try:
         front_portmode = tb_device.custom['front_portmode']
      except:
         tb_device.custom['front_portmode'] = 'default'
      clear_line(tb_device) 
      try:
         tb_device.connect(prompt_recovery = True, learn_hostname = True)
      except:
         log.info('Unable to connect %r', tb_device.name)
         return 0
      if not tb_device.is_connected():
         log.info('Unable to connect %r', tb_device.name)
         return 0
      if tb_device.os != 'linux':
        tb_device.sendline('configure ; hostname ' + tb_device.name + ' ; end\n')
        tb_device.expect(r"# $", timeout=5)
        if tb_device.hostname != tb_device.name:
           tb_device.destroy()
           try:
              tb_device.connect(prompt_recovery = True, learn_hostname = True)
           except:
              log.info('Unable to connect %r', tb_device.name)
              return 0
        configure_mgmt_vrf(tb_device, save_config = save_mgmt_vrf_config)
   if tb_device.os != 'linux':
      if connect_mgmt:
         for tb_device in device_list:
            if not device_connect_mgmt([tb_device]):
               return 0
      for tb_device in device_list:
         if not check_core(tb_device):
            return 0
   return 1

def check_core (device):
    op = device.execute('show cores')
    return 1

def make_interface_default (device_handle, interface):
    conf_str = 'default interface ' + interface + '\n'
    device_handle.configure(conf_str)

def check_module_online (device_handle, module_nu, sleep_time = 120):
    cmd_line = 'show module ' + str(module_nu)
    i = 1 
    module_ok = 0
    while i <= 2:
      try:
        oput = device_handle.execute(cmd_line)
        time.sleep(5)
      except:
        oput = device_handle.execute(cmd_line)
      lines = oput.splitlines() 
      module_pres = 0
      module_ok = 0
      j = 0
      for line in lines:
        j += 1
        if re.search('Module-Type', line, re.I):
           module_pres = 1
           break
      if not module_pres:
         log.info('Module %r is not Listed for device %r', module_nu,device_handle.name) 
         return 0
      j += 1
      line = lines[j]
      if re.search('active|ok|standby', line, re.I):
         return 1
      if i < 2:
         time.sleep(sleep_time)
      i += 1
    if not module_ok:
       log.info('Module %r is not online for device %r', module_nu,device_handle.name)
       return 0
    return 1

def get_module_number (interface_nu):    
   match = re.search(r'(\d+)/(\d+)/(\d+)', interface_nu, re.I)
   if match:
      return match.group(1)
   match = re.search(r'(\d+)/(\d+)', interface_nu, re.I)
   if match:
      return match.group(1)
   return 0

def breakout_intf (device_handle, interface_nu, speed = ''):
   match = re.search(r'(\d+)/(\d+)/(\d+)', interface_nu, re.I)
   if not speed:
      for ind_intf in device_handle:
          if ind_intf.name.lower() == interface_nu.lower():
             speed = ind_intf.speed
             break
   if not speed:
      log.info('Not able to determine speed of interface %r for device %r', interface_nu, device_handle.name)
      return 0
   conf_str = ""
   if match:
      module_nu = str(match.group(1))
      if not check_module_online (device_handle, module_nu):
         return 0
      if re.search(r'10gig', speed, re.I):
         conf_s = 'interface breakout module ' + str(match.group(1)) + ' port ' + str(match.group(2)) + ' map 10g\n'
         device_handle.mgmt.configure(conf_s, timeout = 120)
      if re.search(r'25gig', speed, re.I):
         conf_s = 'interface breakout module ' + str(match.group(1)) + ' port ' + str(match.group(2)) + ' map 25g\n'
         device_handle.mgmt.configure(conf_s, timeout = 120)
      if re.search(r'50gig', speed, re.I):
         conf_s = 'interface breakout module ' + str(match.group(1)) + ' port ' + str(match.group(2)) + ' map 50g\n'
         device_handle.mgmt.configure(conf_s, timeout = 120)
      make_interface_default (device_handle, interface_nu)
      conf_str += 'interface ethernet ' + str(match.group(1)) + '/' + str(match.group(2)) + '/' + str(1) + '\n'
      conf_str += 'no shut\n'
      conf_str += 'interface ethernet ' + str(match.group(1)) + '/' + str(match.group(2)) + '/' + str(match.group(3)) + '\n'
      conf_str += 'no shut\n'
   else:
      match = re.search(r'(\d+)/(\d+)', interface_nu, re.I)
      module_nu = str(match.group(1))
      if not check_module_online (device_handle, module_nu):
         return 0
      make_interface_default (device_handle, interface_nu)
      conf_str += 'interface ethernet ' + str(match.group(1)) + '/' + str(match.group(2)) + '\n'
      conf_str += 'no shut\n'
   device_handle.mgmt.configure(conf_str)
   return 1
   
def delete_all_rpm_entries(device):
    oput = device.execute("show run rpm")
    lines = oput.splitlines()
    config_str = ""
    for line in lines:
       if re.search('route-map( )|ip prefix-list|ip community-list', line, re.I):
         config_str = config_str + 'no ' + line + '\n'
    if config_str:
       device.configure(config_str)

def delete_all_tcam_entries(device):
    oput = device.execute("show run | i 'tcam'")
    lines = oput.splitlines()
    config_str = ""
    for line in lines:
       if re.search('hardware access-list tcam', line, re.I):
          config_str = config_str + 'no ' + line + '\n'
       if re.search('ref-template|service-template', line, re.I):
          config_str = config_str + 'no ' + line + '\n'
    if config_str:
       device.configure(config_str)

def set_portmode_reload_devices_parallel_selective(device_list):
   reload_device_list = []
   for device in device_list:
       i = 0
       if not re.search ('default', device.custom['portmode'], re.I):
          device.configure('hardware profile portmode ' + device.custom['portmode'])
          copy_run_to_startup(device)
          reload_device_list.append(device)
          i = 1
       if not re.search ('default', device.custom['front_portmode'], re.I):
          device.configure('hardware profile front portmode ' + device.custom['front_portmode'])
          copy_run_to_startup(device)
          if not i:
            reload_device_list.append(device)
   if reload_device_list:
      reload_devices_parallel(reload_device_list)

def set_portmode_reload_devices_parallel(device_list):
   for device in device_list:
       if not re.search ('default', device.custom['portmode'], re.I):
          device.configure('hardware profile portmode ' + device.custom['portmode'])
          copy_run_to_startup(device)
       if not re.search ('default', device.custom['front_portmode'], re.I):
          device.configure('hardware profile front portmode ' + device.custom['front_portmode'])
          copy_run_to_startup(device)
   reload_devices_parallel(device_list)

def reload_devices_parallel(device_list, save_config = 1):
   mgmt_connected_list = []
   p_reload_list = []
   save_config_list = []
   for device in device_list:
      if device.is_connected(alias = 'mgmt'):
         device.disconnect(alias = 'mgmt')
         mgmt_connected_list.append(device)
      p_reload_list.append(1)
      save_config_list.append(save_config)
   pcall(reload_device, device = device_list, disconnect_before_reload = p_reload_list, save_config = save_config_list )
   #Disconnect devices after pcall for reload and reconnect again
   for device in device_list:
      device.disconnect()
   device_connect(device_list, connect_mgmt = 0, save_mgmt_vrf_config = save_config)
   device_connect_mgmt(mgmt_connected_list)
   return 1

def reload_device (device, save_config = 1, disconnect_before_reload = 0):
   if save_config:
     copy_run_to_startup(device)
   mgmt_connected = 0
   if device.is_connected(alias = 'mgmt'):
      device.disconnect(alias = 'mgmt')
      mgmt_connected = 1
   if disconnect_before_reload:
      device.disconnect()
      time.sleep(5)
      device.connect()
   rel_dialog = Dialog ([
      Statement(pattern = r'This command will reboot the system.* $',
              action = lambda spawn: spawn.sendline('y'), loop_continue = True, continue_timer = True),
      Statement(pattern = r'login: $',
              action = lambda spawn: spawn.sendline(device.tacacs['username']), loop_continue = True, continue_timer = True),
      Statement(pattern = r'assword:',
              action = lambda spawn: spawn.sendline(device.passwords['tacacs']), loop_continue = True, continue_timer = True),
   ])
   time_out = 900
   ret_val = 1
   output = device.execute('reload', reply=rel_dialog, timeout= time_out)
   if not re.search('assword.*', output, re.IGNORECASE):
      log.info('Unable to get password prompt after reload on %r', device.name)
      return 0
   if not check_system_ready(device):
      return 0
   if mgmt_connected:
      device_connect_mgmt([device]) 
   return 1

def check_system_ready(device):
   wait_time = 1200
   while wait_time > 0:
       try:
          output = device.execute('show logging logfile | grep -i ready', timeout = 60)
       except:
          output = ''
       if re.search('System ready', output):
          if device.is_ha:
             if not check_module_online (device, 27):
                log.info('Module 27 is not up after reload')
                return 0
             if not check_module_online (device, 28):
                log.info('Module 28 is not up after reload')
                return 0
          return 1
       else:
          log.info('\nSleeping for 30 seconds so that system can come to ready state\n')
          time.sleep(30)
          wait_time = wait_time - 30
   else:
       log.info('\n Looks like switch is not ready after reboot even after 20 minutes')
       return 0

def execute_cmd_parallel(device_list, cmd_list, timeout_val_list = []):
   pcall(exec_cmd_on_device, device = device_list, cmd_name = cmd_list, timeout_val_list = timeout_val_list)

def exec_cmd_on_device(device, cmd_name, timeout_val = 120):
   op = vpc_dev1.mgmt.execute(cmd_name, timeout = timeout_val)
   
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

def get_switch_platform (device):
    if re.search(r'TH-EOR', device.custom['platform'], re.I):
       return 'TH-EOR'
    if re.search(r'TH-TOR', device.custom['platform'], re.I):
       return 'TH-TOR'
    if re.search(r'TH2-TOR', device.custom['platform'], re.I):
       return 'TH2-TOR'
    if re.search(r'T3-TOR', device.custom['platform'], re.I):
       return 'T3-TOR'
    if re.search(r'T2-TOR', device.custom['platform'], re.I):
       return 'T2-TOR'
    if re.search(r'T2-EOR', device.custom['platform'], re.I):
       return 'T2-EOR'
    if re.search(r'TPLUS', device.custom['platform'], re.I):
       return 'TPLUS'
    if re.search(r'T2-9K-TOR', device.custom['platform'], re.I):
       return 'T2-9K-TOR'
    if re.search(r'T2-9300-TOR', device.custom['platform'], re.I):
       return 'T2-9300-TOR'
    if re.search(r'9200-TOR', device.custom['platform'], re.I):
       return '9200-TOR'
    return ''

def set_switchmode_and_reload (device_list, sw_mode_list):
    write_erase_device_list = []
    i = 0
    for device in device_list:
      sw_mode = sw_mode_list[i]
      if set_switchmode (device, sw_mode):
         write_erase_device_list.append(device)
      i += 1
    if len(write_erase_device_list):
      write_erase_switches(write_erase_device_list)
    return 1
       
def set_switchmode (device, sw_mode):
    log.info('setting switchmode for device %r', device.name)
    oput = device.execute("show system switch-mode", timeout = 60)
    write_erase_req = 0
    if re.search('Switch mode configuration is not applicable', oput, re.I):
       return write_erase_req
    if not re.search('system switch-mode ([a-zA-Z0-9]+)', oput, re.I):
       time.sleep(5)
       oput = device.execute("show system switch-mode", timeout = 60)
    if re.search('Switch mode configuration is not applicable', oput, re.I):
      return write_erase_req
    mode_as_required = 0 
    match = re.search('system switch-mode ([a-zA-Z0-9]+)', oput, re.I)
    if sw_mode.lower() == match.group(1).lower():
      mode_as_required = 1
    if re.search('write erase.*is required', oput, re.I):
      write_erase_req = 1
    if not mode_as_required:
       if re.search(r'9k', sw_mode, re.I):
          device.configure('system switch-mode n9k \n')
       else:
          device.configure('system switch-mode n3k \n')
       write_erase_req = 1
    return write_erase_req

def clean_all_configs (device):
    device_mgmt = ""
    if device.is_connected(alias = 'mgmt'):
       device_mgmt = device.mgmt
    else:
       device_mgmt = device
    delete_all_pos(device_mgmt)
    unconfigure_features_for_clean(device_mgmt)
    delete_all_vrfs_for_clean(device_mgmt)
    unconfigure_breakout_for_clean(device_mgmt)
    delete_all_Loopbacks(device_mgmt)
    delete_all_L3_address(device_mgmt)
    delete_all_tcam_entries(device_mgmt)
    delete_all_rpm_entries(device_mgmt)
    unconfig_ports_from_vlan(device_mgmt)
    delete_all_static_routes(device_mgmt)
    delete_all_monitor_sessions(device_mgmt)
    delete_all_qos_config(device_mgmt)
    delete_all_access_list(device_mgmt)
    return 1

def delete_all_access_list(device):
    oput = device.execute("show ip access-lists | no")
    lines = oput.splitlines() 
    conf_str = ''
    for line in lines:
      if re.search('IP access list', line, re.I):
         if not re.search('IP access list copp-system', line, re.I):
            match = re.search(r'IP access list (.*)', line, re.I)
            if match:
               acl_name = match.group(1)
               conf_str += 'no ip access-list ' + acl_name + '\n'
    oput = device.execute("show ipv6 access-lists | no")
    lines = oput.splitlines() 
    for line in lines:
      if re.search('IPv6 access list', line, re.I):
         if not re.search('IPv6 access list copp-system', line, re.I):
            match = re.search(r'IPv6 access list (.*)', line, re.I)
            if match:
               acl_name = match.group(1)
               conf_str += 'no IPv6 access-list ' + acl_name + '\n'
    if conf_str:
       device.configure(conf_str)

def delete_all_qos_config(device):
    oput = device.execute("show run ipqos")
    lines = oput.splitlines() 
    prev_conf_line = ''
    conf_str = ''
    for line in lines:
      if re.search('interface Ethernet|system qos', line, re.I):
         prev_conf_line = line
      if re.search('service-policy type', line, re.I):
         if not prev_conf_line:
            log.info('Not able to clear QOS config')
            return 0
         else:
            conf_str = prev_conf_line + '\n'
            conf_str += 'no ' + line + '\n'
            device.configure(conf_str)
    for line in lines:
      if re.search('^policy-map type', line, re.I):
         conf_str = 'no ' + line + '\n'
         device.configure(conf_str)
      if re.search('^congestion-control', line, re.I):
         conf_str = 'no ' + line + '\n'
         device.configure(conf_str)
      if re.search('^priority-flow-control', line, re.I):
         conf_str = 'no ' + line + '\n'
         device.configure(conf_str)
    for line in lines:
      if re.search('^class-map type', line, re.I):
         conf_str = 'no ' + line + '\n'
         device.configure(conf_str)

def delete_all_monitor_sessions (device):
    all_session_list = get_all_monitor_sessions(device)
    for each_session in all_session_list:
      conf_str = 'no monitor ' + each_session + '\n'
      device.configure(conf_str)

def get_all_monitor_sessions (device):
    oput = device.execute("show monitor session all")
    session_list = []
    if re.search('no sessions configured', oput, re.I):
       return session_list 
    else:
       lines = oput.splitlines() 
       for line in lines:
          match = re.search('session (\d+)', line, re.I)
          if match:
             session_list.append(match.group(0))
    return session_list 

def delete_all_pos (device):
    po_list = get_all_pos_configured (device)
    for po_no in po_list:
      conf_str = 'no interface ' + po_no + '\n'
      device.configure(conf_str, timeout = 120)

def get_all_pos_configured (device):
    po_list = []
    oput = device.execute("show port-channel database")
    lines = oput.splitlines() 
    for line in lines:
      match = re.search(r'port-channel(\d+)', line, re.I)
      if match:
        po_list.append(match.group(0))
    return po_list

def get_active_sup (device):
    if device.is_ha:
       oput = device.execute('show system redundancy status')
       standby = 0
       ha = 0
       lines = oput.splitlines() 
       for line in lines:
          match = re.search(r'This supervisor \((.*)\)', line, re.I)
          if match:
            return match.group(1)
       return ''
    else:
       return 'sup-1'

def get_all_configured_vlan_list(device):
    oput = device.execute("show vlan | end Vlan-mode")
    lines = oput.splitlines() 
    port_list = []
    vlan_no = ""
    vlan_list = []
    for line in lines:
       match = re.search(r'(\d+).*VLAN', line, re.I)
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
             if re.search(r'Eth', each_word, re.I):
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
      if re.search('vrf context', line, re.I):
         if not re.search('vrf context management', line, re.I):
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
      if re.search('interface breakout', line, re.I):
         config_str += 'no ' + line + '\n'
    if config_str:
       device.configure(config_str, timeout = 250)
    
def unconfigure_features_for_clean(device):
    conf_str = 'no feature vpc\n'
    conf_str += 'no feature nat\n'
    conf_str += 'no feature lacp\n'
    conf_str += 'no feature interface-vlan\n'
    conf_str += 'no feature bgp\n'
    conf_str += 'no feature ospf\n'
    conf_str += 'no feature ospfv3\n'
    conf_str += 'no feature isis\n'
    conf_str += 'no feature mpls static\n'
    conf_str += 'no feature mpls evpn\n'
    conf_str += 'no feature mpls segment-routing traffic-engineering\n'
    conf_str += 'no feature mpls segment-routing\n'
    conf_str += 'no feature-set mpls\n'
    conf_str += 'no install feature-set mpls\n'
    conf_str += 'no feature nv overlay\n'
    conf_str += 'no feature vn-segment-vlan-based\n'
    conf_str += 'no feature ngoam\n'
    conf_str += 'no nv overlay evpn\n'
    conf_str += 'no feature pim\n'
    conf_str += 'no feature private-vlan\n'
    conf_str += 'no feature vrrp\n'
    conf_str += 'no feature hsrp\n'
    device.configure(conf_str, timeout = 120)

def configure_mgmt_vrf (device, save_config = 1):
    mgmt_defined = 1
    try:
       mgmt_ip = str(device.connections['mgmt']['ip'])
    except KeyError:
       mgmt_defined = 0
    if mgmt_defined:
       mgmt_mask = device.connections['mgmt']['mask']
       mgmt_gw = device.connections['mgmt']['gw']
       conf_str = 'feature telnet\n'
       conf_str += 'interface mgmt0\n'
       conf_str += 'ip address ' +  mgmt_ip + ' ' + mgmt_mask + '\n'
       conf_str += 'no shut\n'
       conf_str += 'vrf context management\n'
       conf_str += 'ip route 0/0 ' + mgmt_gw + '\n'
       device.configure(conf_str)
       if save_config == 1:
          copy_run_to_startup(device)
    return 1

def perform_config_replace(device, file_name):   
    dialog = Dialog ([
         [r'Configure replace completed successfully.*# $', None, None, False, False],
         [r'.*FAILED.*# $', None, None, False, False],
    ])
    op = device.execute('configure replace ' + file_name, service_dialog=dialog, timeout=180)
    if not re.search('completed successfully', op, re.I):
       log.error('Config replace Failed')
       return 0
    return 1

def copy_run_to_startup(device):
    if not copy_run_to_file(device):
       log.info('Copy r s Failed on %r', device.name)
       return 0
    return 1

def copy_run_to_file(device, file_name = 'startup-config'):   
    dialog = Dialog ([
         [r'Copy complete.*# $', None, None, False, False],
         [r'Do you want to overwrite', lambda spawn: spawn.sendline('y'), None, True, True],
         [r'##############', None, None, True, True],
         [r'Configuration update aborted: system not ready', None, None, False, False]
    ])
    op = device.execute('copy running ' + file_name, reply=dialog, timeout=280)
    if re.search(r'Configuration update aborted', op, re.I):
       time.sleep(60)
       op = device.execute('copy running ' + file_name, reply=dialog, timeout=280)
       if not re.search(r'Copy complete', op, re.I):
          log.info('Copy of running config failed ')
          return 0
    else:
       if not re.search(r'Copy complete', op, re.I):
          log.info('Copy of running config failed ')
          return 0
    return 1

def write_erase_switches(device_list):
    mgmt_discon_list = device_disconnect_mgmt(device_list)
    if len(device_list) > 1:
       res_list = pcall(write_erase_switch, device = device_list, pcall = [1]*len(device_list))
       for res in res_list:
          if not res:
             return 0
    else:
       if not write_erase_switch(device_list[0]):
          return 0
    log.info('Reconnecting Devices after write erase========')
    for device in device_list:
        device.disconnect()
        if device in mgmt_discon_list:
           device_connect([device])
        else:
           device_connect([device], connect_mgmt = 0)
    return 1   

def write_erase_switch(device, pcall = 0):
    '''
     Function to do write erase of switch 
     called for parallely doing write erase on multiple switches.
    '''
    mgmt_disconnected = 0
    if device.is_connected(alias = 'mgmt'):
       device.disconnect(alias = 'mgmt')
       mgmt_disconnected = 1
    login_name = device.username
    password = device.enable_password
    device.execute('delete bootflash:cfg_before_write_erase' + ' no-prompt', timeout=60)
    if device.is_ha:
       device.execute('delete bootflash:cfg_before_write_erase' + ' no-prompt', timeout=60, target = 'standby')
       output = device.execute('\n', target = 'standby')
       #active_sup = get_active_sup(device)

    if not copy_run_to_file(device, 'cfg_before_write_erase'):
       return 0
    wr_erase_dialog = Dialog ([
          Statement(pattern=r'.*Do you wish to proceed anyway\? \(y/n\)\s*\[n\]',
                         action='sendline(y)',
                         loop_continue=False,
                         continue_timer=False)
    ])
    op = device.execute('write erase', reply=wr_erase_dialog, timeout=60)

    op = device.sendline('reload')
    if device.receive('This command will reboot the system', timeout = 60):
       output = device.receive_buffer()
       if re.search(r"WARNING: AUTO_COPY_IN_PROGRESS", output, re.I):
          op = device.sendline('n')
          device.receive('.*# $')
          log.info('Sleeping for 60 seconds so that image is copied to other sup')
          time.sleep(60)
          op = device.sendline('reload')
          device.receive('This command will reboot the system', timeout = 60)
       op = device.sendline('y')
       device.expect([r'CISCO',r'Cisco'], timeout=260)
       time.sleep(30)
    else:
       log.info('Write erase Failed on %r', device.name)
       return 0

    if device.is_ha:
       if id(device.b.spawn) == id(device.active.spawn):
          device.swap_roles()
    time_out = 1100
    dialog_wr = Dialog ([ 
    Statement(pattern = r'Abort.*Provisioning.*',
              action = lambda spawn: spawn.sendline('yes'), loop_continue = True, continue_timer = True),
    Statement(pattern = r'enforce secure password standard.*:',
              action = lambda spawn: spawn.sendline('no'), loop_continue = True, continue_timer = True),
    Statement(pattern = r'Enter the password for.*',
              action = lambda spawn: spawn.sendline(password), loop_continue = True, continue_timer = True),
    Statement(pattern = r'Confirm the password for.*',
              action = lambda spawn: spawn.sendline(password), loop_continue = True, continue_timer = True),
    Statement(pattern = r'Would you like to enter the basic configuration dialog.*:',
              action = lambda spawn: spawn.sendline('no'), loop_continue = True, continue_timer = True),
    Statement(pattern = r'login:',
              action = lambda spawn: spawn.sendline(login_name), loop_continue = True, continue_timer = True),
    Statement(pattern = r'assword:',
              action = lambda spawn: spawn.sendline(password), loop_continue = False, continue_timer = False),
    ])
    output = device.execute('', reply=dialog_wr, timeout= time_out) 
    if not re.search(r"Abort.*Provisioning.*", output, re.I):
       log.warning ("\nDid not get Abort POAP message even after %r seconds on %r", time_out, device.name)
       return 0
    if not re.search(r"login:", output, re.I):
       log.warning ("\nDid not get login prompt after poap on %r", device.name)
       return 0
    device.sendline('configure ; hostname ' + device.name + ' ; end\n')
    device.expect(r'.*# $', timeout=5) 
    if not pcall:
       device.disconnect()
       if mgmt_disconnected:
          device_connect([device])
       else:
          device_connect ([device], connect_mgmt = 0)
    return 1 

def get_cdp_neighbor (device_obj, intf):
    oput = device_obj.execute('show cdp neighbors interface ' + intf + '\n')
    neighbor = ''
    nei_int = ''
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
    host_str = get_words_list_from_line(line)[0]
    match = re.search(r'(.*)\(', host_str)
    if len(get_words_list_from_line(line)) > 1:
       words = get_words_list_from_line(line)
       nei_int = words[len(words) -1]
    else:
       line = lines[i+1]
       words = get_words_list_from_line(line)
       nei_int = words[len(words) -1]
    if match:
       neighbor = match.group(1)
    return (neighbor, nei_int)

def check_cdp_nbring(device1, device1_intf, device2, device2_intf):
    (remote, remote_cdp_int) = get_cdp_neighbor(device1, device1_intf)
    match = re.search(r'{0}'.format(device2.name) , remote, re.I)
    if not match:
       log.info('Remote Device is %r, Exepcted is %r', remote, device2.name)
       return 0
    remote_cdp_int = re.sub('[a-zA-Z]+', '', remote_cdp_int)
    device2_intf = re.sub('[a-zA-Z]+', '', device2_intf)
    match = re.search(r'{0}'.format(device2_intf) , remote_cdp_int, re.I)
    if not match:
       log.info('%r interface %r is not connected to %r interface %r\n',\
                device1.name, device1_intf, device2.name, device2_intf)
       return 0       
    return 1

def check_device_comb_in_list(device_combo_list, device1, device2):
    for combo in device_combo_list:
       if device1 in combo:
          if device2 in combo:
             return 1
    return 0

def check_links_up (topo_dict, tb_obj):
    checked_list = []
    fail_flag = 1
    for device in topo_dict['devices']:
       device_obj = tb_obj.devices[topo_dict['devices'][device]['node_name']]
       if not re.search(r'spirent|ixia', device_obj.type, re.I):
          for peer_d in topo_dict['devices'][device]['peer_device']:
              peer_d_obj = tb_obj.devices[topo_dict['devices'][peer_d]['node_name']]
              if not re.search(r'spirent|ixia', peer_d_obj.type, re.I):
                 #If combination is not checked already
                 if not check_device_comb_in_list(checked_list, device, peer_d):
                    comb_list = []
                    comb_list.append(device)
                    comb_list.append(peer_d)
                    checked_list.append(comb_list)
                    if not check_peering_links(topo_dict, device, peer_d, device_obj, peer_d_obj):
                       fail_flag = 0
    return fail_flag
        
def check_peering_links (topo_info, device1, device2, device1_obj, device2_obj = None):
    device1_2_device2_dict = topo_info['devices'][device1]['peer_device'][device2]
    device2_2_device1_dict = topo_info['devices'][device2]['peer_device'][device1]
    any_fail = 0
    log.info('Checking peering Links between %r and %r', device1, device2)
    for link in device1_2_device2_dict['links'].keys():
      local_intf = device1_2_device2_dict['links'][link]['physical_interface']
      for intf in device1_obj:
         physical_intf = intf.name
         #if re.search(physical_intf, local_intf, re.I):
         if physical_intf.lower() == local_intf.lower():
            local_intf = physical_intf
      remote_intf = device1_obj.interfaces[local_intf].remote_interfaces.pop().name
      remote_dev_obj = device1_obj.interfaces[local_intf].remote_devices.pop()
      if not check_cdp_nbring(device1_obj, local_intf, remote_dev_obj, remote_intf):
         log.info('CDP Neighboring will be checked again after 60 seconds')
         time.sleep(60)
         if not check_cdp_nbring(device1_obj, local_intf, remote_dev_obj, remote_intf):
            any_fail = 1
    if any_fail:
       return 0
    return 1

def download_image_to_switches(device_list, image_list, set_boot_var = 1):
    boot_var_set_list = []
    for device in device_list:
        boot_var_set_list.append(set_boot_var)
    res_list = pcall(copy_image, device_hdl = device_list, image_name = image_list, \
                     set_boot_var = boot_var_set_list)
    result = 1
    for res in res_list:
       if not res:
          log.info('Image copy Failed in one of the switches')
          return 0
    return result

def copy_image(device_hdl, image_name, set_boot_var = 1):
    testbed_obj = device_hdl.testbed
    if not image_name:
       log.info('image name has to be specified for copy')
       return 0
    scp_server = testbed_obj.servers['tftp_server']['address']
    user_name = testbed_obj.servers['tftp_server']['username']
    passwd = testbed_obj.servers['tftp_server']['password']
    dir_name, img_name = os.path.split(image_name)
    device_hdl.execute('delete bootflash:nxos.*' + ' no-prompt')
    if device_hdl.is_ha:
      device_hdl.execute('delete bootflash:nxos.*' + ' no-prompt', target='standby')
    output = device_hdl.execute('\n')
    output = device_hdl.execute('\n')
    dialog = Dialog ([
      Statement(pattern = r'Connection refused.*# $',
              action = None, loop_continue = False, continue_timer = False),
      Statement(pattern = r'Switch is booted with.*Overwriting.*# $',
              action = None, loop_continue = False, continue_timer = False),
      Statement(pattern = r'Not enough free memory either.*# $',
              action = None, loop_continue = False, continue_timer = False),
      Statement(pattern = r'No route to host.*# $',
              action = None, loop_continue = False, continue_timer = False),
      Statement(pattern = r'Copy complete.*Copy complete.*# $',
              action = None, args = None, loop_continue = False, continue_timer = False),
      Statement(pattern = r'Destination file is a boot image.Cannot overwrite.*# $',
              action = None, args = None, loop_continue = False, continue_timer = False),
      Statement(pattern = r'Are you sure',
              action = lambda spawn: spawn.sendline('yes'), loop_continue = True, continue_timer = True),
      Statement(pattern = r'Do you want to overwrite',
              action = lambda spawn: spawn.sendline('y'), loop_continue = True, continue_timer = True),
      Statement(pattern = r'password:',
              action = lambda spawn: spawn.sendline(passwd), loop_continue = True, continue_timer = True),
      Statement(pattern = r'Invalid command at.*# $',
              action = None, loop_continue = False, continue_timer = False),
    ])
    if whether_xl_platform(device_hdl):
       copy_str = 'copy scp://' + user_name + '@' + scp_server + image_name + ' bootflash: vrf management use-kstack'
       copy_str1 = 'copy scp://' + user_name + '@' + scp_server + image_name + ' bootflash: vrf management'
       copy_str2 = 'copy scp://' + user_name + '@' + scp_server + image_name + ' bootflash: vrf management'
    else:
       copy_str = 'copy scp://' + user_name + '@' + scp_server + image_name + ' bootflash: compact vrf management use-kstack'
       copy_str1 = 'copy scp://' + user_name + '@' + scp_server + image_name + ' bootflash: compact vrf management'
       copy_str2 = 'copy scp://' + user_name + '@' + scp_server + image_name + ' bootflash: vrf management'
    try:
       copy_str_success = copy_str
       oput = device_hdl.execute(copy_str_success,service_dialog=dialog, timeout=1800)
    except Exception as ex:
       if re.search('nvalid.*command', ex.args[1].args[1][0]):
          oput = 'Invalid command'
    if re.search(r'Invalid command', oput, re.I):
       output = device_hdl.execute('\n')
       try:
          copy_str_success = copy_str1
          oput = device_hdl.execute(copy_str_success,service_dialog=dialog, timeout=1800)
       except Exception as ex:
          if re.search('nvalid.*command', ex.args[1].args[1][0]):
             oput = 'Invalid command'
    if re.search(r'Invalid command', oput, re.I):
       output = device_hdl.execute('\n')
       try:
          copy_str_success = copy_str2
          oput = device_hdl.execute(copy_str_success, service_dialog=dialog, timeout=1800)
       except:
          oput = ''
    if re.search(r'Host key verification failed', oput, re.I):
       output = device_hdl.execute('\n')
       output = device_hdl.execute('\n')
       oput = device_hdl.execute(copy_str_success, service_dialog=dialog, timeout=1800)
    if re.search(r'Copy complete|Switch is booted with|Destination file is a boot image', oput, re.I):
       if set_boot_var:
          if not set_boot_img_var(device_hdl, img_name, copy_rs = 1):
             return 0
          log.info('Image copy complete on %r', device_hdl.name)
       return 1
    else:
       log.info('Image copy Failed on %r', device_hdl.name)
       return 0
    return 1

def check_ha_system(func_name):
   def inner_func(device):
      if device.is_ha:
         return 1
      return func_name(device)
   return inner_func

@check_ha_system
def check_spanning_tree_issu_impact (device):
    device.execute("\n", timeout = 60)
    oput = device.execute("show spanning-tree issu-impact", timeout = 60)
    if re.search(r'ISSU Cannot Proceed', oput, re.I):
       lines = oput.splitlines() 
       vlan_list = []
       i = 0
       j = 0
       k = 0
       for line in lines:
          if re.search(r'Port.*VLAN.*Role.*Type.*Instance.*', line, re.I):
             i = k + 2
          if re.search(r'Criteria 3 FAILED', line, re.I):
             j = k
          k += 1
       while i < j:
          line = lines[i] 
          words = get_words_list_from_line(line)
          try:
             vlan_no = words[5]
          except IndexError:
             i += 1
             continue
          if not vlan_no in vlan_list:
             vlan_list.append(vlan_no)
             device.configure('no spanning-tree vlan ' + vlan_no + '\n')
          i += 1
       time.sleep(15)
       oput = device.execute("show spanning-tree issu-impact")
       if re.search(r'ISSU Cannot Proceed', oput, re.I):
          log.info('Device is not ready with respect to spanning tree for issu')
          return 0
    return 1

def start_issu(device, issu_command):
    mgmt_disconnected = 0
    if device.is_connected(alias = 'mgmt'):
       device.disconnect(alias = 'mgmt')
       mgmt_disconnected = 1
    match_pat = 'Install has been successful.*# $'
    if device.is_ha:
       match_pat = 'Cisco Nexus Operating System.*# $'
    dialog = Dialog ([
       Statement(pattern = r'Installer will perform compatibility check first.*',
           action = None, loop_continue = True, continue_timer = True),
       Statement(pattern = r'Verifying image bootflash.*',
           action = None, loop_continue = True, continue_timer = True),
       Statement(pattern = r'Installer will perform compatibility check first.*',
           action = None, loop_continue = True, continue_timer = True),
       Statement(pattern = r'Do you want to continue with the installation.* $',
           action = lambda spawn: spawn.sendline('y'), loop_continue = True, continue_timer = True),
       Statement(pattern = r'Disruptive ISSU will be performed',
           action = lambda spawn: spawn.sendline('n'), loop_continue = False, continue_timer = False),
       Statement(pattern = r'Pre-upgrade check failed.*# $',
           action = None, loop_continue = False, continue_timer = False),
       Statement(pattern = match_pat, action = None, loop_continue = False, continue_timer = False),
       Statement(pattern = r'login: $', action = lambda spawn: spawn.sendline(device.tacacs['username']), 
                 loop_continue = True, continue_timer = True),
       Statement(pattern = r'assword:', action = lambda spawn: spawn.sendline(device.passwords['tacacs']), 
                 loop_continue = True, continue_timer = True),
    ])
    time_out = 3000
    ret_val = 1
    device.execute('show clock')
    output = device.execute(issu_command, service_dialog=dialog, timeout = time_out)
    if not re.search(r"Do you want to continue with the installation.*", output, re.I):
       log.warning ("\nDid not get continue prompt for ISSU\n")
       ret_val = 0
    if re.search(r'.*Disruptive ISSU will be performed.*', output, re.I):
       log.info('Not Able to proceed for ISSU due to error')
       ret_val = 0
    if re.search(r'Pre-upgrade check failed', output, re.I):
       log.info('Not Able to proceed for ISSU due to error pre upgrade check error')
       return 0
    
    device_reloaded = 0
    if ret_val:
       if not re.search(r'.*login:', output, re.I):
          try:
            log.info('Transmitting new line and receiving output for 60 sec to check whether its rebooting')
            device.transmit('\n')
            device.receive(r'nopattern^', timeout = 60)
            rec_buff = device.receive_buffer()
            if re.search(r'cisco', rec_buff, re.I):
               device.transmit('\n')
               device.receive(r'login:', timeout = 1000)
            if re.search(r'kexec: Starting new kernel', rec_buff, re.I):
               device.transmit('\n')
               device.receive(r'login:', timeout = 180)
            #If install success message is there its same major version upgrade manual reboot is required
            elif re.search(r'Install has been successful', output, re.I):
               log.info('\n\nReloading switch as its same major release upgrade\n\n')
               if not reload_device (device, save_config = 0, disconnect_before_reload = 0):
                  return 0
               device_reloaded = 1
          except:
            #If install success message is there its same major version upgrade manual reboot is required
            if re.search('Install has been successful', output):
               log.info('\n\nEXCEPTION Reloading switch as its same major release upgrade\n\n')
               if not reload_device (device, save_config = 0, disconnect_before_reload = 0):
                  return 0
               device_reloaded = 1
            else:
               log.info('Did not get login prompt after issu')
               ret_val = 0
    if device_reloaded:
       device.execute('show version')
       return 1
    if not device.is_ha:
       log.info('Disconnecting device')
       device.disconnect()
       log.info('sleeping for 15 Seconds')
       time.sleep(15)
       device.connect()
       targ = 'active'
    else:
       # For modular we need to check whether standby is successfully upgraded 
       match_pat = 'Install has been successful.*# $'
       dialog = Dialog ([
         Statement(pattern = match_pat, action = None, loop_continue = False, continue_timer = False),
         Statement(pattern = r'login: $', action = lambda spawn: spawn.sendline(device.tacacs['username']), 
                 loop_continue = True, continue_timer = True),
         Statement(pattern = r'assword:', action = lambda spawn: spawn.sendline(device.passwords['tacacs']), 
                 loop_continue = True, continue_timer = True),
       ])
       time_out = 3000
       ret_val = 1
       log.info('Expecting prompts on standby\n')
       output = device.execute('', service_dialog=dialog, timeout= 3000, target='standby')
       if not re.search(r'.*login:', output, re.I):
         try:
           device.sendline(target='standby')
           device.expect(r'login:', timeout = 400, target='standby')
         except TimeoutError as err:
           log.info('Did not get login prompt after issu on secondary')
           ret_val = 0
       if ret_val:
          log.info('Disconnecting device')
          device.disconnect()
          log.info('sleeping for 15 Seconds')
          time.sleep(15)
          device.connect()
    if not check_system_ready(device):
       log.info('System is not ready afetr ISSU')
       return 0
    device.execute('show version')
    if re.search('non-disruptive', issu_command, re.I):
       oput = device.execute('show install all status')
       if not re.search(r'.*Install has been successful.*', oput, re.I):
         log.info('ISSU is not successful on %r, please check logs', device.name)
         ret_val = 0
       time_taken_for_issu(device)
    if mgmt_disconnected:
       if not device_connect_mgmt([device]):
          log.info('Unable to connect to device %r through mgmt after issu', device.name)
          ret_val = 0
    return ret_val

def start_nd_issu (device, issu_image):
    issu_cmd = 'install all nxos bootflash:' + issu_image + ' non-disruptive'
    ret_val = 1
    if not start_issu(device, issu_cmd):
       ret_val = 0
       log.info('ISSU Failed on %r, Check Logs', device.name)
    return ret_val

def perform_disruptive_issu (device_hdl = '', image_name = '', img_copy = 1, down_grade = 0):
    if img_copy:
       if not copy_image(device_hdl, image_name, set_boot_var = 0):
          return 0
    dir_name, issu_image_name = os.path.split(image_name)
    if down_grade:
       issu_cmd = 'install all nxos bootflash:' + issu_image_name + ' bios-force'
    else:
       issu_cmd = 'install all nxos bootflash:' + issu_image_name
    if not start_issu(device_hdl, issu_cmd):
       log.info('ISSU Failed on %r, Check Logs', device_hdl.name)
       return 0
    return 1

def check_stp_impact(func_name):
   def inner_func( **kwargs):
      if not check_spanning_tree_issu_impact (kwargs['device_hdl']):
         log.info('%r is not ready for ND issu', kwargs['device_hdl'].name)
         return 0
      return func_name(**kwargs)
   return inner_func

@check_stp_impact    
def perform_nd_issu (device_hdl = '', tgn_hdl = '', image_name = '', img_copy = 1,\
                                   tgn_traffic_dict = {}, strm_name_list = []):
    if img_copy:
       if not copy_image(device_hdl, image_name, set_boot_var = 0):
          return 0
    dir_name, issu_image_name = os.path.split(image_name)
    if tgn_hdl:
       port_hdl_list = []
       str_id_list = []
       log.info('Starting Traffic on TGNs')
       port_hdl_list = get_tgn_port_hdl_list_from_strm_name_list(tgn_traffic_dict, strm_name_list = strm_name_list)
       str_id_list = get_tgn_strm_id_list_from_name_list(tgn_traffic_dict, strm_name_list = strm_name_list)
       tgn_start_traffic (tgn_hdl = tgn_hdl, port_hdl_list = port_hdl_list, stream_list = str_id_list)
    #Now Start ND ISSU on switches
    if not start_nd_issu(device_hdl, issu_image_name):
       log.info('ISSU FAILED on %r', device_hdl.name)
       if tgn_hdl:
          tgn_stop_traffic_on_ports (tgn_hdl = tgn_hdl, port_hdl_list = port_hdl_list)
       return 0
    if tgn_hdl:
       log.info('Stopping Traffic on TGNs')
       tgn_stop_traffic_on_ports (tgn_hdl = tgn_hdl, port_hdl_list = port_hdl_list)
       time.sleep(10)
       traffic_results = tgn_get_traffic_stats_for_port(tgn_hdl = tgn_hdl, port_hdl = port_hdl_list)
       if not tgn_verify_traffic(tgn_hdl, tgn_traffic_dict, traffic_results, \
              src_port_hdl_list = port_hdl_list, strm_name_list = strm_name_list):
          log.info('Traffic drop seen during ISSU')
          return 0
    return 1

@check_ha_system
def time_taken_for_issu (device):
    device.configure('feature bash-shell\n')
    oput = device.execute('show install all time-stats')
    if re.search('Invalid command', oput, re.I):
       oput = device.execute('run bash cat /mnt/pss/installer.log | grep -i control')
    match = re.search(r'Total time taken between control plane being down and box online: (\d+) seconds', oput, re.I)
    if match:
       log.info ('ISSU control plane down time %r', match.group(1))
       return match.group(1)
    else:
       log.info('Not able to determine control plane down time')
       return 0

#To get physical interface and other info
# input arg - 
# device - device obj
# link_name - defined as per testbed
# return vale : dict
#  local_physical intf
#  remote_physicalintf
#  remotedevice hostname
def get_intf_info_from_link_name (device, link_name):
   physical_intf = ''
   return_info = {}
   for intf in device:
      if link_name == intf.link.name:
         physical_intf = intf.name
         return_info['local_physical_intf'] = physical_intf
         return_info['remote_physical_intf'] = intf.remote_interfaces.pop().name
         return_info['remote_device_name'] = intf.remote_devices.pop().name
         break
   if not physical_intf:
      log.info('Link %r not found in device %r', link_name, device.name)
   return return_info

#Following will create a dict in below format
'''
devices:
  TGN2:
    node_name:  "tgn1"
    peer_device:
      CE2:
        nu_of_links:  "1"
        links:
          link_1:
            physical_interface:  "9/1"   
          link_2:
            physical_interface:  "9/2"   
  CE2:
    node_name:  "node08"
    peer_device:
      CE2:
        nu_of_links:  "1"
        links:
          link_1:
            physical_interface:  "ethernet 1/1"
          link_2:
            physical_interface:  "ethernet 1/2"
'''
def build_topology_dict (topology_dict = {}, testbed = '', dev_topo_name = '', dev_tb_name = '', peerdev_topo_name = '', \
                         peerdev_tb_name = '', link_name_list = []):

    if not isinstance(topology_dict, dict):
       log.info('topology_dict argument is not instance of dict')
       return 0
    if not 'devices' in topology_dict.keys():
       topology_dict['devices'] = {}

    if not dev_topo_name in topology_dict['devices'].keys():
       topology_dict['devices'][dev_topo_name] = {}
       topology_dict['devices'][dev_topo_name]['node_name'] = dev_tb_name
    if not peerdev_topo_name in topology_dict['devices'].keys():
       topology_dict['devices'][peerdev_topo_name] = {}
       topology_dict['devices'][peerdev_topo_name]['node_name'] = peerdev_tb_name
    if not 'peer_device' in topology_dict['devices'][dev_topo_name].keys():
       topology_dict['devices'][dev_topo_name]['peer_device'] = {}
    topology_dict['devices'][dev_topo_name]['peer_device'][peerdev_topo_name] = {}
    topology_dict['devices'][dev_topo_name]['peer_device'][peerdev_topo_name]['links'] = {}
    if not 'peer_device' in topology_dict['devices'][peerdev_topo_name].keys():
       topology_dict['devices'][peerdev_topo_name]['peer_device'] = {}
    topology_dict['devices'][peerdev_topo_name]['peer_device'][dev_topo_name] = {}
    topology_dict['devices'][peerdev_topo_name]['peer_device'][dev_topo_name]['links'] = {}
    dev_tb_obj = testbed.devices[dev_tb_name]
    i = 1
    for each_link in link_name_list:
        info_d = {}
        info_d = get_intf_info_from_link_name(dev_tb_obj, each_link)
        if not info_d:
           log.info('Link name %r is not listed in testbed either for %r or %r', each_link, dev_tb_name, peerdev_tb_name)
           return 0
        intf_name = info_d['local_physical_intf']
        remote_intf_name = info_d['remote_physical_intf']
        remote_d = info_d['remote_device_name']
        if not remote_d == peerdev_tb_name:
           log.info('Link name %r is not listed in testbed for %r and %r', each_link, dev_tb_name, peerdev_tb_name)
           return 0
        topology_dict['devices'][dev_topo_name]['peer_device'][peerdev_topo_name]['links']['link_' + str(i)] = {}
        topology_dict['devices'][dev_topo_name]['peer_device'][peerdev_topo_name]['links']['link_' + str(i)]['physical_interface'] = intf_name
        topology_dict['devices'][peerdev_topo_name]['peer_device'][dev_topo_name]['links']['link_' + str(i)] = {}
        topology_dict['devices'][peerdev_topo_name]['peer_device'][dev_topo_name]['links']['link_' + str(i)]['physical_interface'] = remote_intf_name
        i += 1
    return 1

#This Function will return configured Tacacs servers in side configured TACACS Groups
def get_tacacs_svr_grps_configured(device):
    try:
       oput = device.execute('show tacacs-server groups | json')
    except:
       return {}
    try:
       joput = json.loads(oput)
    except:
       return {}
    return_dict = {}
    try:
       if isinstance(joput['TABLE_group']['ROW_group'], list):
          for each_grp in joput['TABLE_group']['ROW_group']:
              grp_name = each_grp['group_name']
              return_dict[grp_name] = {}
              return_dict[grp_name]['svr_list'] = []
              try:
                 if isinstance(each_grp['TABLE_server']['ROW_server'], list):
                    for each_svr in each_grp['TABLE_server']['ROW_server']:
                       svr_ip = each_svr['server_ip']
                       return_dict[grp_name]['svr_list'].append(svr_ip)
                 else:
                    each_grp['TABLE_server']['ROW_server']['server_ip']
                    return_dict[grp_name]['svr_list'].append(svr_ip)
              except:
                 pass
       else:
          grp_name = joput['TABLE_group']['ROW_group']['group_name']
          return_dict[grp_name] = {}
          return_dict[grp_name]['svr_list'] = []
          try:
             if isinstance(joput['TABLE_group']['ROW_group']['TABLE_server']['ROW_server'], list):
                for each_svr in joput['TABLE_group']['ROW_group']['TABLE_server']['ROW_server']:
                   svr_ip = each_svr['server_ip']
                   return_dict[grp_name]['svr_list'].append(svr_ip)
             else:
                svr_ip = joput['TABLE_group']['ROW_group']['TABLE_server']['ROW_server']['server_ip']
                return_dict[grp_name]['svr_list'].append(svr_ip)
          except:
             pass
    except:
       pass
    return return_dict

def set_boot_img_var(device, img_name, copy_rs = 1):
   dir_name, img_name = os.path.split(img_name)
   op = device.configure('boot nxos ' + img_name + '\n', timeout = 240)
   if re.search(r'Corrupted image', op, re.I):
      log.info('Copied image is Corrupted %r', img_name)
      return 0
   if copy_rs:
      copy_run_to_startup(device)
   return 1
