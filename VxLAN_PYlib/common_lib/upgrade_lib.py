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
from common_lib.infra_lib import *

log = logging.getLogger(__name__)
log.setLevel(logging.DEBUG)
#ch = logging.StreamHandler()
#log.addHandler(ch)

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

class bios_extraction:
    fail_flag = 0

def check_bios_unpacked(spawn):
    lines = spawn.buffer.splitlines() 
    flag = 0
    bios_info_found = 0
    for line in lines:
       if re.search('Running-Version.*New-Version', line):
          flag = 1 
       if flag:
          if re.search('bios', line):
             bios_info_found = 1
             words = get_words_list_from_line(line)
             if len(words) != 5:
                log.info('BIOS Line doesn\'t have 5 columns FAIL')
                bios_extraction.fail_flag = 1
                spawn.sendline('n')
                break
             else:
                if not re.search('v.* v.*', line):
                   log.info('BIOS is not extracted FAIL')
                   bios_extraction.fail_flag = 1
                   spawn.sendline('n')
                   break
    else:
       if not bios_info_found:
          bios_extraction.fail_flag = 1
          spawn.sendline('n')
       spawn.sendline('y')
       
def start_issu(device, issu_command):
    mgmt_disconnected = 0
    if device.device.is_connected(alias = 'mgmt'):
       device.disconnect(alias = 'mgmt')
       mgmt_disconnected = 1
    match_pat = 'Install has been successful.*# $'
    if device.is_ha:
       match_pat = 'Cisco Nexus Operating System.*# $'
    dialog = Dialog ([
       Statement(pattern = r'Installer will perform compatibility check first',
           action = None, loop_continue = True, continue_timer = True),
       Statement(pattern = r'Verifying image bootflash.*',
           action = None, loop_continue = True, continue_timer = True),
       Statement(pattern = r'Installer will perform compatibility check first.*',
           action = None, loop_continue = True, continue_timer = True),
       Statement(pattern = r'Do you want to continue with the installation.* $',
           action = check_bios_unpacked, loop_continue = True, continue_timer = True),
       Statement(pattern = r'Disruptive ISSU will be performed',
           action = lambda spawn: spawn.sendline('n'), loop_continue = False, continue_timer = False),
       Statement(pattern = r'OBFL device not found.*',
           action = None, loop_continue = False, continue_timer = False),
       Statement(pattern = r'Invalid option.*specified  bios-force.*# $',
           action = None, loop_continue = False, continue_timer = False),
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
    op = device.execute('show clock', timeout = 60)
    if not re.search('Time source is', op):
       device.execute('\n', timeout = 60)
       time.sleep(5)
    try:
       output = device.execute(issu_command, service_dialog=dialog, timeout = time_out)
    except:
       if mgmt_disconnected:
          if not device_connect_mgmt([device]):
             log.info('Unable to connect to device %r through mgmt after Fail ', device.name)
       return 0, 'TIMEOUT EXCEPTION'
    msg = 'pass'
    #Commented Here Added belowi as below was overwriting msg variable
    #if re.search(r"OBFL device not found.*", output, re.I):
    #   log.info('Got OBFL device not found message')
    #   ret_val = 0
    #   msg = 'Got OBFL device not found message'
    if not re.search(r"Do you want to continue with the installation.*", output, re.I):
       log.warning ("\nDid not get continue prompt for ISSU\n")
       msg = 'Did not get continue prompt for ISSU'
       ret_val = 0
    if re.search(r'.*Disruptive ISSU will be performed.*', output, re.I):
       log.info('Not Able to proceed for ISSU due to error')
       msg = 'Disruptive ISSU will be performed'
       ret_val = 0
    if re.search(r'Pre-upgrade check failed', output, re.I):
       if re.search(r'SRG extraction failed', output, re.I):
          log.info('SRG Extraction failed during install all\n')
          msg = 'SRG Extraction failed'
       else:
          log.info('Not Able to proceed for ISSU due to error pre upgrade check error')
          msg = 'Pre-upgrade check failed'
       ret_val = 0
    if re.search(r"OBFL device not found.*", output, re.I):
       log.info('Got OBFL device not found message')
       ret_val = 0
       msg = 'Got OBFL device not found message'
    if re.search(r"Invalid option.*specified  bios-force.*", output, re.I):
       log.info('Got Invalid option bios-force')
       ret_val = 0
       msg = 'Got Invalid option bios-force'
    if not ret_val: 
       if mgmt_disconnected:
          if not device_connect_mgmt([device]):
             log.info('Unable to connect to device %r through mgmt after Fail ', device.name)
       return (0, msg)
    if bios_extraction.fail_flag:
       return (0, 'BIOS_EXTRACTION_FAIL')
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
                  return (0, msg)
               device_reloaded = 1
          except:
            #If install success message is there its same major version upgrade manual reboot is required
            if re.search('Install has been successful', output):
               log.info('\n\nEXCEPTION Reloading switch as its same major release upgrade\n\n')
               if not reload_device (device, save_config = 0, disconnect_before_reload = 0):
                  return (0, msg)
               device_reloaded = 1
            else:
               log.info('Did not get login prompt after issu')
               ret_val = 0
    if device_reloaded:
       device.execute('show version')
       if mgmt_disconnected:
          if not device_connect_mgmt([device]):
             log.info('Unable to connect to device %r through mgmt after reload', device.name)
             return (0, msg)
       return (1, msg)
    if not device.is_ha:
       log.info('Disconnecting device')
       device.disconnect()
       log.info('sleeping for 30 Seconds')
       time.sleep(30)
       # some times system takes time to come config prompt so fails, so adding sleep and connecting again
       i = 1
       while i <= 4:
          i += 1
          try:
             device.connect()
          except:
             log.info('Did not connect , so sleeping for 60 seconds before connecting again')
             time.sleep(60)
             log.info('\nDisconnecting and Destroying\n')
             device.disconnect()
             device.destroy()
             time.sleep(5)
             #device.connect() 
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
          # some times system takes time to come config prompt so fails, so adding sleep and connecting again
          i = 1
          while i <= 4:
             i += 1
             try:
                device.connect()
             except:
                log.info('Did not connect EOR , so sleeping for 60 seconds before connecting again')
                time.sleep(60)
                log.info('\nDisconnecting and Destroying\n')
                device.disconnect()
                device.destroy()
                time.sleep(5)
                #device.connect() 
    if not check_system_ready(device):
       log.info('System is not ready after ISSU')
       msg = 'System is not ready after ISSU'
       return (0, msg)
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
    return (ret_val, msg)

def start_nd_issu (device, issu_image):
    issu_cmd = 'install all nxos bootflash:' + issu_image + ' non-disruptive'
    retval, temp = start_issu(device, issu_cmd)
    if not retval:
       log.info('ISSU Failed on %r, Check Logs', device.name)
    return retval
'''
Module 1: Refreshing compact flash and upgrading bios/loader/bootrom/power-seq.
Warning: please do not remove or power off the module at this time.
Note: Power-seq upgrade needs a power-cycle to take into effect.
On success of power-seq upgrade, SWITCH OFF THE POWER to the system and then, power it up.
[########################################] 100% -- SUCCESS
'''
#Removed image_name attribute
def perform_disruptive_issu (device_hdl = '', img_copy = 1, bios_down_grade = 0, **kwargs):
    try:
       nxos = kwargs['nxos']
    except:
       nxos = ''
    try:
       kickimg = kwargs['kickimg']
    except:
       kickimg = ''
    try:
       sysimg = kwargs['sysimg']
    except:
       sysimg = ''
    try:
       compact = kwargs['compact']
    except:
       compact = 1
    try:
       no_save = kwargs['no_save']
    except:
       no_save = 0
       
    if kickimg:
       if not sysimg:
          log.info('kickstart image is specified but system image is not specified')
          return 0
    if sysimg:
       if not kickimg:
          log.info('System image is specified but kickstart image is not specified')
          return 0
    if not nxos and not sysimg:
       log.info('None of the image is specified')
       return 0
    if nxos and sysimg:
       log.info('Either nxos or kickstart image needs to be specified')
       return 0
    if img_copy:
       if nxos:
          if not copy_image(device_hdl, nxos, set_boot_var = 0):
             return 0
       if kickimg:
          if not copy_image(device_hdl, kickimg, set_boot_var = 0, compact = 0):
             return 0
       if sysimg:
          if not copy_image(device_hdl, sysimg, set_boot_var = 0, delete_image = 0, compact = 0):
             return 0
    if nxos: 
       dir_name, issu_image_name = os.path.split(nxos)
       if bios_down_grade:
          issu_cmd = 'install all nxos bootflash:' + issu_image_name + ' bios-force'
       else:
          issu_cmd = 'install all nxos bootflash:' + issu_image_name
    if sysimg: 
       dir_name, kickimg = os.path.split(kickimg)
       dir_name, sysimg = os.path.split(sysimg)
       
       issu_cmd = 'install all kickstart bootflash:' + kickimg + ' system bootflash:' + sysimg
       if no_save:
          issu_cmd += ' no-save'
       if bios_down_grade:
          issu_cmd += ' bios-force'
       else:
          issu_cmd = 'install all kickstart bootflash:' + kickimg + ' system bootflash:' + sysimg

    retval, msg = start_issu(device_hdl, issu_cmd)
    if not retval:
       log.info('ISSU Failed on %r, Check Logs', device_hdl.name)
       #Added return here as upgrade failed no need to check below return here
       return (retval, msg)
    device_hdl.configure('feature bash-shell\n')
    device_hdl.transmit('run bash\n')
    if not device_hdl.receive('bash.* $', timeout = 5):
       log.info('Not able to acceess bash prompt after upgrade')
       msg = 'Not able to acceess bash prompt after upgrade'
       return (0, msg)
    device_hdl.transmit('mount | grep ext\n')
    device_hdl.receive('bash.*\$ $', timeout = 15)
    op = device_hdl.receive_buffer()
    if nxos:
       #patt = '.*bootflash type ext.* \(rw,noexec,nodev,noatime,data=journal'
       patt = '.*bootflash type ext.* \(rw,.*,data=journal'
    else:
       patt = '.*bootflash type ext.* \(rw,noexec,nodev,noatime,nodiratime,noacl,data=writeback'
    lines = op.splitlines() 
    for line in lines:
       if re.search(patt, op):
          break
    else:
       log.info('bootflash is not mounted properly after install all')
       msg = 'bootflash is not mounted properly after install all'
       retval = 0
    device_hdl.transmit('exit\n')
    device_hdl.receive('.*# $', timeout = 10)
    return (retval, msg)

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
