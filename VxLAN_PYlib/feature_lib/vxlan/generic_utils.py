#!/usr/bin/python
# -*- coding: utf-8 -*-

import sys
import subprocess
import logging
import re
import pdb
import os
import traceback
import time
import sys
from jinja2 import Environment
from collections import defaultdict
from genie.conf import Genie
from genie.libs.conf.vrf.vrf import Vrf
from genie.libs.conf.interface.nxos.interface import SubInterface
from genie.libs.conf.interface.nxos.interface import PortchannelInterface
from genie.libs.conf.vlan.vlan import Vlan
from genie.libs.conf.ospf.ospf import Ospf
import parsergen
import sys
sys.path.insert(0, r'/auto/Nexus-n39K/')
from ISSU_Test_Automation.templates_dir import feature_config_template

# pyATS

from pyats import aetest
from pyats.log.utils import banner
from pyats.datastructures.logic import Not, And, Or
from pyats.easypy import run
from unicon.eal.dialogs import Dialog
from unicon.eal.dialogs import Statement
import collections


def core_check(device, logger):
    """ this method checks if any core present in device
        arguments :
            device : device console handle
            logger : logging handle

        Return Values:
          # returns 1   - success
          # returns 0 - Failed case
    """

    res = 1
    cmd = 'show cores'
    try:
        core_output = device.execute(cmd)
    except Exception:
        logger.error(traceback.format_exc())
        logger.error('Error while executing cmd %s on device %s' % cmd)
        return 0
    if core_output:
        res = re.search("[a-zA-Z]+\s+(\d+)", core_output)
        if res:
            pid = res.group(1)
            logger.error('UUT CRASHED for process %s' % pid)
            return 0
        else:
            logger.info('Crash not found')
    return 1

def mts_leak_verification( logger, device):
    """ this method checks if any core present in device
        arguments :
            device : device console handle
            logger : logging handle

        Return Values:
          # returns 1   - success
          # returns 0 - Failed case
    """
    res = 1
    cmd = 'show system internal mts buffers summary'
    try:
        mts_output = device.execute(cmd)
    except Exception:
        logger.error(traceback.format_exc())
        logger.error('Error while executing cmd %s on device %s' % cmd)
        res = 0
    time.sleep(10)
    count=0
    if mts_output is not None:
        lines = mts_output.splitlines()
        for i in lines:
            if len(i.strip()) != 0: 
                k = i.split()
                if (k[0]=='sup' or k[0]=='lc') and k[1] != '284':
                    count = count + 1
    if count > 1:
        logger.error('MTS Leak found !!!!!!!!')
        res =0
    else:
        logger.info('MTS Leak not found')
    return res

        
def render_featuresets_from_jinja(features):
    '''returns string:
    feature <features[0]>
    feature <features[1]>
    '''

    cfgfeat = \
        [Environment().from_string(feature_config_template.FEATURE).render(feature=feature)
         for feature in features]
    return ''.join(cfgfeat)


def render_ospf_config_from_jinja(ospf_type, process_id='', router_id=''
                                  ):
    '''returns string:
    '''

    if ospf_type == 'ospf':
        return Environment().from_string(feature_config_template.OSPF).render(process_id=process_id,
                router_id=router_id)
    elif ospf_type == 'ospfv3':
        return Environment().from_string(feature_config_template.OSPF3).render(process_id=process_id,
                router_id=router_id)


def render_ospf_interface_config_from_jinja(
    ospf_type,
    interface,
    process_id='',
    area_id='',
    ):
    '''returns string:
    '''

    if ospf_type == 'ospf':
        return Environment().from_string(feature_config_template.L3_INTERFACE_OSPF_CONFIG).render(interface=interface,
                process_id=process_id, area_id=area_id)
    elif ospf_type == 'ospf3':
        return Environment().from_string(feature_config_template.L3_INTERFACE_OSPF3_CONFIG).render(interface=interface,
                process_id=process_id, area_id=area_id)


def render_l3_interface_config_from_jinja(ip_type, interface, ip_addr):
    '''returns string:
    '''

    if ip_type == 'ipv4':
        return Environment().from_string(feature_config_template.L3_IPV4_INTERFACE_CONFIG).render(interface=interface,
                ipv4=ip_addr)
    elif ip_type == 'ipv6':
        return Environment().from_string(feature_config_template.L3_IPV6_INTERFACE_CONFIG).render(interface=interface,
                ipv6=ip_addr)


def render_breakout_interface_config(module_no, port_no):
    '''returns string:
    '''

    return Environment().from_string(feature_config_template.BREAKOUT_INTERFACE).render(module_no=module_no,
            port_no=port_no)


def config_device(logger, device, feature):
    res = 1
    try:
        device.configure(feature)
    except:
        logger.error(traceback.format_exc())
        res = 0
    return res


def apply_ospf_interface(
    logger,
    device,
    interface,
    ospf_type,
    ospf_pro_id,
    area_id,
    ):

    res = 1
    if ospf_type == 'ospf':
        feature_string = render_ospf_interface_config_from_jinja('ospf'
                , interface.name, process_id=ospf_pro_id,
                area_id=area_id)
        if not config_device(logger, device, feature_string):
            return 0
        else:
            return 1
    elif ospf_type == 'ospfv3':
        feature_string = render_ospf_interface_config_from_jinja('ospf3'
                , interface.name, process_id=ospf_pro_id,
                area_id=area_id)
        if not config_device(logger, device, feature_string):
            return 0
        else:
            return 1


def ospf_verification(
    logger,
    device,
    vrf,
    area_id,
    process_id,
    interface,
    address_family,
    neighbour_router_id,
    ):

    res = 1
    try:
        ospf_out = device.learn('ospf')
    except:
        logger.error(traceback.format_exc())
        res = 0
    logger.info(ospf_out)
    ospf_out = ospf_out.to_dict()
    try:
        if ospf_out['info']['vrf'][vrf]['address_family'
                ][address_family]['instance'][process_id]['areas'
                ][area_id]['interfaces'][interface]['neighbors'
                ][neighbour_router_id]['neighbor_router_id']:
            neighbour_id = ospf_out['info']['vrf'][vrf]['address_family'
                    ][address_family]['instance'][process_id]['areas'
                    ][area_id]['interfaces'][interface]['neighbors'
                    ][neighbour_router_id]['neighbor_router_id']
            logger.info('ospf neighbour details %s', neighbour_id)
            if neighbour_id == neighbour_router_id:
                logger.info('OSPF neighbour learnt succesfully')
            else:
                logger.error('OSPF neighbour not learnt,FAILED')
                res = 0
            state = ospf_out['info']['vrf'][vrf]['address_family'
                    ][address_family]['instance'][process_id]['areas'
                    ][area_id]['interfaces'][interface]['neighbors'
                    ][neighbour_router_id]['state']
            logger.info('ospf state %s', state)
            if state == 'full':
                logger.info('OSPF state is full')
            else:
                logger.error('OSPF state is not FULL,FAILED')
                res = 0
    except:
        res = 0
    return res


def interface_inoutput_rate_compare(logger, device, interface):
    cmd1 = 'show interface ' + interface + ' counters br'
    out = device.execute(cmd1)
    res = 1
    try:
        command = 'show interface ' + interface + ' counters br | json'
        out = device.execute(command)
    except:
        logger.error(traceback.format_exc())
        res = 0
    out_dict = device.api.get_config_dict(out)
    input_rate = out_dict['TABLE_interface']['ROW_interface'
            ]['eth_inrate2']
    output_rate = out_dict['TABLE_interface']['ROW_interface'
            ]['eth_outrate2']
    logger.info('interface traffic input rate %s ' % input_rate)
    logger.info('interface traffic input rate %s ' % output_rate)
    if input_rate != output_rate:
        res = 0
    return res


def interface_reset_status(logger, device):
    cmd = 'show interface'
    res = 1
    try:
        out = device.parse(cmd)
    except:
        logger.error(traceback.format_exc())
        res = 0
    expr="^Ethernet.*"
    intf_list=[]
    for interface in out.keys():
        if re.search(expr,interface):
            intf_list.append(interface)
    for interface in intf_list:
        if out[interface]['interface_reset'] == 0:
            logger.info('interface %s reset status is proper '
                        % interface)
        else:
            logger.error('interface %s reset status is not proper '
                         % interface)
            res = 0
    return res


def config_device_through_jinja(
    logger,
    device,
    template_dir,
    template,
    **kwargs
    ):
    """configure device through jinja template"""

    fail_flag = 0
    key_args = {}
    for (key, value) in kwargs.items():
        key_args[key] = value
    if 'TOTAL_VNI_MEMBERS' in key_args.keys():
        TOTAL_MEMBERS = int(key_args['TOTAL_VNI_MEMBERS'])
        logger.info('Total VNI members:%s ' % TOTAL_MEMBERS)

        try:
            out = \
                device.api.configure_by_jinja2(templates_dir=template_dir,
                    template_name=template, TOTAL_MEMBERS=TOTAL_MEMBERS)
        except:
            fail_flag = 1
            logger.error(traceback.format_exc())
    elif 'rp_address' in key_args.keys():

        rp_address = key_args['rp_address']
        group_lst = key_args['group_lst']
        logger.info('rp-address:%s ' % rp_address)
        logger.info('group-list:%s ' % group_lst)

        try:
            out = \
                device.api.configure_by_jinja2(templates_dir=template_dir,
                    template_name=template, rp_address=rp_address,
                    group_lst=group_lst)
        except:
            fail_flag = 1
            logger.error(traceback.format_exc())
    elif 'vlan_range' in key_args.keys():
        vlan_range = key_args['vlan_range']

        logger.info('vlan_range:%s ' % vlan_range)

        try:
            out = \
                device.api.configure_by_jinja2(templates_dir=template_dir,
                    template_name=template, vlan_range=int(vlan_range))
        except:
            fail_flag = 1
            logger.error(traceback.format_exc())
    else:
        try:
            out = \
                device.api.configure_by_jinja2(templates_dir=template_dir,
                    template_name=template)
        except:
            fail_flag = 1
            logger.error(traceback.format_exc())

    if fail_flag:
        return 0
    else:
        return 1


def bfd_state_verify(
    testbed,
    device,
    our_addr,
    neigh_addr,
    vrf_name='default',
    ):

    try:
        parsedOutput = parsergen.oper_fill_tabular(device=device,
                show_command='show bfd neighbors', header_fields=[
            r'OurAddr[\t]*',
            r'NeighAddr[\t]*',
            r'LD\/RD[\t]*',
            r'RH\/RS[\t]*',
            r'Holdown\(mult\)[\t]*',
            r'State[\t]*',
            r'Int[\t]*',
            r'Vrf[\t]*',
            ], index=0)
        status = parsedOutput.entries[our_addr][r'State[\t]*']

    # cmd = "show bfd neighbors vrf %s" % vrf_name
    # output = device.execute(cmd)
    # lines = output.splitlines()
    # pattern = "%s.*%s.*Up.*" % (our_addr, neigh_addr)
    # for line in lines:
    #    bfd_is_up = re.search(pattern, line)
    #    if bfd_is_up:
    #        return 1

        if status:
            return 1
    except:
        return 0
    return 0


def bfd_verification(logger, device):
    res = 1
    try:
        bfd_out = device.execute('show bfd neighbors | json')
        bfd_out_dict = device.api.get_config_dict(bfd_out)
    except:
        logger.error(traceback.format_exc())
        res = 0

    if bfd_out_dict['TABLE_bfdNeighbor']['ROW_bfdNeighbor'
            ]['local_state'] != 'Up' \
        and bfd_out_dict['TABLE_bfdNeighbor']['ROW_bfdNeighbor'
            ]['remote_state'] != 'Up':
        res = 0
    return res


def generate_port_channel_interface_dict(
    testbed,
    device,
    po,
    int_list,
    ):

    interface_po_dict = defaultdict(list)
    po = po
    int_start_range = int_list.split('-')[0]
    int_end_range = int_list.split('-')[1]
    for i in range(int(int_start_range), int(int_end_range) + 1):
        alias = 'int' + str(i)
        interface = device.interfaces[alias]
        interface_po_dict[po].append(interface)
    return interface_po_dict


def configure_port_channel(
    logger,
    testbed,
    device,
    interface_po_dict,
    ):

    fail_flag = 0
    logger.info('Configure port channel: calling genie apis')
    logger.info(interface_po_dict)
    for (key, value) in interface_po_dict.items():
        po_name = key
        po_int = PortchannelInterface(device=device, name='Port-channel'
                 + str(po_name), force=True)
        for i in range(len(value)):
            int_obj = value[i]
            int_obj.restore_default()
            int_obj.switchport_enable = False
            po_int.add_member(int_obj)
            int_obj.shutdown = False
            try:
                int_obj.build_config()
            except:
                logger.error(traceback.format_exc())
                fail_flag = 1
        po_int.channel_group_mode = 'on'
        po_int.switchport_enable = False
        po_int_obj = 'po' + str(po_name)
        po_int.ipv4 = device.interfaces[po_int_obj].custom['ipv4']
        po_int.ipv6 = device.interfaces[po_int_obj].custom['ipv6']
        try:
            po_int.build_config()
        except:
            logger.error(traceback.format_exc())
            fail_flag = 1
    if fail_flag:
        return 0
    else:
        return 1


def execute_with_reply(
    device,
    cmd,
    dialog_list,
    resp_list,
    timeout=90,
    ):

    stmt = []
    for (idx, dialog) in enumerate(dialog_list):
        s = Statement(pattern=dialog, action='sendline('
                      + resp_list[idx] + ')', loop_continue=True,
                      continue_timer=False)
        stmt.append(s)
    response = Dialog(stmt)
    out = device.execute(cmd, reply=response, timeout=10000)
    return out


def validate_issu(
    logger,
    device,
    img_name,
    upgrade_type,
    ):
    issu_upgrade=1
    res = 1
    logger.info('relogin to the box')
    device.disconnect()
    try:
        device.connect(timeout=150)
    except:
        logger.error('Device not logging in after ISSU')
        logger.error(traceback.format_exc())
        res = 0
    try:
        device.api.verify_module_status()
    except:
        logger.error('Module status not proper after issu')
        logger.error(traceback.format_exc())
        res = 0
    try:
        out = device.api.get_running_image()
    except:
        logger.error('Show version is not showing correct image after issu'
                     )
        logger.error(traceback.format_exc())
        res = 0

    if out:
        if out[0].split('/')[1] == img_name:
            logger.info('Device loaded with proper image after ISSU')
        else:
            logger.error('Device loaded with incorrect image after ISSU'
                         )
            res = 0
    try:
        out = device.execute('show install all status')
    except:
        res = 0
        logger.error(traceback.format_exc())
    if upgrade_type == 'downgrade':
        if out:
            if not re.search(r'.*Finishing the upgrade, switch will reboot in 10 seconds.*'
                             , out, re.I):
                logger.error('show install all status after ISSU downgrade is not proper'
                             )
                res = 0
    elif upgrade_type == 'upgrade':
        if out:
            if not re.search(r'.*Install has been successful.*', out,
                             re.I) \
                and re.search(r'.*Finishing the upgrade, switch will reboot in 10 seconds.*'
                              , out, re.I):
                logger.warning('FYI:Disruptive ISSU happened instead of non-disruptive ISSU'
                               )
                issu_upgrade=0
            elif not re.search(r'.*Install has been successful.*', out,
                               re.I):

                logger.error('show install all status after ISSU upgrade is not proper'
                             )
                res = 0
    try:
        out = device.execute('sh system reset-reason | json')
        out_dict = device.api.get_config_dict(out)
    except:
        res = 0
        logger.error(traceback.format_exc())
    if upgrade_type == 'downgrade':
        if out_dict:
            if out_dict['TABLE_reason']['ROW_reason']['TABLE_rr'
                    ]['ROW_rr'][0]['reason'] \
                == 'Reset due to non-disruptive upgrade':
                logger.error('show system reset reason is not proper after ISSU downgrade'
                             )
                res = 0
            else:
                logger.info('show system reset reason is proper after ISSU downgrade') 
    elif upgrade_type == 'upgrade':
        if out_dict:
            if out_dict['TABLE_reason']['ROW_reason']['TABLE_rr'
                    ]['ROW_rr'][0]['reason'] == 'Reset due to upgrade' and issu_upgrade==0:
                logger.warning('show system reset reason is proper after ISSU upgrade, FYI:Disruptive ISSU happened instead of non-disruptive ISSU'
                               )
                #res = 0
            elif out_dict['TABLE_reason']['ROW_reason']['TABLE_rr'
                    ]['ROW_rr'][0]['reason'] \
                != 'Reset due to non-disruptive upgrade':
                logger.error('show system reset reason is not proper after ISSU upgrade'
                             )
                res=0
            else:
                logger.info('show system reset reason is proper after ISSU upgrade')

    if upgrade_type == 'upgrade' and issu_upgrade==1:
        try:
            out = device.execute('sh install all time-stats”')
        except:
            res = 0
            logger.error(traceback.format_exc())
        pattern = \
            re.compile('Total time taken between control plane being down and box online: (.*) seconds'
                   )
        if out:
            if re.search(pattern, out):
                cp_down_time = re.search(pattern, out).group(1)
                if int(cp_down_time) > 120:
                    logger.warning('cp downtime not proper post ISSU')
                    res = 0
                else:
                    logger.info('cp downtime is proper post ISSU')
            else:
                logger.warning('cp downtime info is not available, please check "sh install all time-stats" logs')
                res=0 
    return res


def trigger_issu(
    logger,
    device,
    issu_command,
    issu_image,
    ):
    dialog = \
        [r"Do you want to continue with the installation \(y\/n\)\?  \[n\]"
         , r"Do you want to save the configuration \(y\/n\)"]
    resp = ['y', 'y']
    try:
        output = execute_with_reply(device, issu_command, dialog, resp,
                                    timeout=10000)
    except:
        logger.error(traceback.format_exc())
        logger.info('Sleep for 1 min')
        time.sleep(60)
        device.disconnect()
        device.connect()
        logger.error('Error encountered during install: \n{}'.format(sys.exc_info()[0]))
        return 0

    str1 = 'switch will reboot in 10 seconds.'
    str2 = 'Switching over onto standby'
    str3 = 'Install all currently is not supported'
    str4 = 'Switch is not ready for Install all yet'
    str5 = 'Rebooting the switch to proceed with the upgrade'
    str6 = 'Disruptive ISSU will be performed'
    str7 = 'Pre-upgrade check failed'
    str8 = \
        '"Running-config contains configuration that is incompatible with the new image'
    str9 = 'preupgrade check failed - Upgrade needs to be disruptive!'
    str10 = 'Install has been successful'
    if str1 in output or str2 in output or str5 in output or str10 \
        in output:
        logger.info('Install all Done and device logged in back')
        return 1
    elif str3 in output:
        logger.warning('Install all failed as currently not supported')
        return 0
    elif str4 in output:
        logger.warning('Install all failed as Switch is not ready for install all yet'
                       )
        return 0
    elif str6 in output:
        logger.warning('Non disruptive ISSU not supported')
        return 0
    elif str7 and str8 in output:
        logger.warning('Running-config contains configuration that is incompatible with the new image'
                       )
        logger.warning("Please run 'show incompatibility-all nxos <image>' command to find out which feature needs to be disabled."
                       )
        compatibility_cmd = 'show incompatibility-all nxos ' \
            + issu_image
        try:
            out = device.execute(compatibility_cmd)
        except:
            logger.error(traceback.format_exc())
        return 0
    elif str7 in output:
        logger.warning('Pre-upgrade check failed')
        return 0
    else:
        logger.warning('Install all Command Failed')
        return 0


def trigger_verify_ISSU(
    logger,
    testbed,
    device,
    **kwargs
    ):

    res = 1
    try:
        issu_image = kwargs['issu_image']
    except:
        issu_image = ''
    try:
        issu_image_path = kwargs['issu_image_path']
    except:
        issu_image_path = ''
    try:
        issu_upgrade_type = kwargs['issu_upgrade_type']
    except:
        issu_upgrade_type = ''
    try:
        bios_down_grade = kwargs['bios_down_grade']
    except:
        bios_down_grade = ''
    try:
        issu_upgrade_subtype = kwargs['issu_upgrade_subtype']
    except:
        issu_upgrade_subtype = ''
    logger.info(issu_upgrade_subtype)
    if not issu_image or not issu_image_path or not issu_upgrade_type \
        or not issu_upgrade_subtype:
        logger.error('Mandatory parameters missing. issu_image,issu_image_path,issu_upgrade_type,issu_upgrade_subtype info needed to proceed further'
                     )
        return 0

    current_image = device.api.get_running_image()
    logger.info(banner('Current image on device is %s' % current_image))

    logger.info(banner('copy issu_image %s to device' % issu_image))
    issu_image_withpath = issu_image_path + issu_image
    logger.info(issu_image)
    if device.api.verify_file_exists(issu_image) != True:
        try:
            device.api.copy_to_device(issu_image_withpath, 'bootflash:',
                                      testbed.servers.tftp['address'], 'scp'
                                      , timeout=2000,vrf='management')
        except:
            logger.error(traceback.format_exc())
    else:
        logger.info('Skipping copy image as it is already present in the box')
    if device.api.verify_file_exists(issu_image) != True:
        logger.error('Image copy fails . Please check logs')

        # return 0

        res = 0
    logger.info(issu_upgrade_subtype)
    logger.info(banner('Start ISSU based on upgrade type : %s upgrade subtype : %s'
                 % (issu_upgrade_type, issu_upgrade_subtype)))
    if issu_upgrade_type == 'upgrade' and issu_upgrade_subtype \
        == 'nondisruptive':
        issu_command = 'install all nxos bootflash:' + issu_image \
            + ' non-disruptive'
        logger.info('ISSU command is %s' % issu_command)
    elif issu_upgrade_type == 'upgrade' and issu_upgrade_subtype \
        == 'disruptive':
        issu_command = 'install all nxos bootflash:' + issu_image \
            #+ ' disruptive'
        logger.info('ISSU command is %s' % issu_command)
    elif issu_upgrade_type == 'downgrade' and bios_down_grade == 1:
        issu_command = 'install all nxos bootflash:' + issu_image \
            + ' bios-force'
        logger.info('ISSU command is %s' % issu_command)
        logger.info(banner('Write erase reload needed for ISSU Downgrade type'
                    ))
        logger.info('save boot variables')
        device.api.execute_change_boot_variable(device.api.get_running_image()[0])
        device.api.execute_copy_run_to_start()
        device.api.execute_reload(prompt_recovery='true',
                                  reload_creds='admin nbv12345',
                                  timeout=600)
    else:
        issu_command = 'install all nxos bootflash:' + issu_image
        logger.info('ISSU command is %s' % issu_command)
#        logger.info(banner('Write erase reload needed for ISSU Downgrade type'
#                    ))

#        logger.info('save boot variables')
#        try:
#            device.api.execute_change_boot_variable(device.api.get_running_image()[0])
#        except:
#            result = 0
#            logger.error(traceback.format_exc())
#        try:
#            device.api.execute_copy_run_to_start()
#        except:
#            logger.error(traceback.format_exc())
#            result = 0
#        try:
#            device.api.write_erase_reload_device_without_reconfig('a' ,reload_timeout=180)
#        except:
#            logger.error(traceback.format_exc())
#            result=0

        cmd = 'install deactivate icam'
        try:
            out = device.execute(cmd)
        except:
            logger.error(traceback.format_exc())
            res = 0
    logger.info('trigger ISSU')
    result = trigger_issu(logger, device, issu_command, issu_image)
    if not result:
        logger.error('ISSU not successful on device %s', device.name)
        return result
    logger.info('sleep for 10 mins waiting for Active Sup up')
    time.sleep(720)
    result = validate_issu(logger, device, issu_image,
                           issu_upgrade_type)
    return result

