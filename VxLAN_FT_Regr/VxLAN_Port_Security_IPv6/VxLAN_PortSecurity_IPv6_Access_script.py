###################################################################
###                  Importing Libraries                        ###
###################################################################
import logging
import time
import yaml
import json
import re
import os
from time import sleep
from yaml import Loader
from pyats import aetest
from pyats.log.utils import banner
from random import random
import chevron
import pdb
import sys
import ipaddress as ip
import numpy as np
from operator import itemgetter
import texttable
import difflib
from unicon.eal.dialogs import Statement, Dialog

log = logging.getLogger(__name__)
log.setLevel(logging.DEBUG)

#################################################################################
from pyats import tcl
from pyats import aetest
from pyats.log.utils import banner
#from pyats.async import pcall

from pyats.aereport.exceptions.utils_errors import \
MissingArgError, TypeMismatchError,\
DictInvalidKeyError, DictMissingMandatoryKeyError,\
StrInvalidOptionError, InvalidArgumentError

from ats.topology import loader
from pyats.aereport.utils.argsvalidator import ArgsValidator
ArgVal = ArgsValidator()
import pdb
import os
import re
import logging
import time
import lib.nxos.util as util
import lib.nxos.connection as connection
import lib.nxos.vdc as vdc

log = logging.getLogger(__name__)
log.setLevel(logging.DEBUG)

# ------------------------------------------------------
# Import pyats genie libraries
# ------------------------------------------------------
from genie.conf import Genie
from genie.conf.base import Device
from genie.libs.parser.nxos.show_platform import ShowCores
from genie.libs.parser.nxos.show_platform import ShowVersion
from genie.libs.parser.nxos.show_vrf import ShowVrf
from genie.libs.sdk.apis.execute import execute_copy_run_to_start
from genie.abstract import Lookup
from genie.libs import conf, ops, sdk, parser

# Import the RestPy module
from ixnetwork_restpy import *

#################################################################################

import pdb
import sys
import copy

class ForkedPdb(pdb.Pdb):
    """A Pdb subclass that may be used
    from a forked multiprocessing child
    """
    def interaction(self, *args, **kwargs):
        _stdin = sys.stdin
        try:
            sys.stdin = open('/dev/stdin')
            pdb.Pdb.interaction(self, *args, **kwargs)
        finally:
            sys.stdin = _stdin

# ------------------------------------------------------
# Import and initialize EVPN specific libraries
# ------------------------------------------------------
import vxlanEVPN_FNL_lib
evpnLib     = vxlanEVPN_FNL_lib.configure39KVxlanEvpn()
verifyEvpn  = vxlanEVPN_FNL_lib.verifyEVPNconfiguration()

import infra_lib
infraTrig = infra_lib.infraTrigger()
infraConfig = infra_lib.infraConfigure()
infraVerify = infra_lib.infraVerify()

# ------------------------------------------------------
# Import and initialize NIA specific libraries
# ------------------------------------------------------
import vxlanNIA_lib
niaLib = vxlanNIA_lib.verifyVxlanNIA()

###################################################################
###                  User Library Methods                       ###
###################################################################
# Verify IXIA Traffic (Traffic Item Stats View)
def validateSteadystateTraffic(testscript, expected_threshold=1):
    
    session     = testscript.parameters['session']
    ixNetwork   = testscript.parameters['ixNetwork']
    threshold   = testscript.parameters['traffic_threshold']

    TrafficItemTable = texttable.Texttable()
    TrafficItemTable.header(['Traffic Item', 'Loss % Observed\nThreshold - '+str(threshold)+' %', 'Status','Remarks'])
    TrafficItemTable.set_cols_width([40,20,20,50])
    fail_flag = []

    # Start all protocols and wait for 60sec
    #ixNetwork.StartAllProtocols(Arg1='sync')
    #time.sleep(60)
    
    # Apply traffic, start traffic and wait for 30min
    
    ixNetwork.Traffic.Start()
    log.info("==> Wait for 5min for the MSite Scale traffic to populate")
    time.sleep(300)
    
    # Loop wait buffer for 5 more min
    waitIteration = 1
    while waitIteration < 16:
        # Clear stats
        ixNetwork.ClearStats()
        time.sleep(20)
        fail_flag = []

        # Get Traffic Item Statistics
        trafficItemStatistics = session.StatViewAssistant('Traffic Item Statistics')
        for row in trafficItemStatistics.Rows:
            # Verify loss percentage for Traffic Items
            if row['Loss %'] != '':
                if int(float(row['Loss %'])) > threshold:
                    fail_flag.append(0)
            # Verify loss percentage for BUM Traffic Items
            else:
                if 'BUM' in str(row['Traffic Item']):
                    # Remote Site VTEPs
                    # Verify Tx Rate*256 = Rx Rate for Traffic Items
                    if 'DCI_BUM' in str(row['Traffic Item']):
                        if int(float(row['Tx Frame Rate']))*256 != int(float(row['Rx Frame Rate'])):
                            fail_flag.append(0)
                    # Remote Internal Site VTEPs
                    # Verify Tx Rate*116 = Rx Rate for Traffic Items
                    elif 'INT_BUM' in str(row['Traffic Item']):
                        if int(float(row['Tx Frame Rate']))*117 != int(float(row['Rx Frame Rate'])):
                            fail_flag.append(0)
                # Verify Traffic if Loss % is not available
                else:
                    if (int(float(row['Tx Frame Rate']))-int(float(row['Rx Frame Rate']))) not in range(0,1001):
                        fail_flag.append(0)

        if 0 in fail_flag:
            log.info("==> Iteration done , but traffic not converged , need to wait more")
            waitIteration+=1
            continue
        else:
            log.info("time ===>")
            log.info(time.gmtime())
            log.info("time ===>")
            break

    # Collect Data and tabulate it for reporting
    ixNetwork.ClearStats()
    time.sleep(20)
    fail_flag = []

    # Get Traffic Item Statistics
    trafficItemStatistics = session.StatViewAssistant('Traffic Item Statistics')
    for row in trafficItemStatistics.Rows:
        # Verify loss percentage for Traffic Items
        if row['Loss %'] != '':
            if int(float(row['Loss %'])) < threshold and int(float(row['Loss %'])) > expected_threshold:
                TrafficItemTable.add_row([str(row['Traffic Item']), str(row['Loss %']), 'PASS', ''])
            else:
                TrafficItemTable.add_row([str(row['Traffic Item']), str(row['Loss %']), 'FAIL', ''])
                fail_flag.append(0)
        # Verify loss percentage for BUM Traffic Items
        else:
            if 'BUM' in str(row['Traffic Item']):
                # Remote Site VTEPs
                # Verify Tx Rate*256 = Rx Rate for Traffic Items
                if 'DCI_BUM' in str(row['Traffic Item']):
                    if int(float(row['Tx Frame Rate']))*256 == int(float(row['Rx Frame Rate'])):
                        TrafficItemTable.add_row([str(row['Traffic Item']), str(int(float(row['Tx Frame Rate'])))+'-'+str(int(float(row['Rx Frame Rate']))), 'PASS', 'Receiving 2560 for 256 Remote Site VTEPs'])
                    else:
                        TrafficItemTable.add_row([str(row['Traffic Item']), str(int(float(row['Tx Frame Rate'])))+'-'+str(int(float(row['Rx Frame Rate']))), 'FAIL', 'Not Receiving 2560 for 256 Remote Site VTEPs'])
                        fail_flag.append(0)
                # Remote Internal Site VTEPs
                # Verify Tx Rate*116 = Rx Rate for Traffic Items
                elif 'INT_BUM' in str(row['Traffic Item']):
                    if int(float(row['Tx Frame Rate']))*117 == int(float(row['Rx Frame Rate'])):
                        TrafficItemTable.add_row([str(row['Traffic Item']), str(int(float(row['Tx Frame Rate'])))+'-'+str(int(float(row['Rx Frame Rate']))), 'PASS', 'Receiving 1170 for 116 Internal Remote VTEPs + 1 BGW'])
                    else:
                        TrafficItemTable.add_row([str(row['Traffic Item']), str(int(float(row['Tx Frame Rate'])))+'-'+str(int(float(row['Rx Frame Rate']))), 'FAIL', 'Not Receiving 1170 for 116 Internal Remote VTEPs + 1 BGW'])
                        fail_flag.append(0)
            # Verify Traffic if Loss % is not available
            else:
                if (int(float(row['Tx Frame Rate']))-int(float(row['Rx Frame Rate']))) in range(0,1001):
                    TrafficItemTable.add_row([str(row['Traffic Item']), str(int(float(row['Tx Frame Rate'])))+'-'+str(int(float(row['Rx Frame Rate']))), 'PASS', ''])
                else:
                    TrafficItemTable.add_row([str(row['Traffic Item']), str(int(float(row['Tx Frame Rate'])))+'-'+str(int(float(row['Rx Frame Rate']))), 'FAIL', ''])
                    fail_flag.append(0)
    
    log.info(TrafficItemTable.draw())
    if 0 in fail_flag:
        return 0
    else:
        return 1

# Verify IXIA Traffic (Traffic Item Stats View)
def VerifyTraffic(section, testscript, **kwargs):
    
    session     = testscript.parameters['session']
    ixNetwork   = testscript.parameters['ixNetwork']
    threshold   = testscript.parameters['traffic_threshold']
    traffic_item = kwargs.get('traffic_item')

    TrafficItemTable = texttable.Texttable()
    TrafficItemTable.header(['Traffic Item', 'Loss % Observed\nThreshold - '+str(threshold)+' %', 'Status','Remarks'])
    TrafficItemTable.set_cols_width([40,20,20,50])
    fail_flag = []


    traffic = ixNetwork.Traffic.TrafficItem.find()
    traffic.StopStatelessTraffic()
    log.info('Waiting 60secs to stop all traffic')
    time.sleep(60)
    
    # # Apply traffic, start traffic and wait for 60sec
    ixNetwork.Traffic.Apply()
    stream1 = ixNetwork.Traffic.TrafficItem.find(Name=traffic_item)
    stream1.StartStatelessTraffic()
    log.info('Waiting 240secs for the traffic')
    time.sleep(240)

    # Clear stats
    ixNetwork.ClearStats()
    log.info('Waiting 30secs to clear stats')
    time.sleep(30)
    
    # Get Traffic Item Statistics
    trafficItemStatistics = session.StatViewAssistant('Traffic Item Statistics')
    for row in trafficItemStatistics.Rows:
        # Verify loss percentage for Traffic Items
        if row['Loss %'] != '':
            if int(float(row['Loss %'])) < threshold and int(float(row['Loss %'])) != 100:
                TrafficItemTable.add_row([str(row['Traffic Item']), str(row['Loss %']), 'PASS', ''])
            else:
                TrafficItemTable.add_row([str(row['Traffic Item']), str(row['Loss %']), 'FAIL', ''])
                fail_flag.append(0)
        # Verify loss percentage for BUM Traffic Items
        else:
            if 'BUM' in str(row['Traffic Item']):
                # Remote Site VTEPs
                # Verify Tx Rate*256 = Rx Rate for Traffic Items
                if 'DCI_BUM' in str(row['Traffic Item']):
                    if int(float(row['Tx Frame Rate']))*256 == int(float(row['Rx Frame Rate'])):
                        TrafficItemTable.add_row([str(row['Traffic Item']), str(int(float(row['Tx Frame Rate'])))+'-'+str(int(float(row['Rx Frame Rate']))), 'PASS', 'Receiving 2560 for 256 Remote Site VTEPs'])
                    else:
                        TrafficItemTable.add_row([str(row['Traffic Item']), str(int(float(row['Tx Frame Rate'])))+'-'+str(int(float(row['Rx Frame Rate']))), 'FAIL', 'Not Receiving 2560 for 256 Remote Site VTEPs'])
                        fail_flag.append(0)
                # Remote Internal Site VTEPs
                # Verify Tx Rate*116 = Rx Rate for Traffic Items
                elif 'INT_BUM' in str(row['Traffic Item']):
                    if int(float(row['Tx Frame Rate']))*117 == int(float(row['Rx Frame Rate'])):
                        TrafficItemTable.add_row([str(row['Traffic Item']), str(int(float(row['Tx Frame Rate'])))+'-'+str(int(float(row['Rx Frame Rate']))), 'PASS', 'Receiving 1170 for 116 Internal Remote VTEPs + 1 BGW'])
                    else:
                        TrafficItemTable.add_row([str(row['Traffic Item']), str(int(float(row['Tx Frame Rate'])))+'-'+str(int(float(row['Rx Frame Rate']))), 'FAIL', 'Not Receiving 1170 for 116 Internal Remote VTEPs + 1 BGW'])
                        fail_flag.append(0)
            # Verify Traffic if Loss % is not available
            else:
                if (int(float(row['Tx Frame Rate']))-int(float(row['Rx Frame Rate']))) in range(0,1001):
                    TrafficItemTable.add_row([str(row['Traffic Item']), str(int(float(row['Tx Frame Rate'])))+'-'+str(int(float(row['Rx Frame Rate']))), 'PASS', ''])
                else:
                    TrafficItemTable.add_row([str(row['Traffic Item']), str(int(float(row['Tx Frame Rate'])))+'-'+str(int(float(row['Rx Frame Rate']))), 'FAIL', ''])
                    fail_flag.append(0)
    
    log.info(TrafficItemTable.draw())
    
    stream1.StopStatelessTraffic()    
    time.sleep(30)

    if 0 in fail_flag:
        return 0
    else:
        return 1

def VerifyTrafficDrop(section, testscript, **kwargs):
    
    session     = testscript.parameters['session']
    ixNetwork   = testscript.parameters['ixNetwork']
    threshold   = testscript.parameters['traffic_threshold']
    traffic_item = kwargs.get('traffic_item')

    TrafficItemTable = texttable.Texttable()
    TrafficItemTable.header(['Traffic Item', 'Loss % Observed\nThreshold - '+str(threshold)+' %', 'Status','Remarks'])
    TrafficItemTable.set_cols_width([40,20,20,50])
    fail_flag = []

    # # Start all protocols and wait for 60sec
    # ixNetwork.StartAllProtocols(Arg1='sync')
    # time.sleep(60)
    
    # # Apply traffic, start traffic and wait for 60sec
    stream1 = ixNetwork.Traffic.TrafficItem.find(Name=traffic_item)
    
    stream1.StartStatelessTraffic()

    # ixNetwork.Traffic.Start()
    time.sleep(240)

    # Clear stats
    ixNetwork.ClearStats()
    time.sleep(20)
    
    # Get Traffic Item Statistics
    trafficItemStatistics = session.StatViewAssistant('Traffic Item Statistics')
    for row in trafficItemStatistics.Rows:
        # Verify Receiving traffic is having drops
        if int(float(row['Tx Frame Rate']))*256 >= int(float(row['Rx Frame Rate'])):
            TrafficItemTable.add_row([str(row['Traffic Item']), str(int(float(row['Tx Frame Rate'])))+'-'+str(int(float(row['Rx Frame Rate']))), 'PASS', 'Receiving Traffic has drop as expected'])
        else:
            TrafficItemTable.add_row([str(row['Traffic Item']), str(int(float(row['Tx Frame Rate'])))+'-'+str(int(float(row['Rx Frame Rate']))), 'FAIL', 'Not Receiving 2560 for 256 Remote Site VTEPs'])
            fail_flag.append(0)
        
    log.info(TrafficItemTable.draw())
    
    stream1.StopStatelessTraffic()    
    time.sleep(30)

    if 0 in fail_flag:
        return 0
    else:
        return 1

def increment_prefix_network(pref, count):
    size = 1 << (pref.network.max_prefixlen - pref.network.prefixlen)
    pref_lst = []
    for i in range(count):
        pref_lst.append(str((pref.ip+size*i)) + "/" + str(pref.network.prefixlen))
    return pref_lst

def getNvePeerList(allLeaves_data):
    nve_peer_lst = []
    for item in allLeaves_data:
        if 'VPC_VTEP_IPV6' in item['NVE_data'].keys():
            if item['NVE_data']['VPC_VTEP_IPV6'] not in nve_peer_lst:
                nve_peer_lst.append(item['NVE_data']['VPC_VTEP_IPV6'])
        else:
            nve_peer_lst.append(item['NVE_data']['VTEP_IPV6'])
    return nve_peer_lst

def verify_port_sec_addr_count(device, interface, expected_count, type='STATIC'):
    cli = 'show port-security address interface ' + interface + ' | inc ' + type + ' | count '
    no_of_mac_learn = device.execute(cli, timeout= 120)
    if int(no_of_mac_learn) != expected_count:
       log.info("Mac learned is not as expected count %r ", expected_count)
       return 0
    return 1

def verifyerrorDisable(hdl, intf, log, vpc=False):

    "VerifyerrorDisable - Verify Security Error-Disable Violation on Interface"

    result= False
    log.info('Verifying Port Security Mac Violation')
    show_cmd='show interface {0} brief'.format(intf)
    output=hdl.execute(show_cmd)
    if vpc:
        result=re.search('down\s+Channel error-disabled', output)
    else:
        result=re.search('down\s+Sec-violation errDisab', output)
    if result:
        log.info("Port is down with securtiy-violation error disabled message as expected")
        result = True
    else:
        log.error("Port is not down with security-violation error")
    return result

def display_configs(testscript):
    sa_vtep         = testscript.parameters['LEAF-3']
    prim_vtep       = testscript.parameters['LEAF-1']
    sec_vtep        = testscript.parameters['LEAF-2']
    prim_vtep_if    = str(testscript.parameters['intf_LEAF_1_1_to_IXIA'])
    prim_vtep_if1   = str(testscript.parameters['intf_LEAF_1_2_to_IXIA'])
    fex_if          = str(testscript.parameters['intf_LEAF_1_FEX_to_IXIA'])
    sec_vtep_if     = str(testscript.parameters['intf_LEAF_2_to_IXIA'])
    sa_vtep_if      = str(testscript.parameters['intf_LEAF_3_to_IXIA'])
    
    
    prim_vtep.execute('show run interface {intf}'.format(intf=prim_vtep_if))
    prim_vtep.execute('show run interface {intf}'.format(intf=prim_vtep_if1))
    prim_vtep.execute('show run interface {intf}'.format(intf=fex_if))
    prim_vtep.execute('show run interface port-channel 11')
    sec_vtep.execute('show run interface {intf}'.format(intf=sec_vtep_if))
    sec_vtep.execute('show run interface port-channel 11')
    sa_vtep.execute('show run interface {intf}'.format(intf=sa_vtep_if))
        
def verify_secure_mac_on_vteps(device, vlan, expected_count, start_mac, type='static'):
    cli = 'show mac address-table ' + 'vlan ' + vlan + ' | inc ' + type + ' | inc ' + start_mac +' | count '

    no_of_mac_learn = device.execute(cli, timeout= 120)
    if int(no_of_mac_learn) != expected_count:
       log.info("Mac learned is not as expected count %r ", expected_count)
       return 0
    return 1

def get_mts_leak(logger, device):
    """ this method checks if any MTS leak present in device
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
        mts_output = device.execute(cmd, timeout=120)
    except Exception:
        logger.error('Error while executing cmd %s on device %s' % cmd)
        res = 0
    time.sleep(10)
    count = 0
    if mts_output is not None:
        lines = mts_output.splitlines()
        for i in lines:
            if len(i.strip()) != 0:
                k = i.split()
                if (k[0] == 'sup' or k[0] == 'lc') and k[1] != '284':
                    logger.info("MTS leak found with module:%s sapno:%s,sleep for 10 secs and check again" % (k[0], k[1]))
                    count = count + 1
    logger.info(count)
    if count > 1:
        return count
    else:
        logger.info(banner('MTS Leak not found'))
        return None

def mts_leak_verification(logger, device):
    res = 1
    timeout_sec=300
    interval_sec=10
    counter = interval_sec
    
    while counter <= timeout_sec:
        logger.info("Check MTS detail for device : %s" % device)
        mts_leak = get_mts_leak(logger,device)
        if mts_leak:
            logger.error("MTS leak found for device:%s" % device )
            time.sleep(interval_sec)
            res=0
        else:
            logger.info("No MTS leak found for device:%s" % device )
            res = 1
            break
        counter = counter + interval_sec
    
    return res

def verify_mts_leak(device_list, log):
	
    result = True
	
    for device in device_list:
        res = mts_leak_verification(log, device)
        if res:
            log.info("MTS Leak Verification success for primary vtep")
        else:
            log.debug('MTS Leak Verification failed for primary vtep')
            result = False
		
    return result
    
def verify_traffic_drop(dut,interface):
    output=dut.execute('''show int ''' + str(interface) + ''' | i rate | i "30 seconds input"''')
    output1=dut.execute('''show int ''' + str(interface) + ''' | i rate | i "30 seconds output"''')
    m1=re.search('.*([0-9]+) packets\/sec',output)
    m2=re.search('.*([0-9]+) packets\/sec',output1)
    m = int(m1.group(1)) - int(m2.group(1))
    if m:
        print(m)
        if int(m) >= 10:
            return True
    return False

def change_vpc_role(testscript):
    prim_vtep           = testscript.parameters['LEAF-1']
    sec_vtep            = testscript.parameters['LEAF-2']
    role_priority       = str(testscript.parameters['PORTSEC_Dict']['vpc_role_priority'])
    
    vpc_domain_id       = testscript.parameters['LEAF_1_dict']['VPC_data']['domain_id']
    
    dialog = Dialog([ \
        Statement(pattern='.*Changing domain id will flap peer-link and vPCs. Continue \(yes/no\)\?',
                action='sendline(y)', \
                        loop_continue=True,
                        continue_timer=False)
                        ])
    
    
    cmd = ""
    cmd += "vpc domain %s"%vpc_domain_id+ "\n"
    cmd += "role priority %s"%role_priority+ "\n"

    device = get_vpc_primary_secondary_device([prim_vtep, sec_vtep])
    try:
        output = device.configure(cmd,reply = dialog)
        
        if len(output.strip().split("\n")) > 2:
            
            if re.search("Change will take effect after user has",output):
                log.info("Configured  %s on device %s "%(cmd.strip(),device.name))
            else: 
                log.error("Error when configuring  %s on device %s "%(cmd,device.name))
                log.error(output)
                return 0
    except Exception:
        log.error("Error while executing cmd %s on device %s" % (cmd,device.name))
        return 0

    dialog = Dialog([ \
        Statement(pattern='Please ensure peer-switch is enabled and operational.*\. Continue \(yes/no\)\?',
                action='sendline(y)', \
                        loop_continue=True,
                        continue_timer=False)
                        ])
    
    cmd = ""
    cmd += "vpc domain %s"%vpc_domain_id+ "\n"
   
    cmd += "vpc role preempt"+ "\n"
    
    try:
        output = device.configure(cmd,reply = dialog)
        
    except Exception:
        log.error("Error while executing cmd %s on device %s" % (cmd,device))
        return 0
    
    return 1,output

def get_vpc_primary_secondary_device(device_list, role='primary'):
    vpc_peer = 'primary'
    if role == 'primary':
        vpc_peer = 'secondary'
    
    for device in device_list:
        output = device.execute('show vpc role | grep -i \"vpc role  \"')
        count1 = len(re.findall(": {role}$|: {role} ".format(role=role), output))
        count2 = len(re.findall(": {peer}, operational {role}".format(peer=vpc_peer, role=role), output))
            
        if count1 == 1 or count2 == 1:
            return device

def getVpcPoStatus(device, intf_po):
    status = True
    vpc_status_output = device.execute('show vpc')
    po_match = re.search(r'(\d+)\s+({0})\s+(\w+)\s+(\w+)\s+'.format(intf_po),
            vpc_status_output,
            re.I)
    
    vpc_status_value = []
    for i in range(1, 5):
        vpc_status_value.append(po_match.group(i))
    
    if vpc_status_value[2].rstrip() == 'up':
        return True
    else:
        return False

def verify_mac_cc_between_hardware_software(device_list):
		device_list[0].execute('sh consistency-checker l2 module 1')
		device_list[1].execute('sh consistency-checker l2 module 1')
		device_list[2].execute('sh consistency-checker l2 module 1')
		retval = device_list[0].execute('sh consistency-checker l2 module 1 | inc FAILED | count')
		retval1 = device_list[1].execute('sh consistency-checker l2 module 1 | inc FAILED | count')
		retval2 = device_list[2].execute('sh consistency-checker l2 module 1 | inc FAILED | count')
		if int(retval) or int(retval1) or int(retval2):
			log.error('Learned mac address consistency between hardware and software failed')
			return False
		else:
			log.info('Mac CC between hardware and software is success')
			return True

def verify_process_restart(dut, process, testscript, log):
    fail_flag = []

    if infraTrig.verifyProcessRestart(dut, process):
        log.info("Successfully restarted process {process}".format(process=process))
    else:
        fail_flag.append(0)
        log.debug(f"Failed to restarted process {process}\n".format(process=process))
        
    time.sleep(120)
    
    # Verify NVE UP
    nve_out = dut.execute("sh int nve 1 brief | xml | i i state>")
    if ">up<" in nve_out:
        log.info("NVE INT is UP after process restart")
    else:
        fail_flag.append(0)
        log.debug("NVE INT is not UP after process restart\n")
        
    time.sleep(120)
    
    # Verify NVE Peers with new IP
    nvePeerData = verifyEVPNNvePeers(testscript.parameters['leavesDict'])
    if nvePeerData['result'] is 1:
        log.info("PASS : Successfully verified NVE Peering\n")
    else:
        fail_flag.append(0)
        log.debug("FAIL : Failed to verify NVE Peering\n")
    
    if 0 in fail_flag:
        return False
    else:
        return True

def cr_log_dump(uut):
    global counter

    uut.execute("delete bootflash:show_config_replace_log_exec_step no-prompt")
    uut.execute("delete bootflash:show_config_replace_log_verify_step no-prompt")

    uut.execute ('show config-replace status' , timeout=6000)
    uut.execute ('show config-replace log exec > show_config_replace_log_exec_step'  , timeout=6000)
    uut.execute ('show config-replace log verify > show_config_replace_log_verify_step' , timeout=6000)
    return 1

def rollback_log_dump(uut):
    uut.execute ('show rollback status' , timeout=6000)
    uut.execute ('show rollback log veirfy' , timeout=6000)
    uut.execute ('show rollback log exec' , timeout=6000)
    return 0

def verify_config_replace(device_list, log):
    Flag = True
    for uut in device_list:
        output = uut.execute ('configure replace bootflash:{config_file}'.format(config_file=cr_file), timeout = 6000)
        if 'Configure replace completed successfully' in output :
            log.info('CR got success with base config')
        else:
            log.error('Configure replace Failed')
            Flag = False
            cr_log_dump(uut)
    
        counter = 1
        while counter <= 3:
            output = uut.execute ('show rollback status' , timeout = 6000)
            if 'Operation Status: Success' in output or 'Operation Status: Failed' in output or 'Config are same' in output :
                log.info('Rollback completed')
                break
            else:
                log.error('Rollback in progess')
                rollback_log_dump(uut)
                Flag = False
        
            log.info("Waiting 10secs")
            time.sleep(10)
            counter += 1
    
    return Flag
def basic_interface_configs(device_list, interface, vlan, mode='access'):
    
    if mode == 'access':
        vlan_config = '''switchport
                         switchport mode access
                         switchport access vlan {vlan}
                         spanning-tree port type edge'''.format(vlan=vlan)
    else:
        vlan_config = '''switchport
                         switchport mode trunk
                         switchport access vlan {vlan}
                         spanning-tree port type edge trunk'''.format(vlan=vlan)
        
    clis = '''interface {prim_vtep_if}
            shutdown
            switchport
            {vlan_config}
            no shutdown
        '''.format(prim_vtep_if=interface, vlan_config=vlan_config)
            
    for device in device_list:
        try:
            device.configure(clis)
        except Exception as error:
                log.debug("Unable to configure - Encountered Exception " + str(error))
                return False
        
    return True

def config_interface_ps(device_list, interface, log, new_config=''):
    for device in device_list:     
        try:
            device.configure('''interface {prim_vtep_if}
                                shutdown
                                switchport port-security maximum 1025
                                switchport port-security aging type inactivity
                                switchport port-security violation restrict
                                switchport port-security
                                {config}
                                no shutdown
                            '''.format(prim_vtep_if=interface, config=new_config))
        except Exception as error:
                log.debug("Unable to configure - Encountered Exception " + str(error))
                return False
        
    return True

def unconfig_interface_ps(device_list, interface, log, new_config = '', noshut = False):
    
    for device in device_list:
        if noshut:
            try:
                device.configure('''interface {prim_vtep_if}
                                no switchport port-security aging type inactivity
                                no switchport port-security violation restrict
                                no switchport port-security
                                {config}
                            '''.format(prim_vtep_if=interface, config=new_config))
            except Exception as error:
                log.debug("Unable to configure - Encountered Exception " + str(error))
                return False
        else:    
            try:
                device.configure('''interface {prim_vtep_if}
                                shutdown
                                no switchport port-security aging type inactivity
                                no switchport port-security violation restrict
                                no switchport port-security
                                {config}
                                no shutdown
                            '''.format(prim_vtep_if=interface, config=new_config))
            except Exception as error:
                log.debug("Unable to configure - Encountered Exception " + str(error))
                return False
        
    return True

def stop_stream(testscript, stream):
    ixNetwork   = testscript.parameters['ixNetwork']

    stream1 = ixNetwork.Traffic.TrafficItem.find(Name=stream)
    stream1.StopStatelessTraffic()

    log.info('Waiting {}secs to stop 1025 hosts'.format(traffic_stop_time))
    time.sleep(traffic_stop_time)

def stop_all_streams(steps, testscript):
    ixNetwork   = testscript.parameters['ixNetwork']

    with steps.start("Stopping all hosts..."):
            ixNetwork.StopAllProtocols()

    log.info('Waiting {}secs to stop the hosts'.format(traffic_stop_time))
    time.sleep(traffic_stop_time)

    stream1 = ixNetwork.Traffic.TrafficItem.find(Name='Access Orphan To Standalone')
    stream1.StopStatelessTraffic()

    log.info('Waiting {}secs to stop 1025 hosts'.format(traffic_stop_time))
    time.sleep(traffic_stop_time)
    
    stream1 = ixNetwork.Traffic.TrafficItem.find(Name='Access FEX To Standalone')
    stream1.StopStatelessTraffic()
    
    log.info('Waiting {}secs to stop 1025 hosts'.format(traffic_stop_time))
    time.sleep(traffic_stop_time)
    
    stream1 = ixNetwork.Traffic.TrafficItem.find(Name='Access VPC To Standalone')
    stream1.StopStatelessTraffic()
    
    log.info('Waiting {}secs to stop 1025 hosts'.format(traffic_stop_time))
    time.sleep(traffic_stop_time)
    
###################################################################
###              BGP EVPN Configuration procs for IPv6          ###
###################################################################
def configureEVPNSpinesIpv6(spineList, forwardingSysDict, leavesDictList):

        # --------------------------------------------
        # Parse the arguments for their types
        # --------------------------------------------
        if type(spineList) is not list:
            print("Passed Argument spineList is not a LIST")
            return 0
        if type(leavesDictList) is not list:
            print("Passed Argument leaves_dicts is not a LIST of Leaf dictionaries")
            return 0
        if type(forwardingSysDict) is not dict:
            print("Passed Argument forwardingSysDict is not a Dictionary")
            return 0

        # --------------------------------------------
        # Parameters to be used in the following proc
        # --------------------------------------------
        spine1_config           = ""
        spine1_ospfv3_config    = ""
        spine1_bgp_config       = ""

        if 'SPINE_COUNT' not in forwardingSysDict.keys():
            forwardingSysDict['SPINE_COUNT'] = 1
        for leaf in leavesDictList:
            if 'spine_leaf_po_v6' not in leaf['SPINE_1_UPLINK_PO']:
                leaf['spine_leaf_po_v6']    = ""
                leaf['leaf_spine_mask_v6']  = ""
                leaf['spine_leaf_po_v6']    = ""
                leaf['leaf_spine_mask_v6']  = ""

        # --------------------------------------------
        # Print out the Parameters passed to the proc
        # --------------------------------------------
        print("========================================")
        print("Given Forwarding System Dictionary is")
        print("========================================")
        print(json.dumps(forwardingSysDict, indent=5))
        log.info("========================================")
        log.info("Given Forwarding System Dictionary is")
        log.info("========================================")
        log.info(json.dumps(forwardingSysDict, indent=5))

        for leaf_num in range(len(leavesDictList)):
            print("========================================")
            print("Given data dictionary of LEAF-" + str(leaf_num+1))
            print("========================================")
            print(json.dumps(leavesDictList[leaf_num], indent=6))
            log.info("========================================")
            log.info("Given data dictionary of LEAF-" + str(leaf_num+1))
            log.info("========================================")
            log.info(json.dumps(leavesDictList[leaf_num], indent=6))

        # --------------------------------------------
        # Building PIM RP Configuration
        # --------------------------------------------
        spine1_config = '''
                        nv overlay evpn

                        interface loopback10
                            ipv6 address ''' + str(leavesDictList[0]['SPINE_1_UPLINK_PO']['spine_loop10_ipv6']) + '''/64
                            ipv6 router ospfv3 ''' + str(forwardingSysDict['OSPF_AS']) + ''' area 0.0.0.0
                            no shutdown
                    '''

        # --------------------------------------------
        # Building OSPF Configuration
        # --------------------------------------------
        spine1_ospfv3_config = '''
                        router ospfv3 ''' + str(forwardingSysDict['OSPF_AS']) + '''
                        router-id ''' + str(leavesDictList[0]['SPINE_1_UPLINK_PO']['spine_loop0_ip']) + '''
                        log-adjacency-changes detail
                        address-family ipv6 unicast
                            maximum-paths 16
        '''

        # --------------------------------------------
        # Building BGP Configuration
        # --------------------------------------------
        spine1_bgp_config = '''
                        route-map setnh_unchanged permit 10
                        
                        router bgp ''' + str(forwardingSysDict['BGP_AS_num']) + '''
                            router-id ''' + str(leavesDictList[0]['SPINE_1_UPLINK_PO']['spine_loop0_ip']) + '''
                            graceful-restart restart-time 180
                            reconnect-interval 1
                            log-neighbor-changes
                            address-family ipv4 unicast
                            address-family ipv6 unicast
                                redistribute direct route-map allow
                            address-family l2vpn evpn
                                maximum-paths 64
                            template peer ibgp_evpn
                                log-neighbor-changes
                                update-source loopback10
                                address-family l2vpn evpn
                                    allowas-in 3
                                    send-community both
                                    route-reflector-client
        '''

        # --------------------------------------------
        # Building BGP Neighbor Configuration
        # --------------------------------------------
        for leaf in leavesDictList:
            spine1_bgp_config += '''
                            neighbor ''' + str(leaf['loop10_ipv6']) + ''' remote-as ''' + str(forwardingSysDict['BGP_AS_num']) + '''
                            inherit peer ibgp_evpn
            '''

        # --------------------------------------------
        # Apply the configuration on the SPINEs.
        # --------------------------------------------
        
        print("=========== SPINE-1: Performing Configurations ===========")
        log.info("=========== SPINE-1: Performing Configurations ===========")
        spineList[0].configure(spine1_config + spine1_ospfv3_config + spine1_bgp_config)
    
def configureEVPNVPCLeafsIpv6(forwardingSysDict, vpc_leaves_dicts):

        # --------------------------------------------
        # Parse the arguments for their types
        # --------------------------------------------
        if type(vpc_leaves_dicts) is not dict:
            print("Passed Argument vpc_leaves_dicts is not a Dictionary of Leaf data")
            return 0
        if type(forwardingSysDict) is not dict:
            print("Passed Argument forwardingSysDict is not a Dictionary")
            return 0

        # --------------------------------------------
        # Building VPC Dialogs
        # --------------------------------------------
        # Continue (yes/no)? [no]
        vpc_dialog = Dialog([
            Statement(pattern=r'Continue \(yes/no\)\? \[no\]',
                      action='sendline(yes)',
                      loop_continue=True,
                      continue_timer=True)
        ])

        # --------------------------------------------
        # Parameters to be used in the following proc
        # --------------------------------------------
        leaf1_config, leaf2_config                      = "", ""
        leaf1_nve_config, leaf2_nve_config              = "", ""
        leaf1_vpc_config, leaf2_vpc_config              = "", ""
        leaf1_ospfv3_config, leaf2_ospfv3_config        = "", ""
        leaf1_bgp_config, leaf2_bgp_config              = "", ""

        leaf1       = list(vpc_leaves_dicts.keys())[0]
        leaf2       = list(vpc_leaves_dicts.keys())[1]
        leaf1_data  = vpc_leaves_dicts[leaf1]
        leaf2_data  = vpc_leaves_dicts[leaf2]

        leafDictLst = [leaf1_data, leaf2_data]

        if 'SPINE_COUNT' not in forwardingSysDict.keys():
            forwardingSysDict['SPINE_COUNT'] = 1

        if 'spine_leaf_po_v6' not in leaf1_data['SPINE_1_UPLINK_PO']:
            leaf1_data['SPINE_1_UPLINK_PO']['spine_leaf_po_v6']    = ""
            leaf1_data['SPINE_1_UPLINK_PO']['leaf_spine_mask_v6']  = ""
            leaf1_data['SPINE_1_UPLINK_PO']['spine_leaf_po_v6']    = ""
            leaf1_data['SPINE_1_UPLINK_PO']['leaf_spine_mask_v6']  = ""

        # --------------------------------------------
        # Print out the Parameters passed to the proc
        # --------------------------------------------
        print("========================================")
        print("Given Forwarding System Dictionary is")
        print("========================================")
        print(json.dumps(forwardingSysDict, indent=5))
        log.info("========================================")
        log.info("Given Forwarding System Dictionary is")
        log.info("========================================")
        log.info(json.dumps(forwardingSysDict, indent=5))

        for leaf_num in range(len(leafDictLst)):
            print("========================================")
            print("Given data dictionary of LEAF-" + str(leaf_num+1))
            print("========================================")
            print(json.dumps(leafDictLst[leaf_num], indent=6))
            log.info("========================================")
            log.info("Given data dictionary of LEAF-" + str(leaf_num+1))
            log.info("========================================")
            log.info(json.dumps(leafDictLst[leaf_num], indent=6))

        # -----------------------------------------------------
        # Buildup the configurations to be applied
        # -----------------------------------------------------
        leaf1_config += '''
            nv overlay evpn
            fabric forwarding anycast-gateway-mac 0000.000a.aaaa
        '''

        leaf2_config += '''
            nv overlay evpn
            fabric forwarding anycast-gateway-mac 0000.000a.aaaa
        '''

        leaf1_config += '''
                interface loopback10
                  ipv6 address ''' + str(leaf1_data['loop10_ipv6']) + '''/128
                  ipv6 router ospfv3 ''' + str(forwardingSysDict['OSPF_AS']) + ''' area 0.0.0.0
                  no shutdown
    
                interface loopback11
                  ipv6 address ''' + str(leaf1_data['NVE_data']['VTEP_IPV6']) + '''/128
                  ipv6 router ospfv3 ''' + str(forwardingSysDict['OSPF_AS']) + ''' area 0.0.0.0
                  no shutdown
                
                interface loopback12
                  ipv6 address ''' + str(leaf1_data['NVE_data']['VPC_VTEP_IPV6']) + '''/128
                  ipv6 router ospfv3 ''' + str(forwardingSysDict['OSPF_AS']) + ''' area 0.0.0.0
                  no shutdown      
        '''

        leaf2_config += '''
                interface loopback10
                  ipv6 address ''' + str(leaf2_data['loop10_ipv6']) + '''/128
                  ipv6 router ospfv3 ''' + str(forwardingSysDict['OSPF_AS']) + ''' area 0.0.0.0
                  no shutdown
    
                interface loopback11
                  ipv6 address ''' + str(leaf2_data['NVE_data']['VTEP_IPV6']) + '''/128
                  ipv6 router ospfv3 ''' + str(forwardingSysDict['OSPF_AS']) + ''' area 0.0.0.0
                  no shutdown
                
                interface loopback12
                  ipv6 address ''' + str(leaf2_data['NVE_data']['VPC_VTEP_IPV6']) + '''/128
                  ipv6 router ospfv3 ''' + str(forwardingSysDict['OSPF_AS']) + ''' area 0.0.0.0       
                  no shutdown
        '''

        # --------------------------------------------
        # Building VPC Configuration
        # --------------------------------------------
        leaf1_vpc_config += '''
                vrf context ''' + str(leaf1_data['VPC_data']['kp_al_vrf']) + '''

                vpc domain ''' + str(leaf1_data['VPC_data']['domain_id']) + '''
                  peer-switch
                  peer-keepalive destination ''' + str(leaf2_data['VPC_data']['kp_al_ip']) + ''' source ''' + str(leaf1_data['VPC_data']['kp_al_ip']) + '''
                  peer-gateway
                  ipv6 nd synchronize                    
                  ip arp synchronize
                  system-priority 3000
                  role priority 3000
                  
                interface port-channel''' + str(leaf1_data['VPC_data']['peer_link_po']) + '''
                  switchport
                  switchport mode trunk
                  spanning-tree port type network
                  vpc peer-link
                  no shut
        '''

        leaf2_vpc_config += '''
                vrf context ''' + str(leaf2_data['VPC_data']['kp_al_vrf']) + '''

                vpc domain ''' + str(leaf2_data['VPC_data']['domain_id']) + '''
                  peer-switch
                  peer-keepalive destination ''' + str(leaf1_data['VPC_data']['kp_al_ip']) + ''' source ''' + str(leaf2_data['VPC_data']['kp_al_ip']) + '''
                  peer-gateway
                  ipv6 nd synchronize                    
                  ip arp synchronize
                  system-priority 3000
                  role priority 3001
                  
                interface port-channel''' + str(leaf2_data['VPC_data']['peer_link_po']) + '''
                  switchport
                  switchport mode trunk
                  spanning-tree port type network
                  vpc peer-link                              
                  no shutdown
                interface port-channel''' + str(leaf1_data['VPC_data']['peer_link_po']) + '''
                  shutdown ; sleep 10 ; no shutdown
        '''

        # --------------------------------------------
        # Building OSPF Configuration
        # --------------------------------------------
        leaf1_ospfv3_config += '''
                router ospfv3 ''' + str(forwardingSysDict['OSPF_AS']) + '''
                  router-id ''' + str(leaf1_data['loop0_ip']) + '''
        '''

        leaf2_ospfv3_config += '''
                router ospfv3 ''' + str(forwardingSysDict['OSPF_AS']) + '''
                  router-id ''' + str(leaf2_data['loop0_ip']) + '''
        '''

        # --------------------------------------------
        # Building BGP Configuration
        # --------------------------------------------
        leaf1_bgp_config += '''
                route-map ANY permit 10
                      
                router bgp ''' + str(forwardingSysDict['BGP_AS_num']) + '''
                  router-id ''' + str(leaf1_data['loop0_ip']) + '''
                  graceful-restart restart-time 180
                  reconnect-interval 1
                  address-family ipv4 unicast
                  address-family ipv6 unicast
                    redistribute direct route-map allow
                  address-family l2vpn evpn
                    advertise-pip
                  template peer ibgp_evpn
                    log-neighbor-changes
                    update-source loopback10
                    address-family ipv6 unicast
                    address-family l2vpn evpn
                      allowas-in 3
                      send-community
                      send-community extended
        '''

        leaf2_bgp_config += '''
                route-map ANY permit 10

                router bgp ''' + str(forwardingSysDict['BGP_AS_num']) + '''
                  router-id ''' + str(leaf2_data['loop0_ip']) + '''
                  graceful-restart restart-time 180
                  reconnect-interval 1
                  address-family ipv4 unicast
                  address-family ipv6 unicast
                    redistribute direct route-map allow
                  address-family l2vpn evpn
                    advertise-pip
                  template peer ibgp_evpn
                    log-neighbor-changes
                    update-source loopback10
                    address-family ipv6 unicast
                    address-family l2vpn evpn
                        allowas-in 3
                      send-community
                      send-community extended
        '''

        # --------------------------------------------
        # Building BGP Neighbor Configuration
        # --------------------------------------------
        leaf1_bgp_config += '''
                  neighbor ''' + str(leaf1_data['SPINE_1_UPLINK_PO']['spine_loop10_ipv6']) + '''
                    inherit peer ibgp_evpn
                    remote-as ''' + str(forwardingSysDict['BGP_AS_num']) + '''
        '''

        leaf2_bgp_config += '''
                  neighbor ''' + str(leaf2_data['SPINE_1_UPLINK_PO']['spine_loop10_ipv6']) + '''
                    inherit peer ibgp_evpn
                    remote-as ''' + str(forwardingSysDict['BGP_AS_num']) + '''
        '''

        # --------------------------------------------
        # Building NVE Interface Configuration
        # --------------------------------------------
        leaf1_nve_config += '''
                interface nve1
                  no shutdown
                  host-reachability protocol bgp
                  advertise virtual-rmac
                  source-interface ''' + str(leaf1_data['NVE_data']['src_loop']) + ' anycast ' + str(leaf1_data['NVE_data']['anycast_loop']) + '''
        '''

        leaf2_nve_config += '''
                interface nve1
                  no shutdown
                  host-reachability protocol bgp
                  advertise virtual-rmac
                  source-interface ''' + str(leaf2_data['NVE_data']['src_loop']) + ' anycast ' + str(leaf2_data['NVE_data']['anycast_loop']) + '''
        '''

        # --------------------------------------------
        # Building VPC ACCESS PO Configuration
        # If List of POs are given then configure all.
        # If a single PO is given then configure PO.
        # --------------------------------------------
        if 'VPC_ACC_po' in leaf1_data['VPC_data'].keys() and 'VPC_ACC_po' in leaf2_data['VPC_data'].keys():
            if type(leaf1_data['VPC_data']['VPC_ACC_po']) is list and type(leaf2_data['VPC_data']['VPC_ACC_po']) is list:
                for PO in leaf1_data['VPC_data']['VPC_ACC_po']:
                    leaf1_vpc_config += '''
                    interface port-channel''' + str(PO) + '''
                      switchport
                      switchport mode access
                      spanning-tree port type edge
                      vpc ''' + str(PO) + '''
                      no shutdown
                    '''

                    leaf2_vpc_config += '''
                    interface port-channel''' + str(PO) + '''
                      switchport
                      switchport mode access
                      spanning-tree port type edge
                      vpc ''' + str(PO) + '''
                      no shutdown
                    '''

            elif type(leaf1_data['VPC_data']['VPC_ACC_po']) in [str, int] and type(leaf2_data['VPC_data']['VPC_ACC_po']) in [str, int]:
                leaf1_vpc_config += '''
                    interface port-channel''' + str(leaf1_data['VPC_data']['VPC_ACC_po']) + '''
                      switchport
                      switchport mode access
                      vpc ''' + str(leaf1_data['VPC_data']['VPC_ACC_po']) + '''
                      spanning-tree port type edge
                      no shutdown
                '''

                leaf2_vpc_config += '''
                    interface port-channel''' + str(leaf2_data['VPC_data']['VPC_ACC_po']) + '''
                      switchport
                      switchport mode access
                      vpc ''' + str(leaf2_data['VPC_data']['VPC_ACC_po']) + '''
                      spanning-tree port type edge
                      no shutdown
                '''
        else:
            log.info("VPC_ACC_po Key not present in the input DICT, hence skipping VPC Down stream PO configuration")
        # ----------------------------------------------------
        # Build Incremental configs for VRF, VNI, L2/L3 VLANs
        # ----------------------------------------------------
        # ----------------------------------------------------
        # LEAF Configuration Parameters
        # ----------------------------------------------------
        leaf_vlan_config    = ""
        leaf_vrf_config     = ""
        leaf_svi_config     = ""
        leaf_nve_config     = ""
        leaf_vni_bgp_config = ""

        # ----------------------------------------------------
        # Check if BGP IR
        # ----------------------------------------------------
        if "STATIC_IR_VNI_data" in leaf1_data.keys():
            
            # ----------------------------------------------------
            # Counter Variables
            # ----------------------------------------------------
            l3_vrf_count_iter   = 0
            ip_index            = 0
            l2_ipv6s            = []

            # ----------------------------------------------------
            # Fetching IP and VNI data from the configuration dict
            # ----------------------------------------------------
            total_ip_count  = int(leaf1_data['STATIC_IR_VNI_data']['VLAN_PER_VRF_count']) * int(leaf1_data['STATIC_IR_VNI_data']['VRF_count'])
            l2_ipv4s        = increment_prefix_network(ip.IPv4Interface(str(leaf1_data['STATIC_IR_VNI_data']['l2_vlan_ipv4_start']) + str(leaf1_data['STATIC_IR_VNI_data']['l2_vlan_ipv4_mask'])), total_ip_count)
            if 'l2_vlan_ipv6_start' in leaf1_data['STATIC_IR_VNI_data'].keys() and 'l2_vlan_ipv6_start' in leaf2_data['STATIC_IR_VNI_data'].keys():
                l2_ipv6s        = increment_prefix_network(ip.IPv6Interface(str(leaf1_data['STATIC_IR_VNI_data']['l2_vlan_ipv6_start']) + str(leaf1_data['STATIC_IR_VNI_data']['l2_vlan_ipv6_mask'])), total_ip_count)

            vrf_id          = leaf1_data['STATIC_IR_VNI_data']['VRF_id_start']

            l3_vlan_id      = leaf1_data['STATIC_IR_VNI_data']['l3_vlan_start']
            l3_vn_seg_id    = leaf1_data['STATIC_IR_VNI_data']['l3_vni_start']

            l2_vlan_id      = leaf1_data['STATIC_IR_VNI_data']['l2_vlan_start']
            l2_vn_seg_id    = leaf1_data['STATIC_IR_VNI_data']['l2_vni_start']

            # ----------------------------------------------------
            # Outer While Loop for L3 Configurations
            # ----------------------------------------------------
            while l3_vrf_count_iter < leaf1_data['STATIC_IR_VNI_data']['VRF_count']:
                # Configure L3 VRF and L3 VNIs
                leaf_vlan_config += '''
                        vlan ''' + str(l3_vlan_id) + '''
                        no shut
                        vn-segment ''' + str(l3_vn_seg_id) + '''
                '''

                leaf_vrf_config += '''
                        vrf context ''' + str(leaf1_data['STATIC_IR_VNI_data']['VRF_string']) + str(vrf_id) + '''
                        vni ''' + str(l3_vn_seg_id) + '''
                        rd auto
                        address-family ipv4 unicast
                            route-target both auto
                            route-target both auto evpn
                            export map ANY
                        address-family ipv6 unicast
                            route-target both auto
                            route-target both auto evpn
                            export map ANY
                '''

                leaf_svi_config += '''
                        interface Vlan''' + str(l3_vlan_id) + '''
                        no shutdown
                        vrf member ''' + str(leaf1_data['STATIC_IR_VNI_data']['VRF_string']) + str(vrf_id) + '''
                        no ip redirects
                        ip forward
                        ipv6 forward
                        no ipv6 redirects
                '''

                leaf_nve_config += '''
                        interface nve 1
                            member vni ''' + str(l3_vn_seg_id) + ''' associate-vrf
                '''

                leaf_vni_bgp_config += '''
                        router bgp ''' + str(forwardingSysDict['BGP_AS_num']) + '''
                            vrf ''' + str(leaf1_data['STATIC_IR_VNI_data']['VRF_string']) + str(vrf_id) + '''
                            address-family ipv4 unicast
                                advertise l2vpn evpn
                                wait-igp-convergence
                                redistribute direct route-map ANY
                            address-family ipv6 unicast
                                advertise l2vpn evpn
                                wait-igp-convergence
                                redistribute direct route-map ANY
                '''

                # ----------------------------------------------------
                # Inner while loop for L2 Configurations
                # ----------------------------------------------------
                l2_vlan_count_iter = 0
                while l2_vlan_count_iter < leaf1_data['STATIC_IR_VNI_data']['VLAN_PER_VRF_count']:
                    # Configure L2 VNIs
                    leaf_vlan_config += '''
                        vlan ''' + str(l2_vlan_id) + '''
                        no shut
                        vn-segment ''' + str(l2_vn_seg_id) + '''
                    '''

                    leaf_nve_config += '''
                        interface nve 1
                            member vni ''' + str(l2_vn_seg_id) + '''
                            ingress-replication protocol bgp
                    '''

                    leaf_vni_bgp_config += '''
                        router bgp ''' + str(forwardingSysDict['BGP_AS_num']) + '''
                            evpn
                            vni ''' + str(l2_vn_seg_id) + ''' l2
                                rd auto
                                route-target import auto
                                route-target export auto
                    '''

                    if "l2_vlan_ipv4_start" in leaf1_data['STATIC_IR_VNI_data'].keys() and "l2_vlan_ipv4_start" in leaf2_data['STATIC_IR_VNI_data'].keys():
                        leaf_svi_config += '''
                        interface Vlan''' + str(l2_vlan_id) + '''
                        no shutdown
                        vrf member ''' + str(leaf1_data['STATIC_IR_VNI_data']['VRF_string']) + str(vrf_id) + '''
                        no ip redirects
                        ip address ''' + str(l2_ipv4s[ip_index]) + '''
                        no ipv6 redirects
                        fabric forwarding mode anycast-gateway'''

                    if 'l2_vlan_ipv6_start' in leaf1_data['STATIC_IR_VNI_data'].keys() and 'l2_vlan_ipv6_start' in leaf2_data['STATIC_IR_VNI_data'].keys():
                        leaf_svi_config += '''
                        ipv6 address ''' + str(l2_ipv6s[ip_index]) + '''
                        '''

                    # Incrementing L2 VLAN Iteration counters
                    l2_vlan_count_iter += 1
                    l2_vlan_id += 1
                    l2_vn_seg_id += 1
                    ip_index += 1

                # Incrementing L3 VRF Iteration counters
                l3_vrf_count_iter += 1
                l3_vlan_id += 1
                l3_vn_seg_id += 1
                vrf_id += 1

        # ----------------------------------------------------
        # Perform the configurations
        # ----------------------------------------------------
        print("=========== LEAF1: Performing Base EVPN and VPC Configurations ===========")
        log.info("=========== LEAF1: Performing Base EVPN and VPC Configurations ===========")

        leaf1.configure(leaf1_config) 
        leaf1.configure(leaf1_vpc_config, reply=vpc_dialog, timeout=300) 
        leaf1.configure(leaf1_ospfv3_config + leaf1_bgp_config + leaf1_nve_config)
        print("=========== LEAF2: Performing Base EVPN and VPC Configurations ===========")
        log.info("=========== LEAF2: Performing Base EVPN and VPC Configurations ===========")
        leaf2.configure(leaf2_config) 
        leaf2.configure(leaf2_vpc_config, reply=vpc_dialog, timeout=300)
        leaf2.configure(leaf2_ospfv3_config + leaf2_bgp_config + leaf2_nve_config)

        print("=========== LEAF1: Performing NVE VLAN Configurations ===========")
        log.info("=========== LEAF1: Performing NVE VLAN Configurations ===========")
        leaf1.configure(leaf_vlan_config + leaf_vrf_config + leaf_svi_config + leaf_nve_config + leaf_vni_bgp_config)
        print("=========== LEAF2: Performing NVE VLAN Configurations ===========")
        log.info("=========== LEAF2: Performing NVE VLAN Configurations ===========")
        leaf2.configure(leaf_vlan_config + leaf_vrf_config + leaf_svi_config + leaf_nve_config + leaf_vni_bgp_config)


###################################################################################################
def configureEVPNLeafIPv6(leaf, forwardingSysDict, leaf_dict):

        # --------------------------------------------
        # Parse the arguments for their types
        # --------------------------------------------
        if type(leaf_dict) is not dict:
            print("Passed Argument leaves_dicts is not a LIST of Leaf dictionaries")
            return 0
        if type(forwardingSysDict) is not dict:
            print("Passed Argument forwardingSysDict is not a Dictionary")
            return 0

        # --------------------------------------------
        # Parameters to be used in the following proc
        # --------------------------------------------
        leaf1_config     = ""
        leaf1_nve_config        = ""
        leaf1_vpc_config        = ""
        leaf1_ospfv3_config       = ""
        leaf1_bgp_config        = ""

        if 'SPINE_COUNT' not in forwardingSysDict.keys():
            forwardingSysDict['SPINE_COUNT'] = 1

        if 'spine_leaf_po_v6' not in leaf_dict['SPINE_1_UPLINK_PO']:
            leaf_dict['SPINE_1_UPLINK_PO']['spine_leaf_po_v6']    = ""
            leaf_dict['SPINE_1_UPLINK_PO']['leaf_spine_mask_v6']  = ""
            leaf_dict['SPINE_1_UPLINK_PO']['spine_leaf_po_v6']    = ""
            leaf_dict['SPINE_1_UPLINK_PO']['leaf_spine_mask_v6']  = ""

        # --------------------------------------------
        # Print out the Parameters passed to the proc
        # --------------------------------------------
        print("========================================")
        print("Given Forwarding System Dictionary is")
        print("========================================")
        print(json.dumps(forwardingSysDict, indent=5))
        log.info("========================================")
        log.info("Given Forwarding System Dictionary is")
        log.info("========================================")
        log.info(json.dumps(forwardingSysDict, indent=5))

        print("========================================")
        print("Given data dictionary of LEAF")
        print("========================================")
        print(json.dumps(leaf_dict, indent=6))
        log.info("========================================")
        log.info("Given data dictionary of LEAF")
        log.info("========================================")
        log.info(json.dumps(leaf_dict, indent=6))

        # -----------------------------------------------------
        # Buildup the configurations to be applied
        # If the no.of SPINEs are 2 then configure any cast RP.
        # -----------------------------------------------------
        
        leaf1_config += '''
            nv overlay evpn
            fabric forwarding anycast-gateway-mac 0000.000a.aaaa
        '''

        leaf1_config += '''
                interface loopback10
                  ipv6 address ''' + str(leaf_dict['loop10_ipv6']) + '''/128
                  ip ospf network point-to-point
                  ipv6 router ospfv3 ''' + str(forwardingSysDict['OSPF_AS']) + ''' area 0.0.0.0

                interface loopback11
                  ipv6 address ''' + str(leaf_dict['NVE_data']['VTEP_IPV6']) + '''/128
                  ipv6 router ospfv3 ''' + str(forwardingSysDict['OSPF_AS']) + ''' area 0.0.0.0
        '''
        # --------------------------------------------
        # Building OSPF Configuration
        # --------------------------------------------
        leaf1_ospfv3_config += '''
                router ospfv3 ''' + str(forwardingSysDict['OSPF_AS']) + '''
                  router-id ''' + str(leaf_dict['loop0_ip']) + '''
        '''

        # --------------------------------------------
        # Building BGP Configuration
        # --------------------------------------------
        leaf1_bgp_config += '''
                route-map ANY permit 10

                router bgp ''' + str(forwardingSysDict['BGP_AS_num']) + '''
                  router-id ''' + str(leaf_dict['loop0_ip']) + '''
                  address-family ipv4 unicast
                  address-family ipv6 unicast
                    redistribute direct route-map allow
                  address-family l2vpn evpn
                  template peer ibgp_evpn
                    log-neighbor-changes
                    update-source loopback10
                    address-family l2vpn evpn
                      allowas-in 3
                      send-community
                      send-community extended
        '''

        # --------------------------------------------
        # Building BGP Neighbor Configuration
        # --------------------------------------------
        leaf1_bgp_config += '''
                  neighbor ''' + str(leaf_dict['SPINE_1_UPLINK_PO']['spine_loop10_ipv6']) + '''
                    inherit peer ibgp_evpn
                    remote-as ''' + str(forwardingSysDict['BGP_AS_num']) + '''
        '''

        # --------------------------------------------
        # Building BGP Neighbor Configuration
        # --------------------------------------------
        leaf1_nve_config += '''
                interface nve1
                  no shutdown
                  host-reachability protocol bgp
                  source-interface ''' + str(leaf_dict['NVE_data']['src_loop']) + '''
        '''

        # ----------------------------------------------------
        # Build Incremental configs for VRF, VNI, L2/L3 VLANs
        # ----------------------------------------------------
        # ----------------------------------------------------
        # LEAF Configuration Parameters
        # ----------------------------------------------------
        leaf_vlan_config = ""
        leaf_vrf_config = ""
        leaf_svi_config = ""
        leaf_nve_config = ""
        leaf_vni_bgp_config = ""

        # ----------------------------------------------------
        # Check if BGP IR
        # ----------------------------------------------------
        if "STATIC_IR_VNI_data" in leaf_dict.keys():
            
            # ----------------------------------------------------
            # Counter Variables
            # ----------------------------------------------------
            l3_vrf_count_iter = 0
            ip_index = 0
            l2_ipv6s = []

            # ----------------------------------------------------
            # Fetching IP and VNI data from the configuration dict
            # ----------------------------------------------------
            total_ip_count = int(leaf_dict['STATIC_IR_VNI_data']['VLAN_PER_VRF_count']) * int(leaf_dict['STATIC_IR_VNI_data']['VRF_count'])
            l2_ipv4s = increment_prefix_network(ip.IPv4Interface(str(leaf_dict['STATIC_IR_VNI_data']['l2_vlan_ipv4_start']) + str(leaf_dict['STATIC_IR_VNI_data']['l2_vlan_ipv4_mask'])), total_ip_count)
            if 'l2_vlan_ipv6_start' in leaf_dict['STATIC_IR_VNI_data'].keys():
                l2_ipv6s = increment_prefix_network(ip.IPv6Interface(str(leaf_dict['STATIC_IR_VNI_data']['l2_vlan_ipv6_start']) + str(leaf_dict['STATIC_IR_VNI_data']['l2_vlan_ipv6_mask'])), total_ip_count)
            
            vrf_id = leaf_dict['STATIC_IR_VNI_data']['VRF_id_start']

            l3_vlan_id = leaf_dict['STATIC_IR_VNI_data']['l3_vlan_start']
            l3_vn_seg_id = leaf_dict['STATIC_IR_VNI_data']['l3_vni_start']

            l2_vlan_id = leaf_dict['STATIC_IR_VNI_data']['l2_vlan_start']
            l2_vn_seg_id = leaf_dict['STATIC_IR_VNI_data']['l2_vni_start']

            # ----------------------------------------------------
            # Outer While Loop for L3 Configurations
            # ----------------------------------------------------
            while l3_vrf_count_iter < leaf_dict['STATIC_IR_VNI_data']['VRF_count']:
                # Configure L3 VRF and L3 VNIs
                leaf_vlan_config += '''
                        vlan ''' + str(l3_vlan_id) + '''
                        no shut
                        vn-segment ''' + str(l3_vn_seg_id) + '''
                '''

                leaf_vrf_config += '''
                        vrf context ''' + str(leaf_dict['STATIC_IR_VNI_data']['VRF_string']) + str(vrf_id) + '''
                        vni ''' + str(l3_vn_seg_id) + '''
                        rd auto
                        address-family ipv4 unicast
                            route-target both auto
                            route-target both auto evpn
                            export map ANY
                        address-family ipv6 unicast
                            route-target both auto
                            route-target both auto evpn
                            export map ANY
                '''

                leaf_svi_config += '''
                        interface Vlan''' + str(l3_vlan_id) + '''
                        no shutdown
                        vrf member ''' + str(leaf_dict['STATIC_IR_VNI_data']['VRF_string']) + str(vrf_id) + '''
                        no ip redirects
                        ip forward
                        ipv6 forward
                        no ipv6 redirects
                '''

                leaf_nve_config += '''
                        interface nve 1
                            member vni ''' + str(l3_vn_seg_id) + ''' associate-vrf
                '''

                leaf_vni_bgp_config += '''
                        router bgp ''' + str(forwardingSysDict['BGP_AS_num']) + '''
                            vrf ''' + str(leaf_dict['STATIC_IR_VNI_data']['VRF_string']) + str(vrf_id) + '''
                            address-family ipv4 unicast
                                advertise l2vpn evpn
                                wait-igp-convergence
                                redistribute direct route-map ANY
                            address-family ipv6 unicast
                                advertise l2vpn evpn
                                wait-igp-convergence
                                redistribute direct route-map ANY
                '''

                # ----------------------------------------------------
                # Inner while loop for L2 Configurations
                # ----------------------------------------------------
                l2_vlan_count_iter = 0
                while l2_vlan_count_iter < leaf_dict['STATIC_IR_VNI_data']['VLAN_PER_VRF_count']:
                    # Configure L2 VNIs
                    leaf_vlan_config += '''
                        vlan ''' + str(l2_vlan_id) + '''
                        no shut
                        vn-segment ''' + str(l2_vn_seg_id) + '''
                    '''

                    leaf_nve_config += '''
                        interface nve 1
                            member vni ''' + str(l2_vn_seg_id) + '''
                            ingress-replication protocol bgp
                    '''

                    leaf_vni_bgp_config += '''
                        router bgp ''' + str(forwardingSysDict['BGP_AS_num']) + '''
                            evpn
                            vni ''' + str(l2_vn_seg_id) + ''' l2
                                rd auto
                                route-target import auto
                                route-target export auto
                    '''

                    if "l2_vlan_ipv4_start" in leaf_dict['STATIC_IR_VNI_data'].keys():
                        leaf_svi_config += '''
                        interface Vlan''' + str(l2_vlan_id) + '''
                        no shutdown
                        vrf member ''' + str(leaf_dict['STATIC_IR_VNI_data']['VRF_string']) + str(vrf_id) + '''
                        no ip redirects
                        ip address ''' + str(l2_ipv4s[ip_index]) + '''
                        no ipv6 redirects
                        fabric forwarding mode anycast-gateway'''

                    if 'l2_vlan_ipv6_start' in leaf_dict['STATIC_IR_VNI_data'].keys():
                        leaf_svi_config += '''
                        ipv6 address ''' + str(l2_ipv6s[ip_index]) + '''
                        '''

                    # Incrementing L2 VLAN Iteration counters
                    l2_vlan_count_iter += 1
                    l2_vlan_id += 1
                    l2_vn_seg_id += 1
                    ip_index += 1

                # Incrementing L3 VRF Iteration counters
                l3_vrf_count_iter += 1
                l3_vlan_id += 1
                l3_vn_seg_id += 1
                vrf_id += 1

        # ----------------------------------------------------
        # Perform the configurations
        # ----------------------------------------------------
        print("=========== LEAF1: Performing Base EVPN and VPC Configurations ===========")
        log.info("=========== LEAF1: Performing Base EVPN and VPC Configurations ===========")
        leaf.configure(leaf1_config + leaf1_vpc_config + leaf1_ospfv3_config + leaf1_bgp_config + leaf1_nve_config)

        print("=========== LEAF1: Performing NVE VLAN Configurations ===========")
        log.info("=========== LEAF1: Performing NVE VLAN Configurations ===========")
        leaf.configure(leaf_vlan_config + leaf_vrf_config + leaf_svi_config + leaf_nve_config + leaf_vni_bgp_config)

def verifyEvpnUpLinkBGPSessions(forwardingSysDict, leavesDict):
        bgpSessionStat          = []
        bgpSessionMsgs          = "\n"

        # ----------------------------------------------------
        # Iterate through each leaf and its dict data
        # ----------------------------------------------------
        for leaf in leavesDict.keys():
            sessionOutput = leaf.execute('show bgp session | i ' + str(leavesDict[leaf]['SPINE_1_UPLINK_PO']['spine_loop10_ipv6']) + ' | i i E')
            if sessionOutput == "":
                bgpSessionStat.append(0)
                bgpSessionMsgs += "BGP Session from SPINE to LEAF_IP : " + str(leavesDict[leaf]['SPINE_1_UPLINK_PO']['spine_loop10_ipv6']) + " has not been established\n"
            elif str(leavesDict[leaf]['SPINE_1_UPLINK_PO']['spine_loop10_ipv6']) in sessionOutput and 'E' in sessionOutput:
                bgpSessionStat.append(1)
                bgpSessionMsgs += "BGP Session from SPINE to LEAF_IP : " + str(leavesDict[leaf]['SPINE_1_UPLINK_PO']['spine_loop10_ipv6']) + " has been established\n"
            else:
                bgpSessionStat.append(0)
                bgpSessionMsgs += "BGP Session from SPINE to LEAF_IP : " + str(leavesDict[leaf]['SPINE_1_UPLINK_PO']['spine_loop10_ipv6']) + " has not been established\n"

        if 0 in bgpSessionStat:
            return {'result' : 0, 'log' : bgpSessionMsgs}
        else:
            return {'result' : 1, 'log' : bgpSessionMsgs}

# ====================================================================================================#
def verifyEVPNNvePeers(leavesDict):
    nvePeerStat     = []
    nvePeerMsgs     = "\n"

    # ------------------------------------------------------------
    # Pick one Leaf and compare with all other and goto next Leaf
    # ------------------------------------------------------------
    for leaf in leavesDict.keys():
        for neighborPeer in leavesDict.keys():

            # ------------------------------------------------------------
            # Check if Current Leaf Neighbor Leaf are not same
            # ------------------------------------------------------------
            if leaf is not neighborPeer:

                # ------------------------------------------------------------
                # If Current and Neighbor Leaf are VPC with same VPC_VTEP_IPV6,
                # then continue to next iteration
                # ------------------------------------------------------------
                if 'VPC_VTEP_IPV6' in leavesDict[neighborPeer]['NVE_data'].keys() and 'VPC_VTEP_IPV6' in leavesDict[leaf]['NVE_data'].keys():
                    if leavesDict[leaf]['NVE_data']['VPC_VTEP_IPV6'] == leavesDict[neighborPeer]['NVE_data']['VPC_VTEP_IPV6']:
                        continue

                # ------------------------------------------------------------
                # If neighbor Leaf is a VPC then use VPC VTEP IP to verify
                # else verify with normal VTEP IP
                # ------------------------------------------------------------
                if 'VPC_VTEP_IPV6' in leavesDict[neighborPeer]['NVE_data'].keys():
                    nvePeerOutput = leaf.execute('sh nve peers peer-ip ' + str(leavesDict[neighborPeer]['NVE_data']['VPC_VTEP_IPV6']) + ' detail | xml | i i peer-state ')
                    if "Up" not in nvePeerOutput:
                        nvePeerStat.append(0)
                        nvePeerMsgs += "NVE Peer from : " + str(leaf) + " for " + str(leavesDict[neighborPeer]['NVE_data']['VPC_VTEP_IPV6']) + " has not been established\n"
                    else:
                        nvePeerStat.append(1)
                        nvePeerMsgs += "NVE Peer from : " + str(leaf) + " for " + str(leavesDict[neighborPeer]['NVE_data']['VPC_VTEP_IPV6']) + " has been established\n"
                else:
                    nvePeerOutput = leaf.execute('sh nve peers peer-ip ' + str(leavesDict[neighborPeer]['NVE_data']['VTEP_IPV6']) + ' detail | xml | i i peer-state ')
                    if "Up" not in nvePeerOutput:
                        nvePeerStat.append(0)
                        nvePeerMsgs += "NVE Peer from : " + str(leaf) + " for " + str(leavesDict[neighborPeer]['NVE_data']['VTEP_IPV6']) + " has not been established\n"
                    else:
                        nvePeerStat.append(1)
                        nvePeerMsgs += "NVE Peer from : " + str(leaf) + " for " + str(leavesDict[neighborPeer]['NVE_data']['VTEP_IPV6']) + " has been established\n"

    if 0 in nvePeerStat:
        return {'result' : 0, 'log' : nvePeerMsgs}
    else:
        return {'result' : 1, 'log' : nvePeerMsgs}
# ====================================================================================================#

def verifyEVPNVNIData(forwardingSysDict, leavesDict):
        vniStatusMsgs = "\n"
        vniStatusFlag = []

        for leaf in leavesDict.keys():

            vniStatusMsgs += "\n\nFor " + str(leaf.alias) + "\n"
            vniStatusMsgs += "====================================\n\n"

            if "STATIC_IR_VNI_data" in leavesDict[leaf].keys():
                
                # ----------------------------------------------------
                # Counter Variables
                # ----------------------------------------------------
                l3_vrf_count_iter = 0
                ip_index = 0

                # ----------------------------------------------------
                # Fetching IP and VNI data from the configuration dict
                # ----------------------------------------------------

                vrf_id          = leavesDict[leaf]['STATIC_IR_VNI_data']['VRF_id_start']

                l3_vlan_id      = leavesDict[leaf]['STATIC_IR_VNI_data']['l3_vlan_start']
                l3_vn_seg_id    = leavesDict[leaf]['STATIC_IR_VNI_data']['l3_vni_start']

                l2_vlan_id      = leavesDict[leaf]['STATIC_IR_VNI_data']['l2_vlan_start']
                l2_vn_seg_id    = leavesDict[leaf]['STATIC_IR_VNI_data']['l2_vni_start']

                # ----------------------------------------------------
                # Outer While Loop for L3 Configurations
                # ----------------------------------------------------
                while l3_vrf_count_iter < leavesDict[leaf]['STATIC_IR_VNI_data']['VRF_count']:

                    # Get L3 VNI data
                    vniStatusMsgs += "For VNI --> " + str(l3_vn_seg_id) + "\n"
                    vniData = leaf.execute("sh nve vni " + str(l3_vn_seg_id) + " | xml | i '<vni>|state>|<type>|<mcast>'")

                    # Verify VNI state to be UP
                    if re.search("<vni-state>Up<", vniData, re.I):
                        vniStatusMsgs += "\t PASS : VNI State is UP\n"
                        vniStatusFlag.append(1)
                    else:
                        vniStatusMsgs += "\t FAIL : VNI State is not UP\n"
                        vniStatusFlag.append(0)

                    # Verify VNI type to be L2/L3
                    if re.search("<type>L3", vniData, re.I):
                        vniStatusMsgs += "\t PASS : VNI Type (L3) Match Verified Successfully\n"
                        vniStatusFlag.append(1)
                    else:
                        vniStatusMsgs += "\t FAIL : VNI Type (L3) Match Failed\n"
                        vniStatusFlag.append(0)

                    L3_VRF = str(leavesDict[leaf]['STATIC_IR_VNI_data']['VRF_string']) + str(vrf_id)
                    if re.search("\[" + L3_VRF + "\]</type>", vniData, re.I):
                        vniStatusMsgs += "\t PASS : L3 VNI VRF Mapping Verified Successfully\n"
                        vniStatusFlag.append(1)
                    else:
                        vniStatusMsgs += "\t FAIL : L3 VNI VRF Mapping Failed\n"
                        vniStatusFlag.append(0)

                    # ----------------------------------------------------
                    # Inner while loop for L2 Configurations
                    # ----------------------------------------------------
                    l2_vlan_count_iter = 0
                    while l2_vlan_count_iter < leavesDict[leaf]['STATIC_IR_VNI_data']['VLAN_PER_VRF_count']:

                        # Get L2 VNI data
                        vniStatusMsgs += "For VNI --> " + str(l2_vn_seg_id) + "\n"
                        vniData = leaf.execute(
                            "sh nve vni " + str(l2_vn_seg_id) + " | xml | i '<vni>|state>|<type>|<mcast>'")

                        # Verify VNI state to be UP
                        if re.search("<vni-state>Up<", vniData, re.I):
                            vniStatusMsgs += "\t PASS : VNI State is UP\n"
                            vniStatusFlag.append(1)
                        else:
                            vniStatusMsgs += "\t FAIL : VNI State is not UP\n"
                            vniStatusFlag.append(0)

                        # Verify VNI type to be L2/L3
                        if re.search("<type>L2", vniData, re.I):
                            vniStatusMsgs += "\t PASS : VNI Type (L2) Match Verified Successfully\n"
                            vniStatusFlag.append(1)
                        else:
                            vniStatusMsgs += "\t FAIL : VNI Type (L2) Match Failed\n"
                            vniStatusFlag.append(0)

                        if re.search("\[" + str(l2_vlan_id) + "\]</type>", vniData, re.I):
                            vniStatusMsgs += "\t PASS : L2 VNI VLAN Mapping Verified Successfully\n"
                            vniStatusFlag.append(1)
                        else:
                            vniStatusMsgs += "\t FAIL : L2 VNI VLAN Mapping Failed\n"
                            vniStatusFlag.append(0)

                        # Incrementing L2 VLAN Iteration counters
                        l2_vlan_count_iter += 1
                        l2_vlan_id += 1
                        l2_vn_seg_id += 1
                        ip_index += 1

                    # Incrementing L3 VRF Iteration counters
                    l3_vrf_count_iter += 1
                    l3_vlan_id += 1
                    l3_vn_seg_id += 1
                    vrf_id += 1

        if 0 in vniStatusFlag:
            return {'result' : 0, 'log' : vniStatusMsgs}
        else:
            return {'result' : 1, 'log' : vniStatusMsgs}

def verifyEVPNNvePeers(leavesDict):
        nvePeerStat     = []
        nvePeerMsgs     = "\n"

        # ------------------------------------------------------------
        # Pick one Leaf and compare with all other and goto next Leaf
        # ------------------------------------------------------------
        for leaf in leavesDict.keys():
            for neighborPeer in leavesDict.keys():

                # ------------------------------------------------------------
                # Check if Current Leaf Neighbor Leaf are not same
                # ------------------------------------------------------------
                if leaf is not neighborPeer:

                    # ------------------------------------------------------------
                    # If Current and Neighbor Leaf are VPC with same VPC_VTEP_IP,
                    # then continue to next iteration
                    # ------------------------------------------------------------
                    if 'VPC_VTEP_IPV6' in leavesDict[neighborPeer]['NVE_data'].keys() and 'VPC_VTEP_IPV6' in leavesDict[leaf]['NVE_data'].keys():
                        if leavesDict[leaf]['NVE_data']['VPC_VTEP_IPV6'] == leavesDict[neighborPeer]['NVE_data']['VPC_VTEP_IPV6']:
                            continue

                    # ------------------------------------------------------------
                    # If neighbor Leaf is a VPC then use VPC VTEP IP to verify
                    # else verify with normal VTEP IP
                    # ------------------------------------------------------------
                    if 'VPC_VTEP_IPV6' in leavesDict[neighborPeer]['NVE_data'].keys():
                        nvePeerOutput = leaf.execute('sh nve peers peer-ip ' + str(leavesDict[neighborPeer]['NVE_data']['VPC_VTEP_IPV6']) + ' detail | xml | i i peer-state ')
                        if "Up" not in nvePeerOutput:
                            nvePeerStat.append(0)
                            nvePeerMsgs += "NVE Peer from : " + str(leaf) + " for " + str(leavesDict[neighborPeer]['NVE_data']['VPC_VTEP_IPV6']) + " has not been established\n"
                        else:
                            nvePeerStat.append(1)
                            nvePeerMsgs += "NVE Peer from : " + str(leaf) + " for " + str(leavesDict[neighborPeer]['NVE_data']['VPC_VTEP_IPV6']) + " has been established\n"
                    else:
                        nvePeerOutput = leaf.execute('sh nve peers peer-ip ' + str(leavesDict[neighborPeer]['NVE_data']['VTEP_IPV6']) + ' detail | xml | i i peer-state ')
                        if "Up" not in nvePeerOutput:
                            nvePeerStat.append(0)
                            nvePeerMsgs += "NVE Peer from : " + str(leaf) + " for " + str(leavesDict[neighborPeer]['NVE_data']['VTEP_IPV6']) + " has not been established\n"
                        else:
                            nvePeerStat.append(1)
                            nvePeerMsgs += "NVE Peer from : " + str(leaf) + " for " + str(leavesDict[neighborPeer]['NVE_data']['VTEP_IPV6']) + " has been established\n"

        if 0 in nvePeerStat:
            return {'result' : 0, 'log' : nvePeerMsgs}
        else:
            return {'result' : 1, 'log' : nvePeerMsgs}


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

def check_fex_state(testscript, device):
    fex_po      = testscript.parameters['PORTSEC_Dict']['fex_po']
    output = device.execute("show fex")
    if re.search("{po}\s+FEX0{po}\s+Online".format(po=fex_po), output):
        return True
    else: 
        return False
###################################################################
###                  GLOBAL VARIABLES                           ###
###################################################################

device_list             = []
traffic_stop_time       = 20
traffic_start_time      = 30
config_time             = 30
host_start_time         = 30
cr_file                 = 'PS_CR_CFG'
issu_time_limit         = 120
###################################################################
###                  COMMON SETUP SECTION                       ###
###################################################################

# Configure and setup all devices and test equipment in this section.
# This should represent the BASE CONFIGURATION that is applicable
# for the bunch of test cases that would follow.


class COMMON_SETUP(aetest.CommonSetup):
    """ Common Setup """

    log.info(banner("Common Setup"))

    @aetest.subsection
    def connecting_to_devices(self, testscript, testbed, uut_list, configurationFile, 
                              script_flags=None, abs_target_image=None, abs_base_image=None):
        """ common setup subsection: Connecting to devices """

        log.info(banner("Connecting to Devices"))

        # =============================================================================================================================#
        # Grab the device object of the uut device with that name
        if script_flags is None:
            script_flags = {}
        SPINE = testscript.parameters['SPINE'] = testbed.devices[uut_list['SPINE']]

        LEAF_1 = testscript.parameters['LEAF-1'] = testbed.devices[uut_list['LEAF-1']]
        LEAF_2 = testscript.parameters['LEAF-2'] = testbed.devices[uut_list['LEAF-2']]
        LEAF_3 = testscript.parameters['LEAF-3'] = testbed.devices[uut_list['LEAF-3']]

        FAN = testscript.parameters['FANOUT-3172'] = testbed.devices[uut_list['FANOUT-3172']]

        # =============================================================================================================================#
        # Connect to the device
        SPINE.connect()
        LEAF_1.connect()
        LEAF_2.connect()
        LEAF_3.connect()
        FAN.connect()

        device_list.append(SPINE)
        device_list.append(LEAF_1)
        device_list.append(LEAF_2)
        device_list.append(LEAF_3)
        device_list.append(FAN)

        # =============================================================================================================================#
        # Make sure that the connection went fine

        for dut in device_list:
            if not hasattr(dut, 'execute'):
                self.failed()

            if dut.execute != dut.connectionmgr.default.execute:
                self.failed()

        # testscript.parameters['abs_base_image'] = abs_base_image
        testscript.parameters['abs_target_image'] = abs_target_image
        testscript.parameters['abs_base_image'] = abs_base_image
        
        # =============================================================================================================================#
        # Import script_flags into testscript.parameters
        if script_flags is not None:
            if 'skip_device_config' in script_flags.keys():
                testscript.parameters['script_flags']['skip_device_config'] = script_flags['skip_device_config']
            else:
                testscript.parameters['script_flags']['skip_device_config'] = 0

            if 'skip_tgen_config' in script_flags.keys():
                testscript.parameters['script_flags']['skip_tgen_config'] = script_flags['skip_tgen_config']
            else:
                testscript.parameters['script_flags']['skip_tgen_config'] = 0

            if 'skip_device_cleanup' in script_flags.keys():
                testscript.parameters['script_flags']['skip_device_cleanup'] = script_flags['skip_device_cleanup']
            else:
                testscript.parameters['script_flags']['skip_device_cleanup'] = 0
        else:
            testscript.parameters['script_flags']['skip_device_config'] = 0
            testscript.parameters['script_flags']['skip_tgen_config'] = 0
            testscript.parameters['script_flags']['skip_device_cleanup'] = 0

    # =============================================================================================================================#
    # Import Configuration File and create required Structures

        with open(configurationFile) as cfgFile:
            configuration = yaml.load(cfgFile, Loader=Loader)

        testscript.parameters['LEAF_1_dict']            = configuration['LEAF_1_dict']
        testscript.parameters['LEAF_2_dict']            = configuration['LEAF_2_dict']
        testscript.parameters['LEAF_3_dict']            = configuration['LEAF_3_dict']
        
        testscript.parameters['LEAF_1_Orphan1_TGEN_dict']   = configuration['LEAF_1_Orphan1_TGEN_data']
        testscript.parameters['LEAF_1_Orphan2_TGEN_dict']   = configuration['LEAF_1_Orphan2_TGEN_data']
        testscript.parameters['LEAF_1_Fex_TGEN_dict']       = configuration['LEAF_1_Fex_TGEN_data']
        testscript.parameters['LEAF_3_TGEN_dict']       = configuration['LEAF_3_TGEN_data']
        testscript.parameters['LEAF_2_TGEN_dict']       = configuration['LEAF_2_TGEN_data']
        testscript.parameters['FANOUT_TGEN_dict']       = configuration['FANOUT_TGEN_data']
        
        testscript.parameters['PORTSEC_Dict']       = configuration['PORTSEC_Dict']
        testscript.parameters['forwardingSysDict']      = configuration['FWD_SYS_dict']

        testscript.parameters['leafVPCDictData']        = {LEAF_1 : configuration['LEAF_1_dict'], LEAF_2 : configuration['LEAF_2_dict']}
        testscript.parameters['leavesDictList']         = [configuration['LEAF_1_dict'], configuration['LEAF_2_dict'], configuration['LEAF_3_dict']]
        testscript.parameters['leavesDict']             = {LEAF_1 : configuration['LEAF_1_dict'],
                                                           LEAF_2 : configuration['LEAF_2_dict'],
                                                           LEAF_3 : configuration['LEAF_3_dict']}

        testscript.parameters['VTEP_List'] = [testscript.parameters['LEAF_1_dict'], testscript.parameters['LEAF_2_dict'], testscript.parameters['LEAF_3_dict']]

    # *****************************************************************************************************************************#

    @aetest.subsection
    def set_script_flags(self, testscript, configurationFile, job_file_params):
        global post_test_process_dict
        global cc_verification_dict
        LEAF_1 = testscript.parameters['LEAF-1']
        LEAF_2 = testscript.parameters['LEAF-2']
        LEAF_3 = testscript.parameters['LEAF-3']

        # =============================================================================================================================#
        # Import script_flags into testscript.parameters
        if 'script_flags' not in job_file_params.keys():
            script_flags = {}
            testscript.parameters['script_flags'] = {}
        else:
            script_flags = job_file_params['script_flags']
            testscript.parameters['script_flags'] = job_file_params['script_flags']

        if script_flags is not None:
            if 'skip_device_config' in script_flags.keys():
                testscript.parameters['script_flags']['skip_device_config'] = script_flags['skip_device_config']
            else:
                testscript.parameters['script_flags']['skip_device_config'] = 0

            if 'skip_tgen_config' in script_flags.keys():
                testscript.parameters['script_flags']['skip_tgen_config'] = script_flags['skip_tgen_config']
            else:
                testscript.parameters['script_flags']['skip_tgen_config'] = 0

            if 'skip_device_cleanup' in script_flags.keys():
                testscript.parameters['script_flags']['skip_device_cleanup'] = script_flags['skip_device_cleanup']
            else:
                testscript.parameters['script_flags']['skip_device_cleanup'] = 0

            if 'brcm_flag' in script_flags.keys():
                testscript.parameters['script_flags']['brcm_flag'] = script_flags['brcm_flag']
            else:
                testscript.parameters['script_flags']['brcm_flag'] = 0

            # if 'eor_flag' in script_flags.keys():
            #     testscript.parameters['script_flags']['eor_flag'] = script_flags['eor_flag']
            # else:
            #     testscript.parameters['script_flags']['eor_flag'] = 0
        else:
            testscript.parameters['script_flags']['skip_device_config'] = 0
            testscript.parameters['script_flags']['skip_tgen_config'] = 0
            testscript.parameters['script_flags']['skip_device_cleanup'] = 0

        post_test_process_dict = {}
        post_test_process_dict = job_file_params['postTestArgs']
        post_test_process_dict['dut_list'] = [LEAF_1, LEAF_2, LEAF_3]

        # cc_verification_dict = {}
        # # cc_verification_dict = job_file_params['postTestArgs']
        # if not testscript.parameters['script_flags']['eor_flag']:
        #     cc_verification_dict['cc_check'] = 1
        # cc_verification_dict['cores_check'] = 0
        # cc_verification_dict['logs_check'] = 1
        # cc_verification_dict['fnl_flag'] = 1
        # cc_verification_dict['dut_list'] = [LEAF_1, LEAF_2, LEAF_3]

        log.info("===> Post Test Check Process Parameters")
        log.info(post_test_process_dict)

        # log.info("===> CC Verification Parameters")
        # log.info(cc_verification_dict)

        # Flags to control pre-clean, config and EOR Trigger test-cases
        resn = "Skipped by the user via job file"
        # eorCCresn = "Skipping CC since EOR does not support VxLAN CC"
        log.info(resn)
        if job_file_params['script_flags']['skip_device_config']:
            aetest.skip.affix(section=DEVICE_BRINGUP, reason=resn)

        # if job_file_params['script_flags']['skip_eor_triggers']:
        #     aetest.skip.affix(section=TC022_vxlan_vpc_leaf1_LC_reload, reason=resn)
        #     aetest.skip.affix(section=TC023_vxlan_vpc_leaf2_LC_reload, reason=resn)
        #     aetest.skip.affix(section=TC024_vxlan_leaf3_LC_reload, reason=resn)
        #     aetest.skip.affix(section=TC025_vxlan_vpc_leaf1_FM_all_reload, reason=resn)
        #     aetest.skip.affix(section=TC026_vxlan_vpc_leaf2_FM_all_reload, reason=resn)
        #     aetest.skip.affix(section=TC027_vxlan_leaf3_FM_all_reload, reason=resn)
        #     aetest.skip.affix(section=TC028_vxlan_vpc_leaf1_SC_all_reload, reason=resn)
        #     aetest.skip.affix(section=TC029_vxlan_vpc_leaf2_SC_all_reload, reason=resn)
        #     aetest.skip.affix(section=TC030_vxlan_leaf3_SC_all_reload, reason=resn)
        #     aetest.skip.affix(section=TC031_vxlan_vpc_leaf1_SSO, reason=resn)
        #     aetest.skip.affix(section=TC032_vxlan_vpc_leaf2_SSO, reason=resn)
        #     aetest.skip.affix(section=TC033_vxlan_leaf3_SSO, reason=resn)
        
    @aetest.subsection
    def get_interfaces(self, testscript):
        """ common setup subsection: Getting required Connections for Test """

        log.info(banner("Retrieve the interfaces from Yaml file"))

        SPINE = testscript.parameters['SPINE']
        LEAF_1 = testscript.parameters['LEAF-1']
        LEAF_2 = testscript.parameters['LEAF-2']
        LEAF_3 = testscript.parameters['LEAF-3']
        FAN = testscript.parameters['FANOUT-3172']
        # IXIA = testscript.parameters['IXIA']

        # =============================================================================================================================#

        log.info("================================================")
        log.info("All Available Interfaces from the YAML file are:")
        for dut in device_list:
            log.info("\n\n--->" + str(dut) + " Interface list")
            for interface in dut.interfaces.keys():
                log.info(str(interface) + " --> " + str(dut.interfaces[interface].intf))

        # =============================================================================================================================#
        # Fetching the specific interfaces
        testscript.parameters['intf_SPINE_to_LEAF_1']       = SPINE.interfaces['SPINE_to_LEAF-1'].intf
        testscript.parameters['intf_SPINE_to_LEAF_2']       = SPINE.interfaces['SPINE_to_LEAF-2'].intf
        testscript.parameters['intf_SPINE_to_LEAF_3']       = SPINE.interfaces['SPINE_to_LEAF-3'].intf

        testscript.parameters['intf_LEAF_1_to_LEAF_2_1']    = LEAF_1.interfaces['LEAF-1_to_LEAF-2_1'].intf
        testscript.parameters['intf_LEAF_1_to_LEAF_2_2']    = LEAF_1.interfaces['LEAF-1_to_LEAF-2_2'].intf
        testscript.parameters['intf_LEAF_1_to_SPINE']       = LEAF_1.interfaces['LEAF-1_to_SPINE'].intf
        testscript.parameters['intf_LEAF_1_to_FAN3172']     = LEAF_1.interfaces['LEAF-1_to_FAN3172'].intf
        testscript.parameters['intf_LEAF_1_1_to_IXIA']      = LEAF_1.interfaces['LEAF-1_1_to_IXIA'].intf
        testscript.parameters['intf_LEAF_1_2_to_IXIA']      = LEAF_1.interfaces['LEAF-1_2_to_IXIA'].intf
        testscript.parameters['intf_LEAF_1_FEX_to_IXIA']    = LEAF_1.interfaces['LEAF-1_FEX_to_IXIA'].intf

        testscript.parameters['intf_LEAF_2_to_LEAF_1_1']    = LEAF_2.interfaces['LEAF-2_to_LEAF-1_1'].intf
        testscript.parameters['intf_LEAF_2_to_LEAF_1_2']    = LEAF_2.interfaces['LEAF-2_to_LEAF-1_2'].intf
        testscript.parameters['intf_LEAF_2_to_SPINE']       = LEAF_2.interfaces['LEAF-2_to_SPINE'].intf
        testscript.parameters['intf_LEAF_2_to_IXIA']        = LEAF_2.interfaces['LEAF-2_to_IXIA'].intf
        testscript.parameters['intf_LEAF_2_to_FAN3172']     = LEAF_2.interfaces['LEAF-2_to_FAN3172'].intf

        testscript.parameters['intf_LEAF_3_to_SPINE']       = LEAF_3.interfaces['LEAF-3_to_SPINE'].intf
        testscript.parameters['intf_LEAF_3_to_IXIA']        = LEAF_3.interfaces['LEAF-3_to_IXIA'].intf

        testscript.parameters['intf_FAN3172_to_LEAF_1']     = FAN.interfaces['FAN3172_to_LEAF-1'].intf
        testscript.parameters['intf_FAN3172_to_LEAF_2']     = FAN.interfaces['FAN3172_to_LEAF-2'].intf
        testscript.parameters['intf_FAN3172_to_IXIA']       = FAN.interfaces['FAN3172_to_IXIA'].intf

        # =============================================================================================================================#

        log.info("\n\n================================================")
        log.info("Topology Specific Interfaces \n\n")
        for key in testscript.parameters.keys():
            if "intf_" in key:
                log.info("%-25s   ---> %-15s" % (key, testscript.parameters[key]))
        log.info("\n\n")

    # *****************************************************************************************************************************#

    @aetest.subsection
    def topology_used_for_suite(self):
        """ common setup subsection: Represent Topology """

        log.info(banner("Topology to be used"))

        # Set topology to be used
        topology = """
        
                                            +-------------+
                                            |    SPINE    |
                                            +-------------+
                                           /       |       \\
                                          /        |        \\
                                         /         |         \\
                                        /          |          \\
                                       /           |           \\
                                      /            |            \\
            +---------+       +-----------+    +-----------+    +-----------+
            |   IXIA  |-------|   LEAF-1  |====|   LEAF-2  |    |   LEAF-3  |
            +---------+       +-----------+    +-----------+    +-----------+
                                   \\             /                 |
                                    \\           /                  |
                                     \\         /                   |
                                      \\       /                    |
                                    +-----------+             +-----------+
                                    |   FAN     |             |   IXIA    |
                                    +-----------+             +-----------+     
                                         |
                                         |
                                    +-----------+
                                    |   IXIA    |
                                    +-----------+
        """

        log.info("Topology to be used is")
        log.info(topology)


# *****************************************************************************************************************************#
class DEVICE_BRINGUP(aetest.Testcase):
    """Device Bring-up Test-Case"""

    log.info(banner("Device Bring UP"))

    @aetest.test
    def enable_feature_set(self, testscript):
        """ Device Bring-up subsection: Configuring Features and Feature-sets """

        log.info(banner("Enabling Feature Set"))

        # Do not perform configurations if skip_device_config flag is set
        if not testscript.parameters['script_flags']['skip_device_config']:

            testscript.parameters['leafLst']                = leafLst               = [testscript.parameters['LEAF-1'], testscript.parameters['LEAF-2'], testscript.parameters['LEAF-3']]
            testscript.parameters['spineFeatureList']       = spineFeatureList      = ['ospf', 'ospfv3', 'bgp', 'pim', 'lacp', 'nv overlay']
            testscript.parameters['vpcLeafFeatureList']     = vpcLeafFeatureList    = ['vpc', 'ospf', 'ospfv3', 'bgp', 'interface-vlan', 'vn-segment-vlan-based', 'lacp', 'nv overlay', 'fabric forwarding', 'port-security']
            testscript.parameters['LeafFeatureList']        = LeafFeatureList       = ['ospf', 'ospfv3', 'bgp', 'interface-vlan', 'vn-segment-vlan-based', 'lacp', 'nv overlay', 'fabric forwarding', 'port-security']
            testscript.parameters['fanOutFeatureList']      = fanOutFeatureList     = ['lacp']
            configFeatureSet_status = []
            configFeatureSet_msgs = ""

            # --------------------------------
            # Configure Features on SPINE
            featureConfigureSpine_status = infraConfig.configureVerifyFeature(testscript.parameters['SPINE'], spineFeatureList)
            if featureConfigureSpine_status['result']:
                log.info("Passed Configuring features on SPINE")
            else:
                log.debug("Failed configuring features on SPINE")
                configFeatureSet_msgs += featureConfigureSpine_status['log']
                configFeatureSet_status.append(0)

            # --------------------------------
            # Configure Feature-set on LEAF-1
            featureConfigureLeaf1_status = infraConfig.configureVerifyFeature(testscript.parameters['LEAF-1'], vpcLeafFeatureList)
            if featureConfigureLeaf1_status['result']:
                log.info("Passed Configuring features on LEAF-1")
            else:
                log.debug("Failed configuring features on LEAF-1")
                configFeatureSet_msgs += featureConfigureLeaf1_status['log']
                configFeatureSet_status.append(0)

            # --------------------------------
            # Configure Feature-set on LEAF-2
            featureConfigureLeaf2_status = infraConfig.configureVerifyFeature(testscript.parameters['LEAF-2'], vpcLeafFeatureList)
            if featureConfigureLeaf2_status['result']:
                log.info("Passed Configuring features on LEAF-2")
            else:
                log.debug("Failed configuring features on LEAF-2")
                configFeatureSet_msgs += featureConfigureLeaf1_status['log']
                configFeatureSet_status.append(0)

            # --------------------------------
            # Configure Feature-set on LEAF-3
            featureConfigureLeaf3_status = infraConfig.configureVerifyFeature(testscript.parameters['LEAF-3'], LeafFeatureList)
            if featureConfigureLeaf3_status['result']:
                log.info("Passed Configuring features on LEAF-3")
            else:
                log.debug("Failed configuring features on LEAF-3")
                configFeatureSet_msgs += featureConfigureLeaf1_status['log']
                configFeatureSet_status.append(0)

            # --------------------------------
            # Configure Feature Set on Leafs
            featureSetConfigureLeafs_status = infraConfig.configureVerifyFeatureSet(leafLst, ['mpls'])
            if featureSetConfigureLeafs_status['result']:
                log.info("Passed Configuring feature Sets on all Leafs")
            else:
                log.debug("Failed Configuring feature Sets on all Leafs")
                configFeatureSet_msgs += featureSetConfigureLeafs_status['log']
                configFeatureSet_status.append(0)

            featureConfigureLeafs_status = infraConfig.configureVerifyFeature(leafLst, LeafFeatureList)
            if featureConfigureLeafs_status['result']:
                log.info("Passed Configuring features on LEAFs")
            else:
                log.debug("Failed configuring features on LEAFs")
                configFeatureSet_msgs += featureConfigureLeafs_status['log']
                configFeatureSet_status.append(0)

            # --------------------------------
            # Configure Feature-set on FANOUTs
            featureConfigureFan_status = infraConfig.configureVerifyFeature(testscript.parameters['FANOUT-3172'], fanOutFeatureList)
            if featureConfigureFan_status['result']:
                log.info("Passed Configuring features on FAN boxes")
            else:
                log.debug("Failed configuring features on FAN boxes")
                configFeatureSet_msgs += featureConfigureFan_status['log']
                configFeatureSet_status.append(0)

            if 0 in configFeatureSet_status:
                self.failed(reason=configFeatureSet_msgs, goto=['common_cleanup'])

        else:
            self.passed(reason="Skipped Device Configuration as per request")


    # *****************************************************************************************************************************#

    @aetest.test
    def configure_SPINE(self, testscript):
        """ Device Bring-up subsection: Configuring SPINE """

        configureEVPNSpinesIpv6([testscript.parameters['SPINE']], testscript.parameters['forwardingSysDict'] , testscript.parameters['leavesDictList'])

        try:
            testscript.parameters['SPINE'].configure('''
                interface ''' + str(testscript.parameters['intf_SPINE_to_LEAF_1']) + '''
                    no switchport
                    ipv6 address ''' + str(testscript.parameters['LEAF_1_dict']['SPINE_1_UPLINK_PO']['spine_leaf_po_v6']) + str(testscript.parameters['LEAF_1_dict']['SPINE_1_UPLINK_PO']['spine_leaf_mask_v6']) + '''
                    ipv6 router ospfv3 ''' + str(testscript.parameters['forwardingSysDict']['OSPF_AS']) + ''' area 0.0.0.0
                    no shutdown
                interface ''' + str(testscript.parameters['intf_SPINE_to_LEAF_2']) + '''
                    no switchport
                    ipv6 address ''' + str(testscript.parameters['LEAF_2_dict']['SPINE_1_UPLINK_PO']['spine_leaf_po_v6']) + str(testscript.parameters['LEAF_2_dict']['SPINE_1_UPLINK_PO']['spine_leaf_mask_v6']) + '''
                    ipv6 router ospfv3 ''' + str(testscript.parameters['forwardingSysDict']['OSPF_AS']) + ''' area 0.0.0.0
                    no shutdown
                interface ''' + str(testscript.parameters['intf_SPINE_to_LEAF_3']) + '''
                    no switchport
                    ipv6 address ''' + str(testscript.parameters['LEAF_3_dict']['SPINE_1_UPLINK_PO']['spine_leaf_po_v6']) + str(testscript.parameters['LEAF_3_dict']['SPINE_1_UPLINK_PO']['spine_leaf_mask_v6']) + '''
                    ipv6 router ospfv3 ''' + str(testscript.parameters['forwardingSysDict']['OSPF_AS']) + ''' area 0.0.0.0
                    no shutdown
            ''')
        except Exception as error:
            log.debug("Unable to configure - Encountered Exception " + str(error))
            self.failed('Exception occurred while configuring on SPINE', goto=['common_cleanup'])

    # *****************************************************************************************************************************#
    @aetest.test
    def configure_LEAF_1_2(self, testscript):
        """ Device Bring-up subsection: Configuring LEAF-1 """

        configureEVPNVPCLeafsIpv6(testscript.parameters['forwardingSysDict'], testscript.parameters['leafVPCDictData'])

        try:
            testscript.parameters['LEAF-1'].configure('''
              interface ''' + str(testscript.parameters['intf_LEAF_1_to_SPINE']) + '''
                no switchport
                ipv6 address ''' + str(testscript.parameters['LEAF_1_dict']['SPINE_1_UPLINK_PO']['leaf_spine_po_v6']) + str(testscript.parameters['LEAF_1_dict']['SPINE_1_UPLINK_PO']['leaf_spine_mask_v6']) + '''
                ipv6 router ospfv3 ''' + str(testscript.parameters['forwardingSysDict']['OSPF_AS']) + ''' area 0.0.0.0
                no shutdown
              default interface ''' + str(testscript.parameters['intf_LEAF_1_to_FAN3172']) + '''
              interface ''' + str(testscript.parameters['intf_LEAF_1_to_FAN3172']) + '''
                switchport
                switchport mode access
                switchport access vlan ''' + str(testscript.parameters['LEAF_1_Orphan1_TGEN_dict']['vlan_id']) + '''
                channel-group ''' + str(testscript.parameters['LEAF_1_dict']['VPC_data']['VPC_ACC_po']) + '''
                no shutdown
              interface port-channel ''' + str(testscript.parameters['LEAF_1_dict']['VPC_data']['VPC_ACC_po']) + '''
                switchport
                switchport mode access
                switchport access vlan ''' + str(testscript.parameters['LEAF_1_Orphan1_TGEN_dict']['vlan_id']) + '''
                spanning-tree port type edge
                vpc ''' + str(testscript.parameters['LEAF_1_dict']['VPC_data']['VPC_ACC_po']) + '''
                no shut
              default interface ''' + str(testscript.parameters['intf_LEAF_1_to_LEAF_2_1']) + '''
              interface ''' + str(testscript.parameters['intf_LEAF_1_to_LEAF_2_1']) + '''
                switchport
                switchport mode trunk
                channel-group ''' + str(testscript.parameters['LEAF_1_dict']['VPC_data']['peer_link_po']) + ''' mode active
                no shutdown
              default interface ''' + str(testscript.parameters['intf_LEAF_1_1_to_IXIA']) + '''
              interface ''' + str(testscript.parameters['intf_LEAF_1_1_to_IXIA']) + '''
                switchport
                switchport mode access
                switchport access vlan ''' + str(testscript.parameters['LEAF_1_Orphan1_TGEN_dict']['vlan_id']) + '''
                spanning-tree port type edge
                no shutdown
              default interface ''' + str(testscript.parameters['intf_LEAF_1_2_to_IXIA']) + '''
              interface ''' + str(testscript.parameters['intf_LEAF_1_2_to_IXIA']) + '''
                switchport
                switchport mode access
                switchport access vlan ''' + str(testscript.parameters['LEAF_1_Orphan1_TGEN_dict']['vlan_id']) + '''
                spanning-tree port type edge
                no shutdown
          ''')
        except Exception as error:
            log.debug("Unable to configure - Encountered Exception " + str(error))
            self.errored('Exception occurred while configuring on LEAF-1', goto=['common_cleanup'])

        try:
            testscript.parameters['LEAF-2'].configure('''
              interface ''' + str(testscript.parameters['intf_LEAF_2_to_SPINE']) + '''
                no switchport
                ipv6 address ''' + str(testscript.parameters['LEAF_2_dict']['SPINE_1_UPLINK_PO']['leaf_spine_po_v6']) + str(testscript.parameters['LEAF_2_dict']['SPINE_1_UPLINK_PO']['leaf_spine_mask_v6']) + '''
                ipv6 router ospfv3 ''' + str(testscript.parameters['forwardingSysDict']['OSPF_AS']) + ''' area 0.0.0.0
                no shutdown
              default interface ''' + str(testscript.parameters['intf_LEAF_2_to_FAN3172']) + '''
              interface ''' + str(testscript.parameters['intf_LEAF_2_to_FAN3172']) + '''
                switchport
                switchport mode access
                switchport access vlan ''' + str(testscript.parameters['LEAF_2_dict']['STATIC_IR_VNI_data']['l2_vlan_start']) + '''
                spanning-tree port type edge
                channel-group ''' + str(testscript.parameters['LEAF_2_dict']['VPC_data']['VPC_ACC_po']) + '''
                no shutdown
              interface port-channel ''' + str(testscript.parameters['LEAF_2_dict']['VPC_data']['VPC_ACC_po']) + '''
                switchport
                switchport mode access
                switchport access vlan ''' + str(testscript.parameters['LEAF_2_dict']['STATIC_IR_VNI_data']['l2_vlan_start']) + '''
                spanning-tree port type edge
              default interface ''' + str(testscript.parameters['intf_LEAF_2_to_LEAF_1_1']) + '''
              interface ''' + str(testscript.parameters['intf_LEAF_2_to_LEAF_1_1']) + '''
                switchport
                switchport mode trunk
                channel-group ''' + str(testscript.parameters['LEAF_2_dict']['VPC_data']['peer_link_po']) + ''' mode active
                no shutdown
          ''')
        except Exception as error:
            log.debug("Unable to configure - Encountered Exception " + str(error))
            self.errored('Exception occurred while configuring on LEAF-2', goto=['common_cleanup'])

    # *****************************************************************************************************************************#

    @aetest.test
    def configure_LEAF_3(self, testscript):
        """ Device Bring-up subsection: Configuring LEAF-3 """

        configureEVPNLeafIPv6(testscript.parameters['LEAF-3'], testscript.parameters['forwardingSysDict'], testscript.parameters['LEAF_3_dict'])

        try:
            testscript.parameters['LEAF-3'].configure('''
              
              interface ''' + str(testscript.parameters['intf_LEAF_3_to_SPINE']) + '''
                no switchport
                ipv6 address ''' + str(testscript.parameters['LEAF_3_dict']['SPINE_1_UPLINK_PO']['leaf_spine_po_v6']) + str(testscript.parameters['LEAF_3_dict']['SPINE_1_UPLINK_PO']['leaf_spine_mask_v6']) + '''
                ipv6 router ospfv3 ''' + str(testscript.parameters['forwardingSysDict']['OSPF_AS']) + ''' area 0.0.0.0
                no shutdown
              default interface ''' + str(testscript.parameters['intf_LEAF_3_to_IXIA']) + '''
              interface ''' + str(testscript.parameters['intf_LEAF_3_to_IXIA']) + '''
                switchport
                switchport mode access
                switchport access vlan ''' + str(testscript.parameters['LEAF_3_TGEN_dict']['vlan_id']) + '''
                spanning-tree port type edge
                no shutdown
          ''')

        except Exception as error:
            log.debug("Unable to configure - Encountered Exception " + str(error))
            self.errored('Exception occurred while configuring on LEAF-3', goto=['common_cleanup'])

    # *****************************************************************************************************************************#

    @aetest.test
    def configure_FAN(self, testscript):
        """ Device Bring-up subsection: Configuring FAN """

        fanOut_vlanConfiguration   = ""

        l3_vrf_count_iter           = 0
        l2_vlan_id                  = testscript.parameters['LEAF_1_dict']['STATIC_IR_VNI_data']['l2_vlan_start']
        l3_vlan_id                  = testscript.parameters['LEAF_1_dict']['STATIC_IR_VNI_data']['l3_vlan_start']

        while l3_vrf_count_iter < testscript.parameters['forwardingSysDict']['VRF_count']:
            l2_vlan_count_iter = 0
            fanOut_vlanConfiguration += '''vlan ''' + str(l3_vlan_id) + '''
                                           no shut\n'''
            while l2_vlan_count_iter < testscript.parameters['forwardingSysDict']['VLAN_PER_VRF_count']:
                # Incrementing L2 VLAN Iteration counters
                fanOut_vlanConfiguration += '''vlan ''' + str(l2_vlan_id) + '''
                                               no shut\n'''
                l2_vlan_count_iter += 1
                l2_vlan_id += 1
            
            # Incrementing L3 VRF Iteration counters
            l3_vrf_count_iter += 1
            l3_vlan_id += 1

        val = int(testscript.parameters['LEAF_3_TGEN_dict']['vlan_id']) + 1
        print(val)
        cmd = '''vlan ''' + str(testscript.parameters['LEAF_3_TGEN_dict']['vlan_id']) + '''
                  no shut
                 default interface ''' + str(testscript.parameters['intf_FAN3172_to_IXIA']) + '''
                 interface ''' + str(testscript.parameters['intf_FAN3172_to_IXIA']) + '''
                  switchport
                  switchport mode access
                  spanning-tree port type edge
                  no shut
              '''
        try:
            testscript.parameters['FANOUT-3172'].configure(str(fanOut_vlanConfiguration))
        except Exception as error:
            log.debug("Unable to configure - Encountered Exception " + str(error))
            self.errored('Exception occurred while configuring on FAN', goto=['common_cleanup'])
            
        try:
            testscript.parameters['FANOUT-3172'].configure(cmd)
        except Exception as error:
            log.debug("Unable to configure - Encountered Exception " + str(error))
            self.errored('Exception occurred while configuring on FAN', goto=['common_cleanup'])

    # *****************************************************************************************************************************#

    @aetest.test
    def configure_access_vlan_port_security(self, testscript, testbed, steps):
        prim_vtep       = testscript.parameters['LEAF-1']
        sec_vtep        = testscript.parameters['LEAF-2']
        sa_vtep         = testscript.parameters['LEAF-3']
        fan_3172        = testscript.parameters['FANOUT-3172']
    
        prim_vtep_if        = str(testscript.parameters['intf_LEAF_1_1_to_IXIA'])
        prim_vtep_if1       = str(testscript.parameters['intf_LEAF_1_2_to_IXIA'])
        sec_vtep_if         = str(testscript.parameters['intf_LEAF_2_to_IXIA'])
        sa_vtep_if          = str(testscript.parameters['intf_LEAF_3_to_IXIA'])
        leaf1_to_fan_if     = str(testscript.parameters['intf_LEAF_1_to_FAN3172'])
        leaf2_to_fan_if     = str(testscript.parameters['intf_LEAF_2_to_FAN3172'])
        fan_to_leaf1        = str(testscript.parameters['intf_FAN3172_to_LEAF_1'])
        fan_to_leaf2        = str(testscript.parameters['intf_FAN3172_to_LEAF_2'])
        fan_to_ixia         = str(testscript.parameters['intf_FAN3172_to_IXIA'])
        fex_vtep_if         = str(testscript.parameters['intf_LEAF_1_FEX_to_IXIA'])
        vlan1               = int(testscript.parameters['LEAF_1_Orphan1_TGEN_dict']['vlan_id'])
        vlan3               = int(testscript.parameters['LEAF_3_TGEN_dict']['vlan_id'])
        
        with steps.start("Defaulting Orphan1 interface"):
            try:
                prim_vtep.configure('default interface {intf}'.format(intf=prim_vtep_if))
            except Exception as error:
                log.debug("Unable to configure - Encountered Exception " + str(error))
                self.errored('Exception occured during default interface configuration', 
                             goto=['common_cleanup'])
        
        with steps.start("Defaulting Orphan2 interface"):
            try:
                prim_vtep.configure('default interface {intf}'.format(intf=prim_vtep_if))
            except Exception as error:
                log.debug("Unable to configure - Encountered Exception " + str(error))
                self.errored('Exception occured during default interface configuration', 
                             goto=['common_cleanup'])

        with steps.start("Defaulting Standalone interface"):
            try:
                sa_vtep.configure('default interface {intf}'.format(intf=sa_vtep_if))
            except Exception as error:
                log.debug("Unable to configure - Encountered Exception " + str(error))
                self.errored('Exception occured during default interface configuration', 
                             goto=['common_cleanup'])
        
        with steps.start("Defaulting Primary interface port-channel 11"):
            try:
                prim_vtep.configure('default interface port-channel 11')
            except Exception as error:
                log.debug("Unable to configure - Encountered Exception " + str(error))
                self.errored('Exception occured during default interface configuration', 
                             goto=['common_cleanup'])

        with steps.start("Defaulting Secondary interface port-channel 11"):
            try:
                sec_vtep.configure('default interface port-channel 11')
            except Exception as error:
                log.debug("Unable to configure - Encountered Exception " + str(error))
                self.errored('Exception occured during default interface configuration', 
                             goto=['common_cleanup'])

        with steps.start("Defaulting Primary To FANOUT interface"):
            try:
                prim_vtep.configure('default interface {intf}'.format(intf=leaf1_to_fan_if))
            except Exception as error:
                log.debug("Unable to configure - Encountered Exception " + str(error))
                self.errored('Exception occured during default interface configuration', 
                             goto=['common_cleanup'])

        with steps.start("Defaulting Secondary To FANOUT interface"):
            try:
                sec_vtep.configure('default interface {intf}'.format(intf=leaf2_to_fan_if))
            except Exception as error:
                log.debug("Unable to configure - Encountered Exception " + str(error))
                self.errored('Exception occured during default interface configuration', 
                             goto=['common_cleanup'])
        
        with steps.start("Defaulting FANOUT interface port-channel 200"):
            try:
                fan_3172.configure('default interface port-channel 200')
            except Exception as error:
                log.debug("Unable to configure - Encountered Exception " + str(error))
                self.errored('Exception occured during default interface configuration', 
                             goto=['common_cleanup'])
        
        with steps.start("Defaulting FANOUT To Primary interface"):
            try:
                fan_3172.configure('default interface {intf}'.format(intf=fan_to_leaf1))
            except Exception as error:
                log.debug("Unable to configure - Encountered Exception " + str(error))
                self.errored('Exception occured during default interface configuration', 
                             goto=['common_cleanup'])
        
        with steps.start("Defaulting FANOUT To Secondary interface"):
            try:
                fan_3172.configure('default interface {intf}'.format(intf=fan_to_leaf2))
            except Exception as error:
                log.debug("Unable to configure - Encountered Exception " + str(error))
                self.errored('Exception occured during default interface configuration', 
                             goto=['common_cleanup'])
        
        with steps.start("Defaulting FANOUT To IXIA interface"):
            try:
                fan_3172.configure('default interface {intf}'.format(intf=fan_to_ixia))
            except Exception as error:
                log.debug("Unable to configure - Encountered Exception " + str(error))
                self.errored('Exception occured during default interface configuration', 
                             goto=['common_cleanup'])
        
        with steps.start("Defaulting Leaf-1 FEX interface"):
            try:
                prim_vtep.configure('default interface {intf}'.format(intf=fex_vtep_if))
            except Exception as error:
                log.debug("Unable to configure - Encountered Exception " + str(error))
                self.errored('Exception occured during default interface configuration', 
                             goto=['common_cleanup'])
        
        with steps.start("Configure Port-Security on Primary Orphan1"):
            try:
                prim_vtep.configure('''interface {intf}
                                switchport
                                switchport mode access
                                switchport access vlan {vlan}
                                spanning-tree port type edge
                                switchport port-security maximum 1025
                                switchport port-security
                                no shutdown
                            '''.format(intf=prim_vtep_if, vlan=vlan1))
            except Exception as error:
                log.debug("Unable to configure - Encountered Exception " + str(error))
                self.errored('Exception occurred while configuring port security', 
                             goto=['common_cleanup'])
        
        with steps.start("Configure Port-Security on Primary Orphan2"):
            try:
                prim_vtep.configure('''interface {intf}
                                switchport
                                switchport mode accesss
                                switchport access vlan {vlan}
                                spanning-tree port type edge
                                switchport port-security maximum 1025
                                switchport port-security
                                no shutdown
                            '''.format(intf=prim_vtep_if1, vlan=vlan1))
            except Exception as error:
                log.debug("Unable to configure - Encountered Exception " + str(error))
                self.errored('Exception occurred while configuring port security', 
                             goto=['common_cleanup'])

        with steps.start("Configure Port-Security on Secondary Orphan"):
            try:
                prim_vtep.configure('''interface {intf}
                                switchport
                                switchport mode access
                                switchport access vlan {vlan}
                                spanning-tree port type edge
                                switchport port-security maximum 1025
                                switchport port-security
                                no shutdown
                            '''.format(intf=sec_vtep_if, vlan=vlan1))
            except Exception as error:
                log.debug("Unable to configure - Encountered Exception " + str(error))
                self.errored('Exception occurred while configuring port security', 
                             goto=['common_cleanup'])
         
        with steps.start("Configure Port-Security on Standalone interface"):
            try:
                sa_vtep.configure('''interface {intf}
                                switchport
                                switchport mode access
                                switchport access vlan {vlan}
                                spanning-tree port type edge
                                switchport port-security maximum 1025
                                switchport port-security
                                no shutdown
                            '''.format(intf=sa_vtep_if, vlan=vlan3))

            except Exception as error:
                log.debug("Unable to configure - Encountered Exception " + str(error))
                self.errored('Exception occurred while configuring port security', 
                             goto=['common_cleanup'])

        with steps.start("Configure Port-Security on Primary port-channel 11"):
            try:
                prim_vtep.configure('''interface port-channel 11
                                switchport
                                switchport mode access
                                switchport access vlan {vlan}
                                spanning-tree port type edge
                                switchport port-security maximum 1025
                                switchport port-security
                                vpc 11
                                no shutdown
                            '''.format(vlan=vlan1))
            except Exception as error:
                log.debug("Unable to configure - Encountered Exception " + str(error))
                self.errored('Exception occurred while configuring port security', 
                             goto=['common_cleanup'])
        
        with steps.start("Configure Port-Security on Secondary port-channel 11"):
            try:
                sec_vtep.configure('''interface port-channel 11
                                switchport
                                switchport mode access
                                switchport access vlan {vlan}
                                spanning-tree port type edge
                                switchport port-security maximum 1025
                                switchport port-security
                                vpc 11
                                no shutdown
                            '''.format(vlan=vlan1))
            except Exception as error:
                log.debug("Unable to configure - Encountered Exception " + str(error))
                self.errored('Exception occurred while configuring port security', 
                             goto=['common_cleanup']) 

        with steps.start("Configure Primary to FANOUT interface"):
            try:
                prim_vtep.configure('''interface {intf}
                                switchport
                                switchport mode access
                                switchport access vlan {vlan}
                                spanning-tree port type edge
                                channel-group 11
                                no shutdown
                            '''.format(vlan=vlan1, intf=leaf1_to_fan_if))
            except Exception as error:
                log.debug("Unable to configure - Encountered Exception " + str(error))
                self.errored('Exception occurred while configuring port security', 
                             goto=['common_cleanup']) 
        
        with steps.start("Configure Secondary to FANOUT interface"):
            try:
                sec_vtep.configure('''interface {intf}
                                switchport
                                switchport mode access
                                switchport access vlan {vlan}
                                spanning-tree port type edge
                                channel-group 11
                                no shutdown
                            '''.format(vlan=vlan1, intf=leaf2_to_fan_if))
            except Exception as error:
                log.debug("Unable to configure - Encountered Exception " + str(error))
                self.errored('Exception occurred while configuring port security', 
                             goto=['common_cleanup'])
        
        with steps.start("Configure port-channel 200 on FANOUT"):
            try:
                fan_3172.configure('''interface port-channel 200
                                switchport
                                switchport mode access
                                switchport access vlan {vlan}
                                spanning-tree port type edge
                                no shutdown
                            '''.format(vlan=vlan1), timeout=60)
            except Exception as error:
                log.debug("Unable to configure - Encountered Exception " + str(error))
                self.errored('Exception occurred while configuring port security', 
                             goto=['common_cleanup']) 
        
        with steps.start("Configure FANOUT to Primary interface"):
            try:
                fan_3172.configure('''interface {intf}
                                switchport
                                switchport mode access
                                switchport access vlan {vlan}
                                spanning-tree port type edge
                                channel-group 200
                                no shutdown
                            '''.format(vlan=vlan1, intf=fan_to_leaf1), timeout=60)
            except Exception as error:
                log.debug("Unable to configure - Encountered Exception " + str(error))
                self.errored('Exception occurred while configuring port security', 
                             goto=['common_cleanup']) 
        
        with steps.start("Configure FANOUT to Secondary interface"):
            try:
                fan_3172.configure('''interface {intf}
                                switchport
                                switchport mode access
                                switchport access vlan {vlan}
                                spanning-tree port type edge
                                channel-group 200
                                no shutdown
                            '''.format(vlan=vlan1, intf=fan_to_leaf2), timeout=60)
            except Exception as error:
                log.debug("Unable to configure - Encountered Exception " + str(error))
                self.errored('Exception occurred while configuring port security', 
                             goto=['common_cleanup'])
        
        with steps.start("Configure FANOUT to IXIA interface"):
            try:
                fan_3172.configure('''interface {intf}
                                switchport
                                switchport mode access
                                switchport access vlan {vlan}
                                spanning-tree port type edge
                                no shutdown
                            '''.format(vlan=vlan1, intf=fan_to_ixia), timeout=60)
            except Exception as error:
                log.debug("Unable to configure - Encountered Exception " + str(error))
                self.errored('Exception occurred while configuring port security', 
                             goto=['common_cleanup'])
        
        with steps.start("Configure Leaf1 FEX interface"):
            try:
                prim_vtep.configure('''interface {intf}
                                switchport
                                switchport mode access
                                switchport access vlan {vlan}
                                spanning-tree port type edge
                                switchport port-security maximum 1025
                                switchport port-security
                                no shut
                            '''.format(vlan=vlan1, intf=fex_vtep_if))
            except Exception as error:
                log.debug("Unable to configure - Encountered Exception " + str(error))
                self.errored('Exception occurred while configuring port security', 
                             goto=['common_cleanup'])
        
        log.info("Waiting for interface to come up")
        time.sleep(30)
    
        prim_vtep.execute('show version')
        sec_vtep.execute('show version')
        sa_vtep.execute('show version')
        
        prim_vtep.execute('show run interface {intf}'.format(intf=prim_vtep_if))
        prim_vtep.execute('show run interface {intf}'.format(intf=prim_vtep_if1))
        prim_vtep.execute('show run interface port-channel 11')
        sec_vtep.execute('show run interface port-channel 11')
        sec_vtep.execute('show run interface {intf}'.format(intf=sec_vtep_if))
        sa_vtep.execute('show run interface {intf}'.format(intf=sa_vtep_if))
    
    # =============================================================================================================================#
    # @aetest.test
    def perform_copy_r_s(self, testscript):
        """ ENABLE_L2_TRM_CONFIGURATION test subsection: Save all configurations (copy r s) """

        log.info(banner("Performing Copy R S"))

        testscript.parameters['LEAF-1'].configure("copy r s", timeout=300)
        testscript.parameters['LEAF-2'].configure("copy r s", timeout=300)
        testscript.parameters['LEAF-3'].configure("copy r s", timeout=300)

        time.sleep(300)

    #*****************************************************************************************************************************#
class VERIFY_NETWORK(aetest.Testcase):
    """This is description for my testcase one"""

    # =============================================================================================================================#
    @aetest.test
    def verify_vpc(self, testscript):
        """ VERIFY_NETWORK subsection: Verify VPC """
        LEAF_1 = testscript.parameters['LEAF-1']
        LEAF_2 = testscript.parameters['LEAF-2']

        log.info('Waiting 300secs for interfaces to comeup')
        time.sleep(300)
        VPCStatus = infraVerify.verifyVPCStatus(LEAF_1, LEAF_2)

        if VPCStatus['result']:
            log.info(VPCStatus['log'])
            log.info("PASS : VPC Status for '" + str(LEAF_1) + "' and '" + str(LEAF_2) + "' is Successfully Verified\n\n")
        else:
            log.info(VPCStatus['log'])
            log.info("FAIL : VPC Status for '" + str(LEAF_1) + "' and '" + str(LEAF_2) + "' is Failed\n\n")
            self.failed()

    # =============================================================================================================================#
    @aetest.test
    def verify_bgp_neighborship(self, testscript):
        """ VERIFY_NETWORK subsection: Verify SPINE BGP Neighborship """
        time.sleep(30)
        bgpSessionData = verifyEvpnUpLinkBGPSessions(testscript.parameters['forwardingSysDict'],testscript.parameters['leavesDict'])

        if bgpSessionData['result'] is 1:
            log.info("PASS : Successfully verified SPINE BGP Neighborship with Leaf's\n\n")
            self.passed(reason=bgpSessionData['log'])
        else:
            log.info("FAIL : Failed to verify SPINE BGP Neighborship with LEAF's\n\n")
            self.failed(reason=bgpSessionData['log'])

    # =============================================================================================================================#
    @aetest.test
    def verify_NVE_peering(self, testscript):
        """ VERIFY_NETWORK subsection: Verify NVE Peering """

        nvePeerData = verifyEVPNNvePeers(testscript.parameters['leavesDict'])

        if nvePeerData['result'] is 1:
            log.info("PASS : Successfully verified NVE Peering\n\n")
            self.passed(reason=nvePeerData['log'])
        else:
            log.info("FAIL : Failed to verify NVE Peering\n\n")
            self.failed(reason=nvePeerData['log'])

    # =============================================================================================================================#
    @aetest.test
    def verify_VNI(self, testscript):
        """ VERIFY_NETWORK subsection: Verify NVE Peering """

        nveVniData = verifyEVPNVNIData(testscript.parameters['forwardingSysDict'],testscript.parameters['leavesDict'])

        if nveVniData['result'] is 1:
            log.info("PASS : Successfully verified NVE VNI Data\n\n")
            self.passed(reason=nveVniData['log'])
        else:
            log.info("FAIL : Failed to verify NVE VNI Data\n\n")
            self.failed(reason=nveVniData['log'])

# *****************************************************************************************************************************#

###################################################################
###                  Traffic Generator Configurations           ###
###################################################################
class ConfigureIxia(aetest.Testcase):
    """ Configuring IXIA """

    @aetest.test
    def InitializeIxia(self, testscript, testbed, steps):
        """ Initializing IXIA Testbed """

        with steps.start("Get the IXIA details from testbed YAML file"):

            if "ixia" in testbed.devices:
                testscript.parameters['traffic_threshold'] = 2
                ixia_chassis_ip = testbed.devices['ixia'].connections.tgn.ixia_chassis_ip
                ixia_tcl_server = testbed.devices['ixia'].connections.tgn.ixnetwork_api_server_ip
                ixia_port_list  = testbed.devices['ixia'].connections.tgn.ixia_port_list
            
            else:
                log.info("IXIA details not provided in testbed file")

        with steps.start("Connect to IXIA Chassis"):
            # Forcefully take port ownership if the portList are owned by other users.
            forceTakePortOwnership = True

            testscript.parameters['session'] = session = SessionAssistant(
                                                        IpAddress=ixia_tcl_server, 
                                                        UserName='admin', 
                                                        Password='admin', 
                                                        ClearConfig=True, 
                                                        LogLevel='all', 
                                                        LogFilename='restpy.log')
            
            testscript.parameters['ixNetwork'] = ixNetwork = testscript.parameters['session'].Ixnetwork

            ixia_int_list   = []
            for intPort in ixia_port_list:
                intPort_split = intPort.split('/')
                ixia_int_list.append([ixia_chassis_ip, intPort_split[0], intPort_split[1]])
            # Assign ports. Map physical ports to the configured vports.
            portMap = testscript.parameters['session'].PortMapAssistant()
            
            for index,port in enumerate(ixia_int_list):
                # For the port name, get the loaded configuration's port name
                print(index,port)
                portName = "Port_{}".format(ixia_port_list[index])
                portMap.Map(IpAddress=port[0], CardId=port[1], PortId=port[2], Name=portName)
            
            portMap.Connect(forceTakePortOwnership)

            if session:
                log.info("Connection Establishment to chassis is successful")
            else:
                log.error("Failed to connect to the chassis")
    
    @aetest.test
    def CreateTopology(self, testscript, steps):
        
        ixNetwork       = testscript.parameters['ixNetwork']
        orphan1_port    = ixNetwork.Vport.find()[0]
        sa_port         = ixNetwork.Vport.find()[1]
        orphan2_port    = ixNetwork.Vport.find()[2]
        fex_port        = ixNetwork.Vport.find()[3]
        vpc_port        = ixNetwork.Vport.find()[4]
        sec_port        = ixNetwork.Vport.find()[5]
        
        with steps.start("Creating Topologies"):
            testscript.parameters['orphan1_handle'] = ixNetwork.Topology.add(Name='ORPHAN1-Topo', Ports=orphan1_port)
            if not testscript.parameters['orphan1_handle']:
                log.error('Failed to create topology for Orphan2 port')
            
            testscript.parameters['sa_handle'] = ixNetwork.Topology.add(Name='SA-Topo', Ports=sa_port)
            if not testscript.parameters['sa_handle']:
                log.error('Failed to create topology for Standalone port')
            
            testscript.parameters['orphan2_handle'] = ixNetwork.Topology.add(Name='ORPHAN2-Topo', Ports=orphan2_port)
            if not testscript.parameters['orphan2_handle']:
                log.error('Failed to create topology for Orphan2 port')
            
            testscript.parameters['fex_handle'] = ixNetwork.Topology.add(Name='FEX-Topo', Ports=fex_port)
            if not testscript.parameters['fex_handle']:
                log.error('Failed to create topology for FEX port')
            
            testscript.parameters['vpc_handle'] = ixNetwork.Topology.add(Name='VPC-Topo', Ports=vpc_port)
            if not testscript.parameters['vpc_handle']:
                log.error('Failed to create topology for VPC port')

            testscript.parameters['sec_handle'] = ixNetwork.Topology.add(Name='SEC-Topo', Ports=sec_port)
            if not testscript.parameters['sec_handle']:
                log.error('Failed to create topology for Secondary port')

    @aetest.test
    def CreateDeviceGroup(self, testscript):
        ixNetwork   = testscript.parameters['ixNetwork']
        
        p1_handle = testscript.parameters['orphan1_handle']
        p2_handle = testscript.parameters['sa_handle']
        p3_handle = testscript.parameters['orphan2_handle']
        p4_handle = testscript.parameters['fex_handle']
        p5_handle = testscript.parameters['vpc_handle']
        p6_handle = testscript.parameters['sec_handle']
        
        P1_tgen_dict = testscript.parameters['LEAF_1_Orphan1_TGEN_dict']
        P2_tgen_dict = testscript.parameters['LEAF_3_TGEN_dict']
        P3_tgen_dict = testscript.parameters['LEAF_1_Orphan2_TGEN_dict']
        P4_tgen_dict = testscript.parameters['LEAF_1_Fex_TGEN_dict']
        P5_tgen_dict = testscript.parameters['FANOUT_TGEN_dict']
        P6_tgen_dict = testscript.parameters['LEAF_2_TGEN_dict']
        
        log.info("Creating DeviceGroup For Orphan1")
        deviceGroup = p1_handle.DeviceGroup.add(Name='DG1', Multiplier=P1_tgen_dict['no_of_ints'])
        ethernet = deviceGroup.Ethernet.add(Name="Eth1", VlanCount="1")
        ethernet.Mac.Increment(start_value=P1_tgen_dict['mac'], step_value=P1_tgen_dict['mac_step'])
        ethernet.EnableVlans.Single(False)
        vlanObj = ethernet.Vlan.find()[0].VlanId.Increment(
            start_value=P1_tgen_dict['vlan_id'], step_value=P1_tgen_dict['vlan_id_step']
        )
        
        if P1_tgen_dict['protocol'] == 'ipv4':
            log.info("Configuring IPv4")
            ipv4 = ethernet.Ipv4.add(Name="Ipv4")
            ipv4.Address.Increment(start_value=P1_tgen_dict['v4_addr'], step_value=P1_tgen_dict['v4_addr_step'])
            ipv4.GatewayIp.Increment(
                start_value=P1_tgen_dict['v4_gateway'], step_value=P1_tgen_dict['v4_gateway_step']
            )
            ipv4.Prefix.Single('16')

        if P1_tgen_dict['protocol'] == 'ipv6':
            log.info("Configuring IPv6")
            ipv6 = ethernet.Ipv6.add(Name="Ipv6")
            ipv6.Address.Increment(start_value=P1_tgen_dict['v6_addr'], step_value=P1_tgen_dict['v6_addr_step'])
            ipv6.GatewayIp.Increment(
                start_value=P1_tgen_dict['v6_gateway'], step_value=P1_tgen_dict['v6_gateway_step']
            )
            ipv6.Prefix.Single('64')
        
        if not deviceGroup:
            log.error("Ixia DeviceGroup creation failed for Orphan1")

        log.info("Creating DeviceGroup For LEAF3")
        deviceGroup = p2_handle.DeviceGroup.add(Name='DG2', Multiplier=P2_tgen_dict['no_of_ints'])
        ethernet = deviceGroup.Ethernet.add(Name="Eth2", VlanCount="1")
        ethernet.Mac.Increment(start_value=P2_tgen_dict['mac'], step_value=P2_tgen_dict['mac_step'])
        ethernet.EnableVlans.Single(False)
        vlanObj = ethernet.Vlan.find()[0].VlanId.Increment(
            start_value=P2_tgen_dict['vlan_id'], step_value=P2_tgen_dict['vlan_id_step']
        )
        
        if P2_tgen_dict['protocol'] == 'ipv4':
            log.info("Configuring IPv4")
            ipv4 = ethernet.Ipv4.add(Name="Ipv4")
            ipv4.Address.Increment(start_value=P2_tgen_dict['v4_addr'], step_value=P2_tgen_dict['v4_addr_step'])
            ipv4.GatewayIp.Increment(
                start_value=P2_tgen_dict['v4_gateway'], step_value=P2_tgen_dict['v4_gateway_step']
            )
            ipv4.Prefix.Single('16')

        if P2_tgen_dict['protocol'] == 'ipv6':
            log.info("Configuring IPv6")
            ipv6 = ethernet.Ipv6.add(Name="Ipv6")
            ipv6.Address.Increment(start_value=P2_tgen_dict['v6_addr'], step_value=P2_tgen_dict['v6_addr_step'])
            ipv6.GatewayIp.Increment(
                start_value=P2_tgen_dict['v6_gateway'], step_value=P2_tgen_dict['v6_gateway_step']
            )
            ipv6.Prefix.Single('64')
        
        if not deviceGroup:
            log.error("Ixia DeviceGroup creation failed for LEAF3")

        log.info("Creating DeviceGroup For Orphan2")
        deviceGroup = p3_handle.DeviceGroup.add(Name='DG3', Multiplier=P3_tgen_dict['no_of_ints'])
        ethernet = deviceGroup.Ethernet.add(Name="Eth3", VlanCount="1")
        ethernet.Mac.Increment(start_value=P3_tgen_dict['mac'], step_value=P3_tgen_dict['mac_step'])
        ethernet.EnableVlans.Single(False)
        vlanObj = ethernet.Vlan.find()[0].VlanId.Increment(
            start_value=P3_tgen_dict['vlan_id'], step_value=P3_tgen_dict['vlan_id_step']
        )
        
        if P3_tgen_dict['protocol'] == 'ipv4':
            log.info("Configuring IPv4")
            ipv4 = ethernet.Ipv4.add(Name="Ipv4")
            ipv4.Address.Increment(start_value=P3_tgen_dict['v4_addr'], step_value=P3_tgen_dict['v4_addr_step'])
            ipv4.GatewayIp.Increment(
                start_value=P3_tgen_dict['v4_gateway'], step_value=P3_tgen_dict['v4_gateway_step']
            )
            ipv4.Prefix.Single('16')

        if P3_tgen_dict['protocol'] == 'ipv6':
            log.info("Configuring IPv6")
            ipv6 = ethernet.Ipv6.add(Name="Ipv6")
            ipv6.Address.Increment(start_value=P3_tgen_dict['v6_addr'], step_value=P3_tgen_dict['v6_addr_step'])
            ipv6.GatewayIp.Increment(
                start_value=P3_tgen_dict['v6_gateway'], step_value=P3_tgen_dict['v6_gateway_step']
            )
            ipv6.Prefix.Single('64')
        
        if not deviceGroup:
            log.error("Ixia DeviceGroup creation failed for LEAF2")
        
        log.info("Creating DeviceGroup For FEX")
        deviceGroup = p4_handle.DeviceGroup.add(Name='DG4', Multiplier=P4_tgen_dict['no_of_ints'])
        ethernet = deviceGroup.Ethernet.add(Name="Eth4", VlanCount="1")
        ethernet.Mac.Increment(start_value=P4_tgen_dict['mac'], step_value=P4_tgen_dict['mac_step'])
        ethernet.EnableVlans.Single(False)
        vlanObj = ethernet.Vlan.find()[0].VlanId.Increment(
            start_value=P4_tgen_dict['vlan_id'], step_value=P4_tgen_dict['vlan_id_step']
        )
        
        if P4_tgen_dict['protocol'] == 'ipv4':
            log.info("Configuring IPv4")
            ipv4 = ethernet.Ipv4.add(Name="Ipv4")
            ipv4.Address.Increment(start_value=P4_tgen_dict['v4_addr'], step_value=P4_tgen_dict['v4_addr_step'])
            ipv4.GatewayIp.Increment(
                start_value=P4_tgen_dict['v4_gateway'], step_value=P4_tgen_dict['v4_gateway_step']
            )
            ipv4.Prefix.Single('16')

        if P4_tgen_dict['protocol'] == 'ipv6':
            log.info("Configuring IPv6")
            ipv6 = ethernet.Ipv6.add(Name="Ipv6")
            ipv6.Address.Increment(start_value=P4_tgen_dict['v6_addr'], step_value=P4_tgen_dict['v6_addr_step'])
            ipv6.GatewayIp.Increment(
                start_value=P4_tgen_dict['v6_gateway'], step_value=P4_tgen_dict['v6_gateway_step']
            )
            ipv6.Prefix.Single('64')
        
        if not deviceGroup:
            log.error("Ixia DeviceGroup creation failed for FEX")
            
        log.info("Creating DeviceGroup For VPC")
        deviceGroup = p5_handle.DeviceGroup.add(Name='DG5', Multiplier=P5_tgen_dict['no_of_ints'])
        ethernet = deviceGroup.Ethernet.add(Name="Eth5", VlanCount="1")
        ethernet.Mac.Increment(start_value=P5_tgen_dict['mac'], step_value=P5_tgen_dict['mac_step'])
        ethernet.EnableVlans.Single(False)
        vlanObj = ethernet.Vlan.find()[0].VlanId.Increment(
            start_value=P5_tgen_dict['vlan_id'], step_value=P5_tgen_dict['vlan_id_step']
        )
        
        if P5_tgen_dict['protocol'] == 'ipv4':
            log.info("Configuring IPv4")
            ipv4 = ethernet.Ipv4.add(Name="Ipv4")
            ipv4.Address.Increment(start_value=P5_tgen_dict['v4_addr'], step_value=P5_tgen_dict['v4_addr_step'])
            ipv4.GatewayIp.Increment(
                start_value=P5_tgen_dict['v4_gateway'], step_value=P5_tgen_dict['v4_gateway_step']
            )
            ipv4.Prefix.Single('16')

        if P5_tgen_dict['protocol'] == 'ipv6':
            log.info("Configuring IPv6")
            ipv6 = ethernet.Ipv6.add(Name="Ipv6")
            ipv6.Address.Increment(start_value=P5_tgen_dict['v6_addr'], step_value=P5_tgen_dict['v6_addr_step'])
            ipv6.GatewayIp.Increment(
                start_value=P5_tgen_dict['v6_gateway'], step_value=P5_tgen_dict['v6_gateway_step']
            )
            ipv6.Prefix.Single('64')
        
        if not deviceGroup:
            log.error("Ixia DeviceGroup creation failed for VPC")

        log.info("Creating DeviceGroup For Secondary Orphan")
        deviceGroup = p6_handle.DeviceGroup.add(Name='DG6', Multiplier=P6_tgen_dict['no_of_ints'])
        ethernet = deviceGroup.Ethernet.add(Name="Eth6", VlanCount="1")
        ethernet.Mac.Increment(start_value=P6_tgen_dict['mac'], step_value=P6_tgen_dict['mac_step'])
        ethernet.EnableVlans.Single(False)
        vlanObj = ethernet.Vlan.find()[0].VlanId.Increment(
            start_value=P6_tgen_dict['vlan_id'], step_value=P6_tgen_dict['vlan_id_step']
        )
        
        if P6_tgen_dict['protocol'] == 'ipv4':
            log.info("Configuring IPv4")
            ipv4 = ethernet.Ipv4.add(Name="Ipv4")
            ipv4.Address.Increment(start_value=P6_tgen_dict['v4_addr'], step_value=P6_tgen_dict['v4_addr_step'])
            ipv4.GatewayIp.Increment(
                start_value=P6_tgen_dict['v4_gateway'], step_value=P6_tgen_dict['v4_gateway_step']
            )
            ipv4.Prefix.Single('16')

        if P6_tgen_dict['protocol'] == 'ipv6':
            log.info("Configuring IPv6")
            ipv6 = ethernet.Ipv6.add(Name="Ipv6")
            ipv6.Address.Increment(start_value=P6_tgen_dict['v6_addr'], step_value=P6_tgen_dict['v6_addr_step'])
            ipv6.GatewayIp.Increment(
                start_value=P6_tgen_dict['v6_gateway'], step_value=P6_tgen_dict['v6_gateway_step']
            )
            ipv6.Prefix.Single('64')
        
        if not deviceGroup:
            log.error("Ixia DeviceGroup creation failed for LEAF2")

    @aetest.test
    def CreateTrafficItems(self, testscript, testbed, steps):
        ixNetwork   = testscript.parameters['ixNetwork']
        p1_handle = testscript.parameters['orphan1_handle']
        p2_handle = testscript.parameters['sa_handle']
        p3_handle = testscript.parameters['orphan2_handle']
        p4_handle = testscript.parameters['fex_handle']
        p5_handle = testscript.parameters['vpc_handle']
        p6_handle = testscript.parameters['sec_handle']
        
        prim_vtep = testscript.parameters['LEAF-1']
        sec_vtep = testscript.parameters['LEAF-2']
        sa_vtep = testscript.parameters['LEAF-3']
        prim_vtep_if = str(testscript.parameters['intf_LEAF_1_1_to_IXIA'])
        prim_vtep_if1 = str(testscript.parameters['intf_LEAF_1_2_to_IXIA'])
  
        p1_handle.Start()
        p2_handle.Start()
        p4_handle.Start()
        p5_handle.Start()
        
        log.info('Waiting for 30 secs')      
        time.sleep(30)
        
        # Traffic Item for Orphan to Standalone
        trafficItem1 = ixNetwork.Traffic.TrafficItem.add(
            Name='Access Orphan To Standalone',
            BiDirectional=True,
            TrafficType='ipv6',
        )

        trafficItem1.EndpointSet.add(Sources=p1_handle, Destinations=p2_handle)
        configElement = trafficItem1.ConfigElement.find()[0]
        configElement.FrameRate.update(Type='framesPerSecond', Rate=1000.00)
        configElement.TransmissionControl.update(Type='continuous')
        configElement.FrameSize.FixedSize = 800

        trafficItem1.Tracking.find()[0].TrackBy = ["ethernetIiSourceaddress0"]
        trafficItem1.Generate()
                
        # Traffic Item for VPC to Standalone
        trafficItem2 = ixNetwork.Traffic.TrafficItem.add(
            Name='Access VPC To Standalone',
            BiDirectional=True,
            TrafficType='ipv6',
        )
        trafficItem2.EndpointSet.add(Sources=p5_handle, Destinations=p2_handle)
        configElement = trafficItem2.ConfigElement.find()[0]
        configElement.FrameRate.update(Type='framesPerSecond', Rate=1000.00)
        configElement.FrameSize.FixedSize = 800

        trafficItem2.Tracking.find()[0].TrackBy = ['ethernetIiSourceaddress0']
        trafficItem2.Generate()
        
        # Traffic Item for FEX to Standalone
        trafficItem3 = ixNetwork.Traffic.TrafficItem.add(
            Name='Access FEX To Standalone',
            BiDirectional=True,
            TrafficType='ipv6',
        )
        trafficItem3.EndpointSet.add(Sources=p4_handle, Destinations=p2_handle)
        configElement = trafficItem3.ConfigElement.find()[0]
        configElement.FrameRate.update(Type='framesPerSecond', Rate=1000.00)
        configElement.FrameSize.FixedSize = 800

        trafficItem3.Tracking.find()[0].TrackBy = ['ethernetIiSourceaddress0']

        trafficItem3.Generate()
        ixNetwork.Traffic.Apply()
        
        ixNetwork.StopAllProtocols(Arg1="sync")

        log.info("Shut / no shut Orphan1 to clear macs")
        prim_vtep.configure('''interface {intf}
                        shutdown ; sleep 30 ; no shutdown
                    '''.format(intf=prim_vtep_if), timeout=60)
        
        log.info("Shut / no shut PO11 on primary to clear macs")
        prim_vtep.configure('''interface port-channel 11
                        shutdown ; sleep 30 ; no shutdown''', timeout=60)
        
        log.info("Shut / no shut PO11 on secondary to clear macs")
        sec_vtep.configure('''interface port-channel 11
                        shutdown ; sleep 30 ; no shutdown''', timeout=60)
        
        log.info('Waiting for 30 secs to clear macs')
        time.sleep(30)
        
        p3_handle.Start()
        p2_handle.Start()
        
        log.info('Waiting for 30 secs to clear macs')
        time.sleep(30)
        
        # Traffic Item for Orphan2 to Standalone
        trafficItem4 = ixNetwork.Traffic.TrafficItem.add(
            Name='Access Orphan2 To Standalone',
            BiDirectional=True,
            TrafficType='ipv6',
        )

        trafficItem4.EndpointSet.add(Sources=p3_handle, Destinations=p2_handle)
        configElement = trafficItem4.ConfigElement.find()[0]
        configElement.FrameRate.update(Type='framesPerSecond', Rate=1000.00)
        configElement.TransmissionControl.update(Type='continuous')
        configElement.FrameSize.FixedSize = 800

        trafficItem4.Tracking.find()[0].TrackBy = ["ethernetIiSourceaddress0"]
        trafficItem4.Generate()
        
        ixNetwork.Traffic.Apply()
        ixNetwork.StopAllProtocols(Arg1="sync")

        log.info("Shut / no shut Orphan2 to clear macs")
        prim_vtep.configure('''interface {intf}
                        shutdown ; sleep 30 ; no shutdown
                    '''.format(intf=prim_vtep_if1), timeout=60)
        
        log.info('Waiting for 30 secs to clear macs')
        time.sleep(30)

        prim_vtep.execute("clear logging logfile")
        sec_vtep.execute("clear logging logfile")
        sa_vtep.execute("clear logging logfile")

########################################################################################################
# TC: VXLAN_PS_000 - Trunk - Mapping case - TC47 -ISSU
# Verify LXC ND-ISSU NR3F .bin to .upg with port-security
# VPC port-channel and orphan, Standalone, Standalone + FEX ST
########################################################################################################
class TC_VXLAN_PS_000_Access(aetest.Testcase):
    @aetest.test
    def test_setup(self, testscript, testbed, steps):
        sa_vtep = testscript.parameters['LEAF-3']
        prim_vtep = testscript.parameters['LEAF-1']
        sec_vtep = testscript.parameters['LEAF-2']
        leaf1_mac = str(testscript.parameters['PORTSEC_Dict']['vpc_static_mac'])
        leaf2_mac = str(testscript.parameters['PORTSEC_Dict']['vpc_static_mac1'])
        prim_vtep_if = str(testscript.parameters['intf_LEAF_1_1_to_IXIA'])
        sa_vtep_if = str(testscript.parameters['intf_LEAF_3_to_IXIA'])
        fex_vtep_if = str(testscript.parameters['intf_LEAF_1_FEX_to_IXIA'])
        src_vlan = int(testscript.parameters['LEAF_1_Orphan1_TGEN_dict']['vlan_id'])
        
        new_config = '''switchport port-security aging type inactivity
                        switchport port-security mac-address sticky
                        switchport port-security violation restrict'''
        with steps.start("Configure Port-Security on Primary VTEP Orphan"):
            if not config_interface_ps([prim_vtep], prim_vtep_if, log, new_config):
                self.errored('Exception occurred while configuring port security', goto=['common_cleanup'])
        
        with steps.start("Configure Port-Security on Standalone VTEP"):
            if not config_interface_ps([sa_vtep], sa_vtep_if, log, new_config):
                self.errored('Exception occurred while configuring port security', goto=['common_cleanup'])
        
        new_config = '''switchport port-security aging type inactivity
                        switchport port-security violation restrict'''
        with steps.start("Configure Port-Security on Leaf-1 FEX - FEX port of VTEP"):
            if not config_interface_ps([prim_vtep], fex_vtep_if, log, new_config):
                self.errored('Exception occurred while configuring port security', goto=['common_cleanup'])

        new_config = '''switchport port-security aging type inactivity
                        switchport port-security violation restrict
                        switchport port-security mac-address {mac}'''.format(mac=leaf1_mac)
        with steps.start("Configure Port-Security on VPC Primary/Secondary - Static"):
            if not config_interface_ps([prim_vtep, sec_vtep], 'port-channel 11', log, new_config):
                self.errored('Exception occurred while configuring port security', goto=['common_cleanup'])
        
        log.info("Waiting {}secs for interface to come up".format(config_time))
        time.sleep(config_time)
        display_configs(testscript)

    # Flap Uplink on VPC primary and standalone
    @aetest.test
    def verify_nd_issu_standalone(self, testscript, testbed, steps):
        sa_vtep         = testscript.parameters['LEAF-3']
        prim_vtep       = testscript.parameters['LEAF-1']
        sec_vtep        = testscript.parameters['LEAF-2']
        sa_vtep_if      = str(testscript.parameters['intf_LEAF_3_to_IXIA'])
        prim_vtep_if    = str(testscript.parameters['intf_LEAF_1_1_to_IXIA'])
        sa_mac          = str(testscript.parameters['PORTSEC_Dict']['sa_mac'])
        prim_mac        = str(testscript.parameters['PORTSEC_Dict']['prim_orphan_mac'])
        ixNetwork       = testscript.parameters['ixNetwork']
        p1_handle       = testscript.parameters['orphan1_handle']
        p2_handle       = testscript.parameters['sa_handle']
        issu_image      = testscript.parameters['abs_target_image']
        
        with steps.start("Starting hosts..."):
            p1_handle.Start()
            p2_handle.Start()
        
        log.info('Waiting {}secs to start 1025 hosts'.format(host_start_time))
        time.sleep(host_start_time)
        
        stream1 = ixNetwork.Traffic.TrafficItem.find(Name='Access Orphan To Standalone')
        stream1.StartStatelessTraffic()
        log.info('Waiting {}secs to start the traffic'.format(traffic_start_time))
        time.sleep(traffic_start_time)
        
        with steps.start('Doing ISSU and verifying cores/errors after ISSU'):    
            # Establish dialogs for running ISSU command
            dialog = Dialog([
                Statement(pattern=r'Do you want to continue with the installation \(y/n\)\?',
                        action='sendline(y)',
                        loop_continue=True,
                        continue_timer=True),
            ])
            
            # Create ISSU command
            issu_cmd = 'install all nxos bootflash:' + str(issu_image) + ' non-disruptive'
            
            # Perform ISSU
            result, output = sa_vtep.reload(reload_command=issu_cmd, prompt_recovery=True, dialog=dialog, timeout=2000, return_output=True)
            output_split = list(filter(None, output.split('\n')))
            fail_flag = []
            fail_logs = '\n'
        
            # Process logs for any failure reasons
            for log_line in output_split:
                if re.search('CRASHED|CPU Hog|malloc|core dump|mts_send|redzone', log_line, re.I):
                    if 'Upgrade can no longer be aborted' in log_line:
                        continue
                    else:
                        fail_flag.append(0)
                        fail_logs += str(log_line) + '\n'
            
            # Reporting
            if 0 in fail_flag:
                self.failed(reason=fail_logs)
            else:
                self.passed(reason="Upgrade successful")
                    
            log.info("Waiting for 60 sec for the topology to come UP")
            time.sleep(60)

        with steps.start("checking NVE peers are up"):
            # Verify NVE Peers with new IP
            nvePeerData = verifyEVPNNvePeers(testscript.parameters['leavesDict'])

            if nvePeerData['result'] is 1:
                log.info("PASS : Successfully verified NVE Peering\n\n")
            else:
                log.error("FAIL : Failed to verify NVE Peering\n\n")
                self.failed(reason=nvePeerData['log'])
        
        with steps.start("checking CPDT time with ND ISSU"):
            ret = time_taken_for_issu(device = prim_vtep)
            if int(ret) > issu_time_limit or int(ret) == 0:
                log.error('ISSU Time taken is more than allowed time %r', issu_time_limit)
                self.failed('ISSU Time taken is more than allowed time %r', issu_time_limit)
        
        with steps.start("Checking mac relearning on standalone and remote after ISSU"):
            if not verify_port_sec_addr_count(sa_vtep, sa_vtep_if, 1025, 'STICKY'):
                log.error("DYNAMIC Mac learning failed")
                self.failed("DYNAMIC Mac learning failed")

            if not verify_secure_mac_on_vteps(sa_vtep, '1002', 1025, sa_mac, 'secure'):
                log.error("Mac learning failed on Standalone")
                self.failed("Mac learning failed on Standalone")

            if not verify_secure_mac_on_vteps(prim_vtep, '1002', 1025, sa_mac):
                log.error("DYNAMIC Mac learning failed on remote vtep(leaf1)")
                self.failed("DYNAMIC Mac learning failed on remote vtep(leaf1)")

            if not verify_secure_mac_on_vteps(sec_vtep, '1002', 1025, sa_mac):
                log.error("DYNAMIC Mac learning failed on remote vtep(leaf2)")
                self.failed("DYNAMIC Mac learning failed on remote vtep(leaf2)")

        with steps.start("Checking Mac relearning on vpc vteps and remote vtep after no shut"):
            if not verify_port_sec_addr_count(prim_vtep, prim_vtep_if, 1025, 'STICKY'):
                log.error("DYNAMIC Mac learning failed")
                self.failed("DYNAMIC Mac learning failed")

            if not verify_secure_mac_on_vteps(prim_vtep, '1001', 1025, prim_mac, 'secure'):
                log.error("Mac learning failed on primary")
                self.failed("Mac learning failed on primary")

            if not verify_secure_mac_on_vteps(sec_vtep, '1001', 1025, prim_mac, 'secure'):
                log.error("DYNAMIC Mac learning failed on remote vtep(leaf2)")
                self.failed("DYNAMIC Mac learning failed on remote vtep(leaf2)")

            if not verify_secure_mac_on_vteps(sa_vtep, '1001', 1025, prim_mac):
                log.error("Mac learning failed on standalone")
                self.failed("Mac learning failed on standalone")

        stream1.StopStatelessTraffic()
        log.info('Waiting {}secs to stop the traffic'.format(traffic_stop_time))
        time.sleep(traffic_stop_time)
        
        with steps.start("Verify Steady State after ISSU"):
            if VerifyTraffic("Test_SA_Access_ISSU", testscript, traffic_item='Access Orphan To Standalone'):
                log.info('Verify traffic success after ISSU')
            else:
                self.failed('Verify traffic failed after ISSU')

        with steps.start('Verify Learned mac address consistency between hardware and software'):
            if verify_mac_cc_between_hardware_software([prim_vtep, sec_vtep, sa_vtep]):
                self.passed('MAC CC success')
            else:
                self.failed('MAC CC failed')

    @aetest.test
    def verify_nd_issu_primary(self, testscript, testbed, steps):
        sa_vtep         = testscript.parameters['LEAF-3']
        prim_vtep       = testscript.parameters['LEAF-1']
        sec_vtep        = testscript.parameters['LEAF-2']
        prim_vpc_mac    = str(testscript.parameters['PORTSEC_Dict']['prim_vpc_mac'])
        ixNetwork       = testscript.parameters['ixNetwork']
        p1_handle       = testscript.parameters['vpc_handle']
        p2_handle       = testscript.parameters['sa_handle']
        issu_image      = testscript.parameters['abs_target_image']
        
        with steps.start("Starting hosts.."):
            p1_handle.Start()
            p2_handle.Start()
        
        log.info('Waiting {}secs to start 1025 hosts'.format(host_start_time))
        time.sleep(host_start_time)
    
        stream1 = ixNetwork.Traffic.TrafficItem.find(Name='Access VPC To Standalone')
        stream1.StartStatelessTraffic()
        log.info('Waiting {}secs to start the traffic'.format(traffic_start_time))
        time.sleep(traffic_start_time)
        
        with steps.start("Checking mac re-learning on local and remote vtep"):
            if not verify_port_sec_addr_count(prim_vtep, 'port-channel 11', 1, 'STATIC'):
                log.error("STATIC Mac learning failed")
                self.failed("STATIC Mac learning failed")
        
            if not verify_port_sec_addr_count(prim_vtep, 'port-channel 11', 1024, 'DYNAMIC'):
                log.error("DYNAMIC Mac learning failed")
                self.failed("DYNAMIC Mac learning failed")

            if not verify_port_sec_addr_count(sec_vtep, 'port-channel 11', 1, 'STATIC'):
                log.error("STATIC Mac learning failed")
                self.failed("STATIC Mac learning failed")
        
            if not verify_port_sec_addr_count(sec_vtep, 'port-channel 11', 1024, 'DYNAMIC'):
                log.error("DYNAMIC Mac learning failed")
                self.failed("DYNAMIC Mac learning failed")
            
            if not verify_secure_mac_on_vteps(prim_vtep, '1001', 1025, prim_vpc_mac, 'secure'):
                log.error("Mac learning failed on primary")
                self.failed("Mac learning failed on primary")

            if not verify_secure_mac_on_vteps(sec_vtep, '1001', 1025, prim_vpc_mac, 'secure'):
                log.error("Mac learning failed on primary")
                self.failed("Mac learning failed on primary")
                
            if not verify_secure_mac_on_vteps(sa_vtep, '1001', 1025, prim_vpc_mac):
                log.error("Mac learning failed on standalone")
                self.failed("Mac learning failed on standalone")
        
        # Establish dialogs for running ISSU command
        dialog = Dialog([
            Statement(pattern=r'Do you want to continue with the installation \(y/n\)\?',
                      action='sendline(y)',
                      loop_continue=True,
                      continue_timer=True),
        ])
        
        with steps.start("Doing ISSU and verifying core/errors after ISSU"):
            primary_handle = get_vpc_primary_secondary_device([prim_vtep, sec_vtep])
            # Create ISSU command
            issu_cmd = 'install all nxos bootflash:'+str(issu_image)+' non-disruptive'
            
            # Perform ISSU
            result, output = primary_handle.reload(reload_command=issu_cmd, prompt_recovery=True, 
                                                   dialog=dialog, timeout=2000, return_output=True)
            output_split = list(filter(None, output.split('\n')))
            fail_flag = []
            fail_logs = '\n'
            
            # Process logs for any failure reasons
            for log_line in output_split:
                if re.search('CRASHED|CPU Hog|malloc|core dump|mts_send|redzone', log_line, re.I):
                    if 'Upgrade can no longer be aborted' in log_line:
                        continue
                    else:
                        fail_flag.append(0)
                        fail_logs += str(log_line) + '\n'
            
            # Reporting
            if 0 in fail_flag:
                self.failed(reason=fail_logs)
            else:
                self.passed(reason="Upgrade successful")
                        
            log.info("Waiting for 100 sec for the topology to come UP")
            time.sleep(100)
        
        with steps.start("checking NVE peers are up"):
            # Verify NVE Peers with new IP
            nvePeerData = verifyEVPNNvePeers(testscript.parameters['leavesDict'])

            if nvePeerData['result'] is 1:
                log.info("PASS : Successfully verified NVE Peering\n\n")
            else:
                log.error("FAIL : Failed to verify NVE Peering\n\n")
                self.failed(reason=nvePeerData['log'])
    
        with steps.start("checking CPDT time with ND ISSU"):
            ret = time_taken_for_issu(device = primary_handle)
            if int(ret) > issu_time_limit or int(ret) == 0:
                log.error('ISSU Time taken is more than allowed time %r', issu_time_limit)
                self.failed('ISSU Time taken is more than allowed time %r', issu_time_limit)
        
        with steps.start("Checking mac learning on local and remote vtep"):
            if not verify_port_sec_addr_count(prim_vtep, 'port-channel 11', 1, 'STATIC'):
                log.error("STATIC Mac learning failed")
                self.failed("STATIC Mac learning failed")
        
            if not verify_port_sec_addr_count(prim_vtep, 'port-channel 11', 1024, 'DYNAMIC'):
                log.error("DYNAMIC Mac learning failed")
                self.failed("DYNAMIC Mac learning failed")

            if not verify_port_sec_addr_count(sec_vtep, 'port-channel 11', 1, 'STATIC'):
                log.error("STATIC Mac learning failed")
                self.failed("STATIC Mac learning failed")
        
            if not verify_port_sec_addr_count(sec_vtep, 'port-channel 11', 1024, 'DYNAMIC'):
                log.error("DYNAMIC Mac learning failed")
                self.failed("DYNAMIC Mac learning failed")
            
            if not verify_secure_mac_on_vteps(prim_vtep, '1001', 1025, prim_vpc_mac, 'secure'):
                log.error("Mac learning failed on primary")
                self.failed("Mac learning failed on primary")

            if not verify_secure_mac_on_vteps(sec_vtep, '1001', 1025, prim_vpc_mac, 'secure'):
                log.error("Mac learning failed on primary")
                self.failed("Mac learning failed on primary")
                
            if not verify_secure_mac_on_vteps(sa_vtep, '1001', 1025, prim_vpc_mac):
                log.error("Mac learning failed on standalone")
                self.failed("Mac learning failed on standalone")

        stream1.StopStatelessTraffic()
        log.info('Waiting {}secs to stop the traffic'.format(traffic_stop_time))
        time.sleep(traffic_stop_time)

        with steps.start("Verify Steady State"):
            if VerifyTraffic("Test_Primary_ISSU_Access", testscript, traffic_item='Access VPC To Standalone'):
                log.info('Verify Traffic Success after ISSU')
            else:
                self.failed('Verify Traffic Failed after ISSU')

        with steps.start('Verify Learned mac address consistency between hardware and software'):
            if verify_mac_cc_between_hardware_software([prim_vtep, sec_vtep, sa_vtep]):
                self.passed('MAC CC success')
            else:
                self.failed('MAC CC failed')

    @aetest.test
    def verify_nd_issu_newprimary(self, testscript, testbed, steps):
        sa_vtep         = testscript.parameters['LEAF-3']
        prim_vtep       = testscript.parameters['LEAF-1']
        sec_vtep        = testscript.parameters['LEAF-2']
        prim_vpc_mac    = str(testscript.parameters['PORTSEC_Dict']['prim_vpc_mac'])
        ixNetwork       = testscript.parameters['ixNetwork']
        p1_handle       = testscript.parameters['vpc_handle']
        p2_handle       = testscript.parameters['sa_handle']
        issu_image      = testscript.parameters['abs_target_image']
        
        with steps.start("Starting hosts.."):
            p1_handle.Start()
            p2_handle.Start()
        
        log.info('Waiting {}secs to start 1025 hosts'.format(host_start_time))
        time.sleep(host_start_time)
    
        stream1 = ixNetwork.Traffic.TrafficItem.find(Name='Access VPC To Standalone')
        stream1.StartStatelessTraffic()
        log.info('Waiting {}secs to start the traffic'.format(traffic_start_time))
        time.sleep(traffic_start_time)
        
        with steps.start("Checking mac re-learning on local and remote vtep"):
            if not verify_port_sec_addr_count(prim_vtep, 'port-channel 11', 1, 'STATIC'):
                log.error("STATIC Mac learning failed")
                self.failed("STATIC Mac learning failed")
        
            if not verify_port_sec_addr_count(prim_vtep, 'port-channel 11', 1024, 'DYNAMIC'):
                log.error("DYNAMIC Mac learning failed")
                self.failed("DYNAMIC Mac learning failed")

            if not verify_port_sec_addr_count(sec_vtep, 'port-channel 11', 1, 'STATIC'):
                log.error("STATIC Mac learning failed")
                self.failed("STATIC Mac learning failed")
        
            if not verify_port_sec_addr_count(sec_vtep, 'port-channel 11', 1024, 'DYNAMIC'):
                log.error("DYNAMIC Mac learning failed")
                self.failed("DYNAMIC Mac learning failed")
            
            if not verify_secure_mac_on_vteps(prim_vtep, '1001', 1025, prim_vpc_mac, 'secure'):
                log.error("Mac learning failed on primary")
                self.failed("Mac learning failed on primary")

            if not verify_secure_mac_on_vteps(sec_vtep, '1001', 1025, prim_vpc_mac, 'secure'):
                log.error("Mac learning failed on primary")
                self.failed("Mac learning failed on primary")
                
            if not verify_secure_mac_on_vteps(sa_vtep, '1001', 1025, prim_vpc_mac):
                log.error("Mac learning failed on standalone")
                self.failed("Mac learning failed on standalone")
        
        # Establish dialogs for running ISSU command
        dialog = Dialog([
            Statement(pattern=r'Do you want to continue with the installation \(y/n\)\?',
                      action='sendline(y)',
                      loop_continue=True,
                      continue_timer=True),
        ])
        
        with steps.start("Doing ISSU and verifying core/errors after ISSU"):
            primary_handle = get_vpc_primary_secondary_device([prim_vtep, sec_vtep])
            # Create ISSU command
            issu_cmd = 'install all nxos bootflash:'+str(issu_image)+' non-disruptive'
            
            # Perform ISSU
            result, output = primary_handle.reload(reload_command=issu_cmd, prompt_recovery=True, 
                                                   dialog=dialog, timeout=2000, return_output=True)
            output_split = list(filter(None, output.split('\n')))
            fail_flag = []
            fail_logs = '\n'
            
            # Process logs for any failure reasons
            for log_line in output_split:
                if re.search('CRASHED|CPU Hog|malloc|core dump|mts_send|redzone', log_line, re.I):
                    if 'Upgrade can no longer be aborted' in log_line:
                        continue
                    else:
                        fail_flag.append(0)
                        fail_logs += str(log_line) + '\n'
            
            # Reporting
            if 0 in fail_flag:
                self.failed(reason=fail_logs)
            else:
                self.passed(reason="Upgrade successful")
                        
            log.info("Waiting for 100 sec for the topology to come UP")
            time.sleep(100)
        
        with steps.start("checking NVE peers are up"):
            # Verify NVE Peers with new IP
            nvePeerData = verifyEVPNNvePeers(testscript.parameters['leavesDict'])

            if nvePeerData['result'] is 1:
                log.info("PASS : Successfully verified NVE Peering\n\n")
            else:
                log.error("FAIL : Failed to verify NVE Peering\n\n")
                self.failed(reason=nvePeerData['log'])
    
        with steps.start("checking CPDT time with ND ISSU"):
            ret = time_taken_for_issu(device = primary_handle)
            if int(ret) > issu_time_limit or int(ret) == 0:
                log.error('ISSU Time taken is more than allowed time %r', issu_time_limit)
                self.failed('ISSU Time taken is more than allowed time %r', issu_time_limit)
        
        with steps.start("Checking mac learning on local and remote vtep"):
            if not verify_port_sec_addr_count(prim_vtep, 'port-channel 11', 1, 'STATIC'):
                log.error("STATIC Mac learning failed")
                self.failed("STATIC Mac learning failed")
        
            if not verify_port_sec_addr_count(prim_vtep, 'port-channel 11', 1024, 'DYNAMIC'):
                log.error("DYNAMIC Mac learning failed")
                self.failed("DYNAMIC Mac learning failed")

            if not verify_port_sec_addr_count(sec_vtep, 'port-channel 11', 1, 'STATIC'):
                log.error("STATIC Mac learning failed")
                self.failed("STATIC Mac learning failed")
        
            if not verify_port_sec_addr_count(sec_vtep, 'port-channel 11', 1024, 'DYNAMIC'):
                log.error("DYNAMIC Mac learning failed")
                self.failed("DYNAMIC Mac learning failed")
            
            if not verify_secure_mac_on_vteps(prim_vtep, '1001', 1025, prim_vpc_mac, 'secure'):
                log.error("Mac learning failed on primary")
                self.failed("Mac learning failed on primary")

            if not verify_secure_mac_on_vteps(sec_vtep, '1001', 1025, prim_vpc_mac, 'secure'):
                log.error("Mac learning failed on primary")
                self.failed("Mac learning failed on primary")
                
            if not verify_secure_mac_on_vteps(sa_vtep, '1001', 1025, prim_vpc_mac):
                log.error("Mac learning failed on standalone")
                self.failed("Mac learning failed on standalone")

        stream1.StopStatelessTraffic()
        log.info('Waiting {}secs to stop the traffic'.format(traffic_stop_time))
        time.sleep(traffic_stop_time)

        with steps.start("Verify Steady State"):
            if VerifyTraffic("Test_New_Primary_ISSU_Access", testscript, 
                             traffic_item='Access VPC To Standalone'):
                log.info('Verify Traffic Success after ISSU')
            else:
                self.failed('Verify Traffic Failed after ISSU')

        with steps.start('Verify Learned mac address consistency between hardware and software'):
            if verify_mac_cc_between_hardware_software([prim_vtep, sec_vtep, sa_vtep]):
                self.passed('MAC CC success')
            else:
                self.failed('MAC CC failed')

    @aetest.test
    def check_fex_status(self, testscript, steps):
        prim_vtep = testscript.parameters['LEAF-1']
        with steps.start("checking FEX Online after ISSU"):
            i = 0
            result = False
            while i < 900:
                if check_fex_state(prim_vtep):
                    log.info('FEX is up')
                    result = True
                    break
                
                log.info('Sleeping for 120sec')
                time.sleep(150)
                i = i + 150
            
            if not result:
                log.error('After ISSU, FEX is not Online')
                self.failed('After ISSU, FEX is not online')

    @aetest.test
    def test_cleanup(self, testscript, testbed, steps):
        sa_vtep         = testscript.parameters['LEAF-3']
        prim_vtep       = testscript.parameters['LEAF-1']
        sec_vtep        = testscript.parameters['LEAF-2']
        prim_vtep_if    = str(testscript.parameters['intf_LEAF_1_1_to_IXIA'])
        sa_vtep_if      = str(testscript.parameters['intf_LEAF_3_to_IXIA'])
        leaf1_mac       = str(testscript.parameters['PORTSEC_Dict']['vpc_static_mac'])
        fex_vtep_if     = str(testscript.parameters['intf_LEAF_1_FEX_to_IXIA'])
        src_vlan        = int(testscript.parameters['LEAF_1_Orphan1_TGEN_dict']['vlan_id'])
        ixNetwork       = testscript.parameters['ixNetwork']
        
        with steps.start("Stopping all hosts..."):
            ixNetwork.StopAllProtocols()

        traffic = ixNetwork.Traffic.TrafficItem.find()
        traffic.StopStatelessTraffic()
        log.info('Waiting 60secs to stop all traffic')
        time.sleep(60)
        
        new_config = '''no switchport port-security aging type inactivity
                        no switchport port-security violation restrict
                        no switchport port-security mac-address sticky'''
    
        with steps.start("UnConfigure Port-Security on Primary VTEP Orphan"):
            if not unconfig_interface_ps([prim_vtep], prim_vtep_if, log, new_config):
                self.errored('Exception occurred while configuring port security', goto=['common_cleanup'])
        
        with steps.start("UnConfigure Port-Security on Standalone VTEP"):
            if not unconfig_interface_ps([sa_vtep], sa_vtep_if, log, new_config):
                self.errored('Exception occurred while configuring port security', goto=['common_cleanup'])
        
        new_config = '''no switchport port-security aging type inactivity
                      no switchport port-security violation restrict
                      no switchport port-security mac-address {mac}'''.format(mac=leaf1_mac)
        with steps.start("UnConfigure Port-Security on VPC Primary/Secondary - Static"):
            
            if not unconfig_interface_ps([prim_vtep, sec_vtep], 'port-channel 11', log, new_config):
                self.errored('Exception occurred while configuring port security', goto=['common_cleanup'])
        
        new_config = '''no switchport port-security aging type inactivity
                        no switchport port-security violation restrict'''
        with steps.start("UnConfigure Port-Security on Leaf-1 FEX - FEX port of VTEP"):
            if not unconfig_interface_ps([prim_vtep], fex_vtep_if, log, new_config):
                self.errored('Exception occurred while configuring port security', goto=['common_cleanup'])

        log.info("Waiting {}secs for interface to come up".format(config_time))
        time.sleep(config_time)
        
        with steps.start("Verifying MTS leak.."):
            if verify_mts_leak([prim_vtep, sec_vtep, sa_vtep], log):
                log.info('MTS Leak verification success')
            else:
                self.failed('MTS Leak verification failed')

        with steps.start("Verifying Cores and Log Errors"):
            status = infraVerify.postTestVerification(post_test_process_dict)
            if status['status'] == 0:
                self.failed(reason=status['logs'])
            else:
                self.passed(reason=status['logs'])

# =============================================================================================================================#
# TC-ID: TC-11 - Orphan 
# Testcase:
# 1. Configure the port security with trunk mode and 
#     learn the dynamic mac
#     - Check mac learnt on current vtep as secure 
#        and remote vtep as static
# 2. Check the traffic end to end with vlan 1002
# 3. Learn mac with vlan 1001 as dynamic and 1002
# =============================================================================================================================#
class TC_VXLAN_PS_001_Access(aetest.Testcase):
    @aetest.test
    def test_setup(self, testscript, testbed, steps):
        sa_vtep         = testscript.parameters['LEAF-3']
        prim_vtep       = testscript.parameters['LEAF-1']
        sec_vtep       = testscript.parameters['LEAF-2']
        prim_vtep_if    = str(testscript.parameters['intf_LEAF_1_1_to_IXIA'])
        sec_vtep_if    = str(testscript.parameters['intf_LEAF_2_to_IXIA'])
        sa_vtep_if      = str(testscript.parameters['intf_LEAF_3_to_IXIA'])
        
        with steps.start("Configure Port-Security on Primary VTEP Orphan"):
            if not config_interface_ps([prim_vtep], prim_vtep_if, log):
                self.errored('Exception occurred while configuring port security', goto=['common_cleanup'])

        with steps.start("Configure Port-Security on Primary VTEP Orphan"):
            if not config_interface_ps([prim_vtep], prim_vtep_if, log):
                self.errored('Exception occurred while configuring port security', goto=['common_cleanup'])
        with steps.start("Configure Port-Security on Standalone VTEP"):
            if not config_interface_ps([sa_vtep], sa_vtep_if, log):
                self.errored('Exception occurred while configuring port security', goto=['common_cleanup'])
        
        log.info("Waiting {}secs for interface to come up".format(config_time))
        time.sleep(config_time)
        display_configs(testscript)
        
    @aetest.test
    def learn_mac_and_verify_peer_vtep(self, testscript, testbed, steps):
        sa_vtep         = testscript.parameters['LEAF-3']
        prim_vtep       = testscript.parameters['LEAF-1']
        sec_vtep        = testscript.parameters['LEAF-2']
        prim_vtep_if    = str(testscript.parameters['intf_LEAF_1_1_to_IXIA'])
        sa_vtep_if      = str(testscript.parameters['intf_LEAF_3_to_IXIA'])
        prim_orphan_mac = str(testscript.parameters['PORTSEC_Dict']['prim_orphan_mac'])
        sa_mac          = str(testscript.parameters['PORTSEC_Dict']['sa_mac'])
        ixNetwork       = testscript.parameters['ixNetwork']
        p1_handle       = testscript.parameters['orphan1_handle']
        p2_handle       = testscript.parameters['sa_handle']
        
        with steps.start("Starting hosts..."):
            p1_handle.Start()
            p2_handle.Start()
        
        log.info('Waiting {}secs to start 1025 hosts'.format(host_start_time))
        time.sleep(host_start_time)

        stream1 = ixNetwork.Traffic.TrafficItem.find(Name='Access Orphan To Standalone')
        ixNetwork.Traffic.Apply()
        stream1.StartStatelessTraffic()
        log.info('Waiting {}secs to start the traffic'.format(traffic_start_time))
        time.sleep(traffic_start_time)
        
        stream1.StopStatelessTraffic()
        log.info('Waiting {}secs to stop the traffic'.format(traffic_stop_time))
        time.sleep(traffic_stop_time)

        with steps.start("Checking mac learning on VPC vteps and remote"):
            if not verify_port_sec_addr_count(prim_vtep, prim_vtep_if, 1025, 'DYNAMIC'):
                log.error("DYNAMIC Mac learning failed")
                self.failed("DYNAMIC Mac learning failed")

            if not verify_secure_mac_on_vteps(prim_vtep, '1001', 1025, prim_orphan_mac, 'secure'):
                log.error("Mac learning failed on primary")
                self.failed("Mac learning failed on primary")

            if not verify_secure_mac_on_vteps(sec_vtep, '1001', 1025, prim_orphan_mac, 'secure'):
                log.error("Mac learning failed on primary")
                self.failed("Mac learning failed on primary")
                
            if not verify_secure_mac_on_vteps(sa_vtep, '1001', 1025, prim_orphan_mac):
                log.error("Mac learning failed on standalone")
                self.failed("Mac learning failed on standalone")

        with steps.start("Checking mac learning on Standalone and remote"):
            if not verify_port_sec_addr_count(sa_vtep, sa_vtep_if, 1025, 'DYNAMIC'):
                log.error("DYNAMIC Mac learning failed")
                self.failed("DYNAMIC Mac learning failed")

            if not verify_secure_mac_on_vteps(sa_vtep, '1002', 1025, sa_mac, 'secure'):
                log.error("Mac learning failed on Standalone")
                self.failed("Mac learning failed on Standalone")

            if not verify_secure_mac_on_vteps(prim_vtep, '1002', 1025, sa_mac):
                log.error("DYNAMIC Mac learning failed on remote vtep(leaf1)")
                self.failed("DYNAMIC Mac learning failed on remote vtep(leaf1)")

            if not verify_secure_mac_on_vteps(sec_vtep, '1002', 1025, sa_mac):
                log.error("DYNAMIC Mac learning failed on remote vtep(leaf2)")
                self.failed("DYNAMIC Mac learning failed on remote vtep(leaf2)")

        with steps.start("Verify Steady State"):
            if VerifyTraffic("Test_001_Orphan", testscript, traffic_item='Access Orphan To Standalone'):
                log.info('Verify Traffic success with Test_011_Orphan')
            else:
                self.failed('Verify Traffic failed with Test_011_Orphan')
    
    @aetest.test
    def remove_portsecurity_check_macs(self, testscript, testbed, steps):
        sa_vtep = testscript.parameters['LEAF-3']
        prim_vtep = testscript.parameters['LEAF-1']
        sec_vtep = testscript.parameters['LEAF-2']
        prim_vtep_if = str(testscript.parameters['intf_LEAF_1_1_to_IXIA'])
        sa_vtep_if = str(testscript.parameters['intf_LEAF_3_to_IXIA'])
        prim_orphan_mac = str(testscript.parameters['PORTSEC_Dict']['prim_orphan_mac'])
        sa_mac          = str(testscript.parameters['PORTSEC_Dict']['sa_mac'])
        vlan = int(testscript.parameters['LEAF_3_TGEN_dict']['vlan_id'])
        ixNetwork   = testscript.parameters['ixNetwork']

        with steps.start("Remove Port-Security on Leaf-3"):
            try:
                sa_vtep.configure('''interface {sa_vtep_if}
                                no switchport port-security
                            '''.format(sa_vtep_if=sa_vtep_if))
            except Exception as error:
                log.debug("Unable to configure - Encountered Exception " + str(error))
                self.errored('Exception occurred while configuring port security', goto=['common_cleanup'])
        
        log.info('Waiting 30secs for secure mac to dynamic mac conversion on standalone')
        time.sleep(30)
        
        with steps.start("Checking secure to dynamic mac conversion on standalone and remote"):
            if not verify_secure_mac_on_vteps(sa_vtep, '1002', 1025, sa_mac, 'dynamic'):
                log.error("Mac learning failed on Standalone")
                self.failed("DYNAMIC Mac learning failed on local vtep")
            
            if not verify_secure_mac_on_vteps(prim_vtep, '1002', 1025, sa_mac, 'dynamic'):
                log.error("DYNAMIC Mac learning failed on remote vtep(leaf1)")
                self.failed("DYNAMIC Mac learning failed on remote vtep(leaf1)")

            if not verify_secure_mac_on_vteps(sec_vtep, '1002', 1025, sa_mac, 'dynamic'):
                log.error("DYNAMIC Mac learning failed on remote vtep(leaf2)")
                self.failed("DYNAMIC Mac learning failed on remote vtep(leaf2)")

        with steps.start("Remove Port-Security on Leaf-1 Orphan"):
            try:
                prim_vtep.configure('''interface {prim_vtep_if}
                                no switchport port-security
                            '''.format(prim_vtep_if=prim_vtep_if))
            except Exception as error:
                log.debug("Unable to configure - Encountered Exception " + str(error))
                self.errored('Exception occurred while configuring port security', goto=['common_cleanup'])

        log.info('Waiting 30secs for secure mac to dynamic mac conversion on VPC')
        time.sleep(30)
        
        with steps.start("Checking secure to dynamic mac conversion on VPC and remote"):
            if not verify_secure_mac_on_vteps(sa_vtep, '1001', 1025, prim_orphan_mac, 'dynamic'):
                log.error("Mac learning failed on standalone")
                self.failed("DYNAMIC Mac learning failed on local vtep")
            if not verify_secure_mac_on_vteps(prim_vtep, '1001', 1025, prim_orphan_mac, 'dynamic'):
                log.error("Mac learning failed on primary")
                self.failed("Mac learning failed on primary")

            if not verify_secure_mac_on_vteps(sec_vtep, '1001', 1025, prim_orphan_mac, 'dynamic'):
                log.error("DYNAMIC Mac learning failed on secondary")
                self.failed("DYNAMIC Mac learning failed on secondary")

        with steps.start("UnConfigure Port-Security on Primary VTEP Orphan"):
            if not unconfig_interface_ps([prim_vtep], prim_vtep_if, log):
                self.errored('Exception occurred while configuring port security', goto=['common_cleanup'])
        
        with steps.start("UnConfigure Port-Security on Primary VTEP Orphan"):
            if not unconfig_interface_ps([prim_vtep], prim_vtep_if, log):
                self.errored('Exception occurred while configuring port security', goto=['common_cleanup'])
        with steps.start("UnConfigure Port-Security on Standalone VTEP"):
            if not unconfig_interface_ps([sa_vtep], sa_vtep_if, log):
                self.errored('Exception occurred while configuring port security', goto=['common_cleanup'])
        
        log.info("Waiting {}secs for interface to come up".format(config_time))
        time.sleep(config_time)
        
        with steps.start("Stopping all hosts..."):
            ixNetwork.StopAllProtocols()

        log.info('Waiting {}secs to stop the hosts'.format(traffic_stop_time))
        time.sleep(traffic_stop_time)

        with steps.start('Verify Learned mac address consistency between hardware and software'):
            if verify_mac_cc_between_hardware_software([prim_vtep, sec_vtep, sa_vtep]):
                log.info('MAC CC success')
            else:
                self.failed('MAC CC failed')
        
        with steps.start("Verifying MTS leak.."):
            if verify_mts_leak([prim_vtep, sec_vtep, sa_vtep], log):
                log.info('MTS Leak verification success')
            else:
                self.failed('MTS Leak verification failed')

        with steps.start("Verifying Cores and Log Errors"):
            status = infraVerify.postTestVerification(post_test_process_dict)
            if status['status'] == 0:
                self.failed(reason=status['logs'])
            else:
                self.passed(reason=status['logs'])

# =============================================================================================================================#
# TC-ID: TC11 FEX
# Testcase:
# 1. Configure the port security with trunk mode and 
#     learn the dynamic mac
#     - Check mac learnt on current vtep as secure 
#        and remote vtep as static
# 2. Check the traffic end to end with vlan 1002
# 3. Learn mac with vlan 1001 as dynamic and 1002
# =============================================================================================================================#
class TC_VXLAN_PS_002_Access(aetest.Testcase):
    @aetest.test
    def configure_access_vlan_port_security(self, testscript, testbed, steps):
        sa_vtep         = testscript.parameters['LEAF-3']
        prim_vtep       = testscript.parameters['LEAF-1']
        sa_vtep_if      = str(testscript.parameters['intf_LEAF_3_to_IXIA'])
        fex_vtep_if     = str(testscript.parameters['intf_LEAF_1_FEX_to_IXIA'])
        
        with steps.start("Configure Port-Security on FEX"):
            if not config_interface_ps([prim_vtep], fex_vtep_if, log):
                self.errored('Exception occurred while configuring port security', goto=['common_cleanup'])
        
        with steps.start("Configure Port-Security on Standalone VTEP"):
            if not config_interface_ps([sa_vtep], sa_vtep_if, log):
                self.errored('Exception occurred while configuring port security', goto=['common_cleanup'])
        
        log.info("Waiting {}secs for interface to come up".format(config_time))
        time.sleep(config_time)

        display_configs(testscript)

    @aetest.test
    def learn_mac_and_verify_peer_vtep(self, testscript, testbed, steps):
        sa_vtep         = testscript.parameters['LEAF-3']
        prim_vtep       = testscript.parameters['LEAF-1']
        sec_vtep        = testscript.parameters['LEAF-2']
        fex_vtep_if     = str(testscript.parameters['intf_LEAF_1_FEX_to_IXIA'])
        prim_fex_mac    = str(testscript.parameters['PORTSEC_Dict']['prim_fex_mac'])
        ixNetwork       = testscript.parameters['ixNetwork']
        p1_handle       = testscript.parameters['fex_handle']
        p2_handle       = testscript.parameters['sa_handle']
        
        with steps.start("Starting hosts..."):
            p1_handle.Start()
            p2_handle.Start()
        
        log.info('Waiting {}secs to start 1025 hosts'.format(host_start_time))
        time.sleep(host_start_time)
        
        stream1 = ixNetwork.Traffic.TrafficItem.find(Name='Access FEX To Standalone')
        stream1.StartStatelessTraffic()

        log.info('Waiting {}secs to start the traffic'.format(traffic_start_time))
        time.sleep(traffic_start_time)
        
        stream1.StopStatelessTraffic()
        log.info('Waiting {}secs to stop the traffic'.format(traffic_stop_time))
        time.sleep(traffic_stop_time)

        with steps.start("Checking mac learning on fex port and remote"):
            if not verify_port_sec_addr_count(prim_vtep, fex_vtep_if, 1025, 'DYNAMIC'):
                log.error("DYNAMIC Mac learning failed")
                self.failed("DYNAMIC Mac learning failed")

            if not verify_secure_mac_on_vteps(prim_vtep, '1001', 1025, prim_fex_mac, 'secure'):
                log.error("Mac learning failed on primary")
                self.failed("Mac learning failed on primary")
            if not verify_secure_mac_on_vteps(sec_vtep, '1001', 1025, prim_fex_mac, 'secure'):
                log.error("Mac learning failed on primary")
                self.failed("Mac learning failed on primary")
            if not verify_secure_mac_on_vteps(sa_vtep, '1001', 1025, prim_fex_mac):
                log.error("Mac learning failed on standalone")
                self.failed("Mac learning failed on standalone")

        with steps.start("Verify Steady State"):
            if VerifyTraffic("Test_001_FEX", testscript, traffic_item='Access FEX To Standalone'):
                self.passed('Verify traffic success')
            else:
                self.failed('Verify traffic failure')
    
    @aetest.test
    def remove_portsecurity_check_macs(self, testscript, testbed, steps):
        sa_vtep = testscript.parameters['LEAF-3']
        prim_vtep = testscript.parameters['LEAF-1']
        sa_vtep_if = str(testscript.parameters['intf_LEAF_3_to_IXIA'])
        sec_vtep = testscript.parameters['LEAF-2']
        fex_vtep_if = str(testscript.parameters['intf_LEAF_1_FEX_to_IXIA'])
        prim_fex_mac = str(testscript.parameters['PORTSEC_Dict']['prim_fex_mac'])
        ixNetwork   = testscript.parameters['ixNetwork']
        
        with steps.start("Remove Port-Security on Primary VTEP FEX port"):
            try:
                prim_vtep.configure('''interface {intf}
                                no switchport port-security
                            '''.format(intf=fex_vtep_if))
            except Exception as error:
                log.debug("Unable to configure - Encountered Exception " + str(error))
                self.errored('Exception occurred while configuring port security', goto=['common_cleanup'])

        log.info("Waiting {}secs for interface to come up".format(config_time))
        time.sleep(config_time)

        with steps.start("Checking mac/arp learning on fex port and remote vtep (leaf3).."):
            if not verify_secure_mac_on_vteps(sa_vtep, '1001', 1025, prim_fex_mac, 'dynamic'):
                log.error("Mac learning failed on standalone")
                self.failed("DYNAMIC Mac learning failed on local vtep")
            if not verify_secure_mac_on_vteps(prim_vtep, '1001', 1025, prim_fex_mac, 'dynamic'):
                log.error("Mac learning failed on primary")
                self.failed("Mac learning failed on primary")

            if not verify_secure_mac_on_vteps(sec_vtep, '1001', 1025, prim_fex_mac, 'dynamic'):
                log.error("DYNAMIC Mac learning failed on secondary")
                self.failed("DYNAMIC Mac learning failed on secondary")

        with steps.start("UnConfigure Port-Security on FEX"):
            if not unconfig_interface_ps([prim_vtep], fex_vtep_if, log):
                self.errored('Exception occurred while configuring port security', goto=['common_cleanup'])
        
        with steps.start("UnConfigure Port-Security on Standalone VTEP"):
            if not unconfig_interface_ps([sa_vtep], sa_vtep_if, log):
                self.errored('Exception occurred while configuring port security', goto=['common_cleanup'])
        
        log.info("Waiting {}secs for interface to come up".format(config_time))
        time.sleep(config_time)
        
        with steps.start("Stopping all hosts..."):
            ixNetwork.StopAllProtocols()

        log.info('Waiting {}secs to stop the hosts'.format(traffic_stop_time))
        time.sleep(traffic_stop_time)

        with steps.start('Verify Learned mac address consistency between hardware and software'):
            if verify_mac_cc_between_hardware_software([prim_vtep, sec_vtep, sa_vtep]):
                log.info('MAC CC success')
            else:
                self.failed('MAC CC failed')
        
        with steps.start("Verifying MTS leak.."):
            if verify_mts_leak([prim_vtep, sec_vtep, sa_vtep], log):
                log.info('MTS Leak verification success')
            else:
                self.failed('MTS Leak verification failed')

        with steps.start("Verifying Cores and Log Errors"):
            status = infraVerify.postTestVerification(post_test_process_dict)
            if status['status'] == 0:
                self.failed(reason=status['logs'])
            else:
                self.passed(reason=status['logs'])

# =============================================================================================================================#
# TC-ID: TC11 - VPC
# Testcase:
# 1. Configure the port security with trunk mode and 
#     learn the dynamic mac
#     - Check mac learnt on current vtep as secure 
#        and remote vtep as static
# 2. Check the traffic end to end with vlan 1002
# 3. Learn mac with vlan 1001 as dynamic and 1002
# =============================================================================================================================#
class TC_VXLAN_PS_003_Access(aetest.Testcase):
    @aetest.test
    def verify_dynamic_mac_vpc(self, testscript, testbed, steps):
        sa_vtep         = testscript.parameters['LEAF-3']
        prim_vtep       = testscript.parameters['LEAF-1']
        sec_vtep        = testscript.parameters['LEAF-2']
        sa_vtep_if      = str(testscript.parameters['intf_LEAF_3_to_IXIA'])
        prim_vpc_mac    = str(testscript.parameters['PORTSEC_Dict']['prim_vpc_mac'])
        ixNetwork       = testscript.parameters['ixNetwork']
        p1_handle       = testscript.parameters['vpc_handle']
        p2_handle       = testscript.parameters['sa_handle']
        
        with steps.start("Configure Port-Security on VPC Primary/Secondary"):
            if not config_interface_ps([prim_vtep, sec_vtep], 'port-channel 11', log):
                self.errored('Exception occurred while configuring port security', goto=['common_cleanup'])

        with steps.start("Configure Port-Security on Standalone VTEP"):
            if not config_interface_ps([sa_vtep], sa_vtep_if, log):
                self.errored('Exception occurred while configuring port security', goto=['common_cleanup'])
        
        log.info("Waiting {}secs for interface to come up".format(config_time))
        time.sleep(config_time)
        display_configs(testscript)
        
        with steps.start("Starting hosts.."):
            p1_handle.Start()
            p2_handle.Start()

        log.info('Waiting {}secs to start 1025 hosts'.format(host_start_time))
        time.sleep(host_start_time)
                
        stream1 = ixNetwork.Traffic.TrafficItem.find(Name='Access VPC To Standalone')
        
        stream1.StartStatelessTraffic()
        log.info('Waiting {}secs to start the traffic'.format(traffic_start_time))
        time.sleep(traffic_start_time)
        
        stream1.StopStatelessTraffic()
        log.info('Waiting {}secs to stop the traffic'.format(traffic_stop_time))
        time.sleep(traffic_stop_time)
        
        with steps.start("Checking mac learning on primary/secondary and remote"):
            if not verify_port_sec_addr_count(prim_vtep, 'port-channel 11', 1025, 'DYNAMIC'):
                log.error("DYNAMIC Mac learning failed")
                self.failed("DYNAMIC Mac learning failed")
            if not verify_port_sec_addr_count(sec_vtep, 'port-channel 11', 1025, 'DYNAMIC'):
                log.error("DYNAMIC Mac learning failed")
                self.failed("DYNAMIC Mac learning failed")

            if not verify_secure_mac_on_vteps(prim_vtep, '1001', 1025, prim_vpc_mac, 'secure'):
                log.error("Mac learning failed on primary")
                self.failed("Mac learning failed on primary")
            if not verify_secure_mac_on_vteps(sec_vtep, '1001', 1025, prim_vpc_mac, 'secure'):
                log.error("Mac learning failed on primary")
                self.failed("Mac learning failed on primary")
            if not verify_secure_mac_on_vteps(sa_vtep, '1001', 1025, prim_vpc_mac):
                log.error("Mac learning failed on standalone")
                self.failed("Mac learning failed on standalone")

        with steps.start("Verify Steady State"):

            if VerifyTraffic("Test_004_VPC", testscript, traffic_item='Access VPC To Standalone'):
                self.passed('Verify traffic success')
            else:
                self.failed('Verify traffic failure')
    
    @aetest.test
    def remove_portsecurity_check_macs(self, testscript, testbed, steps):
        sa_vtep         = testscript.parameters['LEAF-3']
        prim_vtep       = testscript.parameters['LEAF-1']
        sec_vtep        = testscript.parameters['LEAF-2']
        sa_vtep_if      = str(testscript.parameters['intf_LEAF_3_to_IXIA'])
        prim_vpc_mac    = str(testscript.parameters['PORTSEC_Dict']['prim_vpc_mac'])
        ixNetwork       = testscript.parameters['ixNetwork']
        
        with steps.start("Remove Port-Security on Leaf-3"):
            try:
                prim_vtep.configure('''interface port-channel 11
                                no switchport port-security
                            ''')
            except Exception as error:
                log.debug("Unable to configure - Encountered Exception " + str(error))
                self.errored('Exception occurred while configuring port security', goto=['common_cleanup'])
        
        with steps.start("Remove Port-Security on Secondary"):
            try:
                sec_vtep.configure('''interface port-channel 11
                                no switchport port-security
                            ''')
            except Exception as error:
                log.debug("Unable to configure - Encountered Exception " + str(error))
                self.errored('Exception occurred while configuring port security', goto=['common_cleanup'])
        
        log.info('Waiting 30secs for secure mac to dynamic mac conversion on standalone')
        time.sleep(30)
        
        with steps.start("Checking non-secure dynamic mac learning on primary/secondary and remote"):
            if not verify_secure_mac_on_vteps(sa_vtep, '1001', 1025, prim_vpc_mac, 'dynamic'):
                log.error("Mac learning failed on standalone")
                self.failed("DYNAMIC Mac learning failed on local vtep")
            if not verify_secure_mac_on_vteps(prim_vtep, '1001', 1025, prim_vpc_mac, 'dynamic'):
                log.error("Mac learning failed on primary")
                self.failed("Mac learning failed on primary")

            if not verify_secure_mac_on_vteps(sec_vtep, '1001', 1025, prim_vpc_mac, 'dynamic'):
                log.error("DYNAMIC Mac learning failed on secondary")
                self.failed("DYNAMIC Mac learning failed on secondary")

        with steps.start("UnConfigure Port-Security on VPC Primary/Secondary - Static"):
            if not unconfig_interface_ps([prim_vtep, sec_vtep], 'port-channel 11', log):
                self.errored('Exception occurred while configuring port security', goto=['common_cleanup'])
        
        with steps.start("UnConfigure Port-Security on Standalone VTEP"):
            if not unconfig_interface_ps([sa_vtep], sa_vtep_if, log):
                self.errored('Exception occurred while configuring port security', goto=['common_cleanup'])
        
        log.info("Waiting {}secs for interface to come up".format(config_time))
        time.sleep(config_time)

        with steps.start("Stopping all hosts..."):
            ixNetwork.StopAllProtocols()

        log.info('Waiting {}secs to stop the hosts'.format(traffic_stop_time))
        time.sleep(traffic_stop_time)
		
        with steps.start('Verify Learned mac address consistency between hardware and software'):
            if verify_mac_cc_between_hardware_software([prim_vtep, sec_vtep, sa_vtep]):
                log.info('MAC CC success')
            else:
                self.failed('MAC CC failed')
        
        with steps.start("Verifying MTS leak.."):
            if verify_mts_leak([prim_vtep, sec_vtep, sa_vtep], log):
                log.info('MTS Leak verification success')
            else:
                self.failed('MTS Leak verification failed')

        with steps.start("Verifying Cores and Log Errors"):
            status = infraVerify.postTestVerification(post_test_process_dict)
            if status['status'] == 0:
                self.failed(reason=status['logs'])
            else:
                self.passed(reason=status['logs'])

# =============================================================================================================================#
# TC-ID: TC003, TC005, TC009
# Testcase:
# 1. Configure the port security with static and sticky mac
# 2. Check mac learnt on current vtep as secure 
#    and remote vtep as static
# 3. Check the traffic end to end
# 4. Remove port-security and mac shoud be removed
# 5. Remove using "no switchport port-security mac-
#     address sticky
# =============================================================================================================================#
class TC_VXLAN_PS_004_Access(aetest.Testcase):
    @aetest.test
    def verify_sticky_static_mac_orphan(self, testscript, testbed, steps):
        sa_vtep         = testscript.parameters['LEAF-3']
        prim_vtep       = testscript.parameters['LEAF-1']
        sec_vtep        = testscript.parameters['LEAF-2']
        prim_vtep_if    = str(testscript.parameters['intf_LEAF_1_1_to_IXIA'])
        sa_vtep_if      = str(testscript.parameters['intf_LEAF_3_to_IXIA'])
        leaf3_mac       = str(testscript.parameters['PORTSEC_Dict']['sa_static_mac'])
        leaf1_mac       = str(testscript.parameters['PORTSEC_Dict']['orphan_static_mac'])
        prim_orphan_mac = str(testscript.parameters['PORTSEC_Dict']['prim_orphan_mac'])
        sa_mac          = str(testscript.parameters['PORTSEC_Dict']['sa_mac'])
        vlan            = int(testscript.parameters['LEAF_1_Orphan1_TGEN_dict']['vlan_id'])
        vlan3           = int(testscript.parameters['LEAF_3_TGEN_dict']['vlan_id'])
        ixNetwork       = testscript.parameters['ixNetwork']
        p1_handle       = testscript.parameters['orphan1_handle']
        p2_handle       = testscript.parameters['sa_handle']
        
        with steps.start("Starting hosts..."):
            p1_handle.Start()
            p2_handle.Start()
        
        log.info('Waiting {}secs to start 1025 hosts'.format(host_start_time))
        time.sleep(host_start_time)
        
        stream1 = ixNetwork.Traffic.TrafficItem.find(Name='Access Orphan To Standalone')
        stream1.StartStatelessTraffic()
        
        log.info('Waiting {}secs to start the traffic'.format(traffic_start_time))
        time.sleep(traffic_start_time)
        
        with steps.start("Configure Port-Security - Static and Sticky on Standalone VTEP"):
            new_config = '''switchport port-security mac-address {mac}
                            switchport port-security mac-address sticky'''.format(mac=leaf3_mac)

            if not config_interface_ps([sa_vtep], sa_vtep_if, log, new_config):
                self.errored('Exception occurred while configuring port security', goto=['common_cleanup'])

        with steps.start("Configure Port-Security - Static and Sticky on Primary VTEP"):
            new_config = '''switchport port-security mac-address {mac}
                            switchport port-security mac-address sticky'''.format(mac=leaf1_mac)

            if not config_interface_ps([prim_vtep], prim_vtep_if, log, new_config):
                self.errored('Exception occurred while configuring port security', goto=['common_cleanup'])
        
        log.info("Waiting {}secs for interface to come up".format(config_time))
        time.sleep(config_time)
        display_configs(testscript)

        stream1.StopStatelessTraffic()
        log.info('Waiting {}secs to stop the traffic'.format(traffic_stop_time))
        time.sleep(traffic_stop_time)

        with steps.start("Starting hosts..."):
            p1_handle.Start()
            p2_handle.Start()
        
        log.info('Waiting {}secs to start 1025 hosts'.format(host_start_time))
        time.sleep(host_start_time)
        
        stream1 = ixNetwork.Traffic.TrafficItem.find(Name='Access Orphan To Standalone')
        stream1.StartStatelessTraffic()
        
        log.info('Waiting {}secs to start the traffic'.format(traffic_start_time))
        time.sleep(traffic_start_time)
        
        stream1.StopStatelessTraffic()
        log.info('Waiting {}secs to stop the traffic'.format(traffic_stop_time))
        time.sleep(traffic_stop_time)

        with steps.start("Checking mac learning on Orphan and remote"):
            if not verify_port_sec_addr_count(prim_vtep, prim_vtep_if, 1, 'STATIC'):
                log.error("STATIC Mac learning failed")
                self.failed("STATIC Mac learning failed")
        
            if not verify_port_sec_addr_count(prim_vtep, prim_vtep_if, 1024, 'STICKY'):
                log.error("Mac learning failed")
                self.failed("Mac learning failed")
        
            if not verify_secure_mac_on_vteps(prim_vtep, '1001', 1025, prim_orphan_mac, 'secure'):
                log.error("Mac learning failed on primary")
                self.failed("Mac learning failed on primary")

            if not verify_secure_mac_on_vteps(sec_vtep, '1001', 1025, prim_orphan_mac, 'secure'):
                log.error("Mac learning failed on primary")
                self.failed("Mac learning failed on primary")
                
            if not verify_secure_mac_on_vteps(sa_vtep, '1001', 1025, prim_orphan_mac):
                log.error("Mac learning failed on standalone")
                self.failed("Mac learning failed on standalone")

        with steps.start("Checking mac learning on standalone and remote"):
            if not verify_port_sec_addr_count(sa_vtep, sa_vtep_if, 1, 'STATIC'):
                log.error("STATIC Mac learning failed")
                self.failed("STATIC Mac learning failed")
            if not verify_port_sec_addr_count(sa_vtep, sa_vtep_if, 1024, 'STICKY'):
                log.error("Mac learning failed")
                self.failed("Mac learning failed")

            if not verify_secure_mac_on_vteps(sa_vtep, '1002', 1025, sa_mac, 'secure'):
                log.error("Mac learning failed on local vtep(leaf3)")
                self.failed("Mac learning failed on local vtep (leaf3)")

            if not verify_secure_mac_on_vteps(prim_vtep, '1002', 1025, sa_mac):
                log.error("Mac learning failed on remote vtep(leaf1)")
                self.failed("Mac learning failed on remote vtep(leaf1)")

            if not verify_secure_mac_on_vteps(sec_vtep, '1002', 1025, sa_mac):
                log.error("Mac learning failed on remote vtep(leaf2)")
                self.failed("Mac learning failed on remote vtep(leaf2)")

        with steps.start("Verify Steady State"):
            if VerifyTraffic("Test_004_Orphan", testscript, traffic_item='Access Orphan To Standalone'):
                log.info('Verify traffic success')
            else:
                self.failed('Verify traffic failed')
    
    @aetest.test
    def remove_portsecurity_check_macs(self, testscript, testbed, steps):
        sa_vtep         = testscript.parameters['LEAF-3']
        prim_vtep       = testscript.parameters['LEAF-1']
        sec_vtep        = testscript.parameters['LEAF-2']
        prim_vtep_if    = str(testscript.parameters['intf_LEAF_1_1_to_IXIA'])
        sa_vtep_if      = str(testscript.parameters['intf_LEAF_3_to_IXIA'])
        vlan            = int(testscript.parameters['LEAF_1_Orphan1_TGEN_dict']['vlan_id'])
        vlan3           = int(testscript.parameters['LEAF_3_TGEN_dict']['vlan_id'])
        leaf3_mac       = str(testscript.parameters['PORTSEC_Dict']['sa_static_mac'])
        leaf1_mac       = str(testscript.parameters['PORTSEC_Dict']['orphan_static_mac'])
        prim_orphan_mac = str(testscript.parameters['PORTSEC_Dict']['prim_orphan_mac'])
        sa_mac          = str(testscript.parameters['PORTSEC_Dict']['sa_mac'])
        ixNetwork       = testscript.parameters['ixNetwork']
        
        with steps.start("UnConfigure Port-Security - Static and Sticky on Standalone VTEP"):
            new_config = '''no switchport port-security mac-address {mac}
                            no switchport port-security mac-address sticky'''.format(mac=leaf3_mac)

            if not unconfig_interface_ps([sa_vtep], sa_vtep_if, log, new_config, True):
                self.errored('Exception occurred while configuring port security', goto=['common_cleanup'])

        log.info("Waiting {}secs for interface to come up".format(config_time))
        time.sleep(config_time)
        
        with steps.start("Checking non-secure dynamic mac learning on standalone and remote vtep.."):
            if not verify_secure_mac_on_vteps(sa_vtep, '1002', 1025, sa_mac, 'dynamic'):
                log.error("Mac learning failed on local vtep(leaf3)")
                self.failed("Mac learning failed on local vtep")
            
            if not verify_secure_mac_on_vteps(prim_vtep, '1002', 1025, sa_mac, 'dynamic'):
                log.error("Mac learning failed on remote vtep(leaf1)")
                self.failed("Mac learning failed on remote vtep(leaf1)")

            if not verify_secure_mac_on_vteps(sec_vtep, '1002', 1025, sa_mac, 'dynamic'):
                log.error("Mac learning failed on remote vtep(leaf2)")
                self.failed("Mac learning failed on remote vtep(leaf2)")

        with steps.start("Configure Port-Security - Static and Sticky on Primary VTEP"):
            new_config = '''no switchport port-security mac-address {mac}
                            no switchport port-security mac-address sticky'''.format(mac=leaf1_mac)

            if not unconfig_interface_ps([prim_vtep], prim_vtep_if, log, new_config, True):
                self.errored('Exception occurred while configuring port security', goto=['common_cleanup'])
                
        log.info("Waiting {}secs for interface to come up".format(config_time))
        time.sleep(config_time)
        
        with steps.start("Checking non-secure dynamic mac learning on orphan and remote vtep.."):
            if not verify_secure_mac_on_vteps(sa_vtep, '1001', 1025, prim_orphan_mac, 'dynamic'):
                log.error("Mac learning failed on standalone")
                self.failed("Mac learning failed on local vtep")
            if not verify_secure_mac_on_vteps(prim_vtep, '1001', 1025, prim_orphan_mac, 'dynamic'):
                log.error("Mac learning failed on primary")
                self.failed("Mac learning failed on primary")

            if not verify_secure_mac_on_vteps(sec_vtep, '1001', 1025, prim_orphan_mac, 'dynamic'):
                log.error("Mac learning failed on secondary")
                self.failed("Mac learning failed on secondary")
        
        with steps.start("Stopping all hosts..."):
            ixNetwork.StopAllProtocols()

        log.info('Waiting {}secs to stop the hosts'.format(traffic_stop_time))
        time.sleep(traffic_stop_time)

        with steps.start('Verify Learned mac address consistency between hardware and software'):
            if verify_mac_cc_between_hardware_software([prim_vtep, sec_vtep, sa_vtep]):
                log.info('MAC CC success')
            else:
                self.failed('MAC CC failed')
        
        with steps.start("Verifying MTS leak.."):
            if verify_mts_leak([prim_vtep, sec_vtep, sa_vtep], log):
                log.info('MTS Leak verification success')
            else:
                self.failed('MTS Leak verification failed')
        
        with steps.start("Verifying Cores and Log Errors"):
            status = infraVerify.postTestVerification(post_test_process_dict)
            if status['status'] == 0:
                self.failed(reason=status['logs'])
            else:
                self.passed(reason=status['logs'])

# =============================================================================================================================#
# TC-ID: TC003, TC005, TC009
# Testcase:
# 1. Configure the port security with static and sticky mac
# 2. Check mac learnt on current vtep as secure 
#    and remote vtep as static
# 3. Check the traffic end to end
# 4. Remove port-security and mac shoud be removed
# =============================================================================================================================#
class TC_VXLAN_PS_005_Access(aetest.Testcase):
    @aetest.test
    def verify_sticky_static_mac_vpc(self, testscript, testbed, steps):
        sa_vtep         = testscript.parameters['LEAF-3']
        prim_vtep       = testscript.parameters['LEAF-1']
        sec_vtep        = testscript.parameters['LEAF-2']
        sa_vtep_if      = str(testscript.parameters['intf_LEAF_3_to_IXIA'])
        leaf1_mac       = str(testscript.parameters['PORTSEC_Dict']['vpc_static_mac'])
        prim_vpc_mac    = str(testscript.parameters['PORTSEC_Dict']['prim_vpc_mac'])
        vlan            = int(testscript.parameters['LEAF_1_Orphan1_TGEN_dict']['vlan_id'])
        p1_handle       = testscript.parameters['vpc_handle']
        p2_handle       = testscript.parameters['sa_handle']
        ixNetwork       = testscript.parameters['ixNetwork']

        with steps.start("Configure Port-Security - Static and Sticky on Standalone VTEP"):
            if not config_interface_ps([sa_vtep], sa_vtep_if, log):
                self.errored('Exception occurred while configuring port security', 
                             goto=['common_cleanup'])

        with steps.start("Configure Port-Security - Static and Sticky on Primary VTEP"):
            new_config = '''switchport port-security mac-address {mac}
                            switchport port-security mac-address sticky'''.format(mac=leaf1_mac)

            if not config_interface_ps([prim_vtep, sec_vtep], 'port-channel 11', log, new_config):
                self.errored('Exception occurred while configuring port security', 
                             goto=['common_cleanup'])
        
        log.info("Waiting {}secs for interface to come up".format(config_time))
        time.sleep(config_time)
        display_configs(testscript)
        
        with steps.start("Starting hosts..."):
            p1_handle.Start()
            p2_handle.Start()

        log.info('Waiting {}secs to stop the hosts'.format(traffic_stop_time))
        time.sleep(traffic_stop_time)
    
        stream1 = ixNetwork.Traffic.TrafficItem.find(Name='Access VPC To Standalone')
        stream1.StartStatelessTraffic()
        log.info('Waiting {}secs to start the traffic'.format(traffic_start_time))
        time.sleep(traffic_start_time)
        
        stream1.StopStatelessTraffic()
        log.info('Waiting {}secs to stop the traffic'.format(traffic_stop_time))
        time.sleep(traffic_stop_time)

        with steps.start("Checking mac learning on orphan and remote.."):
            if not verify_port_sec_addr_count(prim_vtep, 'port-channel 11', 1, 'STATIC'):
                log.error("STATIC Mac learning failed")
                self.failed("STATIC Mac learning failed")
        
            if not verify_port_sec_addr_count(prim_vtep, 'port-channel 11', 1024, 'STICKY'):
                log.error("Mac learning failed")
                self.failed("Mac learning failed")

            if not verify_port_sec_addr_count(sec_vtep, 'port-channel 11', 1, 'STATIC'):
                log.error("STATIC Mac learning failed")
                self.failed("STATIC Mac learning failed")
        
            if not verify_port_sec_addr_count(sec_vtep, 'port-channel 11', 1024, 'STICKY'):
                log.error("Mac learning failed")
                self.failed("Mac learning failed")
            
            if not verify_secure_mac_on_vteps(prim_vtep, '1001', 1025, prim_vpc_mac, 'secure'):
                log.error("Mac learning failed on primary")
                self.failed("Mac learning failed on primary")

            if not verify_secure_mac_on_vteps(sec_vtep, '1001', 1025, prim_vpc_mac, 'secure'):
                log.error("Mac learning failed on primary")
                self.failed("Mac learning failed on primary")
                
            if not verify_secure_mac_on_vteps(sa_vtep, '1001', 1025, prim_vpc_mac):
                log.error("Mac learning failed on standalone")
                self.failed("Mac learning failed on standalone")

        with steps.start("Verify Steady State"):
            if VerifyTraffic("Test_005_VPC", testscript, traffic_item='Access VPC To Standalone'):
                log.info('Verify traffic success')
            else:
                self.failed('Verify traffic failed')

    @aetest.test
    def remove_portsecurity_check_macs(self, testscript, testbed, steps):
        sa_vtep         = testscript.parameters['LEAF-3']
        prim_vtep       = testscript.parameters['LEAF-1']
        sec_vtep        = testscript.parameters['LEAF-2']
        sa_vtep_if      = str(testscript.parameters['intf_LEAF_3_to_IXIA'])
        leaf1_mac       = str(testscript.parameters['PORTSEC_Dict']['vpc_static_mac'])
        prim_vpc_mac    = str(testscript.parameters['PORTSEC_Dict']['prim_vpc_mac'])
        vlan            = int(testscript.parameters['LEAF_1_Orphan1_TGEN_dict']['vlan_id'])
        ixNetwork       = testscript.parameters['ixNetwork']
        
        with steps.start("Configure Port-Security - Static and Sticky on Standalone VTEP"):
            if not unconfig_interface_ps([sa_vtep], sa_vtep_if, log):
                self.errored('Exception occurred while configuring port security', goto=['common_cleanup'])

        with steps.start("UnConfigure Port-Security - Static and Sticky on Primary VTEP"):
            new_config = '''no switchport port-security mac-address {mac}
                            no switchport port-security mac-address sticky'''.format(mac=leaf1_mac)

            if not unconfig_interface_ps([prim_vtep, sec_vtep], 'port-channel 11', log, new_config, True):
                self.errored('Exception occurred while configuring port security', goto=['common_cleanup'])
        
        log.info("Waiting {}secs for interface to come up".format(config_time))
        time.sleep(config_time)
        
        with steps.start("Checking non-secure dynamic mac learning on primary/secondary and remote"):
            if not verify_secure_mac_on_vteps(sa_vtep, '1001', 1025, prim_vpc_mac, 'dynamic'):
                log.error("Mac learning failed on standalone")
                self.failed("Mac learning failed on local vtep")
            if not verify_secure_mac_on_vteps(prim_vtep, '1001', 1025, prim_vpc_mac, 'dynamic'):
                log.error("Mac learning failed on primary")
                self.failed("Mac learning failed on primary")

            if not verify_secure_mac_on_vteps(sec_vtep, '1001', 1025, prim_vpc_mac, 'dynamic'):
                log.error("Mac learning failed on secondary")
                self.failed("Mac learning failed on secondary")

        with steps.start("Stopping all hosts..."):
            ixNetwork.StopAllProtocols()

        log.info('Waiting {}secs to stop the hosts'.format(traffic_stop_time))
        time.sleep(traffic_stop_time)
    
        with steps.start('Verify Learned mac address consistency between hardware and software'):
            if verify_mac_cc_between_hardware_software([prim_vtep, sec_vtep, sa_vtep]):
                log.info('MAC CC success')
            else:
                self.failed('MAC CC failed')
        
        with steps.start("Verifying MTS leak.."):
            if verify_mts_leak([prim_vtep, sec_vtep, sa_vtep], log):
                log.info('MTS Leak verification success')
            else:
                self.failed('MTS Leak verification failed')

        with steps.start("Verifying Cores and Log Errors"):
            status = infraVerify.postTestVerification(post_test_process_dict)
            if status['status'] == 0:
                self.failed(reason=status['logs'])
            else:
                self.passed(reason=status['logs'])

# =============================================================================================================================#
# TC-ID: TC003, TC005, TC009
# Testcase:
# 1. Configure the port security with static and sticky mac
# 2. Check mac learnt on current vtep as secure 
#    and remote vtep as static
# 3. Check the traffic end to end
# 4. Remove port-security and mac shoud be removed
# =============================================================================================================================#
class TC_VXLAN_PS_006_Access(aetest.Testcase):
    @aetest.test
    def verify_sticky_static_mac_fex(self, testscript, testbed, steps):
        sa_vtep         = testscript.parameters['LEAF-3']
        prim_vtep       = testscript.parameters['LEAF-1']
        sec_vtep        = testscript.parameters['LEAF-2']
        sa_vtep_if      = str(testscript.parameters['intf_LEAF_3_to_IXIA'])
        leaf1_mac       = str(testscript.parameters['PORTSEC_Dict']['fex_static_mac'])
        prim_fex_mac    = str(testscript.parameters['PORTSEC_Dict']['prim_fex_mac'])
        fex_vtep_if     = str(testscript.parameters['intf_LEAF_1_FEX_to_IXIA'])
        vlan            = int(testscript.parameters['LEAF_1_Orphan1_TGEN_dict']['vlan_id'])
        p1_handle       = testscript.parameters['fex_handle']
        p2_handle       = testscript.parameters['sa_handle']
        ixNetwork       = testscript.parameters['ixNetwork']

        with steps.start("Configure Port-Security - Static and Sticky on Standalone VTEP"):
            if not config_interface_ps([sa_vtep], sa_vtep_if, log):
                self.errored('Exception occurred while configuring port security', goto=['common_cleanup'])

        with steps.start("Configure Port-Security - Static and Sticky on FEX"):
            new_config = '''switchport port-security mac-address {mac}
                            switchport port-security mac-address sticky'''.format(mac=leaf1_mac)

            if not config_interface_ps([prim_vtep], fex_vtep_if, log, new_config):
                self.errored('Exception occurred while configuring port security', goto=['common_cleanup'])
        
        log.info("Waiting {}secs for interface to come up".format(config_time))
        time.sleep(config_time)
        display_configs(testscript)
        
        with steps.start("Starting hosts..."):
            p1_handle.Start()
            p2_handle.Start()

        log.info('Waiting {}secs to stop the hosts'.format(traffic_stop_time))
        time.sleep(traffic_stop_time)
    
        stream1 = ixNetwork.Traffic.TrafficItem.find(Name='Access FEX To Standalone')
        stream1.StartStatelessTraffic()
        log.info('Waiting {}secs to start the traffic'.format(traffic_start_time))
        time.sleep(traffic_start_time)
        
        stream1.StopStatelessTraffic()
        log.info('Waiting {}secs to stop the traffic'.format(traffic_stop_time))
        time.sleep(traffic_stop_time)

        with steps.start("Checking mac learning on fex and remote.."):
            if not verify_port_sec_addr_count(prim_vtep, fex_vtep_if, 1, 'STATIC'):
                log.error("STATIC Mac learning failed")
                self.failed("STATIC Mac learning failed")
        
            if not verify_port_sec_addr_count(prim_vtep, fex_vtep_if, 1024, 'STICKY'):
                log.error("Mac learning failed")
                self.failed("Mac learning failed")
            
            if not verify_secure_mac_on_vteps(prim_vtep, '1001', 1025, prim_fex_mac, 'secure'):
                log.error("Mac learning failed on primary")
                self.failed("Mac learning failed on primary")

            if not verify_secure_mac_on_vteps(sec_vtep, '1001', 1025, prim_fex_mac, 'secure'):
                log.error("Mac learning failed on primary")
                self.failed("Mac learning failed on primary")
                
            if not verify_secure_mac_on_vteps(sa_vtep, '1001', 1025, prim_fex_mac):
                log.error("Mac learning failed on standalone")
                self.failed("Mac learning failed on standalone")

        with steps.start("Verify Steady State"):
            if VerifyTraffic("Test_006_FEX", testscript, traffic_item='Access FEX To Standalone'):
                log.info('Verify traffic success')
            else:
                self.failed('Verify traffic failed')

    @aetest.test
    def remove_portsecurity_check_macs(self, testscript, testbed, steps):
        sa_vtep         = testscript.parameters['LEAF-3']
        prim_vtep       = testscript.parameters['LEAF-1']
        sec_vtep        = testscript.parameters['LEAF-2']
        sa_vtep_if      = str(testscript.parameters['intf_LEAF_3_to_IXIA'])
        leaf1_mac       = str(testscript.parameters['PORTSEC_Dict']['fex_static_mac'])
        prim_fex_mac    = str(testscript.parameters['PORTSEC_Dict']['prim_fex_mac'])
        fex_vtep_if     = str(testscript.parameters['intf_LEAF_1_FEX_to_IXIA'])
        vlan            = int(testscript.parameters['LEAF_1_Orphan1_TGEN_dict']['vlan_id'])
        ixNetwork       = testscript.parameters['ixNetwork']
        
        with steps.start("Configure Port-Security - Static and Sticky on Standalone VTEP"):
            if not unconfig_interface_ps([sa_vtep], sa_vtep_if, log):
                self.errored('Exception occurred while configuring port security', goto=['common_cleanup'])

        with steps.start("UnConfigure Port-Security - Static and Sticky on Primary VTEP"):
            new_config = '''no switchport port-security mac-address {mac}
                            no switchport port-security mac-address sticky'''.format(mac=leaf1_mac)

            if not unconfig_interface_ps([prim_vtep], fex_vtep_if, log, new_config, True):
                self.errored('Exception occurred while configuring port security', 
                             goto=['common_cleanup'])
        
        log.info("Waiting {}secs for interface to come up".format(config_time))
        time.sleep(config_time)
        
        with steps.start("Checking non-secure dynamic mac learning on primary/secondary and remote"):
            if not verify_secure_mac_on_vteps(sa_vtep, '1001', 1025, prim_fex_mac, 'dynamic'):
                log.error("Mac learning failed on standalone")
                self.failed("Mac learning failed on local vtep")
            if not verify_secure_mac_on_vteps(prim_vtep, '1001', 1025, prim_fex_mac, 'dynamic'):
                log.error("Mac learning failed on primary")
                self.failed("Mac learning failed on primary")

            if not verify_secure_mac_on_vteps(sec_vtep, '1001', 1025, prim_fex_mac, 'dynamic'):
                log.error("Mac learning failed on secondary")
                self.failed("Mac learning failed on secondary")

        with steps.start("Stopping all hosts..."):
            ixNetwork.StopAllProtocols()

        log.info('Waiting {}secs to stop the hosts'.format(traffic_stop_time))
        time.sleep(traffic_stop_time)
    
        with steps.start('Verify Learned mac address consistency between hardware and software'):
            if verify_mac_cc_between_hardware_software([prim_vtep, sec_vtep, sa_vtep]):
                log.info('MAC CC success')
            else:
                self.failed('MAC CC failed')
        
        with steps.start("Verifying MTS leak.."):
            if verify_mts_leak([prim_vtep, sec_vtep, sa_vtep], log):
                log.info('MTS Leak verification success')
            else:
                self.failed('MTS Leak verification failed')

        with steps.start("Verifying Cores and Log Errors"):
            status = infraVerify.postTestVerification(post_test_process_dict)
            if status['status'] == 0:
                self.failed(reason=status['logs'])
            else:
                self.passed(reason=status['logs'])

############################################################################################################
# MAC aging cases
# =========================================================================================================#
# TC-ID: TC35 - Trunk
# Testcase:
#  - Configure port-security with aging time - min
#  - Wait for 2 min
#  - Check for mac aging absolute
#  - Re-learn the macs through same port and verify the traffic
# =========================================================================================================#
class TC_VXLAN_PS_007_Access(aetest.Testcase):
    @aetest.test
    def test_setup(self, testscript, testbed, steps):
        sa_vtep         = testscript.parameters['LEAF-3']
        prim_vtep       = testscript.parameters['LEAF-1']
        sec_vtep        = testscript.parameters['LEAF-2']
        prim_vtep_if    = str(testscript.parameters['intf_LEAF_1_1_to_IXIA'])
        sa_vtep_if      = str(testscript.parameters['intf_LEAF_3_to_IXIA'])
        fex_vtep_if     = str(testscript.parameters['intf_LEAF_1_FEX_to_IXIA'])
        
        with steps.start("Configure Port-Security on Primary VTEP Orphan"):
            new_config = '''switchport port-security aging time 2
                            switchport port-security aging type absolute
                            '''
            if not config_interface_ps([prim_vtep], prim_vtep_if, log, new_config):
                self.errored('Exception occurred while configuring port security', goto=['common_cleanup'])
        
        with steps.start("Configure Port-Security on Standalone VTEP"):
            new_config = '''switchport port-security aging time 2
                            switchport port-security aging type absolute
                            '''
            if not config_interface_ps([sa_vtep], sa_vtep_if, log, new_config):
                self.errored('Exception occurred while configuring port security', goto=['common_cleanup'])
        
        with steps.start("Configure Port-Security on VPC Primary/Secondary - Static"):
            new_config = '''switchport port-security aging time 2
                            switchport port-security aging type absolute
                            '''
            if not config_interface_ps([prim_vtep, sec_vtep], 'port-channel 11', log, new_config):
                self.errored('Exception occurred while configuring port security', goto=['common_cleanup'])
        
        with steps.start("Configure Port-Security on Leaf-1 FEX - FEX port of VTEP"):
            new_config = '''switchport port-security aging time 2
                            switchport port-security aging type absolute
                            '''
            if not config_interface_ps([prim_vtep], fex_vtep_if, log, new_config):
                self.errored('Exception occurred while configuring port security', goto=['common_cleanup'])

        log.info("Waiting {}secs for interface to come up".format(config_time))
        time.sleep(config_time)
        display_configs(testscript)

    @aetest.test
    def verify_aging_absolute_orphan(self, testscript, testbed, steps):
        sa_vtep         = testscript.parameters['LEAF-3']
        prim_vtep       = testscript.parameters['LEAF-1']
        sec_vtep        = testscript.parameters['LEAF-2']
        prim_vtep_if    = str(testscript.parameters['intf_LEAF_1_1_to_IXIA'])
        sa_vtep_if      = str(testscript.parameters['intf_LEAF_3_to_IXIA'])
        prim_mac        = str(testscript.parameters['PORTSEC_Dict']['prim_orphan_mac'])
        sa_mac          = str(testscript.parameters['PORTSEC_Dict']['sa_mac'])
        ixNetwork       = testscript.parameters['ixNetwork']
        p1_handle       = testscript.parameters['orphan1_handle']
        p2_handle       = testscript.parameters['sa_handle']

        with steps.start("Starting hosts..."):
            p1_handle.Start()
            p2_handle.Start()
        
        log.info('Waiting {}secs to start 1025 hosts'.format(host_start_time))
        time.sleep(host_start_time)
        
        stream1 = ixNetwork.Traffic.TrafficItem.find(Name='Access Orphan To Standalone')
        stream1.StartStatelessTraffic()
        log.info('Waiting {}secs to start the traffic'.format(traffic_start_time))
        time.sleep(traffic_start_time)
        log.info('Stopping traffic')
        stream1.StopStatelessTraffic()
                        
        with steps.start("Checking orphan mac learning on local and remote"):

            if not verify_secure_mac_on_vteps(prim_vtep, '1001', 1025, prim_mac, 'secure'):
                log.error("Mac learning failed on primary")
                self.failed("Mac learning failed on primary")
            if not verify_secure_mac_on_vteps(sec_vtep, '1001', 1025, prim_mac, 'secure'):
                log.error("Mac learning failed on primary")
                self.failed("Mac learning failed on primary")
            if not verify_secure_mac_on_vteps(sa_vtep, '1001', 1025, prim_mac):
                log.error("Mac learning failed on Standalone")
                self.failed("Mac learning failed on Standalone")
    
        with steps.start("Checking standalone mac learning on local and remote"):
            if not verify_secure_mac_on_vteps(sa_vtep, '1002', 1025, sa_mac, 'secure'):
                log.error("Mac learning failed on Standalone")
                self.failed("Mac learning failed on Standalone")
            if not verify_secure_mac_on_vteps(prim_vtep, '1002', 1025, sa_mac):
                log.error("Mac learning failed on primary")
                self.failed("Mac learning failed on primary")
            if not verify_secure_mac_on_vteps(sec_vtep, '1002', 1025, sa_mac):
                log.error("Mac learning failed on primary")
                self.failed("Mac learning failed on primary")

        with steps.start("Stopping all hosts..."):
            ixNetwork.StopAllProtocols()
        log.info('Waiting {}secs to stop the traffic'.format(traffic_stop_time))
        time.sleep(traffic_stop_time)

        log.info('Waiting 180 secs for mac aging')
        time.sleep(180)

        with steps.start("Checking orphan mac flushout on local and remote"):
            if not verify_port_sec_addr_count(prim_vtep, prim_vtep_if, 0, 'DYNAMIC'):
                log.error("Mac learning failed")
                self.failed("Mac learning failed")

            if not verify_secure_mac_on_vteps(prim_vtep, '1001', 0, prim_mac, 'secure'):
                log.error("Mac learning failed on primary")
                self.failed("Mac learning failed on primary")

            if not verify_secure_mac_on_vteps(sec_vtep, '1001', 0, prim_mac, 'secure'):
                log.error("Mac learning failed on primary")
                self.failed("Mac learning failed on primary")
                
            if not verify_secure_mac_on_vteps(sa_vtep, '1001', 0, prim_mac):
                log.error("Mac learning failed on standalone")
                self.failed("Mac learning failed on standalone")

        with steps.start("Checking standalone mac flushout on local and remote"):
            if not verify_port_sec_addr_count(sa_vtep, sa_vtep_if, 0, 'DYNAMIC'):
                log.error("DYNAMIC Mac learning failed")
                self.failed("DYNAMIC Mac learning failed")

            if not verify_secure_mac_on_vteps(sa_vtep, '1002', 0, sa_mac, 'secure'):
                log.error("Mac learning failed on Standalone")
                self.failed("Mac learning failed on Standalone")

            if not verify_secure_mac_on_vteps(prim_vtep, '1002', 0, sa_mac):
                log.error("DYNAMIC Mac learning failed on remote vtep(leaf1)")
                self.failed("DYNAMIC Mac learning failed on remote vtep(leaf1)")

            if not verify_secure_mac_on_vteps(sec_vtep, '1002', 0, sa_mac):
                log.error("DYNAMIC Mac learning failed on remote vtep(leaf2)")
                self.failed("DYNAMIC Mac learning failed on remote vtep(leaf2)")
    
        with steps.start("Starting hosts..."):
            p1_handle.Start()
            p2_handle.Start()

        log.info('Waiting {}secs to start 1025 hosts'.format(host_start_time))
        time.sleep(host_start_time)
        
        log.info('Starting Stateless stream to learn macs')
        stream1 = ixNetwork.Traffic.TrafficItem.find(Name='Access Orphan To Standalone')
        
        stream1.StartStatelessTraffic()
        log.info('Waiting {}secs to start the traffic'.format(traffic_start_time))
        time.sleep(traffic_start_time)
        
        log.info('Stopping traffic')
        stream1.StopStatelessTraffic()
        log.info('Waiting {}secs to stop the traffic'.format(traffic_stop_time))
        time.sleep(traffic_stop_time)

        with steps.start("Checking standalone mac re-learning on local and remote"):
            if not verify_port_sec_addr_count(sa_vtep, sa_vtep_if, 1025, 'DYNAMIC'):
                log.error("DYNAMIC Mac learning failed")
                self.failed("DYNAMIC Mac learning failed")

            if not verify_secure_mac_on_vteps(sa_vtep, '1002', 1025, sa_mac, 'secure'):
                log.error("Mac learning failed on Standalone")
                self.failed("Mac learning failed on Standalone")

            if not verify_secure_mac_on_vteps(prim_vtep, '1002', 1025, sa_mac):
                log.error("DYNAMIC Mac learning failed on remote vtep(leaf1)")
                self.failed("DYNAMIC Mac learning failed on remote vtep(leaf1)")

            if not verify_secure_mac_on_vteps(sec_vtep, '1002', 1025, sa_mac):
                log.error("DYNAMIC Mac learning failed on remote vtep(leaf2)")
                self.failed("DYNAMIC Mac learning failed on remote vtep(leaf2)")
                
        with steps.start("Checking orphan mac re-learning between local and remote"):

            if not verify_secure_mac_on_vteps(prim_vtep, '1001', 1025, prim_mac, 'secure'):
                log.error("Mac learning failed on primary")
                self.failed("Mac learning failed on primary")

            if not verify_secure_mac_on_vteps(sec_vtep, '1001', 1025, prim_mac, 'secure'):
                log.error("Mac learning failed on primary")
                self.failed("Mac learning failed on primary")

            if not verify_secure_mac_on_vteps(sa_vtep, '1001', 1025, prim_mac):
                log.error("Mac learning failed on Standalone")
                self.failed("Mac learning failed on Standalone")
        
        with steps.start("Verify Steady State"):
            if VerifyTraffic("Test_007_Orphan", testscript, traffic_item='Access Orphan To Standalone'):
                log.info('Verify traffic success')
            else:
                self.failed('Verify traffic failed')

    @aetest.test
    def verify_aging_absolute_vpc(self, testscript, testbed, steps):
        sa_vtep         = testscript.parameters['LEAF-3']
        prim_vtep       = testscript.parameters['LEAF-1']
        sec_vtep        = testscript.parameters['LEAF-2']
        prim_vpc_mac    = str(testscript.parameters['PORTSEC_Dict']['prim_vpc_mac'])
        ixNetwork       = testscript.parameters['ixNetwork']
        p1_handle       = testscript.parameters['vpc_handle']
        p2_handle       = testscript.parameters['sa_handle']
        
        with steps.start("Starting hosts.."):
            p1_handle.Start()
            p2_handle.Start()
        
        log.info('Waiting {}secs to start 1025 hosts'.format(host_start_time))
        time.sleep(host_start_time)

        stream1 = ixNetwork.Traffic.TrafficItem.find(Name='Access VPC To Standalone')
        stream1.StartStatelessTraffic()
        log.info('Waiting {}secs to start the traffic'.format(traffic_start_time))
        time.sleep(traffic_start_time)
        
        with steps.start("Checking mac learning between VPC member(local) --> standalone(remote)"):
            if not verify_secure_mac_on_vteps(prim_vtep, '1001', 1025, prim_vpc_mac, 'secure'):
                log.error("Mac learning failed on primary")
                self.failed("Mac learning failed on primary")
            if not verify_secure_mac_on_vteps(sec_vtep, '1001', 1025, prim_vpc_mac, 'secure'):
                log.error("Mac learning failed on primary")
                self.failed("Mac learning failed on primary")
            if not verify_secure_mac_on_vteps(sa_vtep, '1001', 1025, prim_vpc_mac):
                log.error("Mac learning failed on standalone")
                self.failed("Mac learning failed on standalone")
        
        log.info('Stopping traffic')
        stream1.StopStatelessTraffic()
        
        with steps.start("Stopping all hosts..."):
            ixNetwork.StopAllProtocols()

        log.info('Waiting {}secs to stop the hosts'.format(traffic_stop_time))
        time.sleep(traffic_stop_time)
        
        log.info('Waiting 180 secs for mac aging')
        time.sleep(180)
    
        with steps.start("Checking mac flushout betweem VPC member port(local) and standalone(remote)"):
            if not verify_port_sec_addr_count(prim_vtep, 'port-channel 11', 0, 'DYNAMIC'):
                log.error("DYNAMIC Mac learning failed")
                self.failed("DYNAMIC Mac learning failed")
            if not verify_port_sec_addr_count(sec_vtep, 'port-channel 11', 0, 'DYNAMIC'):
                log.error("DYNAMIC Mac learning failed")
                self.failed("DYNAMIC Mac learning failed")

            if not verify_secure_mac_on_vteps(prim_vtep, '1001', 0, prim_vpc_mac, 'secure'):
                log.error("Mac learning failed on primary")
                self.failed("Mac learning failed on primary")
            if not verify_secure_mac_on_vteps(sec_vtep, '1001', 0, prim_vpc_mac, 'secure'):
                log.error("Mac learning failed on primary")
                self.failed("Mac learning failed on primary")
            if not verify_secure_mac_on_vteps(sa_vtep, '1001', 0, prim_vpc_mac):
                log.error("Mac learning failed on standalone")
                self.failed("Mac learning failed on standalone")

        with steps.start("Starting hosts..."):
            p1_handle.Start()
            p2_handle.Start()

        log.info('Waiting {}secs to start 1025 hosts'.format(host_start_time))
        time.sleep(host_start_time)

        log.info('Starting Stateless stream to learn macs')
        stream1 = ixNetwork.Traffic.TrafficItem.find(Name='Access VPC To Standalone')
        stream1.StartStatelessTraffic()
        log.info('Waiting {}secs to start the traffic'.format(traffic_start_time))
        time.sleep(traffic_start_time)

        log.info('Stopping traffic')
        stream1.StopStatelessTraffic()
        log.info('Waiting {}secs to stop the traffic'.format(traffic_stop_time))
        time.sleep(traffic_stop_time)

        with steps.start("Checking mac learning on VPC and remote vtep (leaf3).."):
            if not verify_secure_mac_on_vteps(prim_vtep, '1001', 1025, prim_vpc_mac, 'secure'):
                log.error("Mac learning failed on primary")
                self.failed("Mac learning failed on primary")
            if not verify_secure_mac_on_vteps(sec_vtep, '1001', 1025, prim_vpc_mac, 'secure'):
                log.error("Mac learning failed on primary")
                self.failed("Mac learning failed on primary")
            if not verify_secure_mac_on_vteps(sa_vtep, '1001', 1025, prim_vpc_mac):
                log.error("Mac learning failed on standalone")
                self.failed("Mac learning failed on standalone")

        with steps.start("Verify Steady State"):
            if VerifyTraffic("Test_007_VPC", testscript, traffic_item='Access VPC To Standalone'):
                log.info('Verify traffic success')
            else:
                self.failed('Verify traffic failed')

    @aetest.test
    def verify_aging_absolute_fex(self, testscript, testbed, steps):
        sa_vtep         = testscript.parameters['LEAF-3']
        prim_vtep       = testscript.parameters['LEAF-1']
        sec_vtep        = testscript.parameters['LEAF-2']
        fex_vtep_if     = str(testscript.parameters['intf_LEAF_1_FEX_to_IXIA'])
        prim_fex_mac    = str(testscript.parameters['PORTSEC_Dict']['prim_fex_mac'])
        ixNetwork       = testscript.parameters['ixNetwork']
        p1_handle       = testscript.parameters['fex_handle']
        p2_handle       = testscript.parameters['sa_handle']
        
        with steps.start('Starting hosts'):
            p1_handle.Start()
            p2_handle.Start()

        log.info('Waiting {}secs to start 1025 hosts'.format(host_start_time))
        time.sleep(host_start_time)
    
        stream1 = ixNetwork.Traffic.TrafficItem.find(Name='Access FEX To Standalone')
        stream1.StartStatelessTraffic()
        log.info('Waiting {}secs to start the traffic'.format(traffic_start_time))
        time.sleep(traffic_start_time)
        log.info('Stopping traffic')
        stream1.StopStatelessTraffic()
        
        with steps.start("Checking mac learning on primary-fex(local) --> standalone (remote)"):
            if not verify_secure_mac_on_vteps(prim_vtep, '1001', 1025, prim_fex_mac, 'secure'):
                log.error("Mac learning failed on primary")
                self.failed("Mac learning failed on primary")
            if not verify_secure_mac_on_vteps(sec_vtep, '1001', 1025, prim_fex_mac, 'secure'):
                log.error("Mac learning failed on primary")
                self.failed("Mac learning failed on primary")
            if not verify_secure_mac_on_vteps(sa_vtep, '1001', 1025, prim_fex_mac):
                log.error("Mac learning failed on standalone")
                self.failed("Mac learning failed on standalone")
        
        with steps.start("Stopping all hosts..."):
            ixNetwork.StopAllProtocols()

        log.info('Waiting {}secs to stop the traffic'.format(traffic_stop_time))
        time.sleep(traffic_stop_time)
        
        log.info('Waiting 180 secs for mac aging')
        time.sleep(180)
        
        with steps.start("hecking mac flushout betweem primary-fex(local) --> standalone (remote)"):
            if not verify_port_sec_addr_count(prim_vtep, fex_vtep_if, 0, 'DYNAMIC'):
                log.error("DYNAMIC Mac learning failed")
                self.failed("DYNAMIC Mac learning failed")

            if not verify_secure_mac_on_vteps(prim_vtep, '1001', 0, prim_fex_mac, 'secure'):
                log.error("Mac learning failed on primary")
                self.failed("Mac learning failed on primary")
            if not verify_secure_mac_on_vteps(sec_vtep, '1001', 0, prim_fex_mac, 'secure'):
                log.error("Mac learning failed on primary")
                self.failed("Mac learning failed on primary")
            if not verify_secure_mac_on_vteps(sa_vtep, '1001', 0, prim_fex_mac):
                log.error("Mac learning failed on standalone")
                self.failed("Mac learning failed on standalone")
        
        with steps.start("Starting hosts..."):
            p1_handle.Start()
            p2_handle.Start()

        log.info('Waiting {}secs to start 1025 hosts'.format(host_start_time))
        time.sleep(host_start_time)

        log.info('Starting Stateless stream to learn macs')
        stream1 = ixNetwork.Traffic.TrafficItem.find(Name='Access FEX To Standalone')
        stream1.StartStatelessTraffic()
        log.info('Waiting {}secs to start the traffic'.format(traffic_start_time))
        time.sleep(traffic_start_time)
        
        log.info('Stopping traffic')
        stream1.StopStatelessTraffic()
        log.info('Waiting {}secs to stop the traffic'.format(traffic_stop_time))
        time.sleep(traffic_stop_time)
        
        with steps.start("Checking mac re-learning between primary-fex(local) --> standalone(remote)."):
            if not verify_port_sec_addr_count(prim_vtep, fex_vtep_if, 1025, 'DYNAMIC'):
                log.error("DYNAMIC Mac learning failed")
                self.failed("DYNAMIC Mac learning failed")

            if not verify_secure_mac_on_vteps(prim_vtep, '1001', 1025, prim_fex_mac, 'secure'):
                log.error("Mac learning failed on primary")
                self.failed("Mac learning failed on primary")
            if not verify_secure_mac_on_vteps(sec_vtep, '1001', 1025, prim_fex_mac, 'secure'):
                log.error("Mac learning failed on primary")
                self.failed("Mac learning failed on primary")
            if not verify_secure_mac_on_vteps(sa_vtep, '1001', 1025, prim_fex_mac):
                log.error("Mac learning failed on standalone")
                self.failed("Mac learning failed on standalone")

        with steps.start("Verify Steady State"):
            if VerifyTraffic("Test_007_FEX", testscript, traffic_item='Access FEX To Standalone'):
                log.info('Verify traffic success')
            else:
                self.failed('Verify traffic failed')
        
    @aetest.test
    def test_cleanup(self, testscript, testbed, steps):
        sa_vtep         = testscript.parameters['LEAF-3']
        prim_vtep       = testscript.parameters['LEAF-1']
        sec_vtep        = testscript.parameters['LEAF-2']
        prim_vtep_if    = str(testscript.parameters['intf_LEAF_1_1_to_IXIA'])
        sa_vtep_if      = str(testscript.parameters['intf_LEAF_3_to_IXIA'])
        fex_vtep_if     = str(testscript.parameters['intf_LEAF_1_FEX_to_IXIA'])
        ixNetwork       = testscript.parameters['ixNetwork']
        
        with steps.start("Stopping all hosts..."):
            ixNetwork.StopAllProtocols()

        log.info('Waiting {}secs to stop the hosts'.format(traffic_stop_time))
        time.sleep(traffic_stop_time)

        with steps.start("UnConfigure Port-Security on Primary VTEP Orphan"):
            new_config = '''no switchport port-security aging time 2
                            switchport port-security maximum 1025'''
            if not unconfig_interface_ps([prim_vtep], prim_vtep_if, log, new_config):
                self.errored('Exception occurred while configuring port security', goto=['common_cleanup'])
        
        with steps.start("UnConfigure Port-Security on Standalone VTEP"):
            new_config = '''no switchport port-security aging time 2
                            switchport port-security maximum 1025
                         '''
            if not unconfig_interface_ps([sa_vtep], sa_vtep_if, log, new_config):
                self.errored('Exception occurred while configuring port security', goto=['common_cleanup'])
        
        with steps.start("UnConfigure Port-Security on VPC Primary/Secondary - Static"):
            new_config = '''no switchport port-security aging time 2
                            switchport port-security maximum 1025
                            '''
            if not unconfig_interface_ps([prim_vtep, sec_vtep], 'port-channel 11', log, new_config):
                self.errored('Exception occurred while configuring port security', goto=['common_cleanup'])
        
        with steps.start("UnConfigure Port-Security on Leaf-1 FEX - FEX port of VTEP"):
            new_config = '''no switchport port-security aging time 2
                            switchport port-security maximum 1025
                            '''
            if not unconfig_interface_ps([prim_vtep], fex_vtep_if, log, new_config):
                self.errored('Exception occurred while configuring port security', goto=['common_cleanup'])

        log.info("Waiting {}secs for interface to come up".format(config_time))
        time.sleep(config_time)
        
        with steps.start("Verifying MTS leak.."):
            if verify_mts_leak([prim_vtep, sec_vtep, sa_vtep], log):
                log.info('MTS Leak verification success')
            else:
                self.failed('MTS Leak verification failed')

        with steps.start("Verifying Cores and Log Errors"):
            status = infraVerify.postTestVerification(post_test_process_dict)
            if status['status'] == 0:
                self.failed(reason=status['logs'])
            else:
                self.passed(reason=status['logs'])

###########################################################################################################
# MAC aging cases
# ========================================================================================================#
# TC-ID: TC39 - Trunk
# Testcase:
#  - Configure port-security with aging time - min
#  - Configure port-security aging type as inactivity
#  - Wait for 2 min
#  - Check for mac aging
#  - Re-learn the macs through same port and verify the traffic
# ========================================================================================================#
class TC_VXLAN_PS_008_Access(aetest.Testcase):
    @aetest.test
    def test_setup(self, testscript, testbed, steps):
        sa_vtep         = testscript.parameters['LEAF-3']
        prim_vtep       = testscript.parameters['LEAF-1']
        sec_vtep        = testscript.parameters['LEAF-2']
        prim_vtep_if    = str(testscript.parameters['intf_LEAF_1_1_to_IXIA'])
        sa_vtep_if      = str(testscript.parameters['intf_LEAF_3_to_IXIA'])
        fex_vtep_if     = str(testscript.parameters['intf_LEAF_1_FEX_to_IXIA'])
        
        with steps.start("Configure Port-Security on Primary VTEP Orphan"):
            new_config = '''switchport port-security aging time 2'''
            if not config_interface_ps([prim_vtep], prim_vtep_if, log, new_config):
                self.errored('Exception occurred while configuring port security', goto=['common_cleanup'])
        
        with steps.start("Configure Port-Security on Standalone VTEP"):
            new_config = '''switchport port-security aging time 2'''
            if not config_interface_ps([sa_vtep], sa_vtep_if, log, new_config):
                self.errored('Exception occurred while configuring port security', goto=['common_cleanup'])
        
        with steps.start("Configure Port-Security on VPC Primary/Secondary - Static"):
            new_config = '''switchport port-security aging time 2'''
            if not config_interface_ps([prim_vtep, sec_vtep], 'port-channel 11', log, new_config):
                self.errored('Exception occurred while configuring port security', goto=['common_cleanup'])
        
        with steps.start("Configure Port-Security on Leaf-1 FEX - FEX port of VTEP"):
            new_config = '''switchport port-security aging time 2'''
            if not config_interface_ps([prim_vtep], fex_vtep_if, log, new_config):
                self.errored('Exception occurred while configuring port security', goto=['common_cleanup'])

        log.info("Waiting {}secs for interface to come up".format(config_time))
        time.sleep(config_time)
        display_configs(testscript)

    @aetest.test
    def verify_aging_inactive_orphan(self, testscript, testbed, steps):
        sa_vtep         = testscript.parameters['LEAF-3']
        prim_vtep       = testscript.parameters['LEAF-1']
        sec_vtep        = testscript.parameters['LEAF-2']
        prim_vtep_if    = str(testscript.parameters['intf_LEAF_1_1_to_IXIA'])
        sa_vtep_if      = str(testscript.parameters['intf_LEAF_3_to_IXIA'])
        prim_mac        = str(testscript.parameters['PORTSEC_Dict']['prim_orphan_mac'])
        sa_mac          = str(testscript.parameters['PORTSEC_Dict']['sa_mac'])
        ixNetwork       = testscript.parameters['ixNetwork']
        p1_handle       = testscript.parameters['orphan1_handle']
        p2_handle       = testscript.parameters['sa_handle']
        
        with steps.start("Starting hosts..."):
            p1_handle.Start()
            p2_handle.Start()
        
        log.info('Waiting {}secs to start 1025 hosts'.format(host_start_time))
        time.sleep(host_start_time)

        stream1 = ixNetwork.Traffic.TrafficItem.find(Name='Access Orphan To Standalone')
        stream1.StartStatelessTraffic()
        
        log.info('Waiting {}secs to start the traffic'.format(traffic_start_time))
        time.sleep(traffic_start_time)
        
        log.info('Stopping traffic')
        stream1.StopStatelessTraffic()
        log.info('Waiting {}secs to stop the traffic'.format(traffic_stop_time))
        time.sleep(traffic_stop_time)
        
        with steps.start("Checking mac learning on VPC(local) --> standalone (remote)"):

            if not verify_secure_mac_on_vteps(prim_vtep, '1001', 1025, prim_mac, 'secure'):
                log.error("Mac learning failed on primary")
                self.failed("Mac learning failed on primary")

            if not verify_secure_mac_on_vteps(sec_vtep, '1001', 1025, prim_mac, 'secure'):
                log.error("Mac learning failed on primary")
                self.failed("Mac learning failed on primary")

            if not verify_secure_mac_on_vteps(sa_vtep, '1001', 1025, prim_mac):
                log.error("Mac learning failed on primary")
                self.failed("Mac learning failed on primary")

        with steps.start("Checking mac/arp learning on local vtep (leaf3) and remote vpc peer (leaf1 and leaf2).."):
            if not verify_secure_mac_on_vteps(sa_vtep, '1002', 1025, sa_mac, 'secure'):
                log.error("Mac learning failed on Standalone")
                self.failed("Mac learning failed on Standalone")

            if not verify_secure_mac_on_vteps(prim_vtep, '1002', 1025, sa_mac):
                log.error("Mac learning failed on primary")
                self.failed("Mac learning failed on primary")
            
            if not verify_secure_mac_on_vteps(sec_vtep, '1002', 1025, sa_mac):
                log.error("Mac learning failed on secondary")
                self.failed("Mac learning failed on secondary")

        with steps.start("Stopping all hosts..."):
            ixNetwork.StopAllProtocols()

        log.info('Waiting 210 secs for mac aging')
        time.sleep(210)

        with steps.start("Checking mac flushout betweem primary/secondary(local) --> standalone (remote)"):
            if not verify_port_sec_addr_count(prim_vtep, prim_vtep_if, 0, 'DYNAMIC'):
                log.error("DYNAMIC Mac learning failed")
                self.failed("DYNAMIC Mac learning failed")

            if not verify_secure_mac_on_vteps(prim_vtep, '1001', 0, prim_mac, 'secure'):
                log.error("Mac learning failed on primary")
                self.failed("Mac learning failed on primary")

            if not verify_secure_mac_on_vteps(sec_vtep, '1001', 0, prim_mac, 'secure'):
                log.error("Mac learning failed on primary")
                self.failed("Mac learning failed on primary")
                
            if not verify_secure_mac_on_vteps(sa_vtep, '1001', 0, prim_mac):
                log.error("Mac learning failed on standalone")
                self.failed("Mac learning failed on standalone")

        with steps.start("Checking mac flushout between standalone (local) --> VPC(remote)"):
            if not verify_port_sec_addr_count(sa_vtep, sa_vtep_if, 0, 'DYNAMIC'):
                log.error("DYNAMIC Mac learning failed")
                self.failed("DYNAMIC Mac learning failed")

            if not verify_secure_mac_on_vteps(sa_vtep, '1002', 0, sa_mac, 'secure'):
                log.error("Mac learning failed on Standalone")
                self.failed("Mac learning failed on Standalone")

            if not verify_secure_mac_on_vteps(prim_vtep, '1002', 0, sa_mac):
                log.error("DYNAMIC Mac learning failed on remote vtep(leaf1)")
                self.failed("DYNAMIC Mac learning failed on remote vtep(leaf1)")

            if not verify_secure_mac_on_vteps(sec_vtep, '1002', 0, sa_mac):
                log.error("DYNAMIC Mac learning failed on remote vtep(leaf2)")
                self.failed("DYNAMIC Mac learning failed on remote vtep(leaf2)")
    
        with steps.start("Starting hosts..."):
            p1_handle.Start()
            p2_handle.Start()

        log.info('Waiting {}secs to start 1025 hosts'.format(host_start_time))
        time.sleep(host_start_time)

        log.info('Starting Stateless stream to learn macs')
        stream1 = ixNetwork.Traffic.TrafficItem.find(Name='Access Orphan To Standalone')
        stream1.StartStatelessTraffic()
        log.info('Waiting {}secs to start the traffic'.format(traffic_start_time))
        time.sleep(traffic_start_time)
        
        log.info('Stopping traffic')
        stream1.StopStatelessTraffic()
        log.info('Waiting {}secs to stop the traffic'.format(traffic_stop_time))
        time.sleep(traffic_stop_time)

        with steps.start("Checking mac re-learning between primary/secondary(local) --> standalone(remote)"):
            if not verify_port_sec_addr_count(sa_vtep, sa_vtep_if, 1025, 'DYNAMIC'):
                log.error("DYNAMIC Mac learning failed")
                self.failed("DYNAMIC Mac learning failed")

            if not verify_secure_mac_on_vteps(sa_vtep, '1002', 1025, sa_mac, 'secure'):
                log.error("Mac learning failed on Standalone")
                self.failed("Mac learning failed on Standalone")

            if not verify_secure_mac_on_vteps(prim_vtep, '1002', 1025, sa_mac):
                log.error("DYNAMIC Mac learning failed on remote vtep(leaf1)")
                self.failed("DYNAMIC Mac learning failed on remote vtep(leaf1)")

            if not verify_secure_mac_on_vteps(sec_vtep, '1002', 1025, sa_mac):
                log.error("DYNAMIC Mac learning failed on remote vtep(leaf2)")
                self.failed("DYNAMIC Mac learning failed on remote vtep(leaf2)")
                
        with steps.start("Checking mac re-learning between standalone(local) --> primary/secondary(remote)"):

            if not verify_secure_mac_on_vteps(prim_vtep, '1001', 1025, prim_mac, 'secure'):
                log.error("Mac learning failed on primary")
                self.failed("Mac learning failed on primary")

            if not verify_secure_mac_on_vteps(sec_vtep, '1001', 1025, prim_mac, 'secure'):
                log.error("Mac learning failed on primary")
                self.failed("Mac learning failed on primary")

            if not verify_secure_mac_on_vteps(sa_vtep, '1001', 1025, prim_mac):
                log.error("Mac learning failed on Standalone")
                self.failed("Mac learning failed on Standalone")
        
        with steps.start("Verify Steady State"):
            if VerifyTraffic("Test_008_Orphan", testscript, 
                             traffic_item='Access Orphan To Standalone'):
                log.info('Verify traffic success')
            else:
                self.failed('Verify traffic failed')

    @aetest.test
    def verify_aging_inactive_vpc(self, testscript, testbed, steps):
        sa_vtep         = testscript.parameters['LEAF-3']
        prim_vtep       = testscript.parameters['LEAF-1']
        sec_vtep        = testscript.parameters['LEAF-2']
        prim_vpc_mac    = str(testscript.parameters['PORTSEC_Dict']['prim_vpc_mac'])
        ixNetwork       = testscript.parameters['ixNetwork']
        p1_handle       = testscript.parameters['vpc_handle']
        p2_handle       = testscript.parameters['sa_handle']
        
        with steps.start("Starting hosts.."):
            p1_handle.Start()
            p2_handle.Start()
        
        log.info('Waiting {}secs to start 1025 hosts'.format(host_start_time))
        time.sleep(host_start_time)

        stream1 = ixNetwork.Traffic.TrafficItem.find(Name='Access VPC To Standalone')
        stream1.StartStatelessTraffic()
        log.info('Waiting {}secs to start the traffic'.format(traffic_start_time))
        time.sleep(traffic_start_time)
        
        with steps.start("Checking mac re-learning between VPC member(local) --> standalone(remote)"):
            if not verify_secure_mac_on_vteps(prim_vtep, '1001', 1025, prim_vpc_mac, 'secure'):
                log.error("Mac learning failed on primary")
                self.failed("Mac learning failed on primary")
            if not verify_secure_mac_on_vteps(sec_vtep, '1001', 1025, prim_vpc_mac, 'secure'):
                log.error("Mac learning failed on primary")
                self.failed("Mac learning failed on primary")
            if not verify_secure_mac_on_vteps(sa_vtep, '1001', 1025, prim_vpc_mac):
                log.error("Mac learning failed on standalone")
                self.failed("Mac learning failed on standalone")
        
        log.info('Stopping traffic')
        stream1.StopStatelessTraffic()
        
        with steps.start("Stopping all hosts..."):
            ixNetwork.StopAllProtocols()

        log.info('Waiting 210 secs for mac aging')
        time.sleep(210)
    
        with steps.start("Checking mac flushout betweem VPC member port(local) and standalone(remote)"):
            if not verify_port_sec_addr_count(prim_vtep, 'port-channel 11', 0, 'DYNAMIC'):
                log.error("DYNAMIC Mac learning failed")
                self.failed("DYNAMIC Mac learning failed")
            if not verify_port_sec_addr_count(sec_vtep, 'port-channel 11', 0, 'DYNAMIC'):
                log.error("DYNAMIC Mac learning failed")
                self.failed("DYNAMIC Mac learning failed")

            if not verify_secure_mac_on_vteps(prim_vtep, '1001', 0, prim_vpc_mac, 'secure'):
                log.error("Mac learning failed on primary")
                self.failed("Mac learning failed on primary")
            if not verify_secure_mac_on_vteps(sec_vtep, '1001', 0, prim_vpc_mac, 'secure'):
                log.error("Mac learning failed on primary")
                self.failed("Mac learning failed on primary")
            if not verify_secure_mac_on_vteps(sa_vtep, '1001', 0, prim_vpc_mac):
                log.error("Mac learning failed on standalone")
                self.failed("Mac learning failed on standalone")

        with steps.start("Starting hosts..."):
            p1_handle.Start()
            p2_handle.Start()

        log.info('Waiting {}secs to start 1025 hosts'.format(host_start_time))
        time.sleep(host_start_time)

        log.info('Starting Stateless stream to learn macs')
        stream1 = ixNetwork.Traffic.TrafficItem.find(Name='Access VPC To Standalone')
        stream1.StartStatelessTraffic()
        log.info('Waiting {}secs to start the traffic'.format(traffic_start_time))
        time.sleep(traffic_start_time)
        
        log.info('Stopping traffic')
        stream1.StopStatelessTraffic()
        log.info('Waiting {}secs to stop the traffic'.format(traffic_stop_time))
        time.sleep(traffic_stop_time)

        with steps.start("Verify Steady State"):
            if VerifyTraffic("Test_008_VPC", testscript, traffic_item='Access VPC To Standalone'):
                log.info('Verify traffic success')
            else:
                self.failed('Verify traffic failed')
    
        with steps.start("Checking mac learning on VPC and remote vtep.."):
            if not verify_secure_mac_on_vteps(prim_vtep, '1001', 1025, prim_vpc_mac, 'secure'):
                log.error("Mac learning failed on primary")
                self.failed("Mac learning failed on primary")
            if not verify_secure_mac_on_vteps(sec_vtep, '1001', 1025, prim_vpc_mac, 'secure'):
                log.error("Mac learning failed on primary")
                self.failed("Mac learning failed on primary")
            if not verify_secure_mac_on_vteps(sa_vtep, '1001', 1025, prim_vpc_mac):
                log.error("Mac learning failed on standalone")
                self.failed("Mac learning failed on standalone")

    @aetest.test
    def verify_aging_inactive_fex(self, testscript, testbed, steps):
        sa_vtep         = testscript.parameters['LEAF-3']
        prim_vtep       = testscript.parameters['LEAF-1']
        sec_vtep        = testscript.parameters['LEAF-2']
        fex_vtep_if     = str(testscript.parameters['intf_LEAF_1_FEX_to_IXIA'])
        prim_fex_mac    = str(testscript.parameters['PORTSEC_Dict']['prim_fex_mac'])
        ixNetwork       = testscript.parameters['ixNetwork']
        p1_handle       = testscript.parameters['fex_handle']
        p2_handle       = testscript.parameters['sa_handle']
        
        with steps.start('Starting hosts...'):
            p1_handle.Start()
            p2_handle.Start()
        
        log.info('Waiting {}secs to start 1025 hosts'.format(host_start_time))
        time.sleep(host_start_time)
    
        stream1 = ixNetwork.Traffic.TrafficItem.find(Name='Access FEX To Standalone')
        stream1.StartStatelessTraffic()
        log.info('Waiting {}secs to start the traffic'.format(traffic_start_time))
        time.sleep(traffic_start_time)
        
        log.info('Stopping traffic')
        stream1.StopStatelessTraffic()
        
        with steps.start("Checking mac learning on primary-fex(local) --> standalone (remote)"):
            if not verify_secure_mac_on_vteps(prim_vtep, '1001', 1025, prim_fex_mac, 'secure'):
                log.error("Mac learning failed on primary")
                self.failed("Mac learning failed on primary")
            if not verify_secure_mac_on_vteps(sec_vtep, '1001', 1025, prim_fex_mac, 'secure'):
                log.error("Mac learning failed on primary")
                self.failed("Mac learning failed on primary")
            if not verify_secure_mac_on_vteps(sa_vtep, '1001', 1025, prim_fex_mac):
                log.error("Mac learning failed on standalone")
                self.failed("Mac learning failed on standalone")
        
        with steps.start("Stopping all hosts..."):
            ixNetwork.StopAllProtocols()

        log.info('Waiting {}secs to stop the traffic'.format(traffic_stop_time))
        time.sleep(traffic_stop_time)

        log.info('Waiting 210 secs for mac aging')
        time.sleep(210)
        
        with steps.start("Checking mac flushout betweem primary-fex(local) --> standalone (remote)"):
            if not verify_port_sec_addr_count(prim_vtep, fex_vtep_if, 0, 'DYNAMIC'):
                log.error("DYNAMIC Mac learning failed")
                self.failed("DYNAMIC Mac learning failed")

            if not verify_secure_mac_on_vteps(prim_vtep, '1001', 0, prim_fex_mac, 'secure'):
                log.error("Mac learning failed on primary")
                self.failed("Mac learning failed on primary")
            if not verify_secure_mac_on_vteps(sec_vtep, '1001', 0, prim_fex_mac, 'secure'):
                log.error("Mac learning failed on primary")
                self.failed("Mac learning failed on primary")
            if not verify_secure_mac_on_vteps(sa_vtep, '1001', 0, prim_fex_mac):
                log.error("Mac learning failed on standalone")
                self.failed("Mac learning failed on standalone")
        
        with steps.start("Starting hosts..."):
            p1_handle.Start()
            p2_handle.Start()

        log.info('Waiting {}secs to start 1025 hosts'.format(host_start_time))
        time.sleep(host_start_time)

        log.info('Starting Stateless stream to learn macs')
        stream1 = ixNetwork.Traffic.TrafficItem.find(Name='Access FEX To Standalone')
        stream1.StartStatelessTraffic()
        log.info('Waiting {}secs to start the traffic'.format(traffic_start_time))
        time.sleep(traffic_start_time)
        
        log.info('Stopping traffic')
        stream1.StopStatelessTraffic()
        log.info('Waiting {}secs to stop the traffic'.format(traffic_stop_time))
        time.sleep(traffic_stop_time)
        
        with steps.start("Checking mac re-learning between primary-fex(local) --> standalone(remote)."):
            if not verify_port_sec_addr_count(prim_vtep, fex_vtep_if, 1025, 'DYNAMIC'):
                log.error("DYNAMIC Mac learning failed")
                self.failed("DYNAMIC Mac learning failed")

            if not verify_secure_mac_on_vteps(prim_vtep, '1001', 1025, prim_fex_mac, 'secure'):
                log.error("Mac learning failed on primary")
                self.failed("Mac learning failed on primary")
            if not verify_secure_mac_on_vteps(sec_vtep, '1001', 1025, prim_fex_mac, 'secure'):
                log.error("Mac learning failed on primary")
                self.failed("Mac learning failed on primary")
            if not verify_secure_mac_on_vteps(sa_vtep, '1001', 1025, prim_fex_mac):
                log.error("Mac learning failed on standalone")
                self.failed("Mac learning failed on standalone")
        
        with steps.start("Verify Steady State"):
            if VerifyTraffic("Test_008_FEX", testscript, traffic_item='Access FEX To Standalone'):
                log.info('Verify traffic success')
            else:
                self.failed('Verify traffic failed')

    @aetest.test
    def test_cleanup(self, testscript, testbed, steps):
        sa_vtep         = testscript.parameters['LEAF-3']
        prim_vtep       = testscript.parameters['LEAF-1']
        sec_vtep        = testscript.parameters['LEAF-2']
        prim_vtep_if    = str(testscript.parameters['intf_LEAF_1_1_to_IXIA'])
        sa_vtep_if      = str(testscript.parameters['intf_LEAF_3_to_IXIA'])
        fex_vtep_if     = str(testscript.parameters['intf_LEAF_1_FEX_to_IXIA'])
        ixNetwork       = testscript.parameters['ixNetwork']
        
        with steps.start("Stopping all hosts..."):
            ixNetwork.StopAllProtocols()

        log.info('Waiting {}secs to stop the hosts'.format(traffic_stop_time))
        time.sleep(traffic_stop_time)

        with steps.start("UnConfigure Port-Security on Primary VTEP Orphan"):
            new_config = '''no switchport port-security aging time 2
                            no switchport port-security aging type inactivity
                            switchport port-security maximum 1025'''
            if not unconfig_interface_ps([prim_vtep], prim_vtep_if, log, new_config):
                self.errored('Exception occurred while configuring port security', goto=['common_cleanup'])
        
        with steps.start("UnConfigure Port-Security on Standalone VTEP"):
            new_config = '''no switchport port-security aging time 2
                            no switchport port-security aging type inactivity
                            switchport port-security maximum 1025
                         '''
            if not unconfig_interface_ps([sa_vtep], sa_vtep_if, log, new_config):
                self.errored('Exception occurred while configuring port security', goto=['common_cleanup'])
        
        with steps.start("UnConfigure Port-Security on VPC Primary/Secondary - Static"):
            new_config = '''no switchport port-security aging time 2
                            no switchport port-security aging type inactivity
                            switchport port-security maximum 1025
                            '''
            if not unconfig_interface_ps([prim_vtep, sec_vtep], 'port-channel 11', log, new_config):
                self.errored('Exception occurred while configuring port security', goto=['common_cleanup'])
        
        with steps.start("UnConfigure Port-Security on Leaf-1 FEX - FEX port of VTEP"):
            new_config = '''no switchport port-security aging time 2
                            no switchport port-security aging type inactivity
                            switchport port-security maximum 1025
                            '''
            if not unconfig_interface_ps([prim_vtep], fex_vtep_if, log, new_config):
                self.errored('Exception occurred while configuring port security', goto=['common_cleanup'])

        log.info("Waiting {}secs for interface to come up".format(config_time))
        time.sleep(config_time)
        
        with steps.start("Verifying MTS leak.."):
            if verify_mts_leak([prim_vtep, sec_vtep, sa_vtep], log):
                log.info('MTS Leak verification success')
            else:
                self.failed('MTS Leak verification failed')

        with steps.start("Verifying Cores and Log Errors"):
            status = infraVerify.postTestVerification(post_test_process_dict)
            if status['status'] == 0:
                self.failed(reason=status['logs'])
            else:
                self.passed(reason=status['logs'])

############################################################################################################
# MAC aging cases - inactivity aging + violation mode restict
# =========================================================================================================#
# TC-ID: TC35 - Trunk
# Testcase:
#  - Configure port-security with aging time - min and violation mode restrict
#  - Wait for 2 min
#  - Check for mac aging
#  - Re-learn the macs through same port and verify the traffic
# =========================================================================================================#
class TC_VXLAN_PS_009_Access(aetest.Testcase):
    @aetest.test
    def test_setup(self, testscript, testbed, steps):
        sa_vtep         = testscript.parameters['LEAF-3']
        prim_vtep       = testscript.parameters['LEAF-1']
        sec_vtep        = testscript.parameters['LEAF-2']
        prim_vtep_if    = str(testscript.parameters['intf_LEAF_1_1_to_IXIA'])
        sa_vtep_if      = str(testscript.parameters['intf_LEAF_3_to_IXIA'])
        fex_vtep_if     = str(testscript.parameters['intf_LEAF_1_FEX_to_IXIA'])
        
        with steps.start("Configure Port-Security on Primary VTEP Orphan"):
            new_config = '''switchport port-security aging time 2
                            switchport port-security maximum 1014
                            '''
            if not config_interface_ps([prim_vtep], prim_vtep_if, log, new_config):
                self.errored('Exception occurred while configuring port security', goto=['common_cleanup'])
        
        with steps.start("Configure Port-Security on Standalone VTEP"):
            new_config = '''switchport port-security aging time 2
                            switchport port-security maximum 1014
                            '''
            if not config_interface_ps([sa_vtep], sa_vtep_if, log, new_config):
                self.errored('Exception occurred while configuring port security', goto=['common_cleanup'])
        
        with steps.start("Configure Port-Security on VPC Primary/Secondary - Static"):
            new_config = '''switchport port-security aging time 2
                            switchport port-security maximum 1000
                            '''
            if not config_interface_ps([prim_vtep, sec_vtep], 'port-channel 11', log, new_config):
                self.errored('Exception occurred while configuring port security', goto=['common_cleanup'])
        
        with steps.start("Configure Port-Security on Leaf-1 FEX - FEX port of VTEP"):
            new_config = '''switchport port-security aging time 2
                            switchport port-security maximum 1014
                            '''
            if not config_interface_ps([prim_vtep], fex_vtep_if, log, new_config):
                self.errored('Exception occurred while configuring port security', goto=['common_cleanup'])

        log.info("Waiting {}secs for interface to come up".format(config_time))
        time.sleep(config_time)
        display_configs(testscript)

    @aetest.test
    def verify_aging_inactive_violation_restrict_orphan(self, testscript, testbed, steps):
        sa_vtep         = testscript.parameters['LEAF-3']
        prim_vtep       = testscript.parameters['LEAF-1']
        sec_vtep        = testscript.parameters['LEAF-2']
        prim_vtep_if    = str(testscript.parameters['intf_LEAF_1_1_to_IXIA'])
        sa_vtep_if      = str(testscript.parameters['intf_LEAF_3_to_IXIA'])
        prim_mac        = str(testscript.parameters['PORTSEC_Dict']['prim_orphan_mac'])
        sa_mac          = str(testscript.parameters['PORTSEC_Dict']['sa_mac'])
        ixNetwork       = testscript.parameters['ixNetwork']
        p1_handle       = testscript.parameters['orphan1_handle']
        p2_handle       = testscript.parameters['sa_handle']
        
        with steps.start("Starting hosts..."):
            p1_handle.Start()
            p2_handle.Start()
        
        log.info('Waiting {}secs to start 1025 hosts'.format(host_start_time))
        time.sleep(host_start_time)
        
        stream1 = ixNetwork.Traffic.TrafficItem.find(Name='Access Orphan To Standalone')
        stream1.StartStatelessTraffic()
        log.info('Waiting {}secs to start the traffic'.format(traffic_start_time))
        time.sleep(traffic_start_time)
        log.info('Stopping traffic')
        stream1.StopStatelessTraffic()
        log.info('Waiting {}secs to stop the traffic'.format(traffic_stop_time))
        time.sleep(traffic_stop_time)

        with steps.start("Checking mac learning on primary/secondary --> standalone (remote)"):

            if not verify_secure_mac_on_vteps(prim_vtep, '1001', 1014, prim_mac, 'secure'):
                log.error("Mac learning failed on primary")
                self.failed("Mac learning failed on primary")

            if not verify_secure_mac_on_vteps(sec_vtep, '1001', 1014, prim_mac, 'secure'):
                log.error("Mac learning failed on primary")
                self.failed("Mac learning failed on primary")

        with steps.start("Checking mac/arp learning on local vtep (leaf3) and remote vpc peer (leaf1 and leaf2).."):
            if not verify_secure_mac_on_vteps(sa_vtep, '1002', 1014, sa_mac, 'secure'):
                log.error("Mac learning failed on Standalone")
                self.failed("Mac learning failed on Standalone")

        with steps.start("Stopping all hosts..."):
            ixNetwork.StopAllProtocols()

        log.info('Waiting 240 secs for mac aging')
        time.sleep(240)

        with steps.start("Checking mac flushout on VPC and standalone (remote)"):
            if not verify_port_sec_addr_count(prim_vtep, prim_vtep_if, 0, 'DYNAMIC'):
                log.error("DYNAMIC Mac learning failed")
                self.failed("DYNAMIC Mac learning failed")

            if not verify_secure_mac_on_vteps(prim_vtep, '1001', 0, prim_mac, 'secure'):
                log.error("Mac learning failed on primary")
                self.failed("Mac learning failed on primary")

            if not verify_secure_mac_on_vteps(sec_vtep, '1001', 0, prim_mac, 'secure'):
                log.error("Mac learning failed on primary")
                self.failed("Mac learning failed on primary")
                
            if not verify_secure_mac_on_vteps(sa_vtep, '1001', 0, prim_mac):
                log.error("Mac learning failed on standalone")
                self.failed("Mac learning failed on standalone")

        with steps.start("Checking mac flushout on standalone (local) --> VPC"):
            if not verify_port_sec_addr_count(sa_vtep, sa_vtep_if, 0, 'DYNAMIC'):
                log.error("DYNAMIC Mac learning failed")
                self.failed("DYNAMIC Mac learning failed")

            if not verify_secure_mac_on_vteps(sa_vtep, '1002', 0, sa_mac, 'secure'):
                log.error("Mac learning failed on Standalone")
                self.failed("Mac learning failed on Standalone")

            if not verify_secure_mac_on_vteps(prim_vtep, '1002', 0, sa_mac):
                log.error("DYNAMIC Mac learning failed on remote vtep(leaf1)")
                self.failed("DYNAMIC Mac learning failed on remote vtep(leaf1)")

            if not verify_secure_mac_on_vteps(sec_vtep, '1002', 0, sa_mac):
                log.error("DYNAMIC Mac learning failed on remote vtep(leaf2)")
                self.failed("DYNAMIC Mac learning failed on remote vtep(leaf2)")
    
        with steps.start("Starting hosts..."):
            p1_handle.Start()
            p2_handle.Start()

        log.info('Waiting {}secs to start 1025 hosts'.format(host_start_time))
        time.sleep(host_start_time)
        
        log.info('Starting Stateless stream to learn macs')
        stream1 = ixNetwork.Traffic.TrafficItem.find(Name='Access Orphan To Standalone')
        stream1.StartStatelessTraffic()
        log.info('Waiting {}secs to start the traffic'.format(traffic_start_time))
        time.sleep(traffic_start_time)
        
        log.info('Stopping traffic')
        stream1.StopStatelessTraffic()
        log.info('Waiting {}secs to stop the traffic'.format(traffic_stop_time))
        time.sleep(traffic_stop_time)

        with steps.start("Checking Standalone mac relearning on local and remote"):
            if not verify_port_sec_addr_count(sa_vtep, sa_vtep_if, 1014, 'DYNAMIC'):
                log.error("DYNAMIC Mac learning failed")
                self.failed("DYNAMIC Mac learning failed")

            if not verify_secure_mac_on_vteps(sa_vtep, '1002', 1014, sa_mac, 'secure'):
                log.error("Mac learning failed on Standalone")
                self.failed("Mac learning failed on Standalone")

            if not verify_secure_mac_on_vteps(prim_vtep, '1002', 1024, sa_mac):
                log.error("DYNAMIC Mac learning failed on remote vtep(leaf1)")
                self.failed("DYNAMIC Mac learning failed on remote vtep(leaf1)")

            if not verify_secure_mac_on_vteps(sec_vtep, '1002', 1024, sa_mac):
                log.error("DYNAMIC Mac learning failed on remote vtep(leaf2)")
                self.failed("DYNAMIC Mac learning failed on remote vtep(leaf2)")
                
        with steps.start("Checking orphan mac re-learning on local and remote"):

            if not verify_secure_mac_on_vteps(prim_vtep, '1001', 1014, prim_mac, 'secure'):
                log.error("Mac learning failed on primary")
                self.failed("Mac learning failed on primary")

            if not verify_secure_mac_on_vteps(sec_vtep, '1001', 1014, prim_mac, 'secure'):
                log.error("Mac learning failed on primary")
                self.failed("Mac learning failed on primary")

            if not verify_secure_mac_on_vteps(sa_vtep, '1001', 1024, prim_mac):
                log.error("Mac learning failed on Standalone")
                self.failed("Mac learning failed on Standalone")
        
        with steps.start("Verify Steady State"):
            if VerifyTrafficDrop("Test_009_Orphan", testscript, 
                                 traffic_item='Access Orphan To Standalone'):
                log.info('Verify traffic success')
            else:
                self.failed('Verify traffic failed')

    @aetest.test
    def verify_aging_inactive_violation_restrict_vpc(self, testscript, testbed, steps):
        sa_vtep         = testscript.parameters['LEAF-3']
        prim_vtep       = testscript.parameters['LEAF-1']
        sec_vtep        = testscript.parameters['LEAF-2']
        prim_vpc_mac    = str(testscript.parameters['PORTSEC_Dict']['prim_vpc_mac'])
        ixNetwork       = testscript.parameters['ixNetwork']
        p1_handle       = testscript.parameters['vpc_handle']
        p2_handle       = testscript.parameters['sa_handle']
        
        with steps.start("Starting hosts.."):
            p1_handle.Start()
            p2_handle.Start()
        
        log.info('Waiting {}secs to start 1025 hosts'.format(host_start_time))
        time.sleep(host_start_time)

        stream1 = ixNetwork.Traffic.TrafficItem.find(Name='Access VPC To Standalone')
        stream1.StartStatelessTraffic()
        log.info('Waiting {}secs to start the traffic'.format(traffic_start_time))
        time.sleep(traffic_start_time)
        
        log.info('Stopping traffic')
        stream1.StopStatelessTraffic()

        with steps.start("Checking vpc mac re-learning on local and remote"):
            if not verify_secure_mac_on_vteps(prim_vtep, '1001', 1000, prim_vpc_mac, 'secure'):
                log.error("Mac learning failed on primary")
                self.failed("Mac learning failed on primary")
            if not verify_secure_mac_on_vteps(sec_vtep, '1001', 1000, prim_vpc_mac, 'secure'):
                log.error("Mac learning failed on primary")
                self.failed("Mac learning failed on primary")
            if not verify_secure_mac_on_vteps(sa_vtep, '1001', 1010, prim_vpc_mac):
                log.error("Mac learning failed on standalone")
                self.failed("Mac learning failed on standalone")
        
        with steps.start("Stopping all hosts..."):
            ixNetwork.StopAllProtocols()

        log.info('Waiting {}secs to stop the hosts'.format(traffic_stop_time))
        time.sleep(traffic_stop_time)
        
        log.info('Waiting 240 secs for mac aging')
        time.sleep(240)
    
        with steps.start("Checking vpc mac flushout on local and remote"):
            if not verify_port_sec_addr_count(prim_vtep, 'port-channel 11', 0, 'DYNAMIC'):
                log.error("DYNAMIC Mac learning failed")
                self.failed("DYNAMIC Mac learning failed")
            if not verify_port_sec_addr_count(sec_vtep, 'port-channel 11', 0, 'DYNAMIC'):
                log.error("DYNAMIC Mac learning failed")
                self.failed("DYNAMIC Mac learning failed")

            if not verify_secure_mac_on_vteps(prim_vtep, '1001', 0, prim_vpc_mac, 'secure'):
                log.error("Mac learning failed on primary")
                self.failed("Mac learning failed on primary")
            if not verify_secure_mac_on_vteps(sec_vtep, '1001', 0, prim_vpc_mac, 'secure'):
                log.error("Mac learning failed on primary")
                self.failed("Mac learning failed on primary")
            if not verify_secure_mac_on_vteps(sa_vtep, '1001', 0, prim_vpc_mac):
                log.error("Mac learning failed on standalone")
                self.failed("Mac learning failed on standalone")

        with steps.start("Starting hosts..."):
            p1_handle.Start()
            p2_handle.Start()

        log.info('Waiting {}secs to start 1025 hosts'.format(host_start_time))
        time.sleep(host_start_time)

        log.info('Starting Stateless stream to learn macs')
        stream1 = ixNetwork.Traffic.TrafficItem.find(Name='Access VPC To Standalone')
        stream1.StartStatelessTraffic()
        log.info('Waiting {}secs to start the traffic'.format(traffic_start_time))
        time.sleep(traffic_start_time)
        
        log.info('Stopping traffic')
        stream1.StopStatelessTraffic()
        log.info('Waiting {}secs to stop the traffic'.format(traffic_stop_time))
        time.sleep(traffic_stop_time)

        with steps.start("Checking vpc mac relearning on local and remote"):
            if not verify_secure_mac_on_vteps(prim_vtep, '1001', 1000, prim_vpc_mac, 'secure'):
                log.error("Mac learning failed on primary")
                self.failed("Mac learning failed on primary")
            if not verify_secure_mac_on_vteps(sec_vtep, '1001', 1000, prim_vpc_mac, 'secure'):
                log.error("Mac learning failed on primary")
                self.failed("Mac learning failed on primary")
            if not verify_secure_mac_on_vteps(sa_vtep, '1001', 1010, prim_vpc_mac):
                log.error("Mac learning failed on standalone")
                self.failed("Mac learning failed on standalone")

        with steps.start("Verify Steady State"):
            if VerifyTrafficDrop("Test_009_VPC", testscript, traffic_item='Access VPC To Standalone'):
                log.info('Verify traffic success')
            else:
                self.failed('Verify traffic failed')

    @aetest.test
    def verify_aging_inactive_violation_restrict_fex(self, testscript, testbed, steps):
        sa_vtep         = testscript.parameters['LEAF-3']
        prim_vtep       = testscript.parameters['LEAF-1']
        sec_vtep        = testscript.parameters['LEAF-2']
        fex_vtep_if     = str(testscript.parameters['intf_LEAF_1_FEX_to_IXIA'])
        prim_fex_mac    = str(testscript.parameters['PORTSEC_Dict']['prim_fex_mac'])
        ixNetwork       = testscript.parameters['ixNetwork']
        p1_handle       = testscript.parameters['fex_handle']
        p2_handle       = testscript.parameters['sa_handle']

        with steps.start('Starting hosts'):
            p1_handle.Start()
            p2_handle.Start()

        log.info('Waiting {}secs to start 1025 hosts'.format(host_start_time))
        time.sleep(host_start_time)
    
        stream1 = ixNetwork.Traffic.TrafficItem.find(Name='Access FEX To Standalone')
        stream1.StartStatelessTraffic()
        log.info('Waiting {}secs to start the traffic'.format(traffic_start_time))
        time.sleep(traffic_start_time)
        
        log.info('Stopping traffic')
        stream1.StopStatelessTraffic()
        
        with steps.start("Checking fex mac learning on local and remote"):
            if not verify_secure_mac_on_vteps(prim_vtep, '1001', 1014, prim_fex_mac, 'secure'):
                log.error("Mac learning failed on primary")
                self.failed("Mac learning failed on primary")
            if not verify_secure_mac_on_vteps(sec_vtep, '1001', 1014, prim_fex_mac, 'secure'):
                log.error("Mac learning failed on primary")
                self.failed("Mac learning failed on primary")
            if not verify_secure_mac_on_vteps(sa_vtep, '1001', 1024, prim_fex_mac):
                log.error("Mac learning failed on standalone")
                self.failed("Mac learning failed on standalone")
        
        with steps.start("Stopping all hosts..."):
            ixNetwork.StopAllProtocols()

        log.info('Waiting {}secs to stop the traffic'.format(traffic_stop_time))
        time.sleep(traffic_stop_time)

        log.info('Waiting 240 secs for mac aging')
        time.sleep(240)
        
        with steps.start("Checking fex mac flushout on local and remote"):
            if not verify_port_sec_addr_count(prim_vtep, fex_vtep_if, 0, 'DYNAMIC'):
                log.error("DYNAMIC Mac learning failed")
                self.failed("DYNAMIC Mac learning failed")

            if not verify_secure_mac_on_vteps(prim_vtep, '1001', 0, prim_fex_mac, 'secure'):
                log.error("Mac learning failed on primary")
                self.failed("Mac learning failed on primary")
            if not verify_secure_mac_on_vteps(sec_vtep, '1001', 0, prim_fex_mac, 'secure'):
                log.error("Mac learning failed on primary")
                self.failed("Mac learning failed on primary")
            if not verify_secure_mac_on_vteps(sa_vtep, '1001', 0, prim_fex_mac):
                log.error("Mac learning failed on standalone")
                self.failed("Mac learning failed on standalone")
        
        with steps.start("Starting hosts..."):
            p1_handle.Start()
            p2_handle.Start()

        log.info('Waiting {}secs to start 1025 hosts'.format(host_start_time))
        time.sleep(host_start_time)

        log.info('Starting Stateless stream to learn macs')
        stream1 = ixNetwork.Traffic.TrafficItem.find(Name='Access FEX To Standalone')
        stream1.StartStatelessTraffic()
        log.info('Waiting {}secs to start the traffic'.format(traffic_start_time))
        time.sleep(traffic_start_time)
        
        log.info('Stopping traffic')
        stream1.StopStatelessTraffic()
        log.info('Waiting {}secs to stop the traffic'.format(traffic_stop_time))
        time.sleep(traffic_stop_time)
        
        with steps.start("Checking mac re-learning between primary-fex(local) --> standalone(remote)."):
            if not verify_port_sec_addr_count(prim_vtep, fex_vtep_if, 1014, 'DYNAMIC'):
                log.error("DYNAMIC Mac learning failed")
                self.failed("DYNAMIC Mac learning failed")

            if not verify_secure_mac_on_vteps(prim_vtep, '1001', 1014, prim_fex_mac, 'secure'):
                log.error("Mac learning failed on primary")
                self.failed("Mac learning failed on primary")
            if not verify_secure_mac_on_vteps(sec_vtep, '1001', 1014, prim_fex_mac, 'secure'):
                log.error("Mac learning failed on primary")
                self.failed("Mac learning failed on primary")
            if not verify_secure_mac_on_vteps(sa_vtep, '1001', 1024, prim_fex_mac):
                log.error("Mac learning failed on standalone")
                self.failed("Mac learning failed on standalone")
        
        with steps.start("Verify Steady State"):
            if VerifyTraffic("Test_009_FEX", testscript, traffic_item='Access FEX To Standalone'):
                log.info('Verify traffic success')
            else:
                self.failed('Verify traffic failed')

    @aetest.test
    def test_cleanup(self, testscript, testbed, steps):
        sa_vtep = testscript.parameters['LEAF-3']
        prim_vtep = testscript.parameters['LEAF-1']
        sec_vtep = testscript.parameters['LEAF-2']
        prim_vtep_if = str(testscript.parameters['intf_LEAF_1_1_to_IXIA'])
        sa_vtep_if = str(testscript.parameters['intf_LEAF_3_to_IXIA'])
        fex_vtep_if = str(testscript.parameters['intf_LEAF_1_FEX_to_IXIA'])
        vlan = int(testscript.parameters['LEAF_3_TGEN_dict']['vlan_id'])
        ixNetwork   = testscript.parameters['ixNetwork']
        
        with steps.start("Stopping all hosts..."):
            ixNetwork.StopAllProtocols()

        log.info('Waiting {}secs to stop the hosts'.format(traffic_stop_time))
        time.sleep(traffic_stop_time)

        with steps.start("UnConfigure Port-Security on Primary VTEP Orphan"):
            new_config = '''no switchport port-security aging time 2
                            no switchport port-security aging type inactivity
                            switchport port-security maximum 1025'''
            if not unconfig_interface_ps([prim_vtep], prim_vtep_if, log, new_config):
                self.errored('Exception occurred while configuring port security', goto=['common_cleanup'])
        
        with steps.start("UnConfigure Port-Security on Standalone VTEP"):
            new_config = '''no switchport port-security aging time 2
                            no switchport port-security aging type inactivity
                            switchport port-security maximum 1025
                         '''
            if not unconfig_interface_ps([sa_vtep], sa_vtep_if, log, new_config):
                self.errored('Exception occurred while configuring port security', goto=['common_cleanup'])
        
        with steps.start("UnConfigure Port-Security on VPC Primary/Secondary - Static"):
            new_config = '''no switchport port-security aging time 2
                            no switchport port-security aging type inactivity
                            switchport port-security maximum 1025
                            '''
            if not unconfig_interface_ps([prim_vtep, sec_vtep], 'port-channel 11', log, new_config):
                self.errored('Exception occurred while configuring port security', goto=['common_cleanup'])
        
        with steps.start("UnConfigure Port-Security on Leaf-1 FEX - FEX port of VTEP"):
            new_config = '''no switchport port-security aging time 2
                            no switchport port-security aging type inactivity
                            switchport port-security maximum 1025
                            '''
            if not unconfig_interface_ps([prim_vtep], fex_vtep_if, log, new_config):
                self.errored('Exception occurred while configuring port security', goto=['common_cleanup'])

        log.info("Waiting {}secs for interface to come up".format(config_time))
        time.sleep(config_time)
        
        with steps.start("Verifying MTS leak.."):
            if verify_mts_leak([prim_vtep, sec_vtep, sa_vtep], log):
                log.info('MTS Leak verification success')
            else:
                self.failed('MTS Leak verification failed')

        with steps.start("Verifying Cores and Log Errors"):
            status = infraVerify.postTestVerification(post_test_process_dict)
            if status['status'] == 0:
                self.failed(reason=status['logs'])
            else:
                self.passed(reason=status['logs'])

############################################################################################################
# MAC aging cases - inactivity aging + violation mode protect
# =========================================================================================================#
# TC-ID: TC35 - Trunk
# Testcase:
#  - Configure port-security with aging time - min and violation mode protect
#  - Wait for 2 min
#  - Check for mac aging
#  - Re-learn the macs through same port and verify the traffic
# =========================================================================================================#
class TC_VXLAN_PS_010_Access(aetest.Testcase):
    @aetest.test
    def test_setup(self, testscript, testbed, steps):
        sa_vtep         = testscript.parameters['LEAF-3']
        prim_vtep       = testscript.parameters['LEAF-1']
        sec_vtep        = testscript.parameters['LEAF-2']
        prim_vtep_if    = str(testscript.parameters['intf_LEAF_1_1_to_IXIA'])
        sa_vtep_if      = str(testscript.parameters['intf_LEAF_3_to_IXIA'])
        fex_vtep_if     = str(testscript.parameters['intf_LEAF_1_FEX_to_IXIA'])
        
        with steps.start("Configure Port-Security on Primary VTEP Orphan"):
            new_config = '''switchport port-security aging time 2
                            switchport port-security maximum 1014
                            switchport port-security violation protect
                            '''
            if not config_interface_ps([prim_vtep], prim_vtep_if, log, new_config):
                self.errored('Exception occurred while configuring port security', goto=['common_cleanup'])
        
        with steps.start("Configure Port-Security on Standalone VTEP"):
            new_config = '''switchport port-security aging time 2
                            switchport port-security maximum 1014
                            switchport port-security violation protect
                            '''
            if not config_interface_ps([sa_vtep], sa_vtep_if, log, new_config):
                self.errored('Exception occurred while configuring port security', goto=['common_cleanup'])
        
        with steps.start("Configure Port-Security on VPC Primary/Secondary - Static"):
            new_config = '''switchport port-security aging time 2
                            switchport port-security maximum 1000
                            switchport port-security violation protect
                            '''
            if not config_interface_ps([prim_vtep, sec_vtep], 'port-channel 11', log, new_config):
                self.errored('Exception occurred while configuring port security', goto=['common_cleanup'])
        
        with steps.start("Configure Port-Security on Leaf-1 FEX - FEX port of VTEP"):
            new_config = '''switchport port-security aging time 2
                            switchport port-security maximum 1014
                            switchport port-security violation protect
                            '''
            if not config_interface_ps([prim_vtep], fex_vtep_if, log, new_config):
                self.errored('Exception occurred while configuring port security', goto=['common_cleanup'])

        log.info("Waiting {}secs for interface to come up".format(config_time))
        time.sleep(config_time)
        display_configs(testscript)

    @aetest.test
    def verify_aging_inactive_violation_protect_orphan(self, testscript, testbed, steps):
        sa_vtep         = testscript.parameters['LEAF-3']
        prim_vtep       = testscript.parameters['LEAF-1']
        sec_vtep        = testscript.parameters['LEAF-2']
        prim_vtep_if    = str(testscript.parameters['intf_LEAF_1_1_to_IXIA'])
        sa_vtep_if      = str(testscript.parameters['intf_LEAF_3_to_IXIA'])
        prim_mac        = str(testscript.parameters['PORTSEC_Dict']['prim_orphan_mac'])
        sa_mac          = str(testscript.parameters['PORTSEC_Dict']['sa_mac'])
        ixNetwork       = testscript.parameters['ixNetwork']
        p1_handle       = testscript.parameters['orphan1_handle']
        p2_handle       = testscript.parameters['sa_handle']
        
        with steps.start("Starting hosts..."):
            p1_handle.Start()
            p2_handle.Start()
        
        log.info('Waiting {}secs to start 1025 hosts'.format(host_start_time))
        time.sleep(host_start_time)
        
        stream1 = ixNetwork.Traffic.TrafficItem.find(Name='Access Orphan To Standalone')
        stream1.StartStatelessTraffic()
        log.info('Waiting {}secs to start the traffic'.format(traffic_start_time))
        time.sleep(traffic_start_time)
        
        log.info('Stopping traffic')
        stream1.StopStatelessTraffic()
    
        with steps.start("Checking mac learning on primary/secondary --> standalone (remote)"):

            if not verify_secure_mac_on_vteps(prim_vtep, '1001', 1014, prim_mac, 'secure'):
                log.error("Mac learning failed on primary")
                self.failed("Mac learning failed on primary")

            if not verify_secure_mac_on_vteps(sec_vtep, '1001', 1014, prim_mac, 'secure'):
                log.error("Mac learning failed on primary")
                self.failed("Mac learning failed on primary")

        with steps.start("Checking mac/arp learning on local vtep (leaf3) and remote vpc peer (leaf1 and leaf2).."):
            if not verify_secure_mac_on_vteps(sa_vtep, '1002', 1014, sa_mac, 'secure'):
                log.error("Mac learning failed on Standalone")
                self.failed("Mac learning failed on Standalone")

        with steps.start("Stopping all hosts..."):
            ixNetwork.StopAllProtocols()

        log.info('Waiting {}secs to stop the traffic'.format(traffic_stop_time))
        time.sleep(traffic_stop_time)

        log.info('Waiting 240 secs for mac aging')
        time.sleep(240)

        with steps.start("Checking mac flushout on VPC and standalone (remote)"):
            if not verify_port_sec_addr_count(prim_vtep, prim_vtep_if, 0, 'DYNAMIC'):
                log.error("DYNAMIC Mac learning failed")
                self.failed("DYNAMIC Mac learning failed")

            if not verify_secure_mac_on_vteps(prim_vtep, '1001', 0, prim_mac, 'secure'):
                log.error("Mac learning failed on primary")
                self.failed("Mac learning failed on primary")

            if not verify_secure_mac_on_vteps(sec_vtep, '1001', 0, prim_mac, 'secure'):
                log.error("Mac learning failed on primary")
                self.failed("Mac learning failed on primary")
                
            if not verify_secure_mac_on_vteps(sa_vtep, '1001', 0, prim_mac):
                log.error("Mac learning failed on standalone")
                self.failed("Mac learning failed on standalone")

        with steps.start("Checking mac flushout on standalone (local) --> VPC"):
            if not verify_port_sec_addr_count(sa_vtep, sa_vtep_if, 0, 'DYNAMIC'):
                log.error("DYNAMIC Mac learning failed")
                self.failed("DYNAMIC Mac learning failed")

            if not verify_secure_mac_on_vteps(sa_vtep, '1002', 0, sa_mac, 'secure'):
                log.error("Mac learning failed on Standalone")
                self.failed("Mac learning failed on Standalone")

            if not verify_secure_mac_on_vteps(prim_vtep, '1002', 0, sa_mac):
                log.error("DYNAMIC Mac learning failed on remote vtep(leaf1)")
                self.failed("DYNAMIC Mac learning failed on remote vtep(leaf1)")

            if not verify_secure_mac_on_vteps(sec_vtep, '1002', 0, sa_mac):
                log.error("DYNAMIC Mac learning failed on remote vtep(leaf2)")
                self.failed("DYNAMIC Mac learning failed on remote vtep(leaf2)")
    
        with steps.start("Starting hosts..."):
            p1_handle.Start()
            p2_handle.Start()

        log.info('Waiting {}secs to start 1025 hosts'.format(host_start_time))
        time.sleep(host_start_time)
        
        log.info('Starting Stateless stream to learn macs')
        stream1 = ixNetwork.Traffic.TrafficItem.find(Name='Access Orphan To Standalone')
        stream1.StartStatelessTraffic()
        log.info('Waiting {}secs to start the traffic'.format(traffic_start_time))
        time.sleep(traffic_start_time)
        
        log.info('Stopping traffic')
        stream1.StopStatelessTraffic()
        log.info('Waiting {}secs to stop the traffic'.format(traffic_stop_time))
        time.sleep(traffic_stop_time)

        with steps.start("Checking Standalone mac relearning on local and remote"):
            if not verify_port_sec_addr_count(sa_vtep, sa_vtep_if, 1014, 'DYNAMIC'):
                log.error("DYNAMIC Mac learning failed")
                self.failed("DYNAMIC Mac learning failed")

            if not verify_secure_mac_on_vteps(sa_vtep, '1002', 1014, sa_mac, 'secure'):
                log.error("Mac learning failed on Standalone")
                self.failed("Mac learning failed on Standalone")

            if not verify_secure_mac_on_vteps(prim_vtep, '1002', 1015, sa_mac):
                log.error("DYNAMIC Mac learning failed on remote vtep(leaf1)")
                self.failed("DYNAMIC Mac learning failed on remote vtep(leaf1)")

            if not verify_secure_mac_on_vteps(sec_vtep, '1002', 1015, sa_mac):
                log.error("DYNAMIC Mac learning failed on remote vtep(leaf2)")
                self.failed("DYNAMIC Mac learning failed on remote vtep(leaf2)")
                
        with steps.start("Checking orphan mac re-learning on local and remote"):

            if not verify_secure_mac_on_vteps(prim_vtep, '1001', 1014, prim_mac, 'secure'):
                log.error("Mac learning failed on primary")
                self.failed("Mac learning failed on primary")

            if not verify_secure_mac_on_vteps(sec_vtep, '1001', 1014, prim_mac, 'secure'):
                log.error("Mac learning failed on primary")
                self.failed("Mac learning failed on primary")

            if not verify_secure_mac_on_vteps(sa_vtep, '1001', 1015, prim_mac):
                log.error("Mac learning failed on Standalone")
                self.failed("Mac learning failed on Standalone")
        
        with steps.start("Verify Steady State"):
            if VerifyTrafficDrop("Test_010_Orphan", testscript, 
                                 traffic_item='Access Orphan To Standalone'):
                log.info('Verify traffic success')
            else:
                self.failed('Verify traffic failed')

    @aetest.test
    def verify_aging_inactive_violation_protect_vpc(self, testscript, testbed, steps):
        sa_vtep         = testscript.parameters['LEAF-3']
        prim_vtep       = testscript.parameters['LEAF-1']
        sec_vtep        = testscript.parameters['LEAF-2']
        prim_vpc_mac    = str(testscript.parameters['PORTSEC_Dict']['prim_vpc_mac'])
        ixNetwork       = testscript.parameters['ixNetwork']
        p1_handle       = testscript.parameters['vpc_handle']
        p2_handle       = testscript.parameters['sa_handle']
        
        with steps.start("Starting hosts.."):
            p1_handle.Start()
            p2_handle.Start()
        
        log.info('Waiting {}secs to start 1025 hosts'.format(host_start_time))
        time.sleep(host_start_time)

        stream1 = ixNetwork.Traffic.TrafficItem.find(Name='Access VPC To Standalone')
        stream1.StartStatelessTraffic()
        log.info('Waiting {}secs to start the traffic'.format(traffic_start_time))
        time.sleep(traffic_start_time)
        
        log.info('Stopping traffic')
        stream1.StopStatelessTraffic()
        
        with steps.start("Checking vpc mac re-learning on local and remote"):
            if not verify_secure_mac_on_vteps(prim_vtep, '1001', 1000, prim_vpc_mac, 'secure'):
                log.error("Mac learning failed on primary")
                self.failed("Mac learning failed on primary")
            if not verify_secure_mac_on_vteps(sec_vtep, '1001', 1000, prim_vpc_mac, 'secure'):
                log.error("Mac learning failed on primary")
                self.failed("Mac learning failed on primary")
            if not verify_secure_mac_on_vteps(sa_vtep, '1001', 1001, prim_vpc_mac):
                log.error("Mac learning failed on standalone")
                self.failed("Mac learning failed on standalone")
        
        with steps.start("Stopping all hosts..."):
            ixNetwork.StopAllProtocols()

        log.info('Waiting {}secs to stop the hosts'.format(traffic_stop_time))
        time.sleep(traffic_stop_time)
        
        log.info('Waiting 240 secs for mac aging')
        time.sleep(240)
    
        with steps.start("Checking vpc mac flushout on local and remote"):
            if not verify_port_sec_addr_count(prim_vtep, 'port-channel 11', 0, 'DYNAMIC'):
                log.error("DYNAMIC Mac learning failed")
                self.failed("DYNAMIC Mac learning failed")
            if not verify_port_sec_addr_count(sec_vtep, 'port-channel 11', 0, 'DYNAMIC'):
                log.error("DYNAMIC Mac learning failed")
                self.failed("DYNAMIC Mac learning failed")

            if not verify_secure_mac_on_vteps(prim_vtep, '1001', 0, prim_vpc_mac, 'secure'):
                log.error("Mac learning failed on primary")
                self.failed("Mac learning failed on primary")
            if not verify_secure_mac_on_vteps(sec_vtep, '1001', 0, prim_vpc_mac, 'secure'):
                log.error("Mac learning failed on primary")
                self.failed("Mac learning failed on primary")
            if not verify_secure_mac_on_vteps(sa_vtep, '1001', 0, prim_vpc_mac):
                log.error("Mac learning failed on standalone")
                self.failed("Mac learning failed on standalone")

        with steps.start("Starting hosts..."):
            p1_handle.Start()
            p2_handle.Start()

        log.info('Waiting {}secs to start 1025 hosts'.format(host_start_time))
        time.sleep(host_start_time)

        log.info('Starting Stateless stream to learn macs')
        stream1 = ixNetwork.Traffic.TrafficItem.find(Name='Access VPC To Standalone')
        stream1.StartStatelessTraffic()
        log.info('Waiting {}secs to start the traffic'.format(traffic_start_time))
        time.sleep(traffic_start_time)
        
        log.info('Stopping traffic')
        stream1.StopStatelessTraffic()
        log.info('Waiting {}secs to stop the traffic'.format(traffic_stop_time))
        time.sleep(traffic_stop_time)

        with steps.start("Checking vpc mac relearning on local and remote"):
            if not verify_secure_mac_on_vteps(prim_vtep, '1001', 1000, prim_vpc_mac, 'secure'):
                log.error("Mac learning failed on primary")
                self.failed("Mac learning failed on primary")
            if not verify_secure_mac_on_vteps(sec_vtep, '1001', 1000, prim_vpc_mac, 'secure'):
                log.error("Mac learning failed on primary")
                self.failed("Mac learning failed on primary")
            if not verify_secure_mac_on_vteps(sa_vtep, '1001', 1001, prim_vpc_mac):
                log.error("Mac learning failed on standalone")
                self.failed("Mac learning failed on standalone")

        with steps.start("Verify Steady State"):
            if VerifyTrafficDrop("Test_010_VPC", testscript, traffic_item='Access VPC To Standalone'):
                log.info('Verify traffic success')
            else:
                self.failed('Verify traffic failed')

    @aetest.test
    def verify_aging_inactive_violation_protect_fex(self, testscript, testbed, steps):
        sa_vtep         = testscript.parameters['LEAF-3']
        prim_vtep       = testscript.parameters['LEAF-1']
        sec_vtep        = testscript.parameters['LEAF-2']
        fex_vtep_if     = str(testscript.parameters['intf_LEAF_1_FEX_to_IXIA'])
        prim_fex_mac    = str(testscript.parameters['PORTSEC_Dict']['prim_fex_mac'])
        ixNetwork       = testscript.parameters['ixNetwork']
        p1_handle       = testscript.parameters['fex_handle']
        p2_handle       = testscript.parameters['sa_handle']

        with steps.start('Starting hosts'):
            p1_handle.Start()
            p2_handle.Start()

        log.info('Waiting {}secs to start 1025 hosts'.format(host_start_time))
        time.sleep(host_start_time)
    
        stream1 = ixNetwork.Traffic.TrafficItem.find(Name='Access FEX To Standalone')
        stream1.StartStatelessTraffic()
        log.info('Waiting {}secs to start the traffic'.format(traffic_start_time))
        time.sleep(traffic_start_time)
        
        log.info('Stopping traffic')
        stream1.StopStatelessTraffic()
        
        with steps.start("Checking fex mac learning on local and remote"):
            if not verify_secure_mac_on_vteps(prim_vtep, '1001', 1014, prim_fex_mac, 'secure'):
                log.error("Mac learning failed on primary")
                self.failed("Mac learning failed on primary")
            if not verify_secure_mac_on_vteps(sec_vtep, '1001', 1014, prim_fex_mac, 'secure'):
                log.error("Mac learning failed on primary")
                self.failed("Mac learning failed on primary")
            if not verify_secure_mac_on_vteps(sa_vtep, '1001', 1015, prim_fex_mac):
                log.error("Mac learning failed on standalone")
                self.failed("Mac learning failed on standalone")
        
        with steps.start("Stopping all hosts..."):
            ixNetwork.StopAllProtocols()
        log.info('Waiting {}secs to stop the traffic'.format(traffic_stop_time))
        time.sleep(traffic_stop_time)
    
        log.info('Waiting 240 secs for mac aging')
        time.sleep(240)
        
        with steps.start("Checking fex mac flushout on local and remote"):
            if not verify_port_sec_addr_count(prim_vtep, fex_vtep_if, 0, 'DYNAMIC'):
                log.error("DYNAMIC Mac learning failed")
                self.failed("DYNAMIC Mac learning failed")

            if not verify_secure_mac_on_vteps(prim_vtep, '1001', 0, prim_fex_mac, 'secure'):
                log.error("Mac learning failed on primary")
                self.failed("Mac learning failed on primary")
            if not verify_secure_mac_on_vteps(sec_vtep, '1001', 0, prim_fex_mac, 'secure'):
                log.error("Mac learning failed on primary")
                self.failed("Mac learning failed on primary")
            if not verify_secure_mac_on_vteps(sa_vtep, '1001', 0, prim_fex_mac):
                log.error("Mac learning failed on standalone")
                self.failed("Mac learning failed on standalone")
        
        with steps.start("Starting hosts..."):
            p1_handle.Start()
            p2_handle.Start()

        log.info('Waiting {}secs to start 1025 hosts'.format(host_start_time))
        time.sleep(host_start_time)

        log.info('Starting Stateless stream to learn macs')
        stream1 = ixNetwork.Traffic.TrafficItem.find(Name='Access FEX To Standalone')
        stream1.StartStatelessTraffic()
        log.info('Waiting {}secs to start the traffic'.format(traffic_start_time))
        time.sleep(traffic_start_time)
        
        log.info('Stopping traffic')
        stream1.StopStatelessTraffic()
        log.info('Waiting {}secs to stop the traffic'.format(traffic_stop_time))
        time.sleep(traffic_stop_time)
        
        with steps.start("Checking mac re-learning between primary-fex(local) --> standalone(remote)."):
            if not verify_port_sec_addr_count(prim_vtep, fex_vtep_if, 1014, 'DYNAMIC'):
                log.error("DYNAMIC Mac learning failed")
                self.failed("DYNAMIC Mac learning failed")

            if not verify_secure_mac_on_vteps(prim_vtep, '1001', 1014, prim_fex_mac, 'secure'):
                log.error("Mac learning failed on primary")
                self.failed("Mac learning failed on primary")
            if not verify_secure_mac_on_vteps(sec_vtep, '1001', 1014, prim_fex_mac, 'secure'):
                log.error("Mac learning failed on primary")
                self.failed("Mac learning failed on primary")
            if not verify_secure_mac_on_vteps(sa_vtep, '1001', 1015, prim_fex_mac):
                log.error("Mac learning failed on standalone")
                self.failed("Mac learning failed on standalone")

        with steps.start("Verify Steady State"):
            if VerifyTraffic("Test_010_FEX", testscript, traffic_item='Access FEX To Standalone'):
                log.info('Verify traffic success')
            else:
                self.failed('Verify traffic failed')

    @aetest.test
    def test_cleanup(self, testscript, testbed, steps):
        sa_vtep         = testscript.parameters['LEAF-3']
        prim_vtep       = testscript.parameters['LEAF-1']
        sec_vtep        = testscript.parameters['LEAF-2']
        prim_vtep_if    = str(testscript.parameters['intf_LEAF_1_1_to_IXIA'])
        sa_vtep_if      = str(testscript.parameters['intf_LEAF_3_to_IXIA'])
        fex_vtep_if     = str(testscript.parameters['intf_LEAF_1_FEX_to_IXIA'])
        ixNetwork       = testscript.parameters['ixNetwork']
        
        with steps.start("Stopping all hosts..."):
            ixNetwork.StopAllProtocols()

        log.info('Waiting {}secs to stop the hosts'.format(traffic_stop_time))
        time.sleep(traffic_stop_time)

        with steps.start("UnConfigure Port-Security on Primary VTEP Orphan"):
            new_config = '''no switchport port-security aging time 2
                            no switchport port-security aging type inactivity
                            no switchport port-security violation protect
                            switchport port-security maximum 1025'''
            if not unconfig_interface_ps([prim_vtep], prim_vtep_if, log, new_config):
                self.errored('Exception occurred while configuring port security', goto=['common_cleanup'])
        
        with steps.start("UnConfigure Port-Security on Standalone VTEP"):
            new_config = '''no switchport port-security aging time 2
                            no switchport port-security aging type inactivity
                            no switchport port-security violation protect
                            switchport port-security maximum 1025
                         '''
            if not unconfig_interface_ps([sa_vtep], sa_vtep_if, log, new_config):
                self.errored('Exception occurred while configuring port security', goto=['common_cleanup'])
        
        with steps.start("UnConfigure Port-Security on VPC Primary/Secondary - Static"):
            new_config = '''no switchport port-security aging time 2
                            no switchport port-security aging type inactivity
                            no switchport port-security violation protect
                            switchport port-security maximum 1025
                            '''
            if not unconfig_interface_ps([prim_vtep, sec_vtep], 'port-channel 11', log, new_config):
                self.errored('Exception occurred while configuring port security', goto=['common_cleanup'])
        
        with steps.start("UnConfigure Port-Security on Leaf-1 FEX - FEX port of VTEP"):
            new_config = '''no switchport port-security aging time 2
                            no switchport port-security aging type inactivity
                            no switchport port-security violation protect
                            switchport port-security maximum 1025
                            '''
            if not unconfig_interface_ps([prim_vtep], fex_vtep_if, log, new_config):
                self.errored('Exception occurred while configuring port security', goto=['common_cleanup'])

        log.info("Waiting {}secs for interface to come up".format(config_time))
        time.sleep(config_time)
        
        with steps.start("Verifying MTS leak.."):
            if verify_mts_leak([prim_vtep, sec_vtep, sa_vtep], log):
                log.info('MTS Leak verification success')
            else:
                self.failed('MTS Leak verification failed')

        with steps.start("Verifying Cores and Log Errors"):
            status = infraVerify.postTestVerification(post_test_process_dict)
            if status['status'] == 0:
                self.failed(reason=status['logs'])
            else:
                self.passed(reason=status['logs'])

###########################################################################################################
# MAC Violation cases - shudown mode
# ========================================================================================================#
# TC-ID: TC19
# Testcase:
#   - Configure interface port-security maximum address as 1024, 
#   - Try to learn 1025 macs
#   - When switch tries to learn 1025th Mac and port becomes shut with error disable
# ========================================================================================================#
class TC_VXLAN_PS_011_Access(aetest.Testcase):
    @aetest.test
    def test_setup(self, testscript, testbed, steps):
        sa_vtep         = testscript.parameters['LEAF-3']
        prim_vtep       = testscript.parameters['LEAF-1']
        sec_vtep        = testscript.parameters['LEAF-2']
        prim_vtep_if    = str(testscript.parameters['intf_LEAF_1_1_to_IXIA'])
        sa_vtep_if      = str(testscript.parameters['intf_LEAF_3_to_IXIA'])
        fex_vtep_if     = str(testscript.parameters['intf_LEAF_1_FEX_to_IXIA'])
        
        new_config = '''switchport port-security maximum 1024
                        no switchport port-security violation restrict'''
        
        with steps.start("Configure Port-Security on Primary VTEP Orphan"):
            if not config_interface_ps([prim_vtep], prim_vtep_if, log, new_config):
                self.errored('Exception occurred while configuring port security', goto=['common_cleanup'])
        
        with steps.start("Configure Port-Security on Standalone VTEP"):
            if not config_interface_ps([sa_vtep], sa_vtep_if, log, new_config):
                self.errored('Exception occurred while configuring port security', goto=['common_cleanup'])

        with steps.start("Configure Port-Security on VPC Primary/Secondary - Static"):
            if not config_interface_ps([prim_vtep, sec_vtep], 'port-channel 11', log, new_config):
                self.errored('Exception occurred while configuring port security', goto=['common_cleanup'])
        
        with steps.start("Configure Port-Security on Leaf-1 FEX - FEX port of VTEP"):
            if not config_interface_ps([prim_vtep], fex_vtep_if, log, new_config):
                self.errored('Exception occurred while configuring port security', goto=['common_cleanup'])
        
        log.info("Waiting {}secs for interface to come up".format(config_time))
        time.sleep(config_time)
        display_configs(testscript)

    @aetest.test
    def verify_violation_shutdown_orphan(self, testscript, testbed, steps):
        sa_vtep         = testscript.parameters['LEAF-3']
        prim_vtep       = testscript.parameters['LEAF-1']
        sec_vtep        = testscript.parameters['LEAF-2']
        prim_vtep_if    = str(testscript.parameters['intf_LEAF_1_1_to_IXIA'])
        sa_vtep_if      = str(testscript.parameters['intf_LEAF_3_to_IXIA'])
        prim_mac        = str(testscript.parameters['PORTSEC_Dict']['prim_orphan_mac'])
        sa_mac          = str(testscript.parameters['PORTSEC_Dict']['sa_mac'])
        ixNetwork       = testscript.parameters['ixNetwork']
        p1_handle       = testscript.parameters['orphan1_handle']
        p2_handle       = testscript.parameters['sa_handle']
        
        with steps.start("Starting hosts..."):
            p1_handle.Start()
            p2_handle.Start()
        
        log.info("Waiting {}secs for interface to come up".format(config_time))
        time.sleep(config_time)
  
        stream1 = ixNetwork.Traffic.TrafficItem.find(Name='Access Orphan To Standalone')
        stream1.StartStatelessTraffic()
        log.info('Waiting {}secs to start the traffic'.format(traffic_start_time))
        time.sleep(traffic_start_time)
        
        stream1.StopStatelessTraffic()
        log.info('Waiting {}secs to stop the traffic'.format(traffic_stop_time))
        time.sleep(traffic_stop_time)

        with steps.start('Verfying the securty volation'):
            
            retval = prim_vtep.execute('show interface {intf} brief | inc Sec-violation | count'.format(intf=prim_vtep_if))
            retval1 = sa_vtep.execute('show interface {intf} brief | inc Sec-violation | count'.format(intf=sa_vtep_if))
            if int(retval) == 0 or int(retval1) == 0:
                log.error('Security Violation valdation failed')
                self.failed("Security Violation valdation failed")
        
        with steps.start("Checking mac/arp learning on local vtep (leaf1 orphan) and remote vtep (leaf3).."):
            if not verify_port_sec_addr_count(prim_vtep, prim_vtep_if, 0, 'DYNAMIC'):
                log.error("DYNAMIC Mac learning failed")
                self.failed("DYNAMIC Mac learning failed")

            if not verify_secure_mac_on_vteps(prim_vtep, '1001', 0, prim_mac, 'secure'):
                log.error("Mac learning failed on primary")
                self.failed("Mac learning failed on primary")

            if not verify_secure_mac_on_vteps(sec_vtep, '1001', 0, prim_mac, 'secure'):
                log.error("Mac learning failed on primary")
                self.failed("Mac learning failed on primary")
                
            if not verify_secure_mac_on_vteps(sa_vtep, '1001', 0, prim_mac):
                log.error("Mac learning failed on standalone")
                self.failed("Mac learning failed on standalone")

        with steps.start("Checking mac/arp learning on local vtep (leaf3) and remote vpc peer (leaf1 and leaf2).."):
            if not verify_port_sec_addr_count(sa_vtep, sa_vtep_if, 0, 'DYNAMIC'):
                log.error("DYNAMIC Mac learning failed")
                self.failed("DYNAMIC Mac learning failed")

            if not verify_secure_mac_on_vteps(sa_vtep, '1002', 0, sa_mac, 'secure'):
                log.error("Mac learning failed on Standalone")
                self.failed("Mac learning failed on Standalone")

            if not verify_secure_mac_on_vteps(prim_vtep, '1002', 0, sa_mac):
                log.error("DYNAMIC Mac learning failed on remote vtep(leaf1)")
                self.failed("DYNAMIC Mac learning failed on remote vtep(leaf1)")

            if not verify_secure_mac_on_vteps(sec_vtep, '1002', 0, sa_mac):
                log.error("DYNAMIC Mac learning failed on remote vtep(leaf2)")
                self.failed("DYNAMIC Mac learning failed on remote vtep(leaf2)")

    @aetest.test
    def verify_violation_shutdown_vpc(self, testscript, testbed, steps):
        sa_vtep         = testscript.parameters['LEAF-3']
        prim_vtep       = testscript.parameters['LEAF-1']
        sec_vtep        = testscript.parameters['LEAF-2']
        prim_vpc_mac    = str(testscript.parameters['PORTSEC_Dict']['prim_vpc_mac'])
        ixNetwork       = testscript.parameters['ixNetwork']
        p1_handle       = testscript.parameters['vpc_handle']
        p2_handle       = testscript.parameters['sa_handle']
        
        with steps.start("Starting hosts.."):
            p1_handle.Start()
            p2_handle.Start()

        log.info('Waiting {}secs to start hosts'.format(host_start_time))
        time.sleep(host_start_time)
        
        stream1 = ixNetwork.Traffic.TrafficItem.find(Name='Access VPC To Standalone')
        stream1.StartStatelessTraffic()
        log.info('Waiting {}secs to start the traffic'.format(traffic_start_time))
        time.sleep(traffic_start_time)
        
        stream1.StopStatelessTraffic()
        log.info('Waiting {}secs to stop the traffic'.format(traffic_stop_time))
        time.sleep(traffic_stop_time)

        with steps.start('Verfying the securty volation'):
            retval = prim_vtep.execute('show interface port-channel 11 brief | inc Sec-violation | count')
            retval1 = sec_vtep.execute('show interface port-channel 11 brief | inc Sec-violation | count')
            if int(retval) == 0 or int(retval1) == 0:
                log.error('Security Violation valdation failed')
                self.failed("Security Violation valdation failed")
        
        with steps.start("Checking mac/arp learning on local vtep (leaf1/leaf2 member port) and remote vtep (leaf3).."):
            if not verify_port_sec_addr_count(prim_vtep, 'port-channel 11', 0, 'DYNAMIC'):
                log.error("DYNAMIC Mac learning failed")
                self.failed("DYNAMIC Mac learning failed")
            if not verify_port_sec_addr_count(sec_vtep, 'port-channel 11', 0, 'DYNAMIC'):
                log.error("DYNAMIC Mac learning failed")
                self.failed("DYNAMIC Mac learning failed")

            if not verify_secure_mac_on_vteps(prim_vtep, '1001', 0, prim_vpc_mac, 'secure'):
                log.error("Mac learning failed on primary")
                self.failed("Mac learning failed on primary")
            if not verify_secure_mac_on_vteps(sec_vtep, '1001', 0, prim_vpc_mac, 'secure'):
                log.error("Mac learning failed on primary")
                self.failed("Mac learning failed on primary")
            if not verify_secure_mac_on_vteps(sa_vtep, '1001', 0, prim_vpc_mac):
                log.error("Mac learning failed on standalone")
                self.failed("Mac learning failed on standalone")

    @aetest.test
    def verify_violation_shutdown_fex(self, testscript, testbed, steps):
        sa_vtep         = testscript.parameters['LEAF-3']
        prim_vtep       = testscript.parameters['LEAF-1']
        sec_vtep        = testscript.parameters['LEAF-2']
        fex_vtep_if     = str(testscript.parameters['intf_LEAF_1_FEX_to_IXIA'])
        prim_fex_mac    = str(testscript.parameters['PORTSEC_Dict']['prim_fex_mac'])
        ixNetwork       = testscript.parameters['ixNetwork']
        p1_handle       = testscript.parameters['fex_handle']
        p2_handle       = testscript.parameters['sa_handle']
        
        with steps.start('Verfying the security volation'):
            p1_handle.Start()
            p2_handle.Start()

        log.info('Waiting {}secs to start 1025 hosts'.format(host_start_time))
        time.sleep(host_start_time)
        
        stream1 = ixNetwork.Traffic.TrafficItem.find(Name='Access FEX To Standalone')
        stream1.StartStatelessTraffic()
        log.info('Waiting {}secs to start the traffic'.format(traffic_start_time))
        time.sleep(traffic_start_time)
        
        stream1.StopStatelessTraffic()
        log.info('Waiting {}secs to stop the traffic'.format(traffic_stop_time))
        time.sleep(traffic_stop_time)

        with steps.start('Verfying the securty volation'):
            retval = prim_vtep.execute('show interface {intf} brief | inc Sec-violation | count'.format(intf=fex_vtep_if))
            if int(retval) == 0:
                log.error('Security Violation valdation failed')
                self.failed("Security Violation valdation failed")
                
        with steps.start("Checking mac/arp learning on local vtep fex port and remote vtep (leaf3).."):
            if not verify_port_sec_addr_count(prim_vtep, fex_vtep_if, 0, 'DYNAMIC'):
                log.error("DYNAMIC Mac learning failed")
                self.failed("DYNAMIC Mac learning failed")

            if not verify_secure_mac_on_vteps(prim_vtep, '1001', 0, prim_fex_mac, 'secure'):
                log.error("Mac learning failed on primary")
                self.failed("Mac learning failed on primary")
            if not verify_secure_mac_on_vteps(sec_vtep, '1001', 0, prim_fex_mac, 'secure'):
                log.error("Mac learning failed on primary")
                self.failed("Mac learning failed on primary")
            if not verify_secure_mac_on_vteps(sa_vtep, '1001', 0, prim_fex_mac):
                log.error("Mac learning failed on standalone")
                self.failed("Mac learning failed on standalone")
         
    @aetest.test
    def test_cleanup(self, testscript, testbed, steps):
        sa_vtep         = testscript.parameters['LEAF-3']
        prim_vtep       = testscript.parameters['LEAF-1']
        sec_vtep        = testscript.parameters['LEAF-2']
        prim_vtep_if    = str(testscript.parameters['intf_LEAF_1_1_to_IXIA'])
        sa_vtep_if      = str(testscript.parameters['intf_LEAF_3_to_IXIA'])
        fex_vtep_if     = str(testscript.parameters['intf_LEAF_1_FEX_to_IXIA'])
        
        new_config = 'switchport port-security maximum 1025'
        with steps.start("UnConfigure Port-Security on Primary VTEP Orphan"):
            if not unconfig_interface_ps([prim_vtep], prim_vtep_if, log, new_config):
                self.errored('Exception occurred while configuring port security', goto=['common_cleanup'])
        
        with steps.start("UnConfigure Port-Security on Standalone VTEP"):
            if not unconfig_interface_ps([sa_vtep], sa_vtep_if, log, new_config):
                self.errored('Exception occurred while configuring port security', goto=['common_cleanup'])
        
        with steps.start("UnConfigure Port-Security on VPC Primary/Secondary - Static"):
            if not unconfig_interface_ps([prim_vtep, sec_vtep], 'port-channel 11', log, new_config):
                self.errored('Exception occurred while configuring port security', goto=['common_cleanup'])
        
        with steps.start("UnConfigure Port-Security on Leaf-1 FEX - FEX port of VTEP"):
            
            if not unconfig_interface_ps([prim_vtep], fex_vtep_if, log, new_config):
                self.errored('Exception occurred while configuring port security', goto=['common_cleanup'])

        log.info("Waiting {}secs for interface to come up".format(config_time))
        time.sleep(config_time)

        with steps.start('Verify Learned mac address consistency between hardware and software'):
            if verify_mac_cc_between_hardware_software([prim_vtep, sec_vtep, sa_vtep]):
                log.info('MAC CC success')
            else:
                self.failed('MAC CC failed')
        
        with steps.start("Verifying MTS leak.."):
            if verify_mts_leak([prim_vtep, sec_vtep, sa_vtep], log):
                log.info('MTS Leak verification success')
            else:
                self.failed('MTS Leak verification failed')

        with steps.start("Verifying Cores and Log Errors"):
            exclude_bkp = post_test_process_dict['exclude_log_check_pattern']
            post_test_process_dict['exclude_log_check_pattern'] = str(exclude_bkp) + '|ETHPORT-5-IF_DOWN_ERROR_DISABLED|ETHPORT-5-IF_DOWN_CHANNEL_ERR_DISABLED'
            status = infraVerify.postTestVerification(post_test_process_dict)
            if status['status'] == 0:
                self.failed(reason=status['logs'])
            else:
                self.passed(reason=status['logs'])
            
            post_test_process_dict['exclude_log_check_pattern'] = exclude_bkp

# =============================================================================================================================#
# TC-ID: TC21 - Violatinon mode restrict
# Testcase:
# Configure interface global maximum port-sec count 1014, 
#     configure violation mode restrict and try to learn 1025 mac's
#      - 10 Mac's Learnt as drop mac on local/remote vtep (1015-1024) and 11th (1025) mac will not be learnt
#      - All traffic with the drop mac should be dropped
# =============================================================================================================================#
class TC_VXLAN_PS_012_Access(aetest.Testcase):
    @aetest.test
    def test_setup(self, testscript, testbed, steps):
        sa_vtep         = testscript.parameters['LEAF-3']
        prim_vtep       = testscript.parameters['LEAF-1']
        sec_vtep        = testscript.parameters['LEAF-2']
        prim_vtep_if    = str(testscript.parameters['intf_LEAF_1_1_to_IXIA'])
        sa_vtep_if      = str(testscript.parameters['intf_LEAF_3_to_IXIA'])
        fex_vtep_if     = str(testscript.parameters['intf_LEAF_1_FEX_to_IXIA'])
        
        new_config = 'switchport port-security maximum 1014'
        with steps.start("Configure Port-Security on Primary VTEP Orphan"):
            if not config_interface_ps([prim_vtep], prim_vtep_if, log, new_config):
                self.errored('Exception occurred while configuring port security', goto=['common_cleanup'])
        
        with steps.start("Configure Port-Security on Standalone VTEP"):
            if not config_interface_ps([sa_vtep], sa_vtep_if, log, new_config):
                self.errored('Exception occurred while configuring port security', goto=['common_cleanup'])
        
        with steps.start("Configure Port-Security on VPC Primary/Secondary"):
            if not config_interface_ps([prim_vtep, sec_vtep], 'port-channel 11', log, new_config):
                self.errored('Exception occurred while configuring port security', goto=['common_cleanup'])
        
        with steps.start("Configure Port-Security on Leaf-1 FEX - FEX port of VTEP"):
            if not config_interface_ps([prim_vtep], fex_vtep_if, log, new_config):
                self.errored('Exception occurred while configuring port security', goto=['common_cleanup'])

        log.info("Waiting {}secs for interface to come up".format(config_time))
        time.sleep(config_time)
        display_configs(testscript)

    @aetest.test
    def verify_violation_restrict_orphan(self, testscript, testbed, steps):
        sa_vtep         = testscript.parameters['LEAF-3']
        prim_vtep       = testscript.parameters['LEAF-1']
        sec_vtep        = testscript.parameters['LEAF-2']
        prim_vtep_if    = str(testscript.parameters['intf_LEAF_1_1_to_IXIA'])
        sa_vtep_if      = str(testscript.parameters['intf_LEAF_3_to_IXIA'])
        prim_mac        = str(testscript.parameters['PORTSEC_Dict']['prim_orphan_mac'])
        sa_mac          = str(testscript.parameters['PORTSEC_Dict']['sa_mac'])
        ixNetwork       = testscript.parameters['ixNetwork']
        p1_handle       = testscript.parameters['orphan1_handle']
        p2_handle       = testscript.parameters['sa_handle']
        
        with steps.start("Starting hosts..."):
            p1_handle.Start()
            p2_handle.Start()
        
        log.info('Waiting {}secs to start 1025 hosts'.format(host_start_time))
        time.sleep(host_start_time)
        
        stream1 = ixNetwork.Traffic.TrafficItem.find(Name='Access Orphan To Standalone')
        stream1.StartStatelessTraffic()
        log.info('Waiting {}secs to start the traffic'.format(traffic_start_time))
        time.sleep(traffic_start_time)
        
        stream1.StopStatelessTraffic()
        log.info('Waiting {}secs to stop the traffic'.format(traffic_stop_time))
        time.sleep(traffic_stop_time)
        
        with steps.start('Verfying the security volation'):
            retval = prim_vtep.execute('show mac address-table interface {intf} | inc Drop | count'.format(intf=prim_vtep_if))
            retval1 = sa_vtep.execute('show mac address-table interface {intf} | inc Drop | count'.format(intf=sa_vtep_if))
            if (int(retval) != 10) or (int(retval1) != 10):
                log.error('Security Violation valdation failed')
                self.failed("Security Violation valdation failed")
        
        with steps.start("Checking mac/arp learning on local vtep (leaf1 orphan) and remote vtep (leaf3).."):
            if not verify_port_sec_addr_count(prim_vtep, prim_vtep_if, 1014, 'DYNAMIC'):
                log.error("DYNAMIC Mac learning failed")
                self.failed("DYNAMIC Mac learning failed")

            if not verify_secure_mac_on_vteps(prim_vtep, '1001', 1014, prim_mac, 'secure'):
                log.error("Mac learning failed on primary")
                self.failed("Mac learning failed on primary")

            if not verify_secure_mac_on_vteps(sec_vtep, '1001', 1014, prim_mac, 'secure'):
                log.error("Mac learning failed on primary")
                self.failed("Mac learning failed on primary")
                
            if not verify_secure_mac_on_vteps(sa_vtep, '1001', 1024, prim_mac):
                log.error("Mac learning failed on standalone")
                self.failed("Mac learning failed on standalone")

        with steps.start("Checking mac/arp learning on local vtep (leaf3) and remote vpc peer (leaf1 and leaf2).."):
            if not verify_port_sec_addr_count(sa_vtep, sa_vtep_if, 1014, 'DYNAMIC'):
                log.error("DYNAMIC Mac learning failed")
                self.failed("DYNAMIC Mac learning failed")

            if not verify_secure_mac_on_vteps(sa_vtep, '1002', 1014, sa_mac, 'secure'):
                log.error("Mac learning failed on Standalone")
                self.failed("Mac learning failed on Standalone")

            if not verify_secure_mac_on_vteps(prim_vtep, '1002', 1024, sa_mac):
                log.error("DYNAMIC Mac learning failed on remote vtep(leaf1)")
                self.failed("DYNAMIC Mac learning failed on remote vtep(leaf1)")

            if not verify_secure_mac_on_vteps(sec_vtep, '1002', 1024, sa_mac):
                log.error("DYNAMIC Mac learning failed on remote vtep(leaf2)")
                self.failed("DYNAMIC Mac learning failed on remote vtep(leaf2)")

        with steps.start("Verify Steady State"):
            if VerifyTrafficDrop("Test_012_Orphan", testscript, traffic_item='Access Orphan To Standalone'):
                self.passed('Verify traffic success')
            else:
                self.failed('Verify traffic failed')
        
    @aetest.test
    def verify_violation_restrict_vpc(self, testscript, testbed, steps):
        sa_vtep         = testscript.parameters['LEAF-3']
        prim_vtep       = testscript.parameters['LEAF-1']
        sec_vtep        = testscript.parameters['LEAF-2']
        prim_vpc_mac    = str(testscript.parameters['PORTSEC_Dict']['prim_vpc_mac'])
        ixNetwork       = testscript.parameters['ixNetwork']
        p1_handle       = testscript.parameters['vpc_handle']
        p2_handle       = testscript.parameters['sa_handle']
        
        with steps.start("Starting hosts.."):
            p1_handle.Start()
            p2_handle.Start()
        
        log.info('Waiting {}secs to start 1025 hosts'.format(host_start_time))
        time.sleep(host_start_time)

        stream1 = ixNetwork.Traffic.TrafficItem.find(Name='Access VPC To Standalone')
        stream1.StartStatelessTraffic()
        log.info('Waiting {}secs to start the traffic'.format(traffic_start_time))
        time.sleep(traffic_start_time)
        
        stream1.StopStatelessTraffic()
        log.info('Waiting {}secs to stop the traffic'.format(traffic_stop_time))
        time.sleep(traffic_stop_time)

        with steps.start('Verfying the security volation'):
            retval = prim_vtep.execute('show mac address-table interface port-channel 11  | inc Drop | count')
            retval1 = sec_vtep.execute('show mac address-table interface port-channel 11 | inc Drop | count')
            if (int(retval) == 10) or (int(retval1) == 10):
                log.info('Security Violation valdation success')
            else:
                log.error('Security Violation valdation failed')
                self.failed("Security Violation valdation failed")
        
        with steps.start("Checking mac learning on vpc and remote vtep (leaf3).."):
            if not verify_port_sec_addr_count(prim_vtep, 'port-channel 11', 1014, 'DYNAMIC'):
                log.error("DYNAMIC Mac learning failed")
                self.failed("DYNAMIC Mac learning failed")
            if not verify_port_sec_addr_count(sec_vtep, 'port-channel 11', 1014, 'DYNAMIC'):
                log.error("DYNAMIC Mac learning failed")
                self.failed("DYNAMIC Mac learning failed")

            if not verify_secure_mac_on_vteps(prim_vtep, '1001', 1014, prim_vpc_mac, 'secure'):
                log.error("Mac learning failed on primary")
                self.failed("Mac learning failed on primary")
            if not verify_secure_mac_on_vteps(sec_vtep, '1001', 1014, prim_vpc_mac, 'secure'):
                log.error("Mac learning failed on primary")
                self.failed("Mac learning failed on primary")
            if not verify_secure_mac_on_vteps(sa_vtep, '1001', 1024, prim_vpc_mac):
                log.error("Mac learning failed on standalone")
                self.failed("Mac learning failed on standalone")
                
        with steps.start("Verify Steady State"):
            if VerifyTrafficDrop("Test_012_VPC", testscript, traffic_item='Access VPC To Standalone'):
                self.passed('Verify traffic success')
            else:
                self.failed('Verify traffic failed')
           
    @aetest.test
    def verify_violation_restrict_fex(self, testscript, testbed, steps):
        sa_vtep         = testscript.parameters['LEAF-3']
        prim_vtep       = testscript.parameters['LEAF-1']
        sec_vtep        = testscript.parameters['LEAF-2']
        fex_vtep_if     = str(testscript.parameters['intf_LEAF_1_FEX_to_IXIA'])
        prim_fex_mac    = str(testscript.parameters['PORTSEC_Dict']['prim_fex_mac'])
        ixNetwork       = testscript.parameters['ixNetwork']
        p1_handle       = testscript.parameters['fex_handle']
        p2_handle       = testscript.parameters['sa_handle']
    
        with steps.start('Starting hosts'):
            p1_handle.Start()
            p2_handle.Start()
        
        log.info('Waiting {}secs to start 1025 hosts'.format(host_start_time))
        time.sleep(host_start_time)
    
        stream1 = ixNetwork.Traffic.TrafficItem.find(Name='Access FEX To Standalone')        
        stream1.StartStatelessTraffic()
        log.info('Waiting {}secs to start the traffic'.format(traffic_start_time))
        time.sleep(traffic_start_time)
        
        stream1.StopStatelessTraffic()
        log.info('Waiting {}secs to stop the traffic'.format(traffic_stop_time))
        time.sleep(traffic_stop_time)

        with steps.start('Verfying the security volation'):
            retval = prim_vtep.execute('show mac address-table interface {intf} | inc Drop | count'.format(intf=fex_vtep_if))
            if int(retval) == 0:
                log.error('Security Violation valdation failed')
                self.failed("Security Violation valdation failed")
        
        with steps.start("Checking mac learning on fex port and remote vtep.."):
            if not verify_port_sec_addr_count(prim_vtep, fex_vtep_if, 1014, 'DYNAMIC'):
                log.error("DYNAMIC Mac learning failed")
                self.failed("DYNAMIC Mac learning failed")

            if not verify_secure_mac_on_vteps(prim_vtep, '1001', 1014, prim_fex_mac, 'secure'):
                log.error("Mac learning failed on primary")
                self.failed("Mac learning failed on primary")
            if not verify_secure_mac_on_vteps(sec_vtep, '1001', 1014, prim_fex_mac, 'secure'):
                log.error("Mac learning failed on primary")
                self.failed("Mac learning failed on primary")
            if not verify_secure_mac_on_vteps(sa_vtep, '1001', 1024, prim_fex_mac):
                log.error("Mac learning failed on standalone")
                self.failed("Mac learning failed on standalone")
                
        with steps.start("Verify Steady State"):
            if VerifyTrafficDrop("Test_012_FEX", testscript, traffic_item='Access FEX To Standalone'):
                self.passed('Verify traffic success')
            else:
                self.failed('Verify traffic failed')
         
    @aetest.test
    def test_cleanup(self, testscript, testbed, steps):
        sa_vtep         = testscript.parameters['LEAF-3']
        prim_vtep       = testscript.parameters['LEAF-1']
        sec_vtep        = testscript.parameters['LEAF-2']
        prim_vtep_if    = str(testscript.parameters['intf_LEAF_1_1_to_IXIA'])
        sa_vtep_if      = str(testscript.parameters['intf_LEAF_3_to_IXIA'])
        fex_vtep_if     = str(testscript.parameters['intf_LEAF_1_FEX_to_IXIA'])
        ixNetwork       = testscript.parameters['ixNetwork']
        
        with steps.start("Stopping all hosts..."):
            ixNetwork.StopAllProtocols()

        log.info('Waiting {}secs to stop the hosts'.format(traffic_stop_time))
        time.sleep(traffic_stop_time)
        
        new_config = 'switchport port-security maximum 1025'
        with steps.start("UnConfigure Port-Security on Primary VTEP Orphan"):
            if not unconfig_interface_ps([prim_vtep], prim_vtep_if, log, new_config):
                self.errored('Exception occurred while configuring port security', goto=['common_cleanup'])
        
        with steps.start("UnConfigure Port-Security on Standalone VTEP"):
            if not unconfig_interface_ps([sa_vtep], sa_vtep_if, log, new_config):
                self.errored('Exception occurred while configuring port security', goto=['common_cleanup'])
        
        with steps.start("UnConfigure Port-Security on VPC Primary/Secondary"):
            if not unconfig_interface_ps([prim_vtep, sec_vtep], 'port-channel 11', log, new_config):
                self.errored('Exception occurred while configuring port security', goto=['common_cleanup'])
        
        with steps.start("UnConfigure Port-Security on Leaf-1 FEX - FEX port of VTEP"):
            if not unconfig_interface_ps([prim_vtep], fex_vtep_if, log, new_config):
                self.errored('Exception occurred while configuring port security', goto=['common_cleanup'])

        log.info("Waiting {}secs for interface to come up".format(config_time))
        time.sleep(config_time)
        
        with steps.start("Verifying MTS leak.."):
            if verify_mts_leak([prim_vtep, sec_vtep, sa_vtep], log):
                log.info('MTS Leak verification success')
            else:
                self.failed('MTS Leak verification failed')

        with steps.start("Verifying Cores and Log Errors"):
            status = infraVerify.postTestVerification(post_test_process_dict)
            if status['status'] == 0:
                self.failed(reason=status['logs'])
            else:
                self.passed(reason=status['logs'])

# =============================================================================================================================#
# TC-ID: TC23 - Trunk Mode
# Testcase:
# Configure interface global maximum port-sec count 1014, 
#     configure violation mode protect and try to learn 1025 mac's
#      - 10 Mac's Learnt as drop mac on local/remote vtep and 1015th mac onwards will not be learnt
#      - All traffic with the drop mac should be dropped
# =============================================================================================================================#
class TC_VXLAN_PS_013_Access(aetest.Testcase):
    @aetest.test
    def configure_port_security(self, testscript, testbed, steps):
        sa_vtep         = testscript.parameters['LEAF-3']
        prim_vtep       = testscript.parameters['LEAF-1']
        sec_vtep        = testscript.parameters['LEAF-2']
        prim_vtep_if    = str(testscript.parameters['intf_LEAF_1_1_to_IXIA'])
        sa_vtep_if      = str(testscript.parameters['intf_LEAF_3_to_IXIA'])
        fex_vtep_if     = str(testscript.parameters['intf_LEAF_1_FEX_to_IXIA'])
        
        new_config = '''switchport port-security maximum 1014
                        switchport port-security violation protect'''
        with steps.start("Configure Port-Security on Primary VTEP Orphan"):
            if not config_interface_ps([prim_vtep], prim_vtep_if, log, new_config):
                self.errored('Exception occurred while configuring port security', goto=['common_cleanup'])
        
        with steps.start("Configure Port-Security on Standalone VTEP"):
            if not config_interface_ps([sa_vtep], sa_vtep_if, log, new_config):
                self.errored('Exception occurred while configuring port security', goto=['common_cleanup'])
        
        with steps.start("Configure Port-Security on VPC Primary/Secondary"):
            if not config_interface_ps([prim_vtep, sec_vtep], 'port-channel 11', log, new_config):
                self.errored('Exception occurred while configuring port security', goto=['common_cleanup'])
        
        with steps.start("Configure Port-Security on Leaf-1 FEX - FEX port of VTEP"):
            if not config_interface_ps([prim_vtep], fex_vtep_if, log, new_config):
                self.errored('Exception occurred while configuring port security', goto=['common_cleanup'])

        log.info("Waiting {}secs for interface to come up".format(config_time))
        time.sleep(config_time)
        display_configs(testscript)

    @aetest.test
    def verify_violation_protect_orphan(self, testscript, testbed, steps):
        sa_vtep         = testscript.parameters['LEAF-3']
        prim_vtep       = testscript.parameters['LEAF-1']
        sec_vtep        = testscript.parameters['LEAF-2']
        prim_vtep_if    = str(testscript.parameters['intf_LEAF_1_1_to_IXIA'])
        sa_vtep_if      = str(testscript.parameters['intf_LEAF_3_to_IXIA'])
        prim_mac        = str(testscript.parameters['PORTSEC_Dict']['prim_orphan_mac'])
        sa_mac          = str(testscript.parameters['PORTSEC_Dict']['sa_mac'])
        ixNetwork       = testscript.parameters['ixNetwork']
        p1_handle       = testscript.parameters['orphan1_handle']
        p2_handle       = testscript.parameters['sa_handle']
        
        with steps.start("Starting hosts..."):
            p1_handle.Start()
            p2_handle.Start()
        
        log.info('Waiting {}secs to start 1025 hosts'.format(host_start_time))
        time.sleep(host_start_time)

        stream1 = ixNetwork.Traffic.TrafficItem.find(Name='Access Orphan To Standalone')
        stream1.StartStatelessTraffic()
        log.info('Waiting {}secs to start the traffic'.format(traffic_start_time))
        time.sleep(traffic_start_time)

        stream1.StopStatelessTraffic()
        log.info('Waiting {}secs to stop the traffic'.format(traffic_stop_time))
        time.sleep(traffic_stop_time)

        with steps.start("Checking mac/arp learning on orphan port and remote vtep.."):
            if not verify_port_sec_addr_count(prim_vtep, prim_vtep_if, 1014, 'DYNAMIC'):
                log.error("DYNAMIC Mac learning failed")
                self.failed("DYNAMIC Mac learning failed")

            if not verify_secure_mac_on_vteps(prim_vtep, '1001', 1014, prim_mac, 'secure'):
                log.error("Mac learning failed on primary")
                self.failed("Mac learning failed on primary")

            if not verify_secure_mac_on_vteps(sec_vtep, '1001', 1014, prim_mac, 'secure'):
                log.error("Mac learning failed on primary")
                self.failed("Mac learning failed on primary")
                
            if not verify_secure_mac_on_vteps(sa_vtep, '1001', 1015, prim_mac):
                log.error("Mac learning failed on standalone")
                self.failed("Mac learning failed on standalone")

        with steps.start("Checking mac/arp learning on local vtep (leaf3) and remote vpc peer (leaf1 and leaf2).."):
            if not verify_port_sec_addr_count(sa_vtep, sa_vtep_if, 1014, 'DYNAMIC'):
                log.error("DYNAMIC Mac learning failed")
                self.failed("DYNAMIC Mac learning failed")

            if not verify_secure_mac_on_vteps(sa_vtep, '1002', 1014, sa_mac, 'secure'):
                log.error("Mac learning failed on Standalone")
                self.failed("Mac learning failed on Standalone")

            if not verify_secure_mac_on_vteps(prim_vtep, '1002', 1015, sa_mac):
                log.error("DYNAMIC Mac learning failed on remote vtep(leaf1)")
                self.failed("DYNAMIC Mac learning failed on remote vtep(leaf1)")

            if not verify_secure_mac_on_vteps(sec_vtep, '1002', 1015, sa_mac):
                log.error("DYNAMIC Mac learning failed on remote vtep(leaf2)")
                self.failed("DYNAMIC Mac learning failed on remote vtep(leaf2)")

        with steps.start("Verify Steady State"):
            if VerifyTrafficDrop("Test_013_Orphan", testscript, 
                                 traffic_item='Access Orphan To Standalone'):
                self.passed('Verify traffic success')
            else:
                self.failed('Verify traffic failed')
        
    @aetest.test
    def verify_violation_protect_vpc(self, testscript, testbed, steps):
        sa_vtep         = testscript.parameters['LEAF-3']
        prim_vtep       = testscript.parameters['LEAF-1']
        sec_vtep        = testscript.parameters['LEAF-2']
        prim_vpc_mac    = str(testscript.parameters['PORTSEC_Dict']['prim_vpc_mac'])
        ixNetwork       = testscript.parameters['ixNetwork']
        p1_handle       = testscript.parameters['vpc_handle']
        p2_handle       = testscript.parameters['sa_handle']
        
        with steps.start("Starting hosts.."):
            p1_handle.Start()
            p2_handle.Start()
        
        log.info('Waiting {}secs to start 1025 hosts'.format(host_start_time))
        time.sleep(host_start_time)

        stream1 = ixNetwork.Traffic.TrafficItem.find(Name='Access VPC To Standalone')
        stream1.StartStatelessTraffic()
        log.info('Waiting {}secs to start the traffic'.format(traffic_start_time))
        time.sleep(traffic_start_time)
        
        stream1.StopStatelessTraffic()
        log.info('Waiting {}secs to stop the traffic'.format(traffic_stop_time))
        time.sleep(traffic_stop_time)

        with steps.start("Checking mac/arp learning on local vtep (leaf1/leaf2 member port) and remote vtep (leaf3).."):
            if not verify_port_sec_addr_count(prim_vtep, 'port-channel 11', 1014, 'DYNAMIC'):
                log.error("DYNAMIC Mac learning failed")
                self.failed("DYNAMIC Mac learning failed")
            if not verify_port_sec_addr_count(sec_vtep, 'port-channel 11', 1014, 'DYNAMIC'):
                log.error("DYNAMIC Mac learning failed")
                self.failed("DYNAMIC Mac learning failed")

            if not verify_secure_mac_on_vteps(prim_vtep, '1001', 1014, prim_vpc_mac, 'secure'):
                log.error("Mac learning failed on primary")
                self.failed("Mac learning failed on primary")
            if not verify_secure_mac_on_vteps(sec_vtep, '1001', 1014, prim_vpc_mac, 'secure'):
                log.error("Mac learning failed on primary")
                self.failed("Mac learning failed on primary")
            if not verify_secure_mac_on_vteps(sa_vtep, '1001', 1015, prim_vpc_mac):
                log.error("Mac learning failed on standalone")
                self.failed("Mac learning failed on standalone")
                
        with steps.start("Verify Steady State"):
            if VerifyTrafficDrop("Test_013_VPC", testscript, traffic_item='Access VPC To Standalone'):
                self.passed('Verify traffic success')
            else:
                self.failed('Verify traffic failed')

    @aetest.test
    def verify_violation_restrict_fex(self, testscript, testbed, steps):
        sa_vtep         = testscript.parameters['LEAF-3']
        prim_vtep       = testscript.parameters['LEAF-1']
        sec_vtep        = testscript.parameters['LEAF-2']
        fex_vtep_if     = str(testscript.parameters['intf_LEAF_1_FEX_to_IXIA'])
        prim_fex_mac    = str(testscript.parameters['PORTSEC_Dict']['prim_fex_mac'])
        ixNetwork       = testscript.parameters['ixNetwork']
        p1_handle       = testscript.parameters['fex_handle']
        p2_handle       = testscript.parameters['sa_handle']
        
        with steps.start('Starting hosts...'):
            p1_handle.Start()
            p2_handle.Start()
        
        log.info('Waiting {}secs to start 1025 hosts'.format(host_start_time))
        time.sleep(host_start_time)
    
        stream1 = ixNetwork.Traffic.TrafficItem.find(Name='Access FEX To Standalone')        
        stream1.StartStatelessTraffic()
        log.info('Waiting {}secs to start the traffic'.format(traffic_start_time))
        time.sleep(traffic_start_time)
        
        stream1.StopStatelessTraffic()
        log.info('Waiting {}secs to stop the traffic'.format(traffic_stop_time))
        time.sleep(traffic_stop_time)

        with steps.start("Checking mac/arp learning on fex port and remote vtep.."):
            if not verify_port_sec_addr_count(prim_vtep, fex_vtep_if, 1014, 'DYNAMIC'):
                log.error("DYNAMIC Mac learning failed")
                self.failed("DYNAMIC Mac learning failed")

            if not verify_secure_mac_on_vteps(prim_vtep, '1001', 1014, prim_fex_mac, 'secure'):
                log.error("Mac learning failed on primary")
                self.failed("Mac learning failed on primary")
            if not verify_secure_mac_on_vteps(sec_vtep, '1001', 1014, prim_fex_mac, 'secure'):
                log.error("Mac learning failed on primary")
                self.failed("Mac learning failed on primary")
            if not verify_secure_mac_on_vteps(sa_vtep, '1001', 1015, prim_fex_mac):
                log.error("Mac learning failed on standalone")
                self.failed("Mac learning failed on standalone")
                
        with steps.start("Verify Steady State"):

            if VerifyTrafficDrop("Test_013_FEX", testscript, traffic_item='Access FEX To Standalone'):
                self.passed('Verify traffic success')
            else:
                self.failed('Verify traffic failed')

    @aetest.test
    def test_cleanup(self, testscript, testbed, steps):
        sa_vtep         = testscript.parameters['LEAF-3']
        prim_vtep       = testscript.parameters['LEAF-1']
        sec_vtep        = testscript.parameters['LEAF-2']
        prim_vtep_if    = str(testscript.parameters['intf_LEAF_1_1_to_IXIA'])
        sa_vtep_if      = str(testscript.parameters['intf_LEAF_3_to_IXIA'])
        fex_vtep_if     = str(testscript.parameters['intf_LEAF_1_FEX_to_IXIA'])
        ixNetwork       = testscript.parameters['ixNetwork']
        
        with steps.start("Stopping all hosts..."):
            ixNetwork.StopAllProtocols()

        log.info('Waiting {}secs to stop the hosts'.format(traffic_stop_time))
        time.sleep(traffic_stop_time)
        
        new_config = '''switchport port-security maximum 1025
                        switchport port-security violation restrict'''

        with steps.start("UnConfigure Port-Security on Primary VTEP Orphan"):
            if not unconfig_interface_ps([prim_vtep], prim_vtep_if, log, new_config):
                self.errored('Exception occurred while configuring port security', goto=['common_cleanup'])
        
        with steps.start("UnConfigure Port-Security on Standalone VTEP"):
            if not unconfig_interface_ps([sa_vtep], sa_vtep_if, log, new_config):
                self.errored('Exception occurred while configuring port security', goto=['common_cleanup'])
        
        with steps.start("UnConfigure Port-Security on VPC Primary/Secondary - Static"):
            if not unconfig_interface_ps([prim_vtep, sec_vtep], 'port-channel 11', log, new_config):
                self.errored('Exception occurred while configuring port security', goto=['common_cleanup'])
        
        with steps.start("UnConfigure Port-Security on Leaf-1 FEX - FEX port of VTEP"):
            if not unconfig_interface_ps([prim_vtep], fex_vtep_if, log, new_config):
                self.errored('Exception occurred while configuring port security', goto=['common_cleanup'])

        log.info("Waiting {}secs for interface to come up".format(config_time))
        time.sleep(config_time)
        
        with steps.start("Verifying MTS leak.."):
            if verify_mts_leak([prim_vtep, sec_vtep, sa_vtep], log):
                log.info('MTS Leak verification success')
            else:
                self.failed('MTS Leak verification failed')

        with steps.start("Verifying Cores and Log Errors"):
            status = infraVerify.postTestVerification(post_test_process_dict)
            if status['status'] == 0:
                self.failed(reason=status['logs'])
            else:
                self.passed(reason=status['logs'])

########################################################################################################
# Triggers 
########################################################################################################
# TC: VXLAN_PS_055 and VXLAN_PS_079 - Trunk Mode
# Verify defaulting interface, port-channel and switchport flush out the learnt mac's
# Use config-replace to replace the configuration after default interface
########################################################################################################
class TC_VXLAN_PS_014_Access(aetest.Testcase):
    @aetest.test
    def test_setup(self, testscript, testbed, steps):
        sa_vtep         = testscript.parameters['LEAF-3']
        prim_vtep       = testscript.parameters['LEAF-1']
        sec_vtep        = testscript.parameters['LEAF-2']
        src_vlan        = int(testscript.parameters['LEAF_1_Orphan1_TGEN_dict']['vlan_id'])
        leaf1_mac       = str(testscript.parameters['PORTSEC_Dict']['vpc_static_mac'])
        prim_vtep_if    = str(testscript.parameters['intf_LEAF_1_1_to_IXIA'])
        sa_vtep_if      = str(testscript.parameters['intf_LEAF_3_to_IXIA'])
        fex_vtep_if     = str(testscript.parameters['intf_LEAF_1_FEX_to_IXIA'])
        
        with steps.start("Configure Port-Security on Primary VTEP Orphan"):
            if not config_interface_ps([prim_vtep], prim_vtep_if, log):
                self.errored('Exception occurred while configuring port security', goto=['common_cleanup'])
         
        with steps.start("Configure Port-Security on Standalone VTEP"):
            if not config_interface_ps([sa_vtep], sa_vtep_if, log):
                self.errored('Exception occurred while configuring port security', goto=['common_cleanup'])

        with steps.start("Configure Port-Security on VPC Primary/Secondary - Static"):
            new_config = 'switchport port-security mac-address {mac}'.format(mac=leaf1_mac)
            if not config_interface_ps([prim_vtep, sec_vtep], 'port-channel 11', log, new_config):
                self.errored('Exception occurred while configuring port security', goto=['common_cleanup'])
        
        with steps.start("Configure Port-Security on Leaf-1 FEX - FEX port of VTEP"):
            new_config = 'switchport port-security mac-address sticky'
            if not config_interface_ps([prim_vtep], fex_vtep_if, log, new_config):
                self.errored('Exception occurred while configuring port security', goto=['common_cleanup'])
        
        log.info("Waiting {}secs for interface to come up".format(config_time))
        time.sleep(config_time)
        display_configs(testscript)

    # Default port-security interface on VPC orphan and standalone
    @aetest.test
    def verify_default_standalone_and_orphan_interface(self, testscript, testbed, steps):
        sa_vtep         = testscript.parameters['LEAF-3']
        prim_vtep       = testscript.parameters['LEAF-1']
        sec_vtep        = testscript.parameters['LEAF-2']
        sa_vtep_if      = str(testscript.parameters['intf_LEAF_3_to_IXIA'])
        prim_vtep_if    = str(testscript.parameters['intf_LEAF_1_1_to_IXIA'])
        sa_mac          = str(testscript.parameters['PORTSEC_Dict']['sa_mac'])
        prim_mac        = str(testscript.parameters['PORTSEC_Dict']['prim_orphan_mac'])
        ixNetwork       = testscript.parameters['ixNetwork']
        p1_handle       = testscript.parameters['orphan1_handle']
        p2_handle       = testscript.parameters['sa_handle']
        
        with steps.start("Starting hosts..."):
            p1_handle.Start()
            p2_handle.Start()
        
        log.info('Waiting {}secs to start 1025 hosts'.format(host_start_time))
        time.sleep(host_start_time)
        
        stream1 = ixNetwork.Traffic.TrafficItem.find(Name='Access Orphan To Standalone')
        stream1.StartStatelessTraffic()
        
        log.info('Waiting {}secs to start the traffic'.format(traffic_start_time))
        time.sleep(traffic_start_time)

        with steps.start('Do Config backup on VPC Primary and Standalone before default-interface'):
            prim_vtep.execute('delete bootflash:{cr_file} no-prompt'.format(cr_file=cr_file))
            sa_vtep.execute('delete bootflash:{cr_file} no-prompt'.format(cr_file=cr_file))
            prim_vtep.execute("copy running-config bootflash:{cr_file}".format(cr_file=cr_file))
            sa_vtep.execute("copy running-config bootflash:{cr_file}".format(cr_file=cr_file))
        
        with steps.start('Do default-interface on orphan port at VPC primary and standalone'):
            sa_vtep.configure('''default interface {intf1}'''.format(intf1=sa_vtep_if))
            prim_vtep.configure('''default interface {intf2}'''.format(intf2=prim_vtep_if))
        
        log.info('Waiting 30secs mac flushout')
        time.sleep(30)

        with steps.start("Checking Mac flushout on standalone and remote vtep after trigger"):
            if not verify_port_sec_addr_count(sa_vtep, sa_vtep_if, 0, 'DYNAMIC'):
                log.error("DYNAMIC Mac learning failed")
                self.failed("DYNAMIC Mac learning failed")

            if not verify_secure_mac_on_vteps(sa_vtep, '1002', 0, sa_mac, 'secure'):
                log.error("Mac learning failed on Standalone")
                self.failed("Mac learning failed on Standalone")

            if not verify_secure_mac_on_vteps(prim_vtep, '1002', 0, sa_mac):
                log.error("DYNAMIC Mac learning failed on remote vtep(leaf1)")
                self.failed("DYNAMIC Mac learning failed on remote vtep(leaf1)")

            if not verify_secure_mac_on_vteps(sec_vtep, '1002', 0, sa_mac):
                log.error("DYNAMIC Mac learning failed on remote vtep(leaf2)")
                self.failed("DYNAMIC Mac learning failed on remote vtep(leaf2)")
        
        with steps.start("Checking Mac flushout on local and remote vtep after trigger"):
            if not verify_port_sec_addr_count(prim_vtep, prim_vtep_if, 0, 'DYNAMIC'):
                log.error("DYNAMIC Mac learning failed")
                self.failed("DYNAMIC Mac learning failed")

            if not verify_secure_mac_on_vteps(prim_vtep, '1001', 0, prim_mac, 'secure'):
                log.error("Mac learning failed on primary")
                self.failed("Mac learning failed on primary")

            if not verify_secure_mac_on_vteps(sec_vtep, '1001', 0, prim_mac, 'secure'):
                log.error("DYNAMIC Mac learning failed on remote vtep(leaf2)")
                self.failed("DYNAMIC Mac learning failed on remote vtep(leaf2)")

            if not verify_secure_mac_on_vteps(sa_vtep, '1001', 0, prim_mac):
                log.error("Mac learning failed on standalone")
                self.failed("Mac learning failed on standalone")

        with steps.start('Doing Config Replace to replace the configs on orphan and standalone'):
            if verify_config_replace([prim_vtep, sa_vtep], log):
                log.info('Config-Replace success')
            else:
                self.failed('Config-Replace failed')
       
        log.info('Waiting 30secs for mac relearning')
        time.sleep(30)
        
        with steps.start("Checking mac relearning on standalone and remote after trigger"):
            if not verify_port_sec_addr_count(sa_vtep, sa_vtep_if, 1025, 'DYNAMIC'):
                log.error("DYNAMIC Mac learning failed")
                self.failed("DYNAMIC Mac learning failed")

            if not verify_secure_mac_on_vteps(sa_vtep, '1002', 1025, sa_mac, 'secure'):
                log.error("Mac learning failed on Standalone")
                self.failed("Mac learning failed on Standalone")

            if not verify_secure_mac_on_vteps(prim_vtep, '1002', 1025, sa_mac):
                log.error("DYNAMIC Mac learning failed on remote vtep(leaf1)")
                self.failed("DYNAMIC Mac learning failed on remote vtep(leaf1)")

            if not verify_secure_mac_on_vteps(sec_vtep, '1002', 1025, sa_mac):
                log.error("DYNAMIC Mac learning failed on remote vtep(leaf2)")
                self.failed("DYNAMIC Mac learning failed on remote vtep(leaf2)")

        with steps.start("Checking Mac relearning on local and remote after trigger"):
            if not verify_port_sec_addr_count(prim_vtep, prim_vtep_if, 1025, 'DYNAMIC'):
                log.error("DYNAMIC Mac learning failed")
                self.failed("DYNAMIC Mac learning failed")

            if not verify_secure_mac_on_vteps(prim_vtep, '1001', 1025, prim_mac, 'secure'):
                log.error("Mac learning failed on primary")
                self.failed("Mac learning failed on primary")

            if not verify_secure_mac_on_vteps(sec_vtep, '1001', 1025, prim_mac, 'secure'):
                log.error("DYNAMIC Mac learning failed on remote vtep(leaf2)")
                self.failed("DYNAMIC Mac learning failed on remote vtep(leaf2)")

            if not verify_secure_mac_on_vteps(sa_vtep, '1001', 1025, prim_mac):
                log.error("Mac learning failed on standalone")
                self.failed("Mac learning failed on standalone")

        stream1.StopStatelessTraffic()
        log.info('Waiting {}secs to stop the traffic'.format(traffic_stop_time))
        time.sleep(traffic_stop_time)
        
        with steps.start("Verify Steady State after trigger"):
            if VerifyTraffic("Test_016_Orphan", testscript, traffic_item='Access Orphan To Standalone'):
                log.info('Verify traffic success after trigger')
            else:
                self.failed('Verify traffic failed after trigger')

        with steps.start('Verify Learned mac address consistency between hardware and software'):
            if verify_mac_cc_between_hardware_software([prim_vtep, sec_vtep, sa_vtep]):
                self.passed('MAC CC success')
            else:
                self.failed('MAC CC failed')
    
    @aetest.test
    def verify_default_portchannel(self, testscript, testbed, steps):
        sa_vtep         = testscript.parameters['LEAF-3']
        prim_vtep       = testscript.parameters['LEAF-1']
        sec_vtep        = testscript.parameters['LEAF-2']
        leaf1_mac       = str(testscript.parameters['PORTSEC_Dict']['vpc_static_mac'])
        prim_vpc_mac    = str(testscript.parameters['PORTSEC_Dict']['prim_vpc_mac'])
        src_vlan        = int(testscript.parameters['LEAF_1_Orphan1_TGEN_dict']['vlan_id'])
        ixNetwork       = testscript.parameters['ixNetwork']
        p1_handle       = testscript.parameters['vpc_handle']
        p2_handle       = testscript.parameters['sa_handle']
        
        with steps.start("Starting hosts.."):
            p1_handle.Start()
            p2_handle.Start()
        
        log.info('Waiting {}secs to start 1025 hosts'.format(host_start_time))
        time.sleep(host_start_time)
    
        stream1 = ixNetwork.Traffic.TrafficItem.find(Name='Access VPC To Standalone')
        
        stream1.StartStatelessTraffic()
        log.info('Waiting {}secs to start the traffic'.format(traffic_start_time))
        time.sleep(traffic_start_time)
    
        with steps.start("Default VPC Port Channel"):
            try:
                prim_vtep.configure('default interface port-channel 11')
                sec_vtep.configure('default interface port-channel 11')
            except Exception as error:
                log.debug("Unable to configure - Encountered Exception " + str(error))
                self.errored('Exception occured during default interface configuration', 
                             goto=['common_cleanup'])
                        
        log.info('Waiting 60secs for mac flushout')    
        time.sleep(60)

        with steps.start("Checking mac learning on local and remote vtep after default interface"):
            if not verify_port_sec_addr_count(prim_vtep, 'port-channel 11', 0, 'STATIC'):
                log.error("STATIC Mac learning failed")
                self.failed("STATIC Mac learning failed")
    
            if not verify_port_sec_addr_count(prim_vtep, 'port-channel 11', 0, 'DYNAMIC'):
                log.error("DYNAMIC Mac learning failed")
                self.failed("DYNAMIC Mac learning failed")
            
            if not verify_port_sec_addr_count(sec_vtep, 'port-channel 11', 0, 'STATIC'):
                log.error("STATIC Mac learning failed")
                self.failed("STATIC Mac learning failed")
        
            if not verify_port_sec_addr_count(sec_vtep, 'port-channel 11', 0, 'DYNAMIC'):
                log.error("DYNAMIC Mac learning failed")
                self.failed("DYNAMIC Mac learning failed")
            
            if not verify_secure_mac_on_vteps(prim_vtep, '1001', 0, prim_vpc_mac, 'secure'):
                log.error("Mac learning failed on primary")
                self.failed("Mac learning failed on primary")

            if not verify_secure_mac_on_vteps(sec_vtep, '1001', 0, prim_vpc_mac, 'secure'):
                log.error("Mac learning failed on primary")
                self.failed("Mac learning failed on primary")
                
            if not verify_secure_mac_on_vteps(sa_vtep, '1001', 0, prim_vpc_mac):
                log.error("Mac learning failed on standalone")
                self.failed("Mac learning failed on standalone")
        
        with steps.start("Configure Port-Security on VPC Primary/Secondary - Static"):
            if not basic_interface_configs([prim_vtep, sec_vtep], 'port-channel 11', '1001'):
                self.errored('Exception occurred while configuring port security', goto=['common_cleanup'])
            new_config = '''switchport port-security mac-address {mac}
                           vpc 11'''.format(mac=leaf1_mac)
            if not config_interface_ps([prim_vtep, sec_vtep], 'port-channel 11', log, new_config):
                self.errored('Exception occurred while configuring port security', goto=['common_cleanup'])

        log.info('Waiting 60secs for mac relearning')
        time.sleep(60)
                
        with steps.start("Checking mac learning on local and remote vtep after trigger"):        
            if not verify_port_sec_addr_count(prim_vtep, 'port-channel 11', 1, 'STATIC'):
                log.error("STATIC Mac learning failed")
                self.failed("STATIC Mac learning failed")
                
            if not verify_port_sec_addr_count(prim_vtep, 'port-channel 11', 1024, 'DYNAMIC'):
                log.error("DYNAMIC Mac learning failed")
                self.failed("DYNAMIC Mac learning failed")
        
            if not verify_port_sec_addr_count(sec_vtep, 'port-channel 11', 1, 'STATIC'):
                log.error("STATIC Mac learning failed")
                self.failed("STATIC Mac learning failed")
                
            if not verify_port_sec_addr_count(sec_vtep, 'port-channel 11', 1024, 'DYNAMIC'):
                log.error("DYNAMIC Mac learning failed")
                self.failed("DYNAMIC Mac learning failed")
            
            if not verify_secure_mac_on_vteps(prim_vtep, '1001', 1025, prim_vpc_mac, 'secure'):
                log.error("Mac learning failed on primary")
                self.failed("Mac learning failed on primary")

            if not verify_secure_mac_on_vteps(sec_vtep, '1001', 1025, prim_vpc_mac, 'secure'):
                log.error("Mac learning failed on primary")
                self.failed("Mac learning failed on primary")
                
            if not verify_secure_mac_on_vteps(sa_vtep, '1001', 1025, prim_vpc_mac):
                log.error("Mac learning failed on standalone")
                self.failed("Mac learning failed on standalone")

        stream1.StopStatelessTraffic()
        log.info('Waiting {}secs to stop the traffic'.format(traffic_stop_time))
        time.sleep(traffic_stop_time)

        with steps.start("Verify Steady State after trigger"):
            if VerifyTraffic("Test_016_VPC", testscript, traffic_item='Access VPC To Standalone'):
                log.info('Verify Traffic Success after trigger')
            else:
                self.failed('Verify Traffic Failed after trigger')

        with steps.start('Verify Learned mac address consistency between hardware and software'):
            if verify_mac_cc_between_hardware_software([prim_vtep, sec_vtep, sa_vtep]):
                self.passed('MAC CC success')
            else:
                self.failed('MAC CC failed')

    @aetest.test
    def verify_default_fex_interface(self, testscript, testbed, steps):
        sa_vtep         = testscript.parameters['LEAF-3']
        prim_vtep       = testscript.parameters['LEAF-1']
        sec_vtep        = testscript.parameters['LEAF-2']
        fex_vtep_if     = str(testscript.parameters['intf_LEAF_1_FEX_to_IXIA'])
        prim_fex_mac    = str(testscript.parameters['PORTSEC_Dict']['prim_fex_mac'])
        ixNetwork       = testscript.parameters['ixNetwork']
        p1_handle       = testscript.parameters['fex_handle']
        p2_handle       = testscript.parameters['sa_handle']

        with steps.start("Starting hosts..."):
            p1_handle.Start()
            p2_handle.Start()
        
        log.info('Waiting {}secs to start 1025 hosts'.format(host_start_time))
        time.sleep(host_start_time)
    
        stream1 = ixNetwork.Traffic.TrafficItem.find(Name='Access FEX To Standalone')        
        stream1.StartStatelessTraffic()
        log.info('Waiting {}secs to start the traffic'.format(traffic_start_time))
        time.sleep(traffic_start_time)
        
        with steps.start('Doing Config backup on VPC Primary'):
            prim_vtep.execute('delete bootflash:{cr_file} no-prompt'.format(cr_file=cr_file))
            prim_vtep.execute("copy running-config bootflash:{cr_file}".format(cr_file=cr_file))
        
        with steps.start('Doing default fex interface on Primary'):
            try:
                prim_vtep.configure('''default interface {intf2}'''.format(intf2=fex_vtep_if))
            except Exception as error:
                log.debug("Unable to configure - Encountered Exception " + str(error))
                self.errored('Exception occurred while configuring PVMAP', 
                             goto=['common_cleanup'])

        log.info('Waiting 30secs for Mac flushout')
        time.sleep(30)
        
        with steps.start("Checking mac flushout on local and remote after default fex interface"):
            if not verify_port_sec_addr_count(prim_vtep, fex_vtep_if, 0, 'STICKY'):
                log.error("DYNAMIC Mac learning failed")
                self.failed("DYNAMIC Mac learning failed")

            if not verify_secure_mac_on_vteps(prim_vtep, '1001', 0, prim_fex_mac, 'secure'):
                log.error("Mac learning failed on primary")
                self.failed("Mac learning failed on primary")
            if not verify_secure_mac_on_vteps(sec_vtep, '1001', 0, prim_fex_mac, 'secure'):
                log.error("Mac learning failed on primary")
                self.failed("Mac learning failed on primary")
            if not verify_secure_mac_on_vteps(sa_vtep, '1001', 0, prim_fex_mac):
                log.error("Mac learning failed on standalone")
                self.failed("Mac learning failed on standalone")
		
        with steps.start('Doing Config Replace Fex interface'):
            if verify_config_replace([prim_vtep], log):
                log.info('Config-Replace success')
            else:
                self.failed('Config-Replace failed')
       
        log.info('Waiting 60secs for mac relearning')
        time.sleep(60)
        
        with steps.start("Checking mac learning after fex after trigger"):
            if not verify_port_sec_addr_count(prim_vtep, fex_vtep_if, 1025, 'STICKY'):
                log.error("Mac learning failed")
                self.failed("Mac learning failed")

            if not verify_secure_mac_on_vteps(prim_vtep, '1001', 1025, prim_fex_mac, 'secure'):
                log.error("Mac learning failed on primary")
                self.failed("Mac learning failed on primary")
            if not verify_secure_mac_on_vteps(sec_vtep, '1001', 1025, prim_fex_mac, 'secure'):
                log.error("Mac learning failed on primary")
                self.failed("Mac learning failed on primary")
            if not verify_secure_mac_on_vteps(sa_vtep, '1001', 1025, prim_fex_mac):
                log.error("Mac learning failed on standalone")
                self.failed("Mac learning failed on standalone")
        
        stream1.StopStatelessTraffic()
        log.info('Waiting {}secs to stop the traffic'.format(traffic_stop_time))
        time.sleep(traffic_stop_time)
        
        with steps.start("Verify Steady State after trigger"):
            if VerifyTraffic("Test_016_FEX", testscript, traffic_item='Access FEX To Standalone'):
                log.info('Verify Traffic success after fex idefault interface and config-replace')
            else:
                self.failed('Verify Traffic failed after fex default interface and config-replace')

        with steps.start('Verify Learned mac address consistency between hardware and software'):
            if verify_mac_cc_between_hardware_software([prim_vtep, sec_vtep, sa_vtep]):
                self.passed('MAC CC success')
            else:
                self.failed('MAC CC failed')
    
    @aetest.test
    def test_cleanup(self, testscript, testbed, steps):
        sa_vtep         = testscript.parameters['LEAF-3']
        prim_vtep       = testscript.parameters['LEAF-1']
        sec_vtep        = testscript.parameters['LEAF-2']
        prim_vtep_if    = str(testscript.parameters['intf_LEAF_1_1_to_IXIA'])
        sa_vtep_if      = str(testscript.parameters['intf_LEAF_3_to_IXIA'])
        leaf1_mac       = str(testscript.parameters['PORTSEC_Dict']['vpc_static_mac'])
        fex_vtep_if     = str(testscript.parameters['intf_LEAF_1_FEX_to_IXIA'])
        src_vlan        = int(testscript.parameters['LEAF_1_Orphan1_TGEN_dict']['vlan_id'])
        ixNetwork       = testscript.parameters['ixNetwork']
        
        with steps.start("Stopping all hosts..."):
            ixNetwork.StopAllProtocols()

        log.info('Waiting {}secs to stop the hosts'.format(traffic_stop_time))
        time.sleep(traffic_stop_time)
        
        with steps.start("UnConfigure Port-Security on Primary VTEP Orphan"):
            if not unconfig_interface_ps([prim_vtep], prim_vtep_if, log):
                self.errored('Exception occurred while configuring port security', goto=['common_cleanup'])
        
        with steps.start("UnConfigure Port-Security on Standalone VTEP"):
            if not unconfig_interface_ps([sa_vtep], sa_vtep_if, log):
                self.errored('Exception occurred while configuring port security', goto=['common_cleanup'])
        
        with steps.start("UnConfigure Port-Security on VPC Primary/Secondary - Static"):
            new_config = 'no switchport port-security mac-address {mac}'.format(mac=leaf1_mac)
            if not unconfig_interface_ps([prim_vtep, sec_vtep], 'port-channel 11', log, new_config):
                self.errored('Exception occurred while configuring port security', goto=['common_cleanup'])
        
        with steps.start("UnConfigure Port-Security on Leaf-1 FEX - FEX port of VTEP"):
            new_config = 'no switchport port-security mac-address sticky'
            if not unconfig_interface_ps([prim_vtep], fex_vtep_if, log, new_config):
                self.errored('Exception occurred while configuring port security', goto=['common_cleanup'])
        
        with steps.start("Verifying MTS leak.."):
            if verify_mts_leak([prim_vtep, sec_vtep, sa_vtep], log):
                log.info('MTS Leak verification success')
            else:
                self.failed('MTS Leak verification failed')

        with steps.start("Verifying Cores and Log Errors"):
            status = infraVerify.postTestVerification(post_test_process_dict)
            if status['status'] == 0:
                self.failed(reason=status['logs'])
            else:
                self.passed(reason=status['logs'])

########################################################################################################
# Triggers 
########################################################################################################
# TC: VXLAN_PS_063
# Interface shutdown case - Trunk mode
#   - shut/no shut orphan port interface, fex port interface, vpc interface and vpc port-channel
########################################################################################################
class TC_VXLAN_PS_015_Access(aetest.Testcase):
    @aetest.test
    def test_setup(self, testscript, testbed, steps):
        sa_vtep         = testscript.parameters['LEAF-3']
        prim_vtep       = testscript.parameters['LEAF-1']
        sec_vtep        = testscript.parameters['LEAF-2']
        src_vlan        = int(testscript.parameters['LEAF_1_Orphan1_TGEN_dict']['vlan_id'])
        leaf1_mac       = str(testscript.parameters['PORTSEC_Dict']['vpc_static_mac'])
        prim_vtep_if    = str(testscript.parameters['intf_LEAF_1_1_to_IXIA'])
        sa_vtep_if      = str(testscript.parameters['intf_LEAF_3_to_IXIA'])
        fex_vtep_if     = str(testscript.parameters['intf_LEAF_1_FEX_to_IXIA'])
        
        new_config = '''switchport port-security aging type inactivity
                        switchport port-security violation restrict'''
        with steps.start("Configure Port-Security on Primary VTEP Orphan"):
            if not config_interface_ps([prim_vtep], prim_vtep_if, log, new_config):
                self.errored('Exception occurred while configuring port security', goto=['common_cleanup'])
        
        with steps.start("Configure Port-Security on Standalone VTEP"):
            if not config_interface_ps([sa_vtep], sa_vtep_if, log, new_config):
                self.errored('Exception occurred while configuring port security', goto=['common_cleanup'])
        
        with steps.start("Configure Port-Security on Leaf-1 FEX - FEX port of VTEP"):
            if not config_interface_ps([prim_vtep], fex_vtep_if, log, new_config):
                self.errored('Exception occurred while configuring port security', goto=['common_cleanup'])

        new_config = '''switchport port-security aging type inactivity
                        switchport port-security violation restrict
                        switchport port-security mac-address {mac}'''.format(mac=leaf1_mac)
        with steps.start("Configure Port-Security on VPC Primary/Secondary - Static"):
            if not config_interface_ps([prim_vtep, sec_vtep], 'port-channel 11', log, new_config):
                self.errored('Exception occurred while configuring port security', goto=['common_cleanup'])
        
        log.info("Waiting {}secs for interface to come up".format(config_time))
        time.sleep(config_time)
        display_configs(testscript)

    # Flap port-security interface on VPC orphan and standalone
    @aetest.test
    def verify_flap_standalone_and_orphan_interface(self, testscript, testbed, steps):
        sa_vtep         = testscript.parameters['LEAF-3']
        prim_vtep       = testscript.parameters['LEAF-1']
        sec_vtep        = testscript.parameters['LEAF-2']
        sa_vtep_if      = str(testscript.parameters['intf_LEAF_3_to_IXIA'])
        prim_vtep_if    = str(testscript.parameters['intf_LEAF_1_1_to_IXIA'])
        sa_mac          = str(testscript.parameters['PORTSEC_Dict']['sa_mac'])
        prim_mac        = str(testscript.parameters['PORTSEC_Dict']['prim_orphan_mac'])
        ixNetwork       = testscript.parameters['ixNetwork']
        p1_handle       = testscript.parameters['orphan1_handle']
        p2_handle       = testscript.parameters['sa_handle']

        with steps.start("Starting hosts..."):
            p1_handle.Start()
            p2_handle.Start()
        
        log.info('Waiting {}secs to start 1025 hosts'.format(host_start_time))
        time.sleep(host_start_time)

        stream1 = ixNetwork.Traffic.TrafficItem.find(Name='Access Orphan To Standalone')
        stream1.StartStatelessTraffic()
        log.info('Waiting {}secs to start the traffic'.format(traffic_start_time))
        time.sleep(traffic_start_time)
        
        with steps.start('Shut standalone port-security interface and VPC orphan interface'):
            sa_vtep.configure('''interface {intf1}
                                 shut'''.format(intf1=sa_vtep_if))
            prim_vtep.configure('''interface {intf2}
                                 shut
                              '''.format(intf2=prim_vtep_if))
        
        with steps.start("Checking Mac flushout on standalone and remote vtep after shut"):
            if not verify_port_sec_addr_count(sa_vtep, sa_vtep_if, 0, 'DYNAMIC'):
                log.error("DYNAMIC Mac learning failed")
                self.failed("DYNAMIC Mac learning failed")

            if not verify_secure_mac_on_vteps(sa_vtep, '1002', 0, sa_mac, 'secure'):
                log.error("Mac learning failed on Standalone")
                self.failed("Mac learning failed on Standalone")

            if not verify_secure_mac_on_vteps(prim_vtep, '1002', 0, sa_mac):
                log.error("DYNAMIC Mac learning failed on remote vtep(leaf1)")
                self.failed("DYNAMIC Mac learning failed on remote vtep(leaf1)")

            if not verify_secure_mac_on_vteps(sec_vtep, '1002', 0, sa_mac):
                log.error("DYNAMIC Mac learning failed on remote vtep(leaf2)")
                self.failed("DYNAMIC Mac learning failed on remote vtep(leaf2)")
        
        with steps.start("Checking Mac flushout on local and remote vtep for shut \
                         of orphan interface"):
            if not verify_port_sec_addr_count(prim_vtep, prim_vtep_if, 0, 'DYNAMIC'):
                log.error("DYNAMIC Mac learning failed")
                self.failed("DYNAMIC Mac learning failed")

            if not verify_secure_mac_on_vteps(prim_vtep, '1001', 0, prim_mac, 'secure'):
                log.error("Mac learning failed on primary")
                self.failed("Mac learning failed on primary")

            if not verify_secure_mac_on_vteps(sec_vtep, '1001', 0, prim_mac, 'secure'):
                log.error("DYNAMIC Mac learning failed on remote vtep(leaf2)")
                self.failed("DYNAMIC Mac learning failed on remote vtep(leaf2)")

            if not verify_secure_mac_on_vteps(sa_vtep, '1001', 0, prim_mac):
                log.error("Mac learning failed on standalone")
                self.failed("Mac learning failed on standalone")

        with steps.start('No Shut of standalone port-security interface and VPC orphan interface'):
            sa_vtep.configure('''interface {intf1}
                                 no shut'''.format(intf1=sa_vtep_if))
            prim_vtep.configure('''interface {intf2}
                                   no shut
                                '''.format(intf2=prim_vtep_if))
        
        log.info('Waiting 30secs for mac relearning')
        time.sleep(30)
        
        with steps.start("Checking mac relearning on standalone and remote after no shut"):
            if not verify_port_sec_addr_count(sa_vtep, sa_vtep_if, 1025, 'DYNAMIC'):
                log.error("DYNAMIC Mac learning failed")
                self.failed("DYNAMIC Mac learning failed")

            if not verify_secure_mac_on_vteps(sa_vtep, '1002', 1025, sa_mac, 'secure'):
                log.error("Mac learning failed on Standalone")
                self.failed("Mac learning failed on Standalone")

            if not verify_secure_mac_on_vteps(prim_vtep, '1002', 1025, sa_mac):
                log.error("DYNAMIC Mac learning failed on remote vtep(leaf1)")
                self.failed("DYNAMIC Mac learning failed on remote vtep(leaf1)")

            if not verify_secure_mac_on_vteps(sec_vtep, '1002', 1025, sa_mac):
                log.error("DYNAMIC Mac learning failed on remote vtep(leaf2)")
                self.failed("DYNAMIC Mac learning failed on remote vtep(leaf2)")

        with steps.start("Checking Mac relearning on vpc vteps and remote vtep after no shut"):
            if not verify_port_sec_addr_count(prim_vtep, prim_vtep_if, 1025, 'DYNAMIC'):
                log.error("DYNAMIC Mac learning failed")
                self.failed("DYNAMIC Mac learning failed")

            if not verify_secure_mac_on_vteps(prim_vtep, '1001', 1025, prim_mac, 'secure'):
                log.error("Mac learning failed on primary")
                self.failed("Mac learning failed on primary")

            if not verify_secure_mac_on_vteps(sec_vtep, '1001', 1025, prim_mac, 'secure'):
                log.error("DYNAMIC Mac learning failed on remote vtep(leaf2)")
                self.failed("DYNAMIC Mac learning failed on remote vtep(leaf2)")

            if not verify_secure_mac_on_vteps(sa_vtep, '1001', 1025, prim_mac):
                log.error("Mac learning failed on standalone")
                self.failed("Mac learning failed on standalone")

        stream1.StopStatelessTraffic()
        log.info('Waiting {}secs to stop the traffic'.format(traffic_stop_time))
        time.sleep(traffic_stop_time)
        
        with steps.start("Verify Steady State after interface flap"):
            if VerifyTraffic("Test_017_Orphan", testscript, traffic_item='Access Orphan To Standalone'):
                log.info('Verify traffic success after flap')
            else:
                self.failed('Verify traffic failed after flap')

        with steps.start('Verify Learned mac address consistency between hardware and software'):
            if verify_mac_cc_between_hardware_software([prim_vtep, sec_vtep, sa_vtep]):
                self.passed('MAC CC success')
            else:
                self.failed('MAC CC failed')
    
    @aetest.test
    def verify_portchannel_flap(self, testscript, testbed, steps):
        sa_vtep         = testscript.parameters['LEAF-3']
        prim_vtep       = testscript.parameters['LEAF-1']
        sec_vtep        = testscript.parameters['LEAF-2']
        prim_vpc_mac    = str(testscript.parameters['PORTSEC_Dict']['prim_vpc_mac'])
        ixNetwork       = testscript.parameters['ixNetwork']
        p1_handle       = testscript.parameters['vpc_handle']
        p2_handle       = testscript.parameters['sa_handle']
        
        with steps.start("Starting hosts.."):
            p1_handle.Start()
            p2_handle.Start()
        
        log.info('Waiting {}secs to start 1025 hosts'.format(host_start_time))
        time.sleep(host_start_time)
    
        stream1 = ixNetwork.Traffic.TrafficItem.find(Name='Access VPC To Standalone')
        stream1.StartStatelessTraffic()
        log.info('Waiting {}secs to start the traffic'.format(traffic_start_time))
        time.sleep(traffic_start_time)
        
        with steps.start('shut primary portchannel'):
            prim_vtep.configure('''interface port-channel 11
                                   shut''')
        
        log.info('Waiting 30secs for mac flushout')    
        time.sleep(30)
        
        with steps.start("Checking mac learning on local and remote vtep"):
            if not verify_port_sec_addr_count(prim_vtep, 'port-channel 11', 1, 'STATIC'):
                log.error("STATIC Mac learning failed")
                self.failed("STATIC Mac learning failed")
        
            if not verify_port_sec_addr_count(prim_vtep, 'port-channel 11', 1024, 'DYNAMIC'):
                log.error("DYNAMIC Mac learning failed")
                self.failed("DYNAMIC Mac learning failed")

            if not verify_port_sec_addr_count(sec_vtep, 'port-channel 11', 1, 'STATIC'):
                log.error("STATIC Mac learning failed")
                self.failed("STATIC Mac learning failed")
        
            if not verify_port_sec_addr_count(sec_vtep, 'port-channel 11', 1024, 'DYNAMIC'):
                log.error("DYNAMIC Mac learning failed")
                self.failed("DYNAMIC Mac learning failed")
            
            if not verify_secure_mac_on_vteps(prim_vtep, '1001', 1025, prim_vpc_mac, 'secure'):
                log.error("Mac learning failed on primary")
                self.failed("Mac learning failed on primary")

            if not verify_secure_mac_on_vteps(sec_vtep, '1001', 1025, prim_vpc_mac, 'secure'):
                log.error("Mac learning failed on primary")
                self.failed("Mac learning failed on primary")
                
            if not verify_secure_mac_on_vteps(sa_vtep, '1001', 1025, prim_vpc_mac):
                log.error("Mac learning failed on standalone")
                self.failed("Mac learning failed on standalone")
        
        with steps.start('shut - secondary vtep port-channel'):
            sec_vtep.configure('''interface port-channel 11
                                   shut''')
        
        log.info('Waiting 30secs for mac flushout')
        time.sleep(30)

        with steps.start("Checking mac learning on local and remote vtep"):
            if not verify_port_sec_addr_count(prim_vtep, 'port-channel 11', 1, 'STATIC'):
                log.error("STATIC Mac learning failed")
                self.failed("STATIC Mac learning failed")
        
            if not verify_port_sec_addr_count(prim_vtep, 'port-channel 11', 0, 'DYNAMIC'):
                log.error("DYNAMIC Mac learning failed")
                self.failed("DYNAMIC Mac learning failed")

            if not verify_port_sec_addr_count(sec_vtep, 'port-channel 11', 0, 'STATIC'):
                log.error("STATIC Mac learning failed")
                self.failed("STATIC Mac learning failed")
        
            if not verify_port_sec_addr_count(sec_vtep, 'port-channel 11', 0, 'DYNAMIC'):
                log.error("DYNAMIC Mac learning failed")
                self.failed("DYNAMIC Mac learning failed")
            
            if not verify_secure_mac_on_vteps(prim_vtep, '1001', 0, prim_vpc_mac, 'secure'):
                log.error("Mac learning failed on primary")
                self.failed("Mac learning failed on primary")

            if not verify_secure_mac_on_vteps(sec_vtep, '1001', 0, prim_vpc_mac, 'secure'):
                log.error("Mac learning failed on primary")
                self.failed("Mac learning failed on primary")
                
            if not verify_secure_mac_on_vteps(sa_vtep, '1001', 0, prim_vpc_mac):
                log.error("Mac learning failed on standalone")
                self.failed("Mac learning failed on standalone")

        with steps.start('no shut - primary / secondary vtep port-channel'):
            prim_vtep.configure('''interface port-channel 11
                                   no shut''')
            sec_vtep.configure('''interface port-channel 11
                                  no shut''')
        
        log.info('Waiting 30secs for mac relearning')
        time.sleep(30)
        
        with steps.start("Checking mac learning on local and remote vtep"):
            if not verify_port_sec_addr_count(prim_vtep, 'port-channel 11', 1, 'STATIC'):
                log.error("STATIC Mac learning failed")
                self.failed("STATIC Mac learning failed")
        
            if not verify_port_sec_addr_count(prim_vtep, 'port-channel 11', 1024, 'DYNAMIC'):
                log.error("DYNAMIC Mac learning failed")
                self.failed("DYNAMIC Mac learning failed")

            if not verify_port_sec_addr_count(sec_vtep, 'port-channel 11', 1, 'STATIC'):
                log.error("STATIC Mac learning failed")
                self.failed("STATIC Mac learning failed")
        
            if not verify_port_sec_addr_count(sec_vtep, 'port-channel 11', 1024, 'DYNAMIC'):
                log.error("DYNAMIC Mac learning failed")
                self.failed("DYNAMIC Mac learning failed")
            
            if not verify_secure_mac_on_vteps(prim_vtep, '1001', 1025, prim_vpc_mac, 'secure'):
                log.error("Mac learning failed on primary")
                self.failed("Mac learning failed on primary")

            if not verify_secure_mac_on_vteps(sec_vtep, '1001', 1025, prim_vpc_mac, 'secure'):
                log.error("Mac learning failed on primary")
                self.failed("Mac learning failed on primary")
                
            if not verify_secure_mac_on_vteps(sa_vtep, '1001', 1025, prim_vpc_mac):
                log.error("Mac learning failed on standalone")
                self.failed("Mac learning failed on standalone")

        stream1.StopStatelessTraffic()
        log.info('Waiting {}secs to stop the traffic'.format(traffic_stop_time))
        time.sleep(traffic_stop_time)

        with steps.start("Verify Steady State"):
            if VerifyTraffic("Test_017_VPC", testscript, traffic_item='Access VPC To Standalone'):
                log.info('Verify Traffic Success after interface flap')
            else:
                self.failed('Verify Traffic Failed after interface flap')

        with steps.start('Verify Learned mac address consistency between hardware and software'):
            if verify_mac_cc_between_hardware_software([prim_vtep, sec_vtep, sa_vtep]):
                self.passed('MAC CC success')
            else:
                self.failed('MAC CC failed')

    @aetest.test
    def verify_fex_interface_flap(self, testscript, testbed, steps):
        sa_vtep         = testscript.parameters['LEAF-3']
        prim_vtep       = testscript.parameters['LEAF-1']
        sec_vtep        = testscript.parameters['LEAF-2']
        fex_vtep_if     = str(testscript.parameters['intf_LEAF_1_FEX_to_IXIA'])
        prim_fex_mac    = str(testscript.parameters['PORTSEC_Dict']['prim_fex_mac'])
        ixNetwork       = testscript.parameters['ixNetwork']
        p1_handle       = testscript.parameters['fex_handle']
        p2_handle       = testscript.parameters['sa_handle']
        
        with steps.start('Starting hosts...'):
            p1_handle.Start()
            p2_handle.Start()
        
        log.info('Waiting {}secs to start 1025 hosts'.format(host_start_time))
        time.sleep(host_start_time)
    
        stream1 = ixNetwork.Traffic.TrafficItem.find(Name='Access FEX To Standalone')
        stream1.StartStatelessTraffic()
        log.info('Waiting {}secs to start the traffic'.format(traffic_start_time))
        time.sleep(traffic_start_time)
        
        with steps.start('Shut FEX interface'):
            prim_vtep.configure('''inter {intf}
                                   shut
                                '''.format(intf=fex_vtep_if))
        
        log.info('Waiting 30secs for Mac flushout')
        time.sleep(30)
        
        with steps.start("Checking mac flushout on local and remote"):
            if not verify_port_sec_addr_count(prim_vtep, fex_vtep_if, 0, 'DYNAMIC'):
                log.error("DYNAMIC Mac learning failed")
                self.failed("DYNAMIC Mac learning failed")

            if not verify_secure_mac_on_vteps(prim_vtep, '1001', 0, prim_fex_mac, 'secure'):
                log.error("Mac learning failed on primary")
                self.failed("Mac learning failed on primary")
            if not verify_secure_mac_on_vteps(sec_vtep, '1001', 0, prim_fex_mac, 'secure'):
                log.error("Mac learning failed on primary")
                self.failed("Mac learning failed on primary")
            if not verify_secure_mac_on_vteps(sa_vtep, '1001', 0, prim_fex_mac):
                log.error("Mac learning failed on standalone")
                self.failed("Mac learning failed on standalone")
		
        with steps.start('No Shut FEX interface'):
            prim_vtep.configure('''inter {intf}
                                   no shut
                                '''.format(intf=fex_vtep_if))
        
        log.info('Waiting 30secs for Mac relearning')
        time.sleep(30)
        
        with steps.start("Checking mac learning after fex interface flap"):
            if not verify_port_sec_addr_count(prim_vtep, fex_vtep_if, 1025, 'DYNAMIC'):
                log.error("DYNAMIC Mac learning failed")
                self.failed("DYNAMIC Mac learning failed")

            if not verify_secure_mac_on_vteps(prim_vtep, '1001', 1025, prim_fex_mac, 'secure'):
                log.error("Mac learning failed on primary")
                self.failed("Mac learning failed on primary")
            if not verify_secure_mac_on_vteps(sec_vtep, '1001', 1025, prim_fex_mac, 'secure'):
                log.error("Mac learning failed on primary")
                self.failed("Mac learning failed on primary")
            if not verify_secure_mac_on_vteps(sa_vtep, '1001', 1025, prim_fex_mac):
                log.error("Mac learning failed on standalone")
                self.failed("Mac learning failed on standalone")
        
        stream1.StopStatelessTraffic()
        log.info('Waiting {}secs to stop the traffic'.format(traffic_stop_time))
        time.sleep(traffic_stop_time)
        
        with steps.start("Verify Steady State after fex interface flap"):
            if VerifyTraffic("Test_017_FEX", testscript, traffic_item='Access FEX To Standalone'):
                log.info('Verify Traffic success after fex interface flap')
            else:
                log.debug('Verify Traffic failed after fex interface flap')

        with steps.start('Verify Learned mac address consistency between hardware and software'):
            if verify_mac_cc_between_hardware_software([prim_vtep, sec_vtep, sa_vtep]):
                self.passed('MAC CC success')
            else:
                self.failed('MAC CC failed')
    
    @aetest.test
    def test_cleanup(self, testscript, testbed, steps):
        sa_vtep         = testscript.parameters['LEAF-3']
        prim_vtep       = testscript.parameters['LEAF-1']
        sec_vtep        = testscript.parameters['LEAF-2']
        prim_vtep_if    = str(testscript.parameters['intf_LEAF_1_1_to_IXIA'])
        sa_vtep_if      = str(testscript.parameters['intf_LEAF_3_to_IXIA'])
        leaf1_mac       = str(testscript.parameters['PORTSEC_Dict']['vpc_static_mac'])
        src_vlan        = int(testscript.parameters['LEAF_1_Orphan1_TGEN_dict']['vlan_id'])
        fex_vtep_if     = str(testscript.parameters['intf_LEAF_1_FEX_to_IXIA'])
        ixNetwork       = testscript.parameters['ixNetwork']
        
        with steps.start("Stopping all hosts..."):
            ixNetwork.StopAllProtocols()

        log.info('Waiting {}secs to stop the hosts'.format(traffic_stop_time))
        time.sleep(traffic_stop_time)
        
        new_config = '''no switchport port-security aging type inactivity
                        no switchport port-security violation restrict'''
    
        with steps.start("UnConfigure Port-Security on Primary VTEP Orphan"):
            if not unconfig_interface_ps([prim_vtep], prim_vtep_if, log, new_config):
                self.errored('Exception occurred while configuring port security', goto=['common_cleanup'])
        
        with steps.start("UnConfigure Port-Security on Standalone VTEP"):
            if not unconfig_interface_ps([sa_vtep], sa_vtep_if, log, new_config):
                self.errored('Exception occurred while configuring port security', goto=['common_cleanup'])
        
        new_config = '''no switchport port-security aging type inactivity
                      no switchport port-security violation restrict
                      no switchport port-security mac-address {mac}'''.format(mac=leaf1_mac)
        with steps.start("UnConfigure Port-Security on VPC Primary/Secondary - Static"):
            
            if not unconfig_interface_ps([prim_vtep, sec_vtep], 'port-channel 11', log, new_config):
                self.errored('Exception occurred while configuring port security', goto=['common_cleanup'])
        
        new_config = '''no switchport port-security aging type inactivity
                        no switchport port-security violation restrict'''
        with steps.start("UnConfigure Port-Security on Leaf-1 FEX - FEX port of VTEP"):
            
            if not unconfig_interface_ps([prim_vtep], fex_vtep_if, log, new_config):
                self.errored('Exception occurred while configuring port security', goto=['common_cleanup'])
        
        log.info("Waiting {}secs for interface to come up".format(config_time))
        time.sleep(config_time)

        with steps.start("Verifying MTS leak.."):
            if verify_mts_leak([prim_vtep, sec_vtep, sa_vtep], log):
                log.info('MTS Leak verification success')
            else:
                self.failed('MTS Leak verification failed')

        with steps.start("Verifying Cores and Log Errors"):
            status = infraVerify.postTestVerification(post_test_process_dict)
            if status['status'] == 0:
                self.failed(reason=status['logs'])
            else:
                self.passed(reason=status['logs'])

########################################################################################################
# Triggers 
########################################################################################################
# TC: VXLAN_PS_063
# Uplink FLAP - Trunk Mode
#   - shut/no shut orphan port interface, fex port interface, vpc interface and vpc port-channel
########################################################################################################
class TC_VXLAN_PS_016_Access(aetest.Testcase):
    @aetest.test
    def test_setup(self, testscript, testbed, steps):
        sa_vtep         = testscript.parameters['LEAF-3']
        prim_vtep       = testscript.parameters['LEAF-1']
        sec_vtep        = testscript.parameters['LEAF-2']
        src_vlan        = int(testscript.parameters['LEAF_1_Orphan1_TGEN_dict']['vlan_id'])
        leaf1_mac       = str(testscript.parameters['PORTSEC_Dict']['vpc_static_mac'])
        prim_vtep_if    = str(testscript.parameters['intf_LEAF_1_1_to_IXIA'])
        sa_vtep_if      = str(testscript.parameters['intf_LEAF_3_to_IXIA'])
        fex_vtep_if     = str(testscript.parameters['intf_LEAF_1_FEX_to_IXIA'])
        
        new_config = '''switchport port-security aging type inactivity
                        switchport port-security mac-address sticky
                        switchport port-security violation restrict'''
        with steps.start("Configure Port-Security on Primary VTEP Orphan"):
            if not config_interface_ps([prim_vtep], prim_vtep_if, log, new_config):
                self.errored('Exception occurred while configuring port security', goto=['common_cleanup'])
        
        with steps.start("Configure Port-Security on Standalone VTEP"):
            if not config_interface_ps([sa_vtep], sa_vtep_if, log, new_config):
                self.errored('Exception occurred while configuring port security', goto=['common_cleanup'])
        
        new_config = '''switchport port-security aging type inactivity
                        switchport port-security violation restrict'''
        with steps.start("Configure Port-Security on Leaf-1 FEX - FEX port of VTEP"):
            if not config_interface_ps([prim_vtep], fex_vtep_if, log, new_config):
                self.errored('Exception occurred while configuring port security', goto=['common_cleanup'])

        new_config = '''switchport port-security aging type inactivity
                        switchport port-security violation restrict
                        switchport port-security mac-address {mac}'''.format(mac=leaf1_mac)
        with steps.start("Configure Port-Security on VPC Primary/Secondary"):
            if not config_interface_ps([prim_vtep, sec_vtep], 'port-channel 11', log, new_config):
                self.errored('Exception occurred while configuring port security', goto=['common_cleanup'])
        
        log.info("Waiting {}secs for interface to come up".format(config_time))
        time.sleep(config_time)
        display_configs(testscript)

    # Flap Uplink on VPC primary and standalone
    @aetest.test
    def verify_access_port_flap_standalone_and_orphan_interface(self, testscript, testbed, steps):
        sa_vtep         = testscript.parameters['LEAF-3']
        prim_vtep       = testscript.parameters['LEAF-1']
        sec_vtep        = testscript.parameters['LEAF-2']
        sa_vtep_if      = str(testscript.parameters['intf_LEAF_3_to_IXIA'])
        prim_vtep_if    = str(testscript.parameters['intf_LEAF_1_1_to_IXIA'])
        sa_mac          = str(testscript.parameters['PORTSEC_Dict']['sa_mac'])
        prim_mac        = str(testscript.parameters['PORTSEC_Dict']['prim_orphan_mac'])
        leaf1_uplink_if = str(testscript.parameters['intf_LEAF_1_to_SPINE'])
        leaf3_uplink_if = str(testscript.parameters['intf_LEAF_3_to_SPINE'])
        ixNetwork       = testscript.parameters['ixNetwork']
        p1_handle       = testscript.parameters['orphan1_handle']
        p2_handle       = testscript.parameters['sa_handle']
        
        with steps.start("Starting hosts..."):
            p1_handle.Start()
            p2_handle.Start()

        log.info('Waiting {}secs to start 1025 hosts'.format(host_start_time))
        time.sleep(host_start_time)
                
        stream1 = ixNetwork.Traffic.TrafficItem.find(Name='Access Orphan To Standalone')
        stream1.StartStatelessTraffic()
        log.info('Waiting {}secs to start the traffic'.format(traffic_start_time))
        time.sleep(traffic_start_time)
        
        with steps.start('Shut standalone and VPE uplink interface'):
            sa_vtep.configure('''interface {intf1}
                                 shut'''.format(intf1=leaf3_uplink_if))
            prim_vtep.configure('''interface {intf2}
                                 shut
                              '''.format(intf2=leaf1_uplink_if))
        
        with steps.start("Checking Mac flushout on standalone and remote vtep after uplink shut"):
            if not verify_port_sec_addr_count(sa_vtep, sa_vtep_if, 1025, 'STICKY'):
                log.error("DYNAMIC Mac learning failed")
                self.failed("DYNAMIC Mac learning failed")

            if not verify_secure_mac_on_vteps(sa_vtep, '1002', 1025, sa_mac, 'secure'):
                log.error("Mac learning failed on Standalone")
                self.failed("Mac learning failed on Standalone")

            if not verify_secure_mac_on_vteps(prim_vtep, '1002', 0, sa_mac):
                log.error("DYNAMIC Mac learning failed on remote vtep(leaf1)")
                self.failed("DYNAMIC Mac learning failed on remote vtep(leaf1)")

            if not verify_secure_mac_on_vteps(sec_vtep, '1002', 0, sa_mac):
                log.error("DYNAMIC Mac learning failed on remote vtep(leaf2)")
                self.failed("DYNAMIC Mac learning failed on remote vtep(leaf2)")
        
        with steps.start("Checking Mac flushout on VPC and remote vtep after uplink shut"):
            if not verify_port_sec_addr_count(prim_vtep, prim_vtep_if, 1025, 'STICKY'):
                log.error("DYNAMIC Mac learning failed")
                self.failed("DYNAMIC Mac learning failed")

            if not verify_secure_mac_on_vteps(prim_vtep, '1001', 1025, prim_mac, 'secure'):
                log.error("Mac learning failed on primary")
                self.failed("Mac learning failed on primary")

            if not verify_secure_mac_on_vteps(sec_vtep, '1001', 1025, prim_mac, 'secure'):
                log.error("DYNAMIC Mac learning failed on remote vtep(leaf2)")
                self.failed("DYNAMIC Mac learning failed on remote vtep(leaf2)")

            if not verify_secure_mac_on_vteps(sa_vtep, '1001', 0, prim_mac):
                log.error("Mac learning failed on standalone")
                self.failed("Mac learning failed on standalone")

        with steps.start('No Shut of standalone and VPC uplink interface'):
            sa_vtep.configure('''interface {intf1}
                                 no shut'''.format(intf1=leaf3_uplink_if))
            prim_vtep.configure('''interface {intf2}
                                   no shut
                                '''.format(intf2=leaf1_uplink_if))
        
        log.info('Waiting 90secs for mac relearning')
        time.sleep(90)
        
        with steps.start("Checking mac relearning on standalone and remote after no shut"):
            if not verify_port_sec_addr_count(sa_vtep, sa_vtep_if, 1025, 'STICKY'):
                log.error("DYNAMIC Mac learning failed")
                self.failed("DYNAMIC Mac learning failed")

            if not verify_secure_mac_on_vteps(sa_vtep, '1002', 1025, sa_mac, 'secure'):
                log.error("Mac learning failed on Standalone")
                self.failed("Mac learning failed on Standalone")

            if not verify_secure_mac_on_vteps(prim_vtep, '1002', 1025, sa_mac):
                log.error("DYNAMIC Mac learning failed on remote vtep(leaf1)")
                self.failed("DYNAMIC Mac learning failed on remote vtep(leaf1)")

            if not verify_secure_mac_on_vteps(sec_vtep, '1002', 1025, sa_mac):
                log.error("DYNAMIC Mac learning failed on remote vtep(leaf2)")
                self.failed("DYNAMIC Mac learning failed on remote vtep(leaf2)")

        with steps.start("Checking Mac relearning on vpc vteps and remote vtep after no shut"):
            if not verify_port_sec_addr_count(prim_vtep, prim_vtep_if, 1025, 'STICKY'):
                log.error("DYNAMIC Mac learning failed")
                self.failed("DYNAMIC Mac learning failed")

            if not verify_secure_mac_on_vteps(prim_vtep, '1001', 1025, prim_mac, 'secure'):
                log.error("Mac learning failed on primary")
                self.failed("Mac learning failed on primary")

            if not verify_secure_mac_on_vteps(sec_vtep, '1001', 1025, prim_mac, 'secure'):
                log.error("DYNAMIC Mac learning failed on remote vtep(leaf2)")
                self.failed("DYNAMIC Mac learning failed on remote vtep(leaf2)")

            if not verify_secure_mac_on_vteps(sa_vtep, '1001', 1025, prim_mac):
                log.error("Mac learning failed on standalone")
                self.failed("Mac learning failed on standalone")

        stream1.StopStatelessTraffic()
        log.info('Waiting {}secs to stop the traffic'.format(traffic_stop_time))
        time.sleep(traffic_stop_time)
        
        with steps.start("Verify Steady State after interface flap"):
            if VerifyTraffic("Test_018_Orphan", testscript, traffic_item='Access Orphan To Standalone'):
                log.info('Verify traffic success after flap')
            else:
                self.failed('Verify traffic failed after flap')

        with steps.start('Verify Learned mac address consistency between hardware and software'):
            if verify_mac_cc_between_hardware_software([prim_vtep, sec_vtep, sa_vtep]):
                self.passed('MAC CC success')
            else:
                self.failed('MAC CC failed')
    
    @aetest.test
    def verify_portchannel_flap(self, testscript, testbed, steps):
        sa_vtep         = testscript.parameters['LEAF-3']
        prim_vtep       = testscript.parameters['LEAF-1']
        sec_vtep        = testscript.parameters['LEAF-2']
        prim_vpc_mac    = str(testscript.parameters['PORTSEC_Dict']['prim_vpc_mac'])
        leaf1_uplink_if = str(testscript.parameters['intf_LEAF_1_to_SPINE'])
        leaf2_uplink_if = str(testscript.parameters['intf_LEAF_2_to_SPINE'])
        ixNetwork       = testscript.parameters['ixNetwork']
        p1_handle       = testscript.parameters['vpc_handle']
        p2_handle       = testscript.parameters['sa_handle']
        
        with steps.start("Starting hosts.."):
            p1_handle.Start()
            p2_handle.Start()
        
        log.info('Waiting {}secs to start 1025 hosts'.format(host_start_time))
        time.sleep(host_start_time)
    
        stream1 = ixNetwork.Traffic.TrafficItem.find(Name='Access VPC To Standalone')
        stream1.StartStatelessTraffic()
        log.info('Waiting {}secs to start the traffic'.format(traffic_start_time))
        time.sleep(traffic_start_time)
        
        with steps.start('Shut VPC Primary uplink interface'):
            prim_vtep.configure('''interface {intf2}
                                 shut
                              '''.format(intf2=leaf1_uplink_if))
        
        log.info('Waiting 60secs for mac flushout')    
        time.sleep(60)
        
        with steps.start("Checking mac learning on local and remote vtep"):
            if not verify_port_sec_addr_count(prim_vtep, 'port-channel 11', 1, 'STATIC'):
                log.error("STATIC Mac learning failed")
                self.failed("STATIC Mac learning failed")
        
            if not verify_port_sec_addr_count(prim_vtep, 'port-channel 11', 1024, 'DYNAMIC'):
                log.error("DYNAMIC Mac learning failed")
                self.failed("DYNAMIC Mac learning failed")

            if not verify_port_sec_addr_count(sec_vtep, 'port-channel 11', 1, 'STATIC'):
                log.error("STATIC Mac learning failed")
                self.failed("STATIC Mac learning failed")
        
            if not verify_port_sec_addr_count(sec_vtep, 'port-channel 11', 1024, 'DYNAMIC'):
                log.error("DYNAMIC Mac learning failed")
                self.failed("DYNAMIC Mac learning failed")
            
            if not verify_secure_mac_on_vteps(prim_vtep, '1001', 1025, prim_vpc_mac, 'secure'):
                log.error("Mac learning failed on primary")
                self.failed("Mac learning failed on primary")

            if not verify_secure_mac_on_vteps(sec_vtep, '1001', 1025, prim_vpc_mac, 'secure'):
                log.error("Mac learning failed on primary")
                self.failed("Mac learning failed on primary")
                
            if not verify_secure_mac_on_vteps(sa_vtep, '1001', 1025, prim_vpc_mac):
                log.error("Mac learning failed on standalone")
                self.failed("Mac learning failed on standalone")
        
        with steps.start('Shut VPC Secondary uplink interface'):
            sec_vtep.configure('''interface {intf2}
                                 shut
                              '''.format(intf2=leaf2_uplink_if))
        
        log.info('Waiting 60secs for mac flushout')
        time.sleep(60)

        with steps.start("Checking mac learning on local and remote vtep"):
            if not verify_port_sec_addr_count(prim_vtep, 'port-channel 11', 1, 'STATIC'):
                log.error("STATIC Mac learning failed")
                self.failed("STATIC Mac learning failed")
        
            if not verify_port_sec_addr_count(prim_vtep, 'port-channel 11', 1024, 'DYNAMIC'):
                log.error("DYNAMIC Mac learning failed")
                self.failed("DYNAMIC Mac learning failed")

            if not verify_port_sec_addr_count(sec_vtep, 'port-channel 11', 1, 'STATIC'):
                log.error("STATIC Mac learning failed")
                self.failed("STATIC Mac learning failed")
        
            if not verify_port_sec_addr_count(sec_vtep, 'port-channel 11', 1024, 'DYNAMIC'):
                log.error("DYNAMIC Mac learning failed")
                self.failed("DYNAMIC Mac learning failed")
            
            if not verify_secure_mac_on_vteps(prim_vtep, '1001', 1025, prim_vpc_mac, 'secure'):
                log.error("Mac learning failed on primary")
                self.failed("Mac learning failed on primary")

            if not verify_secure_mac_on_vteps(sec_vtep, '1001', 1025, prim_vpc_mac, 'secure'):
                log.error("Mac learning failed on primary")
                self.failed("Mac learning failed on primary")
                
            if not verify_secure_mac_on_vteps(sa_vtep, '1001', 0, prim_vpc_mac):
                log.error("Mac learning failed on standalone")
                self.failed("Mac learning failed on standalone")

        with steps.start('no shut - primary / secondary vtep port-channel'):
            prim_vtep.configure('''interface {intf2}
                                 no shut
                              '''.format(intf2=leaf1_uplink_if))
            sec_vtep.configure('''interface {intf2}
                                 no shut
                              '''.format(intf2=leaf2_uplink_if))
        
        log.info('Waiting 90secs for mac relearning')
        time.sleep(90)
        
        with steps.start("Checking mac learning on local and remote vtep"):
            if not verify_port_sec_addr_count(prim_vtep, 'port-channel 11', 1, 'STATIC'):
                log.error("STATIC Mac learning failed")
                self.failed("STATIC Mac learning failed")
        
            if not verify_port_sec_addr_count(prim_vtep, 'port-channel 11', 1024, 'DYNAMIC'):
                log.error("DYNAMIC Mac learning failed")
                self.failed("DYNAMIC Mac learning failed")

            if not verify_port_sec_addr_count(sec_vtep, 'port-channel 11', 1, 'STATIC'):
                log.error("STATIC Mac learning failed")
                self.failed("STATIC Mac learning failed")
        
            if not verify_port_sec_addr_count(sec_vtep, 'port-channel 11', 1024, 'DYNAMIC'):
                log.error("DYNAMIC Mac learning failed")
                self.failed("DYNAMIC Mac learning failed")
            
            if not verify_secure_mac_on_vteps(prim_vtep, '1001', 1025, prim_vpc_mac, 'secure'):
                log.error("Mac learning failed on primary")
                self.failed("Mac learning failed on primary")

            if not verify_secure_mac_on_vteps(sec_vtep, '1001', 1025, prim_vpc_mac, 'secure'):
                log.error("Mac learning failed on primary")
                self.failed("Mac learning failed on primary")
                
            if not verify_secure_mac_on_vteps(sa_vtep, '1001', 1025, prim_vpc_mac):
                log.error("Mac learning failed on standalone")
                self.failed("Mac learning failed on standalone")

        stream1.StopStatelessTraffic()
        log.info('Waiting {}secs to stop the traffic'.format(traffic_stop_time))
        time.sleep(traffic_stop_time)

        with steps.start("Verify Steady State"):
            if VerifyTraffic("Test_018_VPC", testscript, traffic_item='Access VPC To Standalone'):
                log.info('Verify Traffic Success after interface flap')
            else:
                self.failed('Verify Traffic Failed after interface flap')

        with steps.start('Verify Learned mac address consistency between hardware and software'):
            if verify_mac_cc_between_hardware_software([prim_vtep, sec_vtep, sa_vtep]):
                self.passed('MAC CC success')
            else:
                self.failed('MAC CC failed')

    @aetest.test
    def verify_fex_uplink_flap(self, testscript, testbed, steps):
        sa_vtep         = testscript.parameters['LEAF-3']
        prim_vtep       = testscript.parameters['LEAF-1']
        sec_vtep        = testscript.parameters['LEAF-2']
        fex_vtep_if     = str(testscript.parameters['intf_LEAF_1_FEX_to_IXIA'])
        prim_fex_mac    = str(testscript.parameters['PORTSEC_Dict']['prim_fex_mac'])
        leaf1_uplink_if = str(testscript.parameters['intf_LEAF_1_to_SPINE'])
        leaf2_uplink_if = str(testscript.parameters['intf_LEAF_2_to_SPINE'])
        ixNetwork       = testscript.parameters['ixNetwork']
        p1_handle       = testscript.parameters['fex_handle']
        p2_handle       = testscript.parameters['sa_handle']
        
        with steps.start('Starting hosts...'):
            p1_handle.Start()
            p2_handle.Start()
        
        log.info('Waiting {}secs to start 1025 hosts'.format(host_start_time))
        time.sleep(host_start_time)
    
        stream1 = ixNetwork.Traffic.TrafficItem.find(Name='Access FEX To Standalone')
        stream1.StartStatelessTraffic()
        log.info('Waiting {}secs to start the traffic'.format(traffic_start_time))
        time.sleep(traffic_start_time)
        
        with steps.start('Shut VPC Primary/secondary uplink interface'):
            prim_vtep.configure('''interface {intf2}
                                 shut
                              '''.format(intf2=leaf1_uplink_if))
            sec_vtep.configure('''interface {intf2}
                                 shut
                              '''.format(intf2=leaf2_uplink_if))
        
        log.info('Waiting 60secs for Mac flushout')
        time.sleep(60)
        
        with steps.start("Checking mac flushout on FEX vtep and remote"):
            if not verify_port_sec_addr_count(prim_vtep, fex_vtep_if, 1025, 'DYNAMIC'):
                log.error("DYNAMIC Mac learning failed")
                self.failed("DYNAMIC Mac learning failed")

            if not verify_secure_mac_on_vteps(prim_vtep, '1001', 1025, prim_fex_mac, 'secure'):
                log.error("Mac learning failed on primary")
                self.failed("Mac learning failed on primary")
            if not verify_secure_mac_on_vteps(sec_vtep, '1001', 1025, prim_fex_mac, 'secure'):
                log.error("Mac learning failed on primary")
                self.failed("Mac learning failed on primary")
            if not verify_secure_mac_on_vteps(sa_vtep, '1001', 0, prim_fex_mac):
                log.error("Mac learning failed on standalone")
                self.failed("Mac learning failed on standalone")
		
        with steps.start('No Shut VPC Primary uplink interface'):
            prim_vtep.configure('''interface {intf2}
                                 no shut
                              '''.format(intf2=leaf1_uplink_if))
            sec_vtep.configure('''interface {intf2}
                                 no shut
                              '''.format(intf2=leaf2_uplink_if))
        
        log.info('Waiting 90secs for Mac relearning')
        time.sleep(90)
        
        with steps.start("Checking mac learning after fex interface flap"):
            if not verify_port_sec_addr_count(prim_vtep, fex_vtep_if, 1025, 'DYNAMIC'):
                log.error("DYNAMIC Mac learning failed")
                self.failed("DYNAMIC Mac learning failed")

            if not verify_secure_mac_on_vteps(prim_vtep, '1001', 1025, prim_fex_mac, 'secure'):
                log.error("Mac learning failed on primary")
                self.failed("Mac learning failed on primary")
            if not verify_secure_mac_on_vteps(sec_vtep, '1001', 1025, prim_fex_mac, 'secure'):
                log.error("Mac learning failed on primary")
                self.failed("Mac learning failed on primary")
            if not verify_secure_mac_on_vteps(sa_vtep, '1001', 1025, prim_fex_mac):
                log.error("Mac learning failed on standalone")
                self.failed("Mac learning failed on standalone")
        
        stream1.StopStatelessTraffic()
        log.info('Waiting {}secs to stop the traffic'.format(traffic_stop_time))
        time.sleep(traffic_stop_time)
        
        with steps.start("Verify Steady State after fex interface flap"):
            if VerifyTraffic("Test_018_FEX", testscript, traffic_item='Access FEX To Standalone'):
                log.info('Verify Traffic success after fex interface flap')
            else:
                log.debug('Verify Traffic failed after fex interface flap')

        with steps.start('Verify Learned mac address consistency between hardware and software'):
            if verify_mac_cc_between_hardware_software([prim_vtep, sec_vtep, sa_vtep]):
                self.passed('MAC CC success')
            else:
                self.failed('MAC CC failed')
    
    @aetest.test
    def test_cleanup(self, testscript, testbed, steps):
        sa_vtep         = testscript.parameters['LEAF-3']
        prim_vtep       = testscript.parameters['LEAF-1']
        sec_vtep        = testscript.parameters['LEAF-2']
        prim_vtep_if    = str(testscript.parameters['intf_LEAF_1_1_to_IXIA'])
        sa_vtep_if      = str(testscript.parameters['intf_LEAF_3_to_IXIA'])
        leaf1_mac       = str(testscript.parameters['PORTSEC_Dict']['vpc_static_mac'])
        src_vlan        = int(testscript.parameters['LEAF_1_Orphan1_TGEN_dict']['vlan_id'])
        fex_vtep_if     = str(testscript.parameters['intf_LEAF_1_FEX_to_IXIA'])  
        ixNetwork       = testscript.parameters['ixNetwork']
        leaf1_uplink_if = str(testscript.parameters['intf_LEAF_1_to_SPINE'])
        leaf2_uplink_if = str(testscript.parameters['intf_LEAF_2_to_SPINE'])
        leaf3_uplink_if = str(testscript.parameters['intf_LEAF_3_to_SPINE'])
        
        with steps.start("Stopping all hosts..."):
            ixNetwork.StopAllProtocols()

        log.info('Waiting {}secs to stop the hosts'.format(traffic_stop_time))
        time.sleep(traffic_stop_time)
        
        new_config = '''no switchport port-security aging type inactivity
                        no switchport port-security violation restrict
                        no switchport port-security mac-address sticky'''
    
        with steps.start("UnConfigure Port-Security on Primary VTEP Orphan"):
            if not unconfig_interface_ps([prim_vtep], prim_vtep_if, log, new_config):
                self.errored('Exception occurred while configuring port security', goto=['common_cleanup'])
        
        with steps.start("UnConfigure Port-Security on Standalone VTEP"):
            if not unconfig_interface_ps([sa_vtep], sa_vtep_if, log, new_config):
                self.errored('Exception occurred while configuring port security', goto=['common_cleanup'])
        
        new_config = '''no switchport port-security aging type inactivity
                      no switchport port-security violation restrict
                      no switchport port-security mac-address {mac}'''.format(mac=leaf1_mac)
        with steps.start("UnConfigure Port-Security on VPC Primary/Secondary - Static"):
            
            if not unconfig_interface_ps([prim_vtep, sec_vtep], 'port-channel 11', log, new_config):
                self.errored('Exception occurred while configuring port security', goto=['common_cleanup'])
        
        new_config = '''no switchport port-security aging type inactivity
                        no switchport port-security violation restrict'''
        with steps.start("UnConfigure Port-Security on Leaf-1 FEX - FEX port of VTEP"):
            if not unconfig_interface_ps([prim_vtep], fex_vtep_if, log, new_config):
                self.errored('Exception occurred while configuring port security', goto=['common_cleanup'])

        with steps.start('no shut - uplink interfaces on all nodes'):
            prim_vtep.configure('''interface {intf2}
                                 no shut
                              '''.format(intf2=leaf1_uplink_if))
            sec_vtep.configure('''interface {intf2}
                                 no shut
                              '''.format(intf2=leaf2_uplink_if))
            sa_vtep.configure('''interface {intf1}
                                 no shut'''.format(intf1=leaf3_uplink_if))
        
        log.info("Waiting {}secs for interface to come up".format(config_time))
        time.sleep(config_time)
        
        with steps.start("Verifying MTS leak.."):
            if verify_mts_leak([prim_vtep, sec_vtep, sa_vtep], log):
                log.info('MTS Leak verification success')
            else:
                self.failed('MTS Leak verification failed')

        with steps.start("Verifying Cores and Log Errors"):
            exclude_bkp = post_test_process_dict['exclude_log_check_pattern']
            post_test_process_dict['exclude_log_check_pattern'] = str(exclude_bkp) + '|BGP-5-ADJCHANGE'
            status = infraVerify.postTestVerification(post_test_process_dict)
            if status['status'] == 0:
                self.failed(reason=status['logs'])
            else:
                self.passed(reason=status['logs'])
            post_test_process_dict['exclude_log_check_pattern'] = exclude_bkp

########################################################################################################
# Triggers 
########################################################################################################
# TC: VXLAN_PS_067
# NVE FLAP - Trunk Mode
########################################################################################################
class TC_VXLAN_PS_017_Access(aetest.Testcase):
    @aetest.test
    def test_setup(self, testscript, testbed, steps):
        log.info("STARTING NVE FLAP case ...")
        sa_vtep         = testscript.parameters['LEAF-3']
        prim_vtep       = testscript.parameters['LEAF-1']
        sec_vtep        = testscript.parameters['LEAF-2']
        src_vlan        = int(testscript.parameters['LEAF_1_Orphan1_TGEN_dict']['vlan_id'])
        leaf1_mac       = str(testscript.parameters['PORTSEC_Dict']['vpc_static_mac'])
        leaf2_mac       = str(testscript.parameters['PORTSEC_Dict']['vpc_static_mac1'])
        prim_vtep_if    = str(testscript.parameters['intf_LEAF_1_1_to_IXIA'])
        sa_vtep_if      = str(testscript.parameters['intf_LEAF_3_to_IXIA'])
        fex_vtep_if     = str(testscript.parameters['intf_LEAF_1_FEX_to_IXIA'])
        
        with steps.start("Configure Port-Security - Dynamic on Leaf-1 - Primary VTEP Orphan"):
            try:
                prim_vtep.configure('''interface {prim_vtep_if}
                                    switchport port-security maximum 1025
                                    switchport port-security aging type inactivity
                                    switchport port-security violation restrict
                                    switchport port-security
                                    no shutdown
                                    '''.format(prim_vtep_if=prim_vtep_if))
            except Exception as error:
                log.debug("Unable to configure - Encountered Exception " + str(error))
                self.errored('Exception occurred while configuring port security', goto=['common_cleanup'])
         
        with steps.start("Configure Port-Security - Dynamic on Leaf-3 - Standalone VTEP"):
            try:
                sa_vtep.configure('''interface {sa_vtep_if}
                                    switchport port-security maximum 1025
                                    switchport port-security aging type inactivity
                                    switchport port-security violation restrict
                                    switchport port-security
                                    no shutdown
                                    '''.format(sa_vtep_if=sa_vtep_if))
            except Exception as error:
                log.debug("Unable to configure - Encountered Exception " + str(error))
                self.errored('Exception occurred while configuring port security', goto=['common_cleanup'])

        with steps.start("Configure Port-Security on Leaf1(Primary) - Static and Sticky on port-channel 11"):
            try:
                prim_vtep.configure('''interface port-channel 11
                                no switchport port-security
                                shutdown
                                switchport port-security mac-address {mac}
                                switchport port-security aging type inactivity
                                switchport port-security violation restrict
                                switchport port-security
                                no shutdown 
                            '''.format(mac=leaf1_mac))
            except Exception as error:
                log.debug("Unable to configure - Encountered Exception " + str(error))
                self.errored('Exception occurred while configuring port security', goto=['common_cleanup'])
        
        with steps.start("Configure Port-Security on Leaf2(Secondary) - Static and Sticky on port-channel 11"):
            try:
                sec_vtep.configure('''interface port-channel 11
                                no switchport port-security
                                shutdown
                                switchport port-security mac-address
                                switchport port-security aging type inactivity
                                switchport port-security violation restrict
                                switchport port-security
                                no shutdown 
                            '''.format(mac=leaf2_mac))
            except Exception as error:
                log.debug("Unable to configure - Encountered Exception " + str(error))
                self.errored('Exception occurred while configuring port security', goto=['common_cleanup'])
        
        with steps.start("Configure Port-Security on Leaf-1 FEX - FEX port of VTEP"):
            try:
                prim_vtep.configure('''interface {intf}
                                    switchport port-security maximum 1025
                                    switchport port-security violation protect
                                    switchport port-security
                                    no shutdown'''.format(intf=fex_vtep_if))
            except Exception as error:
                log.debug("Unable to configure - Encountered Exception " + str(error))
                self.errored('Exception occurred while configuring port security', goto=['common_cleanup'])
        
        log.info("Waiting {}secs for interface to come up".format(config_time))
        time.sleep(config_time)
        display_configs(testscript)

    # Flap port-security interface on VPC orphan and standalone
    @aetest.test
    def verify_nve_flap_standalone_and_orphan_interface(self, testscript, testbed, steps):
        sa_vtep         = testscript.parameters['LEAF-3']
        prim_vtep       = testscript.parameters['LEAF-1']
        sec_vtep        = testscript.parameters['LEAF-2']
        sa_vtep_if      = str(testscript.parameters['intf_LEAF_3_to_IXIA'])
        prim_vtep_if    = str(testscript.parameters['intf_LEAF_1_1_to_IXIA'])
        sa_mac          = str(testscript.parameters['PORTSEC_Dict']['sa_mac'])
        prim_mac        = str(testscript.parameters['PORTSEC_Dict']['prim_orphan_mac'])
        ixNetwork       = testscript.parameters['ixNetwork']
        p1_handle       = testscript.parameters['orphan1_handle']
        p2_handle       = testscript.parameters['sa_handle']
        
        with steps.start("Starting hosts..."):
            p1_handle.Start()
            p2_handle.Start()

        log.info('Waiting {}secs to start 1025 hosts'.format(host_start_time))
        time.sleep(host_start_time)
                
        stream1 = ixNetwork.Traffic.TrafficItem.find(Name='Access Orphan To Standalone')
        stream1.StartStatelessTraffic()
        log.info('Waiting {}secs to start the traffic'.format(traffic_start_time))
        time.sleep(traffic_start_time)
        
        with steps.start('Shut nve on VPC and Standalone'):
            sa_vtep.configure('''interface nve 1
                                 shut''')
            prim_vtep.configure('''interface nve 1
                                 shut''')
            sec_vtep.configure('''interface nve 1
                                 shut''')
            log.info('Waiting 30secs for nve shut')
            time.sleep(30)
            sa_vtep.configure('''interface nve 1
                                 no shut''')
            prim_vtep.configure('''interface nve 1
                                 no shut''')
            sec_vtep.configure('''interface nve 1
                                 no shut''')
        
        log.info('Waiting 90secs for nve to comeup')
        time.sleep(90)
            
        with steps.start("Checking mac relearning on standalone and remote after nve flap"):
            if not verify_port_sec_addr_count(sa_vtep, sa_vtep_if, 1025, 'DYNAMIC'):
                log.error("DYNAMIC Mac learning failed")
                self.failed("DYNAMIC Mac learning failed")

            if not verify_secure_mac_on_vteps(sa_vtep, '1002', 1025, sa_mac, 'secure'):
                log.error("Mac learning failed on Standalone")
                self.failed("Mac learning failed on Standalone")

            if not verify_secure_mac_on_vteps(prim_vtep, '1002', 1025, sa_mac):
                log.error("DYNAMIC Mac learning failed on remote vtep(leaf1)")
                self.failed("DYNAMIC Mac learning failed on remote vtep(leaf1)")

            if not verify_secure_mac_on_vteps(sec_vtep, '1002', 1025, sa_mac):
                log.error("DYNAMIC Mac learning failed on remote vtep(leaf2)")
                self.failed("DYNAMIC Mac learning failed on remote vtep(leaf2)")

        with steps.start("Checking Mac relearning on vpc vteps and remote vtep after nve flap"):
            if not verify_port_sec_addr_count(prim_vtep, prim_vtep_if, 1025, 'DYNAMIC'):
                log.error("DYNAMIC Mac learning failed")
                self.failed("DYNAMIC Mac learning failed")

            if not verify_secure_mac_on_vteps(prim_vtep, '1001', 1025, prim_mac, 'secure'):
                log.error("Mac learning failed on primary")
                self.failed("Mac learning failed on primary")

            if not verify_secure_mac_on_vteps(sec_vtep, '1001', 1025, prim_mac, 'secure'):
                log.error("DYNAMIC Mac learning failed on remote vtep(leaf2)")
                self.failed("DYNAMIC Mac learning failed on remote vtep(leaf2)")

            if not verify_secure_mac_on_vteps(sa_vtep, '1001', 1025, prim_mac):
                log.error("Mac learning failed on standalone")
                self.failed("Mac learning failed on standalone")

        stream1.StopStatelessTraffic()
        log.info('Waiting {}secs to stop the traffic'.format(traffic_stop_time))
        time.sleep(traffic_stop_time)
        
        with steps.start("Verify Steady State after nve flap"):
            if VerifyTraffic("Test_019_NVE_Flap", testscript, traffic_item='Access Orphan To Standalone'):
                log.info('Verify traffic success after nve flap')
            else:
                self.failed('Verify traffic failed after nve flap')

        with steps.start('Verify Learned mac address consistency between hardware and software'):
            if verify_mac_cc_between_hardware_software([prim_vtep, sec_vtep, sa_vtep]):
                self.passed('MAC CC success')
            else:
                self.failed('MAC CC failed')
    
    @aetest.test
    def verify_portchannel_nve_flap(self, testscript, testbed, steps):
        sa_vtep = testscript.parameters['LEAF-3']
        prim_vtep = testscript.parameters['LEAF-1']
        sec_vtep = testscript.parameters['LEAF-2']
        prim_vpc_mac = str(testscript.parameters['PORTSEC_Dict']['prim_vpc_mac'])
        ixNetwork   = testscript.parameters['ixNetwork']
        p1_handle       = testscript.parameters['vpc_handle']
        p2_handle       = testscript.parameters['sa_handle']
        
        with steps.start("Starting hosts.."):
            p1_handle.Start()
            p2_handle.Start()
        
        log.info('Waiting {}secs to start 1025 hosts'.format(host_start_time))
        time.sleep(host_start_time)
    
        stream1 = ixNetwork.Traffic.TrafficItem.find(Name='Access VPC To Standalone')
        stream1.StartStatelessTraffic()
        log.info('Waiting {}secs to start the traffic'.format(traffic_start_time))
        time.sleep(traffic_start_time)
        
        with steps.start('NVE shut on VPC Primary'):
            prim_vtep.configure('''interface nve 1
                                 shut''')
        
        log.info('Waiting 90secs for nve to shut')
        time.sleep(90)
    
        with steps.start("Checking mac learning on VPC and remote vtep after primary nve shut"):
            if not verify_port_sec_addr_count(prim_vtep, 'port-channel 11', 1, 'STATIC'):
                log.error("STATIC Mac learning failed")
                self.failed("STATIC Mac learning failed")
        
            if not verify_port_sec_addr_count(prim_vtep, 'port-channel 11', 1024, 'DYNAMIC'):
                log.error("DYNAMIC Mac learning failed")
                self.failed("DYNAMIC Mac learning failed")

            if not verify_port_sec_addr_count(sec_vtep, 'port-channel 11', 1, 'STATIC'):
                log.error("STATIC Mac learning failed")
                self.failed("STATIC Mac learning failed")
        
            if not verify_port_sec_addr_count(sec_vtep, 'port-channel 11', 1024, 'DYNAMIC'):
                log.error("DYNAMIC Mac learning failed")
                self.failed("DYNAMIC Mac learning failed")
            
            if not verify_secure_mac_on_vteps(prim_vtep, '1001', 1025, prim_vpc_mac, 'secure'):
                log.error("Mac learning failed on primary")
                self.failed("Mac learning failed on primary")

            if not verify_secure_mac_on_vteps(sec_vtep, '1001', 1025, prim_vpc_mac, 'secure'):
                log.error("Mac learning failed on primary")
                self.failed("Mac learning failed on primary")
                
            if not verify_secure_mac_on_vteps(sa_vtep, '1001', 1025, prim_vpc_mac):
                log.error("Mac learning failed on standalone")
                self.failed("Mac learning failed on standalone")
        
        with steps.start('NVE shut on VPC Secondary'):
            sec_vtep.configure('''interface nve 1
                                 shut''')
        
        log.info('Waiting 90secs for nve shut')
        time.sleep(90)

        with steps.start("Checking mac learning on VPC and remote vtep after secondary nve shut"):
            if not verify_port_sec_addr_count(prim_vtep, 'port-channel 11', 1, 'STATIC'):
                log.error("STATIC Mac learning failed")
                self.failed("STATIC Mac learning failed")
        
            if not verify_port_sec_addr_count(prim_vtep, 'port-channel 11', 1024, 'DYNAMIC'):
                log.error("DYNAMIC Mac learning failed")
                self.failed("DYNAMIC Mac learning failed")

            if not verify_port_sec_addr_count(sec_vtep, 'port-channel 11', 1, 'STATIC'):
                log.error("STATIC Mac learning failed")
                self.failed("STATIC Mac learning failed")
        
            if not verify_port_sec_addr_count(sec_vtep, 'port-channel 11', 1024, 'DYNAMIC'):
                log.error("DYNAMIC Mac learning failed")
                self.failed("DYNAMIC Mac learning failed")
            
            if not verify_secure_mac_on_vteps(prim_vtep, '1001', 1025, prim_vpc_mac, 'secure'):
                log.error("Mac learning failed on primary")
                self.failed("Mac learning failed on primary")

            if not verify_secure_mac_on_vteps(sec_vtep, '1001', 1025, prim_vpc_mac, 'secure'):
                log.error("Mac learning failed on primary")
                self.failed("Mac learning failed on primary")
                
            if not verify_secure_mac_on_vteps(sa_vtep, '1001', 0, prim_vpc_mac):
                log.error("Mac learning failed on standalone")
                self.failed("Mac learning failed on standalone")

        with steps.start('NVE no shut on VPC Primary/secondary'):
            prim_vtep.configure('''interface nve 1
                                 no shut''')
            sec_vtep.configure('''interface nve 1
                                 no shut''')
        
        log.info('Waiting 90secs for nve to comeup')
        time.sleep(90)
        
        with steps.start("Checking mac learning on VPC and remote vtep after nve flap"):
            if not verify_port_sec_addr_count(prim_vtep, 'port-channel 11', 1, 'STATIC'):
                log.error("STATIC Mac learning failed")
                self.failed("STATIC Mac learning failed")
        
            if not verify_port_sec_addr_count(prim_vtep, 'port-channel 11', 1024, 'DYNAMIC'):
                log.error("DYNAMIC Mac learning failed")
                self.failed("DYNAMIC Mac learning failed")

            if not verify_port_sec_addr_count(sec_vtep, 'port-channel 11', 1, 'STATIC'):
                log.error("STATIC Mac learning failed")
                self.failed("STATIC Mac learning failed")
        
            if not verify_port_sec_addr_count(sec_vtep, 'port-channel 11', 1024, 'DYNAMIC'):
                log.error("DYNAMIC Mac learning failed")
                self.failed("DYNAMIC Mac learning failed")
            
            if not verify_secure_mac_on_vteps(prim_vtep, '1001', 1025, prim_vpc_mac, 'secure'):
                log.error("Mac learning failed on primary")
                self.failed("Mac learning failed on primary")

            if not verify_secure_mac_on_vteps(sec_vtep, '1001', 1025, prim_vpc_mac, 'secure'):
                log.error("Mac learning failed on primary")
                self.failed("Mac learning failed on primary")
                
            if not verify_secure_mac_on_vteps(sa_vtep, '1001', 1025, prim_vpc_mac):
                log.error("Mac learning failed on standalone")
                self.failed("Mac learning failed on standalone")

        stream1.StopStatelessTraffic()
        log.info('Waiting {}secs to stop the traffic'.format(traffic_stop_time))
        time.sleep(traffic_stop_time)

        with steps.start("Verify Steady State after nve flap"):
            if VerifyTraffic("Test_019_NVE_Flap", testscript, traffic_item='Access VPC To Standalone'):
                log.info('Verify Traffic Success after nve flap')
            else:
                self.failed('Verify Traffic Failed after nve flap')

        with steps.start('Verify Learned mac address consistency between hardware and software'):
            if verify_mac_cc_between_hardware_software([prim_vtep, sec_vtep, sa_vtep]):
                self.passed('MAC CC success')
            else:
                self.failed('MAC CC failed')

    @aetest.test
    def verify_fex_nve_flap(self, testscript, testbed, steps):
        sa_vtep = testscript.parameters['LEAF-3']
        prim_vtep = testscript.parameters['LEAF-1']
        sec_vtep = testscript.parameters['LEAF-2']
        fex_vtep_if = str(testscript.parameters['intf_LEAF_1_FEX_to_IXIA'])
        prim_fex_mac = str(testscript.parameters['PORTSEC_Dict']['prim_fex_mac'])
        ixNetwork   = testscript.parameters['ixNetwork']
        p1_handle       = testscript.parameters['fex_handle']
        p2_handle       = testscript.parameters['sa_handle']
        
        with steps.start("Starting hosts.."):
            p1_handle.Start()
            p2_handle.Start()
        
        log.info('Waiting {}secs to start 1025 hosts'.format(host_start_time))
        time.sleep(host_start_time)
    
        stream1 = ixNetwork.Traffic.TrafficItem.find(Name='Access FEX To Standalone')
        #
        stream1.StartStatelessTraffic()
        log.info('Waiting {}secs to start the traffic'.format(traffic_start_time))
        time.sleep(traffic_start_time)
        
        with steps.start('NVE flap on VPC and Standalone'):
            prim_vtep.configure('''interface nve 1
                                 shut''')
            sec_vtep.configure('''interface nve 1
                                 shut''')
            
            log.info('Waiting 60secs for nve shut')
            time.sleep(60)
            
            prim_vtep.configure('''interface nve 1
                                 no shut''')
            sec_vtep.configure('''interface nve 1
                                 no shut''')
        
        log.info('Waiting 90secs for nve to comeup')
        time.sleep(90)
        
        with steps.start("Checking mac learning after fex nve flap"):
            if not verify_port_sec_addr_count(prim_vtep, fex_vtep_if, 1025, 'DYNAMIC'):
                log.error("DYNAMIC Mac learning failed")
                self.failed("DYNAMIC Mac learning failed")

            if not verify_secure_mac_on_vteps(prim_vtep, '1001', 1025, prim_fex_mac, 'secure'):
                log.error("Mac learning failed on primary")
                self.failed("Mac learning failed on primary")
            if not verify_secure_mac_on_vteps(sec_vtep, '1001', 1025, prim_fex_mac, 'secure'):
                log.error("Mac learning failed on primary")
                self.failed("Mac learning failed on primary")
            if not verify_secure_mac_on_vteps(sa_vtep, '1001', 1025, prim_fex_mac):
                log.error("Mac learning failed on standalone")
                self.failed("Mac learning failed on standalone")
        
        stream1.StopStatelessTraffic()
        log.info('Waiting {}secs to stop the traffic'.format(traffic_stop_time))
        time.sleep(traffic_stop_time)
        
        with steps.start("Verify Steady State after fex nve flap"):
            if VerifyTraffic("Test_019_FEX_NVE_Flap", testscript, traffic_item='Access FEX To Standalone'):
                log.info('Verify Traffic success after fex nve flap')
            else:
                log.debug('Verify Traffic failed after fex nve flap')

        with steps.start('Verify Learned mac address consistency between hardware and software'):
            if verify_mac_cc_between_hardware_software([prim_vtep, sec_vtep, sa_vtep]):
                self.passed('MAC CC success')
            else:
                self.failed('MAC CC failed')
    
    @aetest.test
    def test_cleanup(self, testscript, testbed, steps):
        sa_vtep = testscript.parameters['LEAF-3']
        prim_vtep = testscript.parameters['LEAF-1']
        sec_vtep = testscript.parameters['LEAF-2']
        prim_vtep_if = str(testscript.parameters['intf_LEAF_1_1_to_IXIA'])
        sa_vtep_if = str(testscript.parameters['intf_LEAF_3_to_IXIA'])
        leaf1_mac = str(testscript.parameters['PORTSEC_Dict']['vpc_static_mac'])
        leaf2_mac = str(testscript.parameters['PORTSEC_Dict']['vpc_static_mac1'])
        src_vlan = int(testscript.parameters['LEAF_1_Orphan1_TGEN_dict']['vlan_id'])
        fex_vtep_if = str(testscript.parameters['intf_LEAF_1_FEX_to_IXIA'])
        
        ixNetwork   = testscript.parameters['ixNetwork']
        
        with steps.start("Stopping all hosts..."):
            ixNetwork.StopAllProtocols()

        log.info('Waiting {}secs to stop the hosts'.format(traffic_stop_time))
        time.sleep(traffic_stop_time)
        
        with steps.start("ReConfigure Port-Security - Dynamic on Leaf-1 - Primary VTEP Orphan"):
            try:
                prim_vtep.configure('''interface {prim_vtep_if}
                                    shutdown
                                    no switchport port-security aging type inactivity
                                    no switchport port-security violation restrict
                                    no shutdown
                                    '''.format(prim_vtep_if=prim_vtep_if))
            except Exception as error:
                log.debug("Unable to configure - Encountered Exception " + str(error))
                self.errored('Exception occurred while configuring port security', goto=['common_cleanup'])
         
        with steps.start("Reconfigure Port-Security - Dynamic on Leaf-3 - Standalone VTEP"):
            try:
                sa_vtep.configure('''interface {sa_vtep_if}
                                    shutdown
                                    no switchport port-security violation restrict
                                    no switchport port-security aging type inactivity
                                    no shutdown
                                    '''.format(sa_vtep_if=sa_vtep_if))
            except Exception as error:
                log.debug("Unable to configure - Encountered Exception " + str(error))
                self.errored('Exception occurred while configuring port security', goto=['common_cleanup'])

        with steps.start("Remove Port-Security on Leaf-1 VPC Member"):
            try:
                prim_vtep.configure('''interface port-channel 11
                                no switchport port-security mac-address {mac}
                                no switchport port-security aging type inactivity
                                no switchport port-security violation restrict
                                no switchport port-security'''.format(mac=leaf1_mac))
            except Exception as error:
                log.debug("Unable to configure - Encountered Exception " + str(error))
                self.errored('Exception occurred while configuring port security', goto=['common_cleanup'])

        with steps.start("Remove Port-Security on Leaf-2 VPC Member"):
            try:
                sec_vtep.configure('''interface port-channel 11
                                no switchport port-security mac-address {mac}
                                no switchport port-security aging type inactivity
                                no switchport port-security violation restrict
                                no switchport port-security'''.format(mac=leaf2_mac))
            except Exception as error:
                log.debug("Unable to configure - Encountered Exception " + str(error))
                self.errored('Exception occurred while configuring port security', goto=['common_cleanup'])
        
        with steps.start("ReConfigure Port-Security on Leaf-1 FEX - FEX port of VTEP"):
            try:
                prim_vtep.configure('''interface {intf}
                                    shutdown
                                    no switchport port-security violation protect
                                    switchport port-security
                                    no shutdown'''.format(intf=fex_vtep_if))
            except Exception as error:
                log.debug("Unable to configure - Encountered Exception " + str(error))
                self.errored('Exception occurred while configuring port security', goto=['common_cleanup'])
        
        with steps.start("Verifying MTS leak.."):
            if verify_mts_leak([prim_vtep, sec_vtep, sa_vtep], log):
                self.passed('MTS Leak verification success')
            else:
                self.failed('MTS Leak verification failed')

########################################################################################################
# Triggers 
########################################################################################################
# TC: VXLAN_PS_065
# BGP Restart - Trunk mode
########################################################################################################
class TC_VXLAN_PS_018_Access(aetest.Testcase):
    @aetest.test
    def test_setup(self, testscript, testbed, steps):
        log.info('STARTING BGP Restart case ...')
        sa_vtep         = testscript.parameters['LEAF-3']
        prim_vtep       = testscript.parameters['LEAF-1']
        sec_vtep        = testscript.parameters['LEAF-2']
        src_vlan        = int(testscript.parameters['LEAF_1_Orphan1_TGEN_dict']['vlan_id'])
        leaf1_mac       = str(testscript.parameters['PORTSEC_Dict']['vpc_static_mac'])
        prim_vtep_if    = str(testscript.parameters['intf_LEAF_1_1_to_IXIA'])
        sa_vtep_if      = str(testscript.parameters['intf_LEAF_3_to_IXIA'])
        fex_vtep_if     = str(testscript.parameters['intf_LEAF_1_FEX_to_IXIA'])
        
        new_config = '''switchport port-security aging type inactivity
                        switchport port-security mac-address sticky
                        switchport port-security violation restrict'''
        with steps.start("Configure Port-Security on Primary VTEP Orphan"):
            if not config_interface_ps([prim_vtep], prim_vtep_if, log, new_config):
                self.errored('Exception occurred while configuring port security', goto=['common_cleanup'])
        
        with steps.start("Configure Port-Security on Standalone VTEP"):
            if not config_interface_ps([sa_vtep], sa_vtep_if, log, new_config):
                self.errored('Exception occurred while configuring port security', goto=['common_cleanup'])
        
        new_config = '''switchport port-security aging type inactivity
                        switchport port-security violation restrict'''
        with steps.start("Configure Port-Security on Leaf-1 FEX - FEX port of VTEP"):
            if not config_interface_ps([prim_vtep], fex_vtep_if, log, new_config):
                self.errored('Exception occurred while configuring port security', goto=['common_cleanup'])

        new_config = '''switchport port-security aging type inactivity
                        switchport port-security violation restrict
                        switchport port-security mac-address {mac}'''.format(mac=leaf1_mac)
        with steps.start("Configure Port-Security on VPC Primary/Secondary - Static"):
            if not config_interface_ps([prim_vtep, sec_vtep], 'port-channel 11', log, new_config):
                self.errored('Exception occurred while configuring port security', goto=['common_cleanup'])
        
        log.info("Waiting {}secs for interface to come up".format(config_time))
        time.sleep(config_time)
        display_configs(testscript)

    # Flap Uplink on VPC primary and standalone
    @aetest.test
    def verify_flap_standalone_and_orphan_interface(self, testscript, testbed, steps):
        sa_vtep         = testscript.parameters['LEAF-3']
        prim_vtep       = testscript.parameters['LEAF-1']
        sec_vtep        = testscript.parameters['LEAF-2']
        sa_vtep_if      = str(testscript.parameters['intf_LEAF_3_to_IXIA'])
        prim_vtep_if    = str(testscript.parameters['intf_LEAF_1_1_to_IXIA'])
        sa_mac          = str(testscript.parameters['PORTSEC_Dict']['sa_mac'])
        prim_mac        = str(testscript.parameters['PORTSEC_Dict']['prim_orphan_mac'])
        AS_number       = testscript.parameters['forwardingSysDict']['BGP_AS_num']
        ixNetwork       = testscript.parameters['ixNetwork']
        p1_handle       = testscript.parameters['orphan1_handle']
        p2_handle       = testscript.parameters['sa_handle']

        with steps.start("Starting hosts..."):
            p1_handle.Start()
            p2_handle.Start()

        log.info('Waiting {}secs to start 1025 hosts'.format(host_start_time))
        time.sleep(host_start_time)
        
        stream1 = ixNetwork.Traffic.TrafficItem.find(Name='Access Orphan To Standalone')
        stream1.StartStatelessTraffic()
        log.info('Waiting {}secs to start the traffic'.format(traffic_start_time))
        time.sleep(traffic_start_time)
        
        with steps.start('BGP Restart on VPC primary and standalone'):
            sa_vtep.configure('restart bgp {AS}'.format(AS=AS_number))
            prim_vtep.configure('restart bgp {AS}'.format(AS=AS_number))
        
        log.info('Wait for 30 secs to sync macs')
        time.sleep(30)
        with steps.start("Checking Mac flushout on standalone and remote vtep after uplink shut"):
            if not verify_port_sec_addr_count(sa_vtep, sa_vtep_if, 1025, 'STICKY'):
                log.error("DYNAMIC Mac learning failed")
                self.failed("DYNAMIC Mac learning failed")

            if not verify_secure_mac_on_vteps(sa_vtep, '1002', 1025, sa_mac, 'secure'):
                log.error("Mac learning failed on Standalone")
                self.failed("Mac learning failed on Standalone")

            if not verify_secure_mac_on_vteps(prim_vtep, '1002', 1025, sa_mac):
                log.error("DYNAMIC Mac learning failed on remote vtep(leaf1)")
                self.failed("DYNAMIC Mac learning failed on remote vtep(leaf1)")

            if not verify_secure_mac_on_vteps(sec_vtep, '1002', 1025, sa_mac):
                log.error("DYNAMIC Mac learning failed on remote vtep(leaf2)")
                self.failed("DYNAMIC Mac learning failed on remote vtep(leaf2)")
        
        with steps.start("Checking Mac flushout on VPC and remote vtep after uplink shut"):
            if not verify_port_sec_addr_count(prim_vtep, prim_vtep_if, 1025, 'STICKY'):
                log.error("DYNAMIC Mac learning failed")
                self.failed("DYNAMIC Mac learning failed")

            if not verify_secure_mac_on_vteps(prim_vtep, '1001', 1025, prim_mac, 'secure'):
                log.error("Mac learning failed on primary")
                self.failed("Mac learning failed on primary")

            if not verify_secure_mac_on_vteps(sec_vtep, '1001', 1025, prim_mac, 'secure'):
                log.error("DYNAMIC Mac learning failed on remote vtep(leaf2)")
                self.failed("DYNAMIC Mac learning failed on remote vtep(leaf2)")

            if not verify_secure_mac_on_vteps(sa_vtep, '1001', 1025, prim_mac):
                log.error("Mac learning failed on standalone")
                self.failed("Mac learning failed on standalone")

        stream1.StopStatelessTraffic()
        log.info('Waiting {}secs to stop the traffic'.format(traffic_stop_time))
        time.sleep(traffic_stop_time)
        
        with steps.start("Verify Steady State after bgp restart"):
            if VerifyTraffic("Test_016_Orphan", testscript, traffic_item='Access Orphan To Standalone'):
                log.info('Verify traffic success after bgp restart')
            else:
                self.failed('Verify traffic failed after bgp restart')

        with steps.start('Verify Learned mac address consistency between hardware and software'):
            if verify_mac_cc_between_hardware_software([prim_vtep, sec_vtep, sa_vtep]):
                self.passed('MAC CC success')
            else:
                self.failed('MAC CC failed')
    
    @aetest.test
    def verify_portchannel_flap(self, testscript, testbed, steps):
        sa_vtep         = testscript.parameters['LEAF-3']
        prim_vtep       = testscript.parameters['LEAF-1']
        sec_vtep        = testscript.parameters['LEAF-2']
        prim_vpc_mac    = str(testscript.parameters['PORTSEC_Dict']['prim_vpc_mac'])
        AS_number       = testscript.parameters['forwardingSysDict']['BGP_AS_num']
        ixNetwork       = testscript.parameters['ixNetwork']
        p1_handle       = testscript.parameters['vpc_handle']
        p2_handle       = testscript.parameters['sa_handle']

        with steps.start("Starting hosts.."):
            p1_handle.Start()
            p2_handle.Start()
        
        log.info('Waiting {}secs to start 1025 hosts'.format(host_start_time))
        time.sleep(host_start_time)
    
        stream1 = ixNetwork.Traffic.TrafficItem.find(Name='Access VPC To Standalone')
        stream1.StartStatelessTraffic()
        log.info('Waiting {}secs to start the traffic'.format(traffic_start_time))
        time.sleep(traffic_start_time)
        
        with steps.start('BGP restart on VPC primary/sec'):
            prim_vtep.configure('restart bgp {AS}'.format(AS=AS_number))
        
        log.info('Waiting 30secs for macs sync')    
        time.sleep(30)
        
        with steps.start("Checking mac learning on local and remote vtep"):
            if not verify_port_sec_addr_count(prim_vtep, 'port-channel 11', 1, 'STATIC'):
                log.error("STATIC Mac learning failed")
                self.failed("STATIC Mac learning failed")
        
            if not verify_port_sec_addr_count(prim_vtep, 'port-channel 11', 1024, 'DYNAMIC'):
                log.error("DYNAMIC Mac learning failed")
                self.failed("DYNAMIC Mac learning failed")

            if not verify_port_sec_addr_count(sec_vtep, 'port-channel 11', 1, 'STATIC'):
                log.error("STATIC Mac learning failed")
                self.failed("STATIC Mac learning failed")
        
            if not verify_port_sec_addr_count(sec_vtep, 'port-channel 11', 1024, 'DYNAMIC'):
                log.error("DYNAMIC Mac learning failed")
                self.failed("DYNAMIC Mac learning failed")
            
            if not verify_secure_mac_on_vteps(prim_vtep, '1001', 1025, prim_vpc_mac, 'secure'):
                log.error("Mac learning failed on primary")
                self.failed("Mac learning failed on primary")

            if not verify_secure_mac_on_vteps(sec_vtep, '1001', 1025, prim_vpc_mac, 'secure'):
                log.error("Mac learning failed on primary")
                self.failed("Mac learning failed on primary")
                
            if not verify_secure_mac_on_vteps(sa_vtep, '1001', 1025, prim_vpc_mac):
                log.error("Mac learning failed on standalone")
                self.failed("Mac learning failed on standalone")
        
        with steps.start('BGP restart on VPC primary/sec'):
            sec_vtep.configure('restart bgp {AS}'.format(AS=AS_number))
        
        log.info('Waiting 30secs for macs sync')
        time.sleep(30)

        with steps.start("Checking mac learning on VPC vtep and remote vtep"):
            if not verify_port_sec_addr_count(prim_vtep, 'port-channel 11', 1, 'STATIC'):
                log.error("STATIC Mac learning failed")
                self.failed("STATIC Mac learning failed")
        
            if not verify_port_sec_addr_count(prim_vtep, 'port-channel 11', 1024, 'DYNAMIC'):
                log.error("DYNAMIC Mac learning failed")
                self.failed("DYNAMIC Mac learning failed")

            if not verify_port_sec_addr_count(sec_vtep, 'port-channel 11', 1, 'STATIC'):
                log.error("STATIC Mac learning failed")
                self.failed("STATIC Mac learning failed")
        
            if not verify_port_sec_addr_count(sec_vtep, 'port-channel 11', 1024, 'DYNAMIC'):
                log.error("DYNAMIC Mac learning failed")
                self.failed("DYNAMIC Mac learning failed")
            
            if not verify_secure_mac_on_vteps(prim_vtep, '1001', 1025, prim_vpc_mac, 'secure'):
                log.error("Mac learning failed on primary")
                self.failed("Mac learning failed on primary")

            if not verify_secure_mac_on_vteps(sec_vtep, '1001', 1025, prim_vpc_mac, 'secure'):
                log.error("Mac learning failed on primary")
                self.failed("Mac learning failed on primary")
                
            if not verify_secure_mac_on_vteps(sa_vtep, '1001', 1025, prim_vpc_mac):
                log.error("Mac learning failed on standalone")
                self.failed("Mac learning failed on standalone")

        stream1.StopStatelessTraffic()
        log.info('Waiting {}secs to stop the traffic'.format(traffic_stop_time))
        time.sleep(traffic_stop_time)

        with steps.start("Verify Steady State after BGP Restart"):
            if VerifyTraffic("Test_016_VPC", testscript, traffic_item='Access VPC To Standalone'):
                log.info('Verify Traffic Success after BGP Restart')
            else:
                self.failed('Verify Traffic Failed after BGP Restart')

        with steps.start('Verify Learned mac address consistency between hardware and software'):
            if verify_mac_cc_between_hardware_software([prim_vtep, sec_vtep, sa_vtep]):
                self.passed('MAC CC success')
            else:
                self.failed('MAC CC failed')

    @aetest.test
    def verify_fex_uplink_flap(self, testscript, testbed, steps):
        sa_vtep         = testscript.parameters['LEAF-3']
        prim_vtep       = testscript.parameters['LEAF-1']
        sec_vtep        = testscript.parameters['LEAF-2']
        fex_vtep_if     = str(testscript.parameters['intf_LEAF_1_FEX_to_IXIA'])
        prim_fex_mac    = str(testscript.parameters['PORTSEC_Dict']['prim_fex_mac'])
        AS_number       = testscript.parameters['forwardingSysDict']['BGP_AS_num']
        ixNetwork       = testscript.parameters['ixNetwork']
        p1_handle       = testscript.parameters['fex_handle']
        p2_handle       = testscript.parameters['sa_handle']
        
        with steps.start('Starting hosts...'):
            p1_handle.Start()
            p2_handle.Start()
        
        log.info('Waiting {}secs to start 1025 hosts'.format(host_start_time))
        time.sleep(host_start_time)
    
        stream1 = ixNetwork.Traffic.TrafficItem.find(Name='Access FEX To Standalone')
        #
        stream1.StartStatelessTraffic()
        log.info('Waiting {}secs to start the traffic'.format(traffic_start_time))
        time.sleep(traffic_start_time)
        
        with steps.start('BGP restart on VPC primary'):
            prim_vtep.configure('restart bgp {AS}'.format(AS=AS_number))
        
        log.info('Waiting 30secs for Macs sync')
        time.sleep(30)
        
        with steps.start("Checking mac learning after fex interface flap"):
            if not verify_port_sec_addr_count(prim_vtep, fex_vtep_if, 1025, 'DYNAMIC'):
                log.error("DYNAMIC Mac learning failed")
                self.failed("DYNAMIC Mac learning failed")

            if not verify_secure_mac_on_vteps(prim_vtep, '1001', 1025, prim_fex_mac, 'secure'):
                log.error("Mac learning failed on primary")
                self.failed("Mac learning failed on primary")
            if not verify_secure_mac_on_vteps(sec_vtep, '1001', 1025, prim_fex_mac, 'secure'):
                log.error("Mac learning failed on primary")
                self.failed("Mac learning failed on primary")
            if not verify_secure_mac_on_vteps(sa_vtep, '1001', 1025, prim_fex_mac):
                log.error("Mac learning failed on standalone")
                self.failed("Mac learning failed on standalone")
        
        stream1.StopStatelessTraffic()
        log.info('Waiting {}secs to stop the traffic'.format(traffic_stop_time))
        time.sleep(traffic_stop_time)
        
        with steps.start("Verify Steady State after BGP Restart"):
            if VerifyTraffic("Test_016_FEX", testscript, traffic_item='Access FEX To Standalone'):
                log.info('Verify Traffic success after BGP Restart')
            else:
                log.debug('Verify Traffic failed after BGP Restart')

        with steps.start('Verify Learned mac address consistency between hardware and software'):
            if verify_mac_cc_between_hardware_software([prim_vtep, sec_vtep, sa_vtep]):
                self.passed('MAC CC success')
            else:
                self.failed('MAC CC failed')
    
    @aetest.test
    def test_cleanup(self, testscript, testbed, steps):
        sa_vtep         = testscript.parameters['LEAF-3']
        prim_vtep       = testscript.parameters['LEAF-1']
        sec_vtep        = testscript.parameters['LEAF-2']
        prim_vtep_if    = str(testscript.parameters['intf_LEAF_1_1_to_IXIA'])
        sa_vtep_if      = str(testscript.parameters['intf_LEAF_3_to_IXIA'])
        leaf1_mac       = str(testscript.parameters['PORTSEC_Dict']['vpc_static_mac'])
        leaf2_mac       = str(testscript.parameters['PORTSEC_Dict']['vpc_static_mac1'])
        src_vlan        = int(testscript.parameters['LEAF_1_Orphan1_TGEN_dict']['vlan_id'])
        fex_vtep_if     = str(testscript.parameters['intf_LEAF_1_FEX_to_IXIA'])
        ixNetwork   = testscript.parameters['ixNetwork']
        
        with steps.start("Stopping all hosts..."):
            ixNetwork.StopAllProtocols()

        log.info('Waiting {}secs to stop the hosts'.format(traffic_stop_time))
        time.sleep(traffic_stop_time)
        
        with steps.start("ReConfigure Port-Security - Dynamic on Leaf-1 - Primary VTEP Orphan"):
            try:
                prim_vtep.configure('''interface {prim_vtep_if}
                                    shutdown
                                    no switchport port-security aging type inactivity
                                    no switchport port-security mac-address sticky
                                    no switchport port-security violation restrict
                                    no shutdown
                                    '''.format(prim_vtep_if=prim_vtep_if))
            except Exception as error:
                log.debug("Unable to configure - Encountered Exception " + str(error))
                self.errored('Exception occurred while configuring port security', goto=['common_cleanup'])
         
        with steps.start("Reconfigure Port-Security - Dynamic on Leaf-3 - Standalone VTEP"):
            try:
                sa_vtep.configure('''interface {sa_vtep_if}
                                    shutdown
                                    no switchport port-security violation restrict
                                    no switchport port-security mac-address sticky
                                    no switchport port-security aging type inactivity
                                    no shutdown
                                    '''.format(sa_vtep_if=sa_vtep_if))
            except Exception as error:
                log.debug("Unable to configure - Encountered Exception " + str(error))
                self.errored('Exception occurred while configuring port security', goto=['common_cleanup'])

        with steps.start("Remove Port-Security on Leaf-1 VPC Member"):
            try:
                prim_vtep.configure('''interface port-channel 11
                                no switchport port-security mac-address {mac}
                                no switchport port-security aging type inactivity
                                no switchport port-security violation restrict
                                no switchport port-security'''.format(mac=leaf1_mac))
            except Exception as error:
                log.debug("Unable to configure - Encountered Exception " + str(error))
                self.errored('Exception occurred while configuring port security', goto=['common_cleanup'])

        with steps.start("Remove Port-Security on Leaf-2 VPC Member"):
            try:
                sec_vtep.configure('''interface port-channel 11
                                no switchport port-security mac-address {mac}
                                no switchport port-security aging type inactivity
                                no switchport port-security violation restrict
                                no switchport port-security'''.format(mac=leaf2_mac))
            except Exception as error:
                log.debug("Unable to configure - Encountered Exception " + str(error))
                self.errored('Exception occurred while configuring port security', goto=['common_cleanup'])
        
        with steps.start("ReConfigure Port-Security on Leaf-1 FEX - FEX port of VTEP"):
            try:
                prim_vtep.configure('''interface {intf}
                                    shutdown
                                    no switchport port-security violation protect
                                    switchport port-security
                                    no shutdown'''.format(intf=fex_vtep_if))
            except Exception as error:
                log.debug("Unable to configure - Encountered Exception " + str(error))
                self.errored('Exception occurred while configuring port security', goto=['common_cleanup'])
        
        with steps.start("Verifying MTS leak.."):
            if verify_mts_leak([prim_vtep, sec_vtep, sa_vtep], log):
                log.info('MTS Leak verification success')
            else:
                self.failed('MTS Leak verification failed')

        with steps.start("Verifying Cores and Log Errors"):
            status = infraVerify.postTestVerification(post_test_process_dict)
            if status['status'] == 0:
                self.failed(reason=status['logs'])
            else:
                self.passed(reason=status['logs'])

########################################################################################################
# Triggers 
########################################################################################################
# TC: VXLAN_PS_066
# NVE process Restart - Trunk Mode
########################################################################################################
class TC_VXLAN_PS_019_Access(aetest.Testcase):
    @aetest.test
    def test_setup(self, testscript, testbed, steps):
        log.info('STARTING NVE Restart case ...')
        
        sa_vtep = testscript.parameters['LEAF-3']
        prim_vtep = testscript.parameters['LEAF-1']
        sec_vtep = testscript.parameters['LEAF-2']
        src_vlan = int(testscript.parameters['LEAF_1_Orphan1_TGEN_dict']['vlan_id'])
        leaf1_mac = str(testscript.parameters['PORTSEC_Dict']['vpc_static_mac'])
        leaf2_mac = str(testscript.parameters['PORTSEC_Dict']['vpc_static_mac1'])
        prim_vtep_if = str(testscript.parameters['intf_LEAF_1_1_to_IXIA'])
        sa_vtep_if = str(testscript.parameters['intf_LEAF_3_to_IXIA'])
        fex_vtep_if = str(testscript.parameters['intf_LEAF_1_FEX_to_IXIA'])
        
        with steps.start("Configure Port-Security - Dynamic on Leaf-1 - Primary VTEP Orphan"):
            try:
                prim_vtep.configure('''interface {prim_vtep_if}
                                    switchport port-security maximum 1025
                                    switchport port-security aging type inactivity
                                    switchport port-security mac-address sticky
                                    switchport port-security violation restrict
                                    switchport port-security
                                    no shutdown
                                    '''.format(prim_vtep_if=prim_vtep_if))
            except Exception as error:
                log.debug("Unable to configure - Encountered Exception " + str(error))
                self.errored('Exception occurred while configuring port security', goto=['common_cleanup'])
         
        with steps.start("Configure Port-Security - Dynamic on Leaf-3 - Standalone VTEP"):
            try:
                sa_vtep.configure('''interface {sa_vtep_if}
                                    switchport port-security maximum 1025
                                    switchport port-security aging type inactivity
                                    switchport port-security mac-address sticky
                                    switchport port-security violation restrict
                                    switchport port-security
                                    no shutdown
                                    '''.format(sa_vtep_if=sa_vtep_if))
            except Exception as error:
                log.debug("Unable to configure - Encountered Exception " + str(error))
                self.errored('Exception occurred while configuring port security', goto=['common_cleanup'])

        with steps.start("Configure Port-Security on Leaf1(Primary) - Static and Sticky on port-channel 11"):
            try:
                prim_vtep.configure('''interface port-channel 11
                                no switchport port-security
                                shutdown
                                switchport port-security maximum 1025
                                switchport port-security mac-address {mac}
                                switchport port-security aging type inactivity
                                switchport port-security violation restrict
                                switchport port-security
                                no shutdown 
                            '''.format(mac=leaf1_mac))
            except Exception as error:
                log.debug("Unable to configure - Encountered Exception " + str(error))
                self.errored('Exception occurred while configuring port security', goto=['common_cleanup'])
        
        with steps.start("Configure Port-Security on Leaf2(Secondary) - Static and Sticky on port-channel 11"):
            try:
                sec_vtep.configure('''interface port-channel 11
                                no switchport port-security
                                shutdown
                                switchport port-security maximum 1025
                                switchport port-security mac-address {mac}
                                switchport port-security aging type inactivity
                                switchport port-security violation restrict
                                switchport port-security
                                no shutdown 
                            '''.format(mac=leaf2_mac))
            except Exception as error:
                log.debug("Unable to configure - Encountered Exception " + str(error))
                self.errored('Exception occurred while configuring port security', goto=['common_cleanup'])
        
        with steps.start("Configure Port-Security on Leaf-1 FEX - FEX port of VTEP"):
            try:
                prim_vtep.configure('''interface {intf}
                                    switchport port-security maximum 1025
                                    switchport port-security violation protect
                                    switchport port-security
                                    no shutdown'''.format(intf=fex_vtep_if))
            except Exception as error:
                log.debug("Unable to configure - Encountered Exception " + str(error))
                self.errored('Exception occurred while configuring port security', goto=['common_cleanup'])
        
        log.info("Waiting {}secs for interface to come up".format(config_time))
        time.sleep(config_time)
        display_configs(testscript)

    @aetest.test
    def verify_nve_restart_standalone_and_orphan_interface(self, testscript, testbed, steps):
        sa_vtep         = testscript.parameters['LEAF-3']
        prim_vtep       = testscript.parameters['LEAF-1']
        sec_vtep        = testscript.parameters['LEAF-2']
        sa_vtep_if      = str(testscript.parameters['intf_LEAF_3_to_IXIA'])
        prim_vtep_if    = str(testscript.parameters['intf_LEAF_1_1_to_IXIA'])
        sa_mac          = str(testscript.parameters['PORTSEC_Dict']['sa_mac'])
        prim_mac        = str(testscript.parameters['PORTSEC_Dict']['prim_orphan_mac'])
        ixNetwork       = testscript.parameters['ixNetwork']
        p1_handle       = testscript.parameters['orphan1_handle']
        p2_handle       = testscript.parameters['sa_handle']

        with steps.start("Starting hosts..."):
            p1_handle.Start()
            p2_handle.Start()
        
        log.info('Waiting {}secs to start 1025 hosts'.format(host_start_time))
        time.sleep(host_start_time)
        
        stream1 = ixNetwork.Traffic.TrafficItem.find(Name='Access Orphan To Standalone')
        #
        stream1.StartStatelessTraffic()
        
        log.info('Waiting {}secs to start the traffic'.format(traffic_start_time))
        time.sleep(traffic_start_time)
        
        with steps.start('NVE process restart on VPC primary/secondary and standalone'):
            if not verify_process_restart(prim_vtep, "nve", testscript, log):
                log.error("NVE process restart failed on primary")
                self.failed("NVE process restart failed on primary")
            
            if not verify_process_restart(sec_vtep, "nve", testscript, log):
                log.error("NVE process restart failed on secondary")
                self.failed("NVE process restart failed on secondary")
            
            if not verify_process_restart(sa_vtep, "nve", testscript, log):
                log.error("NVE process restart failed on standalone")
                self.failed("NVE process restart failed on standalone")

        log.info('Wait for 60 secs to sync macs')
        time.sleep(60)
        
        with steps.start("Checking Mac flushout on standalone and remote vtep after uplink shut"):
            if not verify_port_sec_addr_count(sa_vtep, sa_vtep_if, 1025, 'STICKY'):
                log.error("DYNAMIC Mac learning failed")
                self.failed("DYNAMIC Mac learning failed")

            if not verify_secure_mac_on_vteps(sa_vtep, '1002', 1025, sa_mac, 'secure'):
                log.error("Mac learning failed on Standalone")
                self.failed("Mac learning failed on Standalone")

            if not verify_secure_mac_on_vteps(prim_vtep, '1002', 1025, sa_mac):
                log.error("DYNAMIC Mac learning failed on remote vtep(leaf1)")
                self.failed("DYNAMIC Mac learning failed on remote vtep(leaf1)")

            if not verify_secure_mac_on_vteps(sec_vtep, '1002', 1025, sa_mac):
                log.error("DYNAMIC Mac learning failed on remote vtep(leaf2)")
                self.failed("DYNAMIC Mac learning failed on remote vtep(leaf2)")
        
        with steps.start("Checking Mac flushout on VPC and remote vtep after uplink shut"):
            if not verify_port_sec_addr_count(prim_vtep, prim_vtep_if, 1025, 'STICKY'):
                log.error("DYNAMIC Mac learning failed")
                self.failed("DYNAMIC Mac learning failed")

            if not verify_secure_mac_on_vteps(prim_vtep, '1001', 1025, prim_mac, 'secure'):
                log.error("Mac learning failed on primary")
                self.failed("Mac learning failed on primary")

            if not verify_secure_mac_on_vteps(sec_vtep, '1001', 1025, prim_mac, 'secure'):
                log.error("DYNAMIC Mac learning failed on remote vtep(leaf2)")
                self.failed("DYNAMIC Mac learning failed on remote vtep(leaf2)")

            if not verify_secure_mac_on_vteps(sa_vtep, '1001', 1025, prim_mac):
                log.error("Mac learning failed on standalone")
                self.failed("Mac learning failed on standalone")

        stream1.StopStatelessTraffic()
        log.info('Waiting {}secs to stop the traffic'.format(traffic_stop_time))
        time.sleep(traffic_stop_time)
        
        with steps.start("Verify Steady State after nve process restart"):
            if VerifyTraffic("Test_017_VPC_NVE_Restart", testscript, traffic_item='Access Orphan To Standalone'):
                log.info('Verify traffic success after nve process restart')
            else:
                self.failed('Verify traffic failed after nve process restart')

        with steps.start('Verify Learned mac address consistency between hardware and software'):
            if verify_mac_cc_between_hardware_software([prim_vtep, sec_vtep, sa_vtep]):
                self.passed('MAC CC success')
            else:
                self.failed('MAC CC failed')
    
    @aetest.test
    def verify_portchannel_nve_restart(self, testscript, testbed, steps):
        sa_vtep = testscript.parameters['LEAF-3']
        prim_vtep = testscript.parameters['LEAF-1']
        sec_vtep = testscript.parameters['LEAF-2']
        prim_vpc_mac = str(testscript.parameters['PORTSEC_Dict']['prim_vpc_mac'])
        ixNetwork   = testscript.parameters['ixNetwork']
        p1_handle       = testscript.parameters['vpc_handle']
        p2_handle       = testscript.parameters['sa_handle']
        
        with steps.start("Starting hosts.."):
            p1_handle.Start()
            p2_handle.Start()
        
        log.info('Waiting {}secs to start 1025 hosts'.format(host_start_time))
        time.sleep(host_start_time)
    
        stream1 = ixNetwork.Traffic.TrafficItem.find(Name='Access VPC To Standalone')
        stream1.StartStatelessTraffic()
        
        log.info('Waiting {}secs to start the traffic'.format(traffic_start_time))
        time.sleep(traffic_start_time)
        
        with steps.start('NVE process restart on VPC primary'):
            if not verify_process_restart(prim_vtep, "nve", testscript, log):
                log.error("NVE process restart failed on primary")
                self.failed("NVE process restart failed on primary")
            
        log.info('Waiting 60secs for macs sync')    
        time.sleep(60)
        
        with steps.start("Checking mac learning on VPC and remote after primary nve restart"):
            if not verify_port_sec_addr_count(prim_vtep, 'port-channel 11', 1, 'STATIC'):
                log.error("STATIC Mac learning failed")
                self.failed("STATIC Mac learning failed")
        
            if not verify_port_sec_addr_count(prim_vtep, 'port-channel 11', 1024, 'DYNAMIC'):
                log.error("DYNAMIC Mac learning failed")
                self.failed("DYNAMIC Mac learning failed")

            if not verify_port_sec_addr_count(sec_vtep, 'port-channel 11', 1, 'STATIC'):
                log.error("STATIC Mac learning failed")
                self.failed("STATIC Mac learning failed")
        
            if not verify_port_sec_addr_count(sec_vtep, 'port-channel 11', 1024, 'DYNAMIC'):
                log.error("DYNAMIC Mac learning failed")
                self.failed("DYNAMIC Mac learning failed")
            
            if not verify_secure_mac_on_vteps(prim_vtep, '1001', 1025, prim_vpc_mac, 'secure'):
                log.error("Mac learning failed on primary")
                self.failed("Mac learning failed on primary")

            if not verify_secure_mac_on_vteps(sec_vtep, '1001', 1025, prim_vpc_mac, 'secure'):
                log.error("Mac learning failed on primary")
                self.failed("Mac learning failed on primary")
                
            if not verify_secure_mac_on_vteps(sa_vtep, '1001', 1025, prim_vpc_mac):
                log.error("Mac learning failed on standalone")
                self.failed("Mac learning failed on standalone")
        
        with steps.start('NVE process restart on VPC secondary'):
            if not verify_process_restart(sec_vtep, "nve", testscript, log):
                log.error("NVE process restart failed on secondary")
                self.failed("NVE process restart failed on secondary")
        
        log.info('Waiting 30secs for macs sync')
        time.sleep(30)

        with steps.start("Checking mac learning on VPC vtep and remote vtep after secondary nve restart"):
            prim_vtep.execute('show port-security address inter po11 | inc STATIC')
            if not verify_port_sec_addr_count(prim_vtep, 'port-channel 11', 1, 'STATIC'):
                log.error("STATIC Mac learning failed")
                self.failed("STATIC Mac learning failed")
        
            if not verify_port_sec_addr_count(prim_vtep, 'port-channel 11', 1024, 'DYNAMIC'):
                log.error("DYNAMIC Mac learning failed")
                self.failed("DYNAMIC Mac learning failed")

            if not verify_port_sec_addr_count(sec_vtep, 'port-channel 11', 1, 'STATIC'):
                log.error("STATIC Mac learning failed")
                self.failed("STATIC Mac learning failed")
        
            if not verify_port_sec_addr_count(sec_vtep, 'port-channel 11', 1024, 'DYNAMIC'):
                log.error("DYNAMIC Mac learning failed")
                self.failed("DYNAMIC Mac learning failed")
            
            if not verify_secure_mac_on_vteps(prim_vtep, '1001', 1025, prim_vpc_mac, 'secure'):
                log.error("Mac learning failed on primary")
                self.failed("Mac learning failed on primary")

            if not verify_secure_mac_on_vteps(sec_vtep, '1001', 1025, prim_vpc_mac, 'secure'):
                log.error("Mac learning failed on primary")
                self.failed("Mac learning failed on primary")
                
            if not verify_secure_mac_on_vteps(sa_vtep, '1001', 1025, prim_vpc_mac):
                log.error("Mac learning failed on standalone")
                self.failed("Mac learning failed on standalone")

        stream1.StopStatelessTraffic()
        log.info('Waiting {}secs to stop the traffic'.format(traffic_stop_time))
        time.sleep(traffic_stop_time)

        with steps.start("Verify Steady State after nve restart on VPC Primary/Secondary"):
            if VerifyTraffic("Test_017_VPC", testscript, traffic_item='Access VPC To Standalone'):
                log.info('Verify Traffic Success after NVE Restart')
            else:
                self.failed('Verify Traffic Failed after NVE Restart')

        with steps.start('Verify Learned mac address consistency between hardware and software'):
            if verify_mac_cc_between_hardware_software([prim_vtep, sec_vtep, sa_vtep]):
                self.passed('MAC CC success')
            else:
                self.failed('MAC CC failed')

    @aetest.test
    def verify_fex_nve_restart(self, testscript, testbed, steps):
        sa_vtep         = testscript.parameters['LEAF-3']
        prim_vtep       = testscript.parameters['LEAF-1']
        sec_vtep        = testscript.parameters['LEAF-2']
        fex_vtep_if     = str(testscript.parameters['intf_LEAF_1_FEX_to_IXIA'])
        prim_fex_mac    = str(testscript.parameters['PORTSEC_Dict']['prim_fex_mac'])
        ixNetwork       = testscript.parameters['ixNetwork']
        p1_handle       = testscript.parameters['fex_handle']
        p2_handle       = testscript.parameters['sa_handle']
        
        with steps.start('Starting hosts...'):
            p1_handle.Start()
            p2_handle.Start()
        
        log.info('Waiting {}secs to start 1025 hosts'.format(host_start_time))
        time.sleep(host_start_time)
        
        log.info('Waiting {}secs to start 1025 hosts'.format(host_start_time))
        time.sleep(host_start_time)
    
        stream1 = ixNetwork.Traffic.TrafficItem.find(Name='Access FEX To Standalone')
        #
        stream1.StartStatelessTraffic()
        
        log.info('Waiting {}secs to start the traffic'.format(traffic_start_time))
        time.sleep(traffic_start_time)
        
        with steps.start('NVE process restart on VPC primary/secondary and standalone'):
            if not verify_process_restart(prim_vtep, "nve", testscript, log):
                log.error("NVE process restart failed on primary")
                self.failed("NVE process restart failed on primary")
            
            if not verify_process_restart(sec_vtep, "nve", testscript, log):
                log.error("NVE process restart failed on secondary")
                self.failed("NVE process restart failed on secondary")
        
        log.info('Waiting 60secs for Macs sync')
        time.sleep(60)
        
        with steps.start("Checking mac learning on vpc and remote after nve restart"):
            if not verify_port_sec_addr_count(prim_vtep, fex_vtep_if, 1025, 'DYNAMIC'):
                log.error("DYNAMIC Mac learning failed")
                self.failed("DYNAMIC Mac learning failed")

            if not verify_secure_mac_on_vteps(prim_vtep, '1001', 1025, prim_fex_mac, 'secure'):
                log.error("Mac learning failed on primary")
                self.failed("Mac learning failed on primary")
            if not verify_secure_mac_on_vteps(sec_vtep, '1001', 1025, prim_fex_mac, 'secure'):
                log.error("Mac learning failed on primary")
                self.failed("Mac learning failed on primary")
            if not verify_secure_mac_on_vteps(sa_vtep, '1001', 1025, prim_fex_mac):
                log.error("Mac learning failed on standalone")
                self.failed("Mac learning failed on standalone")
        
        stream1.StopStatelessTraffic()
        log.info('Waiting {}secs to stop the traffic'.format(traffic_stop_time))
        time.sleep(traffic_stop_time)
        
        with steps.start("Verify Steady State after NVE Restart"):
            if VerifyTraffic("Test_017_FEX", testscript, traffic_item='Access FEX To Standalone'):
                log.info('Verify Traffic success after NVE Restart')
            else:
                log.debug('Verify Traffic failed after NVE Restart')

        with steps.start('Verify Learned mac address consistency between hardware and software'):
            if verify_mac_cc_between_hardware_software([prim_vtep, sec_vtep, sa_vtep]):
                self.passed('MAC CC success')
            else:
                self.failed('MAC CC failed')
    
    @aetest.test
    def test_cleanup(self, testscript, testbed, steps):
        sa_vtep = testscript.parameters['LEAF-3']
        prim_vtep = testscript.parameters['LEAF-1']
        sec_vtep = testscript.parameters['LEAF-2']
        prim_vtep_if = str(testscript.parameters['intf_LEAF_1_1_to_IXIA'])
        sa_vtep_if = str(testscript.parameters['intf_LEAF_3_to_IXIA'])
        leaf1_mac = str(testscript.parameters['PORTSEC_Dict']['vpc_static_mac'])
        leaf2_mac = str(testscript.parameters['PORTSEC_Dict']['vpc_static_mac1'])
        src_vlan = int(testscript.parameters['LEAF_1_Orphan1_TGEN_dict']['vlan_id'])
        fex_vtep_if = str(testscript.parameters['intf_LEAF_1_FEX_to_IXIA'])
        
        ixNetwork   = testscript.parameters['ixNetwork']
        
        with steps.start("Stopping all hosts..."):
            ixNetwork.StopAllProtocols()

        log.info('Waiting {}secs to stop the hosts'.format(traffic_stop_time))
        time.sleep(traffic_stop_time)
        
        with steps.start("ReConfigure Port-Security - Dynamic on Leaf-1 - Primary VTEP Orphan"):
            try:
                prim_vtep.configure('''interface {prim_vtep_if}
                                    shutdown
                                    no switchport port-security aging type inactivity
                                    no switchport port-security mac-address sticky
                                    no switchport port-security violation restrict
                                    no shutdown
                                    '''.format(prim_vtep_if=prim_vtep_if))
            except Exception as error:
                log.debug("Unable to configure - Encountered Exception " + str(error))
                self.errored('Exception occurred while configuring port security', goto=['common_cleanup'])
         
        with steps.start("Reconfigure Port-Security - Dynamic on Leaf-3 - Standalone VTEP"):
            try:
                sa_vtep.configure('''interface {sa_vtep_if}
                                    shutdown
                                    no switchport port-security violation restrict
                                    no switchport port-security mac-address sticky
                                    no switchport port-security aging type inactivity
                                    no shutdown
                                    '''.format(sa_vtep_if=sa_vtep_if))
            except Exception as error:
                log.debug("Unable to configure - Encountered Exception " + str(error))
                self.errored('Exception occurred while configuring port security', goto=['common_cleanup'])

        with steps.start("Remove Port-Security on Leaf-1 VPC Member"):
            try:
                prim_vtep.configure('''interface port-channel 11
                                no switchport port-security mac-address {mac}
                                no switchport port-security aging type inactivity
                                no switchport port-security violation restrict
                                no switchport port-security'''.format(mac=leaf1_mac))
            except Exception as error:
                log.debug("Unable to configure - Encountered Exception " + str(error))
                self.errored('Exception occurred while configuring port security', goto=['common_cleanup'])

        with steps.start("Remove Port-Security on Leaf-2 VPC Member"):
            try:
                sec_vtep.configure('''interface port-channel 11
                                no switchport port-security mac-address {mac}
                                no switchport port-security aging type inactivity
                                no switchport port-security violation restrict
                                no switchport port-security'''.format(mac=leaf2_mac))
            except Exception as error:
                log.debug("Unable to configure - Encountered Exception " + str(error))
                self.errored('Exception occurred while configuring port security', goto=['common_cleanup'])
        
        with steps.start("ReConfigure Port-Security on Leaf-1 FEX - FEX port of VTEP"):
            try:
                prim_vtep.configure('''interface {intf}
                                    shutdown
                                    no switchport port-security violation protect
                                    switchport port-security
                                    no shutdown'''.format(intf=fex_vtep_if))
            except Exception as error:
                log.debug("Unable to configure - Encountered Exception " + str(error))
                self.errored('Exception occurred while configuring port security', goto=['common_cleanup'])
        
        with steps.start("Verifying Cores and Log Errors"):
            exclude_bkp = post_test_process_dict['exclude_log_check_pattern']
            post_test_process_dict['exclude_log_check_pattern'] = str(exclude_bkp) + '|SYSMGR-2-SERVICE_CRASHED'
            status = infraVerify.postTestVerification(post_test_process_dict)
            if status['status'] == 0:
                self.failed(reason=status['logs'])
            else:
                self.passed(reason=status['logs'])
            post_test_process_dict['exclude_log_check_pattern'] = exclude_bkp

########################################################################################################
# Triggers 
########################################################################################################
# TC: VXLAN_PS_068 - Trunk Mode
# L2FM process Restart
########################################################################################################
class TC_VXLAN_PS_020_Access(aetest.Testcase):
    @aetest.test
    def test_setup(self, testscript, testbed, steps):
        log.info('STARTING L2FM Restart case ...')
        
        sa_vtep = testscript.parameters['LEAF-3']
        prim_vtep = testscript.parameters['LEAF-1']
        sec_vtep = testscript.parameters['LEAF-2']
        src_vlan = int(testscript.parameters['LEAF_1_Orphan1_TGEN_dict']['vlan_id'])
        leaf1_mac = str(testscript.parameters['PORTSEC_Dict']['vpc_static_mac'])
        leaf2_mac = str(testscript.parameters['PORTSEC_Dict']['vpc_static_mac1'])
        prim_vtep_if = str(testscript.parameters['intf_LEAF_1_1_to_IXIA'])
        sa_vtep_if = str(testscript.parameters['intf_LEAF_3_to_IXIA'])
        fex_vtep_if = str(testscript.parameters['intf_LEAF_1_FEX_to_IXIA'])
        
        with steps.start("Configure Port-Security - Dynamic on Leaf-1 - Primary VTEP Orphan"):
            try:
                prim_vtep.configure('''interface {prim_vtep_if}
                                    switchport port-security maximum 1025
                                    switchport port-security aging type inactivity
                                    switchport port-security mac-address sticky
                                    switchport port-security violation restrict
                                    switchport port-security
                                    no shutdown
                                    '''.format(prim_vtep_if=prim_vtep_if))
            except Exception as error:
                log.debug("Unable to configure - Encountered Exception " + str(error))
                self.errored('Exception occurred while configuring port security', goto=['common_cleanup'])
         
        with steps.start("Configure Port-Security - Dynamic on Leaf-3 - Standalone VTEP"):
            try:
                sa_vtep.configure('''interface {sa_vtep_if}
                                    switchport port-security maximum 1025
                                    switchport port-security aging type inactivity
                                    switchport port-security mac-address sticky
                                    switchport port-security violation restrict
                                    switchport port-security
                                    no shutdown
                                    '''.format(sa_vtep_if=sa_vtep_if))
            except Exception as error:
                log.debug("Unable to configure - Encountered Exception " + str(error))
                self.errored('Exception occurred while configuring port security', goto=['common_cleanup'])

        with steps.start("Configure Port-Security on Leaf1(Primary) - Static and Sticky on port-channel 11"):
            try:
                prim_vtep.configure('''interface port-channel 11
                                no switchport port-security
                                shutdown
                                switchport port-security maximum 1025
                                switchport port-security mac-address {mac}
                                switchport port-security aging type inactivity
                                switchport port-security violation restrict
                                switchport port-security
                                no shutdown 
                            '''.format(mac=leaf1_mac))
            except Exception as error:
                log.debug("Unable to configure - Encountered Exception " + str(error))
                self.errored('Exception occurred while configuring port security', goto=['common_cleanup'])
        
        with steps.start("Configure Port-Security on Leaf2(Secondary) - Static and Sticky on port-channel 11"):
            try:
                sec_vtep.configure('''interface port-channel 11
                                no switchport port-security
                                shutdown
                                switchport port-security maximum 1025
                                switchport port-security mac-address {mac}
                                switchport port-security aging type inactivity
                                switchport port-security violation restrict
                                switchport port-security
                                no shutdown 
                            '''.format(mac=leaf2_mac))
            except Exception as error:
                log.debug("Unable to configure - Encountered Exception " + str(error))
                self.errored('Exception occurred while configuring port security', goto=['common_cleanup'])
        
        with steps.start("Configure Port-Security on Leaf-1 FEX - FEX port of VTEP"):
            try:
                prim_vtep.configure('''interface {intf}
                                    switchport port-security maximum 1025
                                    switchport port-security violation protect
                                    switchport port-security
                                    no shutdown'''.format(intf=fex_vtep_if))
            except Exception as error:
                log.debug("Unable to configure - Encountered Exception " + str(error))
                self.errored('Exception occurred while configuring port security', goto=['common_cleanup'])
        
        log.info("Waiting {}secs for interface to come up".format(config_time))
        time.sleep(config_time)

    @aetest.test
    def verify_l2fm_restart_standalone_and_orphan_interface(self, testscript, testbed, steps):
        sa_vtep = testscript.parameters['LEAF-3']
        prim_vtep = testscript.parameters['LEAF-1']
        sec_vtep = testscript.parameters['LEAF-2']
        sa_vtep_if = str(testscript.parameters['intf_LEAF_3_to_IXIA'])
        prim_vtep_if = str(testscript.parameters['intf_LEAF_1_1_to_IXIA'])
        sa_mac = str(testscript.parameters['PORTSEC_Dict']['sa_mac'])
        prim_mac = str(testscript.parameters['PORTSEC_Dict']['prim_orphan_mac'])
        ixNetwork   = testscript.parameters['ixNetwork']
        p1_handle       = testscript.parameters['orphan1_handle']
        p2_handle       = testscript.parameters['sa_handle']

        with steps.start("Starting hosts..."):
            p1_handle.Start()
            p2_handle.Start()
        
        log.info('Waiting {}secs to start 1025 hosts'.format(host_start_time))
        time.sleep(host_start_time)
        
        stream1 = ixNetwork.Traffic.TrafficItem.find(Name='Access Orphan To Standalone')
        #
        stream1.StartStatelessTraffic()
        
        log.info('Waiting {}secs to start the traffic'.format(traffic_start_time))
        time.sleep(traffic_start_time)
        
        with steps.start('L2FM restart on VPC primary/secondary and standalone'):
            if not verify_process_restart(prim_vtep, "l2fm", testscript, log):
                log.error("L2FM restart failed on primary")
                self.failed("L2FM restart failed on primary")
            
            if not verify_process_restart(sec_vtep, "l2fm", testscript, log):
                log.error("L2FM restart failed on secondary")
                self.failed("L2FM restart failed on secondary")
            
            if not verify_process_restart(sa_vtep, "l2fm", testscript, log):
                log.error("L2FM restart failed on standalone")
                self.failed("L2FM restart failed on standalone")

        log.info('Wait for 30 secs to sync macs')
        time.sleep(30)
        
        with steps.start("Checking Mac flushout on standalone and remote vtep after l2fm restart"):
            if not verify_port_sec_addr_count(sa_vtep, sa_vtep_if, 1025, 'STICKY'):
                log.error("DYNAMIC Mac learning failed")
                self.failed("DYNAMIC Mac learning failed")

            if not verify_secure_mac_on_vteps(sa_vtep, '1002', 1025, sa_mac, 'secure'):
                log.error("Mac learning failed on Standalone")
                self.failed("Mac learning failed on Standalone")

            if not verify_secure_mac_on_vteps(prim_vtep, '1002', 1025, sa_mac):
                log.error("DYNAMIC Mac learning failed on remote vtep(leaf1)")
                self.failed("DYNAMIC Mac learning failed on remote vtep(leaf1)")

            if not verify_secure_mac_on_vteps(sec_vtep, '1002', 1025, sa_mac):
                log.error("DYNAMIC Mac learning failed on remote vtep(leaf2)")
                self.failed("DYNAMIC Mac learning failed on remote vtep(leaf2)")
        
        with steps.start("Checking Mac flushout on VPC and remote vtep after l2fm"):
            if not verify_port_sec_addr_count(prim_vtep, prim_vtep_if, 1025, 'STICKY'):
                log.error("DYNAMIC Mac learning failed")
                self.failed("DYNAMIC Mac learning failed")

            if not verify_secure_mac_on_vteps(prim_vtep, '1001', 1025, prim_mac, 'secure'):
                log.error("Mac learning failed on primary")
                self.failed("Mac learning failed on primary")

            if not verify_secure_mac_on_vteps(sec_vtep, '1001', 1025, prim_mac, 'secure'):
                log.error("DYNAMIC Mac learning failed on remote vtep(leaf2)")
                self.failed("DYNAMIC Mac learning failed on remote vtep(leaf2)")

            if not verify_secure_mac_on_vteps(sa_vtep, '1001', 1025, prim_mac):
                log.error("Mac learning failed on standalone")
                self.failed("Mac learning failed on standalone")

        stream1.StopStatelessTraffic()
        log.info('Waiting {}secs to stop the traffic'.format(traffic_stop_time))
        time.sleep(traffic_stop_time)
        
        with steps.start("Verify Steady State after l2fm restart"):
            if VerifyTraffic("Test_068_VPC_L2FM_Restart", testscript, traffic_item='Access Orphan To Standalone'):
                log.info('Verify traffic success after l2fm restart')
            else:
                self.failed('Verify traffic failed after l2fm restart')

        with steps.start('Verify Learned mac address consistency between hardware and software'):
            if verify_mac_cc_between_hardware_software([prim_vtep, sec_vtep, sa_vtep]):
                self.passed('MAC CC success')
            else:
                self.failed('MAC CC failed')
    
    @aetest.test
    def verify_portchannel_l2fm_restart(self, testscript, testbed, steps):
        sa_vtep = testscript.parameters['LEAF-3']
        prim_vtep = testscript.parameters['LEAF-1']
        sec_vtep = testscript.parameters['LEAF-2']
        prim_vpc_mac = str(testscript.parameters['PORTSEC_Dict']['prim_vpc_mac'])
        ixNetwork   = testscript.parameters['ixNetwork']
        p1_handle       = testscript.parameters['vpc_handle']
        p2_handle       = testscript.parameters['sa_handle']

        with steps.start("Starting hosts.."):
            p1_handle.Start()
            p2_handle.Start()
        
        log.info('Waiting {}secs to start 1025 hosts'.format(host_start_time))
        time.sleep(host_start_time)
    
        stream1 = ixNetwork.Traffic.TrafficItem.find(Name='Access VPC To Standalone')
        #
        stream1.StartStatelessTraffic()
        
        log.info('Waiting {}secs to start the traffic'.format(traffic_start_time))
        time.sleep(traffic_start_time)
        
        with steps.start('L2FM restart on VPC primary'):
            if not verify_process_restart(prim_vtep, "l2fm", testscript, log):
                log.error("L2FM restart failed on primary")
                self.failed("L2FM restart failed on primary")
            
        log.info('Waiting 30secs for macs sync')    
        time.sleep(30)
        
        with steps.start("Checking mac learning on VPC and remote after primary l2fm restart"):
            if not verify_port_sec_addr_count(prim_vtep, 'port-channel 11', 1, 'STATIC'):
                log.error("STATIC Mac learning failed")
                self.failed("STATIC Mac learning failed")
        
            if not verify_port_sec_addr_count(prim_vtep, 'port-channel 11', 1024, 'DYNAMIC'):
                log.error("DYNAMIC Mac learning failed")
                self.failed("DYNAMIC Mac learning failed")

            if not verify_port_sec_addr_count(sec_vtep, 'port-channel 11', 1, 'STATIC'):
                log.error("STATIC Mac learning failed")
                self.failed("STATIC Mac learning failed")
        
            if not verify_port_sec_addr_count(sec_vtep, 'port-channel 11', 1024, 'DYNAMIC'):
                log.error("DYNAMIC Mac learning failed")
                self.failed("DYNAMIC Mac learning failed")
            
            if not verify_secure_mac_on_vteps(prim_vtep, '1001', 1025, prim_vpc_mac, 'secure'):
                log.error("Mac learning failed on primary")
                self.failed("Mac learning failed on primary")

            if not verify_secure_mac_on_vteps(sec_vtep, '1001', 1025, prim_vpc_mac, 'secure'):
                log.error("Mac learning failed on primary")
                self.failed("Mac learning failed on primary")
                
            if not verify_secure_mac_on_vteps(sa_vtep, '1001', 1025, prim_vpc_mac):
                log.error("Mac learning failed on standalone")
                self.failed("Mac learning failed on standalone")
        
        with steps.start('L2FM restart on VPC secondary'):
            if not verify_process_restart(sec_vtep, "l2fm", testscript, log):
                log.error("L2FM restart failed on secondary")
                self.failed("L2FM restart failed on secondary")
        
        log.info('Waiting 30secs for macs sync')
        time.sleep(30)

        with steps.start("Checking mac learning on VPC vtep and remote vtep after secondary l2fm restart"):
            if not verify_port_sec_addr_count(prim_vtep, 'port-channel 11', 1, 'STATIC'):
                log.error("STATIC Mac learning failed")
                self.failed("STATIC Mac learning failed")
        
            if not verify_port_sec_addr_count(prim_vtep, 'port-channel 11', 1024, 'DYNAMIC'):
                log.error("DYNAMIC Mac learning failed")
                self.failed("DYNAMIC Mac learning failed")

            if not verify_port_sec_addr_count(sec_vtep, 'port-channel 11', 1, 'STATIC'):
                log.error("STATIC Mac learning failed")
                self.failed("STATIC Mac learning failed")
        
            if not verify_port_sec_addr_count(sec_vtep, 'port-channel 11', 1024, 'DYNAMIC'):
                log.error("DYNAMIC Mac learning failed")
                self.failed("DYNAMIC Mac learning failed")
            
            if not verify_secure_mac_on_vteps(prim_vtep, '1001', 1025, prim_vpc_mac, 'secure'):
                log.error("Mac learning failed on primary")
                self.failed("Mac learning failed on primary")

            if not verify_secure_mac_on_vteps(sec_vtep, '1001', 1025, prim_vpc_mac, 'secure'):
                log.error("Mac learning failed on primary")
                self.failed("Mac learning failed on primary")
                
            if not verify_secure_mac_on_vteps(sa_vtep, '1001', 1025, prim_vpc_mac):
                log.error("Mac learning failed on standalone")
                self.failed("Mac learning failed on standalone")

        stream1.StopStatelessTraffic()
        log.info('Waiting {}secs to stop the traffic'.format(traffic_stop_time))
        time.sleep(traffic_stop_time)

        with steps.start("Verify Steady State after l2fm restart on VPC Primary/Secondary"):
            if VerifyTraffic("Test_066_L2FM_Restart", testscript, traffic_item='Access VPC To Standalone'):
                log.info('Verify Traffic Success after L2FM Restart')
            else:
                self.failed('Verify Traffic Failed after L2FM Restart')

        with steps.start('Verify Learned mac address consistency between hardware and software'):
            if verify_mac_cc_between_hardware_software([prim_vtep, sec_vtep, sa_vtep]):
                self.passed('MAC CC success')
            else:
                self.failed('MAC CC failed')

    @aetest.test
    def verify_fex_l2fm_restart(self, testscript, testbed, steps):
        sa_vtep = testscript.parameters['LEAF-3']
        prim_vtep = testscript.parameters['LEAF-1']
        sec_vtep = testscript.parameters['LEAF-2']
        fex_vtep_if = str(testscript.parameters['intf_LEAF_1_FEX_to_IXIA'])
        prim_fex_mac = str(testscript.parameters['PORTSEC_Dict']['prim_fex_mac'])
        ixNetwork   = testscript.parameters['ixNetwork']
        p1_handle       = testscript.parameters['fex_handle']
        p2_handle       = testscript.parameters['sa_handle']

        with steps.start('Starting hosts..'):
            p1_handle.Start()
            p2_handle.Start()
        
        log.info('Waiting {}secs to start 1025 hosts'.format(host_start_time))
        time.sleep(host_start_time)
        
        stream1 = ixNetwork.Traffic.TrafficItem.find(Name='Access FEX To Standalone')
        #
        stream1.StartStatelessTraffic()
        
        log.info('Waiting {}secs to start the traffic'.format(traffic_start_time))
        time.sleep(traffic_start_time)
        
        with steps.start('L2FM restart on VPC primary/secondary and standalone'):
            if not verify_process_restart(prim_vtep, "l2fm", testscript, log):
                log.error("L2FM restart failed on primary")
                self.failed("L2FM restart failed on primary")
            
            if not verify_process_restart(sec_vtep, "l2fm", testscript, log):
                log.error("L2FM restart failed on secondary")
                self.failed("L2FM restart failed on secondary")
        
        log.info('Waiting 30secs for Macs sync')
        time.sleep(30)
        
        with steps.start("Checking mac learning on vpc and remote after l2fm restart"):
            if not verify_port_sec_addr_count(prim_vtep, fex_vtep_if, 1025, 'DYNAMIC'):
                log.error("DYNAMIC Mac learning failed")
                self.failed("DYNAMIC Mac learning failed")

            if not verify_secure_mac_on_vteps(prim_vtep, '1001', 1025, prim_fex_mac, 'secure'):
                log.error("Mac learning failed on primary")
                self.failed("Mac learning failed on primary")
            if not verify_secure_mac_on_vteps(sec_vtep, '1001', 1025, prim_fex_mac, 'secure'):
                log.error("Mac learning failed on primary")
                self.failed("Mac learning failed on primary")
            if not verify_secure_mac_on_vteps(sa_vtep, '1001', 1025, prim_fex_mac):
                log.error("Mac learning failed on standalone")
                self.failed("Mac learning failed on standalone")
        
        stream1.StopStatelessTraffic()
        log.info('Waiting {}secs to stop the traffic'.format(traffic_stop_time))
        time.sleep(traffic_stop_time)
        
        with steps.start("Verify Steady State after L2FM Restart"):
            if VerifyTraffic("Test_022_FEX_L2FM_Restart", testscript, traffic_item='Access FEX To Standalone'):
                log.info('Verify Traffic success after L2FM Restart')
            else:
                log.debug('Verify Traffic failed after L2FM Restart')

        with steps.start('Verify Learned mac address consistency between hardware and software'):
            if verify_mac_cc_between_hardware_software([prim_vtep, sec_vtep, sa_vtep]):
                self.passed('MAC CC success')
            else:
                self.failed('MAC CC failed')
    
    @aetest.test
    def test_cleanup(self, testscript, testbed, steps):
        sa_vtep = testscript.parameters['LEAF-3']
        prim_vtep = testscript.parameters['LEAF-1']
        sec_vtep = testscript.parameters['LEAF-2']
        prim_vtep_if = str(testscript.parameters['intf_LEAF_1_1_to_IXIA'])
        sa_vtep_if = str(testscript.parameters['intf_LEAF_3_to_IXIA'])
        leaf1_mac = str(testscript.parameters['PORTSEC_Dict']['vpc_static_mac'])
        leaf2_mac = str(testscript.parameters['PORTSEC_Dict']['vpc_static_mac1'])
        src_vlan = int(testscript.parameters['LEAF_1_Orphan1_TGEN_dict']['vlan_id'])
        fex_vtep_if = str(testscript.parameters['intf_LEAF_1_FEX_to_IXIA'])
        
        ixNetwork   = testscript.parameters['ixNetwork']
        
        with steps.start("Stopping all hosts..."):
            ixNetwork.StopAllProtocols()

        log.info('Waiting {}secs to stop the hosts'.format(traffic_stop_time))
        time.sleep(traffic_stop_time)
        
        with steps.start("ReConfigure Port-Security - Dynamic on Leaf-1 - Primary VTEP Orphan"):
            try:
                prim_vtep.configure('''interface {prim_vtep_if}
                                    shutdown
                                    no switchport port-security aging type inactivity
                                    no switchport port-security mac-address sticky
                                    no switchport port-security violation restrict
                                    no shutdown
                                    '''.format(prim_vtep_if=prim_vtep_if))
            except Exception as error:
                log.debug("Unable to configure - Encountered Exception " + str(error))
                self.errored('Exception occurred while configuring port security', goto=['common_cleanup'])
         
        with steps.start("Reconfigure Port-Security - Dynamic on Leaf-3 - Standalone VTEP"):
            try:
                sa_vtep.configure('''interface {sa_vtep_if}
                                    shutdown
                                    no switchport port-security violation restrict
                                    no switchport port-security mac-address sticky
                                    no switchport port-security aging type inactivity
                                    no shutdown
                                    '''.format(sa_vtep_if=sa_vtep_if))
            except Exception as error:
                log.debug("Unable to configure - Encountered Exception " + str(error))
                self.errored('Exception occurred while configuring port security', goto=['common_cleanup'])

        with steps.start("Remove Port-Security on Leaf-1 VPC Member"):
            try:
                prim_vtep.configure('''interface port-channel 11
                                no switchport port-security mac-address {mac}
                                no switchport port-security aging type inactivity
                                no switchport port-security violation restrict
                                no switchport port-security'''.format(mac=leaf1_mac))
            except Exception as error:
                log.debug("Unable to configure - Encountered Exception " + str(error))
                self.errored('Exception occurred while configuring port security', goto=['common_cleanup'])

        with steps.start("Remove Port-Security on Leaf-2 VPC Member"):
            try:
                sec_vtep.configure('''interface port-channel 11
                                no switchport port-security mac-address {mac}
                                no switchport port-security aging type inactivity
                                no switchport port-security violation restrict
                                no switchport port-security'''.format(mac=leaf2_mac))
            except Exception as error:
                log.debug("Unable to configure - Encountered Exception " + str(error))
                self.errored('Exception occurred while configuring port security', goto=['common_cleanup'])
        
        with steps.start("ReConfigure Port-Security on Leaf-1 FEX - FEX port of VTEP"):
            try:
                prim_vtep.configure('''interface {intf}
                                    shutdown
                                    no switchport port-security violation protect
                                    switchport port-security
                                    no shutdown'''.format(intf=fex_vtep_if))
            except Exception as error:
                log.debug("Unable to configure - Encountered Exception " + str(error))
                self.errored('Exception occurred while configuring port security', goto=['common_cleanup'])
        
        with steps.start("Verifying MTS leak.."):
            if verify_mts_leak([prim_vtep, sec_vtep, sa_vtep], log):
                self.passed('MTS Leak verification success')
            else:
                self.failed('MTS Leak verification failed')

########################################################################################################
# Triggers 
########################################################################################################
# TC: VXLAN_PS_069
# HMM process Restart Trunk Mode
########################################################################################################
class TC_VXLAN_PS_021_Access(aetest.Testcase):
    @aetest.test
    def test_setup(self, testscript, testbed, steps):
        log.info('STARTING HMM Restart case ...')
        
        sa_vtep = testscript.parameters['LEAF-3']
        prim_vtep = testscript.parameters['LEAF-1']
        sec_vtep = testscript.parameters['LEAF-2']
        src_vlan = int(testscript.parameters['LEAF_1_Orphan1_TGEN_dict']['vlan_id'])
        leaf1_mac = str(testscript.parameters['PORTSEC_Dict']['vpc_static_mac'])
        leaf2_mac = str(testscript.parameters['PORTSEC_Dict']['vpc_static_mac1'])
        prim_vtep_if = str(testscript.parameters['intf_LEAF_1_1_to_IXIA'])
        sa_vtep_if = str(testscript.parameters['intf_LEAF_3_to_IXIA'])
        fex_vtep_if = str(testscript.parameters['intf_LEAF_1_FEX_to_IXIA'])
        
        with steps.start("Configure Port-Security - Dynamic on Leaf-1 - Primary VTEP Orphan"):
            try:
                prim_vtep.configure('''interface {prim_vtep_if}
                                    switchport port-security maximum 1025
                                    switchport port-security aging type inactivity
                                    switchport port-security mac-address sticky
                                    switchport port-security violation restrict
                                    switchport port-security
                                    no shutdown
                                    '''.format(prim_vtep_if=prim_vtep_if))
            except Exception as error:
                log.debug("Unable to configure - Encountered Exception " + str(error))
                self.errored('Exception occurred while configuring port security', goto=['common_cleanup'])
         
        with steps.start("Configure Port-Security - Dynamic on Leaf-3 - Standalone VTEP"):
            try:
                sa_vtep.configure('''interface {sa_vtep_if}
                                    switchport port-security maximum 1025
                                    switchport port-security aging type inactivity
                                    switchport port-security mac-address sticky
                                    switchport port-security violation restrict
                                    switchport port-security
                                    no shutdown
                                    '''.format(sa_vtep_if=sa_vtep_if))
            except Exception as error:
                log.debug("Unable to configure - Encountered Exception " + str(error))
                self.errored('Exception occurred while configuring port security', goto=['common_cleanup'])

        with steps.start("Configure Port-Security on Leaf1(Primary) - Static and Sticky on port-channel 11"):
            try:
                prim_vtep.configure('''interface port-channel 11
                                no switchport port-security
                                shutdown
                                switchport port-security maximum 1025
                                switchport port-security mac-address {mac}
                                switchport port-security aging type inactivity
                                switchport port-security violation restrict
                                switchport port-security
                                no shutdown 
                            '''.format(mac=leaf1_mac))
            except Exception as error:
                log.debug("Unable to configure - Encountered Exception " + str(error))
                self.errored('Exception occurred while configuring port security', goto=['common_cleanup'])
        
        with steps.start("Configure Port-Security on Leaf2(Secondary) - Static and Sticky on port-channel 11"):
            try:
                sec_vtep.configure('''interface port-channel 11
                                no switchport port-security
                                shutdown
                                switchport port-security maximum 1025
                                switchport port-security mac-address {mac}
                                switchport port-security aging type inactivity
                                switchport port-security violation restrict
                                switchport port-security
                                no shutdown 
                            '''.format(mac=leaf2_mac))
            except Exception as error:
                log.debug("Unable to configure - Encountered Exception " + str(error))
                self.errored('Exception occurred while configuring port security', goto=['common_cleanup'])
        
        with steps.start("Configure Port-Security on Leaf-1 FEX - FEX port of VTEP"):
            try:
                prim_vtep.configure('''interface {intf}
                                    switchport port-security maximum 1025
                                    switchport port-security violation protect
                                    switchport port-security
                                    no shutdown'''.format(intf=fex_vtep_if))
            except Exception as error:
                log.debug("Unable to configure - Encountered Exception " + str(error))
                self.errored('Exception occurred while configuring port security', goto=['common_cleanup'])
        
        log.info("Waiting {}secs for interface to come up".format(config_time))
        time.sleep(config_time)

    @aetest.test
    def verify_l2fm_restart_standalone_and_orphan_interface(self, testscript, testbed, steps):
        sa_vtep = testscript.parameters['LEAF-3']
        prim_vtep = testscript.parameters['LEAF-1']
        sec_vtep = testscript.parameters['LEAF-2']
        sa_vtep_if = str(testscript.parameters['intf_LEAF_3_to_IXIA'])
        prim_vtep_if = str(testscript.parameters['intf_LEAF_1_1_to_IXIA'])
        sa_mac = str(testscript.parameters['PORTSEC_Dict']['sa_mac'])
        prim_mac = str(testscript.parameters['PORTSEC_Dict']['prim_orphan_mac'])
        ixNetwork   = testscript.parameters['ixNetwork']
        p1_handle       = testscript.parameters['orphan1_handle']
        p2_handle       = testscript.parameters['sa_handle']
        
        with steps.start("Starting hosts..."):
            p1_handle.Start()
            p2_handle.Start()
        
        log.info('Waiting {}secs to start 1025 hosts'.format(host_start_time))
        time.sleep(host_start_time)
        
        stream1 = ixNetwork.Traffic.TrafficItem.find(Name='Access Orphan To Standalone')
        #
        stream1.StartStatelessTraffic()
        
        log.info('Waiting {}secs to start the traffic'.format(traffic_start_time))
        time.sleep(traffic_start_time)
        
        with steps.start('HMM restart on VPC primary/secondary and standalone'):
            if not verify_process_restart(prim_vtep, "hmm", testscript, log):
                log.error("HMM restart failed on primary")
                self.failed("HMM restart failed on primary")
            
            if not verify_process_restart(sec_vtep, "hmm", testscript, log):
                log.error("HMM restart failed on secondary")
                self.failed("HMM restart failed on secondary")
            
            if not verify_process_restart(sa_vtep, "hmm", testscript, log):
                log.error("HMM restart failed on standalone")
                self.failed("HMM restart failed on standalone")

        log.info('Wait for 30 secs to sync macs')
        time.sleep(30)
        
        with steps.start("Checking Mac flushout on standalone and remote vtep after HMM restart"):
            if not verify_port_sec_addr_count(sa_vtep, sa_vtep_if, 1025, 'STICKY'):
                log.error("DYNAMIC Mac learning failed")
                self.failed("DYNAMIC Mac learning failed")

            if not verify_secure_mac_on_vteps(sa_vtep, '1002', 1025, sa_mac, 'secure'):
                log.error("Mac learning failed on Standalone")
                self.failed("Mac learning failed on Standalone")

            if not verify_secure_mac_on_vteps(prim_vtep, '1002', 1025, sa_mac):
                log.error("DYNAMIC Mac learning failed on remote vtep(leaf1)")
                self.failed("DYNAMIC Mac learning failed on remote vtep(leaf1)")

            if not verify_secure_mac_on_vteps(sec_vtep, '1002', 1025, sa_mac):
                log.error("DYNAMIC Mac learning failed on remote vtep(leaf2)")
                self.failed("DYNAMIC Mac learning failed on remote vtep(leaf2)")
        
        with steps.start("Checking Mac flushout on VPC and remote vtep after HMM"):
            if not verify_port_sec_addr_count(prim_vtep, prim_vtep_if, 1025, 'STICKY'):
                log.error("DYNAMIC Mac learning failed")
                self.failed("DYNAMIC Mac learning failed")

            if not verify_secure_mac_on_vteps(prim_vtep, '1001', 1025, prim_mac, 'secure'):
                log.error("Mac learning failed on primary")
                self.failed("Mac learning failed on primary")

            if not verify_secure_mac_on_vteps(sec_vtep, '1001', 1025, prim_mac, 'secure'):
                log.error("DYNAMIC Mac learning failed on remote vtep(leaf2)")
                self.failed("DYNAMIC Mac learning failed on remote vtep(leaf2)")

            if not verify_secure_mac_on_vteps(sa_vtep, '1001', 1025, prim_mac):
                log.error("Mac learning failed on standalone")
                self.failed("Mac learning failed on standalone")

        stream1.StopStatelessTraffic()
        log.info('Waiting {}secs to stop the traffic'.format(traffic_stop_time))
        time.sleep(traffic_stop_time)
        
        with steps.start("Verify Steady State after HMM restart"):
            if VerifyTraffic("Test_023_Orphan_HMM_Restart", testscript, 
                             traffic_item='Access Orphan To Standalone'):
                log.info('Verify traffic success after HMM restart')
            else:
                self.failed('Verify traffic failed after HMM restart')

        with steps.start('Verify Learned mac address consistency between hardware and software'):
            if verify_mac_cc_between_hardware_software([prim_vtep, sec_vtep, sa_vtep]):
                self.passed('MAC CC success')
            else:
                self.failed('MAC CC failed')
    
    @aetest.test
    def verify_portchannel_HMM_restart(self, testscript, testbed, steps):
        sa_vtep = testscript.parameters['LEAF-3']
        prim_vtep = testscript.parameters['LEAF-1']
        sec_vtep = testscript.parameters['LEAF-2']
        prim_vpc_mac = str(testscript.parameters['PORTSEC_Dict']['prim_vpc_mac'])
        ixNetwork   = testscript.parameters['ixNetwork']
        p1_handle       = testscript.parameters['vpc_handle']
        p2_handle       = testscript.parameters['sa_handle']
        
        with steps.start("Starting hosts.."):
            p1_handle.Start()
            p2_handle.Start()
        
        log.info('Waiting {}secs to start 1025 hosts'.format(host_start_time))
        time.sleep(host_start_time)
    
        stream1 = ixNetwork.Traffic.TrafficItem.find(Name='Access VPC To Standalone')
        #
        stream1.StartStatelessTraffic()
        
        log.info('Waiting {}secs to start the traffic'.format(traffic_start_time))
        time.sleep(traffic_start_time)
        
        with steps.start('HMM restart on VPC primary'):
            if not verify_process_restart(prim_vtep, "hmm", testscript, log):
                log.error("HMM restart failed on primary")
                self.failed("HMM restart failed on primary")
            
        log.info('Waiting 30secs for macs sync')    
        time.sleep(30)
        
        with steps.start("Checking mac learning on VPC and remote after primary HMM restart"):
            if not verify_port_sec_addr_count(prim_vtep, 'port-channel 11', 1, 'STATIC'):
                log.error("STATIC Mac learning failed")
                self.failed("STATIC Mac learning failed")
        
            if not verify_port_sec_addr_count(prim_vtep, 'port-channel 11', 1024, 'DYNAMIC'):
                log.error("DYNAMIC Mac learning failed")
                self.failed("DYNAMIC Mac learning failed")

            if not verify_port_sec_addr_count(sec_vtep, 'port-channel 11', 1, 'STATIC'):
                log.error("STATIC Mac learning failed")
                self.failed("STATIC Mac learning failed")
        
            if not verify_port_sec_addr_count(sec_vtep, 'port-channel 11', 1024, 'DYNAMIC'):
                log.error("DYNAMIC Mac learning failed")
                self.failed("DYNAMIC Mac learning failed")
            
            if not verify_secure_mac_on_vteps(prim_vtep, '1001', 1025, prim_vpc_mac, 'secure'):
                log.error("Mac learning failed on primary")
                self.failed("Mac learning failed on primary")

            if not verify_secure_mac_on_vteps(sec_vtep, '1001', 1025, prim_vpc_mac, 'secure'):
                log.error("Mac learning failed on primary")
                self.failed("Mac learning failed on primary")
                
            if not verify_secure_mac_on_vteps(sa_vtep, '1001', 1025, prim_vpc_mac):
                log.error("Mac learning failed on standalone")
                self.failed("Mac learning failed on standalone")
        
        with steps.start('HMM restart on VPC secondary'):
            if not verify_process_restart(sec_vtep, "hmm", testscript, log):
                log.error("HMM restart failed on secondary")
                self.failed("HMM restart failed on secondary")
        
        log.info('Waiting 30secs for macs sync')
        time.sleep(30)

        with steps.start("Checking mac learning on VPC vtep and remote vtep after secondary HMM restart"):
            if not verify_port_sec_addr_count(prim_vtep, 'port-channel 11', 1, 'STATIC'):
                log.error("STATIC Mac learning failed")
                self.failed("STATIC Mac learning failed")
        
            if not verify_port_sec_addr_count(prim_vtep, 'port-channel 11', 1024, 'DYNAMIC'):
                log.error("DYNAMIC Mac learning failed")
                self.failed("DYNAMIC Mac learning failed")

            if not verify_port_sec_addr_count(sec_vtep, 'port-channel 11', 1, 'STATIC'):
                log.error("STATIC Mac learning failed")
                self.failed("STATIC Mac learning failed")
        
            if not verify_port_sec_addr_count(sec_vtep, 'port-channel 11', 1024, 'DYNAMIC'):
                log.error("DYNAMIC Mac learning failed")
                self.failed("DYNAMIC Mac learning failed")
            
            if not verify_secure_mac_on_vteps(prim_vtep, '1001', 1025, prim_vpc_mac, 'secure'):
                log.error("Mac learning failed on primary")
                self.failed("Mac learning failed on primary")

            if not verify_secure_mac_on_vteps(sec_vtep, '1001', 1025, prim_vpc_mac, 'secure'):
                log.error("Mac learning failed on primary")
                self.failed("Mac learning failed on primary")
                
            if not verify_secure_mac_on_vteps(sa_vtep, '1001', 1025, prim_vpc_mac):
                log.error("Mac learning failed on standalone")
                self.failed("Mac learning failed on standalone")

        stream1.StopStatelessTraffic()
        log.info('Waiting {}secs to stop the traffic'.format(traffic_stop_time))
        time.sleep(traffic_stop_time)

        with steps.start("Verify Steady State after HMM restart on VPC Primary/Secondary"):
            if VerifyTraffic("Test_023_VPC_HMM_Restart", testscript, 
                             traffic_item='Access VPC To Standalone'):
                log.info('Verify Traffic Success after HMM Restart')
            else:
                self.failed('Verify Traffic Failed after HMM Restart')

        with steps.start('Verify Learned mac address consistency between hardware and software'):
            if verify_mac_cc_between_hardware_software([prim_vtep, sec_vtep, sa_vtep]):
                self.passed('MAC CC success')
            else:
                self.failed('MAC CC failed')

    @aetest.test
    def verify_fex_HMM_restart(self, testscript, testbed, steps):
        sa_vtep = testscript.parameters['LEAF-3']
        prim_vtep = testscript.parameters['LEAF-1']
        sec_vtep = testscript.parameters['LEAF-2']
        fex_vtep_if = str(testscript.parameters['intf_LEAF_1_FEX_to_IXIA'])
        prim_fex_mac = str(testscript.parameters['PORTSEC_Dict']['prim_fex_mac'])
        ixNetwork   = testscript.parameters['ixNetwork']
        p1_handle       = testscript.parameters['fex_handle']
        p2_handle       = testscript.parameters['sa_handle']
        
        with steps.start('Starting hosts..'):
            p1_handle.Start()
            p2_handle.Start()
        
        log.info('Waiting {}secs to start 1025 hosts'.format(host_start_time))
        time.sleep(host_start_time)
        
        stream1 = ixNetwork.Traffic.TrafficItem.find(Name='Access FEX To Standalone')
        #
        stream1.StartStatelessTraffic()
        
        log.info('Waiting {}secs to start the traffic'.format(traffic_start_time))
        time.sleep(traffic_start_time)
        
        with steps.start('HMM restart on VPC primary/secondary and standalone'):
            if not verify_process_restart(prim_vtep, "hmm", testscript, log):
                log.error("HMM restart failed on primary")
                self.failed("HMM restart failed on primary")
            
            if not verify_process_restart(sec_vtep, "hmm", testscript, log):
                log.error("HMM restart failed on secondary")
                self.failed("HMM restart failed on secondary")
        
        log.info('Waiting 30secs for Macs sync')
        time.sleep(30)
        
        with steps.start("Checking mac learning on vpc and remote after HMM restart"):
            if not verify_port_sec_addr_count(prim_vtep, fex_vtep_if, 1025, 'DYNAMIC'):
                log.error("DYNAMIC Mac learning failed")
                self.failed("DYNAMIC Mac learning failed")

            if not verify_secure_mac_on_vteps(prim_vtep, '1001', 1025, prim_fex_mac, 'secure'):
                log.error("Mac learning failed on primary")
                self.failed("Mac learning failed on primary")
            if not verify_secure_mac_on_vteps(sec_vtep, '1001', 1025, prim_fex_mac, 'secure'):
                log.error("Mac learning failed on primary")
                self.failed("Mac learning failed on primary")
            if not verify_secure_mac_on_vteps(sa_vtep, '1001', 1025, prim_fex_mac):
                log.error("Mac learning failed on standalone")
                self.failed("Mac learning failed on standalone")
        
        stream1.StopStatelessTraffic()
        log.info('Waiting {}secs to stop the traffic'.format(traffic_stop_time))
        time.sleep(traffic_stop_time)
        
        with steps.start("Verify Steady State after HMM Restart"):
            if VerifyTraffic("Test_023_FEX_HMM_Restart", testscript, traffic_item='Access FEX To Standalone'):
                log.info('Verify Traffic success after HMM Restart')
            else:
                log.debug('Verify Traffic failed after HMM Restart')

        with steps.start('Verify Learned mac address consistency between hardware and software'):
            if verify_mac_cc_between_hardware_software([prim_vtep, sec_vtep, sa_vtep]):
                self.passed('MAC CC success')
            else:
                self.failed('MAC CC failed')
    
    @aetest.test
    def test_cleanup(self, testscript, testbed, steps):
        sa_vtep = testscript.parameters['LEAF-3']
        prim_vtep = testscript.parameters['LEAF-1']
        sec_vtep = testscript.parameters['LEAF-2']
        prim_vtep_if = str(testscript.parameters['intf_LEAF_1_1_to_IXIA'])
        sa_vtep_if = str(testscript.parameters['intf_LEAF_3_to_IXIA'])
        leaf1_mac = str(testscript.parameters['PORTSEC_Dict']['vpc_static_mac'])
        leaf2_mac = str(testscript.parameters['PORTSEC_Dict']['vpc_static_mac1'])
        src_vlan = int(testscript.parameters['LEAF_1_Orphan1_TGEN_dict']['vlan_id'])
        fex_vtep_if = str(testscript.parameters['intf_LEAF_1_FEX_to_IXIA'])
        
        ixNetwork   = testscript.parameters['ixNetwork']
        
        with steps.start("Stopping all hosts..."):
            ixNetwork.StopAllProtocols()

        log.info('Waiting {}secs to stop the hosts'.format(traffic_stop_time))
        time.sleep(traffic_stop_time)
        
        with steps.start("ReConfigure Port-Security - Dynamic on Leaf-1 - Primary VTEP Orphan"):
            try:
                prim_vtep.configure('''interface {prim_vtep_if}
                                    shutdown
                                    no switchport port-security aging type inactivity
                                    no switchport port-security mac-address sticky
                                    no switchport port-security violation restrict
                                    no shutdown
                                    '''.format(prim_vtep_if=prim_vtep_if))
            except Exception as error:
                log.debug("Unable to configure - Encountered Exception " + str(error))
                self.errored('Exception occurred while configuring port security', goto=['common_cleanup'])
         
        with steps.start("Reconfigure Port-Security - Dynamic on Leaf-3 - Standalone VTEP"):
            try:
                sa_vtep.configure('''interface {sa_vtep_if}
                                    shutdown
                                    no switchport port-security violation restrict
                                    no switchport port-security mac-address sticky
                                    no switchport port-security aging type inactivity
                                    no shutdown
                                    '''.format(sa_vtep_if=sa_vtep_if))
            except Exception as error:
                log.debug("Unable to configure - Encountered Exception " + str(error))
                self.errored('Exception occurred while configuring port security', goto=['common_cleanup'])

        with steps.start("Remove Port-Security on Leaf-1 VPC Member"):
            try:
                prim_vtep.configure('''interface port-channel 11
                                no switchport port-security mac-address {mac}
                                no switchport port-security aging type inactivity
                                no switchport port-security violation restrict
                                no switchport port-security'''.format(mac=leaf1_mac))
            except Exception as error:
                log.debug("Unable to configure - Encountered Exception " + str(error))
                self.errored('Exception occurred while configuring port security', goto=['common_cleanup'])

        with steps.start("Remove Port-Security on Leaf-2 VPC Member"):
            try:
                sec_vtep.configure('''interface port-channel 11
                                no switchport port-security mac-address {mac}
                                no switchport port-security aging type inactivity
                                no switchport port-security violation restrict
                                no switchport port-security'''.format(mac=leaf2_mac))
            except Exception as error:
                log.debug("Unable to configure - Encountered Exception " + str(error))
                self.errored('Exception occurred while configuring port security', goto=['common_cleanup'])
        
        with steps.start("ReConfigure Port-Security on Leaf-1 FEX - FEX port of VTEP"):
            try:
                prim_vtep.configure('''interface {intf}
                                    shutdown
                                    no switchport port-security violation protect
                                    switchport port-security
                                    no shutdown'''.format(intf=fex_vtep_if))
            except Exception as error:
                log.debug("Unable to configure - Encountered Exception " + str(error))
                self.errored('Exception occurred while configuring port security', goto=['common_cleanup'])
        
        with steps.start("Verifying MTS leak.."):
            if verify_mts_leak([prim_vtep, sec_vtep, sa_vtep], log):
                self.passed('MTS Leak verification success')
            else:
                self.failed('MTS Leak verification failed')

# =============================================================================================================================#
# TC-ID: TC70 - Orphan
# Testcase:
#
# 1. Once traffic started change mode from access to trunk
# 2. Check whether macs flushed out
# 3. Reconfigure the mode back to access
# 4. Check traffic is fine
# =============================================================================================================================#
class TC_VXLAN_PS_022_Access(aetest.Testcase):    
    @aetest.test
    def verify_mode_change_access_to_trunk_orphan(self, testscript, testbed, steps):
        sa_vtep         = testscript.parameters['LEAF-3']
        prim_vtep       = testscript.parameters['LEAF-1']
        sec_vtep        = testscript.parameters['LEAF-2']
        prim_vtep_if    = str(testscript.parameters['intf_LEAF_1_1_to_IXIA'])
        sa_vtep_if      = str(testscript.parameters['intf_LEAF_3_to_IXIA'])
        prim_orphan_mac = str(testscript.parameters['PORTSEC_Dict']['prim_orphan_mac'])
        sa_mac          = str(testscript.parameters['PORTSEC_Dict']['sa_mac'])
        p1_handle       = testscript.parameters['orphan1_handle']
        p2_handle       = testscript.parameters['sa_handle']
        ixNetwork       = testscript.parameters['ixNetwork']

        with steps.start("Configure Port-Security on Standalone VTEP"):
            if not config_interface_ps([sa_vtep], sa_vtep_if, log):
                self.errored('Exception occurred while configuring port security', goto=['common_cleanup'])

        with steps.start("Configure Port-Security on Primary VTEP Orphan"):
            if not config_interface_ps([prim_vtep], prim_vtep_if, log):
                self.errored('Exception occurred while configuring port security', goto=['common_cleanup'])
        
        log.info("Waiting {}secs for interface to come up".format(config_time))
        time.sleep(config_time)
        display_configs(testscript)
        
        with steps.start("Starting hosts.."):
            p1_handle.Start()
            p2_handle.Start()
        
        log.info('Waiting {}secs to start 1025 hosts'.format(host_start_time))
        time.sleep(host_start_time)
        
        stream1 = ixNetwork.Traffic.TrafficItem.find(Name='Access Orphan To Standalone')
        stream1.StartStatelessTraffic()
        log.info('Waiting {}secs to start the traffic'.format(traffic_start_time))
        time.sleep(traffic_start_time)
        
        stream1.StopStatelessTraffic()
        log.info('Waiting {}secs to stop the traffic'.format(traffic_stop_time))
        time.sleep(traffic_stop_time)

        with steps.start("Checking mac learning on orphan and remote"):
            if not verify_port_sec_addr_count(prim_vtep, prim_vtep_if, 1025, 'DYNAMIC'):
                log.error("DYNAMIC Mac learning failed")
                self.failed("DYNAMIC Mac learning failed")

            if not verify_secure_mac_on_vteps(prim_vtep, '1001', 1025, prim_orphan_mac, 'secure'):
                log.error("Mac learning failed on primary")
                self.failed("Mac learning failed on primary")

            if not verify_secure_mac_on_vteps(sec_vtep, '1001', 1025, prim_orphan_mac, 'secure'):
                log.error("Mac learning failed on primary")
                self.failed("Mac learning failed on primary")
                
            if not verify_secure_mac_on_vteps(sa_vtep, '1001', 1025, prim_orphan_mac):
                log.error("Mac learning failed on standalone")
                self.failed("Mac learning failed on standalone")

        with steps.start("Checking mac learning on standalone and remote"):
            if not verify_port_sec_addr_count(sa_vtep, sa_vtep_if, 1025, 'DYNAMIC'):
                log.error("DYNAMIC Mac learning failed")
                self.failed("DYNAMIC Mac learning failed")

            if not verify_secure_mac_on_vteps(sa_vtep, '1002', 1025, sa_mac, 'secure'):
                log.error("Mac learning failed on Standalone")
                self.failed("Mac learning failed on Standalone")

            if not verify_secure_mac_on_vteps(prim_vtep, '1002', 1025, sa_mac):
                log.error("DYNAMIC Mac learning failed on remote vtep(leaf1)")
                self.failed("DYNAMIC Mac learning failed on remote vtep(leaf1)")

            if not verify_secure_mac_on_vteps(sec_vtep, '1002', 1025, sa_mac):
                log.error("DYNAMIC Mac learning failed on remote vtep(leaf2)")
                self.failed("DYNAMIC Mac learning failed on remote vtep(leaf2)")

        with steps.start("Change switchport mode to trunk - Standalone"):
            try:
                sa_vtep.configure('''interface {sa_vtep_if}
                                     switchport mode trunk  
                                  '''.format(sa_vtep_if=sa_vtep_if))
            except Exception as error:
                log.debug("Unable to configure - Encountered Exception " + str(error))
                self.errored('Exception occurred while configuring port security', goto=['common_cleanup'])
        
        with steps.start("Change switchport mode to trunk - Orphan"):
            try:
                prim_vtep.configure('''interface {intf}
                                       switchport mode trunk
                                    '''.format(intf=prim_vtep_if))
            except Exception as error:
                log.debug("Unable to configure - Encountered Exception " + str(error))
                self.errored('Exception occurred while configuring port security', 
                             goto=['common_cleanup'])
        
        log.info('Waiting 30secs for mac flushout')
        time.sleep(30)
        
        with steps.start("Checking mac flushout on orphan and remote"):
            if not verify_port_sec_addr_count(prim_vtep, prim_vtep_if, 0, 'DYNAMIC'):
                log.error("DYNAMIC Mac learning failed")
                self.failed("DYNAMIC Mac learning failed")

            if not verify_secure_mac_on_vteps(prim_vtep, '1001', 0, prim_orphan_mac, 'secure'):
                log.error("Mac learning failed on primary")
                self.failed("Mac learning failed on primary")

            if not verify_secure_mac_on_vteps(sec_vtep, '1001', 0, prim_orphan_mac, 'secure'):
                log.error("Mac learning failed on primary")
                self.failed("Mac learning failed on primary")
                
            if not verify_secure_mac_on_vteps(sa_vtep, '1001', 0, prim_orphan_mac):
                log.error("Mac learning failed on standalone")
                self.failed("Mac learning failed on standalone")

        with steps.start("Checking mac learning on standalone and remote"):
            if not verify_port_sec_addr_count(sa_vtep, sa_vtep_if, 0, 'DYNAMIC'):
                log.error("DYNAMIC Mac learning failed")
                self.failed("DYNAMIC Mac learning failed")

            if not verify_secure_mac_on_vteps(sa_vtep, '1002', 0, sa_mac, 'secure'):
                log.error("Mac learning failed on Standalone")
                self.failed("Mac learning failed on Standalone")

            if not verify_secure_mac_on_vteps(prim_vtep, '1002', 0, sa_mac):
                log.error("DYNAMIC Mac learning failed on remote vtep(leaf1)")
                self.failed("DYNAMIC Mac learning failed on remote vtep(leaf1)")

            if not verify_secure_mac_on_vteps(sec_vtep, '1002', 0, sa_mac):
                log.error("DYNAMIC Mac learning failed on remote vtep(leaf2)")
                self.failed("DYNAMIC Mac learning failed on remote vtep(leaf2)")

        with steps.start("Change switchport mode to trunk - Standalone"):
            try:
                sa_vtep.configure('''interface {sa_vtep_if}
                                     switchport mode access   
                                  '''.format(sa_vtep_if=sa_vtep_if))
            except Exception as error:
                log.debug("Unable to configure - Encountered Exception " + str(error))
                self.errored('Exception occurred while configuring port security', 
                             goto=['common_cleanup'])
        
        with steps.start("Change switchport mode to trunk - Orphan"):
            try:
                prim_vtep.configure('''interface {intf}
                                       switchport mode access
                                    '''.format(intf=prim_vtep_if))
            except Exception as error:
                log.debug("Unable to configure - Encountered Exception " + str(error))
                self.errored('Exception occurred while configuring port security', 
                             goto=['common_cleanup'])
                
        log.info('Waiting 30secs for interfaces to come up')
        time.sleep(30)
        
        stream1 = ixNetwork.Traffic.TrafficItem.find(Name='Access Orphan To Standalone')
        stream1.StartStatelessTraffic()
        log.info('Waiting {}secs to start the traffic'.format(traffic_start_time))
        time.sleep(traffic_start_time)
        
        stream1.StopStatelessTraffic()
        log.info('Waiting {}secs to stop the traffic'.format(traffic_stop_time))
        time.sleep(traffic_stop_time)
        
        with steps.start("Checking mac relearning on orphan and remote"):
            if not verify_port_sec_addr_count(prim_vtep, prim_vtep_if, 1025, 'DYNAMIC'):
                log.error("DYNAMIC Mac learning failed")
                self.failed("DYNAMIC Mac learning failed")

            if not verify_secure_mac_on_vteps(prim_vtep, '1001', 1025, prim_orphan_mac, 'secure'):
                log.error("Mac learning failed on primary")
                self.failed("Mac learning failed on primary")

            if not verify_secure_mac_on_vteps(sec_vtep, '1001', 1025, prim_orphan_mac, 'secure'):
                log.error("Mac learning failed on primary")
                self.failed("Mac learning failed on primary")
                
            if not verify_secure_mac_on_vteps(sa_vtep, '1001', 1025, prim_orphan_mac):
                log.error("Mac learning failed on standalone")
                self.failed("Mac learning failed on standalone")

        with steps.start("Checking mac relearning on standalone and remote"):
            if not verify_port_sec_addr_count(sa_vtep, sa_vtep_if, 1025, 'DYNAMIC'):
                log.error("DYNAMIC Mac learning failed")
                self.failed("DYNAMIC Mac learning failed")

            if not verify_secure_mac_on_vteps(sa_vtep, '1002', 1025, sa_mac, 'secure'):
                log.error("Mac learning failed on Standalone")
                self.failed("Mac learning failed on Standalone")

            if not verify_secure_mac_on_vteps(prim_vtep, '1002', 1025, sa_mac):
                log.error("DYNAMIC Mac learning failed on remote vtep(leaf1)")
                self.failed("DYNAMIC Mac learning failed on remote vtep(leaf1)")

            if not verify_secure_mac_on_vteps(sec_vtep, '1002', 1025, sa_mac):
                log.error("DYNAMIC Mac learning failed on remote vtep(leaf2)")
                self.failed("DYNAMIC Mac learning failed on remote vtep(leaf2)")

        with steps.start("Verify Steady State"):
            if VerifyTraffic("Test_024_Orphan", testscript, 
                             traffic_item='Access Orphan To Standalone'):
                self.passed('Verify traffic success')
            else:
                self.failed('Verify traffic failure')

    @aetest.test
    def test_cleanup(self, testscript, testbed, steps):
        sa_vtep         = testscript.parameters['LEAF-3']
        prim_vtep       = testscript.parameters['LEAF-1']
        sec_vtep        = testscript.parameters['LEAF-2']
        prim_vtep_if    = str(testscript.parameters['intf_LEAF_1_1_to_IXIA'])
        sa_vtep_if      = str(testscript.parameters['intf_LEAF_3_to_IXIA'])
        ixNetwork       = testscript.parameters['ixNetwork']
        
        with steps.start("Stopping all hosts..."):
            ixNetwork.StopAllProtocols()

        log.info('Waiting {}secs to stop the hosts'.format(traffic_stop_time))
        time.sleep(traffic_stop_time)
        
        with steps.start("UnConfigure Port-Security on Primary VTEP Orphan"):
            if not unconfig_interface_ps([prim_vtep], prim_vtep_if, log):
                self.errored('Exception occurred while configuring port security', goto=['common_cleanup'])
        
        with steps.start("UnConfigure Port-Security on Standalone VTEP"):
            if not unconfig_interface_ps([sa_vtep], sa_vtep_if, log):
                self.errored('Exception occurred while configuring port security', goto=['common_cleanup'])
        
        with steps.start('Verify Learned mac address consistency between hardware and software'):
            if verify_mac_cc_between_hardware_software([prim_vtep, sec_vtep, sa_vtep]):
                log.info('MAC CC success')
            else:
                self.failed('MAC CC failed')
        
        with steps.start("Verifying MTS leak.."):
            if verify_mts_leak([prim_vtep, sec_vtep, sa_vtep], log):
                log.info('MTS Leak verification success')
            else:
                self.failed('MTS Leak verification failed')

        with steps.start("Verifying Cores and Log Errors"):
            status = infraVerify.postTestVerification(post_test_process_dict)
            if status['status'] == 0:
                self.failed(reason=status['logs'])
            else:
                self.passed(reason=status['logs'])

# =============================================================================================================================#
# TC-ID: TC70 - VPC
# Testcase:
#
# 1. Once traffic started change mode from access to trunk
# 2. Check whether macs flushed out
# 3. Reconfigure the mode back to access
# 4. Check traffic is fine
# =============================================================================================================================#
class TC_VXLAN_PS_023_Access(aetest.Testcase):
    @aetest.test
    def verify_mode_change_from_access_to_trunk_vpc(self, testscript, testbed, steps):
        sa_vtep         = testscript.parameters['LEAF-3']
        prim_vtep       = testscript.parameters['LEAF-1']
        sec_vtep        = testscript.parameters['LEAF-2']
        sa_vtep_if      = str(testscript.parameters['intf_LEAF_3_to_IXIA'])
        prim_vpc_mac    = str(testscript.parameters['PORTSEC_Dict']['prim_vpc_mac'])
        p1_handle       = testscript.parameters['vpc_handle']
        p2_handle       = testscript.parameters['sa_handle']
        ixNetwork       = testscript.parameters['ixNetwork']

        with steps.start("Configure Port-Security on VPC Primary/Secondary"):
            if not config_interface_ps([prim_vtep, sec_vtep], 'port-channel 11', log):
                self.errored('Exception occurred while configuring port security', goto=['common_cleanup'])
        
        with steps.start("Configure Port-Security on Standalone VTEP"):
            if not config_interface_ps([sa_vtep], sa_vtep_if, log):
                self.errored('Exception occurred while configuring port security', goto=['common_cleanup'])
        
        log.info("Waiting {}secs for interface to come up".format(config_time))
        time.sleep(config_time)
        display_configs(testscript)

        with steps.start("Starting hosts..."):
            p1_handle.Start()
            p2_handle.Start()

        log.info('Waiting {}secs to start 1025 hosts'.format(host_start_time))
        time.sleep(host_start_time)
    
        stream1 = ixNetwork.Traffic.TrafficItem.find(Name='Access VPC To Standalone')
        stream1.StartStatelessTraffic()
        log.info('Waiting {}secs to start the traffic'.format(traffic_start_time))
        time.sleep(traffic_start_time)
        
        stream1.StopStatelessTraffic()
        log.info('Waiting {}secs to stop the traffic'.format(traffic_stop_time))
        time.sleep(traffic_stop_time)

        with steps.start("Checking mac learning on orphan and remote"):
            if not verify_port_sec_addr_count(prim_vtep, 'port-channel 11', 1025, 'DYNAMIC'):
                log.error("DYNAMIC Mac learning failed")
                self.failed("DYNAMIC Mac learning failed")
        
            if not verify_port_sec_addr_count(sec_vtep, 'port-channel 11', 1025, 'DYNAMIC'):
                log.error("STATIC Mac learning failed")
                self.failed("STATIC Mac learning failed")
        
            if not verify_secure_mac_on_vteps(prim_vtep, '1001', 1025, prim_vpc_mac, 'secure'):
                log.error("Mac learning failed on primary")
                self.failed("Mac learning failed on primary")

            if not verify_secure_mac_on_vteps(sec_vtep, '1001', 1025, prim_vpc_mac, 'secure'):
                log.error("Mac learning failed on primary")
                self.failed("Mac learning failed on primary")
                
            if not verify_secure_mac_on_vteps(sa_vtep, '1001', 1025, prim_vpc_mac):
                log.error("Mac learning failed on standalone")
                self.failed("Mac learning failed on standalone")

        with steps.start("Change switchport mode to trunk - PO11 Primary"):
            try:
                prim_vtep.configure('''interface port-channel 11
                                       switchport mode trunk''')
            except Exception as error:
                log.debug("Unable to configure - Encountered Exception " + str(error))
                self.errored('Exception occurred while configuring port security', 
                             goto=['common_cleanup'])
        
        with steps.start("Change switchport mode to trunk - PO11 Secondary"):
            try:
                sec_vtep.configure('''interface port-channel 11
                                      switchport mode trunk''')

            except Exception as error:
                log.debug("Unable to configure - Encountered Exception " + str(error))
                self.errored('Exception occurred while configuring port security', 
                             goto=['common_cleanup'])
        
        log.info('Waiting 30secs for mac flushout')
        time.sleep(30)
        
        with steps.start("Checking mac flushout on orphan and remote"):
            if not verify_port_sec_addr_count(prim_vtep, 'port-channel 11', 0, 'DYNAMIC'):
                log.error("DYNAMIC Mac learning failed")
                self.failed("DYNAMIC Mac learning failed")
        
            if not verify_port_sec_addr_count(sec_vtep, 'port-channel 11', 0, 'DYNAMIC'):
                log.error("STATIC Mac learning failed")
                self.failed("STATIC Mac learning failed")
        
            if not verify_secure_mac_on_vteps(prim_vtep, '1001', 0, prim_vpc_mac, 'secure'):
                log.error("Mac learning failed on primary")
                self.failed("Mac learning failed on primary")

            if not verify_secure_mac_on_vteps(sec_vtep, '1001', 0, prim_vpc_mac, 'secure'):
                log.error("Mac learning failed on primary")
                self.failed("Mac learning failed on primary")
                
            if not verify_secure_mac_on_vteps(sa_vtep, '1001', 0, prim_vpc_mac):
                log.error("Mac learning failed on standalone")
                self.failed("Mac learning failed on standalone")
        
        with steps.start("Change mode back to access"):
            try:
                prim_vtep.configure('''interface port-channel 11
                                       switchport mode access''')
            except Exception as error:
                log.debug("Unable to configure - Encountered Exception " + str(error))
                self.errored('Exception occurred while configuring port security', 
                             goto=['common_cleanup'])

            try:
                sec_vtep.configure('''interface port-channel 11
                                       switchport mode access''')
            except Exception as error:
                log.debug("Unable to configure - Encountered Exception " + str(error))
                self.errored('Exception occurred while configuring port security', 
                             goto=['common_cleanup'])
    
        log.info('Waiting 60secs for mac relearning')
        time.sleep(60)
        
        stream1 = ixNetwork.Traffic.TrafficItem.find(Name='Access VPC To Standalone')
        stream1.StartStatelessTraffic()
        log.info('Waiting {}secs to start the traffic'.format(traffic_start_time))
        time.sleep(traffic_start_time)
        
        stream1.StopStatelessTraffic()
        log.info('Waiting {}secs to stop the traffic'.format(traffic_stop_time))
        time.sleep(traffic_stop_time)

        with steps.start("Checking mac relearning on orphan and remote"):
            if not verify_port_sec_addr_count(prim_vtep, 'port-channel 11', 1025, 'DYNAMIC'):
                log.error("DYNAMIC Mac learning failed")
                self.failed("DYNAMIC Mac learning failed")
        
            if not verify_port_sec_addr_count(sec_vtep, 'port-channel 11', 1025, 'DYNAMIC'):
                log.error("STATIC Mac learning failed")
                self.failed("STATIC Mac learning failed")
        
            if not verify_secure_mac_on_vteps(prim_vtep, '1001', 1025, prim_vpc_mac, 'secure'):
                log.error("Mac learning failed on primary")
                self.failed("Mac learning failed on primary")

            if not verify_secure_mac_on_vteps(sec_vtep, '1001', 1025, prim_vpc_mac, 'secure'):
                log.error("Mac learning failed on primary")
                self.failed("Mac learning failed on primary")
                
            if not verify_secure_mac_on_vteps(sa_vtep, '1001', 1025, prim_vpc_mac):
                log.error("Mac learning failed on standalone")
                self.failed("Mac learning failed on standalone")
        
        with steps.start('Verify Learned mac address consistency between hardware and software'):
            if verify_mac_cc_between_hardware_software([prim_vtep, sec_vtep, sa_vtep]):
                log.info('MAC CC success')
            else:
                self.failed('MAC CC failed')

        with steps.start("Verify Steady State"):
            if VerifyTraffic("Test_025_VPC", testscript, traffic_item='Access VPC To Standalone'):
                self.passed('Verify traffic success')
            else:
                self.failed('Verify traffic failure')
    
    @aetest.test
    def unconfig(self, testscript, testbed, steps):
        sa_vtep         = testscript.parameters['LEAF-3']
        prim_vtep       = testscript.parameters['LEAF-1']
        sec_vtep        = testscript.parameters['LEAF-2']
        sa_vtep_if      = str(testscript.parameters['intf_LEAF_3_to_IXIA'])
        ixNetwork       = testscript.parameters['ixNetwork']

        with steps.start("UnConfigure Port-Security on VPC Primary/Secondary - Static"):
            if not unconfig_interface_ps([prim_vtep, sec_vtep], 'port-channel 11', log):
                self.errored('Exception occurred while configuring port security', goto=['common_cleanup'])
        
        with steps.start("UnConfigure Port-Security on Standalone VTEP"):
            if not unconfig_interface_ps([sa_vtep], sa_vtep_if, log):
                self.errored('Exception occurred while configuring port security', goto=['common_cleanup'])
        
        log.info("Waiting {}secs for interface to come up".format(config_time))
        time.sleep(config_time)
        
        with steps.start("Stopping all hosts..."):
            ixNetwork.StopAllProtocols()

        log.info('Waiting {}secs to stop the hosts'.format(traffic_stop_time))
        time.sleep(traffic_stop_time)
        
        with steps.start("Verifying MTS leak.."):
            if verify_mts_leak([prim_vtep, sec_vtep, sa_vtep], log):
                log.info('MTS Leak verification success')
            else:
                self.failed('MTS Leak verification failed')

        with steps.start("Verifying Cores and Log Errors"):
            status = infraVerify.postTestVerification(post_test_process_dict)
            if status['status'] == 0:
                self.failed(reason=status['logs'])
            else:
                self.passed(reason=status['logs'])

# =============================================================================================================================#
# TC-ID: TC70 - Fex
# Testcase:
#
# 1. Once traffic started change mode from access to trunk
# 2. Check whether macs flushed out
# 3. Reconfigure the mode back to access
# 4. Check traffic is fine
# =============================================================================================================================#
class TC_VXLAN_PS_024_Access(aetest.Testcase):    
    @aetest.test
    def verify_mode_change_access_to_trunk_fex(self, testscript, testbed, steps):
        sa_vtep         = testscript.parameters['LEAF-3']
        prim_vtep       = testscript.parameters['LEAF-1']
        sec_vtep        = testscript.parameters['LEAF-2']
        prim_vtep_if    = str(testscript.parameters['intf_LEAF_1_FEX_to_IXIA'])
        sa_vtep_if      = str(testscript.parameters['intf_LEAF_3_to_IXIA'])
        prim_mac        = str(testscript.parameters['PORTSEC_Dict']['prim_fex_mac'])
        sa_mac          = str(testscript.parameters['PORTSEC_Dict']['sa_mac'])
        p1_handle       = testscript.parameters['fex_handle']
        p2_handle       = testscript.parameters['sa_handle']
        ixNetwork       = testscript.parameters['ixNetwork']

        with steps.start("Configure Port-Security on Standalone VTEP"):
            if not config_interface_ps([sa_vtep], sa_vtep_if, log):
                self.errored('Exception occurred while configuring port security', goto=['common_cleanup'])

        with steps.start("Configure Port-Security on Primary VTEP FEX"):
            if not config_interface_ps([prim_vtep], prim_vtep_if, log):
                self.errored('Exception occurred while configuring port security', goto=['common_cleanup'])
        
        log.info("Waiting {}secs for interface to come up".format(config_time))
        time.sleep(config_time)
        display_configs(testscript)

        with steps.start("Starting hosts.."):
            p1_handle.Start()
            p2_handle.Start()
        
        log.info('Waiting {}secs to start 1025 hosts'.format(host_start_time))
        time.sleep(host_start_time)
        
        stream1 = ixNetwork.Traffic.TrafficItem.find(Name='Access FEX To Standalone')
        stream1.StartStatelessTraffic()
        log.info('Waiting {}secs to start the traffic'.format(traffic_start_time))
        time.sleep(traffic_start_time)
        
        stream1.StopStatelessTraffic()
        log.info('Waiting {}secs to stop the traffic'.format(traffic_stop_time))
        time.sleep(traffic_stop_time)

        with steps.start("Checking mac learning on orphan and remote"):
            if not verify_port_sec_addr_count(prim_vtep, prim_vtep_if, 1025, 'DYNAMIC'):
                log.error("DYNAMIC Mac learning failed")
                self.failed("DYNAMIC Mac learning failed")

            if not verify_secure_mac_on_vteps(prim_vtep, '1001', 1025, prim_mac, 'secure'):
                log.error("Mac learning failed on primary")
                self.failed("Mac learning failed on primary")

            if not verify_secure_mac_on_vteps(sec_vtep, '1001', 1025, prim_mac, 'secure'):
                log.error("Mac learning failed on primary")
                self.failed("Mac learning failed on primary")
                
            if not verify_secure_mac_on_vteps(sa_vtep, '1001', 1025, prim_mac):
                log.error("Mac learning failed on standalone")
                self.failed("Mac learning failed on standalone")

        with steps.start("Checking mac learning on standalone and remote"):
            if not verify_port_sec_addr_count(sa_vtep, sa_vtep_if, 1025, 'DYNAMIC'):
                log.error("DYNAMIC Mac learning failed")
                self.failed("DYNAMIC Mac learning failed")

            if not verify_secure_mac_on_vteps(sa_vtep, '1002', 1025, sa_mac, 'secure'):
                log.error("Mac learning failed on Standalone")
                self.failed("Mac learning failed on Standalone")

            if not verify_secure_mac_on_vteps(prim_vtep, '1002', 1025, sa_mac):
                log.error("DYNAMIC Mac learning failed on remote vtep(leaf1)")
                self.failed("DYNAMIC Mac learning failed on remote vtep(leaf1)")

            if not verify_secure_mac_on_vteps(sec_vtep, '1002', 1025, sa_mac):
                log.error("DYNAMIC Mac learning failed on remote vtep(leaf2)")
                self.failed("DYNAMIC Mac learning failed on remote vtep(leaf2)")

        with steps.start("Cange switchport mode to trunk - FEX"):
            try:
                prim_vtep.configure('''interface {intf}
                                       switchport mode trunk
                                    '''.format(intf=prim_vtep_if))
            except Exception as error:
                log.debug("Unable to configure - Encountered Exception " + str(error))
                self.errored('Exception occurred while configuring port security', 
                             goto=['common_cleanup'])
        
        log.info('Waiting 30secs for mac flushout')
        time.sleep(30)
        
        with steps.start("Checking mac flushout on orphan and remote"):
            if not verify_port_sec_addr_count(prim_vtep, prim_vtep_if, 0, 'DYNAMIC'):
                log.error("DYNAMIC Mac learning failed")
                self.failed("DYNAMIC Mac learning failed")

            if not verify_secure_mac_on_vteps(prim_vtep, '1001', 0, prim_mac, 'secure'):
                log.error("Mac learning failed on primary")
                self.failed("Mac learning failed on primary")

            if not verify_secure_mac_on_vteps(sec_vtep, '1001', 0, prim_mac, 'secure'):
                log.error("Mac learning failed on primary")
                self.failed("Mac learning failed on primary")
                
            if not verify_secure_mac_on_vteps(sa_vtep, '1001', 0, prim_mac):
                log.error("Mac learning failed on standalone")
                self.failed("Mac learning failed on standalone")

        with steps.start("Checking mac learning on standalone and remote"):
            if not verify_port_sec_addr_count(sa_vtep, sa_vtep_if, 1025, 'DYNAMIC'):
                log.error("DYNAMIC Mac learning failed")
                self.failed("DYNAMIC Mac learning failed")

            if not verify_secure_mac_on_vteps(sa_vtep, '1002', 1025, sa_mac, 'secure'):
                log.error("Mac learning failed on Standalone")
                self.failed("Mac learning failed on Standalone")

            if not verify_secure_mac_on_vteps(prim_vtep, '1002', 1025, sa_mac):
                log.error("DYNAMIC Mac learning failed on remote vtep(leaf1)")
                self.failed("DYNAMIC Mac learning failed on remote vtep(leaf1)")

            if not verify_secure_mac_on_vteps(sec_vtep, '1002', 1025, sa_mac):
                log.error("DYNAMIC Mac learning failed on remote vtep(leaf2)")
                self.failed("DYNAMIC Mac learning failed on remote vtep(leaf2)")

        with steps.start("Change switchport mode to access - FEX"):
            try:
                prim_vtep.configure('''interface {intf}
                                       switchport mode access
                                    '''.format(intf=prim_vtep_if))
            except Exception as error:
                log.debug("Unable to configure - Encountered Exception " + str(error))
                self.errored('Exception occurred while configuring port security', 
                             goto=['common_cleanup'])
                
        log.info('Waiting 30secs for interfaces to come up')
        time.sleep(30)
        
        stream1 = ixNetwork.Traffic.TrafficItem.find(Name='Access FEX To Standalone')
        stream1.StartStatelessTraffic()
        log.info('Waiting {}secs to start the traffic'.format(traffic_start_time))
        time.sleep(traffic_start_time)
        
        stream1.StopStatelessTraffic()
        log.info('Waiting {}secs to stop the traffic'.format(traffic_stop_time))
        time.sleep(traffic_stop_time)
        
        with steps.start("Checking mac relearning on orphan and remote"):
            if not verify_port_sec_addr_count(prim_vtep, prim_vtep_if, 1025, 'DYNAMIC'):
                log.error("DYNAMIC Mac learning failed")
                self.failed("DYNAMIC Mac learning failed")

            if not verify_secure_mac_on_vteps(prim_vtep, '1001', 1025, prim_mac, 'secure'):
                log.error("Mac learning failed on primary")
                self.failed("Mac learning failed on primary")

            if not verify_secure_mac_on_vteps(sec_vtep, '1001', 1025, prim_mac, 'secure'):
                log.error("Mac learning failed on primary")
                self.failed("Mac learning failed on primary")
                
            if not verify_secure_mac_on_vteps(sa_vtep, '1001', 1025, prim_mac):
                log.error("Mac learning failed on standalone")
                self.failed("Mac learning failed on standalone")

        with steps.start("Checking mac relearning on standalone and remote"):
            if not verify_port_sec_addr_count(sa_vtep, sa_vtep_if, 1025, 'DYNAMIC'):
                log.error("DYNAMIC Mac learning failed")
                self.failed("DYNAMIC Mac learning failed")

            if not verify_secure_mac_on_vteps(sa_vtep, '1002', 1025, sa_mac, 'secure'):
                log.error("Mac learning failed on Standalone")
                self.failed("Mac learning failed on Standalone")

            if not verify_secure_mac_on_vteps(prim_vtep, '1002', 1025, sa_mac):
                log.error("DYNAMIC Mac learning failed on remote vtep(leaf1)")
                self.failed("DYNAMIC Mac learning failed on remote vtep(leaf1)")

            if not verify_secure_mac_on_vteps(sec_vtep, '1002', 1025, sa_mac):
                log.error("DYNAMIC Mac learning failed on remote vtep(leaf2)")
                self.failed("DYNAMIC Mac learning failed on remote vtep(leaf2)")

        with steps.start('Verify Learned mac address consistency between hardware and software'):
            if verify_mac_cc_between_hardware_software([prim_vtep, sec_vtep, sa_vtep]):
                log.info('MAC CC success')
            else:
                self.failed('MAC CC failed')
        
        with steps.start("Verify Steady State"):
            if VerifyTraffic("Test_026_FEX", testscript, traffic_item='Access FEX To Standalone'):
                self.passed('Verify traffic success')
            else:
                self.failed('Verify traffic failure')

    @aetest.test
    def test_cleanup(self, testscript, testbed, steps):
        sa_vtep         = testscript.parameters['LEAF-3']
        prim_vtep       = testscript.parameters['LEAF-1']
        sec_vtep        = testscript.parameters['LEAF-2']
        prim_vtep_if    = str(testscript.parameters['intf_LEAF_1_FEX_to_IXIA'])
        sa_vtep_if      = str(testscript.parameters['intf_LEAF_3_to_IXIA'])
        
        ixNetwork       = testscript.parameters['ixNetwork']
        
        with steps.start("Stopping all hosts..."):
            ixNetwork.StopAllProtocols()

        log.info('Waiting {}secs to stop the hosts'.format(traffic_stop_time))
        time.sleep(traffic_stop_time)
        
        with steps.start("UnConfigure Port-Security on Primary VTEP Orphan"):
            if not unconfig_interface_ps([prim_vtep], prim_vtep_if, log):
                self.errored('Exception occurred while configuring port security', goto=['common_cleanup'])
        
        with steps.start("UnConfigure Port-Security on Standalone VTEP"):
            if not unconfig_interface_ps([sa_vtep], sa_vtep_if, log):
                self.errored('Exception occurred while configuring port security', goto=['common_cleanup'])
                
        with steps.start("Verifying MTS leak.."):
            if verify_mts_leak([prim_vtep, sec_vtep, sa_vtep], log):
                log.info('MTS Leak verification success')
            else:
                self.failed('MTS Leak verification failed')

        with steps.start("Verifying Cores and Log Errors"):
            status = infraVerify.postTestVerification(post_test_process_dict)
            if status['status'] == 0:
                self.failed(reason=status['logs'])
            else:
                self.passed(reason=status['logs'])

# =============================================================================================================================#
# TC-ID: TC028 - Secure to Secure move Orphan to Orphan move - same vtep
# Testcase:
#   Mac move should trigger security violation on Orphan2 interface
# =============================================================================================================================#
class TC_VXLAN_PS_025_Access(aetest.Testcase):
    @aetest.test
    def test_setup(self, testscript, testbed, steps):
        sa_vtep         = testscript.parameters['LEAF-3']
        prim_vtep       = testscript.parameters['LEAF-1']
        prim_vtep_if    = str(testscript.parameters['intf_LEAF_1_1_to_IXIA'])
        prim_vtep_if1   = str(testscript.parameters['intf_LEAF_1_2_to_IXIA'])
        sa_vtep_if      = str(testscript.parameters['intf_LEAF_3_to_IXIA'])
        
        with steps.start("Configure Port-Security on Primary VTEP Orphan"):
            if not config_interface_ps([prim_vtep], prim_vtep_if, log):
                self.errored('Exception occurred while configuring port security', goto=['common_cleanup'])
         
        with steps.start("Configure Port-Security on Primary VTEP Orphan1"):
            if not config_interface_ps([prim_vtep], prim_vtep_if1, log):
                self.errored('Exception occurred while configuring port security', goto=['common_cleanup'])
                
        with steps.start("Configure Port-Security on Standalone VTEP"):
            if not config_interface_ps([sa_vtep], sa_vtep_if, log):
                self.errored('Exception occurred while configuring port security', goto=['common_cleanup'])

        log.info("Waiting {}secs for interface to come up".format(config_time))
        time.sleep(config_time)

    @aetest.test
    def learn_mac_and_verify_peer_vtep(self, testscript, testbed, steps):
        sa_vtep         = testscript.parameters['LEAF-3']
        prim_vtep       = testscript.parameters['LEAF-1']
        sec_vtep        = testscript.parameters['LEAF-2']
        prim_vtep_if    = str(testscript.parameters['intf_LEAF_1_1_to_IXIA'])
        prim_vtep_if1   = str(testscript.parameters['intf_LEAF_1_2_to_IXIA'])
        sa_vtep_if      = str(testscript.parameters['intf_LEAF_3_to_IXIA'])
        prim_mac        = str(testscript.parameters['PORTSEC_Dict']['prim_orphan_mac'])
        sa_mac          = str(testscript.parameters['PORTSEC_Dict']['sa_mac'])
        p1_handle       = testscript.parameters['orphan1_handle']
        p3_handle       = testscript.parameters['orphan2_handle']
        p2_handle       = testscript.parameters['sa_handle']

        ixNetwork   = testscript.parameters['ixNetwork']

        with steps.start("Starting hosts..."):
            p1_handle.Start()
            p2_handle.Start()
        
        log.info('Waiting {}secs to start 1025 hosts'.format(host_start_time))
        time.sleep(host_start_time)

        stream1 = ixNetwork.Traffic.TrafficItem.find(Name='Access Orphan To Standalone')
        stream1.StartStatelessTraffic()
        log.info('Waiting {}secs to start the traffic'.format(traffic_start_time))
        time.sleep(traffic_start_time)
        
        stream1.StopStatelessTraffic()
        log.info('Waiting {}secs to stop the traffic'.format(traffic_stop_time))
        time.sleep(traffic_stop_time)

        with steps.start("checking mac learning on orphan and remote"):
            if not verify_port_sec_addr_count(prim_vtep, prim_vtep_if, 1025, 'DYNAMIC'):
                log.error("DYNAMIC Mac learning failed")
                self.failed("DYNAMIC Mac learning failed")

            if not verify_secure_mac_on_vteps(prim_vtep, '1001', 1025, prim_mac, 'secure'):
                log.error("Mac learning failed on primary")
                self.failed("Mac learning failed on primary")

            if not verify_secure_mac_on_vteps(sec_vtep, '1001', 1025, prim_mac, 'secure'):
                log.error("Mac learning failed on primary")
                self.failed("Mac learning failed on primary")
                
            if not verify_secure_mac_on_vteps(sa_vtep, '1001', 1025, prim_mac):
                log.error("Mac learning failed on standalone")
                self.failed("Mac learning failed on standalone")

        with steps.start("Checking mac learning on standalone and orphan"):
            if not verify_port_sec_addr_count(sa_vtep, sa_vtep_if, 1025, 'DYNAMIC'):
                log.error("DYNAMIC Mac learning failed")
                self.failed("DYNAMIC Mac learning failed")

            if not verify_secure_mac_on_vteps(sa_vtep, '1002', 1025, sa_mac, 'secure'):
                log.error("Mac learning failed on Standalone")
                self.failed("Mac learning failed on Standalone")

            if not verify_secure_mac_on_vteps(prim_vtep, '1002', 1025, sa_mac):
                log.error("DYNAMIC Mac learning failed on remote vtep(leaf1)")
                self.failed("DYNAMIC Mac learning failed on remote vtep(leaf1)")

            if not verify_secure_mac_on_vteps(sec_vtep, '1002', 1025, sa_mac):
                log.error("DYNAMIC Mac learning failed on remote vtep(leaf2)")
                self.failed("DYNAMIC Mac learning failed on remote vtep(leaf2)")

        with steps.start("Stopping all hosts..."):
            ixNetwork.StopAllProtocols()
        
        with steps.start("Starting hosts..."):
            p3_handle.Start()
            p2_handle.Start()
        
        log.info('Waiting {}secs to start 1025 hosts'.format(host_start_time))
        time.sleep(host_start_time)

        stream1 = ixNetwork.Traffic.TrafficItem.find(Name='Access Orphan2 To Standalone')
        stream1.StartStatelessTraffic()
        log.info('Waiting {}secs to start the traffic'.format(traffic_start_time))
        time.sleep(traffic_start_time)
        
        stream1.StopStatelessTraffic()
        log.info('Waiting {}secs to stop the traffic'.format(traffic_stop_time))
        time.sleep(traffic_stop_time)

        with steps.start("Stopping all hosts..."):
            ixNetwork.StopAllProtocols()

        if not verifyerrorDisable(prim_vtep, prim_vtep_if1, log):
            log.error("Mac move violation - validation failed")
            self.failed("Mac move violation - validation failed")
            
        with steps.start('Verify Learned mac address consistency between hardware and software'):
            if verify_mac_cc_between_hardware_software([prim_vtep, sec_vtep, sa_vtep]):
                self.passed('MAC CC success')
            else:
                self.failed('MAC CC failed')

    @aetest.test
    def remove_portsecurity_check_macs(self, testscript, testbed, steps):
        sa_vtep         = testscript.parameters['LEAF-3']
        prim_vtep       = testscript.parameters['LEAF-1']
        sec_vtep        = testscript.parameters['LEAF-2']
        prim_vtep_if    = str(testscript.parameters['intf_LEAF_1_1_to_IXIA'])
        prim_vtep_if1   = str(testscript.parameters['intf_LEAF_1_2_to_IXIA'])
        sa_vtep_if      = str(testscript.parameters['intf_LEAF_3_to_IXIA'])
        ixNetwork       = testscript.parameters['ixNetwork']

        with steps.start("UnConfigure Port-Security on Standalone VTEP"):
            if not unconfig_interface_ps([sa_vtep], sa_vtep_if, log):
                self.errored('Exception occurred while configuring port security', goto=['common_cleanup'])
        with steps.start("UnConfigure Port-Security on Primary VTEP Orphan1"):
            if not unconfig_interface_ps([prim_vtep], prim_vtep_if, log):
                self.errored('Exception occurred while configuring port security', goto=['common_cleanup'])
        with steps.start("UnConfigure Port-Security on Primary VTEP Orphan2"):
            if not unconfig_interface_ps([prim_vtep], prim_vtep_if1, log):
                self.errored('Exception occurred while configuring port security', goto=['common_cleanup'])

        log.info("Waiting {}secs for interface to come up".format(config_time))
        time.sleep(config_time)
        
        with steps.start("Stopping all hosts..."):
            ixNetwork.StopAllProtocols()

        log.info('Waiting {}secs to stop the hosts'.format(traffic_stop_time))
        time.sleep(traffic_stop_time)

        with steps.start('Verify Learned mac address consistency between hardware and software'):
            if verify_mac_cc_between_hardware_software([prim_vtep, sec_vtep, sa_vtep]):
                log.info('MAC CC success')
            else:
                self.failed('MAC CC failed')
        
        with steps.start("Verifying MTS leak.."):
            if verify_mts_leak([prim_vtep, sec_vtep, sa_vtep], log):
                log.info('MTS Leak verification success')
            else:
                self.failed('MTS Leak verification failed')

        with steps.start("Verifying Cores and Log Errors"):
            exclude_bkp = post_test_process_dict['exclude_log_check_pattern']
            post_test_process_dict['exclude_log_check_pattern'] = str(exclude_bkp) + '|Security violation)'
            status = infraVerify.postTestVerification(post_test_process_dict)
            if status['status'] == 0:
                self.failed(reason=status['logs'])
            else:
                self.passed(reason=status['logs'])
            
            post_test_process_dict['exclude_log_check_pattern'] = exclude_bkp


# =============================================================================================================================#
# TC-ID: TC029 - Orphan to Member move - same vtep
# Testcase:
# Mac move should work and traffic should be fine after move
# =============================================================================================================================#
class TC_VXLAN_PS_026_Access(aetest.Testcase):
    @aetest.test
    def test_setup(self, testscript, testbed, steps):
        sa_vtep         = testscript.parameters['LEAF-3']
        prim_vtep       = testscript.parameters['LEAF-1']
        prim_vtep_if    = str(testscript.parameters['intf_LEAF_1_1_to_IXIA'])
        prim_vtep_if1   = str(testscript.parameters['intf_LEAF_1_2_to_IXIA'])
        sa_vtep_if      = str(testscript.parameters['intf_LEAF_3_to_IXIA'])
        
        with steps.start("Configure Port-Security on Primary VTEP Orphan"):
            if not config_interface_ps([prim_vtep], prim_vtep_if, log):
                self.errored('Exception occurred while configuring port security', goto=['common_cleanup'])
         
        with steps.start("Configure Port-Security on Primary VTEP Orphan1"):
            if not config_interface_ps([prim_vtep], prim_vtep_if1, log):
                self.errored('Exception occurred while configuring port security', goto=['common_cleanup'])
                
        with steps.start("Configure Port-Security on Standalone VTEP"):
            if not config_interface_ps([sa_vtep], sa_vtep_if, log):
                self.errored('Exception occurred while configuring port security', goto=['common_cleanup'])

        log.info("Waiting {}secs for interface to come up".format(config_time))
        time.sleep(config_time)

    @aetest.test
    def change_vpc_mac_on_ixia(self, testscript, testbed, steps):
        p3_handle       = testscript.parameters['vpc_handle']
        tgen_dict = testscript.parameters['LEAF_1_Orphan1_TGEN_dict']
        
        eth = p3_handle.DeviceGroup.find()[0].Ethernet.find()[0].update()
        eth.Mac.Increment(start_value=tgen_dict['mac'], step_value=tgen_dict['mac_step'])
        eth.EnableVlans.Single(True)
        eth.Vlan.find()[0].VlanId.Increment(
            start_value=tgen_dict['vlan_id'], step_value=tgen_dict['vlan_id_step']
        )
        
    @aetest.test
    def verify_secure_secure_move_orphantomember(self, testscript, testbed, steps):
        sa_vtep         = testscript.parameters['LEAF-3']
        prim_vtep       = testscript.parameters['LEAF-1']
        sec_vtep        = testscript.parameters['LEAF-2']
        prim_vtep_if    = str(testscript.parameters['intf_LEAF_1_1_to_IXIA'])
        prim_vpc_if     = str(testscript.parameters['intf_LEAF_1_to_FAN3172'])
        sec_vpc_if      = str(testscript.parameters['intf_LEAF_2_to_FAN3172'])
        tgen_dict       = testscript.parameters['LEAF_1_Orphan1_TGEN_dict']
        tgen_dict1      = testscript.parameters['FANOUT_TGEN_dict']
        prim_mac        = str(testscript.parameters['PORTSEC_Dict']['prim_orphan_mac'])
        p1_handle       = testscript.parameters['orphan1_handle']
        p3_handle       = testscript.parameters['vpc_handle']
        p2_handle       = testscript.parameters['sa_handle']

        ixNetwork   = testscript.parameters['ixNetwork']

        with steps.start("Starting hosts..."):
            p1_handle.Start()
            p2_handle.Start()
        
        log.info('Waiting {}secs to start 1025 hosts'.format(host_start_time))
        time.sleep(host_start_time)

        stream1 = ixNetwork.Traffic.TrafficItem.find(Name='Access Orphan To Standalone')
        stream1.StartStatelessTraffic()
        log.info('Waiting {}secs to start the traffic'.format(traffic_start_time))
        time.sleep(traffic_start_time)
        
        stream1.StopStatelessTraffic()
        log.info('Waiting {}secs to stop the traffic'.format(traffic_stop_time))
        time.sleep(traffic_stop_time)

        with steps.start("checking mac learning on orphan and remote"):
            if not verify_port_sec_addr_count(prim_vtep, prim_vtep_if, 1025, 'DYNAMIC'):
                log.error("DYNAMIC Mac learning failed")
                self.failed("DYNAMIC Mac learning failed")

            if not verify_secure_mac_on_vteps(prim_vtep, '1001', 1025, prim_mac, 'secure'):
                log.error("Mac learning failed on primary")
                self.failed("Mac learning failed on primary")

            if not verify_secure_mac_on_vteps(sec_vtep, '1001', 1025, prim_mac, 'secure'):
                log.error("Mac learning failed on primary")
                self.failed("Mac learning failed on primary")
                
            if not verify_secure_mac_on_vteps(sa_vtep, '1001', 1025, prim_mac):
                log.error("Mac learning failed on standalone")
                self.failed("Mac learning failed on standalone")
        
        with steps.start('Change vpc mac to orphan mac'):
            eth = p3_handle.DeviceGroup.find()[0].Ethernet.find()[0].update()
            eth.Mac.Increment(start_value=tgen_dict['mac'], step_value=tgen_dict['mac_step'])
            eth.EnableVlans.Single(True)
            eth.Vlan.find()[0].VlanId.Increment(
                start_value=tgen_dict['vlan_id'], step_value=tgen_dict['vlan_id_step']
            )
        
        with steps.start("Starting hosts..."):
            p3_handle.Start()
            p2_handle.Start()
        
        log.info('Waiting {}secs to start 1025 hosts'.format(host_start_time))
        time.sleep(host_start_time)

        stream1 = ixNetwork.Traffic.TrafficItem.find(Name='Access VPC To Standalone')
        stream1.StartStatelessTraffic()
        log.info('Waiting {}secs to start the traffic'.format(traffic_start_time))
        time.sleep(traffic_start_time)
        
        stream1.StopStatelessTraffic()
        log.info('Waiting {}secs to stop the traffic'.format(traffic_stop_time))
        time.sleep(traffic_stop_time)

        with steps.start("Stopping all hosts..."):
            ixNetwork.StopAllProtocols()

        if not verifyerrorDisable(prim_vtep, prim_vpc_if, log, True):
            log.error("Mac move violation - validation failed on Primary VPC")
            self.failed("Mac move violation - validation failed on Primary VPC")
        
        if not verifyerrorDisable(sec_vtep, sec_vpc_if, log, True):
            log.error("Mac move violation - validation failed on Secondary VPC")
            self.failed("Mac move violation - validation failed on Secondary VPC")

        with steps.start('Change mac back to vpc mac for VPC'):
            eth = p3_handle.DeviceGroup.find()[0].Ethernet.find()[0].update()
            eth.Mac.Increment(start_value=tgen_dict1['mac'], step_value=tgen_dict1['mac_step'])
            eth.EnableVlans.Single(True)
            eth.Vlan.find()[0].VlanId.Increment(
                start_value=tgen_dict1['vlan_id'], step_value=tgen_dict1['vlan_id_step']
            )

        with steps.start('Verify Learned mac address consistency between hardware and software'):
            if verify_mac_cc_between_hardware_software([prim_vtep, sec_vtep, sa_vtep]):
                self.passed('MAC CC success')
            else:
                self.failed('MAC CC failed')

        
    @aetest.test
    def remove_portsecurity_check_macs(self, testscript, testbed, steps):
        sa_vtep         = testscript.parameters['LEAF-3']
        prim_vtep       = testscript.parameters['LEAF-1']
        sec_vtep        = testscript.parameters['LEAF-2']
        prim_vtep_if    = str(testscript.parameters['intf_LEAF_1_1_to_IXIA'])
        prim_vtep_if1   = str(testscript.parameters['intf_LEAF_1_2_to_IXIA'])
        prim_vpc_if     = str(testscript.parameters['intf_LEAF_1_to_FAN3172'])
        sec_vpc_if      = str(testscript.parameters['intf_LEAF_2_to_FAN3172'])
        sa_vtep_if      = str(testscript.parameters['intf_LEAF_3_to_IXIA'])
        ixNetwork       = testscript.parameters['ixNetwork']

        with steps.start("UnConfigure Port-Security on Standalone Orphan1, Orphan2"):
            if not unconfig_interface_ps([sa_vtep], sa_vtep_if, log):
                self.errored('Exception occurred while configuring port security', goto=['common_cleanup'])
            if not unconfig_interface_ps([prim_vtep], prim_vtep_if, log):
                self.errored('Exception occurred while configuring port security', goto=['common_cleanup'])
            if not unconfig_interface_ps([prim_vtep], prim_vtep_if1, log):
                self.errored('Exception occurred while configuring port security', goto=['common_cleanup'])

            cmd = '''interface {0}
                     shutdown ; sleep 10 ; no shutdown ; exit
                  '''.format(prim_vpc_if, timeout=60)
            prim_vtep.configure(cmd)
            cmd = '''interface {0}
                     shutdown ; sleep 10 ; no shutdown ; exit
                  '''.format(sec_vpc_if)
            sec_vtep.configure(cmd, timeout=60)

        log.info("Waiting {}secs for interface to come up".format(config_time))
        time.sleep(config_time)
        
        with steps.start("Stopping all hosts..."):
            ixNetwork.StopAllProtocols()

        log.info('Waiting {}secs to stop the hosts'.format(traffic_stop_time))
        time.sleep(traffic_stop_time)

        with steps.start('Verify Learned mac address consistency between hardware and software'):
            if verify_mac_cc_between_hardware_software([prim_vtep, sec_vtep, sa_vtep]):
                log.info('MAC CC success')
            else:
                self.failed('MAC CC failed')
        
        with steps.start("Verifying MTS leak.."):
            if verify_mts_leak([prim_vtep, sec_vtep, sa_vtep], log):
                log.info('MTS Leak verification success')
            else:
                self.failed('MTS Leak verification failed')

        with steps.start("Verifying Cores and Log Errors"):
            exclude_bkp = post_test_process_dict['exclude_log_check_pattern']
            post_test_process_dict['exclude_log_check_pattern'] = str(exclude_bkp) + '|Channel error disabled'
            status = infraVerify.postTestVerification(post_test_process_dict)
            if status['status'] == 0:
                self.failed(reason=status['logs'])
            else:
                self.passed(reason=status['logs'])
            
            post_test_process_dict['exclude_log_check_pattern'] = exclude_bkp

# =================================================================================================#
# TC-ID: TC051 - Port Security configuration with Member Port 
#        Configuration should not be allowed
# =================================================================================================#
class TC_VXLAN_PS_027_Access(aetest.Testcase):
    @aetest.test
    def verify_port_security_with_member_port(self, testscript, testbed, steps):
        prim_vtep = testscript.parameters['LEAF-1']
        leaf1_to_fan_if = str(testscript.parameters['intf_LEAF_1_to_FAN3172'])
        
        output = prim_vtep.configure('''interface {eth_if}
                                switchport port-security
                            '''.format(eth_if=leaf1_to_fan_if))

        if re.search("% Invalid command at '^' marker.", output):
            log.info("Port Security configuration not allowed on member port")
            self.passed("Port Security configuration not allowed on member port")
        else:
            log.error("Port Security configuration allowed on member port")
            self.failed("Port Security configuration allowed on member port")

    @aetest.test
    def verify_errors_cores(self, testscript, testbed, steps):
        with steps.start("Verifying Cores and Log Errors"):
            status = infraVerify.postTestVerification(post_test_process_dict)
            if status['status'] == 0:
                self.failed(reason=status['logs'])
            else:
                self.passed(reason=status['logs'])

# ================================================================================================#
# TC-ID: TC052 - Port Security configuration with VPC Peer link port-channel
#        Configuration should not be allowed
# ================================================================================================#
class TC_VXLAN_PS_028_Access(aetest.Testcase):
    @aetest.test
    def verify_port_security_with_peerlink_po(self, testscript, testbed, steps):
        prim_vtep = testscript.parameters['LEAF-1']
        vpc_peer_po = str(testscript.parameters['LEAF_1_dict']['VPC_data']['peer_link_po'])
        
        output = prim_vtep.configure('''interface port-channel {po}
                                switchport port-security
                            '''.format(po=vpc_peer_po))

        if re.search("ERROR:\s+port-security\s+cannot\s+be\s+configured\s+on\s+virtual\s+peerlink\s+port-channel", output):
            log.info("Port Security configuration not allowed on vpc peer-link po")
            self.passed("Port Security configuration not allowed on vpc peerlink po")
        else:
            log.error("Port Security configuration allowed on vpc peer-link po")
            self.failed("Port Security configuration allowed on vpc peer-link po")

    @aetest.test
    def verify_errors_cores(self, testscript, testbed, steps):
        with steps.start("Verifying Cores and Log Errors"):
            status = infraVerify.postTestVerification(post_test_process_dict)
            if status['status'] == 0:
                self.failed(reason=status['logs'])
            else:
                self.passed(reason=status['logs'])

# =============================================================================================================================#
# TC-ID: TC054 - Port Security configuration with SPAN Destination 
#        Configuration should not be allowed
# =============================================================================================================================#
class TC_VXLAN_PS_029_Access(aetest.Testcase):
    @aetest.test
    def verify_orphan_port_security_with_span_dest(self, testscript, testbed, steps):
        prim_vtep = testscript.parameters['LEAF-1']
        prim_vtep_if = str(testscript.parameters['intf_LEAF_1_1_to_IXIA'])
        
        with steps.start("Making Leaf1 - Orphan1, VTEP-IXIA interface default"):
            try:
                prim_vtep.configure('default interface {prim_vtep_if}'.format(prim_vtep_if=prim_vtep_if))
            except Exception as error:
                log.debug("Unable to configure - Encountered Exception " + str(error))
                self.errored('Exception occured during default interface configuration', goto=['common_cleanup'])

        prim_vtep.configure('''monitor session 1
                               destination interface {eth_if} tx
                               no shut
                            '''.format(eth_if=prim_vtep_if))
        output = prim_vtep.configure('''interface {eth_if}
                                switchport
                                no shutdown
                                switchport monitor
                                switchport port-security
                            '''.format(eth_if=prim_vtep_if))
        
        prim_vtep.configure('''no monitor session 1
                               interface {eth_if}
                               no switchport monitor
                            '''.format(eth_if=prim_vtep_if))

        if re.search('ERROR:\s+Port Security is not supported on SPAN Destination', output):
            log.info("Orphan: Port-security configuration passed with span destination")
            self.passed("Orphan: Port-security configuration passed with span destination")
        else:
            log.error("Orphan: Port-security configuration failed with span destination")
            self.failed("Orphan: Port-security configuration failed with span destination")
    
    @aetest.test
    def verify_vpc_port_security_with_span_dest(self, testscript, testbed, steps):
        prim_vtep = testscript.parameters['LEAF-1']
        output = ''
        
        with steps.start("Default inter port-channel 11"):
            try:
                prim_vtep.configure('default interface port-channel 11')
            except Exception as error:
                log.debug("Unable to configure - Encountered Exception " + str(error))
                self.errored('Exception occured during default interface configuration', goto=['common_cleanup'])

        prim_vtep.configure('''monitor session 1
                               destination interface port-channel 11 tx
                               no shut
                            ''')
        output = prim_vtep.configure('''interface port-channel 11
                                switchport
                                no shutdown
                                switchport monitor
                                switchport port-security
                            ''')
        
        prim_vtep.configure('''no monitor session 1
                               interface port-channel 11
                               no switchport monitor
                            ''')

        if re.search('ERROR:\s+Port Security is not supported on SPAN Destination', output):
            log.info("VPC: Port-security configuration passed with span destination")
            self.passed("VPC: Port-security configuration passed with span destination")
        else:
            log.error("VPC: Port-security configuration failed with span destination")
            self.failed("VPC: Port-security configuration failed with span destination")
    
    @aetest.test
    def verify_fex_port_security_with_span_dest(self, testscript, testbed, steps):
        prim_vtep = testscript.parameters['LEAF-1']
        fex_vtep_if = str(testscript.parameters['intf_LEAF_1_FEX_to_IXIA'])
        
        with steps.start("Default Fex interface"):
            try:
                prim_vtep.configure('default interface {prim_vtep_if}'.format(prim_vtep_if=fex_vtep_if))
            except Exception as error:
                log.debug("Unable to configure - Encountered Exception " + str(error))
                self.errored('Exception occured during default interface configuration', goto=['common_cleanup'])

        prim_vtep.configure('''monitor session 1
                               destination interface {eth_if} tx
                               no shut
                            '''.format(eth_if=fex_vtep_if))
        output = prim_vtep.configure('''interface {eth_if}
                                switchport
                                no shutdown
                                switchport monitor
                                switchport port-security
                            '''.format(eth_if=fex_vtep_if))
        
        prim_vtep.configure('''no monitor session 1
                               interface {eth_if}
                               no switchport monitor
                            '''.format(eth_if=fex_vtep_if))

        if re.search('ERROR:\s+Port Security is not supported on SPAN Destination', output):
            log.info("Fex: Port-security configuration passed with span destination")
            self.passed("Fex: Port-security configuration passed with span destination")
        else:
            log.error("Fex: Port-security configuration failed with span destination")
            self.failed("Fex: Port-security configuration failed with span destination")
    
    @aetest.test
    def reconfigure_interfaces(self, testscript, testbed, steps):
        prim_vtep = testscript.parameters['LEAF-1']
        prim_vtep_if = str(testscript.parameters['intf_LEAF_1_1_to_IXIA'])
        fex_vtep_if = str(testscript.parameters['intf_LEAF_1_FEX_to_IXIA'])
        vlan = int(testscript.parameters['LEAF_3_TGEN_dict']['vlan_id'])
        
        with steps.start("Configure Port-Security - Dynamic on Leaf-1 - Primary VTEP Orphan"):
            try:
                prim_vtep.configure('''interface {prim_vtep_if}
                                switchport
                                switchport mode access
                                switchport access vlan {vlan}
                                spanning-tree port type edge
                                switchport port-security maximum 1025
                                switchport port-security
                                no shutdown
                            '''.format(prim_vtep_if=prim_vtep_if, vlan=vlan))
            except Exception as error:
                log.debug("Unable to configure - Encountered Exception " + str(error))
                self.errored('Exception occurred while configuring port security', goto=['common_cleanup'])
        
            with steps.start("Configure Port-Security on Primary VTEP - port-channel 11"):
                try:
                    prim_vtep.configure('''interface port-channel 11
                                    switchport
                                    switchport mode access
                                    switchport access vlan {vlan}
                                    spanning-tree port type edge
                                    switchport port-security maximum 1025
                                    switchport port-security
                                    vpc 11
                                    no shutdown
                                '''.format(vlan=vlan))
                except Exception as error:
                    log.debug("Unable to configure - Encountered Exception " + str(error))
                    self.errored('Exception occurred while configuring port security', goto=['common_cleanup'])
            
            with steps.start("Configure Leaf1 FEX interface"):
                try:
                    prim_vtep.configure('''interface {intf}
                                switchport
                                switchport mode access
                                switchport access vlan {vlan}
                                spanning-tree port type edge
                                switchport port-security maximum 1025
                                switchport port-security
                                no shut
                            '''.format(vlan=vlan, intf=fex_vtep_if))
                except Exception as error:
                    log.debug("Unable to configure - Encountered Exception " + str(error))
                    self.errored('Exception occurred while configuring port security', goto=['common_cleanup'])
        
        log.info("Waiting for interface to come up")
        time.sleep(30)
    
    @aetest.test
    def verify_errors_cores(self, testscript, testbed, steps):
        with steps.start("Verifying Cores and Log Errors"):
            status = infraVerify.postTestVerification(post_test_process_dict)
            if status['status'] == 0:
                self.failed(reason=status['logs'])
            else:
                self.passed(reason=status['logs'])

# =============================================================================================================================#
# TC-ID: TC059 - Static mac and port security
# Static mac configuration with same vlan + interface with port-security not allowed
# =============================================================================================================================#
class TC_VXLAN_PS_030_Access(aetest.Testcase):
    @aetest.test
    def verify_orphan_port_security_with_static_mac(self, testscript, testbed, steps):
        prim_vtep = testscript.parameters['LEAF-1']
        prim_vtep_if = str(testscript.parameters['intf_LEAF_1_1_to_IXIA'])
        vlan = int(testscript.parameters['LEAF_1_Orphan1_TGEN_dict']['vlan_id'])
        prim_vtep.configure('''interface {intf}
                                no switchport port-security
                            '''.format(intf=prim_vtep_if))
        
        prim_vtep.configure('''mac address-table static 0000.0011.0000 vlan {vlan} interface {intf}'''.format(intf=prim_vtep_if, vlan=vlan))

        output = prim_vtep.configure('''interface {intf}
                                switchport port-security
                            '''.format(intf=prim_vtep_if))
        prim_vtep.configure('''no mac address-table static 0000.0011.0000 vlan {vlan} interface {intf}'''.format(intf=prim_vtep_if, vlan=vlan))
        
        if re.search("ERROR:\s+Cannot enable port-security when static-mac is configured on the interface", output):
            log.info("Orphan: Port Security configuration not allowed with static mac")
            self.passed("Orphan: Port Security configuration not allowed with static mac")
        else:
            log.error("Orphan: Port Security configuration allowed with static mac")
            self.failed("Orphan: Port Security configuration allowed with static mac")

        prim_vtep.configure('''interface {intf}
                               switchport port-security'''.format(intf=prim_vtep_if))
        
        output = prim_vtep.configure('''mac address-table static 0000.0011.0000 vlan {vlan} interface {intf}'''.format(intf=prim_vtep_if, vlan=vlan))
        
        if re.search("Static MAC operation not allowed, security protocol enabled", output):
            log.info("Orphan: Port Security configuration not allowed with static mac")
            self.passed("Orphan: Port Security configuration not allowed with static mac")
        else:
            log.error("Orphan: Port Security configuration allowed with static mac")
            self.failed("Orphan: Port Security configuration allowed with static mac")

    @aetest.test
    def verify_portchannel_port_security_with_static_mac(self, testscript, testbed, steps):
        prim_vtep = testscript.parameters['LEAF-1']
        vlan = int(testscript.parameters['LEAF_1_Orphan1_TGEN_dict']['vlan_id'])
        prim_vtep.configure('''interface port-channel 11
                                no switchport port-security''')
        
        prim_vtep.configure('''mac address-table static 0000.0011.0000 vlan {vlan} interface port-channel 11'''.format(vlan=vlan))

        output = prim_vtep.configure('''interface port-channel 11
                                switchport port-security''')

        prim_vtep.configure('''no mac address-table static 0000.0011.0000 vlan {vlan} interface port-channel 11'''.format(vlan=vlan))
        
        if re.search("ERROR:\s+Cannot enable port-security when static-mac is configured on the interface", output):
            log.info("PortChannel: Port Security configuration not allowed with static mac")
            self.passed("PortChannel: Port Security configuration not allowed with static mac")
        else:
            log.error("PortChannel: Port Security configuration allowed with static mac")
            self.failed("PortChannel: Port Security configuration allowed with static mac")

        prim_vtep.configure('''interface port-channel 11
                               switchport port-security''')
        
        output = prim_vtep.configure('''mac address-table static 0000.0011.0000 vlan {vlan} interface port-channel 11'''.format(vlan=vlan))
        
        if re.search("Static MAC operation not allowed, security protocol enabled", output):
            log.info("PortChannel: Port Security configuration not allowed with static mac")
            self.passed("PortChannel: Port Security configuration not allowed with static mac")
        else:
            log.error("PortChannel: Port Security configuration allowed with static mac")
            self.failed("PortChannel: Port Security configuration allowed with static mac")
    
    @aetest.test
    def verify_fex_port_security_with_static_mac(self, testscript, testbed, steps):
        prim_vtep = testscript.parameters['LEAF-1']
        fex_vtep_if = str(testscript.parameters['intf_LEAF_1_FEX_to_IXIA'])
        vlan = int(testscript.parameters['LEAF_1_Orphan1_TGEN_dict']['vlan_id'])
        prim_vtep.configure('''interface {intf}
                                no switchport port-security
                            '''.format(intf=fex_vtep_if))
        
        prim_vtep.configure('''mac address-table static 0000.0011.0000 vlan {vlan} interface {intf}'''.format(intf=fex_vtep_if, vlan=vlan))

        output = prim_vtep.configure('''interface {intf}
                                switchport port-security
                            '''.format(intf=fex_vtep_if))
        prim_vtep.configure('''no mac address-table static 0000.0011.0000 vlan {vlan} interface {intf}'''.format(intf=fex_vtep_if, vlan=vlan))
        
        if re.search("ERROR:\s+Cannot enable port-security when static-mac is configured on the interface", output):
            log.info("FEX: Port Security configuration not allowed with static mac")
            self.passed("FEX: Port Security configuration not allowed with static mac")
        else:
            log.error("FEX: Port Security configuration allowed with static mac")
            self.failed("FEX: Port Security configuration allowed with static mac")

        prim_vtep.configure('''interface {intf}
                               switchport port-security'''.format(intf=fex_vtep_if))
        
        output = prim_vtep.configure('''mac address-table static 0000.0011.0000 vlan {vlan} interface {intf}'''.format(intf=fex_vtep_if, vlan=vlan))
        
        if re.search("Static MAC operation not allowed, security protocol enabled", output):
            log.info("FEX: Port Security configuration not allowed with static mac")
            self.passed("FEX: Port Security configuration not allowed with static mac")
        else:
            log.error("FEX: Port Security configuration allowed with static mac")
            self.failed("FEX: Port Security configuration allowed with static mac")

    @aetest.test
    def verify_errors_cores(self, testscript, testbed, steps):
        with steps.start("Verifying Cores and Log Errors"):
            status = infraVerify.postTestVerification(post_test_process_dict)
            if status['status'] == 0:
                self.failed(reason=status['logs'])
            else:
                self.passed(reason=status['logs'])

# =============================================================================================================================#
# TC-ID: TC080 - Static mac and port security
# Static mac configuration with same vlan + interface with port-security not allowed
# =============================================================================================================================#
class TC_VXLAN_PS_031_Access(aetest.Testcase):
    @aetest.test
    def test_setup(self, testscript, testbed, steps):
        sa_vtep         = testscript.parameters['LEAF-3']
        prim_vtep       = testscript.parameters['LEAF-1']
        sec_vtep        = testscript.parameters['LEAF-2']
        prim_vtep_if    = str(testscript.parameters['intf_LEAF_1_1_to_IXIA'])
        sa_vtep_if      = str(testscript.parameters['intf_LEAF_3_to_IXIA'])
        fex_vtep_if     = str(testscript.parameters['intf_LEAF_1_FEX_to_IXIA'])
        
        with steps.start("Configure Port-Security on Primary VTEP Orphan"):
            new_config = '''switchport access vlan add 1002'''
            if not config_interface_ps([prim_vtep], prim_vtep_if, log, new_config):
                self.errored('Exception occurred while configuring port security', goto=['common_cleanup'])
        
        with steps.start("Configure Port-Security on Standalone VTEP"):
            new_config = '''switchport access vlan add 1002'''
            if not config_interface_ps([sa_vtep], sa_vtep_if, log, new_config):
                self.errored('Exception occurred while configuring port security', goto=['common_cleanup'])
        
        with steps.start("Configure Port-Security on VPC Primary/Secondary - Static"):
            new_config = '''switchport access vlan add 1002'''
            if not config_interface_ps([prim_vtep, sec_vtep], 'port-channel 11', log, new_config):
                self.errored('Exception occurred while configuring port security', goto=['common_cleanup'])
        
        with steps.start("Configure Port-Security on Leaf-1 FEX - FEX port of VTEP"):
            new_config = '''switchport access vlan add 1002'''
            if not config_interface_ps([prim_vtep], fex_vtep_if, log, new_config):
                self.errored('Exception occurred while configuring port security', goto=['common_cleanup'])

        log.info("Waiting {}secs for interface to come up".format(config_time))
        time.sleep(config_time)
        display_configs(testscript)

    @aetest.test
    def verify_orphan_port_security_with_remote_static(self, testscript, testbed, steps):
        prim_vtep       = testscript.parameters['LEAF-1']
        prim_vtep_if    = str(testscript.parameters['intf_LEAF_1_1_to_IXIA'])
        leaf3_mac       = str(testscript.parameters['PORTSEC_Dict']['sa_static_mac'])
        vlan            = int(testscript.parameters['LEAF_3_TGEN_dict']['vlan_id'])
        ixNetwork       = testscript.parameters['ixNetwork']
        p1_handle       = testscript.parameters['orphan1_handle']
        p2_handle       = testscript.parameters['sa_handle']
        
        with steps.start("Starting hosts..."):
            p1_handle.Start()
            p2_handle.Start()
        
        log.info('Waiting {}secs to start 1025 hosts'.format(host_start_time))
        time.sleep(host_start_time)
        
        stream1 = ixNetwork.Traffic.TrafficItem.find(Name='Access Orphan To Standalone')
        stream1.StartStatelessTraffic()
        log.info('Waiting {}secs to start the traffic'.format(traffic_start_time))
        time.sleep(traffic_start_time)
        log.info('Stopping traffic')
        stream1.StopStatelessTraffic()
        log.info('Waiting {}secs to stop the traffic'.format(traffic_stop_time))
        time.sleep(traffic_stop_time)

        cmd = 'mac address-table static {mac} vlan {vlan} interface {intf}'.format(mac=leaf3_mac, intf=prim_vtep_if, vlan=vlan)
        output = prim_vtep.configure(cmd)
        
        if re.search("Static MAC operation not allowed, security protocol enabled", output):
            log.info("Orphan: Port Security configuration not allowed with remote static mac")
            self.passed("Orphan: Port Security configuration not allowed with remote static mac")
        else:
            log.error("Orphan: Port Security configuration allowed with remote static mac")
            self.failed("Orphan: Port Security configuration allowed with remote static mac")

        cmd = 'switchport port-security mac {mac} vlan {vlan}'.format(mac=leaf3_mac, vlan=vlan)
        output = prim_vtep.configure('''interface {intf}
                               {cmd}'''.format(intf=prim_vtep_if, cmd=cmd))

        if re.search("ERROR:\s+Static MAC entry already exists", output):
            log.info("Orphan: Port Security configuration not allowed with remote static mac")
            self.passed("Orphan: Port Security configuration not allowed with remote static mac")
        else:
            log.error("Orphan: Port Security configuration allowed with remote static mac")
            self.failed("Orphan: Port Security configuration allowed with remote static mac")

        with steps.start("Verify Steady State"):
            if VerifyTrafficDrop("Test_033_Orphan", testscript, 
                                 traffic_item='Access Orphan To Standalone'):
                log.info('Verify traffic success')
            else:
                self.failed('Verify traffic failed')

    @aetest.test
    def verify_vpc_port_security_with_remote_static(self, testscript, testbed, steps):
        sa_vtep         = testscript.parameters['LEAF-3']
        prim_vtep       = testscript.parameters['LEAF-1']
        sec_vtep        = testscript.parameters['LEAF-2']
        prim_vtep_if    = str(testscript.parameters['intf_LEAF_1_1_to_IXIA'])
        vlan            = int(testscript.parameters['LEAF_3_TGEN_dict']['vlan_id'])
        leaf3_mac       = str(testscript.parameters['PORTSEC_Dict']['sa_static_mac'])
        ixNetwork       = testscript.parameters['ixNetwork']
        p1_handle       = testscript.parameters['vpc_handle']
        p2_handle       = testscript.parameters['sa_handle']
        
        with steps.start("Starting hosts..."):
            p1_handle.Start()
            p2_handle.Start()
        
        log.info('Waiting {}secs to start 1025 hosts'.format(host_start_time))
        time.sleep(host_start_time)
        
        stream1 = ixNetwork.Traffic.TrafficItem.find(Name='Access VPC To Standalone')
        stream1.StartStatelessTraffic()
        log.info('Waiting {}secs to start the traffic'.format(traffic_start_time))
        time.sleep(traffic_start_time)
        log.info('Stopping traffic')
        stream1.StopStatelessTraffic()
        log.info('Waiting {}secs to stop the traffic'.format(traffic_stop_time))
        time.sleep(traffic_stop_time)
        
        cmd = 'switchport port-security mac {mac} vlan {vlan}'.format(mac=leaf3_mac, vlan=vlan)
        output = prim_vtep.configure('''interface port-channel 11
                               {cmd}'''.format(cmd=cmd))

        if re.search("ERROR:\s+Static MAC entry already exists", output):
            log.info("Primary PO: Port Security configuration not allowed with remote static mac")
            self.passed("Primary PO: Port Security configuration not allowed with remote static mac")
        else:
            log.error("Primary PO: Port Security configuration allowed with remote static mac")
            self.failed("Primary PO: Port Security configuration allowed with remote static mac")
        
        cmd = 'switchport port-security mac {mac} vlan {vlan}'.format(mac=leaf3_mac, vlan=vlan)
        output = sec_vtep.configure('''interface port-channel 11
                               {cmd}'''.format(cmd=cmd))

        if re.search("ERROR:\s+Static MAC entry already exists", output):
            log.info("Secondary PO: Port Security configuration not allowed with remote static mac")
            self.passed("Secondary PO: Port Security configuration not allowed with remote static mac")
        else:
            log.error("Secondary PO: Port Security configuration allowed with remote static mac")
            self.failed("Secondary PO: Port Security configuration allowed with remote static mac")
    
        with steps.start("Verify Steady State"):
            if VerifyTrafficDrop("Test_033_VPC", testscript, 
                                 traffic_item='Access VPC To Standalone'):
                log.info('Verify traffic success')
            else:
                self.failed('Verify traffic failed')

    @aetest.test
    def verify_fex_port_security_with_remote_static(self, testscript, testbed, steps):
        prim_vtep       = testscript.parameters['LEAF-1']
        prim_vtep_if    = str(testscript.parameters['intf_LEAF_1_FEX_to_IXIA'])
        leaf3_mac       = str(testscript.parameters['PORTSEC_Dict']['sa_static_mac'])
        vlan            = int(testscript.parameters['LEAF_3_TGEN_dict']['vlan_id'])
        ixNetwork       = testscript.parameters['ixNetwork']
        p1_handle       = testscript.parameters['fex_handle']
        p2_handle       = testscript.parameters['sa_handle']
        
        with steps.start("Starting hosts..."):
            p1_handle.Start()
            p2_handle.Start()
        
        log.info('Waiting {}secs to start 1025 hosts'.format(host_start_time))
        time.sleep(host_start_time)
        
        stream1 = ixNetwork.Traffic.TrafficItem.find(Name='Access FEX To Standalone')
        stream1.StartStatelessTraffic()
        log.info('Waiting {}secs to start the traffic'.format(traffic_start_time))
        time.sleep(traffic_start_time)
        log.info('Stopping traffic')
        stream1.StopStatelessTraffic()
        log.info('Waiting {}secs to stop the traffic'.format(traffic_stop_time))
        time.sleep(traffic_stop_time)

        cmd = 'switchport port-security mac {mac} vlan {vlan}'.format(mac=leaf3_mac, vlan=vlan)
        output = prim_vtep.configure('''interface {intf}
                               {cmd}'''.format(intf=prim_vtep_if, cmd=cmd))

        if re.search("ERROR:\s+Static MAC entry already exists", output):
            log.info("FEX: Port Security configuration not allowed with remote static mac")
            self.passed("FEX: Port Security configuration not allowed with remote static mac")
        else:
            log.error("FEX: Port Security configuration allowed with remote static mac")
            self.failed("FEX: Port Security configuration allowed with remote static mac")

        with steps.start("Verify Steady State"):
            if VerifyTrafficDrop("Test_033_Fex", testscript, 
                                 traffic_item='Access FEX To Standalone'):
                log.info('Verify traffic success')
            else:
                self.failed('Verify traffic failed')

    @aetest.test
    def verify_errors_cores(self, testscript, testbed, steps):
        sa_vtep = testscript.parameters['LEAF-3']
        prim_vtep = testscript.parameters['LEAF-1']
        sec_vtep = testscript.parameters['LEAF-2']
        prim_vtep_if = str(testscript.parameters['intf_LEAF_1_1_to_IXIA'])
        sa_vtep_if = str(testscript.parameters['intf_LEAF_3_to_IXIA'])
        fex_vtep_if = str(testscript.parameters['intf_LEAF_1_FEX_to_IXIA'])
        vlan = int(testscript.parameters['LEAF_3_TGEN_dict']['vlan_id'])
        ixNetwork   = testscript.parameters['ixNetwork']
        
        with steps.start("Stopping all hosts..."):
            ixNetwork.StopAllProtocols()

        log.info('Waiting {}secs to stop the hosts'.format(traffic_stop_time))
        time.sleep(traffic_stop_time)

        with steps.start("UnConfigure Port-Security on Primary VTEP Orphan"):
            new_config = '''switchport access vlan remove 1002
                            switchport port-security maximum 1025'''
            if not unconfig_interface_ps([prim_vtep], prim_vtep_if, log, new_config):
                self.errored('Exception occurred while configuring port security', goto=['common_cleanup'])
        
        with steps.start("UnConfigure Port-Security on Standalone VTEP"):
            new_config = '''switchport port-security maximum 1025'''
            if not unconfig_interface_ps([sa_vtep], sa_vtep_if, log, new_config):
                self.errored('Exception occurred while configuring port security', goto=['common_cleanup'])
        
        with steps.start("UnConfigure Port-Security on VPC Primary/Secondary - Static"):
            new_config = '''switchport access vlan remove 1002
                            switchport port-security maximum 1025
                            '''
            if not unconfig_interface_ps([prim_vtep, sec_vtep], 'port-channel 11', log, new_config):
                self.errored('Exception occurred while configuring port security', goto=['common_cleanup'])
        
        with steps.start("UnConfigure Port-Security on Leaf-1 FEX - FEX port of VTEP"):
            new_config = '''switchport access vlan remove 1002
                            switchport port-security maximum 1025
                            '''
            if not unconfig_interface_ps([prim_vtep], fex_vtep_if, log, new_config):
                self.errored('Exception occurred while configuring port security', goto=['common_cleanup'])

        log.info("Waiting {}secs for interface to come up".format(config_time))
        time.sleep(config_time)

        with steps.start("Verifying Cores and Log Errors"):
            status = infraVerify.postTestVerification(post_test_process_dict)
            if status['status'] == 0:
                self.failed(reason=status['logs'])
            else:
                self.passed(reason=status['logs'])


########################################################################################################
# Triggers 
########################################################################################################
# TC: TC056 and TC079
# Verify removal of vlan from trunk port allowed list, will flushout the mac
# Use config-replace to replace the configuration after default interface
########################################################################################################
class TC_VXLAN_PS_032_Access(aetest.Testcase):
    @aetest.test
    def test_setup(self, testscript, testbed, steps):
        sa_vtep         = testscript.parameters['LEAF-3']
        prim_vtep       = testscript.parameters['LEAF-1']
        sec_vtep        = testscript.parameters['LEAF-2']
        prim_vtep_if    = str(testscript.parameters['intf_LEAF_1_1_to_IXIA'])
        sa_vtep_if      = str(testscript.parameters['intf_LEAF_3_to_IXIA'])
        fex_vtep_if     = str(testscript.parameters['intf_LEAF_1_FEX_to_IXIA'])
        
        with steps.start("Configure Port-Security on Primary VTEP Orphan"):
            if not config_interface_ps([prim_vtep], prim_vtep_if, log):
                self.errored('Exception occurred while configuring port security', goto=['common_cleanup'])
         
        with steps.start("Configure Port-Security on Standalone VTEP"):
            if not config_interface_ps([sa_vtep], sa_vtep_if, log):
                self.errored('Exception occurred while configuring port security', goto=['common_cleanup'])

        with steps.start("Configure Port-Security on VPC Primary/Secondary - Static"):
            if not config_interface_ps([prim_vtep, sec_vtep], 'port-channel 11', log):
                self.errored('Exception occurred while configuring port security', goto=['common_cleanup'])
        
        with steps.start("Configure Port-Security on Leaf-1 FEX - FEX port of VTEP"):
            if not config_interface_ps([prim_vtep], fex_vtep_if, log):
                self.errored('Exception occurred while configuring port security', goto=['common_cleanup'])
        
        log.info("Waiting {}secs for interface to come up".format(config_time))
        time.sleep(config_time)
        display_configs(testscript)

    # Flap port-security interface on VPC orphan and standalone
    @aetest.test
    def verify_orphan_remove_allowed_vlan(self, testscript, testbed, steps):
        sa_vtep         = testscript.parameters['LEAF-3']
        prim_vtep       = testscript.parameters['LEAF-1']
        sec_vtep        = testscript.parameters['LEAF-2']
        sa_vtep_if      = str(testscript.parameters['intf_LEAF_3_to_IXIA'])
        prim_vtep_if    = str(testscript.parameters['intf_LEAF_1_1_to_IXIA'])
        sa_mac          = str(testscript.parameters['PORTSEC_Dict']['sa_mac'])
        prim_mac        = str(testscript.parameters['PORTSEC_Dict']['prim_orphan_mac'])
        ixNetwork       = testscript.parameters['ixNetwork']
        p1_handle       = testscript.parameters['orphan1_handle']
        p2_handle       = testscript.parameters['sa_handle']
        vlan            = int(testscript.parameters['LEAF_1_Orphan1_TGEN_dict']['vlan_id'])
        vlan1           = int(testscript.parameters['LEAF_3_TGEN_dict']['vlan_id'])
        
        with steps.start("Starting hosts..."):
            p1_handle.Start()
            p2_handle.Start()
        
        log.info('Waiting {}secs to start 1025 hosts'.format(host_start_time))
        time.sleep(host_start_time)
        
        stream1 = ixNetwork.Traffic.TrafficItem.find(Name='Access Orphan To Standalone')
        stream1.StartStatelessTraffic()
        log.info('Waiting {}secs to start the traffic'.format(traffic_start_time))
        time.sleep(traffic_start_time)

        with steps.start('Do Config backup on VPC Primary and Standalone before default-interface'):
            prim_vtep.execute('delete bootflash:{cr_file} no-prompt'.format(cr_file=cr_file))
            sa_vtep.execute('delete bootflash:{cr_file} no-prompt'.format(cr_file=cr_file))
            prim_vtep.execute("copy running-config bootflash:{cr_file}".format(cr_file=cr_file))
            sa_vtep.execute("copy running-config bootflash:{cr_file}".format(cr_file=cr_file))
        
        with steps.start('Remove trunk allowed vlan on orphan port and standalone'):
            sa_vtep.configure('''interface {intf1}
                                 switchport access vlan remove {vlan}
                              '''.format(intf1=sa_vtep_if, vlan=vlan1))
            prim_vtep.configure('''interface {intf2}
                                   switchport access vlan remove {vlan}
                                '''.format(intf2=prim_vtep_if, vlan=vlan))
        
        log.info('Waiting 30secs mac flushout')
        time.sleep(30)

        with steps.start("Checking Mac flushout on standalone and remote vtep after trigger"):
            if not verify_port_sec_addr_count(sa_vtep, sa_vtep_if, 0, 'DYNAMIC'):
                log.error("DYNAMIC Mac learning failed")
                self.failed("DYNAMIC Mac learning failed")

            if not verify_secure_mac_on_vteps(sa_vtep, '1002', 0, sa_mac, 'secure'):
                log.error("DYNAMIC Mac learning failed on local vtep(leaf3)")
                self.failed("DYNAMIC Mac learning failed on local vtep (leaf3)")

            if not verify_secure_mac_on_vteps(prim_vtep, '1002', 0, sa_mac):
                log.error("DYNAMIC Mac learning failed on remote vtep(leaf1)")
                self.failed("DYNAMIC Mac learning failed on remote vtep(leaf1)")

            if not verify_secure_mac_on_vteps(sec_vtep, '1002', 0, sa_mac):
                log.error("DYNAMIC Mac learning failed on remote vtep(leaf2)")
                self.failed("DYNAMIC Mac learning failed on remote vtep(leaf2)")
        
        with steps.start("Checking Mac flushout on local and remote vtep after trigger"):
            if not verify_port_sec_addr_count(prim_vtep, prim_vtep_if, 0, 'DYNAMIC'):
                log.error("DYNAMIC Mac learning failed")
                self.failed("DYNAMIC Mac learning failed")

            if not verify_secure_mac_on_vteps(prim_vtep, '1001', 0, prim_mac, 'secure'):
                log.error("DYNAMIC Mac learning failed on primary")
                self.failed("DYNAMIC Mac learning failed on primary")

            if not verify_secure_mac_on_vteps(sec_vtep, '1001', 0, prim_mac, 'secure'):
                log.error("DYNAMIC Mac learning failed on remote vtep(leaf2)")
                self.failed("DYNAMIC Mac learning failed on remote vtep(leaf2)")

            if not verify_secure_mac_on_vteps(sa_vtep, '1001', 0, prim_mac):
                log.error("DYNAMIC Mac learning failed on standalone")
                self.failed("DYNAMIC Mac learning failed on standalone")

        with steps.start('Doing Config Replace to replace the configs on orphan and standalone'):
            if verify_config_replace([prim_vtep, sa_vtep], log):
                log.info('Config-Replace success')
            else:
                self.failed('Config-Replace failed')
       
        log.info('Waiting 30secs for mac relearning')
        time.sleep(30)
        
        with steps.start("Checking mac relearning on standalone and remote after trigger"):
            if not verify_port_sec_addr_count(sa_vtep, sa_vtep_if, 1025, 'DYNAMIC'):
                log.error("DYNAMIC Mac learning failed")
                self.failed("DYNAMIC Mac learning failed")

            if not verify_secure_mac_on_vteps(sa_vtep, '1002', 1025, sa_mac, 'secure'):
                log.error("DYNAMIC Mac learning failed on local vtep(leaf3)")
                self.failed("DYNAMIC Mac learning failed on local vtep (leaf3)")

            if not verify_secure_mac_on_vteps(prim_vtep, '1002', 1025, sa_mac):
                log.error("DYNAMIC Mac learning failed on remote vtep(leaf1)")
                self.failed("DYNAMIC Mac learning failed on remote vtep(leaf1)")

            if not verify_secure_mac_on_vteps(sec_vtep, '1002', 1025, sa_mac):
                log.error("DYNAMIC Mac learning failed on remote vtep(leaf2)")
                self.failed("DYNAMIC Mac learning failed on remote vtep(leaf2)")

        with steps.start("Checking Mac relearning on local and remote after trigger"):
            if not verify_port_sec_addr_count(prim_vtep, prim_vtep_if, 1025, 'DYNAMIC'):
                log.error("DYNAMIC Mac learning failed")
                self.failed("DYNAMIC Mac learning failed")

            if not verify_secure_mac_on_vteps(prim_vtep, '1001', 1025, prim_mac, 'secure'):
                log.error("DYNAMIC Mac learning failed on primary")
                self.failed("DYNAMIC Mac learning failed on primary")

            if not verify_secure_mac_on_vteps(sec_vtep, '1001', 1025, prim_mac, 'secure'):
                log.error("DYNAMIC Mac learning failed on remote vtep(leaf2)")
                self.failed("DYNAMIC Mac learning failed on remote vtep(leaf2)")

            if not verify_secure_mac_on_vteps(sa_vtep, '1001', 1025, prim_mac):
                log.error("DYNAMIC Mac learning failed on standalone")
                self.failed("DYNAMIC Mac learning failed on standalone")

        stream1.StopStatelessTraffic()
        log.info('Waiting {}secs to stop the traffic'.format(traffic_stop_time))
        time.sleep(traffic_stop_time)
        
        with steps.start("Verify Steady State after trigger"):
            if VerifyTraffic("Test_034_Access", testscript, traffic_item='Access Orphan To Standalone'):
                log.info('Verify traffic success after trigger')
            else:
                self.failed('Verify traffic failed after trigger')

        with steps.start('Verify Learned mac address consistency between hardware and software'):
            if verify_mac_cc_between_hardware_software([prim_vtep, sec_vtep, sa_vtep]):
                log.info('MAC CC success')
            else:
                self.failed('MAC CC failed')
    
    @aetest.test
    def verify_portchannel_remove_allowed_vlan(self, testscript, testbed, steps):
        sa_vtep         = testscript.parameters['LEAF-3']
        prim_vtep       = testscript.parameters['LEAF-1']
        sec_vtep        = testscript.parameters['LEAF-2']
        prim_vpc_mac    = str(testscript.parameters['PORTSEC_Dict']['prim_vpc_mac'])
        ixNetwork       = testscript.parameters['ixNetwork']
        p1_handle       = testscript.parameters['vpc_handle']
        p2_handle       = testscript.parameters['sa_handle']
        vlan            = int(testscript.parameters['LEAF_1_Orphan1_TGEN_dict']['vlan_id'])
        
        with steps.start("Starting hosts.."):
            p1_handle.Start()
            p2_handle.Start()
        
        log.info('Waiting {}secs to start 1025 hosts'.format(host_start_time))
        time.sleep(host_start_time)
    
        stream1 = ixNetwork.Traffic.TrafficItem.find(Name='Access VPC To Standalone')
        stream1.StartStatelessTraffic()
        log.info('Waiting {}secs to start the traffic'.format(traffic_start_time))
        time.sleep(traffic_start_time)

        with steps.start('Do Config backup on VPC Primary and Standalone before default-interface'):
            prim_vtep.execute('delete bootflash:{cr_file} no-prompt'.format(cr_file=cr_file))
            sec_vtep.execute('delete bootflash:{cr_file} no-prompt'.format(cr_file=cr_file))
            prim_vtep.execute("copy running-config bootflash:{cr_file}".format(cr_file=cr_file))
            sec_vtep.execute("copy running-config bootflash:{cr_file}".format(cr_file=cr_file))
                
        with steps.start('Remove allowed vlan from vpc port-channel on primary/secondary'):
            prim_vtep.configure('''interface port-channel 11
                                   switchport access vlan remove {vlan}
                              '''.format(vlan=vlan))
            sec_vtep.configure('''interface port-channel 11
                                   switchport access vlan remove {vlan}
                                '''.format(vlan=vlan))
        
        log.info('Waiting 30secs for mac flushout')    
        time.sleep(30)
        
        with steps.start("Checking mac learning on local and remote vtep after default interface"):
            if not verify_port_sec_addr_count(prim_vtep, 'port-channel 11', 0, 'DYNAMIC'):
                log.error("DYNAMIC Mac learning failed")
                self.failed("DYNAMIC Mac learning failed")
            
            if not verify_port_sec_addr_count(sec_vtep, 'port-channel 11', 0, 'DYNAMIC'):
                log.error("DYNAMIC Mac learning failed")
                self.failed("DYNAMIC Mac learning failed")
            
            if not verify_secure_mac_on_vteps(prim_vtep, '1001', 0, prim_vpc_mac, 'secure'):
                log.error("Mac learning failed on primary")
                self.failed("Mac learning failed on primary")

            if not verify_secure_mac_on_vteps(sec_vtep, '1001', 0, prim_vpc_mac, 'secure'):
                log.error("Mac learning failed on primary")
                self.failed("Mac learning failed on primary")
                
            if not verify_secure_mac_on_vteps(sa_vtep, '1001', 0, prim_vpc_mac):
                log.error("Mac learning failed on standalone")
                self.failed("Mac learning failed on standalone")
        
        with steps.start('Doing Config Replace to replace the configs'):
            if verify_config_replace([prim_vtep, sec_vtep], log):
                log.info('Config-Replace success')
            else:
                self.failed('Config-Replace failed')
       
        log.info('Waiting 30secs for mac relearning')
        time.sleep(30)
        
        with steps.start("Checking mac learning on local and remote vtep after trigger"):        
            if not verify_port_sec_addr_count(prim_vtep, 'port-channel 11', 1025, 'DYNAMIC'):
                log.error("DYNAMIC Mac learning failed")
                self.failed("DYNAMIC Mac learning failed")
            if not verify_port_sec_addr_count(sec_vtep, 'port-channel 11', 1025, 'DYNAMIC'):
                log.error("DYNAMIC Mac learning failed")
                self.failed("DYNAMIC Mac learning failed")
            
            if not verify_secure_mac_on_vteps(prim_vtep, '1001', 1025, prim_vpc_mac, 'secure'):
                log.error("Mac learning failed on primary")
                self.failed("Mac learning failed on primary")

            if not verify_secure_mac_on_vteps(sec_vtep, '1001', 1025, prim_vpc_mac, 'secure'):
                log.error("Mac learning failed on primary")
                self.failed("Mac learning failed on primary")
                
            if not verify_secure_mac_on_vteps(sa_vtep, '1001', 1025, prim_vpc_mac):
                log.error("Mac learning failed on standalone")
                self.failed("Mac learning failed on standalone")

        stream1.StopStatelessTraffic()
        log.info('Waiting {}secs to stop the traffic'.format(traffic_stop_time))
        time.sleep(traffic_stop_time)

        with steps.start("Verify Steady State after trigger"):
            if VerifyTraffic("Test_034_VPC", testscript, traffic_item='Access VPC To Standalone'):
                log.info('Verify Traffic Success after trigger')
            else:
                self.failed('Verify Traffic Failed after trigger')

        with steps.start('Verify Learned mac address consistency between hardware and software'):
            if verify_mac_cc_between_hardware_software([prim_vtep, sec_vtep, sa_vtep]):
                log.info('MAC CC success')
            else:
                self.failed('MAC CC failed')

    @aetest.test
    def verify_fex_remove_allowed_vlan(self, testscript, testbed, steps):
        sa_vtep         = testscript.parameters['LEAF-3']
        prim_vtep       = testscript.parameters['LEAF-1']
        sec_vtep        = testscript.parameters['LEAF-2']
        fex_vtep_if     = str(testscript.parameters['intf_LEAF_1_FEX_to_IXIA'])
        prim_fex_mac    = str(testscript.parameters['PORTSEC_Dict']['prim_fex_mac'])
        ixNetwork       = testscript.parameters['ixNetwork']
        p1_handle       = testscript.parameters['fex_handle']
        p2_handle       = testscript.parameters['sa_handle']
        vlan            = int(testscript.parameters['LEAF_1_Orphan1_TGEN_dict']['vlan_id'])
        
        with steps.start("Starting hosts..."):
            p1_handle.Start()
            p2_handle.Start()
        
        log.info('Waiting {}secs to start 1025 hosts'.format(host_start_time))
        time.sleep(host_start_time)
    
        stream1 = ixNetwork.Traffic.TrafficItem.find(Name='Access FEX To Standalone')
        stream1.StartStatelessTraffic()
        log.info('Waiting {}secs to start the traffic'.format(traffic_start_time))
        time.sleep(traffic_start_time)
        
        with steps.start('Doing Config backup on VPC Primary'):
            prim_vtep.execute('delete bootflash:{cr_file} no-prompt'.format(cr_file=cr_file))
            prim_vtep.execute("copy running-config bootflash:{cr_file}".format(cr_file=cr_file))
        
        with steps.start('Remove allowed vlan on fex interface'):
            prim_vtep.configure('''interface {intf2}
                                   switchport access vlan remove {vlan}
                                '''.format(intf2=fex_vtep_if, vlan=vlan))

        log.info('Waiting 30secs for Mac flushout')
        time.sleep(30)
        
        with steps.start("Checking mac flushout on local and remote after default fex interface"):
            if not verify_port_sec_addr_count(prim_vtep, fex_vtep_if, 0, 'DYNAMIC'):
                log.error("DYNAMIC Mac learning failed")
                self.failed("DYNAMIC Mac learning failed")

            if not verify_secure_mac_on_vteps(prim_vtep, '1001', 0, prim_fex_mac, 'secure'):
                log.error("DYNAMIC Mac learning failed on primary")
                self.failed("DYNAMIC Mac learning failed on primary")
            if not verify_secure_mac_on_vteps(sec_vtep, '1001', 0, prim_fex_mac, 'secure'):
                log.error("DYNAMIC Mac learning failed on primary")
                self.failed("DYNAMIC Mac learning failed on primary")
            if not verify_secure_mac_on_vteps(sa_vtep, '1001', 0, prim_fex_mac):
                log.error("DYNAMIC Mac learning failed on standalone")
                self.failed("DYNAMIC Mac learning failed on standalone")
		
        with steps.start('Doing Config Replace Fex VTEP - VPC primary'):
            if verify_config_replace([prim_vtep], log):
                log.info('Config-Replace success')
            else:
                self.failed('Config-Replace failed')
       
        log.info('Waiting 30secs for mac relearning')
        time.sleep(30)
        
        with steps.start("Checking mac learning after fex after trigger"):
            if not verify_port_sec_addr_count(prim_vtep, fex_vtep_if, 1025, 'DYNAMIC'):
                log.error("Mac learning failed")
                self.failed("Mac learning failed")

            if not verify_secure_mac_on_vteps(prim_vtep, '1001', 1025, prim_fex_mac, 'secure'):
                log.error("Mac learning failed on primary")
                self.failed("Mac learning failed on primary")
            if not verify_secure_mac_on_vteps(sec_vtep, '1001', 1025, prim_fex_mac, 'secure'):
                log.error("Mac learning failed on primary")
                self.failed("Mac learning failed on primary")
            if not verify_secure_mac_on_vteps(sa_vtep, '1001', 1025, prim_fex_mac):
                log.error("Mac learning failed on standalone")
                self.failed("Mac learning failed on standalone")
        
        stream1.StopStatelessTraffic()
        log.info('Waiting {}secs to stop the traffic'.format(traffic_stop_time))
        time.sleep(traffic_stop_time)
        
        with steps.start("Verify Steady State after trigger"):
            if VerifyTraffic("Test_034_FEX_Access", testscript, traffic_item='Access FEX To Standalone'):
                log.info('Verify Traffic success after trigger')
            else:
                self.failed('Verify Traffic failed after trigger')

        with steps.start('Verify Learned mac address consistency between hardware and software'):
            if verify_mac_cc_between_hardware_software([prim_vtep, sec_vtep, sa_vtep]):
                log.info('MAC CC success')
            else:
                self.failed('MAC CC failed')
    
    @aetest.test
    def test_cleanup(self, testscript, testbed, steps):
        sa_vtep         = testscript.parameters['LEAF-3']
        prim_vtep       = testscript.parameters['LEAF-1']
        sec_vtep        = testscript.parameters['LEAF-2']
        prim_vtep_if    = str(testscript.parameters['intf_LEAF_1_1_to_IXIA'])
        sa_vtep_if      = str(testscript.parameters['intf_LEAF_3_to_IXIA'])
        fex_vtep_if     = str(testscript.parameters['intf_LEAF_1_FEX_to_IXIA'])
        ixNetwork       = testscript.parameters['ixNetwork']

        with steps.start("Stopping hosts..."):
            ixNetwork.StopAllProtocols()
        
        log.info('Waiting {}secs to stop the hosts'.format(traffic_stop_time))
        time.sleep(traffic_stop_time)
        
        with steps.start("UnConfigure Port-Security on Primary VTEP Orphan"):
            if not unconfig_interface_ps([prim_vtep], prim_vtep_if, log):
                self.errored('Exception occurred while configuring port security', goto=['common_cleanup'])
        
        with steps.start("UnConfigure Port-Security on Standalone VTEP"):
            if not unconfig_interface_ps([sa_vtep], sa_vtep_if, log):
                self.errored('Exception occurred while configuring port security', goto=['common_cleanup'])
        
        with steps.start("UnConfigure Port-Security on VPC Primary/Secondary - Static"):
            if not unconfig_interface_ps([prim_vtep, sec_vtep], 'port-channel 11', log):
                self.errored('Exception occurred while configuring port security', goto=['common_cleanup'])
        
        with steps.start("UnConfigure Port-Security on Leaf-1 FEX - FEX port of VTEP"):
            if not unconfig_interface_ps([prim_vtep], fex_vtep_if, log):
                self.errored('Exception occurred while configuring port security', goto=['common_cleanup'])
        
        with steps.start("Verifying MTS leak.."):
            if verify_mts_leak([prim_vtep, sec_vtep, sa_vtep], log):
                log.info('MTS Leak verification success')
            else:
                self.failed('MTS Leak verification failed')

        with steps.start("Verifying Cores and Log Errors"):
            status = infraVerify.postTestVerification(post_test_process_dict)
            if status['status'] == 0:
                self.failed(reason=status['logs'])
            else:
                self.passed(reason=status['logs'])

# TC-42
# Switch reload after learning the mac in Trunk mode
# VPC port-channel and orphan, Standalone, Standalone + FEX ST
class TC_VXLAN_PS_033_Access(aetest.Testcase):
    @aetest.test
    def test_setup(self, testscript, testbed, steps):
        sa_vtep         = testscript.parameters['LEAF-3']
        prim_vtep       = testscript.parameters['LEAF-1']
        sec_vtep        = testscript.parameters['LEAF-2']
        src_vlan        = int(testscript.parameters['LEAF_1_Orphan1_TGEN_dict']['vlan_id'])
        leaf1_mac       = str(testscript.parameters['PORTSEC_Dict']['vpc_static_mac'])
        prim_vtep_if    = str(testscript.parameters['intf_LEAF_1_1_to_IXIA'])
        sa_vtep_if      = str(testscript.parameters['intf_LEAF_3_to_IXIA'])
        
        new_config = '''switchport port-security aging time 5
                        switchport port-security aging type inactivity
                        switchport port-security violation restrict
                    '''                    
        with steps.start("Configure Port-Security on Primary VTEP Orphan"):
            if not config_interface_ps([prim_vtep], prim_vtep_if, log, new_config):
                self.errored('Exception occurred while configuring port security', goto=['common_cleanup'])
        
        with steps.start("Configure Port-Security on Standalone VTEP"):
            if not config_interface_ps([sa_vtep], sa_vtep_if, log, new_config):
                self.errored('Exception occurred while configuring port security', goto=['common_cleanup'])
        
        new_config = '''switchport port-security aging time 5
                        switchport port-security aging type inactivity
                        switchport port-security violation restrict
                        switchport port-security mac-address {mac}
                        switchport port-security mac-address sticky
                    '''.format(mac=leaf1_mac)
        
        with steps.start("Configure Port-Security on VPC Primary/Secondary - Static"):
            if not config_interface_ps([prim_vtep, sec_vtep], 'port-channel 11', log, new_config):
                self.errored('Exception occurred while configuring port security', goto=['common_cleanup'])
        
        log.info("Waiting {}secs for interface to come up".format(config_time))
        time.sleep(config_time)
        display_configs(testscript)
        
    @aetest.test
    def verify_reload_standalone(self, testscript, testbed, steps):
        sa_vtep         = testscript.parameters['LEAF-3']
        prim_vtep       = testscript.parameters['LEAF-1']
        sec_vtep        = testscript.parameters['LEAF-2']
        sa_vtep_if      = str(testscript.parameters['intf_LEAF_3_to_IXIA'])
        sa_mac          = str(testscript.parameters['PORTSEC_Dict']['sa_mac'])
        ixNetwork       = testscript.parameters['ixNetwork']
        p1_handle       = testscript.parameters['orphan1_handle']
        p2_handle       = testscript.parameters['sa_handle']
        
        with steps.start("Starting hosts..."):
            p1_handle.Start()
            p2_handle.Start()
        
        log.info('Waiting {}secs to start 1025 hosts'.format(host_start_time))
        time.sleep(host_start_time)

        stream1 = ixNetwork.Traffic.TrafficItem.find(Name='Access Orphan To Standalone')
        stream1.StartStatelessTraffic()
        log.info('Waiting {}secs to start the traffic'.format(traffic_start_time))
        time.sleep(traffic_start_time)
        
        with steps.start("Checking mac/arp learning on local vtep (leaf3) and remote vpc peer (leaf1 and leaf2).."):
            if not verify_port_sec_addr_count(sa_vtep, sa_vtep_if, 1025, 'DYNAMIC'):
                log.error("DYNAMIC Mac learning failed")
                self.failed("DYNAMIC Mac learning failed")

            if not verify_secure_mac_on_vteps(sa_vtep, '1002', 1025, sa_mac, 'secure'):
                log.error("Mac learning failed on Standalone")
                self.failed("Mac learning failed on Standalone")

            if not verify_secure_mac_on_vteps(prim_vtep, '1002', 1025, sa_mac):
                log.error("DYNAMIC Mac learning failed on remote vtep(leaf1)")
                self.failed("DYNAMIC Mac learning failed on remote vtep(leaf1)")

            if not verify_secure_mac_on_vteps(sec_vtep, '1002', 1025, sa_mac):
                log.error("DYNAMIC Mac learning failed on remote vtep(leaf2)")
                self.failed("DYNAMIC Mac learning failed on remote vtep(leaf2)")

        with steps.start('Reload Standalone VTEP'):
            
            result = infraTrig.switchReload(sa_vtep)
            if result:
                log.info("Reload completed Successfully")
            else:
                log.debug("Reload Failed")
                self.failed("Reload Failed")
            
        log.info("Waiting for 300 sec for the topology to come UP")
        time.sleep(300)

        with steps.start("Check NVE peers"):
            # Verify NVE Peers with new IP
            nvePeerData = verifyEVPNNvePeers(testscript.parameters['leavesDict'])

            if nvePeerData['result'] is 1:
                log.info("PASS : Successfully verified NVE Peering\n\n")
            else:
                log.info("FAIL : Failed to verify NVE Peering\n\n")
                self.failed(reason=nvePeerData['log'])
        
        stream1.StopStatelessTraffic()
        log.info('Waiting {}secs to stop the traffic'.format(traffic_stop_time))
        time.sleep(traffic_stop_time)
        
        with steps.start("Checking mac learning on local and remote after reload"):
            if not verify_port_sec_addr_count(sa_vtep, sa_vtep_if, 1025, 'DYNAMIC'):
                log.error("DYNAMIC Mac learning failed")
                self.failed("DYNAMIC Mac learning failed")

            if not verify_secure_mac_on_vteps(sa_vtep, '1002', 1025, sa_mac, 'secure'):
                log.error("Mac learning failed on Standalone")
                self.failed("Mac learning failed on Standalone")

            if not verify_secure_mac_on_vteps(prim_vtep, '1002', 1025, sa_mac):
                log.error("DYNAMIC Mac learning failed on remote vtep(leaf1)")
                self.failed("DYNAMIC Mac learning failed on remote vtep(leaf1)")

            if not verify_secure_mac_on_vteps(sec_vtep, '1002', 1025, sa_mac):
                log.error("DYNAMIC Mac learning failed on remote vtep(leaf2)")
                self.failed("DYNAMIC Mac learning failed on remote vtep(leaf2)")

        with steps.start("Verify Steady State after reload"):
            if VerifyTraffic("Test_011_Standalone", testscript, traffic_item='Access Orphan To Standalone'):
                log.info('Verify traffic success after reload')
            else:
                self.failed('Verify traffic failed after reload')
    
    @aetest.test
    def verify_reload_vpc(self, testscript, testbed, steps):
        sa_vtep         = testscript.parameters['LEAF-3']
        prim_vtep       = testscript.parameters['LEAF-1']
        sec_vtep        = testscript.parameters['LEAF-2']
        prim_vpc_mac    = str(testscript.parameters['PORTSEC_Dict']['prim_vpc_mac'])
        ixNetwork       = testscript.parameters['ixNetwork']
        p1_handle       = testscript.parameters['vpc_handle']
        p2_handle       = testscript.parameters['sa_handle']
        
        with steps.start("Starting hosts.."):
            p1_handle.Start()
            p2_handle.Start()
        
        log.info('Waiting {}secs to start 1025 hosts'.format(host_start_time))
        time.sleep(host_start_time)
    
        stream1 = ixNetwork.Traffic.TrafficItem.find(Name='Access VPC To Standalone')
        stream1.StartStatelessTraffic()
        log.info('Waiting {}secs to start the traffic'.format(traffic_start_time))
        time.sleep(traffic_start_time)
        
        with steps.start("Checking mac learning on local and remote vtep"):
            if not verify_port_sec_addr_count(prim_vtep, 'port-channel 11', 1, 'STATIC'):
                log.error("STATIC Mac learning failed")
                self.failed("STATIC Mac learning failed")
        
            if not verify_port_sec_addr_count(prim_vtep, 'port-channel 11', 1024, 'STICKY'):
                log.error("Mac learning failed")
                self.failed("Mac learning failed")

            if not verify_port_sec_addr_count(sec_vtep, 'port-channel 11', 1, 'STATIC'):
                log.error("STATIC Mac learning failed")
                self.failed("STATIC Mac learning failed")
        
            if not verify_port_sec_addr_count(sec_vtep, 'port-channel 11', 1024, 'STICKY'):
                log.error("Mac learning failed")
                self.failed("Mac learning failed")
            
            if not verify_secure_mac_on_vteps(prim_vtep, '1001', 1025, prim_vpc_mac, 'secure'):
                log.error("Mac learning failed on primary")
                self.failed("Mac learning failed on primary")

            if not verify_secure_mac_on_vteps(sec_vtep, '1001', 1025, prim_vpc_mac, 'secure'):
                log.error("Mac learning failed on primary")
                self.failed("Mac learning failed on primary")
                
            if not verify_secure_mac_on_vteps(sa_vtep, '1001', 1025, prim_vpc_mac):
                log.error("Mac learning failed on standalone")
                self.failed("Mac learning failed on standalone")

        primary_handle = get_vpc_primary_secondary_device([prim_vtep, sec_vtep])
        with steps.start('Reload Primary VTEP'):
            result = infraTrig.switchReload(primary_handle)
            if result:
                log.info("Primary Reload completed Successfully")
            else:
                log.debug("Primary Reload Failed")
                self.failed("Primary Reload Failed")
            
        log.info("Waiting for 240 sec for the topology to come UP")
        time.sleep(240)
        
        with steps.start("Check NVE Peers"):
            # Verify NVE Peers with new IP
            nvePeerData = verifyEVPNNvePeers(testscript.parameters['leavesDict'])

            if nvePeerData['result'] is 1:
                log.info("PASS : Successfully verified NVE Peering\n\n")
            else:
                log.info("FAIL : Failed to verify NVE Peering\n\n")
                self.failed(reason=nvePeerData['log'])
        
        with steps.start("Check VPC PO Status"):
            primary_handle = get_vpc_primary_secondary_device([prim_vtep, sec_vtep])
            if getVpcPoStatus(primary_handle, 'Po11'):
                log.info("Po11 is up")
            else:
                log.info('Po11 is down')
                self.failed('Po11 is down')

        with steps.start("Checking mac learning on local and remote vtep after primary reload"):
            if not verify_port_sec_addr_count(prim_vtep, 'port-channel 11', 1, 'STATIC'):
                log.error("STATIC Mac learning failed")
                self.failed("STATIC Mac learning failed")
        
            if not verify_port_sec_addr_count(prim_vtep, 'port-channel 11', 1024, 'STICKY'):
                log.error("Mac learning failed")
                self.failed("Mac learning failed")

            if not verify_port_sec_addr_count(sec_vtep, 'port-channel 11', 1, 'STATIC'):
                log.error("STATIC Mac learning failed")
                self.failed("STATIC Mac learning failed")
        
            if not verify_port_sec_addr_count(sec_vtep, 'port-channel 11', 1024, 'STICKY'):
                log.error("Mac learning failed")
                self.failed("Mac learning failed")
                
            if not verify_secure_mac_on_vteps(prim_vtep, '1001', 1025, prim_vpc_mac, 'secure'):
                log.error("Mac learning failed on primary")
                self.failed("Mac learning failed on primary")

            if not verify_secure_mac_on_vteps(sec_vtep, '1001', 1025, prim_vpc_mac, 'secure'):
                log.error("Mac learning failed on primary")
                self.failed("Mac learning failed on primary")
                
            if not verify_secure_mac_on_vteps(sa_vtep, '1001', 1025, prim_vpc_mac):
                log.error("Mac learning failed on standalone")
                self.failed("Mac learning failed on standalone")
        
        stream1.StopStatelessTraffic()
        log.info('Waiting {}secs to stop the traffic'.format(traffic_stop_time))
        time.sleep(traffic_stop_time)

        with steps.start("Verify Steady State"):

            if VerifyTraffic("Test_014_VPC", testscript, traffic_item='Access VPC To Standalone'):
                log.info('Verify Traffic Success after Primary Reload')
            else:
                self.failed('Verify Traffic Success after Primary Reload')

        stream1.StartStatelessTraffic()
        log.info('Waiting {}secs to start the traffic'.format(traffic_start_time))
        time.sleep(traffic_start_time)
        
        primary_handle = get_vpc_primary_secondary_device([prim_vtep, sec_vtep])
        with steps.start('Reload Primary VTEP'):
            primary_handle.configure("copy r s")
            
            result = infraTrig.switchReload(primary_handle)
            if result:
                log.info("Primary Reload completed Successfully")
            else:
                log.debug("Primary Reload Failed")
                self.failed("Primary Reload Failed")
            
        log.info("Waiting for 240 sec for the topology to come UP")
        time.sleep(240)
        
        with steps.start("Check NVE Peers"):
            # Verify NVE Peers with new IP
            nvePeerData = verifyEVPNNvePeers(testscript.parameters['leavesDict'])

            if nvePeerData['result'] is 1:
                log.info("PASS : Successfully verified NVE Peering\n\n")
            else:
                log.info("FAIL : Failed to verify NVE Peering\n\n")
                self.failed(reason=nvePeerData['log'])
        
        with steps.start("Check VPC PO Status"):
            primary_handle = get_vpc_primary_secondary_device([prim_vtep, sec_vtep])
            if getVpcPoStatus(primary_handle, 'Po11'):
                log.info("Po11 is up")
            else:
                log.info('Po11 is down')
                self.failed('Po11 is down')

        with steps.start("Checking mac learning on local and remote vtep after primary reload"):
            if not verify_port_sec_addr_count(prim_vtep, 'port-channel 11', 1, 'STATIC'):
                log.error("STATIC Mac learning failed")
                self.failed("STATIC Mac learning failed")
        
            if not verify_port_sec_addr_count(prim_vtep, 'port-channel 11', 1024, 'STICKY'):
                log.error("Mac learning failed")
                self.failed("Mac learning failed")

            if not verify_port_sec_addr_count(sec_vtep, 'port-channel 11', 1, 'STATIC'):
                log.error("STATIC Mac learning failed")
                self.failed("STATIC Mac learning failed")
        
            if not verify_port_sec_addr_count(sec_vtep, 'port-channel 11', 1024, 'STICKY'):
                log.error("Mac learning failed")
                self.failed("Mac learning failed")
            
            if not verify_secure_mac_on_vteps(prim_vtep, '1001', 1025, prim_vpc_mac, 'secure'):
                log.error("Mac learning failed on primary")
                self.failed("Mac learning failed on primary")

            if not verify_secure_mac_on_vteps(sec_vtep, '1001', 1025, prim_vpc_mac, 'secure'):
                log.error("Mac learning failed on primary")
                self.failed("Mac learning failed on primary")
                
            if not verify_secure_mac_on_vteps(sa_vtep, '1001', 1025, prim_vpc_mac):
                log.error("Mac learning failed on standalone")
                self.failed("Mac learning failed on standalone")
        
        stream1.StopStatelessTraffic()
        log.info('Waiting {}secs to stop the traffic'.format(traffic_stop_time))
        time.sleep(traffic_stop_time)

        with steps.start("Verify Steady State after secondary reload"):

            if VerifyTraffic("Test_014_VPC", testscript, traffic_item='Access VPC To Standalone'):
                log.info('Verify Traffic Success after Secondary Reload')
            else:
                self.failed('Verify Traffic Success after Secondary Reload')

    @aetest.test
    def test_cleanup(self, testscript, testbed, steps):
        sa_vtep         = testscript.parameters['LEAF-3']
        prim_vtep       = testscript.parameters['LEAF-1']
        sec_vtep        = testscript.parameters['LEAF-2']
        prim_vtep_if    = str(testscript.parameters['intf_LEAF_1_1_to_IXIA'])
        sa_vtep_if      = str(testscript.parameters['intf_LEAF_3_to_IXIA'])
        leaf1_mac       = str(testscript.parameters['PORTSEC_Dict']['vpc_static_mac'])
        src_vlan        = int(testscript.parameters['LEAF_1_Orphan1_TGEN_dict']['vlan_id'])
        prim_vpc_mac    = str(testscript.parameters['PORTSEC_Dict']['prim_vpc_mac'])
        ixNetwork       = testscript.parameters['ixNetwork']
        
        new_config = '''no switchport port-security aging time 5
                        no switchport port-security aging type inactivity'''
        with steps.start("UnConfigure Port-Security on Primary VTEP Orphan"):
            if not unconfig_interface_ps([prim_vtep], prim_vtep_if, log, new_config):
                self.errored('Exception occurred while configuring port security', goto=['common_cleanup'])
        
        with steps.start("UnConfigure Port-Security on Standalone VTEP"):
            if not unconfig_interface_ps([sa_vtep], sa_vtep_if, log, new_config):
                self.errored('Exception occurred while configuring port security', goto=['common_cleanup'])
        
        new_config = '''no switchport port-security aging time 5
                        no switchport port-security aging type inactivity
                        no switchport port-security mac-address {mac}'''.format(mac=leaf1_mac)
                        
        with steps.start("UnConfigure Port-Security on VPC Primary/Secondary - Static"):
            if not unconfig_interface_ps([prim_vtep, sec_vtep], 'port-channel 11', log, new_config):
                self.errored('Exception occurred while configuring port security', goto=['common_cleanup'])
        
        log.info("Waiting {}secs for interface to come up".format(config_time))
        time.sleep(config_time)
        
        with steps.start("Checking mac/arp learning on local(leaf1 VPC) and remote vtep (leaf3).."):
            if not verify_secure_mac_on_vteps(sa_vtep, '1001', 1025, prim_vpc_mac, 'dynamic'):
                log.error("Mac learning failed on standalone")
                self.failed("Mac learning failed on local vtep")
            if not verify_secure_mac_on_vteps(prim_vtep, '1001', 1025, prim_vpc_mac, 'dynamic'):
                log.error("Mac learning failed on primary")
                self.failed("Mac learning failed on primary")
            if not verify_secure_mac_on_vteps(sec_vtep, '1001', 1025, prim_vpc_mac, 'dynamic'):
                log.error("Mac learning failed on secondary")
                self.failed("Mac learning failed on secondary")

        with steps.start("Stopping all hosts..."):
            ixNetwork.StopAllProtocols()

        log.info('Waiting {}secs to stop the hosts'.format(traffic_stop_time))
        time.sleep(traffic_stop_time)

        with steps.start('Verify Learned mac address consistency between hardware and software'):
            if verify_mac_cc_between_hardware_software([prim_vtep, sec_vtep, sa_vtep]):
                log.info('MAC CC success')
            else:
                self.failed('MAC CC failed')

        with steps.start("Verifying MTS leak.."):
            if verify_mts_leak([prim_vtep, sec_vtep, sa_vtep], log):
                log.info('MTS Leak verification success')
            else:
                self.failed('MTS Leak verification failed')

        with steps.start("Verifying Cores and Log Errors"):
            status = infraVerify.postTestVerification(post_test_process_dict)
            if status['status'] == 0:
                self.failed(reason=status['logs'])
            else:
                self.passed(reason=status['logs'])

# TC-41 - ASCII Reload
class TC_VXLAN_PS_034_Access(aetest.Testcase):
    @aetest.test
    def test_setup(self, testscript, testbed, steps):
        sa_vtep         = testscript.parameters['LEAF-3']
        prim_vtep       = testscript.parameters['LEAF-1']
        sec_vtep        = testscript.parameters['LEAF-2']
        src_vlan        = int(testscript.parameters['LEAF_1_Orphan1_TGEN_dict']['vlan_id'])
        leaf1_mac       = str(testscript.parameters['PORTSEC_Dict']['vpc_static_mac'])
        prim_vtep_if    = str(testscript.parameters['intf_LEAF_1_1_to_IXIA'])
        sa_vtep_if      = str(testscript.parameters['intf_LEAF_3_to_IXIA'])
        
        new_config = '''switchport port-security aging time 5
                        switchport port-security aging type inactivity
                        switchport port-security violation restrict
                    '''                    
        with steps.start("Configure Port-Security on Primary VTEP Orphan"):
            if not config_interface_ps([prim_vtep], prim_vtep_if, log, new_config):
                self.errored('Exception occurred while configuring port security', goto=['common_cleanup'])
        
        with steps.start("Configure Port-Security on Standalone VTEP"):
            if not config_interface_ps([sa_vtep], sa_vtep_if, log, new_config):
                self.errored('Exception occurred while configuring port security', goto=['common_cleanup'])
        
        new_config = '''switchport port-security aging time 5
                        switchport port-security aging type inactivity
                        switchport port-security violation restrict
                        switchport port-security mac-address {mac}
                        switchport port-security mac-address sticky
                    '''.format(mac=leaf1_mac)
        
        with steps.start("Configure Port-Security on VPC Primary/Secondary - Static"):
            if not config_interface_ps([prim_vtep, sec_vtep], 'port-channel 11', log, new_config):
                self.errored('Exception occurred while configuring port security', goto=['common_cleanup'])
        
        log.info("Waiting {}secs for interface to come up".format(config_time))
        time.sleep(config_time)
        display_configs(testscript)

    @aetest.test
    def verify_reload_standalone(self, testscript, testbed, steps):
        sa_vtep         = testscript.parameters['LEAF-3']
        prim_vtep       = testscript.parameters['LEAF-1']
        sec_vtep        = testscript.parameters['LEAF-2']
        sa_vtep_if      = str(testscript.parameters['intf_LEAF_3_to_IXIA'])
        sa_mac          = str(testscript.parameters['PORTSEC_Dict']['sa_mac'])
        ixNetwork       = testscript.parameters['ixNetwork']
        p1_handle       = testscript.parameters['orphan1_handle']
        p2_handle       = testscript.parameters['sa_handle']
        
        with steps.start("Starting hosts..."):
            p1_handle.Start()
            p2_handle.Start()
        
        log.info('Waiting {}secs to start 1025 hosts'.format(host_start_time))
        time.sleep(host_start_time)

        stream1 = ixNetwork.Traffic.TrafficItem.find(Name='Access Orphan To Standalone')
        stream1.StartStatelessTraffic()
        log.info('Waiting {}secs to start the traffic'.format(traffic_start_time))
        time.sleep(traffic_start_time)
        
        with steps.start("Checking mac/arp learning on local vtep (leaf3) and remote vpc peer (leaf1 and leaf2).."):
            if not verify_port_sec_addr_count(sa_vtep, sa_vtep_if, 1025, 'DYNAMIC'):
                log.error("DYNAMIC Mac learning failed")
                self.failed("DYNAMIC Mac learning failed")

            if not verify_secure_mac_on_vteps(sa_vtep, '1002', 1025, sa_mac, 'secure'):
                log.error("Mac learning failed on Standalone")
                self.failed("Mac learning failed on Standalone")

            if not verify_secure_mac_on_vteps(prim_vtep, '1002', 1025, sa_mac):
                log.error("DYNAMIC Mac learning failed on remote vtep(leaf1)")
                self.failed("DYNAMIC Mac learning failed on remote vtep(leaf1)")

            if not verify_secure_mac_on_vteps(sec_vtep, '1002', 1025, sa_mac):
                log.error("DYNAMIC Mac learning failed on remote vtep(leaf2)")
                self.failed("DYNAMIC Mac learning failed on remote vtep(leaf2)")

        with steps.start('Reload Secondary VTEP'):
            result = infraTrig.switchASCIIreload(sa_vtep)
            if result:
                log.info("Reload completed Successfully")
            else:
                log.debug("Reload Failed")
                self.failed("Reload Failed")
            
        log.info("Waiting for 240 sec for the topology to come UP")
        time.sleep(240)
        
        with steps.start("Check NVE Peers"):
            # Verify NVE Peers with new IP
            nvePeerData = verifyEVPNNvePeers(testscript.parameters['leavesDict'])

            if nvePeerData['result'] is 1:
                log.info("PASS : Successfully verified NVE Peering\n\n")
            else:
                log.info("FAIL : Failed to verify NVE Peering\n\n")
                self.failed(reason=nvePeerData['log'])
        
        stream1.StopStatelessTraffic()
        log.info('Waiting {}secs to stop the traffic'.format(traffic_stop_time))
        time.sleep(traffic_stop_time)
        
        with steps.start("Checking mac learning on local and remote after reload"):
            if not verify_port_sec_addr_count(sa_vtep, sa_vtep_if, 1025, 'DYNAMIC'):
                log.error("DYNAMIC Mac learning failed")
                self.failed("DYNAMIC Mac learning failed")

            if not verify_secure_mac_on_vteps(sa_vtep, '1002', 1025, sa_mac, 'secure'):
                log.error("Mac learning failed on Standalone")
                self.failed("Mac learning failed on Standalone")

            if not verify_secure_mac_on_vteps(prim_vtep, '1002', 1025, sa_mac):
                log.error("DYNAMIC Mac learning failed on remote vtep(leaf1)")
                self.failed("DYNAMIC Mac learning failed on remote vtep(leaf1)")

            if not verify_secure_mac_on_vteps(sec_vtep, '1002', 1025, sa_mac):
                log.error("DYNAMIC Mac learning failed on remote vtep(leaf2)")
                self.failed("DYNAMIC Mac learning failed on remote vtep(leaf2)")

        with steps.start("Verify Steady State after reload"):
            if VerifyTraffic("Test_015_Orphan_Access", testscript, 
                             traffic_item='Access Orphan To Standalone'):
                log.info('Verify traffic success after reload')
            else:
                self.failed('Verify traffic failed after reload')
    
    @aetest.test
    def verify_vpc(self, testscript, testbed, steps):
        sa_vtep = testscript.parameters['LEAF-3']
        prim_vtep = testscript.parameters['LEAF-1']
        sec_vtep = testscript.parameters['LEAF-2']
        prim_vpc_mac = str(testscript.parameters['PORTSEC_Dict']['prim_vpc_mac'])
        ixNetwork   = testscript.parameters['ixNetwork']
        p1_handle       = testscript.parameters['vpc_handle']
        p2_handle       = testscript.parameters['sa_handle']

        with steps.start("Starting hosts.."):
            p1_handle.Start()
            p2_handle.Start()
        
        log.info('Waiting {}secs to start 1025 hosts'.format(host_start_time))
        time.sleep(host_start_time)
    
        stream1 = ixNetwork.Traffic.TrafficItem.find(Name='Access VPC To Standalone')        
        stream1.StartStatelessTraffic()
        log.info('Waiting {}secs to start the traffic'.format(traffic_start_time))
        time.sleep(traffic_start_time)
        
        with steps.start("Checking mac learning on local and remote vtep"):
            if not verify_port_sec_addr_count(prim_vtep, 'port-channel 11', 1, 'STATIC'):
                log.error("STATIC Mac learning failed")
                self.failed("STATIC Mac learning failed")
        
            if not verify_port_sec_addr_count(prim_vtep, 'port-channel 11', 1024, 'STICKY'):
                log.error("Mac learning failed")
                self.failed("Mac learning failed")

            if not verify_port_sec_addr_count(sec_vtep, 'port-channel 11', 1, 'STATIC'):
                log.error("STATIC Mac learning failed")
                self.failed("STATIC Mac learning failed")
        
            if not verify_port_sec_addr_count(sec_vtep, 'port-channel 11', 1024, 'STICKY'):
                log.error("Mac learning failed")
                self.failed("Mac learning failed")
            
            if not verify_secure_mac_on_vteps(prim_vtep, '1001', 1025, prim_vpc_mac, 'secure'):
                log.error("Mac learning failed on primary")
                self.failed("Mac learning failed on primary")

            if not verify_secure_mac_on_vteps(sec_vtep, '1001', 1025, prim_vpc_mac, 'secure'):
                log.error("Mac learning failed on primary")
                self.failed("Mac learning failed on primary")
                
            if not verify_secure_mac_on_vteps(sa_vtep, '1001', 1025, prim_vpc_mac):
                log.error("Mac learning failed on standalone")
                self.failed("Mac learning failed on standalone")

        primary_handle = get_vpc_primary_secondary_device([prim_vtep, sec_vtep])
        with steps.start('Reload Primary VTEP'):
            result = infraTrig.switchASCIIreload(primary_handle)
            if result:
                log.info("Primary Reload completed Successfully")
            else:
                log.debug("Primary Reload Failed")
                self.failed("Primary Reload Failed")
                            
        with steps.start("Check NVE Peers"):
            # Verify NVE Peers with new IP
            nvePeerData = verifyEVPNNvePeers(testscript.parameters['leavesDict'])

            if nvePeerData['result'] is 1:
                log.info("PASS : Successfully verified NVE Peering\n\n")
            else:
                log.info("FAIL : Failed to verify NVE Peering\n\n")
                self.failed(reason=nvePeerData['log'])
        
        with steps.start("Check VPC PO Status"):
            primary_handle = get_vpc_primary_secondary_device([prim_vtep, sec_vtep])
            if getVpcPoStatus(primary_handle, 'Po11'):
                log.info("Po11 is up")
            else:
                log.info('Po11 is down')
                self.failed('Po11 is down')

        with steps.start("Checking mac learning on local and remote vtep after primary reload"):
            if not verify_port_sec_addr_count(prim_vtep, 'port-channel 11', 1, 'STATIC'):
                log.error("STATIC Mac learning failed")
                self.failed("STATIC Mac learning failed")
        
            if not verify_port_sec_addr_count(prim_vtep, 'port-channel 11', 1024, 'STICKY'):
                log.error("Mac learning failed")
                self.failed("Mac learning failed")

            if not verify_port_sec_addr_count(sec_vtep, 'port-channel 11', 1, 'STATIC'):
                log.error("STATIC Mac learning failed")
                self.failed("STATIC Mac learning failed")
        
            if not verify_port_sec_addr_count(sec_vtep, 'port-channel 11', 1024, 'STICKY'):
                log.error("Mac learning failed")
                self.failed("Mac learning failed")
                
            if not verify_secure_mac_on_vteps(prim_vtep, '1001', 1025, prim_vpc_mac, 'secure'):
                log.error("Mac learning failed on primary")
                self.failed("Mac learning failed on primary")

            if not verify_secure_mac_on_vteps(sec_vtep, '1001', 1025, prim_vpc_mac, 'secure'):
                log.error("Mac learning failed on primary")
                self.failed("Mac learning failed on primary")
                
            if not verify_secure_mac_on_vteps(sa_vtep, '1001', 1025, prim_vpc_mac):
                log.error("Mac learning failed on standalone")
                self.failed("Mac learning failed on standalone")
        
        stream1.StopStatelessTraffic()
        log.info('Waiting {}secs to stop the traffic'.format(traffic_stop_time))
        time.sleep(traffic_stop_time)

        with steps.start("Verify Steady State"):

            if VerifyTraffic("Test_015_Access", testscript, traffic_item='Access VPC To Standalone'):
                log.info('Verify Traffic Success after Primary Reload')
            else:
                self.failed('Verify Traffic Success after Primary Reload')

        stream1.StartStatelessTraffic()
        log.info('Waiting {}secs to start the traffic'.format(traffic_start_time))
        time.sleep(traffic_start_time)
        
        primary_handle = get_vpc_primary_secondary_device([prim_vtep, sec_vtep])
        with steps.start('Reload Primary VTEP'):
            primary_handle.configure("copy r s")
            
            result = infraTrig.switchASCIIreload(primary_handle)
            if result:
                log.info("Primary Reload completed Successfully")
            else:
                log.debug("Primary Reload Failed")
                self.failed("Primary Reload Failed")
        
        with steps.start("Check NVE Peers"):
            # Verify NVE Peers with new IP
            nvePeerData = verifyEVPNNvePeers(testscript.parameters['leavesDict'])

            if nvePeerData['result'] is 1:
                log.info("PASS : Successfully verified NVE Peering\n\n")
            else:
                log.info("FAIL : Failed to verify NVE Peering\n\n")
                self.failed(reason=nvePeerData['log'])
        
        with steps.start("Check VPC PO status"):
            primary_handle = get_vpc_primary_secondary_device([prim_vtep, sec_vtep])
            if getVpcPoStatus(primary_handle, 'Po11'):
                log.info("Po11 is up")
            else:
                log.info('Po11 is down')
                self.failed('Po11 is down')

        with steps.start("Checking mac learning on local and remote vtep after primary reload"):
            if not verify_port_sec_addr_count(prim_vtep, 'port-channel 11', 1, 'STATIC'):
                log.error("STATIC Mac learning failed")
                self.failed("STATIC Mac learning failed")
        
            if not verify_port_sec_addr_count(prim_vtep, 'port-channel 11', 1024, 'STICKY'):
                log.error("Mac learning failed")
                self.failed("Mac learning failed")

            if not verify_port_sec_addr_count(sec_vtep, 'port-channel 11', 1, 'STATIC'):
                log.error("STATIC Mac learning failed")
                self.failed("STATIC Mac learning failed")
        
            if not verify_port_sec_addr_count(sec_vtep, 'port-channel 11', 1024, 'STICKY'):
                log.error("Mac learning failed")
                self.failed("Mac learning failed")
            
            if not verify_secure_mac_on_vteps(prim_vtep, '1001', 1025, prim_vpc_mac, 'secure'):
                log.error("Mac learning failed on primary")
                self.failed("Mac learning failed on primary")

            if not verify_secure_mac_on_vteps(sec_vtep, '1001', 1025, prim_vpc_mac, 'secure'):
                log.error("Mac learning failed on primary")
                self.failed("Mac learning failed on primary")
                
            if not verify_secure_mac_on_vteps(sa_vtep, '1001', 1025, prim_vpc_mac):
                log.error("Mac learning failed on standalone")
                self.failed("Mac learning failed on standalone")
        
        stream1.StopStatelessTraffic()
        log.info('Waiting {}secs to stop the traffic'.format(traffic_stop_time))
        time.sleep(traffic_stop_time)

        with steps.start("Verify Steady State after secondary reload"):

            if VerifyTraffic("Test_015_Access", testscript, traffic_item='Access VPC To Standalone'):
                log.info('Verify Traffic Success after Secondary Reload')
            else:
                self.failed('Verify Traffic Success after Secondary Reload')

    @aetest.test
    def test_cleanup(self, testscript, testbed, steps):
        sa_vtep         = testscript.parameters['LEAF-3']
        prim_vtep       = testscript.parameters['LEAF-1']
        sec_vtep        = testscript.parameters['LEAF-2']
        prim_vtep_if    = str(testscript.parameters['intf_LEAF_1_1_to_IXIA'])
        sa_vtep_if      = str(testscript.parameters['intf_LEAF_3_to_IXIA'])
        leaf1_mac       = str(testscript.parameters['PORTSEC_Dict']['vpc_static_mac'])
        src_vlan        = int(testscript.parameters['LEAF_1_Orphan1_TGEN_dict']['vlan_id'])
        prim_vpc_mac    = str(testscript.parameters['PORTSEC_Dict']['prim_vpc_mac'])
        ixNetwork       = testscript.parameters['ixNetwork']
        
        new_config = '''no switchport port-security aging time 5
                        no switchport port-security aging type inactivity'''
        with steps.start("UnConfigure Port-Security on Primary VTEP Orphan"):
            if not unconfig_interface_ps([prim_vtep], prim_vtep_if, log, new_config):
                self.errored('Exception occurred while configuring port security', goto=['common_cleanup'])
        
        with steps.start("UnConfigure Port-Security on Standalone VTEP"):
            if not unconfig_interface_ps([sa_vtep], sa_vtep_if, log, new_config):
                self.errored('Exception occurred while configuring port security', goto=['common_cleanup'])
        
        new_config = '''no switchport port-security aging time 5
                        no switchport port-security aging type inactivity
                        no switchport port-security mac-address {mac}
                        no switchport port-security mac-address sticky'''.format(mac=leaf1_mac)
                        
        with steps.start("UnConfigure Port-Security on VPC Primary/Secondary - Static"):
            if not unconfig_interface_ps([prim_vtep, sec_vtep], 'port-channel 11', log, new_config):
                self.errored('Exception occurred while configuring port security', goto=['common_cleanup'])
        
        log.info("Waiting {}secs for interface to come up".format(config_time))
        time.sleep(config_time)
        
        with steps.start("Checking mac/arp learning on local(leaf1 VPC) and remote vtep (leaf3).."):
            if not verify_secure_mac_on_vteps(sa_vtep, '1001', 1025, prim_vpc_mac, 'dynamic'):
                log.error("Mac learning failed on standalone")
                self.failed("Mac learning failed on local vtep")
            if not verify_secure_mac_on_vteps(prim_vtep, '1001', 1025, prim_vpc_mac, 'dynamic'):
                log.error("Mac learning failed on primary")
                self.failed("Mac learning failed on primary")
            if not verify_secure_mac_on_vteps(sec_vtep, '1001', 1025, prim_vpc_mac, 'dynamic'):
                log.error("Mac learning failed on secondary")
                self.failed("Mac learning failed on secondary")
        
        with steps.start("Stopping all hosts..."):
            ixNetwork.StopAllProtocols()

        log.info('Waiting {}secs to stop the hosts'.format(traffic_stop_time))
        time.sleep(traffic_stop_time)

        with steps.start('Verify Learned mac address consistency between hardware and software'):
            if verify_mac_cc_between_hardware_software([prim_vtep, sec_vtep, sa_vtep]):
                log.info('MAC CC success')
            else:
                self.failed('MAC CC failed')
        
        with steps.start("Verifying MTS leak.."):
            if verify_mts_leak([prim_vtep, sec_vtep, sa_vtep], log):
                log.info('MTS Leak verification success')
            else:
                self.failed('MTS Leak verification failed')

        with steps.start("Verifying Cores and Log Errors"):
            status = infraVerify.postTestVerification(post_test_process_dict)
            if status['status'] == 0:
                self.failed(reason=status['logs'])
            else:
                self.passed(reason=status['logs'])

########################################################################################################
# TC: Mapping case - TC47 -ISSU
# Verify LXC ISSD NR3F .upg to .bin with port-security
# VPC port-channel and orphan, Standalone, Standalone + FEX ST
########################################################################################################
class TC_VXLAN_PS_035_Access(aetest.Testcase):
    @aetest.test
    def test_setup(self, testscript, testbed, steps):
        sa_vtep = testscript.parameters['LEAF-3']
        prim_vtep = testscript.parameters['LEAF-1']
        sec_vtep = testscript.parameters['LEAF-2']
        leaf1_mac = str(testscript.parameters['PORTSEC_Dict']['vpc_static_mac'])
        leaf2_mac = str(testscript.parameters['PORTSEC_Dict']['vpc_static_mac1'])
        prim_vtep_if = str(testscript.parameters['intf_LEAF_1_1_to_IXIA'])
        sa_vtep_if = str(testscript.parameters['intf_LEAF_3_to_IXIA'])
        fex_vtep_if = str(testscript.parameters['intf_LEAF_1_FEX_to_IXIA'])
        src_vlan = int(testscript.parameters['LEAF_1_Orphan1_TGEN_dict']['vlan_id'])
        
        new_config = '''switchport port-security aging type inactivity
                        switchport port-security mac-address sticky
                        switchport port-security violation restrict'''
        with steps.start("Configure Port-Security on Primary VTEP Orphan"):
            if not config_interface_ps([prim_vtep], prim_vtep_if, log, new_config):
                self.errored('Exception occurred while configuring port security', goto=['common_cleanup'])
        
        with steps.start("Configure Port-Security on Standalone VTEP"):
            if not config_interface_ps([sa_vtep], sa_vtep_if, log, new_config):
                self.errored('Exception occurred while configuring port security', goto=['common_cleanup'])
        
        new_config = '''switchport port-security aging type inactivity
                        switchport port-security violation restrict'''
        with steps.start("Configure Port-Security on Leaf-1 FEX - FEX port of VTEP"):
            if not config_interface_ps([prim_vtep], fex_vtep_if, log, new_config):
                self.errored('Exception occurred while configuring port security', goto=['common_cleanup'])

        new_config = '''switchport port-security aging type inactivity
                        switchport port-security violation restrict
                        switchport port-security mac-address {mac}'''.format(mac=leaf1_mac)
        with steps.start("Configure Port-Security on VPC Primary/Secondary - Static"):
            if not config_interface_ps([prim_vtep, sec_vtep], 'port-channel 11', log, new_config):
                self.errored('Exception occurred while configuring port security', goto=['common_cleanup'])
        
        log.info("Waiting {}secs for interface to come up".format(config_time))
        time.sleep(config_time)
        display_configs(testscript)

    # Flap Uplink on VPC primary and standalone
    @aetest.test
    def verify_issd_standalone(self, testscript, testbed, steps):
        sa_vtep         = testscript.parameters['LEAF-3']
        prim_vtep       = testscript.parameters['LEAF-1']
        sec_vtep        = testscript.parameters['LEAF-2']
        sa_vtep_if      = str(testscript.parameters['intf_LEAF_3_to_IXIA'])
        prim_vtep_if    = str(testscript.parameters['intf_LEAF_1_1_to_IXIA'])
        sa_mac          = str(testscript.parameters['PORTSEC_Dict']['sa_mac'])
        prim_mac        = str(testscript.parameters['PORTSEC_Dict']['prim_orphan_mac'])
        ixNetwork       = testscript.parameters['ixNetwork']
        p1_handle       = testscript.parameters['orphan1_handle']
        p2_handle       = testscript.parameters['sa_handle']
        issd_image      = testscript.parameters['abs_base_image']
        
        with steps.start("Starting hosts..."):
            p1_handle.Start()
            p2_handle.Start()
        
        log.info('Waiting {}secs to start 1025 hosts'.format(host_start_time))
        time.sleep(host_start_time)
        
        stream1 = ixNetwork.Traffic.TrafficItem.find(Name='Access Orphan To Standalone')
        stream1.StartStatelessTraffic()
        log.info('Waiting {}secs to start the traffic'.format(traffic_start_time))
        time.sleep(traffic_start_time)
        
        with steps.start('Doing ISSD and verifying cores/errors after ISSD'):    
            # Establish dialogs for running ISSD command
            dialog = Dialog([
                Statement(pattern=r'Do you want to continue with the installation \(y/n\)\?',
                        action='sendline(y)',
                        loop_continue=True,
                        continue_timer=True),
            ])
            
            # Create ISSD command
            issd_cmd = 'install all nxos bootflash:' + str(issd_image)
            
            # Perform ISSD
            result, output = sa_vtep.reload(reload_command=issd_cmd, prompt_recovery=True, dialog=dialog, timeout=2000, return_output=True)
            output_split = list(filter(None, output.split('\n')))
            fail_flag = []
            fail_logs = '\n'
        
            # Process logs for any failure reasons
            for log_line in output_split:
                if re.search('CRASHED|CPU Hog|malloc|core dump|mts_send|redzone', log_line, re.I):
                    if 'Upgrade can no longer be aborted' in log_line:
                        continue
                    else:
                        fail_flag.append(0)
                        fail_logs += str(log_line) + '\n'
            
            # Reporting
            if 0 in fail_flag:
                self.failed(reason=fail_logs)
            else:
                self.passed(reason="Upgrade successful")
                    
            log.info("Waiting for 60 sec for the topology to come UP")
            time.sleep(60)

        with steps.start("checking NVE peers are up"):
            # Verify NVE Peers with new IP
            nvePeerData = verifyEVPNNvePeers(testscript.parameters['leavesDict'])

            if nvePeerData['result'] is 1:
                log.info("PASS : Successfully verified NVE Peering\n\n")
            else:
                log.error("FAIL : Failed to verify NVE Peering\n\n")
                self.failed(reason=nvePeerData['log'])
        
        with steps.start("Checking mac relearning on standalone and remote after ISSU"):
            if not verify_port_sec_addr_count(sa_vtep, sa_vtep_if, 1025, 'STICKY'):
                log.error("DYNAMIC Mac learning failed")
                self.failed("DYNAMIC Mac learning failed")

            if not verify_secure_mac_on_vteps(sa_vtep, '1002', 1025, sa_mac, 'secure'):
                log.error("Mac learning failed on Standalone")
                self.failed("Mac learning failed on Standalone")

            if not verify_secure_mac_on_vteps(prim_vtep, '1002', 1025, sa_mac):
                log.error("DYNAMIC Mac learning failed on remote vtep(leaf1)")
                self.failed("DYNAMIC Mac learning failed on remote vtep(leaf1)")

            if not verify_secure_mac_on_vteps(sec_vtep, '1002', 1025, sa_mac):
                log.error("DYNAMIC Mac learning failed on remote vtep(leaf2)")
                self.failed("DYNAMIC Mac learning failed on remote vtep(leaf2)")

        with steps.start("Checking Mac relearning on vpc vteps and remote vtep after no shut"):
            if not verify_port_sec_addr_count(prim_vtep, prim_vtep_if, 1025, 'STICKY'):
                log.error("DYNAMIC Mac learning failed")
                self.failed("DYNAMIC Mac learning failed")

            if not verify_secure_mac_on_vteps(prim_vtep, '1001', 1025, prim_mac, 'secure'):
                log.error("Mac learning failed on primary")
                self.failed("Mac learning failed on primary")

            if not verify_secure_mac_on_vteps(sec_vtep, '1001', 1025, prim_mac, 'secure'):
                log.error("DYNAMIC Mac learning failed on remote vtep(leaf2)")
                self.failed("DYNAMIC Mac learning failed on remote vtep(leaf2)")

            if not verify_secure_mac_on_vteps(sa_vtep, '1001', 1025, prim_mac):
                log.error("Mac learning failed on standalone")
                self.failed("Mac learning failed on standalone")

        stream1.StopStatelessTraffic()
        log.info('Waiting {}secs to stop the traffic'.format(traffic_stop_time))
        time.sleep(traffic_stop_time)
        
        with steps.start("Verify Steady State after ISSD"):
            if VerifyTraffic("Test_SA_Access_ISSD", testscript, traffic_item='Access Orphan To Standalone'):
                log.info('Verify traffic success after ISSD')
            else:
                self.failed('Verify traffic failed after ISSD')

        with steps.start('Verify Learned mac address consistency between hardware and software'):
            if verify_mac_cc_between_hardware_software([prim_vtep, sec_vtep, sa_vtep]):
                self.passed('MAC CC success')
            else:
                self.failed('MAC CC failed')

    @aetest.test
    def verify_issd_primary(self, testscript, testbed, steps):
        sa_vtep         = testscript.parameters['LEAF-3']
        prim_vtep       = testscript.parameters['LEAF-1']
        sec_vtep        = testscript.parameters['LEAF-2']
        prim_vpc_mac    = str(testscript.parameters['PORTSEC_Dict']['prim_vpc_mac'])
        ixNetwork       = testscript.parameters['ixNetwork']
        p1_handle       = testscript.parameters['vpc_handle']
        p2_handle       = testscript.parameters['sa_handle']
        issd_image      = testscript.parameters['abs_base_image']
        
        with steps.start("Starting hosts.."):
            p1_handle.Start()
            p2_handle.Start()
        
        log.info('Waiting {}secs to start 1025 hosts'.format(host_start_time))
        time.sleep(host_start_time)
    
        stream1 = ixNetwork.Traffic.TrafficItem.find(Name='Access VPC To Standalone')
        stream1.StartStatelessTraffic()
        log.info('Waiting {}secs to start the traffic'.format(traffic_start_time))
        time.sleep(traffic_start_time)
        
        with steps.start("Checking mac re-learning on local and remote vtep"):
            if not verify_port_sec_addr_count(prim_vtep, 'port-channel 11', 1, 'STATIC'):
                log.error("STATIC Mac learning failed")
                self.failed("STATIC Mac learning failed")
        
            if not verify_port_sec_addr_count(prim_vtep, 'port-channel 11', 1024, 'DYNAMIC'):
                log.error("DYNAMIC Mac learning failed")
                self.failed("DYNAMIC Mac learning failed")

            if not verify_port_sec_addr_count(sec_vtep, 'port-channel 11', 1, 'STATIC'):
                log.error("STATIC Mac learning failed")
                self.failed("STATIC Mac learning failed")
        
            if not verify_port_sec_addr_count(sec_vtep, 'port-channel 11', 1024, 'DYNAMIC'):
                log.error("DYNAMIC Mac learning failed")
                self.failed("DYNAMIC Mac learning failed")
            
            if not verify_secure_mac_on_vteps(prim_vtep, '1001', 1025, prim_vpc_mac, 'secure'):
                log.error("Mac learning failed on primary")
                self.failed("Mac learning failed on primary")

            if not verify_secure_mac_on_vteps(sec_vtep, '1001', 1025, prim_vpc_mac, 'secure'):
                log.error("Mac learning failed on primary")
                self.failed("Mac learning failed on primary")
                
            if not verify_secure_mac_on_vteps(sa_vtep, '1001', 1025, prim_vpc_mac):
                log.error("Mac learning failed on standalone")
                self.failed("Mac learning failed on standalone")
        
        # Establish dialogs for running ISSD command
        dialog = Dialog([
            Statement(pattern=r'Do you want to continue with the installation \(y/n\)\?',
                      action='sendline(y)',
                      loop_continue=True,
                      continue_timer=True),
        ])
        
        with steps.start("Doing ISSD and verifying core/errors after ISSD"):
            primary_handle = get_vpc_primary_secondary_device([prim_vtep, sec_vtep])
            # Create ISSD command
            issd_cmd = 'install all nxos bootflash:' + str(issd_image)
            
            # Perform ISSD
            result, output = primary_handle.reload(reload_command=issd_cmd, prompt_recovery=True, 
                                                   dialog=dialog, timeout=2000, return_output=True)
            output_split = list(filter(None, output.split('\n')))
            fail_flag = []
            fail_logs = '\n'
            
            # Process logs for any failure reasons
            for log_line in output_split:
                if re.search('CRASHED|CPU Hog|malloc|core dump|mts_send|redzone', log_line, re.I):
                    if 'Upgrade can no longer be aborted' in log_line:
                        continue
                    else:
                        fail_flag.append(0)
                        fail_logs += str(log_line) + '\n'
            
            # Reporting
            if 0 in fail_flag:
                self.failed(reason=fail_logs)
            else:
                self.passed(reason="Upgrade successful")
                        
            log.info("Waiting for 100 sec for the topology to come UP")
            time.sleep(100)
        
        with steps.start("checking NVE peers are up"):
            # Verify NVE Peers with new IP
            nvePeerData = verifyEVPNNvePeers(testscript.parameters['leavesDict'])

            if nvePeerData['result'] is 1:
                log.info("PASS : Successfully verified NVE Peering\n\n")
            else:
                log.error("FAIL : Failed to verify NVE Peering\n\n")
                self.failed(reason=nvePeerData['log'])
    
        with steps.start("Checking mac learning on local and remote vtep"):
            if not verify_port_sec_addr_count(prim_vtep, 'port-channel 11', 1, 'STATIC'):
                log.error("STATIC Mac learning failed")
                self.failed("STATIC Mac learning failed")
        
            if not verify_port_sec_addr_count(prim_vtep, 'port-channel 11', 1024, 'DYNAMIC'):
                log.error("DYNAMIC Mac learning failed")
                self.failed("DYNAMIC Mac learning failed")

            if not verify_port_sec_addr_count(sec_vtep, 'port-channel 11', 1, 'STATIC'):
                log.error("STATIC Mac learning failed")
                self.failed("STATIC Mac learning failed")
        
            if not verify_port_sec_addr_count(sec_vtep, 'port-channel 11', 1024, 'DYNAMIC'):
                log.error("DYNAMIC Mac learning failed")
                self.failed("DYNAMIC Mac learning failed")
            
            if not verify_secure_mac_on_vteps(prim_vtep, '1001', 1025, prim_vpc_mac, 'secure'):
                log.error("Mac learning failed on primary")
                self.failed("Mac learning failed on primary")

            if not verify_secure_mac_on_vteps(sec_vtep, '1001', 1025, prim_vpc_mac, 'secure'):
                log.error("Mac learning failed on primary")
                self.failed("Mac learning failed on primary")
                
            if not verify_secure_mac_on_vteps(sa_vtep, '1001', 1025, prim_vpc_mac):
                log.error("Mac learning failed on standalone")
                self.failed("Mac learning failed on standalone")

        stream1.StopStatelessTraffic()
        log.info('Waiting {}secs to stop the traffic'.format(traffic_stop_time))
        time.sleep(traffic_stop_time)

        with steps.start("Verify Steady State"):
            if VerifyTraffic("Test_Primary_ISSD_Access", testscript, traffic_item='Access VPC To Standalone'):
                log.info('Verify Traffic Success after ISSD')
            else:
                self.failed('Verify Traffic Failed after ISSD')

        with steps.start('Verify Learned mac address consistency between hardware and software'):
            if verify_mac_cc_between_hardware_software([prim_vtep, sec_vtep, sa_vtep]):
                self.passed('MAC CC success')
            else:
                self.failed('MAC CC failed')

    @aetest.test
    def verify_issd_newprimary(self, testscript, testbed, steps):
        sa_vtep         = testscript.parameters['LEAF-3']
        prim_vtep       = testscript.parameters['LEAF-1']
        sec_vtep        = testscript.parameters['LEAF-2']
        prim_vpc_mac    = str(testscript.parameters['PORTSEC_Dict']['prim_vpc_mac'])
        ixNetwork       = testscript.parameters['ixNetwork']
        p1_handle       = testscript.parameters['vpc_handle']
        p2_handle       = testscript.parameters['sa_handle']
        issd_image      = testscript.parameters['abs_base_image']
        
        with steps.start("Starting hosts.."):
            p1_handle.Start()
            p2_handle.Start()
        
        log.info('Waiting {}secs to start 1025 hosts'.format(host_start_time))
        time.sleep(host_start_time)
    
        stream1 = ixNetwork.Traffic.TrafficItem.find(Name='Access VPC To Standalone')
        stream1.StartStatelessTraffic()
        log.info('Waiting {}secs to start the traffic'.format(traffic_start_time))
        time.sleep(traffic_start_time)
        
        with steps.start("Checking mac re-learning on local and remote vtep"):
            if not verify_port_sec_addr_count(prim_vtep, 'port-channel 11', 1, 'STATIC'):
                log.error("STATIC Mac learning failed")
                self.failed("STATIC Mac learning failed")
        
            if not verify_port_sec_addr_count(prim_vtep, 'port-channel 11', 1024, 'DYNAMIC'):
                log.error("DYNAMIC Mac learning failed")
                self.failed("DYNAMIC Mac learning failed")

            if not verify_port_sec_addr_count(sec_vtep, 'port-channel 11', 1, 'STATIC'):
                log.error("STATIC Mac learning failed")
                self.failed("STATIC Mac learning failed")
        
            if not verify_port_sec_addr_count(sec_vtep, 'port-channel 11', 1024, 'DYNAMIC'):
                log.error("DYNAMIC Mac learning failed")
                self.failed("DYNAMIC Mac learning failed")
            
            if not verify_secure_mac_on_vteps(prim_vtep, '1001', 1025, prim_vpc_mac, 'secure'):
                log.error("Mac learning failed on primary")
                self.failed("Mac learning failed on primary")

            if not verify_secure_mac_on_vteps(sec_vtep, '1001', 1025, prim_vpc_mac, 'secure'):
                log.error("Mac learning failed on primary")
                self.failed("Mac learning failed on primary")
                
            if not verify_secure_mac_on_vteps(sa_vtep, '1001', 1025, prim_vpc_mac):
                log.error("Mac learning failed on standalone")
                self.failed("Mac learning failed on standalone")
        
        # Establish dialogs for running ISSD command
        dialog = Dialog([
            Statement(pattern=r'Do you want to continue with the installation \(y/n\)\?',
                      action='sendline(y)',
                      loop_continue=True,
                      continue_timer=True),
        ])
        
        with steps.start("Doing ISSD and verifying core/errors after ISSD"):
            primary_handle = get_vpc_primary_secondary_device([prim_vtep, sec_vtep])
            # Create ISSD command
            issd_cmd = 'install all nxos bootflash:' + str(issd_image)
            
            # Perform ISSD
            result, output = primary_handle.reload(reload_command=issd_cmd, prompt_recovery=True, 
                                                   dialog=dialog, timeout=2000, return_output=True)
            output_split = list(filter(None, output.split('\n')))
            fail_flag = []
            fail_logs = '\n'
            
            # Process logs for any failure reasons
            for log_line in output_split:
                if re.search('CRASHED|CPU Hog|malloc|core dump|mts_send|redzone', log_line, re.I):
                    if 'Upgrade can no longer be aborted' in log_line:
                        continue
                    else:
                        fail_flag.append(0)
                        fail_logs += str(log_line) + '\n'
            
            # Reporting
            if 0 in fail_flag:
                self.failed(reason=fail_logs)
            else:
                self.passed(reason="Upgrade successful")
                        
            log.info("Waiting for 100 sec for the topology to come UP")
            time.sleep(100)
        
        with steps.start("checking NVE peers are up"):
            # Verify NVE Peers with new IP
            nvePeerData = verifyEVPNNvePeers(testscript.parameters['leavesDict'])

            if nvePeerData['result'] is 1:
                log.info("PASS : Successfully verified NVE Peering\n\n")
            else:
                log.error("FAIL : Failed to verify NVE Peering\n\n")
                self.failed(reason=nvePeerData['log'])
    
        with steps.start("Checking mac learning on local and remote vtep"):
            if not verify_port_sec_addr_count(prim_vtep, 'port-channel 11', 1, 'STATIC'):
                log.error("STATIC Mac learning failed")
                self.failed("STATIC Mac learning failed")
        
            if not verify_port_sec_addr_count(prim_vtep, 'port-channel 11', 1024, 'DYNAMIC'):
                log.error("DYNAMIC Mac learning failed")
                self.failed("DYNAMIC Mac learning failed")

            if not verify_port_sec_addr_count(sec_vtep, 'port-channel 11', 1, 'STATIC'):
                log.error("STATIC Mac learning failed")
                self.failed("STATIC Mac learning failed")
        
            if not verify_port_sec_addr_count(sec_vtep, 'port-channel 11', 1024, 'DYNAMIC'):
                log.error("DYNAMIC Mac learning failed")
                self.failed("DYNAMIC Mac learning failed")
            
            if not verify_secure_mac_on_vteps(prim_vtep, '1001', 1025, prim_vpc_mac, 'secure'):
                log.error("Mac learning failed on primary")
                self.failed("Mac learning failed on primary")

            if not verify_secure_mac_on_vteps(sec_vtep, '1001', 1025, prim_vpc_mac, 'secure'):
                log.error("Mac learning failed on primary")
                self.failed("Mac learning failed on primary")
                
            if not verify_secure_mac_on_vteps(sa_vtep, '1001', 1025, prim_vpc_mac):
                log.error("Mac learning failed on standalone")
                self.failed("Mac learning failed on standalone")

        stream1.StopStatelessTraffic()
        log.info('Waiting {}secs to stop the traffic'.format(traffic_stop_time))
        time.sleep(traffic_stop_time)

        with steps.start("Verify Steady State"):
            if VerifyTraffic("Test_New_Primary_ISSD_Access", testscript, 
                             traffic_item='Access VPC To Standalone'):
                log.info('Verify Traffic Success after ISSD')
            else:
                self.failed('Verify Traffic Failed after ISSD')

        with steps.start('Verify Learned mac address consistency between hardware and software'):
            if verify_mac_cc_between_hardware_software([prim_vtep, sec_vtep, sa_vtep]):
                self.passed('MAC CC success')
            else:
                self.failed('MAC CC failed')

    @aetest.test
    def check_fex_status(self, testscript, steps):
        prim_vtep = testscript.parameters['LEAF-1']
        with steps.start("checking FEX Online after ISSD"):
            i = 0
            result = False
            while i < 900:
                if check_fex_state(testscript, prim_vtep):
                    log.info('FEX is up')
                    result = True
                    break
                
                log.info('Sleeping for 120sec')
                time.sleep(150)
                i = i + 150
            
            if not result:
                log.error('After ISSD, FEX is not Online')
                self.failed('After ISSD, FEX is not online')

    @aetest.test
    def test_cleanup(self, testscript, testbed, steps):
        sa_vtep = testscript.parameters['LEAF-3']
        prim_vtep = testscript.parameters['LEAF-1']
        sec_vtep = testscript.parameters['LEAF-2']
        prim_vtep_if = str(testscript.parameters['intf_LEAF_1_1_to_IXIA'])
        sa_vtep_if = str(testscript.parameters['intf_LEAF_3_to_IXIA'])
        leaf1_mac = str(testscript.parameters['PORTSEC_Dict']['vpc_static_mac'])
        leaf2_mac = str(testscript.parameters['PORTSEC_Dict']['vpc_static_mac1'])
        fex_vtep_if = str(testscript.parameters['intf_LEAF_1_FEX_to_IXIA'])
        src_vlan = int(testscript.parameters['LEAF_1_Orphan1_TGEN_dict']['vlan_id'])
        ixNetwork   = testscript.parameters['ixNetwork']
        
        with steps.start("Stopping all hosts..."):
            ixNetwork.StopAllProtocols()

        stream1 = ixNetwork.Traffic.TrafficItem.find(Name='Access Orphan To Standalone')
        stream1.StopStatelessTraffic()
        stream2 = ixNetwork.Traffic.TrafficItem.find(Name='Access VPC To Standalone')
        stream2.StopStatelessTraffic()
        stream3 = ixNetwork.Traffic.TrafficItem.find(Name='Access FEX To Standalone')
        stream3.StopStatelessTraffic()

        log.info('Waiting {}secs to stop the hosts'.format(traffic_stop_time))
        time.sleep(traffic_stop_time)
        
        new_config = '''no switchport port-security aging type inactivity
                        no switchport port-security violation restrict
                        no switchport port-security mac-address sticky'''
    
        with steps.start("UnConfigure Port-Security on Primary VTEP Orphan"):
            if not unconfig_interface_ps([prim_vtep], prim_vtep_if, log, new_config):
                self.errored('Exception occurred while configuring port security', goto=['common_cleanup'])
        
        with steps.start("UnConfigure Port-Security on Standalone VTEP"):
            if not unconfig_interface_ps([sa_vtep], sa_vtep_if, log, new_config):
                self.errored('Exception occurred while configuring port security', goto=['common_cleanup'])
        
        new_config = '''no switchport port-security aging type inactivity
                      no switchport port-security violation restrict
                      no switchport port-security mac-address {mac}'''.format(mac=leaf1_mac)
        with steps.start("UnConfigure Port-Security on VPC Primary/Secondary - Static"):
            
            if not unconfig_interface_ps([prim_vtep, sec_vtep], 'port-channel 11', log, new_config):
                self.errored('Exception occurred while configuring port security', goto=['common_cleanup'])
        
        new_config = '''no switchport port-security aging type inactivity
                        no switchport port-security violation restrict'''
        with steps.start("UnConfigure Port-Security on Leaf-1 FEX - FEX port of VTEP"):
            if not unconfig_interface_ps([prim_vtep], fex_vtep_if, log, new_config):
                self.errored('Exception occurred while configuring port security', goto=['common_cleanup'])

        log.info("Waiting {}secs for interface to come up".format(config_time))
        time.sleep(config_time)
        
        with steps.start("Verifying MTS leak.."):
            if verify_mts_leak([prim_vtep, sec_vtep, sa_vtep], log):
                log.info('MTS Leak verification success')
            else:
                self.failed('MTS Leak verification failed')

        with steps.start("Verifying Cores and Log Errors"):
            status = infraVerify.postTestVerification(post_test_process_dict)
            if status['status'] == 0:
                self.failed(reason=status['logs'])
            else:
                self.passed(reason=status['logs'])

class common_cleanup(aetest.CommonCleanup):
    @aetest.subsection
    def unconfigure_vteps(self, testscript, testbed, steps):
        sa_vtep         = testscript.parameters['LEAF-3']
        prim_vtep       = testscript.parameters['LEAF-1']
        sec_vtep        = testscript.parameters['LEAF-2']
        vlan            = int(testscript.parameters['LEAF_1_Orphan1_TGEN_dict']['vlan_id'])
        vlan1           = int(testscript.parameters['LEAF_3_TGEN_dict']['vlan_id'])
        VRF_string      = str(testscript.parameters['forwardingSysDict']['VRF_string'])
        VRF_id_start    = str(testscript.parameters['forwardingSysDict']['VRF_id_start'])
        vrf_id 			= VRF_string + VRF_id_start
        as_num 			= str(testscript.parameters['forwardingSysDict']['BGP_AS_num'])
        
        with steps.start("Remove interfaces"):
            try:
                prim_vtep.configure('no interface port-channel 11')
                sec_vtep.configure('no interface port-channel 11')
            except Exception as error:
                    log.debug("Unable to configure - Encountered Exception " + str(error))
                    self.failed("Unable to configure - Encountered Exception " + str(error))

        with steps.start("Remove VLANs"):
            try:
                prim_vtep.configure('no vlan {} ; no vlan {}'.format(vlan, vlan1))
                sec_vtep.configure('no vlan {} ; no vlan {}'.format(vlan, vlan1))
                sa_vtep.configure('no vlan {} ; no vlan {}'.format(vlan, vlan1))
            except Exception as error:
                    log.debug("Unable to configure - Encountered Exception " + str(error))
                    self.failed("Unable to configure - Encountered Exception " + str(error))
                    
        with steps.start("Remove VRF"):
            try:
                prim_vtep.configure('no vrf context {}'.format(vrf_id))
                sec_vtep.configure('no vrf context {}'.format(vrf_id))
                sa_vtep.configure('no vrf context {}'.format(vrf_id))
            except Exception as error:
                    log.debug("Unable to configure - Encountered Exception " + str(error))
                    self.failed("Unable to configure - Encountered Exception " + str(error))
        
        with steps.start("Remove NVE"):
            try:
                prim_vtep.configure('no interface nve 1')
                sec_vtep.configure('no interface nve 1')
                sa_vtep.configure('no interface nve 1')
            except Exception as error:
                    log.debug("Unable to configure - Encountered Exception " + str(error))
                    self.failed("Unable to configure - Encountered Exception " + str(error))
        
        with steps.start("Remove BGP"):
            try:
                prim_vtep.configure('no router bgp {}'.format(as_num))
                sec_vtep.configure('no router bgp {}'.format(as_num))
                sa_vtep.configure('no router bgp {}'.format(as_num))
            except Exception as error:
                    log.debug("Unable to configure - Encountered Exception " + str(error))
                    self.failed("Unable to configure - Encountered Exception " + str(error))
        
        with steps.start("Default interfaces - SPINE"):            
            try:
                testscript.parameters['SPINE'].configure('''
                    default interface ''' + str(testscript.parameters['intf_SPINE_to_LEAF_1']) + '''
                    default interface ''' + str(testscript.parameters['intf_SPINE_to_LEAF_2']) + '''
                    default interface ''' + str(testscript.parameters['intf_SPINE_to_LEAF_3']) + '''
                    default interface loopback10
                ''')
            except Exception as error:
                log.debug("Unable to configure - Encountered Exception " + str(error))
                self.failed('Exception occurred while configuring on SPINE', goto=['common_cleanup'])
        
        with steps.start("Default interfaces - LEAF-1"):
            try:
                testscript.parameters['LEAF-1'].configure('''
                default interface ''' + str(testscript.parameters['intf_LEAF_1_to_SPINE']) + '''
                default interface ''' + str(testscript.parameters['intf_LEAF_1_to_FAN3172']) + '''
                default interface port-channel ''' + str(testscript.parameters['LEAF_1_dict']['VPC_data']['VPC_ACC_po']) + '''
                default interface ''' + str(testscript.parameters['intf_LEAF_1_to_LEAF_2_1']) + '''
                default interface ''' + str(testscript.parameters['intf_LEAF_1_1_to_IXIA']) + '''
                default interface ''' + str(testscript.parameters['intf_LEAF_1_2_to_IXIA']) + '''
                default interface loopback10
                default interface loopback11
                default interface loopback12
            ''')
            except Exception as error:
                log.debug("Unable to configure - Encountered Exception " + str(error))
                self.errored('Exception occurred while configuring on LEAF-1', goto=['common_cleanup'])
        
        with steps.start("Default interfaces - LEAF-2"):
            try:
                testscript.parameters['LEAF-2'].configure('''
                default interface ''' + str(testscript.parameters['intf_LEAF_2_to_SPINE']) + '''
                default interface ''' + str(testscript.parameters['intf_LEAF_2_to_FAN3172']) + '''
                default interface port-channel ''' + str(testscript.parameters['LEAF_2_dict']['VPC_data']['VPC_ACC_po']) + '''
                default interface ''' + str(testscript.parameters['intf_LEAF_2_to_LEAF_1_1']) + '''
                default interface loopback10
                default interface loopback11
                default interface loopback12
            ''')
            except Exception as error:
                log.debug("Unable to configure - Encountered Exception " + str(error))
                self.errored('Exception occurred while configuring on LEAF-2', goto=['common_cleanup'])
        
        with steps.start("Default interfaces - LEAF-3"):
            try:
                testscript.parameters['LEAF-3'].configure('''
                default interface ''' + str(testscript.parameters['intf_LEAF_3_to_SPINE']) + '''
                default interface ''' + str(testscript.parameters['intf_LEAF_3_to_IXIA']) + '''
                default interface loopback10
                default interface loopback11
                default interface loopback12
            ''')

            except Exception as error:
                log.debug("Unable to configure - Encountered Exception " + str(error))
                self.errored('Exception occurred while configuring on LEAF-3', goto=['common_cleanup'])