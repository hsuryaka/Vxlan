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
import requests
import pdb
import sys
import ipaddress as ip
import numpy as np
from operator import itemgetter
import texttable
import difflib

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

from unicon.eal.dialogs import Statement, Dialog
###################################################################
###                  User Library Methods                       ###
###################################################################
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

    # Apply traffic, start traffic and wait for 60sec
    stream1 = ixNetwork.Traffic.TrafficItem.find(Name=traffic_item)
    #ixNetwork.Traffic.Apply()
    stream1.StartStatelessTraffic()

    # ixNetwork.Traffic.Start()
    time.sleep(100)

    # Clear stats
    ixNetwork.ClearStats()
    time.sleep(20)
    
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

    # Apply traffic, start traffic and wait for 60sec
    stream1 = ixNetwork.Traffic.TrafficItem.find(Name=traffic_item)
    stream1.StartStatelessTraffic()
    time.sleep(100)

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

def display_configs(testscript):
    sa_vtep         = testscript.parameters['LEAF-3']
    prim_vtep       = testscript.parameters['LEAF-1']
    sec_vtep        = testscript.parameters['LEAF-2']
    prim_vtep_if    = str(testscript.parameters['intf_LEAF_1_1_to_IXIA'])
    prim_vtep_if1   = str(testscript.parameters['intf_LEAF_1_2_to_IXIA'])
    sec_vtep_if     = str(testscript.parameters['intf_LEAF_2_to_IXIA'])
    sa_vtep_if      = str(testscript.parameters['intf_LEAF_3_to_IXIA'])
    
    
    prim_vtep.execute('show run interface {intf}'.format(intf=prim_vtep_if))
    prim_vtep.execute('show run interface {intf}'.format(intf=prim_vtep_if1))
    prim_vtep.execute('show run interface port-channel 11')
    sec_vtep.execute('show run interface port-channel 11')
    sec_vtep.execute('show run interface {intf}'.format(intf=sec_vtep_if))
    sa_vtep.execute('show run interface {intf}'.format(intf=sa_vtep_if))

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
        log.info("Successfully restarted process NVE")
    else:
        fail_flag.append(0)
        log.debug("Failed to restarted process NVE\n")
        
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

def basic_interface_configs(device_list, interface, vlan, mode):
    
    if mode == 'access':
        vlan_config = '''switchport mode access
                         switchport access vlan {vlan}
                         spanning-tree port type edge'''.format(vlan=vlan)
    else:
        vlan_config = '''switchport mode trunk
                         switchport trunk allowed vlan {vlan}
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

def verify_mac_on_vteps(device_list, vlan, expected_count, start_mac, type='dynamic'):
    cli = 'show mac address-table ' + 'vlan ' + vlan + ' | inc ' + type + ' | inc ' + start_mac +' | count '
    for device in device_list:
        no_of_mac_learn = device.execute(cli, timeout= 120)
        if int(no_of_mac_learn) != expected_count:
            log.info("Mac learned is not as expected count %r ", expected_count)
            return 0
    return 1

def get_vpc_role(switch):

        output=switch.execute("show vpc role").split("\n")
        for line in output:
            if "vPC role" in line:
                break
        
        role = line.split(':')[1].strip()
        if role != "":
            return role
        else:
            return 0
def increment_prefix_network(pref, count):
    size = 1 << (pref.network.max_prefixlen - pref.network.prefixlen)
    pref_lst = []
    for i in range(count):
        pref_lst.append(str((pref.ip+size*i)) + "/" + str(pref.network.prefixlen))
    return pref_lst

def nxapi_disable_pvmap(ip, user, passwd, intf, log):
    
    url             = 'http://{}/ins'.format(ip) 
    switchuser      = user
    switchpassword  = passwd
    
    myheaders={'content-type':'application/json'}
    cli1    = 'interface {}'.format(intf)
    cli2    = 'no switchport vlan mapping all'
    cli3    = 'no switchport vlan mapping enable'
    payload = {
                "ins_api": {
                "version": "1.0",
                "type": "cli_conf",
                "chunk": "0",
                "sid": "sid",
                "input": "{} ; {} ; {}".format(cli1, cli2, cli3),
                "output_format": "json"
                }
            }
    print(payload)
    print(url)
    response = requests.post(url,data=json.dumps(payload), headers=myheaders,auth=(switchuser,switchpassword)).json()
    output = json.dumps(response, indent=4, sort_keys=True)
    log.info('NXAPI output:\n{}'.format(output))

def nxapi_validate_disable_pvmap(device, ip, user, passwd, intf, log):
    url             = 'http://{}/ins'.format(ip) 
    switchuser      = user
    switchpassword  = passwd
    
    myheaders={'content-type':'application/json'}
    cli1    = "show inter {} vlan mapping".format(intf)
    payload = {
                "ins_api": {
                "version": "1.0",
                "type": "cli_show",
                "chunk": "0",
                "sid": "sid",
                "input": "{}".format(cli1),
                "output_format": "json"
                }
            }
    print(payload)
    print(url)
    response = requests.post(url,data=json.dumps(payload), headers=myheaders,auth=(switchuser,switchpassword)).json()
    json_output = json.dumps(response, indent=4, sort_keys=True)
    log.info('NXAPI output:\n{}'.format(json_output))
    
    cli_output = ''
    cli_output = device.execute('show run inter {} | sec mapping | count'.format(intf))
    print(cli_output, json_output)
    if not re.search('\"body\"\s*:\s*\"\"', json_output) or int(cli_output) != 0:
        log.error('PVMAP disable through nxapi failed')
        return False
    
    return True

def nxapi_enable_pvmap(testscript, device, ip, user, passwd, intf, log):
    
    url             = 'http://{}/ins'.format(ip) 
    switchuser      = user
    switchpassword  = passwd
    
    if device == 'Orphan1' or device == 'VPC':
        vlan            = int(testscript.parameters['LEAF_1_Orphan1_TGEN_dict']['vlan_id'])
        vlan1           = int(testscript.parameters['LEAF_1_Orphan1_TGEN_dict']['vlan_id1'])
    else:
        vlan            = int(testscript.parameters['LEAF_3_TGEN_dict']['vlan_id'])
        vlan1           = int(testscript.parameters['LEAF_3_TGEN_dict']['vlan_id1'])

    myheaders={'content-type':'application/json'}
    cli1 = 'interface {}'.format(intf)
    cli2 = 'switchport vlan mapping enable'
    cli3 = 'switchport vlan mapping {} {}'.format(vlan1, vlan)
    payload = {
                "ins_api": {
                "version": "1.0",
                "type": "cli_conf",
                "chunk": "0",
                "sid": "sid",
                "input": "{} ; {} ; {}".format(cli1, cli2, cli3),
                "output_format": "json"
                }
            }
    response = requests.post(url,data=json.dumps(payload), headers=myheaders,auth=(switchuser,switchpassword)).json()
    output = json.dumps(response, indent=4, sort_keys=True)
    log.info('NXAPI output:\n{}'.format(output))

def nxapi_validate_enable_pvmap(testscript, device, ip, user, passwd, intf, log):
    url             = 'http://{}/ins'.format(ip) 
    switchuser      = user
    switchpassword  = passwd
    
    if device == 'Orphan1' or device == 'VPC':
        vlan2   = int(testscript.parameters['LEAF_1_Orphan1_TGEN_dict']['vlan_id'])
        vlan1   = int(testscript.parameters['LEAF_1_Orphan1_TGEN_dict']['vlan_id1'])
    else:
        vlan2   = int(testscript.parameters['LEAF_3_TGEN_dict']['vlan_id'])
        vlan1   = int(testscript.parameters['LEAF_3_TGEN_dict']['vlan_id1'])

    myheaders={'content-type':'application/json'}
    cli1    = "show inter {} vlan mapping".format(intf)
    payload = {
                "ins_api": {
                "version": "1.0",
                "type": "cli_show",
                "chunk": "0",
                "sid": "sid",
                "input": "{}".format(cli1),
                "output_format": "json"
                }
            }
    print(payload)
    print(url)
    response = requests.post(url,data=json.dumps(payload), headers=myheaders,auth=(switchuser,switchpassword)).json()
    json_output = json.dumps(response, indent=4, sort_keys=True)
    log.info('NXAPI output:\n{}'.format(json_output))
    outp1 = re.search('\"orig-vlan-id\"\s*:\s*\"{}\"'.format(vlan1), json_output)
    outp2 = re.search('\"xlt-vlan-id\"\s*:\s*\"{}\"'.format(vlan2), json_output)
    if not outp1 or not outp2:
        log.error('PVMAP enable through nxapi failed for {}'.format(intf))
        return False
    
    return True

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
    
                interface loopback11
                  ipv6 address ''' + str(leaf1_data['NVE_data']['VTEP_IPV6']) + '''/128
                  ipv6 router ospfv3 ''' + str(forwardingSysDict['OSPF_AS']) + ''' area 0.0.0.0
                
                interface loopback12
                  ipv6 address ''' + str(leaf1_data['NVE_data']['VPC_VTEP_IPV6']) + '''/128
                  ipv6 router ospfv3 ''' + str(forwardingSysDict['OSPF_AS']) + ''' area 0.0.0.0        
        '''

        leaf2_config += '''
                interface loopback10
                  ipv6 address ''' + str(leaf2_data['loop10_ipv6']) + '''/128
                  ipv6 router ospfv3 ''' + str(forwardingSysDict['OSPF_AS']) + ''' area 0.0.0.0
    
                interface loopback11
                  ipv6 address ''' + str(leaf2_data['NVE_data']['VTEP_IPV6']) + '''/128
                  ipv6 router ospfv3 ''' + str(forwardingSysDict['OSPF_AS']) + ''' area 0.0.0.0
                
                interface loopback12
                  ipv6 address ''' + str(leaf2_data['NVE_data']['VPC_VTEP_IPV6']) + '''/128
                  ipv6 router ospfv3 ''' + str(forwardingSysDict['OSPF_AS']) + ''' area 0.0.0.0       
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

###################################################################
###                  GLOBAL VARIABLES                           ###
###################################################################

device_list     = []
traffic_stop_time = 10
traffic_start_time = 30
config_time = 60
host_start_time = 10
cr_file = 'pvmap_cr_file'

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
    def connecting_to_devices(self, testscript, testbed, uut_list, configurationFile, script_flags=None, abs_target_image=None):
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

        FAN = testscript.parameters['FAN'] = testbed.devices[uut_list['FAN']]

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

        testscript.parameters['abs_target_image'] = abs_target_image

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
        testscript.parameters['LEAF_3_TGEN_dict']           = configuration['LEAF_3_TGEN_data']
        testscript.parameters['LEAF_3_1_TGEN_dict']         = configuration['LEAF_3_1_TGEN_data']
        testscript.parameters['LEAF_2_TGEN_dict']           = configuration['LEAF_2_TGEN_data']
        testscript.parameters['FANOUT_TGEN_dict']           = configuration['FANOUT_TGEN_data']
        testscript.parameters['PVMAP_Dict']                 = configuration['PVMAP_Dict']
        testscript.parameters['forwardingSysDict']          = configuration['FWD_SYS_dict']
        testscript.parameters['leafVPCDictData']            = {LEAF_1 : configuration['LEAF_1_dict'], LEAF_2 : configuration['LEAF_2_dict']}
        testscript.parameters['leavesDictList']             = [configuration['LEAF_1_dict'], configuration['LEAF_2_dict'], configuration['LEAF_3_dict']]
        testscript.parameters['leavesDict']                 = {LEAF_1 : configuration['LEAF_1_dict'],
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

            if 'eor_flag' in script_flags.keys():
                testscript.parameters['script_flags']['eor_flag'] = script_flags['eor_flag']
            else:
                testscript.parameters['script_flags']['eor_flag'] = 0
        else:
            testscript.parameters['script_flags']['skip_device_config'] = 0
            testscript.parameters['script_flags']['skip_tgen_config'] = 0
            testscript.parameters['script_flags']['skip_device_cleanup'] = 0

        post_test_process_dict = {}
        post_test_process_dict = job_file_params['postTestArgs']
        post_test_process_dict['dut_list'] = [LEAF_1, LEAF_2, LEAF_3]

        log.info("===> Post Test Check Process Parameters")
        log.info(post_test_process_dict)

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
    
    # *****************************************************************************************************************************#

    @aetest.subsection
    def get_interfaces(self, testscript):
        """ common setup subsection: Getting required Connections for Test """

        log.info(banner("Retrieve the interfaces from Yaml file"))

        SPINE = testscript.parameters['SPINE']
        LEAF_1 = testscript.parameters['LEAF-1']
        LEAF_2 = testscript.parameters['LEAF-2']
        LEAF_3 = testscript.parameters['LEAF-3']
        FAN = testscript.parameters['FAN']
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
            featureConfigureFan_status = infraConfig.configureVerifyFeature(testscript.parameters['FAN'], fanOutFeatureList)
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
              default interface ''' + str(testscript.parameters['intf_LEAF_1_1_to_IXIA']) + '''
              interface ''' + str(testscript.parameters['intf_LEAF_1_1_to_IXIA']) + '''
                switchport
                switchport mode trunk
                switchport trunk allowed vlan ''' + str(testscript.parameters['LEAF_1_dict']['STATIC_IR_VNI_data']['l2_vlan_start']) + '''
                spanning-tree port type edge trunk
                no shutdown
              default interface ''' + str(testscript.parameters['intf_LEAF_1_2_to_IXIA']) + '''
              interface ''' + str(testscript.parameters['intf_LEAF_1_2_to_IXIA']) + '''
                switchport
                switchport mode trunk
                switchport trunk allowed vlan ''' + str(testscript.parameters['LEAF_1_dict']['STATIC_IR_VNI_data']['l2_vlan_start']) + '''
                spanning-tree port type edge trunk
                no shutdown
              vpc domain ''' + str(testscript.parameters['LEAF_1_dict']['VPC_data']['domain_id']) + '''
                no layer3 peer-router
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
              default interface ''' + str(testscript.parameters['intf_LEAF_2_to_LEAF_1_2']) + '''
              interface ''' + str(testscript.parameters['intf_LEAF_2_to_LEAF_1_2']) + '''
                switchport
                switchport mode trunk
                channel-group ''' + str(testscript.parameters['LEAF_1_dict']['VPC_data']['peer_link_po']) + ''' mode active
                no shutdown
              default interface ''' + str(testscript.parameters['intf_LEAF_1_1_to_IXIA']) + '''
              interface ''' + str(testscript.parameters['intf_LEAF_1_1_to_IXIA']) + '''
                switchport
                switchport mode trunk
                switchport trunk allowed vlan ''' + str(testscript.parameters['LEAF_1_dict']['STATIC_IR_VNI_data']['l2_vlan_start']) + '''
                spanning-tree port type edge trunk
                no shutdown
              default interface ''' + str(testscript.parameters['intf_LEAF_2_to_IXIA']) + '''
              interface ''' + str(testscript.parameters['intf_LEAF_2_to_IXIA']) + '''
                switchport
                switchport mode trunk
                switchport trunk allowed vlan ''' + str(testscript.parameters['LEAF_2_dict']['STATIC_IR_VNI_data']['l2_vlan_start']) + '''
                spanning-tree port type edge trunk
                no shutdown
              vpc domain ''' + str(testscript.parameters['LEAF_2_dict']['VPC_data']['domain_id']) + '''
                no layer3 peer-router
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
                switchport mode trunk
                switchport trunk allowed vlan ''' + str(testscript.parameters['LEAF_3_dict']['STATIC_IR_VNI_data']['l2_vlan_start']) + '''
                spanning-tree port type edge trunk
                no shutdown
          ''')

        except Exception as error:
            log.debug("Unable to configure - Encountered Exception " + str(error))
            self.errored('Exception occurred while configuring on LEAF-3', goto=['common_cleanup'])

    # *****************************************************************************************************************************#
    ''' Configure PVMAP'''
    @aetest.test
    def configure_pvmap(self, testscript, testbed, steps):
        prim_vtep = testscript.parameters['LEAF-1']
        sec_vtep = testscript.parameters['LEAF-2']
        sa_vtep = testscript.parameters['LEAF-3']
        fan_3172 = testscript.parameters['FAN']
        
        prim_vtep_if        = str(testscript.parameters['intf_LEAF_1_1_to_IXIA'])
        prim_vtep_if1       = str(testscript.parameters['intf_LEAF_1_2_to_IXIA'])
        sec_vtep_if         = str(testscript.parameters['intf_LEAF_2_to_IXIA'])
        sa_vtep_if          = str(testscript.parameters['intf_LEAF_3_to_IXIA'])
        leaf1_to_fan_if     = str(testscript.parameters['intf_LEAF_1_to_FAN3172'])
        leaf2_to_fan_if     = str(testscript.parameters['intf_LEAF_2_to_FAN3172'])
        fan_to_leaf1        = str(testscript.parameters['intf_FAN3172_to_LEAF_1'])
        fan_to_leaf2        = str(testscript.parameters['intf_FAN3172_to_LEAF_2'])
        fan_to_ixia         = str(testscript.parameters['intf_FAN3172_to_IXIA'])
        
        vlan1 = int(testscript.parameters['LEAF_1_Orphan1_TGEN_dict']['vlan_id'])
        vlan11 = int(testscript.parameters['LEAF_1_Orphan1_TGEN_dict']['vlan_id1'])
        vlan13 = int(testscript.parameters['LEAF_3_TGEN_dict']['vlan_id1'])
        vlan3 = int(testscript.parameters['LEAF_3_TGEN_dict']['vlan_id'])
        
        with steps.start("Default Orphan interface"):
            try:
                prim_vtep.configure('default interface {intf}'.format(intf=prim_vtep_if))
            except Exception as error:
                log.debug("Unable to configure - Encountered Exception " + str(error))
                self.errored('Exception occured during default interface configuration', 
                             goto=['common_cleanup'])

        with steps.start("Default Orphan2 interface"):
            try:
                prim_vtep.configure('default interface {intf}'.format(intf=prim_vtep_if1))
            except Exception as error:
                log.debug("Unable to configure - Encountered Exception " + str(error))
                self.errored('Exception occured during default interface configuration', 
                             goto=['common_cleanup'])
        
        with steps.start("Default Standalone interface"):
            try:
                sa_vtep.configure('default interface {intf}'.format(intf=sa_vtep_if))
            except Exception as error:
                log.debug("Unable to configure - Encountered Exception " + str(error))
                self.errored('Exception occured during default interface configuration', 
                             goto=['common_cleanup'])

        with steps.start("Default Secondary Orphan interface"):
            try:
                sec_vtep.configure('default interface {intf}'.format(intf=sec_vtep_if))
            except Exception as error:
                log.debug("Unable to configure - Encountered Exception " + str(error))
                self.errored('Exception occured during default interface configuration', 
                             goto=['common_cleanup'])
        
        with steps.start("Default Primary port-channel 11"):
            try:
                prim_vtep.configure('default interface port-channel 11')
            except Exception as error:
                log.debug("Unable to configure - Encountered Exception " + str(error))
                self.errored('Exception occured during default interface configuration', 
                             goto=['common_cleanup'])

        with steps.start("Default Secondary port-channel 11"):
            try:
                sec_vtep.configure('default interface port-channel 11')
            except Exception as error:
                log.debug("Unable to configure - Encountered Exception " + str(error))
                self.errored('Exception occured during default interface configuration', 
                             goto=['common_cleanup'])

        with steps.start("Default Primary To FAN interface"):
            try:
                prim_vtep.configure('default interface {intf}'.format(intf=leaf1_to_fan_if))
            except Exception as error:
                log.debug("Unable to configure - Encountered Exception " + str(error))
                self.errored('Exception occured during default interface configuration', 
                             goto=['common_cleanup'])

        with steps.start("Default Secondary To FAN interface"):
            try:
                sec_vtep.configure('default interface {intf}'.format(intf=leaf2_to_fan_if))
            except Exception as error:
                log.debug("Unable to configure - Encountered Exception " + str(error))
                self.errored('Exception occured during default interface configuration', 
                             goto=['common_cleanup'])
        
        with steps.start("Default FANOUT interface port-channel 200"):
            try:
                fan_3172.configure('default interface port-channel 200')
            except Exception as error:
                log.debug("Unable to configure - Encountered Exception " + str(error))
                self.errored('Exception occured during default interface configuration', 
                             goto=['common_cleanup'])
        
        with steps.start("Default FANOUT To Primary interface"):
            try:
                fan_3172.configure('default interface {intf}'.format(intf=fan_to_leaf1))
            except Exception as error:
                log.debug("Unable to configure - Encountered Exception " + str(error))
                self.errored('Exception occured during default interface configuration', 
                             goto=['common_cleanup'])
        
        with steps.start("Default FANOUT To Secondary interface"):
            try:
                fan_3172.configure('default interface {intf}'.format(intf=fan_to_leaf2))
            except Exception as error:
                log.debug("Unable to configure - Encountered Exception " + str(error))
                self.errored('Exception occured during default interface configuration', 
                             goto=['common_cleanup'])
        
        with steps.start("Default FANOUT To IXIA interface"):
            try:
                fan_3172.configure('default interface {intf}'.format(intf=fan_to_ixia))
            except Exception as error:
                log.debug("Unable to configure - Encountered Exception " + str(error))
                self.errored('Exception occured during default interface configuration', 
                             goto=['common_cleanup'])

        with steps.start("Configure Primary Orphan1 interface"):
            try:
                prim_vtep.configure('''interface {intf}
                                switchport
                                switchport mode trunk
                                switchport trunk allowed vlan {vlan},{vlan3}
                                spanning-tree port type edge trunk
                                switchport vlan mapping enable
                                switchport vlan mapping {vlan1} {vlan}
                                no shutdown
                            '''.format(intf=prim_vtep_if, vlan=vlan1, vlan1=vlan11, vlan3=vlan3))
            except Exception as error:
                log.debug("Unable to configure - Encountered Exception " + str(error))
                self.errored('Exception occurred while configuring PVMAP', 
                             goto=['common_cleanup'])
        
        with steps.start("Configure Primary Orphan2 interface"):
            try:
                prim_vtep.configure('''interface {intf}
                                switchport
                                switchport mode trunk
                                switchport trunk allowed vlan {vlan},{vlan3}
                                spanning-tree port type edge trunk
                                switchport vlan mapping enable
                                switchport vlan mapping {vlan1} {vlan}
                                no shutdown
                            '''.format(intf=prim_vtep_if1, vlan=vlan1, vlan1=vlan11, vlan3=vlan3))
            except Exception as error:
                log.debug("Unable to configure - Encountered Exception " + str(error))
                self.errored('Exception occurred while confinguring PVMAP', 
                             goto=['common_cleanup'])
            
        with steps.start("Configure Secondary Orphan interface"):
            try:
                sec_vtep.configure('''interface {intf}
                                switchport
                                switchport mode trunk
                                switchport trunk allowed vlan {vlan},{vlan3}
                                spanning-tree port type edge trunk
                                switchport vlan mapping enable
                                switchport vlan mapping {vlan1} {vlan}
                                no shutdown
                            '''.format(intf=sec_vtep_if, vlan=vlan1, vlan1=vlan11, vlan3=vlan3))
            except Exception as error:
                log.debug("Unable to configure - Encountered Exception " + str(error))
                self.errored('Exception occurred while configuring PVMAP', 
                             goto=['common_cleanup'])
         
        with steps.start("Configure Standalone interface"):
            try:
                sa_vtep.configure('''interface {intf}
                                switchport
                                switchport mode trunk
                                switchport trunk allowed vlan {vlan},{vlan3}
                                spanning-tree port type edge trunk
                                switchport vlan mapping enable
                                switchport vlan mapping {vlan1} {vlan3}
                                no shutdown
                            '''.format(intf=sa_vtep_if, vlan=vlan1, vlan1=vlan13, vlan3=vlan3))
            except Exception as error:
                log.debug("Unable to configure - Encountered Exception " + str(error))
                self.errored('Exception occurred while configuring PVMAP', 
                             goto=['common_cleanup'])

        with steps.start("Configure Primary port-channel 11 interface"):
            try:
                prim_vtep.configure('''interface port-channel 11
                                switchport
                                switchport mode trunk
                                switchport trunk allowed vlan {vlan},{vlan3}
                                spanning-tree port type edge trunk
                                switchport vlan mapping enable
                                switchport vlan mapping {vlan1} {vlan}
                                vpc 11
                                no shutdown
                            '''.format(vlan=vlan1, vlan1=vlan11, vlan3=vlan3))
            except Exception as error:
                log.debug("Unable to configure - Encountered Exception " + str(error))
                self.errored('Exception occurred while configuring PVMAP', 
                             goto=['common_cleanup'])
        
        with steps.start("Configure Secondary port-channel 11 interface"):
            try:
                sec_vtep.configure('''interface port-channel 11
                                switchport
                                switchport mode trunk
                                switchport trunk allowed vlan {vlan},{vlan3}
                                spanning-tree port type edge trunk
                                switchport vlan mapping enable
                                switchport vlan mapping {vlan1} {vlan}
                                vpc 11
                                no shutdown
                            '''.format(vlan=vlan1, vlan1=vlan11, vlan3=vlan3))
            except Exception as error:
                log.debug("Unable to configure - Encountered Exception " + str(error))
                self.errored('Exception occurred while configuring PVMAP', 
                             goto=['common_cleanup']) 

        with steps.start("Configure Primary to FANOUT interface"):
            try:
                prim_vtep.configure('''interface {intf}
                                switchport
                                switchport mode trunk
                                switchport trunk allowed vlan {vlan},{vlan3}
                                spanning-tree port type edge trunk
                                channel-group 11
                                no shutdown
                            '''.format(vlan=vlan1, intf=leaf1_to_fan_if, vlan3=vlan3))
            except Exception as error:
                log.debug("Unable to configure - Encountered Exception " + str(error))
                self.errored('Exception occurred while configuring PVMAP', 
                             goto=['common_cleanup']) 
        
        with steps.start("Configure VLANs on FAN"):
            try:
                sec_vtep.configure('''vlan {vlan} ; exit ; vlan {vlan1} ; vlan {vlan2}
                            '''.format(vlan=vlan1, vlan1=vlan11, vlan2=vlan13))
            except Exception as error:
                log.debug("Unable to configure - Encountered Exception " + str(error))
                self.errored('Exception occurred while configuring PVMAP', 
                             goto=['common_cleanup'])

        with steps.start("Configure Secondary to FANOUT interface"):
            try:
                sec_vtep.configure('''interface {intf}
                                switchport
                                switchport mode trunk
                                switchport trunk allowed vlan {vlan},{vlan3}
                                spanning-tree port type edge trunk
                                channel-group 11
                                no shutdown
                            '''.format(vlan=vlan1, intf=leaf2_to_fan_if, vlan3=vlan3))
            except Exception as error:
                log.debug("Unable to configure - Encountered Exception " + str(error))
                self.errored('Exception occurred while configuring PVMAP', 
                             goto=['common_cleanup'])
        
        with steps.start("Configure FANOUT port-channel 200 interface"):
            try:
                fan_3172.configure('''interface port-channel 200
                                switchport
                                switchport mode trunk
                                switchport trunk allowed vlan {vlan1}
                                spanning-tree port type edge trunk
                                no shutdown
                            '''.format(vlan1=vlan11))
            except Exception as error:
                log.debug("Unable to configure - Encountered Exception " + str(error))
                self.errored('Exception occurred while configuring PVMAP', 
                             goto=['common_cleanup']) 
        
        with steps.start("Configure FANOUT to Primary interface"):
            try:
                fan_3172.configure('''interface {intf}
                                switchport
                                switchport mode trunk
                                switchport trunk allowed vlan {vlan1}
                                spanning-tree port type edge trunk
                                channel-group 200
                                no shutdown
                            '''.format(intf=fan_to_leaf1, vlan1=vlan11))
            except Exception as error:
                log.debug("Unable to configure - Encountered Exception " + str(error))
                self.errored('Exception occurred while configuring PVMAP', 
                             goto=['common_cleanup']) 
        
        with steps.start("Configure FANOUT to Secondary interface"):
            try:
                fan_3172.configure('''interface {intf}
                                switchport
                                switchport mode trunk
                                switchport trunk allowed vlan {vlan1}
                                spanning-tree port type edge trunk
                                channel-group 200
                                no shutdown
                            '''.format(intf=fan_to_leaf2, vlan1=vlan11))
            except Exception as error:
                log.debug("Unable to configure - Encountered Exception " + str(error))
                self.errored('Exception occurred while configuring PVMAP', 
                             goto=['common_cleanup'])
        
        with steps.start("Configure FANOUT to IXIA interface"):
            try:
                fan_3172.configure('''interface {intf}
                                switchport
                                switchport mode trunk
                                switchport trunk allowed vlan {vlan},{vlan1},{vlan2}
                                spanning-tree port type edge trunk
                                no shutdown
                            '''.format(intf=fan_to_ixia, vlan=vlan1, vlan1=vlan11, vlan2=vlan13))
            except Exception as error:
                log.debug("Unable to configure - Encountered Exception " + str(error))
                self.errored('Exception occurred while configuring PVMAP', 
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
    @aetest.test
    def perform_copy_r_s(self, testscript):
        """ ENABLE_L2_TRM_CONFIGURATION test subsection: Save all configurations (copy r s) """

        log.info(banner("Performing Copy R S"))

        testscript.parameters['LEAF-1'].configure("copy r s", timeout=300)
        testscript.parameters['LEAF-2'].configure("copy r s", timeout=300)
        testscript.parameters['LEAF-3'].configure("copy r s", timeout=300)

        time.sleep(400)

#*****************************************************************************************************************************#
class VERIFY_NETWORK(aetest.Testcase):
    """This is description for my testcase one"""

    # =============================================================================================================================#
    @aetest.test
    def verify_vpc(self, testscript):
        """ VERIFY_NETWORK subsection: Verify VPC """
        LEAF_1 = testscript.parameters['LEAF-1']
        LEAF_2 = testscript.parameters['LEAF-2']

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
        """ VERIFY_NETWORK subsection: Verify NVE Peering """

        nvePeerData = verifyEVPNNvePeers(testscript.parameters['leavesDict'])

        if nvePeerData['result'] is 1:
            log.info("PASS : Successfully verified NVE Peering\n\n")
            self.passed(reason=nvePeerData['log'])
        else:
            log.error("FAIL : Failed to verify NVE Peering\n\n")
            self.failed(reason=nvePeerData['log'])

    # =============================================================================================================================#
    @aetest.test
    def verify_NVE_peering(self, testscript):
        """ VERIFY_NETWORK subsection: Verify NVE Peering """

        nvePeerData = verifyEVPNNvePeers(testscript.parameters['leavesDict'])

        if nvePeerData['result'] is 1:
            log.info("PASS : Successfully verified NVE Peering\n\n")
            self.passed(reason=nvePeerData['log'])
        else:
            log.error("FAIL : Failed to verify NVE Peering\n\n")
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
            
            for vport in ixNetwork.Vport.find():
                portType = vport.L1Config.CurrentType
                if portType == 'novusTenGigLan' or portType == 'ethernet':
                    capitalizedPortType = re.sub('([a-zA-Z])', lambda x: x.groups()[0].upper(), portType, 1)
                    getattr(vport.L1Config, capitalizedPortType).Media = 'fiber'

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
        vpc_port        = ixNetwork.Vport.find()[3]
        sec_port        = ixNetwork.Vport.find()[4]
        
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
        p4_handle = testscript.parameters['vpc_handle']
        p5_handle = testscript.parameters['sec_handle']
        
        P1_tgen_dict = testscript.parameters['LEAF_1_Orphan1_TGEN_dict']
        P2_tgen_dict = testscript.parameters['LEAF_3_TGEN_dict']
        P3_tgen_dict = testscript.parameters['LEAF_1_Orphan2_TGEN_dict']
        P4_tgen_dict = testscript.parameters['FANOUT_TGEN_dict']
        P5_tgen_dict = testscript.parameters['LEAF_2_TGEN_dict']
        
        log.info("Creating DeviceGroup For Orphan1")
        deviceGroup = p1_handle.DeviceGroup.add(Name='DG1', Multiplier=P1_tgen_dict['no_of_ints'])
        ethernet = deviceGroup.Ethernet.add(Name="Eth1", VlanCount="1")
        ethernet.Mac.Increment(start_value=P1_tgen_dict['mac'], step_value=P1_tgen_dict['mac_step'])
        ethernet.EnableVlans.Single(True)
        vlanObj = ethernet.Vlan.find()[0].VlanId.Increment(
            start_value=P1_tgen_dict['vlan_id1'], step_value=P1_tgen_dict['vlan_id_step']
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
        ethernet.EnableVlans.Single(True)
        vlanObj = ethernet.Vlan.find()[0].VlanId.Increment(
            start_value=P2_tgen_dict['vlan_id1'], step_value=P2_tgen_dict['vlan_id_step']
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
        ethernet.EnableVlans.Single(True)
        vlanObj = ethernet.Vlan.find()[0].VlanId.Increment(
            start_value=P3_tgen_dict['vlan_id1'], step_value=P3_tgen_dict['vlan_id_step']
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
            
        log.info("Creating DeviceGroup For FANOUT")
        deviceGroup = p4_handle.DeviceGroup.add(Name='DG4', Multiplier=P4_tgen_dict['no_of_ints'])
        ethernet = deviceGroup.Ethernet.add(Name="Eth4", VlanCount="1")
        ethernet.Mac.Increment(start_value=P4_tgen_dict['mac'], step_value=P4_tgen_dict['mac_step'])
        ethernet.EnableVlans.Single(True)
        vlanObj = ethernet.Vlan.find()[0].VlanId.Increment(
            start_value=P4_tgen_dict['vlan_id1'], step_value=P4_tgen_dict['vlan_id_step']
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
            log.error("Ixia DeviceGroup creation failed for FANOUT")

        log.info("Creating DeviceGroup Secondary Orphan")
        deviceGroup = p5_handle.DeviceGroup.add(Name='DG5', Multiplier=P5_tgen_dict['no_of_ints'])
        ethernet = deviceGroup.Ethernet.add(Name="Eth5", VlanCount="1")
        ethernet.Mac.Increment(start_value=P5_tgen_dict['mac'], step_value=P5_tgen_dict['mac_step'])
        ethernet.EnableVlans.Single(True)
        vlanObj = ethernet.Vlan.find()[0].VlanId.Increment(
            start_value=P5_tgen_dict['vlan_id1'], step_value=P5_tgen_dict['vlan_id_step']
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
            log.error("Ixia DeviceGroup creation failed for Secondary Orphan")

    @aetest.test
    def CreateTrafficItems(self, testscript, testbed, steps):
        prim_vtep = testscript.parameters['LEAF-1']
        sec_vtep = testscript.parameters['LEAF-2']
        sa_vtep = testscript.parameters['LEAF-3']
        prim_vtep_if = str(testscript.parameters['intf_LEAF_1_1_to_IXIA'])
        prim_vtep_if1 = str(testscript.parameters['intf_LEAF_1_2_to_IXIA'])
		
        prim_vtep.configure('interface {prim_vtep_if}'.format(prim_vtep_if=prim_vtep_if))
  
        ixNetwork   = testscript.parameters['ixNetwork']
        p1_handle = testscript.parameters['orphan1_handle']
        p2_handle = testscript.parameters['sa_handle']
        p3_handle = testscript.parameters['orphan2_handle']
        p4_handle = testscript.parameters['vpc_handle']
        p5_handle = testscript.parameters['sec_handle']
        
        p1_handle.Start()
        p2_handle.Start()
        p4_handle.Start()
        
        log.info('Waiting for 30 secs')      
        time.sleep(30)

        # Traffic Item for Orphan to Standalone
        trafficItem1 = ixNetwork.Traffic.TrafficItem.add(
            Name='Trunk Orphan To Standalone',
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
            Name='Trunk VPC To Standalone',
            BiDirectional=True,
            TrafficType='ipv6',
        )
        trafficItem2.EndpointSet.add(Sources=p4_handle, Destinations=p2_handle)
        configElement = trafficItem2.ConfigElement.find()[0]
        configElement.FrameRate.update(Type='framesPerSecond', Rate=1000.00)
        configElement.FrameSize.FixedSize = 800

        trafficItem2.Tracking.find()[0].TrackBy = ['ethernetIiSourceaddress0']
        trafficItem2.Generate()
        
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
            Name='Trunk Orphan2 To Standalone',
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

# =====================================================================================================#
# TC-ID: TC_VXLAN_PVMAP_000 - ISSU
# Testcase:  
#   - Reload device - traffic between orphan and standalone
#   - Check mac learning and traffic
# ======================================================================================================#
class TC_VXLAN_PVMAP_000(aetest.Testcase):
    def CHECK_ISSU_IMPACT(self, testscript):
        prim_vtep       = testscript.parameters['LEAF-1']
        sec_vtep        = testscript.parameters['LEAF-2']

        # Prepare the ISSU Impact Check command
        issu_impact_cmd = 'sh install all impact nxos bootflash:'+str(testscript.parameters['abs_target_image'])+' non-disruptive'

        # Execute the ISSU Impact command
        impact_output = prim_vtep.execute(issu_impact_cmd, timeout=1200)
        output_split = list(filter(None, impact_output.split('\n')))
        fail_flag = []
        fail_logs = '\n'

        # Process logs for any failure reasons
        for log_line in output_split:
            if re.search('CRASHED|fail|CPU Hog|malloc|core dump|mts_send|redzone|error', log_line, re.I):
                fail_flag.append(0)
                fail_logs += str(log_line) + '\n'
            if re.search('\\d+\\s+yes\\s+(\\S+)\\s+reset', log_line, re.I):
                if not re.search('\\d+\\s+yes\\s+(non-disruptive)\\s+reset', log_line, re.I):
                    fail_flag.append(0)
                    fail_logs += 'The ISSU Impact is reporting Disruptive, Please check\n'
        
        time.sleep(120)

        # Reporting
        if 0 in fail_flag:
            self.failed(reason=fail_logs, goto=['common_cleanup'])
        else:
            log.info(reason="Upgrade successful")

    @aetest.test
    def testcase_vpc_issu_primary(self, testscript, steps):
        sa_vtep         = testscript.parameters['LEAF-3']
        prim_vtep       = testscript.parameters['LEAF-1']
        sec_vtep        = testscript.parameters['LEAF-2']
        prim_mac        = str(testscript.parameters['PVMAP_Dict']['prim_vpc_mac'])
        sa_mac          = str(testscript.parameters['PVMAP_Dict']['sa_mac'])
        p1_handle       = testscript.parameters['vpc_handle']
        p2_handle       = testscript.parameters['sa_handle']
        ixNetwork       = testscript.parameters['ixNetwork']
        issu_image      = testscript.parameters['abs_target_image']

        with steps.start("Starting hosts..."):
            p1_handle.Start()
            p2_handle.Start()
        
        log.info('Waiting {}secs to start hosts'.format(host_start_time))
        time.sleep(host_start_time)

        stream1 = ixNetwork.Traffic.TrafficItem.find(Name='Trunk VPC To Standalone')
        stream1.StartStatelessTraffic()
        log.info('Waiting {}secs to start the traffic'.format(traffic_start_time))
        time.sleep(traffic_start_time)
        
        with steps.start("checking mac learning for vpc mac"):
            if not verify_mac_on_vteps([prim_vtep, sec_vtep, sa_vtep], '1001', 1025, prim_mac):
                log.error("Mac learning failed for vpc mac")
                self.failed("Mac learning failed for vpc mac")

        with steps.start("Checking mac learning for standalone mac"):
            if not verify_mac_on_vteps([prim_vtep, sec_vtep, sa_vtep], '1002', 1025, sa_mac):
                log.error("Mac learning failed for standalone mac")
                self.failed("Mac learning failed for standalone mac")
        
        # Establish dialogs for running ISSU command
        dialog = Dialog([
            Statement(pattern=r'Do you want to continue with the installation \(y/n\)\?',
                      action='sendline(y)',
                      loop_continue=True,
                      continue_timer=True),
        ])
        
        # Create ISSU command
        issu_cmd = 'install all nxos bootflash:'+str(issu_image)+' non-disruptive' 
        
        # Perform ISSU
        result, output = testscript.parameters['LEAF-2'].reload(reload_command=issu_cmd, prompt_recovery=True, dialog=dialog, timeout=2000, return_output=True)
        output_split = list(filter(None, output.split('\n')))
        fail_flag = []
        fail_logs = '\n'
        
        # Process logs for any failure reasons
        for log_line in output_split:
            if re.search('CRASHED|fail|CPU Hog|malloc|core dump|mts_send|redzone|error', log_line, re.I):
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
        
        with steps.start('Reload Standalone'):            
            result = infraTrig.switchReload(prim_vtep)
            if result:
                log.info("Reload completed Successfully")
            else:
                log.debug("Reload Failed")
                self.failed("Reload Failed")
            
        log.info("Waiting for 340 sec for the topology to come UP")
        time.sleep(340)

        # Verify NVE Peers with new IP
        nvePeerData = verifyEVPNNvePeers(testscript.parameters['leavesDict'])

        if nvePeerData['result'] is 1:
            log.info("PASS : Successfully verified NVE Peering\n\n")
        else:
            log.error("FAIL : Failed to verify NVE Peering\n\n")
            self.failed(reason=nvePeerData['log'])
    
        with steps.start("checking mac learning for vpc mac"):
            if not verify_mac_on_vteps([prim_vtep, sec_vtep, sa_vtep], '1001', 1025, prim_mac):
                log.error("Mac learning failed for vpc mac")
                self.failed("Mac learning failed for vpc mac")

        with steps.start("checking mac learning for standalone mac"):
            if not verify_mac_on_vteps([prim_vtep, sec_vtep, sa_vtep], '1002', 1025, sa_mac):
                log.error("Mac learning failed for standalone mac")
                self.failed("Mac learning failed for standalone mac")

        with steps.start('Verify Learned mac address consistency between hardware and software'):
            if verify_mac_cc_between_hardware_software([prim_vtep, sec_vtep, sa_vtep]):
                log.info('MAC CC success')
            else:
                self.failed('MAC CC failed')

        stream1.StopStatelessTraffic()
        log.info('Waiting {}secs to stop the traffic'.format(traffic_stop_time))
        time.sleep(traffic_stop_time)

        with steps.start("Verify Steady State"):
            if VerifyTraffic("TC_VXLAN_PVMAP_042", testscript, traffic_item='Trunk VPC To Standalone'):
                log.info('Verify traffic success')
            else:
                self.failed('Verify traffic failed') 

    @aetest.test
    def testcase_vpc_reload_secondary(self, testscript, steps):
        sa_vtep         = testscript.parameters['LEAF-3']
        prim_vtep       = testscript.parameters['LEAF-1']
        sec_vtep        = testscript.parameters['LEAF-2']
        prim_mac        = str(testscript.parameters['PVMAP_Dict']['prim_vpc_mac'])
        sa_mac          = str(testscript.parameters['PVMAP_Dict']['sa_mac'])
        p1_handle       = testscript.parameters['vpc_handle']
        p2_handle       = testscript.parameters['sa_handle']
        ixNetwork       = testscript.parameters['ixNetwork']

        with steps.start("Starting hosts..."):
            p1_handle.Start()
            p2_handle.Start()
        
        log.info('Waiting {}secs to start hosts'.format(host_start_time))
        time.sleep(host_start_time)

        stream1 = ixNetwork.Traffic.TrafficItem.find(Name='Trunk VPC To Standalone')
        stream1.StartStatelessTraffic()
        log.info('Waiting {}secs to start the traffic'.format(traffic_start_time))
        time.sleep(traffic_start_time)
        
        with steps.start("checking mac learning for vpc mac"):
            if not verify_mac_on_vteps([prim_vtep, sec_vtep, sa_vtep], '1001', 1025, prim_mac):
                log.error("Mac learning failed for vpc mac")
                self.failed("Mac learning failed for vpc mac")

        with steps.start("Checking mac learning for standalone mac"):
            if not verify_mac_on_vteps([prim_vtep, sec_vtep, sa_vtep], '1002', 1025, sa_mac):
                log.error("Mac learning failed for standalone mac")
                self.failed("Mac learning failed for standalone mac")
        
        with steps.start('Reload Secondary'):            
            result = infraTrig.switchReload(sec_vtep)
            if result:
                log.info("Reload completed Successfully")
            else:
                log.debug("Reload Failed")
                self.failed("Reload Failed")
            
        log.info("Waiting for 340 sec for the topology to come UP")
        time.sleep(340)

        # Verify NVE Peers with new IP
        nvePeerData = verifyEVPNNvePeers(testscript.parameters['leavesDict'])

        if nvePeerData['result'] is 1:
            log.info("PASS : Successfully verified NVE Peering\n\n")
        else:
            log.error("FAIL : Failed to verify NVE Peering\n\n")
            self.failed(reason=nvePeerData['log'])
    
        with steps.start("checking mac learning for vpc mac"):
            if not verify_mac_on_vteps([prim_vtep, sec_vtep, sa_vtep], '1001', 1025, prim_mac):
                log.error("Mac learning failed for vpc mac")
                self.failed("Mac learning failed for vpc mac")

        with steps.start("checking mac learning for standalone mac"):
            if not verify_mac_on_vteps([prim_vtep, sec_vtep, sa_vtep], '1002', 1025, sa_mac):
                log.error("Mac learning failed for standalone mac")
                self.failed("Mac learning failed for standalone mac")

        with steps.start('Verify Learned mac address consistency between hardware and software'):
            if verify_mac_cc_between_hardware_software([prim_vtep, sec_vtep, sa_vtep]):
                log.info('MAC CC success')
            else:
                self.failed('MAC CC failed')

        stream1.StopStatelessTraffic()
        log.info('Waiting {}secs to stop the traffic'.format(traffic_stop_time))
        time.sleep(traffic_stop_time)

        with steps.start("Verify Steady State"):
            if VerifyTraffic("TC_VXLAN_PVMAP_042", testscript, traffic_item='Trunk VPC To Standalone'):
                log.info('Verify traffic success')
            else:
                self.failed('Verify traffic failed') 
    
    @aetest.test
    def verify_error_cores(self, testscript, testbed, steps):
        sa_vtep         = testscript.parameters['LEAF-3']
        prim_vtep       = testscript.parameters['LEAF-1']
        sec_vtep        = testscript.parameters['LEAF-2']
        ixNetwork       = testscript.parameters['ixNetwork']

        with steps.start("Stopping hosts..."):
            ixNetwork.StopAllProtocols()

        log.info('Waiting {}secs'.format(traffic_stop_time))
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
# TC-ID: TC_VXLAN_PVMAP_001
# Testcase:
#   - Configure PVMAP on orphan port
#   - Check mac learning
#   - Check traffic
# =============================================================================================================================#
class TC_VXLAN_PVMAP_001(aetest.Testcase):
    @aetest.test
    def testcase_1(self, testscript, testbed, steps):
        sa_vtep         = testscript.parameters['LEAF-3']
        prim_vtep       = testscript.parameters['LEAF-1']
        sec_vtep        = testscript.parameters['LEAF-2']
        prim_vtep_if    = str(testscript.parameters['intf_LEAF_1_1_to_IXIA'])
        sa_vtep_if      = str(testscript.parameters['intf_LEAF_3_to_IXIA'])
        prim_mac        = str(testscript.parameters['PVMAP_Dict']['prim_orphan_mac'])
        sa_mac          = str(testscript.parameters['PVMAP_Dict']['sa_mac'])
        p1_handle       = testscript.parameters['orphan1_handle']
        p2_handle       = testscript.parameters['sa_handle']
        
        ixNetwork       = testscript.parameters['ixNetwork']

        with steps.start("Starting hosts..."):
            p1_handle.Start()
            p2_handle.Start()
        
        log.info('Waiting {}secs to start hosts'.format(host_start_time))
        time.sleep(host_start_time)

        stream1 = ixNetwork.Traffic.TrafficItem.find(Name='Trunk Orphan To Standalone')
        stream1.StartStatelessTraffic()
        log.info('Waiting {}secs to start the traffic'.format(traffic_start_time))
        time.sleep(traffic_start_time)
        
        stream1.StopStatelessTraffic()
        log.info('Waiting {}secs to stop the traffic'.format(traffic_stop_time))
        time.sleep(traffic_stop_time)

        with steps.start("checking mac learning for primary orphan mac"):
            if not verify_mac_on_vteps([prim_vtep, sec_vtep, sa_vtep], '1001', 1025, prim_mac):
                log.error("Mac learning failed for orpan mac")
                self.failed("Mac learning failed for orphan mac")
                
        with steps.start("Checking mac learning for standalone mac"):
            if not verify_mac_on_vteps([prim_vtep, sec_vtep, sa_vtep], '1002', 1025, sa_mac):
                log.error("Mac learning failed for standalone mac")
                self.failed("Mac learning failed for standalone mac")

        with steps.start('Verify Learned mac address consistency between hardware and software'):
            if verify_mac_cc_between_hardware_software([prim_vtep, sec_vtep, sa_vtep]):
                log.info('MAC CC success')
            else:
                self.failed('MAC CC failed')

        with steps.start("Verify Steady State"):
            if VerifyTraffic("TC_VXLAN_PVMAP_001", testscript, traffic_item='Trunk Orphan To Standalone'):
                log.info('Verify traffic success')
            else:
                self.failed('Verify traffic failed')

    @aetest.test
    def verify_error_cores(self, testscript, testbed, steps):
        sa_vtep         = testscript.parameters['LEAF-3']
        prim_vtep       = testscript.parameters['LEAF-1']
        sec_vtep        = testscript.parameters['LEAF-2']
        ixNetwork       = testscript.parameters['ixNetwork']

        with steps.start("Stopping hosts..."):
            ixNetwork.StopAllProtocols()
        
        log.info('Waiting {}secs to stop the traffic'.format(traffic_stop_time))
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
# TC-ID: TC_VXLAN_PVMAP_002
# Testcase:
#   - Configure PVMAP on VPC port-channel port
#   - Check mac learning
#   - Check traffic
# =============================================================================================================================#
class TC_VXLAN_PVMAP_002(aetest.Testcase):
    @aetest.test
    def testcase_2(self, testscript, testbed, steps):
        sa_vtep         = testscript.parameters['LEAF-3']
        prim_vtep       = testscript.parameters['LEAF-1']
        sec_vtep        = testscript.parameters['LEAF-2']
        prim_mac        = str(testscript.parameters['PVMAP_Dict']['prim_vpc_mac'])
        sa_mac          = str(testscript.parameters['PVMAP_Dict']['sa_mac'])
        p1_handle       = testscript.parameters['vpc_handle']
        p2_handle       = testscript.parameters['sa_handle']
        
        ixNetwork       = testscript.parameters['ixNetwork']

        with steps.start("Starting hosts..."):
            p1_handle.Start()
            p2_handle.Start()
        
        log.info('Waiting {}secs to start hosts'.format(host_start_time))
        time.sleep(host_start_time)

        stream1 = ixNetwork.Traffic.TrafficItem.find(Name='Trunk VPC To Standalone')
        stream1.StartStatelessTraffic()
        log.info('Waiting {}secs to start the traffic'.format(traffic_start_time))
        time.sleep(traffic_start_time)
        
        stream1.StopStatelessTraffic()
        log.info('Waiting {}secs to stop the traffic'.format(traffic_stop_time))
        time.sleep(traffic_stop_time)

        with steps.start("checking mac learning for vpc mac"):
            if not verify_mac_on_vteps([prim_vtep, sec_vtep, sa_vtep], '1001', 1025, prim_mac):
                log.error("Mac learning failed for vpc mac")
                self.failed("Mac learning failed for vpc mac")

        with steps.start("Checking mac learning on standalone and orphan"):
            if not verify_mac_on_vteps([prim_vtep, sec_vtep, sa_vtep], '1002', 1025, sa_mac):
                log.error("Mac learning failed for standalone mac")
                self.failed("Mac learning failed for standalone mac")

        with steps.start('Verify Learned mac address consistency between hardware and software'):
            if verify_mac_cc_between_hardware_software([prim_vtep, sec_vtep, sa_vtep]):
                log.info('MAC CC success')
            else:
                self.failed('MAC CC failed')

        with steps.start("Verify Steady State"):
            if VerifyTraffic("TC_VXLAN_PVMAP_002", testscript, traffic_item='Trunk VPC To Standalone'):
                log.info('Verify traffic success')
            else:
                self.failed('Verify traffic failed')

    @aetest.test
    def verify_error_cores(self, testscript, testbed, steps):
        sa_vtep         = testscript.parameters['LEAF-3']
        prim_vtep       = testscript.parameters['LEAF-1']
        sec_vtep        = testscript.parameters['LEAF-2']
        ixNetwork       = testscript.parameters['ixNetwork']

        with steps.start("Stopping hosts..."):
            ixNetwork.StopAllProtocols()
        
        log.info('Waiting {}secs to stop the traffic'.format(traffic_stop_time))
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
# TC-ID: TC_VXLAN_PVMAP_003
# Testcase:
#   - Configure PVMAP on non-vpc port-channel and configure to orphan port
#   - Check mac learning
#   - Check traffic
# =============================================================================================================================#
class TC_VXLAN_PVMAP_003(aetest.Testcase):
    @aetest.test
    def test_config(self, testscript, steps):
        prim_vtep       = testscript.parameters['LEAF-1']
        sa_vtep         = testscript.parameters['LEAF-3']
        prim_vtep_if    = str(testscript.parameters['intf_LEAF_1_1_to_IXIA'])
        vlan            = int(testscript.parameters['LEAF_1_Orphan1_TGEN_dict']['vlan_id'])
        vlan1           = int(testscript.parameters['LEAF_1_Orphan1_TGEN_dict']['vlan_id1'])
        
        with steps.start("Default Orphan interface"):
            try:
                prim_vtep.configure('default interface {intf}'.format(intf=prim_vtep_if))
            except Exception as error:
                log.debug("Unable to configure - Encountered Exception " + str(error))
                self.errored('Exception occured during default interface configuration', 
                             goto=['common_cleanup'])
        
        with steps.start("Configure non-vpc port-channel 110 with PVMAP"):
            try:
                prim_vtep.configure('''interface port-channel 110
                                switchport
                                switchport mode trunk
                                switchport trunk allowed vlan {vlan}
                                spanning-tree port type edge trunk
                                switchport vlan mapping enable
                                switchport vlan mapping {vlan1} {vlan}
                                no shutdown
                            '''.format(vlan=vlan, vlan1=vlan1))
            except Exception as error:
                log.debug("Unable to configure - Encountered Exception " + str(error))
                self.errored('Exception occurred while configuring PVMAP', 
                             goto=['common_cleanup']) 
        
        with steps.start("Configure port-channel on Orphan"):
            try:
                prim_vtep.configure('''interface {intf}
                                switchport
                                switchport mode trunk
                                switchport trunk allowed vlan {vlan}
                                spanning-tree port type edge trunk
                                channel-group 110
                                no shutdown
                            '''.format(vlan=vlan, intf=prim_vtep_if))
            except Exception as error:
                log.debug("Unable to configure - Encountered Exception " + str(error))
                self.errored('Exception occurred while configuring PVMAP', 
                             goto=['common_cleanup']) 
        
        log.info('Waiting for 30ses')
        time.sleep(30)
        
    @aetest.test
    def testcase_3(self, testscript, steps):
        sa_vtep         = testscript.parameters['LEAF-3']
        prim_vtep       = testscript.parameters['LEAF-1']
        sec_vtep        = testscript.parameters['LEAF-2']
        prim_mac        = str(testscript.parameters['PVMAP_Dict']['prim_vpc_mac'])
        sa_mac          = str(testscript.parameters['PVMAP_Dict']['sa_mac'])
        p1_handle       = testscript.parameters['orphan1_handle']
        p2_handle       = testscript.parameters['sa_handle']
        ixNetwork       = testscript.parameters['ixNetwork']

        with steps.start("Starting hosts..."):
            p1_handle.Start()
            p2_handle.Start()
        
        log.info('Waiting {}secs to start hosts'.format(host_start_time))
        time.sleep(host_start_time)

        stream1 = ixNetwork.Traffic.TrafficItem.find(Name='Trunk Orphan To Standalone')
        stream1.StartStatelessTraffic()
        log.info('Waiting {}secs to start the traffic'.format(traffic_start_time))
        time.sleep(traffic_start_time)
        
        stream1.StopStatelessTraffic()
        log.info('Waiting {}secs to stop the traffic'.format(traffic_stop_time))
        time.sleep(traffic_stop_time)

        with steps.start("checking mac learning orphan mac"):
            if not verify_mac_on_vteps([prim_vtep, sec_vtep, sa_vtep], '1001', 1025, prim_mac):
                log.error("Mac learning failed for orphan mac")
                self.failed("Mac learning failed for orphan mac")

        with steps.start("Checking mac learning for standalone mac"):
            if not verify_mac_on_vteps([prim_vtep, sec_vtep, sa_vtep], '1002', 1025, sa_mac):
                log.error("Mac learning failed for standalone mac")
                self.failed("Mac learning failed for standalone mac")

        with steps.start('Verify Learned mac address consistency between hardware and software'):
            if verify_mac_cc_between_hardware_software([prim_vtep, sec_vtep, sa_vtep]):
                log.info('MAC CC success')
            else:
                self.failed('MAC CC failed')

        with steps.start("Verify Steady State"):
            if VerifyTraffic("TC_VXLAN_PVMAP_003", testscript, traffic_item='Trunk Orphan To Standalone'):
                log.info('Verify traffic success')
            else:
                self.failed('Verify traffic failed')

    @aetest.test
    def test_unconfig(self, testscript, steps):
        prim_vtep       = testscript.parameters['LEAF-1']
        vlan            = int(testscript.parameters['LEAF_1_Orphan1_TGEN_dict']['vlan_id'])
        vlan1           = int(testscript.parameters['LEAF_1_Orphan1_TGEN_dict']['vlan_id1'])
        leaf1_if = str(testscript.parameters['intf_LEAF_1_1_to_IXIA'])
        
        with steps.start("ReConfigure Orphan with PVMAP"):
            try:
                prim_vtep.configure('''interface {intf}
                                no channel-group 110
                                switchport vlan mapping enable
                                switchport vlan mapping {vlan1} {vlan}
                                no shutdown
                            '''.format(vlan=vlan, vlan1=vlan1, intf=leaf1_if))
            except Exception as error:
                log.debug("Unable to configure - Encountered Exception " + str(error))
                self.errored('Exception occurred while configuring PVMAP', 
                             goto=['common_cleanup']) 
        
        with steps.start("Remove non-vpc port-channel 110"):
            try:
                prim_vtep.configure('no interface port-channel 110')
            except Exception as error:
                log.debug("Unable to configure - Encountered Exception " + str(error))
                self.errored('Exception occurred while configuring PVMAP', 
                             goto=['common_cleanup']) 
        
    @aetest.test
    def verify_error_cores(self, testscript, testbed, steps):
        sa_vtep         = testscript.parameters['LEAF-3']
        prim_vtep       = testscript.parameters['LEAF-1']
        sec_vtep        = testscript.parameters['LEAF-2']
        ixNetwork       = testscript.parameters['ixNetwork']

        with steps.start("Stopping hosts..."):
            ixNetwork.StopAllProtocols()
        
        log.info('Waiting {}secs'.format(traffic_stop_time))
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
# TC-ID: TC_VXLAN_PVMAP_004
# Testcase:
#   - Configure overlap mapping
#   - Check mac learning
#   - Check traffic
# =============================================================================================================================#
class TC_VXLAN_PVMAP_004(aetest.Testcase):
    @aetest.test
    def test_config(self, testscript, steps):
        prim_vtep       = testscript.parameters['LEAF-1']
        vlan            = int(testscript.parameters['LEAF_1_Orphan1_TGEN_dict']['vlan_id'])
        vlan1           = int(testscript.parameters['LEAF_1_Orphan1_TGEN_dict']['vlan_id1'])
        vlan3           = int(testscript.parameters['LEAF_3_TGEN_dict']['vlan_id'])
        leaf1_if        = str(testscript.parameters['intf_LEAF_1_1_to_IXIA'])
        p1_handle       = testscript.parameters['orphan1_handle']
        leaf1_if        = str(testscript.parameters['intf_LEAF_1_1_to_IXIA'])
        tgen_dict1      = testscript.parameters['LEAF_3_TGEN_dict']
        tgen_dict       = testscript.parameters['LEAF_1_Orphan1_TGEN_dict']
        ixNetwork       = testscript.parameters['ixNetwork']
        
        with steps.start("Configure Orphan with overlap mapping"):
            try:
                prim_vtep.configure('''interface {intf}
                                switchport vlan mapping enable
                                no switchport vlan mapping all
                                switchport vlan mapping {vlan1} {vlan3}
                                switchport vlan mapping {vlan3} {vlan}
                                no shutdown
                            '''.format(vlan=vlan, vlan1=vlan1, vlan3=vlan3, intf=leaf1_if))
            except Exception as error:
                log.debug("Unable to configure - Encountered Exception " + str(error))
                self.errored('Exception occurred while configuring PVMAP', 
                             goto=['common_cleanup']) 

        log.info('Waiting 30secs for configuration changes')
        time.sleep(30)

        with steps.start("Stopping hosts..."):
            ixNetwork.StopAllProtocols()
        
        log.info('Waiting {}secs to stop the traffic'.format(traffic_stop_time))
        time.sleep(traffic_stop_time)

        with steps.start('Change vlan id to orphan from non vxlan id to vxlan id'):
            eth = p1_handle.DeviceGroup.find()[0].Ethernet.find()[0].update()
            eth.Mac.Increment(start_value=tgen_dict['mac'], step_value=tgen_dict['mac_step'])
            eth.EnableVlans.Single(True)
            eth.Vlan.find()[0].VlanId.Increment(
                start_value=tgen_dict1['vlan_id'], step_value=tgen_dict1['vlan_id_step']
            )
    
    @aetest.test
    def testcase(self, testscript, steps):
        sa_vtep         = testscript.parameters['LEAF-3']
        prim_vtep       = testscript.parameters['LEAF-1']
        sec_vtep        = testscript.parameters['LEAF-2']
        prim_mac        = str(testscript.parameters['PVMAP_Dict']['prim_orphan_mac'])
        sa_mac          = str(testscript.parameters['PVMAP_Dict']['sa_mac'])
        p1_handle       = testscript.parameters['orphan1_handle']
        p2_handle       = testscript.parameters['sa_handle']
        
        ixNetwork       = testscript.parameters['ixNetwork']

        with steps.start("Starting hosts..."):
            p1_handle.Start()
            p2_handle.Start()
        
        log.info('Waiting {}secs to start hosts'.format(host_start_time))
        time.sleep(host_start_time)

        stream1 = ixNetwork.Traffic.TrafficItem.find(Name='Trunk Orphan To Standalone')
        stream1.StartStatelessTraffic()
        log.info('Waiting {}secs to start the traffic'.format(traffic_start_time))
        time.sleep(traffic_start_time)
        
        stream1.StopStatelessTraffic()
        log.info('Waiting {}secs to stop the traffic'.format(traffic_stop_time))
        time.sleep(traffic_stop_time)

        with steps.start("checking mac learning for orphan mac"):
            if not verify_mac_on_vteps([prim_vtep, sec_vtep, sa_vtep], '1001', 1025, prim_mac):
                log.error("Mac learning failed for orphan mac")
                self.failed("Mac learning failed for orphan mac")

        with steps.start("Checking mac learning for standalone mac"):
            if not verify_mac_on_vteps([prim_vtep, sec_vtep, sa_vtep], '1002', 1025, sa_mac):
                log.error("Mac learning failed for standalone mac")
                self.failed("Mac learning failed for standalone mac")

        with steps.start('Verify Learned mac address consistency between hardware and software'):
            if verify_mac_cc_between_hardware_software([prim_vtep, sec_vtep, sa_vtep]):
                log.info('MAC CC success')
            else:
                self.failed('MAC CC failed')

        with steps.start("Verify Steady State"):
            if VerifyTraffic("TC_VXLAN_PVMAP_004", testscript, traffic_item='Trunk Orphan To Standalone'):
                log.info('Verify traffic success')
            else:
                self.failed('Verify traffic failed')

    @aetest.test
    def test_unconfig(self, testscript, steps):
        prim_vtep       = testscript.parameters['LEAF-1']
        vlan            = int(testscript.parameters['LEAF_1_Orphan1_TGEN_dict']['vlan_id'])
        vlan3           = int(testscript.parameters['LEAF_3_TGEN_dict']['vlan_id'])
        vlan1           = int(testscript.parameters['LEAF_1_Orphan1_TGEN_dict']['vlan_id1'])
        leaf1_if        = str(testscript.parameters['intf_LEAF_1_1_to_IXIA'])
        tgen_dict1       = testscript.parameters['LEAF_1_Orphan1_TGEN_dict']
        p1_handle       = testscript.parameters['orphan1_handle']
        ixNetwork       = testscript.parameters['ixNetwork']
                
        with steps.start("Remove overlap mapping"):
            try:
                prim_vtep.configure('''interface {intf}
                                no switchport vlan mapping all
                                switchport vlan mapping {vlan1} {vlan}
                            '''.format(vlan=vlan, vlan1=vlan1, vlan3=vlan3, intf=leaf1_if))
            except Exception as error:
                log.debug("Unable to configure - Encountered Exception " + str(error))
                self.errored('Exception occurred while configuring PVMAP', 
                             goto=['common_cleanup']) 
        
        log.info('Waiting 30secs for configuration changes')
        time.sleep(30)

        with steps.start("Stopping hosts..."):
            ixNetwork.StopAllProtocols()
        
        log.info('Waiting {}secs to stop the traffic'.format(traffic_stop_time))
        time.sleep(traffic_stop_time)
        
        with steps.start('Change vlan id to orphan from vxlan id to non vxlan id'):
            eth = p1_handle.DeviceGroup.find()[0].Ethernet.find()[0].update()
            eth.Mac.Increment(start_value=tgen_dict1['mac'], step_value=tgen_dict1['mac_step'])
            eth.EnableVlans.Single(True)
            eth.Vlan.find()[0].VlanId.Increment(
                start_value=tgen_dict1['vlan_id1'], step_value=tgen_dict1['vlan_id_step']
            )
        log.info('Waiting 30secs for configuration changes')
        time.sleep(30)

    @aetest.test
    def verify_error_cores(self, testscript, testbed, steps):
        sa_vtep         = testscript.parameters['LEAF-3']
        prim_vtep       = testscript.parameters['LEAF-1']
        sec_vtep        = testscript.parameters['LEAF-2']
        ixNetwork       = testscript.parameters['ixNetwork']

        with steps.start("Stopping hosts..."):
            ixNetwork.StopAllProtocols()
        
        log.info('Waiting {}secs to stop the traffic'.format(traffic_stop_time))
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
# TC-ID: TC_VXLAN_PVMAP_005
# Testcase:
#   - Remove member from vpc port channel
#   - Check mac gets flushed out
#   - Add member to vpc port-channel
#   - Check traffic
# =============================================================================================================================#
class TC_VXLAN_PVMAP_005(aetest.Testcase):
    @aetest.test
    def testcase_5(self, testscript, steps):
        sa_vtep         = testscript.parameters['LEAF-3']
        prim_vtep       = testscript.parameters['LEAF-1']
        sec_vtep        = testscript.parameters['LEAF-2']
        prim_mac        = str(testscript.parameters['PVMAP_Dict']['prim_vpc_mac'])
        sa_mac          = str(testscript.parameters['PVMAP_Dict']['sa_mac'])
        p1_handle       = testscript.parameters['vpc_handle']
        p2_handle       = testscript.parameters['sa_handle']
        leaf1_to_fan_if = str(testscript.parameters['intf_LEAF_1_to_FAN3172'])
        leaf2_to_fan_if = str(testscript.parameters['intf_LEAF_2_to_FAN3172'])
        ixNetwork       = testscript.parameters['ixNetwork']

        with steps.start("Starting hosts..."):
            p1_handle.Start()
            p2_handle.Start()
        
        log.info('Waiting {}secs to start hosts'.format(host_start_time))
        time.sleep(host_start_time)

        stream1 = ixNetwork.Traffic.TrafficItem.find(Name='Trunk VPC To Standalone')
        stream1.StartStatelessTraffic()
        log.info('Waiting {}secs to start the traffic'.format(traffic_start_time))
        time.sleep(traffic_start_time)
        
        stream1.StopStatelessTraffic()
        log.info('Waiting {}secs to stop the traffic'.format(traffic_stop_time))
        time.sleep(traffic_stop_time)

        with steps.start("checking mac learning for vpc mac"):
            if not verify_mac_on_vteps([prim_vtep, sec_vtep, sa_vtep], '1001', 1025, prim_mac):
                log.error("Mac learning failed for orphan mac")
                self.failed("Mac learning failed for orphan mac")

        with steps.start("Checking mac for standalone mac"):
            if not verify_mac_on_vteps([prim_vtep, sec_vtep, sa_vtep], '1002', 1025, sa_mac):
                log.error("Mac learning failed for standalone mac")
                self.failed("Mac learning failed for standalone mac")

        with steps.start("Remove member from vpc port-channel"):
            try:
                prim_vtep.configure('''interface {intf}
                                       no channel-group 11'''.format(intf=leaf1_to_fan_if))
                sec_vtep.configure('''interface {intf}
                                      no channel-group 11'''.format(intf=leaf2_to_fan_if))
            except Exception as error:
                log.debug("Unable to configure - Encountered Exception " + str(error))
                self.errored('Exception occurred while configuring PVMAP', 
                             goto=['common_cleanup']) 
        
        log.info('Waiting 60secs for mac flushout')
        time.sleep(60)

        with steps.start("checking mac flushout for po11"):
            if not verify_mac_on_vteps([prim_vtep, sec_vtep], '1001', 0, 'Po11'):
                log.error("Mac learning failed for orphan mac")
                self.failed("Mac learning failed for orphan mac")
                
        with steps.start("Checking mac learning for standalone mac"):
            if not verify_mac_on_vteps([prim_vtep, sec_vtep, sa_vtep], '1002', 1025, sa_mac):
                log.error("Mac learning failed for standalone mac")
                self.failed("Mac learning failed for standalone mac")
        
        with steps.start("Verify Traffic Drop"):
            if VerifyTrafficDrop("TC_VXLAN_PVMAP_005", testscript, traffic_item='Trunk VPC To Standalone'):
                log.info('Verify traffic drop success')
            else:
                self.failed('Verify traffic drop failed') 

        with steps.start("Add member to vpc port-channel"):
            try:
                prim_vtep.configure('''interface {intf}
                                       channel-group 11'''.format(intf=leaf1_to_fan_if))
                sec_vtep.configure('''interface {intf}
                                       channel-group 11'''.format(intf=leaf2_to_fan_if))
            except Exception as error:
                log.debug("Unable to configure - Encountered Exception " + str(error))
                self.errored('Exception occurred while configuring PVMAP', 
                             goto=['common_cleanup']) 

        stream1 = ixNetwork.Traffic.TrafficItem.find(Name='Trunk VPC To Standalone')
        stream1.StartStatelessTraffic()
        log.info('Waiting {}secs to start the traffic'.format(traffic_start_time))
        time.sleep(traffic_start_time)
        
        stream1.StopStatelessTraffic()
        log.info('Waiting {}secs to stop the traffic'.format(traffic_stop_time))
        time.sleep(traffic_stop_time)
        
        log.info('Waiting 60secs for mac relearning')
        time.sleep(60)

        with steps.start("checking mac relearning on for orphan mac"):
            if not verify_mac_on_vteps([prim_vtep, sec_vtep, sa_vtep], '1001', 1025, prim_mac):
                log.error("Mac learning failed for orphan mac")
                self.failed("Mac learning failed for orphan mac")

        with steps.start("checking mac relearning on for standalone mac"):
            if not verify_mac_on_vteps([prim_vtep, sec_vtep, sa_vtep], '1002', 1025, sa_mac):
                log.error("Mac learning failed for standalone mac")
                self.failed("Mac learning failed for standalone mac")

        with steps.start('Verify Learned mac address consistency between hardware and software'):
            if verify_mac_cc_between_hardware_software([prim_vtep, sec_vtep, sa_vtep]):
                log.info('MAC CC success')
            else:
                self.failed('MAC CC failed')

        with steps.start("Verify Steady State"):
            if VerifyTraffic("TC_VXLAN_PVMAP_005", testscript, traffic_item='Trunk VPC To Standalone'):
                log.info('Verify traffic success')
            else:
                self.failed('Verify traffic failed') 

    @aetest.test
    def verify_error_cores(self, testscript, testbed, steps):
        sa_vtep         = testscript.parameters['LEAF-3']
        prim_vtep       = testscript.parameters['LEAF-1']
        sec_vtep        = testscript.parameters['LEAF-2']
        ixNetwork       = testscript.parameters['ixNetwork']
        leaf1_to_fan_if = str(testscript.parameters['intf_LEAF_1_to_FAN3172'])
        leaf2_to_fan_if = str(testscript.parameters['intf_LEAF_2_to_FAN3172'])
        
        with steps.start("Stopping hosts..."):
            ixNetwork.StopAllProtocols()
        
        with steps.start("Add member to vpc port-channel"):
            try:
                prim_vtep.configure('''interface {intf}
                                       channel-group 11'''.format(intf=leaf1_to_fan_if))
                sec_vtep.configure('''interface {intf}
                                       channel-group 11'''.format(intf=leaf2_to_fan_if))
            except Exception as error:
                log.debug("Unable to configure - Encountered Exception " + str(error))
                self.errored('Exception occurred while configuring PVMAP', 
                             goto=['common_cleanup'])
        
        log.info('Waiting {}secs'.format(traffic_stop_time))
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
# TC-ID: TC_VXLAN_PVMAP_006
# Testcase:
#   - Delete some of the per port mapping to the translated vlan.
#   - On the same port, other per port vlan should be PV routed.
#   - Other customer vlan on the same port which are vxlan enabled should be be PV routed.
#   - Put back the removed per port vlan mapping added mapped local vlan should work .
#   - Repeat steps 1-4 by doing "no switchport vlan mapping x y" under range of interfaces and verify after each step. 
# =============================================================================================================================#
class TC_VXLAN_PVMAP_006(aetest.Testcase):
    @aetest.test
    def test_config(self, testscript, steps):
        prim_vtep       = testscript.parameters['LEAF-1']
        vlan            = int(testscript.parameters['LEAF_1_Orphan1_TGEN_dict']['vlan_id'])     # vlan-1001
        vlan1           = int(testscript.parameters['LEAF_1_Orphan1_TGEN_dict']['vlan_id1'])    # vlan-10
        vlan3           = int(testscript.parameters['LEAF_3_TGEN_dict']['vlan_id'])             # vlan-1002
        leaf1_if        = str(testscript.parameters['intf_LEAF_1_1_to_IXIA'])
        
        with steps.start('Do Config backup on Primary, Secondary and Standalone'):
            prim_vtep.execute('delete bootflash:{cr_file} no-prompt'.format(cr_file=cr_file))
            prim_vtep.execute("copy running-config bootflash:{cr_file}".format(cr_file=cr_file))

        with steps.start("Configure Orphan with overlap mapping"):
            try:
                prim_vtep.configure('''interface {intf}
                                switchport vlan mapping enable
                                switchport vlan mapping {vlan1} {vlan}
                                switchport vlan mapping {vlan} {vlan3}
                                no shutdown
                            '''.format(vlan=vlan, vlan1=vlan1, vlan3=vlan3, intf=leaf1_if))
            except Exception as error:
                log.debug("Unable to configure - Encountered Exception " + str(error))
                self.errored('Exception occurred while configuring PVMAP', 
                             goto=['common_cleanup']) 
    
        display_configs(testscript)

    @aetest.test
    def testcase_6(self, testscript, testbed, steps):
        sa_vtep         = testscript.parameters['LEAF-3']
        prim_vtep       = testscript.parameters['LEAF-1']
        sec_vtep        = testscript.parameters['LEAF-2']
        fan             = testscript.parameters['FAN']
        prim_mac        = str(testscript.parameters['PVMAP_Dict']['prim_orphan_mac'])
        sa_mac          = str(testscript.parameters['PVMAP_Dict']['sa_mac'])
        vlan            = int(testscript.parameters['LEAF_1_Orphan1_TGEN_dict']['vlan_id'])     # vlan-1001
        vlan1           = int(testscript.parameters['LEAF_1_Orphan1_TGEN_dict']['vlan_id1'])    # vlan-10
        vlan3           = int(testscript.parameters['LEAF_3_TGEN_dict']['vlan_id'])             # vlan-1002
        p1_handle       = testscript.parameters['orphan1_handle']
        p2_handle       = testscript.parameters['sa_handle']
        leaf1_if        = str(testscript.parameters['intf_LEAF_1_1_to_IXIA'])
        tgen_dict1       = testscript.parameters['LEAF_1_Orphan1_TGEN_dict']
        tgen_dict       = testscript.parameters['LEAF_3_1_TGEN_dict']
        ixNetwork       = testscript.parameters['ixNetwork']

        with steps.start("Starting hosts..."):
            p1_handle.Start()
            p2_handle.Start()
        
        log.info('Waiting {}secs to start hosts'.format(host_start_time))
        time.sleep(host_start_time)

        stream1 = ixNetwork.Traffic.TrafficItem.find(Name='Trunk Orphan To Standalone')
        stream1.StartStatelessTraffic()
        log.info('Waiting {}secs to start the traffic'.format(traffic_start_time))
        time.sleep(traffic_start_time)
        
        stream1.StopStatelessTraffic()
        log.info('Waiting {}secs to stop the traffic'.format(traffic_stop_time))
        time.sleep(traffic_stop_time)

        with steps.start("checking mac learning for primary orphan mac"):
            if not verify_mac_on_vteps([prim_vtep, sec_vtep, sa_vtep], '1001', 1025, prim_mac):
                log.error("Mac learning failed for orpan mac")
                self.failed("Mac learning failed for orphan mac")
                
        with steps.start("Checking mac learning for standalone mac"):
            if not verify_mac_on_vteps([prim_vtep, sec_vtep, sa_vtep], '1002', 1025, sa_mac):
                log.error("Mac learning failed for standalone mac")
                self.failed("Mac learning failed for standalone mac")

        with steps.start("Remove 1st vlan mapping"):
            try:
                prim_vtep.configure('''interface {intf}
                                no switchport vlan mapping {vlan1} {vlan}
                            '''.format(vlan=vlan, vlan1=vlan1, intf=leaf1_if))
            except Exception as error:
                log.debug("Unable to configure - Encountered Exception " + str(error))
                self.errored('Exception occurred while configuring PVMAP', 
                             goto=['common_cleanup']) 
        
        display_configs(testscript)

        with steps.start("Stopping hosts..."):
            ixNetwork.StopAllProtocols()

        log.info('Waiting for 60secs for mac flushout')
        time.sleep(60)
        
        with steps.start("checking mac learning for primary orphan mac"):
            if not verify_mac_on_vteps([prim_vtep, sec_vtep, sa_vtep], '1001', 0, prim_mac):
                log.error("Mac learning failed for orpan mac")
                self.failed("Mac learning failed for orphan mac")
                
        with steps.start("Checking mac learning for standalone mac"):
            if not verify_mac_on_vteps([prim_vtep, sec_vtep, sa_vtep], '1001', 0, sa_mac):
                log.error("Mac learning failed for standalone mac")
                self.failed("Mac learning failed for standalone mac")

        with steps.start('Change vlan id to orphan and configure mac/ip of same'):
            eth = p1_handle.DeviceGroup.find()[0].Ethernet.find()[0].update()
            eth.Mac.Increment(start_value=tgen_dict1['mac'], step_value=tgen_dict1['mac_step'])
            eth.EnableVlans.Single(True)
            eth.Vlan.find()[0].VlanId.Increment(
                start_value=tgen_dict1['vlan_id'], step_value=tgen_dict1['vlan_id_step']
            )

            ipv4 = p1_handle.DeviceGroup.find()[0].Ethernet.find()[0].Ipv4.find().update()
            ipv4.Address.Increment(start_value=tgen_dict['v4_addr'], step_value=tgen_dict['v4_addr_step'])
            ipv4.GatewayIp.Increment(
                start_value=tgen_dict['v4_gateway'], step_value=tgen_dict['v4_gateway_step']
            )
            ipv4.Prefix.Single('16')

        with steps.start('Update traffic item'):
            with steps.start("Starting hosts..."):
                p1_handle.Start()
                p2_handle.Start()

            ixNetwork.Traffic.TrafficItem.find(Name='Trunk Orphan To Standalone').remove()
            tItem = ixNetwork.Traffic.TrafficItem.add(
                Name='Trunk Orphan To Standalone',
                BiDirectional=True,
                TrafficType='ipv4',
            )
            tItem.EndpointSet.add(Sources=p1_handle, Destinations=p2_handle)
            configElement = tItem.ConfigElement.find()[0]
            configElement.FrameRate.update(Type='framesPerSecond', Rate=1000.00)
            configElement.TransmissionControl.update(Type='continuous')
            configElement.FrameSize.FixedSize = 800

            tItem.Tracking.find()[0].TrackBy = ["ethernetIiSourceaddress0"]
            tItem.Generate()
            ixNetwork.Traffic.Apply()
            
        log.info('Waiting {}secs to start hosts'.format(host_start_time))
        time.sleep(host_start_time)

        stream1 = ixNetwork.Traffic.TrafficItem.find(Name='Trunk Orphan To Standalone')
        stream1.StartStatelessTraffic()
        log.info('Waiting {}secs to start the traffic'.format(traffic_start_time))
        time.sleep(traffic_start_time)
        
        stream1.StopStatelessTraffic()
        log.info('Waiting {}secs to stop the traffic'.format(traffic_stop_time))
        time.sleep(traffic_stop_time)

        with steps.start("checking mac learning for primary orphan mac"):
            if not verify_mac_on_vteps([prim_vtep, sec_vtep, sa_vtep], '1002', 1025, prim_mac):
                log.error("Mac learning failed for orpan mac")
                self.failed("Mac learning failed for orphan mac")
                
        with steps.start("Checking mac learning for standalone mac"):
            if not verify_mac_on_vteps([prim_vtep, sec_vtep, sa_vtep], '1002', 1025, sa_mac):
                log.error("Mac learning failed for standalone mac")
                self.failed("Mac learning failed for standalone mac")

        with steps.start('Verify Learned mac address consistency between hardware and software'):
            if verify_mac_cc_between_hardware_software([prim_vtep, sec_vtep, sa_vtep]):
                log.info('MAC CC success')
            else:
                self.failed('MAC CC failed')

        with steps.start("Verify Steady State"):
            if VerifyTraffic("TC_VXLAN_PVMAP_006", testscript, traffic_item='Trunk Orphan To Standalone'):
                log.info('Verify traffic success')
            else:
                self.failed('Verify traffic failed')

        with steps.start('Doing Config Replace to replace the configs on orphan and standalone'):
            if verify_config_replace([prim_vtep], log):
                log.info('Config-Replace success')
            else:
                self.failed('Config-Replace failed')

            log.info('Waiting 60secs for mac relearning')
            time.sleep(60)
            
            log.info("Display configs..")
            display_configs(testscript)
    
        with steps.start("Stopping hosts..."):
            ixNetwork.StopAllProtocols()
            log.info('Waiting 10secs to stop hosts')
            time.sleep(10)

        with steps.start('Change vlan id to orphan and configure mac/ip of same'):
            eth = p1_handle.DeviceGroup.find()[0].Ethernet.find()[0].update()
            eth.Mac.Increment(start_value=tgen_dict1['mac'], step_value=tgen_dict1['mac_step'])
            eth.EnableVlans.Single(True)
            eth.Vlan.find()[0].VlanId.Increment(
                start_value=tgen_dict1['vlan_id1'], step_value=tgen_dict1['vlan_id_step']
            )

            ipv4 = p1_handle.DeviceGroup.find().Ethernet.find().Ipv4.find().update()
            ipv4.Address.Increment(start_value=tgen_dict1['v4_addr'], step_value=tgen_dict1['v4_addr_step'])
            ipv4.GatewayIp.Increment(
                start_value=tgen_dict1['v4_gateway'], step_value=tgen_dict1['v4_gateway_step']
            )
            ipv4.Prefix.Single('16')
        
        with steps.start('Update traffic item'):
            with steps.start("Starting hosts..."):
                p1_handle.Start()
                p2_handle.Start()

            ixNetwork.Traffic.TrafficItem.find(Name='Trunk Orphan To Standalone').remove()
            tItem = ixNetwork.Traffic.TrafficItem.add(
                Name='Trunk Orphan To Standalone',
                BiDirectional=True,
                TrafficType='ipv4',
            )
            tItem.EndpointSet.add(Sources=p1_handle, Destinations=p2_handle)
            configElement = tItem.ConfigElement.find()[0]
            configElement.FrameRate.update(Type='framesPerSecond', Rate=1000.00)
            configElement.TransmissionControl.update(Type='continuous')
            configElement.FrameSize.FixedSize = 800

            tItem.Tracking.find()[0].TrackBy = ["ethernetIiSourceaddress0"]
            tItem.Generate()
            ixNetwork.Traffic.Apply()
            
        log.info('Waiting {}secs to start hosts'.format(host_start_time))
        time.sleep(host_start_time)
        
    #     stream1 = ixNetwork.Traffic.TrafficItem.find(Name='Trunk Orphan To Standalone')
    #     stream1.StartStatelessTraffic()
    #     log.info('Waiting {}secs to start the traffic'.format(traffic_start_time))
    #     time.sleep(traffic_start_time)
        
    #     stream1.StopStatelessTraffic()
    #     log.info('Waiting {}secs to stop the traffic'.format(traffic_stop_time))
    #     time.sleep(traffic_stop_time)
        
    #     with steps.start("checking mac learning for primary orphan mac"):
    #         if not verify_mac_on_vteps([prim_vtep, sec_vtep, sa_vtep], '1001', 1025, prim_mac):
    #             log.error("Mac learning failed for orpan mac")
    #             self.failed("Mac learning failed for orphan mac")
                
    #     with steps.start("Checking mac learning for standalone mac"):
    #         if not verify_mac_on_vteps([prim_vtep, sec_vtep, sa_vtep], '1002', 1025, sa_mac):
    #             log.error("Mac learning failed for standalone mac")
    #             self.failed("Mac learning failed for standalone mac")
        
    #     with steps.start("Verify Steady State"):
    #         if VerifyTraffic("TC_VXLAN_PVMAP_006", testscript, traffic_item='Trunk Orphan To Standalone'):
    #             log.info('Verify traffic success')
    #         else:
    #             self.failed('Verify traffic failed')

    # @aetest.test
    # def verify_error_cores(self, testscript, testbed, steps):
    #     sa_vtep         = testscript.parameters['LEAF-3']
    #     prim_vtep       = testscript.parameters['LEAF-1']
    #     sec_vtep        = testscript.parameters['LEAF-2']
    #     ixNetwork       = testscript.parameters['ixNetwork']

    #     with steps.start("Stopping hosts..."):
    #         ixNetwork.StopAllProtocols()
        
    #     log.info('Waiting {}secs to stop the traffic'.format(traffic_stop_time))
    #     time.sleep(traffic_stop_time)
        
    #     with steps.start("Verifying MTS leak.."):
    #         if verify_mts_leak([prim_vtep, sec_vtep, sa_vtep], log):
    #             log.info('MTS Leak verification success')
    #         else:
    #             self.failed('MTS Leak verification failed')

    #     with steps.start("Verifying Cores and Log Errors"):
    #         status = infraVerify.postTestVerification(post_test_process_dict)
    #         if status['status'] == 0:
    #             self.failed(reason=status['logs'])
    #         else:
    #             self.passed(reason=status['logs'])

# =============================================================================================================================#
# TC-ID: TC_VXLAN_PVMAP_007
# Testcase:
#   - Remove vlan mapping 
#   - Check mac gets flushed out
#   - Check traffic dropped
#   - Add vlan mapping
#   - Check traffic
# =============================================================================================================================#
class TC_VXLAN_PVMAP_007(aetest.Testcase):
    @aetest.test
    def testcase_7(self, testscript, steps):
        sa_vtep         = testscript.parameters['LEAF-3']
        prim_vtep       = testscript.parameters['LEAF-1']
        sec_vtep        = testscript.parameters['LEAF-2']
        prim_mac        = str(testscript.parameters['PVMAP_Dict']['prim_vpc_mac'])
        sa_mac          = str(testscript.parameters['PVMAP_Dict']['sa_mac'])
        p1_handle       = testscript.parameters['vpc_handle']
        p2_handle       = testscript.parameters['sa_handle']
        ixNetwork       = testscript.parameters['ixNetwork']

        with steps.start("Starting hosts..."):
            p1_handle.Start()
            p2_handle.Start()
        
        log.info('Waiting {}secs to start hosts'.format(host_start_time))
        time.sleep(host_start_time)

        stream1 = ixNetwork.Traffic.TrafficItem.find(Name='Trunk VPC To Standalone')
        stream1.StartStatelessTraffic()
        log.info('Waiting {}secs to start the traffic'.format(traffic_start_time))
        time.sleep(traffic_start_time)
        
        stream1.StopStatelessTraffic()
        log.info('Waiting {}secs to stop the traffic'.format(traffic_stop_time))
        time.sleep(traffic_stop_time)

        with steps.start("checking mac learning on orphan --> remote"):
            if not verify_mac_on_vteps([prim_vtep, sec_vtep, sa_vtep], '1001', 1025, prim_mac):
                log.error("Mac learning failed for orphan mac")
                self.failed("Mac learning failed for orphan mac")

        with steps.start("Checking mac learning for standalone mac"):
            if not verify_mac_on_vteps([prim_vtep, sec_vtep, sa_vtep], '1002', 1025, sa_mac):
                log.error("Mac learning failed for standalone mac")
                self.failed("Mac learning failed for standalone mac")

        with steps.start("Remove disable vlan mapping from vpc port-channel"):
            try:
                prim_vtep.configure('''interface port-channel 11
                                       no switchport vlan mapping enable''')
                sec_vtep.configure('''interface port-channel 11
                                      no switchport vlan mapping enable''')
            except Exception as error:
                log.debug("Unable to configure - Encountered Exception " + str(error))
                self.errored('Exception occurred while configuring PVMAP', 
                             goto=['common_cleanup']) 
        
        log.info('Waiting 160secs for mac flushout')
        time.sleep(160)

        with steps.start("checking mac flushout for vpc mac"):
            if not verify_mac_on_vteps([prim_vtep, sec_vtep, sa_vtep], '1001', 0, prim_mac):
                log.error("Mac learning failed for orphan mac")
                self.failed("Mac learning failed for orphan mac")

        with steps.start("Checking mac learning for standalone mac"):
            if not verify_mac_on_vteps([prim_vtep, sec_vtep, sa_vtep], '1002', 1025, sa_mac):
                log.error("Mac learning failed for standalone mac")
                self.failed("Mac learning failed for standalone mac")
        
        with steps.start("Verify traffic drop"):
            if VerifyTrafficDrop("TC_VXLAN_PVMAP_007", testscript, traffic_item='Trunk VPC To Standalone'):
                log.info('Verify traffic drop validation success')
            else:
                self.failed('Verify traffic validation failed') 

        with steps.start("Add member to vpc port-channel"):
            try:
                prim_vtep.configure('''interface port-channel 11
                                       switchport vlan mapping enable''')
                sec_vtep.configure('''interface port-channel 11
                                      switchport vlan mapping enable''')
            except Exception as error:
                log.debug("Unable to configure - Encountered Exception " + str(error))
                self.errored('Exception occurred while configuring PVMAP', 
                             goto=['common_cleanup']) 
        
        log.info('Waiting 60secs for mac relearning')
        time.sleep(60)
        
        stream1.StartStatelessTraffic()
        log.info('Waiting {}secs to start the traffic'.format(traffic_start_time))
        time.sleep(traffic_start_time)
        
        stream1.StopStatelessTraffic()
        log.info('Waiting {}secs to stop the traffic'.format(traffic_stop_time))
        time.sleep(traffic_stop_time)

        with steps.start("checking mac learning after mapping enable for vpc mac"):
            if not verify_mac_on_vteps([prim_vtep, sec_vtep, sa_vtep], '1001', 1025, prim_mac):
                log.error("Mac learning failed for orphan mac")
                self.failed("Mac learning failed for orphan mac")

        with steps.start("checking mac learning after mapping enable for standalone mac"):
            if not verify_mac_on_vteps([prim_vtep, sec_vtep, sa_vtep], '1002', 1025, sa_mac):
                log.error("Mac learning failed for standalone mac")
                self.failed("Mac learning failed for standalone mac")

        with steps.start('Verify Learned mac address consistency between hardware and software'):
            if verify_mac_cc_between_hardware_software([prim_vtep, sec_vtep, sa_vtep]):
                log.info('MAC CC success')
            else:
                self.failed('MAC CC failed')

        with steps.start("Verify Steady State"):
            if VerifyTraffic("TC_VXLAN_PVMAP_007", testscript, traffic_item='Trunk VPC To Standalone'):
                log.info('Verify traffic success')
            else:
                self.failed('Verify traffic failed') 

    @aetest.test
    def verify_error_cores(self, testscript, testbed, steps):
        sa_vtep         = testscript.parameters['LEAF-3']
        prim_vtep       = testscript.parameters['LEAF-1']
        sec_vtep        = testscript.parameters['LEAF-2']
        ixNetwork       = testscript.parameters['ixNetwork']

        with steps.start("Stopping hosts..."):
            ixNetwork.StopAllProtocols()
        
        with steps.start("Add member to vpc port-channel"):
            try:
                prim_vtep.configure('''interface port-channel 11
                                       switchport vlan mapping enable''')
                sec_vtep.configure('''interface port-channel 11
                                      switchport vlan mapping enable''')
            except Exception as error:
                log.debug("Unable to configure - Encountered Exception " + str(error))
                self.errored('Exception occurred while configuring PVMAP', 
                             goto=['common_cleanup']) 
        
        log.info('Waiting {}secs'.format(traffic_stop_time))
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
# TC-ID: TC_VXLAN_PVMAP_008
# Testcase:
#   - Change mode from trunk to access
#   - Check mac gets flushed out
#   - Check traffic dropped
#   - change back trunk mode
#   - Check traffic
# =============================================================================================================================#
class TC_VXLAN_PVMAP_008(aetest.Testcase):
    @aetest.test
    def testcase_vpc(self, testscript, steps):
        sa_vtep         = testscript.parameters['LEAF-3']
        prim_vtep       = testscript.parameters['LEAF-1']
        sec_vtep        = testscript.parameters['LEAF-2']
        prim_mac        = str(testscript.parameters['PVMAP_Dict']['prim_vpc_mac'])
        sa_mac          = str(testscript.parameters['PVMAP_Dict']['sa_mac'])
        p1_handle       = testscript.parameters['vpc_handle']
        p2_handle       = testscript.parameters['sa_handle']
        ixNetwork       = testscript.parameters['ixNetwork']
        vlan            = int(testscript.parameters['LEAF_1_Orphan1_TGEN_dict']['vlan_id'])
        vlan1           = int(testscript.parameters['LEAF_1_Orphan1_TGEN_dict']['vlan_id1'])

        with steps.start("Starting hosts..."):
            p1_handle.Start()
            p2_handle.Start()
        
        log.info('Waiting {}secs to start hosts'.format(host_start_time))
        time.sleep(host_start_time)

        stream1 = ixNetwork.Traffic.TrafficItem.find(Name='Trunk VPC To Standalone')
        stream1.StartStatelessTraffic()
        log.info('Waiting {}secs to start the traffic'.format(traffic_start_time))
        time.sleep(traffic_start_time)
        
        stream1.StopStatelessTraffic()
        log.info('Waiting {}secs to stop the traffic'.format(traffic_stop_time))
        time.sleep(traffic_stop_time)

        with steps.start("checking mac learning for orphan mac"):
            if not verify_mac_on_vteps([prim_vtep, sec_vtep, sa_vtep], '1001', 1025, prim_mac):
                log.error("Mac learning failed for orphan mac")
                self.failed("Mac learning failed for orphan mac")

        with steps.start("Checking mac learning for standalone mac"):
            if not verify_mac_on_vteps([prim_vtep, sec_vtep, sa_vtep], '1002', 1025, sa_mac):
                log.error("Mac learning failed for standalone mac")
                self.failed("Mac learning failed for standalone mac")
        
        with steps.start("Remove disable vlan mapping from vpc port-channel"):
            try:
                prim_vtep.configure('''interface port-channel 11
                                       switchport mode access''')
                sec_vtep.configure('''interface port-channel 11
                                      switchport mode access''')
            except Exception as error:
                log.debug("Unable to configure - Encountered Exception " + str(error))
                self.errored('Exception occurred while configuring PVMAP', 
                             goto=['common_cleanup']) 
        
        output = prim_vtep.configure('''interface port-channel 11
                                       switchport vlan mapping enable''')

        if not re.search('ERROR: The command (switchport vlan mapping enable) is not supported in the current switching mode on interface', 
                         output):
            log.info("Port-Channel: PVMAP validation on access mode success")
            self.passed("Port-Channel: PVMAP validation on access mode success")
        else:
            log.error("Port-Channel: PVMAP validation on access mode failed")
            self.failed("Port-Channel: PVMAP validation on access mode failed")
            
        log.info('Waiting 60secs for mac flushout')
        time.sleep(60)

        with steps.start("checking mac flushout for vpc mac"):
            if not verify_mac_on_vteps([prim_vtep, sec_vtep, sa_vtep], '1001', 0, prim_mac):
                log.error("Mac learning failed for orphan mac")
                self.failed("Mac learning failed for orphan mac")

        with steps.start("Checking mac learning for standalone mac"):
            if not verify_mac_on_vteps([prim_vtep, sec_vtep, sa_vtep], '1002', 1025, sa_mac):
                log.error("Mac learning failed for standalone mac")
                self.failed("Mac learning failed for standalone mac")
        
        with steps.start("Verify traffic drop"):
            if VerifyTrafficDrop("TC_VXLAN_PVMAP_008", testscript, traffic_item='Trunk VPC To Standalone'):
                log.info('Verify traffic drop validation success')
            else:
                self.failed('Verify traffic validation failed') 

        with steps.start("Add member to vpc port-channel"):
            try:
                prim_vtep.configure('''interface port-channel 11
                                       switchport mode trunk
                                       switchport vlan mapping enable
                                       switchport vlan mapping {vlan1} {vlan}'''
                                       .format(vlan=vlan, vlan1=vlan1))
                sec_vtep.configure('''interface port-channel 11
                                      switchport mode trunk
                                       switchport vlan mapping enable
                                       switchport vlan mapping {vlan1} {vlan}'''
                                       .format(vlan=vlan, vlan1=vlan1))
            except Exception as error:
                log.debug("Unable to configure - Encountered Exception " + str(error))
                self.errored('Exception occurred while configuring PVMAP', 
                             goto=['common_cleanup']) 
        
        stream1.StartStatelessTraffic()
        log.info('Waiting {}secs to start the traffic'.format(traffic_start_time))
        time.sleep(traffic_start_time)
        
        stream1.StopStatelessTraffic()
        log.info('Waiting {}secs to stop the traffic'.format(traffic_stop_time))
        time.sleep(traffic_stop_time)
        
        log.info('Waiting 60secs for mac relearning')
        time.sleep(60)
        
        with steps.start("checking mac learning after mapping enable for vpc mac"):
            if not verify_mac_on_vteps([prim_vtep, sec_vtep, sa_vtep], '1001', 1025, prim_mac):
                log.error("Mac learning failed for orphan mac")
                self.failed("Mac learning failed for orphan mac")

        with steps.start("checking mac learning after mapping enable for standalone mac"):
            if not verify_mac_on_vteps([prim_vtep, sec_vtep, sa_vtep], '1002', 1025, sa_mac):
                log.error("Mac learning failed for standalone mac")
                self.failed("Mac learning failed for standalone mac")

        with steps.start('Verify Learned mac address consistency between hardware and software'):
            if verify_mac_cc_between_hardware_software([prim_vtep, sec_vtep, sa_vtep]):
                log.info('MAC CC success')
            else:
                self.failed('MAC CC failed')

        with steps.start("Verify Steady State"):
            if VerifyTraffic("TC_VXLAN_PVMAP_008", testscript, traffic_item='Trunk VPC To Standalone'):
                log.info('Verify traffic success')
            else:
                self.failed('Verify traffic failed') 

    @aetest.test
    def testcase_orphan(self, testscript, steps):
        sa_vtep         = testscript.parameters['LEAF-3']
        prim_vtep       = testscript.parameters['LEAF-1']
        sec_vtep        = testscript.parameters['LEAF-2']
        prim_mac        = str(testscript.parameters['PVMAP_Dict']['prim_orphan_mac'])
        sa_mac          = str(testscript.parameters['PVMAP_Dict']['sa_mac'])
        p1_handle       = testscript.parameters['orphan1_handle']
        p2_handle       = testscript.parameters['sa_handle']
        ixNetwork       = testscript.parameters['ixNetwork']
        prim_if         = str(testscript.parameters['intf_LEAF_1_1_to_IXIA'])
        vlan            = int(testscript.parameters['LEAF_1_Orphan1_TGEN_dict']['vlan_id'])
        vlan1           = int(testscript.parameters['LEAF_1_Orphan1_TGEN_dict']['vlan_id1'])

        with steps.start("Starting hosts..."):
            p1_handle.Start()
            p2_handle.Start()
        
        log.info('Waiting {}secs to start hosts'.format(host_start_time))
        time.sleep(host_start_time)

        stream1 = ixNetwork.Traffic.TrafficItem.find(Name='Trunk Orphan To Standalone')
        stream1.StartStatelessTraffic()
        log.info('Waiting {}secs to start the traffic'.format(traffic_start_time))
        time.sleep(traffic_start_time)
        
        stream1.StopStatelessTraffic()
        log.info('Waiting {}secs to stop the traffic'.format(traffic_stop_time))
        time.sleep(traffic_stop_time)

        with steps.start("checking mac learning for orphan mac"):
            if not verify_mac_on_vteps([prim_vtep, sec_vtep, sa_vtep], '1001', 1025, prim_mac):
                log.error("Mac learning failed for orphan mac")
                self.failed("Mac learning failed for orphan mac")

        with steps.start("Checking mac learning for standalone mac"):
            if not verify_mac_on_vteps([prim_vtep, sec_vtep, sa_vtep], '1002', 1025, sa_mac):
                log.error("Mac learning failed for standalone mac")
                self.failed("Mac learning failed for standalone mac")

        with steps.start("Change trunk to access on orphan"):
            try:
                prim_vtep.configure('''interface {intf}
                                       switchport mode access'''.format(intf=prim_if))
            except Exception as error:
                log.debug("Unable to configure - Encountered Exception " + str(error))
                self.errored('Exception occurred while configuring PVMAP', 
                             goto=['common_cleanup']) 
        
        output = prim_vtep.configure('''interface {intf}
                                       switchport vlan mapping enable'''.format(intf=prim_if))

        if not re.search('ERROR: The command (switchport vlan mapping enable) is not supported in the current switching mode on interface', 
                         output):
            log.info("Orphan: PVMAP validation on access mode success")
            self.passed("Orphan: PVMAP validation on access mode success")
        else:
            log.error("Orphan: PVMAP validation on access mode failed")
            self.failed("Orphan: PVMAP validation on access mode failed")
        
        log.info('Waiting 60secs for mac flushout')
        time.sleep(60)

        with steps.start("checking mac flushout for orphan mac"):
            if not verify_mac_on_vteps([prim_vtep, sec_vtep, sa_vtep], '1001', 0, prim_mac):
                log.error("Mac learning failed for orphan mac")
                self.failed("Mac learning failed for orphan mac")

        with steps.start("Checking mac learning for standalone mac"):
            if not verify_mac_on_vteps([prim_vtep, sec_vtep, sa_vtep], '1002', 1025, sa_mac):
                log.error("Mac learning failed for standalone mac")
                self.failed("Mac learning failed for standalone mac")
        
        with steps.start("Verify traffic drop"):
            if VerifyTrafficDrop("TC_VXLAN_PVMAP_008", testscript, traffic_item='Trunk Orphan To Standalone'):
                log.info('Verify traffic drop validation success')
            else:
                self.failed('Verify traffic validation failed') 

        with steps.start("Change back from access to trunk mode"):
            try:
                prim_vtep.configure('''interface {intf}
                                       switchport mode trunk
                                       switchport vlan mapping enable
                                       switchport vlan mapping {vlan1} {vlan}'''.
                                       format(vlan=vlan, vlan1=vlan1, intf=prim_if))
            except Exception as error:
                log.debug("Unable to configure - Encountered Exception " + str(error))
                self.errored('Exception occurred while configuring PVMAP', 
                             goto=['common_cleanup']) 
        
        stream1.StartStatelessTraffic()
        log.info('Waiting {}secs to start the traffic'.format(traffic_start_time))
        time.sleep(traffic_start_time)
        
        stream1.StopStatelessTraffic()
        log.info('Waiting {}secs to stop the traffic'.format(traffic_stop_time))
        time.sleep(traffic_stop_time)
        
        log.info('Waiting 60secs for mac relearning')
        time.sleep(60)
        
        with steps.start("checking mac learning after mapping enable for  orphan mac"):
            if not verify_mac_on_vteps([prim_vtep, sec_vtep, sa_vtep], '1001', 1025, prim_mac):
                log.error("Mac learning failed for orphan mac")
                self.failed("Mac learning failed for orphan mac")

        with steps.start("checking mac learning after mapping enable for standalone mac"):
            if not verify_mac_on_vteps([prim_vtep, sec_vtep, sa_vtep], '1002', 1025, sa_mac):
                log.error("Mac learning failed for standalone mac")
                self.failed("Mac learning failed for standalone mac")

        with steps.start('Verify Learned mac address consistency between hardware and software'):
            if verify_mac_cc_between_hardware_software([prim_vtep, sec_vtep, sa_vtep]):
                log.info('MAC CC success')
            else:
                self.failed('MAC CC failed')

        with steps.start("Verify Steady State"):
            if VerifyTraffic("TC_VXLAN_PVMAP_008", testscript, traffic_item='Trunk Orphan To Standalone'):
                log.info('Verify traffic success')
            else:
                self.failed('Verify traffic failed') 


    @aetest.test
    def verify_error_cores(self, testscript, testbed, steps):
        sa_vtep         = testscript.parameters['LEAF-3']
        prim_vtep       = testscript.parameters['LEAF-1']
        sec_vtep        = testscript.parameters['LEAF-2']
        ixNetwork       = testscript.parameters['ixNetwork']
        vlan            = int(testscript.parameters['LEAF_1_Orphan1_TGEN_dict']['vlan_id'])
        vlan1           = int(testscript.parameters['LEAF_1_Orphan1_TGEN_dict']['vlan_id1'])
        prim_if         = str(testscript.parameters['intf_LEAF_1_1_to_IXIA'])

        with steps.start("Stopping hosts..."):
            ixNetwork.StopAllProtocols()

        log.info('Waiting {}secs'.format(traffic_stop_time))
        time.sleep(traffic_stop_time)

        with steps.start("Add member to vpc port-channel"):
            try:
                prim_vtep.configure('''interface port-channel 11
                                       switchport mode trunk
                                       switchport vlan mapping enable
                                       switchport vlan mapping {vlan1} {vlan}'''.format(vlan=vlan, vlan1=vlan1))
                sec_vtep.configure('''interface port-channel 11
                                      switchport mode trunk
                                       switchport vlan mapping enable
                                       switchport vlan mapping {vlan1} {vlan}'''.format(vlan=vlan, vlan1=vlan1))
            except Exception as error:
                log.debug("Unable to configure - Encountered Exception " + str(error))
                self.errored('Exception occurred while configuring PVMAP', 
                             goto=['common_cleanup']) 
        
        with steps.start("Change back from access to trunk mode"):
            try:
                prim_vtep.configure('''interface {intf}
                                       switchport mode trunk
                                       switchport vlan mapping enable
                                       switchport vlan mapping {vlan1} {vlan}'''.
                                       format(vlan=vlan, vlan1=vlan1, intf=prim_if))
            except Exception as error:
                log.debug("Unable to configure - Encountered Exception " + str(error))
                self.errored('Exception occurred while configuring PVMAP', 
                             goto=['common_cleanup']) 
        
        log.info('Waiting 60secs for mac relearning')
        time.sleep(60)
        
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
# TC-ID: TC_VXLAN_PVMAP_009
# Testcase:
#   - Remove translated vlan from trunk allowed list
#   - Check mac gets flushed out
#   - Check traffic dropped
#   - Add vlan back into trunk allowed list
#   - Check traffic
# =============================================================================================================================#
class TC_VXLAN_PVMAP_009(aetest.Testcase):
    @aetest.test
    def testcase_vpc(self, testscript, steps):
        sa_vtep         = testscript.parameters['LEAF-3']
        prim_vtep       = testscript.parameters['LEAF-1']
        sec_vtep        = testscript.parameters['LEAF-2']
        prim_mac        = str(testscript.parameters['PVMAP_Dict']['prim_vpc_mac'])
        sa_mac          = str(testscript.parameters['PVMAP_Dict']['sa_mac'])
        p1_handle       = testscript.parameters['vpc_handle']
        p2_handle       = testscript.parameters['sa_handle']
        ixNetwork       = testscript.parameters['ixNetwork']
        vlan            = int(testscript.parameters['LEAF_1_Orphan1_TGEN_dict']['vlan_id'])
        vlan1           = int(testscript.parameters['LEAF_1_Orphan1_TGEN_dict']['vlan_id1'])

        with steps.start("Starting hosts..."):
            p1_handle.Start()
            p2_handle.Start()
        
        log.info('Waiting {}secs to start hosts'.format(host_start_time))
        time.sleep(host_start_time)

        stream1 = ixNetwork.Traffic.TrafficItem.find(Name='Trunk VPC To Standalone')
        stream1.StartStatelessTraffic()
        log.info('Waiting {}secs to start the traffic'.format(traffic_start_time))
        time.sleep(traffic_start_time)
        
        stream1.StopStatelessTraffic()
        log.info('Waiting {}secs to stop the traffic'.format(traffic_stop_time))
        time.sleep(traffic_stop_time)

        with steps.start("checking mac learning for orphan mac"):
            if not verify_mac_on_vteps([prim_vtep, sec_vtep, sa_vtep], '1001', 1025, prim_mac):
                log.error("Mac learning failed for orphan mac")
                self.failed("Mac learning failed for orphan mac")

        with steps.start("Checking mac learning for standalone mac"):
            if not verify_mac_on_vteps([prim_vtep, sec_vtep, sa_vtep], '1002', 1025, sa_mac):
                log.error("Mac learning failed for standalone mac")
                self.failed("Mac learning failed for standalone mac")

        with steps.start("Remove translated vlan from trunk list"):
            try:
                prim_vtep.configure('''interface port-channel 11
                                       switchport trunk allowed vlan remove {vlan}'''
                                       .format(vlan=vlan))
                sec_vtep.configure('''interface port-channel 11
                                      switchport trunk allowed vlan remove {vlan}'''
                                      .format(vlan=vlan))
            except Exception as error:
                log.debug("Unable to configure - Encountered Exception " + str(error))
                self.errored('Exception occurred while configuring PVMAP', 
                             goto=['common_cleanup']) 
        
        log.info('Waiting 60secs for mac flushout')
        time.sleep(60)

        with steps.start("checking mac flushout for vpc mac"):
            if not verify_mac_on_vteps([prim_vtep, sec_vtep, sa_vtep], '1001', 0, prim_mac):
                log.error("Mac learning failed for orphan mac")
                self.failed("Mac learning failed for orphan mac")

        with steps.start("Checking mac learning for standalone mac"):
            if not verify_mac_on_vteps([prim_vtep, sec_vtep, sa_vtep], '1002', 1025, sa_mac):
                log.error("Mac learning failed for standalone mac")
                self.failed("Mac learning failed for standalone mac")
        
        with steps.start("Verify traffic drop"):
            if VerifyTrafficDrop("TC_VXLAN_PVMAP_009", testscript, traffic_item='Trunk VPC To Standalone'):
                log.info('Verify traffic drop validation success')
            else:
                self.failed('Verify traffic validation failed') 

        with steps.start("Add translated vlan back trunk list"):
            try:
                prim_vtep.configure('''interface port-channel 11
                                       switchport trunk allowed vlan add {vlan}'''
                                       .format(vlan=vlan))
                sec_vtep.configure('''interface port-channel 11
                                      switchport trunk allowed vlan add {vlan}'''
                                      .format(vlan=vlan))
            except Exception as error:
                log.debug("Unable to configure - Encountered Exception " + str(error))
                self.errored('Exception occurred while configuring PVMAP', 
                             goto=['common_cleanup']) 

        stream1.StartStatelessTraffic()
        log.info('Waiting {}secs to start the traffic'.format(traffic_start_time))
        time.sleep(traffic_start_time)
        
        stream1.StopStatelessTraffic()
        log.info('Waiting {}secs to stop the traffic'.format(traffic_stop_time))
        time.sleep(traffic_stop_time)
        
        log.info('Waiting 60secs for mac relearning')
        time.sleep(60)
        
        with steps.start("checking mac learning after mapping enable for vpc mac"):
            if not verify_mac_on_vteps([prim_vtep, sec_vtep, sa_vtep], '1001', 1025, prim_mac):
                log.error("Mac learning failed for orphan mac")
                self.failed("Mac learning failed for orphan mac")

        with steps.start("checking mac learning after mapping enable for standalone mac"):
            if not verify_mac_on_vteps([prim_vtep, sec_vtep, sa_vtep], '1002', 1025, sa_mac):
                log.error("Mac learning failed for standalone mac")
                self.failed("Mac learning failed for standalone mac")

        with steps.start('Verify Learned mac address consistency between hardware and software'):
            if verify_mac_cc_between_hardware_software([prim_vtep, sec_vtep, sa_vtep]):
                log.info('MAC CC success')
            else:
                self.failed('MAC CC failed')

        with steps.start("Verify Steady State"):
            if VerifyTraffic("TC_VXLAN_PVMAP_009", testscript, traffic_item='Trunk VPC To Standalone'):
                log.info('Verify traffic success')
            else:
                self.failed('Verify traffic failed') 

    @aetest.test
    def testcase_orphan(self, testscript, steps):
        sa_vtep         = testscript.parameters['LEAF-3']
        prim_vtep       = testscript.parameters['LEAF-1']
        sec_vtep        = testscript.parameters['LEAF-2']
        prim_mac        = str(testscript.parameters['PVMAP_Dict']['prim_orphan_mac'])
        sa_mac          = str(testscript.parameters['PVMAP_Dict']['sa_mac'])
        p1_handle       = testscript.parameters['orphan1_handle']
        p2_handle       = testscript.parameters['sa_handle']
        ixNetwork       = testscript.parameters['ixNetwork']
        prim_if         = str(testscript.parameters['intf_LEAF_1_1_to_IXIA'])
        vlan            = int(testscript.parameters['LEAF_1_Orphan1_TGEN_dict']['vlan_id'])
        vlan1           = int(testscript.parameters['LEAF_1_Orphan1_TGEN_dict']['vlan_id1'])

        with steps.start("Starting hosts..."):
            p1_handle.Start()
            p2_handle.Start()
        
        log.info('Waiting {}secs to start hosts'.format(host_start_time))
        time.sleep(host_start_time)

        stream1 = ixNetwork.Traffic.TrafficItem.find(Name='Trunk Orphan To Standalone')
        stream1.StartStatelessTraffic()
        log.info('Waiting {}secs to start the traffic'.format(traffic_start_time))
        time.sleep(traffic_start_time)
        
        stream1.StopStatelessTraffic()
        log.info('Waiting {}secs to stop the traffic'.format(traffic_stop_time))
        time.sleep(traffic_stop_time)

        with steps.start("checking mac learning for orphan mac"):
            if not verify_mac_on_vteps([prim_vtep, sec_vtep, sa_vtep], '1001', 1025, prim_mac):
                log.error("Mac learning failed for orphan mac")
                self.failed("Mac learning failed for orphan mac")

        with steps.start("Checking mac learning for standalone mac"):
            if not verify_mac_on_vteps([prim_vtep, sec_vtep, sa_vtep], '1002', 1025, sa_mac):
                log.error("Mac learning failed for standalone mac")
                self.failed("Mac learning failed for standalone mac")

        with steps.start("Remove vlan from trunk list"):
            try:
                prim_vtep.configure('''interface {intf}
                                       switchport trunk allowed vlan remove {vlan}'''
                                       .format(intf=prim_if, vlan=vlan))
            except Exception as error:
                log.debug("Unable to configure - Encountered Exception " + str(error))
                self.errored('Exception occurred while configuring PVMAP', 
                             goto=['common_cleanup']) 
        
        log.info('Waiting 60secs for mac flushout')
        time.sleep(60)

        with steps.start("checking mac flushout for orphan mac"):
            if not verify_mac_on_vteps([prim_vtep, sec_vtep, sa_vtep], '1001', 0, prim_mac):
                log.error("Mac learning failed for orphan mac")
                self.failed("Mac learning failed for orphan mac")

        with steps.start("Checking mac learning for standalone mac"):
            if not verify_mac_on_vteps([prim_vtep, sec_vtep, sa_vtep], '1002', 1025, sa_mac):
                log.error("Mac learning failed for standalone mac")
                self.failed("Mac learning failed for standalone mac")
        
        with steps.start("Verify traffic drop"):
            if VerifyTrafficDrop("TC_VXLAN_PVMAP_009", testscript, traffic_item='Trunk Orphan To Standalone'):
                log.info('Verify traffic drop validation success')
            else:
                self.failed('Verify traffic validation failed') 

        with steps.start("Add vlan to trunk list"):
            try:
                prim_vtep.configure('''interface {intf}
                                       switchport trunk allowed vlan add {vlan}'''
                                       .format(intf=prim_if, vlan=vlan))
            except Exception as error:
                log.debug("Unable to configure - Encountered Exception " + str(error))
                self.errored('Exception occurred while configuring PVMAP', 
                             goto=['common_cleanup']) 

        log.info('Waiting 60secs for mac relearning')
        time.sleep(60)
        
        stream1.StartStatelessTraffic()
        log.info('Waiting {}secs to start the traffic'.format(traffic_start_time))
        time.sleep(traffic_start_time)
        
        stream1.StopStatelessTraffic()
        log.info('Waiting {}secs to stop the traffic'.format(traffic_stop_time))
        time.sleep(traffic_stop_time)
        
        with steps.start("checking mac learning after mapping enable for  orphan mac"):
            if not verify_mac_on_vteps([prim_vtep, sec_vtep, sa_vtep], '1001', 1025, prim_mac):
                log.error("Mac learning failed for orphan mac")
                self.failed("Mac learning failed for orphan mac")

        with steps.start("checking mac learning after mapping enable for standalone mac"):
            if not verify_mac_on_vteps([prim_vtep, sec_vtep, sa_vtep], '1002', 1025, sa_mac):
                log.error("Mac learning failed for standalone mac")
                self.failed("Mac learning failed for standalone mac")

        with steps.start('Verify Learned mac address consistency between hardware and software'):
            if verify_mac_cc_between_hardware_software([prim_vtep, sec_vtep, sa_vtep]):
                log.info('MAC CC success')
            else:
                self.failed('MAC CC failed')

        with steps.start("Verify Steady State"):
            if VerifyTraffic("TC_VXLAN_PVMAP_009", testscript, traffic_item='Trunk Orphan To Standalone'):
                log.info('Verify traffic success')
            else:
                self.failed('Verify traffic failed') 


    @aetest.test
    def verify_error_cores(self, testscript, testbed, steps):
        sa_vtep         = testscript.parameters['LEAF-3']
        prim_vtep       = testscript.parameters['LEAF-1']
        sec_vtep        = testscript.parameters['LEAF-2']
        ixNetwork       = testscript.parameters['ixNetwork']
        vlan            = int(testscript.parameters['LEAF_1_Orphan1_TGEN_dict']['vlan_id'])
        vlan1           = int(testscript.parameters['LEAF_1_Orphan1_TGEN_dict']['vlan_id1'])
        prim_if         = str(testscript.parameters['intf_LEAF_1_1_to_IXIA'])

        with steps.start("Stopping hosts..."):
            ixNetwork.StopAllProtocols()

        log.info('Waiting {}secs'.format(traffic_stop_time))
        time.sleep(traffic_stop_time)

        with steps.start("Add translated vlan back trunk list"):
            try:
                prim_vtep.configure('''interface port-channel 11
                                       switchport trunk allowed vlan add {vlan}'''
                                       .format(vlan=vlan))
                sec_vtep.configure('''interface port-channel 11
                                      switchport trunk allowed vlan add {vlan}'''
                                      .format(vlan=vlan))
            except Exception as error:
                log.debug("Unable to configure - Encountered Exception " + str(error))
                self.errored('Exception occurred while configuring PVMAP', 
                             goto=['common_cleanup'])  
        
        with steps.start("Add vlan to trunk list"):
            try:
                prim_vtep.configure('''interface {intf}
                                       switchport trunk allowed vlan add {vlan}'''
                                       .format(intf=prim_if, vlan=vlan))
            except Exception as error:
                log.debug("Unable to configure - Encountered Exception " + str(error))
                self.errored('Exception occurred while configuring PVMAP', 
                             goto=['common_cleanup']) 
        
        log.info('Waiting 60secs for mac relearning')
        time.sleep(60)
        
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
# TC-ID: TC_VXLAN_PVMAP_010
# Testcase:
#   - Default interface of orphan, standand and vpc po
#   - Check mac gets flushed out
#   - Check traffic dropped
#   - Do config-replace to add vlan mappings back
#   - Check traffic
# =============================================================================================================================#
class TC_VXLAN_PVMAP_010(aetest.Testcase):
    @aetest.test
    def testcase_vpc(self, testscript, steps):
        sa_vtep         = testscript.parameters['LEAF-3']
        prim_vtep       = testscript.parameters['LEAF-1']
        sec_vtep        = testscript.parameters['LEAF-2']
        prim_mac        = str(testscript.parameters['PVMAP_Dict']['prim_vpc_mac'])
        sa_mac          = str(testscript.parameters['PVMAP_Dict']['sa_mac'])
        p1_handle       = testscript.parameters['vpc_handle']
        p2_handle       = testscript.parameters['sa_handle']
        ixNetwork       = testscript.parameters['ixNetwork']
        vlan            = int(testscript.parameters['LEAF_1_Orphan1_TGEN_dict']['vlan_id'])
        vlan1           = int(testscript.parameters['LEAF_1_Orphan1_TGEN_dict']['vlan_id1'])

        with steps.start("Starting hosts..."):
            p1_handle.Start()
            p2_handle.Start()
        
        log.info('Waiting {}secs to start hosts'.format(host_start_time))
        time.sleep(host_start_time)

        stream1 = ixNetwork.Traffic.TrafficItem.find(Name='Trunk VPC To Standalone')
        stream1.StartStatelessTraffic()
        log.info('Waiting {}secs to start the traffic'.format(traffic_start_time))
        time.sleep(traffic_start_time)
        
        stream1.StopStatelessTraffic()
        log.info('Waiting {}secs to stop the traffic'.format(traffic_stop_time))
        time.sleep(traffic_stop_time)

        with steps.start("checking mac learning for orphan mac"):
            if not verify_mac_on_vteps([prim_vtep, sec_vtep, sa_vtep], '1001', 1025, prim_mac):
                log.error("Mac learning failed for orphan mac")
                self.failed("Mac learning failed for orphan mac")

        with steps.start("Checking mac learning for standalone mac"):
            if not verify_mac_on_vteps([prim_vtep, sec_vtep, sa_vtep], '1002', 1025, sa_mac):
                log.error("Mac learning failed for standalone mac")
                self.failed("Mac learning failed for standalone mac")

        with steps.start('Do Config backup on Primary, Secondary and Standalone'):
            prim_vtep.execute('delete bootflash:{cr_file} no-prompt'.format(cr_file=cr_file))
            sec_vtep.execute('delete bootflash:{cr_file} no-prompt'.format(cr_file=cr_file))
            prim_vtep.execute("copy running-config bootflash:{cr_file}".format(cr_file=cr_file))
            sec_vtep.execute("copy running-config bootflash:{cr_file}".format(cr_file=cr_file))

        with steps.start("Default interface po11"):
            try:
                prim_vtep.configure('''default interface port-channel 11''')
                sec_vtep.configure('''default interface port-channel 11''' )
            except Exception as error:
                log.debug("Unable to configure - Encountered Exception " + str(error))
                self.errored('Exception occurred while configuring PVMAP', 
                             goto=['common_cleanup']) 
        
        log.info('Waiting 60secs for mac flushout')
        time.sleep(60)

        with steps.start("checking mac flushout for vpc mac"):
            if not verify_mac_on_vteps([prim_vtep, sec_vtep, sa_vtep], '1001', 0, prim_mac):
                log.error("Mac learning failed for orphan mac")
                self.failed("Mac learning failed for orphan mac")

        with steps.start("Checking mac learning for standalone mac"):
            if not verify_mac_on_vteps([prim_vtep, sec_vtep, sa_vtep], '1002', 1025, sa_mac):
                log.error("Mac learning failed for standalone mac")
                self.failed("Mac learning failed for standalone mac")
        
        with steps.start("Verify traffic drop"):
            if VerifyTrafficDrop("TC_VXLAN_PVMAP_010", testscript, traffic_item='Trunk VPC To Standalone'):
                log.info('Verify traffic drop validation success')
            else:
                self.failed('Verify traffic validation failed') 

        with steps.start('Doing Config Replace to replace the configs on orphan and standalone'):
            if verify_config_replace([prim_vtep, sec_vtep], log):
                log.info('Config-Replace success')
            else:
                self.failed('Config-Replace failed')

        stream1.StartStatelessTraffic()
        log.info('Waiting {}secs to start the traffic'.format(traffic_start_time))
        time.sleep(traffic_start_time)
        
        stream1.StopStatelessTraffic()
        log.info('Waiting {}secs to stop the traffic'.format(traffic_stop_time))
        time.sleep(traffic_stop_time)
        
        log.info('Waiting 60secs for mac relearning')
        time.sleep(60)
        
        with steps.start("checking mac learning after mapping enable for vpc mac"):
            if not verify_mac_on_vteps([prim_vtep, sec_vtep, sa_vtep], '1001', 1025, prim_mac):
                log.error("Mac learning failed for orphan mac")
                self.failed("Mac learning failed for orphan mac")

        with steps.start("checking mac learning after mapping enable for standalone mac"):
            if not verify_mac_on_vteps([prim_vtep, sec_vtep, sa_vtep], '1002', 1025, sa_mac):
                log.error("Mac learning failed for standalone mac")
                self.failed("Mac learning failed for standalone mac")

        with steps.start('Verify Learned mac address consistency between hardware and software'):
            if verify_mac_cc_between_hardware_software([prim_vtep, sec_vtep, sa_vtep]):
                log.info('MAC CC success')
            else:
                self.failed('MAC CC failed')

        with steps.start("Verify Steady State"):
            if VerifyTraffic("TC_VXLAN_PVMAP_010", testscript, traffic_item='Trunk VPC To Standalone'):
                log.info('Verify traffic success')
            else:
                self.failed('Verify traffic failed') 

    @aetest.test
    def testcase_orphan(self, testscript, steps):
        sa_vtep         = testscript.parameters['LEAF-3']
        prim_vtep       = testscript.parameters['LEAF-1']
        sec_vtep        = testscript.parameters['LEAF-2']
        prim_mac        = str(testscript.parameters['PVMAP_Dict']['prim_orphan_mac'])
        sa_mac          = str(testscript.parameters['PVMAP_Dict']['sa_mac'])
        p1_handle       = testscript.parameters['orphan1_handle']
        p2_handle       = testscript.parameters['sa_handle']
        ixNetwork       = testscript.parameters['ixNetwork']
        prim_if         = str(testscript.parameters['intf_LEAF_1_1_to_IXIA'])
        sa_if           = str(testscript.parameters['intf_LEAF_3_to_IXIA'])

        with steps.start("Starting hosts..."):
            p1_handle.Start()
            p2_handle.Start()
        
        log.info('Waiting {}secs to start hosts'.format(host_start_time))
        time.sleep(host_start_time)

        stream1 = ixNetwork.Traffic.TrafficItem.find(Name='Trunk Orphan To Standalone')
        stream1.StartStatelessTraffic()
        log.info('Waiting {}secs to start the traffic'.format(traffic_start_time))
        time.sleep(traffic_start_time)
        
        stream1.StopStatelessTraffic()
        log.info('Waiting {}secs to stop the traffic'.format(traffic_stop_time))
        time.sleep(traffic_stop_time)

        with steps.start("checking mac learning for orphan mac"):
            if not verify_mac_on_vteps([prim_vtep, sec_vtep, sa_vtep], '1001', 1025, prim_mac):
                log.error("Mac learning failed for orphan mac")
                self.failed("Mac learning failed for orphan mac")

        with steps.start("Checking mac learning for standalone mac"):
            if not verify_mac_on_vteps([prim_vtep, sec_vtep, sa_vtep], '1002', 1025, sa_mac):
                log.error("Mac learning failed for standalone mac")
                self.failed("Mac learning failed for standalone mac")

        with steps.start('Do Config backup on Primary, Secondary and Standalone'):
            prim_vtep.execute('delete bootflash:{cr_file} no-prompt'.format(cr_file=cr_file))
            sa_vtep.execute('delete bootflash:{cr_file} no-prompt'.format(cr_file=cr_file))
            prim_vtep.execute("copy running-config bootflash:{cr_file}".format(cr_file=cr_file))
            sa_vtep.execute("copy running-config bootflash:{cr_file}".format(cr_file=cr_file))
        
        with steps.start("Default interface orphan and standalone"):
            try:
                prim_vtep.configure('''default interface {intf}'''.format(intf=prim_if))
                sa_vtep.configure('''default interface {intf}'''.format(intf=sa_if))
            except Exception as error:
                log.debug("Unable to configure - Encountered Exception " + str(error))
                self.errored('Exception occurred while configuring PVMAP', 
                             goto=['common_cleanup']) 
        
        log.info('Waiting 160secs for mac flushout')
        time.sleep(160)

        with steps.start("checking mac flushout for orphan mac"):
            if not verify_mac_on_vteps([prim_vtep, sec_vtep, sa_vtep], '1001', 0, prim_mac):
                log.error("Mac learning failed for orphan mac")
                self.failed("Mac learning failed for orphan mac")

        with steps.start("Checking mac learning for standalone mac"):
            if not verify_mac_on_vteps([prim_vtep, sec_vtep, sa_vtep], '1002', 0, sa_mac):
                log.error("Mac learning failed for standalone mac")
                self.failed("Mac learning failed for standalone mac")
        
        with steps.start("Verify traffic drop"):
            if VerifyTrafficDrop("TC_VXLAN_PVMAP_010", testscript, traffic_item='Trunk Orphan To Standalone'):
                log.info('Verify traffic drop validation success')
            else:
                self.failed('Verify traffic validation failed') 

        with steps.start('Doing Config Replace to replace the configs on orphan and standalone'):
            if verify_config_replace([prim_vtep, sa_vtep], log):
                log.info('Config-Replace success')
            else:
                self.failed('Config-Replace failed')

        log.info('Waiting 60secs for mac relearning')
        time.sleep(60) 
        
        stream1.StartStatelessTraffic()
        log.info('Waiting {}secs to start the traffic'.format(traffic_start_time))
        time.sleep(traffic_start_time)
        
        stream1.StopStatelessTraffic()
        log.info('Waiting {}secs to stop the traffic'.format(traffic_stop_time))
        time.sleep(traffic_stop_time)
        
        with steps.start("checking mac learning after mapping enable for  orphan mac"):
            if not verify_mac_on_vteps([prim_vtep, sec_vtep, sa_vtep], '1001', 1025, prim_mac):
                log.error("Mac learning failed for orphan mac")
                self.failed("Mac learning failed for orphan mac")

        with steps.start("checking mac learning after mapping enable for standalone mac"):
            if not verify_mac_on_vteps([prim_vtep, sec_vtep, sa_vtep], '1002', 1025, sa_mac):
                log.error("Mac learning failed for standalone mac")
                self.failed("Mac learning failed for standalone mac")

        with steps.start('Verify Learned mac address consistency between hardware and software'):
            if verify_mac_cc_between_hardware_software([prim_vtep, sec_vtep, sa_vtep]):
                log.info('MAC CC success')
            else:
                self.failed('MAC CC failed')

        with steps.start("Verify Steady State"):
            if VerifyTraffic("TC_VXLAN_PVMAP_010", testscript, traffic_item='Trunk Orphan To Standalone'):
                log.info('Verify traffic success')
            else:
                self.failed('Verify traffic failed') 

    @aetest.test
    def verify_error_cores(self, testscript, testbed, steps):
        sa_vtep         = testscript.parameters['LEAF-3']
        prim_vtep       = testscript.parameters['LEAF-1']
        sec_vtep        = testscript.parameters['LEAF-2']
        ixNetwork       = testscript.parameters['ixNetwork']

        with steps.start("Stopping hosts..."):
            ixNetwork.StopAllProtocols()

        log.info('Waiting {}secs'.format(traffic_stop_time))
        time.sleep(traffic_stop_time)

        verify_config_replace([prim_vtep, sec_vtep, sa_vtep], log)
        
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
# TC-ID: TC_VXLAN_PVMAP_011
# Testcase:
#   - Change VNI on translated vlan
#   - Check mac gets flushed out
#   - Check traffic dropped
#   - Do config-replace to add vlan mappings back
#   - Check traffic
# =============================================================================================================================#
class TC_VXLAN_PVMAP_011(aetest.Testcase):
    @aetest.test
    def testcase_vpc(self, testscript, steps):
        sa_vtep         = testscript.parameters['LEAF-3']
        prim_vtep       = testscript.parameters['LEAF-1']
        sec_vtep        = testscript.parameters['LEAF-2']
        prim_mac        = str(testscript.parameters['PVMAP_Dict']['prim_vpc_mac'])
        sa_mac          = str(testscript.parameters['PVMAP_Dict']['sa_mac'])
        p1_handle       = testscript.parameters['vpc_handle']
        p2_handle       = testscript.parameters['sa_handle']
        ixNetwork       = testscript.parameters['ixNetwork']
        vlan            = int(testscript.parameters['LEAF_1_Orphan1_TGEN_dict']['vlan_id'])

        with steps.start("Starting hosts..."):
            p1_handle.Start()
            p2_handle.Start()
        
        log.info('Waiting {}secs to start hosts'.format(host_start_time))
        time.sleep(host_start_time)

        stream1 = ixNetwork.Traffic.TrafficItem.find(Name='Trunk VPC To Standalone')
        stream1.StartStatelessTraffic()
        log.info('Waiting {}secs to start the traffic'.format(traffic_start_time))
        time.sleep(traffic_start_time)
        
        stream1.StopStatelessTraffic()
        log.info('Waiting {}secs to stop the traffic'.format(traffic_stop_time))
        time.sleep(traffic_stop_time)

        with steps.start("checking mac learning for orphan mac"):
            if not verify_mac_on_vteps([prim_vtep, sec_vtep, sa_vtep], '1001', 1025, prim_mac):
                log.error("Mac learning failed for orphan mac")
                self.failed("Mac learning failed for orphan mac")

        with steps.start("Checking mac learning for standalone mac"):
            if not verify_mac_on_vteps([prim_vtep, sec_vtep, sa_vtep], '1002', 1025, sa_mac):
                log.error("Mac learning failed for standalone mac")
                self.failed("Mac learning failed for standalone mac")

        with steps.start('Do Config backup on Primary, Secondary and Standalone'):
            prim_vtep.execute('delete bootflash:{cr_file} no-prompt'.format(cr_file=cr_file))
            sec_vtep.execute('delete bootflash:{cr_file} no-prompt'.format(cr_file=cr_file))
            prim_vtep.execute("copy running-config bootflash:{cr_file}".format(cr_file=cr_file))
            sec_vtep.execute("copy running-config bootflash:{cr_file}".format(cr_file=cr_file))

        with steps.start("Change vni on translated vlan"):
            try:
                prim_vtep.configure('''vlan {vlan}
                                       no vn-segment
                                       vn-segment 10101
                                    '''.format(vlan=vlan))
                sec_vtep.configure('''vlan {vlan}
                                      no vn-segment
                                      vn-segment 10101
                                    '''.format(vlan=vlan))
            except Exception as error:
                log.debug("Unable to configure - Encountered Exception " + str(error))
                self.errored('Exception occurred while configuring PVMAP', 
                             goto=['common_cleanup']) 
        
        log.info('Waiting 60secs for mac flushout')
        time.sleep(60)

        with steps.start("checking mac flushout for vpc mac"):
            if not verify_mac_on_vteps([prim_vtep, sec_vtep, sa_vtep], '1001', 0, prim_mac):
                log.error("Mac learning failed for orphan mac")
                self.failed("Mac learning failed for orphan mac")

        with steps.start("Checking mac learning for standalone mac"):
            if not verify_mac_on_vteps([prim_vtep, sec_vtep, sa_vtep], '1002', 1025, sa_mac):
                log.error("Mac learning failed for standalone mac")
                self.failed("Mac learning failed for standalone mac")
        
        with steps.start("Verify traffic drop"):
            if VerifyTrafficDrop("TC_VXLAN_PVMAP_011", testscript, traffic_item='Trunk VPC To Standalone'):
                log.info('Verify traffic drop validation success')
            else:
                self.failed('Verify traffic validation failed') 
        
        with steps.start('Doing Config Replace to replace the configs on orphan and standalone'):
            if verify_config_replace([prim_vtep, sec_vtep], log):
                log.info('Config-Replace success')
            else:
                self.failed('Config-Replace failed')

        stream1.StartStatelessTraffic()
        log.info('Waiting {}secs to start the traffic'.format(traffic_start_time))
        time.sleep(traffic_start_time)
        
        stream1.StopStatelessTraffic()
        log.info('Waiting {}secs to stop the traffic'.format(traffic_stop_time))
        time.sleep(traffic_stop_time)
        
        log.info('Waiting 60secs for mac relearning')
        time.sleep(60)
        
        with steps.start("checking mac learning after mapping enable for vpc mac"):
            if not verify_mac_on_vteps([prim_vtep, sec_vtep, sa_vtep], '1001', 1025, prim_mac):
                log.error("Mac learning failed for orphan mac")
                self.failed("Mac learning failed for orphan mac")

        with steps.start("checking mac learning after mapping enable for standalone mac"):
            if not verify_mac_on_vteps([prim_vtep, sec_vtep, sa_vtep], '1002', 1025, sa_mac):
                log.error("Mac learning failed for standalone mac")
                self.failed("Mac learning failed for standalone mac")

        with steps.start('Verify Learned mac address consistency between hardware and software'):
            if verify_mac_cc_between_hardware_software([prim_vtep, sec_vtep, sa_vtep]):
                log.info('MAC CC success')
            else:
                self.failed('MAC CC failed')

        with steps.start("Verify Steady State"):
            if VerifyTraffic("TC_VXLAN_PVMAP_011", testscript, traffic_item='Trunk VPC To Standalone'):
                log.info('Verify traffic success')
            else:
                self.failed('Verify traffic failed') 

    @aetest.test
    def testcase_orphan(self, testscript, steps):
        sa_vtep         = testscript.parameters['LEAF-3']
        prim_vtep       = testscript.parameters['LEAF-1']
        sec_vtep        = testscript.parameters['LEAF-2']
        prim_mac        = str(testscript.parameters['PVMAP_Dict']['prim_orphan_mac'])
        sa_mac          = str(testscript.parameters['PVMAP_Dict']['sa_mac'])
        p1_handle       = testscript.parameters['orphan1_handle']
        p2_handle       = testscript.parameters['sa_handle']
        ixNetwork       = testscript.parameters['ixNetwork']
        vlan            = int(testscript.parameters['LEAF_1_Orphan1_TGEN_dict']['vlan_id'])
        vlan1           = int(testscript.parameters['LEAF_3_TGEN_dict']['vlan_id'])

        with steps.start("Starting hosts..."):
            p1_handle.Start()
            p2_handle.Start()
        
        log.info('Waiting {}secs to start hosts'.format(host_start_time))
        time.sleep(host_start_time)

        stream1 = ixNetwork.Traffic.TrafficItem.find(Name='Trunk Orphan To Standalone')
        stream1.StartStatelessTraffic()
        log.info('Waiting {}secs to start the traffic'.format(traffic_start_time))
        time.sleep(traffic_start_time)
        
        stream1.StopStatelessTraffic()
        log.info('Waiting {}secs to stop the traffic'.format(traffic_stop_time))
        time.sleep(traffic_stop_time)

        with steps.start("checking mac learning for orphan mac"):
            if not verify_mac_on_vteps([prim_vtep, sec_vtep, sa_vtep], '1001', 1025, prim_mac):
                log.error("Mac learning failed for orphan mac")
                self.failed("Mac learning failed for orphan mac")

        with steps.start("Checking mac learning for standalone mac"):
            if not verify_mac_on_vteps([prim_vtep, sec_vtep, sa_vtep], '1002', 1025, sa_mac):
                log.error("Mac learning failed for standalone mac")
                self.failed("Mac learning failed for standalone mac")

        with steps.start('Do Config backup on Primary, Secondary and Standalone'):
            prim_vtep.execute('delete bootflash:{cr_file} no-prompt'.format(cr_file=cr_file))
            sec_vtep.execute('delete bootflash:{cr_file} no-prompt'.format(cr_file=cr_file))
            sa_vtep.execute('delete bootflash:{cr_file} no-prompt'.format(cr_file=cr_file))
            prim_vtep.execute("copy running-config bootflash:{cr_file}".format(cr_file=cr_file))
            sec_vtep.execute("copy running-config bootflash:{cr_file}".format(cr_file=cr_file))
            sa_vtep.execute("copy running-config bootflash:{cr_file}".format(cr_file=cr_file))
        
        with steps.start("Change vni on translated vlan"):
            prim_vtep.configure('''vlan {vlan}
                                    no vn-segment
                                    vn-segment 10101
                                '''.format(vlan=vlan))
            sec_vtep.configure('''vlan {vlan}
                                    no vn-segment
                                    vn-segment 10101
                                '''.format(vlan=vlan))
            sa_vtep.configure('''vlan {vlan}
                                    no vn-segment
                                    vn-segment 10102
                                '''.format(vlan=vlan1))
        
        log.info('Waiting 120secs for mac flushout')
        time.sleep(120)

        with steps.start("Verify traffic drop"):
            if VerifyTrafficDrop("TC_VXLAN_PVMAP_011", testscript, traffic_item='Trunk Orphan To Standalone'):
                log.info('Verify traffic drop validation success')
            else:
                self.failed('Verify traffic validation failed') 

        with steps.start('Doing Config Replace to replace the configs on orphan and standalone'):
            if verify_config_replace([prim_vtep, sec_vtep, sa_vtep], log):
                log.info('Config-Replace success')
            else:
                self.failed('Config-Replace failed')

        log.info('Waiting 60secs for mac relearning')
        time.sleep(60) 
        
        stream1.StartStatelessTraffic()
        log.info('Waiting {}secs to start the traffic'.format(traffic_start_time))
        time.sleep(traffic_start_time)
        
        stream1.StopStatelessTraffic()
        log.info('Waiting {}secs to stop the traffic'.format(traffic_stop_time))
        time.sleep(traffic_stop_time)
        
        with steps.start("checking mac learning after mapping enable for  orphan mac"):
            if not verify_mac_on_vteps([prim_vtep, sec_vtep, sa_vtep], '1001', 1025, prim_mac):
                log.error("Mac learning failed for orphan mac")
                self.failed("Mac learning failed for orphan mac")

        with steps.start("checking mac learning after mapping enable for standalone mac"):
            if not verify_mac_on_vteps([prim_vtep, sec_vtep, sa_vtep], '1002', 1025, sa_mac):
                log.error("Mac learning failed for standalone mac")
                self.failed("Mac learning failed for standalone mac")

        with steps.start('Verify Learned mac address consistency between hardware and software'):
            if verify_mac_cc_between_hardware_software([prim_vtep, sec_vtep, sa_vtep]):
                log.info('MAC CC success')
            else:
                self.failed('MAC CC failed')

        with steps.start("Verify Steady State"):
            if VerifyTraffic("TC_VXLAN_PVMAP_011", testscript, traffic_item='Trunk Orphan To Standalone'):
                log.info('Verify traffic success')
            else:
                self.failed('Verify traffic failed') 

    @aetest.test
    def verify_error_cores(self, testscript, testbed, steps):
        sa_vtep         = testscript.parameters['LEAF-3']
        prim_vtep       = testscript.parameters['LEAF-1']
        sec_vtep        = testscript.parameters['LEAF-2']
        ixNetwork       = testscript.parameters['ixNetwork']

        with steps.start("Stopping hosts..."):
            ixNetwork.StopAllProtocols()

        log.info('Waiting {}secs'.format(traffic_stop_time))
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
# TC-ID: TC_VXLAN_PVMAP_012
# Testcase:
#   - Delete translated vlan VNI
#   - Check mac gets flushed out
#   - Check traffic dropped
#   - Do config-replace to add vni back
#   - Check traffic
# =============================================================================================================================#
class TC_VXLAN_PVMAP_012(aetest.Testcase):
    @aetest.test
    def testcase_vpc(self, testscript, steps):
        sa_vtep         = testscript.parameters['LEAF-3']
        prim_vtep       = testscript.parameters['LEAF-1']
        sec_vtep        = testscript.parameters['LEAF-2']
        prim_mac        = str(testscript.parameters['PVMAP_Dict']['prim_vpc_mac'])
        sa_mac          = str(testscript.parameters['PVMAP_Dict']['sa_mac'])
        p1_handle       = testscript.parameters['vpc_handle']
        p2_handle       = testscript.parameters['sa_handle']
        ixNetwork       = testscript.parameters['ixNetwork']
        vni_1           = str(testscript.parameters['LEAF_1_dict']['STATIC_IR_VNI_data']['l2_vni_start'])
        vlan            = int(testscript.parameters['LEAF_1_Orphan1_TGEN_dict']['vlan_id'])

        with steps.start("Starting hosts..."):
            p1_handle.Start()
            p2_handle.Start()
        
        log.info('Waiting {}secs to start hosts'.format(host_start_time))
        time.sleep(host_start_time)

        stream1 = ixNetwork.Traffic.TrafficItem.find(Name='Trunk VPC To Standalone')
        stream1.StartStatelessTraffic()
        log.info('Waiting {}secs to start the traffic'.format(traffic_start_time))
        time.sleep(traffic_start_time)
        
        stream1.StopStatelessTraffic()
        log.info('Waiting {}secs to stop the traffic'.format(traffic_stop_time))
        time.sleep(traffic_stop_time)

        with steps.start("checking mac learning for orphan mac"):
            if not verify_mac_on_vteps([prim_vtep, sec_vtep, sa_vtep], '1001', 1025, prim_mac):
                log.error("Mac learning failed for orphan mac")
                self.failed("Mac learning failed for orphan mac")

        with steps.start("Checking mac learning for standalone mac"):
            if not verify_mac_on_vteps([prim_vtep, sec_vtep, sa_vtep], '1002', 1025, sa_mac):
                log.error("Mac learning failed for standalone mac")
                self.failed("Mac learning failed for standalone mac")

        with steps.start('Do Config backup on Primary, Secondary and Standalone'):
            prim_vtep.execute('delete bootflash:{cr_file} no-prompt'.format(cr_file=cr_file))
            sec_vtep.execute('delete bootflash:{cr_file} no-prompt'.format(cr_file=cr_file))
            prim_vtep.execute("copy running-config bootflash:{cr_file}".format(cr_file=cr_file))
            sec_vtep.execute("copy running-config bootflash:{cr_file}".format(cr_file=cr_file))

        with steps.start("Change vni on translated vlan"):
            try:
                prim_vtep.configure('''vlan {vlan}
                                       no vn-segment {vni}
                                    '''.format(vlan=vlan, vni=vni_1))
                sec_vtep.configure('''vlan {vlan}
                                       no vn-segment {vni}
                                    '''.format(vlan=vlan, vni=vni_1))
            except Exception as error:
                log.debug("Unable to configure - Encountered Exception " + str(error))
                self.errored('Exception occurred while configuring PVMAP', 
                             goto=['common_cleanup']) 
        
        log.info('Waiting 60secs for mac flushout')
        time.sleep(60)

        with steps.start("checking mac flushout for vpc mac"):
            if not verify_mac_on_vteps([prim_vtep, sec_vtep, sa_vtep], '1001', 0, prim_mac):
                log.error("Mac learning failed for orphan mac")
                self.failed("Mac learning failed for orphan mac")

        with steps.start("Checking mac learning for standalone mac"):
            if not verify_mac_on_vteps([prim_vtep, sec_vtep, sa_vtep], '1002', 1025, sa_mac):
                log.error("Mac learning failed for standalone mac")
                self.failed("Mac learning failed for standalone mac")
        
        with steps.start("Verify traffic drop"):
            if VerifyTrafficDrop("TC_VXLAN_PVMAP_012", testscript, traffic_item='Trunk VPC To Standalone'):
                log.info('Verify traffic drop validation success')
            else:
                self.failed('Verify traffic validation failed') 
        
        with steps.start('Doing Config Replace to replace the configs on orphan and standalone'):
            if verify_config_replace([prim_vtep, sec_vtep], log):
                log.info('Config-Replace success')
            else:
                self.failed('Config-Replace failed')

        stream1.StartStatelessTraffic()
        log.info('Waiting {}secs to start the traffic'.format(traffic_start_time))
        time.sleep(traffic_start_time)
        
        stream1.StopStatelessTraffic()
        log.info('Waiting {}secs to stop the traffic'.format(traffic_stop_time))
        time.sleep(traffic_stop_time)
        
        log.info('Waiting 60secs for mac relearning')
        time.sleep(60)
        
        with steps.start("checking mac learning after mapping enable for vpc mac"):
            if not verify_mac_on_vteps([prim_vtep, sec_vtep, sa_vtep], '1001', 1025, prim_mac):
                log.error("Mac learning failed for orphan mac")
                self.failed("Mac learning failed for orphan mac")

        with steps.start("checking mac learning after mapping enable for standalone mac"):
            if not verify_mac_on_vteps([prim_vtep, sec_vtep, sa_vtep], '1002', 1025, sa_mac):
                log.error("Mac learning failed for standalone mac")
                self.failed("Mac learning failed for standalone mac")

        with steps.start('Verify Learned mac address consistency between hardware and software'):
            if verify_mac_cc_between_hardware_software([prim_vtep, sec_vtep, sa_vtep]):
                log.info('MAC CC success')
            else:
                self.failed('MAC CC failed')

        with steps.start("Verify Steady State"):
            if VerifyTraffic("TC_VXLAN_PVMAP_012", testscript, traffic_item='Trunk VPC To Standalone'):
                log.info('Verify traffic success')
            else:
                self.failed('Verify traffic failed') 

    @aetest.test
    def testcase_orphan(self, testscript, steps):
        sa_vtep         = testscript.parameters['LEAF-3']
        prim_vtep       = testscript.parameters['LEAF-1']
        sec_vtep        = testscript.parameters['LEAF-2']
        prim_mac        = str(testscript.parameters['PVMAP_Dict']['prim_orphan_mac'])
        sa_mac          = str(testscript.parameters['PVMAP_Dict']['sa_mac'])
        p1_handle       = testscript.parameters['orphan1_handle']
        p2_handle       = testscript.parameters['sa_handle']
        ixNetwork       = testscript.parameters['ixNetwork']
        vlan            = int(testscript.parameters['LEAF_1_Orphan1_TGEN_dict']['vlan_id'])
        vlan1           = int(testscript.parameters['LEAF_3_TGEN_dict']['vlan_id'])
        vni_1           = str(testscript.parameters['LEAF_1_dict']['STATIC_IR_VNI_data']['l2_vni_start'])
        vni_2           = str(testscript.parameters['LEAF_3_dict']['STATIC_IR_VNI_data']['l2_vni_start'])

        with steps.start("Starting hosts..."):
            p1_handle.Start()
            p2_handle.Start()
        
        log.info('Waiting {}secs to start hosts'.format(host_start_time))
        time.sleep(host_start_time)

        stream1 = ixNetwork.Traffic.TrafficItem.find(Name='Trunk Orphan To Standalone')
        stream1.StartStatelessTraffic()
        log.info('Waiting {}secs to start the traffic'.format(traffic_start_time))
        time.sleep(traffic_start_time)
        
        stream1.StopStatelessTraffic()
        log.info('Waiting {}secs to stop the traffic'.format(traffic_stop_time))
        time.sleep(traffic_stop_time)

        with steps.start("checking mac learning for orphan mac"):
            if not verify_mac_on_vteps([prim_vtep, sec_vtep, sa_vtep], '1001', 1025, prim_mac):
                log.error("Mac learning failed for orphan mac")
                self.failed("Mac learning failed for orphan mac")

        with steps.start("Checking mac learning for standalone mac"):
            if not verify_mac_on_vteps([prim_vtep, sec_vtep, sa_vtep], '1002', 1025, sa_mac):
                log.error("Mac learning failed for standalone mac")
                self.failed("Mac learning failed for standalone mac")

        with steps.start('Do Config backup on Primary, Secondary and Standalone'):
            prim_vtep.execute('delete bootflash:{cr_file} no-prompt'.format(cr_file=cr_file))
            sec_vtep.execute('delete bootflash:{cr_file} no-prompt'.format(cr_file=cr_file))
            sa_vtep.execute('delete bootflash:{cr_file} no-prompt'.format(cr_file=cr_file))
            prim_vtep.execute("copy running-config bootflash:{cr_file}".format(cr_file=cr_file))
            sec_vtep.execute("copy running-config bootflash:{cr_file}".format(cr_file=cr_file))
            sa_vtep.execute("copy running-config bootflash:{cr_file}".format(cr_file=cr_file))
        
        with steps.start("Change vni on translated vlan"):
            try:
                prim_vtep.configure('''vlan {vlan}
                                       no vn-segment {vni}
                                    '''.format(vlan=vlan, vni=vni_1))
                sec_vtep.configure('''vlan {vlan}
                                      no vn-segment {vni}
                                    '''.format(vlan=vlan, vni=vni_1))
                sa_vtep.configure('''vlan {vlan}
                                     no vn-segment {vni}
                                    '''.format(vlan=vlan1, vni=vni_2))
            except Exception as error:
                log.debug("Unable to configure - Encountered Exception " + str(error))
                self.errored('Exception occurred while configuring PVMAP', 
                             goto=['common_cleanup']) 
        
        log.info('Waiting 60secs for mac flushout')
        time.sleep(60)

        with steps.start("Verify traffic drop"):
            if VerifyTrafficDrop("TC_VXLAN_PVMAP_012", testscript, traffic_item='Trunk Orphan To Standalone'):
                log.info('Verify traffic drop validation success')
            else:
                self.failed('Verify traffic validation failed') 

        with steps.start('Doing Config Replace to replace the configs on orphan and standalone'):
            if verify_config_replace([prim_vtep, sec_vtep, sa_vtep], log):
                log.info('Config-Replace success')
            else:
                self.failed('Config-Replace failed')

        log.info('Waiting 60secs for mac relearning')
        time.sleep(60) 
        
        stream1.StartStatelessTraffic()
        log.info('Waiting {}secs to start the traffic'.format(traffic_start_time))
        time.sleep(traffic_start_time)
        
        stream1.StopStatelessTraffic()
        log.info('Waiting {}secs to stop the traffic'.format(traffic_stop_time))
        time.sleep(traffic_stop_time)

        with steps.start("checking mac learning after mapping enable for  orphan mac"):
            if not verify_mac_on_vteps([prim_vtep, sec_vtep, sa_vtep], '1001', 1025, prim_mac):
                log.error("Mac learning failed for orphan mac")
                self.failed("Mac learning failed for orphan mac")

        with steps.start("checking mac learning after mapping enable for standalone mac"):
            if not verify_mac_on_vteps([prim_vtep, sec_vtep, sa_vtep], '1002', 1025, sa_mac):
                log.error("Mac learning failed for standalone mac")
                self.failed("Mac learning failed for standalone mac")

        with steps.start('Verify Learned mac address consistency between hardware and software'):
            if verify_mac_cc_between_hardware_software([prim_vtep, sec_vtep, sa_vtep]):
                log.info('MAC CC success')
            else:
                self.failed('MAC CC failed')

        with steps.start("Verify Steady State"):
            if VerifyTraffic("TC_VXLAN_PVMAP_012", testscript, traffic_item='Trunk Orphan To Standalone'):
                log.info('Verify traffic success')
            else:
                self.failed('Verify traffic failed') 

    @aetest.test
    def verify_error_cores(self, testscript, testbed, steps):
        sa_vtep         = testscript.parameters['LEAF-3']
        prim_vtep       = testscript.parameters['LEAF-1']
        sec_vtep        = testscript.parameters['LEAF-2']
        ixNetwork       = testscript.parameters['ixNetwork']

        with steps.start("Stopping hosts..."):
            ixNetwork.StopAllProtocols()

        log.info('Waiting {}secs'.format(traffic_stop_time))
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
# TC-ID: TC_VXLAN_PVMAP_013
# Testcase:
#   - Delete VPC port-channel
#   - Check mac gets flushed out
#   - Check traffic dropped
#   - Do config-replace to port-channel back
#   - Check traffic
# =============================================================================================================================#
class TC_VXLAN_PVMAP_013(aetest.Testcase):
    @aetest.test
    def testcase_vpc(self, testscript, steps):
        sa_vtep         = testscript.parameters['LEAF-3']
        prim_vtep       = testscript.parameters['LEAF-1']
        sec_vtep        = testscript.parameters['LEAF-2']
        prim_mac        = str(testscript.parameters['PVMAP_Dict']['prim_vpc_mac'])
        sa_mac          = str(testscript.parameters['PVMAP_Dict']['sa_mac'])
        p1_handle       = testscript.parameters['vpc_handle']
        p2_handle       = testscript.parameters['sa_handle']
        ixNetwork       = testscript.parameters['ixNetwork']
        vni_1           = str(testscript.parameters['LEAF_1_dict']['STATIC_IR_VNI_data']['l2_vni_start'])
        vlan            = int(testscript.parameters['LEAF_1_Orphan1_TGEN_dict']['vlan_id'])

        with steps.start("Starting hosts..."):
            p1_handle.Start()
            p2_handle.Start()
        
        log.info('Waiting {}secs to start hosts'.format(host_start_time))
        time.sleep(host_start_time)

        stream1 = ixNetwork.Traffic.TrafficItem.find(Name='Trunk VPC To Standalone')
        stream1.StartStatelessTraffic()
        log.info('Waiting {}secs to start the traffic'.format(traffic_start_time))
        time.sleep(traffic_start_time)
        
        stream1.StopStatelessTraffic()
        log.info('Waiting {}secs to stop the traffic'.format(traffic_stop_time))
        time.sleep(traffic_stop_time)

        with steps.start("checking mac learning for orphan mac"):
            if not verify_mac_on_vteps([prim_vtep, sec_vtep, sa_vtep], '1001', 1025, prim_mac):
                log.error("Mac learning failed for orphan mac")
                self.failed("Mac learning failed for orphan mac")

        with steps.start("Checking mac learning for standalone mac"):
            if not verify_mac_on_vteps([prim_vtep, sec_vtep, sa_vtep], '1002', 1025, sa_mac):
                log.error("Mac learning failed for standalone mac")
                self.failed("Mac learning failed for standalone mac")

        with steps.start('Do Config backup on Primary, Secondary and Standalone'):
            prim_vtep.execute('delete bootflash:{cr_file} no-prompt'.format(cr_file=cr_file))
            sec_vtep.execute('delete bootflash:{cr_file} no-prompt'.format(cr_file=cr_file))
            prim_vtep.execute("copy running-config bootflash:{cr_file}".format(cr_file=cr_file))
            sec_vtep.execute("copy running-config bootflash:{cr_file}".format(cr_file=cr_file))

        with steps.start("Delete VPC Port-channel"):
            try:
                prim_vtep.configure('''no interface port-channel 11''')
                sec_vtep.configure('''no interface port-channel 11''')
            except Exception as error:
                log.debug("Unable to configure - Encountered Exception " + str(error))
                self.errored('Exception occurred while configuring PVMAP', 
                             goto=['common_cleanup']) 
        
        log.info('Waiting 60secs for mac flushout')
        time.sleep(60)

        with steps.start("checking mac flushout for vpc mac"):
            if not verify_mac_on_vteps([prim_vtep, sec_vtep, sa_vtep], '1001', 0, prim_mac):
                log.error("Mac learning failed for orphan mac")
                self.failed("Mac learning failed for orphan mac")

        with steps.start("Checking mac learning for standalone mac"):
            if not verify_mac_on_vteps([prim_vtep, sec_vtep, sa_vtep], '1002', 1025, sa_mac):
                log.error("Mac learning failed for standalone mac")
                self.failed("Mac learning failed for standalone mac")
        
        with steps.start("Verify traffic drop"):
            if VerifyTrafficDrop("TC_VXLAN_PVMAP_013", testscript, traffic_item='Trunk VPC To Standalone'):
                log.info('Verify traffic drop validation success')
            else:
                self.failed('Verify traffic validation failed') 
        
        with steps.start('Doing Config Replace to replace the configs on orphan and standalone'):
            if verify_config_replace([prim_vtep, sec_vtep], log):
                log.info('Config-Replace success')
            else:
                self.failed('Config-Replace failed')

        stream1.StartStatelessTraffic()
        log.info('Waiting {}secs to start the traffic'.format(traffic_start_time))
        time.sleep(traffic_start_time)
        
        stream1.StopStatelessTraffic()
        log.info('Waiting {}secs to stop the traffic'.format(traffic_stop_time))
        time.sleep(traffic_stop_time)
        
        log.info('Waiting 60secs for mac relearning')
        time.sleep(60)
        
        with steps.start("checking mac learning after mapping enable for vpc mac"):
            if not verify_mac_on_vteps([prim_vtep, sec_vtep, sa_vtep], '1001', 1025, prim_mac):
                log.error("Mac learning failed for orphan mac")
                self.failed("Mac learning failed for orphan mac")

        with steps.start("checking mac learning after mapping enable for standalone mac"):
            if not verify_mac_on_vteps([prim_vtep, sec_vtep, sa_vtep], '1002', 1025, sa_mac):
                log.error("Mac learning failed for standalone mac")
                self.failed("Mac learning failed for standalone mac")

        with steps.start('Verify Learned mac address consistency between hardware and software'):
            if verify_mac_cc_between_hardware_software([prim_vtep, sec_vtep, sa_vtep]):
                log.info('MAC CC success')
            else:
                self.failed('MAC CC failed')

        with steps.start("Verify Steady State"):
            if VerifyTraffic("TC_VXLAN_PVMAP_013", testscript, traffic_item='Trunk VPC To Standalone'):
                log.info('Verify traffic success')
            else:
                self.failed('Verify traffic failed') 

    @aetest.test
    def verify_error_cores(self, testscript, testbed, steps):
        sa_vtep         = testscript.parameters['LEAF-3']
        prim_vtep       = testscript.parameters['LEAF-1']
        sec_vtep        = testscript.parameters['LEAF-2']
        ixNetwork       = testscript.parameters['ixNetwork']

        with steps.start("Stopping hosts..."):
            ixNetwork.StopAllProtocols()

        log.info('Waiting {}secs'.format(traffic_stop_time))
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
# TC-ID: TC_VXLAN_PVMAP_014
# Testcase:
#   Mac move between orphan ports
# =============================================================================================================================#
class TC_VXLAN_PVMAP_014(aetest.Testcase):
    @aetest.test
    def testcase_vpc(self, testscript, steps):
        sa_vtep         = testscript.parameters['LEAF-3']
        prim_vtep       = testscript.parameters['LEAF-1']
        sec_vtep        = testscript.parameters['LEAF-2']
        prim_mac        = str(testscript.parameters['PVMAP_Dict']['prim_vpc_mac'])
        sa_mac          = str(testscript.parameters['PVMAP_Dict']['sa_mac'])
        p1_handle       = testscript.parameters['orphan1_handle']
        p2_handle       = testscript.parameters['sa_handle']
        p3_handle       = testscript.parameters['orphan2_handle']
        ixNetwork       = testscript.parameters['ixNetwork']

        with steps.start("Starting hosts..."):
            p1_handle.Start()
            p2_handle.Start()
        
        log.info('Waiting {}secs to start hosts'.format(host_start_time))
        time.sleep(host_start_time)

        stream1 = ixNetwork.Traffic.TrafficItem.find(Name='Trunk Orphan To Standalone')
        stream1.StartStatelessTraffic()
        log.info('Waiting {}secs to start the traffic'.format(traffic_start_time))
        time.sleep(traffic_start_time)
        
        stream1.StopStatelessTraffic()
        log.info('Waiting {}secs to stop the traffic'.format(traffic_stop_time))
        time.sleep(traffic_stop_time)

        with steps.start("checking mac learning for orphan mac"):
            if not verify_mac_on_vteps([prim_vtep, sec_vtep, sa_vtep], '1001', 1025, prim_mac):
                log.error("Mac learning failed for orphan mac")
                self.failed("Mac learning failed for orphan mac")

        with steps.start("Checking mac learning for standalone mac"):
            if not verify_mac_on_vteps([prim_vtep, sec_vtep, sa_vtep], '1002', 1025, sa_mac):
                log.error("Mac learning failed for standalone mac")
                self.failed("Mac learning failed for standalone mac")

        with steps.start("Verify Steady State"):
            if VerifyTraffic("TC_VXLAN_PVMAP_014", testscript, traffic_item='Trunk Orphan To Standalone'):
                log.info('Verify traffic success')
            else:
                self.failed('Verify traffic failed') 

        with steps.start("Stopping hosts..."):
            ixNetwork.StopAllProtocols()
    
        with steps.start("Starting hosts..."):
            p3_handle.Start()
            p2_handle.Start()
        
        log.info('Waiting {}secs to start hosts'.format(host_start_time))
        time.sleep(host_start_time)

        stream1 = ixNetwork.Traffic.TrafficItem.find(Name='Trunk Orphan2 To Standalone')
        stream1.StartStatelessTraffic()
        log.info('Waiting 120 secs to start the traffic')
        time.sleep(120)
        
        stream1.StopStatelessTraffic()
        log.info('Waiting {}secs to stop the traffic'.format(traffic_stop_time))
        time.sleep(traffic_stop_time)

        with steps.start("checking mac learning for orphan mac"):
            if not verify_mac_on_vteps([prim_vtep, sec_vtep, sa_vtep], '1001', 1025, prim_mac):
                log.error("Mac learning failed for orphan mac")
                self.failed("Mac learning failed for orphan mac")

        with steps.start("Checking mac learning for standalone mac"):
            if not verify_mac_on_vteps([prim_vtep, sec_vtep, sa_vtep], '1002', 1025, sa_mac):
                log.error("Mac learning failed for standalone mac")
                self.failed("Mac learning failed for standalone mac")
        
        with steps.start('Verify Learned mac address consistency between hardware and software'):
            if verify_mac_cc_between_hardware_software([prim_vtep, sec_vtep, sa_vtep]):
                log.info('MAC CC success')
            else:
                self.failed('MAC CC failed')

        with steps.start("Verify Steady State"):
            if VerifyTraffic("TC_VXLAN_PVMAP_014", testscript, traffic_item='Trunk Orphan2 To Standalone'):
                log.info('Verify traffic success')
            else:
                self.failed('Verify traffic failed') 

    @aetest.test
    def verify_error_cores(self, testscript, testbed, steps):
        sa_vtep         = testscript.parameters['LEAF-3']
        prim_vtep       = testscript.parameters['LEAF-1']
        sec_vtep        = testscript.parameters['LEAF-2']
        ixNetwork       = testscript.parameters['ixNetwork']

        with steps.start("Stopping hosts..."):
            ixNetwork.StopAllProtocols()

        log.info('Waiting {}secs'.format(traffic_stop_time))
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
# TC-ID: TC_VXLAN_PVMAP_016
# Testcase:
#   - Delete loopback interfaces
#   - Check mac gets flushed out
#   - Check traffic dropped
#   - Do config-replace to add loopback's back
#   - Check mac learning and traffic
# =============================================================================================================================#
class TC_VXLAN_PVMAP_016(aetest.Testcase):
    @aetest.test
    def testcase_vpc(self, testscript, steps):
        sa_vtep         = testscript.parameters['LEAF-3']
        prim_vtep       = testscript.parameters['LEAF-1']
        sec_vtep        = testscript.parameters['LEAF-2']
        prim_mac        = str(testscript.parameters['PVMAP_Dict']['prim_vpc_mac'])
        sa_mac          = str(testscript.parameters['PVMAP_Dict']['sa_mac'])
        loop_ifs        = testscript.parameters['PVMAP_Dict']['loopb_intf']
        p1_handle       = testscript.parameters['vpc_handle']
        p2_handle       = testscript.parameters['sa_handle']
        ixNetwork       = testscript.parameters['ixNetwork']

        with steps.start("Starting hosts..."):
            p1_handle.Start()
            p2_handle.Start()
        
        log.info('Waiting {}secs to start hosts'.format(host_start_time))
        time.sleep(host_start_time)

        stream1 = ixNetwork.Traffic.TrafficItem.find(Name='Trunk VPC To Standalone')
        stream1.StartStatelessTraffic()
        log.info('Waiting {}secs to start the traffic'.format(traffic_start_time))
        time.sleep(traffic_start_time)
        
        stream1.StopStatelessTraffic()
        log.info('Waiting {}secs to stop the traffic'.format(traffic_stop_time))
        time.sleep(traffic_stop_time)

        with steps.start("checking mac learning for orphan mac"):
            if not verify_mac_on_vteps([prim_vtep, sec_vtep, sa_vtep], '1001', 1025, prim_mac):
                log.error("Mac learning failed for orphan mac")
                self.failed("Mac learning failed for orphan mac")

        with steps.start("Checking mac learning for standalone mac"):
            if not verify_mac_on_vteps([prim_vtep, sec_vtep, sa_vtep], '1002', 1025, sa_mac):
                log.error("Mac learning failed for standalone mac")
                self.failed("Mac learning failed for standalone mac")

        with steps.start('Do Config backup on Primary, Secondary and Standalone'):
            prim_vtep.execute('delete bootflash:{cr_file} no-prompt'.format(cr_file=cr_file))
            sec_vtep.execute('delete bootflash:{cr_file} no-prompt'.format(cr_file=cr_file))
            prim_vtep.execute("copy running-config bootflash:{cr_file}".format(cr_file=cr_file))
            sec_vtep.execute("copy running-config bootflash:{cr_file}".format(cr_file=cr_file))

        with steps.start("Delete loopback interfaces"):
            for intf in loop_ifs:
                try:
                    prim_vtep.configure('''no interface {intf}'''.format(intf=intf))
                    sec_vtep.configure('''no interface {intf}'''.format(intf=intf))
                except Exception as error:
                    log.debug("Unable to configure - Encountered Exception " + str(error))
                    self.errored('Exception occurred while configuring PVMAP', 
                                goto=['common_cleanup']) 

        log.info('Waiting 60secs for mac flushout')
        time.sleep(60)

        with steps.start("checking mac flushout for vpc mac"):
            if not verify_mac_on_vteps([prim_vtep, sec_vtep], '1001', 1025, prim_mac):
                log.error("Mac learning failed for orphan mac")
                self.failed("Mac learning failed for orphan mac")
        if not verify_mac_on_vteps([sa_vtep], '1001', 0, prim_mac):
                log.error("Mac learning failed for orphan mac")
                self.failed("Mac learning failed for orphan mac")

        with steps.start("Checking mac learning for standalone mac"):
            if not verify_mac_on_vteps([sa_vtep], '1002', 1025, sa_mac):
                log.error("Mac learning failed for standalone mac")
                self.failed("Mac learning failed for standalone mac")

            if not verify_mac_on_vteps([prim_vtep, sec_vtep], '1002', 0, sa_mac):
                log.error("Mac learning failed for standalone mac")
                self.failed("Mac learning failed for standalone mac")

        with steps.start("Verify traffic drop"):
            if VerifyTrafficDrop("TC_VXLAN_PVMAP_016", testscript, traffic_item='Trunk VPC To Standalone'):
                log.info('Verify traffic drop validation success')
            else:
                self.failed('Verify traffic validation failed') 
        
        with steps.start('Doing Config Replace to replace the configs on vpc'):
            if verify_config_replace([prim_vtep, sec_vtep], log):
                log.info('Config-Replace success')
            else:
                self.failed('Config-Replace failed')

        stream1.StartStatelessTraffic()
        log.info('Waiting {}secs to start the traffic'.format(traffic_start_time))
        time.sleep(traffic_start_time)
        
        stream1.StopStatelessTraffic()
        log.info('Waiting {}secs to stop the traffic'.format(traffic_stop_time))
        time.sleep(traffic_stop_time)
        
        log.info('Waiting 60secs for mac relearning')
        time.sleep(60)
        
        with steps.start("checking mac learning after mapping enable for vpc mac"):
            if not verify_mac_on_vteps([prim_vtep, sec_vtep, sa_vtep], '1001', 1025, prim_mac):
                log.error("Mac learning failed for orphan mac")
                self.failed("Mac learning failed for orphan mac")

        with steps.start("checking mac learning after mapping enable for standalone mac"):
            if not verify_mac_on_vteps([prim_vtep, sec_vtep, sa_vtep], '1002', 1025, sa_mac):
                log.error("Mac learning failed for standalone mac")
                self.failed("Mac learning failed for standalone mac")

        with steps.start('Verify Learned mac address consistency between hardware and software'):
            if verify_mac_cc_between_hardware_software([prim_vtep, sec_vtep, sa_vtep]):
                log.info('MAC CC success')
            else:
                self.failed('MAC CC failed')

        with steps.start("Verify Steady State"):
            if VerifyTraffic("TC_VXLAN_PVMAP_016", testscript, traffic_item='Trunk VPC To Standalone'):
                log.info('Verify traffic success')
            else:
                self.failed('Verify traffic failed') 

    @aetest.test
    def testcase_orphan(self, testscript, steps):
        sa_vtep         = testscript.parameters['LEAF-3']
        prim_vtep       = testscript.parameters['LEAF-1']
        sec_vtep        = testscript.parameters['LEAF-2']
        prim_mac        = str(testscript.parameters['PVMAP_Dict']['prim_orphan_mac'])
        sa_mac          = str(testscript.parameters['PVMAP_Dict']['sa_mac'])
        loop_ifs        = testscript.parameters['PVMAP_Dict']['loopb_intf']
        p1_handle       = testscript.parameters['orphan1_handle']
        p2_handle       = testscript.parameters['sa_handle']
        ixNetwork       = testscript.parameters['ixNetwork']

        with steps.start("Starting hosts..."):
            p1_handle.Start()
            p2_handle.Start()
        
        log.info('Waiting {}secs to start hosts'.format(host_start_time))
        time.sleep(host_start_time)

        stream1 = ixNetwork.Traffic.TrafficItem.find(Name='Trunk Orphan To Standalone')
        stream1.StartStatelessTraffic()
        log.info('Waiting {}secs to start the traffic'.format(traffic_start_time))
        time.sleep(traffic_start_time)
        
        stream1.StopStatelessTraffic()
        log.info('Waiting {}secs to stop the traffic'.format(traffic_stop_time))
        time.sleep(traffic_stop_time)

        with steps.start("checking mac learning for orphan mac"):
            if not verify_mac_on_vteps([prim_vtep, sec_vtep, sa_vtep], '1001', 1025, prim_mac):
                log.error("Mac learning failed for orphan mac")
                self.failed("Mac learning failed for orphan mac")

        with steps.start("Checking mac learning for standalone mac"):
            if not verify_mac_on_vteps([prim_vtep, sec_vtep, sa_vtep], '1002', 1025, sa_mac):
                log.error("Mac learning failed for standalone mac")
                self.failed("Mac learning failed for standalone mac")

        with steps.start('Do Config backup on Primary, Secondary and Standalone'):
            prim_vtep.execute('delete bootflash:{cr_file} no-prompt'.format(cr_file=cr_file))
            sa_vtep.execute('delete bootflash:{cr_file} no-prompt'.format(cr_file=cr_file))
            prim_vtep.execute("copy running-config bootflash:{cr_file}".format(cr_file=cr_file))
            sa_vtep.execute("copy running-config bootflash:{cr_file}".format(cr_file=cr_file))
        
        with steps.start("Delete loopback interfaces"):
            for intf in loop_ifs:
                try:
                    prim_vtep.configure('''no interface {intf}'''.format(intf=intf))
                    sa_vtep.configure('''no interface {intf}'''.format(intf=intf))
                except Exception as error:
                    log.debug("Unable to configure - Encountered Exception " + str(error))
                    self.errored('Exception occurred while configuring PVMAP', 
                                goto=['common_cleanup']) 
        
        log.info('Waiting 60secs for mac flushout')
        time.sleep(60)

        with steps.start("checking mac flushout for orphan mac"):
            if not verify_mac_on_vteps([prim_vtep, sec_vtep], '1001', 1025, prim_mac):
                log.error("Mac learning failed for orphan mac")
                self.failed("Mac learning failed for orphan mac")

            if not verify_mac_on_vteps([sa_vtep], '1001', 0, prim_mac):
                log.error("Mac learning failed for orphan mac")
                self.failed("Mac learning failed for orphan mac")

        with steps.start("Checking mac learning for standalone mac"):
            if not verify_mac_on_vteps([prim_vtep, sec_vtep], '1002', 0, sa_mac):
                log.error("Mac learning failed for standalone mac")
                self.failed("Mac learning failed for standalone mac")
            
            if not verify_mac_on_vteps([sa_vtep], '1002', 1025, sa_mac):
                log.error("Mac learning failed for standalone mac")
                self.failed("Mac learning failed for standalone mac")

        with steps.start("Verify traffic drop"):
            if VerifyTrafficDrop("TC_VXLAN_PVMAP_016", testscript, traffic_item='Trunk Orphan To Standalone'):
                log.info('Verify traffic drop validation success')
            else:
                self.failed('Verify traffic validation failed') 

        with steps.start('Doing Config Replace to replace the configs on orphan and standalone'):
            if verify_config_replace([prim_vtep, sa_vtep], log):
                log.info('Config-Replace success')
            else:
                self.failed('Config-Replace failed')

        stream1.StartStatelessTraffic()
        log.info('Waiting {}secs to start the traffic'.format(traffic_start_time))
        time.sleep(traffic_start_time)
        
        stream1.StopStatelessTraffic()
        log.info('Waiting {}secs to stop the traffic'.format(traffic_stop_time))
        time.sleep(traffic_stop_time)

        log.info('Waiting 60secs for mac relearning')
        time.sleep(60) 
        
        with steps.start("checking mac learning after mapping enable for  orphan mac"):
            if not verify_mac_on_vteps([prim_vtep, sec_vtep, sa_vtep], '1001', 1025, prim_mac):
                log.error("Mac learning failed for orphan mac")
                self.failed("Mac learning failed for orphan mac")

        with steps.start("checking mac learning after mapping enable for standalone mac"):
            if not verify_mac_on_vteps([prim_vtep, sec_vtep, sa_vtep], '1002', 1025, sa_mac):
                log.error("Mac learning failed for standalone mac")
                self.failed("Mac learning failed for standalone mac")

        with steps.start('Verify Learned mac address consistency between hardware and software'):
            if verify_mac_cc_between_hardware_software([prim_vtep, sec_vtep, sa_vtep]):
                log.info('MAC CC success')
            else:
                self.failed('MAC CC failed')

        with steps.start("Verify Steady State"):
            if VerifyTraffic("TC_VXLAN_PVMAP_016", testscript, traffic_item='Trunk Orphan To Standalone'):
                log.info('Verify traffic success')
            else:
                self.failed('Verify traffic failed') 

    @aetest.test
    def verify_error_cores(self, testscript, testbed, steps):
        sa_vtep         = testscript.parameters['LEAF-3']
        prim_vtep       = testscript.parameters['LEAF-1']
        sec_vtep        = testscript.parameters['LEAF-2']
        ixNetwork       = testscript.parameters['ixNetwork']

        with steps.start("Stopping hosts..."):
            ixNetwork.StopAllProtocols()

        log.info('Waiting {}secs'.format(traffic_stop_time))
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
# TC-ID: TC_VXLAN_PVMAP_017
# Testcase:  - TC-16 without between delete and add
#   - Delete and add loopback interfaces without much delay
#   - Do config-replace to add loopback's back
#   - Check mac learning and traffic
# =============================================================================================================================#
class TC_VXLAN_PVMAP_017(aetest.Testcase):
    @aetest.test
    def testcase_vpc(self, testscript, steps):
        sa_vtep         = testscript.parameters['LEAF-3']
        prim_vtep       = testscript.parameters['LEAF-1']
        sec_vtep        = testscript.parameters['LEAF-2']
        prim_mac        = str(testscript.parameters['PVMAP_Dict']['prim_vpc_mac'])
        sa_mac          = str(testscript.parameters['PVMAP_Dict']['sa_mac'])
        loop_ifs        = testscript.parameters['PVMAP_Dict']['loopb_intf']
        p1_handle       = testscript.parameters['vpc_handle']
        p2_handle       = testscript.parameters['sa_handle']
        ixNetwork       = testscript.parameters['ixNetwork']

        with steps.start("Starting hosts..."):
            p1_handle.Start()
            p2_handle.Start()
        
        log.info('Waiting {}secs to start hosts'.format(host_start_time))
        time.sleep(host_start_time)

        stream1 = ixNetwork.Traffic.TrafficItem.find(Name='Trunk VPC To Standalone')
        stream1.StartStatelessTraffic()
        log.info('Waiting {}secs to start the traffic'.format(traffic_start_time))
        time.sleep(traffic_start_time)
        
        stream1.StopStatelessTraffic()
        log.info('Waiting {}secs to stop the traffic'.format(traffic_stop_time))
        time.sleep(traffic_stop_time)

        with steps.start("checking mac learning for orphan mac"):
            if not verify_mac_on_vteps([prim_vtep, sec_vtep, sa_vtep], '1001', 1025, prim_mac):
                log.error("Mac learning failed for orphan mac")
                self.failed("Mac learning failed for orphan mac")

        with steps.start("Checking mac learning for standalone mac"):
            if not verify_mac_on_vteps([prim_vtep, sec_vtep, sa_vtep], '1002', 1025, sa_mac):
                log.error("Mac learning failed for standalone mac")
                self.failed("Mac learning failed for standalone mac")

        with steps.start('Do Config backup on Primary, Secondary and Standalone'):
            prim_vtep.execute('delete bootflash:{cr_file} no-prompt'.format(cr_file=cr_file))
            sec_vtep.execute('delete bootflash:{cr_file} no-prompt'.format(cr_file=cr_file))
            prim_vtep.execute("copy running-config bootflash:{cr_file}".format(cr_file=cr_file))
            sec_vtep.execute("copy running-config bootflash:{cr_file}".format(cr_file=cr_file))
        
        with steps.start("Delete Loopback interfaces"):
            for intf in loop_ifs:
                try:
                    prim_vtep.configure('''no interface {intf} ; sleep 10'''.format(intf=intf))
                    sec_vtep.configure('''no interface {intf} ; sleep 10'''.format(intf=intf))
                except Exception as error:
                    log.debug("Unable to configure - Encountered Exception " + str(error))
                    self.errored('Exception occurred while configuring PVMAP', 
                                goto=['common_cleanup']) 

        with steps.start('Doing Config Replace to replace the configs on vpc'):
            if verify_config_replace([prim_vtep, sec_vtep], log):
                log.info('Config-Replace success')
            else:
                self.failed('Config-Replace failed')

        log.info('Waiting for 60secs for confing apply')
        time.sleep(60)

        # Verify NVE Peers with new IP
        nvePeerData = verifyEVPNNvePeers(testscript.parameters['leavesDict'])

        if nvePeerData['result'] is 1:
            log.info("PASS : Successfully verified NVE Peering\n\n")
        else:
            log.error("FAIL : Failed to verify NVE Peering\n\n")
            self.failed(reason=nvePeerData['log'])

        stream1.StartStatelessTraffic()
        log.info('Waiting {}secs to start the traffic'.format(traffic_start_time))
        time.sleep(traffic_start_time)
        
        stream1.StopStatelessTraffic()
        log.info('Waiting {}secs to stop the traffic'.format(traffic_stop_time))
        time.sleep(traffic_stop_time)
        
        log.info('Waiting 60secs for mac relearning')
        time.sleep(60)
        
        with steps.start("checking mac learning after mapping enable for vpc mac"):
            if not verify_mac_on_vteps([prim_vtep, sec_vtep, sa_vtep], '1001', 1025, prim_mac):
                log.error("Mac learning failed for orphan mac")
                self.failed("Mac learning failed for orphan mac")

        with steps.start("checking mac learning after mapping enable for standalone mac"):
            if not verify_mac_on_vteps([prim_vtep, sec_vtep, sa_vtep], '1002', 1025, sa_mac):
                log.error("Mac learning failed for standalone mac")
                self.failed("Mac learning failed for standalone mac")

        with steps.start('Verify Learned mac address consistency between hardware and software'):
            if verify_mac_cc_between_hardware_software([prim_vtep, sec_vtep, sa_vtep]):
                log.info('MAC CC success')
            else:
                self.failed('MAC CC failed')

        with steps.start("Verify Steady State"):
            if VerifyTraffic("TC_VXLAN_PVMAP_017", testscript, traffic_item='Trunk VPC To Standalone'):
                log.info('Verify traffic success')
            else:
                self.failed('Verify traffic failed') 

    @aetest.test
    def testcase_orphan(self, testscript, steps):
        sa_vtep         = testscript.parameters['LEAF-3']
        prim_vtep       = testscript.parameters['LEAF-1']
        sec_vtep        = testscript.parameters['LEAF-2']
        prim_mac        = str(testscript.parameters['PVMAP_Dict']['prim_orphan_mac'])
        sa_mac          = str(testscript.parameters['PVMAP_Dict']['sa_mac'])
        loop_ifs        = testscript.parameters['PVMAP_Dict']['loopb_intf']
        p1_handle       = testscript.parameters['orphan1_handle']
        p2_handle       = testscript.parameters['sa_handle']
        ixNetwork       = testscript.parameters['ixNetwork']

        with steps.start("Starting hosts..."):
            p1_handle.Start()
            p2_handle.Start()
        
        log.info('Waiting {}secs to start hosts'.format(host_start_time))
        time.sleep(host_start_time)

        stream1 = ixNetwork.Traffic.TrafficItem.find(Name='Trunk Orphan To Standalone')
        stream1.StartStatelessTraffic()
        log.info('Waiting {}secs to start the traffic'.format(traffic_start_time))
        time.sleep(traffic_start_time)
        
        stream1.StopStatelessTraffic()
        log.info('Waiting {}secs to stop the traffic'.format(traffic_stop_time))
        time.sleep(traffic_stop_time)

        with steps.start("checking mac learning for orphan mac"):
            if not verify_mac_on_vteps([prim_vtep, sec_vtep, sa_vtep], '1001', 1025, prim_mac):
                log.error("Mac learning failed for orphan mac")
                self.failed("Mac learning failed for orphan mac")

        with steps.start("Checking mac learning for standalone mac"):
            if not verify_mac_on_vteps([prim_vtep, sec_vtep, sa_vtep], '1002', 1025, sa_mac):
                log.error("Mac learning failed for standalone mac")
                self.failed("Mac learning failed for standalone mac")

        with steps.start('Do Config backup on Primary, Secondary and Standalone'):
            prim_vtep.execute('delete bootflash:{cr_file} no-prompt'.format(cr_file=cr_file))
            sec_vtep.execute('delete bootflash:{cr_file} no-prompt'.format(cr_file=cr_file))
            sa_vtep.execute('delete bootflash:{cr_file} no-prompt'.format(cr_file=cr_file))
            prim_vtep.execute("copy running-config bootflash:{cr_file}".format(cr_file=cr_file))
            sec_vtep.execute("copy running-config bootflash:{cr_file}".format(cr_file=cr_file))
            sa_vtep.execute("copy running-config bootflash:{cr_file}".format(cr_file=cr_file))
        
        with steps.start("Delete loopback interfaces"):
            for intf in loop_ifs:
                try:
                    prim_vtep.configure('''no interface {intf}'''.format(intf=intf))
                    sec_vtep.configure('''no interface {intf}'''.format(intf=intf))
                    sa_vtep.configure('''no interface {intf}'''.format(intf=intf))
                except Exception as error:
                    log.debug("Unable to configure - Encountered Exception " + str(error))
                    self.errored('Exception occurred while configuring PVMAP', 
                                goto=['common_cleanup']) 

        with steps.start('Doing Config Replace to replace the configs on orphan and standalone'):
            if verify_config_replace([prim_vtep, sec_vtep, sa_vtep], log):
                log.info('Config-Replace success')
            else:
                self.failed('Config-Replace failed')

        log.info('Waiting for 60secs for confing apply')
        time.sleep(60)

        # Verify NVE Peers with new IP
        nvePeerData = verifyEVPNNvePeers(testscript.parameters['leavesDict'])

        if nvePeerData['result'] is 1:
            log.info("PASS : Successfully verified NVE Peering\n\n")
        else:
            log.error("FAIL : Failed to verify NVE Peering\n\n")
            self.failed(reason=nvePeerData['log'])
        
        with steps.start("checking mac learning after mapping enable for  orphan mac"):
            if not verify_mac_on_vteps([prim_vtep, sec_vtep, sa_vtep], '1001', 1025, prim_mac):
                log.error("Mac learning failed for orphan mac")
                self.failed("Mac learning failed for orphan mac")

        with steps.start("checking mac learning after mapping enable for standalone mac"):
            if not verify_mac_on_vteps([prim_vtep, sec_vtep, sa_vtep], '1002', 1025, sa_mac):
                log.error("Mac learning failed for standalone mac")
                self.failed("Mac learning failed for standalone mac")

        with steps.start('Verify Learned mac address consistency between hardware and software'):
            if verify_mac_cc_between_hardware_software([prim_vtep, sec_vtep, sa_vtep]):
                log.info('MAC CC success')
            else:
                self.failed('MAC CC failed')

        with steps.start("Verify Steady State"):
            if VerifyTraffic("TC_VXLAN_PVMAP_017", testscript, traffic_item='Trunk Orphan To Standalone'):
                log.info('Verify traffic success')
            else:
                self.failed('Verify traffic failed') 

    @aetest.test
    def verify_error_cores(self, testscript, testbed, steps):
        sa_vtep         = testscript.parameters['LEAF-3']
        prim_vtep       = testscript.parameters['LEAF-1']
        sec_vtep        = testscript.parameters['LEAF-2']
        ixNetwork       = testscript.parameters['ixNetwork']

        with steps.start("Stopping hosts..."):
            ixNetwork.StopAllProtocols()

        log.info('Waiting {}secs'.format(traffic_stop_time))
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

# ======================================================================================================#
# TC-ID: TC_VXLAN_PVMAP_019
# Testcase:  
#   - Delete and add bgp vrf
#   - Do config-replace to add cli back
#   - Check mac learning and traffic
# ======================================================================================================#
class TC_VXLAN_PVMAP_019(aetest.Testcase):
    @aetest.test
    def testcase_vpc(self, testscript, steps):
        sa_vtep         = testscript.parameters['LEAF-3']
        prim_vtep       = testscript.parameters['LEAF-1']
        sec_vtep        = testscript.parameters['LEAF-2']
        prim_mac        = str(testscript.parameters['PVMAP_Dict']['prim_vpc_mac'])
        sa_mac          = str(testscript.parameters['PVMAP_Dict']['sa_mac'])
        as_num 			= str(testscript.parameters['forwardingSysDict']['BGP_AS_num'])
        VRF_string      = str(testscript.parameters['forwardingSysDict']['VRF_string'])
        VRF_id_start    = str(testscript.parameters['forwardingSysDict']['VRF_id_start'])
        vrf_id 			= VRF_string + VRF_id_start
        p1_handle       = testscript.parameters['vpc_handle']
        p2_handle       = testscript.parameters['sa_handle']
        ixNetwork       = testscript.parameters['ixNetwork']

        with steps.start("Starting hosts..."):
            p1_handle.Start()
            p2_handle.Start()
        
        log.info('Waiting {}secs to start hosts'.format(host_start_time))
        time.sleep(host_start_time)

        stream1 = ixNetwork.Traffic.TrafficItem.find(Name='Trunk VPC To Standalone')
        stream1.StartStatelessTraffic()
        log.info('Waiting {}secs to start the traffic'.format(traffic_start_time))
        time.sleep(traffic_start_time)
        
        stream1.StopStatelessTraffic()
        log.info('Waiting {}secs to stop the traffic'.format(traffic_stop_time))
        time.sleep(traffic_stop_time)

        with steps.start("checking mac learning for orphan mac"):
            if not verify_mac_on_vteps([prim_vtep, sec_vtep, sa_vtep], '1001', 1025, prim_mac):
                log.error("Mac learning failed for orphan mac")
                self.failed("Mac learning failed for orphan mac")

        with steps.start("Checking mac learning for standalone mac"):
            if not verify_mac_on_vteps([prim_vtep, sec_vtep, sa_vtep], '1002', 1025, sa_mac):
                log.error("Mac learning failed for standalone mac")
                self.failed("Mac learning failed for standalone mac")

        with steps.start('Do Config backup on Primary, Secondary and Standalone'):
            prim_vtep.execute('delete bootflash:{cr_file} no-prompt'.format(cr_file=cr_file))
            sec_vtep.execute('delete bootflash:{cr_file} no-prompt'.format(cr_file=cr_file))
            prim_vtep.execute("copy running-config bootflash:{cr_file}".format(cr_file=cr_file))
            sec_vtep.execute("copy running-config bootflash:{cr_file}".format(cr_file=cr_file))
        
        with steps.start("Delete and BGP VRF"):
            try:
                prim_vtep.configure('''router bgp {asn}
                                       no vrf {vrf_id}
                                    '''.format(asn=as_num, vrf_id=vrf_id))
                sec_vtep.configure('''router bgp {asn}
                                      no vrf {vrf_id}
                                    '''.format(asn=as_num, vrf_id=vrf_id))
            except Exception as error:
                log.debug("Unable to configure - Encountered Exception " + str(error))
                self.errored('Exception occurred while configuring PVMAP', 
                            goto=['common_cleanup']) 

        log.info('Waiting for 30secs for confing apply')
        time.sleep(30)

        with steps.start('Doing Config Replace to replace the configs on vpc'):
            if verify_config_replace([prim_vtep, sec_vtep], log):
                log.info('Config-Replace success')
            else:
                self.failed('Config-Replace failed')

        log.info('Waiting for 120secs for confing apply')
        time.sleep(120)

        # Verify NVE Peers with new IP
        nvePeerData = verifyEVPNNvePeers(testscript.parameters['leavesDict'])

        if nvePeerData['result'] is 1:
            log.info("PASS : Successfully verified NVE Peering\n\n")
        else:
            log.error("FAIL : Failed to verify NVE Peering\n\n")
            self.failed(reason=nvePeerData['log'])

        stream1.StartStatelessTraffic()
        log.info('Waiting {}secs to start the traffic'.format(traffic_start_time))
        time.sleep(traffic_start_time)
        
        stream1.StopStatelessTraffic()
        log.info('Waiting {}secs to stop the traffic'.format(traffic_stop_time))
        time.sleep(traffic_stop_time)
        
        log.info('Waiting 60secs for mac relearning')
        time.sleep(60)
        
        with steps.start("checking mac learning after mapping enable for vpc mac"):
            if not verify_mac_on_vteps([prim_vtep, sec_vtep, sa_vtep], '1001', 1025, prim_mac):
                log.error("Mac learning failed for orphan mac")
                self.failed("Mac learning failed for orphan mac")

        with steps.start("checking mac learning after mapping enable for standalone mac"):
            if not verify_mac_on_vteps([prim_vtep, sec_vtep, sa_vtep], '1002', 1025, sa_mac):
                log.error("Mac learning failed for standalone mac")
                self.failed("Mac learning failed for standalone mac")

        with steps.start('Verify Learned mac address consistency between hardware and software'):
            if verify_mac_cc_between_hardware_software([prim_vtep, sec_vtep, sa_vtep]):
                log.info('MAC CC success')
            else:
                self.failed('MAC CC failed')

        with steps.start("Verify Steady State"):
            if VerifyTraffic("TC_VXLAN_PVMAP_019", testscript, traffic_item='Trunk VPC To Standalone'):
                log.info('Verify traffic success')
            else:
                self.failed('Verify traffic failed') 

    @aetest.test
    def testcase_orphan(self, testscript, steps):
        sa_vtep         = testscript.parameters['LEAF-3']
        prim_vtep       = testscript.parameters['LEAF-1']
        sec_vtep        = testscript.parameters['LEAF-2']
        prim_mac        = str(testscript.parameters['PVMAP_Dict']['prim_orphan_mac'])
        sa_mac          = str(testscript.parameters['PVMAP_Dict']['sa_mac'])
        as_num 			= str(testscript.parameters['forwardingSysDict']['BGP_AS_num'])
        VRF_string      = str(testscript.parameters['forwardingSysDict']['VRF_string'])
        VRF_id_start    = str(testscript.parameters['forwardingSysDict']['VRF_id_start'])
        vrf_id 			= VRF_string + VRF_id_start
        p1_handle       = testscript.parameters['orphan1_handle']
        p2_handle       = testscript.parameters['sa_handle']
        ixNetwork       = testscript.parameters['ixNetwork']

        with steps.start("Starting hosts..."):
            p1_handle.Start()
            p2_handle.Start()
        
        log.info('Waiting {}secs to start hosts'.format(host_start_time))
        time.sleep(host_start_time)

        stream1 = ixNetwork.Traffic.TrafficItem.find(Name='Trunk Orphan To Standalone')
        stream1.StartStatelessTraffic()
        log.info('Waiting {}secs to start the traffic'.format(traffic_start_time))
        time.sleep(traffic_start_time)
        
        stream1.StopStatelessTraffic()
        log.info('Waiting {}secs to stop the traffic'.format(traffic_stop_time))
        time.sleep(traffic_stop_time)

        with steps.start("checking mac learning for orphan mac"):
            if not verify_mac_on_vteps([prim_vtep, sec_vtep, sa_vtep], '1001', 1025, prim_mac):
                log.error("Mac learning failed for orphan mac")
                self.failed("Mac learning failed for orphan mac")

        with steps.start("Checking mac learning for standalone mac"):
            if not verify_mac_on_vteps([prim_vtep, sec_vtep, sa_vtep], '1002', 1025, sa_mac):
                log.error("Mac learning failed for standalone mac")
                self.failed("Mac learning failed for standalone mac")
        
        with steps.start('Do Config backup on Primary, Secondary and Standalone'):
            prim_vtep.execute('delete bootflash:{cr_file} no-prompt'.format(cr_file=cr_file))
            sec_vtep.execute('delete bootflash:{cr_file} no-prompt'.format(cr_file=cr_file))
            sa_vtep.execute('delete bootflash:{cr_file} no-prompt'.format(cr_file=cr_file))
            prim_vtep.execute("copy running-config bootflash:{cr_file}".format(cr_file=cr_file))
            sa_vtep.execute("copy running-config bootflash:{cr_file}".format(cr_file=cr_file))
            sec_vtep.execute("copy running-config bootflash:{cr_file}".format(cr_file=cr_file))

        with steps.start("Delete/Add vrf cli"):
            try:
                prim_vtep.configure('''router bgp {asn}
                                       no vrf {vrf_id}
                                    '''.format(asn=as_num, vrf_id=vrf_id))
                sec_vtep.configure('''router bgp {asn}
                                      no vrf {vrf_id}
                                    '''.format(asn=as_num, vrf_id=vrf_id))
                sa_vtep.configure('''router bgp {asn}
                                      no vrf {vrf_id}
                                    '''.format(asn=as_num, vrf_id=vrf_id))
            except Exception as error:
                log.debug("Unable to configure - Encountered Exception " + str(error))
                self.errored('Exception occurred while configuring PVMAP', 
                            goto=['common_cleanup']) 

        log.info('Waiting for 30secs for confing apply')
        time.sleep(30)

        with steps.start('Doing Config Replace to replace the configs on orphan and standalone'):
            if verify_config_replace([prim_vtep, sec_vtep, sa_vtep], log):
                log.info('Config-Replace success')
            else:
                self.failed('Config-Replace failed')

        log.info('Waiting for 120secs for confing apply')
        time.sleep(120)

        # Verify NVE Peers with new IP
        nvePeerData = verifyEVPNNvePeers(testscript.parameters['leavesDict'])

        if nvePeerData['result'] is 1:
            log.info("PASS : Successfully verified NVE Peering\n\n")
        else:
            log.error("FAIL : Failed to verify NVE Peering\n\n")
            self.failed(reason=nvePeerData['log'])
        
        with steps.start("checking mac learning after mapping enable for  orphan mac"):
            if not verify_mac_on_vteps([prim_vtep, sec_vtep, sa_vtep], '1001', 1025, prim_mac):
                log.error("Mac learning failed for orphan mac")
                self.failed("Mac learning failed for orphan mac")

        with steps.start("checking mac learning after mapping enable for standalone mac"):
            if not verify_mac_on_vteps([prim_vtep, sec_vtep, sa_vtep], '1002', 1025, sa_mac):
                log.error("Mac learning failed for standalone mac")
                self.failed("Mac learning failed for standalone mac")

        with steps.start('Verify Learned mac address consistency between hardware and software'):
            if verify_mac_cc_between_hardware_software([prim_vtep, sec_vtep, sa_vtep]):
                log.info('MAC CC success')
            else:
                self.failed('MAC CC failed')

        with steps.start("Verify Steady State"):
            if VerifyTraffic("TC_VXLAN_PVMAP_019", testscript, traffic_item='Trunk Orphan To Standalone'):
                log.info('Verify traffic success')
            else:
                self.failed('Verify traffic failed') 

    @aetest.test
    def verify_error_cores(self, testscript, testbed, steps):
        sa_vtep         = testscript.parameters['LEAF-3']
        prim_vtep       = testscript.parameters['LEAF-1']
        sec_vtep        = testscript.parameters['LEAF-2']
        ixNetwork       = testscript.parameters['ixNetwork']

        with steps.start("Stopping hosts..."):
            ixNetwork.StopAllProtocols()

        log.info('Waiting {}secs'.format(traffic_stop_time))
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

# ======================================================================================================#
# TC-ID: TC_VXLAN_PVMAP_021 - Triggers - shut/no shut
# Testcase:  
#   - Shut l2 trunk (physical and po)
#   - check mac flushout
#   - check packet drop
#   - No shut interface
#   - Check mac learning and traffic
# ======================================================================================================#
class TC_VXLAN_PVMAP_021(aetest.Testcase):
    @aetest.test
    def testcase_vpc_phy_intf(self, testscript, steps):
        sa_vtep         = testscript.parameters['LEAF-3']
        prim_vtep       = testscript.parameters['LEAF-1']
        sec_vtep        = testscript.parameters['LEAF-2']
        prim_mac        = str(testscript.parameters['PVMAP_Dict']['prim_vpc_mac'])
        sa_mac          = str(testscript.parameters['PVMAP_Dict']['sa_mac'])
        prim_vtep_if    = str(testscript.parameters['intf_LEAF_1_to_FAN3172'])
        sec_vtep_if     = str(testscript.parameters['intf_LEAF_2_to_FAN3172'])
        p1_handle       = testscript.parameters['vpc_handle']
        p2_handle       = testscript.parameters['sa_handle']
        ixNetwork       = testscript.parameters['ixNetwork']

        with steps.start("Starting hosts..."):
            p1_handle.Start()
            p2_handle.Start()
        
        log.info('Waiting {}secs to start hosts'.format(host_start_time))
        time.sleep(host_start_time)

        stream1 = ixNetwork.Traffic.TrafficItem.find(Name='Trunk VPC To Standalone')
        stream1.StartStatelessTraffic()
        log.info('Waiting {}secs to start the traffic'.format(traffic_start_time))
        time.sleep(traffic_start_time)
        
        stream1.StopStatelessTraffic()
        log.info('Waiting {}secs to stop the traffic'.format(traffic_stop_time))
        time.sleep(traffic_stop_time)

        with steps.start("checking mac learning for orphan mac"):
            if not verify_mac_on_vteps([prim_vtep, sec_vtep, sa_vtep], '1001', 1025, prim_mac):
                log.error("Mac learning failed for orphan mac")
                self.failed("Mac learning failed for orphan mac")

        with steps.start("Checking mac learning for standalone mac"):
            if not verify_mac_on_vteps([prim_vtep, sec_vtep, sa_vtep], '1002', 1025, sa_mac):
                log.error("Mac learning failed for standalone mac")
                self.failed("Mac learning failed for standalone mac")
        
        with steps.start("shut VPC to fanout interface"):
            try:
                prim_vtep.configure('''interface {intf}
                                       shutdown
                                    '''.format(intf=prim_vtep_if))
                sec_vtep.configure('''interface {intf}
                                      shutdown
                                    '''.format(intf=sec_vtep_if))
            except Exception as error:
                log.debug("Unable to configure - Encountered Exception " + str(error))
                self.errored('Exception occurred while configuring PVMAP', 
                            goto=['common_cleanup']) 

        log.info('Waiting 60secs for mac flushout')
        time.sleep(60)

        with steps.start("checking mac flushout for vpc mac"):
            if not verify_mac_on_vteps([prim_vtep, sec_vtep, sa_vtep], '1001', 0, prim_mac):
                log.error("Mac learning failed for orphan mac")
                self.failed("Mac learning failed for orphan mac")
                
        with steps.start("Checking mac learning for standalone mac"):
            if not verify_mac_on_vteps([prim_vtep, sec_vtep, sa_vtep], '1002', 1025, sa_mac):
                log.error("Mac learning failed for standalone mac")
                self.failed("Mac learning failed for standalone mac")

        with steps.start("Verify traffic drop"):
            if VerifyTrafficDrop("TC_VXLAN_PVMAP_021", testscript, traffic_item='Trunk VPC To Standalone'):
                log.info('Verify traffic drop validation success')
            else:
                self.failed('Verify traffic validation failed')

        with steps.start("no shut VPC to fanout interface"):
            try:
                prim_vtep.configure('''interface {intf}
                                       no shutdown
                                    '''.format(intf=prim_vtep_if))
                sec_vtep.configure('''interface {intf}
                                      no shutdown
                                    '''.format(intf=sec_vtep_if))
            except Exception as error:
                log.debug("Unable to configure - Encountered Exception " + str(error))
                self.errored('Exception occurred while configuring PVMAP', 
                            goto=['common_cleanup']) 

        stream1.StartStatelessTraffic()
        log.info('Waiting {}secs to start the traffic'.format(traffic_start_time))
        time.sleep(traffic_start_time)
        
        stream1.StopStatelessTraffic()
        log.info('Waiting {}secs to stop the traffic'.format(traffic_stop_time))
        time.sleep(traffic_stop_time)
        
        log.info('Waiting 60secs for mac relearning')
        time.sleep(60)
        
        with steps.start("checking mac learning after mapping enable for vpc mac"):
            if not verify_mac_on_vteps([prim_vtep, sec_vtep, sa_vtep], '1001', 1025, prim_mac):
                log.error("Mac learning failed for orphan mac")
                self.failed("Mac learning failed for orphan mac")

        with steps.start("checking mac learning after mapping enable for standalone mac"):
            if not verify_mac_on_vteps([prim_vtep, sec_vtep, sa_vtep], '1002', 1025, sa_mac):
                log.error("Mac learning failed for standalone mac")
                self.failed("Mac learning failed for standalone mac")

        with steps.start('Verify Learned mac address consistency between hardware and software'):
            if verify_mac_cc_between_hardware_software([prim_vtep, sec_vtep, sa_vtep]):
                log.info('MAC CC success')
            else:
                self.failed('MAC CC failed')

        with steps.start("Verify Steady State"):
            if VerifyTraffic("TC_VXLAN_PVMAP_021", testscript, traffic_item='Trunk VPC To Standalone'):
                log.info('Verify traffic success')
            else:
                self.failed('Verify traffic failed') 

    @aetest.test
    def testcase_vpc_po(self, testscript, steps):
        sa_vtep         = testscript.parameters['LEAF-3']
        prim_vtep       = testscript.parameters['LEAF-1']
        sec_vtep        = testscript.parameters['LEAF-2']
        prim_mac        = str(testscript.parameters['PVMAP_Dict']['prim_vpc_mac'])
        sa_mac          = str(testscript.parameters['PVMAP_Dict']['sa_mac'])
        p1_handle       = testscript.parameters['vpc_handle']
        p2_handle       = testscript.parameters['sa_handle']
        ixNetwork       = testscript.parameters['ixNetwork']

        with steps.start("Starting hosts..."):
            p1_handle.Start()
            p2_handle.Start()
        
        log.info('Waiting {}secs to start hosts'.format(host_start_time))
        time.sleep(host_start_time)

        stream1 = ixNetwork.Traffic.TrafficItem.find(Name='Trunk VPC To Standalone')
        stream1.StartStatelessTraffic()
        log.info('Waiting {}secs to start the traffic'.format(traffic_start_time))
        time.sleep(traffic_start_time)
        
        stream1.StopStatelessTraffic()
        log.info('Waiting {}secs to stop the traffic'.format(traffic_stop_time))
        time.sleep(traffic_stop_time)

        with steps.start("checking mac learning for orphan mac"):
            if not verify_mac_on_vteps([prim_vtep, sec_vtep, sa_vtep], '1001', 1025, prim_mac):
                log.error("Mac learning failed for orphan mac")
                self.failed("Mac learning failed for orphan mac")

        with steps.start("Checking mac learning for standalone mac"):
            if not verify_mac_on_vteps([prim_vtep, sec_vtep, sa_vtep], '1002', 1025, sa_mac):
                log.error("Mac learning failed for standalone mac")
                self.failed("Mac learning failed for standalone mac")
        
        with steps.start("shut VPC port-channel"):
            try:
                prim_vtep.configure('''interface port-channel 11
                                       shutdown
                                    ''')
                sec_vtep.configure('''interface port-channel 11
                                      shutdown
                                    ''')
            except Exception as error:
                log.debug("Unable to configure - Encountered Exception " + str(error))
                self.errored('Exception occurred while configuring PVMAP', 
                            goto=['common_cleanup']) 

        log.info('Waiting 60secs for mac flushout')
        time.sleep(60)

        with steps.start("checking mac flushout for vpc mac"):
            if not verify_mac_on_vteps([prim_vtep, sec_vtep, sa_vtep], '1001', 0, prim_mac):
                log.error("Mac learning failed for orphan mac")
                self.failed("Mac learning failed for orphan mac")
                
        with steps.start("Checking mac learning for standalone mac"):
            if not verify_mac_on_vteps([prim_vtep, sec_vtep, sa_vtep], '1002', 1025, sa_mac):
                log.error("Mac learning failed for standalone mac")
                self.failed("Mac learning failed for standalone mac")

        with steps.start("Verify traffic drop"):
            if VerifyTrafficDrop("TC_VXLAN_PVMAP_021", testscript, traffic_item='Trunk VPC To Standalone'):
                log.info('Verify traffic drop validation success')
            else:
                self.failed('Verify traffic validation failed')

        with steps.start("no shut VPC port-channel"):
            try:
                prim_vtep.configure('''interface port-channel 11
                                       no shutdown
                                    ''')
                sec_vtep.configure('''interface port-channel 11
                                      no shutdown
                                    ''')
            except Exception as error:
                log.debug("Unable to configure - Encountered Exception " + str(error))
                self.errored('Exception occurred while configuring PVMAP', 
                            goto=['common_cleanup']) 

        stream1.StartStatelessTraffic()
        log.info('Waiting {}secs to start the traffic'.format(traffic_start_time))
        time.sleep(traffic_start_time)
        
        stream1.StopStatelessTraffic()
        log.info('Waiting {}secs to stop the traffic'.format(traffic_stop_time))
        time.sleep(traffic_stop_time)
        
        log.info('Waiting 60secs for mac relearning')
        time.sleep(60)
        
        with steps.start("checking mac learning after mapping enable for vpc mac"):
            if not verify_mac_on_vteps([prim_vtep, sec_vtep, sa_vtep], '1001', 1025, prim_mac):
                log.error("Mac learning failed for orphan mac")
                self.failed("Mac learning failed for orphan mac")

        with steps.start("checking mac learning after mapping enable for standalone mac"):
            if not verify_mac_on_vteps([prim_vtep, sec_vtep, sa_vtep], '1002', 1025, sa_mac):
                log.error("Mac learning failed for standalone mac")
                self.failed("Mac learning failed for standalone mac")

        with steps.start('Verify Learned mac address consistency between hardware and software'):
            if verify_mac_cc_between_hardware_software([prim_vtep, sec_vtep, sa_vtep]):
                log.info('MAC CC success')
            else:
                self.failed('MAC CC failed')

        with steps.start("Verify Steady State"):
            if VerifyTraffic("TC_VXLAN_PVMAP_021", testscript, traffic_item='Trunk VPC To Standalone'):
                log.info('Verify traffic success')
            else:
                self.failed('Verify traffic failed') 
    
    @aetest.test
    def testcase_orphan(self, testscript, steps):
        sa_vtep         = testscript.parameters['LEAF-3']
        prim_vtep       = testscript.parameters['LEAF-1']
        sec_vtep        = testscript.parameters['LEAF-2']
        prim_mac        = str(testscript.parameters['PVMAP_Dict']['prim_orphan_mac'])
        sa_mac          = str(testscript.parameters['PVMAP_Dict']['sa_mac'])
        prim_vtep_if    = str(testscript.parameters['intf_LEAF_1_1_to_IXIA'])
        sa_vtep_if      = str(testscript.parameters['intf_LEAF_3_to_IXIA'])
        p1_handle       = testscript.parameters['orphan1_handle']
        p2_handle       = testscript.parameters['sa_handle']
        ixNetwork       = testscript.parameters['ixNetwork']

        with steps.start("Starting hosts..."):
            p1_handle.Start()
            p2_handle.Start()
        
        log.info('Waiting {}secs to start hosts'.format(host_start_time))
        time.sleep(host_start_time)

        stream1 = ixNetwork.Traffic.TrafficItem.find(Name='Trunk Orphan To Standalone')
        stream1.StartStatelessTraffic()
        log.info('Waiting {}secs to start the traffic'.format(traffic_start_time))
        time.sleep(traffic_start_time)
        
        stream1.StopStatelessTraffic()
        log.info('Waiting {}secs to stop the traffic'.format(traffic_stop_time))
        time.sleep(traffic_stop_time)

        with steps.start("checking mac learning for orphan mac"):
            if not verify_mac_on_vteps([prim_vtep, sec_vtep, sa_vtep], '1001', 1025, prim_mac):
                log.error("Mac learning failed for orphan mac")
                self.failed("Mac learning failed for orphan mac")

        with steps.start("Checking mac learning for standalone mac"):
            if not verify_mac_on_vteps([prim_vtep, sec_vtep, sa_vtep], '1002', 1025, sa_mac):
                log.error("Mac learning failed for standalone mac")
                self.failed("Mac learning failed for standalone mac")
        
        with steps.start("shut orphan and standalone interface"):
            try:
                prim_vtep.configure('''interface {intf}
                                       shutdown
                                    '''.format(intf=prim_vtep_if))
                sa_vtep.configure('''interface {intf}
                                      shutdown
                                    '''.format(intf=sa_vtep_if))
            except Exception as error:
                log.debug("Unable to configure - Encountered Exception " + str(error))
                self.errored('Exception occurred while configuring PVMAP', 
                            goto=['common_cleanup']) 

        log.info('Waiting for 60secs for confing apply')
        time.sleep(60)
        
        with steps.start("checking mac flushout for vpc mac"):
            if not verify_mac_on_vteps([prim_vtep, sec_vtep, sa_vtep], '1001', 0, prim_mac):
                log.error("Mac learning failed for orphan mac")
                self.failed("Mac learning failed for orphan mac")

        with steps.start("Checking mac learning for standalone mac"):
            if not verify_mac_on_vteps([prim_vtep, sec_vtep, sa_vtep], '1002', 0, sa_mac):
                log.error("Mac learning failed for standalone mac")
                self.failed("Mac learning failed for standalone mac")

        with steps.start("Verify traffic drop"):
            if VerifyTrafficDrop("TC_VXLAN_PVMAP_021", testscript, traffic_item='Trunk Orphan To Standalone'):
                log.info('Verify traffic drop validation success')
            else:
                self.failed('Verify traffic validation failed')

        with steps.start("no shut orphan and standalone interface"):
            try:
                prim_vtep.configure('''interface {intf}
                                       no shutdown
                                    '''.format(intf=prim_vtep_if))
                sa_vtep.configure('''interface {intf}
                                      no shutdown
                                    '''.format(intf=sa_vtep_if))
            except Exception as error:
                log.debug("Unable to configure - Encountered Exception " + str(error))
                self.errored('Exception occurred while configuring PVMAP', 
                            goto=['common_cleanup'])

        log.info('Waiting for 60secs for confing apply')
        time.sleep(60)

        stream1.StartStatelessTraffic()
        log.info('Waiting {}secs to start the traffic'.format(traffic_start_time))
        time.sleep(traffic_start_time)
        
        stream1.StopStatelessTraffic()
        log.info('Waiting {}secs to stop the traffic'.format(traffic_stop_time))
        time.sleep(traffic_stop_time)

        with steps.start("checking mac learning for orphan mac"):
            if not verify_mac_on_vteps([prim_vtep, sec_vtep, sa_vtep], '1001', 1025, prim_mac):
                log.error("Mac learning failed for orphan mac")
                self.failed("Mac learning failed for orphan mac")

        with steps.start("checking mac learning for standalone mac"):
            if not verify_mac_on_vteps([prim_vtep, sec_vtep, sa_vtep], '1002', 1025, sa_mac):
                log.error("Mac learning failed for standalone mac")
                self.failed("Mac learning failed for standalone mac")

        with steps.start('Verify Learned mac address consistency between hardware and software'):
            if verify_mac_cc_between_hardware_software([prim_vtep, sec_vtep, sa_vtep]):
                log.info('MAC CC success')
            else:
                self.failed('MAC CC failed')

        with steps.start("Verify Steady State"):
            if VerifyTraffic("TC_VXLAN_PVMAP_021", testscript, traffic_item='Trunk Orphan To Standalone'):
                log.info('Verify traffic success')
            else:
                self.failed('Verify traffic failed') 

    @aetest.test
    def verify_error_cores(self, testscript, testbed, steps):
        sa_vtep         = testscript.parameters['LEAF-3']
        prim_vtep       = testscript.parameters['LEAF-1']
        sec_vtep        = testscript.parameters['LEAF-2']
        ixNetwork       = testscript.parameters['ixNetwork']

        with steps.start("Stopping hosts..."):
            ixNetwork.StopAllProtocols()

        log.info('Waiting {}secs'.format(traffic_stop_time))
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

# ======================================================================================================#
# TC-ID: TC_VXLAN_PVMAP_022 - Triggers - shut/no shut
# Testcase:  
#   - Shut/noshut l2 trunk (physical and po) - almost no delay between shut/no shut
#   - Check mac learning and traffic
# ======================================================================================================#
class TC_VXLAN_PVMAP_022(aetest.Testcase):
    @aetest.test
    def testcase_vpc_phy_intf(self, testscript, steps):
        sa_vtep         = testscript.parameters['LEAF-3']
        prim_vtep       = testscript.parameters['LEAF-1']
        sec_vtep        = testscript.parameters['LEAF-2']
        prim_mac        = str(testscript.parameters['PVMAP_Dict']['prim_vpc_mac'])
        sa_mac          = str(testscript.parameters['PVMAP_Dict']['sa_mac'])
        prim_vtep_if    = str(testscript.parameters['intf_LEAF_1_to_FAN3172'])
        sec_vtep_if     = str(testscript.parameters['intf_LEAF_2_to_FAN3172'])
        p1_handle       = testscript.parameters['vpc_handle']
        p2_handle       = testscript.parameters['sa_handle']
        ixNetwork       = testscript.parameters['ixNetwork']

        with steps.start("Starting hosts..."):
            p1_handle.Start()
            p2_handle.Start()
        
        log.info('Waiting {}secs to start hosts'.format(host_start_time))
        time.sleep(host_start_time)

        stream1 = ixNetwork.Traffic.TrafficItem.find(Name='Trunk VPC To Standalone')
        stream1.StartStatelessTraffic()
        log.info('Waiting {}secs to start the traffic'.format(traffic_start_time))
        time.sleep(traffic_start_time)
        
        stream1.StopStatelessTraffic()
        log.info('Waiting {}secs to stop the traffic'.format(traffic_stop_time))
        time.sleep(traffic_stop_time)

        with steps.start("checking mac learning for orphan mac"):
            if not verify_mac_on_vteps([prim_vtep, sec_vtep, sa_vtep], '1001', 1025, prim_mac):
                log.error("Mac learning failed for orphan mac")
                self.failed("Mac learning failed for orphan mac")

        with steps.start("Checking mac learning for standalone mac"):
            if not verify_mac_on_vteps([prim_vtep, sec_vtep, sa_vtep], '1002', 1025, sa_mac):
                log.error("Mac learning failed for standalone mac")
                self.failed("Mac learning failed for standalone mac")
        
        with steps.start("shut/no shut VPC to fanout interface"):
            try:
                prim_vtep.configure('''interface {intf}
                                       shutdown ; sleep 2 ; no shutdown
                                    '''.format(intf=prim_vtep_if))
                sec_vtep.configure('''interface {intf}
                                      shutdown ; sleep 2 ; no shutdown
                                    '''.format(intf=sec_vtep_if))
            except Exception as error:
                log.debug("Unable to configure - Encountered Exception " + str(error))
                self.errored('Exception occurred while configuring PVMAP', 
                            goto=['common_cleanup']) 

        stream1.StartStatelessTraffic()
        log.info('Waiting {}secs to start the traffic'.format(traffic_start_time))
        time.sleep(traffic_start_time)
        
        stream1.StopStatelessTraffic()
        log.info('Waiting {}secs to stop the traffic'.format(traffic_stop_time))
        time.sleep(traffic_stop_time)
        
        log.info('Waiting 60secs for mac relearning')
        time.sleep(60)
        
        with steps.start("checking mac learning for vpc mac"):
            if not verify_mac_on_vteps([prim_vtep, sec_vtep, sa_vtep], '1001', 1025, prim_mac):
                log.error("Mac learning failed for orphan mac")
                self.failed("Mac learning failed for orphan mac")

        with steps.start("checking mac learning for standalone mac"):
            if not verify_mac_on_vteps([prim_vtep, sec_vtep, sa_vtep], '1002', 1025, sa_mac):
                log.error("Mac learning failed for standalone mac")
                self.failed("Mac learning failed for standalone mac")

        with steps.start('Verify Learned mac address consistency between hardware and software'):
            if verify_mac_cc_between_hardware_software([prim_vtep, sec_vtep, sa_vtep]):
                log.info('MAC CC success')
            else:
                self.failed('MAC CC failed')

        with steps.start("Verify Steady State"):
            if VerifyTraffic("TC_VXLAN_PVMAP_022", testscript, traffic_item='Trunk VPC To Standalone'):
                log.info('Verify traffic success')
            else:
                self.failed('Verify traffic failed') 

    @aetest.test
    def testcase_vpc_po(self, testscript, steps):
        sa_vtep         = testscript.parameters['LEAF-3']
        prim_vtep       = testscript.parameters['LEAF-1']
        sec_vtep        = testscript.parameters['LEAF-2']
        prim_mac        = str(testscript.parameters['PVMAP_Dict']['prim_vpc_mac'])
        sa_mac          = str(testscript.parameters['PVMAP_Dict']['sa_mac'])
        p1_handle       = testscript.parameters['vpc_handle']
        p2_handle       = testscript.parameters['sa_handle']
        ixNetwork       = testscript.parameters['ixNetwork']

        with steps.start("Starting hosts..."):
            p1_handle.Start()
            p2_handle.Start()
        
        log.info('Waiting {}secs to start hosts'.format(host_start_time))
        time.sleep(host_start_time)

        stream1 = ixNetwork.Traffic.TrafficItem.find(Name='Trunk VPC To Standalone')
        stream1.StartStatelessTraffic()
        log.info('Waiting {}secs to start the traffic'.format(traffic_start_time))
        time.sleep(traffic_start_time)
        
        stream1.StopStatelessTraffic()
        log.info('Waiting {}secs to stop the traffic'.format(traffic_stop_time))
        time.sleep(traffic_stop_time)

        with steps.start("checking mac learning for orphan mac"):
            if not verify_mac_on_vteps([prim_vtep, sec_vtep, sa_vtep], '1001', 1025, prim_mac):
                log.error("Mac learning failed for orphan mac")
                self.failed("Mac learning failed for orphan mac")

        with steps.start("Checking mac learning for standalone mac"):
            if not verify_mac_on_vteps([prim_vtep, sec_vtep, sa_vtep], '1002', 1025, sa_mac):
                log.error("Mac learning failed for standalone mac")
                self.failed("Mac learning failed for standalone mac")
        
        with steps.start("shut/no shut VPC port-channel"):
            try:
                prim_vtep.configure('''interface port-channel 11
                                       shutdown ; sleep 2 ; no shutdown
                                    ''')
                sec_vtep.configure('''interface port-channel 11
                                      shutdown ; sleep 2 ; no shutdown
                                    ''')
            except Exception as error:
                log.debug("Unable to configure - Encountered Exception " + str(error))
                self.errored('Exception occurred while configuring PVMAP', 
                            goto=['common_cleanup']) 

        stream1.StartStatelessTraffic()
        log.info('Waiting {}secs to start the traffic'.format(traffic_start_time))
        time.sleep(traffic_start_time)
        
        stream1.StopStatelessTraffic()
        log.info('Waiting {}secs to stop the traffic'.format(traffic_stop_time))
        time.sleep(traffic_stop_time)
        
        log.info('Waiting 60secs for mac relearning')
        time.sleep(60)
        
        with steps.start("checking mac learning for vpc mac"):
            if not verify_mac_on_vteps([prim_vtep, sec_vtep, sa_vtep], '1001', 1025, prim_mac):
                log.error("Mac learning failed for orphan mac")
                self.failed("Mac learning failed for orphan mac")

        with steps.start("checking mac learning for standalone mac"):
            if not verify_mac_on_vteps([prim_vtep, sec_vtep, sa_vtep], '1002', 1025, sa_mac):
                log.error("Mac learning failed for standalone mac")
                self.failed("Mac learning failed for standalone mac")

        with steps.start('Verify Learned mac address consistency between hardware and software'):
            if verify_mac_cc_between_hardware_software([prim_vtep, sec_vtep, sa_vtep]):
                log.info('MAC CC success')
            else:
                self.failed('MAC CC failed')

        with steps.start("Verify Steady State"):
            if VerifyTraffic("TC_VXLAN_PVMAP_022", testscript, traffic_item='Trunk VPC To Standalone'):
                log.info('Verify traffic success')
            else:
                self.failed('Verify traffic failed') 
    
    @aetest.test
    def testcase_orphan(self, testscript, steps):
        sa_vtep         = testscript.parameters['LEAF-3']
        prim_vtep       = testscript.parameters['LEAF-1']
        sec_vtep        = testscript.parameters['LEAF-2']
        prim_mac        = str(testscript.parameters['PVMAP_Dict']['prim_orphan_mac'])
        sa_mac          = str(testscript.parameters['PVMAP_Dict']['sa_mac'])
        prim_vtep_if    = str(testscript.parameters['intf_LEAF_1_1_to_IXIA'])
        sa_vtep_if      = str(testscript.parameters['intf_LEAF_3_to_IXIA'])
        p1_handle       = testscript.parameters['orphan1_handle']
        p2_handle       = testscript.parameters['sa_handle']
        ixNetwork       = testscript.parameters['ixNetwork']

        with steps.start("Starting hosts..."):
            p1_handle.Start()
            p2_handle.Start()
        
        log.info('Waiting {}secs to start hosts'.format(host_start_time))
        time.sleep(host_start_time)

        stream1 = ixNetwork.Traffic.TrafficItem.find(Name='Trunk Orphan To Standalone')
        stream1.StartStatelessTraffic()
        log.info('Waiting {}secs to start the traffic'.format(traffic_start_time))
        time.sleep(traffic_start_time)
        
        stream1.StopStatelessTraffic()
        log.info('Waiting {}secs to stop the traffic'.format(traffic_stop_time))
        time.sleep(traffic_stop_time)

        with steps.start("checking mac learning for orphan mac"):
            if not verify_mac_on_vteps([prim_vtep, sec_vtep, sa_vtep], '1001', 1025, prim_mac):
                log.error("Mac learning failed for orphan mac")
                self.failed("Mac learning failed for orphan mac")

        with steps.start("Checking mac learning for standalone mac"):
            if not verify_mac_on_vteps([prim_vtep, sec_vtep, sa_vtep], '1002', 1025, sa_mac):
                log.error("Mac learning failed for standalone mac")
                self.failed("Mac learning failed for standalone mac")
        
        with steps.start("shut/noshut orphan and standalone interface"):
            try:
                prim_vtep.configure('''interface {intf}
                                       shutdown ; sleep 2 ; no shut
                                    '''.format(intf=prim_vtep_if))
                sa_vtep.configure('''interface {intf}
                                      shutdown ; sleep 2 ; no shut
                                    '''.format(intf=sa_vtep_if))
            except Exception as error:
                log.debug("Unable to configure - Encountered Exception " + str(error))
                self.errored('Exception occurred while configuring PVMAP', 
                            goto=['common_cleanup']) 

        stream1.StartStatelessTraffic()
        log.info('Waiting {}secs to start the traffic'.format(traffic_start_time))
        time.sleep(traffic_start_time)
        
        stream1.StopStatelessTraffic()
        log.info('Waiting {}secs to stop the traffic'.format(traffic_stop_time))
        time.sleep(traffic_stop_time)

        with steps.start("checking mac learning for orphan mac"):
            if not verify_mac_on_vteps([prim_vtep, sec_vtep, sa_vtep], '1001', 1025, prim_mac):
                log.error("Mac learning failed for orphan mac")
                self.failed("Mac learning failed for orphan mac")

        with steps.start("checking mac learning for standalone mac"):
            if not verify_mac_on_vteps([prim_vtep, sec_vtep, sa_vtep], '1002', 1025, sa_mac):
                log.error("Mac learning failed for standalone mac")
                self.failed("Mac learning failed for standalone mac")

        with steps.start('Verify Learned mac address consistency between hardware and software'):
            if verify_mac_cc_between_hardware_software([prim_vtep, sec_vtep, sa_vtep]):
                log.info('MAC CC success')
            else:
                self.failed('MAC CC failed')

        with steps.start("Verify Steady State"):
            if VerifyTraffic("TC_VXLAN_PVMAP_022", testscript, traffic_item='Trunk Orphan To Standalone'):
                log.info('Verify traffic success')
            else:
                self.failed('Verify traffic failed') 

    @aetest.test
    def verify_error_cores(self, testscript, testbed, steps):
        sa_vtep         = testscript.parameters['LEAF-3']
        prim_vtep       = testscript.parameters['LEAF-1']
        sec_vtep        = testscript.parameters['LEAF-2']
        ixNetwork       = testscript.parameters['ixNetwork']

        with steps.start("Stopping hosts..."):
            ixNetwork.StopAllProtocols()

        log.info('Waiting {}secs'.format(traffic_stop_time))
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

# ======================================================================================================#
# TC-ID: TC_VXLAN_PVMAP_023
# Testcase:    Triggers - shut/no shut
#   - Shut on  non-vpc po
#   - Check mac learning and traffic loss
#   - no shut
#   - Check mac learning
#   - Check traffic
# ======================================================================================================#
class TC_VXLAN_PVMAP_023(aetest.Testcase):
    @aetest.test
    def test_config(self, testscript, steps):
        prim_vtep       = testscript.parameters['LEAF-1']
        prim_vtep_if    = str(testscript.parameters['intf_LEAF_1_1_to_IXIA'])
        vlan            = int(testscript.parameters['LEAF_1_Orphan1_TGEN_dict']['vlan_id'])
        vlan1           = int(testscript.parameters['LEAF_1_Orphan1_TGEN_dict']['vlan_id1'])
        
        with steps.start("Default Orphan interface"):
            try:
                prim_vtep.configure('default interface {intf}'.format(intf=prim_vtep_if))
            except Exception as error:
                log.debug("Unable to configure - Encountered Exception " + str(error))
                self.errored('Exception occured during default interface configuration', 
                             goto=['common_cleanup'])
        
        with steps.start("Configure non-vpc port-channel 110 with PVMAP"):
            try:
                prim_vtep.configure('''interface port-channel 110
                                switchport
                                switchport mode trunk
                                switchport trunk allowed vlan {vlan}
                                spanning-tree port type edge trunk
                                switchport vlan mapping enable
                                switchport vlan mapping {vlan1} {vlan}
                                no shutdown
                            '''.format(vlan=vlan, vlan1=vlan1))
            except Exception as error:
                log.debug("Unable to configure - Encountered Exception " + str(error))
                self.errored('Exception occurred while configuring PVMAP', 
                             goto=['common_cleanup']) 
        
        with steps.start("Configure port-channel on Orphan"):
            try:
                prim_vtep.configure('''interface {intf}
                                switchport
                                switchport mode trunk
                                switchport trunk allowed vlan {vlan}
                                spanning-tree port type edge trunk
                                channel-group 110
                                no shutdown
                            '''.format(vlan=vlan, intf=prim_vtep_if))
            except Exception as error:
                log.debug("Unable to configure - Encountered Exception " + str(error))
                self.errored('Exception occurred while configuring PVMAP', 
                             goto=['common_cleanup']) 
        
        log.info('Waiting for 30ses')
        time.sleep(30)
        
    @aetest.test
    def testcase_23(self, testscript, steps):
        sa_vtep         = testscript.parameters['LEAF-3']
        prim_vtep       = testscript.parameters['LEAF-1']
        sec_vtep        = testscript.parameters['LEAF-2']
        prim_mac        = str(testscript.parameters['PVMAP_Dict']['prim_orphan_mac'])
        sa_mac          = str(testscript.parameters['PVMAP_Dict']['sa_mac'])
        p1_handle       = testscript.parameters['orphan1_handle']
        p2_handle       = testscript.parameters['sa_handle']
        ixNetwork       = testscript.parameters['ixNetwork']

        with steps.start("Starting hosts..."):
            p1_handle.Start()
            p2_handle.Start()
        
        log.info('Waiting {}secs to start hosts'.format(host_start_time))
        time.sleep(host_start_time)

        stream1 = ixNetwork.Traffic.TrafficItem.find(Name='Trunk Orphan To Standalone')
        stream1.StartStatelessTraffic()
        log.info('Waiting {}secs to start the traffic'.format(traffic_start_time))
        time.sleep(traffic_start_time)
        
        stream1.StopStatelessTraffic()
        log.info('Waiting {}secs to stop the traffic'.format(traffic_stop_time))
        time.sleep(traffic_stop_time)

        with steps.start("checking mac learning orphan mac"):
            if not verify_mac_on_vteps([prim_vtep, sec_vtep, sa_vtep], '1001', 1025, prim_mac):
                log.error("Mac learning failed for orphan mac")
                self.failed("Mac learning failed for orphan mac")

        with steps.start("Checking mac learning for standalone mac"):
            if not verify_mac_on_vteps([prim_vtep, sec_vtep, sa_vtep], '1002', 1025, sa_mac):
                log.error("Mac learning failed for standalone mac")
                self.failed("Mac learning failed for standalone mac")

        with steps.start("shut non-VPC port-channel"):
            try:
                prim_vtep.configure('''interface port-channel 110
                                       shutdown
                                    ''')
                sec_vtep.configure('''interface port-channel 110
                                      shutdown
                                    ''')
            except Exception as error:
                log.debug("Unable to configure - Encountered Exception " + str(error))
                self.errored('Exception occurred while configuring PVMAP', 
                            goto=['common_cleanup']) 

        log.info('Waiting 60secs for mac flushout')
        time.sleep(60)

        with steps.start("checking mac flushout for vpc mac"):
            if not verify_mac_on_vteps([prim_vtep, sec_vtep, sa_vtep], '1001', 0, prim_mac):
                log.error("Mac learning failed for orphan mac")
                self.failed("Mac learning failed for orphan mac")
                
        with steps.start("Checking mac learning for standalone mac"):
            if not verify_mac_on_vteps([prim_vtep, sec_vtep, sa_vtep], '1002', 1025, sa_mac):
                log.error("Mac learning failed for standalone mac")
                self.failed("Mac learning failed for standalone mac")

        with steps.start("Verify traffic drop"):
            if VerifyTrafficDrop("TC_VXLAN_PVMAP_023", testscript, traffic_item='Trunk Orphan To Standalone'):
                log.info('Verify traffic drop validation success')
            else:
                self.failed('Verify traffic validation failed')

        with steps.start("no shut non-VPC port-channel"):
            try:
                prim_vtep.configure('''interface port-channel 110
                                       no shutdown
                                    ''')
                sec_vtep.configure('''interface port-channel 110
                                      no shutdown
                                    ''')
            except Exception as error:
                log.debug("Unable to configure - Encountered Exception " + str(error))
                self.errored('Exception occurred while configuring PVMAP', 
                            goto=['common_cleanup']) 

        stream1.StartStatelessTraffic()
        log.info('Waiting {}secs to start the traffic'.format(traffic_start_time))
        time.sleep(traffic_start_time)
        
        stream1.StopStatelessTraffic()
        log.info('Waiting {}secs to stop the traffic'.format(traffic_stop_time))
        time.sleep(traffic_stop_time)
        
        log.info('Waiting 60secs for mac relearning')
        time.sleep(60)
        
        with steps.start("checking mac learning for vpc mac"):
            if not verify_mac_on_vteps([prim_vtep, sec_vtep, sa_vtep], '1001', 1025, prim_mac):
                log.error("Mac learning failed for orphan mac")
                self.failed("Mac learning failed for orphan mac")

        with steps.start("checking mac learning for standalone mac"):
            if not verify_mac_on_vteps([prim_vtep, sec_vtep, sa_vtep], '1002', 1025, sa_mac):
                log.error("Mac learning failed for standalone mac")
                self.failed("Mac learning failed for standalone mac")

        with steps.start('Verify Learned mac address consistency between hardware and software'):
            if verify_mac_cc_between_hardware_software([prim_vtep, sec_vtep, sa_vtep]):
                log.info('MAC CC success')
            else:
                self.failed('MAC CC failed')

        with steps.start("Verify Steady State"):
            if VerifyTraffic("TC_VXLAN_PVMAP_023", testscript, traffic_item='Trunk Orphan To Standalone'):
                log.info('Verify traffic success')
            else:
                self.failed('Verify traffic failed')

    @aetest.test
    def test_unconfig(self, testscript, steps):
        prim_vtep       = testscript.parameters['LEAF-1']
        vlan            = int(testscript.parameters['LEAF_1_Orphan1_TGEN_dict']['vlan_id'])
        vlan1           = int(testscript.parameters['LEAF_1_Orphan1_TGEN_dict']['vlan_id1'])
        leaf1_if = str(testscript.parameters['intf_LEAF_1_1_to_IXIA'])
        
        with steps.start("ReConfigure Orphan with PVMAP"):
            try:
                prim_vtep.configure('''interface {intf}
                                no channel-group 110
                                switchport vlan mapping enable
                                switchport vlan mapping {vlan1} {vlan}
                                no shutdown
                            '''.format(vlan=vlan, vlan1=vlan1, intf=leaf1_if))
            except Exception as error:
                log.debug("Unable to configure - Encountered Exception " + str(error))
                self.errored('Exception occurred while configuring PVMAP', 
                             goto=['common_cleanup']) 
        
        with steps.start("Remove non-vpc port-channel 110"):
            try:
                prim_vtep.configure('no interface port-channel 110')
            except Exception as error:
                log.debug("Unable to configure - Encountered Exception " + str(error))
                self.errored('Exception occurred while configuring PVMAP', 
                             goto=['common_cleanup']) 
        
    @aetest.test
    def verify_error_cores(self, testscript, testbed, steps):
        sa_vtep         = testscript.parameters['LEAF-3']
        prim_vtep       = testscript.parameters['LEAF-1']
        sec_vtep        = testscript.parameters['LEAF-2']
        ixNetwork       = testscript.parameters['ixNetwork']

        with steps.start("Stopping hosts..."):
            ixNetwork.StopAllProtocols()
        
        log.info('Waiting {}secs'.format(traffic_stop_time))
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

# ======================================================================================================#
# TC-ID: TC_VXLAN_PVMAP_024 - Triggers - shut/no shut
# Testcase:  
#   - Shut/no shut uplink
#   - Check mac learning and traffic
# ======================================================================================================#
class TC_VXLAN_PVMAP_024(aetest.Testcase):
    @aetest.test
    def testcase_vpc_uplink_shut(self, testscript, steps):
        sa_vtep         = testscript.parameters['LEAF-3']
        prim_vtep       = testscript.parameters['LEAF-1']
        sec_vtep        = testscript.parameters['LEAF-2']
        prim_mac        = str(testscript.parameters['PVMAP_Dict']['prim_vpc_mac'])
        sa_mac          = str(testscript.parameters['PVMAP_Dict']['sa_mac'])
        prim_vtep_if    = str(testscript.parameters['intf_LEAF_1_to_SPINE'])
        sec_vtep_if     = str(testscript.parameters['intf_LEAF_2_to_SPINE'])
        p1_handle       = testscript.parameters['vpc_handle']
        p2_handle       = testscript.parameters['sa_handle']
        ixNetwork       = testscript.parameters['ixNetwork']

        with steps.start("Starting hosts..."):
            p1_handle.Start()
            p2_handle.Start()
        
        log.info('Waiting {}secs to start hosts'.format(host_start_time))
        time.sleep(host_start_time)

        stream1 = ixNetwork.Traffic.TrafficItem.find(Name='Trunk VPC To Standalone')
        stream1.StartStatelessTraffic()
        log.info('Waiting {}secs to start the traffic'.format(traffic_start_time))
        time.sleep(traffic_start_time)
        
        stream1.StopStatelessTraffic()
        log.info('Waiting {}secs to stop the traffic'.format(traffic_stop_time))
        time.sleep(traffic_stop_time)

        with steps.start("checking mac learning for orphan mac"):
            if not verify_mac_on_vteps([prim_vtep, sec_vtep, sa_vtep], '1001', 1025, prim_mac):
                log.error("Mac learning failed for orphan mac")
                self.failed("Mac learning failed for orphan mac")

        with steps.start("Checking mac learning for standalone mac"):
            if not verify_mac_on_vteps([prim_vtep, sec_vtep, sa_vtep], '1002', 1025, sa_mac):
                log.error("Mac learning failed for standalone mac")
                self.failed("Mac learning failed for standalone mac")
        
        with steps.start("shut/no shut uplink interface"):
            try:
                prim_vtep.configure('''interface {intf}
                                       shutdown
                                    '''.format(intf=prim_vtep_if))
                sec_vtep.configure('''interface {intf}
                                      shutdown
                                    '''.format(intf=sec_vtep_if))
            except Exception as error:
                log.debug("Unable to configure - Encountered Exception " + str(error))
                self.errored('Exception occurred while configuring PVMAP', 
                            goto=['common_cleanup']) 

        log.info('Waiting 60secs for mac flushout')
        time.sleep(60)

        with steps.start("checking mac flushout for vpc mac"):
            if not verify_mac_on_vteps([sa_vtep], '1001', 0, prim_mac):
                log.error("Mac learning failed for orphan mac")
                self.failed("Mac learning failed for orphan mac")
        if not verify_mac_on_vteps([prim_vtep, sec_vtep], '1001', 1025, prim_mac):
                log.error("Mac learning failed for orphan mac")
                self.failed("Mac learning failed for orphan mac")
        
        with steps.start("Checking mac learning for standalone mac"):
            if not verify_mac_on_vteps([sa_vtep], '1002', 1025, sa_mac):
                log.error("Mac learning failed for standalone mac")
                self.failed("Mac learning failed for standalone mac")
            if not verify_mac_on_vteps([prim_vtep, sec_vtep], '1002', 0, sa_mac):
                log.error("Mac learning failed for standalone mac")
                self.failed("Mac learning failed for standalone mac")
    
        with steps.start("Verify traffic drop"):
            if VerifyTrafficDrop("TC_VXLAN_PVMAP_024", testscript, traffic_item='Trunk VPC To Standalone'):
                log.info('Verify traffic drop validation success')
            else:
                self.failed('Verify traffic validation failed')

        with steps.start("no shut uplink interface"):
            try:
                prim_vtep.configure('''interface {intf}
                                       no shutdown
                                    '''.format(intf=prim_vtep_if))
                sec_vtep.configure('''interface {intf}
                                      no shutdown
                                    '''.format(intf=sec_vtep_if))
            except Exception as error:
                log.debug("Unable to configure - Encountered Exception " + str(error))
                self.errored('Exception occurred while configuring PVMAP', 
                            goto=['common_cleanup']) 

        log.info('Waiting 60secs for mac flushout')
        time.sleep(60)
        
        stream1.StartStatelessTraffic()
        log.info('Waiting {}secs to start the traffic'.format(traffic_start_time))
        time.sleep(traffic_start_time)
        
        stream1.StopStatelessTraffic()
        log.info('Waiting {}secs to stop the traffic'.format(traffic_stop_time))
        time.sleep(traffic_stop_time)
        
        log.info('Waiting 60secs for mac relearning')
        time.sleep(60)
        
        with steps.start("checking mac learning for vpc mac"):
            if not verify_mac_on_vteps([prim_vtep, sec_vtep, sa_vtep], '1001', 1025, prim_mac):
                log.error("Mac learning failed for orphan mac")
                self.failed("Mac learning failed for orphan mac")

        with steps.start("checking mac learning for standalone mac"):
            if not verify_mac_on_vteps([prim_vtep, sec_vtep, sa_vtep], '1002', 1025, sa_mac):
                log.error("Mac learning failed for standalone mac")
                self.failed("Mac learning failed for standalone mac")

        with steps.start('Verify Learned mac address consistency between hardware and software'):
            if verify_mac_cc_between_hardware_software([prim_vtep, sec_vtep, sa_vtep]):
                log.info('MAC CC success')
            else:
                self.failed('MAC CC failed')

        with steps.start("Verify Steady State"):
            if VerifyTraffic("TC_VXLAN_PVMAP_024", testscript, traffic_item='Trunk VPC To Standalone'):
                log.info('Verify traffic success')
            else:
                self.failed('Verify traffic failed') 

    @aetest.test
    def testcase_orphan_uplink_shut(self, testscript, steps):
        sa_vtep         = testscript.parameters['LEAF-3']
        prim_vtep       = testscript.parameters['LEAF-1']
        sec_vtep        = testscript.parameters['LEAF-2']
        prim_mac        = str(testscript.parameters['PVMAP_Dict']['prim_orphan_mac'])
        sa_mac          = str(testscript.parameters['PVMAP_Dict']['sa_mac'])
        prim_vtep_if    = str(testscript.parameters['intf_LEAF_1_to_SPINE'])
        sa_vtep_if      = str(testscript.parameters['intf_LEAF_3_to_SPINE'])
        p1_handle       = testscript.parameters['orphan1_handle']
        p2_handle       = testscript.parameters['sa_handle']
        ixNetwork       = testscript.parameters['ixNetwork']

        with steps.start("Starting hosts..."):
            p1_handle.Start()
            p2_handle.Start()
        
        log.info('Waiting {}secs to start hosts'.format(host_start_time))
        time.sleep(host_start_time)

        stream1 = ixNetwork.Traffic.TrafficItem.find(Name='Trunk Orphan To Standalone')
        stream1.StartStatelessTraffic()
        log.info('Waiting {}secs to start the traffic'.format(traffic_start_time))
        time.sleep(traffic_start_time)
        
        stream1.StopStatelessTraffic()
        log.info('Waiting {}secs to stop the traffic'.format(traffic_stop_time))
        time.sleep(traffic_stop_time)

        with steps.start("checking mac learning for orphan mac"):
            if not verify_mac_on_vteps([prim_vtep, sec_vtep, sa_vtep], '1001', 1025, prim_mac):
                log.error("Mac learning failed for orphan mac")
                self.failed("Mac learning failed for orphan mac")

        with steps.start("Checking mac learning for standalone mac"):
            if not verify_mac_on_vteps([prim_vtep, sec_vtep, sa_vtep], '1002', 1025, sa_mac):
                log.error("Mac learning failed for standalone mac")
                self.failed("Mac learning failed for standalone mac")
        
        with steps.start("shut primary and standalone uplink interface"):
            try:
                prim_vtep.configure('''interface {intf}
                                       shutdown
                                    '''.format(intf=prim_vtep_if))
                sa_vtep.configure('''interface {intf}
                                      shutdown
                                    '''.format(intf=sa_vtep_if))
            except Exception as error:
                log.debug("Unable to configure - Encountered Exception " + str(error))
                self.errored('Exception occurred while configuring PVMAP', 
                            goto=['common_cleanup']) 

        log.info('Waiting for 60secs for confing apply')
        time.sleep(60)
        
        with steps.start("checking mac flushout for vpc mac"):
            if not verify_mac_on_vteps([prim_vtep, sec_vtep], '1001', 1025, prim_mac):
                log.error("Mac learning failed for orphan mac")
                self.failed("Mac learning failed for orphan mac")
            
            if not verify_mac_on_vteps([sa_vtep], '1001', 0, prim_mac):
                log.error("Mac learning failed for orphan mac")
                self.failed("Mac learning failed for orphan mac")
            
        with steps.start("Checking mac learning for standalone mac"):
            if not verify_mac_on_vteps([sa_vtep], '1002', 1025, sa_mac):
                log.error("Mac learning failed for standalone mac")
                self.failed("Mac learning failed for standalone mac")
            if not verify_mac_on_vteps([prim_vtep, sec_vtep], '1002', 0, sa_mac):
                log.error("Mac learning failed for standalone mac")
                self.failed("Mac learning failed for standalone mac")

        with steps.start("Verify traffic drop"):
            if VerifyTrafficDrop("TC_VXLAN_PVMAP_024", testscript, traffic_item='Trunk Orphan To Standalone'):
                log.info('Verify traffic drop validation success')
            else:
                self.failed('Verify traffic validation failed')

        with steps.start("no shut orphan and standalone interface"):
            try:
                prim_vtep.configure('''interface {intf}
                                       no shutdown
                                    '''.format(intf=prim_vtep_if))
                sa_vtep.configure('''interface {intf}
                                      no shutdown
                                    '''.format(intf=sa_vtep_if))
            except Exception as error:
                log.debug("Unable to configure - Encountered Exception " + str(error))
                self.errored('Exception occurred while configuring PVMAP', 
                            goto=['common_cleanup'])

        log.info('Waiting for 60secs for confing apply')
        time.sleep(60)

        with steps.start("checking mac learning for orphan mac"):
            if not verify_mac_on_vteps([prim_vtep, sec_vtep, sa_vtep], '1001', 1025, prim_mac):
                log.error("Mac learning failed for orphan mac")
                self.failed("Mac learning failed for orphan mac")

        with steps.start("checking mac learning for standalone mac"):
            if not verify_mac_on_vteps([prim_vtep, sec_vtep, sa_vtep], '1002', 1025, sa_mac):
                log.error("Mac learning failed for standalone mac")
                self.failed("Mac learning failed for standalone mac")

        with steps.start('Verify Learned mac address consistency between hardware and software'):
            if verify_mac_cc_between_hardware_software([prim_vtep, sec_vtep, sa_vtep]):
                log.info('MAC CC success')
            else:
                self.failed('MAC CC failed')

        with steps.start("Verify Steady State"):
            if VerifyTraffic("TC_VXLAN_PVMAP_024", testscript, traffic_item='Trunk Orphan To Standalone'):
                log.info('Verify traffic success')
            else:
                self.failed('Verify traffic failed') 

    @aetest.test
    def verify_error_cores(self, testscript, testbed, steps):
        sa_vtep         = testscript.parameters['LEAF-3']
        prim_vtep       = testscript.parameters['LEAF-1']
        sec_vtep        = testscript.parameters['LEAF-2']
        ixNetwork       = testscript.parameters['ixNetwork']

        with steps.start("Stopping hosts..."):
            ixNetwork.StopAllProtocols()

        log.info('Waiting {}secs'.format(traffic_stop_time))
        time.sleep(traffic_stop_time)

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

# ======================================================================================================#
# TC-ID: TC_VXLAN_PVMAP_025 - Triggers - shut/no shut
# Testcase:  
#   - Shut/no shut keep-alive
#   - Check mac learning and traffic
# ======================================================================================================#
class TC_VXLAN_PVMAP_025(aetest.Testcase):
    @aetest.test
    def testcase_vpc_shut_keepalive(self, testscript, steps):
        sa_vtep         = testscript.parameters['LEAF-3']
        prim_vtep       = testscript.parameters['LEAF-1']
        sec_vtep        = testscript.parameters['LEAF-2']
        prim_mac        = str(testscript.parameters['PVMAP_Dict']['prim_vpc_mac'])
        sa_mac          = str(testscript.parameters['PVMAP_Dict']['sa_mac'])
        prim_vtep_if    = str(testscript.parameters['intf_LEAF_1_to_LEAF_2_2'])
        sec_vtep_if     = str(testscript.parameters['intf_LEAF_2_to_LEAF_1_2'])
        p1_handle       = testscript.parameters['vpc_handle']
        p2_handle       = testscript.parameters['sa_handle']
        ixNetwork       = testscript.parameters['ixNetwork']

        with steps.start("Starting hosts..."):
            p1_handle.Start()
            p2_handle.Start()
        
        log.info('Waiting {}secs to start hosts'.format(host_start_time))
        time.sleep(host_start_time)

        stream1 = ixNetwork.Traffic.TrafficItem.find(Name='Trunk VPC To Standalone')
        stream1.StartStatelessTraffic()
        log.info('Waiting {}secs to start the traffic'.format(traffic_start_time))
        time.sleep(traffic_start_time)
        
        stream1.StopStatelessTraffic()
        log.info('Waiting {}secs to stop the traffic'.format(traffic_stop_time))
        time.sleep(traffic_stop_time)

        with steps.start("checking mac learning for orphan mac"):
            if not verify_mac_on_vteps([prim_vtep, sec_vtep, sa_vtep], '1001', 1025, prim_mac):
                log.error("Mac learning failed for orphan mac")
                self.failed("Mac learning failed for orphan mac")

        with steps.start("Checking mac learning for standalone mac"):
            if not verify_mac_on_vteps([prim_vtep, sec_vtep, sa_vtep], '1002', 1025, sa_mac):
                log.error("Mac learning failed for standalone mac")
                self.failed("Mac learning failed for standalone mac")
        
        with steps.start("shut keepalive interface"):
            try:
                prim_vtep.configure('''interface {intf}
                                       shutdown
                                    '''.format(intf=prim_vtep_if))
                sec_vtep.configure('''interface {intf}
                                      shutdown
                                    '''.format(intf=sec_vtep_if))
            except Exception as error:
                log.debug("Unable to configure - Encountered Exception " + str(error))
                self.errored('Exception occurred while configuring PVMAP', 
                            goto=['common_cleanup']) 

        log.info('Waiting 60secs for mac flushout')
        time.sleep(60)

        with steps.start("checking mac flushout for vpc mac"):
            if not verify_mac_on_vteps([prim_vtep, sa_vtep], '1001', 1025, prim_mac):
                log.error("Mac learning failed for orphan mac")
                self.failed("Mac learning failed for orphan mac")
            if not verify_mac_on_vteps([sec_vtep], '1001', 0, prim_mac):
                log.error("Mac learning failed for orphan mac")
                self.failed("Mac learning failed for orphan mac")
        
        with steps.start("Checking mac learning for standalone mac"):
            if not verify_mac_on_vteps([prim_vtep, sa_vtep], '1002', 1025, sa_mac):
                log.error("Mac learning failed for standalone mac")
                self.failed("Mac learning failed for standalone mac")
            if not verify_mac_on_vteps([sec_vtep], '1002', 0, sa_mac):
                log.error("Mac learning failed for standalone mac")
                self.failed("Mac learning failed for standalone mac")
        with steps.start("Verify traffic drop"):
            if VerifyTrafficDrop("TC_VXLAN_PVMAP_025", testscript, traffic_item='Trunk VPC To Standalone'):
                log.info('Verify traffic drop validation success')
            else:
                self.failed('Verify traffic validation failed')

        with steps.start("no shut keepalive interface"):
            try:
                prim_vtep.configure('''interface {intf}
                                       no shutdown
                                    '''.format(intf=prim_vtep_if))
                sec_vtep.configure('''interface {intf}
                                      no shutdown
                                    '''.format(intf=sec_vtep_if))
            except Exception as error:
                log.debug("Unable to configure - Encountered Exception " + str(error))
                self.errored('Exception occurred while configuring PVMAP', 
                            goto=['common_cleanup']) 

        log.info('Waiting 60secs for mac flushout')
        time.sleep(60)
        
        stream1.StartStatelessTraffic()
        log.info('Waiting {}secs to start the traffic'.format(traffic_start_time))
        time.sleep(traffic_start_time)
        
        stream1.StopStatelessTraffic()
        log.info('Waiting {}secs to stop the traffic'.format(traffic_stop_time))
        time.sleep(traffic_stop_time)
        
        log.info('Waiting 60secs for mac relearning')
        time.sleep(60)
        
        with steps.start("checking mac learning after mapping enable for vpc mac"):
            if not verify_mac_on_vteps([prim_vtep, sec_vtep, sa_vtep], '1001', 1025, prim_mac):
                log.error("Mac learning failed for orphan mac")
                self.failed("Mac learning failed for orphan mac")

        with steps.start("checking mac learning after mapping enable for standalone mac"):
            if not verify_mac_on_vteps([prim_vtep, sec_vtep, sa_vtep], '1002', 1025, sa_mac):
                log.error("Mac learning failed for standalone mac")
                self.failed("Mac learning failed for standalone mac")

        with steps.start('Verify Learned mac address consistency between hardware and software'):
            if verify_mac_cc_between_hardware_software([prim_vtep, sec_vtep, sa_vtep]):
                log.info('MAC CC success')
            else:
                self.failed('MAC CC failed')

        with steps.start("Verify Steady State"):
            if VerifyTraffic("TC_VXLAN_PVMAP_025", testscript, traffic_item='Trunk VPC To Standalone'):
                log.info('Verify traffic success')
            else:
                self.failed('Verify traffic failed') 

    @aetest.test
    def verify_error_cores(self, testscript, testbed, steps):
        sa_vtep         = testscript.parameters['LEAF-3']
        prim_vtep       = testscript.parameters['LEAF-1']
        sec_vtep        = testscript.parameters['LEAF-2']
        ixNetwork       = testscript.parameters['ixNetwork']

        with steps.start("Stopping hosts..."):
            ixNetwork.StopAllProtocols()

        log.info('Waiting {}secs'.format(traffic_stop_time))
        time.sleep(traffic_stop_time)

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

# ======================================================================================================#
# TC-ID: TC_VXLAN_PVMAP_026 - Triggers - shut/no shut
# Testcase:  
#   - NVE shut/noshut
#   - Check mac learning and traffic
# ======================================================================================================#
class TC_VXLAN_PVMAP_026(aetest.Testcase):
    @aetest.test
    def testcase_vpc_nve_shut(self, testscript, steps):
        sa_vtep         = testscript.parameters['LEAF-3']
        prim_vtep       = testscript.parameters['LEAF-1']
        sec_vtep        = testscript.parameters['LEAF-2']
        prim_mac        = str(testscript.parameters['PVMAP_Dict']['prim_vpc_mac'])
        sa_mac          = str(testscript.parameters['PVMAP_Dict']['sa_mac'])
        prim_vtep_if    = 'nve 1'
        sec_vtep_if     = 'nve 1'
        p1_handle       = testscript.parameters['vpc_handle']
        p2_handle       = testscript.parameters['sa_handle']
        ixNetwork       = testscript.parameters['ixNetwork']

        with steps.start("Starting hosts..."):
            p1_handle.Start()
            p2_handle.Start()
        
        log.info('Waiting {}secs to start hosts'.format(host_start_time))
        time.sleep(host_start_time)

        stream1 = ixNetwork.Traffic.TrafficItem.find(Name='Trunk VPC To Standalone')
        stream1.StartStatelessTraffic()
        log.info('Waiting {}secs to start the traffic'.format(traffic_start_time))
        time.sleep(traffic_start_time)
        
        stream1.StopStatelessTraffic()
        log.info('Waiting {}secs to stop the traffic'.format(traffic_stop_time))
        time.sleep(traffic_stop_time)

        with steps.start("checking mac learning for orphan mac"):
            if not verify_mac_on_vteps([prim_vtep, sec_vtep, sa_vtep], '1001', 1025, prim_mac):
                log.error("Mac learning failed for orphan mac")
                self.failed("Mac learning failed for orphan mac")

        with steps.start("Checking mac learning for standalone mac"):
            if not verify_mac_on_vteps([prim_vtep, sec_vtep, sa_vtep], '1002', 1025, sa_mac):
                log.error("Mac learning failed for standalone mac")
                self.failed("Mac learning failed for standalone mac")
        
        dialog = Dialog([
        Statement(pattern=r'Do you want to continue\? \(yes/no\) \[n\] ',
                  action='sendline(yes)',
                  loop_continue=True,
                  continue_timer=True),])

        with steps.start("shut nve interface"):
            try:
                prim_vtep.configure('''interface {intf}
                                       shutdown
                                    '''.format(intf=prim_vtep_if), prompt_recovery=True, reply=dialog, timeout=120)
                sec_vtep.configure('''interface {intf}
                                      shutdown
                                    '''.format(intf=sec_vtep_if), prompt_recovery=True, reply=dialog, timeout=120)
            except Exception as error:
                log.debug("Unable to configure - Encountered Exception " + str(error))
                self.errored('Exception occurred while configuring PVMAP', 
                            goto=['common_cleanup']) 

        log.info('Waiting 60secs for mac flushout')
        time.sleep(60)

        with steps.start("checking mac flushout for vpc mac"):
            if not verify_mac_on_vteps([sa_vtep], '1001', 0, prim_mac):
                log.error("Mac learning failed for orphan mac")
                self.failed("Mac learning failed for orphan mac")
        if not verify_mac_on_vteps([prim_vtep, sec_vtep], '1001', 1025, prim_mac):
                log.error("Mac learning failed for orphan mac")
                self.failed("Mac learning failed for orphan mac")
        
        with steps.start("Checking mac learning for standalone mac"):
            if not verify_mac_on_vteps([sa_vtep], '1002', 1025, sa_mac):
                log.error("Mac learning failed for standalone mac")
                self.failed("Mac learning failed for standalone mac")
            if not verify_mac_on_vteps([prim_vtep, sec_vtep], '1002', 0, sa_mac):
                log.error("Mac learning failed for standalone mac")
                self.failed("Mac learning failed for standalone mac")
    
        with steps.start("Verify traffic drop"):
            if VerifyTrafficDrop("TC_VXLAN_PVMAP_026", testscript, traffic_item='Trunk VPC To Standalone'):
                log.info('Verify traffic drop validation success')
            else:
                self.failed('Verify traffic validation failed')

        with steps.start("no shut uplink interface"):
            try:
                prim_vtep.configure('''interface {intf}
                                       no shutdown
                                    '''.format(intf=prim_vtep_if))
                sec_vtep.configure('''interface {intf}
                                      no shutdown
                                    '''.format(intf=sec_vtep_if))
            except Exception as error:
                log.debug("Unable to configure - Encountered Exception " + str(error))
                self.errored('Exception occurred while configuring PVMAP', 
                            goto=['common_cleanup']) 

        log.info('Waiting 60secs for mac flushout')
        time.sleep(60)
        
        stream1.StartStatelessTraffic()
        log.info('Waiting {}secs to start the traffic'.format(traffic_start_time))
        time.sleep(traffic_start_time)
        
        stream1.StopStatelessTraffic()
        log.info('Waiting {}secs to stop the traffic'.format(traffic_stop_time))
        time.sleep(traffic_stop_time)
        
        log.info('Waiting 60secs for mac relearning')
        time.sleep(60)
        
        with steps.start("checking mac learning after mapping enable for vpc mac"):
            if not verify_mac_on_vteps([prim_vtep, sec_vtep, sa_vtep], '1001', 1025, prim_mac):
                log.error("Mac learning failed for orphan mac")
                self.failed("Mac learning failed for orphan mac")

        with steps.start("checking mac learning after mapping enable for standalone mac"):
            if not verify_mac_on_vteps([prim_vtep, sec_vtep, sa_vtep], '1002', 1025, sa_mac):
                log.error("Mac learning failed for standalone mac")
                self.failed("Mac learning failed for standalone mac")

        with steps.start('Verify Learned mac address consistency between hardware and software'):
            if verify_mac_cc_between_hardware_software([prim_vtep, sec_vtep, sa_vtep]):
                log.info('MAC CC success')
            else:
                self.failed('MAC CC failed')

        with steps.start("Verify Steady State"):
            if VerifyTraffic("TC_VXLAN_PVMAP_026", testscript, traffic_item='Trunk VPC To Standalone'):
                log.info('Verify traffic success')
            else:
                self.failed('Verify traffic failed') 

    @aetest.test
    def testcase_vpc_nve_shut_nodelay(self, testscript, steps):
        sa_vtep         = testscript.parameters['LEAF-3']
        prim_vtep       = testscript.parameters['LEAF-1']
        sec_vtep        = testscript.parameters['LEAF-2']
        prim_mac        = str(testscript.parameters['PVMAP_Dict']['prim_vpc_mac'])
        sa_mac          = str(testscript.parameters['PVMAP_Dict']['sa_mac'])
        prim_vtep_if    = 'nve 1'
        sec_vtep_if     = 'nve 1'
        p1_handle       = testscript.parameters['vpc_handle']
        p2_handle       = testscript.parameters['sa_handle']
        ixNetwork       = testscript.parameters['ixNetwork']

        with steps.start("Starting hosts..."):
            p1_handle.Start()
            p2_handle.Start()
        
        log.info('Waiting {}secs to start hosts'.format(host_start_time))
        time.sleep(host_start_time)

        stream1 = ixNetwork.Traffic.TrafficItem.find(Name='Trunk VPC To Standalone')
        stream1.StartStatelessTraffic()
        log.info('Waiting {}secs to start the traffic'.format(traffic_start_time))
        time.sleep(traffic_start_time)
        
        stream1.StopStatelessTraffic()
        log.info('Waiting {}secs to stop the traffic'.format(traffic_stop_time))
        time.sleep(traffic_stop_time)

        with steps.start("checking mac learning for orphan mac"):
            if not verify_mac_on_vteps([prim_vtep, sec_vtep, sa_vtep], '1001', 1025, prim_mac):
                log.error("Mac learning failed for orphan mac")
                self.failed("Mac learning failed for orphan mac")

        with steps.start("Checking mac learning for standalone mac"):
            if not verify_mac_on_vteps([prim_vtep, sec_vtep, sa_vtep], '1002', 1025, sa_mac):
                log.error("Mac learning failed for standalone mac")
                self.failed("Mac learning failed for standalone mac")
        
        dialog = Dialog([
        Statement(pattern=r'Do you want to continue\? \(yes/no\) \[n\] ',
                  action='sendline(yes)',
                  loop_continue=True,
                  continue_timer=True),])

        with steps.start("shut/no shut nve interface"):
            try:
                prim_vtep.configure('''interface {intf}
                                       shutdown ; sleep 2 ; no shutdown
                                    '''.format(intf=prim_vtep_if), prompt_recovery=True, reply=dialog, timeout=120)
                sec_vtep.configure('''interface {intf}
                                      shutdown ; sleep 2 ; no shutdown
                                    '''.format(intf=sec_vtep_if), prompt_recovery=True, reply=dialog, timeout=120)
            except Exception as error:
                log.debug("Unable to configure - Encountered Exception " + str(error))
                self.errored('Exception occurred while configuring PVMAP', 
                            goto=['common_cleanup']) 

        stream1.StartStatelessTraffic()
        log.info('Waiting {}secs to start the traffic'.format(traffic_start_time))
        time.sleep(traffic_start_time)
        
        stream1.StopStatelessTraffic()
        log.info('Waiting {}secs to stop the traffic'.format(traffic_stop_time))
        time.sleep(traffic_stop_time)
        
        log.info('Waiting 60secs for mac relearning')
        time.sleep(60)
        
        with steps.start("checking mac learning after mapping enable for vpc mac"):
            if not verify_mac_on_vteps([prim_vtep, sec_vtep, sa_vtep], '1001', 1025, prim_mac):
                log.error("Mac learning failed for orphan mac")
                self.failed("Mac learning failed for orphan mac")

        with steps.start("checking mac learning after mapping enable for standalone mac"):
            if not verify_mac_on_vteps([prim_vtep, sec_vtep, sa_vtep], '1002', 1025, sa_mac):
                log.error("Mac learning failed for standalone mac")
                self.failed("Mac learning failed for standalone mac")

        with steps.start('Verify Learned mac address consistency between hardware and software'):
            if verify_mac_cc_between_hardware_software([prim_vtep, sec_vtep, sa_vtep]):
                log.info('MAC CC success')
            else:
                self.failed('MAC CC failed')

        with steps.start("Verify Steady State"):
            if VerifyTraffic("TC_VXLAN_PVMAP_026", testscript, traffic_item='Trunk VPC To Standalone'):
                log.info('Verify traffic success')
            else:
                self.failed('Verify traffic failed') 

    @aetest.test
    def testcase_orphan_nve_shut(self, testscript, steps):
        sa_vtep         = testscript.parameters['LEAF-3']
        prim_vtep       = testscript.parameters['LEAF-1']
        sec_vtep        = testscript.parameters['LEAF-2']
        prim_mac        = str(testscript.parameters['PVMAP_Dict']['prim_orphan_mac'])
        sa_mac          = str(testscript.parameters['PVMAP_Dict']['sa_mac'])
        prim_vtep_if    = 'nve 1'
        sa_vtep_if      = 'nve 1'
        p1_handle       = testscript.parameters['orphan1_handle']
        p2_handle       = testscript.parameters['sa_handle']
        ixNetwork       = testscript.parameters['ixNetwork']

        with steps.start("Starting hosts..."):
            p1_handle.Start()
            p2_handle.Start()
        
        log.info('Waiting {}secs to start hosts'.format(host_start_time))
        time.sleep(host_start_time)

        stream1 = ixNetwork.Traffic.TrafficItem.find(Name='Trunk Orphan To Standalone')
        stream1.StartStatelessTraffic()
        log.info('Waiting {}secs to start the traffic'.format(traffic_start_time))
        time.sleep(traffic_start_time)
        
        stream1.StopStatelessTraffic()
        log.info('Waiting {}secs to stop the traffic'.format(traffic_stop_time))
        time.sleep(traffic_stop_time)

        with steps.start("checking mac learning for orphan mac"):
            if not verify_mac_on_vteps([prim_vtep, sec_vtep, sa_vtep], '1001', 1025, prim_mac):
                log.error("Mac learning failed for orphan mac")
                self.failed("Mac learning failed for orphan mac")

        with steps.start("Checking mac learning for standalone mac"):
            if not verify_mac_on_vteps([prim_vtep, sec_vtep, sa_vtep], '1002', 1025, sa_mac):
                log.error("Mac learning failed for standalone mac")
                self.failed("Mac learning failed for standalone mac")

        dialog = Dialog([
        Statement(pattern=r'Do you want to continue\? \(yes/no\) \[n\] ',
                  action='sendline(yes)',
                  loop_continue=True,
                  continue_timer=True),])
        
        with steps.start("shut nve on primary and standalone interface"):
            try:
                prim_vtep.configure('''interface {intf}
                                       shutdown
                                    '''.format(intf=prim_vtep_if), prompt_recovery=True, reply=dialog, timeout=120)
                sa_vtep.configure('''interface {intf}
                                      shutdown
                                    '''.format(intf=sa_vtep_if))
            except Exception as error:
                log.debug("Unable to configure - Encountered Exception " + str(error))
                self.errored('Exception occurred while configuring PVMAP', 
                            goto=['common_cleanup']) 

        log.info('Waiting for 60secs for confing apply')
        time.sleep(60)
        
        with steps.start("checking mac flushout for vpc mac"):
            if not verify_mac_on_vteps([prim_vtep, sec_vtep], '1001', 1025, prim_mac):
                log.error("Mac learning failed for orphan mac")
                self.failed("Mac learning failed for orphan mac")
            
            if not verify_mac_on_vteps([sa_vtep], '1001', 0, prim_mac):
                log.error("Mac learning failed for orphan mac")
                self.failed("Mac learning failed for orphan mac")
    
        with steps.start("Checking mac learning for standalone mac"):
            if not verify_mac_on_vteps([sa_vtep], '1002', 1025, sa_mac):
                log.error("Mac learning failed for standalone mac")
                self.failed("Mac learning failed for standalone mac")
            if not verify_mac_on_vteps([prim_vtep, sec_vtep], '1002', 0, sa_mac):
                log.error("Mac learning failed for standalone mac")
                self.failed("Mac learning failed for standalone mac")

        with steps.start("Verify traffic drop"):
            if VerifyTrafficDrop("TC_VXLAN_PVMAP_026", testscript, traffic_item='Trunk Orphan To Standalone'):
                log.info('Verify traffic drop validation success')
            else:
                self.failed('Verify traffic validation failed')

        with steps.start("no shut orphan and standalone interface"):
            try:
                prim_vtep.configure('''interface {intf}
                                       no shutdown
                                    '''.format(intf=prim_vtep_if), prompt_recovery=True, reply=dialog, timeout=120)
                sa_vtep.configure('''interface {intf}
                                      no shutdown
                                    '''.format(intf=sa_vtep_if))
            except Exception as error:
                log.debug("Unable to configure - Encountered Exception " + str(error))
                self.errored('Exception occurred while configuring PVMAP', 
                            goto=['common_cleanup'])

        log.info('Waiting for 60secs for confing apply')
        time.sleep(60)

        with steps.start("checking mac learning after mapping enable for  orphan mac"):
            if not verify_mac_on_vteps([prim_vtep, sec_vtep, sa_vtep], '1001', 1025, prim_mac):
                log.error("Mac learning failed for orphan mac")
                self.failed("Mac learning failed for orphan mac")

        with steps.start("checking mac learning after mapping enable for standalone mac"):
            if not verify_mac_on_vteps([prim_vtep, sec_vtep, sa_vtep], '1002', 1025, sa_mac):
                log.error("Mac learning failed for standalone mac")
                self.failed("Mac learning failed for standalone mac")

        with steps.start('Verify Learned mac address consistency between hardware and software'):
            if verify_mac_cc_between_hardware_software([prim_vtep, sec_vtep, sa_vtep]):
                log.info('MAC CC success')
            else:
                self.failed('MAC CC failed')

        with steps.start("Verify Steady State"):
            if VerifyTraffic("TC_VXLAN_PVMAP_026", testscript, traffic_item='Trunk Orphan To Standalone'):
                log.info('Verify traffic success')
            else:
                self.failed('Verify traffic failed') 

    @aetest.test
    def testcase_orphan_nve_shut_nodelat(self, testscript, steps):
        sa_vtep         = testscript.parameters['LEAF-3']
        prim_vtep       = testscript.parameters['LEAF-1']
        sec_vtep        = testscript.parameters['LEAF-2']
        prim_mac        = str(testscript.parameters['PVMAP_Dict']['prim_orphan_mac'])
        sa_mac          = str(testscript.parameters['PVMAP_Dict']['sa_mac'])
        prim_vtep_if    = 'nve 1'
        sa_vtep_if      = 'nve 1'
        p1_handle       = testscript.parameters['orphan1_handle']
        p2_handle       = testscript.parameters['sa_handle']
        ixNetwork       = testscript.parameters['ixNetwork']

        with steps.start("Starting hosts..."):
            p1_handle.Start()
            p2_handle.Start()
        
        log.info('Waiting {}secs to start hosts'.format(host_start_time))
        time.sleep(host_start_time)

        stream1 = ixNetwork.Traffic.TrafficItem.find(Name='Trunk Orphan To Standalone')
        stream1.StartStatelessTraffic()
        log.info('Waiting {}secs to start the traffic'.format(traffic_start_time))
        time.sleep(traffic_start_time)
        
        stream1.StopStatelessTraffic()
        log.info('Waiting {}secs to stop the traffic'.format(traffic_stop_time))
        time.sleep(traffic_stop_time)

        with steps.start("checking mac learning for orphan mac"):
            if not verify_mac_on_vteps([prim_vtep, sec_vtep, sa_vtep], '1001', 1025, prim_mac):
                log.error("Mac learning failed for orphan mac")
                self.failed("Mac learning failed for orphan mac")

        with steps.start("Checking mac learning for standalone mac"):
            if not verify_mac_on_vteps([prim_vtep, sec_vtep, sa_vtep], '1002', 1025, sa_mac):
                log.error("Mac learning failed for standalone mac")
                self.failed("Mac learning failed for standalone mac")

        dialog = Dialog([
        Statement(pattern=r'Do you want to continue\? \(yes/no\) \[n\] ',
                  action='sendline(yes)',
                  loop_continue=True,
                  continue_timer=True),])
        
        with steps.start("shut/no shut nve primary and standalone interface"):
            try:
                prim_vtep.configure('''interface {intf}
                                       shutdown ; sleep 2 ; no shutdown
                                    '''.format(intf=prim_vtep_if), prompt_recovery=True, reply=dialog, timeout=120)
                sa_vtep.configure('''interface {intf}
                                      shutdown ; sleep 2 ; no shutdown
                                    '''.format(intf=sa_vtep_if))
            except Exception as error:
                log.debug("Unable to configure - Encountered Exception " + str(error))
                self.errored('Exception occurred while configuring PVMAP', 
                            goto=['common_cleanup']) 

        log.info('Waiting for 60secs for confing apply')
        time.sleep(60)

        with steps.start("checking mac learning after mapping enable for  orphan mac"):
            if not verify_mac_on_vteps([prim_vtep, sec_vtep, sa_vtep], '1001', 1025, prim_mac):
                log.error("Mac learning failed for orphan mac")
                self.failed("Mac learning failed for orphan mac")

        with steps.start("checking mac learning after mapping enable for standalone mac"):
            if not verify_mac_on_vteps([prim_vtep, sec_vtep, sa_vtep], '1002', 1025, sa_mac):
                log.error("Mac learning failed for standalone mac")
                self.failed("Mac learning failed for standalone mac")

        with steps.start('Verify Learned mac address consistency between hardware and software'):
            if verify_mac_cc_between_hardware_software([prim_vtep, sec_vtep, sa_vtep]):
                log.info('MAC CC success')
            else:
                self.failed('MAC CC failed')

        with steps.start("Verify Steady State"):
            if VerifyTraffic("TC_VXLAN_PVMAP_026", testscript, traffic_item='Trunk Orphan To Standalone'):
                log.info('Verify traffic success')
            else:
                self.failed('Verify traffic failed') 

    @aetest.test
    def verify_error_cores(self, testscript, testbed, steps):
        sa_vtep         = testscript.parameters['LEAF-3']
        prim_vtep       = testscript.parameters['LEAF-1']
        sec_vtep        = testscript.parameters['LEAF-2']
        prim_vtep_if    = 'nve 1'
        sa_vtep_if      = 'nve 1'
        ixNetwork       = testscript.parameters['ixNetwork']

        with steps.start("Stopping hosts..."):
            ixNetwork.StopAllProtocols()

        log.info('Waiting {}secs'.format(traffic_stop_time))
        time.sleep(traffic_stop_time)

        with steps.start("no shut orphan and standalone interface"):
            try:
                prim_vtep.configure('''interface {intf}
                                       no shutdown
                                    '''.format(intf=prim_vtep_if))
                sec_vtep.configure('''interface {intf}
                                       no shutdown
                                    '''.format(intf=prim_vtep_if))
                sa_vtep.configure('''interface {intf}
                                      no shutdown
                                    '''.format(intf=sa_vtep_if))
            except Exception as error:
                log.debug("Unable to configure - Encountered Exception " + str(error))
                self.errored('Exception occurred while configuring PVMAP', 
                            goto=['common_cleanup'])

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

# =====================================================================================================#
# TC-ID: TC_VXLAN_PVMAP_027 - Triggers - shut/no shut
# Testcase:  
#   - bgp flap
#   - Check mac learning and traffic
# ======================================================================================================#
class TC_VXLAN_PVMAP_027(aetest.Testcase):
    @aetest.test
    def testcase_vpc_bgp_flap(self, testscript, steps):
        sa_vtep         = testscript.parameters['LEAF-3']
        prim_vtep       = testscript.parameters['LEAF-1']
        sec_vtep        = testscript.parameters['LEAF-2']
        prim_mac        = str(testscript.parameters['PVMAP_Dict']['prim_vpc_mac'])
        sa_mac          = str(testscript.parameters['PVMAP_Dict']['sa_mac'])
        bgp_as          = str(testscript.parameters['forwardingSysDict']['BGP_AS_num'])
        p1_handle       = testscript.parameters['vpc_handle']
        p2_handle       = testscript.parameters['sa_handle']
        ixNetwork       = testscript.parameters['ixNetwork']

        with steps.start("Starting hosts..."):
            p1_handle.Start()
            p2_handle.Start()
        
        log.info('Waiting {}secs to start hosts'.format(host_start_time))
        time.sleep(host_start_time)

        stream1 = ixNetwork.Traffic.TrafficItem.find(Name='Trunk VPC To Standalone')
        stream1.StartStatelessTraffic()
        log.info('Waiting {}secs to start the traffic'.format(traffic_start_time))
        time.sleep(traffic_start_time)
        
        stream1.StopStatelessTraffic()
        log.info('Waiting {}secs to stop the traffic'.format(traffic_stop_time))
        time.sleep(traffic_stop_time)

        with steps.start("checking mac learning for orphan mac"):
            if not verify_mac_on_vteps([prim_vtep, sec_vtep, sa_vtep], '1001', 1025, prim_mac):
                log.error("Mac learning failed for orphan mac")
                self.failed("Mac learning failed for orphan mac")

        with steps.start("Checking mac learning for standalone mac"):
            if not verify_mac_on_vteps([prim_vtep, sec_vtep, sa_vtep], '1002', 1025, sa_mac):
                log.error("Mac learning failed for standalone mac")
                self.failed("Mac learning failed for standalone mac")
        
        with steps.start("BGP shut/no shut"):
            try:
                prim_vtep.configure('''router bgp {asn}
                                       shutdown ; sleep 2 ; no shutdown
                                    '''.format(asn=bgp_as))
                sec_vtep.configure('''router bgp {asn}
                                       shutdown ; sleep 2 ; no shutdown
                                    '''.format(asn=bgp_as))
            except Exception as error:
                log.debug("Unable to configure - Encountered Exception " + str(error))
                self.errored('Exception occurred while configuring PVMAP', 
                            goto=['common_cleanup']) 

        stream1.StartStatelessTraffic()
        log.info('Waiting {}secs to start the traffic'.format(traffic_start_time))
        time.sleep(traffic_start_time)
        
        stream1.StopStatelessTraffic()
        log.info('Waiting {}secs to stop the traffic'.format(traffic_stop_time))
        time.sleep(traffic_stop_time)
        
        log.info('Waiting 60secs for mac relearning')
        time.sleep(60)
        
        with steps.start("checking mac learning after mapping enable for vpc mac"):
            if not verify_mac_on_vteps([prim_vtep, sec_vtep, sa_vtep], '1001', 1025, prim_mac):
                log.error("Mac learning failed for orphan mac")
                self.failed("Mac learning failed for orphan mac")

        with steps.start("checking mac learning after mapping enable for standalone mac"):
            if not verify_mac_on_vteps([prim_vtep, sec_vtep, sa_vtep], '1002', 1025, sa_mac):
                log.error("Mac learning failed for standalone mac")
                self.failed("Mac learning failed for standalone mac")

        with steps.start('Verify Learned mac address consistency between hardware and software'):
            if verify_mac_cc_between_hardware_software([prim_vtep, sec_vtep, sa_vtep]):
                log.info('MAC CC success')
            else:
                self.failed('MAC CC failed')

        with steps.start("Verify Steady State"):
            if VerifyTraffic("TC_VXLAN_PVMAP_027", testscript, traffic_item='Trunk VPC To Standalone'):
                log.info('Verify traffic success')
            else:
                self.failed('Verify traffic failed') 

    @aetest.test
    def testcase_orphan_bgp_flap(self, testscript, steps):
        sa_vtep         = testscript.parameters['LEAF-3']
        prim_vtep       = testscript.parameters['LEAF-1']
        sec_vtep        = testscript.parameters['LEAF-2']
        prim_mac        = str(testscript.parameters['PVMAP_Dict']['prim_orphan_mac'])
        sa_mac          = str(testscript.parameters['PVMAP_Dict']['sa_mac'])
        bgp_as          = str(testscript.parameters['forwardingSysDict']['BGP_AS_num'])
        p1_handle       = testscript.parameters['orphan1_handle']
        p2_handle       = testscript.parameters['sa_handle']
        ixNetwork       = testscript.parameters['ixNetwork']

        with steps.start("Starting hosts..."):
            p1_handle.Start()
            p2_handle.Start()
        
        log.info('Waiting {}secs to start hosts'.format(host_start_time))
        time.sleep(host_start_time)

        stream1 = ixNetwork.Traffic.TrafficItem.find(Name='Trunk Orphan To Standalone')
        stream1.StartStatelessTraffic()
        log.info('Waiting {}secs to start the traffic'.format(traffic_start_time))
        time.sleep(traffic_start_time)
        
        stream1.StopStatelessTraffic()
        log.info('Waiting {}secs to stop the traffic'.format(traffic_stop_time))
        time.sleep(traffic_stop_time)

        with steps.start("checking mac learning for orphan mac"):
            if not verify_mac_on_vteps([prim_vtep, sec_vtep, sa_vtep], '1001', 1025, prim_mac):
                log.error("Mac learning failed for orphan mac")
                self.failed("Mac learning failed for orphan mac")

        with steps.start("Checking mac learning for standalone mac"):
            if not verify_mac_on_vteps([prim_vtep, sec_vtep, sa_vtep], '1002', 1025, sa_mac):
                log.error("Mac learning failed for standalone mac")
                self.failed("Mac learning failed for standalone mac")
        
        with steps.start("shut orphan and standalone interface"):
            try:
                prim_vtep.configure('''router bgp {asn}
                                       shutdown ; sleep 20 ; no shutdown
                                    '''.format(asn=bgp_as))
                sa_vtep.configure('''router bgp {asn}
                                       shutdown ; sleep 20 ; no shutdown
                                    '''.format(asn=bgp_as))
            except Exception as error:
                log.debug("Unable to configure - Encountered Exception " + str(error))
                self.errored('Exception occurred while configuring PVMAP', 
                            goto=['common_cleanup']) 

        stream1.StartStatelessTraffic()
        log.info('Waiting {}secs to start the traffic'.format(traffic_start_time))
        time.sleep(traffic_start_time)
        
        stream1.StopStatelessTraffic()
        log.info('Waiting {}secs to stop the traffic'.format(traffic_stop_time))
        time.sleep(traffic_stop_time)

        log.info('Waiting for 60secs for confing apply')
        time.sleep(60)

        with steps.start("checking mac learning after mapping enable for  orphan mac"):
            if not verify_mac_on_vteps([prim_vtep, sec_vtep, sa_vtep], '1001', 1025, prim_mac):
                log.error("Mac learning failed for orphan mac")
                self.failed("Mac learning failed for orphan mac")

        with steps.start("checking mac learning after mapping enable for standalone mac"):
            if not verify_mac_on_vteps([prim_vtep, sec_vtep, sa_vtep], '1002', 1025, sa_mac):
                log.error("Mac learning failed for standalone mac")
                self.failed("Mac learning failed for standalone mac")

        with steps.start('Verify Learned mac address consistency between hardware and software'):
            if verify_mac_cc_between_hardware_software([prim_vtep, sec_vtep, sa_vtep]):
                log.info('MAC CC success')
            else:
                self.failed('MAC CC failed')

        with steps.start("Verify Steady State"):
            if VerifyTraffic("TC_VXLAN_PVMAP_027", testscript, traffic_item='Trunk Orphan To Standalone'):
                log.info('Verify traffic success')
            else:
                self.failed('Verify traffic failed') 

    @aetest.test
    def verify_error_cores(self, testscript, testbed, steps):
        sa_vtep         = testscript.parameters['LEAF-3']
        prim_vtep       = testscript.parameters['LEAF-1']
        sec_vtep        = testscript.parameters['LEAF-2']
        ixNetwork       = testscript.parameters['ixNetwork']

        with steps.start("Stopping hosts..."):
            ixNetwork.StopAllProtocols()

        log.info('Waiting {}secs'.format(traffic_stop_time))
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

# =====================================================================================================#
# TC-ID: TC_VXLAN_PVMAP_028 - Triggers - shut/no shut
# Testcase:  
#   - vrf flap
#   - Check mac learning and traffic
# ======================================================================================================#
class TC_VXLAN_PVMAP_028(aetest.Testcase):
    @aetest.test
    def testcase_vpc_vrf_flap(self, testscript, steps):
        sa_vtep         = testscript.parameters['LEAF-3']
        prim_vtep       = testscript.parameters['LEAF-1']
        sec_vtep        = testscript.parameters['LEAF-2']
        prim_mac        = str(testscript.parameters['PVMAP_Dict']['prim_vpc_mac'])
        sa_mac          = str(testscript.parameters['PVMAP_Dict']['sa_mac'])
        VRF_string      = str(testscript.parameters['forwardingSysDict']['VRF_string'])
        VRF_id_start    = str(testscript.parameters['forwardingSysDict']['VRF_id_start'])
        vrf_id 			= VRF_string + VRF_id_start
        p1_handle       = testscript.parameters['vpc_handle']
        p2_handle       = testscript.parameters['sa_handle']
        ixNetwork       = testscript.parameters['ixNetwork']

        with steps.start("Starting hosts..."):
            p1_handle.Start()
            p2_handle.Start()
        
        log.info('Waiting {}secs to start hosts'.format(host_start_time))
        time.sleep(host_start_time)

        stream1 = ixNetwork.Traffic.TrafficItem.find(Name='Trunk VPC To Standalone')
        stream1.StartStatelessTraffic()
        log.info('Waiting {}secs to start the traffic'.format(traffic_start_time))
        time.sleep(traffic_start_time)
        
        stream1.StopStatelessTraffic()
        log.info('Waiting {}secs to stop the traffic'.format(traffic_stop_time))
        time.sleep(traffic_stop_time)

        with steps.start("checking mac learning for orphan mac"):
            if not verify_mac_on_vteps([prim_vtep, sec_vtep, sa_vtep], '1001', 1025, prim_mac):
                log.error("Mac learning failed for orphan mac")
                self.failed("Mac learning failed for orphan mac")

        with steps.start("Checking mac learning for standalone mac"):
            if not verify_mac_on_vteps([prim_vtep, sec_vtep, sa_vtep], '1002', 1025, sa_mac):
                log.error("Mac learning failed for standalone mac")
                self.failed("Mac learning failed for standalone mac")
        
        with steps.start("VRF shut/no shut"):
            try:
                prim_vtep.configure('''vrf context {vrf}
                                       shutdown ; sleep 120 ; no shutdown
                                    '''.format(vrf=vrf_id), timeout=150)
                sec_vtep.configure('''vrf context {vrf}
                                       shutdown ; sleep 120 ; no shutdown
                                    '''.format(vrf=vrf_id), timeout=150)
            except Exception as error:
                log.debug("Unable to configure - Encountered Exception " + str(error))
                self.errored('Exception occurred while configuring PVMAP', 
                            goto=['common_cleanup']) 

        stream1.StartStatelessTraffic()
        log.info('Waiting {}secs to start the traffic'.format(traffic_start_time))
        time.sleep(traffic_start_time)
        
        stream1.StopStatelessTraffic()
        log.info('Waiting {}secs to stop the traffic'.format(traffic_stop_time))
        time.sleep(traffic_stop_time)
        
        log.info('Waiting 60secs for mac relearning')
        time.sleep(60)
        
        with steps.start("checking mac learning after mapping enable for vpc mac"):
            if not verify_mac_on_vteps([prim_vtep, sec_vtep, sa_vtep], '1001', 1025, prim_mac):
                log.error("Mac learning failed for orphan mac")
                self.failed("Mac learning failed for orphan mac")

        with steps.start("checking mac learning after mapping enable for standalone mac"):
            if not verify_mac_on_vteps([prim_vtep, sec_vtep, sa_vtep], '1002', 1025, sa_mac):
                log.error("Mac learning failed for standalone mac")
                self.failed("Mac learning failed for standalone mac")

        with steps.start('Verify Learned mac address consistency between hardware and software'):
            if verify_mac_cc_between_hardware_software([prim_vtep, sec_vtep, sa_vtep]):
                log.info('MAC CC success')
            else:
                self.failed('MAC CC failed')

        with steps.start("Verify Steady State"):
            if VerifyTraffic("TC_VXLAN_PVMAP_028", testscript, traffic_item='Trunk VPC To Standalone'):
                log.info('Verify traffic success')
            else:
                self.failed('Verify traffic failed') 

    @aetest.test
    def testcase_orphan_vrf_flap(self, testscript, steps):
        sa_vtep         = testscript.parameters['LEAF-3']
        prim_vtep       = testscript.parameters['LEAF-1']
        sec_vtep        = testscript.parameters['LEAF-2']
        prim_mac        = str(testscript.parameters['PVMAP_Dict']['prim_orphan_mac'])
        sa_mac          = str(testscript.parameters['PVMAP_Dict']['sa_mac'])
        VRF_string      = str(testscript.parameters['forwardingSysDict']['VRF_string'])
        VRF_id_start    = str(testscript.parameters['forwardingSysDict']['VRF_id_start'])
        vrf_id 			= VRF_string + VRF_id_start
        p1_handle       = testscript.parameters['orphan1_handle']
        p2_handle       = testscript.parameters['sa_handle']
        ixNetwork       = testscript.parameters['ixNetwork']

        with steps.start("Starting hosts..."):
            p1_handle.Start()
            p2_handle.Start()
        
        log.info('Waiting {}secs to start hosts'.format(host_start_time))
        time.sleep(host_start_time)

        stream1 = ixNetwork.Traffic.TrafficItem.find(Name='Trunk Orphan To Standalone')
        stream1.StartStatelessTraffic()
        log.info('Waiting {}secs to start the traffic'.format(traffic_start_time))
        time.sleep(traffic_start_time)
        
        stream1.StopStatelessTraffic()
        log.info('Waiting {}secs to stop the traffic'.format(traffic_stop_time))
        time.sleep(traffic_stop_time)

        with steps.start("checking mac learning for orphan mac"):
            if not verify_mac_on_vteps([prim_vtep, sec_vtep, sa_vtep], '1001', 1025, prim_mac):
                log.error("Mac learning failed for orphan mac")
                self.failed("Mac learning failed for orphan mac")

        with steps.start("Checking mac learning for standalone mac"):
            if not verify_mac_on_vteps([prim_vtep, sec_vtep, sa_vtep], '1002', 1025, sa_mac):
                log.error("Mac learning failed for standalone mac")
                self.failed("Mac learning failed for standalone mac")
        
        with steps.start("shut/no shut vrf on orphan and standalone"):
            try:
                prim_vtep.configure('''vrf context {vrf}
                                       shutdown ; sleep 120 ; no shutdown
                                    '''.format(vrf=vrf_id), timeout=150)
                sa_vtep.configure('''vrf context {vrf}
                                       shutdown ; sleep 120 ; no shutdown
                                    '''.format(vrf=vrf_id), timeout=150)
            except Exception as error:
                log.debug("Unable to configure - Encountered Exception " + str(error))
                self.errored('Exception occurred while configuring PVMAP', 
                            goto=['common_cleanup']) 

        stream1.StartStatelessTraffic()
        log.info('Waiting {}secs to start the traffic'.format(traffic_start_time))
        time.sleep(traffic_start_time)
        
        stream1.StopStatelessTraffic()
        log.info('Waiting {}secs to stop the traffic'.format(traffic_stop_time))
        time.sleep(traffic_stop_time)

        log.info('Waiting for 60secs for confing apply')
        time.sleep(60)

        with steps.start("checking mac learning after mapping enable for  orphan mac"):
            if not verify_mac_on_vteps([prim_vtep, sec_vtep, sa_vtep], '1001', 1025, prim_mac):
                log.error("Mac learning failed for orphan mac")
                self.failed("Mac learning failed for orphan mac")

        with steps.start("checking mac learning after mapping enable for standalone mac"):
            if not verify_mac_on_vteps([prim_vtep, sec_vtep, sa_vtep], '1002', 1025, sa_mac):
                log.error("Mac learning failed for standalone mac")
                self.failed("Mac learning failed for standalone mac")

        with steps.start('Verify Learned mac address consistency between hardware and software'):
            if verify_mac_cc_between_hardware_software([prim_vtep, sec_vtep, sa_vtep]):
                log.info('MAC CC success')
            else:
                self.failed('MAC CC failed')

        with steps.start("Verify Steady State"):
            if VerifyTraffic("TC_VXLAN_PVMAP_028", testscript, traffic_item='Trunk Orphan To Standalone'):
                log.info('Verify traffic success')
            else:
                self.failed('Verify traffic failed') 

    @aetest.test
    def verify_error_cores(self, testscript, testbed, steps):
        sa_vtep         = testscript.parameters['LEAF-3']
        prim_vtep       = testscript.parameters['LEAF-1']
        sec_vtep        = testscript.parameters['LEAF-2']
        ixNetwork       = testscript.parameters['ixNetwork']

        with steps.start("Stopping hosts..."):
            ixNetwork.StopAllProtocols()

        log.info('Waiting {}secs'.format(traffic_stop_time))
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

# =====================================================================================================#
# TC-ID: TC_VXLAN_PVMAP_029 - Triggers - shut/no shut
# Testcase:  
#   - vrf flap
#   - Check mac learning and traffic
# ======================================================================================================#
class TC_VXLAN_PVMAP_029(aetest.Testcase):
    @aetest.test
    def testcase_vpc_svi_flap(self, testscript, steps):
        sa_vtep         = testscript.parameters['LEAF-3']
        prim_vtep       = testscript.parameters['LEAF-1']
        sec_vtep        = testscript.parameters['LEAF-2']
        prim_mac        = str(testscript.parameters['PVMAP_Dict']['prim_vpc_mac'])
        sa_mac          = str(testscript.parameters['PVMAP_Dict']['sa_mac'])
        vlan1           = int(testscript.parameters['LEAF_1_Orphan1_TGEN_dict']['vlan_id'])
        vlan3           = int(testscript.parameters['LEAF_3_TGEN_dict']['vlan_id'])
        p1_handle       = testscript.parameters['vpc_handle']
        p2_handle       = testscript.parameters['sa_handle']
        ixNetwork       = testscript.parameters['ixNetwork']

        with steps.start("Starting hosts..."):
            p1_handle.Start()
            p2_handle.Start()
        
        log.info('Waiting {}secs to start hosts'.format(host_start_time))
        time.sleep(host_start_time)

        stream1 = ixNetwork.Traffic.TrafficItem.find(Name='Trunk VPC To Standalone')
        stream1.StartStatelessTraffic()
        log.info('Waiting {}secs to start the traffic'.format(traffic_start_time))
        time.sleep(traffic_start_time)
        
        stream1.StopStatelessTraffic()
        log.info('Waiting {}secs to stop the traffic'.format(traffic_stop_time))
        time.sleep(traffic_stop_time)

        with steps.start("checking mac learning for orphan mac"):
            if not verify_mac_on_vteps([prim_vtep, sec_vtep, sa_vtep], '1001', 1025, prim_mac):
                log.error("Mac learning failed for orphan mac")
                self.failed("Mac learning failed for orphan mac")

        with steps.start("Checking mac learning for standalone mac"):
            if not verify_mac_on_vteps([prim_vtep, sec_vtep, sa_vtep], '1002', 1025, sa_mac):
                log.error("Mac learning failed for standalone mac")
                self.failed("Mac learning failed for standalone mac")
        
        with steps.start("SVI shut/no on VPC"):
            try:
                prim_vtep.configure('''interface vlan {vlan1}
                                       shutdown ; sleep 20 ; no shutdown
                                       interface vlan {vlan3}
                                       shutdown ; sleep 20 ; no shutdown
                                    '''.format(vlan1=vlan1, vlan3=vlan3))
                sec_vtep.configure('''interface vlan {vlan1}
                                       shutdown ; sleep 20 ; no shutdown
                                       interface vlan {vlan3}
                                       shutdown ; sleep 20 ; no shutdown
                                    '''.format(vlan1=vlan1, vlan3=vlan3))
            except Exception as error:
                log.debug("Unable to configure - Encountered Exception " + str(error))
                self.errored('Exception occurred while configuring PVMAP', 
                            goto=['common_cleanup']) 

        stream1.StartStatelessTraffic()
        log.info('Waiting {}secs to start the traffic'.format(traffic_start_time))
        time.sleep(traffic_start_time)
        
        stream1.StopStatelessTraffic()
        log.info('Waiting {}secs to stop the traffic'.format(traffic_stop_time))
        time.sleep(traffic_stop_time)
        
        log.info('Waiting 60secs for mac relearning')
        time.sleep(60)
        
        with steps.start("checking mac learning after mapping enable for vpc mac"):
            if not verify_mac_on_vteps([prim_vtep, sec_vtep, sa_vtep], '1001', 1025, prim_mac):
                log.error("Mac learning failed for orphan mac")
                self.failed("Mac learning failed for orphan mac")

        with steps.start("checking mac learning after mapping enable for standalone mac"):
            if not verify_mac_on_vteps([prim_vtep, sec_vtep, sa_vtep], '1002', 1025, sa_mac):
                log.error("Mac learning failed for standalone mac")
                self.failed("Mac learning failed for standalone mac")

        with steps.start('Verify Learned mac address consistency between hardware and software'):
            if verify_mac_cc_between_hardware_software([prim_vtep, sec_vtep, sa_vtep]):
                log.info('MAC CC success')
            else:
                self.failed('MAC CC failed')

        with steps.start("Verify Steady State"):
            if VerifyTraffic("TC_VXLAN_PVMAP_029", testscript, traffic_item='Trunk VPC To Standalone'):
                log.info('Verify traffic success')
            else:
                self.failed('Verify traffic failed') 

    @aetest.test
    def testcase_orphan_svi_flap(self, testscript, steps):
        sa_vtep         = testscript.parameters['LEAF-3']
        prim_vtep       = testscript.parameters['LEAF-1']
        sec_vtep        = testscript.parameters['LEAF-2']
        prim_mac        = str(testscript.parameters['PVMAP_Dict']['prim_orphan_mac'])
        sa_mac          = str(testscript.parameters['PVMAP_Dict']['sa_mac'])
        vlan1           = int(testscript.parameters['LEAF_1_Orphan1_TGEN_dict']['vlan_id'])
        vlan3           = int(testscript.parameters['LEAF_3_TGEN_dict']['vlan_id'])
        p1_handle       = testscript.parameters['orphan1_handle']
        p2_handle       = testscript.parameters['sa_handle']
        ixNetwork       = testscript.parameters['ixNetwork']

        with steps.start("Starting hosts..."):
            p1_handle.Start()
            p2_handle.Start()
        
        log.info('Waiting {}secs to start hosts'.format(host_start_time))
        time.sleep(host_start_time)

        stream1 = ixNetwork.Traffic.TrafficItem.find(Name='Trunk Orphan To Standalone')
        stream1.StartStatelessTraffic()
        log.info('Waiting {}secs to start the traffic'.format(traffic_start_time))
        time.sleep(traffic_start_time)
        
        stream1.StopStatelessTraffic()
        log.info('Waiting {}secs to stop the traffic'.format(traffic_stop_time))
        time.sleep(traffic_stop_time)

        with steps.start("checking mac learning for orphan mac"):
            if not verify_mac_on_vteps([prim_vtep, sec_vtep, sa_vtep], '1001', 1025, prim_mac):
                log.error("Mac learning failed for orphan mac")
                self.failed("Mac learning failed for orphan mac")

        with steps.start("Checking mac learning for standalone mac"):
            if not verify_mac_on_vteps([prim_vtep, sec_vtep, sa_vtep], '1002', 1025, sa_mac):
                log.error("Mac learning failed for standalone mac")
                self.failed("Mac learning failed for standalone mac")
        
        with steps.start("SVI shut/no shut on orphan and standalone"):
            try:
                prim_vtep.configure('''interface vlan {vlan1}
                                       shutdown ; sleep 20 ; no shutdown
                                       interface vlan {vlan3}
                                       shutdown ; sleep 20 ; no shutdown
                                    '''.format(vlan1=vlan1, vlan3=vlan3))
                sa_vtep.configure('''interface vlan {vlan1}
                                       shutdown ; sleep 20 ; no shutdown
                                       interface vlan {vlan3}
                                       shutdown ; sleep 20 ; no shutdown
                                    '''.format(vlan1=vlan1, vlan3=vlan3))
            except Exception as error:
                log.debug("Unable to configure - Encountered Exception " + str(error))
                self.errored('Exception occurred while configuring PVMAP', 
                            goto=['common_cleanup']) 

        stream1.StartStatelessTraffic()
        log.info('Waiting {}secs to start the traffic'.format(traffic_start_time))
        time.sleep(traffic_start_time)
        
        stream1.StopStatelessTraffic()
        log.info('Waiting {}secs to stop the traffic'.format(traffic_stop_time))
        time.sleep(traffic_stop_time)
        
        log.info('Waiting for 60secs for confing apply')
        time.sleep(60)

        with steps.start("checking mac learning after mapping enable for  orphan mac"):
            if not verify_mac_on_vteps([prim_vtep, sec_vtep, sa_vtep], '1001', 1025, prim_mac):
                log.error("Mac learning failed for orphan mac")
                self.failed("Mac learning failed for orphan mac")

        with steps.start("checking mac learning after mapping enable for standalone mac"):
            if not verify_mac_on_vteps([prim_vtep, sec_vtep, sa_vtep], '1002', 1025, sa_mac):
                log.error("Mac learning failed for standalone mac")
                self.failed("Mac learning failed for standalone mac")

        with steps.start('Verify Learned mac address consistency between hardware and software'):
            if verify_mac_cc_between_hardware_software([prim_vtep, sec_vtep, sa_vtep]):
                log.info('MAC CC success')
            else:
                self.failed('MAC CC failed')

        with steps.start("Verify Steady State"):
            if VerifyTraffic("TC_VXLAN_PVMAP_029", testscript, traffic_item='Trunk Orphan To Standalone'):
                log.info('Verify traffic success')
            else:
                self.failed('Verify traffic failed') 

    @aetest.test
    def verify_error_cores(self, testscript, testbed, steps):
        sa_vtep         = testscript.parameters['LEAF-3']
        prim_vtep       = testscript.parameters['LEAF-1']
        sec_vtep        = testscript.parameters['LEAF-2']
        ixNetwork       = testscript.parameters['ixNetwork']

        with steps.start("Stopping hosts..."):
            ixNetwork.StopAllProtocols()

        log.info('Waiting {}secs'.format(traffic_stop_time))
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

# =====================================================================================================#
# TC-ID: TC_VXLAN_PVMAP_030 - Triggers - Process Restart
# Testcase:  
#   - NVE restart
#   - Check mac learning and traffic
# ======================================================================================================#
class TC_VXLAN_PVMAP_030(aetest.Testcase):
    @aetest.test
    def testcase_vpc_restart_nve(self, testscript, steps):
        sa_vtep         = testscript.parameters['LEAF-3']
        prim_vtep       = testscript.parameters['LEAF-1']
        sec_vtep        = testscript.parameters['LEAF-2']
        prim_mac        = str(testscript.parameters['PVMAP_Dict']['prim_vpc_mac'])
        sa_mac          = str(testscript.parameters['PVMAP_Dict']['sa_mac'])
        p1_handle       = testscript.parameters['vpc_handle']
        p2_handle       = testscript.parameters['sa_handle']
        ixNetwork       = testscript.parameters['ixNetwork']

        with steps.start("Starting hosts..."):
            p1_handle.Start()
            p2_handle.Start()
        
        log.info('Waiting {}secs to start hosts'.format(host_start_time))
        time.sleep(host_start_time)

        stream1 = ixNetwork.Traffic.TrafficItem.find(Name='Trunk VPC To Standalone')
        stream1.StartStatelessTraffic()
        log.info('Waiting {}secs to start the traffic'.format(traffic_start_time))
        time.sleep(traffic_start_time)
        
        stream1.StopStatelessTraffic()
        log.info('Waiting {}secs to stop the traffic'.format(traffic_stop_time))
        time.sleep(traffic_stop_time)

        with steps.start("checking mac learning for vpc mac"):
            if not verify_mac_on_vteps([prim_vtep, sec_vtep, sa_vtep], '1001', 1025, prim_mac):
                log.error("Mac learning failed for vpc mac")
                self.failed("Mac learning failed for vpc mac")

        with steps.start("Checking mac learning for standalone mac"):
            if not verify_mac_on_vteps([prim_vtep, sec_vtep, sa_vtep], '1002', 1025, sa_mac):
                log.error("Mac learning failed for standalone mac")
                self.failed("Mac learning failed for standalone mac")
        
        with steps.start("Restart Process - NVE"):
            if not verify_process_restart(prim_vtep, "nve", testscript, log):
                log.error("Process restart failed on primary")
                self.failed("Process restart failed on primary")
            
            if not verify_process_restart(sec_vtep, "nve", testscript, log):
                log.error("Process restart failed on secondary")
                self.failed("Process restart failed on secondary")
            
            if not verify_process_restart(sa_vtep, "nve", testscript, log):
                log.error("Process restart failed on standalone")
                self.failed("Process restart failed on standalone")
    
        stream1.StartStatelessTraffic()
        log.info('Waiting {}secs to start the traffic'.format(traffic_start_time))
        time.sleep(traffic_start_time)
        
        stream1.StopStatelessTraffic()
        log.info('Waiting {}secs to stop the traffic'.format(traffic_stop_time))
        time.sleep(traffic_stop_time)
        
        with steps.start("checking mac learning for vpc mac"):
            if not verify_mac_on_vteps([prim_vtep, sec_vtep, sa_vtep], '1001', 1025, prim_mac):
                log.error("Mac learning failed for vpc mac")
                self.failed("Mac learning failed for vpc mac")

        with steps.start("checking mac learning for standalone mac"):
            if not verify_mac_on_vteps([prim_vtep, sec_vtep, sa_vtep], '1002', 1025, sa_mac):
                log.error("Mac learning failed for standalone mac")
                self.failed("Mac learning failed for standalone mac")

        with steps.start('Verify Learned mac address consistency between hardware and software'):
            if verify_mac_cc_between_hardware_software([prim_vtep, sec_vtep, sa_vtep]):
                log.info('MAC CC success')
            else:
                self.failed('MAC CC failed')

        with steps.start("Verify Steady State"):
            if VerifyTraffic("TC_VXLAN_PVMAP_030", testscript, traffic_item='Trunk VPC To Standalone'):
                log.info('Verify traffic success')
            else:
                self.failed('Verify traffic failed') 

    @aetest.test
    def testcase_orphan_restart_nve(self, testscript, steps):
        sa_vtep         = testscript.parameters['LEAF-3']
        prim_vtep       = testscript.parameters['LEAF-1']
        sec_vtep        = testscript.parameters['LEAF-2']
        prim_mac        = str(testscript.parameters['PVMAP_Dict']['prim_orphan_mac'])
        sa_mac          = str(testscript.parameters['PVMAP_Dict']['sa_mac'])
        p1_handle       = testscript.parameters['orphan1_handle']
        p2_handle       = testscript.parameters['sa_handle']
        ixNetwork       = testscript.parameters['ixNetwork']

        with steps.start("Starting hosts..."):
            p1_handle.Start()
            p2_handle.Start()
        
        log.info('Waiting {}secs to start hosts'.format(host_start_time))
        time.sleep(host_start_time)

        stream1 = ixNetwork.Traffic.TrafficItem.find(Name='Trunk Orphan To Standalone')
        stream1.StartStatelessTraffic()
        log.info('Waiting {}secs to start the traffic'.format(traffic_start_time))
        time.sleep(traffic_start_time)
        
        stream1.StopStatelessTraffic()
        log.info('Waiting {}secs to stop the traffic'.format(traffic_stop_time))
        time.sleep(traffic_stop_time)

        with steps.start("checking mac learning for orphan mac"):
            if not verify_mac_on_vteps([prim_vtep, sec_vtep, sa_vtep], '1001', 1025, prim_mac):
                log.error("Mac learning failed for orphan mac")
                self.failed("Mac learning failed for orphan mac")

        with steps.start("Checking mac learning for standalone mac"):
            if not verify_mac_on_vteps([prim_vtep, sec_vtep, sa_vtep], '1002', 1025, sa_mac):
                log.error("Mac learning failed for standalone mac")
                self.failed("Mac learning failed for standalone mac")
        
        with steps.start("Restart Process - NVE"):
            if not verify_process_restart(prim_vtep, "nve", testscript, log):
                log.error("Process restart failed on primary")
                self.failed("Process restart failed on primary")
            
            if not verify_process_restart(sec_vtep, "nve", testscript, log):
                log.error("Process restart failed on secondary")
                self.failed("Process restart failed on secondary")
            
            if not verify_process_restart(sa_vtep, "nve", testscript, log):
                log.error("Process restart failed on standalone")
                self.failed("Process restart failed on standalone")
    
        stream1.StartStatelessTraffic()
        log.info('Waiting {}secs to start the traffic'.format(traffic_start_time))
        time.sleep(traffic_start_time)
        
        stream1.StopStatelessTraffic()
        log.info('Waiting {}secs to stop the traffic'.format(traffic_stop_time))
        time.sleep(traffic_stop_time)

        with steps.start("checking mac learning for  orphan mac"):
            if not verify_mac_on_vteps([prim_vtep, sec_vtep, sa_vtep], '1001', 1025, prim_mac):
                log.error("Mac learning failed for orphan mac")
                self.failed("Mac learning failed for orphan mac")

        with steps.start("checking mac learning for standalone mac"):
            if not verify_mac_on_vteps([prim_vtep, sec_vtep, sa_vtep], '1002', 1025, sa_mac):
                log.error("Mac learning failed for standalone mac")
                self.failed("Mac learning failed for standalone mac")

        with steps.start('Verify Learned mac address consistency between hardware and software'):
            if verify_mac_cc_between_hardware_software([prim_vtep, sec_vtep, sa_vtep]):
                log.info('MAC CC success')
            else:
                self.failed('MAC CC failed')

        with steps.start("Verify Steady State"):
            if VerifyTraffic("TC_VXLAN_PVMAP_030", testscript, traffic_item='Trunk Orphan To Standalone'):
                log.info('Verify traffic success')
            else:
                self.failed('Verify traffic failed') 

    @aetest.test
    def verify_error_cores(self, testscript, testbed, steps):
        sa_vtep         = testscript.parameters['LEAF-3']
        prim_vtep       = testscript.parameters['LEAF-1']
        sec_vtep        = testscript.parameters['LEAF-2']
        ixNetwork       = testscript.parameters['ixNetwork']

        with steps.start("Stopping hosts..."):
            ixNetwork.StopAllProtocols()

        log.info('Waiting {}secs'.format(traffic_stop_time))
        time.sleep(traffic_stop_time)

        with steps.start("Verifying MTS leak.."):
            if verify_mts_leak([prim_vtep, sec_vtep, sa_vtep], log):
                log.info('MTS Leak verification success')
            else:
                self.failed('MTS Leak verification failed')

        with steps.start("Verifying Cores and Log Errors"):
            exclude_bkp = post_test_process_dict['exclude_log_check_pattern']
            post_test_process_dict['exclude_log_check_pattern'] = str(exclude_bkp) + '|SYSMGR-2-SERVICE_CRASHED'
            status = infraVerify.postTestVerification(post_test_process_dict)
            if status['status'] == 0:
                self.failed(reason=status['logs'])
            else:
                self.passed(reason=status['logs'])
            post_test_process_dict['exclude_log_check_pattern'] = exclude_bkp

# =====================================================================================================#
# TC-ID: TC_VXLAN_PVMAP_031 - Triggers - Process Restart
# Testcase:  
#   - vlan mgr restart
#   - Check mac learning and traffic
# ======================================================================================================#
class TC_VXLAN_PVMAP_031(aetest.Testcase):
    @aetest.test
    def testcase_vpc_restart_vlanmgr(self, testscript, steps):
        sa_vtep         = testscript.parameters['LEAF-3']
        prim_vtep       = testscript.parameters['LEAF-1']
        sec_vtep        = testscript.parameters['LEAF-2']
        prim_mac        = str(testscript.parameters['PVMAP_Dict']['prim_vpc_mac'])
        sa_mac          = str(testscript.parameters['PVMAP_Dict']['sa_mac'])
        p1_handle       = testscript.parameters['vpc_handle']
        p2_handle       = testscript.parameters['sa_handle']
        ixNetwork       = testscript.parameters['ixNetwork']

        with steps.start("Starting hosts..."):
            p1_handle.Start()
            p2_handle.Start()
        
        log.info('Waiting {}secs to start hosts'.format(host_start_time))
        time.sleep(host_start_time)

        stream1 = ixNetwork.Traffic.TrafficItem.find(Name='Trunk VPC To Standalone')
        stream1.StartStatelessTraffic()
        log.info('Waiting {}secs to start the traffic'.format(traffic_start_time))
        time.sleep(traffic_start_time)
        
        stream1.StopStatelessTraffic()
        log.info('Waiting {}secs to stop the traffic'.format(traffic_stop_time))
        time.sleep(traffic_stop_time)

        with steps.start("checking mac learning for vpc mac"):
            if not verify_mac_on_vteps([prim_vtep, sec_vtep, sa_vtep], '1001', 1025, prim_mac):
                log.error("Mac learning failed for vpc mac")
                self.failed("Mac learning failed for vpc mac")

        with steps.start("Checking mac learning for standalone mac"):
            if not verify_mac_on_vteps([prim_vtep, sec_vtep, sa_vtep], '1002', 1025, sa_mac):
                log.error("Mac learning failed for standalone mac")
                self.failed("Mac learning failed for standalone mac")
        
        with steps.start("Restart Process - Vlan Manager"):
            if not verify_process_restart(prim_vtep, "vlan_mgr", testscript, log):
                log.error("Process restart failed on primary")
                self.failed("Process restart failed on primary")
            
            if not verify_process_restart(sec_vtep, "vlan_mgr", testscript, log):
                log.error("Process restart failed on secondary")
                self.failed("Process restart failed on secondary")
            
            if not verify_process_restart(sa_vtep, "vlan_mgr", testscript, log):
                log.error("Process restart failed on standalone")
                self.failed("Process restart failed on standalone")
    
        stream1.StartStatelessTraffic()
        log.info('Waiting {}secs to start the traffic'.format(traffic_start_time))
        time.sleep(traffic_start_time)
        
        stream1.StopStatelessTraffic()
        log.info('Waiting {}secs to stop the traffic'.format(traffic_stop_time))
        time.sleep(traffic_stop_time)
        
        with steps.start("checking mac learning for vpc mac"):
            if not verify_mac_on_vteps([prim_vtep, sec_vtep, sa_vtep], '1001', 1025, prim_mac):
                log.error("Mac learning failed for orphan mac")
                self.failed("Mac learning failed for orphan mac")

        with steps.start("checking mac learning for standalone mac"):
            if not verify_mac_on_vteps([prim_vtep, sec_vtep, sa_vtep], '1002', 1025, sa_mac):
                log.error("Mac learning failed for standalone mac")
                self.failed("Mac learning failed for standalone mac")

        with steps.start('Verify Learned mac address consistency between hardware and software'):
            if verify_mac_cc_between_hardware_software([prim_vtep, sec_vtep, sa_vtep]):
                log.info('MAC CC success')
            else:
                self.failed('MAC CC failed')

        with steps.start("Verify Steady State"):
            if VerifyTraffic("TC_VXLAN_PVMAP_031", testscript, traffic_item='Trunk VPC To Standalone'):
                log.info('Verify traffic success')
            else:
                self.failed('Verify traffic failed') 

    @aetest.test
    def testcase_orphan_restart_vlanmgr(self, testscript, steps):
        sa_vtep         = testscript.parameters['LEAF-3']
        prim_vtep       = testscript.parameters['LEAF-1']
        sec_vtep        = testscript.parameters['LEAF-2']
        prim_mac        = str(testscript.parameters['PVMAP_Dict']['prim_orphan_mac'])
        sa_mac          = str(testscript.parameters['PVMAP_Dict']['sa_mac'])
        p1_handle       = testscript.parameters['orphan1_handle']
        p2_handle       = testscript.parameters['sa_handle']
        ixNetwork       = testscript.parameters['ixNetwork']

        with steps.start("Starting hosts..."):
            p1_handle.Start()
            p2_handle.Start()
        
        log.info('Waiting {}secs to start hosts'.format(host_start_time))
        time.sleep(host_start_time)

        stream1 = ixNetwork.Traffic.TrafficItem.find(Name='Trunk Orphan To Standalone')
        stream1.StartStatelessTraffic()
        log.info('Waiting {}secs to start the traffic'.format(traffic_start_time))
        time.sleep(traffic_start_time)
        
        stream1.StopStatelessTraffic()
        log.info('Waiting {}secs to stop the traffic'.format(traffic_stop_time))
        time.sleep(traffic_stop_time)

        with steps.start("checking mac learning for orphan mac"):
            if not verify_mac_on_vteps([prim_vtep, sec_vtep, sa_vtep], '1001', 1025, prim_mac):
                log.error("Mac learning failed for orphan mac")
                self.failed("Mac learning failed for orphan mac")

        with steps.start("Checking mac learning for standalone mac"):
            if not verify_mac_on_vteps([prim_vtep, sec_vtep, sa_vtep], '1002', 1025, sa_mac):
                log.error("Mac learning failed for standalone mac")
                self.failed("Mac learning failed for standalone mac")
        
        with steps.start("Restart Process - Vlan manager"):
            if not verify_process_restart(prim_vtep, "vlan_mgr", testscript, log):
                log.error("Process restart failed on primary")
                self.failed("Process restart failed on primary")
            
            if not verify_process_restart(sec_vtep, "vlan_mgr", testscript, log):
                log.error("Process restart failed on secondary")
                self.failed("Process restart failed on secondary")
            
            if not verify_process_restart(sa_vtep, "vlan_mgr", testscript, log):
                log.error("Process restart failed on standalone")
                self.failed("Process restart failed on standalone")
    
        stream1.StartStatelessTraffic()
        log.info('Waiting {}secs to start the traffic'.format(traffic_start_time))
        time.sleep(traffic_start_time)
        
        stream1.StopStatelessTraffic()
        log.info('Waiting {}secs to stop the traffic'.format(traffic_stop_time))
        time.sleep(traffic_stop_time)

        with steps.start("checking mac learning for orphan mac"):
            if not verify_mac_on_vteps([prim_vtep, sec_vtep, sa_vtep], '1001', 1025, prim_mac):
                log.error("Mac learning failed for orphan mac")
                self.failed("Mac learning failed for orphan mac")

        with steps.start("checking mac learning for standalone mac"):
            if not verify_mac_on_vteps([prim_vtep, sec_vtep, sa_vtep], '1002', 1025, sa_mac):
                log.error("Mac learning failed for standalone mac")
                self.failed("Mac learning failed for standalone mac")

        with steps.start('Verify Learned mac address consistency between hardware and software'):
            if verify_mac_cc_between_hardware_software([prim_vtep, sec_vtep, sa_vtep]):
                log.info('MAC CC success')
            else:
                self.failed('MAC CC failed')

        with steps.start("Verify Steady State"):
            if VerifyTraffic("TC_VXLAN_PVMAP_031", testscript, traffic_item='Trunk Orphan To Standalone'):
                log.info('Verify traffic success')
            else:
                self.failed('Verify traffic failed') 

    @aetest.test
    def verify_error_cores(self, testscript, testbed, steps):
        sa_vtep         = testscript.parameters['LEAF-3']
        prim_vtep       = testscript.parameters['LEAF-1']
        sec_vtep        = testscript.parameters['LEAF-2']
        ixNetwork       = testscript.parameters['ixNetwork']

        with steps.start("Stopping hosts..."):
            ixNetwork.StopAllProtocols()

        log.info('Waiting {}secs'.format(traffic_stop_time))
        time.sleep(traffic_stop_time)

        with steps.start("Verifying MTS leak.."):
            if verify_mts_leak([prim_vtep, sec_vtep, sa_vtep], log):
                log.info('MTS Leak verification success')
            else:
                self.failed('MTS Leak verification failed')

        with steps.start("Verifying Cores and Log Errors"):
            exclude_bkp = post_test_process_dict['exclude_log_check_pattern']
            post_test_process_dict['exclude_log_check_pattern'] = str(exclude_bkp) + '|SYSMGR-2-SERVICE_CRASHED'
            status = infraVerify.postTestVerification(post_test_process_dict)
            if status['status'] == 0:
                self.failed(reason=status['logs'])
            else:
                self.passed(reason=status['logs'])
            post_test_process_dict['exclude_log_check_pattern'] = exclude_bkp

# =====================================================================================================#
# TC-ID: TC_VXLAN_PVMAP_032 - Triggers - Process Restart
# Testcase:  
#   - L2FM restart
#   - Check mac learning and traffic
# ======================================================================================================#
class TC_VXLAN_PVMAP_032(aetest.Testcase):
    @aetest.test
    def testcase_vpc_restart_l2fm(self, testscript, steps):
        sa_vtep         = testscript.parameters['LEAF-3']
        prim_vtep       = testscript.parameters['LEAF-1']
        sec_vtep        = testscript.parameters['LEAF-2']
        prim_mac        = str(testscript.parameters['PVMAP_Dict']['prim_vpc_mac'])
        sa_mac          = str(testscript.parameters['PVMAP_Dict']['sa_mac'])
        p1_handle       = testscript.parameters['vpc_handle']
        p2_handle       = testscript.parameters['sa_handle']
        ixNetwork       = testscript.parameters['ixNetwork']

        with steps.start("Starting hosts..."):
            p1_handle.Start()
            p2_handle.Start()
        
        log.info('Waiting {}secs to start hosts'.format(host_start_time))
        time.sleep(host_start_time)

        stream1 = ixNetwork.Traffic.TrafficItem.find(Name='Trunk VPC To Standalone')
        stream1.StartStatelessTraffic()
        log.info('Waiting {}secs to start the traffic'.format(traffic_start_time))
        time.sleep(traffic_start_time)
        
        stream1.StopStatelessTraffic()
        log.info('Waiting {}secs to stop the traffic'.format(traffic_stop_time))
        time.sleep(traffic_stop_time)

        with steps.start("checking mac learning for vpc mac"):
            if not verify_mac_on_vteps([prim_vtep, sec_vtep, sa_vtep], '1001', 1025, prim_mac):
                log.error("Mac learning failed for vpc mac")
                self.failed("Mac learning failed for vpc mac")

        with steps.start("Checking mac learning for standalone mac"):
            if not verify_mac_on_vteps([prim_vtep, sec_vtep, sa_vtep], '1002', 1025, sa_mac):
                log.error("Mac learning failed for standalone mac")
                self.failed("Mac learning failed for standalone mac")
        
        with steps.start("Restart Process - L2Fm"):
            if not verify_process_restart(prim_vtep, "l2fm", testscript, log):
                log.error("Process restart failed on primary")
                self.failed("Process restart failed on primary")
            
            if not verify_process_restart(sec_vtep, "l2fm", testscript, log):
                log.error("Process restart failed on secondary")
                self.failed("Process restart failed on secondary")
            
            if not verify_process_restart(sa_vtep, "l2fm", testscript, log):
                log.error("Process restart failed on standalone")
                self.failed("Process restart failed on standalone")

        stream1.StartStatelessTraffic()
        log.info('Waiting {}secs to start the traffic'.format(traffic_start_time))
        time.sleep(traffic_start_time)
        
        stream1.StopStatelessTraffic()
        log.info('Waiting {}secs to stop the traffic'.format(traffic_stop_time))
        time.sleep(traffic_stop_time)
                
        with steps.start("checking mac learning for vpc mac"):
            if not verify_mac_on_vteps([prim_vtep, sec_vtep, sa_vtep], '1001', 1025, prim_mac):
                log.error("Mac learning failed for orphan mac")
                self.failed("Mac learning failed for orphan mac")

        with steps.start("checking mac learning for standalone mac"):
            if not verify_mac_on_vteps([prim_vtep, sec_vtep, sa_vtep], '1002', 1025, sa_mac):
                log.error("Mac learning failed for standalone mac")
                self.failed("Mac learning failed for standalone mac")

        with steps.start('Verify Learned mac address consistency between hardware and software'):
            if verify_mac_cc_between_hardware_software([prim_vtep, sec_vtep, sa_vtep]):
                log.info('MAC CC success')
            else:
                self.failed('MAC CC failed')

        with steps.start("Verify Steady State"):
            if VerifyTraffic("TC_VXLAN_PVMAP_032", testscript, traffic_item='Trunk VPC To Standalone'):
                log.info('Verify traffic success')
            else:
                self.failed('Verify traffic failed') 

    @aetest.test
    def testcase_orphan_restart_l2fm(self, testscript, steps):
        sa_vtep         = testscript.parameters['LEAF-3']
        prim_vtep       = testscript.parameters['LEAF-1']
        sec_vtep        = testscript.parameters['LEAF-2']
        prim_mac        = str(testscript.parameters['PVMAP_Dict']['prim_orphan_mac'])
        sa_mac          = str(testscript.parameters['PVMAP_Dict']['sa_mac'])
        p1_handle       = testscript.parameters['orphan1_handle']
        p2_handle       = testscript.parameters['sa_handle']
        ixNetwork       = testscript.parameters['ixNetwork']

        with steps.start("Starting hosts..."):
            p1_handle.Start()
            p2_handle.Start()
        
        log.info('Waiting {}secs to start hosts'.format(host_start_time))
        time.sleep(host_start_time)

        stream1 = ixNetwork.Traffic.TrafficItem.find(Name='Trunk Orphan To Standalone')
        stream1.StartStatelessTraffic()
        log.info('Waiting {}secs to start the traffic'.format(traffic_start_time))
        time.sleep(traffic_start_time)
        
        stream1.StopStatelessTraffic()
        log.info('Waiting {}secs to stop the traffic'.format(traffic_stop_time))
        time.sleep(traffic_stop_time)

        with steps.start("checking mac learning for orphan mac"):
            if not verify_mac_on_vteps([prim_vtep, sec_vtep, sa_vtep], '1001', 1025, prim_mac):
                log.error("Mac learning failed for orphan mac")
                self.failed("Mac learning failed for orphan mac")

        with steps.start("Checking mac learning for standalone mac"):
            if not verify_mac_on_vteps([prim_vtep, sec_vtep, sa_vtep], '1002', 1025, sa_mac):
                log.error("Mac learning failed for standalone mac")
                self.failed("Mac learning failed for standalone mac")
        
        with steps.start("Restart Process - L2FM"):
            if not verify_process_restart(prim_vtep, "l2fm", testscript, log):
                log.error("Process restart failed on primary")
                self.failed("Process restart failed on primary")
            
            if not verify_process_restart(sec_vtep, "l2fm", testscript, log):
                log.error("Process restart failed on secondary")
                self.failed("Process restart failed on secondary")
            
            if not verify_process_restart(sa_vtep, "l2fm", testscript, log):
                log.error("Process restart failed on standalone")
                self.failed("Process restart failed on standalone")
    
        stream1.StartStatelessTraffic()
        log.info('Waiting {}secs to start the traffic'.format(traffic_start_time))
        time.sleep(traffic_start_time)
        
        stream1.StopStatelessTraffic()
        log.info('Waiting {}secs to stop the traffic'.format(traffic_stop_time))
        time.sleep(traffic_stop_time)

        with steps.start("checking mac learning for  orphan mac"):
            if not verify_mac_on_vteps([prim_vtep, sec_vtep, sa_vtep], '1001', 1025, prim_mac):
                log.error("Mac learning failed for orphan mac")
                self.failed("Mac learning failed for orphan mac")

        with steps.start("checking mac learning for standalone mac"):
            if not verify_mac_on_vteps([prim_vtep, sec_vtep, sa_vtep], '1002', 1025, sa_mac):
                log.error("Mac learning failed for standalone mac")
                self.failed("Mac learning failed for standalone mac")

        with steps.start('Verify Learned mac address consistency between hardware and software'):
            if verify_mac_cc_between_hardware_software([prim_vtep, sec_vtep, sa_vtep]):
                log.info('MAC CC success')
            else:
                self.failed('MAC CC failed')

        with steps.start("Verify Steady State"):
            if VerifyTraffic("TC_VXLAN_PVMAP_032", testscript, traffic_item='Trunk Orphan To Standalone'):
                log.info('Verify traffic success')
            else:
                self.failed('Verify traffic failed') 

    @aetest.test
    def verify_error_cores(self, testscript, testbed, steps):
        sa_vtep         = testscript.parameters['LEAF-3']
        prim_vtep       = testscript.parameters['LEAF-1']
        sec_vtep        = testscript.parameters['LEAF-2']
        ixNetwork       = testscript.parameters['ixNetwork']

        with steps.start("Stopping hosts..."):
            ixNetwork.StopAllProtocols()

        log.info('Waiting {}secs'.format(traffic_stop_time))
        time.sleep(traffic_stop_time)

        with steps.start("Verifying MTS leak.."):
            if verify_mts_leak([prim_vtep, sec_vtep, sa_vtep], log):
                log.info('MTS Leak verification success')
            else:
                self.failed('MTS Leak verification failed')

        with steps.start("Verifying Cores and Log Errors"):
            exclude_bkp = post_test_process_dict['exclude_log_check_pattern']
            post_test_process_dict['exclude_log_check_pattern'] = str(exclude_bkp) + '|SYSMGR-2-SERVICE_CRASHED'
            status = infraVerify.postTestVerification(post_test_process_dict)
            if status['status'] == 0:
                self.failed(reason=status['logs'])
            else:
                self.passed(reason=status['logs'])
            post_test_process_dict['exclude_log_check_pattern'] = exclude_bkp

# =====================================================================================================#
# TC-ID: TC_VXLAN_PVMAP_033 - Triggers - Process Restart
# Testcase:  
#   - L2RIB restart
#   - Check mac learning and traffic
# ======================================================================================================#
class TC_VXLAN_PVMAP_033(aetest.Testcase):
    @aetest.test
    def testcase_vpc_restart_l2rib(self, testscript, steps):
        sa_vtep         = testscript.parameters['LEAF-3']
        prim_vtep       = testscript.parameters['LEAF-1']
        sec_vtep        = testscript.parameters['LEAF-2']
        prim_mac        = str(testscript.parameters['PVMAP_Dict']['prim_vpc_mac'])
        sa_mac          = str(testscript.parameters['PVMAP_Dict']['sa_mac'])
        p1_handle       = testscript.parameters['vpc_handle']
        p2_handle       = testscript.parameters['sa_handle']
        ixNetwork       = testscript.parameters['ixNetwork']

        with steps.start("Starting hosts..."):
            p1_handle.Start()
            p2_handle.Start()
        
        log.info('Waiting {}secs to start hosts'.format(host_start_time))
        time.sleep(host_start_time)

        stream1 = ixNetwork.Traffic.TrafficItem.find(Name='Trunk VPC To Standalone')
        stream1.StartStatelessTraffic()
        log.info('Waiting {}secs to start the traffic'.format(traffic_start_time))
        time.sleep(traffic_start_time)
        
        stream1.StopStatelessTraffic()
        log.info('Waiting {}secs to stop the traffic'.format(traffic_stop_time))
        time.sleep(traffic_stop_time)

        with steps.start("checking mac learning for vpc mac"):
            if not verify_mac_on_vteps([prim_vtep, sec_vtep, sa_vtep], '1001', 1025, prim_mac):
                log.error("Mac learning failed for vpc mac")
                self.failed("Mac learning failed for vpc mac")

        with steps.start("Checking mac learning for standalone mac"):
            if not verify_mac_on_vteps([prim_vtep, sec_vtep, sa_vtep], '1002', 1025, sa_mac):
                log.error("Mac learning failed for standalone mac")
                self.failed("Mac learning failed for standalone mac")
        
        with steps.start("Restart Process - L2RIB"):
            if not verify_process_restart(prim_vtep, "l2rib", testscript, log):
                log.error("Process restart failed on primary")
                self.failed("Process restart failed on primary")
            
            if not verify_process_restart(sec_vtep, "l2rib", testscript, log):
                log.error("Process restart failed on secondary")
                self.failed("Process restart failed on secondary")
            
            if not verify_process_restart(sa_vtep, "l2rib", testscript, log):
                log.error("Process restart failed on standalone")
                self.failed("Process restart failed on standalone")
    
        stream1.StartStatelessTraffic()
        log.info('Waiting {}secs to start the traffic'.format(traffic_start_time))
        time.sleep(traffic_start_time)
        
        stream1.StopStatelessTraffic()
        log.info('Waiting {}secs to stop the traffic'.format(traffic_stop_time))
        time.sleep(traffic_stop_time)
        
        with steps.start("checking mac learning for vpc mac"):
            if not verify_mac_on_vteps([prim_vtep, sec_vtep, sa_vtep], '1001', 1025, prim_mac):
                log.error("Mac learning failed for orphan mac")
                self.failed("Mac learning failed for orphan mac")

        with steps.start("checking mac learning for standalone mac"):
            if not verify_mac_on_vteps([prim_vtep, sec_vtep, sa_vtep], '1002', 1025, sa_mac):
                log.error("Mac learning failed for standalone mac")
                self.failed("Mac learning failed for standalone mac")

        with steps.start('Verify Learned mac address consistency between hardware and software'):
            if verify_mac_cc_between_hardware_software([prim_vtep, sec_vtep, sa_vtep]):
                log.info('MAC CC success')
            else:
                self.failed('MAC CC failed')

        with steps.start("Verify Steady State"):
            if VerifyTraffic("TC_VXLAN_PVMAP_033", testscript, traffic_item='Trunk VPC To Standalone'):
                log.info('Verify traffic success')
            else:
                self.failed('Verify traffic failed') 

    @aetest.test
    def testcase_orphan_restart_l2rib(self, testscript, steps):
        sa_vtep         = testscript.parameters['LEAF-3']
        prim_vtep       = testscript.parameters['LEAF-1']
        sec_vtep        = testscript.parameters['LEAF-2']
        prim_mac        = str(testscript.parameters['PVMAP_Dict']['prim_orphan_mac'])
        sa_mac          = str(testscript.parameters['PVMAP_Dict']['sa_mac'])
        p1_handle       = testscript.parameters['orphan1_handle']
        p2_handle       = testscript.parameters['sa_handle']
        ixNetwork       = testscript.parameters['ixNetwork']

        with steps.start("Starting hosts..."):
            p1_handle.Start()
            p2_handle.Start()
        
        log.info('Waiting {}secs to start hosts'.format(host_start_time))
        time.sleep(host_start_time)

        stream1 = ixNetwork.Traffic.TrafficItem.find(Name='Trunk Orphan To Standalone')
        stream1.StartStatelessTraffic()
        log.info('Waiting {}secs to start the traffic'.format(traffic_start_time))
        time.sleep(traffic_start_time)
        
        stream1.StopStatelessTraffic()
        log.info('Waiting {}secs to stop the traffic'.format(traffic_stop_time))
        time.sleep(traffic_stop_time)

        with steps.start("checking mac learning for orphan mac"):
            if not verify_mac_on_vteps([prim_vtep, sec_vtep, sa_vtep], '1001', 1025, prim_mac):
                log.error("Mac learning failed for orphan mac")
                self.failed("Mac learning failed for orphan mac")

        with steps.start("Checking mac learning for standalone mac"):
            if not verify_mac_on_vteps([prim_vtep, sec_vtep, sa_vtep], '1002', 1025, sa_mac):
                log.error("Mac learning failed for standalone mac")
                self.failed("Mac learning failed for standalone mac")
        
        with steps.start("Restart Process - l2rib"):
            if not verify_process_restart(prim_vtep, "l2rib", testscript, log):
                log.error("Process restart failed on primary")
                self.failed("Process restart failed on primary")
            
            if not verify_process_restart(sec_vtep, "l2rib", testscript, log):
                log.error("Process restart failed on secondary")
                self.failed("Process restart failed on secondary")
            
            if not verify_process_restart(sa_vtep, "l2rib", testscript, log):
                log.error("Process restart failed on standalone")
                self.failed("Process restart failed on standalone")
    
        stream1.StartStatelessTraffic()
        log.info('Waiting {}secs to start the traffic'.format(traffic_start_time))
        time.sleep(traffic_start_time)
        
        stream1.StopStatelessTraffic()
        log.info('Waiting {}secs to stop the traffic'.format(traffic_stop_time))
        time.sleep(traffic_stop_time)

        with steps.start("checking mac learning for  orphan mac"):
            if not verify_mac_on_vteps([prim_vtep, sec_vtep, sa_vtep], '1001', 1025, prim_mac):
                log.error("Mac learning failed for orphan mac")
                self.failed("Mac learning failed for orphan mac")

        with steps.start("checking mac learning for standalone mac"):
            if not verify_mac_on_vteps([prim_vtep, sec_vtep, sa_vtep], '1002', 1025, sa_mac):
                log.error("Mac learning failed for standalone mac")
                self.failed("Mac learning failed for standalone mac")

        with steps.start('Verify Learned mac address consistency between hardware and software'):
            if verify_mac_cc_between_hardware_software([prim_vtep, sec_vtep, sa_vtep]):
                log.info('MAC CC success')
            else:
                self.failed('MAC CC failed')

        with steps.start("Verify Steady State"):
            if VerifyTraffic("TC_VXLAN_PVMAP_033", testscript, traffic_item='Trunk Orphan To Standalone'):
                log.info('Verify traffic success')
            else:
                self.failed('Verify traffic failed') 

    @aetest.test
    def verify_error_cores(self, testscript, testbed, steps):
        sa_vtep         = testscript.parameters['LEAF-3']
        prim_vtep       = testscript.parameters['LEAF-1']
        sec_vtep        = testscript.parameters['LEAF-2']
        ixNetwork       = testscript.parameters['ixNetwork']

        with steps.start("Stopping hosts..."):
            ixNetwork.StopAllProtocols()

        log.info('Waiting {}secs'.format(traffic_stop_time))
        time.sleep(traffic_stop_time)

        with steps.start("Verifying MTS leak.."):
            if verify_mts_leak([prim_vtep, sec_vtep, sa_vtep], log):
                log.info('MTS Leak verification success')
            else:
                self.failed('MTS Leak verification failed')

        with steps.start("Verifying Cores and Log Errors"):
            exclude_bkp = post_test_process_dict['exclude_log_check_pattern']
            post_test_process_dict['exclude_log_check_pattern'] = str(exclude_bkp) + '|SYSMGR-2-SERVICE_CRASHED'
            status = infraVerify.postTestVerification(post_test_process_dict)
            if status['status'] == 0:
                self.failed(reason=status['logs'])
            else:
                self.passed(reason=status['logs'])
            post_test_process_dict['exclude_log_check_pattern'] = exclude_bkp

# =====================================================================================================#
# TC-ID: TC_VXLAN_PVMAP_034 - Triggers - Process Restart
# Testcase:  
#   - ethpm restart
#   - Check mac learning and traffic
# ======================================================================================================#
class TC_VXLAN_PVMAP_034(aetest.Testcase):
    @aetest.test
    def testcase_vpc_restart_ethpm(self, testscript, steps):
        sa_vtep         = testscript.parameters['LEAF-3']
        prim_vtep       = testscript.parameters['LEAF-1']
        sec_vtep        = testscript.parameters['LEAF-2']
        prim_mac        = str(testscript.parameters['PVMAP_Dict']['prim_vpc_mac'])
        sa_mac          = str(testscript.parameters['PVMAP_Dict']['sa_mac'])
        p1_handle       = testscript.parameters['vpc_handle']
        p2_handle       = testscript.parameters['sa_handle']
        ixNetwork       = testscript.parameters['ixNetwork']

        with steps.start("Starting hosts..."):
            p1_handle.Start()
            p2_handle.Start()
        
        log.info('Waiting {}secs to start hosts'.format(host_start_time))
        time.sleep(host_start_time)

        stream1 = ixNetwork.Traffic.TrafficItem.find(Name='Trunk VPC To Standalone')
        stream1.StartStatelessTraffic()
        log.info('Waiting {}secs to start the traffic'.format(traffic_start_time))
        time.sleep(traffic_start_time)
        
        stream1.StopStatelessTraffic()
        log.info('Waiting {}secs to stop the traffic'.format(traffic_stop_time))
        time.sleep(traffic_stop_time)

        with steps.start("checking mac learning for vpc mac"):
            if not verify_mac_on_vteps([prim_vtep, sec_vtep, sa_vtep], '1001', 1025, prim_mac):
                log.error("Mac learning failed for vpc mac")
                self.failed("Mac learning failed for vpc mac")

        with steps.start("Checking mac learning for standalone mac"):
            if not verify_mac_on_vteps([prim_vtep, sec_vtep, sa_vtep], '1002', 1025, sa_mac):
                log.error("Mac learning failed for standalone mac")
                self.failed("Mac learning failed for standalone mac")
        
        with steps.start("Restart Process - ethpm"):
            if not verify_process_restart(prim_vtep, "ethpm", testscript, log):
                log.error("Process restart failed on primary")
                self.failed("Process restart failed on primary")
            
            if not verify_process_restart(sec_vtep, "ethpm", testscript, log):
                log.error("Process restart failed on secondary")
                self.failed("Process restart failed on secondary")
            
            if not verify_process_restart(sa_vtep, "ethpm", testscript, log):
                log.error("Process restart failed on standalone")
                self.failed("Process restart failed on standalone")
    
        stream1.StartStatelessTraffic()
        log.info('Waiting {}secs to start the traffic'.format(traffic_start_time))
        time.sleep(traffic_start_time)
        
        stream1.StopStatelessTraffic()
        log.info('Waiting {}secs to stop the traffic'.format(traffic_stop_time))
        time.sleep(traffic_stop_time)
        
        with steps.start("checking mac learning for vpc mac"):
            if not verify_mac_on_vteps([prim_vtep, sec_vtep, sa_vtep], '1001', 1025, prim_mac):
                log.error("Mac learning failed for orphan mac")
                self.failed("Mac learning failed for orphan mac")

        with steps.start("checking mac learning for standalone mac"):
            if not verify_mac_on_vteps([prim_vtep, sec_vtep, sa_vtep], '1002', 1025, sa_mac):
                log.error("Mac learning failed for standalone mac")
                self.failed("Mac learning failed for standalone mac")

        with steps.start('Verify Learned mac address consistency between hardware and software'):
            if verify_mac_cc_between_hardware_software([prim_vtep, sec_vtep, sa_vtep]):
                log.info('MAC CC success')
            else:
                self.failed('MAC CC failed')

        with steps.start("Verify Steady State"):
            if VerifyTraffic("TC_VXLAN_PVMAP_034", testscript, traffic_item='Trunk VPC To Standalone'):
                log.info('Verify traffic success')
            else:
                self.failed('Verify traffic failed') 

    @aetest.test
    def testcase_orphan_restart_ethpm(self, testscript, steps):
        sa_vtep         = testscript.parameters['LEAF-3']
        prim_vtep       = testscript.parameters['LEAF-1']
        sec_vtep        = testscript.parameters['LEAF-2']
        prim_mac        = str(testscript.parameters['PVMAP_Dict']['prim_orphan_mac'])
        sa_mac          = str(testscript.parameters['PVMAP_Dict']['sa_mac'])
        p1_handle       = testscript.parameters['orphan1_handle']
        p2_handle       = testscript.parameters['sa_handle']
        ixNetwork       = testscript.parameters['ixNetwork']

        with steps.start("Starting hosts..."):
            p1_handle.Start()
            p2_handle.Start()
        
        log.info('Waiting {}secs to start hosts'.format(host_start_time))
        time.sleep(host_start_time)

        stream1 = ixNetwork.Traffic.TrafficItem.find(Name='Trunk Orphan To Standalone')
        stream1.StartStatelessTraffic()
        log.info('Waiting {}secs to start the traffic'.format(traffic_start_time))
        time.sleep(traffic_start_time)
        
        stream1.StopStatelessTraffic()
        log.info('Waiting {}secs to stop the traffic'.format(traffic_stop_time))
        time.sleep(traffic_stop_time)

        with steps.start("checking mac learning for orphan mac"):
            if not verify_mac_on_vteps([prim_vtep, sec_vtep, sa_vtep], '1001', 1025, prim_mac):
                log.error("Mac learning failed for orphan mac")
                self.failed("Mac learning failed for orphan mac")

        with steps.start("Checking mac learning for standalone mac"):
            if not verify_mac_on_vteps([prim_vtep, sec_vtep, sa_vtep], '1002', 1025, sa_mac):
                log.error("Mac learning failed for standalone mac")
                self.failed("Mac learning failed for standalone mac")
        
        with steps.start("Restart Process - ethpm"):
            if not verify_process_restart(prim_vtep, "ethpm", testscript, log):
                log.error("Process restart failed on primary")
                self.failed("Process restart failed on primary")
            
            if not verify_process_restart(sec_vtep, "ethpm", testscript, log):
                log.error("Process restart failed on secondary")
                self.failed("Process restart failed on secondary")
            
            if not verify_process_restart(sa_vtep, "ethpm", testscript, log):
                log.error("Process restart failed on standalone")
                self.failed("Process restart failed on standalone")
    
        stream1.StartStatelessTraffic()
        log.info('Waiting {}secs to start the traffic'.format(traffic_start_time))
        time.sleep(traffic_start_time)
        
        stream1.StopStatelessTraffic()
        log.info('Waiting {}secs to stop the traffic'.format(traffic_stop_time))
        time.sleep(traffic_stop_time)

        with steps.start("checking mac learning for  orphan mac"):
            if not verify_mac_on_vteps([prim_vtep, sec_vtep, sa_vtep], '1001', 1025, prim_mac):
                log.error("Mac learning failed for orphan mac")
                self.failed("Mac learning failed for orphan mac")

        with steps.start("checking mac learning for standalone mac"):
            if not verify_mac_on_vteps([prim_vtep, sec_vtep, sa_vtep], '1002', 1025, sa_mac):
                log.error("Mac learning failed for standalone mac")
                self.failed("Mac learning failed for standalone mac")

        with steps.start('Verify Learned mac address consistency between hardware and software'):
            if verify_mac_cc_between_hardware_software([prim_vtep, sec_vtep, sa_vtep]):
                log.info('MAC CC success')
            else:
                self.failed('MAC CC failed')

        with steps.start("Verify Steady State"):
            if VerifyTraffic("TC_VXLAN_PVMAP_034", testscript, traffic_item='Trunk Orphan To Standalone'):
                log.info('Verify traffic success')
            else:
                self.failed('Verify traffic failed') 

    @aetest.test
    def verify_error_cores(self, testscript, testbed, steps):
        sa_vtep         = testscript.parameters['LEAF-3']
        prim_vtep       = testscript.parameters['LEAF-1']
        sec_vtep        = testscript.parameters['LEAF-2']
        ixNetwork       = testscript.parameters['ixNetwork']

        with steps.start("Stopping hosts..."):
            ixNetwork.StopAllProtocols()

        log.info('Waiting {}secs'.format(traffic_stop_time))
        time.sleep(traffic_stop_time)

        with steps.start("Verifying MTS leak.."):
            if verify_mts_leak([prim_vtep, sec_vtep, sa_vtep], log):
                log.info('MTS Leak verification success')
            else:
                self.failed('MTS Leak verification failed')

        with steps.start("Verifying Cores and Log Errors"):
            exclude_bkp = post_test_process_dict['exclude_log_check_pattern']
            post_test_process_dict['exclude_log_check_pattern'] = str(exclude_bkp) + '|SYSMGR-2-SERVICE_CRASHED'
            status = infraVerify.postTestVerification(post_test_process_dict)
            if status['status'] == 0:
                self.failed(reason=status['logs'])
            else:
                self.passed(reason=status['logs'])
            post_test_process_dict['exclude_log_check_pattern'] = exclude_bkp

# =====================================================================================================#
# TC-ID: TC_VXLAN_PVMAP_035 - Triggers - Process Restart
# Testcase:  
#   - bgp restart
#   - Check mac learning and traffic
# ======================================================================================================#
class TC_VXLAN_PVMAP_035(aetest.Testcase):
    @aetest.test
    def testcase_vpc_restart_bgp(self, testscript, steps):
        sa_vtep         = testscript.parameters['LEAF-3']
        prim_vtep       = testscript.parameters['LEAF-1']
        sec_vtep        = testscript.parameters['LEAF-2']
        prim_mac        = str(testscript.parameters['PVMAP_Dict']['prim_vpc_mac'])
        sa_mac          = str(testscript.parameters['PVMAP_Dict']['sa_mac'])
        p1_handle       = testscript.parameters['vpc_handle']
        p2_handle       = testscript.parameters['sa_handle']
        ixNetwork       = testscript.parameters['ixNetwork']

        with steps.start("Starting hosts..."):
            p1_handle.Start()
            p2_handle.Start()
        
        log.info('Waiting {}secs to start hosts'.format(host_start_time))
        time.sleep(host_start_time)

        stream1 = ixNetwork.Traffic.TrafficItem.find(Name='Trunk VPC To Standalone')
        stream1.StartStatelessTraffic()
        log.info('Waiting {}secs to start the traffic'.format(traffic_start_time))
        time.sleep(traffic_start_time)
        
        stream1.StopStatelessTraffic()
        log.info('Waiting {}secs to stop the traffic'.format(traffic_stop_time))
        time.sleep(traffic_stop_time)

        with steps.start("checking mac learning for vpc mac"):
            if not verify_mac_on_vteps([prim_vtep, sec_vtep, sa_vtep], '1001', 1025, prim_mac):
                log.error("Mac learning failed for vpc mac")
                self.failed("Mac learning failed for vpc mac")

        with steps.start("Checking mac learning for standalone mac"):
            if not verify_mac_on_vteps([prim_vtep, sec_vtep, sa_vtep], '1002', 1025, sa_mac):
                log.error("Mac learning failed for standalone mac")
                self.failed("Mac learning failed for standalone mac")
        
        with steps.start("Restart Process - bgp"):
            if not verify_process_restart(prim_vtep, "bgp", testscript, log):
                log.error("Process restart failed on primary")
                self.failed("Process restart failed on primary")
            
            if not verify_process_restart(sec_vtep, "bgp", testscript, log):
                log.error("Process restart failed on secondary")
                self.failed("Process restart failed on secondary")
            
            if not verify_process_restart(sa_vtep, "bgp", testscript, log):
                log.error("Process restart failed on standalone")
                self.failed("Process restart failed on standalone")
    
        stream1.StartStatelessTraffic()
        log.info('Waiting {}secs to start the traffic'.format(traffic_start_time))
        time.sleep(traffic_start_time)
        
        stream1.StopStatelessTraffic()
        log.info('Waiting {}secs to stop the traffic'.format(traffic_stop_time))
        time.sleep(traffic_stop_time)
        
        with steps.start("checking mac learning for vpc mac"):
            if not verify_mac_on_vteps([prim_vtep, sec_vtep, sa_vtep], '1001', 1025, prim_mac):
                log.error("Mac learning failed for orphan mac")
                self.failed("Mac learning failed for orphan mac")

        with steps.start("checking mac learning for standalone mac"):
            if not verify_mac_on_vteps([prim_vtep, sec_vtep, sa_vtep], '1002', 1025, sa_mac):
                log.error("Mac learning failed for standalone mac")
                self.failed("Mac learning failed for standalone mac")

        with steps.start('Verify Learned mac address consistency between hardware and software'):
            if verify_mac_cc_between_hardware_software([prim_vtep, sec_vtep, sa_vtep]):
                log.info('MAC CC success')
            else:
                self.failed('MAC CC failed')

        with steps.start("Verify Steady State"):
            if VerifyTraffic("TC_VXLAN_PVMAP_035", testscript, traffic_item='Trunk VPC To Standalone'):
                log.info('Verify traffic success')
            else:
                self.failed('Verify traffic failed') 

    @aetest.test
    def testcase_orphan_restart_bgp(self, testscript, steps):
        sa_vtep         = testscript.parameters['LEAF-3']
        prim_vtep       = testscript.parameters['LEAF-1']
        sec_vtep        = testscript.parameters['LEAF-2']
        prim_mac        = str(testscript.parameters['PVMAP_Dict']['prim_orphan_mac'])
        sa_mac          = str(testscript.parameters['PVMAP_Dict']['sa_mac'])
        p1_handle       = testscript.parameters['orphan1_handle']
        p2_handle       = testscript.parameters['sa_handle']
        ixNetwork       = testscript.parameters['ixNetwork']

        with steps.start("Starting hosts..."):
            p1_handle.Start()
            p2_handle.Start()
        
        log.info('Waiting {}secs to start hosts'.format(host_start_time))
        time.sleep(host_start_time)

        stream1 = ixNetwork.Traffic.TrafficItem.find(Name='Trunk Orphan To Standalone')
        stream1.StartStatelessTraffic()
        log.info('Waiting {}secs to start the traffic'.format(traffic_start_time))
        time.sleep(traffic_start_time)
        
        stream1.StopStatelessTraffic()
        log.info('Waiting {}secs to stop the traffic'.format(traffic_stop_time))
        time.sleep(traffic_stop_time)

        with steps.start("checking mac learning for orphan mac"):
            if not verify_mac_on_vteps([prim_vtep, sec_vtep, sa_vtep], '1001', 1025, prim_mac):
                log.error("Mac learning failed for orphan mac")
                self.failed("Mac learning failed for orphan mac")

        with steps.start("Checking mac learning for standalone mac"):
            if not verify_mac_on_vteps([prim_vtep, sec_vtep, sa_vtep], '1002', 1025, sa_mac):
                log.error("Mac learning failed for standalone mac")
                self.failed("Mac learning failed for standalone mac")
        
        with steps.start("Restart Process - bgp"):
            if not verify_process_restart(prim_vtep, "bgp", testscript, log):
                log.error("Process restart failed on primary")
                self.failed("Process restart failed on primary")
            
            if not verify_process_restart(sec_vtep, "bgp", testscript, log):
                log.error("Process restart failed on secondary")
                self.failed("Process restart failed on secondary")
            
            if not verify_process_restart(sa_vtep, "bgp", testscript, log):
                log.error("Process restart failed on standalone")
                self.failed("Process restart failed on standalone")
    
        stream1.StartStatelessTraffic()
        log.info('Waiting {}secs to start the traffic'.format(traffic_start_time))
        time.sleep(traffic_start_time)
        
        stream1.StopStatelessTraffic()
        log.info('Waiting {}secs to stop the traffic'.format(traffic_stop_time))
        time.sleep(traffic_stop_time)

        with steps.start("checking mac learning for orphan mac"):
            if not verify_mac_on_vteps([prim_vtep, sec_vtep, sa_vtep], '1001', 1025, prim_mac):
                log.error("Mac learning failed for orphan mac")
                self.failed("Mac learning failed for orphan mac")

        with steps.start("checking mac learning for standalone mac"):
            if not verify_mac_on_vteps([prim_vtep, sec_vtep, sa_vtep], '1002', 1025, sa_mac):
                log.error("Mac learning failed for standalone mac")
                self.failed("Mac learning failed for standalone mac")

        with steps.start('Verify Learned mac address consistency between hardware and software'):
            if verify_mac_cc_between_hardware_software([prim_vtep, sec_vtep, sa_vtep]):
                log.info('MAC CC success')
            else:
                self.failed('MAC CC failed')

        with steps.start("Verify Steady State"):
            if VerifyTraffic("TC_VXLAN_PVMAP_035", testscript, traffic_item='Trunk Orphan To Standalone'):
                log.info('Verify traffic success')
            else:
                self.failed('Verify traffic failed') 

    @aetest.test
    def verify_error_cores(self, testscript, testbed, steps):
        sa_vtep         = testscript.parameters['LEAF-3']
        prim_vtep       = testscript.parameters['LEAF-1']
        sec_vtep        = testscript.parameters['LEAF-2']
        ixNetwork       = testscript.parameters['ixNetwork']

        with steps.start("Stopping hosts..."):
            ixNetwork.StopAllProtocols()

        log.info('Waiting {}secs'.format(traffic_stop_time))
        time.sleep(traffic_stop_time)

        with steps.start("Verifying MTS leak.."):
            if verify_mts_leak([prim_vtep, sec_vtep, sa_vtep], log):
                log.info('MTS Leak verification success')
            else:
                self.failed('MTS Leak verification failed')

        with steps.start("Verifying Cores and Log Errors"):
            exclude_bkp = post_test_process_dict['exclude_log_check_pattern']
            post_test_process_dict['exclude_log_check_pattern'] = str(exclude_bkp) + '|SYSMGR-2-SERVICE_CRASHED'
            status = infraVerify.postTestVerification(post_test_process_dict)
            if status['status'] == 0:
                self.failed(reason=status['logs'])
            else:
                self.passed(reason=status['logs'])
            post_test_process_dict['exclude_log_check_pattern'] = exclude_bkp

# =====================================================================================================#
# TC-ID: TC_VXLAN_PVMAP_036 - Triggers - clear command
# Testcase:  
#   - clear ip route restart
#   - Check mac learning and traffic
# ======================================================================================================#
class TC_VXLAN_PVMAP_036(aetest.Testcase):
    @aetest.test
    def testcase_vpc_clear_iproute(self, testscript, steps):
        sa_vtep         = testscript.parameters['LEAF-3']
        prim_vtep       = testscript.parameters['LEAF-1']
        sec_vtep        = testscript.parameters['LEAF-2']
        prim_mac        = str(testscript.parameters['PVMAP_Dict']['prim_vpc_mac'])
        sa_mac          = str(testscript.parameters['PVMAP_Dict']['sa_mac'])
        p1_handle       = testscript.parameters['vpc_handle']
        p2_handle       = testscript.parameters['sa_handle']
        ixNetwork       = testscript.parameters['ixNetwork']

        with steps.start("Starting hosts..."):
            p1_handle.Start()
            p2_handle.Start()
        
        log.info('Waiting {}secs to start hosts'.format(host_start_time))
        time.sleep(host_start_time)

        stream1 = ixNetwork.Traffic.TrafficItem.find(Name='Trunk VPC To Standalone')
        stream1.StartStatelessTraffic()
        log.info('Waiting {}secs to start the traffic'.format(traffic_start_time))
        time.sleep(traffic_start_time)
        
        stream1.StopStatelessTraffic()
        log.info('Waiting {}secs to stop the traffic'.format(traffic_stop_time))
        time.sleep(traffic_stop_time)

        with steps.start("checking mac learning for vpc mac"):
            if not verify_mac_on_vteps([prim_vtep, sec_vtep, sa_vtep], '1001', 1025, prim_mac):
                log.error("Mac learning failed for vpc mac")
                self.failed("Mac learning failed for vpc mac")

        with steps.start("Checking mac learning for standalone mac"):
            if not verify_mac_on_vteps([prim_vtep, sec_vtep, sa_vtep], '1002', 1025, sa_mac):
                log.error("Mac learning failed for standalone mac")
                self.failed("Mac learning failed for standalone mac")
        
        with steps.start("Clear - ip route"):
            try:
                prim_vtep.execute('''clear ip route *''')
                sec_vtep.configure('''clear ip route *''')
            except Exception as error:
                log.debug("Unable to configure - Encountered Exception " + str(error))
                self.errored('Exception occurred while configuring PVMAP', 
                            goto=['common_cleanup']) 
    
        stream1.StartStatelessTraffic()
        log.info('Waiting {}secs to start the traffic'.format(traffic_start_time))
        time.sleep(traffic_start_time)
        
        stream1.StopStatelessTraffic()
        log.info('Waiting {}secs to stop the traffic'.format(traffic_stop_time))
        time.sleep(traffic_stop_time)
        
        with steps.start("checking mac learning for vpc mac"):
            if not verify_mac_on_vteps([prim_vtep, sec_vtep, sa_vtep], '1001', 1025, prim_mac):
                log.error("Mac learning failed for orphan mac")
                self.failed("Mac learning failed for orphan mac")

        with steps.start("checking mac learning for standalone mac"):
            if not verify_mac_on_vteps([prim_vtep, sec_vtep, sa_vtep], '1002', 1025, sa_mac):
                log.error("Mac learning failed for standalone mac")
                self.failed("Mac learning failed for standalone mac")

        with steps.start('Verify Learned mac address consistency between hardware and software'):
            if verify_mac_cc_between_hardware_software([prim_vtep, sec_vtep, sa_vtep]):
                log.info('MAC CC success')
            else:
                self.failed('MAC CC failed')

        with steps.start("Verify Steady State"):
            if VerifyTraffic("TC_VXLAN_PVMAP_036", testscript, traffic_item='Trunk VPC To Standalone'):
                log.info('Verify traffic success')
            else:
                self.failed('Verify traffic failed') 

    @aetest.test
    def testcase_orphan_clear_iproute(self, testscript, steps):
        sa_vtep         = testscript.parameters['LEAF-3']
        prim_vtep       = testscript.parameters['LEAF-1']
        sec_vtep        = testscript.parameters['LEAF-2']
        prim_mac        = str(testscript.parameters['PVMAP_Dict']['prim_orphan_mac'])
        sa_mac          = str(testscript.parameters['PVMAP_Dict']['sa_mac'])
        p1_handle       = testscript.parameters['orphan1_handle']
        p2_handle       = testscript.parameters['sa_handle']
        ixNetwork       = testscript.parameters['ixNetwork']

        with steps.start("Starting hosts..."):
            p1_handle.Start()
            p2_handle.Start()
        
        log.info('Waiting {}secs to start hosts'.format(host_start_time))
        time.sleep(host_start_time)

        stream1 = ixNetwork.Traffic.TrafficItem.find(Name='Trunk Orphan To Standalone')
        stream1.StartStatelessTraffic()
        log.info('Waiting {}secs to start the traffic'.format(traffic_start_time))
        time.sleep(traffic_start_time)
        
        stream1.StopStatelessTraffic()
        log.info('Waiting {}secs to stop the traffic'.format(traffic_stop_time))
        time.sleep(traffic_stop_time)

        with steps.start("checking mac learning for orphan mac"):
            if not verify_mac_on_vteps([prim_vtep, sec_vtep, sa_vtep], '1001', 1025, prim_mac):
                log.error("Mac learning failed for orphan mac")
                self.failed("Mac learning failed for orphan mac")

        with steps.start("Checking mac learning for standalone mac"):
            if not verify_mac_on_vteps([prim_vtep, sec_vtep, sa_vtep], '1002', 1025, sa_mac):
                log.error("Mac learning failed for standalone mac")
                self.failed("Mac learning failed for standalone mac")
        

        with steps.start("Clear - ip route"):
            try:
                prim_vtep.execute('''clear ip route *''')
                sec_vtep.execute('''clear ip route *''')
                sa_vtep.configure('''clear ip route *''')
            except Exception as error:
                log.debug("Unable to configure - Encountered Exception " + str(error))
                self.errored('Exception occurred while configuring PVMAP', 
                            goto=['common_cleanup']) 
    
        stream1.StartStatelessTraffic()
        log.info('Waiting {}secs to start the traffic'.format(traffic_start_time))
        time.sleep(traffic_start_time)
        
        stream1.StopStatelessTraffic()
        log.info('Waiting {}secs to stop the traffic'.format(traffic_stop_time))
        time.sleep(traffic_stop_time)

        with steps.start("checking mac learning for orphan mac"):
            if not verify_mac_on_vteps([prim_vtep, sec_vtep, sa_vtep], '1001', 1025, prim_mac):
                log.error("Mac learning failed for orphan mac")
                self.failed("Mac learning failed for orphan mac")

        with steps.start("checking mac learning for standalone mac"):
            if not verify_mac_on_vteps([prim_vtep, sec_vtep, sa_vtep], '1002', 1025, sa_mac):
                log.error("Mac learning failed for standalone mac")
                self.failed("Mac learning failed for standalone mac")

        with steps.start('Verify Learned mac address consistency between hardware and software'):
            if verify_mac_cc_between_hardware_software([prim_vtep, sec_vtep, sa_vtep]):
                log.info('MAC CC success')
            else:
                self.failed('MAC CC failed')

        with steps.start("Verify Steady State"):
            if VerifyTraffic("TC_VXLAN_PVMAP_036", testscript, traffic_item='Trunk Orphan To Standalone'):
                log.info('Verify traffic success')
            else:
                self.failed('Verify traffic failed') 

    @aetest.test
    def verify_error_cores(self, testscript, testbed, steps):
        sa_vtep         = testscript.parameters['LEAF-3']
        prim_vtep       = testscript.parameters['LEAF-1']
        sec_vtep        = testscript.parameters['LEAF-2']
        ixNetwork       = testscript.parameters['ixNetwork']

        with steps.start("Stopping hosts..."):
            ixNetwork.StopAllProtocols()

        log.info('Waiting {}secs'.format(traffic_stop_time))
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

# =====================================================================================================#
# TC-ID: TC_VXLAN_PVMAP_037 - Triggers - clear command
# Testcase:  
#   - clear ip bgp restart
#   - Check mac learning and traffic
# ======================================================================================================#
class TC_VXLAN_PVMAP_037(aetest.Testcase):
    @aetest.test
    def testcase_vpc_clear_ipbgp(self, testscript, steps):
        sa_vtep         = testscript.parameters['LEAF-3']
        prim_vtep       = testscript.parameters['LEAF-1']
        sec_vtep        = testscript.parameters['LEAF-2']
        prim_mac        = str(testscript.parameters['PVMAP_Dict']['prim_vpc_mac'])
        sa_mac          = str(testscript.parameters['PVMAP_Dict']['sa_mac'])
        p1_handle       = testscript.parameters['vpc_handle']
        p2_handle       = testscript.parameters['sa_handle']
        ixNetwork       = testscript.parameters['ixNetwork']

        with steps.start("Starting hosts..."):
            p1_handle.Start()
            p2_handle.Start()
        
        log.info('Waiting {}secs to start hosts'.format(host_start_time))
        time.sleep(host_start_time)

        stream1 = ixNetwork.Traffic.TrafficItem.find(Name='Trunk VPC To Standalone')
        stream1.StartStatelessTraffic()
        log.info('Waiting {}secs to start the traffic'.format(traffic_start_time))
        time.sleep(traffic_start_time)
        
        stream1.StopStatelessTraffic()
        log.info('Waiting {}secs to stop the traffic'.format(traffic_stop_time))
        time.sleep(traffic_stop_time)

        with steps.start("checking mac learning for vpc mac"):
            if not verify_mac_on_vteps([prim_vtep, sec_vtep, sa_vtep], '1001', 1025, prim_mac):
                log.error("Mac learning failed for vpc mac")
                self.failed("Mac learning failed for vpc mac")

        with steps.start("Checking mac learning for standalone mac"):
            if not verify_mac_on_vteps([prim_vtep, sec_vtep, sa_vtep], '1002', 1025, sa_mac):
                log.error("Mac learning failed for standalone mac")
                self.failed("Mac learning failed for standalone mac")
        
        with steps.start("Clear - ip bgp"):
            try:
                prim_vtep.execute('''clear ip bgp *''')
                sec_vtep.configure('''clear ip bgp *''')
            except Exception as error:
                log.debug("Unable to configure - Encountered Exception " + str(error))
                self.errored('Exception occurred while configuring PVMAP', 
                            goto=['common_cleanup']) 
    
        stream1.StartStatelessTraffic()
        log.info('Waiting {}secs to start the traffic'.format(traffic_start_time))
        time.sleep(traffic_start_time)
        
        stream1.StopStatelessTraffic()
        log.info('Waiting {}secs to stop the traffic'.format(traffic_stop_time))
        time.sleep(traffic_stop_time)
        
        with steps.start("checking mac learning for vpc mac"):
            if not verify_mac_on_vteps([prim_vtep, sec_vtep, sa_vtep], '1001', 1025, prim_mac):
                log.error("Mac learning failed for orphan mac")
                self.failed("Mac learning failed for orphan mac")

        with steps.start("checking mac learning after for standalone mac"):
            if not verify_mac_on_vteps([prim_vtep, sec_vtep, sa_vtep], '1002', 1025, sa_mac):
                log.error("Mac learning failed for standalone mac")
                self.failed("Mac learning failed for standalone mac")

        with steps.start('Verify Learned mac address consistency between hardware and software'):
            if verify_mac_cc_between_hardware_software([prim_vtep, sec_vtep, sa_vtep]):
                log.info('MAC CC success')
            else:
                self.failed('MAC CC failed')

        with steps.start("Verify Steady State"):
            if VerifyTraffic("TC_VXLAN_PVMAP_037", testscript, traffic_item='Trunk VPC To Standalone'):
                log.info('Verify traffic success')
            else:
                self.failed('Verify traffic failed') 

    @aetest.test
    def testcase_orphan_clear_ipbgp(self, testscript, steps):
        sa_vtep         = testscript.parameters['LEAF-3']
        prim_vtep       = testscript.parameters['LEAF-1']
        sec_vtep        = testscript.parameters['LEAF-2']
        prim_mac        = str(testscript.parameters['PVMAP_Dict']['prim_orphan_mac'])
        sa_mac          = str(testscript.parameters['PVMAP_Dict']['sa_mac'])
        p1_handle       = testscript.parameters['orphan1_handle']
        p2_handle       = testscript.parameters['sa_handle']
        ixNetwork       = testscript.parameters['ixNetwork']

        with steps.start("Starting hosts..."):
            p1_handle.Start()
            p2_handle.Start()
        
        log.info('Waiting {}secs to start hosts'.format(host_start_time))
        time.sleep(host_start_time)

        stream1 = ixNetwork.Traffic.TrafficItem.find(Name='Trunk Orphan To Standalone')
        stream1.StartStatelessTraffic()
        log.info('Waiting {}secs to start the traffic'.format(traffic_start_time))
        time.sleep(traffic_start_time)
        
        stream1.StopStatelessTraffic()
        log.info('Waiting {}secs to stop the traffic'.format(traffic_stop_time))
        time.sleep(traffic_stop_time)

        with steps.start("checking mac learning for orphan mac"):
            if not verify_mac_on_vteps([prim_vtep, sec_vtep, sa_vtep], '1001', 1025, prim_mac):
                log.error("Mac learning failed for orphan mac")
                self.failed("Mac learning failed for orphan mac")

        with steps.start("Checking mac learning for standalone mac"):
            if not verify_mac_on_vteps([prim_vtep, sec_vtep, sa_vtep], '1002', 1025, sa_mac):
                log.error("Mac learning failed for standalone mac")
                self.failed("Mac learning failed for standalone mac")
        

        with steps.start("Clear - ip bgp"):
            try:
                prim_vtep.execute('''clear ip bgp *''')
                sec_vtep.execute('''clear ip bgp *''')
                sa_vtep.configure('''clear ip bgp *''')
            except Exception as error:
                log.debug("Unable to configure - Encountered Exception " + str(error))
                self.errored('Exception occurred while configuring PVMAP', 
                            goto=['common_cleanup']) 
    
        stream1.StartStatelessTraffic()
        log.info('Waiting {}secs to start the traffic'.format(traffic_start_time))
        time.sleep(traffic_start_time)
        
        stream1.StopStatelessTraffic()
        log.info('Waiting {}secs to stop the traffic'.format(traffic_stop_time))
        time.sleep(traffic_stop_time)

        with steps.start("checking mac learning for orphan mac"):
            if not verify_mac_on_vteps([prim_vtep, sec_vtep, sa_vtep], '1001', 1025, prim_mac):
                log.error("Mac learning failed for orphan mac")
                self.failed("Mac learning failed for orphan mac")

        with steps.start("checking mac learning for standalone mac"):
            if not verify_mac_on_vteps([prim_vtep, sec_vtep, sa_vtep], '1002', 1025, sa_mac):
                log.error("Mac learning failed for standalone mac")
                self.failed("Mac learning failed for standalone mac")

        with steps.start('Verify Learned mac address consistency between hardware and software'):
            if verify_mac_cc_between_hardware_software([prim_vtep, sec_vtep, sa_vtep]):
                log.info('MAC CC success')
            else:
                self.failed('MAC CC failed')

        with steps.start("Verify Steady State"):
            if VerifyTraffic("TC_VXLAN_PVMAP_037", testscript, traffic_item='Trunk Orphan To Standalone'):
                log.info('Verify traffic success')
            else:
                self.failed('Verify traffic failed') 

    @aetest.test
    def verify_error_cores(self, testscript, testbed, steps):
        sa_vtep         = testscript.parameters['LEAF-3']
        prim_vtep       = testscript.parameters['LEAF-1']
        sec_vtep        = testscript.parameters['LEAF-2']
        ixNetwork       = testscript.parameters['ixNetwork']

        with steps.start("Stopping hosts..."):
            ixNetwork.StopAllProtocols()

        log.info('Waiting {}secs'.format(traffic_stop_time))
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

# =====================================================================================================#
# TC-ID: TC_VXLAN_PVMAP_039 - Triggers - clear command
# Testcase:  
#   - clear mac address table restart
#   - Check mac learning and traffic
# ======================================================================================================#
class TC_VXLAN_PVMAP_039(aetest.Testcase):
    @aetest.test
    def testcase_vpc_clear_mactable(self, testscript, steps):
        sa_vtep         = testscript.parameters['LEAF-3']
        prim_vtep       = testscript.parameters['LEAF-1']
        sec_vtep        = testscript.parameters['LEAF-2']
        prim_mac        = str(testscript.parameters['PVMAP_Dict']['prim_vpc_mac'])
        sa_mac          = str(testscript.parameters['PVMAP_Dict']['sa_mac'])
        p1_handle       = testscript.parameters['vpc_handle']
        p2_handle       = testscript.parameters['sa_handle']
        ixNetwork       = testscript.parameters['ixNetwork']

        with steps.start("Starting hosts..."):
            p1_handle.Start()
            p2_handle.Start()
        
        log.info('Waiting {}secs to start hosts'.format(host_start_time))
        time.sleep(host_start_time)

        stream1 = ixNetwork.Traffic.TrafficItem.find(Name='Trunk VPC To Standalone')
        stream1.StartStatelessTraffic()
        log.info('Waiting {}secs to start the traffic'.format(traffic_start_time))
        time.sleep(traffic_start_time)
        
        stream1.StopStatelessTraffic()
        log.info('Waiting {}secs to stop the traffic'.format(traffic_stop_time))
        time.sleep(traffic_stop_time)

        with steps.start("checking mac learning for vpc mac"):
            if not verify_mac_on_vteps([prim_vtep, sec_vtep, sa_vtep], '1001', 1025, prim_mac):
                log.error("Mac learning failed for vpc mac")
                self.failed("Mac learning failed for vpc mac")

        with steps.start("Checking mac learning for standalone mac"):
            if not verify_mac_on_vteps([prim_vtep, sec_vtep, sa_vtep], '1002', 1025, sa_mac):
                log.error("Mac learning failed for standalone mac")
                self.failed("Mac learning failed for standalone mac")
        
        with steps.start("Stopping hosts..."):
            ixNetwork.StopAllProtocols()

        log.info('Waiting {}secs to stop the traffic'.format(traffic_stop_time))
        time.sleep(traffic_stop_time)
        
        with steps.start("Clear - mac table"):
            try:
                prim_vtep.execute('''clear mac address-table dynamic''')
                sec_vtep.configure('''clear mac address-table dynamic''')
                sa_vtep.configure('''clear mac address-table dynamic''')
            except Exception as error:
                log.debug("Unable to configure - Encountered Exception " + str(error))
                self.errored('Exception occurred while configuring PVMAP', 
                            goto=['common_cleanup']) 
        
        log.info('Waiting 60secs to clear macs')
        time.sleep(60)

        with steps.start("checking mac learning for vpc mac"):
            if not verify_mac_on_vteps([prim_vtep, sec_vtep, sa_vtep], '1001', 0, prim_mac):
                log.error("Mac learning failed for vpc mac")
                self.failed("Mac learning failed for vpc mac")

        with steps.start("checking mac learning for standalone mac"):
            if not verify_mac_on_vteps([prim_vtep, sec_vtep, sa_vtep], '1002', 0, sa_mac):
                log.error("Mac learning failed for standalone mac")
                self.failed("Mac learning failed for standalone mac")
        
        with steps.start("Starting hosts..."):
            p1_handle.Start()
            p2_handle.Start()
        
        log.info('Waiting {}secs to start hosts'.format(host_start_time))
        time.sleep(host_start_time)

        stream1.StartStatelessTraffic()
        log.info('Waiting {}secs to start the traffic'.format(traffic_start_time))
        time.sleep(traffic_start_time)
        
        stream1.StopStatelessTraffic()
        log.info('Waiting {}secs to stop the traffic'.format(traffic_stop_time))
        time.sleep(traffic_stop_time)
        
        log.info('Waiting 60secs for mac relearning')
        time.sleep(60)
        
        with steps.start("checking mac learning for vpc mac"):
            if not verify_mac_on_vteps([prim_vtep, sec_vtep, sa_vtep], '1001', 1025, prim_mac):
                log.error("Mac learning failed for vpc mac")
                self.failed("Mac learning failed for vpc mac")

        with steps.start("checking mac learning for standalone mac"):
            if not verify_mac_on_vteps([prim_vtep, sec_vtep, sa_vtep], '1002', 1025, sa_mac):
                log.error("Mac learning failed for standalone mac")
                self.failed("Mac learning failed for standalone mac")

        with steps.start('Verify Learned mac address consistency between hardware and software'):
            if verify_mac_cc_between_hardware_software([prim_vtep, sec_vtep, sa_vtep]):
                log.info('MAC CC success')
            else:
                self.failed('MAC CC failed')

        with steps.start("Verify Steady State"):
            if VerifyTraffic("TC_VXLAN_PVMAP_039", testscript, traffic_item='Trunk VPC To Standalone'):
                log.info('Verify traffic success')
            else:
                self.failed('Verify traffic failed') 

    @aetest.test
    def testcase_orphan_clear_mactable(self, testscript, steps):
        sa_vtep         = testscript.parameters['LEAF-3']
        prim_vtep       = testscript.parameters['LEAF-1']
        sec_vtep        = testscript.parameters['LEAF-2']
        prim_mac        = str(testscript.parameters['PVMAP_Dict']['prim_orphan_mac'])
        sa_mac          = str(testscript.parameters['PVMAP_Dict']['sa_mac'])
        p1_handle       = testscript.parameters['orphan1_handle']
        p2_handle       = testscript.parameters['sa_handle']
        ixNetwork       = testscript.parameters['ixNetwork']

        with steps.start("Starting hosts..."):
            p1_handle.Start()
            p2_handle.Start()
        
        log.info('Waiting {}secs to start hosts'.format(host_start_time))
        time.sleep(host_start_time)

        stream1 = ixNetwork.Traffic.TrafficItem.find(Name='Trunk Orphan To Standalone')
        stream1.StartStatelessTraffic()
        log.info('Waiting {}secs to start the traffic'.format(traffic_start_time))
        time.sleep(traffic_start_time)
        
        stream1.StopStatelessTraffic()
        log.info('Waiting {}secs to stop the traffic'.format(traffic_stop_time))
        time.sleep(traffic_stop_time)

        with steps.start("checking mac learning for orphan mac"):
            if not verify_mac_on_vteps([prim_vtep, sec_vtep, sa_vtep], '1001', 1025, prim_mac):
                log.error("Mac learning failed for orphan mac")
                self.failed("Mac learning failed for orphan mac")

        with steps.start("Checking mac learning for standalone mac"):
            if not verify_mac_on_vteps([prim_vtep, sec_vtep, sa_vtep], '1002', 1025, sa_mac):
                log.error("Mac learning failed for standalone mac")
                self.failed("Mac learning failed for standalone mac")
        
        with steps.start("Stopping hosts..."):
            ixNetwork.StopAllProtocols()

        log.info('Waiting {}secs to stop the traffic'.format(traffic_stop_time))
        time.sleep(traffic_stop_time)
        
        with steps.start("Clear - mac table"):
            try:
                prim_vtep.execute('''clear mac address-table dynamic''')
                sec_vtep.execute('''clear mac address-table dynamic''')
                sa_vtep.configure('''clear mac address-table dynamic''')
            except Exception as error:
                log.debug("Unable to configure - Encountered Exception " + str(error))
                self.errored('Exception occurred while configuring PVMAP', 
                            goto=['common_cleanup']) 

        log.info('Waiting for 30secs for mac relearning')
        time.sleep(30)

        with steps.start("checking mac learning for orphan mac"):
            if not verify_mac_on_vteps([prim_vtep, sec_vtep, sa_vtep], '1001', 0, prim_mac):
                log.error("Mac learning failed for orphan mac")
                self.failed("Mac learning failed for orphan mac")

        with steps.start("checking mac learning for standalone mac"):
            if not verify_mac_on_vteps([prim_vtep, sec_vtep, sa_vtep], '1002', 0, sa_mac):
                log.error("Mac learning failed for standalone mac")
                self.failed("Mac learning failed for standalone mac")

        with steps.start("Starting hosts..."):
            p1_handle.Start()
            p2_handle.Start()
        
        log.info('Waiting {}secs to start hosts'.format(host_start_time))
        time.sleep(host_start_time)

        stream1 = ixNetwork.Traffic.TrafficItem.find(Name='Trunk Orphan To Standalone')
        stream1.StartStatelessTraffic()
        log.info('Waiting {}secs to start the traffic'.format(traffic_start_time))
        time.sleep(traffic_start_time)
        
        stream1.StopStatelessTraffic()
        log.info('Waiting {}secs to stop the traffic'.format(traffic_stop_time))
        time.sleep(traffic_stop_time)
        
        with steps.start("checking mac learning for orphan mac"):
            if not verify_mac_on_vteps([prim_vtep, sec_vtep, sa_vtep], '1001', 1025, prim_mac):
                log.error("Mac learning failed for orphan mac")
                self.failed("Mac learning failed for orphan mac")

        with steps.start("checking mac learning for standalone mac"):
            if not verify_mac_on_vteps([prim_vtep, sec_vtep, sa_vtep], '1002', 1025, sa_mac):
                log.error("Mac learning failed for standalone mac")
                self.failed("Mac learning failed for standalone mac")

        with steps.start('Verify Learned mac address consistency between hardware and software'):
            if verify_mac_cc_between_hardware_software([prim_vtep, sec_vtep, sa_vtep]):
                log.info('MAC CC success')
            else:
                self.failed('MAC CC failed')

        with steps.start("Verify Steady State"):
            if VerifyTraffic("TC_VXLAN_PVMAP_039", testscript, traffic_item='Trunk Orphan To Standalone'):
                log.info('Verify traffic success')
            else:
                self.failed('Verify traffic failed') 

    @aetest.test
    def verify_error_cores(self, testscript, testbed, steps):
        sa_vtep         = testscript.parameters['LEAF-3']
        prim_vtep       = testscript.parameters['LEAF-1']
        sec_vtep        = testscript.parameters['LEAF-2']
        ixNetwork       = testscript.parameters['ixNetwork']

        with steps.start("Stopping hosts..."):
            ixNetwork.StopAllProtocols()

        log.info('Waiting {}secs'.format(traffic_stop_time))
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

# =====================================================================================================#
# TC-ID: TC_VXLAN_PVMAP_040 - Triggers - clear command
# Testcase:  
#   - clear arp table restart
#   - Check mac learning and traffic
# ======================================================================================================#
class TC_VXLAN_PVMAP_040(aetest.Testcase):
    @aetest.test
    def testcase_vpc_clear_arptable(self, testscript, steps):
        sa_vtep         = testscript.parameters['LEAF-3']
        prim_vtep       = testscript.parameters['LEAF-1']
        sec_vtep        = testscript.parameters['LEAF-2']
        prim_mac        = str(testscript.parameters['PVMAP_Dict']['prim_vpc_mac'])
        sa_mac          = str(testscript.parameters['PVMAP_Dict']['sa_mac'])
        VRF_string      = str(testscript.parameters['forwardingSysDict']['VRF_string'])
        VRF_id_start    = str(testscript.parameters['forwardingSysDict']['VRF_id_start'])
        vrf_id 			= VRF_string + VRF_id_start
        p1_handle       = testscript.parameters['vpc_handle']
        p2_handle       = testscript.parameters['sa_handle']
        ixNetwork       = testscript.parameters['ixNetwork']

        with steps.start("Starting hosts..."):
            p1_handle.Start()
            p2_handle.Start()
        
        log.info('Waiting {}secs to start hosts'.format(host_start_time))
        time.sleep(host_start_time)

        stream1 = ixNetwork.Traffic.TrafficItem.find(Name='Trunk VPC To Standalone')
        stream1.StartStatelessTraffic()
        log.info('Waiting {}secs to start the traffic'.format(traffic_start_time))
        time.sleep(traffic_start_time)
        
        stream1.StopStatelessTraffic()
        log.info('Waiting {}secs to stop the traffic'.format(traffic_stop_time))
        time.sleep(traffic_stop_time)

        with steps.start("checking mac learning for vpc mac"):
            if not verify_mac_on_vteps([prim_vtep, sec_vtep, sa_vtep], '1001', 1025, prim_mac):
                log.error("Mac learning failed for vpc mac")
                self.failed("Mac learning failed for vpc mac")

        with steps.start("Checking mac learning for standalone mac"):
            if not verify_mac_on_vteps([prim_vtep, sec_vtep, sa_vtep], '1002', 1025, sa_mac):
                log.error("Mac learning failed for standalone mac")
                self.failed("Mac learning failed for standalone mac")
        
        with steps.start("Stopping hosts..."):
            ixNetwork.StopAllProtocols()

        log.info('Waiting {}secs to stop the traffic'.format(traffic_stop_time))
        time.sleep(traffic_stop_time)
        
        with steps.start("Clear - arp table"):
            try:
                prim_vtep.execute('''clear ip arp vrf {vrfid} force-delete'''.format(vrfid=vrf_id))
                sec_vtep.configure('''clear ip arp vrf {vrfid} force-delete'''.format(vrfid=vrf_id))
            except Exception as error:
                log.debug("Unable to configure - Encountered Exception " + str(error))
                self.errored('Exception occurred while configuring PVMAP', 
                            goto=['common_cleanup']) 
    
        with steps.start("Starting hosts..."):
            p1_handle.Start()
            p2_handle.Start()
        
        log.info('Waiting {}secs to start hosts'.format(host_start_time))
        time.sleep(host_start_time)

        stream1.StartStatelessTraffic()
        log.info('Waiting {}secs to start the traffic'.format(traffic_start_time))
        time.sleep(traffic_start_time)
        
        stream1.StopStatelessTraffic()
        log.info('Waiting {}secs to stop the traffic'.format(traffic_stop_time))
        time.sleep(traffic_stop_time)
        
        log.info('Waiting 60secs for mac relearning')
        time.sleep(60)
        
        with steps.start("checking mac learning for vpc mac"):
            if not verify_mac_on_vteps([prim_vtep, sec_vtep, sa_vtep], '1001', 1025, prim_mac):
                log.error("Mac learning failed for orphan mac")
                self.failed("Mac learning failed for orphan mac")

        with steps.start("checking mac learning for standalone mac"):
            if not verify_mac_on_vteps([prim_vtep, sec_vtep, sa_vtep], '1002', 1025, sa_mac):
                log.error("Mac learning failed for standalone mac")
                self.failed("Mac learning failed for standalone mac")

        with steps.start('Verify Learned mac address consistency between hardware and software'):
            if verify_mac_cc_between_hardware_software([prim_vtep, sec_vtep, sa_vtep]):
                log.info('MAC CC success')
            else:
                self.failed('MAC CC failed')

        with steps.start("Verify Steady State"):
            if VerifyTraffic("TC_VXLAN_PVMAP_040", testscript, traffic_item='Trunk VPC To Standalone'):
                log.info('Verify traffic success')
            else:
                self.failed('Verify traffic failed') 

    @aetest.test
    def testcase_orphan_clear_mactable(self, testscript, steps):
        sa_vtep         = testscript.parameters['LEAF-3']
        prim_vtep       = testscript.parameters['LEAF-1']
        sec_vtep        = testscript.parameters['LEAF-2']
        prim_mac        = str(testscript.parameters['PVMAP_Dict']['prim_orphan_mac'])
        sa_mac          = str(testscript.parameters['PVMAP_Dict']['sa_mac'])
        VRF_string      = str(testscript.parameters['forwardingSysDict']['VRF_string'])
        VRF_id_start    = str(testscript.parameters['forwardingSysDict']['VRF_id_start'])
        vrf_id 			= VRF_string + VRF_id_start
        p1_handle       = testscript.parameters['orphan1_handle']
        p2_handle       = testscript.parameters['sa_handle']
        ixNetwork       = testscript.parameters['ixNetwork']

        with steps.start("Starting hosts..."):
            p1_handle.Start()
            p2_handle.Start()
        
        log.info('Waiting {}secs to start hosts'.format(host_start_time))
        time.sleep(host_start_time)

        stream1 = ixNetwork.Traffic.TrafficItem.find(Name='Trunk Orphan To Standalone')
        stream1.StartStatelessTraffic()
        log.info('Waiting {}secs to start the traffic'.format(traffic_start_time))
        time.sleep(traffic_start_time)
        
        stream1.StopStatelessTraffic()
        log.info('Waiting {}secs to stop the traffic'.format(traffic_stop_time))
        time.sleep(traffic_stop_time)

        with steps.start("checking mac learning for orphan mac"):
            if not verify_mac_on_vteps([prim_vtep, sec_vtep, sa_vtep], '1001', 1025, prim_mac):
                log.error("Mac learning failed for orphan mac")
                self.failed("Mac learning failed for orphan mac")

        with steps.start("Checking mac learning for standalone mac"):
            if not verify_mac_on_vteps([prim_vtep, sec_vtep, sa_vtep], '1002', 1025, sa_mac):
                log.error("Mac learning failed for standalone mac")
                self.failed("Mac learning failed for standalone mac")
        
        with steps.start("Stopping hosts..."):
            ixNetwork.StopAllProtocols()

        log.info('Waiting {}secs to stop the traffic'.format(traffic_stop_time))
        time.sleep(traffic_stop_time)
        
        with steps.start("Clear - arp table"):
            try:
                prim_vtep.execute('''clear ip arp vrf {vrfid} force-delete'''.format(vrfid=vrf_id))
                sec_vtep.execute('''clear ip arp vrf {vrfid} force-delete'''.format(vrfid=vrf_id))
                sa_vtep.configure('''clear ip arp vrf {vrfid} force-delete'''.format(vrfid=vrf_id))
            except Exception as error:
                log.debug("Unable to configure - Encountered Exception " + str(error))
                self.errored('Exception occurred while configuring PVMAP', 
                            goto=['common_cleanup']) 

        with steps.start("Starting hosts..."):
            p1_handle.Start()
            p2_handle.Start()
        
        log.info('Waiting {}secs to start hosts'.format(host_start_time))
        time.sleep(host_start_time)

        stream1 = ixNetwork.Traffic.TrafficItem.find(Name='Trunk Orphan To Standalone')
        stream1.StartStatelessTraffic()
        log.info('Waiting {}secs to start the traffic'.format(traffic_start_time))
        time.sleep(traffic_start_time)
        
        stream1.StopStatelessTraffic()
        log.info('Waiting {}secs to stop the traffic'.format(traffic_stop_time))
        time.sleep(traffic_stop_time)
        
        with steps.start("checking mac learning for orphan mac"):
            if not verify_mac_on_vteps([prim_vtep, sec_vtep, sa_vtep], '1001', 1025, prim_mac):
                log.error("Mac learning failed for orphan mac")
                self.failed("Mac learning failed for orphan mac")

        with steps.start("checking mac learning for standalone mac"):
            if not verify_mac_on_vteps([prim_vtep, sec_vtep, sa_vtep], '1002', 1025, sa_mac):
                log.error("Mac learning failed for standalone mac")
                self.failed("Mac learning failed for standalone mac")

        with steps.start('Verify Learned mac address consistency between hardware and software'):
            if verify_mac_cc_between_hardware_software([prim_vtep, sec_vtep, sa_vtep]):
                log.info('MAC CC success')
            else:
                self.failed('MAC CC failed')

        with steps.start("Verify Steady State"):
            if VerifyTraffic("TC_VXLAN_PVMAP_040", testscript, traffic_item='Trunk Orphan To Standalone'):
                log.info('Verify traffic success')
            else:
                self.failed('Verify traffic failed') 

    @aetest.test
    def verify_error_cores(self, testscript, testbed, steps):
        sa_vtep         = testscript.parameters['LEAF-3']
        prim_vtep       = testscript.parameters['LEAF-1']
        sec_vtep        = testscript.parameters['LEAF-2']
        ixNetwork       = testscript.parameters['ixNetwork']

        with steps.start("Stopping hosts..."):
            ixNetwork.StopAllProtocols()

        log.info('Waiting {}secs'.format(traffic_stop_time))
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

# =====================================================================================================#
# TC-ID: TC_VXLAN_PVMAP_041 - Reload
# Testcase:  
#   - Reload device - traffic between orphan and standalone
#   - Check mac learning and traffic
# ======================================================================================================#
class TC_VXLAN_PVMAP_041(aetest.Testcase):
    @aetest.test
    def testcase_orphan_reload_standalone(self, testscript, steps):
        sa_vtep         = testscript.parameters['LEAF-3']
        prim_vtep       = testscript.parameters['LEAF-1']
        sec_vtep        = testscript.parameters['LEAF-2']
        prim_mac        = str(testscript.parameters['PVMAP_Dict']['prim_orphan_mac'])
        sa_mac          = str(testscript.parameters['PVMAP_Dict']['sa_mac'])
        p1_handle       = testscript.parameters['orphan1_handle']
        p2_handle       = testscript.parameters['sa_handle']
        ixNetwork       = testscript.parameters['ixNetwork']

        with steps.start("Starting hosts..."):
            p1_handle.Start()
            p2_handle.Start()
        
        log.info('Waiting {}secs to start hosts'.format(host_start_time))
        time.sleep(host_start_time)

        stream1 = ixNetwork.Traffic.TrafficItem.find(Name='Trunk Orphan To Standalone')
        stream1.StartStatelessTraffic()
        log.info('Waiting {}secs to start the traffic'.format(traffic_start_time))
        time.sleep(traffic_start_time)
        
        with steps.start("checking mac learning for orphan mac"):
            if not verify_mac_on_vteps([prim_vtep, sec_vtep, sa_vtep], '1001', 1025, prim_mac):
                log.error("Mac learning failed for orphan mac")
                self.failed("Mac learning failed for orphan mac")

        with steps.start("Checking mac learning for standalone mac"):
            if not verify_mac_on_vteps([prim_vtep, sec_vtep, sa_vtep], '1002', 1025, sa_mac):
                log.error("Mac learning failed for standalone mac")
                self.failed("Mac learning failed for standalone mac")

        with steps.start('Reload Standalone'):            
            result = infraTrig.switchReload(sa_vtep)
            if result:
                log.info("Reload completed Successfully")
            else:
                log.debug("Reload Failed")
                self.failed("Reload Failed")
            
        log.info("Waiting for 340 sec for the topology to come UP")
        time.sleep(340)

        # Verify NVE Peers with new IP
        nvePeerData = verifyEVPNNvePeers(testscript.parameters['leavesDict'])

        if nvePeerData['result'] is 1:
            log.info("PASS : Successfully verified NVE Peering\n\n")
        else:
            log.error("FAIL : Failed to verify NVE Peering\n\n")
            self.failed(reason=nvePeerData['log'])
    
        with steps.start("checking mac learning for orphan mac"):
            if not verify_mac_on_vteps([prim_vtep, sec_vtep, sa_vtep], '1001', 1025, prim_mac):
                log.error("Mac learning failed for orphan mac")
                self.failed("Mac learning failed for orphan mac")

        with steps.start("checking mac learning for standalone mac"):
            if not verify_mac_on_vteps([prim_vtep, sec_vtep, sa_vtep], '1002', 1025, sa_mac):
                log.error("Mac learning failed for standalone mac")
                self.failed("Mac learning failed for standalone mac")

        with steps.start('Verify Learned mac address consistency between hardware and software'):
            if verify_mac_cc_between_hardware_software([prim_vtep, sec_vtep, sa_vtep]):
                log.info('MAC CC success')
            else:
                self.failed('MAC CC failed')

        stream1.StopStatelessTraffic()
        log.info('Waiting {}secs to stop the traffic'.format(traffic_stop_time))
        time.sleep(traffic_stop_time)

        with steps.start("Verify Steady State"):
            if VerifyTraffic("TC_VXLAN_PVMAP_041", testscript, traffic_item='Trunk Orphan To Standalone'):
                log.info('Verify traffic success')
            else:
                self.failed('Verify traffic failed') 

    @aetest.test
    def testcase_orphan_reload_primary(self, testscript, steps):
        sa_vtep         = testscript.parameters['LEAF-3']
        prim_vtep       = testscript.parameters['LEAF-1']
        sec_vtep        = testscript.parameters['LEAF-2']
        prim_mac        = str(testscript.parameters['PVMAP_Dict']['prim_orphan_mac'])
        sa_mac          = str(testscript.parameters['PVMAP_Dict']['sa_mac'])
        p1_handle       = testscript.parameters['orphan1_handle']
        p2_handle       = testscript.parameters['sa_handle']
        ixNetwork       = testscript.parameters['ixNetwork']

        with steps.start("Starting hosts..."):
            p1_handle.Start()
            p2_handle.Start()
        
        log.info('Waiting {}secs to start hosts'.format(host_start_time))
        time.sleep(host_start_time)

        stream1 = ixNetwork.Traffic.TrafficItem.find(Name='Trunk Orphan To Standalone')
        stream1.StartStatelessTraffic()
        log.info('Waiting {}secs to start the traffic'.format(traffic_start_time))
        time.sleep(traffic_start_time)
        
        with steps.start("checking mac learning for orphan mac"):
            if not verify_mac_on_vteps([prim_vtep, sec_vtep, sa_vtep], '1001', 1025, prim_mac):
                log.error("Mac learning failed for orphan mac")
                self.failed("Mac learning failed for orphan mac")

        with steps.start("Checking mac learning for standalone mac"):
            if not verify_mac_on_vteps([prim_vtep, sec_vtep, sa_vtep], '1002', 1025, sa_mac):
                log.error("Mac learning failed for standalone mac")
                self.failed("Mac learning failed for standalone mac")
        
        primary_handle = get_vpc_primary_secondary_device([prim_vtep, sec_vtep])
        with steps.start('Reload Primary'):            
            result = infraTrig.switchReload(primary_handle)
            if result:
                log.info("Reload completed Successfully")
            else:
                log.debug("Reload Failed")
                self.failed("Reload Failed")
            
        log.info("Waiting for 340 sec for the topology to come UP")
        time.sleep(340)

        # Verify NVE Peers with new IP
        nvePeerData = verifyEVPNNvePeers(testscript.parameters['leavesDict'])

        if nvePeerData['result'] is 1:
            log.info("PASS : Successfully verified NVE Peering\n\n")
        else:
            log.error("FAIL : Failed to verify NVE Peering\n\n")
            self.failed(reason=nvePeerData['log'])

        with steps.start("checking mac learning for orphan mac"):
            if not verify_mac_on_vteps([prim_vtep, sec_vtep, sa_vtep], '1001', 1025, prim_mac):
                log.error("Mac learning failed for orphan mac")
                self.failed("Mac learning failed for orphan mac")

        with steps.start("checking mac learning for standalone mac"):
            if not verify_mac_on_vteps([prim_vtep, sec_vtep, sa_vtep], '1002', 1025, sa_mac):
                log.error("Mac learning failed for standalone mac")
                self.failed("Mac learning failed for standalone mac")

        with steps.start('Verify Learned mac address consistency between hardware and software'):
            if verify_mac_cc_between_hardware_software([prim_vtep, sec_vtep, sa_vtep]):
                log.info('MAC CC success')
            else:
                self.failed('MAC CC failed')

        stream1.StopStatelessTraffic()
        log.info('Waiting {}secs to stop the traffic'.format(traffic_stop_time))
        time.sleep(traffic_stop_time)

        with steps.start("Verify Steady State"):
            if VerifyTraffic("TC_VXLAN_PVMAP_041", testscript, traffic_item='Trunk Orphan To Standalone'):
                log.info('Verify traffic success')
            else:
                self.failed('Verify traffic failed') 

    @aetest.test
    def testcase_orphan_reload_new_primary(self, testscript, steps):
        sa_vtep         = testscript.parameters['LEAF-3']
        prim_vtep       = testscript.parameters['LEAF-1']
        sec_vtep        = testscript.parameters['LEAF-2']
        prim_mac        = str(testscript.parameters['PVMAP_Dict']['prim_orphan_mac'])
        sa_mac          = str(testscript.parameters['PVMAP_Dict']['sa_mac'])
        p1_handle       = testscript.parameters['orphan1_handle']
        p2_handle       = testscript.parameters['sa_handle']
        ixNetwork       = testscript.parameters['ixNetwork']

        with steps.start("Starting hosts..."):
            p1_handle.Start()
            p2_handle.Start()
        
        log.info('Waiting {}secs to start hosts'.format(host_start_time))
        time.sleep(host_start_time)

        stream1 = ixNetwork.Traffic.TrafficItem.find(Name='Trunk Orphan To Standalone')
        stream1.StartStatelessTraffic()
        log.info('Waiting {}secs to start the traffic'.format(traffic_start_time))
        time.sleep(traffic_start_time)
        
        with steps.start("checking mac learning for orphan mac"):
            if not verify_mac_on_vteps([prim_vtep, sec_vtep, sa_vtep], '1001', 1025, prim_mac):
                log.error("Mac learning failed for orphan mac")
                self.failed("Mac learning failed for orphan mac")

        with steps.start("Checking mac learning for standalone mac"):
            if not verify_mac_on_vteps([prim_vtep, sec_vtep, sa_vtep], '1002', 1025, sa_mac):
                log.error("Mac learning failed for standalone mac")
                self.failed("Mac learning failed for standalone mac")
        
        primary_handle = get_vpc_primary_secondary_device([prim_vtep, sec_vtep])
        with steps.start('Reload new primary'):            
            result = infraTrig.switchReload(primary_handle)
            if result:
                log.info("Reload completed Successfully")
            else:
                log.debug("Reload Failed")
                self.failed("Reload Failed")
            
        log.info("Waiting for 340 sec for the topology to come UP")
        time.sleep(340)

        # Verify NVE Peers with new IP
        nvePeerData = verifyEVPNNvePeers(testscript.parameters['leavesDict'])

        if nvePeerData['result'] is 1:
            log.info("PASS : Successfully verified NVE Peering\n\n")
        else:
            log.error("FAIL : Failed to verify NVE Peering\n\n")
            self.failed(reason=nvePeerData['log'])
    
        with steps.start("checking mac learning for orphan mac"):
            if not verify_mac_on_vteps([prim_vtep, sec_vtep, sa_vtep], '1001', 1025, prim_mac):
                log.error("Mac learning failed for orphan mac")
                self.failed("Mac learning failed for orphan mac")

        with steps.start("checking mac learning for standalone mac"):
            if not verify_mac_on_vteps([prim_vtep, sec_vtep, sa_vtep], '1002', 1025, sa_mac):
                log.error("Mac learning failed for standalone mac")
                self.failed("Mac learning failed for standalone mac")

        with steps.start('Verify Learned mac address consistency between hardware and software'):
            if verify_mac_cc_between_hardware_software([prim_vtep, sec_vtep, sa_vtep]):
                log.info('MAC CC success')
            else:
                self.failed('MAC CC failed')

        stream1.StopStatelessTraffic()
        log.info('Waiting {}secs to stop the traffic'.format(traffic_stop_time))
        time.sleep(traffic_stop_time)

        with steps.start("Verify Steady State"):
            if VerifyTraffic("TC_VXLAN_PVMAP_041", testscript, traffic_item='Trunk Orphan To Standalone'):
                log.info('Verify traffic success')
            else:
                self.failed('Verify traffic failed') 
    
    @aetest.test
    def verify_error_cores(self, testscript, testbed, steps):
        sa_vtep         = testscript.parameters['LEAF-3']
        prim_vtep       = testscript.parameters['LEAF-1']
        sec_vtep        = testscript.parameters['LEAF-2']
        ixNetwork       = testscript.parameters['ixNetwork']

        with steps.start("Stopping hosts..."):
            ixNetwork.StopAllProtocols()

        log.info('Waiting {}secs'.format(traffic_stop_time))
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

# =====================================================================================================#
# TC-ID: TC_VXLAN_PVMAP_042 - Triggers - Reload
# Testcase:  
#   - Reload device - traffic between orphan and standalone
#   - Check mac learning and traffic
# ======================================================================================================#
class TC_VXLAN_PVMAP_042(aetest.Testcase):
    @aetest.test
    def testcase_vpc_reload_primary(self, testscript, steps):
        sa_vtep         = testscript.parameters['LEAF-3']
        prim_vtep       = testscript.parameters['LEAF-1']
        sec_vtep        = testscript.parameters['LEAF-2']
        prim_mac        = str(testscript.parameters['PVMAP_Dict']['prim_vpc_mac'])
        sa_mac          = str(testscript.parameters['PVMAP_Dict']['sa_mac'])
        p1_handle       = testscript.parameters['vpc_handle']
        p2_handle       = testscript.parameters['sa_handle']
        ixNetwork       = testscript.parameters['ixNetwork']

        with steps.start("Starting hosts..."):
            p1_handle.Start()
            p2_handle.Start()
        
        log.info('Waiting {}secs to start hosts'.format(host_start_time))
        time.sleep(host_start_time)

        stream1 = ixNetwork.Traffic.TrafficItem.find(Name='Trunk VPC To Standalone')
        stream1.StartStatelessTraffic()
        log.info('Waiting {}secs to start the traffic'.format(traffic_start_time))
        time.sleep(traffic_start_time)
        
        with steps.start("checking mac learning for vpc mac"):
            if not verify_mac_on_vteps([prim_vtep, sec_vtep, sa_vtep], '1001', 1025, prim_mac):
                log.error("Mac learning failed for vpc mac")
                self.failed("Mac learning failed for vpc mac")

        with steps.start("Checking mac learning for standalone mac"):
            if not verify_mac_on_vteps([prim_vtep, sec_vtep, sa_vtep], '1002', 1025, sa_mac):
                log.error("Mac learning failed for standalone mac")
                self.failed("Mac learning failed for standalone mac")
        
        primary_handle = get_vpc_primary_secondary_device([prim_vtep, sec_vtep])
        with steps.start('Reload primary'):            
            result = infraTrig.switchReload(primary_handle)
            if result:
                log.info("Reload completed Successfully")
            else:
                log.debug("Reload Failed")
                self.failed("Reload Failed")
            
        log.info("Waiting for 340 sec for the topology to come UP")
        time.sleep(340)

        # Verify NVE Peers with new IP
        nvePeerData = verifyEVPNNvePeers(testscript.parameters['leavesDict'])

        if nvePeerData['result'] is 1:
            log.info("PASS : Successfully verified NVE Peering\n\n")
        else:
            log.error("FAIL : Failed to verify NVE Peering\n\n")
            self.failed(reason=nvePeerData['log'])
    
        with steps.start("checking mac learning for vpc mac"):
            if not verify_mac_on_vteps([prim_vtep, sec_vtep, sa_vtep], '1001', 1025, prim_mac):
                log.error("Mac learning failed for vpc mac")
                self.failed("Mac learning failed for vpc mac")

        with steps.start("checking mac learning for standalone mac"):
            if not verify_mac_on_vteps([prim_vtep, sec_vtep, sa_vtep], '1002', 1025, sa_mac):
                log.error("Mac learning failed for standalone mac")
                self.failed("Mac learning failed for standalone mac")

        with steps.start('Verify Learned mac address consistency between hardware and software'):
            if verify_mac_cc_between_hardware_software([prim_vtep, sec_vtep, sa_vtep]):
                log.info('MAC CC success')
            else:
                self.failed('MAC CC failed')

        stream1.StopStatelessTraffic()
        log.info('Waiting {}secs to stop the traffic'.format(traffic_stop_time))
        time.sleep(traffic_stop_time)

        with steps.start("Verify Steady State"):
            if VerifyTraffic("TC_VXLAN_PVMAP_042", testscript, traffic_item='Trunk VPC To Standalone'):
                log.info('Verify traffic success')
            else:
                self.failed('Verify traffic failed') 

    @aetest.test
    def testcase_vpc_reload_new_primary(self, testscript, steps):
        sa_vtep         = testscript.parameters['LEAF-3']
        prim_vtep       = testscript.parameters['LEAF-1']
        sec_vtep        = testscript.parameters['LEAF-2']
        prim_mac        = str(testscript.parameters['PVMAP_Dict']['prim_vpc_mac'])
        sa_mac          = str(testscript.parameters['PVMAP_Dict']['sa_mac'])
        p1_handle       = testscript.parameters['vpc_handle']
        p2_handle       = testscript.parameters['sa_handle']
        ixNetwork       = testscript.parameters['ixNetwork']

        with steps.start("Starting hosts..."):
            p1_handle.Start()
            p2_handle.Start()
        
        log.info('Waiting {}secs to start hosts'.format(host_start_time))
        time.sleep(host_start_time)

        stream1 = ixNetwork.Traffic.TrafficItem.find(Name='Trunk VPC To Standalone')
        stream1.StartStatelessTraffic()
        log.info('Waiting {}secs to start the traffic'.format(traffic_start_time))
        time.sleep(traffic_start_time)
        
        with steps.start("checking mac learning for vpc mac"):
            if not verify_mac_on_vteps([prim_vtep, sec_vtep, sa_vtep], '1001', 1025, prim_mac):
                log.error("Mac learning failed for vpc mac")
                self.failed("Mac learning failed for vpc mac")

        with steps.start("Checking mac learning for standalone mac"):
            if not verify_mac_on_vteps([prim_vtep, sec_vtep, sa_vtep], '1002', 1025, sa_mac):
                log.error("Mac learning failed for standalone mac")
                self.failed("Mac learning failed for standalone mac")
        
        primary_handle = get_vpc_primary_secondary_device([prim_vtep, sec_vtep])
        with steps.start('Reload new primary'):            
            result = infraTrig.switchReload(primary_handle)
            if result:
                log.info("Reload completed Successfully")
            else:
                log.debug("Reload Failed")
                self.failed("Reload Failed")
            
        log.info("Waiting for 340 sec for the topology to come UP")
        time.sleep(340)

        # Verify NVE Peers with new IP
        nvePeerData = verifyEVPNNvePeers(testscript.parameters['leavesDict'])

        if nvePeerData['result'] is 1:
            log.info("PASS : Successfully verified NVE Peering\n\n")
        else:
            log.error("FAIL : Failed to verify NVE Peering\n\n")
            self.failed(reason=nvePeerData['log'])
    
        with steps.start("checking mac learning for vpc mac"):
            if not verify_mac_on_vteps([prim_vtep, sec_vtep, sa_vtep], '1001', 1025, prim_mac):
                log.error("Mac learning failed for vpc mac")
                self.failed("Mac learning failed for vpc mac")

        with steps.start("checking mac learning for standalone mac"):
            if not verify_mac_on_vteps([prim_vtep, sec_vtep, sa_vtep], '1002', 1025, sa_mac):
                log.error("Mac learning failed for standalone mac")
                self.failed("Mac learning failed for standalone mac")

        with steps.start('Verify Learned mac address consistency between hardware and software'):
            if verify_mac_cc_between_hardware_software([prim_vtep, sec_vtep, sa_vtep]):
                log.info('MAC CC success')
            else:
                self.failed('MAC CC failed')

        stream1.StopStatelessTraffic()
        log.info('Waiting {}secs to stop the traffic'.format(traffic_stop_time))
        time.sleep(traffic_stop_time)

        with steps.start("Verify Steady State"):
            if VerifyTraffic("TC_VXLAN_PVMAP_042", testscript, traffic_item='Trunk VPC To Standalone'):
                log.info('Verify traffic success')
            else:
                self.failed('Verify traffic failed') 
    
    @aetest.test
    def verify_error_cores(self, testscript, testbed, steps):
        sa_vtep         = testscript.parameters['LEAF-3']
        prim_vtep       = testscript.parameters['LEAF-1']
        sec_vtep        = testscript.parameters['LEAF-2']
        ixNetwork       = testscript.parameters['ixNetwork']

        with steps.start("Stopping hosts..."):
            ixNetwork.StopAllProtocols()

        log.info('Waiting {}secs'.format(traffic_stop_time))
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

# =====================================================================================================#
# TC-ID: TC_VXLAN_PVMAP_043 - Reload
# Testcase:  
#   - ASCII Reload device - traffic between orphan and standalone
#   - Check mac learning and traffic
# ======================================================================================================#
class TC_VXLAN_PVMAP_043(aetest.Testcase):
    @aetest.test
    def testcase_ascii_orphan_reload_standalone(self, testscript, steps):
        sa_vtep         = testscript.parameters['LEAF-3']
        prim_vtep       = testscript.parameters['LEAF-1']
        sec_vtep        = testscript.parameters['LEAF-2']
        prim_mac        = str(testscript.parameters['PVMAP_Dict']['prim_orphan_mac'])
        sa_mac          = str(testscript.parameters['PVMAP_Dict']['sa_mac'])
        p1_handle       = testscript.parameters['orphan1_handle']
        p2_handle       = testscript.parameters['sa_handle']
        ixNetwork       = testscript.parameters['ixNetwork']

        with steps.start("Starting hosts..."):
            p1_handle.Start()
            p2_handle.Start()
        
        log.info('Waiting {}secs to start hosts'.format(host_start_time))
        time.sleep(host_start_time)

        stream1 = ixNetwork.Traffic.TrafficItem.find(Name='Trunk Orphan To Standalone')
        stream1.StartStatelessTraffic()
        log.info('Waiting {}secs to start the traffic'.format(traffic_start_time))
        time.sleep(traffic_start_time)
        
        with steps.start("checking mac learning for orphan mac"):
            if not verify_mac_on_vteps([prim_vtep, sec_vtep, sa_vtep], '1001', 1025, prim_mac):
                log.error("Mac learning failed for orphan mac")
                self.failed("Mac learning failed for orphan mac")

        with steps.start("Checking mac learning for standalone mac"):
            if not verify_mac_on_vteps([prim_vtep, sec_vtep, sa_vtep], '1002', 1025, sa_mac):
                log.error("Mac learning failed for standalone mac")
                self.failed("Mac learning failed for standalone mac")

        with steps.start('Reload Standalone'):            
            result = infraTrig.switchASCIIreload(sa_vtep)
            if result:
                log.info("Reload completed Successfully")
            else:
                log.debug("Reload Failed")
                self.failed("Reload Failed")
            
        log.info("Waiting for 340 sec for the topology to come UP")
        time.sleep(340)

        # Verify NVE Peers with new IP
        nvePeerData = verifyEVPNNvePeers(testscript.parameters['leavesDict'])

        if nvePeerData['result'] is 1:
            log.info("PASS : Successfully verified NVE Peering\n\n")
        else:
            log.error("FAIL : Failed to verify NVE Peering\n\n")
            self.failed(reason=nvePeerData['log'])
    
        with steps.start("checking mac learning for orphan mac"):
            if not verify_mac_on_vteps([prim_vtep, sec_vtep, sa_vtep], '1001', 1025, prim_mac):
                log.error("Mac learning failed for orphan mac")
                self.failed("Mac learning failed for orphan mac")

        with steps.start("checking mac learning for standalone mac"):
            if not verify_mac_on_vteps([prim_vtep, sec_vtep, sa_vtep], '1002', 1025, sa_mac):
                log.error("Mac learning failed for standalone mac")
                self.failed("Mac learning failed for standalone mac")

        with steps.start('Verify Learned mac address consistency between hardware and software'):
            if verify_mac_cc_between_hardware_software([prim_vtep, sec_vtep, sa_vtep]):
                log.info('MAC CC success')
            else:
                self.failed('MAC CC failed')

        stream1.StopStatelessTraffic()
        log.info('Waiting {}secs to stop the traffic'.format(traffic_stop_time))
        time.sleep(traffic_stop_time)

        with steps.start("Verify Steady State"):
            if VerifyTraffic("TC_VXLAN_PVMAP_043", testscript, traffic_item='Trunk Orphan To Standalone'):
                log.info('Verify traffic success')
            else:
                self.failed('Verify traffic failed') 

    @aetest.test
    def testcase_ascii_orphan_reload_primary(self, testscript, steps):
        sa_vtep         = testscript.parameters['LEAF-3']
        prim_vtep       = testscript.parameters['LEAF-1']
        sec_vtep        = testscript.parameters['LEAF-2']
        prim_mac        = str(testscript.parameters['PVMAP_Dict']['prim_orphan_mac'])
        sa_mac          = str(testscript.parameters['PVMAP_Dict']['sa_mac'])
        p1_handle       = testscript.parameters['orphan1_handle']
        p2_handle       = testscript.parameters['sa_handle']
        ixNetwork       = testscript.parameters['ixNetwork']

        with steps.start("Starting hosts..."):
            p1_handle.Start()
            p2_handle.Start()
        
        log.info('Waiting {}secs to start hosts'.format(host_start_time))
        time.sleep(host_start_time)

        stream1 = ixNetwork.Traffic.TrafficItem.find(Name='Trunk Orphan To Standalone')
        stream1.StartStatelessTraffic()
        log.info('Waiting {}secs to start the traffic'.format(traffic_start_time))
        time.sleep(traffic_start_time)
        
        with steps.start("checking mac learning for orphan mac"):
            if not verify_mac_on_vteps([prim_vtep, sec_vtep, sa_vtep], '1001', 1025, prim_mac):
                log.error("Mac learning failed for orphan mac")
                self.failed("Mac learning failed for orphan mac")

        with steps.start("Checking mac learning for standalone mac"):
            if not verify_mac_on_vteps([prim_vtep, sec_vtep, sa_vtep], '1002', 1025, sa_mac):
                log.error("Mac learning failed for standalone mac")
                self.failed("Mac learning failed for standalone mac")
        
        primary_handle = get_vpc_primary_secondary_device([prim_vtep, sec_vtep])
        with steps.start('Reload primary'):            
            result = infraTrig.switchASCIIreload(primary_handle)
            if result:
                log.info("Reload completed Successfully")
            else:
                log.debug("Reload Failed")
                self.failed("Reload Failed")
            
        log.info("Waiting for 340 sec for the topology to come UP")
        time.sleep(340)

        # Verify NVE Peers with new IP
        nvePeerData = verifyEVPNNvePeers(testscript.parameters['leavesDict'])

        if nvePeerData['result'] is 1:
            log.info("PASS : Successfully verified NVE Peering\n\n")
        else:
            log.error("FAIL : Failed to verify NVE Peering\n\n")
            self.failed(reason=nvePeerData['log'])

        with steps.start("checking mac learning for orphan mac"):
            if not verify_mac_on_vteps([prim_vtep, sec_vtep, sa_vtep], '1001', 1025, prim_mac):
                log.error("Mac learning failed for orphan mac")
                self.failed("Mac learning failed for orphan mac")

        with steps.start("checking mac learning for standalone mac"):
            if not verify_mac_on_vteps([prim_vtep, sec_vtep, sa_vtep], '1002', 1025, sa_mac):
                log.error("Mac learning failed for standalone mac")
                self.failed("Mac learning failed for standalone mac")

        with steps.start('Verify Learned mac address consistency between hardware and software'):
            if verify_mac_cc_between_hardware_software([prim_vtep, sec_vtep, sa_vtep]):
                log.info('MAC CC success')
            else:
                self.failed('MAC CC failed')

        stream1.StopStatelessTraffic()
        log.info('Waiting {}secs to stop the traffic'.format(traffic_stop_time))
        time.sleep(traffic_stop_time)

        with steps.start("Verify Steady State"):
            if VerifyTraffic("TC_VXLAN_PVMAP_043", testscript, traffic_item='Trunk Orphan To Standalone'):
                log.info('Verify traffic success')
            else:
                self.failed('Verify traffic failed') 

    @aetest.test
    def testcase_ascii_orphan_reload_new_primary(self, testscript, steps):
        sa_vtep         = testscript.parameters['LEAF-3']
        prim_vtep       = testscript.parameters['LEAF-1']
        sec_vtep        = testscript.parameters['LEAF-2']
        prim_mac        = str(testscript.parameters['PVMAP_Dict']['prim_orphan_mac'])
        sa_mac          = str(testscript.parameters['PVMAP_Dict']['sa_mac'])
        p1_handle       = testscript.parameters['orphan1_handle']
        p2_handle       = testscript.parameters['sa_handle']
        ixNetwork       = testscript.parameters['ixNetwork']

        with steps.start("Starting hosts..."):
            p1_handle.Start()
            p2_handle.Start()
        
        log.info('Waiting {}secs to start hosts'.format(host_start_time))
        time.sleep(host_start_time)

        stream1 = ixNetwork.Traffic.TrafficItem.find(Name='Trunk Orphan To Standalone')
        stream1.StartStatelessTraffic()
        log.info('Waiting {}secs to start the traffic'.format(traffic_start_time))
        time.sleep(traffic_start_time)
        
        with steps.start("checking mac learning for orphan mac"):
            if not verify_mac_on_vteps([prim_vtep, sec_vtep, sa_vtep], '1001', 1025, prim_mac):
                log.error("Mac learning failed for orphan mac")
                self.failed("Mac learning failed for orphan mac")

        with steps.start("Checking mac learning for standalone mac"):
            if not verify_mac_on_vteps([prim_vtep, sec_vtep, sa_vtep], '1002', 1025, sa_mac):
                log.error("Mac learning failed for standalone mac")
                self.failed("Mac learning failed for standalone mac")
        
        primary_handle = get_vpc_primary_secondary_device([prim_vtep, sec_vtep])
        with steps.start('Reload new primary'):            
            result = infraTrig.switchASCIIreload(primary_handle)
            if result:
                log.info("Reload completed Successfully")
            else:
                log.debug("Reload Failed")
                self.failed("Reload Failed")
            
        log.info("Waiting for 340 sec for the topology to come UP")
        time.sleep(340)

        # Verify NVE Peers with new IP
        nvePeerData = verifyEVPNNvePeers(testscript.parameters['leavesDict'])

        if nvePeerData['result'] is 1:
            log.info("PASS : Successfully verified NVE Peering\n\n")
        else:
            log.error("FAIL : Failed to verify NVE Peering\n\n")
            self.failed(reason=nvePeerData['log'])
    
        with steps.start("checking mac learning for orphan mac"):
            if not verify_mac_on_vteps([prim_vtep, sec_vtep, sa_vtep], '1001', 1025, prim_mac):
                log.error("Mac learning failed for orphan mac")
                self.failed("Mac learning failed for orphan mac")

        with steps.start("checking mac learning for standalone mac"):
            if not verify_mac_on_vteps([prim_vtep, sec_vtep, sa_vtep], '1002', 1025, sa_mac):
                log.error("Mac learning failed for standalone mac")
                self.failed("Mac learning failed for standalone mac")

        with steps.start('Verify Learned mac address consistency between hardware and software'):
            if verify_mac_cc_between_hardware_software([prim_vtep, sec_vtep, sa_vtep]):
                log.info('MAC CC success')
            else:
                self.failed('MAC CC failed')

        stream1.StopStatelessTraffic()
        log.info('Waiting {}secs to stop the traffic'.format(traffic_stop_time))
        time.sleep(traffic_stop_time)

        with steps.start("Verify Steady State"):
            if VerifyTraffic("TC_VXLAN_PVMAP_043", testscript, traffic_item='Trunk Orphan To Standalone'):
                log.info('Verify traffic success')
            else:
                self.failed('Verify traffic failed') 
    
    @aetest.test
    def verify_error_cores(self, testscript, testbed, steps):
        sa_vtep         = testscript.parameters['LEAF-3']
        prim_vtep       = testscript.parameters['LEAF-1']
        sec_vtep        = testscript.parameters['LEAF-2']
        ixNetwork       = testscript.parameters['ixNetwork']

        with steps.start("Stopping hosts..."):
            ixNetwork.StopAllProtocols()

        log.info('Waiting {}secs'.format(traffic_stop_time))
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

# =====================================================================================================#
# TC-ID: TC_VXLAN_PVMAP_044 - Reload
# Testcase:  
#   - ASCII Reload device - traffic between VPC and standalone
#   - Check mac learning and traffic
# ======================================================================================================#
class TC_VXLAN_PVMAP_044(aetest.Testcase):
    @aetest.test
    def testcase_ascii_vpc_reload_primary(self, testscript, steps):
        sa_vtep         = testscript.parameters['LEAF-3']
        prim_vtep       = testscript.parameters['LEAF-1']
        sec_vtep        = testscript.parameters['LEAF-2']
        prim_mac        = str(testscript.parameters['PVMAP_Dict']['prim_vpc_mac'])
        sa_mac          = str(testscript.parameters['PVMAP_Dict']['sa_mac'])
        p1_handle       = testscript.parameters['vpc_handle']
        p2_handle       = testscript.parameters['sa_handle']
        ixNetwork       = testscript.parameters['ixNetwork']

        with steps.start("Starting hosts..."):
            p1_handle.Start()
            p2_handle.Start()
        
        log.info('Waiting {}secs to start hosts'.format(host_start_time))
        time.sleep(host_start_time)

        stream1 = ixNetwork.Traffic.TrafficItem.find(Name='Trunk VPC To Standalone')
        stream1.StartStatelessTraffic()
        log.info('Waiting {}secs to start the traffic'.format(traffic_start_time))
        time.sleep(traffic_start_time)
        
        with steps.start("checking mac learning for vpc mac"):
            if not verify_mac_on_vteps([prim_vtep, sec_vtep, sa_vtep], '1001', 1025, prim_mac):
                log.error("Mac learning failed for vpc mac")
                self.failed("Mac learning failed for vpc mac")

        with steps.start("Checking mac learning for standalone mac"):
            if not verify_mac_on_vteps([prim_vtep, sec_vtep, sa_vtep], '1002', 1025, sa_mac):
                log.error("Mac learning failed for standalone mac")
                self.failed("Mac learning failed for standalone mac")
        
        primary_handle = get_vpc_primary_secondary_device([prim_vtep, sec_vtep])
        with steps.start('Reload primary'):            
            result = infraTrig.switchASCIIreload(primary_handle)
            if result:
                log.info("Reload completed Successfully")
            else:
                log.debug("Reload Failed")
                self.failed("Reload Failed")
            
        log.info("Waiting for 500 sec for the topology to come UP")
        time.sleep(500)

        # Verify NVE Peers with new IP
        nvePeerData = verifyEVPNNvePeers(testscript.parameters['leavesDict'])

        if nvePeerData['result'] is 1:
            log.info("PASS : Successfully verified NVE Peering\n\n")
        else:
            log.error("FAIL : Failed to verify NVE Peering\n\n")
            self.failed(reason=nvePeerData['log'])
    
        with steps.start("checking mac learning for vpc mac"):
            if not verify_mac_on_vteps([prim_vtep, sec_vtep, sa_vtep], '1001', 1025, prim_mac):
                log.error("Mac learning failed for vpc mac")
                self.failed("Mac learning failed for vpc mac")

        with steps.start("checking mac learning for standalone mac"):
            if not verify_mac_on_vteps([prim_vtep, sec_vtep, sa_vtep], '1002', 1025, sa_mac):
                log.error("Mac learning failed for standalone mac")
                self.failed("Mac learning failed for standalone mac")

        with steps.start('Verify Learned mac address consistency between hardware and software'):
            if verify_mac_cc_between_hardware_software([prim_vtep, sec_vtep, sa_vtep]):
                log.info('MAC CC success')
            else:
                self.failed('MAC CC failed')

        stream1.StopStatelessTraffic()
        log.info('Waiting {}secs to stop the traffic'.format(traffic_stop_time))
        time.sleep(traffic_stop_time)

        with steps.start("Verify Steady State"):
            if VerifyTraffic("TC_VXLAN_PVMAP_044", testscript, traffic_item='Trunk VPC To Standalone'):
                log.info('Verify traffic success')
            else:
                self.failed('Verify traffic failed') 

    @aetest.test
    def testcase_ascii_vpc_reload_new_primary(self, testscript, steps):
        sa_vtep         = testscript.parameters['LEAF-3']
        prim_vtep       = testscript.parameters['LEAF-1']
        sec_vtep        = testscript.parameters['LEAF-2']
        prim_mac        = str(testscript.parameters['PVMAP_Dict']['prim_vpc_mac'])
        sa_mac          = str(testscript.parameters['PVMAP_Dict']['sa_mac'])
        p1_handle       = testscript.parameters['vpc_handle']
        p2_handle       = testscript.parameters['sa_handle']
        ixNetwork       = testscript.parameters['ixNetwork']

        with steps.start("Starting hosts..."):
            p1_handle.Start()
            p2_handle.Start()
        
        log.info('Waiting {}secs to start hosts'.format(host_start_time))
        time.sleep(host_start_time)

        stream1 = ixNetwork.Traffic.TrafficItem.find(Name='Trunk VPC To Standalone')
        stream1.StartStatelessTraffic()
        log.info('Waiting {}secs to start the traffic'.format(traffic_start_time))
        time.sleep(traffic_start_time)
        
        with steps.start("checking mac learning for vpc mac"):
            if not verify_mac_on_vteps([prim_vtep, sec_vtep, sa_vtep], '1001', 1025, prim_mac):
                log.error("Mac learning failed for vpc mac")
                self.failed("Mac learning failed for vpc mac")

        with steps.start("Checking mac learning for standalone mac"):
            if not verify_mac_on_vteps([prim_vtep, sec_vtep, sa_vtep], '1002', 1025, sa_mac):
                log.error("Mac learning failed for standalone mac")
                self.failed("Mac learning failed for standalone mac")
        
        primary_handle = get_vpc_primary_secondary_device([prim_vtep, sec_vtep])
        with steps.start('Reload new primary'):            
            result = infraTrig.switchASCIIreload(primary_handle)
            if result:
                log.info("Reload completed Successfully")
            else:
                log.debug("Reload Failed")
                self.failed("Reload Failed")
            
        log.info("Waiting for 500 sec for the topology to come UP")
        time.sleep(500)

        # Verify NVE Peers with new IP
        nvePeerData = verifyEVPNNvePeers(testscript.parameters['leavesDict'])

        if nvePeerData['result'] is 1:
            log.info("PASS : Successfully verified NVE Peering\n\n")
        else:
            log.error("FAIL : Failed to verify NVE Peering\n\n")
            self.failed(reason=nvePeerData['log'])
    
        with steps.start("checking mac learning for vpc mac"):
            if not verify_mac_on_vteps([prim_vtep, sec_vtep, sa_vtep], '1001', 1025, prim_mac):
                log.error("Mac learning failed for vpc mac")
                self.failed("Mac learning failed for vpc mac")

        with steps.start("checking mac learning for standalone mac"):
            if not verify_mac_on_vteps([prim_vtep, sec_vtep, sa_vtep], '1002', 1025, sa_mac):
                log.error("Mac learning failed for standalone mac")
                self.failed("Mac learning failed for standalone mac")

        with steps.start('Verify Learned mac address consistency between hardware and software'):
            if verify_mac_cc_between_hardware_software([prim_vtep, sec_vtep, sa_vtep]):
                log.info('MAC CC success')
            else:
                self.failed('MAC CC failed')

        stream1.StopStatelessTraffic()
        log.info('Waiting {}secs to stop the traffic'.format(traffic_stop_time))
        time.sleep(traffic_stop_time)

        with steps.start("Verify Steady State"):
            if VerifyTraffic("TC_VXLAN_PVMAP_044", testscript, traffic_item='Trunk VPC To Standalone'):
                log.info('Verify traffic success')
            else:
                self.failed('Verify traffic failed')

    @aetest.test
    def verify_error_cores(self, testscript, testbed, steps):
        sa_vtep         = testscript.parameters['LEAF-3']
        prim_vtep       = testscript.parameters['LEAF-1']
        sec_vtep        = testscript.parameters['LEAF-2']
        ixNetwork       = testscript.parameters['ixNetwork']

        with steps.start("Stopping hosts..."):
            ixNetwork.StopAllProtocols()

        log.info('Waiting {}secs'.format(traffic_stop_time))
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

# =====================================================================================================#
# TC-ID: TC_VXLAN_PVMAP_045 - VPC role change
# Testcase:  
#   - Change primary role to secondary 
#   - Check mac learning and traffic
#   - Change new primary role to secondary
#   - Check mac learning and traffic
# ======================================================================================================#
class TC_VXLAN_PVMAP_045(aetest.Testcase):
    @aetest.test
    def testcase_vpc_role_change(self, testscript, steps):
        sa_vtep         = testscript.parameters['LEAF-3']
        prim_vtep       = testscript.parameters['LEAF-1']
        sec_vtep        = testscript.parameters['LEAF-2']
        prim_mac        = str(testscript.parameters['PVMAP_Dict']['prim_vpc_mac'])
        sa_mac          = str(testscript.parameters['PVMAP_Dict']['sa_mac'])
        domain          = str(testscript.parameters['LEAF_2_dict']['VPC_data']['domain_id'])
        p1_handle       = testscript.parameters['vpc_handle']
        p2_handle       = testscript.parameters['sa_handle']
        ixNetwork       = testscript.parameters['ixNetwork']

        with steps.start("Starting hosts..."):
            p1_handle.Start()
            p2_handle.Start()
        
        log.info('Waiting {}secs to start hosts'.format(host_start_time))
        time.sleep(host_start_time)

        stream1 = ixNetwork.Traffic.TrafficItem.find(Name='Trunk VPC To Standalone')
        stream1.StartStatelessTraffic()
        log.info('Waiting {}secs to start the traffic'.format(traffic_start_time))
        time.sleep(traffic_start_time)
        
        stream1.StopStatelessTraffic()
        log.info('Waiting {}secs to stop the traffic'.format(traffic_stop_time))
        time.sleep(traffic_stop_time)

        with steps.start("checking mac learning for vpc mac"):
            if not verify_mac_on_vteps([prim_vtep, sec_vtep, sa_vtep], '1001', 1025, prim_mac):
                log.error("Mac learning failed for vpc mac")
                self.failed("Mac learning failed for vpc mac")

        with steps.start("Checking mac learning for standalone mac"):
            if not verify_mac_on_vteps([prim_vtep, sec_vtep, sa_vtep], '1002', 1025, sa_mac):
                log.error("Mac learning failed for standalone mac")
                self.failed("Mac learning failed for standalone mac")
                
        primary_handle = get_vpc_primary_secondary_device([prim_vtep, sec_vtep])
        with steps.start("Change the primary role"):
            try:
                primary_handle.configure('''vpc domain {domain}
                                            shutdown'''.format(domain=domain))
            except Exception as error:
                log.debug("Unable to configure - Encountered Exception " + str(error))
                self.errored('Exception occurred while configuring PVMAP', 
                             goto=['common_cleanup'])
        
            log.info('Waiting 180secs for role change')
            time.sleep(180)

            try:
                primary_handle.configure('''vpc domain {domain}
                                            no shutdown'''.format(domain=domain))
            except Exception as error:
                log.debug("Unable to configure - Encountered Exception " + str(error))
                self.errored('Exception occurred while configuring PVMAP', 
                             goto=['common_cleanup'])

            log.info('Waiting 60secs for role change')
            time.sleep(60)

            if not get_vpc_role(primary_handle) == 'primary, operational secondary':
                log.error('Role change failed')
                self.failed('Role change failed')
                
        with steps.start("checking mac learning for vpc mac"):
            if not verify_mac_on_vteps([prim_vtep, sec_vtep, sa_vtep], '1001', 1025, prim_mac):
                log.error("Mac learning failed for orphan mac")
                self.failed("Mac learning failed for orphan mac")

        with steps.start("checking mac learning for standalone mac"):
            if not verify_mac_on_vteps([prim_vtep, sec_vtep, sa_vtep], '1002', 1025, sa_mac):
                log.error("Mac learning failed for standalone mac")
                self.failed("Mac learning failed for standalone mac")

        with steps.start("Verify Steady State"):
            if VerifyTraffic("TC_VXLAN_PVMAP_045", testscript, traffic_item='Trunk VPC To Standalone'):
                log.info('Verify traffic success')
            else:
                self.failed('Verify traffic failed') 
        
        primary_handle = get_vpc_primary_secondary_device([prim_vtep, sec_vtep])
        with steps.start("Change the role on new primary"):
            try:
                primary_handle.configure('''vpc domain {domain}
                                            shutdown'''.format(domain=domain))
            except Exception as error:
                log.debug("Unable to configure - Encountered Exception " + str(error))
                self.errored('Exception occurred while configuring PVMAP', 
                             goto=['common_cleanup'])
        
            log.info('Waiting 180secs for role change')
            time.sleep(180)
        
            try:
                primary_handle.configure('''vpc domain {domain}
                                            no shutdown'''.format(domain=domain))
            except Exception as error:
                log.debug("Unable to configure - Encountered Exception " + str(error))
                self.errored('Exception occurred while configuring PVMAP', 
                             goto=['common_cleanup'])

            log.info('Waiting 60secs for role change')
            time.sleep(60)

            if not get_vpc_role(primary_handle) == 'secondary':
                log.error('Role change failed')
                self.failed('Role change failed')

        with steps.start("checking mac learning for vpc mac"):
            if not verify_mac_on_vteps([prim_vtep, sec_vtep, sa_vtep], '1001', 1025, prim_mac):
                log.error("Mac learning failed for orphan mac")
                self.failed("Mac learning failed for orphan mac")

        with steps.start("checking mac learning for standalone mac"):
            if not verify_mac_on_vteps([prim_vtep, sec_vtep, sa_vtep], '1002', 1025, sa_mac):
                log.error("Mac learning failed for standalone mac")
                self.failed("Mac learning failed for standalone mac")

        with steps.start("Verify Steady State"):
            if VerifyTraffic("TC_VXLAN_PVMAP_045", testscript, traffic_item='Trunk VPC To Standalone'):
                log.info('Verify traffic success')
            else:
                self.failed('Verify traffic failed') 

        with steps.start('Verify Learned mac address consistency between hardware and software'):
            if verify_mac_cc_between_hardware_software([prim_vtep, sec_vtep, sa_vtep]):
                log.info('MAC CC success')
            else:
                self.failed('MAC CC failed')

    @aetest.test
    def verify_error_cores(self, testscript, testbed, steps):
        sa_vtep         = testscript.parameters['LEAF-3']
        prim_vtep       = testscript.parameters['LEAF-1']
        sec_vtep        = testscript.parameters['LEAF-2']
        ixNetwork       = testscript.parameters['ixNetwork']

        with steps.start("Stopping hosts..."):
            ixNetwork.StopAllProtocols()

        log.info('Waiting {}secs'.format(traffic_stop_time))
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

# ======================================================================================================#
# TC-ID: TC_VXLAN_PVMAP_046
# Testcase:  
#   - Configure port-security with PVMAP
#   - Check mac learning and traffic
# ======================================================================================================#
class TC_VXLAN_PVMAP_046(aetest.Testcase):
    @aetest.test
    def testcase_config(self, testscript, steps):
        sa_vtep         = testscript.parameters['LEAF-3']
        prim_vtep       = testscript.parameters['LEAF-1']
        sec_vtep        = testscript.parameters['LEAF-2']
        prim_vtep_if    = str(testscript.parameters['intf_LEAF_1_1_to_IXIA'])
        sa_vtep_if    = str(testscript.parameters['intf_LEAF_3_to_IXIA'])

        with steps.start("Configure port-security"):
            try:
                prim_vtep.configure('''interface {intf}
                                    switchport port-security maximum 1025
                                    switchport port-security aging type inactivity
                                    switchport port-security violation restrict
                                    switchport port-security
                                '''.format(intf=prim_vtep_if))
                sa_vtep.configure('''interface {intf}
                                    switchport port-security maximum 1025
                                    switchport port-security aging type inactivity
                                    switchport port-security violation restrict
                                    switchport port-security
                                '''.format(intf=sa_vtep_if))
                prim_vtep.configure('''interface port-channel 11
                                    switchport port-security maximum 1025
                                    switchport port-security aging type inactivity
                                    switchport port-security violation restrict
                                    switchport port-security
                                ''')
                sec_vtep.configure('''interface port-channel 11
                                    switchport port-security maximum 1025
                                    switchport port-security aging type inactivity
                                    switchport port-security violation restrict
                                    switchport port-security
                                ''')
            except Exception as error:
                    log.debug("Unable to configure - Encountered Exception " + str(error))
                    return False
        

    @aetest.test
    def testcase_vpc(self, testscript, steps):
        sa_vtep         = testscript.parameters['LEAF-3']
        prim_vtep       = testscript.parameters['LEAF-1']
        sec_vtep        = testscript.parameters['LEAF-2']
        prim_mac        = str(testscript.parameters['PVMAP_Dict']['prim_vpc_mac'])
        sa_mac          = str(testscript.parameters['PVMAP_Dict']['sa_mac'])
        p1_handle       = testscript.parameters['vpc_handle']
        p2_handle       = testscript.parameters['sa_handle']
        ixNetwork       = testscript.parameters['ixNetwork']

        with steps.start("Starting hosts..."):
            p1_handle.Start()
            p2_handle.Start()
        
        log.info('Waiting {}secs to start hosts'.format(host_start_time))
        time.sleep(host_start_time)

        stream1 = ixNetwork.Traffic.TrafficItem.find(Name='Trunk VPC To Standalone')
        stream1.StartStatelessTraffic()
        log.info('Waiting {}secs to start the traffic'.format(traffic_start_time))
        time.sleep(traffic_start_time)
        
        stream1.StopStatelessTraffic()
        log.info('Waiting {}secs to stop the traffic'.format(traffic_stop_time))
        time.sleep(traffic_stop_time)

        with steps.start("checking mac learning for vpc mac"):
            if not verify_mac_on_vteps([prim_vtep, sec_vtep], '1001', 1025, prim_mac, 'secure'):
                log.error("Mac learning failed for vpc mac")
                self.failed("Mac learning failed for vpc mac")
            if not verify_mac_on_vteps([sa_vtep], '1001', 1025, prim_mac, 'static'):
                log.error("Mac learning failed for vpc mac")
                self.failed("Mac learning failed for vpc mac")

        with steps.start("Checking mac learning for standalone mac"):
            if not verify_mac_on_vteps([sa_vtep], '1002', 1025, sa_mac, 'secure'):
                log.error("Mac learning failed for standalone mac")
                self.failed("Mac learning failed for standalone mac")
            if not verify_mac_on_vteps([prim_vtep, sec_vtep], '1002', 1025, sa_mac, 'static'):
                log.error("Mac learning failed for standalone mac")
                self.failed("Mac learning failed for standalone mac")

        with steps.start('Verify Learned mac address consistency between hardware and software'):
            if verify_mac_cc_between_hardware_software([prim_vtep, sec_vtep, sa_vtep]):
                log.info('MAC CC success')
            else:
                self.failed('MAC CC failed')

        with steps.start("Verify Steady State"):
            if VerifyTraffic("TC_VXLAN_PVMAP_046", testscript, traffic_item='Trunk VPC To Standalone'):
                log.info('Verify traffic success')
            else:
                self.failed('Verify traffic failed') 

    @aetest.test
    def testcase_orphan(self, testscript, steps):
        sa_vtep         = testscript.parameters['LEAF-3']
        prim_vtep       = testscript.parameters['LEAF-1']
        sec_vtep        = testscript.parameters['LEAF-2']
        prim_mac        = str(testscript.parameters['PVMAP_Dict']['prim_orphan_mac'])
        sa_mac          = str(testscript.parameters['PVMAP_Dict']['sa_mac'])
        p1_handle       = testscript.parameters['orphan1_handle']
        p2_handle       = testscript.parameters['sa_handle']
        ixNetwork       = testscript.parameters['ixNetwork']

        with steps.start("Starting hosts..."):
            p1_handle.Start()
            p2_handle.Start()
        
        log.info('Waiting {}secs to start hosts'.format(host_start_time))
        time.sleep(host_start_time)

        stream1 = ixNetwork.Traffic.TrafficItem.find(Name='Trunk Orphan To Standalone')
        stream1.StartStatelessTraffic()
        log.info('Waiting {}secs to start the traffic'.format(traffic_start_time))
        time.sleep(traffic_start_time)
        
        stream1.StopStatelessTraffic()
        log.info('Waiting {}secs to stop the traffic'.format(traffic_stop_time))
        time.sleep(traffic_stop_time)

        with steps.start("checking mac learning for orphan mac"):
            if not verify_mac_on_vteps([prim_vtep, sec_vtep], '1001', 1025, prim_mac, 'secure'):
                log.error("Mac learning failed for orphan mac")
                self.failed("Mac learning failed for orphan mac")

            if not verify_mac_on_vteps([sa_vtep], '1001', 1025, prim_mac, 'static'):
                log.error("Mac learning failed for orphan mac")
                self.failed("Mac learning failed for orphan mac")

        with steps.start("Checking mac learning for standalone mac"):
            if not verify_mac_on_vteps([prim_vtep, sec_vtep], '1002', 1025, sa_mac, 'static'):
                log.error("Mac learning failed for standalone mac")
                self.failed("Mac learning failed for standalone mac")

            if not verify_mac_on_vteps([sa_vtep], '1002', 1025, sa_mac, 'secure'):
                log.error("Mac learning failed for standalone mac")
                self.failed("Mac learning failed for standalone mac")

        with steps.start('Verify Learned mac address consistency between hardware and software'):
            if verify_mac_cc_between_hardware_software([prim_vtep, sec_vtep, sa_vtep]):
                log.info('MAC CC success')
            else:
                self.failed('MAC CC failed')

        with steps.start("Verify Steady State"):
            if VerifyTraffic("TC_VXLAN_PVMAP_047", testscript, traffic_item='Trunk Orphan To Standalone'):
                log.info('Verify traffic success')
            else:
                self.failed('Verify traffic failed') 

    @aetest.test
    def testcase_unconfig(self, testscript, steps):
        sa_vtep         = testscript.parameters['LEAF-3']
        prim_vtep       = testscript.parameters['LEAF-1']
        sec_vtep        = testscript.parameters['LEAF-2']
        prim_vtep_if    = str(testscript.parameters['intf_LEAF_1_1_to_IXIA'])
        sa_vtep_if    = str(testscript.parameters['intf_LEAF_3_to_IXIA'])

        try:
            prim_vtep.configure('''interface {intf}
                                no switchport port-security maximum 1025
                                no switchport port-security aging type inactivity
                                no switchport port-security violation restrict
                                no switchport port-security
                            '''.format(intf=prim_vtep_if))
            sa_vtep.configure('''interface {intf}
                                no switchport port-security maximum 1025
                                no switchport port-security aging type inactivity
                                no switchport port-security violation restrict
                                no switchport port-security
                            '''.format(intf=sa_vtep_if))
            prim_vtep.configure('''interface port-channel 11
                                no switchport port-security maximum 1025
                                no switchport port-security aging type inactivity
                                no switchport port-security violation restrict
                                no switchport port-security
                            ''')
            sec_vtep.configure('''interface port-channel 11
                                no switchport port-security maximum 1025
                                no switchport port-security aging type inactivity
                                no switchport port-security violation restrict
                                no switchport port-security
                            ''')
        except Exception as error:
                log.debug("Unable to configure - Encountered Exception " + str(error))
                self.failed("Unable to configure - Encountered Exception " + str(error))

    @aetest.test
    def verify_error_cores(self, testscript, testbed, steps):
        sa_vtep         = testscript.parameters['LEAF-3']
        prim_vtep       = testscript.parameters['LEAF-1']
        sec_vtep        = testscript.parameters['LEAF-2']
        ixNetwork       = testscript.parameters['ixNetwork']

        with steps.start("Stopping hosts..."):
            ixNetwork.StopAllProtocols()

        log.info('Waiting {}secs'.format(traffic_stop_time))
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

# ======================================================================================================#
# TC-ID: TC_VXLAN_PVMAP_047
# Testcase:  
#   - Configure PVMAP with nxapi
#   - Check mac learning and traffic
# ======================================================================================================#
class TC_VXLAN_PVMAP_047(aetest.Testcase):
    @aetest.test
    def testcase_config_nxapi(self, testbed, testscript, steps):
        sa_vtep         = testscript.parameters['LEAF-3']
        prim_vtep       = testscript.parameters['LEAF-1']
        sec_vtep        = testscript.parameters['LEAF-2']
        user            = str(testscript.parameters['PVMAP_Dict']['nxapi_user'])
        passwd          = str(testscript.parameters['PVMAP_Dict']['nxapi_passwd'])
        leaf1_ip        = str(testscript.parameters['LEAF-1'].connections.alt.ip)
        leaf2_ip        = str(testscript.parameters['LEAF-2'].connections.alt.ip)
        leaf3_ip        = str(testscript.parameters['LEAF-3'].connections.alt.ip)
        prim_vtep_if    = str(testscript.parameters['intf_LEAF_1_1_to_IXIA'])
        sa_vtep_if      = str(testscript.parameters['intf_LEAF_3_to_IXIA'])

        with steps.start("Enable nxapi"):
            try:
                prim_vtep.configure('''feature nxapi
                                    nxapi http port 80
                                    ''')

                sec_vtep.configure('''feature nxapi
                                    nxapi http port 80
                                    ''')
                
                sa_vtep.configure('''feature nxapi
                                    nxapi http port 80
                                    ''')
            except Exception as error:
                log.debug("Unable to configure - Encountered Exception " + str(error))
                self.failed("Unable to configure - Encountered Exception " + str(error))

        with steps.start("Disable PVMAP"):
            passwd = 'nbv12345'
            print(leaf1_ip, user, passwd, prim_vtep_if)
            nxapi_disable_pvmap(leaf1_ip, user, passwd, prim_vtep_if, log)
            nxapi_disable_pvmap(leaf3_ip, user, passwd, sa_vtep_if, log)
            nxapi_disable_pvmap(leaf1_ip, user, passwd, 'port-channel 11', log)
            nxapi_disable_pvmap(leaf2_ip, user, passwd, 'port-channel 11', log)
        
        with steps.start('Validating PVMAP disabled'):
            if not nxapi_validate_disable_pvmap(prim_vtep, leaf1_ip, user, passwd, prim_vtep_if, log):
                log.error('Diabling PVMAP failed')
                self.failed('Diabling PVMAP failed')
            if not nxapi_validate_disable_pvmap(sa_vtep, leaf3_ip, user, passwd, sa_vtep_if, log):
                log.error('Diabling PVMAP failed')
                self.failed('Diabling PVMAP failed')
            if not nxapi_validate_disable_pvmap(prim_vtep, leaf1_ip, user, passwd, 'port-channel 11', log):
                log.error('Diabling PVMAP failed')
                self.failed('Diabling PVMAP failed')
            if not nxapi_validate_disable_pvmap(sec_vtep, leaf2_ip, user, passwd, 'port-channel 11', log):
                log.error('Diabling PVMAP failed')
                self.failed('Diabling PVMAP failed')
        
        with steps.start("Enable PVMAP"):
            nxapi_enable_pvmap(testscript, 'Orphan1', leaf1_ip, user, passwd, prim_vtep_if, log)
            nxapi_enable_pvmap(testscript, 'SA', leaf3_ip, user, passwd, sa_vtep_if, log)
            nxapi_enable_pvmap(testscript, 'VPC', leaf1_ip, user, passwd, 'port-channel 11', log)
            nxapi_enable_pvmap(testscript, 'VPC', leaf2_ip, user, passwd, 'port-channel 11', log)

        with steps.start('Validating PVMAP enable'):
            if not nxapi_validate_enable_pvmap(testscript, 'Orphan1', leaf1_ip, user, passwd, prim_vtep_if, log):
                log.error('Enabling PVMAP failed')
                self.failed('Enabling PVMAP failed')
            if not nxapi_validate_enable_pvmap(testscript, 'SA', leaf3_ip, user, passwd, sa_vtep_if, log):
                log.error('Enabling PVMAP failed')
                self.failed('Enabling PVMAP failed')
            if not nxapi_validate_enable_pvmap(testscript, 'VPC', leaf1_ip, user, passwd, 'port-channel 11', log):
                log.error('Enabling PVMAP failed')
                self.failed('Enabling PVMAP failed')
            if not nxapi_validate_enable_pvmap(testscript, 'VPC', leaf2_ip, user, passwd, 'port-channel 11', log):
                log.error('Enabling PVMAP failed')
                self.failed('Enabling PVMAP failed')
    @aetest.test
    def testcase_vpc(self, testscript, steps):
        sa_vtep         = testscript.parameters['LEAF-3']
        prim_vtep       = testscript.parameters['LEAF-1']
        sec_vtep        = testscript.parameters['LEAF-2']
        prim_mac        = str(testscript.parameters['PVMAP_Dict']['prim_vpc_mac'])
        sa_mac          = str(testscript.parameters['PVMAP_Dict']['sa_mac'])
        p1_handle       = testscript.parameters['vpc_handle']
        p2_handle       = testscript.parameters['sa_handle']
        ixNetwork       = testscript.parameters['ixNetwork']

        with steps.start("Starting hosts..."):
            p1_handle.Start()
            p2_handle.Start()
        
        log.info('Waiting {}secs to start hosts'.format(host_start_time))
        time.sleep(host_start_time)

        stream1 = ixNetwork.Traffic.TrafficItem.find(Name='Trunk VPC To Standalone')
        stream1.StartStatelessTraffic()
        log.info('Waiting {}secs to start the traffic'.format(traffic_start_time))
        time.sleep(traffic_start_time)
        
        stream1.StopStatelessTraffic()
        log.info('Waiting {}secs to stop the traffic'.format(traffic_stop_time))
        time.sleep(traffic_stop_time)

        with steps.start("checking mac learning for vpc mac"):
            if not verify_mac_on_vteps([prim_vtep, sec_vtep, sa_vtep], '1001', 1025, prim_mac):
                log.error("Mac learning failed for vpc mac")
                self.failed("Mac learning failed for vpc mac")

        with steps.start("Checking mac learning for standalone mac"):
            if not verify_mac_on_vteps([prim_vtep, sec_vtep, sa_vtep], '1002', 1025, sa_mac):
                log.error("Mac learning failed for standalone mac")
                self.failed("Mac learning failed for standalone mac")

        with steps.start('Verify Learned mac address consistency between hardware and software'):
            if verify_mac_cc_between_hardware_software([prim_vtep, sec_vtep, sa_vtep]):
                log.info('MAC CC success')
            else:
                self.failed('MAC CC failed')

        with steps.start("Verify Steady State"):
            if VerifyTraffic("TC_VXLAN_PVMAP_047", testscript, traffic_item='Trunk VPC To Standalone'):
                log.info('Verify traffic success')
            else:
                self.failed('Verify traffic failed') 

    @aetest.test
    def testcase_orphan(self, testscript, steps):
        sa_vtep         = testscript.parameters['LEAF-3']
        prim_vtep       = testscript.parameters['LEAF-1']
        sec_vtep        = testscript.parameters['LEAF-2']
        prim_mac        = str(testscript.parameters['PVMAP_Dict']['prim_orphan_mac'])
        sa_mac          = str(testscript.parameters['PVMAP_Dict']['sa_mac'])
        p1_handle       = testscript.parameters['orphan1_handle']
        p2_handle       = testscript.parameters['sa_handle']
        ixNetwork       = testscript.parameters['ixNetwork']

        with steps.start("Starting hosts..."):
            p1_handle.Start()
            p2_handle.Start()
        
        log.info('Waiting {}secs to start hosts'.format(host_start_time))
        time.sleep(host_start_time)

        stream1 = ixNetwork.Traffic.TrafficItem.find(Name='Trunk Orphan To Standalone')
        stream1.StartStatelessTraffic()
        log.info('Waiting {}secs to start the traffic'.format(traffic_start_time))
        time.sleep(traffic_start_time)
        
        stream1.StopStatelessTraffic()
        log.info('Waiting {}secs to stop the traffic'.format(traffic_stop_time))
        time.sleep(traffic_stop_time)

        with steps.start("checking mac learning for orphan mac"):
            if not verify_mac_on_vteps([prim_vtep, sec_vtep, sa_vtep], '1001', 1025, prim_mac):
                log.error("Mac learning failed for orphan mac")
                self.failed("Mac learning failed for orphan mac")

        with steps.start("Checking mac learning for standalone mac"):
            if not verify_mac_on_vteps([prim_vtep, sec_vtep, sa_vtep], '1002', 1025, sa_mac):
                log.error("Mac learning failed for standalone mac")
                self.failed("Mac learning failed for standalone mac")
        
        with steps.start('Verify Learned mac address consistency between hardware and software'):
            if verify_mac_cc_between_hardware_software([prim_vtep, sec_vtep, sa_vtep]):
                log.info('MAC CC success')
            else:
                self.failed('MAC CC failed')

        with steps.start("Verify Steady State"):
            if VerifyTraffic("TC_VXLAN_PVMAP_047", testscript, traffic_item='Trunk Orphan To Standalone'):
                log.info('Verify traffic success')
            else:
                self.failed('Verify traffic failed') 

    @aetest.test
    def testcase_unconfig_nxapi(self, testbed, testscript, steps):
        sa_vtep         = testscript.parameters['LEAF-3']
        prim_vtep       = testscript.parameters['LEAF-1']
        sec_vtep        = testscript.parameters['LEAF-2']
        user            = str(testscript.parameters['PVMAP_Dict']['nxapi_user'])
        passwd          = str(testscript.parameters['PVMAP_Dict']['nxapi_passwd'])
        leaf1_ip        = str(testscript.parameters['LEAF-1'].connections.alt.ip)
        leaf2_ip        = str(testscript.parameters['LEAF-2'].connections.alt.ip)
        leaf3_ip        = str(testscript.parameters['LEAF-3'].connections.alt.ip)
        prim_vtep_if    = str(testscript.parameters['intf_LEAF_1_1_to_IXIA'])
        sa_vtep_if      = str(testscript.parameters['intf_LEAF_3_to_IXIA'])

        with steps.start("Disable PVMAP"):
            passwd = 'nbv12345'
            print(leaf1_ip, user, passwd, prim_vtep_if)
            nxapi_disable_pvmap(leaf1_ip, user, passwd, prim_vtep_if, log)
            nxapi_disable_pvmap(leaf3_ip, user, passwd, sa_vtep_if, log)
            nxapi_disable_pvmap(leaf1_ip, user, passwd, 'port-channel 11', log)
            nxapi_disable_pvmap(leaf2_ip, user, passwd, 'port-channel 11', log)
        with steps.start('Validating PVMAP disabled'):
            if not nxapi_validate_disable_pvmap(prim_vtep, leaf1_ip, user, passwd, prim_vtep_if, log):
                log.error('Diabling PVMAP failed')
                self.failed('Diabling PVMAP failed')
            if not nxapi_validate_disable_pvmap(sa_vtep, leaf3_ip, user, passwd, sa_vtep_if, log):
                log.error('Diabling PVMAP failed')
                self.failed('Diabling PVMAP failed')
            if not nxapi_validate_disable_pvmap(prim_vtep, leaf1_ip, user, passwd, 'port-channel 11', log):
                log.error('Diabling PVMAP failed')
                self.failed('Diabling PVMAP failed')
            if not nxapi_validate_disable_pvmap(sec_vtep, leaf2_ip, user, passwd, 'port-channel 11', log):
                log.error('Diabling PVMAP failed')
                self.failed('Diabling PVMAP failed')

        with steps.start("Enable nxapi"):
            try:
                prim_vtep.configure('''no feature nxapi''')

                sec_vtep.configure('''no feature nxapi''')
                
                sa_vtep.configure('''no feature nxapi''')
            except Exception as error:
                log.debug("Unable to configure - Encountered Exception " + str(error))
                self.failed("Unable to configure - Encountered Exception " + str(error))
    @aetest.test
    def verify_error_cores(self, testscript, testbed, steps):
        sa_vtep         = testscript.parameters['LEAF-3']
        prim_vtep       = testscript.parameters['LEAF-1']
        sec_vtep        = testscript.parameters['LEAF-2']
        ixNetwork       = testscript.parameters['ixNetwork']

        with steps.start("Stopping hosts..."):
            ixNetwork.StopAllProtocols()

        log.info('Waiting {}secs'.format(traffic_stop_time))
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
                sa_vtep.configure('no interface port-channel 11')
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