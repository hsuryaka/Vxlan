#
#   Demo script file for setup bring

# python generic imports
import yaml
import logging
import argparse
import re
import time
from common_lib import utils
from common_lib.utils import *
import MyLib
from MyLib import my_utils
from MyLib import my_config_utils
from MyLib import my_trigger_utils
from MyLib import my_multisite_lib
from MyLib import my_cloudsec_lib

from common_lib import routing_utils
from common_lib.routing_utils import *
from pyats import aetest
from common_lib import config_bringup
import yaml
import logging
from pyats.topology import loader
import argparse

# pyATS imports

from unicon import Connection
from ats import aetest
from ats.log.utils import banner
from ats.datastructures.logic import Not, And, Or
from ats.easypy import run
from ats.log.utils import banner
from common_lib import bringup_lib
#import evpn_lib
from feature_lib.vxlan import vxlan_lib
from feature_lib.l3 import ospfv2_lib
from feature_lib.l3 import ospfv3_lib
from feature_lib.l3 import bgp_lib
from feature_lib.vxlan import evpn_lib
from common_lib import tcam_lib
from feature_lib.l3 import pim_lib
from feature_lib.l2 import vpc_lib
#import oam_lib
from pyats.async_ import pcall
from pyats.async_ import Pcall

import threading

# N39k Library imports
from common_lib import config_bringup
from common_lib import config_bringup_test
from common_lib import interface_lib
import ipaddress

from itertools import chain
from collections import OrderedDict
from itertools import permutations
import json
from bs4 import BeautifulSoup
from prettytable import PrettyTable
from _ast import alias

#Ixia Libraries
from common_lib import ixia_lib_new
from common_lib.ixia_lib_new import *

# Import the RestPy module
from ixnetwork_restpy import *

# *****************************************************************************************************************************#

def expandTrafficItemList(a):
    skip_list = []
    pat = re.compile(r'([A-Za-z]+)(\d+)-[A-Za-z]+(\d+)', flags=re.I)
    if a:
        log.info(banner('The Value of a is : {0}'.format(a)))
        c = a.split(',')
        log.info(banner('The Value of c is : {0}'.format(c)))
        for items in c:
            b = pat.search(items)
            [skip_list.append(b.group(1) + str("{:03d}".format(i))) for i in range(int(b.group(2)), int(b.group(3))+1)]
            
    return skip_list

# *****************************************************************************************************************************#

def countDownTimer(a):
    for i in range(a):
        log.info('seconds remaining is: {0}'.format(int(a-i)))
        time.sleep(1)
    return 1

# *****************************************************************************************************************************#

def parseVpcDomainParams(args,log):
    arggrammar={}
    arggrammar['domain_id']='-type int -default 1'
    arggrammar['system_mac']='-type str'
    arggrammar['system_priority']='-type int -default 32667'
    arggrammar['role_priority']='-type int -default 100'
    arggrammar['peer_keepalive_src_ipv4_addr']='-type str'
    arggrammar['peer_keepalive_dst_ipv4_addr']='-type str'
    arggrammar['peer_switch']='-type bool -default True'
    arggrammar['peer_gateway']='-type bool -default True'
    arggrammar['arp_synchronize']='-type bool -default True'
    arggrammar['peer_keepalive_vrf']='-type str'
    arggrammar['nd_synchronize']='-type bool -default True'
    return utils.parserutils_lib.argsToCommandOptions( args, arggrammar, log)

# *****************************************************************************************************************************#

def parseVpcPeerLinkParams(args,log):
    arggrammar={}
    arggrammar['pc_no']='-type int -default 4096'
    return utils.parserutils_lib.argsToCommandOptions( args, arggrammar, log)

# *****************************************************************************************************************************#

def parseVpcPCParams(args,log):
    arggrammar={}
    arggrammar['members']='-type str'
    arggrammar['pc_no']='-type int -default 1'
    arggrammar['vpc_id']='-type int -default 1'
    arggrammar['port_mode']='-type str'
    return utils.parserutils_lib.argsToCommandOptions( args, arggrammar, log)

# *****************************************************************************************************************************#

def verifyProcessRestart(dut, p_name):
    
    log.info('Inside verifyProcessRestart .....')
#     unicon_state = unicon.statemachine.statemachine.State(name='enable', pattern=r'^.*|%N#')
#     unicon_state.add_state_pattern(pattern_list = "r'bash-*$'")
    
    dut.configure("feature bash-shell")
    dut.configure('system no hap-reset')
    
    # Get the PID of the process before killing it
    pid_data = dut.execute("show system internal sysmgr service name " + str(p_name) + " | i i PID")
    pid_regex = re.search("PID = (\\d+)",pid_data,re.I)
    if pid_regex is not 0:
        pid = pid_regex.group(1)
    
    # Kill the process in bash prompt
    dut.execute("run bash", allow_state_change = "True")
    dut.execute("sudo su", allow_state_change = "True")
    dut.execute("kill -9 "+str(pid), allow_state_change = "True")
    dut.execute("exit", allow_state_change = "True")
    dut.execute("exit", allow_state_change = "True")
    
#     unicon_state.restore_state_pattern()
#     unicon_state = ""
    
    countDownTimer(30)
    
    # Get the PID of the process after killing it
    post_kill_pid_data = dut.execute("show system internal sysmgr service name " + str(p_name) + " | i i PID")
    post_kill_pid_regex = re.search("PID = (\\d+)",post_kill_pid_data,re.I)
    if post_kill_pid_regex is not 0:
        post_kill_pid = post_kill_pid_regex.group(1)
    
    # Check if pre-kill PID and post-kill PID are different
    if pid != post_kill_pid:
        return 1
    else:
        return 0

# *****************************************************************************************************************************#

def verifyProcessRestartWithFlushRoutes(dut, p_name,**kwargs):
    
    log.info('Inside verifyProcessRestart wtih Flush Route .....')
#     unicon_state = unicon.statemachine.statemachine.State(name='enable', pattern=r'^.*|%N#')
#     unicon_state.add_state_pattern(pattern_list = "r'bash-*$'")
    
    dut.configure("feature bash-shell")
    dut.configure('system no hap-reset')
    
    if kwargs:
        process_id = kwargs['process_id']
    # Get the PID of the process before restarting it
    pid_data = dut.execute("show system internal sysmgr service name " + str(p_name) + " | i i PID")
    pid_regex = re.search("PID = (\\d+)",pid_data,re.I)
    if pid_regex is not 0:
        pid = pid_regex.group(1)
    
    if p_name == 'ospf' and kwargs:
        cfg = ''' router {0} {1}
                  flush-routes
              '''.format(p_name,process_id)
        dut.configure(cfg)
        dut.configure('restart {0} {1}'.format(p_name,process_id))
    if p_name == 'igmp':
        dut.configure('ip igmp flush-routes')
        dut.configure('restart {0}'.format(p_name))
    if p_name == 'pim':
        dut.configure('ip pim flush-routes')
        dut.configure('restart {0}'.format(p_name))
    if p_name == 'bgp' and kwargs:
        cfg = ''' router {0} {1}
                  flush-routes
              '''.format(p_name,process_id)
        dut.configure(cfg)
        dut.configure('restart {0} {1}'.format(p_name,process_id))
    if p_name == 'ngmvpn':
        dut.configure('restart {0}'.format(p_name))

    countDownTimer(30)
    # Get the PID of the process after restarting it
    post_kill_pid_data = dut.execute("show system internal sysmgr service name " + str(p_name) + " | i i PID")
    post_kill_pid_regex = re.search("PID = (\\d+)",post_kill_pid_data,re.I)
    if post_kill_pid_regex is not 0:
        post_kill_pid = post_kill_pid_regex.group(1)

    # Check if pre-kill PID and post-kill PID are different
    if pid != post_kill_pid:
        return 1
    else:
        return 0

# *****************************************************************************************************************************#

def parseTGParams(args,log):
    arggrammar={}
    arggrammar['apiServerIp']='-type str'
    arggrammar['ixChassisIpList']='-type str'
    arggrammar['configFile']='-type str'
    return utils.parserutils_lib.argsToCommandOptions( args, arggrammar, log)

# *****************************************************************************************************************************#

def verifyTraffic(testscript):
        ixNetwork = testscript.parameters['ixNetwork']
        session = testscript.parameters['session']
        traffic_threshold = testscript.parameters['traffic_threshold']

        ixNetwork.StartAllProtocols(Arg1='sync')

        ixNetwork.Traffic.Apply()
        ixNetwork.Traffic.Start()

        print("sampling traffic for 120sec")
        time.sleep(120)

        ixNetwork.ClearStats()

        time.sleep(20)

        trafficItemStatistics = session.StatViewAssistant('Traffic Item Statistics')
        # Loss_per = trafficItemStatistics.Rows['Loss %']
        # txFrames = trafficItemStatistics.Rows['Tx Frames']
        # rxFrames = trafficItemStatistics.Rows['Rx Frames']

        a = trafficItemStatistics.Rows.Columns
        TI_idx = a.index('Traffic Item')
        TI_TxFr_idx = a.index('Tx Frames')
        TI_RxFr_idx = a.index('Rx Frames')
        TI_LP_idx = a.index('Loss %')

        fail_flag = []
        stat_msgs = '\n'
        stats = trafficItemStatistics.Rows.RawData
        for stat in stats:
            if stat[TI_LP_idx] == '':
                if (int(stat[TI_TxFr_idx])-int(stat[TI_RxFr_idx])) in range(0,1001):
                    stat_msgs += (str(stat[TI_idx]) + ' - ' + str(stat[TI_TxFr_idx]) + ' - ' + str(stat[TI_RxFr_idx]) + ' - LossPkts -' + str(int(stat[TI_TxFr_idx])-int(stat[TI_RxFr_idx])) + ' - Traffic Passed \n')
                else:
                    stat_msgs += (str(stat[TI_idx]) + ' - ' + str(stat[TI_TxFr_idx]) + ' - ' + str(stat[TI_RxFr_idx]) + ' - LossPkts -' + str(int(stat[TI_TxFr_idx])-int(stat[TI_RxFr_idx])) + ' - Traffic Failed \n')
                    fail_flag.append(0)
            else:
                if int(float(stat[5])) < traffic_threshold:
                    stat_msgs += (str(stat[TI_idx]) + ' - ' + str(stat[TI_TxFr_idx]) + ' - ' + str(stat[TI_RxFr_idx]) + ' - ' + str(stat[TI_LP_idx]) + ' - Traffic Passed \n')
                else:
                    stat_msgs += (str(stat[TI_idx]) + ' - ' + str(stat[TI_TxFr_idx]) + ' - ' + str(stat[TI_RxFr_idx]) + ' - ' + str(stat[TI_LP_idx]) + ' - Traffic Failed \n')
                    fail_flag.append(0)

        time.sleep(20)

        ixNetwork.Traffic.Stop()
        ixNetwork.StopAllProtocols()

        if 0 in fail_flag:
            return {'status':0, 'msgs':stat_msgs}
        else:
            return {'status':1, 'msgs':stat_msgs}

# *****************************************************************************************************************************#

class CommonSetup(aetest.CommonSetup):

    '''
    Setup :
        **********

    '''

    uid = 'common_setup'
    @aetest.subsection
    def initialize_logging(self, testscript):
        """ Common setup section to initialize logging for script"""

        log = logging.getLogger(__name__)
        log.setLevel(logging.DEBUG)
        testscript.parameters['log'] = log

    @aetest.subsection
    def check_topology(self, testbed, testscript,log,traffic_threshold='', tgn_connect = '', **kwargs):
        """ common setup subsection: connecting devices """

        testscript.parameters['traffic_threshold'] = traffic_threshold
        testscript.parameters['tgn_connect'] = tgn_connect
 
        log.info(banner('The value of kwargs is : {0}'.format(kwargs)))
        testscript.parameters['config_interface'] = kwargs['config_interface']
        testscript.parameters['config_ospf'] = kwargs['config_ospf']
        testscript.parameters['config_bgp'] = kwargs['config_bgp']
        testscript.parameters['config_keepalive_vrf'] = kwargs['config_keepalive_vrf']
        testscript.parameters['config_trmv6'] = kwargs['config_trmv6']
        testscript.parameters['config_vpc'] = kwargs['config_vpc']
        testscript.parameters['config_pim'] = kwargs['config_pim']
        testscript.parameters['config_vxlan_global'] = kwargs['config_vxlan_global']
        testscript.parameters['config_bgp_global'] = kwargs['config_bgp_global']
        testscript.parameters['config_vlan'] = kwargs['config_vlan']
        testscript.parameters['config_vrf'] = kwargs['config_vrf']
        testscript.parameters['config_svi'] = kwargs['config_svi']
        testscript.parameters['config_evpn'] = kwargs['config_evpn']
        testscript.parameters['config_nve_global'] = kwargs['config_nve_global'] 
        testscript.parameters['config_nve_l2vni'] = kwargs['config_nve_l2vni']
        testscript.parameters['config_nve_l3vni'] = kwargs['config_nve_l3vni']
        testscript.parameters['config_loopback_intf'] = kwargs['config_loopback_intf']
        testscript.parameters['config_route_map'] = kwargs['config_route_map']
        testscript.parameters['config_multisite'] = kwargs['config_multisite']

        parser = argparse.ArgumentParser()
        parser.add_argument('--config-file',dest='config_file',type=str)
        # args = parser.parse_args()
        # config_file = args.config_file
        args = parser.parse_known_args()
        config_file = args[0].config_file
        fp = open(config_file)
        configdict=yaml.safe_load(fp)
        fp.close()        
        fail_result=0
        log.info('Getting testbed objects from the testbed file')
        testbed_obj = testbed

        # Way to get password and login from Testbed file
        # passw = testbed_obj.passwords['tacacs']
        # login = testbed_obj.tacacs['username']

        log.info(banner('The Devices in Testbed File are : \n {0}'.format("\n".join(list(testbed_obj.devices.keys())))))

        duts = list(filter(lambda x: 'TG' not in x, list(testbed_obj.devices.aliases)))
        TGs = list(filter(lambda x: 'uut' not in x , list (testbed_obj.devices.aliases)))

        log.info('{0} are the available duts in the testbed'.format(duts))
        log.info('{0} are the available TGs in the testbed'.format(TGs))   
                
        duts.sort()
        TGs.sort()

        # As per Testbed File following links are present.
        
        alias_intf_mapping = {}
        for dut in list(testbed_obj.devices.keys()):
            a = testbed_obj.devices[dut].alias
            log.info(banner('Dut Alias is  : {0}'.format(a)))
            alias_intf_mapping[a] = {}
            if 'ixia' not in dut:
                log.info(banner('DUT is {0}'.format(dut)))
            else:
                log.info(banner('TRAFFIC GENERATOR is: {0}'.format(dut)))
            intf = [x for x in testbed_obj.devices[dut].interfaces.keys()]
            alias = [testbed_obj.devices[dut].interfaces[x].alias for x in testbed_obj.devices[dut].interfaces.keys()]
            res = list(zip(intf,alias))
            alias_intf_mapping.update(dict(zip(alias,intf)))
            alias_intf_mapping[a].update(dict(zip(alias,intf)))
            alias_intf_mapping.setdefault('all_intf',{})
            alias_intf_mapping['all_intf'].update(dict(zip(alias,intf)))
            log.info(banner('The interfaces and alias on dut {1} are \n {0}'.format("\n".join(["->".join(x) for x in res]),dut)))
            
            
        log.info('The value of alias_intf_mapping is {0}'.format(yaml.dump(alias_intf_mapping)))

        # Way to take variable to other section
        testscript.parameters['testbed_obj'] = testbed_obj
        testscript.parameters['configdict'] = configdict
        testscript.parameters['fail_result'] = fail_result
        testscript.parameters['alias_intf_mapping'] = alias_intf_mapping
       
    @aetest.subsection
    def topology_used_for_suite(self,log):
        """ common setup subsection: Represent Topology """

        log.info(banner("Topology to be used"))

        # Set topology to be used
        topology = """
        
                                                 +----------------------------------------------------------+
                                                 |                           DCI-CORE                       |
                                                 +----------------------------------------------------------+                                                         
                                                   /  |                          |  \\                    \\
                                                  /   |                          |   \\                    \\
                                                 /    |         SITE-1           |    \\       SITE-2       \\
                                                /     |                          |     \\                    \\                                       
                                               /      |                          |      \\                    \\
                                              /       |                          |       \\                    \\
                                             /        |                          |        \\                    \\
                                            /         |                          |         \\                    \\
                                           /          |                          |          \\                    \\
                                          /           |                          |           \\                    \\
            +---------+       +-----------+    +-----------+    +-----------+    |       +-----------+          +-----------+
            |   IXIA  |-------| vPC-BGW-1 |====| vPC-BGW-2 |----|   IXIA    |    |       |  AC-BGW-1 |          |  AC-BGW-2 |
            +---------+       +-----------+    +-----------+    +-----------+    |       +-----------+          +-----------+
                                   \\             /     \\                       |               \\               /
                                    \\           /       \\                      |                \\             /
                                     \\         /         \\                     |                 \\           /
                                      \\       /           \\                    |                  \\         /
                                    +-----------+         +-----------+          |                 +-----------+
                                    |   FAN     |         |  SPINE-1  |          |                 |  SPINE-2  |
                                    +-----------+         +-----------+          |                 +-----------+
                                         |                      |                |                       |
                                         |                      |                |                       |
                                         |                      |                |                       |
                                    +-----------+         +-----------+          |                 +-----------+
                                    |   IXIA    |         |  S-1-LEAF |          |                 |  S-2-LEAF |
                                    +-----------+         +-----------+          |                 +-----------+
                                                                |                |                       |
                                                                |                |                       |
                                                                |                |                       |
                                                          +-----------+          |                 +-----------+
                                                          |   IXIA    |          |                 |   IXIA    |
                                                          +-----------+          |                 +-----------+      
                                                                                 |
                                                                                 |
        """

        log.info("Topology to be used is")
        log.info(topology)

    @aetest.subsection
    def configBringUp(self,testscript,log,steps):
        
        testbed_obj = testscript.parameters['testbed_obj']

        # DUTs required to test this feature 
        dutList_config_file = list(testscript.parameters['configdict']['dut'].keys())
        log.info('{0} are the duts required for EVPN tests'.format(dutList_config_file))
        
        # Create obj for each node from config file
        dutList_obj_config_file = []
        for dut_config_file in dutList_config_file:
            dutList_obj_config_file.append(testscript.parameters['testbed_obj'].devices[dut_config_file])
            
        # declaring vtep list
        node_dict = {}
        
        for node in list(testbed_obj.devices.keys()):
            log.info('The Value of node is : {0}'.format(node))
            log.info('The value of node.type is : {0}'.format(testbed_obj.devices[node].type))
            if re.search('Site1',testbed_obj.devices[node].type,re.IGNORECASE):
                node_dict.setdefault('Site1',{})
                node_dict.setdefault('all_bgws',{})
                if re.search('BGW',testbed_obj.devices[node].type,re.IGNORECASE):
                    if re.search('VPC',testbed_obj.devices[node].type,re.IGNORECASE):
                        node_dict['Site1'].setdefault('VPC_BGW',{})
                        node_dict['Site1']['VPC_BGW'][testbed_obj.devices[node].alias] = testbed_obj.devices[node]
                    else:
                        node_dict['Site1'].setdefault('BGW',{})
                        node_dict['Site1']['BGW'][testbed_obj.devices[node].alias] = testbed_obj.devices[node]
                    node_dict['all_bgws'][testbed_obj.devices[node].alias] = testbed_obj.devices[node]
                if re.search('SPINE',testbed_obj.devices[node].type,re.IGNORECASE):
                    log.info('Inside the Site1: Spine re.search block()')
                    node_dict['Site1'].setdefault('SPINE',{})
                    node_dict['Site1']['SPINE'][testbed_obj.devices[node].alias] = testbed_obj.devices[node]
                if re.search('LEAF',testbed_obj.devices[node].type,re.IGNORECASE):
                    log.info('Inside the Site1: leaf re.search block()')
                    node_dict['Site1'].setdefault('LEAF',{})
                    node_dict['Site1']['LEAF'][testbed_obj.devices[node].alias] = testbed_obj.devices[node] 
                if re.search('ACCESS_SWITCH',testbed_obj.devices[node].type,re.IGNORECASE):
                    log.info('Inside the Site1: access_switch re.search block()')
                    node_dict['Site1'].setdefault('ACCESS_SWITCH',{})
                    node_dict['Site1']['ACCESS_SWITCH'][testbed_obj.devices[node].alias] = testbed_obj.devices[node]  
            elif re.search('Site2',testbed_obj.devices[node].type,re.IGNORECASE):
                node_dict.setdefault('Site2',{})
                node_dict.setdefault('all_bgws',{})
                if re.search('BGW',testbed_obj.devices[node].type,re.IGNORECASE):
                    node_dict['Site2'].setdefault('BGW',{})
                    node_dict['Site2']['BGW'][testbed_obj.devices[node].alias] = testbed_obj.devices[node]
                    node_dict['all_bgws'][testbed_obj.devices[node].alias] = testbed_obj.devices[node]
                if re.search('SPINE',testbed_obj.devices[node].type,re.IGNORECASE):
                    node_dict['Site2'].setdefault('SPINE',{})
                    node_dict['Site2']['SPINE'][testbed_obj.devices[node].alias] = testbed_obj.devices[node]
                if re.search('LEAF',testbed_obj.devices[node].type,re.IGNORECASE):
                    node_dict['Site2'].setdefault('LEAF',{})
                    node_dict['Site2']['LEAF'][testbed_obj.devices[node].alias] = testbed_obj.devices[node]
            elif re.search('Site3',testbed_obj.devices[node].type,re.IGNORECASE):
                node_dict.setdefault('Site3',{})
                node_dict.setdefault('all_bgws',{})
                if re.search('BGW',testbed_obj.devices[node].type,re.IGNORECASE):
                    node_dict['Site3'].setdefault('BGW',{})
                    node_dict['Site3']['BGW'][testbed_obj.devices[node].alias] = testbed_obj.devices[node]
                    node_dict['all_bgws'][testbed_obj.devices[node].alias] = testbed_obj.devices[node]
                if re.search('SPINE',testbed_obj.devices[node].type,re.IGNORECASE):
                    node_dict['Site3'].setdefault('SPINE',{})
                    node_dict['Site3']['SPINE'][testbed_obj.devices[node].alias] = testbed_obj.devices[node]
                if re.search('LEAF',testbed_obj.devices[node].type,re.IGNORECASE):
                    node_dict['Site3'].setdefault('LEAF',{})
                    node_dict['Site3']['LEAF'][testbed_obj.devices[node].alias] = testbed_obj.devices[node]
            elif re.search('DCI',testbed_obj.devices[node].type,re.IGNORECASE):
                node_dict.setdefault('DCI',{})
                node_dict['DCI'][testbed_obj.devices[node].alias] = testbed_obj.devices[node]
            elif re.search('External',testbed_obj.devices[node].type,re.IGNORECASE):
                node_dict.setdefault('External_RP',{})
                node_dict['External_RP'][testbed_obj.devices[node].alias] = testbed_obj.devices[node]
            elif re.search('ixia',testbed_obj.devices[node].type,re.IGNORECASE):
                node_dict.setdefault('trf_gen',{})
                node_dict['trf_gen'][testbed_obj.devices[node].alias] = testbed_obj.devices[node]
            node_dict.setdefault('all_dut',{})
            node_dict['all_dut'][testbed_obj.devices[node].alias] = testbed_obj.devices[node]

        log.info(banner('Value of Node dict is : {0}'.format(node_dict)))
                
        for dut in node_dict['all_dut']:
            if not re.search(r'TG',dut,re.I):
                node_dict['all_dut'][dut].connect()

        testscript.parameters['node_dict'] = node_dict
                            
    @aetest.subsection
    def configureInterfaces(self,testscript,log):
        
        config_interface = testscript.parameters['config_interface']
        alias_intf_mapping = testscript.parameters['alias_intf_mapping']
        
        if config_interface:
            #interface config dict 
            config_dict = testscript.parameters['configdict']
            node_dict = testscript.parameters['node_dict']
            testbed_obj = testscript.parameters['testbed_obj']
            
            intf_config_dict = testscript.parameters['configdict']['interface_config_dict']
    
            log.info(banner('The value of interface_config_dict is {0} '.format(intf_config_dict)))
            
            log.info(banner('The value of node_dict is {0} '.format(node_dict)))
            
            intf_obj = config_bringup_test.configSetup(config_dict,testbed_obj,log)
            
            uut_list = ['uut1','uut2','uut5','uut6','uut7','uut9']
            for node in uut_list:
                hdl = node_dict['all_dut'][node]
                hdl.configure('''feature fabric forwarding''')

            #######################################################################################
            #THIS IS APPLICABLE ONLY FOR MY TB
            # hdl_uut8 = node_dict['all_dut']['uut8']
            # hdl_uut8.configure('''interface {0}
            #                 speed 40000
            #                 no shutdown
            #                 interface {1}
            #                 speed 40000
            #                 no shutdown'''.format(alias_intf_mapping['uut8_uut9_1'],alias_intf_mapping['uut8_uut9_2']))
            # hdl_uut9 = node_dict['all_dut']['uut9']
            # hdl_uut9.configure('''interface {0}
            #                 speed 40000
            #                 no shutdown
            #                 interface {1}
            #                 speed 40000
            #                 no shutdown'''.format(alias_intf_mapping['uut9_uut8_1'],alias_intf_mapping['uut9_uut8_2']))
            #######################################################################################

            if not intf_obj:
                self.failed()
        else:
            pass
        
    @aetest.subsection
    def configureUnderlayOSPF(self,testscript,log):

        config_ospf = testscript.parameters['config_ospf']
        if config_ospf:
            #ospf_config_dict
            ospf_config_dict = testscript.parameters['configdict']['ospfv2_config_dict']
            node_dict = testscript.parameters['node_dict']
            
            obj_ospf=ospfv2_lib.configOspfv2(node_dict['all_dut'],ospf_config_dict,log)
            
            if not obj_ospf:
                self.failed()
        else:
            pass
            
    @aetest.subsection       
    def configureBGPNeighbors(self,testscript,log):

        config_bgp = testscript.parameters['config_bgp']
        
        if config_bgp:
        
            #BGP_config_dict 
            bgp_config_dict = testscript.parameters['configdict']['bgp_config_dict']
    
            node_dict = testscript.parameters['node_dict']
            
            for dut in bgp_config_dict.keys():
                obj_bgp=bgp_lib.configBgp(bgp_config_dict,node_dict['all_dut'],log)
                if not obj_bgp.Nodes(dut):
                    self.failed()
        else:
            pass

    @aetest.subsection                     
    def configureKeepAliveVRF(self,testscript,log):     
        
        config_keepalive_vrf = testscript.parameters['config_keepalive_vrf']
        config_dict = testscript.parameters['configdict']
        node_dict = testscript.parameters['node_dict']
        alias_intf_mapping = testscript.parameters['alias_intf_mapping']
        
        if config_keepalive_vrf:
            
            for node in config_dict['vrf_config_dict'].keys():
                hdl = node_dict['all_dut'][node]
                cfg = 'vrf context {0}'.format(config_dict['vrf_config_dict'][node])
                log.info('The value of cfg is : {0}'.format(cfg))
                hdl.configure(cfg)
        else:
            pass

    @aetest.subsection                     
    def configureTRMv6CLI(self,testscript,log):     
        
        config_trmv6 = testscript.parameters['config_trmv6']
        node_dict = testscript.parameters['node_dict']
        
        if config_trmv6:
            uut_list = ['uut1','uut2','uut5','uut6','uut7','uut9']
            for node in uut_list:
                hdl = node_dict['all_dut'][node]
                hdl.configure('''ip multicast multipath s-g-hash next-hop-based
                        ipv6 multicast multipath sg-nexthop-hash
                        ipv6 mld snooping
                        ipv6 mld snooping vxlan
                        system mld snooping
                        ''')
        else:
            pass
        
    @aetest.subsection       
    def configureVPCSwitches(self,testscript,log):
        
        config_vpc = testscript.parameters['config_vpc']
        
        if config_vpc:
            node_dict = testscript.parameters['node_dict']
            config_dict = testscript.parameters['configdict']
            for items in node_dict.keys():
                if re.search('Site',items):
                    log.info('The value of item is : {0}'.format(items))
                    for sub_items in node_dict[items].keys():
                        if re.search('VPC',sub_items, re.IGNORECASE):
                            vpc_vteps = node_dict[items][sub_items].keys()
                            log.info('The value of vpc_vteps is: {0}'.format(vpc_vteps))
                    
            
            for dut in vpc_vteps:
                hdl = node_dict['all_dut'][dut]
                d = config_bringup.setupConfigVpc(hdl,dut,log,config_dict)
        else:
            pass
        
    @aetest.subsection       
    def configurePIMNeighbors(self,testscript,log):

        config_pim = testscript.parameters['config_pim']
        
        if config_pim:
            intf_config_dict = testscript.parameters['configdict']['interface_config_dict']
      
            pim_config_dict = testscript.parameters['configdict']['pim_config_dict']
    
            node_dict = testscript.parameters['node_dict']
            
            for dut in pim_config_dict.keys():
                obj_pim = pim_lib.configPim(intf_config_dict,pim_config_dict,node_dict['all_dut'],log,'-dut {0}'.format(dut))
                
            if  obj_pim.result=='fail':
                self.failed()
        else:
            pass
        
    @aetest.subsection                     
    def configureGlobalVxlan(self,testscript,log):    
        
        config_vxlan_global = testscript.parameters['config_vxlan_global']
        config_dict = testscript.parameters['configdict']
        node_dict = testscript.parameters['node_dict']
        alias_intf_mapping = testscript.parameters['alias_intf_mapping']
        
        if config_vxlan_global:
            #SCALE_Config_dict
            scale_config_obj = MyLib.my_config_utils.ScaleConfig(log,node_dict,config_dict,alias_intf_mapping)
            vtep_dict = scale_config_obj.getMultisiteDeviceDict('all_vtep')
            
            log.info(banner('The value of vtep_dict is {0}'.format(vtep_dict)))
    
            res = scale_config_obj.configureGlobalVxlanParams(vtep_dict)
            
            if not res:
                self.failed()
        else:
            pass
        
    @aetest.subsection                     
    def configureGlobalBGP(self,testscript,log):    
        
        config_bgp_global = testscript.parameters['config_bgp_global']
        config_dict = testscript.parameters['configdict']
        node_dict = testscript.parameters['node_dict']
        alias_intf_mapping = testscript.parameters['alias_intf_mapping']
        
        if config_bgp_global:
            #SCALE_Config_dict
            scale_config_obj = MyLib.my_config_utils.ScaleConfig(log,node_dict,config_dict,alias_intf_mapping)
            vtep_dict = scale_config_obj.getMultisiteDeviceDict('all_vtep')
            #vtep_dict.update(node_dict['External_RP'])

            log.info(banner('The value of vtep_dict is {0}'.format(vtep_dict)))
            
            res = scale_config_obj.configureGlobalBGPParams(vtep_dict)
            if not res:
                self.failed()
        else:
            pass
        
    @aetest.subsection       
    def configureScaleVlan(self,testscript,log):
        
        config_vlan = testscript.parameters['config_vlan']
        config_dict = testscript.parameters['configdict']
        node_dict = testscript.parameters['node_dict']
        alias_intf_mapping = testscript.parameters['alias_intf_mapping']
        
        if config_vlan:
            #SCALE_Config_dict
            scale_config_obj = MyLib.my_config_utils.ScaleConfig(log,node_dict,config_dict,alias_intf_mapping)
            device_dict = scale_config_obj.getMultisiteDeviceDict('all_vtep')
            for items in node_dict.keys():
                if re.search('Site', items, re.IGNORECASE):
                    for sub_items in node_dict[items].keys():
                        if re.search('ACCESS', sub_items, re.IGNORECASE):
                            device_dict.update(node_dict[items][sub_items])
                if re.search('External', items, re.IGNORECASE):
                    device_dict.update(node_dict[items])
                            
            log.info('The value of device_dict is: {0}'.format(device_dict))

            log.info(banner('The value of device_dict_dict is : {0}'.format(device_dict)))
            
            res = scale_config_obj.configScaleVlans(device_dict)
    
            if not res:
                self.failed()
        else:
            pass
        
    @aetest.subsection  
    def configureScaleVRF(self,testscript,log):
        
        config_vrf = testscript.parameters['config_vrf']
        config_dict = testscript.parameters['configdict']
        node_dict = testscript.parameters['node_dict']
        alias_intf_mapping = testscript.parameters['alias_intf_mapping']
        
        if config_vrf:
            scale_config_obj = MyLib.my_config_utils.ScaleConfig(log,node_dict,config_dict,alias_intf_mapping)
            device_dict = scale_config_obj.getMultisiteDeviceDict('all_vtep')

            log.info(banner('The value of device_dict_dict is : {0}'.format(device_dict)))
            
            res = scale_config_obj.configScaleVRFs(device_dict)
            
            if not res:
                self.failed()
        else:
            pass

    @aetest.subsection       
    def configureScaleSVI(self,testscript,log):     
        
        config_svi = testscript.parameters['config_svi']
        config_dict = testscript.parameters['configdict']
        node_dict = testscript.parameters['node_dict']
        alias_intf_mapping = testscript.parameters['alias_intf_mapping']
        
        if config_svi:
            scale_config_obj = MyLib.my_config_utils.ScaleConfig(log,node_dict,config_dict,alias_intf_mapping)
            device_dict = scale_config_obj.getMultisiteDeviceDict('all_vtep')

            log.info(banner('The value of device_dict_dict is : {0}'.format(device_dict)))
            
            res = scale_config_obj.configScaleSVIs(device_dict)
            
            if not res:
                self.failed()
        else:
            pass

    @aetest.subsection                     
    def configureScaleEvpn(self,testscript,log):  
        
        config_evpn = testscript.parameters['config_evpn']
        config_dict = testscript.parameters['configdict']
        node_dict = testscript.parameters['node_dict']
        alias_intf_mapping = testscript.parameters['alias_intf_mapping']
                
        if config_evpn:
            scale_config_obj = MyLib.my_config_utils.ScaleConfig(log,node_dict,config_dict,alias_intf_mapping)
            vtep_dict = scale_config_obj.getMultisiteDeviceDict('all_vtep')
            log.info(banner('The value of vtep_dict is : {0}'.format(vtep_dict)))
    
            res = scale_config_obj.configScaleEVPN(vtep_dict)
            
            if not res:
                self.failed()
        else:
            pass

    @aetest.subsection                     
    def configureNveInterfaceGlobals(self,testscript,log):  
        
        config_nve_global = testscript.parameters['config_nve_global']
        config_dict = testscript.parameters['configdict']
        node_dict = testscript.parameters['node_dict']
        alias_intf_mapping = testscript.parameters['alias_intf_mapping']        
        
        if config_nve_global:
            
            scale_config_obj = MyLib.my_config_utils.ScaleConfig(log,node_dict,config_dict,alias_intf_mapping)
            vtep_dict = scale_config_obj.getMultisiteDeviceDict('all_vtep')
            log.info(banner('The value of vtep_dict is : {0}'.format(vtep_dict)))
    
            res = scale_config_obj.configureNveGlobal(vtep_dict)
            
            if not res:
                self.failed()
        else:
            pass
        
    @aetest.subsection                     
    def configureL2VNIOnNveInterface(self,testscript,log):     
        
        config_nve_l2vni = testscript.parameters['config_nve_l2vni']
        config_dict = testscript.parameters['configdict']
        node_dict = testscript.parameters['node_dict']  
        alias_intf_mapping = testscript.parameters['alias_intf_mapping'] 
        
        if config_nve_l2vni:
        
            scale_config_obj = MyLib.my_config_utils.ScaleConfig(log,node_dict,config_dict,alias_intf_mapping)
            vtep_dict = scale_config_obj.getMultisiteDeviceDict('all_vtep')
            log.info(banner('The value of vtep_dict is : {0}'.format(vtep_dict)))
    
            res = scale_config_obj.configureL2VNIOnNve(vtep_dict)
            
            if not res:
                self.failed()
        else:
            pass
        
    @aetest.subsection                     
    def configureL3VNIOnNveInterface(self,testscript,log):     
        
        config_nve_l3vni = testscript.parameters['config_nve_l3vni']
        config_dict = testscript.parameters['configdict']
        node_dict = testscript.parameters['node_dict']
        alias_intf_mapping = testscript.parameters['alias_intf_mapping'] 
        
        if config_nve_l3vni:
        
            scale_config_obj = MyLib.my_config_utils.ScaleConfig(log,node_dict,config_dict,alias_intf_mapping)
            vtep_dict = scale_config_obj.getMultisiteDeviceDict('all_vtep')
            log.info(banner('The value of vtep_dict is : {0}'.format(vtep_dict)))
    
            res = scale_config_obj.configureL3VNIOnNve(vtep_dict)
            
            if not res:
                self.failed()
        else:
            pass

    @aetest.subsection                     
    def configureLoopbackInterfaces(self,testscript,log):     
        
        config_loopback_intf = testscript.parameters['config_loopback_intf']
        config_dict = testscript.parameters['configdict']
        node_dict = testscript.parameters['node_dict']
        alias_intf_mapping = testscript.parameters['alias_intf_mapping']
        
        if config_loopback_intf:
        
            scale_config_obj = MyLib.my_config_utils.ScaleConfig(log,node_dict,config_dict,alias_intf_mapping)
            external_rp_dict = scale_config_obj.getMultisiteDeviceDict('all_vtep')

            log.info(banner('The value of external_rp_dict is : {0}'.format(external_rp_dict)))
    
            res = scale_config_obj.configureLoopbackInterface(external_rp_dict)
             
            if not res:
                self.failed()
        else:
            pass

    @aetest.subsection                     
    def configureMultisiteConfigs(self,testscript,log):     
        
        config_multisite = testscript.parameters['config_multisite']
        config_dict = testscript.parameters['configdict']
        node_dict = testscript.parameters['node_dict']
        alias_intf_mapping = testscript.parameters['alias_intf_mapping'] 
        
        if config_multisite:
        
            multisite_config_dict = config_dict['multisite_config_dict']
    
            for dut in multisite_config_dict.keys():
                obj_ms=MyLib.my_multisite_lib.configMultisite(multisite_config_dict,node_dict,alias_intf_mapping,log)
                if not obj_ms.Nodes(dut):
                    self.failed()
        else:
            pass

    @aetest.subsection                     
    def configureGlobalRouteMaps(self,testscript,log):     
        
        config_route_map = testscript.parameters['config_route_map']
        config_dict = testscript.parameters['configdict']
        node_dict = testscript.parameters['node_dict']
        alias_intf_mapping = testscript.parameters['alias_intf_mapping']
        
        if config_route_map:
            
            scale_config_obj = MyLib.my_config_utils.ScaleConfig(log,node_dict,config_dict,alias_intf_mapping)
            temp_dict = scale_config_obj.getMultisiteDeviceDict('bgw')
            dci_dict= node_dict['DCI']
            log.info('The value of dci_dict is : {0}'.format(dci_dict))
            temp_dict.update(dci_dict)
            route_map_config_dict = config_dict['route_map_config_dict']
            res = routing_utils.configRouteMaps(log,temp_dict,route_map_config_dict)
                
        else:
            pass    

    @aetest.subsection                     
    def verifyConfiguationsBeforeStartOfTest(self,testscript,log,steps):
        config_dict = testscript.parameters['configdict']
        node_dict = testscript.parameters['node_dict']
        alias_intf_mapping = testscript.parameters['alias_intf_mapping']
        
        scale_config_obj = MyLib.my_config_utils.ScaleConfig(log,node_dict,config_dict,alias_intf_mapping)
        vtep_dict = scale_config_obj.getMultisiteDeviceDict('all_vtep')
                
        verify_obj = MyLib.my_config_utils.VerifyConfigs(log,config_dict,node_dict,alias_intf_mapping)
        '''
        with steps.start('Verify OSPFv2 Neighborship on all duts') as s:
            log.info('Verifying the OSPFv2 Neighborship on all duts ......')
            res = verify_obj.verifyOSPFv4Neighorship()
            if not res:
                self.failed()


        log.info('Waiting for 30 seconds before checking the BGP Neighborship')
        countDownTimer(30)
        with steps.start('Verify BGP L2EVPN Neighborship on all duts') as s:
            log.info('Verify BGP L2EVPN Neighborship on all duts ......')
            res = verify_obj.verifyBGPL2EVPNNeighbor()
            if not res:
                self.failed()

        with steps.start('Verify BGP L2EVPN Neighborship on all duts') as s:
            log.info('Verify BGP mVPN Neighborship on all duts ......')
            res = verify_obj.verifyBGPL2EVPNNeighbor()
            if not res:
                self.failed()
                        
        with steps.start('Verify L2 and L3 VNI Status on all VTEPS') as s:
            log.info('Verifying L2 and L3 VNI status on all VTEPs ......')
            res = verify_obj.verifyVNIStatus(vtep_dict)
            if not res:
                self.failed()

        with steps.start('Verify Nve Peers in VTEPs') as s:
            log.info('VVerify Nve Peers in VTEPs ......')
            res = verify_obj.verifyNVEStatus(vtep_dict)
            if not res:
                self.failed()  
        
        log.info(banner('Waiting for 30 seconds before Configuring the Traffic ... {0}'.format(countDownTimer(30))))
    
        '''
        
    @aetest.subsection                     
    def Connect_To_Ixia(self,testscript,log):     
        
        tgn_connect =  testscript.parameters['tgn_connect']
        configdict = testscript.parameters['configdict']
        node_dict = testscript.parameters['node_dict']
        alias_intf_mapping = testscript.parameters['alias_intf_mapping']
        
        tp_uut1 = alias_intf_mapping['TG1_uut1_1']
        tp_uut2 = alias_intf_mapping['TG1_uut2_1']
        tp_uut3 = alias_intf_mapping['TG1_uut3_1']
        tp_uut5 = alias_intf_mapping['TG1_uut5_1']
        tp_uut9 = alias_intf_mapping['TG1_uut9_1']

        ixia_lc_port_uut1 = tp_uut1.split('/')
        ixia_lc_port_uut2 = tp_uut2.split('/')
        ixia_lc_port_uut3 = tp_uut3.split('/')
        ixia_lc_port_uut5 = tp_uut5.split('/')
        ixia_lc_port_uut9 = tp_uut9.split('/')

        # Fetch IXIA Details via TB File
        # IXIA = node_dict['all_dut']['TG1']
        # ixChassisIpList = utils.strtolist(str(IXIA.connections.hltapi.ip))
        # apiServerIp = str(IXIA.connections.hltapi.tcl_server)

        # Fetch IXIA Details via Config File
        ns = parseTGParams(configdict['tg_config_dict'],log)
        apiServerIp = ns.apiServerIp
        ixChassisIpList = utils.strtolist(ns.ixChassisIpList)
        configFile = ns.configFile
        portList = [[ixChassisIpList[0], ixia_lc_port_uut1[0], ixia_lc_port_uut1[1]], [ixChassisIpList[0], ixia_lc_port_uut2[0], ixia_lc_port_uut2[1]], [ixChassisIpList[0], ixia_lc_port_uut3[0], ixia_lc_port_uut3[1]] , [ixChassisIpList[0], ixia_lc_port_uut5[0], ixia_lc_port_uut5[1]], [ixChassisIpList[0], ixia_lc_port_uut9[0], ixia_lc_port_uut9[1]]]

        if tgn_connect:
            # Connect and confiure TG
            # apiServerIp = '10.225.127.16'
            # ixChassisIpList = ['10.197.127.16']
            # portList = [[ixChassisIpList[0], 2, 9], [ixChassisIpList[0], 2, 11], [ixChassisIpList[0], 2, 12] , [ixChassisIpList[0], 2, 13], [ixChassisIpList[0], 2, 5]]
            # configFile = '/ws/jumashan-bgl/DCI_MCAST_512_400.ixncfg'

            # Forcefully take port ownership if the portList are owned by other users.
            forceTakePortOwnership = True

            # LogLevel: none, info, warning, request, request_response, all
            testscript.parameters['session'] = session = SessionAssistant(IpAddress=apiServerIp, RestPort=None, UserName='admin', Password='admin', 
                               SessionName=None, SessionId=None, ApiKey=None,
                               ClearConfig=True, LogLevel='all', LogFilename='restpy.log')

            testscript.parameters['ixNetwork'] = ixNetwork = session.Ixnetwork

            #######Load a saved config file
            ixNetwork.info('Loading config file: {0}'.format(configFile))
            ixNetwork.LoadConfig(Files(configFile, local_file=True))

            # Assign ports. Map physical ports to the configured vports.
            portMap = session.PortMapAssistant()
            vport = dict()
            for index,port in enumerate(portList):
                # For the port name, get the loaded configuration's port name
                portName = ixNetwork.Vport.find()[index].Name
                portMap.Map(IpAddress=port[0], CardId=port[1], PortId=port[2], Name=portName)
                    
            portMap.Connect(forceTakePortOwnership)

        else:
            pass

# *****************************************************************************************************************************#

class TC000_Verify_Steady_State(aetest.Testcase):
    """ TC000_Verify_Steady_State """

    @aetest.test
    def Verify_Steady_State(self,testscript,log):
        """ Verify_Steady_State """

        node_dict = testscript.parameters['node_dict']
        
        for dut in node_dict['all_dut']:
            if not re.search(r'TG',dut,re.I):
                hdl = node_dict['all_dut'][dut]
                hdl.configure('''show version''')

        result = verifyTraffic(testscript)
        if result['status'] == 0:
            self.failed(reason=result['msgs'])
        else:
            self.passed(reason=result['msgs'])

# *****************************************************************************************************************************#

class TC001_vPC_BGW_NVE_Flap(aetest.Testcase):
    """ TC001_vPC_BGW_NVE_Flap """

    @aetest.test
    def vPC_BGW_NVE_Flap(self,testscript):
        """ vPC_BGW_NVE_Flap """

        node_dict = testscript.parameters['node_dict']

        uut_list = ['uut1','uut2']
        for node in uut_list:
            hdl = node_dict['all_dut'][node]
            hdl.configure('''interface nve 1
                            shutdown''')

        time.sleep(60)

        for node in uut_list:
            hdl = node_dict['all_dut'][node]
            hdl.configure('''interface nve 1
                            no shutdown''')

        time.sleep(100)

    @aetest.test
    def Verify_Traffic_Post_Trigger(self, testscript,log):
        """ Verify_Traffic_Post_Trigger """

        result = verifyTraffic(testscript)
        if result['status'] == 0:
            self.failed(reason=result['msgs'])
        else:
            self.passed(reason=result['msgs'])

# *****************************************************************************************************************************#

class TC002_AC_BGW_BGW_NVE_Flap(aetest.Testcase):
    """ TC002_AC_BGW_BGW_NVE_Flap """

    @aetest.test
    def AC_BGW_NVE_Flap(self, testscript):
        """ AC_BGW_NVE_Flap """

        node_dict = testscript.parameters['node_dict']

        uut_list = ['uut6','uut7']
        for node in uut_list:
            hdl = node_dict['all_dut'][node]
            hdl.configure('''interface nve 1
                            shutdown''')

        time.sleep(60)

        for node in uut_list:
            hdl = node_dict['all_dut'][node]
            hdl.configure('''interface nve 1
                            no shutdown''')

        time.sleep(100)

    @aetest.test
    def Verify_Traffic_Post_Trigger(self, testscript,log):
        """ Verify_Traffic_Post_Trigger """

        result = verifyTraffic(testscript)
        if result['status'] == 0:
            self.failed(reason=result['msgs'])
        else:
            self.passed(reason=result['msgs'])

# *****************************************************************************************************************************#

class TC003_Site_1_LEAF_NVE_Flap(aetest.Testcase):
    """ TC003_Site_1_LEAF_NVE_Flap """

    @aetest.test
    def Site_1_LEAF_NVE_Flap(self, testscript):
        """ Site_1_LEAF_NVE_Flap """

        node_dict = testscript.parameters['node_dict']

        uut_list = ['uut5']
        for node in uut_list:
            hdl = node_dict['all_dut'][node]
            hdl.configure('''interface nve 1
                            shutdown''')

        time.sleep(60)

        for node in uut_list:
            hdl = node_dict['all_dut'][node]
            hdl.configure('''interface nve 1
                            no shutdown''')

        time.sleep(100)

    @aetest.test
    def Verify_Traffic_Post_Trigger(self, testscript,log):
        """ Verify_Traffic_Post_Trigger """

        result = verifyTraffic(testscript)
        if result['status'] == 0:
            self.failed(reason=result['msgs'])
        else:
            self.passed(reason=result['msgs'])

# *****************************************************************************************************************************#

class TC004_Site_2_LEAF_NVE_Flap(aetest.Testcase):
    """ TC004_Site_2_LEAF_NVE_Flap """

    @aetest.test
    def Site_2_LEAF_NVE_Flap(self, testscript):
        """ Site_2_LEAF_NVE_Flap """

        node_dict = testscript.parameters['node_dict']

        uut_list = ['uut9']
        for node in uut_list:
            hdl = node_dict['all_dut'][node]
            hdl.configure('''interface nve 1
                            shutdown''')

        time.sleep(60)

        for node in uut_list:
            hdl = node_dict['all_dut'][node]
            hdl.configure('''interface nve 1
                            no shutdown''')

        time.sleep(100)

    @aetest.test
    def Verify_Traffic_Post_Trigger(self, testscript,log):
        """ Verify_Traffic_Post_Trigger """

        result = verifyTraffic(testscript)
        if result['status'] == 0:
            self.failed(reason=result['msgs'])
        else:
            self.passed(reason=result['msgs'])

# *****************************************************************************************************************************#

class TC005_vPC_BGW_Fab_Link_Flap(aetest.Testcase):
    """ TC005_vPC_BGW_Fab_Link_Flap """

    @aetest.test
    def vPC_BGW_Fab_Link_Flap(self, testscript):
        """ vPC_BGW_Fab_Link_Flap """

        node_dict = testscript.parameters['node_dict']
        alias_intf_mapping = testscript.parameters['alias_intf_mapping']

        uut_list = ['uut1','uut2']
        for node in uut_list:
            hdl = node_dict['all_dut'][node]
            hdl.configure('''interface {0}
                            shutdown
                            interface {1}
                            shutdown'''.format(alias_intf_mapping[node+'_uut4_1'],alias_intf_mapping[node+'_uut4_2']))

        time.sleep(60)

        for node in uut_list:
            hdl = node_dict['all_dut'][node]
            hdl.configure('''interface {0}
                            no shutdown
                            interface {1}
                            no shutdown'''.format(alias_intf_mapping[node+'_uut4_1'],alias_intf_mapping[node+'_uut4_2']))

        time.sleep(100)

    @aetest.test
    def Verify_Traffic_Post_Trigger(self, testscript,log):
        """ Verify_Traffic_Post_Trigger """

        result = verifyTraffic(testscript)
        if result['status'] == 0:
            self.failed(reason=result['msgs'])
        else:
            self.passed(reason=result['msgs'])

# *****************************************************************************************************************************#

class TC006_AC_BGW_Fab_Link_Flap(aetest.Testcase):
    """ TC006_AC_BGW_Fab_Link_Flap """

    @aetest.test
    def AC_BGW_Fab_Link_Flap(self, testscript):
        """ AC_BGW_Fab_Link_Flap """

        node_dict = testscript.parameters['node_dict']
        alias_intf_mapping = testscript.parameters['alias_intf_mapping']

        uut_list = ['uut6','uut7']
        for node in uut_list:
            hdl = node_dict['all_dut'][node]
            hdl.configure('''interface {0}
                            shutdown
                            interface {1}
                            shutdown'''.format(alias_intf_mapping[node+'_uut8_1'],alias_intf_mapping[node+'_uut8_2']))

        time.sleep(60)

        for node in uut_list:
            hdl = node_dict['all_dut'][node]
            hdl.configure('''interface {0}
                            no shutdown
                            interface {1}
                            no shutdown'''.format(alias_intf_mapping[node+'_uut8_1'],alias_intf_mapping[node+'_uut8_2']))

        time.sleep(100)

    @aetest.test
    def Verify_Traffic_Post_Trigger(self, testscript,log):
        """ Verify_Traffic_Post_Trigger """

        result = verifyTraffic(testscript)
        if result['status'] == 0:
            self.failed(reason=result['msgs'])
        else:
            self.passed(reason=result['msgs'])

# *****************************************************************************************************************************#

class TC007_Site_1_LEAF_Fab_Link_Flap(aetest.Testcase):
    """ TC007_Site_1_LEAF_Fab_Link_Flap """

    @aetest.test
    def Site_1_LEAF_Fab_Link_Flap(self, testscript):
        """ Site_1_LEAF_Fab_Link_Flap """

        node_dict = testscript.parameters['node_dict']
        alias_intf_mapping = testscript.parameters['alias_intf_mapping']

        uut_list = ['uut5']
        for node in uut_list:
            hdl = node_dict['all_dut'][node]
            hdl.configure('''interface {0}
                            shutdown
                            interface {1}
                            shutdown'''.format(alias_intf_mapping[node+'_uut4_1'],alias_intf_mapping[node+'_uut4_2']))

        time.sleep(60)

        for node in uut_list:
            hdl = node_dict['all_dut'][node]
            hdl.configure('''interface {0}
                            no shutdown
                            interface {1}
                            no shutdown'''.format(alias_intf_mapping[node+'_uut4_1'],alias_intf_mapping[node+'_uut4_2']))

        time.sleep(100)

    @aetest.test
    def Verify_Traffic_Post_Trigger(self, testscript,log):
        """ Verify_Traffic_Post_Trigger """

        result = verifyTraffic(testscript)
        if result['status'] == 0:
            self.failed(reason=result['msgs'])
        else:
            self.passed(reason=result['msgs'])

# *****************************************************************************************************************************#

class TC008_Site_2_LEAF_Fab_Link_Flap(aetest.Testcase):
    """ TC008_Site_2_LEAF_Fab_Link_Flap """

    @aetest.test
    def Site_2_LEAF_Fab_Link_Flap(self, testscript):
        """ Site_2_LEAF_Fab_Link_Flap """

        node_dict = testscript.parameters['node_dict']
        alias_intf_mapping = testscript.parameters['alias_intf_mapping']

        uut_list = ['uut9']
        for node in uut_list:
            hdl = node_dict['all_dut'][node]
            hdl.configure('''interface {0}
                            shutdown
                            interface {1}
                            shutdown'''.format(alias_intf_mapping[node+'_uut8_1'],alias_intf_mapping[node+'_uut8_2']))

        time.sleep(60)

        for node in uut_list:
            hdl = node_dict['all_dut'][node]
            hdl.configure('''interface {0}
                            no shutdown
                            interface {1}
                            no shutdown'''.format(alias_intf_mapping[node+'_uut8_1'],alias_intf_mapping[node+'_uut8_2']))

        time.sleep(100)

    @aetest.test
    def Verify_Traffic_Post_Trigger(self, testscript,log):
        """ Verify_Traffic_Post_Trigger """

        result = verifyTraffic(testscript)
        if result['status'] == 0:
            self.failed(reason=result['msgs'])
        else:
            self.passed(reason=result['msgs'])

# *****************************************************************************************************************************#

class TC009_vPC_BGW_DCI_Link_Flap(aetest.Testcase):
    """ TC009_vPC_BGW_DCI_Link_Flap """

    @aetest.test
    def vPC_BGW_DCI_Link_Flap(self, testscript):
        """ vPC_BGW_DCI_Link_Flap """

        node_dict = testscript.parameters['node_dict']
        alias_intf_mapping = testscript.parameters['alias_intf_mapping']

        uut_list = ['uut1','uut2']
        for node in uut_list:
            hdl = node_dict['all_dut'][node]
            hdl.configure('''interface {0}
                            shutdown
                            interface {1}
                            shutdown'''.format(alias_intf_mapping[node+'_uut10_1'],alias_intf_mapping[node+'_uut10_2']))

        time.sleep(60)

        for node in uut_list:
            hdl = node_dict['all_dut'][node]
            hdl.configure('''interface {0}
                            no shutdown
                            interface {1}
                            no shutdown'''.format(alias_intf_mapping[node+'_uut10_1'],alias_intf_mapping[node+'_uut10_2']))

        time.sleep(100)

    @aetest.test
    def Verify_Traffic_Post_Trigger(self, testscript,log):
        """ Verify_Traffic_Post_Trigger """

        result = verifyTraffic(testscript)
        if result['status'] == 0:
            self.failed(reason=result['msgs'])
        else:
            self.passed(reason=result['msgs'])

# *****************************************************************************************************************************#

class TC010_AC_BGW_DCI_Link_Flap(aetest.Testcase):
    """ TC010_AC_BGW_DCI_Link_Flap """

    @aetest.test
    def AC_BGW_DCI_Link_Flap(self, testscript):
        """ AC_BGW_DCI_Link_Flap """

        node_dict = testscript.parameters['node_dict']
        alias_intf_mapping = testscript.parameters['alias_intf_mapping']

        uut_list = ['uut6','uut7']
        for node in uut_list:
            hdl = node_dict['all_dut'][node]
            hdl.configure('''interface {0}
                            shutdown
                            interface {1}
                            shutdown'''.format(alias_intf_mapping[node+'_uut10_1'],alias_intf_mapping[node+'_uut10_2']))

        time.sleep(60)

        for node in uut_list:
            hdl = node_dict['all_dut'][node]
            hdl.configure('''interface {0}
                            no shutdown
                            interface {1}
                            no shutdown'''.format(alias_intf_mapping[node+'_uut10_1'],alias_intf_mapping[node+'_uut10_2']))

        time.sleep(100)

    @aetest.test
    def Verify_Traffic_Post_Trigger(self, testscript,log):
        """ Verify_Traffic_Post_Trigger """

        result = verifyTraffic(testscript)
        if result['status'] == 0:
            self.failed(reason=result['msgs'])
        else:
            self.passed(reason=result['msgs'])

# *****************************************************************************************************************************#

class TC011_vPC_MultiSite_Loopback_Flap(aetest.Testcase):
    """ TC011_vPC_MultiSite_Loopback_Flap """

    @aetest.test
    def vPC_MultiSite_Loopback_Flap(self, testscript):
        """ vPC_MultiSite_Loopback_Flap """

        node_dict = testscript.parameters['node_dict']

        uut_list = ['uut1','uut2']
        for node in uut_list:
            hdl = node_dict['all_dut'][node]
            hdl.configure('''interface loopback2
                            shutdown
                        ''')

        time.sleep(60)

        for node in uut_list:
            hdl = node_dict['all_dut'][node]
            hdl.configure('''interface loopback2
                            no shutdown
                        ''')

        time.sleep(100)

    @aetest.test
    def Verify_Traffic_Post_Trigger(self, testscript,log):
        """ Verify_Traffic_Post_Trigger """

        result = verifyTraffic(testscript)
        if result['status'] == 0:
            self.failed(reason=result['msgs'])
        else:
            self.passed(reason=result['msgs'])

# *****************************************************************************************************************************#

class TC012_AC_MultiSite_Loopback_Flap(aetest.Testcase):
    """ TC012_AC_MultiSite_Loopback_Flap """

    @aetest.test
    def AC_MultiSite_Loopback_Flap(self, testscript):
        """ AC_MultiSite_Loopback_Flap """

        node_dict = testscript.parameters['node_dict']

        uut_list = ['uut6','uut7']
        for node in uut_list:
            hdl = node_dict['all_dut'][node]
            hdl.configure('''interface loopback2
                            shutdown
                        ''')

        time.sleep(60)

        for node in uut_list:
            hdl = node_dict['all_dut'][node]
            hdl.configure('''interface loopback2
                            no shutdown
                        ''')

        time.sleep(100)

    @aetest.test
    def Verify_Traffic_Post_Trigger(self, testscript,log):
        """ Verify_Traffic_Post_Trigger """

        result = verifyTraffic(testscript)
        if result['status'] == 0:
            self.failed(reason=result['msgs'])
        else:
            self.passed(reason=result['msgs'])

# *****************************************************************************************************************************#

class TC013_vPC_IntraSite_Loopback_Flap(aetest.Testcase):
    """ TC013_vPC_IntraSite_Loopback_Flap """

    @aetest.test
    def vPC_IntraSite_Loopback_Flap(self, testscript):
        """ vPC_IntraSite_Loopback_Flap """

        node_dict = testscript.parameters['node_dict']

        uut_list = ['uut1','uut2']
        for node in uut_list:
            hdl = node_dict['all_dut'][node]
            hdl.configure('''interface loopback1
                            shutdown
                        ''')

        time.sleep(60)

        for node in uut_list:
            hdl = node_dict['all_dut'][node]
            hdl.configure('''interface loopback1
                            no shutdown
                        ''')

        time.sleep(100)

    @aetest.test
    def Verify_Traffic_Post_Trigger(self, testscript,log):
        """ Verify_Traffic_Post_Trigger """

        result = verifyTraffic(testscript)
        if result['status'] == 0:
            self.failed(reason=result['msgs'])
        else:
            self.passed(reason=result['msgs'])

# *****************************************************************************************************************************#

class TC014_AC_IntraSite_Loopback_Flap(aetest.Testcase):
    """ TC014_AC_IntraSite_Loopback_Flap """

    @aetest.test
    def AC_IntraSite_Loopback_Flap(self, testscript):
        """ AC_IntraSite_Loopback_Flap """

        node_dict = testscript.parameters['node_dict']

        uut_list = ['uut6','uut7']
        for node in uut_list:
            hdl = node_dict['all_dut'][node]
            hdl.configure('''interface loopback1
                            shutdown
                        ''')

        time.sleep(60)

        for node in uut_list:
            hdl = node_dict['all_dut'][node]
            hdl.configure('''interface loopback1
                            no shutdown
                        ''')

        time.sleep(100)

    @aetest.test
    def Verify_Traffic_Post_Trigger(self, testscript,log):
        """ Verify_Traffic_Post_Trigger """

        result = verifyTraffic(testscript)
        if result['status'] == 0:
            self.failed(reason=result['msgs'])
        else:
            self.passed(reason=result['msgs'])

# *****************************************************************************************************************************#

class TC015_Site_1_Loopback_Flap(aetest.Testcase):
    """ TC015_Site_1_Loopback_Flap """

    @aetest.test
    def Site_1_Loopback_Flap(self, testscript):
        """ Site_1_Loopback_Flap """

        node_dict = testscript.parameters['node_dict']

        uut_list = ['uut5']
        for node in uut_list:
            hdl = node_dict['all_dut'][node]
            hdl.configure('''interface loopback1
                            shutdown
                        ''')

        time.sleep(60)

        for node in uut_list:
            hdl = node_dict['all_dut'][node]
            hdl.configure('''interface loopback1
                            no shutdown
                        ''')

        time.sleep(100)

    @aetest.test
    def Verify_Traffic_Post_Trigger(self, testscript,log):
        """ Verify_Traffic_Post_Trigger """

        result = verifyTraffic(testscript)
        if result['status'] == 0:
            self.failed(reason=result['msgs'])
        else:
            self.passed(reason=result['msgs'])

# *****************************************************************************************************************************#

class TC016_Site_2_Loopback_Flap(aetest.Testcase):
    """ TC016_Site_2_Loopback_Flap """

    @aetest.test
    def Site_2_Loopback_Flap(self, testscript):
        """ Site_2_Loopback_Flap """

        node_dict = testscript.parameters['node_dict']

        uut_list = ['uut9']
        for node in uut_list:
            hdl = node_dict['all_dut'][node]
            hdl.configure('''interface loopback1
                            shutdown
                        ''')

        time.sleep(60)

        for node in uut_list:
            hdl = node_dict['all_dut'][node]
            hdl.configure('''interface loopback1
                            no shutdown
                        ''')

        time.sleep(100)

    @aetest.test
    def Verify_Traffic_Post_Trigger(self, testscript,log):
        """ Verify_Traffic_Post_Trigger """

        result = verifyTraffic(testscript)
        if result['status'] == 0:
            self.failed(reason=result['msgs'])
        else:
            self.passed(reason=result['msgs'])

# *****************************************************************************************************************************#

class TC017_vPC_BGW_Domain_Flap(aetest.Testcase):
    """ TC017_vPC_BGW_Domain_Flap """

    @aetest.test
    def vPC_BGW_Domain_Flap(self, testscript, log):
        """ vPC_BGW_Domain_Flap """

        node_dict = testscript.parameters['node_dict']
        configdict = testscript.parameters['configdict']

        uut_list = ['uut1','uut2']
        for node in uut_list:
            hdl = node_dict['all_dut'][node]
            hdl.configure('''vpc domain {0}
                            shutdown
                        '''.format(parseVpcDomainParams(configdict['vpc_config_dict'][node]['vpc_domain'],log).domain_id))

        time.sleep(60)

        for node in uut_list:
            hdl = node_dict['all_dut'][node]
            hdl.configure('''vpc domain {0}
                            no shutdown
                        '''.format(parseVpcDomainParams(configdict['vpc_config_dict'][node]['vpc_domain'],log).domain_id))

        time.sleep(100)

    @aetest.test
    def Verify_Traffic_Post_Trigger(self, testscript,log):
        """ Verify_Traffic_Post_Trigger """

        result = verifyTraffic(testscript)
        if result['status'] == 0:
            self.failed(reason=result['msgs'])
        else:
            self.passed(reason=result['msgs'])

# *****************************************************************************************************************************#

class TC018_vPC_BGW_MCT_Flap(aetest.Testcase):
    """ TC018_vPC_BGW_MCT_Flap """

    @aetest.test
    def vPC_BGW_MCT_Flap(self, testscript, log):
        """ vPC_BGW_MCT_Flap """

        node_dict = testscript.parameters['node_dict']
        configdict = testscript.parameters['configdict']

        uut_list = ['uut1','uut2']
        for node in uut_list:
            hdl = node_dict['all_dut'][node]
            hdl.configure('''interface port-channel {0}
                            shutdown
                        '''.format(parseVpcPeerLinkParams(configdict['vpc_config_dict'][node]['vpc_peer_link'],log).pc_no))

        time.sleep(60)

        for node in uut_list:
            hdl = node_dict['all_dut'][node]
            hdl.configure('''interface port-channel {0}
                            no shutdown
                        '''.format(parseVpcPeerLinkParams(configdict['vpc_config_dict'][node]['vpc_peer_link'],log).pc_no))

        time.sleep(100)

    @aetest.test
    def Verify_Traffic_Post_Trigger(self, testscript,log):
        """ Verify_Traffic_Post_Trigger """

        result = verifyTraffic(testscript)
        if result['status'] == 0:
            self.failed(reason=result['msgs'])
        else:
            self.passed(reason=result['msgs'])

# *****************************************************************************************************************************#

class TC019_vPC_BGW_Leg_Flap(aetest.Testcase):
    """ TC019_vPC_BGW_Leg_Flap """

    @aetest.test
    def vPC_BGW_Leg_Flap(self, testscript, log):
        """ vPC_BGW_Leg_Flap """

        node_dict = testscript.parameters['node_dict']
        configdict = testscript.parameters['configdict']

        uut_list = ['uut1','uut2']
        for node in uut_list:
            hdl = node_dict['all_dut'][node]
            hdl.configure('''interface port-channel {0}
                            shutdown
                        '''.format(parseVpcPCParams(configdict['vpc_config_dict'][node]['vpc_port_channels']['port-channel1'],log).pc_no))

        time.sleep(60)

        for node in uut_list:
            hdl = node_dict['all_dut'][node]
            hdl.configure('''interface port-channel {0}
                            no shutdown
                        '''.format(parseVpcPCParams(configdict['vpc_config_dict'][node]['vpc_port_channels']['port-channel1'],log).pc_no))

        time.sleep(100)

    @aetest.test
    def Verify_Traffic_Post_Trigger(self, testscript,log):
        """ Verify_Traffic_Post_Trigger """

        result = verifyTraffic(testscript)
        if result['status'] == 0:
            self.failed(reason=result['msgs'])
        else:
            self.passed(reason=result['msgs'])

# *****************************************************************************************************************************#

class TC020_vPC_BGW_Remove_Add_L2_VN_Segment(aetest.Testcase):
    """ TC020_vPC_BGW_Remove_Add_L2_VN_Segment """

    @aetest.test
    def vPC_BGW_Remove_Add_L2_VN_Segment(self, testscript, log):
        """ vPC_BGW_Remove_Add_L2_VN_Segment """

        node_dict = testscript.parameters['node_dict']
        configdict = testscript.parameters['configdict']

        #Removing L2VNIs for VLANs
        uut_list = ['uut1','uut2']
        for node in uut_list:
            hdl = node_dict['all_dut'][node]
            ns = MyLib.my_config_utils.parseScaleVlanParms(log,configdict['scale_config_dict'][node]['global']['vlan'])
            for i in range(5):
                hdl.configure('''vlan {0}
                                no vn-segment {1} 
                            '''.format(ns.l2_vlan_start+i,ns.l2_vni_start+i))

        time.sleep(60)

        #Adding L2VNIs for VLANs
        for node in uut_list:
            hdl = node_dict['all_dut'][node]
            ns = MyLib.my_config_utils.parseScaleVlanParms(log,configdict['scale_config_dict'][node]['global']['vlan'])
            for i in range(5):
                hdl.configure('''vlan {0}
                                vn-segment {1} 
                            '''.format(ns.l2_vlan_start+i,ns.l2_vni_start+i))

        time.sleep(100)

    @aetest.test
    def Verify_Traffic_Post_Trigger(self, testscript,log):
        """ Verify_Traffic_Post_Trigger """

        result = verifyTraffic(testscript)
        if result['status'] == 0:
            self.failed(reason=result['msgs'])
        else:
            self.passed(reason=result['msgs'])

# *****************************************************************************************************************************#

class TC021_vPC_BGW_Remove_Add_L3_VN_Segment(aetest.Testcase):
    """ TC021_vPC_BGW_Remove_Add_L3_VN_Segment """

    @aetest.test
    def vPC_BGW_Remove_Add_L3_VN_Segment(self, testscript, log):
        """ vPC_BGW_Remove_Add_L3_VN_Segment """

        node_dict = testscript.parameters['node_dict']
        configdict = testscript.parameters['configdict']

        #Removing L3VNIs for VLANs
        uut_list = ['uut1','uut2']
        for node in uut_list:
            hdl = node_dict['all_dut'][node]
            ns = MyLib.my_config_utils.parseScaleVlanParms(log,configdict['scale_config_dict'][node]['global']['vlan'])
            for i in range(5):
                hdl.configure('''vlan {0}
                                no vn-segment {1} 
                            '''.format(ns.l3_vlan_start+i,ns.l3_vni_start+i))

        time.sleep(60)

        #Adding L3VNIs for VLANs
        for node in uut_list:
            hdl = node_dict['all_dut'][node]
            ns = MyLib.my_config_utils.parseScaleVlanParms(log,configdict['scale_config_dict'][node]['global']['vlan'])
            for i in range(5):
                hdl.configure('''vlan {0}
                                vn-segment {1} 
                            '''.format(ns.l3_vlan_start+i,ns.l3_vni_start+i))

        time.sleep(100)

    @aetest.test
    def Verify_Traffic_Post_Trigger(self, testscript,log):
        """ Verify_Traffic_Post_Trigger """

        result = verifyTraffic(testscript)
        if result['status'] == 0:
            self.failed(reason=result['msgs'])
        else:
            self.passed(reason=result['msgs'])

# *****************************************************************************************************************************#

class TC022_AC_BGW_Remove_Add_L2_VN_Segment(aetest.Testcase):
    """ TC022_AC_BGW_Remove_Add_L2_VN_Segment """

    @aetest.test
    def AC_BGW_Remove_Add_L2_VN_Segment(self, testscript, log):
        """ AC_BGW_Remove_Add_L2_VN_Segment """

        node_dict = testscript.parameters['node_dict']
        configdict = testscript.parameters['configdict']

        #Removing L2VNIs for VLANs
        uut_list = ['uut6','uut7']
        for node in uut_list:
            hdl = node_dict['all_dut'][node]
            ns = MyLib.my_config_utils.parseScaleVlanParms(log,configdict['scale_config_dict'][node]['global']['vlan'])
            for i in range(5):
                hdl.configure('''vlan {0}
                                no vn-segment {1} 
                            '''.format(ns.l2_vlan_start+i,ns.l2_vni_start+i))

        time.sleep(60)

        #Adding L2VNIs for VLANs
        for node in uut_list:
            hdl = node_dict['all_dut'][node]
            ns = MyLib.my_config_utils.parseScaleVlanParms(log,configdict['scale_config_dict'][node]['global']['vlan'])
            for i in range(5):
                hdl.configure('''vlan {0}
                                vn-segment {1} 
                            '''.format(ns.l2_vlan_start+i,ns.l2_vni_start+i))

        time.sleep(100)

    @aetest.test
    def Verify_Traffic_Post_Trigger(self, testscript,log):
        """ Verify_Traffic_Post_Trigger """

        result = verifyTraffic(testscript)
        if result['status'] == 0:
            self.failed(reason=result['msgs'])
        else:
            self.passed(reason=result['msgs'])

# *****************************************************************************************************************************#

class TC023_AC_BGW_Remove_Add_L3_VN_Segment(aetest.Testcase):
    """ TC023_AC_BGW_Remove_Add_L3_VN_Segment """

    @aetest.test
    def AC_BGW_Remove_Add_L3_VN_Segment(self, testscript,log):
        """ AC_BGW_Remove_Add_L3_VN_Segment """

        node_dict = testscript.parameters['node_dict']
        configdict = testscript.parameters['configdict']

        #Removing L3VNIs for VLANs
        uut_list = ['uut6','uut7']
        for node in uut_list:
            hdl = node_dict['all_dut'][node]
            ns = MyLib.my_config_utils.parseScaleVlanParms(log,configdict['scale_config_dict'][node]['global']['vlan'])
            for i in range(5):
                hdl.configure('''vlan {0}
                                no vn-segment {1} 
                            '''.format(ns.l3_vlan_start+i,ns.l3_vni_start+i))

        time.sleep(60)

        #Adding L3VNIs for VLANs
        for node in uut_list:
            hdl = node_dict['all_dut'][node]
            ns = MyLib.my_config_utils.parseScaleVlanParms(log,configdict['scale_config_dict'][node]['global']['vlan'])
            for i in range(5):
                hdl.configure('''vlan {0}
                                vn-segment {1} 
                            '''.format(ns.l3_vlan_start+i,ns.l3_vni_start+i))

        time.sleep(100)

    @aetest.test
    def Verify_Traffic_Post_Trigger(self, testscript,log):
        """ Verify_Traffic_Post_Trigger """

        result = verifyTraffic(testscript)
        if result['status'] == 0:
            self.failed(reason=result['msgs'])
        else:
            self.passed(reason=result['msgs'])

# *****************************************************************************************************************************#

class TC024_vPC_BGW_Remove_Add_L2_VNI(aetest.Testcase):
    """ TC024_vPC_BGW_Remove_Add_L2_VNI """

    @aetest.test
    def vPC_BGW_Remove_Add_L2_VNI(self,testscript,log,steps):
        """ vPC_BGW_Remove_Add_L2_VNI """

        node_dict = testscript.parameters['node_dict']
        configdict = testscript.parameters['configdict']
        alias_intf_mapping = testscript.parameters['alias_intf_mapping']
        scale_config_obj = MyLib.my_config_utils.ScaleConfig(log,node_dict,configdict,alias_intf_mapping)
        log = testscript.parameters['log']
        
        res = [node_dict['all_dut'][dut].execute('terminal session-timeout 0') for dut in node_dict['all_dut'] if re.search('uut', dut)]
                
        log.info(banner('Test:- Removing/Adding L2 VNI on Both VPC BGWs...'))

        vpc_dict = scale_config_obj.getMultisiteDeviceDict('vpc_vtep')
        
        log.info('The value of VPC_DICT is : {0}'.format(vpc_dict))

        with steps.start('Backing Up Configs - on VPC BGWs') as s:
            log.info(banner('Backing Up  configs on duts {0}'.format(list(vpc_dict.keys()))))
            
            for dut in vpc_dict.keys():
                log.info(banner('Backing up config on dut : {0}'.format(dut)))
                res = MyLib.my_utils.configBackUpOrRestoreOrCleanUp(log,node_dict['all_dut'][dut],'backup')
                if not res:
                    log.error(banner('restore Failed on the dut: {0}'.format(dut)))
                    self.failed()
                    
        with steps.start('Remove L2 VNI from the VPC BGWs')  as s:
            log.info(banner('Remove L2 VNI from the VPC BGWs {0}'.format(list(vpc_dict.keys()))))
            for dut in vpc_dict:
                args = configdict['scale_config_dict'][dut]['global']['vlan']
                ns = MyLib.my_config_utils.parseScaleVlanParms(log,args)
                for i in range(ns.l2_vni_start, ns.l2_vni_start+ns.no_of_l2_vlans):
                    cfg = '''interface nve1
                                no member vni {0}'''.format(i)
                    node_dict['all_dut'][dut].configure(cfg)
                    
        log.info(banner('Wait for 180 seconds'))
        countDownTimer(180)

        with steps.start('Restoring Configs - on vPC BGWs') as s:
            log.info(banner('Restoring  configs on duts {0}'.format(list(vpc_dict.keys()))))
            
            for dut in vpc_dict.keys():
                log.info(banner('Restoring config on dut : {0}'.format(dut)))
                res = MyLib.my_utils.configBackUpOrRestoreOrCleanUp(log,node_dict['all_dut'][dut],'restore')
                if not res:
                    log.error(banner('restore Failed on the dut: {0}'.format(dut)))
                    self.failed
                    
        log.info(banner('Waiting for 180 seconds before measuring the Traffic Stats: '))
        countDownTimer(300)

    @aetest.test
    def Verify_Traffic_Post_Trigger(self, testscript,log):
        """ Verify_Traffic_Post_Trigger """

        result = verifyTraffic(testscript)
        if result['status'] == 0:
            self.failed(reason=result['msgs'])
        else:
            self.passed(reason=result['msgs'])

# *****************************************************************************************************************************#

class TC025_vPC_BGW_Remove_Add_L3_VNI(aetest.Testcase):
    """ TC025_vPC_BGW_Remove_Add_L3_VNI """

    @aetest.test
    def vPC_BGW_Remove_Add_L3_VNI(self,testscript,steps,log):
        """ vPC_BGW_Remove_Add_L3_VNI """

        node_dict = testscript.parameters['node_dict']
        configdict = testscript.parameters['configdict']
        alias_intf_mapping = testscript.parameters['alias_intf_mapping']
        scale_config_obj = MyLib.my_config_utils.ScaleConfig(log,node_dict,configdict,alias_intf_mapping)
        log = testscript.parameters['log']
        
        res = [node_dict['all_dut'][dut].execute('terminal session-timeout 0') for dut in node_dict['all_dut'] if re.search('uut', dut)]
                
        log.info(banner('Test:- Removing/Adding L3 VNI on BOth VPC BGWs...'))

        vpc_dict = scale_config_obj.getMultisiteDeviceDict('vpc_vtep')
        
        log.info('The value of VPC_DICT is : {0}'.format(vpc_dict))

        with steps.start('Backing Up Configs - on VPC BGWs') as s:
            log.info(banner('Backing Up  configs on duts {0}'.format(list(vpc_dict.keys()))))
            
            for dut in vpc_dict.keys():
                log.info(banner('Restoring config on dut : {0}'.format(dut)))
                res = MyLib.my_utils.configBackUpOrRestoreOrCleanUp(log,node_dict['all_dut'][dut],'backup')
                if not res:
                    log.error(banner('restore Failed on the dut: {0}'.format(dut)))
                    self.failed()
                    
        with steps.start('Remove L3 VNI from the VPC BGWs')  as s:
            log.info(banner('Remove L3 VNI configs on duts {0}'.format(list(vpc_dict.keys()))))
            for dut in vpc_dict:
                args = configdict['scale_config_dict'][dut]['global']['vlan']
                ns = MyLib.my_config_utils.parseScaleVlanParms(log,args)
                for i in range(ns.l3_vni_start, ns.l3_vni_start+ns.no_of_l3_vlans):
                    cfg = '''interface nve1
                                no member vni {0} associate-vrf'''.format(i)
                    node_dict['all_dut'][dut].configure(cfg)
                    
        log.info(banner('Wait for 120 seconds'))
        countDownTimer(120)

        with steps.start('Restoring Configs - on vPC BGWs') as s:
            log.info(banner('Restoring  configs on duts {0}'.format(list(vpc_dict.keys()))))
            
            for dut in vpc_dict.keys():
                log.info(banner('Restoring config on dut : {0}'.format(dut)))
                res = MyLib.my_utils.configBackUpOrRestoreOrCleanUp(log,node_dict['all_dut'][dut],'restore')
                if not res:
                    log.error(banner('restore Failed on the dut: {0}'.format(dut)))
                    self.failed
                    
        log.info(banner('Waiting for 180 seconds before measuring the Traffic Stats: '))
        countDownTimer(180)
        
    @aetest.test
    def Verify_Traffic_Post_Trigger(self, testscript,log):
        """ Verify_Traffic_Post_Trigger """

        result = verifyTraffic(testscript)
        if result['status'] == 0:
            self.failed(reason=result['msgs'])
        else:
            self.passed(reason=result['msgs'])

# *****************************************************************************************************************************#

class TC026_AC_BGW_Remove_Add_L2_VNI(aetest.Testcase):
    """ TC026_AC_BGW_Remove_Add_L2_VNI """

    @aetest.test
    def AC_BGW_Remove_Add_L2_VNI_Member(self,testscript,steps,log):
        """ AC_BGW_Remove_Add_L2_VNI """

        node_dict = testscript.parameters['node_dict']
        configdict = testscript.parameters['configdict']
        
        res = [node_dict['all_dut'][dut].execute('terminal session-timeout 0') for dut in node_dict['all_dut'] if re.search('uut', dut)]
                
        log.info(banner('Test:- Removing/Adding L2 VNI on Both AC BGWs...'))

        ac_dict = ['uut6','uut7']

        with steps.start('Backing Up Configs - on AC BGWs') as s:
            log.info(banner('Backing Up Configs - on AC BGWs {0}'.format(list(ac_dict))))
            
            for dut in ac_dict:
                log.info(banner('Backing Up configs on dut : {0}'.format(dut)))
                res = MyLib.my_utils.configBackUpOrRestoreOrCleanUp(log,node_dict['all_dut'][dut],'backup')
                if not res:
                    log.error(banner('Backing Up Failed on the dut: {0}'.format(dut)))
                    self.failed()
                    
        with steps.start('Remove L2 VNI from the AC BGWs')  as s:
            log.info(banner('Remove L2 VNI from the AC BGWs {0}'.format(list(ac_dict))))
            for dut in ac_dict:
                args = configdict['scale_config_dict'][dut]['global']['vlan']
                ns = MyLib.my_config_utils.parseScaleVlanParms(log,args)
                for i in range(ns.l2_vni_start, ns.l2_vni_start+ns.no_of_l2_vlans):
                    cfg = '''interface nve1
                                no member vni {0}'''.format(i)
                    node_dict['all_dut'][dut].configure(cfg)
                    
        log.info(banner('Wait for 120 seconds'))
        countDownTimer(120)

        with steps.start('Restoring Configs - on AC BGWs') as s:
            log.info(banner('Restoring Configs - on AC BGWs {0}'.format(list(ac_dict))))
            
            for dut in ac_dict:
                log.info(banner('Restoring config on dut : {0}'.format(dut)))
                res = MyLib.my_utils.configBackUpOrRestoreOrCleanUp(log,node_dict['all_dut'][dut],'restore')
                if not res:
                    log.error(banner('restore Failed on the dut: {0}'.format(dut)))
                    self.failed
                    
        log.info(banner('Waiting for 180 seconds before measuring the Traffic Stats: '))
        countDownTimer(180)
        
    @aetest.test
    def Verify_Traffic_Post_Trigger(self, testscript,log):
        """ Verify_Traffic_Post_Trigger """

        result = verifyTraffic(testscript)
        if result['status'] == 0:
            self.failed(reason=result['msgs'])
        else:
            self.passed(reason=result['msgs'])

# *****************************************************************************************************************************#

class TC027_AC_BGW_Remove_Add_L3_VNI(aetest.Testcase):
    """ TC027_AC_BGW_Remove_Add_L3_VNI """

    @aetest.test
    def AC_BGW_Remove_Add_L3_VNI(self,testscript,log,steps):
        """ AC_BGW_Remove_Add_L3_VNI """

        node_dict = testscript.parameters['node_dict']
        configdict = testscript.parameters['configdict']
        
        res = [node_dict['all_dut'][dut].execute('terminal session-timeout 0') for dut in node_dict['all_dut'] if re.search('uut', dut)]
                
        log.info(banner('Test:- Removing/Adding L3 VNI on Both AC BGWs...'))

        ac_dict = ['uut6','uut7']

        with steps.start('Backing Up Configs - on AC BGWs') as s:
            log.info(banner('Backing Up Configs - on AC BGWs {0}'.format(list(ac_dict))))
            
            for dut in ac_dict:
                log.info(banner('Backing Up configs on dut : {0}'.format(dut)))
                res = MyLib.my_utils.configBackUpOrRestoreOrCleanUp(log,node_dict['all_dut'][dut],'backup')
                if not res:
                    log.error(banner('Backing Up Failed on the dut: {0}'.format(dut)))
                    self.failed()
                    
        with steps.start('Remove L3 VNI from the AC BGWs')  as s:
            log.info(banner('Remove L3 VNI from the AC BGWs {0}'.format(list(ac_dict))))
            for dut in ac_dict:
                args = configdict['scale_config_dict'][dut]['global']['vlan']
                ns = MyLib.my_config_utils.parseScaleVlanParms(log,args)
                for i in range(ns.l3_vni_start, ns.l3_vni_start+ns.no_of_l3_vlans):
                    cfg = '''interface nve1
                                no member vni {0} associate-vrf'''.format(i)
                    node_dict['all_dut'][dut].configure(cfg)
                    
        log.info(banner('Wait for 120 seconds'))
        countDownTimer(120)

        with steps.start('Restoring Configs - on AC BGWs') as s:
            log.info(banner('Restoring Configs - on AC BGWs {0}'.format(list(ac_dict))))
            
            for dut in ac_dict:
                log.info(banner('Restoring config on dut : {0}'.format(dut)))
                res = MyLib.my_utils.configBackUpOrRestoreOrCleanUp(log,node_dict['all_dut'][dut],'restore')
                if not res:
                    log.error(banner('restore Failed on the dut: {0}'.format(dut)))
                    self.failed
                    
        log.info(banner('Waiting for 180 seconds before measuring the Traffic Stats: '))
        countDownTimer(180)
        
    @aetest.test
    def Verify_Traffic_Post_Trigger(self, testscript,log):
        """ Verify_Traffic_Post_Trigger """

        result = verifyTraffic(testscript)
        if result['status'] == 0:
            self.failed(reason=result['msgs'])
        else:
            self.passed(reason=result['msgs'])

# *****************************************************************************************************************************#

class TC028_vPC_BGW_Remove_Add_L2_VNI_Mcast_Grp(aetest.Testcase):
    """ TC028_vPC_BGW_Remove_Add_L2_VNI_Mcast_Grp """

    @aetest.test
    def vPC_BGW_Remove_Add_L2_VNI_Mcast_Grp(self,testscript,log,steps):
        """ vPC_BGW_Remove_Add_L2_VNI_Mcast_Grp """

        node_dict = testscript.parameters['node_dict']
        configdict = testscript.parameters['configdict']
        alias_intf_mapping = testscript.parameters['alias_intf_mapping']
        scale_config_obj = MyLib.my_config_utils.ScaleConfig(log,node_dict,configdict,alias_intf_mapping)
        log = testscript.parameters['log']
        
        res = [node_dict['all_dut'][dut].execute('terminal session-timeout 0') for dut in node_dict['all_dut'] if re.search('uut', dut)]
                
        log.info(banner('Test:- Removing/Adding L2 VNI on Both VPC BGWs...'))

        vpc_dict = scale_config_obj.getMultisiteDeviceDict('vpc_vtep')
        
        log.info('The value of VPC_DICT is : {0}'.format(vpc_dict))

        with steps.start('Backing Up Configs - on VPC BGWs') as s:
            log.info(banner('Backing Up  configs on duts {0}'.format(list(vpc_dict.keys()))))
            
            for dut in vpc_dict.keys():
                log.info(banner('Backing up config on dut : {0}'.format(dut)))
                res = MyLib.my_utils.configBackUpOrRestoreOrCleanUp(log,node_dict['all_dut'][dut],'backup')
                if not res:
                    log.error(banner('restore Failed on the dut: {0}'.format(dut)))
                    self.failed()

        with steps.start('Remove L2 VNI from the VPC BGWs')  as s:
            log.info(banner('Remove L2 VNI from the VPC BGWs {0}'.format(list(vpc_dict.keys()))))
            for dut in vpc_dict:
                args = configdict['scale_config_dict'][dut]['interface']['nve']
                ns = MyLib.my_config_utils.parseNVEParams(log,args)
                mcast_grp_list = MyLib.my_config_utils.ipaddrgen(ns.no_of_l2_vni, ns.l2_vni_mcast, ns.l2_vni_mcast_mask)
                j=0
                for i in range(ns.no_of_l2_vni):
                    cfg = '''interface nve1
                                member vni {0}
                                no mcast-group {1}'''.format(int(ns.l2_vni_start+i),mcast_grp_list[j])
                    if ((ns.l2_vni_start + i) % ns.mcast_grp_per_vni == 0):
                        j+=1
                    node_dict['all_dut'][dut].configure(cfg)
                    
        log.info(banner('Wait for 200 seconds'))
        countDownTimer(200)

        with steps.start('Restoring Configs - on vPC BGWs') as s:
            log.info(banner('Restoring  configs on duts {0}'.format(list(vpc_dict.keys()))))
            
            for dut in vpc_dict.keys():
                log.info(banner('Restoring config on dut : {0}'.format(dut)))
                res = MyLib.my_utils.configBackUpOrRestoreOrCleanUp(log,node_dict['all_dut'][dut],'restore')
                if not res:
                    log.error(banner('restore Failed on the dut: {0}'.format(dut)))
                    self.failed
                    
        log.info(banner('Waiting for 300 seconds before measuring the Traffic Stats: '))
        countDownTimer(300)

    @aetest.test
    def Verify_Traffic_Post_Trigger(self, testscript,log):
        """ Verify_Traffic_Post_Trigger """

        result = verifyTraffic(testscript)
        if result['status'] == 0:
            self.failed(reason=result['msgs'])
        else:
            self.passed(reason=result['msgs'])

# *****************************************************************************************************************************#

class TC029_vPC_BGW_Remove_Add_L3_VNI_Mcast_Grp(aetest.Testcase):
    """ TC029_vPC_BGW_Remove_Add_L3_VNI_Mcast_Grp """

    @aetest.test
    def vPC_BGW_Remove_Add_L3_VNI_Mcast_Grp(self,testscript,log,steps):
        """ vPC_BGW_Remove_Add_L3_VNI_Mcast_Grp """

        node_dict = testscript.parameters['node_dict']
        configdict = testscript.parameters['configdict']
        alias_intf_mapping = testscript.parameters['alias_intf_mapping']
        scale_config_obj = MyLib.my_config_utils.ScaleConfig(log,node_dict,configdict,alias_intf_mapping)
        log = testscript.parameters['log']
        
        res = [node_dict['all_dut'][dut].execute('terminal session-timeout 0') for dut in node_dict['all_dut'] if re.search('uut', dut)]
                
        log.info(banner('Test:- Removing/Adding L3 VNI on Both VPC BGWs...'))

        vpc_dict = scale_config_obj.getMultisiteDeviceDict('vpc_vtep')
        
        log.info('The value of VPC_DICT is : {0}'.format(vpc_dict))

        with steps.start('Backing Up Configs - on VPC BGWs') as s:
            log.info(banner('Backing Up  configs on duts {0}'.format(list(vpc_dict.keys()))))
            
            for dut in vpc_dict.keys():
                log.info(banner('Backing up config on dut : {0}'.format(dut)))
                res = MyLib.my_utils.configBackUpOrRestoreOrCleanUp(log,node_dict['all_dut'][dut],'backup')
                if not res:
                    log.error(banner('restore Failed on the dut: {0}'.format(dut)))
                    self.failed()

        with steps.start('Remove L3 VNI from the VPC BGWs')  as s:
            log.info(banner('Remove L3 VNI from the VPC BGWs {0}'.format(list(vpc_dict.keys()))))
            for dut in vpc_dict:
                args = configdict['scale_config_dict'][dut]['interface']['nve']
                ns = MyLib.my_config_utils.parseNVEParams(log,args)
                trm_mcast_group_list = MyLib.my_config_utils.ipaddrgen(ns.no_of_l3_vni, ns.trm_mcast_group_start, ns.trm_mcast_group_start_mask)
                j=0
                for i in range(ns.no_of_l3_vni):
                    cfg = '''interface nve1
                                member vni {0} associate-vrf
                                no mcast-group {1}'''.format(int(ns.l3_vni_start+i),trm_mcast_group_list[j])
                    if ((ns.l3_vni_start + i) % ns.mcast_grp_per_vni == 0):
                        j+=1
                    node_dict['all_dut'][dut].configure(cfg)
                    
        log.info(banner('Wait for 200 seconds'))
        countDownTimer(200)

        with steps.start('Restoring Configs - on vPC BGWs') as s:
            log.info(banner('Restoring  configs on duts {0}'.format(list(vpc_dict.keys()))))
            
            for dut in vpc_dict.keys():
                log.info(banner('Restoring config on dut : {0}'.format(dut)))
                res = MyLib.my_utils.configBackUpOrRestoreOrCleanUp(log,node_dict['all_dut'][dut],'restore')
                if not res:
                    log.error(banner('restore Failed on the dut: {0}'.format(dut)))
                    self.failed
                    
        log.info(banner('Waiting for 300 seconds before measuring the Traffic Stats: '))
        countDownTimer(300)

    @aetest.test
    def Verify_Traffic_Post_Trigger(self, testscript,log):
        """ Verify_Traffic_Post_Trigger """

        result = verifyTraffic(testscript)
        if result['status'] == 0:
            self.failed(reason=result['msgs'])
        else:
            self.passed(reason=result['msgs'])

# *****************************************************************************************************************************#

class TC030_AC_BGW_Remove_Add_L2_VNI_Mcast_Grp(aetest.Testcase):
    """ TC030_AC_BGW_Remove_Add_L2_VNI_Mcast_Grp """

    @aetest.test
    def AC_BGW_Remove_Add_L2_VNI_Mcast_Grp(self,testscript,log,steps):
        """ AC_BGW_Remove_Add_L2_VNI_Mcast_Grp """

        node_dict = testscript.parameters['node_dict']
        configdict = testscript.parameters['configdict']

        res = [node_dict['all_dut'][dut].execute('terminal session-timeout 0') for dut in node_dict['all_dut'] if re.search('uut', dut)]
                
        log.info(banner('Test:- Removing/Adding L2 VNI on Both AC BGWs...'))

        ac_dict = ['uut6','uut7']
        
        log.info('The value of AC_DICT is : {0}'.format(ac_dict))

        with steps.start('Backing Up Configs - on AC BGWs') as s:
            log.info(banner('Backing Up  configs on duts {0}'.format(list(ac_dict))))
            for dut in ac_dict:
                log.info(banner('Backing up config on dut : {0}'.format(dut)))
                res = MyLib.my_utils.configBackUpOrRestoreOrCleanUp(log,node_dict['all_dut'][dut],'backup')
                if not res:
                    log.error(banner('restore Failed on the dut: {0}'.format(dut)))
                    self.failed()

        with steps.start('Remove L2 VNI from the AC BGWs')  as s:
            log.info(banner('Remove L2 VNI from the AC BGWs {0}'.format(list(ac_dict))))
            for dut in ac_dict:
                args = configdict['scale_config_dict'][dut]['interface']['nve']
                ns = MyLib.my_config_utils.parseNVEParams(log,args)
                mcast_grp_list = MyLib.my_config_utils.ipaddrgen(ns.no_of_l2_vni, ns.l2_vni_mcast, ns.l2_vni_mcast_mask)
                j=0
                for i in range(ns.no_of_l2_vni):
                    cfg = '''interface nve1
                                member vni {0}
                                no mcast-group {1}'''.format(int(ns.l2_vni_start+i),mcast_grp_list[j])
                    if ((ns.l2_vni_start + i) % ns.mcast_grp_per_vni == 0):
                        j+=1
                    node_dict['all_dut'][dut].configure(cfg)
                    
        log.info(banner('Wait for 200 seconds'))
        countDownTimer(200)

        with steps.start('Restoring Configs - on AC BGWs') as s:
            log.info(banner('Restoring  configs on duts {0}'.format(list(ac_dict))))
            for dut in ac_dict:
                log.info(banner('Restoring config on dut : {0}'.format(dut)))
                res = MyLib.my_utils.configBackUpOrRestoreOrCleanUp(log,node_dict['all_dut'][dut],'restore')
                if not res:
                    log.error(banner('restore Failed on the dut: {0}'.format(dut)))
                    self.failed

        log.info(banner('Waiting for 300 seconds before measuring the Traffic Stats: '))
        countDownTimer(300)

    @aetest.test
    def Verify_Traffic_Post_Trigger(self, testscript,log):
        """ Verify_Traffic_Post_Trigger """

        result = verifyTraffic(testscript)
        if result['status'] == 0:
            self.failed(reason=result['msgs'])
        else:
            self.passed(reason=result['msgs'])

# *****************************************************************************************************************************#

class TC031_AC_BGW_Remove_Add_L3_VNI_Mcast_Grp(aetest.Testcase):
    """ TC031_AC_BGW_Remove_Add_L3_VNI_Mcast_Grp """

    @aetest.test
    def AC_BGW_Remove_Add_L3_VNI_Mcast_Grp(self,testscript,log,steps):
        """ AC_BGW_Remove_Add_L3_VNI_Mcast_Grp """

        node_dict = testscript.parameters['node_dict']
        configdict = testscript.parameters['configdict']
        
        res = [node_dict['all_dut'][dut].execute('terminal session-timeout 0') for dut in node_dict['all_dut'] if re.search('uut', dut)]
                
        log.info(banner('Test:- Removing/Adding L3 VNI on Both AC BGWs...'))

        ac_dict = ['uut6','uut7']
        
        log.info('The value of AC_DICT is : {0}'.format(ac_dict))

        with steps.start('Backing Up Configs - on AC BGWs') as s:
            log.info(banner('Backing Up  configs on duts {0}'.format(list(ac_dict))))
            
            for dut in ac_dict:
                log.info(banner('Backing up config on dut : {0}'.format(dut)))
                res = MyLib.my_utils.configBackUpOrRestoreOrCleanUp(log,node_dict['all_dut'][dut],'backup')
                if not res:
                    log.error(banner('restore Failed on the dut: {0}'.format(dut)))
                    self.failed()

        with steps.start('Remove L3 VNI from the AC BGWs')  as s:
            log.info(banner('Remove L3 VNI from the AC BGWs {0}'.format(list(ac_dict))))
            for dut in ac_dict:
                args = configdict['scale_config_dict'][dut]['interface']['nve']
                ns = MyLib.my_config_utils.parseNVEParams(log,args)
                trm_mcast_group_list = MyLib.my_config_utils.ipaddrgen(ns.no_of_l3_vni, ns.trm_mcast_group_start, ns.trm_mcast_group_start_mask)
                j=0
                for i in range(ns.no_of_l3_vni):
                    cfg = '''interface nve1
                                member vni {0} associate-vrf
                                no mcast-group {1}'''.format(int(ns.l3_vni_start+i),trm_mcast_group_list[j])
                    if ((ns.l3_vni_start + i) % ns.mcast_grp_per_vni == 0):
                        j+=1
                    node_dict['all_dut'][dut].configure(cfg)
                    
        log.info(banner('Wait for 200 seconds'))
        countDownTimer(200)

        with steps.start('Restoring Configs - on AC BGWs') as s:
            log.info(banner('Restoring  configs on duts {0}'.format(list(ac_dict))))
            
            for dut in ac_dict:
                log.info(banner('Restoring config on dut : {0}'.format(dut)))
                res = MyLib.my_utils.configBackUpOrRestoreOrCleanUp(log,node_dict['all_dut'][dut],'restore')
                if not res:
                    log.error(banner('restore Failed on the dut: {0}'.format(dut)))
                    self.failed
                    
        log.info(banner('Waiting for 300 seconds before measuring the Traffic Stats: '))
        countDownTimer(300)

    @aetest.test
    def Verify_Traffic_Post_Trigger(self, testscript,log):
        """ Verify_Traffic_Post_Trigger """

        result = verifyTraffic(testscript)
        if result['status'] == 0:
            self.failed(reason=result['msgs'])
        else:
            self.passed(reason=result['msgs'])

# *****************************************************************************************************************************#

class TC032_vPC_BGW_Remove_Add_TRM_L2_VNI_Mcast_Grp(aetest.Testcase):
    """ TC032_vPC_BGW_Remove_Add_TRM_L2_VNI_Mcast_Grp """

    @aetest.test
    def vPC_BGW_Remove_Add_TRM_L2_VNI_Mcast_Grp(self,testscript,log,steps):
        """ vPC_BGW_Remove_Add_TRM_L2_VNI_Mcast_Grp """

        node_dict = testscript.parameters['node_dict']
        configdict = testscript.parameters['configdict']
        alias_intf_mapping = testscript.parameters['alias_intf_mapping']
        scale_config_obj = MyLib.my_config_utils.ScaleConfig(log,node_dict,configdict,alias_intf_mapping)
        log = testscript.parameters['log']
        
        res = [node_dict['all_dut'][dut].execute('terminal session-timeout 0') for dut in node_dict['all_dut'] if re.search('uut', dut)]
                
        log.info(banner('Test:- Removing/Adding TRM L2 VNI Mcast Grp on Both VPC BGWs...'))

        vpc_dict = scale_config_obj.getMultisiteDeviceDict('vpc_vtep')
        
        log.info('The value of VPC_DICT is : {0}'.format(vpc_dict))

        with steps.start('Backing Up Configs - on VPC BGWs') as s:
            log.info(banner('Backing Up  configs on duts {0}'.format(list(vpc_dict.keys()))))
            
            for dut in vpc_dict.keys():
                log.info(banner('Backing up config on dut : {0}'.format(dut)))
                res = MyLib.my_utils.configBackUpOrRestoreOrCleanUp(log,node_dict['all_dut'][dut],'backup')
                if not res:
                    log.error(banner('restore Failed on the dut: {0}'.format(dut)))
                    self.failed()

        with steps.start('Remove TRM L2 VNI Mcast Grp from the VPC BGWs')  as s:
            log.info(banner('Remove TRM L2 VNI Mcast Grp from the VPC BGWs {0}'.format(list(vpc_dict.keys()))))
            for dut in vpc_dict:
                args = configdict['scale_config_dict'][dut]['interface']['nve']
                ns = MyLib.my_config_utils.parseNVEParams(log,args)
                for i in range(ns.no_of_l2_vni):
                    cfg = '''interface nve1
                                member vni {0}
                                no multisite mcast-group'''.format(int(ns.l2_vni_start+i))
                    node_dict['all_dut'][dut].configure(cfg)
                    
        log.info(banner('Wait for 200 seconds'))
        countDownTimer(200)

        with steps.start('Restoring Configs - on vPC BGWs') as s:
            log.info(banner('Restoring  configs on duts {0}'.format(list(vpc_dict.keys()))))
            
            for dut in vpc_dict.keys():
                log.info(banner('Restoring config on dut : {0}'.format(dut)))
                res = MyLib.my_utils.configBackUpOrRestoreOrCleanUp(log,node_dict['all_dut'][dut],'restore')
                if not res:
                    log.error(banner('restore Failed on the dut: {0}'.format(dut)))
                    self.failed
                    
        log.info(banner('Waiting for 300 seconds before measuring the Traffic Stats: '))
        countDownTimer(300)

    @aetest.test
    def Verify_Traffic_Post_Trigger(self, testscript,log):
        """ Verify_Traffic_Post_Trigger """

        result = verifyTraffic(testscript)
        if result['status'] == 0:
            self.failed(reason=result['msgs'])
        else:
            self.passed(reason=result['msgs'])

# *****************************************************************************************************************************#

class TC033_vPC_BGW_Remove_Add_TRM_L3_VNI_Mcast_Grp(aetest.Testcase):
    """ TC033_vPC_BGW_Remove_Add_TRM_L3_VNI_Mcast_Grp """

    @aetest.test
    def vPC_BGW_Remove_Add_TRM_L3_VNI_Mcast_Grp(self,testscript,log,steps):
        """ vPC_BGW_Remove_Add_TRM_L3_VNI_Mcast_Grp """

        node_dict = testscript.parameters['node_dict']
        configdict = testscript.parameters['configdict']
        alias_intf_mapping = testscript.parameters['alias_intf_mapping']
        scale_config_obj = MyLib.my_config_utils.ScaleConfig(log,node_dict,configdict,alias_intf_mapping)
        log = testscript.parameters['log']
        
        res = [node_dict['all_dut'][dut].execute('terminal session-timeout 0') for dut in node_dict['all_dut'] if re.search('uut', dut)]
                
        log.info(banner('Test:- Removing/Adding TRM L3 VNI Mcast Grp on Both VPC BGWs...'))

        vpc_dict = scale_config_obj.getMultisiteDeviceDict('vpc_vtep')
        
        log.info('The value of VPC_DICT is : {0}'.format(vpc_dict))

        with steps.start('Backing Up Configs - on VPC BGWs') as s:
            log.info(banner('Backing Up  configs on duts {0}'.format(list(vpc_dict.keys()))))
            
            for dut in vpc_dict.keys():
                log.info(banner('Backing up config on dut : {0}'.format(dut)))
                res = MyLib.my_utils.configBackUpOrRestoreOrCleanUp(log,node_dict['all_dut'][dut],'backup')
                if not res:
                    log.error(banner('restore Failed on the dut: {0}'.format(dut)))
                    self.failed()

        with steps.start('Remove TRM L3 VNI Mcast Grp from the VPC BGWs')  as s:
            log.info(banner('Remove TRM L3 VNI Mcast Grp from the VPC BGWs {0}'.format(list(vpc_dict.keys()))))
            for dut in vpc_dict:
                args = configdict['scale_config_dict'][dut]['interface']['nve']
                ns = MyLib.my_config_utils.parseNVEParams(log,args)
                for i in range(ns.no_of_l3_vni):
                    cfg = '''interface nve1
                                member vni {0} associate-vrf
                                no multisite mcast-group'''.format(int(ns.l3_vni_start+i))
                    node_dict['all_dut'][dut].configure(cfg)
                    
        log.info(banner('Wait for 200 seconds'))
        countDownTimer(200)

        with steps.start('Restoring Configs - on vPC BGWs') as s:
            log.info(banner('Restoring  configs on duts {0}'.format(list(vpc_dict.keys()))))
            
            for dut in vpc_dict.keys():
                log.info(banner('Restoring config on dut : {0}'.format(dut)))
                res = MyLib.my_utils.configBackUpOrRestoreOrCleanUp(log,node_dict['all_dut'][dut],'restore')
                if not res:
                    log.error(banner('restore Failed on the dut: {0}'.format(dut)))
                    self.failed
                    
        log.info(banner('Waiting for 300 seconds before measuring the Traffic Stats: '))
        countDownTimer(300)

    @aetest.test
    def Verify_Traffic_Post_Trigger(self, testscript,log):
        """ Verify_Traffic_Post_Trigger """

        result = verifyTraffic(testscript)
        if result['status'] == 0:
            self.failed(reason=result['msgs'])
        else:
            self.passed(reason=result['msgs'])

# *****************************************************************************************************************************#

class TC034_AC_BGW_Remove_Add_TRM_L2_VNI_Mcast_Grp(aetest.Testcase):
    """ TC034_AC_BGW_Remove_Add_TRM_L2_VNI_Mcast_Grp """

    @aetest.test
    def AC_BGW_Remove_Add_TRM_L2_VNI_Mcast_Grp(self,testscript,log,steps):
        """ AC_BGW_Remove_Add_TRM_L2_VNI_Mcast_Grp """

        node_dict = testscript.parameters['node_dict']
        configdict = testscript.parameters['configdict']

        res = [node_dict['all_dut'][dut].execute('terminal session-timeout 0') for dut in node_dict['all_dut'] if re.search('uut', dut)]
                
        log.info(banner('Test:- Removing/Adding TRM L2 VNI Mcast Grp on Both AC BGWs...'))

        ac_dict = ['uut6','uut7']
        
        log.info('The value of AC_DICT is : {0}'.format(ac_dict))

        with steps.start('Backing Up Configs - on AC BGWs') as s:
            log.info(banner('Backing Up  configs on duts {0}'.format(list(ac_dict))))
            for dut in ac_dict:
                log.info(banner('Backing up config on dut : {0}'.format(dut)))
                res = MyLib.my_utils.configBackUpOrRestoreOrCleanUp(log,node_dict['all_dut'][dut],'backup')
                if not res:
                    log.error(banner('restore Failed on the dut: {0}'.format(dut)))
                    self.failed()

        with steps.start('Remove TRM L2 VNI Mcast Grp from the AC BGWs')  as s:
            log.info(banner('Remove TRM L2 VNI Mcast Grp from the AC BGWs {0}'.format(list(ac_dict))))
            for dut in ac_dict:
                args = configdict['scale_config_dict'][dut]['interface']['nve']
                ns = MyLib.my_config_utils.parseNVEParams(log,args)
                for i in range(ns.no_of_l2_vni):
                    cfg = '''interface nve1
                                member vni {0}
                                no multisite mcast-group'''.format(int(ns.l2_vni_start+i))
                    node_dict['all_dut'][dut].configure(cfg)
                    
        log.info(banner('Wait for 200 seconds'))
        countDownTimer(200)

        with steps.start('Restoring Configs - on AC BGWs') as s:
            log.info(banner('Restoring  configs on duts {0}'.format(list(ac_dict))))
            for dut in ac_dict:
                log.info(banner('Restoring config on dut : {0}'.format(dut)))
                res = MyLib.my_utils.configBackUpOrRestoreOrCleanUp(log,node_dict['all_dut'][dut],'restore')
                if not res:
                    log.error(banner('restore Failed on the dut: {0}'.format(dut)))
                    self.failed

        log.info(banner('Waiting for 300 seconds before measuring the Traffic Stats: '))
        countDownTimer(300)

    @aetest.test
    def Verify_Traffic_Post_Trigger(self, testscript,log):
        """ Verify_Traffic_Post_Trigger """

        result = verifyTraffic(testscript)
        if result['status'] == 0:
            self.failed(reason=result['msgs'])
        else:
            self.passed(reason=result['msgs'])

# *****************************************************************************************************************************#

class TC035_AC_BGW_Remove_Add_TRM_L3_VNI_Mcast_Grp(aetest.Testcase):
    """ TC035_AC_BGW_Remove_Add_TRM_L3_VNI_Mcast_Grp """

    @aetest.test
    def AC_BGW_Remove_Add_TRM_L3_VNI_Mcast_Grp(self,testscript,log,steps):
        """ AC_BGW_Remove_Add_TRM_L3_VNI_Mcast_Grp """

        node_dict = testscript.parameters['node_dict']
        configdict = testscript.parameters['configdict']
        
        res = [node_dict['all_dut'][dut].execute('terminal session-timeout 0') for dut in node_dict['all_dut'] if re.search('uut', dut)]
                
        log.info(banner('Test:- Removing/Adding TRM L3 VNI Mcast Grp on Both AC BGWs...'))

        ac_dict = ['uut6','uut7']
        
        log.info('The value of AC_DICT is : {0}'.format(ac_dict))

        with steps.start('Backing Up Configs - on AC BGWs') as s:
            log.info(banner('Backing Up  configs on duts {0}'.format(list(ac_dict))))
            
            for dut in ac_dict:
                log.info(banner('Backing up config on dut : {0}'.format(dut)))
                res = MyLib.my_utils.configBackUpOrRestoreOrCleanUp(log,node_dict['all_dut'][dut],'backup')
                if not res:
                    log.error(banner('restore Failed on the dut: {0}'.format(dut)))
                    self.failed()

        with steps.start('Remove TRM L3 VNI Mcast Grp from the AC BGWs')  as s:
            log.info(banner('Remove TRM L3 VNI Mcast Grp from the AC BGWs {0}'.format(list(ac_dict))))
            for dut in ac_dict:
                args = configdict['scale_config_dict'][dut]['interface']['nve']
                ns = MyLib.my_config_utils.parseNVEParams(log,args)
                for i in range(ns.no_of_l3_vni):
                    cfg = '''interface nve1
                                member vni {0} associate-vrf
                                no multisite mcast-group'''.format(int(ns.l3_vni_start+i))
                    node_dict['all_dut'][dut].configure(cfg)
                    
        log.info(banner('Wait for 200 seconds'))
        countDownTimer(200)

        with steps.start('Restoring Configs - on AC BGWs') as s:
            log.info(banner('Restoring  configs on duts {0}'.format(list(ac_dict))))
            
            for dut in ac_dict:
                log.info(banner('Restoring config on dut : {0}'.format(dut)))
                res = MyLib.my_utils.configBackUpOrRestoreOrCleanUp(log,node_dict['all_dut'][dut],'restore')
                if not res:
                    log.error(banner('restore Failed on the dut: {0}'.format(dut)))
                    self.failed
                    
        log.info(banner('Waiting for 300 seconds before measuring the Traffic Stats: '))
        countDownTimer(300)

    @aetest.test
    def Verify_Traffic_Post_Trigger(self, testscript,log):
        """ Verify_Traffic_Post_Trigger """

        result = verifyTraffic(testscript)
        if result['status'] == 0:
            self.failed(reason=result['msgs'])
        else:
            self.passed(reason=result['msgs'])

# *****************************************************************************************************************************#

class TC036_vPC_BGW_Process_Restart(aetest.Testcase):
    """ TC036_vPC_BGW_Process_Restart """

    @aetest.test
    def vPC_BGW_Process_Restart(self,testscript,log):
        """ vPC_BGW_Process_Restart """

        node_dict = testscript.parameters['node_dict']
        uut_list = ['uut1','uut2']

        for node in uut_list:
            if verifyProcessRestart(node_dict['all_dut'][node],"pim"):
                log.info(banner('PIM Process Restart on vPC BGWs Passed for: {0}'.format(node)))
            else:
                log.error(banner('PIM Process Restart on vPC BGWs Failed for: {0}'.format(node)))

        for node in uut_list:
            if verifyProcessRestart(node_dict['all_dut'][node],"bgp"):
                log.info(banner('BGP Process Restart on vPC BGWs Passed for: {0}'.format(node)))
            else:
                log.error(banner('BGP Process Restart on vPC BGWs Failed for: {0}'.format(node)))

        for node in uut_list:
            if verifyProcessRestart(node_dict['all_dut'][node],"mfdm"):
                log.info(banner('MFDM Process Restart on vPC BGWs Passed for: {0}'.format(node)))
            else:
                log.error(banner('MFDM Process Restart on vPC BGWs Failed for: {0}'.format(node)))

        for node in uut_list:
            if verifyProcessRestart(node_dict['all_dut'][node],"nve"):
                log.info(banner('NVE Process Restart on vPC BGWs Passed for: {0}'.format(node)))
            else:
                log.error(banner('NVE Process Restart on vPC BGWs Failed for: {0}'.format(node)))

        for node in uut_list:
            if verifyProcessRestart(node_dict['all_dut'][node],"mld"):
                log.info(banner('MLD Process Restart on vPC BGWs Passed for: {0}'.format(node)))
            else:
                log.error(banner('MLD Process Restart on vPC BGWs Failed for: {0}'.format(node)))

        for node in uut_list:
            if verifyProcessRestart(node_dict['all_dut'][node],"igmp"):
                log.info(banner('IGMP Process Restart on vPC BGWs Passed for: {0}'.format(node)))
            else:
                log.error(banner('IGMP Process Restart on vPC BGWs Failed for: {0}'.format(node)))

        for node in uut_list:
            if verifyProcessRestart(node_dict['all_dut'][node],"ngmvpn"):
                log.info(banner('NGMVPN Process Restart on vPC BGWs Passed for: {0}'.format(node)))
            else:
                log.error(banner('NGMVPN Process Restart on vPC BGWs Failed for: {0}'.format(node)))

        log.info(banner('Waiting for 300 seconds before measuring the Traffic Stats: '))
        countDownTimer(300)

    @aetest.test
    def Verify_Traffic_Post_Trigger(self, testscript,log):
        """ Verify_Traffic_Post_Trigger """

        result = verifyTraffic(testscript)
        if result['status'] == 0:
            self.failed(reason=result['msgs'])
        else:
            self.passed(reason=result['msgs'])

# *****************************************************************************************************************************#

class TC037_AC_BGW_Process_Restart(aetest.Testcase):
    """ TC037_AC_BGW_Process_Restart """

    @aetest.test
    def AC_BGW_Process_Restart(self,testscript,log):
        """ AC_BGW_Process_Restart """

        node_dict = testscript.parameters['node_dict']
        uut_list = ['uut6','uut7']

        for node in uut_list:
            if verifyProcessRestart(node_dict['all_dut'][node],"pim"):
                log.info(banner('PIM Process Restart on AC BGWs Passed for: {0}'.format(node)))
            else:
                log.error(banner('PIM Process Restart on AC BGWs Failed for: {0}'.format(node)))

        for node in uut_list:
            if verifyProcessRestart(node_dict['all_dut'][node],"bgp"):
                log.info(banner('BGP Process Restart on AC BGWs Passed for: {0}'.format(node)))
            else:
                log.error(banner('BGP Process Restart on AC BGWs Failed for: {0}'.format(node)))

        for node in uut_list:
            if verifyProcessRestart(node_dict['all_dut'][node],"mfdm"):
                log.info(banner('MFDM Process Restart on AC BGWs Passed for: {0}'.format(node)))
            else:
                log.error(banner('MFDM Process Restart on AC BGWs Failed for: {0}'.format(node)))

        for node in uut_list:
            if verifyProcessRestart(node_dict['all_dut'][node],"nve"):
                log.info(banner('NVE Process Restart on AC BGWs Passed for: {0}'.format(node)))
            else:
                log.error(banner('NVE Process Restart on AC BGWs Failed for: {0}'.format(node)))

        for node in uut_list:
            if verifyProcessRestart(node_dict['all_dut'][node],"mld"):
                log.info(banner('MLD Process Restart on AC BGWs Passed for: {0}'.format(node)))
            else:
                log.error(banner('MLD Process Restart on AC BGWs Failed for: {0}'.format(node)))

        for node in uut_list:
            if verifyProcessRestart(node_dict['all_dut'][node],"igmp"):
                log.info(banner('IGMP Process Restart on AC BGWs Passed for: {0}'.format(node)))
            else:
                log.error(banner('IGMP Process Restart on AC BGWs Failed for: {0}'.format(node)))

        for node in uut_list:
            if verifyProcessRestart(node_dict['all_dut'][node],"ngmvpn"):
                log.info(banner('NGMVPN Process Restart on AC BGWs Passed for: {0}'.format(node)))
            else:
                log.error(banner('NGMVPN Process Restart on AC BGWs Failed for: {0}'.format(node)))

        log.info(banner('Waiting for 300 seconds before measuring the Traffic Stats: '))
        countDownTimer(300)

    @aetest.test
    def Verify_Traffic_Post_Trigger(self, testscript,log):
        """ Verify_Traffic_Post_Trigger """

        result = verifyTraffic(testscript)
        if result['status'] == 0:
            self.failed(reason=result['msgs'])
        else:
            self.passed(reason=result['msgs'])

# *****************************************************************************************************************************#

class TC038_vPC_BGW_Clear_CLIs(aetest.Testcase):
    """ TC038_vPC_BGW_Clear_CLIs """

    @aetest.test
    def vPC_BGW_Clear_CLIs(self,testscript,log):
        """ vPC_BGW_Clear_CLIs """

        node_dict = testscript.parameters['node_dict']

        uut_list = ['uut1','uut2']
        for node in uut_list:
            log.info(banner('vPC BGW Clear CLIs on : {0}'.format(node)))
            hdl = node_dict['all_dut'][node]
            hdl.configure('''clear ip mroute *
                            clear ipv6 mroute *
                            clear ip pim route *
                            clear ipv6 pim route *
                            clear ip bgp *
                        ''')

        log.info(banner('Waiting for 300 seconds before measuring the Traffic Stats: '))
        countDownTimer(300)

    @aetest.test
    def Verify_Traffic_Post_Trigger(self, testscript,log):
        """ Verify_Traffic_Post_Trigger """

        result = verifyTraffic(testscript)
        if result['status'] == 0:
            self.failed(reason=result['msgs'])
        else:
            self.passed(reason=result['msgs'])

# *****************************************************************************************************************************#

class TC039_AC_BGW_Clear_CLIs(aetest.Testcase):
    """ TC039_AC_BGW_Clear_CLIs """

    @aetest.test
    def AC_BGW_Clear_CLIs(self,testscript,log):
        """ AC_BGW_Clear_CLIs """

        node_dict = testscript.parameters['node_dict']

        uut_list = ['uut6','uut7']
        for node in uut_list:
            log.info(banner('AC BGW Clear CLIs on : {0}'.format(node)))
            hdl = node_dict['all_dut'][node]
            hdl.configure('''clear ip mroute *
                            clear ipv6 mroute *
                            clear ip pim route *
                            clear ipv6 pim route *
                            clear ip bgp *
                        ''')

        log.info(banner('Waiting for 300 seconds before measuring the Traffic Stats: '))
        countDownTimer(300)

    @aetest.test
    def Verify_Traffic_Post_Trigger(self, testscript,log):
        """ Verify_Traffic_Post_Trigger """

        result = verifyTraffic(testscript)
        if result['status'] == 0:
            self.failed(reason=result['msgs'])
        else:
            self.passed(reason=result['msgs'])

# *****************************************************************************************************************************#

class TC040_vPC_BGW_VxLAN_CC(aetest.Testcase):
    """ TC040_vPC_BGW_VxLAN_CC """

    @aetest.test
    def vPC_BGW_VxLAN_CC(self, testscript,log):
        """ vPC_BGW_VxLAN_CC """

        node_dict = testscript.parameters['node_dict']

        uut_list = ['uut1','uut2']
        for node in uut_list:
            log.info(banner('Verifying CC on vPC BGW for: {0}'.format(node)))
            hdl = node_dict['all_dut'][node]
            VxLANCC = json.loads(hdl.execute('''show consistency-checker vxlan l2 module 1 brief | no-more'''))
            if "CC_STATUS_NOT_OK" in VxLANCC['result']['status']:
                log.error("FAIL : VxLAN L2 CC BRIEF Failed\n\n")
            else:
                log.info("PASS : VxLAN L2 CC BRIEF Passed\n\n")
        
        for node in uut_list:
            log.info(banner('Verifying CC on vPC BGW for: {0}'.format(node)))
            hdl = node_dict['all_dut'][node]
            VxLANCC = json.loads(hdl.execute('''show consistency-checker vpc brief | no-more'''))
            if "CC_STATUS_NOT_OK" in VxLANCC['result']['status']:
                log.error("FAIL : vPC CC BRIEF Failed\n\n")
            else:
                log.info("PASS : vPC CC BRIEF Passed\n\n")

        log.info(banner('Waiting for 60 seconds before measuring the Traffic Stats: '))
        countDownTimer(60)

    @aetest.test
    def Verify_Traffic_Post_Trigger(self, testscript,log):
        """ Verify_Traffic_Post_Trigger """

        result = verifyTraffic(testscript)
        if result['status'] == 0:
            self.failed(reason=result['msgs'])
        else:
            self.passed(reason=result['msgs'])

# *****************************************************************************************************************************#

class TC041_AC_BGW_VxLAN_CC(aetest.Testcase):
    """ TC041_AC_BGW_VxLAN_CC """

    @aetest.test
    def AC_BGW_VxLAN_CC(self,testscript,log):
        """ AC_BGW_VxLAN_CC """

        node_dict = testscript.parameters['node_dict']

        uut_list = ['uut6','uut7']
        for node in uut_list:
            log.info(banner('Verifying CC on AC BGW for: {0}'.format(node)))
            hdl = node_dict['all_dut'][node]
            VxLANCC = json.loads(hdl.execute('''show consistency-checker vxlan l2 module 1 brief | no-more'''))
            if "CC_STATUS_NOT_OK" in VxLANCC['result']['status']:
                log.error("FAIL : VxLAN L2 CC BRIEF Failed\n\n")
            else:
                log.info("PASS : VxLAN L2 CC BRIEF Passed\n\n")
        
        for node in uut_list:
            log.info(banner('Verifying CC on AC BGW for: {0}'.format(node)))
            hdl = node_dict['all_dut'][node]
            VxLANCC = json.loads(hdl.execute('''show consistency-checker vpc brief | no-more'''))
            if "CC_STATUS_NOT_OK" in VxLANCC['result']['status']:
                log.error("FAIL : vPC CC BRIEF Failed\n\n")
            else:
                log.info("PASS : vPC CC BRIEF Passed\n\n")

        log.info(banner('Waiting for 60 seconds before measuring the Traffic Stats: '))
        countDownTimer(60)

    @aetest.test
    def Verify_Traffic_Post_Trigger(self, testscript,log):
        """ Verify_Traffic_Post_Trigger """

        result = verifyTraffic(testscript)
        if result['status'] == 0:
            self.failed(reason=result['msgs'])
        else:
            self.passed(reason=result['msgs'])

# *****************************************************************************************************************************#

class TC042_vPC_BGW_Config_Replace(aetest.Testcase):
    """ TC042_vPC_BGW_Config_Replace """

    @aetest.test
    def vPC_BGW_Config_Replace(self,testscript,log,steps):
        """ vPC_BGW_Config_Replace """

        node_dict = testscript.parameters['node_dict']
        config_dict = testscript.parameters['configdict']
        alias_intf_mapping = testscript.parameters['alias_intf_mapping']
        scale_config_obj = MyLib.my_config_utils.ScaleConfig(log,node_dict,config_dict,alias_intf_mapping)
        log = testscript.parameters['log'] 
        
        res = [node_dict['all_dut'][dut].execute('terminal session-timeout 0') for dut in node_dict['all_dut'] if re.search('uut', dut)]
                
        log.info(banner('Test:- Configure Replace Test by Removing Feature BGP on vPC BGWs'))

        vpc_dict = scale_config_obj.getMultisiteDeviceDict('vpc_vtep')

        with steps.start('Backup Configs - on vPC BGWs') as s:
            log.info(banner('Backing up configs on duts {0}'.format(list(vpc_dict.keys()))))
            
            for dut in vpc_dict.keys():
                log.info(banner('Backing up config on dut : {0}'.format(dut)))
                res = MyLib.my_utils.configBackUpOrRestoreOrCleanUp(log,node_dict['all_dut'][dut],'backup')
                if not res:
                    log.error(banner('Backup Failed on the dut: {0}'.format(dut)))
                    self.failed()
        
        with steps.start('Remove Feature BGP - on vPC BGWs') as s:
            log.info(banner('Remove Feature BGP on duts {0}'.format(list(vpc_dict.keys()))))
            
            for dut in vpc_dict.keys():
                log.info(banner('Removing feature BGP on dut : {0}'.format(dut)))
                out=bringup_lib.unconfigFeature(node_dict['all_dut'][dut], log, '-feature bgp' )
                if out.result=='fail':
                    log.error('Disable of BGP failed on dut %s' % dut)
                    self.failed()
                else:
                    log.info('Disable of BGP passes on dut %s' % dut)

        with steps.start('Restoring Configs - on vPC BGWs') as s:
            log.info(banner('Restoring  configs on duts {0}'.format(list(vpc_dict.keys()))))
            
            for dut in vpc_dict.keys():
                log.info(banner('Restoring config on dut : {0}'.format(dut)))
                res = MyLib.my_utils.configBackUpOrRestoreOrCleanUp(log,node_dict['all_dut'][dut],'restore')
                if not res:
                    log.error(banner('restore Failed on the dut: {0}'.format(dut)))
                    self.failed
                    
        log.info(banner('Waiting for 300 seconds before measuring the Traffic Stats: '))
        countDownTimer(300)

    @aetest.test
    def Verify_Traffic_Post_Trigger(self, testscript,log):
        """ Verify_Traffic_Post_Trigger """

        result = verifyTraffic(testscript)
        if result['status'] == 0:
            self.failed(reason=result['msgs'])
        else:
            self.passed(reason=result['msgs'])

# *****************************************************************************************************************************#

class TC043_AC_BGW_Config_Replace(aetest.Testcase):
    """ TC043_AC_BGW_Config_Replace """

    @aetest.test
    def AC_BGW_Config_Replace(self,testscript,log,steps):
        """ AC_BGW_Config_Replace """

        node_dict = testscript.parameters['node_dict']
        
        res = [node_dict['all_dut'][dut].execute('terminal session-timeout 0') for dut in node_dict['all_dut'] if re.search('uut', dut)]
                
        log.info(banner('Test:- Configure Replace Test by Removing Feature BGP on AC BGWs'))

        ac_dict = ['uut6','uut7']

        with steps.start('Backup Configs - on AC BGWs') as s:
            log.info(banner('Backing up configs on duts {0}'.format(list(ac_dict))))
            
            for dut in ac_dict:
                log.info(banner('Backing up config on dut : {0}'.format(dut)))
                res = MyLib.my_utils.configBackUpOrRestoreOrCleanUp(log,node_dict['all_dut'][dut],'backup')
                if not res:
                    log.error(banner('Backup Failed on the dut: {0}'.format(dut)))
                    self.failed()
        
        with steps.start('Remove Feature BGP - on AC BGWs') as s:
            log.info(banner('Remove Feature BGP on duts {0}'.format(list(ac_dict))))
            
            for dut in ac_dict:
                log.info(banner('Removing feature BGP on dut : {0}'.format(dut)))
                out=bringup_lib.unconfigFeature(node_dict['all_dut'][dut], log, '-feature bgp' )
                if out.result=='fail':
                    log.error('Disable of BGP failed on dut %s' % dut)
                    self.failed()
                else:
                    log.info('Disable of BGP passes on dut %s' % dut)

        with steps.start('Restoring Configs - on AC BGWs') as s:
            log.info(banner('Restoring  configs on duts {0}'.format(list(ac_dict))))
            
            for dut in ac_dict:
                log.info(banner('Restoring config on dut : {0}'.format(dut)))
                res = MyLib.my_utils.configBackUpOrRestoreOrCleanUp(log,node_dict['all_dut'][dut],'restore')
                if not res:
                    log.error(banner('restore Failed on the dut: {0}'.format(dut)))
                    self.failed
                    
        log.info(banner('Waiting for 300 seconds before measuring the Traffic Stats: '))
        countDownTimer(300)

    @aetest.test
    def Verify_Traffic_Post_Trigger(self, testscript,log):
        """ Verify_Traffic_Post_Trigger """

        result = verifyTraffic(testscript)
        if result['status'] == 0:
            self.failed(reason=result['msgs'])
        else:
            self.passed(reason=result['msgs'])

# *****************************************************************************************************************************#

class TC044_vPC_BGW_iCAM(aetest.Testcase):
    """ TC044_vPC_BGW_iCAM """

    @aetest.test
    def vPC_BGW_iCAM(self,testscript,log):
        """ vPC_BGW_iCAM """

        node_dict = testscript.parameters['node_dict']

        uut_list = ['uut1','uut2']
        for node in uut_list:
            log.info(banner('vPC BGW iCAM CLIs on : {0}'.format(node)))
            hdl = node_dict['all_dut'][node]
            hdl.configure('''
                    icam monitor scale

                    show icam system | no-more
          
                    show icam scale | no-more
          
                    show icam scale vxlan | no-more
          
                    show icam health | no-more
          
                    show icam prediction scale vxlan 2030 Jan 01 01:01:01 
                        ''', timeout=300)

        log.info(banner('Waiting for 300 seconds before measuring the Traffic Stats: '))
        countDownTimer(300)

    @aetest.test
    def Verify_Traffic_Post_Trigger(self, testscript,log):
        """ Verify_Traffic_Post_Trigger """

        result = verifyTraffic(testscript)
        if result['status'] == 0:
            self.failed(reason=result['msgs'])
        else:
            self.passed(reason=result['msgs'])

# *****************************************************************************************************************************#

class TC045_AC_BGW_iCAM(aetest.Testcase):
    """ TC045_AC_BGW_iCAM """

    @aetest.test
    def AC_BGW_iCAM(self,testscript,log):
        """ AC_BGW_iCAM """

        node_dict = testscript.parameters['node_dict']

        uut_list = ['uut6','uut7']
        for node in uut_list:
            log.info(banner('AC BGW iCAM CLIs on : {0}'.format(node)))
            hdl = node_dict['all_dut'][node]
            hdl.configure('''
                    icam monitor scale

                    show icam system | no-more
          
                    show icam scale | no-more
          
                    show icam scale vxlan | no-more
          
                    show icam health | no-more
          
                    show icam prediction scale vxlan 2030 Jan 01 01:01:01 
                        ''', timeout=300)

        log.info(banner('Waiting for 300 seconds before measuring the Traffic Stats: '))
        countDownTimer(300)

    @aetest.test
    def Verify_Traffic_Post_Trigger(self, testscript,log):
        """ Verify_Traffic_Post_Trigger """

        result = verifyTraffic(testscript)
        if result['status'] == 0:
            self.failed(reason=result['msgs'])
        else:
            self.passed(reason=result['msgs'])

# *****************************************************************************************************************************#

class TC046_Verify_512_Underlay_Scale_on_vPC_BGW(aetest.Testcase):
    """ TC046_Verify_512_Underlay_Scale_on_vPC_BGW """

    @aetest.test
    def Verify_512_Underlay_Scale_on_vPC_BGW(self,testscript,log):
        """ Verify_512_Underlay_Scale_on_vPC_BGW """

        node_dict = testscript.parameters['node_dict']

        uut_list = ['uut1','uut2']
        for node in uut_list:
            log.info(banner('Verifying 512 Underlay Scale on vPC BGW for: {0}'.format(node)))
            hdl = node_dict['all_dut'][node]
            mroute_summary = json.loads(hdl.execute('''show ip mroute summary count vrf default | json'''))
            mcast_ul_scale = mroute_summary['TABLE_vrf']['ROW_vrf']['TABLE_route_summary']['ROW_route_summary']['star-g-route']
            if int(mcast_ul_scale) == 500:
                log.info("Multicast Underlay Scale is as per Configuration\n\n")
            else:
                log.error("Multicast Underlay Scale is NOT as per Configuration\n\n")

        log.info(banner('Waiting for 10 seconds before measuring the Traffic Stats: '))
        countDownTimer(10)

    @aetest.test
    def Verify_Traffic_Post_Trigger(self, testscript,log):
        """ Verify_Traffic_Post_Trigger """

        result = verifyTraffic(testscript)
        if result['status'] == 0:
            self.failed(reason=result['msgs'])
        else:
            self.passed(reason=result['msgs'])

# *****************************************************************************************************************************#

class TC047_Verify_512_Underlay_Scale_on_AC_BGW(aetest.Testcase):
    """ TC047_Verify_512_Underlay_Scale_on_AC_BGW """

    @aetest.test
    def Verify_512_Underlay_Scale_on_AC_BGW(self,testscript,log):
        """ Verify_512_Underlay_Scale_on_AC_BGW """

        node_dict = testscript.parameters['node_dict']

        uut_list = ['uut6','uut7']
        for node in uut_list:
            log.info(banner('Verifying 512 Underlay Scale on AC BGW for: {0}'.format(node)))
            hdl = node_dict['all_dut'][node]
            mroute_summary = json.loads(hdl.execute('''show ip mroute summary count vrf default | json'''))
            mcast_ul_scale = mroute_summary['TABLE_vrf']['ROW_vrf']['TABLE_route_summary']['ROW_route_summary']['star-g-route']
            if int(mcast_ul_scale) == 500:
                log.info("Multicast Underlay Scale is as per Configuration on AC BGWs\n\n")
            else:
                log.error("Multicast Underlay Scale is NOT as per Configuration on AC BGWs\n\n")

        log.info(banner('Waiting for 10 seconds before measuring the Traffic Stats: '))
        countDownTimer(10)

    @aetest.test
    def Verify_Traffic_Post_Trigger(self, testscript,log):
        """ Verify_Traffic_Post_Trigger """

        result = verifyTraffic(testscript)
        if result['status'] == 0:
            self.failed(reason=result['msgs'])
        else:
            self.passed(reason=result['msgs'])

# *****************************************************************************************************************************#

class TC048_vPC_BGW_L2VNI_SVI_Shut_UnShut(aetest.Testcase):
    """ TC048_vPC_BGW_L2VNI_SVI_Shut_UnShut """

    @aetest.test
    def vPC_BGW_L2VNI_SVI_Shut_UnShut(self,testscript,log,steps):
        """ vPC_BGW_L2VNI_SVI_Shut_UnShut """

        node_dict = testscript.parameters['node_dict']
        configdict = testscript.parameters['configdict']
        alias_intf_mapping = testscript.parameters['alias_intf_mapping']
        scale_config_obj = MyLib.my_config_utils.ScaleConfig(log,node_dict,configdict,alias_intf_mapping)
        
        res = [node_dict['all_dut'][dut].execute('terminal session-timeout 0') for dut in node_dict['all_dut'] if re.search('uut', dut)]
                
        log.info(banner('Test:- L2 VNI SVI Shut/Unshut on Both VPC BGWs...'))

        vpc_dict = scale_config_obj.getMultisiteDeviceDict('vpc_vtep')
        
        log.info('The value of VPC_DICT is : {0}'.format(vpc_dict))

        with steps.start('Backing Up Configs - on VPC BGWs') as s:
            log.info(banner('Backing Up  configs on duts {0}'.format(list(vpc_dict.keys()))))
            
            for dut in vpc_dict.keys():
                log.info(banner('Backing up config on dut : {0}'.format(dut)))
                res = MyLib.my_utils.configBackUpOrRestoreOrCleanUp(log,node_dict['all_dut'][dut],'backup')
                if not res:
                    log.error(banner('restore Failed on the dut: {0}'.format(dut)))
                    self.failed()
                    
        with steps.start('Shutting Down L2 VNI VLAN on VPC BGWs')  as s:
            log.info(banner('Shutting Down L2 VNI VLAN on VPC BGWs {0}'.format(list(vpc_dict.keys()))))
            for dut in vpc_dict:
                args = configdict['scale_config_dict'][dut]['global']['vlan']
                ns = MyLib.my_config_utils.parseScaleVlanParms(log,args)
                for i in range(ns.l2_vlan_start, ns.l2_vlan_start+ns.no_of_l2_vlans):
                    cfg = '''interface vlan {0}
                                shutdown'''.format(i)
                    node_dict['all_dut'][dut].configure(cfg)
                    
        log.info(banner('Wait for 180 seconds'))
        countDownTimer(180)

        with steps.start('Restoring Configs - on vPC BGWs') as s:
            log.info(banner('Restoring  configs on duts {0}'.format(list(vpc_dict.keys()))))
            
            for dut in vpc_dict.keys():
                log.info(banner('Restoring config on dut : {0}'.format(dut)))
                res = MyLib.my_utils.configBackUpOrRestoreOrCleanUp(log,node_dict['all_dut'][dut],'restore')
                if not res:
                    log.error(banner('restore Failed on the dut: {0}'.format(dut)))
                    self.failed
                    
        log.info(banner('Waiting for 180 seconds before measuring the Traffic Stats: '))
        countDownTimer(300)

    @aetest.test
    def Verify_Traffic_Post_Trigger(self, testscript,log):
        """ Verify_Traffic_Post_Trigger """

        result = verifyTraffic(testscript)
        if result['status'] == 0:
            self.failed(reason=result['msgs'])
        else:
            self.passed(reason=result['msgs'])

# *****************************************************************************************************************************#

class TC049_AC_BGW_L2VNI_SVI_Shut_UnShut(aetest.Testcase):
    """ TC049_AC_BGW_L2VNI_SVI_Shut_UnShut """

    @aetest.test
    def AC_BGW_L2VNI_SVI_Shut_UnShut(self,testscript,log,steps):
        """ AC_BGW_L2VNI_SVI_Shut_UnShut """

        node_dict = testscript.parameters['node_dict']
        configdict = testscript.parameters['configdict']
        
        res = [node_dict['all_dut'][dut].execute('terminal session-timeout 0') for dut in node_dict['all_dut'] if re.search('uut', dut)]
                
        log.info(banner('Test:- L2 VNI VLAN Shut/Unshut on Both AC BGWs...'))

        ac_dict = ['uut6','uut7']

        with steps.start('Backing Up Configs - on AC BGWs') as s:
            log.info(banner('Backing Up Configs - on AC BGWs {0}'.format(list(ac_dict))))
            
            for dut in ac_dict:
                log.info(banner('Backing Up configs on dut : {0}'.format(dut)))
                res = MyLib.my_utils.configBackUpOrRestoreOrCleanUp(log,node_dict['all_dut'][dut],'backup')
                if not res:
                    log.error(banner('Backing Up Failed on the dut: {0}'.format(dut)))
                    self.failed()
                    
        with steps.start('Shutting Down L2 VNI VLAN on AC BGWs')  as s:
            log.info(banner('Shutting Down L2 VNI VLAN on AC BGWs {0}'.format(list(ac_dict))))
            for dut in ac_dict:
                args = configdict['scale_config_dict'][dut]['global']['vlan']
                ns = MyLib.my_config_utils.parseScaleVlanParms(log,args)
                for i in range(ns.l2_vlan_start, ns.l2_vlan_start+ns.no_of_l2_vlans):
                    cfg = '''interface vlan {0}
                                shutdown'''.format(i)
                    node_dict['all_dut'][dut].configure(cfg)
                    
        log.info(banner('Wait for 120 seconds'))
        countDownTimer(120)

        with steps.start('Restoring Configs - on AC BGWs') as s:
            log.info(banner('Restoring Configs - on AC BGWs {0}'.format(list(ac_dict))))
            
            for dut in ac_dict:
                log.info(banner('Restoring config on dut : {0}'.format(dut)))
                res = MyLib.my_utils.configBackUpOrRestoreOrCleanUp(log,node_dict['all_dut'][dut],'restore')
                if not res:
                    log.error(banner('restore Failed on the dut: {0}'.format(dut)))
                    self.failed
                    
        log.info(banner('Waiting for 180 seconds before measuring the Traffic Stats: '))
        countDownTimer(180)
        
    @aetest.test
    def Verify_Traffic_Post_Trigger(self, testscript,log):
        """ Verify_Traffic_Post_Trigger """

        result = verifyTraffic(testscript)
        if result['status'] == 0:
            self.failed(reason=result['msgs'])
        else:
            self.passed(reason=result['msgs'])

# *****************************************************************************************************************************#

class TC050_vPC_BGW_L3VNI_SVI_Shut_UnShut(aetest.Testcase):
    """ TC050_vPC_BGW_L3VNI_SVI_Shut_UnShut """

    @aetest.test
    def vPC_BGW_L3VNI_SVI_Shut_UnShut(self,testscript,log,steps):
        """ vPC_BGW_L3VNI_SVI_Shut_UnShut """

        node_dict = testscript.parameters['node_dict']
        configdict = testscript.parameters['configdict']
        alias_intf_mapping = testscript.parameters['alias_intf_mapping']
        scale_config_obj = MyLib.my_config_utils.ScaleConfig(log,node_dict,configdict,alias_intf_mapping)
        log = testscript.parameters['log']
        
        res = [node_dict['all_dut'][dut].execute('terminal session-timeout 0') for dut in node_dict['all_dut'] if re.search('uut', dut)]
                
        log.info(banner('Test:- L3 VNI Shut/Unshut on Both VPC BGWs...'))

        vpc_dict = scale_config_obj.getMultisiteDeviceDict('vpc_vtep')
        
        log.info('The value of VPC_DICT is : {0}'.format(vpc_dict))

        with steps.start('Backing Up Configs - on VPC BGWs') as s:
            log.info(banner('Backing Up  configs on duts {0}'.format(list(vpc_dict.keys()))))
            
            for dut in vpc_dict.keys():
                log.info(banner('Restoring config on dut : {0}'.format(dut)))
                res = MyLib.my_utils.configBackUpOrRestoreOrCleanUp(log,node_dict['all_dut'][dut],'backup')
                if not res:
                    log.error(banner('restore Failed on the dut: {0}'.format(dut)))
                    self.failed()
                    
        with steps.start('Shutting Down L3 VNI on VPC BGWs')  as s:
            log.info(banner('Shutting Down L3 VNI on duts {0}'.format(list(vpc_dict.keys()))))
            for dut in vpc_dict:
                args = configdict['scale_config_dict'][dut]['global']['vlan']
                ns = MyLib.my_config_utils.parseScaleVlanParms(log,args)
                for i in range(ns.l3_vlan_start, ns.l3_vlan_start+ns.no_of_l3_vlans):
                    cfg = '''interface vlan {0}
                                shutdown'''.format(i)
                    node_dict['all_dut'][dut].configure(cfg)
                    
        log.info(banner('Wait for 120 seconds'))
        countDownTimer(120)

        with steps.start('Restoring Configs - on vPC BGWs') as s:
            log.info(banner('Restoring  configs on duts {0}'.format(list(vpc_dict.keys()))))
            
            for dut in vpc_dict.keys():
                log.info(banner('Restoring config on dut : {0}'.format(dut)))
                res = MyLib.my_utils.configBackUpOrRestoreOrCleanUp(log,node_dict['all_dut'][dut],'restore')
                if not res:
                    log.error(banner('restore Failed on the dut: {0}'.format(dut)))
                    self.failed
                    
        log.info(banner('Waiting for 180 seconds before measuring the Traffic Stats: '))
        countDownTimer(180)
        
    @aetest.test
    def Verify_Traffic_Post_Trigger(self, testscript,log):
        """ Verify_Traffic_Post_Trigger """

        result = verifyTraffic(testscript)
        if result['status'] == 0:
            self.failed(reason=result['msgs'])
        else:
            self.passed(reason=result['msgs'])

# *****************************************************************************************************************************#

class TC051_AC_BGW_L3VNI_SVI_Shut_UnShut(aetest.Testcase):
    """ TC051_AC_BGW_L3VNI_SVI_Shut_UnShut """

    @aetest.test
    def AC_BGW_L3VNI_SVI_Shut_UnShut(self,testscript,log,steps):
        """ AC_BGW_L3VNI_SVI_Shut_UnShut """

        node_dict = testscript.parameters['node_dict']
        configdict = testscript.parameters['configdict']
        
        res = [node_dict['all_dut'][dut].execute('terminal session-timeout 0') for dut in node_dict['all_dut'] if re.search('uut', dut)]
                
        log.info(banner('Test:- L3 VNI Shut/Unshut on Both AC BGWs...'))

        ac_dict = ['uut6','uut7']

        with steps.start('Backing Up Configs - on AC BGWs') as s:
            log.info(banner('Backing Up Configs - on AC BGWs {0}'.format(list(ac_dict))))
            
            for dut in ac_dict:
                log.info(banner('Backing Up configs on dut : {0}'.format(dut)))
                res = MyLib.my_utils.configBackUpOrRestoreOrCleanUp(log,node_dict['all_dut'][dut],'backup')
                if not res:
                    log.error(banner('Backing Up Failed on the dut: {0}'.format(dut)))
                    self.failed()
                    
        with steps.start('Shutting down L3VNI on AC BGWs')  as s:
            log.info(banner('Shutting down L3VNI on AC BGWs {0}'.format(list(ac_dict))))
            for dut in ac_dict:
                args = configdict['scale_config_dict'][dut]['global']['vlan']
                ns = MyLib.my_config_utils.parseScaleVlanParms(log,args)
                for i in range(ns.l3_vlan_start, ns.l3_vlan_start+ns.no_of_l3_vlans):
                    cfg = '''interface vlan {0}
                                shutdown'''.format(i)
                    node_dict['all_dut'][dut].configure(cfg)
                    
        log.info(banner('Wait for 120 seconds'))
        countDownTimer(120)

        with steps.start('Restoring Configs - on AC BGWs') as s:
            log.info(banner('Restoring Configs - on AC BGWs {0}'.format(list(ac_dict))))
            
            for dut in ac_dict:
                log.info(banner('Restoring config on dut : {0}'.format(dut)))
                res = MyLib.my_utils.configBackUpOrRestoreOrCleanUp(log,node_dict['all_dut'][dut],'restore')
                if not res:
                    log.error(banner('restore Failed on the dut: {0}'.format(dut)))
                    self.failed
                    
        log.info(banner('Waiting for 180 seconds before measuring the Traffic Stats: '))
        countDownTimer(180)
        
    @aetest.test
    def Verify_Traffic_Post_Trigger(self, testscript,log):
        """ Verify_Traffic_Post_Trigger """

        result = verifyTraffic(testscript)
        if result['status'] == 0:
            self.failed(reason=result['msgs'])
        else:
            self.passed(reason=result['msgs'])

# *****************************************************************************************************************************#

class TC052_RemovingFeatureNGMVPNOnBGW(aetest.Testcase):

    """ TC052_RemovingFeatureNGMVPNOnBGW """

    @aetest.test
    def RemovingFeatureNGMVPNOnBGW(self,log,testscript,steps):
        node_dict = testscript.parameters['node_dict']
        config_dict = testscript.parameters['configdict']
        alias_intf_mapping = testscript.parameters['alias_intf_mapping']
        scale_config_obj = MyLib.my_config_utils.ScaleConfig(log,node_dict,config_dict,alias_intf_mapping)
        log = testscript.parameters['log'] 
        
        res = [node_dict['all_dut'][dut].execute('terminal session-timeout 0') for dut in node_dict['all_dut'] if re.search('uut', dut)]
                
        log.info(banner('Test:- Removing Feature NGMVPN on BGWs'))

        bgw_dict = scale_config_obj.getMultisiteDeviceDict('bgw')

        with steps.start('Backup Configs - on BGWs') as s:
            log.info(banner('Backing up configs on duts {0}'.format(list(bgw_dict.keys()))))
            
            for dut in bgw_dict.keys():
                log.info(banner('Backing up config on dut : {0}'.format(dut)))
                res = MyLib.my_utils.configBackUpOrRestoreOrCleanUp(log,node_dict['all_dut'][dut],'backup')
                if not res:
                    log.error(banner('Backup Failed on the dut: {0}'.format(dut)))
                    self.failed()
        
        with steps.start('Remove Feature NGMVPN  - on BGWs') as s:
            log.info(banner('Remove Feature NGMVPN on duts {0}'.format(list(bgw_dict.keys()))))
            
            for dut in bgw_dict.keys():
                log.info(banner('Removing feature ngmvpn on dut : {0}'.format(dut)))
                out=bringup_lib.unconfigFeature(node_dict['all_dut'][dut], log, '-feature ngmvpn' )
                if out.result=='fail':
                    log.error('Disable of NGMVPN failed on dut %s' % dut)
                    self.failed()
                else:
                    log.info('Disable of NGMVPN passes on dut %s' % dut)

        with steps.start('Restoring Configs - on BGWs') as s:
            log.info(banner('Restoring  configs on duts {0}'.format(list(bgw_dict.keys()))))
            
            for dut in bgw_dict.keys():
                log.info(banner('Restoring config on dut : {0}'.format(dut)))
                res = MyLib.my_utils.configBackUpOrRestoreOrCleanUp(log,node_dict['all_dut'][dut],'restore')
                if not res:
                    log.error(banner('restore Failed on the dut: {0}'.format(dut)))
                    self.failed
                    
        log.info(banner('Waiting for 180 seconds before measuring the Traffic Stats: '))
        countDownTimer(180)

    @aetest.test
    def Verify_Traffic_Post_Trigger(self, testscript,log):
        """ Verify_Traffic_Post_Trigger """

        result = verifyTraffic(testscript)
        if result['status'] == 0:
            self.failed(reason=result['msgs'])
        else:
            self.passed(reason=result['msgs'])

# *****************************************************************************************************************************#

class TC053_ShuttingDCILinksOnVPCPrimary(aetest.Testcase):

    """ TC053_ShuttingDCILinksOnVPCPrimary """

    @aetest.test
    def ShuttingDCILinksOnVPCPrimary(self,log,testscript, steps):
        node_dict = testscript.parameters['node_dict']
        config_dict = testscript.parameters['configdict']
        alias_intf_mapping = testscript.parameters['alias_intf_mapping']
        scale_config_obj = MyLib.my_config_utils.ScaleConfig(log,node_dict,config_dict,alias_intf_mapping)
        log = testscript.parameters['log'] 
        
        res = [node_dict['all_dut'][dut].execute('terminal session-timeout 0') for dut in node_dict['all_dut'] if re.search('uut', dut)]
                
        log.info(banner('Test:- Shutting DCI links on VPC Primary...'))

        bgw_dict = scale_config_obj.getMultisiteDeviceDict('bgw')
                
        with steps.start('Getting VPC Primary handle') as s:
            log.info(banner('Getting VPC Primary handle'))
            vpc_dict = {}
            
            for dev in node_dict.keys():
                if re.search('Site',dev, re.IGNORECASE):
                    for dut in node_dict[dev].keys():
                        if re.search('VPC', dut):
                            vpc_dict.update(node_dict[dev][dut])
            log.info(banner('The value of VPC_dict is: {0}'.format(vpc_dict)))
            
            vpc_primary = MyLib.my_utils.returnVPCSwitchHandle(log,vpc_dict)['primary']
            log.info('The value of VPC_primary is: {0}'.format(vpc_primary))

        
        with steps.start('Getting the DCI links from VPC Primary') as s:
            log.info(banner('Getting the DCI links from VPC Primary {0}'.format(vpc_primary['dut'])))
            
            cfg = 'sh nve multisite dci-links | xml'
            switch_hdl = vpc_primary['hdl']
            out = switch_hdl.execute(cfg)
            intf_list = []
            for line in out.splitlines():
                if re.search('if-name',line,re.IGNORECASE):
                    s = BeautifulSoup(line)
                    try:
                        intf = s.find('if-name').string
                        intf_list.append(intf)
                    except Exception:
                        log.error('Interface name could not be generated')
                        flag = 2
            log.info('The value of intf_list is : {0}'.format(intf_list))
            
            if intf_list:
                for intf in intf_list:
                    cfg = '''interface {0}
                                shutdown'''.format(intf)
                    switch_hdl.configure(cfg)

        with steps.start('Restoring Configs - on BGWs') as s:
            log.info(banner('Restoring  configs on duts {0}'.format(list(bgw_dict.keys()))))
            
            for dut in bgw_dict.keys():
                log.info(banner('Restoring config on dut : {0}'.format(dut)))
                res = MyLib.my_utils.configBackUpOrRestoreOrCleanUp(log,node_dict['all_dut'][dut],'restore')
                if not res:
                    log.error(banner('restore Failed on the dut: {0}'.format(dut)))
                    self.failed
                    
        log.info(banner('Waiting for 180 seconds before measuring the Traffic Stats: '))
        countDownTimer(180)
       
    @aetest.test
    def Verify_Traffic_Post_Trigger(self, testscript,log):
        """ Verify_Traffic_Post_Trigger """

        result = verifyTraffic(testscript)
        if result['status'] == 0:
            self.failed(reason=result['msgs'])
        else:
            self.passed(reason=result['msgs'])

# *****************************************************************************************************************************#

class TC054_ShuttingFabricLinksOnVPCPrimary(aetest.Testcase):

    """ TC054_ShuttingFabricLinksOnVPCPrimary """

    @aetest.test
    def ShuttingFabricLinksOnVPCPrimary(self,log,testscript,steps):
        node_dict = testscript.parameters['node_dict']
        configdict = testscript.parameters['configdict']
        alias_intf_mapping = testscript.parameters['alias_intf_mapping']
        scale_config_obj = MyLib.my_config_utils.ScaleConfig(log,node_dict,configdict,alias_intf_mapping)
        log = testscript.parameters['log']
        
        res = [node_dict['all_dut'][dut].execute('terminal session-timeout 0') for dut in node_dict['all_dut'] if re.search('uut', dut)]
                
        log.info(banner('Test:- Shutting Fabric links on VPC Primary...'))

        bgw_dict = scale_config_obj.getMultisiteDeviceDict('bgw')
                
        with steps.start('Getting VPC Primary handle') as s:
            log.info(banner('Getting VPC Primary handle'))
            vpc_dict = {}
            
            for dev in node_dict.keys():
                if re.search('Site',dev, re.IGNORECASE):
                    for dut in node_dict[dev].keys():
                        if re.search('VPC', dut):
                            vpc_dict.update(node_dict[dev][dut])
            log.info(banner('The value of VPC_dict is: {0}'.format(vpc_dict)))
            
            vpc_primary = MyLib.my_utils.returnVPCSwitchHandle(log,vpc_dict)['primary']
            log.info('The value of VPC_primary is: {0}'.format(vpc_primary))

        
        with steps.start('Getting the Fabric links from VPC Primary') as s:
            log.info(banner('Getting the Fabric links from VPC Primary {0}'.format(vpc_primary['dut'])))
            
            cfg = 'sh nve multisite fabric-links  | xml'
            switch_hdl = vpc_primary['hdl']
            out = switch_hdl.execute(cfg)
            intf_list = []
            for line in out.splitlines():
                if re.search('if-name',line,re.IGNORECASE):
                    s = BeautifulSoup(line)
                    try:
                        intf = s.find('if-name').string
                        intf_list.append(intf)
                    except Exception:
                        log.error('Interface name could not be generated')
                        flag = 2
            log.info('The value of intf_list is : {0}'.format(intf_list))
            
            if intf_list:
                for intf in intf_list:
                    cfg = '''interface {0}
                                shutdown'''.format(intf)
                    switch_hdl.configure(cfg)

        with steps.start('Restoring Configs - on BGWs') as s:
            log.info(banner('Restoring  configs on duts {0}'.format(list(bgw_dict.keys()))))
            
            for dut in bgw_dict.keys():
                log.info(banner('Restoring config on dut : {0}'.format(dut)))
                res = MyLib.my_utils.configBackUpOrRestoreOrCleanUp(log,node_dict['all_dut'][dut],'restore')
                if not res:
                    log.error(banner('restore Failed on the dut: {0}'.format(dut)))
                    self.failed
                    
        log.info(banner('Waiting for 180 seconds before measuring the Traffic Stats: '))
        countDownTimer(180)
        
    @aetest.test
    def Verify_Traffic_Post_Trigger(self, testscript,log):
        """ Verify_Traffic_Post_Trigger """

        result = verifyTraffic(testscript)
        if result['status'] == 0:
            self.failed(reason=result['msgs'])
        else:
            self.passed(reason=result['msgs'])

# *****************************************************************************************************************************#

class TC055_ShuttingVPCPeerkeepalive(aetest.Testcase):

    """ TC055_ShuttingVPCPeerkeepalive """

    @aetest.test
    def ShuttingVPCPeerkeepalive(self,log,testscript,steps):
        node_dict = testscript.parameters['node_dict']
        log = testscript.parameters['log']
        configdict = testscript.parameters['configdict']
                
        log.info(banner('Test:- Flapping VPC Peer-Keepalive on VPC Primary...'))
                    
        with steps.start('Getting VPC Primary handle') as s:
            log.info(banner('Getting VPC Primary handle'))
            vpc_dict = {}
            
            for dev in node_dict.keys():
                if re.search('Site',dev, re.IGNORECASE):
                    for dut in node_dict[dev].keys():
                        if re.search('VPC', dut):
                            vpc_dict.update(node_dict[dev][dut])
            log.info(banner('The value of VPC_dict is: {0}'.format(vpc_dict)))
            
            vpc_primary = MyLib.my_utils.returnVPCSwitchHandle(log,vpc_dict)['primary']
            log.info('The value of VPC_primary is: {0}'.format(vpc_primary))

        ifmgmt = parseVpcDomainParams(configdict['vpc_config_dict'][vpc_primary['dut']]['vpc_domain'],log).peer_keepalive_vrf

        if ifmgmt == "management":
            with steps.start('Shutting down the vPC Keepalive on VPC Primary') as s:
                log.info(banner('Shutting down the vPC Keepalive on VPC Primary {0}'.format(vpc_primary['dut'])))
                switch_hdl = vpc_primary['hdl']
                cfg = '''terminal dont-ask
                            interface mgmt0
                            shutdown'''
                switch_hdl.configure(cfg)

            with steps.start('Checking status of Keepalive link') as s:
                cfg = 'show int mgmt0 | xml'
                out = switch_hdl.execute(cfg)
                s = BeautifulSoup(out)
                try:
                    state = s.find('admin_state').string
                    if re.search('down', state, re.IGNORECASE):
                        log.info('The link is admin shut as expected. state is {0}'.format(state))
                except Exception:
                    log.error(banner('Could not find the admin state of the interface .. Hence failing the test case.'))
                    self.failed()
                    
            log.info('Waiting for 30 seconds before bringing up the Interface')
            countDownTimer(30)

            with steps.start('Bringing up the VPC Keepalive link') as s:
                log.info(banner('Bringing up the VPC Keepalive link on VPC Primary {0}'.format(vpc_primary['dut'])))
                
                log.info('Checking the status of Peer-keepalive')
                out = switch_hdl.execute('show vpc | xml')
                s = BeautifulSoup(out)
                try:
                    keepalive_status = s.find('vpc-peer-keepalive-status').string
                    if re.search('not', keepalive_status,re.IGNORECASE):
                        log.info('The Keepalive status is as expected.. .The state is {0}'.format(keepalive_status))
                        
                        cfg = '''no terminal dont-ask
                                    interface mgmt0
                                    no shutdown'''
                        switch_hdl.configure(cfg)
                        countDownTimer(15)
                        
                except Exception:
                    log.error('The VPC KEepalive status is not as expected. Failing the test case w/o proceeding')
                    self.failed()
                    
            with steps.start('Check VPC Keepalive interface status and VPC Status ') as s:
                log.info(banner('Check VPC Keepalive interface status and VPC Status on VPC Primary {0}'.format(vpc_primary['dut'])))
                
                log.info('Checking the Interface status:')
                
                cfg = 'show int mgm0 | xml'
                out = switch_hdl.execute(cfg)
                s = BeautifulSoup(out)
                link_flag = 0
                try:
                    state = s.find('admin_state').string
                    if re.search('up', state, re.IGNORECASE):
                        log.info('The link is Up as expected. state is {0}'.format(state))
                        link_flag = 1
                except Exception:
                    log.error(banner('Link is not up as expected. .. Hence failing the test case.'))
                    self.failed()
                    
                if link_flag:
                    log.info(banner('Checking the VPC Keepalive status:'))
                    out = switch_hdl.execute('show vpc | xml')
                    s = BeautifulSoup(out)
                    try:
                        keepalive_status = s.find('vpc-peer-keepalive-status').string
                        if re.search('peer-alive', keepalive_status,re.IGNORECASE):
                            log.info('The Keepalive status is as expected.. .The state is {0}'.format(keepalive_status))
                            log.info(banner('Proceeding with traffic measurement.. Waiting for 100 sec'))

                    except Exception:
                        log.error('The VPC Keepalive status is not as expected. Failing the test case w/o proceeding')
                        self.failed() 
        else:    
            with steps.start('Getting the Peer Keepalive link from VPC Primary') as s:
                log.info(banner('Getting the Peer Keepalive link VPC Primary {0}'.format(vpc_primary['dut'])))
                
                cfg = 'sh ip arp detail vrf VPC-KEEPALIVE | xml'
                switch_hdl = vpc_primary['hdl']
                out = switch_hdl.execute(cfg)
                s = BeautifulSoup(out)
                try:
                    intf = s.find('intf-out').string
                except Exception:
                    log.error(banner('Could not find the Interface Corresponding to VPC Keepalive. Failing the test case'))
                    self.failed()
                
            with steps.start('Shutting down the vPC Keepalive on VPC Primary') as s:
                log.info(banner('Shutting down the vPC Keepalive on VPC Primary {0}'.format(vpc_primary['dut'])))

                switch_hdl = vpc_primary['hdl']
                cfg = '''interface {0}
                            shutdown'''.format(intf)
                switch_hdl.configure(cfg)

            with steps.start('Checking status of Keepalive link') as s:
                cfg = 'show int {0} | xml'.format(intf)
                out = switch_hdl.execute(cfg)
                s = BeautifulSoup(out)
                try:
                    state = s.find('admin_state').string
                    if re.search('down', state, re.IGNORECASE):
                        log.info('The link is admin shut as expected. state is {0}'.format(state))
                except Exception:
                    log.error(banner('Could not find the admin state of the interface .. Hence failing the test case.'))
                    self.failed()
                    
            log.info('Waiting for 30 seconds before bringing up the Interface')
            countDownTimer(30)

            with steps.start('Bringing up the VPC Keepalive link') as s:
                log.info(banner('Bringing up the VPC Keepalive link on VPC Primary {0}'.format(vpc_primary['dut'])))
                
                log.info('Checking the status of Peer-keepalive')
                out = switch_hdl.execute('show vpc | xml')
                s = BeautifulSoup(out)
                try:
                    keepalive_status = s.find('vpc-peer-keepalive-status').string
                    if re.search('not', keepalive_status,re.IGNORECASE):
                        log.info('The Keepalive status is as expected.. .The state is {0}'.format(keepalive_status))
                        
                        cfg = '''interface {0}
                                    no shutdown'''.format(intf)
                        switch_hdl.configure(cfg)
                        countDownTimer(15)
                        
                except Exception:
                    log.error('The VPC KEepalive status is not as expected. Failing the test case w/o proceeding')
                    self.failed()
                    
            with steps.start('Check VPC Keepalive interface status and VPC Status ') as s:
                log.info(banner('Check VPC Keepalive interface status and VPC Status on VPC Primary {0}'.format(vpc_primary['dut'])))
                
                log.info('Checking the Interface status:')
                
                cfg = 'show int {0} | xml'.format(intf)
                out = switch_hdl.execute(cfg)
                s = BeautifulSoup(out)
                link_flag = 0
                try:
                    state = s.find('admin_state').string
                    if re.search('up', state, re.IGNORECASE):
                        log.info('The link is Up as expected. state is {0}'.format(state))
                        link_flag = 1
                except Exception:
                    log.error(banner('Link is not up as expected. .. Hence failing the test case.'))
                    self.failed()
                    
                if link_flag:
                    log.info(banner('Checking the VPC Keepalive status:'))
                    out = switch_hdl.execute('show vpc | xml')
                    s = BeautifulSoup(out)
                    try:
                        keepalive_status = s.find('vpc-peer-keepalive-status').string
                        if re.search('peer-alive', keepalive_status,re.IGNORECASE):
                            log.info('The Keepalive status is as expected.. .The state is {0}'.format(keepalive_status))
                            log.info(banner('Proceeding with traffic measurement.. Waiting for 100 sec'))

                    except Exception:
                        log.error('The VPC Keepalive status is not as expected. Failing the test case w/o proceeding')
                        self.failed()                

                    
        log.info(banner('Waiting for 180 seconds before measuring the Traffic Stats: '))
        countDownTimer(180)
        
    @aetest.test
    def Verify_Traffic_Post_Trigger(self, testscript,log):
        """ Verify_Traffic_Post_Trigger """

        result = verifyTraffic(testscript)
        if result['status'] == 0:
            self.failed(reason=result['msgs'])
        else:
            self.passed(reason=result['msgs'])

# *****************************************************************************************************************************#

class TC056_SplitBrainScenario(aetest.Testcase):

    """ TC056_SplitBrainScenario """

    @aetest.test
    def SplitBrainScenario(self,log,testscript,steps):
        node_dict = testscript.parameters['node_dict']
        log = testscript.parameters['log']
        configdict = testscript.parameters['configdict']
                
        log.info(banner('Test:- L3 TRM with VPC as BGW - SplitBrain Scenario...'))
        
        with steps.start('Getting VPC Primary handle') as s:
            log.info(banner('Getting VPC Primary handle'))
            vpc_dict = {}
            
            for dev in node_dict.keys():
                if re.search('Site',dev, re.IGNORECASE):
                    for dut in node_dict[dev].keys():
                        if re.search('VPC', dut):
                            vpc_dict.update(node_dict[dev][dut])
            log.info(banner('The value of VPC_dict is: {0}'.format(vpc_dict)))
            
            vpc_primary = MyLib.my_utils.returnVPCSwitchHandle(log,vpc_dict)['primary']
            log.info(banner('The value of VPC_primary is: {0}'.format(vpc_primary)))

        ifmgmt = parseVpcDomainParams(configdict['vpc_config_dict'][vpc_primary['dut']]['vpc_domain'],log).peer_keepalive_vrf

        if ifmgmt == "management":
            with steps.start('Getting the Peer-link') as s:
                log.info(banner('Getting the Peer-link from VPC Primary {0}'.format(vpc_primary['dut'])))
                
                cfg = 'sh vpc  | xml'
                switch_hdl = vpc_primary['hdl']
                out = switch_hdl.execute(cfg)
                s = BeautifulSoup(out)
                try:
                    peerlink_intf = s.find('peerlink-ifindex').string
                    log.info(banner('The value of peerlink_intf is : {0}'.format(peerlink_intf)))
                except Exception:
                    log.error(banner('Could not find the Interface Corresponding to VPC Keepalive. Failing the test case'))
                    self.failed()

            with steps.start('Shutting down the vPC Keepalive') as s:
                log.info(banner('Shutting down the vPC Keepalive on VPC Primary {0}'.format(vpc_primary['dut'])))
                
                cfg = '''terminal dont-ask
                            interface mgmt0
                            shutdown'''
                switch_hdl.configure(cfg)
                
            with steps.start('Shutting down the vPC PeerLink') as s:
                log.info(banner('Shutting down the vPC PeerLink on VPC Primary {0}'.format(vpc_primary['dut'])))
                
                cfg = '''interface {0}
                            shutdown'''.format(peerlink_intf)
                switch_hdl.configure(cfg)

            with steps.start('Checking status of Keepalive link') as s:
                cfg = 'show int mgmt0 | xml'
                out = switch_hdl.execute(cfg)
                s = BeautifulSoup(out)
                try:
                    state = s.find('admin_state').string
                    if re.search('down', state, re.IGNORECASE):
                        log.info(banner('The link is admin shut as expected. state is {0}'.format(state)))
                except Exception:
                    log.error(banner('Could not find the admin state of the interface .. Hence failing the test case.'))
                    self.failed()
                    
            with steps.start('Checking status of Peerlink') as s:
                cfg = 'show int {0} | xml'.format(peerlink_intf)
                out = switch_hdl.execute(cfg)
                s = BeautifulSoup(out)
                try:
                    state = s.find('admin_state').string
                    if re.search('down', state, re.IGNORECASE):
                        log.info(banner('The link is admin shut as expected. state is {0}'.format(state)))
                except Exception:
                    log.error(banner('Could not find the admin state of the interface .. Hence failing the test case.'))
                    self.failed()


            log.info('Waiting for 180 seconds before bringing up the Interface')
            countDownTimer(180)

            with steps.start('Bringing up the VPC Keepalive link') as s:
                log.info(banner('Bringing up the VPC Keepalive link on VPC Primary {0}'.format(vpc_primary['dut'])))
                
                log.info('Checking the status of Peer-keepalive')
                out = switch_hdl.execute('show vpc | xml')
                s = BeautifulSoup(out)
                try:

                    keepalive_status = s.find('vpc-peer-keepalive-status').string
                    peer_link_status = int(s.find('peer-link-port-state').string)

                    if re.search('not', keepalive_status,re.IGNORECASE):
                        log.info('The Keepalive status is as expected.. .The state is {0}'.format(keepalive_status))
                        cfg = '''no terminal dont-ask
                                    interface mgmt0
                                    no shutdown'''
                        switch_hdl.configure(cfg)
                        countDownTimer(15)
                        
                    log.info('The value of peer_link_status is : {0} and type is : {1}'.format(peer_link_status, type(peer_link_status)))
                    
                    if not peer_link_status:
                        log.info('The peerlink Status is as expected.. The state is {0}'.format(peer_link_status))
                        cfg = '''interface {0}
                                    no shutdown'''.format(peerlink_intf)
                        switch_hdl.configure(cfg)
                        countDownTimer(15)

                except Exception:
                    log.error('The VPC KEepalive status  / peerlink status is not as expected. Failing the test case w/o proceeding')
                    self.failed()
                    
            with steps.start('Check VPC Keepalive interface status and VPC Status ') as s:
                log.info(banner('Check VPC Keepalive interface status and VPC Status on VPC Primary {0}'.format(vpc_primary['dut'])))
                
                log.info('Checking the Interface status:')
                
                cfg = 'show int mgmt0 | xml'
                out = switch_hdl.execute(cfg)
                s = BeautifulSoup(out)
                link_flag = 0
                try:
                    state = s.find('admin_state').string
                    if re.search('up', state, re.IGNORECASE):
                        log.info(banner('The link is Up as expected. state is {0}'.format(state)))
                        link_flag = 1
                except Exception:
                    log.error(banner('Link is not up as expected. .. Hence failing the test case.'))
                    self.failed()
                    
                if link_flag:
                    log.info(banner('Checking the VPC Keepalive status:'))
                    out = switch_hdl.execute('show vpc | xml')
                    s = BeautifulSoup(out)
                    try:
                        keepalive_status = s.find('vpc-peer-keepalive-status').string
                        if re.search('peer-alive', keepalive_status,re.IGNORECASE):
                            log.info(banner('The Keepalive status is as expected.. .The state is {0}'.format(keepalive_status)))
                            log.info(banner('Proceeding with traffic measurement.. Waiting for 100 sec'))

                    except Exception:
                        log.error('The VPC KEepalive status is not as expected. Failing the test case w/o proceeding')
                        self.failed()                

            with steps.start('Check VPC Peerlink interface status and VPC Status ') as s:
                log.info(banner('Check VPC Peerlink interface status and VPC Status on VPC Primary {0}'.format(vpc_primary['dut'])))
                
                log.info('Checking the Interface status:')
                
                cfg = 'show int {0} | xml'.format(peerlink_intf)
                out = switch_hdl.execute(cfg)
                s = BeautifulSoup(out)
                link_flag = 0
                try:
                    state = s.find('admin_state').string
                    if re.search('up', state, re.IGNORECASE):
                        log.info(banner('The link is Up as expected. state is {0}'.format(state)))
                        link_flag = 1
                except Exception:
                    log.error(banner('Link is not up as expected. .. Hence failing the test case.'))
                    self.failed()
                    
                if link_flag:
                    log.info(banner('Checking the VPC Peerlink status:'))
                    out = switch_hdl.execute('show vpc | xml')
                    s = BeautifulSoup(out)
                    try:
                        peerlink_status = s.find('peer-link-port-state').string
                        if peerlink_status:
                            log.info(banner('The Keepalive status is as expected.. .The state is {0}'.format(peerlink_status)))
                            log.info(banner('Proceeding with traffic measurement.. Waiting for 180 sec'))

                    except Exception:
                        log.error('The VPC KEepalive status is not as expected. Failing the test case w/o proceeding')
                        self.failed()      
        else:
            with steps.start('Getting the Peer Keepalive link') as s:
                log.info(banner('Getting the Peer Keepalive link VPC Primary {0}'.format(vpc_primary['dut'])))
                
                cfg = 'sh ip arp detail vrf VPC-KEEPALIVE | xml'
                switch_hdl = vpc_primary['hdl']
                out = switch_hdl.execute(cfg)
                s = BeautifulSoup(out)
                try:
                    keepalive_intf = s.find('intf-out').string
                    log.info(banner('The value of keepalive_intf is : {0}'.format(keepalive_intf)))
                except Exception:
                    log.error(banner('Could not find the Interface Corresponding to VPC Keepalive. Failing the test case'))
                    self.failed()
                
            with steps.start('Getting the Peer-link') as s:
                log.info(banner('Getting the Peer-link from VPC Primary {0}'.format(vpc_primary['dut'])))
                
                cfg = 'sh vpc  | xml'
                out = switch_hdl.execute(cfg)
                s = BeautifulSoup(out)
                try:
                    peerlink_intf = s.find('peerlink-ifindex').string
                    log.info(banner('The value of peerlink_intf is : {0}'.format(peerlink_intf)))
                except Exception:
                    log.error(banner('Could not find the Interface Corresponding to VPC Keepalive. Failing the test case'))
                    self.failed()

            with steps.start('Shutting down the vPC Keepalive') as s:
                log.info(banner('Shutting down the vPC Keepalive on VPC Primary {0}'.format(vpc_primary['dut'])))
                
                cfg = '''interface {0}
                            shutdown'''.format(keepalive_intf)
                switch_hdl.configure(cfg)
                
            with steps.start('Shutting down the vPC PeerLink') as s:
                log.info(banner('Shutting down the vPC PeerLink on VPC Primary {0}'.format(vpc_primary['dut'])))
                
                cfg = '''interface {0}
                            shutdown'''.format(peerlink_intf)
                switch_hdl.configure(cfg)

            with steps.start('Checking status of Keepalive link') as s:
                cfg = 'show int {0} | xml'.format(keepalive_intf)
                out = switch_hdl.execute(cfg)
                s = BeautifulSoup(out)
                try:
                    state = s.find('admin_state').string
                    if re.search('down', state, re.IGNORECASE):
                        log.info(banner('The link is admin shut as expected. state is {0}'.format(state)))
                except Exception:
                    log.error(banner('Could not find the admin state of the interface .. Hence failing the test case.'))
                    self.failed()
                    
            with steps.start('Checking status of Peerlink') as s:
                cfg = 'show int {0} | xml'.format(peerlink_intf)
                out = switch_hdl.execute(cfg)
                s = BeautifulSoup(out)
                try:
                    state = s.find('admin_state').string
                    if re.search('down', state, re.IGNORECASE):
                        log.info(banner('The link is admin shut as expected. state is {0}'.format(state)))
                except Exception:
                    log.error(banner('Could not find the admin state of the interface .. Hence failing the test case.'))
                    self.failed()


            log.info('Waiting for 180 seconds before bringing up the Interface')
            countDownTimer(180)

            with steps.start('Bringing up the VPC Keepalive link') as s:
                log.info(banner('Bringing up the VPC Keepalive link on VPC Primary {0}'.format(vpc_primary['dut'])))
                
                log.info('Checking the status of Peer-keepalive')
                out = switch_hdl.execute('show vpc | xml')
                s = BeautifulSoup(out)
                try:

                    keepalive_status = s.find('vpc-peer-keepalive-status').string
                    peer_link_status = int(s.find('peer-link-port-state').string)

                    if re.search('not', keepalive_status,re.IGNORECASE):
                        log.info('The Keepalive status is as expected.. .The state is {0}'.format(keepalive_status))
                        cfg = '''interface {0}
                                    no shutdown'''.format(keepalive_intf)
                        switch_hdl.configure(cfg)
                        countDownTimer(15)
                        
                    log.info('The value of peer_link_status is : {0} and type is : {1}'.format(peer_link_status, type(peer_link_status)))
                    
                    if not peer_link_status:
                        log.info('The peerlink Status is as expected.. The state is {0}'.format(peer_link_status))
                        cfg = '''interface {0}
                                    no shutdown'''.format(peerlink_intf)
                        switch_hdl.configure(cfg)
                        countDownTimer(15)

                except Exception:
                    log.error('The VPC KEepalive status  / peerlink status is not as expected. Failing the test case w/o proceeding')
                    self.failed()
                    
            with steps.start('Check VPC Keepalive interface status and VPC Status ') as s:
                log.info(banner('Check VPC Keepalive interface status and VPC Status on VPC Primary {0}'.format(vpc_primary['dut'])))
                
                log.info('Checking the Interface status:')
                
                cfg = 'show int {0} | xml'.format(keepalive_intf)
                out = switch_hdl.execute(cfg)
                s = BeautifulSoup(out)
                link_flag = 0
                try:
                    state = s.find('admin_state').string
                    if re.search('up', state, re.IGNORECASE):
                        log.info(banner('The link is Up as expected. state is {0}'.format(state)))
                        link_flag = 1
                except Exception:
                    log.error(banner('Link is not up as expected. .. Hence failing the test case.'))
                    self.failed()
                    
                if link_flag:
                    log.info(banner('Checking the VPC Keepalive status:'))
                    out = switch_hdl.execute('show vpc | xml')
                    s = BeautifulSoup(out)
                    try:
                        keepalive_status = s.find('vpc-peer-keepalive-status').string
                        if re.search('peer-alive', keepalive_status,re.IGNORECASE):
                            log.info(banner('The Keepalive status is as expected.. .The state is {0}'.format(keepalive_status)))
                            log.info(banner('Proceeding with traffic measurement.. Waiting for 100 sec'))

                    except Exception:
                        log.error('The VPC KEepalive status is not as expected. Failing the test case w/o proceeding')
                        self.failed()                


            with steps.start('Check VPC Peerlink interface status and VPC Status ') as s:
                log.info(banner('Check VPC Peerlink interface status and VPC Status on VPC Primary {0}'.format(vpc_primary['dut'])))
                
                log.info('Checking the Interface status:')
                
                cfg = 'show int {0} | xml'.format(peerlink_intf)
                out = switch_hdl.execute(cfg)
                s = BeautifulSoup(out)
                link_flag = 0
                try:
                    state = s.find('admin_state').string
                    if re.search('up', state, re.IGNORECASE):
                        log.info(banner('The link is Up as expected. state is {0}'.format(state)))
                        link_flag = 1
                except Exception:
                    log.error(banner('Link is not up as expected. .. Hence failing the test case.'))
                    self.failed()
                    
                if link_flag:
                    log.info(banner('Checking the VPC Peerlink status:'))
                    out = switch_hdl.execute('show vpc | xml')
                    s = BeautifulSoup(out)
                    try:
                        peerlink_status = s.find('peer-link-port-state').string
                        if peerlink_status:
                            log.info(banner('The Keepalive status is as expected.. .The state is {0}'.format(peerlink_status)))
                            log.info(banner('Proceeding with traffic measurement.. Waiting for 180 sec'))

                    except Exception:
                        log.error('The VPC KEepalive status is not as expected. Failing the test case w/o proceeding')
                        self.failed()      
                    
        log.info(banner('Waiting for 800 seconds before measuring the Traffic Stats: '))
        countDownTimer(800)
                  
    @aetest.test
    def Verify_Traffic_Post_Trigger(self, testscript,log):
        """ Verify_Traffic_Post_Trigger """

        result = verifyTraffic(testscript)
        if result['status'] == 0:
            self.failed(reason=result['msgs'])
        else:
            self.passed(reason=result['msgs'])

# *****************************************************************************************************************************#

class TC057_ModifyNVESourceLoopbackIPOnVPCPrimary(aetest.Testcase):

    """ TC057_ModifyNVESourceLoopbackIPOnVPCPrimary """

    @aetest.test
    def ModifyNVESourceLoopbackIPOnVPCPrimary(self,log,testscript,steps):
        node_dict = testscript.parameters['node_dict']
        configdict = testscript.parameters['configdict']
        log = testscript.parameters['log']
        
        with steps.start('Getting VPC Primary handle') as s:
            log.info(banner('Getting VPC Primary handle'))
            vpc_dict = {}
            
            for dev in node_dict.keys():
                if re.search('Site',dev, re.IGNORECASE):
                    for dut in node_dict[dev].keys():
                        if re.search('VPC', dut):
                            vpc_dict.update(node_dict[dev][dut])
            log.info(banner('The value of VPC_dict is: {0}'.format(vpc_dict)))
            
            vpc_primary = MyLib.my_utils.returnVPCSwitchHandle(log,vpc_dict)['primary']
            log.info(banner('The value of VPC_primary is: {0}'.format(vpc_primary)))
            
        with steps.start('Changing VPC Primary PIP') as s:
            log.info(banner('Changing VPC Primary PIP'))
            uut = vpc_primary['dut']
            
            args = configdict['scale_config_dict'][uut]['interface']['nve']
            ns  = MyLib.my_config_utils.parseNVEParams(log,args)
            log.info('The value of source_interface is : {0}'.format(ns.source_interface))
            cfg = '''interface nve 1
                        shutdown
                        interface {0}
                        ip add 101.101.101.101/32 tag 11111
                        interface nve 1
                        no shutdown
                        '''.format(ns.source_interface)
                        
            vpc_primary['hdl'].configure(cfg) 
        
        with steps.start('Getting List of Devices to check') as s:
            log.info(banner('Getting List of Devices to check'))
            vtep_dict = {}
            leaf_at_site = 0
            for site in node_dict.keys():
                if re.search('Site', site, re.I):
                    for dut in node_dict[site].keys():
                        if re.search('VPC_BGW', dut, re.I):
                            vtep_dict.update(node_dict[site][dut])
                            leaf_at_site = site
                        elif re.search(r'^BGW$', dut, re.I):
                            vtep_dict.update(node_dict[site][dut])
            if leaf_at_site:
                vtep_dict.update(node_dict[leaf_at_site]['LEAF'])
            
            vtep_dict.pop(uut)
            log.info('The value of vtep_dict is {0}'.format(vtep_dict))
            
        log.info(banner('Waiting for 120 seconds before checking the Nve peers'))
        countDownTimer(320)
                    
        with steps.start('Checking Nve Peers ') as s:
            # log.info(banner('Checking Nve Peers '))
            # track_list  = []
            # cfg = 'sh nve peers | xml'
            # for dut in vtep_dict.keys():
            #     out  = vtep_dict[dut].configure(cfg)
            #     for line in out.splitlines():
            #         if re.search('peer-ip', line, re.I):
            #             log.info('The value of line is : {0}'.format(line))
            #             s = BeautifulSoup(line)
            #             try:
            #                 peer_ip = s.find('peer-ip').string
            #                 log.info('The value of peer_ip is : {0} and type is : {1}'.format(peer_ip,type(peer_ip)))
            #                 if peer_ip == '101.101.101.101':
            #                     track_list.append(1)
            #             except Exception:
            #                 log.error('Some exception Occured while finding the peer_ip')
                            
            # if len(track_list) == len(list(vtep_dict.keys())):
            #     log.info('New Peer-IP is found on all devives')
            # else:
            #     log.inf('New peer-IP is not found on one / more devices')
            #     self.failed()

            #Verifying Traffic Post Changing PIP
            ixNetwork = testscript.parameters['ixNetwork']
            session = testscript.parameters['session']
            traffic_threshold = testscript.parameters['traffic_threshold']
            ixNetwork.StartAllProtocols(Arg1='sync')
            ixNetwork.Traffic.Apply()
            ixNetwork.Traffic.Start()
            time.sleep(100)
            ixNetwork.ClearStats()
            time.sleep(20)
            trafficItemStatistics = session.StatViewAssistant('Traffic Item Statistics')
            Loss_per = trafficItemStatistics.Rows['Loss %']
            txFrames = trafficItemStatistics.Rows['Tx Frames']
            rxFrames = trafficItemStatistics.Rows['Rx Frames']
            log.info("Loss Percentage: "+ Loss_per)
            log.info("Tx Frames: "+ txFrames)
            log.info("Rx Frames: "+ rxFrames)
            time.sleep(20)
            ixNetwork.Traffic.Stop()
            ixNetwork.StopAllProtocols()
            if Loss_per == '':
                if (int(txFrames)-int(rxFrames)) in range(-1001,1001):
                    self.passed(reason="Steady State Traffic Verification Passed")
                else:
                    self.failed(reason="Steady State Traffic Verification Failed")
            else:
                if int(float(Loss_per)) < traffic_threshold:
                    self.passed(reason="Steady State Traffic Verification Passed")
                else:
                    self.failed(reason="Steady State Traffic Verification Failed")

        with steps.start('Reverting back VPC Primary PIP') as s:
            log.info(banner('Reverting back VPC Primary PIP'))
            uut = vpc_primary['dut']
            
            args = configdict['scale_config_dict'][uut]['interface']['nve']
            ns  = MyLib.my_config_utils.parseNVEParams(log,args)
            log.info('The value of source_interface is : {0}'.format(ns.source_interface))
            cfg = '''interface nve 1
                        shutdown
                        interface {0}
                        ip add 10.10.10.10/32 tag 11111
                        interface nve 1
                        no shutdown
                        '''.format(ns.source_interface)
                        
            vpc_primary['hdl'].configure(cfg)             
        
        log.info(banner('Waiting for 120 seconds before checking the Nve peers'))
        countDownTimer(120)

    @aetest.test
    def Verify_Traffic_Post_Trigger(self, testscript,log):
        """ Verify_Traffic_Post_Trigger """

        result = verifyTraffic(testscript)
        if result['status'] == 0:
            self.failed(reason=result['msgs'])
        else:
            self.passed(reason=result['msgs'])

# *****************************************************************************************************************************#

class TC058_RemoveDCILinkTrackingCliOnVPCPrimary(aetest.Testcase):

    """ TC058_RemoveDCILinkTrackingCliOnVPCPrimary """

    @aetest.test
    def RemoveDCILinkTrackingCliOnVPCPrimary(self,log,testscript,steps):
        node_dict = testscript.parameters['node_dict']
        config_dict = testscript.parameters['configdict']
        alias_intf_mapping = testscript.parameters['alias_intf_mapping']
        scale_config_obj = MyLib.my_config_utils.ScaleConfig(log,node_dict,config_dict,alias_intf_mapping)
        log = testscript.parameters['log']
        
        res = [node_dict['all_dut'][dut].execute('terminal session-timeout 0') for dut in node_dict['all_dut'] if re.search('uut', dut)]
                
        log.info(banner('Test:- Removing DCI link Tracking CLI on VPC Primary...'))
        
        bgw_dict = scale_config_obj.getMultisiteDeviceDict('bgw')
                
        with steps.start('Getting VPC Primary handle') as s:
            log.info(banner('Getting VPC Primary handle'))
            vpc_dict = {}
            
            for dev in node_dict.keys():
                if re.search('Site',dev, re.IGNORECASE):
                    for dut in node_dict[dev].keys():
                        if re.search('VPC', dut):
                            vpc_dict.update(node_dict[dev][dut])
            log.info(banner('The value of VPC_dict is: {0}'.format(vpc_dict)))
            
            vpc_primary = MyLib.my_utils.returnVPCSwitchHandle(log,vpc_dict)['primary']
            log.info('The value of VPC_primary is: {0}'.format(vpc_primary))

        
        with steps.start('Getting the DCI links from VPC Primary') as s:
            log.info(banner('Getting the DCI links from VPC Primary {0}'.format(vpc_primary['dut'])))
            
            cfg = 'sh nve multisite dci-links | xml'
            switch_hdl = vpc_primary['hdl']
            out = switch_hdl.execute(cfg)
            intf_list = []
            for line in out.splitlines():
                if re.search('if-name',line,re.IGNORECASE):
                    s = BeautifulSoup(line)
                    try:
                        intf = s.find('if-name').string
                        intf_list.append(intf)
                    except Exception:
                        log.error('Interface name could not be generated')
                        flag = 2
            log.info('The value of intf_list is : {0}'.format(intf_list))
            
            if intf_list:
                for intf in intf_list:
                    cfg = '''interface {0}
                                no evpn multisite dci-tracking'''.format(intf)
                    switch_hdl.configure(cfg)

        with steps.start('Restoring Configs - on BGWs') as s:
            log.info(banner('Restoring  configs on duts {0}'.format(list(bgw_dict.keys()))))
            
            for dut in bgw_dict.keys():
                log.info(banner('Restoring config on dut : {0}'.format(dut)))
                res = MyLib.my_utils.configBackUpOrRestoreOrCleanUp(log,node_dict['all_dut'][dut],'restore')
                if not res:
                    log.error(banner('restore Failed on the dut: {0}'.format(dut)))
                    self.failed
                    
        log.info(banner('Waiting for 180 seconds before measuring the Traffic Stats: '))
        countDownTimer(180)
              
    @aetest.test
    def Verify_Traffic_Post_Trigger(self, testscript,log):
        """ Verify_Traffic_Post_Trigger """

        result = verifyTraffic(testscript)
        if result['status'] == 0:
            self.failed(reason=result['msgs'])
        else:
            self.passed(reason=result['msgs'])

# *****************************************************************************************************************************#

class TC059_RemoveFabricLinkTrackingCliOnVPCPrimary(aetest.Testcase):

    """ TC059_RemoveFabricLinkTrackingCliOnVPCPrimary """

    @aetest.test
    def RemoveFabricLinkTrackingCliOnVPCPrimary(self,log,testscript,steps):
        node_dict = testscript.parameters['node_dict']
        config_dict = testscript.parameters['configdict']
        alias_intf_mapping = testscript.parameters['alias_intf_mapping']
        scale_config_obj = MyLib.my_config_utils.ScaleConfig(log,node_dict,config_dict,alias_intf_mapping)
        log = testscript.parameters['log']
        
        res = [node_dict['all_dut'][dut].execute('terminal session-timeout 0') for dut in node_dict['all_dut'] if re.search('uut', dut)]
                
        log.info(banner('Test:- Removing DCI link Tracking CLI on VPC Primary...'))

        bgw_dict = scale_config_obj.getMultisiteDeviceDict('bgw')
                
        with steps.start('Getting VPC Primary handle') as s:
            log.info(banner('Getting VPC Primary handle'))
            vpc_dict = {}
            
            for dev in node_dict.keys():
                if re.search('Site',dev, re.IGNORECASE):
                    for dut in node_dict[dev].keys():
                        if re.search('VPC', dut):
                            vpc_dict.update(node_dict[dev][dut])
            log.info(banner('The value of VPC_dict is: {0}'.format(vpc_dict)))
            
            vpc_primary = MyLib.my_utils.returnVPCSwitchHandle(log,vpc_dict)['primary']
            log.info('The value of VPC_primary is: {0}'.format(vpc_primary))

        
        with steps.start('Getting the DCI links from VPC Primary') as s:
            log.info(banner('Getting the DCI links from VPC Primary {0}'.format(vpc_primary['dut'])))
            
            cfg = 'sh nve multisite fabric-links | xml'
            switch_hdl = vpc_primary['hdl']
            out = switch_hdl.execute(cfg)
            intf_list = []
            for line in out.splitlines():
                if re.search('if-name',line,re.IGNORECASE):
                    s = BeautifulSoup(line)
                    try:
                        intf = s.find('if-name').string
                        intf_list.append(intf)
                    except Exception:
                        log.error('Interface name could not be generated')
                        flag = 2
            log.info('The value of intf_list is : {0}'.format(intf_list))
            
            if intf_list:
                for intf in intf_list:
                    cfg = '''interface {0}
                                no evpn multisite fabric-tracking'''.format(intf)
                    switch_hdl.configure(cfg)

        with steps.start('Restoring Configs - on BGWs') as s:
            log.info(banner('Restoring  configs on duts {0}'.format(list(bgw_dict.keys()))))
            
            for dut in bgw_dict.keys():
                log.info(banner('Restoring config on dut : {0}'.format(dut)))
                res = MyLib.my_utils.configBackUpOrRestoreOrCleanUp(log,node_dict['all_dut'][dut],'restore')
                if not res:
                    log.error(banner('restore Failed on the dut: {0}'.format(dut)))
                    self.failed
                    
        log.info(banner('Waiting for 180 seconds before measuring the Traffic Stats: '))
        countDownTimer(180)
        
    @aetest.test
    def Verify_Traffic_Post_Trigger(self, testscript,log):
        """ Verify_Traffic_Post_Trigger """

        result = verifyTraffic(testscript)
        if result['status'] == 0:
            self.failed(reason=result['msgs'])
        else:
            self.passed(reason=result['msgs'])

# *****************************************************************************************************************************#

class TC060_RemoveAddL3VNIonBothVPCSwitches(aetest.Testcase):

    """ TC060_RemoveAddL3VNIonBothVPCSwitches """

    @aetest.test
    def RemoveAddL3VNIonBothVPCSwitches(self,log,testscript,steps):
        node_dict = testscript.parameters['node_dict']
        configdict = testscript.parameters['configdict']
        alias_intf_mapping = testscript.parameters['alias_intf_mapping']
        scale_config_obj = MyLib.my_config_utils.ScaleConfig(log,node_dict,configdict,alias_intf_mapping)
        log = testscript.parameters['log']
        
        res = [node_dict['all_dut'][dut].execute('terminal session-timeout 0') for dut in node_dict['all_dut'] if re.search('uut', dut)]
                
        log.info(banner('Test:- Removing/Adding L3 VNI on BOth VPC Switches...'))

        vpc_dict = scale_config_obj.getMultisiteDeviceDict('vpc_vtep')
        
        log.info('The value of VPC_DICT is : {0}'.format(vpc_dict))

        with steps.start('Backing Up Configs - on VPC Switches') as s:
            log.info(banner('Backing Up  configs on duts {0}'.format(list(vpc_dict.keys()))))
            
            for dut in vpc_dict.keys():
                log.info(banner('Restoring config on dut : {0}'.format(dut)))
                res = MyLib.my_utils.configBackUpOrRestoreOrCleanUp(log,node_dict['all_dut'][dut],'backup')
                if not res:
                    log.error(banner('restore Failed on the dut: {0}'.format(dut)))
                    self.failed()
                    
        with steps.start('Remove L3 VNI from the VPC Switches')  as s:
            log.info(banner('Backing Up  configs on duts {0}'.format(list(vpc_dict.keys()))))
            for dut in vpc_dict:
                args = configdict['scale_config_dict'][dut]['global']['vlan']
                ns = MyLib.my_config_utils.parseScaleVlanParms(log,args)
                for i in range(ns.l3_vni_start, ns.l3_vni_start+ns.no_of_l3_vlans):
                    cfg = '''interface nve1
                                no member vni {0} associate-vrf'''.format(i)
                    node_dict['all_dut'][dut].configure(cfg)
                    
        log.info(banner('Wait for 120 seconds'))
        countDownTimer(120)

        with steps.start('Restoring Configs - on BGWs') as s:
            log.info(banner('Restoring  configs on duts {0}'.format(list(vpc_dict.keys()))))
            
            for dut in vpc_dict.keys():
                log.info(banner('Restoring config on dut : {0}'.format(dut)))
                res = MyLib.my_utils.configBackUpOrRestoreOrCleanUp(log,node_dict['all_dut'][dut],'restore')
                if not res:
                    log.error(banner('restore Failed on the dut: {0}'.format(dut)))
                    self.failed
                    
        log.info(banner('Waiting for 180 seconds before measuring the Traffic Stats: '))
        countDownTimer(180)
        
    @aetest.test
    def Verify_Traffic_Post_Trigger(self, testscript,log):
        """ Verify_Traffic_Post_Trigger """

        result = verifyTraffic(testscript)
        if result['status'] == 0:
            self.failed(reason=result['msgs'])
        else:
            self.passed(reason=result['msgs'])

# *****************************************************************************************************************************#

class TC061_RemoveAddMultisiteConfig(aetest.Testcase):

    """ TC061_RemoveAddMultisiteConfig """

    @aetest.test
    def RemoveAddMultisiteConfig(self,log,testscript,steps):
        node_dict = testscript.parameters['node_dict']
        configdict = testscript.parameters['configdict']
        alias_intf_mapping = testscript.parameters['alias_intf_mapping']
        scale_config_obj = MyLib.my_config_utils.ScaleConfig(log,node_dict,configdict,alias_intf_mapping)
        log = testscript.parameters['log']
        
        res = [node_dict['all_dut'][dut].execute('terminal session-timeout 0') for dut in node_dict['all_dut'] if re.search('uut', dut)]
                
        log.info(banner('Test:- Removing/Adding Multisite Config - multisite mcast-group on Both VPC Switches...'))
        
        bgw_dict = scale_config_obj.getMultisiteDeviceDict('bgw')
        vpc_dict = scale_config_obj.getMultisiteDeviceDict('vpc_vtep')
        
        log.info('The value of VPC_DICT is : {0}'.format(vpc_dict))
        
        with steps.start('Backing Up Configs - on VPC Switches') as s:
            log.info(banner('Backing Up  configs on duts {0}'.format(list(vpc_dict.keys()))))
            
            for dut in vpc_dict.keys():
                log.info(banner('Restoring config on dut : {0}'.format(dut)))
                res = MyLib.my_utils.configBackUpOrRestoreOrCleanUp(log,node_dict['all_dut'][dut],'backup')
                if not res:
                    log.error(banner('restore Failed on the dut: {0}'.format(dut)))
                    self.failed()
                    
        with steps.start('Remove Multisite Config from the VPC Switches')  as s:
            log.info(banner('Remove Multisite Config on duts {0}'.format(list(vpc_dict.keys()))))
            for dut in vpc_dict:
                args = configdict['scale_config_dict'][dut]['global']['vlan']
                ns = MyLib.my_config_utils.parseScaleVlanParms(log,args)
                for i in range(ns.l3_vni_start, ns.l3_vni_start+ns.no_of_l3_vlans):
                    cfg = '''interface nve1
                                member vni {0} associate-vrf
                                no multisite mcast-group'''.format(i)
                    node_dict['all_dut'][dut].configure(cfg)
                    
        log.info(banner('Wait for 180 seconds'))
        countDownTimer(180)

        with steps.start('Restoring Configs - on BGWs') as s:
            log.info(banner('Restoring  configs on duts {0}'.format(list(bgw_dict.keys()))))
            
            for dut in bgw_dict.keys():
                log.info(banner('Restoring config on dut : {0}'.format(dut)))
                res = MyLib.my_utils.configBackUpOrRestoreOrCleanUp(log,node_dict['all_dut'][dut],'restore')
                if not res:
                    log.error(banner('restore Failed on the dut: {0}'.format(dut)))
                    self.failed
                    
        log.info(banner('Waiting for 180 seconds before measuring the Traffic Stats: '))
        countDownTimer(180)
        
    @aetest.test
    def Verify_Traffic_Post_Trigger(self, testscript,log):
        """ Verify_Traffic_Post_Trigger """

        result = verifyTraffic(testscript)
        if result['status'] == 0:
            self.failed(reason=result['msgs'])
        else:
            self.passed(reason=result['msgs'])

# *****************************************************************************************************************************#

class TC062_NVESourceLoopbackFlapOnVPCPrimary(aetest.Testcase):

    """ TC062_NVESourceLoopbackFlapOnVPCPrimary """

    @aetest.test
    def NVESourceLoopbackFlapOnVPCPrimary(self,log,testscript,steps):
        node_dict = testscript.parameters['node_dict']
        configdict = testscript.parameters['configdict']
        log = testscript.parameters['log']
        
        with steps.start('Getting VPC Primary handle') as s:
            log.info(banner('Getting VPC Primary handle'))
            vpc_dict = {}
            
            for dev in node_dict.keys():
                if re.search('Site',dev, re.IGNORECASE):
                    for dut in node_dict[dev].keys():
                        if re.search('VPC', dut):
                            vpc_dict.update(node_dict[dev][dut])
            log.info(banner('The value of VPC_dict is: {0}'.format(vpc_dict)))
            
            vpc_primary = MyLib.my_utils.returnVPCSwitchHandle(log,vpc_dict)['primary']
            log.info(banner('The value of VPC_primary is: {0}'.format(vpc_primary)))
            
        with steps.start('Shut Down PIP Loopback on VPC Primary') as s:
            log.info(banner('ShutDown PIP Loopback on VPC Primary'))
            uut = vpc_primary['dut']
            
            args = configdict['scale_config_dict'][uut]['interface']['nve']
            ns  = MyLib.my_config_utils.parseNVEParams(log,args)
            log.info('The value of source_interface is : {0}'.format(ns.source_interface))
            cfg = '''interface {0}
                        shutdown
                        '''.format(ns.source_interface)
                        
            vpc_primary['hdl'].configure(cfg) 
            
        log.info(banner('Waiting for 120 seconds before checking the Nve peers'))
        countDownTimer(120)
                    
        with steps.start('Getting List of Devices to check') as s:
            log.info(banner('Getting List of Devices to check'))
            vtep_dict = {}
            leaf_at_site = 0
            for site in node_dict.keys():
                if re.search('Site', site, re.I):
                    for dut in node_dict[site].keys():
                        if re.search('VPC_BGW', dut, re.I):
                            vtep_dict.update(node_dict[site][dut])
                            leaf_at_site = site
                        elif re.search(r'^BGW$', dut, re.I):
                            vtep_dict.update(node_dict[site][dut])
            if leaf_at_site:
                vtep_dict.update(node_dict[leaf_at_site]['LEAF'])
            
            vtep_dict.pop(uut)
            log.info('The value of vtep_dict is {0}'.format(vtep_dict))

        with steps.start('Checking Nve Peers ') as s:
            log.info(banner('Checking Nve Peers '))
            count  = 0
            cfg = 'sh nve peers | xml'
            for dut in vtep_dict.keys():
                out  = vtep_dict[dut].configure(cfg)
                for line in out.splitlines():
                    if re.search('peer-ip', line, re.I):
                        log.info('The value of line is : {0}'.format(line))
                        s = BeautifulSoup(line)
                        try:
                            peer_ip = s.find('peer-ip').string
                            log.info('The value of peer_ip is : {0} and type is : {1}'.format(peer_ip,type(peer_ip)))
                            if peer_ip == '10.10.10.10':
                                count += 1
                        except Exception:
                            log.error('Some exception Occured while finding the peer_ip')
                            
            if not count:
                log.info('Nve Loopback is destroyed on all other VTEPs as expected.')
            else:
                log.inf('New is still discovered after Loopback shut on one / more devices')
                self.failed()

        with steps.start('Unflapping the Loopback Interface on VPC Primary') as s:
            log.info(banner('Unflapping the Loopback Interface on VPC Primary'))
            uut = vpc_primary['dut']
            
            args = configdict['scale_config_dict'][uut]['interface']['nve']
            ns  = MyLib.my_config_utils.parseNVEParams(log,args)
            log.info('The value of source_interface is : {0}'.format(ns.source_interface))
            cfg = '''interface {0}
                        no shutdown
                        '''.format(ns.source_interface)
                        
            vpc_primary['hdl'].configure(cfg)             
        
        log.info(banner('Waiting for 200 seconds before checking the Nve peers'))
        countDownTimer(200)

        # with steps.start('Checking Nve Peers ') as s:
        #     log.info(banner('Checking Nve Peers '))
        #     count  = 0
        #     cfg = 'sh nve peers | xml'
        #     for dut in vtep_dict.keys():
        #         out  = vtep_dict[dut].configure(cfg)
        #         for line in out.splitlines():
        #             if re.search('peer-ip', line, re.I):
        #                 log.info('The value of line is : {0}'.format(line))
        #                 s = BeautifulSoup(line)
        #                 try:
        #                     peer_ip = s.find('peer-ip').string
        #                     log.info('The value of peer_ip is : {0} and type is : {1}'.format(peer_ip,type(peer_ip)))
        #                     if peer_ip == '10.10.10.10':
        #                         count += 1
        #                 except Exception:
        #                     log.error('Some exception Occured while finding the peer_ip')
                            
        #     if len(list(vtep_dict.keys())) ==  count:
        #         log.info('Nve Loopback is seen on all other VTEPs as expected.')
        #     else:
        #         log.inf('Nve Peer is still discovered after Loopback shut on one / more devices')
        #         self.failed()

    @aetest.test
    def Verify_Traffic_Post_Trigger(self, testscript,log):
        """ Verify_Traffic_Post_Trigger """

        result = verifyTraffic(testscript)
        if result['status'] == 0:
            self.failed(reason=result['msgs'])
        else:
            self.passed(reason=result['msgs'])

# *****************************************************************************************************************************#

class TC063_VlanShutUnshutOnVPCSwitches(aetest.Testcase):

    """ TC063_VlanShutUnshutOnVPCSwitches """

    @aetest.test
    def VlanShutUnshutOnVPCSwitches(self,log,testscript,steps):
        node_dict = testscript.parameters['node_dict']
        configdict = testscript.parameters['configdict']
        alias_intf_mapping = testscript.parameters['alias_intf_mapping']
        scale_config_obj = MyLib.my_config_utils.ScaleConfig(log,node_dict,configdict,alias_intf_mapping)
        log = testscript.parameters['log']
        
        vpc_dict = scale_config_obj.getMultisiteDeviceDict('vpc_vtep')
    
        with steps.start('ShutDown Vlans on VPC Switches') as s:
            log.info('ShutDown Vlans on VPC Switches {0}'.format(list(vpc_dict.keys())))
            for dut in vpc_dict.keys():
                args = configdict['scale_config_dict'][dut]['global']['vlan']
                ns = MyLib.my_config_utils.parseScaleVlanParms(log,args)
                for i in range(ns.l2_vlan_start,ns.l2_vlan_start + ns.no_of_l2_vlans):
                    cfg = '''vlan {0}
                                shutdown'''.format(i)
                    node_dict['all_dut'][dut].configure(cfg)
                
            
        log.info(banner('Waiting for 120 seconds before checking the Nve peers'))
        countDownTimer(120)

        with steps.start('UnShutDown Vlans on VPC Switches') as s:
            log.info('ShutDown Vlans on VPC Switches {0}'.format(list(vpc_dict.keys())))
            for dut in vpc_dict.keys():
                args = configdict['scale_config_dict'][dut]['global']['vlan']
                ns = MyLib.my_config_utils.parseScaleVlanParms(log,args)
                for i in range(ns.l2_vlan_start,ns.l2_vlan_start + ns.no_of_l2_vlans):
                    cfg = '''vlan {0}
                                no shutdown'''.format(i)
                    node_dict['all_dut'][dut].configure(cfg)       
        
        log.info(banner('Waiting for 120 seconds before checking the Nve peers'))
        countDownTimer(120)

    @aetest.test
    def Verify_Traffic_Post_Trigger(self, testscript,log):
        """ Verify_Traffic_Post_Trigger """

        result = verifyTraffic(testscript)
        if result['status'] == 0:
            self.failed(reason=result['msgs'])
        else:
            self.passed(reason=result['msgs'])

# *****************************************************************************************************************************#

class TC064_VRFLiteLinkFlapOnVPCSwitches(aetest.Testcase):

    """ TC064_VRFLiteLinkFlapOnVPCSwitches """

    @aetest.test
    def VRFLiteLinkFlapOnVPCSwitches(self,log,testscript,steps):
        node_dict = testscript.parameters['node_dict']
        configdict = testscript.parameters['configdict']
        alias_intf_mapping = testscript.parameters['alias_intf_mapping']
        scale_config_obj = MyLib.my_config_utils.ScaleConfig(log,node_dict,configdict,alias_intf_mapping)
        log = testscript.parameters['log']
        
        log.info(banner('VRFLite Link Flap On VPCSwitches'))

        vpc_dict = scale_config_obj.getMultisiteDeviceDict('vpc_vtep')
    
        with steps.start('VRF Lite Link Shut on VPC Switches') as s:
            log.info('VRF lite Link shut on VPC Switches {0}'.format(list(vpc_dict.keys())))
            
            for dut in vpc_dict.keys():
                try:
                    intf = list(configdict['scale_config_dict'][dut]['interface']['sub_if'].keys())[0]
                                        
                    if re.search('uut', intf,re.I):
                        intf = alias_intf_mapping[dut][intf]
                        
                    cfg = '''interface {0}
                                shutdown'''.format(intf)
                    node_dict['all_dut'][dut].configure(cfg)
                except Exception:
                    log.info('Sub-interface config does not exist on config_dict for dut {0}'.format(dut))

        log.info(banner('Waiting for 120 seconds before checking the Nve peers'))
        countDownTimer(120)

        with steps.start('VRF Lite Link unshut on VPC Switches') as s:
            log.info('VRF lite Link unshut on VPC Switches {0}'.format(list(vpc_dict.keys())))
            
            for dut in vpc_dict.keys():
                try:
                    intf = list(configdict['scale_config_dict'][dut]['interface']['sub_if'].keys())[0]
                    if re.search('uut', intf,re.I):
                        intf = alias_intf_mapping[dut][intf]
                        
                    cfg = '''interface {0}
                                no shutdown'''.format(intf)
                    node_dict['all_dut'][dut].configure(cfg) 
                except Exception:
                    log.info('Sub-interface config does not exist on config_dict for dut {0}'.format(dut))

        
        log.info(banner('Waiting for 120 seconds before checking the Nve peers'))
        countDownTimer(120)

    @aetest.test
    def Verify_Traffic_Post_Trigger(self, testscript,log):
        """ Verify_Traffic_Post_Trigger """

        result = verifyTraffic(testscript)
        if result['status'] == 0:
            self.failed(reason=result['msgs'])
        else:
            self.passed(reason=result['msgs'])

# *****************************************************************************************************************************#

class CommonCleanup(aetest.Testcase):
    
    """ VLan State Change on Both the DUTS """

    uid = 'VXLAN-L3-TRM-FUNC-001'

    @aetest.subsection
    def checkTopo(self):
        pass

# *****************************************************************************************************************************#        

class CommonCleanup(aetest.CommonCleanup):

    @aetest.subsection
    def disconnect(self):
        pass

# *****************************************************************************************************************************#