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

from pyats import aetest
from common_lib import config_bringup
import yaml
import logging
from pyats.topology import loader
import argparse
import json
import datetime
from datetime import datetime,timedelta
import unicon.statemachine.statemachine
import random

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

#Ixia Libraries
from common_lib import ixia_lib_new
from common_lib.ixia_lib_new import *

# N39k Library imports
from common_lib import config_bringup
# import config_bringup_test
from common_lib import config_bringup_test_vijay
from common_lib import interface_lib
import ipaddress

from itertools import chain
from collections import OrderedDict
from itertools import permutations
import json
from bs4 import BeautifulSoup
from prettytable import PrettyTable
from _ast import alias

import unicon.statemachine.statemachine
from unicon.eal.dialogs import Statement, Dialog

#from bs4 import BeautifulSoup


def deleteAndCreateCheckpoint(log,hdl):
    cfg = 'sh checkpoint | xml | grep <name>'
    out = hdl.execute(cfg)
    if out:
        for i in out.splitlines():
            t = re.findall(">(\S+)<",i)
            if t:
                if 'system' not in i:
                    if isinstance(t, list):
                        flag = 1
                        for i in t:
                            cmd = 'no checkpoint ' + i
                            hdl.execute(cmd)
                            time.sleep(5)        
                        if flag:
                            hdl.execute('checkpoint c1')
                else:
                    hdl.execute('checkpoint c1')

    return 1

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

def countDownTimer(a):
    for i in range(a):
        log.info('seconds remaining is: {0}'.format(int(a-i)))
        time.sleep(1)
    return 1

def startStopIgmpReports(tg_hdl='',action=''):
    log.info('The value of tg_hdl is = %r', tg_hdl)
    log.info('The value of action  is = %r', action)
    igmp_status = tg_hdl.test_control(action = action)
    return(igmp_status)  


def parseScaleTGParams(log,args):
    arggrammar = {}
    arggrammar['no_of_intf'] = '-type int'
    arggrammar['no_of_vlans'] = '-type int'
    arggrammar['vlan_start'] = '-type int'
    arggrammar['ip_addr_start'] = '-type str'
    arggrammar['netmask'] = '-type str'
    arggrammar['ip_addr_step'] = '-type str'
    arggrammar['ipv4_network_step'] = '-type str'
    arggrammar['gateway'] = '-type str'
    arggrammar['mode'] = '-type str'
    arggrammar['vlan'] = '-type int'
    ns = utils.parserutils_lib.argsToCommandOptions(args,arggrammar,log)
    return ns

def generateTrafficGenIntfConfigs(log,args):
    intf_list = []
    count = 1
    ns = parseScaleTGParams(log,args)
    no_of_intf_per_vlan = ns.no_of_intf / ns.no_of_vlans
    print('The value of no_of_intf_per_vlan is : {0}'.format(no_of_intf_per_vlan))
    ip_addr = ipaddress.IPv4Address(ns.ip_addr_start)
    gw = ipaddress.IPv4Address(ns.gateway)
    v = ns.vlan_start
    ip_addr_step = '0.0.0.1'
    gw_addr_step = '0.0.0.0'
    vlan_step = 0
    for i in range(0,ns.no_of_intf):
        if(count <= int(no_of_intf_per_vlan)): 
            if(count == 1):
                a = "".join('-mode {0} -connected_count {1} -intf_ip_addr {2} -intf_ip_addr_step {3} -netmask {4} -gateway {5} -gateway_step {6} -vlan {7} -vlan_id {8} -vlan_id_step {9}'.format(ns.mode,int(no_of_intf_per_vlan),ip_addr,ip_addr_step,ns.netmask,gw,gw_addr_step,ns.vlan,v,vlan_step))
                intf_list.append(a)
            ip_addr = ipaddress.IPv4Address(ip_addr) + int(ipaddress.IPv4Address(ns.ip_addr_step))
            count = count+1
        if(count > no_of_intf_per_vlan):
            ns.ip_addr_start = ipaddress.IPv4Address(ns.ip_addr_start)+int(ipaddress.IPv4Address(ns.ipv4_network_step))
            ip_addr = ns.ip_addr_start
            gw = ipaddress.IPv4Address(gw) + int(ipaddress.IPv4Address(ns.ipv4_network_step))
            v = v + 1
            count = 1
            
    return intf_list

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
        testscript.parameters['config_ospfv3'] = kwargs['config_ospfv3']
        testscript.parameters['config_bgp'] = kwargs['config_bgp']
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
        testscript.parameters['config_sub_intf'] = kwargs['config_sub_intf']
        testscript.parameters['config_loopback_intf'] = kwargs['config_loopback_intf']
        testscript.parameters['config_ospf_router_id'] = kwargs['config_ospf_router_id']
        testscript.parameters['config_tgn_conn'] = kwargs['config_tgn_conn']
        testscript.parameters['config_tgn_interface'] = kwargs['config_tgn_interface']
                                         
        parser = argparse.ArgumentParser()
        parser.add_argument('--config-file',dest='config_file',type=str)
        args = parser.parse_args()
        config_file = args.config_file
        fp = open(config_file)
        configdict=yaml.safe_load(fp)
        fp.close()        
        fail_result=0
        log.info('Getting testbed objects from the testbed file')
        testbed_obj = testbed

        # Way to get password and login from Testbed file
        passw = testbed_obj.passwords['tacacs']
        login = testbed_obj.tacacs['username']

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
            log.info(banner('the value of a is : {0}'.format(a)))
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
            log.info(banner('The interfaces and alias are \n {0}'.format("\n".join(["->".join(x) for x in res]))))
            
            
        log.info('The value of alias_intf_mapping is {0}'.format(yaml.dump(alias_intf_mapping)))

        # Way to take variable to other section
        testscript.parameters['testbed_obj'] = testbed_obj
        testscript.parameters['configdict'] = configdict
        testscript.parameters['fail_result'] = fail_result
        testscript.parameters['alias_intf_mapping'] = alias_intf_mapping
       
    @aetest.subsection
    def configBringUp(self,testscript,log,steps):
        
        testbed_obj = testscript.parameters['testbed_obj']

        # DUTs required to test this feature 
        dutList_config_file = list(testscript.parameters['configdict']['dut'].keys())
        log.info('{0} are the duts required for EVPN tests'.format(dutList_config_file))
        
        # TGNs required for this CFD
        TGList_config_file = list(testscript.parameters['configdict']['TG'].keys())
        log.info('{0} are the TGNs required for EVPN tests'.format(TGList_config_file))
        
        # Create obj for each node from config file
        dutList_obj_config_file = []
        for dut_config_file in dutList_config_file:
            dutList_obj_config_file.append(testscript.parameters['testbed_obj'].devices[dut_config_file])
            
        # declaring vtep list
        node_dict = {}
        
        for node in list(testbed_obj.devices.keys()):
            log.info('The Value of node is : {0}'.format(node))
            log.info('The value of node.type is : {0}'.format(testbed_obj.devices[node].type))
            if re.search('VPC',testbed_obj.devices[node].type):
                node_dict.setdefault('vpc_vteps',{})
                node_dict.setdefault('all_vteps',{})
                node_dict['vpc_vteps'][testbed_obj.devices[node].alias] = testbed_obj.devices[node]
                node_dict['all_vteps'][testbed_obj.devices[node].alias] = testbed_obj.devices[node]
            elif re.search('STAND',testbed_obj.devices[node].type):
                node_dict.setdefault('stand_vteps',{})
                node_dict.setdefault('all_vteps',{})
                node_dict['stand_vteps'][testbed_obj.devices[node].alias] = testbed_obj.devices[node]
                node_dict['all_vteps'][testbed_obj.devices[node].alias] = testbed_obj.devices[node]
            elif re.search('SPINE',testbed_obj.devices[node].type):
                node_dict.setdefault('spines',{})
                node_dict['spines'][testbed_obj.devices[node].alias] = testbed_obj.devices[node]
            elif re.search('L2',testbed_obj.devices[node].type):
                node_dict.setdefault('l2_switch',{})
                node_dict['l2_switch'][testbed_obj.devices[node].alias] = testbed_obj.devices[node]
            elif re.search('EXTERNAL',testbed_obj.devices[node].type):
                node_dict.setdefault('external_rp',{})
                node_dict['external_rp'][testbed_obj.devices[node].alias] = testbed_obj.devices[node]
            elif re.search('CORE',testbed_obj.devices[node].type):
                node_dict.setdefault('core',{})
                node_dict['core'][testbed_obj.devices[node].alias] = testbed_obj.devices[node]
            elif re.search('ixia',testbed_obj.devices[node].type):
                node_dict.setdefault('trf_gen',{})
                node_dict['trf_gen'][testbed_obj.devices[node].alias] = testbed_obj.devices[node]
            node_dict.setdefault('all_dut',{})
            node_dict['all_dut'][testbed_obj.devices[node].alias] = testbed_obj.devices[node]

        log.info(banner('Value of Node dict is : {0}'.format(node_dict)))   
                
        for dut in node_dict['all_dut']:
            if not re.search(r'TG',dut,re.I):
                node_dict['all_dut'][dut].connect()
        
        testscript.parameters['node_dict'] = node_dict
        testscript.parameters['TGList'] = TGList_config_file
                            
    @aetest.subsection
    def configureInterfaces(self,testscript,log):
        
        config_interface = testscript.parameters['config_interface']
        
        if config_interface:
            #interface config dict 
            config_dict = testscript.parameters['configdict']
            node_dict = testscript.parameters['node_dict']
            testbed_obj = testscript.parameters['testbed_obj']
            
            intf_config_dict = testscript.parameters['configdict']['interface_config_dict']
    
            log.info(banner('The value of interface_config_dict is {0} '.format(intf_config_dict)))
            
            log.info(banner('The value of node_dict is {0} '.format(node_dict)))
            
            intf_obj = config_bringup_test_vijay.configSetup(config_dict,testbed_obj,log)
            
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
    def configureUnderlayOSPFv3(self,testscript,log):
        
        config_ospfv3 = testscript.parameters['config_ospfv3']
        
        if config_ospfv3:
            #ospf_config_dict
            ospfv3_config_dict = testscript.parameters['configdict']['ospfv3_config_dict']
            node_dict = testscript.parameters['node_dict']
            
            obj_ospf=ospfv3_lib.configOspfv3(node_dict['all_dut'],ospfv3_config_dict,log)
            
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
    def configureVPCSwitches(self,testscript,log):
        
        config_vpc = testscript.parameters['config_vpc']
        
        if config_vpc:
            node_dict = testscript.parameters['node_dict']
            config_dict = testscript.parameters['configdict']
            
            for dut in node_dict['vpc_vteps'].keys():
                hdl = node_dict['vpc_vteps'][dut]
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
            vtep_dict = scale_config_obj.getDeviceDict('all_vtep')
            
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
            vtep_dict = scale_config_obj.getDeviceDict('all_vtep')

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
            device_dict = {}
            for dut in ['all_vtep','core','l2_switch']:
                device_dict.update(scale_config_obj.getDeviceDict(dut))

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
            device_dict = {}
            for dut in ['all_vtep','external_rp','core']:
                device_dict.update(scale_config_obj.getDeviceDict(dut))

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
            device_dict = {}
            for dut in ['all_vtep','core']:
#             for dut in ['core']:
                device_dict.update(scale_config_obj.getDeviceDict(dut))

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
            vtep_dict = scale_config_obj.getDeviceDict('all_vtep')
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
            vtep_dict = scale_config_obj.getDeviceDict('all_vtep')
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
            vtep_dict = scale_config_obj.getDeviceDict('all_vtep')
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
            vtep_dict = scale_config_obj.getDeviceDict('all_vtep')
            log.info(banner('The value of vtep_dict is : {0}'.format(vtep_dict)))
    
            res = scale_config_obj.configureL3VNIOnNve(vtep_dict)
            
            if not res:
                self.failed()
        else:
            pass

    @aetest.subsection                     
    def configureSubInterfaces(self,testscript,log):     
        
        config_sub_intf = testscript.parameters['config_sub_intf']
        config_dict = testscript.parameters['configdict']
        node_dict = testscript.parameters['node_dict']
        alias_intf_mapping = testscript.parameters['alias_intf_mapping']
        
        if config_sub_intf:
        
            scale_config_obj = MyLib.my_config_utils.ScaleConfig(log,node_dict,config_dict,alias_intf_mapping)
            device_dict = {}
            for dut in ['vpc_vtep','external_rp','core']:
                device_dict.update(scale_config_obj.getDeviceDict(dut))

            log.info(banner('The value of device_dict_dict is : {0}'.format(device_dict)))
    
            res = scale_config_obj.configureL3SubInterface(device_dict)
             
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
            external_rp_dict = scale_config_obj.getDeviceDict('external_rp')

            log.info(banner('The value of external_rp_dict is : {0}'.format(external_rp_dict)))
    
            res = scale_config_obj.configureLoopbackInterface(external_rp_dict)
             
            if not res:
                self.failed()
        else:
            pass
        
    @aetest.subsection                     
    def configureVRFOspfRouterID(self,testscript,log):     
        
        config_ospf_router_id = testscript.parameters['config_ospf_router_id']
        config_dict = testscript.parameters['configdict']
        node_dict = testscript.parameters['node_dict']
        alias_intf_mapping = testscript.parameters['alias_intf_mapping']
        
        if config_ospf_router_id:
        
            scale_config_obj = MyLib.my_config_utils.ScaleConfig(log,node_dict,config_dict,alias_intf_mapping)
            vtep_dict = scale_config_obj.getDeviceDict('vpc_vtep')

            log.info(banner('The value of external_rp_dict is : {0}'.format(vtep_dict)))
    
            res = scale_config_obj.configureOspfRouterID(vtep_dict)
             
            if not res:
                self.failed()
        else:
            pass

    @aetest.subsection                     
    def connectionToTrafficGenerator(self,testscript,log): 


        config_tgn_conn =  testscript.parameters['config_tgn_conn']
        
        if config_tgn_conn:
            # Connect and confiure TG
    
            log.info('Connecting and configuring TG as per config dict...')
            # Get physical interface from logical interface of config file for TG
             
            testbed_obj = testscript.parameters['testbed_obj']
     
            TGList_config_file = testscript.parameters['TGList']
            ix_port_list = []
            ix_port_list_alias = []
            tgn_port_dut_mapping={}
            for TG in TGList_config_file:
                d = testscript.parameters['testbed_obj'].devices[TG]
                log.info('The value of d is : {0}'.format(d))
                TGIntList = testscript.parameters['configdict']['TG'][TG]['global']['ports'].keys()
                for port in TGIntList:
                    a = d.interfaces[port].alias
                    b = re.search('(uut[\d]+)',a)
                    if b:
                        dut = b.group(1)
                        tgn_port_dut_mapping[port] = dut
                
                
                for TGInt in TGIntList:
                    log.info('The value of TGint is : {0}'.format(TGInt))
                    ix_port_list.append(d.interfaces[TGInt].name)
                    ix_port_list_alias.append(d.interfaces[TGInt].alias)
                    # Connect to TG
                ix_port_list.sort(key=lambda x: '{0:0>8}'.format(x).lower())
                log.info('The value of ix_port_list is : {0}'.format(ix_port_list))
                log.info('The value of ix_port_list_alias is : {0}'.format(ix_port_list_alias))
                ixia_connect = connectToIxNetwork(self, tg_hdl = d, port_list = ix_port_list)
                     
                # Get port handles
                port_handle_list = []
                for port_handle in ixia_connect['vport_list'].split():
                    port_handle_list.append(port_handle)
                 
                port_handle_list.sort(key=lambda x: '{0:0>8}'.format(x).lower())
                 
                port_handle_dict = dict(zip(ix_port_list,port_handle_list))

                for tgPort,ixPort in zip(ix_port_list,port_handle_list):
                    # Updating the IXIA port type
                    result = d.interface_config(port_handle = ixPort, phy_mode=d.interfaces[tgPort].type)
                    if result.status:
                        log.info("Changed the interface phymode successfully")
                    else:
                        log.info("Changed the interface phymode failed")

                log.info("Port handles are {0}".format(port_handle_list))
                log.info('The Value of port_handle_dict is: {0}'.format(port_handle_dict))
                testscript.parameters['port_handle_dict'] = port_handle_dict
                log.info('The value of tgn_port_dut_mapping is : {0}'.format(tgn_port_dut_mapping))
                testscript.parameters['tgn_port_dut_mapping'] = tgn_port_dut_mapping
                
    @aetest.subsection      
    def configuringInterfacesOnTrafficGenerator(self,testscript,log):
        
        config_tgn_interface = testscript.parameters['config_tgn_interface']

        if config_tgn_interface:
            tg_interface_hdl_dict = {}
            port_handle_dict = testscript.parameters['port_handle_dict']
     
                #interface_handle_list = []
            TGList_config_file = testscript.parameters['TGList']
            for TG in TGList_config_file:
                tg_interface_hdl_dict[TG] = {}
                d = testscript.parameters['testbed_obj'].devices[TG]
                skip_traffic_items = testscript.parameters['configdict']['TG'][TG]['skip_traffic_items']
                log.info('Type of skip_traffic_items is : {0}'.format(type(skip_traffic_items)))
                if skip_traffic_items:
                    traffic_item_skip_list = expandTrafficItemList(testscript.parameters['configdict']['TG'][TG]['skip_traffic_items'])
                    log.info('The value of traffic_item_skip_list is : {0}'.format(traffic_item_skip_list))
                else:
                    traffic_item_skip_list = ''
                log.info('The value of traffic_item_skip_list is : {0}'.format(traffic_item_skip_list))       
                configured_stream  = []
                skipped_stream = []     
                for trf_stream in testscript.parameters['configdict']['TG'][TG]:
                    if(re.search('TRF',trf_stream)):
                        if trf_stream not in traffic_item_skip_list:
                            configured_stream.append(trf_stream)
                            tg_interface_hdl_dict[TG][trf_stream] = {}
                            TGIntList = testscript.parameters['configdict']['TG'][TG][trf_stream]['tg_interface_config_dict'].keys()
                            for TGInt in TGIntList:
                                log.info('The value of TGInt is : {0}'.format(TGInt))
                                ixia_intf_ip_list=[]
                                tg_interface_hdl_dict[TG][trf_stream][TGInt] = {}
                                intf_args = generateTrafficGenIntfConfigs(log,testscript.parameters['configdict']['TG'][TG][trf_stream]['tg_interface_config_dict'][TGInt]) 
                                log.info('The value of intf_args is : {0}'.format(intf_args))
                                for j,k  in enumerate(intf_args):
                                    a = intf_args[j]
                                    ixia_interface_config = configureMultiIxNetworkInterface(self,a,tg_hdl=d,port_handle=port_handle_dict[TGInt])
                                    log.info('the value of ixia_interface_config is : {0}'.format(ixia_interface_config))
                                    for b in ixia_interface_config:
                                        ixia_intf_ip_list.append(b)
                                        tg_interface_hdl_dict[TG][trf_stream][TGInt][b]={}
                                        tg_interface_hdl_dict[TG][trf_stream][TGInt][b]['handle']=ixia_interface_config[b]
                                    tg_interface_hdl_dict[TG][trf_stream][TGInt]['ip_list']=ixia_intf_ip_list
                        else:
                            skipped_stream.append(trf_stream)

                    elif(re.search('RAW',trf_stream)):
                        if trf_stream not in traffic_item_skip_list:
                            configured_stream.append(trf_stream)
                        else:
                            skipped_stream.append(trf_stream)
            
            log.info(banner('The following traffic stream  %s is skipped from configuring ... ' % skipped_stream))
                        
            c = yaml.dump(tg_interface_hdl_dict)
            log.info('The value of c is : {0}'.format(c))
            testscript.parameters['tg_interface_hdl_dict'] = tg_interface_hdl_dict
            testscript.parameters['configured_stream'] = configured_stream
            log.info(banner('The value of configured_stream is : {0}'.format(configured_stream)))


    @aetest.subsection                     
    def verifyConfiguationsBeforeStartOfTest(self,testscript,log,steps):
#         '''
        config_dict = testscript.parameters['configdict']
        node_dict = testscript.parameters['node_dict']
        alias_intf_mapping = testscript.parameters['alias_intf_mapping']
        
        scale_config_obj = MyLib.my_config_utils.ScaleConfig(log,node_dict,config_dict,alias_intf_mapping)
        vtep_dict = scale_config_obj.getDeviceDict('all_vtep')
                
        verify_obj = MyLib.my_config_utils.VerifyConfigs(log,config_dict,node_dict,alias_intf_mapping)
        
        with steps.start('Verify OSPFv2 Neighborship on all duts') as s:
            log.info('Verifying the OSPFv2 Neighborship on all duts ......')
            res = verify_obj.verifyOSPFv4Neighorship()
            if not res:
                self.failed()

#         with steps.start('Verify OSPFv3 Neighborship on all duts') as s:
#             log.info('Verifying the OSPFv3 Neighborship on all duts ......')
#             res = verify_obj.verifyOSPFv6Neighorship()
#             if not res:
#                 self.failed()

        with steps.start('Verify BGP L2EVPN Neighborship on all duts') as s:
            log.info('Verify BGP L2EVPN Neighborship on all duts ......')
            res = verify_obj.verifyBGPL2EVPNNeighbor()
            if not res:
                self.failed()

        with steps.start('Verify BGP mVPN Neighborship on all duts') as s:
            log.info('Verify BGP mVPN Neighborship on all duts ......')
            res = verify_obj.verifyBGPL2MVPNNeighbor()
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
#         '''       
        
    @aetest.subsection 
    def configureIGMPReports(self,testscript,log):
        
#         '''
        TGList_config_file = testscript.parameters['TGList']
        tg_interface_hdl_dict = testscript.parameters['tg_interface_hdl_dict']
        config_dict = testscript.parameters['configdict']
        configured_stream = testscript.parameters['configured_stream'] 
        
        log.info(banner('The value of traffic_interface_handle_dict is : {0}'.format(yaml.dump(tg_interface_hdl_dict))))

        for TG in TGList_config_file:
            d = testscript.parameters['testbed_obj'].devices[TG]
            for trf_stream in configured_stream:
                if(re.search('TRF',trf_stream)):
                    log.info('The value of trf_stream is : {0}'.format(trf_stream))
                    TGIgmpIntList = list(config_dict['TG'][TG][trf_stream]['igmp_config_dict'].keys())
                    for TGIgmpInt in TGIgmpIntList:
                        e = d.interfaces[TGIgmpInt].tgen_port_handle
                        igmp_group_dict = MyLib.my_config_utils.generateIGMPGroupList(log,config_dict['TG'][TG][trf_stream]['igmp_config_dict'][TGIgmpInt])
                        log.info('the value of igmp_group_dict is : {0}'.format(igmp_group_dict))
                        ip_list = tg_interface_hdl_dict[TG][trf_stream][TGIgmpInt]['ip_list']
                        group_list = igmp_group_dict['groups']
                        group_config = igmp_group_dict['configs']
                        for i,ip in enumerate(ip_list):
                            tg_interface_hdl_dict[TG][trf_stream][TGIgmpInt][ip]['group'] = group_list[i]
                            if igmp_group_dict['v3_configs']:
                                emulation_igmp_group_cfg = configureIgmpReports(self, group_config[i], tg_hdl=d, port_handle = e, intf_handle=tg_interface_hdl_dict[TG][trf_stream][TGIgmpInt][ip]['handle'],
                                                                                g_filter_mode=igmp_group_dict['v3_configs']['g_filter_mode'],source_pool_handle=igmp_group_dict['v3_configs']['source_pool_handle'])
                            else:
                                emulation_igmp_group_cfg = configureIgmpReports(self, group_config[i], tg_hdl=d, port_handle = e, intf_handle=tg_interface_hdl_dict[TG][trf_stream][TGIgmpInt][ip]['handle'])
                            tg_interface_hdl_dict[TG][trf_stream][TGIgmpInt][ip]['session_handle'] = emulation_igmp_group_cfg.handle
              
        a = yaml.dump(tg_interface_hdl_dict)
        log.info('the value of tg_interface_hdl_dict is : {0}'.format(a)) 
#         '''
#         pass 
    @aetest.subsection     
    def configureTrafficStreams(self,testscript,log):
        
#         '''
        tg_interface_hdl_dict = testscript.parameters['tg_interface_hdl_dict'] 
        log.info('the value of tg_interface_hdl_dict is : {0}'.format(tg_interface_hdl_dict))
        configured_stream = testscript.parameters['configured_stream']
        
        log.info(banner('The value of configured_stream is : {0}'.format(configured_stream)))
        port_handle_dict = testscript.parameters['port_handle_dict']
        log.info('the value of port_handle_dict is : {0}'.format(port_handle_dict))
         
        TGList_config_file = testscript.parameters['TGList']
         
        traffic_stream_dict = {}
        for TG in TGList_config_file:
            d = testscript.parameters['testbed_obj'].devices[TG]
            for trf_stream in testscript.parameters['configdict']['TG'][TG]:
                log.info(banner('The value of trf_stream is : {0}'.format(trf_stream)))
                if(re.search('TRF',trf_stream)):
                    if trf_stream in configured_stream:
                        TGIgmpIntList = testscript.parameters['configdict']['TG'][TG][trf_stream]['traffic_config_dict'].keys()
                        src_handle = []
                        dest_handle = []
                        traffic_stream_dict[trf_stream] = {}
                        source_port = testscript.parameters['configdict']['TG'][TG][trf_stream]['traffic_config_dict']['source']
                        receiver_port = testscript.parameters['configdict']['TG'][TG][trf_stream]['traffic_config_dict']['receivers']
                        traffic_args=testscript.parameters['configdict']['TG'][TG][trf_stream]['traffic_config_dict']['params']
                        if isinstance(source_port, list):
                            for i in source_port:
                                log.info('src: The value of i is : {0}'.format(i))
                                for port in tg_interface_hdl_dict[TG][trf_stream]:
                                    log.info('src: The value of port is : {0}'.format(port))
                                    if(port == i):
                                        pat = re.compile("^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$")
                                        for ip in tg_interface_hdl_dict[TG][trf_stream][port]:
                                            test=pat.match(ip)
                                            if test:
                                                log.info('src: The value of i is : {0}'.format(i))
                                                log.info('src: The value of port is : {0}'.format(port))
                                                log.info('src: The value of ip is : {0}'.format(ip))
                                                log.info('src: The value of trf_stream is : {0}'.format(trf_stream))
                                                handle = tg_interface_hdl_dict[TG][trf_stream][port][ip]['handle']
                                                src_handle.append(handle)
                     
                        if isinstance(receiver_port,list):
                            for i in receiver_port:
                                log.info('rcv:The value of i is : {0}'.format(i))
                                for port in tg_interface_hdl_dict[TG][trf_stream]:
                                    log.info('rcv: The value of port is : {0}'.format(port))
                                    if(port == i):
                                        pat = re.compile("^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$")
                                        for ip in tg_interface_hdl_dict[TG][trf_stream][port]:
                                            test=pat.match(ip)
                                            if test:
                                                log.info('rcv: The value of i is : {0}'.format(i))
                                                log.info('rcv: The value of port is : {0}'.format(port))
                                                log.info('rcv: The value of ip is : {0}'.format(ip))
                                                log.info('rcv: The value of trf_stream is : {0}'.format(trf_stream))
                                                handle = tg_interface_hdl_dict[TG][trf_stream][port][ip]['session_handle']
                                                dest_handle.append(handle)
                        traffic_stream_dict[trf_stream]['source'] = source_port
                        traffic_stream_dict[trf_stream]['destination'] = receiver_port
                     
                        log.info('The value of src_handle is : {0}'.format(src_handle))
                        log.info('The value of dest_handle is : {0}'.format(dest_handle))
                         
                        ixia_traffic_config = configureIxNetworkTraffic(self, traffic_args, tg_hdl=d, emulation_src_handle=src_handle, emulation_dst_handle=dest_handle)
                        log.info('The value of ixia_traffic_config is : {0}'.format(ixia_traffic_config))
                    
                        traffic_stream_dict[trf_stream]['stream_id'] = ixia_traffic_config.stream_id
                        traffic_stream_dict[trf_stream]['traffic_item'] = ixia_traffic_config.traffic_item
                        traffic_stream_dict[trf_stream]['status'] = ixia_traffic_config.status
                        
                elif(re.search('RAW',trf_stream)):
                    log.info(banner('Inside RAW Stream Configuration : '))
                    if trf_stream in configured_stream:
                        TGIgmpIntList = testscript.parameters['configdict']['TG'][TG][trf_stream]['traffic_config_dict'].keys()
                        traffic_stream_dict[trf_stream] = {}
                        source_port = testscript.parameters['configdict']['TG'][TG][trf_stream]['traffic_config_dict']['source']
                        receiver_port = testscript.parameters['configdict']['TG'][TG][trf_stream]['traffic_config_dict']['receivers']
                        traffic_args=testscript.parameters['configdict']['TG'][TG][trf_stream]['traffic_config_dict']['params']

                        traffic_stream_dict[trf_stream]['source'] = source_port
                        traffic_stream_dict[trf_stream]['destination'] = receiver_port
                         
                        src_port = [port_handle_dict[x] for x in source_port]
                        dst_port = [port_handle_dict[x] for x in receiver_port]
                        log.info('The value of src_port is : {0}'.format(src_port))
                        log.info('The value of dst_port is : {0}'.format(dst_port))
                        
                        ixia_traffic_config = configureIxNetworkRawTrafficL2(self, traffic_args, tg_hdl=d, emulation_src_handle=src_port, emulation_dst_handle=dst_port)
                        log.info('The value of ixia_traffic_config is : {0}'.format(ixia_traffic_config))
                    
                        traffic_stream_dict[trf_stream]['stream_id'] = ixia_traffic_config.stream_id
                        traffic_stream_dict[trf_stream]['traffic_item'] = ixia_traffic_config.traffic_item
                        traffic_stream_dict[trf_stream]['status'] = ixia_traffic_config.status
                    
 
        log.info('The value of traffic_stream_dict is : {0}'.format(traffic_stream_dict))
        testscript.parameters['traffic_stream_dict']  = traffic_stream_dict 
        

    @aetest.subsection     
    def sendIGMPReports(self,testscript,log):  

        tg_interface_hdl_dict = testscript.parameters['tg_interface_hdl_dict'] 
        traffic_stream_dict = testscript.parameters['traffic_stream_dict'] 
        port_handle_dict = testscript.parameters['port_handle_dict']
        TGList_config_file = testscript.parameters['TGList']
        configdict = testscript.parameters['configdict'] 
        tgn_config_dict = configdict['TG']
        
        for TG in tgn_config_dict.keys():
            log.info('The value of TG is = %r', TG)
            tgn_hdl = testscript.parameters['testbed_obj'].devices[TG]
        
            igmp_status = startStopIgmpReports(tgn_hdl, action='start_all_protocols')
        
            if not igmp_status:
                log.info('IGMP Groups have not been sent successfully .. . Pls debug ')
    
    @aetest.subsection     
    def startAllTrafficStreams(self,testscript,log):  
   
        tg_interface_hdl_dict = testscript.parameters['tg_interface_hdl_dict'] 
        traffic_stream_dict = testscript.parameters['traffic_stream_dict'] 
        port_handle_dict = testscript.parameters['port_handle_dict']
        TGList_config_file = testscript.parameters['TGList']
        configdict = testscript.parameters['configdict'] 
        tgn_config_dict = configdict['TG']
        threshold = testscript.parameters['traffic_threshold'] 
        
        log.info(banner('The value of traffic_stream_dict is : {0}'.format(traffic_stream_dict)))
           
        unstarted_stream = []
        for TG in tgn_config_dict.keys():
            log.info('The value of TG is = %r', TG)
            tgn_hdl = testscript.parameters['testbed_obj'].devices[TG]
            flag = 1
            failed_traffic_stream_stats = {}
            for trf_stream in traffic_stream_dict:
                if traffic_stream_dict[trf_stream]['status']:
                    stream_handle = traffic_stream_dict[trf_stream]['traffic_item']
                    x = tgn_hdl.traffic_control(action='run', handle = stream_handle, max_wait_timer=60)
                    stream_id = traffic_stream_dict[trf_stream]['stream_id']
                    if not x.status:
                        log.error(banner('The Stream {0} could not be started as expected '.format(stream_id)))
                        unstarted_stream.append(stream_id)
                        
        log.info(banner('Waiting for 120 seconds after starting Traffic:'))
        countDownTimer(120)
        if unstarted_stream:
            log.error(banner('The Following Streams could not be started..{0}'.format(unstarted_stream)))
            self.failed()
    
    @aetest.subsection     
    def checkAllTrafficStreamsStats(self,testscript,log):  
   
        tg_interface_hdl_dict = testscript.parameters['tg_interface_hdl_dict'] 
        traffic_stream_dict = testscript.parameters['traffic_stream_dict'] 
        port_handle_dict = testscript.parameters['port_handle_dict']
        TGList_config_file = testscript.parameters['TGList']
        configdict = testscript.parameters['configdict'] 
        tgn_config_dict = configdict['TG']
        threshold = testscript.parameters['traffic_threshold']
        node_dict = testscript.parameters['node_dict']
        alias_intf_mapping = testscript.parameters['alias_intf_mapping']
        configured_stream = testscript.parameters['configured_stream']
        
        log.info(banner('The value of traffic_stream_dict is : {0}'.format(traffic_stream_dict)))
        
        log.info(banner('Waiting for 240 seconds before collecting Traffic Stats:'))
        countDownTimer(240)

        failed_stream_list = []
        for TG in tgn_config_dict.keys():
            log.info('The value of TG is = %r', TG)
            tgn_hdl = testscript.parameters['testbed_obj'].devices[TG]
            x = tgn_hdl.traffic_control(action='clear_stats',max_wait_timer=60)
            for trf_stream in traffic_stream_dict:
                if traffic_stream_dict[trf_stream]['status']:
                    stream_handle = traffic_stream_dict[trf_stream]['traffic_item']
                    x = tgn_hdl.traffic_control(action='clear_stats', handle = stream_handle, max_wait_timer=60)
                    stream_id = traffic_stream_dict[trf_stream]['stream_id']
                    countDownTimer(20)
                    y = tgn_hdl.traffic_stats(stream=stream_id,mode='traffic_item')
                    log.info(banner('The value of y is : {0}'.format(y)))
                    for i in y['traffic_item']:
                        if i == stream_id:
                            loss_percent= y['traffic_item'][i]['rx']['loss_percent']
                            log.info(banner('The value of loss_percent is : {0}'.format(loss_percent)))
                            if loss_percent > 1.0:
                                failed_stream_list.append(trf_stream)
            
            log.info(banner('Traffic Stream Details and Breakup is'))
            
            traffic_obj = MyLib.my_config_utils.TrafficStatistics(log,tg_interface_hdl_dict,traffic_stream_dict,port_handle_dict,
                                                              threshold,node_dict,alias_intf_mapping,configured_stream)
            
            traffic_obj.getAllBoundStreamStatistics(tgn_hdl)
#            traffic_obj.getAllRawStreamStatistics(tgn_hdl)
        
            if failed_stream_list:
                log.error(banner('The Initial Traffic Pass Criteria is not met for the following streams..{0}'.format(failed_stream_list)))
                failed_stream_dict = {}
                for stream in failed_stream_list:
                    failed_stream_dict[stream] = MyLib.my_config_utils.getTrafficItemStatistics(log,tgn_hdl,traffic_stream_dict,stream)
                log.info('the value of failed_stream_dict is : {0}'.format(failed_stream_dict))
                MyLib.my_config_utils.drawTrafficTable(log,failed_stream_dict,traffic_stream_dict)
                self.failed()
                
    @aetest.subsection     
    def initializeFewThingsForTest(self,testscript,log):
        tg_interface_hdl_dict = testscript.parameters['tg_interface_hdl_dict']
        traffic_stream_dict = testscript.parameters['traffic_stream_dict']
        port_handle_dict = testscript.parameters['port_handle_dict']
        threshold = testscript.parameters['traffic_threshold']
        node_dict = testscript.parameters['node_dict']
        alias_intf_mapping = testscript.parameters['alias_intf_mapping']
        configured_stream = testscript.parameters['configured_stream']
        config_dict = testscript.parameters['configdict']

        traffic_obj = MyLib.my_config_utils.TrafficStatistics(log,tg_interface_hdl_dict,traffic_stream_dict,port_handle_dict,
                                                       threshold,node_dict,alias_intf_mapping,configured_stream)
        testscript.parameters['traffic_obj'] = traffic_obj
        
        traffic_config_obj = MyLib.my_config_utils.TrafficConfiguration(log,testscript,config_dict,port_handle_dict)
        
        testscript.parameters['traffic_config_obj'] = traffic_config_obj
        
        scale_config_obj = MyLib.my_config_utils.ScaleConfig(log,node_dict,config_dict,alias_intf_mapping)
        
        testscript.parameters['scale_config_obj'] = scale_config_obj
        
        multicast_trigger_obj = MyLib.my_trigger_utils.MulticastTrigger(log,node_dict,config_dict,alias_intf_mapping)
        
        testscript.parameters['multicast_trigger_obj'] = multicast_trigger_obj
        
        trigger_obj = MyLib.my_utils.TriggerItems(log,node_dict,config_dict,traffic_stream_dict,port_handle_dict,threshold,alias_intf_mapping,configured_stream)
        testscript.parameters['trigger_obj'] = trigger_obj
 
        
        


class VXLANL3TRMVPCBLFUNC001(aetest.Testcase):

    """ Verify Source on BL (VPC1) and Rx Int"""

    uid = 'VXLAN-L3-TRM-VPC-BL-FUNC-001'

    @aetest.test
    def VxlanL3TRMVPC1BLSourceRxInt(self,log,testscript,testbed):
        tg_interface_hdl_dict = testscript.parameters['tg_interface_hdl_dict'] 
        traffic_stream_dict = testscript.parameters['traffic_stream_dict'] 
        port_handle_dict = testscript.parameters['port_handle_dict']
        TGList_config_file = testscript.parameters['TGList']
        configdict = testscript.parameters['configdict'] 
        tgn_config_dict = configdict['TG']
        threshold = testscript.parameters['traffic_threshold']
        node_dict = testscript.parameters['node_dict']
        alias_intf_mapping = testscript.parameters['alias_intf_mapping']
        configured_stream = testscript.parameters['configured_stream']
        traffic_obj = testscript.parameters['traffic_obj'] 
        traffic_config_obj = testscript.parameters['traffic_config_obj']
        trigger_obj = testscript.parameters['trigger_obj'] 
        
        res = [node_dict['all_dut'][dut].execute('terminal session-timeout 0') for dut in node_dict['all_dut'] if re.search('uut', dut)]
        
        for TG in tgn_config_dict.keys():
            log.info('The value of TG is = %r', TG)
            tgn_hdl = testscript.parameters['testbed_obj'].devices[TG]
            
            out = trigger_obj.checkAllStreamStats(tgn_hdl)
            traffic_obj.getAllBoundStreamStatistics(tgn_hdl)
            if out:
                log.info('Initial Traffic is fine.. Proceeding with the test case...')
                traffic_item = tgn_config_dict[TG]['TEST-001']
#                 configured_stream.append('TEST-001')
                
                log.info(banner('Stopping all the stream and waiting for 15 seconds'))
                x = tgn_hdl.traffic_control(action='stop',max_wait_timer=60)
                countDownTimer(15)
                
                log.info(banner('Creating the new Traffic Item - VPC BL-1  Src, Int Rcv'))
                
                new_tg_intf_config_dict = traffic_config_obj.generateIGMPTrafficdict(tgn_hdl,traffic_item)
                
                log.info(banner('The value of new_tg_intf_config_dict is : {0}'.format(new_tg_intf_config_dict)))
                
                log.info(banner('Waiting For 30 seconds before Sending IGMP JOINS .'))
                countDownTimer(30)
                log.info(banner('Sending IGMP Joins now.. '))
                
                for i in new_tg_intf_config_dict['destination']:
                    pat = re.compile("^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$")
                    for ip in new_tg_intf_config_dict[i]:
                        test=pat.match(ip)
                        if test:
                            a = new_tg_intf_config_dict[i][ip]['session_handle']
                            b = tgn_hdl.emulation_igmp_control(mode='start')
                            c = tgn_hdl.emulation_igmp_control(mode='start', group_member_handle=a)
                            o=tgn_hdl.emulation_igmp_control(mode='join',group_member_handle=a)
                            if not o.status:
                                log.info('IGMP join is not sent to the group . Pls debug.....')
                                self.failed()
                                        
                log.info(banner('Waiting for 30 seconds before starting the traffic:'))
                countDownTimer(30)
                
                log.info(banner('Starting the New Stream Created for this test ..'))
                x = tgn_hdl.traffic_control(action='run', handle = new_tg_intf_config_dict['traffic_item'],max_wait_timer=60)
                
                if not x.status:
                    log.error(banner('The Stream {0} could not be started as expected '.format(new_tg_intf_config_dict['stream_id'])))
                    self.failed()
                
                
                ixia_stream = new_tg_intf_config_dict['stream_id']
                res = MyLib.my_config_utils.getTrafficItemStatistics(log,tgn_hdl,ixia_stream,'TEST-001')
                
                log.info(banner('The Value of res is: {0}'.format(res)))
                
                flag = 0
                
                if abs(res['tx']-res['rx']) < threshold:
                    log.info('The TRM traffic is as expected.... Adding the Created stream and re-starting all other streams:')
                    
                    log.info('Stopping the New Traffic Item stream Created for this test:')
                    x1 = tgn_hdl.traffic_control(action='stop', handle = new_tg_intf_config_dict['traffic_item'], max_wait_timer=60)
                    
                    log.info(banner('Adding the New stream to the Main Traffic Stream Dict: '))
                    traffic_stream_dict.setdefault('TEST-001',{})
                    trimmed_stream_config_dict = dict((k,new_tg_intf_config_dict[k]) for k in new_tg_intf_config_dict.keys() if k in ['source','destination','stream_id','status','traffic_item'])
                    traffic_stream_dict['TEST-001'].update(trimmed_stream_config_dict)
                    log.info('The value of traffic_stream_dict is : {0}'.format(yaml.dump(traffic_stream_dict)))
                    
                    log.info(banner('Adding the New stream to the configured stream list :'))
                    configured_stream.append('TEST-001')
                    
                    log.info(banner('Sending the Modified Traffic_stream_dict and Configured_stream to global Testscript params'))
                    
                    testscript.parameters['configured_stream'] = configured_stream
                    testscript.parameters['traffic_stream_dict'] = traffic_stream_dict

                    
                else:
                    log.error(banner('TRM Traffic item is not as expected. The value of tx and rx is : {0} and {1}'.format(res['tx'],res['rx'])))
                    log.info(banner('Stopping the newly created Stream. Ixia Name: {0} Config_file Name is  : {1}'.format(ixia_stream,'TEST-001')))
                    x1 = tgn_hdl.traffic_control(action='stop', handle = new_tg_intf_config_dict['traffic_item'],max_wait_timer=60)
                    log.info(banner('Waiting for 30 seconds before removing the newly created stream {0}'.format(ixia_stream)))
                    countDownTimer(30)
                    log.info('Removing the stream {0}:'.format(ixia_stream))
                    y = tgn_hdl.traffic_config(mode='remove',stream_id=ixia_stream)
                    flag = 1
                    
                log.info(banner('Waiting for 30 seconds before starting all the streams..'))
                countDownTimer(30)

                log.info('Starting all the other streams')
                z = tgn_hdl.traffic_control(action='run',max_wait_timer=60)
                
                log.info(banner('Waiting for 30 seconds for the traffic to Converge'))
                countDownTimer(30)

                out = trigger_obj.checkAllStreamStats(tgn_hdl)
                traffic_obj.getAllBoundStreamStatistics(tgn_hdl)
                
                if not out:
                    log.error(banner('Traffic  Stream stats is not as expected after the end of the test .. Traffic status in Table format is: .. '))
                    traffic_obj.getAllBoundStreamStatistics(tgn_hdl)
                    flag = 1

                else:
                    log.info(banner('Cummulative Traffic flow is as expected.. '))
                    traffic_obj.getAllBoundStreamStatistics(tgn_hdl)     
                    
                if flag:
                    log.info(banner('Traffic flow is not as expected. Breakup is as follows:'))
                    traffic_obj.getAllBoundStreamStatistics(tgn_hdl)
                    countDownTimer(300)
                    self.failed()   
            else:
                log.error(banner('Initial Traffic flow is NOT as expected. Few streams failed. The Failed streams are : '))
                res1 = traffic_obj.getAllBoundStreamStatistics(tgn_hdl)
                self.failed()


 

class VXLANL3TRMVPCBLFUNC002(aetest.Testcase):

    """ Verify Source on BL (VPC2) and Rx Int """

    uid = 'VXLAN-L3-TRM-VPC-BL-FUNC-002'

    @aetest.test
    def VxlanL3TRMVPC2BLSourceRxInt(self,log,testscript,testbed):
        tg_interface_hdl_dict = testscript.parameters['tg_interface_hdl_dict'] 
        traffic_stream_dict = testscript.parameters['traffic_stream_dict'] 
        port_handle_dict = testscript.parameters['port_handle_dict']
        TGList_config_file = testscript.parameters['TGList']
        configdict = testscript.parameters['configdict'] 
        tgn_config_dict = configdict['TG']
        threshold = testscript.parameters['traffic_threshold']
        node_dict = testscript.parameters['node_dict']
        alias_intf_mapping = testscript.parameters['alias_intf_mapping']
        configured_stream = testscript.parameters['configured_stream']
        traffic_obj = testscript.parameters['traffic_obj'] 
        traffic_config_obj = testscript.parameters['traffic_config_obj']
        trigger_obj = testscript.parameters['trigger_obj'] 
        
        res = [node_dict['all_dut'][dut].execute('terminal session-timeout 0') for dut in node_dict['all_dut'] if re.search('uut', dut)]
        
        for TG in tgn_config_dict.keys():
            log.info('The value of TG is = %r', TG)
            tgn_hdl = testscript.parameters['testbed_obj'].devices[TG]
            
            out = trigger_obj.checkAllStreamStats(tgn_hdl)
            traffic_obj.getAllBoundStreamStatistics(tgn_hdl)
            if out:
                log.info('Initial Traffic is fine.. Proceeding with the test case...')
                traffic_item = tgn_config_dict[TG]['TEST-002']
#                 configured_stream.append('TEST-002')
                
                log.info(banner('Stopping all the stream and waiting for 15 seconds'))
                x = tgn_hdl.traffic_control(action='stop',max_wait_timer=60)
                countDownTimer(15)
                
                log.info(banner('Creating the new Traffic Item - VPC BL-1  Src, Int Rcv'))
                
                new_tg_intf_config_dict = traffic_config_obj.generateIGMPTrafficdict(tgn_hdl,traffic_item)
                
                log.info(banner('The value of new_tg_intf_config_dict is : {0}'.format(new_tg_intf_config_dict)))
                
                log.info(banner('Waiting For 30 seconds before Sending IGMP JOINS .'))
                countDownTimer(30)
                log.info(banner('Sending IGMP Joins now.. '))
                
                for i in new_tg_intf_config_dict['destination']:
                    pat = re.compile("^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$")
                    for ip in new_tg_intf_config_dict[i]:
                        test=pat.match(ip)
                        if test:
                            a = new_tg_intf_config_dict[i][ip]['session_handle']
                            b = tgn_hdl.emulation_igmp_control(mode='start')
                            c = tgn_hdl.emulation_igmp_control(mode='start', group_member_handle=a)
                            o=tgn_hdl.emulation_igmp_control(mode='join',group_member_handle=a)
                            if not o.status:
                                log.info('IGMP join is not sent to the group . Pls debug.....')
                                self.failed()
                                        
                log.info(banner('Waiting for 30 seconds before starting the traffic:'))
                countDownTimer(30)
                
                log.info(banner('Starting the New Stream Created for this test ..'))
                x = tgn_hdl.traffic_control(action='run', handle = new_tg_intf_config_dict['traffic_item'],max_wait_timer=60)
                
                if not x.status:
                    log.error(banner('The Stream {0} could not be started as expected '.format(new_tg_intf_config_dict['stream_id'])))
                    self.failed()
                
                
                ixia_stream = new_tg_intf_config_dict['stream_id']
                res = MyLib.my_config_utils.getTrafficItemStatistics(log,tgn_hdl,ixia_stream,'TEST-002')
                
                log.info(banner('The Value of res is: {0}'.format(res)))
                
                flag = 0
                
                if abs(res['tx']-res['rx']) < threshold:
                    log.info('The TRM traffic is as expected.... Adding the Created stream and re-starting all other streams:')
                    
                    log.info('Stopping the New Traffic Item stream Created for this test:')
                    x1 = tgn_hdl.traffic_control(action='stop', handle = new_tg_intf_config_dict['traffic_item'], max_wait_timer=60)
                    
                    log.info(banner('Adding the New stream to the Main Traffic Stream Dict: '))
                    traffic_stream_dict.setdefault('TEST-002',{})
                    trimmed_stream_config_dict = dict((k,new_tg_intf_config_dict[k]) for k in new_tg_intf_config_dict.keys() if k in ['source','destination','stream_id','status','traffic_item'])
                    traffic_stream_dict['TEST-002'].update(trimmed_stream_config_dict)
                    log.info('The value of traffic_stream_dict is : {0}'.format(yaml.dump(traffic_stream_dict)))
                    
                    log.info(banner('Adding the New stream to the configured stream list :'))
                    configured_stream.append('TEST-002')
                    
                    log.info(banner('Sending the Modified Traffic_stream_dict and Configured_stream to global Testscript params'))
                    
                    testscript.parameters['configured_stream'] = configured_stream
                    testscript.parameters['traffic_stream_dict'] = traffic_stream_dict

                    
                else:
                    log.error(banner('TRM Traffic item is not as expected. The value of tx and rx is : {0} and {1}'.format(res['tx'],res['rx'])))
                    log.info(banner('Stopping the newly created Stream. Ixia Name: {0} Config_file Name is  : {1}'.format(ixia_stream,'TEST-002')))
                    x1 = tgn_hdl.traffic_control(action='stop', handle = new_tg_intf_config_dict['traffic_item'],max_wait_timer=60)
                    log.info(banner('Waiting for 30 seconds before removing the newly created stream {0}'.format(ixia_stream)))
                    countDownTimer(30)
                    log.info('Removing the stream {0}:'.format(ixia_stream))
                    y = tgn_hdl.traffic_config(mode='remove',stream_id=ixia_stream)
                    flag = 1
                    
                log.info(banner('Waiting for 30 seconds before starting all the streams..'))
                countDownTimer(30)

                log.info('Starting all the other streams')
                z = tgn_hdl.traffic_control(action='run',max_wait_timer=60)
                
                log.info(banner('Waiting for 30 seconds for the traffic to Converge'))
                countDownTimer(30)

                out = trigger_obj.checkAllStreamStats(tgn_hdl)
                traffic_obj.getAllBoundStreamStatistics(tgn_hdl)
                
                if not out:
                    log.error(banner('Traffic  Stream stats is not as expected after the end of the test .. Traffic status in Table format is: .. '))
                    traffic_obj.getAllBoundStreamStatistics(tgn_hdl)
                    flag = 1

                else:
                    log.info(banner('Cummulative Traffic flow is as expected.. '))
                    traffic_obj.getAllBoundStreamStatistics(tgn_hdl)     
                    
                if flag:
                    log.info(banner('Traffic flow is not as expected. Breakup is as follows:'))
                    traffic_obj.getAllBoundStreamStatistics(tgn_hdl)
                    countDownTimer(300)
                    self.failed()   
            else:
                log.error(banner('Initial Traffic flow is NOT as expected. Few streams failed. The Failed streams are : '))
                res1 = traffic_obj.getAllBoundStreamStatistics(tgn_hdl)
                self.failed()



class VXLANL3TRMVPCBLFUNC003(aetest.Testcase):

    """ Verify Source on BL (VPC Ports) and Rx Int """

    uid = 'VXLAN-L3-TRM-VPC-BL-FUNC-003'

    @aetest.test
    def VxlanL3TRMVPC2BLSourceVPCPortRxInt(self,log,testscript,testbed):
        tg_interface_hdl_dict = testscript.parameters['tg_interface_hdl_dict'] 
        traffic_stream_dict = testscript.parameters['traffic_stream_dict'] 
        port_handle_dict = testscript.parameters['port_handle_dict']
        TGList_config_file = testscript.parameters['TGList']
        configdict = testscript.parameters['configdict'] 
        tgn_config_dict = configdict['TG']
        threshold = testscript.parameters['traffic_threshold']
        node_dict = testscript.parameters['node_dict']
        alias_intf_mapping = testscript.parameters['alias_intf_mapping']
        configured_stream = testscript.parameters['configured_stream']
        traffic_obj = testscript.parameters['traffic_obj'] 
        traffic_config_obj = testscript.parameters['traffic_config_obj']
        trigger_obj = testscript.parameters['trigger_obj'] 
        
        res = [node_dict['all_dut'][dut].execute('terminal session-timeout 0') for dut in node_dict['all_dut'] if re.search('uut', dut)]
        
        for TG in tgn_config_dict.keys():
            log.info('The value of TG is = %r', TG)
            tgn_hdl = testscript.parameters['testbed_obj'].devices[TG]
            
            out = trigger_obj.checkAllStreamStats(tgn_hdl)
            traffic_obj.getAllBoundStreamStatistics(tgn_hdl)
            if out:
                log.info('Initial Traffic is fine.. Proceeding with the test case...')
                traffic_item = tgn_config_dict[TG]['TEST-003']
#                 configured_stream.append('TEST-003')
                
                log.info(banner('Stopping all the stream and waiting for 15 seconds'))
                x = tgn_hdl.traffic_control(action='stop',max_wait_timer=60)
                countDownTimer(15)
                
                log.info(banner('Creating the new Traffic Item - VPC BL-1  Src, Int Rcv'))
                
                new_tg_intf_config_dict = traffic_config_obj.generateIGMPTrafficdict(tgn_hdl,traffic_item)
                
                log.info(banner('The value of new_tg_intf_config_dict is : {0}'.format(new_tg_intf_config_dict)))
                
                log.info(banner('Waiting For 30 seconds before Sending IGMP JOINS .'))
                countDownTimer(30)
                log.info(banner('Sending IGMP Joins now.. '))
                
                for i in new_tg_intf_config_dict['destination']:
                    pat = re.compile("^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$")
                    for ip in new_tg_intf_config_dict[i]:
                        test=pat.match(ip)
                        if test:
                            a = new_tg_intf_config_dict[i][ip]['session_handle']
                            b = tgn_hdl.emulation_igmp_control(mode='start')
                            c = tgn_hdl.emulation_igmp_control(mode='start', group_member_handle=a)
                            o=tgn_hdl.emulation_igmp_control(mode='join',group_member_handle=a)
                            if not o.status:
                                log.info('IGMP join is not sent to the group . Pls debug.....')
                                self.failed()
                                        
                log.info(banner('Waiting for 30 seconds before starting the traffic:'))
                countDownTimer(30)
                
                log.info(banner('Starting the New Stream Created for this test ..'))
                x = tgn_hdl.traffic_control(action='run', handle = new_tg_intf_config_dict['traffic_item'],max_wait_timer=60)
                
                if not x.status:
                    log.error(banner('The Stream {0} could not be started as expected '.format(new_tg_intf_config_dict['stream_id'])))
                    self.failed()
                
                
                ixia_stream = new_tg_intf_config_dict['stream_id']
                res = MyLib.my_config_utils.getTrafficItemStatistics(log,tgn_hdl,ixia_stream,'TEST-003')
                
                log.info(banner('The Value of res is: {0}'.format(res)))
                
                flag = 0
                
                if abs(res['tx']-res['rx']) < threshold:
                    log.info('The TRM traffic is as expected.... Adding the Created stream and re-starting all other streams:')
                    
                    log.info('Stopping the New Traffic Item stream Created for this test:')
                    x1 = tgn_hdl.traffic_control(action='stop', handle = new_tg_intf_config_dict['traffic_item'], max_wait_timer=60)
                    
                    log.info(banner('Adding the New stream to the Main Traffic Stream Dict: '))
                    traffic_stream_dict.setdefault('TEST-003',{})
                    trimmed_stream_config_dict = dict((k,new_tg_intf_config_dict[k]) for k in new_tg_intf_config_dict.keys() if k in ['source','destination','stream_id','status','traffic_item'])
                    traffic_stream_dict['TEST-003'].update(trimmed_stream_config_dict)
                    log.info('The value of traffic_stream_dict is : {0}'.format(yaml.dump(traffic_stream_dict)))
                    
                    log.info(banner('Adding the New stream to the configured stream list :'))
                    configured_stream.append('TEST-003')
                    
                    log.info(banner('Sending the Modified Traffic_stream_dict and Configured_stream to global Testscript params'))
                    
                    testscript.parameters['configured_stream'] = configured_stream
                    testscript.parameters['traffic_stream_dict'] = traffic_stream_dict

                    
                else:
                    log.error(banner('TRM Traffic item is not as expected. The value of tx and rx is : {0} and {1}'.format(res['tx'],res['rx'])))
                    log.info(banner('Stopping the newly created Stream. Ixia Name: {0} Config_file Name is  : {1}'.format(ixia_stream,'TEST-003')))
                    x1 = tgn_hdl.traffic_control(action='stop', handle = new_tg_intf_config_dict['traffic_item'],max_wait_timer=60)
                    log.info(banner('Waiting for 30 seconds before removing the newly created stream {0}'.format(ixia_stream)))
                    countDownTimer(30)
                    log.info('Removing the stream {0}:'.format(ixia_stream))
                    y = tgn_hdl.traffic_config(mode='remove',stream_id=ixia_stream)
                    flag = 1
                    
                log.info(banner('Waiting for 30 seconds before starting all the streams..'))
                countDownTimer(30)

                log.info('Starting all the other streams')
                z = tgn_hdl.traffic_control(action='run',max_wait_timer=60)
                
                log.info(banner('Waiting for 30 seconds for the traffic to Converge'))
                countDownTimer(30)

                out = trigger_obj.checkAllStreamStats(tgn_hdl)
                traffic_obj.getAllBoundStreamStatistics(tgn_hdl)
                
                if not out:
                    log.error(banner('Traffic  Stream stats is not as expected after the end of the test .. Traffic status in Table format is: .. '))
                    traffic_obj.getAllBoundStreamStatistics(tgn_hdl)
                    flag = 1

                else:
                    log.info(banner('Cummulative Traffic flow is as expected.. '))
                    traffic_obj.getAllBoundStreamStatistics(tgn_hdl)     
                    
                if flag:
                    log.info(banner('Traffic flow is not as expected. Breakup is as follows:'))
                    traffic_obj.getAllBoundStreamStatistics(tgn_hdl)
                    countDownTimer(300)
                    self.failed()   
            else:
                log.error(banner('Initial Traffic flow is NOT as expected. Few streams failed. The Failed streams are : '))
                res1 = traffic_obj.getAllBoundStreamStatistics(tgn_hdl)
                self.failed()



class VXLANL3TRMVPCBLFUNC004(aetest.Testcase):

    """ Verify Source on Stand VTEP1 Rx. Int """

    uid = 'VXLAN-L3-TRM-VPC-BL-FUNC-004'

    @aetest.test
    def VxlanL3TRMVPC2BLSourceStandVtep1RxInt1(self,log,testscript,testbed):
        tg_interface_hdl_dict = testscript.parameters['tg_interface_hdl_dict'] 
        traffic_stream_dict = testscript.parameters['traffic_stream_dict'] 
        port_handle_dict = testscript.parameters['port_handle_dict']
        TGList_config_file = testscript.parameters['TGList']
        configdict = testscript.parameters['configdict'] 
        tgn_config_dict = configdict['TG']
        threshold = testscript.parameters['traffic_threshold']
        node_dict = testscript.parameters['node_dict']
        alias_intf_mapping = testscript.parameters['alias_intf_mapping']
        configured_stream = testscript.parameters['configured_stream']
        traffic_obj = testscript.parameters['traffic_obj'] 
        traffic_config_obj = testscript.parameters['traffic_config_obj']
        trigger_obj = testscript.parameters['trigger_obj'] 
        
        res = [node_dict['all_dut'][dut].execute('terminal session-timeout 0') for dut in node_dict['all_dut'] if re.search('uut', dut)]
        
        for TG in tgn_config_dict.keys():
            log.info('The value of TG is = %r', TG)
            tgn_hdl = testscript.parameters['testbed_obj'].devices[TG]
            
            out = trigger_obj.checkAllStreamStats(tgn_hdl)
            traffic_obj.getAllBoundStreamStatistics(tgn_hdl)
            if out:
                log.info('Initial Traffic is fine.. Proceeding with the test case...')
                traffic_item = tgn_config_dict[TG]['TEST-004']
#                 configured_stream.append('TEST-004')
                
                log.info(banner('Stopping all the stream and waiting for 15 seconds'))
                x = tgn_hdl.traffic_control(action='stop',max_wait_timer=60)
                countDownTimer(15)
                
                log.info(banner('Creating the new Traffic Item - VPC BL-1  Src, Int Rcv'))
                
                new_tg_intf_config_dict = traffic_config_obj.generateIGMPTrafficdict(tgn_hdl,traffic_item)
                
                log.info(banner('The value of new_tg_intf_config_dict is : {0}'.format(new_tg_intf_config_dict)))
                
                log.info(banner('Waiting For 30 seconds before Sending IGMP JOINS .'))
                countDownTimer(30)
                log.info(banner('Sending IGMP Joins now.. '))
                
                for i in new_tg_intf_config_dict['destination']:
                    pat = re.compile("^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$")
                    for ip in new_tg_intf_config_dict[i]:
                        test=pat.match(ip)
                        if test:
                            a = new_tg_intf_config_dict[i][ip]['session_handle']
                            b = tgn_hdl.emulation_igmp_control(mode='start')
                            c = tgn_hdl.emulation_igmp_control(mode='start', group_member_handle=a)
                            o=tgn_hdl.emulation_igmp_control(mode='join',group_member_handle=a)
                            if not o.status:
                                log.info('IGMP join is not sent to the group . Pls debug.....')
                                self.failed()
                                        
                log.info(banner('Waiting for 30 seconds before starting the traffic:'))
                countDownTimer(30)
                
                log.info(banner('Starting the New Stream Created for this test ..'))
                x = tgn_hdl.traffic_control(action='run', handle = new_tg_intf_config_dict['traffic_item'],max_wait_timer=60)
                
                if not x.status:
                    log.error(banner('The Stream {0} could not be started as expected '.format(new_tg_intf_config_dict['stream_id'])))
                    self.failed()
                
                
                ixia_stream = new_tg_intf_config_dict['stream_id']
                res = MyLib.my_config_utils.getTrafficItemStatistics(log,tgn_hdl,ixia_stream,'TEST-004')
                
                log.info(banner('The Value of res is: {0}'.format(res)))
                
                flag = 0
                
                if abs(res['tx']-res['rx']) < threshold:
                    log.info('The TRM traffic is as expected.... Adding the Created stream and re-starting all other streams:')
                    
                    log.info('Stopping the New Traffic Item stream Created for this test:')
                    x1 = tgn_hdl.traffic_control(action='stop', handle = new_tg_intf_config_dict['traffic_item'], max_wait_timer=60)
                    
                    log.info(banner('Adding the New stream to the Main Traffic Stream Dict: '))
                    traffic_stream_dict.setdefault('TEST-004',{})
                    trimmed_stream_config_dict = dict((k,new_tg_intf_config_dict[k]) for k in new_tg_intf_config_dict.keys() if k in ['source','destination','stream_id','status','traffic_item'])
                    traffic_stream_dict['TEST-004'].update(trimmed_stream_config_dict)
                    log.info('The value of traffic_stream_dict is : {0}'.format(yaml.dump(traffic_stream_dict)))
                    
                    log.info(banner('Adding the New stream to the configured stream list :'))
                    configured_stream.append('TEST-004')
                    
                    log.info(banner('Sending the Modified Traffic_stream_dict and Configured_stream to global Testscript params'))
                    
                    testscript.parameters['configured_stream'] = configured_stream
                    testscript.parameters['traffic_stream_dict'] = traffic_stream_dict

                    
                else:
                    log.error(banner('TRM Traffic item is not as expected. The value of tx and rx is : {0} and {1}'.format(res['tx'],res['rx'])))
                    log.info(banner('Stopping the newly created Stream. Ixia Name: {0} Config_file Name is  : {1}'.format(ixia_stream,'TEST-004')))
                    x1 = tgn_hdl.traffic_control(action='stop', handle = new_tg_intf_config_dict['traffic_item'],max_wait_timer=60)
                    log.info(banner('Waiting for 30 seconds before removing the newly created stream {0}'.format(ixia_stream)))
                    countDownTimer(30)
                    log.info('Removing the stream {0}:'.format(ixia_stream))
                    y = tgn_hdl.traffic_config(mode='remove',stream_id=ixia_stream)
                    flag = 1
                    
                log.info(banner('Waiting for 30 seconds before starting all the streams..'))
                countDownTimer(30)

                log.info('Starting all the other streams')
                z = tgn_hdl.traffic_control(action='run',max_wait_timer=60)
                
                log.info(banner('Waiting for 30 seconds for the traffic to Converge'))
                countDownTimer(30)

                out = trigger_obj.checkAllStreamStats(tgn_hdl)
                traffic_obj.getAllBoundStreamStatistics(tgn_hdl)
                
                if not out:
                    log.error(banner('Traffic  Stream stats is not as expected after the end of the test .. Traffic status in Table format is: .. '))
                    traffic_obj.getAllBoundStreamStatistics(tgn_hdl)
                    flag = 1

                else:
                    log.info(banner('Cummulative Traffic flow is as expected.. '))
                    traffic_obj.getAllBoundStreamStatistics(tgn_hdl)     
                    
                if flag:
                    log.info(banner('Traffic flow is not as expected. Breakup is as follows:'))
                    traffic_obj.getAllBoundStreamStatistics(tgn_hdl)
                    countDownTimer(300)
                    self.failed()   
            else:
                log.error(banner('Initial Traffic flow is NOT as expected. Few streams failed. The Failed streams are : '))
                res1 = traffic_obj.getAllBoundStreamStatistics(tgn_hdl)
                self.failed()


                
                
class VXLANL3TRMVPCBLFUNC005(aetest.Testcase):

    """ Verify Source on Stand 1 VTEP and Rx Int """

    uid = 'VXLAN-L3-TRM-VPC-BL-FUNC-005'

    @aetest.test
    def VxlanL3TRMVPC2BLSourceStandVtep1RxInt2(self,log,testscript,testbed):
        tg_interface_hdl_dict = testscript.parameters['tg_interface_hdl_dict'] 
        traffic_stream_dict = testscript.parameters['traffic_stream_dict'] 
        port_handle_dict = testscript.parameters['port_handle_dict']
        TGList_config_file = testscript.parameters['TGList']
        configdict = testscript.parameters['configdict'] 
        tgn_config_dict = configdict['TG']
        threshold = testscript.parameters['traffic_threshold']
        node_dict = testscript.parameters['node_dict']
        alias_intf_mapping = testscript.parameters['alias_intf_mapping']
        configured_stream = testscript.parameters['configured_stream']
        traffic_obj = testscript.parameters['traffic_obj'] 
        traffic_config_obj = testscript.parameters['traffic_config_obj']
        trigger_obj = testscript.parameters['trigger_obj'] 
        
        res = [node_dict['all_dut'][dut].execute('terminal session-timeout 0') for dut in node_dict['all_dut'] if re.search('uut', dut)]
        
        for TG in tgn_config_dict.keys():
            log.info('The value of TG is = %r', TG)
            tgn_hdl = testscript.parameters['testbed_obj'].devices[TG]
            
            out = trigger_obj.checkAllStreamStats(tgn_hdl)
            traffic_obj.getAllBoundStreamStatistics(tgn_hdl)
            if out:
                log.info('Initial Traffic is fine.. Proceeding with the test case...')
                traffic_item = tgn_config_dict[TG]['TEST-005']
#                 configured_stream.append('TEST-005')
                
                log.info(banner('Stopping all the stream and waiting for 15 seconds'))
                x = tgn_hdl.traffic_control(action='stop',max_wait_timer=60)
                countDownTimer(15)
                
                log.info(banner('Creating the new Traffic Item - VPC BL-1  Src, Int Rcv'))
                
                new_tg_intf_config_dict = traffic_config_obj.generateIGMPTrafficdict(tgn_hdl,traffic_item)
                
                log.info(banner('The value of new_tg_intf_config_dict is : {0}'.format(new_tg_intf_config_dict)))
                
                log.info(banner('Waiting For 30 seconds before Sending IGMP JOINS .'))
                countDownTimer(30)
                log.info(banner('Sending IGMP Joins now.. '))
                
                for i in new_tg_intf_config_dict['destination']:
                    pat = re.compile("^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$")
                    for ip in new_tg_intf_config_dict[i]:
                        test=pat.match(ip)
                        if test:
                            a = new_tg_intf_config_dict[i][ip]['session_handle']
                            b = tgn_hdl.emulation_igmp_control(mode='start')
                            c = tgn_hdl.emulation_igmp_control(mode='start', group_member_handle=a)
                            o=tgn_hdl.emulation_igmp_control(mode='join',group_member_handle=a)
                            if not o.status:
                                log.info('IGMP join is not sent to the group . Pls debug.....')
                                self.failed()
                                        
                log.info(banner('Waiting for 30 seconds before starting the traffic:'))
                countDownTimer(30)
                
                log.info(banner('Starting the New Stream Created for this test ..'))
                x = tgn_hdl.traffic_control(action='run', handle = new_tg_intf_config_dict['traffic_item'],max_wait_timer=60)
                
                if not x.status:
                    log.error(banner('The Stream {0} could not be started as expected '.format(new_tg_intf_config_dict['stream_id'])))
                    self.failed()
                
                
                ixia_stream = new_tg_intf_config_dict['stream_id']
                res = MyLib.my_config_utils.getTrafficItemStatistics(log,tgn_hdl,ixia_stream,'TEST-005')
                
                log.info(banner('The Value of res is: {0}'.format(res)))
                
                flag = 0
                
                if abs(res['tx']-res['rx']) < threshold:
                    log.info('The TRM traffic is as expected.... Adding the Created stream and re-starting all other streams:')
                    
                    log.info('Stopping the New Traffic Item stream Created for this test:')
                    x1 = tgn_hdl.traffic_control(action='stop', handle = new_tg_intf_config_dict['traffic_item'], max_wait_timer=60)
                    
                    log.info(banner('Adding the New stream to the Main Traffic Stream Dict: '))
                    traffic_stream_dict.setdefault('TEST-005',{})
                    trimmed_stream_config_dict = dict((k,new_tg_intf_config_dict[k]) for k in new_tg_intf_config_dict.keys() if k in ['source','destination','stream_id','status','traffic_item'])
                    traffic_stream_dict['TEST-005'].update(trimmed_stream_config_dict)
                    log.info('The value of traffic_stream_dict is : {0}'.format(yaml.dump(traffic_stream_dict)))
                    
                    log.info(banner('Adding the New stream to the configured stream list :'))
                    configured_stream.append('TEST-005')
                    
                    log.info(banner('Sending the Modified Traffic_stream_dict and Configured_stream to global Testscript params'))
                    
                    testscript.parameters['configured_stream'] = configured_stream
                    testscript.parameters['traffic_stream_dict'] = traffic_stream_dict

                    
                else:
                    log.error(banner('TRM Traffic item is not as expected. The value of tx and rx is : {0} and {1}'.format(res['tx'],res['rx'])))
                    log.info(banner('Stopping the newly created Stream. Ixia Name: {0} Config_file Name is  : {1}'.format(ixia_stream,'TEST-005')))
                    x1 = tgn_hdl.traffic_control(action='stop', handle = new_tg_intf_config_dict['traffic_item'],max_wait_timer=60)
                    log.info(banner('Waiting for 30 seconds before removing the newly created stream {0}'.format(ixia_stream)))
                    countDownTimer(30)
                    log.info('Removing the stream {0}:'.format(ixia_stream))
                    y = tgn_hdl.traffic_config(mode='remove',stream_id=ixia_stream)
                    flag = 1
                    
                log.info(banner('Waiting for 30 seconds before starting all the streams..'))
                countDownTimer(30)

                log.info('Starting all the other streams')
                z = tgn_hdl.traffic_control(action='run',max_wait_timer=60)
                
                log.info(banner('Waiting for 30 seconds for the traffic to Converge'))
                countDownTimer(30)

                out = trigger_obj.checkAllStreamStats(tgn_hdl)
                traffic_obj.getAllBoundStreamStatistics(tgn_hdl)
                
                if not out:
                    log.error(banner('Traffic  Stream stats is not as expected after the end of the test .. Traffic status in Table format is: .. '))
                    traffic_obj.getAllBoundStreamStatistics(tgn_hdl)
                    flag = 1

                else:
                    log.info(banner('Cummulative Traffic flow is as expected.. '))
                    traffic_obj.getAllBoundStreamStatistics(tgn_hdl)     
                    
                if flag:
                    log.info(banner('Traffic flow is not as expected. Breakup is as follows:'))
                    traffic_obj.getAllBoundStreamStatistics(tgn_hdl)
                    countDownTimer(300)
                    self.failed()   
            else:
                log.error(banner('Initial Traffic flow is NOT as expected. Few streams failed. The Failed streams are : '))
                res1 = traffic_obj.getAllBoundStreamStatistics(tgn_hdl)
                self.failed()
                
class VXLANL3TRMVPCBLFUNC006(aetest.Testcase):

    """ Verify Source on BL (VPC Ports) and Rx Int """

    uid = 'VXLAN-L3-TRM-VPC-BL-FUNC-006'

    @aetest.test
    def VxlanL3TRMVPC2BLSourceStandVtep1RxInt3(self,log,testscript,testbed):
        tg_interface_hdl_dict = testscript.parameters['tg_interface_hdl_dict'] 
        traffic_stream_dict = testscript.parameters['traffic_stream_dict'] 
        port_handle_dict = testscript.parameters['port_handle_dict']
        TGList_config_file = testscript.parameters['TGList']
        configdict = testscript.parameters['configdict'] 
        tgn_config_dict = configdict['TG']
        threshold = testscript.parameters['traffic_threshold']
        node_dict = testscript.parameters['node_dict']
        alias_intf_mapping = testscript.parameters['alias_intf_mapping']
        configured_stream = testscript.parameters['configured_stream']
        traffic_obj = testscript.parameters['traffic_obj'] 
        traffic_config_obj = testscript.parameters['traffic_config_obj']
        trigger_obj = testscript.parameters['trigger_obj'] 
        
        res = [node_dict['all_dut'][dut].execute('terminal session-timeout 0') for dut in node_dict['all_dut'] if re.search('uut', dut)]
        
        for TG in tgn_config_dict.keys():
            log.info('The value of TG is = %r', TG)
            tgn_hdl = testscript.parameters['testbed_obj'].devices[TG]
            
            out = trigger_obj.checkAllStreamStats(tgn_hdl)
            traffic_obj.getAllBoundStreamStatistics(tgn_hdl)
            if out:
                log.info('Initial Traffic is fine.. Proceeding with the test case...')
                traffic_item = tgn_config_dict[TG]['TEST-006']
#                 configured_stream.append('TEST-006')
                
                log.info(banner('Stopping all the stream and waiting for 15 seconds'))
                x = tgn_hdl.traffic_control(action='stop',max_wait_timer=60)
                countDownTimer(15)
                
                log.info(banner('Creating the new Traffic Item - VPC BL-1  Src, Int Rcv'))
                
                new_tg_intf_config_dict = traffic_config_obj.generateIGMPTrafficdict(tgn_hdl,traffic_item)
                
                log.info(banner('The value of new_tg_intf_config_dict is : {0}'.format(new_tg_intf_config_dict)))
                
                log.info(banner('Waiting For 30 seconds before Sending IGMP JOINS .'))
                countDownTimer(30)
                log.info(banner('Sending IGMP Joins now.. '))
                
                for i in new_tg_intf_config_dict['destination']:
                    pat = re.compile("^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$")
                    for ip in new_tg_intf_config_dict[i]:
                        test=pat.match(ip)
                        if test:
                            a = new_tg_intf_config_dict[i][ip]['session_handle']
                            b = tgn_hdl.emulation_igmp_control(mode='start')
                            c = tgn_hdl.emulation_igmp_control(mode='start', group_member_handle=a)
                            o=tgn_hdl.emulation_igmp_control(mode='join',group_member_handle=a)
                            if not o.status:
                                log.info('IGMP join is not sent to the group . Pls debug.....')
                                self.failed()
                                        
                log.info(banner('Waiting for 30 seconds before starting the traffic:'))
                countDownTimer(30)
                
                log.info(banner('Starting the New Stream Created for this test ..'))
                x = tgn_hdl.traffic_control(action='run', handle = new_tg_intf_config_dict['traffic_item'],max_wait_timer=60)
                
                if not x.status:
                    log.error(banner('The Stream {0} could not be started as expected '.format(new_tg_intf_config_dict['stream_id'])))
                    self.failed()
                
                
                ixia_stream = new_tg_intf_config_dict['stream_id']
                res = MyLib.my_config_utils.getTrafficItemStatistics(log,tgn_hdl,ixia_stream,'TEST-006')
                
                log.info(banner('The Value of res is: {0}'.format(res)))
                
                flag = 0
                
                if abs(res['tx']-res['rx']) < threshold:
                    log.info('The TRM traffic is as expected.... Adding the Created stream and re-starting all other streams:')
                    
                    log.info('Stopping the New Traffic Item stream Created for this test:')
                    x1 = tgn_hdl.traffic_control(action='stop', handle = new_tg_intf_config_dict['traffic_item'], max_wait_timer=60)
                    
                    log.info(banner('Adding the New stream to the Main Traffic Stream Dict: '))
                    traffic_stream_dict.setdefault('TEST-006',{})
                    trimmed_stream_config_dict = dict((k,new_tg_intf_config_dict[k]) for k in new_tg_intf_config_dict.keys() if k in ['source','destination','stream_id','status','traffic_item'])
                    traffic_stream_dict['TEST-006'].update(trimmed_stream_config_dict)
                    log.info('The value of traffic_stream_dict is : {0}'.format(yaml.dump(traffic_stream_dict)))
                    
                    log.info(banner('Adding the New stream to the configured stream list :'))
                    configured_stream.append('TEST-006')
                    
                    log.info(banner('Sending the Modified Traffic_stream_dict and Configured_stream to global Testscript params'))
                    
                    testscript.parameters['configured_stream'] = configured_stream
                    testscript.parameters['traffic_stream_dict'] = traffic_stream_dict

                    
                else:
                    log.error(banner('TRM Traffic item is not as expected. The value of tx and rx is : {0} and {1}'.format(res['tx'],res['rx'])))
                    log.info(banner('Stopping the newly created Stream. Ixia Name: {0} Config_file Name is  : {1}'.format(ixia_stream,'TEST-006')))
                    x1 = tgn_hdl.traffic_control(action='stop', handle = new_tg_intf_config_dict['traffic_item'],max_wait_timer=60)
                    log.info(banner('Waiting for 30 seconds before removing the newly created stream {0}'.format(ixia_stream)))
                    countDownTimer(30)
                    log.info('Removing the stream {0}:'.format(ixia_stream))
                    y = tgn_hdl.traffic_config(mode='remove',stream_id=ixia_stream)
                    flag = 1
                    
                log.info(banner('Waiting for 30 seconds before starting all the streams..'))
                countDownTimer(30)

                log.info('Starting all the other streams')
                z = tgn_hdl.traffic_control(action='run',max_wait_timer=60)
                
                log.info(banner('Waiting for 30 seconds for the traffic to Converge'))
                countDownTimer(30)

                out = trigger_obj.checkAllStreamStats(tgn_hdl)
                traffic_obj.getAllBoundStreamStatistics(tgn_hdl)
                
                if not out:
                    log.error(banner('Traffic  Stream stats is not as expected after the end of the test .. Traffic status in Table format is: .. '))
                    traffic_obj.getAllBoundStreamStatistics(tgn_hdl)
                    flag = 1

                else:
                    log.info(banner('Cummulative Traffic flow is as expected.. '))
                    traffic_obj.getAllBoundStreamStatistics(tgn_hdl)     
                    
                if flag:
                    log.info(banner('Traffic flow is not as expected. Breakup is as follows:'))
                    traffic_obj.getAllBoundStreamStatistics(tgn_hdl)
                    countDownTimer(300)
                    self.failed()   
            else:
                log.error(banner('Initial Traffic flow is NOT as expected. Few streams failed. The Failed streams are : '))
                res1 = traffic_obj.getAllBoundStreamStatistics(tgn_hdl)
                self.failed()


             
class VXLANL3TRMVPCBLFUNC007(aetest.Testcase):

    """ Verify Source on BL (VPC Ports) and Rx Int """

    uid = 'VXLAN-L3-TRM-VPC-BL-FUNC-007'

    @aetest.test
    def VxlanL3TRMVPC2BLSourceStandVTEP2RxInt1(self,log,testscript,testbed):
        tg_interface_hdl_dict = testscript.parameters['tg_interface_hdl_dict'] 
        traffic_stream_dict = testscript.parameters['traffic_stream_dict'] 
        port_handle_dict = testscript.parameters['port_handle_dict']
        TGList_config_file = testscript.parameters['TGList']
        configdict = testscript.parameters['configdict'] 
        tgn_config_dict = configdict['TG']
        threshold = testscript.parameters['traffic_threshold']
        node_dict = testscript.parameters['node_dict']
        alias_intf_mapping = testscript.parameters['alias_intf_mapping']
        configured_stream = testscript.parameters['configured_stream']
        traffic_obj = testscript.parameters['traffic_obj'] 
        traffic_config_obj = testscript.parameters['traffic_config_obj']
        trigger_obj = testscript.parameters['trigger_obj'] 
        
        res = [node_dict['all_dut'][dut].execute('terminal session-timeout 0') for dut in node_dict['all_dut'] if re.search('uut', dut)]
        
        for TG in tgn_config_dict.keys():
            log.info('The value of TG is = %r', TG)
            tgn_hdl = testscript.parameters['testbed_obj'].devices[TG]
            
            out = trigger_obj.checkAllStreamStats(tgn_hdl)
            traffic_obj.getAllBoundStreamStatistics(tgn_hdl)
            if out:
                log.info('Initial Traffic is fine.. Proceeding with the test case...')
                traffic_item = tgn_config_dict[TG]['TEST-007']
#                 configured_stream.append('TEST-007')
                
                log.info(banner('Stopping all the stream and waiting for 15 seconds'))
                x = tgn_hdl.traffic_control(action='stop',max_wait_timer=60)
                countDownTimer(15)
                
                log.info(banner('Creating the new Traffic Item - VPC BL-1  Src, Int Rcv'))
                
                new_tg_intf_config_dict = traffic_config_obj.generateIGMPTrafficdict(tgn_hdl,traffic_item)
                
                log.info(banner('The value of new_tg_intf_config_dict is : {0}'.format(new_tg_intf_config_dict)))
                
                log.info(banner('Waiting For 30 seconds before Sending IGMP JOINS .'))
                countDownTimer(30)
                log.info(banner('Sending IGMP Joins now.. '))
                
                for i in new_tg_intf_config_dict['destination']:
                    pat = re.compile("^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$")
                    for ip in new_tg_intf_config_dict[i]:
                        test=pat.match(ip)
                        if test:
                            a = new_tg_intf_config_dict[i][ip]['session_handle']
                            b = tgn_hdl.emulation_igmp_control(mode='start')
                            c = tgn_hdl.emulation_igmp_control(mode='start', group_member_handle=a)
                            o=tgn_hdl.emulation_igmp_control(mode='join',group_member_handle=a)
                            if not o.status:
                                log.info('IGMP join is not sent to the group . Pls debug.....')
                                self.failed()
                                        
                log.info(banner('Waiting for 30 seconds before starting the traffic:'))
                countDownTimer(30)
                
                log.info(banner('Starting the New Stream Created for this test ..'))
                x = tgn_hdl.traffic_control(action='run', handle = new_tg_intf_config_dict['traffic_item'],max_wait_timer=60)
                
                if not x.status:
                    log.error(banner('The Stream {0} could not be started as expected '.format(new_tg_intf_config_dict['stream_id'])))
                    self.failed()
                
                
                ixia_stream = new_tg_intf_config_dict['stream_id']
                res = MyLib.my_config_utils.getTrafficItemStatistics(log,tgn_hdl,ixia_stream,'TEST-007')
                
                log.info(banner('The Value of res is: {0}'.format(res)))
                
                flag = 0
                
                if abs(res['tx']-res['rx']) < threshold:
                    log.info('The TRM traffic is as expected.... Adding the Created stream and re-starting all other streams:')
                    
                    log.info('Stopping the New Traffic Item stream Created for this test:')
                    x1 = tgn_hdl.traffic_control(action='stop', handle = new_tg_intf_config_dict['traffic_item'], max_wait_timer=60)
                    
                    log.info(banner('Adding the New stream to the Main Traffic Stream Dict: '))
                    traffic_stream_dict.setdefault('TEST-007',{})
                    trimmed_stream_config_dict = dict((k,new_tg_intf_config_dict[k]) for k in new_tg_intf_config_dict.keys() if k in ['source','destination','stream_id','status','traffic_item'])
                    traffic_stream_dict['TEST-007'].update(trimmed_stream_config_dict)
                    log.info('The value of traffic_stream_dict is : {0}'.format(yaml.dump(traffic_stream_dict)))
                    
                    log.info(banner('Adding the New stream to the configured stream list :'))
                    configured_stream.append('TEST-007')
                    
                    log.info(banner('Sending the Modified Traffic_stream_dict and Configured_stream to global Testscript params'))
                    
                    testscript.parameters['configured_stream'] = configured_stream
                    testscript.parameters['traffic_stream_dict'] = traffic_stream_dict

                    
                else:
                    log.error(banner('TRM Traffic item is not as expected. The value of tx and rx is : {0} and {1}'.format(res['tx'],res['rx'])))
                    log.info(banner('Stopping the newly created Stream. Ixia Name: {0} Config_file Name is  : {1}'.format(ixia_stream,'TEST-007')))
                    x1 = tgn_hdl.traffic_control(action='stop', handle = new_tg_intf_config_dict['traffic_item'],max_wait_timer=60)
                    log.info(banner('Waiting for 30 seconds before removing the newly created stream {0}'.format(ixia_stream)))
                    countDownTimer(30)
                    log.info('Removing the stream {0}:'.format(ixia_stream))
                    y = tgn_hdl.traffic_config(mode='remove',stream_id=ixia_stream)
                    flag = 1
                    
                log.info(banner('Waiting for 30 seconds before starting all the streams..'))
                countDownTimer(30)

                log.info('Starting all the other streams')
                z = tgn_hdl.traffic_control(action='run',max_wait_timer=60)
                
                log.info(banner('Waiting for 30 seconds for the traffic to Converge'))
                countDownTimer(30)

                out = trigger_obj.checkAllStreamStats(tgn_hdl)
                traffic_obj.getAllBoundStreamStatistics(tgn_hdl)
                
                if not out:
                    log.error(banner('Traffic  Stream stats is not as expected after the end of the test .. Traffic status in Table format is: .. '))
                    traffic_obj.getAllBoundStreamStatistics(tgn_hdl)
                    flag = 1

                else:
                    log.info(banner('Cummulative Traffic flow is as expected.. '))
                    traffic_obj.getAllBoundStreamStatistics(tgn_hdl)     
                    
                if flag:
                    log.info(banner('Traffic flow is not as expected. Breakup is as follows:'))
                    traffic_obj.getAllBoundStreamStatistics(tgn_hdl)
                    countDownTimer(300)
                    self.failed()   
            else:
                log.error(banner('Initial Traffic flow is NOT as expected. Few streams failed. The Failed streams are : '))
                res1 = traffic_obj.getAllBoundStreamStatistics(tgn_hdl)
                self.failed()
 
class VXLANL3TRMVPCBLFUNC008(aetest.Testcase):

    """ Verify Source on BL (VPC Ports) and Rx Int """

    uid = 'VXLAN-L3-TRM-VPC-BL-FUNC-008'

    @aetest.test
    def VxlanL3TRMVPC2BLSourceStandVTEP2RxInt2(self,log,testscript,testbed):
        tg_interface_hdl_dict = testscript.parameters['tg_interface_hdl_dict'] 
        traffic_stream_dict = testscript.parameters['traffic_stream_dict'] 
        port_handle_dict = testscript.parameters['port_handle_dict']
        TGList_config_file = testscript.parameters['TGList']
        configdict = testscript.parameters['configdict'] 
        tgn_config_dict = configdict['TG']
        threshold = testscript.parameters['traffic_threshold']
        node_dict = testscript.parameters['node_dict']
        alias_intf_mapping = testscript.parameters['alias_intf_mapping']
        configured_stream = testscript.parameters['configured_stream']
        traffic_obj = testscript.parameters['traffic_obj'] 
        traffic_config_obj = testscript.parameters['traffic_config_obj']
        trigger_obj = testscript.parameters['trigger_obj'] 
        
        res = [node_dict['all_dut'][dut].execute('terminal session-timeout 0') for dut in node_dict['all_dut'] if re.search('uut', dut)]
        
        for TG in tgn_config_dict.keys():
            log.info('The value of TG is = %r', TG)
            tgn_hdl = testscript.parameters['testbed_obj'].devices[TG]
            
            out = trigger_obj.checkAllStreamStats(tgn_hdl)
            traffic_obj.getAllBoundStreamStatistics(tgn_hdl)
            if out:
                log.info('Initial Traffic is fine.. Proceeding with the test case...')
                traffic_item = tgn_config_dict[TG]['TEST-008']
#                 configured_stream.append('TEST-008')
                
                log.info(banner('Stopping all the stream and waiting for 15 seconds'))
                x = tgn_hdl.traffic_control(action='stop',max_wait_timer=60)
                countDownTimer(15)
                
                log.info(banner('Creating the new Traffic Item - VPC BL-1  Src, Int Rcv'))
                
                new_tg_intf_config_dict = traffic_config_obj.generateIGMPTrafficdict(tgn_hdl,traffic_item)
                
                log.info(banner('The value of new_tg_intf_config_dict is : {0}'.format(new_tg_intf_config_dict)))
                
                log.info(banner('Waiting For 30 seconds before Sending IGMP JOINS .'))
                countDownTimer(30)
                log.info(banner('Sending IGMP Joins now.. '))
                
                for i in new_tg_intf_config_dict['destination']:
                    pat = re.compile("^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$")
                    for ip in new_tg_intf_config_dict[i]:
                        test=pat.match(ip)
                        if test:
                            a = new_tg_intf_config_dict[i][ip]['session_handle']
                            b = tgn_hdl.emulation_igmp_control(mode='start')
                            c = tgn_hdl.emulation_igmp_control(mode='start', group_member_handle=a)
                            o=tgn_hdl.emulation_igmp_control(mode='join',group_member_handle=a)
                            if not o.status:
                                log.info('IGMP join is not sent to the group . Pls debug.....')
                                self.failed()
                                        
                log.info(banner('Waiting for 30 seconds before starting the traffic:'))
                countDownTimer(30)
                
                log.info(banner('Starting the New Stream Created for this test ..'))
                x = tgn_hdl.traffic_control(action='run', handle = new_tg_intf_config_dict['traffic_item'],max_wait_timer=60)
                
                if not x.status:
                    log.error(banner('The Stream {0} could not be started as expected '.format(new_tg_intf_config_dict['stream_id'])))
                    self.failed()
                
                
                ixia_stream = new_tg_intf_config_dict['stream_id']
                res = MyLib.my_config_utils.getTrafficItemStatistics(log,tgn_hdl,ixia_stream,'TEST-008')
                
                log.info(banner('The Value of res is: {0}'.format(res)))
                
                flag = 0
                
                if abs(res['tx']-res['rx']) < threshold:
                    log.info('The TRM traffic is as expected.... Adding the Created stream and re-starting all other streams:')
                    
                    log.info('Stopping the New Traffic Item stream Created for this test:')
                    x1 = tgn_hdl.traffic_control(action='stop', handle = new_tg_intf_config_dict['traffic_item'], max_wait_timer=60)
                    
                    log.info(banner('Adding the New stream to the Main Traffic Stream Dict: '))
                    traffic_stream_dict.setdefault('TEST-008',{})
                    trimmed_stream_config_dict = dict((k,new_tg_intf_config_dict[k]) for k in new_tg_intf_config_dict.keys() if k in ['source','destination','stream_id','status','traffic_item'])
                    traffic_stream_dict['TEST-008'].update(trimmed_stream_config_dict)
                    log.info('The value of traffic_stream_dict is : {0}'.format(yaml.dump(traffic_stream_dict)))
                    
                    log.info(banner('Adding the New stream to the configured stream list :'))
                    configured_stream.append('TEST-008')
                    
                    log.info(banner('Sending the Modified Traffic_stream_dict and Configured_stream to global Testscript params'))
                    
                    testscript.parameters['configured_stream'] = configured_stream
                    testscript.parameters['traffic_stream_dict'] = traffic_stream_dict

                    
                else:
                    log.error(banner('TRM Traffic item is not as expected. The value of tx and rx is : {0} and {1}'.format(res['tx'],res['rx'])))
                    log.info(banner('Stopping the newly created Stream. Ixia Name: {0} Config_file Name is  : {1}'.format(ixia_stream,'TEST-008')))
                    x1 = tgn_hdl.traffic_control(action='stop', handle = new_tg_intf_config_dict['traffic_item'],max_wait_timer=60)
                    log.info(banner('Waiting for 30 seconds before removing the newly created stream {0}'.format(ixia_stream)))
                    countDownTimer(30)
                    log.info('Removing the stream {0}:'.format(ixia_stream))
                    y = tgn_hdl.traffic_config(mode='remove',stream_id=ixia_stream)
                    flag = 1
                    
                log.info(banner('Waiting for 30 seconds before starting all the streams..'))
                countDownTimer(30)

                log.info('Starting all the other streams')
                z = tgn_hdl.traffic_control(action='run',max_wait_timer=60)
                
                log.info(banner('Waiting for 30 seconds for the traffic to Converge'))
                countDownTimer(30)

                out = trigger_obj.checkAllStreamStats(tgn_hdl)
                traffic_obj.getAllBoundStreamStatistics(tgn_hdl)
                
                if not out:
                    log.error(banner('Traffic  Stream stats is not as expected after the end of the test .. Traffic status in Table format is: .. '))
                    traffic_obj.getAllBoundStreamStatistics(tgn_hdl)
                    flag = 1

                else:
                    log.info(banner('Cummulative Traffic flow is as expected.. '))
                    traffic_obj.getAllBoundStreamStatistics(tgn_hdl)     
                    
                if flag:
                    log.info(banner('Traffic flow is not as expected. Breakup is as follows:'))
                    traffic_obj.getAllBoundStreamStatistics(tgn_hdl)
                    countDownTimer(300)
                    self.failed()   
            else:
                log.error(banner('Initial Traffic flow is NOT as expected. Few streams failed. The Failed streams are : '))
                res1 = traffic_obj.getAllBoundStreamStatistics(tgn_hdl)
                self.failed()
                 
                
class VXLANL3TRMVPCBLFUNC009(aetest.Testcase):

    """ Verify Source on BL (VPC Ports) and Rx Int """

    uid = 'VXLAN-L3-TRM-VPC-BL-FUNC-009'

    @aetest.test
    def VxlanL3TRMVPC2BLSourceStandVTEP2RxInt3(self,log,testscript,testbed):
        tg_interface_hdl_dict = testscript.parameters['tg_interface_hdl_dict'] 
        traffic_stream_dict = testscript.parameters['traffic_stream_dict'] 
        port_handle_dict = testscript.parameters['port_handle_dict']
        TGList_config_file = testscript.parameters['TGList']
        configdict = testscript.parameters['configdict'] 
        tgn_config_dict = configdict['TG']
        threshold = testscript.parameters['traffic_threshold']
        node_dict = testscript.parameters['node_dict']
        alias_intf_mapping = testscript.parameters['alias_intf_mapping']
        configured_stream = testscript.parameters['configured_stream']
        traffic_obj = testscript.parameters['traffic_obj'] 
        traffic_config_obj = testscript.parameters['traffic_config_obj']
        trigger_obj = testscript.parameters['trigger_obj'] 
        
        res = [node_dict['all_dut'][dut].execute('terminal session-timeout 0') for dut in node_dict['all_dut'] if re.search('uut', dut)]
        
        for TG in tgn_config_dict.keys():
            log.info('The value of TG is = %r', TG)
            tgn_hdl = testscript.parameters['testbed_obj'].devices[TG]
            
            out = trigger_obj.checkAllStreamStats(tgn_hdl)
            traffic_obj.getAllBoundStreamStatistics(tgn_hdl)
            if out:
                log.info('Initial Traffic is fine.. Proceeding with the test case...')
                traffic_item = tgn_config_dict[TG]['TEST-009']
#                 configured_stream.append('TEST-009')
                
                log.info(banner('Stopping all the stream and waiting for 15 seconds'))
                x = tgn_hdl.traffic_control(action='stop',max_wait_timer=60)
                countDownTimer(15)
                
                log.info(banner('Creating the new Traffic Item - VPC BL-1  Src, Int Rcv'))
                
                new_tg_intf_config_dict = traffic_config_obj.generateIGMPTrafficdict(tgn_hdl,traffic_item)
                
                log.info(banner('The value of new_tg_intf_config_dict is : {0}'.format(new_tg_intf_config_dict)))
                
                log.info(banner('Waiting For 30 seconds before Sending IGMP JOINS .'))
                countDownTimer(30)
                log.info(banner('Sending IGMP Joins now.. '))
                
                for i in new_tg_intf_config_dict['destination']:
                    pat = re.compile("^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$")
                    for ip in new_tg_intf_config_dict[i]:
                        test=pat.match(ip)
                        if test:
                            a = new_tg_intf_config_dict[i][ip]['session_handle']
                            b = tgn_hdl.emulation_igmp_control(mode='start')
                            c = tgn_hdl.emulation_igmp_control(mode='start', group_member_handle=a)
                            o=tgn_hdl.emulation_igmp_control(mode='join',group_member_handle=a)
                            if not o.status:
                                log.info('IGMP join is not sent to the group . Pls debug.....')
                                self.failed()
                                        
                log.info(banner('Waiting for 30 seconds before starting the traffic:'))
                countDownTimer(30)
                
                log.info(banner('Starting the New Stream Created for this test ..'))
                x = tgn_hdl.traffic_control(action='run', handle = new_tg_intf_config_dict['traffic_item'],max_wait_timer=60)
                
                if not x.status:
                    log.error(banner('The Stream {0} could not be started as expected '.format(new_tg_intf_config_dict['stream_id'])))
                    self.failed()
                
                
                ixia_stream = new_tg_intf_config_dict['stream_id']
                res = MyLib.my_config_utils.getTrafficItemStatistics(log,tgn_hdl,ixia_stream,'TEST-009')
                
                log.info(banner('The Value of res is: {0}'.format(res)))
                
                flag = 0
                
                if abs(res['tx']-res['rx']) < threshold:
                    log.info('The TRM traffic is as expected.... Adding the Created stream and re-starting all other streams:')
                    
                    log.info('Stopping the New Traffic Item stream Created for this test:')
                    x1 = tgn_hdl.traffic_control(action='stop', handle = new_tg_intf_config_dict['traffic_item'], max_wait_timer=60)
                    
                    log.info(banner('Adding the New stream to the Main Traffic Stream Dict: '))
                    traffic_stream_dict.setdefault('TEST-009',{})
                    trimmed_stream_config_dict = dict((k,new_tg_intf_config_dict[k]) for k in new_tg_intf_config_dict.keys() if k in ['source','destination','stream_id','status','traffic_item'])
                    traffic_stream_dict['TEST-009'].update(trimmed_stream_config_dict)
                    log.info('The value of traffic_stream_dict is : {0}'.format(yaml.dump(traffic_stream_dict)))
                    
                    log.info(banner('Adding the New stream to the configured stream list :'))
                    configured_stream.append('TEST-009')
                    
                    log.info(banner('Sending the Modified Traffic_stream_dict and Configured_stream to global Testscript params'))
                    
                    testscript.parameters['configured_stream'] = configured_stream
                    testscript.parameters['traffic_stream_dict'] = traffic_stream_dict

                    
                else:
                    log.error(banner('TRM Traffic item is not as expected. The value of tx and rx is : {0} and {1}'.format(res['tx'],res['rx'])))
                    log.info(banner('Stopping the newly created Stream. Ixia Name: {0} Config_file Name is  : {1}'.format(ixia_stream,'TEST-009')))
                    x1 = tgn_hdl.traffic_control(action='stop', handle = new_tg_intf_config_dict['traffic_item'],max_wait_timer=60)
                    log.info(banner('Waiting for 30 seconds before removing the newly created stream {0}'.format(ixia_stream)))
                    countDownTimer(30)
                    log.info('Removing the stream {0}:'.format(ixia_stream))
                    y = tgn_hdl.traffic_config(mode='remove',stream_id=ixia_stream)
                    flag = 1
                    
                log.info(banner('Waiting for 30 seconds before starting all the streams..'))
                countDownTimer(30)

                log.info('Starting all the other streams')
                z = tgn_hdl.traffic_control(action='run',max_wait_timer=60)
                
                log.info(banner('Waiting for 30 seconds for the traffic to Converge'))
                countDownTimer(30)

                out = trigger_obj.checkAllStreamStats(tgn_hdl)
                traffic_obj.getAllBoundStreamStatistics(tgn_hdl)
                
                if not out:
                    log.error(banner('Traffic  Stream stats is not as expected after the end of the test .. Traffic status in Table format is: .. '))
                    traffic_obj.getAllBoundStreamStatistics(tgn_hdl)
                    flag = 1

                else:
                    log.info(banner('Cummulative Traffic flow is as expected.. '))
                    traffic_obj.getAllBoundStreamStatistics(tgn_hdl)     
                    
                if flag:
                    log.info(banner('Traffic flow is not as expected. Breakup is as follows:'))
                    traffic_obj.getAllBoundStreamStatistics(tgn_hdl)
                    countDownTimer(300)
                    self.failed()   
            else:
                log.error(banner('Initial Traffic flow is NOT as expected. Few streams failed. The Failed streams are : '))
                res1 = traffic_obj.getAllBoundStreamStatistics(tgn_hdl)
                self.failed()
 
class VXLANL3TRMVPCBLFUNC010(aetest.Testcase):

    """ Verify Source Entry clearing post stopping the traffic. """

    uid = 'VXLAN-L3-TRM-VPC-BL-FUNC-010'

    @aetest.test
    def VxlanL3TRMStopAllSourceAndCheckForSGEntry(self,log,testscript,testbed):
        tg_interface_hdl_dict = testscript.parameters['tg_interface_hdl_dict'] 
        traffic_stream_dict = testscript.parameters['traffic_stream_dict'] 
        port_handle_dict = testscript.parameters['port_handle_dict']
        TGList_config_file = testscript.parameters['TGList']
        configdict = testscript.parameters['configdict'] 
        tgn_config_dict = configdict['TG']
        threshold = testscript.parameters['traffic_threshold']
        node_dict = testscript.parameters['node_dict']
        alias_intf_mapping = testscript.parameters['alias_intf_mapping']
        configured_stream = testscript.parameters['configured_stream']
        traffic_obj = testscript.parameters['traffic_obj'] 
        traffic_config_obj = testscript.parameters['traffic_config_obj']
        multicast_trigger_obj = testscript.parameters['multicast_trigger_obj'] 
        scale_config_obj = testscript.parameters['scale_config_obj']
        trigger_obj = testscript.parameters['trigger_obj'] 
        
        res = [node_dict['all_dut'][dut].execute('terminal session-timeout 0') for dut in node_dict['all_dut'] if re.search('uut', dut)]
        
        for TG in tgn_config_dict.keys():
            log.info('The value of TG is = %r', TG)
            tgn_hdl = testscript.parameters['testbed_obj'].devices[TG]
            flag = 0
            out = trigger_obj.checkAllStreamStats(tgn_hdl)
            traffic_obj.getAllBoundStreamStatistics(tgn_hdl)
            if out:
                log.info('Initial Traffic is fine.. Proceeding with the test case...')                
                log.info(banner('Stopping all the other stream and waiting for 15 seconds'))
                t = tgn_hdl.traffic_control(action='stop',max_wait_timer=60)
                countDownTimer(15)
                
                log.info(banner('Waiting for 400 seconds to check for S-G entry to expire'))
                
                countDownTimer(400)
                vtep_dict = scale_config_obj.getDeviceDict('all_vtep')
                msg_list = []
                final_result = []
                for dut in vtep_dict:
                    hdl = node_dict['all_dut'][dut]
                    log.info('Checking for S,G entry on the dut {0} for all VRFs ..'.format(dut))
                    vrf_list  = multicast_trigger_obj.getVRFInformationFromDut(log,dut,hdl)
                    log.info('The value of vrf_list is : {0}'.format(vrf_list))
                    
                    for vrf_name in vrf_list:
                        res1 = multicast_trigger_obj.getMulticastSourceOnVRF(dut,hdl,vrf_name)
                        if res1:
                            msg = 'The following S,G entries {0} are not cleared on dut {1} on vrf {2}'.format(res1,dut,vrf_name)
                            msg_list.append(msg)
                            flag = 1
                        try:
                            final_result.append((dut,vrf_name,len(res1),res1))
                        except:
                            log.info('Some exception Occured.')
                
                log.info('the value of final_result is : {0}'.format(final_result))
                            
                t = PrettyTable(['DUT','VRF_NAME', 'LEN-SOURCE' , 'SOURCES']) 
                for item in final_result:
                    dut,vrf_na,source_len,sources = item
                    t.add_row([dut,vrf_na,source_len,sources])
                    
                log.info('The S,G Table is : {0}'.format(t))
                
                log.info('Starting all the other streams')
                z = tgn_hdl.traffic_control(action='run',max_wait_timer=60)
                
                log.info(banner('Waiting for 30 seconds for the traffic to Converge'))
                countDownTimer(30)

                out = trigger_obj.checkAllStreamStats(tgn_hdl)
                traffic_obj.getAllBoundStreamStatistics(tgn_hdl)
                
                if not out:
                    log.error(banner('Traffic is not as expected after the end of the test .. '))
                    res1 = traffic_obj.getAllBoundStreamStatistics(tgn_hdl)
                    if flag:
                        log.error(banner('The following S,G entries are not cleared at the end of the test: {0}'.format(msg_list))) 
                        self.failed()    
                    self.failed()
                else:
                    log.info(banner(' Traffic flow is as expected After the test.. '))
                    res1 = traffic_obj.getAllBoundStreamStatistics(tgn_hdl)   
                    if flag:
                        log.error(banner('The following S,G entries are not cleared at end end of the test: {0}'.format(msg_list))) 
                        self.failed()

            else:
                log.error(banner('Initial Traffic flow is NOT as expected. Few streams failed. The Failed streams are : '))
                res1 = traffic_obj.getAllBoundStreamStatistics(tgn_hdl)
                self.failed()   

class VXLANL3TRMVPCBLFUNC011(aetest.Testcase):

    """ Verify *,G clearing post stopping the IGMP Protocol """

    uid = 'VXLAN-L3-TRM-VPC-BL-FUNC-011'

    @aetest.test
    def VxlanL3TRMStopAllIGMPHosts(self,log,testscript,testbed):
        tg_interface_hdl_dict = testscript.parameters['tg_interface_hdl_dict'] 
        traffic_stream_dict = testscript.parameters['traffic_stream_dict'] 
        port_handle_dict = testscript.parameters['port_handle_dict']
        TGList_config_file = testscript.parameters['TGList']
        configdict = testscript.parameters['configdict'] 
        tgn_config_dict = configdict['TG']
        threshold = testscript.parameters['traffic_threshold']
        node_dict = testscript.parameters['node_dict']
        alias_intf_mapping = testscript.parameters['alias_intf_mapping']
        configured_stream = testscript.parameters['configured_stream']
        traffic_obj = testscript.parameters['traffic_obj'] 
        traffic_config_obj = testscript.parameters['traffic_config_obj']
        multicast_trigger_obj = testscript.parameters['multicast_trigger_obj'] 
        scale_config_obj = testscript.parameters['scale_config_obj']
        trigger_obj = testscript.parameters['trigger_obj'] 
        
        
        res = [node_dict['all_dut'][dut].execute('terminal session-timeout 0') for dut in node_dict['all_dut'] if re.search('uut', dut)]
        
        for TG in tgn_config_dict.keys():
            log.info('The value of TG is = %r', TG)
            tgn_hdl = testscript.parameters['testbed_obj'].devices[TG]
            out = trigger_obj.checkAllStreamStats(tgn_hdl)
            traffic_obj.getAllBoundStreamStatistics(tgn_hdl)
            flag = 0
            if out:
                log.info('Initial Traffic is fine.. Proceeding with the test case...')                
                log.info(banner('Stopping all the other stream and waiting for 15 seconds'))
                igmp_status = startStopIgmpReports(tgn_hdl, action='stop_all_protocols')
                countDownTimer(15)
                
                log.info('Waiting for 400 seconds to check for *.G entry to expire ')
                
                countDownTimer(400)
                vtep_dict = scale_config_obj.getDeviceDict('all_vtep')
                msg_list = []
                final_result = []
                for dut in vtep_dict:
                    hdl = node_dict['all_dut'][dut]
                    log.info('Checking for S,G entry on the dut {0} for all VRFs ..'.format(dut))
                    vrf_list  = multicast_trigger_obj.getVRFInformationFromDut(log,dut,hdl)
                    log.info('The value of vrf_list is : {0}'.format(vrf_list))
                    
                    for vrf_name in vrf_list:
                        res1 = multicast_trigger_obj.getMulticastIGMPGroupsOnVRF(dut,hdl,vrf_name)
                        if res1:
                            msg = 'The following S,G entries {0} are not cleared on dut {1} on vrf {2}'.format(res1,dut,vrf_name)
                            msg_list.append(msg)
                            flag = 1
                        try:
                            final_result.append((dut,vrf_name,len(res1),res1))
                        except:
                            log.info('Some exception Occured.')
                
                log.info('the value of final_result is : {0}'.format(final_result))
                            
                t = PrettyTable(['DUT','VRF_NAME', 'LEN-SOURCE' , 'SOURCES']) 
                for item in final_result:
                    dut,vrf_na,source_len,sources = item
                    t.add_row([dut,vrf_na,source_len,sources])
                    
                log.info('The S,G Table is : {0}'.format(t))
                
                log.info('Starting all the other streams')
                igmp_status = startStopIgmpReports(tgn_hdl, action='start_all_protocols')
                
                log.info(banner('Waiting for 30 seconds for the traffic to Converge'))
                countDownTimer(30)

                out = trigger_obj.checkAllStreamStats(tgn_hdl)
                traffic_obj.getAllBoundStreamStatistics(tgn_hdl)
                
                if not out:
                    log.error(banner('Traffic is not as expected after the end of the test .. '))
                    res1 = traffic_obj.getAllBoundStreamStatistics(tgn_hdl)
                    if flag:
                        log.error(banner('The following S,G entries are not cleared at the end of the test: {0}'.format(msg_list))) 
                        self.failed()    
                    self.failed()
                else:
                    log.info(banner(' Traffic flow is as expected After the test.. '))
                    res1 = traffic_obj.getAllBoundStreamStatistics(tgn_hdl)   
                    if flag:
                        log.error(banner('The following S,G entries are not cleared at end end of the test: {0}'.format(msg_list))) 
                        self.failed()

            else:
                log.error(banner('Initial Traffic flow is NOT as expected. Few streams failed. The Failed streams are : '))
                res1 = traffic_obj.getAllBoundStreamStatistics(tgn_hdl)
                self.failed() 


class VXLANL3TRMVPCBLFUNC012(aetest.Testcase):

    """ Verify *,G and S,G clearing post stopping the Traffic and IGMP Protocol """

    uid = 'VXLAN-L3-TRM-VPC-BL-FUNC-012'

    @aetest.test
    def VxlanL3TRMStopAllTrafficAndIGMPHosts(self,log,testscript,testbed):
        tg_interface_hdl_dict = testscript.parameters['tg_interface_hdl_dict'] 
        traffic_stream_dict = testscript.parameters['traffic_stream_dict'] 
        port_handle_dict = testscript.parameters['port_handle_dict']
        TGList_config_file = testscript.parameters['TGList']
        configdict = testscript.parameters['configdict'] 
        tgn_config_dict = configdict['TG']
        threshold = testscript.parameters['traffic_threshold']
        node_dict = testscript.parameters['node_dict']
        alias_intf_mapping = testscript.parameters['alias_intf_mapping']
        configured_stream = testscript.parameters['configured_stream']
        traffic_obj = testscript.parameters['traffic_obj'] 
        traffic_config_obj = testscript.parameters['traffic_config_obj']
        multicast_trigger_obj = testscript.parameters['multicast_trigger_obj'] 
        scale_config_obj = testscript.parameters['scale_config_obj']
        trigger_obj = testscript.parameters['trigger_obj'] 
        
        
        res = [node_dict['all_dut'][dut].execute('terminal session-timeout 0') for dut in node_dict['all_dut'] if re.search('uut', dut)]
        
        for TG in tgn_config_dict.keys():
            log.info('The value of TG is = %r', TG)
            tgn_hdl = testscript.parameters['testbed_obj'].devices[TG]
            out = trigger_obj.checkAllStreamStats(tgn_hdl)
            traffic_obj.getAllBoundStreamStatistics(tgn_hdl)
            flag = 0
            if out:
                log.info('Initial Traffic is fine.. Proceeding with the test case...')                
                log.info(banner('Stopping all the IGMP Protocol and waiting for 15 seconds'))
                igmp_status = startStopIgmpReports(tgn_hdl, action='stop_all_protocols')
                countDownTimer(15)
                log.info(banner('Stopping all the Stream and waiting for 15 seconds'))
                t = tgn_hdl.traffic_control(action='stop',max_wait_timer=60)
                countDownTimer(15)
                
                log.info('Waiting for 400 seconds for S,G and *,G to Expire ')
                
                countDownTimer(400)
                vtep_dict = scale_config_obj.getDeviceDict('all_vtep')
                msg_list = []
                for dut in vtep_dict:
                    hdl = node_dict['all_dut'][dut]
                    log.info('Checking for S,G entry on the dut {0} for all VRFs ..'.format(dut))
                    vrf_list  = multicast_trigger_obj.getVRFInformationFromDut(log,dut,hdl)
                    log.info('The value of vrf_list is : {0}'.format(vrf_list))
                    
                    for vrf_name in vrf_list:
                        res1 = multicast_trigger_obj.getMulticastSourceOnVRF(dut,hdl,vrf_name)
                        if res1:
                            msg = 'The following S,G entries {0} are not cleared on dut {1} on vrf {2}'.format(res1,dut,vrf_name)
                            msg_list.append(msg)
                            flag = 1
                            
                        res2 = multicast_trigger_obj.getMulticastIGMPGroupsOnVRF(dut,hdl,vrf_name)
                        if res2:
                            msg = 'The following *,G entries {0} are not cleared on dut {1} on vrf {2}'.format(res2,dut,vrf_name)
                            msg_list.append(msg)
                            flag = 1                            
                
                log.info('Starting all the other streams')
                igmp_status = startStopIgmpReports(tgn_hdl, action='start_all_protocols')
                countDownTimer(30)
                
                log.info(banner('Starting all the Stream and waiting for 300 seconds'))
                t = tgn_hdl.traffic_control(action='run',max_wait_timer=60)
                
                countDownTimer(300)
                
                log.info(banner('Waiting for 30 seconds for the traffic to Converge'))
                countDownTimer(30)

                out = trigger_obj.checkAllStreamStats(tgn_hdl)
                traffic_obj.getAllBoundStreamStatistics(tgn_hdl)
                
                if not out:
                    log.error(banner('Traffic is not as expected after the end of the test .. '))
                    res1 = traffic_obj.getAllBoundStreamStatistics(tgn_hdl)
                    if flag:
                        log.error(banner('The following S,G entries are not cleared at the end of the test: {0}'.format(msg_list))) 
                        self.failed()    
                    self.failed()
                else:
                    log.info(banner(' Traffic flow is as expected After the test.. '))
                    res1 = traffic_obj.getAllBoundStreamStatistics(tgn_hdl)   
                    if flag:
                        log.error(banner('The following S,G entries are not cleared at end end of the test: {0}'.format(msg_list))) 
                        self.failed()

            else:
                log.error(banner('Initial Traffic flow is NOT as expected. Few streams failed. The Failed streams are : '))
                res1 = traffic_obj.getAllBoundStreamStatistics(tgn_hdl)
                self.failed() 


class VXLANL3TRMVPCBLFUNC013(aetest.Testcase):
 
    """ VPC Trigger - 1 -  VPC (BL-1)  MCT PORT Flap -- PRIMARY"""
 
    uid = 'VXLAN-L3-TRM-VPC-BL-FUNC-013'
 
    @aetest.test
    def VxlanL3TRMSVPCBLMCTFlapPrimary(self,log,testscript,testbed):
        node_dict = testscript.parameters['node_dict']
        traffic_stream_dict = testscript.parameters['traffic_stream_dict'] 
        tg_interface_hdl_dict = testscript.parameters['tg_interface_hdl_dict']
        port_handle_dict = testscript.parameters['port_handle_dict']
        configdict = testscript.parameters['configdict'] 
        tgn_config_dict = configdict['TG']
        threshold = testscript.parameters['traffic_threshold'] 
        tgn_port_dut_mapping = testscript.parameters['tgn_port_dut_mapping']
        traffic_obj = testscript.parameters['traffic_obj']
        trigger_obj = testscript.parameters['trigger_obj']
        alias_intf_mapping = testscript.parameters['alias_intf_mapping']
         
        res = [node_dict['all_dut'][dut].configure('terminal session-timeout 0') for dut in node_dict['all_dut'] if re.search('uut', dut)]
         
        for TG in tgn_config_dict.keys():
            tgn_hdl = testscript.parameters['testbed_obj'].devices[TG]
            out = trigger_obj.checkAllStreamStats(tgn_hdl)
         
            if out:
                log.info(banner('Initial Traffic flow is as expected:'))
                traffic_obj.getAllBoundStreamStatistics(tgn_hdl)
                 
                log.info(banner('Taking Backup of configs on all the VTEPs:'))
                 
                device_dict = trigger_obj.getDeviceDict('vpc_vtep')
                 
                res = trigger_obj.backUpAndRestoreConfigs(list(device_dict.keys()),'backup')
                 
                vpc_vtep_dict = trigger_obj.getVPCSwitchhdl('details')
                 
                dut = vpc_vtep_dict['primary']['dut']
                hdl = vpc_vtep_dict['primary']['hdl']
                 
                out = hdl.execute('sh vpc brief  | xml')
                 
                s = BeautifulSoup(out)
                mct = s.find('peerlink-ifindex').string
                 
                log.info(banner('The value of mct is : {0}'.format(mct)))
                 
                k = 1
                while (k <= 10):
                    log.info(banner('***** Iteration # {0} ******'.format(k)))
                    log.info('Flapping the Interface {0} in dut {1}'.format(mct,dut))
                    res = MyLib.my_utils.flapInterface(log,hdl,mct,dut)
                    k += 1
                     
                log.info(banner('Waiting for 100 seconds before collecting the traffic stats:'))
                countDownTimer(100)
                 
                out = trigger_obj.checkAllStreamStats(tgn_hdl)
                traffic_obj.getAllBoundStreamStatistics(tgn_hdl)
                 
                flag = 0
                if not out:
                    log.error(banner('Traffic has not restored properly after the Trigger - DisablePIML2VNI'))
                    trigger_obj.backUpAndRestoreConfigs(list(device_dict.keys()),'restore')
                    flag = 1
                
                if flag:
                    log.error(banner('Traffic has not restored after the trigger:'))
                    traffic_obj.getAllBoundStreamStatistics(tgn_hdl)
                    self.failed()
 
            else:
                log.error('The Initial Traffic Condition did not pass:')
                traffic_obj.getAllBoundStreamStatistics(tgn_hdl)
                countDownTimer(180)
                self.failed()    
                 
class VXLANL3TRMVPCBLFUNC014(aetest.Testcase):
 
    """ VPC Trigger - 1 -  VPC (BL-2)  MCT PORT Flap -- PRIMARY"""
 
    uid = 'VXLAN-L3-TRM-VPC-BL-FUNC-014'
 
    @aetest.test
    def VxlanL3TRMSVPCBLMCTFlapSecondary(self,log,testscript,testbed):
        node_dict = testscript.parameters['node_dict']
        traffic_stream_dict = testscript.parameters['traffic_stream_dict'] 
        tg_interface_hdl_dict = testscript.parameters['tg_interface_hdl_dict']
        port_handle_dict = testscript.parameters['port_handle_dict']
        configdict = testscript.parameters['configdict'] 
        tgn_config_dict = configdict['TG']
        threshold = testscript.parameters['traffic_threshold'] 
        tgn_port_dut_mapping = testscript.parameters['tgn_port_dut_mapping']
        traffic_obj = testscript.parameters['traffic_obj']
        trigger_obj = testscript.parameters['trigger_obj']
        alias_intf_mapping = testscript.parameters['alias_intf_mapping']
         
        res = [node_dict['all_dut'][dut].configure('terminal session-timeout 0') for dut in node_dict['all_dut'] if re.search('uut', dut)]
         
        for TG in tgn_config_dict.keys():
            tgn_hdl = testscript.parameters['testbed_obj'].devices[TG]
            out = trigger_obj.checkAllStreamStats(tgn_hdl)
         
            if out:
                log.info(banner('Initial Traffic flow is as expected:'))
                traffic_obj.getAllBoundStreamStatistics(tgn_hdl)
                 
                log.info(banner('Taking Backup of configs on all the VTEPs:'))
                 
                device_dict = trigger_obj.getDeviceDict('vpc_vtep')
                 
                res = trigger_obj.backUpAndRestoreConfigs(list(device_dict.keys()),'backup')
                 
                vpc_vtep_dict = trigger_obj.getVPCSwitchhdl('details')
                 
                dut = vpc_vtep_dict['secondary']['dut']
                hdl = vpc_vtep_dict['secondary']['hdl']
                 
                out = hdl.execute('sh vpc brief  | xml')
                 
                s = BeautifulSoup(out)
                mct = s.find('peerlink-ifindex').string
                 
                log.info(banner('The value of mct is : {0}'.format(mct)))
                 
                k = 1
                while (k <= 10):
                    log.info(banner('***** Iteration # {0} ******'.format(k)))
                    log.info('Flapping the Interface {0} in dut {1}'.format(mct,dut))
                    res = MyLib.my_utils.flapInterface(log,hdl,mct,dut)
                    k += 1
                     
                log.info(banner('Waiting for 100 seconds before collecting the traffic stats:'))
                countDownTimer(100)
                 
                out = trigger_obj.checkAllStreamStats(tgn_hdl)
                traffic_obj.getAllBoundStreamStatistics(tgn_hdl)
                 
                flag = 0
                if not out:
                    log.error(banner('Traffic has not restored properly after the Trigger - DisablePIML2VNI'))
                    trigger_obj.backUpAndRestoreConfigs(list(device_dict.keys()),'restore')
                    flag = 1
                
                if flag:
                    log.error(banner('Traffic has not restored after the trigger:'))
                    traffic_obj.getAllBoundStreamStatistics(tgn_hdl)
                    self.failed()
 
            else:
                log.error('The Initial Traffic Condition did not pass:')
                traffic_obj.getAllBoundStreamStatistics(tgn_hdl)
                countDownTimer(180)
                self.failed()        


class VXLANL3TRMVPCBLFUNC015(aetest.Testcase):
 
    """ VPC Trigger - 3 -  VPC PORT CHANNEL FLAP - PRIMARY """
 
    uid = 'VXLAN-L3-TRM-VPC-BL-FUNC-015'
 
    @aetest.test
    def VxlanL3TRMSVPCBLVPCPoFlapPrimary(self,log,testscript,testbed):
        node_dict = testscript.parameters['node_dict']
        traffic_stream_dict = testscript.parameters['traffic_stream_dict'] 
        tg_interface_hdl_dict = testscript.parameters['tg_interface_hdl_dict']
        port_handle_dict = testscript.parameters['port_handle_dict']
        configdict = testscript.parameters['configdict'] 
        tgn_config_dict = configdict['TG']
        threshold = testscript.parameters['traffic_threshold'] 
        tgn_port_dut_mapping = testscript.parameters['tgn_port_dut_mapping']
        traffic_obj = testscript.parameters['traffic_obj']
        trigger_obj = testscript.parameters['trigger_obj']
        alias_intf_mapping = testscript.parameters['alias_intf_mapping']
         
        res = [node_dict['all_dut'][dut].configure('terminal session-timeout 0') for dut in node_dict['all_dut'] if re.search('uut', dut)]
         
        for TG in tgn_config_dict.keys():
            tgn_hdl = testscript.parameters['testbed_obj'].devices[TG]
            out = trigger_obj.checkAllStreamStats(tgn_hdl)
         
            if out:
                log.info(banner('Initial Traffic flow is as expected:'))
                traffic_obj.getAllBoundStreamStatistics(tgn_hdl)
                 
                log.info(banner('Taking Backup of configs on all the VTEPs:'))
                 
                device_dict = trigger_obj.getDeviceDict('vpc_vtep')
                 
                res = trigger_obj.backUpAndRestoreConfigs(list(device_dict.keys()),'backup')
                 
                vpc_vtep_dict = trigger_obj.getVPCSwitchhdl('details')
                 
                dut = vpc_vtep_dict['primary']['dut']
                hdl = vpc_vtep_dict['primary']['hdl']
                 
                out = hdl.execute('sh vpc brief  | xml')
                 
                s = BeautifulSoup(out)
                vpc_po = s.find('vpc-ifindex').string
                 
                log.info(banner('The value of vpc_po is : {0}'.format(vpc_po)))
                 
                k = 1
                while (k <= 10):
                    log.info(banner('***** Iteration # {0} ******'.format(k)))
                    log.info('Flapping the Interface {0} in dut {1}'.format(vpc_po,dut))
                    res = MyLib.my_utils.flapInterface(log,hdl,vpc_po,dut)
                    k += 1
                     
                log.info(banner('Waiting for 30 seconds before collecting the traffic stats:'))
                countDownTimer(30)
                 
                out = trigger_obj.checkAllStreamStats(tgn_hdl)
                traffic_obj.getAllBoundStreamStatistics(tgn_hdl)
                 
                flag = 0
                if not out:
                    log.error(banner('Traffic has not restored properly after the Trigger - DisablePIML2VNI'))
                    trigger_obj.backUpAndRestoreConfigs(list(device_dict.keys()),'restore')
                    flag = 1
                
                if flag:
                    log.error(banner('Traffic has not restored after the trigger:'))
                    traffic_obj.getAllBoundStreamStatistics(tgn_hdl)
                    self.failed()
 
            else:
                log.error('The Initial Traffic Condition did not pass:')
                traffic_obj.getAllBoundStreamStatistics(tgn_hdl)
                countDownTimer(180)
                self.failed() 
 
class VXLANL3TRMVPCBLFUNC016(aetest.Testcase):
 
    """ VPC Trigger - 2 -  VPC PORT CHANNEL FLAP -  SECONDARY"""
 
    uid = 'VXLAN-L3-TRM-VPC-BL-FUNC-016'
 
    @aetest.test
    def VxlanL3TRMSVPCBLVPCPoFlapSecondary(self,log,testscript,testbed):
        node_dict = testscript.parameters['node_dict']
        traffic_stream_dict = testscript.parameters['traffic_stream_dict'] 
        tg_interface_hdl_dict = testscript.parameters['tg_interface_hdl_dict']
        port_handle_dict = testscript.parameters['port_handle_dict']
        configdict = testscript.parameters['configdict'] 
        tgn_config_dict = configdict['TG']
        threshold = testscript.parameters['traffic_threshold'] 
        tgn_port_dut_mapping = testscript.parameters['tgn_port_dut_mapping']
        traffic_obj = testscript.parameters['traffic_obj']
        trigger_obj = testscript.parameters['trigger_obj']
        alias_intf_mapping = testscript.parameters['alias_intf_mapping']
         
        res = [node_dict['all_dut'][dut].configure('terminal session-timeout 0') for dut in node_dict['all_dut'] if re.search('uut', dut)]
         
        for TG in tgn_config_dict.keys():
            tgn_hdl = testscript.parameters['testbed_obj'].devices[TG]
            out = trigger_obj.checkAllStreamStats(tgn_hdl)
         
            if out:
                log.info(banner('Initial Traffic flow is as expected:'))
                traffic_obj.getAllBoundStreamStatistics(tgn_hdl)
                 
                log.info(banner('Taking Backup of configs on all the VTEPs:'))
                 
                device_dict = trigger_obj.getDeviceDict('vpc_vtep')
                 
                res = trigger_obj.backUpAndRestoreConfigs(list(device_dict.keys()),'backup')
                 
                vpc_vtep_dict = trigger_obj.getVPCSwitchhdl('details')
                 
                dut = vpc_vtep_dict['secondary']['dut']
                hdl = vpc_vtep_dict['secondary']['hdl']
                 
                out = hdl.execute('sh vpc brief  | xml')
                 
                s = BeautifulSoup(out)
                vpc_po = s.find('vpc-ifindex').string
                 
                log.info(banner('The value of vpc_po is : {0}'.format(vpc_po)))
                 
                k = 1
                while (k <= 10):
                    log.info(banner('***** Iteration # {0} ******'.format(k)))
                    log.info('Flapping the Interface {0} in dut {1}'.format(vpc_po,dut))
                    res = MyLib.my_utils.flapInterface(log,hdl,vpc_po,dut)
                    k += 1
                     
                log.info(banner('Waiting for 30 seconds before collecting the traffic stats:'))
                countDownTimer(30)
                 
                out = trigger_obj.checkAllStreamStats(tgn_hdl)
                traffic_obj.getAllBoundStreamStatistics(tgn_hdl)
                flag = 0
                if not out:
                    log.error(banner('Traffic has not restored properly after the Trigger - DisablePIML2VNI'))
                    trigger_obj.backUpAndRestoreConfigs(list(device_dict.keys()),'restore')
                    flag = 1
                
                if flag:
                    log.error(banner('Traffic has not restored after the trigger:'))
                    traffic_obj.getAllBoundStreamStatistics(tgn_hdl)
                    self.failed()
 
            else:
                log.error('The Initial Traffic Condition did not pass:')
                traffic_obj.getAllBoundStreamStatistics(tgn_hdl)
                countDownTimer(180)
                self.failed()  

class VXLANL3TRMVPCBLFUNC017(aetest.Testcase):
 
    """ Vlan-State-Change """
 
    uid = 'VXLAN-L3-TRM-VPC-BL-FUNC-017'
 
    @aetest.test
    def vlanStateChange(self,log,testscript,testbed):
        node_dict = testscript.parameters['node_dict']
        traffic_stream_dict = testscript.parameters['traffic_stream_dict'] 
        tg_interface_hdl_dict = testscript.parameters['tg_interface_hdl_dict']
        port_handle_dict = testscript.parameters['port_handle_dict']
        configdict = testscript.parameters['configdict'] 
        tgn_config_dict = configdict['TG']
        threshold = testscript.parameters['traffic_threshold'] 
        tgn_port_dut_mapping = testscript.parameters['tgn_port_dut_mapping']
        traffic_obj = testscript.parameters['traffic_obj']
        trigger_obj = testscript.parameters['trigger_obj']
        alias_intf_mapping = testscript.parameters['alias_intf_mapping']
         
        res = [node_dict['all_dut'][dut].configure('terminal session-timeout 0') for dut in node_dict['all_dut'] if re.search('uut', dut)]
         
        for TG in tgn_config_dict.keys():
            tgn_hdl = testscript.parameters['testbed_obj'].devices[TG]
            out = trigger_obj.checkAllStreamStats(tgn_hdl)
         
            if out:
                log.info(banner('Initial Traffic flow is as expected:'))
                traffic_obj.getAllBoundStreamStatistics(tgn_hdl)
                 
                log.info(banner('Taking Backup of configs on all the VTEPs:'))
                 
                device_dict = trigger_obj.getDeviceDict('all_vtep')
                 
                res = trigger_obj.backUpAndRestoreConfigs(list(device_dict.keys()),'backup')
                 
                svi_args = configdict['trigger_dict']['pim-enable-disable']['svi']
                ns = MyLib.my_config_utils.parseScaleSVIParams(log,svi_args)
                 
                log.info(banner('Shutting down Vlans on all the VTEPs'))
                 
                for dut in device_dict.keys():
                    for i in range(int(ns.l2_vni_svi_start), int(ns.l2_vni_svi_start)+int(ns.no_of_l2_vni_svi)):
                        log.info('**** Vlan State Change .. Shutting Vlan {0} on Dut {1}'.format(i,dut))
                        res = MyLib.my_utils.vlanOperations(log,node_dict['all_dut'][dut],dut,i,'shut')
                         
                log.info(banner('Waiting for 30 seconds before Unshutting the vlans'))
                countDownTimer(30)
                 
                log.info(banner('Unshutting the vlans on all the VTEPs'))
                 
                for dut in device_dict.keys():
                    for i in range(int(ns.l2_vni_svi_start), int(ns.l2_vni_svi_start)+int(ns.no_of_l2_vni_svi)):
                        log.info('**** Vlan State Change .. Shutting Vlan {0} on Dut {1}'.format(i,dut))
                        res = MyLib.my_utils.vlanOperations(log,node_dict['all_dut'][dut],dut,i,'unshut')
                         
                log.info(banner('Waiting for 180 seconds before collecting the stats:'))
                countDownTimer(180)
                 
                flag = 0
                out = trigger_obj.checkAllStreamStats(tgn_hdl)
                traffic_obj.getAllBoundStreamStatistics(tgn_hdl)
                 
                if not out:
                    log.error(banner('Traffic did not resume as expected..Traffic breakup is: '))
                    traffic_obj.getAllBoundStreamStatistics(tgn_hdl)
                    trigger_obj.backUpAndRestoreConfigs(list(device_dict.keys()),'restore')
                    countDownTimer(100)
                    flag = 1
                
                if flag:
                    log.error(banner('VPC Consitency Check is not working as expected. Refer Logss'))
                    traffic_obj.getAllBoundStreamStatistics(tgn_hdl)
                    self.failed()
 
            else:
                log.error('The Initial Traffic Condition did not pass:')
                traffic_obj.getAllBoundStreamStatistics(tgn_hdl)
                countDownTimer(180)
                self.failed()  

class VXLANL3TRMVPCBLFUNC018(aetest.Testcase):
 
    """ Vlan-Removal-Readd """
 
    uid = 'VXLAN-L3-TRM-VPC-BL-FUNC-018'
 
    @aetest.test
    def vlanRemovalAndAdd(self,log,testscript,testbed):
        node_dict = testscript.parameters['node_dict']
        traffic_stream_dict = testscript.parameters['traffic_stream_dict'] 
        tg_interface_hdl_dict = testscript.parameters['tg_interface_hdl_dict']
        port_handle_dict = testscript.parameters['port_handle_dict']
        configdict = testscript.parameters['configdict'] 
        tgn_config_dict = configdict['TG']
        threshold = testscript.parameters['traffic_threshold'] 
        tgn_port_dut_mapping = testscript.parameters['tgn_port_dut_mapping']
        traffic_obj = testscript.parameters['traffic_obj']
        trigger_obj = testscript.parameters['trigger_obj']
        alias_intf_mapping = testscript.parameters['alias_intf_mapping']
         
        res = [node_dict['all_dut'][dut].configure('terminal session-timeout 0') for dut in node_dict['all_dut'] if re.search('uut', dut)]
         
        for TG in tgn_config_dict.keys():
            tgn_hdl = testscript.parameters['testbed_obj'].devices[TG]
            out = trigger_obj.checkAllStreamStats(tgn_hdl)
         
            if out:
                log.info(banner('Initial Traffic flow is as expected:'))
                traffic_obj.getAllBoundStreamStatistics(tgn_hdl)
                 
                log.info(banner('Taking Backup of configs on all the VTEPs:'))
                 
                device_dict = trigger_obj.getDeviceDict('all_vtep')
                 
                res = trigger_obj.backUpAndRestoreConfigs(list(device_dict.keys()),'backup')
                 
                svi_args = configdict['trigger_dict']['pim-enable-disable']['svi']
                ns = MyLib.my_config_utils.parseScaleSVIParams(log,svi_args)
                 
                log.info(banner('Shutting down Vlans on all the VTEPs'))
                 
                for dut in device_dict.keys():
                    for i in range(int(ns.l2_vni_svi_start), int(ns.l2_vni_svi_start)+int(ns.no_of_l2_vni_svi)):
                        log.info('**** Vlan State Change .. Removing Vlan {0} on Dut {1}'.format(i,dut))
                        res = MyLib.my_utils.vlanOperations(log,node_dict['all_dut'][dut],dut,i,'remove')
                         
                log.info(banner('Waiting for 30 seconds before Unshutting the vlans'))
                countDownTimer(30)
                 
                log.info(banner('configuring  the vlans on all the VTEPs'))
                 
                res = trigger_obj.backUpAndRestoreConfigs(list(device_dict.keys()),'restore')
                         
                log.info(banner('Waiting for 180 seconds before collecting the stats:'))
                countDownTimer(180)
                 
                flag = 0
                out = trigger_obj.checkAllStreamStats(tgn_hdl)
                traffic_obj.getAllBoundStreamStatistics(tgn_hdl)
                 
                if not out:
                    log.error(banner('Traffic did not resume as expected..Traffic breakup is: '))
                    traffic_obj.getAllBoundStreamStatistics(tgn_hdl)
                    trigger_obj.backUpAndRestoreConfigs(list(device_dict.keys()),'restore')
                    countDownTimer(100)
                    flag = 1
                
                if flag:
                    log.error(banner('VPC Consitency Check is not working as expected. Refer Logss'))
                    traffic_obj.getAllBoundStreamStatistics(tgn_hdl)
                    self.failed()
 
            else:
                log.error('The Initial Traffic Condition did not pass:')
                traffic_obj.getAllBoundStreamStatistics(tgn_hdl)
                countDownTimer(180)
                self.failed()   


class VXLANL3TRMVPCBLFUNC019(aetest.Testcase):
 
    """ NVE Shut on VPC Primary """
 
    uid = 'VXLAN-L3-TRM-VPC-BL-FUNC-019'
 
    @aetest.test
    def nveShutPrimary(self,log,testscript,testbed):
        node_dict = testscript.parameters['node_dict']
        traffic_stream_dict = testscript.parameters['traffic_stream_dict'] 
        tg_interface_hdl_dict = testscript.parameters['tg_interface_hdl_dict']
        port_handle_dict = testscript.parameters['port_handle_dict']
        configdict = testscript.parameters['configdict'] 
        tgn_config_dict = configdict['TG']
        threshold = testscript.parameters['traffic_threshold'] 
        tgn_port_dut_mapping = testscript.parameters['tgn_port_dut_mapping']
        traffic_obj = testscript.parameters['traffic_obj']
        trigger_obj = testscript.parameters['trigger_obj']
        alias_intf_mapping = testscript.parameters['alias_intf_mapping']
         
        res = [node_dict['all_dut'][dut].configure('terminal session-timeout 0') for dut in node_dict['all_dut'] if re.search('uut', dut)]
         
        for TG in tgn_config_dict.keys():
            tgn_hdl = testscript.parameters['testbed_obj'].devices[TG]
            out = trigger_obj.checkAllStreamStats(tgn_hdl)
         
            if out:
                log.info(banner('Initial Traffic flow is as expected:'))
                traffic_obj.getAllBoundStreamStatistics(tgn_hdl)
                 
                log.info(banner('Taking Backup of configs on all the VTEPs:'))
                 
                device_dict = trigger_obj.getDeviceDict('vpc_vtep')
                 
                res = trigger_obj.backUpAndRestoreConfigs(list(device_dict.keys()),'backup')
                 
                vpc_vtep_dict = trigger_obj.getVPCSwitchhdl('details')
                 
                primary_dut = vpc_vtep_dict['primary']['dut']
                primary_hdl = vpc_vtep_dict['primary']['hdl']
                 
                log.info(banner('Flapping the NVE Interface on VPC Primary : {0}'.format(primary_dut)))
                 
                res = MyLib.my_utils.flapInterface(log,primary_hdl,'nve1',primary_dut)
                 
                log.info(banner('Waiting for 100 seconds before measuring the Traffic Stats: '))
                countDownTimer(100)
                 
                flag = 0
                out = trigger_obj.checkAllStreamStats(tgn_hdl)
                traffic_obj.getAllBoundStreamStatistics(tgn_hdl)
                 
                if not out:
                    log.error(banner('VPC Consitency Check is not working as expected.'))
                    traffic_obj.getAllBoundStreamStatistics(tgn_hdl)
                    trigger_obj.backUpAndRestoreConfigs(list(device_dict.keys()),'restore')
                    flag = 1
                
                if flag:
                    log.error(banner('VPC Consitency Check is not working as expected. Refer Logss'))
                    traffic_obj.getAllBoundStreamStatistics(tgn_hdl)
                    self.failed()
 
            else:
                log.error('The Initial Traffic Condition did not pass:')
                traffic_obj.getAllBoundStreamStatistics(tgn_hdl)
                countDownTimer(180)
                self.failed()  
                     
 
class VXLANL3TRMVPCBLFUNC020(aetest.Testcase):
 
    """ NVE Shut on VPC Secondary """
 
    uid = 'VXLAN-L3-TRM-VPC-BL-FUNC-020'
 
    @aetest.test
    def nveShutSecondary(self,log,testscript,testbed):
        node_dict = testscript.parameters['node_dict']
        traffic_stream_dict = testscript.parameters['traffic_stream_dict'] 
        tg_interface_hdl_dict = testscript.parameters['tg_interface_hdl_dict']
        port_handle_dict = testscript.parameters['port_handle_dict']
        configdict = testscript.parameters['configdict'] 
        tgn_config_dict = configdict['TG']
        threshold = testscript.parameters['traffic_threshold'] 
        tgn_port_dut_mapping = testscript.parameters['tgn_port_dut_mapping']
        traffic_obj = testscript.parameters['traffic_obj']
        trigger_obj = testscript.parameters['trigger_obj']
        alias_intf_mapping = testscript.parameters['alias_intf_mapping']
         
        res = [node_dict['all_dut'][dut].configure('terminal session-timeout 0') for dut in node_dict['all_dut'] if re.search('uut', dut)]
         
        for TG in tgn_config_dict.keys():
            tgn_hdl = testscript.parameters['testbed_obj'].devices[TG]
            out = trigger_obj.checkAllStreamStats(tgn_hdl)
         
            if out:
                log.info(banner('Initial Traffic flow is as expected:'))
                traffic_obj.getAllBoundStreamStatistics(tgn_hdl)
                 
                log.info(banner('Taking Backup of configs on all the VTEPs:'))
                 
                device_dict = trigger_obj.getDeviceDict('vpc_vtep')
                 
                res = trigger_obj.backUpAndRestoreConfigs(list(device_dict.keys()),'backup')
                 
                vpc_vtep_dict = trigger_obj.getVPCSwitchhdl('details')
                 
                secondary_dut = vpc_vtep_dict['secondary']['dut']
                secondary_hdl = vpc_vtep_dict['secondary']['hdl']
                 
                log.info(banner('Flapping the NVE Interface on VPC Secondary : {0}'.format(secondary_dut)))
                 
                res = MyLib.my_utils.flapInterface(log,secondary_hdl,'nve1',secondary_dut)
                 
                log.info(banner('Waiting for 100 seconds before measuring the Traffic Stats: '))
                countDownTimer(100)
                 
                flag = 0
                out = trigger_obj.checkAllStreamStats(tgn_hdl)
                traffic_obj.getAllBoundStreamStatistics(tgn_hdl)
                 
                if not out:
                    log.error(banner('Traffic Flow is not working as expected.'))
                    traffic_obj.getAllBoundStreamStatistics(tgn_hdl)
                    trigger_obj.backUpAndRestoreConfigs(list(device_dict.keys()),'restore')
                    flag = 1
                
                if flag:
                    log.error(banner('Traffic Flow is not working as expected. Refer Logss'))
                    traffic_obj.getAllBoundStreamStatistics(tgn_hdl)
                    self.failed()
 
            else:
                log.error('The Initial Traffic Condition did not pass:')
                traffic_obj.getAllBoundStreamStatistics(tgn_hdl)
                countDownTimer(180)
                self.failed()                          

class VXLANL3TRMVPCBLFUNC021(aetest.Testcase):
 
    """ NVE Source IP Change """
 
    uid = 'VXLAN-L3-TRM-VPC-BL-FUNC-021'
 
    @aetest.test
    def modifyNveSourceIP(self,log,testscript,testbed):
        node_dict = testscript.parameters['node_dict']
        traffic_stream_dict = testscript.parameters['traffic_stream_dict'] 
        tg_interface_hdl_dict = testscript.parameters['tg_interface_hdl_dict']
        port_handle_dict = testscript.parameters['port_handle_dict']
        configdict = testscript.parameters['configdict'] 
        tgn_config_dict = configdict['TG']
        threshold = testscript.parameters['traffic_threshold'] 
        tgn_port_dut_mapping = testscript.parameters['tgn_port_dut_mapping']
        traffic_obj = testscript.parameters['traffic_obj']
        trigger_obj = testscript.parameters['trigger_obj']
        alias_intf_mapping = testscript.parameters['alias_intf_mapping']
         
        res = [node_dict['all_dut'][dut].configure('terminal session-timeout 0') for dut in node_dict['all_dut'] if re.search('uut', dut)]
         
        verify_obj = MyLib.my_config_utils.VerifyConfigs(log,configdict,node_dict,alias_intf_mapping)
         
        for TG in tgn_config_dict.keys():
            tgn_hdl = testscript.parameters['testbed_obj'].devices[TG]
            out = trigger_obj.checkAllStreamStats(tgn_hdl)
         
            if out:
                log.info(banner('Initial Traffic flow is as expected:'))
                traffic_obj.getAllBoundStreamStatistics(tgn_hdl)
                 
                log.info(banner('Taking Backup of configs on all the VTEPs:'))
                 
                vpc_device_dict = trigger_obj.getDeviceDict('vpc_vtep')
                stand_vtep_dict = trigger_obj.getDeviceDict('stand_vtep')
                vtep_dict = trigger_obj.getDeviceDict('all_vtep')
                 
                res = trigger_obj.backUpAndRestoreConfigs(list(vtep_dict.keys()),'backup')
                 
                standby_ip_addr_list = MyLib.my_config_utils.ipaddrgen(2,'71.1.1.1',24)
                log.info(banner('The value of ip_addr_list is : {0}'.format(standby_ip_addr_list)))
                 
                log.info(banner('Chaning the Nve source interface on VPC SWitches:::'))
                 
                for dut in vpc_device_dict.keys():
                    log.info(banner('Changing the NVE source interface IP on dut {0}'.format(dut)))
                     
                    node_dict['all_dut'][dut].configure('interface nve 1 ;  shutdown')
                    loop_cfg = '''interface loopback 0
                                  ip addres 61.62.61.62/32 secondary'''
                    output = node_dict['all_dut'][dut].execute('show run int loopback 0')
                    for line in output.splitlines():
                        if re.search('secondary',line):
                            cfg = '''interface loopback 0
                                     no {0}'''.format(line)
                            node_dict['all_dut'][dut].configure(cfg)
                    node_dict['all_dut'][dut].configure(loop_cfg)
                    node_dict['all_dut'][dut].configure('interface nve 1 ; no shutdown')
                 
                log.info(banner('Chaning the Nve source interface on StandAlone VTEP SWitches:::'))   
                for i,dut in enumerate(stand_vtep_dict.keys()):
                    log.info(banner('Changing the nve source interface IP on dut {0}'.format(dut)))
                    node_dict['all_dut'][dut].configure('interface nve 1 ;  shutdown')
                    loop_cfg = '''interface loopback 0
                                  ip address {0}/32'''.format(standby_ip_addr_list[i])
                    node_dict['all_dut'][dut].configure(loop_cfg)
                    node_dict['all_dut'][dut].configure('interface nve 1 ; no shutdown')
                 
                log.info(banner('Waiting for 240 seconds before Checking the Nve Peers:')) 
                countDownTimer(240)
                 
                res = verify_obj.verifyNVEStatus(vtep_dict)
                 
                flag = 0
                if not res:
                    log.info(banner('Some of the NVE Peer did not come up....'))
                    flag = 1
                 
                if not flag:
                    out = trigger_obj.checkAllStreamStats(tgn_hdl)
                    traffic_obj.getAllBoundStreamStatistics(tgn_hdl)
                 
                    if not out:
                        log.error(banner('Traffic Flow is not working as expected After changing the source Intf IP.'))
                        traffic_obj.getAllBoundStreamStatistics(tgn_hdl)
                        trigger_obj.backUpAndRestoreConfigs(list(vtep_dict.keys()),'restore')
                        flag = 2
                     
                    else:
                        log.info(banner('Traffic flow is as expected After NVe Source I/F IP Change: '))
                        traffic_obj.getAllBoundStreamStatistics(tgn_hdl)
                     
                log.info(banner('Reverting back the configs:'))
                res = trigger_obj.backUpAndRestoreConfigs(list(vtep_dict.keys()),'restore')
                 
                log.info(banner('Waiting for 100 seconds before starting the Traffic...'))
                countDownTimer(100)
                 
                out = trigger_obj.checkAllStreamStats(tgn_hdl)
                traffic_obj.getAllBoundStreamStatistics(tgn_hdl)
                 
                if not out:
                    log.error(banner('Traffic Flow is not working as expected After reverting the source Intf IP.'))
                    traffic_obj.getAllBoundStreamStatistics(tgn_hdl)
                    self.failed()
                
                if flag == 1:
                    log.error(banner('Trigger: NVE Source IP Change : Fail Reason: Peer did not come up..'))
                    res = trigger_obj.backUpAndRestoreConfigs(list(vtep_dict.keys()),'restore')
                    self.failed()
                     
                if flag == 2:
                    log.error(banner('Trigger : Nve Source IP Change: Fail Reason: Traffic flow failed ..'))
                    self.failed()                
 
            else:
                log.error('The Initial Traffic Condition did not pass:')
                traffic_obj.getAllBoundStreamStatistics(tgn_hdl)
                countDownTimer(180)
                self.failed()  


class VXLANL3TRMVPCBLFUNC022(aetest.Testcase):
 
    """ NVE Source Interface Change"""
 
    uid = 'VXLAN-L3-TRM-VPC-BL-FUNC-022'
 
    @aetest.test
    def modifyNveSourceInterface(self,log,testscript,testbed):
        node_dict = testscript.parameters['node_dict']
        traffic_stream_dict = testscript.parameters['traffic_stream_dict'] 
        tg_interface_hdl_dict = testscript.parameters['tg_interface_hdl_dict']
        port_handle_dict = testscript.parameters['port_handle_dict']
        configdict = testscript.parameters['configdict'] 
        tgn_config_dict = configdict['TG']
        threshold = testscript.parameters['traffic_threshold'] 
        tgn_port_dut_mapping = testscript.parameters['tgn_port_dut_mapping']
        traffic_obj = testscript.parameters['traffic_obj']
        trigger_obj = testscript.parameters['trigger_obj']
        alias_intf_mapping = testscript.parameters['alias_intf_mapping']
         
        res = [node_dict['all_dut'][dut].configure('terminal session-timeout 0') for dut in node_dict['all_dut'] if re.search('uut', dut)]
         
        verify_obj = MyLib.my_config_utils.VerifyConfigs(log,configdict,node_dict,alias_intf_mapping)
         
        for TG in tgn_config_dict.keys():
            tgn_hdl = testscript.parameters['testbed_obj'].devices[TG]
            out = trigger_obj.checkAllStreamStats(tgn_hdl)
         
            if out:
                log.info(banner('Initial Traffic flow is as expected:'))
                traffic_obj.getAllBoundStreamStatistics(tgn_hdl)
                 
                log.info(banner('Taking Backup of configs on all the VTEPs:'))
                 
                vpc_device_dict = trigger_obj.getDeviceDict('vpc_vtep')
                stand_vtep_dict = trigger_obj.getDeviceDict('stand_vtep')
                vtep_dict = trigger_obj.getDeviceDict('all_vtep')
                 
                res = trigger_obj.backUpAndRestoreConfigs(list(vtep_dict.keys()),'backup')
                 
                vpc_ip_addr_list = MyLib.my_config_utils.ipaddrgen(2,'71.1.1.1',24)
                log.info(banner('The value of ip_addr_list is : {0}'.format(vpc_ip_addr_list)))
                 
                standalone_ip_addr_list = MyLib.my_config_utils.ipaddrgen(2,'91.1.1.1',24)
                log.info(banner('The value of ip_addr_list is : {0}'.format(standalone_ip_addr_list)))
                 
                log.info(banner('Chaning the Nve source interface on VPC SWitches:::'))
                 
                for i,dut in enumerate(vpc_device_dict.keys()):
                    log.info(banner('Changing the NVE source interface IP on dut {0}'.format(dut)))
                     
                    nve_cfg = '''interface nve 1 
                                 shutdown
                                 no source-interface
                                 source-interface loopback 1001
                                 no shutdown'''
                    loop_cfg = '''interface loopback 1001
                                  ip addres {0}/32
                                  ip address 71.72.71.72/32 secondary
                                  ip router ospf vxlan area 0
                                  ip pim sparse-mode'''.format(vpc_ip_addr_list[i])
                    node_dict['all_dut'][dut].configure(loop_cfg)
                    node_dict['all_dut'][dut].configure(nve_cfg)
                 
                log.info(banner('Chaning the Nve source interface on StandAlone VTEP SWitches:::'))  
                  
                for j,dut in enumerate(stand_vtep_dict.keys()):
                    log.info(banner('Changing the NVE source interface IP on dut {0}'.format(dut)))
                    nve_cfg = '''interface nve 1 
                                 shutdown
                                 no source-interface
                                 source-interface loopback 1001
                                 no shutdown'''
                    loop_cfg = '''interface loopback 1001
                                  ip address {0}/32
                                  ip router ospf vxlan area 0
                                  ip pim sparse-mode'''.format(standalone_ip_addr_list[j])
                    node_dict['all_dut'][dut].configure(loop_cfg)
                    node_dict['all_dut'][dut].configure(nve_cfg)
                 
                log.info(banner('Waiting for 100 seconds before Checking the Nve Peers:')) 
                countDownTimer(100)
                 
                res = verify_obj.verifyNVEStatus(vtep_dict)
                 
                flag = 0
                if not res:
                    log.info(banner('Some of the NVE Peer did not come up....'))
                    flag = 1
                 
                if not flag:
                    out = trigger_obj.checkAllStreamStats(tgn_hdl)
                    traffic_obj.getAllBoundStreamStatistics(tgn_hdl)
                 
                    if not out:
                        log.error(banner('Traffic Flow is not working as expected After changing the source Intf IP.'))
                        traffic_obj.getAllBoundStreamStatistics(tgn_hdl)
                        trigger_obj.backUpAndRestoreConfigs(list(vtep_dict.keys()),'restore')
                        flag = 2
                     
                    else:
                        log.info(banner('Traffic flow is as expected After NVe Source I/F IP Change: '))
                        traffic_obj.getAllBoundStreamStatistics(tgn_hdl)
                     
                log.info(banner('Reverting back the configs:'))
                res = trigger_obj.backUpAndRestoreConfigs(list(vtep_dict.keys()),'restore')
                 
                log.info(banner('Waiting for 100 seconds before starting the Traffic...'))
                countDownTimer(100)
                 
                out = trigger_obj.checkAllStreamStats(tgn_hdl)
                traffic_obj.getAllBoundStreamStatistics(tgn_hdl)
                 
                if not out:
                    log.error(banner('Traffic Flow is not working as expected After reverting the source Intf IP.'))
                    traffic_obj.getAllBoundStreamStatistics(tgn_hdl)
                    self.failed()
                
                if flag == 1:
                    log.error(banner('Trigger: NVE Source IP Change : Fail Reason: Peer did not come up..'))
                    res = trigger_obj.backUpAndRestoreConfigs(list(vtep_dict.keys()),'restore')
                    self.failed()
                     
                if flag == 2:
                    log.error(banner('Trigger : Nve Source IP Change: Fail Reason: Traffic flow failed ..'))
                    self.failed()                
 
            else:
                log.error('The Initial Traffic Condition did not pass:')
                traffic_obj.getAllBoundStreamStatistics(tgn_hdl)
                countDownTimer(180)
                self.failed()  

class VXLANL3TRMVPCBLFUNC023(aetest.Testcase):
 
    """ Shut NVE Uplink Interfaces - Primary"""
 
    uid = 'VXLAN-L3-TRM-VPC-BL-FUNC-023'
 
    @aetest.test
    def shutNVEUplinkPrimary(self,log,testscript,testbed):
        node_dict = testscript.parameters['node_dict']
        traffic_stream_dict = testscript.parameters['traffic_stream_dict'] 
        tg_interface_hdl_dict = testscript.parameters['tg_interface_hdl_dict']
        port_handle_dict = testscript.parameters['port_handle_dict']
        configdict = testscript.parameters['configdict'] 
        tgn_config_dict = configdict['TG']
        threshold = testscript.parameters['traffic_threshold'] 
        tgn_port_dut_mapping = testscript.parameters['tgn_port_dut_mapping']
        traffic_obj = testscript.parameters['traffic_obj']
        trigger_obj = testscript.parameters['trigger_obj']
        alias_intf_mapping = testscript.parameters['alias_intf_mapping']
         
        res = [node_dict['all_dut'][dut].configure('terminal session-timeout 0') for dut in node_dict['all_dut'] if re.search('uut', dut)]
         
        for TG in tgn_config_dict.keys():
            tgn_hdl = testscript.parameters['testbed_obj'].devices[TG]
            out = trigger_obj.checkAllStreamStats(tgn_hdl)
         
            if out:
                log.info(banner('Initial Traffic flow is as expected:'))
                traffic_obj.getAllBoundStreamStatistics(tgn_hdl)
                 
                log.info(banner('Taking Backup of configs on all the VTEPs:'))
                 
                device_dict = trigger_obj.getDeviceDict('vpc_vtep')
                 
                res = trigger_obj.backUpAndRestoreConfigs(list(device_dict.keys()),'backup')
                 
                vpc_vtep_dict = trigger_obj.getVPCSwitchhdl('details')
                 
                primary_dut = vpc_vtep_dict['primary']['dut']
                primary_hdl = vpc_vtep_dict['primary']['hdl']
                 
                 
                log.info(banner('Shutting down the Uplink on Primary: {0}'.format(primary_dut)))
                out = primary_hdl.execute('show nve peers | xml')
                s = BeautifulSoup(out)
                peer_ip = s.find('peer-ip').string
                out1 = primary_hdl.execute('show ip route {0} | json'.format(peer_ip))
                t = json.loads(out1)
                uplink_port = []
                for intf in t['TABLE_vrf']['ROW_vrf']['TABLE_addrf']['ROW_addrf']['TABLE_prefix']['ROW_prefix']['TABLE_path']['ROW_path']:
                    uplink_port.append(intf['ifname'])
                 
                log.info('The value of Uplink Port is : {0}'.format(uplink_port))
                 
                for intf in uplink_port:
                    log.info(banner('Shutting down Interface {0} on dut {1}'.format(intf,primary_dut)))
                    res = MyLib.my_utils.shutDownInterface(log,primary_hdl,intf,primary_dut)
 
                 
                log.info(banner('Waiting for 180 seconds before collecting the Traffic Stats: '))
                countDownTimer(180)
                 
                out = trigger_obj.checkAllStreamStats(tgn_hdl)
                 
                flag = 0
                if out:
                    log.info(banner('Traffic is as expected. ....Traffic STream breakup is : '))
                    traffic_obj.getAllBoundStreamStatistics(tgn_hdl)
                 
                else:
                    log.error(banner('Traffic drop was not as expected. But Seen. Traffic Break up is : '))
                    traffic_obj.getAllBoundStreamStatistics(tgn_hdl)
                    flag = 1
                     
                log.info(banner('Reverting back the configs:'))
                res = trigger_obj.backUpAndRestoreConfigs(list(device_dict.keys()),'restore')
                 
                log.info(banner('Waiting for 60 seconds before collecting the Traffic stats..'))
                countDownTimer(60)
                     
                out = trigger_obj.checkAllStreamStats(tgn_hdl)
                traffic_obj.getAllBoundStreamStatistics(tgn_hdl)
                 
                if not out:
                    log.error(banner('Traffic Drop was seen after reverting to Original configs.'))
                    traffic_obj.getAllBoundStreamStatistics(tgn_hdl)
                    trigger_obj.backUpAndRestoreConfigs(list(device_dict.keys()),'restore')
                    flag = 1
                
                if flag:
                    log.error(banner('Traffic was not as expected. Refer Logs.'))
                    self.failed()
 
            else:
                log.error('The Initial Traffic Condition did not pass:')
                traffic_obj.getAllBoundStreamStatistics(tgn_hdl)
                countDownTimer(180)
                self.failed()  
                               
class VXLANL3TRMVPCBLFUNC024(aetest.Testcase):
 
    """ Shut NVE Uplink Interfaces - Secondary"""
 
    uid = 'VXLAN-L3-TRM-VPC-BL-FUNC-024'
 
    @aetest.test
    def shutNVEUplinkSecondary(self,log,testscript,testbed):
        node_dict = testscript.parameters['node_dict']
        traffic_stream_dict = testscript.parameters['traffic_stream_dict'] 
        tg_interface_hdl_dict = testscript.parameters['tg_interface_hdl_dict']
        port_handle_dict = testscript.parameters['port_handle_dict']
        configdict = testscript.parameters['configdict'] 
        tgn_config_dict = configdict['TG']
        threshold = testscript.parameters['traffic_threshold'] 
        tgn_port_dut_mapping = testscript.parameters['tgn_port_dut_mapping']
        traffic_obj = testscript.parameters['traffic_obj']
        trigger_obj = testscript.parameters['trigger_obj']
        alias_intf_mapping = testscript.parameters['alias_intf_mapping']
         
        res = [node_dict['all_dut'][dut].configure('terminal session-timeout 0') for dut in node_dict['all_dut'] if re.search('uut', dut)]
         
        for TG in tgn_config_dict.keys():
            tgn_hdl = testscript.parameters['testbed_obj'].devices[TG]
            out = trigger_obj.checkAllStreamStats(tgn_hdl)
         
            if out:
                log.info(banner('Initial Traffic flow is as expected:'))
                traffic_obj.getAllBoundStreamStatistics(tgn_hdl)
                 
                log.info(banner('Taking Backup of configs on all the VTEPs:'))
                 
                device_dict = trigger_obj.getDeviceDict('vpc_vtep')
                 
                res = trigger_obj.backUpAndRestoreConfigs(list(device_dict.keys()),'backup')
                 
                vpc_vtep_dict = trigger_obj.getVPCSwitchhdl('details')
                 
                secondary_dut = vpc_vtep_dict['secondary']['dut']
                secondary_hdl = vpc_vtep_dict['secondary']['hdl']
                 
                 
                log.info(banner('Shutting down the Uplink on secondary: {0}'.format(secondary_dut)))
                out = secondary_hdl.execute('show nve peers | xml')
                s = BeautifulSoup(out)
                peer_ip = s.find('peer-ip').string
                out1 = secondary_hdl.execute('show ip route {0} | json'.format(peer_ip))
                t = json.loads(out1)
                uplink_port = []
                for intf in t['TABLE_vrf']['ROW_vrf']['TABLE_addrf']['ROW_addrf']['TABLE_prefix']['ROW_prefix']['TABLE_path']['ROW_path']:
                    uplink_port.append(intf['ifname'])
                 
                log.info('The value of Uplink Port is : {0}'.format(uplink_port))
                 
                for intf in uplink_port:
                    log.info(banner('Shutting down Interface {0} on dut {1}'.format(intf,secondary_dut)))
                    res = MyLib.my_utils.shutDownInterface(log,secondary_hdl,intf,secondary_dut)
 
                 
                log.info(banner('Waiting for 180 seconds before collecting the Traffic Stats: '))
                countDownTimer(180)
                 
                out = trigger_obj.checkAllStreamStats(tgn_hdl)
                 
                flag = 0
                if out:
                    log.info(banner('Traffic is as expected. ....Traffic STream breakup is : '))
                    traffic_obj.getAllBoundStreamStatistics(tgn_hdl)
                 
                else:
                    log.error(banner('Traffic drop was not as expected. But Seen. Traffic Break up is : '))
                    traffic_obj.getAllBoundStreamStatistics(tgn_hdl)
                    flag = 1
                     
                log.info(banner('Reverting back the configs:'))
                res = trigger_obj.backUpAndRestoreConfigs(list(device_dict.keys()),'restore')
                 
                log.info(banner('Waiting for 60 seconds before collecting the Traffic stats..'))
                countDownTimer(60)
                     
                out = trigger_obj.checkAllStreamStats(tgn_hdl)
                traffic_obj.getAllBoundStreamStatistics(tgn_hdl)
                 
                if not out:
                    log.error(banner('Traffic Drop was seen after reverting to Original configs.'))
                    traffic_obj.getAllBoundStreamStatistics(tgn_hdl)
                    trigger_obj.backUpAndRestoreConfigs(list(device_dict.keys()),'restore')
                    flag = 1
                
                if flag:
                    log.error(banner('Traffic was not as expected. Refer Logs.'))
                    self.failed()
 
            else:
                log.error('The Initial Traffic Condition did not pass:')
                traffic_obj.getAllBoundStreamStatistics(tgn_hdl)
                countDownTimer(180)
                self.failed()  
 
class VXLANL3TRMVPCBLFUNC025(aetest.Testcase):
 
    """ Flap NVE Uplink Interfaces - Primary"""
 
    uid = 'VXLAN-L3-TRM-VPC-BL-FUNC-025'
 
    @aetest.test
    def flapNVEUplinks(self,log,testscript,testbed):
        node_dict = testscript.parameters['node_dict']
        traffic_stream_dict = testscript.parameters['traffic_stream_dict'] 
        tg_interface_hdl_dict = testscript.parameters['tg_interface_hdl_dict']
        port_handle_dict = testscript.parameters['port_handle_dict']
        configdict = testscript.parameters['configdict'] 
        tgn_config_dict = configdict['TG']
        threshold = testscript.parameters['traffic_threshold'] 
        tgn_port_dut_mapping = testscript.parameters['tgn_port_dut_mapping']
        traffic_obj = testscript.parameters['traffic_obj']
        trigger_obj = testscript.parameters['trigger_obj']
        alias_intf_mapping = testscript.parameters['alias_intf_mapping']
         
        res = [node_dict['all_dut'][dut].configure('terminal session-timeout 0') for dut in node_dict['all_dut'] if re.search('uut', dut)]
         
        for TG in tgn_config_dict.keys():
            tgn_hdl = testscript.parameters['testbed_obj'].devices[TG]
            out = trigger_obj.checkAllStreamStats(tgn_hdl)
         
            if out:
                log.info(banner('Initial Traffic flow is as expected:'))
                traffic_obj.getAllBoundStreamStatistics(tgn_hdl)
                 
                log.info(banner('Taking Backup of configs on all the VTEPs:'))
                 
                device_dict = trigger_obj.getDeviceDict('vpc_vtep')
                 
                res = trigger_obj.backUpAndRestoreConfigs(list(device_dict.keys()),'backup')
                 
                vpc_vtep_dict = trigger_obj.getVPCSwitchhdl('details')
                 
                primary_dut = vpc_vtep_dict['primary']['dut']
                primary_hdl = vpc_vtep_dict['primary']['hdl']
                 
                 
                log.info(banner('Shutting down the Uplink on Primary: {0}'.format(primary_dut)))
                out = primary_hdl.execute('show nve peers | xml')
                s = BeautifulSoup(out)
                peer_ip = s.find('peer-ip').string
                out1 = primary_hdl.execute('show ip route {0} | json'.format(peer_ip))
                t = json.loads(out1)
                uplink_port = []
                for intf in t['TABLE_vrf']['ROW_vrf']['TABLE_addrf']['ROW_addrf']['TABLE_prefix']['ROW_prefix']['TABLE_path']['ROW_path']:
                    uplink_port.append(intf['ifname'])
                 
                log.info('The value of Uplink Port is : {0}'.format(uplink_port))
                 
                for intf in uplink_port:
                    log.info(banner('Shutting down Interface {0} on dut {1}'.format(intf,primary_dut)))
                    res = MyLib.my_utils.flapInterface(log,primary_hdl,intf,primary_dut)
 
                 
                log.info(banner('Waiting for 30 seconds before collecting the Traffic Stats: '))
                countDownTimer(30)
                 
                out = trigger_obj.checkAllStreamStats(tgn_hdl)
                 
                flag = 0
                if out:
                    log.info(banner('Traffic is as expected. ....Traffic STream breakup is : '))
                    traffic_obj.getAllBoundStreamStatistics(tgn_hdl)
                 
                else:
                    log.error(banner('Traffic drop was not as expected. But Seen. Traffic Break up is : '))
                    traffic_obj.getAllBoundStreamStatistics(tgn_hdl)
                    flag = 1
                     
                log.info(banner('Reverting back the configs:'))
                res = trigger_obj.backUpAndRestoreConfigs(list(device_dict.keys()),'restore')
                 
                log.info(banner('Waiting for 60 seconds before collecting the Traffic stats..'))
                countDownTimer(60)
                     
                out = trigger_obj.checkAllStreamStats(tgn_hdl)
                traffic_obj.getAllBoundStreamStatistics(tgn_hdl)
                 
                if not out:
                    log.error(banner('Traffic Drop was seen after reverting to Original configs.'))
                    traffic_obj.getAllBoundStreamStatistics(tgn_hdl)
                    trigger_obj.backUpAndRestoreConfigs(list(device_dict.keys()),'restore')
                    flag = 1
                
                if flag:
                    log.error(banner('Traffic was not as expected. Refer Logs.'))
                    self.failed()
 
            else:
                log.error('The Initial Traffic Condition did not pass:')
                traffic_obj.getAllBoundStreamStatistics(tgn_hdl)
                countDownTimer(180)
                self.failed() 
 
class VXLANL3TRMVPCBLFUNC026(aetest.Testcase):
 
    """ Flap NVE Uplink Interfaces - Secondary"""
 
    uid = 'VXLAN-L3-TRM-VPC-BL-FUNC-026'
 
    @aetest.test
    def flapNVEUplinksOnSecondary(self,log,testscript,testbed):
        node_dict = testscript.parameters['node_dict']
        traffic_stream_dict = testscript.parameters['traffic_stream_dict'] 
        tg_interface_hdl_dict = testscript.parameters['tg_interface_hdl_dict']
        port_handle_dict = testscript.parameters['port_handle_dict']
        configdict = testscript.parameters['configdict'] 
        tgn_config_dict = configdict['TG']
        threshold = testscript.parameters['traffic_threshold'] 
        tgn_port_dut_mapping = testscript.parameters['tgn_port_dut_mapping']
        traffic_obj = testscript.parameters['traffic_obj']
        trigger_obj = testscript.parameters['trigger_obj']
        alias_intf_mapping = testscript.parameters['alias_intf_mapping']
         
        res = [node_dict['all_dut'][dut].configure('terminal session-timeout 0') for dut in node_dict['all_dut'] if re.search('uut', dut)]
         
        for TG in tgn_config_dict.keys():
            tgn_hdl = testscript.parameters['testbed_obj'].devices[TG]
            out = trigger_obj.checkAllStreamStats(tgn_hdl)
         
            if out:
                log.info(banner('Initial Traffic flow is as expected:'))
                traffic_obj.getAllBoundStreamStatistics(tgn_hdl)
                 
                log.info(banner('Taking Backup of configs on all the VTEPs:'))
                 
                device_dict = trigger_obj.getDeviceDict('vpc_vtep')
                 
                res = trigger_obj.backUpAndRestoreConfigs(list(device_dict.keys()),'backup')
                 
                vpc_vtep_dict = trigger_obj.getVPCSwitchhdl('details')
                 
                secondary_dut = vpc_vtep_dict['secondary']['dut']
                secondary_hdl = vpc_vtep_dict['secondary']['hdl']
                 
                 
                log.info(banner('Shutting down the Uplink on Secondary: {0}'.format(secondary_dut)))
                out = secondary_hdl.execute('show nve peers | xml')
                s = BeautifulSoup(out)
                peer_ip = s.find('peer-ip').string
                out1 = secondary_hdl.execute('show ip route {0} | json'.format(peer_ip))
                t = json.loads(out1)
                uplink_port = []
                for intf in t['TABLE_vrf']['ROW_vrf']['TABLE_addrf']['ROW_addrf']['TABLE_prefix']['ROW_prefix']['TABLE_path']['ROW_path']:
                    uplink_port.append(intf['ifname'])
                 
                log.info('The value of Uplink Port is : {0}'.format(uplink_port))
                 
                for intf in uplink_port:
                    log.info(banner('Shutting down Interface {0} on dut {1}'.format(intf,secondary_dut)))
                    res = MyLib.my_utils.flapInterface(log,secondary_hdl,intf,secondary_dut)
 
                 
                log.info(banner('Waiting for 30 seconds before collecting the Traffic Stats: '))
                countDownTimer(30)
                 
                out = trigger_obj.checkAllStreamStats(tgn_hdl)
                 
                flag = 0
                if out:
                    log.info(banner('Traffic is as expected. ....Traffic STream breakup is : '))
                    traffic_obj.getAllBoundStreamStatistics(tgn_hdl)
                 
                else:
                    log.error(banner('Traffic drop was not as expected. But Seen. Traffic Break up is : '))
                    traffic_obj.getAllBoundStreamStatistics(tgn_hdl)
                    flag = 1
                     
                log.info(banner('Reverting back the configs:'))
                res = trigger_obj.backUpAndRestoreConfigs(list(device_dict.keys()),'restore')
                 
                log.info(banner('Waiting for 60 seconds before collecting the Traffic stats..'))
                countDownTimer(60)
                     
                out = trigger_obj.checkAllStreamStats(tgn_hdl)
                traffic_obj.getAllBoundStreamStatistics(tgn_hdl)
                 
                if not out:
                    log.error(banner('Traffic Drop was seen after reverting to Original configs.'))
                    traffic_obj.getAllBoundStreamStatistics(tgn_hdl)
                    trigger_obj.backUpAndRestoreConfigs(list(device_dict.keys()),'restore')
                    flag = 1
                
                if flag:
                    log.error(banner('Traffic was not as expected. Refer Logs.'))
                    self.failed()
 
            else:
                log.error('The Initial Traffic Condition did not pass:')
                traffic_obj.getAllBoundStreamStatistics(tgn_hdl)
                countDownTimer(180)
                self.failed() 

class VXLANL3TRMVPCBLFUNC027(aetest.Testcase):
 
    """ Flap VRF-Lite Uplink Interfaces - Primary"""
 
    uid = 'VXLAN-L3-TRM-VPC-BL-FUNC-027'
 
    @aetest.test
    def flapVRFLiteUplinksOnPrimary(self,log,testscript,testbed):
        node_dict = testscript.parameters['node_dict']
        traffic_stream_dict = testscript.parameters['traffic_stream_dict'] 
        tg_interface_hdl_dict = testscript.parameters['tg_interface_hdl_dict']
        port_handle_dict = testscript.parameters['port_handle_dict']
        configdict = testscript.parameters['configdict'] 
        tgn_config_dict = configdict['TG']
        threshold = testscript.parameters['traffic_threshold'] 
        tgn_port_dut_mapping = testscript.parameters['tgn_port_dut_mapping']
        traffic_obj = testscript.parameters['traffic_obj']
        trigger_obj = testscript.parameters['trigger_obj']
        alias_intf_mapping = testscript.parameters['alias_intf_mapping']
        testbed_obj = testscript.parameters['testbed_obj']
         
        res = [node_dict['all_dut'][dut].configure('terminal session-timeout 0') for dut in node_dict['all_dut'] if re.search('uut', dut)]
         
        for TG in tgn_config_dict.keys():
            tgn_hdl = testscript.parameters['testbed_obj'].devices[TG]
            out = trigger_obj.checkAllStreamStats(tgn_hdl)
         
            if out:
                log.info(banner('Initial Traffic flow is as expected:'))
                traffic_obj.getAllBoundStreamStatistics(tgn_hdl)
                 
                log.info(banner('Taking Backup of configs on all the VTEPs:'))
                 
                device_dict = trigger_obj.getDeviceDict('vpc_vtep')
                 
                res = trigger_obj.backUpAndRestoreConfigs(list(device_dict.keys()),'backup')
                 
                vpc_vtep_dict = trigger_obj.getVPCSwitchhdl('details')
                 
                primary_dut = vpc_vtep_dict['primary']['dut']
                primary_hdl = vpc_vtep_dict['primary']['hdl']
                
                for node in testbed_obj.devices:
                    if re.search('EXTERNAL',testbed_obj.devices[node].type):
                        vrf_lite_dut = testbed_obj.devices[node].alias
                
                for intf in alias_intf_mapping[primary_dut]:
                    if re.search(vrf_lite_dut,intf):
                        intf1 = alias_intf_mapping[primary_dut][intf]
                        log.info(banner('The Interface to Shut is : {0}'.format(intf1)))
                        
                log.info(banner('Shutting down the interface {0} on dut {1}'.format(intf1,primary_dut)))
                        
                res = MyLib.my_utils.shutDownInterface(log,primary_hdl,intf1,primary_dut)
                
                log.info(banner('Waiting for 30 seconds before measuring Traffic Stats:'))
                countDownTimer(30)
                 
                out = trigger_obj.checkAllStreamStats(tgn_hdl)
                 
                flag = 0
                if out:
                    log.info(banner('Traffic is as expected. ....Traffic STream breakup is : '))
                    traffic_obj.getAllBoundStreamStatistics(tgn_hdl)
                 
                else:
                    log.error(banner('Traffic drop was not as expected. But Seen. Traffic Break up is : '))
                    traffic_obj.getAllBoundStreamStatistics(tgn_hdl)
                    flag = 1
                     
                log.info(banner('Reverting back the configs:'))
                res = trigger_obj.backUpAndRestoreConfigs(list(device_dict.keys()),'restore')
                 
                log.info(banner('Waiting for 60 seconds before collecting the Traffic stats..'))
                countDownTimer(60)
                     
                out = trigger_obj.checkAllStreamStats(tgn_hdl)
                traffic_obj.getAllBoundStreamStatistics(tgn_hdl)
                 
                if not out:
                    log.error(banner('Traffic Drop was seen after reverting to Original configs.'))
                    traffic_obj.getAllBoundStreamStatistics(tgn_hdl)
                    trigger_obj.backUpAndRestoreConfigs(list(device_dict.keys()),'restore')
                    flag = 1
                
                if flag:
                    log.error(banner('Traffic was not as expected. Refer Logs.'))
                    self.failed()
 
            else:
                log.error('The Initial Traffic Condition did not pass:')
                traffic_obj.getAllBoundStreamStatistics(tgn_hdl)
                countDownTimer(180)
                self.failed() 
                
class VXLANL3TRMVPCBLFUNC027(aetest.Testcase):
 
    """ Flap VRF-Lite Uplink Interfaces - Primary"""
 
    uid = 'VXLAN-L3-TRM-VPC-BL-FUNC-027'
 
    @aetest.test
    def flapVRFLiteUplinksOnPrimary(self,log,testscript,testbed):
        node_dict = testscript.parameters['node_dict']
        traffic_stream_dict = testscript.parameters['traffic_stream_dict'] 
        tg_interface_hdl_dict = testscript.parameters['tg_interface_hdl_dict']
        port_handle_dict = testscript.parameters['port_handle_dict']
        configdict = testscript.parameters['configdict'] 
        tgn_config_dict = configdict['TG']
        threshold = testscript.parameters['traffic_threshold'] 
        tgn_port_dut_mapping = testscript.parameters['tgn_port_dut_mapping']
        traffic_obj = testscript.parameters['traffic_obj']
        trigger_obj = testscript.parameters['trigger_obj']
        alias_intf_mapping = testscript.parameters['alias_intf_mapping']
        testbed_obj = testscript.parameters['testbed_obj']
         
        res = [node_dict['all_dut'][dut].configure('terminal session-timeout 0') for dut in node_dict['all_dut'] if re.search('uut', dut)]
         
        for TG in tgn_config_dict.keys():
            tgn_hdl = testscript.parameters['testbed_obj'].devices[TG]
            out = trigger_obj.checkAllStreamStats(tgn_hdl)
         
            if out:
                log.info(banner('Initial Traffic flow is as expected:'))
                traffic_obj.getAllBoundStreamStatistics(tgn_hdl)
                 
                log.info(banner('Taking Backup of configs on all the VTEPs:'))
                 
                device_dict = trigger_obj.getDeviceDict('vpc_vtep')
                 
                res = trigger_obj.backUpAndRestoreConfigs(list(device_dict.keys()),'backup')
                 
                vpc_vtep_dict = trigger_obj.getVPCSwitchhdl('details')
                 
                primary_dut = vpc_vtep_dict['primary']['dut']
                primary_hdl = vpc_vtep_dict['primary']['hdl']
                
                for node in testbed_obj.devices:
                    if re.search('EXTERNAL',testbed_obj.devices[node].type):
                        vrf_lite_dut = testbed_obj.devices[node].alias
                
                for intf in alias_intf_mapping[primary_dut]:
                    if re.search(vrf_lite_dut,intf):
                        intf1 = alias_intf_mapping[primary_dut][intf]
                        log.info(banner('The Interface to Shut is : {0}'.format(intf1)))
                        
                log.info(banner('Shutting down the interface {0} on dut {1}'.format(intf1,primary_dut)))
                        
                res = MyLib.my_utils.shutDownInterface(log,primary_hdl,intf1,primary_dut)
                
                log.info(banner('Waiting for 30 seconds before measuring Traffic Stats:'))
                countDownTimer(30)
                 
                out = trigger_obj.checkAllStreamStats(tgn_hdl)
                 
                flag = 0
                if out:
                    log.info(banner('Traffic is as expected. ....Traffic STream breakup is : '))
                    traffic_obj.getAllBoundStreamStatistics(tgn_hdl)
                 
                else:
                    log.error(banner('Traffic drop was not as expected. But Seen. Traffic Break up is : '))
                    traffic_obj.getAllBoundStreamStatistics(tgn_hdl)
                    flag = 1
                     
                log.info(banner('Reverting back the configs:'))
                res = trigger_obj.backUpAndRestoreConfigs(list(device_dict.keys()),'restore')
                 
                log.info(banner('Waiting for 60 seconds before collecting the Traffic stats..'))
                countDownTimer(60)
                     
                out = trigger_obj.checkAllStreamStats(tgn_hdl)
                traffic_obj.getAllBoundStreamStatistics(tgn_hdl)
                 
                if not out:
                    log.error(banner('Traffic Drop was seen after reverting to Original configs.'))
                    traffic_obj.getAllBoundStreamStatistics(tgn_hdl)
                    trigger_obj.backUpAndRestoreConfigs(list(device_dict.keys()),'restore')
                    flag = 1
                
                if flag:
                    log.error(banner('Traffic was not as expected. Refer Logs.'))
                    cfg = 'interface nve 1 ; shutdown ; sleep 5 ; no shutdown'
                    [node_dict['all_dut'][dut].configure(cfg) for dut in list(device_dict.keys())]
                    countDownTimer(600)
                    self.failed()
 
            else:
                log.error('The Initial Traffic Condition did not pass:')
                traffic_obj.getAllBoundStreamStatistics(tgn_hdl)
                countDownTimer(180)
                self.failed()                 
 
class VXLANL3TRMVPCBLFUNC028(aetest.Testcase):
 
    """ Flap VRF-Lite Uplink Interfaces - secondary"""
 
    uid = 'VXLAN-L3-TRM-VPC-BL-FUNC-028'
 
    @aetest.test
    def flapVRFLiteUplinksOnsecondary(self,log,testscript,testbed):
        node_dict = testscript.parameters['node_dict']
        traffic_stream_dict = testscript.parameters['traffic_stream_dict'] 
        tg_interface_hdl_dict = testscript.parameters['tg_interface_hdl_dict']
        port_handle_dict = testscript.parameters['port_handle_dict']
        configdict = testscript.parameters['configdict'] 
        tgn_config_dict = configdict['TG']
        threshold = testscript.parameters['traffic_threshold'] 
        tgn_port_dut_mapping = testscript.parameters['tgn_port_dut_mapping']
        traffic_obj = testscript.parameters['traffic_obj']
        trigger_obj = testscript.parameters['trigger_obj']
        alias_intf_mapping = testscript.parameters['alias_intf_mapping']
        testbed_obj = testscript.parameters['testbed_obj']
         
        res = [node_dict['all_dut'][dut].configure('terminal session-timeout 0') for dut in node_dict['all_dut'] if re.search('uut', dut)]
         
        for TG in tgn_config_dict.keys():
            tgn_hdl = testscript.parameters['testbed_obj'].devices[TG]
            out = trigger_obj.checkAllStreamStats(tgn_hdl)
         
            if out:
                log.info(banner('Initial Traffic flow is as expected:'))
                traffic_obj.getAllBoundStreamStatistics(tgn_hdl)
                 
                log.info(banner('Taking Backup of configs on all the VTEPs:'))
                 
                device_dict = trigger_obj.getDeviceDict('vpc_vtep')
                 
                res = trigger_obj.backUpAndRestoreConfigs(list(device_dict.keys()),'backup')
                 
                vpc_vtep_dict = trigger_obj.getVPCSwitchhdl('details')
                 
                secondary_dut = vpc_vtep_dict['secondary']['dut']
                secondary_hdl = vpc_vtep_dict['secondary']['hdl']
                
                for node in testbed_obj.devices:
                    if re.search('EXTERNAL',testbed_obj.devices[node].type):
                        vrf_lite_dut = testbed_obj.devices[node].alias
                
                for intf in alias_intf_mapping[secondary_dut]:
                    if re.search(vrf_lite_dut,intf):
                        intf1 = alias_intf_mapping[secondary_dut][intf]
                        log.info(banner('The Interface to Shut is : {0}'.format(intf1)))
                        
                log.info(banner('Shutting down the interface {0} on dut {1}'.format(intf1,secondary_dut)))
                        
                res = MyLib.my_utils.shutDownInterface(log,secondary_hdl,intf1,secondary_dut)
                
                log.info(banner('Waiting for 30 seconds before measuring Traffic Stats:'))
                countDownTimer(30)
                 
                out = trigger_obj.checkAllStreamStats(tgn_hdl)
                 
                flag = 0
                if out:
                    log.info(banner('Traffic is as expected. ....Traffic STream breakup is : '))
                    traffic_obj.getAllBoundStreamStatistics(tgn_hdl)
                 
                else:
                    log.error(banner('Traffic drop was not as expected. But Seen. Traffic Break up is : '))
                    traffic_obj.getAllBoundStreamStatistics(tgn_hdl)
                    flag = 1
                     
                log.info(banner('Reverting back the configs:'))
                res = trigger_obj.backUpAndRestoreConfigs(list(device_dict.keys()),'restore')
                 
                log.info(banner('Waiting for 60 seconds before collecting the Traffic stats..'))
                countDownTimer(60)
                     
                out = trigger_obj.checkAllStreamStats(tgn_hdl)
                traffic_obj.getAllBoundStreamStatistics(tgn_hdl)
                 
                if not out:
                    log.error(banner('Traffic Drop was seen after reverting to Original configs.'))
                    traffic_obj.getAllBoundStreamStatistics(tgn_hdl)
                    trigger_obj.backUpAndRestoreConfigs(list(device_dict.keys()),'restore')
                    flag = 1
                
                if flag:
                    log.error(banner('Traffic was not as expected. Refer Logs.'))
                    cfg = 'interface nve 1 ; shutdown ; sleep 5 ; no shutdown'
                    [node_dict['all_dut'][dut].configure(cfg) for dut in list(device_dict.keys())]
                    countDownTimer(600)
                    self.failed()
 
            else:
                log.error('The Initial Traffic Condition did not pass:')
                traffic_obj.getAllBoundStreamStatistics(tgn_hdl)
                countDownTimer(180)
                self.failed()                 
 
class VXLANL3TRMVPCBLFUNC029(aetest.Testcase):
 
    """ NVE Rechability - only Through Secondary"""
 
    uid = 'VXLAN-L3-TRM-VPC-BL-FUNC-029'
 
    @aetest.test
    def nveReachabilityOnlyThroughSecondary(self,log,testscript,testbed):
        node_dict = testscript.parameters['node_dict']
        traffic_stream_dict = testscript.parameters['traffic_stream_dict'] 
        tg_interface_hdl_dict = testscript.parameters['tg_interface_hdl_dict']
        port_handle_dict = testscript.parameters['port_handle_dict']
        configdict = testscript.parameters['configdict'] 
        tgn_config_dict = configdict['TG']
        threshold = testscript.parameters['traffic_threshold'] 
        tgn_port_dut_mapping = testscript.parameters['tgn_port_dut_mapping']
        traffic_obj = testscript.parameters['traffic_obj']
        trigger_obj = testscript.parameters['trigger_obj']
        alias_intf_mapping = testscript.parameters['alias_intf_mapping']
        testbed_obj = testscript.parameters['testbed_obj']
         
        res = [node_dict['all_dut'][dut].configure('terminal session-timeout 0') for dut in node_dict['all_dut'] if re.search('uut', dut)]
         
        for TG in tgn_config_dict.keys():
            tgn_hdl = testscript.parameters['testbed_obj'].devices[TG]
            out = trigger_obj.checkAllStreamStats(tgn_hdl)
         
            if out:
                log.info(banner('Initial Traffic flow is as expected:'))
                traffic_obj.getAllBoundStreamStatistics(tgn_hdl)
                 
                log.info(banner('Taking Backup of configs on all the VTEPs:'))
                 
                device_dict = trigger_obj.getDeviceDict('vpc_vtep')
                 
                res = trigger_obj.backUpAndRestoreConfigs(list(device_dict.keys()),'backup')
                 
                vpc_vtep_dict = trigger_obj.getVPCSwitchhdl('details')
                 
                primary_dut = vpc_vtep_dict['primary']['dut']
                primary_hdl = vpc_vtep_dict['primary']['hdl']
                
                node_dict = {}
                for node in testbed_obj.devices:
                    if re.search('EXTERNAL',testbed_obj.devices[node].type):
                        dut = testbed_obj.devices[node].alias
                        node_dict[node]=dut
                    if re.search('SPINE',testbed_obj.devices[node].type):
                        dut = testbed_obj.devices[node].alias
                        node_dict[node]=dut
                
                log.info(banner('Uplink Interface to shut : Nodes : {0} and intfs : {0}'.format(node_dict.keys(), node_dict.values())))    
                
                for node in node_dict.values():
                    for intf in alias_intf_mapping[primary_dut]:
                        if node in intf:
                            intf1 = alias_intf_mapping[primary_dut][intf]
                            log.info(banner('Shutting down the interface {0} on dut {1}'.format(intf1,primary_dut)))       
                            res = MyLib.my_utils.shutDownInterface(log,primary_hdl,intf1,primary_dut)
                
                log.info(banner('Waiting for 30 seconds before measuring Traffic Stats:'))
                countDownTimer(30)
                 
                out = trigger_obj.checkAllStreamStats(tgn_hdl)
                 
                flag = 0
                if out:
                    log.info(banner('Traffic is as expected. ....Traffic STream breakup is : '))
                    traffic_obj.getAllBoundStreamStatistics(tgn_hdl)
                 
                else:
                    log.error(banner('Traffic drop was not as expected. But Seen. Traffic Break up is : '))
                    traffic_obj.getAllBoundStreamStatistics(tgn_hdl)
                    flag = 1
                     
                log.info(banner('Reverting back the configs:'))
                res = trigger_obj.backUpAndRestoreConfigs(list(device_dict.keys()),'restore')
                 
                log.info(banner('Waiting for 60 seconds before collecting the Traffic stats..'))
                countDownTimer(60)
                     
                out = trigger_obj.checkAllStreamStats(tgn_hdl)
                traffic_obj.getAllBoundStreamStatistics(tgn_hdl)
                 
                if not out:
                    log.error(banner('Traffic Drop was seen after reverting to Original configs.'))
                    traffic_obj.getAllBoundStreamStatistics(tgn_hdl)
                    trigger_obj.backUpAndRestoreConfigs(list(device_dict.keys()),'restore')
                    flag = 1
                
                if flag:
                    log.error(banner('Traffic was not as expected. Refer Logs.'))
                    cfg = 'interface nve 1 ; shutdown ; sleep 5 ; no shutdown'
                    [node_dict['all_dut'][dut].configure(cfg) for dut in list(device_dict.keys())]
                    countDownTimer(600)
                    self.failed()
 
            else:
                log.error('The Initial Traffic Condition did not pass:')
                traffic_obj.getAllBoundStreamStatistics(tgn_hdl)
                countDownTimer(180)
                self.failed()                 


class VXLANL3TRMVPCBLFUNC030(aetest.Testcase):
 
    """ NVE Rechability - only Through Primary"""
 
    uid = 'VXLAN-L3-TRM-VPC-BL-FUNC-030'
 
    @aetest.test
    def nveReachabilityOnlyThroughPrimary(self,log,testscript,testbed):
        node_dict = testscript.parameters['node_dict']
        traffic_stream_dict = testscript.parameters['traffic_stream_dict'] 
        tg_interface_hdl_dict = testscript.parameters['tg_interface_hdl_dict']
        port_handle_dict = testscript.parameters['port_handle_dict']
        configdict = testscript.parameters['configdict'] 
        tgn_config_dict = configdict['TG']
        threshold = testscript.parameters['traffic_threshold'] 
        tgn_port_dut_mapping = testscript.parameters['tgn_port_dut_mapping']
        traffic_obj = testscript.parameters['traffic_obj']
        trigger_obj = testscript.parameters['trigger_obj']
        alias_intf_mapping = testscript.parameters['alias_intf_mapping']
        testbed_obj = testscript.parameters['testbed_obj']
         
        res = [node_dict['all_dut'][dut].configure('terminal session-timeout 0') for dut in node_dict['all_dut'] if re.search('uut', dut)]
         
        for TG in tgn_config_dict.keys():
            tgn_hdl = testscript.parameters['testbed_obj'].devices[TG]
            out = trigger_obj.checkAllStreamStats(tgn_hdl)
         
            if out:
                log.info(banner('Initial Traffic flow is as expected:'))
                traffic_obj.getAllBoundStreamStatistics(tgn_hdl)
                 
                log.info(banner('Taking Backup of configs on all the VTEPs:'))
                 
                device_dict = trigger_obj.getDeviceDict('vpc_vtep')
                 
                res = trigger_obj.backUpAndRestoreConfigs(list(device_dict.keys()),'backup')
                 
                vpc_vtep_dict = trigger_obj.getVPCSwitchhdl('details')
                 
                secondary_dut = vpc_vtep_dict['secondary']['dut']
                secondary_hdl = vpc_vtep_dict['secondary']['hdl']
                
                node_dict = {}
                for node in testbed_obj.devices:
                    if re.search('EXTERNAL',testbed_obj.devices[node].type):
                        dut = testbed_obj.devices[node].alias
                        node_dict[node]=dut
                    if re.search('SPINE',testbed_obj.devices[node].type):
                        dut = testbed_obj.devices[node].alias
                        node_dict[node]=dut
                
                log.info(banner('Uplink Interface to shut : Nodes : {0} and intfs : {0}'.format(node_dict.keys(), node_dict.values())))    
                
                for node in node_dict.values():
                    for intf in alias_intf_mapping[secondary_dut]:
                        if node in intf:
                            intf1 = alias_intf_mapping[secondary_dut][intf]
                            log.info(banner('Shutting down the interface {0} on dut {1}'.format(intf1,secondary_dut)))       
                            res = MyLib.my_utils.shutDownInterface(log,secondary_hdl,intf1,secondary_dut)
                
                log.info(banner('Waiting for 30 seconds before measuring Traffic Stats:'))
                countDownTimer(30)
                 
                out = trigger_obj.checkAllStreamStats(tgn_hdl)
                 
                flag = 0
                if out:
                    log.info(banner('Traffic is as expected. ....Traffic STream breakup is : '))
                    traffic_obj.getAllBoundStreamStatistics(tgn_hdl)
                 
                else:
                    log.error(banner('Traffic drop was not as expected. But Seen. Traffic Break up is : '))
                    traffic_obj.getAllBoundStreamStatistics(tgn_hdl)
                    flag = 1
                     
                log.info(banner('Reverting back the configs:'))
                res = trigger_obj.backUpAndRestoreConfigs(list(device_dict.keys()),'restore')
                 
                log.info(banner('Waiting for 60 seconds before collecting the Traffic stats..'))
                countDownTimer(60)
                     
                out = trigger_obj.checkAllStreamStats(tgn_hdl)
                traffic_obj.getAllBoundStreamStatistics(tgn_hdl)
                 
                if not out:
                    log.error(banner('Traffic Drop was seen after reverting to Original configs.'))
                    traffic_obj.getAllBoundStreamStatistics(tgn_hdl)
                    trigger_obj.backUpAndRestoreConfigs(list(device_dict.keys()),'restore')
                    flag = 1
                
                if flag:
                    log.error(banner('Traffic was not as expected. Refer Logs.'))
                    cfg = 'interface nve 1 ; shutdown ; sleep 5 ; no shutdown'
                    [node_dict['all_dut'][dut].configure(cfg) for dut in list(device_dict.keys())]
                    countDownTimer(600)
                    self.failed()
 
            else:
                log.error('The Initial Traffic Condition did not pass:')
                traffic_obj.getAllBoundStreamStatistics(tgn_hdl)
                countDownTimer(180)
                self.failed()                 

class VXLANL3TRMVPCBLFUNC031(aetest.Testcase):
 
    """ L3 VXLAN VRF shut/no shut """
 
    uid = 'VXLAN-L3-TRM-VPC-BL-FUNC-031'
 
    @aetest.test
    def l3VxlanVRFFlap(self,log,testscript,testbed):
        node_dict = testscript.parameters['node_dict']
        traffic_stream_dict = testscript.parameters['traffic_stream_dict'] 
        tg_interface_hdl_dict = testscript.parameters['tg_interface_hdl_dict']
        port_handle_dict = testscript.parameters['port_handle_dict']
        configdict = testscript.parameters['configdict'] 
        tgn_config_dict = configdict['TG']
        threshold = testscript.parameters['traffic_threshold'] 
        tgn_port_dut_mapping = testscript.parameters['tgn_port_dut_mapping']
        traffic_obj = testscript.parameters['traffic_obj']
        trigger_obj = testscript.parameters['trigger_obj']
        alias_intf_mapping = testscript.parameters['alias_intf_mapping']
         
        res = [node_dict['all_dut'][dut].configure('terminal session-timeout 0') for dut in node_dict['all_dut'] if re.search('uut', dut)]
         
        for TG in tgn_config_dict.keys():
            tgn_hdl = testscript.parameters['testbed_obj'].devices[TG]
            out = trigger_obj.checkAllStreamStats(tgn_hdl)
         
            if out:
                log.info(banner('Initial Traffic flow is as expected:'))
                traffic_obj.getAllBoundStreamStatistics(tgn_hdl)
                 
                log.info(banner('Taking Backup of configs on all the VTEPs:'))
                 
                device_dict = trigger_obj.getDeviceDict('all_vtep')
                 
                res = trigger_obj.backUpAndRestoreConfigs(list(device_dict.keys()),'backup')
                 
                vrf_list = []
                 
                for dut in device_dict.keys():
                    hdl = node_dict['all_dut'][dut]
                    out = hdl.execute('show vrf | xml')
                    for line in out.splitlines():
                        if re.search('vrf_name',line):
                            s = BeautifulSoup(line)
                            vrf_name = s.find('vrf_name').string
                            if not re.search('default|management|egress-loadbalance',vrf_name):
                                vrf_list.append(vrf_name)
                                 
                    break
                 
                log.info(banner('The configured VRFs are : {0}'.format(vrf_list)))
                 
                for dut in device_dict.keys():
                    hdl = node_dict['all_dut'][dut]
                    for vrf in vrf_list:
                        res = MyLib.my_utils.vrfOperations(log,hdl,dut,vrf,'shut')
                         
                log.info(banner('WAiting for 250 seconds before unshutting the VRFs'))
                countDownTimer(250)
                 
                for dut in device_dict.keys():
                    hdl = node_dict['all_dut'][dut]
                    for vrf in vrf_list:
                        res = MyLib.my_utils.vrfOperations(log,hdl,dut,vrf,'unshut')
                 
                 
                log.info(banner('Waiting for 180 seconds before collecting traffic stats: - After Trigger interface shut and unshut '))
                countDownTimer(180)     
                 
                out = trigger_obj.checkAllStreamStats(tgn_hdl)
                traffic_obj.getAllBoundStreamStatistics(tgn_hdl)
                 
                flag = 0
                 
                if not out:
                    log.error(banner('Traffic did not resume after flapping the uplink PO'))
                    traffic_obj.getAllBoundStreamStatistics(tgn_hdl)
                    trigger_obj.backUpAndRestoreConfigs(list(device_dict.keys()),'restore')
                    flag = 1
                                     
                if flag:
                    log.error(banner('Traffic Flow is not working as expected'))
                    traffic_obj.getAllBoundStreamStatistics(tgn_hdl)
                    self.failed()
 
            else:
                log.error('The Initial Traffic Condition did not pass:')
                traffic_obj.getAllBoundStreamStatistics(tgn_hdl)
                countDownTimer(180)
                self.failed() 

class VXLANL3TRMVPCBLFUNC032(aetest.Testcase):
 
    """ VRF Removal and Readd """
 
    uid = 'VXLAN-L3-TRM-VPC-BL-FUNC-032'
 
    @aetest.test
    def removeVRFAndReadd(self,log,testscript,testbed):
        node_dict = testscript.parameters['node_dict']
        traffic_stream_dict = testscript.parameters['traffic_stream_dict'] 
        tg_interface_hdl_dict = testscript.parameters['tg_interface_hdl_dict']
        port_handle_dict = testscript.parameters['port_handle_dict']
        configdict = testscript.parameters['configdict'] 
        tgn_config_dict = configdict['TG']
        threshold = testscript.parameters['traffic_threshold'] 
        tgn_port_dut_mapping = testscript.parameters['tgn_port_dut_mapping']
        traffic_obj = testscript.parameters['traffic_obj']
        trigger_obj = testscript.parameters['trigger_obj']
        alias_intf_mapping = testscript.parameters['alias_intf_mapping']
         
        res = [node_dict['all_dut'][dut].configure('terminal session-timeout 0') for dut in node_dict['all_dut'] if re.search('uut', dut)]
         
        for TG in tgn_config_dict.keys():
            tgn_hdl = testscript.parameters['testbed_obj'].devices[TG]
            out = trigger_obj.checkAllStreamStats(tgn_hdl)
         
            if out:
                log.info(banner('Initial Traffic flow is as expected:'))
                traffic_obj.getAllBoundStreamStatistics(tgn_hdl)
                 
                log.info(banner('Taking Backup of configs on all the VTEPs:'))
                 
                device_dict = trigger_obj.getDeviceDict('all_vtep')
                 
                res = trigger_obj.backUpAndRestoreConfigs(list(device_dict.keys()),'backup')
                 
                vrf_list = []
                 
                for dut in device_dict.keys():
                    hdl = node_dict['all_dut'][dut]
                    out = hdl.execute('show vrf | xml')
                    for line in out.splitlines():
                        if re.search('vrf_name',line):
                            s = BeautifulSoup(line)
                            vrf_name = s.find('vrf_name').string
                            if not re.search('default|management|egress-loadbalance',vrf_name):
                                vrf_list.append(vrf_name)
                                 
                    break
                 
                log.info(banner('The configured VRFs are : {0}'.format(vrf_list)))
                 
                log.info(banner('Deleting the VRFs from the VTEP'))
                 
                for dut in device_dict.keys():
                    hdl = node_dict['all_dut'][dut]
                    for vrf in vrf_list:
                        res = MyLib.my_utils.vrfOperations(log,hdl,dut,vrf,'delete')
                         
                log.info(banner('WAiting for 100 seconds before configuring back the VRFs'))
                countDownTimer(100)
                 
                res = trigger_obj.backUpAndRestoreConfigs(list(device_dict.keys()),'restore')
             
                 
                 
                log.info(banner('Waiting for 180 seconds before collecting traffic stats: - After Trigger VRF removal and re-add '))
                countDownTimer(180)     
                 
                out = trigger_obj.checkAllStreamStats(tgn_hdl)
                traffic_obj.getAllBoundStreamStatistics(tgn_hdl)
                 
                flag = 0
                 
                if not out:
                    log.error(banner('Traffic did not resume after flapping the uplink PO'))
                    traffic_obj.getAllBoundStreamStatistics(tgn_hdl)
                    trigger_obj.backUpAndRestoreConfigs(list(device_dict.keys()),'restore')
                    flag = 1
                                     
                if flag:
                    log.error(banner('Traffic Flow is not working as expected'))
                    traffic_obj.getAllBoundStreamStatistics(tgn_hdl)
                    self.failed()
 
            else:
                log.error('The Initial Traffic Condition did not pass:')
                traffic_obj.getAllBoundStreamStatistics(tgn_hdl)
                countDownTimer(180)
                self.failed() 

class VXLANL3TRMVPCBLFUNC033(aetest.Testcase):
 
    """ L3 VNI SVI FLAP"""
 
    uid = 'VXLAN-L3-TRM-VPC-BL-FUNC-033'
 
    @aetest.test
    def l3VNISviFlap(self,log,testscript,testbed):
        node_dict = testscript.parameters['node_dict']
        traffic_stream_dict = testscript.parameters['traffic_stream_dict'] 
        tg_interface_hdl_dict = testscript.parameters['tg_interface_hdl_dict']
        port_handle_dict = testscript.parameters['port_handle_dict']
        configdict = testscript.parameters['configdict'] 
        tgn_config_dict = configdict['TG']
        threshold = testscript.parameters['traffic_threshold'] 
        tgn_port_dut_mapping = testscript.parameters['tgn_port_dut_mapping']
        traffic_obj = testscript.parameters['traffic_obj']
        trigger_obj = testscript.parameters['trigger_obj']
        alias_intf_mapping = testscript.parameters['alias_intf_mapping']
         
        res = [node_dict['all_dut'][dut].configure('terminal session-timeout 0') for dut in node_dict['all_dut'] if re.search('uut', dut)]
         
        for TG in tgn_config_dict.keys():
            tgn_hdl = testscript.parameters['testbed_obj'].devices[TG]
            out = trigger_obj.checkAllStreamStats(tgn_hdl)
         
            if out:
                log.info(banner('Initial Traffic flow is as expected:'))
                traffic_obj.getAllBoundStreamStatistics(tgn_hdl)
                 
                log.info(banner('Taking Backup of configs on all the VTEPs:'))
                 
                device_dict = trigger_obj.getDeviceDict('all_vtep')
                 
                res = trigger_obj.backUpAndRestoreConfigs(list(device_dict.keys()),'backup')
                 
                log.info(banner('Flapping the L3 VNI SVI on  all the VTEPs'))
                 
                svi_args = configdict['trigger_dict']['pim-enable-disable']['svi']
                ns = MyLib.my_config_utils.parseScaleSVIParams(log,svi_args)
                 
                log.info('The value of ns is : {0}'.format(ns))
                 
                log.info(banner('Flapping the L3VNI SVI on all the VTEPS'))
                for dut in device_dict.keys():
                    hdl = node_dict['all_dut'][dut]
                    log.info(' ******** Flapping the L3VNI SVI- on the device {0} *********'.format(dut))
                    for i in range(int(ns.l3_vni_svi_start),int(ns.l3_vni_svi_start) + int(ns.no_of_l3_vni_svi)):
                        res = MyLib.my_utils.shutDownSVIInterface(log,hdl,dut,i)
                        countDownTimer(5)
                        res = MyLib.my_utils.unShutDownSVIInterface(log,hdl,dut,i)
 
                log.info(banner('Waiting for 100 seconds before starting the Traffic...'))
                countDownTimer(100)
 
                out = trigger_obj.checkAllStreamStats(tgn_hdl)
                 
                flag = 0
                if out:
                    log.info(banner('Traffic flow is as expected after Trigger: Change L2 VNI'))
                    traffic_obj.getAllBoundStreamStatistics(tgn_hdl)
                else:
                    log.error(banner('Traffic flow is NOT as expected after Trigger: Change L2 VNI . Traffic Breakup is: '))
                    traffic_obj.getAllBoundStreamStatistics(tgn_hdl)
                    flag = 1
                 
                log.info(banner('Reverting back the configs:'))
                res = trigger_obj.backUpAndRestoreConfigs(list(device_dict.keys()),'restore')
                 
                log.info(banner('Waiting for 100 seconds before starting the Traffic...'))
                countDownTimer(100)
                 
                out = trigger_obj.checkAllStreamStats(tgn_hdl)
                traffic_obj.getAllBoundStreamStatistics(tgn_hdl)
                 
                if not out:
                    log.error(banner('Traffic Item stats is not as expected.'))
                    traffic_obj.getAllBoundStreamStatistics(tgn_hdl)
                    trigger_obj.backUpAndRestoreConfigs(list(device_dict.keys()),'restore')
                    flag = 1
                
                if flag:
                    log.error(banner('Traffic Item stats is not as expected. Refer Logss'))
                    traffic_obj.getAllBoundStreamStatistics(tgn_hdl)
                    self.failed()
 
            else:
                log.error('The Initial Traffic Condition did not pass:')
                traffic_obj.getAllBoundStreamStatistics(tgn_hdl)
                countDownTimer(180)
                self.failed()  
 
 
class VXLANL3TRMVPCBLFUNC034(aetest.Testcase):
 
    """ L3 VNI SVI Remove / Readd"""
 
    uid = 'VXLAN-L3-TRM-VPC-BL-FUNC-034'
 
    @aetest.test
    def l3VNISviRemoveReadd(self,log,testscript,testbed):
        node_dict = testscript.parameters['node_dict']
        traffic_stream_dict = testscript.parameters['traffic_stream_dict'] 
        tg_interface_hdl_dict = testscript.parameters['tg_interface_hdl_dict']
        port_handle_dict = testscript.parameters['port_handle_dict']
        configdict = testscript.parameters['configdict'] 
        tgn_config_dict = configdict['TG']
        threshold = testscript.parameters['traffic_threshold'] 
        tgn_port_dut_mapping = testscript.parameters['tgn_port_dut_mapping']
        traffic_obj = testscript.parameters['traffic_obj']
        trigger_obj = testscript.parameters['trigger_obj']
        alias_intf_mapping = testscript.parameters['alias_intf_mapping']
         
        res = [node_dict['all_dut'][dut].configure('terminal session-timeout 0') for dut in node_dict['all_dut'] if re.search('uut', dut)]
         
        for TG in tgn_config_dict.keys():
            tgn_hdl = testscript.parameters['testbed_obj'].devices[TG]
            out = trigger_obj.checkAllStreamStats(tgn_hdl)
         
            if out:
                log.info(banner('Initial Traffic flow is as expected:'))
                traffic_obj.getAllBoundStreamStatistics(tgn_hdl)
                 
                log.info(banner('Taking Backup of configs on all the VTEPs:'))
                 
                device_dict = trigger_obj.getDeviceDict('all_vtep')
                 
                res = trigger_obj.backUpAndRestoreConfigs(list(device_dict.keys()),'backup')
                 
                log.info(banner('Remove / Readd the L3 VNI SVI on  all the VTEPs'))
                 
                svi_args = configdict['trigger_dict']['pim-enable-disable']['svi']
                ns = MyLib.my_config_utils.parseScaleSVIParams(log,svi_args)
                 
                log.info('The value of ns is : {0}'.format(ns))
                 
                log.info(banner('Removing the L3VNI SVI on all the VTEPS'))
                for dut in device_dict.keys():
                    hdl = node_dict['all_dut'][dut]
                    log.info(' ******** Flapping the L3VNI SVI- on the device {0} *********'.format(dut))
                    for i in range(int(ns.l3_vni_svi_start),int(ns.l3_vni_svi_start) + int(ns.no_of_l3_vni_svi)):
                        res = MyLib.my_utils.sviOperations(log,hdl,dut,i,'delete')
 
 
                log.info(banner('Waiting for 100 seconds before adding the SVIs on all VTEPs..'))
                countDownTimer(100)
                 
                res = trigger_obj.backUpAndRestoreConfigs(list(device_dict.keys()),'restore')
                 
                log.info(banner('Waiting for 100 seconds before measuring the Traffic Stats:'))
                countDownTimer(100)
 
                out = trigger_obj.checkAllStreamStats(tgn_hdl)
                 
                flag = 0
                if out:
                    log.info(banner('Traffic flow is as expected after Trigger: Change L2 VNI'))
                    traffic_obj.getAllBoundStreamStatistics(tgn_hdl)
                else:
                    log.error(banner('Traffic flow is NOT as expected after Trigger: Change L2 VNI . Traffic Breakup is: '))
                    traffic_obj.getAllBoundStreamStatistics(tgn_hdl)
                    flag = 1
                 
                log.info(banner('Reverting back the configs:'))
                res = trigger_obj.backUpAndRestoreConfigs(list(device_dict.keys()),'restore')
                 
                log.info(banner('Waiting for 100 seconds before starting the Traffic...'))
                countDownTimer(100)
                 
                out = trigger_obj.checkAllStreamStats(tgn_hdl)
                traffic_obj.getAllBoundStreamStatistics(tgn_hdl)
                 
                if not out:
                    log.error(banner('Traffic Item stats is not as expected.'))
                    traffic_obj.getAllBoundStreamStatistics(tgn_hdl)
                    trigger_obj.backUpAndRestoreConfigs(list(device_dict.keys()),'restore')
                    flag = 1
                
                if flag:
                    log.error(banner('Traffic Item stats is not as expected. Refer Logss'))
                    traffic_obj.getAllBoundStreamStatistics(tgn_hdl)
                    self.failed()
 
            else:
                log.error('The Initial Traffic Condition did not pass:')
                traffic_obj.getAllBoundStreamStatistics(tgn_hdl)
                countDownTimer(180)
                self.failed()  


class VXLANL3TRMVPCBLFUNC035(aetest.Testcase):
 
    """ L2 VNI SVI Shut / Unshut"""
 
    uid = 'VXLAN-L3-TRM-VPC-BL-FUNC-035'
 
    @aetest.test
    def l2VNISviShutUnshut(self,log,testscript,testbed):
        node_dict = testscript.parameters['node_dict']
        traffic_stream_dict = testscript.parameters['traffic_stream_dict'] 
        tg_interface_hdl_dict = testscript.parameters['tg_interface_hdl_dict']
        port_handle_dict = testscript.parameters['port_handle_dict']
        configdict = testscript.parameters['configdict'] 
        tgn_config_dict = configdict['TG']
        threshold = testscript.parameters['traffic_threshold'] 
        tgn_port_dut_mapping = testscript.parameters['tgn_port_dut_mapping']
        traffic_obj = testscript.parameters['traffic_obj']
        trigger_obj = testscript.parameters['trigger_obj']
        alias_intf_mapping = testscript.parameters['alias_intf_mapping']
         
        res = [node_dict['all_dut'][dut].configure('terminal session-timeout 0') for dut in node_dict['all_dut'] if re.search('uut', dut)]
         
        for TG in tgn_config_dict.keys():
            tgn_hdl = testscript.parameters['testbed_obj'].devices[TG]
            out = trigger_obj.checkAllStreamStats(tgn_hdl)
         
            if out:
                log.info(banner('Initial Traffic flow is as expected:'))
                traffic_obj.getAllBoundStreamStatistics(tgn_hdl)
                 
                log.info(banner('Taking Backup of configs on all the VTEPs:'))
                 
                device_dict = trigger_obj.getDeviceDict('all_vtep')
                 
                res = trigger_obj.backUpAndRestoreConfigs(list(device_dict.keys()),'backup')
                 
                log.info(banner('Flapping the L2 VNI SVI on  all the VTEPs'))
                 
                svi_args = configdict['trigger_dict']['pim-enable-disable']['svi']
                ns = MyLib.my_config_utils.parseScaleSVIParams(log,svi_args)
                 
                log.info('The value of ns is : {0}'.format(ns))
                 
                log.info(banner('Flapping the L2 VNI SVI on all the VTEPS'))
                for dut in device_dict.keys():
                    hdl = node_dict['all_dut'][dut]
                    log.info(' ******** Flapping the L2VNI SVI- on the device {0} *********'.format(dut))
                    for i in range(int(ns.l2_vni_svi_start),int(ns.l2_vni_svi_start) + int(ns.no_of_l2_vni_svi)):
                        res = MyLib.my_utils.shutDownSVIInterface(log,hdl,dut,i)
                        countDownTimer(5)
                        res = MyLib.my_utils.unShutDownSVIInterface(log,hdl,dut,i)
 
                log.info(banner('Waiting for 100 seconds before starting the Traffic...'))
                countDownTimer(100)
 
                out = trigger_obj.checkAllStreamStats(tgn_hdl)
                 
                flag = 0
                if out:
                    log.info(banner('Traffic flow is as expected after Trigger: L2 VNI SVI FLAP'))
                    traffic_obj.getAllBoundStreamStatistics(tgn_hdl)
                else:
                    log.error(banner('Traffic flow is NOT as expected after Trigger: L2 VNI SVI FLAP . Traffic Breakup is: '))
                    traffic_obj.getAllBoundStreamStatistics(tgn_hdl)
                    flag = 1
                 
                log.info(banner('Reverting back the configs:'))
                res = trigger_obj.backUpAndRestoreConfigs(list(device_dict.keys()),'restore')
                 
                log.info(banner('Waiting for 100 seconds before starting the Traffic...'))
                countDownTimer(100)
                 
                out = trigger_obj.checkAllStreamStats(tgn_hdl)
                traffic_obj.getAllBoundStreamStatistics(tgn_hdl)
                 
                if not out:
                    log.error(banner('Traffic Item stats is not as expected.'))
                    traffic_obj.getAllBoundStreamStatistics(tgn_hdl)
                    trigger_obj.backUpAndRestoreConfigs(list(device_dict.keys()),'restore')
                    flag = 1
                
                if flag:
                    log.error(banner('Traffic Item stats is not as expected. Refer Logss'))
                    traffic_obj.getAllBoundStreamStatistics(tgn_hdl)
                    self.failed()
 
            else:
                log.error('The Initial Traffic Condition did not pass:')
                traffic_obj.getAllBoundStreamStatistics(tgn_hdl)
                countDownTimer(180)
                self.failed()  
 
class VXLANL3TRMVPCBLFUNC036(aetest.Testcase):
 
    """ L2 VNI SVI Remove / Reddd """
 
    uid = 'VXLAN-L3-TRM-VPC-BL-FUNC-036'
 
    @aetest.test
    def l2VNISviRemoveReadd(self,log,testscript,testbed):
        node_dict = testscript.parameters['node_dict']
        traffic_stream_dict = testscript.parameters['traffic_stream_dict'] 
        tg_interface_hdl_dict = testscript.parameters['tg_interface_hdl_dict']
        port_handle_dict = testscript.parameters['port_handle_dict']
        configdict = testscript.parameters['configdict'] 
        tgn_config_dict = configdict['TG']
        threshold = testscript.parameters['traffic_threshold'] 
        tgn_port_dut_mapping = testscript.parameters['tgn_port_dut_mapping']
        traffic_obj = testscript.parameters['traffic_obj']
        trigger_obj = testscript.parameters['trigger_obj']
        alias_intf_mapping = testscript.parameters['alias_intf_mapping']
         
        res = [node_dict['all_dut'][dut].configure('terminal session-timeout 0') for dut in node_dict['all_dut'] if re.search('uut', dut)]
         
        for TG in tgn_config_dict.keys():
            tgn_hdl = testscript.parameters['testbed_obj'].devices[TG]
            out = trigger_obj.checkAllStreamStats(tgn_hdl)
         
            if out:
                log.info(banner('Initial Traffic flow is as expected:'))
                traffic_obj.getAllBoundStreamStatistics(tgn_hdl)
                 
                log.info(banner('Taking Backup of configs on all the VTEPs:'))
                 
                device_dict = trigger_obj.getDeviceDict('all_vtep')
                 
                res = trigger_obj.backUpAndRestoreConfigs(list(device_dict.keys()),'backup')
                 
                log.info(banner('Remove / Readd the L2 VNI SVI on  all the VTEPs'))
                 
                svi_args = configdict['trigger_dict']['pim-enable-disable']['svi']
                ns = MyLib.my_config_utils.parseScaleSVIParams(log,svi_args)
                 
                log.info('The value of ns is : {0}'.format(ns))
                 
                log.info(banner('Removing the L2VNI SVI on all the VTEPS'))
                for dut in device_dict.keys():
                    hdl = node_dict['all_dut'][dut]
                    log.info(' ******** Flapping the L3VNI SVI- on the device {0} *********'.format(dut))
                    for i in range(int(ns.l2_vni_svi_start),int(ns.l2_vni_svi_start) + int(ns.no_of_l2_vni_svi)):
                        res = MyLib.my_utils.sviOperations(log,hdl,dut,i,'delete')
 
 
                log.info(banner('Waiting for 100 seconds before adding the SVIs on all VTEPs..'))
                countDownTimer(100)
                 
                res = trigger_obj.backUpAndRestoreConfigs(list(device_dict.keys()),'restore')
                 
                log.info(banner('Waiting for 100 seconds before measuring the Traffic Stats:'))
                countDownTimer(100)
 
                out = trigger_obj.checkAllStreamStats(tgn_hdl)
                 
                flag = 0
                if out:
                    log.info(banner('Traffic flow is as expected after Trigger: Change L2 VNI'))
                    traffic_obj.getAllBoundStreamStatistics(tgn_hdl)
                else:
                    log.error(banner('Traffic flow is NOT as expected after Trigger: Change L2 VNI . Traffic Breakup is: '))
                    traffic_obj.getAllBoundStreamStatistics(tgn_hdl)
                    flag = 1
                 
                log.info(banner('Reverting back the configs:'))
                res = trigger_obj.backUpAndRestoreConfigs(list(device_dict.keys()),'restore')
                 
                log.info(banner('Waiting for 100 seconds before starting the Traffic...'))
                countDownTimer(100)
                 
                out = trigger_obj.checkAllStreamStats(tgn_hdl)
                traffic_obj.getAllBoundStreamStatistics(tgn_hdl)
                 
                if not out:
                    log.error(banner('Traffic Item stats is not as expected.'))
                    traffic_obj.getAllBoundStreamStatistics(tgn_hdl)
                    trigger_obj.backUpAndRestoreConfigs(list(device_dict.keys()),'restore')
                    flag = 1
                
                if flag:
                    log.error(banner('Traffic Item stats is not as expected. Refer Logss'))
                    traffic_obj.getAllBoundStreamStatistics(tgn_hdl)
                    self.failed()
 
            else:
                log.error('The Initial Traffic Condition did not pass:')
                traffic_obj.getAllBoundStreamStatistics(tgn_hdl)
                countDownTimer(180)
                self.failed()   

class VXLANL3TRMVPCBLFUNC037(aetest.Testcase):
 
    """ Enable Disable Pim On L2 VNI SVI's"""
 
    uid = 'VXLAN-L3-TRM-VPC-BL-FUNC-037'
 
    @aetest.test
    def enableDisablePimInL2VNIs(self,log,testscript,testbed):
        node_dict = testscript.parameters['node_dict']
        traffic_stream_dict = testscript.parameters['traffic_stream_dict'] 
        tg_interface_hdl_dict = testscript.parameters['tg_interface_hdl_dict']
        port_handle_dict = testscript.parameters['port_handle_dict']
        configdict = testscript.parameters['configdict'] 
        tgn_config_dict = configdict['TG']
        threshold = testscript.parameters['traffic_threshold'] 
        tgn_port_dut_mapping = testscript.parameters['tgn_port_dut_mapping']
        traffic_obj = testscript.parameters['traffic_obj']
        trigger_obj = testscript.parameters['trigger_obj']
        alias_intf_mapping = testscript.parameters['alias_intf_mapping']
         
        res = [node_dict['all_dut'][dut].configure('terminal session-timeout 0') for dut in node_dict['all_dut'] if re.search('uut', dut)]
         
        for TG in tgn_config_dict.keys():
            tgn_hdl = testscript.parameters['testbed_obj'].devices[TG]
            out = trigger_obj.checkAllStreamStats(tgn_hdl)
         
            if out:
                log.info(banner('Initial Traffic flow is as expected:'))
                traffic_obj.getAllBoundStreamStatistics(tgn_hdl)
                 
                log.info(banner('Taking Backup of configs on all the VTEPs:'))
                 
                device_dict = trigger_obj.getDeviceDict('all_vtep')
                 
                res = trigger_obj.backUpAndRestoreConfigs(list(device_dict.keys()),'backup')
                 
                svi_args = configdict['trigger_dict']['pim-enable-disable']['svi']
                ns = MyLib.my_config_utils.parseScaleSVIParams(log,svi_args)
                 
                for dut in device_dict:
                    log.info(banner('Disabling the Pim on the dut : {0}'.format(dut)))
                    for i in range(0,ns.no_of_l2_vni_svi):
                        cfg = '''interface vlan {0}
                                 no ip pim sparse-mode
                              '''.format(int(ns.l2_vni_svi_start)+i)
                        log.info('*** Disabling Pim on Vlan {0} in dut {1}***'.format(int(ns.l2_vni_svi_start)+i,dut))
                        node_dict['all_dut'][dut].configure(cfg)
             
                log.info(banner('Waiting for 300 seconds before re-configuring PIM on L2-VNI'))
                countDownTimer(300)
                 
                [trigger_obj.backUpAndRestoreConfigs(list(device_dict.keys()),'restore') for dut in device_dict]
                 
                log.info(banner('Waiting for 60 seconds before measuring the Traffic stats'))
                countDownTimer(60)
                 
                out = trigger_obj.checkAllStreamStats(tgn_hdl)
                flag = 0
                if not out:
                    log.error(banner('Traffic has not restored properly after the Trigger - DisablePIML2VNI'))
                    flag = 1
                if flag:
                    log.error(banner('Traffic has not restored after the trigger:'))
                    traffic_obj.getAllBoundStreamStatistics(tgn_hdl)
                    self.failed()
 
            else:
                log.error('The Initial Traffic Condition did not pass:')
                traffic_obj.getAllBoundStreamStatistics(tgn_hdl)
                countDownTimer(180)
                self.failed() 
                 
class VXLANL3TRMVPCBLFUNC038(aetest.Testcase):
 
    """ Enable Disable Pim On L3 VNI SVI's"""
 
    uid = 'VXLAN-L3-TRM-VPC-BL-FUNC-038'
 
    @aetest.test
    def enableDisablePimInL3VNIs(self,log,testscript,testbed):
        node_dict = testscript.parameters['node_dict']
        traffic_stream_dict = testscript.parameters['traffic_stream_dict'] 
        tg_interface_hdl_dict = testscript.parameters['tg_interface_hdl_dict']
        port_handle_dict = testscript.parameters['port_handle_dict']
        configdict = testscript.parameters['configdict'] 
        tgn_config_dict = configdict['TG']
        threshold = testscript.parameters['traffic_threshold'] 
        tgn_port_dut_mapping = testscript.parameters['tgn_port_dut_mapping']
        traffic_obj = testscript.parameters['traffic_obj']
        trigger_obj = testscript.parameters['trigger_obj']
        alias_intf_mapping = testscript.parameters['alias_intf_mapping']
         
        res = [node_dict['all_dut'][dut].configure('terminal session-timeout 0') for dut in node_dict['all_dut'] if re.search('uut', dut)]
         
        for TG in tgn_config_dict.keys():
            tgn_hdl = testscript.parameters['testbed_obj'].devices[TG]
            out = trigger_obj.checkAllStreamStats(tgn_hdl)
         
            if out:
                log.info(banner('Initial Traffic flow is as expected:'))
                traffic_obj.getAllBoundStreamStatistics(tgn_hdl)
                 
                log.info(banner('Taking Backup of configs on all the VTEPs:'))
                 
                device_dict = trigger_obj.getDeviceDict('all_vtep')
                 
                res = trigger_obj.backUpAndRestoreConfigs(list(device_dict.keys()),'backup')
                 
                svi_args = configdict['trigger_dict']['pim-enable-disable']['svi']
                ns = MyLib.my_config_utils.parseScaleSVIParams(log,svi_args)
                 
                for dut in device_dict:
                    log.info(banner('Disabling the Pim on the dut : {0}'.format(dut)))
                    for i in range(0,ns.no_of_l3_vni_svi):
                        cfg = '''interface vlan {0}
                                 no ip pim sparse-mode
                              '''.format(int(ns.l3_vni_svi_start)+i)
                        log.info('*** Disabling Pim on Vlan {0} in dut {1}***'.format(int(ns.l2_vni_svi_start)+i,dut))
                        node_dict['all_dut'][dut].configure(cfg)
             
                log.info(banner('Waiting for 300 seconds before re-configuring PIM on L3-VNI'))
                countDownTimer(300)
                 
                [trigger_obj.backUpAndRestoreConfigs(list(device_dict.keys()),'restore') for dut in device_dict]
                 
                log.info(banner('Waiting for 60 seconds before measuring the Traffic stats'))
                countDownTimer(60)
                 
                out = trigger_obj.checkAllStreamStats(tgn_hdl)
                flag = 0
                if not out:
                    log.error(banner('Traffic has not restored properly after the Trigger - DisablePIML2VNI'))
                    flag = 1
                if flag:
                    log.error(banner('Traffic has not restored after the trigger:'))
                    traffic_obj.getAllBoundStreamStatistics(tgn_hdl)
                    self.failed()
 
            else:
                log.error('The Initial Traffic Condition did not pass:')
                traffic_obj.getAllBoundStreamStatistics(tgn_hdl)
                countDownTimer(180)
                self.failed() 
                                     
class VXLANL3TRMVPCBLFUNC039(aetest.Testcase):
 
    """ Enable Disable ip forward clis"""
 
    uid = 'VXLAN-L3-TRM-VPC-BL-FUNC-039'
 
    @aetest.test
    def enableDisableIpForward(self,log,testscript,testbed):
        node_dict = testscript.parameters['node_dict']
        traffic_stream_dict = testscript.parameters['traffic_stream_dict'] 
        tg_interface_hdl_dict = testscript.parameters['tg_interface_hdl_dict']
        port_handle_dict = testscript.parameters['port_handle_dict']
        configdict = testscript.parameters['configdict'] 
        tgn_config_dict = configdict['TG']
        threshold = testscript.parameters['traffic_threshold'] 
        tgn_port_dut_mapping = testscript.parameters['tgn_port_dut_mapping']
        traffic_obj = testscript.parameters['traffic_obj']
        trigger_obj = testscript.parameters['trigger_obj']
        alias_intf_mapping = testscript.parameters['alias_intf_mapping']
         
        res = [node_dict['all_dut'][dut].configure('terminal session-timeout 0') for dut in node_dict['all_dut'] if re.search('uut', dut)]
         
        for TG in tgn_config_dict.keys():
            tgn_hdl = testscript.parameters['testbed_obj'].devices[TG]
            out = trigger_obj.checkAllStreamStats(tgn_hdl)
         
            if out:
                log.info(banner('Initial Traffic flow is as expected:'))
                traffic_obj.getAllBoundStreamStatistics(tgn_hdl)
                 
                log.info(banner('Taking Backup of configs on all the VTEPs:'))
                 
                device_dict = trigger_obj.getDeviceDict('all_vtep')
                 
                res = trigger_obj.backUpAndRestoreConfigs(list(device_dict.keys()),'backup')
                 
                svi_args = configdict['trigger_dict']['pim-enable-disable']['svi']
                ns = MyLib.my_config_utils.parseScaleSVIParams(log,svi_args)
                 
                for dut in device_dict:
                    log.info(banner('Disabling ip forward cli on the dut : {0}'.format(dut)))
                    for i in range(0,ns.no_of_l3_vni_svi):
                        cfg = '''interface vlan {0}
                                 no ip forward
                              '''.format(int(ns.l3_vni_svi_start)+i)
                        log.info('*** Disabling ip forward cli on Vlan {0} in dut {1}***'.format(int(ns.l2_vni_svi_start)+i,dut))
                        node_dict['all_dut'][dut].configure(cfg)
             
                log.info(banner('Waiting for 300 seconds before re-configuring ip Forward cli on L3-VNI'))
                countDownTimer(300)
                 
                [trigger_obj.backUpAndRestoreConfigs(list(device_dict.keys()),'restore') for dut in device_dict]
                 
                log.info(banner('Waiting for 60 seconds before measuring the Traffic stats'))
                countDownTimer(60)
                 
                out = trigger_obj.checkAllStreamStats(tgn_hdl)
                flag = 0
                if not out:
                    log.error(banner('Traffic has not restored properly after the Trigger - DisablePIML2VNI'))
                    flag = 1
                if flag:
                    log.error(banner('Traffic has not restored after the trigger:'))
                    traffic_obj.getAllBoundStreamStatistics(tgn_hdl)
                    self.failed()
 
            else:
                log.error('The Initial Traffic Condition did not pass:')
                traffic_obj.getAllBoundStreamStatistics(tgn_hdl)
                countDownTimer(180)
                self.failed() 

class VXLANL3TRMVPCBLFUNC040(aetest.Testcase):
 
    """ remove and readd vxlan IGMP snooping cli """
 
    uid = 'VXLAN-L3-TRM-VPC-BL-FUNC-040'
 
    @aetest.test
    def enableDisableVxlanIGMPSnooping(self,log,testscript,testbed):
#         standalone_vtep_dict = testscript.parameters['standalone_vtep_dict']
        node_dict = testscript.parameters['node_dict']
        tg_interface_hdl_dict = testscript.parameters['tg_interface_hdl_dict'] 
        traffic_stream_dict = testscript.parameters['traffic_stream_dict'] 
#         port_handle_dict = testscript.parameters['port_handle_dict']
#         TGList_config_file = testscript.parameters['TGList']
        configdict = testscript.parameters['configdict'] 
        tgn_config_dict = configdict['TG']
        threshold = testscript.parameters['traffic_threshold']
        traffic_obj = testscript.parameters['traffic_obj']
        trigger_obj = testscript.parameters['trigger_obj']
        tgn_port_dut_mapping = testscript.parameters['tgn_port_dut_mapping']
         
        res = [node_dict['all_dut'][dut].configure('terminal session-timeout 0') for dut in node_dict['all_dut'] if re.search('uut', dut)]
         
        for TG in tgn_config_dict.keys():
            tgn_hdl = testscript.parameters['testbed_obj'].devices[TG]
            out = trigger_obj.checkAllStreamStats(tgn_hdl)
         
            if out:
                log.info(banner('Initial Traffic flow is as expected:'))
                traffic_obj.getAllBoundStreamStatistics(tgn_hdl)
                 
                log.info(banner('Taking Backup of configs on all the VTEPs:'))
                 
                device_dict = trigger_obj.getDeviceDict('all_vtep')
 
                log.info(banner('Removing Vxlan IGMP Snooping CLI from all the VTEPs'))
                 
                cfg = 'ip igmp snooping vxlan'
                for dut in device_dict:
                    node_dict['all_dut'][dut].configure('no ' + cfg)
                 
                log.info(banner('Waiting for 30 seconds before Enabling the Vxlan IGMP Snooping'))
                countDownTimer(30)
                 
                log.info(banner('Enabling the Vxlan IGMP Snooping CLI on All boxes'))
                 
                for dut in device_dict:
                    node_dict['all_dut'][dut].configure(cfg)
                 
                log.info(banner('Waiting for 100 seconds before collecting the Traffic Stats'))
                countDownTimer(100)    
                 
                out = trigger_obj.checkAllStreamStats(tgn_hdl)
                 
                if not out:
                    log.error(banner('Traffic has not recovered on some of the streams after starting the Original Streams.. Collecting the individual STream stats:'))
                    traffic_obj.getAllBoundStreamStatistics(tgn_hdl)
                    cfg = 'interface nve 1 ; shutdown ; sleep 5 ; no shutdown'
                    [node_dict['all_dut'][dut].configure(cfg) for dut in list(device_dict.keys())]
                    countDownTimer(180)
                    self.failed()
 
            else:
                log.error('The Initial Traffic Condition did not pass:')
                traffic_obj.getAllBoundStreamStatistics(tgn_hdl)
                self.failed()  

class VXLANL3TRMVPCBLFUNC041(aetest.Testcase):
 
    """ Enable / disable of NGMVPN feature """
 
    uid = 'VXLAN-L3-TRM-VPC-BL-FUNC-041'
 
    @aetest.test
    def enableDisableNgmpvn(self,log,testscript,testbed):
#         standalone_vtep_dict = testscript.parameters['standalone_vtep_dict']
        node_dict = testscript.parameters['node_dict']
        tg_interface_hdl_dict = testscript.parameters['tg_interface_hdl_dict'] 
        traffic_stream_dict = testscript.parameters['traffic_stream_dict'] 
#         port_handle_dict = testscript.parameters['port_handle_dict']
#         TGList_config_file = testscript.parameters['TGList']
        configdict = testscript.parameters['configdict'] 
        tgn_config_dict = configdict['TG']
        threshold = testscript.parameters['traffic_threshold']
        traffic_obj = testscript.parameters['traffic_obj']
        trigger_obj = testscript.parameters['trigger_obj']
        tgn_port_dut_mapping = testscript.parameters['tgn_port_dut_mapping']
         
        res = [node_dict['all_dut'][dut].configure('terminal session-timeout 0') for dut in node_dict['all_dut'] if re.search('uut', dut)]
         
        for TG in tgn_config_dict.keys():
            tgn_hdl = testscript.parameters['testbed_obj'].devices[TG]
            out = trigger_obj.checkAllStreamStats(tgn_hdl)
         
            if out:
                log.info(banner('Initial Traffic flow is as expected:'))
                traffic_obj.getAllBoundStreamStatistics(tgn_hdl)
                 
                log.info(banner('Taking Backup of configs on all the VTEPs:'))
                 
                device_dict = trigger_obj.getDeviceDict('all_vtep')
                 
                res = trigger_obj.backUpAndRestoreConfigs(list(device_dict.keys()),'backup')
                 
                log.info(banner('Removing the feature NGMVPN from all the VTEPs'))
                 
                for dut in device_dict:
                    log.info('Removing the Feature ngmvpn from the VTEP {0}'.format(dut))
                    out=bringup_lib.unconfigFeature(node_dict['all_dut'][dut], log, '-feature ngmvpn' )
                    if out.result=='fail':
                        log.error('Disable of ngmvpn failed on VTEP {0}'.format(dut))
                        self.failed()
                    else:
                        log.info('Disable of ngmvpn Successful on VTEP {0}'.format(dut))
 
                 
                log.info(banner('Waiting for 30 seconds before Enabling the Feature Ngmvpn on Vteps'))
                countDownTimer(30)
                 
                for dut in device_dict:
                    log.info('Removing the Feature ngmvpn from the VTEP {0}'.format(dut))
                    out=bringup_lib.configFeature(node_dict['all_dut'][dut], log, '-feature ngmvpn' )
                    if out.result=='fail':
                        log.error('Disable of ngmvpn failed on VTEP {0}'.format(dut))
                        self.failed()
                    else:
                        log.info('Disable of ngmvpn Successful on VTEP {0}'.format(dut))
                        res = trigger_obj.backUpAndRestoreConfigs(dut.split(),'restore')
                 
                log.info(banner('Waiting for 60 seconds before getting the interface counters'))
                countDownTimer(60)
                 
                out = trigger_obj.checkAllStreamStats(tgn_hdl)
                 
                if not out:
                    log.error(banner('Traffic has not recovered on some of the streams after starting the Original Streams.. Collecting the individual STream stats:'))
                    traffic_obj.getAllBoundStreamStatistics(tgn_hdl)
                    countDownTimer(600)
                    self.failed()
 
            else:
                log.error('The Initial Traffic Condition did not pass:')
                traffic_obj.getAllBoundStreamStatistics(tgn_hdl)
                self.failed()     
 
class VXLANL3TRMVPCBLFUNC042(aetest.Testcase):
 
    """ Enable / disable of BGP feature """
 
    uid = 'VXLAN-L3-TRM-VPC-BL-FUNC-042'
 
    @aetest.test
    def enableDisableBGP(self,log,testscript,testbed):
#         standalone_vtep_dict = testscript.parameters['standalone_vtep_dict']
        node_dict = testscript.parameters['node_dict']
        tg_interface_hdl_dict = testscript.parameters['tg_interface_hdl_dict'] 
        traffic_stream_dict = testscript.parameters['traffic_stream_dict'] 
#         port_handle_dict = testscript.parameters['port_handle_dict']
#         TGList_config_file = testscript.parameters['TGList']
        configdict = testscript.parameters['configdict'] 
        tgn_config_dict = configdict['TG']
        threshold = testscript.parameters['traffic_threshold']
        traffic_obj = testscript.parameters['traffic_obj']
        trigger_obj = testscript.parameters['trigger_obj']
        tgn_port_dut_mapping = testscript.parameters['tgn_port_dut_mapping']
         
        res = [node_dict['all_dut'][dut].configure('terminal session-timeout 0') for dut in node_dict['all_dut'] if re.search('uut', dut)]
         
        for TG in tgn_config_dict.keys():
            tgn_hdl = testscript.parameters['testbed_obj'].devices[TG]
            out = trigger_obj.checkAllStreamStats(tgn_hdl)
         
            if out:
                log.info(banner('Initial Traffic flow is as expected:'))
                traffic_obj.getAllBoundStreamStatistics(tgn_hdl)
                 
                log.info(banner('Taking Backup of configs on all the VTEPs:'))
                 
                device_dict = trigger_obj.getDeviceDict('all_vtep')
                 
                res = trigger_obj.backUpAndRestoreConfigs(list(device_dict.keys()),'backup')
                 
                log.info(banner('Removing the feature bgp from all the VTEPs'))
                 
                for dut in device_dict:
                    log.info('Removing the Feature bgp from the VTEP {0}'.format(dut))
                    out=bringup_lib.unconfigFeature(node_dict['all_dut'][dut], log, '-feature bgp' )
                    if out.result=='fail':
                        log.error('Disable of bgp failed on VTEP {0}'.format(dut))
                        self.failed()
                    else:
                        log.info('Disable of bgp Successful on VTEP {0}'.format(dut))
 
                 
                log.info(banner('Waiting for 30 seconds before Enabling the Feature bgp on Vteps'))
                countDownTimer(30)
                 
                for dut in device_dict:
                    log.info('Removing the Feature bgp from the VTEP {0}'.format(dut))
                    out=bringup_lib.configFeature(node_dict['all_dut'][dut], log, '-feature bgp' )
                    if out.result=='fail':
                        log.error('Disable of bgp failed on VTEP {0}'.format(dut))
                        self.failed()
                    else:
                        log.info('Disable of bgp Successful on VTEP {0}'.format(dut))
                        res = trigger_obj.backUpAndRestoreConfigs(dut.split(),'restore')
                 
                log.info(banner('Waiting for 60 seconds before getting the interface counters'))
                countDownTimer(60)
                 
                out = trigger_obj.checkAllStreamStats(tgn_hdl)
                 
                if not out:
                    log.error(banner('Traffic has not recovered on some of the streams after starting the Original Streams.. Collecting the individual STream stats:'))
                    traffic_obj.getAllBoundStreamStatistics(tgn_hdl)
                    countDownTimer(600)
                    self.failed()
 
            else:
                log.error('The Initial Traffic Condition did not pass:')
                traffic_obj.getAllBoundStreamStatistics(tgn_hdl)
                self.failed()     
           
class VXLANL3TRMVPCBLFUNC043(aetest.Testcase):
 
    """ Enable / disable of nv Overlay feature """
 
    uid = 'VXLAN-L3-TRM-VPC-BL-FUNC-043'
 
    @aetest.test
    def enableDisableNvOverlay(self,log,testscript,testbed):
#         standalone_vtep_dict = testscript.parameters['standalone_vtep_dict']
        node_dict = testscript.parameters['node_dict']
        tg_interface_hdl_dict = testscript.parameters['tg_interface_hdl_dict'] 
        traffic_stream_dict = testscript.parameters['traffic_stream_dict'] 
#         port_handle_dict = testscript.parameters['port_handle_dict']
#         TGList_config_file = testscript.parameters['TGList']
        configdict = testscript.parameters['configdict'] 
        tgn_config_dict = configdict['TG']
        threshold = testscript.parameters['traffic_threshold']
        traffic_obj = testscript.parameters['traffic_obj']
        trigger_obj = testscript.parameters['trigger_obj']
        tgn_port_dut_mapping = testscript.parameters['tgn_port_dut_mapping']
         
        res = [node_dict['all_dut'][dut].configure('terminal session-timeout 0') for dut in node_dict['all_dut'] if re.search('uut', dut)]
         
        for TG in tgn_config_dict.keys():
            tgn_hdl = testscript.parameters['testbed_obj'].devices[TG]
            out = trigger_obj.checkAllStreamStats(tgn_hdl)
         
            if out:
                log.info(banner('Initial Traffic flow is as expected:'))
                traffic_obj.getAllBoundStreamStatistics(tgn_hdl)
                 
                log.info(banner('Taking Backup of configs on all the VTEPs:'))
                 
                device_dict = trigger_obj.getDeviceDict('all_vtep')
                 
                res = trigger_obj.backUpAndRestoreConfigs(list(device_dict.keys()),'backup')
                 
                log.info(banner('Removing the feature nv overlay from all the VTEPs'))
                 
                for dut in device_dict:
                    log.info('Removing the Feature nv overlay from the VTEP {0}'.format(dut))
                    out=bringup_lib.unconfigFeature(node_dict['all_dut'][dut], log, '-feature nve' )
                    if out.result=='fail':
                        log.error('Disable of nv overlay failed on VTEP {0}'.format(dut))
                        self.failed()
                    else:
                        log.info('Disable of nv overlay Successful on VTEP {0}'.format(dut))
 
                 
                log.info(banner('Waiting for 30 seconds before Enabling the Feature nv overlay on Vteps'))
                countDownTimer(30)
                 
                for dut in device_dict:
                    log.info('Removing the Feature nv overlay from the VTEP {0}'.format(dut))
                    out=bringup_lib.configFeature(node_dict['all_dut'][dut], log, '-feature nve' )
                    if out.result=='fail':
                        log.error('Disable of nv overlay failed on VTEP {0}'.format(dut))
                        self.failed()
                    else:
                        log.info('Disable of nv overlay Successful on VTEP {0}'.format(dut))
                        res = trigger_obj.backUpAndRestoreConfigs(dut.split(),'restore')
                 
                log.info(banner('Waiting for 60 seconds before getting the interface counters'))
                countDownTimer(300)
                 
                out = trigger_obj.checkAllStreamStats(tgn_hdl)
                 
                if not out:
                    log.error(banner('Traffic has not recovered on some of the streams after starting the Original Streams.. Collecting the individual STream stats:'))
                    traffic_obj.getAllBoundStreamStatistics(tgn_hdl)
                    countDownTimer(600)
                    self.failed()
 
            else:
                log.error('The Initial Traffic Condition did not pass:')
                traffic_obj.getAllBoundStreamStatistics(tgn_hdl)
                self.failed()  
 
class VXLANL3TRMVPCBLFUNC044(aetest.Testcase):
 
    """ Enable / disable of nv Overlay evpn feature """
 
    uid = 'VXLAN-L3-TRM-VPC-BL-FUNC-044'
 
    @aetest.test
    def enableDisableNvOverlayEVPN(self,log,testscript,testbed):
#         standalone_vtep_dict = testscript.parameters['standalone_vtep_dict']
        node_dict = testscript.parameters['node_dict']
        tg_interface_hdl_dict = testscript.parameters['tg_interface_hdl_dict'] 
        traffic_stream_dict = testscript.parameters['traffic_stream_dict'] 
#         port_handle_dict = testscript.parameters['port_handle_dict']
#         TGList_config_file = testscript.parameters['TGList']
        configdict = testscript.parameters['configdict'] 
        tgn_config_dict = configdict['TG']
        threshold = testscript.parameters['traffic_threshold']
        traffic_obj = testscript.parameters['traffic_obj']
        trigger_obj = testscript.parameters['trigger_obj']
        tgn_port_dut_mapping = testscript.parameters['tgn_port_dut_mapping']
         
        res = [node_dict['all_dut'][dut].configure('terminal session-timeout 0') for dut in node_dict['all_dut'] if re.search('uut', dut)]
         
        for TG in tgn_config_dict.keys():
            tgn_hdl = testscript.parameters['testbed_obj'].devices[TG]
            out = trigger_obj.checkAllStreamStats(tgn_hdl)
         
            if out:
                log.info(banner('Initial Traffic flow is as expected:'))
                traffic_obj.getAllBoundStreamStatistics(tgn_hdl)
                 
                log.info(banner('Taking Backup of configs on all the VTEPs:'))
                 
                device_dict = trigger_obj.getDeviceDict('all_vtep')
                 
                res = trigger_obj.backUpAndRestoreConfigs(list(device_dict.keys()),'backup')
                 
                log.info(banner('Removing the feature nv overlay from all the VTEPs'))
                 
                cfg = 'nv overlay evpn'
                for dut in device_dict:
                    log.info('Removing the Feature nv overlay EVPN from the VTEP {0}'.format(dut))
                    node_dict['all_dut'][dut].configure('no ' + cfg, timeout=600)
 
                 
                log.info(banner('Waiting for 30 seconds before Enabling the Feature nv overlay on Vteps'))
                countDownTimer(30)
                 
                for dut in device_dict:
                    log.info('Enabling the Feature nv overlay EVPN on the VTEP {0}'.format(dut))
                    res = trigger_obj.backUpAndRestoreConfigs(dut.split(),'restore')
                 
                log.info(banner('Waiting for 300 seconds before getting the interface counters'))
                countDownTimer(300)
                 
                out = trigger_obj.checkAllStreamStats(tgn_hdl)
                 
                if not out:
                    log.error(banner('Traffic has not recovered on some of the streams after starting the Original Streams.. Collecting the individual STream stats:'))
                    traffic_obj.getAllBoundStreamStatistics(tgn_hdl)
                    countDownTimer(600)
                    self.failed()
 
            else:
                log.error('The Initial Traffic Condition did not pass:')
                traffic_obj.getAllBoundStreamStatistics(tgn_hdl)
                self.failed()  
 
class VXLANL3TRMVPCBLFUNC045(aetest.Testcase):
 
    """ Enable / disable of vn-segment-vlan-based feature """
 
    uid = 'VXLAN-L3-TRM-VPC-BL-FUNC-045'
 
    @aetest.test
    def enableDisableVNSegment(self,log,testscript,testbed):
#         standalone_vtep_dict = testscript.parameters['standalone_vtep_dict']
        node_dict = testscript.parameters['node_dict']
        tg_interface_hdl_dict = testscript.parameters['tg_interface_hdl_dict'] 
        traffic_stream_dict = testscript.parameters['traffic_stream_dict'] 
#         port_handle_dict = testscript.parameters['port_handle_dict']
#         TGList_config_file = testscript.parameters['TGList']
        configdict = testscript.parameters['configdict'] 
        tgn_config_dict = configdict['TG']
        threshold = testscript.parameters['traffic_threshold']
        traffic_obj = testscript.parameters['traffic_obj']
        trigger_obj = testscript.parameters['trigger_obj']
        tgn_port_dut_mapping = testscript.parameters['tgn_port_dut_mapping']
         
        res = [node_dict['all_dut'][dut].configure('terminal session-timeout 0') for dut in node_dict['all_dut'] if re.search('uut', dut)]
         
        for TG in tgn_config_dict.keys():
            tgn_hdl = testscript.parameters['testbed_obj'].devices[TG]
            out = trigger_obj.checkAllStreamStats(tgn_hdl)
         
            if out:
                log.info(banner('Initial Traffic flow is as expected:'))
                traffic_obj.getAllBoundStreamStatistics(tgn_hdl)
                 
                log.info(banner('Taking Backup of configs on all the VTEPs:'))
                 
                device_dict = trigger_obj.getDeviceDict('all_vtep')
                 
                res = trigger_obj.backUpAndRestoreConfigs(list(device_dict.keys()),'backup')
                 
                log.info(banner('Removing the feature nv overlay from all the VTEPs'))
                 
                for dut in device_dict:
                    log.info('Removing the Feature nv overlay from the VTEP {0}'.format(dut))
                    out=bringup_lib.unconfigFeature(node_dict['all_dut'][dut], log, '-feature nve,vn-segment-vlan-based' )
                    if out.result=='fail':
                        log.error('Disable of nv overlay failed on VTEP {0}'.format(dut))
                        self.failed()
                    else:
                        log.info('Disable of nv overlay Successful on VTEP {0}'.format(dut))
 
                 
                log.info(banner('Waiting for 30 seconds before Enabling the Feature nv overlay on Vteps'))
                countDownTimer(30)
                 
                for dut in device_dict:
                    log.info('Removing the Feature nv overlay from the VTEP {0}'.format(dut))
                    out=bringup_lib.configFeature(node_dict['all_dut'][dut], log, '-feature nve,vn-segment-vlan-based' )
                    if out.result=='fail':
                        log.error('Disable of nv overlay failed on VTEP {0}'.format(dut))
                        self.failed()
                    else:
                        log.info('Disable of nv overlay Successful on VTEP {0}'.format(dut))
                        res = trigger_obj.backUpAndRestoreConfigs(dut.split(),'restore')
                 
                log.info(banner('Waiting for 60 seconds before getting the interface counters'))
                countDownTimer(300)
                 
                out = trigger_obj.checkAllStreamStats(tgn_hdl)
                 
                if not out:
                    log.error(banner('Traffic has not recovered on some of the streams after starting the Original Streams.. Collecting the individual STream stats:'))
                    traffic_obj.getAllBoundStreamStatistics(tgn_hdl)
                    countDownTimer(600)
                    self.failed()
 
            else:
                log.error('The Initial Traffic Condition did not pass:')
                traffic_obj.getAllBoundStreamStatistics(tgn_hdl)
                self.failed()  
                 
class VXLANL3TRMVPCBLFUNC046(aetest.Testcase):
 
    """ Enable / disable of interface-vlan feature """
 
    uid = 'VXLAN-L3-TRM-VPC-BL-FUNC-046'
 
    @aetest.test
    def enableDisableInterfaceVlan(self,log,testscript,testbed):
#         standalone_vtep_dict = testscript.parameters['standalone_vtep_dict']
        node_dict = testscript.parameters['node_dict']
        tg_interface_hdl_dict = testscript.parameters['tg_interface_hdl_dict'] 
        traffic_stream_dict = testscript.parameters['traffic_stream_dict'] 
#         port_handle_dict = testscript.parameters['port_handle_dict']
#         TGList_config_file = testscript.parameters['TGList']
        configdict = testscript.parameters['configdict'] 
        tgn_config_dict = configdict['TG']
        threshold = testscript.parameters['traffic_threshold']
        traffic_obj = testscript.parameters['traffic_obj']
        trigger_obj = testscript.parameters['trigger_obj']
        tgn_port_dut_mapping = testscript.parameters['tgn_port_dut_mapping']
         
        res = [node_dict['all_dut'][dut].configure('terminal session-timeout 0') for dut in node_dict['all_dut'] if re.search('uut', dut)]
         
        for TG in tgn_config_dict.keys():
            tgn_hdl = testscript.parameters['testbed_obj'].devices[TG]
            out = trigger_obj.checkAllStreamStats(tgn_hdl)
         
            if out:
                log.info(banner('Initial Traffic flow is as expected:'))
                traffic_obj.getAllBoundStreamStatistics(tgn_hdl)
                 
                log.info(banner('Taking Backup of configs on all the VTEPs:'))
                 
                device_dict = trigger_obj.getDeviceDict('all_vtep')
                 
                res = trigger_obj.backUpAndRestoreConfigs(list(device_dict.keys()),'backup')
                 
                log.info(banner('Removing the feature Interface-vlan from all the VTEPs'))
                 
                for dut in device_dict:
                    log.info('Removing the Feature Interface-vlan from the VTEP {0}'.format(dut))
                    out=bringup_lib.unconfigFeature(node_dict['all_dut'][dut], log, '-feature interface-vlan' )
                    if out.result=='fail':
                        log.error('Disable of Interface-vlan failed on VTEP {0}'.format(dut))
                        self.failed()
                    else:
                        log.info('Disable of Interface-vlan Successful on VTEP {0}'.format(dut))
 
                 
                log.info(banner('Waiting for 30 seconds before Enabling the Feature Interface-vlan on Vteps'))
                countDownTimer(30)
                 
                for dut in device_dict:
                    log.info('Removing the Feature Interface-vlan from the VTEP {0}'.format(dut))
                    out=bringup_lib.configFeature(node_dict['all_dut'][dut], log, '-feature interface-vlan' )
                    if out.result=='fail':
                        log.error('Disable of Interface-vlan failed on VTEP {0}'.format(dut))
                        self.failed()
                    else:
                        log.info('Disable of Interface-vlan Successful on VTEP {0}'.format(dut))
                        res = trigger_obj.backUpAndRestoreConfigs(dut.split(),'restore')
                 
                log.info(banner('Waiting for 500 seconds before getting the interface counters'))
                countDownTimer(500)
                 
                out = trigger_obj.checkAllStreamStats(tgn_hdl)
                 
                if not out:
                    log.error(banner('Traffic has not recovered on some of the streams after starting the Original Streams.. Collecting the individual STream stats:'))
                    traffic_obj.getAllBoundStreamStatistics(tgn_hdl)
                    cfg = 'interface nve 1 ; shutdown ; sleep 5 ; no shutdown'
                    [node_dict['all_dut'][dut].configure(cfg) for dut in list(device_dict.keys())]
                    countDownTimer(600)
                    self.failed()
 
            else:
                log.error('The Initial Traffic Condition did not pass:')
                traffic_obj.getAllBoundStreamStatistics(tgn_hdl)
                self.failed()  
 
class VXLANL3TRMVPCBLFUNC047(aetest.Testcase):
 
    """ Enable / disable of Pim feature """
 
    uid = 'VXLAN-L3-TRM-VPC-BL-FUNC-047'
 
    @aetest.test
    def enableDisablePim(self,log,testscript,testbed):
#         standalone_vtep_dict = testscript.parameters['standalone_vtep_dict']
        node_dict = testscript.parameters['node_dict']
        tg_interface_hdl_dict = testscript.parameters['tg_interface_hdl_dict'] 
        traffic_stream_dict = testscript.parameters['traffic_stream_dict'] 
#         port_handle_dict = testscript.parameters['port_handle_dict']
#         TGList_config_file = testscript.parameters['TGList']
        configdict = testscript.parameters['configdict'] 
        tgn_config_dict = configdict['TG']
        threshold = testscript.parameters['traffic_threshold']
        traffic_obj = testscript.parameters['traffic_obj']
        trigger_obj = testscript.parameters['trigger_obj']
        tgn_port_dut_mapping = testscript.parameters['tgn_port_dut_mapping']
         
        res = [node_dict['all_dut'][dut].configure('terminal session-timeout 0') for dut in node_dict['all_dut'] if re.search('uut', dut)]
         
        for TG in tgn_config_dict.keys():
            tgn_hdl = testscript.parameters['testbed_obj'].devices[TG]
            out = trigger_obj.checkAllStreamStats(tgn_hdl)
         
            if out:
                log.info(banner('Initial Traffic flow is as expected:'))
                traffic_obj.getAllBoundStreamStatistics(tgn_hdl)
                 
                log.info(banner('Taking Backup of configs on all the VTEPs:'))
                 
                device_dict = trigger_obj.getDeviceDict('all_vtep')
                 
                res = trigger_obj.backUpAndRestoreConfigs(list(device_dict.keys()),'backup')
                 
                log.info(banner('Removing the feature pim from all the VTEPs'))
                 
                for dut in device_dict:
                    log.info('Removing the Feature pim from the VTEP {0}'.format(dut))
                    out=bringup_lib.unconfigFeature(node_dict['all_dut'][dut], log, '-feature pim' )
                    if out.result=='fail':
                        log.error('Disable of pim failed on VTEP {0}'.format(dut))
                        self.failed()
                    else:
                        log.info('Disable of pim Successful on VTEP {0}'.format(dut))
 
                 
                log.info(banner('Waiting for 30 seconds before Enabling the Feature pim on Vteps'))
                countDownTimer(30)
                 
                for dut in device_dict:
                    log.info('Removing the Feature pim from the VTEP {0}'.format(dut))
                    out=bringup_lib.configFeature(node_dict['all_dut'][dut], log, '-feature pim' )
                    if out.result=='fail':
                        log.error('Disable of pim failed on VTEP {0}'.format(dut))
                        self.failed()
                    else:
                        log.info('Disable of pim Successful on VTEP {0}'.format(dut))
                        res = trigger_obj.backUpAndRestoreConfigs(dut.split(),'restore')
                 
                log.info(banner('Waiting for 60 seconds before getting the interface counters'))
                countDownTimer(300)
                 
                out = trigger_obj.checkAllStreamStats(tgn_hdl)
                 
                if not out:
                    log.error(banner('Traffic has not recovered on some of the streams after starting the Original Streams.. Collecting the individual STream stats:'))
                    traffic_obj.getAllBoundStreamStatistics(tgn_hdl)
                    cfg = 'interface nve 1 ; shutdown ; sleep 5 ; no shutdown'
                    [node_dict['all_dut'][dut].configure(cfg) for dut in list(device_dict.keys())]
                    countDownTimer(600)
                    self.failed()
 
            else:
                log.error('The Initial Traffic Condition did not pass:')
                traffic_obj.getAllBoundStreamStatistics(tgn_hdl)
                self.failed()  
                 
                 
class VXLANL3TRMVPCBLFUNC048(aetest.Testcase):
 
    """ Enable / disable of Ospf feature """
 
    uid = 'VXLAN-L3-TRM-VPC-BL-FUNC-048'
 
    @aetest.test
    def enableDisableOspf(self,log,testscript,testbed):
#         standalone_vtep_dict = testscript.parameters['standalone_vtep_dict']
        node_dict = testscript.parameters['node_dict']
        tg_interface_hdl_dict = testscript.parameters['tg_interface_hdl_dict'] 
        traffic_stream_dict = testscript.parameters['traffic_stream_dict'] 
#         port_handle_dict = testscript.parameters['port_handle_dict']
#         TGList_config_file = testscript.parameters['TGList']
        configdict = testscript.parameters['configdict'] 
        tgn_config_dict = configdict['TG']
        threshold = testscript.parameters['traffic_threshold']
        traffic_obj = testscript.parameters['traffic_obj']
        trigger_obj = testscript.parameters['trigger_obj']
        tgn_port_dut_mapping = testscript.parameters['tgn_port_dut_mapping']
         
        res = [node_dict['all_dut'][dut].configure('terminal session-timeout 0') for dut in node_dict['all_dut'] if re.search('uut', dut)]
         
        for TG in tgn_config_dict.keys():
            tgn_hdl = testscript.parameters['testbed_obj'].devices[TG]
            out = trigger_obj.checkAllStreamStats(tgn_hdl)
         
            if out:
                log.info(banner('Initial Traffic flow is as expected:'))
                traffic_obj.getAllBoundStreamStatistics(tgn_hdl)
                 
                log.info(banner('Taking Backup of configs on all the VTEPs:'))
                 
                device_dict = trigger_obj.getDeviceDict('all_vtep')
                 
                res = trigger_obj.backUpAndRestoreConfigs(list(device_dict.keys()),'backup')
                 
                log.info(banner('Removing the feature ospf from all the VTEPs'))
                 
                for dut in device_dict:
                    log.info('Removing the Feature Ospf from the VTEP {0}'.format(dut))
                    out=bringup_lib.unconfigFeature(node_dict['all_dut'][dut], log, '-feature ospf' )
                    if out.result=='fail':
                        log.error('Disable of Ospf failed on VTEP {0}'.format(dut))
                        self.failed()
                    else:
                        log.info('Disable of Ospf Successful on VTEP {0}'.format(dut))
 
                 
                log.info(banner('Waiting for 30 seconds before Enabling the Feature Ospf on Vteps'))
                countDownTimer(30)
                 
                for dut in device_dict:
                    log.info('Removing the Feature Ospf from the VTEP {0}'.format(dut))
                    out=bringup_lib.configFeature(node_dict['all_dut'][dut], log, '-feature ospf' )
                    if out.result=='fail':
                        log.error('Disable of Ospf failed on VTEP {0}'.format(dut))
                        self.failed()
                    else:
                        log.info('Disable of Ospf Successful on VTEP {0}'.format(dut))
                        res = trigger_obj.backUpAndRestoreConfigs(dut.split(),'restore')
                 
                log.info(banner('Waiting for 60 seconds before getting the interface counters'))
                countDownTimer(300)
                 
                out = trigger_obj.checkAllStreamStats(tgn_hdl)
                 
                if not out:
                    log.error(banner('Traffic has not recovered on some of the streams after starting the Original Streams.. Collecting the individual STream stats:'))
                    traffic_obj.getAllBoundStreamStatistics(tgn_hdl)
                    cfg = 'interface nve 1 ; shutdown ; sleep 5 ; no shutdown'
                    [node_dict['all_dut'][dut].configure(cfg) for dut in list(device_dict.keys())]
                    countDownTimer(600)
                    self.failed()
 
            else:
                log.error('The Initial Traffic Condition did not pass:')
                traffic_obj.getAllBoundStreamStatistics(tgn_hdl)
                self.failed()  
 
class VXLANL3TRMVPCBLFUNC049(aetest.Testcase):
 
    """ Enable / disable of VPC feature """
 
    uid = 'VXLAN-L3-TRM-VPC-BL-FUNC-049'
 
    @aetest.test
    def enableDisableVpc(self,log,testscript,testbed):
#         standalone_vtep_dict = testscript.parameters['standalone_vtep_dict']
        node_dict = testscript.parameters['node_dict']
        tg_interface_hdl_dict = testscript.parameters['tg_interface_hdl_dict'] 
        traffic_stream_dict = testscript.parameters['traffic_stream_dict'] 
#         port_handle_dict = testscript.parameters['port_handle_dict']
#         TGList_config_file = testscript.parameters['TGList']
        configdict = testscript.parameters['configdict'] 
        tgn_config_dict = configdict['TG']
        threshold = testscript.parameters['traffic_threshold']
        traffic_obj = testscript.parameters['traffic_obj']
        trigger_obj = testscript.parameters['trigger_obj']
        tgn_port_dut_mapping = testscript.parameters['tgn_port_dut_mapping']
         
        res = [node_dict['all_dut'][dut].configure('terminal session-timeout 0') for dut in node_dict['all_dut'] if re.search('uut', dut)]
         
        for TG in tgn_config_dict.keys():
            tgn_hdl = testscript.parameters['testbed_obj'].devices[TG]
            out = trigger_obj.checkAllStreamStats(tgn_hdl)
         
            if out:
                log.info(banner('Initial Traffic flow is as expected:'))
                traffic_obj.getAllBoundStreamStatistics(tgn_hdl)
                 
                log.info(banner('Taking Backup of configs on all the VTEPs:'))
                 
                device_dict = trigger_obj.getDeviceDict('vpc_vtep')
                 
                res = trigger_obj.backUpAndRestoreConfigs(list(device_dict.keys()),'backup')
                 
                log.info(banner('Removing the feature vpc from all the VTEPs'))
                 
                for dut in device_dict:
                    log.info('Removing the Feature vpc from the VTEP {0}'.format(dut))
                    out=bringup_lib.unconfigFeature(node_dict['all_dut'][dut], log, '-feature vpc' )
                    if out.result=='fail':
                        log.error('Disable of vPC failed on VTEP {0}'.format(dut))
                        self.failed()
                    else:
                        log.info('Disable of vPC Successful on VTEP {0}'.format(dut))
 
                 
                log.info(banner('Waiting for 30 seconds before Enabling the Feature vPC on Vteps'))
                countDownTimer(30)
                 
                for dut in device_dict:
                    log.info('Removing the Feature vPC from the VTEP {0}'.format(dut))
                    out=bringup_lib.configFeature(node_dict['all_dut'][dut], log, '-feature vpc' )
                    if out.result=='fail':
                        log.error('Disable of vPC failed on VTEP {0}'.format(dut))
                        self.failed()
                    else:
                        log.info('Disable of vPC Successful on VTEP {0}'.format(dut))
                        res = trigger_obj.backUpAndRestoreConfigs(dut.split(),'restore')
                 
                log.info(banner('Waiting for 60 seconds before getting the interface counters'))
                countDownTimer(360)
                 
                out = trigger_obj.checkAllStreamStats(tgn_hdl)
                 
                if not out:
                    log.error(banner('Traffic has not recovered on some of the streams after starting the Original Streams.. Collecting the individual STream stats:'))
                    traffic_obj.getAllBoundStreamStatistics(tgn_hdl)
                    cfg = 'interface nve 1 ; shutdown ; sleep 5 ; no shutdown'
                    [node_dict['all_dut'][dut].configure(cfg) for dut in list(device_dict.keys())]
                    countDownTimer(600)
                    self.failed()
 
            else:
                log.error('The Initial Traffic Condition did not pass:')
                traffic_obj.getAllBoundStreamStatistics(tgn_hdl)
                self.failed()  


class VXLANL3TRMVPCBLFUNC050(aetest.Testcase):
 
    """ clear ip igmp snooping entries"""
 
    uid = 'VXLAN-L3-TRM-VPC-BL-FUNC-050'
 
    @aetest.test
    def clearIpIGMPSnoopingEntries(self,log,testscript,testbed):
#         standalone_vtep_dict = testscript.parameters['standalone_vtep_dict']
        node_dict = testscript.parameters['node_dict']
        tg_interface_hdl_dict = testscript.parameters['tg_interface_hdl_dict'] 
        traffic_stream_dict = testscript.parameters['traffic_stream_dict'] 
#         port_handle_dict = testscript.parameters['port_handle_dict']
#         TGList_config_file = testscript.parameters['TGList']
        configdict = testscript.parameters['configdict'] 
        tgn_config_dict = configdict['TG']
        threshold = testscript.parameters['traffic_threshold']
        traffic_obj = testscript.parameters['traffic_obj']
        trigger_obj = testscript.parameters['trigger_obj']
        tgn_port_dut_mapping = testscript.parameters['tgn_port_dut_mapping']
         
        res = [node_dict['all_dut'][dut].configure('terminal session-timeout 0') for dut in node_dict['all_dut'] if re.search('uut', dut)]
         
        for TG in tgn_config_dict.keys():
            tgn_hdl = testscript.parameters['testbed_obj'].devices[TG]
            out = trigger_obj.checkAllStreamStats(tgn_hdl)
         
            if out:
                log.info(banner('Initial Traffic flow is as expected:'))
                traffic_obj.getAllBoundStreamStatistics(tgn_hdl)
                 
                log.info(banner('Taking Backup of configs on all the VTEPs:'))
                 
                device_dict = trigger_obj.getDeviceDict('all_vtep')
 
                log.info(banner('Clearing IGMP Snooping Groups from all the VTEPs'))
                 
                cfg = 'clear ip igmp snooping groups * vlan all'
                for dut in device_dict:
                    node_dict['all_dut'][dut].configure(cfg)
                 
                log.info(banner('Waiting for 100 seconds before collecting the Traffic Stats'))
                countDownTimer(150)    
                 
                out = trigger_obj.checkAllStreamStats(tgn_hdl)
                 
                if not out:
                    log.error(banner('Traffic has not recovered on some of the streams after starting the Original Streams.. Collecting the individual STream stats:'))
                    traffic_obj.getAllBoundStreamStatistics(tgn_hdl)
                    cfg = 'interface nve 1 ; shutdown ; sleep 5 ; no shutdown'
                    [node_dict['all_dut'][dut].configure(cfg) for dut in list(device_dict.keys())]
                    countDownTimer(300)
                    self.failed()
 
            else:
                log.error('The Initial Traffic Condition did not pass:')
                traffic_obj.getAllBoundStreamStatistics(tgn_hdl)
                self.failed()  
 
 
 
class VXLANL3TRMVPCBLFUNC051(aetest.Testcase):
 
    """ clear ip igmp group entries"""
 
    uid = 'VXLAN-L3-TRM-VPC-BL-FUNC-051'
 
    @aetest.test
    def clearIpIGMPGroupEntries(self,log,testscript,testbed):
#         standalone_vtep_dict = testscript.parameters['standalone_vtep_dict']
        node_dict = testscript.parameters['node_dict']
        tg_interface_hdl_dict = testscript.parameters['tg_interface_hdl_dict'] 
        traffic_stream_dict = testscript.parameters['traffic_stream_dict'] 
#         port_handle_dict = testscript.parameters['port_handle_dict']
#         TGList_config_file = testscript.parameters['TGList']
        configdict = testscript.parameters['configdict'] 
        tgn_config_dict = configdict['TG']
        threshold = testscript.parameters['traffic_threshold']
        traffic_obj = testscript.parameters['traffic_obj']
        trigger_obj = testscript.parameters['trigger_obj']
        tgn_port_dut_mapping = testscript.parameters['tgn_port_dut_mapping']
         
        res = [node_dict['all_dut'][dut].configure('terminal session-timeout 0') for dut in node_dict['all_dut'] if re.search('uut', dut)]
         
        for TG in tgn_config_dict.keys():
            tgn_hdl = testscript.parameters['testbed_obj'].devices[TG]
            out = trigger_obj.checkAllStreamStats(tgn_hdl)
         
            if out:
                log.info(banner('Initial Traffic flow is as expected:'))
                traffic_obj.getAllBoundStreamStatistics(tgn_hdl)
                 
                log.info(banner('Taking Backup of configs on all the VTEPs:'))
                 
                device_dict = trigger_obj.getDeviceDict('all_vtep')
 
                log.info(banner('Clearing IGMP Snooping Groups from all the VTEPs'))
                 
                cfg = 'clear ip igmp groups *  vrf all'
                for dut in device_dict:
                    node_dict['all_dut'][dut].configure(cfg)
                 
                log.info(banner('Waiting for 100 seconds before collecting the Traffic Stats'))
                countDownTimer(150)    
                 
                out = trigger_obj.checkAllStreamStats(tgn_hdl)
                 
                if not out:
                    log.error(banner('Traffic has not recovered on some of the streams after starting the Original Streams.. Collecting the individual STream stats:'))
                    traffic_obj.getAllBoundStreamStatistics(tgn_hdl)
                    cfg = 'interface nve 1 ; shutdown ; sleep 5 ; no shutdown'
                    [node_dict['all_dut'][dut].configure(cfg) for dut in list(device_dict.keys())]
                    countDownTimer(300)
                    self.failed()
 
            else:
                log.error('The Initial Traffic Condition did not pass:')
                traffic_obj.getAllBoundStreamStatistics(tgn_hdl)
                self.failed()  
 
class VXLANL3TRMVPCBLFUNC052(aetest.Testcase):
 
    """ clear ip mroute entries"""
 
    uid = 'VXLAN-L3-TRM-VPC-BL-FUNC-052'
 
    @aetest.test
    def clearIpMrouteEntries(self,log,testscript,testbed):
#         standalone_vtep_dict = testscript.parameters['standalone_vtep_dict']
        node_dict = testscript.parameters['node_dict']
        tg_interface_hdl_dict = testscript.parameters['tg_interface_hdl_dict'] 
        traffic_stream_dict = testscript.parameters['traffic_stream_dict'] 
#         port_handle_dict = testscript.parameters['port_handle_dict']
#         TGList_config_file = testscript.parameters['TGList']
        configdict = testscript.parameters['configdict'] 
        tgn_config_dict = configdict['TG']
        threshold = testscript.parameters['traffic_threshold']
        traffic_obj = testscript.parameters['traffic_obj']
        trigger_obj = testscript.parameters['trigger_obj']
        tgn_port_dut_mapping = testscript.parameters['tgn_port_dut_mapping']
         
        res = [node_dict['all_dut'][dut].configure('terminal session-timeout 0') for dut in node_dict['all_dut'] if re.search('uut', dut)]
         
        for TG in tgn_config_dict.keys():
            tgn_hdl = testscript.parameters['testbed_obj'].devices[TG]
            out = trigger_obj.checkAllStreamStats(tgn_hdl)
         
            if out:
                log.info(banner('Initial Traffic flow is as expected:'))
                traffic_obj.getAllBoundStreamStatistics(tgn_hdl)
                 
                log.info(banner('Taking Backup of configs on all the VTEPs:'))
                 
                device_dict = trigger_obj.getDeviceDict('all_vtep')
 
                log.info(banner('Clearing IGMP Snooping Groups from all the VTEPs'))
                 
                cfg = 'clear ip mroute * vrf all'
                for dut in device_dict:
                    node_dict['all_dut'][dut].configure(cfg)
                 
                log.info(banner('Waiting for 300 seconds before collecting the Traffic Stats'))
                countDownTimer(300)    
                 
                out = trigger_obj.checkAllStreamStats(tgn_hdl)
                 
                if not out:
                    log.error(banner('Traffic has not recovered on some of the streams after starting the Original Streams.. Collecting the individual STream stats:'))
                    traffic_obj.getAllBoundStreamStatistics(tgn_hdl)
                    cfg = 'interface nve 1 ; shutdown ; sleep 5 ; no shutdown'
                    [node_dict['all_dut'][dut].configure(cfg) for dut in list(device_dict.keys())]
                    countDownTimer(600)
                    self.failed()
 
            else:
                log.error('The Initial Traffic Condition did not pass:')
                traffic_obj.getAllBoundStreamStatistics(tgn_hdl)
                self.failed()  
                                                               
class VXLANL3TRMVPCBLFUNC053(aetest.Testcase):
 
    """ clear ip route entries"""
 
    uid = 'VXLAN-L3-TRM-VPC-BL-FUNC-053'
 
    @aetest.test
    def clearIpRouteEntries(self,log,testscript,testbed):
#         standalone_vtep_dict = testscript.parameters['standalone_vtep_dict']
        node_dict = testscript.parameters['node_dict']
        tg_interface_hdl_dict = testscript.parameters['tg_interface_hdl_dict'] 
        traffic_stream_dict = testscript.parameters['traffic_stream_dict'] 
#         port_handle_dict = testscript.parameters['port_handle_dict']
#         TGList_config_file = testscript.parameters['TGList']
        configdict = testscript.parameters['configdict'] 
        tgn_config_dict = configdict['TG']
        threshold = testscript.parameters['traffic_threshold']
        traffic_obj = testscript.parameters['traffic_obj']
        trigger_obj = testscript.parameters['trigger_obj']
        tgn_port_dut_mapping = testscript.parameters['tgn_port_dut_mapping']
         
        res = [node_dict['all_dut'][dut].configure('terminal session-timeout 0') for dut in node_dict['all_dut'] if re.search('uut', dut)]
         
        for TG in tgn_config_dict.keys():
            tgn_hdl = testscript.parameters['testbed_obj'].devices[TG]
            out = trigger_obj.checkAllStreamStats(tgn_hdl)
         
            if out:
                log.info(banner('Initial Traffic flow is as expected:'))
                traffic_obj.getAllBoundStreamStatistics(tgn_hdl)
                 
                log.info(banner('Taking Backup of configs on all the VTEPs:'))
                 
                device_dict = trigger_obj.getDeviceDict('all_vtep')
 
                log.info(banner('Clearing IGMP Snooping Groups from all the VTEPs'))
                 
                cfg = 'clear ip route vrf all *'
                for dut in device_dict:
                    node_dict['all_dut'][dut].configure(cfg)
                 
                log.info(banner('Waiting for 100 seconds before collecting the Traffic Stats'))
                countDownTimer(100)    
                 
                out = trigger_obj.checkAllStreamStats(tgn_hdl)
                 
                if not out:
                    log.error(banner('Traffic has not recovered on some of the streams after starting the Original Streams.. Collecting the individual STream stats:'))
                    traffic_obj.getAllBoundStreamStatistics(tgn_hdl)
                    cfg = 'interface nve 1 ; shutdown ; sleep 5 ; no shutdown'
                    [node_dict['all_dut'][dut].configure(cfg) for dut in list(device_dict.keys())]
                    countDownTimer(180)
                    self.failed()
 
            else:
                log.error('The Initial Traffic Condition did not pass:')
                traffic_obj.getAllBoundStreamStatistics(tgn_hdl)
                self.failed()  
 
class VXLANL3TRMVPCBLFUNC054(aetest.Testcase):
 
    """ clear ip BGP Route entries"""
 
    uid = 'VXLAN-L3-TRM-VPC-BL-FUNC-054'
 
    @aetest.test
    def clearIpBGPRouteEntries(self,log,testscript,testbed):
#         standalone_vtep_dict = testscript.parameters['standalone_vtep_dict']
        node_dict = testscript.parameters['node_dict']
        tg_interface_hdl_dict = testscript.parameters['tg_interface_hdl_dict'] 
        traffic_stream_dict = testscript.parameters['traffic_stream_dict'] 
#         port_handle_dict = testscript.parameters['port_handle_dict']
#         TGList_config_file = testscript.parameters['TGList']
        configdict = testscript.parameters['configdict'] 
        tgn_config_dict = configdict['TG']
        threshold = testscript.parameters['traffic_threshold']
        traffic_obj = testscript.parameters['traffic_obj']
        trigger_obj = testscript.parameters['trigger_obj']
        tgn_port_dut_mapping = testscript.parameters['tgn_port_dut_mapping']
         
        res = [node_dict['all_dut'][dut].configure('terminal session-timeout 0') for dut in node_dict['all_dut'] if re.search('uut', dut)]
         
        for TG in tgn_config_dict.keys():
            tgn_hdl = testscript.parameters['testbed_obj'].devices[TG]
            out = trigger_obj.checkAllStreamStats(tgn_hdl)
         
            if out:
                log.info(banner('Initial Traffic flow is as expected:'))
                traffic_obj.getAllBoundStreamStatistics(tgn_hdl)
                 
                log.info(banner('Taking Backup of configs on all the VTEPs:'))
                 
                device_dict = trigger_obj.getDeviceDict('all_vtep')
 
                log.info(banner('Clearing IGMP Snooping Groups from all the VTEPs'))
                 
                cfg = 'clear ip bgp * vrf all '
                for dut in device_dict:
                    node_dict['all_dut'][dut].configure(cfg)
                 
                log.info(banner('Waiting for 100 seconds before collecting the Traffic Stats'))
                countDownTimer(100)    
                 
                out = trigger_obj.checkAllStreamStats(tgn_hdl)
                 
                if not out:
                    log.error(banner('Traffic has not recovered on some of the streams after starting the Original Streams.. Collecting the individual STream stats:'))
                    traffic_obj.getAllBoundStreamStatistics(tgn_hdl)
                    cfg = 'interface nve 1 ; shutdown ; sleep 5 ; no shutdown'
                    [node_dict['all_dut'][dut].configure(cfg) for dut in list(device_dict.keys())]
                    countDownTimer(180)
                    self.failed()
 
            else:
                log.error('The Initial Traffic Condition did not pass:')
                traffic_obj.getAllBoundStreamStatistics(tgn_hdl)
                self.failed()
                 
class VXLANL3TRMVPCBLFUNC055(aetest.Testcase):
 
    """ clear ip ARP entries"""
 
    uid = 'VXLAN-L3-TRM-VPC-BL-FUNC-055'
 
    @aetest.test
    def clearIpARPEntries(self,log,testscript,testbed):
#         standalone_vtep_dict = testscript.parameters['standalone_vtep_dict']
        node_dict = testscript.parameters['node_dict']
        tg_interface_hdl_dict = testscript.parameters['tg_interface_hdl_dict'] 
        traffic_stream_dict = testscript.parameters['traffic_stream_dict'] 
#         port_handle_dict = testscript.parameters['port_handle_dict']
#         TGList_config_file = testscript.parameters['TGList']
        configdict = testscript.parameters['configdict'] 
        tgn_config_dict = configdict['TG']
        threshold = testscript.parameters['traffic_threshold']
        traffic_obj = testscript.parameters['traffic_obj']
        trigger_obj = testscript.parameters['trigger_obj']
        tgn_port_dut_mapping = testscript.parameters['tgn_port_dut_mapping']
         
        res = [node_dict['all_dut'][dut].configure('terminal session-timeout 0') for dut in node_dict['all_dut'] if re.search('uut', dut)]
         
        for TG in tgn_config_dict.keys():
            tgn_hdl = testscript.parameters['testbed_obj'].devices[TG]
            out = trigger_obj.checkAllStreamStats(tgn_hdl)
         
            if out:
                log.info(banner('Initial Traffic flow is as expected:'))
                traffic_obj.getAllBoundStreamStatistics(tgn_hdl)
                 
                log.info(banner('Taking Backup of configs on all the VTEPs:'))
                 
                device_dict = trigger_obj.getDeviceDict('all_vtep')
 
                log.info(banner('Clearing IGMP Snooping Groups from all the VTEPs'))
                 
                cfg = 'clear ip arp vrf all force-delete'
                for dut in device_dict:
                    node_dict['all_dut'][dut].configure(cfg)
                 
                log.info(banner('Waiting for 100 seconds before collecting the Traffic Stats'))
                countDownTimer(100)    
                 
                out = trigger_obj.checkAllStreamStats(tgn_hdl)
                 
                if not out:
                    log.error(banner('Traffic has not recovered on some of the streams after starting the Original Streams.. Collecting the individual STream stats:'))
                    traffic_obj.getAllBoundStreamStatistics(tgn_hdl)
                    cfg = 'interface nve 1 ; shutdown ; sleep 5 ; no shutdown'
                    [node_dict['all_dut'][dut].configure(cfg) for dut in list(device_dict.keys())]
                    countDownTimer(180)
                    self.failed()
 
            else:
                log.error('The Initial Traffic Condition did not pass:')
                traffic_obj.getAllBoundStreamStatistics(tgn_hdl)
                self.failed()
 
class VXLANL3TRMVPCBLFUNC056(aetest.Testcase):
 
    """ clear ip PIM Route entries"""
 
    uid = 'VXLAN-L3-TRM-VPC-BL-FUNC-056'
 
    @aetest.test
    def clearIpPIMRouteEntries(self,log,testscript,testbed):
#         standalone_vtep_dict = testscript.parameters['standalone_vtep_dict']
        node_dict = testscript.parameters['node_dict']
        tg_interface_hdl_dict = testscript.parameters['tg_interface_hdl_dict'] 
        traffic_stream_dict = testscript.parameters['traffic_stream_dict'] 
#         port_handle_dict = testscript.parameters['port_handle_dict']
#         TGList_config_file = testscript.parameters['TGList']
        configdict = testscript.parameters['configdict'] 
        tgn_config_dict = configdict['TG']
        threshold = testscript.parameters['traffic_threshold']
        traffic_obj = testscript.parameters['traffic_obj']
        trigger_obj = testscript.parameters['trigger_obj']
        tgn_port_dut_mapping = testscript.parameters['tgn_port_dut_mapping']
         
        res = [node_dict['all_dut'][dut].configure('terminal session-timeout 0') for dut in node_dict['all_dut'] if re.search('uut', dut)]
         
        for TG in tgn_config_dict.keys():
            tgn_hdl = testscript.parameters['testbed_obj'].devices[TG]
            out = trigger_obj.checkAllStreamStats(tgn_hdl)
         
            if out:
                log.info(banner('Initial Traffic flow is as expected:'))
                traffic_obj.getAllBoundStreamStatistics(tgn_hdl)
                 
                log.info(banner('Taking Backup of configs on all the VTEPs:'))
                 
                device_dict = trigger_obj.getDeviceDict('all_vtep')
 
                log.info(banner('Clearing IGMP Snooping Groups from all the VTEPs'))
                 
                cfg = 'clear ip pim route * vrf all '
                for dut in device_dict:
                    node_dict['all_dut'][dut].configure(cfg)
                 
                log.info(banner('Waiting for 100 seconds before collecting the Traffic Stats'))
                countDownTimer(200)    
                 
                out = trigger_obj.checkAllStreamStats(tgn_hdl)
                 
                if not out:
                    log.error(banner('Traffic has not recovered on some of the streams after starting the Original Streams.. Collecting the individual STream stats:'))
                    traffic_obj.getAllBoundStreamStatistics(tgn_hdl)
                    cfg = 'interface nve 1 ; shutdown ; sleep 5 ; no shutdown'
                    [node_dict['all_dut'][dut].configure(cfg) for dut in list(device_dict.keys())]
                    countDownTimer(600)
                    self.failed()
 
            else:
                log.error('The Initial Traffic Condition did not pass:')
                traffic_obj.getAllBoundStreamStatistics(tgn_hdl)
                self.failed()
 
class VXLANL3TRMVPCBLFUNC057(aetest.Testcase):
 
    """ clear ip MBGP Route entries"""
 
    uid = 'VXLAN-L3-TRM-VPC-BL-FUNC-057'
 
    @aetest.test
    def clearMBGPRouteEntries(self,log,testscript,testbed):
#         standalone_vtep_dict = testscript.parameters['standalone_vtep_dict']
        node_dict = testscript.parameters['node_dict']
        tg_interface_hdl_dict = testscript.parameters['tg_interface_hdl_dict'] 
        traffic_stream_dict = testscript.parameters['traffic_stream_dict'] 
#         port_handle_dict = testscript.parameters['port_handle_dict']
#         TGList_config_file = testscript.parameters['TGList']
        configdict = testscript.parameters['configdict'] 
        tgn_config_dict = configdict['TG']
        threshold = testscript.parameters['traffic_threshold']
        traffic_obj = testscript.parameters['traffic_obj']
        trigger_obj = testscript.parameters['trigger_obj']
        tgn_port_dut_mapping = testscript.parameters['tgn_port_dut_mapping']
         
        res = [node_dict['all_dut'][dut].configure('terminal session-timeout 0') for dut in node_dict['all_dut'] if re.search('uut', dut)]
         
        for TG in tgn_config_dict.keys():
            tgn_hdl = testscript.parameters['testbed_obj'].devices[TG]
            out = trigger_obj.checkAllStreamStats(tgn_hdl)
         
            if out:
                log.info(banner('Initial Traffic flow is as expected:'))
                traffic_obj.getAllBoundStreamStatistics(tgn_hdl)
                 
                log.info(banner('Taking Backup of configs on all the VTEPs:'))
                 
                device_dict = trigger_obj.getDeviceDict('all_vtep')
 
                log.info(banner('Clearing IGMP Snooping Groups from all the VTEPs'))
                 
                cfg = 'clear ip mbgp * vrf all'
                for dut in device_dict:
                    node_dict['all_dut'][dut].configure(cfg)
                 
                log.info(banner('Waiting for 100 seconds before collecting the Traffic Stats'))
                countDownTimer(200)    
                 
                out = trigger_obj.checkAllStreamStats(tgn_hdl)
                 
                if not out:
                    log.error(banner('Traffic has not recovered on some of the streams after starting the Original Streams.. Collecting the individual STream stats:'))
                    traffic_obj.getAllBoundStreamStatistics(tgn_hdl)
                    cfg = 'interface nve 1 ; shutdown ; sleep 5 ; no shutdown'
                    [node_dict['all_dut'][dut].configure(cfg) for dut in list(device_dict.keys())]
                    countDownTimer(180)
                    self.failed()
 
            else:
                log.error('The Initial Traffic Condition did not pass:')
                traffic_obj.getAllBoundStreamStatistics(tgn_hdl)
                self.failed()


class VXLANL3TRMVPCBLFUNC058(aetest.Testcase):
 
    """ Kill IGMP Process """
 
    uid = 'VXLAN-L3-TRM-VPC-BL-FUNC-058'
 
    @aetest.test
    def killIGMPProcess(self,log,testscript,testbed):
#         standalone_vtep_dict = testscript.parameters['standalone_vtep_dict']
        node_dict = testscript.parameters['node_dict']
        tg_interface_hdl_dict = testscript.parameters['tg_interface_hdl_dict'] 
        traffic_stream_dict = testscript.parameters['traffic_stream_dict'] 
#         port_handle_dict = testscript.parameters['port_handle_dict']
#         TGList_config_file = testscript.parameters['TGList']
        configdict = testscript.parameters['configdict'] 
        tgn_config_dict = configdict['TG']
        threshold = testscript.parameters['traffic_threshold']
        traffic_obj = testscript.parameters['traffic_obj']
        trigger_obj = testscript.parameters['trigger_obj']
        tgn_port_dut_mapping = testscript.parameters['tgn_port_dut_mapping']
         
        res = [node_dict['all_dut'][dut].configure('terminal session-timeout 0') for dut in node_dict['all_dut'] if re.search('uut', dut)]
         
        for TG in tgn_config_dict.keys():
            tgn_hdl = testscript.parameters['testbed_obj'].devices[TG]
            out = trigger_obj.checkAllStreamStats(tgn_hdl)
         
            if out:
                log.info(banner('Initial Traffic flow is as expected:'))
                traffic_obj.getAllBoundStreamStatistics(tgn_hdl)
                 
                log.info(banner('Taking Backup of configs on all the VTEPs:'))
                 
                device_dict = trigger_obj.getDeviceDict('all_vtep')
 
                log.info(banner('Killing IGMP Process from all the VTEPs'))
                 
                for dut in device_dict:
                    res = verifyProcessRestart(node_dict['all_dut'][dut],'igmp')
                     
                    if not res:
                        log.error('Process restart failed on the dut {0}'.format(dut))
                 
                log.info(banner('Waiting for 30 seconds before getting the Traffic Stats'))
                countDownTimer(30)
                 
                out = trigger_obj.checkAllStreamStats(tgn_hdl)
                 
                if not out:
                    log.error(banner('Traffic has not recovered on some of the streams after starting the Original Streams.. Collecting the individual STream stats:'))
                    traffic_obj.getAllBoundStreamStatistics(tgn_hdl)
                    cfg = 'interface nve 1 ; shutdown ; sleep 5 ; no shutdown'
                    [node_dict['all_dut'][dut].configure(cfg) for dut in list(device_dict.keys())]
                    countDownTimer(180)
                    self.failed()
 
            else:
                log.error('The Initial Traffic Condition did not pass:')
                traffic_obj.getAllBoundStreamStatistics(tgn_hdl)
                self.failed()  
         
class VXLANL3TRMVPCBLFUNC059(aetest.Testcase):
 
    """ Kill L2RIB Process """
 
    uid = 'VXLAN-L3-TRM-VPC-BL-FUNC-059'
 
    @aetest.test
    def killL2ribProcess(self,log,testscript,testbed):
#         standalone_vtep_dict = testscript.parameters['standalone_vtep_dict']
        node_dict = testscript.parameters['node_dict']
        tg_interface_hdl_dict = testscript.parameters['tg_interface_hdl_dict'] 
        traffic_stream_dict = testscript.parameters['traffic_stream_dict'] 
#         port_handle_dict = testscript.parameters['port_handle_dict']
#         TGList_config_file = testscript.parameters['TGList']
        configdict = testscript.parameters['configdict'] 
        tgn_config_dict = configdict['TG']
        threshold = testscript.parameters['traffic_threshold']
        traffic_obj = testscript.parameters['traffic_obj']
        trigger_obj = testscript.parameters['trigger_obj']
        tgn_port_dut_mapping = testscript.parameters['tgn_port_dut_mapping']
         
        res = [node_dict['all_dut'][dut].configure('terminal session-timeout 0') for dut in node_dict['all_dut'] if re.search('uut', dut)]
         
        for TG in tgn_config_dict.keys():
            tgn_hdl = testscript.parameters['testbed_obj'].devices[TG]
            out = trigger_obj.checkAllStreamStats(tgn_hdl)
         
            if out:
                log.info(banner('Initial Traffic flow is as expected:'))
                traffic_obj.getAllBoundStreamStatistics(tgn_hdl)
                 
                log.info(banner('Taking Backup of configs on all the VTEPs:'))
                 
                device_dict = trigger_obj.getDeviceDict('all_vtep')
 
                log.info(banner('Killing IGMP Process from all the VTEPs'))
                 
                for dut in device_dict:
                    res = verifyProcessRestart(node_dict['all_dut'][dut],'l2rib')
                     
                    if not res:
                        log.error('Process restart failed on the dut {0}'.format(dut))
                 
                log.info(banner('Waiting for 30 seconds before getting the Traffic Stats'))
                countDownTimer(30)
                 
                out = trigger_obj.checkAllStreamStats(tgn_hdl)
                 
                if not out:
                    log.error(banner('Traffic has not recovered on some of the streams after starting the Original Streams.. Collecting the individual STream stats:'))
                    traffic_obj.getAllBoundStreamStatistics(tgn_hdl)
                    cfg = 'interface nve 1 ; shutdown ; sleep 5 ; no shutdown'
                    [node_dict['all_dut'][dut].configure(cfg) for dut in list(device_dict.keys())]
                    countDownTimer(180)
                    self.failed()
 
            else:
                log.error('The Initial Traffic Condition did not pass:')
                traffic_obj.getAllBoundStreamStatistics(tgn_hdl)
                self.failed()  
         
class VXLANL3TRMVPCBLFUNC060(aetest.Testcase):
 
    """ Kill BGP Process """
 
    uid = 'VXLAN-L3-TRM-VPC-BL-FUNC-060'
 
    @aetest.test
    def killBGPProcess(self,log,testscript,testbed):
#         standalone_vtep_dict = testscript.parameters['standalone_vtep_dict']
        node_dict = testscript.parameters['node_dict']
        tg_interface_hdl_dict = testscript.parameters['tg_interface_hdl_dict'] 
        traffic_stream_dict = testscript.parameters['traffic_stream_dict'] 
#         port_handle_dict = testscript.parameters['port_handle_dict']
#         TGList_config_file = testscript.parameters['TGList']
        configdict = testscript.parameters['configdict'] 
        tgn_config_dict = configdict['TG']
        threshold = testscript.parameters['traffic_threshold']
        traffic_obj = testscript.parameters['traffic_obj']
        trigger_obj = testscript.parameters['trigger_obj']
        tgn_port_dut_mapping = testscript.parameters['tgn_port_dut_mapping']
         
        res = [node_dict['all_dut'][dut].configure('terminal session-timeout 0') for dut in node_dict['all_dut'] if re.search('uut', dut)]
         
        for TG in tgn_config_dict.keys():
            tgn_hdl = testscript.parameters['testbed_obj'].devices[TG]
            out = trigger_obj.checkAllStreamStats(tgn_hdl)
         
            if out:
                log.info(banner('Initial Traffic flow is as expected:'))
                traffic_obj.getAllBoundStreamStatistics(tgn_hdl)
                 
                log.info(banner('Taking Backup of configs on all the VTEPs:'))
                 
                device_dict = trigger_obj.getDeviceDict('all_vtep')
 
                log.info(banner('Killing IGMP Process from all the VTEPs'))
                 
                for dut in device_dict:
                    res = verifyProcessRestart(node_dict['all_dut'][dut],'bgp')
                     
                    if not res:
                        log.error('Process restart failed on the dut {0}'.format(dut))
                 
                log.info(banner('Waiting for 30 seconds before getting the Traffic Stats'))
                countDownTimer(30)
                 
                out = trigger_obj.checkAllStreamStats(tgn_hdl)
                 
                if not out:
                    log.error(banner('Traffic has not recovered on some of the streams after starting the Original Streams.. Collecting the individual STream stats:'))
                    traffic_obj.getAllBoundStreamStatistics(tgn_hdl)
                    cfg = 'interface nve 1 ; shutdown ; sleep 5 ; no shutdown'
                    [node_dict['all_dut'][dut].configure(cfg) for dut in list(device_dict.keys())]
                    countDownTimer(180)
                    self.failed()
 
            else:
                log.error('The Initial Traffic Condition did not pass:')
                traffic_obj.getAllBoundStreamStatistics(tgn_hdl)
                self.failed()  
         
         
class VXLANL3TRMVPCBLFUNC061(aetest.Testcase):
 
    """ Kill MFDM Process """
 
    uid = 'VXLAN-L3-TRM-VPC-BL-FUNC-061'
 
    @aetest.test
    def killMFDMProcess(self,log,testscript,testbed):
#         standalone_vtep_dict = testscript.parameters['standalone_vtep_dict']
        node_dict = testscript.parameters['node_dict']
        tg_interface_hdl_dict = testscript.parameters['tg_interface_hdl_dict'] 
        traffic_stream_dict = testscript.parameters['traffic_stream_dict'] 
#         port_handle_dict = testscript.parameters['port_handle_dict']
#         TGList_config_file = testscript.parameters['TGList']
        configdict = testscript.parameters['configdict'] 
        tgn_config_dict = configdict['TG']
        threshold = testscript.parameters['traffic_threshold']
        traffic_obj = testscript.parameters['traffic_obj']
        trigger_obj = testscript.parameters['trigger_obj']
        tgn_port_dut_mapping = testscript.parameters['tgn_port_dut_mapping']
         
        res = [node_dict['all_dut'][dut].configure('terminal session-timeout 0') for dut in node_dict['all_dut'] if re.search('uut', dut)]
         
        for TG in tgn_config_dict.keys():
            tgn_hdl = testscript.parameters['testbed_obj'].devices[TG]
            out = trigger_obj.checkAllStreamStats(tgn_hdl)
         
            if out:
                log.info(banner('Initial Traffic flow is as expected:'))
                traffic_obj.getAllBoundStreamStatistics(tgn_hdl)
                 
                log.info(banner('Taking Backup of configs on all the VTEPs:'))
                 
                device_dict = trigger_obj.getDeviceDict('all_vtep')
 
                log.info(banner('Killing IGMP Process from all the VTEPs'))
                 
                for dut in device_dict:
                    res = verifyProcessRestart(node_dict['all_dut'][dut],'mfdm')
                     
                    if not res:
                        log.error('Process restart failed on the dut {0}'.format(dut))
                 
                log.info(banner('Waiting for 30 seconds before getting the Traffic Stats'))
                countDownTimer(30)
                 
                out = trigger_obj.checkAllStreamStats(tgn_hdl)
                 
                if not out:
                    log.error(banner('Traffic has not recovered on some of the streams after starting the Original Streams.. Collecting the individual STream stats:'))
                    traffic_obj.getAllBoundStreamStatistics(tgn_hdl)
                    cfg = 'interface nve 1 ; shutdown ; sleep 5 ; no shutdown'
                    [node_dict['all_dut'][dut].configure(cfg) for dut in list(device_dict.keys())]
                    countDownTimer(180)
                    self.failed()
 
            else:
                log.error('The Initial Traffic Condition did not pass:')
                traffic_obj.getAllBoundStreamStatistics(tgn_hdl)
                self.failed()  
         
class VXLANL3TRMVPCBLFUNC062(aetest.Testcase):
 
    """ Kill ufdm Process """
 
    uid = 'VXLAN-L3-TRM-VPC-BL-FUNC-062'
 
    @aetest.test
    def killUFDMProcess(self,log,testscript,testbed):
#         standalone_vtep_dict = testscript.parameters['standalone_vtep_dict']
        node_dict = testscript.parameters['node_dict']
        tg_interface_hdl_dict = testscript.parameters['tg_interface_hdl_dict'] 
        traffic_stream_dict = testscript.parameters['traffic_stream_dict'] 
#         port_handle_dict = testscript.parameters['port_handle_dict']
#         TGList_config_file = testscript.parameters['TGList']
        configdict = testscript.parameters['configdict'] 
        tgn_config_dict = configdict['TG']
        threshold = testscript.parameters['traffic_threshold']
        traffic_obj = testscript.parameters['traffic_obj']
        trigger_obj = testscript.parameters['trigger_obj']
        tgn_port_dut_mapping = testscript.parameters['tgn_port_dut_mapping']
         
        res = [node_dict['all_dut'][dut].configure('terminal session-timeout 0') for dut in node_dict['all_dut'] if re.search('uut', dut)]
         
        for TG in tgn_config_dict.keys():
            tgn_hdl = testscript.parameters['testbed_obj'].devices[TG]
            out = trigger_obj.checkAllStreamStats(tgn_hdl)
         
            if out:
                log.info(banner('Initial Traffic flow is as expected:'))
                traffic_obj.getAllBoundStreamStatistics(tgn_hdl)
                 
                log.info(banner('Taking Backup of configs on all the VTEPs:'))
                 
                device_dict = trigger_obj.getDeviceDict('all_vtep')
 
                log.info(banner('Killing IGMP Process from all the VTEPs'))
                 
                for dut in device_dict:
                    res = verifyProcessRestart(node_dict['all_dut'][dut],'ufdm')
                     
                    if not res:
                        log.error('Process restart failed on the dut {0}'.format(dut))
                 
                log.info(banner('Waiting for 30 seconds before getting the Traffic Stats'))
                countDownTimer(30)
                 
                out = trigger_obj.checkAllStreamStats(tgn_hdl)
                 
                if not out:
                    log.error(banner('Traffic has not recovered on some of the streams after starting the Original Streams.. Collecting the individual STream stats:'))
                    traffic_obj.getAllBoundStreamStatistics(tgn_hdl)
                    cfg = 'interface nve 1 ; shutdown ; sleep 5 ; no shutdown'
                    [node_dict['all_dut'][dut].configure(cfg) for dut in list(device_dict.keys())]
                    countDownTimer(180)
                    self.failed()
 
            else:
                log.error('The Initial Traffic Condition did not pass:')
                traffic_obj.getAllBoundStreamStatistics(tgn_hdl)
                self.failed()  
         
class VXLANL3TRMVPCBLFUNC063(aetest.Testcase):
 
    """ Kill nve Process """
 
    uid = 'VXLAN-L3-TRM-VPC-BL-FUNC-063'
 
    @aetest.test
    def killNVEProcess(self,log,testscript,testbed):
#         standalone_vtep_dict = testscript.parameters['standalone_vtep_dict']
        node_dict = testscript.parameters['node_dict']
        tg_interface_hdl_dict = testscript.parameters['tg_interface_hdl_dict'] 
        traffic_stream_dict = testscript.parameters['traffic_stream_dict'] 
#         port_handle_dict = testscript.parameters['port_handle_dict']
#         TGList_config_file = testscript.parameters['TGList']
        configdict = testscript.parameters['configdict'] 
        tgn_config_dict = configdict['TG']
        threshold = testscript.parameters['traffic_threshold']
        traffic_obj = testscript.parameters['traffic_obj']
        trigger_obj = testscript.parameters['trigger_obj']
        tgn_port_dut_mapping = testscript.parameters['tgn_port_dut_mapping']
         
        res = [node_dict['all_dut'][dut].configure('terminal session-timeout 0') for dut in node_dict['all_dut'] if re.search('uut', dut)]
         
        for TG in tgn_config_dict.keys():
            tgn_hdl = testscript.parameters['testbed_obj'].devices[TG]
            out = trigger_obj.checkAllStreamStats(tgn_hdl)
         
            if out:
                log.info(banner('Initial Traffic flow is as expected:'))
                traffic_obj.getAllBoundStreamStatistics(tgn_hdl)
                 
                log.info(banner('Taking Backup of configs on all the VTEPs:'))
                 
                device_dict = trigger_obj.getDeviceDict('all_vtep')
 
                log.info(banner('Killing IGMP Process from all the VTEPs'))
                 
                for dut in device_dict:
                    res = verifyProcessRestart(node_dict['all_dut'][dut],'nve')
                     
                    if not res:
                        log.error('Process restart failed on the dut {0}'.format(dut))
                 
                log.info(banner('Waiting for 30 seconds before getting the Traffic Stats'))
                countDownTimer(30)
                 
                out = trigger_obj.checkAllStreamStats(tgn_hdl)
                 
                if not out:
                    log.error(banner('Traffic has not recovered on some of the streams after starting the Original Streams.. Collecting the individual STream stats:'))
                    traffic_obj.getAllBoundStreamStatistics(tgn_hdl)
                    cfg = 'interface nve 1 ; shutdown ; sleep 5 ; no shutdown'
                    [node_dict['all_dut'][dut].configure(cfg) for dut in list(device_dict.keys())]
                    countDownTimer(180)
                    self.failed()
 
            else:
                log.error('The Initial Traffic Condition did not pass:')
                traffic_obj.getAllBoundStreamStatistics(tgn_hdl)
                self.failed()  
                                        
         
class VXLANL3TRMVPCBLFUNC064(aetest.Testcase):
 
    """ Kill pim Process """
 
    uid = 'VXLAN-L3-TRM-VPC-BL-FUNC-064'
 
    @aetest.test
    def killPIMProcess(self,log,testscript,testbed):
#         standalone_vtep_dict = testscript.parameters['standalone_vtep_dict']
        node_dict = testscript.parameters['node_dict']
        tg_interface_hdl_dict = testscript.parameters['tg_interface_hdl_dict'] 
        traffic_stream_dict = testscript.parameters['traffic_stream_dict'] 
#         port_handle_dict = testscript.parameters['port_handle_dict']
#         TGList_config_file = testscript.parameters['TGList']
        configdict = testscript.parameters['configdict'] 
        tgn_config_dict = configdict['TG']
        threshold = testscript.parameters['traffic_threshold']
        traffic_obj = testscript.parameters['traffic_obj']
        trigger_obj = testscript.parameters['trigger_obj']
        tgn_port_dut_mapping = testscript.parameters['tgn_port_dut_mapping']
         
        res = [node_dict['all_dut'][dut].configure('terminal session-timeout 0') for dut in node_dict['all_dut'] if re.search('uut', dut)]
         
        for TG in tgn_config_dict.keys():
            tgn_hdl = testscript.parameters['testbed_obj'].devices[TG]
            out = trigger_obj.checkAllStreamStats(tgn_hdl)
         
            if out:
                log.info(banner('Initial Traffic flow is as expected:'))
                traffic_obj.getAllBoundStreamStatistics(tgn_hdl)
                 
                log.info(banner('Taking Backup of configs on all the VTEPs:'))
                 
                device_dict = trigger_obj.getDeviceDict('all_vtep')
 
                log.info(banner('Killing IGMP Process from all the VTEPs'))
                 
                for dut in device_dict:
                    res = verifyProcessRestart(node_dict['all_dut'][dut],'pim')
                     
                    if not res:
                        log.error('Process restart failed on the dut {0}'.format(dut))
                 
                log.info(banner('Waiting for 30 seconds before getting the Traffic Stats'))
                countDownTimer(200)
                 
                out = trigger_obj.checkAllStreamStats(tgn_hdl)
                 
                if not out:
                    log.error(banner('Traffic has not recovered on some of the streams after starting the Original Streams.. Collecting the individual STream stats:'))
                    traffic_obj.getAllBoundStreamStatistics(tgn_hdl)
                    cfg = 'interface nve 1 ; shutdown ; sleep 5 ; no shutdown'
                    [node_dict['all_dut'][dut].configure(cfg) for dut in list(device_dict.keys())]
                    countDownTimer(300)
                    self.failed()
 
            else:
                log.error('The Initial Traffic Condition did not pass:')
                traffic_obj.getAllBoundStreamStatistics(tgn_hdl)
                self.failed()  


class VXLANL3TRMVPCBLFUNC065(aetest.Testcase):
 
    """ restart ospf Process """
 
    uid = 'VXLAN-L3-TRM-VPC-BL-FUNC-065'
 
    @aetest.test
    def restartOSPFProcess(self,log,testscript,testbed):
#         standalone_vtep_dict = testscript.parameters['standalone_vtep_dict']
        node_dict = testscript.parameters['node_dict']
        tg_interface_hdl_dict = testscript.parameters['tg_interface_hdl_dict'] 
        traffic_stream_dict = testscript.parameters['traffic_stream_dict'] 
#         port_handle_dict = testscript.parameters['port_handle_dict']
#         TGList_config_file = testscript.parameters['TGList']
        configdict = testscript.parameters['configdict'] 
        tgn_config_dict = configdict['TG']
        threshold = testscript.parameters['traffic_threshold']
        traffic_obj = testscript.parameters['traffic_obj']
        trigger_obj = testscript.parameters['trigger_obj']
        tgn_port_dut_mapping = testscript.parameters['tgn_port_dut_mapping']
         
        res = [node_dict['all_dut'][dut].configure('terminal session-timeout 0') for dut in node_dict['all_dut'] if re.search('uut', dut)]
         
        for TG in tgn_config_dict.keys():
            tgn_hdl = testscript.parameters['testbed_obj'].devices[TG]
            out = trigger_obj.checkAllStreamStats(tgn_hdl)
         
            if out:
                log.info(banner('Initial Traffic flow is as expected:'))
                traffic_obj.getAllBoundStreamStatistics(tgn_hdl)
                 
                log.info(banner('Taking Backup of configs on all the VTEPs:'))
                 
                device_dict = trigger_obj.getDeviceDict('all_vtep')
 
                log.info(banner('Restarting  OSPF Process from all the VTEPs'))
                 
                for dut in device_dict:
                    res = verifyProcessRestartWithFlushRoutes(node_dict['all_dut'][dut],'ospf', process_id = 'vxlan')
                     
                    if not res:
                        log.error('Process restart failed on the dut {0}'.format(dut))
                 
                log.info(banner('Waiting for 30 seconds before getting the Traffic Stats'))
                countDownTimer(100)
                 
                out = trigger_obj.checkAllStreamStats(tgn_hdl)
                 
                if not out:
                    log.error(banner('Traffic has not recovered on some of the streams after starting the Original Streams.. Collecting the individual STream stats:'))
                    traffic_obj.getAllBoundStreamStatistics(tgn_hdl)
                    cfg = 'interface nve 1 ; shutdown ; sleep 5 ; no shutdown'
                    [node_dict['all_dut'][dut].configure(cfg) for dut in list(device_dict.keys())]
                    countDownTimer(180)
                    self.failed()
 
            else:
                log.error('The Initial Traffic Condition did not pass:')
                traffic_obj.getAllBoundStreamStatistics(tgn_hdl)
                self.failed()  
                                        
class VXLANL3TRMVPCBLFUNC066(aetest.Testcase):
 
    """ restart bgp Process """
 
    uid = 'VXLAN-L3-TRM-VPC-BL-FUNC-066'
 
    @aetest.test
    def restartBGPProcess(self,log,testscript,testbed):
#         standalone_vtep_dict = testscript.parameters['standalone_vtep_dict']
        node_dict = testscript.parameters['node_dict']
        tg_interface_hdl_dict = testscript.parameters['tg_interface_hdl_dict'] 
        traffic_stream_dict = testscript.parameters['traffic_stream_dict'] 
#         port_handle_dict = testscript.parameters['port_handle_dict']
#         TGList_config_file = testscript.parameters['TGList']
        configdict = testscript.parameters['configdict'] 
        tgn_config_dict = configdict['TG']
        threshold = testscript.parameters['traffic_threshold']
        traffic_obj = testscript.parameters['traffic_obj']
        trigger_obj = testscript.parameters['trigger_obj']
        tgn_port_dut_mapping = testscript.parameters['tgn_port_dut_mapping']
         
        res = [node_dict['all_dut'][dut].configure('terminal session-timeout 0') for dut in node_dict['all_dut'] if re.search('uut', dut)]
         
        for TG in tgn_config_dict.keys():
            tgn_hdl = testscript.parameters['testbed_obj'].devices[TG]
            out = trigger_obj.checkAllStreamStats(tgn_hdl)
         
            if out:
                log.info(banner('Initial Traffic flow is as expected:'))
                traffic_obj.getAllBoundStreamStatistics(tgn_hdl)
                 
                log.info(banner('Taking Backup of configs on all the VTEPs:'))
                 
                device_dict = trigger_obj.getDeviceDict('all_vtep')
 
                log.info(banner('Restarting  OSPF Process from all the VTEPs'))
                 
                for dut in device_dict:
                    res = verifyProcessRestartWithFlushRoutes(node_dict['all_dut'][dut],'bgp', process_id = '65100')
                     
                    if not res:
                        log.error('Process restart failed on the dut {0}'.format(dut))
                 
                log.info(banner('Waiting for 30 seconds before getting the Traffic Stats'))
                countDownTimer(100)
                 
                out = trigger_obj.checkAllStreamStats(tgn_hdl)
                 
                if not out:
                    log.error(banner('Traffic has not recovered on some of the streams after starting the Original Streams.. Collecting the individual STream stats:'))
                    traffic_obj.getAllBoundStreamStatistics(tgn_hdl)
                    cfg = 'interface nve 1 ; shutdown ; sleep 5 ; no shutdown'
                    [node_dict['all_dut'][dut].configure(cfg) for dut in list(device_dict.keys())]
                    countDownTimer(180)
                    self.failed()
 
            else:
                log.error('The Initial Traffic Condition did not pass:')
                traffic_obj.getAllBoundStreamStatistics(tgn_hdl)
                self.failed()  
 
class VXLANL3TRMVPCBLFUNC067(aetest.Testcase):
 
    """ restart ngmvpn Process """
 
    uid = 'VXLAN-L3-TRM-VPC-BL-FUNC-067'
 
    @aetest.test
    def restartNGMPVNProcess(self,log,testscript,testbed):
#         standalone_vtep_dict = testscript.parameters['standalone_vtep_dict']
        node_dict = testscript.parameters['node_dict']
        tg_interface_hdl_dict = testscript.parameters['tg_interface_hdl_dict'] 
        traffic_stream_dict = testscript.parameters['traffic_stream_dict'] 
#         port_handle_dict = testscript.parameters['port_handle_dict']
#         TGList_config_file = testscript.parameters['TGList']
        configdict = testscript.parameters['configdict'] 
        tgn_config_dict = configdict['TG']
        threshold = testscript.parameters['traffic_threshold']
        traffic_obj = testscript.parameters['traffic_obj']
        trigger_obj = testscript.parameters['trigger_obj']
        tgn_port_dut_mapping = testscript.parameters['tgn_port_dut_mapping']
         
        res = [node_dict['all_dut'][dut].configure('terminal session-timeout 0') for dut in node_dict['all_dut'] if re.search('uut', dut)]
         
        for TG in tgn_config_dict.keys():
            tgn_hdl = testscript.parameters['testbed_obj'].devices[TG]
            out = trigger_obj.checkAllStreamStats(tgn_hdl)
         
            if out:
                log.info(banner('Initial Traffic flow is as expected:'))
                traffic_obj.getAllBoundStreamStatistics(tgn_hdl)
                 
                log.info(banner('Taking Backup of configs on all the VTEPs:'))
                 
                device_dict = trigger_obj.getDeviceDict('all_vtep')
 
                log.info(banner('Restarting  OSPF Process from all the VTEPs'))
                 
                for dut in device_dict:
                    res = verifyProcessRestartWithFlushRoutes(node_dict['all_dut'][dut],'ngmvpn')
                     
                    if not res:
                        log.error('Process restart failed on the dut {0}'.format(dut))
                 
                log.info(banner('Waiting for 30 seconds before getting the Traffic Stats'))
                countDownTimer(100)
                 
                out = trigger_obj.checkAllStreamStats(tgn_hdl)
                 
                if not out:
                    log.error(banner('Traffic has not recovered on some of the streams after starting the Original Streams.. Collecting the individual STream stats:'))
                    traffic_obj.getAllBoundStreamStatistics(tgn_hdl)
                    cfg = 'interface nve 1 ; shutdown ; sleep 5 ; no shutdown'
                    [node_dict['all_dut'][dut].configure(cfg) for dut in list(device_dict.keys())]
                    countDownTimer(180)
                    self.failed()
 
            else:
                log.error('The Initial Traffic Condition did not pass:')
                traffic_obj.getAllBoundStreamStatistics(tgn_hdl)
                self.failed()  
 
class VXLANL3TRMVPCBLFUNC068(aetest.Testcase):
 
    """ restart pim Process """
 
    uid = 'VXLAN-L3-TRM-VPC-BL-FUNC-068'
 
    @aetest.test
    def restartPIMProcess(self,log,testscript,testbed):
#         standalone_vtep_dict = testscript.parameters['standalone_vtep_dict']
        node_dict = testscript.parameters['node_dict']
        tg_interface_hdl_dict = testscript.parameters['tg_interface_hdl_dict'] 
        traffic_stream_dict = testscript.parameters['traffic_stream_dict'] 
#         port_handle_dict = testscript.parameters['port_handle_dict']
#         TGList_config_file = testscript.parameters['TGList']
        configdict = testscript.parameters['configdict'] 
        tgn_config_dict = configdict['TG']
        threshold = testscript.parameters['traffic_threshold']
        traffic_obj = testscript.parameters['traffic_obj']
        trigger_obj = testscript.parameters['trigger_obj']
        tgn_port_dut_mapping = testscript.parameters['tgn_port_dut_mapping']
         
        res = [node_dict['all_dut'][dut].configure('terminal session-timeout 0') for dut in node_dict['all_dut'] if re.search('uut', dut)]
         
        for TG in tgn_config_dict.keys():
            tgn_hdl = testscript.parameters['testbed_obj'].devices[TG]
            out = trigger_obj.checkAllStreamStats(tgn_hdl)
         
            if out:
                log.info(banner('Initial Traffic flow is as expected:'))
                traffic_obj.getAllBoundStreamStatistics(tgn_hdl)
                 
                log.info(banner('Taking Backup of configs on all the VTEPs:'))
                 
                device_dict = trigger_obj.getDeviceDict('all_vtep')
 
                log.info(banner('Restarting  OSPF Process from all the VTEPs'))
                 
                for dut in device_dict:
                    res = verifyProcessRestartWithFlushRoutes(node_dict['all_dut'][dut],'pim')
                     
                    if not res:
                        log.error('Process restart failed on the dut {0}'.format(dut))
                 
                log.info(banner('Waiting for 30 seconds before getting the Traffic Stats'))
                countDownTimer(200)
                 
                out = trigger_obj.checkAllStreamStats(tgn_hdl)
                 
                if not out:
                    log.error(banner('Traffic has not recovered on some of the streams after starting the Original Streams.. Collecting the individual STream stats:'))
                    traffic_obj.getAllBoundStreamStatistics(tgn_hdl)
                    cfg = 'interface nve 1 ; shutdown ; sleep 5 ; no shutdown'
                    [node_dict['all_dut'][dut].configure(cfg) for dut in list(device_dict.keys())]
                    countDownTimer(600)
                    self.failed()
 
            else:
                log.error('The Initial Traffic Condition did not pass:')
                traffic_obj.getAllBoundStreamStatistics(tgn_hdl)
                self.failed()                                                                  
 
class VXLANL3TRMVPCBLFUNC069(aetest.Testcase):
 
    """ restart igmp Process """
 
    uid = 'VXLAN-L3-TRM-VPC-BL-FUNC-069'
 
    @aetest.test
    def restartPIMProcess(self,log,testscript,testbed):
#         standalone_vtep_dict = testscript.parameters['standalone_vtep_dict']
        node_dict = testscript.parameters['node_dict']
        tg_interface_hdl_dict = testscript.parameters['tg_interface_hdl_dict'] 
        traffic_stream_dict = testscript.parameters['traffic_stream_dict'] 
#         port_handle_dict = testscript.parameters['port_handle_dict']
#         TGList_config_file = testscript.parameters['TGList']
        configdict = testscript.parameters['configdict'] 
        tgn_config_dict = configdict['TG']
        threshold = testscript.parameters['traffic_threshold']
        traffic_obj = testscript.parameters['traffic_obj']
        trigger_obj = testscript.parameters['trigger_obj']
        tgn_port_dut_mapping = testscript.parameters['tgn_port_dut_mapping']
         
        res = [node_dict['all_dut'][dut].configure('terminal session-timeout 0') for dut in node_dict['all_dut'] if re.search('uut', dut)]
         
        for TG in tgn_config_dict.keys():
            tgn_hdl = testscript.parameters['testbed_obj'].devices[TG]
            out = trigger_obj.checkAllStreamStats(tgn_hdl)
         
            if out:
                log.info(banner('Initial Traffic flow is as expected:'))
                traffic_obj.getAllBoundStreamStatistics(tgn_hdl)
                 
                log.info(banner('Taking Backup of configs on all the VTEPs:'))
                 
                device_dict = trigger_obj.getDeviceDict('all_vtep')
 
                log.info(banner('Restarting  OSPF Process from all the VTEPs'))
                 
                for dut in device_dict:
                    res = verifyProcessRestartWithFlushRoutes(node_dict['all_dut'][dut],'igmp')
                     
                    if not res:
                        log.error('Process restart failed on the dut {0}'.format(dut))
                 
                log.info(banner('Waiting for 30 seconds before getting the Traffic Stats'))
                countDownTimer(100)
                 
                out = trigger_obj.checkAllStreamStats(tgn_hdl)
                 
                if not out:
                    log.error(banner('Traffic has not recovered on some of the streams after starting the Original Streams.. Collecting the individual STream stats:'))
                    traffic_obj.getAllBoundStreamStatistics(tgn_hdl)
                    cfg = 'interface nve 1 ; shutdown ; sleep 5 ; no shutdown'
                    [node_dict['all_dut'][dut].configure(cfg) for dut in list(device_dict.keys())]
                    countDownTimer(300)
                    self.failed()
 
            else:
                log.error('The Initial Traffic Condition did not pass:')
                traffic_obj.getAllBoundStreamStatistics(tgn_hdl)
                self.failed()           

class VXLANL3TRMVPCBLFUNC070(aetest.Testcase):
 
    """ checking ConfigReplace functionality"""
 
    uid = 'VXLAN-L3-TRM-VPC-BL-FUNC-070'
 
    @aetest.test
    def checkConfigReplaceFunctionlity(self,log,testscript,testbed):
#         standalone_vtep_dict = testscript.parameters['standalone_vtep_dict']
        node_dict = testscript.parameters['node_dict']
        tg_interface_hdl_dict = testscript.parameters['tg_interface_hdl_dict'] 
        traffic_stream_dict = testscript.parameters['traffic_stream_dict'] 
#         port_handle_dict = testscript.parameters['port_handle_dict']
#         TGList_config_file = testscript.parameters['TGList']
        configdict = testscript.parameters['configdict'] 
        tgn_config_dict = configdict['TG']
        threshold = testscript.parameters['traffic_threshold']
        traffic_obj = testscript.parameters['traffic_obj']
        trigger_obj = testscript.parameters['trigger_obj']
        tgn_port_dut_mapping = testscript.parameters['tgn_port_dut_mapping']
         
        res = [node_dict['all_dut'][dut].configure('terminal session-timeout 0') for dut in node_dict['all_dut'] if re.search('uut', dut)]
         
        delete = 'delete bootflash:automation* no-prompt'
        cfg = 'copy running-config bootflash:automation-config-replace-config'
         
        for TG in tgn_config_dict.keys():
            tgn_hdl = testscript.parameters['testbed_obj'].devices[TG]
            out = trigger_obj.checkAllStreamStats(tgn_hdl)
         
            if out:
                log.info(banner('Initial Traffic flow is as expected:'))
                traffic_obj.getAllBoundStreamStatistics(tgn_hdl)
                 
                log.info(banner('Taking Backup of configs on all the VTEPs:'))
                 
                device_dict = trigger_obj.getDeviceDict('all_vtep')
                 
                for dut in device_dict:
                    log.info('Deleting any Existing File and Creating a new file on dut {0}'.format(dut))
                    node_dict['all_dut'][dut].configure(delete)
                    node_dict['all_dut'][dut].configure(cfg)
                 
                log.info(banner('Removing all the Features required for the VXlan'))
                for feature in ['ospf','bgp','pim','interface-vlan','ngmvpn','nve','vn-segment-vlan-based']:
                    for dut in device_dict:
                        log.info(banner('Deleting feature {0} on dut {1}'.format(feature,dut)))
                        out=bringup_lib.unconfigFeature(node_dict['all_dut'][dut], log, '-feature {0}'.format(feature) )
                        if out.result=='fail':
                            log.error('Disable of nv overlay failed on VTEP {0}'.format(dut))
                            self.failed()
                        else:
                            log.info('Disable of nv overlay Successful on VTEP {0}'.format(dut))
                 
                log.info(banner('Waiting for 50 seconds before reverting the CheckPoint...'))
                countDownTimer(50)
                 
                log.info(banner('Verifying Config REplace Functionality. Replaying the configs..'))
                 
                cfg2 = 'configure replace bootflash:automation-config-replace-config verbose'
#                 threads = []
#                 for dut in device_dict:
#                     t = threading.Thread(target = node_dict['all_dut'][dut].configure(cfg2,timeout=600))
#                     t.start()
#                     threads.append(t)
#                 [thread.join() for thread in threads]
                for dut in device_dict:
                    log.info('Performing Config Replace on Dut {0}'.format(dut))
                    node_dict['all_dut'][dut].configure(cfg2, timeout=600)
  
                 
                log.info(banner('Waiting for 400 seconds before Collecting the stats...'))
                countDownTimer(400)
                 
                out = trigger_obj.checkAllStreamStats(tgn_hdl)
                if not out:
                    log.error(banner('Traffic has not recovered on some of the streams after starting the Original Streams.. Collecting the individual STream stats:'))
                    traffic_obj.getAllBoundStreamStatistics(tgn_hdl)
                    cfg = 'interface nve 1 ; shutdown ; sleep 5 ; no shutdown'
                    [node_dict['all_dut'][dut].configure(cfg) for dut in list(device_dict.keys())]
                    countDownTimer(600)
                    self.failed()
 
            else:
                log.error('The Initial Traffic Condition did not pass:')
                traffic_obj.getAllBoundStreamStatistics(tgn_hdl)
                self.failed()
                                                               


class CommonCleanup(aetest.Testcase):
    
    """ VLan State Change on Both the DUTS """

    uid = 'VXLAN-L3-TRM-FUNC-001'

    @aetest.subsection
    def checkTopo(self):
        pass
        
        
class CommonCleanup(aetest.CommonCleanup):

    @aetest.subsection
    def disconnect(self):
        pass

