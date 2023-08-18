#
#   Demo script file for setup bring

# python generic imports
import yaml
import logging
import argparse
import re
import time
import utils
from utils import *

from pyats import aetest
import config_bringup
import config_bringup_test
import yaml
import logging
from pyats.topology import loader
import argparse
import MyLib
from MyLib import my_utils
from MyLib import my_config_utils
from MyLib import my_trigger_utils
from MyLib import *
# pyATS imports

from unicon import Connection
from ats import aetest
from ats.log.utils import banner
from ats.datastructures.logic import Not, And, Or
from ats.easypy import run
from ats.log.utils import banner
import bringup_lib
#import evpn_lib
import vxlan_lib
import ospfv2_lib
import bgp_lib
import evpn_lib
import tcam_lib
import pim_lib
import vpc_lib
#import oam_lib
from pyats.async_ import pcall
from pyats.async_ import Pcall

#Ixia Libraries
import ixia_lib_new
from ixia_lib_new import *

# N39k Library imports
import config_bringup
import interface_lib
import ipaddress

from itertools import chain
from collections import OrderedDict
from itertools import permutations
import json
from bs4 import BeautifulSoup



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

def switch_reload(uut):
 
    dialog = Dialog([
        Statement(pattern=r'.*Do you wish to proceed anyway.*',
                        action='sendline(y)',
                        loop_continue=True,
                        continue_timer=True)
        ])
       
    result=uut.reload(reload_command = "reload", dialog=dialog)
 
    if result:
        log.info('Reload successful -- Waiting 180 seconds for config sync')
        countDownTimer(180)
        return 1
    else:
        logger.info('Reload Failed')
        return 0



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
        testscript.parameters['config_prefix_list'] = kwargs['config_prefix_list']
        testscript.parameters['config_route_map'] = kwargs['config_route_map']
        testscript.parameters['config_pim_anycast_loopback_intf'] = kwargs['config_pim_anycast_loopback_intf']
        testscript.parameters['config_pim_anycast_rp_set'] = kwargs['config_pim_anycast_rp_set']
        testscript.parameters['config_tgn_conn'] = kwargs['config_tgn_conn']
        testscript.parameters['config_tgn_interface'] = kwargs['config_tgn_interface']
                                         
        parser = argparse.ArgumentParser()
        parser.add_argument('--config-file',dest='config_file',type=str)
        args = parser.parse_args()
        config_file = args.config_file
        fp = open(config_file)
        configdict=yaml.load(fp)
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
                node_dict['all_dut'][dut].connect(via='vty')
        
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
            
            intf_obj = config_bringup_test.configSetup(config_dict,testbed_obj,log)
            
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
            for dut in ['stand_vtep','external_rp','core']:
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
            device_dict = {}
            for dut in ['all_vtep','external_rp']:
                device_dict.update(scale_config_obj.getDeviceDict(dut))

            log.info(banner('The value of external_rp_dict is : {0}'.format(device_dict)))
    
            res = scale_config_obj.configureLoopbackInterface(device_dict)
             
            if not res:
                self.failed()
        else:
            pass

    @aetest.subsection                     
    def configureGlobalPrefixList(self,testscript,log):     
        
        config_prefix_list = testscript.parameters['config_prefix_list']
        config_dict = testscript.parameters['configdict']
        node_dict = testscript.parameters['node_dict']
        alias_intf_mapping = testscript.parameters['alias_intf_mapping']
        
        if config_prefix_list:
        
            scale_config_obj = MyLib.my_config_utils.ScaleConfig(log,node_dict,config_dict,alias_intf_mapping)
            stand_vtep_dict = scale_config_obj.getDeviceDict('stand_vtep')

            log.info(banner('The value of stand_vtep_dict is : {0}'.format(stand_vtep_dict)))
    
            res = scale_config_obj.configurePrefixList(stand_vtep_dict)
             
            if not res:
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
            stand_vtep_dict = scale_config_obj.getDeviceDict('stand_vtep')

            log.info(banner('The value of stand_vtep_dict is : {0}'.format(stand_vtep_dict)))
    
            res = scale_config_obj.configureRouteMap(stand_vtep_dict)
             
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
            device_dict = {}
            for dut in ['stand_vtep','external_rp']:
                device_dict.update(scale_config_obj.getDeviceDict(dut))

            log.info(banner('The value of external_rp_dict is : {0}'.format(device_dict)))
    
            res = scale_config_obj.configureOspfRouterID(device_dict)
             
            if not res:
                self.failed()
        else:
            pass

    @aetest.subsection                     
    def configurePimAnyCastLoopbackInterfaces(self,testscript,log):     
        
        config_pim_anycast_loopback_intf = testscript.parameters['config_pim_anycast_loopback_intf']
        config_dict = testscript.parameters['configdict']
        node_dict = testscript.parameters['node_dict']
        alias_intf_mapping = testscript.parameters['alias_intf_mapping']
        
        if config_pim_anycast_loopback_intf:
        
            scale_config_obj = MyLib.my_config_utils.ScaleConfig(log,node_dict,config_dict,alias_intf_mapping)
            device_dict = {}
            for dut in ['stand_vtep','external_rp']:
                device_dict.update(scale_config_obj.getDeviceDict(dut))

            log.info(banner('The value of device_dict is : {0}'.format(device_dict)))
    
            res = scale_config_obj.configurePimAnyCastLoopbackInterface(device_dict)
             
            if not res:
                self.failed()
        else:
            pass

    @aetest.subsection                     
    def configurePimAnyCastRPSet(self,testscript,log):     
        
        config_pim_anycast_rp_set = testscript.parameters['config_pim_anycast_rp_set']
        config_dict = testscript.parameters['configdict']
        node_dict = testscript.parameters['node_dict']
        alias_intf_mapping = testscript.parameters['alias_intf_mapping']
        
        if config_pim_anycast_rp_set:
        
            scale_config_obj = MyLib.my_config_utils.ScaleConfig(log,node_dict,config_dict,alias_intf_mapping)
            device_dict = {}
            for dut in ['stand_vtep','external_rp']:
                device_dict.update(scale_config_obj.getDeviceDict(dut))

            log.info(banner('The value of device_dict is : {0}'.format(device_dict)))
    
            res = scale_config_obj.configurePimAnyCastRPSet(device_dict)
             
            if not res:
                self.failed()
        else:
            pass    
    

    @aetest.subsection                     
    def connectionToTrafficGenerator(self,testscript,log): 
        
        # Connect and confiure TG
 
        log.info('Connecting and configuring TG as per config dict...')
        # Get physical interface from logical interface of config file for TG
         
        config_dict = testscript.parameters['configdict']
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
                    tgn_port_dut_mapping[dut] = port
            
            
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
        
#         '''
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
#         '''
#         pass    
    

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
        
        log.info(banner('Waiting for 60 seconds before collecting Traffic Stats:'))
        countDownTimer(10)
        
        failed_stream_list = []
        for TG in tgn_config_dict.keys():
            log.info('The value of TG is = %r', TG)
            tgn_hdl = testscript.parameters['testbed_obj'].devices[TG]
            x = tgn_hdl.traffic_control(action='clear_stats',max_wait_timer=60)
            for trf_stream in traffic_stream_dict:
                if traffic_stream_dict[trf_stream]['status']:
                    stream_handle = traffic_stream_dict[trf_stream]['traffic_item']
#                     x = tgn_hdl.traffic_control(action='clear_stats', handle = stream_handle, max_wait_timer=60)
                    stream_id = traffic_stream_dict[trf_stream]['stream_id']
#                     countDownTimer(20)
                    y = tgn_hdl.traffic_stats(stream=stream_id,mode='traffic_item')
                    log.info(banner('The value of y is : {0}'.format(y)))
                    for i in y['traffic_item']:
                        if i == stream_id:
                            loss_percent= y['traffic_item'][i]['rx']['loss_percent']
                            log.info(banner('The value of loss_percent is : {0}'.format(loss_percent)))
                            try:
                                if loss_percent > 10.0:
                                    failed_stream_list.append(trf_stream)
                            except:
                                log.info(banner('Traffic stats was not proper.. Waiting for another 10 seconds'))
                                countDownTimer(10)
                                loss_percent= y['traffic_item'][i]['rx']['loss_percent']
                                log.info(banner('The value of loss_percent is : {0}'.format(loss_percent)))
                                try:
                                    if loss_percent > 10.0:
                                        failed_stream_list.append(trf_stream)
                                except:
                                    log.info(banner('Traffic stats could not be collected again for this stream.'))
            
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


               
class VXLANL3TRMANYCASTRPFUNC001(aetest.Testcase):

    """ Verify Int Src Int Rv"""

    uid = 'VXLAN-L3-TRM-ANYCAST-RP-FUNC-001'

    @aetest.test
    def VxlanL3TRMAnyCastRPIntSrcIntRcv(self,log,testscript,testbed):
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
            
            if out:
                log.info(banner('Initial Traffic flow is as expected:'))
                traffic_obj.getAllBoundStreamStatistics(tgn_hdl)
                
                traffic_item = tgn_config_dict[TG]['TEST-001']
                
                log.info(banner('Stopping all the stream and waiting for 15 seconds'))
                x = tgn_hdl.traffic_control(action='stop',max_wait_timer=60)
                countDownTimer(15)
                
                log.info(banner('Creating the new Traffic Item - Int Src, Int Rcv'))
        
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
#                            b = tgn_hdl.emulation_igmp_control(mode='start')
                            o = tgn_hdl.emulation_igmp_control(mode='join',group_member_handle=a)
                            if not o.status:
                                log.info('IGMP join is not sent to the group . Pls debug.....')
                                self.failed()
                                        
                log.info(banner('Waiting for 30 seconds before starting the traffic:'))
                countDownTimer(30)
                
                log.info(banner('Starting the New Stream Created for this test ..'))
                x = tgn_hdl.traffic_control(action='run', handle = new_tg_intf_config_dict['traffic_item'],max_wait_timer=60)
                
                if not x.status:
                    log.error(banner('The Stream {0} could not be started as expected '.format(ixia_traffic_config.stream_id)))
                    self.failed()
                
                log.info(banner('Waiting for 30 seconds before measuring the traffic stats:'))
                countDownTimer(30)
                
                ixia_stream = new_tg_intf_config_dict['stream_id']
                res = MyLib.my_config_utils.getTrafficItemStatistics(log,tgn_hdl,ixia_stream,'TEST-001')
                
                log.info(banner('The Value of res is: {0}'.format(res)))
                
                flag = 0
                
                if abs(res['tx']-res['rx']) < threshold:
                    log.info('The TRM traffic is as expected.... Adding the Created stream and re-starting all other streams:')
                    
                    log.info('Stopping the New Traffic Item stream Created for this test:')
                    x1 = tgn_hdl.traffic_control(action='stop', handle = new_tg_intf_config_dict['traffic_item'], max_wait_timer=60)
                    
                    log.info('Removing the stream {0}:'.format(ixia_stream))
                    y = tgn_hdl.traffic_config(mode='remove',stream_id=ixia_stream)
                    
#                     log.info(banner('Adding the New stream to the Main Traffic Stream Dict: '))
#                     traffic_stream_dict.setdefault('TEST-001',{})
#                     traffic_stream_dict['TEST-001'].update(new_tg_intf_config_dict)
#                     log.info('The value of traffic_stream_dict is : {0}'.format(yaml.dump(traffic_stream_dict)))
                    
#                     log.info(banner('Adding the New stream to the configured stream list :'))
#                     configured_stream.append('TEST-001')
                    
#                     log.info(banner('Sending the Modified Traffic_stream_dict and Configured_stream to global Testscript params'))
#                     
#                     testscript.parameters['configured_stream'] = configured_stream
#                     testscript.parameters['traffic_stream_dict'] = traffic_stream_dict

                    
                else:
                    log.error(banner('TRM Traffic item is not as expected. The value of tx and rx is : {0} and {1}'.format(res['tx'],res['rx'])))
                    log.info(banner('Stopping the newly created Stream. Ixia Name: {0} User Name is  : {1}'.format(ixia_stream,'TEST-001')))
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

class VXLANL3TRMANYCASTRPFUNC002(aetest.Testcase):

    """ Verify Int Src Ext Rv"""

    uid = 'VXLAN-L3-TRM-ANYCAST-RP-FUNC-002'

    @aetest.test
    def VxlanL3TRMAnyCastRPIntSrcExtRcv(self,log,testscript,testbed):
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
            
            if out:
                log.info(banner('Initial Traffic flow is as expected:'))
                traffic_obj.getAllBoundStreamStatistics(tgn_hdl)
                
                traffic_item = tgn_config_dict[TG]['TEST-002']
                
                log.info(banner('Stopping all the stream and waiting for 15 seconds'))
                x = tgn_hdl.traffic_control(action='stop',max_wait_timer=60)
                countDownTimer(15)
                
                log.info(banner('Creating the new Traffic Item - Int Src, Int Rcv'))
        
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
                            c = tgn_hdl.emulation_igmp_control(mode='start',group_member_handle=a)
                            o=tgn_hdl.emulation_igmp_control(mode='join',group_member_handle=a)
                            if not o.status:
                                        log.info('IGMP join is not sent to the group . Pls debug.....')
                                        self.failed()
                                        
                log.info(banner('Waiting for 30 seconds before starting the traffic:'))
                countDownTimer(30)
                
                log.info(banner('Starting the New Stream Created for this test ..'))
                x = tgn_hdl.traffic_control(action='run', handle = new_tg_intf_config_dict['traffic_item'],max_wait_timer=60)
                
                if not x.status:
                    log.error(banner('The Stream {0} could not be started as expected '.format(ixia_traffic_config.stream_id)))
                    self.failed()
                
                log.info(banner('Waiting for 30 seconds before measuring the traffic stats:'))
                countDownTimer(30)
                
                ixia_stream = new_tg_intf_config_dict['stream_id']
                res = MyLib.my_config_utils.getTrafficItemStatistics(log,tgn_hdl,ixia_stream,'TEST-002')
                
                log.info(banner('The Value of res is: {0}'.format(res)))
                
                flag = 0
                
                if abs(res['tx']-res['rx']) < threshold:
                    log.info('The TRM traffic is as expected.... Adding the Created stream and re-starting all other streams:')
                    
                    log.info('Stopping the New Traffic Item stream Created for this test:')
                    x1 = tgn_hdl.traffic_control(action='stop', handle = new_tg_intf_config_dict['traffic_item'], max_wait_timer=60)
                    
                    log.info('Removing the stream {0}:'.format(ixia_stream))
                    y = tgn_hdl.traffic_config(mode='remove',stream_id=ixia_stream)
                    
#                     log.info(banner('Adding the New stream to the Main Traffic Stream Dict: '))
#                     traffic_stream_dict.setdefault('TEST-002',{})
#                     traffic_stream_dict['TEST-002'].update(new_tg_intf_config_dict)
#                     log.info('The value of traffic_stream_dict is : {0}'.format(yaml.dump(traffic_stream_dict)))
#                     
#                     log.info(banner('Adding the New stream to the configured stream list :'))
#                     configured_stream.append('TEST-002')
#                     
#                     log.info(banner('Sending the Modified Traffic_stream_dict and Configured_stream to global Testscript params'))
#                     
#                     testscript.parameters['configured_stream'] = configured_stream
#                     testscript.parameters['traffic_stream_dict'] = traffic_stream_dict

                    
                else:
                    log.error(banner('TRM Traffic item is not as expected. The value of tx and rx is : {0} and {1}'.format(res['tx'],res['rx'])))
                    log.info(banner('Stopping the newly created Stream. Ixia Name: {0} User Name is  : {1}'.format(ixia_stream,'TEST-002')))
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

class VXLANL3TRMANYCASTRPFUNC003(aetest.Testcase):

    """ Verify Int Src BL-1 Rv"""

    uid = 'VXLAN-L3-TRM-ANYCAST-RP-FUNC-003'

    @aetest.test
    def VxlanL3TRMAnyCastRPIntSrcBL1Rcv(self,log,testscript,testbed):
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
            
            if out:
                log.info(banner('Initial Traffic flow is as expected:'))
                traffic_obj.getAllBoundStreamStatistics(tgn_hdl)
                
                traffic_item = tgn_config_dict[TG]['TEST-003']
                
                log.info(banner('Stopping all the stream and waiting for 15 seconds'))
                x = tgn_hdl.traffic_control(action='stop',max_wait_timer=60)
                countDownTimer(15)
                
                log.info(banner('Creating the new Traffic Item - Int Src, Int Rcv'))
        
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
#                            b = tgn_hdl.emulation_igmp_control(mode='start')
                            o = tgn_hdl.emulation_igmp_control(mode='join',group_member_handle=a)
                            if not o.status:
                                log.info('IGMP join is not sent to the group . Pls debug.....')
                                self.failed()
                                        
                log.info(banner('Waiting for 30 seconds before starting the traffic:'))
                countDownTimer(30)
                
                log.info(banner('Starting the New Stream Created for this test ..'))
                x = tgn_hdl.traffic_control(action='run', handle = new_tg_intf_config_dict['traffic_item'],max_wait_timer=60)
                
                if not x.status:
                    log.error(banner('The Stream {0} could not be started as expected '.format(ixia_traffic_config.stream_id)))
                    self.failed()
                
                log.info(banner('Waiting for 30 seconds before measuring the traffic stats:'))
                countDownTimer(30)
                
                ixia_stream = new_tg_intf_config_dict['stream_id']
                res = MyLib.my_config_utils.getTrafficItemStatistics(log,tgn_hdl,ixia_stream,'TEST-003')
                
                log.info(banner('The Value of res is: {0}'.format(res)))
                
                flag = 0
                
                if abs(res['tx']-res['rx']) < threshold:
                    log.info('The TRM traffic is as expected.... Adding the Created stream and re-starting all other streams:')
                    
                    log.info('Stopping the New Traffic Item stream Created for this test:')
                    x1 = tgn_hdl.traffic_control(action='stop', handle = new_tg_intf_config_dict['traffic_item'], max_wait_timer=60)
                    
                    log.info('Removing the stream {0}:'.format(ixia_stream))
                    y = tgn_hdl.traffic_config(mode='remove',stream_id=ixia_stream)
                    
#                     log.info(banner('Adding the New stream to the Main Traffic Stream Dict: '))
#                     traffic_stream_dict.setdefault('TEST-003',{})
#                     traffic_stream_dict['TEST-003'].update(new_tg_intf_config_dict)
#                     log.info('The value of traffic_stream_dict is : {0}'.format(yaml.dump(traffic_stream_dict)))
#                     
#                     log.info(banner('Adding the New stream to the configured stream list :'))
#                     configured_stream.append('TEST-003')
#                     
#                     log.info(banner('Sending the Modified Traffic_stream_dict and Configured_stream to global Testscript params'))
#                     
#                     testscript.parameters['configured_stream'] = configured_stream
#                     testscript.parameters['traffic_stream_dict'] = traffic_stream_dict

                    
                else:
                    log.error(banner('TRM Traffic item is not as expected. The value of tx and rx is : {0} and {1}'.format(res['tx'],res['rx'])))
                    log.info(banner('Stopping the newly created Stream. Ixia Name: {0} User Name is  : {1}'.format(ixia_stream,'TEST-003')))
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


class VXLANL3TRMANYCASTRPFUNC004(aetest.Testcase):

    """ Verify Int Src BL-2 Rv"""

    uid = 'VXLAN-L3-TRM-ANYCAST-RP-FUNC-004'

    @aetest.test
    def VxlanL3TRMAnyCastRPIntSrcBL2Rcv(self,log,testscript,testbed):
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
            
            if out:
                log.info(banner('Initial Traffic flow is as expected:'))
                traffic_obj.getAllBoundStreamStatistics(tgn_hdl)
                
                traffic_item = tgn_config_dict[TG]['TEST-004']
                
                log.info(banner('Stopping all the stream and waiting for 15 seconds'))
                x = tgn_hdl.traffic_control(action='stop',max_wait_timer=60)
                countDownTimer(15)
                
                log.info(banner('Creating the new Traffic Item - Int Src, Int Rcv'))
        
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
#                            b = tgn_hdl.emulation_igmp_control(mode='start')
                            o = tgn_hdl.emulation_igmp_control(mode='join',group_member_handle=a)
                            if not o.status:
                                log.info('IGMP join is not sent to the group . Pls debug.....')
                                self.failed()
                                        
                log.info(banner('Waiting for 30 seconds before starting the traffic:'))
                countDownTimer(30)
                
                log.info(banner('Starting the New Stream Created for this test ..'))
                x = tgn_hdl.traffic_control(action='run', handle = new_tg_intf_config_dict['traffic_item'],max_wait_timer=60)
                
                if not x.status:
                    log.error(banner('The Stream {0} could not be started as expected '.format(ixia_traffic_config.stream_id)))
                    self.failed()
                
                log.info(banner('Waiting for 30 seconds before measuring the traffic stats:'))
                countDownTimer(30)
                
                ixia_stream = new_tg_intf_config_dict['stream_id']
                res = MyLib.my_config_utils.getTrafficItemStatistics(log,tgn_hdl,ixia_stream,'TEST-004')
                
                log.info(banner('The Value of res is: {0}'.format(res)))
                
                flag = 0
                
                if abs(res['tx']-res['rx']) < threshold:
                    log.info('The TRM traffic is as expected.... Adding the Created stream and re-starting all other streams:')
                    
                    log.info('Stopping the New Traffic Item stream Created for this test:')
                    x1 = tgn_hdl.traffic_control(action='stop', handle = new_tg_intf_config_dict['traffic_item'], max_wait_timer=60)
                    
                    log.info('Removing the stream {0}:'.format(ixia_stream))
                    y = tgn_hdl.traffic_config(mode='remove',stream_id=ixia_stream)
                    
#                     log.info(banner('Adding the New stream to the Main Traffic Stream Dict: '))
#                     traffic_stream_dict.setdefault('TEST-004',{})
#                     traffic_stream_dict['TEST-004'].update(new_tg_intf_config_dict)
#                     log.info('The value of traffic_stream_dict is : {0}'.format(yaml.dump(traffic_stream_dict)))
#                     
#                     log.info(banner('Adding the New stream to the configured stream list :'))
#                     configured_stream.append('TEST-004')
#                     
#                     log.info(banner('Sending the Modified Traffic_stream_dict and Configured_stream to global Testscript params'))
#                     
#                     testscript.parameters['configured_stream'] = configured_stream
#                     testscript.parameters['traffic_stream_dict'] = traffic_stream_dict

                    
                else:
                    log.error(banner('TRM Traffic item is not as expected. The value of tx and rx is : {0} and {1}'.format(res['tx'],res['rx'])))
                    log.info(banner('Stopping the newly created Stream. Ixia Name: {0} User Name is  : {1}'.format(ixia_stream,'TEST-004')))
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


class VXLANL3TRMANYCASTRPFUNC005(aetest.Testcase):

    """ Verify Int Src BL-1 and BL-2 Rv"""

    uid = 'VXLAN-L3-TRM-ANYCAST-RP-FUNC-005'

    @aetest.test
    def VxlanL3TRMAnyCastRPIntSrcBL1BL2Rcv(self,log,testscript,testbed):
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
            
            if out:
                log.info(banner('Initial Traffic flow is as expected:'))
                traffic_obj.getAllBoundStreamStatistics(tgn_hdl)
                
                traffic_item = tgn_config_dict[TG]['TEST-005']
                
                log.info(banner('Stopping all the stream and waiting for 15 seconds'))
                x = tgn_hdl.traffic_control(action='stop',max_wait_timer=60)
                countDownTimer(15)
                
                log.info(banner('Creating the new Traffic Item - Int Src, Int Rcv'))
        
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
#                            b = tgn_hdl.emulation_igmp_control(mode='start')
                            o = tgn_hdl.emulation_igmp_control(mode='join',group_member_handle=a)
                            if not o.status:
                                log.info('IGMP join is not sent to the group . Pls debug.....')
                                self.failed()
                                        
                log.info(banner('Waiting for 30 seconds before starting the traffic:'))
                countDownTimer(30)
                
                log.info(banner('Starting the New Stream Created for this test ..'))
                x = tgn_hdl.traffic_control(action='run', handle = new_tg_intf_config_dict['traffic_item'],max_wait_timer=60)
                
                if not x.status:
                    log.error(banner('The Stream {0} could not be started as expected '.format(ixia_traffic_config.stream_id)))
                    self.failed()
                
                log.info(banner('Waiting for 30 seconds before measuring the traffic stats:'))
                countDownTimer(30)
                
                ixia_stream = new_tg_intf_config_dict['stream_id']
                res = MyLib.my_config_utils.getTrafficItemStatistics(log,tgn_hdl,ixia_stream,'TEST-005')
                
                log.info(banner('The Value of res is: {0}'.format(res)))
                
                flag = 0
                
                if abs(res['tx']-res['rx']) < threshold:
                    log.info('The TRM traffic is as expected.... Adding the Created stream and re-starting all other streams:')
                    
                    log.info('Stopping the New Traffic Item stream Created for this test:')
                    x1 = tgn_hdl.traffic_control(action='stop', handle = new_tg_intf_config_dict['traffic_item'], max_wait_timer=60)
                    
                    log.info('Removing the stream {0}:'.format(ixia_stream))
                    y = tgn_hdl.traffic_config(mode='remove',stream_id=ixia_stream)
                    
#                     log.info(banner('Adding the New stream to the Main Traffic Stream Dict: '))
#                     traffic_stream_dict.setdefault('TEST-005',{})
#                     traffic_stream_dict['TEST-005'].update(new_tg_intf_config_dict)
#                     log.info('The value of traffic_stream_dict is : {0}'.format(yaml.dump(traffic_stream_dict)))
#                     
#                     log.info(banner('Adding the New stream to the configured stream list :'))
#                     configured_stream.append('TEST-005')
#                     
#                     log.info(banner('Sending the Modified Traffic_stream_dict and Configured_stream to global Testscript params'))
#                     
#                     testscript.parameters['configured_stream'] = configured_stream
#                     testscript.parameters['traffic_stream_dict'] = traffic_stream_dict

                    
                else:
                    log.error(banner('TRM Traffic item is not as expected. The value of tx and rx is : {0} and {1}'.format(res['tx'],res['rx'])))
                    log.info(banner('Stopping the newly created Stream. Ixia Name: {0} User Name is  : {1}'.format(ixia_stream,'TEST-005')))
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

class VXLANL3TRMANYCASTRPFUNC006(aetest.Testcase):

    """ Verify Int Src Rx Internal and BL-1"""

    uid = 'VXLAN-L3-TRM-ANYCAST-RP-FUNC-006'

    @aetest.test
    def VxlanL3TRMAnyCastRPIntSrcIntRxBL1Rx(self,log,testscript,testbed):
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
            
            if out:
                log.info(banner('Initial Traffic flow is as expected:'))
                traffic_obj.getAllBoundStreamStatistics(tgn_hdl)
                
                traffic_item = tgn_config_dict[TG]['TEST-006']
                
                log.info(banner('Stopping all the stream and waiting for 15 seconds'))
                x = tgn_hdl.traffic_control(action='stop',max_wait_timer=60)
                countDownTimer(15)
                
                log.info(banner('Creating the new Traffic Item - Int Src, Int Rcv'))
        
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
#                            b = tgn_hdl.emulation_igmp_control(mode='start')
                            o = tgn_hdl.emulation_igmp_control(mode='join',group_member_handle=a)
                            if not o.status:
                                log.info('IGMP join is not sent to the group . Pls debug.....')
                                self.failed()
                                        
                log.info(banner('Waiting for 30 seconds before starting the traffic:'))
                countDownTimer(30)
                
                log.info(banner('Starting the New Stream Created for this test ..'))
                x = tgn_hdl.traffic_control(action='run', handle = new_tg_intf_config_dict['traffic_item'],max_wait_timer=60)
                
                if not x.status:
                    log.error(banner('The Stream {0} could not be started as expected '.format(ixia_traffic_config.stream_id)))
                    self.failed()
                
                log.info(banner('Waiting for 30 seconds before measuring the traffic stats:'))
                countDownTimer(30)
                
                ixia_stream = new_tg_intf_config_dict['stream_id']
                res = MyLib.my_config_utils.getTrafficItemStatistics(log,tgn_hdl,ixia_stream,'TEST-006')
                
                log.info(banner('The Value of res is: {0}'.format(res)))
                
                flag = 0
                
                if abs(res['tx']-res['rx']) < threshold:
                    log.info('The TRM traffic is as expected.... Adding the Created stream and re-starting all other streams:')
                    
                    log.info('Stopping the New Traffic Item stream Created for this test:')
                    x1 = tgn_hdl.traffic_control(action='stop', handle = new_tg_intf_config_dict['traffic_item'], max_wait_timer=60)
                    
                    log.info('Removing the stream {0}:'.format(ixia_stream))
                    y = tgn_hdl.traffic_config(mode='remove',stream_id=ixia_stream)
                    
#                     log.info(banner('Adding the New stream to the Main Traffic Stream Dict: '))
#                     traffic_stream_dict.setdefault('TEST-006',{})
#                     traffic_stream_dict['TEST-006'].update(new_tg_intf_config_dict)
#                     log.info('The value of traffic_stream_dict is : {0}'.format(yaml.dump(traffic_stream_dict)))
#                     
#                     log.info(banner('Adding the New stream to the configured stream list :'))
#                     configured_stream.append('TEST-006')
#                     
#                     log.info(banner('Sending the Modified Traffic_stream_dict and Configured_stream to global Testscript params'))
#                     
#                     testscript.parameters['configured_stream'] = configured_stream
#                     testscript.parameters['traffic_stream_dict'] = traffic_stream_dict

                    
                else:
                    log.error(banner('TRM Traffic item is not as expected. The value of tx and rx is : {0} and {1}'.format(res['tx'],res['rx'])))
                    log.info(banner('Stopping the newly created Stream. Ixia Name: {0} User Name is  : {1}'.format(ixia_stream,'TEST-006')))
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

class VXLANL3TRMANYCASTRPFUNC007(aetest.Testcase):

    """ Verify Int Src Rx Internal and BL-2"""

    uid = 'VXLAN-L3-TRM-ANYCAST-RP-FUNC-007'

    @aetest.test
    def VxlanL3TRMAnyCastRPIntSrcIntRxBL2Rx(self,log,testscript,testbed):
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
            
            if out:
                log.info(banner('Initial Traffic flow is as expected:'))
                traffic_obj.getAllBoundStreamStatistics(tgn_hdl)
                
                traffic_item = tgn_config_dict[TG]['TEST-007']
                
                log.info(banner('Stopping all the stream and waiting for 15 seconds'))
                x = tgn_hdl.traffic_control(action='stop',max_wait_timer=60)
                countDownTimer(15)
                
                log.info(banner('Creating the new Traffic Item - Int Src, Int Rcv'))
        
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
#                            b = tgn_hdl.emulation_igmp_control(mode='start')
                            o = tgn_hdl.emulation_igmp_control(mode='join',group_member_handle=a)
                            if not o.status:
                                log.info('IGMP join is not sent to the group . Pls debug.....')
                                self.failed()
                                        
                log.info(banner('Waiting for 30 seconds before starting the traffic:'))
                countDownTimer(30)
                
                log.info(banner('Starting the New Stream Created for this test ..'))
                x = tgn_hdl.traffic_control(action='run', handle = new_tg_intf_config_dict['traffic_item'],max_wait_timer=60)
                
                if not x.status:
                    log.error(banner('The Stream {0} could not be started as expected '.format(ixia_traffic_config.stream_id)))
                    self.failed()
                
                log.info(banner('Waiting for 30 seconds before measuring the traffic stats:'))
                countDownTimer(30)
                
                ixia_stream = new_tg_intf_config_dict['stream_id']
                res = MyLib.my_config_utils.getTrafficItemStatistics(log,tgn_hdl,ixia_stream,'TEST-007')
                
                log.info(banner('The Value of res is: {0}'.format(res)))
                
                flag = 0
                
                if abs(res['tx']-res['rx']) < threshold:
                    log.info('The TRM traffic is as expected.... Adding the Created stream and re-starting all other streams:')
                    
                    log.info('Stopping the New Traffic Item stream Created for this test:')
                    x1 = tgn_hdl.traffic_control(action='stop', handle = new_tg_intf_config_dict['traffic_item'], max_wait_timer=60)
                    
                    log.info('Removing the stream {0}:'.format(ixia_stream))
                    y = tgn_hdl.traffic_config(mode='remove',stream_id=ixia_stream)
                    
#                     log.info(banner('Adding the New stream to the Main Traffic Stream Dict: '))
#                     traffic_stream_dict.setdefault('TEST-007',{})
#                     traffic_stream_dict['TEST-007'].update(new_tg_intf_config_dict)
#                     log.info('The value of traffic_stream_dict is : {0}'.format(yaml.dump(traffic_stream_dict)))
#                     
#                     log.info(banner('Adding the New stream to the configured stream list :'))
#                     configured_stream.append('TEST-007')
#                     
#                     log.info(banner('Sending the Modified Traffic_stream_dict and Configured_stream to global Testscript params'))
#                     
#                     testscript.parameters['configured_stream'] = configured_stream
#                     testscript.parameters['traffic_stream_dict'] = traffic_stream_dict
                    
                else:
                    log.error(banner('TRM Traffic item is not as expected. The value of tx and rx is : {0} and {1}'.format(res['tx'],res['rx'])))
                    log.info(banner('Stopping the newly created Stream. Ixia Name: {0} User Name is  : {1}'.format(ixia_stream,'TEST-007')))
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

class VXLANL3TRMANYCASTRPFUNC008(aetest.Testcase):

    """ Verify Int Src Rx Internal and Ext Rx"""

    uid = 'VXLAN-L3-TRM-ANYCAST-RP-FUNC-008'

    @aetest.test
    def VxlanL3TRMAnyCastRPIntSrcIntRxExtRx(self,log,testscript,testbed):
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
            
            if out:
                log.info(banner('Initial Traffic flow is as expected:'))
                traffic_obj.getAllBoundStreamStatistics(tgn_hdl)
                
                traffic_item = tgn_config_dict[TG]['TEST-008']
                
                log.info(banner('Stopping all the stream and waiting for 15 seconds'))
                x = tgn_hdl.traffic_control(action='stop',max_wait_timer=60)
                countDownTimer(15)
                
                log.info(banner('Creating the new Traffic Item - Int Src, Int Rcv'))
        
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
                            c = tgn_hdl.emulation_igmp_control(mode='start',group_member_handle=a)
                            o = tgn_hdl.emulation_igmp_control(mode='join',group_member_handle=a)
                            if not o.status:
                                log.info('IGMP join is not sent to the group . Pls debug.....')
                                self.failed()
                                        
                log.info(banner('Waiting for 30 seconds before starting the traffic:'))
                countDownTimer(30)
                
                log.info(banner('Starting the New Stream Created for this test ..'))
                x = tgn_hdl.traffic_control(action='run', handle = new_tg_intf_config_dict['traffic_item'],max_wait_timer=60)
                
                if not x.status:
                    log.error(banner('The Stream {0} could not be started as expected '.format(ixia_traffic_config.stream_id)))
                    self.failed()
                
                log.info(banner('Waiting for 30 seconds before measuring the traffic stats:'))
                countDownTimer(30)
                
                ixia_stream = new_tg_intf_config_dict['stream_id']
                res = MyLib.my_config_utils.getTrafficItemStatistics(log,tgn_hdl,ixia_stream,'TEST-008')
                
                log.info(banner('The Value of res is: {0}'.format(res)))
                
                flag = 0
                
                if abs(res['tx']-res['rx']) < threshold:
                    log.info('The TRM traffic is as expected.... Adding the Created stream and re-starting all other streams:')
                    
                    log.info('Stopping the New Traffic Item stream Created for this test:')
                    x1 = tgn_hdl.traffic_control(action='stop', handle = new_tg_intf_config_dict['traffic_item'], max_wait_timer=60)
                    
                    log.info('Removing the stream {0}:'.format(ixia_stream))
                    y = tgn_hdl.traffic_config(mode='remove',stream_id=ixia_stream)
                    
#                     log.info(banner('Adding the New stream to the Main Traffic Stream Dict: '))
#                     traffic_stream_dict.setdefault('TEST-008',{})
#                     traffic_stream_dict['TEST-008'].update(new_tg_intf_config_dict)
#                     log.info('The value of traffic_stream_dict is : {0}'.format(yaml.dump(traffic_stream_dict)))
#                     
#                     log.info(banner('Adding the New stream to the configured stream list :'))
#                     configured_stream.append('TEST-008')
#                     
#                     log.info(banner('Sending the Modified Traffic_stream_dict and Configured_stream to global Testscript params'))
#                     
#                     testscript.parameters['configured_stream'] = configured_stream
#                     testscript.parameters['traffic_stream_dict'] = traffic_stream_dict
                    
                else:
                    log.error(banner('TRM Traffic item is not as expected. The value of tx and rx is : {0} and {1}'.format(res['tx'],res['rx'])))
                    log.info(banner('Stopping the newly created Stream. Ixia Name: {0} User Name is  : {1}'.format(ixia_stream,'TEST-008')))
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


class VXLANL3TRMANYCASTRPFUNC009(aetest.Testcase):

    """ Verify Int Src Rx Ext and BL-1 Rx"""

    uid = 'VXLAN-L3-TRM-ANYCAST-RP-FUNC-009'

    @aetest.test
    def VxlanL3TRMAnyCastRPIntSrcExtRxBL1Rx(self,log,testscript,testbed):
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
            
            if out:
                log.info(banner('Initial Traffic flow is as expected:'))
                traffic_obj.getAllBoundStreamStatistics(tgn_hdl)
                
                traffic_item = tgn_config_dict[TG]['TEST-009']
                
                log.info(banner('Stopping all the stream and waiting for 15 seconds'))
                x = tgn_hdl.traffic_control(action='stop',max_wait_timer=60)
                countDownTimer(15)
                
                log.info(banner('Creating the new Traffic Item - Int Src, Int Rcv'))
        
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
                            c = tgn_hdl.emulation_igmp_control(mode='start',group_member_handle=a)
                            o = tgn_hdl.emulation_igmp_control(mode='join',group_member_handle=a)
                            if not o.status:
                                log.info('IGMP join is not sent to the group . Pls debug.....')
                                self.failed()
                                        
                log.info(banner('Waiting for 30 seconds before starting the traffic:'))
                countDownTimer(30)
                
                log.info(banner('Starting the New Stream Created for this test ..'))
                x = tgn_hdl.traffic_control(action='run', handle = new_tg_intf_config_dict['traffic_item'],max_wait_timer=60)
                
                if not x.status:
                    log.error(banner('The Stream {0} could not be started as expected '.format(ixia_traffic_config.stream_id)))
                    self.failed()
                
                log.info(banner('Waiting for 30 seconds before measuring the traffic stats:'))
                countDownTimer(30)
                
                ixia_stream = new_tg_intf_config_dict['stream_id']
                res = MyLib.my_config_utils.getTrafficItemStatistics(log,tgn_hdl,ixia_stream,'TEST-009')
                
                log.info(banner('The Value of res is: {0}'.format(res)))
                
                flag = 0
                
                if abs(res['tx']-res['rx']) < threshold:
                    log.info('The TRM traffic is as expected.... Adding the Created stream and re-starting all other streams:')
                    
                    log.info('Stopping the New Traffic Item stream Created for this test:')
                    x1 = tgn_hdl.traffic_control(action='stop', handle = new_tg_intf_config_dict['traffic_item'], max_wait_timer=60)
                    
                    log.info('Removing the stream {0}:'.format(ixia_stream))
                    y = tgn_hdl.traffic_config(mode='remove',stream_id=ixia_stream)
                    
#                     log.info(banner('Adding the New stream to the Main Traffic Stream Dict: '))
#                     traffic_stream_dict.setdefault('TEST-009',{})
#                     traffic_stream_dict['TEST-009'].update(new_tg_intf_config_dict)
#                     log.info('The value of traffic_stream_dict is : {0}'.format(yaml.dump(traffic_stream_dict)))
#                     
#                     log.info(banner('Adding the New stream to the configured stream list :'))
#                     configured_stream.append('TEST-009')
#                     
#                     log.info(banner('Sending the Modified Traffic_stream_dict and Configured_stream to global Testscript params'))
#                     
#                     testscript.parameters['configured_stream'] = configured_stream
#                     testscript.parameters['traffic_stream_dict'] = traffic_stream_dict
                    
                else:
                    log.error(banner('TRM Traffic item is not as expected. The value of tx and rx is : {0} and {1}'.format(res['tx'],res['rx'])))
                    log.info(banner('Stopping the newly created Stream. Ixia Name: {0} User Name is  : {1}'.format(ixia_stream,'TEST-009')))
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

class VXLANL3TRMANYCASTRPFUNC010(aetest.Testcase):

    """ Verify Int Src Rx Ext and BL-2 Rx"""

    uid = 'VXLAN-L3-TRM-ANYCAST-RP-FUNC-010'

    @aetest.test
    def VxlanL3TRMAnyCastRPIntSrcExtRxBL1Rx(self,log,testscript,testbed):
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
            
            if out:
                log.info(banner('Initial Traffic flow is as expected:'))
                traffic_obj.getAllBoundStreamStatistics(tgn_hdl)
                
                traffic_item = tgn_config_dict[TG]['TEST-010']
                
                log.info(banner('Stopping all the stream and waiting for 15 seconds'))
                x = tgn_hdl.traffic_control(action='stop',max_wait_timer=60)
                countDownTimer(15)
                
                log.info(banner('Creating the new Traffic Item - Int Src, Int Rcv'))
        
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
                            c = tgn_hdl.emulation_igmp_control(mode='start',group_member_handle=a)
                            o = tgn_hdl.emulation_igmp_control(mode='join',group_member_handle=a)
                            if not o.status:
                                log.info('IGMP join is not sent to the group . Pls debug.....')
                                self.failed()
                                        
                log.info(banner('Waiting for 30 seconds before starting the traffic:'))
                countDownTimer(30)
                
                log.info(banner('Starting the New Stream Created for this test ..'))
                x = tgn_hdl.traffic_control(action='run', handle = new_tg_intf_config_dict['traffic_item'],max_wait_timer=60)
                
                if not x.status:
                    log.error(banner('The Stream {0} could not be started as expected '.format(ixia_traffic_config.stream_id)))
                    self.failed()
                
                log.info(banner('Waiting for 30 seconds before measuring the traffic stats:'))
                countDownTimer(30)
                
                ixia_stream = new_tg_intf_config_dict['stream_id']
                res = MyLib.my_config_utils.getTrafficItemStatistics(log,tgn_hdl,ixia_stream,'TEST-010')
                
                log.info(banner('The Value of res is: {0}'.format(res)))
                
                flag = 0
                
                if abs(res['tx']-res['rx']) < threshold:
                    log.info('The TRM traffic is as expected.... Adding the Created stream and re-starting all other streams:')
                    
                    log.info('Stopping the New Traffic Item stream Created for this test:')
                    x1 = tgn_hdl.traffic_control(action='stop', handle = new_tg_intf_config_dict['traffic_item'], max_wait_timer=60)
                    
                    log.info('Removing the stream {0}:'.format(ixia_stream))
                    y = tgn_hdl.traffic_config(mode='remove',stream_id=ixia_stream)
                    
#                     log.info(banner('Adding the New stream to the Main Traffic Stream Dict: '))
#                     traffic_stream_dict.setdefault('TEST-010',{})
#                     traffic_stream_dict['TEST-010'].update(new_tg_intf_config_dict)
#                     log.info('The value of traffic_stream_dict is : {0}'.format(yaml.dump(traffic_stream_dict)))
#                     
#                     log.info(banner('Adding the New stream to the configured stream list :'))
#                     configured_stream.append('TEST-010')
#                     
#                     log.info(banner('Sending the Modified Traffic_stream_dict and Configured_stream to global Testscript params'))
#                     
#                     testscript.parameters['configured_stream'] = configured_stream
#                     testscript.parameters['traffic_stream_dict'] = traffic_stream_dict
                    
                else:
                    log.error(banner('TRM Traffic item is not as expected. The value of tx and rx is : {0} and {1}'.format(res['tx'],res['rx'])))
                    log.info(banner('Stopping the newly created Stream. Ixia Name: {0} User Name is  : {1}'.format(ixia_stream,'TEST-010')))
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

class VXLANL3TRMANYCASTRPFUNC011(aetest.Testcase):

    """ Verify Int Src Rx Everwhere"""

    uid = 'VXLAN-L3-TRM-ANYCAST-RP-FUNC-011'

    @aetest.test
    def VxlanL3TRMAnyCastRPIntSrcRxEverywhere(self,log,testscript,testbed):
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
            
            if out:
                log.info(banner('Initial Traffic flow is as expected:'))
                traffic_obj.getAllBoundStreamStatistics(tgn_hdl)
                
                traffic_item = tgn_config_dict[TG]['TEST-011']
                
                log.info(banner('Stopping all the stream and waiting for 15 seconds'))
                x = tgn_hdl.traffic_control(action='stop',max_wait_timer=60)
                countDownTimer(15)
                
                log.info(banner('Creating the new Traffic Item - Int Src, Int Rcv'))
        
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
                            c = tgn_hdl.emulation_igmp_control(mode='start',group_member_handle=a)
                            o = tgn_hdl.emulation_igmp_control(mode='join',group_member_handle=a)
                            if not o.status:
                                log.info('IGMP join is not sent to the group . Pls debug.....')
                                self.failed()
                                        
                log.info(banner('Waiting for 30 seconds before starting the traffic:'))
                countDownTimer(30)
                
                log.info(banner('Starting the New Stream Created for this test ..'))
                x = tgn_hdl.traffic_control(action='run', handle = new_tg_intf_config_dict['traffic_item'],max_wait_timer=60)
                
                if not x.status:
                    log.error(banner('The Stream {0} could not be started as expected '.format(ixia_traffic_config.stream_id)))
                    self.failed()
                
                log.info(banner('Waiting for 30 seconds before measuring the traffic stats:'))
                countDownTimer(30)
                
                ixia_stream = new_tg_intf_config_dict['stream_id']
                res = MyLib.my_config_utils.getTrafficItemStatistics(log,tgn_hdl,ixia_stream,'TEST-011')
                
                log.info(banner('The Value of res is: {0}'.format(res)))
                
                flag = 0
                
                if abs(res['tx']-res['rx']) < threshold:
                    log.info('The TRM traffic is as expected.... Adding the Created stream and re-starting all other streams:')
                    
                    log.info('Stopping the New Traffic Item stream Created for this test:')
                    x1 = tgn_hdl.traffic_control(action='stop', handle = new_tg_intf_config_dict['traffic_item'], max_wait_timer=60)
                    
                    log.info('Removing the stream {0}:'.format(ixia_stream))
                    y = tgn_hdl.traffic_config(mode='remove',stream_id=ixia_stream)
                    
#                     log.info(banner('Adding the New stream to the Main Traffic Stream Dict: '))
#                     traffic_stream_dict.setdefault('TEST-011',{})
#                     traffic_stream_dict['TEST-011'].update(new_tg_intf_config_dict)
#                     log.info('The value of traffic_stream_dict is : {0}'.format(yaml.dump(traffic_stream_dict)))
#                     
#                     log.info(banner('Adding the New stream to the configured stream list :'))
#                     configured_stream.append('TEST-011')
#                     
#                     log.info(banner('Sending the Modified Traffic_stream_dict and Configured_stream to global Testscript params'))
#                     
#                     testscript.parameters['configured_stream'] = configured_stream
#                     testscript.parameters['traffic_stream_dict'] = traffic_stream_dict
                    
                else:
                    log.error(banner('TRM Traffic item is not as expected. The value of tx and rx is : {0} and {1}'.format(res['tx'],res['rx'])))
                    log.info(banner('Stopping the newly created Stream. Ixia Name: {0} User Name is  : {1}'.format(ixia_stream,'TEST-011')))
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

class VXLANL3TRMANYCASTRPFUNC012(aetest.Testcase):

    """ Verify Int Src BL-2 Int Rx EveryWhere"""

    uid = 'VXLAN-L3-TRM-ANYCAST-RP-FUNC-012'

    @aetest.test
    def VxlanL3TRMAnyCastRPIntSrcBL2RxIntEverywhere(self,log,testscript,testbed):
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
            
            if out:
                log.info(banner('Initial Traffic flow is as expected:'))
                traffic_obj.getAllBoundStreamStatistics(tgn_hdl)
                
                traffic_item = tgn_config_dict[TG]['TEST-012']
                
                log.info(banner('Stopping all the stream and waiting for 15 seconds'))
                x = tgn_hdl.traffic_control(action='stop',max_wait_timer=60)
                countDownTimer(15)
                
                log.info(banner('Creating the new Traffic Item - Int Src, Int Rcv'))
        
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
                            c = tgn_hdl.emulation_igmp_control(mode='start',group_member_handle=a)
                            o = tgn_hdl.emulation_igmp_control(mode='join',group_member_handle=a)
                            if not o.status:
                                log.info('IGMP join is not sent to the group . Pls debug.....')
                                self.failed()
                                        
                log.info(banner('Waiting for 30 seconds before starting the traffic:'))
                countDownTimer(30)
                
                log.info(banner('Starting the New Stream Created for this test ..'))
                x = tgn_hdl.traffic_control(action='run', handle = new_tg_intf_config_dict['traffic_item'],max_wait_timer=60)
                
                if not x.status:
                    log.error(banner('The Stream {0} could not be started as expected '.format(ixia_traffic_config.stream_id)))
                    self.failed()
                
                log.info(banner('Waiting for 30 seconds before measuring the traffic stats:'))
                countDownTimer(30)
                
                ixia_stream = new_tg_intf_config_dict['stream_id']
                res = MyLib.my_config_utils.getTrafficItemStatistics(log,tgn_hdl,ixia_stream,'TEST-012')
                
                log.info(banner('The Value of res is: {0}'.format(res)))
                
                flag = 0
                
                if abs(res['tx']-res['rx']) < threshold:
                    log.info('The TRM traffic is as expected.... Adding the Created stream and re-starting all other streams:')
                    
                    log.info('Stopping the New Traffic Item stream Created for this test:')
                    x1 = tgn_hdl.traffic_control(action='stop', handle = new_tg_intf_config_dict['traffic_item'], max_wait_timer=60)
                    
                    log.info('Removing the stream {0}:'.format(ixia_stream))
                    y = tgn_hdl.traffic_config(mode='remove',stream_id=ixia_stream)
                    
#                     log.info(banner('Adding the New stream to the Main Traffic Stream Dict: '))
#                     traffic_stream_dict.setdefault('TEST-012',{})
#                     traffic_stream_dict['TEST-012'].update(new_tg_intf_config_dict)
#                     log.info('The value of traffic_stream_dict is : {0}'.format(yaml.dump(traffic_stream_dict)))
#                     
#                     log.info(banner('Adding the New stream to the configured stream list :'))
#                     configured_stream.append('TEST-012')
#                     
#                     log.info(banner('Sending the Modified Traffic_stream_dict and Configured_stream to global Testscript params'))
#                     
#                     testscript.parameters['configured_stream'] = configured_stream
#                     testscript.parameters['traffic_stream_dict'] = traffic_stream_dict
                    
                else:
                    log.error(banner('TRM Traffic item is not as expected. The value of tx and rx is : {0} and {1}'.format(res['tx'],res['rx'])))
                    log.info(banner('Stopping the newly created Stream. Ixia Name: {0} User Name is  : {1}'.format(ixia_stream,'TEST-012')))
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

class VXLANL3TRMANYCASTRPFUNC013(aetest.Testcase):

    """ Verify BL-1 Source  Rx EveryWhere"""

    uid = 'VXLAN-L3-TRM-ANYCAST-RP-FUNC-013'

    @aetest.test
    def VxlanL3TRMAnyCastRPBL1SrcRxEverywhere(self,log,testscript,testbed):
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
            
            if out:
                log.info(banner('Initial Traffic flow is as expected:'))
                traffic_obj.getAllBoundStreamStatistics(tgn_hdl)
                
                traffic_item = tgn_config_dict[TG]['TEST-013']
                
                log.info(banner('Stopping all the stream and waiting for 15 seconds'))
                x = tgn_hdl.traffic_control(action='stop',max_wait_timer=60)
                countDownTimer(15)
                
                log.info(banner('Creating the new Traffic Item - Int Src, Int Rcv'))
        
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
                            c = tgn_hdl.emulation_igmp_control(mode='start',group_member_handle=a)
                            o = tgn_hdl.emulation_igmp_control(mode='join',group_member_handle=a)
                            if not o.status:
                                log.info('IGMP join is not sent to the group . Pls debug.....')
                                self.failed()
                                        
                log.info(banner('Waiting for 30 seconds before starting the traffic:'))
                countDownTimer(30)
                
                log.info(banner('Starting the New Stream Created for this test ..'))
                x = tgn_hdl.traffic_control(action='run', handle = new_tg_intf_config_dict['traffic_item'],max_wait_timer=60)
                
                if not x.status:
                    log.error(banner('The Stream {0} could not be started as expected '.format(ixia_traffic_config.stream_id)))
                    self.failed()
                
                log.info(banner('Waiting for 30 seconds before measuring the traffic stats:'))
                countDownTimer(30)
                
                ixia_stream = new_tg_intf_config_dict['stream_id']
                res = MyLib.my_config_utils.getTrafficItemStatistics(log,tgn_hdl,ixia_stream,'TEST-013')
                
                log.info(banner('The Value of res is: {0}'.format(res)))
                
                flag = 0
                
                if abs(res['tx']-res['rx']) < threshold:
                    log.info('The TRM traffic is as expected.... Adding the Created stream and re-starting all other streams:')
                    
                    log.info('Stopping the New Traffic Item stream Created for this test:')
                    x1 = tgn_hdl.traffic_control(action='stop', handle = new_tg_intf_config_dict['traffic_item'], max_wait_timer=60)
                    
                    log.info('Removing the stream {0}:'.format(ixia_stream))
                    y = tgn_hdl.traffic_config(mode='remove',stream_id=ixia_stream)
                    
#                     log.info(banner('Adding the New stream to the Main Traffic Stream Dict: '))
#                     traffic_stream_dict.setdefault('TEST-013',{})
#                     traffic_stream_dict['TEST-013'].update(new_tg_intf_config_dict)
#                     log.info('The value of traffic_stream_dict is : {0}'.format(yaml.dump(traffic_stream_dict)))
#                     
#                     log.info(banner('Adding the New stream to the configured stream list :'))
#                     configured_stream.append('TEST-013')
#                     
#                     log.info(banner('Sending the Modified Traffic_stream_dict and Configured_stream to global Testscript params'))
#                     
#                     testscript.parameters['configured_stream'] = configured_stream
#                     testscript.parameters['traffic_stream_dict'] = traffic_stream_dict
                    
                else:
                    log.error(banner('TRM Traffic item is not as expected. The value of tx and rx is : {0} and {1}'.format(res['tx'],res['rx'])))
                    log.info(banner('Stopping the newly created Stream. Ixia Name: {0} User Name is  : {1}'.format(ixia_stream,'TEST-013')))
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


class VXLANL3TRMANYCASTRPFUNC014(aetest.Testcase):

    """ Verify BL-2 Source  Rx EveryWhere"""

    uid = 'VXLAN-L3-TRM-ANYCAST-RP-FUNC-014'

    @aetest.test
    def VxlanL3TRMAnyCastRPBL2SrcRxEverywhere(self,log,testscript,testbed):
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
            
            if out:
                log.info(banner('Initial Traffic flow is as expected:'))
                traffic_obj.getAllBoundStreamStatistics(tgn_hdl)
                
                traffic_item = tgn_config_dict[TG]['TEST-014']
                
                log.info(banner('Stopping all the stream and waiting for 15 seconds'))
                x = tgn_hdl.traffic_control(action='stop',max_wait_timer=60)
                countDownTimer(15)
                
                log.info(banner('Creating the new Traffic Item - Int Src, Int Rcv'))
        
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
                            c = tgn_hdl.emulation_igmp_control(mode='start',group_member_handle=a)
                            o = tgn_hdl.emulation_igmp_control(mode='join',group_member_handle=a)
                            if not o.status:
                                log.info('IGMP join is not sent to the group . Pls debug.....')
                                self.failed()
                                        
                log.info(banner('Waiting for 30 seconds before starting the traffic:'))
                countDownTimer(30)
                
                log.info(banner('Starting the New Stream Created for this test ..'))
                x = tgn_hdl.traffic_control(action='run', handle = new_tg_intf_config_dict['traffic_item'],max_wait_timer=60)
                
                if not x.status:
                    log.error(banner('The Stream {0} could not be started as expected '.format(ixia_traffic_config.stream_id)))
                    self.failed()
                
                log.info(banner('Waiting for 30 seconds before measuring the traffic stats:'))
                countDownTimer(30)
                
                ixia_stream = new_tg_intf_config_dict['stream_id']
                res = MyLib.my_config_utils.getTrafficItemStatistics(log,tgn_hdl,ixia_stream,'TEST-014')
                
                log.info(banner('The Value of res is: {0}'.format(res)))
                
                flag = 0
                
                if abs(res['tx']-res['rx']) < threshold:
                    log.info('The TRM traffic is as expected.... Adding the Created stream and re-starting all other streams:')
                    
                    log.info('Stopping the New Traffic Item stream Created for this test:')
                    x1 = tgn_hdl.traffic_control(action='stop', handle = new_tg_intf_config_dict['traffic_item'], max_wait_timer=60)
                    
                    log.info('Removing the stream {0}:'.format(ixia_stream))
                    y = tgn_hdl.traffic_config(mode='remove',stream_id=ixia_stream)
                    
#                     log.info(banner('Adding the New stream to the Main Traffic Stream Dict: '))
#                     traffic_stream_dict.setdefault('TEST-014',{})
#                     traffic_stream_dict['TEST-014'].update(new_tg_intf_config_dict)
#                     log.info('The value of traffic_stream_dict is : {0}'.format(yaml.dump(traffic_stream_dict)))
#                     
#                     log.info(banner('Adding the New stream to the configured stream list :'))
#                     configured_stream.append('TEST-014')
#                     
#                     log.info(banner('Sending the Modified Traffic_stream_dict and Configured_stream to global Testscript params'))
#                     
#                     testscript.parameters['configured_stream'] = configured_stream
#                     testscript.parameters['traffic_stream_dict'] = traffic_stream_dict
                    
                else:
                    log.error(banner('TRM Traffic item is not as expected. The value of tx and rx is : {0} and {1}'.format(res['tx'],res['rx'])))
                    log.info(banner('Stopping the newly created Stream. Ixia Name: {0} User Name is  : {1}'.format(ixia_stream,'TEST-014')))
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

class VXLANL3TRMANYCASTRPFUNC015(aetest.Testcase):

    """ Verify Ext Src  Rx VTEPs and BL1"""

    uid = 'VXLAN-L3-TRM-ANYCAST-RP-FUNC-015'

    @aetest.test
    def VxlanL3TRMAnyCastRPExtSrcIntRxBL1Rx(self,log,testscript,testbed):
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
            
            if out:
                log.info(banner('Initial Traffic flow is as expected:'))
                traffic_obj.getAllBoundStreamStatistics(tgn_hdl)
                
                traffic_item = tgn_config_dict[TG]['TEST-015']
                
                log.info(banner('Stopping all the stream and waiting for 15 seconds'))
                x = tgn_hdl.traffic_control(action='stop',max_wait_timer=60)
                countDownTimer(15)
                
                log.info(banner('Creating the new Traffic Item - Int Src, Int Rcv'))
        
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
                            c = tgn_hdl.emulation_igmp_control(mode='start',group_member_handle=a)
                            o = tgn_hdl.emulation_igmp_control(mode='join',group_member_handle=a)
                            if not o.status:
                                log.info('IGMP join is not sent to the group . Pls debug.....')
                                self.failed()
                                        
                log.info(banner('Waiting for 30 seconds before starting the traffic:'))
                countDownTimer(30)
                
                log.info(banner('Starting the New Stream Created for this test ..'))
                x = tgn_hdl.traffic_control(action='run', handle = new_tg_intf_config_dict['traffic_item'],max_wait_timer=60)
                
                if not x.status:
                    log.error(banner('The Stream {0} could not be started as expected '.format(ixia_traffic_config.stream_id)))
                    self.failed()
                
                log.info(banner('Waiting for 30 seconds before measuring the traffic stats:'))
                countDownTimer(30)
                
                ixia_stream = new_tg_intf_config_dict['stream_id']
                res = MyLib.my_config_utils.getTrafficItemStatistics(log,tgn_hdl,ixia_stream,'TEST-015')
                
                log.info(banner('The Value of res is: {0}'.format(res)))
                
                flag = 0
                
                if abs(res['tx']-res['rx']) < threshold:
                    log.info('The TRM traffic is as expected.... Adding the Created stream and re-starting all other streams:')
                    
                    log.info('Stopping the New Traffic Item stream Created for this test:')
                    x1 = tgn_hdl.traffic_control(action='stop', handle = new_tg_intf_config_dict['traffic_item'], max_wait_timer=60)
                    
                    log.info('Removing the stream {0}:'.format(ixia_stream))
                    y = tgn_hdl.traffic_config(mode='remove',stream_id=ixia_stream)
                    
#                     log.info(banner('Adding the New stream to the Main Traffic Stream Dict: '))
#                     traffic_stream_dict.setdefault('TEST-015',{})
#                     traffic_stream_dict['TEST-015'].update(new_tg_intf_config_dict)
#                     log.info('The value of traffic_stream_dict is : {0}'.format(yaml.dump(traffic_stream_dict)))
#                     
#                     log.info(banner('Adding the New stream to the configured stream list :'))
#                     configured_stream.append('TEST-015')
#                     
#                     log.info(banner('Sending the Modified Traffic_stream_dict and Configured_stream to global Testscript params'))
#                     
#                     testscript.parameters['configured_stream'] = configured_stream
#                     testscript.parameters['traffic_stream_dict'] = traffic_stream_dict
                    
                else:
                    log.error(banner('TRM Traffic item is not as expected. The value of tx and rx is : {0} and {1}'.format(res['tx'],res['rx'])))
                    log.info(banner('Stopping the newly created Stream. Ixia Name: {0} User Name is  : {1}'.format(ixia_stream,'TEST-015')))
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

class VXLANL3TRMANYCASTRPFUNC016(aetest.Testcase):

    """ Verify Ext Src  Rx VTEPs and BL2"""

    uid = 'VXLAN-L3-TRM-ANYCAST-RP-FUNC-016'

    @aetest.test
    def VxlanL3TRMAnyCastRPExtSrcIntRxBL2Rx(self,log,testscript,testbed):
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
            
            if out:
                log.info(banner('Initial Traffic flow is as expected:'))
                traffic_obj.getAllBoundStreamStatistics(tgn_hdl)
                
                traffic_item = tgn_config_dict[TG]['TEST-016']
                
                log.info(banner('Stopping all the stream and waiting for 15 seconds'))
                x = tgn_hdl.traffic_control(action='stop',max_wait_timer=60)
                countDownTimer(15)
                
                log.info(banner('Creating the new Traffic Item - Int Src, Int Rcv'))
        
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
                            c = tgn_hdl.emulation_igmp_control(mode='start',group_member_handle=a)
                            o = tgn_hdl.emulation_igmp_control(mode='join',group_member_handle=a)
                            if not o.status:
                                log.info('IGMP join is not sent to the group . Pls debug.....')
                                self.failed()
                                        
                log.info(banner('Waiting for 30 seconds before starting the traffic:'))
                countDownTimer(30)
                
                log.info(banner('Starting the New Stream Created for this test ..'))
                x = tgn_hdl.traffic_control(action='run', handle = new_tg_intf_config_dict['traffic_item'],max_wait_timer=60)
                
                if not x.status:
                    log.error(banner('The Stream {0} could not be started as expected '.format(ixia_traffic_config.stream_id)))
                    self.failed()
                
                log.info(banner('Waiting for 30 seconds before measuring the traffic stats:'))
                countDownTimer(30)
                
                ixia_stream = new_tg_intf_config_dict['stream_id']
                res = MyLib.my_config_utils.getTrafficItemStatistics(log,tgn_hdl,ixia_stream,'TEST-016')
                
                log.info(banner('The Value of res is: {0}'.format(res)))
                
                flag = 0
                
                if abs(res['tx']-res['rx']) < threshold:
                    log.info('The TRM traffic is as expected.... Adding the Created stream and re-starting all other streams:')
                    
                    log.info('Stopping the New Traffic Item stream Created for this test:')
                    x1 = tgn_hdl.traffic_control(action='stop', handle = new_tg_intf_config_dict['traffic_item'], max_wait_timer=60)
                    
                    log.info('Removing the stream {0}:'.format(ixia_stream))
                    y = tgn_hdl.traffic_config(mode='remove',stream_id=ixia_stream)
                    
#                     log.info(banner('Adding the New stream to the Main Traffic Stream Dict: '))
#                     traffic_stream_dict.setdefault('TEST-016',{})
#                     traffic_stream_dict['TEST-016'].update(new_tg_intf_config_dict)
#                     log.info('The value of traffic_stream_dict is : {0}'.format(yaml.dump(traffic_stream_dict)))
#                     
#                     log.info(banner('Adding the New stream to the configured stream list :'))
#                     configured_stream.append('TEST-016')
#                     
#                     log.info(banner('Sending the Modified Traffic_stream_dict and Configured_stream to global Testscript params'))
#                     
#                     testscript.parameters['configured_stream'] = configured_stream
#                     testscript.parameters['traffic_stream_dict'] = traffic_stream_dict
                    
                else:
                    log.error(banner('TRM Traffic item is not as expected. The value of tx and rx is : {0} and {1}'.format(res['tx'],res['rx'])))
                    log.info(banner('Stopping the newly created Stream. Ixia Name: {0} User Name is  : {1}'.format(ixia_stream,'TEST-016')))
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

class VXLANL3TRMANYCASTRPFUNC017(aetest.Testcase):

    """ Verify Ext Src  Rx VTEPs and BLs"""

    uid = 'VXLAN-L3-TRM-ANYCAST-RP-FUNC-017'

    @aetest.test
    def VxlanL3TRMAnyCastRPExtSrcIntRxBL1RxBL2Rx(self,log,testscript,testbed):
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
            
            if out:
                log.info(banner('Initial Traffic flow is as expected:'))
                traffic_obj.getAllBoundStreamStatistics(tgn_hdl)
                
                traffic_item = tgn_config_dict[TG]['TEST-017']
                
                log.info(banner('Stopping all the stream and waiting for 15 seconds'))
                x = tgn_hdl.traffic_control(action='stop',max_wait_timer=60)
                countDownTimer(15)
                
                log.info(banner('Creating the new Traffic Item - Int Src, Int Rcv'))
        
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
                            c = tgn_hdl.emulation_igmp_control(mode='start',group_member_handle=a)
                            o = tgn_hdl.emulation_igmp_control(mode='join',group_member_handle=a)
                            if not o.status:
                                log.info('IGMP join is not sent to the group . Pls debug.....')
                                self.failed()
                                        
                log.info(banner('Waiting for 30 seconds before starting the traffic:'))
                countDownTimer(30)
                
                log.info(banner('Starting the New Stream Created for this test ..'))
                x = tgn_hdl.traffic_control(action='run', handle = new_tg_intf_config_dict['traffic_item'],max_wait_timer=60)
                
                if not x.status:
                    log.error(banner('The Stream {0} could not be started as expected '.format(ixia_traffic_config.stream_id)))
                    self.failed()
                
                log.info(banner('Waiting for 30 seconds before measuring the traffic stats:'))
                countDownTimer(30)
                
                ixia_stream = new_tg_intf_config_dict['stream_id']
                res = MyLib.my_config_utils.getTrafficItemStatistics(log,tgn_hdl,ixia_stream,'TEST-017')
                
                log.info(banner('The Value of res is: {0}'.format(res)))
                
                flag = 0
                
                if abs(res['tx']-res['rx']) < threshold:
                    log.info('The TRM traffic is as expected.... Adding the Created stream and re-starting all other streams:')
                    
                    log.info('Stopping the New Traffic Item stream Created for this test:')
                    x1 = tgn_hdl.traffic_control(action='stop', handle = new_tg_intf_config_dict['traffic_item'], max_wait_timer=60)
                    
                    log.info('Removing the stream {0}:'.format(ixia_stream))
                    y = tgn_hdl.traffic_config(mode='remove',stream_id=ixia_stream)
                    
#                     log.info(banner('Adding the New stream to the Main Traffic Stream Dict: '))
#                     traffic_stream_dict.setdefault('TEST-017',{})
#                     traffic_stream_dict['TEST-017'].update(new_tg_intf_config_dict)
#                     log.info('The value of traffic_stream_dict is : {0}'.format(yaml.dump(traffic_stream_dict)))
#                     
#                     log.info(banner('Adding the New stream to the configured stream list :'))
#                     configured_stream.append('TEST-017')
#                     
#                     log.info(banner('Sending the Modified Traffic_stream_dict and Configured_stream to global Testscript params'))
#                     
#                     testscript.parameters['configured_stream'] = configured_stream
#                     testscript.parameters['traffic_stream_dict'] = traffic_stream_dict
                    
                else:
                    log.error(banner('TRM Traffic item is not as expected. The value of tx and rx is : {0} and {1}'.format(res['tx'],res['rx'])))
                    log.info(banner('Stopping the newly created Stream. Ixia Name: {0} User Name is  : {1}'.format(ixia_stream,'TEST-017')))
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


class VXLANL3TRMANYCASTRPFUNC018(aetest.Testcase):

    """ Verify Ext Src  Rx Int Rx"""

    uid = 'VXLAN-L3-TRM-ANYCAST-RP-FUNC-018'

    @aetest.test
    def VxlanL3TRMAnyCastRPExtSrcIntRx(self,log,testscript,testbed):
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
            
            if out:
                log.info(banner('Initial Traffic flow is as expected:'))
                traffic_obj.getAllBoundStreamStatistics(tgn_hdl)
                
                traffic_item = tgn_config_dict[TG]['TEST-018']
                
                log.info(banner('Stopping all the stream and waiting for 15 seconds'))
                x = tgn_hdl.traffic_control(action='stop',max_wait_timer=60)
                countDownTimer(15)
                
                log.info(banner('Creating the new Traffic Item - Int Src, Int Rcv'))
        
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
                            c = tgn_hdl.emulation_igmp_control(mode='start',group_member_handle=a)
                            o = tgn_hdl.emulation_igmp_control(mode='join',group_member_handle=a)
                            if not o.status:
                                log.info('IGMP join is not sent to the group . Pls debug.....')
                                self.failed()
                                        
                log.info(banner('Waiting for 30 seconds before starting the traffic:'))
                countDownTimer(30)
                
                log.info(banner('Starting the New Stream Created for this test ..'))
                x = tgn_hdl.traffic_control(action='run', handle = new_tg_intf_config_dict['traffic_item'],max_wait_timer=60)
                
                if not x.status:
                    log.error(banner('The Stream {0} could not be started as expected '.format(ixia_traffic_config.stream_id)))
                    self.failed()
                
                log.info(banner('Waiting for 30 seconds before measuring the traffic stats:'))
                countDownTimer(30)
                
                ixia_stream = new_tg_intf_config_dict['stream_id']
                res = MyLib.my_config_utils.getTrafficItemStatistics(log,tgn_hdl,ixia_stream,'TEST-018')
                
                log.info(banner('The Value of res is: {0}'.format(res)))
                
                flag = 0
                
                if abs(res['tx']-res['rx']) < threshold:
                    log.info('The TRM traffic is as expected.... Adding the Created stream and re-starting all other streams:')
                    
                    log.info('Stopping the New Traffic Item stream Created for this test:')
                    x1 = tgn_hdl.traffic_control(action='stop', handle = new_tg_intf_config_dict['traffic_item'], max_wait_timer=60)
                    
                    log.info('Removing the stream {0}:'.format(ixia_stream))
                    y = tgn_hdl.traffic_config(mode='remove',stream_id=ixia_stream)
                    
#                     log.info(banner('Adding the New stream to the Main Traffic Stream Dict: '))
#                     traffic_stream_dict.setdefault('TEST-018',{})
#                     traffic_stream_dict['TEST-018'].update(new_tg_intf_config_dict)
#                     log.info('The value of traffic_stream_dict is : {0}'.format(yaml.dump(traffic_stream_dict)))
#                     
#                     log.info(banner('Adding the New stream to the configured stream list :'))
#                     configured_stream.append('TEST-018')
#                     
#                     log.info(banner('Sending the Modified Traffic_stream_dict and Configured_stream to global Testscript params'))
#                     
#                     testscript.parameters['configured_stream'] = configured_stream
#                     testscript.parameters['traffic_stream_dict'] = traffic_stream_dict
                    
                else:
                    log.error(banner('TRM Traffic item is not as expected. The value of tx and rx is : {0} and {1}'.format(res['tx'],res['rx'])))
                    log.info(banner('Stopping the newly created Stream. Ixia Name: {0} User Name is  : {1}'.format(ixia_stream,'TEST-018')))
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

class VXLANL3TRMANYCASTRPFUNC019(aetest.Testcase):

    """ Verify Ext Src  Rx VPC orphans"""

    uid = 'VXLAN-L3-TRM-ANYCAST-RP-FUNC-019'

    @aetest.test
    def VxlanL3TRMAnyCastRPExtSrcVPCRx(self,log,testscript,testbed):
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
            
            if out:
                log.info(banner('Initial Traffic flow is as expected:'))
                traffic_obj.getAllBoundStreamStatistics(tgn_hdl)
                
                traffic_item = tgn_config_dict[TG]['TEST-019']
                
                log.info(banner('Stopping all the stream and waiting for 15 seconds'))
                x = tgn_hdl.traffic_control(action='stop',max_wait_timer=60)
                countDownTimer(15)
                
                log.info(banner('Creating the new Traffic Item - Int Src, Int Rcv'))
        
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
                            c = tgn_hdl.emulation_igmp_control(mode='start',group_member_handle=a)
                            o = tgn_hdl.emulation_igmp_control(mode='join',group_member_handle=a)
                            if not o.status:
                                log.info('IGMP join is not sent to the group . Pls debug.....')
                                self.failed()
                                        
                log.info(banner('Waiting for 30 seconds before starting the traffic:'))
                countDownTimer(30)
                
                log.info(banner('Starting the New Stream Created for this test ..'))
                x = tgn_hdl.traffic_control(action='run', handle = new_tg_intf_config_dict['traffic_item'],max_wait_timer=60)
                
                if not x.status:
                    log.error(banner('The Stream {0} could not be started as expected '.format(ixia_traffic_config.stream_id)))
                    self.failed()
                
                log.info(banner('Waiting for 30 seconds before measuring the traffic stats:'))
                countDownTimer(30)
                
                ixia_stream = new_tg_intf_config_dict['stream_id']
                res = MyLib.my_config_utils.getTrafficItemStatistics(log,tgn_hdl,ixia_stream,'TEST-019')
                
                log.info(banner('The Value of res is: {0}'.format(res)))
                
                flag = 0
                
                if abs(res['tx']-res['rx']) < threshold:
                    log.info('The TRM traffic is as expected.... Adding the Created stream and re-starting all other streams:')
                    
                    log.info('Stopping the New Traffic Item stream Created for this test:')
                    x1 = tgn_hdl.traffic_control(action='stop', handle = new_tg_intf_config_dict['traffic_item'], max_wait_timer=60)
                    
                    log.info('Removing the stream {0}:'.format(ixia_stream))
                    y = tgn_hdl.traffic_config(mode='remove',stream_id=ixia_stream)
                    
#                     log.info(banner('Adding the New stream to the Main Traffic Stream Dict: '))
#                     traffic_stream_dict.setdefault('TEST-019',{})
#                     traffic_stream_dict['TEST-019'].update(new_tg_intf_config_dict)
#                     log.info('The value of traffic_stream_dict is : {0}'.format(yaml.dump(traffic_stream_dict)))
#                     
#                     log.info(banner('Adding the New stream to the configured stream list :'))
#                     configured_stream.append('TEST-019')
#                     
#                     log.info(banner('Sending the Modified Traffic_stream_dict and Configured_stream to global Testscript params'))
#                     
#                     testscript.parameters['configured_stream'] = configured_stream
#                     testscript.parameters['traffic_stream_dict'] = traffic_stream_dict
                    
                else:
                    log.error(banner('TRM Traffic item is not as expected. The value of tx and rx is : {0} and {1}'.format(res['tx'],res['rx'])))
                    log.info(banner('Stopping the newly created Stream. Ixia Name: {0} User Name is  : {1}'.format(ixia_stream,'TEST-019')))
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


class VXLANL3TRMANYCASTRPFUNC020(aetest.Testcase):

    """ Verify Ext Src  Rx BL-1"""

    uid = 'VXLAN-L3-TRM-ANYCAST-RP-FUNC-020'

    @aetest.test
    def VxlanL3TRMAnyCastRPExtSrcBL1Rx(self,log,testscript,testbed):
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
            
            if out:
                log.info(banner('Initial Traffic flow is as expected:'))
                traffic_obj.getAllBoundStreamStatistics(tgn_hdl)
                
                traffic_item = tgn_config_dict[TG]['TEST-020']
                
                log.info(banner('Stopping all the stream and waiting for 15 seconds'))
                x = tgn_hdl.traffic_control(action='stop',max_wait_timer=60)
                countDownTimer(15)
                
                log.info(banner('Creating the new Traffic Item - Int Src, Int Rcv'))
        
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
                            c = tgn_hdl.emulation_igmp_control(mode='start',group_member_handle=a)
                            o = tgn_hdl.emulation_igmp_control(mode='join',group_member_handle=a)
                            if not o.status:
                                log.info('IGMP join is not sent to the group . Pls debug.....')
                                self.failed()
                                        
                log.info(banner('Waiting for 30 seconds before starting the traffic:'))
                countDownTimer(30)
                
                log.info(banner('Starting the New Stream Created for this test ..'))
                x = tgn_hdl.traffic_control(action='run', handle = new_tg_intf_config_dict['traffic_item'],max_wait_timer=60)
                
                if not x.status:
                    log.error(banner('The Stream {0} could not be started as expected '.format(ixia_traffic_config.stream_id)))
                    self.failed()
                
                log.info(banner('Waiting for 30 seconds before measuring the traffic stats:'))
                countDownTimer(30)
                
                ixia_stream = new_tg_intf_config_dict['stream_id']
                res = MyLib.my_config_utils.getTrafficItemStatistics(log,tgn_hdl,ixia_stream,'TEST-020')
                
                log.info(banner('The Value of res is: {0}'.format(res)))
                
                flag = 0
                
                if abs(res['tx']-res['rx']) < threshold:
                    log.info('The TRM traffic is as expected.... Adding the Created stream and re-starting all other streams:')
                    
                    log.info('Stopping the New Traffic Item stream Created for this test:')
                    x1 = tgn_hdl.traffic_control(action='stop', handle = new_tg_intf_config_dict['traffic_item'], max_wait_timer=60)
                    
                    log.info('Removing the stream {0}:'.format(ixia_stream))
                    y = tgn_hdl.traffic_config(mode='remove',stream_id=ixia_stream)
                    
#                     log.info(banner('Adding the New stream to the Main Traffic Stream Dict: '))
#                     traffic_stream_dict.setdefault('TEST-020',{})
#                     traffic_stream_dict['TEST-020'].update(new_tg_intf_config_dict)
#                     log.info('The value of traffic_stream_dict is : {0}'.format(yaml.dump(traffic_stream_dict)))
#                     
#                     log.info(banner('Adding the New stream to the configured stream list :'))
#                     configured_stream.append('TEST-020')
#                     
#                     log.info(banner('Sending the Modified Traffic_stream_dict and Configured_stream to global Testscript params'))
#                     
#                     testscript.parameters['configured_stream'] = configured_stream
#                     testscript.parameters['traffic_stream_dict'] = traffic_stream_dict
                    
                else:
                    log.error(banner('TRM Traffic item is not as expected. The value of tx and rx is : {0} and {1}'.format(res['tx'],res['rx'])))
                    log.info(banner('Stopping the newly created Stream. Ixia Name: {0} User Name is  : {1}'.format(ixia_stream,'TEST-020')))
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

class VXLANL3TRMANYCASTRPFUNC021(aetest.Testcase):

    """ Verify Ext Src  Rx BL2"""

    uid = 'VXLAN-L3-TRM-ANYCAST-RP-FUNC-021'

    @aetest.test
    def VxlanL3TRMAnyCastRPExtSrcBL2Rx(self,log,testscript,testbed):
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
            
            if out:
                log.info(banner('Initial Traffic flow is as expected:'))
                traffic_obj.getAllBoundStreamStatistics(tgn_hdl)
                
                traffic_item = tgn_config_dict[TG]['TEST-021']
                
                log.info(banner('Stopping all the stream and waiting for 15 seconds'))
                x = tgn_hdl.traffic_control(action='stop',max_wait_timer=60)
                countDownTimer(15)
                
                log.info(banner('Creating the new Traffic Item - Int Src, Int Rcv'))
        
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
                            c = tgn_hdl.emulation_igmp_control(mode='start',group_member_handle=a)
                            o = tgn_hdl.emulation_igmp_control(mode='join',group_member_handle=a)
                            if not o.status:
                                log.info('IGMP join is not sent to the group . Pls debug.....')
                                self.failed()
                                        
                log.info(banner('Waiting for 30 seconds before starting the traffic:'))
                countDownTimer(30)
                
                log.info(banner('Starting the New Stream Created for this test ..'))
                x = tgn_hdl.traffic_control(action='run', handle = new_tg_intf_config_dict['traffic_item'],max_wait_timer=60)
                
                if not x.status:
                    log.error(banner('The Stream {0} could not be started as expected '.format(ixia_traffic_config.stream_id)))
                    self.failed()
                
                log.info(banner('Waiting for 30 seconds before measuring the traffic stats:'))
                countDownTimer(30)
                
                ixia_stream = new_tg_intf_config_dict['stream_id']
                res = MyLib.my_config_utils.getTrafficItemStatistics(log,tgn_hdl,ixia_stream,'TEST-021')
                
                log.info(banner('The Value of res is: {0}'.format(res)))
                
                flag = 0
                
                if abs(res['tx']-res['rx']) < threshold:
                    log.info('The TRM traffic is as expected.... Adding the Created stream and re-starting all other streams:')
                    
                    log.info('Stopping the New Traffic Item stream Created for this test:')
                    x1 = tgn_hdl.traffic_control(action='stop', handle = new_tg_intf_config_dict['traffic_item'], max_wait_timer=60)
                    
                    log.info('Removing the stream {0}:'.format(ixia_stream))
                    y = tgn_hdl.traffic_config(mode='remove',stream_id=ixia_stream)
                    
#                     log.info(banner('Adding the New stream to the Main Traffic Stream Dict: '))
#                     traffic_stream_dict.setdefault('TEST-021',{})
#                     traffic_stream_dict['TEST-021'].update(new_tg_intf_config_dict)
#                     log.info('The value of traffic_stream_dict is : {0}'.format(yaml.dump(traffic_stream_dict)))
#                     
#                     log.info(banner('Adding the New stream to the configured stream list :'))
#                     configured_stream.append('TEST-021')
#                     
#                     log.info(banner('Sending the Modified Traffic_stream_dict and Configured_stream to global Testscript params'))
#                     
#                     testscript.parameters['configured_stream'] = configured_stream
#                     testscript.parameters['traffic_stream_dict'] = traffic_stream_dict
                    
                else:
                    log.error(banner('TRM Traffic item is not as expected. The value of tx and rx is : {0} and {1}'.format(res['tx'],res['rx'])))
                    log.info(banner('Stopping the newly created Stream. Ixia Name: {0} User Name is  : {1}'.format(ixia_stream,'TEST-021')))
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

class VXLANL3TRMANYCASTRPFUNC022(aetest.Testcase):

    """ Verify Ext Src  Rx BLs"""

    uid = 'VXLAN-L3-TRM-ANYCAST-RP-FUNC-022'

    @aetest.test
    def VxlanL3TRMAnyCastRPExtSrcBL1RxBL2Rx(self,log,testscript,testbed):
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
            
            if out:
                log.info(banner('Initial Traffic flow is as expected:'))
                traffic_obj.getAllBoundStreamStatistics(tgn_hdl)
                
                traffic_item = tgn_config_dict[TG]['TEST-022']
                
                log.info(banner('Stopping all the stream and waiting for 15 seconds'))
                x = tgn_hdl.traffic_control(action='stop',max_wait_timer=60)
                countDownTimer(15)
                
                log.info(banner('Creating the new Traffic Item - Int Src, Int Rcv'))
        
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
                            c = tgn_hdl.emulation_igmp_control(mode='start',group_member_handle=a)
                            o = tgn_hdl.emulation_igmp_control(mode='join',group_member_handle=a)
                            if not o.status:
                                log.info('IGMP join is not sent to the group . Pls debug.....')
                                self.failed()
                                        
                log.info(banner('Waiting for 30 seconds before starting the traffic:'))
                countDownTimer(30)
                
                log.info(banner('Starting the New Stream Created for this test ..'))
                x = tgn_hdl.traffic_control(action='run', handle = new_tg_intf_config_dict['traffic_item'],max_wait_timer=60)
                
                if not x.status:
                    log.error(banner('The Stream {0} could not be started as expected '.format(ixia_traffic_config.stream_id)))
                    self.failed()
                
                log.info(banner('Waiting for 30 seconds before measuring the traffic stats:'))
                countDownTimer(30)
                
                ixia_stream = new_tg_intf_config_dict['stream_id']
                res = MyLib.my_config_utils.getTrafficItemStatistics(log,tgn_hdl,ixia_stream,'TEST-022')
                
                log.info(banner('The Value of res is: {0}'.format(res)))
                
                flag = 0
                
                if abs(res['tx']-res['rx']) < threshold:
                    log.info('The TRM traffic is as expected.... Adding the Created stream and re-starting all other streams:')
                    
                    log.info('Stopping the New Traffic Item stream Created for this test:')
                    x1 = tgn_hdl.traffic_control(action='stop', handle = new_tg_intf_config_dict['traffic_item'], max_wait_timer=60)
                    
                    log.info('Removing the stream {0}:'.format(ixia_stream))
                    y = tgn_hdl.traffic_config(mode='remove',stream_id=ixia_stream)
                    
#                     log.info(banner('Adding the New stream to the Main Traffic Stream Dict: '))
#                     traffic_stream_dict.setdefault('TEST-022',{})
#                     traffic_stream_dict['TEST-022'].update(new_tg_intf_config_dict)
#                     log.info('The value of traffic_stream_dict is : {0}'.format(yaml.dump(traffic_stream_dict)))
#                     
#                     log.info(banner('Adding the New stream to the configured stream list :'))
#                     configured_stream.append('TEST-022')
#                     
#                     log.info(banner('Sending the Modified Traffic_stream_dict and Configured_stream to global Testscript params'))
#                     
#                     testscript.parameters['configured_stream'] = configured_stream
#                     testscript.parameters['traffic_stream_dict'] = traffic_stream_dict
                    
                else:
                    log.error(banner('TRM Traffic item is not as expected. The value of tx and rx is : {0} and {1}'.format(res['tx'],res['rx'])))
                    log.info(banner('Stopping the newly created Stream. Ixia Name: {0} User Name is  : {1}'.format(ixia_stream,'TEST-022')))
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

class VXLANL3TRMANYCASTRPFUNC023(aetest.Testcase):

    """ Verify Ext Src  VPC Rx Rx BLs"""

    uid = 'VXLAN-L3-TRM-ANYCAST-RP-FUNC-023'

    @aetest.test
    def VxlanL3TRMAnyCastRPExtSrcVPCPortRxBL1Rx(self,log,testscript,testbed):
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
            
            if out:
                log.info(banner('Initial Traffic flow is as expected:'))
                traffic_obj.getAllBoundStreamStatistics(tgn_hdl)
                
                traffic_item = tgn_config_dict[TG]['TEST-023']
                
                log.info(banner('Stopping all the stream and waiting for 15 seconds'))
                x = tgn_hdl.traffic_control(action='stop',max_wait_timer=60)
                countDownTimer(15)
                
                log.info(banner('Creating the new Traffic Item - Int Src, Int Rcv'))
        
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
                            c = tgn_hdl.emulation_igmp_control(mode='start',group_member_handle=a)
                            o = tgn_hdl.emulation_igmp_control(mode='join',group_member_handle=a)
                            if not o.status:
                                log.info('IGMP join is not sent to the group . Pls debug.....')
                                self.failed()
                                        
                log.info(banner('Waiting for 30 seconds before starting the traffic:'))
                countDownTimer(30)
                
                log.info(banner('Starting the New Stream Created for this test ..'))
                x = tgn_hdl.traffic_control(action='run', handle = new_tg_intf_config_dict['traffic_item'],max_wait_timer=60)
                
                if not x.status:
                    log.error(banner('The Stream {0} could not be started as expected '.format(ixia_traffic_config.stream_id)))
                    self.failed()
                
                log.info(banner('Waiting for 30 seconds before measuring the traffic stats:'))
                countDownTimer(30)
                
                ixia_stream = new_tg_intf_config_dict['stream_id']
                res = MyLib.my_config_utils.getTrafficItemStatistics(log,tgn_hdl,ixia_stream,'TEST-023')
                
                log.info(banner('The Value of res is: {0}'.format(res)))
                
                flag = 0
                
                if abs(res['tx']-res['rx']) < threshold:
                    log.info('The TRM traffic is as expected.... Adding the Created stream and re-starting all other streams:')
                    
                    log.info('Stopping the New Traffic Item stream Created for this test:')
                    x1 = tgn_hdl.traffic_control(action='stop', handle = new_tg_intf_config_dict['traffic_item'], max_wait_timer=60)
                    
                    log.info('Removing the stream {0}:'.format(ixia_stream))
                    y = tgn_hdl.traffic_config(mode='remove',stream_id=ixia_stream)
                    
#                     log.info(banner('Adding the New stream to the Main Traffic Stream Dict: '))
#                     traffic_stream_dict.setdefault('TEST-023',{})
#                     traffic_stream_dict['TEST-023'].update(new_tg_intf_config_dict)
#                     log.info('The value of traffic_stream_dict is : {0}'.format(yaml.dump(traffic_stream_dict)))
#                     
#                     log.info(banner('Adding the New stream to the configured stream list :'))
#                     configured_stream.append('TEST-023')
#                     
#                     log.info(banner('Sending the Modified Traffic_stream_dict and Configured_stream to global Testscript params'))
#                     
#                     testscript.parameters['configured_stream'] = configured_stream
#                     testscript.parameters['traffic_stream_dict'] = traffic_stream_dict
                    
                else:
                    log.error(banner('TRM Traffic item is not as expected. The value of tx and rx is : {0} and {1}'.format(res['tx'],res['rx'])))
                    log.info(banner('Stopping the newly created Stream. Ixia Name: {0} User Name is  : {1}'.format(ixia_stream,'TEST-023')))
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

class VXLANL3TRMANYCASTRPFUNC024(aetest.Testcase):

    """ Verify Ext Src  VPC Rx Rx BL-2"""

    uid = 'VXLAN-L3-TRM-ANYCAST-RP-FUNC-024'

    @aetest.test
    def VxlanL3TRMAnyCastRPExtSrcVPCPortRxBL2Rx(self,log,testscript,testbed):
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
            
            if out:
                log.info(banner('Initial Traffic flow is as expected:'))
                traffic_obj.getAllBoundStreamStatistics(tgn_hdl)
                
                traffic_item = tgn_config_dict[TG]['TEST-024']
                
                log.info(banner('Stopping all the stream and waiting for 15 seconds'))
                x = tgn_hdl.traffic_control(action='stop',max_wait_timer=60)
                countDownTimer(15)
                
                log.info(banner('Creating the new Traffic Item - Int Src, Int Rcv'))
        
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
                            c = tgn_hdl.emulation_igmp_control(mode='start',group_member_handle=a)
                            o = tgn_hdl.emulation_igmp_control(mode='join',group_member_handle=a)
                            if not o.status:
                                log.info('IGMP join is not sent to the group . Pls debug.....')
                                self.failed()
                                        
                log.info(banner('Waiting for 30 seconds before starting the traffic:'))
                countDownTimer(30)
                
                log.info(banner('Starting the New Stream Created for this test ..'))
                x = tgn_hdl.traffic_control(action='run', handle = new_tg_intf_config_dict['traffic_item'],max_wait_timer=60)
                
                if not x.status:
                    log.error(banner('The Stream {0} could not be started as expected '.format(ixia_traffic_config.stream_id)))
                    self.failed()
                
                log.info(banner('Waiting for 30 seconds before measuring the traffic stats:'))
                countDownTimer(30)
                
                ixia_stream = new_tg_intf_config_dict['stream_id']
                res = MyLib.my_config_utils.getTrafficItemStatistics(log,tgn_hdl,ixia_stream,'TEST-024')
                
                log.info(banner('The Value of res is: {0}'.format(res)))
                
                flag = 0
                
                if abs(res['tx']-res['rx']) < threshold:
                    log.info('The TRM traffic is as expected.... Adding the Created stream and re-starting all other streams:')
                    
                    log.info('Stopping the New Traffic Item stream Created for this test:')
                    x1 = tgn_hdl.traffic_control(action='stop', handle = new_tg_intf_config_dict['traffic_item'], max_wait_timer=60)
                    
                    log.info('Removing the stream {0}:'.format(ixia_stream))
                    y = tgn_hdl.traffic_config(mode='remove',stream_id=ixia_stream)
                    
#                     log.info(banner('Adding the New stream to the Main Traffic Stream Dict: '))
#                     traffic_stream_dict.setdefault('TEST-024',{})
#                     traffic_stream_dict['TEST-024'].update(new_tg_intf_config_dict)
#                     log.info('The value of traffic_stream_dict is : {0}'.format(yaml.dump(traffic_stream_dict)))
#                     
#                     log.info(banner('Adding the New stream to the configured stream list :'))
#                     configured_stream.append('TEST-024')
#                     
#                     log.info(banner('Sending the Modified Traffic_stream_dict and Configured_stream to global Testscript params'))
#                     
#                     testscript.parameters['configured_stream'] = configured_stream
#                     testscript.parameters['traffic_stream_dict'] = traffic_stream_dict
                    
                else:
                    log.error(banner('TRM Traffic item is not as expected. The value of tx and rx is : {0} and {1}'.format(res['tx'],res['rx'])))
                    log.info(banner('Stopping the newly created Stream. Ixia Name: {0} User Name is  : {1}'.format(ixia_stream,'TEST-024')))
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

class VXLANL3TRMANYCASTRPFUNC025(aetest.Testcase):

    """ Verify Ext Src  VPC Orphan Rx and vPC Port"""

    uid = 'VXLAN-L3-TRM-ANYCAST-RP-FUNC-025'

    @aetest.test
    def VxlanL3TRMAnyCastRPExtSrcVPCPortAndVPCOrphan(self,log,testscript,testbed):
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
            
            if out:
                log.info(banner('Initial Traffic flow is as expected:'))
                traffic_obj.getAllBoundStreamStatistics(tgn_hdl)
                
                traffic_item = tgn_config_dict[TG]['TEST-025']
                
                log.info(banner('Stopping all the stream and waiting for 15 seconds'))
                x = tgn_hdl.traffic_control(action='stop',max_wait_timer=60)
                countDownTimer(15)
                
                log.info(banner('Creating the new Traffic Item - Int Src, Int Rcv'))
        
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
                            c = tgn_hdl.emulation_igmp_control(mode='start',group_member_handle=a)
                            o = tgn_hdl.emulation_igmp_control(mode='join',group_member_handle=a)
                            if not o.status:
                                log.info('IGMP join is not sent to the group . Pls debug.....')
                                self.failed()
                                        
                log.info(banner('Waiting for 30 seconds before starting the traffic:'))
                countDownTimer(30)
                
                log.info(banner('Starting the New Stream Created for this test ..'))
                x = tgn_hdl.traffic_control(action='run', handle = new_tg_intf_config_dict['traffic_item'],max_wait_timer=60)
                
                if not x.status:
                    log.error(banner('The Stream {0} could not be started as expected '.format(ixia_traffic_config.stream_id)))
                    self.failed()
                
                log.info(banner('Waiting for 30 seconds before measuring the traffic stats:'))
                countDownTimer(30)
                
                ixia_stream = new_tg_intf_config_dict['stream_id']
                res = MyLib.my_config_utils.getTrafficItemStatistics(log,tgn_hdl,ixia_stream,'TEST-025')
                
                log.info(banner('The Value of res is: {0}'.format(res)))
                
                flag = 0
                
                if abs(res['tx']-res['rx']) < threshold:
                    log.info('The TRM traffic is as expected.... Adding the Created stream and re-starting all other streams:')
                    
                    log.info('Stopping the New Traffic Item stream Created for this test:')
                    x1 = tgn_hdl.traffic_control(action='stop', handle = new_tg_intf_config_dict['traffic_item'], max_wait_timer=60)
                    
                    log.info('Removing the stream {0}:'.format(ixia_stream))
                    y = tgn_hdl.traffic_config(mode='remove',stream_id=ixia_stream)
                    
#                     log.info(banner('Adding the New stream to the Main Traffic Stream Dict: '))
#                     traffic_stream_dict.setdefault('TEST-025',{})
#                     traffic_stream_dict['TEST-025'].update(new_tg_intf_config_dict)
#                     log.info('The value of traffic_stream_dict is : {0}'.format(yaml.dump(traffic_stream_dict)))
#                     
#                     log.info(banner('Adding the New stream to the configured stream list :'))
#                     configured_stream.append('TEST-025')
#                     
#                     log.info(banner('Sending the Modified Traffic_stream_dict and Configured_stream to global Testscript params'))
#                     
#                     testscript.parameters['configured_stream'] = configured_stream
#                     testscript.parameters['traffic_stream_dict'] = traffic_stream_dict
                    
                else:
                    log.error(banner('TRM Traffic item is not as expected. The value of tx and rx is : {0} and {1}'.format(res['tx'],res['rx'])))
                    log.info(banner('Stopping the newly created Stream. Ixia Name: {0} User Name is  : {1}'.format(ixia_stream,'TEST-025')))
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

class VXLANL3TRMANYCASTRPFUNC026(aetest.Testcase):

    """ Verify Int Ext Src BL Rx"""

    uid = 'VXLAN-L3-TRM-ANYCAST-RP-FUNC-026'

    @aetest.test
    def VxlanL3TRMAnyCastRPOIntExtSrcBL1Rx(self,log,testscript,testbed):
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
            
            if out:
                log.info(banner('Initial Traffic flow is as expected:'))
                traffic_obj.getAllBoundStreamStatistics(tgn_hdl)
                
                traffic_item = tgn_config_dict[TG]['TEST-026']
                
                log.info(banner('Stopping all the stream and waiting for 15 seconds'))
                x = tgn_hdl.traffic_control(action='stop',max_wait_timer=60)
                countDownTimer(15)
                
                log.info(banner('Creating the new Traffic Item - Int Src, Int Rcv'))
        
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
                            c = tgn_hdl.emulation_igmp_control(mode='start',group_member_handle=a)
                            o = tgn_hdl.emulation_igmp_control(mode='join',group_member_handle=a)
                            if not o.status:
                                log.info('IGMP join is not sent to the group . Pls debug.....')
                                self.failed()
                                        
                log.info(banner('Waiting for 30 seconds before starting the traffic:'))
                countDownTimer(30)
                
                log.info(banner('Starting the New Stream Created for this test ..'))
                x = tgn_hdl.traffic_control(action='run', handle = new_tg_intf_config_dict['traffic_item'],max_wait_timer=60)
                
                if not x.status:
                    log.error(banner('The Stream {0} could not be started as expected '.format(ixia_traffic_config.stream_id)))
                    self.failed()
                
                log.info(banner('Waiting for 30 seconds before measuring the traffic stats:'))
                countDownTimer(30)
                
                ixia_stream = new_tg_intf_config_dict['stream_id']
                res = MyLib.my_config_utils.getTrafficItemStatistics(log,tgn_hdl,ixia_stream,'TEST-026')
                
                log.info(banner('The Value of res is: {0}'.format(res)))
                
                flag = 0
                
                if abs(res['tx']-res['rx']) < threshold:
                    log.info('The TRM traffic is as expected.... Adding the Created stream and re-starting all other streams:')
                    
                    log.info('Stopping the New Traffic Item stream Created for this test:')
                    x1 = tgn_hdl.traffic_control(action='stop', handle = new_tg_intf_config_dict['traffic_item'], max_wait_timer=60)
                    
                    log.info('Removing the stream {0}:'.format(ixia_stream))
                    y = tgn_hdl.traffic_config(mode='remove',stream_id=ixia_stream)
                    
#                     log.info(banner('Adding the New stream to the Main Traffic Stream Dict: '))
#                     traffic_stream_dict.setdefault('TEST-026',{})
#                     traffic_stream_dict['TEST-026'].update(new_tg_intf_config_dict)
#                     log.info('The value of traffic_stream_dict is : {0}'.format(yaml.dump(traffic_stream_dict)))
#                     
#                     log.info(banner('Adding the New stream to the configured stream list :'))
#                     configured_stream.append('TEST-026')
#                     
#                     log.info(banner('Sending the Modified Traffic_stream_dict and Configured_stream to global Testscript params'))
#                     
#                     testscript.parameters['configured_stream'] = configured_stream
#                     testscript.parameters['traffic_stream_dict'] = traffic_stream_dict
                    
                else:
                    log.error(banner('TRM Traffic item is not as expected. The value of tx and rx is : {0} and {1}'.format(res['tx'],res['rx'])))
                    log.info(banner('Stopping the newly created Stream. Ixia Name: {0} User Name is  : {1}'.format(ixia_stream,'TEST-026')))
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


class VXLANL3TRMANYCASTRPFUNC027(aetest.Testcase):

    """ Verify Int Ext Src BL 2 Rx"""

    uid = 'VXLAN-L3-TRM-ANYCAST-RP-FUNC-027'

    @aetest.test
    def VxlanL3TRMAnyCastRPOIntExtSrcBL2Rx(self,log,testscript,testbed):
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
            
            if out:
                log.info(banner('Initial Traffic flow is as expected:'))
                traffic_obj.getAllBoundStreamStatistics(tgn_hdl)
                
                traffic_item = tgn_config_dict[TG]['TEST-027']
                
                log.info(banner('Stopping all the stream and waiting for 15 seconds'))
                x = tgn_hdl.traffic_control(action='stop',max_wait_timer=60)
                countDownTimer(15)
                
                log.info(banner('Creating the new Traffic Item - Int Src, Int Rcv'))
        
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
                            c = tgn_hdl.emulation_igmp_control(mode='start',group_member_handle=a)
                            o = tgn_hdl.emulation_igmp_control(mode='join',group_member_handle=a)
                            if not o.status:
                                log.info('IGMP join is not sent to the group . Pls debug.....')
                                self.failed()
                                        
                log.info(banner('Waiting for 30 seconds before starting the traffic:'))
                countDownTimer(30)
                
                log.info(banner('Starting the New Stream Created for this test ..'))
                x = tgn_hdl.traffic_control(action='run', handle = new_tg_intf_config_dict['traffic_item'],max_wait_timer=60)
                
                if not x.status:
                    log.error(banner('The Stream {0} could not be started as expected '.format(ixia_traffic_config.stream_id)))
                    self.failed()
                
                log.info(banner('Waiting for 30 seconds before measuring the traffic stats:'))
                countDownTimer(30)
                
                ixia_stream = new_tg_intf_config_dict['stream_id']
                res = MyLib.my_config_utils.getTrafficItemStatistics(log,tgn_hdl,ixia_stream,'TEST-027')
                
                log.info(banner('The Value of res is: {0}'.format(res)))
                
                flag = 0
                
                if abs(res['tx']-res['rx']) < threshold:
                    log.info('The TRM traffic is as expected.... Adding the Created stream and re-starting all other streams:')
                    
                    log.info('Stopping the New Traffic Item stream Created for this test:')
                    x1 = tgn_hdl.traffic_control(action='stop', handle = new_tg_intf_config_dict['traffic_item'], max_wait_timer=60)
                    
                    log.info('Removing the stream {0}:'.format(ixia_stream))
                    y = tgn_hdl.traffic_config(mode='remove',stream_id=ixia_stream)
                    
#                     log.info(banner('Adding the New stream to the Main Traffic Stream Dict: '))
#                     traffic_stream_dict.setdefault('TEST-027',{})
#                     traffic_stream_dict['TEST-027'].update(new_tg_intf_config_dict)
#                     log.info('The value of traffic_stream_dict is : {0}'.format(yaml.dump(traffic_stream_dict)))
#                     
#                     log.info(banner('Adding the New stream to the configured stream list :'))
#                     configured_stream.append('TEST-027')
#                     
#                     log.info(banner('Sending the Modified Traffic_stream_dict and Configured_stream to global Testscript params'))
#                     
#                     testscript.parameters['configured_stream'] = configured_stream
#                     testscript.parameters['traffic_stream_dict'] = traffic_stream_dict
                    
                else:
                    log.error(banner('TRM Traffic item is not as expected. The value of tx and rx is : {0} and {1}'.format(res['tx'],res['rx'])))
                    log.info(banner('Stopping the newly created Stream. Ixia Name: {0} User Name is  : {1}'.format(ixia_stream,'TEST-027')))
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

class VXLANL3TRMANYCASTRPFUNC028(aetest.Testcase):

    """ Verify Int Ext Src BL 1 BL2  Rx"""

    uid = 'VXLAN-L3-TRM-ANYCAST-RP-FUNC-028'

    @aetest.test
    def VxlanL3TRMAnyCastRPOIntExtSrcBL2Rx(self,log,testscript,testbed):
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
            
            if out:
                log.info(banner('Initial Traffic flow is as expected:'))
                traffic_obj.getAllBoundStreamStatistics(tgn_hdl)
                
                traffic_item = tgn_config_dict[TG]['TEST-028']
                
                log.info(banner('Stopping all the stream and waiting for 15 seconds'))
                x = tgn_hdl.traffic_control(action='stop',max_wait_timer=60)
                countDownTimer(15)
                
                log.info(banner('Creating the new Traffic Item - Int Src, Int Rcv'))
        
                new_tg_intf_config_dict = traffic_config_obj.generateIGMPTrafficdict(tgn_hdl,traffic_item)
                
                log.info(banner('The value of new_tg_intf_config_dict is : {0}'.format(new_tg_intf_config_dict)))
                
                log.info(banner('Waiting For 30 seconds before Sending IGMP JOINS .'))
                countDownTimer(30)
                log.info(banner('Sending IGMP Joins now.. '))
                
                source_len = len(tgn_config_dict[TG]['TEST-028']['traffic_config_dict']['source'])
                
                for i in new_tg_intf_config_dict['destination']:
                    pat = re.compile("^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$")
                    for ip in new_tg_intf_config_dict[i]:
                        test=pat.match(ip)
                        if test:
                            a = new_tg_intf_config_dict[i][ip]['session_handle']
                            b = tgn_hdl.emulation_igmp_control(mode='start')
                            c = tgn_hdl.emulation_igmp_control(mode='start',group_member_handle=a)
                            o = tgn_hdl.emulation_igmp_control(mode='join',group_member_handle=a)
                            if not o.status:
                                log.info('IGMP join is not sent to the group . Pls debug.....')
                                self.failed()
                                        
                log.info(banner('Waiting for 30 seconds before starting the traffic:'))
                countDownTimer(30)
                
                log.info(banner('Starting the New Stream Created for this test ..'))
                x = tgn_hdl.traffic_control(action='run', handle = new_tg_intf_config_dict['traffic_item'],max_wait_timer=60)
                
                if not x.status:
                    log.error(banner('The Stream {0} could not be started as expected '.format(ixia_traffic_config.stream_id)))
                    self.failed()
                
                log.info(banner('Waiting for 30 seconds before measuring the traffic stats:'))
                countDownTimer(30)
                
                ixia_stream = new_tg_intf_config_dict['stream_id']
                res = MyLib.my_config_utils.getTrafficItemStatistics(log,tgn_hdl,ixia_stream,'TEST-028')
                
                log.info(banner('The Value of res is: {0}'.format(res)))
                
                flag = 0
                
                if abs(source_len * res['tx']-res['rx']) < threshold:
                    log.info('The TRM traffic is as expected.... Adding the Created stream and re-starting all other streams:')
                    
                    log.info('Stopping the New Traffic Item stream Created for this test:')
                    x1 = tgn_hdl.traffic_control(action='stop', handle = new_tg_intf_config_dict['traffic_item'], max_wait_timer=60)
                    
                    log.info('Removing the stream {0}:'.format(ixia_stream))
                    y = tgn_hdl.traffic_config(mode='remove',stream_id=ixia_stream)
                    
#                     log.info(banner('Adding the New stream to the Main Traffic Stream Dict: '))
#                     traffic_stream_dict.setdefault('TEST-028',{})
#                     traffic_stream_dict['TEST-028'].update(new_tg_intf_config_dict)
#                     log.info('The value of traffic_stream_dict is : {0}'.format(yaml.dump(traffic_stream_dict)))
#                     
#                     log.info(banner('Adding the New stream to the configured stream list :'))
#                     configured_stream.append('TEST-028')
#                     
#                     log.info(banner('Sending the Modified Traffic_stream_dict and Configured_stream to global Testscript params'))
#                     
#                     testscript.parameters['configured_stream'] = configured_stream
#                     testscript.parameters['traffic_stream_dict'] = traffic_stream_dict
                    
                else:
                    log.error(banner('TRM Traffic item is not as expected. The value of tx and rx is : {0} and {1}'.format(res['tx'],res['rx'])))
                    log.info(banner('Stopping the newly created Stream. Ixia Name: {0} User Name is  : {1}'.format(ixia_stream,'TEST-028')))
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

class VXLANL3TRMANYCASTRPFUNC029(aetest.Testcase):

    """ Verify BL Src Ext Src Int Rx"""

    uid = 'VXLAN-L3-TRM-ANYCAST-RP-FUNC-029'

    @aetest.test
    def VxlanL3TRMAnyCastRPBLSrcExtSrcIntRx(self,log,testscript,testbed):
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
            
            if out:
                log.info(banner('Initial Traffic flow is as expected:'))
                traffic_obj.getAllBoundStreamStatistics(tgn_hdl)
                
                traffic_item = tgn_config_dict[TG]['TEST-029']
                
                log.info(banner('Stopping all the stream and waiting for 15 seconds'))
                x = tgn_hdl.traffic_control(action='stop',max_wait_timer=60)
                countDownTimer(15)
                
                log.info(banner('Creating the new Traffic Item - Int Src, Int Rcv'))
        
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
                            c = tgn_hdl.emulation_igmp_control(mode='start',group_member_handle=a)
                            o = tgn_hdl.emulation_igmp_control(mode='join',group_member_handle=a)
                            if not o.status:
                                log.info('IGMP join is not sent to the group . Pls debug.....')
                                self.failed()
                                        
                log.info(banner('Waiting for 30 seconds before starting the traffic:'))
                countDownTimer(30)
                
                log.info(banner('Starting the New Stream Created for this test ..'))
                x = tgn_hdl.traffic_control(action='run', handle = new_tg_intf_config_dict['traffic_item'],max_wait_timer=60)
                
                if not x.status:
                    log.error(banner('The Stream {0} could not be started as expected '.format(ixia_traffic_config.stream_id)))
                    self.failed()
                
                log.info(banner('Waiting for 30 seconds before measuring the traffic stats:'))
                countDownTimer(30)
                
                ixia_stream = new_tg_intf_config_dict['stream_id']
                res = MyLib.my_config_utils.getTrafficItemStatistics(log,tgn_hdl,ixia_stream,'TEST-029')
                
                log.info(banner('The Value of res is: {0}'.format(res)))
                
                flag = 0
                
                if abs(res['tx']-res['rx']) < threshold:
                    log.info('The TRM traffic is as expected.... Adding the Created stream and re-starting all other streams:')
                    
                    log.info('Stopping the New Traffic Item stream Created for this test:')
                    x1 = tgn_hdl.traffic_control(action='stop', handle = new_tg_intf_config_dict['traffic_item'], max_wait_timer=60)
                    
                    log.info('Removing the stream {0}:'.format(ixia_stream))
                    y = tgn_hdl.traffic_config(mode='remove',stream_id=ixia_stream)
                    
#                     log.info(banner('Adding the New stream to the Main Traffic Stream Dict: '))
#                     traffic_stream_dict.setdefault('TEST-029',{})
#                     traffic_stream_dict['TEST-029'].update(new_tg_intf_config_dict)
#                     log.info('The value of traffic_stream_dict is : {0}'.format(yaml.dump(traffic_stream_dict)))
#                     
#                     log.info(banner('Adding the New stream to the configured stream list :'))
#                     configured_stream.append('TEST-029')
#                     
#                     log.info(banner('Sending the Modified Traffic_stream_dict and Configured_stream to global Testscript params'))
#                     
#                     testscript.parameters['configured_stream'] = configured_stream
#                     testscript.parameters['traffic_stream_dict'] = traffic_stream_dict
                    
                else:
                    log.error(banner('TRM Traffic item is not as expected. The value of tx and rx is : {0} and {1}'.format(res['tx'],res['rx'])))
                    log.info(banner('Stopping the newly created Stream. Ixia Name: {0} User Name is  : {1}'.format(ixia_stream,'TEST-029')))
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


class VXLANL3TRMANYCASTRPFUNC030(aetest.Testcase):

    """ Verify BL -2 Src Ext Src Int Rx"""

    uid = 'VXLAN-L3-TRM-ANYCAST-RP-FUNC-030'

    @aetest.test
    def VxlanL3TRMAnyCastRPBL2SrcExtSrcIntRx(self,log,testscript,testbed):
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
            
            if out:
                log.info(banner('Initial Traffic flow is as expected:'))
                traffic_obj.getAllBoundStreamStatistics(tgn_hdl)
                
                traffic_item = tgn_config_dict[TG]['TEST-030']
                
                log.info(banner('Stopping all the stream and waiting for 15 seconds'))
                x = tgn_hdl.traffic_control(action='stop',max_wait_timer=60)
                countDownTimer(15)
                
                log.info(banner('Creating the new Traffic Item - Int Src, Int Rcv'))
        
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
                            c = tgn_hdl.emulation_igmp_control(mode='start',group_member_handle=a)
                            o = tgn_hdl.emulation_igmp_control(mode='join',group_member_handle=a)
                            if not o.status:
                                log.info('IGMP join is not sent to the group . Pls debug.....')
                                self.failed()
                                        
                log.info(banner('Waiting for 30 seconds before starting the traffic:'))
                countDownTimer(30)
                
                log.info(banner('Starting the New Stream Created for this test ..'))
                x = tgn_hdl.traffic_control(action='run', handle = new_tg_intf_config_dict['traffic_item'],max_wait_timer=60)
                
                if not x.status:
                    log.error(banner('The Stream {0} could not be started as expected '.format(ixia_traffic_config.stream_id)))
                    self.failed()
                
                log.info(banner('Waiting for 30 seconds before measuring the traffic stats:'))
                countDownTimer(30)
                
                ixia_stream = new_tg_intf_config_dict['stream_id']
                res = MyLib.my_config_utils.getTrafficItemStatistics(log,tgn_hdl,ixia_stream,'TEST-030')
                
                log.info(banner('The Value of res is: {0}'.format(res)))
                
                flag = 0
                
                if abs(res['tx']-res['rx']) < threshold:
                    log.info('The TRM traffic is as expected.... Adding the Created stream and re-starting all other streams:')
                    
                    log.info('Stopping the New Traffic Item stream Created for this test:')
                    x1 = tgn_hdl.traffic_control(action='stop', handle = new_tg_intf_config_dict['traffic_item'], max_wait_timer=60)
                    
                    log.info('Removing the stream {0}:'.format(ixia_stream))
                    y = tgn_hdl.traffic_config(mode='remove',stream_id=ixia_stream)
                    
#                     log.info(banner('Adding the New stream to the Main Traffic Stream Dict: '))
#                     traffic_stream_dict.setdefault('TEST-030',{})
#                     traffic_stream_dict['TEST-030'].update(new_tg_intf_config_dict)
#                     log.info('The value of traffic_stream_dict is : {0}'.format(yaml.dump(traffic_stream_dict)))
#                     
#                     log.info(banner('Adding the New stream to the configured stream list :'))
#                     configured_stream.append('TEST-030')
#                     
#                     log.info(banner('Sending the Modified Traffic_stream_dict and Configured_stream to global Testscript params'))
#                     
#                     testscript.parameters['configured_stream'] = configured_stream
#                     testscript.parameters['traffic_stream_dict'] = traffic_stream_dict
                    
                else:
                    log.error(banner('TRM Traffic item is not as expected. The value of tx and rx is : {0} and {1}'.format(res['tx'],res['rx'])))
                    log.info(banner('Stopping the newly created Stream. Ixia Name: {0} User Name is  : {1}'.format(ixia_stream,'TEST-030')))
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


class VXLANL3TRMANYCASTRPFUNC031(aetest.Testcase):

    """ Verify BL -1 Src Ext Src Int Rx Everywhere"""

    uid = 'VXLAN-L3-TRM-ANYCAST-RP-FUNC-031'

    @aetest.test
    def VxlanL3TRMAnyCastRPBL2SrcExtSrcIntRx(self,log,testscript,testbed):
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
            
            if out:
                log.info(banner('Initial Traffic flow is as expected:'))
                traffic_obj.getAllBoundStreamStatistics(tgn_hdl)
                
                traffic_item = tgn_config_dict[TG]['TEST-031']
                
                log.info(banner('Stopping all the stream and waiting for 15 seconds'))
                x = tgn_hdl.traffic_control(action='stop',max_wait_timer=60)
                countDownTimer(15)
                
                log.info(banner('Creating the new Traffic Item - Int Src, Int Rcv'))
        
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
                            c = tgn_hdl.emulation_igmp_control(mode='start',group_member_handle=a)
                            o = tgn_hdl.emulation_igmp_control(mode='join',group_member_handle=a)
                            if not o.status:
                                log.info('IGMP join is not sent to the group . Pls debug.....')
                                self.failed()
                                        
                log.info(banner('Waiting for 30 seconds before starting the traffic:'))
                countDownTimer(30)
                
                log.info(banner('Starting the New Stream Created for this test ..'))
                x = tgn_hdl.traffic_control(action='run', handle = new_tg_intf_config_dict['traffic_item'],max_wait_timer=60)
                
                if not x.status:
                    log.error(banner('The Stream {0} could not be started as expected '.format(ixia_traffic_config.stream_id)))
                    self.failed()
                
                log.info(banner('Waiting for 30 seconds before measuring the traffic stats:'))
                countDownTimer(30)
                
                ixia_stream = new_tg_intf_config_dict['stream_id']
                res = MyLib.my_config_utils.getTrafficItemStatistics(log,tgn_hdl,ixia_stream,'TEST-031')
                
                log.info(banner('The Value of res is: {0}'.format(res)))
                
                flag = 0
                
                if abs(res['tx']-res['rx']) < threshold:
                    log.info('The TRM traffic is as expected.... Adding the Created stream and re-starting all other streams:')
                    
                    log.info('Stopping the New Traffic Item stream Created for this test:')
                    x1 = tgn_hdl.traffic_control(action='stop', handle = new_tg_intf_config_dict['traffic_item'], max_wait_timer=60)
                    
                    log.info('Removing the stream {0}:'.format(ixia_stream))
                    y = tgn_hdl.traffic_config(mode='remove',stream_id=ixia_stream)
                    
#                     log.info(banner('Adding the New stream to the Main Traffic Stream Dict: '))
#                     traffic_stream_dict.setdefault('TEST-031',{})
#                     traffic_stream_dict['TEST-031'].update(new_tg_intf_config_dict)
#                     log.info('The value of traffic_stream_dict is : {0}'.format(yaml.dump(traffic_stream_dict)))
#                     
#                     log.info(banner('Adding the New stream to the configured stream list :'))
#                     configured_stream.append('TEST-031')
#                     
#                     log.info(banner('Sending the Modified Traffic_stream_dict and Configured_stream to global Testscript params'))
#                     
#                     testscript.parameters['configured_stream'] = configured_stream
#                     testscript.parameters['traffic_stream_dict'] = traffic_stream_dict
                    
                else:
                    log.error(banner('TRM Traffic item is not as expected. The value of tx and rx is : {0} and {1}'.format(res['tx'],res['rx'])))
                    log.info(banner('Stopping the newly created Stream. Ixia Name: {0} User Name is  : {1}'.format(ixia_stream,'TEST-031')))
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

class VXLANL3TRMANYCASTRPFUNC032(aetest.Testcase):

    """ Verify BL -2 Src Ext Src Int Rx Everywhere"""

    uid = 'VXLAN-L3-TRM-ANYCAST-RP-FUNC-032'

    @aetest.test
    def VxlanL3TRMAnyCastRPBL2SrcExtSrcIntRx(self,log,testscript,testbed):
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
            #log.info('The value of TG is = %r', TG)
            tgn_hdl = testscript.parameters['testbed_obj'].devices[TG]
            out = trigger_obj.checkAllStreamStats(tgn_hdl)
            
            if out:
                log.info(banner('Initial Traffic flow is as expected:'))
                traffic_obj.getAllBoundStreamStatistics(tgn_hdl)
                
                traffic_item = tgn_config_dict[TG]['TEST-032']
                
                log.info(banner('Stopping all the stream and waiting for 15 seconds'))
                x = tgn_hdl.traffic_control(action='stop',max_wait_timer=60)
                countDownTimer(15)
                
                log.info(banner('Creating the new Traffic Item - Int Src, Int Rcv'))
        
                new_tg_intf_config_dict = traffic_config_obj.generateIGMPTrafficdict(tgn_hdl,traffic_item)
                
                #log.info(banner('The value of new_tg_intf_config_dict is : {0}'.format(new_tg_intf_config_dict)))
                
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
                            c = tgn_hdl.emulation_igmp_control(mode='start',group_member_handle=a)
                            o = tgn_hdl.emulation_igmp_control(mode='join',group_member_handle=a)
                            if not o.status:
                                log.info('IGMP join is not sent to the group . Pls debug.....')
                                self.failed()
                                        
                log.info(banner('Waiting for 30 seconds before starting the traffic:'))
                countDownTimer(30)
                
                log.info(banner('Starting the New Stream Created for this test ..'))
                x = tgn_hdl.traffic_control(action='run', handle = new_tg_intf_config_dict['traffic_item'],max_wait_timer=60)
                
                if not x.status:
                    log.error(banner('The Stream {0} could not be started as expected '.format(ixia_traffic_config.stream_id)))
                    self.failed()
                
                log.info(banner('Waiting for 30 seconds before measuring the traffic stats:'))
                countDownTimer(30)
                
                ixia_stream = new_tg_intf_config_dict['stream_id']
                res = MyLib.my_config_utils.getTrafficItemStatistics(log,tgn_hdl,ixia_stream,'TEST-032')
                
                log.info(banner('The Value of res is: {0}'.format(res)))
                
                flag = 0
                
                if abs(res['tx']-res['rx']) < threshold:
                    log.info('The TRM traffic is as expected.... Adding the Created stream and re-starting all other streams:')
                    
                    log.info('Stopping the New Traffic Item stream Created for this test:')
                    x1 = tgn_hdl.traffic_control(action='stop', handle = new_tg_intf_config_dict['traffic_item'], max_wait_timer=60)
                    
                    log.info('Removing the stream {0}:'.format(ixia_stream))
                    y = tgn_hdl.traffic_config(mode='remove',stream_id=ixia_stream)
                    
#                     log.info(banner('Adding the New stream to the Main Traffic Stream Dict: '))
#                     traffic_stream_dict.setdefault('TEST-032',{})
#                     traffic_stream_dict['TEST-032'].update(new_tg_intf_config_dict)
#                     log.info('The value of traffic_stream_dict is : {0}'.format(yaml.dump(traffic_stream_dict)))
#                     
#                     log.info(banner('Adding the New stream to the configured stream list :'))
#                     configured_stream.append('TEST-032')
#                     
#                     log.info(banner('Sending the Modified Traffic_stream_dict and Configured_stream to global Testscript params'))
#                     
#                     testscript.parameters['configured_stream'] = configured_stream
#                     testscript.parameters['traffic_stream_dict'] = traffic_stream_dict
                    
                else:
                    log.error(banner('TRM Traffic item is not as expected. The value of tx and rx is : {0} and {1}'.format(res['tx'],res['rx'])))
                    log.info(banner('Stopping the newly created Stream. Ixia Name: {0} User Name is  : {1}'.format(ixia_stream,'TEST-032')))
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

 
  
class VXLANL3TRMANYCASTRPFUNC033(aetest.Testcase):
  
    """ Enable / disable of NGMVPN feature """
  
    uid = 'VXLAN-L3-TRM-ANYCAST-RP-FUNC-033'
  
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
  
class VXLANL3TRMANYCASTRPFUNC034(aetest.Testcase):
  
    """ Enable / disable of BGP feature """
  
    uid = 'VXLAN-L3-TRM-ANYCAST-RP-FUNC-034'
  
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
            
class VXLANL3TRMANYCASTRPFUNC035(aetest.Testcase):
  
    """ Enable / disable of nv Overlay feature """
  
    uid = 'VXLAN-L3-TRM-ANYCAST-RP-FUNC-035'
  
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
                    out=bringup_lib.unconfigFeature(node_dict['all_dut'][dut], log, '-feature nv overlay' )
                    if out.result=='fail':
                        log.error('Disable of nv overlay failed on VTEP {0}'.format(dut))
                        self.failed()
                    else:
                        log.info('Disable of nv overlay Successful on VTEP {0}'.format(dut))
  
                  
                log.info(banner('Waiting for 30 seconds before Enabling the Feature nv overlay on Vteps'))
                countDownTimer(30)
                  
                for dut in device_dict:
                    log.info('Removing the Feature nv overlay from the VTEP {0}'.format(dut))
                    out=bringup_lib.configFeature(node_dict['all_dut'][dut], log, '-feature nv overlay' )
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
  
class VXLANL3TRMANYCASTRPFUNC036(aetest.Testcase):
  
    """ Enable / disable of nv Overlay evpn feature """
  
    uid = 'VXLAN-L3-TRM-ANYCAST-RP-FUNC-036'
  
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
  
class VXLANL3TRMANYCASTRPFUNC037(aetest.Testcase):
  
    """ Enable / disable of vn-segment-vlan-based feature """
  
    uid = 'VXLAN-L3-TRM-ANYCAST-RP-FUNC-037'
  
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
                    out=bringup_lib.unconfigFeature(node_dict['all_dut'][dut], log, '-feature nv overlay,vn-segment-vlan-based' )
                    if out.result=='fail':
                        log.error('Disable of nv overlay failed on VTEP {0}'.format(dut))
                        self.failed()
                    else:
                        log.info('Disable of nv overlay Successful on VTEP {0}'.format(dut))
  
                  
                log.info(banner('Waiting for 30 seconds before Enabling the Feature nv overlay on Vteps'))
                countDownTimer(30)
                  
                for dut in device_dict:
                    log.info('Removing the Feature nv overlay from the VTEP {0}'.format(dut))
                    out=bringup_lib.configFeature(node_dict['all_dut'][dut], log, '-feature nv overlay,vn-segment-vlan-based' )
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
                  
class VXLANL3TRMANYCASTRPFUNC038(aetest.Testcase):
  
    """ Enable / disable of interface-vlan feature """
  
    uid = 'VXLAN-L3-TRM-ANYCAST-RP-FUNC-038'
  
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
  
class VXLANL3TRMANYCASTRPFUNC039(aetest.Testcase):
  
    """ Enable / disable of Pim feature """
  
    uid = 'VXLAN-L3-TRM-ANYCAST-RP-FUNC-039'
  
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
                  
                  
class VXLANL3TRMANYCASTRPFUNC040(aetest.Testcase):
  
    """ Enable / disable of Ospf feature """
  
    uid = 'VXLAN-L3-TRM-ANYCAST-RP-FUNC-040'
  
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
  
class VXLANL3TRMANYCASTRPFUNC041(aetest.Testcase):
  
    """ Enable / disable of VPC feature """
  
    uid = 'VXLAN-L3-TRM-ANYCAST-RP-FUNC-041'
  
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
  
  
  
class VXLANL3TRMANYCASTRPFUNC042(aetest.Testcase):
  
    """ Kill IGMP Process """
  
    uid = 'VXLAN-L3-TRM-ANYCAST-RP-FUNC-042'
  
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
          
class VXLANL3TRMANYCASTRPFUNC043(aetest.Testcase):
  
    """ Kill L2RIB Process """
  
    uid = 'VXLAN-L3-TRM-ANYCAST-RP-FUNC-043'
  
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
          
class VXLANL3TRMANYCASTRPFUNC044(aetest.Testcase):
  
    """ Kill BGP Process """
  
    uid = 'VXLAN-L3-TRM-ANYCAST-RP-FUNC-044'
  
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
          
          
class VXLANL3TRMANYCASTRPFUNC045(aetest.Testcase):
  
    """ Kill MFDM Process """
  
    uid = 'VXLAN-L3-TRM-ANYCAST-RP-FUNC-045'
  
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
          
class VXLANL3TRMANYCASTRPFUNC046(aetest.Testcase):
  
    """ Kill ufdm Process """
  
    uid = 'VXLAN-L3-TRM-ANYCAST-RP-FUNC-046'
  
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
          
class VXLANL3TRMANYCASTRPFUNC047(aetest.Testcase):
  
    """ Kill nve Process """
  
    uid = 'VXLAN-L3-TRM-ANYCAST-RP-FUNC-047'
  
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
                                         
          
class VXLANL3TRMANYCASTRPFUNC048(aetest.Testcase):
  
    """ Kill pim Process """
  
    uid = 'VXLAN-L3-TRM-ANYCAST-RP-FUNC-048'
  
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
  
class VXLANL3TRMANYCASTRPFUNC049(aetest.Testcase):
  
    """ restart ospf Process """
  
    uid = 'VXLAN-L3-TRM-ANYCAST-RP-FUNC-049'
  
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
                                         
class VXLANL3TRMANYCASTRPFUNC050(aetest.Testcase):
  
    """ restart bgp Process """
  
    uid = 'VXLAN-L3-TRM-ANYCAST-RP-FUNC-050'
  
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
  
class VXLANL3TRMANYCASTRPFUNC051(aetest.Testcase):
  
    """ restart ngmvpn Process """
  
    uid = 'VXLAN-L3-TRM-ANYCAST-RP-FUNC-051'
  
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
  
class VXLANL3TRMANYCASTRPFUNC052(aetest.Testcase):
  
    """ restart pim Process """
  
    uid = 'VXLAN-L3-TRM-ANYCAST-RP-FUNC-052'
  
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
  
class VXLANL3TRMANYCASTRPFUNC053(aetest.Testcase):
  
    """ restart igmp Process """
  
    uid = 'VXLAN-L3-TRM-ANYCAST-RP-FUNC-053'
  
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
  
  
class VXLANL3TRMANYCASTRPFUNC054(aetest.Testcase):
  
    """ remove and readd vxlan IGMP snooping cli """
  
    uid = 'VXLAN-L3-TRM-ANYCAST-RP-FUNC-054'
  
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
                  
                log.info(banner('Waiting for 300 seconds before collecting the Traffic Stats'))
                countDownTimer(300)    
                  
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
                                        
class VXLANL3TRMANYCASTRPFUNC055(aetest.Testcase):
  
    """ clear ip igmp snooping entries"""
  
    uid = 'VXLAN-L3-TRM-ANYCAST-RP-FUNC-055'
  
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
  
  
  
class VXLANL3TRMANYCASTRPFUNC056(aetest.Testcase):
  
    """ clear ip igmp group entries"""
  
    uid = 'VXLAN-L3-TRM-ANYCAST-RP-FUNC-056'
  
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
  
class VXLANL3TRMANYCASTRPFUNC057(aetest.Testcase):
  
    """ clear ip mroute entries"""
  
    uid = 'VXLAN-L3-TRM-ANYCAST-RP-FUNC-057'
  
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
                                                                
class VXLANL3TRMANYCASTRPFUNC058(aetest.Testcase):
  
    """ clear ip route entries"""
  
    uid = 'VXLAN-L3-TRM-ANYCAST-RP-FUNC-058'
  
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
  
class VXLANL3TRMANYCASTRPFUNC059(aetest.Testcase):
  
    """ clear ip BGP Route entries"""
  
    uid = 'VXLAN-L3-TRM-ANYCAST-RP-FUNC-059'
  
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
                  
class VXLANL3TRMANYCASTRPFUNC060(aetest.Testcase):
  
    """ clear ip ARP entries"""
  
    uid = 'VXLAN-L3-TRM-ANYCAST-RP-FUNC-060'
  
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
  
class VXLANL3TRMANYCASTRPFUNC061(aetest.Testcase):
  
    """ clear ip PIM Route entries"""
  
    uid = 'VXLAN-L3-TRM-ANYCAST-RP-FUNC-061'
  
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
  
class VXLANL3TRMANYCASTRPFUNC062(aetest.Testcase):
  
    """ clear ip MBGP Route entries"""
  
    uid = 'VXLAN-L3-TRM-ANYCAST-RP-FUNC-062'
  
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
  
class VXLANL3TRMANYCASTRPFUNC063(aetest.Testcase):
  
    """ checking Checkpoint functionality"""
  
    uid = 'VXLAN-L3-TRM-ANYCAST-RP-FUNC-063'
  
    @aetest.test
    def checkCheckpointFunctionlity(self,log,testscript,testbed):
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
  
                log.info(banner('Verifying Checkpoint Functionality. Creating Checkpoint.'))
                  
                for dut in device_dict:
                    log.info('Deleting Existing CheckPoint and Creating in Dut {0}'.format(dut))
                    node_dict['all_dut'][dut].configure('no checkpoint c1')
                    node_dict['all_dut'][dut].configure('checkpoint c1')
                  
                log.info(banner('Removing all the Features required for the VXlan'))
                for feature in ['ospf','bgp','pim','interface-vlan','ngmvpn','nv overlay','vn-segment-vlan-based']:
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
                cfg = 'rollback running-config checkpoint c1 verbose'
#                 threads = []
#                 for dut in device_dict:
#                     t = threading.Thread(target = node_dict['all_dut'][dut].configure(cfg,timeout=600))
#                     t.start()
#                     threads.append(t)
#                 [thread.join() for thread in threads]
                for dut in device_dict:
                    log.info('Rolling Back to CheckPoint in Dut {0}'.format(dut))
                    node_dict['all_dut'][dut].configure(cfg, timeout=600)
   
                #out = trigger_obj.checkAllStreamStats(tgn_hdl)
                log.info(banner('Waiting for 360 seconds before Collecting the stats...'))
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
                                                                 
class VXLANL3TRMANYCASTRPFUNC064(aetest.Testcase):
  
    """ checking ConfigReplace functionality"""
  
    uid = 'VXLAN-L3-TRM-ANYCAST-RP-FUNC-064'
  
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
                for feature in ['ospf','bgp','pim','interface-vlan','ngmvpn','nv overlay','vn-segment-vlan-based']:
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
                                                                
                                                                
class VXLANL3TRMANYCASTRPFUNC065(aetest.Testcase):
  
    """ checking rollback functionality"""
  
    uid = 'VXLAN-L3-TRM-ANYCAST-RP-FUNC-065'
  
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
        cfg = 'checkpoint file bootflash:automation-rollback-config'
          
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
                for feature in ['ospf','bgp','pim','interface-vlan','ngmvpn','nv overlay','vn-segment-vlan-based']:
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
                  
                cfg2 = 'rollback running-config file bootflash:automation-rollback-config verbose'
#                 threads = []
#                 for dut in device_dict:
#                     t = threading.Thread(target = node_dict['all_dut'][dut].configure(cfg2,timeout=600))
#                     t.start()
#                     threads.append(t)
#                 [thread.join() for thread in threads]
                for dut in device_dict:
                    log.info('Rolling Back to Stored config in Dut {0}'.format(dut))
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
                    
                  
                                                                                     
class VXLANL3TRMANYCASTRPFUNC066(aetest.Testcase):
  
    """ Enable Disable Pim On L2 VNI SVI's"""
  
    uid = 'VXLAN-L3-TRM-ANYCAST-RP-FUNC-066'
  
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
                  
class VXLANL3TRMANYCASTRPFUNC067(aetest.Testcase):
  
    """ Enable Disable Pim On L3 VNI SVI's"""
  
    uid = 'VXLAN-L3-TRM-ANYCAST-RP-FUNC-067'
  
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
                                      
class VXLANL3TRMANYCASTRPFUNC068(aetest.Testcase):
  
    """ Enable Disable ip forward clis"""
  
    uid = 'VXLAN-L3-TRM-ANYCAST-RP-FUNC-068'
  
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
      
              
class VXLANL3TRMANYCASTRPFUNC069(aetest.Testcase):
  
    """ VPC Trigger - 1 -  VPC PORT CHANNEL FLAP - PRIMARY """
  
    uid = 'VXLAN-L3-TRM-ANYCAST-RP-FUNC-069'
  
    @aetest.test
    def vpcPortChannelShutOnPrimary(self,log,testscript,testbed):
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
  
class VXLANL3TRMANYCASTRPFUNC070(aetest.Testcase):
  
    """ VPC Trigger - 2 -  VPC PORT CHANNEL FLAP -  SECONDARY"""
  
    uid = 'VXLAN-L3-TRM-ANYCAST-RP-FUNC-070'
  
    @aetest.test
    def vpcPortChannelFlapOnSecondary(self,log,testscript,testbed):
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
  
class VXLANL3TRMANYCASTRPFUNC071(aetest.Testcase):
  
    """ VPC Trigger - 2 -  VPC Member PORT FLAP -  PRIMARY"""
  
    uid = 'VXLAN-L3-TRM-ANYCAST-RP-FUNC-071'
  
    @aetest.test
    def vpcMemberPortFlapOnPrimary(self,log,testscript,testbed):
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
                  
                out = hdl.execute('sh port-channel database interface {0} | json'.format(vpc_po))
                json_out = json.loads(out)
                  
                member_port_list = []
                for i in json_out['TABLE_interface']['ROW_interface']['TABLE_member']['ROW_member']:
                    member_port_list.append(i['port'])
                      
                log.info(banner('The vPC Member Ports are: {0}'.format(member_port_list)))
   
                k = 1
                while (k <= 10):
                    log.info(banner('***** Iteration # {0} ******'.format(k)))
                    log.info('Flapping the Interface {0} in dut {1}'.format(vpc_po,dut))
                    for intf in member_port_list:
                        res = MyLib.my_utils.flapInterface(log,hdl,intf,dut)
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
  
class VXLANL3TRMANYCASTRPFUNC072(aetest.Testcase):
  
    """ VPC Trigger - 2 -  VPC Member PORT FLAP -  Secondary"""
  
    uid = 'VXLAN-L3-TRM-ANYCAST-RP-FUNC-072'
  
    @aetest.test
    def vpcMemberPortFlapOnSecondary(self,log,testscript,testbed):
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
                  
                out = hdl.execute('sh port-channel database interface {0} | json'.format(vpc_po))
                json_out = json.loads(out)
                  
                member_port_list = []
                for i in json_out['TABLE_interface']['ROW_interface']['TABLE_member']['ROW_member']:
                    member_port_list.append(i['port'])
   
                k = 1
                while (k <= 10):
                    log.info(banner('***** Iteration # {0} ******'.format(k)))
                    log.info('Flapping the Interface {0} in dut {1}'.format(vpc_po,dut))
                    for intf in member_port_list:
                        res = MyLib.my_utils.flapInterface(log,hdl,intf,dut)
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
  
class VXLANL3TRMANYCASTRPFUNC073(aetest.Testcase):
  
    """ VPC Trigger - 2 -  VPC Role Change and VPC Domain SHut / Unshut"""
  
    uid = 'VXLAN-L3-TRM-ANYCAST-RP-FUNC-073'
  
    @aetest.test
    def vpcRoleChange(self,log,testscript,testbed):
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
                domain_id = s.find('vpc-domain-id').string
                  
                log.info(banner('The value of vpc_po is : {0}'.format(domain_id)))
                  
                cfg = '''vpc domain {0}
                         shutdown'''.format(domain_id)
                           
                hdl.configure(cfg)
                  
                log.info(banner('Wait for 100 seconds for VPC Role Change :'))
                countDownTimer(100)
                  
                cfg = '''vpc domain {0}
                         no shutdown'''.format(domain_id)
                           
                hdl.configure(cfg)
                  
                log.info(banner('Wait for 300 seconds for VPC Role Change :'))
                countDownTimer(300)
  
                out1 = trigger_obj.checkAllStreamStats(tgn_hdl)
                  
                flag = 0
                if out1:
                    log.info(banner('Traffic flow is as expected'))
                    traffic_obj.getAllBoundStreamStatistics(tgn_hdl)
                      
                    log.info(banner('Getting Back to the old VPC Role on dut {0}'.format(dut)))
                      
                    hdl.configure('terminal dont-ask')
                    countDownTimer(10)
                      
                    hdl.configure('vpc role preempt')
                      
                    log.info(banner('Wait for 300 seconds before measuring Traffic Stats :'))
                    countDownTimer(300)
                      
                    out2 = trigger_obj.checkAllStreamStats(tgn_hdl)
                    traffic_obj.getAllBoundStreamStatistics(tgn_hdl)
                      
                    if not out2:
                        log.error(banner('Traffic Flow is not as expected after vPC Role Switchover'))
                        traffic_obj.getAllBoundStreamStatistics(tgn_hdl)
                        flag = 1
                          
                    hdl.configure('terminal dont-ask')
                    countDownTimer(10)
  
                else:
                    log.error(banner('Traffic Flow is not as expected after vPC Role Switchover'))
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
  
  
class VXLANL3TRMANYCASTRPFUNC074(aetest.Testcase):
  
    """ VPC Trigger - 2 -  VPC MCT PORT Flap -- PRIMARY"""
  
    uid = 'VXLAN-L3-TRM-ANYCAST-RP-FUNC-074'
  
    @aetest.test
    def vpcMCTFlapOnPrimary(self,log,testscript,testbed):
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
                  
class VXLANL3TRMANYCASTRPFUNC075(aetest.Testcase):
  
    """ VPC Trigger - 2 -  VPC MCT PORT Flap -- SECONDARY"""
  
    uid = 'VXLAN-L3-TRM-ANYCAST-RP-FUNC-075'
  
    @aetest.test
    def vpcMCTFlapOnSecondary(self,log,testscript,testbed):
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
                  
class VXLANL3TRMANYCASTRPFUNC076(aetest.Testcase):
  
    """ VPC Trigger - 2 -  MCT Member PORT FLAP -  PRIMARY"""
  
    uid = 'VXLAN-L3-TRM-ANYCAST-RP-FUNC-076'
  
    @aetest.test
    def mctMemberPortFlapOnPrimary(self,log,testscript,testbed):
        node_dict = testscript.parameters['node_dict']
        traffic_stream_dict = testscript.parameters['traffic_stream_dict'] 
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
                mct_po = s.find('peerlink-ifindex').string
                  
                log.info(banner('The value of mct_po is : {0}'.format(mct_po)))
                  
                out = hdl.execute('sh port-channel database interface {0} | json'.format(mct_po))
                json_out = json.loads(out)
                  
                member_port_list = []
                  
                if isinstance(json_out['TABLE_interface']['ROW_interface']['TABLE_member']['ROW_member'],list):
                    for i in json_out['TABLE_interface']['ROW_interface']['TABLE_member']['ROW_member']:
                        member_port_list.append(i['port'])
                elif isinstance(json_out['TABLE_interface']['ROW_interface']['TABLE_member']['ROW_member'],dict):
                    intf = json_out['TABLE_interface']['ROW_interface']['TABLE_member']['ROW_member']['port']
                    log.info('The value of intf is : {0}'.format(intf))
                    member_port_list.append(intf)
                      
                log.info(banner('The MCT Member Ports are: {0}'.format(member_port_list)))
   
                k = 1
                while (k <= 10):
                    log.info(banner('***** Iteration # {0} ******'.format(k)))
                    log.info('Flapping the Interface {0} in dut {1}'.format(mct_po,dut))
                    for intf in member_port_list:
                        res = MyLib.my_utils.flapInterface(log,hdl,intf,dut)
                    k += 1
                      
                log.info(banner('Waiting for 90 seconds before collecting the traffic stats:'))
                countDownTimer(90)
                  
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
  
class VXLANL3TRMANYCASTRPFUNC077(aetest.Testcase):
  
    """ VPC Trigger - 2 -  MCT PORT FLAP -  Secondary"""
  
    uid = 'VXLAN-L3-TRM-ANYCAST-RP-FUNC-077'
  
    @aetest.test
    def mctMemberPortFlapOnSecondary(self,log,testscript,testbed):
        node_dict = testscript.parameters['node_dict']
        traffic_stream_dict = testscript.parameters['traffic_stream_dict'] 
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
                mct_po = s.find('peerlink-ifindex').string
                  
                log.info(banner('The value of mct_po is : {0}'.format(mct_po)))
                  
                out = hdl.execute('sh port-channel database interface {0} | json'.format(mct_po))
                json_out = json.loads(out)
                  
                member_port_list = []
                if isinstance(json_out['TABLE_interface']['ROW_interface']['TABLE_member']['ROW_member'],list):
                    for i in json_out['TABLE_interface']['ROW_interface']['TABLE_member']['ROW_member']:
                        member_port_list.append(i['port'])
                elif isinstance(json_out['TABLE_interface']['ROW_interface']['TABLE_member']['ROW_member'],dict):
                    intf = json_out['TABLE_interface']['ROW_interface']['TABLE_member']['ROW_member']['port']
                    log.info('The value of intf is : {0}'.format(intf))
                    member_port_list.append(intf)
   
                k = 1
                while (k <= 10):
                    log.info(banner('***** Iteration # {0} ******'.format(k)))
                    log.info('Flapping the Interface {0} in dut {1}'.format(mct_po,dut))
                    for intf in member_port_list:
                        res = MyLib.my_utils.flapInterface(log,hdl,intf,dut)
                    k += 1
                      
                log.info(banner('Waiting for 90 seconds before collecting the traffic stats:'))
                countDownTimer(90)
                  
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
  
class VXLANL3TRMANYCASTRPFUNC078(aetest.Testcase):
  
    """ Remove and Add VPC PO -- PRIMARY """
  
    uid = 'VXLAN-L3-TRM-ANYCAST-RP-FUNC-078'
  
    @aetest.test
    def removeAddVPCPoPrimary(self,log,testscript,testbed):
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
                  
                hdl.configure('no interface {0}'.format(vpc_po))
                      
                log.info(banner('Waiting for 30 seconds before adding back the PO:'))
                countDownTimer(30)
                  
                trigger_obj.backUpAndRestoreConfigs(list(device_dict.keys()),'restore')
                  
                log.info(banner('Waiting for 180 seconds before measuring the Traffic Stats'))
                  
                countDownTimer(180)
                  
                log.info(banner('Measuing Traffic stats:'))
                  
                out = trigger_obj.checkAllStreamStats(tgn_hdl)
                traffic_obj.getAllBoundStreamStatistics(tgn_hdl)
                flag = 0
                if not out:
                    log.error(banner('Traffic has not restored properly after the Trigger - Remove-Readd-VPC PO'))
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
  
class VXLANL3TRMANYCASTRPFUNC079(aetest.Testcase):
  
    """ Remove and Add VPC PO -- SECONDARY """
  
    uid = 'VXLAN-L3-TRM-ANYCAST-RP-FUNC-079'
  
    @aetest.test
    def removeAddVPCPoSecondary(self,log,testscript,testbed):
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
                  
                hdl.configure('no interface {0}'.format(vpc_po))
                      
                log.info(banner('Waiting for 30 seconds before adding back the PO:'))
                countDownTimer(30)
                  
                trigger_obj.backUpAndRestoreConfigs(list(device_dict.keys()),'restore')
                  
                log.info(banner('Waiting for 180 seconds before measuring the Traffic Stats'))
                  
                countDownTimer(180)
                  
                log.info(banner('Measuing Traffic stats:'))
                  
                out = trigger_obj.checkAllStreamStats(tgn_hdl)
                traffic_obj.getAllBoundStreamStatistics(tgn_hdl)
                flag = 0
                if not out:
                    log.error(banner('Traffic has not restored properly after the Trigger - Remove-Readd-VPC PO'))
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
  
class VXLANL3TRMANYCASTRPFUNC080(aetest.Testcase):
  
    """ Remove and Add MCT PO -- PRIMARY """
  
    uid = 'VXLAN-L3-TRM-ANYCAST-RP-FUNC-080'
  
    @aetest.test
    def removeAddMCTPoPRIMARY(self,log,testscript,testbed):
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
                mct_po = s.find('peerlink-ifindex').string
                  
                log.info(banner('The value of vpc_po is : {0}'.format(mct_po)))
                  
                hdl.configure('no interface {0}'.format(mct_po))
                      
                log.info(banner('Waiting for 30 seconds before adding back the MCT PO:'))
                countDownTimer(30)
                  
                trigger_obj.backUpAndRestoreConfigs(list(device_dict.keys()),'restore')
                  
                log.info(banner('Waiting for 180 seconds before measuring the Traffic Stats'))
                  
                countDownTimer(180)
                  
                log.info(banner('Measuing Traffic stats:'))
                  
                out = trigger_obj.checkAllStreamStats(tgn_hdl)
                traffic_obj.getAllBoundStreamStatistics(tgn_hdl)
                flag = 0
                if not out:
                    log.error(banner('Traffic has not restored properly after the Trigger - Remove-Readd-VPC PO'))
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
                  
class VXLANL3TRMANYCASTRPFUNC081(aetest.Testcase):
  
    """ Remove and Add MCT PO -- SECONDARY """
  
    uid = 'VXLAN-L3-TRM-ANYCAST-RP-FUNC-081'
  
    @aetest.test
    def removeAddMCTPoSecondary(self,log,testscript,testbed):
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
                mct_po = s.find('peerlink-ifindex').string
                  
                log.info(banner('The value of vpc_po is : {0}'.format(mct_po)))
                  
                hdl.configure('no interface {0}'.format(mct_po))
                      
                log.info(banner('Waiting for 30 seconds before adding back the MCT PO:'))
                countDownTimer(30)
                  
                trigger_obj.backUpAndRestoreConfigs(list(device_dict.keys()),'restore')
                  
                log.info(banner('Waiting for 180 seconds before measuring the Traffic Stats'))
                  
                countDownTimer(180)
                  
                log.info(banner('Measuing Traffic stats:'))
                  
                out = trigger_obj.checkAllStreamStats(tgn_hdl)
                traffic_obj.getAllBoundStreamStatistics(tgn_hdl)
                flag = 0
                if not out:
                    log.error(banner('Traffic has not restored properly after the Trigger - Remove-Readd-VPC PO'))
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
  
class VXLANL3TRMANYCASTRPFUNC082(aetest.Testcase):
  
    """ FLap Po on the L2 Switch """
  
    uid = 'VXLAN-L3-TRM-ANYCAST-RP-FUNC-082'
  
    @aetest.test
    def FlapPoOnL2Switch(self,log,testscript,testbed):
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
                  
                device_dict = trigger_obj.getDeviceDict('l2_switch')
                  
                res = trigger_obj.backUpAndRestoreConfigs(list(device_dict.keys()),'backup')
                  
                for dut,hdl in device_dict.items(): pass
                  
                po = list(configdict['interface_config_dict']['portchannel'][dut].keys())[0]
                  
                log.info(banner('The value of Po is : {0}'.format(po)))
                  
                res = MyLib.my_utils.flapInterface(log,hdl,po,dut)
                  
                log.info(banner('Waiting for 180 seconds before measuring the Traffic Stats'))
                  
                countDownTimer(180)
                  
                log.info(banner('Measuing Traffic stats:'))
                  
                out = trigger_obj.checkAllStreamStats(tgn_hdl)
                traffic_obj.getAllBoundStreamStatistics(tgn_hdl)
                flag = 0
                if not out:
                    log.error(banner('Traffic has not restored properly after the Trigger - Remove-Readd-VPC PO'))
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
  
class VXLANL3TRMANYCASTRPFUNC083(aetest.Testcase):
  
    """ FLap Member ports on the L2 Switch """
  
    uid = 'VXLAN-L3-TRM-ANYCAST-RP-FUNC-083'
  
    @aetest.test
    def FlapMemberPortsOnL2Switch(self,log,testscript,testbed):
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
                  
                device_dict = trigger_obj.getDeviceDict('l2_switch')
                  
                res = trigger_obj.backUpAndRestoreConfigs(list(device_dict.keys()),'backup')
                  
                for dut,hdl in device_dict.items(): pass
                  
                po = list(configdict['interface_config_dict']['portchannel'][dut].keys())[0]
                  
                log.info(banner('The value of Po is : {0}'.format(po)))
                  
                out = hdl.execute('sh port-channel database interface {0} | json'.format(po))
                json_out = json.loads(out)
                  
                member_port_list = []
                if isinstance(json_out['TABLE_interface']['ROW_interface']['TABLE_member']['ROW_member'],list):
                    for i in json_out['TABLE_interface']['ROW_interface']['TABLE_member']['ROW_member']:
                        member_port_list.append(i['port'])
                elif isinstance(json_out['TABLE_interface']['ROW_interface']['TABLE_member']['ROW_member'],dict):
                    intf = json_out['TABLE_interface']['ROW_interface']['TABLE_member']['ROW_member']['port']
                    log.info('The value of intf is : {0}'.format(intf))
                    member_port_list.append(intf)
                  
                for intf in member_port_list:
                    res = MyLib.my_utils.flapInterface(log,hdl,intf,dut)
                      
                log.info(banner('Waiting for 30 seconds before adding back the PO:'))
                  
                try:
                    trigger_obj.backUpAndRestoreConfigs(list(device_dict.keys()),'restore')
                except:
                    log.info(banner('Config Replace Errored out. Looks like not supported.'))
                  
                log.info(banner('Waiting for 180 seconds before measuring the Traffic Stats'))
                  
                countDownTimer(180)
                  
                log.info(banner('Measuing Traffic stats:'))
                  
                out = trigger_obj.checkAllStreamStats(tgn_hdl)
                traffic_obj.getAllBoundStreamStatistics(tgn_hdl)
                flag = 0
                if not out:
                    log.error(banner('Traffic has not restored properly after the Trigger - Remove-Readd-VPC PO'))
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
  
                                  
class VXLANL3TRMANYCASTRPFUNC084(aetest.Testcase):
  
    """ Remove /Readd Po on the L2 Switch """
  
    uid = 'VXLAN-L3-TRM-ANYCAST-RP-FUNC-084'
  
    @aetest.test
    def RemoveReaddPOOnL2Switch(self,log,testscript,testbed):
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
                  
                device_dict = trigger_obj.getDeviceDict('l2_switch')
                  
                res = trigger_obj.backUpAndRestoreConfigs(list(device_dict.keys()),'backup')
                  
                for dut,hdl in device_dict.items(): pass
                  
                po = list(configdict['interface_config_dict']['portchannel'][dut].keys())[0]
                  
                po_num = re.search('port-channel(\d+)',po).group(1)
                  
                log.info(banner('The value of Po is : {0}'.format(po)))
                  
#                 hdl.configure('no interface {0}'.format(po))
                      
#                 log.info(banner('Waiting for 30 seconds before adding back the PO:'))
                  
                out = hdl.execute('sh port-channel database interface {0} | json'.format(po))
                json_out = json.loads(out)
                  
                member_port_list = []
                if isinstance(json_out['TABLE_interface']['ROW_interface']['TABLE_member']['ROW_member'],list):
                    for i in json_out['TABLE_interface']['ROW_interface']['TABLE_member']['ROW_member']:
                        member_port_list.append(i['port'])
                elif isinstance(json_out['TABLE_interface']['ROW_interface']['TABLE_member']['ROW_member'],dict):
                    intf = json_out['TABLE_interface']['ROW_interface']['TABLE_member']['ROW_member']['port']
                    log.info('The value of intf is : {0}'.format(intf))
                    member_port_list.append(intf)
                      
                hdl.configure('no interface {0}'.format(po))
                      
                log.info(banner('Waiting for 30 seconds before adding back the PO:'))
                          
                for intf in member_port_list:
                    cfg = '''interface {0}
                             channel-group {1} force mode active'''.format(intf,po_num)
                    hdl.configure(cfg)
                  
                try:
                    trigger_obj.backUpAndRestoreConfigs(list(device_dict.keys()),'restore')
                except:
                    log.info(banner('Config Replace Errored out. Looks like not supported.'))
                  
                log.info(banner('Waiting for 180 seconds before measuring the Traffic Stats'))
                  
                countDownTimer(180)
                  
                log.info(banner('Measuing Traffic stats:'))
                  
                out = trigger_obj.checkAllStreamStats(tgn_hdl)
                traffic_obj.getAllBoundStreamStatistics(tgn_hdl)
                flag = 0
                if not out:
                    log.error(banner('Traffic has not restored properly after the Trigger - Remove-Readd-VPC PO'))
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
                  
class VXLANL3TRMANYCASTRPFUNC085(aetest.Testcase):
  
    """ VPC Consistency Check """
  
    uid = 'VXLAN-L3-TRM-ANYCAST-RP-FUNC-085'
  
    @aetest.test
    def checkVPCConsistency(self,log,testscript,testbed):
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
                  
                log.info(banner('Checking The VPC Consistency State Initially....'))
  
                cfg = ''' vlan 1501
                          vn-segment 101501
                      '''
                cfg1 = 'sh vpc | xml '
                out = hdl.execute(cfg1)
                soup = BeautifulSoup(out)
                status = soup.find('vpc-per-vlan-peer-consistency').string
                  
                log.info('****** Initial VPC consistency state is : {0} *****'.format(status))
                if status == 'consistent':
                    log.info(banner('Configuring a dummy vlan to induce vPC inconsistency...'))
                    hdl.configure(cfg)
                    out = hdl.execute(cfg1)
                    soup = BeautifulSoup(out)
                    log.info(banner('Waiting for 30 seconds before checking the VPC consistency..'))
                    countDownTimer(30)
                    status = soup.find('vpc-per-vlan-peer-consistency').string
                    log.info('****** Current VPC consistency state is : {0} *****'.format(status))
                    if status !='consistent':
                        log.info('VPC consistency check failed as expected.. .THe value of status is : {0}'.format(status))
                        cfg = 'no vlan 1501'
                        hdl.configure(cfg)
                        countDownTimer(30)
                        out = hdl.execute(cfg1)
                        soup = BeautifulSoup(out)
                        status = soup.find('vpc-per-vlan-peer-consistency').string
                        flag = 0
                        if status == 'consistent':
                            log.info('VPC consistency check restored as expected. THe value of status is : {0}'.format(status))
                        else:
                            log.error('VPC consistency check should have restored but.. .THe value of status is : {0}'.format(status))
                            flag = 1
                    else:
                        log.error('VPC consistency check should have failed but.. .THe value of status is : {0}'.format(status))
                        flag = 1
                  
                out = trigger_obj.checkAllStreamStats(tgn_hdl)
                traffic_obj.getAllBoundStreamStatistics(tgn_hdl)
                  
                if not out:
                    log.error(banner('VPC Consitency Check is not working as expected.'))
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
                    
class VXLANL3TRMANYCASTRPFUNC086(aetest.Testcase):
  
    """ Z-Traffic-Check -1 """
  
    uid = 'VXLAN-L3-TRM-ANYCAST-RP-FUNC-086'
  
    @aetest.test
    def zTrafficCheck(self,log,testscript,testbed):
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
                  
                secondary_dut = vpc_vtep_dict['secondary']['dut']
                secondary_hdl = vpc_vtep_dict['secondary']['hdl']
                  
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
                    res = MyLib.my_utils.shutDownInterface(log,primary_hdl,intf,primary_dut)
                      
                log.info(banner('Shutting down the Downlink Po on vPC Secondary: {0}'.format(secondary_dut)))
                  
                out = secondary_hdl.execute('show vpc brief | xml')
                s = BeautifulSoup(out)
                po = s.find('vpc-ifindex').string
                log.info('***** The Value of Po is : {0}'.format(po))
                  
                res = MyLib.my_utils.shutDownInterface(log,secondary_hdl,po,secondary_dut)
                  
                log.info(banner('Waiting for 300 seconds before collecting the Traffic Stats: '))
                countDownTimer(300)
                  
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
  
  
class VXLANL3TRMANYCASTRPFUNC087(aetest.Testcase):
  
    """ Z-Traffic-Check -2 """
  
    uid = 'VXLAN-L3-TRM-ANYCAST-RP-FUNC-087'
  
    @aetest.test
    def zTrafficCheck2(self,log,testscript,testbed):
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
                  
                secondary_dut = vpc_vtep_dict['secondary']['dut']
                secondary_hdl = vpc_vtep_dict['secondary']['hdl']
                  
                log.info(banner('Shutting down the Uplink on Secondary: {0}'.format(primary_dut)))
                out = primary_hdl.execute('show nve peers | xml')
                s = BeautifulSoup(out)
                peer_ip = s.find('peer-ip').string
                out1 = secondary_hdl.execute('show ip route {0} | json'.format(peer_ip))
                t = json.loads(out1)
                uplink_port = []
                for intf in t['TABLE_vrf']['ROW_vrf']['TABLE_addrf']['ROW_addrf']['TABLE_prefix']['ROW_prefix']['TABLE_path']['ROW_path']:
                    uplink_port.append(intf['ifname'])
                  
                log.info('The value of Uplink Port is : {0}'.format(uplink_port))
                  
                for intf in uplink_port:
                    res = MyLib.my_utils.shutDownInterface(log,primary_hdl,intf,secondary_hdl)
                      
                log.info(banner('Shutting down the Downlink Po on vPC Primary: {0}'.format(secondary_dut)))
                  
                out = primary_hdl.execute('show vpc brief | xml')
                s = BeautifulSoup(out)
                po = s.find('vpc-ifindex').string
                log.info('***** The Value of Po is : {0}'.format(po))
                  
                res = MyLib.my_utils.shutDownInterface(log,primary_hdl,po,primary_dut)
                  
                log.info(banner('Waiting for 300 seconds before collecting the Traffic Stats: '))
                countDownTimer(300)
                  
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
  
class VXLANL3TRMANYCASTRPFUNC088(aetest.Testcase):
  
    """ Vlan-State-Change """
  
    uid = 'VXLAN-L3-TRM-ANYCAST-RP-FUNC-088'
  
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
  
class VXLANL3TRMANYCASTRPFUNC089(aetest.Testcase):
  
    """ Vlan-Removal-Readd """
  
    uid = 'VXLAN-L3-TRM-ANYCAST-RP-FUNC-089'
  
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
  
class VXLANL3TRMANYCASTRPFUNC090(aetest.Testcase):
  
    """ Modify L2VNI Mapping """
  
    uid = 'VXLAN-L3-TRM-ANYCAST-RP-FUNC-090'
  
    @aetest.test
    def modfiyL2VNIMapping(self,log,testscript,testbed):
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
                  
                log.info(banner('Stopping all the Streams:'))
                a = tgn_hdl.traffic_control(action='stop',max_wait_timer=60)
                  
                log.info(banner('Modifying the L2VNI on all the VTEPs'))
                  
                svi_args = configdict['trigger_dict']['pim-enable-disable']['svi']
                ns = MyLib.my_config_utils.parseScaleSVIParams(log,svi_args)
                  
                log.info('The value of ns is : {0}'.format(ns))
                  
                nve_args = configdict['trigger_dict']['nve']['global']
                ns1 = MyLib.my_config_utils.parseNVEParams(log,nve_args)
                  
                log.info('The value of ns is : {0}'.format(ns1))
                  
                dummy_vni_start = 666401
                  
                for dut in device_dict.keys():
                    log.info(' ******** MOdifying the L2VNI on the device {0} *********'.format(dut))
                    ip_addr_list = MyLib.my_config_utils.ipaddrgen(int(ns1.no_of_l2_vni),ns1.l2_vni_mcast,ns1.l2_vni_mcast_mask)
                    log.info(banner('The value of ip_addr_list is : {0}'.format(ip_addr_list)))
                    for i,j in enumerate(range(int(ns.l2_vni_svi_start), int(ns.l2_vni_svi_start)+int(ns.no_of_l2_vni_svi))):
                        log.info('&&&&&&&& Changing VNI on Vlan {0} in dut {1} &&&&&&&&'.format(i,dut))
                        res = MyLib.my_utils.vlanOperations(log,node_dict['all_dut'][dut],dut,j,'vni_change',vni=dummy_vni_start+i)
                        log.info('Configuring the corresponding EVPN configs:')
                        evpn_cfg = '''evpn
                                 vni {0} l2
                                 rd auto
                                 route-target import auto
                                 route-target export auto'''.format(dummy_vni_start+i)
                        log.info('Value of evpn_cfg is : {0}'.format(evpn_cfg))
                        node_dict['all_dut'][dut].configure(evpn_cfg)
                        log.info('Configuring the nve configs:')
                        nve_cfg = '''interface nve 1
                                     member vni {0}
                                     mcast-group {1}'''.format(dummy_vni_start+i,ip_addr_list[i])
                        log.info('Value of nve_cfg is : {0}'.format(nve_cfg))
                        node_dict['all_dut'][dut].configure(nve_cfg)
                  
                log.info(banner('Waiting for 100 seconds before starting the Traffic...'))
                countDownTimer(100)
                  
                log.info(banner('Starting all the other streams'))
                c = tgn_hdl.traffic_control(action='run',max_wait_timer=60)
                  
                out = trigger_obj.checkAllStreamStats(tgn_hdl)
                  
                flag = 0
                if out:
                    log.info(banner('Traffic flow is as expected after Trigger: Change L2 VNI'))
                    traffic_obj.getAllBoundStreamStatistics(tgn_hdl)
                else:
                    log.error(banner('Traffic flow is NOT as expected after Trigger: Change L2 VNI . Traffic Breakup is: '))
                    traffic_obj.getAllBoundStreamStatistics(tgn_hdl)
                    flag = 1
                  
                log.info(banner('Stopping all the Streams:'))
                a = tgn_hdl.traffic_control(action='stop',max_wait_timer=60)
                  
                log.info(banner('Reverting back the configs:'))
                res = trigger_obj.backUpAndRestoreConfigs(list(device_dict.keys()),'restore')
                  
                log.info(banner('Waiting for 100 seconds before starting the Traffic...'))
                countDownTimer(100)
                  
                log.info(banner('Starting all the other streams'))
                c = a = tgn_hdl.traffic_control(action='run',max_wait_timer=60)
                  
                log.info(banner('Waiting for 100 seconds before getting Traffic Stats...'))
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
              
class VXLANL3TRMANYCASTRPFUNC091(aetest.Testcase):
  
    """ Modify L2VNI Multicast Mapping """
  
    uid = 'VXLAN-L3-TRM-ANYCAST-RP-FUNC-091'
  
    @aetest.test
    def modfiyL2VNIMcastMapping(self,log,testscript,testbed):
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
                  
                log.info(banner('Stopping all the Streams:'))
                a = tgn_hdl.traffic_control(action='stop',max_wait_timer=60)
                  
                log.info(banner('Modifying the L2VNI - MCAST MAPPING on all the VTEPs'))
                  
                nve_args = configdict['trigger_dict']['nve']['global']
                ns = MyLib.my_config_utils.parseNVEParams(log,nve_args)
                  
                log.info('The value of ns is : {0}'.format(ns))
                  
                dummy_mcast_start = '229.1.1.1'
                  
                for dut in device_dict.keys():
                    log.info(' ******** MOdifying the L2VNI - Multicast Mapping on the device {0} *********'.format(dut))
                    ip_addr_list = MyLib.my_config_utils.ipaddrgen(int(ns.no_of_l2_vni),dummy_mcast_start,ns.l2_vni_mcast_mask)
                    log.info(banner('The value of ip_addr_list is : {0}'.format(ip_addr_list)))
                    for i,j in enumerate(range(int(ns.l2_vni_start), int(ns.l2_vni_start)+int(ns.no_of_l2_vni))):
                        log.info('&&&&&&&& Changing Multicast Mapping on VNI {0} in dut {1} &&&&&&&&'.format(j,dut))
                        nve_cfg = '''interface nve 1
                                     member vni {0}
                                     mcast-group {1}'''.format(j,ip_addr_list[i])
                        log.info('Value of nve_cfg is : {0}'.format(nve_cfg))
                        node_dict['all_dut'][dut].configure(nve_cfg)
                  
                log.info(banner('Waiting for 100 seconds before starting the Traffic...'))
                countDownTimer(100)
                  
                log.info(banner('Starting all the Streams'))
                c = tgn_hdl.traffic_control(action='run',max_wait_timer=60)
                
                log.info(banner('Waiting for 100 seconds before Measuring the Traffic stats ..'))
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
                  
                log.info(banner('Stopping all the Streams:'))
                a = tgn_hdl.traffic_control(action='stop',max_wait_timer=60)
                  
                log.info(banner('Reverting back the configs:'))
                res = trigger_obj.backUpAndRestoreConfigs(list(device_dict.keys()),'restore')
                  
                log.info(banner('Waiting for 100 seconds before starting the Traffic...'))
                countDownTimer(100)
                  
                log.info(banner('Starting all the other streams'))
                c = a = tgn_hdl.traffic_control(action='run',max_wait_timer=60)
                  
                log.info(banner('Waiting for 300 seconds before getting Traffic Stats...'))
                countDownTimer(300)
                  
                out = trigger_obj.checkAllStreamStats(tgn_hdl)
                traffic_obj.getAllBoundStreamStatistics(tgn_hdl)
                  
                if not out:
                    log.error(banner('Traffic Item stats is not as expected.'))
                    traffic_obj.getAllBoundStreamStatistics(tgn_hdl)
                    trigger_obj.backUpAndRestoreConfigs(list(device_dict.keys()),'restore')
                    countDownTimer(300)
                    flag = 1
                 
                if flag:
                    log.error(banner('Traffic Item stats is not as expected. Refer Logss'))
                    traffic_obj.getAllBoundStreamStatistics(tgn_hdl)
                    cfg = 'interface nve 1 ; shutdown ; sleep 5 ; no shutdown'
                    [node_dict['all_dut'][dut].configure(cfg) for dut in list(device_dict.keys())]
                    countDownTimer(300)
                    self.failed()
  
            else:
                log.error('The Initial Traffic Condition did not pass:')
                traffic_obj.getAllBoundStreamStatistics(tgn_hdl)
                countDownTimer(180)
                self.failed()  
  
  
class VXLANL3TRMANYCASTRPFUNC092(aetest.Testcase):
  
    """ Modify L3VNI Multicast Mapping """
  
    uid = 'VXLAN-L3-TRM-ANYCAST-RP-FUNC-092'
  
    @aetest.test
    def modfiyL3VNIMcastMapping(self,log,testscript,testbed):
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
                  
                log.info(banner('Stopping all the Streams:'))
                a = tgn_hdl.traffic_control(action='stop',max_wait_timer=60)
                  
                log.info(banner('Modifying the L3VNI - MCAST MAPPING on all the VTEPs'))
                  
                nve_args = configdict['trigger_dict']['nve']['global']
                ns = MyLib.my_config_utils.parseNVEParams(log,nve_args)
                  
                log.info('The value of ns is : {0}'.format(ns))
                  
                dummy_mcast_start = '230.1.1.1'
                  
                for dut in device_dict.keys():
                    log.info(' ******** MOdifying the L2VNI - Multicast Mapping on the device {0} *********'.format(dut))
                    ip_addr_list = MyLib.my_config_utils.ipaddrgen(int(ns.no_of_l3_vni),dummy_mcast_start,ns.trm_mcast_group_start_mask)
                    log.info(banner('The value of ip_addr_list is : {0}'.format(ip_addr_list)))
                    for i,j in enumerate(range(int(ns.l3_vni_start), int(ns.l3_vni_start)+int(ns.no_of_l3_vni))):
                        log.info('&&&&&&&& Changing Multicast Mapping on VNI {0} in dut {1} &&&&&&&&'.format(j,dut))
                        nve_cfg = '''interface nve 1
                                     member vni {0} associate-vrf
                                     mcast-group {1}'''.format(j,ip_addr_list[i])
                        log.info('Value of nve_cfg is : {0}'.format(nve_cfg))
                        node_dict['all_dut'][dut].configure(nve_cfg)
                  
                log.info(banner('Waiting for 100 seconds before starting the Traffic...'))
                countDownTimer(100)
                  
                log.info(banner('Starting all the Streams'))
                c = tgn_hdl.traffic_control(action='run',max_wait_timer=60)
                  
                out = trigger_obj.checkAllStreamStats(tgn_hdl)
                  
                flag = 0
                if out:
                    log.info(banner('Traffic flow is as expected after Trigger: Change L2 VNI'))
                    traffic_obj.getAllBoundStreamStatistics(tgn_hdl)
                else:
                    log.error(banner('Traffic flow is NOT as expected after Trigger: Change L2 VNI . Traffic Breakup is: '))
                    traffic_obj.getAllBoundStreamStatistics(tgn_hdl)
                    flag = 1
                  
                log.info(banner('Stopping all the Streams:'))
                a = tgn_hdl.traffic_control(action='stop',max_wait_timer=60)
                  
                log.info(banner('Reverting back the configs:'))
                res = trigger_obj.backUpAndRestoreConfigs(list(device_dict.keys()),'restore')
                  
                log.info(banner('Waiting for 100 seconds before starting the Traffic...'))
                countDownTimer(100)
                  
                log.info(banner('Starting all the other streams'))
                c = tgn_hdl.traffic_control(action='run',max_wait_timer=60)
                  
                log.info(banner('Waiting for 100 seconds before getting Traffic Stats...'))
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
                    cfg = 'interface nve 1 ; shutdown ; sleep 5 ; no shutdown'
                    [node_dict['all_dut'][dut].configure(cfg) for dut in list(device_dict.keys())]
                    self.failed()
  
            else:
                log.error('The Initial Traffic Condition did not pass:')
                traffic_obj.getAllBoundStreamStatistics(tgn_hdl)
                countDownTimer(180)
                self.failed()  
  
class VXLANL3TRMANYCASTRPFUNC093(aetest.Testcase):
  
    """ NVE Shut on VPC Primary """
  
    uid = 'VXLAN-L3-TRM-ANYCAST-RP-FUNC-093'
  
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
                    cfg = 'interface nve 1 ; shutdown ; sleep 5 ; no shutdown'
                    [node_dict['all_dut'][dut].configure(cfg) for dut in list(device_dict.keys())]
                    self.failed()
  
            else:
                log.error('The Initial Traffic Condition did not pass:')
                traffic_obj.getAllBoundStreamStatistics(tgn_hdl)
                countDownTimer(180)
                self.failed()  
                      
  
class VXLANL3TRMANYCASTRPFUNC094(aetest.Testcase):
  
    """ NVE Shut on VPC Secondary """
  
    uid = 'VXLAN-L3-TRM-ANYCAST-RP-FUNC-094'
  
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
                    cfg = 'interface nve 1 ; shutdown ; sleep 5 ; no shutdown'
                    [node_dict['all_dut'][dut].configure(cfg) for dut in list(device_dict.keys())]
                    self.failed()
  
            else:
                log.error('The Initial Traffic Condition did not pass:')
                traffic_obj.getAllBoundStreamStatistics(tgn_hdl)
                countDownTimer(180)
                self.failed()                          
  
class VXLANL3TRMANYCASTRPFUNC095(aetest.Testcase):
  
    """ NVE Source IP Change """
  
    uid = 'VXLAN-L3-TRM-ANYCAST-RP-FUNC-095'
  
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
                    res = trigger_obj.backUpAndRestoreConfigs(list(device_dict.keys()),'restore')
                    cfg = 'interface nve 1 ; shutdown ; sleep 5 ; no shutdown'
                    [node_dict['all_dut'][dut].configure(cfg) for dut in list(device_dict.keys())]
                    countDownTimer(300)
                    self.failed()
                      
                if flag == 2:
                    log.error(banner('Trigger : Nve Source IP Change: Fail Reason: Traffic flow failed ..'))
                    cfg = 'interface nve 1 ; shutdown ; sleep 5 ; no shutdown'
                    [node_dict['all_dut'][dut].configure(cfg) for dut in list(device_dict.keys())]
                    countDownTimer(300)
                    self.failed()                
  
            else:
                log.error('The Initial Traffic Condition did not pass:')
                traffic_obj.getAllBoundStreamStatistics(tgn_hdl)
                countDownTimer(180)
                self.failed()  
  
   
class VXLANL3TRMANYCASTRPFUNC096(aetest.Testcase):
  
    """ NVE Source Interface Change"""
  
    uid = 'VXLAN-L3-TRM-ANYCAST-RP-FUNC-096'
  
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
                  
                log.info(banner('Waiting for 600 seconds before Checking the Nve Peers:')) 
                countDownTimer(600)
                  
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
                  
                log.info(banner('Waiting for 600 seconds before starting the Traffic...'))
                countDownTimer(600)
                  
                out = trigger_obj.checkAllStreamStats(tgn_hdl)
                traffic_obj.getAllBoundStreamStatistics(tgn_hdl)
                  
                if not out:
                    log.error(banner('Traffic Flow is not working as expected After reverting the source Intf IP.'))
                    traffic_obj.getAllBoundStreamStatistics(tgn_hdl)
                    cfg = 'interface nve 1 ; shutdown ; sleep 5 ; no shutdown'
                    [node_dict['all_dut'][dut].configure(cfg) for dut in list(device_dict.keys())]
                    countDownTimer(600)
                    self.failed()
                 
                if flag == 1:
                    log.error(banner('Trigger: NVE Source IP Change : Fail Reason: Peer did not come up..'))
                    res = trigger_obj.backUpAndRestoreConfigs(list(vtep_dict.keys()),'restore')
                    cfg = 'interface nve 1 ; shutdown ; sleep 5 ; no shutdown'
                    [node_dict['all_dut'][dut].configure(cfg) for dut in list(device_dict.keys())]
                    countDownTimer(600)
                    self.failed()
                      
                if flag == 2:
                    log.error(banner('Trigger : Nve Source IP Change: Fail Reason: Traffic flow failed ..'))
                    cfg = 'interface nve 1 ; shutdown ; sleep 5 ; no shutdown'
                    [node_dict['all_dut'][dut].configure(cfg) for dut in list(device_dict.keys())]
                    countDownTimer(600)
                    self.failed()                
  
            else:
                log.error('The Initial Traffic Condition did not pass:')
                traffic_obj.getAllBoundStreamStatistics(tgn_hdl)
                countDownTimer(180)
                self.failed()  
  
class VXLANL3TRMANYCASTRPFUNC097(aetest.Testcase):
  
    """ Flap NVE Source Interface"""
  
    uid = 'VXLAN-L3-TRM-ANYCAST-RP-FUNC-097'
  
    @aetest.test
    def flapNVESourceInterface(self,log,testscript,testbed):
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
                  
                log.info(banner('Flapping the NVE Source Interface on all VTEPs:'))
                  
                for dut in device_dict.keys():
                    log.info(banner('Flapping the nve source Interface on the dut {0}'.format(dut)))
                    res = MyLib.my_utils.flapInterface(log,node_dict['all_dut'][dut],'loopback 0',dut)
  
  
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
  
class VXLANL3TRMANYCASTRPFUNC098(aetest.Testcase):
  
    """ Shut NVE Uplink Interfaces - Primary"""
  
    uid = 'VXLAN-L3-TRM-ANYCAST-RP-FUNC-098'
  
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
                                
class VXLANL3TRMANYCASTRPFUNC099(aetest.Testcase):
  
    """ Shut NVE Uplink Interfaces - Secondary"""
  
    uid = 'VXLAN-L3-TRM-ANYCAST-RP-FUNC-099'
  
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
  
class VXLANL3TRMANYCASTRPFUNC100(aetest.Testcase):
  
    """ Flap NVE Uplink Interfaces - Primary"""
  
    uid = 'VXLAN-L3-TRM-ANYCAST-RP-FUNC-100'
  
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
  
class VXLANL3TRMANYCASTRPFUNC101(aetest.Testcase):
  
    """ Flap NVE Uplink Interfaces - Secondary"""
  
    uid = 'VXLAN-L3-TRM-ANYCAST-RP-FUNC-101'
  
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
  
class VXLANL3TRMANYCASTRPFUNC0102(aetest.Testcase):
  
    """ Modify Uplink To Port-Channel """
  
    uid = 'VXLAN-L3-TRM-ANYCAST-RP-FUNC-102'
  
    @aetest.test
    def modifyUplinkToPortChannel(self,log,testscript,testbed):
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
              
            #interfaces = configdict['trigger_dict']['modify-uplink']['interfaces'].split()
            port_channel_dict = configdict['trigger_dict']['modify-uplink']['portchannel']
              
            if out:
                log.info(banner('Initial Traffic flow is as expected:'))
                traffic_obj.getAllBoundStreamStatistics(tgn_hdl)
                  
                log.info(banner('Taking Backup of configs on all the VTEPs:'))
                  
                device_list = list(configdict['trigger_dict']['modify-uplink']['portchannel'].keys())
                  
                res = trigger_obj.backUpAndRestoreConfigs(device_list,'backup')
                  
                log.info(banner('Defaulting the interfaces before configuring the port-channel...'))
                  
                for dut in configdict['trigger_dict']['modify-uplink']['interfaces'].keys():
                    hdl = node_dict['all_dut'][dut]
                    interfaces = configdict['trigger_dict']['modify-uplink']['interfaces'][dut].split()
                    log.info(banner('Defaulting the interfaces : {0}'.format([alias_intf_mapping[intf] if re.search('uut',intf) else intf for intf in interfaces])))
                    new_interfaces = [alias_intf_mapping[intf] if re.search('uut',intf) else intf for intf in interfaces]
                    default_res = trigger_obj.defaultSetOfInterfaces(hdl,new_interfaces)
                      
                  
                for dut in port_channel_dict:
                    log.info('the value of dut  inside scripts is : {0}'.format(dut))
                    hdl = node_dict['all_dut'][dut]
                    for intf in port_channel_dict[dut].keys():
                        log.info('the value of intf  inside scripts is : {0}'.format(intf))
                        args = port_channel_dict[dut][intf]
                        log.info('the value of args  inside scripts is : {0}'.format(args))
                        res = trigger_obj.configurePo(hdl,intf,args)
  
                log.info(banner('Waiting for 180 seconds before collecting traffic stats: - After changing UPlink as PO'))
                countDownTimer(180)
                flag = 0
                out = trigger_obj.checkAllStreamStats(tgn_hdl)
                traffic_obj.getAllBoundStreamStatistics(tgn_hdl)
                  
                if not out:
                    log.error(banner('Traffic Flow is not working as expected.'))
                    traffic_obj.getAllBoundStreamStatistics(tgn_hdl)
                    trigger_obj.backUpAndRestoreConfigs(device_list,'restore')
                    flag = 1
                  
                log.info(banner('Reverting back to Original configs...')) 
                res = trigger_obj.backUpAndRestoreConfigs(device_list,'restore') 
                  
                log.info(banner('Waiting for 180 seconds before collecting traffic stats: - After Reverting to Phy. IF'))
                countDownTimer(180) 
                  
                out = trigger_obj.checkAllStreamStats(tgn_hdl)
                traffic_obj.getAllBoundStreamStatistics(tgn_hdl)
                  
                if not out:
                    log.error(banner('Traffic Flow is not as expected after reverting back to Original configs.'))
                    traffic_obj.getAllBoundStreamStatistics(tgn_hdl)
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
   
class VXLANL3TRMANYCASTRPFUNC103(aetest.Testcase):
  
    """ Shutdown Uplink Port-Channel - VPC Primary. """
  
    uid = 'VXLAN-L3-TRM-ANYCAST-RP-FUNC-103'
  
    @aetest.test
    def ShutUplinkPortChannelPrimary(self,log,testscript,testbed):
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
              
            #interfaces = configdict['trigger_dict']['modify-uplink']['interfaces'].split()
            port_channel_dict = configdict['trigger_dict']['modify-uplink']['portchannel']
              
            if out:
                log.info(banner('Initial Traffic flow is as expected:'))
                traffic_obj.getAllBoundStreamStatistics(tgn_hdl)
                  
                log.info(banner('Taking Backup of configs on all the VTEPs:'))
                  
                device_list = list(configdict['trigger_dict']['modify-uplink']['portchannel'].keys())
                  
                res = trigger_obj.backUpAndRestoreConfigs(device_list,'backup')
                  
                log.info(banner('Defaulting the interfaces before configuring the port-channel...'))
                  
                for dut in configdict['trigger_dict']['modify-uplink']['interfaces'].keys():
                    hdl = node_dict['all_dut'][dut]
                    interfaces = configdict['trigger_dict']['modify-uplink']['interfaces'][dut].split()
                    log.info(banner('Defaulting the interfaces : {0}'.format([alias_intf_mapping[intf] if re.search('uut',intf) else intf for intf in interfaces])))
                    new_interfaces = [alias_intf_mapping[intf] if re.search('uut',intf) else intf for intf in interfaces]
                    default_res = trigger_obj.defaultSetOfInterfaces(hdl,new_interfaces)
                  
                for dut in port_channel_dict:
                    log.info('the value of dut  inside scripts is : {0}'.format(dut))
                    hdl = node_dict['all_dut'][dut]
                    for intf in port_channel_dict[dut].keys():
                        log.info('the value of intf  inside scripts is : {0}'.format(intf))
                        args = port_channel_dict[dut][intf]
                        log.info('the value of args  inside scripts is : {0}'.format(args))
                        res = trigger_obj.configurePo(hdl,intf,args)
  
                log.info(banner('Waiting for 180 seconds before collecting traffic stats: - After changing UPlink as PO'))
                countDownTimer(180)
                flag = 0
                out = trigger_obj.checkAllStreamStats(tgn_hdl)
                traffic_obj.getAllBoundStreamStatistics(tgn_hdl)
                  
                  
                if out: 
                    log.info(banner('Traffic flow is as expected After changing the Uplink to PO.'))
                    traffic_obj.getAllBoundStreamStatistics(tgn_hdl)
                      
                    log.info(banner('Shutting down the UPlink Port-channels on VPC PRimary:'))
                    vpc_vtep_dict = trigger_obj.getVPCSwitchhdl('details')
                  
                    primary_dut = vpc_vtep_dict['primary']['dut']
                    primary_hdl = vpc_vtep_dict['primary']['hdl']
                      
                    port_channel_list = list(configdict['trigger_dict']['modify-uplink']['portchannel'][primary_dut].keys())
                    for intf in port_channel_list:
                        res = MyLib.my_utils.shutDownInterface(log,primary_hdl,intf,primary_dut)
                          
                    log.info(banner('Waiting for 30 seconds before measuring the Traffic stats:'))
                    countDownTimer(30)
                      
                    out = trigger_obj.checkAllStreamStats(tgn_hdl)
                    traffic_obj.getAllBoundStreamStatistics(tgn_hdl)
                      
                    if out:
                        log.info(banner('Traffic flow is as expected after PO SHut:'))
                        traffic_obj.getAllBoundStreamStatistics(tgn_hdl)
                        log.info(banner('Unshutting the Port-channels'))
                        for intf in port_channel_list:
                            res = MyLib.my_utils.unshutDownInterface(log,primary_hdl,intf,primary_dut)
                        log.info(banner('Waiting for 30 seconds before collecting the Traffic stats: '))
                        countDownTimer(30)
                          
                        out = trigger_obj.checkAllStreamStats(tgn_hdl)
                          
                        if out:
                            log.info(banner('Traffic flow is as expected After PO unshut:'))
                            traffic_obj.getAllBoundStreamStatistics(tgn_hdl)
                        else:
                            log.error(banner('Traffic flow is not as expected after PO unshut'))
                            traffic_obj.getAllBoundStreamStatistics(tgn_hdl)
                            flag = 1
                              
                    else:
                        log.error(banner('Traffic flow not as expected after shutting down the PO'))
                        traffic_obj.getAllBoundStreamStatistics(tgn_hdl)
                        flag = 1
                  
                if not out:
                    log.error(banner('Traffic Flow is not working as expected.'))
                    traffic_obj.getAllBoundStreamStatistics(tgn_hdl)
                    trigger_obj.backUpAndRestoreConfigs(device_list,'restore')
                    flag = 1
  
                log.info(banner('Reverting back to Original configs...')) 
                res = trigger_obj.backUpAndRestoreConfigs(device_list,'restore') 
                  
                log.info(banner('Waiting for 180 seconds before collecting traffic stats: - After Reverting to Phy. IF'))
                countDownTimer(180) 
                  
                out = trigger_obj.checkAllStreamStats(tgn_hdl)
                traffic_obj.getAllBoundStreamStatistics(tgn_hdl)
                  
                if not out:
                    log.error(banner('Traffic Flow is not as expected after reverting back to Original configs.'))
                    traffic_obj.getAllBoundStreamStatistics(tgn_hdl)
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
  
class VXLANL3TRMANYCASTRPFUNC104(aetest.Testcase):
  
    """ Shutdown Uplink Port-Channel - VPC Secondary. """
  
    uid = 'VXLAN-L3-TRM-ANYCAST-RP-FUNC-104'
  
    @aetest.test
    def ShutUplinkPortChannelSecondary(self,log,testscript,testbed):
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
              
            #interfaces = configdict['trigger_dict']['modify-uplink']['interfaces'].split()
            port_channel_dict = configdict['trigger_dict']['modify-uplink']['portchannel']
              
            if out:
                log.info(banner('Initial Traffic flow is as expected:'))
                traffic_obj.getAllBoundStreamStatistics(tgn_hdl)
                  
                log.info(banner('Taking Backup of configs on all the VTEPs:'))
                  
                device_list = list(configdict['trigger_dict']['modify-uplink']['portchannel'].keys())
                  
                res = trigger_obj.backUpAndRestoreConfigs(device_list,'backup')
                  
                log.info(banner('Defaulting the interfaces before configuring the port-channel...'))
                  
                for dut in configdict['trigger_dict']['modify-uplink']['interfaces'].keys():
                    hdl = node_dict['all_dut'][dut]
                    interfaces = configdict['trigger_dict']['modify-uplink']['interfaces'][dut].split()
                    log.info(banner('Defaulting the interfaces : {0}'.format([alias_intf_mapping[intf] if re.search('uut',intf) else intf for intf in interfaces])))
                    new_interfaces = [alias_intf_mapping[intf] if re.search('uut',intf) else intf for intf in interfaces]
                    default_res = trigger_obj.defaultSetOfInterfaces(hdl,new_interfaces)
                  
                for dut in port_channel_dict:
                    log.info('the value of dut  inside scripts is : {0}'.format(dut))
                    hdl = node_dict['all_dut'][dut]
                    for intf in port_channel_dict[dut].keys():
                        log.info('the value of intf  inside scripts is : {0}'.format(intf))
                        args = port_channel_dict[dut][intf]
                        log.info('the value of args  inside scripts is : {0}'.format(args))
                        res = trigger_obj.configurePo(hdl,intf,args)
  
                log.info(banner('Waiting for 180 seconds before collecting traffic stats: - After changing UPlink as PO'))
                countDownTimer(180)
                flag = 0
                out = trigger_obj.checkAllStreamStats(tgn_hdl)
                traffic_obj.getAllBoundStreamStatistics(tgn_hdl)
                  
                  
                if out: 
                    log.info(banner('Traffic flow is as expected After changing the Uplink to PO.'))
                    traffic_obj.getAllBoundStreamStatistics(tgn_hdl)
                      
                    log.info(banner('Shutting down the UPlink Port-channels on VPC PRimary:'))
                    vpc_vtep_dict = trigger_obj.getVPCSwitchhdl('details')
                  
                    secondary_dut = vpc_vtep_dict['secondary']['dut']
                    secondary_hdl = vpc_vtep_dict['secondary']['hdl']
                      
                    port_channel_list = list(configdict['trigger_dict']['modify-uplink']['portchannel'][secondary_dut].keys())
                    for intf in port_channel_list:
                        res = MyLib.my_utils.shutDownInterface(log,secondary_hdl,intf,secondary_dut)
                          
                    log.info(banner('Waiting for 30 seconds before measuring the Traffic stats:'))
                    countDownTimer(30)
                      
                    out = trigger_obj.checkAllStreamStats(tgn_hdl)
                    traffic_obj.getAllBoundStreamStatistics(tgn_hdl)
                      
                    if out:
                        log.info(banner('Traffic flow is as expected after PO SHut:'))
                        traffic_obj.getAllBoundStreamStatistics(tgn_hdl)
                        log.info(banner('Unshutting the Port-channels'))
                        for intf in port_channel_list:
                            res = MyLib.my_utils.unshutDownInterface(log,secondary_hdl,intf,secondary_dut)
                        log.info(banner('Waiting for 30 seconds before collecting the Traffic stats: '))
                        countDownTimer(30)
                          
                        out = trigger_obj.checkAllStreamStats(tgn_hdl)
                          
                        if out:
                            log.info(banner('Traffic flow is as expected After PO unshut:'))
                            traffic_obj.getAllBoundStreamStatistics(tgn_hdl)
                        else:
                            log.error(banner('Traffic flow is not as expected after PO unshut'))
                            traffic_obj.getAllBoundStreamStatistics(tgn_hdl)
                            flag = 1
                              
                    else:
                        log.error(banner('Traffic flow not as expected after shutting down the PO'))
                        traffic_obj.getAllBoundStreamStatistics(tgn_hdl)
                        flag = 1
                  
                if not out:
                    log.error(banner('Traffic Flow is not working as expected.'))
                    traffic_obj.getAllBoundStreamStatistics(tgn_hdl)
                    trigger_obj.backUpAndRestoreConfigs(device_list,'restore')
                    flag = 1
  
                log.info(banner('Reverting back to Original configs...')) 
                res = trigger_obj.backUpAndRestoreConfigs(device_list,'restore') 
                  
                log.info(banner('Waiting for 180 seconds before collecting traffic stats: - After Reverting to Phy. IF'))
                countDownTimer(180) 
                  
                out = trigger_obj.checkAllStreamStats(tgn_hdl)
                traffic_obj.getAllBoundStreamStatistics(tgn_hdl)
                  
                if not out:
                    log.error(banner('Traffic Flow is not as expected after reverting back to Original configs.'))
                    traffic_obj.getAllBoundStreamStatistics(tgn_hdl)
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
  
class VXLANL3TRMANYCASTRPFUNC105(aetest.Testcase):
  
    """ Flap Uplink Port-Channel member ports - Primary """ 
  
    uid = 'VXLAN-L3-TRM-ANYCAST-RP-FUNC-105'
  
    @aetest.test
    def flapUplinkPortChannelMemberPortsPrimary(self,log,testscript,testbed):
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
              
            #interfaces = configdict['trigger_dict']['modify-uplink']['interfaces'].split()
            port_channel_dict = configdict['trigger_dict']['modify-uplink']['portchannel']
              
            if out:
                log.info(banner('Initial Traffic flow is as expected:'))
                traffic_obj.getAllBoundStreamStatistics(tgn_hdl)
                  
                log.info(banner('Taking Backup of configs on all the VTEPs:'))
                  
                vpc_vtep_dict = trigger_obj.getDeviceDict('vpc_vtep')
                  
                device_list = list(configdict['trigger_dict']['modify-uplink']['portchannel'].keys())
                  
                res = trigger_obj.backUpAndRestoreConfigs(device_list,'backup')
                  
                log.info(banner('Defaulting the interfaces before configuring the port-channel...'))
                  
                for dut in configdict['trigger_dict']['modify-uplink']['interfaces'].keys():
                    hdl = node_dict['all_dut'][dut]
                    interfaces = configdict['trigger_dict']['modify-uplink']['interfaces'][dut].split()
                    log.info(banner('Defaulting the interfaces : {0}'.format([alias_intf_mapping[intf] if re.search('uut',intf) else intf for intf in interfaces])))
                    new_interfaces = [alias_intf_mapping[intf] if re.search('uut',intf) else intf for intf in interfaces]
                    default_res = trigger_obj.defaultSetOfInterfaces(hdl,new_interfaces)
                  
                for dut in port_channel_dict:
                    log.info('the value of dut  inside scripts is : {0}'.format(dut))
                    hdl = node_dict['all_dut'][dut]
                    for intf in port_channel_dict[dut].keys():
                        log.info('the value of intf  inside scripts is : {0}'.format(intf))
                        args = port_channel_dict[dut][intf]
                        log.info('the value of args  inside scripts is : {0}'.format(args))
                        res = trigger_obj.configurePo(hdl,intf,args)
  
                flag = 0
                  
                log.info(banner('Waiting for 180 seconds before collecting traffic stats: - After Reverting to Phy. IF'))
                countDownTimer(180) 
                  
                out = trigger_obj.checkAllStreamStats(tgn_hdl)
                traffic_obj.getAllBoundStreamStatistics(tgn_hdl)
                  
                  
                if out:
                    log.info(banner('Traffic flow is as expected after changing the Uplink To PO'))
                    traffic_obj.getAllBoundStreamStatistics(tgn_hdl)
                      
                    log.info(banner('Flapping the Uplink Port-channels Member Ports...'))
                      
                    vpc_vtep_dict = trigger_obj.getVPCSwitchhdl('details')
                  
                    primary_dut = vpc_vtep_dict['primary']['dut']
                    primary_hdl = vpc_vtep_dict['primary']['hdl']
                      
                    log.info(banner('Shutting down the Uplink PO member POrt on Primary: {0}'.format(primary_dut)))
                    out = primary_hdl.execute('show nve peers | xml')
                    s = BeautifulSoup(out)
                    peer_ip = s.find('peer-ip').string
                    out1 = primary_hdl.execute('show ip route {0} | json'.format(peer_ip))
                    t = json.loads(out1)
                    uplink_port = []
                    for intf in t['TABLE_vrf']['ROW_vrf']['TABLE_addrf']['ROW_addrf']['TABLE_prefix']['ROW_prefix']['TABLE_path']['ROW_path']:
                        uplink_port.append(intf['ifname'])
                      
                    log.info('The value of Uplink Port is : {0}'.format(uplink_port))
                      
                    for po in uplink_port:
                        a = primary_hdl.execute('sh port-channel database interface {0} | xml'.format(po))
                        s = BeautifulSoup(a)
                        member_port = s.find('port').string
                        log.info(banner('Shutting down the Port {0} belonging to Po {1} on dut {2}'.format(member_port,po,primary_dut)))
                        res = MyLib.my_utils.flapInterface(log,primary_hdl,member_port,primary_dut)
                          
                    log.info(banner('Waiting for 30 seconds before measuring the Traffic stats: '))
                    countDownTimer(30)
                      
                    out = trigger_obj.checkAllStreamStats(tgn_hdl)
                    traffic_obj.getAllBoundStreamStatistics(tgn_hdl)
                      
                    if not out:
                        log.error(banner('Traffic did not resume after flapping the uplink PO'))
                        traffic_obj.getAllBoundStreamStatistics(tgn_hdl)
                        trigger_obj.backUpAndRestoreConfigs(device_list,'restore')
                        flag = 1
                  
                else:
                    log.error(banner('Traffic Flow is not working as expected after Changing the uplink to PO.'))
                    traffic_obj.getAllBoundStreamStatistics(tgn_hdl)
                    trigger_obj.backUpAndRestoreConfigs(device_list,'restore')
                    flag = 1
                  
                log.info(banner('Reverting back to Original configs...')) 
                res = trigger_obj.backUpAndRestoreConfigs(device_list,'restore')  
                  
                log.info(banner('Waiting for 180 seconds before collecting traffic stats: - After Reverting to Phy. IF'))
                countDownTimer(180) 
                  
                out = trigger_obj.checkAllStreamStats(tgn_hdl)
                traffic_obj.getAllBoundStreamStatistics(tgn_hdl)
                  
                if not out:
                    log.error(banner('Traffic Flow is not as expected after reverting back to Original configs.'))
                    traffic_obj.getAllBoundStreamStatistics(tgn_hdl)
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
                   
class VXLANL3TRMANYCASTRPFUNC106(aetest.Testcase):
  
    """ Flap Uplink Port-Channel member ports - Secondary """
  
    uid = 'VXLAN-L3-TRM-ANYCAST-RP-FUNC-106'
  
    @aetest.test
    def flapUplinkPortChannelMemberPortsSecondary(self,log,testscript,testbed):
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
              
            #interfaces = configdict['trigger_dict']['modify-uplink']['interfaces'].split()
            port_channel_dict = configdict['trigger_dict']['modify-uplink']['portchannel']
              
            if out:
                log.info(banner('Initial Traffic flow is as expected:'))
                traffic_obj.getAllBoundStreamStatistics(tgn_hdl)
                  
                log.info(banner('Taking Backup of configs on all the VTEPs:'))
                  
                vpc_vtep_dict = trigger_obj.getDeviceDict('vpc_vtep')
                  
                device_list = list(configdict['trigger_dict']['modify-uplink']['portchannel'].keys())
                  
                res = trigger_obj.backUpAndRestoreConfigs(device_list,'backup')
                  
                log.info(banner('Defaulting the interfaces before configuring the port-channel...'))
                  
                for dut in configdict['trigger_dict']['modify-uplink']['interfaces'].keys():
                    hdl = node_dict['all_dut'][dut]
                    interfaces = configdict['trigger_dict']['modify-uplink']['interfaces'][dut].split()
                    log.info(banner('Defaulting the interfaces : {0}'.format([alias_intf_mapping[intf] if re.search('uut',intf) else intf for intf in interfaces])))
                    new_interfaces = [alias_intf_mapping[intf] if re.search('uut',intf) else intf for intf in interfaces]
                    default_res = trigger_obj.defaultSetOfInterfaces(hdl,new_interfaces)
                  
                for dut in port_channel_dict:
                    log.info('the value of dut  inside scripts is : {0}'.format(dut))
                    hdl = node_dict['all_dut'][dut]
                    for intf in port_channel_dict[dut].keys():
                        log.info('the value of intf  inside scripts is : {0}'.format(intf))
                        args = port_channel_dict[dut][intf]
                        log.info('the value of args  inside scripts is : {0}'.format(args))
                        res = trigger_obj.configurePo(hdl,intf,args)
  
                flag = 0
                  
                log.info(banner('Waiting for 180 seconds before collecting traffic stats: - After Reverting to Phy. IF'))
                countDownTimer(180) 
                  
                out = trigger_obj.checkAllStreamStats(tgn_hdl)
                traffic_obj.getAllBoundStreamStatistics(tgn_hdl)
                  
                  
                if out:
                    log.info(banner('Traffic flow is as expected after changing the Uplink To PO'))
                    traffic_obj.getAllBoundStreamStatistics(tgn_hdl)
                      
                    log.info(banner('Flapping the Uplink Port-channels Member Ports...'))
                      
                    vpc_vtep_dict = trigger_obj.getVPCSwitchhdl('details')
                  
                    secondary_dut = vpc_vtep_dict['secondary']['dut']
                    secondary_hdl = vpc_vtep_dict['secondary']['hdl']
                      
                    log.info(banner('Shutting down the Uplink PO member POrt on secondary: {0}'.format(secondary_dut)))
                    out = secondary_hdl.execute('show nve peers | xml')
                    s = BeautifulSoup(out)
                    peer_ip = s.find('peer-ip').string
                    out1 = secondary_hdl.execute('show ip route {0} | json'.format(peer_ip))
                    t = json.loads(out1)
                    uplink_port = []
                    for intf in t['TABLE_vrf']['ROW_vrf']['TABLE_addrf']['ROW_addrf']['TABLE_prefix']['ROW_prefix']['TABLE_path']['ROW_path']:
                        uplink_port.append(intf['ifname'])
                      
                    log.info('The value of Uplink Port is : {0}'.format(uplink_port))
                      
                    for po in uplink_port:
                        a = secondary_hdl.execute('sh port-channel database interface {0} | xml'.format(po))
                        s = BeautifulSoup(a)
                        member_port = s.find('port').string
                        log.info(banner('Shutting down the Port {0} belonging to Po {1} on dut {2}'.format(member_port,po,secondary_dut)))
                        res = MyLib.my_utils.flapInterface(log,secondary_hdl,member_port,secondary_dut)
                          
                    log.info(banner('Waiting for 30 seconds before measuring the Traffic stats: '))
                    countDownTimer(30)
                      
                    out = trigger_obj.checkAllStreamStats(tgn_hdl)
                    traffic_obj.getAllBoundStreamStatistics(tgn_hdl)
                      
                    if not out:
                        log.error(banner('Traffic did not resume after flapping the uplink PO'))
                        traffic_obj.getAllBoundStreamStatistics(tgn_hdl)
                        trigger_obj.backUpAndRestoreConfigs(device_list,'restore')
                        flag = 1
                  
                else:
                    log.error(banner('Traffic Flow is not working as expected after Changing the uplink to PO.'))
                    traffic_obj.getAllBoundStreamStatistics(tgn_hdl)
                    trigger_obj.backUpAndRestoreConfigs(device_list,'restore')
                    flag = 1
                  
                log.info(banner('Reverting back to Original configs...')) 
                res = trigger_obj.backUpAndRestoreConfigs(device_list,'restore')  
                  
                log.info(banner('Waiting for 180 seconds before collecting traffic stats: - After Reverting to Phy. IF'))
                countDownTimer(180) 
                  
                out = trigger_obj.checkAllStreamStats(tgn_hdl)
                traffic_obj.getAllBoundStreamStatistics(tgn_hdl)
                  
                if not out:
                    log.error(banner('Traffic Flow is not as expected after reverting back to Original configs.'))
                    traffic_obj.getAllBoundStreamStatistics(tgn_hdl)
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
                  
class VXLANL3TRMANYCASTRPFUNC107(aetest.Testcase):
  
    """ Flap Uplink Port-Channel - Primary """
  
    uid = 'VXLAN-L3-TRM-ANYCAST-RP-FUNC-107'
  
    @aetest.test
    def flapUplinkPortChannelPrimary(self,log,testscript,testbed):
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
              
            #interfaces = configdict['trigger_dict']['modify-uplink']['interfaces'].split()
            port_channel_dict = configdict['trigger_dict']['modify-uplink']['portchannel']
              
            if out:
                log.info(banner('Initial Traffic flow is as expected:'))
                traffic_obj.getAllBoundStreamStatistics(tgn_hdl)
                  
                log.info(banner('Taking Backup of configs on all the VTEPs:'))
                  
                vpc_vtep_dict = trigger_obj.getDeviceDict('vpc_vtep')
                  
                device_list = list(configdict['trigger_dict']['modify-uplink']['portchannel'].keys())
                  
                res = trigger_obj.backUpAndRestoreConfigs(device_list,'backup')
                  
                log.info(banner('Defaulting the interfaces before configuring the port-channel...'))
                  
                for dut in configdict['trigger_dict']['modify-uplink']['interfaces'].keys():
                    hdl = node_dict['all_dut'][dut]
                    interfaces = configdict['trigger_dict']['modify-uplink']['interfaces'][dut].split()
                    log.info(banner('Defaulting the interfaces : {0}'.format([alias_intf_mapping[intf] if re.search('uut',intf) else intf for intf in interfaces])))
                    new_interfaces = [alias_intf_mapping[intf] if re.search('uut',intf) else intf for intf in interfaces]
                    default_res = trigger_obj.defaultSetOfInterfaces(hdl,new_interfaces)
                  
                for dut in port_channel_dict:
                    log.info('the value of dut  inside scripts is : {0}'.format(dut))
                    hdl = node_dict['all_dut'][dut]
                    for intf in port_channel_dict[dut].keys():
                        log.info('the value of intf  inside scripts is : {0}'.format(intf))
                        args = port_channel_dict[dut][intf]
                        log.info('the value of args  inside scripts is : {0}'.format(args))
                        res = trigger_obj.configurePo(hdl,intf,args)
  
                flag = 0
                  
                log.info(banner('Waiting for 180 seconds before collecting traffic stats: - After Reverting to Phy. IF'))
                countDownTimer(180) 
                  
                out = trigger_obj.checkAllStreamStats(tgn_hdl)
                traffic_obj.getAllBoundStreamStatistics(tgn_hdl)
                  
                  
                if out:
                    log.info(banner('Traffic flow is as expected after changing the Uplink To PO'))
                    traffic_obj.getAllBoundStreamStatistics(tgn_hdl)
                      
                    log.info(banner('Flapping the UPlink Port-channels on VPC PRimary:'))
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
                        res = MyLib.my_utils.flapInterface(log,primary_hdl,intf,primary_dut)
                          
                    log.info(banner('Waiting for 180 seconds before collecting traffic stats: - After Reverting to Phy. IF'))
                    countDownTimer(180) 
                          
                    out = trigger_obj.checkAllStreamStats(tgn_hdl)
                    traffic_obj.getAllBoundStreamStatistics(tgn_hdl)
                      
                    if not out:
                        log.error(banner('Traffic did not resume after flapping the uplink PO'))
                        traffic_obj.getAllBoundStreamStatistics(tgn_hdl)
                        trigger_obj.backUpAndRestoreConfigs(device_list,'restore')
                        flag = 1
                  
                else:
                    log.error(banner('Traffic Flow is not working as expected after Changing the uplink to PO.'))
                    traffic_obj.getAllBoundStreamStatistics(tgn_hdl)
                    trigger_obj.backUpAndRestoreConfigs(device_list,'restore')
                    flag = 1
                  
                log.info(banner('Reverting back to Original configs...')) 
                res = trigger_obj.backUpAndRestoreConfigs(device_list,'restore') 
                  
                log.info(banner('Waiting for 180 seconds before collecting traffic stats: - After Reverting to Phy. IF'))
                countDownTimer(180)  
                  
                out = trigger_obj.checkAllStreamStats(tgn_hdl)
                traffic_obj.getAllBoundStreamStatistics(tgn_hdl)
                  
                if not out:
                    log.error(banner('Traffic Flow is not as expected after reverting back to Original configs.'))
                    traffic_obj.getAllBoundStreamStatistics(tgn_hdl)
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
                  
class VXLANL3TRMANYCASTRPFUNC108(aetest.Testcase):
  
    """ Flap Uplink Port-Channel - Secondary """
  
    uid = 'VXLAN-L3-TRM-ANYCAST-RP-FUNC-108'
  
    @aetest.test
    def flapUplinkPortChannelSecondary(self,log,testscript,testbed):
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
              
            #interfaces = configdict['trigger_dict']['modify-uplink']['interfaces'].split()
            port_channel_dict = configdict['trigger_dict']['modify-uplink']['portchannel']
              
            if out:
                log.info(banner('Initial Traffic flow is as expected:'))
                traffic_obj.getAllBoundStreamStatistics(tgn_hdl)
                  
                log.info(banner('Taking Backup of configs on all the VTEPs:'))
                  
                vpc_vtep_dict = trigger_obj.getDeviceDict('vpc_vtep')
                  
                device_list = list(configdict['trigger_dict']['modify-uplink']['portchannel'].keys())
                  
                res = trigger_obj.backUpAndRestoreConfigs(device_list,'backup')
                  
                log.info(banner('Defaulting the interfaces before configuring the port-channel...'))
                  
                for dut in configdict['trigger_dict']['modify-uplink']['interfaces'].keys():
                    hdl = node_dict['all_dut'][dut]
                    interfaces = configdict['trigger_dict']['modify-uplink']['interfaces'][dut].split()
                    log.info(banner('Defaulting the interfaces : {0}'.format([alias_intf_mapping[intf] if re.search('uut',intf) else intf for intf in interfaces])))
                    new_interfaces = [alias_intf_mapping[intf] if re.search('uut',intf) else intf for intf in interfaces]
                    default_res = trigger_obj.defaultSetOfInterfaces(hdl,new_interfaces)
                  
                for dut in port_channel_dict:
                    log.info('the value of dut  inside scripts is : {0}'.format(dut))
                    hdl = node_dict['all_dut'][dut]
                    for intf in port_channel_dict[dut].keys():
                        log.info('the value of intf  inside scripts is : {0}'.format(intf))
                        args = port_channel_dict[dut][intf]
                        log.info('the value of args  inside scripts is : {0}'.format(args))
                        res = trigger_obj.configurePo(hdl,intf,args)
  
                flag = 0
                  
                log.info(banner('Waiting for 180 seconds before collecting traffic stats: - After Reverting to Phy. IF'))
                countDownTimer(180) 
                  
                out = trigger_obj.checkAllStreamStats(tgn_hdl)
                traffic_obj.getAllBoundStreamStatistics(tgn_hdl)
                  
                  
                if out:
                    log.info(banner('Traffic flow is as expected after changing the Uplink To PO'))
                    traffic_obj.getAllBoundStreamStatistics(tgn_hdl)
                      
                    log.info(banner('Flapping the UPlink Port-channels on VPC PRimary:'))
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
                        res = MyLib.my_utils.flapInterface(log,secondary_hdl,intf,secondary_dut)
                          
                    log.info(banner('Waiting for 180 seconds before collecting traffic stats: - After Reverting to Phy. IF'))
                    countDownTimer(180) 
                          
                    out = trigger_obj.checkAllStreamStats(tgn_hdl)
                    traffic_obj.getAllBoundStreamStatistics(tgn_hdl)
                      
                    if not out:
                        log.error(banner('Traffic did not resume after flapping the uplink PO'))
                        traffic_obj.getAllBoundStreamStatistics(tgn_hdl)
                        trigger_obj.backUpAndRestoreConfigs(device_list,'restore')
                        flag = 1
                  
                else:
                    log.error(banner('Traffic Flow is not working as expected after Changing the uplink to PO.'))
                    traffic_obj.getAllBoundStreamStatistics(tgn_hdl)
                    trigger_obj.backUpAndRestoreConfigs(device_list,'restore')
                    flag = 1
                  
                log.info(banner('Reverting back to Original configs...')) 
                res = trigger_obj.backUpAndRestoreConfigs(device_list,'restore')
                  
                log.info(banner('Waiting for 180 seconds before collecting traffic stats: - After Reverting to Phy. IF'))
                countDownTimer(180)   
                  
                out = trigger_obj.checkAllStreamStats(tgn_hdl)
                traffic_obj.getAllBoundStreamStatistics(tgn_hdl)
                  
                if not out:
                    log.error(banner('Traffic Flow is not as expected after reverting back to Original configs.'))
                    traffic_obj.getAllBoundStreamStatistics(tgn_hdl)
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
  
class VXLANL3TRMANYCASTRPFUNC109(aetest.Testcase):
  
    """ Change Uplink to SVI """
  
    uid = 'VXLAN-L3-TRM-ANYCAST-RP-FUNC-109'
  
    @aetest.test
    def modifyUplinkToSVI(self,log,testscript,testbed):
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
              
            #interfaces = configdict['trigger_dict']['modify-uplink']['interfaces'].split()
            svi_dict = configdict['trigger_dict']['modify-uplink']['svi']
              
            if out:
                log.info(banner('Initial Traffic flow is as expected:'))
                traffic_obj.getAllBoundStreamStatistics(tgn_hdl)
                  
                log.info(banner('Taking Backup of configs on all the VTEPs:'))
                  
                device_list = list(configdict['trigger_dict']['modify-uplink']['portchannel'].keys())
                  
                res = trigger_obj.backUpAndRestoreConfigs(device_list,'backup')
                  
                log.info(banner('Defaulting the interfaces before configuring the port-channel...'))
                  
                for dut in configdict['trigger_dict']['modify-uplink']['interfaces'].keys():
                    hdl = node_dict['all_dut'][dut]
                    interfaces = configdict['trigger_dict']['modify-uplink']['interfaces'][dut].split()
                    log.info(banner('Defaulting the interfaces : {0}'.format([alias_intf_mapping[intf] if re.search('uut',intf) else intf for intf in interfaces])))
                    new_interfaces = [alias_intf_mapping[intf] if re.search('uut',intf) else intf for intf in interfaces]
                    default_res = trigger_obj.defaultSetOfInterfaces(hdl,new_interfaces)
                  
                for dut in svi_dict:
                    log.info('the value of dut  inside scripts is : {0}'.format(dut))
                    hdl = node_dict['all_dut'][dut]
                    for intf in svi_dict[dut].keys():
                        log.info('the value of intf  inside scripts is : {0}'.format(intf))
                        args = svi_dict[dut][intf]
                        log.info('the value of args  inside scripts is : {0}'.format(args))
                        res = trigger_obj.configureSVI(hdl,intf,args)
  
                log.info(banner('Waiting for 180 seconds before collecting traffic stats: - After changing UPlink as PO'))
                countDownTimer(180)
                flag = 0
                out = trigger_obj.checkAllStreamStats(tgn_hdl)
                traffic_obj.getAllBoundStreamStatistics(tgn_hdl)
                  
                if not out:
                    log.error(banner('Traffic Flow is not working as expected.'))
                    traffic_obj.getAllBoundStreamStatistics(tgn_hdl)
                    trigger_obj.backUpAndRestoreConfigs(device_list,'restore')
                    flag = 1
                  
                log.info(banner('Reverting back to Original configs...')) 
                res = trigger_obj.backUpAndRestoreConfigs(device_list,'restore') 
                  
                log.info(banner('Waiting for 180 seconds before collecting traffic stats: - After Reverting to Phy. IF'))
                countDownTimer(180) 
                  
                out = trigger_obj.checkAllStreamStats(tgn_hdl)
                traffic_obj.getAllBoundStreamStatistics(tgn_hdl)
                  
                if not out:
                    log.error(banner('Traffic Flow is not as expected after reverting back to Original configs.'))
                    traffic_obj.getAllBoundStreamStatistics(tgn_hdl)
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
   
class VXLANL3TRMANYCASTRPFUNC110(aetest.Testcase):
  
    """ Remote VTEP reachability via Secondary"""
  
    uid = 'VXLAN-L3-TRM-ANYCAST-RP-FUNC-110'
  
    @aetest.test
    def removeVTEPRechabilityViaSecondary(self,log,testscript,testbed):
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
              
            #interfaces = configdict['trigger_dict']['modify-uplink']['interfaces'].split()
            port_channel_dict = configdict['trigger_dict']['modify-uplink']['portchannel']
              
            if out:
                log.info(banner('Initial Traffic flow is as expected:'))
                traffic_obj.getAllBoundStreamStatistics(tgn_hdl)
                  
                log.info(banner('Taking Backup of configs on all the VTEPs:'))
                  
                vpc_vtep_dict = trigger_obj.getDeviceDict('vpc_vtep')
                  
                device_list = list(configdict['trigger_dict']['modify-uplink']['portchannel'].keys())
                  
                res = trigger_obj.backUpAndRestoreConfigs(device_list,'backup')
              
                log.info(banner('Flapping the UPlink and Parallel link on VPC PRimary - complete connectivity loss...:'))
                vpc_vtep_dict = trigger_obj.getVPCSwitchhdl('details')
              
                primary_dut = vpc_vtep_dict['primary']['dut']
                primry_hdl = vpc_vtep_dict['primary']['hdl']
                  
                port_list = []
                log.info(banner('Shutting down the Uplink and parallel Intf on Primary: {0}'.format(primary_dut)))
                out = primry_hdl.execute('sh ip ospf neighbors  | xml')
                for line in out.splitlines():
                    if re.search('intf',line):
                        s = BeautifulSoup(line)
                        port = s.find('intf').string
                        port_list.append(port)
  
                log.info('The value of port_list is : {0}'.format(port_list))
                  
                for intf in port_list:
                    res = MyLib.my_utils.shutDownInterface(log,primry_hdl,intf,primary_dut)
                      
                log.info(banner('Unshutting the Uplink interface and parallel Intf on Primary: {0}'.format(primary_dut)))
                  
                for intf in port_list:
                    res = MyLib.my_utils.unshutDownInterface(log,primry_hdl,intf,primary_dut)
                      
                log.info(banner('Waiting for 180 seconds before collecting traffic stats: - After Trigger interface shut and unshut '))
                countDownTimer(180) 
                      
                out = trigger_obj.checkAllStreamStats(tgn_hdl)
                traffic_obj.getAllBoundStreamStatistics(tgn_hdl)
                  
                flag = 0
                  
                if not out:
                    log.error(banner('Traffic did not resume after flapping the uplink PO'))
                    traffic_obj.getAllBoundStreamStatistics(tgn_hdl)
                    trigger_obj.backUpAndRestoreConfigs(device_list,'restore')
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
  
class VXLANL3TRMANYCASTRPFUNC111(aetest.Testcase):
  
    """ Remote VTEP reachability via Primary"""
  
    uid = 'VXLAN-L3-TRM-ANYCAST-RP-FUNC-111'
  
    @aetest.test
    def remoteVTEPRechabilityViaPrimary(self,log,testscript,testbed):
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
                  
                vpc_vtep_dict = trigger_obj.getDeviceDict('vpc_vtep')
                  
                device_list = list(vpc_vtep_dict.keys())
                  
                res = trigger_obj.backUpAndRestoreConfigs(device_list,'backup')
              
                log.info(banner('Flapping the UPlink and Parallel link on VPC PRimary - complete connectivity loss...:'))
                vpc_vtep_dict = trigger_obj.getVPCSwitchhdl('details')
              
                secondary_dut = vpc_vtep_dict['secondary']['dut']
                secondary_hdl = vpc_vtep_dict['secondary']['hdl']
                  
                port_list = []
                log.info(banner('Shutting down the Uplink and parallel Intf on secondary: {0}'.format(secondary_dut)))
                out = secondary_hdl.execute('sh ip ospf neighbors  | xml')
                for line in out.splitlines():
                    if re.search('intf',line):
                        s = BeautifulSoup(line)
                        port = s.find('intf').string
                        port_list.append(port)
  
                log.info('The value of port_list is : {0}'.format(port_list))
                  
                for intf in port_list:
                    res = MyLib.my_utils.shutDownInterface(log,secondary_hdl,intf,secondary_dut)
                      
                log.info(banner('Unshutting the Uplink interface and parallel Intf on secondary: {0}'.format(secondary_dut)))
                  
                for intf in port_list:
                    res = MyLib.my_utils.unshutDownInterface(log,secondary_hdl,intf,secondary_dut)
                      
                log.info(banner('Waiting for 180 seconds before collecting traffic stats: - After Trigger interface shut and unshut '))
                countDownTimer(180) 
                      
                out = trigger_obj.checkAllStreamStats(tgn_hdl)
                traffic_obj.getAllBoundStreamStatistics(tgn_hdl)
                  
                flag = 0
                  
                if not out:
                    log.error(banner('Traffic did not resume after flapping the Interfaces'))
                    traffic_obj.getAllBoundStreamStatistics(tgn_hdl)
                    trigger_obj.backUpAndRestoreConfigs(device_list,'restore')
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
                  
class VXLANL3TRMANYCASTRPFUNC112(aetest.Testcase):
  
    """ L3 VXLAN VRF shut/no shut """
  
    uid = 'VXLAN-L3-TRM-ANYCAST-RP-FUNC-112'
  
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
                            if not re.search('default|management',vrf_name):
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
                countDownTimer(300)     
                  
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
  
class VXLANL3TRMANYCASTRPFUNC0113(aetest.Testcase):
  
    """ L3 VNI SVI FLAP"""
  
    uid = 'VXLAN-L3-TRM-ANYCAST-RP-FUNC-113'
  
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
  
  
class VXLANL3TRMANYCASTRPFUNC114(aetest.Testcase):
  
    """ L3 VNI SVI Remove / Readd"""
  
    uid = 'VXLAN-L3-TRM-ANYCAST-RP-FUNC-114'
  
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
  
class VXLANL3TRMANYCASTRPFUNC115(aetest.Testcase):
  
    """ L2 VNI SVI Shut / Unshut"""
  
    uid = 'VXLAN-L3-TRM-ANYCAST-RP-FUNC-115'
  
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
  
class VXLANL3TRMANYCASTRPFUNC116(aetest.Testcase):
  
    """ L2 VNI SVI Remove / Reddd """
  
    uid = 'VXLAN-L3-TRM-ANYCAST-RP-FUNC-116'
  
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
  
class VXLANL3TRMANYCASTRPFUNC117(aetest.Testcase):
  
    """ VRF Removal and Readd """
  
    uid = 'VXLAN-L3-TRM-ANYCAST-RP-FUNC-117'
  
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
                            if not re.search('default|management',vrf_name):
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
                countDownTimer(300)     
                  
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
  
class VXLANL3TRMANYCASTRPFUNC118(aetest.Testcase):
  
    """ nve Removal and Readd """
  
    uid = 'VXLAN-L3-TRM-ANYCAST-RP-FUNC-118'
  
    @aetest.test
    def removeNVEAndReadd(self,log,testscript,testbed):
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
                  
  
                for dut in device_dict.keys():
                    hdl = node_dict['all_dut'][dut]
                    hdl.configure('no interface nve 1')
                          
                log.info(banner('WAiting for 100 seconds before configuring back the nve Interface'))
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
 


class CommonCleanup(aetest.Testcase):
    
    """ VLan State Change on Both the DUTS """

    uid = 'VXLAN-L3-TRM-ANYCAST-RP-FUNC-001'

    @aetest.subsection
    def checkTopo(self):
        pass
        
        
class CommonCleanup(aetest.CommonCleanup):

    @aetest.subsection
    def disconnect(self):
        pass
