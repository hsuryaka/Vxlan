import logging
from ats.log.utils import banner
from common_lib import utils
from common_lib.utils import *
import threading
import random
from bs4 import BeautifulSoup
import time
import ipaddress
from feature_lib.vxlan import evpn_lib
import json
import yaml
from common_lib.ixia_lib_new import *
from prettytable import PrettyTable

from unicon import Unicon
from unicon.eal.dialogs import Dialog
from unicon.eal.dialogs import Statement

def get_v4_mask_len(i):
    switcher={
            '24':256,
            '25':128,
            '26':64,
            '27':32,
            '28':15,
            '29':8,
            '30':4,
            '31':2,
            '32':1
             }
    return switcher.get(i,"Invalid Mask")


def get_v6_mask_len(i):
    switcher={
            '48':2**64,
            '64':2**64,
            '65':2**65,
            '66':2**66,
            '67':2**67,
            '68':2**68,
            '69':2**69,
            '70':2**70,
            '71':2**71,
            '72':2**72,
            '73':2**73,
            '74':2**74,
            '75':2**75,
            '76':2**76,
            '77':2**77,
            '78':2**78,
            '79':2**79,
            '80':2**80,
            '81':2**71,
            '82':2**82,
            '83':2**83,
            '84':2**84,
            '85':2**85,
            '86':2**86,
             }
    return switcher.get(i,"Invalid Mask")


def isEmpty(evpn_config_dict):
    for element in evpn_config_dict:
        if element:
            return True
        return False

def generateVRFlist(vrf_name,no):
    return [vrf_name.rsplit('-',1)[0] + '-' + str("{:03d}".format(int(vrf_name.rsplit('-',1)[1])+i)) for i in range(no)]

def parseGlobalVxlanConfigs(log,args):
    arggrammar = {}
    arggrammar['anycast_gateway_mac'] = '-type str'
    arggrammar['vxlan_igmp_snooping'] = '-type bool'
    arggrammar['ip_pim_evpn_border_leaf'] = '-type bool'
    ns = utils.parserutils_lib.argsToCommandOptions(args,arggrammar,log)
    log.info('The value of ns is : {0}'.format(ns))
    return ns 

def ipaddrgen(no_of_ip_address,start_ip,mask):
    return [(ipaddress.IPv4Address(start_ip) + i*get_v4_mask_len(str(mask))).exploded for i in range(no_of_ip_address)]

def ipv6addrgen(no_of_ip_address,start_ip,mask):
    return [(ipaddress.IPv6Address(start_ip) + i*get_v6_mask_len(str(mask))).exploded for i in range(no_of_ip_address)]

def countDownTimer(a):
    for i in range(a):
        log.info('seconds remaining is: {0}'.format(int(a-i)))
        time.sleep(1)
    return 1

def parseMultisiteConfigs(log, args):

    arggrammar={}
    arggrammar['site_id']='-type int'
    arggrammar['dci_advertise_pip']='-type bool -default False'
    arggrammar['delay_restore_time']='-type int -default 30'
    arggrammar['evpn_multisite_dci_tracking']='-type bool -default True'
    arggrammar['evpn_multisite_fabric_tracking']='-type bool -default True'
    arggrammar['multisite_loopback']='-type str'
    ns=parserutils_lib.argsToCommandOptions( args, arggrammar, log )
    return ns

def mychain(spans):
    for start, no , vni_start in spans:
        for count,i in enumerate(range(start, start+no)):
            vni = vni_start + count
            cfg = ''' vlan {0}
                      no vn-segment
                      vn-segment {1}
                  '''.format(i,vni)
            yield cfg
            
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

def getNveSourceIPFromConfigs(log,config_dict,dut,intf=None):
    log.info('Getting Nve Source IP on dut {0} from config File '.format(dut))
    args = config_dict['interface_config_dict']['loopback'][dut][intf]
    ns = parseInterfaceConfigDictLoopbackParams(log,args)
    return ns.ipv4_addr



def getMSNvePeerDict(log,node_dict,config_dict):
    nve_peer_config_dict = {}
    site_list = [ms for ms in node_dict.keys() if re.search('site', ms, re.I)]
    log.info('The Value of site_list is {0}'.format(site_list))
    i = 0
    outer_site = site_list[i]   # site 2
    log.info('Outer Site : {0}'.format(outer_site))
    nve_peer_config_dict[outer_site] = {}
    nve_peer_config_dict[outer_site]['Local-Site'] = {}
    nve_peer_config_dict[outer_site]['Local-Site']['LEAF'] = {}
    
    leaf_list = list(node_dict[outer_site]['LEAF'].keys())
    log.info('The value of leaf_list is : {0}'.format(leaf_list))
    for l in leaf_list:
        nve_peer_config_dict[outer_site]['Local-Site']['LEAF'].update({'pip':getNveSourceIPFromConfigs(log,config_dict,l,intf='loopback1')})
        
    for j in range(i+1, len(site_list)):
        inner_site = site_list[j] # site 1
        log.info('inner Site {0}:'.format(inner_site))  # site 1
        nve_peer_config_dict[outer_site].setdefault('Remote-Site',{}) # site 2{'remote_site'}{'site1'}
        nve_peer_config_dict[outer_site]['Remote-Site'][inner_site] = {}  # site 1
        for role in node_dict[inner_site].keys():
            log.info('The value of role is : {0}'.format(role)) # LEAF
            if re.search(r'VPC|BGW',role,re.I):
                bgw_list = list(node_dict[inner_site][role].keys())
                log.info('The value of bgw_list is : {0}'.format(bgw_list))
                for k in bgw_list:
                    nve_peer_config_dict[outer_site]['Remote-Site'][inner_site].update({'pip':getNveSourceIPFromConfigs(log,config_dict,k,intf = 'loopback1')})
                    nve_peer_config_dict[outer_site]['Remote-Site'][inner_site].update({'ms_pip':getNveSourceIPFromConfigs(log,config_dict,k,intf = 'loopback2')})            
            
                nve_peer_config_dict[inner_site] = {}
                nve_peer_config_dict[inner_site].setdefault('Remote-Site',{})
                nve_peer_config_dict[inner_site].setdefault('Local-Site',{})
                nve_peer_config_dict[inner_site]['Local-Site']['LEAF'] = {}
                nve_peer_config_dict[inner_site]['Remote-Site'][outer_site] = {}
                leaf_list = list(node_dict[inner_site]['LEAF'].keys())
                log.info('the value of leaf_list in site {1} is : {0}'.format(leaf_list, inner_site))
                for l in leaf_list:
                    nve_peer_config_dict[inner_site]['Local-Site']['LEAF'].update({'pip':getNveSourceIPFromConfigs(log,config_dict,l,intf = 'loopback1')})
                
                for role in node_dict[outer_site].keys():
                    if re.search(r'VPC|BGW',role,re.I):
                        bgw_list = list(node_dict[outer_site][role].keys())
                        log.info('The value of bgw_list is : {0}'.format(bgw_list))
                        for k in bgw_list:
                            nve_peer_config_dict[inner_site]['Remote-Site'][outer_site].update({'pip':getNveSourceIPFromConfigs(log,config_dict,k,intf = 'loopback1')})
                            nve_peer_config_dict[inner_site]['Remote-Site'][outer_site].update({'ms_pip':getNveSourceIPFromConfigs(log,config_dict,k,intf = 'loopback2')})            

            
    c = yaml.dump(nve_peer_config_dict)
    log.info('The value of nve_peer_config_dict is : \n {0}'.format(c))
    
    return nve_peer_config_dict

class ScaleConfig:

    # First we create a constructor for this class
    # and add members to it, here models
    def __init__(self,log, node_dict,configdict,alias_intf_mapping_dict):
        self.log = log
        self.node_dict = node_dict
        self.configdict = configdict
        self.alias_intf_mapping_dict = alias_intf_mapping_dict
        self.configsuccess = 1
        
    def getDeviceDict(self,*args):
        dut = args
        self.dev_dict = {}
        for item in dut:
            if item == 'all_vtep':
                log.info(banner('The value of node_dict.items() is : {0}'.format(self.node_dict.items())))
                res = {k : v for k,v in self.node_dict.items() if 'vtep' in k}
                for k, v in res.items():
                    self.dev_dict.update(v)
            elif item =='stand_vtep':
                self.dev_dict = self.node_dict['stand_vteps']
            elif item == 'vpc_vtep':
                self.dev_dict = self.node_dict['vpc_vteps']
            elif item == 'esi_vtep':
                self.dev_dict = self.node_dict['esi_vteps']
            elif item == 'l2_switch':
                self.dev_dict = self.node_dict['l2_switch']
            elif item == 'spines':
                self.dev_dict = self.node_dict['spines']
            elif item == 'external_rp':
                self.dev_dict = self.node_dict['external_rp']
            elif item == 'vpc_access':
                self.dev_dict = self.node_dict['vpc_access']
            elif item == 'esi_access':
                self.dev_dict = self.node_dict['esi_access']                
            elif item == 'core':
                self.dev_dict = self.node_dict['core']
            self.log.info('The value of dev_dict is : {0}'.format(self.dev_dict))
        return self.dev_dict
    
    def getMultisiteDeviceDict(self, *args):
        dut = args
        self.dev_dict = {}
        for item in dut:
            if item == 'all_vtep':
                for k,v in self.node_dict.items():
                    log.info('The value of k, v is : {0} and {1}'.format(k,v))
                    if re.search("Site",k):    
                        for k, v in v.items():
                            self.log.info('The value of k is : {0}'.format(k))
                            self.log.info('The value of v is : {0}'.format(v))
                            if re.search('BGW|LEAF', k):
                                self.dev_dict.update(v)
            if item == 'bgw':
                for k,v in self.node_dict.items():
                    log.info('The value of k, v is : {0} and {1}'.format(k,v))
                    if re.search("Site",k):    
                        for k, v in v.items():
                            self.log.info('The value of k is : {0}'.format(k))
                            self.log.info('The value of v is : {0}'.format(v))
                            if re.search('BGW', k):
                                self.dev_dict.update(v)
                        
            if item == 'vpc_vtep':
                for k,v in self.node_dict.items():
                    log.info('The value of k, v is : {0} and {1}'.format(k,v))
                    if re.search("Site",k):    
                        for k, v in v.items():
                            self.log.info('The value of k is : {0}'.format(k))
                            self.log.info('The value of v is : {0}'.format(v))
                            if re.search('VPC', k):
                                self.dev_dict.update(v)

            if item == 'leaf':
                for k,v in self.node_dict.items():
                    log.info('The value of k, v is : {0} and {1}'.format(k,v))
                    if re.search("Site",k):    
                        for k, v in v.items():
                            self.log.info('The value of k is : {0}'.format(k))
                            self.log.info('The value of v is : {0}'.format(v))
                            if re.search('LEAF', k):
                                self.dev_dict.update(v)
                                
        self.log.info('The value of dev_dict is : {0}'.format(self.dev_dict))
        return self.dev_dict

                        
                
        
    
    
    def configureGlobalVxlanParams(self,vtep_dict):
        for dut in vtep_dict:
            ns = parseGlobalVxlanConfigs(self.log,self.configdict['scale_config_dict'][dut]['global']['vxlan']) 
            cfg = ''
            if hasattr(ns, 'anycast_gateway_mac') and ns.anycast_gateway_mac:
                cfg += 'fabric forwarding anycast-gateway-mac 0000.1234.5678 \n'
            if ns.vxlan_igmp_snooping:
                cfg += 'ip igmp snooping vxlan \n'
            if ns.ip_pim_evpn_border_leaf:
                cfg += 'ip pim evpn-border-leaf \n'
            vtep_dict[dut].configure(cfg)
        return 1
    
    def configureGlobalBGPParams(self,vtep_dict):
        
        '''
        dut = 'uut12'
        as_no = list(self.configdict['bgp_config_dict'][dut].keys())[0]
        res = cfgGlobalBGPParameters(self.log,self.node_dict['all_dut'][dut],self.configdict['scale_config_dict'][dut]['global']['bgp'],as_no)

        '''
        threads = []
        for dut in vtep_dict:
            as_no = list(self.configdict['bgp_config_dict'][dut].keys())[0]
            t = threading.Thread(target = cfgGlobalBGPParameters, 
                                 args = [self.log,vtep_dict[dut],self.configdict['scale_config_dict'][dut]['global']['bgp'],as_no])
            t.start()
            threads.append(t)
        [thread.join() for thread in threads]

        return 1
        
        
    def configScaleVlans(self,vtep_dict):
        
        '''
        dut = 'uut12'
        res = configureVlans(self.log,vtep_dict[dut],self.configdict['scale_config_dict'][dut]['global']['vlan'])
        
        '''
        
        threads = []
        for dut in vtep_dict:
            t = threading.Thread(target = configureVlans,
                                 args = [self.log,vtep_dict[dut],self.configdict['scale_config_dict'][dut]['global']['vlan']])
            t.start()
            threads.append(t)
        [thread.join() for thread in threads]
        return 1
        
    
    def configScaleVRFs(self,vtep_dict):
        '''
        dut = 'uut12'
        res = configureVRFs(self.log,vtep_dict[dut],self.configdict['scale_config_dict'][dut]['global']['vrf'])
        '''
        threads = []
        for dut in vtep_dict:
            t = threading.Thread(target = configureVRFs,
                                 args = [self.log,vtep_dict[dut],self.configdict['scale_config_dict'][dut]['global']['vrf']])
            t.start()
            threads.append(t)
        [thread.join() for thread in threads]
        return 1
        

    def configScaleSVIs(self,vtep_dict):
        
        '''
        dut = 'uut2'
        res = configureSVIs(self.log,vtep_dict[dut],self.configdict['scale_config_dict'][dut]['interface']['svi'])
        
        '''
        threads = []
        for dut in vtep_dict:
            t = threading.Thread(target = configureSVIs,
                                 args = [self.log,vtep_dict[dut],self.configdict['scale_config_dict'][dut]['interface']['svi']])
            t.start()
            threads.append(t)
        [thread.join() for thread in threads]
        return 1
        
    
    def configScaleEVPN(self,vtep_dict):
        evpn_config_dict = generateEvpnDict(self.log,self.configdict['scale_config_dict'],vtep_dict)
        threads = []
        for dut in vtep_dict:
            t = threading.Thread(target = evpn_lib.configEvpn,
                                 args = [dut, vtep_dict[dut], evpn_config_dict[dut],self.log])
            t.start()
            threads.append(t)
        [thread.join() for thread in threads]
        return 1

    def configureNveGlobal(self,vtep_dict):
        
        for dut in vtep_dict:
            self.log.info('configuring NveInterfaceGlobals on dut {0}'.format(dut))
            nve_global_config_dict = self.configdict['scale_config_dict'][dut]['interface']['nve']
            
            if 'multisite_config_dict' in self.configdict.keys():
                multisite_config_dict = self.configdict['multisite_config_dict']
                if dut in multisite_config_dict.keys():
                    if 'global' in multisite_config_dict[dut]:
                        ns = parseMultisiteConfigs(self.log, multisite_config_dict[dut]['global'])
                        self.log.info(banner('The value of ns is : {0}'.format(ns)))
                        cfg = ''
                        if hasattr (ns, 'site_id') and ns.site_id:
                            cfg += 'evpn multisite border-gateway {0}'.format(ns.site_id) + '\n'
                        if hasattr (ns, 'dci_advertise_pip') and ns.dci_advertise_pip:
                            cfg += 'dci-advertise-pip' + '\n'
                        if hasattr (ns, 'delay_restore_time') and ns.delay_restore_time:
                            cfg += 'delay-restore time {0}'.format(ns.delay_restore_time) + '\n'
                        vtep_dict[dut].configure(cfg)
            
            res = cfgNveGlobal(dut,vtep_dict[dut],nve_global_config_dict,self.log)
        return 1
        # threads = []
        # for dut in vtep_dict:
        #     t = threading.Thread(target = cfgNveGlobal,
        #                          args = [dut, vtep_dict[dut],self.configdict['scale_config_dict'][dut]['interface']['nve'],self.log])
        #     t.start()
        #     threads.append(t)
        # [thread.join() for thread in threads]
        # return 1

    def configureL2VNIOnNve(self,vtep_dict):
        threads = []
        for dut in vtep_dict:
            t = threading.Thread(target = cfgL2VNIOnNVeIntf,
                                 args = [dut, vtep_dict[dut],self.configdict['scale_config_dict'][dut]['interface']['nve'],self.log])
            t.start()
            threads.append(t)
        [thread.join() for thread in threads]
        return 1

    def configureL3VNIOnNve(self,vtep_dict):
        threads = []
        for dut in vtep_dict:
            t = threading.Thread(target = cfgL3VNIOnNVeIntf,
                                 args = [dut, vtep_dict[dut],self.configdict['scale_config_dict'][dut]['interface']['nve'],self.log])
            t.start()
            threads.append(t)
        [thread.join() for thread in threads]
        return 1
    
    def configureL3SubInterface(self,device_dut):
#         threads = []
#         for dut in device_dut:
#             self.log.info('the value of dut is : {0}'.format(dut))
#             t = threading.Thread(target = cfgL3SubIf,
#                                  args = [dut,device_dut[dut],self.configdict['scale_config_dict'][dut]['interface']['sub_if'],\
#                                          self.log,self.alias_intf_mapping_dict])
#             t.start()
#             threads.append(t)
#         [thread.join() for thread in threads]
#         return 1
        
        for dut in device_dut:
            self.log.info('configuring SubInterface on dut {0}'.format(dut))
            if 'sub_if' in self.configdict['scale_config_dict'][dut]['interface'].keys():
                sub_intf_config_dict = self.configdict['scale_config_dict'][dut]['interface']['sub_if']
                res = cfgL3SubIf(dut,device_dut[dut],sub_intf_config_dict,self.log,self.alias_intf_mapping_dict)
        return 1
    
    def configureLoopbackInterface(self,external_rp_dict):
        for dut in external_rp_dict:
            loopback_config_dict = self.configdict['scale_config_dict'][dut]['interface']['loopback']
            res = cfgLoopbackIntf(dut,external_rp_dict[dut],loopback_config_dict,self.log)
        return 1

    def configureOspfRouterID(self,external_rp_dict):
        for dut in external_rp_dict:
            ospf_router_id_dict = self.configdict['scale_config_dict'][dut]['global']['ospf_router_id']
            res = cfgOspfRouterID(dut,external_rp_dict[dut],ospf_router_id_dict,self.log)
        return 1

    def configurePrefixList(self,device_dict):
        for dut in device_dict:
            prefix_list_dict = self.configdict['scale_config_dict'][dut]['global']['prefix_list']
            res = cfgPrefixList(dut,device_dict[dut],prefix_list_dict,self.log)
        return 1
   
    def configureRouteMap(self,device_dict):
        for dut in device_dict:
            route_map_dict = self.configdict['scale_config_dict'][dut]['global']['route_map']
            res = cfgRouteMap(dut,device_dict[dut],route_map_dict,self.log)
        return 1
        
    def configurePimAnyCastLoopbackInterface(self,device_dict):
        for dut in device_dict:
            pim_anycast_loopback_config_dict = self.configdict['scale_config_dict'][dut]['interface']['pim_anycast_loopback']
            res = cfgLoopbackIntfForAnyCastRP(dut,device_dict[dut],pim_anycast_loopback_config_dict,self.log)
        return 1
    
    def configurePimAnyCastRPSet(self,device_dict):
        for dut in device_dict:
            pim_anycast_loopback_rp_set_dict = self.configdict['scale_config_dict'][dut]['interface']['pim_anycast_rp_set']
            res = cfgPimAnyCastRPSet(dut,device_dict[dut],pim_anycast_loopback_rp_set_dict,self.log)  
        return 1      
    
class TrafficConfiguration:
    
    def __init__(self,log,testscript,configdict,port_handle_dict):
        self.log = log
        self.testscript = testscript
        self.configdict = configdict
        self.port_handle_dict = port_handle_dict
        
    def tgnConnection(self):
        testbed_obj = testscript.parameters['testbed_obj']
        tgn_list = testscript.parameters['TGList']
        
        for tg in tgn_list:
            tgn_hdl = testbed_obj.devices(tg)
            
    def sendArpRequest(self,arp_args = '',tg_hdl = '', port_handle=''):
#        ns = parseArpArgs(self.log,arp_args)
        arp_config = tg_hdl.interface_config(port_handle = port_handle,
                                             arp_on_linkup = '1',arp_send_req = '1',
                                             arp_req_retries = '4',single_arp_per_gateway = '0')
        if not arp_config['status']:
            self.log.error('ARP Request sent is not succcessful...')
            return 0
        return 1

        
    def generateIGMPTrafficdict(self,tgn_hdl,trf_config_dict):
        igmp_traffic_config_dict = {}
        
        self.log.info(banner('Configuring the Interfaces required for the test : '))
        for TGInt in trf_config_dict['tg_interface_config_dict'].keys():
            ip_list = []
            igmp_traffic_config_dict[TGInt]={}
            self.log.info('The Value of TGInt is : {0}'.format(TGInt))
            intf_args = generateTrafficGenIntfConfigs(self.log,trf_config_dict['tg_interface_config_dict'][TGInt])
            self.log.info('The Value of intf_args is : {0}'.format(intf_args))
            for i in intf_args:
                ixia_interface_config = configureMultiIxNetworkInterface(self,i,tg_hdl=tgn_hdl,port_handle=self.port_handle_dict[TGInt])
                self.log.info('the value of ixia_interface_config is : {0}'.format(ixia_interface_config))
                for ip,intf_hdl in ixia_interface_config.items():
                    self.log.info('The value of ip is : {0}'.format(ip))
                    ip_list.append(ip)
                    igmp_traffic_config_dict[TGInt][ip]={}
                    self.log.info('The value of intf_hdl is : {0}'.format(intf_hdl))
                    igmp_traffic_config_dict[TGInt][ip]['handle'] = intf_hdl
                self.log.info('The value of ip_list is : {0}'.format(ip_list))
                igmp_traffic_config_dict[TGInt]['ip_list'] = ip_list
                #countDownTimer(5)
                
        self.log.info(banner('The igmp_traffic_config_dict after generating the interface is: {0}'.format(yaml.dump(igmp_traffic_config_dict))))
        
        #igmp_status = tgn_hdl.test_control(action = 'stop_all_protocols')
        
        #countDownTimer(10)
        
        self.log.info(banner('Creating IGMP hosts in TGN:'))
        
        TGIgmpIntList = list(trf_config_dict['igmp_config_dict'].keys())
        
        for TGIgmpInt in TGIgmpIntList:
            e = tgn_hdl.interfaces[TGIgmpInt].tgen_port_handle
            igmp_group_dict = generateIGMPGroupList(self.log,trf_config_dict['igmp_config_dict'][TGIgmpInt])
            self.log.info('the value of igmp_group_dict is : {0}'.format(igmp_group_dict))
            group_list = igmp_group_dict['groups']
            group_config = igmp_group_dict['configs']
            for i,ip in enumerate(igmp_traffic_config_dict[TGIgmpInt]['ip_list']):
                igmp_traffic_config_dict[TGIgmpInt][ip]['group'] = group_list[i]
                if igmp_group_dict['v3_configs']:
                    new_emulation_igmp_group_cfg = configureIgmpReports(self, group_config[i], tg_hdl=tgn_hdl, port_handle = e, intf_handle=igmp_traffic_config_dict[TGIgmpInt][ip]['handle'],
                                                                    g_filter_mode=igmp_group_dict['v3_configs']['g_filter_mode'],source_pool_handle=igmp_group_dict['v3_configs']['source_pool_handle'])
                else:
                    new_emulation_igmp_group_cfg = configureIgmpReports(self, group_config[i], tg_hdl=tgn_hdl, port_handle = e, intf_handle=igmp_traffic_config_dict[TGIgmpInt][ip]['handle'])
                igmp_traffic_config_dict[TGIgmpInt][ip]['session_handle'] = new_emulation_igmp_group_cfg.handle
                
        
        self.log.info(banner('The igmp_traffic_config_dict after generating the interface is: {0}'.format(yaml.dump(igmp_traffic_config_dict))))
        
        #igmp_status = tgn_hdl.test_control(action = 'start_all_protocols')
        
        #countDownTimer(10)
        
        self.log.info(banner('Generating Traffic Item in TGN:'))
        
        source_port = trf_config_dict['traffic_config_dict']['source']
        receiver_port = trf_config_dict['traffic_config_dict']['receivers']
        traffic_args = trf_config_dict['traffic_config_dict']['params']
        src_handle = []
        dest_handle = []
        for i in source_port:
            for port in igmp_traffic_config_dict:
                if (port == i):
                    pat = re.compile("^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$")
                    for ip in igmp_traffic_config_dict[port]:
                        test = pat.match(ip)
                        if test:
                            handle = igmp_traffic_config_dict[port][ip]['handle']
                            src_handle.append(handle)
        for i in receiver_port:
            for port in igmp_traffic_config_dict:
                if (port == i):
                    pat = re.compile("^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$")
                    for ip in igmp_traffic_config_dict[port]:
                        test = pat.match(ip)
                        if test:
                            handle = igmp_traffic_config_dict[port][ip]['session_handle']
                            dest_handle.append(handle)    
        
        ixia_traffic_config = configureIxNetworkTraffic(self, traffic_args, tg_hdl=tgn_hdl, emulation_src_handle=src_handle, emulation_dst_handle=dest_handle)                
        
        self.log.info(banner('The value of ixia_traffic_config is : {0}'.format(ixia_traffic_config)))
        
        self.log.info(banner('The Value of ixia_traffic_config is : {0}'.format(list(ixia_traffic_config.keys()))))
        
        igmp_traffic_config_dict['source'] = source_port
        igmp_traffic_config_dict['destination'] = receiver_port
        igmp_traffic_config_dict['status'] = ixia_traffic_config['status']
        igmp_traffic_config_dict['traffic_item'] = ixia_traffic_config['traffic_item']
        igmp_traffic_config_dict['stream_id'] = ixia_traffic_config['stream_id']
        
        self.log.info(banner('The igmp_traffic_config_dict after generating the interface is: {0}'.format(yaml.dump(igmp_traffic_config_dict))))
        
        return igmp_traffic_config_dict
        

class IxiaRawTrafficGeneration:
    
    def __init__(self,log,tgn_hdl,configdict,port_handle_dict):
        self.log = log
        self.tgn_hdl = tgn_hdl
        self.configdict = configdict
        self.port_handle_dict = port_handle_dict
    
    def configureTrafficEndPoints(self,traffic_endpoint_args,emulation_src_handle,emulation_dst_handle):
        ns = parseTrafficEndPointArgs(self.log,traffic_endpoint_args)
        self.log.info('The value of ns is : {0}'.format(ns))
        raw_stream_config_hdl = self.tgn_hdl.traffic_config(mode=ns.mode,emulation_dst_handle=emulation_dst_handle,emulation_src_handle=emulation_src_handle,
                                                            circuit_type=ns.circuit_type,bidirectional=ns.bidirectional,name=ns.name)
        if raw_stream_config_hdl['status'] == 1:
            self.log.info('Successfully Configured the Traffic End Points .. ... ')
        else:
            self.log.error('Failed to configure Traffic end points.... ... .. ')
            self.failed()
        return raw_stream_config_hdl
    
    def configureTrafficStreamParameters(self, stream_hdl, traffic_stream_args):
        ns = parseTrafficStreamArgs(self.log,traffic_stream_args)
        self.log.info('The Value of ns is : {0}'.format(ns))
        
        raw_stream_config_hdl = self.tgn_hdl.traffic_config(mode=ns.mode, stream_id = stream_hdl,rate_pps = ns.rate_pps,
                                                            frame_size = ns.frame_size, transmit_mode = ns.transmit_mode,
                                                            track_by = ns.track_by)
        if raw_stream_config_hdl['status'] == 1:
            self.log.info('Successfully Configured the Stream Parameters .. ... ')
        else:
            self.log.error('Failed to configure the Stream Parameters.... ... .. ')
            self.failed()
        return raw_stream_config_hdl
    
    def configureEthernetHeader(self,stream_hdl,ethernet_header_args):
        ns = parseEthernetHeaderArgs(self.log,ethernet_header_args)
        self.log.info('The value of ns is : {0}'.format(ns))
        
        raw_stream_config_hdl = self.tgn_hdl.traffic_config(mode=ns.mode, stream_id = stream_hdl, stack_index = ns.stack_index,
                                                            l2_encap = ns.l2_encap,mac_dst = ns.mac_dst,mac_src = ns.mac_src,
                                                            mac_src_mode = ns.mac_src_mode, mac_src_step = ns.mac_src_step,
                                                            mac_src_count = ns.mac_src_count)
        if raw_stream_config_hdl['status'] == 1:
            self.log.info('Successfully Configured Ethenet Headers .. ... ')
        else:
            self.log.error('Failed to configure Ethernet HEaders.... ... .. ')
            self.failed()
        return raw_stream_config_hdl
               
    def configureVlanHeader(self,stream_hdl,vlan_header_args):
        ns = parseVlanHeaderArgs(self.log,vlan_header_args)
        self.log.info('The value of ns is : {0}'.format(ns))
        
        raw_stream_config_hdl = self.tgn_hdl.traffic_config(mode=ns.mode, stream_id = stream_hdl, stack_index = ns.stack_index,
                                                            vlan = ns.vlan,vlan_id = ns.vlan_id)
        if raw_stream_config_hdl['status'] == 1:
            self.log.info('Successfully Configured the Vlan Headers.. ... ')
        else:
            self.log.error('Failed to configure Vlan Headers... ... .. ')
            self.failed()
        return raw_stream_config_hdl        

    def configureARPHeader(self,stream_hdl,arp_header_args):
        ns = parseARPHeaderArgs(self.log,arp_header_args)
        self.log.info('The value of ns is : {0}'.format(ns))
        
        raw_stream_config_hdl = self.tgn_hdl.traffic_config(mode=ns.mode, stream_id = stream_hdl, stack_index = ns.stack_index,
                                                            l3_protocol = ns.l3_protocol, arp_protocol_type = ns.arp_protocol_type,
                                                            arp_hw_address_length_mode = ns.arp_hw_address_length_mode, arp_hw_type_mode = ns.arp_hw_type_mode,
                                                            arp_hw_type = ns.arp_hw_type, arp_hw_type_tracking = ns.arp_hw_type_tracking,
                                                            arp_protocol_type_mode = ns.arp_protocol_type_mode, arp_protocol_type_tracking = ns.arp_protocol_type_tracking,
                                                            arp_hw_address_length= ns.arp_hw_address_length,arp_hw_address_length_tracking = ns.arp_hw_address_length_tracking,
                                                            arp_protocol_addr_length_mode=ns.arp_protocol_addr_length_mode,arp_protocol_addr_length=ns.arp_protocol_addr_length,
                                                            arp_protocol_addr_length_tracking=ns.arp_protocol_addr_length_tracking,
                                                            arp_operation_mode=ns.arp_operation_mode,arp_operation=ns.arp_operation,
                                                            arp_operation_tracking=ns.arp_operation_tracking,arp_src_hw_mode=ns.arp_src_hw_mode,
                                                            arp_src_hw_tracking=ns.arp_src_hw_tracking,arp_src_hw_addr=ns.arp_src_hw_addr,
                                                            arp_src_protocol_addr_mode=ns.arp_src_protocol_addr_mode,arp_src_protocol_addr=ns.arp_src_protocol_addr,
                                                            arp_src_protocol_addr_tracking=ns.arp_src_protocol_addr_tracking,arp_dst_hw_mode=ns.arp_dst_hw_mode,
                                                            arp_dst_hw_tracking=ns.arp_dst_hw_tracking,arp_dst_hw_addr=ns.arp_dst_hw_addr,
                                                            arp_dst_protocol_addr_mode=ns.arp_dst_protocol_addr_mode,arp_dst_protocol_addr=ns.arp_dst_protocol_addr,
                                                            arp_dst_protocol_addr_tracking=ns.arp_dst_protocol_addr_tracking,track_by=ns.track_by,
                                                            egress_tracking=ns.egress_tracking)
                                                            
        if raw_stream_config_hdl['status'] == 1:
            self.log.info('Successfully Configured the Vlan Headers.. ... ')
        else:
            self.log.error('Failed to configure Vlan Headers... ... .. ')
            self.failed()
        return raw_stream_config_hdl        

    def configureIPv6ProtocolHeader(self,stream_hdl,ip_header_args):
        ns = parseIPv6HeaderArgs(self.log,ip_header_args)
        self.log.info('The value of ns is : {0}'.format(ns))
        
        raw_stream_config_hdl = self.tgn_hdl.traffic_config(mode=ns.mode, stream_id = stream_hdl, stack_index = ns.stack_index,
                                                            l3_protocol= ns.l3_protocol, ipv6_src_addr = ns.ipv6_src_addr, 
                                                            ipv6_dst_addr  = ns.ipv6_dst_addr)
        if raw_stream_config_hdl['status'] == 1:
            self.log.info('Successfully Configured the Traffic End Points .. ... ')
        else:
            self.log.error('Failed to configure Traffic end points.... ... .. ')
            self.failed()
        return raw_stream_config_hdl                                                                 
        
    def configureIPv4ProtocolHeader(self,stream_hdl,ip_header_args):
        ns = parseIPv4HeaderArgs(self.log,ip_header_args)
        self.log.info('The value of ns is : {0}'.format(ns))
        
        #raw_stream_config_hdl = self.tgn_hdl.traffic_config(mode=ns.mode, stream_id = stream_hdl, stack_index = ns.stack_index,
        #                                                    l3_protocol= ns.l3_protocol, ip_src_addr = ns.ip_src_addr, 
        #                                                    ip_dst_addr  = ns.ip_dst_addr, ip_precedence= ns.ip_precedence, ip_delay = ns.ip_delay)

        raw_stream_config_hdl = self.tgn_hdl.traffic_config(mode=ns.mode, stream_id = stream_hdl, stack_index = ns.stack_index,
                                                            l3_protocol= ns.l3_protocol, ip_src_addr = ns.ip_src_addr, 
                                                            ip_dst_addr  = ns.ip_dst_addr)
        if raw_stream_config_hdl['status'] == 1:
            self.log.info('Successfully Configured the Traffic End Points .. ... ')
        else:
            self.log.error('Failed to configure Traffic end points.... ... .. ')
            self.failed()
        return raw_stream_config_hdl                    

    def configureUDPHeader(self,stream_hdl,udp_header_args):
        ns = parseUDPHeaderArgs(self.log,udp_header_args)
        self.log.info('The value of ns is : {0}'.format(ns))
        
        raw_stream_config_hdl = self.tgn_hdl.traffic_config(mode=ns.mode, stream_id = stream_hdl, stack_index = ns.stack_index,
                                                            l4_protocol= ns.l4_protocol, udp_src_port = ns.udp_src_port, 
                                                            udp_dst_port  = ns.udp_dst_port)
        if raw_stream_config_hdl['status'] == 1:
            self.log.info('Successfully Configured the Traffic End Points .. ... ')
        else:
            self.log.error('Failed to configure Traffic end points.... ... .. ')
            self.failed()
        return raw_stream_config_hdl    
    
    def configureVxlanHeader(self,stream_hdl,vxlan_header_args):
        ns = parseVxlanHeaderArgs(self.log,vxlan_header_args)
        self.log.info('The value of ns is : {0}'.format(ns))
        
        raw_stream_config_hdl = self.tgn_hdl.traffic_config(mode=ns.mode, stream_id = stream_hdl, stack_index = ns.stack_index,
                                                            pt_handle = ns.pt_handle)
        if raw_stream_config_hdl['status'] == 1:
            self.log.info('Successfully Configured the Traffic End Points .. ... ')
        else:
            self.log.error('Failed to configure Traffic end points.... ... .. ')
            self.failed()
        return raw_stream_config_hdl                       

    def configureVxlanVNIHeader(self,stream_hdl,vni_header_args,last_stack):
        ns = parseVxlanVNIHeaderArgs(self.log,vni_header_args)
        self.log.info('The value of ns is : {0}'.format(ns))
        
        raw_stream_config_hdl = self.tgn_hdl.traffic_config(mode=ns.mode, header_handle = last_stack, field_handle = ns.field_handle,
                                                            pt_handle = ns.pt_handle,field_valueType = ns.field_valueType, 
                                                            field_singleValue = ns.field_singleValue)
        if raw_stream_config_hdl['status'] == 1:
            self.log.info('Successfully Configured the Traffic End Points .. ... ')
        else:
            self.log.error('Failed to configure Traffic end points.... ... .. ')
            self.failed()
        return raw_stream_config_hdl  

class VerifyConfigs:
    
    def __init__(self,log,config_dict,node_dict,alias_intf_mapping_dict):
        self.log = log
        self.configdict = config_dict
        self.nodedict = node_dict
        self.alias_intf_mapping_dict = alias_intf_mapping_dict
        
    def verifyOSPFv4Neighorship(self):
        self.log.info(banner('Inside Verify OSPF V4 Neighborship'))
        flag = 0
        for dut in self.configdict['ospfv2_config_dict']:
            log.info('Verifying OSPF Neighborship on Dut : {0}'.format(dut))
            hdl = self.nodedict['all_dut'][dut]
            process_id = list(self.configdict['ospfv2_config_dict'][dut].keys())[0]
            for intf in self.configdict['ospfv2_config_dict'][dut][process_id]['interface_configs']:
                if re.search('uut', intf):
                    res = getV4OSPFNeighborshipState(self.log,hdl,self.alias_intf_mapping_dict[dut][intf],dut)
                    if not res:
                        self.log.error('OSPF Neighborship is not Established on Interface {0} in dut {1}'.format(self.alias_intf_mapping_dict[dut][intf],dut))
                        flag = 1
        if flag:
            return 0
        return 1

    def verifyOSPFv6Neighorship(self):
        self.log.info(banner('Inside Verify OSPF V6 Neighborship'))
        flag = 0
        for dut in self.configdict['ospfv3_config_dict']:
            hdl = self.nodedict['all_dut'][dut]
            for intf in self.configdict['ospfv3_config_dict'][dut]['interface_config']:
                if re.search('uut', intf):
                    res = getV6OSPFNeighborshipState(self.log,hdl,self.alias_intf_mapping_dict[dut][intf],dut)
                    if not res:
                        self.log.error('OSPFv3 Neighborship is not Established on Interface {0} in dut {1}'.format(self.alias_intf_mapping_dict[dut][intf],dut))
                        flag = 1
        if flag:
            return 0
        return 1
    
    def verifyBGPL2EVPNNeighbor(self):
        self.log.info(banner('Inside Verify BGP L2EVPN Neighborship'))
        flag = 0 
        for dut in self.configdict['bgp_config_dict']:
            hdl = self.nodedict['all_dut'][dut]
            as_no = list(self.configdict['bgp_config_dict'][dut].keys())[0]
            try:
                self.log.info(banner('The value of keys is : {0}'.format(list(self.configdict['bgp_config_dict'][dut][as_no]['default']['neighbors'].keys()))))
                neighbor_list = []
                if 'ipv6' in list(self.configdict['bgp_config_dict'][dut][as_no]['default']['neighbors'].keys()):
                    self.log.info('Inside v6 Block')
                    [neighbor_list.append(x) for x in list(self.configdict['bgp_config_dict'][dut][as_no]['default']['neighbors']['ipv6'].keys())]
                if 'ipv4' in list(self.configdict['bgp_config_dict'][dut][as_no]['default']['neighbors'].keys()):
                    self.log.info('Inside v4 block')
                    [neighbor_list.append(x) for x in list(self.configdict['bgp_config_dict'][dut][as_no]['default']['neighbors']['ipv4'].keys())]
                self.log.info('The value of neighbor_list is : {0}'.format(neighbor_list))
                for neighbor in neighbor_list:
                    res = getBGPL2eVPNState(self.log,hdl,neighbor,dut)
                    if not res:
                        self.log.error(banner('EVPN neighborship {0} on dut {1} is not established as expected'.format(neighbor,dut)))
                        flag = 1
            except Exception:
                self.log.info(banner('The Neighbors are not defined in the config-dict for dut {0}'.format(dut)))


        if flag:
            return 0
        return 1

    def verifyBGPL2MVPNNeighbor(self):
        self.log.info(banner('Inside Verify BGP L2MVPN Neighborship'))
        flag = 0 
        for dut in self.configdict['bgp_config_dict']:
            hdl = self.nodedict['all_dut'][dut]
            as_no = list(self.configdict['bgp_config_dict'][dut].keys())[0]
            self.log.info(banner('The value of keys is : {0}'.format(list(self.configdict['bgp_config_dict'][dut][as_no]['default']['neighbors'].keys()))))
            neighbor_list = []
            if 'ipv6' in list(self.configdict['bgp_config_dict'][dut][as_no]['default']['neighbors'].keys()):
                self.log.info('Inside v6 Block')
                [neighbor_list.append(x) for x in list(self.configdict['bgp_config_dict'][dut][as_no]['default']['neighbors']['ipv6'].keys())]
            if 'ipv4' in list(self.configdict['bgp_config_dict'][dut][as_no]['default']['neighbors'].keys()):
                self.log.info('Inside v4 block')
                [neighbor_list.append(x) for x in list(self.configdict['bgp_config_dict'][dut][as_no]['default']['neighbors']['ipv4'].keys())]
            self.log.info('The value of neighbor_list is : {0}'.format(neighbor_list))
            for neighbor in neighbor_list:
                res = getBGPL2mVPNState(self.log,hdl,neighbor,dut)
                if not res:
                    self.log.error(banner('MVPN neighborship {0} on dut {1} is not established as expected'.format(neighbor,dut)))
                    flag = 1
        if flag:
            return 0
        return 1
    
    def verifyVNIStatus(self, vtep_dict):
        self.log.info(banner('Inside Verify VNI Status:'))
        flag = 0
        for dut in vtep_dict:
            res = getVNIStatus(self.log,vtep_dict[dut], dut,self.configdict)
        
        if not res:
            self.log.info(banner('VNI Status / Count is not as expected. Refer Script logs for details'))
            flag = 1
            
        if flag:
            return 0
        return 1
    
    def verifyNVEStatus(self,vtep_dict):
        for dut in vtep_dict:
            ns = parseNVEParams(self.log,self.configdict['scale_config_dict'][dut]['interface']['nve'])
            cfg = 'show nve peers | json'
            out =vtep_dict[dut].execute(cfg)
            json_out = json.loads(out)
            for item in json_out['TABLE_nve_peers']['ROW_nve_peers']:
                self.log.info('The value of item is : {0} and its type is : {1}'.format(item, type(item)))
                peer_state = item['peer-state']
                if not re.search('Up',peer_state):
                    log.info('The Nve Peer {0} is not up. state is {1}'.format(ns.peer_ip,peer_state))
                    return 0
        return 1

    def verifyNVEStatus1(self,vtep_dict):
        for dut in vtep_dict:
            ns = parseNVEParams(self.log,self.configdict['scale_config_dict'][dut]['interface']['nve'])
            log.info('The value of ns is : {0}'.format(ns))
            cfg = 'show nve peers | json'
            out =vtep_dict[dut].execute(cfg)
            json_out = json.loads(out)
            
            if isinstance(json_out['TABLE_nve_peers']['ROW_nve_peers'],list):
                for item in json_out['TABLE_nve_peers']['ROW_nve_peers']:
                    self.log.info('The value of item is : {0} and its type is : {1}'.format(item, type(item)))
                    peer_state = item['peer-state']
                    if not re.search('Up',peer_state):
                        log.info('The Nve Peer {0} is not up. state is {1}'.format(ns.peer_ip,peer_state))
                        return 0
            else:
                for item in json_out['TABLE_nve_peers']['ROW_nve_peers']:
                    self.log.info('The value of item inside else is : {0} and its type is : {1}'.format(item, type(item)))
                    if re.search('peer-state',item):
                        peer_state = json_out['TABLE_nve_peers']['ROW_nve_peers'][item]
                        #log.info('The Nve Peer {0} status is : {1}'.format(ns.peer_ip,peer_state))
                        if not re.search('Up', peer_state):
                            log.info('The Nve Peer {0} is not up. state is {1}'.format(ns.peer_ip,peer_state))
                            return 0
                
        return 1
    
class TrafficStatistics: 
    
    def __init__(self,log,tg_interface_hdl_dict,traffic_stream_dict,port_handle_dict,
                 threshold,node_dict,alias_intf_mapping,configured_stream):
        self.log = log
        self.tg_interface_hdl_dict = tg_interface_hdl_dict
        self.port_handle_dict = port_handle_dict
        self.threshold = threshold
        self.nodedict = node_dict
        self.traffic_stream_dict = traffic_stream_dict
        self.alias_intf_mapping = alias_intf_mapping
        self.configured_stream = configured_stream
        
    def getAllBoundStreamStatistics(self,tgn_hdl):
        self.log.info(banner('Getting All Bound Stream statistics'))
        bound_trf_stats = {}
        for stream in self.configured_stream:
            log.info('getAllBoundStreamStatistics:The value of stream is : {0}'.format(stream))
            if re.search('TRF|TEST|BL', stream):
                res = getTrafficItemStatistics(self.log,tgn_hdl,self.traffic_stream_dict,stream)
                bound_trf_stats[stream] = res
        self.log.info(banner('The value of bound_trf_stats is : {0}'.format(yaml.dump(bound_trf_stats))))
        
        self.log.info(banner('The Traffic stats in tabular Format is :'))
        res = drawTrafficTable(self.log,bound_trf_stats)
        self.log.info('\n {0}'.format(res))
        
    def getAllRawStreamStatistics(self,tgn_hdl):
        self.log.info(banner('Getting All Raw Stream statistics'))
        raw_trf_stats = {}
        for stream in self.configured_stream:
            if re.search('RAW', stream):
                res = getTrafficItemStatistics(self.log,tgn_hdl,self.traffic_stream_dict,stream)
                raw_trf_stats[stream] = res
        self.log.info(banner('The value of bound_trf_stats is : {0}'.format(yaml.dump(raw_trf_stats))))
        
        self.log.info(banner('The Traffic stats in tabular Format is :'))
        res = drawTrafficTable(self.log,raw_trf_stats,self.traffic_stream_dict)
        self.log.info('\n {0}'.format(res))
        
    def getAllTrafficStatus(self, tgn_hdl):
        self.log.info(banner('Getting Total Statistics ..'))
        final_status = 1
        all_traffic_dict = {}
        failed_stream = []
        for stream in self.configured_stream:
            stream_id = self.traffic_stream_dict[stream]['stream_id']
            y = tgn_hdl.traffic_stats(stream=stream_id,mode='traffic_item')
            for i in y['traffic_item']:
                if i == stream_id:
                    loss_percent= y['traffic_item'][i]['rx']['loss_percent']
                    if loss_percent > 10.0:
                        failed_stream.append(stream)
        
        if  failed_stream:
            failed_stream_table_dict = {}
            final_status = 0
            self.log.info(banner('The Following stream did not meet the pass criteria'))
            for stream in failed_stream:
                failed_stream_table_dict[stream] = getTrafficItemStatistics(self.log,tgn_hdl,self.traffic_stream_dict,stream)
            final_status = failed_stream_table_dict
        
        all_traffic_dict['status'] = final_status
#        all_traffic_dict['']
        
        return final_status
    


# ******************** START : PREFIX_LIST AND ROUTE_MAP METHODS ********************#

def parsePrefixListArgs(log,args):
    arggrammar = {}
    arggrammar['name'] = '-type str'
    arggrammar['seq1'] = '-type int'
    arggrammar['seq1_action'] = '-type str'
    arggrammar['seq1_route'] = '-type str'
    arggrammar['seq1_route_qualifier'] = '-type str'
    arggrammar['seq1_route_qualifier_mask'] = '-type int'
    ns = utils.parserutils_lib.argsToCommandOptions(args,arggrammar,log)
    return ns

def parseRouteMapArgs(log,args):
    arggrammar = {}
    arggrammar['name'] = '-type str'
    arggrammar['seq1'] = '-type int'
    arggrammar['seq1_action'] = '-type str'
    arggrammar['seq1_match_prefix_list'] = '-type str'
    arggrammar['match_tag' ] = '-type str'
    ns = utils.parserutils_lib.argsToCommandOptions(args,arggrammar,log)
    return ns

def cfgPrefixList(dut,hdl,prefix_list_args,log):
    ns = parsePrefixListArgs(log,prefix_list_args)
    log.info('The value of ns is : {0}'.format(ns))
    cfg = ''
    if hasattr(ns,'name') and ns.name:
        if hasattr(ns, 'seq1') and ns.seq1:
            if hasattr(ns, 'seq1_action') and ns.seq1_action:
                if hasattr(ns, 'seq1_route') and ns.seq1_route:
                    if hasattr(ns, 'seq1_route_qualifier') and ns.seq1_route_qualifier:
                        if hasattr(ns, 'seq1_route_qualifier_mask') and ns.seq1_route_qualifier_mask:
                            cfg += 'ip prefix-list {0} seq {1} {2} {3} {4} {5}'.format(ns.name,ns.seq1,ns.seq1_action,ns.seq1_route,
                                                                                       ns.seq1_route_qualifier,ns.seq1_route_qualifier_mask)
                            log.info('Configuring the Prefix list {0} on dut {1} with config value {2}'.format(ns.name,dut,cfg))
        hdl.configure(cfg)
    return 1

def cfgRouteMap(dut,hdl,prefix_list_args,log):
    ns = parseRouteMapArgs(log,prefix_list_args)
    log.info('The value of ns is : {0}'.format(ns))
    cfg = ''
    if hasattr(ns,'name') and ns.name:
        if hasattr(ns, 'seq1_action') and ns.seq1_action:
            if hasattr(ns, 'seq1') and ns.seq1:
                cfg += 'route-map {0} {1} {2}\n'.format(ns.name,ns.seq1_action,ns.seq1)
            if hasattr(ns,'match_tag') and ns.match_tag:
                cfg += 'match tag {0} \n'.format(ns.match_tag)
            if hasattr(ns, 'seq1_match_prefix_list') and ns.seq1_match_prefix_list:
                cfg += 'match ip address prefix-list {0}'.format(ns.seq1_match_prefix_list)
                log.info('Configuring the Prefix list {0} on dut {1} with config value {2}'.format(ns.name,dut,cfg))
        hdl.configure(cfg)
    return 1

# ******************** START: RAW TRAFFIC GENERATION METHODS *********************** #

def parseTrafficEndPointArgs(log,args):
    arggrammar = {}
    arggrammar['mode'] = '-type str'
    arggrammar['circuit_type'] = '-type str'
    arggrammar['bidirectional'] = '-type str'
    arggrammar['name'] = '-type str'
    ns = utils.parserutils_lib.argsToCommandOptions(args,arggrammar,log)
    return ns
 
def parseTrafficStreamArgs(log,args):
    arggrammar = {}
    arggrammar['mode'] = '-type str'
    arggrammar['rate_pps'] = '-type str'
    arggrammar['transmit_mode'] = '-type str'
    arggrammar['track_by'] = '-type str'
    arggrammar['frame_size'] = '-type str'
    ns = utils.parserutils_lib.argsToCommandOptions(args,arggrammar,log)
    return ns

def parseEthernetHeaderArgs(log, args):
    log.info('Inside parseEthernetHeaderArgs:')
    arggrammar = {}
    arggrammar['mode'] = '-type str'
    arggrammar['stack_index'] = '-type str'
    arggrammar['l2_encap'] = '-type str'
    arggrammar['mac_dst'] = '-type str'
    arggrammar['mac_src'] = '-type str'
    arggrammar['mac_src_mode'] = '-type str'
    arggrammar['mac_src_step'] = '-type str'
    arggrammar['mac_src_count'] = '-type str'
    ns = utils.parserutils_lib.argsToCommandOptions(args,arggrammar,log)
    return ns

def parseVlanHeaderArgs(log,args):
    log.info('Inside VlanHeader Args:')
    arggrammar = {}
    arggrammar['mode'] = '-type str'
    arggrammar['stack_index'] = '-type str'
    arggrammar['vlan'] = '-type str'
    arggrammar['vlan_id'] = '-type str'
    arggrammar['vlan_id_mode'] = '-type str'
    arggrammar['vlan_id_step'] = '-type str'
    arggrammar['vlan_id_count'] = '-type str'
    ns = utils.parserutils_lib.argsToCommandOptions(args,arggrammar,log)
    return ns

def parseARPHeaderArgs(log, args):
    log.info('Inside ARP Header Args:')
    arggrammar = {}
    arggrammar['mode'] = '-type str'
    arggrammar['stack_index'] = '-type str'
    arggrammar['l3_protocol'] = '-type str'
    arggrammar['arp_protocol_type'] = '-type str'
    arggrammar['arp_hw_address_length_mode']  = '-type str'
    arggrammar['arp_hw_type_mode'] = '-type str'
    arggrammar['arp_hw_type'] = '-type str'
    arggrammar['arp_hw_type'] = '-type str'
    arggrammar['arp_hw_type_tracking'] = '-type str'
    arggrammar['arp_protocol_type_mode'] = '-type str'
    arggrammar['arp_protocol_type'] = '-type str'
    arggrammar['arp_protocol_type_tracking'] = '-type str'
    arggrammar['arp_hw_address_length_mode'] = '-type str'
    arggrammar['arp_hw_address_length'] = '-type str'
    arggrammar['arp_hw_address_length_tracking'] = '-type str'
    arggrammar['arp_protocol_addr_length_mode'] = '-type str'
    arggrammar['arp_protocol_addr_length'] = '-type str'
    arggrammar['arp_protocol_addr_length_tracking'] = '-type str'
    arggrammar['arp_operation_mode'] = '-type str'
    arggrammar['arp_operation'] = '-type str'
    arggrammar['arp_operation_tracking'] = '-type str'
    arggrammar['arp_src_hw_mode'] = '-type str'
    arggrammar['arp_src_hw_tracking'] = '-type str'
    arggrammar['arp_src_hw_addr'] = '-type str'
    arggrammar['arp_src_protocol_addr_mode'] = '-type str'
    arggrammar['arp_src_protocol_addr'] = '-type str'
    arggrammar['arp_src_protocol_addr_tracking'] = '-type str'
    arggrammar['arp_dst_hw_mode'] = '-type str'
    arggrammar['arp_dst_hw_tracking'] = '-type str'
    arggrammar['arp_dst_hw_addr'] = '-type str'
    arggrammar['arp_dst_protocol_addr_mode'] = '-type str'
    arggrammar['arp_dst_protocol_addr'] = '-type str'
    arggrammar['arp_dst_protocol_addr_tracking'] = '-type str'
    arggrammar['track_by'] = '-type str'
    arggrammar['egress_tracking'] = '-type str'
    ns = utils.parserutils_lib.argsToCommandOptions(args,arggrammar,log)
    return ns


def parseIPv6HeaderArgs(log,args):
    log.info('Inside IPv6Header Args:')
    arggrammar = {}
    arggrammar['mode'] = '-type str'
    arggrammar['stack_index'] = '-type str'
    arggrammar['l3_protocol'] = '-type str'
    arggrammar['ipv6_src_addr'] = '-type str'
    arggrammar['ipv6_dst_addr'] = '-type str'
    arggrammar['ipv6_dst_mode'] = '-type str'
    arggrammar['ipv6_dst_count'] = '-type str'
    arggrammar['ipv6_dst_step'] = '-type str'
    ns = utils.parserutils_lib.argsToCommandOptions(args,arggrammar,log)
    return ns   

def parseIPv4HeaderArgs(log,args):
    log.info('Inside IPv4Header Args:')
    log.info('The value of args is: {0}'.format(args))
    arggrammar = {}
    arggrammar['mode'] = '-type str'
    arggrammar['stack_index'] = '-type str'
    arggrammar['l3_protocol'] = '-type str'
    arggrammar['ip_src_addr'] = '-type str'
    arggrammar['ip_dst_addr'] = '-type str'
    arggrammar['ip_dst_mode'] = '-type str'
    arggrammar['ip_dst_count'] = '-type str'
    arggrammar['ip_dst_step'] = '-type str'
    arggrammar['ip_precedence'] = '-type str'
    arggrammar['ip_delay'] = '-type str'
    ns = utils.parserutils_lib.argsToCommandOptions(args,arggrammar,log)
    return ns   

def parseUDPHeaderArgs(log,args):
    log.info('Inside UDP Args:')
    arggrammar = {}
    arggrammar['mode'] = '-type str'
    arggrammar['stack_index'] = '-type str'
    arggrammar['l4_protocol'] = '-type str'
    arggrammar['udp_src_port'] = '-type str'
    arggrammar['udp_dst_port'] = '-type str'
    ns = utils.parserutils_lib.argsToCommandOptions(args,arggrammar,log)
    return ns   

def parseVxlanHeaderArgs(log,args):
    log.info('Inside Vxlan Header Args:')
    arggrammar = {}
    arggrammar['mode'] = '-type str'
    arggrammar['stack_index'] = '-type str'
    arggrammar['pt_handle'] = '-type str'
    ns = utils.parserutils_lib.argsToCommandOptions(args,arggrammar,log)
    return ns  

def parseVxlanVNIHeaderArgs(log,args):
    log.info('Inside Vxlan VNI Header Args:')
    arggrammar = {}
    arggrammar['mode'] = '-type str'
    arggrammar['pt_handle'] = '-type str'
    arggrammar['field_handle'] = '-type str'
    arggrammar['field_valueType'] = '-type str'
    arggrammar['field_singleValue'] = '-type str'
    ns = utils.parserutils_lib.argsToCommandOptions(args,arggrammar,log)
    return ns   

def parseArpArgs(log,args):
    log.info('Inside Parse Arp Args:')
    arggrammar = {}
    arggrammar['mode'] = '-type str'
    arggrammar['arp_on_linkup'] = '-type str'
    arggrammar['arp_send_req'] = '-type str'
    arggrammar['arp_req_retries'] = '-type str'
    ns = utils.parserutils_lib.argsToCommandOptions(args,arggrammar,log)
    return ns   

def parseHostInterfaceArg(log,args):
    log.info('Inside ParseHostInterfaceArgs:')
    arggrammar = {}
    arggrammar['mode'] = '-type str'
    arggrammar['intf_ip_addr'] = '-type str'
    arggrammar['netmask'] = '-type str'
    arggrammar['gateway'] = '-type str'
    arggrammar['vlan'] = '-type str'
    arggrammar['vlan_id'] = '-type str'
    arggrammar['src_mac_addr'] = '-type str'
    arggrammar['mtu'] = '-type str'    
    ns = utils.parserutils_lib.argsToCommandOptions(args,arggrammar,log)
    return ns   

# ********************  START: IGMP Related Methods ******************************** #

def addIGMPTrafficConfigDictToGlobalTrafficStreamDict(log,stream,configdict,new_tg_intf_config_dict):
    log.info('Inside addTrafficItemToGlobalTrafficStreamDict')
    igmp_traffic_dict = {}
    igmp_traffic_dict[stream] = {}
    igmp_traffic_dict[stream]['source'] = configdict['traffic_config_dict']['source']
    igmp_traffic_dict[stream]['destination'] = configdict['traffic_config_dict']['receivers']
    igmp_traffic_dict[stream]['status'] = new_tg_intf_config_dict['traffic_config']['status']
    igmp_traffic_dict[stream]['traffic_item'] = new_tg_intf_config_dict['traffic_config']['traffic_item']
    igmp_traffic_dict[stream]['stream_id'] = new_tg_intf_config_dict['traffic_config']['stream_id'] 
    log.info('The value of igmp_traffic_dict is : {0}'.format(igmp_traffic_dict))
    return igmp_traffic_dict
    

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



def f(log,args):
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






# ********************  END: IGMP Related Methods ******************************** #


            

# *********************  START TRAFFIC RELATED METHODS *****************************#

def getTrafficLossPercentage(log,tgn_hdl,traffic_stream_dict,stream):
    log.info('Inside getTrafficLossPercentage')
    stream_id = traffic_stream_dict[stream]['stream_id']
    stats = tgn_hdl.traffic_stats(stream=stream_id,mode='traffic_item')
 
 
def getTrafficItemStatistics(log,tgn_hdl,traffic_stream_dict,stream):
     
    trf_stats = {}
#    log.info('The value of traffic_stream_dict is : {0}'.format(traffic_stream_dict))
    log.info(banner('Getting the traffic Statistics for Stream : {0}'.format(stream)))
     
    if isinstance(traffic_stream_dict, dict):
        stream_name = traffic_stream_dict[stream]['stream_id']
    else:
        stream_name = traffic_stream_dict
        
    log.info('The value of stream_name is : {0}'.format(stream_name))
        
    stats = tgn_hdl.traffic_stats(stream = stream_name, mode = 'traffic_item')
     
    #log.info(banner('The value of traffic_stats is : {0}'.format(stats)))
     
    tx_stat = stats.traffic_item[stream_name]['tx'].total_pkt_rate
    rx_stat = stats.traffic_item[stream_name]['rx'].total_pkt_rate
     
    trf_stats['tx'] = tx_stat
    trf_stats['rx'] = rx_stat
     
    return trf_stats 

def drawTrafficTable(log,bound_trf_stats,traffic_stream_dict = ''):
    log.info('Inside Draw Traffic Table')
    if traffic_stream_dict:
        log.info('Inside Traffic_stream_dict')
        t = PrettyTable(['Stream Name', 'Actual Tx' , 'Actual Rx', 'Expected','LOSS'])
        for traffic_item in bound_trf_stats:
            destination = len(traffic_stream_dict[traffic_item]['destination'])
            t.add_row([traffic_item,bound_trf_stats[traffic_item]['tx'],bound_trf_stats[traffic_item]['rx'],
                       destination*bound_trf_stats[traffic_item]['tx'], destination*bound_trf_stats[traffic_item]['tx']-bound_trf_stats[traffic_item]['rx']])
    else:
        t = PrettyTable(['Stream Name', 'Actual Tx' , 'Actual Rx','LOSS'])
        for traffic_item in bound_trf_stats:
            if (isinstance(bound_trf_stats[traffic_item]['tx'], str) or isinstance(bound_trf_stats[traffic_item]['tx'], str)):
                t.add_row([traffic_item, bound_trf_stats[traffic_item]['tx'], bound_trf_stats[traffic_item]['rx'], 
                          (bound_trf_stats[traffic_item]['tx'],bound_trf_stats[traffic_item]['rx'])])
            else:
                t.add_row([traffic_item, bound_trf_stats[traffic_item]['tx'], bound_trf_stats[traffic_item]['rx'], 
                      bound_trf_stats[traffic_item]['tx']-bound_trf_stats[traffic_item]['rx']])
    return t

# *********************  END TRAFFIC RELATED METHODS *****************************#

# ******************** START IGMP RELATED METHODS ************************* #

def parseIGMPGroupParams(log,args):
    log.info('Inside parseIGMPGroupParams function')
    log.info('The value of args is : {0}'.format(args))
    arggrammar = {}
    arggrammar['no_of_hosts'] = '-type int'
    arggrammar['ip_addr_start'] = '-type str'
    arggrammar['ip_addr_step'] = '-type str'
    arggrammar['igmp_version'] = '-type str'
    arggrammar['g_filter_mode'] = '-type str'
    arggrammar['source_pool_handle'] = '-type str'
    ns = utils.parserutils_lib.argsToCommandOptions(args,arggrammar,log)
    return ns

def generateIGMPGroupList(log,args):
    igmp_group_dict = {}
    igmp_group_list = []
    igmp_group_config = []
    igmp_v3_group_configs = {}
    ns = parseIGMPGroupParams(log,args)
    log.info('the value of ns is : {0}'.format(ns))
    new_ip_addr = ip_addr = ipaddress.IPv4Address(ns.ip_addr_start)
    igmp_version = ns.igmp_version
    ip_addr_step = ns.ip_addr_step
    for i in range(0,ns.no_of_hosts):
        igmp_group_list.append(new_ip_addr.exploded)
        a = "".join('-mode create -count 1 -group_query 1 -ip_router_alert 1 -igmp_version {0} -general_query 1 -num_groups 1 -ip_addr_start {1} -ip_addr_step {2}'.format(igmp_version,new_ip_addr,ip_addr_step))
        igmp_group_config.append(a)
        new_ip_addr = ipaddress.IPv4Address(new_ip_addr) + int(ipaddress.IPv4Address(ns.ip_addr_step))
        if ns.g_filter_mode:
            igmp_v3_group_configs['g_filter_mode'] = ns.g_filter_mode
        if ns.source_pool_handle:
            igmp_v3_group_configs['source_pool_handle'] = ns.source_pool_handle
    igmp_group_dict['groups']=igmp_group_list
    igmp_group_dict['configs']=igmp_group_config
    igmp_group_dict['v3_configs'] = igmp_v3_group_configs
    return igmp_group_dict


# ******************* START VERIFY VNI STATUS ********************** #

def getVNIStatus(log,hdl,dut,config_dict):
    cfg = 'show nve vni | json'
    out = hdl.execute(cfg)
    json_out = json.loads(out)
    output_parse = json_out['TABLE_nve_vni']['ROW_nve_vni']
    d={}
    for items in output_parse:
        log.info('The value of items is : {0}'.format(items))
        if re.search('L2', items['type']):
            d.setdefault('L2',{})
            d['L2'][items['vni']] = items['vni-state']
        if re.search('L3',items['type']):
            d.setdefault('L3',{})
            d['L3'][items['vni']] = items['vni-state']
    log.info('The Value of VNI_status_dict is {0}'.format(d))
    args = config_dict['scale_config_dict'][dut]['global']['vlan']
    ns = parseScaleVlanParms(log, args)
    log.info('No.of L2 VNIs to be configured  is : {0}'.format(ns.no_of_l2_vlans))
    if not len(d['L2'].keys()) == ns.no_of_l2_vlans:
        log.info('One or more L2 VNI is not configured... Kindly check...The VNIs configured are {0}'.format(list(d.keys())))
        return 0
    if not len(d['L3'].keys()) == ns.no_of_l3_vlans:
        log.info('One or more L2 VNI is not configured... Kindly check...The VNIs configured are {0}'.format(list(d.keys())))
        return 0        
    flag = True
    for k,v in d['L2'].items():
        log.info('The value of k is {0} and value of v is : {1}'.format(k,v))
        if not re.search('Up',v):
            log.info(banner('The following L2 VNis are not up {0}'.format(k)))
            flag = False
    for k,v in d['L3'].items():
        log.info('The value of k is {0} and value of v is : {1}'.format(k,v))
        if not re.search('Up',v):
            log.info(banner('The following L3 VNis are not up {0}'.format(k)))
            flag = False
    if not flag:
        return 0
    if flag:
        return 1

# ******************* END VERIFY VNI STATUS ********************** #

# ******************* START VERIFY BGP eVPN NEIGHBOR ******************** #


def getBGPL2eVPNState(log,hdl,neighbor,dut):
    cfg =  'sh bgp l2vpn evpn neighbors {0} | xml'.format(neighbor)
    out = hdl.execute(cfg)
    s = BeautifulSoup(out)
    bgp_state = s.find('state').string
    log.info('The value of BGP State is : {0}'.format(bgp_state))
    if not re.search('Established',bgp_state,re.I):
        log.info('BGP L2EVPN Session did not come up with neighbor {0}'.format(neighbor))
        return 0
    log.info(banner('DUT -> {0} , Neighbor -> {1},  State :  {2}'.format(dut,neighbor,bgp_state)))
    return 1
    

# ******************* END VERIFY BGP eVPN NEIGHBOR ******************** #


# ******************* START VERIFY BGP mVPN NEIGHBOR ******************** #


def getBGPL2mVPNState(log,hdl,neighbor,dut):
    cfg =  'sh bgp l2vpn evpn neighbors {0}  | xml'.format(neighbor)
    out = hdl.execute(cfg)
    s = BeautifulSoup(out)
    bgp_state = s.find('state').string
    log.info('The value of BGP State is : {0}'.format(bgp_state))
    if not re.search('Established',bgp_state,re.I):
        log.info('BGP MVPN Session did not come up with neighbor {0}'.format(neighbor))
        return 0
    log.info(banner('DUT -> {0} , Neighbor -> {1},  State :  {2}'.format(dut,neighbor,bgp_state)))
    return 1
    

# ******************* END VERIFY BGP mVPN NEIGHBOR ******************** #


# *******************START VERIFY OSPF NEIGHBOR ******************** #


def getV4OSPFNeighborshipState(log,hdl,intf,dut):
    log.info('Getting the OSPF Neighborship state on Interface {0} on Dut {1}'.format(intf,dut))
    cfg = 'show ip ospf neighbor {0} | xml'.format(intf)
    out = hdl.execute(cfg)
    if out:
        s = BeautifulSoup(out)
        ospf_state = s.find('state').string
        log.info(banner('The value of ospf_state is : {0}'.format(ospf_state)))
        if not re.search('FULL',ospf_state,re.I):
            return 0
    return 1


def getV6OSPFNeighborshipState(log,hdl,intf,dut):
    log.info('Getting the OSPFv3 Neighborship state on Interface {0} on Dut {1}'.format(intf,dut))
    cfg = 'sh ipv6 ospfv3 neighbors {0} | xml'.format(intf)
    out = hdl.execute(cfg)
    if out:
        s = BeautifulSoup(out)
        ospf_state = s.find('state').string
        log.info(banner('The value of ospf_state is : {0}'.format(ospf_state)))
        if not re.search('FULL',ospf_state,re.I):
            return 0
    return 1

#********************* END VERIFY OSPF NEIGHBOR ******************** #

# ******************* START OF LOOPBACK CONFIG ********************* #

def parseLoopbackParamsForAnyCastRP(log,args):
    log.info('Inside  parseLoopbackParamsForAnyCastRP function()')
    log.info('Inside parseLoopbackParamsForAnyCastRP.. the value of args is : {0}'.format(args))
    arggrammar = {}
    arggrammar['no_of_loopback'] = '-type int'
    arggrammar['loopback_start'] = '-type int'
    arggrammar['vrf_start_name'] = '-type str'
    arggrammar['ip_addr_start'] = '-type str'
    arggrammar['ip_addr_mask'] = '-type int'
    arggrammar['pim_enable'] = '-type bool'
    arggrammar['ospf_enable'] = '-type bool'
    ns = utils.parserutils_lib.argsToCommandOptions(args,arggrammar,log)
    return ns

def parseLoopbackParams(log,args):
    log.info('Inside  parseLoopbackParams function()')
    log.info('Inside parseLoopbackParams.. the value of args is : {0}'.format(args))
    arggrammar = {}
    arggrammar['no_of_loopback'] = '-type int'
    arggrammar['loopback_start'] = '-type int'
    arggrammar['vrf_start_name'] = '-type str'
    arggrammar['ip_addr_start'] = '-type str'
    arggrammar['ip_addr_mask'] = '-type int'
    arggrammar['pim_enable'] = '-type bool'
    arggrammar['ospf_enable'] = '-type bool'
    ns = utils.parserutils_lib.argsToCommandOptions(args,arggrammar,log)
    return ns

def parseInterfaceConfigDictLoopbackParams(log,args):
    log.info('Inside  parseInterfaceConfigDictLoopbackParsms function()')
    log.info('Inside parseInterfaceConfigDictLoopbackParsms.. the value of args is : {0}'.format(args))
    arggrammar={}
    arggrammar['ipv4_addr']='-type str'
    arggrammar['ipv6_addr']='-type str'
    arggrammar['ipv4_prf_len']='-type str'
    arggrammar['ipv6_prf_len']='-type str'
    arggrammar['vrf']='-type str'
    arggrammar['ipv4_addr_sec']='-type str'
    arggrammar['ipv4_prf_len_sec']='-type str'
    arggrammar['tag'] = '-type int'
    ns = utils.parserutils_lib.argsToCommandOptions(args,arggrammar,log)
    return ns

def parseOspfRouterId(log,args):
    log.info('Inside parseOspfRouterId function()')
    log.info('Inside parseOspfRouterId.. the value of args is : {0}'.format(args))
    arggrammar = {}
    arggrammar['ospf_process'] = '-type str'
    arggrammar['no_of_vrf'] = '-type int'
    arggrammar['vrf_start_name'] = '-type str'
    arggrammar['router_id_start'] = '-type str'
    arggrammar['router_id_mask'] = '-type str'
    arggrammar['redistribute_direct'] = '-type bool'
    arggrammar['route_map_direct'] = '-type str'
    ns = utils.parserutils_lib.argsToCommandOptions(args,arggrammar,log)
    return ns    

def cfgOspfRouterID(dut,hdl,ospf_router_id_args,log):
    ns = parseOspfRouterId(log,ospf_router_id_args)
    log.info('The value of ns is : {0}'.format(ns))
    if ns.vrf_start_name:
        vrf_name_list = generateVRFlist(ns.vrf_start_name,ns.no_of_vrf)
    if ns.router_id_start:
        ip_addr_list = ipaddrgen(ns.no_of_vrf,ns.router_id_start,ns.router_id_mask)
    for i in range(0,ns.no_of_vrf):
        cfg = ''
        if hasattr(ns,'ospf_process') and ns.ospf_process:
            cfg += 'router ospf {0} \n'.format(ns.ospf_process)
        if hasattr(ns, 'vrf_start_name') and ns.vrf_start_name:
            cfg += 'vrf {0}'.format(vrf_name_list[i]) + '\n'
        if hasattr(ns, 'router_id_start') and ns.router_id_start:
            cfg += 'router-id {0}'.format(ip_addr_list[i]) + '\n'
        if hasattr(ns, 'redistribute_direct') and ns.redistribute_direct:
            if hasattr(ns, 'route_map_direct') and ns.route_map_direct:
                cfg += 'redistribute direct route-map {0}'.format(ns.route_map_direct) + '\n'
        log.info('The value of cfg is : {0}'.format(cfg))
        hdl.configure(cfg) 
    return 1   
     
def cfgLoopbackIntf(dut,hdl,loopback_config_dict,log):
    ns = parseLoopbackParams(log,loopback_config_dict)
    log.info('The value of ns is : {0}'.format(ns))
    if ns.vrf_start_name:
        vrf_name_list = generateVRFlist(ns.vrf_start_name,ns.no_of_loopback)
    if ns.ip_addr_start:
        ip_addr_list = ipaddrgen(ns.no_of_loopback,ns.ip_addr_start,ns.ip_addr_mask)
    if not ns.loopback_start:
        ns.loopback_start = 1
    for i, j in enumerate(range(ns.loopback_start,ns.no_of_loopback+ns.loopback_start)):
        cfg = ''
        cfg += '''no interface loopback {0}
                  interface loopback {0}
                  no shutdown'''.format(j) + '\n'
        if hasattr(ns, 'vrf_start_name') and ns.vrf_start_name:
            cfg += 'vrf member {0}'.format(vrf_name_list[i]) + '\n'
        if hasattr(ns, 'ip_addr_start') and ns.ip_addr_start:
            cfg += 'ip address {0}/{1}'.format(ip_addr_list[i],ns.ip_addr_mask) + '\n'
        if ns.pim_enable:
            cfg += 'ip pim sparse-mode' + '\n'
        if ns.ospf_enable:
            cfg += 'ip router ospf vxlan area 0 ' + '\n'
        hdl.configure(cfg) 
    return 1       

def cfgLoopbackIntfForAnyCastRP(dut,hdl,loopback_config_dict,log):
    ns = parseLoopbackParamsForAnyCastRP(log,loopback_config_dict)
    log.info('The value of ns is : {0}'.format(ns))
    if ns.vrf_start_name:
        vrf_name_list = generateVRFlist(ns.vrf_start_name,ns.no_of_loopback)
    if ns.ip_addr_start:
        ip_addr_list = []
        ip_addr_list.append(ns.ip_addr_start)
        ip_addr_step = '0.0.0.3'
        ip_addr = ns.ip_addr_start
        for i in range(1,ns.no_of_loopback):
            ip_addr = ipaddress.IPv4Address(ip_addr) + int(ipaddress.IPv4Address(ip_addr_step))
            ip_addr_list.append(ip_addr)
        log.info(banner('The value of ip_addr_list is : {0}'.format(ip_addr_list)))
    for i in range(0,ns.no_of_loopback):
        cfg = ''
        cfg += '''interface loopback {0}
                  no shutdown'''.format(ns.loopback_start+i) + '\n'
        if hasattr(ns, 'vrf_start_name') and ns.vrf_start_name:
            cfg += 'vrf member {0}'.format(vrf_name_list[i]) + '\n'
        if hasattr(ns, 'ip_addr_start') and ns.ip_addr_start:
            cfg += 'ip address {0}/{1}'.format(ip_addr_list[i],ns.ip_addr_mask) + '\n'
        if ns.pim_enable:
            cfg += 'ip pim sparse-mode' + '\n'
        if ns.ospf_enable:
            cfg += 'ip router ospf vxlan area 0 ' + '\n'
        hdl.configure(cfg) 
    return 1       

# ********************* PIM ANYCAST-RP-SET-CONFIG **********************#

def parsePimAnyCastRPSetParams(log,args):
    log.info('Inside  parsePimAnyCastRPSetParams function()')
    log.info('Inside parsePimAnyCastRPSetParams.. the value of args is : {0}'.format(args))
    arggrammar = {}
    arggrammar['no_of_vrf'] = '-type int'
    arggrammar['rp_addr_start'] = '-type str'
    arggrammar['rp_addr_mask'] = '-type int'
    arggrammar['rp_set_start'] = '-type str'
    arggrammar['rp_set_addr_mask'] = '-type int'
    arggrammar['no_of_rp_set'] = '-type int'
    arggrammar['vrf_start_name'] = '-type str'
    ns = utils.parserutils_lib.argsToCommandOptions(args,arggrammar,log)
    return ns

def cfgPimAnyCastRPSet(dut,hdl,cfg_dict,log):
    ns = parsePimAnyCastRPSetParams(log,cfg_dict)
    log.info('The value of ns is : {0}'.format(ns))
    if ns.vrf_start_name:
        vrf_name_list = generateVRFlist(ns.vrf_start_name,ns.no_of_vrf)
    if ns.rp_addr_start:
        ip_addr_list = ipaddrgen(ns.no_of_vrf,ns.rp_addr_start,ns.rp_addr_mask)
    if ns.rp_set_start:
        rp_set_list = []
        for k in range(0,ns.no_of_vrf):
            rp_set_inner = []
            for i in range(0,ns.no_of_rp_set):
                if k == 0 and i == 0:
                    rp_set_inner.append(ns.rp_set_start)
                    ip_addr = ns.rp_set_start
                else:
                    ip_addr = ipaddress.IPv4Address(ip_addr) + int(ipaddress.IPv4Address('0.0.0.1'))
                    rp_set_inner.append(ip_addr.exploded)
            rp_set_list.append(rp_set_inner)
        
        log.info(banner('The value of rp_set_list is : {0}'.format(rp_set_list)))
    
    for i in range(0,ns.no_of_vrf):
        cfg = ''
        if hasattr(ns, 'vrf_start_name') and ns.vrf_start_name:
            cfg += 'vrf context {0}'.format(vrf_name_list[i]) + '\n'
        if hasattr(ns, 'rp_addr_start') and ns.rp_addr_start:
            new_cfg = 'ip pim anycast-rp {0} '.format(ip_addr_list[i])
        if ns.rp_set_start:
            for j in rp_set_list[i]:
                new_cfg_1 = new_cfg + j + '\n'
                cfg += new_cfg_1
        log.info('The value of cfg is : {0}'.format(cfg))
        hdl.configure(cfg)     
    
        
    

# ******************* START OF LOOPBACK CONFIG ********************* #

# ******************* START Sub-Interface Configs ****************** #

def parseSubInterfaceParams(log,args):
    log.info('Inside  parseSubInterfaceParams function()')
    log.info('Inside parseSubInterfaceParams.. the value of args is : {0}'.format(args))
    arggrammar = {}
    arggrammar['no_of_sub_if'] = '-type int'
    arggrammar['encapsulation_start'] = '-type int'
    arggrammar['shutdown'] = '-type bool -default no shut'
    arggrammar['vrf_start_name'] = '-type str'
    arggrammar['ip_addr_start'] = '-type str'
    arggrammar['ip_addr_mask'] = '-type str'
    arggrammar['ipv6_addr_start'] = '-type str'
    arggrammar['ipv6_addr_mask'] = '-type int'
    arggrammar['ospf_enable'] = '-type bool'
    arggrammar['pim_enable'] = '-type bool'
    ns = utils.parserutils_lib.argsToCommandOptions(args,arggrammar,log)
    return ns

def cfgL3SubIf(dut,hdl,sub_intf_config_dict,log,alias_dict):
    for link in list(sub_intf_config_dict.keys()):
        log.info('The value of link is : {0}'.format(link))
        args = sub_intf_config_dict[link]
        log.info('The value of args is : {0}'.format(args))
        ns = parseSubInterfaceParams(log,args)
        log.info(banner('The value of ns is : {0}'.format(ns)))

        if not re.search('uut',link):
            interface = link
        else:
            interface = alias_dict[dut][link]
        log.info('The Final value of link is : {0}'.format(interface))

        if ns.vrf_start_name:
            vrf_list = generateVRFlist(ns.vrf_start_name,ns.no_of_sub_if)
        if ns.ip_addr_start:
            ip_addr_list = ipaddrgen(ns.no_of_sub_if,ns.ip_addr_start,ns.ip_addr_mask)
        if ns.ipv6_addr_start:
            ipv6_addr_list = ipv6addrgen(ns.no_of_sub_if,ns.ipv6_addr_start,ns.ipv6_addr_mask)
        for i in range(0,ns.no_of_sub_if):
            cfg = ''
            if hasattr(ns, 'encapsulation_start') and ns.encapsulation_start:
                cfg += '''interface {0}.{1}
                          encapsulation dot1q {1}
                          no shutdown'''.format(interface,ns.encapsulation_start+i) + '\n'
            if hasattr(ns,'vrf_start_name') and ns.vrf_start_name:
                cfg += 'vrf member {0}'.format(vrf_list[i]) + '\n'
            if hasattr(ns, 'ip_addr_start') and ns.ip_addr_start:
                cfg += 'ip address {0}/{1}'.format(ip_addr_list[i],ns.ip_addr_mask) + '\n'
            if hasattr(ns, 'ipv6_addr_start') and ns.ipv6_addr_start:
                cfg += 'ipv6 address {0}/{1}'.format(ipv6_addr_list[i],ns.ipv6_addr_mask) + '\n'
            if ns.ospf_enable:
                process_id = 'vxlan'
                cfg += '''ip router ospf {0} area 0
                          ip ospf hello-interval 1
                          ip ospf dead-interval 4'''.format(process_id) + '\n'
            if ns.pim_enable:
                cfg += 'ip pim sparse-mode' + '\n'
        
            hdl.configure(cfg)
    return 1
            
# ******************** END OF SUB-INTERFACE CONFIGS ********************* #
    
# ******************* START NVE CONFIGS ****************** #

def parseNVEParams(log,args):
    log.info('Inside the parseNVEParams function()')
    log.info('Inside parseNVEParams.. the value of args is : {0}'.format(args))
    arggrammar = {}
    arggrammar['host_reachability_protocol_bgp'] = '-type bool'
    arggrammar['shutdown'] = '-type bool'
#    arggrammar['shutdown'] = '-type bool -default no shut'
    arggrammar['advertise_virtual_rmac'] = '-type bool'
    arggrammar['source_interface'] = '-type str'
    arggrammar['global_suppress_arp'] = '-type bool'
    arggrammar['anycast'] = '-type str'
    arggrammar['source_interface_hold_down_time'] = '-type int'
    arggrammar['multisite_source_interface'] = '-type str'
    arggrammar['no_of_l2_vni'] = '-type int'
    arggrammar['l2_vni_start'] = '-type int'
    arggrammar['evpn_ir'] = '-type bool'
    arggrammar['static_ir'] = '-type bool'
    arggrammar['peer_ip'] = '-type str'
    arggrammar['evpn_mcast'] = '-type bool'
    arggrammar['multisite_ir'] = '-type bool'
    arggrammar['l2_vni_mcast'] = '-type str'
    arggrammar['l2_vni_mcast_mask'] = '-type int'
    arggrammar['no_of_l3_vni'] = '-type int'
    arggrammar['l3_vni_start'] = '-type int'
    arggrammar['trm_mcast_group_start'] = '-type str'
    arggrammar['trm_mcast_group_start_mask'] = '-type int'
    arggrammar['supress_arp'] = '-type bool'
    arggrammar['multisite_ir_optimized'] = '-type bool' 
    ns = utils.parserutils_lib.argsToCommandOptions(args,arggrammar,log)
    return ns

def cfgNveGlobal(dut,hdl,config_dict,log):
    ns = parseNVEParams(log,config_dict)
    log.info(banner('The value of ns is : {0}'.format(ns)))
    cfg = 'feature nv overlay' + '\n'
    hdl.configure(cfg)
    cfg = ''
    if hasattr(ns,'host_reachability_protocol_bgp') and ns.host_reachability_protocol_bgp:
        cfg += '''interface nve1
                  no shutdown
                  host-reachability protocol bgp''' + '\n'
    else:
        cfg += '''interface nve1
                  no shutdown''' + '\n'
    if hasattr(ns, 'shutdown') and ns.shutdown:
        cfg += 'shutdown' + '\n'
    if hasattr(ns, 'advertise_virtual_rmac') and ns.advertise_virtual_rmac:
        cfg += 'advertise virtual-rmac' + '\n'
    if hasattr(ns, 'global_suppress_arp') and ns.global_suppress_arp:
        cfg += 'global suppress-arp' + '\n'    
    if hasattr(ns, 'source_interface') and hasattr(ns, 'anycast') and ns.anycast:
            cfg += 'source-interface {0} anycast {1}'.format(ns.source_interface,ns.anycast) + '\n'
    if not ns.anycast:
            cfg += 'source-interface {0}'.format(ns.source_interface) + '\n'
    if hasattr(ns,'multisite_source_interface') and ns.multisite_source_interface:
        cfg += 'multisite border-gateway interface {0}'.format(ns.multisite_source_interface) + '\n'
    if hasattr(ns, 'source_interface_hold_down_time') and ns.source_interface_hold_down_time:
        cfg += 'source-interface hold-down-time {0}'.format(ns.source_interface_hold_down_time) + '\n'
    hdl.configure(cfg)
    
    return 1


def cfgL2VNIOnNVeIntf(dut,hdl,args,log):
    ns = parseNVEParams(log,args)
    log.info(banner('The value of ns is : {0}'.format(ns)))
    for i in range(ns.no_of_l2_vni):
        if hasattr(ns, 'evpn_ir') and ns.evpn_ir:
            cfg = '''interface nve 1
                     member vni {0}
                     ingress-replication protocol bgp'''.format(ns.l2_vni_start+i) + '\n'
            if hasattr(ns, 'supress_arp') and ns.supress_arp:
                cfg += 'supress-arp' + '\n'
            if hasattr(ns, 'multisite_ir') and ns.multisite_ir:
                cfg += 'multisite ingress-replication' + '\n'

        elif hasattr(ns,'static_ir') and ns.static_ir:
            cfg = '''interface nve1
                     member vni {0}
                     ingress-replication protocol static
                     peer-ip {1}'''.format(ns.l2_vni_start+i,ns.peer_ip) + '\n'
        elif hasattr(ns,'evpn_mcast') and ns.evpn_mcast:
            if hasattr(ns, 'l2_vni_mcast') and ns.l2_vni_mcast:
                mcast_grp_list = ipaddrgen(ns.no_of_l2_vni, ns.l2_vni_mcast, ns.l2_vni_mcast_mask)
                cfg = '''interface nve1
                         member vni {0}
                         mcast-group {1}'''.format(int(ns.l2_vni_start+i),mcast_grp_list[i]) + '\n'
            if hasattr(ns, 'supress_arp') and ns.supress_arp:
                cfg += 'supress-arp' + '\n'
            if hasattr(ns, 'multisite_ir') and ns.multisite_ir:
                cfg += 'multisite ingress-replication' + '\n'
        hdl.configure(cfg)
        
    return 1

def cfgL3VNIOnNVeIntf(dut,hdl,config_dict,log):
    ns = parseNVEParams(log,config_dict)
    log.info(banner('The value of ns is : {0}'.format(ns)))
    for i in range(ns.no_of_l3_vni):
        if hasattr(ns, 'evpn_ir') and ns.evpn_ir:
            cfg = '''interface nve 1
                      member vni {0} associate-vrf'''.format(ns.l3_vni_start+i) + '\n'
        if hasattr(ns, 'evpn_mcast') and ns.evpn_mcast:
            if hasattr(ns, 'trm_mcast_group_start') and ns.trm_mcast_group_start:
                trm_mcast_group_list = ipaddrgen(ns.no_of_l3_vni, ns.trm_mcast_group_start, ns.trm_mcast_group_start_mask)
                cfg = '''interface nve 1
                         member vni {0} associate-vrf
                         mcast-group {1}'''.format(int(ns.l3_vni_start+i),trm_mcast_group_list[i]) + '\n'
            if hasattr(ns,'multisite_ir_optimized') and ns.multisite_ir_optimized:
                cfg += 'multisite ingress-replication optimized \n'
        hdl.configure(cfg)
    return 1

# ******************* END NVE CONFIGS ****************** #
    
# ******************* START EVPN CONFIGS ****************** #


def parseScaleEVPNConfigs(log,args):
    log.info('Inside the parseScaleEVPNConfigs function()')
    log.info('Inside parseScaleEVPNConfigs.. the value of args is : {0}'.format(args))
    arggrammar = {}
    arggrammar['no_of_vnis'] = '-type int'
    arggrammar['l2_vni_start'] = '-type int'
    arggrammar['rd'] = '-type str'
    arggrammar['route_target_import_list'] = '-type str'
    arggrammar['route_target_export_list'] = '-type str' 
    
    ns = utils.parserutils_lib.argsToCommandOptions(args,arggrammar,log)
    return ns

def generateEvpnDict(log,config_dict,vtep_dict):
    evpn_config_dict = {}
    for dut in vtep_dict:
        evpn_config_dict[dut] = {}
        args = config_dict[dut]['evpn']
        ns = parseScaleEVPNConfigs(log,args)
        log.info('The value of ns is : {0}'.format(ns))
        for i in range(0,ns.no_of_vnis):
            evpn_config_dict[dut].setdefault('vni',{})
#             if not isEmpty(evpn_config_dict[dut]):
#                 evpn_config_dict[dut]['vni'] = {}
            v = ns.l2_vni_start + i
            evpn_config_dict[dut]['vni'][v]={}
            evpn_config_dict[dut]['vni'][v]['layer']='l2'
            evpn_config_dict[dut]['vni'][v]['rd'] = ns.rd
            evpn_config_dict[dut]['vni'][v]['route_target_import_list'] = ns.route_target_import_list
            evpn_config_dict[dut]['vni'][v]['route_target_export_list'] =   ns.route_target_export_list
            a = " ".join(['-{} {}'.format(k, v) for k,v in evpn_config_dict[dut]['vni'][v].items()])
            evpn_config_dict[dut]['vni'][v] = a
        
    return evpn_config_dict

# ******************* END EVPN CONFIGS ****************** #

# ******************* START SVI CONFIGS ****************** #

def parseScaleSVIParams(log,args):

    arggrammar = {}
    arggrammar['no_of_l2_vni_svi'] = '-type int'
    arggrammar['l2_vni_svi_start'] = '-type int'
    arggrammar['l2_vni_svi_ipv4_start'] = '-type str'
    arggrammar['l2_vni_svi_ipv4_mask'] = '-type int'
    arggrammar['l2_vni_svi_ipv6_start'] = '-type str'
    arggrammar['l2_vni_svi_ipv6_mask'] = '-type int'
    arggrammar['no_of_l3_vni_svi'] = '-type int'
    arggrammar['l3_vni_svi_start'] = '-type int'
    arggrammar['l3_vni_svi_ipv4_start'] = '-type str'
    arggrammar['l3_vni_svi_ipv6_start'] = '-type str'                
    arggrammar['mtu'] = '-type int'
    arggrammar['anycast_gw'] = '-type bool'
    arggrammar['pim_enable'] = '-type bool'
    arggrammar['ospf_enable'] = '-type bool'
    arggrammar['pim_neighbor_policy'] = '-type str' 
    arggrammar['no_of_l2_vni_svi_per_vrf'] = '-type int'
    arggrammar['shutdown'] = '-type bool'
    arggrammar['vrf_start_name'] = '-type str'
    arggrammar['no_of_svi'] = '-type int'
    arggrammar['svi_ipv4_addr'] = '-type str'
    arggrammar['svi_ipv4_mask'] = '-type int'
    arggrammar['svi_start'] = '-type int'
    arggrammar['hsrp'] = '-type bool'
    arggrammar['hsrp_version'] = '-type int'
    arggrammar['hsrp_preempt'] = '-type bool'
    arggrammar['hsrp_group_start'] = '-type int'
    arggrammar['hsrp_vip_start'] = '-type str'
    ns = utils.parserutils_lib.argsToCommandOptions(args,arggrammar,log)
    return ns

def configureSVIs(log,hdl,args):
    cfg = 'feature interface-vlan \n'
    hdl.configure(cfg)

    ns = parseScaleSVIParams(log,args)
    
    if ns.hsrp:
        cfg = 'feature hsrp \n'
        hdl.configure(cfg)
    log.info('The value of ns is : {0}'.format(ns))
    if ns.no_of_l2_vni_svi:
        vrf_count = int(ns.no_of_l2_vni_svi / ns.no_of_l2_vni_svi_per_vrf)
        ip_addr_list = ipaddrgen(ns.no_of_l2_vni_svi,ns.l2_vni_svi_ipv4_start,ns.l2_vni_svi_ipv4_mask)
        ipv6_addr_list = ipv6addrgen(ns.no_of_l2_vni_svi,ns.l2_vni_svi_ipv6_start,ns.l2_vni_svi_ipv6_mask)
        vrf_name_list = generateVRFlist(ns.vrf_start_name,vrf_count)
        k = 0
        l = 1
        for i,j in enumerate(range(ns.l2_vni_svi_start,ns.l2_vni_svi_start+ns.no_of_l2_vni_svi)):
            log.info('The value of k is {0}'.format(k))
            log.info('The value of vrf_name_list[k] is : {0}'.format(vrf_name_list[k]))
            if(l<=ns.no_of_l2_vni_svi_per_vrf):
                cfg =  '''int vlan {0}
                          vrf member {1}
                          ip address {2}/{3}
                          ipv6 address {4}/{5}
                        '''.format(j,vrf_name_list[k],ip_addr_list[i],ns.l2_vni_svi_ipv4_mask,ipv6_addr_list[i],ns.l2_vni_svi_ipv6_mask)
                if not ns.shutdown:
                    cfg += 'no shutdown \n'
                if ns.mtu:
                    cfg += 'mtu {0} \n'.format(ns.mtu)
                if ns.pim_enable:
                    cfg += 'ip pim sparse-mode \n'
                if ns.pim_neighbor_policy:
                    cfg += 'ip pim neighbor-policy ' + ns.pim_neighbor_policy + '\n'
                if ns.anycast_gw:
                    cfg += 'fabric forwarding mode anycast-gateway \n'
            if(l == ns.no_of_l2_vni_svi_per_vrf):
                k += 1
                l = 0
            l = l + 1
            hdl.configure(cfg)
            
    if ns.l3_vni_svi_start:
        vrf_name_list = generateVRFlist(ns.vrf_start_name,ns.no_of_l3_vni_svi)
        for i,j in enumerate(range(ns.l3_vni_svi_start,ns.l3_vni_svi_start+ns.no_of_l3_vni_svi)):
            cfg = '''int vlan {0}
                     vrf member {1}
                     '''.format(j,vrf_name_list[i])
            if not ns.shutdown:
                cfg += 'no shutdown \n'
            if ns.l3_vni_svi_ipv4_start:
                cfg += 'ip forward \n'
            if ns.l3_vni_svi_ipv6_start:
                cfg += 'ipv6 forward \n'
            if ns.mtu:
                cfg += 'mtu {0} \n'.format(ns.mtu)
            if ns.pim_enable:
                cfg += 'ip pim sparse-mode \n'                        
            hdl.configure(cfg)        
        
        
    if ns.no_of_svi:
        if ns.vrf_start_name:
            vrf_name_list = generateVRFlist(ns.vrf_start_name,ns.no_of_svi)
        ip_addr_list = ipaddrgen(ns.no_of_svi,ns.svi_ipv4_addr,ns.svi_ipv4_mask)
        if ns.hsrp_vip_start:
            vip_list = ipaddrgen(ns.no_of_svi,ns.hsrp_vip_start,ns.svi_ipv4_mask)
        for j,i in enumerate(range(ns.svi_start,ns.svi_start + ns.no_of_svi)):
            cfg = '''interface vlan {0}
                     no shutdown'''.format(ns.svi_start+j) + '\n'
            if hasattr(ns, 'vrf_start_name') and ns.vrf_start_name:
                cfg += 'vrf member {0}'.format(vrf_name_list[j]) + '\n'
            if hasattr(ns, 'svi_ipv4_addr') and ns.svi_ipv4_addr:
                cfg += 'ip address {0}/{1}'.format(ip_addr_list[j],ns.svi_ipv4_mask) + '\n'
            if ns.ospf_enable:
                cfg += 'ip router ospf vxlan area 0' + '\n'
            if ns.pim_enable:
                cfg += 'ip pim sparse-mode \n'
            if ns.hsrp:
                if hasattr(ns,'hsrp_version') and ns.hsrp_version:
                    cfg+= 'hsrp version {0}'.format(ns.hsrp_version) + '\n'     
                if hasattr(ns,'hsrp_group_start') and ns.hsrp_group_start:
                    cfg += 'hsrp {0} ipv4'.format(ns.hsrp_group_start + j) + '\n'
                    if hasattr(ns, 'hsrp_preempt') and ns.hsrp_preempt:
                        cfg += 'preempt' + '\n'
                    if hasattr(ns, 'hsrp_vip_start') and ns.hsrp_vip_start:
                        cfg += 'ip {0}'.format(vip_list[j]) + '\n'
            hdl.configure(cfg)
            

# ******************* END SVI CONFIGS *************#

# ******************* START VRF CONFIGS *************#

def parseScaleVRFParams(log,args):
    arggrammar = {}
    arggrammar['no_of_vrf'] = '-type int'
    arggrammar['vrf_start'] = '-type str'
    arggrammar['vrf_vni_start'] = '-type int '
    arggrammar['pim_rp_addr_start'] = '-type str'
    arggrammar['pim_rp_addr_mask'] = '-type int '
    arggrammar['pim_group_list'] = '-type str'
    arggrammar['rd'] = '-type str'
    arggrammar['v4_af'] = '-type bool'
    arggrammar['v4_af_rt_both'] = '-type str'
    arggrammar['v4_af_rt_both_evpn'] = '-type str'
    arggrammar['v4_af_rt_both_mvpn'] = '-type str'
    arggrammar['v6_af'] = '-type bool'
    arggrammar['v6_af_rt_both'] = '-type str'
    arggrammar['v6_af_rt_both_evpn'] = '-type str'
    arggrammar['v6_af_rt_both_mvpn'] = '-type str'
    ns = utils.parserutils_lib.argsToCommandOptions(args,arggrammar,log)
    log.info('The Value of ns is : {0}'.format(ns))
    return ns

def configureVRFs(log,hdl,args):
    ns = parseScaleVRFParams(log,args)
    if ns.pim_rp_addr_start:
        pim_rp_addr_list = ipaddrgen(ns.no_of_vrf,ns.pim_rp_addr_start,ns.pim_rp_addr_mask)
        log.info('The vale of pim_rp_addr_list is: {0}'.format(pim_rp_addr_list))
    for i in range(0,ns.no_of_vrf):
        cfg = ''
        if hasattr (ns,'vrf_start') and ns.vrf_start:
            # a = ns.vrf_start.rsplit('-',1)
            # log.info('The value of a is : {0}'.format(a))
            cfg = 'vrf context {0}'.format(ns.vrf_start.rsplit('-',1)[0])+ '-' + "{:03d}".format(int(ns.vrf_start.rsplit('-',1)[1])+i) + '\n'
            log.info('The value of cfg is : {0}'.format(cfg))
        if ns.vrf_vni_start:
            cfg += 'vni' + ' ' + str(ns.vrf_vni_start+i) + '\n'
        if hasattr (ns,'rd') and ns.rd:
            cfg += 'rd '+ ns.rd + '\n'
        if hasattr (ns,'pim_rp_addr_start') and ns.pim_rp_addr_start:
            cfg += 'ip pim rp-address '+ pim_rp_addr_list[i] + ' '
            if hasattr(ns,'pim_group_list') and ns.pim_group_list:
                cfg += 'group-list ' + ns.pim_group_list + '\n'
            else:
                cfg += '\n'
        if hasattr (ns,'v4_af') and ns.v4_af:
            cfg += 'address-family ipv4 unicast' + '\n'
        if hasattr (ns,'v4_af_rt_both') and ns.v4_af_rt_both:
            cfg += 'route-target both ' + ns.v4_af_rt_both + '\n'
        if hasattr (ns,'v4_af_rt_both_evpn') and ns.v4_af_rt_both_evpn:
            cfg += 'route-target both ' + ns.v4_af_rt_both_evpn + ' evpn' + '\n' 
        if hasattr (ns,'v4_af_rt_both_mvpn') and ns.v4_af_rt_both_mvpn:
            cfg += 'route-target both ' + ns.v4_af_rt_both_mvpn + ' mvpn' + '\n' 
        if hasattr (ns,'v6_af') and ns.v6_af:
            cfg += 'address-family ipv6 unicast' + '\n'
        if hasattr (ns,'v6_af_rt_both') and ns.v6_af_rt_both:
            cfg += 'route-target both ' + ns.v6_af_rt_both + '\n'
        if hasattr (ns,'v6_af_rt_both_evpn') and ns.v6_af_rt_both_evpn:
            cfg += 'route-target both ' + ns.v6_af_rt_both_evpn + ' evpn' + '\n'      
        if hasattr (ns,'v6_af_rt_both_mvpn') and ns.v6_af_rt_both_mvpn:
            cfg += 'route-target both ' + ns.v6_af_rt_both_mvpn + ' mvpn' + '\n' 
        hdl.configure(cfg)     
        
# ******************* END VRF CONFIGS *************#



# ******************* START VLAN CONFIGS *************#

def parseScaleVlanParms(log,args):
    arggrammar = {}
    arggrammar['no_of_l2_vlans'] = '-type int'
    arggrammar['l2_vlan_start'] = '-type int'
    arggrammar['l2_vni_start'] = '-type int'
    arggrammar['no_of_l3_vlans'] = '-type int'
    arggrammar['l3_vlan_start'] = '-type int'
    arggrammar['l3_vni_start'] = '-type int'
    arggrammar['l2_vlan_name'] = '-type str'
    arggrammar['l2_vlan_shutdown'] = '-type bool -default False'
    arggrammar['l3_vlan_name'] = '-type str'
    arggrammar['l3_vlan_shutdown'] = '-type bool -default False'
    
    ns = utils.parserutils_lib.argsToCommandOptions(args,arggrammar,log)
    return ns

def configureVlans(log,hdl,args):
    ns = parseScaleVlanParms(log,args)
    log.info('The value of ns here is : {0}'.format(ns))   
    cfg = 'feature vn-segment-vlan-based \n'
    spanning_tree_mode_flag = 1
    if ns.no_of_l3_vlans and ns.no_of_l2_vlans:
        for i in mychain(((ns.l2_vlan_start,ns.no_of_l2_vlans,ns.l2_vni_start),(ns.l3_vlan_start,ns.no_of_l3_vlans,ns.l3_vni_start))):
            cfg = i
            cfg += 'exit \n'
            hdl.configure(cfg)
    elif ns.no_of_l2_vlans:
        log.info('Inside the ELIF block')
        
        if ns.no_of_l2_vlans > 507 and spanning_tree_mode_flag:
            hdl.configure('spanning-tree mode mst')
            spanning_tree_mode_flag = 0
        
        if ns.l2_vni_start:
            for i,j in enumerate(range(ns.l2_vlan_start,ns.no_of_l2_vlans+ns.l2_vlan_start)):
                vni = ns.l2_vni_start + i
                cfg = '''vlan {0}
                         no vn-segment
                         vn-segment {1}
                         exit'''.format(j,vni)
                hdl.configure(cfg)
        else:
            for i in range(ns.l2_vlan_start,ns.no_of_l2_vlans+ns.l2_vlan_start):
                cfg = '''vlan {0}
                      exit'''.format(i)
                hdl.configure(cfg)


# ******************* END VLAN CONFIGS *************#

# ******************* START BGP GLOBALS ********************#

def parseGlobalBGPConfigs(log, args):
    arggrammar = {}
    arggrammar['no_of_vrf'] = '-type int'
    arggrammar['vrf_start'] = '-type str'
    arggrammar['af_v4_enable'] = '-type str'
    arggrammar['v4_networks'] = '-type str'
    arggrammar['src_network_ip'] = '-type str'
    arggrammar['src_network_mask'] = '-type int'
    arggrammar['rp_network_ip'] = '-type str'
    arggrammar['rp_network_mask'] = '-type int'
    arggrammar['af_v6_enable'] = '-type str'
    arggrammar['advertise_l2vpn_evpn'] = '-type bool'
    arggrammar['max_path_ebgp'] = '-type int'
    arggrammar['max_path_ibgp'] = '-type int'
    arggrammar['neighbor_1_start_ip'] = '-type str'
    arggrammar['neighbor_ip_mask'] = '-type int'
    arggrammar['neighbor_2_start_ip'] = '-type str'
    arggrammar['neighbor_3_start_ip'] = '-type str'
    arggrammar['vrf_router_id'] = '-type str'
    arggrammar['vrf_router_id_mask'] = '-type int'
    arggrammar['neighbor_1_start_ipv6'] = '-type str'
    arggrammar['neighbor_ipv6_mask'] = '-type int'
    arggrammar['neighbor_2_start_ipv6'] = '-type str'
    arggrammar['neighbor_3_start_ipv6'] = '-type str'
    arggrammar['neighbor_v4_afn'] = '-type bool'
    arggrammar['neighbor_v6_afn'] = '-type bool'
    arggrammar['neighbor_1_remote_as'] = '-type int'
    arggrammar['neighbor_2_remote_as'] = '-type int'
    arggrammar['neighbor_3_remote_as'] = '-type int'
    arggrammar['af_v4_redistribute_type'] = '-type str'
    arggrammar['af_v4_redistribute_rpm'] = '-type str'
    arggrammar['l2vpn_redistribute_type'] = '-type str'
    arggrammar['l2vpn_v6_redistribute_type'] = '-type str'
    arggrammar['l2vpn_route_map'] = '-type str'
    ns = utils.parserutils_lib.argsToCommandOptions(args,arggrammar,log)
    return ns 

def cfgGlobalBGPParameters(log,hdl,args,as_no):
    ns = parseGlobalBGPConfigs(log,args)
    log.info('The value of ns inside is parseGlobalBGPConfigs : {0}'.format(ns))
    if hasattr(ns,'vrf_start') and ns.vrf_start:
        log.info('Inside vrf_start...')
        vrf_name_list = generateVRFlist(ns.vrf_start,ns.no_of_vrf)
        log.info('the value of vrf_name_list is : {0}'.format(vrf_name_list))
    if hasattr(ns, 'src_network_ip') and ns.src_network_ip:
        src_ip_network_list = ipaddrgen(ns.no_of_vrf, ns.src_network_ip, ns.src_network_mask)
        log.info('the value of src_ip_network_list is : {0}'.format(src_ip_network_list))
    if hasattr(ns, 'rp_network_ip') and ns.rp_network_ip:
        rp_ip_network_list = ipaddrgen(ns.no_of_vrf, ns.rp_network_ip, ns.rp_network_mask)
        log.info('the value of rp_ip_network_list is : {0}'.format(rp_ip_network_list))
    if hasattr(ns, 'neighbor_1_start_ip') and ns.neighbor_1_start_ip:
        neighbor_1_ip_list = ipaddrgen(ns.no_of_vrf, ns.neighbor_1_start_ip, ns.neighbor_ip_mask)
        log.info('the value of neighbor_1_ip_list is : {0}'.format(neighbor_1_ip_list))
    if hasattr(ns, 'neighbor_2_start_ip') and ns.neighbor_2_start_ip:
        neighbor_2_ip_list = ipaddrgen(ns.no_of_vrf, ns.neighbor_2_start_ip, ns.neighbor_ip_mask)
        log.info('the value of neighbor_2_ip_list is : {0}'.format(neighbor_2_ip_list))
    if hasattr(ns, 'neighbor_3_start_ip') and ns.neighbor_3_start_ip:
        neighbor_3_ip_list = ipaddrgen(ns.no_of_vrf, ns.neighbor_3_start_ip, ns.neighbor_ip_mask)
        log.info('the value of neighbor_3_ip_list is : {0}'.format(neighbor_3_ip_list))
    if hasattr(ns, 'vrf_router_id') and ns.vrf_router_id:
        vrf_router_id_list = ipaddrgen(ns.no_of_vrf, ns.vrf_router_id, ns.vrf_router_id_mask)
        log.info('the value of vrf_router_id_list is : {0}'.format(vrf_router_id_list))        
    if hasattr(ns, 'neighbor_1_start_ipv6') and ns.neighbor_1_start_ipv6:
        neighbor_1_ipv6_list = ipv6addrgen(ns.no_of_vrf, ns.neighbor_1_start_ipv6, ns.neighbor_ipv6_mask)
        log.info('the value of neighbor_1_ipv6_list is : {0}'.format(neighbor_1_ipv6_list))
    if hasattr(ns, 'neighbor_2_start_ipv6') and ns.neighbor_2_start_ipv6:
        neighbor_2_ipv6_list = ipv6addrgen(ns.no_of_vrf, ns.neighbor_2_start_ipv6, ns.neighbor_ipv6_mask)
        log.info('the value of neighbor_2_ipv6_list is : {0}'.format(neighbor_2_ipv6_list))
    if hasattr(ns, 'neighbor_3_start_ipv6') and ns.neighbor_3_start_ipv6:
        neighbor_3_ipv6_list = ipv6addrgen(ns.no_of_vrf, ns.neighbor_3_start_ipv6, ns.neighbor_ipv6_mask)
        log.info('the value of neighbor_3_ipv6_list is : {0}'.format(neighbor_3_ipv6_list))
    for i in range(0,ns.no_of_vrf):
        cfg = ''
        if ns.vrf_router_id:
            cfg += '''router bgp {0}
                      vrf {1}
                      router-id {2}'''.format(as_no, vrf_name_list[i],vrf_router_id_list[i]) + '\n'
        else:
            cfg += '''router bgp {0}
                      vrf {1}'''.format(as_no,vrf_name_list[i]) + '\n'
        if hasattr(ns, 'af_v4_enable') and ns.af_v4_enable:
            cfg += 'address-family ipv4 unicast \n maximum-paths 64 \n maximum-paths ibgp 64' + '\n'
            if hasattr(ns, 'af_v4_redistribute_type') and ns.af_v4_redistribute_type:
                if hasattr(ns, 'af_v4_redistribute_rpm') and ns.af_v4_redistribute_rpm:
                    cfg += 'redistribute {0} route-map {1}'.format(ns.af_v4_redistribute_type,ns.af_v4_redistribute_rpm) + '\n'
            if hasattr(ns, 'advertise_l2vpn_evpn') and ns.advertise_l2vpn_evpn:
                cfg += 'advertise l2vpn evpn' + '\n'
                if hasattr(ns, 'max_path_ebgp') and ns.max_path_ebgp:
                    cfg += 'maximum-paths {0}'.format(ns.max_path_ebgp) + '\n'
                if hasattr(ns, 'max_path_ibgp') and ns.max_path_ibgp:
                     cfg += 'maximum-paths ibgp {0}'.format(ns.max_path_ebgp) + '\n'
                if hasattr(ns, 'l2vpn_redistribute_type') and ns.l2vpn_redistribute_type:
                    if hasattr(ns,'l2vpn_route_map') and ns.l2vpn_route_map:
                        cfg += 'redistribute {0} route-map {1}'.format(ns.l2vpn_redistribute_type,ns.l2vpn_route_map) + '\n'                
            if hasattr(ns, 'src_network_ip') and ns.src_network_ip:
                cfg += 'network {0}/{1}'.format(src_ip_network_list[i],ns.src_network_mask) + '\n'
            if hasattr(ns, 'rp_network_ip') and ns.rp_network_ip:
                cfg += 'network {0}/{1}'.format(rp_ip_network_list[i],ns.rp_network_mask) + '\n'
        if hasattr(ns, 'af_v6_enable') and ns.af_v6_enable:
            cfg += 'address-family ipv6 unicast \n maximum-paths 64 \n maximum-paths ibgp 64' + '\n'
            if hasattr(ns, 'advertise_l2vpn_evpn') and ns.advertise_l2vpn_evpn:
                cfg += 'advertise l2vpn evpn' + '\n'
                if hasattr(ns, 'max_path_ebgp') and ns.max_path_ebgp:
                    cfg += 'maximum-paths {0}'.format(ns.max_path_ebgp) + '\n'
                if hasattr(ns, 'max_path_ibgp') and ns.max_path_ibgp:
                     cfg += 'maximum-paths ibgp {0}'.format(ns.max_path_ebgp) + '\n'
                if hasattr(ns, 'l2vpn_v6_redistribute_type') and ns.l2vpn_v6_redistribute_type:
                    if hasattr(ns,'l2vpn_route_map') and ns.l2vpn_route_map:
                        cfg += 'redistribute {0} route-map {1}'.format(ns.l2vpn_v6_redistribute_type,ns.l2vpn_route_map) + '\n'    
        if hasattr(ns,'neighbor_1_start_ip') and ns.neighbor_1_start_ip:
            if hasattr(ns,'neighbor_1_remote_as') and ns.neighbor_1_remote_as:
                if hasattr(ns,'neighbor_v4_afn') and ns.neighbor_v4_afn:
                    cfg += '''neighbor {0}
                              remote-as {1}
                              address-family ipv4 unicast
                              soft-reconfiguration inbound always
                           '''.format(neighbor_1_ip_list[i], ns.neighbor_1_remote_as) + '\n'
        if hasattr(ns,'neighbor_2_start_ip') and ns.neighbor_2_start_ip:
            if hasattr(ns,'neighbor_2_remote_as') and ns.neighbor_2_remote_as:
                if hasattr(ns,'neighbor_v4_afn') and ns.neighbor_v4_afn:
                    cfg += '''neighbor {0}
                              remote-as {1}
                              address-family ipv4 unicast
                              soft-reconfiguration inbound always
                           '''.format(neighbor_2_ip_list[i], ns.neighbor_2_remote_as) + '\n'
        if hasattr(ns,'neighbor_3_start_ip') and ns.neighbor_3_start_ip:
            if hasattr(ns,'neighbor_3_remote_as') and ns.neighbor_3_remote_as:
                if hasattr(ns,'neighbor_v4_afn') and ns.neighbor_v4_afn:
                    cfg += '''neighbor {0}
                              remote-as {1}
                              address-family ipv4 unicast
                              soft-reconfiguration inbound always
                           '''.format(neighbor_3_ip_list[i], ns.neighbor_3_remote_as) + '\n'
        if hasattr(ns,'neighbor_1_start_ipv6') and ns.neighbor_1_start_ipv6:
            if hasattr(ns,'neighbor_1_remote_as') and ns.neighbor_1_remote_as:
                if hasattr(ns,'neighbor_v6_afn') and ns.neighbor_v6_afn:
                    cfg += '''neighbor {0}
                              remote-as {1}
                              address-family ipv6 unicast
                              soft-reconfiguration inbound always
                           '''.format(neighbor_1_ipv6_list[i], ns.neighbor_1_remote_as) + '\n' 
        if hasattr(ns,'neighbor_2_start_ipv6') and ns.neighbor_2_start_ipv6:
            if hasattr(ns,'neighbor_2_remote_as') and ns.neighbor_2_remote_as:
                if hasattr(ns,'neighbor_v6_afn') and ns.neighbor_v6_afn:
                    cfg += '''neighbor {0}
                              remote-as {1}
                              address-family ipv6 unicast
                              soft-reconfiguration inbound always
                           '''.format(neighbor_2_ipv6_list[i], ns.neighbor_2_remote_as) + '\n'
        if hasattr(ns,'neighbor_3_start_ipv6') and ns.neighbor_3_start_ipv6:
            if hasattr(ns,'neighbor_3_remote_as') and ns.neighbor_3_remote_as:
                if hasattr(ns,'neighbor_v6_afn') and ns.neighbor_v6_afn:
                    cfg += '''neighbor {0}
                              remote-as {1}
                              address-family ipv6 unicast
                              soft-reconfiguration inbound always
                           '''.format(neighbor_3_ipv6_list[i], ns.neighbor_3_remote_as) + '\n'                           
        log.info('the value of cfg is : {0}'.format(cfg))
        hdl.configure(cfg)
    
# ******************* END BGP GLOBALS ********************#
 
 # ******************** GET METHODS FROM BOX ********************* #
 
def getVRFConfigured(log,dut,node_dict):
    log.info('Getting the VRF Names configured on the box:')
    vrf_list = []
    hdl = node_dict['all_dut'][dut]
    cfg = 'sh vrf | xml | grep vrf_name'
    out = hdl.execute(cfg)
    
    for line in out.splitlines():
        s = BeautifulSoup(line)
        try:
            vrf_name = s.find('vrf_name').string
            if not re.search('default|management', vrf_name):
                vrf_list.append(vrf_name)
        except:
            log.info('vrf Info is not present in the line {0}'.format(line))
    return vrf_list

def copy_running_to_start(self, testscript, device):
    '''This function copies running config to startup config
       call: copy_running_to_start(self, testscript, dutToTest_obj)
    '''

    if not device.copy(source='running-conf', dest='startup-config'):
       log.error('Copy run to start failed')
       testscript.parameters['fail_flag'] = 1
       self.failed()


def disconnect_connect_device(device):
    '''This function disconnects and connects to the device
       call: disconnect_connect_device(device)
    '''

    device.disconnect()
    device.connect(cls=Unicon,via='console')
    return 1


def my_reload_device(testbed, device):
    '''This function reloads the device
       call: my_reload_device(testbed, device)
    '''
    #password = testbed.servers.tftp.password
    uut_username = testbed.tacacs['username']
    uut_password = testbed.passwords['tacacs']

    response = Dialog([
        [r'.*Warning: There is already a file existing with this name. Do you want to overwrite \(y/n\)\?\[n\] '
         , lambda spawn: spawn.sendline('y'), None, True, False],
        [r'.*Warning: There is already a file existing with this name. Do you want to.*'
         , lambda spawn: spawn.sendline('y'), None, True, False],
        [r'.*login\:', lambda spawn: spawn.sendline(uut_username), None,
         True, False],
        [r'Password\:', lambda spawn: spawn.sendline(uut_password),
         None, True, False],
        [r'.*\s+\(y/n\)\?\s+\[n\]', lambda spawn: spawn.sendline('y'),
         None, True, False],
        [r'Do you wish to proceed anyway\?\s+\(y/n\)\s+\[n\]',
         lambda spawn: spawn.sendline('y'), None, True, False],
        ])
    try:
        device.execute("reload", reply = response, timeout = 1200)
    except Exception:
        log.error(traceback.format_exc())
        self.errored('error executing command reload')
    time.sleep(90)
    disconnect_connect_device(device)
    return 1


# ===========================================================================================

def parseTcamConfigs(log,args):
    arggrammar = {}
    arggrammar['size'] = '-type int'
    arggrammar['double_wide'] = '-type bool'
    ns = utils.parserutils_lib.argsToCommandOptions(args,arggrammar,log)
    log.info('The value of ns is : {0}'.format(ns))
    return ns

def configureTcam(log,dut,hdl,region, args):
    ns = parseTcamConfigs(log,args)
    cfg = ''
    log.info(banner('Configuring the TCAM region {0}'.format(region)))
    if re.search('ing-racl', region, re.I):
        if ns.double_wide:
            cfg += 'hardware access-list tcam region {0} {1} double_wide \n'.format(region,ns.size)
        else:
            cfg += 'hardware access-list tcam region {0} {1} \n'.format(region,ns.size)
    if re.search('ing-flow-redirect', region, re.I):
        if ns.double_wide:
            cfg += 'hardware access-list tcam region ing-racl 256 \n'
            cfg += 'hardware access-list tcam region {0} {1} double_wide \n '.format(region,ns.size)
        else:
            cfg += 'hardware access-list tcam region ing-racl 256 \n'
            cfg += 'hardware access-list tcam region {0} {1} \n'.format(region,ns.size)
    out = hdl.configure(cfg)
    if re.search('Error|Invalid|Fail', out, re.I):
        return 0
    return 1
    
    


