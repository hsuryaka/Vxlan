import re
import logging
from ats.log.utils import banner
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



## Parsing Multisite dashed args ..

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

def parseMultisiteL2VNIConfigs(log,args):
    
    arggrammar={}
    arggrammar['no_of_l2_vni']='-type int'
    arggrammar['l2_vni_start']='-type int'
    ns=parserutils_lib.argsToCommandOptions( args, arggrammar, log )
    return ns


def parseMultisiteL3VNIConfigs(log,args):
    
    arggrammar={}
    arggrammar['no_of_l3_vni']='-type int'
    arggrammar['l3_vni_start']='-type int'
    ns=parserutils_lib.argsToCommandOptions( args, arggrammar, log )
    return ns

class configMultisite():
    
    def __init__(self, multisite_config_dict,node_dict,alias_intf_mapping,log):
        self.log  = log
        self.result = 'pass'
        self.multisite_config_dict = multisite_config_dict
        self.node_dict = node_dict
        self.alias_intf_mapping = alias_intf_mapping
        log.info('Configuring EVPN Multisite Configs')
        try:
            self.node_list = self.multisite_config_dict.keys()
        except KeyError:
            err_msg='Error !!! multisite_config_dict has not been defined properly, does not have nodes   \
              as the top level keys'
            testResult( 'fail', err_msg, self.log )
            
    def configureDCILinks(self, node):
        self.log.info(node)
        hdl = self.node_dict['all_dut'][node]
        
        
        self.log.info(banner('The value of alias_intf_mapping is : {0}'.format(self.alias_intf_mapping)))
        if 'interface_config' in self.multisite_config_dict[node].keys():
            if 'dci_links'  in self.multisite_config_dict[node]['interface_config']:
                for intf in self.multisite_config_dict[node]['interface_config']['dci_links']:
                    if re.search('uut', intf):
                        intf = self.alias_intf_mapping[node][intf]
                    cfg = '''interface {0}
                             evpn multisite dci-tracking'''.format(intf)
     
                    hdl.configure(cfg)
            
        else:
            err_msg = 'Error !! multisite_config_dict does not have interface_config as top level keys'
            testResult( 'fail', err_msg, self.log )
            
    def configureFabricLinks(self, node):
        self.log.info(node)
        hdl = self.node_dict['all_dut'][node]
        
        if 'interface_config' in self.multisite_config_dict[node].keys():
            if 'dci_links'  in self.multisite_config_dict[node]['interface_config']:
                for intf in self.multisite_config_dict[node]['interface_config']['fabric_links']:
                    if re.search('uut', intf):
                        intf = self.alias_intf_mapping[node][intf]
                    cfg = '''interface {0}
                             evpn multisite fabric-tracking'''.format(intf)
                    hdl.configure(cfg)
        else:
            err_msg = 'Error !! multisite_config_dict does not have interface_config as top level keys'
            testResult( 'fail', err_msg, self.log )
            
    def configureMultiSiteIR(self, node):
        self.log.info(node)
        hdl = self.node_dict['all_dut'][node]
        
        if 'l2_vni' in self.multisite_config_dict[node].keys():
            ns = parseMultisiteL2VNIConfigs(self.log,self.multisite_config_dict[node]['l2_vni'])
            self.log.info(banner('The value of ns is : {0}'.format(ns)))
            if hasattr (ns, 'no_of_l2_vni') and ns.no_of_l2_vni:
                if hasattr(ns,'l2_vni_start') and ns.l2_vni_start:
                    for i in range(0,ns.no_of_l2_vni):
                        cfg = '''interface nve 1
                                 member vni {0}
                                 multisite ingress-replication'''.format(ns.l2_vni_start + i)
                        hdl.configure(cfg)
                     
        else:
            err_msg = 'Error !! multisite_config_dict does not have interface_config as top level keys'
            testResult( 'fail', err_msg, self.log )
            
    def configureMultiSiteIROptimized(self, node):
        self.log.info(node)
        hdl = self.node_dict['all_dut'][node]
        
        if 'l3_vni' in self.multisite_config_dict[node].keys():
            ns = parseMultisiteL3VNIConfigs(self.log,self.multisite_config_dict[node]['l3_vni'])
            self.log.info(banner('The value of ns is : {0}'.format(ns)))
            if hasattr (ns, 'no_of_l3_vni') and ns.no_of_l3_vni:
                if hasattr(ns,'l3_vni_start') and ns.l3_vni_start:
                    for i in range(0,ns.no_of_l3_vni):
                        cfg = '''interface nve 1
                                 member vni {0} associate-vrf
                                 multisite ingress-replication optimized'''.format(ns.l3_vni_start + i)
                        hdl.configure(cfg)
                        
    def configureMultiSiteLoopback(self, node):
        self.log.info(node)
        hdl = self.node_dict['all_dut'][node]
        
        if 'loopback' in self.multisite_config_dict[node]['interface_config'].keys():
            cfg = '''interface nve 1
                      multisite border-gateway interface {0}'''.format(self.multisite_config_dict[node]['interface_config']['loopback'])
            hdl.configure(cfg)
    
        

    def Nodes(self, node):
        self.log.info(node)
        hdl = self.node_dict['all_dut'][node]
        
        if 'global' in self.multisite_config_dict[node]:
            ns = parseMultisiteConfigs(self.log, self.multisite_config_dict[node]['global'])
            self.log.info(banner('The value of ns is : {0}'.format(ns)))
            cfg = ''
            if hasattr (ns, 'site_id') and ns.site_id:
                cfg += 'evpn multisite border-gateway {0}'.format(ns.site_id) + '\n'
            if hasattr (ns, 'dci_advertise_pip') and ns.dci_advertise_pip:
                cfg += 'dci-advertise-pip' + '\n'
            if hasattr (ns, 'delay_restore_time') and ns.delay_restore_time:
                cfg += 'delay-restore time {0}'.format(ns.delay_restore_time) + '\n'
            
            hdl.configure(cfg)
         
        
        
        if 'dci_links' in self.multisite_config_dict[node]['interface_config']:
            
            self.log.info(banner('configuring the DCI links :'))
            self.configureDCILinks(node)
            
        else:
            err_msg = 'Error !! multisite_config_dict does not have dci_links defined in interface configs'
            testResult( 'fail', err_msg, self.log )
            

        if 'fabric_links' in self.multisite_config_dict[node]['interface_config']:
            
            self.log.info(banner('configuring the Fabric links :'))
            self.configureFabricLinks(node)
            
        else:
            err_msg = 'Error !! multisite_config_dict does not have fabric_link defined in interface configs'
            testResult( 'fail', err_msg, self.log )
            
        if 'l2_vni' in self.multisite_config_dict[node]:
            
            self.log.info(banner('configuring the Multisite IR on L2 VNI:'))
            self.configureMultiSiteIR(node)
            
        else:
            err_msg = 'Error !! multisite_config_dict does not have MultisiteIR L2VNI defined in interface configs'
            testResult( 'fail', err_msg, self.log )
            
        if 'l3_vni' in self.multisite_config_dict[node]:
            self.log.info(banner('configuring the Multisite IR Optimzed on L3 VNI FOR TRM Multisite:'))
            self.configureMultiSiteIROptimized(node)

            
        if 'loopback' in self.multisite_config_dict[node]['interface_config']:
            self.log.info(banner('Configuring the Multisite Loopback Interface on dut {0}'.format(node)))
            self.configureMultiSiteLoopback(node)
            
        else:
            err_msg = 'Error !! multisite_config_dict does not have MultisiteIR Loopback defined in interface configs'
            testResult( 'fail', err_msg, self.log )
        
        return 1
    
    def getDciLinksFromConfigFile(self, node):
        pass
    
    def getDciLinksFromBox(self, node):
        pass
    
    def getFabricLinkFromConfigFile(self, node):
        pass
    
    def getFabricLinkFromBox(self, node):
        pass
    
    def getMultisiteLoopbackInterface(self, node):
        pass
    
    def configMultisiteLoopbackInterface(self, node):
        pass
    

    
            