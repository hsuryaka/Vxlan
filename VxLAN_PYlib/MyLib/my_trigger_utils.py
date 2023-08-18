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


class Trigger:

    # First we create a constructor for this class
    # and add members to it, here models
    def __init__(self,log, node_dict,configdict,alias_intf_mapping_dict):
        self.log = log
        self.node_dict = node_dict
        self.configdict = configdict
        self.alias_intf_mapping_dict = alias_intf_mapping_dict
        self.configsuccess = 1
        
    def globalMulticastRoute(self,dut):
        self.log.info('The value of dut is : {0}'.format(dut))
        hdl = self.node_dict[dut]
        cfg = ''
        
        
    def getVRFInformationFromDut(self,log,dut,hdl):
        self.log.info('Inside getVRFInformationFromDut...')
        vrf_list = []
        cfg = 'show vrf | xml | grep vrf_name'
        out = hdl.execute(cfg)
        for line in out.splitlines():
            if not re.search('default|management', line):
                s = BeautifulSoup(line)
                try:
                    vrf_name = s.find('vrf_name').string
                    if vrf_name:
                        vrf_list.append(vrf_name)
                except:
                    self.log.info('VRF information not found in this line : {0}'.format(line))
        
        self.log.info('The value of vrf_list is : {0}'.format(vrf_list))            
        return vrf_list
                    

        
class MulticastTrigger(Trigger):
    
    def __init__(self,log,node_dict,config_dict,alias_intf_mapping_dict):
        Trigger.__init__(self,log,node_dict,config_dict,alias_intf_mapping_dict)
        
    def getMulticastSourceOnVRF(self,dut,hdl,vrf):
        sourceTree_list = []
        cfg = 'show ip mroute vrf {0} | xml '.format(vrf)
        out = hdl.execute(cfg)
        pat = re.compile("^\(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\/32$", flags = re.I)
        for line in out.splitlines():
            if 'mcast-addrs' in line:
                s = BeautifulSoup(line)
                try:
                    ip = s.find('mcast-addrs').string
                    if ip:
                        source,group = ip.split(',')
                        self.log.info('the value of source is {0}'.format(source))
                        self.log.info('The value of group is {0}'.format(group))
                        test = pat.search(source)
                        if test:
                            sourceTree_list.append(ip)
                except:
                    self.log.info('The mcast-addrs is not found in this line : The line is : {0}'.format(line))
        
        self.log.info(banner('The sourceTree_list in dut {2} on VRF {1} is : {0}'.format(sourceTree_list, vrf,dut)))
        return sourceTree_list
                
    def getMulticastIGMPGroupsOnVRF(self,dut,hdl,vrf):
        sharedTree_list = []
        cfg = 'show ip mroute vrf {0} | xml '.format(vrf)
        out = hdl.execute(cfg)
        pat = re.compile("\(\*,\s+\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\/32\)", flags = re.I)
#        pat = re.compile("^\(\*, \d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\/32\)$", flags = re.I)
        for line in out.splitlines():
            if 'mcast-addrs' in line:
                s = BeautifulSoup(line)
                try:
                    ip = s.find('mcast-addrs').string
                    if ip:
                        self.log.info('the value of ip is : {0}'.format(ip))
                        test = pat.search(ip)
                        if test:
                            self.log.info('the value of test is : {0}'.format(test))
                            if ip.find('232.0.0.0/8') == -1:
                                sharedTree_list.append(ip)
                except:
                    self.log.info('The mcast-addrs is not found in this line : The line is : {0}'.format(line))
        
        self.log.info(banner('the value of sharedTree_list in dut {2} on VRF {1} is : {0}'.format(sharedTree_list, vrf,dut)))
        return sharedTree_list                
                