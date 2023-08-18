
import os
import re
import time
import sys
import logging

from common_lib import parserutils_lib
from common_lib import utils
from common_lib import verify_lib
from common_lib import bringup_lib


class configureInterfaces(object):
    '''Class to configure interfaces as per following interface_config_dict
    interface_config_dict:
       node02:
          ethernet:
             Eth1/54: -mode switchport -switchportmode access -access_vlan 100
             Eth1/49: -mode no switchport -mtu 9100 -ipv4_addr 2.1.1.1 -ipv4_prf_len 24 -ipv6_addr 2000:1:1::1 -ipv6_prf_len 64
          loopback:
             loopback1: -ipv4_addr 150.1.1.2 -ipv4_prf_len 32 -ipv6_addr 1500::2 -ipv6_prf_len 128
          svi:
             100: -ipv4_addr 100.1.101.254 -ipv4_prf_len 24 -ipv6_addr 1000:101::254 -ipv6_prf_len 64 -mtu 9100
       node03:
          breakout_ports:
             1: -port_list Eth1/1 Eth1/2 Eth1/3 Eth1/4 Eth1/5 Eth1/7 -speed 10000
          ethernet:
             Eth1/1/1-4: -channelGroup 3 -channelGroupMode active -switchMode no switchport -mtu 9100
             Eth1/2/1-4: -channelGroup 3 -channelGroupMode active -switchMode no switchport -mtu 9100
             Eth1/3/1-4: -channelGroup 3 -channelGroupMode active -switchMode no switchport -mtu 9100
             Eth1/4/1-4: -channelGroup 31 -channelGroupMode active -switchMode no switchport -mtu 9100
             Eth1/5/1-4: -channelGroup 31 -channelGroupMode active -switchMode no switchport -mtu 9100
             Eth1/7/1-4: -channelGroup 31 -channelGroupMode active -switchMode no switchport -mtu 9100
             Eth1/9: -mode no switchport -mtu 9100 -ipv4_addr 1.1.1.2 -ipv4_prf_len 24 -ipv6_addr 1000:1:1::2 -ipv6_prf_len 64
             Eth1/10: -mode no switchport -mtu 9100 -ipv4_addr 2.1.1.2 -ipv4_prf_len 24 -ipv6_addr 2000:1:1::2 -ipv6_prf_len 64
          portchannel:
             port-channel3: -memberList Eth1/1/1-4 Eth1/2/1-4 -mode no switchport -ipv4_addr 3.1.1.2 -ipv4_prf_len 24 -ipv6_addr 3000:1:1::2 -ipv6_prf_len 64 -mtu 9100
             port-channel31: -memberList Eth1/4/1-4 Eth1/5/1-4 Eth1/7/1-4 -mode switchport -switchportmode access -access_vlan 100
          loopback:
             loopback1: -ipv4_addr 150.1.1.3 -ipv4_prf_len 32 -ipv6_addr 1500::3 -ipv6_prf_len 128
    '''
    def __init__(self,log, switch_hdl_dict=None, interface_config_dict=None):

        self.log=log
        self.result='pass'

        if not switch_hdl_dict:
            self.log.error('switch_hdl_dict not available')
            self.result='fail'
            return
        else:
            self.hdl_dict=switch_hdl_dict

        if not interface_config_dict:
            self.log.error('interface_config_dict not available')
            self.result='fail'
            return
        else:
            self.interface_config_dict=interface_config_dict

        for node in self.interface_config_dict.keys():
           # Make default conf on all ethernet interfaces first on that node
           if 'ethernet' in self.interface_config_dict[node].keys():
              for intf in self.interface_config_dict[node]['ethernet'].keys():
                 cfg = 'default interface ' + intf
                 self.hdl_dict[node].configure(cfg)

           # if port-channel is specified, delete port channels which might be present on switch
           if 'portchannel' in self.interface_config_dict[node].keys():
              for intf in self.interface_config_dict[node]['portchannel'].keys():
                 cfg = 'no interface ' + intf
                 self.hdl_dict[node].configure(cfg)
                 self.hdl_dict[node].configure('feature lacp')

           for intf_type in self.interface_config_dict[node].keys():
              if re.match('ethernet', intf_type, re.I):
                 if not self.configureEthernet(node):
                    self.log.error('Ethernet configuration failed')
                    self.result='fail'
              elif re.match('svi', intf_type, re.I):
                 if not self.configureSvi(node):
                    self.log.error('SVI configuration failed')
                    self.result='fail'
              elif re.match('portchannel', intf_type, re.I):
                 if not self.configurePo(node):
                    self.log.error('PortChannel configuration failed')
                    self.result='fail'
              elif re.match('loopback', intf_type, re.I):
                 if not self.configureLoopback(node):
                    self.log.error('Loopback configuration failed')
                    self.result='fail'
    def configureEthernet(self, node):
        self.log.info('Configuring Ethernet interfaces')
        self.log.info('continuing {0}'.format(node))
        sw_hdl=self.hdl_dict[node]

        if 'breakout_ports' in self.interface_config_dict[node].keys():
           sw_eth_breakout_ports_dict=self.interface_config_dict[node]['breakout_ports']
           for var in sw_eth_breakout_ports_dict.keys():
              bo_args=sw_eth_breakout_ports_dict[var]
              if not configureBreakOut(sw_hdl, bo_args, self.log):
                 #self.log.error('Breaking out ports failed on {0} for {1}'.format(sw_hdl.name,bo_args))
                 return 0
        print("interface_config_dict ......................")
        eth_dict=self.interface_config_dict[node]['ethernet']
        for intf in eth_dict.keys():
           eth_args=eth_dict[intf]
           if not configureEthIntf(sw_hdl, intf, eth_args, self.log):
              #self.log.error('Configuring Ethernet interface failed on {0} with {1}'.format(sw_hdl.name,eth_args))
              return 0
        return 1
    def configureSvi(self, node):
        self.log.info('Configuring SVI interfaces')

        sw_hdl=self.hdl_dict[node]
        sw_hdl.configure('feature interface-vlan')

        sw_svi_dict=self.interface_config_dict[node]['svi']
        for var in sw_svi_dict.keys():
           svi_args=sw_svi_dict[var]
           if not configureSviIntf(sw_hdl,var,svi_args,self.log):
              self.log.error('Configuring SVI interface failed on {0} with {1}'.format(sw_hdl.name,svi_args))
              return 0
        return 1

    def configurePo(self, node):
        self.log.info('Configuring Port channel interfaces')

        sw_hdl=self.hdl_dict[node]

        sw_po_dict=self.interface_config_dict[node]['portchannel']
        for var in sw_po_dict.keys():
           po_args=sw_po_dict[var]

           if not configureEthIntf(sw_hdl,var,po_args,self.log):
              self.log.error('Configuring PO interface failed on {0} with {1}'.format(sw_hdl.name,po_args))
              return 0
        return 1

    def configureLoopback(self, node):
        self.log.info('Configuring Loopback interfaces')

        sw_hdl=self.hdl_dict[node]

        sw_lo_dict=self.interface_config_dict[node]['loopback']
        for var in sw_lo_dict.keys():
           lo_args=sw_lo_dict[var]
           lo_args+=' -loopFlag True'
           if not configureL3Intf(sw_hdl,var,lo_args,self.log):
              self.log.error('Configuring loopback interface failed on {0} with {1}'.format(sw_hdl.name,lo_args))
              return 0
        return 1

#pyATS
class configInterface(object):
    '''Class to configure interfaces as in interface_config_dict'''
    def __init__(self,log,switch_hdl_dict=None,interface_config_dict=None,*args,**kwargs):

        self.log=log

        self.result='pass'

        if not switch_hdl_dict:
            self.log.error('switch_hdl_dict not available')
            self.result='fail'
            return
        else:
            self.hdl_dict=switch_hdl_dict

        if not interface_config_dict:
            self.log.error('interface_config_dict not available')
            self.result='fail'
            return
        else:
            self.interface_config_dict=interface_config_dict
            print(self.interface_config_dict)
    
        keyList=[str.lower(x) for x in self.interface_config_dict.keys()]
        if 'vrf_evpn' in kwargs:
                self.log.info('Configuring BGP EVPN parameters after BGP config')
                if 'vrf' in keyList:
                       if not self.configureVrfEvpn():
                          self.log.error('Vrf EVPN  configuration failed')
                          self.result='fail'
                          return 
        if 'vlan' in keyList:
                if not self.configureVlan():
                   self.log.error('Vlan configuration failed')
                   self.result='fail'
                   return
        if 'pvlan' in keyList:
                if not self.configurePvlan():
                   self.log.error('Pvlan configuration failed')
                   self.result='fail'
                   return
        if 'vrf' in keyList:
                if not self.configureVrf():
                   self.log.error('Vrf configuration failed')
                   self.result='fail'
                   return

        for var in self.interface_config_dict.keys():
            if re.match('ethernet',var,re.I):
                if not self.configureEthernet():
                   self.log.error('Ethernet configuration failed')
                   self.result='fail'
                   return
        for var in self.interface_config_dict.keys():
            if re.match('svi',var,re.I):
                if not self.configureSvi():
                   self.log.error('SVI configuration failed')
                   self.result='fail'
                   return
            elif re.match('portchannel',var,re.I):
                if not self.configurePo():
                   self.log.error('PortChannel configuration failed')
                   self.result='fail'
                   return
            elif re.match('loopback',var,re.I):
                if not self.configureLoopback():
                   self.log.error('Loopback configuration failed')
                   self.result='fail'
                   return
        print("inside class configinterface {0}".format(self.result))


    def configureVrfEvpn(self):
        self.log.info('Configuring EVPN for the Vrf ')
        vrf_dict=self.interface_config_dict['vrf']
        self.log.info('\nvrf_dict : {0}'.format(vrf_dict))
        for sw in  self.hdl_dict.keys():
            sw_hdl=self.hdl_dict[sw]
            if not sw in vrf_dict.keys():
                self.log.info('Switch Vrf config not present for node {0}'.format(sw))
                continue
            sw_vrf_dict=vrf_dict[sw]
            sw_vrf = vrf_dict[sw]
            cfg=''
            self.log.info('\n sw_vrf_dict : {0}'.format(sw_vrf_dict))
            self.log.info('\n Type of sw_vrf_dict : {0}'.format(type(sw_vrf_dict)))
            if re.findall('(type \'dict\')',str(type(sw_vrf_dict))):
             for vrf in sw_vrf_dict.keys():
                     if 'evpn' in sw_vrf_dict[vrf].keys():
                             sw_vrf_evpn_dict=sw_vrf_dict[vrf]['evpn']
                             cfg=''
                             cfg+='vrf context {0}\n'.format(vrf)
                             if 'vni' in sw_vrf_evpn_dict.keys():
                                  cfg+='vni {0}\n'.format(sw_vrf_evpn_dict['vni'])
                             if 'rd' in sw_vrf_evpn_dict.keys():
                                  cfg+='rd {0}\n'.format(sw_vrf_evpn_dict['rd'])
                             out=sw_hdl.configure(cfg)
                             if out:
                                self.log.error('Configuring Vrf failed on {0} with {1}'.format(sw_hdl.name,out))
                                return 0
                             if 'address_family' in sw_vrf_evpn_dict.keys():
                                    add_family_dict=sw_vrf_evpn_dict['address_family']
                                    for var in add_family_dict.keys():
                                      bo_args=add_family_dict[var]
                                      if not configureVrfContextAddressFamily(sw_hdl,var,vrf,bo_args,self.log):
                                            self.log.error('Address family config on vrf failed on {0} ',format(sw_hdl.name))
                                            return 0
        return 1

    def configureVrf(self):
        self.log.info('Configuring Vrf')
        vrf_dict=self.interface_config_dict['vrf']
        self.log.info('\nvrf_dict : {0}'.format(vrf_dict))
        for sw in  self.hdl_dict.keys():
            sw_hdl=self.hdl_dict[sw]
            if not sw in vrf_dict.keys():
                self.log.info('Switch Vrf config not present for node {0}'.format(sw))
                continue
            sw_vrf_dict=vrf_dict[sw]
            sw_vrf = vrf_dict[sw]
            cfg=''
            self.log.info('\n sw_vrf_dict : {0}'.format(sw_vrf_dict))
            self.log.info('\n Type of sw_vrf_dict : {0}'.format(type(sw_vrf_dict)))
            if re.findall('(type \'dict\')',str(type(sw_vrf_dict))):
             for vrf in sw_vrf_dict.keys():
              cfg+='vrf context {0}\n'.format(vrf)
              out=sw_hdl.configure(cfg)
              #if out:
              #    #self.log.error('Configuring Vrf failed on {0} with {1}'.format(sw_hdl.name,out))
              #    return 0
              sw_add_dict=sw_vrf_dict[vrf] 
              self.log.info('DICT IS {0}'.format(sw_add_dict))
              if sw_add_dict:
                if 'address_family' in sw_add_dict.keys():
                   add_family_dict=sw_add_dict['address_family']
                   for var in add_family_dict.keys():             
                      bo_args=add_family_dict[var]
                      if not configureVrfContextAddressFamily(sw_hdl,var,vrf,bo_args,self.log):
                         #self.log.error('Address family config on vrf failed on {0} ',format(sw_hdl.name))
                         return 0  
            else: 
             for vrf in sw_vrf.split(','):
              cfg+='vrf context {0}\n'.format(vrf)

             out=sw_hdl.configure(cfg)
             #if out:
             #   #self.log.error('Configuring Vrf failed on {0} with {1}'.format(sw_hdl.name,out))
             #   return 0
        return 1

    def configureEthernet(self):
        self.log.info('Configuring Ethernet interfaces')    
        eth_dict=self.interface_config_dict['ethernet']
        for sw in self.hdl_dict.keys():
            sw_hdl=self.hdl_dict[sw]
            if not sw in eth_dict.keys():
                    self.log.info('Switch Ethernet config not present for DUT - {0}'.format(sw))
                    continue 
            sw_eth_dict=eth_dict[sw]
            if 'breakout_ports' in sw_eth_dict.keys():
                sw_eth_breakout_ports_dict=sw_eth_dict['breakout_ports']
                for var in sw_eth_breakout_ports_dict.keys():
                    bo_args=sw_eth_breakout_ports_dict[var] 
                    if not configureBreakOut(sw_hdl,bo_args,self.log):
                        #self.log.error('Breaking out ports failed on {0} for {1}'.format(sw_hdl.name,bo_args))
                        return 0
            eth_intf_list=sorted(sw_eth_dict.keys())
            #eth_intf_list.sort()
            for var in eth_intf_list:
                print('eth config {0}'.format(var))
                if var == 'breakout_ports':
                    continue
                else:
                    eth_args=sw_eth_dict[var]
                    if not configureEthIntf(sw_hdl,var,eth_args,self.log):
                        #self.log.error('Configuring Ethernet interface failed on {0} with {1}'.format(sw_hdl.name,eth_args))
                        return 0
        return 1 

    def configureVlan(self):
        self.log.info('Configuring Vlan')
        vlan_dict=self.interface_config_dict['vlan']
        for sw in  self.hdl_dict.keys():
            sw_hdl=self.hdl_dict[sw]
            if not sw in vlan_dict.keys():
                    self.log.info('Switch Vlan config not present for DUT - {0}'.format(sw))
                    continue 
            sw_vlan=vlan_dict[sw]
            sw_hdl.configure('spanning-tree mode mst')
            out=sw_hdl.configure('conf\n vlan {0}\n exit\n'.format(sw_vlan))
            if re.search('error|invalid',out,re.I):
                #self.log.error('Configuring Vlan failed on {0} with {1}'.format(sw_hdl.name,out))
                return 0
        return 1
    
    def configurePvlan(self):
        self.log.info('Configuring PVlan')
        pvlan_dict=self.interface_config_dict['pvlan']
        for sw in  self.hdl_dict.keys():
            sw_hdl=self.hdl_dict[sw]
            if sw in pvlan_dict.keys():
               sw_pvlan=pvlan_dict[sw]
               for pvlan in sw_pvlan.keys():
                        pvlan_args=sw_pvlan[pvlan]
                        if not configurepvlan(sw_hdl,pvlan,pvlan_args,self.log):
                                #self.log.error('Configuring PVLAN failed on {0} with {1}'.format(sw_hdl.name,pvlan_args)) 
                                return 0
        return 1 

    def configureSvi(self):
        self.log.info('Configuring SVI interfaces')
        svi_dict=self.interface_config_dict['svi']
        for sw in  self.hdl_dict.keys():
            sw_hdl=self.hdl_dict[sw]
            if sw in svi_dict.keys():
                 sw_svi_dict=svi_dict[sw]
                 for var in sw_svi_dict.keys():
                     svi_args=sw_svi_dict[var]
                     if not configureSviIntf(sw_hdl,var,svi_args,self.log):
                         #self.log.error('Configuring SVI interface failed on {0} with {1}'.format(sw_hdl.name,svi_args))
                         return 0
        return 1 

    def configurePo(self):
        self.log.info('Configuring Port channel interfaces')
        po_dict=self.interface_config_dict['portchannel']    
        self.log.info(po_dict)
        for sw in  self.hdl_dict.keys():
            sw_hdl=self.hdl_dict[sw]
            if sw in po_dict.keys():
               sw_po_dict=po_dict[sw]
               po_intf_list=sorted(sw_po_dict.keys())
               #po_intf_list.sort()
               for var in po_intf_list:
                       po_args=sw_po_dict[var]
                       self.log.info('Configuring PO Eth interfaces:' + var + po_args)
                       if not configureEthIntf(sw_hdl,var,po_args,self.log):
                               #self.log.error('Configuring PO interface failed on {0} with {1}'.format(sw_hdl.name,po_args))
                               return 0
        return 1 

    def configureLoopback(self):
        self.log.info('Configuring Loopback interfaces')
        lo_dict=self.interface_config_dict['loopback']    
        for sw in  self.hdl_dict.keys():
            sw_hdl=self.hdl_dict[sw]
            if sw in lo_dict.keys():
               sw_lo_dict=lo_dict[sw]
               for var in sw_lo_dict.keys():
                  lo_args=sw_lo_dict[var]
                  lo_args+=' -loopFlag True'
                  if not configureL3Intf(sw_hdl,var,lo_args,self.log):
                     #self.log.error('Configuring loopback interface failed on {0} with {1}'.format(sw_hdl.name,lo_args))
                     return 0
        return 1 
                
def configurepvlan(sw_hdl,pvlan,pvlan_args,log):
    arggrammar={}
    arggrammar['isolated']='-type str -default None'
    arggrammar['community']='-type str -default None'
    try:
        ns=parserutils_lib.argsToCommandOptions(pvlan_args,arggrammar,log)
    except Exception as e:
        log.error('Args parsing failed for pvlan {0} on device {1}. Error is {2}'.format(pvlan,sw_hdl.name,e)) 
        return 0
    cfg=''
    secondary_vlan=''
    if ns.isolated != 'None':
            cfg='''vlan {0}
                   private-vlan isolated
                   '''.format(ns.isolated)
            secondary_vlan='{0},'.format(ns.isolated)
    if ns.community != 'None':
            cfg+='''vlan {0}
                   private-vlan community
                   '''.format(ns.community)
            secondary_vlan+='{0}'.format(ns.community)
    cfg+='''vlan {0}
            private-vlan primary
            private-vlan association {1}
           '''.format(pvlan,secondary_vlan) 

    kdict={}
    kdict['verifySuccess']=True
    sw_hdl.configure(cfg)
    #if sw_hdl.errFlag:
    #    return 0
    return 1

def unconfigurepvlan(sw_hdl,pvlan,pvlan_args,log):
    arggrammar={}
    arggrammar['isolated']='-type str -default None'
    arggrammar['community']='-type str -default None'
    try:
        ns=parserutils_lib.argsToCommandOptions(pvlan_args,arggrammar,log)
    except Exception as e:
        log.error('Args parsing failed for pvlan {0} on device {1}. Error is {2}'.format(pvlan,sw_hdl.name,e))
        return 0
    cfg=''
    secondary_vlan=''
    if ns.isolated != 'None':
            cfg='''no vlan {0}
                   '''.format(ns.isolated)
    if ns.community != 'None':
            cfg+='''no vlan {0}
                   '''.format(ns.community)
    cfg+='''no vlan {0}
           '''.format(pvlan)

    kdict={}
    kdict['verifySuccess']=True
    sw_hdl.configure(cfg)
    #if sw_hdl.errFlag:
    #    return 0
    return 1

def configureVrfContextAddressFamily(sw_hdl,add_family,vrf_name,vrf_args,log):
      log.info('Configuring VRF Conetxt on {0}'.format(sw_hdl.name))
      arggrammar={}
      arggrammar['imports']='-type str'
      arggrammar['export']='-type str'
      arggrammar['export_map']='-type str'
      arggrammar['import_map']='-type str'
      arggrammar['import_default_vrf_map']='-type str'
      cfg=''
      try:
          ns=parserutils_lib.argsToCommandOptions(vrf_args,arggrammar,log)
      except Exception as e:
          log.error('Parsing Args failed on Switch {0} '.format(sw_hdl.name))
          return 0
      
      if ns.imports and ns.export: 
              imp = ns.imports
              imp_str = imp.replace("\"", " ")
              exp = ns.export
              exp_str = exp.replace("\"", " ")
      # ipv4_unicast: -import "2:2" -export "1:1" -export_map TO_CUST
      cfg+='''vrf context {0}
                address-family {1} unicast \n 
               '''.format(vrf_name,add_family)
      if ns.imports:
        cfg+=''' route-target import {0} \n '''.format(imp_str)
      if ns.export:
        cfg+=''' route-target export {0} \n '''.format(exp_str)
      if ns.export_map:
        cfg+=''' export map {0} \n  '''.format(ns.export_map)
      if ns.import_map:
        cfg+=''' import map {0} \n '''.format(ns.import_map)
      if ns.import_default_vrf_map:
        cfg+=''' import vrf default map  {0} \n '''.format(ns.import_default_vrf_map)
      kdict={}
      kdict['verifySuccess']=True
      sw_hdl.configure(cfg)
      #if sw_hdl.errFlag:
      #    return 0
      return 1
                
def configureBreakOut(sw_hdl,bo_args,log):
    log.info('Breaking out ports on {0}'.format(sw_hdl.name))    
    arggrammar={}
    arggrammar['port_list']='-type str -required True'
    arggrammar['mode']='-type str -choices ["n3k","n9k","n3k-t2p"] -default n3k'
    arggrammar['map']='-type str'
    arggrammar['speed']='-type int -default 10000'
    cfg='' 
    try:
        ns=parserutils_lib.argsToCommandOptions(bo_args,arggrammar,log)
    except Exception as e:
        log.error('Port list not provided for breakout')
        return 0
    if ns.mode == "n3k":
      for port in strToList(ns.port_list):
        op=sw_hdl.iexec('sh run int {0}'.format(port))
        if re.search('Invalid range',op,re.I):
            op=sw_hdl.iexec('sh run int {0}/1'.format(port))
        if not re.search('speed\s+{0}'.format(ns.speed),op,re.I):
            cfg+='''interface {0}
                     speed {1}
                 '''.format(port,ns.speed)
        else:
            log.info('Port already in breakout mode')
            return 1
    elif ns.mode == "n9k":
       if ns.map:
           for port in strToList(ns.port_list):
                   mod_port=port.split("/")
                   mod=re.findall('[0-9]+',mod_port[0])[0]
                   port=mod_port[1]
                   cfg+='interface breakout module {0} port {1} map {2}\n'.format(mod,port,ns.map)
    elif ns.mode == "n3k-t2p":
       if ns.map:
           for port in strToList(ns.port_list):
                mod_port=port.split("/")
                mod=re.findall('[0-9]+',mod_port[0])[0]
                port=mod_port[1]
                cfg+='hardware profile front portmode sfp-plus\n'
                cfg+='interface breakout module {0} port {1} map {2}\n'.format(mod,port,ns.map) 
       else:
           log.error('Mapping of port breakout not provided for {0} of {1}'.format(ns.port_list,sw_hdl.switchName))
           return 0     
    #kdict={}
    #kdict['verifySuccess']=True
    sw_hdl.configure(cfg)
    #if sw_hdl.errFlag:
    #    return 0
    return 1

def configureEthIntf(sw_hdl,eth,eth_args,log):
    log.info('Configuring Ethernet interface {0} : {1}'.format(eth, eth_args))
    arggrammar={}
    arggrammar['mode']='-type str'
    arggrammar['channelGroup']='-type str'

    try:
        ns=parserutils_lib.argsToCommandOptions(eth_args,arggrammar,log)
    except Exception as e:
        #log.error('Neither mode nor channelGroup found for {0} in {1} for {2}'.format(eth,eth_args,sw_hdl.name))
        log.info('Error inside parser util:\n' + e + '\n')
        return 0

    if ns.mode:
        if ns.mode=='no switchport':
            if not configureL3Intf(sw_hdl,eth,eth_args,log):
                #log.error('Configuring {0} as L3 failed on {1}'.format(eth,sw_hdl.name))
                return 0
        elif ns.mode=='switchport':
            log.info('Inside configure L2')
            if not configureL2Intf(sw_hdl,eth,eth_args,log):
                #log.error('Configuring {0} as L2 failed on {1}'.format(eth,sw_hdl.name))
                return 0
    if ns.channelGroup:
        log.info('Inside PO member port config')
        if not configurePomemberPorts(sw_hdl,eth,eth_args,log):
            #log.error('Configuring member ports failed with {0} on {1} for {2}'.format(eth_args,eth,sw_hdl.name))
            return 0
    return 1

def configureL3Intf(sw_hdl,intf,intf_args,log):
    log.info('Configuring {0} as L3 interface with parameters {1}'.format(intf,intf_args))
    print(intf_args)
    arggrammar={}
    arggrammar['ipv4_addr']='-type str'
    arggrammar['ipv6_addr']='-type str'
    arggrammar['ipv4_prf_len']='-type str'
    arggrammar['ipv6_prf_len']='-type str'
    arggrammar['mtu']='-type str'
    arggrammar['speed']='-type str'
    arggrammar['no_negotiate_auto']='-type bool -default False'
    arggrammar['memberList']='-type str'
    arggrammar['loopFlag']='-type bool -default False'
    arggrammar['encapDot1q']='-type int'
    arggrammar['vrf']='-type str'
    arggrammar['local_arp_proxy']='-type bool -default False'
    arggrammar['nat']='-type str'
    arggrammar['mpls_forwarding']='-type bool -default False'
    arggrammar['secondary_ipv4_addr']='-type str'
    arggrammar['secondary_ipv4_addr_tag']='-type str'
    arggrammar['tag']='-type int'

    try:
        ns=parserutils_lib.argsToCommandOptions(intf_args,arggrammar,log)
    except Exception as e:
        #log.error('Args parsing failed for interface {0} on device {1}. Error is {2}'.format(intf,sw_hdl.name,e)) 
        return 0

    if  ns.loopFlag: 
        cfg='''interface {0}
            '''.format(intf)
    else:
        if  re.match('port-channel\d+\.\d+',intf) or re.match('[E|e]th\d+/\d+\.\d+',intf):
           cfg='''interface {0}
           '''.format(intf)
        else:
           cfg='''
              interface {0}
              no switchport
            '''.format(intf)

    if ns.vrf:
        cfg+='vrf member {0}\n'.format(ns.vrf)
    if ns.encapDot1q:
        cfg+='encapsulation dot1q {0}\n'.format(ns.encapDot1q)
    if ns.ipv4_addr and ns.ipv4_prf_len:
        cfg+='ip address {0}/{1}\n'.format(ns.ipv4_addr,ns.ipv4_prf_len)
    if ns.secondary_ipv4_addr and ns.ipv4_prf_len:
        cfg+='ip address {0}/{1} secondary\n'.format(ns.secondary_ipv4_addr,ns.ipv4_prf_len)
    if ns.tag:
        cfg+='ip address {0}/{1} tag {2}\n'.format(ns.ipv4_addr,ns.ipv4_prf_len,ns.tag)
    if ns.secondary_ipv4_addr_tag:
        cfg+='ip address {0}/{1} secondary tag {2}\n'.format(ns.secondary_ipv4_addr,ns.ipv4_prf_len,ns.secondary_ipv4_addr_tag)
    if ns.ipv6_addr and ns.ipv6_prf_len:
        cfg+='ipv6 address {0}/{1}\n'.format(ns.ipv6_addr,ns.ipv6_prf_len) 
    if ns.mtu:
        cfg+='mtu {0}\n'.format(ns.mtu)
    if ns.speed:
        cfg+='speed {0}\n'.format(ns.speed)
    if ns.local_arp_proxy:
        cfg+='ip local-proxy-arp\n'
    if ns.nat:
            cfg+='ip nat {0}\n'.format(ns.nat)
    if ns.no_negotiate_auto:
            cfg+='no negotiate auto\n'
    if ns.mpls_forwarding:
            cfg+='mpls ip forwarding\n'
    cfg+='no shut\n'

    kdict={}
    kdict['verifySuccess']=True
    sw_hdl.configure(cfg)
    #if sw_hdl.errFlag:
    #    return 0
    return 1

def configureL2Intf(sw_hdl,intf,intf_args,log):
    log.info('Configuring {0} as L2 interface with parameters {1}'.format(intf,intf_args))
    arggrammar={}
    arggrammar['switchportmode']='-type str -required True'
    arggrammar['access_vlan']='-type str'
    arggrammar['spanning_tree_edge']='-type bool -default False'
    arggrammar['allowed_vlan_list']='-type str'
    arggrammar['speed']='-type str'
    arggrammar['isolated']='-type bool -default False'
    arggrammar['private_vlan_type']='-type str -default None'
    arggrammar['private_vlan_subtype']='-type str -default None'
    arggrammar['pvlan_host_association']='-type str -default None'
    arggrammar['pvlan_trunk_vlan']='-type str -default None'
    arggrammar['pvlan_promiscuos_mapping']='-type str -default None'
    cfg='''interface {0}
            switchport
        '''.format(intf)
    try:
        ns=parserutils_lib.argsToCommandOptions(intf_args,arggrammar,log)
    except Exception as e:
        #log.error('Args parsing failed for interface {0} on device {1}. Error is {2}'.format(intf,sw_hdl.name,e)) 
        return 0
    if ns.switchportmode=='access' and ns.access_vlan:
        cfg+='''switchport mode access
                 switchport access vlan {0}
             '''.format(ns.access_vlan) 
    if ns.switchportmode=='trunk' :
        cfg+='''switchport mode trunk
             '''
        if ns.allowed_vlan_list:
                cfg+='''switchport trunk allowed vlan {0}
                             '''.format(ns.allowed_vlan_list)
    if ns.switchportmode=='private-vlan' and ns.private_vlan_type:
        vlan_subtype=''
        if ns.private_vlan_type == 'trunk':
                if ns.private_vlan_subtype != 'None':
                     vlan_subtype= ns.private_vlan_subtype
                cfg+='''switchport mode private-vlan {0} {1}\n'''.format(ns.private_vlan_type,vlan_subtype) 
                if ns.pvlan_trunk_vlan != 'None':
                        cfg+='''switchport private-vlan trunk allowed vlan {0}
                     '''.format(ns.pvlan_trunk_vlan)
                if ns.pvlan_promiscuos_mapping != 'None':
                     pvlan_mapping_list=ns.pvlan_promiscuos_mapping.split(' ')
                     for item in pvlan_mapping_list:
                                pvlan_svlan=item.split(':')
                                cfg+='''switchport private-vlan mapping trunk {0} {1}
                                '''.format(pvlan_svlan[0],pvlan_svlan[1])
        elif ns.private_vlan_type == 'promiscuous':
                cfg+='''switchport mode private-vlan {0}
                '''.format(ns.private_vlan_type)
                if ns.pvlan_promiscuos_mapping != 'None':
                     pvlan_mapping_list=ns.pvlan_promiscuos_mapping.split(' ')
                     for item in pvlan_mapping_list:
                                pvlan_svlan=item.split(':')
                                cfg+='''switchport private-vlan mapping {0} {1}
                                '''.format(pvlan_svlan[0],pvlan_svlan[1])
        elif ns.private_vlan_type == 'host':
                cfg+='''switchport mode private-vlan {0}
                '''.format(ns.private_vlan_type)
                if ns.pvlan_host_association != 'None':
                        cfg+='''switchport private-vlan host-association  {0}
                             '''.format(ns.pvlan_host_association)
    if ns.speed:
        cfg+='speed {0}\n'.format(ns.speed)
    if ns.spanning_tree_edge:
        cfg+='spanning-tree port type edge trunk\n'
    if ns.isolated:
        cfg+='switchport isolated\n'
    cfg+='no shut\n'

    kdict={}
    kdict['verifySuccess']=True
    sw_hdl.configure(cfg, timeout=600)
    #if sw_hdl.errFlag:
    #    return 0
    return 1

def configurePomemberPorts(sw_hdl,intf,intf_args,log):
    #log.info('Configuring {0} as Po member port with parameters {1} on {2}'.format(intf,intf_args,sw_hdl.name))
    arggrammar={}
    arggrammar['channelGroup']='-type str -required True'
    arggrammar['channelGroupMode']='-type str -required True'
    arggrammar['switchMode']='-type str -required True'
    arggrammar['mtu']='-type str'
    arggrammar['speed']='-type int'

    try:
        ns=parserutils_lib.argsToCommandOptions(intf_args,arggrammar,log)
    except Exception as e:
        log.error('Args parsing failed for interface {0} on device {1}. Error is {2}'.format(intf,sw_hdl.name,e)) 
        return 0

    cfg='''interface {0}
            no channel-group
            {1} 
        '''.format(intf,ns.switchMode)
    if ns.mtu:
        cfg+='mtu {0}\n'.format(ns.mtu)
    if ns.speed:
        cfg+='speed {0}\n'.format(ns.speed)
    cfg+='channel-group {0} force mode {1}\n'.format(ns.channelGroup,ns.channelGroupMode)
    cfg+='no shut\n'

    #kdict={}
    #kdict['verifySuccess']=True
    sw_hdl.configure(cfg)
    #if sw_hdl.errFlag:
    #    return 0
    return 1

def configureSviIntf(sw_hdl,intf,intf_args,log):
    log.info('Configuring {0} as SVI interface with parameters {1} on {2}'.format(intf,intf_args,sw_hdl.name))
    arggrammar={}
    arggrammar['ipv4_addr']='-type str'
    arggrammar['ipv6_addr']='-type str'
    arggrammar['ipv4_prf_len']='-type str'
    arggrammar['ipv6_prf_len']='-type str'
    arggrammar['mtu']='-type str'
    arggrammar['vrf']='-type str'
    arggrammar['speed']='-type str'
    arggrammar['bandwidth']='-type str'
    arggrammar['mac_address']='-type str'
    arggrammar['nat']='-type str'
    try:
        ns=parserutils_lib.argsToCommandOptions(intf_args,arggrammar,log)
    except Exception as e:
        log.error('Args parsing failed for interface {0} on device {1}. Error is {2}'.format(intf,sw_hdl.name,e)) 
        return 0
    cfg='''vlan {0}
            state active
           interface vlan {0}
        '''.format(intf)
    if ns.vrf:
        cfg+='vrf member {0}\n'.format(ns.vrf)
    if ns.mac_address:
        cfg+='mac-address {0}\n'.format(ns.mac_address)
    if ns.ipv4_addr and ns.ipv4_prf_len:
        cfg+='ip address {0}/{1}\n'.format(ns.ipv4_addr,ns.ipv4_prf_len) 
    if ns.ipv6_addr and ns.ipv6_prf_len:
        cfg+='ipv6 address {0}/{1}\n'.format(ns.ipv6_addr,ns.ipv6_prf_len) 
    if ns.mtu:
        cfg+='mtu {0}\n'.format(ns.mtu)
    if ns.speed:
        cfg+='speed {0}\n'.format(ns.speed)
    if ns.bandwidth:
        cfg+='bandwidth {0}\n'.format(ns.bandwidth)
    if ns.nat:
            cfg+='ip nat {0}\n'.format(ns.nat)
    cfg+='no shut\n'

    kdict={}
    kdict['verifySuccess']=True
    sw_hdl.configure(cfg)
    #if sw_hdl.errFlag:
    #    return 0
    return 1


class unconfigInterface(object):
    '''Class to unconfigure interfaces as in interface_config_dict'''
    def __init__(self,log,switch_hdl_dict=None,interface_config_dict=None):

        self.log=log

        self.result='pass'

        if not switch_hdl_dict:
            self.log.error('switch_hdl_dict not available')
            self.result='fail'
            return
        else:
            self.hdl_dict=switch_hdl_dict

        if not interface_config_dict:
            self.log.error('interface_config_dict not available')
            self.result='fail'
            return
        else:
            self.interface_config_dict=interface_config_dict
        
        for var in self.interface_config_dict.keys():
            if re.match('svi',var,re.I):
                if not self.unconfigureSvi():
                   self.log.error('SVI unconfiguration failed')
                   self.result='fail'
            if re.match('vlan',var,re.I):
                if not self.unconfigureVlan():
                   self.log.error('Vlan unconfiguration failed')
                   self.result='fail'
            if re.match('pvlan',var,re.I):
                if not self.unconfigurePvlan():
                   self.log.error('Private-Vlan unconfiguration failed')
                   self.result='fail'
            if re.match('vrf',var,re.I):
                if not self.unconfigureVrf():
                   self.log.error('Vrf unconfiguration failed')
                   self.result='fail'
            elif re.match('portchannel',var,re.I):
                if not self.unconfigurePo():
                   self.log.error('PortChannel unconfiguration failed')
                   self.result='fail'
            elif re.match('loopback',var,re.I):
                if not self.unconfigureLoopback():
                   self.log.error('Loopback unconfiguration failed')
                   self.result='fail'
       
        for var in self.interface_config_dict.keys():
            if re.match('ethernet',var,re.I):
                if not self.unconfigureEthernet():
                   self.log.error('Ethernet unconfiguration failed')
                   self.result='fail'

    def unconfigureVrf(self):
        self.log.info('Unconfiguring Vrf')
        vrf_dict=self.interface_config_dict['vrf']
        for sw in vrf_dict.keys():
            sw_hdl=self.hdl_dict[sw]
            sw_vrf_dict=vrf_dict[sw]
            sw_vrf = vrf_dict[sw]
            cfg=''
            if sw_vrf_dict.keys():
             for vrf in sw_vrf_dict.keys():
              cfg+='no vrf context {0}\n'.format(vrf)
              out=sw_hdl.configure(cfg)
              if out:
                  self.log.error('Un Configuring Vrf failed on {0} with {1}'.format(sw_hdl.name,out))
                  return 0
            else:
              for vrf in sw_vrf.split(','):
                 cfg+='no vrf context {0}\n'.format(vrf)

            out=sw_hdl.configure(cfg)
            if out:
                self.log.error('Unconfiguring Vrf failed on {0} with {1}'.format(sw_hdl.name,out))
                return 0
        return 1

    def unconfigureVlan(self):
        self.log.info('Unconfiguring Vlan')
        vlan_dict=self.interface_config_dict['vlan']
        for sw in vlan_dict.keys():
            sw_hdl=self.hdl_dict[sw]
            sw_vlan=vlan_dict[sw]
            out=sw_hdl.iexec('conf\n no vlan {0}\n'.format(sw_vlan))
            if re.search('error|invalid',out,re.I):
                self.log.error('Unconfiguring Vlan failed on {0} with {1}'.format(sw_hdl.name,out))
                return 0
        return 1

    def unconfigurePvlan(self):
        self.log.info('Unconfiguring PVlan')
        pvlan_dict=self.interface_config_dict['pvlan']
        for sw in  self.hdl_dict.keys():
            sw_hdl=self.hdl_dict[sw]
            if sw in pvlan_dict.keys():
               sw_pvlan=pvlan_dict[sw]
               for pvlan in sw_pvlan.keys():
                        pvlan_args=sw_pvlan[pvlan]
                        if not unconfigurepvlan(sw_hdl,pvlan,pvlan_args,self.log):
                                self.log.error('Unconfiguring PVLAN failed on {0} with {1}'.format(sw_hdl.name,pvlan_args))
                                return 0
        return 1

    def unconfigureSvi(self):
        result = 1
        self.log.info('Unconfiguring SVI interfaces')
        svi_dict=self.interface_config_dict['svi']
        for sw in svi_dict.keys():
            sw_hdl=self.hdl_dict[sw]
            sw_svi_dict=svi_dict[sw]
            for var in sw_svi_dict.keys():
                out = sw_hdl.configure('no interface vlan {0}'.format(var))
                if out != None:
                  result = 0
        return result

    def unconfigurePo(self):
        result = 1
        counter = 1
        self.log.info('Unconfiguring Port channel interfaces')
        old_cfg=rex.CONFIG_ERROR_LIST
        rex.CONFIG_ERROR_LIST=rex.CONFIG_ERROR_LIST+'|fail'
        po_dict=self.interface_config_dict['portchannel']
        for sw in po_dict.keys():
            sw_hdl=self.hdl_dict[sw]
            sw_po_dict=po_dict[sw]
            for var in sw_po_dict.keys():
                i = 0
                while i == 0 :
                  self.log.info('Sleeping for 30 seconds for PO member to get update')
                  print('Sleeping for 30 seconds...')
                  time.sleep(30)
                  out = sw_hdl.configure('no interface {0}'.format(var),verifySuccess=True)
                  if out == None and not sw_hdl.errFlag:
                    i = 1
                  else:
                    print('Sleeping for 10 seconds...')
                    time.sleep(10)
                    counter += 1
                  if counter == 10:
                    result = 0
                    continue
        rex.CONFIG_ERROR_LIST=old_cfg
        return result

    def unconfigureLoopback(self):
        result = 1
        self.log.info('Unconfiguring Loopback interfaces')
        lo_dict=self.interface_config_dict['loopback']
        for sw in lo_dict.keys():
            sw_hdl=self.hdl_dict[sw]
            sw_lo_dict=lo_dict[sw]
            for var in sw_lo_dict.keys():
                out = sw_hdl.configure('no interface {0}'.format(var))
                if out != None:
                  result = 0
        return result

    def unconfigureEthernet(self):
        result = 1
        self.log.info('Unconfiguring Ethernet interfaces')
        eth_dict=self.interface_config_dict['ethernet']
        for sw in eth_dict.keys():
            sw_hdl=self.hdl_dict[sw]
            sw_eth_dict=eth_dict[sw]
            for var in sw_eth_dict.keys():
                print('eth config {0}'.format(var))
                if var == 'breakout_ports':
                    continue
                else:
                    out = sw_hdl.configure('default interface {0}'.format(var))
                    if out != None:
                      result = 0
        return result


class verifyInterface(object):
    '''Class to validate interface_config_dict, verify interface status'''

    def __init__(self,log,switch_hdl_dict=None,node_dict=None,interface_config_dict=None):

        self.log=log

        try:
            self.result
        except:
            self.result='pass'

        if not node_dict:
            try:
                self.node_dict
            except:
                self.log.error('node_dict not available')
                self.result='fail'
                return
        else:
            self.node_dict=node_dict

        if not switch_hdl_dict:
            try:
                self.hdl_dict
            except:
                self.log.error('switch_hdl_dict not available')
                self.result='fail'
                return
        else:
            self.hdl_dict=switch_hdl_dict

        if not interface_config_dict:
            try:
                self.interface_config_dict
            except:
                self.log.error('interface_config_dict not available')
                self.result='fail'
                return
        else:
            self.interface_config_dict=interface_config_dict

        if not hasattr(self, 'verify_connectivity_only'):
            self.verify_connectivity_only=False

        self.validateInterfaceDict()


    def validateGrammar(self,arggrammar,node,intf):
        '''Validate interface parameters for given grammar, node, and interface.'''

        if intf.strip()=='global_config':
            # global configurations
            for global_cfg_type in self.interface_config_dict[node]['global_config']:
                if global_cfg_type=='pvlan':
                    global_pvlan_params=self.interface_config_dict[node]['global_config']['pvlan']
                    global_pvlan_grammar=arggrammar['global_config']['pvlan']
                    global_pvlan_options=parserutils_lib.argsToCommandOptions(\
                        global_pvlan_params,global_pvlan_grammar,self.log)
                    if not global_pvlan_options.VALIDARGS:
                        testResult('fail','interface_config_dict global pvlan config has invalid ' + \
                            'parameters for node {0}'.format(node),self.log)
                        sys.exit()
                    self.global_config_dict[node]['pvlan']={}
                    for key in global_pvlan_options.KEYS:
                        self.global_config_dict[node]['pvlan'][key]=getattr(global_pvlan_options,key)
                if global_cfg_type=='vxlan':
                    global_vxlan_params=self.interface_config_dict[node]['global_config']['vxlan']
                    global_vxlan_grammar=arggrammar['global_config']['vxlan']
                    global_vxlan_options=parserutils_lib.argsToCommandOptions(\
                        global_vxlan_params,global_vxlan_grammar,self.log)
                    if not global_vxlan_options.VALIDARGS:
                        testResult('fail','interface_config_dict global vxlan config has invalid ' + \
                            'parameters for node {0}'.format(node),self.log)
                        sys.exit()
                    self.global_config_dict[node]['vxlan']={}
                    for key in global_vxlan_options.KEYS:
                        self.global_config_dict[node]['vxlan'][key]=getattr(global_vxlan_options,key)
            return

        intf_list=strtoexpandedlist(intf)
        if re.search('all',intf.strip(),re.I) or len(intf_list)>1: 
            intf_type='range'
        elif len(intf_list)==1:
            intf_type='individual'

        if 'base_config' in self.interface_config_dict[node][intf]:
            if not self.interface_config_dict[node][intf]['base_config']:
                base_params='-admin_state noshut'
            else:
                base_params=self.interface_config_dict[node][intf]['base_config']
            if intf_type=='range':
                base_config_grammar=dict(arggrammar['base_config'],\
                    **arggrammar['base_config_range'])
            else:
                base_config_grammar=arggrammar['base_config']
            base_options=parserutils_lib.argsToCommandOptions(\
                base_params,base_config_grammar,self.log)
            if not base_options.VALIDARGS:
                testResult('fail','interface_config_dict base_config has invalid ' + \
                    'parameters for node {0} interfaces {1}'.format(node,intf),self.log)
                sys.exit()
        else:
            # Doing a no-shut by default even if not specified in input file 
            # Its debatable whether to do it or not
            base_params='-admin_state noshut'
            if intf_type=='range':
                base_config_grammar=dict(arggrammar['base_config'],\
                    **arggrammar['base_config_range'])
            else:
                base_config_grammar=arggrammar['base_config']
            base_options=parserutils_lib.argsToCommandOptions(\
                base_params,base_config_grammar,self.log)
            if not base_options.VALIDARGS:
                testResult('fail','interface_config_dict base_config has invalid ' + \
                    'parameters for node {0} interfaces {1}'.format(node,intf),self.log)
                sys.exit()

        if 'switchport' in self.interface_config_dict[node][intf]:
            switchport_params=self.interface_config_dict[node][intf]['switchport']
            if intf_type=='range':
                switchport_grammar=dict(arggrammar['switchport'],\
                    **arggrammar['switchport_range'])
            else:
                switchport_grammar=arggrammar['switchport']
            switchport_options=parserutils_lib.argsToCommandOptions(\
                switchport_params,switchport_grammar,self.log)
            if not switchport_options.VALIDARGS:
                testResult('fail','interface_config_dict switchport config has invalid ' + \
                    'parameters for node {0} interfaces {1}'.format(node,intf),self.log)
                sys.exit()

        if 'ipv4' in self.interface_config_dict[node][intf]:
            ipv4_params=self.interface_config_dict[node][intf]['ipv4']
            if intf_type=='range':
                ipv4_grammar=dict(arggrammar['ipv4'],\
                    **arggrammar['ipv4_range'])
            else:
                ipv4_grammar=arggrammar['ipv4']
            ipv4_options=parserutils_lib.argsToCommandOptions(
                ipv4_params,ipv4_grammar,self.log)
            if not ipv4_options.VALIDARGS:
                testResult('fail','interface_config_dict ipv4 config has invalid ' + \
                    'parameters for node {0} interfaces {1}'.format(node,intf),self.log)
                sys.exit()

        if 'ipv6' in self.interface_config_dict[node][intf]:
            ipv6_params=self.interface_config_dict[node][intf]['ipv6']
            if intf_type=='range':
                ipv6_grammar=dict(arggrammar['ipv6'],\
                    **arggrammar['ipv6_range'])
            else:
                ipv6_grammar=arggrammar['ipv6']
            ipv6_options=parserutils_lib.argsToCommandOptions(\
                ipv6_params,ipv6_grammar,self.log)
            if not ipv6_options.VALIDARGS:
                testResult('fail','interface_config_dict ipv6 config has invalid ' + \
                    'parameters for node {0} interfaces {1}'.format(node,intf),self.log)
                sys.exit()

        # Check if interface is individual or range
        if re.search('all',intf.strip(),re.I):
            # All interfaces
            intf_type='all'
            intf_range='all'
            # Get all interfaces from the switch
            intf_list=utils.getInterfaceList(self.hdl_dict[node],self.log)
            intf_list=filter(re.compile('^(?!mgmt)').search,intf_list)

            # Get all the logical interfaces from the input file
            # since they may not have been configured already
            for intf in self.interface_config_dict[node]:
                if re.search('Po[0-9]+|Vlan[0-9]+|Lo[0-9]+',intf,re.I):
                    intf_list.append(intf)
        else:
            intf_list=strtoexpandedlist(intf)
            if len(intf_list)==1:
                # Individual interface
                intf_type='individual'
            elif len(intf_list)>1:
                # Interface range
                intf_type='range'
                intf_range=intf

        for intf in intf_list:
            intf=utils.normalizeInterfaceName(self.log,intf.strip())
            # Initialize the structure for individual interface
            try:
                self.interface_dict[node][intf]
            except:
                self.interface_dict[node][intf]={}
                self.interface_dict[node][intf]['base']={}
                self.interface_dict[node][intf]['switchport']={}
                self.interface_dict[node][intf]['ipv4']={}
                self.interface_dict[node][intf]['ipv6']={}

            # Initialize the structure for range interface
            # commenting the below line: not allowing iterative params for "all"
            #if intf_type=='range' or intf_type=='all':
            if intf_type=='range':
                # this will be needed to process iterative parameters later
                # ex: like incrementing ip network etc
                try:
                    self.interface_dict[node]['range']
                except:
                    self.interface_dict[node]['range']={}
                try:
                    self.interface_dict[node]['range'][intf_range]
                except:
                    self.interface_dict[node]['range'][intf_range]={}
                    self.interface_dict[node]['range'][intf_range]['base']={}
                    self.interface_dict[node]['range'][intf_range]['switchport']={}
                    self.interface_dict[node]['range'][intf_range]['ipv4']={}
                    self.interface_dict[node]['range'][intf_range]['ipv6']={}

            # skip config parameters if it already exists for the port 
            # store only iterative params in interface_dict[node]['range']
            try:
                base_options
            except:
                self.log.info('No base config for {0} {1}'.format(node,intf))
            else:
                for key in base_options.KEYS:
                    # copy attributes to individual interfaces that are not range specific
                    if key not in arggrammar['base_config_range']:
                        try:
                            self.interface_dict[node][intf]['base'][key]
                        except:
                            self.interface_dict[node][intf]['base'][key]=getattr(base_options,key)
                    if intf_type=='range' and key in arggrammar['base_config_range']:
                        try:
                            self.interface_dict[node]['range'][intf_range]['base'][key]
                        except:
                            self.interface_dict[node]['range'][intf_range]['base'][key]=\
                                getattr(base_options,key)

            try:
                switchport_options
            except:
                self.log.info('No switchport config for {0} {1}'.format(node,intf))
            else:
                for key in switchport_options.KEYS:
                    # copy attributes to individual interfaces that are not range specific
                    if key not in arggrammar['switchport_range']:
                        try:
                            self.interface_dict[node][intf]['switchport'][key]
                        except:
                            self.interface_dict[node][intf]['switchport'][key]=getattr(switchport_options,key)
                    if intf_type=='range' and key in arggrammar['switchport_range']:
                        try:
                            self.interface_dict[node]['range'][intf_range]['switchport'][key]
                        except:
                            self.interface_dict[node]['range'][intf_range]['switchport'][key]=\
                                getattr(switchport_options,key)

            try:
                ipv4_options
            except:
                self.log.info('No ipv4 config for {0} {1}'.format(node,intf))
            else:
                for key in ipv4_options.KEYS:
                    # copy attributes to individual interfaces that are not range specific
                    if key not in arggrammar['ipv4_range']:
                        try:
                            self.interface_dict[node][intf]['ipv4'][key]
                        except:
                            self.interface_dict[node][intf]['ipv4'][key]=getattr(ipv4_options,key)
                    if intf_type=='range' and key in arggrammar['ipv4_range']:
                        try:
                            self.interface_dict[node]['range'][intf_range]['ipv4'][key]
                        except:
                            self.interface_dict[node]['range'][intf_range]['ipv4'][key]=\
                                getattr(ipv4_options,key)

            try:
                ipv6_options
            except:
                self.log.info('No ipv6 config for {0} {1}'.format(node,intf))
            else:
                for key in ipv6_options.KEYS:
                    # copy attributes to individual interfaces that are not range specific
                    if key not in arggrammar['ipv6_range']:
                        try:
                            self.interface_dict[node][intf]['ipv6'][key]
                        except:
                            self.interface_dict[node][intf]['ipv6'][key]=getattr(ipv6_options,key)
                    if intf_type=='range' and key in arggrammar['ipv6_range']:
                        try:
                            self.interface_dict[node]['range'][intf_range]['ipv6'][key]
                        except:
                            self.interface_dict[node]['range'][intf_range]['ipv6'][key]=\
                                getattr(ipv6_options,key)


    def validateInterfaceDict(self):
        '''Validate the interface_config_dict input with arggrammar

        The input should be in the format as specified in the comments for bringupInterface
        '''

        # More options need to be added to support all interface parameters
        arggrammar={}
        arggrammar['base_config']={}
        arggrammar['switchport']={}
        arggrammar['ipv4']={}
        arggrammar['ipv6']={}
        arggrammar['base_config_range']={}
        arggrammar['switchport_range']={}
        arggrammar['ipv4_range']={}
        arggrammar['ipv6_range']={}
        arggrammar['global_config']={}
        base_config_grammar=arggrammar['base_config']
        switchport_grammar=arggrammar['switchport']
        ipv4_grammar=arggrammar['ipv4']
        ipv6_grammar=arggrammar['ipv6']
        base_config_range_grammar=arggrammar['base_config_range']
        switchport_range_grammar=arggrammar['switchport_range']
        ipv4_range_grammar=arggrammar['ipv4_range']
        ipv6_range_grammar=arggrammar['ipv6_range']
        global_config_grammar=arggrammar['global_config']

        # base config
        base_config_grammar['members']='-type str -mandatoryargs po_mode -format {0}'.format(rex.PHYSICAL_INTERFACE_RANGE)
        base_config_grammar['po_mode']='-type str -choices ["on","active","passive"] -mandatoryargs members'
        base_config_grammar['mac_addr']='-type str -format {0}'.format(rex.MACADDR)
        base_config_grammar['mtu']='-type str -format [0-9]+'
        base_config_grammar['description']='-type str'
        base_config_grammar['speed']='-type str -format [0-9]+'
        base_config_grammar['nonegotiate']='-type bool'
        base_config_grammar['duplex']='-type str'
        base_config_grammar['flowcontrol']='-type str'
        base_config_grammar['load_interval']='-type list' #Format: [(1,30),(2,300),(3,200)]
        base_config_grammar['admin_state']='-type str -choices ["shut","noshut"] -default noshut'
        base_config_grammar['link_debounce']='-type str -format [0-9]+'
        base_config_grammar['logging']='-type str -choices ["link-status","trunk-status"]'
        base_config_grammar['buffer_boost']='-type bool'
        # sub-intf related
        base_config_grammar['encap_vlan']='-type str -format [0-9]+'
        # vxlan related
        base_config_grammar['overlay_encap']='-type str -default vxlan'
        base_config_grammar['source_intf']='-type str -format {0}'.format(rex.INTERFACE_NAME)
        base_config_grammar['mcast_vnid_map']='-type list'
        # iterative parameters
        base_config_range_grammar['start_encap_vlan']='-type str -mandatoryargs step_encap_vlan -format [0-9]+'
        base_config_range_grammar['step_encap_vlan']='-type str -format [0-9]+'

        # switchport config
        switchport_grammar['mode']='-type str -choices ["access","trunk","pvlan_promisc","pvlan_host","pvlan_promisc_trunk","pvlan_sec_trunk","monitor","dot1q-tunnel"] -required True'
        switchport_grammar['vlan_id']='-type str -format [0-9,-]+'
        switchport_grammar['allowed_vlan_list']='-type str -format [0-9,-]+'
        switchport_grammar['native_vlan']='-type str -format [0-9]+'
        switchport_grammar['pvlan_mapping']='-type list' #Format: [{10:'11-13,15'}]
        switchport_grammar['pvlan_host_assoc']='-type list' #Format: [{10:'11-13,15'}]
        switchport_grammar['pvlan_mapping_trunk']='-type list' #Format: [{10:'11-13,15'},{20:'23,24'}]
        switchport_grammar['pvlan_allowed_vlan_list']='-type str -format [0-9,-]+'
        switchport_grammar['pvlan_assoc_trunk']='-type list' #Format: [{10:'11'},{20:'23,24'}]
        switchport_grammar['stp_port_type']='-type str -choices ["edge","edge_trunk"]'
        switchport_grammar['stp_bpdufilter']='-type bool'

        # ipv4 config
        ipv4_grammar['ipv4_addr']='-type str -mandatoryargs ipv4_prf_len -format {0}'.format(rex.IPv4_ADDR)
        ipv4_grammar['ipv4_prf_len']='-type str -mandatoryargs ipv4_addr -format [0-9]+'
        ipv4_grammar['secondary_ipv4']='-type list -mandatoryargs ipv4_addr' #Format: [('1.2.3.4',24),('192.168.1.1',24)]
        ipv4_grammar['vrf']='-type str -default default'
        ipv4_grammar['proxy_arp']='-type bool'
        ipv4_grammar['redirects']='-type bool'
        ipv4_grammar['directed_broadcast']='-type bool'
        ipv4_grammar['urpf']='-type str -choices ["any","rx"]'
        ipv4_grammar['static_arp']='-type list' #Format: [('1.2.3.4','aaaa.bbbb.cccc'),('6.7.8.9','dddd.eeee.ffff')]
        ipv4_grammar['igmp_group_timeout']='-type int'
        ipv4_grammar['mac_addr']='-type str'
        # iterative parameters
        ipv4_range_grammar['start_ipv4_addr']='-type str -mandatoryargs start_ipv4_prf_len -format {0}'.format(rex.IPv4_ADDR)
        ipv4_range_grammar['start_ipv4_prf_len']='-type str -mandatoryargs step_ipv4_addr -format [0-9]+'
        ipv4_range_grammar['step_ipv4_addr']='-type str -mandatoryargs start_ipv4_addr -format {0}'.format(rex.IPv4_ADDR)
        ipv4_range_grammar['step_ipv4_prf_len']='-type str -format [0-9]+ -default 0'
        # have a little bit of a hack above to make params mandatory

        # ipv6 config
        ipv6_grammar['ipv6_addr']='-type str -mandatoryargs ipv6_prf_len -format {0}'.format(rex.IPv6_ADDR)
        ipv6_grammar['ipv6_prf_len']='-type str -mandatoryargs ipv6_addr -format [0-9]+'
        ipv6_grammar['vrf']='-type str -default default'
        ipv6_grammar['secondary_ipv6']='-type list -mandatoryargs ipv6_addr' #Format: [('2001::1:1:1:1',64),('2001::2:2:2:2',96)]
        ipv6_grammar['redirects']='-type bool'

        # iterative parameters
        ipv6_range_grammar['start_ipv6_addr']='-type str -mandatoryargs start_ipv6_prf_len -format {0}'.format(rex.IPv6_ADDR)
        ipv6_range_grammar['start_ipv6_prf_len']='-type str -mandatoryargs step_ipv6_addr -format [0-9]+'
        ipv6_range_grammar['step_ipv6_addr']='-type str -mandatoryargs start_ipv6_addr -format {0}'.format(rex.IPv6_ADDR)
        ipv6_range_grammar['step_ipv6_prf_len']='-type str -format [0-9]+ -default 0'
        # have a little bit of a hack above to make params mandatory

        # global config
        global_config_grammar['pvlan']={}
        global_pvlan_grammar=global_config_grammar['pvlan']
        global_pvlan_grammar['community_vlans']='-type str'
        global_pvlan_grammar['isolated_vlans']='-type str'
        global_pvlan_grammar['associations']='-type list'

        global_config_grammar['vxlan']={}
        global_vxlan_grammar=global_config_grammar['vxlan']
        global_vxlan_grammar['udp_port']='-type str -format [0-9]+'
        global_vxlan_grammar['vnid_vlan_map']='-type list' #Format: [('10000-10013','1000-1010,1201-1203')]


        global_config_grammar['stp']={}
        global_stp_grammar=global_config_grammar['stp']

        self.interface_dict={}
        self.global_config_dict={}
        # Parse the interface configs in interface_config_dict
        if not self.interface_config_dict:
            self.interface_config_dict={}
        for node in self.interface_config_dict:
            if node=='logical_interconnect':
                continue
            self.interface_dict[node]={}
            self.global_config_dict[node]={}
            input_intf_list=[]
            if not self.interface_config_dict[node]:
                self.interface_config_dict[node]={}
            for intf in self.interface_config_dict[node]:
                if re.search('^{0}$'.format(rex.INTERFACE_NAME),intf.strip()):
                    # Individual interface
                    input_intf_list.append(intf)
                    self.validateGrammar(arggrammar,node,intf)

            for intf_range in self.interface_config_dict[node]:
                if re.search('^{0}$'.format(rex.INTERFACE_RANGE),intf_range.strip()) and \
                    not re.search('^{0}$'.format(rex.INTERFACE_NAME),intf_range.strip()):
                    # Interface range
                    input_intf_list.append(intf_range)
                    self.validateGrammar(arggrammar,node,intf_range)

            for keyword in self.interface_config_dict[node]:
                if keyword.strip()=='all':
                    # All interfaces on this node
                    input_intf_list.append(keyword)
                    self.validateGrammar(arggrammar,node,keyword)
                if keyword.strip()=='global_config':
                    # global configuration on this node
                    input_intf_list.append(keyword)
                    self.validateGrammar(arggrammar,node,keyword)

            if not self.interface_dict[node]:
                self.log.info('No interfaces specified in input file for {0}'.format(node))

            if len(input_intf_list)!=len(self.interface_config_dict[node]):
                # unknown interface type
                testResult('fail','Unknown interface name in interface_config_dict',self.log)

        if not self.interface_dict and not self.verify_connectivity_only:
            testResult('fail','No interfaces specified in input file for any node',self.log)

        # maintain per node list of interfaces for easy reference
        self.intf_list={}
        self.vlan_intf_list={}
        self.lo_intf_list={}
        self.po_intf_list={}
        self.sub_intf_list={}
        self.nve_intf_list={}
        self.intf_range_list={}
        for node in self.interface_dict:
            self.intf_list[node]=self.interface_dict[node].keys()

            self.vlan_intf_list[node]=filter(re.compile('^(?:Vlan)').search,self.intf_list[node])
            self.intf_list[node]=filter(re.compile('^(?!Vlan)').search,self.intf_list[node])

            self.sub_intf_list[node]=filter(re.compile('^(?:Eth[0-9/]+\.[0-9]+)').search,self.intf_list[node])
            self.intf_list[node]=filter(re.compile('^(?!Eth[0-9/]+\.[0-9]+)').search,self.intf_list[node])

            self.sub_intf_list[node].extend(filter(re.compile('^(?:[Pp]o[0-9]+\.[0-9]+)').search,self.intf_list[node]))
            self.intf_list[node]=filter(re.compile('^(?![Pp]o[0-9]+\.[0-9]+)').search,self.intf_list[node])

            self.lo_intf_list[node]=filter(re.compile('^(?:Lo)').search,self.intf_list[node])
            self.intf_list[node]=filter(re.compile('^(?!Lo)').search,self.intf_list[node])

            self.po_intf_list[node]=filter(re.compile('^(?:[Pp]o[0-9]+)').search,self.intf_list[node])
            self.intf_list[node]=filter(re.compile('^(?![Pp]o[0-9]+)').search,self.intf_list[node])

            self.nve_intf_list[node]=filter(re.compile('^(?:Nve)').search,self.intf_list[node])
            self.intf_list[node]=filter(re.compile('^(?!Nve)').search,self.intf_list[node])

            if 'range' in self.interface_dict[node].keys():
                self.intf_range_list[node]=self.interface_dict[node]['range'].keys()
                self.intf_list[node]=filter(re.compile('^(?!range)').search,self.intf_list[node])
                # whats left in intf_list at this point should all be physical interfaces 
            else:
                self.intf_range_list[node]=[]


        # Build physical peers info
        # Parse the physical interconnections from node_dict
        for node in self.node_dict:
            #if re.search('-device_type\s+(?:itgen|fanout)',params):
            #    self.log.info('Skip gathering peer info for node {0}'.format(node))
            #    continue
            if 'interfaces' not in self.node_dict[node] or\
                not self.node_dict[node]['interfaces'] or\
                not len(self.node_dict[node]['interfaces']):
                self.log.info('No interconnections specified for {0}'.format(node))
                continue
            for intf_name in self.node_dict[node]['interfaces']:
                # TODO: Think about enabling a range of interfaces with incremental peer connection
                if re.search('interface[0-9]+',intf_name,re.I):
                    # This is basic_sanity input file format where key is logical name
                    interconnect_grammar={}
                    interconnect_grammar['name']='-type str -required True'
                    interconnect_grammar['peer_device']='-type str -required True'
                    interconnect_grammar['peer_interface']='-type str -required True'
                    interconnect_grammar['flags']=['ignore_unknown_key']
                else:
                    # Alternate is the SIT format where key is the interface itself
                    interconnect_grammar={}
                    interconnect_grammar['peer_device']='-type str -required True'
                    interconnect_grammar['peer_interface']='-type str -required True'
                    interconnect_grammar['flags']=['ignore_unknown_key']

                interconnect_params=self.node_dict[node]['interfaces'][intf_name]
                interconnect=parserutils_lib.argsToCommandOptions(\
                    interconnect_params,interconnect_grammar,self.log)
                if not interconnect.VALIDARGS:
                    testResult('fail','node_dict interfaces config has invalid ' + \
                        'parameters for node {0} interfaces {1}'.format(node,intf_name),self.log)
                    sys.exit()

                if re.search('interface[0-9]+',intf_name,re.I):
                    intf=interconnect.name
                else:
                    intf=intf_name

                intf=utils.normalizeInterfaceName(self.log,intf.strip())

                if node not in self.interface_dict:
                    self.interface_dict[node]={}
                    self.intf_list[node]=[]
                    self.vlan_intf_list[node]=[]
                    self.sub_intf_list[node]=[]
                    self.lo_intf_list[node]=[]
                    self.po_intf_list[node]=[]
                    self.nve_intf_list[node]=[]
                    self.intf_range_list[node]=[]
                    self.global_config_dict[node]={}

                if intf not in self.interface_dict[node]:
                    self.interface_dict[node][intf]={}
                    if self.verify_connectivity_only:
                        self.intf_list[node].append(intf)
                        self.interface_dict[node][intf]['base']={}
                        self.interface_dict[node][intf]['base']['admin_state']='noshut'

                peer_device=interconnect.peer_device
                peer_interface=utils.normalizeInterfaceName(self.log,interconnect.peer_interface)
                peer_type='UNKNOWN'
                if peer_device in self.node_dict and 'params' in self.node_dict[peer_device]:
                    params=self.node_dict[peer_device]['params']
                    peer_type=re.search('-device_type\s+([^\s]+)',params)
                    if peer_type:
                        peer_type=peer_type.group(1)

                self.interface_dict[node][intf]['physical_peers']={}
                self.interface_dict[node][intf]['physical_peers'][peer_device]={}
                self.interface_dict[node][intf]['physical_peers']\
                    [peer_device]['peer_interface']=peer_interface
                self.interface_dict[node][intf]['physical_peers']\
                    [peer_device]['peer_type']=peer_type


        # Build port-channel peers info
        # Parse Po in interface_dict, get peer info from members and from there the Po
        for node in self.interface_dict:
            for intf in self.po_intf_list[node]:
                members=self.interface_dict[node][intf]['base']['members']
                first_member=strtoexpandedlist(members)[0]
                peer_info=self.getPeerInfo('-node {0} -interface {1}'.format(node,intf))
                if peer_info:
                    peer_device=peer_info[node][intf].keys()[0]
                    peer_interface=peer_info[node][intf][peer_device]['peer_interface']
                    # TODO: when configuring po, maintain per member info for po#
                    # but for fanout we may not have that info. how do we do that?
                    # TODO: same way maintain vlan membership per member port

        # Build logical peers info
        # Parse the logical interconnections from interface_dict
        # This below is used to specify itgen peers or SVI peers
        if 'logical_interconnect' not in self.interface_config_dict or\
            not len(self.interface_config_dict['logical_interconnect']):
            self.log.info('logical_interconnect is not provided')
            nodes_list=[]
        else:
            nodes_list=self.interface_config_dict['logical_interconnect'].keys()
        for node in nodes_list:
            for intf_name in self.interface_config_dict['logical_interconnect'][node]:
                # TODO: Think about enabling a range of interfaces with incremental peer connection
                interconnect_grammar={}
                interconnect_grammar['logical_peers']='-type list -required True'
                # Assume 'node06' to be itgen in the below examples
                # Format1: Vlan10: -logical_peers [('node05','Vlan10'),('node02','Vlan10'),('node06','eth1,eth2,eth3')]
                # Format2:   Po11: -logical_peers [('node06','eth4')]
                # Format3: Eth1/1: -logical_peers [('node06','eth5')]
                interconnect_params=self.interface_config_dict['logical_interconnect'][node][intf_name]
                interconnect=parserutils_lib.argsToCommandOptions(\
                    interconnect_params,interconnect_grammar,self.log)
                if not interconnect.VALIDARGS:
                    testResult('fail','logical_interconnect config has invalid ' + \
                        'parameters for node {0} interfaces {1}'.format(node,intf_name),self.log)
                    sys.exit()

                intf=intf_name

                intf=utils.normalizeInterfaceName(self.log,intf.strip())

                if node not in self.interface_dict:
                    self.interface_dict[node]={}
                    self.intf_list[node]=[]
                    self.vlan_intf_list[node]=[]
                    self.sub_intf_list[node]=[]
                    self.lo_intf_list[node]=[]
                    self.po_intf_list[node]=[]
                    self.nve_intf_list[node]=[]
                    self.intf_range_list[node]=[]
                    self.global_config_dict[node]={}

                if intf not in self.interface_dict[node]:
                    self.interface_dict[node][intf]={}

                self.interface_dict[node][intf]['logical_peers']={}
                for peer_device,peer_interface in interconnect.logical_peers:
                    peer_interface=utils.normalizeInterfaceName(self.log,peer_interface)
                    if peer_device in self.node_dict:
                        params=self.node_dict[peer_device]['params']
                        peer_type=re.search('-device_type\s+([^\s]+)',params)
                        if peer_type:
                            peer_type=peer_type.group(1)
                        else:
                            peer_type="UNKNOWN"
                    else:
                        peer_type="UNKNOWN"

                    self.interface_dict[node][intf]['logical_peers'][peer_device]={}
                    self.interface_dict[node][intf]['logical_peers']\
                        [peer_device]['peer_interface']=peer_interface
                    self.interface_dict[node][intf]['logical_peers']\
                        [peer_device]['peer_type']=peer_type



    def verifyInterfaceBringup(self):
        '''Verify all of interface_config_dict parameters are configured and up.'''

        try:
            self.interface_dict
        except:
            testResult('fail','Interface bringup has not been done. Cannot verify',self.log)
            return

        for node in self.interface_dict:
            if re.search('itgen|fanout',node):
                continue
            if node not in self.node_dict:
                continue
            params=self.node_dict[node]['params']
            if re.search('-device_type\s+(?:itgen|fanout)',params,re.I):
                continue

            hdl=self.hdl_dict[node]

            # Verify physical interfaces only (for admin_state)
            if self.verify_connectivity_only:
                for intf in self.intf_list[node]:
                    self.individualVerify(node,intf)
                continue

            if self.vlan_intf_list[node]:
                # Verify feature interface-vlan
                if verify_lib.verifyFeatureState(hdl,self.log,\
                    '-feature interface-vlan').result=='pass':
                    self.log.info('Feature interface-vlan is enabled successfully')
                else:
                    self.log.error('Feature interface-vlan is not enabled properly')
                    testResult('fail','Feature interface-vlan is not enabled properly',self.log)
    
                # Verify vlans for SVI interfaces
                v_list=[re.search('([0-9]+)',vlan,re.I).group(1) for vlan in self.vlan_intf_list[node]]
                vlans=','.join(v_list)
                if verify_lib.verifyVlans(hdl,self.log,'-vlans {0}'.format(vlans)).result=='pass':
                    self.log.info('Vlans {0} are successfully created'.format(vlans))
                else:
                    self.log.error('Vlans {0} are not active, creation failed'.format(vlans))
                    testResult('fail','Vlans {0} are not active'.format(vlans),self.log)


            # Verify SVI 
            for intf in self.vlan_intf_list[node]:
                self.individualVerify(node,intf)

            # Verify sub-intfs
            for intf in self.sub_intf_list[node]:
                self.individualVerify(node,intf)

            # Verify loopback 
            for intf in self.lo_intf_list[node]:
                self.individualVerify(node,intf)

            # Verify port-channel
            for intf in self.po_intf_list[node]:
                self.individualVerify(node,intf)

            # Verify nve 
            for intf in self.nve_intf_list[node]:
                self.individualVerify(node,intf)

            # Verify physical interfaces
            for intf in self.intf_list[node]:
                self.individualVerify(node,intf)

            #TODO: process iterative parameters for ranges
            #for intf in self.intf_range_list[node]:
                #self.rangeVerify(node,intf)

        self.verifyInterfaceCounters()


    def individualVerify(self,node,intf):
        '''Verify interface parameters for given interface.'''

        self.log.info('Verifying interface {0} on node {1}'.format(intf,node))

        hdl=self.hdl_dict[node]

        if 'base_config' in self.config_type:
            # Verify base
            if 'base' in self.interface_dict[node][intf].keys() and \
                len(self.interface_dict[node][intf]['base'].keys()):
                self.baseConfigAndVerify(node,intf,'-mode verify')

        if self.verify_connectivity_only:
            return

        if 'switchport' in self.config_type:
            # Verify switchport
            if 'switchport' in self.interface_dict[node][intf].keys() and \
                len(self.interface_dict[node][intf]['switchport'].keys()):
                self.switchportConfigAndVerify(node,intf,'-mode verify')

        if 'ipv4' in self.config_type:
            # Verify ipv4
            if 'ipv4' in self.interface_dict[node][intf].keys() and \
                len(self.interface_dict[node][intf]['ipv4'].keys()):
                self.ipv4ConfigAndVerify(node,intf,'-mode verify')

        if 'ipv6' in self.config_type:
            # Verify ipv6
            if 'ipv6' in self.interface_dict[node][intf].keys() and \
                len(self.interface_dict[node][intf]['ipv6'].keys()):
                self.ipv6ConfigAndVerify(node,intf,'-mode verify')


    def baseConfigAndVerify(self,node,intf,*args):
        '''Configure or verify base interface parameters for given interface.'''

        arggrammar={}
        arggrammar['mode']='-type str -choices ["config","verify"] -default config'
        options=parserutils_lib.argsToCommandOptions(args,arggrammar,self.log )
        if not options.VALIDARGS:
            testResult('fail','Invalid arguments to baseConfigAndVerify',self.log)
            sys.exit()

        if options.mode=='verify':
            verify_mode=True
        else:
            verify_mode=False

        hdl=self.hdl_dict[node]

        params_list=self.interface_dict[node][intf]['base'].keys()

        if self.verify_connectivity_only:
            params_list=['admin_state']

        # Process port-channel member config first to avoid having inconsistencies
        # between the member ports and the port-channel
        if 'members' in params_list and re.search('[pP]o[0-9]+',intf):
            members=self.interface_dict[node][intf]['base']['members']
            po_mode=self.interface_dict[node][intf]['base']['po_mode']
            if self.interface_dict[node][intf]['base']['admin_state']=='shut':
                admin_state='shutdown'
            elif self.interface_dict[node][intf]['base']['admin_state']=='noshut':
                admin_state='no shutdown'

            if po_mode=='active':
                if not verify_mode:
                    if not self.generate_ascii_only:
                        bringup_lib.configFeature(hdl,self.log,'-feature lacp')
                    self.ascii_cfg_dict[node]['global'].append('feature lacp')
                else:
                    if verify_lib.verifyFeatureState(hdl,self.log,'-feature lacp').result=='fail':
                        testResult('fail','Feature lacp not enable properly',self.log)
            if not verify_mode:
                po_number=re.search('([0-9]+)',intf).group(1)

                # FEX ports would be in switchport mode by default (configured in fex_lib)
                # Determine if the member is a HIF port then config PO to be in switchport first
                member_intf=strtoexpandedlist(members)[0]
                if re.search('Eth[0-9]{3}/[0-9]/[0-9]+',normalizeInterfaceName(self.log,member_intf)):
                    cmds='''interface {0}
                              switchport
                              switchport mode access'''.format(intf)
                    if not self.generate_ascii_only:
                        hdl.configure(cmds)
                    cmd_list=map(str.strip,re.split('\n',cmds))
                    self.ascii_cfg_dict[node][intf].extend(cmd_list)
                    self.ascii_cfg_dict[node][intf]=list(set(self.ascii_cfg_dict[node][intf]))

                if 'buffer_boost' in params_list:
                    if self.interface_dict[node][intf]['base']['buffer_boost']==True:
                        buffer_boost_cmd='buffer-boost'
                    elif self.interface_dict[node][intf]['base']['buffer_boost']==False:
                        buffer_boost_cmd='no buffer-boost'
                    cmds='''interface {0}
                              {1}'''.format(members,buffer_boost_cmd)
                    if not self.generate_ascii_only:
                        hdl.configure(cmds)

                # For debug purposes
                hdl.iexec('show running int {0}'.format(intf))
                hdl.iexec('show running int {0}'.format(members))

                cmds='''interface {0}
                          {1}
                          channel-group {2} mode {3}'''.format(members,admin_state,po_number,po_mode)
                if not self.generate_ascii_only:
                    hdl.configure(cmds)
            else:
                po_memb_list=utils.getPortChannelMemberList(hdl,self.log,\
                    '-pc_nam {0}'.format(intf))
                po_memb_list=sorted(normalizeInterfaceName(self.log,po_memb_list))
                #po_memb_list.sort()
                members_list=sorted(normalizeInterfaceName(self.log,strtoexpandedlist(members)))
                #members_list.sort()
                if po_memb_list==members_list:
                    self.log.info('Port-channel membership for {0} is correct'.format(intf))
                else:
                    testResult('fail','PO membership for {0} is not correct'.format(intf),self.log)
            params_list=filter(re.compile('^(?!members)').search,params_list)
            params_list=filter(re.compile('^(?!po_mode)').search,params_list)
            params_list=filter(re.compile('^(?!buffer_boost)').search,params_list)

        # If the intf is a sub-interface then ensure the parent is already in l3 mode
        if 'encap_vlan' in params_list and re.search('[^\.]+\.[0-9]+',intf):
            if not verify_mode:
                parent_intf=re.search('([^\.]+)\.[0-9]+',intf).group(1)
                cmds='''interface {0}
                          no switchport'''.format(parent_intf)
                if not self.generate_ascii_only:
                    hdl.configure(cmds)
                cmd_list=map(str.strip,re.split('\n',cmds))
                self.ascii_cfg_dict[node][intf].extend(cmd_list)
                self.ascii_cfg_dict[node][intf]=list(set(self.ascii_cfg_dict[node][intf]))

        for param in self.interface_dict[node][intf]['base']:
            if self.verify_connectivity_only:
                if param!='admin_state':
                    continue
            # Gather common outputs for quicker verification
            if verify_mode:
                show_intf_output=hdl.iexec('show interface {0}'.format(intf))
            # Process each parameter and remove it from the params_list
            if param=='mac_addr':
                mac_addr=self.interface_dict[node][intf]['base']['mac_addr']
                if not verify_mode:
                    cmds='''interface {0}
                              no switchport
                              mac-address {1}'''.format(intf,mac_addr)
                    if not self.generate_ascii_only:
                        hdl.configure(cmds)
                    cmd_list=map(str.strip,re.split('\n',cmds))
                    self.ascii_cfg_dict[node][intf].extend(cmd_list)
                    self.ascii_cfg_dict[node][intf]=list(set(self.ascii_cfg_dict[node][intf]))
                else:
                    pass
                params_list=filter(re.compile('^(?!mac_addr)').search,params_list)
            if param=='mtu':
                mtu=self.interface_dict[node][intf]['base']['mtu']
                if not verify_mode:
                    cmds='''interface {0}
                              no switchport
                              mtu {1}'''.format(intf,mtu)
                    if not self.generate_ascii_only:
                        hdl.configure(cmds)
                    cmd_list=map(str.strip,re.split('\n',cmds))
                    self.ascii_cfg_dict[node][intf].extend(cmd_list)
                    self.ascii_cfg_dict[node][intf]=list(set(self.ascii_cfg_dict[node][intf]))
                else:
                    if re.search('MTU {0} bytes'.format(mtu),show_intf_output):
                        self.log.info('MTU is configured successfully for {0}'.format(intf))
                    else:
                        testResult('fail','MTU is not configured properly for {0}'.format(intf),self.log)
                params_list=filter(re.compile('^(?!mtu)').search,params_list)
            if param=='description':
                description=self.interface_dict[node][intf]['base']['description']
                if not verify_mode:
                    cmds='''interface {0}
                              description {1}'''.format(intf,description)
                    if not self.generate_ascii_only:
                        hdl.configure(cmds)
                    cmd_list=map(str.strip,re.split('\n',cmds))
                    self.ascii_cfg_dict[node][intf].extend(cmd_list)
                    self.ascii_cfg_dict[node][intf]=list(set(self.ascii_cfg_dict[node][intf]))
                else:
                    if re.search('Description: {0}'.format(description),show_intf_output):
                        self.log.info('Description is configured successfully for {0}'.format(intf))
                    else:
                        testResult('fail','Description is not configured properly for {0}'.format(intf),self.log)
                params_list=filter(re.compile('^(?!description)').search,params_list)
            if param=='buffer_boost':
                if self.interface_dict[node][intf]['base']['buffer_boost']==True:
                    buffer_boost_cmd='buffer-boost'
                elif self.interface_dict[node][intf]['base']['buffer_boost']==False:
                    buffer_boost_cmd='no buffer-boost'
                if not verify_mode:
                    cmds='''interface {0}
                              {1}'''.format(intf,buffer_boost_cmd)
                    if not self.generate_ascii_only:
                        hdl.configure(cmds)
                    cmd_list=map(str.strip,re.split('\n',cmds))
                    self.ascii_cfg_dict[node][intf].extend(cmd_list)
                    self.ascii_cfg_dict[node][intf]=list(set(self.ascii_cfg_dict[node][intf]))
                else:
                    pass
                params_list=filter(re.compile('^(?!buffer_boost)').search,params_list)
            if param=='speed':
                speed=self.interface_dict[node][intf]['base']['speed']
                if not verify_mode:
                    cmds='''interface {0}
                             speed {1}'''.format(intf,speed)
                    if not self.generate_ascii_only:
                        hdl.configure(cmds)
                    cmd_list=map(str.strip,re.split('\n',cmds))
                    self.ascii_cfg_dict[node][intf].extend(cmd_list)
                    self.ascii_cfg_dict[node][intf]=list(set(self.ascii_cfg_dict[node][intf]))
                else:
                    if int(speed) < 10000 and re.search('{0} Mb/s'.format(speed),show_intf_output):
                        self.log.info('speed is configured successfully for {0}'.format(intf))
                    elif re.search('{0} Gb/s'.format(int(speed)/1000),show_intf_output):
                        self.log.info('speed is configured successfully for {0}'.format(intf))
                    else:
                        testResult('fail','speed is not configured properly for {0}'.format(intf),self.log)
                params_list=filter(re.compile('^(?!speed)').search,params_list)
            if param=='nonegotiate':
                nonegotiate=self.interface_dict[node][intf]['base']['nonegotiate']
                if nonegotiate:
                    cmds='''interface {0}
                            no negotiate auto'''.format(intf)
                    if not self.generate_ascii_only:
                        hdl.configure(cmds)
                    cmd_list=map(str.strip,re.split('\n',cmds))
                    self.ascii_cfg_dict[node][intf].extend(cmd_list)
                    self.ascii_cfg_dict[node][intf]=list(set(self.ascii_cfg_dict[node][intf]))
                params_list=filter(re.compile('^(?!nonegotiate)').search,params_list)
            if param=='admin_state':
                if self.interface_dict[node][intf]['base']['admin_state']=='shut':
                    admin_state='shutdown'
                elif self.interface_dict[node][intf]['base']['admin_state']=='noshut':
                    admin_state='no shutdown'
                if not verify_mode:
                    cmds='''interface {0}
                             {1}'''.format(intf,admin_state)
                    if not self.generate_ascii_only:
                        hdl.configure(cmds)
                    cmd_list=map(str.strip,re.split('\n',cmds))
                    self.ascii_cfg_dict[node][intf].extend(cmd_list)
                    self.ascii_cfg_dict[node][intf]=list(set(self.ascii_cfg_dict[node][intf]))
                else:
                    peer_admin_state='unknown'
                    if re.search(rex.PHYSICAL_INTERFACE_NAME,intf) or re.search('[pP]o[0-9]+',intf):
                        # Check peer interconnection info for peer's admin_state
                        peer_info=self.getPeerInfo('-node {0} -interface {1} -admin_state'\
                            .format(node,intf))
                        if peer_info:
                            peer_device=peer_info[node][intf].keys()[0]
                            if 'admin_state' in peer_info[node][intf][peer_device] and \
                                peer_info[node][intf][peer_device]['admin_state']:
                                # For peer itgen/fanout devices we may not have admin_state info
                                peer_admin_state=peer_info[node][intf][peer_device]['admin_state']
                            if 'peer_interface' in peer_info[node][intf][peer_device] and \
                                peer_info[node][intf][peer_device]['peer_interface']:
                                peer_interface=peer_info[node][intf][peer_device]['peer_interface']
                    # If peer info says "shut" then skip link status verify
                    # If peer info unavailable, then assume the peer is enabled
                    # and so check for link up. Ex: fanout switch/ itgen port etc
                    if admin_state=='no shutdown' and peer_admin_state!='shut':
                        # TODO: This is a very large time for link up. This is temporary for EOR
                        if verify_lib.verifyInterfaceStatus(hdl,self.log,\
                            '-interfaces {0} -iteration 12 -interval 5'\
                            .format(intf)).result=='fail':
                            testResult('fail','Interface {0} is not up'.format(intf),self.log)
                        else:
                            if re.search(rex.PHYSICAL_INTERFACE_NAME,intf) and self.verify_connectivity_only and peer_admin_state=='noshut':
                                # The peer is assumed to be a Cisco device enabled with CDP
                                # admin_state=noshut also means the device has a handle
                                peer_hdl=self.hdl_dict[peer_device]
                                peer_device_name=peer_hdl.name
                                if verify_lib.verifyCdpNeighbor(hdl,self.log,'-interface {0} -neighbor {1} -neighbor_interface {2} -verify_iterations 2'\
                                               .format(intf,peer_device_name,peer_interface)).result=='fail':
                                    testResult('fail','Interface {0} CDP neighbor info failed'.format(intf),self.log)

                params_list=filter(re.compile('^(?!admin_state)').search,params_list)
            if param=='load_interval':
                for counter,interval in self.interface_dict[node][intf]['base']['load_interval']:
                    if not verify_mode:
                        cmds='''interface {0}
                                 load-interval counter {1} {2}'''.format(intf,counter,interval)
                        if not self.generate_ascii_only:
                            hdl.configure(cmds)
                        cmd_list=map(str.strip,re.split('\n',cmds))
                        self.ascii_cfg_dict[node][intf].extend(cmd_list)
                        self.ascii_cfg_dict[node][intf]=list(set(self.ascii_cfg_dict[node][intf]))
                    else:
                        if counter==1:
                            if re.search('{0} seconds input rate'.format(interval),show_intf_output) and\
                                re.search('{0} seconds output rate'.format(interval),show_intf_output):
                                self.log.info('Counter 1 is configured properly for {0}'.format(intf))
                            else:
                                testResult('fail','Counter 1 is not configured properly for {0}'\
                                    .format(intf),self.log)
                        else:
                            if re.search('Load-Interval #{0}: [^(]+\({1} seconds'\
                                .format(counter,interval),show_intf_output):
                                self.log.info('Counter {0} is configured properly for {1}'\
                                    .format(counter,intf))
                            else:
                                testResult('fail','Counter {0} is not configured properly for {1}'\
                                    .format(counter,intf),self.log)
                params_list=filter(re.compile('^(?!load_interval)').search,params_list)
            if param=='encap_vlan':
                encap_vlan=self.interface_dict[node][intf]['base']['encap_vlan']
                if not verify_mode:
                    cmds='''interface {0}
                              encapsulation dot1q {1}'''.format(intf,encap_vlan)
                    if not self.generate_ascii_only:
                        hdl.configure(cmds)
                    cmd_list=map(str.strip,re.split('\n',cmds))
                    self.ascii_cfg_dict[node][intf].extend(cmd_list)
                    self.ascii_cfg_dict[node][intf]=list(set(self.ascii_cfg_dict[node][intf]))
                else:
                    if re.search('Vlan ID {0}'.format(encap_vlan),show_intf_output):
                        self.log.info('Encap vlan is configured successfully for {0}'.format(intf))
                    else:
                        testResult('fail','Encap vlan is not configured properly for {0}'.format(intf),self.log)
                params_list=filter(re.compile('^(?!encap_vlan)').search,params_list)

            if re.search('^Nve',intf,re.I) and param=='overlay_encap':
                overlay_encap=self.interface_dict[node][intf]['base']['overlay_encap']
                if not verify_mode:
                    cmds='''interface {0}
                              overlay-encapsulation {1}'''.format(intf,overlay_encap)
                    if not self.generate_ascii_only:
                        hdl.configure(cmds)
                    cmd_list=map(str.strip,re.split('\n',cmds))
                    self.ascii_cfg_dict[node][intf].extend(cmd_list)
                    self.ascii_cfg_dict[node][intf]=list(set(self.ascii_cfg_dict[node][intf]))
                else:
                    #TODO Verify overlay encap for interface
                    pass
                params_list=filter(re.compile('^(?!overlay_encap)').search,params_list)
            else:
                # This is because overlay_encap has a default value and will always show up
                params_list=filter(re.compile('^(?!overlay_encap)').search,params_list)

            if param=='source_intf':
                source_intf=self.interface_dict[node][intf]['base']['source_intf']
                if not verify_mode:
                    cmds='''interface {0}
                              source-interface {1}'''.format(intf,source_intf)
                    if not self.generate_ascii_only:
                        hdl.configure(cmds)
                    cmd_list=map(str.strip,re.split('\n',cmds))
                    self.ascii_cfg_dict[node][intf].extend(cmd_list)
                    self.ascii_cfg_dict[node][intf]=list(set(self.ascii_cfg_dict[node][intf]))
                else:
                    #TODO Verify source interface
                    pass
                params_list=filter(re.compile('^(?!source_intf)').search,params_list)

            if param=='mcast_vnid_map':
                mcast_vnid_map=self.interface_dict[node][intf]['base']['mcast_vnid_map']
                for every_map in mcast_vnid_map:
                    start_mcast_addr=every_map[0]
                    step_mcast_addr=every_map[1]
                    vnid_list=strtoexpandedlist(every_map[2])
                    if not verify_mode:
                        mcast_addr=start_mcast_addr
                        for vnid in vnid_list:
                            cmds='''interface {0}
                                      member vni {1} mcast-group {2}'''.format(intf,vnid,mcast_addr)
                            if not self.generate_ascii_only:
                                hdl.configure(cmds)
                            cmd_list=map(str.strip,re.split('\n',cmds))
                            self.ascii_cfg_dict[node][intf].extend(cmd_list)
                            self.ascii_cfg_dict[node][intf]=list(set(self.ascii_cfg_dict[node][intf]))
                            mcast_addr=utils.incrementIpv4Address(mcast_addr,step_mcast_addr)
                    else:
                        #TODO Verify mcast group to vnid mappings
                        pass
                params_list=filter(re.compile('^(?!mcast_vnid_map)').search,params_list)

        # check to see if we missed processing any parameters
        if len(params_list):
            testResult('fail','Interface parameters not handled: {0} interface {1} base parameter {2}'\
                .format(node,intf,params_list),self.log)
            sys.exit(1)


    def globalPvlanConfigAndVerify(self,node,*args):
        '''Configure and verify global pvlan parameters for given node.'''

        arggrammar={}
        arggrammar['mode']='-type str -choices ["config","verify"] -default config'
        options=parserutils_lib.argsToCommandOptions(args,arggrammar,self.log )
        if not options.VALIDARGS:
            testResult('fail','Invalid arguments to globalPvlanConfigAndVerify',self.log)
            sys.exit()

        if options.mode=='verify':
            verify_mode=True
        else:
            verify_mode=False

        hdl=self.hdl_dict[node]

        params_list=self.global_config_dict[node]['pvlan'].keys()
        if params_list:
            cmds='feature private-vlan'
            if not self.generate_ascii_only:
                hdl.configure(cmds)
            self.ascii_cfg_dict[node]['global'].append(cmds)
        for param in self.global_config_dict[node]['pvlan']:
            # Process each parameter and remove it from the params_list
            if param=='associations':
                assoc_list=self.global_config_dict[node]['pvlan']['associations']
                if not verify_mode:
                    for assoc in assoc_list:
                        primary_vlan=assoc.keys()[0]
                        secondary_vlans=assoc[primary_vlan]
                        cmds='''vlan {0}
                                  private-vlan primary
                                  private-vlan association {1}'''.format(primary_vlan,secondary_vlans)
                        if not self.generate_ascii_only:
                            hdl.configure(cmds)
                        cmd_list=map(str.strip,re.split('\n',cmds))
                        self.ascii_cfg_dict[node]['global'].extend(cmd_list)
                        # Commenting out since this is one flat list for all global vlan configs
                        #self.ascii_cfg_dict[node]['global']=list(set(self.ascii_cfg_dict[node]['global']))
                else:
                    for assoc in assoc_list:
                        primary_vlan=assoc.keys()[0]
                        secondary_vlans=assoc[primary_vlan]
                        if verify_lib.verifyPvlanInfo(hdl,self.log,\
                            '-primary {0} -secondary {1}'\
                            .format(primary_vlan,secondary_vlans)).result=='fail':
                            testResult('fail','Global pvlan primary validation failed for {0}'.format(node),self.log)
                params_list=filter(re.compile('^(?!associations)').search,params_list)
            if param=='isolated_vlans':
                iso_vlans=self.global_config_dict[node]['pvlan']['isolated_vlans']
                if not verify_mode:
                    cmds='''vlan {0}
                              private-vlan isolated'''.format(iso_vlans)
                    if not self.generate_ascii_only:
                        hdl.configure(cmds)
                    cmd_list=map(str.strip,re.split('\n',cmds))
                    self.ascii_cfg_dict[node]['global'].extend(cmd_list)
                    #self.ascii_cfg_dict[node]['global']=list(set(self.ascii_cfg_dict[node]['global']))
                else:
                    if verify_lib.verifyPvlanInfo(hdl,self.log,\
                        '-secondary {0}'\
                        .format(iso_vlans)).result=='fail':
                        testResult('fail','Global pvlan isolated validation failed for {0}'.format(node),self.log)
                params_list=filter(re.compile('^(?!isolated_vlans)').search,params_list)
            if param=='community_vlans':
                com_vlans=self.global_config_dict[node]['pvlan']['community_vlans']
                if not verify_mode:
                    cmds='''vlan {0}
                              private-vlan community'''.format(com_vlans)
                    if not self.generate_ascii_only:
                        hdl.configure(cmds)
                    cmd_list=map(str.strip,re.split('\n',cmds))
                    self.ascii_cfg_dict[node]['global'].extend(cmd_list)
                    #self.ascii_cfg_dict[node]['global']=list(set(self.ascii_cfg_dict[node]['global']))
                else:
                    if verify_lib.verifyPvlanInfo(hdl,self.log,\
                        '-secondary {0}'\
                        .format(com_vlans)).result=='fail':
                        testResult('fail','Global pvlan community validation failed for {0}'.format(node),self.log)
                params_list=filter(re.compile('^(?!community_vlans)').search,params_list)

        # check to see if we missed processing any parameters
        if len(params_list):
            testResult('fail','Global pvlan parameters not handled: {0} pvlan parameters {1}'\
                .format(node,params_list),self.log)
            sys.exit(1)


    def globalVxlanConfigAndVerify(self,node,*args):
        '''Configure and verify global vxlan parameters for given node.'''

        arggrammar={}
        arggrammar['mode']='-type str -choices ["config","verify"] -default config'
        options=parserutils_lib.argsToCommandOptions(args,arggrammar,self.log )
        if not options.VALIDARGS:
            testResult('fail','Invalid arguments to globalVxlanConfigAndVerify',self.log)
            sys.exit()

        if options.mode=='verify':
            verify_mode=True
        else:
            verify_mode=False

        hdl=self.hdl_dict[node]

        params_list=self.global_config_dict[node]['vxlan'].keys()
        if params_list:
            cmds='''feature nv overlay
                    feature vn-segment-vlan-based'''
            if not self.generate_ascii_only:
                hdl.configure(cmds)
            self.ascii_cfg_dict[node]['global'].append(cmds)
        for param in self.global_config_dict[node]['vxlan']:
            # Process each parameter and remove it from the params_list
            if param=='vnid_vlan_map':
                vnid_vlan_list=self.global_config_dict[node]['vxlan']['vnid_vlan_map']
                vnid_list=strtoexpandedlist(vnid_vlan_list[0][0])
                vlan_list=strtoexpandedlist(vnid_vlan_list[0][1])
                if len(vnid_list)!=len(vlan_list):
                    testResult('fail','Number of VNID and VLAN ID are not the same in global vxlan parameters',self.log)
                    sys.exit(1)
                if not verify_mode:
                    for vlan,vnid in zip(vlan_list,vnid_list):
                        cmds='''vlan {0}
                                  vn-segment {1}'''.format(vlan,vnid)
                        if not self.generate_ascii_only:
                            hdl.configure(cmds)
                        cmd_list=map(str.strip,re.split('\n',cmds))
                        self.ascii_cfg_dict[node]['global'].extend(cmd_list)
                else:
                    #TODO Verify vnid to vlan mappings 
                    pass
                params_list=filter(re.compile('^(?!vnid_vlan_map)').search,params_list)

            if param=='udp_port':
                udp_port=self.global_config_dict[node]['vxlan']['udp_port']
                if not verify_mode:
                    cmds='''vxlan udp port {0}'''.format(udp_port)
                    if not self.generate_ascii_only:
                        hdl.configure(cmds)
                    cmd_list=map(str.strip,re.split('\n',cmds))
                    self.ascii_cfg_dict[node]['global'].extend(cmd_list)
                else:
                    #TODO Verify vxlan udp port setting
                    pass
                params_list=filter(re.compile('^(?!udp_port)').search,params_list)

        # check to see if we missed processing any parameters
        if len(params_list):
            testResult('fail','Global vxlan parameters not handled: {0} vxlan parameters {1}'\
                .format(node,params_list),self.log)
            sys.exit(1)


    def switchportConfigAndVerify(self,node,intf,*args):
        '''Configure and verify switchport interface parameters for given interface.'''

        arggrammar={}
        arggrammar['mode']='-type str -choices ["config","verify"] -default config'
        options=parserutils_lib.argsToCommandOptions(args,arggrammar,self.log )
        if not options.VALIDARGS:
            testResult('fail','Invalid arguments to switchportConfigAndVerify',self.log)
            sys.exit()

        if options.mode=='verify':
            verify_mode=True
        else:
            verify_mode=False

        hdl=self.hdl_dict[node]

        params_list=self.interface_dict[node][intf]['switchport'].keys()
        native_vlan=None
        vlan_id=None
        allowed_vlan_list=None
        pvlan_mapping=None
        pvlan_host_assoc=None
        pvlan_mapping_trunk=None
        pvlan_assoc_trunk=None
        pvlan_allowed_vlan_list=None
        common_params={}
        for param in self.interface_dict[node][intf]['switchport']:
            # Process each parameter and remove it from the params_list
            if param=='mode':
                mode=self.interface_dict[node][intf]['switchport']['mode']
                params_list=filter(re.compile('^(?!mode)').search,params_list)
            if param=='vlan_id':
                vlan_id=self.interface_dict[node][intf]['switchport']['vlan_id']
                params_list=filter(re.compile('^(?!vlan_id)').search,params_list)
            if param=='allowed_vlan_list':
                allowed_vlan_list=self.interface_dict[node][intf]['switchport']['allowed_vlan_list']
                params_list=filter(re.compile('^(?!allowed_vlan_list)').search,params_list)
            if param=='native_vlan':
                native_vlan=self.interface_dict[node][intf]['switchport']['native_vlan']
                params_list=filter(re.compile('^(?!native_vlan)').search,params_list)
            if param=='pvlan_mapping':
                pvlan_mapping=self.interface_dict[node][intf]['switchport']['pvlan_mapping']
                params_list=filter(re.compile('^(?!pvlan_mapping)').search,params_list)
            if param=='pvlan_host_assoc':
                pvlan_host_assoc=self.interface_dict[node][intf]['switchport']['pvlan_host_assoc']
                params_list=filter(re.compile('^(?!pvlan_host_assoc)').search,params_list)
            if param=='pvlan_mapping_trunk':
                pvlan_mapping_trunk=self.interface_dict[node][intf]['switchport']['pvlan_mapping_trunk']
                params_list=filter(re.compile('^(?!pvlan_mapping_trunk)').search,params_list)
            if param=='pvlan_assoc_trunk':
                pvlan_assoc_trunk=self.interface_dict[node][intf]['switchport']['pvlan_assoc_trunk']
                params_list=filter(re.compile('^(?!pvlan_assoc_trunk)').search,params_list)
            if param=='pvlan_allowed_vlan_list':
                pvlan_allowed_vlan_list=self.interface_dict[node][intf]['switchport']['pvlan_allowed_vlan_list']
                params_list=filter(re.compile('^(?!pvlan_allowed_vlan_list)').search,params_list)

            # mode agnostic parameters (to be processed in a common section towards the end
            if param=='stp_port_type':
                common_params['stp_port_type']=self.interface_dict[node][intf]['switchport']['stp_port_type']
                params_list=filter(re.compile('^(?!stp_port_type)').search,params_list)
            if param=='stp_bpdufilter':
                common_params['stp_bpdufilter']=self.interface_dict[node][intf]['switchport']['stp_bpdufilter']
                params_list=filter(re.compile('^(?!stp_bpdufilter)').search,params_list)

        if mode=='access' or mode == 'dot1q-tunnel':
            if vlan_id:
                if not verify_mode:
                    cmds='vlan {0}'.format(vlan_id)
                    if not self.generate_ascii_only:
                        hdl.configure(cmds)
                    self.ascii_cfg_dict[node]['global'].append(cmds)
                    cmds='''interface {1}
                              switchport
                              switchport mode {2}
                              switchport access vlan {0}'''.format(vlan_id,intf,mode)
                    if not self.generate_ascii_only:
                        hdl.configure(cmds)
                    cmd_list=map(str.strip,re.split('\n',cmds))
                    self.ascii_cfg_dict[node][intf].extend(cmd_list)
                    self.ascii_cfg_dict[node][intf]=list(set(self.ascii_cfg_dict[node][intf]))
                else:
                    if verify_lib.verifySwitchportInfo(hdl,self.log,\
                        '-ports {0} -switchport Enabled -oper_mode {1} -access_vlan {2}'\
                        .format(intf,mode,vlan_id)).result=='fail':
                        testResult('fail','Switchport validation failed for {0}'.format(intf),self.log)
            else:
                if not verify_mode:
                    cmds='''interface {0}
                              switchport
                              switchport mode access'''.format(intf)
                    if not self.generate_ascii_only:
                        hdl.configure(cmds)
                    cmd_list=map(str.strip,re.split('\n',cmds))
                    self.ascii_cfg_dict[node][intf].extend(cmd_list)
                    self.ascii_cfg_dict[node][intf]=list(set(self.ascii_cfg_dict[node][intf]))
                else:
                    if verify_lib.verifySwitchportInfo(hdl,self.log,\
                        '-ports {0} -switchport Enabled -oper_mode {1} -access_vlan 1'\
                        .format(intf,mode)).result=='fail':
                        testResult('fail','Switchport validation failed for {0}'.format(intf),self.log)
        elif mode=='trunk':
            if allowed_vlan_list and native_vlan:
                if not verify_mode:
                    cmds='vlan {0}'.format(allowed_vlan_list)
                    if not self.generate_ascii_only:
                        hdl.configure(cmds)
                    self.ascii_cfg_dict[node]['global'].append(cmds)
                    cmds='''interface {1}
                              switchport
                              switchport mode trunk
                              switchport trunk allowed vlan {0}
                              switchport trunk native vlan {2}'''.format(allowed_vlan_list,intf,native_vlan)
                    if not self.generate_ascii_only:
                        hdl.configure(cmds)
                    cmd_list=map(str.strip,re.split('\n',cmds))
                    self.ascii_cfg_dict[node][intf].extend(cmd_list)
                    self.ascii_cfg_dict[node][intf]=list(set(self.ascii_cfg_dict[node][intf]))
                else:
                    if verify_lib.verifySwitchportInfo(hdl,self.log,\
                        '-ports {0} -switchport Enabled -oper_mode {1} -trk_allowed_vlan {2} -trk_native_vlan {3}'\
                        .format(intf,mode,allowed_vlan_list,native_vlan)).result=='fail':
                        testResult('fail','Switchport validation failed for {0}'.format(intf),self.log)
            elif allowed_vlan_list:
                if not verify_mode:
                    cmds='vlan {0}'.format(allowed_vlan_list)
                    if not self.generate_ascii_only:
                        hdl.configure(cmds)
                    self.ascii_cfg_dict[node]['global'].append(cmds)
                    cmds='''interface {1}
                              switchport
                              switchport mode trunk
                              switchport trunk allowed vlan {0}'''.format(allowed_vlan_list,intf)
                    if not self.generate_ascii_only:
                        hdl.configure(cmds)
                    cmd_list=map(str.strip,re.split('\n',cmds))
                    self.ascii_cfg_dict[node][intf].extend(cmd_list)
                    self.ascii_cfg_dict[node][intf]=list(set(self.ascii_cfg_dict[node][intf]))
                else:
                    if verify_lib.verifySwitchportInfo(hdl,self.log,\
                        '-ports {0} -switchport Enabled -oper_mode {1} -trk_allowed_vlan {2} -trk_native_vlan 1'\
                        .format(intf,mode,allowed_vlan_list)).result=='fail':
                        testResult('fail','Switchport validation failed for {0}'.format(intf),self.log)
            elif native_vlan:
                if not verify_mode:
                    cmds='vlan {0}'.format(native_vlan)
                    if not self.generate_ascii_only:
                        hdl.configure(cmds)
                    self.ascii_cfg_dict[node]['global'].append(cmds)
                    cmds='''interface {0}
                              switchport
                              switchport mode trunk
                              switchport trunk native vlan {1}'''.format(intf,native_vlan)
                    if not self.generate_ascii_only:
                        hdl.configure(cmds)
                    cmd_list=map(str.strip,re.split('\n',cmds))
                    self.ascii_cfg_dict[node][intf].extend(cmd_list)
                    self.ascii_cfg_dict[node][intf]=list(set(self.ascii_cfg_dict[node][intf]))
                else:
                    if verify_lib.verifySwitchportInfo(hdl,self.log,\
                        '-ports {0} -switchport Enabled -oper_mode {1} -trk_native_vlan {2} -trk_allowed_vlan_all 1-4094'\
                        .format(intf,mode,native_vlan)).result=='fail':
                        testResult('fail','Switchport validation failed for {0}'.format(intf),self.log)
            else:
                if not verify_mode:
                    cmds='''interface {0}
                              switchport
                              switchport mode trunk'''.format(intf)
                    if not self.generate_ascii_only:
                        hdl.configure(cmds)
                    cmd_list=map(str.strip,re.split('\n',cmds))
                    self.ascii_cfg_dict[node][intf].extend(cmd_list)
                    self.ascii_cfg_dict[node][intf]=list(set(self.ascii_cfg_dict[node][intf]))
                else:
                    if verify_lib.verifySwitchportInfo(hdl,self.log,\
                        '-ports {0} -switchport Enabled -oper_mode {1} -trk_allowed_vlan_all 1-4094 -trk_native_vlan 1'\
                        .format(intf,mode)).result=='fail':
                        testResult('fail','Switchport validation failed for {0}'.format(intf),self.log)
        elif mode=='pvlan_promisc':
            if pvlan_mapping:
                mapping=pvlan_mapping[0]
                primaries=mapping.keys()
                primary_vlan=primaries[0]
                secondary_vlans=mapping[primary_vlan]
                if not verify_mode:
                    cmds='vlan {0},{1}'.format(primary_vlan,secondary_vlans)
                    if not self.generate_ascii_only:
                        hdl.configure(cmds)
                    self.ascii_cfg_dict[node]['global'].append(cmds)
                    cmds='''interface {0}
                              switchport
                              switchport mode private-vlan promiscuous
                              switchport private-vlan mapping {1} {2}'''.format(intf,primary_vlan,secondary_vlans)
                    if not self.generate_ascii_only:
                        hdl.configure(cmds)
                    cmd_list=map(str.strip,re.split('\n',cmds))
                    self.ascii_cfg_dict[node][intf].extend(cmd_list)
                    self.ascii_cfg_dict[node][intf]=list(set(self.ascii_cfg_dict[node][intf]))
                else:
                    if verify_lib.verifySwitchportInfo(hdl,self.log,\
                        '-ports {0} -switchport Enabled -oper_mode {1} -pvlan_primary {2} -pvlan_secondary {3}'\
                        .format(intf,mode,primary_vlan,secondary_vlans)).result=='fail':
                        testResult('fail','Switchport validation failed for {0}'.format(intf),self.log)
            else:
                if not verify_mode:
                    cmds='''interface {0}
                              switchport
                              switchport mode private-vlan promiscuous'''.format(intf)
                    if not self.generate_ascii_only:
                        hdl.configure(cmds)
                    cmd_list=map(str.strip,re.split('\n',cmds))
                    self.ascii_cfg_dict[node][intf].extend(cmd_list)
                    self.ascii_cfg_dict[node][intf]=list(set(self.ascii_cfg_dict[node][intf]))
                else:
                    if verify_lib.verifySwitchportInfo(hdl,self.log,\
                        '-ports {0} -switchport Enabled -oper_mode {1}'\
                        .format(intf,mode)).result=='fail':
                        testResult('fail','Switchport validation failed for {0}'.format(intf),self.log)
        elif mode=='pvlan_host':
            if pvlan_host_assoc:
                mapping=pvlan_host_assoc[0]
                primaries=mapping.keys()
                primary_vlan=primaries[0]
                secondary_vlans=mapping[primary_vlan]
                if not verify_mode:
                    cmds='vlan {0},{1}'.format(primary_vlan,secondary_vlans)
                    if not self.generate_ascii_only:
                        hdl.configure(cmds)
                    self.ascii_cfg_dict[node]['global'].append(cmds)
                    cmds='''interface {0}
                              switchport
                              switchport mode private-vlan host
                              switchport private-vlan host-association {1} {2}'''.format(intf,primary_vlan,secondary_vlans)
                    if not self.generate_ascii_only:
                        hdl.configure(cmds)
                    cmd_list=map(str.strip,re.split('\n',cmds))
                    self.ascii_cfg_dict[node][intf].extend(cmd_list)
                    self.ascii_cfg_dict[node][intf]=list(set(self.ascii_cfg_dict[node][intf]))
                else:
                    if verify_lib.verifySwitchportInfo(hdl,self.log,\
                        '-ports {0} -switchport Enabled -oper_mode {1} -pvlan_primary {2} -pvlan_secondary {3}'\
                        .format(intf,mode,primary_vlan,secondary_vlans)).result=='fail':
                        testResult('fail','Switchport validation failed for {0}'.format(intf),self.log)
            else:
                if not verify_mode:
                    cmds='''interface {0}
                              switchport
                              switchport mode private-vlan host'''.format(intf)
                    if not self.generate_ascii_only:
                        hdl.configure(cmds)
                    cmd_list=map(str.strip,re.split('\n',cmds))
                    self.ascii_cfg_dict[node][intf].extend(cmd_list)
                    self.ascii_cfg_dict[node][intf]=list(set(self.ascii_cfg_dict[node][intf]))
                else:
                    if verify_lib.verifySwitchportInfo(hdl,self.log,\
                        '-ports {0} -switchport Enabled -oper_mode {1}'\
                        .format(intf,mode)).result=='fail':
                        testResult('fail','Switchport validation failed for {0}'.format(intf),self.log)
        elif mode=='pvlan_promisc_trunk':
            if not verify_mode:
                cmds='''interface {0}
                          switchport
                          switchport mode private-vlan trunk promiscuous'''.format(intf)
                if not self.generate_ascii_only:
                    hdl.configure(cmds)
                cmd_list=map(str.strip,re.split('\n',cmds))
                self.ascii_cfg_dict[node][intf].extend(cmd_list)
                self.ascii_cfg_dict[node][intf]=list(set(self.ascii_cfg_dict[node][intf]))
            else:
                if verify_lib.verifySwitchportInfo(hdl,self.log,\
                    '-ports {0} -switchport Enabled -oper_mode {1}'\
                    .format(intf,mode)).result=='fail':
                    testResult('fail','Switchport validation failed for {0}'.format(intf),self.log)
            if pvlan_mapping_trunk:
                for mapping in pvlan_mapping_trunk:
                    primaries=mapping.keys()
                    primary_vlan=primaries[0]
                    secondary_vlans=mapping[primary_vlan]
                    if not verify_mode:
                        cmds='vlan {0},{1}'.format(primary_vlan,secondary_vlans)
                        if not self.generate_ascii_only:
                            hdl.configure(cmds)
                        self.ascii_cfg_dict[node]['global'].append(cmds)
                        cmds='''interface {0}
                                  switchport private-vlan mapping trunk {1} {2}'''.format(intf,primary_vlan,secondary_vlans)
                        if not self.generate_ascii_only:
                            hdl.configure(cmds)
                        cmd_list=map(str.strip,re.split('\n',cmds))
                        self.ascii_cfg_dict[node][intf].extend(cmd_list)
                        self.ascii_cfg_dict[node][intf]=list(set(self.ascii_cfg_dict[node][intf]))
                    else:
                        # TODO Enhance this to validate pvlan info
                        if verify_lib.verifySwitchportInfo(hdl,self.log,\
                            '-ports {0} -switchport Enabled -oper_mode {1} -access_vlan {2}'\
                            .format(intf,mode,vlan_id)).result=='fail':
                            testResult('fail','Switchport validation failed for {0}'.format(intf),self.log)
            if pvlan_allowed_vlan_list:
                if not verify_mode:
                    cmds='vlan {0}'.format(pvlan_allowed_vlan_list)
                    if not self.generate_ascii_only:
                        hdl.configure(cmds)
                    self.ascii_cfg_dict[node]['global'].append(cmds)
                    cmds='''interface {0}
                              switchport private-vlan trunk allowed vlan {1}'''.format(intf,pvlan_allowed_vlan_list)
                    if not self.generate_ascii_only:
                        hdl.configure(cmds)
                    cmd_list=map(str.strip,re.split('\n',cmds))
                    self.ascii_cfg_dict[node][intf].extend(cmd_list)
                    self.ascii_cfg_dict[node][intf]=list(set(self.ascii_cfg_dict[node][intf]))
                else:
                    # TODO Enhance this to validate pvlan info
                    if verify_lib.verifySwitchportInfo(hdl,self.log,\
                        '-ports {0} -switchport Enabled -oper_mode {1} -trk_allowed_vlan {2} -trk_native_vlan 1'\
                        .format(intf,mode,allowed_vlan_list)).result=='fail':
                        testResult('fail','Switchport validation failed for {0}'.format(intf),self.log)
        elif mode=='pvlan_sec_trunk':
            if not verify_mode:
                cmds='''interface {0}
                          switchport
                          switchport mode private-vlan trunk secondary'''.format(intf)
                if not self.generate_ascii_only:
                    hdl.configure(cmds)
                cmd_list=map(str.strip,re.split('\n',cmds))
                self.ascii_cfg_dict[node][intf].extend(cmd_list)
                self.ascii_cfg_dict[node][intf]=list(set(self.ascii_cfg_dict[node][intf]))
            else:
                if verify_lib.verifySwitchportInfo(hdl,self.log,\
                    '-ports {0} -switchport Enabled -oper_mode {1}'\
                    .format(intf,mode)).result=='fail':
                    testResult('fail','Switchport validation failed for {0}'.format(intf),self.log)
            if pvlan_assoc_trunk:
                for mapping in pvlan_assoc_trunk:
                    primaries=mapping.keys()
                    primary_vlan=primaries[0]
                    secondary_vlans=mapping[primary_vlan]
                    if not verify_mode:
                        cmds='vlan {0},{1}'.format(primary_vlan,secondary_vlans)
                        if not self.generate_ascii_only:
                            hdl.configure(cmds)
                        self.ascii_cfg_dict[node]['global'].append(cmds)
                        cmds='''interface {0}
                                  switchport private-vlan association trunk {1} {2}'''.format(intf,primary_vlan,secondary_vlans)
                        if not self.generate_ascii_only:
                            hdl.configure(cmds)
                        cmd_list=map(str.strip,re.split('\n',cmds))
                        self.ascii_cfg_dict[node][intf].extend(cmd_list)
                        self.ascii_cfg_dict[node][intf]=list(set(self.ascii_cfg_dict[node][intf]))
                    else:
                        # TODO Enhance this to validate pvlan info
                        if verify_lib.verifySwitchportInfo(hdl,self.log,\
                            '-ports {0} -switchport Enabled -oper_mode {1} -access_vlan {2}'\
                            .format(intf,mode,vlan_id)).result=='fail':
                            testResult('fail','Switchport validation failed for {0}'.format(intf),self.log)
            if pvlan_allowed_vlan_list:
                if not verify_mode:
                    cmds='vlan {0}'.format(pvlan_allowed_vlan_list)
                    if not self.generate_ascii_only:
                        hdl.configure(cmds)
                    self.ascii_cfg_dict[node]['global'].append(cmds)
                    cmds='''interface {0}
                              switchport private-vlan trunk allowed vlan {1}'''.format(intf,pvlan_allowed_vlan_list)
                    if not self.generate_ascii_only:
                        hdl.configure(cmds)
                    cmd_list=map(str.strip,re.split('\n',cmds))
                    self.ascii_cfg_dict[node][intf].extend(cmd_list)
                    self.ascii_cfg_dict[node][intf]=list(set(self.ascii_cfg_dict[node][intf]))
                else:
                    # TODO Enhance this to validate pvlan info
                    if verify_lib.verifySwitchportInfo(hdl,self.log,\
                        '-ports {0} -switchport Enabled -oper_mode {1} -trk_allowed_vlan {2} -trk_native_vlan 1'\
                        .format(intf,mode,allowed_vlan_list)).result=='fail':
                        testResult('fail','Switchport validation failed for {0}'.format(intf),self.log)
        elif mode=='monitor':
            if not verify_mode:
                cmds='''interface {1}
                          switchport
                          switchport monitor'''
                if not self.generate_ascii_only:
                    hdl.configure(cmds)
                cmd_list=map(str.strip,re.split('\n',cmds))
                self.ascii_cfg_dict[node][intf].extend(cmd_list)
                self.ascii_cfg_dict[node][intf]=list(set(self.ascii_cfg_dict[node][intf]))
            else:
                #TODO Add span port validation
                pass

        # process common parameters here
        if 'stp_port_type' in common_params:
            if common_params['stp_port_type']=='edge':
                port_type='edge'
            elif common_params['stp_port_type']=='edge_trunk':
                port_type='edge trunk'
            if not verify_mode:
                cmds='''interface {0}
                          switchport
                          spanning-tree port type {1}'''.format(intf,port_type)
                if not self.generate_ascii_only:
                    hdl.configure(cmds)
                cmd_list=map(str.strip,re.split('\n',cmds))
                self.ascii_cfg_dict[node][intf].extend(cmd_list)
                self.ascii_cfg_dict[node][intf]=list(set(self.ascii_cfg_dict[node][intf]))
            else:
                #TODO: validate stp port type here
                pass

        if 'stp_bpdufilter' in common_params:
            if common_params['stp_bpdufilter']:
                command='spanning-tree bpdufilter enable'
            else:
                command='no spanning-tree bpdufilter enable'
            if not verify_mode:
                cmds='''interface {0}
                          switchport
                          {1}'''.format(intf,command)
                if not self.generate_ascii_only:
                    hdl.configure(cmds)
                cmd_list=map(str.strip,re.split('\n',cmds))
                self.ascii_cfg_dict[node][intf].extend(cmd_list)
                self.ascii_cfg_dict[node][intf]=list(set(self.ascii_cfg_dict[node][intf]))
            else:
                #TODO: validate stp bpdufilter state here
                pass

        # check to see if we missed processing any parameters
        if len(params_list):
            testResult('fail','Interface parameters not handled: {0} interface {1} switchport parameter {2}'\
                .format(node,intf,params_list),self.log)
            sys.exit(1)


    def ipv4ConfigAndVerify(self,node,intf,*args):
        '''Configure and verify ipv4 interface parameters for given interface.'''

        arggrammar={}
        arggrammar['mode']='-type str -choices ["config","verify"] -default config'
        options=parserutils_lib.argsToCommandOptions(args,arggrammar,self.log )
        if not options.VALIDARGS:
            testResult('fail','Invalid arguments to ipv4ConfigAndVerify',self.log)
            sys.exit()

        if options.mode=='verify':
            verify_mode=True
        else:
            verify_mode=False

        hdl=self.hdl_dict[node]

        params_list=self.interface_dict[node][intf]['ipv4'].keys()
        # Configure vrf first so that it doesnt erase ip config later
        vrf=self.interface_dict[node][intf]['ipv4']['vrf']
        if vrf != "default":
            if not verify_mode:
                cmds='vrf context {0}'.format(vrf)
                if not self.generate_ascii_only:
                    hdl.configure(cmds)
                self.ascii_cfg_dict[node]['global'].append(cmds)
                cmds='''interface {1}
                           no switchport
                           vrf member {0}'''.format(vrf,intf)
                if not self.generate_ascii_only:
                    hdl.configure(cmds)
                cmd_list=map(str.strip,re.split('\n',cmds))
                self.ascii_cfg_dict[node][intf].extend(cmd_list)
                self.ascii_cfg_dict[node][intf]=list(set(self.ascii_cfg_dict[node][intf]))
            else:
                pass
        params_list=filter(re.compile('^(?!vrf)').search,params_list)
        for param in self.interface_dict[node][intf]['ipv4']:
            # Process each parameter and remove it from the params_list
            if param=="mac_addr":
                mac=self.interface_dict[node][intf]['ipv4']['mac_addr']
                if not verify_mode:
                    cmds='''interface {0}
                              mac-address {1}'''.format(intf,mac)
                    if not self.generate_ascii_only:
                        hdl.configure(cmds)
                    cmd_list=map(str.strip,re.split('\n',cmds))
                    self.ascii_cfg_dict[node][intf].extend(cmd_list)
                    self.ascii_cfg_dict[node][intf]=list(set(self.ascii_cfg_dict[node][intf]))
                params_list=filter(re.compile('^(?!mac_addr)').search,params_list)

            if param=='ipv4_addr' and 'ipv4_addr' in params_list:
                ip=self.interface_dict[node][intf]['ipv4']['ipv4_addr']
                prf_len=self.interface_dict[node][intf]['ipv4']['ipv4_prf_len']
                if not verify_mode:
                    cmds='''interface {0}
                              no switchport
                              ip address {1}/{2}'''.format(intf,ip,prf_len)
                    if not self.generate_ascii_only:
                        hdl.configure(cmds)
                    cmd_list=map(str.strip,re.split('\n',cmds))
                    self.ascii_cfg_dict[node][intf].extend(cmd_list)
                    self.ascii_cfg_dict[node][intf]=list(set(self.ascii_cfg_dict[node][intf]))
                else:
                    pass
                params_list=filter(re.compile('^(?!ipv4_addr|ipv4_prf_len)').search,params_list)
            if param=='secondary_ipv4':
                # Adding this here to cover the case where primary IP has to be
                # configured before the secondary IP
                ip=self.interface_dict[node][intf]['ipv4']['ipv4_addr']
                prf_len=self.interface_dict[node][intf]['ipv4']['ipv4_prf_len']
                if not verify_mode:
                    cmds='''interface {0}
                              no switchport
                              ip address {1}/{2}'''.format(intf,ip,prf_len)
                    if not self.generate_ascii_only:
                        hdl.configure(cmds)
                    cmd_list=map(str.strip,re.split('\n',cmds))
                    self.ascii_cfg_dict[node][intf].extend(cmd_list)
                    self.ascii_cfg_dict[node][intf]=list(set(self.ascii_cfg_dict[node][intf]))
                else:
                    pass
                params_list=filter(re.compile('^(?!ipv4_addr|ipv4_prf_len)').search,params_list)
                for ip,prf_len in self.interface_dict[node][intf]['ipv4']['secondary_ipv4']:
                    if not verify_mode:
                        cmds='''interface {0}
                                  no switchport
                                  ip address {1}/{2} secondary'''.format(intf,ip,prf_len)
                        if not self.generate_ascii_only:
                            hdl.configure(cmds)
                        cmd_list=map(str.strip,re.split('\n',cmds))
                        self.ascii_cfg_dict[node][intf].extend(cmd_list)
                        self.ascii_cfg_dict[node][intf]=list(set(self.ascii_cfg_dict[node][intf]))
                    else:
                        pass
                params_list=filter(re.compile('^(?!secondary_ipv4)').search,params_list)
            if param=='redirects':
                if self.interface_dict[node][intf]['ipv4']['redirects']==True:
                    redirect_cmd='ip redirects'
                elif self.interface_dict[node][intf]['ipv4']['redirects']==False:
                    redirect_cmd='no ip redirects'
                if not verify_mode:
                    cmds='''interface {0}
                             no switchport
                             {1}'''.format(intf,redirect_cmd)
                    if not self.generate_ascii_only:
                        hdl.configure(cmds)
                    cmd_list=map(str.strip,re.split('\n',cmds))
                    self.ascii_cfg_dict[node][intf].extend(cmd_list)
                    self.ascii_cfg_dict[node][intf]=list(set(self.ascii_cfg_dict[node][intf]))
                else:
                    pass
                params_list=filter(re.compile('^(?!redirects)').search,params_list)
            if param=='static_arp':
                for ip,mac in self.interface_dict[node][intf]['ipv4']['static_arp']:
                    if not verify_mode:
                        cmds='''interface {0}
                                 no switchport
                                 ip arp {1} {2}'''.format(intf,ip,mac)
                        if not self.generate_ascii_only:
                            hdl.configure(cmds)
                        cmd_list=map(str.strip,re.split('\n',cmds))
                        self.ascii_cfg_dict[node][intf].extend(cmd_list)
                        self.ascii_cfg_dict[node][intf]=list(set(self.ascii_cfg_dict[node][intf]))
                    else:
                        pass
                params_list=filter(re.compile('^(?!static_arp)').search,params_list)
            if param=='igmp_group_timeout':
                igmp_group_timeout_cmd='ip igmp group-timeout {0}'.format(self.interface_dict[node][intf]['ipv4']['igmp_group_timeout'])
                if not verify_mode:
                    cmds='''interface {0}
                             no switchport
                             {1}'''.format(intf,igmp_group_timeout_cmd)
                    if not self.generate_ascii_only:
                        hdl.configure(cmds)
                    cmd_list=map(str.strip,re.split('\n',cmds))
                    self.ascii_cfg_dict[node][intf].extend(cmd_list)
                    self.ascii_cfg_dict[node][intf]=list(set(self.ascii_cfg_dict[node][intf]))
                else:
                    pass
                params_list=filter(re.compile('^(?!igmp_group_timeout)').search,params_list)

        # check to see if we missed processing any parameters
        if len(params_list):
            testResult('fail','Interface parameters not handled: {0} interface {1} ipv4 parameter {2}'\
                .format(node,intf,params_list),self.log)
            sys.exit(1)


    def ipv6ConfigAndVerify(self,node,intf,*args):
        '''Configure and verify ipv6 interface parameters for given interface.'''

        arggrammar={}
        arggrammar['mode']='-type str -choices ["config","verify"] -default config'
        options=parserutils_lib.argsToCommandOptions(args,arggrammar,self.log )
        if not options.VALIDARGS:
            testResult('fail','Invalid arguments to ipv6ConfigAndVerify',self.log)
            sys.exit()

        if options.mode=='verify':
            verify_mode=True
        else:
            verify_mode=False

        hdl=self.hdl_dict[node]

        params_list=self.interface_dict[node][intf]['ipv6'].keys()
        # Configure vrf first so that it doesnt erase ip config later
        vrf=self.interface_dict[node][intf]['ipv6']['vrf']
        if vrf != "default":
            if not verify_mode:
                cmds='vrf context {0}'.format(vrf)
                if not self.generate_ascii_only:
                    hdl.configure(cmds)
                self.ascii_cfg_dict[node]['global'].append(cmds)
                cmds='''interface {1}
                           no switchport
                           vrf member {0}'''.format(vrf,intf)
                if not self.generate_ascii_only:
                    hdl.configure(cmds)
                cmd_list=map(str.strip,re.split('\n',cmds))
                self.ascii_cfg_dict[node][intf].extend(cmd_list)
                self.ascii_cfg_dict[node][intf]=list(set(self.ascii_cfg_dict[node][intf]))
            else:
                pass
        params_list=filter(re.compile('^(?!vrf)').search,params_list)
        for param in self.interface_dict[node][intf]['ipv6']:
            # Process each parameter and remove it from the params_list
            if param=='ipv6_addr' and 'ipv6_addr' in params_list:
                ip=self.interface_dict[node][intf]['ipv6']['ipv6_addr']
                prf_len=self.interface_dict[node][intf]['ipv6']['ipv6_prf_len']
                if not verify_mode:
                    cmds='''interface {0}
                              no switchport
                              ipv6 address {1}/{2}'''.format(intf,ip,prf_len)
                    if not self.generate_ascii_only:
                        hdl.configure(cmds)
                    cmd_list=map(str.strip,re.split('\n',cmds))
                    self.ascii_cfg_dict[node][intf].extend(cmd_list)
                    self.ascii_cfg_dict[node][intf]=list(set(self.ascii_cfg_dict[node][intf]))
                else:
                    pass
                params_list=filter(re.compile('^(?!ipv6_addr|ipv6_prf_len)').search,params_list)
            if param=='secondary_ipv6':
                # Adding this here to cover the case where primary IP has to be
                # configured before the secondary IP
                ip=self.interface_dict[node][intf]['ipv6']['ipv6_addr']
                prf_len=self.interface_dict[node][intf]['ipv6']['ipv6_prf_len']
                if not verify_mode:
                    cmds='''interface {0}
                              no switchport
                              ipv6 address {1}/{2}'''.format(intf,ip,prf_len)
                    if not self.generate_ascii_only:
                        hdl.configure(cmds)
                    cmd_list=map(str.strip,re.split('\n',cmds))
                    self.ascii_cfg_dict[node][intf].extend(cmd_list)
                    self.ascii_cfg_dict[node][intf]=list(set(self.ascii_cfg_dict[node][intf]))
                else:
                    pass
                params_list=filter(re.compile('^(?!ipv6_addr|ipv6_prf_len)').search,params_list)
                for ip,prf_len in self.interface_dict[node][intf]['ipv6']['secondary_ipv6']:
                    if not verify_mode:
                        cmds='''interface {0}
                                  no switchport
                                  ipv6 address {1}/{2} secondary'''.format(intf,ip,prf_len)
                        if not self.generate_ascii_only:
                            hdl.configure(cmds)
                        cmd_list=map(str.strip,re.split('\n',cmds))
                        self.ascii_cfg_dict[node][intf].extend(cmd_list)
                        self.ascii_cfg_dict[node][intf]=list(set(self.ascii_cfg_dict[node][intf]))
                    else:
                        pass
                params_list=filter(re.compile('^(?!secondary_ipv6)').search,params_list)
            if param=='redirects':
                if self.interface_dict[node][intf]['ipv6']['redirects']==True:
                    redirect_cmd='ipv6 redirects'
                elif self.interface_dict[node][intf]['ipv6']['redirects']==False:
                    redirect_cmd='no ipv6 redirects'
                if not verify_mode:
                    cmds='''interface {0}
                             no switchport
                             {1}'''.format(intf,redirect_cmd)
                    if not self.generate_ascii_only:
                        hdl.configure(cmds)
                    cmd_list=map(str.strip,re.split('\n',cmds))
                    self.ascii_cfg_dict[node][intf].extend(cmd_list)
                    self.ascii_cfg_dict[node][intf]=list(set(self.ascii_cfg_dict[node][intf]))
                else:
                    pass
                params_list=filter(re.compile('^(?!redirects)').search,params_list)

        # check to see if we missed processing any parameters
        if len(params_list):
            testResult('fail','Interface parameters not handled: {0} interface {1} ipv6 parameter {2}'\
                .format(node,intf,params_list),self.log)
            sys.exit(1)


    def baseRangeConfigAndVerify(self,node,intf,*args):
        '''Configure or verify iterative base params.'''

        arggrammar={}
        arggrammar['mode']='-type str -choices ["config","verify"] -default config'
        options=parserutils_lib.argsToCommandOptions(args,arggrammar,self.log )
        if not options.VALIDARGS:
            testResult('fail','Invalid arguments to baseRangeConfigAndVerify',self.log)
            sys.exit()

        if options.mode=='verify':
            verify_mode=True
        else:
            verify_mode=False

        hdl=self.hdl_dict[node]

        params_list=self.interface_dict[node]['range'][intf]['base'].keys()
        for param in self.interface_dict[node]['range'][intf]['base']:
            # Process each parameter and remove it from the params_list
            if param=='start_encap_vlan' and 'step_encap_vlan' in params_list:
                start_encap_vlan=self.interface_dict[node]['range'][intf]['base']['start_encap_vlan']
                step_encap_vlan=self.interface_dict[node]['range'][intf]['base']['step_encap_vlan']

                if not verify_mode:
                    # If the intf is a sub-interface then ensure the parent is already in l3 mode
                    if re.search('[^\.]+\.[0-9]+',intf):
                        parent_intf=re.search('([^\.]+)\.[0-9]+',intf).group(1)
                        cmds='''interface {0}
                                  no switchport'''.format(parent_intf)
                        if not self.generate_ascii_only:
                            hdl.configure(cmds)
                        cmd_list=map(str.strip,re.split('\n',cmds))
                        self.ascii_cfg_dict[node][parent_intf].extend(cmd_list)
                        self.ascii_cfg_dict[node][parent_intf]=list(set(self.ascii_cfg_dict[node][parent_intf]))

                    encap_vlan=int(start_encap_vlan)
                    intf_list=utils.normalizeInterfaceName(self.log,strtoexpandedlist(intf))
                    for individual_intf in intf_list:
                        cmds='''interface {0}
                                  encapsulation dot1q {1}'''.format(individual_intf,encap_vlan)
                        if not self.generate_ascii_only:
                            hdl.configure(cmds)
                        cmd_list=map(str.strip,re.split('\n',cmds))
                        self.ascii_cfg_dict[node][individual_intf].extend(cmd_list)
                        self.ascii_cfg_dict[node][individual_intf]=\
                            list(set(self.ascii_cfg_dict[node][individual_intf]))
                        encap_vlan+=int(step_encap_vlan)
                else:
                    pass
                params_list=filter(re.compile('^(?!start_encap_vlan|step_encap_vlan)').search,params_list)

        # check to see if we missed processing any parameters
        if len(params_list):
            testResult('fail','Interface range parameter not handled: {0} interface {1} base parameter {2}'\
                .format(node,intf,params_list),self.log)
            sys.exit(1)


    def switchportRangeConfigAndVerify(self,node,intf,*args):
        '''Configure and verify iterative switchport params.'''

        arggrammar={}
        arggrammar['mode']='-type str -choices ["config","verify"] -default config'
        options=parserutils_lib.argsToCommandOptions(args,arggrammar,self.log )
        if not options.VALIDARGS:
            testResult('fail','Invalid arguments to switchportRangeConfigAndVerify',self.log)
            sys.exit()

        if options.mode=='verify':
            verify_mode=True
        else:
            verify_mode=False

        hdl=self.hdl_dict[node]

        params_list=self.interface_dict[node]['range'][intf]['switchport'].keys()
        native_vlan=None
        vlan_id=None
        allowed_vlan_list=None
        for param in self.interface_dict[node]['range'][intf]['switchport']:
            # TODO
            pass


    def ipv4RangeConfigAndVerify(self,node,intf,*args):
        '''Configure and verify iterative ipv4 params.'''

        arggrammar={}
        arggrammar['mode']='-type str -choices ["config","verify"] -default config'
        options=parserutils_lib.argsToCommandOptions(args,arggrammar,self.log )
        if not options.VALIDARGS:
            testResult('fail','Invalid arguments to ipv4RangeConfigAndVerify',self.log)
            sys.exit()

        if options.mode=='verify':
            verify_mode=True
        else:
            verify_mode=False

        hdl=self.hdl_dict[node]

        params_list=self.interface_dict[node]['range'][intf]['ipv4'].keys()

        # Today vrf is applied to individual members of the range before coming here

        for param in self.interface_dict[node]['range'][intf]['ipv4']:
            # Process each parameter and remove it from the params_list
            if param=='start_ipv4_addr' and 'start_ipv4_addr' in params_list:
                start_ipv4_addr=self.interface_dict[node]['range'][intf]['ipv4']['start_ipv4_addr']
                start_ipv4_prf_len=self.interface_dict[node]['range'][intf]['ipv4']['start_ipv4_prf_len']
                step_ipv4_addr=self.interface_dict[node]['range'][intf]['ipv4']['step_ipv4_addr']
                step_ipv4_prf_len=self.interface_dict[node]['range'][intf]['ipv4']['step_ipv4_prf_len']

                if not verify_mode:
                    ip=start_ipv4_addr
                    prf_len=start_ipv4_prf_len
                    intf_list=utils.normalizeInterfaceName(self.log,strtoexpandedlist(intf))
                    for individual_intf in intf_list:
                        cmds='''interface {0}
                                  no switchport
                                  ip address {1}/{2}'''.format(individual_intf,ip,prf_len)
                        if not self.generate_ascii_only:
                            hdl.configure(cmds)
                        cmd_list=map(str.strip,re.split('\n',cmds))
                        self.ascii_cfg_dict[node][individual_intf].extend(cmd_list)
                        self.ascii_cfg_dict[node][individual_intf]=\
                            list(set(self.ascii_cfg_dict[node][individual_intf]))
                        ip=utils.incrementIpv4Address(ip,step_ipv4_addr)
                        prf_len=str(int(prf_len) + int(step_ipv4_prf_len))
                else:
                    pass
                params_list=filter(re.compile('^(?!start_ipv4_addr|start_ipv4_prf_len|step_ipv4_addr|step_ipv4_prf_len)').search,params_list)
            if param=='step_ipv4_prf_len' and 'start_ipv4_addr' not in params_list:
                # ignore the default value for this param if start_ipv4_addr is not specified
                params_list=filter(re.compile('^(?!step_ipv4_prf_len)').search,params_list)

        # check to see if we missed processing any parameters
        if len(params_list):
            testResult('fail','Interface range parameter not handled: {0} interface {1} ipv4 parameter {2}'\
                .format(node,intf,params_list),self.log)
            sys.exit(1)



    def ipv6RangeConfigAndVerify(self,node,intf,*args):
        '''Configure and verify iterative ipv6 params.'''

        arggrammar={}
        arggrammar['mode']='-type str -choices ["config","verify"] -default config'
        options=parserutils_lib.argsToCommandOptions(args,arggrammar,self.log )
        if not options.VALIDARGS:
            testResult('fail','Invalid arguments to ipv6RangeConfigAndVerify',self.log)
            sys.exit()

        if options.mode=='verify':
            verify_mode=True
        else:
            verify_mode=False

        hdl=self.hdl_dict[node]

        params_list=self.interface_dict[node]['range'][intf]['ipv6'].keys()

        # Today vrf is applied to individual members of the range before coming here

        for param in self.interface_dict[node]['range'][intf]['ipv6']:
            # Process each parameter and remove it from the params_list
            if param=='start_ipv6_addr' and 'start_ipv6_addr' in params_list:
                start_ipv6_addr=self.interface_dict[node]['range'][intf]['ipv6']['start_ipv6_addr']
                start_ipv6_prf_len=self.interface_dict[node]['range'][intf]['ipv6']['start_ipv6_prf_len']
                step_ipv6_addr=self.interface_dict[node]['range'][intf]['ipv6']['step_ipv6_addr']
                step_ipv6_prf_len=self.interface_dict[node]['range'][intf]['ipv6']['step_ipv6_prf_len']

                if not verify_mode:
                    ip=start_ipv6_addr
                    prf_len=start_ipv6_prf_len
                    intf_list=utils.normalizeInterfaceName(self.log,strtoexpandedlist(intf))
                    for individual_intf in intf_list:
                        cmds='''interface {0}
                                  no switchport
                                  ipv6 address {1}/{2}'''.format(individual_intf,ip,prf_len)
                        if not self.generate_ascii_only:
                            hdl.configure(cmds)
                        cmd_list=map(str.strip,re.split('\n',cmds))
                        self.ascii_cfg_dict[node][individual_intf].extend(cmd_list)
                        self.ascii_cfg_dict[node][individual_intf]=\
                            list(set(self.ascii_cfg_dict[node][individual_intf]))
                        ip=utils.incrementIpv6Address(ip,step_ipv6_addr)
                        prf_len=str(int(prf_len) + int(step_ipv6_prf_len))
                else:
                    pass
                params_list=filter(re.compile('^(?!start_ipv6_addr|start_ipv6_prf_len|step_ipv6_addr|step_ipv6_prf_len)').search,params_list)
            if param=='step_ipv6_prf_len' and 'start_ipv6_addr' in params_list:
                # ignore the default value for this param if start_ipv4_addr is not specified
                params_list=filter(re.compile('^(?!step_ipv6_prf_len)').search,params_list)

        # check to see if we missed processing any parameters
        if len(params_list):
            testResult('fail','Interface range parameter not handled: {0} interface {1} ipv6 parameter {2}'\
                .format(node,intf,params_list),self.log)
            sys.exit(1)



    def verifyInterfaceConfig(self):
        '''Verifies the configured state of interfaces as seen in 'show int eth x/y.'''
        # getInterfaceSwitchportDict
        # getInterfaceStatusDict
        # Verify STP state

        for node in self.interface_dict:
            if re.search('itgen|fanout',node):
                continue
            params=self.node_dict[node]['params']
            if re.search('-device_type\s+(?:itgen|fanout)',params,re.I):
                continue

            hdl=self.hdl_dict[node]

            # Physical interfaces
            for intf in self.intf_list[node]:
                show_output=hdl.iexec('show interface {0}'.format(intf))

            # SVI interfaces
            for intf in self.vlan_intf_list[node]:
                show_output=hdl.iexec('show interface {0}'.format(intf))

            # Sub interfaces
            for intf in self.sub_intf_list[node]:
                show_output=hdl.iexec('show interface {0}'.format(intf))

            # Loopback interfaces
            for intf in self.lo_intf_list[node]:
                show_output=hdl.iexec('show interface {0}'.format(intf))

            # port-channel interfaces
            for intf in self.po_intf_list[node]:
                show_output=hdl.iexec('show interface {0}'.format(intf))

            # Nve interfaces
            for intf in self.nve_intf_list[node]:
                show_output=hdl.iexec('show interface {0}'.format(intf))

            # interface range interfaces
            for intf in self.intf_range_list[node]:
                pass


    def verifyInterfaceCounters(self):
        '''Verifies there are no errored counters.'''

        intf_details_dict={}

        # gather interface info
        for node in self.interface_dict:
            if re.search('itgen|fanout',node):
                continue
            if node not in self.node_dict:
                continue
            params=self.node_dict[node]['params']
            if re.search('-device_type\s+(?:itgen|fanout)',params,re.I):
                continue

            hdl=self.hdl_dict[node]

            intf_details_dict[node]={}

            # Physical interfaces
            for intf in self.intf_list[node]:
                intf_details_dict[node][intf]=self.getInterfaceDetailsDict(hdl,intf)

            # SVI interfaces
            for intf in self.vlan_intf_list[node]:
                intf_details_dict[node][intf]=self.getInterfaceDetailsDict(hdl,intf)

            # Sub interfaces
            for intf in self.sub_intf_list[node]:
                intf_details_dict[node][intf]=self.getInterfaceDetailsDict(hdl,intf)

            # Loopback interfaces
            for intf in self.lo_intf_list[node]:
                intf_details_dict[node][intf]=self.getInterfaceDetailsDict(hdl,intf)

            # port-channel interfaces
            for intf in self.po_intf_list[node]:
                intf_details_dict[node][intf]=self.getInterfaceDetailsDict(hdl,intf)

            # Nve interfaces
            for intf in self.nve_intf_list[node]:
                intf_details_dict[node][intf]=self.getInterfaceDetailsDict(hdl,intf)

        # validate for counters
        for node in intf_details_dict:
            for intf in intf_details_dict[node]:
                for key in intf_details_dict[node][intf]['counters']:
                    # validate no negative counters
                    if int(intf_details_dict[node][intf]['counters'][key]) < 0:
                        self.log.error('{0} on {1} has negative counter for {2}'.format(intf,node,key))

                for key in intf_details_dict[node][intf]['error_counters']:
                    # validate no errors 
                    if int(intf_details_dict[node][intf]['error_counters'][key]) > 0:
                        self.log.error('{0} on {1} shows error counters for {2}'.format(intf,node,key))


    def verifyInterfaceState(self):
        '''Verifies the link state is up for interfaces that were admin noshut(unless skip is specified).'''
        pass


    def verifyInterfaceCleanup(self):
        pass


    def getPeerInfo(self,args):
        '''Get peer node and interface information.

        By default return only the physical peer node and peer interface info
        If logical peer info is requested, physical peer info is not returned

        Can be used to get other attributes (note: cant get attribute info for itgen)

        If any of the information requested is unavailable, then returns a null dictionary

        For physical peer info:
          Returns a dictionary: 
            'node01':
                 'Eth1/1': 
                     'node02':
                         'peer_type': 'switch'
                         'peer_interface': 'Eth1/1'
                         'admin_state': 'noshut'
                         'ipv4_addr': '1.1.1.1'
                 'Eth1/2': 
                     'node05':
                         'peer_type': 'fanout'
                         'peer_interface': 'Gi5/1'
            
        For logical peer info:
          Returns a dictionary: 
            'node01':
                 'Vlan10': 
                     'node02'
                         'peer_type': 'switch'
                         'peer_interface': 'Vlan10'
                         'ipv4_addr': '1.1.1.1'
                         'ipv4_prf_len': '24'
                     'node06'
                         'peer_type': 'itgen'
                         'peer_interface': 'eth2,eth3'
        '''

        # Local node input
        arggrammar={}
        arggrammar['node']='-type str -required True'
        arggrammar['interface']='-type str -required True -format {0}'\
            .format(rex.INTERFACE_RANGE)

        # Default is to return physical peer info
        # Below is to return logical peers info
        arggrammar['logical']='-type bool'

        # Peer attributes
        arggrammar['admin_state']='-type bool'
        arggrammar['mac_addr']='-type bool'
        arggrammar['ipv4_addr']='-type bool'
        arggrammar['ipv4_prf_len']='-type bool'
        arggrammar['ipv6_addr']='-type bool'
        arggrammar['ipv6_prf_len']='-type bool'

        options=parserutils_lib.argsToCommandOptions(args, arggrammar,self.log)
        if not options.VALIDARGS:
            testResult('fail','Invalid arguments specified for getPeerInfo',self.log)
            sys.exit(1)

        if len(re.split('[ ,]+',options.node))!=1:
            testResult('fail','Invalid arguments. Specify exactly one node',self.log)
            sys.exit(1)

        if options.logical:
            peers='logical_peers'
        else:
            peers='physical_peers'

        node=options.node

        if node not in self.interface_dict:
            testResult('fail','{0} not defined in interface dict'.format(node),self.log)
            return {}

        intf_list=re.split('[ ,]+',options.interface)
        peer_dict={}
        peer_dict[node]={}
        for intf in intf_list:
            intf=utils.normalizeInterfaceName(self.log,intf)
            peer_dict[node][intf]={}

            if intf not in self.interface_dict[node]:
                testResult('fail','Interface info unavailable for {0} {1}'\
                    .format(node,intf),self.log)
                return {}

            # Dont fail test here since user may want to take alternative action
            if peers not in self.interface_dict[node][intf]:
                self.log.warning('{0} info unavailable for {1} {2}'\
                    .format(peers,node,intf))
                return {}

            for peer_device in self.interface_dict[node][intf][peers]:
                peer_dict[node][intf][peer_device]={}
                peer_intf=self.interface_dict[node][intf][peers][peer_device]['peer_interface']
                peer_dict[node][intf][peer_device]['peer_interface']=peer_intf

                peer_type=self.interface_dict[node][intf][peers][peer_device]['peer_type']
                peer_dict[node][intf][peer_device]['peer_type']=peer_type

                # Make a list of attributes that need to be returned
                attribute_list=\
                    filter(re.compile('^(?!node|interface|logical)').search,options.KEYS)

                # We dont return attribute info for itgen or fanout devices because
                # today we dont configure itgen/fanout devices from interface_dict 
                # hence we dont have that info
                if peer_type in ['itgen','fanout']:
                    if attribute_list: 
                        # Dont fail test here since user may want to take alternative action
                        self.log.warning('getPeerInfo cannot provide attribute info ' +\
                            'for {0} {1} peer {2} {3} peer-type {4}'.format(node,intf,\
                            peer_device,peer_intf,peer_type))
                        continue
                    else:
                        continue

                # Dont fail test here since user may want to take alternative action
                if attribute_list and peer_device not in self.interface_dict or\
                    peer_intf not in self.interface_dict[peer_device]:
                    self.log.warning('Interface info unavailable for peer {0} {1}'\
                        .format(peer_device,peer_intf))
                    return {}

                # Dont fail test here onwards since user may want to take alternative action
                # for missing peer information

                if options.admin_state:
                    if 'base' not in self.interface_dict[peer_device][peer_intf] or\
                        'admin_state' not in self.interface_dict[peer_device][peer_intf]['base']:
                        self.log.warning('admin_state info unavailable for peer {0} {1}'\
                            .format(peer_device,peer_intf))
                        return {}
                    else:
                        peer_dict[node][intf][peer_device]['admin_state']=\
                            self.interface_dict[peer_device][peer_intf]['base']['admin_state']
    
                if options.mac_addr:
                    if 'base' not in self.interface_dict[peer_device][peer_intf] or\
                        'mac_addr' not in self.interface_dict[peer_device][peer_intf]['base']:
                        if peer_device in self.hdl_dict and\
                            self.hdl_dict[peer_device].systemmac!='0000.0000.0000':
                            peer_dict[node][intf][peer_device]['mac_addr']=\
                                self.hdl_dict[peer_device].systemmac
                        else:
                            self.log.warning('mac_addr info unavailable for peer {0} {1}'\
                                .format(peer_device,peer_intf))
                            return {}
                    else:
                        peer_dict[node][intf][peer_device]['mac_addr']=\
                            self.interface_dict[peer_device][peer_intf]['base']['mac_addr']
    
                if options.ipv4_addr:
                    if 'ipv4' not in self.interface_dict[peer_device][peer_intf] or\
                        'ipv4_addr' not in self.interface_dict[peer_device][peer_intf]['ipv4']:
                        self.log.warning('ipv4_addr info unavailable for peer {0} {1}'\
                            .format(peer_device,peer_intf))
                        return {}
                    else:
                        peer_dict[node][intf][peer_device]['ipv4_addr']=\
                            self.interface_dict[peer_device][peer_intf]['ipv4']['ipv4_addr']
    
                if options.ipv4_prf_len:
                    if 'ipv4' not in self.interface_dict[peer_device][peer_intf] or\
                        'ipv4_prf_len' not in self.interface_dict[peer_device][peer_intf]['ipv4']:
                        self.log.warning('ipv4_prf_len info unavailable for peer {0} {1}'\
                            .format(peer_device,peer_intf))
                        return {}
                    else:
                        peer_dict[node][intf][peer_device]['ipv4_prf_len']=\
                            self.interface_dict[peer_device][peer_intf]['ipv4']['ipv4_prf_len']
    
                if options.ipv6_addr:
                    if 'ipv6' not in self.interface_dict[peer_device][peer_intf] or\
                        'ipv6_addr' not in self.interface_dict[peer_device][peer_intf]['ipv6']:
                        self.log.warning('ipv6_addr info unavailable for peer {0} {1}'\
                            .format(peer_device,peer_intf))
                        return {}
                    else:
                        peer_dict[node][intf][peer_device]['ipv6_addr']=\
                            self.interface_dict[peer_device][peer_intf]['ipv6']['ipv6_addr']
    
                if options.ipv6_prf_len:
                    if 'ipv6' not in self.interface_dict[peer_device][peer_intf] or\
                        'ipv6_prf_len' not in self.interface_dict[peer_device][peer_intf]['ipv6']:
                        self.log.warning('ipv6_prf_len info unavailable for peer {0} {1}'\
                            .format(peer_device,peer_intf))
                        return {}
                    else:
                        peer_dict[node][intf][peer_device]['ipv6_prf_len']=\
                            self.interface_dict[peer_device][peer_intf]['ipv6']['ipv6_prf_len']
    
        return peer_dict


    def getInterfaceDetailsDict(self,hdl,intf):
    
        intf_output=hdl.iexec('show interface {0}'.format(intf))
    
        intf_details_dict={}
    
        result=re.search('admin state is ([a-z]+),',intf_output,re.I)
        if result:
            intf_details_dict['admin_state']=result.group(1)
    
        result=re.search('Belongs to (Po[0-9]+)',intf_output,re.I)
        if result:
            intf_details_dict['parent_po']=result.group(1)
    
        result=re.search('address: ({0})'.format(rex.MACADDR),intf_output,re.I)
        if result:
            intf_details_dict['mac_addr']=result.group(1)
    
        result=re.search('MTU ([0-9]+)',intf_output,re.I)
        if result:
            intf_details_dict['mtu']=result.group(1)
    
        result=re.search('Port mode is (\S)',intf_output,re.I)
        if result:
            intf_details_dict['port_mode']=result.group(1)
        else:
            intf_details_dict['port_mode']='routed'
    
        result=re.search('(?:auto-duplex|full-duplex), ([0-9]+|auto-speed)',intf_output,re.I)
        if result:
            intf_details_dict['speed']=result.group(1)
    
        result=re.search('Auto-Negotiation is turned ([a-z]+)',intf_output,re.I)
        if result:
            intf_details_dict['auto_neg']=result.group(1)
    
        result=re.search('Auto-Negotiation is turned ([a-z]+)',intf_output,re.I)
        if result:
            intf_details_dict['auto_neg']=result.group(1)
    
        result=re.search('Input flow-control is ([a-z]+),',intf_output,re.I)
        if result:
            intf_details_dict['rx_flowcontrol']=result.group(1)
    
        result=re.search('output flow-control is ([a-z]+),',intf_output,re.I)
        if result:
            intf_details_dict['tx_flowcontrol']=result.group(1)
    
        result=re.search('Switchport monitor is ([a-z]+),',intf_output,re.I)
        if result:
            intf_details_dict['monitor_mode']=result.group(1)
    
        result=re.search('Last link flapped (\S)',intf_output,re.I)
        if result:
            intf_details_dict['last_link_flap']=result.group(1)
    
        result=re.search('Last clearing of "show interface" counters (\S)',intf_output,re.I)
        if result:
            intf_details_dict['last_clear_counters']=result.group(1)
    
        result=re.search('([0-9]+) interface resets',intf_output,re.I)
        if result:
            intf_details_dict['interface_resets']=result.group(1)
    
        result=re.search('([0-9]+) seconds input rate ([0-9]+) bits/sec, ([0-9]+) packets/sec',intf_output,re.I)
        if result:
            intf_details_dict['load_interval_1_duration']=result.group(1)
            intf_details_dict['load_interval_1_rx_bps']=result.group(2)
            intf_details_dict['load_interval_1_rx_pps']=result.group(3)
    
        result=re.search('([0-9]+) seconds output rate ([0-9]+) bits/sec, ([0-9]+) packets/sec',intf_output,re.I)
        if result:
            intf_details_dict['load_interval_1_duration']=result.group(1)
            intf_details_dict['load_interval_1_tx_bps']=result.group(2)
            intf_details_dict['load_interval_1_tx_pps']=result.group(3)
    
        result=re.search('Load-Interval #2: ([0-9]+) seconds[\r\n ]+input rate ([0-9]+) bps, ([0-9]+) pps; output rate ([0-9]+) bps, ([0-9]+) pps',intf_output,re.I)
        if result:
            intf_details_dict['load_interval_2_duration']=result.group(1)
            intf_details_dict['load_interval_2_rx_bps']=result.group(2)
            intf_details_dict['load_interval_2_rx_pps']=result.group(3)
            intf_details_dict['load_interval_2_tx_bps']=result.group(4)
            intf_details_dict['load_interval_2_tx_pps']=result.group(5)
    
        result=re.search('Load-Interval #3: ([0-9]+) seconds[\r\n ]+input rate ([0-9]+) bps, ([0-9]+) pps; output rate ([0-9]+) bps, ([0-9]+) pps',intf_output,re.I)
        if result:
            intf_details_dict['load_interval_3_duration']=result.group(1)
            intf_details_dict['load_interval_3_rx_bps']=result.group(2)
            intf_details_dict['load_interval_3_rx_pps']=result.group(3)
            intf_details_dict['load_interval_3_tx_bps']=result.group(4)
            intf_details_dict['load_interval_3_tx_pps']=result.group(5)
    
        intf_details_dict['counters']={}
        intf_details_dict['error_counters']={}
    
        # physical and port-channel interface counters
        pattern='RX[\r\n ]+([0-9]+) unicast packets  ([0-9]+) multicast packets  ([0-9]+) broadcast packets[\r\n ]+([0-9]+) input packets  ([0-9]+) bytes[\r\n ]+([0-9]+) jumbo packets  ([0-9]+) storm suppression packets[\r\n ]+([0-9]+) runts  ([0-9]+) giants  ([0-9]+) CRC  ([0-9]+) no buffer[\r\n ]+([0-9]+) input error  ([0-9]+) short frame  ([0-9]+) overrun   ([0-9]+) underrun  ([0-9]+) ignored[\r\n ]+([0-9]+) watchdog  ([0-9]+) bad etype drop  ([0-9]+) bad proto drop  ([0-9]+) if down drop[\r\n ]+([0-9]+) input with dribble  ([0-9]+) input discard[\r\n ]+([0-9]+) Rx pause'
        result=re.search(pattern,intf_output,re.I)
        if result:
            # all counters
            intf_details_dict['counters']['rx_ucast']=result.group(1)
            intf_details_dict['counters']['rx_mcast']=result.group(2)
            intf_details_dict['counters']['rx_bcast']=result.group(3)
            intf_details_dict['counters']['rx_pkts']=result.group(4)
            intf_details_dict['counters']['rx_bytes']=result.group(5)
            intf_details_dict['counters']['rx_jumbo']=result.group(6)
            intf_details_dict['counters']['rx_storm_supp_pkts']=result.group(7)
            intf_details_dict['counters']['rx_runts']=result.group(8)
            intf_details_dict['counters']['rx_giants']=result.group(9)
            intf_details_dict['counters']['rx_crc']=result.group(10)
            intf_details_dict['counters']['rx_no_buffer']=result.group(11)
            intf_details_dict['counters']['rx_err']=result.group(12)
            intf_details_dict['counters']['rx_short_frame']=result.group(13)
            intf_details_dict['counters']['rx_overrun']=result.group(14)
            intf_details_dict['counters']['rx_underrun']=result.group(15)
            intf_details_dict['counters']['rx_ignored']=result.group(16)
            intf_details_dict['counters']['rx_watchdog']=result.group(17)
            intf_details_dict['counters']['rx_bad_etype']=result.group(18)
            intf_details_dict['counters']['rx_bad_proto']=result.group(19)
            intf_details_dict['counters']['rx_ifdown']=result.group(20)
            intf_details_dict['counters']['rx_dribble']=result.group(21)
            intf_details_dict['counters']['rx_discard']=result.group(22)
            intf_details_dict['counters']['rx_pause']=result.group(23)
    
            # error counters
            intf_details_dict['error_counters']['rx_storm_supp_pkts']=result.group(7)
            intf_details_dict['error_counters']['rx_runts']=result.group(8)
            intf_details_dict['error_counters']['rx_giants']=result.group(9)
            intf_details_dict['error_counters']['rx_crc']=result.group(10)
            intf_details_dict['error_counters']['rx_no_buffer']=result.group(11)
            intf_details_dict['error_counters']['rx_err']=result.group(12)
            intf_details_dict['error_counters']['rx_short_frame']=result.group(13)
            intf_details_dict['error_counters']['rx_overrun']=result.group(14)
            intf_details_dict['error_counters']['rx_underrun']=result.group(15)
            intf_details_dict['error_counters']['rx_ignored']=result.group(16)
            intf_details_dict['error_counters']['rx_watchdog']=result.group(17)
            intf_details_dict['error_counters']['rx_bad_etype']=result.group(18)
            intf_details_dict['error_counters']['rx_bad_proto']=result.group(19)
            intf_details_dict['error_counters']['rx_ifdown']=result.group(20)
            intf_details_dict['error_counters']['rx_dribble']=result.group(21)
            intf_details_dict['error_counters']['rx_discard']=result.group(22)

        # physical and port-channel interface counters
        pattern='TX[\r\n ]+([0-9]+) unicast packets  ([0-9]+) multicast packets  ([0-9]+) broadcast packets[\r\n ]+([0-9]+) output packets  ([0-9]+) bytes[\r\n ]+([0-9]+) jumbo packets[\r\n ]+([0-9]+) output error  ([0-9]+) collision  ([0-9]+) deferred  ([0-9]+) late collision[\r\n ]+([0-9]+) lost carrier  ([0-9]+) no carrier  ([0-9]+) babble  ([0-9]+) output discard[\r\n ]+([0-9]+) Tx pause'
        result=re.search(pattern,intf_output,re.I)
        if result:
            # all counters
            intf_details_dict['counters']['tx_ucast']=result.group(1)
            intf_details_dict['counters']['tx_mcast']=result.group(2)
            intf_details_dict['counters']['tx_bcast']=result.group(3)
            intf_details_dict['counters']['tx_pkts']=result.group(4)
            intf_details_dict['counters']['tx_bytes']=result.group(5)
            intf_details_dict['counters']['tx_jumbo']=result.group(6)
            intf_details_dict['counters']['tx_err']=result.group(7)
            intf_details_dict['counters']['tx_collision']=result.group(8)
            intf_details_dict['counters']['tx_deferred']=result.group(9)
            intf_details_dict['counters']['tx_late_collision']=result.group(10)
            intf_details_dict['counters']['tx_lost_carrier']=result.group(11)
            intf_details_dict['counters']['tx_no_carrier']=result.group(12)
            intf_details_dict['counters']['tx_babble']=result.group(13)
            intf_details_dict['counters']['tx_discard']=result.group(14)
            intf_details_dict['counters']['tx_pause']=result.group(15)

            # error counters
            intf_details_dict['error_counters']['tx_err']=result.group(7)
            intf_details_dict['error_counters']['tx_collision']=result.group(8)
            intf_details_dict['error_counters']['tx_deferred']=result.group(9)
            intf_details_dict['error_counters']['tx_late_collision']=result.group(10)
            intf_details_dict['error_counters']['tx_lost_carrier']=result.group(11)
            intf_details_dict['error_counters']['tx_no_carrier']=result.group(12)
            intf_details_dict['error_counters']['tx_babble']=result.group(13)
            intf_details_dict['error_counters']['tx_discard']=result.group(14)

        # loopback interface counters
        pattern='([0-9]+) packets input ([0-9]+) bytes[\r\n ]+([0-9]+) multicast frames ([0-9]+) compressed[\r\n ]+([0-9]+) input errors ([0-9]+) frame ([0-9]+) overrun ([0-9]+) fifo[\r\n ]+([0-9]+) packets output ([0-9]+) bytes ([0-9]+) underruns[\r\n ]+([0-9]+) output errors ([0-9]+) collisions ([0-9]+) fifo[\r\n ]+([0-9]+) out_carrier_errors'
        result=re.search(pattern,intf_output,re.I)
        if result:
            # all counters
            intf_details_dict['counters']['rx_pkts']=result.group(1)
            intf_details_dict['counters']['rx_bytes']=result.group(2)
            intf_details_dict['counters']['rx_mcast_frames']=result.group(3)
            intf_details_dict['counters']['rx_compressed']=result.group(4)
            intf_details_dict['counters']['rx_err']=result.group(5)
            intf_details_dict['counters']['rx_frame']=result.group(6)
            intf_details_dict['counters']['rx_overrun']=result.group(7)
            intf_details_dict['counters']['rx_fifo']=result.group(8)
            intf_details_dict['counters']['tx_pkts']=result.group(9)
            intf_details_dict['counters']['tx_bytes']=result.group(10)
            intf_details_dict['counters']['tx_underruns']=result.group(11)
            intf_details_dict['counters']['tx_err']=result.group(12)
            intf_details_dict['counters']['tx_collisions']=result.group(13)
            intf_details_dict['counters']['tx_fifo']=result.group(14)
            intf_details_dict['counters']['tx_carrier_err']=result.group(15)
    
            # error counters
            intf_details_dict['error_counters']['rx_err']=result.group(5)
            intf_details_dict['error_counters']['rx_frame']=result.group(6)
            intf_details_dict['error_counters']['rx_overrun']=result.group(7)
            intf_details_dict['error_counters']['rx_fifo']=result.group(8)
            intf_details_dict['error_counters']['tx_underruns']=result.group(11)
            intf_details_dict['error_counters']['tx_err']=result.group(12)
            intf_details_dict['error_counters']['tx_collisions']=result.group(13)
            intf_details_dict['error_counters']['tx_fifo']=result.group(14)
            intf_details_dict['error_counters']['tx_carrier_err']=result.group(15)

        return intf_details_dict


class cleanupInterface(object):
    '''Clear configs for interfaces in interface_config_dict'''

    def __init__(self,log,switch_hdl_dict=None,node_dict=None,interface_config_dict=None,clear_all=False):

        self.log=log

        try:
            self.result
        except:
            self.result='pass'

        if not node_dict:
            try:
                self.node_dict
            except:
                self.log.error('node_dict not available')
                self.result='fail'
                return
        else:
            self.node_dict=node_dict

        if not switch_hdl_dict:
            try:
                self.hdl_dict
            except:
                self.log.error('switch_hdl_dict not available')
                self.result='fail'
                return
        else:
            self.hdl_dict=switch_hdl_dict

        if not interface_config_dict:
            try:
                self.interface_config_dict
            except:
                self.log.error('interface_config_dict not available')
                self.result='fail'
                return
        else:
            self.interface_config_dict=interface_config_dict

            interface_obj=bringupInterface(log,switch_hdl_dict,node_dict,interface_config_dict,\
                '-generate_ascii_only -skip_verify')
            self.interface_dict=interface_obj.interface_dict
            self.ascii_cfg_dict=interface_obj.ascii_cfg_dict
            self.vlan_intf_list=interface_obj.vlan_intf_list
            self.sub_intf_list=interface_obj.sub_intf_list
            self.lo_intf_list=interface_obj.lo_intf_list
            self.po_intf_list=interface_obj.po_intf_list
            self.nve_intf_list=interface_obj.nve_intf_list
            self.intf_list=interface_obj.intf_list

        self.log.info('Begin interface cleanup')

        # unconfig here based on ascii_cfg_dict
        for node in self.interface_dict:
            if re.search('itgen|fanout',node):
                continue
            params=self.node_dict[node]['params']
            if re.search('-device_type\s+(?:itgen|fanout)',params,re.I):
                continue

            hdl=self.hdl_dict[node]

            intf_list=[]
            intf_list.extend(self.vlan_intf_list[node])
            intf_list.extend(self.sub_intf_list[node])
            intf_list.extend(self.lo_intf_list[node])
            intf_list.extend(self.po_intf_list[node])
            intf_list.extend(self.nve_intf_list[node])
            intf_list.extend(self.intf_list[node])

            ascii_cfg_dict=self.ascii_cfg_dict[node]

            self.clearConfig(hdl,node,intf_list,ascii_cfg_dict,clear_all)


    def clearConfig(self,hdl,node,intf_list,ascii_cfg_dict,clear_all=False):
        '''Unconfigure commands under the given interfaces'''
    
        global_config_list=ascii_cfg_dict['global']

        logical_intf_list=filter(re.compile('^(?:Lo|Po|Vlan)',re.I).search,intf_list)
        physical_intf_list=filter(re.compile('^(?!Lo|Po|Vlan|global)',re.I).search,intf_list)

        # Process logical interfaces before physical
        intf_list=logical_intf_list + physical_intf_list
    
        for intf in intf_list:
            # get running-config
            intf_config=getRunningConfig(hdl,self.log,'-interface {0}'.format(intf))
            if re.search('Invalid ',intf_config,re.I):
                continue
            config_list=[]
            for cmd in intf_config.split('\r\n'):
                if cmd.strip():
                    config_list.append(cmd.strip())

            if len(config_list)==1:
                if intf in logical_intf_list:
                    if not re.search('vlan1$',intf,re.I):
                        hdl.configure('no interface {0}'.format(intf))
                continue

            if intf in logical_intf_list:
                if not re.search('vlan1$',intf,re.I):
                    hdl.configure('no interface {0}'.format(intf))

            intf_cmd=config_list[0]
            config_list.reverse()
            unconfig_list=[]
            unconfig_list.append(intf_cmd)

            additional_cfg_found=0
            trunk_mode_unconfig=1
            for cmd in config_list[:-1]:
                if cmd:
                    if (cmd=='switchport mode trunk' or cmd=='switchport') and not trunk_mode_unconfig:
                        # if trunk vlans were modified then dont change the mode back to access
                        # there are many more scenarios to worry about. Probably good to just
                        # blindly issue unconfig for our commands and leave it at that
                        continue
                    if not clear_all and cmd not in ascii_cfg_dict[intf]:
                        additional_cfg_found=1
                        if not re.search('switchport trunk allowed',cmd):
                            # if additional command does not begin with this then skip unconfig
                            continue
                        else:
                            # if additional vlans are seen for this command 
                            cmd=filter(re.compile('^switchport trunk allowed').search,\
                                    ascii_cfg_dict[intf])
                            if not cmd:
                                # skip unconfig if this command was never configured by you
                                continue
                            else:
                                # unconfig only what you configured
                                cmd=re.sub('allowed vlan','allowed vlan remove',cmd[0])
                                trunk_mode_unconfig=0
                                    
                    else:
                        # below is to avoid leaving behind 'switchport trunk allowed vlan none'
                        if re.search('switchport trunk allowed',cmd):
                            cmd='switchport trunk allowed vlan'

                    if re.search('^no ',cmd):
                        unconfig_list.append(re.sub('^no ','',cmd))
                    else:
                        unconfig_list.append('no ' + cmd)

            hdl.iexec('config t')
            for cmd in unconfig_list:
                done=0
                while not done:
                    cmd_response=hdl.iexec(cmd)
                    if re.search('Invalid command',cmd_response,re.I):
                        cmd_list=cmd.split()
                        cmd=' '.join(cmd_list[:-1])
                    else:
                        done=1
            hdl.iexec('end')

            if not additional_cfg_found and intf in logical_intf_list:
                # All interface config have been unconfigured. So delete logical intf
                if not re.search('vlan1$',intf,re.I):
                    hdl.configure('no interface {0}'.format(intf))

            if clear_all and intf in logical_intf_list:
                # Delete logical interfaces
                if not re.search('vlan1$',intf,re.I):
                    hdl.configure('no interface {0}'.format(intf))



class bringupInterface(verifyInterface,cleanupInterface):
    '''Class to bring up interfaces in a testbed for interfaces specified in the interface_config_dict. 

    What is not handled here:
      - fex fabric interfaces (defined under node_dict and broughtup using fex_lib)
      - vPC interfaces (defined under vpc_dict and broughtup using vpc_lib)
      - mgmt interface (defined under node_dict and broughtup using connectToNodes)
      - protocols configs (handled by individual protocol libs)
      - acl/qos configs (handled by individual acl/qos dict)
      
    interface_config_dict looks like below in the input yml file:

    Note: Iterative parameters for range of interfaces should have the format:
          -start_<param> and -step_<param> 
              where <param> is any valid parameter as defined in arggrammar

    interface_config_dict:
        node01:
            Eth8/21:
                port_profile: 
                    -name profile2 # This will ignore the rest of the parameters
                base_config: 
                    -speed 10000 -duplex full -flowcontrol send,receive -link_debounce 10 -mtu 2000 -logging link-status,trunk-status -load_interval [(1,30),(2,300),(3,200)] -udld aggressive -state shutdown
                switchport: 
                    -switch_port_mode access -vlan_id 2 -allowed_vlan_list 2-4,6,8 
                ipv4: 
                    -ipv4_addr 11.1.1.20 -ipv4_prf_len 24 -secondary_ipv4 12.1.1.20 -proxy-arp -urpf True -redirects False -directed_broadcast -static_arp [(1.2.3.4,aaaa.bbbb.cccc),(6.7.8.9,dddd.eeee.ffff)]
                ipv6: 
                    -ipv6_addr 2001::11:1:1:20 -ipv6_prf_len 96
            Eth1/1-3,Eth1/5-7: # Range itself as key
                port_profile: 
                    -name profile1 # This will ignore the rest of the parameters
                base_config: 
                    -udld aggressive -PFC auto # Put udld under interfaces in udld_dict
            Vlan2-200: 
                base_config: 
                    -mtu 3000 -udld disable
                ipv4: 
                    -start_ipv4_addr 10.1.2.252 -start_ipv4_prf_len 24 -step_ipv4_addr 0.0.1.0 -vrf_name default
            all:
                port_profile: 
                    -name profile1 # This will ignore the rest of the parameters
                base_config: 
                    -mtu 5000 -duplex auto -load_interval [(2,100)] -udld enable
    '''

    def __init__(self,log,switch_hdl_dict,node_dict,interface_config_dict,*args):
          
        self.result='pass'
        self.log=log
        self.node_dict=node_dict
        self.hdl_dict=switch_hdl_dict
        self.interface_config_dict=interface_config_dict

        init_grammar={}
        init_grammar['skip_config']='-type bool'
        init_grammar['skip_verify']='-type bool'
        init_grammar['config_type']='-type str -format (?:all-)?((base_config|switchport|ipv4|ipv6|(?<!-)all)([ ,]+|$))+ -default all'
        #init_grammar['config_type']='-type str -format (base_config|switchport|ipv4|ipv6|all|,|\ )+ -default all'

        # use below if you want to just generate ascii config while 
        # skipping config without using skip_config flag 
        init_grammar['generate_ascii_only']='-type bool'
        init_grammar['verify_connectivity_only']='-type bool'
        init_grammar['mutualExclusive'] =[('skip_config','generate_ascii_only'), ('skip_verify','verify_connectivity_only'),\
                                          ('generate_ascii_only','verify_connectivity_only')]

        init_options=parserutils_lib.argsToCommandOptions(args,init_grammar,self.log )
        if not init_options.VALIDARGS:
            testResult('fail','Invalid arguments to bringup init',self.log)
            sys.exit()

        self.generate_ascii_only=init_options.generate_ascii_only
        self.verify_connectivity_only=init_options.verify_connectivity_only

        # Dont configure anything other than physical interfaces (admin_state)
        if self.verify_connectivity_only:
            init_options.skip_config=True

        # Get the resultant config_type from input
        if re.search('-',init_options.config_type):
            all_config_type=['base_config','switchport','ipv4','ipv6']
            config_type=re.search('all-(.*)',init_options.config_type).group(1)
            config_type=set(re.split('[ ,]+',config_type))
            config_type=filter(str.strip,list(config_type))
            for item in config_type:
                all_config_type.remove(item)
            self.config_type=all_config_type
        else:
            config_type=re.sub('all','base_config,switchport,ipv4,ipv6',init_options.config_type)
            config_type=set(re.split('[ ,]+',config_type))
            self.config_type=filter(str.strip,list(config_type))

        self.log.info('Begin interface bringup')

        # Parse the input yml dict and create local data structures (interface_dict)
        verifyInterface.__init__(self,log)

        # Maintain a dict of config commands
        self.ascii_cfg_dict={}

        for node in self.interface_dict:
            if re.search('itgen|fanout',node):
                continue
            if node not in self.node_dict:
                continue
            params=self.node_dict[node]['params']
            if re.search('-device_type\s+(?:itgen|fanout)',params,re.I):
                continue

            self.ascii_cfg_dict[node]={}
            self.ascii_cfg_dict[node]['global']=[]

            hdl=self.hdl_dict[node]

            # Config only physical interfaces (for admin_state)
            if self.verify_connectivity_only:
                for intf in self.intf_list[node]:
                    self.ascii_cfg_dict[node][intf]=[]
                    self.individualConfig(node,intf)

            # If config needs to be skipped, jump to verifyInterfaceBringup
            if not init_options.skip_config:
                # First configure global_config if any
                for global_cfg_type in self.global_config_dict[node]:
                    self.globalConfig(node,global_cfg_type)

                # Enable feature interface-vlan
                if self.vlan_intf_list[node]:
                    if not self.generate_ascii_only:
                        bringup_lib.configFeature(hdl,self.log,'-feature interface-vlan')
                    self.ascii_cfg_dict[node]['global'].append('feature interface-vlan')
                    # configure vlans for SVI interfaces
                    v_list=[re.search('([0-9]+)',vlan,re.I).group(1) for vlan in self.vlan_intf_list[node]]
                    vlans=','.join(v_list)
                    cmds='vlan {0}'.format(vlans)
                    if not self.generate_ascii_only:
                        hdl.configure(cmds)
                    self.ascii_cfg_dict[node]['global'].append(cmds)

                # configure SVI 
                for intf in self.vlan_intf_list[node]:
                    self.ascii_cfg_dict[node][intf]=[]
                    self.individualConfig(node,intf)

                # configure sub-intf 
                for intf in self.sub_intf_list[node]:
                    self.ascii_cfg_dict[node][intf]=[]
                    self.individualConfig(node,intf)

                # configure loopback 
                for intf in self.lo_intf_list[node]:
                    self.ascii_cfg_dict[node][intf]=[]
                    self.individualConfig(node,intf)

                # configure port-channel
                for intf in self.po_intf_list[node]:
                    self.ascii_cfg_dict[node][intf]=[]
                    self.individualConfig(node,intf)

                # configure nve 
                for intf in self.nve_intf_list[node]:
                    self.ascii_cfg_dict[node][intf]=[]
                    self.individualConfig(node,intf)

                # configure physical interfaces
                # note: the individual intf from ranges are also part of intf_list
                for intf in self.intf_list[node]:
                    self.ascii_cfg_dict[node][intf]=[]
                    self.individualConfig(node,intf)

                # process iterative params for ranges
                for intf in self.intf_range_list[node]:
                    self.rangeConfig(node,intf)

                # Commenting this section below because it is merging parent configs even when each 
                # of them have different child configs
                # store only unique global configs in ascii
                #self.ascii_cfg_dict[node]['global']=list(set(self.ascii_cfg_dict[node]['global']))
                #global_vlan_list=\
                #    filter(re.compile('^vlan ',re.I).search,self.ascii_cfg_dict[node]['global'])
                #self.ascii_cfg_dict[node]['global']=\
                #    filter(re.compile('^(?!vlan )',re.I).search,self.ascii_cfg_dict[node]['global'])
                # merge all vlan ranges in ascii
                #if global_vlan_list:
                #    vlans=[re.search('vlan +(.*)',vlans,re.I).group(1) for vlans in global_vlan_list]
                #    vlans=list(set(utils.strToExpandedList(','.join(vlans))))
                #    vlans.sort(key=int)
                #    vlans=','.join(utils.shortenedList(vlans))
                #    self.ascii_cfg_dict[node]['global'].append('vlan {0}'.format(vlans))

        if not init_options.skip_verify:
            self.verifyInterfaceBringup()


    def globalConfig(self,node,global_cfg_type):
        '''Configure global parameters for given node.'''

        self.log.info('Configuring global configs for {0}'.format(node))

        hdl=self.hdl_dict[node]

        if global_cfg_type=='pvlan':
            # configure global pvlan config
            if 'pvlan' in self.global_config_dict[node].keys() and \
                len(self.global_config_dict[node]['pvlan'].keys()):
                self.globalPvlanConfigAndVerify(node,'-mode config')

        if global_cfg_type=='vxlan':
            # configure global vxlan config
            if 'vxlan' in self.global_config_dict[node].keys() and \
                len(self.global_config_dict[node]['vxlan'].keys()):
                self.globalVxlanConfigAndVerify(node,'-mode config')


    def individualConfig(self,node,intf):
        '''Configure interface parameters for given interface.'''

        self.log.info('Configuring interface {0}'.format(intf))

        hdl=self.hdl_dict[node]

        if 'base_config' in self.config_type:
            # configure base
            if 'base' in self.interface_dict[node][intf].keys() and \
                len(self.interface_dict[node][intf]['base'].keys()):
                self.baseConfigAndVerify(node,intf,'-mode config')

        if self.verify_connectivity_only:
            return

        if 'switchport' in self.config_type:
            # configure switchport
            if 'switchport' in self.interface_dict[node][intf].keys() and \
                len(self.interface_dict[node][intf]['switchport'].keys()):
                self.switchportConfigAndVerify(node,intf,'-mode config')

        if 'ipv4' in self.config_type:
            # configure ipv4
            if 'ipv4' in self.interface_dict[node][intf].keys() and \
                len(self.interface_dict[node][intf]['ipv4'].keys()):
                self.ipv4ConfigAndVerify(node,intf,'-mode config')

        if 'ipv6' in self.config_type:
            # configure ipv6
            if 'ipv6' in self.interface_dict[node][intf].keys() and \
                len(self.interface_dict[node][intf]['ipv6'].keys()):
                self.ipv6ConfigAndVerify(node,intf,'-mode config')


    def rangeConfig(self,node,intf):
        '''Configure iterative parameters for an interface range.'''

        self.log.info('Configuring iterative params for interfaces {0}'.format(intf))

        hdl=self.hdl_dict[node]

        if 'base_config' in self.config_type:
            # configure base
            if 'base' in self.interface_dict[node]['range'][intf].keys() and \
                len(self.interface_dict[node]['range'][intf]['base'].keys()):
                self.baseRangeConfigAndVerify(node,intf,'-mode config')

        if 'switchport' in self.config_type:
            # configure switchport
            if 'switchport' in self.interface_dict[node]['range'][intf].keys() and \
                len(self.interface_dict[node]['range'][intf]['switchport'].keys()):
                self.switchportRangeConfigAndVerify(node,intf,'-mode config')

        if 'ipv4' in self.config_type:
            # configure ipv4
            if 'ipv4' in self.interface_dict[node]['range'][intf].keys() and \
                len(self.interface_dict[node]['range'][intf]['ipv4'].keys()):
                self.ipv4RangeConfigAndVerify(node,intf,'-mode config')

        if 'ipv6' in self.config_type:
            # configure ipv6
            if 'ipv6' in self.interface_dict[node]['range'][intf].keys() and \
                len(self.interface_dict[node]['range'][intf]['ipv6'].keys()):
                self.ipv6RangeConfigAndVerify(node,intf,'-mode config')

    def verifyInterface(self):
        verifyInterface.__init__(self,self.log)


    def cleanupInterface(self,clear_all=False):
        cleanupInterface.__init__(self,self.log,clear_all=clear_all)


def parseIpv4Configs( log, args):
    ipv4_grammar={}
    # ipv4 config
    ipv4_grammar['ipv4_addr']='-type str -mandatoryargs ipv4_prf_len -format {0}'.format(rex.IPv4_ADDR)
    ipv4_grammar['ipv4_prf_len']='-type str -mandatoryargs ipv4_addr -format [0-9]+'
    ipv4_grammar['secondary_ipv4']='-type list -mandatoryargs ipv4_addr' #Format: [('1.2.3.4',24),('192.168.1.1',24)]
    ipv4_grammar['vrf']='-type str -default default'
    ipv4_grammar['proxy_arp']='-type bool'
    ipv4_grammar['redirects']='-type bool'
    ipv4_grammar['directed_broadcast']='-type bool'
    ipv4_grammar['urpf']='-type str -choices ["any","rx"]'
    ipv4_grammar['static_arp']='-type list' #Format: [('1.2.3.4','aaaa.bbbb.cccc'),('6.7.8.9','dddd.eeee.ffff')]
    ipv4_grammar['igmp_group_timeout']='-type int'
    ns=parserutils_lib.argsToCommandOptions( args, ipv4_grammar, log )
    return ns



def parseIpv6Configs( log, args ):
    ipv6_grammar={}
    # ipv6 config
    ipv6_grammar['ipv6_addr']='-type str -mandatoryargs ipv6_prf_len -format {0}'.format(rex.IPv6_ADDR)
    ipv6_grammar['ipv6_prf_len']='-type str -mandatoryargs ipv6_addr -format [0-9]+'
    ipv6_grammar['vrf']='-type str -default default'
    ipv6_grammar['secondary_ipv6']='-type list -mandatoryargs ipv6_addr' #Format: [('2001::1:1:1:1',64),('2001::2:2:2:2',96)]
    ns=parserutils_lib.argsToCommandOptions( args, ipv6_grammar, log )
    return ns

def getNodeIpv4AddressDict( log, interface_config_dict ):

    ipv4_addr_dict={}
    node_list=interface_config_dict.keys()
    for node in node_list:
        interface_list=interface_config_dict[node].keys()
        ip_addr_list=[]
        for intf in interface_list:
            if interface_config_dict[node][intf].has_key('ipv4'):
                ns=parseIpv4Configs( log, interface_config_dict[node][intf]['ipv4'] )
                ip_addr_list.append(ns.ipv4_addr)
        ipv4_addr_dict[node]=ip_addr_list
    return ipv4_addr_dict
                


def getNodeIpv6AddressDict( log, interface_config_dict ):

    ipv6_addr_dict={}
    node_list=interface_config_dict.keys()
    for node in node_list:
        interface_list=interface_config_dict[node].keys()
        ip_addr_list=[]
        for intf in interface_list:
            if interface_config_dict[node][intf].has_key('ipv6'):
                ns=parseIpv6Configs( log, interface_config_dict[node][intf]['ipv6'] )
                ip_addr_list.append(ns.ipv6_addr)
        ipv6_addr_dict[node]=ip_addr_list
    return ipv6_addr_dict

class config_hsrp(object):
    '''
     Will config HSRP on switches as per following hsrp dictionary
     hsrp_config_dict:
        node03:
           track_object:
              1: -interface Eth1/1
           interfaces:
              Eth1/3:
                 hsrp:
                    1: -ipv4_addr 1.1.1.254 -preempt True -priority 100 -track_obj 1
                    2: -ipv4_addr 1.1.1.253 -preempt True -priority 100 -track_obj 1
                    3: -ipv4_addr 1.1.1.252 -preempt True -priority 100 -track_obj 1 -track_decrement 10
                    4: -ipv4_addr 1.1.1.251 -preempt True -priority 100 -track_obj 1
                    5: -ipv4_addr 1.1.1.250 -preempt True -priority 100 -track_obj 1
              Vlan300:
                    1: -ipv4_addr 2.1.1.254 -preempt True -priority 100 -track_obj 1
              Po100:
                    1: -ipv4_addr 3.1.1.254 -preempt True -priority 100 -track_obj 1
    '''
    def __init__(self, log, switch_hdl_dict=None, hsrp_config_dict=None):

        self.log=log

        self.result='pass'

        if not switch_hdl_dict:
            self.log.error('switch_hdl_dict not available')
            self.result='fail'
            return
        else:
            self.hdl_dict=switch_hdl_dict

        if not hsrp_config_dict:
            self.log.error('hsrp_config_dict not available')
            self.result='fail'
            return
        else:
            self.hsrp_config_dict=hsrp_config_dict

        #First config tracking objects if specified
        for node in self.hsrp_config_dict.keys():
           if 'track_object' in self.hsrp_config_dict[node].keys():
              for obj_n in self.hsrp_config_dict[node]['track_object'].keys():
                 arggrammar={}
                 arggrammar['interface']='-type str'
                 arggrammar['ip']='-type str'
                 arggrammar['ipv6']='-type str'
                 arggrammar['list']='-type str'
                 cmd_list = self.hsrp_config_dict[node]['track_object'][obj_n]
                 parse = parserutils_lib.argsToCommandOptions( cmd_list, arggrammar, self.log )

                 if parse.interface:
                    self.hdl_dict[node].configure('track ' + str(obj_n) + ' interface ' + parse.interface + ' line-protocol')

        # config hsrp objects if specified
        for node in self.hsrp_config_dict.keys():
           output_buff = self.hdl_dict[node].configure('feature hsrp')
           if 'interfaces' in self.hsrp_config_dict[node].keys():
              for intf in self.hsrp_config_dict[node]['interfaces'].keys():
                  match = re.search(r'vlan', intf, re.IGNORECASE)
                  if match is None:
                     output_buff = self.hdl_dict[node].iexec('show interface ' + intf + ' brief')
                     match = re.search(r'routed', output_buff)
                     if match is None:
                        err_msg='FAIL:Interface {0} is a L2 interface, HSRP cann\'t be configured on it {0}'.format(intf)
                        testResult( 'fail', err_msg, self.log )
                        self.result='fail'
                        return
                  if 'hsrp' in self.hsrp_config_dict[node]['interfaces'][intf].keys():
                     for hsrp_no in self.hsrp_config_dict[node]['interfaces'][intf]['hsrp'].keys():
                         arggrammar={}
                         arggrammar['ipv4_addr']='-type str'
                         arggrammar['preempt']='-type str'
                         arggrammar['priority']='-type str'
                         arggrammar['track_obj']='-type str'
                         arggrammar['track_decrement']='-type str'
                         cmd_list = self.hsrp_config_dict[node]['interfaces'][intf]['hsrp'][hsrp_no]
                         parse = parserutils_lib.argsToCommandOptions( cmd_list, arggrammar, self.log )
                         self.hdl_dict[node].configure('interface ' + intf + '\n' + 'hsrp ' + str(hsrp_no))
                         config_str = 'interface ' + intf + '\n'
                         config_str = config_str + 'hsrp ' + str(hsrp_no) + '\n'
                         if parse.ipv4_addr:
                             config_str = config_str + 'ip ' + parse.ipv4_addr + '\n'
                         if parse.priority:
                             config_str = config_str + 'priority ' + parse.priority + '\n'
                         if parse.preempt:
                             config_str = config_str + 'preempt' + '\n'
                         if parse.track_obj:
                             if parse.track_decrement is None:
                                track_decrement = 5
                             else:
                                track_decrement = parse.track_decrement
                             config_str = config_str + 'track ' + str(parse.track_obj) + ' decrement ' + str(track_decrement) + '\n'
                         output_buff = self.hdl_dict[node].configure(config_str)



def configUnconfigInterface(node,switch_hdl_dict,int,ip,prefix,action,log):

          hdl=switch_hdl_dict[node]
          if action == 'unconfig':
               cmd='''int {0}
                      no ip address
                   '''.format(int)
          elif action == 'config':
               cmd =''' int {0}
                        ip address {1}/{2}
                    '''.format(int,ip,prefix)
          hdl.configure(cmd)

