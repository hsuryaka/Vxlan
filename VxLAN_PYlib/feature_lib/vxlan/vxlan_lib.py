
import os
import sys
import yaml
import re
#import netaddr
from common_lib import utils
from common_lib.utils import *
from common_lib import bringup_lib
from common_lib import parserutils_lib
from common_lib import verify_lib
import time
import socket
import ipaddr
import netaddr
from common_lib import interface_lib
from feature_lib.l3 import ospfv2_lib
import json 

from ats.log.utils import banner

class configVxlan():
    def __init__(self,vxlan_dict,key,vni_learning_mode,switch_hdl_dict,log):
        self.log=log
        self.result='pass'
        self.vxlan_config_dict=vxlan_dict
        self.switch_hdl_dict=switch_hdl_dict
        self.key=key
        self.vni_learning_mode=vni_learning_mode
        try:
           self.list_of_nodes=self.vxlan_config_dict.keys()
        except KeyError:
           err_msg='Error !!! vxlan_config_dict has not been defined properly, does not have nodes   \
              as the top level keys'
           testResult( 'fail', err_msg, self.log )
  
    def AllNodes(self):
        for node in self.list_of_nodes:
           self.Nodes(node)

    def Nodes(self,node):
        self.log.info(node)
        hdl=self.switch_hdl_dict[node]
        key=self.key
        self.log.info(self.vni_learning_mode)
        key_list=["global_config","mcast_replication","ingress_replication_static","ingress_replication_bgp","routing","snooping","budNode","vxlan_member_vni"]
        retVal=1
        if key not in key_list:
            self.log.error('{0} not a valid key under vxlan_config_dict. Valid keys\
            are global_config, mcast_replication, ingress_replication_static,ingress_replication_bgp, routing, snooping and budNode'.format(key))
            return 0 
        if key == "global_config":
            self.log.info("Now configuring vxlan global configs")
            bringup_lib.configFeature( hdl, self.log, '-feature {0} -listFlag False'.format('nv overlay') )
            bringup_lib.configFeature( hdl, self.log, '-feature vn-segment-vlan-based' )
            if re.match('cp',self.vni_learning_mode,re.I):
                retVal=configVxlanGlobal(self.vxlan_config_dict[node],hdl,self.log,'-host_reachability_protocol bgp')
            else:
                retVal=configVxlanGlobal(self.vxlan_config_dict[node],hdl,self.log)
        elif key == "vxlan_member_vni":
            self.log.info("Now configuring vxlan member VNIs")
            if re.match('cp',self.vni_learning_mode,re.I):
                retVal=configVxlanMemberVni(self.vxlan_config_dict[node],hdl,self.log,'-mode cp')
            else:
                retVal=configVxlanMemberVni(self.vxlan_config_dict[node],hdl,self.log)
        elif key == "mcast_replication":
            self.log.info("Now configuring mcast-replication VNIs")
            if re.match('cp',self.vni_learning_mode,re.I):
                retVal=configVxlanMcast(self.vxlan_config_dict[node],hdl,self.log,'-mode cp')
            else:
                retVal=configVxlanMcast(self.vxlan_config_dict[node],hdl,self.log)
        elif key == "ingress_replication_static" and re.match('dp',self.vni_learning_mode,re.I):
            self.log.info("Now configuring ingress_replication_static VNIs")
            retVal=configVxlanFloodandLearn(self.vxlan_config_dict[node],hdl,self.log)
        elif key == "ingress_replication_bgp" and re.match('cp',self.vni_learning_mode,re.I):
            self.log.info("Now configuring ingress_replication_bgp VNIs")
            retVal=configVxlanIRbgp(self.vxlan_config_dict[node],hdl,self.log)
        elif key == "routing" and re.match('cp',self.vni_learning_mode,re.I):
            self.log.info("Now configuring routing VNIs")
            retVal=configVxlanRouting(self.vxlan_config_dict[node],hdl,self.log)
        elif key == "snooping":
            retVal=configVxlanSnooping(self.vxlan_config_dict[node],hdl,self.log)
        elif key == "budNode":
            retVal=configVxlanBudnode(self.vxlan_config_dict[node],hdl,self.log)
        if not retVal:
            self.log.error('Vxlan {0} configuration failed on {1}.'.format(key,node))
            return 0
        else:
            return 1 

def parseVxlanGlobalconfigs( log, vxlan_global_args ):
    arggrammar={}
    arggrammar['source_interface']='-type str -required true'
    arggrammar['arp_ether']='-type int -default 0'
    arggrammar['global_ir']='-type bool -default False'
    arggrammar['global_mcast_l2']='-type str'
    arggrammar['global_mcast_l3']='-type str'
    ns=parserutils_lib.argsToCommandOptions( vxlan_global_args, arggrammar, log )
    return ns

def configVxlanGlobal(vxlan_config_dict,hdl,log,*args):
    '''Configure global paramters for vxlan like source-interface on node'''
    ns=parseVxlanGlobalconfigs( log, vxlan_config_dict )
    kdict={}
    kdict['verifySuccess']=True
    if ns.arp_ether:
            cfg='hardware access-list tcam region arp-ether {0} double-wide'.format(ns.arp_ether)
            hdl.configure(cfg, timeout=600)
    cfg='no interface nve1'
    hdl.configure(cfg, timeout=600)
    cfg='''
           interface nve1
             source-interface {0}
             no shutdown
        '''.format(ns.source_interface)

    arggrammar={}
    arggrammar['host_reachability_protocol']='-type str'
    arggrammar['mac_addr']='-type str -default 0000.2222.3333'
    hrp=parserutils_lib.argsToCommandOptions( args, arggrammar, log )
    if hasattr (hrp, 'host_reachability_protocol') and hrp.host_reachability_protocol:
        cfg=cfg+'host-reachability protocol {0}\n'.format(hrp.host_reachability_protocol)
    if ns.global_ir:
        cfg+='global ingress-replication protocol bgp\n' 
    if ns.global_mcast_l2:
        cfg+='global mcast-group {0} l2\n'.format(ns.global_mcast_l2) 
    if ns.global_mcast_l3:
        cfg+='global mcast-group {0} l3\n'.format(ns.global_mcast_l3) 
    if hasattr (hrp, 'host_reachability_protocol') and hrp.host_reachability_protocol:
        cfg=cfg+'fabric forwarding anycast-gateway-mac {0}\n'.format(hrp.mac_addr)
    hdl.configure(cfg, timeout=600)
    return 1

def parseVxlanMemberVni( log, vxlan_mcast_args ):
    arggrammar={}
    #arggrammar['group']='-type str'
    arggrammar['vlan']='-type str'
    ns=parserutils_lib.argsToCommandOptions( vxlan_mcast_args, arggrammar, log )
    return ns

def parseVxlanMcastconfigs( log, vxlan_mcast_args ):
    arggrammar={}
    arggrammar['group']='-type str'
    arggrammar['vlan']='-type str'
    ns=parserutils_lib.argsToCommandOptions( vxlan_mcast_args, arggrammar, log )
    return ns

def configVxlanMemberVni(vxlan_config_dict,hdl,log,*args):
    '''Configure Member Vni for vxlan'''
    kdict={}
    kdict['verifySuccess']=True
    arggrammar={}
    arggrammar['mode']='-type str -default dp'
    ms=parserutils_lib.argsToCommandOptions( args, arggrammar, log )
    if 'vni' in vxlan_config_dict:
        for vn in vxlan_config_dict['vni']:
           ns=parseVxlanMemberVni( log, vxlan_config_dict['vni'][vn] )
           cfg='''vlan {1}
                    vn-segment {0}
                  exit
                  interface nve1
                    member vni {0}
               '''.format(vn,ns.vlan)
           if ms.mode == "cp":
               cfg+='''interface Vlan{0}
                         fabric forwarding mode anycast-gateway
                    '''.format(ns.vlan)
           hdl.configure(cfg, timeout=600)
           return 1
    else:
        log.error('vni key not found under member-vni')      
        return 0
        
def configVxlanMcast(vxlan_config_dict,hdl,log,*args):
    '''Configure mcast replication paramters for vxlan'''
    kdict={}
    kdict['verifySuccess']=True
    arggrammar={}
    arggrammar['mode']='-type str -default dp'
    ms=parserutils_lib.argsToCommandOptions( args, arggrammar, log )
    if 'vni' in vxlan_config_dict:
        for vn in vxlan_config_dict['vni']:
           ns=parseVxlanMcastconfigs( log, vxlan_config_dict['vni'][vn] )
           cfg='''vlan {2}
                    vn-segment {0}
                  exit
                  interface nve1
                    member vni {0}
                      mcast-group {1}
               '''.format(vn,ns.group,ns.vlan)
           if ms.mode == "cp":
               cfg+='''interface Vlan{0}
                         fabric forwarding mode anycast-gateway
                    '''.format(ns.vlan)
           hdl.configure(cfg, timeout=600)
           return 1
    else:
        log.error('vni key not found under mcast-replication')      
        return 0
        

def parseVxlanFloodandLearnconfigs( log, vxlan_fl_args ):
    arggrammar={}
    arggrammar['peer_ip']='-type str'
    arggrammar['vlan']='-type str'
    ns=parserutils_lib.argsToCommandOptions( vxlan_fl_args, arggrammar, log )
    return ns

def configVxlanFloodandLearn(vxlan_config_dict,hdl,log):     
    '''Configure flood and learn paramters for vxlan'''
    kdict={}
    kdict['verifySuccess']=True
    if 'vni' in vxlan_config_dict:
        for vn in vxlan_config_dict['vni']:
           ns=parseVxlanFloodandLearnconfigs( log, vxlan_config_dict['vni'][vn] )
           peer_cfg=""
           for peer in strToList(ns.peer_ip):
               peer_cfg+='peer-ip {0}\n'.format(peer)
           cfg='''vlan {2}
                    vn-segment {0}
                  exit
                  interface nve1
                    member vni {0}
                      ingress-replication protocol static
                        {1} 
               '''.format(vn,peer_cfg,ns.vlan)
           hdl.configure(cfg, timeout=600)
           return 1
    else:
        log.error('vni key not found under ingress_replication_static')
        return 0

def parseVxlanIRbgpconfigs( log, vxlan_ir_bgp_args ):
    arggrammar={}
    arggrammar['protocol']='-type str'
    arggrammar['vlan']='-type str'
    ns=parserutils_lib.argsToCommandOptions( vxlan_ir_bgp_args, arggrammar, log )
    return ns

def configVxlanIRbgp(vxlan_config_dict,hdl,log):     
    '''Configure IR BGP paramters for vxlan'''
    kdict={}
    kdict['verifySuccess']=True
    if 'vni' in vxlan_config_dict:
        for vn in vxlan_config_dict['vni']:
           ns=parseVxlanIRbgpconfigs( log, vxlan_config_dict['vni'][vn] )
           cfg='''vlan {1}
                    vn-segment {0}
                  exit
                  interface nve1
                    member vni {0}
                      ingress-replication protocol bgp
               '''.format(vn,ns.vlan)
           cfg+='''interface Vlan{0}
                     fabric forwarding mode anycast-gateway
                '''.format(ns.vlan)
           hdl.configure(cfg, timeout=600)
        return 1
    else:
        log.error('vni key not found under ingress_replication_bgp')
        return 0

def parseVxlanRoutingconfigs( log, vxlan_routing_args ):
    arggrammar={}
    arggrammar['vrf']='-type str'
    arggrammar['vlan']='-type str'
    ns=parserutils_lib.argsToCommandOptions( vxlan_routing_args, arggrammar, log )
    return ns

def configVxlanRouting(vxlan_config_dict,hdl,log):     
    '''Configure routing paramters for vxlan'''
    kdict={}
    kdict['verifySuccess']=True
    if 'vni' in vxlan_config_dict:
        for vn in vxlan_config_dict['vni']:
           ns=parseVxlanRoutingconfigs( log, vxlan_config_dict['vni'][vn] )
           cfg='''vlan {1}
                    vn-segment {0}
                  exit
                  interface nve1
                    member vni {0} associate-vrf
               '''.format(vn,ns.vlan)
           hdl.configure(cfg, timeout=600)
        return 1
    else:
        log.error('vni key not found under routing')
        return 0

def parseVxlanSnoopingconfigs( log, vxlan_snooping_args ):
    arggrammar={}
    arggrammar['mcast_group']='-type str'
    arggrammar['vlan']='-type str'
    ns=parserutils_lib.argsToCommandOptions( vxlan_snooping_args, arggrammar, log )
    return ns

def configVxlanSnooping(vxlan_config_dict,switch_hdl,log):     
    '''Configure igmp snooping paramters for vxlan'''
    ns=parseVxlanSnoopingconfigs( log, vxlan_config_dict )
    return 1

def parseVxlanBudnodeconfigs( log, vxlan_budnode_args ):
    arggrammar={}
    arggrammar['mcast_group']='-type str'
    arggrammar['vlan']='-type str'
    ns=parserutils_lib.argsToCommandOptions( vxlan_budnode_args, arggrammar, log )
    return ns

def configVxlanBudnode(vxlan_config_dict,switch_hdl,log):     
    '''Configure bud node paramters for vxlan'''
    ns=parseVxlanBudnodeconfigs( log, vxlan_config_dict )
    return 1

class configVxlanScale():
    def __init__(self,vxlan_dict,switch_hdl_dict,log):
        self.log=log
        self.result='pass'
        self.vxlan_config_dict=vxlan_dict
        self.switch_hdl_dict=switch_hdl_dict
        try:
           self.list_of_nodes=self.vxlan_config_dict.keys()
        except KeyError:
           err_msg='Error !!! vxlan_config_dict has not been defined properly, does not have nodes   \
              as the top level keys'
           testResult( 'fail', err_msg, self.log )
  
    def AllNodes(self):
        for node in self.list_of_nodes:
           self.Nodes(node)

    def Nodes(self,node):
        self.log.info(node)
        hdl=self.switch_hdl_dict[node]
        failVal=0
        retVal=[]
        if 'msite' in self.vxlan_config_dict[node]:
                ms_global=parseVxlanMsiteGlobal(self.log, self.vxlan_config_dict[node]['msite']['global'])
                self.log.info('Configuring the Multisite')
                retVal.append(configVxlanMsite(self.vxlan_config_dict[node]['msite'],hdl,self.log))
        if 'evpn' in self.vxlan_config_dict[node]:
            if 'global' in self.vxlan_config_dict[node]['evpn']:
                self.log.info("Now configuring vxlan global configs")
                bringup_lib.configFeature( hdl, self.log, '-feature {0} -listFlag False'.format('nv overlay') )
                bringup_lib.configFeature( hdl, self.log, '-feature vn-segment-vlan-based')
                ns_global=parseVxlanGlobalConfig(self.log, self.vxlan_config_dict[node]['evpn']['global'])
                hdl.configure(f'fabric forwarding anycast-gateway-mac {ns_global.anycast_mac}', timeout=600)
                if ns_global.igmp_snooping:
                    hdl.configure('ip igmp snooping vxlan', timeout=600)
                if ns_global.pim_prebuild_spt:
                    hdl.configure('ip pim pre-build-spt', timeout=600)
                if ns_global.pim_evpn_bl:
                    hdl.configure('ip pim evpn-border-leaf', timeout=600)
            if 'l2_vlan_vni_mapping' in self.vxlan_config_dict[node]['evpn']:
                   self.log.info("Now configuring vxlan l2 VNI mapping")
                   retVal.append(configVxlanVniMapping(self.vxlan_config_dict[node]['evpn']['l2_vlan_vni_mapping'],hdl,self.log))
            if 'l3_vlan_vni_mapping' in self.vxlan_config_dict[node]['evpn']:
                   self.log.info("Now configuring vxlan l3 VNI mapping")
                   retVal.append(configVxlanVniMapping(self.vxlan_config_dict[node]['evpn']['l3_vlan_vni_mapping'],hdl,self.log))
            if 'evpn_config' in self.vxlan_config_dict[node]['evpn']:
                   self.log.info("Now configuring vxlan EVPN config")
                   retVal.append(configVxlanEVPNConf(self.vxlan_config_dict[node]['evpn']['evpn_config'],hdl,self.log))
            if 'vrf' in self.vxlan_config_dict[node]['evpn']:
                   self.log.info("Now configuring vxlan EVPN overlay VRF")
                   retVal.append(configVxlanOverlayVrf(self.vxlan_config_dict[node]['evpn']['vrf'],hdl,self.log))
            if 'l2_vni_svi' in self.vxlan_config_dict[node]['evpn']:
                   self.log.info("Now configuring vxlan L2 vni anycast gateway SVI")
                   retVal.append(configVxlanL2AnyCastGateway(self.vxlan_config_dict[node]['evpn']['l2_vni_svi'],hdl,self.log))
            if 'l3_vni_svi' in self.vxlan_config_dict[node]['evpn']:
                   self.log.info("Now configuring vxlan L3 vni anycast gateway SVI")
                   retVal.append(configVxlanL3AnyCastGateway(self.vxlan_config_dict[node]['evpn']['l3_vni_svi'],hdl,self.log))
        if 'nve1' in self.vxlan_config_dict[node]:
             self.log.info("Now configuring NVE interface")
             retVal.append(configVxlanIntNve(self.vxlan_config_dict[node]['nve1'],hdl,self.log))
        if 'dhcp' in self.vxlan_config_dict[node]:
             self.log.info("Now configuring DHCP")
             retVal.append(configVxlanDhcpEvpn(self.vxlan_config_dict[node]['dhcp'],hdl,self.log))
        if failVal in retVal:
            self.log.error('Vxlan configuration failed on {0}.'.format(node))
            return 0
        else:
            return 1 

def parseVxlanMsiteGlobal(log, vxlan_msite_global):
    arggrammar={}
    arggrammar['msite_id']='-type int'
    arggrammar['delay_restore']='-type int'
    ns=parserutils_lib.argsToCommandOptions(vxlan_msite_global , arggrammar, log )
    return ns



def parseVxlanGlobalConfig( log, vxlan_dict_global ):
    arggrammar={}
    arggrammar['anycast_mac']='-type str'
    arggrammar['igmp_snooping']='-type bool'
    arggrammar['pim_prebuild_spt']='-type bool'
    arggrammar['pim_evpn_bl']='-type bool'
    ns=parserutils_lib.argsToCommandOptions( vxlan_dict_global, arggrammar, log )
    return ns

def parseVxlanVniMapping( log, vxlan_dict_vni ):
    arggrammar={}
    arggrammar['start_vlan_id']='-type int'
    arggrammar['start_vni_id']='-type int'
    arggrammar['incr_step']='-type int'
    arggrammar['count']='-type int'

    ns=parserutils_lib.argsToCommandOptions( vxlan_dict_vni,arggrammar, log )
    return ns

def parseVxlanEvpnConfig( log, vxlan_dict_evpn):
     arggrammar={}
     arggrammar['start_vni']='-type int'
     arggrammar['incr_step']='-type int'
     arggrammar['count']='-type int'
     arggrammar['rd']='-type str'
     arggrammar['rt']='-type str'
     ns=parserutils_lib.argsToCommandOptions( vxlan_dict_evpn ,arggrammar, log )
     return ns


def parseVxlanOverlayVrfaddress_family(log, vxlan_dict_vrf):
     arggrammar={}
     arggrammar['rt']='-type str'
     arggrammar['mvpn']='-type bool'

     ns=parserutils_lib.argsToCommandOptions( vxlan_dict_vrf, arggrammar, log )
     return ns


def parseVxlanl2SviAnyCastGateway(log, vxlan_dict_l2Svi):
     arggrammar={}
     #arggrammar['ip']= '-type bool -default True'
     #arggrammar['ipv6']= '-type bool -default False'
     #arggrammar['ipv4']= '-type bool -default True'
     arggrammar['l2vni_start']='-type int'
     arggrammar['count']='-type int'
     arggrammar['ipv4_start']='-type str'
     arggrammar['ip_step']='-type str'
     arggrammar['ipv4_prf_len']='-type int'
     arggrammar['pim']='-type bool'
     arggrammar['pim6']='-type bool'
     arggrammar['ipv6_start']='-type str'
     arggrammar['ipv6_step']='-type str'
     arggrammar['ipv6_prf_len']='-type int'

     ns=parserutils_lib.argsToCommandOptions( vxlan_dict_l2Svi, arggrammar, log )
     return ns

def parseVxlanl3SviAnyCastGateway(log, vxlan_dict_l3Svi):
     arggrammar={}
     arggrammar['l3vni_start']='-type int'
     arggrammar['count']='-type int'
     arggrammar['ipv4']='-type bool -default True'
     arggrammar['ipv6']='-type bool'
     arggrammar['pim']='-type bool'
     arggrammar['pim6']='-type bool'

     ns=parserutils_lib.argsToCommandOptions( vxlan_dict_l3Svi, arggrammar, log )
     return ns

def parseVxlanNveGlobal(log,vxlan_nveGlobal_dict):
     arggrammar={}
     arggrammar['source_int']='-type str'
     arggrammar['host_reachablity']='-type str'
     arggrammar['adv_vmac']='-type bool'
     arggrammar['evpn_ir']='-type bool'
     arggrammar['mcast_group']='-type str'
     arggrammar['supress_arp']='-type bool'
     arggrammar['msite_int']='-type str'
     ns=parserutils_lib.argsToCommandOptions(vxlan_nveGlobal_dict, arggrammar, log )
     return ns

def parseVxlanNveL2Vni(log,vxlan_nveL2vni_dict):
      arggrammar={}
      arggrammar['l2vni_start']='-type int'
      arggrammar['count']='-type int'
      arggrammar['ir_proto']='-type str'
      arggrammar['mcast_group']='-type str'
      arggrammar['msite_replication']='-type bool' 
      ns=parserutils_lib.argsToCommandOptions(vxlan_nveL2vni_dict, arggrammar, log)
      return ns

def parseVxlanNveL3Vni(log,vxlan_nveL3vni_dict):
      arggrammar={}
      arggrammar['l3vni_start']='-type int'
      arggrammar['count']='-type int'
      arggrammar['trm_mcast_start']='-type str'
      arggrammar['ip_step']='-type str'
      arggrammar['msite_trm']='-type bool'
      ns=parserutils_lib.argsToCommandOptions(vxlan_nveL3vni_dict, arggrammar, log)
      return ns 
      

def parseVxlanDhcp(log,vxlan_dhcp_dict):
      arggrammar={}
      arggrammar['dhcp_server']='-type str'
      arggrammar['src_int']='-type str'
  
      ns=parserutils_lib.argsToCommandOptions(vxlan_nveL3vni_dict, arggrammar, log)
      return ns 
 
def configVxlanDhcpEvpn(vxlan_dhcp_dict,hdl,log):

       log.info(banner(f'Config VXLAN DHCP on {hdl}'))
       ns=parseVxlanDhcp(log,vxlan_dhcp_dict)
       cfg=''
       cfg+='''feature dhcp 
               ip dhcp relay
               ip dhcp relay information option
               ip dhcp relay information option vpn
               ipv6 dhcp relay
             '''
       for vlan in vxlan_dhcp_dict:
            cfg+='''int {0}
                    ip dhcp relay address {1}
                    ip dhcp relay source-interface {2}
                 '''.format(vlan,ns.dhcp_server,ns.src_int)
       out=hdl.configure(cfg,timeout=900)
       if re.search('error|invalid',out,re.I):
          log.error(f'Configuring DHCP failed on {hdl}')
          return 0
       return 1


def configVxlanMsite(vxlan_msite_dict,hdl,log):

      log.info(banner(f'Config VXLAN Msite on {hdl}'))
      ns=parseVxlanMsiteGlobal(log,vxlan_msite_dict['global'])
      cfg=''
      cfg+='''evpn multisite border-gateway {0}
              delay-restore time {1}
           '''.format(ns.msite_id,ns.delay_restore)
      log.info('Enabling the DCI-Links')
      for int in vxlan_msite_dict['dci_int'].split(' '):
             cfg+='''interface {0}
                     evpn multisite dci-tracking
                  '''.format(int)
      log.info('Enabling the Fabric-Links')
      for int in vxlan_msite_dict['fabric_int'].split(' '):
            cfg+='''interface {0}
                    evpn multisite fabric-tracking
                 '''.format(int)
      out=hdl.configure(cfg,timeout=900)
      if re.search('error|invalid',out,re.I):
          log.error(f'Configuring Multisite config failed on {hdl}')
          return 0
      return 1

#def addRemoveFabricTracking(vxlan_msite_dict,hdl,log):

#     log.info(banner(f'Adding and removing Fabric tracking')
     

def configVxlanVniMapping(vxlan_vni_dict,hdl,log):

       log.info(banner(f'Config VXLAN VNI Mapping on {hdl}'))
       ns=parseVxlanVniMapping(log,vxlan_vni_dict)
       cfg=''
       for vlan in range(ns.start_vlan_id,ns.count+ns.start_vlan_id):
           cfg+='''vlan {0}
                   vn-segment {1}
                '''.format(vlan,ns.start_vni_id)
           ns.start_vni_id+=ns.incr_step
       cfg+='''exit
            '''
       out=hdl.configure(cfg,timeout=900)
       if re.search('error|invalid',out,re.I):
            log.error(f'Configuring Vxlan VNI mapping failed on {hdl}')
            return 0
       return 1
              
def configVxlanEVPNConf(vxlan_evpn_dict,hdl,log):

         log.info(banner(f'Config VXLAN EVPN on {hdl}'))
         ns=parseVxlanEvpnConfig(log,vxlan_evpn_dict)
         cfg=''
         cfg+='''evpn
              '''
         for vni in range(ns.start_vni,ns.count+ns.start_vni):
              cfg+='''vni {0} l2
                      rd {1}
                      route-target both {2}
                   '''.format(vni,ns.rd,ns.rt)
         out=hdl.configure(cfg,timeout=900)
         if re.search('error|invalid',out,re.I):
              log.error(f'Configuring Vxlan EVPN failed on {hdl}')
              return 0
         return 1

def configVxlanOverlayVrf(vxlan_vrf_dict,hdl,log):

    log.info(banner(f'Configuring VXLAN VRF on {hdl}'))
    cfg=''
    for vrf in vxlan_vrf_dict:
        cfg+='''vrf context {0}
                vni {1}
                rd {2}
               '''.format(vrf,vxlan_vrf_dict[vrf]['vni'],vxlan_vrf_dict[vrf]['rd'])
        for family in vxlan_vrf_dict[vrf]['address_family']:
             ns=parseVxlanOverlayVrfaddress_family(log, vxlan_vrf_dict[vrf]['address_family'][family])
             cfg+='''address-family {0} unicast
                     route-target both {1}
                     route-target both {1} evpn
                  '''.format(family,ns.rt)
             if ns.mvpn:
               cfg+='''route-target both {0} mvpn
                    '''.format(ns.rt)

    out=hdl.configure(cfg,timeout=900)
    if re.search('error|invalid',out,re.I):
         log.error(f'Configuring Vxlan VRF failed on {hdl}')
         return 0
    return 1

def configVxlanL2AnyCastGateway(vxlan_l2svi_dict,hdl,log):

    log.info(banner(f'Configuring VXLAN L2 vni SVI AnyCastGateway on {hdl}'))
    cfg=''
    for vrf in vxlan_l2svi_dict:
         ns=parseVxlanl2SviAnyCastGateway(log,vxlan_l2svi_dict[vrf])
         print('###############')
         print(type(ns))
         print('###############')
         if ns.ipv4_start:
           ipadd_list=utils.getIPv4AddressesList(ns.ipv4_start,ns.ip_step,ns.count)
           ipaddr=0
         if ns.ipv6_start:
           ipv6add_list=utils.getIPv6AddressesList(ns.ipv6_start,ns.ipv6_step,ns.count)
           ipv6addr=0

         for vlan in range(ns.l2vni_start,ns.count+ns.l2vni_start):
                cfg+='''int vlan {0}
                        no shut
                        mtu 9100
                        vrf member {1}
                        fabric forwarding mode anycast-gateway
                      '''.format(vlan,vrf)
                if ns.ipv4_start:
                    cfg+='''ip address {0}/{1}
                            no ip redirects
                         '''.format(ipadd_list[ipaddr],ns.ipv4_prf_len)
                    ipaddr+=1
                if ns.ipv6_start:
                     cfg+='''ipv6 address {0}/{1}
                             no ipv6 redirects
                          '''.format(ipv6add_list[ipv6addr],ns.ipv6_prf_len)
                     ipv6addr+=1
                if ns.pim:
                  cfg+='''ip pim sparse-mode
                       '''
                if ns.pim6:
                  cfg+='''ipv6 pim sparse-mode
                       '''
    out=hdl.configure(cfg,timeout=900)
    if re.search('error|invalid',out,re.I):
           log.error(f'Configuring Vxlan L2 VNI SVI failed on {hdl}')
           return 0
    return 1

def configVxlanL3AnyCastGateway(vxlan_l3svi_dict,hdl,log):

    log.info(banner(f'Configuring VXLAN L3 vni SVI on {hdl}'))
    cfg=''
    for vrf in vxlan_l3svi_dict:
           ns=parseVxlanl3SviAnyCastGateway(log,vxlan_l3svi_dict[vrf])
           for vlan in range(ns.l3vni_start,ns.count+ns.l3vni_start):
                 cfg+='''int vlan {0}
                         no shut
                         mtu 9100
                         vrf member {1}
                      '''.format(vlan,vrf)
                 if ns.ipv4:
                     cfg+='''no ip redirects
                             ip forward
                          '''
                 if ns.ipv6:
                     cfg+='''no ipv6 redirects
                             ipv6 forward
                          '''
                 if ns.pim:
                     cfg+='''ip pim sparse-mode
                          '''
                 if ns.pim6:
                    cfg+='''ipv6 pim sparse-mode
                       '''
 
    out=hdl.configure(cfg,timeout=900)
    if re.search('error|invalid',out,re.I):
           log.error(f'Configuring Vxlan L3 VNI SVI failed on {hdl}')
           return 0
    return 1

def configVxlanIntNve(vxlan_nve_dict,hdl,log):

      log.info(banner(f'Configuring VXLAN NVE interface on {hdl}'))
      cfg=''
      ng=parseVxlanNveGlobal(log,vxlan_nve_dict['global'])
      cfg+='''int nve 1
             source-interface {0}
             no shut
            '''.format(ng.source_int)
      if ng.host_reachablity:
          cfg+='''host-reachability protocol {0}
               '''.format(ng.host_reachablity)
      if ng.adv_vmac:
          cfg+='''advertise virtual-rmac
               '''
      if ng.evpn_ir:
          cfg+='''global ingress-replication protocol bgp
                '''
      if ng.mcast_group:
          cfg+='''global mcast-group {0}
               '''.format(ng.mcast_group)
      if ng.supress_arp:
          cfg+='''global suppress-arp
               '''
      if ng.msite_int:
          cfg+='''multisite border-gateway interface {0}
               '''.format(ng.msite_int)
      for group in vxlan_nve_dict['l2_vni']:
            vni_list=[]
            na=parseVxlanNveL2Vni(log,vxlan_nve_dict['l2_vni'][group])
            for vni in range(na.l2vni_start,na.count+na.l2vni_start):
                  vni_list.append(vni)
            cfg+='''member vni {0}-{1}
                 '''.format(vni_list[0],vni_list[-1])
            if na.ir_proto:
                 cfg+='''ingress-replication protocol {0}
                      '''.format(na.ir_proto)
            if na.mcast_group:
                 cfg+='''mcast-group {0}
                      '''.format(na.mcast_group)
            if na.msite_replication:
                 cfg+='''multisite ingress-replication
                      '''
      if 'l3_vnis' in vxlan_nve_dict:
       for group in vxlan_nve_dict['l3_vnis']:
         nb=parseVxlanNveL3Vni(log,vxlan_nve_dict['l3_vnis'][group])
         if nb.trm_mcast_start:
          ipadd_list=utils.getIPv4AddressesList(nb.trm_mcast_start,nb.ip_step,nb.count)
          ipaddr=0
          for vni in range(nb.l3vni_start,nb.count+nb.l3vni_start):
             cfg+='''member vni {0} associate-vrf
                     mcast-group {1}
                  '''.format(vni,ipadd_list[ipaddr])
             ipaddr+=1
             if nb.msite_trm:
                cfg+='''multisite ingress-replication optimized
                     '''
         else:
          for vni in range(nb.l3vni_start,nb.count+nb.l3vni_start):
              cfg+='''member vni {0} associate-vrf
                   '''.format(vni)
      else:
         nb=parseVxlanNveL3Vni(log,vxlan_nve_dict['l3_vni'])
         if nb.trm_mcast_start:
          ipadd_list=utils.getIPv4AddressesList(nb.trm_mcast_start,nb.ip_step,nb.count)
          ipaddr=0
          for vni in range(nb.l3vni_start,nb.count+nb.l3vni_start):
             cfg+='''member vni {0} associate-vrf
                     mcast-group {1}
                  '''.format(vni,ipadd_list[ipaddr])
             ipaddr+=1
             if nb.msite_trm:
                cfg+='''multisite ingress-replication optimized
                     '''
         else:
          for vni in range(nb.l3vni_start,nb.count+nb.l3vni_start):
              cfg+='''member vni {0} associate-vrf
                   '''.format(vni)
 
      out=hdl.configure(cfg,timeout=900)
      if re.search('error|invalid',out,re.I):
             log.error(f'Configuring VXLAN interface nve failed on {hdl}')
             return 0
      return 1                 
 
def getNvevniDict(hdl,log):
    '''Method to get vni info in form of dictionary for DUT. Dictionary 
    would look like ('sw3-gd955-paris', {'2000005': {'status': 'Up', 
    'mcast-group': '239.1.1.5', 'vlan': '5', 'type': 'L2', 'mode': 'CP'}
    , '3000005': {'status': 'Up', 'mcast-group': 'n/a', 'type': 'L3', 
    'mode': 'CP', 'vrf': 'evpn-tenant-3000005'})'''
    vni_dict={}
    vni_dict[hdl.switchName]={} 
    vni_op=hdl.iexec('show nve vni')
    vni_reg="(nve[0-9]+\s+(\d+)(.*)\s+(Up|Down)\s+(CP|DP)\s+(L2|L3)\s+\[(.*)\])"
    vni_match=re.findall(vni_reg,vni_op)
    i=0
    while i < len(vni_match):
        vni_dict[hdl.switchName][vni_match[i][1]]={}
        if re.match('L2',vni_match[i][5].strip(),re.I):
            vni_dict[hdl.switchName][vni_match[i][1]].update({'mcast-group': \
            vni_match[i][2].strip(), 'status': vni_match[i][3].strip(), 'mode':\
            vni_match[i][4].strip(), 'type': vni_match[i][5].strip(), 'vlan':\
            vni_match[i][6].strip()})
        else:
            vni_dict[hdl.switchName][vni_match[i][1]].update({'mcast-group':\
            vni_match[i][2].strip(), 'status': vni_match[i][3].strip(), 'mode':\
            vni_match[i][4].strip(), 'type': vni_match[i][5].strip(), 'vrf':\
            vni_match[i][6].strip()})
        i+=1     

    if not vni_dict[hdl.switchName].keys():
        vni_dict={}    
    return vni_dict

def getNveIRDict(hdl,log):
    '''Method to get ingress-replication peer info in form of dictionary
    for DUT. Dictionary looks like {'sw3-gd955-paris': {'2000005': \
    {1: {'source': 'CLI', 'uptime': '00:35:25', 'peer_ip': '40.1.1.1'},\
    2: {'source': 'CLI', 'uptime': '00:35:25', 'peer_ip': '50.1.1.1'}}}}'''

    ingress_peer_dict={}
    ingress_peer_dict[hdl.switchName]={} 
    peer_pat="\n\s+(\d+.\d+.\d+.\d+)\s+(CLI|IMET)\s+(\d\d:\d\d:\d\d)"
    time_pat="\d\d:\d\d:\d\d"
    ipv4_pat="\d+.\d+.\d+.\d+"
    ingress_peer_pat=\
    "(nve[0-9]+\s+(\d+)\s+({0})\s+(CLI|IMET)\s+({1})[{2}]+)".format(ipv4_pat,time_pat,peer_pat)
    ingress_peer_op=hdl.iexec('show nve vni ingress-replication')
    ingress_peer_match=re.findall(ingress_peer_pat,ingress_peer_op)
    while i < len(ingress_peer_match):
        for var in ingress_peer_match[i][0].split("\n"):
            cnt=1
            if var:
                var_list=strToList(var)
                if 'nve1' in var_list:
                    vni=var_list[1] 
                    ingress_peer_dict[hdl.switchName][vni]={}
                    ingress_peer_dict[hdl.switchName][vni][cnt]={}     
                    ingress_peer_dict[hdl.switchName][vni][cnt].update({'peer_ip': var_list[2],'source': var_list[3],'uptime':var_list[4]})
                else:
                    cnt+=1
                    ingress_peer_dict[hdl.switchName][vni][cnt]={} 
                    ingress_peer_dict[hdl.switchName][vni][cnt].update({'peer_ip': var_list[0],'source': var_list[1],'uptime':var_list[2]})
            else:
                continue
        i+=1
    if not ingress_peer_dict[hdl.switchName].keys():
        ingress_peer_dict={}
    return ingress_peer_dict

def getNvepeerDict(hdl,log,*args):
    '''Method to get nve peer info in form of dictionary for DUT. 
    Dictionary looks like {'sw2-gd955-9372PX': {'30.1.1.1': 
    {'status': 'Up', 'uptime': '00:58:34', 'learnType': 'CP', 'mac_address':
    'n/a'}, '50.1.1.1': {'status': 'Up', 'uptime': '01:09:41', 'learnType':
    'CP', 'mac_address': '003a.7d4e.3ee7'}}}'''
    arggrammar={}
    arggrammar['node']='-type str'
    ns=parserutils_lib.argsToCommandOptions( args, arggrammar, log )
    mac_pat="[a-f0-9]{4}\.[a-f0-9]{4}\.[a-f0-9]{4}"
    pat2='n/a' 
    peer_reg="(nve[0-9]+\s+(\d+.\d+.\d+.\d+)\s+(Up|Down)\s+(CP|DP)\s+([0-9\:dh]+)\s+({0}|{1}))".format(mac_pat,pat2)
    peer_op=hdl.execute('show nve peers')
    peer_match=re.findall(peer_reg,peer_op)
    peer_dict={}
    if ns.node:
            key=ns.node
    else:
            key=hdl.switchName

    peer_dict[key]={}
    i=0
    while i < len(peer_match):
        peer_dict[key][peer_match[i][1]]={}
        peer_dict[key][peer_match[i][1]].update({'status':\
        peer_match[i][2],'learnType': peer_match[i][3], 'uptime':\
        peer_match[i][4], 'mac_address': peer_match[i][5]})
        i+=1
    if not peer_dict[key].keys():
        peer_dict={}
    return peer_dict

def getNveintfDict(hdl,log,*args):
    '''Method to get nve interface info in form of dictionary for DUT.
    Dictionary looks like {'sw3-gd955-paris': {'nve1': {'router_mac':
    '003a.7d4e.2da7', 'src_intf': 'loopback0', 'primary': '30.1.1.2',
    'state': 'Up', 'vpc_capability': 'notified', 'host_learning_mode':
    'Control-Plane', 'encap': 'VXLAN', 'secondary': '30.1.1.1'}}}'''

    arggrammar={}
    arggrammar['intf']='-type str -default nve1'
    ns=parserutils_lib.argsToCommandOptions( args, arggrammar, log )
    pat1='Interface:\s+{0},\s+State:\s+(Up|Down),\s+encapsulation:\s+(.*)'.format(ns.intf)
    pat2='VPC Capability:\s+VPC-VIP-Only\s+\[(.*)\]'
    pat3='Local Router MAC:\s+([a-e0-9]+.[a-e0-9]+.[a-e0-9]+)'
    pat4='Host Learning Mode:\s+(.*)'
    pat5='Source-Interface:\s+(.*)\s+\(primary:\s+(.*),\s+secondary:\s+(.*)\)'
    
    intf_op=hdl.iexec('show nve interface {0}'.format(ns.intf))
    pat1_match=re.findall(pat1,op)
    pat2_match=re.findall(pat2,op)
    pat3_match=re.findall(pat3,op)
    pat4_match=re.findall(pat4,op)
    pat5_match=re.findall(pat5,op)
    
    nve_intf_dict={} 
    nve_intf_dict[hdl.switchName]={} 
    nve_intf_dict[hdl.switchName][ns.intf]={}
    if pat1_match and pat2_match and pat3_match and pat4_match and pat5_match:
        nve_intf_dict[hdl.switchName][ns.intf].update({{'state': \
        pat1_match[0][0], 'encap': pat1_match[0][1], 'vpc_capability': \
        pat2_match[0], 'router_mac': pat3_match[0], 'host_learning_mode': \
        pat4_match[0], 'src_intf': pat5_match[0][0], 'primary': \
        pat5_match[0][1], 'secondary': pat5_match[0][2]}})
    if not nve_intf_dict[hdl.switchName][ns.intf].keys():
        nve_intf_dict={}
    return nve_intf_dict 

def getNvevniCountersDict(hdl,vni,log):
    '''Method to get vni counters dict for DUT. Dictionary looks like:
    {'sw3-gd955-paris': {'2000002': {'RX': {'mcast_pkts': '6349', 
    'unicast_pkts': '0', 'unicast_bytes': '0', 'mcast_bytes': '457096'},
    'TX': {'mcast_pkts': '0', 'unicast_pkts': '0', 'unicast_bytes': '0',
    'mcast_bytes': '0'}}}}'''

    pat1='VNI:\s+(\d+)'
    pat2='TX\s*\n\s+(\d+)\s+unicast\s+packets\s+(\d+)\s+unicast\s+bytes\n\s+(\d+)\s+multicast\s+packets\s+(\d+)\s+multicast\s+bytes'
    pat3='RX\s*\n\s+(\d+)\s+unicast\s+packets\s+(\d+)\s+unicast\s+bytes\n\s+(\d+)\s+multicast\s+packets\s+(\d+)\s+multicast\s+bytes'
    vni_counter_op=hdl.iexec('show nve vni {0} counters'.format(vni))

    pat1_match=re.findall(pat1,vni_counter_op)
    pat2_match=re.findall(pat2,vni_counter_op)
    pat3_match=re.findall(pat3,vni_counter_op)
  
    vni_counters_dict={}
    vni_counters_dict[hdl.switchName]={}
    if pat1_match and pat2_match and pat3_match:
        vni_counters_dict[hdl.switchName][pat1_match[0]]={}
        vni_counters_dict[hdl.switchName][pat1_match[0]].update({'TX': {'unicast_pkts': \
        pat2_match[0][0], 'unicast_bytes': pat2_match[0][1], 'mcast_pkts': \
        pat2_match[0][2], 'mcast_bytes': pat2_match[0][3]}})
        vni_counters_dict[hdl.switchName][pat1_match[0]].update({'RX': {'unicast_pkts': \
        pat3_match[0][0], 'unicast_bytes': pat3_match[0][1], 'mcast_pkts': \
        pat3_match[0][2], 'mcast_bytes': pat3_match[0][3]}})
    
    if not vni_counters_dict[hdl.switchName].keys():
        vni_counters_dict={}
    return vni_counters_dict

def getNvepeerCountersDict(hdl,peer,log,*args):
    '''Method to get peer counters dict for DUT. Dictionary looks like:
    {'sw3-gd955-paris': {'40.1.1.1': {'RX': {'mcast_pkts': '0', 'unicast_pkts':
    '0', 'unicast_bytes': '0', 'mcast_bytes': '0'}, 'TX': {'mcast_pkts': '0',
    'unicast_pkts': '0', 'unicast_bytes': '0', 'mcast_bytes': '0'}}}}'''
    arggrammar={}
    arggrammar['intf']='-type str -default nve1'
    ns=parserutils_lib.argsToCommandOptions( args, arggrammar, log )

    pat1='Peer\s+IP:\s+(\d+.\d+.\d+.\d+)'
    pat2='TX\s*\n\s+(\d+)\s+unicast\s+packets\s+(\d+)\s+unicast\s+bytes\n\s+(\d+)\s+multicast\s+packets\s+(\d+)\s+multicast\s+bytes'
    pat3='RX\s*\n\s+(\d+)\s+unicast\s+packets\s+(\d+)\s+unicast\s+bytes\n\s+(\d+)\s+multicast\s+packets\s+(\d+)\s+multicast\s+bytes'
    peer_counter_op=hdl.iexec('show nve peers {0} interface {1} counters'.format(peer,ns.intf))
    pat1_match=re.findall(pat1,peer_counter_op)
    pat2_match=re.findall(pat2,peer_counter_op)
    pat3_match=re.findall(pat3,peer_counter_op)
  
    peer_counters_dict={}
    peer_counters_dict[hdl.switchName]={}
    if pat1_match and pat2_match and pat3_match:
        peer_counters_dict[hdl.switchName][pat1_match[0]]={}
        peer_counters_dict[hdl.switchName][pat1_match[0]].update({'TX': {'unicast_pkts': \
        pat2_match[0][0], 'unicast_bytes': pat2_match[0][1], 'mcast_pkts': \
        pat2_match[0][2], 'mcast_bytes': pat2_match[0][3]}})
        peer_counters_dict[hdl.switchName][pat1_match[0]].update({'RX': {'unicast_pkts': \
        pat3_match[0][0], 'unicast_bytes': pat3_match[0][1], 'mcast_pkts': \
        pat3_match[0][2], 'mcast_bytes': pat3_match[0][3]}})
    
    if not peer_counters_dict[hdl.switchName].keys():
        peer_counters_dict={}
    return peer_counters_dict


#def resolveHostarp(hlite,ping_profile,version):
#    if version == 'v4':
#        ping_Obj=msdc_common_lib.Ping(hlite,ping_profile)
#    elif version == 'v6':
#        ping_Obj=msdc_common_lib.Ping6(hlite,ping_profile)
#    retVal=ping_Obj.verify()
#    if retVal == 'fail':
#        return 0
#    return 1
def verifyMacAddressTable(hdl,log,mac_vtep_dict=None):
        '''mac_vtep_dict[<mac-address>]={'vlan':<vlan-id>,'type'=<static/dynamic>,'vtep_ip'=<peer_vtep_ip to match for'>}
           This function verifies mac entry learnt against specified peer vtep_ip in the dict.'''

        if mac_vtep_dict:
                out=hdl.iexec('show mac address-table')
                for mac in mac_vtep_dict.keys():
                    result=1
                    log.info('Validating mac_vtep entry in mac address table  for mac {0}'.format(mac))
                    pat='.\s+{0}\s+{1}\s+{2}\s+0\s+F\s+F\s+nve\d+\({3}\)'.format(mac_vtep_dict[mac]['vlan'],\
                                   mac,mac_vtep_dict[mac]['type'],mac_vtep_dict[mac]['vtep_ip'])
                    log.info('searching for pattern{0}'.format(pat))
                    if re.findall(pat,out):
                            log.info('Valid peer VTEP IP {0} entry found for the mac {1}'.format(mac_vtep_dict[mac]['vtep_ip'],mac))
                            result&=1
                    else:
                           log.error('NO Valid peer VTEP IP {0} entry found for the mac {1}'.format(mac_vtep_dict[mac]['vtep_ip'],mac))
                           result&=0
    
        else:
                log.error('Empty mac_vtep_dict')
                return 0
        return result 

def populateVtepVmDict(vtep_vm_dict,host_profile_dict,int_config_dict,log,CS_VLAN_DICT=0):
        VtepVMDict={}
        for node in vtep_vm_dict:
                VtepVMDict[node]={}
                #Populate NVE IP
                #loopback0 configured as source interface for nve
                lo0_args=int_config_dict['loopback'][node]['loopback0']
                arggrammar={}
                arggrammar['ipv4_addr']='-type str '
                arggrammar['secondary_ipv4_addr']='-type str '
                ns=parserutils_lib.argsToCommandOptions( lo0_args, arggrammar, log )
                if ns.secondary_ipv4_addr:
                       nveIP=ns.secondary_ipv4_addr
                else:
                       nveIP=ns.ipv4_addr
                VtepVMDict[node]['NVE_IP']=nveIP
                #Populate VM parameters ip,vlan,mac address to node
                vmlist=strToList(vtep_vm_dict[node])

                for vm in vmlist:
                          for port in host_profile_dict:
                                 if vm in host_profile_dict[port]:
                                        arggrammar={}
                                        arggrammar['srcMac']='-type str '
                                        arggrammar['vlan_id']='-type str '
                                        arggrammar['ipv4']='-type str '
                                        arggrammar['ipv6']='-type str '
                                        ns=parserutils_lib.argsToCommandOptions( host_profile_dict[port][vm], arggrammar, log )
                                        VtepVMDict[node][vm]={}
                                        mac=utils.macFormatConverter(ns.srcMac,'dot')
                                        VtepVMDict[node][vm]['mac']=mac
                                        if ns.vlan_id:
                                                 if CS_VLAN_DICT:
                                                         VtepVMDict[node][vm]['vlan']=CS_VLAN_DICT[int(ns.vlan_id)]
                                                 else:
                                                         VtepVMDict[node][vm]['vlan']=ns.vlan_id
                                        if ns.ipv4:
                                                VtepVMDict[node][vm]['IP']=ns.ipv4
                                        if ns.ipv6:
                                                VtepVMDict[node][vm]['IPv6']=ns.ipv6

        return VtepVMDict

def validateMacLearningsOnPeerVtep(sw_hdl_dict,vtep_vm_dict,nve_peer_dict,log):
     log.info('Validating Macs on peer VTEP ')
     for node in vtep_vm_dict:
        for vm in vtep_vm_dict[node]:
         if vm == 'NVE_IP':
                 continue
         if node in nve_peer_dict:
            for RVIP in nve_peer_dict[node]:
                  for RVTEP in vtep_vm_dict:
                            if vtep_vm_dict[RVTEP]['NVE_IP']==RVIP:
                              log.info('Validating Mac {0} learnt on peer VTEP {1}'.format(vtep_vm_dict[node][vm]['mac'],RVTEP))
                              mac_vtep_dict={vtep_vm_dict[node][vm]['mac']:{'vlan':vtep_vm_dict[node][vm]['vlan'],'type':'dynamic','vtep_ip':vtep_vm_dict[node]['NVE_IP']}}
                              if not verifyMacAddressTable(sw_hdl_dict[RVTEP],log,mac_vtep_dict):
                               utils.testResult('fail','Validation failed for Mac {0} learnt on peer VTEP {1}'.format(vtep_vm_dict[node][vm]['mac'],RVTEP),log) 
                               log.error('Validation failed for Mac {0} learnt on peer VTEP {1}'.format(vtep_vm_dict[node][vm]['mac'],RVTEP))
                               return 0
         else:
                 log.error('Nve Peer Dict Empty for node {0}'.format(node))
                 return 0
     return 1

def pingIxiaHosts(sw_hdl_dict,vtep_vm_dict,log):
    for node in vtep_vm_dict:
           for vm in vtep_vm_dict[node]:
              if vm == 'NVE_IP':
                  continue
              hdl=sw_hdl_dict[node]
              out=hdl.iexec('ping {0} source-interface vlan{1}'.format(vtep_vm_dict[node][vm]['IP'],vtep_vm_dict[node][vm]['vlan']))
              pat='\d+ packets transmitted, \d+ packets received, (\d+).\d+% packet loss'
              if int(re.findall(pat,out)[0]) == 100:
                   log.error('pingIxiaHosts: Ping Failure for IP {0} from node {1}'.format(vtep_vm_dict[node][vm]['IP'],node))
                   return 0
    return 1

def setupConfigVxlan(hdl,dut,log,config_dict):
        ''' method to configure vxlan dict defined for each dut under topology'''
        log.info('Inside setupConfigVxlan')
        switch_hdl_dict={}
        switch_hdl_dict[dut]=hdl
        if 'vni_learning' in config_dict['vxlan_config_dict'].keys():
            log.info('Inside setupConfigVxlan vni_learning')
            arggrammar={}
            arggrammar['mode']='-type str -choices ["CP","DP"]'
            args=config_dict['vxlan_config_dict']['vni_learning']
            ns=parserutils_lib.argsToCommandOptions(args,arggrammar,log)
            vni_learning_mode=ns.mode
        else:
            log.error('vni_learning is a mandatory key in vxlan_config_dict and it is missing')
            return 0

        if 'global_config' in config_dict['vxlan_config_dict'].keys():
            log.info('Inside global_config')
            vxlan_dict=config_dict['vxlan_config_dict']['global_config']
            if dut in vxlan_dict:
                log.info('Now calling configVxlan for global vxlan configs')
                obj_vxlan=configVxlan(vxlan_dict,'global_config',vni_learning_mode,switch_hdl_dict,log)
                if not obj_vxlan.Nodes(dut):
                    return 0
        else:
            log.error('global_config is a mandatory key in vxlan_config_dict and it is missing')
            return 0

        for key in config_dict['vxlan_config_dict'].keys():
            if key == "vni_learning" or key == "global_config":
                continue
            vxlan_dict=config_dict['vxlan_config_dict'][key]
            if dut in vxlan_dict:
                log.info('Now calling configVxlan for {0}'.format(key))
                obj_vxlan=configVxlan(vxlan_dict,key,vni_learning_mode,switch_hdl_dict,log)
                if not obj_vxlan.Nodes(dut):
                    return 0
        return 1

def setupConfigVxlanScale(hdl,dut,log,config_dict):
        ''' method to configure vxlan Scale dict defined for each dut under topology'''
        log.info('Inside setupConfigVxlanScale')
        switch_hdl_dict={}
        switch_hdl_dict[dut]=hdl
        if 'vxlan_dict' in config_dict:
            if dut in config_dict['vxlan_dict']:
                  obj_vxlanScale=configVxlanScale(config_dict['vxlan_dict'],switch_hdl_dict,log)
                  if not obj_vxlanScale.Nodes(dut):
                       return 0
        return 1
 
def parseVxlanVlan( log, vxlan_vlan_dict ):
    arggrammar={}
    arggrammar['vni']='-type str'
    ns=parserutils_lib.argsToCommandOptions( vxlan_vlan_dict, arggrammar, log )
    return ns

def DeleteAddVxlanL2Vni(log,hdl,dut,configDict):

        ns=parseVxlanVniMapping(log,configDict['vxlan_dict'][dut]['evpn']['l2_vlan_vni_mapping'])
        vlan_list=[]
        uncfg =''
        log.info('Deleting all L2 VNI')
        for vlan in range(ns.start_vlan_id,ns.count+ns.start_vlan_id):
              vlan_list.append(vlan)
        uncfg += '''no vlan {0}-{1}
                  '''.format(vlan_list[0],vlan_list[-1])
        hdl.configure(uncfg,timeout=900)
        cfg=''
        log.info('Adding the L2 VNI back')
        for vlan in range(ns.start_vlan_id,ns.count+ns.start_vlan_id):
           cfg+='''vlan {0}
                   vn-segment {1}
                '''.format(vlan,ns.start_vni_id)
           ns.start_vni_id+=ns.incr_step
        cfg+='''exit
            '''
        hdl.configure(cfg, timeout=600)
        return 1 

def DeleteAddVxlanL3Vni(log,hdl,dut,configDict):

        ns=parseVxlanVniMapping(log,configDict['vxlan_dict'][dut]['evpn']['l3_vlan_vni_mapping'])
        vlan_list=[]
        uncfg =''
        log.info('Deleting all L3 VNI')
        for vlan in range(ns.start_vlan_id,ns.count+ns.start_vlan_id):
              vlan_list.append(vlan)
        uncfg += '''no vlan {0}-{1}
                  '''.format(vlan_list[0],vlan_list[-1])
        hdl.configure(uncfg,timeout=900)
        cfg=''
        log.info('Adding the L3 VNI back')
        for vlan in range(ns.start_vlan_id,ns.count+ns.start_vlan_id):
           cfg+='''vlan {0}
                   vn-segment {1}
                '''.format(vlan,ns.start_vni_id)
           ns.start_vni_id+=ns.incr_step
        cfg+='''exit
            '''
        hdl.configure(cfg, timeout=600)
        return 1 

def parseTriggerPimNveDict(log,pimTrigger_intNve_dict):

      arggrammar={}
      arggrammar['mode']='-type str'
  
      ns=parserutils_lib.argsToCommandOptions(pimTrigger_intNve_dict,arggrammar, log )
      return ns

def parsePortMapdict(log,vxlan_portMap_dict):
      arggrammar={}
      arggrammar['cust_vlan_id_start']='-type int'
      arggrammar['count']='-type int'
      arggrammar['vlan_start']='-type int'

      ns=parserutils_lib.argsToCommandOptions(vxlan_portMap_dict,arggrammar, log )
      return ns


def configurePortmap(log,hdl,dut,configDict,profile):
      '''Method to configure Portmap for dut'''
      log.info(banner('Configuring PortMap'))
      cfg=''
      for port in configDict['port_mapping_dict'][profile][dut]:
            ns=parsePortMapdict(log,configDict['port_mapping_dict'][profile][dut][port])
            cfg+='''interface {0}
                    switchport vlan mapping enable
                 '''.format(port)
            vlan_list=[]
            for vlan in range(ns.vlan_start,ns.count+ns.vlan_start):
                vlan_list.append(vlan)
                cfg+='''switchport vlan mapping {0} {1}
                     '''.format(ns.cust_vlan_id_start,vlan)
                ns.cust_vlan_id_start+=1
            cfg+='''shut
                    no shut
                 '''
            cfg+='''vlan {0}-{1}
                    shut
                    no shut
                  '''.format(vlan_list[0],vlan_list[-1])
      hdl.configure(cfg,timeout=900)
      return 1

def unconfigurePortmap(log,hdl,dut,configDict,profile):
      '''Method to Unconfigure Portmap for dut'''
      log.info(banner('UnConfiguring PortMap'))
      cfg=''
      for port in configDict['port_mapping_dict'][profile][dut]:
            ns=parsePortMapdict(log,configDict['port_mapping_dict'][profile][dut][port])
            cfg+='''interface {0}
                 '''.format(port)
            for vlan in range(ns.vlan_start,ns.count+ns.vlan_start):
                cfg+='''no switchport vlan mapping {0} {1}
                     '''.format(ns.cust_vlan_id_start,vlan)
                ns.cust_vlan_id_start+=1
            cfg+='''exit
                 '''
      hdl.configure(cfg,timeout=900)
      return 1


def buildPortMapdict(log,portmap_dict,profile):
         portvlanMapdict={}
         for dut in portmap_dict[profile]:
            portvlanMapdict[dut]={}
            for port in portmap_dict[profile][dut]:
                 ns=parsePortMapdict(log,portmap_dict[profile][dut][port])
                 portvlanMapdict[dut][port]={}
                 for vlan in range(ns.vlan_start,ns.count+ns.vlan_start):
                       portvlanMapdict[dut][port][ns.cust_vlan_id_start]=vlan
                       ns.cust_vlan_id_start+=1
         return portvlanMapdict

def verifyPortMap(log,hdl_list,portmap_config_dict,portvlanMapdict,profile):
        '''Method to verify port map configured'''
        log.info(banner('Verifying the Portmap for dut by comparing with portvlanMapdict got from buildPortMapdict'''))
        failVal=0
        retVal=[]
        pattern='(\d+)\s+(\d+)'
        portvlanMapDutDict={}
        for hdl in hdl_list:
         portvlanMapDutDict[hdl.alias]={}
         if hdl.alias in portmap_config_dict[profile]:
           for intf in portmap_config_dict[profile][hdl.alias]:
             portvlanMapDutDict[hdl.alias][intf]={}
             out=hdl.execute(f'show interface {intf} vlan mapping')
             for item in re.findall(pattern,out):
                  #print(f'#####item: {item[0]} and {item[1]}')
                  portvlanMapDutDict[hdl.alias][intf][int(item[0])]=int(item[1])
           print(f'####### portvlanMapdict[hdl.alias].items() is: {portvlanMapdict[hdl.alias].items()}')
           print(f'####### portvlanMapDutDict[hdl.alias].items() is : {portvlanMapDutDict[hdl.alias].items()}')
           if portvlanMapdict[hdl.alias].items()==portvlanMapDutDict[hdl.alias].items():
                   log.info(f'PortVlan Mapping is as expected in {hdl}')
                   retVal.append(1)
           else:
                   log.error(f'PortVlan Mapping is as not expected in {hdl}')
                   retVal.append(0)
        if failVal in retVal:
            return 0
        else:
            return 1 

       

        
def EnableDisableVlanMapping(log,hdl,dut,configDict,profile):
      '''Method to Enable and disable vlan mapping  for dut'''
      log.info(banner('Enable Disable PortMap'))
      cfg=''
      log.info('Disabling the Port mapping')
      for port in configDict['port_mapping_dict'][profile][dut]:
            ns=parsePortMapdict(log,configDict['port_mapping_dict'][profile][dut][port]) 
            cfg+='''interface {0}
                    no switchport vlan mapping enable
                 '''.format(port)
      hdl.configure(cfg, timeout=600)
      cfg1=''
      log.info('Enabling the Port mapping')
      for port in configDict['port_mapping_dict'][profile][dut]:
            ns=parsePortMapdict(log,configDict['port_mapping_dict'][profile][dut][port])
            cfg1+='''interface {0}
                      switchport vlan mapping enable
                      shut
                      no shut
                   '''.format(port)
      hdl.configure(cfg1, timeout=600)
                  
      return 1

def ModeChangePortmapInt(log,hdl,dut,configDict,profile):
      '''Method to configure change mode of Portmap Interface '''
      log.info(banner('Configuring the Portmode to Access in  PortMap enabled interface'))
      cfg1=''
      for port in configDict['port_mapping_dict'][profile][dut]:
            ns=parsePortMapdict(log,configDict['port_mapping_dict'][profile][dut][port]) 
            cfg1+='''interface {0}
                    switchport mode access
                 '''.format(port)
      hdl.configure(cfg1, timeout=600)
      vlan_list=[]
      log.info(banner('Configuring the Portmode to Trunk in  PortMap enabled interface'))
      cfg=''
      for port in configDict['port_mapping_dict'][profile][dut]:
            ns=parsePortMapdict(log,configDict['port_mapping_dict'][profile][dut][port])
            cfg+='''interface {0}
                    switchport mode trunk
                    switchport vlan mapping enable
                 '''.format(port)
            for vlan in range(ns.vlan_start,ns.count+ns.vlan_start):
                vlan_list.append(vlan)
                cfg+='''switchport vlan mapping {0} {1}
                     '''.format(ns.cust_vlan_id_start,vlan)
                ns.cust_vlan_id_start+=1
            cfg+='''switchport trunk allowed vlan {0}-{1}
                 '''.format(vlan_list[0],vlan_list[-1])
            cfg+='''vlan {0}-{1}
                    shut
                    no shut
                 '''.format(vlan_list[0],vlan_list[-1]) 
      out=hdl.configure(cfg,timeout=900)
      if re.search('error|invalid',out,re.I):
          log.error(f'Port Mode change config failed on {hdl}')
          return 0
      return 1


def RemoveAddTrunkVlanPortmapInt(log,hdl,dut,configDict,profile):
      '''Method to remove and Add the vlan in trunk allowed list in Portmap Interface '''
      log.info(banner('Remove the translated vlan from trunk allowed list in PortMap enabled interface'))
      cfg1=''
      vlan_list=[]
      for port in configDict['port_mapping_dict'][profile][dut]:
            ns=parsePortMapdict(log,configDict['port_mapping_dict'][profile][dut][port])
            for vlan in range(ns.vlan_start,ns.count+ns.vlan_start):
               vlan_list.append(vlan) 
            cfg1+='''interface {0}
                     sw trunk allowed vlan remove {1}-{2}
                 '''.format(port,vlan_list[0],vlan_list[-1])
      hdl.configure(cfg1, timeout=600)
      log.info(banner('Add the translated vlan back to Trunk Allowed list in PortMap enabled interface'))
      cfg=''
      for port in configDict['port_mapping_dict'][profile][dut]:
            ns=parsePortMapdict(log,configDict['port_mapping_dict'][profile][dut][port])
            cfg+='''interface {0}
                    sw trunk allowed vlan add {1}-{2}
                 '''.format(port,vlan_list[0],vlan_list[-1])
      out=hdl.configure(cfg, timeout=600)
      if re.search('error|invalid',out,re.I):
          log.error(f'Remove and addition of Trunk vlan failed on {hdl}')
          return 0       
      return 1


def MoveToDefaultAndAddMapping(log,hdl,configDict,profile):
       
      '''Method to move the interface to default and Adding back PortMapConfig'''
      log.info(banner('Default the Interface'))
      cfg1=''
      for port in configDict['port_mapping_dict'][profile][hdl.alias]:
            cfg1+='''default interface {0}
                 '''.format(port)
      hdl.configure(cfg1,timeout=900)
      log.info(banner('Config PortMap after defaulting the Interface'))
      cfg=''
      vlan_list=[]
      for port in configDict['port_mapping_dict'][profile][hdl.alias]:
            ns=parsePortMapdict(log,configDict['port_mapping_dict'][profile][hdl.alias][port])
            cfg+='''interface {0}
                    switchport 
                    switchport mode trunk 
                    switchport vlan mapping enable
                 '''.format(port)
            for vlan in range(ns.vlan_start,ns.count+ns.vlan_start):
                vlan_list.append(vlan) 
                cfg+='''switchport vlan mapping {0} {1}
                     '''.format(ns.cust_vlan_id_start,vlan)
                ns.cust_vlan_id_start+=1
            cfg+='''switchport trunk allowed vlan {0}-{1}
                    shut
                    no shut
                 '''.format(vlan_list[0],vlan_list[-1]) 
      out=hdl.configure(cfg,timeout=900)
      if re.search('error|invalid',out,re.I):
          log.error(f'Moving the interface to default and back to required config failed on {hdl}')
          return 0
      return 1


def AddDeleteNveLoopback(log,hdl,dut,configDict):
 
        log.info('Deleting the loopback of NVE interface')
        uncfg=''
        for intf in configDict['trigger_dict']['nve_int'][dut]['int_conf']:
               uncfg+='''no interface {0}
                      '''.format(intf)
               out=hdl.configure(uncfg, timeout=600)
               if re.search('error|invalid',out,re.I):
                   log.error(f'Deleting source interface loopback failed')
                   return 0
        log.info('Configuring back the loopback of Nve')
        for intf in configDict['trigger_dict']['nve_int'][dut]['int_conf']:
                 lo_args=configDict['trigger_dict']['nve_int'][dut]['int_conf'][intf]  
                 lo_args+=' -loopFlag True'
                 if not interface_lib.configureL3Intf(hdl,intf,lo_args,log):
                        log.error(f'Configuring loopback interface failed on {hdl}') 
                        return 0 
                 else:
                        log.info(f'Configuring loopback interface Sucessfull on {hdl}')
        if 'ospfv2_conf' in configDict['trigger_dict']['nve_int'][dut]:
          for instance in configDict['trigger_dict']['nve_int'][dut]['ospfv2_conf']:
                for intf in configDict['trigger_dict']['nve_int'][dut]['ospfv2_conf'][instance]:
                       sw_cmd=''
                       intf_cfg_dict={}
                       intf_cfg_dict=ospfv2_lib.parseOspfInterfaceConfig(configDict['trigger_dict']['nve_int'][dut]['ospfv2_conf'][instance][intf],log)
                       sw_cmd='''interface {0}
                                 ip router ospf {1} area {2}'''.format(intf, instance, intf_cfg_dict['area_id'])

                       if 'cost' in intf_cfg_dict:
                             sw_cmd='''{0}
                                    ip ospf cost {1}'''.format(sw_cmd, intf_cfg_dict['cost'])

                       if 'hello_interval' in intf_cfg_dict:
                            sw_cmd='''{0}
                                   ip ospf hello-interval {1}'''.format(sw_cmd, intf_cfg_dict['hello_interval'])

                       if 'dead_interval' in intf_cfg_dict:
                            sw_cmd='''{0}
                                   ip ospf dead-interval {1}'''.format(sw_cmd, intf_cfg_dict['dead_interval'])

                       if 'transmit_delay' in intf_cfg_dict:
                             sw_cmd='''{0}
                                    ip ospf transmit-delay {1}'''.format(sw_cmd, intf_cfg_dict['transmit_delay'])

                       if 'retransmit_interval' in intf_cfg_dict:
                            sw_cmd='''{0}
                                   ip ospf retransmit-interval {1}'''.format(sw_cmd, intf_cfg_dict['retransmit_interval'])

                       if 'priority' in intf_cfg_dict:
                           sw_cmd='''{0}
                                  ip ospf priority {1}'''.format(sw_cmd, intf_cfg_dict['priority'])

                       if 'network_type' in intf_cfg_dict:
                            sw_cmd='''{0}
                                   ip ospf network {1}'''.format(sw_cmd, intf_cfg_dict['network_type'])

                       if 'passive_interface' in intf_cfg_dict:
                                if intf_cfg_dict['passive_interface']:
                                       sw_cmd='''{0}
                                              ip ospf passive-interface'''.format(sw_cmd, intf_cfg_dict['passive_interface'])

                       if 'mtu_ignore' in intf_cfg_dict:
                            sw_cmd='''{0}
                                   ip ospf mtu-ignore'''.format(sw_cmd, intf_cfg_dict['mtu_ignore'])

                       out=hdl.configure(sw_cmd, timeout=600)
                       if re.search('error|invalid',out,re.I):
                           log.error(f'Configuring OSPF on loopback interface failed')
                           return 0 

        if 'pim_conf' in configDict['trigger_dict']['nve_int'][dut]:
                for intf in configDict['trigger_dict']['nve_int'][dut]['pim_conf']:
                      sw_cfg=''
                      ns=parseTriggerPimNveDict(log,configDict['trigger_dict']['nve_int'][dut]['pim_conf'][intf])
                      sw_cfg='''interface {0}
                                ip pim {1}-mode
                             '''.format(intf,ns.mode)
                out=hdl.configure(sw_cfg, timeout=600)
                if re.search('error|invalid',out,re.I):
                    log.error(f'Configuring PIM on loopback interface failed')
                    return 0
        return 1

def AddDeleteMsiteNveLoopback(log,hdl,dut,configDict):
 
        log.info('Deleting the Msite loopback of NVE interface')
        uncfg=''
        for intf in configDict['trigger_dict']['nve_int'][dut]['msite']['int_conf']:
               uncfg+='''no interface {0}
                      '''.format(intf)
               out=hdl.configure(uncfg, timeout=600)
               if re.search('error|invalid',out,re.I):
                   log.error(f'Deleting source interface loopback failed')
                   return 0
        log.info('Configuring back the loopback of Nve')
        for intf in configDict['trigger_dict']['nve_int'][dut]['msite']['int_conf']:
                 lo_args=configDict['trigger_dict']['nve_int'][dut]['msite']['int_conf'][intf]  
                 lo_args+=' -loopFlag True'
                 if not interface_lib.configureL3Intf(hdl,intf,lo_args,log):
                        log.error(f'Configuring loopback interface failed on {hdl}') 
                        return 0 
                 else:
                        log.info(f'Configuring loopback interface Sucessfull on {hdl}')
        if 'ospfv2_conf' in configDict['trigger_dict']['nve_int'][dut]['msite']:
          for instance in configDict['trigger_dict']['nve_int'][dut]['msite']['ospfv2_conf']:
                for intf in configDict['trigger_dict']['nve_int'][dut]['msite']['ospfv2_conf'][instance]:
                       sw_cmd=''
                       intf_cfg_dict={}
                       intf_cfg_dict=ospfv2_lib.parseOspfInterfaceConfig(configDict['trigger_dict']['nve_int'][dut]['msite']['ospfv2_conf'][instance][intf],log)
                       sw_cmd='''interface {0}
                                 ip router ospf {1} area {2}'''.format(intf, instance, intf_cfg_dict['area_id'])

                       if 'cost' in intf_cfg_dict:
                             sw_cmd='''{0}
                                    ip ospf cost {1}'''.format(sw_cmd, intf_cfg_dict['cost'])

                       if 'hello_interval' in intf_cfg_dict:
                            sw_cmd='''{0}
                                   ip ospf hello-interval {1}'''.format(sw_cmd, intf_cfg_dict['hello_interval'])

                       if 'dead_interval' in intf_cfg_dict:
                            sw_cmd='''{0}
                                   ip ospf dead-interval {1}'''.format(sw_cmd, intf_cfg_dict['dead_interval'])

                       if 'transmit_delay' in intf_cfg_dict:
                             sw_cmd='''{0}
                                    ip ospf transmit-delay {1}'''.format(sw_cmd, intf_cfg_dict['transmit_delay'])

                       if 'retransmit_interval' in intf_cfg_dict:
                            sw_cmd='''{0}
                                   ip ospf retransmit-interval {1}'''.format(sw_cmd, intf_cfg_dict['retransmit_interval'])

                       if 'priority' in intf_cfg_dict:
                           sw_cmd='''{0}
                                  ip ospf priority {1}'''.format(sw_cmd, intf_cfg_dict['priority'])

                       if 'network_type' in intf_cfg_dict:
                            sw_cmd='''{0}
                                   ip ospf network {1}'''.format(sw_cmd, intf_cfg_dict['network_type'])

                       if 'passive_interface' in intf_cfg_dict:
                                if intf_cfg_dict['passive_interface']:
                                       sw_cmd='''{0}
                                              ip ospf passive-interface'''.format(sw_cmd, intf_cfg_dict['passive_interface'])

                       if 'mtu_ignore' in intf_cfg_dict:
                            sw_cmd='''{0}
                                   ip ospf mtu-ignore'''.format(sw_cmd, intf_cfg_dict['mtu_ignore'])

                       out=hdl.configure(sw_cmd, timeout=600)
                       if re.search('error|invalid',out,re.I):
                           log.error(f'Configuring OSPF on loopback interface failed')
                           return 0 

        if 'pim_conf' in configDict['trigger_dict']['nve_int'][dut]['msite']:
                for intf in configDict['trigger_dict']['nve_int'][dut]['msite']['pim_conf']:
                      sw_cfg=''
                      ns=parseTriggerPimNveDict(log,configDict['trigger_dict']['nve_int'][dut]['msite']['pim_conf'][intf])
                      sw_cfg='''interface {0}
                                ip pim {1}-mode
                             '''.format(intf,ns.mode)
                out=hdl.configure(sw_cfg, timeout=600)
                if re.search('error|invalid',out,re.I):
                    log.error(f'Configuring PIM on loopback interface failed')
                    return 0
        return 1


def addRemoveNveMsiteIRL2vni(log,hdl,dut,configDict):

     '''Method to Remove and Add Msite IR under L2 vni in NVE'''
     log.info(banner('Removing Msite IR under L2 vni in NVE'))
     cfg=''
     cfg+='''int nve 1
          '''
     for group in configDict['vxlan_dict'][dut]['nve1']['l2_vni']:
            vni_list=[]
            na=parseVxlanNveL2Vni(log,configDict['vxlan_dict'][dut]['nve1']['l2_vni'][group])
            for vni in range(na.l2vni_start,na.count+na.l2vni_start):
                  vni_list.append(vni)
            cfg+='''member vni {0}-{1}
                    no multisite ingress-replication                    
                    '''.format(vni_list[0],vni_list[-1])
     out=hdl.configure(cfg, timeout=600)
     if re.search('error|invalid',out,re.I):
              log.error(f'Removing Msite IR under L2 vni in NVE failed on {hdl}')
              return 0

     log.info(banner('Adding Msite IR under L2 vni in NVE'))
     cfg=''
     cfg+='''int nve 1
          '''
     for group in configDict['vxlan_dict'][dut]['nve1']['l2_vni']:
            vni_list=[]
            na=parseVxlanNveL2Vni(log,configDict['vxlan_dict'][dut]['nve1']['l2_vni'][group])
            for vni in range(na.l2vni_start,na.count+na.l2vni_start):
                  vni_list.append(vni)
            cfg+='''member vni {0}-{1}
                    multisite ingress-replication                    
                 '''.format(vni_list[0],vni_list[-1])
     out=hdl.configure(cfg, timeout=600)
     if re.search('error|invalid',out,re.I):
              log.error(f'Adding Msite IR under L2 vni in NVE failed on {hdl}')
              return 0
     return 1

def addRemoveNveTrmMsiteIRL3vni(log,hdl,dut,configDict):

     '''Method to Remove and Add TRM Msite IR under L3 vni in NVE'''
     log.info(banner('Removing TRM Msite IR under L3 vni in NVE'))
     cfg=''
     cfg+='''int nve 1
          '''
     na=parseVxlanNveL3Vni(log,configDict['vxlan_dict'][dut]['nve1']['l3_vni'])
     for vni in range(na.l3vni_start,na.count+na.l3vni_start):
            cfg+='''member vni {0} associate-vrf
                    no multisite ingress-replication optimized                   
                 '''.format(vni)
     out=hdl.configure(cfg, timeout=600)
     if re.search('error|invalid',out,re.I):
              log.error(f'Removing TRM Msite IR under L3 vni in NVE failed on {hdl}')
              return 0

     log.info(banner('Adding TRM Msite IR under L3 vni in NVE'))
     cfg=''
     cfg+='''int nve 1
          '''
     for vni in range(na.l3vni_start,na.count+na.l3vni_start):
            cfg+='''member vni {0} associate-vrf
                    multisite ingress-replication optimized                   
                 '''.format(vni)
     out=hdl.configure(cfg, timeout=600)
     if re.search('error|invalid',out,re.I):
              log.error(f'Adding TRM Msite IR under L3 vni in NVE failed on {hdl}')
              return 0

     return 1

def addRemoveMsiteBorderGw(log,hdl,dut,configDict):

      '''Method to Remove and Add Msite Border gateway'''

      log.info(banner('Removing Msite Border gateway'))
      cfg=''
      ns=parseVxlanMsiteGlobal(log,configDict['vxlan_dict'][dut]['msite']['global'])
      cfg+='''no evpn multisite border-gateway {0}
           '''.format(ns.msite_id)
      out=hdl.configure(cfg,timeout=900)
      if re.search('error|invalid',out,re.I):
          log.error(f'Removing Msite Border gateway failed on {hdl}')
          return 0
 
      log.info(banner('Adding Msite Border gateway'))
      cfg=''
      cfg+='''evpn multisite border-gateway {0}
              delay-restore time {1}
           '''.format(ns.msite_id,ns.delay_restore)
      log.info('Enabling the DCI-Links')
      for int in configDict['vxlan_dict'][dut]['msite']['dci_int'].split(' '):
             cfg+='''interface {0}
                     evpn multisite dci-tracking
                  '''.format(int)
      log.info('Enabling the Fabric-Links')
      for int in configDict['vxlan_dict'][dut]['msite']['fabric_int'].split(' '):
            cfg+='''interface {0}
                    evpn multisite fabric-tracking
                 '''.format(int)
      
      out=hdl.configure(cfg,timeout=900)
      if re.search('error|invalid',out,re.I):
          log.error(f'Adding Msite Border gateway failed on {hdl}')
          return 0
      log.info(banner('Adding Msite IR under L2 vni in NVE'))
      cfg=''
      cfg+='''int nve 1
          '''
      ng=parseVxlanNveGlobal(log,configDict['vxlan_dict'][dut]['nve1']['global'])
      cfg+='''multisite border-gateway interface {0}
           '''.format(ng.msite_int)      
      for group in configDict['vxlan_dict'][dut]['nve1']['l2_vni']:
            vni_list=[]
            na=parseVxlanNveL2Vni(log,configDict['vxlan_dict'][dut]['nve1']['l2_vni'][group])
            for vni in range(na.l2vni_start,na.count+na.l2vni_start):
                  vni_list.append(vni)
            cfg+='''member vni {0}-{1}
                    multisite ingress-replication                    
                 '''.format(vni_list[0],vni_list[-1])
      out=hdl.configure(cfg, timeout=600)
      if re.search('error|invalid',out,re.I):
              log.error(f'Adding Msite IR under L2 vni in NVE failed on {hdl}')
              return 0
      cfg=''
      cfg+='''int nve 1
          '''
      nb=parseVxlanNveL3Vni(log,configDict['vxlan_dict'][dut]['nve1']['l3_vni'])
      if nb.trm_mcast_start:
          for vni in range(nb.l3vni_start,nb.count+nb.l3vni_start):
             cfg+='''member vni {0} associate-vrf
                     multisite ingress-replication optimized
                  '''.format(vni)
          out=hdl.configure(cfg, timeout=600)
          if re.search('error|invalid',out,re.I):
              log.error(f'Adding Msite IR under L3 vni in NVE failed on {hdl}')
              return 0
      return 1
      
def flapMsiteFabricLink(log,hdl,dut,configDict):


     '''Method to Flap the Fabric link'''
     log.info(banner('Flapping the Fabric link'))
     cfg=''
     for int in configDict['vxlan_dict'][dut]['msite']['fabric_int'].split(' '):
            cfg+='''interface {0}
                    shut
                    no shut
                 '''.format(int)
     out=hdl.configure(cfg, timeout=600)
     if re.search('error|invalid',out,re.I):
              log.error(f'Flap Fabric link failed on {hdl}')
              return 0
     return 1

def flapMsiteDciLink(log,hdl,dut,configDict):

     '''Method to Flap the DCI link'''
     log.info(banner('Flapping the DCI link'))
     cfg=''
     for int in configDict['vxlan_dict'][dut]['msite']['dci_int'].split(' '):
            cfg+='''interface {0}
                    shut
                    no shut
                 '''.format(int)
     out=hdl.configure(cfg, timeout=600)
     if re.search('error|invalid',out,re.I):
              log.error(f'Flap DCI link failed on {hdl}')
              return 0
     return 1

def AddRemoveFabricTrack(log,hdl,dut,configDict):

     '''Method to Add/Remove Fabric Tracking'''
     log.info(banner(' Remove the Fabric Track'))
     cfg=''
     for int in configDict['vxlan_dict'][dut]['msite']['fabric_int'].split(' '):
            cfg+='''interface {0}
                    no evpn multisite fabric-tracking
                 '''.format(int)
     out=hdl.configure(cfg, timeout=600)
     if re.search('error|invalid',out,re.I):
              log.error(f'Remove Fabric tracking failed on {hdl}')
              return 0
     
     log.info(banner(' Add back the Fabric Track'))
     cfg=''
     for int in configDict['vxlan_dict'][dut]['msite']['fabric_int'].split(' '):
            cfg+='''interface {0}
                    evpn multisite fabric-tracking
                 '''.format(int)
     out=hdl.configure(cfg, timeout=600)
     if re.search('error|invalid',out,re.I):
              log.error(f'Adding back Fabric tracking failed on {hdl}')
              return 0
     
     return 1

def AddRemoveDciTrack(log,hdl,dut,configDict):

     '''Method to Add/Remove DCI Tracking'''
     log.info(banner(' Remove the dci Track'))
     cfg=''
     for int in configDict['vxlan_dict'][dut]['msite']['dci_int'].split(' '):
            cfg+='''interface {0}
                    no evpn multisite dci-tracking
                 '''.format(int)
     out=hdl.configure(cfg, timeout=600)
     if re.search('error|invalid',out,re.I):
              log.error(f'Remove Dci tracking failed on {hdl}')
              return 0
     
     log.info(banner(' Add back the DCI Track'))
     cfg=''
     for int in configDict['vxlan_dict'][dut]['msite']['dci_int'].split(' '):
            cfg+='''interface {0}
                    evpn multisite dci-tracking
                 '''.format(int)
     out=hdl.configure(cfg, timeout=600)
     if re.search('error|invalid',out,re.I):
              log.error(f'Adding back Dci tracking  failed on {hdl}')
              return 0
     
     return 1

def flapUplink(log,hdl,dut,configDict):
       '''Method to Flap the Uplink'''
       log.info(banner('Flapping the Uplink'))
       cfg=''
       for intf in configDict['trigger_dict']['uplink'][dut]:
             cfg+='''interface {0}
                     shut
                     no shut
                  '''.format(configDict['trigger_dict']['uplink'][dut][intf])
       out=hdl.configure(cfg, timeout=600)
       if re.search('error|invalid',out,re.I):
              log.error(f'Flap Uplink failed on {hdl}')
              return 0
       return 1

def flapvMCTKeepalivelink(log,hdl,dut,configDict):
       '''Method to Flap the vMCT Keepalive link'''
       log.info(banner('Flapping the vMCT Keepalive link'))
       cfg=''
       for intf in configDict['trigger_dict']['VMctKeepalive'][dut]:
             cfg+='''interface {0}
                     shut
                     no shut
                  '''.format(configDict['trigger_dict']['VMctKeepalive'][dut][intf])
       out=hdl.configure(cfg, timeout=600)
       if re.search('error|invalid',out,re.I):
              log.error(f'Flap of vMCT Keepalive failed on {hdl}')
              return 0
       return 1

def flapMCTlink(log,hdl,dut,configDict):
       '''Method to Flap the MCT link'''
       log.info(banner('Flapping the MCT link'))
       cfg=''
       cfg+='''interface {0}
               shut
               no shut
               '''.format(configDict['trigger_dict']['Vpc_MCT'])
       out=hdl.configure(cfg, timeout=600)
       if re.search('error|invalid',out,re.I):
              log.error(f'Flap of vMCT Keepalive failed on {hdl}')
              return 0
       return 1


def shutUnshutPort(log,hdl,dut,configDict,action):
       '''Method to shut / unshut  port'''
       cfg=''
       for intf in configDict['trigger_dict']['uplink'][dut]:
             if action == 'shut':
                  cfg+='''interface {0}
                          shut
                       '''.format(configDict['trigger_dict']['uplink'][dut][intf])
             elif action == 'no shut':
                  cfg+='''interface {0}
                          no shut
                       '''.format(configDict['trigger_dict']['uplink'][dut][intf])
       out=hdl.configure(cfg, timeout=600)
       if re.search('error|invalid',out,re.I):
              log.error(f'Shut or Unshut failed on {hdl}')
              return 0
       return 1

       
def RemoveAddPortTypeFabric(log,hdl,dut,configDict):
      '''Method to Remove and Add port type fabric in uplinks'''
      log.info(banner(' Remove and Add port type fabric in uplinks'))
      uncfg=cfg=''
      log.info('Removing the port-type fabric from uplink')
      for intf in configDict['trigger_dict']['uplink'][dut]:
              uncfg+='''interface {0}
                      no port-type fabric
                   '''.format(configDict['trigger_dict']['uplink'][dut][intf])
      out=hdl.configure(uncfg, timeout=600)
      if re.search('error|invalid',out,re.I):
              log.error(f'Flap Uplink failed on {hdl}')
              return 0
      log.info('Adding the port-type fabric to uplink')
      for intf in configDict['trigger_dict']['uplink'][dut]:
              cfg+='''interface {0}
                      port-type fabric
                   '''.format(configDict['trigger_dict']['uplink'][dut][intf])
      out=hdl.configure(cfg, timeout=600)
      if re.search('error|invalid',out,re.I):
              log.error(f'Flap Uplink failed on {hdl}')
              return 0
      return 1     
      
def flapAccesslink(log,hdl,dut,configDict):
       '''Method to Flap the Access link'''
       log.info(banner('Flapping the Access link'))
       cfg=''
       for intf in configDict['trigger_dict']['Access'][dut]:
             cfg+='''interface {0}
                     shut
                     no shut
                  '''.format(configDict['trigger_dict']['Access'][dut][intf])
       out=hdl.configure(cfg, timeout=600)
       if re.search('error|invalid',out,re.I):
              log.error(f'Flap Access link failed on {hdl}')
              return 0
       return 1

def flapVPCPOlink(log,hdl,dut,configDict):
       '''Method to Flap VPC PO Access link'''
       log.info(banner('Flapping VPC PO the Access link'))
       cfg=''
       for intf in configDict['trigger_dict']['VpcPOAccess'][dut]:
             cfg+='''interface {0}
                     shut
                     no shut
                  '''.format(intf)
       out=hdl.configure(cfg, timeout=600)
       if re.search('error|invalid',out,re.I):
              log.error(f'Flap VPC PO Access link failed on {hdl}')
              return 0
       return 1

def shutUnshutVPCPOlink(log,hdl,dut,configDict,action):
      '''Method to shut and Unshut VPC PO Access link'''
      if action == 'shut':
         cfg=''
         for intf in configDict['trigger_dict']['VpcPOAccess'][dut]:
               cfg+='''interface {0}
                       shut
                    '''.format(intf)
         out=hdl.configure(cfg, timeout=600)
         if re.search('error|invalid',out,re.I):
             log.error(f'Shut of VPC PO Access link failed on {hdl}')
             return 0
      if action == 'unshut':
         cfg=''
         for intf in configDict['trigger_dict']['VpcPOAccess'][dut]:
               cfg+='''interface {0}
                       no shut
                    '''.format(intf)
         out=hdl.configure(cfg, timeout=600)
         if re.search('error|invalid',out,re.I):
             log.error(f'Shut of VPC PO Access link failed on {hdl}')
             return 0
      return 1
    
def flapVPCPOMemlink(log,hdl,dut,configDict):
       '''Method to Flap VPC PO Member Access link'''
       log.info(banner('Flapping the VPC PO Member Access link'))
       cfg=''
       for po in configDict['trigger_dict']['VpcPOAccess'][dut]:
           for intf in configDict['trigger_dict']['VpcPOAccess'][dut][po]['memberList'].split(' '): 
              cfg+='''interface {0}
                     shut
                     no shut
                  '''.format(intf)
       out=hdl.configure(cfg, timeout=600)
       if re.search('error|invalid',out,re.I):
              log.error(f'Flap VPC PO Member Access link failed on {hdl}')
              return 0
       return 1

def shutUnshutVPCPOMemlink(log,hdl,dut,configDict,action):
      '''Method to shut and Unshut VPC PO Access link'''
      if action == 'shut':
         cfg=''
         for po in configDict['trigger_dict']['VpcPOAccess'][dut]:
           for intf in configDict['trigger_dict']['VpcPOAccess'][dut][po]['memberList'].split(' '): 
              cfg+='''interface {0}
                     shut
                  '''.format(intf)
         out=hdl.configure(cfg, timeout=600)
         if re.search('error|invalid',out,re.I):
              log.error(f'Flap VPC PO Member Access link failed on {hdl}')
              return 0
 
      if action == 'unshut':
         cfg=''
         for po in configDict['trigger_dict']['VpcPOAccess'][dut]:
           for intf in configDict['trigger_dict']['VpcPOAccess'][dut][po]['memberList'].split(' '): 
              cfg+='''interface {0}
                     no shut
                  '''.format(intf)
         out=hdl.configure(cfg, timeout=600)
         if re.search('error|invalid',out,re.I):
              log.error(f'Flap VPC PO Member Access link failed on {hdl}')
              return 0
 
         out=hdl.configure(cfg, timeout=600)
         if re.search('error|invalid',out,re.I):
             log.error(f'Shut of VPC PO Access link failed on {hdl}')
             return 0
      return 1
 
def deleteAddVpcId(log,hdl,dut,configDict):
       '''Method to delete Add VPC Id in VPC Po Accesss'''
       uncfg=cfg=''
       cfg=''
       log.info('Deleting the VPC')
       for po in configDict['trigger_dict']['VpcPOAccess'][dut]:
              uncfg+='''interface {0}
                        no vpc {1}
                     '''.format(po,configDict['trigger_dict']['VpcPOAccess'][dut][po]['vpc_id'])
       out=hdl.configure(uncfg, timeout=600)
       if re.search('error|invalid',out,re.I):
                log.error(f'Deleting of VPC failed on {hdl}')
                return 0
       log.info('Adding the VPC')
       for po in configDict['trigger_dict']['VpcPOAccess'][dut]:
                cfg+='''interface {0}
                        vpc {1}
                     '''.format(po,configDict['trigger_dict']['VpcPOAccess'][dut][po]['vpc_id'])
       out=hdl.configure(cfg, timeout=600)
       if re.search('error|invalid',out,re.I):
            log.error(f'Adding of VPC failed on {hdl}')
            return 0
       return 1
                     
def flapNveSourceInt(log,hdl,dut,configDict):
 
        log.info('Flapping the loopback of NVE interface')
        cfg=''
        for intf in configDict['trigger_dict']['nve_int'][dut]['int_conf']:
              cfg+='''interface {0}
                      shut
                      no shut
                   '''.format(intf)
        out=hdl.configure(cfg, timeout=600)
        if re.search('error|invalid',out,re.I):
             log.error(f'Flap source int of Nve {intf} failed on {hdl}')
             return 0
        return 1

def flapNveMsiteSourceInt(log,hdl,dut,configDict):
 
        log.info('Flapping the loopback of NVE Msite interface')
        cfg=''
        for intf in configDict['trigger_dict']['nve_int'][dut]['msite']['int_conf']:
              cfg+='''interface {0}
                      shut
                      no shut
                   '''.format(intf)
        out=hdl.configure(cfg, timeout=600)
        if re.search('error|invalid',out,re.I):
             log.error(f'Flap source int of Nve Msite {intf} failed on {hdl}')
             return 0
        return 1


def flapVxlanVrf(log,hdl,dut,configDict):

     log.info('Flapping the Vxlan VRF')
     shutcfg=''
     cfg=''
     for vrf in configDict['vxlan_dict'][dut]['evpn']['vrf']:
             shutcfg+='''vrf context {0}
                     shut
                  '''.format(vrf)
             out=hdl.configure(cfg, timeout=600)
             if re.search('error|invalid',out,re.I):
                 log.error(f'VRF shut failed on {hdl}')
                 return 0
             log.info(f'Sleeping for some time in  order to complete the VRF shut process in {hdl}')
             time.sleep(60)        
             cfg+='''vrf context {0}
                  no shut
             '''.format(vrf)
             out=hdl.configure(cfg, timeout=600)
             if re.search('error|invalid',out,re.I):
                   log.error(f'VRF unshut failed on {hdl}')
                   return 0
     return 1

def flapL2VniSvi(log,hdl,dut,configDict):

       log.info('Flapping L2 VNI SVI')
       cfg=''
       for vrf in configDict['vxlan_dict'][dut]['evpn']['l2_vni_svi']:
               ns=parseVxlanl2SviAnyCastGateway(log,configDict['vxlan_dict'][dut]['evpn']['l2_vni_svi'][vrf])
               vlan_list=[]
               for vlan in range(ns.l2vni_start,ns.count+ns.l2vni_start):
                      vlan_list.append(vlan)
               cfg+='''interface vlan {0}-{1}
                       shut
                       no shut
                    '''.format(vlan_list[0],vlan_list[-1])
       out=hdl.configure(cfg,timeout=900)
       if re.search('error|invalid',out,re.I):
              log.error(f'L2 VNI SVI failed on {hdl}')
              return 0
       return 1

def SuspendActiveVxlanVlan(log,hdl,dut,configDict):

       log.info('Vxlan Vlan Suspend and Activate')
       cfg_suspend=''
       cfg_activate=''
       for vrf in configDict['vxlan_dict'][dut]['evpn']['l2_vni_svi']:
               ns=parseVxlanl2SviAnyCastGateway(log,configDict['vxlan_dict'][dut]['evpn']['l2_vni_svi'][vrf])
               vlan_list=[]
               for vlan in range(ns.l2vni_start,ns.count+ns.l2vni_start):
                      vlan_list.append(vlan)
               cfg_suspend+='''vlan {0}-{1}
                               state suspend
                               exit 
                             '''.format(vlan_list[0],vlan_list[-1])
               cfg_activate+='''vlan {0}-{1}
                               state active
                               exit 
                             '''.format(vlan_list[0],vlan_list[-1])
       log.info('Vxlan Vlan Suspend')
       out=hdl.configure(cfg_suspend,timeout=900)
       if re.search('error|invalid',out,re.I):
              log.error(f'Vxlan Vlan suspend failed on {hdl}')
              return 0
       log.info('Vxlan Vlan Activate')
       out=hdl.configure(cfg_activate,timeout=900)
       if re.search('error|invalid',out,re.I):
              log.error(f'Vxlan Vlan activate failed on {hdl}')
              return 0
       return 1
 
def flapL3VniSvi(log,hdl,dut,configDict):

       log.info('Flapping L3 VNI SVI')
       cfg=''
       for vrf in configDict['vxlan_dict'][dut]['evpn']['l3_vni_svi']:
               ns=parseVxlanl3SviAnyCastGateway(log,configDict['vxlan_dict'][dut]['evpn']['l3_vni_svi'][vrf])
               vlan_list=[]
               for vlan in range(ns.l3vni_start,ns.count+ns.l3vni_start):
                      vlan_list.append(vlan)
               cfg+='''interface vlan {0}-{1}
                       shut
                       no shut
                    '''.format(vlan_list[0],vlan_list[-1])
       out=hdl.configure(cfg,timeout=900)
       if re.search('error|invalid',out,re.I):
              log.error(f'L3 VNI SVI failed on {hdl}')
              return 0
       return 1

def DeleteAddL2VniSvi(log,hdl,dut,configDict):

       log.info('Deleting and Adding L2 VNI SVI')
       uncfg=''
       cfg=''
       for vrf in configDict['vxlan_dict'][dut]['evpn']['l2_vni_svi']:
               ns=parseVxlanl2SviAnyCastGateway(log,configDict['vxlan_dict'][dut]['evpn']['l2_vni_svi'][vrf])
               vlan_list=[]
               for vlan in range(ns.l2vni_start,ns.count+ns.l2vni_start):
                      vlan_list.append(vlan)
               log.info('DeletingL2 VNI SVI')
               uncfg+='''no interface vlan {0}-{1}
                    '''.format(vlan_list[0],vlan_list[-1])
               out=hdl.configure(uncfg,timeout=900)
               if re.search('error|invalid',out,re.I):
                    log.error(f'Deleting L2 VNI SVI failed on {hdl}')
                    return 0
               time.sleep(20)
               log.info('Adding L2 VNI SVI')
               result=configVxlanL2AnyCastGateway(configDict['vxlan_dict'][dut]['evpn']['l2_vni_svi'],hdl,log)
               if not result:
                    log.error(f'Adding L2 VNI SVI failed on {hdl}')
       return 1

def DeleteAddL3VniSvi(log,hdl,dut,configDict):

       log.info('Deleting and Adding L3 VNI SVI')
       uncfg=''
       cfg=''
       for vrf in configDict['vxlan_dict'][dut]['evpn']['l3_vni_svi']:
               ns=parseVxlanl3SviAnyCastGateway(log,configDict['vxlan_dict'][dut]['evpn']['l3_vni_svi'][vrf])
               vlan_list=[]
               for vlan in range(ns.l3vni_start,ns.count+ns.l3vni_start):
                      vlan_list.append(vlan)
               log.info('Deleting L3 VNI SVI')
               uncfg+='''interface vlan {0}-{1}
                       shut
                       no shut
                    '''.format(vlan_list[0],vlan_list[-1])
               out=hdl.configure(cfg,timeout=900)
               if re.search('error|invalid',out,re.I):
                     log.error(f'L3 VNI SVI failed on {hdl}')
                     return 0
               log.info('Adding back L3 VNI SVI')
               result=configVxlanL3AnyCastGateway(configDict['vxlan_dict'][dut]['evpn']['l3_vni_svi'],hdl,log)
               if not result:
                    log.error(f'Adding L3 VNI SVI failed on {hdl}')
       return 1


def flapVMctDomain(log,hdl,dut,configDict):

      log.info('Flapping VPC Domain')
      cfg=''
      cfg+='''vpc domain {0}
             shut
             no shut
          '''.format(configDict['trigger_dict']['Vpc'][dut]['domain_id'])
      out=hdl.configure(cfg,timeout=900)
      if re.search('error|invalid',out,re.I):
          log.error(f'Vpc domain flap failed on {hdl}')
          return 0
      return 1
      
def verifyPvlanMapCC(log,hdl):

        log.info('Verifing Port Vlan Mapping ')
        out=hdl.execute('show consistency-checker vxlan pv',timeout=350)
        pattern='Vxlan pv Overall status\s+\:\s+PASS'

        if re.search(pattern,out):
           log.info(f'VXLAN CC PV Passed for {hdl}')
           return 1
        else:
           log.error(f'VXLAN CC PV failed for {hdl}')
           return 0

def verifyFexCC(log,hdl,fexno):

        log.info('Verifing Fex CC')
        out=hdl.execute(f'show consistency-checker fex-interfaces fex {fexno}',timeout=350) 
        pattern='Consistency Check:\s+(\S+)'
        cc_result=re.search(pattern,out)[1]
        if cc_result == 'PASSED':
              log.info(f'Fex CC passed for {hdl}')
              return 1
        else:
              log.error(f'Fex CC failed for {hdl}')
              return 0

def verifyVMCTCC(log,hdl):
 
        log.info('Verifing vpc CC')
        out={}
        out=hdl.execute('show consistency-checker vpc brief',timeout=350)
        if re.search('CC_STATUS_OK',out):
               log.info(f'VPC CC passed for {hdl}')
               return 1
        else:
               log.error(f'VPC CC failed for {hdl}')
               return 0

def verifyVMCTVlanCC(log,hdl):

        log.info('Verifing vmct vlan CC')
        out=hdl.execute('sh vpc virtual-peerlink vlan consistency')
        if re.search('inconsistent',out):
              log.error(f'vMCT Vlan CC failed for {hdl}')
              return 0
        else:
              log.info(f'VPC CC passed for {hdl}')
              return 1

def verrifyL2CC(log,hdl):
        
        log.info('Verifing CC for l2 module')
        out=hdl.execute('show consistency-checker l2 module 1')
        time.sleep(20)

        pat='Consistency check:\s+(\S+)'

        result=re.search(pat,out)
        if result[1]=='PASSED':
               log.info('CC for L2 is PASSED')
               return 1
        else:
               log.error('CC for L2 is FAILED')
               return 0

def triggerNveSourceIntChange(log,hdl,sourceInt):
 
         log.info('Triggering Source Interface change for NVE')
         cmd='''interface nve 1
                shut
                no source-interface
                source-interface {0}
                no shut'''.format(sourceInt)
         hdl.configure(cmd, timeout=600)
         '''
         hdl.sendline('configure terminal')
         hdl.expect('# $')
         hdl.sendline('interface nve 1')
         hdl.expect('# $')
         hdl.sendline('shut')
         j=hdl.expect(['# $','\[n\] '],timeout=20)
         if j==0:
           swHdl.sendline('\r')
           swHdl.expect('# $')
           swHdl.sendline('no source-interface')
           swHdl.expect('# $')
           swHdl.sendline('source-interface {0}'.format(sourceInt))
           swHdl.expect('# $')
           swHdl.sendline('no shut')
           swHdl.expect('# $')
         if j==1:
           swHdl.sendline('y')
           swHdl.expect('# $')
           swHdl.sendline('no source-interface')
           swHdl.expect('# $')
           swHdl.sendline('source-interface {0}'.format(sourceInt))
           swHdl.expect('# $')
           swHdl.sendline('no shut')
           swHdl.expect('# $')
           '''

def verifyfexState(log,hdl):

       log.info('Verifying whether Fex is online')
       out=json.loads(hdl.execute('sh fex | json'))
       if out['TABLE_fex']['ROW_fex']['fex_state'] == 'Online':
             log.info('Fex came online after reload as expected')
             return 1
       else:
             log.error('Fex is offline')
             return 0

def verifyNveState(log,hdl):

      '''Method the verify NVE'''
      out=json.loads(hdl.execute('sh int nve 1 | json'))
      if out['TABLE_interface']['ROW_interface']['state'] == 'up' and out['TABLE_interface']['ROW_interface']['admin_state'] == 'up':
            log.info('NVE is up')
            return 1
      else:
           log.error('NVE is not up')
           return 0
       
def reloadFex(log,hdl):

       ''' Method to reload Fex'''
       log.info(f'Reloading Fex on {hdl}')
       hdl.sendline('reload fex all')
       hdl.expect('\[n\]')
       hdl.sendline('y')
       hdl.expect('# $')
       log.info('Sleeping for Fex to come online')
       time.sleep(300)
       log.info('Verifying whether Fex is online')
       if verifyfexState(log,hdl):
             log.info('Reload of Fex is sucessfull')
             return 1
       else:
             log.error('Reload of Fex is not sucessfull and Fex is oflline')
             return 0

def shutNveFex(log,hdl):

      '''Method to shut NVE with Fex'''
      log.info(f'Shut NVE on {hdl}')
      hdl.sendline('conf term')
      hdl.expect('# $')
      hdl.sendline('interface nve 1')
      hdl.expect('# $')
      hdl.sendline('shut') 
      hdl.expect('\[n\]')
      hdl.sendline('y')
      hdl.expect('# $')
      hdl.sendline('no shut')
      hdl.expect('# $')
      hdl.sendline('exit')
      hdl.expect('# $')
      hdl.sendline('exit')
      hdl.expect('# $')
      log.info('Sleeping for NVE to come Up')
      time.sleep(70)
      if verifyNveState(log,hdl):
            log.info('Nve is up after flap')
            return 1
      else:
            log.error('Nve is not up after flap')
            return 0

def parseFex(log,fexDict):
     arggrammar={}
     arggrammar['fex_po']='-type str'
     arggrammar['member_link']='-type str'
     arggrammar['vpc_id']='-type int'

     ns=parserutils_lib.argsToCommandOptions(fexDict, arggrammar, log)
     return ns

def parseFexInt(log,fexDict):
     arggrammar={}
     arggrammar['mode']='-type str'
     arggrammar['switchportmode']='-type str'
     arggrammar['allowed_vlan_list']='-type str'
     arggrammar['vpc_id']='-type int'
     arggrammar['member_link']='-type str'
     arggrammar['po']='-type int'
     arggrammar['disable_bpdu']='-type bool'

     ns=parserutils_lib.argsToCommandOptions(fexDict, arggrammar, log)
     return ns

def configFex(log,hdl,dut,configDict):
      cfg=''
      for fexno in configDict['fex_dict'][dut]:
           ns=parseFex(log,configDict['fex_dict'][dut][fexno]['fex_int'])

           cfg+='''install feature-set fex
                   feature-set fex
                   fex {0}
                   pinning max-links 1
                '''.format(fexno)
           cfg+='''int {0}
                   no shut
                   switchport
                   switchport mode fex-fabric
                   fex associate {1}
                '''.format(ns.fex_po,fexno)
           if ns.vpc_id:
                cfg+='''vpc {0}
                     '''.format(ns.vpc_id)
           for eth in ns.member_link.split(' '):
                cfg+='''int {0}
                        no shut
                        channel-group {1} force
                     '''.format(eth,fexno)

           out=hdl.configure(cfg,timeout=120)
           if re.search('error|invalid',out,re.I):
              log.error(f'Configure Fex failed on {hdl}')
              return 0

           log.info('Sleeping for Fex to come online')
           time.sleep(700)
           log.info('Verifying whether Fex is online')
           if verifyfexState(log,hdl):
                log.info('Fex came online after reload as expected')
           else:
                 log.error('Fex is offline')
                 return 0
           log.info('Configuring Fex interface')
           cfgs=''
           for intf in configDict['fex_dict'][dut][fexno]['int_conf']:
              nf=parseFexInt(log,configDict['fex_dict'][dut][fexno]['int_conf'][intf])
              cfgs+='''int {0}
                       no shut
                       '''.format(intf)
              if nf.mode:
                  cfgs+='''switchport
                        '''
              if nf.switchportmode == 'trunk':
                  cfgs+='''switchport mode trunk
                        '''
              if nf.allowed_vlan_list:
                  cfgs+='''switchport trunk allowed vlan {0}
                        '''.format(nf.allowed_vlan_list)
              if nf.disable_bpdu:
                  cfgs+='''spanning-tree bpduguard disable
                        '''
              if nf.vpc_id:
                  cfgs+='''vpc {0}
                        '''.format(nf.vpc_id)
              if nf.switchportmode == 'access':
                  cfgs+='''switchport mode access
                         '''
              if nf.member_link:
                 for intf in nf.member_link.split(' '):
                      cfgs+='''int {0}
                               channel-group {1} force mode active
                               shut
                               no shut
                            '''.format(intf,nf.po)
           out=hdl.configure(cfgs,timeout=120)
           if re.search('error|invalid',out,re.I):
              log.error(f'Configure Fex failed on {hdl}')
              return 0
      return 1

def ProcessRestart(dut, p_name):

   #Inside verifyProcessRestart

   dut.configure("feature bash-shell", timeout=600)
   dut.configure('system no hap-reset', timeout=600)

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

   # unicon_state.restore_state_pattern()
   # unicon_state = ""

   #countDownTimer(30)

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
