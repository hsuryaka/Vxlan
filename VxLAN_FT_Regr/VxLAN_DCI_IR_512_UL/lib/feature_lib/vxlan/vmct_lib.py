
import os
import sys
import yaml
import re
#import netaddr
import utils
from utils import *
import  bringup_lib
import parserutils_lib
import verify_lib
import time
import socket
import ipaddr
#import netaddr
import interface_lib
import ospfv2_lib
import json 

from ats.log.utils import banner


def parseVmctDomain (log, args):
         arggrammar = {}
         arggrammar['domain_id'] = '-type str -required True'
         arggrammar['peer_gateway'] = '-type bool -default False'
         arggrammar['peer_switch']= '-type bool -default False'
         arggrammar['arp_synchronize'] = '-type bool -default False'
         arggrammar['ipv6_nd_synchronize'] = '-type bool -default False'
         arggrammar['peer_keepalive_dst_ipv4_addr'] = '-type str'
         arggrammar['peer_keepalive_src_ipv4_addr'] = '-type str'
         arggrammar['peer_keepalive_vrf'] = '-type str -default default'
         arggrammar['virtual_peer_dst_addr'] = '-type str'
         arggrammar['virtual_peer_src_addr']='-type str'

         parse = utils.parserutils_lib.argsToCommandOptions(args,arggrammar,log)
         return parse

def parseVmctPeerLink (log, args):
       arggrammar = {}
       arggrammar['pc_no']='-type str'
       parse = utils.parserutils_lib.argsToCommandOptions(args,arggrammar,log)
       return parse

def parseVmctPO (log, args):
       arggrammar = {}
       arggrammar['vpc_id']='-type int'
       arggrammar['port_mode']='-type str'
       arggrammar['fex_associate']='-type int'

       parse = utils.parserutils_lib.argsToCommandOptions(args,arggrammar,log)
       return parse


class configvMCT():
    def __init__(self,vmct_dict,switch_hdl_dict,log):

        self.log=log
        self.result='pass'
        self.vmct_config_dict=vmct_dict
        self.switch_hdl_dict=switch_hdl_dict
        try:
           self.list_of_nodes=self.vmct_config_dict.keys()
        except KeyError:
           err_msg='Error !!! vmct_config_dict has not been defined properly, does not have nodes   \
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

        if 'vpc_domain' in self.vmct_config_dict[node]:
                self.log.info("Now configuring vMCT domain")
                #ns_domain=parseVmctDomain(self.log,self.vmct_config_dict[node]['vpc_domain'])
                retVal.append(configVmctDomain(self.vmct_config_dict[node]['vpc_domain'],hdl,self.log))
        if 'vpc_peer_link' in self.vmct_config_dict[node]:
               self.log.info("Now configuring vMCT Peer Link")
               retVal.append(configVmctPeerLink(self.vmct_config_dict[node]['vpc_peer_link'],hdl,self.log))
        if 'vpc_port_channels' in self.vmct_config_dict[node]:
               self.log.info("Now configuring vMCT Port-Channels")
               retVal.append(configVmctPO(self.vmct_config_dict[node]['vpc_port_channels'],hdl,self.log))
        if 'fabric_link' in self.vmct_config_dict[node]:
              self.log.info("Now configuring vMCT fabric link")
              retVal.append(configVmctFabricLinks(self.vmct_config_dict[node]['fabric_link'],hdl,self.log))
        if 'core_fabric_link' in self.vmct_config_dict[node]:
              self.log.info("Now configuring vMCT Core fabric link")
              retVal.append(configVmctCoreFabricLinks(self.vmct_config_dict[node]['core_fabric_link'],hdl,self.log))

        if failVal in retVal:
            self.log.error('VMCT configuration failed on {0}.'.format(node))
            return 0
        else:
            return 1 


def configVmctDomain(vmct_config_dict,hdl,log):

      log.info(banner('Config VMCT Domain on {0}'.format(hdl)))
      ns_domain=parseVmctDomain(log,vmct_config_dict)

      cfg=''
      cfg+='''vpc domain {0}
           '''.format(ns_domain.domain_id)
      if ns_domain.peer_switch:
              cfg += 'peer-switch\n'
      if ns_domain.peer_gateway:
              cfg += 'peer-gateway\n'      
      if ns_domain.arp_synchronize:
              cfg += 'ip arp synchronize\n'      
      if ns_domain.ipv6_nd_synchronize:
              cfg += 'ipv6 nd synchronize\n'      
      cfg+='''peer-keepalive destination {0} source {1} vrf {2} 
              virtual peer-link destination {3} source {4} dscp 56
           '''.format(ns_domain.peer_keepalive_dst_ipv4_addr,ns_domain.peer_keepalive_src_ipv4_addr,ns_domain.peer_keepalive_vrf,ns_domain.virtual_peer_dst_addr,ns_domain.virtual_peer_src_addr)
      out=hdl.configure(cfg,timeout=150)
      if re.search('error|invalid',out,re.I):
          log.error('Configuring VMCT Domain failed on {0}'.format(hdl))
          return 0
      return 1

def configVmctPeerLink(vmct_config_dict,hdl,log):
      log.info(banner('Config VMCT PeerLink on {0}'.format(hdl)))
      ns=parseVmctPeerLink(log,vmct_config_dict)

      cfg=''
      cfg+='''interface Po{0}
              switchport
              switchport mode trunk
              spanning-tree port type network
              vpc peer-link
           '''.format(ns.pc_no)
      out=hdl.configure(cfg,timeout=150)
      if re.search('error|invalid',out,re.I):
          log.error('Configuring VMCT Peer link failed on {0}'.format(hdl))
          return 0
      return 1


def configVmctPO(vmct_config_dict,hdl,log):
      log.info(banner('Config VMCT PO on {0}'.format(hdl)))
      cfg=''
      for intf in vmct_config_dict:
         ns=parseVmctPO(log,vmct_config_dict[intf])
         cfg+='''interface {0}
                 vpc {1}
              '''.format(intf,ns.vpc_id)
         if ns.port_mode:
            cfg+='''switchport mode {0}
                 '''.format(ns.port_mode)
         if ns.fex_associate:
            cfg+='''fex associate {0}
                 '''.format(ns.fex_associate)
      out=hdl.configure(cfg,timeout=150)
      if re.search('error|invalid',out,re.I):
            log.error('Configuring VMCT PO failed on {0}'.format(hdl))
            return 0
      return 1 
     
def configVmctFabricLinks(vmct_config_dict,hdl,log):
        log.info(banner('Config VMCT FabricLinks on {0}'.format(hdl)))
        cfg=''
        for intf in vmct_config_dict.split(' '):
            cfg+='''interface {0}
                    port-type fabric
                 '''.format(intf)
        out=hdl.configure(cfg,timeout=150)
        if re.search('error|invalid',out,re.I):
            log.error('Configuring VMCT Fabric link config failed on {0}'.format(hdl))
            return 0
        return 1 
 
       
def configVmctCoreFabricLinks(vmct_config_dict,hdl,log):

         log.info(banner('Config VMCT Core FabricLinks on {0}'.format(hdl)))
         cfg=''
         cfg+='''class-map type qos match-all Spine-DSCP56
                 match dscp 56,63
                 policy-map type qos Spine-DSCP56
                 class Spine-DSCP56
                 set qos-group 3 
              '''
         for intf in vmct_config_dict.split(' '):
                cfg+='''interface {0}
                        service-policy type qos input Spine-DSCP56
                     '''.format(intf)
          
         out=hdl.configure(cfg,timeout=150)
         if re.search('error|invalid',out,re.I):
            log.error('Configuring VMCT Core Fabric link config failed on {0}'.format(hdl))
            return 0
         return 1 

def setupConfigVmct(hdl,dut,log,config_dict):
        ''' method to configure vmct defined for each dut under topology'''
        log.info('Inside setupConfigVmct')
        switch_hdl_dict={}
        switch_hdl_dict[dut]=hdl
        if 'vmct_config_dict' in config_dict:
            if dut in config_dict['vmct_config_dict']:
                  obj_vmct=configvMCT(config_dict['vmct_config_dict'],switch_hdl_dict,log)
                  if not obj_vmct.Nodes(dut):
                       return 0
        return 1
 
