
import os
import re
import time
import sys
import argparse
import logging
from common_lib import verify_lib
from common_lib import bringup_lib
from common_lib.bringup_lib import *
from common_lib import utils
from common_lib.utils import *
import ipaddr
import ast

#===================================================================================#
## Create following stimuli
## Initial Bringup
## vPC peer link flap
## vPC keep-alive down
## Flaps vPC member links and verify steady state
## Delete and add member ports for vPCs
## Delete and add vlans
## Type1, 2 consistency checks
## Restart mcecm
## vPC peer reload - primary
## vPC peer reload - secondary
## vPC leaf reload
## multicast IGMP leave 
## SVI shut/no shut
## disable SVI
## FHRP disable/enable
## disable FHRP
## Change timers
##
## verifications 
## STP role on the vPC peers
## MAC table consistency across vPC peers
## IGMP snooping consistency across vPCs
## ping to SVI and FHRP IP address
##  
#===================================================================================#


class configVpc(object):
     """
     Class to bring up vPCs based on the vpc_config dictionary
     item. The constructor configures the vPC domain configs on the vPC peers and
     brings up the vPCs on the peer switches and access layer switch. vpc_config dict looks like below:
     vpc_config:
     node01:
        vpc_domain:
           -domain_id 200 -system_mac 00:01:55:55:55:55 -system_priority 32667 -role_priority 100 -peer_keepalive_src_ipv4_addr 10.10.10.1 -peer_keepalive_dst_ipv4_addr 10.10.10.2 -peer_switch True -peer_gateway True -arp_synchronize True
        vpc_keepalive_interface:
           -interface Eth4/1 -ip_addr 10.10.10.1 -mask 24
        vpc_peer_link:
            -members Eth4/2 -pc_no 101 -native_vlan 2 -vlan 1-10 -mode on
        vpc_port_channels:
            port-channel1:
                -members Eth4/4,Eth3/5 -pc_no 1 -vpc_id 1 -port_mode trunk -native_vlan 1 -vlan 1-10 -mode on
        vlans:
            -id: 2-10 

     """

     def __init__(self,switch_hdl_dict,vpc_config,interface_config_dict,log,*args):
        log.info('Inside __init__ function of configVpc')
        self.result='pass'
        self.log = log
        arggrammar={}
        arggrammar['topo_setup']='-type int' 
        ns=parserutils_lib.argsToCommandOptions(args,arggrammar,log)     
        self.unconfigure = False
        if type(vpc_config) != dict:
             testResult ('fail', 'vpc Config is not in dictionary format',self.log)
             self.result = 'fail'
             return
        else:
             self.vpc_config=vpc_config
        if type(interface_config_dict) != dict:
             testResult ('fail', 'interface Config is not in dictionary format',self.log)
             self.result = 'fail'
             return
        else:
             self.interface_config_dict=interface_config_dict
        if type(switch_hdl_dict) != dict:
             testResult ('fail', 'switch Handles and Names not in dictionary format',self.log)
             self.result = 'fail'
             return
        else:
             self.hdl=switch_hdl_dict
             log.info('Inside __init__ function of configVpc.. Value of switch_hdl_dict is : {0}'.format(self.hdl))
        if len(self.vpc_config.keys()) < 2 and not ns.topo_setup:
             testResult ('fail', 'Total nodes in vpc_config dict needs to be 2 or more',self.log)
             self.result = 'fail'
             return

        self.vpc_nodes = []
        self.vpc_leaf_nodes = []
        for node in self.hdl.keys():
          log.info('The value of node inside __init__ for loop is : {0}'.format(node))
          if node in self.vpc_config.keys():
             if 'vpc_domain' in self.vpc_config[node].keys():
                  self.vpc_nodes.append(node)
                  
             else:
                  self.vpc_leaf_nodes.append(node)
                  
        log.info('Inside __init__ function of configVpc.. Value of vpc_nodes is : {0}'.format(self.vpc_nodes))
        log.info('Inside __init__ function of configVpc.. Value of vpc_leaf_nodes is : {0}'.format(self.vpc_leaf_nodes))

        # Build parameters based on config dict for verification
        self.stp_state_dict = {}
        self.peer_link = {}
        self.peer_link_members = {}
        self.vpc_vlan_list = {}
        self.vpc_port_channels = {}
        self.port_channels = {}
        self.svi_addresses = {}
        for node in self.vpc_nodes:
             log.info('Inside the self.vpc_nodes... The value of node is: {0}'.format(node))
             self.stp_state_dict[node] = {}
             # get port channel name and allowed vlan
             vpc_peer_link_config = self.vpc_config[node]['vpc_peer_link']
             match=re.search('-pc_no\s+({0})'.format(rex.NUM),vpc_peer_link_config)
             self.peer_link[node] = 'Po'+ str(match.group(1))
             #match=re.search('-members\s+((?:{0}[, ]*)+)'.format(rex.INTERFACE_NAME),vpc_peer_link_config)
             #self.peer_link_members[node] = strtoexpandedlist(match.group(1))
             arggrammar={}
             arggrammar['memberList']='-type str -required True' 
             arggrammar['allowed_vlan_list']='-type str' 
             pc_args=interface_config_dict['portchannel'][node]['port-channel{0}'.format(match.group(1))]
             ns_pc=parserutils_lib.argsToCommandOptions(pc_args,arggrammar,log)
             self.peer_link_members[node] = ns_pc.memberList
             self.stp_state_dict[node][self.peer_link[node]] = {}
             vpc_vlan_config = self.vpc_config[node]['vlans']
             match2=re.search('-vlan_id\s+({0})'.format(rex.VLAN_RANGE),vpc_vlan_config)                  
             if match2:
                 vlan_list = strToExpandedList(match2.group(1))
             else:
                 testResult ('fail', 'Couldn"t find allowed vlan on peer-link',self.log)
                 self.result = 'fail'
                 return
             self.vpc_vlan_list[node] = vlan_list
             for vlan in vlan_list:
                  self.stp_state_dict[node][self.peer_link[node]][vlan] = {}
                  self.stp_state_dict[node][self.peer_link[node]][vlan]['state']='FWD'
                  # self.stp_state_dict[node][self.peer_link[node]][vlan]['role']='Desg'
             # get vPCs stp state
             vpc_port_channel_config = self.vpc_config[node]['vpc_port_channels']
             self.vpc_port_channels[node] = {}
             for vpc in vpc_port_channel_config.keys():
                  match1=re.search('-pc_no\s+({0})\s+'.format(rex.NUM),vpc_port_channel_config[vpc])
                  pc_name = 'Po'+ str(match1.group(1))
                  self.vpc_port_channels[node][pc_name] = {}
                  #match=re.search('-vpc_id\s+({0})\s+'.format(rex.NUM),vpc_port_channel_config[vpc])
                  match=re.search('-vpc_id\s+({0})'.format(rex.NUM),vpc_port_channel_config[vpc])
                  vpc_id = match.group(1)
                  self.vpc_port_channels[node][pc_name]['vpc_id'] = vpc_id
                  self.vpc_port_channels[node][pc_name]['members'] = []
                  arggrammar={}
                  arggrammar['memberList']='-type str -required True'
                  arggrammar['allowed_vlan_list']='-type str '
                  pc_args=interface_config_dict['portchannel'][node]['port-channel{0}'.format(match1.group(1))]
                  ns_pc=parserutils_lib.argsToCommandOptions(pc_args,arggrammar,log)     
                  #match=re.search('-members\s+({0})\s+'.format(rex.INTERFACE_RANGE),vpc_port_channel_config[vpc])
                  for member in strToList(ns_pc.memberList):
                       self.vpc_port_channels[node][pc_name]['members'].append(member)
                  self.stp_state_dict[node][pc_name] = {}
                  #match=re.search('-vlan\s+({0})\s+'.format(rex.VLAN_RANGE),vpc_port_channel_config[vpc])
                  #if match:
                  vlan=ns_pc.allowed_vlan_list
                  port_mode = ''
                  match=re.search('-port_mode\s+(\S+)',vpc_port_channel_config[vpc])
                  if match:
                    port_mode=match.group(1)
                  if port_mode=='pvlan_promisc':
                      match=re.search('-pvlan_mapping\s+(\[.*?\])',vpc_port_channel_config[vpc])
                      if match:
                          mapping=ast.literal_eval(match.group(1))[0]
                          primary_vlan=mapping.keys()[0]
                          secondary_vlans=mapping[primary_vlan]
                          vlan=primary_vlan
                  if port_mode=='pvlan_host':
                      match=re.search('-pvlan_host_assoc\s+(\[.*?\])',vpc_port_channel_config[vpc])
                      if match:
                          mapping=ast.literal_eval(match.group(1))[0]
                          primary_vlan=mapping.keys()[0]
                          secondary_vlans=mapping[primary_vlan]
                          vlan=secondary_vlans
                  self.vpc_port_channels[node][pc_name]['allowed_vlans'] = vlan
                  self.stp_state_dict[node][pc_name][vlan] = {}
                  self.stp_state_dict[node][pc_name][vlan]['state']='FWD'
                  # self.stp_state_dict[node][pc_name][vlan]['role']='Desg'

        for node in self.vpc_leaf_nodes:
             self.stp_state_dict[node] = {}
             # Get vPC access nodes port-channels
             port_channel_config = self.vpc_config[node]['port_channels']
             self.port_channels[node] = {}
             self.log.info('port_channel_config: {0}'.format(port_channel_config.keys()))
             for pc in port_channel_config.keys():
                  #match=re.search('-pc_no\s+({0})\s+'.format(rex.NUM),port_channel_config[pc])
                  self.log.info('port_channel_config: {0}'.format(port_channel_config[pc]))
                  match=re.search('-pc_no\s+({0})'.format(rex.NUM),port_channel_config[pc])
                  pc_name = 'Po'+ str(match.group(1))
                  self.port_channels[node][pc_name] = {}
                  self.port_channels[node][pc_name]['members'] = []
                  arggrammar={}
                  arggrammar['allowed_vlan_list']='-type str ' 
                  arggrammar['memberList']='-type str -required True' 
                  pc_args=interface_config_dict['portchannel'][node]['port-channel{0}'.format(match.group(1))]
                  ns_pc=parserutils_lib.argsToCommandOptions(pc_args,arggrammar,log)
                  #match=re.search('-members\s+({0})\s+'.format(rex.INTERFACE_RANGE),port_channel_config[pc])
                  #match=re.search('-members\s+({0})'.format(rex.INTERFACE_RANGE),port_channel_config[pc])
                  #for member in match.group(1).split(','):
                  #     self.port_channels[node][pc_name]['members'].append(member)
                  for member in ns_pc.memberList:
                       self.port_channels[node][pc_name]['members'].append(member)
                  self.stp_state_dict[node][pc_name] = {}
                  #match=re.search('-vlan\s+({0})\s+'.format(rex.VLAN_RANGE),port_channel_config[pc])
                  #match=re.search('-vlan\s+({0})'.format(rex.VLAN_RANGE),port_channel_config[pc])
                  #vlan=match.group(1)
                  vlan = ns_pc.allowed_vlan_list
                  self.stp_state_dict[node][pc_name][vlan] = {}
                  self.stp_state_dict[node][pc_name][vlan]['state']='FWD'
                  # self.stp_state_dict[node][pc_name][vlan]['role']='Root'
        
     def vpcDomainConfig(self,node,args):
         """Method to configure config under vpc domain"""

         arggrammar = {}
         arggrammar['domain_id'] = '-type str -format {0} -required True'.format(rex.NUM)
         arggrammar['system_mac'] = '-type str -format {0}'.format(rex.MACADDR)
         arggrammar['system_priority'] = '-type str -format {0}'.format(rex.NUM)
         arggrammar['role_priority'] = '-type str -format {0}'.format(rex.NUM)
         arggrammar['peer_switch'] = '-type bool -default False'
         arggrammar['peer_gateway'] = '-type bool -default False'
         arggrammar['layer3'] = '-type bool -default False'
         arggrammar['arp_synchronize'] = '-type bool -default False'
         arggrammar['nd_synchronize'] = '-type bool -default False'
         arggrammar['peer_keepalive_dst_ipv4_addr'] = '-type str -format {0} -required True'.format(rex.IPv4_ADDR)
         arggrammar['peer_keepalive_src_ipv4_addr'] = '-type str -format {0} -required True'.format(rex.IPv4_ADDR)
         arggrammar['peer_keepalive_vrf'] = '-type str -format {0} -default default'.format(rex.VRF_NAME)
         parse = utils.parserutils_lib.argsToCommandOptions(args,arggrammar,self.log)
         if self.unconfigure:
              self.hdl[node].configure ('no feature vpc')
              return
         vpc_config = 'feature vpc\nvpc domain {0}\n '.format(parse.domain_id)
         if parse.peer_keepalive_vrf == 'management':
             peer_keepalive_config = 'peer-keepalive destination {0} source {1} '.format(parse.peer_keepalive_dst_ipv4_addr,parse.peer_keepalive_src_ipv4_addr)
         else:
             peer_keepalive_config = 'peer-keepalive destination {0} vrf {1} '\
             .format(parse.peer_keepalive_dst_ipv4_addr,parse.peer_keepalive_vrf)
             if parse.peer_keepalive_src_ipv4_addr:
              peer_keepalive_config += 'source {0} '.format(parse.peer_keepalive_src_ipv4_addr)
         vpc_config += peer_keepalive_config + '\n'
         if parse.peer_switch:
              vpc_config += 'peer-switch\n'
         if parse.peer_gateway:
              vpc_config += 'peer-gateway\n'
         if parse.layer3:
              vpc_config += 'layer3 peer-router\n'
         if parse.arp_synchronize:
              vpc_config += 'ip arp synchronize\n'
         if parse.nd_synchronize:
              vpc_config += 'ipv6 nd synchronize\n'
         if parse.role_priority:
              vpc_config += 'role priority  {0}\n'.format(parse.role_priority)
         self.log.debug ('Apply vpc domain config on {0}'.format(self.hdl[node]._hostname))
         self.hdl[node].configure(vpc_config,timeout=60)
         if parse.system_mac:
              self.hdl[node].sendline('config term')
              self.hdl[node].expect('# $')
              self.hdl[node].sendline('vpc domain {0}'.format(parse.domain_id))
              self.hdl[node].expect('# $')
              self.hdl[node].sendline('system-mac {0}'.format(parse.system_mac))
              prompt_list=['Continue \(yes/no\)\? \[no\]', '# $']
              i=self.hdl[node].expect(prompt_list)
              if i.last_match_index==0:
                   self.hdl[node].sendline('yes')
                   self.hdl[node].expect('# $')
         if parse.system_priority:
              self.hdl[node].sendline('config term')
              self.hdl[node].expect('# $')
              self.hdl[node].sendline('vpc domain {0}'.format(parse.domain_id))
              self.hdl[node].expect('# $')
              self.hdl[node].sendline('system-priority {0}'.format(parse.system_priority))
              prompt_list=['Continue \(yes/no\)\? \[no\]', '# $']
              i=self.hdl[node].expect(prompt_list)
              if i.last_match_index==0: 
                   self.hdl[node].sendline('yes')
                   self.hdl[node].expect('# $')


     def vpcKeepAliveConfig(self,node,args):
         """Method to configure vPC peer-keepalive interface"""

         arggrammar = {}
         arggrammar['interface'] = '-type str -format {0} -required True'.format(rex.INTERFACE_NAME)
         arggrammar['vrf'] = '-type str -format {0}'.format(rex.VRF_NAME)
         arggrammar['ip_addr'] = '-type str -format {0} -required True'.format(rex.IPv4_ADDR)
         arggrammar['mask'] = '-type str -format {0} -required True'.format(rex.NUM)
         parse = utils.parserutils_lib.argsToCommandOptions(args,arggrammar,self.log)
         utils.clearInterfaceConfig(self.hdl[node],self.log,'-interface {0}'.format(parse.interface))
         params = '-interface {0} -ip_address {1} -ip_mask_len {2}'\
             .format(parse.interface,parse.ip_addr,parse.mask)
         if parse.vrf:
              params += ' -vrf {0}'.format(parse.vrf)
         if not self.unconfigure:
              bringup_lib.configureL3Interface(self.hdl[node],self.log,params)                                     

     def vpcVlanConfig(self,node,args):
         """Method to configure vPC peer-keepalive interface"""

         arggrammar = {}
         arggrammar['vlan_id'] = '-type str -required True'
         arggrammar['name'] = '-type str'
         parse = utils.parserutils_lib.argsToCommandOptions(args,arggrammar,self.log)
         if self.unconfigure:
              self.hdl[node].configure('no vlan {0}'.format(parse.vlan_id))
         else:
              self.hdl[node].configure('vlan {0}'.format(parse.vlan_id))
              if parse.name:
                   self.hdl[node].configure('vlan {0}\nname {1}'.format(parse.vlan_id,parse.name))

     def vpcSviConfig(self,node,args):
         """Method to configure vPC peer-keepalive interface"""

         arggrammar = {}
         arggrammar['vlan'] = '-type str -format {0} -required True'.format(rex.VLAN_RANGE)
         arggrammar['ip_start_addr'] = '-type str -required True'
         arggrammar['mask'] = '-type str -default 24'
         arggrammar['incr'] = '-type int -default 1'
         arggrammar['vrf'] = '-type str'
         parse = utils.parserutils_lib.argsToCommandOptions(args,arggrammar,self.log)
         if self.unconfigure:
              self.hdl[node].configure('no int vlan {0}'.format(parse.vlan))
              return
         vlan_list = utils.strToExpandedList(parse.vlan)
         # might use configureSvi later
         ip_addr = ipaddr.IPv4Address(parse.ip_start_addr)
         config  = 'feature interface-vlan'
         for svi in vlan_list:
              if parse.vrf:
                   config += '\ninterface vlan{0}\nvrf member {1}\nip address {2}/{3}\nno shut'.\
                       format(svi,parse.vrf,ip_addr,parse.mask)
              else:
                   config += '\ninterface vlan{0}\nip address {1}/{2}\nno shut'.\
                       format(svi,ip_addr,parse.mask)
              # incr ip address for next use
              ip_addr += parse.incr   
              
         self.hdl[node].configure(config)
              

     def vpcPeerLinkConfig(self,node,args):
         """Method to configure vPC peer-links"""
         
         arggrammar = {}
         arggrammar['pc_no'] = '-type str -format {0} -required True'.format(rex.NUM)
         parse = utils.parserutils_lib.argsToCommandOptions(args,arggrammar,self.log)
         # Configure Port-channel config
         # lacp config should be handled outside at global feature config - ToDo
         # This is added for sanity reqmt, unconfigure any present info
         #if not self.unconfigure:
         #     self.hdl[node].configure ('no interface Po{0}'.format(parse.pc_no))
         #if parse.mode != 'on':
         #     self.hdl[node].configure('feature lacp')
         #if not self.unconfigure:
         #     for interface in parse.members.split(','):
         #          # Configure Port-channel config
         #          args = '-interface {0} -mode {1} -pc_no {2} -port_status_verify False'\
         #              .format(interface,parse.mode,parse.pc_no)
         #          createPortChannel(self.hdl[node],self.log,args)
         # Configure vpc peer link and associated params
         pc_config = 'interface Po{0}\nswitchport\nswitchport mode trunk\nvpc peer-link\n'.format(parse.pc_no)
         pc_unconfig = 'interface Po{0}\nno switchport'.format(parse.pc_no)
         '''
         if pc_parse.native_vlan_list:
              pc_config += 'switchport trunk native vlan {0}\n'.format(pc_parse.native_vlan_list)
         if pc_parse.allowed_vlan_list:
              pc_config += 'switchport trunk allowed vlan {0}\n'.format(pc_parse.allowed_vlan_list)
         '''
         if (self.unconfigure):
              self.hdl[node].configure (pc_unconfig)
              #for interface in parse.members.split(','):
              #     deletePortChannel(self.hdl[node],self.log,'-interface {0} -pc_no {1}'\
              #                            .format(interface,parse.pc_no))
              self.hdl[node].configure ('no interface Po{0}'.format(parse.pc_no))

         else:
              self.hdl[node].configure (pc_config)

     def vpcPortChannelConfig(self,node,args):
         """Method to configure vPC port-channels"""

         arggrammar = {}
         #arggrammar['members'] = '-type str -required True'
         arggrammar['native_vlan'] = '-type str -format {0}'.format(rex.NUM)
         arggrammar['mode'] = '-type str -default on'
         arggrammar['port_mode'] = '-type str -choices ["trunk","access","pvlan_promisc","pvlan_host"] -default trunk'.format(rex.NUM)
         arggrammar['pc_no'] = '-type str -format {0} -required True'.format(rex.NUM)
         arggrammar['vpc_id'] = '-type str -format {0}'.format(rex.NUM)
         arggrammar['vlan'] = '-type str'
         arggrammar['fex_peer'] = '-type bool -default False'
         arggrammar['pvlan_mapping']='-type list' #Format: [{10:'11-13,15'}]
         arggrammar['pvlan_host_assoc']='-type list' #Format: [{10:'11-13,15'}]
 
         parse = utils.parserutils_lib.argsToCommandOptions(args,arggrammar,self.log)
         # lacp config should be handled outside at global feature config - ToDo
         # This is added for sanity reqmt
         #if not self.unconfigure:
         #     self.hdl[node].configure ('no interface Po{0}'.format(parse.pc_no))
         if parse.mode != 'on':
              self.hdl[node].configure('feature lacp')

         #if not self.unconfigure:
         #     for interface in parse.members.split(','):
         #          # Configure Port-channel config
         #          args = '-interface {0} -mode {1} -pc_no {2} -port_status_verify False'\
         #              .format(interface,parse.mode,parse.pc_no)
         #          if parse.fex_peer:
         #               args += ' -bpdufilter True'
         #          createPortChannel(self.hdl[node],self.log,args)
         # Configure vpc port-channels
         if parse.port_mode == 'pvlan_promisc':
             parse.port_mode='private-vlan promiscuous'
         if parse.port_mode == 'pvlan_host':
             parse.port_mode='private-vlan host'
         pc_config = 'interface Po{0}\nswitchport\nswitchport mode {1}\n'.\
             format(parse.pc_no,parse.port_mode)
         pc_unconfig = 'interface Po{0}\nno switchport'.format(parse.pc_no)
         if parse.vpc_id:
              pc_config += 'vpc {0}\n'.format(parse.vpc_id)
         if parse.native_vlan:
              pc_config += 'switchport trunk native vlan {0}\n'.format(parse.native_vlan)
         if parse.port_mode == 'trunk':
              if parse.vlan:
                  pc_config += 'switchport trunk allowed vlan {0}\n'.format(parse.vlan)
         elif parse.port_mode == 'private-vlan promiscuous':
              if parse.pvlan_mapping:
                  mapping=parse.pvlan_mapping[0]
                  primary_vlan=mapping.keys()[0]
                  secondary_vlans=mapping[primary_vlan]
                  pc_config += 'switchport private-vlan mapping {0} {1}\n'''.format(primary_vlan,secondary_vlans)
         elif parse.port_mode == 'private-vlan host':
              if parse.pvlan_host_assoc:
                  mapping=parse.pvlan_host_assoc[0]
                  primary_vlan=mapping.keys()[0]
                  secondary_vlans=mapping[primary_vlan]
                  pc_config += 'switchport private-vlan host-association {0} {1}'''.format(primary_vlan,secondary_vlans)
         else:
              if parse.vlan:
                  pc_config += 'switchport access vlan {0}\n'.format(parse.vlan)
         if (self.unconfigure):
              self.hdl[node].configure (pc_unconfig)
              for interface in parse.members.split(','):
                   #deletePortChannel(self.hdl[node],self.log,'-interface {0} -pc_no {1}'\
                   #                       .format(interface,parse.pc_no))
                   #self.hdl[node].configure('interface {0}\n shut'.format(interface))
                   print('DUMMY')
              self.hdl[node].configure ('no interface Po{0}'.format(parse.pc_no))
         else:
              self.hdl[node].configure (pc_config)

     def vpcPeersAndLeafConfig(self):
          """Method to configure all vpc and leaf node related configs"""
          for node in self.vpc_config.keys():
               # Configuring the vPC domain configs ..
               self.log.info('Configuring the vPC domain configs on node:{0}'.format(node))
               if 'vpc_domain' in self.vpc_config[node].keys():
                    self.vpcDomainConfig(node,self.vpc_config[node]['vpc_domain'])
               if 'vpc_keepalive_interface' in self.vpc_config[node].keys():
                    self.vpcKeepAliveConfig(node,self.vpc_config[node]['vpc_keepalive_interface'])
               if 'vpc_peer_link' in self.vpc_config[node].keys():
                    self.vpcPeerLinkConfig(node,self.vpc_config[node]['vpc_peer_link'])
               # Configure Leaf nodes (do this before vpc, just in case this is fex_peer)
               if 'port_channels' in self.vpc_config[node].keys():
                    for pc in self.vpc_config[node]['port_channels'].keys():
                         self.vpcPortChannelConfig(node,self.vpc_config[node]['port_channels'][pc])
               # Configure vPC port-channels
               if 'vpc_port_channels' in self.vpc_config[node].keys():
                    for pc in self.vpc_config[node]['vpc_port_channels'].keys():
                         self.vpcPortChannelConfig(node,self.vpc_config[node]['vpc_port_channels'][pc])
               # Configure vlans
               if 'vlans' in self.vpc_config[node].keys():
                    self.vpcVlanConfig(node,self.vpc_config[node]['vlans'])
               # Configure Svis
               if 'svi_config' in self.vpc_config[node].keys():
                    self.vpcSviConfig(node,self.vpc_config[node]['svi_config'])

     def vpcPeersAndLeafUnconfig(self):
          """Method to unconfigure all vpc related configs"""

          # unconfigure uses same methods except self.unconfigure is set to true
          self.unconfigure = True
          self.vpcPeersAndLeafConfig()
          self.unconfigure = False

class verifyVpc(configVpc):
     """
     Class to verify vPCs and related verification. This is based on vpc_config dictionary
     item. Verification is for vPC nodes and access or vPC leaf nodes.
     """

     
     def __init__(self,switch_hdl_dict,vpc_config,interface_config_dict,log,*args):
          
          configVpc.__init__(self,switch_hdl_dict,vpc_config,interface_config_dict,log,*args)
                    
     def verifyVpcEnabled(self):
          
          self.log.info('Verify vpc is enabled on vPC nodes')
          for node in self.vpc_nodes:
               if getFeatureState(self.hdl[node],self.log,'-feature vpc') != 'enabled':
                    testResult('fail','vpc feature not enabled on {0}'.format(self.hdl[node]._hostname),self.log)
                    self.result = 'fail'

     def verifyVpcPeerKeepAliveVrf(self):

          self.log.info('Verify keepalive on vPC nodes')
          for node in self.vpc_nodes:
               vpc_dict = getShowVpcDict(self.hdl[node],self.log)
               if not vpc_dict:
                    testResult('fail','vpc peer not alive or adjacency not formed {0}'\
                                    .format(self.hdl[node]._hostname),self.log)
                    self.result= 'fail'
                    return
               elif (vpc_dict['vPC_keep-alive_status'] != 'peer_is_alive'):
                    testResult('fail','vpc peer not alive on {0},expected:peer_is_alive,found:{1}'\
                                    .format(self.hdl[node]._hostname,vpc_dict['vPC_keep-alive_status']),self.log)
                    self.result = 'fail'
               elif (vpc_dict['Peer_status'] != 'peer_adjacency_formed_ok') :
                    testResult('fail','vpc peer not alive on {0},expected:peer_adjacency_formed_ok,found:{1}'\
                                    .format(self.hdl[node]._hostname,vpc_dict['Peer_status']),self.log)
                    self.result = 'fail'
          #show vpc peer-keepalive check - Todo
          #verifyInterfaceStatus(self.hdl[node],self.log,'-interfaces {0} -status up'.format(keepalive_interface)

     def verifyVpcPeerLink(self):
          #verify vPC peer link status"""

          self.log.info('Verify vpc peer link status on on vPC nodes')
          for node in self.vpc_nodes:
               vpc_dict = getShowVpcDict(self.hdl[node],self.log)
               if not vpc_dict:
                    testResult('fail','Error in getting <show vpc brief> on {0}'\
                                    .format(self.hdl[node]._hostname),self.log)
                    self.result= 'fail'
                    return
               elif (vpc_dict['Peer-link_Status'] != 'up'):
                    testResult('fail','Peer-link not up on {0},expected:up,found:{1}'\
                                    .format(self.hdl[node]._hostname,vpc_dict['Peer-link_Status']),self.log)
                    self.result = 'fail'
               peer_link=re.search('Po({0})'.format(rex.NUM),self.peer_link[node],re.I).group(1)
               if (verify_lib.verifyPortChannelMembers(self.hdl[node],self.log,'-pc_list {0}'\
                                                            .format(peer_link)).result == 'fail'):
                    testResult('fail','Some peer-link members not up on {0}'.format(self.hdl[node]._hostname),self.log)
                    self.result = 'fail'
               # verify allowed vlan on Peer Link
               peer_link_active_vlans = set(strToExpandedList(vpc_dict['Peer-link_Active_vlans']))
               peer_link_allowed_vlans = set(self.stp_state_dict[node][self.peer_link[node]].keys())
               if (compareVars(peer_link_allowed_vlans, peer_link_active_vlans,self.log) == 'fail'):
                    testResult('fail','Allowed vlan on  peer-link not as expected,expected:{0},found:{1} on {2}'\
                                    .format(peer_link_allowed_vlans,peer_link_active_vlans,\
                                                 self.hdl[node]._hostname),self.log)
                    self.log.debug ('Difference of allowed vs expected is: {0}'\
                                         .format(list(peer_link_allowed_vlans - peer_link_active_vlans)))
                    self.result ='fail'
                       
               
               

     def verifyVpcConfigConsistency(self):
          """verify vPC config consistency result"""

          self.log.info('Verify vpc Config Consistency on vPC nodes')
          for node in self.vpc_nodes:
               vpc_dict = getShowVpcDict(self.hdl[node],self.log)
               if not vpc_dict:
                    testResult('fail','Error in getting <show vpc brief> on {0}'\
                                    .format(self.hdl[node]._hostname),self.log)
                    self.result= 'fail'
                    return
               elif (vpc_dict['Configuration_consistency_status'] != 'success'):
                    testResult('fail','Configuration consistency fail on {0},expected:success,found:{1}'\
                                    .format(self.hdl[node]._hostname,vpc_dict['Configuration_consistency_status']),\
                                    self.log)
                    self.result = 'fail'

     def verifyVpcPerVlanConsistency(self):
          """verify vPC per-vlan consistency result"""

          self.log.info('Verify vpc peer link status on on vPC nodes')
          for node in self.vpc_nodes:
               vpc_dict = getShowVpcDict(self.hdl[node],self.log)
               if not vpc_dict:
                    testResult('fail','Error in getting <show vpc brief> on {0}'\
                                    .format(self.hdl[node]._hostname),self.log)
                    self.result= 'fail'
                    return
               elif vpc_dict['Per-vlan_consistency_status'] != 'success':
                    testResult('fail','Per vlan confistency fail on {0},expected:success,found:{1}'\
                                    .format(self.hdl[node]._hostname,vpc_dict['Per-vlan_consistency_status']),self.log)
                    self.result = 'fail'

     def verifyVpcType2Consistency(self):        
          """verify vPC type2 consistency result"""

          self.log.info('Verify vpc peer link status on on vPC nodes')
          for node in self.vpc_nodes:
               vpc_dict = getShowVpcDict(self.hdl[node],self.log)
               if not vpc_dict:
                    testResult('fail','Error in getting <show vpc brief> on {0}'\
                                    .format(self.hdl[node]._hostname),self.log)
                    self.result= 'fail'
                    return
               elif vpc_dict['Type-2_consistency_status'] != 'success':
                    testResult('fail','Type2 consistency fail on {0}'\
                                    .format(self.hdl[node]._hostname,vpc_dict['Type-2_consistency_status']),self.log)
                    self.result = 'fail'

     def verifyVpcPortChannels(self):        
          """Method to verify all vpc port channel/members on access node are up"""

          self.log.info('Verify vpc Port Channel status on vPC nodes')
          for node in self.vpc_nodes:
               for vpc in self.vpc_port_channels[node].keys():
                    if (verify_lib.verifyPortChannelMembers(self.hdl[node],self.log,'-pc_list {0}'\
                                                                 .format(vpc)).result == 'fail'):
                         testResult('fail','verify vPC port channel failed on {0}'.\
                                         format(self.hdl[node]._hostname),self.log)
                         self.result = 'fail'
                    # verify allowed vlan on this vPC
                    vpc_dict =  getVpcDict(self.hdl[node],self.log)
                    vpc_id = self.vpc_port_channels[node][vpc]['vpc_id']
                    if vpc_dict[vpc_id]['Active_vlans'] == '-':
                         testResult('fail','No Active_vlans found on vPC:{0}/{1}'\
                                         .format(vpc,self.hdl[node]._hostname),self.log)
                         self.result = 'fail'
                         return
                    active_vlans = set(strToExpandedList(vpc_dict[vpc_id]['Active_vlans']))
                    allowed_vlans = set(strToExpandedList(self.vpc_port_channels[node][vpc]['allowed_vlans']))
                    if (allowed_vlans != active_vlans):
                         testResult('fail','Allowed vlan on  vPC:{0} not as expected,expected:{1},found:{2} on {3}'\
                                         .format(vpc,allowed_vlans,active_vlans,self.hdl[node]._hostname),self.log)
                         self.log.debug ('Difference of allowed vs expected on vPC:{0},node{1} is: {2}'\
                                              .format(vpc,self.hdl[node]._hostname,list(allowed_vlans - active_vlans)))
                         self.result ='fail'
                       


     def verifyVpcLeafPortChannels(self):        
          """Method to verify all peer port channel/members on access node are up"""

          self.log.info('Verify vpc peer link status on on vPC nodes')
          for node in self.vpc_leaf_nodes:
               for pc in self.port_channels[node].keys():
                    pc_id = re.search('Po({0})'.format(rex.NUM),pc,re.I).group(1)
                    if (verify_lib.verifyPortChannelMembers(self.hdl[node],self.log,'-pc_list {0}'\
                                                                 .format(pc_id)).result == 'fail'):
                         testResult('fail','verify vPC port channel failed on {0}'.\
                                         format(self.hdl[node]._hostname),self.log)
                         self.result = 'fail'

     def verifyVpcMacSync(self):        
          """MAC table sync between vPC peers"""

          if (verify_lib.verifyVpcMacConsistencyBetweenPeers(\
                    self.hdl[self.vpc_nodes[0]],self.hdl[self.vpc_nodes[1]],self.log).result == 'fail'):
               testResult('fail','MAC consistency failure between vPC peers',self.log)
               self.result = 'fail'

     def verifyVpcL3PeerRouter(self):
          ''' Method the check the status of Layer3 peer router for L3OverVpc'''
 
          self.log.info('Verify  Layer3 peer router for L3OverVpc')
          for node in self.vpc_nodes:
               vpc_dict = getShowVpcDict(self.hdl[node],self.log)
               if not vpc_dict:
                    testResult('fail','Error in getting <show vpc brief> on {0}'\
                                    .format(self.hdl[node]._hostname),self.log)
                    self.result= 'fail'
                    return
               elif vpc_dict['Layer3_Peer-router'] != 'Enabled':
                    testResult('fail','Layer3 Peer router is not enabled on {0}'\
                              .format(self.hdl[node]._hostname),self.log)
                    self.result= 'fail'
                          
     def verifyVpcAll(self):
          # Wrapper for all methods
          self.verifyVpcEnabled()
          self.verifyVpcPeerKeepAliveVrf()
          self.verifyVpcPeerLink()
          self.verifyVpcConfigConsistency()
          self.verifyVpcPerVlanConsistency()
          self.verifyVpcType2Consistency()
          self.verifyVpcConsistencies()
          self.verifyVpcMacSync()

     def verifyVpcAllWithL3PeerRouter(self):
          # Wrapper for all methods
          self.verifyVpcEnabled()
          self.verifyVpcPeerKeepAliveVrf()
          self.verifyVpcPeerLink()
          self.verifyVpcConfigConsistency()
          self.verifyVpcPerVlanConsistency()
          self.verifyVpcType2Consistency()
          self.verifyVpcConsistencies()
          self.verifyVpcMacSync()
          self.verifyVpcL3PeerRouter()


     def verifyVpcRunningConfig(self):
          #Check <show run vpc> has all details as given in vpc_config dict
          pass

     def verifyVpcConsistencies(self):
          """verify vPC consistency for different parameters"""

          for node in self.vpc_nodes:
               if (verify_lib.verifyVpcConsistencyParameters(self.hdl[node],self.log,'-flag global').result == 'fail'):
                    testResult('fail','Global consistency check fail for {0}'.\
                                    format(self.hdl[node]._hostname),self.log)
                    self.result = 'fail'
               if (verify_lib.verifyVpcConsistencyParameters(self.hdl[node],self.log,'-flag vlans').result == 'fail'):
                    testResult('fail','Vlan consistency check fail for {0}'.\
                                    format(self.hdl[node]._hostname),self.log)
                    self.result = 'fail'
               for pc in self.stp_state_dict[node].keys():
                    if (verify_lib.verifyVpcConsistencyParameters(\
                              self.hdl[node],self.log,'-flag interface -interface {0}'.\
                                                            format(pc)).result == 'fail'):
                         testResult('fail','Consistency check fail for {0} on {1}'.\
                                         format(pc,self.hdl[node]._hostname),self.log)
                         self.result = 'fail'


     def verifyVpcStpState(self):
          # All vPC links and peer-link on vpc nodes should be in FWD state
          # verify STP state for each node
          for node in self.vpc_config.keys():
               for pc_name in self.stp_state_dict[node].keys():
                    obj=verify_lib.verifySpanningTreePortState(\
                         self.hdl[node],self.log,'-interface {0}'.format(pc_name),**self.stp_state_dict[node][pc_name])
                    if (obj.result == 'fail'):
                         testResult('fail','Failed: STP State verification for node:{0}'\
                                         .format(self.hdl[node]._hostname),self.log)
                         self.result = 'fail'


     def verifyVpcUnconfigured(self):
          
          self.log.info('Verify vpc is disabled on vPC nodes')
          for node in self.vpc_nodes:
               if getFeatureState(self.hdl[node],self.log,'-feature vpc') != 'disabled':
                    testResult('fail','vpc feature still enabled on {0}'.format(self.hdl[node]._hostname),self.log)
                    self.result = 'fail'
               else:
                    testResult('pass','vpc feature disabled on {0}'.format(self.hdl[node]._hostname),self.log)


#======================================================================================#
# These will be moved to stimuli Class
#======================================================================================#

class stimuliVpcRandomVpcFlap(configVpc):


   def __init__( self, vpc_config_dict, switch_dict, switch_hdl_dict, log ):

        from random import choice

        self.result='pass'
        self.result_message='stimuli stimuliVpcRandomVpcFlap  - passed'
        self.vpc_config_dict=vpc_config_dict
        self.switch_dict=switch_dict
        self.switch_hdl_dict=switch_hdl_dict
        self.log=log

        self.log.info('vPC stimuli - randomly flap a vPC link ..')
        try:
             list_of_nodes=self.vpc_config_dict.keys()
        except KeyError:
             self.result='fail'
             self.log.error('vpc_config_dict not defined properly, does not have any    \
                keys ..')

        for node in list_of_nodes:

             hdl=self.switch_hdl_dict[node]
        
             if 'vpc_peer_configs' in self.vpc_config_dict[node].keys():
                  vpc_list=self.vpc_config_dict[node]['vpc_peer_configs'].keys()

                  #Randomly choose a vPC
                  vpc_link=choice(vpc_list)

                  sw_cmd='''interface {0}
                            shut
                            no shut'''.format(vpc_link)

                  hdl.configure(sw_cmd)

                  show_cmd='show interface {0} | excl admin'.format(vpc_link)
                  largs='-show_command {0} -expected_pattern {1}'.format( show_cmd,     \
                     'is Up' )
                  test_result=hdl.loopUntil(l_args)
                  self.result=test_result['result']
                  self.result_msg=test_result['msg']
                  if re.search( 'fail', self.result, flags=re.I ):
                      err_msg='vPC link {0} failed to come up after flap on             \
                         switch {1}'.format( vpc_link, node )
                      self.log.error(err_msg)
                      return




#======================================================================================#
# This will be moved to stimuli Class 
#======================================================================================#

class stimuliVpcFlapAllVpcs(configVpc):


   def __init__( self, vpc_config_dict, switch_dict, switch_hdl_dict, log ):

        from random import choice

        self.result='pass'
        self.result_message='stimuli stimuliVpcFlapAllVpcs  - passed'
        self.vpc_config_dict=vpc_config_dict
        self.switch_dict=switch_dict
        self.switch_hdl_dict=switch_hdl_dict
        self.log=log

        try:
             list_of_nodes=self.vpc_config_dict.keys()
        except KeyError:
             self.result='fail'
             self.log.error('vpc_config_dict not defined properly, does not have any    \
                keys ..')

        self.log.info('vPC stimuli - Flapping all vPC links ..')

        for node in list_of_nodes:

             hdl=self.switch_hdl_dict[node]

             if 'vpc_peer_configs' in self.vpc_config_dict[node].keys():
                  vpc_list=self.vpc_config_dict[node]['vpc_peer_configs'].keys()

                  for vpc_link in vpc_list:

                       sw_cmd='''interface {0}
                            shut
                            no shut'''.format(vpc_link)
                       hdl.configure(sw_cmd)

        # Verify the vPC links are back in Up state.
        for node in list_of_nodes:

             hdl=self.switch_hdl_dict[node]

             if 'vpc_peer_configs' in self.vpc_config_dict[node].keys():
                  vpc_list=self.vpc_config_dict[node]['vpc_peer_configs'].keys()

                  for vpc_link in vpc_list:

                       show_cmd='show interface {0} | excl admin'.format(vpc_link)
                       largs='-show_command {0} -expected_pattern {1} -sleep_interval   \
                          {2} -max_iterations {3}'.format( show_cmd, 'is Up',           \
                          10, 20 )
                       test_result=hdl.loopUntil(l_args)
                       self.result=test_result['result']
                       self.result_msg=test_result['msg']
                       if re.search( 'fail', self.result, flags=re.I ):
                           err_msg='vPC link {0} failed to come up after flap on        \
                           switch {1}'.format( vpc_link, node )
                           self.log.error(err_msg)
                           return

def parseVpcDomain (log, args):
         arggrammar = {}
         arggrammar['domain_id'] = '-type str -format {0} -required True'.format(rex.NUM)
         arggrammar['system_mac'] = '-type str -format {0}'.format(rex.MACADDR)
         arggrammar['system_priority'] = '-type str -format {0}'.format(rex.NUM)
         arggrammar['role_priority'] = '-type str -format {0}'.format(rex.NUM)
         arggrammar['peer_switch'] = '-type bool -default False'
         arggrammar['peer_gateway'] = '-type bool -default False'
         arggrammar['layer3'] = '-type bool -default False'
         arggrammar['arp_synchronize'] = '-type bool -default False'
         arggrammar['peer_keepalive_dst_ipv4_addr'] = '-type str -format {0} -required True'.format(rex.IPv4_ADDR)
         arggrammar['peer_keepalive_src_ipv4_addr'] = '-type str -format {0} -required True'.format(rex.IPv4_ADDR)
         arggrammar['peer_keepalive_vrf'] = '-type str -format {0} -default default'.format(rex.VRF_NAME)
         parse = utils.parserutils_lib.argsToCommandOptions(args,arggrammar,log)
         return parse

def parseVpcPeerLink (log, args):
       arggrammar = {}
       arggrammar['pc_no']='-type str'
       parse = utils.parserutils_lib.argsToCommandOptions(args,arggrammar,log)
       return parse
 
def l3PeerRouterEnableDisable(switch_hdl_dict,node,vpcconfigdict,action,log):
       
           if node in vpcconfigdict.keys():
                  if 'vpc_domain' in  vpcconfigdict[node].keys():
                       hdl=switch_hdl_dict[node]
                       parse=parseVpcDomain(log,vpcconfigdict[node]['vpc_domain'])
                       if action == 'disable':
                              cmd='''vpc domain {0}
                                     no layer3 peer-router
                                  '''.format(parse.domain_id)
                       elif action == 'enable':
                               cmd='''vpc domain {0}
                                      layer3 peer-router
                                   '''.format(parse.domain_id)
                             
                  hdl.configure(cmd)

def verifyVpcL3PeerRouter(switch_hdl_dict,node,vpcconfigdict,action,log):
          ''' Method the check the status of Layer3 peer router for L3OverVpc'''
 
          if  node in vpcconfigdict.keys():
               hdl=switch_hdl_dict[node]
               vpc_dict = getShowVpcDict(hdl,log)
               if action == 'enable':
                    if vpc_dict['Layer3_Peer-router'] != 'Enabled':
                        log.error('fail','Layer3 Peer router is not Enable on {0}'\
                              .format(hdl._hostname),log)
                        return 0
               elif action == 'disable':
                    if vpc_dict['Layer3_Peer-router'] != 'Disabled':
                         log.error('fail','Layer3 Peer router is not Disabled on {0}'\
                              .format(hdl._hostname),log)
                         return 0
               return 1

def shutUnshutVpcDomain(switch_hdl_dict,node,vpcconfigdict,action,log):
       
           if node in vpcconfigdict.keys():
                  if 'vpc_domain' in  vpcconfigdict[node].keys():
                       hdl=switch_hdl_dict[node]
                       parse=parseVpcDomain(log,vpcconfigdict[node]['vpc_domain'])
                       if action == 'shut':
                           cmd='''vpc domain {0}
                                  shut
                               '''.format(parse.domain_id)
                       elif action == 'noshut':
                           cmd='''vpc domain {0}
                                  no shut
                               '''.format(parse.domain_id)
                  hdl.configure(cmd)

def flapVpcPeerlink(switch_hdl_dict,vpcconfigdict,log):
           for node in vpcconfigdict.keys():
                if 'vpc_peer_link' in vpcconfigdict[node].keys():
                     parse = parseVpcPeerLink(log,vpcconfigdict[node]['vpc_peer_link'])
                     config= 'interface Po{0}\nshut\nno shut\n'.format(parse.pc_no)
                     switch_hdl_dict[node].configure(config)


def changeVpcRolePriority(switch_hdl_dict,node,vpcconfigdict,log,args):
          
          arggrammar={}
          arggrammar['priority']='-type int -required True'
          parse = utils.parserutils_lib.argsToCommandOptions(args,arggrammar,self.log)

          if node in vpcconfigdict.keys():
                   if 'vpc_domain' in  vpcconfigdict[node].keys():
                       hdl=switch_hdl_dict[node]
                       vpc=parseVpcDomain(log,vpcconfigdict[node]['vpc_domain'])
                    
                       cmd='''vpc domain {0}
                              role priority {1}
                           '''.format(vpc.domain_id,parse.priority)
                   hdl.configure(cmd)


                

