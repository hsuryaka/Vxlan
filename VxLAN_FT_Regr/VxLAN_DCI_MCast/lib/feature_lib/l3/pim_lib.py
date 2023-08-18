import os
import re
import time
import sys
from common_lib import parserutils_lib
import logging
from common_lib import verify_lib
from common_lib import bringup_lib
from common_lib.bringup_lib import *
from common_lib import utils
from common_lib.utils import *
import ipaddr


#======================================================================================#
# Define the PIM parse methods
#======================================================================================#

def parseInterfaceIpv4Configs(args,log):

    arggrammar={} 
    arggrammar['ipv4_addr']='-type str'
    arggrammar['ipv4_prf_len']='-type str'
    arggrammar['flags']=['ignore_unknown_key']
    return parserutils_lib.argsToCommandOptions( args, arggrammar, log)


def parsePimStaticRpConfigs(args, log):

    arggrammar={} 
    arggrammar['prefix_list']='-type str'
    arggrammar['route_map']='-type str'
    arggrammar['override_flag']='-type str -choices ["YES","NO"]'
    arggrammar['bidir_flag']='-type str -choices ["YES","NO"]'
    arggrammar['group_list']='-type str'
    arggrammar['vrf']='-type str -default None'
    return parserutils_lib.argsToCommandOptions( args, arggrammar, log)
    
def parsePimBsrCandidateConfigs(args,log):

    arggrammar={}
    arggrammar['interface']='-type str'
    arggrammar['hash_len']='-type str -default 30'   
    arggrammar['priority']='-type str -default 64'   
    return parserutils_lib.argsToCommandOptions( args, arggrammar, log)



def parsePimBsrRpCandidateConfigs(args,log):

    arggrammar={}
    arggrammar['group_list']='-type str'
    arggrammar['route_map']='-type str'
    arggrammar['interval']='-type str -default 60'
    arggrammar['priority']='-type str -default 192'
    arggrammar['interface']='-type str'
    return parserutils_lib.argsToCommandOptions( args, arggrammar, log)


def parsePimAutoRpMappingAgentConfigs(args,log):

    arggrammar={}
    arggrammar['interface']='-type str'
    arggrammar['route_map']='-type str'
    arggrammar['mapping_agent_policy']='-type str'
    arggrammar['scope']='-type str -default 32'
    return parserutils_lib.argsToCommandOptions( args, arggrammar, log)


def parsePimAutoRpRpCandidateConfigs(args,log):

    arggrammar={}
    arggrammar['group_list']='-type str'
    arggrammar['route_map']='-type str'
    arggrammar['interval']='-type str -default 60'
    arggrammar['scope']='-type str -default 32'
    return parserutils_lib.argsToCommandOptions( args, arggrammar, log)

def parsePimAnycastRpCandidateConfigs(args,log):

    arggrammar={}
    arggrammar['rp_candidate']='-type str'
    arggrammar['rp_set']='-type str'
    return parserutils_lib.argsToCommandOptions( args, arggrammar, log)
    

def parsePimInterfaceConfigs(args,log):

    arggrammar={}
    arggrammar['hello_interval']='-type str -default 30000'
    arggrammar['dr_priority']='-type str -default 1'
    arggrammar['dr_delay']='-type str -default 3'
    arggrammar['border_flag']='-type str -choices ["YES","NO"] -default "NO"'
    arggrammar['join_prune_route_map']='-type str '
    arggrammar['jp_policy']='-type str -default None'
    arggrammar['hello_authentication']='-type str '
    arggrammar['hello_interval']='-type str '
    arggrammar['encryption_key']='-type str'
    arggrammar['join_prune_route_map']='-type str'
    arggrammar['neighbor_policy']='-type str'
    arggrammar['peer_device']='-type str -required True'
    arggrammar['igmp_version']='-type int -default 2'
    arggrammar['peer_interface']='-type str -required True'
    arggrammar['loopback_interface']='-type str -choices ["YES","NO"] -default "NO"'
    arggrammar['authentication_flag']='-type str -choices ["YES","NO"] -default "NO"'
    return parserutils_lib.argsToCommandOptions( args, arggrammar, log)




#======================================================================================#
# configPim - Class to configure and verify PIM configs - Interface, RP etc. based on the
# pim_config_dict dictionary defined in the topology file..
#======================================================================================#


class configPim(object):

    def __init__( self, interface_dict, pim_config_dict, switch_hdl_dict, log, *args ):
 
        arggrammar={}
        arggrammar['dut']='-type str -default all'
        arggrammar['verify_interval']='-type int -default 6'
        arggrammar['verify_iterations']='-type int -default 5'
        arggrammar['noconfig']='-type bool -default False'
        parse_output=parserutils_lib.argsToCommandOptions(args,arggrammar,log)
        self.dut=parse_output.dut
        self.verify_iterations=parse_output.verify_iterations
        self.verify_interval=parse_output.verify_interval
        self.noconfig=parse_output.noconfig
     

        self.log=log
        self.result='pass'
        self.log.info('testPim starts: Switch configure and verify PIM configs')
        #parse L3 interface from interface dict and store it as self.interface_dict
        tmp={}
        for node in interface_dict['ethernet'].keys():
            tmp[node]={}
            for int in interface_dict['ethernet'][node].keys():
                ipv4_info=parseInterfaceIpv4Configs(interface_dict['ethernet'][node][int],self.log)
                if not ipv4_info.ipv4_addr:
                    continue
                int = normalizeInterfaceName(self.log,int)
                tmp[node][int]={}
                tmp[node][int]['ipv4_addr']=ipv4_info.ipv4_addr
                tmp[node][int]['ipv4_prf_len']=ipv4_info.ipv4_prf_len
        #interface_dict:
        #{'node02': {'Vlan1': {'ipv4_addr': '10.0.0.6', 'ipv4_mask': '255.255.255.0'}, 'Vlan2': {'ipv4_addr': '20.0.0.6', 'ipv4_mask': '255.255.255.0'}, 'Eth4/45': {'ipv4_addr': '45.1.1.6', 'ipv4_mask': '255.255.255.0'}}, 'node01': {'Eth4/41': {'ipv4_addr': '45.1.1.5', 'ipv4_mask': '255.255.255.0'}, 'Vlan1': {'ipv4_addr': '10.0.0.5', 'ipv4_mask': '255.255.255.0'}, 'Vlan2': {'ipv4_addr': '20.0.0.5', 'ipv4_mask': '255.255.255.0'}}}
        self.interface_dict=tmp

        #self.pim_config_dict is parsed and the following dicts are initialized in configInitPim()
        self.pim_config_dict=pim_config_dict
        #static RP info parsed from pim_config_dict:
        #{'node02': {'56.1.1.5': {'override_flag': 'YES', 'group_list': ['225.0.0.0/8', '226.0.0.0/8']}}, 'node01': {'56.1.1.5': {'override_flag': 'YES', 'group_list': ['225.0.0.0/8', '226.0.0.0/8']}}}
        self.static_rp={}

        #PIM BSR candidates info parsed from pim_config_dict:
        #{'node02': {'interface': 'Eth4/45', 'priority': '64', 'hash_len': '30'}, 'node01': {'interface': 'Eth4/41', 'priority': '64', 'hash_len': '30'}}
        self.bsr_candidates={}

        #PIM BSR RP candidates info parsed from pim_config_dict:
        #{'node02': {'Vlan2': {'priority': '192', 'interval': '60', 'group_list': '226.0.0.0/8'}}, 'node01': {'Vlan2': {'priority': '192', 'interval': '60', 'group_list': '226.0.0.0/8'}}}
        self.bsr_rp_candidates={}

        #Auto-RP mapping agents info parsed from pim_config_dict:
        #{'node02': {'interface': 'Eth4/45', 'scope': '32'}, 'node01': {'interface': 'Eth4/41', 'scope': '32'}}
        self.ar_mapping_agents={}

        #Auto-RP RP candidates info parsed from pim_config_dict:
        #{'node02': {'Vlan2': {'scope': '32', 'interval': '60', 'group_list': '226.0.0.0/8'}}, 'node01': {'Vlan2': {'scope': '32', 'interval': '60', 'group_list': '226.0.0.0/8'}}}
        self.ar_rp_candidates={}

        #loopback interfaces with PIM enbaled defined in pim_config_dict:
        #{'node03':['Lo0']}
        self.loopback_int={}

        #PIM interfaces defined in pim_config_dict including all PIM interfaces except loopback interfaces and host facing interfaces (which has no peer_device or peer_interface)
        #{'node02': {'Vlan1': {'encryption_level': '0', 'dr_priority': '1', 'authentication_flag': 'YES', 'encryption_key': 'insieme', 'join_prune_route_map': 'jp_route_map', 'hello_interval': '30000', 'neighbor_policy': 'pim_neigh_policy', 'peer_interface': 'Vlan1', 'peer_device': 'node01'}, 'Vlan2': {'encryption_level': '0', 'dr_priority': '1', 'authentication_flag': 'YES', 'encryption_key': 'insieme', 'join_prune_route_map': 'jp_route_map', 'hello_interval': '30000', 'neighbor_policy': 'pim_neigh_policy', 'peer_interface': 'Vlan2', 'peer_device': 'node01'}, 'Eth4/45': {'encryption_level': '0', 'dr_priority': '1', 'authentication_flag': 'YES', 'encryption_key': 'insieme', 'join_prune_route_map': 'jp_route_map', 'hello_interval': '30000', 'neighbor_policy': 'pim_neigh_policy', 'peer_interface': 'Eth4/41', 'peer_device': 'node01'}}, 'node01': {'Eth4/41': {'encryption_level': '0', 'dr_priority': '1', 'authentication_flag': 'YES', 'encryption_key': 'insieme', 'join_prune_route_map': 'jp_route_map', 'hello_interval': '30000', 'neighbor_policy': 'pim_neigh_policy', 'peer_interface': 'Eth4/45', 'peer_device': 'node02'}, 'Vlan1': {'encryption_level': '0', 'dr_priority': '1', 'authentication_flag': 'YES', 'encryption_key': 'insieme', 'join_prune_route_map': 'jp_route_map', 'hello_interval': '30000', 'neighbor_policy': 'pim_neigh_policy', 'peer_interface': 'Vlan1', 'peer_device': 'node02'}, 'Vlan2': {'encryption_level': '0', 'dr_priority': '1', 'authentication_flag': 'YES', 'encryption_key': 'insieme', 'join_prune_route_map': 'jp_route_map', 'hello_interval': '30000', 'neighbor_policy': 'pim_neigh_policy', 'peer_interface': 'Vlan2', 'peer_device': 'node02'}}}
        self.pim_int={}

        #PIM BSR and Auto-RP RPA is determined by the highest BSR-candidate/Mapping-agent's IP or priority. 
        self.bsr=''
        self.bsr_priority=64
        self.ar_rpa=''

        #PIM BSR and Auto-RP RPs parsed from pim_config_dict and interface_config_dict
        #They are defined with RP address as key and group_list as value.
        #{'20.0.0.5': '228.0.0.0/8', '20.0.0.6': '228.0.0.0/8'}
        self.bsr_rp_dict={}

        #{'20.0.0.5': '229.0.0.0/8', '20.0.0.6': '229.0.0.0/8'}
        self.ar_rp_dict={}
        self.log.info('self.dut : {0}'.format(self.dut))
        try:
             if not self.dut == "all" :
                 self.list_of_nodes = utils.strtolist(self.dut)
             else :
                 self.list_of_nodes=sorted(self.pim_config_dict.keys())
        except KeyError:
             testResult('fail','pim_config_dict in input file not defined properly ..               \
                  does not have any keys ..',self.log)
             self.result='fail'
             return None

        self.log.info('self.list_of_nodes : {0}'.format(self.list_of_nodes))
        self.switch_hdl_dict=switch_hdl_dict
        self.configInitPim(noconfig=self.noconfig)
#        self.verifyPim()

    def cleanupPim(self):
        self.configInitPim(cleanup=True)
 
    def configInitPim(self,cleanup=False,noconfig=False):
        self.log.info('self.list_of_nodes : {0}'.format(self.list_of_nodes))
        for node in self.list_of_nodes:
             hdl=self.switch_hdl_dict[node]
             # Enable feature PIM and verify
             if cleanup:
                 hdl.configure('no feature pim')
             else:
                 if not noconfig:
                     hdl.configure('feature pim')
          
             #sw_command='show system internal feature-mgr feature state | inc pim'
             #l_args="-show_command {0} -expected_pattern {1}".format(sw_command, 'SUCCESS')
             #hdl.loopUntil(l_args)
                     
             #if re.search( 'fail', hdl.test['result'], flags=re.I ):
             #    msg='Enabling/Disabling PIM failed on node {0}'.format(node) 
             #    testResult('fail',msg,self.log)
             #    self.result='fail'
             #    return 

             if not 'rp_config' in self.pim_config_dict[node].keys():
                 msg='PIM RP config not defined in pim_config_dict for node {0}'.       \
                     format(node)
                 testResult('fail',msg,self.log)
                 self.result='fail'
                 return 
             else:
                 # Configure Static RP configs ..
                 if 'static' in self.pim_config_dict[node]['rp_config'].keys():
                     #print "pim_config_dict",self.pim_config_dict
                     self.static_rp[node]={}
                     for rp_addr in self.pim_config_dict[node]['rp_config']['static']   \
                          .keys():
                          self.static_rp[node][rp_addr]={}
                          config_option=True
                          static_rp_cfg=None
                          static_rp_cfg=parsePimStaticRpConfigs(self.pim_config_dict    \
                              [node]['rp_config']['static'][rp_addr],self.log)
                          print ('\n\nstatic_rp_cfg.route_map : {0}'.format(static_rp_cfg.route_map))
                          print ('\n\nstatic_rp_cfg.group_list : {0}'.format(static_rp_cfg.group_list))
                          if not static_rp_cfg.route_map == 'None':
                              sw_cmd='ip pim rp-address {0} route-map {1}'.format(      \
                                rp_addr, static_rp_cfg.route_map)
                              self.static_rp[node][rp_addr]['route_map']=static_rp_cfg.route_map
                          elif static_rp_cfg.prefix_list:
                              sw_cmd='ip pim rp-address {0} prefix-list {1}'.format(    \
                                rp_addr, static_rp_cfg.prefix_list)
                              self.static_rp[node][rp_addr]['prefix_list']=static_rp_cfg.prefix_list
                          elif static_rp_cfg.group_list:
                              if static_rp_cfg.bidir_flag == 'YES':
                                  self.static_rp[node][rp_addr]['bidir_flag']=static_rp_cfg.bidir_flag
                                  bidir='bidir'
                              else:
                                  bidir=''
                              if static_rp_cfg.override_flag=='YES':
                                  self.static_rp[node][rp_addr]['override_flag']=static_rp_cfg.override_flag
                                  override='override'
                              else:
                                  override=''
                              self.static_rp[node][rp_addr]['group_list']=strtolist(static_rp_cfg.group_list)
                              sw_cmd=''
                              for group in strtolist(static_rp_cfg.group_list):
                                  sw_cmd+='ip pim rp-address {0} group-list {1} {2} {3}\n'.format(     \
                                           rp_addr, group ,bidir, override)
                              config_option=False
                          else:
                              sw_cmd='ip pim rp-address {0}'.format(rp_addr)

                          if static_rp_cfg.bidir_flag and re.search( 'YES', static_rp_cfg.bidir_flag, flags=re.I ) and config_option: 
                              sw_cmd=sw_cmd + ' bidir'
                              self.static_rp[node][rp_addr]['bidir']=True

                          if static_rp_cfg.override_flag and re.search( 'YES', static_rp_cfg.override_flag, flags=re.I ) and config_option:
                              sw_cmd=sw_cmd + ' override'
                              self.static_rp[node][rp_addr]['override']=True

                          sw_cmd=re.sub( ' +', ' ', sw_cmd )
                          if not static_rp_cfg.vrf == 'None' :
                              cmd = '''vrf context {0}
                                       {1}'''.format(static_rp_cfg.vrf,sw_cmd)
                          else :
                              cmd = sw_cmd
                          if not cleanup and not noconfig:
                              hdl.configure(cmd)

                 # Configure PIM BSR configs ..
                 if 'bsr' in self.pim_config_dict[node]['rp_config'].keys():
                      sw_cmd='ip pim bsr forward listen'
                      sw_cmd=re.sub( ' +', ' ', sw_cmd )
                      # Config BSR candidate info
                      if 'bsr_candidate' in self.pim_config_dict[node]['rp_config']     \
                          ['bsr'].keys():
                           self.bsr_candidates[node]={}
                           bsr_cand_cfg=parsePimBsrCandidateConfigs(                \
                               self.pim_config_dict[node]['rp_config']               \
                               ['bsr']['bsr_candidate'],self.log )
                           if bsr_cand_cfg.interface!='None':
                                self.bsr_candidates[node]['interface']=normalizeInterfaceName(self.log,bsr_cand_cfg.interface)
                                self.bsr_candidates[node]['hash_len']=bsr_cand_cfg.hash_len
                                self.bsr_candidates[node]['priority']=bsr_cand_cfg.priority
                                #calculate the bsr based on the highest IP and priority of bsr_candidates
                                int_ip = self.interface_dict[node][self.bsr_candidates[node]['interface']]['ipv4_addr']
                                if not self.bsr:
                                    self.bsr=int_ip
                                    self.bsr_priority=bsr_cand_cfg.priority
                                else:
                                    if int(bsr_cand_cfg.priority)>int(self.bsr_priority):
                                        self.bsr=int_ip
                                        self.bsr_priority=bsr_cand_cfg.priority
                                    elif int(bsr_cand_cfg.priority)==int(self.bsr_priority) and ipaddr.IPv4Address(int_ip)>ipaddr.IPv4Address(self.bsr):
                                        self.bsr=int_ip
                                        self.bsr_priority=bsr_cand_cfg.priority
                                        sw_cmd='ip pim bsr bsr-candidate {0} hash-len {1}        \
                                        priority {2}'.format( bsr_cand_cfg.interface,                  \
                                        bsr_cand_cfg.hash_len,                                \
                                        bsr_cand_cfg.priority)
                                        sw_cmd=re.sub( ' +', ' ', sw_cmd )
                                        if not cleanup and not noconfig:
                                            hdl.configure(sw_cmd)

                      # Config BSR RP candidate info
                      if 'rp_candidates' in self.pim_config_dict[node]['rp_config']      \
                          ['bsr'].keys():
                           self.bsr_rp_candidates[node]={}
                           rp_candidates=self.pim_config_dict[node]['rp_config']        \
                               ['bsr']['rp_candidates'].keys()
                           for rp_candidate in rp_candidates:
                               old_rp_candidate=rp_candidate
                               rp_candidate=normalizeInterfaceName(self.log,rp_candidate)
                               rp_addr=self.interface_dict[node][rp_candidate]['ipv4_addr']
                               self.bsr_rp_candidates[node][rp_candidate]={}
                               bsr_rp_cand_cfg=parsePimBsrRpCandidateConfigs(           \
                                  self.pim_config_dict[node]['rp_config']               \
                                  ['bsr']['rp_candidates'][old_rp_candidate] ,self.log)
                               sw_cmd='ip pim bsr forward listen'
                               sw_cmd=re.sub( ' +', ' ', sw_cmd )
                               if not cleanup and not noconfig:
                                    hdl.configure(sw_cmd)

                               if bsr_rp_cand_cfg.route_map != 'None':
                                   self.bsr_rp_candidates[node][rp_candidate]['route_map']=bsr_rp_cand_cfg.route_map
                                   self.bsr_rp_candidates[node][rp_candidate]['priority']=bsr_rp_cand_cfg.priority
                                   self.bsr_rp_candidates[node][rp_candidate]['interval']=bsr_rp_cand_cfg.interval
                                   sw_cmd='''ip pim bsr rp-candidate {0} route-map      \
                                     {1} interval {2}'''.format(                        \
                                     rp_candidate, bsr_rp_cand_cfg.route_map,           \
                                     bsr_rp_cand_cfg.interval)
                                   sw_cmd=re.sub( ' +', ' ', sw_cmd )
                                   if not cleanup and not noconfig:
                                        hdl.configure(sw_cmd)
                                   sw_cmd='''ip pim bsr rp-candidate {0} route-map      \
                                     {1} priority {2}'''.format(                        \
                                     rp_candidate, bsr_rp_cand_cfg.route_map,           \
                                     bsr_rp_cand_cfg.priority)
                                   sw_cmd=re.sub( ' +', ' ', sw_cmd )
                                   if not cleanup and not noconfig:
                                        hdl.configure(sw_cmd)

                               if bsr_rp_cand_cfg.group_list:
                                   self.bsr_rp_candidates[node][rp_candidate]['group_list']=bsr_rp_cand_cfg.group_list
                                   self.bsr_rp_candidates[node][rp_candidate]['priority']=bsr_rp_cand_cfg.priority
                                   self.bsr_rp_candidates[node][rp_candidate]['interval']=bsr_rp_cand_cfg.interval
                                   self.bsr_rp_dict[rp_addr]=bsr_rp_cand_cfg.group_list
                                   sw_cmd='''ip pim bsr rp-candidate {0} group-list     \
                                     {1} interval {2}'''.format(                        \
                                     rp_candidate, bsr_rp_cand_cfg.group_list,          \
                                     bsr_rp_cand_cfg.interval)
                                   sw_cmd=re.sub( ' +', ' ', sw_cmd )
                                   if not cleanup and not noconfig:
                                       hdl.configure(sw_cmd)
                                   sw_cmd='''ip pim bsr rp-candidate {0} group-list     \
                                     {1} priority {2}'''.format(                        \
                                     rp_candidate, bsr_rp_cand_cfg.group_list,          \
                                     bsr_rp_cand_cfg.priority)
                                   sw_cmd=re.sub( ' +', ' ', sw_cmd )
                                   if not cleanup and not noconfig:
                                       hdl.configure(sw_cmd)


                 # Configure PIM Auto RP configs ..
                 if 'auto_rp' in self.pim_config_dict[node]['rp_config'].keys():
                      autoRpHdl=self.switch_hdl_dict[node]
                      autoRpHdl.configure('ip pim auto-rp listen')

                      # Config auto-rp mapping agent candidate info
                      if 'mapping_agent' in self.pim_config_dict[node]                 \
                          ['rp_config']['auto_rp'].keys():
                           self.ar_mapping_agents[node]={}
                           auto_map_agent_cfg=parsePimAutoRpMappingAgentConfigs(    \
                              self.pim_config_dict[node]['rp_config']               \
                              ['auto_rp']['mapping_agent'],self.log )
                           self.ar_mapping_agents[node]['interface']=normalizeInterfaceName(self.log,auto_map_agent_cfg.interface)
                           self.ar_mapping_agents[node]['scope']=auto_map_agent_cfg.scope 
                           sw_cmd='ip pim auto-rp mapping-agent {0} scope {1}'      \
                              .format( auto_map_agent_cfg.interface, \
                              auto_map_agent_cfg.scope)
                           sw_cmd=re.sub( ' +', ' ', sw_cmd )
                           if not cleanup and not noconfig:
                                hdl.configure(sw_cmd)

#                           #calculate the auto-rp mapping agent based on the highest IP of mapping agents
#                           int_ip = self.interface_dict[node][self.ar_mapping_agents[node]['interface']]['ipv4_addr']
#                           if not self.ar_rpa:
#                               self.ar_rpa=int_ip
#                           elif ipaddr.IPv4Address(int_ip)>ipaddr.IPv4Address(self.ar_rpa):
#                               self.ar_rpa=int_ip

                      # Config Auto-RP RP candidate info
                      if 'rp_candidates' in self.pim_config_dict[node]['rp_config']     \
                          ['auto_rp'].keys():
                           self.ar_rp_candidates[node]={}
                           rp_candidates=self.pim_config_dict[node]['rp_config']        \
                               ['auto_rp']['rp_candidates'].keys()
                           for rp_candidate in rp_candidates:
                               old_rp_candidate=rp_candidate
                               rp_candidate=normalizeInterfaceName(self.log,rp_candidate)
#                               rp_addr=self.interface_dict[node][rp_candidate]['ipv4_addr']
                               self.ar_rp_candidates[node][rp_candidate]={}
                               auto_rp_agent_cfg=parsePimAutoRpRpCandidateConfigs(      \
                                  self.pim_config_dict[node]['rp_config']               \
                                  ['auto_rp']['rp_candidates'][old_rp_candidate],self.log )
                               sw_cmd='ip pim auto-rp forward listen'
                               sw_cmd=re.sub( ' +', ' ', sw_cmd )
                               if not cleanup and not noconfig:
                                   hdl.configure(sw_cmd)

                               if auto_rp_agent_cfg.route_map != 'None':
                                   self.ar_rp_candidates[node][rp_candidate]['route_map']=auto_rp_agent_cfg.route_map
                                   self.ar_rp_candidates[node][rp_candidate]['scope']=auto_rp_agent_cfg.scope
                                   self.ar_rp_candidates[node][rp_candidate]['interval']=auto_rp_agent_cfg.interval
                                   sw_cmd='''ip pim auto-rp rp-candidate {0} route-map  \
                                     {1} interval {2}'''.format(                        \
                                     rp_candidate, auto_rp_agent_cfg.route_map,         \
                                     auto_rp_agent_cfg.interval)
                                   sw_cmd=re.sub( ' +', ' ', sw_cmd )
                                   if not cleanup and not noconfig:
                                       hdl.configure(sw_cmd)

                               if auto_rp_agent_cfg.group_list:
                                   self.ar_rp_candidates[node][rp_candidate]['group_list']=auto_rp_agent_cfg.group_list
                                   self.ar_rp_candidates[node][rp_candidate]['scope']=auto_rp_agent_cfg.scope
                                   self.ar_rp_candidates[node][rp_candidate]['interval']=auto_rp_agent_cfg.interval
#                                   self.ar_rp_dict[rp_addr]=auto_rp_agent_cfg.group_list
                                   sw_cmd='''ip pim auto-rp rp-candidate {0} group-list     \
                                     {1} interval {2}'''.format(                        \
                                     rp_candidate, auto_rp_agent_cfg.group_list,        \
                                     auto_rp_agent_cfg.interval)
                                   sw_cmd=re.sub( ' +', ' ', sw_cmd )
                                   if not cleanup and not noconfig:
                                       hdl.configure(sw_cmd)

                 else:
                     print('Auto-RP config not available for node {0}'.format(node))
                     autoRpHdl=self.switch_hdl_dict[node]
                     autoRpHdl.configure('ip pim auto-rp listen')

                 # Configure PIM Anycast RP configs ..
                 if 'anycast' in self.pim_config_dict[node]['rp_config'].keys():
                    # Config anycast rp info
                    anycastrp_cfg=parsePimAnycastRpCandidateConfigs(    \
                    self.pim_config_dict[node]['rp_config']               \
                    ['anycast'],self.log )
                    rp_set_list=[]
                    rp_set_list=anycastrp_cfg.rp_set.split(',')
                    for rp in rp_set_list:
                      sw_cmd = ''
                      self.log.info('anycastrp_cfg.rp_candidate : {0}, rp : {1}'.format(anycastrp_cfg.rp_candidate, rp))
                      self.log.info('sw_cmd : {0}'.format(sw_cmd))
                      if anycastrp_cfg.rp_candidate == 'None' or rp == 'None':
                        continue
                      else:
                        sw_cmd='ip pim anycast-rp {0} {1}'      \
                        .format( anycastrp_cfg.rp_candidate,rp)
                        sw_cmd=re.sub( ' +', ' ', sw_cmd )
                        if not cleanup and not noconfig:
                            hdl.configure(sw_cmd)

             # Beginning of PIM Interface Configs ..
             if not 'intf_config' in self.pim_config_dict[node].keys():
                 msg='PIM Interface config not defined in pim_config_dict for           \
                     node {0}'. format(node)
                 self.result='fail'
                 testResult('fail',msg,self.log)
                 return 
             else:
                 self.pim_int[node]={}
                 self.loopback_int[node]=[]
                 # Configure PIM interface configs ..
                 for intf_range in self.pim_config_dict[node]['intf_config'].keys():
                   intf_cfg=parsePimInterfaceConfigs(self.pim_config_dict[node] \
                       ['intf_config'][intf_range],self.log )
                   intf_list=normalizeInterfaceName(self.log,strtoexpandedlist(intf_range))
                   for intf in intf_list:
                      if intf_cfg.igmp_version  == 3:
                          hdl.configure('interface {0}\n\
                                       ip igmp version 3'.format(intf))
                      if intf_cfg.loopback_interface=='YES' and not cleanup and not noconfig:
                          self.loopback_int[node].append(intf)
                          hdl.configure('interface {0}\n\
                                       ip pim sparse-mode'.format(intf))
                          continue
                      if intf_cfg.peer_device=='none' or intf_cfg.peer_interface=='none':
                          if not intf_cfg.dr_priority == "None":
                              hdl.configure('interface {0}\n\
                                           ip pim sparse-mode\n\
                                           ip pim dr-priority {1}'.format(intf, intf_cfg.dr_priority))
                          else :
                              hdl.configure('interface {0}\n\
                                           ip pim sparse-mode'.format(intf))
                          continue
                          
                      self.pim_int[node][intf]={}
                      self.pim_int[node][intf]['hello_interval']=intf_cfg.hello_interval
                      self.pim_int[node][intf]['dr_priority']=intf_cfg.dr_priority
                      idx=intf_list.index(intf)
                      if idx<len(strtoexpandedlist(intf_cfg.peer_device)):
                          self.pim_int[node][intf]['peer_device']=strtoexpandedlist(intf_cfg.peer_device)[idx]
                      else:
                          self.pim_int[node][intf]['peer_device']=intf_cfg.peer_device
                      if idx<len(strtoexpandedlist(intf_cfg.peer_interface)):
                          self.pim_int[node][intf]['peer_interface']=normalizeInterfaceName(self.log,strtoexpandedlist(intf_cfg.peer_interface))[idx]
                      else:
                          self.pim_int[node][intf]['peer_interface']=normalizeInterfaceName(self.log,strtoexpandedlist(intf_cfg.peer_interface))

                      sw_cmd = []
                      sw_cmd.append('conf t')
                      sw_cmd.append('interface {0}'.format(intf))
                      sw_cmd.append('ip pim sparse-mode')
                      if intf_cfg.hello_interval != 'None':
                          sw_cmd.append('ip pim hello-interval {0}'.format(intf_cfg.hello_interval))
                      if intf_cfg.dr_priority != 'None':
                          sw_cmd.append('ip pim dr-priority {0}'.format(intf_cfg.dr_priority))

                      self.log.info('sw_cmd : {0}'. format(sw_cmd))
                      for cmd in sw_cmd:
                          hdl.iexec(cmd)

                      # If PIM hello authentication is set as YES
                      if re.search( 'YES', intf_cfg.authentication_flag,           \
                          flags=re.I ):
                          self.pim_int[node][intf]['authentication_flag']=intf_cfg.authentication_flag
                          self.pim_int[node][intf]['encryption_level']=intf_cfg.encryption_level
                          self.pim_int[node][intf]['encryption_key']=intf_cfg.encryption_key
                          sw_cmd='''interface {0}
                                 ip pim hello-authentication ah-md5 {1} {2}'''.format(  \
                                 intf, intf_cfg.encryption_level,                  \
                                 intf_cfg.encryption_key)
                          sw_cmd=re.sub( ' +', ' ', sw_cmd )
                          if not cleanup and not noconfig:
                              hdl.configure(sw_cmd)
                          
   
                      # If PIM border flag is set as YES
                      if re.search( 'YES', intf_cfg.border_flag, flags=re.I ):
                          self.pim_int[node][intf]['border_flag']=intf_cfg.border_flag
                          sw_cmd='''interface {0}
                                 ip pim border'''.format(intf)
                          sw_cmd=re.sub( ' +', ' ', sw_cmd )
                          if not cleanup and not noconfig:
                              hdl.configure(sw_cmd)

 
                             
                      # If PIM join prune route_map is configured
                      if intf_cfg.join_prune_route_map:
                          self.pim_int[node][intf]['join_prune_route_map']=intf_cfg.join_prune_route_map
                          sw_cmd='''interface {0}
                                 ip pim jp-policy {1}'''.format(                        \
                                 intf, intf_cfg.join_prune_route_map)
                          sw_cmd=re.sub( ' +', ' ', sw_cmd )
                          if not cleanup and not noconfig:
                              hdl.configure(sw_cmd)



                      # If PIM neighbor policy is configured
                      if intf_cfg.neighbor_policy:
                          self.pim_int[node][intf]['neighbor_policy']=intf_cfg.neighbor_policy
                          sw_cmd='''interface {0}
                                 ip pim neighbor-policy {1}'''.format(                  \
                                 intf, intf_cfg.neighbor_policy)
                          sw_cmd=re.sub( ' +', ' ', sw_cmd )
                          if not cleanup and not noconfig:
                              hdl.configure(sw_cmd)

             print ('Sleeping for 10 seconds...')
             time.sleep(10)
             # End of PIM Interface Configs ..

###############################################################################
class verifyMrouteCount ():

  def __init__(self,hdl,log, *args):
    self.result='pass'

    # Sample Usage
    # verifyMrouteCount (hdl,log, -count 5')
    # verifyMrouteCount (hdl,log, '-count 10 -flag sgcount -vrf default')
    # verifyMrouteCount (hdl,log, '-count 1 -flag sGCount')
    # Verifies mroute count against the given count

    arggrammar={}
    arggrammar['vrf']='-type str'
    arggrammar['count']='-type str -required True'
    arggrammar['flag']='-type str -choices ["sgcount","stargcount","starg-pfxcount","total"] -default total'
    arggrammar['verify_iterations']='-type int -default 1'
    arggrammar['verify_interval']='-type int -default 15'
    parse_output=parserutils_lib.argsToCommandOptions(args,arggrammar,log)
    count = parse_output.count
    flag = parse_output.flag.lower()
    options = ' '
    verify_iterations=parse_output.verify_iterations
    verify_interval=parse_output.verify_interval

    if parse_output.vrf:
        options += ' -vrf ' + parse_output.vrf

    verified=False
    for iteration in range(verify_iterations):
        # Get the mroute count
        mroute_dict = getMrouteCountDict(hdl,log,options)
        if (flag == 'total'):
            get_count = mroute_dict['Total']
        elif (flag == 'stargcount'):
            get_count = mroute_dict['(*,G)_routes']
        elif (flag == 'sgcount'):
            get_count = mroute_dict['(S,G)_routes']
        elif (flag == 'starg-pfxcount'):
            get_count = mroute_dict['(*,G-prefix)_routes']
        if (count != get_count):
             log.info('Iteration: {3} - Expected mroutes not present,Looking for:{0},found:{1},expected:{2}'.\
                            format(flag,get_count,count,iteration))
        else:
             verified=True

        if (verified or iteration==verify_iterations-1):
            break

        time.sleep(verify_interval)

    if verified:
        testResult('pass','verifyMrouteCount passed',log)
    else:
        testResult('fail','verifyMrouteCount failed',log)

###############################################################################

class verifyPimNeighbor ():

  def __init__(self,hdl, log, *args):
    self.result='pass'

    # Verifies neighbors are listed in the PIM neighbor table

    # Sample Usage:
    # verifyPimNeighbor(hdl,log, '-vrf default -neighbors ' + str(neighbors))
    # verifyPimNeighbor(hdl,log, '-neighbors ' + str(neighbors))

    arggrammar={}
    arggrammar['vrf']='-type str'
    arggrammar['neighbors']='-type str -required True'
    parse_output=parserutils_lib.argsToCommandOptions(args,arggrammar,log)

    # Get the actual output from switch
    if parse_output.vrf:
        out_pim_dict = getPimNeighborDict(hdl,log,'-vrf ' + parse_output.vrf)
    else:
        out_pim_dict = getPimNeighborDict(hdl,log)

    # get list of neighbors which needs to be verified
    neighbors=re.findall('('+rex.IPv4_ADDR+')',parse_output.neighbors)
    log.info('Actual Neighbors Configured : {0}'.format(neighbors))

    # All verification steps as below
    result=True
    for nei in neighbors:
        if (nei not in  out_pim_dict.keys()):
            # If this is not in output then fail cases
            testResult('fail','FAIL. Neighbor:{0} NOT in PIM neighbor list of switch {1}'.format(nei, hdl.switchName),log)
            result=False

    if result:
        testResult('pass','PASS. PIM neighbor verification passed on switch {0}'.format(hdl.switchName),log)

###############################################################################

class verifyIpPimDR ():

  def __init__(self, hlite, switch_hdl_dict, log, *args):
    self.result='pass'

    # Verifies that the DR is the one with highest IP
    # Sample Usage:
    # verifyIpPimDR(hdl,log)
    # verifyIpPimDR(hdl,log, '-vrf default -neighbors ' + str(neighbors))

    arggrammar={}
    arggrammar['vrf']='-type str'
    parse_output=parserutils_lib.argsToCommandOptions(args,arggrammar,log)

    pim_config_dict=hlite.gd['Topology']['pim_config_dict']

    for dut in sorted(pim_config_dict.keys()):
        hdl = switch_hdl_dict[dut]
        if parse_output.vrf:
            neighList = getPimNeighborDict(hdl,log,'-vrf ' + parse_output.vrf)
            pim_int_dict = getPimInterfaceDict(hdl,log,'-vrf ' + parse_output.vrf)
        else:
            neighList = getPimNeighborDict(hdl,log)
            pim_int_dict = getPimInterfaceDict(hdl,log)

        for neighIp in neighList:
            intf = neighList[neighIp]['interface']
            intfIp = pim_int_dict[intf]['ip']
            if parse_output.vrf:
               DRP=getPIMDRPrioityForInterface(hdl,intf)
               NDRP=getNeighborPIMDRPrioityForInterface(hdl,intf,vrf=parse_output.vrf)
            else:
               DRP=getPIMDRPrioityForInterface(hdl,intf)
               NDRP=getNeighborPIMDRPrioityForInterface(hdl,intf)

            log.info('DR priority is {0}'.format(DRP))
            log.info('Neighbor DR priority is {0}'.format(NDRP))
            print ('DR priority is {0}'.format(DRP))
            print ('Neighbor DR priority is {0}'.format(NDRP))

            if DRP == NDRP:
                expDrIp = getMaxIp([intfIp,neighIp])
            elif DRP > NDRP:
               expDrIp=intfIp
            elif DRP < NDRP:
                expDrIp=neighIp

            drIp = pim_int_dict[intf]['dr']

            if not drIp == expDrIp :
                msg = 'FAIL. Expected DR for Intf {0} is {1}. DR seen is {2} on Switch {3}'.format(intf, expDrIp, drIp, hdl.switchName)
                self.result='fail'
                testResult('fail', msg, log)
            else :
                msg = 'PASS. Expected DR {0} for Intf {1} is seen properly on Switch {2}'.format(expDrIp, intf, hdl.switchName)
                testResult('pass', msg, log)
            
             

###############################################################################

def getPIMDRPrioityForInterface(hdl,intf):

        out=hdl.iexec('show ip pim interface {0}'.format(intf))
        pat='PIM configured DR priority: (\d+)'
        return int(re.findall(pat,out)[0])

def getNeighborPIMDRPrioityForInterface(hdl,intf,vrf=None):
        if vrf:
                out=hdl.iexec('show ip pim neighbor {0} vrf {1}'.format(intf,vrf))
        else:
                out=hdl.iexec('show ip pim neighbor {0}'.format(intf))
 

        pat='\d+\.\d+\.\d+\.\d+\s+.+\s+.+\s+\d+:\d+:\d+\s+(\d+)\s+.*'
        return int(re.findall(pat,out)[0])
             

###############################################################################

class verifyPimInterface():

  def __init__(self,hdl, log, *args, **pim_dict):
    self.result='pass'

    # Sample Usage:

    # verifyPimInterface(hdl,log, '-vrf default -interfaces ' + str(interfaces))
    # verifyPimInterface(hdl,log, **pim_dict)

    # pim_dict is build as below
    # pim_dict = {}
    # pim_dict['Ethernet4/1'] = {}
    # pim_dict['Ethernet4/1']['dr'] = '11.1.1.2'
    # pim_dict['Ethernet4/1']['ip'] = '11.1.1.1'
    # pim_dict['Ethernet4/1']['neighbor_count'] = '1'
    # pim_dict['Ethernet4/2'] = {}
    # pim_dict['Ethernet4/2']['dr'] = '12.1.1.2'
    # pim_dict['Ethernet4/2']['ip'] = '12.1.1.1'
    # pim_dict['Ethernet4/2']['neighbor_count'] = '1'
    # pim_dict['loopback0'] = {}
    # pim_dict['loopback0']['dr'] = '1.1.1.1'
    # pim_dict['loopback0']['ip'] = '1.1.1.1'
    # pim_dict['loopback0']['neighbor_count'] = '0'

    # verifyPimInterface(hdl,log,**pim_dict)

    arggrammar={}
    arggrammar['vrf']='-type str'
    arggrammar['interfaces']='-type str'
    parse_output=parserutils_lib.argsToCommandOptions(args,arggrammar,log)
   # Get the actual output from switch
    if parse_output.vrf:
        out_pim_dict = getPimInterfaceDict(hdl,log,'-vrf ' + parse_output.vrf)
    else:
        out_pim_dict = getPimInterfaceDict(hdl,log)
    if parse_output.interfaces:
        interfaces=re.findall('('+rex.INTERFACE_NAME+')',parse_output.interfaces)
    else:
        interfaces = []

    if (not interfaces) and (not pim_dict):
        # No useful info passed for verification, return fail to avoid user errors
        testResult('fail','No useful info passed for verifying PIM interface table',log)
        return None

    # All verification steps as below
    result=True
    if pim_dict:
        # The values from this dictionary will be verified against the values from get proc
        if (compareVars(pim_dict,out_pim_dict,log) != 'pass'):
            testResult('fail','Expected values for PIM interfaces not in PIM interface table',log)
            result=False
    if interfaces:
        # Interfaces will be tested in this section to make sure they are in the list
        for intf in interfaces:
            if (intf not in  out_pim_dict.keys()):
                # If this is not in output then fail cases
                testResult('fail','No info for Interface:{0} in PIM interface table'.format(intf),log)
                result=False

    if result:
        testResult('pass','PIM interface verification passes',log)

    return None

 ################################################################################################
class verifyMroute ():

  def __init__(self,hdl,log, *args, **mroute_dict):
    self.result='pass'

    # Summary:
    # Source info and Receiver info can be passed as individual value or in form
    # of increment (usefull for 100s of mroutes where many are indentical)
    #
    # sx_info1 = '11.1.1.1' or sx = '11.1.1.1, 11.1.1.100, 1'
    # the later value will expand to 100 sources while verifying
    # Same goes for rx, increment can be any, all possible values between
    # start and end are considered for verification
    #
    # rx_info1 = '225.1.1.1'
    # mroute_dict[sx_info1,rx_info1]={}
    # mroute_dict[sx_info1,rx_info1]['rpf_interface']='Ethernet4/1'
    # mroute_dict[sx_info1,rx_info1]['oif_list']=['Ethernet4/1']
    # mroute_dict[sx_info1,rx_info1]['oif_list1']=['Ethernet4/2','Ethernet4/3']
    # mroute_dict[sx_info1,rx_info1]['uptime']='1:1:1'
    # rpf_interface can be a single interface or a list of interfaces (in case of ECMP RPF paths
    # oif_list can be be a list of interfaces or a keyword 'ANY_VALID' which will pass verification
    # as long as any valid oif interfaces exist.oif_list1 is the oif list with the ECMP paths.
    # If both oif_list and oif_list1 exist,the actual oif_list should have all interfaces from oif_list
    # plus one interface from oif_list1
    # If only oif_list exists, actual oif_list should be the same as expected oif_list
    # If only oif_list1 exists, actual oif_list should be only one interface from oif_list1


    # verifies <show ip mroute> output, accpets values via dict strutcture
    # It does exact match for all parameters passed, rpf_interface can be passed as
    # a list and it passes as long as output has one of this rpf_interface
    # oif_list should always be passed as list (consistence with getMroute)

    # Sample Usage:
    # verifyMroute (hdl,log, value=mroute_dict)
    # verifyMroute (hdl,log,'-vrf default', value=mroute_dict)
    arggrammar={}
    arggrammar['vrf']='-type str'
    arggrammar['negative']='-type str -default False'
    parse_output=parserutils_lib.argsToCommandOptions(args,arggrammar,log)

    # Get the actual output from switch
    if parse_output.vrf:
        out_mroute_dict = getMrouteDict(hdl,log,'-vrf ' + parse_output.vrf)
        pass
    else:
        out_mroute_dict = getMrouteDict(hdl,log)
        pass
    if not mroute_dict:
        testResult ('fail','Mroute info not passed for verification',log)
        self.result='fail'
        return None
    else:
        mroute_dict = mroute_dict['value']

    exp_mroute_dict = {}
    # Construct the expected output for verification
    for key in mroute_dict.keys():
        # Converting String to Tuple type
        key1 = re.findall('\(\'([\d\.\*]+)\'\,\s*\'([\d\.]+)\'\)',str(key))[0]

        # This can be list
        sources = retIpAddressList(key1[0])
        # this can be list
        groups =  retIpAddressList(key1[1])

        for source in sources:
            for group in groups:
                exp_mroute_dict[source,group] = {}
                for next_key in mroute_dict[key].keys():
                    if next_key=='oif_list' or next_key=='rpf_interface':
                        exp_mroute_dict[source,group][next_key]=normalizeInterfaceName(log,mroute_dict[key][next_key])
                    else:
                        exp_mroute_dict[source,group][next_key] = mroute_dict[key][next_key]
            pass
        pass

    print ('exp_mroute_dict : {0}'.format(exp_mroute_dict))
    print ('out_mroute_dict : {0}'.format(out_mroute_dict))

    # Perform Actual verification
    result=True
    for key in exp_mroute_dict.keys():

        if (key not in out_mroute_dict.keys()):
            #testResult ('fail','No info for {0} in mroute output from switch {1}'.format(key,hdl.switchName),log)
            log.error('No info for {0} in mroute output from switch {1}'.format(key,hdl.switchName))
            self.result='fail'
            continue
        print('exp_mroute_dict_keys : {0}'.format(exp_mroute_dict[key].keys()))
        print ('out_mroute_dict_keys : {0}'.format(out_mroute_dict[key].keys()))

        for next_key in exp_mroute_dict[key].keys():
            if (next_key not in out_mroute_dict[key].keys() and next_key!='iif_list'):
                #testResult ('fail','No info for key:{0} in mroute output for:{1} on {2}'.format(key,next_key,hdl.switchName),log)
                log.error('No info for key:{0} in mroute output for:{1} on {2}'.format(key,next_key,hdl.switchName))
                self.result='fail'
                continue
            elif (next_key == 'rpf_interface'):
                if type(exp_mroute_dict[key][next_key])==str and (normalizeInterfaceName(log,out_mroute_dict[key][next_key])!=exp_mroute_dict[key][next_key]):
                    #testResult ('fail','RPF interface not in output for {0} on {3}.expected:{1},found:{2}'.\
                    #                format(key,exp_mroute_dict[key][next_key],out_mroute_dict[key][next_key],hdl.switchName),log)
                    log.error('RPF interface not in output for {0} on {3}.expected:{1},found:{2}'.\
                                    format(key,exp_mroute_dict[key][next_key],out_mroute_dict[key][next_key],hdl.switchName))
                    self.result='fail'
                elif type(exp_mroute_dict[key][next_key])==list and (normalizeInterfaceName(log,out_mroute_dict[key][next_key]) not in exp_mroute_dict[key][next_key]):
                    #testResult ('fail','RPF interface not in output for {0} on {3}.expected:{1},found:{2}'.\
                                    #format(key,exp_mroute_dict[key][next_key],out_mroute_dict[key][next_key],hdl.switchName),log)
                    log.error('RPF interface not in output for {0} on {3}.expected:{1},found:{2}'.\
                                    format(key,exp_mroute_dict[key][next_key],out_mroute_dict[key][next_key],hdl.switchName))
                    self.result='fail'
            elif next_key == 'oif_list':
                if exp_mroute_dict[key][next_key]=='ANY_VALID':
                    if not len(out_mroute_dict[key][next_key]):
                        #testResult ('fail','Incorrect match for key:{0} for {1} on {4}.expected:{2},found:{3}'.\
                        #                format(key,next_key,exp_mroute_dict[key][next_key],\
                        #                           out_mroute_dict[key][next_key],hdl.switchName),log)
                        log.error('Incorrect match for key:{0} for {1} on {4}.expected:{2},found:{3}'.\
                                        format(key,next_key,exp_mroute_dict[key][next_key],\
                                                   out_mroute_dict[key][next_key],hdl.switchName))
                        self.result='fail'
                elif 'oif_list' not in exp_mroute_dict[key].keys() and (set(exp_mroute_dict[key][next_key]) != set(normalizeInterfaceName(log,out_mroute_dict[key][next_key]))):
                    #testResult ('fail','Incorrect match for key:{0} for {1} on {4}.expected:{2},found:{3}'.\
                    #                format(key,next_key,exp_mroute_dict[key][next_key],\
                    #                           out_mroute_dict[key][next_key],hdl.switchName),log)
                    log.error('Incorrect match for key:{0} for {1} on {4}.expected:{2},found:{3}'.\
                                    format(key,next_key,exp_mroute_dict[key][next_key],\
                                               out_mroute_dict[key][next_key],hdl.switchName))
#                elif 'oif_list' in exp_mroute_dict[key].keys() and 'oif_list1' in exp_mroute_dict[key].keys():
#                    #With both oif_list and oif_list1 expected, the actual OIFs should be all interfaces in oif_list plus one inerface from oif_list1
#                    #verify if expected oif_list is a subset of actual oif_list
#                    #and verify there is only one intf from oif_list1 in the actual oif_list
#                    if not all(intf in iter(normalizeInterfaceName(log,out_mroute_dict[key]['oif_list'])) for intf in exp_mroute_dict[key]['oif_list']):
#                        testResult ('fail','Expected oif_list {1} is not a subset of actual oif_list {0} for {2} on {3}'.
#                                   format(out_mroute_dict[key]['oif_list'],exp_mroute_dict[key]['oif_list'],key,hdl.switchName),log)
#                        self.result='fail'
#                    else:
#                        diff= list(set(normalizeInterfaceName(log,out_mroute_dict[key]['oif_list']))-set(exp_mroute_dict[key]['oif_list']))
#                        if len(diff)!=1 or diff[0] not in exp_mroute_dict[key]['oif_list1']:
#                            testResult('fail','Only one of ECMP paths should be in oif_list for {2} on {3}, expected: one interface from {0}, found:{1}'.format(exp_mroute_dict[key]['oif_list1'],diff,key,hdl.switchName),log)
#                            self.result='fail'
#            elif next_key=='oif_list1':
#                if 'oif_list' not in exp_mroute_dict[key].keys():
#                    #with only oif_list1 expected, the actual OIF should be only one intf of the oif_list1
#                    if len(out_mroute_dict[key]['oif_list'])!=1 or normalizeInterfaceName(log,out_mroute_dict[key]['oif_list'])[0] not in exp_mroute_dict[key][next_key]:
#                        testResult ('fail','Incorrect match for key:{0} for {1} on {4}.expected:only one interface from {2},found:{3}'.\
#                                        format(key,next_key,exp_mroute_dict[key][next_key],\
#                                                   out_mroute_dict[key]['oif_list'],hdl.switchName),log)
#                        self.result='fail'
#
            elif (exp_mroute_dict[key][next_key] != out_mroute_dict[key][next_key]):
                    #testResult ('fail','Incorrect match for key:{0} for {1} on {4}.expected:{2},found:{3}'.\
                    #                format(key,next_key,exp_mroute_dict[key][next_key],\
                    #                           out_mroute_dict[key][next_key],hdl.switchName),log)
                    log.error('Incorrect match for key:{0} for {1} on {4}.expected:{2},found:{3}'.\
                                    format(key,next_key,exp_mroute_dict[key][next_key],\
                                               out_mroute_dict[key][next_key],hdl.switchName))
                    self.result='fail'



    if parse_output.negative == 'True':
        if self.result=='fail':
            self.result = 'pass'
            msg = 'PASS (Negative). verifyMroute verification passed'
            testResult('pass', msg, log)
        else:
            self.result = 'fail'
            msg = 'FAIL (Negative): verifyMroute verification failed'
            testResult('fail', msg, log)

    elif parse_output.negative == 'False':
        if self.result == 'fail':
            msg = 'FAIL. verifyMroute verification failed'
            testResult('fail', msg, log)
            log.error( msg)
        else:
            msg = 'PASS. verifyMroute verification passed'
            testResult('pass', msg, log)
            log.info( msg)




class verifyMrouteCount ():

  def __init__(self,hdl,log, *args):
    self.result='pass'

    # Sample Usage
    # verifyMrouteCount (hdl,log, -count 5')
    # verifyMrouteCount (hdl,log, '-count 10 -flag sgcount -vrf default')
    # verifyMrouteCount (hdl,log, '-count 1 -flag sGCount')
    # Verifies mroute count against the given count

    arggrammar={}
    arggrammar['vrf']='-type str'
    arggrammar['count']='-type str -required True'
    arggrammar['flag']='-type str -choices ["sgcount","stargcount","starg-pfxcount","total"] -default total'
    arggrammar['verify_iterations']='-type int -default 1'
    arggrammar['verify_interval']='-type int -default 15'
    parse_output=parserutils_lib.argsToCommandOptions(args,arggrammar,log)
    count = parse_output.count
    flag = parse_output.flag.lower()
    options = ' '
    verify_iterations=parse_output.verify_iterations
    verify_interval=parse_output.verify_interval

    if parse_output.vrf:
        options += ' -vrf ' + parse_output.vrf

    verified=False
    for iteration in range(verify_iterations):
        # Get the mroute count
        mroute_dict = getMrouteCountDict(hdl,log,options)
        print('\nFlag : {0}'.format(flag))
        log.info('\nFlag : {0}'.format(flag))
        print('\nmroute_dict : {0}'.format(mroute_dict))
        log.info('\nmroute_dict : {0}'.format(mroute_dict))
        if (flag == 'total'):
            get_count = mroute_dict['Total']
        elif (flag == 'stargcount'):
            get_count = mroute_dict['(*,G)_routes']
        elif (flag == 'sgcount'):
            get_count = mroute_dict['(S,G)_routes']
        elif (flag == 'starg-pfxcount'):
            get_count = mroute_dict['(*,G-prefix)_routes']
        print('\nCount : {0}'.format(count))
        log.info('\nCount : {0}'.format(count))
        print('\nget_count : {0}'.format(get_count))
        log.info('\nget_count : {0}'.format(get_count))
        if (count != get_count):
             log.info('Iteration: {3} - Expected mroutes not present,Looking for:{0},found:{1},expected:{2}'.\
                            format(flag,get_count,count,iteration))
        else:
             verified=True

        if (verified or iteration==verify_iterations-1):
            break

        time.sleep(verify_interval)

    if verified:
        testResult('pass','PASS: verifyMrouteCount passed',log)
    else:
        testResult('fail','FAIL: verifyMrouteCount failed',log)

#########################################################################################

class verifyIpIgmpSnoopingVlan ():

  def __init__(self,hdl,log, *args):
    self.result='pass'

    # Sample Usage
    # verifyIpIgmpSnoopingVlan (hdl,log, '-vlan 10 -querier_address 10.1.1.1')
    # verifyIpIgmpSnoopingVlan (hdl,log, '-vlan 10 -querier_address 10.1.1.1 -intf Vlan10')
    # verifyIpIgmpSnoopingVlan (hdl,log, '-vlan 10 -querier_address 10.1.1.1 -intf Vlan10 -querier_interval 125 -no_of_router_ports 1 -no_of_groups 1 -active_ports Eth1/19)
    # Verifies Igmp Snooping values against the given values

    arggrammar={}
    arggrammar['vlan']='-type str -required True'
    arggrammar['querier_address']='-type str'
    arggrammar['intf']='-type str'
    arggrammar['querier_interval']='-type str'
    arggrammar['no_of_router_ports']='-type str'
    arggrammar['no_of_groups']='-type str'
    arggrammar['active_ports']='-type list'
    parse_output=parserutils_lib.argsToCommandOptions(args,arggrammar,log)
    vlan = parse_output.vlan
    querier_address = parse_output.querier_address
    intf = parse_output.intf
    querier_interval=parse_output.querier_interval
    no_of_router_ports=parse_output.no_of_router_ports
    no_of_groups=parse_output.no_of_groups
    active_ports=parse_output.active_ports
    
    options = ' '
    verified=True
    snooping_dict = getIgmpSnoopingVlanDict(hdl, log, vlan, options)
    print ('snooping_dict : {0}'.format(snooping_dict))

    if querier_address:
      if not 'querier_address' in snooping_dict:
         testResult('fail','FAIL: Querier Address info is NOT found in the \'show ip igmp snooping vlan {0}\' output on switch {1}'.format(vlan, hdl.switchName),log)
         verified=False
      else:
          if (querier_address != snooping_dict['querier_address']):
             testResult('fail','FAIL: Expected querier address NOT found in the \'show ip igmp snooping vlan {0}\' output on switch {1}'.format(vlan, hdl.switchName),log)
             verified=False
          else:
             testResult('pass','PASS: Expected querier address found in the \'show ip igmp snooping vlan {0}\' output on switch {1}'.format(vlan, hdl.switchName),log)

    if intf:
      if not 'intf' in snooping_dict:
         testResult('fail','FAIL: Querier Interface info is NOT found in the \'show ip igmp snooping vlan {0}\' output on switch {1}'.format(vlan, hdl.switchName),log)
         verified=False
      else:
          if (intf != snooping_dict['intf']):
             testResult('fail','FAIL: Expected intf NOT found in the \'show ip igmp snooping vlan {0}\' output on switch {1}'.format(vlan, hdl.switchName),log)
             verified=False
          else:
             testResult('pass','PASS: Expected intf found in the \'show ip igmp snooping vlan {0}\' output on switch {1}'.format(vlan, hdl.switchName),log)

    if querier_interval:
      if not 'querier_interval' in snooping_dict:
         if querier_interval == "None" :
             testResult('pass','PASS: Querier Interval info is not found in the \'show ip igmp snooping vlan {0}\' output on the Non-querier switch {1}'.format(vlan, hdl.switchName),log)
         else :
             testResult('fail','FAIL: Querier Interval info is NOT found in the \'show ip igmp snooping vlan {0}\' output on switch {1}'.format(vlan, hdl.switchName),log)
             verified=False
      else:
          if 'querier_interval' in snooping_dict.keys():
            if (querier_interval != snooping_dict['querier_interval']):
              testResult('fail','FAIL: Expected querier interval value NOT found in the \'show ip igmp snooping vlan {0}\' output on switch {1}'.format(vlan, hdl.switchName),log)
              verified=False
            else:
              testResult('pass','PASS: Expected querier interval value found in the \'show ip igmp snooping vlan {0}\' output on switch {1}'.format(vlan, hdl.switchName),log)

    if no_of_router_ports:
      if not 'no_of_router_ports' in snooping_dict:
         testResult('fail','FAIL: Number of Router Ports info is NOT found in the \'show ip igmp snooping vlan {0}\' output on switch {1}'.format(vlan, hdl.switchName),log)
         verified=False
      else:
          if (no_of_router_ports != snooping_dict['no_of_router_ports']):
             testResult('fail','FAIL: Expected number of router ports count NOT found in the \'show ip igmp snooping vlan {0}\' output on switch {1}'.format(vlan, hdl.switchName),log)
             verified=False
          else:
             testResult('pass','PASS: Expected number of router ports count found in the \'show ip igmp snooping vlan {0}\' output on switch {1}'.format(vlan, hdl.switchName),log)

    if no_of_groups:
      if not 'no_of_groups' in snooping_dict:
         testResult('fail','FAIL: Number of Groups info is NOT found in the \'show ip igmp snooping vlan {0}\' output on switch {1}'.format(vlan, hdl.switchName),log)
         verified=False
      else:
          if (no_of_groups != snooping_dict['no_of_groups']):
             testResult('fail','FAIL: Expected number of groups count NOT found in the \'show ip igmp snooping vlan {0}\' output on switch {1}'.format(vlan, hdl.switchName),log)
             verified=False
          else:
             testResult('pass','PASS: Expected number of groups count found in the \'show ip igmp snooping vlan {0}\' output on switch {1}'.format(vlan, hdl.switchName),log)

    if active_ports:
      if not 'active_ports' in snooping_dict:
         testResult('fail','FAIL: Active Ports info is NOT found in the \'show ip igmp snooping vlan {0}\' output on switch {1}'.format(vlan, hdl.switchName),log)
         verified=False
      else:
          for i in active_ports:
            if i not in snooping_dict['active_ports']:
              testResult('fail','FAIL: NOT all active ports are listed in the \'show ip igmp snooping vlan {0}\' output on switch {1}'.format(vlan, hdl.switchName),log)
              verified=False
          for i in snooping_dict['active_ports']:
            if i not in active_ports:
              testResult('fail','FAIL: Additional active ports are listed in the \'show ip igmp snooping vlan {0}\' output on switch {1}'.format(vlan, hdl.switchName),log)
              verified=False
          if verified:
            testResult('pass','PASS: Expected active ports list found in the \'show ip igmp snooping vlan {0}\' output on switch {1}'.format(vlan, hdl.switchName),log)

    if verified:
        msg = 'PASS: verifyIpIgmpSnoopingVlan verification Passed'
        testResult('pass', msg, log)
    else:
        self.result = 'fail'
        msg = 'FAIL: verifyIpIgmpSnoopingVlan verification failed'
        testResult('fail', msg, log)


#########################################################################################

class verifyIpIgmpGroups ():
 
  '''verify IGMP groups on the given (source,grp-list,oif_list)'''
  def __init__(self,hdl,log, *args):
    self.result='pass'

    # Sample Usage
    # verifyIpIgmpGroups (hdl, log,'-mcast_group 224.1.1.1 -group_count 1 -oif_list ["vlan10"] -vrf RED')

    arggrammar={}
    arggrammar['source']='-type str -default *'
    arggrammar['mcast_group']='-type str -required True'
    arggrammar['group_count']='-type int -default 1'
    arggrammar['source_count']='-type int -default 1'
    arggrammar['source_step']='-type str -default 0.0.1.0'
    arggrammar['oif_list']='-type str -required True'
    arggrammar['vrf']='-type str -default default'
    arggrammar['type']='-type str -choices ["dynamic","static","host"] -default dynamic'
    arggrammar['negative']='-type str -default False'
    ns=parserutils_lib.argsToCommandOptions(args,arggrammar,log,'namespace')

    if not ns.VALIDARGS:
        log.warning('Invalid arguments')
        return False

    if ns.type=='static':
        type='S'
    if ns.type=='dynamic':
        type='D'
    if ns.type=='host':
        type='H'

    if not ns.vrf == 'default':
        igmp_dict = utils.getIgmpGroupsDict(hdl, log, '-vrf {0}'.format(ns.vrf))
    else:
        igmp_dict=utils.getIgmpGroupsDict(hdl,log)

    print('\n\nigmp_dict : {0}\n'.format(igmp_dict))
    group_list=getIpList(ns.mcast_group,ns.group_count)
    if ns.source_count>1:
        source_list=getIpList(ns.source,ns.source_count,ns.source_step)
    else:
        source_list=[ns.source]

    print('\n\nsource_list : {0}'.format(source_list))
    print('\n\ngroup_list : {0}'.format(group_list))
    print('\n\noif_list : {0}'.format(ns.oif_list))
    for src in source_list:
        for grp in group_list:
            grp_verified=True
            for intf in utils.strtolist(ns.oif_list):
                if intf.isdigit():
                    intf=utils.normalizeInterfaceName(log,'vlan'+intf)
                else:
                    intf=utils.normalizeInterfaceName(log,intf)
                if (src,grp,type,intf) not in igmp_dict.keys():
                     testResult('fail','IGMP group {0}, source {1}, oif {2} was not found'.format(grp,src,intf),log)
                     grp_verified=False
            if not grp_verified:
                self.result='fail'
                testResult('fail','IGMP group verification on group {0} and source {1} failed'.format(grp,src),log)

    if ns.negative == 'True': 
        if self.result=='fail':
            msg = 'PASS (Negative): verifyIpIgmpGroups verification Passed'
            testResult('pass', msg, log)
        else:
            msg = 'FAIL (Negative): verifyIpIgmpGroups verification failed'
            testResult('fail', msg, log)

    elif ns.negative == 'False':
        if self.result=='pass':
            msg = 'PASS: verifyIpIgmpGroups verification Passed'
            testResult('pass', msg, log)
        else:
            self.result = 'fail'
            msg = 'FAIL: verifyIpIgmpGroups verification failed'
            testResult('fail', msg, log)


class verifyIpIgmpSnoopingGroups ():

    def __init__(self,hdl,log, *args):
        self.result='pass'
    
        # Sample Usage
        # verifyIpIgmpSnoopingGroups (hdl, log,'-mcast_group 224.1.1.1 -group_count 1 -oif_list ["vlan10"])
    
        arggrammar={}
        arggrammar['source']='-type str -default *'
        arggrammar['source_count']='-type int -default 1'
        arggrammar['source_step']='-type str -default 0.0.1.0'
        arggrammar['mcast_group']='-type str -required True'
        arggrammar['group_count']='-type int -required True'
        arggrammar['vlan_list']='-type str -required True'
        arggrammar['oif_list']='-type str -required True'
        arggrammar['type']='-type str -choices ["dynamic","static"] -default dynamic'
        arggrammar['igmp_version']='-type str -choices ["v2","v3"] -default v2'
        ns=parserutils_lib.argsToCommandOptions(args,arggrammar,log,'namespace')
    
        if not ns.VALIDARGS:
            log.warning('Invalid arguments')
            return False
    
        if ns.type=='static':
            type='S'
        else:
            type='D'
    
        exp_dict={}
        group_list=getIpList(ns.mcast_group,ns.group_count)
        if ns.source_count>1:
             source_list=getIpList(ns.source,ns.source_count,ns.source_step)
        else:
             source_list=[ns.source]
    
        for src in source_list:
            for group in group_list:
                for vlan in utils.strtolist(ns.vlan_list):
                    exp_dict[vlan,src,group,ns.igmp_version,type]=utils.strtolist(ns.oif_list)
    
        ret=verify_lib.verifyIgmpSnoopingGroups(hdl,log,value=exp_dict)
    
        if ret.result=='pass':
            msg = 'PASS: verifyIpIgmpSnoopingGroups verification Passed'
            testResult('pass', msg, log)
        else:
            self.result = 'fail'
            msg = 'FAIL: verifyIpIgmpSnoopingGroups verification failed'
            testResult('fail', msg, log)



#########################################################################################
def clearIgmpSnoopingStatistics (self, hdl, vlanList, log):
    '''Method to clear Igmp Snooping Statistics Counters'''

    print('Clearing Igmp Snooping Statistics')

    for vlan in vlanList:
       out = ''
       out=hdl.iexec('clear ip igmp snooping statistics vlan {0}'.format(vlan))
       print('Output : {0}'.format(out))

       if out != '' :
         self.result = 'fail'
         msg = 'TEST FAILED. Clearing Igmp Snooping Statistics is supposed to return NULL value. Whereas it returned {0} on Switch {1}'.format(out, hdl.switchName)
         testResult('fail', msg, self.log)


def getIgmpSnoopingStatistics (self, hdl, vlan, log):
    '''Method to get Igmp Snooping Statistics'''

    IgmpSnoopingStatsDict={}   
    IgmpSnoopingStatsDict['ReportsRcvd']=0
    IgmpSnoopingStatsDict['LeavesRcvd']=0
    
    output=hdl.iexec('show ip igmp snooping statistics vlan {0}'.format(vlan)) 
    print('\nOutput : {0}'.format(output))

    reports = leaves = ['0']
    #print reports[0]

    if (re.findall('IGMPv2 reports received\: (\d+)',output)):
        reports=re.findall('IGMPv2 reports received\: (\d+)',output)
        print('\nreports : {0}'.format(reports[0]))
 
    if (re.findall('IGMPv2 leaves received\: (\d+)',output)): 
        leaves=re.findall('IGMPv2 leaves received\: (\d+)',output)
        print('\nleaves : {0}'.format(leaves[0]))
 
    IgmpSnoopingStatsDict['ReportsRcvd'] = reports[0]
    IgmpSnoopingStatsDict['LeavesRcvd'] = leaves[0]
    return IgmpSnoopingStatsDict


def getIpMrouteList (self, hdl, log):
    '''Method to get the list of IPs in show ip mroute list'''
    ipMrouteList = []
    output=hdl.iexec('show ip mroute')
    self.log.info('\nOutput : {0}'.format(output))
    match = re.findall(r'\(.*, ([\d\.]+).*\), uptime',output)
    self.log.info ('match : {0}'.format(match))
    for mroute in match :
        details = utils.strtolist(mroute)
        ipMrouteList.append(details[0])
    self.log.info ('ipMrouteList : {0}'.format(ipMrouteList))
    ipMrouteList.remove('232.0.0.0')
    self.log.info ('ipMrouteList after removing 232.0.0.0: {0}'.format(ipMrouteList))
    return ipMrouteList


def getIpPimRouteList (self, hdl, log):
    '''Method to get the list of IPs in show ip pim route list'''
    ipPimRouteList = []
    output=hdl.iexec('show ip pim route')
    self.log.info('\nOutput : {0}'.format(output))
    match = re.findall(r'\(.*, ([\d\.]+).*\),.*expires',output)
    self.log.info ('match : {0}'.format(match))
    for mroute in match :
        details = utils.strtolist(mroute)
        ipPimRouteList.append(details[0])
    self.log.info ('ipPimRouteList : {0}'.format(ipPimRouteList))
    ipPimRouteList.remove('232.0.0.0')
    self.log.info ('ipPimRouteList after removing 232.0.0.0: {0}'.format(ipPimRouteList))
    return ipPimRouteList



def enableDisableIgmpReportSupression (self, hdl, version = 'v2', operation = 'enable'):
    '''Method to enable/disable Igmp report supression'''

    print ('hdl : {0}'.format(hdl)) 
    print ('version : {0}'.format(version)) 
    print ('operation : {0}'.format(operation)) 

    output = hdl.iexec ('show run igmp all | grep report-suppression')
    print ('Output : {0}'.format(output))

    if operation == 'enable':
        if (re.match('ip igmp snooping report-suppression', output)):
            self.log.info('Report suppression already enabled on switch : {0}'. format(hdl.switchName))
            print('Enabled')
        else :
            hdl.configure('ip igmp snooping report-suppression')
            cmd_out = hdl.iexec ('show run igmp all | grep report-suppression')
            print ('cmd_output : {0}'.format(cmd_out))
            if not (re.match('ip igmp snooping report-suppression', cmd_out)):
                print('Failed')
                self.result = 'fail'
                msg = 'FAIL: Igmp report suppression config failed on switch {0}'.format(hdl.switchName)
                testResult('fail', msg, self.log)
            else :
                print('Passed')
                self.result = 'pass'
                msg = 'PASS: Igmp report suppression config passed on switch {0}'.format(hdl.switchName)
                testResult('pass', msg, self.log)


    elif operation == 'disable':
        if (re.match('no ip igmp snooping report-suppression', output)):
            self.log.info('Report suppression already disabled on switch : {0}'. format(hdl.switchName))
            print('Disabled')
        else :
            hdl.configure('no ip igmp snooping report-suppression')
            cmd_out = hdl.iexec ('show run igmp all | grep report-suppression')
            print ('cmd_output : {0}'.format(cmd_out))
            if not (re.match('no ip igmp snooping report-suppression', cmd_out)):
                print('Failed')
                self.result = 'fail'
                msg = 'FAIL: Igmp report suppression unconfig failed on switch {0}'.format(hdl.switchName)
                testResult('fail', msg, self.log)
            else :
                print('Passed')
                self.result = 'pass'
                msg = 'PASS: Igmp report suppression unconfig passed on switch {0}'.format(hdl.switchName)
                testResult('pass', msg, self.log)


def configUnconfgPimRpAddress (self, hdl, rp_address, policy, operation = 'config'):
    '''Method to config/unconfig Ip PIM RP address'''

    print ('hdl : {0}'.format(hdl)) 
    print ('rp_address : {0}'.format(rp_address)) 
    print ('policy : {0}'.format(policy)) 
    print ('operation : {0}'.format(operation)) 

    output = hdl.iexec ('show run pim')
    print ('Output : {0}'.format(output))

    if operation == 'config':
        if (re.findall('ip pim rp-address {0} route-map {1}'.format(rp_address,policy), output)):
            self.log.info('Policy {0} is already configured for RP address {1} on switch : {2}'. format(policy,rp_address,hdl.switchName))
        else :
            hdl.configure('ip pim rp-address {0} route-map {1}'.format(rp_address,policy))
            cmd_out = hdl.iexec ('show run pim')
            print ('cmd_output : {0}'.format(cmd_out))
            if not (re.findall('ip pim rp-address {0} route-map {1}'.format(rp_address,policy), cmd_out)):
                self.result = 'fail'
                msg = 'FAIL: Policy {0} configuration for RP address {1} failed on switch {2}'.format(policy,rp_address,hdl.switchName)
                testResult('fail', msg, self.log)
            else :
                msg = 'PASS: Policy {0} configuration for RP address {1} passed on switch {2}'.format(policy,rp_address,hdl.switchName)
                testResult('pass', msg, self.log)


    elif operation == 'unconfig':
        if not (re.findall('ip pim rp-address {0} route-map {1}'.format(rp_address,policy), output)):
            self.log.info('Policy {0} for RP address {1} is not avaliable for unconfiguration on switch : {2}'. format(policy,rp_address,hdl.switchName))
        else :
            hdl.configure('no ip pim rp-address {0} route-map {1}'.format(rp_address,policy))
            cmd_out = hdl.iexec ('show run pim')
            print ('cmd_output : {0}'.format(cmd_out))
            if (re.findall('ip pim rp-address {0} route-map {1}'.format(rp_address,policy), cmd_out)):
                self.result = 'fail'
                msg = 'FAIL: Policy {0} unconfiguration for RP address {1} failed on switch {2}'.format(policy,rp_address,hdl.switchName)
                testResult('fail', msg, self.log)
            else :
                msg = 'PASS: Policy {0} unconfiguration for RP address {1} passed on switch {2}'.format(policy,rp_address,hdl.switchName)
                testResult('pass', msg, self.log)


def getIgmpMrouterPorts (self, hdl, log):
    '''Method to get the list of mrouter ports'''

    mrouterList = []
    output=hdl.iexec('show ip igmp snooping mrouter')
    print('\nOutput : {0}'.format(output))

    pattern='[0-9]+ +{0} +[SDVIFU]+ +{1} +{2}'.format(rex.INTERFACE_NAME,rex.UPTIME,rex.XPTIME)
    match = re.findall(pattern,output)
    print ('match : {0}'.format(match))

    for mrouter in match :
        details = utils.strtolist(mrouter)
        mrouterList.append(details[1])
    print ('mrouterList : {0}'.format(mrouterList))
    return mrouterList


def getIpList(start_addr, count,step='0.0.0.1'):
    ip_list=utils.getIPv4AddressesList(start_addr,step,count)
    ret_ip_list=[]
    for ip in ip_list:
        ret_ip_list.append(re.sub('/32','',ip))
    return ret_ip_list


def getMaxIp (ipList):
    ipDict = {}
    for ip in ipList :
        match = re.findall('(\d+)\.(\d+)\.(\d+)\.(\d+)',ip)[0]
        newIp = ""
        for i in range( 0, 4):
            if len(match[i]) == 1 :
                formatIp = '00' + match[i]
            elif len(match[i]) == 2 :
                formatIp = '0' + match[i]
            else :
                formatIp = match[i]
            newIp += formatIp
            if i < 3 :
                newIp += '.'
        ipDict[newIp] = ip

    maxIp = max(ipDict.keys())
    return(ipDict[maxIp])


 

######################################################################################
######                            IGMP Host Proxy Code                          ######
######################################################################################

def parseIgmpHostProxyConfigs(log, args):

    arggrammar={}
    arggrammar['route_map']='-type str -default None'
    arggrammar['prefix_list']='-type str -default None'
    arggrammar['unsolicited']='-type str -default None'
    arggrammar['vrf']='-type str -default default'
    return parserutils_lib.argsToCommandOptions( args, arggrammar, log)


#====================================================================================#
# configIGMPHostProxy - Class to configure IGMP Host Proxy on the interfaces based on 
# the igmp_host_proxy_dict defined in the topology file.
#====================================================================================#


class configIGMPHostProxy(object):

    def __init__( self, igmp_host_proxy_dict, switch_hdl_dict, log, *args ):

        arggrammar={}
        arggrammar['dut']='-type str -default all'
        parse_output=parserutils_lib.argsToCommandOptions(args,arggrammar,log)
        self.dut=parse_output.dut

        self.log=log
        self.result='pass'
        self.log.info('configIGMPHostProxy starts...')

        self.igmp_host_proxy_dict = igmp_host_proxy_dict
        self.log.info('self.dut : {0}'.format(self.dut))
        try:
             if not self.dut == "all" :
                 self.list_of_nodes = utils.strtolist(self.dut)
             else :
                 self.list_of_nodes=sorted(self.igmp_host_proxy_dict.keys())
        except KeyError:
             testResult('fail','igmp_host_proxy_dict in input file not defined properly .. does not have any keys ..',self.log)
             self.result='fail'
             return None

        self.log.info('self.list_of_nodes : {0}'.format(self.list_of_nodes))
        self.switch_hdl_dict=switch_hdl_dict

        for node in self.list_of_nodes:
             hdl=self.switch_hdl_dict[node]

             # Configure IGMP Host Proxy configs ..
             for intf in self.igmp_host_proxy_dict[node].keys():
                 cmd = 'ip igmp host-proxy '
 
                 igmpNs = parseIgmpHostProxyConfigs(self.log,self.igmp_host_proxy_dict[node][intf])
                 print('\n==> igmpNs : {0}'.format(igmpNs))

                 if not igmpNs.vrf == 'default':
                     sw_cmd = '''vrf context {0}
                                 ip multicast multipath legacy'''.format(igmpNs.vrf)
                     hdl.configure(sw_cmd)
                 else:
                     hdl.configure("ip multicast multipath legacy")
                   
                 if not igmpNs.route_map == 'None':
                     cmd = cmd + 'route-map {0}'.format(igmpNs.route_map)

                 if not igmpNs.prefix_list == 'None':
                     cmd = cmd + 'prefix-list {0}'.format(igmpNs.prefix_list)

                 if not igmpNs.unsolicited == 'None':
                     cmd = cmd + 'unsolicited {0}'.format(igmpNs.unsolicited)

 
                 sw_cmd = '''interface {0} 
                             {1}'''.format(intf, cmd) 
                 print('\n\n cmd : {0}'.format(cmd))
                 hdl.configure(sw_cmd)


                 outputChk = hdl.iexec('show run int  {0}'.format(intf))
                 print('\nOutput Check : {0}'.format(outputChk))

                 if not (re.findall('{0}'.format(cmd), outputChk)):
                     self.result = 'fail'
                     self.log.error('IGMP Host Proxy is not configured on the interface {0}'.format(intf))




            

def getIgmpHostProxyPorts (self, hdl, log):
    '''Method to get the list of igmp host proxy enabled ports'''

    intfList = []
    output=hdl.iexec('show run igmp | section interface')
    print('\nOutput : {0}'.format(output))

    outputLines=output.split("\n")
    self.log.info('\noutputLines : {0}'.format(outputLines))

    for line in outputLines:
        self.log.info('\nline : {0}'.format(line))

        if (outputLines.index(line) + 1) == len(outputLines):
            break

        nextLine = outputLines[outputLines.index(line) + 1 ]
        if(re.findall('host-proxy',nextLine)):
            match = re.findall('interface (.*)',line)[0]
            print ('match : {0}'.format(match))
            match = match.rstrip('\r')
            print ('match : {0}'.format(match))
            intfList.append(match)

    print ('\nintfList : {0}'.format(intfList))
    return intfList



