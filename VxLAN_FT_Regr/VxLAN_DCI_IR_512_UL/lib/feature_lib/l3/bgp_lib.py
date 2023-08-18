
import os
import sys
import yaml
import re

import utils
from utils import *
import  bringup_lib
import parserutils_lib
import verify_lib



## Parsing Bgp dashed args ..

def parseBgpRouterConfigs(log, args):

    arggrammar={}
    arggrammar['router_id']='-type str'
    arggrammar['log_neighbor_changes']='-type bool -default True'
    arggrammar['max_as_limit']='-type int -default 10'
    arggrammar['graceful_restart']='-type bool -default True'
    arggrammar['flush_routes']='-type bool -default True'
    arggrammar['keep_alive_time']='-type int'
    arggrammar['hold_time']='-type int'
    arggrammar['prefix_peer_timeout']='-type int -default 30'
    arggrammar['best_path_limit_timeout']='-type int -default 300'
    arggrammar['reconnect_interval']='-type int -default 1'
    arggrammar['bestpath_aspath_multipath_relax'] = '-type bool -default False'
    ns=parserutils_lib.argsToCommandOptions( args, arggrammar, log )
    return ns



def parseBgpTemplate(log, args):
    arggrammar={}
    arggrammar['address_family']='-type str -choices ["ipv4_unicast","ipv4_multicast", \
         "ipv6_unicast", "ipv6_multicast" , "ipv4_mpvn", "l2vpn_evpn"] -default ipv4_unicast'
    arggrammar['description']='-type str'
    arggrammar['local_as']='-type str'
    arggrammar['remote_as']='-type str'
    arggrammar['password']='-type str'
    arggrammar['password_type']='-type str -choices ["0","3","7"] -default 0'
    arggrammar['keep_alive_time']='-type int'
    arggrammar['hold_time']='-type int'
    arggrammar['ebgp_multihop']='-type int'
    arggrammar['update_source']='-type str'
    arggrammar['bfd']='-type bool -default False'
    arggrammar['dynamic_capability']='-type bool -default True'
    arggrammar['maximum_prefix']='-type int'
    arggrammar['allow_as_in']='-type int'
    arggrammar['route_reflector_client']='-type bool'
    arggrammar['next-hop-self']='-type bool'
    arggrammar['soft_reconfiguration']='-type bool'
    arggrammar['send_community']='-type bool'
    arggrammar['send_community_extended']='-type bool'
    arggrammar['log_neighbor_changes']='-type bool'
    arggrammar['peer_type'] = '-type str -choices ["fabric-external",fabric-border-leaf"]'
    arggrammar['rewrite_evpn_rt_asn'] = '-type bool'
    ns=parserutils_lib.argsToCommandOptions( args, arggrammar, log )
    return ns

def parseBgpAfL2vpnEvpn(log, args):
    arggrammar={}
    arggrammar['allow_as_in']='-type int'
    arggrammar['maximum_prefix']='-type int'
    arggrammar['disable_peer_as_check']='-type bool -default False'
    arggrammar['filter_list']='-type str'
    arggrammar['maximum_prefix']='-type int'
    arggrammar['next_hop_third_party']='-type bool'
    arggrammar['route_map']='-type str'
    arggrammar['route_map_direction']='-type str -choices ["in","out"] -default in'
    arggrammar['prefix_list']='-type str'
    arggrammar['encapsulation']='-type str'
    arggrammar['route_reflector_client']='-type bool'
    arggrammar['send_community']='-type bool'
    arggrammar['send_community_extended']='-type bool'
    arggrammar['soft_reconfiguration']='-type bool'
    arggrammar['next_hop_self']='-type bool'
    arggrammar['rewrite_evpn_rt_asn'] = '-type bool'
    ns=parserutils_lib.argsToCommandOptions( args, arggrammar, log )
    return ns

def parseBgpAfIpv4Mvpn(log, args):
    arggrammar={}
    arggrammar['allow_as_in']='-type int'
    arggrammar['maximum_prefix']='-type int'
    arggrammar['disable_peer_as_check']='-type bool -default False'
    arggrammar['filter_list']='-type str'
    arggrammar['maximum_prefix']='-type int'
    arggrammar['next_hop_third_party']='-type bool'
    arggrammar['route_map']='-type str'
    arggrammar['route_map_direction']='-type str -choices ["in","out"] -default in'
    arggrammar['prefix_list']='-type str'
    arggrammar['encapsulation']='-type str'
    arggrammar['route_reflector_client']='-type bool'
    arggrammar['send_community']='-type bool'
    arggrammar['send_community_extended']='-type bool'
    arggrammar['soft_reconfiguration']='-type bool'
    arggrammar['next_hop_self']='-type bool'
    arggrammar['rewrite_rt_asn'] = '-type bool'
    ns=parserutils_lib.argsToCommandOptions( args, arggrammar, log )
    return ns

def parseBgpAfIpv6Mvpn(log, args):
    arggrammar={}
    arggrammar['allow_as_in']='-type int'
    arggrammar['maximum_prefix']='-type int'
    arggrammar['disable_peer_as_check']='-type bool -default False'
    arggrammar['filter_list']='-type str'
    arggrammar['maximum_prefix']='-type int'
    arggrammar['next_hop_third_party']='-type bool'
    arggrammar['route_map']='-type str'
    arggrammar['route_map_direction']='-type str -choices ["in","out"] -default in'
    arggrammar['prefix_list']='-type str'
    arggrammar['encapsulation']='-type str'
    arggrammar['route_reflector_client']='-type bool'
    arggrammar['send_community']='-type bool'
    arggrammar['send_community_extended']='-type bool'
    arggrammar['soft_reconfiguration']='-type bool'
    arggrammar['next_hop_self']='-type bool'
    arggrammar['rewrite_rt_asn'] = '-type bool'
    ns=parserutils_lib.argsToCommandOptions( args, arggrammar, log )
    return ns

def parseBgpNeighborTemplate(log, args):
     arggrammar={}
     arggrammar['inherit_peer']='-type str'
     ns=parserutils_lib.argsToCommandOptions( args, arggrammar, log )
     return ns


def parseBgpNeighborParams(log, args):
    arggrammar={}
    arggrammar['vrf_name']='-type str -default default'
    arggrammar['remote_as']='-type str'
    arggrammar['address_family']='-type str -choices ["ipv4_unicast","ipv4_multicast", \
         "ipv6_unicast", "ipv6_multicast" ] -default ipv4_unicast'
    arggrammar['keep_alive_time']='-type int'
    arggrammar['hold_time']='-type int'
    arggrammar['description']='-type str'
    arggrammar['bfd']='-type bool -default False'
    arggrammar['update_source']='-type str'
    arggrammar['ebgp_multihop']='-type int'
    arggrammar['route_map']='-type str'
    arggrammar['password_type']='-type str -choices ["0","3","7"] -default 0'
    arggrammar['password']='-type str'
    arggrammar['transport_connection_mode']='-type str -choices ["active", "passive"] -default active'
    arggrammar['low_memory_action']='-type str -choices ["exempt", "shutdown"] -default shutdown'
    arggrammar['disable_capability_negotation']='-type bool -default False'
    arggrammar['disable_connected_check']='-type bool -default False'
    arggrammar['dynamic_capability']='-type bool -default True'
    arggrammar['suppress_4_byte_as']='-type bool -default False'
    arggrammar['peer_policy']='-type str'
    arggrammar['neighbor_step']='-type str -default 0.0.0.1'
    arggrammar['neighbor_count']='-type int -default 1'
    arggrammar['remote_as_step']='-type int -default 0'
    arggrammar['inherit_peer']='-type str'
    arggrammar['peer']='-type str'
    arggrammar['intf']='-type str'
    arggrammar['peer_intf']='-type str'
 
    ns=parserutils_lib.argsToCommandOptions( args, arggrammar, log )
    return ns



def parseBgpv6NeighborParams(log, args):
    arggrammar={}
    arggrammar['vrf_name']='-type str -default default'
    arggrammar['remote_as']='-type str'
    arggrammar['address_family']='-type str -choices [ \
         "ipv6_unicast", "ipv6_multicast" ] -default ipv6_unicast'
    arggrammar['keep_alive_time']='-type int'
    arggrammar['hold_time']='-type int'
    arggrammar['description']='-type str'
    arggrammar['bfd']='-type bool -default False'
    arggrammar['update_source']='-type str'
    arggrammar['ebgp_multihop']='-type int'
    arggrammar['route_map']='-type str'
    arggrammar['password_type']='-type str -choices ["0","3","7"] -default 0'
    arggrammar['password']='-type str'
    arggrammar['transport_connection_mode']='-type str -choices ["active", "passive"] -default active'
    arggrammar['low_memory_action']='-type str -choices ["exempt", "shutdown"] -default shutdown'
    arggrammar['disable_capability_negotation']='-type bool -default False'
    arggrammar['disable_connected_check']='-type bool -default False'
    arggrammar['dynamic_capability']='-type bool -default True'
    arggrammar['suppress_4_byte_as']='-type bool -default False'
    arggrammar['peer_policy']='-type str'
    arggrammar['neighbor_step']='-type str -default 0::1'
    arggrammar['neighbor_count']='-type int -default 1'
    arggrammar['remote_as_step']='-type int -default 0'
 
    ns=parserutils_lib.argsToCommandOptions( args, arggrammar, log )
    return ns




def parseGlobalAfIpv4Unicast( log, args ):
    arggrammar={}
    arggrammar['aggregate_address_list']='-type str'
    arggrammar['client_to_client_reflection']='-type bool -default False'
    arggrammar['dampening']='-type bool -default False'
    arggrammar['dampening_half_life']='-type int'
    arggrammar['default_metric']='-type int -default 0'
    arggrammar['ebgp_distance']='-type int -default 20'
    arggrammar['ibgp_distance']='-type int -default 200'
    arggrammar['local_distance']='-type int -default 220'
    arggrammar['maximum_paths']='-type int -default 8'
    arggrammar['maximum_paths_ibgp']='-type int -default 8'
    arggrammar['suppress_inactive']='-type bool -default False'
    arggrammar['network_list']='-type str'
    arggrammar['network_count']='-type int -default 1'
    arggrammar['network_step']='-type str -default 0.0.1.0'
    ns=parserutils_lib.argsToCommandOptions( args, arggrammar, log )
    return ns

def parseGlobalAfL2vpnEvpn( log, args ):
    arggrammar={}
    arggrammar['dampening']='-type bool -default False'
    arggrammar['maximum_paths']='-type int -default 8'
    arggrammar['maximum_paths_ibgp']='-type int -default 8'
    arggrammar['advertise_pip']='-type bool -default False'
    arggrammar['retain_route_target_all'] = '-type bool -default False'
    ns=parserutils_lib.argsToCommandOptions( args, arggrammar, log )
    return ns

def parseGlobalAfipv4mpvn( log, args ):
    arggrammar={}
    arggrammar['maximum_paths']='-type int -default 8'
    arggrammar['maximum_paths_ibgp']='-type int -default 8'
    arggrammar['retain_route_target_all'] = '-type bool -default False'
    ns=parserutils_lib.argsToCommandOptions( args, arggrammar, log )
    return ns

def parseGlobalAfipv6mpvn( log, args ):
    arggrammar={}
    arggrammar['maximum_paths']='-type int -default 8'
    arggrammar['maximum_paths_ibgp']='-type int -default 8'
    arggrammar['retain_route_target_all'] = '-type bool -default False'
    ns=parserutils_lib.argsToCommandOptions( args, arggrammar, log )
    return ns

def parseBgpRedistributionConfigs( log, args ):
    arggrammar={}
    arggrammar['tag_name']='-type str'
    arggrammar['route_map']='-type str'
    ns=parserutils_lib.argsToCommandOptions( args, arggrammar, log )
    return ns

def parseGlobalAfIpv6Unicast( log, args ):
    arggrammar={}
    arggrammar['aggregate_address_list']='-type str'
    arggrammar['client_to_client_reflection']='-type bool -default False'
    arggrammar['dampening']='-type bool -default False'
    arggrammar['dampening_half_life']='-type int'
    arggrammar['default_metric']='-type int -default 0'
    arggrammar['ebgp_distance']='-type int -default 20'
    arggrammar['ibgp_distance']='-type int -default 200'
    arggrammar['local_distance']='-type int -default 220'
    arggrammar['maximum_paths']='-type int -default 8'
    arggrammar['maximum_paths_ibgp']='-type int -default 8'
    arggrammar['suppress_inactive']='-type bool -default False'
    arggrammar['network_list']='-type str'
    arggrammar['network_count']='-type int -default 1'
    arggrammar['network_step']='-type str -default 0::1:0'
    ns=parserutils_lib.argsToCommandOptions( args, arggrammar, log )
    return ns


def parseBgpAfIpv4Unicast(log, args):
    arggrammar={}
    arggrammar['allow_as_in']='-type int'
    arggrammar['as_override']='-type bool'
    arggrammar['maximum_prefix']='-type int'
    arggrammar['default_originate']='-type bool'
    arggrammar['default_originate_route_map']='-type str'
    arggrammar['disable_peer_as_check']='-type bool -default False'
    arggrammar['filter_list']='-type str'
    arggrammar['peer_policy']='-type str'
    arggrammar['maximum_prefix']='-type int'
    arggrammar['next_hop_self']='-type bool'
    arggrammar['next_hop_third_party']='-type bool'
    arggrammar['prefix_list']='-type str'
    arggrammar['prefix_list_direction']='-type str -choices ["in","out"] -default in'
    arggrammar['route_reflector_client']='-type bool'
    arggrammar['send_community']='-type bool'
    arggrammar['send_community_extended']='-type bool'
    arggrammar['soft_reconfiguration']='-type bool'
    arggrammar['suppress_inactive']='-type bool -default False'
    arggrammar['route_map']='-type str'
    arggrammar['route_map_direction']='-type str -choices ["in","out"] -default in'
    arggrammar['weight']='-type int'
    arggrammar['advertise_map']='-type str'
    arggrammar['advertise_exist_map']='-type str'
    arggrammar['network_list']='-type str'
    arggrammar['network_count']='-type int -default 1'
    arggrammar['network_step']='-type str -default 0.0.1.0'
    arggrammar['rewrite_evpn_rt_asn'] = '-type str'
    ns=parserutils_lib.argsToCommandOptions( args, arggrammar, log )
    return ns



def parseBgpAfIpv6Unicast(log, args):
    arggrammar={}
    arggrammar['allow_as_in']='-type int'
    arggrammar['as_override']='-type bool'
    arggrammar['maximum_prefix']='-type int'
    arggrammar['default_originate']='-type bool'
    arggrammar['default_originate_route_map']='-type str'
    arggrammar['disable_peer_as_check']='-type bool -default False'
    arggrammar['filter_list']='-type str'
    arggrammar['peer_policy']='-type str'
    arggrammar['maximum_prefix']='-type int'
    arggrammar['next_hop_self']='-type bool'
    arggrammar['next_hop_third_party']='-type bool'
    arggrammar['prefix_list']='-type str'
    arggrammar['prefix_list_direction']='-type str -choices ["in","out"] -default in'
    arggrammar['route_reflector_client']='-type bool'
    arggrammar['send_community']='-type bool'
    arggrammar['send_community_extended']='-type bool'
    arggrammar['soft_reconfiguration']='-type bool'
    arggrammar['suppress_inactive']='-type bool -default True'
    arggrammar['route_map']='-type str'
    arggrammar['route_map_direction']='-type str -choices ["in","out"] -default in'
    arggrammar['weight']='-type int'
    arggrammar['advertise_map']='-type str'
    arggrammar['advertise_exist_map']='-type str'
    arggrammar['network_list']='-type str'
    arggrammar['network_count']='-type int -default 1'
    arggrammar['network_step']='-type str -default 0::1:0'
    ns=parserutils_lib.argsToCommandOptions( args, arggrammar, log )
    return ns


class configBgp():
    def __init__(self,bgp_config_dict,switch_hdl_dict,log):
        self.log=log
        self.result='pass'
        self.bgp_config_dict=bgp_config_dict
        self.switch_hdl_dict=switch_hdl_dict
        log.info('Insider ConfigBGP class')
        try:
           self.list_of_nodes=self.bgp_config_dict.keys()
        except KeyError:
           err_msg='Error !!! bgp_config_dict has not been defined properly, does not have nodes   \
              as the top level keys'
           testResult( 'fail', err_msg, self.log )

    def AllNodes(self):
        for node in self.list_of_nodes:
           self.Nodes(node)
           
    def Nodes(self,node):
            self.log.info(node)
            hdl=self.switch_hdl_dict[node]
            kdict={}
            kdict['verifySuccess']=True
            bringup_lib.configFeature( hdl, self.log, '-feature bgp' )
            # Enable feature Bgp
            #bringup_lib.configFeature( hdl, self.log, '-feature bgp' )

            as_nos=self.bgp_config_dict[node].keys()

            # In future if we allow multiple AS
            for as_no in as_nos:
              asdotpat="\d+\.\d+"
              asno="{0}".format(as_no)
              if re.findall(asdotpat,asno):
                     cfg='''as-format asdot'''
                     hdl.configure(cfg,**kdict)
              vrf_list=self.bgp_config_dict[node][as_no].keys()
              #VRF
              for vrf_name in vrf_list:
                 # Build Router configs ..
                 if 'evpn_default' in self.bgp_config_dict[node][as_no][vrf_name]:
                         cfg = '''router bgp {0}
                                   vrf {1}
                                '''.format( as_no, vrf_name )
                         hdl.configure(cfg,**kdict) 
                 if 'router_configs' in self.bgp_config_dict[node][as_no][vrf_name]:
                                  
                    ns=parseBgpRouterConfigs( self.log, self.bgp_config_dict[node][as_no]           \
                        [vrf_name]['router_configs'] )
                    print(ns)
                    if vrf_name == "default":
                            cfg = '''router bgp {0}
                                     '''.format( as_no )
                    else:
                            cfg = '''router bgp {0}
                                     vrf {1}
                                    '''.format( as_no, vrf_name )
                      
                    if hasattr (ns, 'router_id') and ns.router_id:
                       cfg = cfg + '\n' + \
                               '''router-id {0}'''.format(ns.router_id)
                    if hasattr (ns, 'prefix_peer_timeout') and ns.prefix_peer_timeout:
                       cfg = cfg + '\n' + \
                               '''timers prefix-peer-timeout {0}'''.format(ns.prefix_peer_timeout)
                    if hasattr (ns, 'best_path_limit_timeout') and ns.best_path_limit_timeout:
                       cfg = cfg + '\n' + \
                               '''timers bestpath-limit {0}'''.format(ns.best_path_limit_timeout)
                    if hasattr( ns, 'keep_alive_time') and hasattr( ns, 'hold_time') and ns.hold_time and ns.keep_alive_time:
                       cfg = cfg + '\n' +  \
                              '''timers bgp {0} {1}'''.format(ns.keep_alive_time, ns.hold_time)
                       
                    if ns.log_neighbor_changes:
                       cfg = cfg + '\n' +  \
                              '''log-neighbor-changes'''

                    if hasattr( ns, 'max_as_limit' ):
                       cfg = cfg + '\n' +  \
                             '''maxas-limit {0}'''.format( ns.max_as_limit )

                    if hasattr( ns, 'graceful_restart' ):
                       cfg = cfg + '\n' +  \
                             '''graceful-restart'''

                    if hasattr( ns, 'reconnect_interval') and ns.reconnect_interval:
                       cfg = cfg + '\n' +  \
                             '''reconnect-interval {0}'''.format(ns.reconnect_interval)
                             
                    if hasattr( ns, 'bestpath_aspath_multipath_relax') and ns.bestpath_aspath_multipath_relax:
                       cfg = cfg + '\n' +  \
                             '''bestpath as-path multipath-relax'''

                    # Apply the BGP router configs ..          
                    hdl.configure(cfg,**kdict)
                    
                 # Global Address Family   
                 if 'address_family' in self.bgp_config_dict[node][as_no][vrf_name]:
                     
                     for family in self.bgp_config_dict[node][as_no][vrf_name]['address_family'].keys():
                       #IPV4_Unicast     
                       if family == "ipv4_unicast":
                           
                           ns=parseGlobalAfIpv4Unicast( self.log, self.bgp_config_dict[node][as_no]        \
                              [vrf_name]['address_family']['ipv4_unicast'] )

                           if vrf_name == "default":
                               cfg = '''router bgp {0}
                                     address-family ipv4 unicast'''.format( as_no )
                           else:
                               cfg = '''router bgp {0}
                                        vrf {1}
                                        address-family ipv4 unicast'''.format( as_no, vrf_name )
                       
                       #Ipv6 unicast                 
                       if family == "ipv6_unicast":
                           
                           ns=parseGlobalAfIpv4Unicast( self.log, self.bgp_config_dict[node][as_no]        \
                              [vrf_name]['address_family']['ipv6_unicast'] )

                           if vrf_name == "default":
                               cfg = '''router bgp {0}
                                     address-family ipv6 unicast'''.format( as_no )
                           else:
                               cfg = '''router bgp {0}
                                        vrf {1}
                                        address-family ipv6 unicast'''.format( as_no, vrf_name )
                       #L2vpn
                       if family == "l2vpn":
                            ns=parseGlobalAfL2vpnEvpn( self.log, self.bgp_config_dict[node][as_no][vrf_name]['address_family']['l2vpn'] )
                            print('The value of ns is  : {0}'.format(ns))
                            if vrf_name == "default":
                                 cfg = '''nv overlay evpn
                                       router bgp {0}
                                       address-family l2vpn evpn'''.format( as_no )
                             # Config ebgp maximum-paths ..       
                            if hasattr( ns, 'maximum_paths') and ns.maximum_paths is not None:
                                 cfg = cfg + '\n' + \
                                   '''maximum-paths {0}'''.format( ns.maximum_paths )

                            # Config ibgp maximum-paths ..       
                            if hasattr( ns, 'maximum_paths_ibgp') and ns.maximum_paths_ibgp is not None:
                                 cfg = cfg + '\n' + \
                                   '''maximum-paths ibgp {0}'''.format( ns.maximum_paths_ibgp )

                            if hasattr( ns, 'advertise_pip') and ns.advertise_pip is True:
                                 cfg = cfg + '\n' + \
                                   '''advertise-pip'''
                       #mvpn
                       if family == "ipv4_mvpn":
                            ns=parseGlobalAfipv4mpvn( self.log, self.bgp_config_dict[node][as_no][vrf_name]['address_family']['ipv4_mvpn'] )
                            if vrf_name == "default":
                                 cfg = '''router bgp {0}
                                       address-family ipv4 mvpn'''.format( as_no )
                             # Config ebgp maximum-paths ..       
                            if hasattr( ns, 'maximum_paths') and ns.maximum_paths is not None:
                                 cfg = cfg + '\n' + \
                                   '''maximum-paths {0}'''.format( ns.maximum_paths )

                            # Config ibgp maximum-paths ..       
                            if hasattr( ns, 'maximum_paths_ibgp') and ns.maximum_paths_ibgp is not None:
                                 cfg = cfg + '\n' + \
                                   '''maximum-paths ibgp {0}'''.format( ns.maximum_paths_ibgp )
                        #ipv6 mvpn
                       if family == "ipv6_mvpn":
                            ns=parseGlobalAfipv6mpvn( self.log, self.bgp_config_dict[node][as_no][vrf_name]['address_family']['ipv6_mvpn'] )
                            if vrf_name == "default":
                                 cfg = '''router bgp {0}
                                       address-family ipv6 mvpn'''.format( as_no )
                             # Config ebgp maximum-paths ..       
                            if hasattr( ns, 'maximum_paths') and ns.maximum_paths is not None:
                                 cfg = cfg + '\n' + \
                                   '''maximum-paths {0}'''.format( ns.maximum_paths )

                            # Config ibgp maximum-paths ..       
                            if hasattr( ns, 'maximum_paths_ibgp') and ns.maximum_paths_ibgp is not None:
                                 cfg = cfg + '\n' + \
                                   '''maximum-paths ibgp {0}'''.format( ns.maximum_paths_ibgp )
                       #IPV4_Label_Unicast
                       if family == "ipv4_label_unicast":
                            ns=parseGlobalAfIpv4LabelUnicast( self.log, self.bgp_config_dict[node][as_no][vrf_name]['address_family']['ipv4_label_unicast'] )
                            if vrf_name == "default":
                                cfg = '''router bgp {0}
                                      address-family ipv4 labeled-unicast'''.format( as_no )
          
        
                       # Aggregate address configuration ..
                       if hasattr( ns, 'aggregate_addr_list') and ns.aggregate_addr_list is not None:
                          for aggregate in ns.aggregate_addr_list.split(','):
                               cfg = cfg + '\n' + \
                                  '''aggregate-address {1}'''.format( aggregate )

                       # Enable client to client reflection
                       if hasattr( ns, 'client_to_client_reflection') and ns.client_to_client_reflection:
                                cfg = cfg + '\n' + \
                                    '''client-to-client reflection'''

                       # Enable dampening 
                       if hasattr( ns, 'dampening') and ns.dampening:
                            cfg = cfg + '\n' + \
                              '''dampening'''

                       # Enable dampening_half_life
                       if hasattr( ns, 'dampening_half_life') and ns.dampening_half_life:
                            cfg = cfg + '\n' + \
                              '''dampening {0}'''.format(ns.dampening_half_life)

                       # Enable retain_route_target_all
                       if hasattr( ns, 'retain_route_target_all') and ns.retain_route_target_all:
                            cfg = cfg + '\n' + \
                              '''retain route-target all'''.format(ns.retain_route_target_all)
                              
                       # Enable MED configuration ..
                       if hasattr( ns, 'default_metric') and ns.default_metric is not None:
                            cfg = cfg + '\n' + \
                              '''default-metric {0}'''.format( ns.default_metric )

                       # Config Administrative distance configuration ..
                       if hasattr( ns, 'ebgp_distance') and ns.ebgp_distance is not None:
                            cfg = cfg + '\n' + \
                              '''distance {0} {1} {2}'''.format( ns.ebgp_distance, ns.ibgp_distance, ns.local_distance )


                       # Config ebgp maximum-paths ..       
                       if hasattr( ns, 'maximum_paths') and ns.maximum_paths is not None:
                            cfg = cfg + '\n' + \
                              '''maximum-paths {0}'''.format( ns.maximum_paths )

                       # Config ibgp maximum-paths ..       
                       if hasattr( ns, 'maximum_paths_ibgp') and ns.maximum_paths_ibgp is not None:
                            cfg = cfg + '\n' + \
                              '''maximum-paths ibgp {0}'''.format( ns.maximum_paths_ibgp )
                              

                       # Enable suppress_inactive 
                       if hasattr( ns, 'suppress_inactive') and ns.suppress_inactive:
                            cfg = cfg + '\n' + \
                              '''suppress-inactive'''
                       # Re-distribution
                       #if hasattr( ns, 'tag_name' ) and ns.tag_name is not None:
                       #         cfg = cfg + '\n' + \
                        #            '''redistribute {0} {1} route-map {2}'''.format( redist_source,   \
                       #                ns.tag_name, ns.route_map )
                       #else:
                        #        cfg = cfg + '\n' + \
                         #           '''redistribute {0} route-map {1}'''.format( redist_source,   \
                          #             ns.route_map )

                       # Network configuration ..
                       if hasattr( ns, 'network_list') and ns.network_list is not None:
                         for network in ns.network_list.split(','):
                            network_addr,prf_len=network.split('/')
                            for i in range( 0, ns.network_count ):
                                 cfg = cfg + '\n' + \
                                 '''network {0}/{1}'''.format( network_addr,prf_len )
                            #network_addr=utils.incrementIpv4Address( network_addr, ns.network_step )

                       hdl.configure(cfg,**kdict)

                    

                 # Template configuration
                 if 'templates' in self.bgp_config_dict[node][as_no][vrf_name]:

                   for template in self.bgp_config_dict[node][as_no][vrf_name]['templates'].keys():
                     #Templete config section                    
                     if 'config' in self.bgp_config_dict[node][as_no][vrf_name]['templates'][template]:

                       ns=parseBgpTemplate( self.log, self.bgp_config_dict[node][as_no][vrf_name]['templates'][template]['config'] )

                       if vrf_name == "default":
                             cfg = '''router bgp {0}
                                    template peer {1}'''.format( as_no,template )
                       else:
                            cfg = '''router bgp {0}
                                     vrf {1}
                                     template peer {2}'''.format( as_no, vrf_name ,template)
                       if hasattr( ns, 'description') and ns.description is not None:
                           cfg = cfg + '\n' + \
                               '''description {0}'''.format(ns.description)

                       if hasattr( ns, 'local_as' ) and ns.local_as is not None:
                            cfg = cfg + '\n' + \
                                '''local-as {0}'''.format(ns.local_as)

                       if hasattr( ns, 'remote_as' ) and ns.remote_as is not None:
                             cfg = cfg + '\n' + \
                                 '''remote-as {0}'''.format(ns.remote_as)

                       if hasattr( ns, 'password' ) and ns.password is not None:
                            cfg = cfg + '\n' + \
                                '''password {0} {1}'''.format(ns.password_type, ns.password)

                       if hasattr( ns, 'update_source') and ns.update_source is not None:
                             cfg = cfg + '\n' + \
                                '''update-source {0}'''.format(ns.update_source)

                       if hasattr( ns, 'ebgp_multihop' ) and ns.ebgp_multihop is not None:
                             cfg = cfg + '\n' + \
                                '''ebgp-multihop {0}'''.format(ns.ebgp_multihop)
   
                       if hasattr( ns, 'dynamic_capability' ) and ns.dynamic_capability is not None:
                               cfg = cfg + '\n' + \
                                   '''dynamic-capability'''

                       if hasattr( ns, 'log_neighbor_changes' ) and ns.log_neighbor_changes is True:
                               cfg = cfg + '\n' + \
                                   ''' log-neighbor-changes'''
                       if hasattr( ns, 'bfd' ) and ns.bfd is True:
                            cfg = cfg + '\n' + \
                                 '''bfd'''
                       if hasattr(ns, 'peer_type' ) and ns.peer_type is not None:
                            cfg = cfg + '\n' + \
                                  '''peer-type {0} '''.format(ns.peer_type)
                       if hasattr(ns, 'rewrite_evpn_rt_asn') and ns.rewrite_evpn_rt_asn is not None:
                            cfg = cfg + '\n' + \
                                  '''rewrite-evpn-rt-asn '''
                       if hasattr(ns, 'rewrite_rt_asn') and ns.rewrite_rt_asn is not None:
                            cfg = cfg + '\n' + \
                                  '''rewrite-rt-asn '''
                       hdl.configure(cfg,**kdict)
                     
                     #Templete Address Family Section
                     if 'address_family' in self.bgp_config_dict[node][as_no][vrf_name]['templates'][template]:
                           for family in self.bgp_config_dict[node][as_no][vrf_name]['templates'][template]['address_family'].keys():
                                 #IPV4_Unicast     
                                 if family == "ipv4_unicast":
                           
                                   afp=parseBgpAfIpv4Unicast( self.log, self.bgp_config_dict[node]   \
                                        [as_no][vrf_name]['templates'][template]['address_family']['ipv4_unicast'] )
                                   
                                   print ('The value of afp inside "ipv4_unicast is:', afp)

                                   if vrf_name == "default":
                                       cfg = '''router bgp {0}
                                                template peer {1}
                                                address-family ipv4 unicast'''.format( as_no,template )
                                   else:
                                       cfg = '''router bgp {0}
                                                vrf {1}
                                                template peer {2}
                                                address-family ipv4 unicast'''.format( as_no, vrf_name,template)
                       
                                 #IPV6_Unicast     
                                 if family == "ipv6_unicast":
                           
                                   afp=parseBgpAfIpv6Unicast( self.log, self.bgp_config_dict[node]   \
                                           [as_no][vrf_name]['templates'][template]['address_family']['ipv6_unicast'] )

                                   if vrf_name == "default":
                                       cfg = '''router bgp {0}
                                                template peer {1}
                                                address-family ipv6 unicast'''.format( as_no,template )
                                   else:
                                       cfg = '''router bgp {0}
                                                vrf {1}
                                                template peer {2}
                                                address-family ipv6 unicast'''.format( as_no, vrf_name,template)
                                 
                                 if family == "l2vpn":
                                      afp=parseBgpAfL2vpnEvpn( self.log, self.bgp_config_dict[node][as_no][vrf_name]['templates'][template]['address_family']['l2vpn'] )
                                      self.log.info('The value of afp inside "address_family l2vpn is: {0}'.format(afp))
                                      if vrf_name == "default":
                                          cfg = '''router bgp {0}
                                                   template peer {1}
                                                   address-family l2vpn evpn'''.format( as_no,template ) 
                                                                                                                     
                                 if family == "ipv4_mvpn":
                                      afp=parseBgpAfIpv4Mvpn( self.log, self.bgp_config_dict[node][as_no][vrf_name]['templates'][template]['address_family']['ipv4_mvpn'] )
                                      print ('The value of afp inside "address_family ipv4_mvpn is:', afp)
                                      if vrf_name == "default":
                                          cfg = '''router bgp {0}
                                                   template peer {1}
                                                   address-family ipv4 mvpn'''.format( as_no,template )   
                                 if family == "ipv6_mvpn":
                                      afp=parseBgpAfIpv6Mvpn( self.log, self.bgp_config_dict[node][as_no][vrf_name]['templates'][template]['address_family']['ipv6_mvpn'] )
                                      print ('The value of afp inside "address_family ipv6_mvpn is:', afp)
                                      if vrf_name == "default":
                                          cfg = '''router bgp {0}
                                                   template peer {1}
                                                   address-family ipv6 mvpn'''.format( as_no,template )   
                                 if family == "ipv4_label_unicast":
                                         afp=parseBgpAfIpv4LabelUnicast( self.log, self.bgp_config_dict[node][as_no][vrf_name]['templates'][template]['address_family']['ipv4_label_unicast'] )
                                         if vrf_name == "default":
                                              cfg = '''router bgp {0}
                                                       template peer {1}
                                                       address-family ipv4 labeled-unicast'''.format( as_no,template )

                                 if hasattr( afp, 'allow_as_in') and afp.allow_as_in is not None:
                                     cfg = cfg + '\n' +  \
                                         '''allowas-in {0}'''.format( afp.allow_as_in )
                             
                                 if hasattr( afp, 'as_override' ) and afp.as_override is True:
                                     cfg = cfg + '\n' + \
                                         '''as-override'''

                                 if hasattr( afp, 'default_originate' ) and afp.default_originate is True:
                                     cfg = cfg + '\n' + \
                                        '''default-originate'''

                                 if hasattr( afp, 'default_originate_route_map' ) and afp.default_originate_route_map \
                                     is not None:
                                     cfg = cfg + '\n' + \
                                       '''default-originate route-map {0}'''.format(afp.default_originate_route_map)

                                 if hasattr( afp, 'disable_peer_as_check' ) and afp.disable_peer_as_check is True:
                                     cfg = cfg + '\n' + \
                                       '''disable-peer-as-check'''                 

                                 if hasattr( afp, 'filter_list' ) and afp.filter_list is not None:
                                     cfg = cfg + '\n' + \
                                       '''filter-list {0}'''.format( afp.filter_list )

                                 if hasattr( afp, 'peer_policy' ) and afp.peer_policy is not None:
                                     cfg = cfg + '\n' + \
                                       '''inherit peer-policy {0}'''.format( afp.peer_policy )

                                 if hasattr( afp, 'maximum_prefix' ) and afp.maximum_prefix is not None:
                                     cfg = cfg + '\n' + \
                                       '''maximum-prefix {0}'''.format(afp.maximum_prefix)

                                 if hasattr( afp, 'next_hop_self' ) and afp.next_hop_self is True:
                                     cfg = cfg + '\n' + \
                                      '''next-hop-self'''

                                 if hasattr( afp, 'next_hop_third_party' ) and afp.next_hop_third_party is True:
                                     cfg = cfg + '\n' + \
                                       '''next-hop-third-party'''

                                 if hasattr( afp, 'next_hop_third_party' ) and afp.next_hop_third_party is True:
                                     cfg = cfg + '\n' + \
                                      '''next-hop-third-party'''

                                 if hasattr( afp, 'prefix_list' ) and afp.prefix_list is not None:
                                     cfg = cfg + '\n' + \
                                      '''prefix-list {0} {1}'''.format(afp.prefix_list, afp.prefix_list_direction)

                                 if hasattr( afp, 'route_reflector_client' ) and afp.route_reflector_client is True:
                                     cfg = cfg + '\n' + \
                                     '''route-reflector-client'''

                                 if hasattr( afp, 'send_community' ) and afp.send_community is True:
                                     cfg = cfg + '\n' + \
                                      '''send-community'''

                                 if hasattr( afp, 'send_community_extended' ) and afp.send_community_extended is True:
                                     cfg = cfg + '\n' + \
                                      '''send-community extended'''

                                 if hasattr( afp, 'soft_reconfiguration' ) and afp.soft_reconfiguration is True:
                                     cfg = cfg + '\n' + \
                                      '''soft-reconfiguration inbound always'''

                                 if hasattr( afp, 'suppress_inactive' ) and afp.suppress_inactive is True:
                                     cfg = cfg + '\n' + \
                                       '''suppress-inactive'''

                                 if hasattr( afp, 'rewrite_evpn_rt_asn' ) and afp.rewrite_evpn_rt_asn is True:
                                     cfg = cfg + '\n' + \
                                       '''rewrite-evpn-rt-asn'''

                                 if hasattr( afp, 'rewrite_rt_asn' ) and afp.rewrite_rt_asn is True:
                                     cfg = cfg + '\n' + \
                                       '''rewrite-rt-asn'''
                                     
                                 if hasattr( afp, 'route_map' ) and afp.route_map is not None:
                                     cfg = cfg + '\n' + \
                                       '''route-map {0} {1}'''.format(afp.route_map, afp.route_map_direction)

                                 if hasattr( afp, 'weight' ) and afp.weight is not None:
                                     cfg = cfg + '\n' + \
                                       '''weight {0}'''.format(afp.weight)

                                 if hasattr( afp, 'advertise_map' ) and afp.advertise_map is not None:
                                     cfg = cfg + '\n' + \
                                      '''advertise-map {0} exist-map {1}'''.format(afp.advertise_map, \
                                      afp.advertise_exist_map)
                                     
                                 hdl.configure(cfg,**kdict)
                                  
   


                 # Neighbor configuration
                 if 'neighbors' in self.bgp_config_dict[node][as_no][vrf_name]:
                            
                        neighborTypes=self.bgp_config_dict[node][as_no][vrf_name]['neighbors'].keys()
                        for neighborType in neighborTypes:
                          for neighbor in self.bgp_config_dict[node][as_no][vrf_name]['neighbors'][neighborType]:
                            #Neighbor template configuration
                            if 'template_params' in self.bgp_config_dict[node][as_no][vrf_name]['neighbors'][neighborType][neighbor]:
                               ns=parseBgpNeighborTemplate(self.log, self.bgp_config_dict[node][as_no][vrf_name]['neighbors'][neighborType][neighbor]['template_params'])
                               if vrf_name == "default":
                                      cfg = '''router bgp {0}
                                               neighbor {1}'''.format( as_no,neighbor )
                               else:
                                      cfg = '''router bgp {0}
                                               vrf {1}
                                               neighbor {2}'''.format( as_no, vrf_name ,neighbor)

                               if hasattr( ns, 'inherit_peer') and ns.inherit_peer is not None:
                                    cfg= cfg + '\n' +\
                                             '''inherit peer {0}'''.format(ns.inherit_peer)
                               hdl.configure(cfg,**kdict)
                                     
                            ##Neighbor Config params    
                            if 'neighbor_params' in self.bgp_config_dict[node][as_no][vrf_name]['neighbors'][neighborType][neighbor]:
                               
                               if 'config' in self.bgp_config_dict[node][as_no][vrf_name]['neighbors'][neighborType][neighbor]['neighbor_params']:

                                 ns=parseBgpTemplate( self.log, self.bgp_config_dict[node][as_no][vrf_name]['neighbors'][neighborType][neighbor]['neighbor_params']['config'])

                                 if vrf_name == "default":
                                      cfg = '''router bgp {0}
                                               neighbor {1}'''.format( as_no,neighbor )
                                 else:
                                      cfg = '''router bgp {0}
                                               vrf {1}
                                               neighbor {2}'''.format( as_no, vrf_name ,neighbor)
                                 if hasattr( ns, 'description') and ns.description is not None:
                                        cfg = cfg + '\n' + \
                                           '''description {0}'''.format(ns.description)

                                 if hasattr( ns, 'local_as' ) and ns.local_as is not None:
                                          cfg = cfg + '\n' + \
                                               '''local-as {0}'''.format(ns.local_as)

                                 if hasattr( ns, 'remote_as' ) and ns.remote_as is not None:
                                         cfg = cfg + '\n' + \
                                               '''remote-as {0}'''.format(ns.remote_as)

                                 if hasattr( ns, 'password' ) and ns.password is not None:
                                         cfg = cfg + '\n' + \
                                               '''password {0} {1}'''.format(ns.password_type, ns.password)

                                 if hasattr( ns, 'update_source') and ns.update_source is not None:
                                        cfg = cfg + '\n' + \
                                              '''update-source {0}'''.format(ns.update_source)

                                 if hasattr( ns, 'ebgp_multihop' ) and ns.ebgp_multihop is not None:
                                        cfg = cfg + '\n' + \
                                             '''ebgp-multihop {0}'''.format(ns.ebgp_multihop)
   
                                 if hasattr( ns, 'dynamic_capability' ) and ns.dynamic_capability is not None:
                                        cfg = cfg + '\n' + \
                                             '''dynamic-capability'''

                                 if hasattr( ns, 'bfd' ) and ns.bfd is True:
                                       cfg = cfg + '\n' + \
                                             '''bfd'''
                                 hdl.configure(cfg,**kdict)
                     
                               #Neighbor Address Family Section
                               if 'address_family' in self.bgp_config_dict[node][as_no][vrf_name]['neighbors'][neighborType][neighbor]['neighbor_params']:
                                  for family in self.bgp_config_dict[node][as_no][vrf_name]['neighbors'][neighborType][neighbor]['neighbor_params']['address_family'].keys():
                                   
                                   #IPV4_Unicast     
                                   if family == "ipv4_unicast":
                           
                                    afp=parseBgpAfIpv4Unicast( self.log, self.bgp_config_dict[node]   \
                                        [as_no][vrf_name]['neighbors'][neighborType][neighbor]['neighbor_params']['address_family']['ipv4_unicast'] )

                                    if vrf_name == "default":
                                       cfg = '''router bgp {0}
                                                neighbor {1}
                                                address-family ipv4 unicast'''.format( as_no,neighbor )
                                    else:
                                       cfg = '''router bgp {0}
                                                vrf {1}
                                                neighbor {2}
                                                address-family ipv4 unicast'''.format( as_no, vrf_name,neighbor)
                       
                                   #IPV6_Unicast     
                                   if family == "ipv6_unicast":
                           
                                     afp=parseBgpAfIpv4Unicast( self.log, self.bgp_config_dict[node]   \
                                           [as_no][vrf_name]['neighbors'][neighborType][neighbor]['neighbor_params']['address_family']['ipv6_unicast'] )

                                     if vrf_name == "default":
                                        cfg = '''router bgp {0}
                                                neighbor {1}
                                                address-family ipv6 unicast'''.format( as_no,neighbor )
                                     else:
                                        cfg = '''router bgp {0}
                                                vrf {1}
                                                neighbor {2}
                                                address-family ipv6 unicast'''.format( as_no, vrf_name,neighbor)
                            

                                   #L2VPN
                                   if family == "l2vpn":
                                       afp=parseBgpAfL2vpnEvpn( self.log, self.bgp_config_dict[node][as_no][vrf_name]['neighbors'][neighborType][neighbor]['neighbor_params']['address_family']['l2vpn'] )
                                       if vrf_name == "default":
                                           cfg = '''router bgp {0}
                                                    neighbor {1}
                                                    address-family l2vpn evpn'''.format( as_no,neighbor )
                                   if hasattr( afp, 'allow_as_in') and afp.allow_as_in is not None:
                                     cfg = cfg + '\n' +  \
                                         '''allowas-in {0}'''.format( afp.allow_as_in )
                             
                                   if hasattr( afp, 'as_override' ) and afp.as_override is True:
                                        cfg = cfg + '\n' + \
                                             '''as-override'''

                                   if hasattr( afp, 'default_originate' ) and afp.default_originate is True:
                                         cfg = cfg + '\n' + \
                                              '''default-originate'''

                                   if hasattr( afp, 'default_originate_route_map' ) and afp.default_originate_route_map \
                                       is not None:
                                        cfg = cfg + '\n' + \
                                           '''default-originate route-map {0}'''.format(afp.default_originate_route_map)

                                   if hasattr( afp, 'disable_peer_as_check' ) and afp.disable_peer_as_check is True:
                                        cfg = cfg + '\n' + \
                                            '''disable-peer-as-check'''

                                   if hasattr( afp, 'filter_list' ) and afp.filter_list is not None:
                                        cfg = cfg + '\n' + \
                                             '''filter-list {0}'''.format( afp.filter_list )

                                   if hasattr( afp, 'peer_policy' ) and afp.peer_policy is not None:
                                        cfg = cfg + '\n' + \
                                            '''inherit peer-policy {0}'''.format( afp.peer_policy )

                                   if hasattr( afp, 'maximum_prefix' ) and afp.maximum_prefix is not None:
                                        cfg = cfg + '\n' + \
                                          '''maximum-prefix {0}'''.format(afp.maximum_prefix)

                                   if hasattr( afp, 'next_hop_self' ) and afp.next_hop_self is True:
                                     cfg = cfg + '\n' + \
                                       '''next-hop-self'''

                                   if hasattr( afp, 'next_hop_third_party' ) and afp.next_hop_third_party is True:
                                         cfg = cfg + '\n' + \
                                            '''next-hop-third-party'''

                                   if hasattr( afp, 'next_hop_third_party' ) and afp.next_hop_third_party is True:
                                        cfg = cfg + '\n' + \
                                           '''next-hop-third-party'''

                                   if hasattr( afp, 'prefix_list' ) and afp.prefix_list is not None:
                                        cfg = cfg + '\n' + \
                                          '''prefix-list {0} {1}'''.format(afp.prefix_list, afp.prefix_list_direction)

                                   if hasattr( afp, 'route_reflector_client' ) and afp.route_reflector_client is True:
                                        cfg = cfg + '\n' + \
                                          '''route-reflector-client'''

                                   if hasattr( afp, 'send_community' ) and afp.send_community is True:
                                          cfg = cfg + '\n' + \
                                           '''send-community'''

                                   if hasattr( afp, 'send_community_extended' ) and afp.send_community_extended is True:
                                          cfg = cfg + '\n' + \
                                            '''send-community extended'''

                                   if hasattr( afp, 'soft_reconfiguration' ) and afp.soft_reconfiguration is True:
                                         cfg = cfg + '\n' + \
                                          '''soft-reconfiguration inbound always'''

                                   if hasattr( afp, 'suppress_inactive' ) and afp.suppress_inactive is True:
                                         cfg = cfg + '\n' + \
                                            '''suppress-inactive'''

                                   if hasattr( afp, 'route_map' ) and afp.route_map is not None:
                                         cfg = cfg + '\n' + \
                                           '''route-map {0} {1}'''.format(afp.route_map, afp.route_map_direction)

                                   if hasattr( afp, 'weight' ) and afp.weight is not None:
                                         cfg = cfg + '\n' + \
                                             '''weight {0}'''.format(afp.weight)

                                   if hasattr( afp, 'advertise_map' ) and afp.advertise_map is not None:
                                         cfg = cfg + '\n' + \
                                           '''advertise-map {0} exist-map {1}'''.format(afp.advertise_map, \
                                                   afp.advertise_exist_map)
                                     
                                   hdl.configure(cfg,**kdict)
                 #Redistribution configs
                 if 'redistribution_configs' in self.bgp_config_dict[node][as_no][vrf_name]:
                     if 'ipv4_unicast' in self.bgp_config_dict[node][as_no][vrf_name]['redistribution_configs']:
                          # Redistribution configs for Bgpv4
                          redist_sources=self.bgp_config_dict[node][as_no][vrf_name]['redistribution_configs'] \
                          ['ipv4_unicast'].keys()
                          # If vrf == default
                          if vrf_name == "default":
                              cfg='''router bgp {0}
                                     address-family ipv4 unicast'''.format(as_no)
                          else:
                              cfg='''router bgp {0}
                                     vrf {1}
                                     address-family ipv4 unicast'''.format(as_no,vrf_name) 


                          for redist_source in redist_sources:
                              rd_ns=parseBgpRedistributionConfigs( self.log, self.bgp_config_dict[node] \
                              [as_no][vrf_name]['redistribution_configs']['ipv4_unicast'][redist_source] )
                              if hasattr( rd_ns, 'tag_name' ) and rd_ns.tag_name is not None:
                                  cfg = cfg + '\n' + \
                                      '''redistribute {0} {1} route-map {2}'''.format( redist_source,   \
                                         rd_ns.tag_name, rd_ns.route_map )
                              else:
                                  cfg = cfg + '\n' + \
                                      '''redistribute {0} route-map {1}'''.format( redist_source,   \
                                         rd_ns.route_map )
                          # Apply the per VRF redistribution configs ..
                          hdl.configure(cfg)
                     if 'ipv6_unicast' in self.bgp_config_dict[node][as_no][vrf_name]['redistribution_configs']:
                          # Redistribution configs for Bgpv6
                          redist_sources=self.bgp_config_dict[node][as_no][vrf_name]['redistribution_configs'] \
                          ['ipv6_unicast'].keys()
                          # If vrf == default
                          if vrf_name == "default":
                              cfg='''router bgp {0}
                                     address-family ipv6 unicast'''.format(as_no)
                          else:
                              cfg='''router bgp {0}
                                     vrf {1}
                                     address-family ipv6 unicast'''.format(as_no,vrf_name) 


                          for redist_source in redist_sources:
                              rd_ns=parseBgpRedistributionConfigs( self.log, self.bgp_config_dict[node] \
                              [as_no][vrf_name]['redistribution_configs']['ipv6_unicast'][redist_source] )
                              if hasattr( rd_ns, 'tag_name' ) and rd_ns.tag_name is not None:
                                  cfg = cfg + '\n' + \
                                      '''redistribute {0} {1} route-map {2}'''.format( redist_source,   \
                                         rd_ns.tag_name, rd_ns.route_map )
                              else:
                                  cfg = cfg + '\n' + \
                                      '''redistribute {0} route-map {1}'''.format( redist_source,   \
                                         rd_ns.route_map )
                          # Apply the per VRF redistribution configs ..
                          hdl.configure(cfg)
            return 1                      

                      

class verifyBgpv4(object):

    def __init__(self, bgp_config_dict, switch_dict, switch_hdl_dict, log, *args ):

        self.log=log
        self.result='pass'
        self.bgp_config_dict=bgp_config_dict

        arggrammar={}
        arggrammar['node_list']='-type str'
        arggrammar['verify_detail'] = '-type bool -default True'
        ns_inputargs=parserutils_lib.argsToCommandOptions(args, arggrammar, log)

        if ns_inputargs.node_list is not None:
            list_of_nodes=ns_inputargs.node_list.split(',')
        else:
            try:
               list_of_nodes=self.bgp_config_dict.keys()
            except KeyError:
               err_msg='Error !!! bgp_config_dict has not been defined properly, does not have nodes   \
                  as the top level keys'
               testResult( 'fail', err_msg, self.log )

        for node in list_of_nodes:
            print(node)
            print('%%% switch_hdl_dict %%%', switch_hdl_dict )
            hdl=switch_hdl_dict[node]

            # Verify Bgp is enabled
            feature_name='bgp'
            if verify_lib.verifyFeatureState(hdl,log,'-feature {0}'.format(feature_name)).result=='pass':
                log.info('Feature {0} is in enabled state'.format(feature_name))
                testResult('pass','Feature {0} is in enabled state'.format(feature_name),log)
            else:
                log.error('Feature {0} is not in enabled state'.format(feature_name))
                testResult('fail','Feature {0} is not in enabled state'.format(feature_name),log)

            hdl.iexec('show ip bgp summary')
            output = hdl.iexec('show ip route summary')
            pattern = r'Total number of paths:[ \t]+([0-9]+)'
            match = re.search(pattern, output)
            total_path = 0
            if match:
               total_path = int(match.group(1))
            if total_path < 100000:
               hdl.iexec('show ip route bgp')
            else:
               output = hdl.iexec('dir bootflash:show_ip_route_bgp')
               match = re.search(r'show_ip_route_bgp', output)
               if match:
                  hdl.isendline('delete bootflash:show_ip_route_bgp')
                  hdl.iexpect('Do you want to delete \"/show_ip_route_bgp\" \? \(yes/no/abort\)   \[y\]')
                  hdl.isendline('y')
                  hdl.iexpect('# $')
               hdl.isendline('show ip route bpg > bootflash:show_ip_route_bgp')

 
            as_nos=self.bgp_config_dict[node].keys()

            # In future if we allow multiple AS
            for as_no in as_nos:

               # Build Router configs ..
               router_vrfs=self.bgp_config_dict[node][as_no]['router_configs']
               
               for vrf_name in router_vrfs:

                   # Verify the VRF is in proper state ..
                   verify_lib.verifyVrfState( hdl, log, '-vrf {0}'.format(vrf_name) )

                   ns=parseBgpRouterConfigs( self.log, self.bgp_config_dict[node][as_no]           \
                        ['router_configs'][vrf_name] )



               # Template configuration
               if 'templates' in self.bgp_config_dict[node][as_no]:
                  for template in self.bgp_config_dict[node][as_no]['templates'].keys():
                     ns=parseBgpTemplate( self.log, self.bgp_config_dict[node][as_no]['templates'][template] )


               bgp_neigh_dict=utils.getIpv4BgpNeighborDict( hdl, self.log, '-vrf all' )
               if len( bgp_neigh_dict.keys() ) == 0:
                 testResult( 'fail', 'No BGP neighbors found .. BGP configs did not take effect', self.log )
                 return


               show_run=hdl.iexec('show running-config bgp all')

               # Neighbor configuration
               for neighbor in self.bgp_config_dict[node][as_no]['neighbors'].keys():

                   if 'neighbor_params' in self.bgp_config_dict[node][as_no]['neighbors'][neighbor]:
                      np_args = self.bgp_config_dict[node][as_no]['neighbors'][neighbor]['neighbor_params']
                      np=parseBgpNeighborParams( self.log, np_args)
                      
                      ns_args = ''
                      if hasattr(np, 'peer_policy'):
                          if 'templates' in self.bgp_config_dict[node][as_no]:
                              if np.peer_policy in self.bgp_config_dict[node][as_no]['templates'].keys():
                                  ns_args=self.bgp_config_dict[node][as_no]['templates'][np.peer_policy]
                           
                      # Iterate over the neighbor_count
                      neighbor_addr=neighbor
                      remote_as=np.remote_as
                      print('%%%% neighbor_addr %%%%', neighbor_addr )
                      for i in range( 0, np.neighbor_count ):

                          # Verify if the states are in Established state ..
                          if neighbor_addr in bgp_neigh_dict:
                            if not re.search( 'Established', bgp_neigh_dict[neighbor_addr]['state'], flags=re.I ):
                               msg='BGP Neighbor {0} is not in Established state on node {1}'.format( neighbor_addr,  \
                                  node )
                               testResult( 'fail', msg, self.log )
                            else:
                               msg='BGP Neighbor {0} is in Established state as expected on node {1}'.format(    \
                                  neighbor_addr, node )
                               testResult( 'pass', msg, self.log )
                          else:
                            msg='BGP Neighbor {0} does not exist on node {1}'.format( neighbor_addr, node ) 
                            testResult( 'fail', msg, self.log )

                          neighbor_addr=utils.incrementIpv4Address( neighbor_addr, np.neighbor_step )
                          #if np.remote_as is not None:
                          #    remote_as = int(remote_as) + int(np.remote_as_step)

                          if not ns_inputargs.verify_detail:
                            continue
                          
                          # Verify if the remote AS is proper for the neighbors ..
                          if hasattr( np, 'remote_as' ) and np.remote_as is not None:

                              if neighbor in bgp_neigh_dict:
                                  if int(np.remote_as) != int(bgp_neigh_dict[neighbor]['as']):
                                      msg='Error remote-as for neighbor {0} is incorrect on node {1},             \
                                         Expected {2} Actual {3}'.format( neighbor, node, np.remote_as,           \
                                         bgp_neigh_dict[neighbor]['as'] )
                                      testResult( 'fail', msg, self.log )
                                  else:
                                      msg='Neighbor remote-as for neighbor {0} is correct on node {1},            \
                                         Expected {2} Actual {3}'.format( neighbor, node, np.remote_as,           \
                                         bgp_neigh_dict[neighbor]['as'] )
                                      testResult( 'pass', msg, self.log )

                              # Verify it is getting saved to running configs
                              run_pattern='neighbor {0} remote-as {1}'.format( neighbor, np.remote_as )
                              if not re.search( run_pattern, show_run, flags=re.I ):
                                  testResult( 'fail', '{0} missing in running config'.format(run_pattern),   \
                                      self.log )
                              

                          # Verify if the update-source is proper ..
                          if hasattr( np, 'update_source' ) and np.update_source is not None:
                              cmd='show ip bgp neighbor {0}'.format(neighbor)
                              show_bgp=hdl.iexec(cmd)
                              if re.search( 'as update source', show_bgp, flags=re.I ):
                                  pattern = 'Using ({0}) as update source for this peer'.format( rex.INTERFACE_NAME )
                                  match=re.search( pattern, show_bgp )
                                  source_int=utils.normalizeInterfaceName( self.log, match.group(1) )
                                  update_source_int=utils.normalizeInterfaceName( self.log, np.update_source )
                                  if source_int != update_source_int:
                                      msg='Error !! Update source intf for neighbor {0} on node {1} incorrect    \
                                        Expected - {2}, Actual - {3}'.format( neighbor, node, update_source_int, \
                                        source_int )
                                      testResult( 'fail', msg, self.log )
                                  else:
                                      msg='Update source for neighbor {0} shows up correctly as {1}'.format(     \
                                        neighbor, source_int )
                                      testResult( 'pass', msg, self.log )
                              # If Update source is missing in the show output          
                              else:
                                  msg='Error !! Update source interface for neighbor {0} is missing'.format(     \
                                    neighbor)
                                  testResult( 'fail', msg, self.log )

                          # Verify timers ..
                          if hasattr( np, 'keep_alive_time') and hasattr( np, 'hold_time') and np.keep_alive_time:
                              expected_keep_alive_time = int(np.keep_alive_time) 
                              if re.search(r'keep_alive_time', ns_args):
                                  expected_keep_alive_time = int(ns.keep_alive_time)
                              if re.search(r'keep_alive_time', np_args):
                                  expected_keep_alive_time = int(np.keep_alive_time)
                              if hasattr( np, 'keep_alive_time' ) and np.keep_alive_time is not None:
                                  if neighbor in bgp_neigh_dict:
                                      if expected_keep_alive_time != int(bgp_neigh_dict[neighbor]['keepalive']):
                                          msg='Error Keeplive time not correct for neighbor {0} on node {1}, Expected    \
                                            = {2} , Actual = {3}'.format( neighbor, node, np.keep_alive_time,            \
                                            bgp_neigh_dict[neighbor]['keepalive'] )
                                          testResult( 'fail', msg, self.log )
                                      else:
                                          msg='Keeplive time configured correctly for neighbor {0} on node {1}, Expected \
                                            = {2} , Actual = {3}'.format( neighbor, node, np.keep_alive_time,            \
                                            bgp_neigh_dict[neighbor]['keepalive'] )
                                          testResult( 'pass', msg, self.log )
    
    
                              expected_hold_time = int(np.hold_time)
                              if re.search(r'hold_time', ns_args):
                                  expected_hold_time = int(ns.hold_time)
                              if re.search(r'hold_time', np_args):
                                  expected_hold_time = int(np.hold_time)
                              if hasattr( np, 'hold_time' ) and np.hold_time is not None:
                                  if neighbor in bgp_neigh_dict:
                                      if expected_hold_time != int(bgp_neigh_dict[neighbor]['holdtime']):
                                          msg='Error Hold time not correct for neighbor {0} on node {1}, Expected       \
                                            = {2} , Actual = {3}'.format( neighbor, node, np.hold_time,                 \
                                            bgp_neigh_dict[neighbor]['holdtime'] )
                                          testResult( 'fail', msg, self.log )
                                      else:
                                          msg='Hold time configured correctly for neighbor {0} on node {1}, Expected    \
                                            = {2} , Actual = {3}'.format( neighbor, node, np.hold_time,                 \
                                            bgp_neigh_dict[neighbor]['holdtime'] )
                                          testResult( 'pass', msg, self.log )




class configBgpv6(object):

    def __init__(self, bgp_config_dict, switch_dict, switch_hdl_dict, log ):

        self.log=log
        self.result='pass'
        self.bgp_config_dict=bgp_config_dict
      
        try:
           list_of_nodes=self.bgp_config_dict.keys()
        except KeyError:
           err_msg='Error !!! bgp_config_dict has not been defined properly, does not have nodes   \
              as the top level keys'
           testResult( 'fail', err_msg, self.log )

        for node in list_of_nodes:
            print(node)
            hdl=switch_hdl_dict[node]
            # Enable feature Bgp
            bringup_lib.configFeature( hdl, self.log, '-feature bgp' )
           
            as_nos=self.bgp_config_dict[node].keys()

            # In future if we allow multiple AS
            for as_no in as_nos:

               # Build address family configs ..
               # For Ipv6 Unicast
               if 'address_family' in self.bgp_config_dict[node][as_no]:

                 vrf_list=self.bgp_config_dict[node][as_no]['address_family'].keys()
                 for vrf_name in vrf_list:
                   if 'ipv6_unicast' in self.bgp_config_dict[node][as_no]['address_family'][vrf_name]:

                     ns=parseGlobalAfIpv6Unicast( self.log, self.bgp_config_dict[node][as_no]        \
                       ['address_family'][vrf_name]['ipv6_unicast'] )

                     if vrf_name == "default":
                         cfg = '''router bgp {0}
                              address-family ipv6 unicast'''.format( as_no )
                     else:
                         cfg = '''router bgp {0}
                              vrf {1}
                              address-family ipv6 unicast'''.format( as_no, vrf_name )
                              
                     # Aggregate address configuration ..
                     if hasattr( ns, 'aggregate_addr_list') and ns.aggregate_addr_list is not None:
                       for aggregate in ns.aggregate_addr_list.split(','):
                           cfg = cfg + '\n' + \
                                  '''aggregate-address {1}'''.format( aggregate )

                     # Enable client to client reflection
                     if hasattr( ns, 'client_to_client_reflection') and ns.client_to_client_reflection:
                           cfg = cfg + '\n' + \
                              '''client-to-client reflection'''

                     # Enable dampening 
                     if hasattr( ns, 'dampening') and ns.dampening:
                       cfg = cfg + '\n' + \
                              '''dampening'''

                     # Enable dampening_half_life
                     if hasattr( ns, 'dampening_half_life') and ns.dampening_half_life:
                       cfg = cfg + '\n' + \
                              '''dampening {0}'''.format(ns.dampening_half_life)

                     # Enable MED configuration ..
                     if hasattr( ns, 'default_metric') and ns.default_metric is not None:
                       cfg = cfg + '\n' + \
                              '''default-metric {0}'''.format( ns.default_metric )

                     # Config Administrative distance configuration ..
                     if hasattr( ns, 'ebgp_distance') and ns.ebgp_distance is not None:
                       cfg = cfg + '\n' + \
                              '''distance {0} {1} {2}'''.format( ns.ebgp_distance, ns.ibgp_distance, ns.local_distance )


                     # Config ebgp maximum-paths ..       
                     if hasattr( ns, 'maximum_paths') and ns.maximum_paths is not None:
                       cfg = cfg + '\n' + \
                              '''maximum-paths {0}'''.format( ns.maximum_paths )

                     # Config ibgp maximum-paths ..       
                     if hasattr( ns, 'maximum_paths_ibgp') and ns.maximum_paths_ibgp is not None:
                       cfg = cfg + '\n' + \
                              '''maximum-paths ibgp {0}'''.format( ns.maximum_paths_ibgp )

                     # Enable suppress_inactive 
                     if hasattr( ns, 'suppress_inactive') and ns.suppress_inactive:
                       cfg = cfg + '\n' + \
                              '''suppress-inactive'''

                     # Network configuration ..
                     if hasattr( ns, 'network_list') and ns.network_list is not None:
                       for network in ns.network_list.split(','):
                           network_addr,prf_len=network.split('/')
                           cfg = cfg + '\n' + \
                                  '''network {0}'''.format( network )
                           network_addr=utils.incrementIpv6Address( network_addr, ns.network_step )

                     hdl.configure(cfg)



               # Build Router configs ..
               router_vrfs=self.bgp_config_dict[node][as_no]['router_configs']
               
               for vrf_name in router_vrfs:

                   ns=parseBgpRouterConfigs( self.log, self.bgp_config_dict[node][as_no]           \
                        ['router_configs'][vrf_name] )
                   cfg='''router bgp {0}
                          router-id {1}
                          timers prefix-peer-timeout {2}
                          timers bestpath-limit {3}'''.format( as_no, ns.router_id,                \
                          ns.prefix_peer_timeout, ns.best_path_limit_timeout )

                   if hasattr( ns, 'keep_alive_time') and hasattr( ns, 'hold_time') and ns.keep_alive_time:
                       cfg = cfg + '\n' +  \
                              '''timers bgp {0} {1}'''.format(ns.keep_alive_time, ns.hold_time)
                       hdl.configure(cfg)

                   if ns.log_neighbor_changes:
                       cfg = cfg + '\n' +  \
                              '''log-neighbor-changes'''
                       hdl.configure(cfg)

                   if hasattr( ns, 'max_as_limit' ):
                       cfg = cfg + '\n' +  \
                             '''maxas-limit {0}'''.format( ns.max_as_limit )

                   if hasattr( ns, 'graceful_restart' ):
                       cfg = cfg + '\n' +  \
                             '''graceful-restart'''


                   # Apply the BGP router configs ..          
                   hdl.configure(cfg)



               # Template configuration
               if 'templates' in self.bgp_config_dict[node][as_no]:

                 for template in self.bgp_config_dict[node][as_no]['templates'].keys():

                   ns=parseBgpTemplate( self.log, self.bgp_config_dict[node][as_no]['templates'][template] )


                   cfg='''router bgp {0}
                          template peer {1}'''.format( as_no, template )

                   if hasattr( ns, 'address_family') and ns.address_family is not None:

                      if re.search( 'ipv6_unicast', ns.address_family, flags=re.I ):
                         cfg = cfg + '\n' + \
                               '''address-family ipv6 unicast'''
                      elif re.search( 'ipv6_multicast', ns.address_family, flags=re.I ):
                         cfg = cfg + '\n' + \
                               '''address-family ipv6 multicast'''
                      elif re.search( 'ipv6_unicast', ns.address_family, flags=re.I ):
                         cfg = cfg + '\n' + \
                               '''address-family ipv6 unicast'''
                      elif re.search( 'ipv6_multicast', ns.address_family, flags=re.I ):
                         cfg = cfg + '\n' + \
                               '''address-family ipv6 multicast'''

                   if hasattr( ns, 'description') and ns.description is not None:
                      cfg = cfg + '\n' + \
                            'description {0}'.format(ns.description)

                   if hasattr( ns, 'local_as' ) and ns.local_as is not None:
                      cfg = cfg + '\n' + \
                            '''local-as {0}'''.format(ns.local_as)

                   if hasattr( ns, 'remote_as' ) and ns.remote_as is not None:
                      cfg = cfg + '\n' + \
                            '''remote-as {0}'''.format(ns.remote_as)

                   if hasattr( ns, 'password' ) and ns.password is not None:
                      cfg = cfg + '\n' + \
                            '''password {0} {1}'''.format(ns.password_type, ns.password)

                   if hasattr( ns, 'update_source') and ns.update_source is not None:
                      cfg = cfg + '\n' + \
                            '''update-source {0}'''.format(ns.update_source)

                   if hasattr( ns, 'ebgp_multihop' ) and ns.ebgp_multihop is not None:
                      cfg = cfg + '\n' + \
                            '''ebgp-multihop {0}'''.format(ns.ebgp_multihop)
   
                   if hasattr( ns, 'dynamic_capability' ) and ns.dynamic_capability is not None:
                      cfg = cfg + '\n' + \
                            '''dynamic-capability'''

                   if hasattr( ns, 'bfd' ) and ns.bfd is True:
                      bringup_lib.configFeature( hdl, self.log, '-feature bfd' )
                      cfg = cfg + '\n' + \
                            '''bfd'''

                   # Apply the BGP template configs ..          
                   hdl.configure(cfg)


               # Neighbor configuration
               for neighbor in self.bgp_config_dict[node][as_no]['neighbors'].keys():

                   if 'neighbor_params' in self.bgp_config_dict[node][as_no]['neighbors'][neighbor]:
                      np=parseBgpv6NeighborParams( self.log, self.bgp_config_dict[node][as_no]['neighbors'] \
                        [neighbor]['neighbor_params'] )

                      # Iterate over the neighbor_count
                      neighbor_addr=neighbor
                      remote_as=np.remote_as
                      print('%%%% remote_as %%%%%', remote_as )
                      for i in range( 0, np.neighbor_count ):

                          # If vrf == default
                          if re.search( 'ipv6_unicast', np.address_family, re.I ):
                                 af_config='address-family ipv6 unicast'
                          elif re.search( 'ipv6_multicast', np.address_family, re.I ):
                                 af_config='address-family ipv6 multicast'

                          if np.vrf_name == "default":

                             if np.peer_policy is not None:
                                 cfg='''router bgp {0}
                                        {1}
                                        neighbor {2}
                                        inherit peer {3}'''.format(
                                        as_no, af_config, neighbor_addr, np.peer_policy )
                             else:
                                 cfg='''router bgp {0}
                                        {1}
                                        neighbor {2} remote-as {3}'''.format(
                                        as_no, af_config, neighbor_addr, remote_as)
                                 if hasattr( np, 'keep_alive_time') and hasattr( np, 'hold_time') and np.keep_alive_time:
                                     cfg = cfg + '\n' + \
                                         '''timers {0} {1}'''.format(
                                            np.keep_alive_time, np.hold_time )
                          # Non default VRF ..
                          else:

                             if np.peer_policy is not None:
                                 cfg='''router bgp {0}
                                        vrf {1}
                                        {2}
                                        neighbor {3}
                                        inherit peer {4}'''.format(
                                        as_no, np.vrf_name, af_config, neighbor_addr, np.peer_policy )
                             else:
                                 cfg='''router bgp {0}
                                        vrf {1}
                                        {2}
                                        neighbor {3} remote-as {4}'''.format(
                                        as_no, np.vrf_name, af_config, neighbor_addr, remote_as)
                                 if hasattr( np, 'keep_alive_time') and hasattr( np, 'hold_time') and np.kee_alive_time:
                                     cfg = cfg + '\n' + \
                                         '''timers {0} {1}'''.format(
                                            np.keep_alive_time, np.hold_time )

 
                          if hasattr( np, 'description' ) and np.description is not None:
                              cfg = cfg + '\n' + \
                                 '''description {0} {1}'''.format( np.description, neighbor_addr )
                         
                          if hasattr( np, 'update_source' ) and np.update_source is not None: 
                              cfg = cfg + '\n' + \
                                 '''update-source {0}'''.format( np.update_source )

                          if hasattr( np, 'ebgp_multihop' ) and np.ebgp_multihop is not None: 
                              cfg = cfg + '\n' + \
                                 '''ebgp-multihop {0}'''.format( np.ebgp_multihop )

                          if hasattr( np, 'password' ) and np.password is not None:
                              cfg = cfg + '\n' + \
                                 '''password {0} {1}'''.format(np.password_type, np.password)

                          if np.transport_connection_mode == "passive":
                              cfg = cfg + '\n' + \
                                  '''transport connection-mode'''

                          if hasattr( np, 'low_memory_action'):
                              if np.low_memory_action == "exempt":
                                 cfg = cfg + '\n' + \
                                    '''low-memory exempt'''

                          if hasattr( np, 'disable_capability_negotiation'):
                              cfg = cfg + '\n' + \
                                 '''dont-capability-negotiate'''

                          if np.disable_connected_check:
                              cfg = cfg + '\n' + \
                                 '''disable-connected-check'''

                          if np.dynamic_capability:
                              cfg = cfg + '\n' + \
                                 '''dynamic-capability'''
                          else:
                              cfg = cfg + '\n' + \
                                 '''no dynamic-capability'''

                          if np.suppress_4_byte_as:
                              cfg = cfg + '\n' + \
                                 '''capability suppress 4-byte-as'''

                          if hasattr( np, 'bfd' ) and np.bfd:
                              bringup_lib.configFeature( hdl, self.log, '-feature bfd' )
                              cfg = cfg + '\n' + \
                                 '''bfd'''



                          # Parse and build the address family configs ..
                          if 'address_family' in self.bgp_config_dict[node][as_no]['neighbors'][neighbor]:

                             # If AF IPv6 Unicast
                             if 'ipv6_unicast' in self.bgp_config_dict[node][as_no]['neighbors'][neighbor]           \
                                 ['address_family']:

                                 cfg = cfg + '\n' + \
                                    '''address-family ipv6 unicast'''

                                 afp=parseBgpAfIpv6Unicast( self.log, self.bgp_config_dict[node]   \
                                    [as_no]['neighbors'][neighbor]['address_family']['ipv6_unicast'] )

                                 if hasattr( afp, 'allow_as_in') and afp.allow_as_in is not None:
                                     cfg = cfg + '\n' +  \
                                         '''allowas-in {0}'''.format( afp.allow_as_in )
                             
                                 if hasattr( afp, 'as_override' ) and afp.as_override is True:
                                     cfg = cfg + '\n' + \
                                         '''as-override'''

                                 if hasattr( afp, 'default_originate' ) and afp.default_originate is True:
                                     cfg = cfg + '\n' + \
                                        '''default-originate'''

                                 if hasattr( afp, 'default_originate_route_map' ) and afp.default_originate_route_map \
                                     is not None:
                                     cfg = cfg + '\n' + \
                                       '''default-originate route-map {0}'''.format(afp.default_originate_route_map)

                                 if hasattr( afp, 'disable_peer_as_check' ) and afp.disable_peer_as_check is True:
                                     cfg = cfg + '\n' + \
                                       '''disable-peer-as-check'''

                                 if hasattr( afp, 'filter_list' ) and afp.filter_list is not None:
                                     cfg = cfg + '\n' + \
                                       '''filter-list {0}'''.format( afp.filter_list )

                                 if hasattr( afp, 'peer_policy' ) and afp.peer_policy is not None:
                                     cfg = cfg + '\n' + \
                                       '''inherit peer-policy {0}'''.format( afp.peer_policy )

                                 if hasattr( afp, 'maximum_prefix' ) and afp.maximum_prefix is not None:
                                     cfg = cfg + '\n' + \
                                       '''maximum-prefix {0}'''.format(afp.maximum_prefix)

                                 if hasattr( afp, 'next_hop_self' ) and afp.next_hop_self is True:
                                     cfg = cfg + '\n' + \
                                       '''next-hop-self'''

                                 if hasattr( afp, 'next_hop_third_party' ) and afp.next_hop_third_party is True:
                                     cfg = cfg + '\n' + \
                                       '''next-hop-third-party'''

                                 if hasattr( afp, 'next_hop_third_party' ) and afp.next_hop_third_party is True:
                                     cfg = cfg + '\n' + \
                                      '''next-hop-third-party'''

                                 if hasattr( afp, 'prefix_list' ) and afp.prefix_list is not None:
                                     cfg = cfg + '\n' + \
                                      '''prefix-list {0} {1}'''.format(afp.prefix_list, afp.prefix_list_direction)

                                 if hasattr( afp, 'route_reflector_client' ) and afp.route_reflector_client is True:
                                     cfg = cfg + '\n' + \
                                     '''route-reflector-client'''

                                 if hasattr( afp, 'send_community' ) and afp.send_community is True:
                                     cfg = cfg + '\n' + \
                                      '''send-community'''

                                 if hasattr( afp, 'send_community_extended' ) and afp.send_community_extended is True:
                                     cfg = cfg + '\n' + \
                                      '''send-community extended'''

                                 if hasattr( afp, 'soft_reconfiguration' ) and afp.soft_reconfiguration is True:
                                     cfg = cfg + '\n' + \
                                      '''soft-reconfiguration inbound'''

                                 if hasattr( afp, 'suppress_inactive' ) and afp.suppress_inactive is True:
                                     cfg = cfg + '\n' + \
                                       '''suppress-inactive'''

                                 if hasattr( afp, 'route_map' ) and afp.route_map is not None:
                                     cfg = cfg + '\n' + \
                                       '''route-map {0} {1}'''.format(afp.route_map, afp.route_map_direction)

                                 if hasattr( afp, 'weight' ) and afp.weight is not None:
                                     cfg = cfg + '\n' + \
                                       '''weight {0}'''.format(afp.weight)

                                 if hasattr( afp, 'advertise_map' ) and afp.advertise_map is not None:
                                     cfg = cfg + '\n' + \
                                      '''advertise-map {0} exist-map {1}'''.format(afp.advertise_map, \
                                      afp.advertise_exist_map)



                          # Apply the neighbor parameter configs  and AF configs..
                          hdl.configure(cfg)
                          # Increment the neighbor addr and remote-as
                          pattern_ipv4_addr = r'[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+'
                          match = re.search(pattern_ipv4_addr, str(neighbor_addr))
                          if match:
                             neighbor_addr=utils.incrementIpv4Address( neighbor_addr, np.neighbor_step )
                          else:
                             neighbor_addr=utils.incrementIpv6Address( neighbor_addr, np.neighbor_step )
                          #remote_as=remote_as + np.remote_as_step
                   else:
                      testResult( 'fail', 'neighbor_params not defined for BGP neighbors in bgp_config_dict', \
                          self.log )
               # Redistribution configs for Bgpv6
               if 'redistribution_configs' in self.bgp_config_dict[node][as_no]:
 
                   vrf_list=self.bgp_config_dict[node][as_no]['redistribution_configs'].keys()
 
                   for vrf_name in vrf_list:
                      if 'ipv6_unicast' in self.bgp_config_dict[node][as_no]['redistribution_configs'][vrf_name]:
 
                         redist_sources=self.bgp_config_dict[node][as_no]['redistribution_configs'] \
                             [vrf_name]['ipv6_unicast'].keys()
                         # If vrf == default
                         if vrf_name == "default":
                             cfg='''router bgp {0}
                                    address-family ipv6 unicast'''.format(as_no)
                         else:
                             cfg='''router bgp {0}
                                    vrf {1}
                                    address-family ipv6 unicast'''.format(as_no,vrf_name) 
 
 
                         for redist_source in redist_sources:
 
                            rd_ns=parseBgpRedistributionConfigs( self.log, self.bgp_config_dict[node] \
                                [as_no]['redistribution_configs'][vrf_name]['ipv6_unicast'][redist_source] )
                            if hasattr( rd_ns, 'tag_name' ) and rd_ns.tag_name is not None:
                                cfg = cfg + '\n' + \
                                    '''redistribute {0} {1} route-map {2}'''.format( redist_source,   \
                                       rd_ns.tag_name, rd_ns.route_map )
                            else:
                                cfg = cfg + '\n' + \
                                    '''redistribute {0} route-map {1}'''.format( redist_source,   \
                                       rd_ns.route_map )
                   # Apply the per VRF redistribution configs ..
                   hdl.configure(cfg)



class verifyBgpv6(object):

    def __init__(self, bgp_config_dict, switch_dict, switch_hdl_dict, log, *args ):

        self.log=log
        self.result='pass'
        self.bgp_config_dict=bgp_config_dict
      
        arggrammar={}
        arggrammar['verify_detail'] = '-type bool -default True'
        ns_inputargs=parserutils_lib.argsToCommandOptions(args, arggrammar, log)

        try:
           list_of_nodes=self.bgp_config_dict.keys()
        except KeyError:
           err_msg='Error !!! bgp_config_dict has not been defined properly, does not have nodes   \
              as the top level keys'
           testResult( 'fail', err_msg, self.log )

        for node in list_of_nodes:
            print(node)
            hdl=switch_hdl_dict[node]

            # Verify Bgp is enabled
            feature_name='bgp'
            if verify_lib.verifyFeatureState(hdl,log,'-feature {0}'.format(feature_name)).result=='pass':
                log.info('Feature {0} is in enabled state'.format(feature_name))
                testResult('pass','Feature {0} is in enabled state'.format(feature_name),log)
            else:
                log.error('Feature {0} is not in enabled state'.format(feature_name))
                testResult('fail','Feature {0} is not in enabled state'.format(feature_name),log)

            hdl.iexec('show ipv6 bgp summary')
            output = hdl.iexec('show ipv6 route summary')
            pattern = r'Total number of paths:[ \t]+([0-9]+)'
            match = re.search(pattern, output)
            total_path = 0
            if match:
               total_path = int(match.group(1))
            if total_path < 100000:
               hdl.iexec('show ipv6 route bgp')
            else:
               output = hdl.iexec('dir bootflash:show_ipv6_route_bgp')
               match = re.search(r'show_ipv6_route_bgp', output)
               if match:
                  hdl.isendline('delete bootflash:show_ipv6_route_bgp')
                  hdl.iexpect('Do you want to delete \"/show_ipv6_route_bgp\" \? \(yes/no/abort\)   \[y\]')
                  hdl.isendline('y')
                  hdl.iexpect('# $')
               hdl.isendline('show ipv6 route bpg > bootflash:show_ipv6_route_bgp')


            as_nos=self.bgp_config_dict[node].keys()

            # In future if we allow multiple AS
            for as_no in as_nos:

               # Build Router configs ..
               router_vrfs=self.bgp_config_dict[node][as_no]['router_configs']
               
               for vrf_name in router_vrfs:

                   # Verify the VRF is in proper state ..
                   verify_lib.verifyVrfState( hdl, log, '-vrf {0}'.format(vrf_name) )

                   ns=parseBgpRouterConfigs( self.log, self.bgp_config_dict[node][as_no]           \
                        ['router_configs'][vrf_name] )



               # Template configuration
               if 'templates' in self.bgp_config_dict[node][as_no]:
                  for template in self.bgp_config_dict[node][as_no]['templates'].keys():
                     ns=parseBgpTemplate( self.log, self.bgp_config_dict[node][as_no]['templates'][template] )


               bgp_neigh_dict=utils.getIpv6BgpNeighborDict( hdl, self.log, '-vrf all' )
               print( 'bgp_neigh_dict', bgp_neigh_dict )

               show_run=hdl.iexec('show running-config bgp all')

               print('%%%%% bgp_neigh_dict %%%', bgp_neigh_dict )
               # Neighbor configuration
               if len( bgp_neigh_dict.keys() ) == 0:

                 testResult( 'fail', 'No BGP neighbors found .. BGP configs did not take effect', self.log )

               else:

                 for neighbor in self.bgp_config_dict[node][as_no]['neighbors'].keys():

                   if 'neighbor_params' in self.bgp_config_dict[node][as_no]['neighbors'][neighbor]:
                      np=parseBgpv6NeighborParams( self.log, self.bgp_config_dict[node][as_no]['neighbors'] \
                        [neighbor]['neighbor_params'] )

                      # Iterate over the neighbor_count
                      neighbor_addr=neighbor
                      remote_as=np.remote_as

                      for i in range( 0, np.neighbor_count ):

                          if neighbor_addr in bgp_neigh_dict:
                              # Verify if the states are in Established state ..
                              if not re.search( 'Established', bgp_neigh_dict[neighbor_addr]['state'], flags=re.I ):
                                 msg='BGP Neighbor {0} is not in Established state on node {1}'.format( neighbor_addr,  \
                                    node )
                                 testResult( 'fail', msg, self.log )
                              else:
                                 msg='BGP Neighbor {0} is in Established state as expected on node {1}'.format(    \
                                    neighbor_addr, node )
                                 testResult( 'pass', msg, self.log )

                          #fix the issue for ipv4 address can be used for neighbor id in BGPv6
                          pattern_ipv4_addr = r'[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+'
                          match = re.search(pattern_ipv4_addr, str(neighbor_addr))
                          if match:
                             neighbor_addr=utils.incrementIpv4Address( neighbor_addr, np.neighbor_step )
                          else:
                             neighbor_addr=str(utils.incrementIpv6Address( neighbor_addr, np.neighbor_step ))
                          #remote_as=remote_as + np.remote_as_step

                          if not ns_inputargs.verify_detail:
                            continue
                          
                          # Verify if the remote AS is proper for the neighbors ..
                          if hasattr( np, 'remote_as' ) and np.remote_as is not None:
                              if neighbor in bgp_neigh_dict:
                                  if int(np.remote_as) != int(bgp_neigh_dict[neighbor]['as']):
                                      msg='Error remote-as for neighbor {0} is incorrect on node {1},             \
                                         Expected {2} Actual {3}'.format( neighbor, node, np.remote_as,           \
                                         bgp_neigh_dict[neighbor]['as'] )
                                      testResult( 'fail', msg, self.log )
                                  else:
                                      msg='Neighbor remote-as for neighbor {0} is correct on node {1},            \
                                         Expected {2} Actual {3}'.format( neighbor, node, np.remote_as,           \
                                         bgp_neigh_dict[neighbor]['as'] )
                                      testResult( 'pass', msg, self.log )

                              # Verify it is getting saved to running configs
                              run_pattern='neighbor {0} remote-as {1}'.format( neighbor, np.remote_as )
                              if not re.search( run_pattern, show_run, flags=re.I ):
                                  testResult( 'fail', '{0} missing in running config'.format(run_pattern),   \
                                      self.log )
                              

                          # Verify if the update-source is proper ..
                          if hasattr( np, 'update_source' ) and np.update_source is not None:
                              cmd='show ip bgp neighbor {0}'.format(neighbor)
                              show_bgp=hdl.iexec(cmd)
                              if re.search( 'as update source', show_bgp, flags=re.I ):
                                  pattern = 'Using ({0}) as update source for this peer'.format( rex.INTERFACE_NAME )
                                  match=re.search( pattern, show_bgp )
                                  source_int=utils.normalizeInterfaceName( self.log, match.group(1) )
                                  update_source_int=utils.normalizeInterfaceName( self.log, np.update_source )
                                  if source_int != update_source_int:
                                      msg='Error !! Update source intf for neighbor {0} on node {1} incorrect    \
                                        Expected - {2}, Actual - {3}'.format( neighbor, node, update_source_int, \
                                        source_int )
                                      testResult( 'fail', msg, self.log )
                                  else:
                                      msg='Update source for neighbor {0} shows up correctly as {1}'.format(     \
                                        neighbor, source_int )
                                      testResult( 'pass', msg, self.log )
                              # If Update source is missing in the show output          
                              else:
                                  msg='Error !! Update source interface for neighbor {0} is missing'.format(     \
                                    neighbor)
                                  testResult( 'fail', msg, self.log )


                          # Verify timers ..
                          if hasattr( np, 'keep_alive_time') and hasattr( np, 'hold_time') and np.keep_alive_time:
                              if neighbor in bgp_neigh_dict:
                                  if int(np.keep_alive_time) != int(bgp_neigh_dict[neighbor]['keepalive']):
                                      msg='Error Keeplive time not correct for neighbor {0} on node {1}, Expected    \
                                        = {2} , Actual = {3}'.format( neighbor, node, np.keep_alive_time,            \
                                        bgp_neigh_dict[neighbor]['keepalive'] )
                                      testResult( 'fail', msg, self.log )
                                  else:
                                      msg='Keeplive time configured correctly for neighbor {0} on node {1}, Expected \
                                        = {2} , Actual = {3}'.format( neighbor, node, np.keep_alive_time,            \
                                        bgp_neigh_dict[neighbor]['keepalive'] )
                                      testResult( 'pass', msg, self.log )


                          if hasattr( np, 'hold_time' ) and np.hold_time is not None:
                              if neighbor in bgp_neigh_dict:
                                  if int(np.hold_time) != int(bgp_neigh_dict[neighbor]['holdtime']):
                                      msg='Error Hold time not correct for neighbor {0} on node {1}, Expected       \
                                        = {2} , Actual = {3}'.format( neighbor, node, np.hold_time,                 \
                                        bgp_neigh_dict[neighbor]['holdtime'] )
                                      testResult( 'fail', msg, self.log )
                                  else:
                                      msg='Hold time configured correctly for neighbor {0} on node {1}, Expected    \
                                        = {2} , Actual = {3}'.format( neighbor, node, np.hold_time,                 \
                                        bgp_neigh_dict[neighbor]['holdtime'] )
                                      testResult( 'pass', msg, self.log )



############
#MSDC
############

class ConnectToIxia(object):

    def __init__(self,log,hlite, hlt_version, ixia_config_file): 
 
        self.log=log
        self.hlite=hlite
        self.hlt_version=hlt_version
        self.ixia_config_file=ixia_config_file

        tcl=Tkinter.Tcl()
        hlite.gd['tcl']=tcl
        cmd='set env(IXIA_VERSION) {0}'.format(self.hlt_version)
        tcl.eval(cmd)
        tcl.eval('package require Ixia')
        time.sleep(30)
        tg_node_dict=self.hlite.gd['Topology']['tg_node_dict']
        #ixia_config_file = self.hlite.gd['Topology']['ixia_config_file']

        # Connect to the chassis and load the config file given through Suite file ..
        l_args='-load_from_config_file YES -config_file {0}'.format(self.ixia_config_file)
        ixia_obj=ixia_lib.ixNetworkConfigFromFile( tcl, self.log, tg_node_dict, l_args )
        time.sleep(10)
        #tcl.eval('set ::ixia::session_resume_keys 1')
        #tcl.eval('update idletasks')

        # Start all protocol emulation from Ixia defined in the config file ..
        ixia_obj.startAllProtocols()
        time.sleep(60)
        #Start the Traffic
        #ixia_obj.startTraffic()
        #return ixia_obj

class verifyBgpSessions(object):

    def __init__(self, bgp_config_dict, switch_dict, switch_hdl_dict, log, *args ):

        self.log=log
        self.result='pass'
        self.duts=utils.strtolist(switch_dict)
        self.bgp_config_dict=bgp_config_dict

        arggrammar={}
        arggrammar['node_list']='-type str'
        arggrammar['verify_detail'] = '-type bool -default True'
        ns_inputargs=parserutils_lib.argsToCommandOptions(args, arggrammar, log)

        if ns_inputargs.node_list is not None:
            list_of_nodes=ns_inputargs.node_list.split(',')
        else:
            try:
               list_of_nodes=self.bgp_config_dict.keys()
            except KeyError:
               err_msg='Error !!! bgp_config_dict has not been defined properly, does not have nodes   \
                  as the top level keys'
               testResult( 'fail', err_msg, self.log )

        for dut in self.duts:
           print(dut)
           self.log.info('Dut: {0}'.format(dut))
           print('%%% switch_hdl_dict %%%', switch_hdl_dict )
           hdl=switch_hdl_dict[dut]

           as_nos=self.bgp_config_dict[dut].keys()
           for as_no in as_nos:
               bgp_session_obj=utils.getIpv4BgpSessionDict( hdl, self.log, '-vrf all' )
               print('%%%% bgp_session_obj  %%%%',bgp_session_obj )
               if len( bgp_session_obj.keys() ) == 0:
                 testResult( 'fail', 'No BGP neighbors found .. BGP configs did not take effect', self.log )
                 return
                 # Neighbor configuration
               for neighbor in self.bgp_config_dict[dut][as_no]['neighbors'].keys():
                   if 'neighbor_params' in self.bgp_config_dict[dut][as_no]['neighbors'][neighbor]:
                      np_args = self.bgp_config_dict[dut][as_no]['neighbors'][neighbor]['neighbor_params']
                      np=parseBgpNeighborParams( self.log, np_args)

                      ns_args = ''
                      if hasattr(np, 'inherit_peer'):
                          if 'templates' in self.bgp_config_dict[dut][as_no]:
                              if np.inherit_peer in self.bgp_config_dict[dut][as_no]['templates'].keys():
                                  ns_args=self.bgp_config_dict[dut][as_no]['templates'][np.inherit_peer]

                      # Iterate over the neighbor_count
                      neighbor_addr=neighbor
                      remote_as=np.remote_as
                      print('%%%% neighbor_addr %%%%', neighbor_addr )
                      for i in range( 0, np.neighbor_count ):

                          # Verify if the states are in Established state ..
                          if neighbor_addr in bgp_session_obj:
                            if not re.search( 'E', bgp_session_obj[neighbor]['state'], flags=re.I ):
                               msg='BGP Neighbor {0} is not in Established state on node {1}'.format( neighbor_addr,  \
                                  dut )
                               testResult( 'fail', msg, self.log )
                            else:
                               msg='BGP Neighbor {0} is in Established state as expected on node {1}'.format(    \
                                  neighbor_addr, dut )
                               testResult( 'pass', msg, self.log )
                          else:
                            msg='BGP Neighbor {0} does not exist on node {1}'.format( neighbor_addr, dut )
                            testResult( 'fail', msg, self.log )



class verifyBgpV6RoutesOverV4Sessions(object):

    def __init__(self, bgp_config_dict, switch_dict, switch_hdl_dict, log, ipv6Overv4, *args ):

        self.log=log
        self.result='pass'
        self.duts=switch_dict
        self.bgp_config_dict=bgp_config_dict
        self.ipv6Overv4=utils.strtolist(ipv6Overv4)


        arggrammar={}
        arggrammar['node_list']='-type str'
        arggrammar['verify_detail'] = '-type bool -default True'
        ns_inputargs=parserutils_lib.argsToCommandOptions(args, arggrammar, log)

        if ns_inputargs.node_list is not None:
            list_of_nodes=ns_inputargs.node_list.split(',')
        else:
            try:
               list_of_nodes=self.bgp_config_dict.keys()
            except KeyError:
               err_msg='Error !!! bgp_config_dict has not been defined properly, does not have nodes   \
                  as the top level keys'
               testResult( 'fail', err_msg, self.log )

        for item in self.ipv6Overv4:
           print(item)
           item=item.split("/")
           dut=item[0]
           self.log.info('item:{0}'.format(item))
           ipv4=item[1]
           prefixrcvd=item[2] 
           self.log.info('Dut: {0}'.format(dut))
           print('%%% switch_hdl_dict %%%', switch_hdl_dict )
           hdl=switch_hdl_dict[dut]
           bgpv6_neighbor_obj=utils.getIpv4FromV6BgpSummaryDict( hdl, self.log, '-vrf all' )
           if ipv4 in bgpv6_neighbor_obj:
               prefix=bgpv6_neighbor_obj[ipv4]['PfxRcd']
               if prefix < prefixrcvd:
               #if not re.search( 'prefixrcvd', bgpv6_neighbor_obj[ipv4]['PfxRcd'], flags=re.I ):
                  msg='BGP V6 route over V4 for Neighbor {0} didnt recieve expected prefix {2} on node {1} instead got {3} '.format( ipv4, dut, prefixrcvd ,prefix)
                  testResult( 'fail', msg, self.log)
               else:
                  msg='BGP V6 route over V4 for Neighbor {0} recieved expected prefix {2} on node {1}'.format(    \
                                  ipv4, dut,prefixrcvd )
                  testResult( 'pass', msg, self.log )
           else:
                msg='BGP v4 Neighbor {0} does not exist on node {1} v6 session'.format( ipv4, dut )
                testResult( 'fail', msg, self.log )


class verifyBgpV4RoutesOverV6Sessions(object):

    def __init__(self, bgp_config_dict, switch_dict, switch_hdl_dict, log, ipv4Overv6, *args ):

        self.log=log
        self.result='pass'
        self.duts=switch_dict
        self.bgp_config_dict=bgp_config_dict
        self.ipv4Overv6=utils.strtolist(ipv4Overv6)


        arggrammar={}
        arggrammar['node_list']='-type str'
        arggrammar['verify_detail'] = '-type bool -default True'
        ns_inputargs=parserutils_lib.argsToCommandOptions(args, arggrammar, log)

        if ns_inputargs.node_list is not None:
            list_of_nodes=ns_inputargs.node_list.split(',')
        else:
            try:
               list_of_nodes=self.bgp_config_dict.keys()
            except KeyError:
               err_msg='Error !!! bgp_config_dict has not been defined properly, does not have nodes   \
                  as the top level keys'
               testResult( 'fail', err_msg, self.log )

        for item in self.ipv4Overv6:
           print(item)
           item=item.split("/")
           dut=item[0]
           self.log.info('item:{0}'.format(item))
           ipv6=item[1]
           prefixrcvd=item[2] 
           self.log.info('Dut: {0}'.format(dut))
           print('%%% switch_hdl_dict %%%', switch_hdl_dict )
           hdl=switch_hdl_dict[dut]
           bgpv4_neighbor_obj=utils.getIpv6FromV4BgpSummaryDict( hdl, self.log, '-vrf all' )
           if ipv6 in bgpv4_neighbor_obj:
               prefix=bgpv4_neighbor_obj[ipv6]['PfxRcd']
               if prefix != prefixrcvd:
               #if not re.search( 'prefixrcvd', bgpv6_neighbor_obj[ipv4]['PfxRcd'], flags=re.I ):
                  msg='BGP V4 route over V6 for Neighbor {0} didnt recieve expected prefix {2} on node {1} instead got {3} '.format( ipv6, dut, prefixrcvd ,prefix)
                  testResult( 'fail', msg, self.log)
               else:
                  msg='BGP V4 route over V4 for Neighbor {0} recieved expected prefix {2} on node {1}'.format(    \
                                  ipv6, dut,prefixrcvd )
                  testResult( 'pass', msg, self.log )
           else:
                msg='BGP v6 Neighbor {0} does not exist on node {1} v4 session'.format( ipv6, dut )
                testResult( 'fail', msg, self.log )


class configBgpPeerRoutemap(object):
    
    def __init__(self, bgp_config_dict, switch_dict, switch_hdl_dict, log,routemapConfig,action,*args ):

      self.log=log
      self.result='pass'
      self.duts=switch_dict
      self.bgp_config_dict=bgp_config_dict
      self.action=action
      self.routemapConfig=utils.strtolist(routemapConfig)

      for item in self.routemapConfig:
          print(item)
          item=item.split("/")
          dut=str(item[0])
          self.log.info('item:{0}'.format(item))
          neighborIp=str(item[1])
          ipType=str(item[2])
          routemap=str(item[3])
          direction=str(item[4])
          print(dut)
          
          self.log.info('Dut: {0}'.format(dut))
          print('%%% switch_hdl_dict %%%', switch_hdl_dict )
          hdl=switch_hdl_dict[dut]
          as_nos=self.bgp_config_dict[dut].keys()
          for as_no in as_nos:
           print(as_no)
           print(neighborIp)
           np_args = self.bgp_config_dict[dut][as_no]['neighbors'][neighborIp]['neighbor_params']
           np=parseBgpNeighborParams( self.log, np_args)
           if action == "add":
                if np.inherit_peer is not None:
                     cfg='''router bgp {0}
                         template peer {1}
                         address-family {2} unicast
                         route-map {3} {4}'''.format(as_no,np.inherit_peer,ipType,routemap,direction)
                else:
                   cfg='''router bgp {0}
                         neighbor {4}
                         address-family {1} unicast
                         route-map {2} {3}'''.format(as_no,ipType,routemap,direction,neighborIp)

           if action == "delete":
               if np.inherit_peer is not None:
                   cfg='''router bgp {0}
                           template peer {1}
                           address-family {2} unicast
                           no route-map {3} {4}'''.format(as_no,np.inherit_peer,ipType,routemap,direction)
               else:
                  cfg='''router bgp {0}
                        neighbor {4}
                        address-family {1} unicast
                        no route-map {2} {3}'''.format(as_no,ipType,routemap,direction,neighborIp)
           hdl.configure(cfg)

class configBgpRoutemap(object):

    def __init__(self, bgp_config_dict, switch_dict, switch_hdl_dict, log,routemapConfig,action,*args ):

      self.log=log
      self.result='pass'
      self.duts=switch_dict
      self.bgp_config_dict=bgp_config_dict
      self.action=action
      self.routemapConfig=utils.strtolist(routemapConfig)

      for item in self.routemapConfig:
          print(item)
          item=item.split("/")
          dut=str(item[0])
          self.log.info('item:{0}'.format(item))
          neighborIp=str(item[1])
          ipType=str(item[2])
          routemap=str(item[3])
          direction=str(item[4])

          print(dut)

          self.log.info('Dut: {0}'.format(dut))
          print('%%% switch_hdl_dict %%%', switch_hdl_dict )
          hdl=switch_hdl_dict[dut]
          as_nos=self.bgp_config_dict[dut].keys()
          for as_no in as_nos:
           print(as_no)
           print(neighborIp)
           np_args = self.bgp_config_dict[dut][as_no]['neighbors'][neighborIp]['neighbor_params']
           np=parseBgpNeighborParams( self.log, np_args)
           if action == "add":
                   cfg='''router bgp {0}
                         neighbor {4}
                         address-family {1} unicast
                         route-map {2} {3}'''.format(as_no,ipType,routemap,direction,neighborIp)

           if action == "delete":
                  cfg='''router bgp {0}
                        neighbor {2}
                        default address-family {1} unicast'''.format(as_no,ipType,neighborIp)
           hdl.configure(cfg)



class configBgpConditionalAdvertisement(object):

    def __init__(self, bgp_config_dict, switch_dict, switch_hdl_dict, log,advertiseMapConfig,action,*args ):

      self.log=log
      self.result='pass'
      self.duts=switch_dict
      self.bgp_config_dict=bgp_config_dict
      self.action=action
      self.advertiseMapConfig=utils.strtolist(advertiseMapConfig)

      for item in self.advertiseMapConfig:
          print(item)
          item=item.split("/")
          dut=str(item[0])
          self.log.info('item:{0}'.format(item))
          neighborIp=str(item[1])
          ipType=str(item[2])
          routemap=str(item[3])
          routemap1=str(item[4])

          print(dut)

          self.log.info('Dut: {0}'.format(dut))
          print('%%% switch_hdl_dict %%%', switch_hdl_dict )
          hdl=switch_hdl_dict[dut]
          as_nos=self.bgp_config_dict[dut].keys()
          for as_no in as_nos:
           print(as_no)
           print(neighborIp)
           np_args = self.bgp_config_dict[dut][as_no]['neighbors'][neighborIp]['neighbor_params']
           np=parseBgpNeighborParams( self.log, np_args)
           if action == "add":
                   cfg='''router bgp {0}
                         neighbor {4}
                         address-family {1} unicast
                         advertise-map {2} non-exist-map {3}'''.format(as_no,ipType,routemap,routemap1,neighborIp)

           if action == "delete":
                  cfg='''router bgp {0}
                        neighbor {2}
                        default address-family {1} unicast'''.format(as_no,ipType,neighborIp)
           hdl.configure(cfg)


class verifyBgpV6NumberofRoutes(object):

     def __init__(self, switch_dict, switch_hdl_dict, log, totalRoutes, *args):

        self.log=log
        self.result='pass'
        self.duts=utils.strtolist(switch_dict)
        self.totalRoutes=totalRoutes
        print(self.duts) 
        for dut in self.duts:
           print(dut)
           self.log.info('Dut: {0}'.format(dut))
           print('%%% switch_hdl_dict %%%', switch_hdl_dict )
           hdl=switch_hdl_dict[dut]
           total_routes=utils.getBgpV6RouteSummary( hdl, self.log, '-vrf all' )
           if total_routes < self.totalRoutes:
                  msg='Number of Routes expected is {0}, but got {1}'.format(self.totalRoutes,total_routes)
                  testResult( 'fail', msg, self.log )
           else:
                  msg='Number of Routes Recieved as Expected'
                  testResult( 'pass',msg, self.log )



class verifyEcmpForwardingIPv4RouteDetail(object):
   
      def __init__(self, switch_dict, switch_hdl_dict, log,*args ):
                  self.log=log
                  self.result='pass'
                  self.duts=switch_dict
                  arggrammar={}
                  arggrammar['dut']='-type str'
                  arggrammar['route']='-type str'
                  arggrammar['path_no']='-type str'
                  arggrammar['nexthop']=''
                  arggrammar['nexthopInt']=''
                  ns=parserutils_lib.argsToCommandOptions(args,arggrammar,log)
                  self.log.info('Dut: {0}'.format(ns.dut))
                  print('%%% switch_hdl_dict %%%', switch_hdl_dict )
                  hdl=switch_hdl_dict[ns.dut]
                  nexthop=utils.strtolist(ns.nexthop)
                  nexthopInt=utils.strtolist(ns.nexthopInt)
                  print(ns.route)
                  routeDict=utils.getForwardingIPv4RouteDetail(hdl,log,ns.route)
                  print('RouteDict:',routeDict)
                  print('RouteDictKe:',routeDict.keys())
                  print('RouteDictVal:',routeDict.values())
                  print('RouteDictItem:',routeDict.items())
                  if ns.route in routeDict:
                     totalPaths=routeDict[ns.route]['Paths']
                     nexthops=routeDict[ns.route]['nexthop']
                     nexthopInts=routeDict[ns.route]['nexthopInt']
                     if ns.path_no == totalPaths:
                        msg='The total path for route {0} is {1} as expected'.format(ns.route,ns.path_no)
                        testResult( 'pass', msg, self.log )
                     else:
                        msg='The total path for route {0} expected is {1} but got {2}'.format(ns.route,ns.path_no,totalPaths)
                        testResult( 'fail', msg, self.log )
                     for item in nexthop:
                       if item in nexthops:
                        msg='The nexthop {0} is seen as expected'.format(item)
                        testResult( 'pass', msg, self.log )
                       else:
                        msg='The nexthop {0} is not found as expected'.format(item)
                        testResult( 'fail', msg, self.log )
                     for item in nexthopInt:
                       if item in nexthopInts:
                        msg='The nexthop interface {0} is seen as expected'.format(item)
                        testResult( 'pass', msg, self.log )
                       else:
                        msg='The nexthop interface {0} not seen as expected'.format(item)
                        testResult( 'fail', msg, self.log )



class AddBgpTemplateForNeighbor(object):

     def __init__(self, bgp_config_dict, switch_dict, switch_hdl_dict, log, templateConfig,template, *args):
          
        self.log=log
        self.result='pass'
        self.bgp_config_dict=bgp_config_dict 
        self.duts=switch_dict
        self.templateConfig=utils.strtolist(templateConfig)

        for item in self.templateConfig:
          print(item)
          item=item.split("/")
          dut=str(item[0])
          neighborIp=item[1]
          #template=item[2]
          action=item[2]
          
          as_nos=self.bgp_config_dict[dut].keys()
          for as_no in as_nos: 
              self.log.info('Dut: {0}'.format(dut))
              print('%%% switch_hdl_dict %%%', switch_hdl_dict )
              hdl=switch_hdl_dict[dut]   
              if action == "add":
                  cfg='''router bgp {0}
                         neighbor {1}
                         inherit peer {2}'''.format(as_no,neighborIp,template)
              if action == "delete":
                  cfg='''router bgp {0}
                        neighbor {1}
                        no inherit peer {2}'''.format(as_no,neighborIp,template)
              hdl.configure(cfg)


class ConfigRemovePrivateAS(object):

    def __init__(self, bgp_config_dict, switch_dict, switch_hdl_dict, log,neighborConfig,action,*args):

       self.log=log
       self.result='pass'
       self.bgp_config_dict=bgp_config_dict
       self.neighborConfig=utils.strtolist(neighborConfig)

       for item in self.neighborConfig:
         print(item)
         item=item.split("/")
         dut=str(item[0])
         self.log.info('item:{0}'.format(item))
         neighborIp=str(item[1])
         #action=item[2]
         self.duts=switch_dict
         as_nos=self.bgp_config_dict[dut].keys()
         hdl=switch_hdl_dict[dut]
         for as_no in as_nos:
           print(as_no)
           print(neighborIp)
           if action == "add":
                   cfg='''router bgp {0}
                         neighbor {1}
                         remove-private-as'''.format(as_no,neighborIp)
           if action == "delete":
                     cfg='''router bgp {0}
                        neighbor {1}
                        default remove-private-as'''.format(as_no,neighborIp)
           hdl.configure(cfg) 

class ConfigBgpRedistribute(object):

    def __init__(self, bgp_config_dict, switch_dict, switch_hdl_dict, log,redistributeConfig,routeType,action,*args):
 
       self.log=log
       self.result='pass'
       self.bgp_config_dict=bgp_config_dict
       self.redistributeConfig=utils.strtolist(redistributeConfig)
       
       for item in self.redistributeConfig:
           item=item.split("/")
           dut=str(item[0])
           ipType=str(item[1])
           routeMap=str(item[2])
           self.duts=switch_dict
           as_nos=self.bgp_config_dict[dut].keys()
           hdl=switch_hdl_dict[dut]
           for as_no in as_nos:
             if action == "add":
                if routeType == "static":
                   cfg='''router bgp {0}
                          address-family {1} unicast
                          redistribute static route-map {2}'''.format(as_no,ipType,routeMap)
                if routeType == "ospf":
                   cfg='''router bgp {0}
                          address-family {1} unicast
                          redistribute ospf 2 route-map {2}'''.format(as_no,ipType,routeMap)
             if action == "delete":
                if routeType == "static":
                   cfg='''router bgp {0}
                          address-family {1} unicast
                          no redistribute static route-map {2}'''.format(as_no,ipType,routeMap)
                if routeType == "ospf":
                   cfg='''router bgp {0}
                          address-family {1} unicast
                          no redistribute ospf 2 route-map {2}'''.format(as_no,ipType,routeMap)
             hdl.configure(cfg)


class ConfigBgpNetwork(object):

    def __init__(self, bgp_config_dict, switch_dict, switch_hdl_dict, log,networkConfig,action,*args):

       self.log=log
       self.result='pass'
       self.bgp_config_dict=bgp_config_dict
       self.networkConfig=utils.strtolist(networkConfig)

       for item in self.networkConfig:
            item=item.split("|")
            dut=str(item[0])
            ipType=str(item[1])
            network=str(item[2])
            self.duts=switch_dict
            as_nos=self.bgp_config_dict[dut].keys()
            hdl=switch_hdl_dict[dut]
            for as_no in as_nos:
               if action == "add":
                   cfg='''router bgp {0}
                          address-family {1} unicast
                          network {2}'''.format(as_no,ipType,network)
               if action == "delete":
                   cfg='''router bgp {0}
                          address-family {1} unicast
                          no network {2}'''.format(as_no,ipType,network)
               hdl.configure(cfg)

class ConfigBgpGracefulRestartHelper(object):

    def __init__(self, bgp_config_dict, switch_dict, switch_hdl_dict, log,*args):

       self.log=log
       self.result='pass'
       self.bgp_config_dict=bgp_config_dict
       arggrammar={}
       arggrammar['dut']='-type str'
       arggrammar['action']='-type str'
       ns=parserutils_lib.argsToCommandOptions(args,arggrammar,self.log)
       self.log.info('Dut: {0}'.format(ns.dut))
       print('%%% switch_hdl_dict %%%', switch_hdl_dict )
       hdl=switch_hdl_dict[ns.dut]
       as_nos=self.bgp_config_dict[ns.dut].keys()
       for as_no in as_nos:
               if ns.action == "add":
                   cfg='''router bgp {0}
                          graceful-restart-helper'''
               if ns.action == "delete":
                   cfg='''router bgp {0}
                          no graceful-restart-helper'''
       hdl.configure(cfg)


class ConfigStaticRoutes(object):

    def __init__(self,switch_dict, switch_hdl_dict, log,routeConfig,action,*args):
        self.log=log
        self.result='pass'
        self.routeConfig=utils.strtolist(routeConfig)

        for item in self.routeConfig:
                item=item.split("|")
                dut=str(item[0])
                prefix=str(item[1])
                gatewayIp=str(item[2])
                self.duts=switch_dict
                hdl=switch_hdl_dict[dut]
                if action == "config":
                    cfg='''ip route {0} {1}'''.format(prefix,gatewayIp)
                if action == "unconfig":
                    cfg='''no ip route {0} {1}'''.format(prefix,gatewayIp)
                hdl.configure(cfg)


class ConfigPrefixList(object):

    def __init__(self,switch_dict, switch_hdl_dict, log,prefixConfig,action,*args):

        self.log=log
        self.result='pass'
        self.prefixConfig=utils.strtolist(prefixConfig)
 
        for item in self.prefixConfig:
                item=item.split("|")
                dut=str(item[0])
                ipType=str(item[1])
                prefixList=str(item[2])
                permission=str(item[3])
                prefix=str(item[4])
                prefixLength=str(item[5])
                self.duts=switch_dict
                hdl=switch_hdl_dict[dut]
                if action == "config":
                    cfg='''{0} prefix-list {1} {2} {3} ge {4}'''.format(ipType,prefixList,permission,prefix,prefixLength)
                if action == "unconfig":
                    cfg='''no {0} prefix-list {1} {2} {3} ge {4}'''.format(ipType,prefixList,permission,prefix,prefixLength)
                hdl.configure(cfg)

class ConfigRouteMap(object):

    def __init__(self,switch_dict, switch_hdl_dict, log,routemapConfig,action,*args):

        self.log=log
        self.result='pass'
        self.routemapConfig=utils.strtolist(routemapConfig)

        for item in self.routemapConfig:
                item=item.split("|")
                dut=str(item[0])
                routemap=str(item[1])
                permission=str(item[2])
                prefixList=str(item[3])
                ipType=str(item[4])
                self.duts=switch_dict
                hdl=switch_hdl_dict[dut]
                if action == "config":
                      cfg='''route-map {0} {1}        
                             match {2} address prefix-list {3}'''.format(routemap,permission,ipType,prefixList)
                if action == "unconfig":
                    cfg='''no route-map {0}'''.format(routemap)
                hdl.configure(cfg)

class ConfigBgpLocalPreferenceRouteMap(object):

    def __init__(self,switch_dict, switch_hdl_dict, log,routemapConfig,action,*args):

        self.log=log
        self.result='pass'
        self.routemapConfig=utils.strtolist(routemapConfig)

        for item in self.routemapConfig:
                item=item.split("|")
                dut=str(item[0])
                routemap=str(item[1])
                permission=str(item[2])
                preference=str(item[3])
                self.duts=switch_dict
                hdl=switch_hdl_dict[dut]
                if action == "config":
                    cfg='''route-map {0} {1}
                              set local-preference {2}'''.format(routemap,permission,preference)
                if action == "unconfig":
                    cfg='''no route-map {0}'''.format(routemap)

                hdl.configure(cfg)

class ConfigBgpASPathPrependRouteMap(object):

    def __init__(self,switch_dict, switch_hdl_dict, log,routemapConfig,action,*args):

        self.log=log
        self.result='pass'
        arggrammar={}
        arggrammar['AsPath']='-type str'
        ns=parserutils_lib.argsToCommandOptions(args,arggrammar,self.log)
        self.routemapConfig=utils.strtolist(routemapConfig)

        for item in self.routemapConfig:
                item=item.split("|")
                print(item)
                dut=str(item[0])
                routemap=str(item[1])
                permission=str(item[2])
                #AsPath=str(item[3])
                #print AsPath
                self.duts=switch_dict
                hdl=switch_hdl_dict[dut]
                if action == "config":
                    cfg='''route-map {0} {1}
                              set as-path prepend {2}'''.format(routemap,permission,ns.AsPath)
                if action == "unconfig":
                    cfg='''no route-map {0}'''.format(routemap)

                hdl.configure(cfg)

class ConfigBgpMEDAttribute(object):

    def __init__(self,switch_dict, switch_hdl_dict, log,routemapConfig,action,*args):

        self.log=log
        self.result='pass'
        self.routemapConfig=utils.strtolist(routemapConfig)

        for item in self.routemapConfig:
                item=item.split("|")
                dut=str(item[0])
                routemap=str(item[1])
                permission=str(item[2])
                metric=str(item[3])
                self.duts=switch_dict
                hdl=switch_hdl_dict[dut]
                if action == "config":
                    cfg='''route-map {0} {1}
                              set metric {2}'''.format(routemap,permission,metric)
                if action == "unconfig":
                    cfg='''no route-map {0}'''.format(routemap)
                hdl.configure(cfg)

class ConfigBgpCommunityAttribute(object):

    def __init__(self,switch_dict, switch_hdl_dict, log,routemapConfig,action,*args):

        self.log=log
        self.result='pass'
        self.routemapConfig=utils.strtolist(routemapConfig)

        for item in self.routemapConfig:
                item=item.split("|")
                dut=str(item[0])
                routemap=str(item[1])
                permission=str(item[2])
                community=str(item[3])
                self.duts=switch_dict
                hdl=switch_hdl_dict[dut]
                if action == "config":
                    cfg='''route-map {0} {1}
                           set community {2}'''.format(routemap,permission,community)
                if action == "unconfig":
                    cfg='''no route-map {0}'''.format(routemap)

                hdl.configure(cfg)

class ConfigBgpCommunityLocalPref(object):
  
     def __init__(self,switch_dict, switch_hdl_dict, log,routemapConfig,action,*args):

        self.log=log
        self.result='pass'
        self.routemapConfig=utils.strtolist(routemapConfig)

        for item in self.routemapConfig:
                item=item.split("|")
                dut=str(item[0])
                routemap=str(item[1])
                permission=str(item[2])
                community=str(item[3])
                communityList=str(item[4])
                localPref=str(item[5])
                self.duts=switch_dict
                hdl=switch_hdl_dict[dut]
                if action == "config":
                    cfg='''ip community-list standard {0} permit {1}
                           route-map {2} {3}
                           match community {0} exact-match
                           set local-preference {4}'''.format(community,communityList,routemap,permission,localPref)
                if action == "unconfig":
                    cfg=''' no ip community-list standard {0} permit {1}
                            no route-map {0}'''.format(community,communityList,routemap)
                hdl.configure(cfg)
  
class VerifyBgpLocalPreferenceValue(object):

     def __init__(self,switch_dict, switch_hdl_dict, log,*args):

        self.log=log
        self.result='pass'
        arggrammar={}
        arggrammar['dut']='-type str'
        arggrammar['ipType']='-type str'
        arggrammar['nexthop_ip']=''
        arggrammar['localPref']='-type str'
        arggrammar['testType']='-type str'
        ns=parserutils_lib.argsToCommandOptions(args,arggrammar,self.log)
        self.log.info('Dut: {0}'.format(ns.dut))
        print('%%% switch_hdl_dict %%%', switch_hdl_dict )
        hdl=switch_hdl_dict[ns.dut]
        if ns.ipType == "ipv4":
             cmd= 'show ip bgp'
        if ns.ipType =="ipv6":
             cmd= 'show ipv6 bgp'
        print(ns.nexthop_ip)
        pattern="\S+\s+{0}\s+(\d+)".format(ns.nexthop_ip)
        out= hdl.iexec(cmd)
        prefValue=re.search(pattern,out)
        prefValue=prefValue.group(1)
        if ns.testType == "positive":
            if prefValue==ns.localPref:
                msg='Local Preference {0} has been set for {1} as expected'.format(ns.localPref,ns.nexthop_ip)
                testResult( 'Pass', msg, self.log )
            else:
                msg='Did not  get expected local preference {0} for {1}'.format(ns.localPref,ns.nexthop_ip)
                testResult( 'fail', msg, self.log )

        if ns.testType == "negative":
            if prefValue==ns.localPref:
                msg='Local Preference {0} has been set for {1} which is not expected'.format(ns.localPref,ns.nexthop_ip)
                testResult( 'fail', msg, self.log )
            else:
                msg='As expected local preference {0} for {1} is not set'.format(ns.localPref,ns.nexthop_ip)
                testResult( 'fail', msg, self.log )
 
class ConfigRemoteAsLocalAS(object):

    def __init__(self, bgp_config_dict, switch_dict, switch_hdl_dict, log,neighborConfig,asType,action,*args):

      self.log=log
      self.result='pass'
      self.bgp_config_dict=bgp_config_dict
      self.neighborConfig=utils.strtolist(neighborConfig)

      for item in self.neighborConfig:
        print(item)
        item=item.split("/")
        dut=str(item[0])
        self.log.info('item:{0}'.format(item))
        neighborIp=str(item[1])
        #asType=item[2]
        #action=item[]
        asNo=item[2]
        self.duts=switch_dict
        hdl=switch_hdl_dict[dut]
        as_nos=self.bgp_config_dict[dut].keys()
        for as_no in as_nos:
           print(as_no)
           print(neighborIp)
           if action == "add":
               if asType == "remote":
                   cfg='''router bgp {0}
                         neighbor {1}
                         remote-as {2}'''.format(as_no,neighborIp,asNo)
               if asType == "local":
                   cfg='''router bgp {0}
                         neighbor {1}
                         local-as {2}'''.format(as_no,neighborIp,asNo)
           if action == "delete":
               if asType == "remote":
                   cfg='''router bgp {0}
                         neighbor {1}
                         default remote-as'''.format(as_no,neighborIp)
               if asType == "local":
                   cfg='''router bgp {0}
                         neighbor {1}
                         default local-as'''.format(as_no,neighborIp)  
           hdl.configure(cfg)


class VerifyRemovePrivateAs(object):

   def __init__(self, bgp_config_dict, switch_dict, switch_hdl_dict, PrivateAsVerifyList,verifyType, log, *args ):
    
        self.log=log
        self.result='pass'
        self.bgp_config_dict=bgp_config_dict
        self.PrivateAsVerifyList=utils.strtolist(PrivateAsVerifyList)

        for item in self.PrivateAsVerifyList:
           print(item)
           item=item.split("/")
           dut=str(item[0])
           self.log.info('item:{0}'.format(item))
           #neighborIp=str(item[1])
           route=str(item[1])
           #verifyType=str(item[2])
           AsNo=item[2]
           hdl=switch_hdl_dict[dut]
           AsPathListItem=utils.getBgpRouteASPaths(hdl,route, self.log)
           for item in AsPathListItem:
              if verifyType == "add":
                 if AsNo in item:
                    msg='PASS:Private As {0} found in AS Path as expected'.format(AsNo)
                    testResult ('pass',msg,self.log)    
                 else:
                    msg='FAIL:Private As {0} not found in AS Path as expected'.format(AsNo)
                    testResult ('fail',msg,self.log)
              if verifyType == "remove":
                 if AsNo in item:
                    msg='FAIL:Private As {0} found in AS Path after applying RemovePrivate AS'.format(AsNo)
                    testResult ('fail',msg,self.log)
                 else:
                    msg='PASS:Private As {0} not found in AS Path as expected'.format(AsNo)
                    testResult ('pass',msg,self.log)
                 
class configBgpAggregateRoute(object):

   def __init__(self, bgp_config_dict, switch_dict, switch_hdl_dict,log,aggregateConfig,*args ):

        self.log=log
        self.result='pass'
        self.bgp_config_dict=bgp_config_dict
        self.aggregateConfig=utils.strtolist(aggregateConfig)

        for item in self.aggregateConfig:
           print(item)
           item=item.split("|")
           dut=str(item[0])
           action=str(item[1])
           ipType=str(item[2])
           route=str(item[3])
           hdl=switch_hdl_dict[dut]
           as_nos=self.bgp_config_dict[dut].keys()
           for as_no in as_nos:
              if action == "add":
                  cfg='''router bgp {0}
                         address-family {1} unicast
                         aggregate-address {2} summary-only'''.format(as_no,ipType,route)
              if action == "delete":
                  cfg='''router bgp {0}
                         address-family {1} unicast
                         no aggregate-address {2} summary-only'''.format(as_no,ipType,route)
           hdl.configure(cfg)
 
class VerifyBgpRouteIP(object):

   def __init__(self, bgp_config_dict, switch_dict, switch_hdl_dict,log,routeVerify, *args ):

        self.log=log
        self.result='pass'
        self.bgp_config_dict=bgp_config_dict
        self.routeVerify=utils.strtolist(routeVerify)

        for item in self.routeVerify:
           print(item)
           item=item.split("|")
           dut=str(item[0])
           self.log.info('item:{0}'.format(item))
           route=str(item[1])
           action=str(item[2])
           hdl=switch_hdl_dict[dut]
           cmd="show ip bgp"
           out = hdl.iexec(cmd)
           if action == "add": 
                if re.search(route,out):
                    msg= 'PASS: Expected route {0} found in node {1}'.format(route,dut)
                    testResult ('pass',msg,self.log)
                else:
                    msg= 'FAIL: Expected route {0} not found in node {1}'.format(route,dut)
                    testResult ('fail',msg,self.log)
           if action == "remove": 
                if re.search(route,out):
                    msg= 'FAIL: route {0} found in node {1} is not expected'.format(route,dut)
                    testResult ('fail',msg,self.log)
                else:
                    msg= 'PASS: As Expected  route {0} not found in node {1}'.format(route,dut)
                    testResult ('pass',msg,self.log)

class VerifyBgpDefaultRouteIP(object):

   def __init__(self, bgp_config_dict, switch_dict, switch_hdl_dict,log,routeVerify, *args ):

        self.log=log
        self.result='pass'
        self.bgp_config_dict=bgp_config_dict
        self.routeVerify=utils.strtolist(routeVerify)

        for item in self.routeVerify:
           print(item)
           item=item.split("|")
           dut=str(item[0])
           self.log.info('item:{0}'.format(item))
           route=str(item[1])
           network=str(item[2])
           action=str(item[3])
           hdl=switch_hdl_dict[dut]
           cmd="show ip bgp"
           print(network)
           print(route)
           pattern='\S+{0}\s+{1}'.format(network,route)
           out = hdl.iexec(cmd)
           if action == "add": 
                if re.search(pattern,out):
                    msg= 'PASS: Expected route {0} found in node {1}'.format(route,dut)
                    testResult ('pass',msg,self.log)
                else:
                    msg= 'FAIL: Expected route {0} not found in node {1}'.format(route,dut)
                    testResult ('fail',msg,self.log)
           if action == "remove": 
                if re.search(pattern,out):
                    msg= 'FAIL: route {0} found in node {1} is not expected'.format(route,dut)
                    testResult ('fail',msg,self.log)
                else:
                    msg= 'PASS: As Expected  route {0} not found in node {1}'.format(route,dut)
                    testResult ('pass',msg,self.log)

class configBgpAttributeNextHopChange(object):

   def __init__(self, bgp_config_dict, switch_dict, switch_hdl_dict,log,routeMapConfig,action, *args ):
   
        self.log=log
        self.result='pass'
        self.bgp_config_dict=bgp_config_dict
        self.routeMapConfig=utils.strtolist(routeMapConfig)

        for item in self.routeMapConfig:
           item=item.split("|")
           dut=str(item[0])
           routeMapName=str(item[1])
           ipType=str(item[2])
           permission=str(item[3])
           sequence=str(item[4])
           nexthopIp=str(item[5])
           hdl=switch_hdl_dict[dut]
           if action =="add":
               cfg='''route-map {0} {1} {2}
                   set {3} next-hop {4}'''.format(routeMapName,permission,sequence,ipType,nexthopIp)
           if action == "delete":
                cfg='''no route-map {0} {1} {2}'''.format(routeMapName,permission,sequence)
           hdl.configure(cfg)

 
class configBgpAttributeNextHopUnChange(object):

   def __init__(self, bgp_config_dict, switch_dict, switch_hdl_dict,log,routeMapConfig,action, *args ):
   
        self.log=log
        self.result='pass'
        self.bgp_config_dict=bgp_config_dict
        self.routeMapConfig=utils.strtolist(routeMapConfig)
        for item in self.routeMapConfig:
            item=item.split("|")
            dut=str(item[0])
            routeMapName=str(item[1])
            ipType=str(item[2])
            permission=str(item[3])
            sequence=str(item[4])
            hdl=switch_hdl_dict[dut]
            if action =="add":
                cfg='''route-map {0} {1} {2}
                    set {3} next-hop unchanged'''.format(routeMapName,permission,sequence,ipType)
            if action == "delete":
                cfg='''no route-map {0} {1} {2}'''.format(routeMapName,permission,sequence)
   
            hdl.configure(cfg)

class bgpParser ():
    def __init__(self,hlite,hdl,*args):
       arggrammar={}
       arggrammar['nw']=''
       self.hdl=hdl
       self.parseoutput=parserutils_lib.argsToCommandOptions(args,arggrammar,hlite.gd['log'])
    def getEbgppath(self):
       op=self.hdl.iexec('show ip bgp {0}'.format(self.parseoutput.nw))
       bp_dict={}
       req_op=op.split('\n')
       flag=0
       nw=self.parseoutput.nw
       for i in req_op:
           if re.search("Path type.*is valid",i):
               flag=1
               mt1=''
               mt2=''
               if re.search("is best path",i):
                   bp=1
               else:
                   bp=0
           if flag:
               mt1=re.search("AS-Path:\s+(.*),\s+path",i)
               if mt1:
                  tmp_mt1=mt1
               mt2=re.search("(.*)\s+\(metric.*from",i)
               if mt2:
                   if nw not in bp_dict.keys():
                       bp_dict[nw]={}
                       bp_dict[nw].update({1: {'AS': tmp_mt1.group(1).strip(), 'ip': mt2.group(1).strip(), 'bestpath': bp}}
)
                   else:
                       i=len(bp_dict[nw])+1
                       bp_dict[nw].update({i: {'AS': tmp_mt1.group(1).strip(), 'ip': mt2.group(1).strip(), 'bestpath': bp}})
                   flag=0
       return bp_dict


class verifyBgpBestPath(object):
    def __init__(self,hlite,switch_hdl_dict, log, *args ):
         
        self.log=log
        self.result='pass'
        arggrammar={}
        arggrammar['dut']='-type str'
        arggrammar['nw']='-type str'
        arggrammar['nexthop_ip']='-type str'
        ns=parserutils_lib.argsToCommandOptions(args,arggrammar,self.log)
        self.log.info('Dut: {0}'.format(ns.dut))
        print('%%% switch_hdl_dict %%%', switch_hdl_dict )
        hdl=switch_hdl_dict[ns.dut]
        l_args='-nw {0}'.format(ns.nw)
        bgp_obj=bgpParser(hlite,hdl,l_args)
        bgppath_dict=bgp_obj.getEbgppath()
        print(bgppath_dict)
        bgp_nexthop_ip=''
        for i in bgppath_dict[ns.nw].keys():
            if bgppath_dict[ns.nw][i]['bestpath']:
                bgp_nexthop_ip=bgppath_dict[ns.nw][i]['ip']
        nexthop_ip=ns.nexthop_ip
        if bgp_nexthop_ip==nexthop_ip:
           msg='The Best-Path for the network {0} is {1} as expected'.format(ns.nw,nexthop_ip)
           testResult( 'Pass', msg, self.log )
        else:
           msg='The Best-Path for the network {0} expected is {1} but got {2}'.format(ns.nw,nexthop_ip,bgp_nexthop_ip)
           testResult( 'fail', msg, self.log )


class configBgpDampening(object):
      def __init__(self,hlite ,switch_dict, switch_hdl_dict, bgp_config_dict, log, *args):
        
        self.log=log
        self.result='pass'
        self.bgp_config_dict=bgp_config_dict
        arggrammar={}
        arggrammar['dut']='-type str'
        arggrammar['ipType']='-type str'
        arggrammar['half_life']='-type str'
        arggrammar['reuse_limit']='-type str'
        arggrammar['suppress_limit']='-type str'
        arggrammar['max_suppress_limit']='-type str'
        arggrammar['action']='-type str'

        ns=parserutils_lib.argsToCommandOptions(args,arggrammar,self.log)
        self.log.info('Dut: {0}'.format(ns.dut))
        print('%%% switch_hdl_dict %%%', switch_hdl_dict )
        hdl=switch_hdl_dict[ns.dut]
        as_nos=self.bgp_config_dict[ns.dut].keys()
        for as_no in as_nos:
           print(as_no)
           if ns.action == "add":
                   cfg='''router bgp {0}
                          address-family {1} unicast
                          dampening {2} {3} {4} {5}'''.format(as_no,ns.ipType,ns.half_life,ns.reuse_limit,ns.suppress_limit,ns.max_suppress_limit)
           if ns.action == "delete":
                   cfg='''clear ip bgp dampening
                          clear ip bgp flap-statistics
                          router bgp {0}
                          address-family {1} unicast
                          no dampening {2} {3} {4} {5}'''.format(as_no,ns.ipType,ns.half_life,ns.reuse_limit,ns.suppress_limit,ns.max_suppress_limit)  
           hdl.configure(cfg)

class verifyBgpv4RouteStatus(object):
     def __init__(self, bgp_config_dict, switch_dict, switch_hdl_dict,log, *args ):
        self.log=log
        self.result='pass'
        arggrammar={}
        arggrammar['dut']='-type str'
        arggrammar['status']='-type str'
        arggrammar['route']='-type str'
        arggrammar['nextHopIp']='-type str'

        ns=parserutils_lib.argsToCommandOptions(args,arggrammar,self.log)
        self.log.info('Dut: {0}'.format(ns.dut))
        print('%%% switch_hdl_dict %%%', switch_hdl_dict )
        hdl=switch_hdl_dict[ns.dut]
        cmd="show ip bgp"
        out = hdl.iexec(cmd)
        pattern='([a-z]+)\s+\S+{1}\s+{0}'.format(ns.nextHopIp,ns.route)
        routeStatus=re.search(pattern,out)
        routeStatus=routeStatus.group(1)
        print(routeStatus)
        Status=ns.status
        if routeStatus == Status:
           msg='The Route status is {0} as Expected'.format(routeStatus)
           testResult('Pass', msg, self.log )
        else:
           msg='Expected Status is {0} ,but got {1}'.format(Status,routeStatus)
           testResult('fail', msg, self.log ) 
     
class configBgpNextHopSelf(object):

    def __init__(self, bgp_config_dict,switch_dict, switch_hdl_dict,log,neighborConfig,action,*args ):

      self.log=log
      self.result='pass'
      self.duts=switch_dict
      self.bgp_config_dict=bgp_config_dict
      self.action=action
      self.neighborConfig=utils.strtolist(neighborConfig)

      for item in self.neighborConfig:
          print(item)
          item=item.split("/")
          dut=str(item[0])
          self.log.info('item:{0}'.format(item))
          neighborIp=str(item[1])
          ipType=str(item[2])
          
          print(dut)

          self.log.info('Dut: {0}'.format(dut))
          print('%%% switch_hdl_dict %%%', switch_hdl_dict )
          hdl=switch_hdl_dict[dut]
          as_nos=self.bgp_config_dict[dut].keys()
          for as_no in as_nos:
           print(as_no)
           print(neighborIp)
           np_args = self.bgp_config_dict[dut][as_no]['neighbors'][neighborIp]['neighbor_params']
           np=parseBgpNeighborParams( self.log, np_args)
           if action == "add":
                   cfg='''router bgp {0}
                         neighbor {2}
                         address-family {1} unicast
                         next-hop-self'''.format(as_no,ipType,neighborIp)

           if action == "delete":
                  cfg='''router bgp {0}
                        neighbor {2}
                        default address-family {1} unicast'''.format(as_no,ipType,neighborIp)
           hdl.configure(cfg)


class configBgpRouteReflectorClient(object):

    def __init__(self, bgp_config_dict,switch_dict, switch_hdl_dict,log,neighborConfig,action,*args ):


      self.log=log
      self.result='pass'
      self.duts=switch_dict
      self.bgp_config_dict=bgp_config_dict
      self.action=action
      self.neighborConfig=utils.strtolist(neighborConfig)

      for item in self.neighborConfig:
          print(item)
          item=item.split("/")
          dut=str(item[0])
          self.log.info('item:{0}'.format(item))
          neighborIp=str(item[1])
          ipType=str(item[2])

          print(dut)

          self.log.info('Dut: {0}'.format(dut))
          print('%%% switch_hdl_dict %%%', switch_hdl_dict )
          hdl=switch_hdl_dict[dut]
          as_nos=self.bgp_config_dict[dut].keys()
          for as_no in as_nos:
           print(as_no)
           print(neighborIp)
           np_args = self.bgp_config_dict[dut][as_no]['neighbors'][neighborIp]['neighbor_params']
           np=parseBgpNeighborParams( self.log, np_args)
           if action == "add":
                   cfg='''router bgp {0}
                         neighbor {2}
                         address-family {1} unicast
                         route-reflector-client'''.format(as_no,ipType,neighborIp)

           if action == "delete":
                  cfg='''router bgp {0}
                        neighbor {2}
                        default address-family {1} unicast'''.format(as_no,ipType,neighborIp)
           hdl.configure(cfg)

class disableSoftReconfig(object):

    def __init__(self, bgp_config_dict, switch_dict, switch_hdl_dict, log,neighborConfig,*args ):

      self.log=log
      self.result='pass'
      self.duts=switch_dict
      arggrammar={}
      arggrammar['action']='-type str'
      ns=parserutils_lib.argsToCommandOptions(args,arggrammar,self.log)
      self.bgp_config_dict=bgp_config_dict
      #self.action=action
      self.neighborConfig=utils.strtolist(neighborConfig)

      for item in self.neighborConfig:
          print(item)
          item=item.split("/")
          dut=str(item[0])
          self.log.info('item:{0}'.format(item))
          neighborIp=str(item[1])
          ipType=str(item[2])

          print(dut)

          self.log.info('Dut: {0}'.format(dut))
          print('%%% switch_hdl_dict %%%', switch_hdl_dict )
          hdl=switch_hdl_dict[dut]
          as_nos=self.bgp_config_dict[dut].keys()
          for as_no in as_nos:
           print(as_no)
           print(neighborIp)
           np_args = self.bgp_config_dict[dut][as_no]['neighbors'][neighborIp]['neighbor_params']
           np=parseBgpNeighborParams( self.log, np_args)
           print(ns.action)
           if ns.action == "disable":
                   cfg='''router bgp {0}
                         neighbor {2}
                         address-family {1} unicast
                         no soft-reconfiguration inbound'''.format(as_no,ipType,neighborIp)
           if ns.action == "enable":
                  cfg='''router bgp {0}
                        neighbor {2}
                        default address-family {1} unicast'''.format(as_no,ipType,neighborIp)
           hdl.configure(cfg)



class configBgpPeerAddressFamily(object):

    def __init__(self, bgp_config_dict, switch_dict, switch_hdl_dict, log,familyConfig,*args ):

      self.log=log
      self.result='pass'
      self.duts=switch_dict
      self.bgp_config_dict=bgp_config_dict
      self.familyConfig=utils.strtolist(familyConfig)
      arggrammar={}
      arggrammar['action']='-type str'
      ns=parserutils_lib.argsToCommandOptions(args,arggrammar,self.log)

      for item in self.familyConfig:
          print(item)
          item=item.split("/")
          dut=str(item[0])
          self.log.info('item:{0}'.format(item))
          neighborIp=str(item[1])
          ipType=str(item[2])
          
          print(dut)

          self.log.info('Dut: {0}'.format(dut))
          print('%%% switch_hdl_dict %%%', switch_hdl_dict )
          hdl=switch_hdl_dict[dut]
          as_nos=self.bgp_config_dict[dut].keys()
          for as_no in as_nos:
           print(as_no)
           print(neighborIp)
           np_args = self.bgp_config_dict[dut][as_no]['neighbors'][neighborIp]['neighbor_params']
           np=parseBgpNeighborParams( self.log, np_args)
           if ns.action == "add":
                 cfg='''router bgp {0}
                         template peer {1}
                         address-family {2} unicast'''.format(as_no,np.inherit_peer,ipType)
               
           if ns.action == "delete":
                  cfg='''router bgp {0}
                         template peer {1}
                         no address-family {2} unicast'''.format(as_no,np.inherit_peer,ipType)
           hdl.configure(cfg)

class AddDeleteBgpNeighbor(object):

    def __init__(self, bgp_config_dict, switch_dict, switch_hdl_dict, log,neighborConfig,*args ):

      self.log=log
      self.result='pass'
      self.duts=switch_dict
      self.bgp_config_dict=bgp_config_dict
      self.neighborConfig=utils.strtolist(neighborConfig)
      arggrammar={}
      arggrammar['action']='-type str'
      ns=parserutils_lib.argsToCommandOptions(args,arggrammar,self.log)

      for item in self.neighborConfig:
          print(item)
          item=item.split("/")
          dut=str(item[0])
          self.log.info('item:{0}'.format(item))
          neighborIp=str(item[1])
                
          print(dut)
          self.log.info('Dut: {0}'.format(dut))
          print('%%% switch_hdl_dict %%%', switch_hdl_dict )
          hdl=switch_hdl_dict[dut]
          as_nos=self.bgp_config_dict[dut].keys()
          for as_no in as_nos:
           print(as_no)
           print(neighborIp)
           np_args = self.bgp_config_dict[dut][as_no]['neighbors'][neighborIp]['neighbor_params']
           np=parseBgpNeighborParams( self.log, np_args)
           if ns.action == "add":
                  cfg='''router bgp {0}
                         neighbor {1}
                         inherit peer {2}'''.format(as_no,neighborIp,np.inherit_peer)                       
           if ns.action == "delete":
                  cfg='''router bgp {0}
                         no neighbor {1}'''.format(as_no,neighborIp)
           hdl.configure(cfg)


def parseInterfaceParams(log, args):
     arggrammar={}
     arggrammar['ipv4_addr']='-type str'
     arggrammar['ipv4_prf_len']='-type str'
     ns=parserutils_lib.argsToCommandOptions( args, arggrammar, log )
     return ns


class configInterfaceIpForward(object):

    def __init__(self,interface_config_dict, switch_dict, switch_hdl_dict, log,interfaceConfig,*args ):
          self.log=log
          self.result='pass'
          self.duts=switch_dict
          arggrammar={}
          arggrammar['action']='-type str'
          np=parserutils_lib.argsToCommandOptions(args,arggrammar,self.log)
          self.interfaceConfig=utils.strtolist(interfaceConfig)

          for item in self.interfaceConfig:
             item=item.split("/")
             dut=str(item[0])
             int=str(item[1])
             port_type=str(item[2])
             print(int)
          
             self.log.info('Dut: {0}'.format(dut))
             print('%%% switch_hdl_dict %%%', switch_hdl_dict )
             hdl=switch_hdl_dict[dut]
             int_args=interface_config_dict[port_type][dut][int]
             ns=parseInterfaceParams(log, int_args)
             print(ns.ipv4_addr)
             print(ns.ipv4_prf_len) 
             if np.action == "add":
                 cfg='''interface {0}
                        no ip address {1}/{2}
                        ip forward'''.format(int,ns.ipv4_addr,ns.ipv4_prf_len)
             if np.action == "delete":
                cfg='''interface {0}
                        no ip forward
                        ip address {1}/{2}'''.format(int,ns.ipv4_addr,ns.ipv4_prf_len)
             hdl.configure(cfg)

#Added by Nilesh
def getEbgppath(hdl,nw):
   op=hdl.iexec('show ip bgp {0}'.format(nw)) 
   bp_dict={}
   req_op=op.split('\n')
   flag=0
   for i in req_op:
       if re.search("Path type.*is valid",i):
           flag=1
           mt1=''
           mt2=''
           if re.search("is best path",i):
               bp=1
           else:
               bp=0
       if flag:
           mt1=re.search("AS-Path:\s+(.*),\s+path",i)
           if mt1:
              tmp_mt1=mt1
           mt2=re.search("(.*)\s+\(metric.*from",i)
           if mt2:
               if nw not in bp_dict.keys():
                   bp_dict[nw]={}
                   bp_dict[nw].update({1: {'AS': tmp_mt1.group(1).strip(), 'ip': mt2.group(1).strip(), 'bestpath': bp}})
               else:
                   i=len(bp_dict[nw])+1
                   bp_dict[nw].update({i: {'AS': tmp_mt1.group(1).strip(), 'ip': mt2.group(1).strip(), 'bestpath': bp}})
               flag=0
   return bp_dict 

def shutEbgpIntf(hdl,nei,nei_dict,flag=0):
    print(nei)
    print(nei_dict)
    if nei in nei_dict:
        tmp_dict=nei_dict[nei]
        if flag:
            cmd='no shut'
        else:
            cmd='shut'    
        for var in tmp_dict.keys():
            intf=tmp_dict[var]['dut_intf']
            cfg='''interface {0}
                    {1}
                '''.format(intf, cmd)
            hdl.configure(cfg)

def shutEbgpIntfByIp(hdl,nei_ip,nei_dict,flag=0):
    print(nei_ip)
    print(nei_dict)
    if flag:
        cmd='no shut'
    else:
        cmd='shut'    
    for i in nei_dict.keys():
        for var in nei_dict[i].keys():
            if nei_dict[i][var]['nei'] == nei_ip:
                intf=nei_dict[i][var]['dut_intf']        
                cfg='''interface {0}
                        {1}
                    '''.format(intf, cmd)    
                hdl.configure(cfg)

def getEbgpIntfByIp(nei_ip,nei_dict):
    print(nei_ip)
    print(nei_dict)
    intf=''
    for i in nei_dict.keys():
        if intf:
            break
        for var in nei_dict[i].keys():
            if nei_dict[i][var]['nei'] == nei_ip:
                intf=nei_dict[i][var]['dut_intf']        
                break
    return intf

def getNeighborinfo(dut_dict,log):
    as_num=dut_dict.keys()[0]
    neighbors=dut_dict[as_num]['neighbors'].keys()
    dut_nei_dict={}
    arggrammar={}
    arggrammar['peer']='-type str -required true'
    arggrammar['intf']='-type str -required true'
    arggrammar['peer_intf']='-type str -required true'
    for nei in neighbors:
        if not re.search(':',nei):
            print(nei)
            nei_params=dut_dict[as_num]['neighbors'][nei]['neighbor_params']    
            dut_np=parserutils_lib.argsToCommandOptions(nei_params,arggrammar,log)
            if dut_np.peer not in dut_nei_dict.keys():
                dut_nei_dict[dut_np.peer]={}
                dut_nei_dict[dut_np.peer].update({1: {'dut_intf': dut_np.intf, 'peer_intf': dut_np.peer_intf, 'nei': nei, 'peer': dut_np.peer}})
            else:
                i=len(dut_nei_dict[dut_np.peer])+1
                dut_nei_dict[dut_np.peer].update({i: {'dut_intf': dut_np.intf, 'peer_intf': dut_np.peer_intf, 'nei': nei, 'peer': dut_np.peer}}) 
    return dut_nei_dict






#-- This procedure is used by some of old script . Please use latest class configBgp which is dev by pradeep 

class configBgpv4(object):

    def __init__(self, bgp_config_dict, switch_dict, switch_hdl_dict, log ):

        self.log=log
        self.result='pass'
        self.bgp_config_dict=bgp_config_dict
      
        try:
           list_of_nodes=self.bgp_config_dict.keys()
        except KeyError:
           err_msg='Error !!! bgp_config_dict has not been defined properly, does not have nodes   \
              as the top level keys'
           testResult( 'fail', err_msg, self.log )

        for node in list_of_nodes:
            print(node)
            hdl=switch_hdl_dict[node]
            # Enable feature Bgp
            bringup_lib.configFeature( hdl, self.log, '-feature bgp' )

            as_nos=self.bgp_config_dict[node].keys()

            # In future if we allow multiple AS
            for as_no in as_nos:

               # Build address family configs ..
               # For Ipv4 Unicast
               if 'address_family' in self.bgp_config_dict[node][as_no]:

                 vrf_list=self.bgp_config_dict[node][as_no]['address_family'].keys()

                 for vrf_name in vrf_list:

                   if 'ipv4_unicast' in self.bgp_config_dict[node][as_no]['address_family'][vrf_name]:

                     ns=parseGlobalAfIpv4Unicast( self.log, self.bgp_config_dict[node][as_no]        \
                       ['address_family'][vrf_name]['ipv4_unicast'] )

                     if vrf_name == "default":
                         cfg = '''router bgp {0}
                              address-family ipv4 unicast'''.format( as_no )
                     else:
                         cfg = '''router bgp {0}
                              vrf {1}
                              address-family ipv4 unicast'''.format( as_no, vrf_name )
                              
                     # Aggregate address configuration ..
                     if hasattr( ns, 'aggregate_addr_list') and ns.aggregate_addr_list is not None:
                       for aggregate in ns.aggregate_addr_list.split(','):
                           cfg = cfg + '\n' + \
                                  '''aggregate-address {1}'''.format( aggregate )

                     # Enable client to client reflection
                     if hasattr( ns, 'client_to_client_reflection') and ns.client_to_client_reflection:
                           cfg = cfg + '\n' + \
                              '''client-to-client reflection'''

                     # Enable dampening 
                     if hasattr( ns, 'dampening') and ns.dampening:
                       cfg = cfg + '\n' + \
                              '''dampening'''

                     # Enable dampening_half_life
                     if hasattr( ns, 'dampening_half_life') and ns.dampening_half_life:
                       cfg = cfg + '\n' + \
                              '''dampening {0}'''.format(ns.dampening_half_life)

                     # Enable MED configuration ..
                     if hasattr( ns, 'default_metric') and ns.default_metric is not None:
                       cfg = cfg + '\n' + \
                              '''default-metric {0}'''.format( ns.default_metric )

                     # Config Administrative distance configuration ..
                     if hasattr( ns, 'ebgp_distance') and ns.ebgp_distance is not None:
                       cfg = cfg + '\n' + \
                              '''distance {0} {1} {2}'''.format( ns.ebgp_distance, ns.ibgp_distance, ns.local_distance )


                     # Config ebgp maximum-paths ..       
                     if hasattr( ns, 'maximum_paths') and ns.maximum_paths is not None:
                       cfg = cfg + '\n' + \
                              '''maximum-paths {0}'''.format( ns.maximum_paths )

                     # Config ibgp maximum-paths ..       
                     if hasattr( ns, 'maximum_paths_ibgp') and ns.maximum_paths_ibgp is not None:
                       cfg = cfg + '\n' + \
                              '''maximum-paths ibgp {0}'''.format( ns.maximum_paths_ibgp )

                     # Enable suppress_inactive 
                     if hasattr( ns, 'suppress_inactive') and ns.suppress_inactive:
                       cfg = cfg + '\n' + \
                              '''suppress-inactive'''

                     # Network configuration ..
                     if hasattr( ns, 'network_list') and ns.network_list is not None:
                       for network in ns.network_list.split(','):
                          network_addr,prf_len=network.split('/')
                          for i in range( 0, ns.network_count ):
                              cfg = cfg + '\n' + \
                                   '''network {0}/{1}'''.format( network_addr,prf_len )
                              network_addr=utils.incrementIpv4Address( network_addr, ns.network_step )

                     hdl.configure(cfg)



                              
               # Build Router configs ..
               router_vrfs=self.bgp_config_dict[node][as_no]['router_configs']
               
               for vrf_name in router_vrfs:

                   ns=parseBgpRouterConfigs( self.log, self.bgp_config_dict[node][as_no]           \
                        ['router_configs'][vrf_name] )
                   cfg='''router bgp {0}
                          router-id {1}
                          timers prefix-peer-timeout {2}
                          timers bestpath-limit {3}'''.format( as_no, ns.router_id,                \
                          ns.prefix_peer_timeout, ns.best_path_limit_timeout )

                   if hasattr( ns, 'keep_alive_time') and hasattr( ns, 'hold_time') and ns.keep_alive_time:
                       cfg = cfg + '\n' +  \
                              '''timers bgp {0} {1}'''.format(ns.keep_alive_time, ns.hold_time)
                       hdl.configure(cfg)

                   if ns.log_neighbor_changes:
                       cfg = cfg + '\n' +  \
                              '''log-neighbor-changes'''
                       hdl.configure(cfg)

                   if hasattr( ns, 'max_as_limit' ):
                       cfg = cfg + '\n' +  \
                             '''maxas-limit {0}'''.format( ns.max_as_limit )

                   if hasattr( ns, 'graceful_restart' ):
                       cfg = cfg + '\n' +  \
                             '''graceful-restart'''


                   # Apply the BGP router configs ..          
                   hdl.configure(cfg)



               # Template configuration
               if 'templates' in self.bgp_config_dict[node][as_no]:

                 for template in self.bgp_config_dict[node][as_no]['templates'].keys():

                   ns=parseBgpTemplate( self.log, self.bgp_config_dict[node][as_no]['templates'][template] )


                   cfg='''router bgp {0}
                          template peer {1}'''.format( as_no, template )

                   if hasattr( ns, 'address_family') and ns.address_family is not None:

                      if re.search( 'ipv4_unicast', ns.address_family, flags=re.I ):
                         cfg = cfg + '\n' + \
                               '''address-family ipv4 unicast'''
                      elif re.search( 'ipv4_multicast', ns.address_family, flags=re.I ):
                         cfg = cfg + '\n' + \
                               '''address-family ipv4 multicast'''
                      elif re.search( 'ipv6_unicast', ns.address_family, flags=re.I ):
                         cfg = cfg + '\n' + \
                               '''address-family ipv4 unicast'''
                      elif re.search( 'ipv6_multicast', ns.address_family, flags=re.I ):
                         cfg = cfg + '\n' + \
                               '''address-family ipv4 multicast'''

                   if hasattr( ns, 'description') and ns.description is not None:
                      cfg = cfg + '\n' + \
                            'description {0}'.format(ns.description)

                   if hasattr( ns, 'local_as' ) and ns.local_as is not None:
                      cfg = cfg + '\n' + \
                            '''local-as {0}'''.format(ns.local_as)

                   if hasattr( ns, 'remote_as' ) and ns.remote_as is not None:
                      cfg = cfg + '\n' + \
                            '''remote-as {0}'''.format(ns.remote_as)

                   if hasattr( ns, 'password' ) and ns.password is not None:
                      cfg = cfg + '\n' + \
                            '''password {0} {1}'''.format(ns.password_type, ns.password)

                   if hasattr( ns, 'update_source') and ns.update_source is not None:
                      cfg = cfg + '\n' + \
                            '''update-source {0}'''.format(ns.update_source)

                   if hasattr( ns, 'ebgp_multihop' ) and ns.ebgp_multihop is not None:
                      cfg = cfg + '\n' + \
                            '''ebgp-multihop {0}'''.format(ns.ebgp_multihop)
   
                   if hasattr( ns, 'dynamic_capability' ) and ns.dynamic_capability is not None:
                      cfg = cfg + '\n' + \
                            '''dynamic-capability'''

                   if hasattr( ns, 'bfd' ) and ns.bfd is True:
                      bringup_lib.configFeature( hdl, self.log, '-feature bfd' )
                      cfg = cfg + '\n' + \
                            '''bfd'''

                   # Apply the BGP template configs ..          
                   hdl.configure(cfg)


               # Neighbor configuration
               if 'neighbors' in self.bgp_config_dict[node][as_no]:

                 for neighbor in self.bgp_config_dict[node][as_no]['neighbors'].keys():

                   if 'neighbor_params' in self.bgp_config_dict[node][as_no]['neighbors'][neighbor]:
                      np=parseBgpNeighborParams( self.log, self.bgp_config_dict[node][as_no]['neighbors'] \
                        [neighbor]['neighbor_params'] )

                      # Iterate over the neighbor_count
                      neighbor_addr=neighbor
                      remote_as=np.remote_as
                      for i in range( 0, np.neighbor_count ):

                          # If vrf == default
                          if np.vrf_name == "default":

                             if re.search( 'ipv4_unicast', np.address_family, re.I ):
                                 af_config='address-family ipv4 unicast'
                             elif re.search( 'ipv4_multicast', np.address_family, re.I ):
                                 af_config='address-family ipv4 multicast'

                             if np.peer_policy is not None:
                                 cfg='''router bgp {0}
                                        {1}
                                        neighbor {2}
                                        inherit peer {3}'''.format(
                                        as_no, af_config, neighbor_addr, np.peer_policy )
                                 if np.remote_as:
                                     cfg = cfg + '\n' + \
                                         '''neighbor {0} remote-as {1}'''.format( neighbor_addr, np.remote_as )
                             else:
                                 cfg='''router bgp {0}
                                        {1}
                                        neighbor {2} remote-as {3}'''.format(
                                        as_no, af_config, neighbor_addr, remote_as)
                                 if hasattr( np, 'keep_alive_time') and hasattr( np, 'hold_time') and np.keep_alive_time:
                                     cfg = cfg + '\n' + \
                                         '''timers {0} {1}'''.format( np.keep_alive_time, np.hold_time )
                          # Non default VRF ..
                          else:
                             if re.search( 'ipv4_unicast', np.address_family, re.I ):
                                 af_config='address-family ipv4 unicast'
                             elif re.search( 'ipv4_multicast', np.address_family, re.I ):
                                 af_config='address-family ipv4 multicast'

                             if np.peer_policy is not None:
                                 cfg='''router bgp {0}
                                        vrf {1}
                                        {2}
                                        neighbor {3}
                                        inherit peer {4}'''.format(
                                        as_no, np.vrf_name, af_config, neighbor_addr, np.peer_policy )
                                 if np.remote_as:
                                     cfg = cfg + '\n' + \
                                         '''neighbor {0} remote-as {1}'''.format( neighbor_addr, np.remote_as )
                             else:
                                 cfg='''router bgp {0}
                                        vrf {1}
                                        {2}
                                        neighbor {3} remote-as {4}'''.format(
                                        as_no, np.vrf_name, af_config, neighbor_addr, remote_as)
                                 if hasattr( np, 'keep_alive_time') and hasattr( np, 'hold_time') and np.keep_alive_time:
                                     cfg = cfg + '\n' + \
                                         '''timers {0} {1}'''.format( np.keep_alive_time, np.hold_time )


                          if hasattr( np, 'bfd' ) and np.bfd:
                              bringup_lib.configFeature( hdl, self.log, '-feature bfd' )
                              cfg = cfg + '\n' + \
                                 '''bfd'''

                          if hasattr( np, 'description' ) and np.description is not None:
                              cfg = cfg + '\n' + \
                                 '''description {0} {1}'''.format( np.description, neighbor_addr )

                          if hasattr( np, 'update_source' ) and np.update_source is not None: 
                              cfg = cfg + '\n' + \
                                 '''update-source {0}'''.format( np.update_source )

                          if hasattr( np, 'ebgp_multihop' ) and np.ebgp_multihop is not None: 
                              cfg = cfg + '\n' + \
                                 '''ebgp-multihop {0}'''.format( np.ebgp_multihop )

                          if hasattr( np, 'password' ) and np.password is not None:
                              cfg = cfg + '\n' + \
                                 '''password {0} {1}'''.format(np.password_type, np.password)

                          if np.transport_connection_mode == "passive":
                              cfg = cfg + '\n' + \
                                  '''transport connection-mode'''

                          if hasattr( np, 'low_memory_action'):
                              if np.low_memory_action == "exempt":
                                 cfg = cfg + '\n' + \
                                    '''low-memory exempt'''

                          if hasattr( np, 'disable_capability_negotiation'):
                              cfg = cfg + '\n' + \
                                 '''dont-capability-negotiate'''

                          if np.disable_connected_check:
                              cfg = cfg + '\n' + \
                                 '''disable-connected-check'''

                          if np.dynamic_capability:
                              cfg = cfg + '\n' + \
                                 '''dynamic-capability'''
                          else:
                              cfg = cfg + '\n' + \
                                 '''no dynamic-capability'''

                          if np.suppress_4_byte_as:
                              cfg = cfg + '\n' + \
                                 '''capability suppress 4-byte-as'''



                          # Parse and build the address family configs ..
                          if 'address_family' in self.bgp_config_dict[node][as_no]['neighbors'][neighbor]:
                             # If AF IPv4 Unicast
                             if 'ipv4_unicast' in self.bgp_config_dict[node][as_no]['neighbors'][neighbor]           \
                                 ['address_family']:

                                 cfg = cfg + '\n' + \
                                    '''address-family ipv4 unicast'''

                                 afp=parseBgpAfIpv4Unicast( self.log, self.bgp_config_dict[node]   \
                                    [as_no]['neighbors'][neighbor]['address_family']['ipv4_unicast'] )

                                 if hasattr( afp, 'allow_as_in') and afp.allow_as_in is not None:
                                     cfg = cfg + '\n' +  \
                                         '''allowas-in {0}'''.format( afp.allow_as_in )
                             
                                 if hasattr( afp, 'as_override' ) and afp.as_override is True:
                                     cfg = cfg + '\n' + \
                                         '''as-override'''

                                 if hasattr( afp, 'default_originate' ) and afp.default_originate is True:
                                     cfg = cfg + '\n' + \
                                        '''default-originate'''

                                 if hasattr( afp, 'default_originate_route_map' ) and afp.default_originate_route_map \
                                     is not None:
                                     cfg = cfg + '\n' + \
                                       '''default-originate route-map {0}'''.format(afp.default_originate_route_map)

                                 if hasattr( afp, 'disable_peer_as_check' ) and afp.disable_peer_as_check is True:
                                     cfg = cfg + '\n' + \
                                       '''disable-peer-as-check'''

                                 if hasattr( afp, 'filter_list' ) and afp.filter_list is not None:
                                     cfg = cfg + '\n' + \
                                       '''filter-list {0}'''.format( afp.filter_list )

                                 if hasattr( afp, 'peer_policy' ) and afp.peer_policy is not None:
                                     cfg = cfg + '\n' + \
                                       '''inherit peer-policy {0}'''.format( afp.peer_policy )

                                 if hasattr( afp, 'maximum_prefix' ) and afp.maximum_prefix is not None:
                                     cfg = cfg + '\n' + \
                                       '''maximum-prefix {0}'''.format(afp.maximum_prefix)

                                 if hasattr( afp, 'next_hop_self' ) and afp.next_hop_self is True:
                                     cfg = cfg + '\n' + \
                                       '''next-hop-self'''

                                 if hasattr( afp, 'next_hop_third_party' ) and afp.next_hop_third_party is True:
                                     cfg = cfg + '\n' + \
                                       '''next-hop-third-party'''

                                 if hasattr( afp, 'next_hop_third_party' ) and afp.next_hop_third_party is True:
                                     cfg = cfg + '\n' + \
                                      '''next-hop-third-party'''

                                 if hasattr( afp, 'prefix_list' ) and afp.prefix_list is not None:
                                     cfg = cfg + '\n' + \
                                      '''prefix-list {0} {1}'''.format(afp.prefix_list, afp.prefix_list_direction)

                                 if hasattr( afp, 'route_reflector_client' ) and afp.route_reflector_client is True:
                                     cfg = cfg + '\n' + \
                                     '''route-reflector-client'''

                                 if hasattr( afp, 'send_community' ) and afp.send_community is True:
                                     cfg = cfg + '\n' + \
                                      '''send-community'''

                                 if hasattr( afp, 'send_community_extended' ) and afp.send_community_extended is True:
                                     cfg = cfg + '\n' + \
                                      '''send-community extended'''

                                 if hasattr( afp, 'soft_reconfiguration' ) and afp.soft_reconfiguration is True:
                                     cfg = cfg + '\n' + \
                                      '''soft-reconfiguration inbound'''

                                 if hasattr( afp, 'suppress_inactive' ) and afp.suppress_inactive is True:
                                     cfg = cfg + '\n' + \
                                       '''suppress-inactive'''

                                 if hasattr( afp, 'route_map' ) and afp.route_map is not None:
                                     cfg = cfg + '\n' + \
                                       '''route-map {0} {1}'''.format(afp.route_map, afp.route_map_direction)

                                 if hasattr( afp, 'weight' ) and afp.weight is not None:
                                     cfg = cfg + '\n' + \
                                       '''weight {0}'''.format(afp.weight)

                                 if hasattr( afp, 'advertise_map' ) and afp.advertise_map is not None:
                                     cfg = cfg + '\n' + \
                                      '''advertise-map {0} exist-map {1}'''.format(afp.advertise_map, \
                                      afp.advertise_exist_map)


                          # Apply the neighbor parameter configs  and AF configs..
                          hdl.configure(cfg)
                          # Increment the neighbor addr and remote-as
                          neighbor_addr=utils.incrementIpv4Address( neighbor_addr, np.neighbor_step )
                          if np.remote_as is not None:
                              remote_as = int(remote_as) + int(np.remote_as_step)
                   else:
                      testResult( 'fail', 'neighbor_params not defined for BGP neighbors in bgp_config_dict', \
                          self.log )


               # Redistribution configs for Bgpv4
               if 'redistribution_configs' in self.bgp_config_dict[node][as_no]:

                   vrf_list=self.bgp_config_dict[node][as_no]['redistribution_configs'].keys()

                   for vrf_name in vrf_list:
                      if 'ipv4_unicast' in self.bgp_config_dict[node][as_no]['redistribution_configs'][vrf_name]:

                         redist_sources=self.bgp_config_dict[node][as_no]['redistribution_configs'] \
                             [vrf_name]['ipv4_unicast'].keys()
                         # If vrf == default
                         if vrf_name == "default":
                             cfg='''router bgp {0}
                                    address-family ipv4 unicast'''.format(as_no)
                         else:
                             cfg='''router bgp {0}
                                    vrf {1}
                                    address-family ipv4 unicast'''.format(as_no,vrf_name)


                         for redist_source in redist_sources:

                            rd_ns=parseBgpRedistributionConfigs( self.log, self.bgp_config_dict[node] \
                                [as_no]['redistribution_configs'][vrf_name]['ipv4_unicast'][redist_source] )
                            if hasattr( rd_ns, 'tag_name' ) and rd_ns.tag_name is not None:
                                cfg = cfg + '\n' + \
                                    '''redistribute {0} {1} route-map {2}'''.format( redist_source,   \
                                       rd_ns.tag_name, rd_ns.route_map )
                            else:
                                cfg = cfg + '\n' + \
                                    '''redistribute {0} route-map {1}'''.format( redist_source,   \
                                       rd_ns.route_map )

                      # Apply the per VRF redistribution configs ..
                      hdl.configure(cfg)

