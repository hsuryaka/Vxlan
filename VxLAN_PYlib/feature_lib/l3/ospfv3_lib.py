import os
import sys
import yaml

from common_lib.utils import *
from common_lib.bringup_lib import *
from common_lib import parserutils_lib
from common_lib.verify_lib import *
from common_lib.interface_lib import *

#======================================================================================#
# Define the Ospfv3 parse methods
#======================================================================================#

def parseOspfv3InstanceConfig(args,log):

#       -vrf_name default -router_id 1.2.1.2 -admin_distance 110 -auto_cost_reference_bandwidth 40000 -graceful_restart_flag YES 
#       -maximum_paths 8 -throttle_spf_timer_start 200 -throttle_spf_timer_hold 1000 -throttle_spf_timer_max 5000 -throttle_lsa_timer_start 0 
#       -throttle_lsa_timer_hold 5000 -throttle_lsa_timer_max 5000 -lsa_arrival_timer 1000 -lsa_group_pacing_timer 10

    arggrammar = {}
    arggrammar['vrf_name'] = '-type str -default default'
    arggrammar['router_id'] = '-type str'
    arggrammar['admin_distance'] = '-type str'
    arggrammar['auto_cost_reference_bandwidth'] = '-type str'
    arggrammar['graceful_restart_flag'] = '-type bool'
    arggrammar['maximum_paths'] = '-type str'
    arggrammar['throttle_spf_timer_start'] = '-type str -mandatoryargs throttle_spf_timer_hold,throttle_spf_timer_max'
    arggrammar['throttle_spf_timer_hold'] = '-type str -mandatoryargs throttle_spf_timer_start,throttle_spf_timer_max'
    arggrammar['throttle_spf_timer_max'] = '-type str -mandatoryargs throttle_spf_timer_start,throttle_spf_timer_hold'
    arggrammar['throttle_lsa_timer_start'] = '-type str -mandatoryargs throttle_lsa_timer_hold,throttle_lsa_timer_max'
    arggrammar['throttle_lsa_timer_hold'] = '-type str -mandatoryargs throttle_lsa_timer_start,throttle_lsa_timer_max'
    arggrammar['throttle_lsa_timer_max'] = '-type str -mandatoryargs throttle_lsa_timer_start,throttle_lsa_timer_hold'
    arggrammar['lsa_arrival_timer'] = '-type str'
    arggrammar['lsa_group_pacing_timer'] = '-type str'
    return parserutils_lib.argsToCommandOptions( args, arggrammar, log, "dict")

    
def parseOspfv3AreaConfigs (args, log):
#        area_config:
#            1:
#             -instance_name 100 -area_type external_capable -auth_type md5
    arggrammar = {}
    arggrammar['vrf_name'] = '-type str'
    arggrammar['instance_name'] = '-type str'
    arggrammar['area_type'] = '-type str'
    arggrammar['auth_type'] = '-type str'
    return parserutils_lib.argsToCommandOptions( args, arggrammar, log, "dict")


def parseOspfv3InterfaceConfig (args, log):
#    -vrf_name default -instance_name 100 -cost 40 -hello_interval 10 -dead_interval 40 -transmit_delay 1 -retransmit_interval 5 -priority 1 -area_id 0 -auth_type md5 -auth_key insieme -md5_key insieme -network_type broadcast -include_secondaries_flag YES

    arggrammar = {}
    arggrammar['vrf_name'] = '-type str'
    arggrammar['instance_name'] = '-type str -required True'
    arggrammar['area_id']= '-type str -required True'
    arggrammar['cost'] = '-type str'
    arggrammar['hello_interval'] = '-type str -default 10'
    arggrammar['dead_interval'] = '-type str -default 40'
    arggrammar['transmit_delay']= '-type str -default 1'
    arggrammar['retransmit_interval']= '-type str -default 5'
    arggrammar['priority']= '-type str -default 1'
    arggrammar['network_type']='-type str -default broadcast'
    arggrammar['passive_interface']='-type bool -default False'
    arggrammar['mtu_ignore']='-type bool -default False'
    arggrammar['auth_type']= '-type str'
    arggrammar['auth_key']='-type str -mandatoryargs auth_type'
    arggrammar['md5_key']='-type str -mandatoryargs auth_type'
    arggrammar['peer_device']='-type str'
    arggrammar['peer_interface']='-type str'

    return parserutils_lib.argsToCommandOptions( args, arggrammar, log, "dict")




#======================================================================================#
# Class to configure and verify Ospfv3 config 
#======================================================================================#


class configOspfv3 ():

    def __init__( self, switch_hdl_dict, ospfv3_config_dict, log, *args):

        self.log=log
        self.result='pass'
        self.log.info('Switch OSPFv3 Bringup test')
        #self.node_dict=node_dict
        #self.interface_config_dict=interface_config_dict
        self.ospfv3_config_dict=ospfv3_config_dict
        self.switch_hdl_dict=switch_hdl_dict
        self.ospfv3_instance_cfg={}
        self.ospfv3_area_cfg={}
        self.ospfv3_interface_cfg={}
        
        try:
             list_of_nodes=self.ospfv3_config_dict.keys()
        except KeyError:
             print('ospfv3_config_dict in input file not defined properly ..               \
                  does not have any keys ..')
             self.result='fail'
             self.log.error('ospfv3_config_dict in input file not defined properly ..      \
                  does not have any keys ..')
             return


        for node in list_of_nodes:
             print(node)
             if not node in switch_hdl_dict.keys():
                continue
             hdl=switch_hdl_dict[node]
             
             self.ospfv3_instance_cfg[node]={}
             self.ospfv3_area_cfg[node]={}
             self.ospfv3_interface_cfg[node]={}
             # Enable feature OSPF and verify        
             configFeature(hdl,self.log,'-feature ospfv3')

             # Configure OSPF Instance specific parameters ..
             if not 'instance_config' in self.ospfv3_config_dict[node].keys():
                 msg='OSPF Instance config not defined in ospfv3_config_dict for node {0}'. \
                     format(node)
                 testResult('fail', msg, self.log)
                 return
             else:
                 for instance in self.ospfv3_config_dict[node]['instance_config'].keys():
                      # Configure OSPF instance configs ..
                      inst_args=self.ospfv3_config_dict[node]['instance_config'][instance]
                      self.ospfv3_instance_cfg[node][instance]=parseOspfv3InstanceConfig(inst_args, self.log)
                      self.configOspfv3Instance(hdl, self.log, instance, self.ospfv3_instance_cfg[node][instance])


                         # Configure OSPF area parameters ..
             if not 'area_config' in self.ospfv3_config_dict[node].keys():
                 msg='OSPF area config not defined in ospfv3_config_dict for node {0}'.   \
                     format(node)
                 testResult('fail', msg, self.log)

             else:
                 # Iterate for every area ..
                 for area_id in self.ospfv3_config_dict[node]['area_config'].keys():
                     area_args=self.ospfv3_config_dict[node]['area_config'][area_id]
                     self.ospfv3_area_cfg[node][area_id]=parseOspfv3AreaConfigs(area_args, self.log)
                     self.configOspfv3Area(hdl, self.log, area_id, self.ospfv3_area_cfg[node][area_id])


             if not 'interface_config' in self.ospfv3_config_dict[node].keys():
                 msg='OSPF Interface config not defined in ospfv3_config_dict for node {0}'. \
                     format(node)
                 testResult('fail', msg, self.log)

             else:
                for intf_range in self.ospfv3_config_dict[node]['interface_config'].keys():
                    intf_args=self.ospfv3_config_dict[node]['interface_config'][intf_range]
                    self.ospfv3_interface_cfg[node][intf_range]=parseOspfv3InterfaceConfig(intf_args, self.log)
                    self.configOspfv3Interface(hdl,log, intf_range, self.ospfv3_interface_cfg[node][intf_range])

    def configOspfv3Instance (self, hdl, log, instance, ospfv3_instance_cfg_dict):
#       -vrf_name default -router_id 1.2.1.2 -admin_distance 110 -auto_cost_reference_bandwidth 40000 -graceful_restart_flag YES 
#       -maximum_paths 8 -throttle_spf_timer_start 200 -throttle_spf_timer_hold 1000 -throttle_spf_timer_max 5000 -throttle_lsa_timer_start 0 
#       -throttle_lsa_timer_hold 5000 -throttle_lsa_timer_max 5000 -lsa_arrival_timer 1000 -lsa_group_pacing_timer 10


        sw_cmd='''router ospfv3 {0}
        log-adjacency-changes detail'''.format(instance)
        if ospfv3_instance_cfg_dict['vrf_name'] != "default":
            sw_cmd='''{0}
                  vrf {1}'''.format(sw_cmd, ospfv3_instance_cfg_dict['vrf_name'])
        if 'router_id' in ospfv3_instance_cfg_dict.keys():
            sw_cmd='''{0}
                  router-id {1}'''.format(sw_cmd, ospfv3_instance_cfg_dict['router_id'])             
        if 'lsa_arrival_timer' in ospfv3_instance_cfg_dict.keys():
            sw_cmd='''{0}
                  timers lsa-arrival {1}'''.format(sw_cmd, ospfv3_instance_cfg_dict['lsa_arrival_timer'])             
        if 'throttle_lsa_timer_start' in ospfv3_instance_cfg_dict.keys():
            sw_cmd='''{0}
                  timers throttle lsa {1} {2} {3}'''.format(sw_cmd, ospfv3_instance_cfg_dict['throttle_lsa_timer_start'], \
                                                            ospfv3_instance_cfg_dict['throttle_lsa_timer_hold'], ospfv3_instance_cfg_dict['throttle_lsa_timer_max'])
        if 'throttle_spf_timer_start' in ospfv3_instance_cfg_dict.keys():
            sw_cmd='''{0}
                  timers throttle spf {1} {2} {3}'''.format(sw_cmd, ospfv3_instance_cfg_dict['throttle_spf_timer_start'], \
                                                            ospfv3_instance_cfg_dict['throttle_spf_timer_hold'], ospfv3_instance_cfg_dict['throttle_spf_timer_max'])                       
        if 'lsa_group_pacing_timer' in ospfv3_instance_cfg_dict.keys():
            sw_cmd='''{0}
                  timers lsa-group-pacing {1}'''.format(sw_cmd, ospfv3_instance_cfg_dict['lsa_group_pacing_timer'])   
        if 'auto_cost_reference_bandwidth' in ospfv3_instance_cfg_dict.keys():
            sw_cmd='''{0}
                  auto-cost reference-bandwidth {1}'''.format(sw_cmd, ospfv3_instance_cfg_dict['auto_cost_reference_bandwidth']) 
        if 'graceful_restart_flag' in ospfv3_instance_cfg_dict.keys() and ospfv3_instance_cfg_dict['graceful_restart_flag']:
            sw_cmd='''{0}
                  graceful-restart'''.format(sw_cmd) 
        if 'maximum_paths' in ospfv3_instance_cfg_dict.keys():
            sw_cmd='''{0}
                  address-family ipv6 unicast
                  maximum-paths {1}
                  exit'''.format(sw_cmd, ospfv3_instance_cfg_dict['maximum_paths']) 
        if 'admin_distance' in ospfv3_instance_cfg_dict.keys():
            sw_cmd='''{0}
                  address-family ipv6 unicast
                  distance {1}
                  exit'''.format(sw_cmd, ospfv3_instance_cfg_dict['admin_distance'])             
                  
        hdl.configure(sw_cmd)


    def configOspfv3Area (self, hdl, log, area_id, area_cfg_dict):
#        area_config:
#            1:
#             -instance_name 100 -area_type external_capable -auth_type md5

         sw_cmd='''router ospfv3 {0}'''.format(area_cfg_dict['instance_name'])
         if 'vrf_name' in area_cfg_dict.keys():
             if area_cfg_dict['vrf_name'] != "default":
                 sw_cmd='''{0}
                  vrf {1}'''.format(sw_cmd, area_cfg_dict['vrf_name'])                                   

         if area_cfg_dict['area_type'] == "external_capable":
             pass
         elif area_cfg_dict['area_type'] == "stub":
             sw_cmd='''{0}
                       area {1} stub'''.format(                        \
                       sw_cmd, area_id )
         elif area_cfg_dict['area_type'] == "nssa":
             sw_cmd='''{0}
                       area {1} nssa'''.format(                        \
                       sw_cmd, area_id )
         elif area_cfg_dict['area_type'] == "totally_stub":
             sw_cmd='''{0}
                       area {1} stub no-summary'''.format(             \
                       sw_cmd, area_id )
         elif area_cfg_dict['area_type'] == "totally_nssa":
             sw_cmd='''{0}
                       area {1} nssa no-summary'''.format(             \
                       sw_cmd, area_id )

         hdl.configure(sw_cmd)

         if 'auth_type' in area_cfg_dict.keys() and re.search( 'md5|message', area_cfg_dict['auth_type'],        \
               flags=re.I ):
             sw_cmd='''router ospfv3 {0}
                   area {1} authentication message-digest'''.format(   \
                   area_cfg_dict['instance_name'], area_id )

         hdl.configure(sw_cmd)


    def configOspfv3Interface (self, hdl, log, intf, intf_cfg_dict):
#               -vrf_name default -instance_name 100 -cost 40 -hello_interval 10 -dead_interval 40 -transmit_delay 1 -retransmit_interval 5 -priority 1 -area_id 0 -auth_type md5 -auth_key insieme -md5_key insieme -network_type broadcast -include_secondaries_flag YES


        sw_cmd='''interface {0}
                ipv6 router ospfv3 {1} area {2}'''.format(intf, intf_cfg_dict['instance_name'], intf_cfg_dict['area_id'])
                
        if 'cost' in intf_cfg_dict:
            sw_cmd='''{0}
                    ospfv3 cost {1}'''.format(sw_cmd, intf_cfg_dict['cost'])
                    
        sw_cmd='''{0}           
                  ospfv3 hello-interval {1}
                  ospfv3 dead-interval {2}
                  ospfv3 transmit-delay {3}
                  ospfv3 retransmit-interval {4}
                  ospfv3 priority {5}'''.format( sw_cmd,  \
                  intf_cfg_dict['hello_interval'],                      \
                  intf_cfg_dict['dead_interval'],                       \
                  intf_cfg_dict['transmit_delay'],                      \
                  intf_cfg_dict['retransmit_interval'],                 \
                  intf_cfg_dict['priority'] )                           
               

        if 'passive_interface' in intf_cfg_dict.keys() and intf_cfg_dict['passive_interface']:
            sw_cmd='''{0}
                   ospfv3 passive-interface'''.format(sw_cmd, intf_cfg_dict['passive_interface'])

        if 'mtu_ignore' in intf_cfg_dict.keys() and intf_cfg_dict['mtu_ignore']:
            sw_cmd='''{0}
                   ospfv3 mtu-ignore'''.format(sw_cmd, intf_cfg_dict['mtu_ignore'])

        hdl.configure(sw_cmd)


    def verifyOspfv3(self):
        
          for node in self.ospfv3_interface_cfg.keys():
             print(node)
             hdl=self.switch_hdl_dict[node]
             
             ## Verify Ospfv3 configs
             #print self.ospfv3_instance_cfg[node]
             ## Get ospfv3 interface detail dict for all ospfv3 interfaces
             ospfv3_int_dict=getOspfv3InterfaceDetailDict(hdl, self.log)

             ## For each interface verify Ospf interface config values from yml input and on dut are same
             for intf_range in self.ospfv3_interface_cfg[node].keys():
                 intf_list=normalizeInterfaceName(self.log,strtoexpandedlist(intf_range))
                 for intf in intf_list:

                     if 'retransmit_interval' in self.ospfv3_interface_cfg[node][intf_range].keys():
                         if self.ospfv3_interface_cfg[node][intf_range]['retransmit_interval'] != ospfv3_int_dict[intf]['Retransmit_interval']:
                             testResult('fail', 'Retransmit interval on {0} expected :{1} actual {2} on {3}'.\
                                        format(intf, self.ospfv3_interface_cfg[node][intf_range]['retransmit_interval'], ospfv3_int_dict[intf]['Retransmit_interval'], node), self.log)
                     if 'dead_interval' in self.ospfv3_interface_cfg[node][intf_range].keys():
                         if self.ospfv3_interface_cfg[node][intf_range]['dead_interval'] != ospfv3_int_dict[intf]['Dead_interval']:
                             testResult('fail', 'Dead interval on {0} expected :{1} actual {2} on {3}'.\
                                        format(intf, self.ospfv3_interface_cfg[node][intf_range]['dead_interval'], ospfv3_int_dict[intf]['Dead_interval'], node), self.log)
                     if 'hello_interval' in self.ospfv3_interface_cfg[node][intf_range].keys():
                         if self.ospfv3_interface_cfg[node][intf_range]['hello_interval'] != ospfv3_int_dict[intf]['Hello_interval']:
                             testResult('fail', 'Hello interval on {0} expected :{1} actual {2} on {3}'.\
                                        format(intf, self.ospfv3_interface_cfg[node][intf_range]['hello_interval'], ospfv3_int_dict[intf]['Hello_interval'], node), self.log)
                     if 'network_type' in self.ospfv3_interface_cfg[node][intf_range].keys():
                         if not re.search(self.ospfv3_interface_cfg[node][intf_range]['network_type'], ospfv3_int_dict[intf]['Network_type'], re.I):
                             testResult('fail', 'Network type on {0} expected :{1} actual {2} on {3}'.\
                                        format(intf, self.ospfv3_interface_cfg[node][intf_range]['network_type'], ospfv3_int_dict[intf]['Network_type'], node), self.log)
                     if 'cost' in self.ospfv3_interface_cfg[node][intf_range].keys():
                         if self.ospfv3_interface_cfg[node][intf_range]['cost'] != ospfv3_int_dict[intf]['cost']:
                             testResult('fail', 'Cost on {0} expected :{1} actual {2} on {3}'.\
                                        format(intf, self.ospfv3_interface_cfg[node][intf_range]['cost'], ospfv3_int_dict[intf]['cost'], node), self.log)


                                              
             # Verify Ospf adjacencies on interfaces  for each interface_range   
             for intf_range in self.ospfv3_interface_cfg[node].keys():
                 intf_list=normalizeInterfaceName(self.log,strtoexpandedlist(intf_range))
                 
                 ## Get the peer node and interface to verify neighbor from ospfv3_config_dict in yml input file
                 peer_intf_list=normalizeInterfaceName(self.log,strtoexpandedlist(self.ospfv3_interface_cfg[node][intf_range]['peer_interface']))
                 peer_node=self.ospfv3_interface_cfg[node][intf_range]['peer_device']

                 for intf,peer_intf in zip(intf_list,peer_intf_list):
                     if 'vrf_name' in self.ospfv3_interface_cfg[node][intf_range].keys():
                        if self.ospfv3_interface_cfg[node][intf_range]['vrf_name'] != 'default':
                             args='-vrf {0}'.self.ospfv3_interface_cfg[node][intf_range]['vrf_name']
                             ospfv3_nei_dict=getOspfv3NeighborDict(hdl, self.log, args)
                        else:
                             ospfv3_nei_dict=getOspfv3NeighborDict(hdl, self.log)
                     else: 
                         ospfv3_nei_dict=getOspfv3NeighborDict(hdl, self.log)
                         
                     verifyOspfv3InterfaceStatus(hdl, self.log, '-interfaces {0}'.format(intf))
                     verifyOspfv3Neighbor(hdl, self.log, '-interface {0}'.format(intf))



                     
 
             
        


