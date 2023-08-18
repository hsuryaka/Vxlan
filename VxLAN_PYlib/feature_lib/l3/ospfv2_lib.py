
import os
import sys
import yaml

from common_lib.utils import *
from common_lib import utils
from common_lib.bringup_lib import *
from common_lib import parserutils_lib
from common_lib.verify_lib import *
from common_lib.interface_lib import *


#======================================================================================#
# Define the Ospfv2 parse methods
#======================================================================================#

def parseOspfInstanceConfig(args,log):

#       -vrf_name default -router_id 1.2.1.2 -admin_distance 110 -auto_cost_reference_bandwidth 40000 -graceful_restart_flag YES 
#       -maximum_paths 8 -throttle_spf_timer_start 200 -throttle_spf_timer_hold 1000 -throttle_spf_timer_max 5000 -throttle_lsa_timer_start 0 
#       -throttle_lsa_timer_hold 5000 -throttle_lsa_timer_max 5000 -lsa_arrival_timer 1000 -lsa_group_pacing_timer 10

    arggrammar = {}
    arggrammar['router_id'] = '-type str'
    arggrammar['admin_distance'] = '-type str -default 110'
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

    
def parseOspfAreaConfigs (args, log):
#   area_config:
#          default:
#              0.0.0.0:
#                   -area_type external_capable -auth_type md5
#              0.0.2.2:
#                   -area_type nssa -auth_type text

    arggrammar = {}
    arggrammar['area_type'] = '-type str'
    arggrammar['auth_type'] = '-type str'
    return parserutils_lib.argsToCommandOptions( args, arggrammar, log, "dict")


def parseOspfInterfaceConfig (args, log):
#    -vrf_name default -instance_name 100 -cost 40 -hello_interval 10 -dead_interval 40 -transmit_delay 1 -retransmit_interval 5 -priority 1 -area_id 0 -auth_type md5 -auth_key insieme -md5_key insieme -network_type broadcast -include_secondaries_flag YES

    arggrammar = {}
    arggrammar['vrf_name'] = '-type str'
    arggrammar['area_id']= '-type str -required True'
    arggrammar['cost'] = '-type str'
    arggrammar['hello_interval'] = '-type str'
    arggrammar['dead_interval'] = '-type str'
    arggrammar['transmit_delay']= '-type str'
    arggrammar['retransmit_interval']= '-type str'
    arggrammar['priority']= '-type str'
    arggrammar['network_type']='-type str'
    arggrammar['passive_interface']='-type bool'
    arggrammar['mtu_ignore']='-type bool'
    arggrammar['auth_type']= '-type str'
    arggrammar['auth_key']='-type str -mandatoryargs auth_type'
    arggrammar['md5_key']='-type str -mandatoryargs auth_type'
    arggrammar['peer_device']='-type str'
    arggrammar['peer_interface']='-type str'

    return parserutils_lib.argsToCommandOptions( args, arggrammar, log, "dict")


def parseOspfRedistributionConfig (args, log):
## -tag_name 200 -route_map rmap3

    arggrammar = {}
    arggrammar['route_map'] = '-type str'
    arggrammar['tag_name'] = '-type str'

    return parserutils_lib.argsToCommandOptions( args, arggrammar, log, "dict")

def parseNodeParams (args, log):
## -tag_name 200 -route_map rmap3

    arggrammar = {}
    arggrammar['device_type']='-type str -format {0} -default NA'.format(rex.DEVICE_TYPE)
    arggrammar['flags']=['ignore_unknown_key']
    return parserutils_lib.argsToCommandOptions( args, arggrammar, log, "dict")

#======================================================================================#
# Class to configure and verify Ospfv2 config 
#======================================================================================#


class configOspfv2 ():
    
    def __init__( self, switch_hdl_dict, ospfv2_config_dict, log, *args):
        
        self.log=log
        self.result='pass'
        self.log.info('Switch OSPFv2 Bringup test')
        # self.node_dict=node_dict
        #self.interface_config_dict=interface_config_dict
        self.ospfv2_config_dict=ospfv2_config_dict
        self.switch_hdl_dict=switch_hdl_dict
        self.ospf_instance_cfg={}
        self.ospf_area_cfg={}
        self.ospf_interface_cfg={}
        self.ospf_redistribution_dict={}
        try:
             list_of_nodes=self.ospfv2_config_dict.keys()
        except KeyError:
             print('ospfv2_config_dict in input file not defined properly ..               \
                  does not have any keys ..')
             self.result='fail'
             self.log.error('ospfv2_config_dict in input file not defined properly ..      \
                  does not have any keys ..')
             return
        
        
        for node in list_of_nodes:
            print(node)
            if not node in switch_hdl_dict.keys():
                continue
            hdl=switch_hdl_dict[node]
            
            self.ospf_instance_cfg[node]={}
            self.ospf_area_cfg[node]={}
            self.ospf_interface_cfg[node]={}
            self.ospf_redistribution_dict[node]={}
            # Enable feature OSPF and verify        
            #configFeature(hdl,self.log,'-feature ospf')
            
            
            try:
                instance_list=self.ospfv2_config_dict[node].keys()
            except KeyError:
                msg='ospfv2_config_dict for node {0} has no ospf instances defined in input file '.format(hdl.switchName)
                testResult('fail', msg, self.log)
                return
            for instance in instance_list:
                self.ospf_instance_cfg[node][instance]={}
                self.ospf_area_cfg[node][instance]={}
                self.ospf_interface_cfg[node][instance]={}     
                self.ospf_redistribution_dict[node][instance]={}
                
                if not 'router_configs' in self.ospfv2_config_dict[node][instance].keys():
                           msg='OSPF Instance router configs not defined in ospfv2_config_dict for node {0} instance {1}'. \
                               format(hdl.switchName, instance)
                           testResult('fail', msg, self.log)
                           return                     
                else:
                    try:
                         vrf_list=self.ospfv2_config_dict[node][instance]['router_configs'].keys()
                    except KeyError:
                         msg='ospfv2_config_dict in input file not defined properly does not have any keys for node {0}'.format(hdl.switchName)
                         testResult('fail', msg, self.log)
                         return           
                    for vrf_name in vrf_list:
                         # Configure OSPF instance configs ..
                         inst_args=self.ospfv2_config_dict[node][instance]['router_configs'][vrf_name]
                         self.ospf_instance_cfg[node][instance][vrf_name]=parseOspfInstanceConfig(inst_args, self.log)
                         self.configOspfv2Instance(hdl, self.log, instance, vrf_name, self.ospf_instance_cfg[node][instance][vrf_name])


                # Configure OSPF area parameters ..Area configs might not be there if all areas are external capable
                if 'area_configs' in self.ospfv2_config_dict[node][instance].keys():
                    area_vrf_list=self.ospfv2_config_dict[node][instance]['area_configs'].keys()
                    if area_vrf_list:
                        for area_vrf in area_vrf_list:
                            self.ospf_area_cfg[node][instance][area_vrf]={}
                            area_list=self.ospfv2_config_dict[node][instance]['area_configs'][area_vrf].keys()
                            
                            if area_list:
                                for area_id in area_list:
                                    area_args=self.ospfv2_config_dict[node][instance]['area_configs'][area_vrf][area_id]
                                    self.ospf_area_cfg[node][instance][area_vrf][area_id]=parseOspfAreaConfigs(area_args, self.log)
                                    self.configv2OspfArea(hdl, self.log, instance, area_vrf, area_id, self.ospf_area_cfg[node][instance][area_vrf][area_id])   
    
                if not 'interface_configs' in self.ospfv2_config_dict[node][instance].keys():
                    msg='OSPF Interface config not defined in ospfv2_config_dict for node {0} instance {1}'. \
                        format(node, instance)
                    testResult('fail', msg, self.log)

                else:
                    if not self.ospfv2_config_dict[node][instance]['interface_configs'].keys():
                        msg='OSPF Interface config not defined in ospfv2_config_dict for node {0} instance {1}'. \
                            format(node, instance)
                        testResult('fail', msg, self.log)
                    else:                      
                        for intf_range in self.ospfv2_config_dict[node][instance]['interface_configs'].keys():
                            intf_args=self.ospfv2_config_dict[node][instance]['interface_configs'][intf_range]
                            self.ospf_interface_cfg[node][instance][intf_range]=parseOspfInterfaceConfig(intf_args, self.log)
                            self.configOspfv2Interface(hdl, log, instance, intf_range, self.ospf_interface_cfg[node][instance][intf_range])
                        
                if 'redistribution_configs' in self.ospfv2_config_dict[node][instance].keys():
                     redistr_vrf_list=self.ospfv2_config_dict[node][instance]['redistribution_configs'].keys()
                     if redistr_vrf_list:
                         for redistr_vrf_name in redistr_vrf_list:
                             self.ospf_redistribution_dict[node][instance][redistr_vrf_name]={}
                             redistr_type_list=self.ospfv2_config_dict[node][instance]['redistribution_configs'][redistr_vrf_name].keys()
                             if redistr_type_list:
                                 for redistr_type in redistr_type_list:
                                     redistr_args=self.ospfv2_config_dict[node][instance]['redistribution_configs'][redistr_vrf_name][redistr_type]
                                     if redistr_args:
                                         self.ospf_redistribution_dict[node][instance][redistr_vrf_name][redistr_type]=\
                                         parseOspfRedistributionConfig(redistr_args, self.log)
                                         self.configOspfv2Redistribution(hdl, log, instance, redistr_vrf_name, redistr_type, \
                                                                       self.ospf_redistribution_dict[node][instance][redistr_vrf_name])
                     

            

    def configOspfv2Instance (self, hdl, log, instance, vrf_name, ospf_instance_cfg_dict):
#       -vrf_name default -router_id 1.2.1.2 -admin_distance 110 -auto_cost_reference_bandwidth 40000 -graceful_restart_flag YES 
#       -maximum_paths 8 -throttle_spf_timer_start 200 -throttle_spf_timer_hold 1000 -throttle_spf_timer_max 5000 -throttle_lsa_timer_start 0 
#       -throttle_lsa_timer_hold 5000 -throttle_lsa_timer_max 5000 -lsa_arrival_timer 1000 -lsa_group_pacing_timer 10
#  Sample Usage: self.configOspfv2Instance(hdl, self.log, instance, vrf_name, self.ospf_instance_cfg[node][instance][vrf_name])

        sw_cmd='''router ospf {0}
        log-adjacency-changes detail'''.format(instance)
        if vrf_name != "default":
            sw_cmd='''{0}
                  vrf {1}'''.format(sw_cmd, vrf_name)
        if 'router_id' in ospf_instance_cfg_dict:
            sw_cmd='''{0}
                  router-id {1}'''.format(sw_cmd, ospf_instance_cfg_dict['router_id'])             
        if 'admin_distance' in ospf_instance_cfg_dict:
            sw_cmd='''{0}
                  distance {1}'''.format(sw_cmd, ospf_instance_cfg_dict['admin_distance'])             
        if 'lsa_arrival_timer' in ospf_instance_cfg_dict:
            sw_cmd='''{0}
                  timers lsa-arrival {1}'''.format(sw_cmd, ospf_instance_cfg_dict['lsa_arrival_timer'])             
        if 'throttle_lsa_timer_start' in ospf_instance_cfg_dict:
            sw_cmd='''{0}
                  timers throttle lsa {1} {2} {3}'''.format(sw_cmd, ospf_instance_cfg_dict['throttle_lsa_timer_start'], \
                                                            ospf_instance_cfg_dict['throttle_lsa_timer_hold'], ospf_instance_cfg_dict['throttle_lsa_timer_max'])
        if 'throttle_spf_timer_start' in ospf_instance_cfg_dict:
            sw_cmd='''{0}
                  timers throttle spf {1} {2} {3}'''.format(sw_cmd, ospf_instance_cfg_dict['throttle_spf_timer_start'], \
                                                            ospf_instance_cfg_dict['throttle_spf_timer_hold'], ospf_instance_cfg_dict['throttle_spf_timer_max'])                       
        if 'lsa_group_pacing_timer' in ospf_instance_cfg_dict:
            sw_cmd='''{0}
                  timers lsa-group-pacing {1}'''.format(sw_cmd, ospf_instance_cfg_dict['lsa_group_pacing_timer'])   
        if 'auto_cost_reference_bandwidth' in ospf_instance_cfg_dict:
            sw_cmd='''{0}
                  auto-cost reference-bandwidth {1}'''.format(sw_cmd, ospf_instance_cfg_dict['auto_cost_reference_bandwidth']) 
        if 'maximum_paths' in ospf_instance_cfg_dict:
            sw_cmd='''{0}
                  maximum-paths {1}'''.format(sw_cmd, ospf_instance_cfg_dict['maximum_paths']) 
        if 'graceful_restart_flag' in ospf_instance_cfg_dict:
            sw_cmd='''{0}
                  graceful-restart'''.format(sw_cmd) 
        if 'auto_cost_reference_bandwidth' in ospf_instance_cfg_dict:
            sw_cmd='''{0}
                  auto-cost reference-bandwidth {1}'''.format(sw_cmd, ospf_instance_cfg_dict['auto_cost_reference_bandwidth']) 
                  
        hdl.configure(sw_cmd)


    def configOspfv2Area (self, hdl, log, instance, vrf_name, area_id, area_cfg_dict):
#        area_config:
#            1:
#             -instance_name 100 -area_type external_capable -auth_type md5

                 
         sw_cmd='''router ospf {0}'''.format(instance)
         if vrf_name != "default":
                 sw_cmd='''{0}
                  vrf {1}'''.format(sw_cmd, vrf_name)                                   
         if 'area_type' in area_cfg_dict:
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
         if 'auth_type' in area_cfg_dict:
             if re.search( 'md5|message', area_cfg_dict['auth_type'],        \
                   flags=re.I ):
                 sw_cmd='''router ospf {0}
                       area {1} authentication message-digest'''.format(   \
                       instance, area_id )
    
             hdl.configure(sw_cmd)


    def configOspfv2Interface (self, hdl, log, instance, intf, intf_cfg_dict):
#               -vrf_name default -instance_name 100 -cost 40 -hello_interval 10 -dead_interval 40 -transmit_delay 1 -retransmit_interval 5 -priority 1 -area_id 0 -auth_type md5 -auth_key insieme -md5_key insieme -network_type broadcast -include_secondaries_flag YES
        print('Starting configOspfv2Interface')

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

        hdl.configure(sw_cmd)


    def configOspfv2Redistribution (self, hdl, log, instance, vrf_name, redistr_type, ospf_redistribution_dict):
#    self.configOspfv2Redistribution(hdl, log, instance, redistr_vrf_name, redistr_type, \
#    self.ospf_redistribution_dict[node][instance][redistr_vrf][redistr_type])
        self.log.info('Starting Ospf Redistribution config on {0}'.format(hdl.switchName))
        
        sw_cmd='''router ospf {0}'''.format(instance)
        if vrf_name  and vrf_name != "default":
                sw_cmd='''{0}
                 vrf {1}'''.format(sw_cmd, vrf_name)      
        
        if ospf_redistribution_dict:
            if redistr_type in ospf_redistribution_dict:
                if re.search('direct', redistr_type, re.I) or re.search('static', redistr_type, re.I):
                    sw_cmd='''{0}
                         redistribute {1} route-map {2}'''.format(sw_cmd, redistr_type, ospf_redistribution_dict[redistr_type]['route_map'])           
                elif re.search('bgp', redistr_type, re.I) or re.search('eigrp', redistr_type, re.I) or \
                re.search('rip', redistr_type, re.I) or re.search('isis', redistr_type, re.I) or re.search('ospf', redistr_type, re.I):
                    sw_cmd='''{0}
                         redistribute {1} {2} route-map {3}'''.format(sw_cmd, redistr_type, ospf_redistribution_dict[redistr_type]['tag_name'], \
                                                                      ospf_redistribution_dict[redistr_type]['route_map'])             
        hdl.configure(sw_cmd)

    def cleanupOspfConfig(self):
        '''Method to remove all ospf config'''
        try:
             list_of_nodes=self.ospfv2_config_dict.keys()
        except KeyError:
             print('ospfv2_config_dict in input file not defined properly ..               \
                  does not have any keys ..')
             self.result='fail'
             self.log.error('ospfv2_config_dict in input file not defined properly ..      \
                  does not have any keys ..')
             return
        
        for node in list_of_nodes:
            print(node)
            hdl=self.switch_hdl_dict[node]
            bringup_lib.unconfigFeature(hdl, self.log, '-feature ospf')



class verifyOspf ():
    ''' Class to verify ospf status and config based on input dict'''
    
    def __init__( self, switch_hdl_dict, node_dict, interface_config_dict, ospfv2_config_dict, log, *args):
        
        self.log=log
        self.result='pass'
        self.log.info('Switch OSPFv2 Bringup test')
        self.node_dict=node_dict
        
        self.interface_config_dict=interface_config_dict
        self.ospfv2_config_dict=ospfv2_config_dict
        self.switch_hdl_dict=switch_hdl_dict
        self.ospf_instance_cfg={}
        self.ospf_area_cfg={}
        self.ospf_interface_cfg={}
        self.ospf_redistribution_dict={}
        
        try:
             list_of_nodes=self.ospfv2_config_dict.keys()
        except KeyError:
             print('ospfv2_config_dict in input file not defined properly ..               \
                  does not have any keys ..')
             self.result='fail'
             self.log.error('ospfv2_config_dict in input file not defined properly ..      \
                  does not have any keys ..')
             return
        
        for node in list_of_nodes:
            print(node)
            hdl=switch_hdl_dict[node]
            
            self.ospf_instance_cfg[node]={}
            self.ospf_area_cfg[node]={}
            self.ospf_interface_cfg[node]={}
            self.ospf_redistribution_dict[node]={}
            # Verify OSPF enabled       
            verifyFeatureState(hdl,self.log,'-feature ospf')
            
            
            try:
                instance_list=self.ospfv2_config_dict[node].keys()
            except KeyError:
                msg='ospfv2_config_dict for node {0} has no ospf instances defined in input file '.format(hdl.switchName)
                testResult('fail', msg, self.log)
                return
            for instance in instance_list:
                self.ospf_instance_cfg[node][instance]={}
                self.ospf_area_cfg[node][instance]={}
                self.ospf_interface_cfg[node][instance]={}     
                self.ospf_redistribution_dict[node][instance]={}
                
                if not 'router_configs' in self.ospfv2_config_dict[node][instance].keys():
                           msg='OSPF Instance router configs not defined in ospfv2_config_dict for node {0} instance {1}'. \
                               format(hdl.switchName, instance)
                           testResult('fail', msg, self.log)
                           return                     
                else:
                    try:
                         vrf_list=self.ospfv2_config_dict[node][instance]['router_configs'].keys()
                    except KeyError:
                         msg='ospfv2_config_dict in input file not defined properly does not have any keys for node {0}'.format(hdl.switchName)
                         testResult('fail', msg, self.log)
                         return           
                    for vrf_name in vrf_list:
                         # Configure OSPF instance configs ..
                         inst_args=self.ospfv2_config_dict[node][instance]['router_configs'][vrf_name]
                         self.ospf_instance_cfg[node][instance][vrf_name]=parseOspfInstanceConfig(inst_args, self.log)
                         self.verifyOspfInstance(hdl, self.log, node, instance, vrf_name)


                # Configure OSPF area parameters ..Area configs might not be there if all areas are external capable
                if 'area_configs' in self.ospfv2_config_dict[node][instance].keys():
                    area_vrf_list=self.ospfv2_config_dict[node][instance]['area_configs'].keys()
                    if area_vrf_list:
                        for area_vrf in area_vrf_list:
                            self.ospf_area_cfg[node][instance][area_vrf]={}
                            area_list=self.ospfv2_config_dict[node][instance]['area_configs'][area_vrf].keys()
                            
                            if area_list:
                                for area_id in area_list:
                                    area_args=self.ospfv2_config_dict[node][instance]['area_configs'][area_vrf][area_id]
                                    self.ospf_area_cfg[node][instance][area_vrf][area_id]=parseOspfAreaConfigs(area_args, self.log)
                                    self.verifyOspfArea(hdl, self.log, node, instance, area_vrf, area_id)   
    
                if not 'interface_configs' in self.ospfv2_config_dict[node][instance].keys():
                    msg='OSPF Interface config not defined in ospfv2_config_dict for node {0} instance {1}'. \
                        format(node, instance)
                    testResult('fail', msg, self.log)

                else:
                    if not self.ospfv2_config_dict[node][instance]['interface_configs'].keys():
                        msg='OSPF Interface config not defined in ospfv2_config_dict for node {0} instance {1}'. \
                            format(node, instance)
                        testResult('fail', msg, self.log)
                    else:                      
                        for intf_range in self.ospfv2_config_dict[node][instance]['interface_configs'].keys():
                            intf_args=self.ospfv2_config_dict[node][instance]['interface_configs'][intf_range]
                            self.ospf_interface_cfg[node][instance][intf_range]=parseOspfInterfaceConfig(intf_args, self.log)
                            self.verifyOspfInterface(hdl, log, node, instance, intf_range)
                            self.verifyOspfNeighbor(hdl, log, node, instance, intf_range) 

    
    ## Todo: Add verifications for instance config- need to add get method
    def verifyOspfInstance(self, hdl, log, node, instance, vrf_name):
        ## Verify dut info with self.ospf_instance_cfg[node][instance][vrf_name]
        pass
  
    ## Todo: Add verifications for area config- need to add get method
    def verifyOspfArea(self, hdl, log, node, instance, area_vrf, area_id):
        ## Verify dut info with self.ospf_area_cfg[node][instance][area_vrf][area_id]
        pass
        

    def verifyOspfInterface(self,hdl, log, node, instance, intf_range):
        
        ##Get Ospf interface dict from node
        if 'vrf_name' in self.ospf_interface_cfg[node][instance][intf_range].keys():
            argl='-vrf {0}'.format(self.ospf_interface_cfg[node][instance][intf_range]['vrf_name'])
            ospf_int_dict=eor_utils.getIpOspfInterfaceDetailDict(hdl, self.log, argl)
        else:
            ospf_int_dict=eor_utils.getIpOspfInterfaceDetailDict(hdl, self.log)
        intf_list=normalizeInterfaceName(self.log,strtoexpandedlist(intf_range))

        for intf in intf_list:
            
            if intf not in ospf_int_dict:
                testResult('fail', 'Interface {0} not in Ospf interface dict on node {1}'.\
                               format(intf, hdl.switchName), self.log)
            else:
                if 'retransmit_interval' in self.ospf_interface_cfg[node][instance][intf_range].keys():
                    if self.ospf_interface_cfg[node][instance][intf_range]['retransmit_interval'] != ospf_int_dict[intf]['Retransmit_interval']:
                        testResult('fail', 'Retransmit interval on {0} expected :{1} actual {2} on {3}'.\
                                   format(intf, self.ospf_interface_cfg[node][intf_range]['retransmit_interval'], ospf_int_dict[intf]['Retransmit_interval'], node), self.log)
                if 'dead_interval' in self.ospf_interface_cfg[node][instance][intf_range].keys():
                    if self.ospf_interface_cfg[node][instance][intf_range]['dead_interval'] != ospf_int_dict[intf]['Dead_interval']:
                        testResult('fail', 'Dead interval on {0} expected :{1} actual {2} on {3}'.\
                                   format(intf, self.ospf_interface_cfg[node][instance][intf_range]['dead_interval'], ospf_int_dict[intf]['Dead_interval'], node), self.log)
                if 'hello_interval' in self.ospf_interface_cfg[node][instance][intf_range].keys():
                    if self.ospf_interface_cfg[node][instance][intf_range]['hello_interval'] != ospf_int_dict[intf]['Hello_interval']:
                        testResult('fail', 'Hello interval on {0} expected :{1} actual {2} on {3}'.\
                                   format(intf, self.ospf_interface_cfg[node][instance][intf_range]['hello_interval'], ospf_int_dict[intf]['Hello_interval'], node), self.log)
                if 'network_type' in self.ospf_interface_cfg[node][instance][intf_range].keys():
                    if not re.search(self.ospf_interface_cfg[node][instance][intf_range]['network_type'], ospf_int_dict[intf]['Network_type'], re.I):
                        testResult('fail', 'Network type on {0} expected :{1} actual {2} on {3}'.\
                                   format(intf, self.ospf_interface_cfg[node][instance][intf_range]['network_type'], ospf_int_dict[intf]['Network_type'], node), self.log)
                if 'cost' in self.ospf_interface_cfg[node][instance][intf_range].keys():
                    if self.ospf_interface_cfg[node][instance][intf_range]['cost'] != ospf_int_dict[intf]['cost']:
                        testResult('fail', 'Cost on {0} expected :{1} actual {2} on {3}'.\
                                   format(intf, self.ospf_interface_cfg[node][instance][intf_range]['cost'], ospf_int_dict[intf]['cost'], node), self.log)


    def verifyOspfNeighbor(self, hdl, log, node, instance, intf_range):

                                              
        # Verify Ospf adjacencies on interfaces  for each interface_range   
        intf_list=normalizeInterfaceName(self.log,strtoexpandedlist(intf_range))
        
        ## Get the peer node and interface to verify neighbor from ospfv2_config_dict in yml input file
        if 'peer_interface' in self.ospf_interface_cfg[node][instance][intf_range] and \
        'peer_device' in self.ospf_interface_cfg[node][instance][intf_range]:
            peer_intf_list=normalizeInterfaceName(self.log,strtoexpandedlist(self.ospf_interface_cfg[node][instance][intf_range]['peer_interface']))
            peer_node=self.ospf_interface_cfg[node][instance][intf_range]['peer_device']

            #### Add a check for device_type is itgen and skip
            node_params_dict=parseNodeParams(self.node_dict[node]['params'], self.log)
            peer_node_params_dict=parseNodeParams(self.node_dict[peer_node]['params'], self.log)
        
            local_device_type=node_params_dict['device_type']
            peer_device_type=peer_node_params_dict['device_type']
            
            if local_device_type=='itgen' or peer_device_type=='itgen':
                self.log.info('Device type of {0} is {1} and peer {2} is {3} - neighbor verification skipped with itgen'.format(node,local_device_type, peer_node,peer_device_type))
            else:
                for intf,peer_intf in zip(intf_list,peer_intf_list):
                    if 'vrf_name' in self.ospf_interface_cfg[node][instance][intf_range].keys():
                       if self.ospf_interface_cfg[node][instance][intf_range]['vrf_name'] != 'default':
                            args='-vrf {0}'.format(self.ospf_interface_cfg[node][instance][intf_range]['vrf_name'])
                            ospf_nei_dict=getIpOspfNeighborDict(hdl, self.log, args)
                       else:
                            ospf_nei_dict=getIpOspfNeighborDict(hdl, self.log)
                    else: 
                        ospf_nei_dict=getIpOspfNeighborDict(hdl, self.log)
       
                    if 'vrf_name' in self.ospf_interface_cfg[node][instance][intf_range].keys():
                        verifyOspfInterfaceStatus(hdl, self.log, '-interfaces {0} -vrf {1}'.format(intf, self.ospf_interface_cfg[node][instance][intf_range]['vrf_name']))
                    else:
                        verifyOspfInterfaceStatus(hdl, self.log, '-interfaces {0}'.format(intf))
                                                
                    ## Get peer Ipv4 address
                    obj=interface_lib.verifyInterface(self.log, self.switch_hdl_dict,self.node_dict,self.interface_config_dict)
                    peer_ip=obj.interface_dict[peer_node][peer_intf]['ipv4']['ipv4_addr']

                    if 'vrf_name' in self.ospf_interface_cfg[node][instance][intf_range].keys():
                       if self.ospf_interface_cfg[node][instance][intf_range]['vrf_name'] != 'default':
                            args='-vrf {0} -neighbors {1}'.format(self.ospf_interface_cfg[node][instance][intf_range]['vrf_name'], peer_ip)
                            verify=verifyOspfNeighbor(hdl,self.log, args)
                            print('verify result is {0}'.format(verify.result))
                       else:
                            args='-neighbors {0}'.format(peer_ip)
                            verifyOspfNeighbor(hdl,self.log, args)
                    else:
                        args='-neighbors {0}'.format(peer_ip)
                        verifyOspfNeighbor(hdl,self.log, args)
    
                    if self.result=='fail':
                        testResult('fail', 'Ospf neighbor verification failed for {0} on {1}'.format(intf, node), self.log)
                
                
