#!/bin/env python
##################################################################
# This file contains Ixia specific proc like interface creation, #
# traffic creation, protocol config in Ixia, etc.                #  
##################################################################

import logging

from common_lib import parserutils_lib
import ipaddress
from collections import OrderedDict
#from hltapi import Ixia

# create logger
log = logging.getLogger(__name__)
log.setLevel(logging.DEBUG)

#ixia = Ixia()

def connectToIxNetwork (self, tg_hdl='', port_list=''):
    ixia_connect = tg_hdl.connect(port_list = port_list)
    if ixia_connect['status'] == 1:
        log.info('Successfully connected to IxNetwork with ports {0}'.format(port_list))
    else:
        log.error("Failed to connect to IxNetwork with ports {0}".format(port_list))
        self.failed()
    return ixia_connect

def configureL2StaticInterfaces(self,intf_args, tg_hdl='',port_handle=''):
    log.info('Inside configureL2StaticInterfaces')
    log.info('Configuring {0} with Parameters {1}'.format(port_handle,intf_args))
    arggrammar={}
    arggrammar['mode']='-type str'
    arggrammar['static_enable']='-type str'
    arggrammar['static_vlan_enable']='-type str'
    arggrammar['static_mac_dst']='-type str'
    arggrammar['static_lan_mac_range_mode']='-type str'
    arggrammar['static_lan_skip_vlan_id_zero']='-type str'
    arggrammar['static_lan_tpid']='-type str'
    arggrammar['static_lan_vlan_stack_count']='-type str'
    arggrammar['static_vlan_id']='-type str'
    arggrammar['static_lan_vlan_priority']='-type str'
    arggrammar['static_mac_dst_mode']='-type str'
    arggrammar['static_mac_dst_count'] = '-type str'
    arggrammar['static_site_id_enable']='-type str'
    arggrammar['static_vlan_id_mode'] = '-type str'
    arggrammar['static_lan_range_count']= '-type str'
     
    try:
        ns=parserutils_lib.argsToCommandOptions(intf_args,arggrammar,log)
    except Exception as e:
        return 0

    log.info('The Value of ns is {0}'.format(ns))
    ixia_interface_config = tg_hdl.interface_config(port_handle=port_handle,mode='config',static_enable = ns.static_enable,
                                                    static_vlan_enable=ns.static_vlan_enable,static_mac_dst=ns.static_mac_dst,
                                                    static_lan_mac_range_mode=ns.static_lan_mac_range_mode,static_lan_skip_vlan_id_zero=1,
                                                    static_lan_tpid='0x8100',static_lan_vlan_stack_count=1,static_vlan_id = ns.static_vlan_id,
                                                    static_lan_vlan_priority = 1,static_mac_dst_mode=ns.static_mac_dst_mode,
                                                    static_mac_dst_count=ns.static_mac_dst_count,
                                                    static_site_id_enable=0,static_vlan_id_mode='fixed',static_lan_range_count=1)

    if ixia_interface_config['status'] == 1:
        log.info('Successfully configured protocol interface for {0}'.format(port_handle))
    else:
        log.error("Failed to configure protocol interface for {0}".format(port_handle))
        self.failed()
    log.info('Value of ixia_interface_config is  {0}'.format(ixia_interface_config))
    return ixia_interface_config

def configureIxNetworkInterface (self, intf_args, tg_hdl='', port_handle=''):
    log.info('Configuring {0} with parameters {1}'.format(port_handle,intf_args))
    arggrammar={}
    arggrammar['mode']='-type str'
    arggrammar['intf_ip_addr']='-type str'
    arggrammar['netmask']='-type str'
    arggrammar['gateway']='-type str'
    arggrammar['ipv6_intf_addr']='-type str'
    arggrammar['ipv6_prefix_length']='-type str'
    arggrammar['ipv6_gateway']='-type str'
    arggrammar['vlan']='-type str'
    arggrammar['vlan_id']='-type str'
    arggrammar['src_mac_addr']='-type str'
    arggrammar['mtu']='-type str'
    arggrammar['arp_send_req'] = '-type str'
    arggrammar['ndp_send_req'] = '-type str'
    
    try:
        ns=parserutils_lib.argsToCommandOptions(intf_args,arggrammar,log)
    except Exception as e:
        return 0
        
    ixia_interface_config = tg_hdl.interface_config(port_handle=port_handle,mode=ns.mode,intf_ip_addr=ns.intf_ip_addr,
                                                    netmask=ns.netmask,gateway=ns.gateway,vlan=ns.vlan,vlan_id=ns.vlan_id,
                                                    arp_send_req = ns.arp_send_req,src_mac_addr = ns.src_mac_addr,
                                                    ipv6_intf_addr = ns.ipv6_intf_addr,ipv6_gateway = ns.ipv6_gateway,
                                                    ipv6_prefix_length = ns.ipv6_prefix_length)
    if ixia_interface_config['status'] == 1:
        log.info('Successfully configured protocol interface for {0}'.format(port_handle))
    else:
        log.error("Failed to configure protocol interface for {0}".format(port_handle))
        self.failed()
    log.info('Value of ixia_interface_config is  {0}'.format(ixia_interface_config))
    return ixia_interface_config

def configureMultiIxNetworkInterface(self, intf_args, tg_hdl='', port_handle=''):
    log.info('Configuring {0} with parameters {1}'.format(port_handle,intf_args))
    arggrammar={}
    arggrammar['mode'] = '-type str'
    arggrammar['connected_count'] = '-type int'
    arggrammar['intf_ip_addr'] = '-type str'
    arggrammar['intf_ip_addr_step'] = '-type str'
    arggrammar['netmask'] = '-type str'
    arggrammar['gateway'] = '-type str'
    arggrammar['gateway_step'] = '-type str'
    arggrammar['ipv6_intf_addr'] = '-type str'
    arggrammar['ipv6_intf_addr_step'] = '-type str'
    arggrammar['ipv6_prefix_length'] = '-type str'
    arggrammar['ipv6_gateway'] = '-type str'
    arggrammar['ipv6_gateway_step'] = '-type str'
    arggrammar['vlan'] = '-type str'
    arggrammar['vlan_id'] = '-type str'
    arggrammar['vlan_id_step'] = '-type str'
    arggrammar['src_mac_addr'] = '-type str'
    arggrammar['mtu'] = '-type str'
    try:
        ns=parserutils_lib.argsToCommandOptions(intf_args,arggrammar,log)
    except Exception as e:
        return 0
    
    ip_addr_list = []
#    if_dict = OrderedDict()
    intf_hdl_list = []
    ixia_interface_config = tg_hdl.interface_config(port_handle = port_handle,mode=ns.mode,connected_count=ns.connected_count,intf_ip_addr=ns.intf_ip_addr,
                                                    intf_ip_addr_step=ns.intf_ip_addr_step,netmask=ns.netmask,gateway=ns.gateway,gateway_step=ns.gateway_step,
                                                    vlan=ns.vlan,vlan_id=ns.vlan_id,vlan_id_step=ns.vlan_id_step,arp_send_req = 0)
    for i in range(0,ns.connected_count):
        ip_addr_list.append(ipaddress.IPv4Address(ns.intf_ip_addr).exploded)
        ns.intf_ip_addr = ipaddress.IPv4Address(ns.intf_ip_addr) + int(ipaddress.IPv4Address(ns.intf_ip_addr_step))
         
    intf_hdl_list = ixia_interface_config.interface_handle.split( )
    

#     d={}
#     for x,y in enumerate(ip_addr_list):
#         d[y]={}
#         d[y]['handle']=intf_hdl_list[x]
         
#     if ns.vlan_id:
#         if_dict['ip_list'] = ip_addr_list
#         if_dict[ns.vlan_id] = {}
#         for i in ip_addr_list:
#             if_dict[ns.vlan_id][i] = {}
#             if_dict[ns.vlan_id][i]['handle'] = d[i]['handle']
 

    
    if ixia_interface_config['status'] == 1:
        log.info('Successfully configured protocol interface for {0}'.format(port_handle))
        res = dict(zip(ip_addr_list, intf_hdl_list))
    else:
        log.error("Failed to configure protocol interface for {0}".format(port_handle))
        self.failed()
    #return ixia_interface_config,ip_addr_list
    #return ixia_interface_config,if_dict
    return res


def configureMultiIxNetworkInterfaceWithV6(self, intf_args, tg_hdl='', port_handle=''):
    log.info('Configuring {0} with parameters {1}'.format(port_handle,intf_args))
    arggrammar={}
    arggrammar['mode'] = '-type str'
    arggrammar['connected_count'] = '-type int'
    arggrammar['intf_ip_addr'] = '-type str'
    arggrammar['intf_ip_addr_step'] = '-type str'
    arggrammar['netmask'] = '-type str'
    arggrammar['gateway'] = '-type str'
    arggrammar['gateway_step'] = '-type str'
    arggrammar['ipv6_intf_addr'] = '-type str'
    arggrammar['ipv6_intf_addr_step'] = '-type str'
    arggrammar['ipv6_prefix_length'] = '-type str'
    arggrammar['ipv6_gateway'] = '-type str'
    arggrammar['ipv6_gateway_step'] = '-type str'
    arggrammar['vlan'] = '-type str'
    arggrammar['vlan_id'] = '-type str'
    arggrammar['vlan_id_step'] = '-type str'
    arggrammar['src_mac_addr'] = '-type str'
    arggrammar['mtu'] = '-type str'
    try:
        ns=parserutils_lib.argsToCommandOptions(intf_args,arggrammar,log)
    except Exception as e:
        return 0
    
    ip_addr_list = []
    ipv6_addr_list = []
#    if_dict = OrderedDict()
    intf_hdl_list = []
    ixia_interface_config = tg_hdl.interface_config(port_handle = port_handle,mode=ns.mode,connected_count=ns.connected_count,intf_ip_addr=ns.intf_ip_addr,
                                                    intf_ip_addr_step=ns.intf_ip_addr_step,netmask=ns.netmask,gateway=ns.gateway,gateway_step=ns.gateway_step,
                                                    vlan=ns.vlan,vlan_id=ns.vlan_id,vlan_id_step=ns.vlan_id_step,arp_send_req = 0,ipv6_intf_addr=ns.ipv6_intf_addr,
                                                    ipv6_intf_addr_step=ns.ipv6_intf_addr_step,ipv6_prefix_length=ns.ipv6_prefix_length,ipv6_gateway=ns.ipv6_gateway,
                                                    ipv6_gateway_step=ns.ipv6_gateway_step)
    for i in range(0,ns.connected_count):
        ip_addr_list.append(ipaddress.IPv4Address(ns.intf_ip_addr).exploded)
        ipv6_addr_list.append(ipaddress.IPv6Address(ns.ipv6_intf_addr).exploded)
        ns.intf_ip_addr = ipaddress.IPv4Address(ns.intf_ip_addr) + int(ipaddress.IPv4Address(ns.intf_ip_addr_step))
        ns.ipv6_intf_addr = ipaddress.IPv6Address(ns.ipv6_intf_addr) + int(ipaddress.IPv6Address(ns.ipv6_intf_addr_step))
         
    intf_hdl_list = ixia_interface_config.interface_handle.split( )
    
    
    if ixia_interface_config['status'] == 1:
        res_dict = {}
        log.info('Successfully configured protocol interface for {0}'.format(port_handle))
        res_dict['ipv4'] = dict(zip(ip_addr_list, intf_hdl_list))
        res_dict['ipv6'] = dict(zip(ipv6_addr_list, intf_hdl_list))
    else:
        log.error("Failed to configure protocol interface for {0}".format(port_handle))
        self.failed()
    #return ixia_interface_config,ip_addr_list
    #return ixia_interface_config,if_dict
    return res_dict



def configureIgmpReports (self, intf_args, tg_hdl='', port_handle='', intf_handle='',**kwargs):
    log.info('Inside configureIgmpReports')
    log.info('Configuring Interfaces with port_handle {0} and with interface handle {1} and Following Interfaces parameters {2}'.format(port_handle, intf_handle,intf_args))
    arggrammar={}
    arggrammar['mode']='-type str'
    arggrammar['count']='-type str'
    arggrammar['group_query']='-type str'
    arggrammar['ip_router_alert']='-type str'
    arggrammar['igmp_version']='-type str'
    arggrammar['general_query']='-type str'
    arggrammar['num_groups']='-type str'
    arggrammar['ip_addr_start']='-type str'
    arggrammar['ip_addr_step']='-type str'
    #arggrammar['interface_handle']= intf_handle

    log.info('the value of kwargs here is : {0}'.format(kwargs))
    v3_specific_configs = kwargs
    
    try:
        ns=parserutils_lib.argsToCommandOptions(intf_args,arggrammar,log)
    except Exception as e:
        return 0
        
    ixia_emulation_igmp_config = tg_hdl.emulation_igmp_config(port_handle=port_handle,mode=ns.mode,count=ns.count,
                                                    group_query=ns.group_query,ip_router_alert=ns.ip_router_alert,
                                                    igmp_version=ns.igmp_version,interface_handle=intf_handle,general_query=ns.general_query)
    if ixia_emulation_igmp_config['status'] == 1:
        log.info('Successfully Emulated IGMP   for {0}'.format(port_handle))
        igmp_intf_hdl = ixia_emulation_igmp_config['handle']
        mcast_grp1 = tg_hdl.emulation_multicast_group_config(mode=ns.mode,num_groups=ns.num_groups,ip_addr_start=ns.ip_addr_start,ip_addr_step=ns.ip_addr_step)
        if mcast_grp1['status'] == 1:
            log.info('Successfully Emulated Multicast group configs Configs  for {0}'.format(port_handle))
            mcast_grp_hdl = mcast_grp1['handle']
            if kwargs:
                emulate_igmp_group_config = tg_hdl.emulation_igmp_group_config(mode=ns.mode,group_pool_handle=mcast_grp_hdl, session_handle=igmp_intf_hdl,
                                                                               g_filter_mode=v3_specific_configs['g_filter_mode'],source_pool_handle=v3_specific_configs['source_pool_handle'])
            else:
                emulate_igmp_group_config = tg_hdl.emulation_igmp_group_config(mode=ns.mode,group_pool_handle=mcast_grp_hdl, session_handle=igmp_intf_hdl)
            
            if emulate_igmp_group_config['status'] == 1:
                log.info('Successfully Configured IGMP reports  for {0}'.format(port_handle))
            else:
                log.info('Failed to configure IGMP reports  for {0}'.format(port_handle))
                self.failed()
        else:
            log.error("Failed to Emulated IGMP  for {0}".format(port_handle))
            self.failed()
    else:
        log.error("Failed to Emulated IGMP  for {0}".format(port_handle))
        self.failed()
    
    return emulate_igmp_group_config



def configureIxNetworkTraffic (self, traffic_args, tg_hdl='', emulation_src_handle='', emulation_dst_handle=''):
    log.info('Configuring traffic with parameters {0} for src {1} and dest {2}'.format(traffic_args, emulation_src_handle, emulation_dst_handle))
    arggrammar={}
    arggrammar['mode']='-type str'
    arggrammar['transmit_mode']='-type str'
    arggrammar['bidirectional']='-type str'
    arggrammar['name']='-type str'
    arggrammar['convert_to_raw']='-type str'
    arggrammar['l3_protocol']='-type str'
    arggrammar['rate_percent']='-type str'
    arggrammar['rate_pps']='-type str'
    arggrammar['rate_bps']='-type str'
    arggrammar['length_mode']='-type str'
    arggrammar['track_by']='-type str'
    arggrammar['src_dest_mesh']='-type str'
    arggrammar['circuit_endpoint_type']='-type str'
    arggrammar['frame_size']='-type str'
    try:
        ns=parserutils_lib.argsToCommandOptions(traffic_args,arggrammar,log)
    except Exception as e:
        return 0
    if ns.rate_percent != None and ns.rate_pps != None and ns.rate_bps != None:
        log.error("Please send only one out of rate_percent, rate_pps and rate_bps")
        self.failed()
    
    if ns.rate_percent != None:    
        ixia_traffic_config = tg_hdl.traffic_config(mode = ns.mode, emulation_src_handle = emulation_src_handle,
                                              emulation_dst_handle = emulation_dst_handle, transmit_mode = ns.transmit_mode, 
                                              bidirectional = ns.bidirectional, name = ns.name, convert_to_raw = ns.convert_to_raw,
                                              l3_protocol = ns.l3_protocol, rate_percent = ns.rate_percent,
                                              length_mode = ns.length_mode, track_by = ns.track_by, src_dest_mesh = ns.src_dest_mesh,
                                              circuit_endpoint_type = ns.circuit_endpoint_type, frame_size = ns.frame_size)
    if ns.rate_pps != None:
        ixia_traffic_config = tg_hdl.traffic_config(mode = ns.mode, emulation_src_handle = emulation_src_handle,
                                              emulation_dst_handle = emulation_dst_handle, transmit_mode = ns.transmit_mode,
                                              bidirectional = ns.bidirectional, name = ns.name, convert_to_raw = ns.convert_to_raw,
                                              l3_protocol = ns.l3_protocol, rate_pps = ns.rate_pps,
                                              length_mode = ns.length_mode, track_by = ns.track_by, src_dest_mesh = ns.src_dest_mesh,
                                              circuit_endpoint_type = ns.circuit_endpoint_type, frame_size = ns.frame_size)
    if ns.rate_bps != None:
        ixia_traffic_config = tg_hdl.traffic_config(mode = ns.mode, emulation_src_handle = emulation_src_handle,
                                              emulation_dst_handle = emulation_dst_handle, transmit_mode = ns.transmit_mode,
                                              bidirectional = ns.bidirectional, name = ns.name, convert_to_raw = ns.convert_to_raw,
                                              l3_protocol = ns.l3_protocol, rate_bps = ns.rate_bps,
                                              length_mode = ns.length_mode, track_by = ns.track_by, src_dest_mesh = ns.src_dest_mesh,
                                              circuit_endpoint_type = ns.circuit_endpoint_type, frame_size = ns.frame_size)
     
    if ixia_traffic_config['status'] == 1:
        log.info('Successfully created traffic')
    else:
        log.error("Failed to create traffic")
        self.failed()
    return ixia_traffic_config

def configureIxNetworkRawTraffic (mode='', port_handle='', port_handle2='',
                                  transmit_mode='', name='',
                                  convert_to_raw='1', l3_protocol='',
                                  rate_percent='', rate_pps='', rate_bps='', length_mode='',
                                  track_by='', circuit_endpoint_type='', frame_size='',
                                  mac_src='', mac_src_mode='', mac_src_step='',
                                  mac_src_count='', mac_dst='', mac_dst_mode='',
                                  mac_dst_step='', mac_dst_count = ''):
    if rate_percent != '' and rate_pps != '' and rate_bps != '':
        log.error("Please send only one out of rate_percent, rate_pps and rate_bps")
        self.failed()

    if rate_percent != '':
        ixia_traffic_config = ixia.traffic_config(mode = mode, port_handle = port_handle, port_handle2 = port_handle2,
                                              transmit_mode = transmit_mode, name = name, convert_to_raw = convert_to_raw,
                                              l3_protocol = l3_protocol, rate_percent = rate_percent, length_mode = length_mode,
                                              track_by = track_by, circuit_endpoint_type = circuit_endpoint_type, frame_size = frame_size,
                                              mac_src = mac_src, mac_src_mode = mac_src_mode, mac_src_step = mac_src_step,
                                              mac_src_count = mac_src_count, mac_dst = mac_dst, mac_dst_mode = mac_dst_mode,
                                              mac_dst_step = mac_dst_step, mac_dst_count = mac_dst_count)
    if rate_pps != '':
        ixia_traffic_config = ixia.traffic_config(mode = mode, port_handle = port_handle, port_handle2 = port_handle2,
                                              transmit_mode = transmit_mode, name = name, convert_to_raw = convert_to_raw,
                                              l3_protocol = l3_protocol, rate_pps = rate_pps, length_mode = length_mode,
                                              track_by = track_by, circuit_endpoint_type = circuit_endpoint_type, frame_size = frame_size,
                                              mac_src = mac_src, mac_src_mode = mac_src_mode, mac_src_step = mac_src_step,
                                              mac_src_count = mac_src_count, mac_dst = mac_dst, mac_dst_mode = mac_dst_mode,
                                              mac_dst_step = mac_dst_step, mac_dst_count = mac_dst_count)
    
    if rate_bps != '':
        ixia_traffic_config = ixia.traffic_config(mode = mode, port_handle = port_handle, port_handle2 = port_handle2,
                                              transmit_mode = transmit_mode, name = name, convert_to_raw = convert_to_raw,
                                              l3_protocol = l3_protocol, rate_bps = rate_bps, length_mode = length_mode,
                                              track_by = track_by, circuit_endpoint_type = circuit_endpoint_type, frame_size = frame_size,
                                              mac_src = mac_src, mac_src_mode = mac_src_mode, mac_src_step = mac_src_step,
                                              mac_src_count = mac_src_count, mac_dst = mac_dst, mac_dst_mode = mac_dst_mode,
                                              mac_dst_step = mac_dst_step, mac_dst_count = mac_dst_count)
    if ixia_traffic_config['status'] == '1':
        log.info('Successfully created traffic')
    else:
        log.error("Failed to create traffic")
        self.failed()
    return ixia_traffic_config    


def configureIxNetworkRawTrafficL2 (self, traffic_args, tg_hdl='', emulation_src_handle='', emulation_dst_handle=''):
    
    log.info('Configuring traffic with parameters {0} for src {1} and dest {2}'.format(traffic_args, emulation_src_handle, emulation_dst_handle))
    arggrammar={}
    arggrammar['mode']='-type str'
    arggrammar['circuit_type']='-type str'
    arggrammar['mac_dst']='-type str'
    arggrammar['mac_src']='-type str'
    arggrammar['mac_src_mode']='-type str'
    arggrammar['mac_src_step']='-type str'
    arggrammar['mac_src_count']='-type str'
    arggrammar['vlan']='-type str'
    arggrammar['vlan_id']='-type str'
    arggrammar['vlan_id_mode']='-type str'
    arggrammar['vlan_id_step']='-type str'
    arggrammar['vlan_id_count']='-type str' 
    arggrammar['track_by']='-type str'
    arggrammar['transmit_mode']='-type str'
    arggrammar['name']='-type str'
    arggrammar['rate_pps']='-type str'
    arggrammar['frame_size'] = '-type str'
    
    try:
        ns=parserutils_lib.argsToCommandOptions(traffic_args,arggrammar,log)
    except Exception as e:
        return 0
    if ns.rate_pps != '':
        ixia_traffic_config = tg_hdl.traffic_config(mode = ns.mode, emulation_src_handle = emulation_src_handle, emulation_dst_handle = emulation_dst_handle,
                                              circuit_type = ns.circuit_type, mac_dst = ns.mac_dst, mac_src = ns.mac_src, mac_src_mode = ns.mac_src_mode, mac_src_step = ns.mac_src_step, 
                                              mac_src_count = ns.mac_src_count, vlan = ns.vlan, vlan_id = ns.vlan_id, vlan_id_mode = ns.vlan_id_mode, vlan_id_step = ns.vlan_id_step, 
                                              vlan_id_count = ns.vlan_id_count, track_by = ns.track_by, transmit_mode = ns.transmit_mode, name = ns.name, rate_pps = ns.rate_pps,frame_size = ns.frame_size)
    if ixia_traffic_config['status'] == 1:
        log.info('Successfully created traffic')
    else:
        log.error("Failed to create traffic")
        self.failed()
    return ixia_traffic_config    


def configureIxNetworkRawTrafficL3New(self, traffic_args, tg_hdl='', emulation_src_handle='', emulation_dst_handle=''):
    
    log.info('configureIxNetworkRawTrafficL3New : Configuring traffic with parameters {0} for src {1} and dest {2}'.format(traffic_args, emulation_src_handle, emulation_dst_handle))
    arggrammar={}
    arggrammar['mode']='-type str'
    arggrammar['circuit_type']='-type str'
    arggrammar['mac_dst']='-type str'
    arggrammar['mac_src']='-type str'
    arggrammar['mac_src_mode']='-type str'
    arggrammar['mac_src_step']='-type str'
    arggrammar['mac_src_count']='-type str'
    arggrammar['vlan']='-type str'
    arggrammar['vlan_id']='-type str'
    arggrammar['vlan_id_mode']='-type str'
    arggrammar['vlan_id_step']='-type str'
    arggrammar['vlan_id_count']='-type str' 
    arggrammar['track_by']='-type str'
    arggrammar['transmit_mode']='-type str'
    arggrammar['name']='-type str'
    arggrammar['rate_pps']='-type str'
    arggrammar['frame_size'] = '-type str'
    arggrammar['l3_protocol'] = '-type str'
    arggrammar['ip_src_addr'] = '-type str'
    arggrammar['ip_dst_addr'] = '-type str'
    arggrammar['ip_dst_mode'] = '-type str'
    arggrammar['ip_dst_count'] = '-type str'
    arggrammar['ip_dst_step'] = '-type str'
    
    try:
        ns=parserutils_lib.argsToCommandOptions(traffic_args,arggrammar,log)
        log.info('The value of ns is : {0}'.format(ns))
    except Exception as e:
        return 0
    if ns.rate_pps != '':
        ixia_traffic_config = tg_hdl.traffic_config(mode = ns.mode, emulation_src_handle = emulation_src_handle, emulation_dst_handle = emulation_dst_handle,
                                              circuit_type = ns.circuit_type, mac_dst = ns.mac_dst, mac_src = ns.mac_src, mac_src_mode = ns.mac_src_mode, mac_src_step = ns.mac_src_step, 
                                              mac_src_count = ns.mac_src_count, vlan = ns.vlan, vlan_id = ns.vlan_id, vlan_id_mode = ns.vlan_id_mode, vlan_id_step = ns.vlan_id_step, 
                                              vlan_id_count = ns.vlan_id_count, track_by = ns.track_by, transmit_mode = ns.transmit_mode, name = ns.name, rate_pps = ns.rate_pps,
                                              frame_size = ns.frame_size,l3_protocol=ns.l3_protocol,ip_src_addr=ns.ip_src_addr,ip_dst_addr=ns.ip_dst_addr,ip_dst_mode=ns.ip_dst_mode,
                                              ip_dst_count=ns.ip_dst_count,ip_dst_step = ns.ip_dst_step)
    if ixia_traffic_config['status'] == 1:
        log.info('Successfully created traffic')
    else:
        log.error("Failed to create traffic")
        self.failed()
    return ixia_traffic_config    

def configureIxNetworkRawTrafficL3 (self, traffic_args, tg_hdl='', emulation_src_handle='', emulation_dst_handle=''):
    
    log.info('Configuring traffic with parameters {0} for src {1} and dest {2}'.format(traffic_args, emulation_src_handle, emulation_dst_handle))
    arggrammar={}
    arggrammar['mode']='-type str'
    arggrammar['circuit_type']='-type str'
    arggrammar['mac_dst']='-type str'
    arggrammar['mac_src']='-type str'
    arggrammar['mac_src_mode']='-type str'
    arggrammar['mac_src_step']='-type str'
    arggrammar['mac_src_count']='-type str'
    arggrammar['vlan']='-type str'
    arggrammar['vlan_id']='-type str'
    arggrammar['vlan_id_mode']='-type str'
    arggrammar['vlan_id_step']='-type str'
    arggrammar['vlan_id_count']='-type str' 
    arggrammar['track_by']='-type str'
    arggrammar['transmit_mode']='-type str'
    arggrammar['name']='-type str'
    arggrammar['rate_pps']='-type str'
    arggrammar['frame_size'] = '-type str'
    
    try:
        ns=parserutils_lib.argsToCommandOptions(traffic_args,arggrammar,log)
    except Exception as e:
        return 0
    if ns.rate_pps != '':
        ixia_traffic_config = tg_hdl.traffic_config(mode = ns.mode, emulation_src_handle = emulation_src_handle, emulation_dst_handle = emulation_dst_handle,
                                              circuit_type = ns.circuit_type, mac_dst = ns.mac_dst, mac_src = ns.mac_src, mac_src_mode = ns.mac_src_mode, mac_src_step = ns.mac_src_step, 
                                              mac_src_count = ns.mac_src_count, vlan = ns.vlan, vlan_id = ns.vlan_id, vlan_id_mode = ns.vlan_id_mode, vlan_id_step = ns.vlan_id_step, 
                                              vlan_id_count = ns.vlan_id_count, track_by = ns.track_by, transmit_mode = ns.transmit_mode, name = ns.name, rate_pps = ns.rate_pps,frame_size = ns.frame_size)
    if ixia_traffic_config['status'] == 1:
        log.info('Successfully created traffic')
    else:
        log.error("Failed to create traffic")
        self.failed()
    return ixia_traffic_config    


def modifyIxNetworkRawTraffic (mode='', stream_id = '', port_handle='', port_handle2='',
                                  transmit_mode='', name='',
                                  convert_to_raw='1', l3_protocol='',
                                  rate_percent='', rate_pps='', rate_bps='', length_mode='',
                                  track_by='', circuit_endpoint_type='', frame_size='',
                                  mac_src='', mac_src_mode='', mac_src_step='',
                                  mac_src_count='', mac_dst='', mac_dst_mode='',
                                  mac_dst_step='', mac_dst_count = ''):
    if rate_percent != '' and rate_pps != '' and rate_bps != '':
        log.error("Please send only one out of rate_percent, rate_pps and rate_bps")
        self.failed()

    if rate_percent != '':
        ixia_traffic_config = ixia.traffic_config(mode = mode, stream_id = stream_id, port_handle = port_handle, port_handle2 = port_handle2,
                                              transmit_mode = transmit_mode, name = name, convert_to_raw = convert_to_raw,
                                              l3_protocol = l3_protocol, rate_percent = rate_percent, length_mode = length_mode,
                                              track_by = track_by, circuit_endpoint_type = circuit_endpoint_type, frame_size = frame_size,
                                              mac_src = mac_src, mac_src_mode = mac_src_mode, mac_src_step = mac_src_step,
                                              mac_src_count = mac_src_count, mac_dst = mac_dst, mac_dst_mode = mac_dst_mode,
                                              mac_dst_step = mac_dst_step, mac_dst_count = mac_dst_count)
    if rate_pps != '':
        ixia_traffic_config = ixia.traffic_config(mode = mode, stream_id = stream_id, port_handle = port_handle, port_handle2 = port_handle2,
                                              transmit_mode = transmit_mode, name = name, convert_to_raw = convert_to_raw,
                                              l3_protocol = l3_protocol, rate_pps = rate_pps, length_mode = length_mode,
                                              track_by = track_by, circuit_endpoint_type = circuit_endpoint_type, frame_size = frame_size,
                                              mac_src = mac_src, mac_src_mode = mac_src_mode, mac_src_step = mac_src_step,
                                              mac_src_count = mac_src_count, mac_dst = mac_dst, mac_dst_mode = mac_dst_mode,
                                              mac_dst_step = mac_dst_step, mac_dst_count = mac_dst_count)

    if rate_bps != '':
        ixia_traffic_config = ixia.traffic_config(mode = mode, stream_id = stream_id, port_handle = port_handle, port_handle2 = port_handle2,
                                              transmit_mode = transmit_mode, name = name, convert_to_raw = convert_to_raw,
                                              l3_protocol = l3_protocol, rate_bps = rate_bps, length_mode = length_mode,
                                              track_by = track_by, circuit_endpoint_type = circuit_endpoint_type, frame_size = frame_size,
                                              mac_src = mac_src, mac_src_mode = mac_src_mode, mac_src_step = mac_src_step,
                                              mac_src_count = mac_src_count, mac_dst = mac_dst, mac_dst_mode = mac_dst_mode,
                                              mac_dst_step = mac_dst_step, mac_dst_count = mac_dst_count)

    if ixia_traffic_config['status'] == '1':
        log.info('Successfully modified traffic')
    else:
        log.error("Failed to modify traffic")
        self.failed()
    return ixia_traffic_config



def configureBgpRouter (self, bgp_args, tg_hdl='', port_handle='', intf_handle=''):
    log.info('Inside configureBgpRouter')
    log.info('Configuring BGP router with port_handle {0} and with interface handle {1} and following parameters {2}'.format(port_handle, intf_handle, bgp_args))
    arggrammar={}
    arggrammar['mode']='-type str'
    arggrammar['ipv4_mpls_vpn_nlri']='-type str -default 1'
    arggrammar['ipv4_multicast_nlri']='-type str -default 1'
    arggrammar['ipv4_unicast_nlri']='-type str -default 1'
    arggrammar['ipv6_mpls_nlri']='-type str -default 1'
    arggrammar['ipv6_mpls_vpn_nlri']='-type str -default 1'
    arggrammar['ipv6_multicast_nlri']='-type str -default 1'
    arggrammar['ipv6_unicast_nlri']='-type str -default 1'
    arggrammar['ipv4_mpls_nlri']='-type str -default 1'
    arggrammar['ip_version']='-type str'
    arggrammar['remote_ip_addr']='-type str'
    arggrammar['neighbor_type']='-type str'
    arggrammar['local_as']='-type str'
    arggrammar['hold_time']='-type str'
    arggrammar['update_interval']='-type str'
    arggrammar['ttl_value']='-type str'
    arggrammar['enable_4_byte_as']='-type str'
    arggrammar['graceful_restart_enable']='-type str'
    arggrammar['restart_time']='-type str'
    arggrammar['stale_time']='-type str'
    arggrammar['active_connect_enable']='-type str'
    arggrammar['md5_enable']='-type str'
    arggrammar['md5_key']='-type str'
    try:
        ns=parserutils_lib.argsToCommandOptions(bgp_args,arggrammar,log)
    except Exception as e:
        return 0

    ixia_emulation_bgp_config = tg_hdl.emulation_bgp_config(
                                    mode = ns.mode,
                                    port_handle = port_handle,
                                    ipv4_mpls_vpn_nlri = ns.ipv4_mpls_vpn_nlri,
                                    ipv4_multicast_nlri = ns.ipv4_multicast_nlri,
                                    ipv4_unicast_nlri = ns.ipv4_unicast_nlri,
                                    ipv6_mpls_nlri = ns.ipv6_mpls_nlri,
                                    ipv6_mpls_vpn_nlri = ns.ipv6_mpls_vpn_nlri,
                                    ipv6_multicast_nlri = ns.ipv6_multicast_nlri,
                                    ipv6_unicast_nlri = ns.ipv6_unicast_nlri,
                                    ipv4_mpls_nlri = ns.ipv4_mpls_nlri,
                                    ip_version = ns.ip_version,
                                    interface_handle = intf_handle,
                                    remote_ip_addr = ns.remote_ip_addr,
                                    neighbor_type = ns.neighbor_type,
                                    local_as = ns.local_as,
                                    hold_time = ns.hold_time,
                                    update_interval = ns.update_interval,
                                    ttl_value = ns.ttl_value,
                                    enable_4_byte_as = ns.enable_4_byte_as,
                                    graceful_restart_enable = ns.graceful_restart_enable,
                                    restart_time = ns.restart_time,
                                    stale_time = ns.stale_time,
                                    active_connect_enable = ns.active_connect_enable,
                                    md5_enable = ns.md5_enable,
                                    md5_key = ns.md5_key)
    if ixia_emulation_bgp_config['status'] == 1:
        log.info('Successfully Emulated BGP for {0}'.format(port_handle))
    else:
        log.error("Failed to Emulated BGP  for {0}".format(port_handle))
        testscript.parameters['fail_flag'] = 1
        self.failed()

    return ixia_emulation_bgp_config





def configureBgpRoutes (self, route_args, tg_hdl='', bgp_router_hdl=''):
    log.info('Configuring BGP Routes in router {0}'.format(bgp_router_hdl))
    arggrammar={}
    arggrammar['mode']='-type str'
    arggrammar['num_sites']='-type str -default 1'
    arggrammar['origin_route_enable']='-type str -default 1'
    arggrammar['originator_id_enable']='-type str -default 0'
    arggrammar['enable_traditional_nlri']='-type str -default 1'
    arggrammar['end_of_rib']='-type str -default 0'
    arggrammar['packing_from']='-type str -default 0'
    arggrammar['prefix_from']='-type str'
    arggrammar['ip_version']='-type str'
    arggrammar['next_hop_enable']='-type str -default 1'
    arggrammar['prefix_step']='-type str'
    arggrammar['prefix']='-type str'
    arggrammar['next_hop']='-type str -default 0.0.0.0'
    arggrammar['next_hop_mode']='-type str -default increment'
    arggrammar['next_hop_set_mode']='-type str -default same'
    arggrammar['num_routes']='-type str'
    arggrammar['origin']='-type str -default igp'
    arggrammar['originator_id']='-type str -default 0.0.0.0'
    arggrammar['packing_to']='-type str -default 0'
    arggrammar['prefix_to']='-type str'
    arggrammar['enable_local_pref']='-type str -default 1'
    arggrammar['as_path_set_mode']='-type str -default include_as_seq'
    arggrammar['enable_as_path']='-type str -default 1'
    arggrammar['as_path']='-type str'
    
    try:
        ns=parserutils_lib.argsToCommandOptions(route_args,arggrammar,log)
    except Exception as e:
        return 0
    emulate_bgp_route_config = tg_hdl.emulation_bgp_route_config(
                                   mode=ns.mode,
                                   handle = bgp_router_hdl,
                                   num_sites = ns.num_sites,
                                   origin_route_enable = ns.origin_route_enable,
                                   originator_id_enable = ns.originator_id_enable,
                                   enable_traditional_nlri = ns.enable_traditional_nlri,
                                   end_of_rib = ns.end_of_rib,
                                   packing_from = ns.packing_from,
                                   prefix_from = ns.prefix_from,
                                   ip_version = ns.ip_version,
                                   next_hop_enable = ns.next_hop_enable,
                                   prefix_step = ns.prefix_step,
                                   prefix = ns.prefix,
                                   next_hop = ns.next_hop,
                                   next_hop_mode = ns.next_hop_mode,
                                   next_hop_set_mode = ns.next_hop_set_mode,
                                   num_routes = ns.num_routes,
                                   origin = ns.origin,
                                   originator_id = ns.originator_id,
                                   packing_to = ns.packing_to,
                                   prefix_to = ns.prefix_to,
                                   enable_local_pref = ns.enable_local_pref,
                                   as_path_set_mode = ns.as_path_set_mode,
                                   enable_as_path = ns.enable_as_path,
                                   as_path = ns.as_path)
    if emulate_bgp_route_config['status'] == 1:
        log.info('Successfully Configured BGP routes for {0}'.format(bgp_router_hdl))
    else:
        log.info('Failed to configure BGP routes for {0}'.format(bgp_router_hdl))
        testscript.parameters['fail_flag'] = 1
        self.failed()
    
    return emulate_bgp_route_config

def startBgpProtocol(self,tg_hdl='', mode = '', handle=''):
    log.info('Inside Start BGP Protocol')
    bgp_protocol_state = tg_hdl.emulation_bgp_control(mode = mode, handle = handle)
    if bgp_protocol_state['status'] == 1:
        log.info('Successfully Started BGP Protocol')
    else:
        log.error('Failed to start BGP Protocol')
        self.failed()
    return bgp_protocol_state

        
def startStopIxNetworkTraffic (self, tg_hdl='', action='',  port_handle=''):
    ixia_traffic_control = tg_hdl.traffic_control(action = action, port_handle = port_handle)
    if ixia_traffic_control['status'] == 1:
        log.info('Successfully started traffic')
    else:
        log.error("Failed to start traffic")
        self.failed()
    return ixia_traffic_control

def statsIxNetworkTraffic (port_handle=''):
    if port_handle == '':
        ixia_traffic_stats = ixia.traffic_stats()
    else:
        ixia_traffic_stats = ixia.traffic_stats(port_handle = port_handle)
    if ixia_traffic_stats['status'] == '1':
        log.info('Successfully fetched Ixia traffic stats')
    else:
        log.error("Failed to fetch Ixia traffic stats")
        self.failed()
    return ixia_traffic_stats

def cleanIxNetwork (self, tg_hdl='', port_handle='', reset=''):
    ixia_cleanup_session = tg_hdl.cleanup_session(port_handle = port_handle, reset = reset)
    if ixia_cleanup_session['status'] == 1:
        log.info('Successfully cleaned up Ixia')
    else:
        log.error("Failed to clean Ixia")
        self.failed()
    return ixia_cleanup_session




