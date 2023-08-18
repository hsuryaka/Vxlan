#!/bin/env python
##################################################################
# This file contains Ixia specific proc like interface creation, #
# traffic creation, protocol config in Ixia, etc.                #  
##################################################################

import logging
import parserutils_lib
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
    
    try:
        ns=parserutils_lib.argsToCommandOptions(intf_args,arggrammar,log)
    except Exception as e:
        return 0
        
    ixia_interface_config = tg_hdl.interface_config(port_handle=port_handle,mode=ns.mode,intf_ip_addr=ns.intf_ip_addr,
                                                    netmask=ns.netmask,gateway=ns.gateway,vlan=ns.vlan,vlan_id=ns.vlan_id,
                                                    arp_send_req = ns.arp_send_req,src_mac_addr = ns.src_mac_addr)
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
                                                    vlan=ns.vlan,vlan_id=ns.vlan_id,vlan_id_step=ns.vlan_id_step,arp_send_req = 1)
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


