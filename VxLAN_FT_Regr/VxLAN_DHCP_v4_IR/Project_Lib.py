#!/usr/bin/env python

# python
import logging
import unittest
from unittest.mock import Mock
from randmac import RandMac
import macaddress
            
import time
import os
from IxNetwork import IxNet

# Genie package
from genie.tests.conf import TestCase
from genie.conf import Genie
from genie.conf.base import Testbed, Device, Link, Interface

# xBU-shared genie pacakge
from genie.libs.conf.interface import TunnelTeInterface
from genie.libs.conf.base import MAC, IPv4Interface, IPv4Interface, IPv4Address, IPv4Address
from genie.libs.conf.interface import Layer, L2_type, IPv4Addr, IPv4Addr,NveInterface
from genie.libs.conf.vrf import Vrf
from genie.libs.conf.interface.nxos import Interface
from genie.conf.base.attributes import UnsupportedAttributeWarning
from netaddr.ip import IPNetwork, IPAddress

# Vpc
from genie.libs.conf.vpc import Vpc
from genie.libs.conf.interface.nxos import LoopbackInterface
from genie.libs.conf.interface.nxos import SubInterface
from genie.libs.conf.ospf import Ospf

logger = logging.getLogger(__name__)

log = logging.getLogger(__name__)
log.setLevel(logging.DEBUG)

# import genie.libs
from genie.libs.conf.bgp import Bgp
import time
from ipaddress import *   
from ixiaPyats_lib import *

from ixiatcl import IxiaTcl
from ixiahlt import IxiaHlt
from ixiangpf import IxiaNgpf
from ixiaerror import IxiaError
import ixiaPyats_lib
ixiatcl = IxiaTcl()
ixiahlt = IxiaHlt(ixiatcl)
ixiangpf = IxiaNgpf(ixiahlt)

import random

import ixiaPyats_lib

from Project_Conf import *
import sys
import os
try:
	ixnHLT_errorHandler('', {})
except (NameError,):
	def ixnHLT_errorHandler(cmd, retval):
		global ixiatcl
		err = ixiatcl.tcl_error_info()
		log = retval['log']
		additional_info = '> command: %s\n> tcl errorInfo: %s\n> log: %s' % (cmd, err, log)
		raise IxiaError(IxiaError.COMMAND_FAIL, additional_info)


def dhcpServerSetup(srv_port_hdl):
    serv_topology_status = createTopo(srv_port_hdl,1)
    srv_deviceGroup_handle = serv_topology_status['device_group_handle']
    topo_handle = serv_topology_status['topology_handle']
    dhcp_status = dhcpServerConf(srv_deviceGroup_handle,1)
    dhcp_server = dhcp_status['dhcpv4server_handle']
    dhcpServerControll(dhcp_server,'collect') 
    countdown(10) 
    return(dhcp_server,srv_deviceGroup_handle,topo_handle)


def dhcpRelayServerSetup(srv_port_hdl, vtep):
    dhcpServerRelay(vtep)
    serv_topology_status = createTopo(srv_port_hdl,1)
    srv_deviceGroup_handle = serv_topology_status['device_group_handle']
    topo_handle = serv_topology_status['topology_handle']
    dhcp_status = dhcpRelayServerConf(srv_deviceGroup_handle,1)
    dhcp_server = dhcp_status['dhcpv4server_handle']
    dhcpServerControll(dhcp_server,'collect') 
    countdown(10) 
    return(dhcp_server,srv_deviceGroup_handle,topo_handle)


def dhcpRelayServerSetupSymm(srv_port_hdl, vtep):
    dhcpServerRelaySymm(vtep)
    serv_topology_status = createTopo(srv_port_hdl,1)
    srv_deviceGroup_handle = serv_topology_status['device_group_handle']
    topo_handle = serv_topology_status['topology_handle']
    dhcp_status = dhcpRelayServerConf(srv_deviceGroup_handle,1)
    dhcp_server = dhcp_status['dhcpv4server_handle']
    dhcpServerControll(dhcp_server,'collect') 
    countdown(10) 
    return(dhcp_server,srv_deviceGroup_handle,topo_handle)


def dhcpRelayServerSetupAsymm(srv_port_hdl, vtep):
    dhcpServerRelayAsymm(vtep)
    serv_topology_status = createTopo(srv_port_hdl,1)
    srv_deviceGroup_handle = serv_topology_status['device_group_handle']
    topo_handle = serv_topology_status['topology_handle']
    dhcp_status = dhcpRelayServerConf(srv_deviceGroup_handle,1)
    dhcp_server = dhcp_status['dhcpv4server_handle']
    dhcpServerControll(dhcp_server,'collect') 
    countdown(10) 
    return(dhcp_server,srv_deviceGroup_handle,topo_handle)


def dhcpRelayServerSetupAsymmDiff(srv_port_hdl, vtep):
    dhcpServerRelayAsymmDiff(vtep)
    serv_topology_status = createTopo(srv_port_hdl,1)
    srv_deviceGroup_handle = serv_topology_status['device_group_handle']
    topo_handle = serv_topology_status['topology_handle']
    dhcp_status = dhcpRelayServerConf(srv_deviceGroup_handle,1)
    dhcp_server = dhcp_status['dhcpv4server_handle']
    dhcpServerControll(dhcp_server,'collect') 
    countdown(10) 
    return(dhcp_server,srv_deviceGroup_handle,topo_handle)

    
def dhcpClientSetup(client_port_hdl,mac_start):
    client_topology_status = createTopo(client_port_hdl,1)
    client_deviceGroup_handle = client_topology_status['device_group_handle']
    client_topo_handle = client_topology_status['topology_handle']
    dhcp_client_status = configure_dhcpclient(client_deviceGroup_handle,client_port_hdl,10,mac_start)
    dhcp_client = dhcp_client_status['dhcpv4client_handle']
    dhcpClientControll(dhcp_client,'bind')
    countdown(10)
    return(client_topology_status,dhcp_client,client_topo_handle)


def getDhcpServerstats(port_handle,dhcp_server):
    # print "Retrieve statistics"
    dhcp_stats_0 = ixiangpf.emulation_dhcp_server_stats(
        port_handle   = port_handle	                                           ,
        action 	= 'collect'				                                   ,
        execution_timeout = '60'                                              ,
    )
    if dhcp_stats_0['status'] != IxiaHlt.SUCCESS:
        ixnHLT_errorHandler('emulation_dhcp_server_stats', dhcp_stats_0)

    # print "\n\nDHCP Server aggregate statistics:\n\n"
    log.info(dhcp_stats_0)

    dhcp_stats_0 = ixiangpf.emulation_dhcp_server_stats(
        dhcp_handle   = dhcp_server	                                           ,
        action =	'collect'				                                       ,
        execution_timeout = '60'                                                  ,
    )
    if dhcp_stats_0['status'] != IxiaHlt.SUCCESS:
        ixnHLT_errorHandler('emulation_dhcp_server_stats', dhcp_stats_0)

    # print "\n\nDHCP Server per session statistics:\n\n"
    log.info(dhcp_stats_0)


def checkClientBindingStatsIxia(port_handle):
    client_stats = getDhcpClientstats(port_handle)
    if not client_stats['aggregate']['success_percentage'] == str(100):
        countdown(30)
        if not client_stats['aggregate']['success_percentage'] == str(100):
            return 0
    return 1


def getDhcpClientstats(port_handle):

    dhcp_stats_0 = ixiangpf.emulation_dhcp_stats(
            port_handle  = port_handle	                                    ,
            mode         = 'aggregate_stats'					            ,
            dhcp_version =	'dhcp4'				                        ,
            execution_timeout = '60'                                       ,
    )
    if dhcp_stats_0['status'] != IxiaHlt.SUCCESS:
        ixnHLT_errorHandler('emulation_dhcp_stats', dhcp_stats_0)

    # print "\n\nDHCP Client aggregate statistics:\n\n"
    log.info(dhcp_stats_0)
    return dhcp_stats_0


def getDhcpClientstats2(port_handle,dhcp_client):
    dhcp_stats_0 = ixiangpf.emulation_dhcp_stats(
        handle  = dhcp_client	                                        ,
        mode     =     'aggregate_stats'					                ,
        dhcp_version =	'dhcp4'				                            ,
        execution_timeout = '60'                                           ,
    )
    if dhcp_stats_0['status'] != IxiaHlt.SUCCESS:
        ixnHLT_errorHandler('emulation_dhcp_stats', dhcp_stats_0)

    # print "\n\nDHCP Client aggregate statistics:\n\n"
    log.info(dhcp_stats_0)

    dhcp_stats_0 = ixiangpf.emulation_dhcp_stats(
            handle   = dhcp_client	                                    ,
            mode       =    'session'					                    ,
            dhcp_version  =	'dhcp4'				                        ,
            execution_timeout  = '60'                                       ,
    )
    if dhcp_stats_0['status'] != IxiaHlt.SUCCESS:
        ixnHLT_errorHandler('emulation_dhcp_stats', dhcp_stats_0)

    # print "\n\nDHCP Client per session statistics:\n\n"
    log.info(dhcp_stats_0)


def IxiaConnect(client_port_list):
    
    ixia_port_list =  " "

    for port in client_port_list:
         ixia_port_list = ixia_port_list+" "+port
         
    ixia_chassis_ip = '10.104.102.68'
    ixia_tcl_server = '10.104.102.238'
    ixia_tcl_port = '8009'
 
    connect_status = ixiangpf.connect(
        reset                  = 1,
        device                 = ixia_chassis_ip,
        port_list              = ixia_port_list,
        ixnetwork_tcl_server   = ixia_tcl_server,
        tcl_server             = ixia_chassis_ip,
    )
    if connect_status['status'] != IxiaHlt.SUCCESS:
        ixnHLT_errorHandler('connect', connect_status)

    port_handle = connect_status['vport_list']
    return (port_handle)


def IxiaReset():
    ixiangpf.cleanup_session(reset='1')


def createTopo(port_hdl,scale):
    topology_status = ixiangpf.topology_config(
        topology_name            =	port_hdl,
        port_handle              =	port_hdl,
        device_group_multiplier  =	scale,
    )
    if topology_status['status'] != IxiaHlt.SUCCESS:
        ixnHLT_errorHandler('topology_config', topology_status)
    return (topology_status)  


def dhcpServerConf(group_handle,scale):    

    dhcp_status = ixiangpf.emulation_dhcp_server_config(
        dhcp_offer_router_address              = "100.1.0.1",
        handle                                 = group_handle,
        ip_dns1                                = "0.0.0.0",
        ip_dns2                                = "0.0.0.0",
        ip_version                             = "4",
        ip_address		                       = '4.5.0.9',
        ip_step		                           = '0.0.0.0',
        ip_gateway		                       = '4.5.0.1',
        ipaddress_count                        = '2000',
        ipaddress_pool                         = "4.5.0.10",
        ipaddress_pool_prefix_length           = "16",
        ipaddress_pool_prefix_inside_step      = "0",
        lease_time                             = "86400",
        mode                                   = "create",
        protocol_name                          = """DHCPv4 Server 1""",
        use_rapid_commit                       = "0",
        echo_relay_info                        = "1",
        enable_vss_addr_assgnmt                = "0",
        vpn_id                                 = "00000000000000",
        vpn_name                               = "ixiacom",
        enable_ignore_opt                      = "0",
        ignore_opt                             = "152",
        pool_address_increment                 = "0.0.0.1",
        pool_count                             = "1",
        subnet_addr_assign                     = "0",
        subnet                                 = "relay",

    )
    if dhcp_status['status'] != IxiaHlt.SUCCESS:
        ixnHLT_errorHandler('emulation_dhcp_server_config', dhcp_status)

    return(dhcp_status)


def dhcpRelayServerConf(group_handle,scale):    

    dhcp_status = ixiangpf.emulation_dhcp_server_config(
        dhcp_offer_router_address              = "4.20.0.1",
        handle                                 = group_handle,
        ip_address		                       = '4.5.0.9',
        ip_step		                           = '0.0.0.0',
        ip_gateway		                       = '4.5.0.1',
        ip_dns1                                = "0.0.0.0",
        ip_dns2                                = "0.0.0.0",
        ip_version                             = "4",
        ipaddress_count                        = "2000",
        ipaddress_pool                         = "4.20.0.10",
        ipaddress_pool_prefix_length           = "16",
        ipaddress_pool_prefix_inside_step      = "0",
        lease_time                             = "86400",
        mode                                   = "create",
        protocol_name                          = """DHCPv4 Server 1""",
        use_rapid_commit                       = "0",
        echo_relay_info                        = "1",
        enable_vss_addr_assgnmt                = "0",
        vpn_id                                 = "00000000000000",
        vpn_name                               = "ixiacom",
        enable_ignore_opt                      = "0",
        ignore_opt                             = "152",
        pool_address_increment                 = "0.0.0.1",
        pool_count                             = "1",
        subnet_addr_assign                     = "1",
        subnet                                 = "link_selection",
    )
    if dhcp_status['status'] != IxiaHlt.SUCCESS:
        ixnHLT_errorHandler('emulation_dhcp_server_config', dhcp_status)

    return(dhcp_status)


def dhcpServerControll(dhcp_server,action):  
    # print "Starting dhcp server...."
    control_status = ixiangpf.emulation_dhcp_server_control(
        dhcp_handle = 			dhcp_server 		                           ,
        action = action								                           ,
    )
    if control_status['status'] != IxiaHlt.SUCCESS:
        ixnHLT_errorHandler('emulation_dhcp_server_control', control_status)

    time.sleep(10)


def configure_dhcpclient(client_deviceGroup_handle,client_port_hdl,scale,mac_start):   
    client_topo_list = []
    
    dhcp_client_status = ixiangpf.emulation_dhcp_group_config(
            handle                         = client_deviceGroup_handle,
            protocol_name 		           = "Dhcp_client"+client_port_hdl,
            mac_addr                       = mac_start,
            mac_addr_step		           = '00.00.00.00.00.02',
            enable_stateless               = '0',
            num_sessions                   = scale,
            vlan_id		                   = "0",
            vlan_id_step		           = '0',
            dhcp_range_use_first_server    = '1',
            dhcp_range_renew_timer         = '20000',
            dhcp_range_ip_type             = 'ipv4',
            vendor_id                      = 'any',
    )

    if dhcp_client_status['status'] != IxiaHlt.SUCCESS:
        ixnHLT_errorHandler('emulation_dhcp_group_config', dhcp_status)
    
    return(dhcp_client_status)

    dhcp_client = dhcp_status['dhcpv4client_handle']


def dhcpClientControll(dhcp_client,action):  

    control_status = ixiangpf.emulation_dhcp_control(
        handle 			=	dhcp_client                            ,
        action = action						                            ,
    )
    if control_status['status'] != IxiaHlt.SUCCESS:
        ixnHLT_errorHandler('emulation_dhcp_control', control_status)

    time.sleep(20)


def dhcpClientTrafficl(src_handle,dst_handle):          
    countdown(30) 
    rate_pps = 10000
    frame_size = 500

    print("Configuring L2-L3 traffic")
    _result_ = ixiangpf.traffic_config(
        mode='create',
        endpointset_count='1',
        emulation_src_handle=src_handle,
        emulation_dst_handle=dst_handle,
        name='Traffic_1_Item',
        circuit_endpoint_type='ipv4',
        rate_pps=rate_pps,
        frame_size=frame_size,
        mac_dst_mode='fixed',
        mac_src_mode='fixed',
        track_by='trackingenabled0',
    )

    if _result_['status'] != IxiaHlt.SUCCESS:
        trafficItem_handle = 0
        ErrorHandler('traffic_config', _result_)
    else:
        trafficItem_handle = _result_["stream_id"]
    
    return trafficItem_handle


def trafficControll(action):    

    print("Running traffic")
    result = 1
    run_traffic = ixiangpf.traffic_control(
        action = action,
        traffic_generator='ixnetwork_540',
        max_wait_timer='60',
    )

    if run_traffic['status'] != IxiaHlt.SUCCESS:
        result = 0
        ErrorHandler('test_control', run_traffic)

    return result
 
 
def getTrafficStats():   

    protostats = ixiangpf.traffic_stats (
    mode = 'all',
    traffic_generator = 'ixnetwork_540',
    measure_mode = 'mixed'
    )

    return protostats