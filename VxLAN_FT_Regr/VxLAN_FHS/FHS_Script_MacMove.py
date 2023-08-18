# Author information
__author__ = 'Nexus India VxLAN DevTest Group'
__copyright__ = 'Copyright (c) 2022, Cisco Systems Inc.'
__contact__ = ['group.jdasgupt@cisco.com']
__credits__ = ['ratrajen']
__version__ = 1.0

###################################################################
###                  Importing Libraries                        ###
###################################################################
# ------------------------------------------------------
# Import generic python libraries
# ------------------------------------------------------
import pdb
from random import random
import yaml
import json
import time
from yaml import Loader
import chevron
import pdb
import sys
import re
import ipaddress as ip
import numpy as np
from operator import itemgetter
import texttable
import difflib

# ------------------------------------------------------
# Import pyats aetest libraries
# ------------------------------------------------------
import logging
from pyats import aetest
from pyats.datastructures.logic import Not
from pyats.log.utils import banner
from pyats.async_ import pcall
from pyats.aereport.utils.argsvalidator import ArgsValidator
from pyats.datastructures.logic import Or
ArgVal = ArgsValidator()
log = logging.getLogger(__name__)
log.setLevel(logging.DEBUG)

# ------------------------------------------------------
# Import pyats genie libraries
# ------------------------------------------------------
from genie.conf import Genie
from genie.conf.base import Device
from genie.libs.parser.nxos.show_platform import ShowCores
from genie.libs.parser.nxos.show_platform import ShowVersion
from genie.libs.parser.nxos.show_vrf import ShowVrf
from genie.libs.sdk.apis.execute import execute_copy_run_to_start
from genie.libs.parser.nxos.show_vpc import ShowVpc
from genie.abstract import Lookup
from genie.libs import conf, ops, sdk, parser
from unicon.eal.dialogs import Statement, Dialog

# ------------------------------------------------------
# Import and initialize EVPN specific libraries
# ------------------------------------------------------
from VxLAN_PYlib import infra_lib

infraTrig = infra_lib.infraTrigger()
infraVerify = infra_lib.infraVerify()
infraEORTrigger = infra_lib.infraEORTrigger()

import vxlanEVPN_FNL_lib
evpnLib     = vxlanEVPN_FNL_lib.configure39KVxlanEvpn()
verifyEvpn  = vxlanEVPN_FNL_lib.verifyEVPNconfiguration()

# ------------------------------------------------------
# Import nxtest / nexus-pyats-test libraries
# ------------------------------------------------------
from lib import nxtest
# from lib.utils.find_path import get_full_with_script_path
from lib.config.interface.generate_interface_logical_map import generate_interface_logical_map
from lib.config.feature.feature_enabler import enable_features
from lib.config.feature.feature_disabler import disable_features
from lib.config.interface.interface_builder import BuildInterfaceConfig
from lib.config.mld.mld_builder import BuildMldConfig
from lib.config.ospf.ospf_builder import BuildOspfConfig
from lib.config.pim.pim_builder import BuildPimConfig
from lib.config.pim6.pim6_builder import BuildPim6Config
from lib.config.prefix_list.prefix_list_builder import BuildPrefixListConfig
from lib.config.routepolicy.route_policy_builder import BuildRoutePolicyConfig
from lib.config.static_route.static_route_builder import BuildStaticRouteConfig
from lib.config.bgp.bgp_builder import BuildBgpConfig
from lib.config.vlan.vlan_builder import BuildVlanConfig
from lib.config.vrf.vrf_builder import BuildVrfConfig
from lib.config.vxlan.vxlan_builder import BuildVxlanConfig
from src.forwarding.vxlan.vxlan_verify import common_verification
from lib.verify.verify_core import cores_check
from lib.triggers.config_trigger_lib import ConfigReplace, ConfigRollback
from lib.stimuli.stimuli_port_lib import StimuliInterfaceFlap
from lib.stimuli.stimuli_vrf_lib import StimuliFlapVrfs
from lib.stimuli.stimuli_intf_status import StimuliIntfStatus
from lib.triggers.flap.interface_flap import FabricOspfLinkFlap

# IXIA Libraries

from ixiatcl import IxiaTcl
from ixiahlt import IxiaHlt
from ixiangpf import IxiaNgpf
from ixiaerror import IxiaError
import ixiaPyats_lib
ixiatcl = IxiaTcl()
ixiahlt = IxiaHlt(ixiatcl)
ixiangpf = IxiaNgpf(ixiahlt)

try:
	ixnHLT_errorHandler('', {})
except (NameError,):
	def ixnHLT_errorHandler(cmd, retval):
		global ixiatcl
		err = ixiatcl.tcl_error_info()
		log = retval['log']
		additional_info = '> command: %s\n> tcl errorInfo: %s\n> log: %s' % (cmd, err, log)
		raise IxiaError(IxiaError.COMMAND_FAIL, additional_info)

###################################################################
###                  GLOBAL VARIABLES                           ###
###################################################################

global_processors = {
    'pre': [],
    'post': [],
    'exception': [],
}
global copy_cores
copy_cores = False
MD_REGEX = '(^default|management|external)'
cr_file  = 'FHS_CR_FILE'
###################################################################
###                     Common Libraries                        ###
###################################################################
def rollback_log_dump(uut):
    uut.execute ('show rollback status' , timeout=6000)
    uut.execute ('show rollback log veirfy' , timeout=6000)
    uut.execute ('show rollback log exec' , timeout=6000)
    return 0

def verify_config_replace(device_list):
    Flag = True
    for uut in device_list:
        output = uut.execute ('configure replace bootflash:{config_file}'.format(config_file=cr_file), timeout = 6000)
        if 'Configure replace completed successfully' in output :
            log.info('CR got success with base config')
        else:
            log.error('Configure replace Failed')
            Flag = False
    
        counter = 1
        while counter <= 3:
            output = uut.execute ('show rollback status' , timeout = 6000)
            if 'Operation Status: Success' in output or 'Operation Status: Failed' in output or 'Config are same' in output :
                log.info('Rollback completed')
                break
            else:
                log.error('Rollback in progess')
                rollback_log_dump(uut)
                Flag = False
        
            log.info("Waiting 10secs")
            time.sleep(10)
            counter += 1
    
    return Flag

###################################################################
###                  DHCP Libraries                             ###
###################################################################
# Creates Topologies
def create_topo(name, handle, host_count):
    topology_status = ixiangpf.topology_config(
        topology_name               =   name,
        port_handle                 =   handle,
        device_group_multiplier     =   host_count,
    )

    if topology_status['status'] != IxiaHlt.SUCCESS:
        log.info('Topology configuration failed for {}'.format(name))
        ixnHLT_errorHandler('topology_config', topology_status)
        

    log.info('Topolog configuration success for {}'.format(name))
    return topology_status

# Configure DHCP Server
def dhcpServerConf(group_handle, params):
    if params['mode'] == 'trunk':
        dhcp_status = ixiangpf.emulation_dhcp_server_config(
            handle				            =	group_handle,
            count				            =	params['no_of_ints'],
            lease_time                      =   params['lease'],
            ipaddress_count		            =	params['no_of_ints'],
            ipaddress_pool		            =   params['v4_start_addr'],
            ipaddress_pool_step		        =	params['v4_addr_step'],
            ipaddress_pool_prefix_length    =	params['v4_netmask'],
            ipaddress_pool_prefix_step	    =	'0',
            dhcp_offer_router_address	    =	params['v4_gateway'],
            dhcp_offer_router_address_step 	=   params['v4_addr_step'],
            ip_address		                =	params['v4_addr'],
            ip_step		                    =	params['v4_addr_step'],
            ip_gateway		                =	params['v4_gateway'],
            ip_gateway_step		            =	'0.0.0.0',
            ip_prefix_length                =   params['v4_netmask'],
            ip_prefix_step		            =	'0',
            local_mac                       =   params['mac'],
            local_mac_outer_step            =   params['mac_step'],
            local_mtu		                =	'1500',
            vlan_id			                =	params['vlan_id'],
            vlan_id_step		            =	'0',
            protocol_name		            =	"DHCP4 Server",
            pool_address_increment	        =	'0.0.0.0',
            pool_address_increment_step     =	'0.0.0.0',
        )
    else:
        dhcp_status = ixiangpf.emulation_dhcp_server_config(
            handle				            =	group_handle,
            count				            =	params['no_of_ints'],
            lease_time                      =   params['lease'],
            ipaddress_count		            =	params['no_of_ints'],
            ipaddress_pool		            =   params['v4_start_addr'],
            ipaddress_pool_step		        =	params['v4_addr_step'],
            ipaddress_pool_prefix_length    =	params['v4_netmask'],
            ipaddress_pool_prefix_step	    =	'0',
            dhcp_offer_router_address	    =	params['v4_gateway'],
            dhcp_offer_router_address_step 	=   params['v4_addr_step'],
            ip_address		                =	params['v4_addr'],
            ip_step		                    =	params['v4_addr_step'],
            ip_gateway		                =	params['v4_gateway'],
            ip_gateway_step		            =	'0.0.0.0',
            ip_prefix_length                =   params['v4_netmask'],
            ip_prefix_step		            =	'0',
            local_mac                       =   params['mac'],
            local_mac_outer_step            =   params['mac_step'],
            local_mtu		                =	'1500',
            protocol_name		            =	"DHCP4 Server",
            pool_address_increment	        =	'0.0.0.0',
            pool_address_increment_step     =	'0.0.0.0',
        )

    if dhcp_status['status'] != IxiaHlt.SUCCESS:
        log.info("Configuring DHCP Server failed")
        ixnHLT_errorHandler('emulation_dhcp_server_config', dhcp_status)

    return(dhcp_status)

# Configures the DHCP Client Device Group
def dhcpClientConf(group_handle, params):
    if params['mode'] == 'trunk':
        dhcp_status = ixiangpf.emulation_dhcp_group_config(
            handle				        =	group_handle,
            protocol_name 		        =	"Dhcp_client",
            mac_addr                    =   params['mac'],
            mac_addr_step               =   params['mac_step'],
            use_rapid_commit            =   '0',
            enable_stateless            =   '0',
            dhcp4_broadcast             =   '1',
            num_sessions                =   params['no_of_ints'],
            vlan_id                     =   params['vlan_id'],
            vlan_id_step		        =	'0',
            dhcp_range_use_first_server =   '1',
            dhcp_range_ip_type          =   params['protocol'],
            vendor_id                   =   'any',
        )
    else:
        dhcp_status = ixiangpf.emulation_dhcp_group_config(
            handle				        =	group_handle,
            protocol_name 		        =	"Dhcp_client",
            mac_addr                    =   params['mac'],
            mac_addr_step               =   params['mac_step'],
            use_rapid_commit            =   '0',
            enable_stateless            =   '0',
            dhcp4_broadcast             =   '1',
            num_sessions                =   params['no_of_ints'],
            dhcp_range_use_first_server =   '1',
            dhcp_range_ip_type          =   params['protocol'],
            vendor_id                   =   'any',
        )
    
    if dhcp_status['status'] != IxiaHlt.SUCCESS:
        log.info("Configuring DHCP Client Device Group failed")
        ixnHLT_errorHandler('emulation_dhcp_group_config', dhcp_status)
    
    return dhcp_status

# Start/Stop's Server
def dhcpServerControll(dhcp_server, action):
    ###print "Starting dhcp server...."
    
    control_status = ixiangpf.emulation_dhcp_server_control(
        dhcp_handle = 			dhcp_server 		                           ,
        action = action								                           ,
    )
    if control_status['status'] != IxiaHlt.SUCCESS:
        log.info('Failed to start / stop server')
        ixnHLT_errorHandler('emulation_dhcp_server_control', control_status)
    
    log.info("Waiting for 20secs...")
    time.sleep(20)

# Start/Stop's Client
def dhcpClientControll(dhcp_client, action):  

    control_status = ixiangpf.emulation_dhcp_control(
        handle 	=   dhcp_client,
        action  =   action,
    )
    if control_status['status'] != IxiaHlt.SUCCESS:
        ixnHLT_errorHandler('emulation_dhcp_control', control_status)
        log.error('Failed to start / stop client')

    log.info("Waiting 5secs to start/stop the client")
    time.sleep(5)

def start_server_client(testscript, handle='ALL'):
    if handle == 'ALL':
        dhcpServerControll(testscript.parameters['dhcp_server1_handle'],'collect')
        dhcpServerControll(testscript.parameters['dhcp_server2_handle'],'collect')
        dhcpClientControll(testscript.parameters['leaf3_client1_handle'],'bind')
        dhcpClientControll(testscript.parameters['leaf3_client2_handle'],'bind')
        dhcpClientControll(testscript.parameters['vpc_client1_handle'],'bind')
        dhcpClientControll(testscript.parameters['vpc_client2_handle'],'bind')
    else:
        dhcpClientControll(handle, 'bind')
    
    log.info("Waiting 25secs to start client/server")
    time.sleep(25)

def stop_client(testscript):
    dhcpClientControll(testscript.parameters['leaf3_client1_handle'],'abort')
    dhcpClientControll(testscript.parameters['leaf3_client2_handle'],'abort')
    dhcpClientControll(testscript.parameters['vpc_client1_handle'],'abort')
    dhcpClientControll(testscript.parameters['vpc_client2_handle'],'abort')
    
    log.info("Waiting 15secs to stop client")
    time.sleep(15)

def release_client(testscript):
    dhcpClientControll(testscript.parameters['leaf3_client1_handle'],'release')
    dhcpClientControll(testscript.parameters['leaf3_client2_handle'],'release')
    dhcpClientControll(testscript.parameters['vpc_client1_handle'],'release')
    dhcpClientControll(testscript.parameters['vpc_client2_handle'],'release')
    
    log.info("Waiting 10secs to stop client")
    time.sleep(10)

def start_stop_dg(handle, action):
    control_status = ixiangpf.test_control(
        handle = handle,
        action = action,
    )
    if control_status['status'] != IxiaHlt.SUCCESS:
        log.info('Failed to start / stop server')
        ixnHLT_errorHandler('test_control', control_status)
    
    log.info("Waiting for 20secs...")
    time.sleep(20)
    
def stop_protocol(testscript):
    start_stop_dg(testscript.parameters['sa1_dg1_handle'],'stop_protocol')
    start_stop_dg(testscript.parameters['sa1_dg2_handle'],'stop_protocol')
    start_stop_dg(testscript.parameters['vpc_dg_handle'],'stop_protocol')
    start_stop_dg(testscript.parameters['vpc1_dg_handle'],'stop_protocol')
    
    log.info("Waiting 5secs to stop protocol")
    time.sleep(5)

def stop_server(testscript):
    
    dhcpServerControll(testscript.parameters['dhcp_server1_handle'],'abort')
    dhcpServerControll(testscript.parameters['dhcp_server2_handle'],'abort')
    log.info("Waiting 25secs to stop servers")
    time.sleep(25)

def start_client(testscript):
    dhcpClientControll(testscript.parameters['leaf3_client1_handle'],'bind')
    dhcpClientControll(testscript.parameters['leaf3_client2_handle'],'bind')
    dhcpClientControll(testscript.parameters['vpc_client1_handle'],'bind')
    dhcpClientControll(testscript.parameters['vpc_client2_handle'],'bind')
    
    log.info("Waiting 10secs to start client")
    time.sleep(10)

def send_arp(handle):
    dhcpClientControll(handle,'send_arp')
        
    log.info("Waiting 10secs to send ARP")
    time.sleep(10)

def start_server(testscript):
    dhcpServerControll(testscript.parameters['dhcp_server1_handle'],'collect')
    dhcpServerControll(testscript.parameters['dhcp_server2_handle'],'collect')
    
    log.info("Waiting 10secs to start server")
    time.sleep(10)

def configureTraffic(self, name, src_handle, dst_handle, type):
    ixia_traffic_config = ixiangpf.traffic_config(
        mode                    =   'create',
        emulation_src_handle    =   src_handle,
        emulation_dst_handle    =   dst_handle,
        name                    =   name,
        circuit_endpoint_type   =   type,
        rate_pps                =   '10000',
        frame_size              =   '500',
        mac_dst_mode            =   'fixed',
        mac_src_mode            =   'fixed',
        track_by                =   'trackingenabled0',
        bidirectional           =   '1',
        transmit_mode           =   'continuous',
        src_dest_mesh           =   'one_to_one',
    )
    if ixia_traffic_config['status'] == IxiaHlt.SUCCESS:
        log.info('Successfully created traffic')
    else:
        ixnHLT_errorHandler('emulation_dhcp_server_control', ixia_traffic_config)
        self.failed("Failed to create traffic")
    
    return ixia_traffic_config

def modifyTraffic(section, testscript, traffic_intf_list):
    for intf_type in traffic_intf_list:
        log.info("Verifying traffic for {}".format(intf_type))
        if intf_type == 'ORPHAN1':
            stream_handle       = testscript.parameters['orph1_trf1_stream_id']
        elif intf_type == 'ORPHAN2':
            stream_handle       = testscript.parameters['orph2_trf2_stream_id']
        elif intf_type == 'VPC1':
            stream_handle       = testscript.parameters['vpc1_trf3_stream_id']
        elif intf_type == 'VPC2':
            stream_handle       = testscript.parameters['vpc2_trf4_stream_id']
        elif intf_type == 'VPC3':
            stream_handle       = testscript.parameters['vpc1_vpc2_stream_id']
        else:
            stream_handle       = testscript.parameters['orph_trf5_stream_id']
    
        ixia_traffic_config = ixiangpf.traffic_config(
            mode                    =   'modify',
            stream_id               =   stream_handle,
        )
        if ixia_traffic_config['status'] == IxiaHlt.SUCCESS:
            log.info('Successfully modified traffic')
        else:
            ixnHLT_errorHandler('traffic_config', ixia_traffic_config)
            section.failed("Failed to modify traffic")
    
    log.info('Waiting 10secs for traffic modify')
    time.sleep(10)
    # return ixia_traffic_config

def startContTraffic(section, testscript, steps, traffic_intf_list):
    for intf_type in traffic_intf_list:
        log.info("Verifying traffic for {}".format(intf_type))
        if intf_type == 'ORPHAN1':
            stream_handle       = testscript.parameters['orph1_trf1_traffic_item']
            stream_id           = testscript.parameters['orph1_trf1_stream_id']
        elif intf_type == 'ORPHAN2':
            stream_handle       = testscript.parameters['orph2_trf2_traffic_item']
            stream_id           = testscript.parameters['orph2_trf2_stream_id']
        elif intf_type == 'VPC1':
            stream_handle       = testscript.parameters['vpc1_trf3_traffic_item']
            stream_id           = testscript.parameters['vpc1_trf3_stream_id']
        elif intf_type == 'VPC2':
            stream_handle       = testscript.parameters['vpc2_trf4_traffic_item']
            stream_id           = testscript.parameters['vpc2_trf4_stream_id']
        elif intf_type == 'VPC3':
            stream_handle       = testscript.parameters['vpc1_vpc2_traffic_item']
            stream_id           = testscript.parameters['vpc1_vpc2_stream_id']
        else:
            stream_handle       = testscript.parameters['orph_trf5_traffic_item']
            stream_id           = testscript.parameters['orph_trf5_stream_id']

        with steps.start("Starting the traffic"):
            x = ixiangpf.traffic_control(action='run', handle = stream_handle, max_wait_timer=240)
            if x['status'] != IxiaHlt.SUCCESS:
                log.error(banner('The Stream {0} could not be started as expected '.format(stream_id)))
                section.failed('The Stream {0} could not be started as expected '.format(stream_id))
            else:
                log.info("Start Traffic stream success")
        
        log.info('Waiting 30secs for the traffic')
        time.sleep(30)
            
        with steps.start("Clearing Stats"):
            x = ixiangpf.traffic_control(action='clear_stats', handle = stream_handle, max_wait_timer=60)
        
        log.info('Waiting 30secs to clear stats')
        time.sleep(30)

def verifyContTraffic(section, testscript, steps, traffic_intf_list, loss=1.0, drop=False):
    for intf_type in traffic_intf_list:
        log.info("Verifying traffic for {}".format(intf_type))
        if intf_type == 'ORPHAN1':
            stream_handle       = testscript.parameters['orph1_trf1_traffic_item']
            stream_id           = testscript.parameters['orph1_trf1_stream_id']
        elif intf_type == 'ORPHAN2':
            stream_handle       = testscript.parameters['orph2_trf2_traffic_item']
            stream_id           = testscript.parameters['orph2_trf2_stream_id']
        elif intf_type == 'VPC1':
            stream_handle       = testscript.parameters['vpc1_trf3_traffic_item']
            stream_id           = testscript.parameters['vpc1_trf3_stream_id']
        elif intf_type == 'VPC2':
            stream_handle       = testscript.parameters['vpc2_trf4_traffic_item']
            stream_id           = testscript.parameters['vpc2_trf4_stream_id']
        elif intf_type == 'VPC3':
            stream_handle       = testscript.parameters['vpc1_vpc2_traffic_item']
            stream_id           = testscript.parameters['vpc1_vpc2_stream_id']
        else:
            stream_handle       = testscript.parameters['orph_trf5_traffic_item']
            stream_id           = testscript.parameters['orph_trf5_stream_id']
        
        Fail = False
        if not drop:
            with steps.start("Verifying traffic"):
                counter = 60
                while counter < 300:
                    y = ixiangpf.traffic_stats(stream=stream_id, mode='traffic_item')
                    log.info(banner('The value of y is : {0}'.format(y)))
                    for i in y['traffic_item']:
                        if i == stream_id:
                            loss_percent = y['traffic_item'][i]['rx']['loss_percent']
                            log.info(banner('The value of loss_percent is : {0}'.format(loss_percent)))
                            if float(loss_percent) > loss:
                                Fail = True
                                log.info("Waiting for 60 secs to traffic stabilize")
                                time.sleep(60)
                                counter += 60
                            else:
                                break
        
        with steps.start("Clearing Stats"):
            x = ixiangpf.traffic_control(action='clear_stats', handle = stream_handle, max_wait_timer=60)
        
        log.info('Waiting 30secs to clear stats')
        time.sleep(30)
        
        with steps.start("Verifying traffic"):
            counter = 60
            while counter < 300:
                y = ixiangpf.traffic_stats(stream=stream_id, mode='traffic_item')
                log.info(banner('The value of y is : {0}'.format(y)))
                for i in y['traffic_item']:
                    if i == stream_id:
                        loss_percent = y['traffic_item'][i]['rx']['loss_percent']
                        log.info(banner('The value of loss_percent is : {0}'.format(loss_percent)))
                        if float(loss_percent) > 1.0:
                            Fail = True
                            log.info("Waiting for 60 secs to traffic stabilize")
                            time.sleep(60)
                            counter += 60
                        else:
                            break
        
        with steps.start("Stopping the traffic"):
            x = ixiangpf.traffic_control(action='stop', handle = stream_handle, max_wait_timer=60)
            if x['status'] != IxiaHlt.SUCCESS:
                log.error(banner('The Stream {0} could not be stopped as expected '.format(stream_id)))
                section.failed('The Stream {0} could not be stopped as expected '.format(stream_id))
            else:
                log.info("Stopping traffic success")

        if Fail:
            log.error("Verify Traffic failed")
            section.failed("Verify Traffic failed")
        else:
            log.info("Verify Traffic Success")

def verifyTraffic(section, testscript, steps, traffic_intf_list, traffic_wait_time=60):
    for intf_type in traffic_intf_list:
        log.info("Verifying traffic for {}".format(intf_type))
        if intf_type == 'ORPHAN1':
            stream_handle       = testscript.parameters['orph1_trf1_traffic_item']
            stream_id           = testscript.parameters['orph1_trf1_stream_id']
        elif intf_type == 'ORPHAN2':
            stream_handle       = testscript.parameters['orph2_trf2_traffic_item']
            stream_id           = testscript.parameters['orph2_trf2_stream_id']
        elif intf_type == 'VPC1':
            stream_handle       = testscript.parameters['vpc1_trf3_traffic_item']
            stream_id           = testscript.parameters['vpc1_trf3_stream_id']
        elif intf_type == 'VPC2':
            stream_handle       = testscript.parameters['vpc2_trf4_traffic_item']
            stream_id           = testscript.parameters['vpc2_trf4_stream_id']
        elif intf_type == 'VPC3':
            stream_handle       = testscript.parameters['vpc1_vpc2_traffic_item']
            stream_id           = testscript.parameters['vpc1_vpc2_stream_id']
        else:
            stream_handle       = testscript.parameters['orph_trf5_traffic_item']
            stream_id           = testscript.parameters['orph_trf5_stream_id']
        
        with steps.start("Starting the traffic"):
            x = ixiangpf.traffic_control(action='run', handle = stream_handle, max_wait_timer=240)
            if x['status'] != IxiaHlt.SUCCESS:
                log.error(banner('The Stream {0} could not be started as expected '.format(stream_id)))
                section.failed('The Stream {0} could not be started as expected '.format(stream_id))
            else:
                log.info("Creation of Traffic stream success")
        
        log.info('Waiting {}secs for the traffic'.format(traffic_wait_time))
        time.sleep(traffic_wait_time)
            
        with steps.start("Clearing Stats"):
            x = ixiangpf.traffic_control(action='clear_stats', handle = stream_handle, max_wait_timer=60)
        
        log.info('Waiting 10secs to clear stats')
        time.sleep(10)

        Fail = False
        with steps.start("Verifying traffic"):
            counter = 60
            while counter < 300:
                y = ixiangpf.traffic_stats(stream=stream_id, mode='traffic_item')
                log.info(banner('The value of y is : {0}'.format(y)))
                for i in y['traffic_item']:
                    if i == stream_id:
                        loss_percent = y['traffic_item'][i]['rx']['loss_percent']
                        log.info(banner('The value of loss_percent is : {0}'.format(loss_percent)))
                        if float(loss_percent) > 1.0:
                            Fail = True
                            log.info("Waiting for 60 secs to traffic stabilize")
                            time.sleep(60)
                            counter += 60
                
                if not Fail:
                    break
        
        with steps.start("Stopping the traffic"):
            x = ixiangpf.traffic_control(action='stop', handle = stream_handle, max_wait_timer=60)
            if x['status'] != IxiaHlt.SUCCESS:
                log.error(banner('The Stream {0} could not be stopped as expected '.format(stream_id)))
                section.failed('The Stream {0} could not be stopped as expected '.format(stream_id))
            else:
                log.info("Stopping traffic success")
        
        with steps.start("Verify traffic final validation"):
            if Fail:
                log.error("Verify Traffic failed")
                section.failed("Verify Traffic failed")
            else:
                log.info("Verify Traffic Success")
            
def stopTraffic(section, testscript, steps, traffic_intf_list):
    for intf_type in traffic_intf_list:
        if intf_type == 'ORPHAN1':
            stream_handle       = testscript.parameters['orph1_trf1_traffic_item']
            stream_id           = testscript.parameters['orph1_trf1_stream_id']
        elif intf_type == 'ORPHAN2':
            stream_handle       = testscript.parameters['orph2_trf2_traffic_item']
            stream_id           = testscript.parameters['orph2_trf2_stream_id']
        elif intf_type == 'VPC1':
            stream_handle       = testscript.parameters['vpc1_trf3_traffic_item']
            stream_id           = testscript.parameters['vpc1_trf3_stream_id']
        elif intf_type == 'VPC2':
            stream_handle       = testscript.parameters['vpc2_trf4_traffic_item']
            stream_id           = testscript.parameters['vpc2_trf4_stream_id']
        elif intf_type == 'VPC3':
            stream_handle       = testscript.parameters['vpc1_vpc2_traffic_item']
            stream_id           = testscript.parameters['vpc1_vpc2_stream_id']
        else:
            stream_handle       = testscript.parameters['orph_trf5_traffic_item']
            stream_id           = testscript.parameters['orph_trf5_stream_id']
        
        with steps.start("Stopping the traffic"):
            x = ixiangpf.traffic_control(action='stop', handle = stream_handle, max_wait_timer=60)
            if x['status'] != IxiaHlt.SUCCESS:
                log.error(banner('The Stream {0} could not be stopped as expected '.format(stream_id)))
                section.failed('The Stream {0} could not be stopped as expected '.format(stream_id))
            else:
                log.info("Stopping traffic success")
        
#################################################################################################
#                                  DHCP SNOOPING API's
#################################################################################################
def clear_ARP(device_dut, testscript, testbed):
    for dut in device_dut:
        LEAF = testbed.devices[dut]
        LEAF.configure("clear ip arp vrf VRF-1 force-delete", timeout=60)
        log.info("Clearing ARP entries on {}".format(dut))

    log.info("Waiting 20secs for convergence")
    time.sleep(20)

def WaitForConvergence(testscript, convergence_time):
    log.info("Waiting for {}secs for convergence".format(int(convergence_time)))
    time.sleep(int(convergence_time))

def reconfigure_fanout(testscript, testbed, steps):
    LEAF6   = testbed.devices['node06']

    vlan = int(testscript.parameters['VPC_dict']['vlan_id'])
    
    for interface in LEAF6.interfaces:
        if LEAF6.interfaces[interface].alias == 'nd06_nd01_1_5':
            leaf6_tgn_1 = interface
        if LEAF6.interfaces[interface].alias == 'nd06_nd01_1_6':
            leaf6_tgn_2 = interface
        if LEAF6.interfaces[interface].alias == 'nd06_nd03_1_1':
            leaf6_tgn_11 = interface
        if LEAF6.interfaces[interface].alias == 'nd06_nd03_1_2':
            leaf6_tgn_22 = interface
    with steps.start("Change the interface vlan for the mac move"):
        try:
            LEAF6.configure('''interface po200
                                switchport trunk allowed vlan {vlan}
                                interface po210
                                switchport trunk allowed vlan {vlan}
                                interface {intf1}
                                switchport trunk allowed vlan none
                                interface {intf2}
                                switchport trunk allowed vlan none
                            '''.format(intf1=leaf6_tgn_1, intf2=leaf6_tgn_2, vlan=vlan), timeout=60)
        except Exception as error:
            log.error("Unable to configure - Encountered Exception " + str(error))

    log.info('Waiting 10secs...')
    time.sleep(10)

def reconfigure_fanout_1(testscript, testbed, steps):
    LEAF6   = testbed.devices['node06']

    vlan = int(testscript.parameters['VPC_dict']['vlan_id'])
    
    for interface in LEAF6.interfaces:
        if LEAF6.interfaces[interface].alias == 'nd06_nd01_1_5':
            print(interface)
            leaf6_tgn_1 = interface
        if LEAF6.interfaces[interface].alias == 'nd06_nd01_1_6':
            print(interface)
            leaf6_tgn_2 = interface
            
        if LEAF6.interfaces[interface].alias == 'nd06_nd03_1_1':
            print(interface)
            leaf6_tgn_11 = interface
        if LEAF6.interfaces[interface].alias == 'nd06_nd03_1_2':
            print(interface)
            leaf6_tgn_22 = interface
    
        try:
            LEAF6.configure('''interface po200
                                switchport trunk allowed vlan {vlan}
                                interface po210
                                switchport trunk allowed vlan none
                                interface {intf1}
                                switchport trunk allowed vlan none
                                interface {intf2}
                                switchport trunk allowed vlan none
                                interface {intf3}
                                switchport trunk allowed vlan none
                                interface {intf4}
                                switchport trunk allowed vlan none
                            '''.format(intf1=leaf6_tgn_1, intf2=leaf6_tgn_2, intf3=leaf6_tgn_11, 
                                       intf4=leaf6_tgn_22, vlan=vlan), timeout=60)
        except Exception as error:
            log.error("Unable to configure - Encountered Exception " + str(error))
    
    log.info('Waiting 10secs...')
    time.sleep(10)

def parsePort(eth_str):
    if eth_str.startswith("port-channel"):
        grp = re.search("port.channel(\d+]+)", eth_str)
    else:
        grp = re.search("Ethernet([\d+/\d+/*\d*]+)", eth_str)
    if grp:
        return grp.group(1)
    else:
        return False

class ParseConfig(aetest.Testcase):
    @aetest.test
    def ParseConfig(self, testscript, testbed, configurationFile):
        with open(configurationFile) as cfgFile:
            configuration = yaml.load(cfgFile, Loader=Loader)
        
        testscript.parameters['LEAF_1_Orphan1_TGEN_dict']   = configuration['LEAF_1_Orphan1_TGEN_data']
        testscript.parameters['LEAF_1_Orphan2_TGEN_dict']   = configuration['LEAF_1_Orphan2_TGEN_data']
        testscript.parameters['LEAF_3_1_TGEN_dict']         = configuration['LEAF_3_1_TGEN_data']
        testscript.parameters['LEAF_3_2_TGEN_dict']         = configuration['LEAF_3_2_TGEN_data']
        testscript.parameters['LEAF_2_TGEN_dict']           = configuration['LEAF_2_TGEN_data']
        testscript.parameters['LEAF_4_1_TGEN_dict']         = configuration['LEAF_4_1_TGEN_data']
        testscript.parameters['LEAF_4_2_TGEN_dict']         = configuration['LEAF_4_2_TGEN_data']
        testscript.parameters['VPC_dict']                   = configuration['FANOUT_TGEN_data']
        testscript.parameters['VPC1_dict']                  = configuration['FANOUT_1_TGEN_data']

class ConfigureIxiaTopo1(aetest.Testcase):
    """ Configuring IXIA """
    @aetest.test
    def InitializeIxia(self, testscript, testbed, steps):
        
        """ Initializing IXIA Testbed """

        with steps.start("Get the IXIA details from testbed YAML file"):

            if "ixia" in testbed.devices:
                testscript.parameters['traffic_threshold'] = 2
                ixia_chassis_ip = testbed.devices['ixia'].connections.tgn.ixia_chassis_ip
                ixia_tcl_server = testbed.devices['ixia'].connections.tgn.ixnetwork_api_server_ip
                ixia_port_list  = testbed.devices['ixia'].connections.tgn.ixia_port_list
            
            else:
                log.info("IXIA details not provided in testbed file")

        with steps.start("Connect to IXIA Chassis"):
            connect_status = ixiangpf.connect(
                reset                  = 1,
                device                 = ixia_chassis_ip,
                port_list              = ixia_port_list,
                ixnetwork_tcl_server   = ixia_tcl_server,
                tcl_server             = ixia_chassis_ip,
            )
            if connect_status['status'] != IxiaHlt.SUCCESS:
                ixnHLT_errorHandler('connect', connect_status)
                log.error('Connecting to IXIA failed')
                self.failed("Connecting to IXIA failed")
            else:
                log.info('Connecting to IXIA success')
            
            port_handle = connect_status['vport_list']
            testscript.parameters['sa1_port1']      = port_handle.split(' ')[1]
            testscript.parameters['vpc_port']       = port_handle.split(' ')[3]
            testscript.parameters['sa1_port2']      = port_handle.split(' ')[5]
            testscript.parameters['sa2_port1']      = port_handle.split(' ')[6]
            testscript.parameters['sa2_port2']      = port_handle.split(' ')[7]
            testscript.parameters['vpc_port1']      = port_handle.split(' ')[8]
            
    @aetest.test
    def CreateTopology(self, testscript, steps):

        sa1_port1       = testscript.parameters['sa1_port1']
        vpc_port        = testscript.parameters['vpc_port']
        sa1_port2       = testscript.parameters['sa1_port2']
        sa2_port1       = testscript.parameters['sa2_port1']
        sa2_port2       = testscript.parameters['sa2_port2']
        vpc_port1       = testscript.parameters['vpc_port1']
        
        P2_tgen_dict = testscript.parameters['LEAF_3_1_TGEN_dict']
        P4_tgen_dict = testscript.parameters['VPC_dict']
        P6_tgen_dict = testscript.parameters['LEAF_3_2_TGEN_dict']
        P7_tgen_dict = testscript.parameters['VPC1_dict']
        
        with steps.start("Creating Topologies"):
            
            retval = create_topo('LEAF3-SA1-Topo', sa1_port1, P2_tgen_dict['no_of_ints'])
            testscript.parameters['sa1_tp1_handle']  = retval['topology_handle']
            testscript.parameters['sa1_dg1_handle']  = retval['device_group_handle']
            
            retval = create_topo('VPC-Topo', vpc_port, P4_tgen_dict['no_of_ints'])
            testscript.parameters['vpc_tp_handle']  = retval['topology_handle']
            testscript.parameters['vpc_dg_handle']  = retval['device_group_handle']

            retval = create_topo('LEAF3-SA2-Topo', sa1_port2, P6_tgen_dict['no_of_ints'])
            testscript.parameters['sa1_tp2_handle']  = retval['topology_handle']
            testscript.parameters['sa1_dg2_handle']  = retval['device_group_handle']
            
            retval = create_topo('LEAF4-SA1-Topo', sa2_port1, '1')
            testscript.parameters['sa2_tp1_handle']  = retval['topology_handle']
            testscript.parameters['sa2_dg1_handle']  = retval['device_group_handle']
            
            retval = create_topo('LEAF4-SA2-Topo', sa2_port2, '1')
            testscript.parameters['sa2_tp2_handle']  = retval['topology_handle']
            testscript.parameters['sa2_dg2_handle']  = retval['device_group_handle']
            
            retval = create_topo('VPC1-Topo', vpc_port1, P7_tgen_dict['no_of_ints'])
            testscript.parameters['vpc1_tp_handle']  = retval['topology_handle']
            testscript.parameters['vpc1_dg_handle']  = retval['device_group_handle']
            
    @aetest.test
    def CreateDeviceGroup(self, testscript, steps):
        leaf3_client1_dg_handle = testscript.parameters['sa1_dg1_handle']
        leaf3_client2_dg_handle = testscript.parameters['sa1_dg2_handle']
        vpc_client1_dg_handle   = testscript.parameters['vpc_dg_handle']
        vpc_client2_dg_handle   = testscript.parameters['vpc1_dg_handle']
        srv1_dg_handle          = testscript.parameters['sa2_dg1_handle']
        srv2_dg_handle          = testscript.parameters['sa2_dg2_handle']
        
        P2_tgen_dict = testscript.parameters['LEAF_3_1_TGEN_dict']
        P4_tgen_dict = testscript.parameters['VPC_dict']
        P6_tgen_dict = testscript.parameters['LEAF_3_2_TGEN_dict']
        P7_tgen_dict = testscript.parameters['LEAF_4_1_TGEN_dict']
        P8_tgen_dict = testscript.parameters['LEAF_4_2_TGEN_dict']
        P9_tgen_dict = testscript.parameters['VPC1_dict']

        with steps.start('Creating DHCP Server1'):
            dhcp_status = dhcpServerConf(srv1_dg_handle, P7_tgen_dict)
            testscript.parameters['dhcp_server1_handle'] = dhcp_status['dhcpv4server_handle']
            
        with steps.start('Creating DHCP Server2'):
            dhcp_status = dhcpServerConf(srv2_dg_handle, P8_tgen_dict)
            testscript.parameters['dhcp_server2_handle'] = dhcp_status['dhcpv4server_handle']

        with steps.start('Creating DHCP Leaf3 Client1'):
            dhcp_status = dhcpClientConf(leaf3_client1_dg_handle, P2_tgen_dict)
            testscript.parameters['leaf3_client1_handle'] = dhcp_status['dhcpv4client_handle']

        with steps.start('Creating DHCP Leaf3 Client2'):
            dhcp_status = dhcpClientConf(leaf3_client2_dg_handle, P6_tgen_dict)
            testscript.parameters['leaf3_client2_handle'] = dhcp_status['dhcpv4client_handle']
        
        with steps.start('Creating DHCP VPC Client1'):
            dhcp_status = dhcpClientConf(vpc_client1_dg_handle, P4_tgen_dict)
            testscript.parameters['vpc_client1_handle'] = dhcp_status['dhcpv4client_handle']

        with steps.start('Creating DHCP VPC Client2'):
            dhcp_status = dhcpClientConf(vpc_client2_dg_handle, P9_tgen_dict)
            testscript.parameters['vpc_client2_handle'] = dhcp_status['dhcpv4client_handle']
    
    @aetest.test
    def StartClientServer(self, testscript, steps):
        start_server_client(testscript)
    
    @aetest.test
    def CreateTrafficItems(self, testscript, testbed, steps):
        
        # Creating Traffic Items
        leaf3_client1_tp_handle = testscript.parameters['sa1_tp1_handle']
        leaf3_client2_tp_handle = testscript.parameters['sa1_tp2_handle']
        vpc_client1_tp_handle   = testscript.parameters['vpc_tp_handle']
        vpc_client2_tp_handle   = testscript.parameters['vpc1_tp_handle']
        
        ixia_traffic_config = configureTraffic(self, 'TRF3_VPC1_TRUNK-SA1_ACCESS', 
                                               vpc_client1_tp_handle, leaf3_client2_tp_handle, 'ipv4')
        
        log.info('The value of ixia_traffic_config is : {0}'.format(ixia_traffic_config))
        testscript.parameters['vpc1_trf3_stream_id']        = ixia_traffic_config['stream_id']
        testscript.parameters['vpc1_trf3_traffic_item']     = ixia_traffic_config['traffic_item']
        
        ixia_traffic_config = configureTraffic(self, 'TRF4_VPC2_ACCESS-SA1_TRUNK', 
                                               vpc_client2_tp_handle, leaf3_client1_tp_handle, 'ipv4')
        
        log.info('The value of ixia_traffic_config is : {0}'.format(ixia_traffic_config))
        testscript.parameters['vpc2_trf4_stream_id']         = ixia_traffic_config['stream_id']
        testscript.parameters['vpc2_trf4_traffic_item']      = ixia_traffic_config['traffic_item']

        ixia_traffic_config = configureTraffic(self, 'TRF5_VPC1_TRUNK-VPC2_ACCESS', 
                                               vpc_client1_tp_handle, vpc_client2_tp_handle, 'ipv4')
        
        log.info('The value of ixia_traffic_config is : {0}'.format(ixia_traffic_config))
        testscript.parameters['vpc1_vpc2_stream_id']        = ixia_traffic_config['stream_id']
        testscript.parameters['vpc1_vpc2_traffic_item']     = ixia_traffic_config['traffic_item']


def macmove_1_unconfigure(testscript, testbed, steps):
    LEAF1   = testbed.devices['node01']
    LEAF3   = testbed.devices['node03']
    LEAF6   = testbed.devices['node06']

    vlan = int(testscript.parameters['VPC_dict']['vlan_id'])
    
    with steps.start("Stopping clients"):
        release_client(testscript)
    
    for interface in LEAF1.interfaces:
        if LEAF1.interfaces[interface].alias == 'nd01_nd06_1_5':
            leaf1_tgn_1 = interface

    for interface in LEAF3.interfaces:
        if LEAF3.interfaces[interface].alias == 'nd03_tgn01_1_1':
            leaf3_tgn_1 = interface

    for interface in LEAF6.interfaces:
        if LEAF6.interfaces[interface].alias == 'nd06_nd01_1_5':
            leaf6_tgn_1 = interface
            
    with steps.start("Change the interface vlan for the mac move"):
        try:
            LEAF6.configure('''interface {intf}
                                switchport trunk allowed vlan {vlan}
                                interface {intf1}
                                switchport trunk allowed vlan none
                            '''.format(intf="po200", intf1=leaf6_tgn_1, vlan=vlan), timeout=60)
        except Exception as error:
            log.error("Unable to configure - Encountered Exception " + str(error))

    log.info('Waiting 10secs...')
    time.sleep(10)

def macmove_2_unconfigure(testscript, testbed, steps):
    LEAF1   = testbed.devices['node01']
    LEAF3   = testbed.devices['node03']
    LEAF6   = testbed.devices['node06']

    vlan = int(testscript.parameters['VPC_dict']['vlan_id'])
    
    with steps.start("Stopping clients"):
        release_client(testscript)
            
    with steps.start("Change the interface vlan for the mac move"):
        try:
            LEAF6.configure('''interface {intf}
                                switchport trunk allowed vlan {vlan}
                                interface {intf1}
                                switchport trunk allowed vlan none
                            '''.format(intf="po200", intf1="po210", vlan=vlan), timeout=60)
        except Exception as error:
            log.error("Unable to configure - Encountered Exception " + str(error))

    log.info('Waiting 10secs...')
    time.sleep(10)

# Configures FANOUT to send traffic through orphan port via fanout
def configure_fanout_orphan1(testscript, testbed, steps, stop=True):
    LEAF6   = testbed.devices['node06']

    vlan = int(testscript.parameters['VPC_dict']['vlan_id'])
    
    if stop:
        with steps.start("Stopping clients"):
            release_client(testscript)
    
    for interface in LEAF6.interfaces:
        if LEAF6.interfaces[interface].alias == 'nd06_nd01_1_5':
            leaf6_tgn_1 = interface
        if LEAF6.interfaces[interface].alias == 'nd06_nd01_1_6':
            leaf6_tgn_1_1 = interface
        if LEAF6.interfaces[interface].alias == 'nd06_nd01_1_7':
            leaf6_tgn_1_2 = interface
        if LEAF6.interfaces[interface].alias == 'nd06_nd01_1_8':
            leaf6_tgn_1_3 = interface
        if LEAF6.interfaces[interface].alias == 'nd06_nd03_1_1':
            leaf6_tgn_2 = interface
        if LEAF6.interfaces[interface].alias == 'nd06_nd02_1_5':
            leaf6_tgn_3 = interface
            
    with steps.start("Change the interface vlan for the mac move"):
        try:
            LEAF6.configure('''interface po200
                                switchport trunk allowed vlan none
                                interface po210
                                switchport trunk allowed vlan none
                                interface {intf}
                                switchport trunk allowed vlan none
                                interface {intf1}
                                switchport trunk allowed vlan none
                                interface {intf2_1}
                                switchport trunk allowed vlan none
                                interface {intf2_2}
                                switchport trunk allowed vlan none
                                interface {intf2_3}
                                switchport trunk allowed vlan none
                                interface {intf2}
                                switchport trunk allowed vlan {vlan}
                            '''.format(intf2=leaf6_tgn_1, intf2_1=leaf6_tgn_1_1, intf2_2=leaf6_tgn_1_2, 
                                       intf2_3=leaf6_tgn_1_3, intf1=leaf6_tgn_2, 
                                       intf=leaf6_tgn_3, vlan=vlan), timeout=60)
        except Exception as error:
            log.error("Unable to configure - Encountered Exception " + str(error))
    
    log.info("Waiting 10secs for config changes")
    time.sleep(10)

def configure_fanout_vpc(testscript, testbed, steps, stop=True):
    LEAF6   = testbed.devices['node06']

    vlan = int(testscript.parameters['VPC_dict']['vlan_id'])
    if stop:
        with steps.start("Stopping clients"):
            release_client(testscript)
    
    for interface in LEAF6.interfaces:
        if LEAF6.interfaces[interface].alias == 'nd06_nd01_1_5':
            leaf6_tgn_1 = interface
        if LEAF6.interfaces[interface].alias == 'nd06_nd01_1_6':
            leaf6_tgn_1_1 = interface
        if LEAF6.interfaces[interface].alias == 'nd06_nd01_1_7':
            leaf6_tgn_1_2 = interface
        if LEAF6.interfaces[interface].alias == 'nd06_nd01_1_8':
            leaf6_tgn_1_3 = interface
        if LEAF6.interfaces[interface].alias == 'nd06_nd03_1_1':
            leaf6_tgn_2 = interface
        if LEAF6.interfaces[interface].alias == 'nd06_nd02_1_5':
            leaf6_tgn_3 = interface

    with steps.start("Change the interface vlan for the mac move"):
        try:
            LEAF6.configure('''interface {intf}
                                switchport trunk allowed vlan none
                                interface {intf1}
                                switchport trunk allowed vlan none
                                interface {intf1_1}
                                switchport trunk allowed vlan none
                                interface {intf1_2}
                                switchport trunk allowed vlan none
                                interface {intf1_3}
                                switchport trunk allowed vlan none
                                interface {intf2}
                                switchport trunk allowed vlan none
                                interface po210
                                switchport trunk allowed vlan none
                                interface po200
                                switchport trunk allowed vlan {vlan}
                            '''.format(intf=leaf6_tgn_2, intf1=leaf6_tgn_1, intf1_1=leaf6_tgn_1_1,
                                       intf1_2=leaf6_tgn_1_2, intf1_3=leaf6_tgn_1_3,
                                       intf2=leaf6_tgn_3, vlan=vlan), timeout=60)
        except Exception as error:
            log.error("Unable to configure - Encountered Exception " + str(error))

    log.info('Waiting 10secs...')
    time.sleep(10)

# Configures FANOUT to send traffic through leaf3 port via fanout
def configure_fanout_to_leaf3(testscript, testbed, steps):
    LEAF1   = testbed.devices['node01']
    LEAF2   = testbed.devices['node02']
    LEAF3   = testbed.devices['node03']
    LEAF6   = testbed.devices['node06']
    
    vlan = int(testscript.parameters['VPC_dict']['vlan_id'])
    FAIL = False

    leaf6_tgn_1 = ''
    leaf6_tgn_2 = ''
    leaf3_tgn_1 = ''

    for interface in LEAF3.interfaces:
        if LEAF3.interfaces[interface].alias == 'nd03_nd06_1_1':
            leaf3_tgn_1 = interface
    
    for interface in LEAF1.interfaces:
        if LEAF1.interfaces[interface].alias == 'nd01_nd06_1_5':
            leaf1_tgn_1 = interface
    for interface in LEAF6.interfaces:
        if LEAF6.interfaces[interface].alias == 'nd06_nd01_1_5':
            leaf6_tgn_1 = interface
    for interface in LEAF6.interfaces:
        if LEAF6.interfaces[interface].alias == 'nd06_nd03_1_1':
            leaf6_tgn_2 = interface
    
    e_port = parsePort(leaf3_tgn_1)
    if not e_port:
        log.error("Not able to get the ethernet port")

    e_port1 = parsePort(leaf1_tgn_1)
    if not e_port1:
        log.error("Not able to get the ethernet port")
        
    with steps.start("Change the interface vlan for the mac move"):
        try:
            LEAF6.configure('''interface {intf}
                                switchport trunk allowed vlan none
                                interface {intf1}
                                switchport trunk allowed vlan {vlan}
                            '''.format(intf=leaf6_tgn_1, intf1=leaf6_tgn_2, vlan=vlan), timeout=60)
        except Exception as error:
            log.error("Unable to configure - Encountered Exception " + str(error))

def configure_macmove_5(testscript, testbed, steps):
    LEAF1   = testbed.devices['node01']
    LEAF2   = testbed.devices['node02']
    LEAF3   = testbed.devices['node03']
    LEAF6   = testbed.devices['node06']

    vlan = int(testscript.parameters['VPC_dict']['vlan_id'])

    leaf6_tgn_2 = ''
    leaf3_tgn_1 = ''

    for interface in LEAF3.interfaces:
        if LEAF3.interfaces[interface].alias == 'nd03_nd06_1_1':
            leaf3_tgn_1 = interface

    for interface in LEAF6.interfaces:
        if LEAF6.interfaces[interface].alias == 'nd06_nd03_1_1':
            leaf6_tgn_2 = interface
    
    e_port = parsePort(leaf3_tgn_1)
    if not e_port:
        log.error("Not able to get the ethernet port")

    with steps.start("Change the interface vlan for the mac move"):
        try:
            LEAF6.configure('''interface po200
                                switchport trunk allowed vlan none
                                interface {intf1}
                                switchport trunk allowed vlan {vlan}
                            '''.format(intf1=leaf6_tgn_2, vlan=vlan), timeout=60)
        except Exception as error:
            log.error("Unable to configure - Encountered Exception " + str(error))

    time.sleep(30)

def configure_macmove_6(testscript, testbed, steps):
    LEAF1   = testbed.devices['node01']
    LEAF2   = testbed.devices['node02']
    LEAF6   = testbed.devices['node06']
    
    vlan = int(testscript.parameters['VPC_dict']['vlan_id'])
    FAIL = False

    leaf6_tgn_1 = ''
    leaf6_tgn_2 = ''
    leaf2_tgn_1 = ''

    for interface in LEAF2.interfaces:
        if LEAF2.interfaces[interface].alias == 'nd02_nd06_1_5':
            leaf2_tgn_1 = interface
    
    for interface in LEAF1.interfaces:
        if LEAF1.interfaces[interface].alias == 'nd01_nd06_1_5':
            leaf1_tgn_1 = interface
    for interface in LEAF6.interfaces:
        if LEAF6.interfaces[interface].alias == 'nd06_nd01_1_5':
            leaf6_tgn_1 = interface
    for interface in LEAF6.interfaces:
        if LEAF6.interfaces[interface].alias == 'nd06_nd02_1_5':
            leaf6_tgn_2 = interface
    
    e_port = parsePort(leaf2_tgn_1)
    if not e_port:
        log.error("Not able to get the ethernet port")

    e_port1 = parsePort(leaf1_tgn_1)
    if not e_port1:
        log.error("Not able to get the ethernet port")
        
    with steps.start("Change the interface vlan for the mac move"):
        try:
            LEAF6.configure('''interface {intf}
                                switchport trunk allowed vlan none
                                interface {intf1}
                                switchport trunk allowed vlan {vlan}
                            '''.format(intf=leaf6_tgn_1, intf1=leaf6_tgn_2, vlan=vlan), timeout=60)
        except Exception as error:
            log.error("Unable to configure - Encountered Exception " + str(error))

    time.sleep(30)

def configure_macmove_7(testscript, testbed, steps):
    LEAF1   = testbed.devices['node01']
    LEAF2   = testbed.devices['node02']
    LEAF3   = testbed.devices['node03']
    LEAF6   = testbed.devices['node06']

    vlan = int(testscript.parameters['VPC_dict']['vlan_id'])

    leaf6_tgn_2 = ''
    leaf2_tgn_1 = ''

    for interface in LEAF2.interfaces:
        if LEAF2.interfaces[interface].alias == 'nd02_nd06_1_5':
            leaf2_tgn_1 = interface

    for interface in LEAF6.interfaces:
        if LEAF6.interfaces[interface].alias == 'nd06_nd02_1_5':
            leaf6_tgn_2 = interface
    
    e_port = parsePort(leaf2_tgn_1)
    if not e_port:
        log.error("Not able to get the ethernet port")

    with steps.start("Change the interface vlan for the mac move"):
        try:
            LEAF6.configure('''interface po200
                                switchport trunk allowed vlan none
                                interface {intf1}
                                switchport trunk allowed vlan {vlan}
                            '''.format(intf1=leaf6_tgn_2, vlan=vlan), timeout=60)
        except Exception as error:
            log.error("Unable to configure - Encountered Exception " + str(error))

    time.sleep(30)

def MACMOVE_4_B(section, testscript, testbed, steps):
        LEAF1   = testbed.devices['node01']
        LEAF2   = testbed.devices['node02']
        LEAF3   = testbed.devices['node03']
        LEAF6   = testbed.devices['node06']

        vpc_count = int(testscript.parameters['VPC_dict']['no_of_ints'])
        vlan = int(testscript.parameters['VPC_dict']['vlan_id'])
        FAIL = False

        leaf6_tgn_1 = ''
        leaf6_tgn_2 = ''
        leaf3_tgn_1 = ''

        for interface in LEAF3.interfaces:
            if LEAF3.interfaces[interface].alias == 'nd03_nd06_1_1':
                leaf3_tgn_1 = interface
        
        for interface in LEAF1.interfaces:
            if LEAF1.interfaces[interface].alias == 'nd01_nd06_1_5':
                leaf1_tgn_1 = interface
        for interface in LEAF6.interfaces:
            if LEAF6.interfaces[interface].alias == 'nd06_nd01_1_5':
                leaf6_tgn_1 = interface
        for interface in LEAF6.interfaces:
            if LEAF6.interfaces[interface].alias == 'nd06_nd03_1_1':
                leaf6_tgn_2 = interface
        
        e_port = parsePort(leaf3_tgn_1)
        if not e_port:
            log.error("Not able to get the ethernet port")
            section.failed("Not able to get the ethernet port")

        e_port1 = parsePort(leaf1_tgn_1)
        if not e_port1:
            log.error("Not able to get the ethernet port")
            section.failed("Not able to get the ethernet port")

        LEAF3.execute("show run interface {intf}".format(intf=leaf3_tgn_1))
        LEAF6.execute("show run interface {intf}".format(intf="po200"))
        LEAF6.execute("show run interface {intf}".format(intf="po210"))
        LEAF6.execute("show run interface {intf}".format(intf=leaf6_tgn_1))
        LEAF6.execute("show run interface {intf}".format(intf=leaf6_tgn_2))

        with steps.start("Verifying FHS entries on LEAF1"):
            cli = "show ip dhcp snooping binding evpn |  in {intf1} | count".format(intf1=leaf1_tgn_1)
            if int(LEAF1.execute(cli)) != vpc_count:
                log.debug("LEAF1: Snooping entries mismatch")
                FAIL = True
            
            cli = "show l2route fhs all |  in Eth{port} | count".format(port=e_port1)
            if int(LEAF1.execute(cli)) != vpc_count:
                log.debug("LEAF1: L2route entries mismatch")
                FAIL = True
            
            cli = "show forwarding route ipsg vrf all |  in {intf1} | count".format(intf1=leaf1_tgn_1)
            if int(LEAF1.execute(cli)) != vpc_count:
                log.debug("LEAF1: IPSG entries mismatch")
                FAIL = True
            
            cli = "show mac address-table dynamic | inc Eth{port} | count".format(port=e_port1)
            if int(LEAF1.execute(cli)) != vpc_count:
                log.debug("LEAF1: MAC entries mismatch")
                FAIL = True

            cli = "show ip arp vrf vrF-1 | inc Vlan{vlan} | count".format(vlan=vlan)
            if int(LEAF1.execute(cli)) != vpc_count:
                log.debug("LEAF1: ARP entries mismatch")
                FAIL = True

        with steps.start("Verifying FHS entries on LEAF2"):
            cli = "show ip dhcp snooping binding evpn |  in port-channel10 | count"
            if int(LEAF2.execute(cli)) != vpc_count:
                log.debug("LEAF2: Snooping entries mismatch")
                FAIL = True
            
            cli = "show l2route fhs all |  in Po10 | count"
            if int(LEAF2.execute(cli)) != vpc_count:
                log.debug("LEAF2: L2route entries mismatch")
                FAIL = True
            
            cli = "show mac address-table | inc dynamic | inc Peer-Link | count"
            if int(LEAF2.execute(cli)) != vpc_count:
                log.debug("LEAF2: MAC entries mismatch")
                FAIL = True

            cli = "show ip arp vrf vrF-1 | inc Vlan{vlan} | count".format(vlan=vlan)
            if int(LEAF2.execute(cli)) != vpc_count:
                log.debug("LEAF2: ARP entries mismatch")
                FAIL = True

        with steps.start("Verifying FHS entries on LEAF3"):
            cli = "show ip dhcp snooping binding evpn |  in {intf1} | count".format(intf1=leaf3_tgn_1)
            if int(LEAF3.execute(cli)) != 0:
                log.debug("LEAF3: Snooping entries mismatch")
                FAIL = True
            
            cli = "show l2route fhs all |  in Eth{port} | count".format(port=e_port)
            if int(LEAF3.execute(cli)) != 0:
                log.debug("LEAF3: L2route entries mismatch")
                FAIL = True
            
            cli = "show forwarding route ipsg vrf all |  in {intf1} | count".format(intf1=leaf3_tgn_1)
            if int(LEAF3.execute(cli)) != 0:
                log.debug("LEAF3: IPSG entries mismatch")
                FAIL = True
            
            cli = "show mac address-table dynamic | inc Eth{port} | count".format(port=e_port)
            if int(LEAF3.execute(cli)) != 0:
                log.debug("LEAF3: MAC entries mismatch")
                FAIL = True

            cli = "show ip arp vrf vrF-1 | inc Vlan{vlan} | count".format(vlan=vlan)
            if int(LEAF3.execute(cli)) != 0:
                log.debug("LEAF3: ARP entries mismatch")
                FAIL = True

        with steps.start("Verifying Remote FHS entries on LEAF1/2"):
            cli = "show ip dhcp snooping binding evpn | inc nve | inc {vlan} | count".format(vlan=vlan)
            if int(LEAF3.execute(cli)) != vpc_count:
                log.debug("LEAF1: Remote Snooping entries mismatch")
                FAIL = True
            if int(LEAF3.execute(cli)) != vpc_count:
                log.debug("LEAF2: Remote Snooping entries mismatch")
                FAIL = True
                
        with steps.start("Checking Complete FHS Validation"):
            if FAIL:
                section.failed("FHS Validation failed")
            else:
                log.info("FHS Validation Success")

def MACMOVE_5_B(section, testscript, testbed, steps):
        LEAF1   = testbed.devices['node01']
        LEAF2   = testbed.devices['node02']
        LEAF3   = testbed.devices['node03']
        LEAF6   = testbed.devices['node06']

        vpc_count = int(testscript.parameters['VPC_dict']['no_of_ints'])
        vlan = int(testscript.parameters['VPC_dict']['vlan_id'])
        FAIL = False

        leaf6_tgn_1 = ''
        leaf6_tgn_2 = ''
        leaf3_tgn_1 = ''

        for interface in LEAF3.interfaces:
            if LEAF3.interfaces[interface].alias == 'nd03_nd06_1_1':
                leaf3_tgn_1 = interface
        
        leaf1_tgn_1 = 'port-channel11'

        for interface in LEAF6.interfaces:
            if LEAF6.interfaces[interface].alias == 'nd06_nd01_1_5':
                leaf6_tgn_1 = interface
        for interface in LEAF6.interfaces:
            if LEAF6.interfaces[interface].alias == 'nd06_nd03_1_1':
                leaf6_tgn_2 = interface
        
        e_port = parsePort(leaf3_tgn_1)
        if not e_port:
            log.error("Not able to get the ethernet port")
            section.failed("Not able to get the ethernet port")

        LEAF3.execute("show run interface {intf}".format(intf=leaf3_tgn_1))
        LEAF6.execute("show run interface {intf}".format(intf="po200"))
        LEAF6.execute("show run interface {intf}".format(intf="po210"))
        LEAF6.execute("show run interface {intf}".format(intf=leaf6_tgn_1))
        LEAF6.execute("show run interface {intf}".format(intf=leaf6_tgn_2))

        with steps.start("Verifying FHS entries on LEAF1"):
            cli = "show ip dhcp snooping binding evpn |  in {intf1} | count".format(intf1=leaf1_tgn_1)
            if int(LEAF1.execute(cli)) != vpc_count:
                log.debug("LEAF1: Snooping entries mismatch")
                FAIL = True
            
            # cli = "show l2route fhs all |  in {port} | count".format(port='Po11')
            # if int(LEAF1.execute(cli)) != vpc_count:
            #     log.debug("LEAF1: L2route entries mismatch")
            #     FAIL = True
            
            cli = "show forwarding route ipsg vrf all |  in {intf1} | count".format(intf1=leaf1_tgn_1)
            if int(LEAF1.execute(cli)) != vpc_count:
                log.debug("LEAF1: IPSG entries mismatch")
                FAIL = True
            
            cli = "show mac address-table dynamic | inc {port} | count".format(port='Po11')
            if int(LEAF1.execute(cli)) != vpc_count:
                log.debug("LEAF1: MAC entries mismatch")
                FAIL = True

            cli = "show ip arp vrf vrF-1 | inc Vlan{vlan} | count".format(vlan=vlan)
            if int(LEAF1.execute(cli)) != vpc_count:
                log.debug("LEAF1: ARP entries mismatch")
                FAIL = True

        with steps.start("Verifying FHS entries on LEAF2"):
            cli = "show ip dhcp snooping binding evpn |  in port-channel11 | count"
            if int(LEAF2.execute(cli)) != vpc_count:
                log.debug("LEAF2: Snooping entries mismatch")
                FAIL = True
            
            # cli = "show l2route fhs all |  in Po11 | count"
            # if int(LEAF2.execute(cli)) != vpc_count:
            #     log.debug("LEAF2: L2route entries mismatch")
            #     FAIL = True
            
            cli = "show mac address-table | inc dynamic | inc Po11 | count"
            if int(LEAF2.execute(cli)) != vpc_count:
                log.debug("LEAF2: MAC entries mismatch")
                FAIL = True

            cli = "show ip arp vrf vrF-1 | inc Vlan{vlan} | count".format(vlan=vlan)
            if int(LEAF2.execute(cli)) != vpc_count:
                log.debug("LEAF2: ARP entries mismatch")
                FAIL = True

        with steps.start("Verifying FHS entries on LEAF3"):
            cli = "show ip dhcp snooping binding evpn |  in {intf1} | count".format(intf1=leaf3_tgn_1)
            if int(LEAF3.execute(cli)) != 0:
                log.debug("LEAF3: Snooping entries mismatch")
                FAIL = True
            
            # cli = "show l2route fhs all |  in Eth{port} | count".format(port=e_port)
            # if int(LEAF3.execute(cli)) != 0:
            #     log.debug("LEAF3: L2route entries mismatch")
            #     FAIL = True
            
            cli = "show forwarding route ipsg vrf all |  in {intf1} | count".format(intf1=leaf3_tgn_1)
            if int(LEAF3.execute(cli)) != 0:
                log.debug("LEAF3: IPSG entries mismatch")
                FAIL = True
            
            cli = "show mac address-table dynamic | inc Eth{port} | count".format(port=e_port)
            if int(LEAF3.execute(cli)) != 0:
                log.debug("LEAF3: MAC entries mismatch")
                FAIL = True

            cli = "show ip arp vrf vrF-1 | inc Vlan{vlan} | count".format(vlan=vlan)
            if int(LEAF3.execute(cli)) != 0:
                log.debug("LEAF3: ARP entries mismatch")
                FAIL = True

        with steps.start("Verifying Remote FHS entries on LEAF3"):
            cli = "show ip dhcp snooping binding evpn | inc nve | inc {vlan} | count".format(vlan=vlan)
            if int(LEAF3.execute(cli)) != vpc_count:
                log.debug("LEAF1: Remote Snooping entries mismatch")
                FAIL = True
            if int(LEAF3.execute(cli)) != vpc_count:
                log.debug("LEAF2: Remote Snooping entries mismatch")
                FAIL = True
                
        with steps.start("Checking Complete FHS Validation"):
            if FAIL:
                section.failed("FHS Validation failed")
            else:
                log.info("FHS Validation Success")

def MACMOVE_6_B(section, testscript, testbed, steps):
        LEAF1   = testbed.devices['node01']
        LEAF2   = testbed.devices['node02']
        LEAF3   = testbed.devices['node03']
        LEAF6   = testbed.devices['node06']

        vpc_count = int(testscript.parameters['VPC_dict']['no_of_ints'])
        vlan = int(testscript.parameters['VPC_dict']['vlan_id'])
        FAIL = False

        leaf6_tgn_1 = ''
        leaf6_tgn_2 = ''
        leaf2_tgn_1 = ''

        for interface in LEAF2.interfaces:
            if LEAF2.interfaces[interface].alias == 'nd02_nd06_1_5':
                leaf2_tgn_1 = interface
        
        for interface in LEAF1.interfaces:
            if LEAF1.interfaces[interface].alias == 'nd01_nd06_1_5':
                leaf1_tgn_1 = interface
        for interface in LEAF6.interfaces:
            if LEAF6.interfaces[interface].alias == 'nd06_nd01_1_5':
                leaf6_tgn_1 = interface
        for interface in LEAF6.interfaces:
            if LEAF6.interfaces[interface].alias == 'nd06_nd02_1_5':
                leaf6_tgn_2 = interface
        
        e_port = parsePort(leaf2_tgn_1)
        if not e_port:
            log.error("Not able to get the ethernet port")
            section.failed("Not able to get the ethernet port")

        e_port1 = parsePort(leaf1_tgn_1)
        if not e_port1:
            log.error("Not able to get the ethernet port")
            section.failed("Not able to get the ethernet port")

        LEAF1.execute("show run interface {intf}".format(intf=leaf2_tgn_1))
        LEAF6.execute("show run interface {intf}".format(intf="po200"))
        LEAF6.execute("show run interface {intf}".format(intf="po210"))
        LEAF6.execute("show run interface {intf}".format(intf=leaf6_tgn_1))
        LEAF6.execute("show run interface {intf}".format(intf=leaf6_tgn_2))

        with steps.start("Verifying FHS entries on LEAF1"):
            cli = "show ip dhcp snooping binding evpn |  in {intf1} | count".format(intf1=leaf1_tgn_1)
            if int(LEAF1.execute(cli)) != vpc_count:
                log.debug("LEAF1: Snooping entries mismatch")
                FAIL = True
            
            # cli = "show l2route fhs all |  in Eth{port} | count".format(port=e_port1)
            # if int(LEAF1.execute(cli)) != vpc_count:
            #     log.debug("LEAF1: L2route entries mismatch")
            #     FAIL = True
            
            cli = "show forwarding route ipsg vrf all |  in {intf1} | count".format(intf1=leaf1_tgn_1)
            if int(LEAF1.execute(cli)) != vpc_count:
                log.debug("LEAF1: IPSG entries mismatch")
                FAIL = True
            
            cli = "show mac address-table dynamic | inc Eth{port} | count".format(port=e_port1)
            if int(LEAF1.execute(cli)) != vpc_count:
                log.debug("LEAF1: MAC entries mismatch")
                FAIL = True

            cli = "show ip arp vrf vrF-1 | inc Vlan{vlan} | count".format(vlan=vlan)
            if int(LEAF1.execute(cli)) != vpc_count:
                log.debug("LEAF1: ARP entries mismatch")
                FAIL = True

        with steps.start("Verifying FHS entries on LEAF2"):
            cli = "show ip dhcp snooping binding evpn |  in port-channel10 | count"
            if int(LEAF2.execute(cli)) != vpc_count:
                log.debug("LEAF2: Snooping entries mismatch")
                FAIL = True
            
            # cli = "show l2route fhs all |  in Po10 | count"
            # if int(LEAF2.execute(cli)) != vpc_count:
            #     log.debug("LEAF2: L2route entries mismatch")
            #     FAIL = True
            
            cli = "show mac address-table | inc dynamic | inc Peer-Link | count"
            if int(LEAF2.execute(cli)) != vpc_count:
                log.debug("LEAF2: MAC entries mismatch")
                FAIL = True

            cli = "show ip arp vrf vrF-1 | inc Vlan{vlan} | count".format(vlan=vlan)
            if int(LEAF2.execute(cli)) != vpc_count:
                log.debug("LEAF2: ARP entries mismatch")
                FAIL = True

        with steps.start("Verifying Remote FHS entries on LEAF3"):
            cli = "show ip dhcp snooping binding evpn | inc nve | inc {vlan} | count".format(vlan=vlan)
            if int(LEAF3.execute(cli)) != vpc_count:
                log.debug("LEAF1: Remote Snooping entries mismatch")
                FAIL = True
            if int(LEAF3.execute(cli)) != vpc_count:
                log.debug("LEAF2: Remote Snooping entries mismatch")
                FAIL = True
                
        with steps.start("Checking Complete FHS Validation"):
            if FAIL:
                section.failed("FHS Validation failed")
            else:
                log.info("FHS Validation Success")

def MACMOVE_7_B(section, testscript, testbed, steps):
        LEAF1   = testbed.devices['node01']
        LEAF2   = testbed.devices['node02']
        LEAF3   = testbed.devices['node03']
        LEAF6   = testbed.devices['node06']

        vpc_count = int(testscript.parameters['VPC_dict']['no_of_ints'])
        vlan = int(testscript.parameters['VPC_dict']['vlan_id'])
        FAIL = False

        leaf6_tgn_1 = ''
        leaf6_tgn_2 = ''
        leaf2_tgn_1 = ''

        for interface in LEAF2.interfaces:
            if LEAF2.interfaces[interface].alias == 'nd02_nd06_1_5':
                leaf2_tgn_1 = interface
        
        leaf1_tgn_1 = 'port-channel11'

        for interface in LEAF6.interfaces:
            if LEAF6.interfaces[interface].alias == 'nd06_nd01_1_5':
                leaf6_tgn_1 = interface
        for interface in LEAF6.interfaces:
            if LEAF6.interfaces[interface].alias == 'nd06_nd02_1_5':
                leaf6_tgn_2 = interface
        
        e_port = parsePort(leaf2_tgn_1)
        if not e_port:
            log.error("Not able to get the ethernet port")
            section.failed("Not able to get the ethernet port")

        LEAF1.execute("show run interface {intf}".format(intf=leaf2_tgn_1))
        LEAF6.execute("show run interface {intf}".format(intf="po200"))
        LEAF6.execute("show run interface {intf}".format(intf="po210"))
        LEAF6.execute("show run interface {intf}".format(intf=leaf6_tgn_1))
        LEAF6.execute("show run interface {intf}".format(intf=leaf6_tgn_2))

        with steps.start("Verifying FHS entries on LEAF1"):
            cli = "show ip dhcp snooping binding evpn |  in {intf1} | count".format(intf1=leaf1_tgn_1)
            if int(LEAF1.execute(cli)) != vpc_count:
                log.debug("LEAF1: Snooping entries mismatch")
                FAIL = True
            
            # cli = "show l2route fhs all |  in {port} | count".format(port='Po11')
            # if int(LEAF1.execute(cli)) != vpc_count:
            #     log.debug("LEAF1: L2route entries mismatch")
            #     FAIL = True
            
            cli = "show forwarding route ipsg vrf all |  in {intf1} | count".format(intf1=leaf1_tgn_1)
            if int(LEAF1.execute(cli)) != vpc_count:
                log.debug("LEAF1: IPSG entries mismatch")
                FAIL = True
            
            cli = "show mac address-table dynamic | inc {port} | count".format(port='Po11')
            if int(LEAF1.execute(cli)) != vpc_count:
                log.debug("LEAF1: MAC entries mismatch")
                FAIL = True

            cli = "show ip arp vrf vrF-1 | inc Vlan{vlan} | count".format(vlan=vlan)
            if int(LEAF1.execute(cli)) != vpc_count:
                log.debug("LEAF1: ARP entries mismatch")
                FAIL = True

        with steps.start("Verifying FHS entries on LEAF2"):
            cli = "show ip dhcp snooping binding evpn |  in port-channel11 | count"
            if int(LEAF2.execute(cli)) != vpc_count:
                log.debug("LEAF2: Snooping entries mismatch")
                FAIL = True
            
            # cli = "show l2route fhs all |  in Po11 | count"
            # if int(LEAF2.execute(cli)) != vpc_count:
            #     log.debug("LEAF2: L2route entries mismatch")
            #     FAIL = True
            
            cli = "show mac address-table | inc dynamic | inc Po11 | count"
            if int(LEAF2.execute(cli)) != vpc_count:
                log.debug("LEAF2: MAC entries mismatch")
                FAIL = True

            cli = "show ip arp vrf vrF-1 | inc Vlan{vlan} | count".format(vlan=vlan)
            if int(LEAF2.execute(cli)) != vpc_count:
                log.debug("LEAF2: ARP entries mismatch")
                FAIL = True

        with steps.start("Verifying Remote FHS entries on LEAF3"):
            cli = "show ip dhcp snooping binding evpn | inc nve | inc {vlan} | count".format(vlan=vlan)
            if int(LEAF3.execute(cli)) != vpc_count:
                log.debug("LEAF1: Remote Snooping entries mismatch")
                FAIL = True
            if int(LEAF3.execute(cli)) != vpc_count:
                log.debug("LEAF2: Remote Snooping entries mismatch")
                FAIL = True
                
        with steps.start("Checking Complete FHS Validation"):
            if FAIL:
                section.failed("FHS Validation failed")
            else:
                log.info("FHS Validation Success")

def mac_move_7(section, testscript, testbed, steps):
    LEAF1   = testbed.devices['node01']
    LEAF2   = testbed.devices['node02']
    LEAF3   = testbed.devices['node03']
    LEAF6   = testbed.devices['node06']

    vpc_count = int(testscript.parameters['VPC_dict']['no_of_ints'])
    vlan = int(testscript.parameters['VPC_dict']['vlan_id'])
    FAIL = False

    leaf6_tgn_1 = ''
    leaf6_tgn_2 = ''
    leaf2_tgn_1 = ''

    for interface in LEAF2.interfaces:
        if LEAF2.interfaces[interface].alias == 'nd02_nd06_1_5':
            leaf2_tgn_1 = interface

    leaf1_tgn_1 = 'port-channel11'
    for interface in LEAF6.interfaces:
        if LEAF6.interfaces[interface].alias == 'nd06_nd01_1_5':
            leaf6_tgn_1 = interface
    for interface in LEAF6.interfaces:
        if LEAF6.interfaces[interface].alias == 'nd06_nd02_1_5':
            leaf6_tgn_2 = interface
    
    e_port = parsePort(leaf2_tgn_1)
    if not e_port:
        log.error("Not able to get the ethernet port")
        section.failed("Not able to get the ethernet port")

    LEAF2.execute("show run interface {intf}".format(intf=leaf2_tgn_1))
    LEAF6.execute("show run interface {intf}".format(intf="po200"))
    LEAF6.execute("show run interface {intf}".format(intf="po210"))
    LEAF6.execute("show run interface {intf}".format(intf=leaf6_tgn_1))
    LEAF6.execute("show run interface {intf}".format(intf=leaf6_tgn_2))

    with steps.start("Verifying FHS entries on LEAF1"):
        cli = "show ip dhcp snooping binding evpn |  in {intf1} | count".format(intf1=leaf1_tgn_1)
        if int(LEAF1.execute(cli)) != 0:
            log.debug("LEAF1: Snooping entries mismatch")
            FAIL = True
        
        # cli = "show l2route fhs all |  in {port} | count".format(port='Po11')
        # if int(LEAF1.execute(cli)) != 0:
        #     log.debug("LEAF1: L2route entries mismatch")
        #     FAIL = True
        
        cli = "show forwarding route ipsg vrf all |  in {intf1} | count".format(intf1=leaf1_tgn_1)
        if int(LEAF1.execute(cli)) != 0:
            log.debug("LEAF1: IPSG entries mismatch")
            FAIL = True
        
        # cli = "show mac address-table dynamic | inc {port} | count".format(port='Po11')
        # if int(LEAF1.execute(cli)) != 0:
        #     log.debug("LEAF1: MAC entries mismatch")
        #     FAIL = True

        cli = "show ip arp vrf vrF-1 | inc Vlan{vlan} | count".format(vlan=vlan)
        if int(LEAF1.execute(cli)) != vpc_count:
            log.debug("LEAF1: ARP entries mismatch")
            FAIL = True

    with steps.start("Verifying FHS entries on LEAF2"):
        cli = "show ip dhcp snooping binding evpn |  in {intf1} | count".format(intf1=leaf2_tgn_1)
        if int(LEAF2.execute(cli)) != vpc_count:
            log.debug("LEAF2: Snooping entries mismatch")
            FAIL = True
        
        # cli = "show l2route fhs all |  in Eth{port} | count".format(port=e_port)
        # if int(LEAF2.execute(cli)) != vpc_count:
        #     log.debug("LEAF2: L2route entries mismatch")
        #     FAIL = True
        
        cli = "show mac address-table | in Eth{port} | count".format(port=e_port)
        if int(LEAF2.execute(cli)) != vpc_count:
            log.debug("LEAF2: MAC entries mismatch")
            FAIL = True

        cli = "show ip arp vrf vrF-1 | inc Vlan{vlan} | count".format(vlan=vlan)
        if int(LEAF2.execute(cli)) != vpc_count:
            log.debug("LEAF2: ARP entries mismatch")
            FAIL = True

    with steps.start("Verifying Remote FHS entries on LEAF3"):
        cli = "show ip dhcp snooping binding evpn | inc nve | inc {vlan} | count".format(vlan=vlan)
        if int(LEAF3.execute(cli)) != vpc_count:
            log.debug("LEAF1: Remote Snooping entries mismatch")
            FAIL = True
        # cli = "show l2route fhs all | inc BGP | inc {vlan} | count".format(vlan=vlan)
        # if int(LEAF3.execute(cli)) != vpc_count:
        #     log.debug("LEAF3: Remote L2route entries mismatch")
        #     FAIL = True
    with steps.start("Checking Complete FHS Validation"):
        if FAIL:
            section.failed("FHS Validation failed")
        else:
            log.info("FHS Validation Success")

# clients move between leaf1 orphan port and vPC port
class MACMOVE_1(aetest.Testcase):
    @aetest.test
    def client_move_from_orphan_to_vpc(self, testscript, testbed, steps):
        LEAF1   = testbed.devices['node01']
        LEAF2   = testbed.devices['node02']
        LEAF3   = testbed.devices['node03']
        LEAF6   = testbed.devices['node06']

        handle = testscript.parameters['vpc_client1_handle']
        vpc_count = int(testscript.parameters['VPC_dict']['no_of_ints'])
        vlan = int(testscript.parameters['VPC_dict']['vlan_id'])
        
        FAIL = False
        
        for interface in LEAF1.interfaces:
            if LEAF1.interfaces[interface].alias == 'nd01_nd06_1_5':
                leaf1_tgn_1 = interface

        for interface in LEAF6.interfaces:
            if LEAF6.interfaces[interface].alias == 'nd06_nd01_1_5':
                leaf6_tgn_1 = interface
        
        e_port = parsePort(leaf1_tgn_1)
        if not e_port:
            log.error("Not able to get the ethernet port")
            self.failed("Not able to get the ethernet port")

        LEAF1.execute("show run interface {intf}".format(intf=leaf1_tgn_1))
        LEAF6.execute("show run interface {intf}".format(intf="po200"))
        LEAF6.execute("show run interface {intf}".format(intf="po210"))
        LEAF6.execute("show run interface {intf}".format(intf=leaf6_tgn_1))

        with steps.start("Change the interface vlan for the mac move"):
            try:
                LEAF6.configure('''interface {intf}
                                  switchport trunk allowed vlan none
                                  interface {intf1}
                                  switchport trunk allowed vlan none
                                  interface {intf2}
                                  switchport trunk allowed vlan {vlan}
                                '''.format(intf="po200", intf1="po210", intf2=leaf6_tgn_1, 
                                           vlan=vlan), timeout=60)
            except Exception as error:
                log.debug("Unable to configure - Encountered Exception " + str(error))
                self.errored('Unable to configure - Encountered Exception')

        log.info('Waiting 10secs...')
        time.sleep(10)
        
        with steps.start("Sending ARP for host move"):
            send_arp(handle)
        
        log.info('Waiting 30secs...')
        time.sleep(30)
        
        with steps.start("Verifying FHS entries on LEAF1"):
            cli = "show ip dhcp snooping binding evpn |  in {intf1} | count".format(intf1=leaf1_tgn_1)
            if int(LEAF1.execute(cli)) != vpc_count:
                log.debug("LEAF1: Snooping entries mismatch")
                FAIL = True
            
            # cli = "show l2route fhs all |  in Eth{port} | count".format(port=e_port)
            # if int(LEAF1.execute(cli)) != vpc_count:
            #     log.debug("LEAF1: L2route entries mismatch")
            #     FAIL = True
            
            cli = "show forwarding route ipsg vrf all |  in {intf1} | count".format(intf1=leaf1_tgn_1)
            if int(LEAF1.execute(cli)) != vpc_count:
                log.debug("LEAF1: IPSG entries mismatch")
                FAIL = True
            
            cli = "show mac address-table dynamic | inc Eth{port} | count".format(port=e_port)
            if int(LEAF1.execute(cli)) != vpc_count:
                log.debug("LEAF1: MAC entries mismatch")
                FAIL = True

            cli = "show ip arp vrf vrF-1 | inc Vlan{vlan} | count".format(vlan=vlan)
            if int(LEAF1.execute(cli)) != vpc_count:
                log.debug("LEAF1: ARP entries mismatch")
                FAIL = True

        with steps.start("Verifying FHS entries on LEAF2"):
            cli = "show ip dhcp snooping binding evpn |  in port-channel10 | count"
            if int(LEAF2.execute(cli)) != vpc_count:
                log.debug("LEAF2: Snooping entries mismatch")
                FAIL = True
            
            # cli = "show l2route fhs all |  in Po10 | count"
            # if int(LEAF2.execute(cli)) != vpc_count:
            #     log.debug("LEAF2: L2route entries mismatch")
            #     FAIL = True
            
            cli = "show mac address-table | inc dynamic | inc Peer-Link | count"
            if int(LEAF2.execute(cli)) != vpc_count:
                log.debug("LEAF2: MAC entries mismatch")
                FAIL = True

            cli = "show ip arp vrf vrF-1 | inc Vlan{vlan} | count".format(vlan=vlan)
            if int(LEAF2.execute(cli)) != vpc_count:
                log.debug("LEAF2: ARP entries mismatch")
                FAIL = True

        with steps.start("Verifying Remote FHS entries on LEAF3"):
            cli = "show ip dhcp snooping binding evpn | inc nve | inc {vlan} | count".format(vlan=vlan)
            if int(LEAF3.execute(cli)) != vpc_count:
                log.debug("LEAF3: Remote Snooping entries mismatch")
                FAIL = True
            
            # cli = "show l2route fhs all | inc BGP | inc {vlan} | count".format(vlan=vlan)
            # if int(LEAF3.execute(cli)) != vpc_count:
            #     log.debug("LEAF3: Remote L2route entries mismatch")
            #     FAIL = True
            
        with steps.start("Checking Complete FHS Validation"):
            if FAIL:
                self.failed("FHS Validation failed")
            else:
                log.info("FHS Validation Success")
    
# clients move between leaf1 vPC ports
class MACMOVE_2(aetest.Testcase):
    @aetest.test
    def client_move_between_vpc(self, testscript, testbed, steps):
        LEAF1   = testbed.devices['node01']
        LEAF2   = testbed.devices['node02']
        LEAF3   = testbed.devices['node03']
        LEAF6   = testbed.devices['node06']

        handle = testscript.parameters['vpc_client1_handle']
        vpc_count = int(testscript.parameters['VPC_dict']['no_of_ints'])
        vlan = int(testscript.parameters['VPC_dict']['vlan_id'])
        FAIL = False
                
        with steps.start("Change the interface vlan for the mac move"):
            try:
                LEAF6.configure('''interface {intf}
                                  switchport trunk allowed vlan none
                                  interface {intf1}
                                  switchport trunk allowed vlan {vlan}
                                '''.format(intf="po200", intf1="po210", vlan=vlan))
            except Exception as error:
                log.debug("Unable to configure - Encountered Exception " + str(error))
                self.errored('Unable to configure - Encountered Exception')

        log.info('Waiting 10secs...')
        time.sleep(10)
        
        with steps.start("Sending ARP for host move"):
            send_arp(handle)
        
        with steps.start("Verifying FHS entries on LEAF1"):
            cli = "show ip dhcp snooping binding evpn |  in {intf1} | count".format(intf1="port-channel110")
            if int(LEAF1.execute(cli)) != vpc_count:
                log.debug("LEAF1: Snooping entries mismatch")
                FAIL = True
            
            # cli = "show l2route fhs all |  in Po110 | count"
            # if int(LEAF1.execute(cli)) != vpc_count:
            #     log.debug("LEAF1: L2route entries mismatch")
            #     FAIL = True
            
            cli = "show forwarding route ipsg vrf all |  in port-channel110 | count"
            if int(LEAF1.execute(cli)) != vpc_count:
                log.debug("LEAF1: IPSG entries mismatch")
                FAIL = True
            
            cli = "show mac address-table dynamic | inc Po110 | count"
            if int(LEAF1.execute(cli)) != vpc_count:
                log.debug("LEAF1: MAC entries mismatch")
                FAIL = True

            cli = "show ip arp vrf vrF-1 | inc Vlan{vlan} | count".format(vlan=vlan)
            if int(LEAF1.execute(cli)) != vpc_count:
                log.debug("LEAF1: ARP entries mismatch")
                FAIL = True

        with steps.start("Verifying FHS entries on LEAF2"):
            cli = "show ip dhcp snooping binding evpn |  in port-channel110 | count"
            if int(LEAF2.execute(cli)) != vpc_count:
                log.debug("LEAF2: Snooping entries mismatch")
                FAIL = True
            
            # cli = "show l2route fhs all |  in Po10 | count"
            # if int(LEAF2.execute(cli)) != 0:
            #     log.debug("LEAF2: L2route entries mismatch")
            #     FAIL = True
            
            cli = "show forwarding route ipsg vrf all |  in port-channel110 | count"
            if int(LEAF2.execute(cli)) != vpc_count:
                log.debug("LEAF2: IPSG entries mismatch")
                FAIL = True
            
            cli = "show mac address-table dynamic | inc Po110 | count"
            if int(LEAF2.execute(cli)) != vpc_count:
                log.debug("LEAF2: MAC entries mismatch")
                FAIL = True

            cli = "show ip arp vrf vrF-1 | inc Vlan{vlan} | count".format(vlan=vlan)
            if int(LEAF2.execute(cli)) != vpc_count:
                log.debug("LEAF2: ARP entries mismatch")
                FAIL = True

        with steps.start("Verifying Remote FHS entries on LEAF3"):
            cli = "show ip dhcp snooping binding evpn | inc nve | inc {vlan} | count".format(vlan=vlan)
            if int(LEAF3.execute(cli)) != vpc_count:
                log.debug("LEAF3: Remote Snooping entries mismatch")
                FAIL = True
            
            # cli = "show l2route fhs all | inc BGP | inc {vlan} | count".format(vlan=vlan)
            # if int(LEAF3.execute(cli)) != vpc_count:
            #     log.debug("LEAF3: Remote L2route entries mismatch")
            #     FAIL = True

        with steps.start("Checking Complete FHS Validation"):
            if FAIL:
                self.failed("FHS Validation failed")
            else:
                log.info("FHS Validation Success")

# clients move between leaf1 orphan ports
class MACMOVE_3(aetest.Testcase):
    @aetest.test
    def client_move_between_orphan(self, testscript, testbed, steps):
        LEAF1   = testbed.devices['node01']
        LEAF2   = testbed.devices['node02']
        LEAF3   = testbed.devices['node03']
        LEAF6   = testbed.devices['node06']

        handle = testscript.parameters['vpc_client1_handle']
        vpc_count = int(testscript.parameters['VPC_dict']['no_of_ints'])
        vlan = int(testscript.parameters['VPC_dict']['vlan_id'])
        FAIL = False
        
        for interface in LEAF1.interfaces:
            if LEAF1.interfaces[interface].alias == 'nd01_nd06_1_6':
                leaf1_tgn_1 = interface

        for interface in LEAF6.interfaces:
            if LEAF6.interfaces[interface].alias == 'nd06_nd01_1_5':
                leaf6_tgn_1 = interface
        for interface in LEAF6.interfaces:
            if LEAF6.interfaces[interface].alias == 'nd06_nd01_1_6':
                leaf6_tgn_2 = interface
        
        e_port = parsePort(leaf1_tgn_1)
        if not e_port:
            log.error("Not able to get the ethernet port")
            self.failed("Not able to get the ethernet port")
            
        with steps.start("Change the interface vlan for the mac move"):
            try:
                LEAF6.configure('''interface {intf}
                                  switchport trunk allowed vlan none
                                  interface {intf1}
                                  switchport trunk allowed vlan {vlan}
                                '''.format(intf=leaf6_tgn_1, intf1=leaf6_tgn_2, vlan=vlan), timeout=60)
            except Exception as error:
                log.debug("Unable to configure - Encountered Exception " + str(error))
                self.errored('Unable to configure - Encountered Exception')

        log.info('Waiting 10secs...')
        time.sleep(10)
        
        with steps.start("Sending ARP for host move"):
            send_arp(handle)
        
        with steps.start("Verifying FHS entries on LEAF1"):
            cli = "show ip dhcp snooping binding evpn |  in {intf1} | count".format(intf1=leaf1_tgn_1)
            if int(LEAF1.execute(cli)) != vpc_count:
                log.debug("LEAF1: Snooping entries mismatch")
                FAIL = True
            
            # cli = "show l2route fhs all |  in Eth{port} | count".format(port=e_port)
            # if int(LEAF1.execute(cli)) != vpc_count:
            #     log.debug("LEAF1: L2route entries mismatch")
            #     FAIL = True
            
            cli = "show forwarding route ipsg vrf all |  in {intf1} | count".format(intf1=leaf1_tgn_1)
            if int(LEAF1.execute(cli)) != vpc_count:
                log.debug("LEAF1: IPSG entries mismatch")
                FAIL = True
            
            cli = "show mac address-table dynamic | inc Eth{port} | count".format(port=e_port)
            if int(LEAF1.execute(cli)) != vpc_count:
                log.debug("LEAF1: MAC entries mismatch")
                FAIL = True

            cli = "show ip arp vrf vrF-1 | inc Vlan{vlan} | count".format(vlan=vlan)
            if int(LEAF1.execute(cli)) != vpc_count:
                log.debug("LEAF1: ARP entries mismatch")
                FAIL = True

        with steps.start("Verifying FHS entries on LEAF2"):
            cli = "show ip dhcp snooping binding evpn |  in port-channel10 | count"
            if int(LEAF2.execute(cli)) != vpc_count:
                log.debug("LEAF2: Snooping entries mismatch")
                FAIL = True
            
            # cli = "show l2route fhs all |  in Po10 | count"
            # if int(LEAF2.execute(cli)) != vpc_count:
            #     log.debug("LEAF2: L2route entries mismatch")
            #     FAIL = True
            
            cli = "show mac address-table | inc dynamic | inc Peer-Link | count"
            if int(LEAF2.execute(cli)) != vpc_count:
                log.debug("LEAF2: MAC entries mismatch")
                FAIL = True

            cli = "show ip arp vrf vrF-1 | inc Vlan{vlan} | count".format(vlan=vlan)
            if int(LEAF2.execute(cli)) != vpc_count:
                log.debug("LEAF2: ARP entries mismatch")
                FAIL = True

        with steps.start("Verifying Remote FHS entries on LEAF3"):
            cli = "show ip dhcp snooping binding evpn | inc nve | inc {vlan} | count".format(vlan=vlan)
            if int(LEAF3.execute(cli)) != vpc_count:
                log.debug("LEAF3: Remote Snooping entries mismatch")
                FAIL = True
            
            # cli = "show l2route fhs all | inc BGP | inc {vlan} | count".format(vlan=vlan)
            # if int(LEAF3.execute(cli)) != vpc_count:
            #     log.debug("LEAF3: Remote L2route entries mismatch")
            #     FAIL = True
            
        with steps.start("Checking Complete FHS Validation"):
            if FAIL:
                self.failed("FHS Validation failed")
            else:
                log.info("FHS Validation Success")

# clients move between leaf1 orphan and leaf3 orphan
class MACMOVE_4(aetest.Testcase):
    @aetest.test
    def MACMOVE_4(self, testscript, testbed, steps):
        LEAF1   = testbed.devices['node01']
        LEAF2   = testbed.devices['node02']
        LEAF3   = testbed.devices['node03']
        LEAF6   = testbed.devices['node06']

        handle = testscript.parameters['vpc_client1_handle']
        vpc_count = int(testscript.parameters['VPC_dict']['no_of_ints'])
        vlan = int(testscript.parameters['VPC_dict']['vlan_id'])
        FAIL = False

        leaf6_tgn_1 = ''
        leaf6_tgn_2 = ''
        leaf3_tgn_1 = ''

        for interface in LEAF3.interfaces:
            if LEAF3.interfaces[interface].alias == 'nd03_nd06_1_1':
                leaf3_tgn_1 = interface
        
        for interface in LEAF1.interfaces:
            if LEAF1.interfaces[interface].alias == 'nd01_nd06_1_5':
                leaf1_tgn_1 = interface
        for interface in LEAF6.interfaces:
            if LEAF6.interfaces[interface].alias == 'nd06_nd01_1_5':
                leaf6_tgn_1 = interface
        for interface in LEAF6.interfaces:
            if LEAF6.interfaces[interface].alias == 'nd06_nd03_1_1':
                leaf6_tgn_2 = interface
        
        e_port = parsePort(leaf3_tgn_1)
        if not e_port:
            log.error("Not able to get the ethernet port")
            self.failed("Not able to get the ethernet port")

        e_port1 = parsePort(leaf1_tgn_1)
        if not e_port1:
            log.error("Not able to get the ethernet port")
            self.failed("Not able to get the ethernet port")
            
        LEAF3.execute("show run interface {intf}".format(intf=leaf3_tgn_1))
        LEAF6.execute("show run interface {intf}".format(intf="po200"))
        LEAF6.execute("show run interface {intf}".format(intf="po210"))
        LEAF6.execute("show run interface {intf}".format(intf=leaf6_tgn_1))
        LEAF6.execute("show run interface {intf}".format(intf=leaf6_tgn_2))

        with steps.start("Verifying FHS entries on LEAF1"):
            cli = "show ip dhcp snooping binding evpn |  in {intf1} | count".format(intf1=leaf1_tgn_1)
            if int(LEAF1.execute(cli)) != 0:
                log.debug("LEAF1: Snooping entries mismatch")
                FAIL = True
            
            cli = "show l2route fhs all |  in Eth{port} | count".format(port=e_port1)
            if int(LEAF1.execute(cli)) != 0:
                log.debug("LEAF1: L2route entries mismatch")
                FAIL = True
            
            cli = "show forwarding route ipsg vrf all |  in {intf1} | count".format(intf1=leaf1_tgn_1)
            if int(LEAF1.execute(cli)) != 0:
                log.debug("LEAF1: IPSG entries mismatch")
                FAIL = True
            
            cli = "show mac address-table dynamic | inc Eth{port} | count".format(port=e_port1)
            if int(LEAF1.execute(cli)) != 0:
                log.debug("LEAF1: MAC entries mismatch")
                FAIL = True

            cli = "show ip arp vrf vrF-1 | inc Vlan{vlan} | count".format(vlan=vlan)
            if int(LEAF1.execute(cli)) != 0:
                log.debug("LEAF1: ARP entries mismatch")
                FAIL = True

        with steps.start("Verifying FHS entries on LEAF2"):
            cli = "show ip dhcp snooping binding evpn |  in port-channel10 | count"
            if int(LEAF2.execute(cli)) != 0:
                log.debug("LEAF2: Snooping entries mismatch")
                FAIL = True
            
            cli = "show l2route fhs all |  in Po10 | count"
            if int(LEAF2.execute(cli)) != 0:
                log.debug("LEAF2: L2route entries mismatch")
                FAIL = True
            
            cli = "show mac address-table | inc dynamic | inc Peer-Link | count"
            if int(LEAF2.execute(cli)) != 0:
                log.debug("LEAF2: MAC entries mismatch")
                FAIL = True

            cli = "show ip arp vrf vrF-1 | inc Vlan{vlan} | count".format(vlan=vlan)
            if int(LEAF2.execute(cli)) != 0:
                log.debug("LEAF2: ARP entries mismatch")
                FAIL = True

        with steps.start("Verifying FHS entries on LEAF3"):
            cli = "show ip dhcp snooping binding evpn |  in {intf1} | count".format(intf1=leaf3_tgn_1)
            if int(LEAF3.execute(cli)) != vpc_count:
                log.debug("LEAF3: Snooping entries mismatch")
                FAIL = True
            
            cli = "show l2route fhs all |  in Eth{port} | count".format(port=e_port)
            if int(LEAF3.execute(cli)) != vpc_count:
                log.debug("LEAF3: L2route entries mismatch")
                FAIL = True
            
            cli = "show forwarding route ipsg vrf all |  in {intf1} | count".format(intf1=leaf3_tgn_1)
            if int(LEAF3.execute(cli)) != vpc_count:
                log.debug("LEAF3: IPSG entries mismatch")
                FAIL = True
            
            cli = "show mac address-table dynamic | inc Eth{port} | count".format(port=e_port)
            if int(LEAF3.execute(cli)) != vpc_count:
                log.debug("LEAF3: MAC entries mismatch")
                FAIL = True

            cli = "show ip arp vrf vrF-1 | inc Vlan{vlan} | count".format(vlan=vlan)
            if int(LEAF3.execute(cli)) != vpc_count:
                log.debug("LEAF3: ARP entries mismatch")
                FAIL = True

        with steps.start("Verifying Remote FHS entries on LEAF1/2"):
            cli = "show ip dhcp snooping binding evpn | inc nve | inc {vlan} | count".format(vlan=vlan)
            if int(LEAF1.execute(cli)) != vpc_count+vpc_count:
                log.debug("LEAF1: Remote Snooping entries mismatch")
                FAIL = True
            if int(LEAF2.execute(cli)) != vpc_count+vpc_count:
                log.debug("LEAF2: Remote Snooping entries mismatch")
                FAIL = True
                
            cli = "show l2route fhs all | inc BGP | inc {vlan} | count".format(vlan=vlan)
            if int(LEAF1.execute(cli)) != vpc_count+vpc_count:
                log.debug("LEAF1: Remote L2route entries mismatch")
                FAIL = True
            if int(LEAF2.execute(cli)) != vpc_count+vpc_count:
                log.debug("LEAF2: Remote L2route entries mismatch")
                FAIL = True

        with steps.start("Checking Complete FHS Validation"):
            if FAIL:
                self.failed("FHS Validation failed")
            else:
                log.info("FHS Validation Success")

# clients move between vpc and leaf3 orphan
class MACMOVE_5(aetest.Testcase):
    @aetest.test
    def MACMOVE_5(self, testscript, testbed, steps):
        LEAF1   = testbed.devices['node01']
        LEAF2   = testbed.devices['node02']
        LEAF3   = testbed.devices['node03']
        LEAF6   = testbed.devices['node06']

        vpc_count = int(testscript.parameters['VPC_dict']['no_of_ints'])
        vlan = int(testscript.parameters['VPC_dict']['vlan_id'])
        FAIL = False

        leaf6_tgn_1 = ''
        leaf6_tgn_2 = ''
        leaf3_tgn_1 = ''

        for interface in LEAF3.interfaces:
            if LEAF3.interfaces[interface].alias == 'nd03_nd06_1_1':
                leaf3_tgn_1 = interface
    
        leaf1_tgn_1 = 'port-channel11'
        for interface in LEAF6.interfaces:
            if LEAF6.interfaces[interface].alias == 'nd06_nd01_1_5':
                leaf6_tgn_1 = interface
        for interface in LEAF6.interfaces:
            if LEAF6.interfaces[interface].alias == 'nd06_nd03_1_1':
                leaf6_tgn_2 = interface
        
        e_port = parsePort(leaf3_tgn_1)
        if not e_port:
            log.error("Not able to get the ethernet port")
            self.failed("Not able to get the ethernet port")

        LEAF3.execute("show run interface {intf}".format(intf=leaf3_tgn_1))
        LEAF6.execute("show run interface {intf}".format(intf="po200"))
        LEAF6.execute("show run interface {intf}".format(intf="po210"))
        LEAF6.execute("show run interface {intf}".format(intf=leaf6_tgn_1))
        LEAF6.execute("show run interface {intf}".format(intf=leaf6_tgn_2))

        with steps.start("Verifying FHS entries on LEAF1"):
            cli = "show ip dhcp snooping binding evpn |  in {intf1} | count".format(intf1=leaf1_tgn_1)
            if int(LEAF1.execute(cli)) != 0:
                log.debug("LEAF1: Snooping entries mismatch")
                FAIL = True
            
            # cli = "show l2route fhs all |  in {port} | count".format(port='Po11')
            # if int(LEAF1.execute(cli)) != 0:
            #     log.debug("LEAF1: L2route entries mismatch")
            #     FAIL = True
            
            cli = "show forwarding route ipsg vrf all |  in {intf1} | count".format(intf1=leaf1_tgn_1)
            if int(LEAF1.execute(cli)) != 0:
                log.debug("LEAF1: IPSG entries mismatch")
                FAIL = True
            
            cli = "show mac address-table dynamic | inc {port} | count".format(port='Po11')
            if int(LEAF1.execute(cli)) != 0:
                log.debug("LEAF1: MAC entries mismatch")
                FAIL = True

            cli = "show ip arp vrf vrF-1 | inc Vlan{vlan} | count".format(vlan=vlan)
            if int(LEAF1.execute(cli)) != 0:
                log.debug("LEAF1: ARP entries mismatch")
                FAIL = True

        with steps.start("Verifying FHS entries on LEAF2"):
            cli = "show ip dhcp snooping binding evpn |  in port-channel11 | count"
            if int(LEAF2.execute(cli)) != 0:
                log.debug("LEAF2: Snooping entries mismatch")
                FAIL = True
            
            # cli = "show l2route fhs all |  in Po11 | count"
            # if int(LEAF2.execute(cli)) != 0:
            #     log.debug("LEAF2: L2route entries mismatch")
            #     FAIL = True
            
            cli = "show mac address-table | inc dynamic | inc Peer-Link | count"
            if int(LEAF2.execute(cli)) != 0:
                log.debug("LEAF2: MAC entries mismatch")
                FAIL = True

            cli = "show ip arp vrf vrF-1 | inc Vlan{vlan} | count".format(vlan=vlan)
            if int(LEAF2.execute(cli)) != 0:
                log.debug("LEAF2: ARP entries mismatch")
                FAIL = True

        with steps.start("Verifying FHS entries on LEAF3"):
            cli = "show ip dhcp snooping binding evpn |  in {intf1} | count".format(intf1=leaf3_tgn_1)
            if int(LEAF3.execute(cli)) != vpc_count:
                log.debug("LEAF3: Snooping entries mismatch")
                FAIL = True
            
            # cli = "show l2route fhs all |  in Eth{port} | count".format(port=e_port)
            # if int(LEAF3.execute(cli)) != vpc_count:
            #     log.debug("LEAF3: L2route entries mismatch")
            #     FAIL = True
            
            cli = "show forwarding route ipsg vrf all |  in {intf1} | count".format(intf1=leaf3_tgn_1)
            if int(LEAF3.execute(cli)) != vpc_count:
                log.debug("LEAF3: IPSG entries mismatch")
                FAIL = True
            
            cli = "show mac address-table dynamic | inc Eth{port} | count".format(port=e_port)
            if int(LEAF3.execute(cli)) != vpc_count:
                log.debug("LEAF3: MAC entries mismatch")
                FAIL = True

            cli = "show ip arp vrf vrF-1 | inc Vlan{vlan} | count".format(vlan=vlan)
            if int(LEAF3.execute(cli)) != vpc_count:
                log.debug("LEAF3: ARP entries mismatch")
                FAIL = True

        with steps.start("Verifying Remote FHS entries on LEAF1/2"):
            cli = "show ip dhcp snooping binding evpn | inc nve | inc {vlan} | count".format(vlan=vlan)
            if int(LEAF1.execute(cli)) != vpc_count+vpc_count:
                log.debug("LEAF1: Remote Snooping entries mismatch")
                FAIL = True
            if int(LEAF2.execute(cli)) != vpc_count+vpc_count:
                log.debug("LEAF2: Remote Snooping entries mismatch")
                FAIL = True

            # cli = "show l2route fhs all | inc BGP | inc {vlan} | count".format(vlan=vlan)
            # if int(LEAF1.execute(cli)) != vpc_count+vpc_count:
            #     log.debug("LEAF1: Remote L2route entries mismatch")
            #     FAIL = True
            if int(LEAF2.execute(cli)) != vpc_count+vpc_count:
                log.debug("LEAF2: Remote L2route entries mismatch")
                FAIL = True

        with steps.start("Checking Complete FHS Validation"):
            if FAIL:
                self.failed("FHS Validation failed")
            else:
                log.info("FHS Validation Success")
                
# clients move between leaf1 orphan and leaf2 orphan
class MACMOVE_6(aetest.Testcase):
    @aetest.test
    def MACMOVE_6(self, testscript, testbed, steps):
        LEAF1   = testbed.devices['node01']
        LEAF2   = testbed.devices['node02']
        LEAF3   = testbed.devices['node03']
        LEAF6   = testbed.devices['node06']

        handle = testscript.parameters['vpc_client1_handle']
        vpc_count = int(testscript.parameters['VPC_dict']['no_of_ints'])
        vlan = int(testscript.parameters['VPC_dict']['vlan_id'])
        FAIL = False

        leaf6_tgn_1 = ''
        leaf6_tgn_2 = ''
        leaf2_tgn_1 = ''

        for interface in LEAF2.interfaces:
            if LEAF2.interfaces[interface].alias == 'nd02_nd06_1_5':
                leaf2_tgn_1 = interface
        
        for interface in LEAF1.interfaces:
            if LEAF1.interfaces[interface].alias == 'nd01_nd06_1_5':
                leaf1_tgn_1 = interface
        for interface in LEAF6.interfaces:
            if LEAF6.interfaces[interface].alias == 'nd06_nd01_1_5':
                leaf6_tgn_1 = interface
        for interface in LEAF6.interfaces:
            if LEAF6.interfaces[interface].alias == 'nd06_nd02_1_5':
                leaf6_tgn_2 = interface
        
        e_port = parsePort(leaf2_tgn_1)
        if not e_port:
            log.error("Not able to get the ethernet port")
            self.failed("Not able to get the ethernet port")

        e_port1 = parsePort(leaf1_tgn_1)
        if not e_port1:
            log.error("Not able to get the ethernet port")
            self.failed("Not able to get the ethernet port")
            
        LEAF2.execute("show run interface {intf}".format(intf=leaf2_tgn_1))
        LEAF6.execute("show run interface {intf}".format(intf="po200"))
        LEAF6.execute("show run interface {intf}".format(intf="po210"))
        LEAF6.execute("show run interface {intf}".format(intf=leaf6_tgn_1))
        LEAF6.execute("show run interface {intf}".format(intf=leaf6_tgn_2))

        with steps.start("Verifying FHS entries on LEAF1"):
            cli = "show ip dhcp snooping binding evpn |  inc {intf1} | count".format(intf1='port-channel10')
            if int(LEAF1.execute(cli)) != vpc_count:
                log.debug("LEAF1: Snooping entries mismatch")
                FAIL = True
            
            # cli = "show l2route fhs all |  in {port} | count".format(port='Po10')
            # if int(LEAF1.execute(cli)) != vpc_count:
            #     log.debug("LEAF1: L2route entries mismatch")
            #     FAIL = True
            
            cli = "show forwarding route ipsg vrf all |  in {intf1} | count".format(intf1=leaf1_tgn_1)
            if int(LEAF1.execute(cli)) != 0:
                log.debug("LEAF1: IPSG entries mismatch")
                FAIL = True
            
            cli = "show mac address-table | inc dynamic | inc Peer-Link |  count"
            if int(LEAF1.execute(cli)) != vpc_count:
                log.debug("LEAF1: MAC entries mismatch")
                FAIL = True

            cli = "show ip arp vrf vrF-1 | inc Vlan{vlan} | count".format(vlan=vlan)
            if int(LEAF1.execute(cli)) != vpc_count:
                log.debug("LEAF1: ARP entries mismatch")
                FAIL = True

        with steps.start("Verifying FHS entries on LEAF2"):
            cli = "show ip dhcp snooping binding evpn |  in {intf1} | count".format(intf1=leaf2_tgn_1)
            if int(LEAF2.execute(cli)) != vpc_count:
                log.debug("LEAF2: Snooping entries mismatch")
                FAIL = True
            
            # cli = "show l2route fhs all |  in Eth{port} | count".format(port=e_port)
            # if int(LEAF2.execute(cli)) != vpc_count:
            #     log.debug("LEAF2: L2route entries mismatch")
            #     FAIL = True
            
            cli = "show mac address-table | inc Eth{port} | count".format(port=e_port)
            if int(LEAF2.execute(cli)) != vpc_count:
                log.debug("LEAF2: MAC entries mismatch")
                FAIL = True

            cli = "show ip arp vrf vrF-1 | inc Vlan{vlan} | count".format(vlan=vlan)
            if int(LEAF2.execute(cli)) != vpc_count:
                log.debug("LEAF2: ARP entries mismatch")
                FAIL = True

        with steps.start("Verifying Remote FHS entries on LEAF3"):
            cli = "show ip dhcp snooping binding evpn | inc nve | inc {vlan} | count".format(vlan=vlan)
            if int(LEAF3.execute(cli)) != vpc_count:
                log.debug("LEAF1: Remote Snooping entries mismatch")
                FAIL = True
                
            # cli = "show l2route fhs all | inc BGP | inc {vlan} | count".format(vlan=vlan)
            # if int(LEAF3.execute(cli)) != vpc_count:
            #     log.debug("LEAF1: Remote L2route entries mismatch")
            #     FAIL = True

        with steps.start("Checking Complete FHS Validation"):
            if FAIL:
                self.failed("FHS Validation failed")
            else:
                log.info("FHS Validation Success")

# clients move between vpc and leaf2 orphan
class MACMOVE_7(aetest.Testcase):
    @aetest.test
    def MACMOVE_7(self, testscript, testbed, steps):
        LEAF1   = testbed.devices['node01']
        LEAF2   = testbed.devices['node02']
        LEAF3   = testbed.devices['node03']
        LEAF6   = testbed.devices['node06']

        vpc_count = int(testscript.parameters['VPC_dict']['no_of_ints'])
        vlan = int(testscript.parameters['VPC_dict']['vlan_id'])
        FAIL = False

        leaf6_tgn_1 = ''
        leaf6_tgn_2 = ''
        leaf2_tgn_1 = ''

        for interface in LEAF2.interfaces:
            if LEAF2.interfaces[interface].alias == 'nd02_nd06_1_5':
                leaf2_tgn_1 = interface
    
        leaf1_tgn_1 = 'port-channel11'
        for interface in LEAF6.interfaces:
            if LEAF6.interfaces[interface].alias == 'nd06_nd01_1_5':
                leaf6_tgn_1 = interface
        for interface in LEAF6.interfaces:
            if LEAF6.interfaces[interface].alias == 'nd06_nd02_1_5':
                leaf6_tgn_2 = interface
        
        e_port = parsePort(leaf2_tgn_1)
        if not e_port:
            log.error("Not able to get the ethernet port")
            self.failed("Not able to get the ethernet port")

        LEAF2.execute("show run interface {intf}".format(intf=leaf2_tgn_1))
        LEAF6.execute("show run interface {intf}".format(intf="po200"))
        LEAF6.execute("show run interface {intf}".format(intf="po210"))
        LEAF6.execute("show run interface {intf}".format(intf=leaf6_tgn_1))
        LEAF6.execute("show run interface {intf}".format(intf=leaf6_tgn_2))

        with steps.start("Verifying FHS entries on LEAF1"):
            cli = "show ip dhcp snooping binding evpn |  in {intf1} | count".format(intf1=leaf1_tgn_1)
            if int(LEAF1.execute(cli)) != 0:
                log.debug("LEAF1: Snooping entries mismatch")
                FAIL = True
            
            # cli = "show l2route fhs all |  in {port} | count".format(port='Po11')
            # if int(LEAF1.execute(cli)) != 0:
            #     log.debug("LEAF1: L2route entries mismatch")
            #     FAIL = True
            
            cli = "show forwarding route ipsg vrf all |  in {intf1} | count".format(intf1=leaf1_tgn_1)
            if int(LEAF1.execute(cli)) != 0:
                log.debug("LEAF1: IPSG entries mismatch")
                FAIL = True
            
            cli = "show mac address-table dynamic | inc {port} | count".format(port='Po11')
            if int(LEAF1.execute(cli)) != 0:
                log.debug("LEAF1: MAC entries mismatch")
                FAIL = True

            cli = "show ip arp vrf vrF-1 | inc Vlan{vlan} | count".format(vlan=vlan)
            if int(LEAF1.execute(cli)) != vpc_count:
                log.debug("LEAF1: ARP entries mismatch")
                FAIL = True

        with steps.start("Verifying FHS entries on LEAF2"):
            cli = "show ip dhcp snooping binding evpn |  in {intf1} | count".format(intf1=leaf2_tgn_1)
            if int(LEAF2.execute(cli)) != vpc_count:
                log.debug("LEAF2: Snooping entries mismatch")
                FAIL = True
            
            # cli = "show l2route fhs all |  in Eth{port} | count".format(port=e_port)
            # if int(LEAF2.execute(cli)) != vpc_count:
            #     log.debug("LEAF2: L2route entries mismatch")
            #     FAIL = True
            
            cli = "show mac address-table | in Eth{port} | count".format(port=e_port)
            if int(LEAF2.execute(cli)) != vpc_count:
                log.debug("LEAF2: MAC entries mismatch")
                FAIL = True

            cli = "show ip arp vrf vrF-1 | inc Vlan{vlan} | count".format(vlan=vlan)
            if int(LEAF2.execute(cli)) != vpc_count:
                log.debug("LEAF2: ARP entries mismatch")
                FAIL = True

        with steps.start("Verifying Remote FHS entries on LEAF3"):
            cli = "show ip dhcp snooping binding evpn | inc nve | inc {vlan} | count".format(vlan=vlan)
            if int(LEAF3.execute(cli)) != vpc_count:
                log.debug("LEAF1: Remote Snooping entries mismatch")
                FAIL = True
            # cli = "show l2route fhs all | inc BGP | inc {vlan} | count".format(vlan=vlan)
            # if int(LEAF3.execute(cli)) != vpc_count:
            #     log.debug("LEAF3: Remote L2route entries mismatch")
            #     FAIL = True
        with steps.start("Checking Complete FHS Validation"):
            if FAIL:
                self.failed("FHS Validation failed")
            else:
                log.info("FHS Validation Success")

# FREEZE with mac move
class MACMOVE_8(aetest.Testcase):
    @aetest.test
    def MACMOVE_8(self, testscript, testbed, steps):
        LEAF1   = testbed.devices['node01']
        LEAF2   = testbed.devices['node02']
        LEAF3   = testbed.devices['node03']
        LEAF6   = testbed.devices['node06']

        vpc_count = int(testscript.parameters['VPC_dict']['no_of_ints'])
        vlan = int(testscript.parameters['VPC_dict']['vlan_id'])
        FAIL = False

        leaf6_tgn_1 = ''
        leaf6_tgn_2 = ''
        leaf3_tgn_1 = ''

        for interface in LEAF3.interfaces:
            if LEAF3.interfaces[interface].alias == 'nd03_nd06_1_1':
                leaf3_tgn_1 = interface
        
        for interface in LEAF1.interfaces:
            if LEAF1.interfaces[interface].alias == 'nd01_nd06_1_5':
                leaf1_tgn_1 = interface
        for interface in LEAF6.interfaces:
            if LEAF6.interfaces[interface].alias == 'nd06_nd01_1_5':
                leaf6_tgn_1 = interface
        for interface in LEAF6.interfaces:
            if LEAF6.interfaces[interface].alias == 'nd06_nd03_1_1':
                leaf6_tgn_2 = interface
        
        e_port = parsePort(leaf3_tgn_1)
        if not e_port:
            log.error("Not able to get the ethernet port")
            self.failed("Not able to get the ethernet port")

        e_port1 = parsePort(leaf1_tgn_1)
        if not e_port1:
            log.error("Not able to get the ethernet port")
            self.failed("Not able to get the ethernet port")
            
        LEAF3.execute("show run interface {intf}".format(intf=leaf3_tgn_1))
        LEAF6.execute("show run interface {intf}".format(intf="po200"))
        LEAF6.execute("show run interface {intf}".format(intf="po210"))
        LEAF6.execute("show run interface {intf}".format(intf=leaf6_tgn_1))
        LEAF6.execute("show run interface {intf}".format(intf=leaf6_tgn_2))

        with steps.start("Verifying FHS entries on LEAF1"):
            cli = "show ip dhcp snooping binding evpn |  in {intf1}".format(intf1=leaf1_tgn_1)
            LEAF1.execute(cli)
            # cli = "show ip dhcp snooping binding evpn |  in {intf1} | count".format(intf1=leaf1_tgn_1)
            # if int(LEAF1.execute(cli)) != 0:
            #     log.debug("LEAF1: Snooping entries mismatch")
            #     FAIL = True
            
            # cli = "show l2route fhs all |  in Eth{port}".format(port=e_port1)
            # LEAF1.execute(cli)
            # cli = "show l2route fhs all |  in Eth{port} | count".format(port=e_port1)
            # if int(LEAF1.execute(cli)) != 0:
            #     log.debug("LEAF1: L2route entries mismatch")
            #     FAIL = True
            
            # cli = "show forwarding route ipsg vrf all |  in {intf1} | count".format(intf1=leaf1_tgn_1)
            # if int(LEAF1.execute(cli)) != 0:
            #     log.debug("LEAF1: IPSG entries mismatch")
            #     FAIL = True
            
            # cli = "show mac address-table dynamic | inc Eth{port} | count".format(port=e_port1)
            # if int(LEAF1.execute(cli)) != 0:
            #     log.debug("LEAF1: MAC entries mismatch")
            #     FAIL = True

            # cli = "show ip arp vrf vrF-1 | inc Vlan{vlan} | count".format(vlan=vlan)
            # if int(LEAF1.execute(cli)) != 0:
            #     log.debug("LEAF1: ARP entries mismatch")
            #     FAIL = True

        with steps.start("Verifying FHS entries on LEAF2"):
            cli = "show ip dhcp snooping binding evpn |  in {intf1}".format(intf1='port-channel10')
            LEAF2.execute(cli)
            # cli = "show ip dhcp snooping binding evpn |  in port-channel10 | count"
            # if int(LEAF2.execute(cli)) != 0:
            #     log.debug("LEAF2: Snooping entries mismatch")
            #     FAIL = True
            
            # cli = "show l2route fhs all |  in Po10 | count"
            # if int(LEAF2.execute(cli)) != 0:
            #     log.debug("LEAF2: L2route entries mismatch")
            #     FAIL = True
            
            # cli = "show mac address-table | inc dynamic | inc Peer-Link | count"
            # if int(LEAF2.execute(cli)) != 0:
            #     log.debug("LEAF2: MAC entries mismatch")
            #     FAIL = True

            # cli = "show ip arp vrf vrF-1 | inc Vlan{vlan} | count".format(vlan=vlan)
            # if int(LEAF2.execute(cli)) != 0:
            #     log.debug("LEAF2: ARP entries mismatch")
            #     FAIL = True

        with steps.start("Verifying FHS entries on LEAF3"):
            cli = "show ip dhcp snooping binding evpn |  in {intf1}".format(intf1=leaf3_tgn_1)
            LEAF3.execute(cli)
            
            # cli = "show ip dhcp snooping binding evpn |  in {intf1} | count".format(intf1=leaf3_tgn_1)
            # if int(LEAF3.execute(cli)) != vpc_count:
            #     log.debug("LEAF3: Snooping entries mismatch")
            #     FAIL = True
            
            # cli = "show l2route fhs all |  in Eth{port} | count".format(port=e_port)
            # if int(LEAF3.execute(cli)) != vpc_count:
            #     log.debug("LEAF3: L2route entries mismatch")
            #     FAIL = True
            
            # cli = "show forwarding route ipsg vrf all |  in {intf1} | count".format(intf1=leaf3_tgn_1)
            # if int(LEAF3.execute(cli)) != vpc_count:
            #     log.debug("LEAF3: IPSG entries mismatch")
            #     FAIL = True
            
            # cli = "show mac address-table dynamic | inc Eth{port} | count".format(port=e_port)
            # if int(LEAF3.execute(cli)) != vpc_count:
            #     log.debug("LEAF3: MAC entries mismatch")
            #     FAIL = True

            # cli = "show ip arp vrf vrF-1 | inc Vlan{vlan} | count".format(vlan=vlan)
            # if int(LEAF3.execute(cli)) != vpc_count:
            #     log.debug("LEAF3: ARP entries mismatch")
            #     FAIL = True

        # with steps.start("Verifying Remote FHS entries on LEAF1/2"):
        #     cli = "show ip dhcp snooping binding evpn | inc nve | inc {vlan} | count".format(vlan=vlan)
        #     if int(LEAF1.execute(cli)) != vpc_count+vpc_count:
        #         log.debug("LEAF1: Remote Snooping entries mismatch")
        #         FAIL = True
        #     if int(LEAF2.execute(cli)) != vpc_count+vpc_count:
        #         log.debug("LEAF2: Remote Snooping entries mismatch")
        #         FAIL = True
                
        #     cli = "show l2route fhs all | inc BGP | inc {vlan} | count".format(vlan=vlan)
        #     if int(LEAF1.execute(cli)) != vpc_count+vpc_count:
        #         log.debug("LEAF1: Remote L2route entries mismatch")
        #         FAIL = True
        #     if int(LEAF2.execute(cli)) != vpc_count+vpc_count:
        #         log.debug("LEAF2: Remote L2route entries mismatch")
        #         FAIL = True

        with steps.start("Checking Complete FHS Validation"):
            if FAIL:
                self.failed("FHS Validation failed")
            else:
                log.info("FHS Validation Success")

# ND ISSU on Standalone
class ND_ISSU_STANDALONE(aetest.Testcase):
    @aetest.test
    def nd_issu_standalone(self, testscript, testbed, steps, issu_image):
        LEAF3   = testbed.devices['node03']

        with steps.start('Doing ISSU and verifying cores/errors after ISSU'):    
            # Establish dialogs for running ISSU command
            dialog = Dialog([
                Statement(pattern=r'Do you want to continue with the installation \(y/n\)\?',
                        action='sendline(y)',
                        loop_continue=True,
                        continue_timer=True),
            ])
        
        with steps.start('Doing ISSU and verifying cores/errors after ISSU'):
            # Create ISSU command
            issu_cmd = 'install all nxos bootflash:' + str(issu_image) + ' non-disruptive'

            # Perform ISSU
            
            result, output = LEAF3.reload(reload_command=issu_cmd, prompt_recovery=True, dialog=dialog, timeout=2000, return_output=True)
            output_split = list(filter(None, output.split('\n')))
            fail_flag = []
            fail_logs = '\n'
        
            # Process logs for any failure reasons
            for log_line in output_split:
                if re.search('CRASHED|CPU Hog|malloc|core dump|mts_send|redzone', log_line, re.I):
                    if 'Upgrade can no longer be aborted' in log_line:
                        continue
                    else:
                        fail_flag.append(0)
                        fail_logs += str(log_line) + '\n'
            
            # Reporting
            if 0 in fail_flag:
                self.failed(reason=fail_logs)
            else:
                self.passed(reason="Upgrade successful")
    
    log.info("Waiting for 180 sec for the topology to come UP")
    time.sleep(180)

# ND ISSU on secondary
class ND_ISSU_SECONDARY(aetest.Testcase):
    @aetest.test
    def nd_issu_secondary(self, testscript, testbed, steps, issu_image):
        LEAF1   = testbed.devices['node01']
        LEAF2   = testbed.devices['node02']

        with steps.start('Doing ISSU and verifying cores/errors after ISSU'):    
            # Establish dialogs for running ISSU command
            dialog = Dialog([
                Statement(pattern=r'Do you want to continue with the installation \(y/n\)\?',
                        action='sendline(y)',
                        loop_continue=True,
                        continue_timer=True),
            ])
        
        with steps.start('Doing ISSU and verifying cores/errors after ISSU'):
            # Create ISSU command
            issu_cmd = 'install all nxos bootflash:' + str(issu_image) + ' non-disruptive'

            # Perform ISSU
            for dut in [LEAF1, LEAF2]:
                if dut.execute('show feature | grep vpc').split()[-1] == 'enabled':
                    vpc_dict = ShowVpc(dut).parse()
                    if vpc_dict['vpc_role'] == 'secondary' or vpc_dict['vpc_role'] == 'primary, operational secondary':
                        log.info('Doing ISSU on vpc Secondary')
                        
                        result, output = dut.reload(reload_command=issu_cmd, prompt_recovery=True, dialog=dialog, timeout=2000, return_output=True)
                        output_split = list(filter(None, output.split('\n')))
                        fail_flag = []
                        fail_logs = '\n'
                    else:
                        log.error("This is not a VPC secondary device")
                else:
                    log.error("This is not a VPC node")
            
            # Process logs for any failure reasons
            for log_line in output_split:
                if re.search('CRASHED|CPU Hog|malloc|core dump|mts_send|redzone', log_line, re.I):
                    if 'Upgrade can no longer be aborted' in log_line:
                        continue
                    else:
                        fail_flag.append(0)
                        fail_logs += str(log_line) + '\n'
            
            # Reporting
            if 0 in fail_flag:
                self.failed(reason=fail_logs)
            else:
                self.passed(reason="Upgrade successful")
        
        log.info("Waiting for 180 sec for the topology to come UP")
        time.sleep(180)

# ND ISSU on primary
class ND_ISSU_PRIMARY(aetest.Testcase):
    @aetest.test
    def nd_issu_primary(self, testscript, testbed, steps, issu_image):
        LEAF1   = testbed.devices['node01']
        LEAF2   = testbed.devices['node02']

        with steps.start('Doing ISSU and verifying cores/errors after ISSU'):    
            # Establish dialogs for running ISSU command
            dialog = Dialog([
                Statement(pattern=r'Do you want to continue with the installation \(y/n\)\?',
                        action='sendline(y)',
                        loop_continue=True,
                        continue_timer=True),
            ])
        
        with steps.start('Doing ISSU and verifying cores/errors after ISSU'):
            # Create ISSU command
            issu_cmd = 'install all nxos bootflash:' + str(issu_image) + ' non-disruptive'

            # Perform ISSU
            device_list = [LEAF1, LEAF2]
            for dut in device_list:
                if dut.execute('show feature | grep vpc').split()[-1] == 'enabled':
                    vpc_dict = ShowVpc(dut).parse()
                    if vpc_dict['vpc_role'] == 'primary' or vpc_dict['vpc_role'] == 'secondary, operational primary':
                        log.info('Doing ISSU on vpc Primary')
                        
                        result, output = dut.reload(reload_command=issu_cmd, prompt_recovery=True, dialog=dialog, timeout=2000, return_output=True)
                        output_split = list(filter(None, output.split('\n')))
                        fail_flag = []
                        fail_logs = '\n'
                    else:
                        log.error("This is not a VPC primary device")
                else:
                    log.error("This is not a VPC node")
            
            # Process logs for any failure reasons
            for log_line in output_split:
                if re.search('CRASHED|CPU Hog|malloc|core dump|mts_send|redzone', log_line, re.I):
                    if 'Upgrade can no longer be aborted' in log_line:
                        continue
                    else:
                        fail_flag.append(0)
                        fail_logs += str(log_line) + '\n'
            
            # Reporting
            if 0 in fail_flag:
                self.failed(reason=fail_logs)
            else:
                self.passed(reason="Upgrade successful")
        
        log.info("Waiting for 180 sec for the topology to come UP")
        time.sleep(180)

# Downgrade - Standalone
class D_ISSU_STANDALONE(aetest.Testcase):
    @aetest.test
    def d_issu_standalone(self, testscript, testbed, steps, issu_image):
        LEAF3   = testbed.devices['node03']

        with steps.start('Doing ISSU and verifying cores/errors after ISSU'):    
            # Establish dialogs for running ISSU command
            dialog = Dialog([
                Statement(pattern=r'Do you want to continue with the installation \(y/n\)\?',
                        action='sendline(y)',
                        loop_continue=True,
                        continue_timer=True),
            ])
        
        with steps.start('Doing ISSU and verifying cores/errors after ISSU'):
            # Create ISSU command
            issu_cmd = 'install all nxos bootflash:' + str(issu_image)

            # Perform ISSU
            
            result, output = LEAF3.reload(reload_command=issu_cmd, prompt_recovery=True, dialog=dialog, timeout=2000, return_output=True)
            output_split = list(filter(None, output.split('\n')))
            fail_flag = []
            fail_logs = '\n'
        
            # Process logs for any failure reasons
            for log_line in output_split:
                if re.search('CRASHED|CPU Hog|malloc|core dump|mts_send|redzone', log_line, re.I):
                    if 'Upgrade can no longer be aborted' in log_line:
                        continue
                    else:
                        fail_flag.append(0)
                        fail_logs += str(log_line) + '\n'
            
            # Reporting
            if 0 in fail_flag:
                self.failed(reason=fail_logs)
            else:
                self.passed(reason="Upgrade successful")
        
        log.info("Waiting for 180 sec for the topology to come UP")
        time.sleep(180)

# Downgrade Primary
class D_ISSU_PRIMARY(aetest.Testcase):
    @aetest.test
    def d_issu_primary(self, testscript, testbed, steps, issu_image):
        LEAF1   = testbed.devices['node01']
        LEAF2   = testbed.devices['node02']

        with steps.start('Doing ISSU and verifying cores/errors after ISSU'):    
            # Establish dialogs for running ISSU command
            dialog = Dialog([
                Statement(pattern=r'Do you want to continue with the installation \(y/n\)\?',
                        action='sendline(y)',
                        loop_continue=True,
                        continue_timer=True),
            ])
        
        with steps.start('Doing ISSU and verifying cores/errors after ISSU'):
            # Create ISSU command
            issu_cmd = 'install all nxos bootflash:' + str(issu_image)

            # Perform ISSU
            for dut in [LEAF1, LEAF2]:
                if dut.execute('show feature | grep vpc').split()[-1] == 'enabled':
                    vpc_dict = ShowVpc(dut).parse()
                    if vpc_dict['vpc_role'] == 'primary' or vpc_dict['vpc_role'] == 'secondary, operational primary':
                        log.info('Doing ISSU on vpc Primary')
                        
                        result, output = dut.reload(reload_command=issu_cmd, prompt_recovery=True, dialog=dialog, timeout=2000, return_output=True)
                        output_split = list(filter(None, output.split('\n')))
                        fail_flag = []
                        fail_logs = '\n'
                    else:
                        log.error("This is not a VPC primary device")
                else:
                    log.error("This is not a VPC node")
            
            # Process logs for any failure reasons
            for log_line in output_split:
                if re.search('CRASHED|CPU Hog|malloc|core dump|mts_send|redzone', log_line, re.I):
                    if 'Upgrade can no longer be aborted' in log_line:
                        continue
                    else:
                        fail_flag.append(0)
                        fail_logs += str(log_line) + '\n'
            
            # Reporting
            if 0 in fail_flag:
                self.failed(reason=fail_logs)
            else:
                self.passed(reason="Upgrade successful")
        
        log.info("Waiting for 180 sec for the topology to come UP")
        time.sleep(180)

# Downgrade - Secondary
class D_ISSU_SECONDARY(aetest.Testcase):
    @aetest.test
    def d_issu_secondary(self, testscript, testbed, steps, issu_image):
        LEAF1   = testbed.devices['node01']
        LEAF2   = testbed.devices['node02']

        with steps.start('Doing ISSU and verifying cores/errors after ISSU'):    
            # Establish dialogs for running ISSU command
            dialog = Dialog([
                Statement(pattern=r'Do you want to continue with the installation \(y/n\)\?',
                        action='sendline(y)',
                        loop_continue=True,
                        continue_timer=True),
            ])
        
        with steps.start('Doing ISSU and verifying cores/errors after ISSU'):
            # Create ISSU command
            issu_cmd = 'install all nxos bootflash:' + str(issu_image)

            # Perform ISSU
            for dut in [LEAF1, LEAF2]:
                if dut.execute('show feature | grep vpc').split()[-1] == 'enabled':
                    vpc_dict = ShowVpc(dut).parse()
                    if vpc_dict['vpc_role'] == 'secondary' or vpc_dict['vpc_role'] == 'primary, operational secondary':
                        log.info('Doing ISSU on vpc Secondary')
                        
                        result, output = dut.reload(reload_command=issu_cmd, prompt_recovery=True, dialog=dialog, timeout=2000, return_output=True)
                        output_split = list(filter(None, output.split('\n')))
                        fail_flag = []
                        fail_logs = '\n'
                    else:
                        log.error("This is not a VPC secondary device")
                else:
                    log.error("This is not a VPC node")
            
            # Process logs for any failure reasons
            for log_line in output_split:
                if re.search('CRASHED|CPU Hog|malloc|core dump|mts_send|redzone', log_line, re.I):
                    if 'Upgrade can no longer be aborted' in log_line:
                        continue
                    else:
                        fail_flag.append(0)
                        fail_logs += str(log_line) + '\n'
            
            # Reporting
            if 0 in fail_flag:
                self.failed(reason=fail_logs)
            else:
                self.passed(reason="Upgrade successful")
        
        log.info("Waiting for 180 sec for the topology to come UP")
        time.sleep(180)

class CLEAN_UP(aetest.Testcase):
    @aetest.test
    def device_clean_up(self, testscript, testbed, steps):
        LEAF1   = testbed.devices['node01']
        LEAF2   = testbed.devices['node02']
        LEAF3   = testbed.devices['node03']
        LEAF4   = testbed.devices['node04']
        LEAF5   = testbed.devices['node05_spine']
        LEAF6   = testbed.devices['node06']
        with steps.start("Defaulting interfaces"):
            for interface in LEAF1.interfaces:
                LEAF1.configure("default interface {intf}".format(intf=interface))
            for interface in LEAF2.interfaces:
                LEAF2.configure("default interface {intf}".format(intf=interface))
            for interface in LEAF3.interfaces:
                LEAF3.configure("default interface {intf}".format(intf=interface))
            for interface in LEAF4.interfaces:
                LEAF4.configure("default interface {intf}".format(intf=interface))
            for interface in LEAF5.interfaces:
                LEAF5.configure("default interface {intf}".format(intf=interface))
            for interface in LEAF6.interfaces:
                LEAF6.configure("default interface {intf}".format(intf=interface))
        
        with steps.start("Removing port-channels"):
            LEAF1.configure('''no interface port-channel11
                               no interface port-channel110
                               no interface port-channel10
                               no interface port-channel12
                            ''')
            LEAF2.configure('''no interface port-channel11
                               no interface port-channel110
                               no interface port-channel10
                               no interface port-channel12
                            ''')
            LEAF6.configure('''no interface port-channel200
                               no interface port-channel201
                               no interface port-channel210
                            ''')
        with steps.start("Removing BGP"):
            LEAF1.configure("no router bgp 100")
            LEAF2.configure("no router bgp 100")
            LEAF3.configure("no router bgp 100")
            LEAF4.configure("no router bgp 100")
            LEAF5.configure("no router bgp 100")
        
        with steps.start("Removing NVE"):
            LEAF1.configure("no interface nve1")
            LEAF2.configure("no interface nve1")
            LEAF3.configure("no interface nve1")
            LEAF4.configure("no interface nve1")
            LEAF5.configure("no interface nve1")
        
        with steps.start("Removing OSPF"):
            LEAF1.configure("no router ospf p1")
            LEAF2.configure("no router ospf p1")
            LEAF3.configure("no router ospf p1")
            LEAF4.configure("no router ospf p1")
            LEAF5.configure("no router ospf p1")
        
        with steps.start("Removing feature DHCP"):
            LEAF1.configure("no feature dhcp")
            LEAF2.configure("no feature dhcp")
            LEAF3.configure("no feature dhcp")
            LEAF4.configure("no feature dhcp")
            
        with steps.start("Removing VPC domain"):
            LEAF1.configure("no vpc domain 100")
            LEAF2.configure("no vpc domain 100")