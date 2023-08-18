from pyats import tcl
from pyats import aetest
from pyats.log.utils import banner
from pyats.async import pcall

from pyats.aereport.exceptions.utils_errors import \
MissingArgError, TypeMismatchError,\
DictInvalidKeyError, DictMissingMandatoryKeyError,\
StrInvalidOptionError, InvalidArgumentError

from ats.topology import loader
from pyats.aereport.utils.argsvalidator import ArgsValidator
ArgVal = ArgsValidator()
import pdb
import os
import re
import logging
import time
# import lib.nxos.util as util
# import lib.nxos.connection as connection
# import lib.nxos.vdc as vdc

log = logging.getLogger(__name__)
log.setLevel(logging.DEBUG)

from ixiatcl import IxiaTcl
from ixiahlt import IxiaHlt
from ixiangpf import IxiaNgpf
from ixiaerror import IxiaError

ixiatcl = IxiaTcl()
ixiahlt = IxiaHlt(ixiatcl)
ixiangpf = IxiaNgpf(ixiahlt)

class ixiaPyats_lib:
    # First we create a constructor for this class 
    # and add members to it, here models 
    def __init__(self): 
        pass
    
    #====================================================================================================#
    def connect_to_ixia (self, args_dict):
        
        help ="""
        ==================================================================================================================================
        
           Proc Name           : connect_to_ixia
        
           Functionality       : Connects to Ixia Chassis via TclServer VM
        
           Parameters          : A dictionary with below key_value pairs.
        
           Name         Required       Description                 Default Value
           ====        ==========      ===========                 =============
           chassis_ip  :   M   :   IP of the IXIA Chassis              : N/A
           port_list   :   M   :   List of ports to be used            : N/A
           tcl_server  :   M   :   IXIA TclServer VM IP                : N/A
           tcl_port    :   M   :   IXIA TclServer Port                 : N/A
           reset       :   O   :   Flag to reset the IXIA              : N/A
                                   configuration on every VM login.
        
           Parameter Example   :
        
                               ixiaArgDict = {
                                   'chassis_ip'     = '10.10.10.10'
                                   'port_list'      = '2/7 2/8'
                                   'tcl_server'     = '10.10.10.10'
                                   'tcl_port'       = '8009'
                                    'reset'         = '1'
                                }
            
            Return Value        : Fail Case:
                                  0 
                                  Pass Case:
                                  _result    : Result of connect statement
        
        ==================================================================================================================================
        """
        
        # Define Arguments Definition
        args_def = [
                ('chassis_ip'   , 'm', [str]),
                ('port_list'    , 'm', [str]),
                ('tcl_server'   , 'm', [str]),
                ('tcl_port'     , 'm', [str]),
                ('reset'        , 'o', [int]),
                ]
        
        # Validate Arguments
        try:
            ArgVal.validate(args_def, **args_dict)
        except Exception as e:
            print(e)
            print(help)
            return 0
        
        ixTclServer = str(args_dict['tcl_server']) + ":" + str(args_dict['tcl_port'])
        
        if 'reset' not in args_dict.keys():
                args_dict['reset'] = 1
            
        
        _result_ = ixiangpf.connect(
            device                  = args_dict['chassis_ip'],
            port_list               = args_dict['port_list'],
            ixnetwork_tcl_server    = ixTclServer,
            tcl_server              = args_dict['chassis_ip'],
            reset                   = args_dict['reset'],
            break_locks             = 1
        )
        
        #print(_result_)
        
        if _result_['status'] == '1':
            print("Ixia connection succsessful")
            return _result_
        else:
            log.info("Ixia connection Failed" + str(_result_['log']))
            return 0
    
    #====================================================================================================#
    def create_topo_device_grp(self, args_dict):
        
        help = """
        ==================================================================================================================================
        
           Proc Name           : create_topo_device_grp
        
           Functionality       : Create Topology and Device Group (IXIA NextGen)
        
           Parameters          : A dictionary with below key_value pairs.
        
           Name                Required        Description                 Default Value
           ====                ==========      ===========                 =============
           topology_name       :   M   :       Name of the Topolgy             : N/A
           device_grp_name     :   M   :       Name of the Device Group        : N/A
                                               under topolgy            
           port_handle         :   M   :       port_handle from IXIA to be     : N/A
                                               added to device_group                
        
           Parameter Example   :
        
                        TOPO_1_dict = { 'topology_name'      : 'ACCESS-1-TG',
                                        'device_grp_name'    : 'ACCESS-1-TG',
                                        'port_handle'        : port_handle_1]}
        
            Return Value        : Fail Case:
                                  0 
                                  Pass Case:
                                  {'topo_hndl' : topo_handle, 'dev_grp_hndl' : tp_device_status['device_group_handle']}
        
        ==================================================================================================================================
        """
        
        # Define Arguments Definition
        args_def = [
                ('topology_name'        , 'm', [str]),
                ('device_grp_name'      , 'm', [str]),
                ('port_handle'          , 'm', [str])
                ]
        
        # Validate Arguments
        try:
            ArgVal.validate(args_def, **args_dict)
        except Exception as e:
            print(e)
            print(help)
            return 0
        
        topology_status = ixiangpf.topology_config(
            port_handle         = args_dict['port_handle'],
            topology_name       = args_dict['topology_name']
        )
        
        if topology_status['status'] == '1':
            print ('Topology created successfully')
        else:
            return 0
        
        topo_handle = topology_status['topology_handle']
        
        tp_device_status = ixiangpf.topology_config(
            topology_handle         =   topo_handle,
            device_group_name       =   args_dict['device_grp_name'],
            device_group_multiplier =   "1",
            device_group_enabled    =   "1"
        )
        
        if tp_device_status['status'] == '1':
            print ('Topology and Device group created successfully')
            return {'topo_hndl' : topo_handle, 'dev_grp_hndl' : tp_device_status['device_group_handle']}
        else:
            log.info('Topology and Device group creation Failed')
            return 0
        
    #====================================================================================================#
    def configure_ixia_interface(self, args_dict):
        
        help = """
        ==================================================================================================================================
        
           Proc Name           : configure_ixia_interface
        
           Functionality       : Configure Ixia Interface
        
           Parameters          : A dictionary with below key_value pairs.
        
           Name            Required        Description                 Default Value
           ====            ==========      ===========                 =============
           dev_grp_hndl    :   M   :       Device Group Handle             : N/A
           port_hndl       :   M   :       port_handle for Ixia interface  : N/A
                                            in device group                    
           phy_mode        :   M   :       IXIA TclServer VM IP            : N/A
           mac             :   M   :       IXIA TclServer Port             : N/A
           protocol        :   O   :       Flag to reset the IXIA          : N/A
           ip_addr         :   M   :       port_handle from IXIA           : N/A
           netmask         :   M   :       port_handle from IXIA           : N/A
           gateway         :   M   :       port_handle from IXIA           : N/A
           vlan_id         :   M   :       port_handle from IXIA           : N/A
        
           Parameter Example   :
        
                               ixiaArgDict = {
                                   'chassis_ip'    = '10.10.10.10'
                                   'port_list'     = '2/7 2/8'
                                   'tcl_server'    = '10.10.10.10'
                                   'tcl_port'      = '8009'
                                    'reset'      = '1'
                                }
        
        ==================================================================================================================================
        """
        
        # Define Arguments Definition
        args_def = [
                ('dev_grp_hndl'  , 'm', [str]),
                ('port_hndl'     , 'm', [str]),
                ('phy_mode'      , 'm', [str]),
                ('mac'           , 'm', [str]),
                ('protocol'      , 'm', [str]),
                ('ip_addr'       , 'm', [str]),
                ('netmask'       , 'm', [str]),
                ('gateway'       , 'm', [str]),
                ('vlan_id'       , 'o', [str])
                ]
        
        # Validate Arguments
        try:
            ArgVal.validate(args_def, **args_dict)
        except Exception as e:
            print(e)
            print(help)
            return 0
        
        vlan_flag = 1
        if 'vlan_id' not in args_dict.keys():
            vlan_flag = 0
            args_dict['vlan_id'] = "0"
        
        if 'phy_mode' in args_dict.keys():
            int_phy_status = ixiangpf.interface_config(
                port_handle         = args_dict['port_hndl'],
                phy_mode            = args_dict['phy_mode']
            )
            
            if int_phy_status['status'] == '1':
                print('Configured Ixia Interface Port Mode successfully')
            else:
                log.info('Configuring Ixia Interface Port Mode Failed')
                return 0
        
        if args_dict['protocol'] == "ipv4":
            eth_config_status = ixiangpf.interface_config(
                protocol_name                       = "Ethernet",
                protocol_handle                     = args_dict['dev_grp_hndl'],
                src_mac_addr                        = args_dict['mac'],
                arp_on_linkup                       = '1',
                vlan                                = vlan_flag,
                vlan_id                             = args_dict['vlan_id']
            )
            
            if eth_config_status['status'] == '1':
                print('Configured Ethernet mode on the Interface')
            else:
                log.info('Failed Configuring Ethernet mode on the Interface')
                return 0
            
            eth_handle = eth_config_status['ethernet_handle']
            
            ipv4_config_status = ixiangpf.interface_config(
                protocol_name                       = "IPv4",
                protocol_handle                     = eth_handle,
                ipv4_resolve_gateway                = "1",
                intf_ip_addr                        = args_dict['ip_addr'],
                gateway                             = args_dict['gateway'],
                netmask                             = args_dict['netmask']
            )
            
            v4_handle = ipv4_config_status['ipv4_handle']
            topo_int_handle = ipv4_config_status['interface_handle']
            
            if ipv4_config_status['status'] == '1':
                print('Configured IPv4 mode on the Interface')
                return {'eth_handle' : eth_handle, 'ipv4_handle' : v4_handle, 'topo_int_handle' : topo_int_handle}
            else:
                log.info('Failed Configuring IPv4 mode on the Interface')
                return 0
            
        elif args_dict['protocol'] == "ipv6":
            eth_config_status = ixiangpf.interface_config(
                protocol_name                       = "Ethernet",
                phy_mode                            = args_dict['phy_mode'],
                protocol_handle                     = args_dict['dev_grp_hndl'],
                src_mac_addr                        = args_dict['mac'],
                arp_on_linkup                       = '1',
                vlan                                = vlan_flag,
                vlan_id                             = args_dict['vlan_id']
            )
            
            if eth_config_status['status'] == '1':
                print('Configured Ethernet mode on the Interface')
            else:
                log.info('Failed Configuring Ethernet mode on the Interface')
                return 0
            
            eth_handle = eth_config_status['ethernet_handle']
            
            ipv6_config_status = ixiangpf.interface_config(
                protocol_name                       = "IPv6",
                protocol_handle                     = eth_handle,
                ipv6_resolve_gateway                = "1",
                ipv6_intf_addr                      = args_dict['ip_addr'],
                ipv6_gateway                        = args_dict['gateway'],
                ipv6_prefix_length                  = args_dict['netmask']
            )
            
            v6_handle = ipv4_config_status['ipv6_handle']
            
            if ipv6_config_status['status'] == '1':
                print('Configured IPv6 mode on the Interface')
                return {'eth_handle' : eth_handle, 'ipv6_handle' : v6_handle, 'topo_int_handle' : topo_int_handle}
            else:
                log.info('Failed Configuring IPv6 mode on the Interface')
                return 0
            
        elif args_dict['protocol'] == "ipv46":
            eth_config_status = ixiangpf.interface_config(
                protocol_name                       = "Ethernet",
                phy_mode                            = args_dict['phy_mode'],
                protocol_handle                     = args_dict['dev_grp_hndl'],
                src_mac_addr                        = args_dict['mac'],
                arp_on_linkup                       = '1',
                vlan                                = vlan_flag,
                vlan_id                             = args_dict['vlan_id']
            )
            
            if eth_config_status['status'] == '1':
                print('Configured Ethernet mode on the Interface')
            else:
                log.info('Failed Configuring Ethernet mode on the Interface')
                return 0
            
            eth_handle = eth_config_status['ethernet_handle']
            
            ipv4_config_status = ixiangpf.interface_config(
                protocol_name                       = "IPv4",
                protocol_handle                     = eth_handle,
                ipv4_resolve_gateway                = "1",
                intf_ip_addr                        = args_dict['ip_addr'],
                gateway                             = args_dict['gateway'],
                netmask                             = args_dict['netmask']
            )
            
            v4_handle = ipv4_config_status['ipv4_handle']
            
            ipv6_config_status = ixiangpf.interface_config(
                protocol_name                       = "IPv6",
                protocol_handle                     = eth_handle,
                ipv6_resolve_gateway                = "1",
                ipv6_intf_addr                      = args_dict['ip_addr'],
                ipv6_gateway                        = args_dict['gateway'],
                ipv6_prefix_length                  = args_dict['netmask']
            )
            
            v6_handle = ipv4_config_status['ipv6_handle']
            topo_int_handle = ipv4_config_status['interface_handle']
            
            if ipv6_config_status['status'] == '1':
                print('Configured IPv4/v6 mode on the Interface')
                return {'eth_handle' : eth_handle, 'ipv4_handle' : v4_handle, 'ipv6_handle' : v6_handle, 'topo_int_handle' : topo_int_handle}
            else:
                log.info('Failed Configuring IPv4/v6 mode on the Interface')
                return 0
            
    #====================================================================================================#
    def configure_multi_ixia_interface(self, args_dict):
        
        # Define Arguments Definition
        args_def = [
                ('dev_grp_hndl'  , 'm', [str]),
                ('no_of_ints'    , 'm', [str]),
                ('port_hndl'     , 'm', [str]),
                ('phy_mode'      , 'm', [str]),
                ('mac'           , 'm', [str]),
                ('mac_step'      , 'm', [str]),
                ('protocol'      , 'm', [str]),
                ('ip_addr'       , 'm', [str]),
                ('ip_addr_step'  , 'm', [str]),
                ('netmask'       , 'm', [str]),
                ('gateway'       , 'm', [str]),
                ('gateway_step'  , 'm', [str]),
                ('vlan_id'       , 'o', [str]),
                ('vlan_id_step'  , 'o', [str])
                ]
        
        # Validate Arguments
        try:
            ArgVal.validate(args_def, **args_dict)
        except Exception as e:
            print(e)
        
        vlan_flag = 1
        if 'vlan_id' not in args_dict.keys():
            vlan_flag = 0
            args_dict['vlan_id'] = "0"
            args_dict['vlan_id_step'] = "1"
        
        if 'phy_mode' in args_dict.keys():
            int_phy_status = ixiangpf.interface_config(
                port_handle         = args_dict['port_hndl'],
                phy_mode            = args_dict['phy_mode']
            )
            
            if int_phy_status['status'] == '1':
                print('Configured Ixia Interface Port Mode successfully')
            else:
                log.info('Configured Ixia Interface Port Mode Failed')
                return 0
        
        tp_device_status = ixiangpf.topology_config(
            mode                    =   "modify",
            device_group_handle     =   args_dict['dev_grp_hndl'],
            device_group_multiplier =   args_dict['no_of_ints'],
            device_group_enabled    =   "1"
        )
        
        if tp_device_status['status'] == '1':
            print("Modified Device group for " + str(args_dict['no_of_ints']) + " successfully")
        else:
            log.info("Modifying Device group for " + str(args_dict['no_of_ints']) + " failed")
            return 0
        
        if args_dict['protocol'] == "ipv4":
            eth_config_status = ixiangpf.interface_config(
                protocol_name                       = "Ethernet",
                protocol_handle                     = args_dict['dev_grp_hndl'],
                src_mac_addr                        = args_dict['mac'],
                src_mac_addr_step                   = args_dict['mac_step'],
                arp_on_linkup                       = '1',
                vlan                                = vlan_flag,
                vlan_id                             = args_dict['vlan_id'],
                vlan_id_step                        = args_dict['vlan_id_step']
            )
            
            if eth_config_status['status'] == '1':
                print('Configured Ethernet mode on the Interface')
            else:
                log.info('Failed Configuring Ethernet mode on the Interface')
                return 0
            
            eth_handle = eth_config_status['ethernet_handle']
            
            ipv4_config_status = ixiangpf.interface_config(
                protocol_name                       = "IPv4",
                protocol_handle                     = eth_handle,
                ipv4_resolve_gateway                = "1",
                intf_ip_addr                        = args_dict['ip_addr'],
                intf_ip_addr_step                   = args_dict['ip_addr_step'],
                gateway                             = args_dict['gateway'],
                gateway_step                        = args_dict['gateway_step'],
                netmask                             = args_dict['netmask']
            )
            
            v4_handle = ipv4_config_status['ipv4_handle']
            topo_int_handle = ipv4_config_status['interface_handle']
            
            #print(eth_config_status)
            #print(ipv4_config_status)
            
            if ipv4_config_status['status'] == '1':
                print('Configured IPv4 mode on the Interface')
                return {'eth_handle' : eth_handle, 'ipv4_handle' : v4_handle, 'topo_int_handle' : topo_int_handle}
            else:
                log.info('Failed Configuring IPv4 mode on the Interface')
                return 0
            
        elif args_dict['protocol'] == "ipv6":
            eth_config_status = ixiangpf.interface_config(
                protocol_name                       = "Ethernet",
                phy_mode                            = args_dict['phy_mode'],
                protocol_handle                     = args_dict['dev_grp_hndl'],
                src_mac_addr                        = args_dict['mac'],
                arp_on_linkup                       = '1',
                vlan                                = vlan_flag,
                vlan_id                             = args_dict['vlan_id']
            )
            
            if eth_config_status['status'] == '1':
                print('Configured Ethernet mode on the Interface')
            else:
                log.info('Failed Configuring Ethernet mode on the Interface')
                return 0
            
            eth_handle = eth_config_status['ethernet_handle']
            
            ipv6_config_status = ixiangpf.interface_config(
                protocol_name                       = "IPv6",
                protocol_handle                     = eth_handle,
                ipv6_resolve_gateway                = "1",
                ipv6_intf_addr                      = args_dict['ip_addr'],
                ipv6_intf_addr_step                 = args_dict['ip_addr_step'],
                ipv6_gateway                        = args_dict['gateway'],
                ipv6_gateway_step                   = args_dict['gateway_step'],
                ipv6_prefix_length                  = args_dict['netmask']
            )
            
            v6_handle = ipv4_config_status['ipv6_handle']
            
            #print(eth_config_status)
            #print(ipv6_config_status)
            
            if ipv6_config_status['status'] == '1':
                print('Configured IPv6 mode on the Interface')
                return {'eth_handle' : eth_handle, 'ipv6_handle' : v6_handle, 'topo_int_handle' : topo_int_handle}
            else:
                log.info('Failed Configuring IPv6 mode on the Interface')
                return 0
            
        elif args_dict['protocol'] == "ipv46":
            eth_config_status = ixiangpf.interface_config(
                protocol_name                       = "Ethernet",
                phy_mode                            = args_dict['phy_mode'],
                protocol_handle                     = args_dict['dev_grp_hndl'],
                src_mac_addr                        = args_dict['mac'],
                arp_on_linkup                       = '1',
                vlan                                = vlan_flag,
                vlan_id                             = args_dict['vlan_id']
            )
            
            if eth_config_status['status'] == '1':
                print('Configured Ethernet mode on the Interface')
            else:
                log.info('Failed Configuring Ethernet mode on the Interface')
                return 0
            
            eth_handle = eth_config_status['ethernet_handle']
            
            ipv4_config_status = ixiangpf.interface_config(
                protocol_name                       = "IPv4",
                protocol_handle                     = eth_handle,
                ipv4_resolve_gateway                = "1",
                intf_ip_addr                        = args_dict['ip_addr'],
                intf_ip_addr_step                   = args_dict['ip_addr_step'],
                gateway                             = args_dict['gateway'],
                gateway_step                        = args_dict['gateway_step'],
                netmask                             = args_dict['netmask']
            )
            
            v4_handle = ipv4_config_status['ipv4_handle']
            
            ipv6_config_status = ixiangpf.interface_config(
                protocol_name                       = "IPv6",
                protocol_handle                     = eth_handle,
                ipv6_resolve_gateway                = "1",
                ipv6_intf_addr                      = args_dict['ip_addr'],
                ipv6_intf_addr_step                 = args_dict['ip_addr_step'],
                ipv6_gateway                        = args_dict['gateway'],
                ipv6_gateway_step                   = args_dict['gateway_step'],
                ipv6_prefix_length                  = args_dict['netmask']
            )
            
            v6_handle = ipv4_config_status['ipv6_handle']
            topo_int_handle = ipv4_config_status['interface_handle']
            
            #print(eth_config_status)
            #print(ipv4_config_status)
            #print(ipv6_config_status)
            
            if ipv6_config_status['status'] == '1':
                print('Configured IPv4/v6 mode on the Interface')
                return {'eth_handle' : eth_handle, 'ipv4_handle' : v4_handle, 'ipv6_handle' : v6_handle, 'topo_int_handle' : topo_int_handle}
            else:
                log.info('Failed Configuring IPv4/v6 mode on the Interface')
                return 0
            
    #====================================================================================================#
    def configure_ixia_traffic_item(self, args_dict):
        
        # Define Arguments Definition
        args_def = [
                ('src_hndl'     , 'm', [list]),
                ('dst_hndl'     , 'm', [list]),
                ('TI_name'      , 'm', [str]),
                ('circuit'      , 'm', [str]),
                ('rate_pps'     , 'm', [str]),
                ('bi_dir'       , 'm', [int, bool]),
                ]
        
        # Validate Arguments
        try:
            ArgVal.validate(args_def, **args_dict)
        except Exception as e:
            print(e)
        
        _result_ = ixiahlt.traffic_config(
            mode                        = 'create',
            traffic_generator           = 'ixnetwork_540',
            endpointset_count           = args_dict['bi_dir'],
            emulation_src_handle        = args_dict['src_hndl'],
            emulation_dst_handle        = args_dict['dst_hndl'],
            bidirectional               = '1',
            name                        = args_dict['TI_name'],
            circuit_endpoint_type       = args_dict['circuit'],
            preamble_size_mode          = 'auto',
            length_mode                 = 'auto',
            rate_pps                    = args_dict['rate_pps'],
            track_by                    = 'sourceDestEndpointPair0 trackingenabled0',
            )
        
        #print(_result_)
        if _result_['status'] == "1":
            print("Configured Traffic Item successfully")
            return 1
        else:
            print("Configuring Traffic Item Failed")
            return 0
        
    #====================================================================================================#
    def emulate_igmp_groupHost(self, args_dict):
        
        # Define Arguments Definition
        args_def = [
                ('ipv4_hndl'                    , 'm', [str]),
                ('igmp_ver'                     , 'm', [str]),
                ('mcast_grp_ip'                 , 'm', [str]),
                ('mcast_grp_ip_step'            , 'm', [str]),
                ('no_of_grps'                   , 'm', [str]),
                ('mcast_src_ip'                 , 'm', [str]),
                ('mcast_src_ip_step'            , 'm', [str]),
                ('mcast_no_of_srcs'             , 'm', [str]),
                ('mcast_src_ip_step_per_port'   , 'o', [str]),
                ('topology_handle'              , 'o', [dict]),
                ]
        
        # Validate Arguments
        try:
            ArgVal.validate(args_def, **args_dict)
        except Exception as e:
            print(e)
        
        _result_ = ixiangpf.emulation_igmp_config(
            handle                  = args_dict['ipv4_hndl'],
            protocol_name           = "IGMP Host",
            mode                    = "create",
            filter_mode             = "include",
            igmp_version            = args_dict['igmp_ver'],
        )
        
        #print(_result_)
        if _result_['status'] == "1":
            print('Passed emulation_igmp_config')
        else:
            print('Failed emulation_igmp_config')
            return 0
            
        igmpHost_handle = _result_['igmp_host_handle']
        
        _result_ = ixiangpf.emulation_multicast_group_config(
            mode                    = "create",
            ip_addr_start           = args_dict['mcast_grp_ip'],
            ip_addr_step            = args_dict['mcast_grp_ip_step'],
            num_groups              = args_dict['no_of_grps'],
            active                  = "1",
        )
        
        #print(_result_)
        if _result_['status'] == "1":
            print('Passed emulation_multicast_group_config')
        else:
            print('Failed emulation_multicast_group_config')
            return 0
            
        igmpMcastIPv4GroupList_handle = _result_['multicast_group_handle']
        
        # Setting default Values
        if 'mcast_src_ip_step_per_port' in args_dict.keys():
        
            _result_ = ixiangpf.multivalue_config(
                pattern                = "counter",
                counter_start          = args_dict['mcast_src_ip'],
                counter_step           = args_dict['mcast_src_ip_step_per_port'],
                counter_direction      = "increment",
                nest_step              = '%s' % ("0.0.0.1"),
                nest_owner             = '%s' % (args_dict['topology_handle']),
                nest_enabled           = '%s' % ("0"),
            )
            if _result_['status'] != IxiaHlt.SUCCESS:
                ixnHLT_errorHandler('multivalue_config', _result_)
            
            multivalue_1_handle = _result_['multivalue_handle']
            
            _result_ = ixiangpf.emulation_multicast_source_config(
                mode                    = "create",
                ip_addr_start           = multivalue_1_handle,
                ip_addr_step            = args_dict['mcast_src_ip_step'],
                num_sources             = args_dict['mcast_no_of_srcs'],
                active                  = "1",
            )
        
        else:
            
            _result_ = ixiangpf.emulation_multicast_source_config(
                mode                    = "create",
                ip_addr_start           = args_dict['mcast_src_ip'],
                ip_addr_step            = args_dict['mcast_src_ip_step'],
                num_sources             = args_dict['mcast_no_of_srcs'],
                active                  = "1",
            )
        
        if _result_['status'] == "1":
            print('Passed emulation_multicast_source_config')
        else:
            print('Failed emulation_multicast_source_config')
            
        igmpUcastIPv4SourceList_handle = _result_['multicast_source_handle']
        
        _result_ = ixiangpf.emulation_igmp_group_config(
            mode                    = "create",
            g_filter_mode           = "include",
            group_pool_handle       = igmpMcastIPv4GroupList_handle,
            no_of_grp_ranges        = "1",
            session_handle          = igmpHost_handle,
            source_pool_handle      = igmpUcastIPv4SourceList_handle,
        )
        
        #print(_result_)
        if _result_['status'] == "1":
            print('Passed emulation_igmp_group_config')
            return {'igmpHost_handle' : igmpHost_handle,'igmp_group_handle' : _result_['igmp_group_handle'], 'igmp_source_handle' : _result_['igmp_source_handle']}
        else:
            print('Failed emulation_igmp_group_config')
            return 0
        
        igmpGroup_1_handle = _result_['igmp_group_handle']
        return 1
    #====================================================================================================#
    
    def emulate_dhcp_server(self,args_dict):
        
        # Define Arguments Definition
        args_def = [
                ('topology_handle'              , 'o', [str]),
                ('router_addr'                  , 'm', [str]),
                ('router_addr_gw'               , 'm', [str]),
                ('vlan'                         , 'm', [str]),
                ('pool_count'                   , 'o', [str]),
                ('lease_pool_start'             , 'm', [str]),
                ('lease_pool_step'              , 'o', [str]),
                ('lease_pool_addr_count'        , 'o', [str]),
                ('lease_pool_prfx_len'          , 'o', [str]),
                ]
        
        # Validate Arguments
        try:
            ArgVal.validate(args_def, **args_dict)
        except Exception as e:
            print(e)
        
        if 'lease_pool_step' not in args_dict.keys():
            args_dict['lease_pool_step'] = "0.0.0.0"
            
        if 'lease_pool_prfx_len' not in args_dict.keys():
            args_dict['lease_pool_prfx_len'] = "24" 
        
        # Validate Arguments
        try:
            ArgVal.validate(args_def, **args_dict)
        except Exception as e:
            print(e)
        
        ip_pool_multivalue = ixiangpf.multivalue_config(
            pattern                                                     = "counter",
            counter_start                                               = args_dict['lease_pool_start'],
            counter_step                                                = args_dict['lease_pool_start'],
            counter_direction                                           = "increment",
            nest_step                                                   = "0.1.0.0",
            nest_owner                                                  = args_dict['topology_handle'],
            nest_enabled                                                = "1",
        )
        
        ip_pool_multivalue_hndle = ip_pool_multivalue['multivalue_handle']
        
        _result_ = ixiangpf.emulation_dhcp_server_config(
            ip_address		                                            = args_dict['router_addr'],
            ip_step		                                                = '0.0.0.1',
            ip_gateway		                                            = args_dict['router_addr_gw'],
            ip_gateway_step	                                            = '0.0.0.1',
            ip_prefix_length	                                        = '24',
            ip_prefix_step		                                        = '1',
            local_mac                                                   = '0000.0001.0001',
            local_mac_outer_step                                        = '0000.0001.0000',
            local_mtu		                                            = '800',
            vlan_id			                                            = args_dict['vlan'],
            vlan_id_step		                                        = '1',
            handle                                                      = args_dict['topology_handle'],
            ip_version                                                  = "4",
            ipaddress_count                                             = args_dict['lease_pool_addr_count'],
            ipaddress_pool		                                        = args_dict['lease_pool_start'],
            ipaddress_pool_step		                                    = '0.0.0.1',
            ipaddress_pool_prefix_length                                = args_dict['lease_pool_prfx_len'],
            ipaddress_pool_prefix_step	                                = '1',
            lease_time                                                  = "86400",
            mode                                                        = "create",
            protocol_name                                               = "DHCP",
            pool_address_increment                                      = "0.0.0.1",
            pool_count                                                  = args_dict['pool_count'],
            subnet_addr_assign                                          = "0",
            subnet                                                      = "relay"
        )
        
        #print(_result_)
        if _result_['status'] == "1":
            print('Passed Emulating DHCP Server')
            return _result_
        else:
            print('Failed Emulating DHCP Server')
            log.info(_result_)
            print (_result_)
            return 0
        
    #====================================================================================================#
    
    def emulate_dhcp_client(self,args_dict):
        
        # Define Arguments Definition
        args_def = [
                ('topo_device_handle'           , 'm', [str]),
                ('num_of_sessions'              , 'm', [str]),
                ('vlan'                         , 'm', [str]),
                ('circuit_type'                 , 'm', [str]),
                ('bcast_flag'                   , 'o', [str]),
                ]
        
        # Validate Arguments
        try:
            ArgVal.validate(args_def, **args_dict)
        except Exception as e:
            print(e)
        
        if 'lease_pool_step' not in args_dict.keys():
            args_dict['lease_pool_step'] = "0.0.0.0"
            
        if 'bcast_flag' not in args_dict.keys():
            args_dict['bcast_flag'] = "0"
            
        if 'lease_pool_prfx_len' not in args_dict.keys():
            args_dict['lease_pool_prfx_len'] = "24" 
            
        dhcp_status = ixiangpf.emulation_dhcp_group_config(
             handle                         = args_dict['topo_device_handle'],
             protocol_name 		            = "Dhcp_client",
             mac_addr                       = '0000.0000.ffff',
             mac_addr_step		            = '00.00.00.00.00.02',
             use_rapid_commit               = '0',
             enable_stateless               = '0',
             num_sessions                   = args_dict['num_of_sessions'],
             vlan_id		                = args_dict['vlan'],
             vlan_id_step		            = '20',
             vlan_user_priority		        = '2',
             dhcp4_broadcast                = args_dict['bcast_flag'],
             dhcp_range_use_first_server    = '1',
             dhcp_range_renew_timer         = '20',
             dhcp_range_ip_type             = args_dict['circuit_type'],
             vendor_id                      = 'any',
        )
        
        if dhcp_status['status'] == "1":
            print('Passed Emulating DHCP Client')
            return dhcp_status
        else:
            print('Failed Emulating DHCP Client')
            log.info(dhcp_status)
            print(dhcp_status)
            return 0

    #====================================================================================================#
    def bindDHCPClient(self, client, action):
        
        status = ixiangpf.emulation_dhcp_control(
            handle          = client,
            action          = action,
        )
        
        if status['status'] == "1":
            print('Initiated DHCP Client')
            return 1
        else:
            print('Failed to Initiate DHCP Client')
            log.info(status)
            print(status)
            return 0
        
    #====================================================================================================#
    def startDHCPServer(self, dhcp_server):
        
        status = ixiangpf.emulation_dhcp_server_control(
            dhcp_handle     = dhcp_server,
            action          = 'collect',
        )
        
        if status['status'] == "1":
            print('Initiated DHCP Server')
            return 1
        else:
            print('Failed to Initiate DHCP Server')
            log.info(status)
            print(status)
            return 0
        
    #====================================================================================================#
    def configure_v4_mcast_traffic_item(self, args_dict):
        
        # Define Arguments Definition
        args_def = [
                ('src_hndl'                 , 'm', [str]),
                ('mcast_dst_hndl'           , 'm', [list]),
                ('mcast_rcvr_hndl'          , 'm', [list]),
                ('TI_name'                  , 'm', [str]),
                ('rate_pps'                 , 'm', [str]),
                ('mcast_rcvr_port_indx'     , 'm', [list]),
                ('mcast_rcvr_host_indx'     , 'm', [list]),
                ('mcast_rcvr_mcst_indx'     , 'm', [list]),
                ]
        
        # Validate Arguments
        try:
            ArgVal.validate(args_def, **args_dict)
        except Exception as e:
            print(e)
        
        mcast_dst_handle_type = []
        for hndl in args_dict['mcast_dst_hndl']:
            mcast_dst_handle_type.append('none')
        
        _result_ = ixiangpf.traffic_config(
            mode                                        = 'create',
            traffic_generator                           = 'ixnetwork_540',
            endpointset_count                           = 1,
            emulation_src_handle                        = args_dict['src_hndl'],
            emulation_dst_handle                        = '',
            emulation_multicast_dst_handle              = args_dict['mcast_dst_hndl'],
            emulation_multicast_dst_handle_type         = mcast_dst_handle_type,
            emulation_multicast_rcvr_handle             = args_dict['mcast_rcvr_hndl'],
            emulation_multicast_rcvr_port_index         = args_dict['mcast_rcvr_port_indx'],
            emulation_multicast_rcvr_host_index         = args_dict['mcast_rcvr_host_indx'],
            emulation_multicast_rcvr_mcast_index        = args_dict['mcast_rcvr_mcst_indx'],
            name                                        = args_dict['TI_name'],
            circuit_endpoint_type                       = 'ipv4',
            transmit_distribution                       = 'srcDestEndpointPair0',                             
            rate_pps                                    = args_dict['rate_pps'],
            preamble_size_mode                          = 'auto',
            length_mode                                 = 'auto',
            track_by                                    = 'trackingenabled0 sourceDestEndpointPair0'
        )
        
        if _result_['status'] == '1':
            print("Create Mcast TI successfully")
            return 1
        else:
            print("Creating Mcast TI Failed")
            return 0
    
    #====================================================================================================#
    def start_protocols(self):
        _result = ixiangpf.test_control(action='start_all_protocols')
        print(_result)
        if _result['status'] == '1':
            print("Protocol started successfully")
            return 1
        else:
            print("Failed to start protocol")
            return 0
        
    #====================================================================================================#
    def change_phymode(self, int_hndle, mode):
        int_phy_status = ixiangpf.interface_config(
            port_handle         = int_hndle,
            phy_mode            = mode
        )
        
    #====================================================================================================#
    def start_topology_protocols(self,topo_hndle):
        _result = ixiangpf.test_control(handle=topo_hndle,action='start_all_protocols')
        print(_result)
        if _result['status'] == '1':
            print("Protocol started successfully")
            return 1
        else:
            print("Failed to start protocol")
            return 0
        
    #====================================================================================================#
    def stop_protocols(self):
        _result = ixiangpf.test_control(action='stop_all_protocols')
        print(_result)
        if _result['status'] == '1':
            print("Protocol stopped successfully")
            return 1
        else:
            print("Failed to stop protocol")
            return 0
        
    #====================================================================================================#
    def start_traffic(self):
        _result = ixiangpf.traffic_control(action='run')
        print(_result)
        if _result['status'] == '1':
            print("Traffic started successfully")
            return 1
        else:
            print("Failed to start Traffic")
            return 0
        
    #====================================================================================================#
    def stop_traffic(self):
        _result = ixiangpf.traffic_control(action='stop')
        print(_result)
        if _result['status'] == '1':
            print("Traffic stopped successfully")
            return 1
        else:
            print("Failed to stop Traffic")
            return 0
    
    #====================================================================================================#
    def clear_traffic_stats(self):
        _result = ixiangpf.traffic_control(action='clear_stats')
        print(_result)
        if _result['status'] == '1':
            print("Cleared Traffic stats successfully")
            return 1
        else:
            print("Failed to clear Traffic stats")
            return 0
    
    #====================================================================================================#
    
    def verify_traffic(self,threshold):
        
        fail_flag = 0
        
        #--------------------------------------------------------------------------------#
        # Populating stats
        
        print("Clearing stats")
        traffic_run_status = self.clear_traffic_stats()
        
        print("Sleeping for 20 after clearing stats")
        time.sleep(20)
        
        #--------------------------------------------------------------------------------#
        # Start traffic
        log.info("--- Populating the statistics --- \n")
        log.info("---- Running Traffic --- \n")
        log.info("Starting Traffic")
        
        traffic_run_status  = self.start_traffic()
        
        if traffic_run_status is not 1:
           lof.info("Failed: To start traffic")
           return 0
        else:
            log.info("\nTraffic started successfully\n")
        
        # Wait for the stats to populate
        print("Sleeping for 20 after starting Traffic")
        time.sleep(20)
        
        #--------------------------------------------------------------------------------#
        # Populating stats
        
        # Stop Traffic
        log.info("--- Stopping Traffic ---- \n")
        print("Stopping Traffic")
        traffic_run_status = self.stop_traffic()
        
        if traffic_run_status is not 1:
           log.info("Failed: To Stop traffic")
           return 0
        else:
            log.info("\nTraffic Stopped successfully\n")
        
        # Wait for the stats to populate
        print("Sleeping for 20 after stopping Traffic")
        time.sleep(20)
        
        #--------------------------------------------------------------------------------#
        # Retrieving Stats
        
        print("Retrieving Stats")
        
        for traffic_stats_retry in range(5):
            r = ixiangpf.traffic_stats(
                mode = 'traffic_item',
                )
            
            if "waiting_for_stats" in r.keys():            
                #print(r['waiting_for_stats'])
                if r['waiting_for_stats'] == '0':
                    break
                print("Traffic waiting_for_stats flag is 1. Trial" + str(traffic_stats_retry))
                time.sleep(10)
                
            if "status" in r.keys():            
                #print(r['waiting_for_stats'])
                if r['status'] == '0':
                    log.debug("Retrieving Traffic Stats failed" + str(r['log']))
                    return 0
        
        if r['waiting_for_stats'] == '1':
            log.info("Traffic statistics are not ready after 120 seconds. waiting_for_stats is 1")
            return 0
        
        for item in r['traffic_item']:
            if re.match("TI\\d+",item,re.I):
                print("TRAFFIC ITEM - " + str(item))
                loss_percent = float(r['traffic_item'][item]['rx']['loss_percent'])
                if loss_percent <= threshold:
                    log.info("For  " + str(item) + " Loss % is acceptable " + str(loss_percent) + " for threshold of "+ str(threshold))
                else:
                    log.info("For  " + str(item) + " Loss % is not acceptable " + str(loss_percent) + " for threshold of "+ str(threshold))
                    fail_flag = 1
        
        if fail_flag == 1:
            return 0
        else:
            return 1