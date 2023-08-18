from pyats.aereport.utils.argsvalidator import ArgsValidator
ArgVal = ArgsValidator()
import re
import logging
import time
import texttable
from pyats.log.utils import banner

log = logging.getLogger(__name__)
log.setLevel(logging.DEBUG)

from ixiatcl import IxiaTcl
from ixiahlt import IxiaHlt
from ixiangpf import IxiaNgpf

ixiatcl = IxiaTcl()
ixiahlt = IxiaHlt(ixiatcl)
ixiangpf = IxiaNgpf(ixiahlt)

class ixiaPyats_lib:
    # First we create a constructor for this class 
    # and add members to it, here models 
    def __init__(self): 
        pass
    
    #====================================================================================================#
    @staticmethod
    def connect_to_ixia (args_dict):
        
        help_string ="""
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
                ('tcl_port'     , '0', [str]),
                ('reset'        , 'o', [int]),
                ]
        
        # Validate Arguments
        try:
            ArgVal.validate(args_def, **args_dict)
        except Exception as e:
            log.info("Exception seen:" + str(e))
            log.info(help_string)
            return 0
        
        ixTclServer = str(args_dict['tcl_server']) + ":" + str(args_dict['tcl_port'])
        
        if 'reset' not in args_dict.keys():
                args_dict['reset'] = 1

        
        _result_ = ixiangpf.connect(
            device                  = args_dict['chassis_ip'],
            port_list               = args_dict['port_list'],
            ixnetwork_tcl_server    = ixTclServer,
            reset                   = args_dict['reset'],
            connect_timeout         = 180,
            break_locks             = 1
        )
        
        #log.info(_result_)
        
        if _result_['status'] == '1':
            log.info("Ixia connection successful")
            return _result_
        else:
            log.info("Ixia connection Failed" + str(_result_['log']))
            return 0
    
    #====================================================================================================#
    @staticmethod
    def create_topo_device_grp(args_dict):
        
        help_string = """
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
            log.info("Exception seen:" + str(e))
            log.info(help_string)
            return 0
        
        topology_status = ixiangpf.topology_config(
            port_handle         = args_dict['port_handle'],
            topology_name       = args_dict['topology_name']
        )
        
        if topology_status['status'] == '1':
            log.info ('Topology created successfully')
        else:
            log.info(topology_status)
            return 0
        
        topo_handle = topology_status['topology_handle']
        
        tp_device_status = ixiangpf.topology_config(
            topology_handle         =   topo_handle,
            device_group_name       =   args_dict['device_grp_name'],
            device_group_multiplier =   "1",
            device_group_enabled    =   "1"
        )
        
        if tp_device_status['status'] == '1':
            log.info ('Topology and Device group created successfully')
            return {'topo_hndl' : topo_handle, 'dev_grp_hndl' : tp_device_status['device_group_handle']}
        else:
            log.info('Topology and Device group creation Failed')
            log.info(tp_device_status)
            return 0
        
    #====================================================================================================#
    @staticmethod
    def configure_ixia_interface(args_dict):
        
        help_string = """
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
            log.info("Exception seen:" + str(e))
            log.info(help_string)
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
                log.info('Configured Ixia Interface Port Mode successfully')
            else:
                log.info('Configuring Ixia Interface Port Mode Failed')
                log.info(int_phy_status)
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
                log.info('Configured Ethernet mode on the Interface')
            else:
                log.info('Failed Configuring Ethernet mode on the Interface')
                log.info(eth_config_status)
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
                log.info('Configured IPv4 mode on the Interface')
                return {'eth_handle' : eth_handle, 'ipv4_handle' : v4_handle, 'topo_int_handle' : topo_int_handle}
            else:
                log.info('Failed Configuring IPv4 mode on the Interface')
                log.info(ipv4_config_status)
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
                log.info('Configured Ethernet mode on the Interface')
            else:
                log.info('Failed Configuring Ethernet mode on the Interface')
                log.info(eth_config_status)
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
            
            v6_handle = ipv6_config_status['ipv6_handle']
            topo_int_handle = ipv6_config_status['interface_handle']
            
            if ipv6_config_status['status'] == '1':
                log.info('Configured IPv6 mode on the Interface')
                return {'eth_handle' : eth_handle, 'ipv6_handle' : v6_handle, 'topo_int_handle' : topo_int_handle}
            else:
                log.info('Failed Configuring IPv6 mode on the Interface')
                log.info(ipv6_config_status)
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
                log.info('Configured Ethernet mode on the Interface')
            else:
                log.info('Failed Configuring Ethernet mode on the Interface')
                log.info(eth_config_status)
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
                log.info('Configured IPv4/v6 mode on the Interface')
                return {'eth_handle' : eth_handle, 'ipv4_handle' : v4_handle, 'ipv6_handle' : v6_handle, 'topo_int_handle' : topo_int_handle}
            else:
                log.info('Failed Configuring IPv4/v6 mode on the Interface')
                log.info(ipv6_config_status)
                return 0
            
    #====================================================================================================#
    @staticmethod
    def configure_multi_ixia_interface(args_dict):
        
        # Define Arguments Definition
        args_def = [
                ('dev_grp_hndl'     , 'm', [str]),
                ('no_of_ints'       , 'm', [str]),
                ('port_hndl'        , 'm', [str]),
                ('phy_mode'         , 'm', [str]),
                ('mac'              , 'm', [str]),
                ('mac_step'         , 'm', [str]),
                ('protocol'         , 'm', [str]),
                ('v4_addr'          , 'm', [str]),
                ('v4_addr_step'     , 'm', [str]),
                ('v4_netmask'       , 'm', [str]),
                ('v4_gateway'       , 'm', [str]),
                ('v4_gateway_step'  , 'm', [str]),
                ('v6_addr'          , 'o', [str]),
                ('v6_addr_step'     , 'o', [str]),
                ('v6_netmask'       , 'o', [str]),
                ('v6_gateway'       , 'o', [str]),
                ('v6_gateway_step'  , 'o', [str]),
                ('vlan_id'          , 'o', [str]),
                ('vlan_id_step'     , 'o', [str])
                ]
        
        # Validate Arguments
        try:
            ArgVal.validate(args_def, **args_dict)
        except Exception as e:
            log.info("Exception seen:" + str(e))
            #log.info(help_string)
            return 0
        
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
                log.info('Configured Ixia Interface Port Mode successfully')
            else:
                log.info('Configured Ixia Interface Port Mode Failed')
                log.info(int_phy_status)
                return 0
        
        tp_device_status = ixiangpf.topology_config(
            mode                    =   "modify",
            device_group_handle     =   args_dict['dev_grp_hndl'],
            device_group_multiplier =   args_dict['no_of_ints'],
            device_group_enabled    =   "1"
        )
        
        if tp_device_status['status'] == '1':
            log.info("Modified Device group for " + str(args_dict['no_of_ints']) + " successfully")
        else:
            log.info("Modifying Device group for " + str(args_dict['no_of_ints']) + " failed")
            log.info(tp_device_status)
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
                log.info('Configured Ethernet mode on the Interface')
            else:
                log.info('Failed Configuring Ethernet mode on the Interface')
                log.info(eth_config_status)
                return 0
            
            eth_handle = eth_config_status['ethernet_handle']
            
            ipv4_config_status = ixiangpf.interface_config(
                protocol_name                       = "IPv4",
                protocol_handle                     = eth_handle,
                ipv4_resolve_gateway                = "1",
                intf_ip_addr                        = args_dict['v4_addr'],
                intf_ip_addr_step                   = args_dict['v4_addr_step'],
                gateway                             = args_dict['v4_gateway'],
                gateway_step                        = args_dict['v4_gateway_step'],
                netmask                             = args_dict['v4_netmask']
            )
            
            v4_handle = ipv4_config_status['ipv4_handle']
            topo_int_handle = ipv4_config_status['interface_handle']
            
            #log.info(eth_config_status)
            #log.info(ipv4_config_status)
            
            if ipv4_config_status['status'] == '1':
                log.info('Configured IPv4 mode on the Interface')
                return {'eth_handle' : eth_handle, 'ipv4_handle' : v4_handle, 'topo_int_handle' : topo_int_handle}
            else:
                log.info('Failed Configuring IPv4 mode on the Interface')
                log.info(ipv4_config_status)
                return 0
            
        elif args_dict['protocol'] == "ipv6":
            eth_config_status = ixiangpf.interface_config(
                protocol_name                       = "Ethernet",
                phy_mode                            = args_dict['phy_mode'],
                protocol_handle                     = args_dict['dev_grp_hndl'],
                src_mac_addr                        = args_dict['mac'],
                arp_on_linkup                       = '1',
                vlan                                = vlan_flag,
                vlan_id                             = args_dict['vlan_id'],
                vlan_id_step                        = args_dict['vlan_id_step']
            )
            
            if eth_config_status['status'] == '1':
                log.info('Configured Ethernet mode on the Interface')
            else:
                log.info('Failed Configuring Ethernet mode on the Interface')
                log.info(eth_config_status)
                return 0
            
            eth_handle = eth_config_status['ethernet_handle']
            
            ipv6_config_status = ixiangpf.interface_config(
                protocol_name                       = "IPv6",
                protocol_handle                     = eth_handle,
                ipv6_resolve_gateway                = "1",
                ipv6_intf_addr                      = args_dict['v6_addr'],
                ipv6_intf_addr_step                 = args_dict['v6_addr_step'],
                ipv6_gateway                        = args_dict['v6_gateway'],
                ipv6_gateway_step                   = args_dict['v6_gateway_step'],
                ipv6_prefix_length                  = args_dict['v6_netmask']
            )
            
            v6_handle = ipv6_config_status['ipv6_handle']
            topo_int_handle = ipv6_config_status['interface_handle']
            
            #log.info(eth_config_status)
            #log.info(ipv6_config_status)
            
            if ipv6_config_status['status'] == '1':
                log.info('Configured IPv6 mode on the Interface')
                return {'eth_handle' : eth_handle, 'ipv6_handle' : v6_handle, 'topo_int_handle' : topo_int_handle}
            else:
                log.info('Failed Configuring IPv6 mode on the Interface')
                log.info(ipv6_config_status)
                return 0
            
        elif args_dict['protocol'] == "ipv46":
            eth_config_status = ixiangpf.interface_config(
                protocol_name                       = "Ethernet",
                phy_mode                            = args_dict['phy_mode'],
                protocol_handle                     = args_dict['dev_grp_hndl'],
                src_mac_addr                        = args_dict['mac'],
                arp_on_linkup                       = '1',
                vlan                                = vlan_flag,
                vlan_id                             = args_dict['vlan_id'],
                vlan_id_step                        = args_dict['vlan_id_step']
            )
            
            if eth_config_status['status'] == '1':
                log.info('Configured Ethernet mode on the Interface')
            else:
                log.info('Failed Configuring Ethernet mode on the Interface')
                log.info(eth_config_status)
                return 0
            
            eth_handle = eth_config_status['ethernet_handle']
            
            ipv4_config_status = ixiangpf.interface_config(
                protocol_name                       = "IPv4",
                protocol_handle                     = eth_handle,
                ipv4_resolve_gateway                = "1",
                intf_ip_addr                        = args_dict['v4_addr'],
                intf_ip_addr_step                   = args_dict['v4_addr_step'],
                gateway                             = args_dict['v4_gateway'],
                gateway_step                        = args_dict['v4_gateway_step'],
                netmask                             = args_dict['v4_netmask']
            )
            
            v4_handle = ipv4_config_status['ipv4_handle']
            
            ipv6_config_status = ixiangpf.interface_config(
                protocol_name                       = "IPv6",
                protocol_handle                     = eth_handle,
                ipv6_resolve_gateway                = "1",
                ipv6_intf_addr                      = args_dict['v6_addr'],
                ipv6_intf_addr_step                 = args_dict['v6_addr_step'],
                ipv6_gateway                        = args_dict['v6_gateway'],
                ipv6_gateway_step                   = args_dict['v6_gateway_step'],
                ipv6_prefix_length                  = args_dict['v6_netmask']
            )

            v6_handle = ipv6_config_status['ipv6_handle']
            topo_int_handle = ipv4_config_status['interface_handle']
            
            if ipv6_config_status['status'] == '1':
                log.info('Configured IPv4/v6 mode on the Interface')
                return {'eth_handle' : eth_handle, 'ipv4_handle' : v4_handle, 'ipv6_handle' : v6_handle, 'topo_int_handle' : topo_int_handle}
            else:
                log.info('Failed Configuring IPv4/v6 mode on the Interface')
                log.info(ipv6_config_status)
                return 0
    #====================================================================================================#
    @staticmethod
    def configure_multi_endpoint_ixia_traffic_item(args_dict):

        # Define Arguments Definition
        args_def = [
                ('src_hndl'                     , 'm', [str, list]),
                ('dst_hndl'                     , 'm', [str, list]),
                ('TI_name'                      , 'm', [str]),
                ('circuit'                      , 'm', [str]),
                ('rate_pps'                     , 'm', [str]),
                ('bi_dir'                       , 'm', [str, int, bool]),
                ('no_of_end_points'             , 'm', [str, int]),
                ('src_port_start'               , 'm', [str]),
                ('src_port_start_step'          , 'm', [str]),
                ('src_intf_count'               , 'm', [str]),
                ('dst_port_start'               , 'm', [str]),
                ('dst_port_start_step'          , 'm', [str]),
                ('dst_intf_count'               , 'm', [str]),
                ('route_mesh'                   , 'o', [str]),
        ]

        # Validate Arguments
        try:
            ArgVal.validate(args_def, **args_dict)
        except Exception as e:
            log.info("Exception seen:" + str(e))
            #log.info(help_string)
            return 0

        if 'route_mesh' not in args_dict.keys():
            args_dict['route_mesh'] = 'one_to_one'

        # Setting iteration variables
        emul_src_hndl = []
        emul_dst_hndl = []
        ti_srcs, ti_dsts = {}, {}
        src_port_start      = int(args_dict['src_port_start'])
        src_port_start_step = int(args_dict['src_port_start_step'])
        dst_port_start      = int(args_dict['dst_port_start'])
        dst_port_start_step = int(args_dict['dst_port_start_step'])
        src_intf_start      = 1
        src_intf_count      = int(args_dict['src_intf_count'])
        dst_intf_start      = 1
        dst_intf_count      = int(args_dict['dst_intf_count'])

        for end_point_id in range(1,int(args_dict['no_of_end_points'])+1):

            ti_srcs['EndpointSet-'+str(end_point_id)] = ''
            ti_dsts['EndpointSet-'+str(end_point_id)] = ''
            end_point = 'EndpointSet-'+str(end_point_id)

            ixiatcl.set_py('ti_scalable_srcs('+end_point+')',args_dict['src_hndl'])
            ixiatcl.set_py('ti_scalable_srcs_port_start('+end_point+')', [src_port_start])
            ixiatcl.set_py('ti_scalable_srcs_port_count('+end_point+')', [1])
            ixiatcl.set_py('ti_scalable_srcs_intf_start('+end_point+')', [src_intf_start])
            ixiatcl.set_py('ti_scalable_srcs_intf_count('+end_point+')', [src_intf_count])

            ixiatcl.set_py('ti_scalable_dsts('+end_point+')', args_dict['dst_hndl'])
            ixiatcl.set_py('ti_scalable_dsts_port_start('+end_point+')', [dst_port_start])
            ixiatcl.set_py('ti_scalable_dsts_port_count('+end_point+')', [1])
            ixiatcl.set_py('ti_scalable_dsts_intf_start('+end_point+')', [dst_intf_start])
            ixiatcl.set_py('ti_scalable_dsts_intf_count('+end_point+')', [dst_intf_count])

            emul_src_hndl.append(ti_srcs['EndpointSet-'+str(end_point_id)])
            emul_dst_hndl.append(ti_dsts['EndpointSet-'+str(end_point_id)])

            src_port_start += src_port_start_step
            dst_port_start += dst_port_start_step
            src_intf_start += src_intf_count
            dst_intf_start += dst_intf_count

        _result_ = ixiahlt.traffic_config(
            mode                                = 'create',
            traffic_generator                   = 'ixnetwork_540',
            endpointset_count                   = args_dict['no_of_end_points'],
            emulation_src_handle                = emul_src_hndl,
            emulation_dst_handle                = emul_dst_hndl,
            bidirectional                       = args_dict['bi_dir'],
            name                                = args_dict['TI_name'],
            circuit_endpoint_type               = args_dict['circuit'],
            preamble_size_mode                  = 'auto',
            length_mode                         = 'auto',
            rate_pps                            = args_dict['rate_pps'],
            route_mesh                          = 'fully',
            track_by                            = 'sourceDestValuePair0 trackingenabled0',
            emulation_scalable_src_handle       ='ti_scalable_srcs',
            emulation_scalable_src_port_start   ='ti_scalable_srcs_port_start',
            emulation_scalable_src_port_count   ='ti_scalable_srcs_port_count',
            emulation_scalable_src_intf_start   ='ti_scalable_srcs_intf_start',
            emulation_scalable_src_intf_count   ='ti_scalable_srcs_intf_count',
            emulation_scalable_dst_handle       ='ti_scalable_dsts',
            emulation_scalable_dst_port_start   ='ti_scalable_dsts_port_start',
            emulation_scalable_dst_port_count   ='ti_scalable_dsts_port_count',
            emulation_scalable_dst_intf_start   ='ti_scalable_dsts_intf_start',
            emulation_scalable_dst_intf_count   ='ti_scalable_dsts_intf_count',
            )

        if _result_['status'] == "1":
            log.info("Configured Traffic Item "+str(args_dict['TI_name'])+" successfully")
            return 1
        else:
            log.info("Configuring Traffic Item "+str(args_dict['TI_name'])+" Failed")
            log.info(_result_)
            return 0

    #====================================================================================================#
    @staticmethod
    def configure_ixia_traffic_item(args_dict):
        
        # Define Arguments Definition
        args_def = [
                ('src_hndl'     , 'm', [str, list]),
                ('dst_hndl'     , 'm', [str, list]),
                ('TI_name'      , 'm', [str]),
                ('circuit'      , 'm', [str]),
                ('rate_pps'     , 'm', [str]),
                ('bi_dir'       , 'm', [str, int, bool]),
                ('end_point_set', '0', [str, int, bool]),
                ]
        
        # Validate Arguments
        try:
            ArgVal.validate(args_def, **args_dict)
        except Exception as e:
            log.info("Exception seen:" + str(e))
            #log.info(help_string)
            return 0

        if 'end_point_set' not in args_dict.keys():
            args_dict['end_point_set'] = 1

        _result_ = ixiahlt.traffic_config(
            mode                        = 'create',
            traffic_generator           = 'ixnetwork_540',
            endpointset_count           = args_dict['end_point_set'],
            emulation_src_handle        = args_dict['src_hndl'],
            emulation_dst_handle        = args_dict['dst_hndl'],
            bidirectional               = args_dict['bi_dir'],
            name                        = args_dict['TI_name'],
            circuit_endpoint_type       = args_dict['circuit'],
            preamble_size_mode          = 'auto',
            length_mode                 = 'auto',
            rate_pps                    = args_dict['rate_pps'],
            track_by                    = 'sourceDestValuePair0 trackingenabled0',
            )

        if _result_['status'] == "1":
            log.info("Configured Traffic Item successfully")
            return 1
        else:
            log.info("Configuring Traffic Item Failed")
            log.info(_result_)
            return 0

    # ====================================================================================================#
    @staticmethod
    def configure_raw_ARP_ixia_traffic_item(args_dict):

        # Define Arguments Definition
        args_def = [
            ('src_hndl', 'm', [str, list]),
            ('dst_hndl', 'm', [str, list]),
            ('TI_name', 'm', [str]),
            ('rate_pps', 'm', [str]),
            ('vlan_id', 'm', [str]),
            ('vlan_count', 'm', [str]),
            ('src_mac', 'm', [str]),
            ('src_mac_step', 'm', [str]),
            ('src_ip', 'm', [str]),
            ('dst_ip', 'm', [str]),
            ('src_ip_step', 'm', [str]),
            ('dst_ip_step', 'm', [str]),
        ]

        # Validate Arguments
        try:
            ArgVal.validate(args_def, **args_dict)
        except Exception as e:
            log.info("Exception seen:" + str(e))
            # log.info(help_string)
            return 0

        _result_ = ixiahlt.traffic_config(
            mode                    = 'create',
            traffic_generator       = 'ixnetwork_540',
            emulation_src_handle    = args_dict['src_hndl'],
            emulation_dst_handle    = args_dict['dst_hndl'],
            circuit_type            = "raw",
            name                    = args_dict['TI_name'],
            preamble_size_mode      = 'auto',
            length_mode             = 'auto',
            rate_pps                = args_dict['rate_pps'],
            track_by                = 'trackingenabled0',

            l2_encap                = 'ethernet_ii_vlan',
            vlan_id                 = args_dict['vlan_id'],
            vlan                    = "enable",
            vlan_id_count           = args_dict['vlan_count'],
            vlan_id_mode            = 'increment',

            mac_src                 = args_dict['src_mac'],
            mac_dst                 = 'ff:ff:ff:ff:ff:ff',
            mac_src_count           = args_dict['vlan_count'],
            mac_src_mode            = 'increment',
            mac_src_step            = args_dict['src_mac_step'],

            arp_src_hw_addr         = args_dict['src_mac'],
            arp_src_hw_mode         = 'increment',
            arp_src_hw_count        = args_dict['vlan_count'],
            arp_dst_hw_addr         = 'ff:ff:ff:ff:ff:ff',
            arp_dst_hw_mode         = "fixed",
            arp_operation           = "arpRequest",

            l3_protocol             = 'arp',
            ip_src_addr             = args_dict['src_ip'],
            ip_src_count            = args_dict['vlan_count'],
            ip_src_mode             = 'increment',
            ip_src_step             = args_dict['src_ip_step'],
            ip_dst_addr             = args_dict['dst_ip'],
            ip_dst_count            = args_dict['vlan_count'],
            ip_dst_mode             = 'increment',
            ip_dst_step             = args_dict['dst_ip_step'],
        )

        if _result_['status'] == "1":
            log.info("Configured Traffic Item successfully")
            return 1
        else:
            log.info("Configuring Traffic Item Failed")
            log.info(_result_)
            return 0

    # ====================================================================================================#
    @staticmethod
    def configure_ixia_BCAST_traffic_item(args_dict):

        # Define Arguments Definition
        args_def = [
            ('src_hndl'         , 'm', [str, list]),
            ('dst_hndl'         , 'm', [str, list]),
            ('TI_name'          , 'm', [str]),
            ('frame_size'       , 'm', [str]),
            ('rate_pps'         , 'm', [str]),
            ('src_mac'          , 'm', [str]),
            ('srcmac_step'      , 'm', [str]),
            ('srcmac_count'     , 'm', [str]),
            ('vlan_id'          , 'm', [str]),
            ('vlanid_step'      , 'm', [str]),
            ('vlanid_count'     , 'm', [str]),
            ('ip_src_addrs'     , 'm', [str]),
            ('ip_step'          , 'm', [str]),
        ]

        # Validate Arguments
        try:
            ArgVal.validate(args_def, **args_dict)
        except Exception as e:
            log.info("Exception seen:" + str(e))
            # log.info(help_string)
            return 0

        _result_ = ixiahlt.traffic_config(
                mode                            = "create" ,
                traffic_generator               =  "ixnetwork_540",
                endpointset_count               = "1",
                emulation_src_handle            = args_dict['src_hndl'],
                emulation_dst_handle            = args_dict['dst_hndl'],
                name                            = args_dict['TI_name'],
                circuit_type                    = "raw",
                rate_pps                        = args_dict['rate_pps'],
                frame_size                      = args_dict['frame_size'],
                transmit_mode                   = "continuous",
                frame_rate_distribution_port    = "apply_to_all",
                frame_rate_distribution_stream  = "apply_to_all",
                l2_encap                        = "ethernet_ii",
                mac_dst_mode                    = "fixed",
                mac_dst                         = "ff:ff:ff:ff:ff:ff",
                mac_src_mode                    = "increment",
                mac_src                         = args_dict['src_mac'],
                mac_src_step                    = args_dict['srcmac_step'],
                mac_src_count                   = args_dict['srcmac_count'],
                vlan                            = "enable",
                vlan_id                         = args_dict['vlan_id'],
                vlan_id_tracking                = 1,
                vlan_id_mode                    = "increment",
                vlan_id_step                    = args_dict['vlanid_step'],
                vlan_id_count                   = args_dict['vlanid_count'],
                ip_src_addr                     = args_dict['ip_src_addrs'],
                ip_src_mode                     = "increment",
                ip_src_count                    = args_dict['vlanid_count'],
                ip_src_step                     = args_dict['ip_step'],
                ip_dst_addr                     = "255.255.255.255",
                track_by                        ='sourceDestEndpointPair0 trackingenabled0'
        )

        if _result_['status'] == "1":
            log.info("Configured Traffic Item successfully")
            return 1
        else:
            log.info("Configuring Traffic Item Failed")
            return 0

    # ====================================================================================================#
    @staticmethod
    def configure_ixia_raw_UDP_v4_vlan(args_dict):

        # Define Arguments Definition
        args_def = [
            ('src_hndl'         , 'm', [str, list]),
            ('dst_hndl'         , 'm', [str, list]),
            ('TI_name'          , 'm', [str]),
            ('frame_size'       , 'm', [str]),
            ('rate_pps'         , 'm', [str]),
            ('src_mac'          , 'm', [str]),
            ('srcmac_step'      , 'm', [str]),
            ('srcmac_count'     , 'm', [str]),
            ('vlan_id'          , 'm', [str]),
            ('vlanid_step'      , 'm', [str]),
            ('vlanid_count'     , 'm', [str]),
            ('ip_src_addrs'     , 'm', [str]),
            ('ip_step'          , 'm', [str]),
            ('udp_src_port'     , 'm', [str]),
            ('udp_dst_port'     , 'm', [str]),
        ]

        # Validate Arguments
        try:
            ArgVal.validate(args_def, **args_dict)
        except Exception as e:
            log.info("Exception seen:" + str(e))
            # log.info(help_string)
            return 0

        _result_ = ixiahlt.traffic_config(
                mode                            = "create" ,
                traffic_generator               =  "ixnetwork_540",
                endpointset_count               = "1",
                emulation_src_handle            = args_dict['src_hndl'],
                emulation_dst_handle            = args_dict['dst_hndl'],
                name                            = args_dict['TI_name'],
                circuit_type                    = "raw",
                rate_pps                        = args_dict['rate_pps'],
                frame_size                      = args_dict['frame_size'],
                transmit_mode                   = "continuous",
                frame_rate_distribution_port    = "apply_to_all",
                frame_rate_distribution_stream  = "apply_to_all",
                l2_encap                        = "ethernet_ii",
                mac_dst_mode                    = "fixed",
                mac_dst                         = "ff:ff:ff:ff:ff:ff",
                mac_src_mode                    = "increment",
                mac_src                         = args_dict['src_mac'],
                mac_src_step                    = args_dict['srcmac_step'],
                mac_src_count                   = args_dict['srcmac_count'],
                l4_protocol                     = 'udp',
                udp_src_port                    = args_dict['udp_src_port'],
                udp_dst_port                    = args_dict['udp_dst_port'],
                vlan                            = "enable",
                vlan_id                         = args_dict['vlan_id'],
                vlan_id_tracking                = 1,
                vlan_id_mode                    = "increment",
                vlan_id_step                    = args_dict['vlanid_step'],
                vlan_id_count                   = args_dict['vlanid_count'],
                ip_src_addr                     = args_dict['ip_src_addrs'],
                ip_src_mode                     = "increment",
                ip_src_count                    = args_dict['vlanid_count'],
                ip_src_step                     = args_dict['ip_step'],
                ip_dst_addr                     = "255.255.255.255",
                track_by                        ='sourceDestEndpointPair0 trackingenabled0'
        )

        if _result_['status'] == "1":
            log.info("Configured Traffic Item successfully")
            return 1
        else:
            log.info("Configuring Traffic Item Failed")
            return 0

    # ====================================================================================================#
    @staticmethod
    def configure_ixia_UNKNOWN_UCAST_traffic_item(args_dict):

        # Define Arguments Definition
        args_def = [
            ('src_hndl'         , 'm', [str, list]),
            ('dst_hndl'         , 'm', [str, list]),
            ('TI_name'          , 'm', [str]),
            ('frame_size'       , 'm', [str]),
            ('rate_pps'         , 'm', [str]),
            ('dst_mac'          , 'm', [str]),
            ('dstmac_step'      , 'm', [str]),
            ('dstmac_count'     , 'm', [str]),
            ('src_mac'          , 'm', [str]),
            ('srcmac_step'      , 'm', [str]),
            ('srcmac_count'     , 'm', [str]),
            ('vlan_id'          , 'm', [str]),
            ('vlanid_step'      , 'm', [str]),
            ('vlanid_count'     , 'm', [str]),
        ]

        # Validate Arguments
        try:
            ArgVal.validate(args_def, **args_dict)
        except Exception as e:
            log.info("Exception seen:" + str(e))
            # log.info(help_string)
            return 0

        _result_ = ixiahlt.traffic_config(
                            mode                           = "create",
                            traffic_generator              = "ixnetwork_540",
                            endpointset_count              = "1",
                            emulation_src_handle           = args_dict['src_hndl'],
                            emulation_dst_handle           = args_dict['dst_hndl'],
                            name                           = args_dict['TI_name'],
                            circuit_type                   = "raw",
                            rate_pps                       = args_dict['rate_pps'],
                            frame_size                     = args_dict['frame_size'],
                            transmit_mode                  = "continuous",
                            frame_rate_distribution_port   = "apply_to_all",
                            frame_rate_distribution_stream = "apply_to_all",
                            l2_encap                       = "ethernet_ii",
                            mac_dst_mode                   = "increment",
                            mac_dst                        = args_dict['dst_mac'],
                            mac_dst_step                   = args_dict['dstmac_step'],
                            mac_dst_count                  = args_dict['dstmac_count'],
                            mac_src_mode                   = "increment",
                            mac_src                        = args_dict['src_mac'],
                            mac_src_step                   = args_dict['srcmac_step'],
                            mac_src_count                  = args_dict['srcmac_count'],
                            vlan                           = "enable",
                            vlan_id                        = args_dict['vlan_id'],
                            vlan_id_tracking               = 1,
                            vlan_id_mode                   = "increment",
                            vlan_id_step                   = args_dict['vlanid_step'],
                            vlan_id_count                  = args_dict['vlanid_count'],
                            track_by                       ='sourceDestEndpointPair0 trackingenabled0',
                            )

        if _result_['status'] == "1":
            log.info("Configured Traffic Item successfully")
            return 1
        else:
            log.info("Configuring Traffic Item Failed")
            return 0
        
    #====================================================================================================#
    @staticmethod
    def emulate_igmp_groupHost(args_dict):
        
        # Define Arguments Definition
        args_def = [
                ('ipv4_hndl'                    , 'm', [str, list]),
                ('igmp_ver'                     , 'm', [str]),
                ('mcast_grp_ip'                 , 'm', [str]),
                ('mcast_grp_ip_step'            , 'm', [str]),
                ('no_of_grps'                   , 'm', [str]),
                ('mcast_src_ip'                 , 'm', [str]),
                ('mcast_src_ip_step'            , 'm', [str]),
                ('mcast_no_of_srcs'             , 'm', [str]),
                ('mcast_grp_ip_step_per_port'   , 'o', [str]),
                ('mcast_src_ip_step_per_port'   , 'o', [str]),
                ('topology_handle'              , 'o', [str, dict]),
                ]
        
        # Validate Arguments
        # Validate Arguments
        try:
            ArgVal.validate(args_def, **args_dict)
        except Exception as e:
            log.info("Exception seen:" + str(e))
            #log.info(help_string)
            return 0

        _result_ = ixiangpf.emulation_igmp_config(
            handle                  = args_dict['ipv4_hndl'],
            protocol_name           = "IGMP Host",
            mode                    = "create",
            filter_mode             = "include",
            igmp_version            = args_dict['igmp_ver'],
        )

        if _result_['status'] == "1":
            log.info('Passed emulation_igmp_config')
        else:
            log.info('Failed emulation_igmp_config')
            log.info(_result_)
            return 0

        igmpHost_handle = _result_['igmp_host_handle']

        # Setting default Values
        if 'mcast_grp_ip_step_per_port' in args_dict.keys():

            _result_ = ixiangpf.multivalue_config(
                pattern                 = "counter",
                counter_start           = args_dict['mcast_grp_ip'],
                counter_step            = args_dict['mcast_grp_ip_step_per_port'],
                counter_direction       = "increment",
                nest_step               = '%s' % "0.0.0.1",
                nest_owner              = '%s' % (args_dict['topology_handle']),
                nest_enabled            = '%s' % "0",
            )
            if _result_['status'] != IxiaHlt.SUCCESS:
                ixnHLT_errorHandler('multivalue_config', _result_)

            multivalue_grp_handle = _result_['multivalue_handle']

            _result_ = ixiangpf.emulation_multicast_group_config(
                mode                    = "create",
                ip_addr_start           = multivalue_grp_handle,
                ip_addr_step            = args_dict['mcast_grp_ip_step'],
                num_groups              = args_dict['no_of_grps'],
                active                  = "1",
            )

            if _result_['status'] == "1":
                log.info('Passed emulation_multicast_group_config')
            else:
                log.info('Failed emulation_multicast_group_config')
                log.info(_result_)
                return 0

            igmpMcastIPv4GroupList_handle = _result_['multicast_group_handle']

        else:

            _result_ = ixiangpf.emulation_multicast_group_config(
                mode                    = "create",
                ip_addr_start           = args_dict['mcast_grp_ip'],
                ip_addr_step            = args_dict['mcast_grp_ip_step'],
                num_groups              = args_dict['no_of_grps'],
                active                  = "1",
            )

            if _result_['status'] == "1":
                log.info('Passed emulation_multicast_group_config')
            else:
                log.info('Failed emulation_multicast_group_config')
                log.info(_result_)
                return 0

            igmpMcastIPv4GroupList_handle = _result_['multicast_group_handle']
        
        # Setting default Values
        if 'mcast_src_ip_step_per_port' in args_dict.keys():
        
            _result_ = ixiangpf.multivalue_config(
                pattern                = "counter",
                counter_start          = args_dict['mcast_src_ip'],
                counter_step           = args_dict['mcast_src_ip_step_per_port'],
                counter_direction      = "increment",
                nest_step              = '%s' % "0.0.0.1",
                nest_owner             = '%s' % (args_dict['topology_handle']),
                nest_enabled           = '%s' % "0",
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
            log.info('Passed emulation_multicast_source_config')
        else:
            log.info('Failed emulation_multicast_source_config')
            log.info(_result_)
            
        igmpUcastIPv4SourceList_handle = _result_['multicast_source_handle']
        
        _result_ = ixiangpf.emulation_igmp_group_config(
            mode                    = "create",
            g_filter_mode           = "include",
            group_pool_handle       = igmpMcastIPv4GroupList_handle,
            no_of_grp_ranges        = "1",
            session_handle          = igmpHost_handle,
            source_pool_handle      = igmpUcastIPv4SourceList_handle,
        )

        if _result_['status'] == "1":
            log.info('Passed emulation_igmp_group_config')
            return {'igmpHost_handle' : igmpHost_handle, 'igmpMcastGrpList': igmpMcastIPv4GroupList_handle,'igmp_group_handle' : _result_['igmp_group_handle'], 'igmp_source_handle' : _result_['igmp_source_handle']}
        else:
            log.info('Failed emulation_igmp_group_config')
            log.info(_result_)
            return 0

    # ====================================================================================================#
    @staticmethod
    def configure_v4_mcast_traffic_item(args_dict):

        # Define Arguments Definition
        args_def = [
            ('src_hndl'             , 'm', [str, list]),
            ('mcast_dst_hndl'       , 'm', [str, list]),
            ('mcast_rcvr_hndl'      , 'm', [list]),
            ('TI_name'              , 'm', [str]),
            ('rate_pps'             , 'm', [str]),
            ('mcast_rcvr_port_indx' , 'm', [list]),
            ('mcast_rcvr_host_indx' , 'm', [list]),
            ('mcast_rcvr_mcst_indx' , 'm', [list]),
        ]

        # Validate Arguments
        try:
            ArgVal.validate(args_def, **args_dict)
        except Exception as e:
            log.info("Exception seen:" + str(e))
            # log.info(help_string)
            return 0

        mcast_dst_handle_type = []
        for _ in args_dict['mcast_dst_hndl']:
            mcast_dst_handle_type.append('none')

        _result_ = ixiangpf.traffic_config(
            mode                                    = 'create',
            traffic_generator                       = 'ixnetwork_540',
            endpointset_count                       = 1,
            emulation_src_handle                    = args_dict['src_hndl'],
            emulation_dst_handle                    = '',
            emulation_multicast_dst_handle          = args_dict['mcast_dst_hndl'],
            emulation_multicast_dst_handle_type     = mcast_dst_handle_type,
            emulation_multicast_rcvr_handle         = args_dict['mcast_rcvr_hndl'],
            emulation_multicast_rcvr_port_index     = args_dict['mcast_rcvr_port_indx'],
            emulation_multicast_rcvr_host_index     = args_dict['mcast_rcvr_host_indx'],
            emulation_multicast_rcvr_mcast_index    = args_dict['mcast_rcvr_mcst_indx'],
            name                                    = args_dict['TI_name'],
            circuit_endpoint_type                   = 'ipv4',
            transmit_distribution                   = 'srcDestEndpointPair0',
            rate_pps                                = args_dict['rate_pps'],
            preamble_size_mode                      = 'auto',
            length_mode                             = 'auto',
            track_by                                = 'trackingenabled0 sourceDestEndpointPair0'
        )

        print(_result_)

        if _result_['status'] == '1':
            log.info("Create Mcast TI successfully")
            return 1
        else:
            log.info("Creating Mcast TI Failed")
            return 0

    # ====================================================================================================#
    @staticmethod
    def configure_tag_config_multiplier(args_dict):

        # Define Arguments Definition
        args_def = [
            ('subject_handle'           , 'm', [str, list]),
            ('TAG_count_per_item'       , 'm', [int, str]),
            ('topo_handle'              , 'm', [str, list]),
        ]

        # Validate Arguments
        try:
            ArgVal.validate(args_def, **args_dict)
        except Exception as e:
            log.info("Exception seen:" + str(e))
            # log.info(help_string)
            return 0

        if type(args_dict['TAG_count_per_item']) is str:
            args_dict['TAG_count_per_item'] = int(args_dict['TAG_count_per_item'])

        if type(args_dict['subject_handle']) is str:
            args_dict['subject_handle'] = [args_dict['subject_handle']]

        # ======================================================================================== #
        counter_start = 1
        final_result = []
        for item in args_dict['subject_handle']:

            _result_ = ixiangpf.multivalue_config(
                pattern                 = "counter",
                counter_start           = counter_start,
                counter_step            = "1",
                counter_direction       = "increment",
                nest_step               = '%s' % ("1"),
                nest_owner              = '%s' % (args_dict['topo_handle']),
                nest_enabled            = '%s' % ("0"),
            )

            print("--> MultiValueHandle")
            print(_result_)

            multivalue_handle = _result_['multivalue_handle']

            _result_ = ixiangpf.traffic_tag_config(
                handle                  = item,
                enabled                 = "1",
                name                    = "TAG",
                id                      = multivalue_handle,
            )

            final_result.append(_result_['status'])
            counter_start += args_dict['TAG_count_per_item']

        if 0 in final_result:
            log.info("Configuring TAG Failed")
            return 0
        else:
            log.info("Configured TAG successfully")
            return 1

    # ====================================================================================================#
    @staticmethod
    def configure_v4_mcast_traffic_item_per_tag(args_dict):

        # Define Arguments Definition
        args_def = [
            ('src_ipv4_topo_handle'         , 'm', [str, list]),
            ('total_tags'                   , 'm', [int, str]),
            ('TI_name'                      , 'm', [str]),
            ('rate_pps'                     , 'm', [str]),
            ('frame_size'                   , 'm', [str]),
        ]

        # Validate Arguments
        try:
            ArgVal.validate(args_def, **args_dict)
        except Exception as e:
            log.info("Exception seen:" + str(e))
            # log.info(help_string)
            return 0

        if type(args_dict['total_tags']) is str:
            args_dict['total_tags'] = int(args_dict['total_tags'])

        # ======================================================================================== #
        #  Generate TAG  filter
        TAG_filter = "TAG:"
        for i in  range(1,args_dict['total_tags']+1):
            TAG_filter += str(i)
            if i != args_dict['total_tags']:
                TAG_filter += str(',')

        print(TAG_filter)
        print([[TAG_filter]])

        # ======================================================================================== #

        _result_ = ixiahlt.traffic_config(
            mode='create',
            emulation_src_handle                = args_dict['src_ipv4_topo_handle'],
            emulation_dst_handle                = '',
            name                                = args_dict['TI_name'],
            rate_pps                            = args_dict['rate_pps'],
            emulation_multicast_dst_handle      = 'all_multicast_ranges',
            emulation_multicast_dst_handle_type = 'none',
            tag_filter                          = [[TAG_filter]],
            merge_destinations                  = '1',
            circuit_endpoint_type               = 'ipv4',
            frame_size                          = args_dict['frame_size'],
            track_by                            = 'trackingenabled'
        )

        print("--> Traffic Config")
        print(_result_)

        if _result_['status'] == '1':
            log.info("Create Mcast TI successfully")
            return 1
        else:
            log.info("Creating Mcast TI Failed")
            return 0

    # ====================================================================================================#
    @staticmethod
    def emulate_bgp(args_dict):

        # Define Arguments Definition
        args_def = [
            ('topology',                    'm', [str, list, dict]),
            ('ip_hndl',                     'm', [str, list]),
            ('count',                       'm', [str, list]),
            ('ip_ver',                      'm', [str, int]),
            ('neighbor_type',               'm', [str]),
            ('dut_ip',                      'm', [str]),
            ('dut_ip_step',                 'm', [str]),
            ('ixia_as',                     'm', [str]),
            ('dut_as',                      'm', [str]),
            ('v4_route_start',              'o', [str]),
            ('v6_route_start',              'o', [str]),
            ('v4_route_step',               'o', [str]),
            ('v6_route_step',               'o', [str]),
            ('v4_route_prfx',               'o', [str]),
            ('v6_route_prfx',               'o', [str]),
            ('route_range_multiplier',      'o', [str]),
            ('no_of_routes_per_rt_range',   'o', [str]),
            ('nest_step',                   'o', [str]),
            ('nest_flag',                   'o', [str]),
        ]

        # Validate Arguments
        try:
            ArgVal.validate(args_def, **args_dict)
        except Exception as e:
            log.info("Exception seen:" + str(e))
            # log.info(help_string)
            return 0

        # set return dict
        bgp_dict = {}

        # Setting few default values
        if 'v4_route_start' not in args_dict.keys():
            args_dict['v4_route_start'] = None
        if 'v6_route_start' not in args_dict.keys():
            args_dict['v6_route_start'] = None
        if 'v4_route_step' not in args_dict.keys():
            args_dict['v4_route_step'] = None
        if 'v6_route_step' not in args_dict.keys():
            args_dict['v6_route_step'] = None
        if 'v4_route_prfx' not in args_dict.keys():
            args_dict['v4_route_prfx'] = None
        if 'v6_route_prfx' not in args_dict.keys():
            args_dict['v6_route_prfx'] = None
        if 'route_range_multiplier' not in args_dict.keys():
            args_dict['route_range_multiplier'] = '1'
        if 'nest_step' not in args_dict.keys():
            args_dict['nest_step'] = '0.1.0.0,0.1.0.0'
        if 'nest_flag' not in args_dict.keys():
            args_dict['nest_flag'] = '0,1'

        # Emulate BGP on passed IP handle for IPv4 circuit
        if args_dict['ip_ver'] == 4:
            bgp_emul_status     = ixiangpf.emulation_bgp_config(
                mode                ='create',
                active              ="1",
                handle              =args_dict['ip_hndl'],
                remote_ip_addr      =args_dict['dut_ip'],
                remote_addr_step    =args_dict['dut_ip_step'],
                neighbor_type       =args_dict['neighbor_type'],
                ip_version          =args_dict['ip_ver'],
                local_as            =args_dict['ixia_as'],
                restart_time        ="100",
            )
            if bgp_emul_status['status'] == '1':
                bgp_dict['bgp_handle'] = bgp_emul_status['bgp_handle']
                if args_dict['v4_route_start'] is not None:
                    # Creating multivalue for network group
                    log.info("Creating multivalue pattern for BGP network group on Port 1")
                    multivalue_result = ixiangpf.multivalue_config(
                        pattern             ="counter",
                        counter_start       =args_dict['v4_route_start'],
                        counter_step        =args_dict['v4_route_step'],
                        counter_direction   ="increment",
                        nest_step           =args_dict['nest_step'],
                        nest_owner          ='%s,%s' % (args_dict['topology']['dev_grp_hndl'], args_dict['topology']['topo_hndl']),
                        nest_enabled        =args_dict['nest_flag'],
                    )
                    if multivalue_result['status'] != '1':
                        log.info('multivalue_config', multivalue_result)
                    else:
                        multivalue_handle = multivalue_result['multivalue_handle']
                        # Creating BGP Network Group
                        log.info("Creating BGP Network Group on Port 1")
                        BGP_nw_group = ixiangpf.network_group_config(
                            protocol_handle                 =args_dict['topology']['dev_grp_hndl'],
                            protocol_name                   ="BGP_v4_Network_Group",
                            multiplier                      =args_dict['route_range_multiplier'],
                            enable_device                   ="1",
                            connected_to_handle             =args_dict['topology']['eth_handle'],
                            type                            ="ipv4-prefix",
                            ipv4_prefix_network_address     =multivalue_handle,
                            ipv4_prefix_length              =args_dict['v4_route_prfx'],
                            ipv4_prefix_number_of_addresses =args_dict['no_of_routes_per_rt_range'],
                        )
                        if BGP_nw_group['status'] != '1':
                            log.info('network_group_config', BGP_nw_group)
                            return 0
                        else:
                            bgp_dict['network_group_handle'] = BGP_nw_group['network_group_handle']
                            bgp_dict['ipv4_prefix_pools_handle'] = BGP_nw_group['ipv4_prefix_pools_handle']
                            log.info("Emulated BGP Successfully")
                            return bgp_dict
                else:
                    log.info("Emulated BGP Successfully")
                    return bgp_dict
            else:
                log.info('bgp_emlu_fail_status', bgp_emul_status)
                return 0

        # Emulate BGP on passed IP handle for IPv6 circuit
        if args_dict['ip_ver'] == 6:
            bgp_emul_status = ixiangpf.emulation_bgp_config(
                mode                ='create',
                active              ="1",
                handle              =args_dict['ip_hndl'],
                remote_ipv6_addr    =args_dict['dut_ip'],
                remote_addr_step    =args_dict['dut_ip_step'],
                neighbor_type       =args_dict['neighbor_type'],
                ip_version          =args_dict['ip_ver'],
                local_as            =args_dict['ixia_as'],
                restart_time        ="100",
            )
            if bgp_emul_status['status'] == '1':
                bgp_dict['bgp_handle'] = bgp_emul_status['bgp_handle']
                if args_dict['v6_route_start'] is not None:
                    # Creating multivalue for network group
                    log.info("Creating multivalue pattern for BGP network group on Port 1")
                    multivalue_result   = ixiangpf.multivalue_config(
                        pattern             ="counter",
                        counter_start       =args_dict['v6_route_start'],
                        counter_step        =args_dict['v6_route_step'],
                        counter_direction   ="increment",
                        nest_step           =args_dict['nest_step'],
                        nest_owner          ='%s,%s' % (args_dict['topology']['dev_grp_hndl'], args_dict['topology']['topo_hndl']),
                        nest_enabled        =args_dict['nest_flag'],
                    )
                    if multivalue_result['status'] != '1':
                        log.info('multivalue_config', multivalue_result)
                    else:
                        multivalue_handle = multivalue_result['multivalue_handle']
                        # Creating BGP Network Group
                        log.info("Creating BGP Network Group on Port 1")
                        BGP_nw_group    = ixiangpf.network_group_config(
                            protocol_handle                 =args_dict['topology']['dev_grp_hndl'],
                            protocol_name                   ="BGP_v6_Network_Group",
                            multiplier                      =args_dict['route_range_multiplier'],
                            enable_device                   ="1",
                            connected_to_handle             =args_dict['topology']['eth_handle'],
                            type                            ="ipv6-prefix",
                            ipv6_prefix_network_address     =multivalue_handle,
                            ipv6_prefix_length              =args_dict['v6_route_prfx'],
                            ipv6_prefix_number_of_addresses =args_dict['no_of_routes_per_rt_range'],
                        )
                        if BGP_nw_group['status'] != '1':
                            log.info('network_group_config', BGP_nw_group)
                            return 0
                        else:
                            bgp_dict['network_group_handle'] = BGP_nw_group['network_group_handle']
                            bgp_dict['ipv6_prefix_pools_handle'] = BGP_nw_group['ipv6_prefix_pools_handle']
                            log.info("Emulated BGP Successfully")
                            return bgp_dict
                else:
                    log.info("Emulated BGP Successfully")
                    return bgp_dict
            else:
                log.info('bgp_emlu_fail_status', bgp_emul_status)
                return 0

    #====================================================================================================#
    @staticmethod
    def emulate_dhcp_server(args_dict):

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
                ('subnet'                       , 'o', [str]),
                ('dhcp_offer_router_address'    , 'o', [str]),
                ]

        # Validate Arguments
        try:
            ArgVal.validate(args_def, **args_dict)
        except Exception as e:
            log.info("Exception seen:" + str(e))
            #log.info(help_string)
            return 0

        if 'lease_pool_step' not in args_dict.keys():
            args_dict['lease_pool_step'] = "0.0.0.0"

        if 'lease_pool_prfx_len' not in args_dict.keys():
            args_dict['lease_pool_prfx_len'] = "24"

        # Validate Arguments
        try:
            ArgVal.validate(args_def, **args_dict)
        except Exception as e:
            log.info(e)

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
            subnet                                                      = args_dict['subnet'],
            dhcp_offer_router_address                                   = args_dict['dhcp_offer_router_address']
        )

        if _result_['status'] == "1":
            log.info('Passed Emulating DHCP Server')
            return _result_
        else:
            log.info('Failed Emulating DHCP Server')
            log.info(_result_)
            log.info (_result_)
            return 0

    #====================================================================================================#
    @staticmethod
    def emulate_dhcp_client(args_dict):

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
            log.info("Exception seen:" + str(e))
            #log.info(help_string)
            return 0

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
            log.info('Passed Emulating DHCP Client')
            return dhcp_status
        else:
            log.info('Failed Emulating DHCP Client')
            log.info(dhcp_status)
            log.info(dhcp_status)
            return 0

    #====================================================================================================#
    @staticmethod
    def bindDHCPClient(client, action):

        status = ixiangpf.emulation_dhcp_control(
            handle          = client,
            action          = action,
        )

        if status['status'] == "1":
            log.info('Initiated DHCP Client')
            return 1
        else:
            log.info('Failed to Initiate DHCP Client')
            log.info(status)
            log.info(status)
            return 0

    #====================================================================================================#
    @staticmethod
    def startDHCPServer(dhcp_server):

        status = ixiangpf.emulation_dhcp_server_control(
            dhcp_handle     = dhcp_server,
            action          = 'collect',
        )

        if status['status'] == "1":
            log.info('Initiated DHCP Server')
            return 1
        else:
            log.info('Failed to Initiate DHCP Server')
            log.info(status)
            log.info(status)
            return 0

    #====================================================================================================#
    @staticmethod
    def start_protocols():
        _result = ixiangpf.test_control(action='start_all_protocols')
        if _result['status'] == '1':
            log.info("Protocol started successfully")
            return 1
        else:
            log.info("Failed to start protocol")
            return 0
        
    #====================================================================================================#
    @staticmethod
    def change_phymode(int_hndle, mode):
        _result = ixiangpf.interface_config(
            port_handle         = int_hndle,
            phy_mode            = mode
        )

        if _result['status'] == '1':
            log.info("Changed Phy mode successfully")
            return 1
        else:
            log.info("Failed to change Phy Mode")
            log.info(_result)
            return 0
        
    #====================================================================================================#
    @staticmethod
    def start_topology_protocols(topo_hndle):
        _result = ixiangpf.test_control(handle=topo_hndle,action='start_all_protocols')
        if _result['status'] == '1':
            log.info("Protocol started successfully")
            return 1
        else:
            log.info("Failed to start protocol")
            log.info(_result)
            return 0
        
    #====================================================================================================#
    @staticmethod
    def stop_protocols():
        _result = ixiangpf.test_control(action='stop_all_protocols')
        if _result['status'] == '1':
            log.info("Protocol stopped successfully")
            return 1
        else:
            log.info("Failed to stop protocol")
            log.info(_result)
            return 0

    #====================================================================================================#
    @staticmethod
    def restart_protocols():
        _result = ixiangpf.test_control(action='stop_all_protocols')
        if _result['status'] != '1':
            log.info("Failed to stop protocol")
            log.info(_result)
            return 0
        time.sleep(20)
        _result = ixiangpf.test_control(action='start_all_protocols')
        if _result['status'] != '1':
            log.info("Failed to start protocol")
            log.info(_result)
            return 0
        time.sleep(20)
        log.info("Restarted Protocols Successfully")
        return 1

    #====================================================================================================#
    @staticmethod
    def start_traffic():
        _result = ixiangpf.traffic_control(action='run')
        if _result['status'] == '1':
            log.info("Traffic started successfully")
            return 1
        else:
            log.info("Failed to start Traffic")
            log.info(_result)
            return 0
        
    #====================================================================================================#
    @staticmethod
    def stop_traffic():
        _result = ixiangpf.traffic_control(action='stop')
        if _result['status'] == '1':
            log.info("Traffic stopped successfully")
            return 1
        else:
            log.info("Failed to stop Traffic")
            log.info(_result)
            return 0

    #====================================================================================================#
    @staticmethod
    def apply_traffic():
        _result = ixiangpf.traffic_control(action='apply')
        if _result['status'] == '1':
            log.info("Traffic Applied successfully")
            return 1
        else:
            log.info("Failed to Apply Traffic")
            log.info(_result)
            return 0
    
    #====================================================================================================#
    @staticmethod
    def clear_traffic_stats():
        _result = ixiangpf.traffic_control(action='clear_stats')
        if _result['status'] == '1':
            log.info("Cleared Traffic stats successfully")
            return 1
        else:
            log.info("Failed to clear Traffic stats")
            log.info(_result)
            return 0

    #====================================================================================================#
    @staticmethod
    def end_session():
        _result = ixiangpf.cleanup_session()
        if _result['status'] == '1':
            log.info("IXIA Session ended successfully")
            return 1
        else:
            log.info("Failed to end IXIA Session")
            log.info(_result)
            return 0

    #====================================================================================================#
    def sendTrafficForDuration(self,duration):

        # --------------------------------------------------------------------------------#
        # Start traffic
        log.info("--- Populating the statistics --- \n")
        log.info("---- Running Traffic --- \n")
        log.info("Starting Traffic")

        traffic_run_status = self.start_traffic()

        if traffic_run_status is not 1:
            log.info("Failed: To start traffic")
            return 0
        else:
            log.info("\nTraffic started successfully\n")

        # Wait for the stats to populate
        log.info("Sleeping for " + str(duration) + "sec after starting Traffic")
        time.sleep(duration)

        # --------------------------------------------------------------------------------#
        # Populating stats

        # Stop Traffic
        log.info("--- Stopping Traffic ---- \n")
        log.info("Stopping Traffic")
        traffic_run_status = self.stop_traffic()

        if traffic_run_status is not 1:
            log.info("Failed: To Stop traffic")
            return 0
        else:
            log.info("\nTraffic Stopped successfully\n")

        # Wait for the stats to populate
        log.info("Sleeping for " + str(duration) + "sec after stopping Traffic")
        time.sleep(duration)

    #====================================================================================================#
    def verify_traffic(self,threshold,waitTimeMultiplier = 1):
        
        fail_flag = 0

        TrafficItemTable = texttable.Texttable()
        TrafficItemTable.header(['Traffic Item', 'Loss % Observed\nThreshold - '+str(threshold)+' %', 'Status','Remarks'])
        TrafficItemTable.set_cols_width([40,20,20,50])
        
        #--------------------------------------------------------------------------------#
        # Populating stats
        
        log.info("Clearing stats")
        traffic_run_status = self.clear_traffic_stats()

        if traffic_run_status is not 1:
           log.info("Failed: To clear Stats")
           return 0
        else:
            log.info("\nFailed: Stats cleared successfully\n")
        
        log.info("Sleeping for "+str(20*waitTimeMultiplier)+"sec after clearing stats")
        time.sleep(20*waitTimeMultiplier)
        
        #--------------------------------------------------------------------------------#
        # Start traffic
        log.info("--- Populating the statistics --- \n")
        log.info("---- Running Traffic --- \n")
        log.info("Starting Traffic")
        
        traffic_run_status  = self.start_traffic()
        
        if traffic_run_status is not 1:
           log.info("Failed: To start traffic")
           return 0
        else:
            log.info("\nTraffic started successfully\n")
        
        # Wait for the stats to populate
        log.info("Sleeping for "+str(20*waitTimeMultiplier)+"sec after starting Traffic")
        time.sleep(20*waitTimeMultiplier)
        
        #--------------------------------------------------------------------------------#
        # Populating stats
        
        # Stop Traffic
        log.info("--- Stopping Traffic ---- \n")
        log.info("Stopping Traffic")
        traffic_run_status = self.stop_traffic()
        
        if traffic_run_status is not 1:
           log.info("Failed: To Stop traffic")
           return 0
        else:
            log.info("\nTraffic Stopped successfully\n")
        
        # Wait for the stats to populate
        log.info("Sleeping for "+str(20*waitTimeMultiplier)+"sec after stopping Traffic")
        time.sleep(20*waitTimeMultiplier)
        
        #--------------------------------------------------------------------------------#
        # Retrieving Stats
        
        log.info("Retrieving Stats")
        r = {}
        for traffic_stats_retry in range(5):
            r = ixiangpf.traffic_stats(
                mode = 'traffic_item',
                )
            
            if "waiting_for_stats" in r.keys():            
                #log.info(r['waiting_for_stats'])
                if r['waiting_for_stats'] == '0':
                    break
                log.info("Traffic waiting_for_stats flag is 1. Trial" + str(traffic_stats_retry))
                time.sleep(10)
                
            if "status" in r.keys():            
                #log.info(r['waiting_for_stats'])
                if r['status'] == '0':
                    log.debug("Retrieving Traffic Stats failed" + str(r['log']))
                    return 0
        
        if r['waiting_for_stats'] == '1':
            log.info("Traffic statistics are not ready after 120 seconds. waiting_for_stats is 1")
            return 0
        
        for item in r['traffic_item']:
            if re.match('TI\\d+', item, re.I):
                #log.info("TRAFFIC ITEM - " + str(item))
                if str(r['traffic_item'][item]['rx']['loss_percent']) == 'N/A':
                    tx_pkts = int(r['traffic_item'][item]['tx']['total_pkts'])
                    rx_pkts = int(r['traffic_item'][item]['rx']['total_pkts'])
                    if rx_pkts > tx_pkts:
                        TrafficItemTable.add_row([item, str(r['traffic_item'][item]['rx']['loss_percent']), 'Pass w/ Exception', "Rx("+str(rx_pkts)+") is > Tx("+str(tx_pkts)+")"])
                    else:
                        TrafficItemTable.add_row([item, str(r['traffic_item'][item]['rx']['loss_percent']),'FAIL', "Rx(" + str(rx_pkts) + ") is < Tx(" + str(tx_pkts) + ")"])
                        fail_flag = 1
                else:
                    loss_percent = float(r['traffic_item'][item]['rx']['loss_percent'])
                    if loss_percent <= threshold:
                        TrafficItemTable.add_row([item, loss_percent,'PASS',''])
                    else:
                        TrafficItemTable.add_row([item, loss_percent, 'FAIL',''])
                        fail_flag = 1

        log.info(banner("Threshold for Traffic Item verification is -> "+str(threshold)))
        log.info(TrafficItemTable.draw())

        if fail_flag == 1:
            return 0
        else:
            return 1

    # ====================================================================================================#
    def verify_sampled_traffic(self, threshold, waitTimeMultiplier=1):

        fail_flag = 0

        # --------------------------------------------------------------------------------#
        # Retrieving Stats

        log.info("Retrieving Stats")
        r = {}
        for traffic_stats_retry in range(5):
            r = ixiangpf.traffic_stats(
                mode='traffic_item',
            )

            if "waiting_for_stats" in r.keys():
                # log.info(r['waiting_for_stats'])
                if r['waiting_for_stats'] == '0':
                    break
                log.info("Traffic waiting_for_stats flag is 1. Trial" + str(traffic_stats_retry))
                time.sleep(10)

            if "status" in r.keys():
                # log.info(r['waiting_for_stats'])
                if r['status'] == '0':
                    log.debug("Retrieving Traffic Stats failed" + str(r['log']))
                    return 0

        if r['waiting_for_stats'] == '1':
            log.info("Traffic statistics are not ready after 120 seconds. waiting_for_stats is 1")
            return 0

        for item in r['traffic_item']:
            if re.match('TI\\d+', item, re.I):
                log.info("TRAFFIC ITEM - " + str(item))
                loss_percent = float(r['traffic_item'][item]['rx']['loss_percent'])
                if loss_percent <= threshold:
                    log.info(
                        "For  " + str(item) + " Loss % is acceptable " + str(loss_percent) + " for threshold of " + str(
                            threshold))
                else:
                    log.info("For  " + str(item) + " Loss % is not acceptable " + str(
                        loss_percent) + " for threshold of " + str(threshold))
                    fail_flag = 1

        if fail_flag == 1:
            return 0
        else:
            return 1

    # ====================================================================================================#
    def verify_running_traffic(self, threshold, waitTimeMultiplier=1):

        fail_flag = 0

        # Wait for the stats to populate
        log.info("Sleeping for " + str(20 * waitTimeMultiplier) + "sec after stopping Traffic")
        time.sleep(20 * waitTimeMultiplier)

        # --------------------------------------------------------------------------------#
        # Retrieving Stats

        log.info("Retrieving Stats")
        r = {}
        for traffic_stats_retry in range(5):
            r = ixiangpf.traffic_stats(
                mode='traffic_item',
            )

            if "waiting_for_stats" in r.keys():
                # log.info(r['waiting_for_stats'])
                if r['waiting_for_stats'] == '0':
                    break
                log.info("Traffic waiting_for_stats flag is 1. Trial" + str(traffic_stats_retry))
                time.sleep(10)

            if "status" in r.keys():
                # log.info(r['waiting_for_stats'])
                if r['status'] == '0':
                    log.debug("Retrieving Traffic Stats failed" + str(r['log']))
                    return 0

        if r['waiting_for_stats'] == '1':
            log.info("Traffic statistics are not ready after 120 seconds. waiting_for_stats is 1")
            return 0

        for item in r['traffic_item']:
            if re.match('TI\\d+', item, re.I):
                log.info("TRAFFIC ITEM - " + str(item))
                loss_percent = float(r['traffic_item'][item]['rx']['loss_percent'])
                if loss_percent <= threshold:
                    log.info(
                        "For  " + str(item) + " Loss % is acceptable " + str(loss_percent) + " for threshold of " + str(
                            threshold))
                else:
                    log.info("For  " + str(item) + " Loss % is not acceptable " + str(
                        loss_percent) + " for threshold of " + str(threshold))
                    fail_flag = 1

        # Stop Traffic
        log.info("--- Stopping Traffic ---- \n")
        log.info("Stopping Traffic")
        traffic_run_status = self.stop_traffic()

        if traffic_run_status is not 1:
            log.info("Failed: To Stop traffic")
            return 0
        else:
            log.info("\nTraffic Stopped successfully\n")

        if fail_flag == 1:
            return 0
        else:
            return 1
