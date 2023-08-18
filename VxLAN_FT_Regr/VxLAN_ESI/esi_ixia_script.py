# IxNetwork version: 8.50.1501.9
# time of scriptgen: 5/24/2020, 4:06 PM
import os
import re
import sys
import time
# sys.path.append('/path/to/hltapi/library/common/ixiangpf/python')
# sys.path.append('/path/to/ixnetwork/api/python')

from ixiatcl import IxiaTcl
from ixiahlt import IxiaHlt
from ixiangpf import IxiaNgpf
from ixiaerror import IxiaError

if os.name == 'nt':
    # Please specify tcl_dependencies if you are not using Ixia provide Python and Tcl.
    # Example: tcl_dependencies = ['C:/Program Files/Python36/tcl/tcl8.6']; ixiatcl = IxiaTcl(tcl_autopath=tcl_dependencies)
    ixiatcl = IxiaTcl()
else:
    # unix dependencies
    tcl_dependencies = [
        '/home/user/ixia/ixos/lib',
        '/home/user/ixia/ixnet/IxTclProtocol',
        '/home/user/ixia/ixnet/IxTclNetwork'
    ]
    ixiatcl = IxiaTcl(tcl_autopath=tcl_dependencies)

ixiahlt = IxiaHlt(ixiatcl, use_legacy_api = 1)
ixiangpf = IxiaNgpf(ixiahlt)
            
def ixnHLT_endpointMatch(ixnHLT, ixnpattern_list, handle_type='HANDLE'):
    traffic_ep_ignore_list = [
        '^::ixNet::OBJ-/vport:\d+/protocols/mld/host:\d+$',
        '^::ixNet::OBJ-/vport:\d+/protocolStack/ethernet:[^/]+/ipEndpoint:[^/]+/range:[^/]+/ptpRangeOverIp:1$'
    ]

    rval = []
    for pat in ixnpattern_list:
        if pat[ 0] != '^': pat = '^' + pat
        if pat[-1] != '$': pat = pat + '$'

        for path in set(x for x in ixnHLT if x.startswith(handle_type)):
            ixn_path = path.split(',')[1]
            parent_ixn_path = '/'.join(ixn_path.split('/')[:-1])
            parent_path = '%s,%s' % (handle_type, parent_ixn_path)

            parent_found = False
            if len(rval) > 0 and parent_path in ixnHLT and parent_path in rval:
                parent_found = True

            if not parent_found and re.match(pat, ixn_path) and len(ixnHLT[path]) > 0:
                if not any(re.match(x, ixnHLT[path]) for x in traffic_ep_ignore_list):
                    rval.append(ixnHLT[path])

    return rval
            
# ----------------------------------------------------------------
# Configuration procedure

try:
    ixnHLT_logger('')
except (NameError,):
    def ixnHLT_logger(msg):
        if ixiangpf.INTERACTIVE: print(msg)

try:
    ixnHLT_errorHandler('', {})
except (NameError,):
    def ixnHLT_errorHandler(cmd, retval):
        global ixiatcl
        err = ixiatcl.tcl_error_info()
        log = retval['log']
        additional_info = '> command: %s\n> tcl errorInfo: %s\n> log: %s' % (cmd, err, log)
        raise IxiaError(IxiaError.COMMAND_FAIL, additional_info)
            
def ixnHLT_Scriptgen_Configure(ixiahlt, ixnHLT):
    ixiatcl = ixiahlt.ixiatcl
    # //vport
    ixnHLT_logger('interface_config://vport:<1>...')
    _result_ = ixiahlt.interface_config(
        mode='config',
        port_handle=ixnHLT['PORT-HANDLE,//vport:<1>'],
        transmit_clock_source='external',
        tx_gap_control_mode='average',
        transmit_mode='advanced',
        port_rx_mode='packet_group',
        flow_control_directed_addr='0180.c200.0001',
        enable_flow_control='1',
        internal_ppm_adjust='0',
        ignore_link='0',
        data_integrity='1',
        additional_fcoe_stat_2='fcoe_invalid_frames',
        additional_fcoe_stat_1='fcoe_invalid_delimiter',
        enable_data_center_shared_stats='0',
        arp_refresh_interval='60',
        intf_mode='ethernet',
        speed='ether100',
        duplex='full',
        autonegotiation=1,
        auto_detect_instrumentation_type='floating',
        phy_mode='copper',
        master_slave_mode='auto'    
    )
    # Check status
    if _result_['status'] != IxiaHlt.SUCCESS:
    	ixnHLT_errorHandler('interface_config', _result_)
    # The last configure command did not scriptgen the following attributes:
    # [//vport:<1>]
    # n kBool -isDirectConfigModeEnabled 'False'
    # n kBool -isMapped 'True'
    # n kObjref -connectedTo '$ixNetSG_ref(72)'
    # n kInteger -internalId '1'
    # n kString -name '1/1/1'
    # n kString -ixnChassisVersion '8.50.1501.9'
    # n kString -connectionStatus '10.127.63.100:01:01 '
    # n kString -connectionInfo 'chassis="10.127.63.100" card="1" port="1" portip="10.0.1.1"'
    # n kString -ixosChassisVersion 'ixos 8.50.1700.5 ea'
    # n kBool -isCloudstormPort 'False'
    # n kString -ixnClientVersion '8.50.1501.9'
    # n kArray -validTxModes '{sequential} {interleaved}'
    # n kEnumValue -connectionState 'connectedLinkUp'
    # n kString -licenses 'obsolete, do not use'
    # n kString -assignedTo '10.127.63.100:1:1'
    # n kBool -isPullOnly 'False'
    # n kBool -isVMPort 'False'
    # n kBool -isAvailable 'True'
    # n kBool -isConnected 'True'
    # n kInteger -actualSpeed '1000'
    
    try:
    	ixnHLT['HANDLE,//vport:<1>'] = _result_['interface_handle']
    	config_handles = ixnHLT.setdefault('VPORT-CONFIG-HANDLES,//vport:<1>,interface_config', [])
    	config_handles.append(_result_['interface_handle'])
    except:
    	pass
    ixnHLT_logger('COMPLETED: interface_config')
    
    # //vport
    ixnHLT_logger('interface_config://vport:<2>...')
    _result_ = ixiahlt.interface_config(
        mode='config',
        port_handle=ixnHLT['PORT-HANDLE,//vport:<2>'],
        transmit_clock_source='external',
        tx_gap_control_mode='average',
        transmit_mode='advanced',
        port_rx_mode='packet_group',
        flow_control_directed_addr='0180.c200.0001',
        enable_flow_control='1',
        internal_ppm_adjust='0',
        data_integrity='1',
        additional_fcoe_stat_2='fcoe_invalid_frames',
        additional_fcoe_stat_1='fcoe_invalid_delimiter',
        enable_data_center_shared_stats='0',
        ignore_link='0',
        intf_mode='ethernet',
        speed='ether100',
        duplex='full',
        autonegotiation=1,
        auto_detect_instrumentation_type='floating',
        phy_mode='copper',
        master_slave_mode='auto',
        arp_refresh_interval='60'    
    )
    # Check status
    if _result_['status'] != IxiaHlt.SUCCESS:
    	ixnHLT_errorHandler('interface_config', _result_)
    # The last configure command did not scriptgen the following attributes:
    # [//vport:<2>]
    # n kBool -isDirectConfigModeEnabled 'False'
    # n kBool -isMapped 'True'
    # n kObjref -connectedTo '$ixNetSG_ref(75)'
    # n kInteger -internalId '2'
    # n kString -name '1/1/4'
    # n kString -ixnChassisVersion '8.50.1501.9'
    # n kString -connectionStatus '10.127.63.100:01:04 '
    # n kString -connectionInfo 'chassis="10.127.63.100" card="1" port="4" portip="10.0.1.4"'
    # n kString -ixosChassisVersion 'ixos 8.50.1700.5 ea'
    # n kBool -isCloudstormPort 'False'
    # n kString -ixnClientVersion '8.50.1501.9'
    # n kArray -validTxModes '{sequential} {interleaved}'
    # n kEnumValue -connectionState 'connectedLinkUp'
    # n kString -licenses 'obsolete, do not use'
    # n kString -assignedTo '10.127.63.100:1:4'
    # n kBool -isPullOnly 'False'
    # n kBool -isVMPort 'False'
    # n kBool -isAvailable 'True'
    # n kBool -isConnected 'True'
    # n kInteger -actualSpeed '1000'
    
    try:
    	ixnHLT['HANDLE,//vport:<2>'] = _result_['interface_handle']
    	config_handles = ixnHLT.setdefault('VPORT-CONFIG-HANDLES,//vport:<2>,interface_config', [])
    	config_handles.append(_result_['interface_handle'])
    except:
    	pass
    ixnHLT_logger('COMPLETED: interface_config')
    
    # //vport
    ixnHLT_logger('interface_config://vport:<3>...')
    _result_ = ixiahlt.interface_config(
        mode='config',
        port_handle=ixnHLT['PORT-HANDLE,//vport:<3>'],
        transmit_clock_source='external',
        tx_gap_control_mode='average',
        transmit_mode='advanced',
        port_rx_mode='packet_group',
        flow_control_directed_addr='0180.c200.0001',
        enable_flow_control='1',
        internal_ppm_adjust='0',
        data_integrity='1',
        additional_fcoe_stat_2='fcoe_invalid_frames',
        additional_fcoe_stat_1='fcoe_invalid_delimiter',
        enable_data_center_shared_stats='0',
        ignore_link='0',
        intf_mode='ethernet',
        speed='ether100',
        duplex='full',
        autonegotiation=1,
        auto_detect_instrumentation_type='floating',
        phy_mode='copper',
        master_slave_mode='auto',
        arp_refresh_interval='60'    
    )
    # Check status
    if _result_['status'] != IxiaHlt.SUCCESS:
    	ixnHLT_errorHandler('interface_config', _result_)
    # The last configure command did not scriptgen the following attributes:
    # [//vport:<3>]
    # n kBool -isDirectConfigModeEnabled 'False'
    # n kBool -isMapped 'True'
    # n kObjref -connectedTo '$ixNetSG_ref(76)'
    # n kInteger -internalId '3'
    # n kString -name '1/1/5'
    # n kString -ixnChassisVersion '8.50.1501.9'
    # n kString -connectionStatus '10.127.63.100:01:05 '
    # n kString -connectionInfo 'chassis="10.127.63.100" card="1" port="5" portip="10.0.1.5"'
    # n kString -ixosChassisVersion 'ixos 8.50.1700.5 ea'
    # n kBool -isCloudstormPort 'False'
    # n kString -ixnClientVersion '8.50.1501.9'
    # n kArray -validTxModes '{sequential} {interleaved}'
    # n kEnumValue -connectionState 'connectedLinkUp'
    # n kString -licenses 'obsolete, do not use'
    # n kString -assignedTo '10.127.63.100:1:5'
    # n kBool -isPullOnly 'False'
    # n kBool -isVMPort 'False'
    # n kBool -isAvailable 'True'
    # n kBool -isConnected 'True'
    # n kInteger -actualSpeed '1000'
    
    try:
    	ixnHLT['HANDLE,//vport:<3>'] = _result_['interface_handle']
    	config_handles = ixnHLT.setdefault('VPORT-CONFIG-HANDLES,//vport:<3>,interface_config', [])
    	config_handles.append(_result_['interface_handle'])
    except:
    	pass
    ixnHLT_logger('COMPLETED: interface_config')
    
    # //vport
    ixnHLT_logger('interface_config://vport:<4>...')
    _result_ = ixiahlt.interface_config(
        mode='config',
        port_handle=ixnHLT['PORT-HANDLE,//vport:<4>'],
        transmit_clock_source='external',
        tx_gap_control_mode='average',
        transmit_mode='advanced',
        port_rx_mode='packet_group',
        flow_control_directed_addr='0180.c200.0001',
        enable_flow_control='1',
        internal_ppm_adjust='0',
        ignore_link='0',
        data_integrity='1',
        additional_fcoe_stat_2='fcoe_invalid_frames',
        additional_fcoe_stat_1='fcoe_invalid_delimiter',
        enable_data_center_shared_stats='0',
        arp_refresh_interval='60',
        intf_mode='ethernet',
        speed='ether100',
        duplex='full',
        autonegotiation=1,
        auto_detect_instrumentation_type='floating',
        phy_mode='copper',
        master_slave_mode='auto'    
    )
    # Check status
    if _result_['status'] != IxiaHlt.SUCCESS:
    	ixnHLT_errorHandler('interface_config', _result_)
    # The last configure command did not scriptgen the following attributes:
    # [//vport:<4>]
    # n kBool -isDirectConfigModeEnabled 'False'
    # n kBool -isMapped 'True'
    # n kObjref -connectedTo '$ixNetSG_ref(77)'
    # n kInteger -internalId '4'
    # n kString -name '1/1/6'
    # n kString -ixnChassisVersion '8.50.1501.9'
    # n kString -connectionStatus '10.127.63.100:01:06 '
    # n kString -connectionInfo 'chassis="10.127.63.100" card="1" port="6" portip="10.0.1.6"'
    # n kString -ixosChassisVersion 'ixos 8.50.1700.5 ea'
    # n kBool -isCloudstormPort 'False'
    # n kString -ixnClientVersion '8.50.1501.9'
    # n kArray -validTxModes '{sequential} {interleaved}'
    # n kEnumValue -connectionState 'connectedLinkUp'
    # n kString -licenses 'obsolete, do not use'
    # n kString -assignedTo '10.127.63.100:1:6'
    # n kBool -isPullOnly 'False'
    # n kBool -isVMPort 'False'
    # n kBool -isAvailable 'True'
    # n kBool -isConnected 'True'
    # n kInteger -actualSpeed '1000'
    
    try:
    	ixnHLT['HANDLE,//vport:<4>'] = _result_['interface_handle']
    	config_handles = ixnHLT.setdefault('VPORT-CONFIG-HANDLES,//vport:<4>,interface_config', [])
    	config_handles.append(_result_['interface_handle'])
    except:
    	pass
    ixnHLT_logger('COMPLETED: interface_config')
    
    # //vport/interface
    ixnHLT_logger('interface_config://vport:<1>/interface:<1>...')
    _result_ = ixiahlt.interface_config(
        mode='modify',
        port_handle=ixnHLT['PORT-HANDLE,//vport:<1>'],
        gateway='5.1.0.2',
        intf_ip_addr='5.1.0.3',
        netmask='255.255.0.0',
        check_opposite_ip_version='0',
        src_mac_addr='0010.3ee9.3e22',
        arp_on_linkup='1',
        ns_on_linkup='1',
        single_arp_per_gateway='1',
        single_ns_per_gateway='1',
        mtu=1500,
        vlan='1',
        vlan_id='1001',
        vlan_user_priority='0',
        vlan_tpid='0x8100',
        l23_config_type='protocol_interface'    
    )
    # Check status
    if _result_['status'] != IxiaHlt.SUCCESS:
    	ixnHLT_errorHandler('interface_config', _result_)
    # The last configure command did not scriptgen the following attributes:
    # [//vport:<1>/interface:<1>]
    # n kString -description '1/1/1 - 00 10 3e e9 3e 22 - 1'
    # n kBlob -eui64Id '02 10 3E FF FE E9 3E 22 '
    # n kInteger -mtu '1500'
    
    try:
    	ixnHLT['HANDLE,//vport:<1>/interface:<1>'] = _result_['interface_handle']
    	config_handles = ixnHLT.setdefault('VPORT-CONFIG-HANDLES,//vport:<1>,interface_config', [])
    	config_handles.append(_result_['interface_handle'])
    except:
    	pass
    ixnHLT_logger('COMPLETED: interface_config')
    
    # //vport/interface
    ixnHLT_logger('interface_config://vport:<1>/interface:<2>...')
    _result_ = ixiahlt.interface_config(
        mode='modify',
        port_handle=ixnHLT['PORT-HANDLE,//vport:<1>'],
        gateway='5.5.0.2',
        intf_ip_addr='5.5.0.3',
        netmask='255.255.0.0',
        check_opposite_ip_version='0',
        src_mac_addr='0010.3eed.3e22',
        arp_on_linkup='1',
        ns_on_linkup='1',
        single_arp_per_gateway='1',
        single_ns_per_gateway='1',
        mtu=1500,
        vlan='1',
        vlan_id='1005',
        vlan_user_priority='0',
        vlan_tpid='0x8100',
        l23_config_type='protocol_interface'    
    )
    # Check status
    if _result_['status'] != IxiaHlt.SUCCESS:
    	ixnHLT_errorHandler('interface_config', _result_)
    # The last configure command did not scriptgen the following attributes:
    # [//vport:<1>/interface:<2>]
    # n kString -description '1/1/1 - 00 10 3e ed 3e 22 - 6'
    # n kBlob -eui64Id '02 10 3E FF FE ED 3E 22 '
    # n kInteger -mtu '1500'
    
    try:
    	ixnHLT['HANDLE,//vport:<1>/interface:<2>'] = _result_['interface_handle']
    	config_handles = ixnHLT.setdefault('VPORT-CONFIG-HANDLES,//vport:<1>,interface_config', [])
    	config_handles.append(_result_['interface_handle'])
    except:
    	pass
    ixnHLT_logger('COMPLETED: interface_config')
    
    # //vport/interface
    ixnHLT_logger('interface_config://vport:<1>/interface:<3>...')
    _result_ = ixiahlt.interface_config(
        mode='modify',
        port_handle=ixnHLT['PORT-HANDLE,//vport:<1>'],
        gateway='5.9.0.2',
        intf_ip_addr='5.9.0.3',
        netmask='255.255.0.0',
        check_opposite_ip_version='0',
        src_mac_addr='0010.3ff1.3f22',
        arp_on_linkup='1',
        ns_on_linkup='1',
        single_arp_per_gateway='1',
        single_ns_per_gateway='1',
        mtu=1500,
        vlan='1',
        vlan_id='1009',
        vlan_user_priority='0',
        vlan_tpid='0x8100',
        l23_config_type='protocol_interface'    
    )
    # Check status
    if _result_['status'] != IxiaHlt.SUCCESS:
    	ixnHLT_errorHandler('interface_config', _result_)
    # The last configure command did not scriptgen the following attributes:
    # [//vport:<1>/interface:<3>]
    # n kString -description '1/1/1 - 00 10 3f f1 3f 22 - 11'
    # n kBlob -eui64Id '02 10 3F FF FE F1 3F 22 '
    # n kInteger -mtu '1500'
    
    try:
    	ixnHLT['HANDLE,//vport:<1>/interface:<3>'] = _result_['interface_handle']
    	config_handles = ixnHLT.setdefault('VPORT-CONFIG-HANDLES,//vport:<1>,interface_config', [])
    	config_handles.append(_result_['interface_handle'])
    except:
    	pass
    ixnHLT_logger('COMPLETED: interface_config')
    
    # //vport/interface
    ixnHLT_logger('interface_config://vport:<1>/interface:<4>...')
    _result_ = ixiahlt.interface_config(
        mode='modify',
        port_handle=ixnHLT['PORT-HANDLE,//vport:<1>'],
        gateway='5.13.0.2',
        intf_ip_addr='5.13.0.3',
        netmask='255.255.0.0',
        check_opposite_ip_version='0',
        src_mac_addr='0010.3ff5.3f22',
        arp_on_linkup='1',
        ns_on_linkup='1',
        single_arp_per_gateway='1',
        single_ns_per_gateway='1',
        mtu=1500,
        vlan='1',
        vlan_id='1013',
        vlan_user_priority='0',
        vlan_tpid='0x8100',
        l23_config_type='protocol_interface'    
    )
    # Check status
    if _result_['status'] != IxiaHlt.SUCCESS:
    	ixnHLT_errorHandler('interface_config', _result_)
    # The last configure command did not scriptgen the following attributes:
    # [//vport:<1>/interface:<4>]
    # n kString -description '1/1/1 - 00 10 3f f5 3f 22 - 16'
    # n kBlob -eui64Id '02 10 3F FF FE F5 3F 22 '
    # n kInteger -mtu '1500'
    
    try:
    	ixnHLT['HANDLE,//vport:<1>/interface:<4>'] = _result_['interface_handle']
    	config_handles = ixnHLT.setdefault('VPORT-CONFIG-HANDLES,//vport:<1>,interface_config', [])
    	config_handles.append(_result_['interface_handle'])
    except:
    	pass
    ixnHLT_logger('COMPLETED: interface_config')
    
    # //vport/interface
    ixnHLT_logger('interface_config://vport:<4>/interface:<1>...')
    _result_ = ixiahlt.interface_config(
        mode='modify',
        port_handle=ixnHLT['PORT-HANDLE,//vport:<4>'],
        gateway='5.1.0.3',
        intf_ip_addr='5.1.0.103',
        netmask='255.255.0.0',
        check_opposite_ip_version='0',
        src_mac_addr='0011.e9e9.3e44',
        arp_on_linkup='1',
        ns_on_linkup='1',
        single_arp_per_gateway='1',
        single_ns_per_gateway='1',
        mtu=1500,
        vlan='1',
        vlan_id='1001',
        vlan_user_priority='0',
        vlan_tpid='0x8100',
        l23_config_type='protocol_interface'    
    )
    # Check status
    if _result_['status'] != IxiaHlt.SUCCESS:
    	ixnHLT_errorHandler('interface_config', _result_)
    # The last configure command did not scriptgen the following attributes:
    # [//vport:<4>/interface:<1>]
    # n kString -description '1/1/6 - 00 11 e9 e9 3e 44 - 2'
    # n kBlob -eui64Id '02 11 E9 FF FE E9 3E 44 '
    # n kInteger -mtu '1500'
    
    try:
    	ixnHLT['HANDLE,//vport:<4>/interface:<1>'] = _result_['interface_handle']
    	config_handles = ixnHLT.setdefault('VPORT-CONFIG-HANDLES,//vport:<4>,interface_config', [])
    	config_handles.append(_result_['interface_handle'])
    except:
    	pass
    ixnHLT_logger('COMPLETED: interface_config')
    
    # //vport/interface
    ixnHLT_logger('interface_config://vport:<4>/interface:<2>...')
    _result_ = ixiahlt.interface_config(
        mode='modify',
        port_handle=ixnHLT['PORT-HANDLE,//vport:<4>'],
        gateway='5.2.0.2',
        intf_ip_addr='5.2.0.102',
        netmask='255.255.0.0',
        check_opposite_ip_version='0',
        src_mac_addr='0010.3eea.3e22',
        arp_on_linkup='1',
        ns_on_linkup='1',
        single_arp_per_gateway='1',
        single_ns_per_gateway='1',
        mtu=1500,
        vlan='1',
        vlan_id='1002',
        vlan_user_priority='0',
        vlan_tpid='0x8100',
        l23_config_type='protocol_interface'    
    )
    # Check status
    if _result_['status'] != IxiaHlt.SUCCESS:
    	ixnHLT_errorHandler('interface_config', _result_)
    # The last configure command did not scriptgen the following attributes:
    # [//vport:<4>/interface:<2>]
    # n kString -description '1/1/6 - 00 10 3e ea 3e 22 - 3'
    # n kBlob -eui64Id '02 10 3E FF FE EA 3E 22 '
    # n kInteger -mtu '1500'
    
    try:
    	ixnHLT['HANDLE,//vport:<4>/interface:<2>'] = _result_['interface_handle']
    	config_handles = ixnHLT.setdefault('VPORT-CONFIG-HANDLES,//vport:<4>,interface_config', [])
    	config_handles.append(_result_['interface_handle'])
    except:
    	pass
    ixnHLT_logger('COMPLETED: interface_config')
    
    # //vport/interface
    ixnHLT_logger('interface_config://vport:<4>/interface:<3>...')
    _result_ = ixiahlt.interface_config(
        mode='modify',
        port_handle=ixnHLT['PORT-HANDLE,//vport:<4>'],
        gateway='5.3.0.2',
        intf_ip_addr='5.3.0.102',
        netmask='255.255.0.0',
        check_opposite_ip_version='0',
        src_mac_addr='0010.3eeb.3e22',
        arp_on_linkup='1',
        ns_on_linkup='1',
        single_arp_per_gateway='1',
        single_ns_per_gateway='1',
        mtu=1500,
        vlan='1',
        vlan_id='1003',
        vlan_user_priority='0',
        vlan_tpid='0x8100',
        l23_config_type='protocol_interface'    
    )
    # Check status
    if _result_['status'] != IxiaHlt.SUCCESS:
    	ixnHLT_errorHandler('interface_config', _result_)
    # The last configure command did not scriptgen the following attributes:
    # [//vport:<4>/interface:<3>]
    # n kString -description '1/1/6 - 00 10 3e eb 3e 22 - 4'
    # n kBlob -eui64Id '02 10 3E FF FE EB 3E 22 '
    # n kInteger -mtu '1500'
    
    try:
    	ixnHLT['HANDLE,//vport:<4>/interface:<3>'] = _result_['interface_handle']
    	config_handles = ixnHLT.setdefault('VPORT-CONFIG-HANDLES,//vport:<4>,interface_config', [])
    	config_handles.append(_result_['interface_handle'])
    except:
    	pass
    ixnHLT_logger('COMPLETED: interface_config')
    
    # //vport/interface
    ixnHLT_logger('interface_config://vport:<4>/interface:<4>...')
    _result_ = ixiahlt.interface_config(
        mode='modify',
        port_handle=ixnHLT['PORT-HANDLE,//vport:<4>'],
        gateway='5.4.0.2',
        intf_ip_addr='5.4.0.102',
        netmask='255.255.0.0',
        check_opposite_ip_version='0',
        src_mac_addr='0010.3eec.3e22',
        arp_on_linkup='1',
        ns_on_linkup='1',
        single_arp_per_gateway='1',
        single_ns_per_gateway='1',
        mtu=1500,
        vlan='1',
        vlan_id='1004',
        vlan_user_priority='0',
        vlan_tpid='0x8100',
        l23_config_type='protocol_interface'    
    )
    # Check status
    if _result_['status'] != IxiaHlt.SUCCESS:
    	ixnHLT_errorHandler('interface_config', _result_)
    # The last configure command did not scriptgen the following attributes:
    # [//vport:<4>/interface:<4>]
    # n kString -description '1/1/6 - 00 10 3e ec 3e 22 - 5'
    # n kBlob -eui64Id '02 10 3E FF FE EC 3E 22 '
    # n kInteger -mtu '1500'
    
    try:
    	ixnHLT['HANDLE,//vport:<4>/interface:<4>'] = _result_['interface_handle']
    	config_handles = ixnHLT.setdefault('VPORT-CONFIG-HANDLES,//vport:<4>,interface_config', [])
    	config_handles.append(_result_['interface_handle'])
    except:
    	pass
    ixnHLT_logger('COMPLETED: interface_config')
    
    # //vport/interface
    ixnHLT_logger('interface_config://vport:<4>/interface:<5>...')
    _result_ = ixiahlt.interface_config(
        mode='modify',
        port_handle=ixnHLT['PORT-HANDLE,//vport:<4>'],
        gateway='5.5.0.3',
        intf_ip_addr='5.5.0.103',
        netmask='255.255.0.0',
        check_opposite_ip_version='0',
        src_mac_addr='0011.eded.3e44',
        arp_on_linkup='1',
        ns_on_linkup='1',
        single_arp_per_gateway='1',
        single_ns_per_gateway='1',
        mtu=1500,
        vlan='1',
        vlan_id='1005',
        vlan_user_priority='0',
        vlan_tpid='0x8100',
        l23_config_type='protocol_interface'    
    )
    # Check status
    if _result_['status'] != IxiaHlt.SUCCESS:
    	ixnHLT_errorHandler('interface_config', _result_)
    # The last configure command did not scriptgen the following attributes:
    # [//vport:<4>/interface:<5>]
    # n kString -description '1/1/6 - 00 11 ed ed 3e 44 - 7'
    # n kBlob -eui64Id '02 11 ED FF FE ED 3E 44 '
    # n kInteger -mtu '1500'
    
    try:
    	ixnHLT['HANDLE,//vport:<4>/interface:<5>'] = _result_['interface_handle']
    	config_handles = ixnHLT.setdefault('VPORT-CONFIG-HANDLES,//vport:<4>,interface_config', [])
    	config_handles.append(_result_['interface_handle'])
    except:
    	pass
    ixnHLT_logger('COMPLETED: interface_config')
    
    # //vport/interface
    ixnHLT_logger('interface_config://vport:<4>/interface:<6>...')
    _result_ = ixiahlt.interface_config(
        mode='modify',
        port_handle=ixnHLT['PORT-HANDLE,//vport:<4>'],
        gateway='5.6.0.2',
        intf_ip_addr='5.6.0.102',
        netmask='255.255.0.0',
        check_opposite_ip_version='0',
        src_mac_addr='0010.3eee.3e22',
        arp_on_linkup='1',
        ns_on_linkup='1',
        single_arp_per_gateway='1',
        single_ns_per_gateway='1',
        mtu=1500,
        vlan='1',
        vlan_id='1006',
        vlan_user_priority='0',
        vlan_tpid='0x8100',
        l23_config_type='protocol_interface'    
    )
    # Check status
    if _result_['status'] != IxiaHlt.SUCCESS:
    	ixnHLT_errorHandler('interface_config', _result_)
    # The last configure command did not scriptgen the following attributes:
    # [//vport:<4>/interface:<6>]
    # n kString -description '1/1/6 - 00 10 3e ee 3e 22 - 8'
    # n kBlob -eui64Id '02 10 3E FF FE EE 3E 22 '
    # n kInteger -mtu '1500'
    
    try:
    	ixnHLT['HANDLE,//vport:<4>/interface:<6>'] = _result_['interface_handle']
    	config_handles = ixnHLT.setdefault('VPORT-CONFIG-HANDLES,//vport:<4>,interface_config', [])
    	config_handles.append(_result_['interface_handle'])
    except:
    	pass
    ixnHLT_logger('COMPLETED: interface_config')
    
    # //vport/interface
    ixnHLT_logger('interface_config://vport:<4>/interface:<7>...')
    _result_ = ixiahlt.interface_config(
        mode='modify',
        port_handle=ixnHLT['PORT-HANDLE,//vport:<4>'],
        gateway='5.7.0.2',
        intf_ip_addr='5.7.0.102',
        netmask='255.255.0.0',
        check_opposite_ip_version='0',
        src_mac_addr='0010.3eef.3e22',
        arp_on_linkup='1',
        ns_on_linkup='1',
        single_arp_per_gateway='1',
        single_ns_per_gateway='1',
        mtu=1500,
        vlan='1',
        vlan_id='1007',
        vlan_user_priority='0',
        vlan_tpid='0x8100',
        l23_config_type='protocol_interface'    
    )
    # Check status
    if _result_['status'] != IxiaHlt.SUCCESS:
    	ixnHLT_errorHandler('interface_config', _result_)
    # The last configure command did not scriptgen the following attributes:
    # [//vport:<4>/interface:<7>]
    # n kString -description '1/1/6 - 00 10 3e ef 3e 22 - 9'
    # n kBlob -eui64Id '02 10 3E FF FE EF 3E 22 '
    # n kInteger -mtu '1500'
    
    try:
    	ixnHLT['HANDLE,//vport:<4>/interface:<7>'] = _result_['interface_handle']
    	config_handles = ixnHLT.setdefault('VPORT-CONFIG-HANDLES,//vport:<4>,interface_config', [])
    	config_handles.append(_result_['interface_handle'])
    except:
    	pass
    ixnHLT_logger('COMPLETED: interface_config')
    
    # //vport/interface
    ixnHLT_logger('interface_config://vport:<4>/interface:<8>...')
    _result_ = ixiahlt.interface_config(
        mode='modify',
        port_handle=ixnHLT['PORT-HANDLE,//vport:<4>'],
        gateway='5.8.0.2',
        intf_ip_addr='5.8.0.102',
        netmask='255.255.0.0',
        check_opposite_ip_version='0',
        src_mac_addr='0010.3ff0.3f22',
        arp_on_linkup='1',
        ns_on_linkup='1',
        single_arp_per_gateway='1',
        single_ns_per_gateway='1',
        mtu=1500,
        vlan='1',
        vlan_id='1008',
        vlan_user_priority='0',
        vlan_tpid='0x8100',
        l23_config_type='protocol_interface'    
    )
    # Check status
    if _result_['status'] != IxiaHlt.SUCCESS:
    	ixnHLT_errorHandler('interface_config', _result_)
    # The last configure command did not scriptgen the following attributes:
    # [//vport:<4>/interface:<8>]
    # n kString -description '1/1/6 - 00 10 3f f0 3f 22 - 10'
    # n kBlob -eui64Id '02 10 3F FF FE F0 3F 22 '
    # n kInteger -mtu '1500'
    
    try:
    	ixnHLT['HANDLE,//vport:<4>/interface:<8>'] = _result_['interface_handle']
    	config_handles = ixnHLT.setdefault('VPORT-CONFIG-HANDLES,//vport:<4>,interface_config', [])
    	config_handles.append(_result_['interface_handle'])
    except:
    	pass
    ixnHLT_logger('COMPLETED: interface_config')
    
    # //vport/interface
    ixnHLT_logger('interface_config://vport:<4>/interface:<9>...')
    _result_ = ixiahlt.interface_config(
        mode='modify',
        port_handle=ixnHLT['PORT-HANDLE,//vport:<4>'],
        gateway='5.9.0.3',
        intf_ip_addr='5.9.0.103',
        netmask='255.255.0.0',
        check_opposite_ip_version='0',
        src_mac_addr='0011.f1f1.3f44',
        arp_on_linkup='1',
        ns_on_linkup='1',
        single_arp_per_gateway='1',
        single_ns_per_gateway='1',
        mtu=1500,
        vlan='1',
        vlan_id='1009',
        vlan_user_priority='0',
        vlan_tpid='0x8100',
        l23_config_type='protocol_interface'    
    )
    # Check status
    if _result_['status'] != IxiaHlt.SUCCESS:
    	ixnHLT_errorHandler('interface_config', _result_)
    # The last configure command did not scriptgen the following attributes:
    # [//vport:<4>/interface:<9>]
    # n kString -description '1/1/6 - 00 11 f1 f1 3f 44 - 12'
    # n kBlob -eui64Id '02 11 F1 FF FE F1 3F 44 '
    # n kInteger -mtu '1500'
    
    try:
    	ixnHLT['HANDLE,//vport:<4>/interface:<9>'] = _result_['interface_handle']
    	config_handles = ixnHLT.setdefault('VPORT-CONFIG-HANDLES,//vport:<4>,interface_config', [])
    	config_handles.append(_result_['interface_handle'])
    except:
    	pass
    ixnHLT_logger('COMPLETED: interface_config')
    
    # //vport/interface
    ixnHLT_logger('interface_config://vport:<4>/interface:<10>...')
    _result_ = ixiahlt.interface_config(
        mode='modify',
        port_handle=ixnHLT['PORT-HANDLE,//vport:<4>'],
        gateway='5.10.0.2',
        intf_ip_addr='5.10.0.102',
        netmask='255.255.0.0',
        check_opposite_ip_version='0',
        src_mac_addr='0010.3ff2.3f22',
        arp_on_linkup='1',
        ns_on_linkup='1',
        single_arp_per_gateway='1',
        single_ns_per_gateway='1',
        mtu=1500,
        vlan='1',
        vlan_id='1010',
        vlan_user_priority='0',
        vlan_tpid='0x8100',
        l23_config_type='protocol_interface'    
    )
    # Check status
    if _result_['status'] != IxiaHlt.SUCCESS:
    	ixnHLT_errorHandler('interface_config', _result_)
    # The last configure command did not scriptgen the following attributes:
    # [//vport:<4>/interface:<10>]
    # n kString -description '1/1/6 - 00 10 3f f2 3f 22 - 13'
    # n kBlob -eui64Id '02 10 3F FF FE F2 3F 22 '
    # n kInteger -mtu '1500'
    
    try:
    	ixnHLT['HANDLE,//vport:<4>/interface:<10>'] = _result_['interface_handle']
    	config_handles = ixnHLT.setdefault('VPORT-CONFIG-HANDLES,//vport:<4>,interface_config', [])
    	config_handles.append(_result_['interface_handle'])
    except:
    	pass
    ixnHLT_logger('COMPLETED: interface_config')
    
    # //vport/interface
    ixnHLT_logger('interface_config://vport:<4>/interface:<11>...')
    _result_ = ixiahlt.interface_config(
        mode='modify',
        port_handle=ixnHLT['PORT-HANDLE,//vport:<4>'],
        gateway='5.11.0.2',
        intf_ip_addr='5.11.0.102',
        netmask='255.255.0.0',
        check_opposite_ip_version='0',
        src_mac_addr='0010.3ff3.3f22',
        arp_on_linkup='1',
        ns_on_linkup='1',
        single_arp_per_gateway='1',
        single_ns_per_gateway='1',
        mtu=1500,
        vlan='1',
        vlan_id='1011',
        vlan_user_priority='0',
        vlan_tpid='0x8100',
        l23_config_type='protocol_interface'    
    )
    # Check status
    if _result_['status'] != IxiaHlt.SUCCESS:
    	ixnHLT_errorHandler('interface_config', _result_)
    # The last configure command did not scriptgen the following attributes:
    # [//vport:<4>/interface:<11>]
    # n kString -description '1/1/6 - 00 10 3f f3 3f 22 - 14'
    # n kBlob -eui64Id '02 10 3F FF FE F3 3F 22 '
    # n kInteger -mtu '1500'
    
    try:
    	ixnHLT['HANDLE,//vport:<4>/interface:<11>'] = _result_['interface_handle']
    	config_handles = ixnHLT.setdefault('VPORT-CONFIG-HANDLES,//vport:<4>,interface_config', [])
    	config_handles.append(_result_['interface_handle'])
    except:
    	pass
    ixnHLT_logger('COMPLETED: interface_config')
    
    # //vport/interface
    ixnHLT_logger('interface_config://vport:<4>/interface:<12>...')
    _result_ = ixiahlt.interface_config(
        mode='modify',
        port_handle=ixnHLT['PORT-HANDLE,//vport:<4>'],
        gateway='5.12.0.2',
        intf_ip_addr='5.12.0.102',
        netmask='255.255.0.0',
        check_opposite_ip_version='0',
        src_mac_addr='0010.3ff4.3f22',
        arp_on_linkup='1',
        ns_on_linkup='1',
        single_arp_per_gateway='1',
        single_ns_per_gateway='1',
        mtu=1500,
        vlan='1',
        vlan_id='1012',
        vlan_user_priority='0',
        vlan_tpid='0x8100',
        l23_config_type='protocol_interface'    
    )
    # Check status
    if _result_['status'] != IxiaHlt.SUCCESS:
    	ixnHLT_errorHandler('interface_config', _result_)
    # The last configure command did not scriptgen the following attributes:
    # [//vport:<4>/interface:<12>]
    # n kString -description '1/1/6 - 00 10 3f f4 3f 22 - 15'
    # n kBlob -eui64Id '02 10 3F FF FE F4 3F 22 '
    # n kInteger -mtu '1500'
    
    try:
    	ixnHLT['HANDLE,//vport:<4>/interface:<12>'] = _result_['interface_handle']
    	config_handles = ixnHLT.setdefault('VPORT-CONFIG-HANDLES,//vport:<4>,interface_config', [])
    	config_handles.append(_result_['interface_handle'])
    except:
    	pass
    ixnHLT_logger('COMPLETED: interface_config')
    
    # //vport/interface
    ixnHLT_logger('interface_config://vport:<4>/interface:<13>...')
    _result_ = ixiahlt.interface_config(
        mode='modify',
        port_handle=ixnHLT['PORT-HANDLE,//vport:<4>'],
        gateway='5.13.0.3',
        intf_ip_addr='5.13.0.103',
        netmask='255.255.0.0',
        check_opposite_ip_version='0',
        src_mac_addr='0011.f5f5.3f44',
        arp_on_linkup='1',
        ns_on_linkup='1',
        single_arp_per_gateway='1',
        single_ns_per_gateway='1',
        mtu=1500,
        vlan='1',
        vlan_id='1013',
        vlan_user_priority='0',
        vlan_tpid='0x8100',
        l23_config_type='protocol_interface'    
    )
    # Check status
    if _result_['status'] != IxiaHlt.SUCCESS:
    	ixnHLT_errorHandler('interface_config', _result_)
    # The last configure command did not scriptgen the following attributes:
    # [//vport:<4>/interface:<13>]
    # n kString -description '1/1/6 - 00 11 f5 f5 3f 44 - 17'
    # n kBlob -eui64Id '02 11 F5 FF FE F5 3F 44 '
    # n kInteger -mtu '1500'
    
    try:
    	ixnHLT['HANDLE,//vport:<4>/interface:<13>'] = _result_['interface_handle']
    	config_handles = ixnHLT.setdefault('VPORT-CONFIG-HANDLES,//vport:<4>,interface_config', [])
    	config_handles.append(_result_['interface_handle'])
    except:
    	pass
    ixnHLT_logger('COMPLETED: interface_config')
    
    # //vport/interface
    ixnHLT_logger('interface_config://vport:<4>/interface:<14>...')
    _result_ = ixiahlt.interface_config(
        mode='modify',
        port_handle=ixnHLT['PORT-HANDLE,//vport:<4>'],
        gateway='5.14.0.2',
        intf_ip_addr='5.14.0.102',
        netmask='255.255.0.0',
        check_opposite_ip_version='0',
        src_mac_addr='0010.3ff6.3f22',
        arp_on_linkup='1',
        ns_on_linkup='1',
        single_arp_per_gateway='1',
        single_ns_per_gateway='1',
        mtu=1500,
        vlan='1',
        vlan_id='1014',
        vlan_user_priority='0',
        vlan_tpid='0x8100',
        l23_config_type='protocol_interface'    
    )
    # Check status
    if _result_['status'] != IxiaHlt.SUCCESS:
    	ixnHLT_errorHandler('interface_config', _result_)
    # The last configure command did not scriptgen the following attributes:
    # [//vport:<4>/interface:<14>]
    # n kString -description '1/1/6 - 00 10 3f f6 3f 22 - 18'
    # n kBlob -eui64Id '02 10 3F FF FE F6 3F 22 '
    # n kInteger -mtu '1500'
    
    try:
    	ixnHLT['HANDLE,//vport:<4>/interface:<14>'] = _result_['interface_handle']
    	config_handles = ixnHLT.setdefault('VPORT-CONFIG-HANDLES,//vport:<4>,interface_config', [])
    	config_handles.append(_result_['interface_handle'])
    except:
    	pass
    ixnHLT_logger('COMPLETED: interface_config')
    
    # //vport/interface
    ixnHLT_logger('interface_config://vport:<4>/interface:<15>...')
    _result_ = ixiahlt.interface_config(
        mode='modify',
        port_handle=ixnHLT['PORT-HANDLE,//vport:<4>'],
        gateway='5.15.0.2',
        intf_ip_addr='5.15.0.102',
        netmask='255.255.0.0',
        check_opposite_ip_version='0',
        src_mac_addr='0010.3ff7.3f22',
        arp_on_linkup='1',
        ns_on_linkup='1',
        single_arp_per_gateway='1',
        single_ns_per_gateway='1',
        mtu=1500,
        vlan='1',
        vlan_id='1015',
        vlan_user_priority='0',
        vlan_tpid='0x8100',
        l23_config_type='protocol_interface'    
    )
    # Check status
    if _result_['status'] != IxiaHlt.SUCCESS:
    	ixnHLT_errorHandler('interface_config', _result_)
    # The last configure command did not scriptgen the following attributes:
    # [//vport:<4>/interface:<15>]
    # n kString -description '1/1/6 - 00 10 3f f7 3f 22 - 19'
    # n kBlob -eui64Id '02 10 3F FF FE F7 3F 22 '
    # n kInteger -mtu '1500'
    
    try:
    	ixnHLT['HANDLE,//vport:<4>/interface:<15>'] = _result_['interface_handle']
    	config_handles = ixnHLT.setdefault('VPORT-CONFIG-HANDLES,//vport:<4>,interface_config', [])
    	config_handles.append(_result_['interface_handle'])
    except:
    	pass
    ixnHLT_logger('COMPLETED: interface_config')
    
    # //vport/interface
    ixnHLT_logger('interface_config://vport:<4>/interface:<16>...')
    _result_ = ixiahlt.interface_config(
        mode='modify',
        port_handle=ixnHLT['PORT-HANDLE,//vport:<4>'],
        gateway='5.16.0.2',
        intf_ip_addr='5.16.0.102',
        netmask='255.255.0.0',
        check_opposite_ip_version='0',
        src_mac_addr='0010.3ff8.3f22',
        arp_on_linkup='1',
        ns_on_linkup='1',
        single_arp_per_gateway='1',
        single_ns_per_gateway='1',
        mtu=1500,
        vlan='1',
        vlan_id='1016',
        vlan_user_priority='0',
        vlan_tpid='0x8100',
        l23_config_type='protocol_interface'    
    )
    # Check status
    if _result_['status'] != IxiaHlt.SUCCESS:
    	ixnHLT_errorHandler('interface_config', _result_)
    # The last configure command did not scriptgen the following attributes:
    # [//vport:<4>/interface:<16>]
    # n kString -description '1/1/6 - 00 10 3f f8 3f 22 - 20'
    # n kBlob -eui64Id '02 10 3F FF FE F8 3F 22 '
    # n kInteger -mtu '1500'
    
    try:
    	ixnHLT['HANDLE,//vport:<4>/interface:<16>'] = _result_['interface_handle']
    	config_handles = ixnHLT.setdefault('VPORT-CONFIG-HANDLES,//vport:<4>,interface_config', [])
    	config_handles.append(_result_['interface_handle'])
    except:
    	pass
    ixnHLT_logger('COMPLETED: interface_config')
    
    # //vport/l1Config/rxFilters/filterPalette
    ixnHLT_logger('uds_config://vport:<1>/l1Config/rxFilters/filterPalette...')
    _result_ = ixiahlt.uds_config(
        port_handle=ixnHLT['PORT-HANDLE,//vport:<1>'],
        uds1='1',
        uds1_SA='any',
        uds1_DA='any',
        uds1_error='errAnyFrame',
        uds1_framesize='any',
        uds1_framesize_from='0',
        uds1_framesize_to='0',
        uds1_pattern='any',
        uds2='1',
        uds2_SA='any',
        uds2_DA='any',
        uds2_error='errAnyFrame',
        uds2_framesize='any',
        uds2_framesize_from='0',
        uds2_framesize_to='0',
        uds2_pattern='any',
        uds3='1',
        uds3_SA='any',
        uds3_DA='any',
        uds3_error='errAnyFrame',
        uds3_framesize='any',
        uds3_framesize_from='0',
        uds3_framesize_to='0',
        uds3_pattern='any',
        uds4='1',
        uds4_SA='any',
        uds4_DA='any',
        uds4_error='errAnyFrame',
        uds4_framesize='any',
        uds4_framesize_from='0',
        uds4_framesize_to='0',
        uds4_pattern='any',
        uds5='1',
        uds5_SA='any',
        uds5_DA='any',
        uds5_error='errAnyFrame',
        uds5_framesize='any',
        uds5_framesize_from='0',
        uds5_framesize_to='0',
        uds5_pattern='any',
        uds6='1',
        uds6_SA='any',
        uds6_DA='any',
        uds6_error='errAnyFrame',
        uds6_framesize='any',
        uds6_framesize_from='0',
        uds6_framesize_to='0',
        uds6_pattern='any'    
    )
    # Check status
    if _result_['status'] != IxiaHlt.SUCCESS:
    	ixnHLT_errorHandler('uds_config', _result_)
    # The last configure command did not scriptgen the following attributes:
    # [//vport:<1>/l1Config/rxFilters/filterPalette]
    # n kString -sourceAddress1Mask '00:00:00:00:00:00'
    # n kString -destinationAddress1Mask '00:00:00:00:00:00'
    # n kString -sourceAddress2 '00:00:00:00:00:00'
    # n kEnumValue -pattern2OffsetType 'fromStartOfFrame'
    # n kInteger -pattern2Offset '20'
    # n kString -sourceAddress2Mask '00:00:00:00:00:00'
    # n kString -destinationAddress2 '00:00:00:00:00:00'
    # n kString -destinationAddress1 '00:00:00:00:00:00'
    # n kString -sourceAddress1 '00:00:00:00:00:00'
    # n kString -pattern1 '00'
    # n kString -destinationAddress2Mask '00:00:00:00:00:00'
    # n kInteger -pattern1Offset '20'
    # n kString -pattern2 '00'
    # n kString -pattern2Mask '00'
    # n kEnumValue -pattern1OffsetType 'fromStartOfFrame'
    # n kString -pattern1Mask '00'
    
    ixnHLT_logger('COMPLETED: uds_config')
    
    # //vport/l1Config/rxFilters/filterPalette
    ixnHLT_logger('uds_config://vport:<2>/l1Config/rxFilters/filterPalette...')
    _result_ = ixiahlt.uds_config(
        port_handle=ixnHLT['PORT-HANDLE,//vport:<2>'],
        uds1='1',
        uds1_SA='any',
        uds1_DA='any',
        uds1_error='errAnyFrame',
        uds1_framesize='any',
        uds1_framesize_from='0',
        uds1_framesize_to='0',
        uds1_pattern='any',
        uds2='1',
        uds2_SA='any',
        uds2_DA='any',
        uds2_error='errAnyFrame',
        uds2_framesize='any',
        uds2_framesize_from='0',
        uds2_framesize_to='0',
        uds2_pattern='any',
        uds3='1',
        uds3_SA='any',
        uds3_DA='any',
        uds3_error='errAnyFrame',
        uds3_framesize='any',
        uds3_framesize_from='0',
        uds3_framesize_to='0',
        uds3_pattern='any',
        uds4='1',
        uds4_SA='any',
        uds4_DA='any',
        uds4_error='errAnyFrame',
        uds4_framesize='any',
        uds4_framesize_from='0',
        uds4_framesize_to='0',
        uds4_pattern='any',
        uds5='1',
        uds5_SA='any',
        uds5_DA='any',
        uds5_error='errAnyFrame',
        uds5_framesize='any',
        uds5_framesize_from='0',
        uds5_framesize_to='0',
        uds5_pattern='any',
        uds6='1',
        uds6_SA='any',
        uds6_DA='any',
        uds6_error='errAnyFrame',
        uds6_framesize='any',
        uds6_framesize_from='0',
        uds6_framesize_to='0',
        uds6_pattern='any'    
    )
    # Check status
    if _result_['status'] != IxiaHlt.SUCCESS:
    	ixnHLT_errorHandler('uds_config', _result_)
    # The last configure command did not scriptgen the following attributes:
    # [//vport:<2>/l1Config/rxFilters/filterPalette]
    # n kString -sourceAddress1Mask '00:00:00:00:00:00'
    # n kString -destinationAddress1Mask '00:00:00:00:00:00'
    # n kString -sourceAddress2 '00:00:00:00:00:00'
    # n kEnumValue -pattern2OffsetType 'fromStartOfFrame'
    # n kInteger -pattern2Offset '20'
    # n kString -sourceAddress2Mask '00:00:00:00:00:00'
    # n kString -destinationAddress2 '00:00:00:00:00:00'
    # n kString -destinationAddress1 '00:00:00:00:00:00'
    # n kString -sourceAddress1 '00:00:00:00:00:00'
    # n kString -pattern1 '00'
    # n kString -destinationAddress2Mask '00:00:00:00:00:00'
    # n kInteger -pattern1Offset '20'
    # n kString -pattern2 '00'
    # n kString -pattern2Mask '00'
    # n kEnumValue -pattern1OffsetType 'fromStartOfFrame'
    # n kString -pattern1Mask '00'
    
    ixnHLT_logger('COMPLETED: uds_config')
    
    # //vport/l1Config/rxFilters/filterPalette
    ixnHLT_logger('uds_config://vport:<3>/l1Config/rxFilters/filterPalette...')
    _result_ = ixiahlt.uds_config(
        port_handle=ixnHLT['PORT-HANDLE,//vport:<3>'],
        uds1='1',
        uds1_SA='any',
        uds1_DA='any',
        uds1_error='errAnyFrame',
        uds1_framesize='any',
        uds1_framesize_from='0',
        uds1_framesize_to='0',
        uds1_pattern='any',
        uds2='1',
        uds2_SA='any',
        uds2_DA='any',
        uds2_error='errAnyFrame',
        uds2_framesize='any',
        uds2_framesize_from='0',
        uds2_framesize_to='0',
        uds2_pattern='any',
        uds3='1',
        uds3_SA='any',
        uds3_DA='any',
        uds3_error='errAnyFrame',
        uds3_framesize='any',
        uds3_framesize_from='0',
        uds3_framesize_to='0',
        uds3_pattern='any',
        uds4='1',
        uds4_SA='any',
        uds4_DA='any',
        uds4_error='errAnyFrame',
        uds4_framesize='any',
        uds4_framesize_from='0',
        uds4_framesize_to='0',
        uds4_pattern='any',
        uds5='1',
        uds5_SA='any',
        uds5_DA='any',
        uds5_error='errAnyFrame',
        uds5_framesize='any',
        uds5_framesize_from='0',
        uds5_framesize_to='0',
        uds5_pattern='any',
        uds6='1',
        uds6_SA='any',
        uds6_DA='any',
        uds6_error='errAnyFrame',
        uds6_framesize='any',
        uds6_framesize_from='0',
        uds6_framesize_to='0',
        uds6_pattern='any'    
    )
    # Check status
    if _result_['status'] != IxiaHlt.SUCCESS:
    	ixnHLT_errorHandler('uds_config', _result_)
    # The last configure command did not scriptgen the following attributes:
    # [//vport:<3>/l1Config/rxFilters/filterPalette]
    # n kString -sourceAddress1Mask '00:00:00:00:00:00'
    # n kString -destinationAddress1Mask '00:00:00:00:00:00'
    # n kString -sourceAddress2 '00:00:00:00:00:00'
    # n kEnumValue -pattern2OffsetType 'fromStartOfFrame'
    # n kInteger -pattern2Offset '20'
    # n kString -sourceAddress2Mask '00:00:00:00:00:00'
    # n kString -destinationAddress2 '00:00:00:00:00:00'
    # n kString -destinationAddress1 '00:00:00:00:00:00'
    # n kString -sourceAddress1 '00:00:00:00:00:00'
    # n kString -pattern1 '00'
    # n kString -destinationAddress2Mask '00:00:00:00:00:00'
    # n kInteger -pattern1Offset '20'
    # n kString -pattern2 '00'
    # n kString -pattern2Mask '00'
    # n kEnumValue -pattern1OffsetType 'fromStartOfFrame'
    # n kString -pattern1Mask '00'
    
    ixnHLT_logger('COMPLETED: uds_config')
    
    # //vport/l1Config/rxFilters/filterPalette
    ixnHLT_logger('uds_config://vport:<4>/l1Config/rxFilters/filterPalette...')
    _result_ = ixiahlt.uds_config(
        port_handle=ixnHLT['PORT-HANDLE,//vport:<4>'],
        uds1='1',
        uds1_SA='any',
        uds1_DA='any',
        uds1_error='errAnyFrame',
        uds1_framesize='any',
        uds1_framesize_from='0',
        uds1_framesize_to='0',
        uds1_pattern='any',
        uds2='1',
        uds2_SA='any',
        uds2_DA='any',
        uds2_error='errAnyFrame',
        uds2_framesize='any',
        uds2_framesize_from='0',
        uds2_framesize_to='0',
        uds2_pattern='any',
        uds3='1',
        uds3_SA='any',
        uds3_DA='any',
        uds3_error='errAnyFrame',
        uds3_framesize='any',
        uds3_framesize_from='0',
        uds3_framesize_to='0',
        uds3_pattern='any',
        uds4='1',
        uds4_SA='any',
        uds4_DA='any',
        uds4_error='errAnyFrame',
        uds4_framesize='any',
        uds4_framesize_from='0',
        uds4_framesize_to='0',
        uds4_pattern='any',
        uds5='1',
        uds5_SA='any',
        uds5_DA='any',
        uds5_error='errAnyFrame',
        uds5_framesize='any',
        uds5_framesize_from='0',
        uds5_framesize_to='0',
        uds5_pattern='any',
        uds6='1',
        uds6_SA='any',
        uds6_DA='any',
        uds6_error='errAnyFrame',
        uds6_framesize='any',
        uds6_framesize_from='0',
        uds6_framesize_to='0',
        uds6_pattern='any'    
    )
    # Check status
    if _result_['status'] != IxiaHlt.SUCCESS:
    	ixnHLT_errorHandler('uds_config', _result_)
    # The last configure command did not scriptgen the following attributes:
    # [//vport:<4>/l1Config/rxFilters/filterPalette]
    # n kString -sourceAddress1Mask '00:00:00:00:00:00'
    # n kString -destinationAddress1Mask '00:00:00:00:00:00'
    # n kString -sourceAddress2 '00:00:00:00:00:00'
    # n kEnumValue -pattern2OffsetType 'fromStartOfFrame'
    # n kInteger -pattern2Offset '20'
    # n kString -sourceAddress2Mask '00:00:00:00:00:00'
    # n kString -destinationAddress2 '00:00:00:00:00:00'
    # n kString -destinationAddress1 '00:00:00:00:00:00'
    # n kString -sourceAddress1 '00:00:00:00:00:00'
    # n kString -pattern1 '00'
    # n kString -destinationAddress2Mask '00:00:00:00:00:00'
    # n kInteger -pattern1Offset '20'
    # n kString -pattern2 '00'
    # n kString -pattern2Mask '00'
    # n kEnumValue -pattern1OffsetType 'fromStartOfFrame'
    # n kString -pattern1Mask '00'
    
    ixnHLT_logger('COMPLETED: uds_config')
    
    # //vport/l1Config/rxFilters/filterPalette
    ixnHLT_logger('uds_filter_pallette_config://vport:<1>/l1Config/rxFilters/filterPalette...')
    _result_ = ixiahlt.uds_filter_pallette_config(
        port_handle=ixnHLT['PORT-HANDLE,//vport:<1>'],
        DA1='00:00:00:00:00:00',
        DA2='00:00:00:00:00:00',
        DA_mask1='00:00:00:00:00:00',
        DA_mask2='00:00:00:00:00:00',
        pattern1='0',
        pattern2='0',
        pattern_mask1='0',
        pattern_mask2='0',
        pattern_offset1='20',
        pattern_offset2='20',
        SA1='00:00:00:00:00:00',
        SA2='00:00:00:00:00:00',
        SA_mask1='00:00:00:00:00:00',
        SA_mask2='00:00:00:00:00:00',
        pattern_offset_type1='startOfFrame',
        pattern_offset_type2='startOfFrame'    
    )
    # Check status
    if _result_['status'] != IxiaHlt.SUCCESS:
    	ixnHLT_errorHandler('uds_filter_pallette_config', _result_)
    
    ixnHLT_logger('COMPLETED: uds_filter_pallette_config')
    
    # //vport/l1Config/rxFilters/filterPalette
    ixnHLT_logger('uds_filter_pallette_config://vport:<2>/l1Config/rxFilters/filterPalette...')
    _result_ = ixiahlt.uds_filter_pallette_config(
        port_handle=ixnHLT['PORT-HANDLE,//vport:<2>'],
        DA1='00:00:00:00:00:00',
        DA2='00:00:00:00:00:00',
        DA_mask1='00:00:00:00:00:00',
        DA_mask2='00:00:00:00:00:00',
        pattern1='0',
        pattern2='0',
        pattern_mask1='0',
        pattern_mask2='0',
        pattern_offset1='20',
        pattern_offset2='20',
        SA1='00:00:00:00:00:00',
        SA2='00:00:00:00:00:00',
        SA_mask1='00:00:00:00:00:00',
        SA_mask2='00:00:00:00:00:00',
        pattern_offset_type1='startOfFrame',
        pattern_offset_type2='startOfFrame'    
    )
    # Check status
    if _result_['status'] != IxiaHlt.SUCCESS:
    	ixnHLT_errorHandler('uds_filter_pallette_config', _result_)
    
    ixnHLT_logger('COMPLETED: uds_filter_pallette_config')
    
    # //vport/l1Config/rxFilters/filterPalette
    ixnHLT_logger('uds_filter_pallette_config://vport:<3>/l1Config/rxFilters/filterPalette...')
    _result_ = ixiahlt.uds_filter_pallette_config(
        port_handle=ixnHLT['PORT-HANDLE,//vport:<3>'],
        DA1='00:00:00:00:00:00',
        DA2='00:00:00:00:00:00',
        DA_mask1='00:00:00:00:00:00',
        DA_mask2='00:00:00:00:00:00',
        pattern1='0',
        pattern2='0',
        pattern_mask1='0',
        pattern_mask2='0',
        pattern_offset1='20',
        pattern_offset2='20',
        SA1='00:00:00:00:00:00',
        SA2='00:00:00:00:00:00',
        SA_mask1='00:00:00:00:00:00',
        SA_mask2='00:00:00:00:00:00',
        pattern_offset_type1='startOfFrame',
        pattern_offset_type2='startOfFrame'    
    )
    # Check status
    if _result_['status'] != IxiaHlt.SUCCESS:
    	ixnHLT_errorHandler('uds_filter_pallette_config', _result_)
    
    ixnHLT_logger('COMPLETED: uds_filter_pallette_config')
    
    # //vport/l1Config/rxFilters/filterPalette
    ixnHLT_logger('uds_filter_pallette_config://vport:<4>/l1Config/rxFilters/filterPalette...')
    _result_ = ixiahlt.uds_filter_pallette_config(
        port_handle=ixnHLT['PORT-HANDLE,//vport:<4>'],
        DA1='00:00:00:00:00:00',
        DA2='00:00:00:00:00:00',
        DA_mask1='00:00:00:00:00:00',
        DA_mask2='00:00:00:00:00:00',
        pattern1='0',
        pattern2='0',
        pattern_mask1='0',
        pattern_mask2='0',
        pattern_offset1='20',
        pattern_offset2='20',
        SA1='00:00:00:00:00:00',
        SA2='00:00:00:00:00:00',
        SA_mask1='00:00:00:00:00:00',
        SA_mask2='00:00:00:00:00:00',
        pattern_offset_type1='startOfFrame',
        pattern_offset_type2='startOfFrame'    
    )
    # Check status
    if _result_['status'] != IxiaHlt.SUCCESS:
    	ixnHLT_errorHandler('uds_filter_pallette_config', _result_)
    
    ixnHLT_logger('COMPLETED: uds_filter_pallette_config')
    
    # The following objects had no attributes that were scriptgenned:
    # n //statistics/measurementMode
    # n //vport:<1>/l1Config/ethernet/fcoe
    # n //vport:<1>/capture/trigger
    # n //vport:<1>/capture/filter
    # n //vport:<1>/capture/filterPallette
    # n //vport:<1>/interface:<1>/gre
    # n //vport:<1>/interface:<1>/unconnected
    # n //vport:<1>/interface:<2>/gre
    # n //vport:<1>/interface:<2>/unconnected
    # n //vport:<1>/interface:<3>/gre
    # n //vport:<1>/interface:<3>/unconnected
    # n //vport:<1>/interface:<4>/gre
    # n //vport:<1>/interface:<4>/unconnected
    # n //vport:<2>/l1Config/ethernet/fcoe
    # n //vport:<2>/capture/trigger
    # n //vport:<2>/capture/filter
    # n //vport:<2>/capture/filterPallette
    # n //vport:<3>/l1Config/ethernet/fcoe
    # n //vport:<3>/capture/trigger
    # n //vport:<3>/capture/filter
    # n //vport:<3>/capture/filterPallette
    # n //vport:<4>/l1Config/ethernet/fcoe
    # n //vport:<4>/capture/trigger
    # n //vport:<4>/capture/filter
    # n //vport:<4>/capture/filterPallette
    # n //vport:<4>/interface:<1>/gre
    # n //vport:<4>/interface:<1>/unconnected
    # n //vport:<4>/interface:<2>/gre
    # n //vport:<4>/interface:<2>/unconnected
    # n //vport:<4>/interface:<3>/gre
    # n //vport:<4>/interface:<3>/unconnected
    # n //vport:<4>/interface:<4>/gre
    # n //vport:<4>/interface:<4>/unconnected
    # n //vport:<4>/interface:<5>/gre
    # n //vport:<4>/interface:<5>/unconnected
    # n //vport:<4>/interface:<6>/gre
    # n //vport:<4>/interface:<6>/unconnected
    # n //vport:<4>/interface:<7>/gre
    # n //vport:<4>/interface:<7>/unconnected
    # n //vport:<4>/interface:<8>/gre
    # n //vport:<4>/interface:<8>/unconnected
    # n //vport:<4>/interface:<9>/gre
    # n //vport:<4>/interface:<9>/unconnected
    # n //vport:<4>/interface:<10>/gre
    # n //vport:<4>/interface:<10>/unconnected
    # n //vport:<4>/interface:<11>/gre
    # n //vport:<4>/interface:<11>/unconnected
    # n //vport:<4>/interface:<12>/gre
    # n //vport:<4>/interface:<12>/unconnected
    # n //vport:<4>/interface:<13>/gre
    # n //vport:<4>/interface:<13>/unconnected
    # n //vport:<4>/interface:<14>/gre
    # n //vport:<4>/interface:<14>/unconnected
    # n //vport:<4>/interface:<15>/gre
    # n //vport:<4>/interface:<15>/unconnected
    # n //vport:<4>/interface:<16>/gre
    # n //vport:<4>/interface:<16>/unconnected
    # n //globals/testInspector
    # n //globals/preferences
    # n //reporter
    # n //reporter/testParameters
    # n //reporter/generate
    # n //reporter/saveResults
    # n //statistics/rawData
    # n //statistics/autoRefresh
    # n //impairment
    # n //impairment/defaultProfile
    # n //impairment/defaultProfile/checksums
    # n //impairment/defaultProfile/rxRateLimit
    # n //impairment/defaultProfile/drop
    # n //impairment/defaultProfile/reorder
    # n //impairment/defaultProfile/duplicate
    # n //impairment/defaultProfile/bitError
    # n //impairment/defaultProfile/delay
    # n //impairment/defaultProfile/delayVariation
    # n //impairment/defaultProfile/customDelayVariation
    # n //vport:<1>/l1Config/ethernet/oam
    # n //vport:<1>/l1Config/ethernet/txLane
    # n //vport:<1>/l1Config/OAM
    # n //vport:<1>/protocols
    # n //vport:<1>/protocols/openFlow
    # n //vport:<1>/protocols/openFlow/hostTopologyLearnedInformation/switchHostRangeLearnedInfoTriggerAttributes
    # n //vport:<1>/protocolStack/options
    # n //vport:<1>/interface:<1>/dhcpV4Properties
    # n //vport:<1>/interface:<1>/dhcpV6Properties
    # n //vport:<1>/interface:<2>/dhcpV4Properties
    # n //vport:<1>/interface:<2>/dhcpV6Properties
    # n //vport:<1>/interface:<3>/dhcpV4Properties
    # n //vport:<1>/interface:<3>/dhcpV6Properties
    # n //vport:<1>/interface:<4>/dhcpV4Properties
    # n //vport:<1>/interface:<4>/dhcpV6Properties
    # n //vport:<2>/l1Config/ethernet/oam
    # n //vport:<2>/l1Config/ethernet/txLane
    # n //vport:<2>/l1Config/OAM
    # n //vport:<2>/protocols
    # n //vport:<2>/protocols/openFlow
    # n //vport:<2>/protocols/openFlow/hostTopologyLearnedInformation/switchHostRangeLearnedInfoTriggerAttributes
    # n //vport:<2>/protocolStack/options
    # n //vport:<3>/l1Config/ethernet/oam
    # n //vport:<3>/l1Config/ethernet/txLane
    # n //vport:<3>/l1Config/OAM
    # n //vport:<3>/protocols
    # n //vport:<3>/protocols/openFlow
    # n //vport:<3>/protocols/openFlow/hostTopologyLearnedInformation/switchHostRangeLearnedInfoTriggerAttributes
    # n //vport:<3>/protocolStack/options
    # n //vport:<4>/l1Config/ethernet/oam
    # n //vport:<4>/l1Config/ethernet/txLane
    # n //vport:<4>/l1Config/OAM
    # n //vport:<4>/protocols
    # n //vport:<4>/protocols/openFlow
    # n //vport:<4>/protocols/openFlow/hostTopologyLearnedInformation/switchHostRangeLearnedInfoTriggerAttributes
    # n //vport:<4>/protocolStack/options
    # n //vport:<4>/interface:<1>/dhcpV4Properties
    # n //vport:<4>/interface:<1>/dhcpV6Properties
    # n //vport:<4>/interface:<2>/dhcpV4Properties
    # n //vport:<4>/interface:<2>/dhcpV6Properties
    # n //vport:<4>/interface:<3>/dhcpV4Properties
    # n //vport:<4>/interface:<3>/dhcpV6Properties
    # n //vport:<4>/interface:<4>/dhcpV4Properties
    # n //vport:<4>/interface:<4>/dhcpV6Properties
    # n //vport:<4>/interface:<5>/dhcpV4Properties
    # n //vport:<4>/interface:<5>/dhcpV6Properties
    # n //vport:<4>/interface:<6>/dhcpV4Properties
    # n //vport:<4>/interface:<6>/dhcpV6Properties
    # n //vport:<4>/interface:<7>/dhcpV4Properties
    # n //vport:<4>/interface:<7>/dhcpV6Properties
    # n //vport:<4>/interface:<8>/dhcpV4Properties
    # n //vport:<4>/interface:<8>/dhcpV6Properties
    # n //vport:<4>/interface:<9>/dhcpV4Properties
    # n //vport:<4>/interface:<9>/dhcpV6Properties
    # n //vport:<4>/interface:<10>/dhcpV4Properties
    # n //vport:<4>/interface:<10>/dhcpV6Properties
    # n //vport:<4>/interface:<11>/dhcpV4Properties
    # n //vport:<4>/interface:<11>/dhcpV6Properties
    # n //vport:<4>/interface:<12>/dhcpV4Properties
    # n //vport:<4>/interface:<12>/dhcpV6Properties
    # n //vport:<4>/interface:<13>/dhcpV4Properties
    # n //vport:<4>/interface:<13>/dhcpV6Properties
    # n //vport:<4>/interface:<14>/dhcpV4Properties
    # n //vport:<4>/interface:<14>/dhcpV6Properties
    # n //vport:<4>/interface:<15>/dhcpV4Properties
    # n //vport:<4>/interface:<15>/dhcpV6Properties
    # n //vport:<4>/interface:<16>/dhcpV4Properties
    # n //vport:<4>/interface:<16>/dhcpV6Properties
    # n //globals/testInspector/statistic:<1>
    # n //globals/testInspector/statistic:<2>
    # n //globals/testInspector/statistic:<3>
    # n //globals/testInspector/statistic:<4>
    # n //globals/testInspector/statistic:<5>
    # n //globals/testInspector/statistic:<6>
    # n //globals/testInspector/statistic:<7>
    # n //globals/testInspector/statistic:<8>
    # n {//statistics/rawData/statistic:"Tx Frames"}
    # n {//statistics/rawData/statistic:"Rx Frames"}
    # n {//statistics/rawData/statistic:"Frames Delta"}
    # n {//statistics/rawData/statistic:"Tx Frame Rate"}
    # n {//statistics/rawData/statistic:"Rx Frames Rate"}
    # n {//statistics/rawData/statistic:"Avg Latency (us)"}
    # n {//statistics/rawData/statistic:"Min Latency (us)"}
    # n {//statistics/rawData/statistic:"Max Latency (us)"}
    # n {//statistics/rawData/statistic:"Minimum Delay Variation"}
    # n {//statistics/rawData/statistic:"Maximum Delay Variation"}
    # n {//statistics/rawData/statistic:"Avg Delay Variation"}
    # n {//statistics/rawData/statistic:"Reordered Packets"}
    # n {//statistics/rawData/statistic:"Lost Packets"}
    # end of list
    
def ixnHLT_Scriptgen_RunTest(ixiahlt, ixnHLT):
    ixiatcl = ixiahlt.ixiatcl
    # #######################
    # start phase of the test
    # #######################
    ixnHLT_logger('Waiting 60 seconds before starting protocol(s) ...')
    time.sleep(60)
    
    ixnHLT_logger('Starting all protocol(s) ...')
    
    _result_ = ixiahlt.test_control(action='start_all_protocols')
    # Check status
    if _result_['status'] != IxiaHlt.SUCCESS:
        ixnHLT_errorHandler('ixiahlt::traffic_control', _result_)
    #@ MARKER: hlapi_framework:HLApiStatsConfig
                    
    # 
    #  Reset traffic
    # 
    ixnHLT_logger('Resetting traffic...')
    _result_ = ixiahlt.traffic_control(
        action='reset',
        traffic_generator='ixnetwork_540',
        cpdp_convergence_enable='0',
        l1_rate_stats_enable ='1',
        misdirected_per_flow ='0',
        delay_variation_enable='0',
        packet_loss_duration_enable='0',
        latency_enable='1',
        latency_bins='enabled',
        latency_control='store_and_forward',
        instantaneous_stats_enable='0'    
    )
    # Check status
    if _result_['status'] != IxiaHlt.SUCCESS:
    	ixnHLT_errorHandler('traffic_control', _result_)
    #
    # Collect port_handles for traffic_stats
    #
    traffic_stats_ph = set()
    for (k, v) in ixnHLT.items():
        if k.startswith('PORT-HANDLE,'):
            traffic_stats_ph.add(v)
                    
    # 
    #  Configure traffic for all configuration elements
    # 
    #  -- Traffic item//traffic/trafficItem:<10>
    ixnHLT_logger('Configuring traffic for traffic item: //traffic/trafficItem:<10>')
    
    ti_srcs, ti_dsts = {}, {}
    ti_mcast_rcvr_handle, ti_mcast_rcvr_port_index, ti_mcast_rcvr_host_index, ti_mcast_rcvr_mcast_index = {}, {}, {}, {}
    
    ti_srcs['EndpointSet-1'] = '::ixNet::OBJ-/vport:1/interface:1'
    ti_dsts['EndpointSet-1'] = '::ixNet::OBJ-/vport:4/interface:4'
    
    _result_ = ixiahlt.traffic_config(
        mode='create',
        traffic_generator='ixnetwork_540',
        endpointset_count=1,
        emulation_src_handle=[[ti_srcs['EndpointSet-1']]],
        emulation_dst_handle=[[ti_dsts['EndpointSet-1']]],
        emulation_multicast_dst_handle=[[]],
        emulation_multicast_dst_handle_type=[[]],
        global_dest_mac_retry_count='1',
        global_dest_mac_retry_delay='5',
        enable_data_integrity='1',
        global_enable_dest_mac_retry='1',
        global_enable_min_frame_size='0',
        global_enable_staggered_transmit='0',
        global_enable_stream_ordering='0',
        global_stream_control='continuous',
        global_stream_control_iterations='1',
        global_large_error_threshhold='2',
        global_enable_mac_change_on_fly='0',
        global_max_traffic_generation_queries='500',
        global_mpls_label_learning_timeout='30',
        global_refresh_learned_info_before_apply='0',
        global_use_tx_rx_sync='1',
        global_wait_time='1',
        global_display_mpls_current_label_value='0',
        global_detect_misdirected_packets='0',
        global_frame_ordering='none',
        frame_sequencing='disable',
        frame_sequencing_mode='rx_threshold',
        src_dest_mesh='one_to_one',
        route_mesh='one_to_one',
        bidirectional='1',
        allow_self_destined='0',
        use_cp_rate='1',
        use_cp_size='1',
        enable_dynamic_mpls_labels='0',
        hosts_per_net='1',
        name='TI9-HLTAPI_TRAFFICITEM_540',
        source_filter='all',
        destination_filter='all',
        tag_filter=[[]],
        merge_destinations='0',
        circuit_endpoint_type='ipv4',
        pending_operations_timeout='30'    
    )
    # Check status
    if _result_['status'] != IxiaHlt.SUCCESS:
    	ixnHLT_errorHandler('traffic_config', _result_)
    
    #  -- All current config elements
    config_elements = ixiatcl.convert_tcl_list(_result_['traffic_item'])
    
    #  -- Config Element //traffic/trafficItem:<10>/configElement:<1>
    ixnHLT_logger('Configuring options for config elem: //traffic/trafficItem:<10>/configElement:<1>')
    _result_ = ixiahlt.traffic_config(
        mode='modify',
        traffic_generator='ixnetwork_540',
        stream_id=config_elements[0],
        preamble_size_mode='auto',
        preamble_custom_size='8',
        data_pattern='',
        data_pattern_mode='incr_byte',
        enforce_min_gap='0',
        rate_pps='12500',
        frame_rate_distribution_port='split_evenly',
        frame_rate_distribution_stream='split_evenly',
        frame_size='64',
        length_mode='fixed',
        tx_mode='advanced',
        transmit_mode='continuous',
        pkts_per_burst='1',
        tx_delay='0',
        tx_delay_unit='bytes',
        number_of_packets_per_stream='1',
        loop_count='1',
        min_gap_bytes='12'    
    )
    # Check status
    if _result_['status'] != IxiaHlt.SUCCESS:
    	ixnHLT_errorHandler('traffic_config', _result_)
    
    #  -- Endpoint set EndpointSet-1
    ixnHLT_logger('Configuring traffic for config elem: //traffic/trafficItem:<10>/configElement:<1>')
    ixnHLT_logger('Configuring traffic for endpoint set: EndpointSet-1')
    #  -- Stack //traffic/trafficItem:<10>/configElement:<1>/stack:"ethernet-1"
    _result_ = ixiahlt.traffic_config(
        mode='modify_or_insert',
        traffic_generator='ixnetwork_540',
        stream_id=config_elements[0],
        stack_index='1',
        l2_encap='ethernet_ii',
        mac_dst_mode='fixed',
        mac_dst_tracking='0',
        mac_dst='00:00:00:00:00:00',
        mac_src_mode='fixed',
        mac_src_tracking='0',
        mac_src='00:00:00:00:00:00',
        ethernet_value_mode='fixed',
        ethernet_value='ffff',
        ethernet_value_tracking='0'    
    )
    # Check status
    if _result_['status'] != IxiaHlt.SUCCESS:
    	ixnHLT_errorHandler('traffic_config', _result_)
    
    #  -- Stack //traffic/trafficItem:<10>/configElement:<1>/stack:"vlan-2"
    _result_ = ixiahlt.traffic_config(
        mode='modify_or_insert',
        traffic_generator='ixnetwork_540',
        stream_id=config_elements[0],
        stack_index='2',
        vlan='enable',
        vlan_user_priority_mode='fixed',
        vlan_user_priority='0',
        vlan_user_priority_tracking='0',
        vlan_cfi_mode='fixed',
        vlan_cfi='0',
        vlan_cfi_tracking='0',
        vlan_id_mode='fixed',
        vlan_id='0',
        vlan_id_tracking='0'    
    )
    # Check status
    if _result_['status'] != IxiaHlt.SUCCESS:
    	ixnHLT_errorHandler('traffic_config', _result_)
    
    #  -- Stack //traffic/trafficItem:<10>/configElement:<1>/stack:"ipv4-3"
    _result_ = ixiahlt.traffic_config(
        mode='modify_or_insert',
        traffic_generator='ixnetwork_540',
        stream_id=config_elements[0],
        stack_index='3',
        l3_protocol='ipv4',
        qos_type_ixn='tos',
        ip_precedence_mode='fixed',
        ip_precedence='0',
        ip_precedence_tracking='0',
        ip_delay_mode='fixed',
        ip_delay='0',
        ip_delay_tracking='0',
        ip_throughput_mode='fixed',
        ip_throughput='0',
        ip_throughput_tracking='0',
        ip_reliability_mode='fixed',
        ip_reliability='0',
        ip_reliability_tracking='0',
        ip_cost_mode='fixed',
        ip_cost='0',
        ip_cost_tracking='0',
        ip_cu_mode='fixed',
        ip_cu='0',
        ip_cu_tracking='0',
        ip_id_mode='fixed',
        ip_id='0',
        ip_id_tracking='0',
        ip_reserved_mode='fixed',
        ip_reserved='0',
        ip_reserved_tracking='0',
        ip_fragment_mode='fixed',
        ip_fragment='1',
        ip_fragment_tracking='0',
        ip_fragment_last_mode='fixed',
        ip_fragment_last='1',
        ip_fragment_last_tracking='0',
        ip_fragment_offset_mode='fixed',
        ip_fragment_offset='0',
        ip_fragment_offset_tracking='0',
        ip_ttl_mode='fixed',
        ip_ttl='64',
        ip_ttl_tracking='0',
        track_by='none',
        egress_tracking='none'    
    )
    # Check status
    if _result_['status'] != IxiaHlt.SUCCESS:
    	ixnHLT_errorHandler('traffic_config', _result_)
    
    #  -- Post Options
    ixnHLT_logger('Configuring post options for config elem: //traffic/trafficItem:<10>/configElement:<1>')
    _result_ = ixiahlt.traffic_config(
        mode='modify',
        traffic_generator='ixnetwork_540',
        stream_id=config_elements[0],
        transmit_distribution='none'    
    )
    # Check status
    if _result_['status'] != IxiaHlt.SUCCESS:
    	ixnHLT_errorHandler('traffic_config', _result_)
    
    #  -- Traffic item//traffic/trafficItem:<11>
    ixnHLT_logger('Configuring traffic for traffic item: //traffic/trafficItem:<11>')
    
    ti_srcs, ti_dsts = {}, {}
    ti_mcast_rcvr_handle, ti_mcast_rcvr_port_index, ti_mcast_rcvr_host_index, ti_mcast_rcvr_mcast_index = {}, {}, {}, {}
    
    ti_srcs['EndpointSet-1'] = '::ixNet::OBJ-/vport:1/interface:2'
    ti_dsts['EndpointSet-1'] = '::ixNet::OBJ-/vport:4/interface:5'
    
    _result_ = ixiahlt.traffic_config(
        mode='create',
        traffic_generator='ixnetwork_540',
        endpointset_count=1,
        emulation_src_handle=[[ti_srcs['EndpointSet-1']]],
        emulation_dst_handle=[[ti_dsts['EndpointSet-1']]],
        emulation_multicast_dst_handle=[[]],
        emulation_multicast_dst_handle_type=[[]],
        global_dest_mac_retry_count='1',
        global_dest_mac_retry_delay='5',
        enable_data_integrity='1',
        global_enable_dest_mac_retry='1',
        global_enable_min_frame_size='0',
        global_enable_staggered_transmit='0',
        global_enable_stream_ordering='0',
        global_stream_control='continuous',
        global_stream_control_iterations='1',
        global_large_error_threshhold='2',
        global_enable_mac_change_on_fly='0',
        global_max_traffic_generation_queries='500',
        global_mpls_label_learning_timeout='30',
        global_refresh_learned_info_before_apply='0',
        global_use_tx_rx_sync='1',
        global_wait_time='1',
        global_display_mpls_current_label_value='0',
        global_detect_misdirected_packets='0',
        global_frame_ordering='none',
        frame_sequencing='disable',
        frame_sequencing_mode='rx_threshold',
        src_dest_mesh='one_to_one',
        route_mesh='one_to_one',
        bidirectional='1',
        allow_self_destined='0',
        use_cp_rate='1',
        use_cp_size='1',
        enable_dynamic_mpls_labels='0',
        hosts_per_net='1',
        name='TI10-HLTAPI_TRAFFICITEM_540',
        source_filter='all',
        destination_filter='all',
        tag_filter=[[]],
        merge_destinations='0',
        circuit_endpoint_type='ipv4',
        pending_operations_timeout='30'    
    )
    # Check status
    if _result_['status'] != IxiaHlt.SUCCESS:
    	ixnHLT_errorHandler('traffic_config', _result_)
    
    #  -- All current config elements
    config_elements = ixiatcl.convert_tcl_list(_result_['traffic_item'])
    
    #  -- Config Element //traffic/trafficItem:<11>/configElement:<1>
    ixnHLT_logger('Configuring options for config elem: //traffic/trafficItem:<11>/configElement:<1>')
    _result_ = ixiahlt.traffic_config(
        mode='modify',
        traffic_generator='ixnetwork_540',
        stream_id=config_elements[0],
        preamble_size_mode='auto',
        preamble_custom_size='8',
        data_pattern='',
        data_pattern_mode='incr_byte',
        enforce_min_gap='0',
        rate_pps='12500',
        frame_rate_distribution_port='split_evenly',
        frame_rate_distribution_stream='split_evenly',
        frame_size='64',
        length_mode='fixed',
        tx_mode='advanced',
        transmit_mode='continuous',
        pkts_per_burst='1',
        tx_delay='0',
        tx_delay_unit='bytes',
        number_of_packets_per_stream='1',
        loop_count='1',
        min_gap_bytes='12'    
    )
    # Check status
    if _result_['status'] != IxiaHlt.SUCCESS:
    	ixnHLT_errorHandler('traffic_config', _result_)
    
    #  -- Endpoint set EndpointSet-1
    ixnHLT_logger('Configuring traffic for config elem: //traffic/trafficItem:<11>/configElement:<1>')
    ixnHLT_logger('Configuring traffic for endpoint set: EndpointSet-1')
    #  -- Stack //traffic/trafficItem:<11>/configElement:<1>/stack:"ethernet-1"
    _result_ = ixiahlt.traffic_config(
        mode='modify_or_insert',
        traffic_generator='ixnetwork_540',
        stream_id=config_elements[0],
        stack_index='1',
        l2_encap='ethernet_ii',
        mac_dst_mode='fixed',
        mac_dst_tracking='0',
        mac_dst='00:00:00:00:00:00',
        mac_src_mode='fixed',
        mac_src_tracking='0',
        mac_src='00:00:00:00:00:00',
        ethernet_value_mode='fixed',
        ethernet_value='ffff',
        ethernet_value_tracking='0'    
    )
    # Check status
    if _result_['status'] != IxiaHlt.SUCCESS:
    	ixnHLT_errorHandler('traffic_config', _result_)
    
    #  -- Stack //traffic/trafficItem:<11>/configElement:<1>/stack:"vlan-2"
    _result_ = ixiahlt.traffic_config(
        mode='modify_or_insert',
        traffic_generator='ixnetwork_540',
        stream_id=config_elements[0],
        stack_index='2',
        vlan='enable',
        vlan_user_priority_mode='fixed',
        vlan_user_priority='0',
        vlan_user_priority_tracking='0',
        vlan_cfi_mode='fixed',
        vlan_cfi='0',
        vlan_cfi_tracking='0',
        vlan_id_mode='fixed',
        vlan_id='0',
        vlan_id_tracking='0'    
    )
    # Check status
    if _result_['status'] != IxiaHlt.SUCCESS:
    	ixnHLT_errorHandler('traffic_config', _result_)
    
    #  -- Stack //traffic/trafficItem:<11>/configElement:<1>/stack:"ipv4-3"
    _result_ = ixiahlt.traffic_config(
        mode='modify_or_insert',
        traffic_generator='ixnetwork_540',
        stream_id=config_elements[0],
        stack_index='3',
        l3_protocol='ipv4',
        qos_type_ixn='tos',
        ip_precedence_mode='fixed',
        ip_precedence='0',
        ip_precedence_tracking='0',
        ip_delay_mode='fixed',
        ip_delay='0',
        ip_delay_tracking='0',
        ip_throughput_mode='fixed',
        ip_throughput='0',
        ip_throughput_tracking='0',
        ip_reliability_mode='fixed',
        ip_reliability='0',
        ip_reliability_tracking='0',
        ip_cost_mode='fixed',
        ip_cost='0',
        ip_cost_tracking='0',
        ip_cu_mode='fixed',
        ip_cu='0',
        ip_cu_tracking='0',
        ip_id_mode='fixed',
        ip_id='0',
        ip_id_tracking='0',
        ip_reserved_mode='fixed',
        ip_reserved='0',
        ip_reserved_tracking='0',
        ip_fragment_mode='fixed',
        ip_fragment='1',
        ip_fragment_tracking='0',
        ip_fragment_last_mode='fixed',
        ip_fragment_last='1',
        ip_fragment_last_tracking='0',
        ip_fragment_offset_mode='fixed',
        ip_fragment_offset='0',
        ip_fragment_offset_tracking='0',
        ip_ttl_mode='fixed',
        ip_ttl='64',
        ip_ttl_tracking='0',
        track_by='none',
        egress_tracking='none'    
    )
    # Check status
    if _result_['status'] != IxiaHlt.SUCCESS:
    	ixnHLT_errorHandler('traffic_config', _result_)
    
    #  -- Post Options
    ixnHLT_logger('Configuring post options for config elem: //traffic/trafficItem:<11>/configElement:<1>')
    _result_ = ixiahlt.traffic_config(
        mode='modify',
        traffic_generator='ixnetwork_540',
        stream_id=config_elements[0],
        transmit_distribution='none'    
    )
    # Check status
    if _result_['status'] != IxiaHlt.SUCCESS:
    	ixnHLT_errorHandler('traffic_config', _result_)
    
    #  -- Traffic item//traffic/trafficItem:<12>
    ixnHLT_logger('Configuring traffic for traffic item: //traffic/trafficItem:<12>')
    
    ti_srcs, ti_dsts = {}, {}
    ti_mcast_rcvr_handle, ti_mcast_rcvr_port_index, ti_mcast_rcvr_host_index, ti_mcast_rcvr_mcast_index = {}, {}, {}, {}
    
    ti_srcs['EndpointSet-1'] = '::ixNet::OBJ-/vport:1/interface:2'
    ti_dsts['EndpointSet-1'] = '::ixNet::OBJ-/vport:4/interface:6'
    
    _result_ = ixiahlt.traffic_config(
        mode='create',
        traffic_generator='ixnetwork_540',
        endpointset_count=1,
        emulation_src_handle=[[ti_srcs['EndpointSet-1']]],
        emulation_dst_handle=[[ti_dsts['EndpointSet-1']]],
        emulation_multicast_dst_handle=[[]],
        emulation_multicast_dst_handle_type=[[]],
        global_dest_mac_retry_count='1',
        global_dest_mac_retry_delay='5',
        enable_data_integrity='1',
        global_enable_dest_mac_retry='1',
        global_enable_min_frame_size='0',
        global_enable_staggered_transmit='0',
        global_enable_stream_ordering='0',
        global_stream_control='continuous',
        global_stream_control_iterations='1',
        global_large_error_threshhold='2',
        global_enable_mac_change_on_fly='0',
        global_max_traffic_generation_queries='500',
        global_mpls_label_learning_timeout='30',
        global_refresh_learned_info_before_apply='0',
        global_use_tx_rx_sync='1',
        global_wait_time='1',
        global_display_mpls_current_label_value='0',
        global_detect_misdirected_packets='0',
        global_frame_ordering='none',
        frame_sequencing='disable',
        frame_sequencing_mode='rx_threshold',
        src_dest_mesh='one_to_one',
        route_mesh='one_to_one',
        bidirectional='1',
        allow_self_destined='0',
        use_cp_rate='1',
        use_cp_size='1',
        enable_dynamic_mpls_labels='0',
        hosts_per_net='1',
        name='TI11-HLTAPI_TRAFFICITEM_540',
        source_filter='all',
        destination_filter='all',
        tag_filter=[[]],
        merge_destinations='0',
        circuit_endpoint_type='ipv4',
        pending_operations_timeout='30'    
    )
    # Check status
    if _result_['status'] != IxiaHlt.SUCCESS:
    	ixnHLT_errorHandler('traffic_config', _result_)
    
    #  -- All current config elements
    config_elements = ixiatcl.convert_tcl_list(_result_['traffic_item'])
    
    #  -- Config Element //traffic/trafficItem:<12>/configElement:<1>
    ixnHLT_logger('Configuring options for config elem: //traffic/trafficItem:<12>/configElement:<1>')
    _result_ = ixiahlt.traffic_config(
        mode='modify',
        traffic_generator='ixnetwork_540',
        stream_id=config_elements[0],
        preamble_size_mode='auto',
        preamble_custom_size='8',
        data_pattern='',
        data_pattern_mode='incr_byte',
        enforce_min_gap='0',
        rate_pps='12500',
        frame_rate_distribution_port='split_evenly',
        frame_rate_distribution_stream='split_evenly',
        frame_size='64',
        length_mode='fixed',
        tx_mode='advanced',
        transmit_mode='continuous',
        pkts_per_burst='1',
        tx_delay='0',
        tx_delay_unit='bytes',
        number_of_packets_per_stream='1',
        loop_count='1',
        min_gap_bytes='12'    
    )
    # Check status
    if _result_['status'] != IxiaHlt.SUCCESS:
    	ixnHLT_errorHandler('traffic_config', _result_)
    
    #  -- Endpoint set EndpointSet-1
    ixnHLT_logger('Configuring traffic for config elem: //traffic/trafficItem:<12>/configElement:<1>')
    ixnHLT_logger('Configuring traffic for endpoint set: EndpointSet-1')
    #  -- Stack //traffic/trafficItem:<12>/configElement:<1>/stack:"ethernet-1"
    _result_ = ixiahlt.traffic_config(
        mode='modify_or_insert',
        traffic_generator='ixnetwork_540',
        stream_id=config_elements[0],
        stack_index='1',
        l2_encap='ethernet_ii',
        mac_dst_mode='fixed',
        mac_dst_tracking='0',
        mac_dst='00:00:00:00:00:00',
        mac_src_mode='fixed',
        mac_src_tracking='0',
        mac_src='00:00:00:00:00:00',
        ethernet_value_mode='fixed',
        ethernet_value='ffff',
        ethernet_value_tracking='0'    
    )
    # Check status
    if _result_['status'] != IxiaHlt.SUCCESS:
    	ixnHLT_errorHandler('traffic_config', _result_)
    
    #  -- Stack //traffic/trafficItem:<12>/configElement:<1>/stack:"vlan-2"
    _result_ = ixiahlt.traffic_config(
        mode='modify_or_insert',
        traffic_generator='ixnetwork_540',
        stream_id=config_elements[0],
        stack_index='2',
        vlan='enable',
        vlan_user_priority_mode='fixed',
        vlan_user_priority='0',
        vlan_user_priority_tracking='0',
        vlan_cfi_mode='fixed',
        vlan_cfi='0',
        vlan_cfi_tracking='0',
        vlan_id_mode='fixed',
        vlan_id='0',
        vlan_id_tracking='0'    
    )
    # Check status
    if _result_['status'] != IxiaHlt.SUCCESS:
    	ixnHLT_errorHandler('traffic_config', _result_)
    
    #  -- Stack //traffic/trafficItem:<12>/configElement:<1>/stack:"ipv4-3"
    _result_ = ixiahlt.traffic_config(
        mode='modify_or_insert',
        traffic_generator='ixnetwork_540',
        stream_id=config_elements[0],
        stack_index='3',
        l3_protocol='ipv4',
        qos_type_ixn='tos',
        ip_precedence_mode='fixed',
        ip_precedence='0',
        ip_precedence_tracking='0',
        ip_delay_mode='fixed',
        ip_delay='0',
        ip_delay_tracking='0',
        ip_throughput_mode='fixed',
        ip_throughput='0',
        ip_throughput_tracking='0',
        ip_reliability_mode='fixed',
        ip_reliability='0',
        ip_reliability_tracking='0',
        ip_cost_mode='fixed',
        ip_cost='0',
        ip_cost_tracking='0',
        ip_cu_mode='fixed',
        ip_cu='0',
        ip_cu_tracking='0',
        ip_id_mode='fixed',
        ip_id='0',
        ip_id_tracking='0',
        ip_reserved_mode='fixed',
        ip_reserved='0',
        ip_reserved_tracking='0',
        ip_fragment_mode='fixed',
        ip_fragment='1',
        ip_fragment_tracking='0',
        ip_fragment_last_mode='fixed',
        ip_fragment_last='1',
        ip_fragment_last_tracking='0',
        ip_fragment_offset_mode='fixed',
        ip_fragment_offset='0',
        ip_fragment_offset_tracking='0',
        ip_ttl_mode='fixed',
        ip_ttl='64',
        ip_ttl_tracking='0',
        track_by='none',
        egress_tracking='none'    
    )
    # Check status
    if _result_['status'] != IxiaHlt.SUCCESS:
    	ixnHLT_errorHandler('traffic_config', _result_)
    
    #  -- Post Options
    ixnHLT_logger('Configuring post options for config elem: //traffic/trafficItem:<12>/configElement:<1>')
    _result_ = ixiahlt.traffic_config(
        mode='modify',
        traffic_generator='ixnetwork_540',
        stream_id=config_elements[0],
        transmit_distribution='none'    
    )
    # Check status
    if _result_['status'] != IxiaHlt.SUCCESS:
    	ixnHLT_errorHandler('traffic_config', _result_)
    
    #  -- Traffic item//traffic/trafficItem:<13>
    ixnHLT_logger('Configuring traffic for traffic item: //traffic/trafficItem:<13>')
    
    ti_srcs, ti_dsts = {}, {}
    ti_mcast_rcvr_handle, ti_mcast_rcvr_port_index, ti_mcast_rcvr_host_index, ti_mcast_rcvr_mcast_index = {}, {}, {}, {}
    
    ti_srcs['EndpointSet-1'] = '::ixNet::OBJ-/vport:1/interface:2'
    ti_dsts['EndpointSet-1'] = '::ixNet::OBJ-/vport:4/interface:7'
    
    _result_ = ixiahlt.traffic_config(
        mode='create',
        traffic_generator='ixnetwork_540',
        endpointset_count=1,
        emulation_src_handle=[[ti_srcs['EndpointSet-1']]],
        emulation_dst_handle=[[ti_dsts['EndpointSet-1']]],
        emulation_multicast_dst_handle=[[]],
        emulation_multicast_dst_handle_type=[[]],
        global_dest_mac_retry_count='1',
        global_dest_mac_retry_delay='5',
        enable_data_integrity='1',
        global_enable_dest_mac_retry='1',
        global_enable_min_frame_size='0',
        global_enable_staggered_transmit='0',
        global_enable_stream_ordering='0',
        global_stream_control='continuous',
        global_stream_control_iterations='1',
        global_large_error_threshhold='2',
        global_enable_mac_change_on_fly='0',
        global_max_traffic_generation_queries='500',
        global_mpls_label_learning_timeout='30',
        global_refresh_learned_info_before_apply='0',
        global_use_tx_rx_sync='1',
        global_wait_time='1',
        global_display_mpls_current_label_value='0',
        global_detect_misdirected_packets='0',
        global_frame_ordering='none',
        frame_sequencing='disable',
        frame_sequencing_mode='rx_threshold',
        src_dest_mesh='one_to_one',
        route_mesh='one_to_one',
        bidirectional='1',
        allow_self_destined='0',
        use_cp_rate='1',
        use_cp_size='1',
        enable_dynamic_mpls_labels='0',
        hosts_per_net='1',
        name='TI12-HLTAPI_TRAFFICITEM_540',
        source_filter='all',
        destination_filter='all',
        tag_filter=[[]],
        merge_destinations='0',
        circuit_endpoint_type='ipv4',
        pending_operations_timeout='30'    
    )
    # Check status
    if _result_['status'] != IxiaHlt.SUCCESS:
    	ixnHLT_errorHandler('traffic_config', _result_)
    
    #  -- All current config elements
    config_elements = ixiatcl.convert_tcl_list(_result_['traffic_item'])
    
    #  -- Config Element //traffic/trafficItem:<13>/configElement:<1>
    ixnHLT_logger('Configuring options for config elem: //traffic/trafficItem:<13>/configElement:<1>')
    _result_ = ixiahlt.traffic_config(
        mode='modify',
        traffic_generator='ixnetwork_540',
        stream_id=config_elements[0],
        preamble_size_mode='auto',
        preamble_custom_size='8',
        data_pattern='',
        data_pattern_mode='incr_byte',
        enforce_min_gap='0',
        rate_pps='12500',
        frame_rate_distribution_port='split_evenly',
        frame_rate_distribution_stream='split_evenly',
        frame_size='64',
        length_mode='fixed',
        tx_mode='advanced',
        transmit_mode='continuous',
        pkts_per_burst='1',
        tx_delay='0',
        tx_delay_unit='bytes',
        number_of_packets_per_stream='1',
        loop_count='1',
        min_gap_bytes='12'    
    )
    # Check status
    if _result_['status'] != IxiaHlt.SUCCESS:
    	ixnHLT_errorHandler('traffic_config', _result_)
    
    #  -- Endpoint set EndpointSet-1
    ixnHLT_logger('Configuring traffic for config elem: //traffic/trafficItem:<13>/configElement:<1>')
    ixnHLT_logger('Configuring traffic for endpoint set: EndpointSet-1')
    #  -- Stack //traffic/trafficItem:<13>/configElement:<1>/stack:"ethernet-1"
    _result_ = ixiahlt.traffic_config(
        mode='modify_or_insert',
        traffic_generator='ixnetwork_540',
        stream_id=config_elements[0],
        stack_index='1',
        l2_encap='ethernet_ii',
        mac_dst_mode='fixed',
        mac_dst_tracking='0',
        mac_dst='00:00:00:00:00:00',
        mac_src_mode='fixed',
        mac_src_tracking='0',
        mac_src='00:00:00:00:00:00',
        ethernet_value_mode='fixed',
        ethernet_value='ffff',
        ethernet_value_tracking='0'    
    )
    # Check status
    if _result_['status'] != IxiaHlt.SUCCESS:
    	ixnHLT_errorHandler('traffic_config', _result_)
    
    #  -- Stack //traffic/trafficItem:<13>/configElement:<1>/stack:"vlan-2"
    _result_ = ixiahlt.traffic_config(
        mode='modify_or_insert',
        traffic_generator='ixnetwork_540',
        stream_id=config_elements[0],
        stack_index='2',
        vlan='enable',
        vlan_user_priority_mode='fixed',
        vlan_user_priority='0',
        vlan_user_priority_tracking='0',
        vlan_cfi_mode='fixed',
        vlan_cfi='0',
        vlan_cfi_tracking='0',
        vlan_id_mode='fixed',
        vlan_id='0',
        vlan_id_tracking='0'    
    )
    # Check status
    if _result_['status'] != IxiaHlt.SUCCESS:
    	ixnHLT_errorHandler('traffic_config', _result_)
    
    #  -- Stack //traffic/trafficItem:<13>/configElement:<1>/stack:"ipv4-3"
    _result_ = ixiahlt.traffic_config(
        mode='modify_or_insert',
        traffic_generator='ixnetwork_540',
        stream_id=config_elements[0],
        stack_index='3',
        l3_protocol='ipv4',
        qos_type_ixn='tos',
        ip_precedence_mode='fixed',
        ip_precedence='0',
        ip_precedence_tracking='0',
        ip_delay_mode='fixed',
        ip_delay='0',
        ip_delay_tracking='0',
        ip_throughput_mode='fixed',
        ip_throughput='0',
        ip_throughput_tracking='0',
        ip_reliability_mode='fixed',
        ip_reliability='0',
        ip_reliability_tracking='0',
        ip_cost_mode='fixed',
        ip_cost='0',
        ip_cost_tracking='0',
        ip_cu_mode='fixed',
        ip_cu='0',
        ip_cu_tracking='0',
        ip_id_mode='fixed',
        ip_id='0',
        ip_id_tracking='0',
        ip_reserved_mode='fixed',
        ip_reserved='0',
        ip_reserved_tracking='0',
        ip_fragment_mode='fixed',
        ip_fragment='1',
        ip_fragment_tracking='0',
        ip_fragment_last_mode='fixed',
        ip_fragment_last='1',
        ip_fragment_last_tracking='0',
        ip_fragment_offset_mode='fixed',
        ip_fragment_offset='0',
        ip_fragment_offset_tracking='0',
        ip_ttl_mode='fixed',
        ip_ttl='64',
        ip_ttl_tracking='0',
        track_by='none',
        egress_tracking='none'    
    )
    # Check status
    if _result_['status'] != IxiaHlt.SUCCESS:
    	ixnHLT_errorHandler('traffic_config', _result_)
    
    #  -- Post Options
    ixnHLT_logger('Configuring post options for config elem: //traffic/trafficItem:<13>/configElement:<1>')
    _result_ = ixiahlt.traffic_config(
        mode='modify',
        traffic_generator='ixnetwork_540',
        stream_id=config_elements[0],
        transmit_distribution='none'    
    )
    # Check status
    if _result_['status'] != IxiaHlt.SUCCESS:
    	ixnHLT_errorHandler('traffic_config', _result_)
    
    #  -- Traffic item//traffic/trafficItem:<14>
    ixnHLT_logger('Configuring traffic for traffic item: //traffic/trafficItem:<14>')
    
    ti_srcs, ti_dsts = {}, {}
    ti_mcast_rcvr_handle, ti_mcast_rcvr_port_index, ti_mcast_rcvr_host_index, ti_mcast_rcvr_mcast_index = {}, {}, {}, {}
    
    ti_srcs['EndpointSet-1'] = '::ixNet::OBJ-/vport:1/interface:2'
    ti_dsts['EndpointSet-1'] = '::ixNet::OBJ-/vport:4/interface:8'
    
    _result_ = ixiahlt.traffic_config(
        mode='create',
        traffic_generator='ixnetwork_540',
        endpointset_count=1,
        emulation_src_handle=[[ti_srcs['EndpointSet-1']]],
        emulation_dst_handle=[[ti_dsts['EndpointSet-1']]],
        emulation_multicast_dst_handle=[[]],
        emulation_multicast_dst_handle_type=[[]],
        global_dest_mac_retry_count='1',
        global_dest_mac_retry_delay='5',
        enable_data_integrity='1',
        global_enable_dest_mac_retry='1',
        global_enable_min_frame_size='0',
        global_enable_staggered_transmit='0',
        global_enable_stream_ordering='0',
        global_stream_control='continuous',
        global_stream_control_iterations='1',
        global_large_error_threshhold='2',
        global_enable_mac_change_on_fly='0',
        global_max_traffic_generation_queries='500',
        global_mpls_label_learning_timeout='30',
        global_refresh_learned_info_before_apply='0',
        global_use_tx_rx_sync='1',
        global_wait_time='1',
        global_display_mpls_current_label_value='0',
        global_detect_misdirected_packets='0',
        global_frame_ordering='none',
        frame_sequencing='disable',
        frame_sequencing_mode='rx_threshold',
        src_dest_mesh='one_to_one',
        route_mesh='one_to_one',
        bidirectional='1',
        allow_self_destined='0',
        use_cp_rate='1',
        use_cp_size='1',
        enable_dynamic_mpls_labels='0',
        hosts_per_net='1',
        name='TI13-HLTAPI_TRAFFICITEM_540',
        source_filter='all',
        destination_filter='all',
        tag_filter=[[]],
        merge_destinations='0',
        circuit_endpoint_type='ipv4',
        pending_operations_timeout='30'    
    )
    # Check status
    if _result_['status'] != IxiaHlt.SUCCESS:
    	ixnHLT_errorHandler('traffic_config', _result_)
    
    #  -- All current config elements
    config_elements = ixiatcl.convert_tcl_list(_result_['traffic_item'])
    
    #  -- Config Element //traffic/trafficItem:<14>/configElement:<1>
    ixnHLT_logger('Configuring options for config elem: //traffic/trafficItem:<14>/configElement:<1>')
    _result_ = ixiahlt.traffic_config(
        mode='modify',
        traffic_generator='ixnetwork_540',
        stream_id=config_elements[0],
        preamble_size_mode='auto',
        preamble_custom_size='8',
        data_pattern='',
        data_pattern_mode='incr_byte',
        enforce_min_gap='0',
        rate_pps='12500',
        frame_rate_distribution_port='split_evenly',
        frame_rate_distribution_stream='split_evenly',
        frame_size='64',
        length_mode='fixed',
        tx_mode='advanced',
        transmit_mode='continuous',
        pkts_per_burst='1',
        tx_delay='0',
        tx_delay_unit='bytes',
        number_of_packets_per_stream='1',
        loop_count='1',
        min_gap_bytes='12'    
    )
    # Check status
    if _result_['status'] != IxiaHlt.SUCCESS:
    	ixnHLT_errorHandler('traffic_config', _result_)
    
    #  -- Endpoint set EndpointSet-1
    ixnHLT_logger('Configuring traffic for config elem: //traffic/trafficItem:<14>/configElement:<1>')
    ixnHLT_logger('Configuring traffic for endpoint set: EndpointSet-1')
    #  -- Stack //traffic/trafficItem:<14>/configElement:<1>/stack:"ethernet-1"
    _result_ = ixiahlt.traffic_config(
        mode='modify_or_insert',
        traffic_generator='ixnetwork_540',
        stream_id=config_elements[0],
        stack_index='1',
        l2_encap='ethernet_ii',
        mac_dst_mode='fixed',
        mac_dst_tracking='0',
        mac_dst='00:00:00:00:00:00',
        mac_src_mode='fixed',
        mac_src_tracking='0',
        mac_src='00:00:00:00:00:00',
        ethernet_value_mode='fixed',
        ethernet_value='ffff',
        ethernet_value_tracking='0'    
    )
    # Check status
    if _result_['status'] != IxiaHlt.SUCCESS:
    	ixnHLT_errorHandler('traffic_config', _result_)
    
    #  -- Stack //traffic/trafficItem:<14>/configElement:<1>/stack:"vlan-2"
    _result_ = ixiahlt.traffic_config(
        mode='modify_or_insert',
        traffic_generator='ixnetwork_540',
        stream_id=config_elements[0],
        stack_index='2',
        vlan='enable',
        vlan_user_priority_mode='fixed',
        vlan_user_priority='0',
        vlan_user_priority_tracking='0',
        vlan_cfi_mode='fixed',
        vlan_cfi='0',
        vlan_cfi_tracking='0',
        vlan_id_mode='fixed',
        vlan_id='0',
        vlan_id_tracking='0'    
    )
    # Check status
    if _result_['status'] != IxiaHlt.SUCCESS:
    	ixnHLT_errorHandler('traffic_config', _result_)
    
    #  -- Stack //traffic/trafficItem:<14>/configElement:<1>/stack:"ipv4-3"
    _result_ = ixiahlt.traffic_config(
        mode='modify_or_insert',
        traffic_generator='ixnetwork_540',
        stream_id=config_elements[0],
        stack_index='3',
        l3_protocol='ipv4',
        qos_type_ixn='tos',
        ip_precedence_mode='fixed',
        ip_precedence='0',
        ip_precedence_tracking='0',
        ip_delay_mode='fixed',
        ip_delay='0',
        ip_delay_tracking='0',
        ip_throughput_mode='fixed',
        ip_throughput='0',
        ip_throughput_tracking='0',
        ip_reliability_mode='fixed',
        ip_reliability='0',
        ip_reliability_tracking='0',
        ip_cost_mode='fixed',
        ip_cost='0',
        ip_cost_tracking='0',
        ip_cu_mode='fixed',
        ip_cu='0',
        ip_cu_tracking='0',
        ip_id_mode='fixed',
        ip_id='0',
        ip_id_tracking='0',
        ip_reserved_mode='fixed',
        ip_reserved='0',
        ip_reserved_tracking='0',
        ip_fragment_mode='fixed',
        ip_fragment='1',
        ip_fragment_tracking='0',
        ip_fragment_last_mode='fixed',
        ip_fragment_last='1',
        ip_fragment_last_tracking='0',
        ip_fragment_offset_mode='fixed',
        ip_fragment_offset='0',
        ip_fragment_offset_tracking='0',
        ip_ttl_mode='fixed',
        ip_ttl='64',
        ip_ttl_tracking='0',
        track_by='none',
        egress_tracking='none'    
    )
    # Check status
    if _result_['status'] != IxiaHlt.SUCCESS:
    	ixnHLT_errorHandler('traffic_config', _result_)
    
    #  -- Post Options
    ixnHLT_logger('Configuring post options for config elem: //traffic/trafficItem:<14>/configElement:<1>')
    _result_ = ixiahlt.traffic_config(
        mode='modify',
        traffic_generator='ixnetwork_540',
        stream_id=config_elements[0],
        transmit_distribution='none'    
    )
    # Check status
    if _result_['status'] != IxiaHlt.SUCCESS:
    	ixnHLT_errorHandler('traffic_config', _result_)
    
    #  -- Traffic item//traffic/trafficItem:<15>
    ixnHLT_logger('Configuring traffic for traffic item: //traffic/trafficItem:<15>')
    
    ti_srcs, ti_dsts = {}, {}
    ti_mcast_rcvr_handle, ti_mcast_rcvr_port_index, ti_mcast_rcvr_host_index, ti_mcast_rcvr_mcast_index = {}, {}, {}, {}
    
    ti_srcs['EndpointSet-1'] = '::ixNet::OBJ-/vport:1/interface:3'
    ti_dsts['EndpointSet-1'] = '::ixNet::OBJ-/vport:4/interface:9'
    
    _result_ = ixiahlt.traffic_config(
        mode='create',
        traffic_generator='ixnetwork_540',
        endpointset_count=1,
        emulation_src_handle=[[ti_srcs['EndpointSet-1']]],
        emulation_dst_handle=[[ti_dsts['EndpointSet-1']]],
        emulation_multicast_dst_handle=[[]],
        emulation_multicast_dst_handle_type=[[]],
        global_dest_mac_retry_count='1',
        global_dest_mac_retry_delay='5',
        enable_data_integrity='1',
        global_enable_dest_mac_retry='1',
        global_enable_min_frame_size='0',
        global_enable_staggered_transmit='0',
        global_enable_stream_ordering='0',
        global_stream_control='continuous',
        global_stream_control_iterations='1',
        global_large_error_threshhold='2',
        global_enable_mac_change_on_fly='0',
        global_max_traffic_generation_queries='500',
        global_mpls_label_learning_timeout='30',
        global_refresh_learned_info_before_apply='0',
        global_use_tx_rx_sync='1',
        global_wait_time='1',
        global_display_mpls_current_label_value='0',
        global_detect_misdirected_packets='0',
        global_frame_ordering='none',
        frame_sequencing='disable',
        frame_sequencing_mode='rx_threshold',
        src_dest_mesh='one_to_one',
        route_mesh='one_to_one',
        bidirectional='1',
        allow_self_destined='0',
        use_cp_rate='1',
        use_cp_size='1',
        enable_dynamic_mpls_labels='0',
        hosts_per_net='1',
        name='TI14-HLTAPI_TRAFFICITEM_540',
        source_filter='all',
        destination_filter='all',
        tag_filter=[[]],
        merge_destinations='0',
        circuit_endpoint_type='ipv4',
        pending_operations_timeout='30'    
    )
    # Check status
    if _result_['status'] != IxiaHlt.SUCCESS:
    	ixnHLT_errorHandler('traffic_config', _result_)
    
    #  -- All current config elements
    config_elements = ixiatcl.convert_tcl_list(_result_['traffic_item'])
    
    #  -- Config Element //traffic/trafficItem:<15>/configElement:<1>
    ixnHLT_logger('Configuring options for config elem: //traffic/trafficItem:<15>/configElement:<1>')
    _result_ = ixiahlt.traffic_config(
        mode='modify',
        traffic_generator='ixnetwork_540',
        stream_id=config_elements[0],
        preamble_size_mode='auto',
        preamble_custom_size='8',
        data_pattern='',
        data_pattern_mode='incr_byte',
        enforce_min_gap='0',
        rate_pps='12500',
        frame_rate_distribution_port='split_evenly',
        frame_rate_distribution_stream='split_evenly',
        frame_size='64',
        length_mode='fixed',
        tx_mode='advanced',
        transmit_mode='continuous',
        pkts_per_burst='1',
        tx_delay='0',
        tx_delay_unit='bytes',
        number_of_packets_per_stream='1',
        loop_count='1',
        min_gap_bytes='12'    
    )
    # Check status
    if _result_['status'] != IxiaHlt.SUCCESS:
    	ixnHLT_errorHandler('traffic_config', _result_)
    
    #  -- Endpoint set EndpointSet-1
    ixnHLT_logger('Configuring traffic for config elem: //traffic/trafficItem:<15>/configElement:<1>')
    ixnHLT_logger('Configuring traffic for endpoint set: EndpointSet-1')
    #  -- Stack //traffic/trafficItem:<15>/configElement:<1>/stack:"ethernet-1"
    _result_ = ixiahlt.traffic_config(
        mode='modify_or_insert',
        traffic_generator='ixnetwork_540',
        stream_id=config_elements[0],
        stack_index='1',
        l2_encap='ethernet_ii',
        mac_dst_mode='fixed',
        mac_dst_tracking='0',
        mac_dst='00:00:00:00:00:00',
        mac_src_mode='fixed',
        mac_src_tracking='0',
        mac_src='00:00:00:00:00:00',
        ethernet_value_mode='fixed',
        ethernet_value='ffff',
        ethernet_value_tracking='0'    
    )
    # Check status
    if _result_['status'] != IxiaHlt.SUCCESS:
    	ixnHLT_errorHandler('traffic_config', _result_)
    
    #  -- Stack //traffic/trafficItem:<15>/configElement:<1>/stack:"vlan-2"
    _result_ = ixiahlt.traffic_config(
        mode='modify_or_insert',
        traffic_generator='ixnetwork_540',
        stream_id=config_elements[0],
        stack_index='2',
        vlan='enable',
        vlan_user_priority_mode='fixed',
        vlan_user_priority='0',
        vlan_user_priority_tracking='0',
        vlan_cfi_mode='fixed',
        vlan_cfi='0',
        vlan_cfi_tracking='0',
        vlan_id_mode='fixed',
        vlan_id='0',
        vlan_id_tracking='0'    
    )
    # Check status
    if _result_['status'] != IxiaHlt.SUCCESS:
    	ixnHLT_errorHandler('traffic_config', _result_)
    
    #  -- Stack //traffic/trafficItem:<15>/configElement:<1>/stack:"ipv4-3"
    _result_ = ixiahlt.traffic_config(
        mode='modify_or_insert',
        traffic_generator='ixnetwork_540',
        stream_id=config_elements[0],
        stack_index='3',
        l3_protocol='ipv4',
        qos_type_ixn='tos',
        ip_precedence_mode='fixed',
        ip_precedence='0',
        ip_precedence_tracking='0',
        ip_delay_mode='fixed',
        ip_delay='0',
        ip_delay_tracking='0',
        ip_throughput_mode='fixed',
        ip_throughput='0',
        ip_throughput_tracking='0',
        ip_reliability_mode='fixed',
        ip_reliability='0',
        ip_reliability_tracking='0',
        ip_cost_mode='fixed',
        ip_cost='0',
        ip_cost_tracking='0',
        ip_cu_mode='fixed',
        ip_cu='0',
        ip_cu_tracking='0',
        ip_id_mode='fixed',
        ip_id='0',
        ip_id_tracking='0',
        ip_reserved_mode='fixed',
        ip_reserved='0',
        ip_reserved_tracking='0',
        ip_fragment_mode='fixed',
        ip_fragment='1',
        ip_fragment_tracking='0',
        ip_fragment_last_mode='fixed',
        ip_fragment_last='1',
        ip_fragment_last_tracking='0',
        ip_fragment_offset_mode='fixed',
        ip_fragment_offset='0',
        ip_fragment_offset_tracking='0',
        ip_ttl_mode='fixed',
        ip_ttl='64',
        ip_ttl_tracking='0',
        track_by='none',
        egress_tracking='none'    
    )
    # Check status
    if _result_['status'] != IxiaHlt.SUCCESS:
    	ixnHLT_errorHandler('traffic_config', _result_)
    
    #  -- Post Options
    ixnHLT_logger('Configuring post options for config elem: //traffic/trafficItem:<15>/configElement:<1>')
    _result_ = ixiahlt.traffic_config(
        mode='modify',
        traffic_generator='ixnetwork_540',
        stream_id=config_elements[0],
        transmit_distribution='none'    
    )
    # Check status
    if _result_['status'] != IxiaHlt.SUCCESS:
    	ixnHLT_errorHandler('traffic_config', _result_)
    
    #  -- Traffic item//traffic/trafficItem:<16>
    ixnHLT_logger('Configuring traffic for traffic item: //traffic/trafficItem:<16>')
    
    ti_srcs, ti_dsts = {}, {}
    ti_mcast_rcvr_handle, ti_mcast_rcvr_port_index, ti_mcast_rcvr_host_index, ti_mcast_rcvr_mcast_index = {}, {}, {}, {}
    
    ti_srcs['EndpointSet-1'] = '::ixNet::OBJ-/vport:1/interface:3'
    ti_dsts['EndpointSet-1'] = '::ixNet::OBJ-/vport:4/interface:10'
    
    _result_ = ixiahlt.traffic_config(
        mode='create',
        traffic_generator='ixnetwork_540',
        endpointset_count=1,
        emulation_src_handle=[[ti_srcs['EndpointSet-1']]],
        emulation_dst_handle=[[ti_dsts['EndpointSet-1']]],
        emulation_multicast_dst_handle=[[]],
        emulation_multicast_dst_handle_type=[[]],
        global_dest_mac_retry_count='1',
        global_dest_mac_retry_delay='5',
        enable_data_integrity='1',
        global_enable_dest_mac_retry='1',
        global_enable_min_frame_size='0',
        global_enable_staggered_transmit='0',
        global_enable_stream_ordering='0',
        global_stream_control='continuous',
        global_stream_control_iterations='1',
        global_large_error_threshhold='2',
        global_enable_mac_change_on_fly='0',
        global_max_traffic_generation_queries='500',
        global_mpls_label_learning_timeout='30',
        global_refresh_learned_info_before_apply='0',
        global_use_tx_rx_sync='1',
        global_wait_time='1',
        global_display_mpls_current_label_value='0',
        global_detect_misdirected_packets='0',
        global_frame_ordering='none',
        frame_sequencing='disable',
        frame_sequencing_mode='rx_threshold',
        src_dest_mesh='one_to_one',
        route_mesh='one_to_one',
        bidirectional='1',
        allow_self_destined='0',
        use_cp_rate='1',
        use_cp_size='1',
        enable_dynamic_mpls_labels='0',
        hosts_per_net='1',
        name='TI15-HLTAPI_TRAFFICITEM_540',
        source_filter='all',
        destination_filter='all',
        tag_filter=[[]],
        merge_destinations='0',
        circuit_endpoint_type='ipv4',
        pending_operations_timeout='30'    
    )
    # Check status
    if _result_['status'] != IxiaHlt.SUCCESS:
    	ixnHLT_errorHandler('traffic_config', _result_)
    
    #  -- All current config elements
    config_elements = ixiatcl.convert_tcl_list(_result_['traffic_item'])
    
    #  -- Config Element //traffic/trafficItem:<16>/configElement:<1>
    ixnHLT_logger('Configuring options for config elem: //traffic/trafficItem:<16>/configElement:<1>')
    _result_ = ixiahlt.traffic_config(
        mode='modify',
        traffic_generator='ixnetwork_540',
        stream_id=config_elements[0],
        preamble_size_mode='auto',
        preamble_custom_size='8',
        data_pattern='',
        data_pattern_mode='incr_byte',
        enforce_min_gap='0',
        rate_pps='12500',
        frame_rate_distribution_port='split_evenly',
        frame_rate_distribution_stream='split_evenly',
        frame_size='64',
        length_mode='fixed',
        tx_mode='advanced',
        transmit_mode='continuous',
        pkts_per_burst='1',
        tx_delay='0',
        tx_delay_unit='bytes',
        number_of_packets_per_stream='1',
        loop_count='1',
        min_gap_bytes='12'    
    )
    # Check status
    if _result_['status'] != IxiaHlt.SUCCESS:
    	ixnHLT_errorHandler('traffic_config', _result_)
    
    #  -- Endpoint set EndpointSet-1
    ixnHLT_logger('Configuring traffic for config elem: //traffic/trafficItem:<16>/configElement:<1>')
    ixnHLT_logger('Configuring traffic for endpoint set: EndpointSet-1')
    #  -- Stack //traffic/trafficItem:<16>/configElement:<1>/stack:"ethernet-1"
    _result_ = ixiahlt.traffic_config(
        mode='modify_or_insert',
        traffic_generator='ixnetwork_540',
        stream_id=config_elements[0],
        stack_index='1',
        l2_encap='ethernet_ii',
        mac_dst_mode='fixed',
        mac_dst_tracking='0',
        mac_dst='00:00:00:00:00:00',
        mac_src_mode='fixed',
        mac_src_tracking='0',
        mac_src='00:00:00:00:00:00',
        ethernet_value_mode='fixed',
        ethernet_value='ffff',
        ethernet_value_tracking='0'    
    )
    # Check status
    if _result_['status'] != IxiaHlt.SUCCESS:
    	ixnHLT_errorHandler('traffic_config', _result_)
    
    #  -- Stack //traffic/trafficItem:<16>/configElement:<1>/stack:"vlan-2"
    _result_ = ixiahlt.traffic_config(
        mode='modify_or_insert',
        traffic_generator='ixnetwork_540',
        stream_id=config_elements[0],
        stack_index='2',
        vlan='enable',
        vlan_user_priority_mode='fixed',
        vlan_user_priority='0',
        vlan_user_priority_tracking='0',
        vlan_cfi_mode='fixed',
        vlan_cfi='0',
        vlan_cfi_tracking='0',
        vlan_id_mode='fixed',
        vlan_id='0',
        vlan_id_tracking='0'    
    )
    # Check status
    if _result_['status'] != IxiaHlt.SUCCESS:
    	ixnHLT_errorHandler('traffic_config', _result_)
    
    #  -- Stack //traffic/trafficItem:<16>/configElement:<1>/stack:"ipv4-3"
    _result_ = ixiahlt.traffic_config(
        mode='modify_or_insert',
        traffic_generator='ixnetwork_540',
        stream_id=config_elements[0],
        stack_index='3',
        l3_protocol='ipv4',
        qos_type_ixn='tos',
        ip_precedence_mode='fixed',
        ip_precedence='0',
        ip_precedence_tracking='0',
        ip_delay_mode='fixed',
        ip_delay='0',
        ip_delay_tracking='0',
        ip_throughput_mode='fixed',
        ip_throughput='0',
        ip_throughput_tracking='0',
        ip_reliability_mode='fixed',
        ip_reliability='0',
        ip_reliability_tracking='0',
        ip_cost_mode='fixed',
        ip_cost='0',
        ip_cost_tracking='0',
        ip_cu_mode='fixed',
        ip_cu='0',
        ip_cu_tracking='0',
        ip_id_mode='fixed',
        ip_id='0',
        ip_id_tracking='0',
        ip_reserved_mode='fixed',
        ip_reserved='0',
        ip_reserved_tracking='0',
        ip_fragment_mode='fixed',
        ip_fragment='1',
        ip_fragment_tracking='0',
        ip_fragment_last_mode='fixed',
        ip_fragment_last='1',
        ip_fragment_last_tracking='0',
        ip_fragment_offset_mode='fixed',
        ip_fragment_offset='0',
        ip_fragment_offset_tracking='0',
        ip_ttl_mode='fixed',
        ip_ttl='64',
        ip_ttl_tracking='0',
        track_by='none',
        egress_tracking='none'    
    )
    # Check status
    if _result_['status'] != IxiaHlt.SUCCESS:
    	ixnHLT_errorHandler('traffic_config', _result_)
    
    #  -- Post Options
    ixnHLT_logger('Configuring post options for config elem: //traffic/trafficItem:<16>/configElement:<1>')
    _result_ = ixiahlt.traffic_config(
        mode='modify',
        traffic_generator='ixnetwork_540',
        stream_id=config_elements[0],
        transmit_distribution='none'    
    )
    # Check status
    if _result_['status'] != IxiaHlt.SUCCESS:
    	ixnHLT_errorHandler('traffic_config', _result_)
    
    #  -- Traffic item//traffic/trafficItem:<17>
    ixnHLT_logger('Configuring traffic for traffic item: //traffic/trafficItem:<17>')
    
    ti_srcs, ti_dsts = {}, {}
    ti_mcast_rcvr_handle, ti_mcast_rcvr_port_index, ti_mcast_rcvr_host_index, ti_mcast_rcvr_mcast_index = {}, {}, {}, {}
    
    ti_srcs['EndpointSet-1'] = '::ixNet::OBJ-/vport:1/interface:3'
    ti_dsts['EndpointSet-1'] = '::ixNet::OBJ-/vport:4/interface:11'
    
    _result_ = ixiahlt.traffic_config(
        mode='create',
        traffic_generator='ixnetwork_540',
        endpointset_count=1,
        emulation_src_handle=[[ti_srcs['EndpointSet-1']]],
        emulation_dst_handle=[[ti_dsts['EndpointSet-1']]],
        emulation_multicast_dst_handle=[[]],
        emulation_multicast_dst_handle_type=[[]],
        global_dest_mac_retry_count='1',
        global_dest_mac_retry_delay='5',
        enable_data_integrity='1',
        global_enable_dest_mac_retry='1',
        global_enable_min_frame_size='0',
        global_enable_staggered_transmit='0',
        global_enable_stream_ordering='0',
        global_stream_control='continuous',
        global_stream_control_iterations='1',
        global_large_error_threshhold='2',
        global_enable_mac_change_on_fly='0',
        global_max_traffic_generation_queries='500',
        global_mpls_label_learning_timeout='30',
        global_refresh_learned_info_before_apply='0',
        global_use_tx_rx_sync='1',
        global_wait_time='1',
        global_display_mpls_current_label_value='0',
        global_detect_misdirected_packets='0',
        global_frame_ordering='none',
        frame_sequencing='disable',
        frame_sequencing_mode='rx_threshold',
        src_dest_mesh='one_to_one',
        route_mesh='one_to_one',
        bidirectional='1',
        allow_self_destined='0',
        use_cp_rate='1',
        use_cp_size='1',
        enable_dynamic_mpls_labels='0',
        hosts_per_net='1',
        name='TI16-HLTAPI_TRAFFICITEM_540',
        source_filter='all',
        destination_filter='all',
        tag_filter=[[]],
        merge_destinations='0',
        circuit_endpoint_type='ipv4',
        pending_operations_timeout='30'    
    )
    # Check status
    if _result_['status'] != IxiaHlt.SUCCESS:
    	ixnHLT_errorHandler('traffic_config', _result_)
    
    #  -- All current config elements
    config_elements = ixiatcl.convert_tcl_list(_result_['traffic_item'])
    
    #  -- Config Element //traffic/trafficItem:<17>/configElement:<1>
    ixnHLT_logger('Configuring options for config elem: //traffic/trafficItem:<17>/configElement:<1>')
    _result_ = ixiahlt.traffic_config(
        mode='modify',
        traffic_generator='ixnetwork_540',
        stream_id=config_elements[0],
        preamble_size_mode='auto',
        preamble_custom_size='8',
        data_pattern='',
        data_pattern_mode='incr_byte',
        enforce_min_gap='0',
        rate_pps='12500',
        frame_rate_distribution_port='split_evenly',
        frame_rate_distribution_stream='split_evenly',
        frame_size='64',
        length_mode='fixed',
        tx_mode='advanced',
        transmit_mode='continuous',
        pkts_per_burst='1',
        tx_delay='0',
        tx_delay_unit='bytes',
        number_of_packets_per_stream='1',
        loop_count='1',
        min_gap_bytes='12'    
    )
    # Check status
    if _result_['status'] != IxiaHlt.SUCCESS:
    	ixnHLT_errorHandler('traffic_config', _result_)
    
    #  -- Endpoint set EndpointSet-1
    ixnHLT_logger('Configuring traffic for config elem: //traffic/trafficItem:<17>/configElement:<1>')
    ixnHLT_logger('Configuring traffic for endpoint set: EndpointSet-1')
    #  -- Stack //traffic/trafficItem:<17>/configElement:<1>/stack:"ethernet-1"
    _result_ = ixiahlt.traffic_config(
        mode='modify_or_insert',
        traffic_generator='ixnetwork_540',
        stream_id=config_elements[0],
        stack_index='1',
        l2_encap='ethernet_ii',
        mac_dst_mode='fixed',
        mac_dst_tracking='0',
        mac_dst='00:00:00:00:00:00',
        mac_src_mode='fixed',
        mac_src_tracking='0',
        mac_src='00:00:00:00:00:00',
        ethernet_value_mode='fixed',
        ethernet_value='ffff',
        ethernet_value_tracking='0'    
    )
    # Check status
    if _result_['status'] != IxiaHlt.SUCCESS:
    	ixnHLT_errorHandler('traffic_config', _result_)
    
    #  -- Stack //traffic/trafficItem:<17>/configElement:<1>/stack:"vlan-2"
    _result_ = ixiahlt.traffic_config(
        mode='modify_or_insert',
        traffic_generator='ixnetwork_540',
        stream_id=config_elements[0],
        stack_index='2',
        vlan='enable',
        vlan_user_priority_mode='fixed',
        vlan_user_priority='0',
        vlan_user_priority_tracking='0',
        vlan_cfi_mode='fixed',
        vlan_cfi='0',
        vlan_cfi_tracking='0',
        vlan_id_mode='fixed',
        vlan_id='0',
        vlan_id_tracking='0'    
    )
    # Check status
    if _result_['status'] != IxiaHlt.SUCCESS:
    	ixnHLT_errorHandler('traffic_config', _result_)
    
    #  -- Stack //traffic/trafficItem:<17>/configElement:<1>/stack:"ipv4-3"
    _result_ = ixiahlt.traffic_config(
        mode='modify_or_insert',
        traffic_generator='ixnetwork_540',
        stream_id=config_elements[0],
        stack_index='3',
        l3_protocol='ipv4',
        qos_type_ixn='tos',
        ip_precedence_mode='fixed',
        ip_precedence='0',
        ip_precedence_tracking='0',
        ip_delay_mode='fixed',
        ip_delay='0',
        ip_delay_tracking='0',
        ip_throughput_mode='fixed',
        ip_throughput='0',
        ip_throughput_tracking='0',
        ip_reliability_mode='fixed',
        ip_reliability='0',
        ip_reliability_tracking='0',
        ip_cost_mode='fixed',
        ip_cost='0',
        ip_cost_tracking='0',
        ip_cu_mode='fixed',
        ip_cu='0',
        ip_cu_tracking='0',
        ip_id_mode='fixed',
        ip_id='0',
        ip_id_tracking='0',
        ip_reserved_mode='fixed',
        ip_reserved='0',
        ip_reserved_tracking='0',
        ip_fragment_mode='fixed',
        ip_fragment='1',
        ip_fragment_tracking='0',
        ip_fragment_last_mode='fixed',
        ip_fragment_last='1',
        ip_fragment_last_tracking='0',
        ip_fragment_offset_mode='fixed',
        ip_fragment_offset='0',
        ip_fragment_offset_tracking='0',
        ip_ttl_mode='fixed',
        ip_ttl='64',
        ip_ttl_tracking='0',
        track_by='none',
        egress_tracking='none'    
    )
    # Check status
    if _result_['status'] != IxiaHlt.SUCCESS:
    	ixnHLT_errorHandler('traffic_config', _result_)
    
    #  -- Post Options
    ixnHLT_logger('Configuring post options for config elem: //traffic/trafficItem:<17>/configElement:<1>')
    _result_ = ixiahlt.traffic_config(
        mode='modify',
        traffic_generator='ixnetwork_540',
        stream_id=config_elements[0],
        transmit_distribution='none'    
    )
    # Check status
    if _result_['status'] != IxiaHlt.SUCCESS:
    	ixnHLT_errorHandler('traffic_config', _result_)
    
    #  -- Traffic item//traffic/trafficItem:<18>
    ixnHLT_logger('Configuring traffic for traffic item: //traffic/trafficItem:<18>')
    
    ti_srcs, ti_dsts = {}, {}
    ti_mcast_rcvr_handle, ti_mcast_rcvr_port_index, ti_mcast_rcvr_host_index, ti_mcast_rcvr_mcast_index = {}, {}, {}, {}
    
    ti_srcs['EndpointSet-1'] = '::ixNet::OBJ-/vport:1/interface:3'
    ti_dsts['EndpointSet-1'] = '::ixNet::OBJ-/vport:4/interface:12'
    
    _result_ = ixiahlt.traffic_config(
        mode='create',
        traffic_generator='ixnetwork_540',
        endpointset_count=1,
        emulation_src_handle=[[ti_srcs['EndpointSet-1']]],
        emulation_dst_handle=[[ti_dsts['EndpointSet-1']]],
        emulation_multicast_dst_handle=[[]],
        emulation_multicast_dst_handle_type=[[]],
        global_dest_mac_retry_count='1',
        global_dest_mac_retry_delay='5',
        enable_data_integrity='1',
        global_enable_dest_mac_retry='1',
        global_enable_min_frame_size='0',
        global_enable_staggered_transmit='0',
        global_enable_stream_ordering='0',
        global_stream_control='continuous',
        global_stream_control_iterations='1',
        global_large_error_threshhold='2',
        global_enable_mac_change_on_fly='0',
        global_max_traffic_generation_queries='500',
        global_mpls_label_learning_timeout='30',
        global_refresh_learned_info_before_apply='0',
        global_use_tx_rx_sync='1',
        global_wait_time='1',
        global_display_mpls_current_label_value='0',
        global_detect_misdirected_packets='0',
        global_frame_ordering='none',
        frame_sequencing='disable',
        frame_sequencing_mode='rx_threshold',
        src_dest_mesh='one_to_one',
        route_mesh='one_to_one',
        bidirectional='1',
        allow_self_destined='0',
        use_cp_rate='1',
        use_cp_size='1',
        enable_dynamic_mpls_labels='0',
        hosts_per_net='1',
        name='TI17-HLTAPI_TRAFFICITEM_540',
        source_filter='all',
        destination_filter='all',
        tag_filter=[[]],
        merge_destinations='0',
        circuit_endpoint_type='ipv4',
        pending_operations_timeout='30'    
    )
    # Check status
    if _result_['status'] != IxiaHlt.SUCCESS:
    	ixnHLT_errorHandler('traffic_config', _result_)
    
    #  -- All current config elements
    config_elements = ixiatcl.convert_tcl_list(_result_['traffic_item'])
    
    #  -- Config Element //traffic/trafficItem:<18>/configElement:<1>
    ixnHLT_logger('Configuring options for config elem: //traffic/trafficItem:<18>/configElement:<1>')
    _result_ = ixiahlt.traffic_config(
        mode='modify',
        traffic_generator='ixnetwork_540',
        stream_id=config_elements[0],
        preamble_size_mode='auto',
        preamble_custom_size='8',
        data_pattern='',
        data_pattern_mode='incr_byte',
        enforce_min_gap='0',
        rate_pps='12500',
        frame_rate_distribution_port='split_evenly',
        frame_rate_distribution_stream='split_evenly',
        frame_size='64',
        length_mode='fixed',
        tx_mode='advanced',
        transmit_mode='continuous',
        pkts_per_burst='1',
        tx_delay='0',
        tx_delay_unit='bytes',
        number_of_packets_per_stream='1',
        loop_count='1',
        min_gap_bytes='12'    
    )
    # Check status
    if _result_['status'] != IxiaHlt.SUCCESS:
    	ixnHLT_errorHandler('traffic_config', _result_)
    
    #  -- Endpoint set EndpointSet-1
    ixnHLT_logger('Configuring traffic for config elem: //traffic/trafficItem:<18>/configElement:<1>')
    ixnHLT_logger('Configuring traffic for endpoint set: EndpointSet-1')
    #  -- Stack //traffic/trafficItem:<18>/configElement:<1>/stack:"ethernet-1"
    _result_ = ixiahlt.traffic_config(
        mode='modify_or_insert',
        traffic_generator='ixnetwork_540',
        stream_id=config_elements[0],
        stack_index='1',
        l2_encap='ethernet_ii',
        mac_dst_mode='fixed',
        mac_dst_tracking='0',
        mac_dst='00:00:00:00:00:00',
        mac_src_mode='fixed',
        mac_src_tracking='0',
        mac_src='00:00:00:00:00:00',
        ethernet_value_mode='fixed',
        ethernet_value='ffff',
        ethernet_value_tracking='0'    
    )
    # Check status
    if _result_['status'] != IxiaHlt.SUCCESS:
    	ixnHLT_errorHandler('traffic_config', _result_)
    
    #  -- Stack //traffic/trafficItem:<18>/configElement:<1>/stack:"vlan-2"
    _result_ = ixiahlt.traffic_config(
        mode='modify_or_insert',
        traffic_generator='ixnetwork_540',
        stream_id=config_elements[0],
        stack_index='2',
        vlan='enable',
        vlan_user_priority_mode='fixed',
        vlan_user_priority='0',
        vlan_user_priority_tracking='0',
        vlan_cfi_mode='fixed',
        vlan_cfi='0',
        vlan_cfi_tracking='0',
        vlan_id_mode='fixed',
        vlan_id='0',
        vlan_id_tracking='0'    
    )
    # Check status
    if _result_['status'] != IxiaHlt.SUCCESS:
    	ixnHLT_errorHandler('traffic_config', _result_)
    
    #  -- Stack //traffic/trafficItem:<18>/configElement:<1>/stack:"ipv4-3"
    _result_ = ixiahlt.traffic_config(
        mode='modify_or_insert',
        traffic_generator='ixnetwork_540',
        stream_id=config_elements[0],
        stack_index='3',
        l3_protocol='ipv4',
        qos_type_ixn='tos',
        ip_precedence_mode='fixed',
        ip_precedence='0',
        ip_precedence_tracking='0',
        ip_delay_mode='fixed',
        ip_delay='0',
        ip_delay_tracking='0',
        ip_throughput_mode='fixed',
        ip_throughput='0',
        ip_throughput_tracking='0',
        ip_reliability_mode='fixed',
        ip_reliability='0',
        ip_reliability_tracking='0',
        ip_cost_mode='fixed',
        ip_cost='0',
        ip_cost_tracking='0',
        ip_cu_mode='fixed',
        ip_cu='0',
        ip_cu_tracking='0',
        ip_id_mode='fixed',
        ip_id='0',
        ip_id_tracking='0',
        ip_reserved_mode='fixed',
        ip_reserved='0',
        ip_reserved_tracking='0',
        ip_fragment_mode='fixed',
        ip_fragment='1',
        ip_fragment_tracking='0',
        ip_fragment_last_mode='fixed',
        ip_fragment_last='1',
        ip_fragment_last_tracking='0',
        ip_fragment_offset_mode='fixed',
        ip_fragment_offset='0',
        ip_fragment_offset_tracking='0',
        ip_ttl_mode='fixed',
        ip_ttl='64',
        ip_ttl_tracking='0',
        track_by='none',
        egress_tracking='none'    
    )
    # Check status
    if _result_['status'] != IxiaHlt.SUCCESS:
    	ixnHLT_errorHandler('traffic_config', _result_)
    
    #  -- Post Options
    ixnHLT_logger('Configuring post options for config elem: //traffic/trafficItem:<18>/configElement:<1>')
    _result_ = ixiahlt.traffic_config(
        mode='modify',
        traffic_generator='ixnetwork_540',
        stream_id=config_elements[0],
        transmit_distribution='none'    
    )
    # Check status
    if _result_['status'] != IxiaHlt.SUCCESS:
    	ixnHLT_errorHandler('traffic_config', _result_)
    
    #  -- Traffic item//traffic/trafficItem:<19>
    ixnHLT_logger('Configuring traffic for traffic item: //traffic/trafficItem:<19>')
    
    ti_srcs, ti_dsts = {}, {}
    ti_mcast_rcvr_handle, ti_mcast_rcvr_port_index, ti_mcast_rcvr_host_index, ti_mcast_rcvr_mcast_index = {}, {}, {}, {}
    
    ti_srcs['EndpointSet-1'] = '::ixNet::OBJ-/vport:1/interface:4'
    ti_dsts['EndpointSet-1'] = '::ixNet::OBJ-/vport:4/interface:13'
    
    _result_ = ixiahlt.traffic_config(
        mode='create',
        traffic_generator='ixnetwork_540',
        endpointset_count=1,
        emulation_src_handle=[[ti_srcs['EndpointSet-1']]],
        emulation_dst_handle=[[ti_dsts['EndpointSet-1']]],
        emulation_multicast_dst_handle=[[]],
        emulation_multicast_dst_handle_type=[[]],
        global_dest_mac_retry_count='1',
        global_dest_mac_retry_delay='5',
        enable_data_integrity='1',
        global_enable_dest_mac_retry='1',
        global_enable_min_frame_size='0',
        global_enable_staggered_transmit='0',
        global_enable_stream_ordering='0',
        global_stream_control='continuous',
        global_stream_control_iterations='1',
        global_large_error_threshhold='2',
        global_enable_mac_change_on_fly='0',
        global_max_traffic_generation_queries='500',
        global_mpls_label_learning_timeout='30',
        global_refresh_learned_info_before_apply='0',
        global_use_tx_rx_sync='1',
        global_wait_time='1',
        global_display_mpls_current_label_value='0',
        global_detect_misdirected_packets='0',
        global_frame_ordering='none',
        frame_sequencing='disable',
        frame_sequencing_mode='rx_threshold',
        src_dest_mesh='one_to_one',
        route_mesh='one_to_one',
        bidirectional='1',
        allow_self_destined='0',
        use_cp_rate='1',
        use_cp_size='1',
        enable_dynamic_mpls_labels='0',
        hosts_per_net='1',
        name='TI18-HLTAPI_TRAFFICITEM_540',
        source_filter='all',
        destination_filter='all',
        tag_filter=[[]],
        merge_destinations='0',
        circuit_endpoint_type='ipv4',
        pending_operations_timeout='30'    
    )
    # Check status
    if _result_['status'] != IxiaHlt.SUCCESS:
    	ixnHLT_errorHandler('traffic_config', _result_)
    
    #  -- All current config elements
    config_elements = ixiatcl.convert_tcl_list(_result_['traffic_item'])
    
    #  -- Config Element //traffic/trafficItem:<19>/configElement:<1>
    ixnHLT_logger('Configuring options for config elem: //traffic/trafficItem:<19>/configElement:<1>')
    _result_ = ixiahlt.traffic_config(
        mode='modify',
        traffic_generator='ixnetwork_540',
        stream_id=config_elements[0],
        preamble_size_mode='auto',
        preamble_custom_size='8',
        data_pattern='',
        data_pattern_mode='incr_byte',
        enforce_min_gap='0',
        rate_pps='12500',
        frame_rate_distribution_port='split_evenly',
        frame_rate_distribution_stream='split_evenly',
        frame_size='64',
        length_mode='fixed',
        tx_mode='advanced',
        transmit_mode='continuous',
        pkts_per_burst='1',
        tx_delay='0',
        tx_delay_unit='bytes',
        number_of_packets_per_stream='1',
        loop_count='1',
        min_gap_bytes='12'    
    )
    # Check status
    if _result_['status'] != IxiaHlt.SUCCESS:
    	ixnHLT_errorHandler('traffic_config', _result_)
    
    #  -- Endpoint set EndpointSet-1
    ixnHLT_logger('Configuring traffic for config elem: //traffic/trafficItem:<19>/configElement:<1>')
    ixnHLT_logger('Configuring traffic for endpoint set: EndpointSet-1')
    #  -- Stack //traffic/trafficItem:<19>/configElement:<1>/stack:"ethernet-1"
    _result_ = ixiahlt.traffic_config(
        mode='modify_or_insert',
        traffic_generator='ixnetwork_540',
        stream_id=config_elements[0],
        stack_index='1',
        l2_encap='ethernet_ii',
        mac_dst_mode='fixed',
        mac_dst_tracking='0',
        mac_dst='00:00:00:00:00:00',
        mac_src_mode='fixed',
        mac_src_tracking='0',
        mac_src='00:00:00:00:00:00',
        ethernet_value_mode='fixed',
        ethernet_value='ffff',
        ethernet_value_tracking='0'    
    )
    # Check status
    if _result_['status'] != IxiaHlt.SUCCESS:
    	ixnHLT_errorHandler('traffic_config', _result_)
    
    #  -- Stack //traffic/trafficItem:<19>/configElement:<1>/stack:"vlan-2"
    _result_ = ixiahlt.traffic_config(
        mode='modify_or_insert',
        traffic_generator='ixnetwork_540',
        stream_id=config_elements[0],
        stack_index='2',
        vlan='enable',
        vlan_user_priority_mode='fixed',
        vlan_user_priority='0',
        vlan_user_priority_tracking='0',
        vlan_cfi_mode='fixed',
        vlan_cfi='0',
        vlan_cfi_tracking='0',
        vlan_id_mode='fixed',
        vlan_id='0',
        vlan_id_tracking='0'    
    )
    # Check status
    if _result_['status'] != IxiaHlt.SUCCESS:
    	ixnHLT_errorHandler('traffic_config', _result_)
    
    #  -- Stack //traffic/trafficItem:<19>/configElement:<1>/stack:"ipv4-3"
    _result_ = ixiahlt.traffic_config(
        mode='modify_or_insert',
        traffic_generator='ixnetwork_540',
        stream_id=config_elements[0],
        stack_index='3',
        l3_protocol='ipv4',
        qos_type_ixn='tos',
        ip_precedence_mode='fixed',
        ip_precedence='0',
        ip_precedence_tracking='0',
        ip_delay_mode='fixed',
        ip_delay='0',
        ip_delay_tracking='0',
        ip_throughput_mode='fixed',
        ip_throughput='0',
        ip_throughput_tracking='0',
        ip_reliability_mode='fixed',
        ip_reliability='0',
        ip_reliability_tracking='0',
        ip_cost_mode='fixed',
        ip_cost='0',
        ip_cost_tracking='0',
        ip_cu_mode='fixed',
        ip_cu='0',
        ip_cu_tracking='0',
        ip_id_mode='fixed',
        ip_id='0',
        ip_id_tracking='0',
        ip_reserved_mode='fixed',
        ip_reserved='0',
        ip_reserved_tracking='0',
        ip_fragment_mode='fixed',
        ip_fragment='1',
        ip_fragment_tracking='0',
        ip_fragment_last_mode='fixed',
        ip_fragment_last='1',
        ip_fragment_last_tracking='0',
        ip_fragment_offset_mode='fixed',
        ip_fragment_offset='0',
        ip_fragment_offset_tracking='0',
        ip_ttl_mode='fixed',
        ip_ttl='64',
        ip_ttl_tracking='0',
        track_by='none',
        egress_tracking='none'    
    )
    # Check status
    if _result_['status'] != IxiaHlt.SUCCESS:
    	ixnHLT_errorHandler('traffic_config', _result_)
    
    #  -- Post Options
    ixnHLT_logger('Configuring post options for config elem: //traffic/trafficItem:<19>/configElement:<1>')
    _result_ = ixiahlt.traffic_config(
        mode='modify',
        traffic_generator='ixnetwork_540',
        stream_id=config_elements[0],
        transmit_distribution='none'    
    )
    # Check status
    if _result_['status'] != IxiaHlt.SUCCESS:
    	ixnHLT_errorHandler('traffic_config', _result_)
    
    #  -- Traffic item//traffic/trafficItem:<1>
    ixnHLT_logger('Configuring traffic for traffic item: //traffic/trafficItem:<1>')
    
    ti_srcs, ti_dsts = {}, {}
    ti_mcast_rcvr_handle, ti_mcast_rcvr_port_index, ti_mcast_rcvr_host_index, ti_mcast_rcvr_mcast_index = {}, {}, {}, {}
    
    ti_srcs['EndpointSet-1'] = ixnHLT_endpointMatch(ixnHLT, ['//vport:<1>'], 'PORT-HANDLE')
    if len(ti_srcs) == 0:
        match_err = {'log': 'Cannot find any src endpoints for EndpointSet-1'}
        ixnHLT_errorHandler('ixnHLT_endpointMatch', match_err)
    
    ti_dsts['EndpointSet-1'] = ixnHLT_endpointMatch(ixnHLT, ['//vport:<1>'], 'PORT-HANDLE')
    if len(ti_dsts) == 0:
        match_err = {'log': 'Cannot find any dst endpoints for elem EndpointSet-1'}
        ixnHLT_errorHandler('ixnHLT_endpointMatch', match_err)
    
    
    _result_ = ixiahlt.traffic_config(
        mode='create',
        traffic_generator='ixnetwork_540',
        endpointset_count=1,
        emulation_src_handle=[[ti_srcs['EndpointSet-1']]],
        emulation_dst_handle=[[ti_dsts['EndpointSet-1']]],
        emulation_multicast_dst_handle=[[]],
        emulation_multicast_dst_handle_type=[[]],
        global_dest_mac_retry_count='1',
        global_dest_mac_retry_delay='5',
        enable_data_integrity='1',
        global_enable_dest_mac_retry='1',
        global_enable_min_frame_size='0',
        global_enable_staggered_transmit='0',
        global_enable_stream_ordering='0',
        global_stream_control='continuous',
        global_stream_control_iterations='1',
        global_large_error_threshhold='2',
        global_enable_mac_change_on_fly='0',
        global_max_traffic_generation_queries='500',
        global_mpls_label_learning_timeout='30',
        global_refresh_learned_info_before_apply='0',
        global_use_tx_rx_sync='1',
        global_wait_time='1',
        global_display_mpls_current_label_value='0',
        global_detect_misdirected_packets='0',
        global_frame_ordering='none',
        frame_sequencing='disable',
        frame_sequencing_mode='rx_threshold',
        src_dest_mesh='one_to_one',
        route_mesh='one_to_one',
        bidirectional='0',
        allow_self_destined='1',
        use_cp_rate='1',
        use_cp_size='1',
        enable_dynamic_mpls_labels='0',
        hosts_per_net='1',
        name='TI0-HLTAPI_TRAFFICITEM_540',
        source_filter='all',
        destination_filter='all',
        tag_filter=[[]],
        merge_destinations='1',
        circuit_type='raw',
        pending_operations_timeout='30'    
    )
    # Check status
    if _result_['status'] != IxiaHlt.SUCCESS:
    	ixnHLT_errorHandler('traffic_config', _result_)
    
    #  -- All current config elements
    config_elements = ixiatcl.convert_tcl_list(_result_['traffic_item'])
    
    #  -- Config Element //traffic/trafficItem:<1>/configElement:<1>
    ixnHLT_logger('Configuring options for config elem: //traffic/trafficItem:<1>/configElement:<1>')
    _result_ = ixiahlt.traffic_config(
        mode='modify',
        traffic_generator='ixnetwork_540',
        stream_id=config_elements[0],
        preamble_size_mode='auto',
        preamble_custom_size='8',
        data_pattern='',
        data_pattern_mode='incr_byte',
        enforce_min_gap='0',
        rate_pps='200000',
        frame_rate_distribution_port='split_evenly',
        frame_rate_distribution_stream='split_evenly',
        frame_size='64',
        length_mode='fixed',
        tx_mode='advanced',
        transmit_mode='continuous',
        pkts_per_burst='1',
        tx_delay='0',
        tx_delay_unit='bytes',
        number_of_packets_per_stream='1',
        loop_count='1',
        min_gap_bytes='12'    
    )
    # Check status
    if _result_['status'] != IxiaHlt.SUCCESS:
    	ixnHLT_errorHandler('traffic_config', _result_)
    
    #  -- Endpoint set EndpointSet-1
    ixnHLT_logger('Configuring traffic for config elem: //traffic/trafficItem:<1>/configElement:<1>')
    ixnHLT_logger('Configuring traffic for endpoint set: EndpointSet-1')
    #  -- Stack //traffic/trafficItem:<1>/configElement:<1>/stack:"ethernet-1"
    _result_ = ixiahlt.traffic_config(
        mode='modify_or_insert',
        traffic_generator='ixnetwork_540',
        stream_id=config_elements[0],
        stack_index='1',
        l2_encap='ethernet_ii',
        mac_dst_mode='fixed',
        mac_dst_tracking='0',
        mac_dst='ff:ff:ff:ff:ff:ff',
        mac_src_mode='increment',
        mac_src_tracking='0',
        mac_src='00:56:44:1b:29:02',
        mac_src_step='00:00:00:00:00:00',
        mac_src_count='16'    
    )
    # Check status
    if _result_['status'] != IxiaHlt.SUCCESS:
    	ixnHLT_errorHandler('traffic_config', _result_)
    
    #  -- Stack //traffic/trafficItem:<1>/configElement:<1>/stack:"ipv4-2"
    _result_ = ixiahlt.traffic_config(
        mode='modify_or_insert',
        traffic_generator='ixnetwork_540',
        stream_id=config_elements[0],
        stack_index='2',
        l3_protocol='ipv4',
        qos_type_ixn='tos',
        ip_precedence_mode='fixed',
        ip_precedence='0',
        ip_precedence_tracking='0',
        ip_delay_mode='fixed',
        ip_delay='0',
        ip_delay_tracking='0',
        ip_throughput_mode='fixed',
        ip_throughput='0',
        ip_throughput_tracking='0',
        ip_reliability_mode='fixed',
        ip_reliability='0',
        ip_reliability_tracking='0',
        ip_cost_mode='fixed',
        ip_cost='0',
        ip_cost_tracking='0',
        ip_cu_mode='fixed',
        ip_cu='0',
        ip_cu_tracking='0',
        ip_id_mode='fixed',
        ip_id='0',
        ip_id_tracking='0',
        ip_reserved_mode='fixed',
        ip_reserved='0',
        ip_reserved_tracking='0',
        ip_fragment_mode='fixed',
        ip_fragment='1',
        ip_fragment_tracking='0',
        ip_fragment_last_mode='fixed',
        ip_fragment_last='1',
        ip_fragment_last_tracking='0',
        ip_fragment_offset_mode='fixed',
        ip_fragment_offset='0',
        ip_fragment_offset_tracking='0',
        ip_ttl_mode='fixed',
        ip_ttl='64',
        ip_ttl_tracking='0',
        track_by='none',
        egress_tracking='none'    
    )
    # Check status
    if _result_['status'] != IxiaHlt.SUCCESS:
    	ixnHLT_errorHandler('traffic_config', _result_)
    
    #  -- Post Options
    ixnHLT_logger('Configuring post options for config elem: //traffic/trafficItem:<1>/configElement:<1>')
    _result_ = ixiahlt.traffic_config(
        mode='modify',
        traffic_generator='ixnetwork_540',
        stream_id=config_elements[0],
        transmit_distribution='none'    
    )
    # Check status
    if _result_['status'] != IxiaHlt.SUCCESS:
    	ixnHLT_errorHandler('traffic_config', _result_)
    
    #  -- Traffic item//traffic/trafficItem:<20>
    ixnHLT_logger('Configuring traffic for traffic item: //traffic/trafficItem:<20>')
    
    ti_srcs, ti_dsts = {}, {}
    ti_mcast_rcvr_handle, ti_mcast_rcvr_port_index, ti_mcast_rcvr_host_index, ti_mcast_rcvr_mcast_index = {}, {}, {}, {}
    
    ti_srcs['EndpointSet-1'] = '::ixNet::OBJ-/vport:1/interface:4'
    ti_dsts['EndpointSet-1'] = '::ixNet::OBJ-/vport:4/interface:14'
    
    _result_ = ixiahlt.traffic_config(
        mode='create',
        traffic_generator='ixnetwork_540',
        endpointset_count=1,
        emulation_src_handle=[[ti_srcs['EndpointSet-1']]],
        emulation_dst_handle=[[ti_dsts['EndpointSet-1']]],
        emulation_multicast_dst_handle=[[]],
        emulation_multicast_dst_handle_type=[[]],
        global_dest_mac_retry_count='1',
        global_dest_mac_retry_delay='5',
        enable_data_integrity='1',
        global_enable_dest_mac_retry='1',
        global_enable_min_frame_size='0',
        global_enable_staggered_transmit='0',
        global_enable_stream_ordering='0',
        global_stream_control='continuous',
        global_stream_control_iterations='1',
        global_large_error_threshhold='2',
        global_enable_mac_change_on_fly='0',
        global_max_traffic_generation_queries='500',
        global_mpls_label_learning_timeout='30',
        global_refresh_learned_info_before_apply='0',
        global_use_tx_rx_sync='1',
        global_wait_time='1',
        global_display_mpls_current_label_value='0',
        global_detect_misdirected_packets='0',
        global_frame_ordering='none',
        frame_sequencing='disable',
        frame_sequencing_mode='rx_threshold',
        src_dest_mesh='one_to_one',
        route_mesh='one_to_one',
        bidirectional='1',
        allow_self_destined='0',
        use_cp_rate='1',
        use_cp_size='1',
        enable_dynamic_mpls_labels='0',
        hosts_per_net='1',
        name='TI19-HLTAPI_TRAFFICITEM_540',
        source_filter='all',
        destination_filter='all',
        tag_filter=[[]],
        merge_destinations='0',
        circuit_endpoint_type='ipv4',
        pending_operations_timeout='30'    
    )
    # Check status
    if _result_['status'] != IxiaHlt.SUCCESS:
    	ixnHLT_errorHandler('traffic_config', _result_)
    
    #  -- All current config elements
    config_elements = ixiatcl.convert_tcl_list(_result_['traffic_item'])
    
    #  -- Config Element //traffic/trafficItem:<20>/configElement:<1>
    ixnHLT_logger('Configuring options for config elem: //traffic/trafficItem:<20>/configElement:<1>')
    _result_ = ixiahlt.traffic_config(
        mode='modify',
        traffic_generator='ixnetwork_540',
        stream_id=config_elements[0],
        preamble_size_mode='auto',
        preamble_custom_size='8',
        data_pattern='',
        data_pattern_mode='incr_byte',
        enforce_min_gap='0',
        rate_pps='12500',
        frame_rate_distribution_port='split_evenly',
        frame_rate_distribution_stream='split_evenly',
        frame_size='64',
        length_mode='fixed',
        tx_mode='advanced',
        transmit_mode='continuous',
        pkts_per_burst='1',
        tx_delay='0',
        tx_delay_unit='bytes',
        number_of_packets_per_stream='1',
        loop_count='1',
        min_gap_bytes='12'    
    )
    # Check status
    if _result_['status'] != IxiaHlt.SUCCESS:
    	ixnHLT_errorHandler('traffic_config', _result_)
    
    #  -- Endpoint set EndpointSet-1
    ixnHLT_logger('Configuring traffic for config elem: //traffic/trafficItem:<20>/configElement:<1>')
    ixnHLT_logger('Configuring traffic for endpoint set: EndpointSet-1')
    #  -- Stack //traffic/trafficItem:<20>/configElement:<1>/stack:"ethernet-1"
    _result_ = ixiahlt.traffic_config(
        mode='modify_or_insert',
        traffic_generator='ixnetwork_540',
        stream_id=config_elements[0],
        stack_index='1',
        l2_encap='ethernet_ii',
        mac_dst_mode='fixed',
        mac_dst_tracking='0',
        mac_dst='00:00:00:00:00:00',
        mac_src_mode='fixed',
        mac_src_tracking='0',
        mac_src='00:00:00:00:00:00',
        ethernet_value_mode='fixed',
        ethernet_value='ffff',
        ethernet_value_tracking='0'    
    )
    # Check status
    if _result_['status'] != IxiaHlt.SUCCESS:
    	ixnHLT_errorHandler('traffic_config', _result_)
    
    #  -- Stack //traffic/trafficItem:<20>/configElement:<1>/stack:"vlan-2"
    _result_ = ixiahlt.traffic_config(
        mode='modify_or_insert',
        traffic_generator='ixnetwork_540',
        stream_id=config_elements[0],
        stack_index='2',
        vlan='enable',
        vlan_user_priority_mode='fixed',
        vlan_user_priority='0',
        vlan_user_priority_tracking='0',
        vlan_cfi_mode='fixed',
        vlan_cfi='0',
        vlan_cfi_tracking='0',
        vlan_id_mode='fixed',
        vlan_id='0',
        vlan_id_tracking='0'    
    )
    # Check status
    if _result_['status'] != IxiaHlt.SUCCESS:
    	ixnHLT_errorHandler('traffic_config', _result_)
    
    #  -- Stack //traffic/trafficItem:<20>/configElement:<1>/stack:"ipv4-3"
    _result_ = ixiahlt.traffic_config(
        mode='modify_or_insert',
        traffic_generator='ixnetwork_540',
        stream_id=config_elements[0],
        stack_index='3',
        l3_protocol='ipv4',
        qos_type_ixn='tos',
        ip_precedence_mode='fixed',
        ip_precedence='0',
        ip_precedence_tracking='0',
        ip_delay_mode='fixed',
        ip_delay='0',
        ip_delay_tracking='0',
        ip_throughput_mode='fixed',
        ip_throughput='0',
        ip_throughput_tracking='0',
        ip_reliability_mode='fixed',
        ip_reliability='0',
        ip_reliability_tracking='0',
        ip_cost_mode='fixed',
        ip_cost='0',
        ip_cost_tracking='0',
        ip_cu_mode='fixed',
        ip_cu='0',
        ip_cu_tracking='0',
        ip_id_mode='fixed',
        ip_id='0',
        ip_id_tracking='0',
        ip_reserved_mode='fixed',
        ip_reserved='0',
        ip_reserved_tracking='0',
        ip_fragment_mode='fixed',
        ip_fragment='1',
        ip_fragment_tracking='0',
        ip_fragment_last_mode='fixed',
        ip_fragment_last='1',
        ip_fragment_last_tracking='0',
        ip_fragment_offset_mode='fixed',
        ip_fragment_offset='0',
        ip_fragment_offset_tracking='0',
        ip_ttl_mode='fixed',
        ip_ttl='64',
        ip_ttl_tracking='0',
        track_by='none',
        egress_tracking='none'    
    )
    # Check status
    if _result_['status'] != IxiaHlt.SUCCESS:
    	ixnHLT_errorHandler('traffic_config', _result_)
    
    #  -- Post Options
    ixnHLT_logger('Configuring post options for config elem: //traffic/trafficItem:<20>/configElement:<1>')
    _result_ = ixiahlt.traffic_config(
        mode='modify',
        traffic_generator='ixnetwork_540',
        stream_id=config_elements[0],
        transmit_distribution='none'    
    )
    # Check status
    if _result_['status'] != IxiaHlt.SUCCESS:
    	ixnHLT_errorHandler('traffic_config', _result_)
    
    #  -- Traffic item//traffic/trafficItem:<21>
    ixnHLT_logger('Configuring traffic for traffic item: //traffic/trafficItem:<21>')
    
    ti_srcs, ti_dsts = {}, {}
    ti_mcast_rcvr_handle, ti_mcast_rcvr_port_index, ti_mcast_rcvr_host_index, ti_mcast_rcvr_mcast_index = {}, {}, {}, {}
    
    ti_srcs['EndpointSet-1'] = '::ixNet::OBJ-/vport:1/interface:4'
    ti_dsts['EndpointSet-1'] = '::ixNet::OBJ-/vport:4/interface:15'
    
    _result_ = ixiahlt.traffic_config(
        mode='create',
        traffic_generator='ixnetwork_540',
        endpointset_count=1,
        emulation_src_handle=[[ti_srcs['EndpointSet-1']]],
        emulation_dst_handle=[[ti_dsts['EndpointSet-1']]],
        emulation_multicast_dst_handle=[[]],
        emulation_multicast_dst_handle_type=[[]],
        global_dest_mac_retry_count='1',
        global_dest_mac_retry_delay='5',
        enable_data_integrity='1',
        global_enable_dest_mac_retry='1',
        global_enable_min_frame_size='0',
        global_enable_staggered_transmit='0',
        global_enable_stream_ordering='0',
        global_stream_control='continuous',
        global_stream_control_iterations='1',
        global_large_error_threshhold='2',
        global_enable_mac_change_on_fly='0',
        global_max_traffic_generation_queries='500',
        global_mpls_label_learning_timeout='30',
        global_refresh_learned_info_before_apply='0',
        global_use_tx_rx_sync='1',
        global_wait_time='1',
        global_display_mpls_current_label_value='0',
        global_detect_misdirected_packets='0',
        global_frame_ordering='none',
        frame_sequencing='disable',
        frame_sequencing_mode='rx_threshold',
        src_dest_mesh='one_to_one',
        route_mesh='one_to_one',
        bidirectional='1',
        allow_self_destined='0',
        use_cp_rate='1',
        use_cp_size='1',
        enable_dynamic_mpls_labels='0',
        hosts_per_net='1',
        name='TI20-HLTAPI_TRAFFICITEM_540',
        source_filter='all',
        destination_filter='all',
        tag_filter=[[]],
        merge_destinations='0',
        circuit_endpoint_type='ipv4',
        pending_operations_timeout='30'    
    )
    # Check status
    if _result_['status'] != IxiaHlt.SUCCESS:
    	ixnHLT_errorHandler('traffic_config', _result_)
    
    #  -- All current config elements
    config_elements = ixiatcl.convert_tcl_list(_result_['traffic_item'])
    
    #  -- Config Element //traffic/trafficItem:<21>/configElement:<1>
    ixnHLT_logger('Configuring options for config elem: //traffic/trafficItem:<21>/configElement:<1>')
    _result_ = ixiahlt.traffic_config(
        mode='modify',
        traffic_generator='ixnetwork_540',
        stream_id=config_elements[0],
        preamble_size_mode='auto',
        preamble_custom_size='8',
        data_pattern='',
        data_pattern_mode='incr_byte',
        enforce_min_gap='0',
        rate_pps='12500',
        frame_rate_distribution_port='split_evenly',
        frame_rate_distribution_stream='split_evenly',
        frame_size='64',
        length_mode='fixed',
        tx_mode='advanced',
        transmit_mode='continuous',
        pkts_per_burst='1',
        tx_delay='0',
        tx_delay_unit='bytes',
        number_of_packets_per_stream='1',
        loop_count='1',
        min_gap_bytes='12'    
    )
    # Check status
    if _result_['status'] != IxiaHlt.SUCCESS:
    	ixnHLT_errorHandler('traffic_config', _result_)
    
    #  -- Endpoint set EndpointSet-1
    ixnHLT_logger('Configuring traffic for config elem: //traffic/trafficItem:<21>/configElement:<1>')
    ixnHLT_logger('Configuring traffic for endpoint set: EndpointSet-1')
    #  -- Stack //traffic/trafficItem:<21>/configElement:<1>/stack:"ethernet-1"
    _result_ = ixiahlt.traffic_config(
        mode='modify_or_insert',
        traffic_generator='ixnetwork_540',
        stream_id=config_elements[0],
        stack_index='1',
        l2_encap='ethernet_ii',
        mac_dst_mode='fixed',
        mac_dst_tracking='0',
        mac_dst='00:00:00:00:00:00',
        mac_src_mode='fixed',
        mac_src_tracking='0',
        mac_src='00:00:00:00:00:00',
        ethernet_value_mode='fixed',
        ethernet_value='ffff',
        ethernet_value_tracking='0'    
    )
    # Check status
    if _result_['status'] != IxiaHlt.SUCCESS:
    	ixnHLT_errorHandler('traffic_config', _result_)
    
    #  -- Stack //traffic/trafficItem:<21>/configElement:<1>/stack:"vlan-2"
    _result_ = ixiahlt.traffic_config(
        mode='modify_or_insert',
        traffic_generator='ixnetwork_540',
        stream_id=config_elements[0],
        stack_index='2',
        vlan='enable',
        vlan_user_priority_mode='fixed',
        vlan_user_priority='0',
        vlan_user_priority_tracking='0',
        vlan_cfi_mode='fixed',
        vlan_cfi='0',
        vlan_cfi_tracking='0',
        vlan_id_mode='fixed',
        vlan_id='0',
        vlan_id_tracking='0'    
    )
    # Check status
    if _result_['status'] != IxiaHlt.SUCCESS:
    	ixnHLT_errorHandler('traffic_config', _result_)
    
    #  -- Stack //traffic/trafficItem:<21>/configElement:<1>/stack:"ipv4-3"
    _result_ = ixiahlt.traffic_config(
        mode='modify_or_insert',
        traffic_generator='ixnetwork_540',
        stream_id=config_elements[0],
        stack_index='3',
        l3_protocol='ipv4',
        qos_type_ixn='tos',
        ip_precedence_mode='fixed',
        ip_precedence='0',
        ip_precedence_tracking='0',
        ip_delay_mode='fixed',
        ip_delay='0',
        ip_delay_tracking='0',
        ip_throughput_mode='fixed',
        ip_throughput='0',
        ip_throughput_tracking='0',
        ip_reliability_mode='fixed',
        ip_reliability='0',
        ip_reliability_tracking='0',
        ip_cost_mode='fixed',
        ip_cost='0',
        ip_cost_tracking='0',
        ip_cu_mode='fixed',
        ip_cu='0',
        ip_cu_tracking='0',
        ip_id_mode='fixed',
        ip_id='0',
        ip_id_tracking='0',
        ip_reserved_mode='fixed',
        ip_reserved='0',
        ip_reserved_tracking='0',
        ip_fragment_mode='fixed',
        ip_fragment='1',
        ip_fragment_tracking='0',
        ip_fragment_last_mode='fixed',
        ip_fragment_last='1',
        ip_fragment_last_tracking='0',
        ip_fragment_offset_mode='fixed',
        ip_fragment_offset='0',
        ip_fragment_offset_tracking='0',
        ip_ttl_mode='fixed',
        ip_ttl='64',
        ip_ttl_tracking='0',
        track_by='none',
        egress_tracking='none'    
    )
    # Check status
    if _result_['status'] != IxiaHlt.SUCCESS:
    	ixnHLT_errorHandler('traffic_config', _result_)
    
    #  -- Post Options
    ixnHLT_logger('Configuring post options for config elem: //traffic/trafficItem:<21>/configElement:<1>')
    _result_ = ixiahlt.traffic_config(
        mode='modify',
        traffic_generator='ixnetwork_540',
        stream_id=config_elements[0],
        transmit_distribution='none'    
    )
    # Check status
    if _result_['status'] != IxiaHlt.SUCCESS:
    	ixnHLT_errorHandler('traffic_config', _result_)
    
    #  -- Traffic item//traffic/trafficItem:<22>
    ixnHLT_logger('Configuring traffic for traffic item: //traffic/trafficItem:<22>')
    
    ti_srcs, ti_dsts = {}, {}
    ti_mcast_rcvr_handle, ti_mcast_rcvr_port_index, ti_mcast_rcvr_host_index, ti_mcast_rcvr_mcast_index = {}, {}, {}, {}
    
    ti_srcs['EndpointSet-1'] = '::ixNet::OBJ-/vport:1/interface:4'
    ti_dsts['EndpointSet-1'] = '::ixNet::OBJ-/vport:4/interface:16'
    
    _result_ = ixiahlt.traffic_config(
        mode='create',
        traffic_generator='ixnetwork_540',
        endpointset_count=1,
        emulation_src_handle=[[ti_srcs['EndpointSet-1']]],
        emulation_dst_handle=[[ti_dsts['EndpointSet-1']]],
        emulation_multicast_dst_handle=[[]],
        emulation_multicast_dst_handle_type=[[]],
        global_dest_mac_retry_count='1',
        global_dest_mac_retry_delay='5',
        enable_data_integrity='1',
        global_enable_dest_mac_retry='1',
        global_enable_min_frame_size='0',
        global_enable_staggered_transmit='0',
        global_enable_stream_ordering='0',
        global_stream_control='continuous',
        global_stream_control_iterations='1',
        global_large_error_threshhold='2',
        global_enable_mac_change_on_fly='0',
        global_max_traffic_generation_queries='500',
        global_mpls_label_learning_timeout='30',
        global_refresh_learned_info_before_apply='0',
        global_use_tx_rx_sync='1',
        global_wait_time='1',
        global_display_mpls_current_label_value='0',
        global_detect_misdirected_packets='0',
        global_frame_ordering='none',
        frame_sequencing='disable',
        frame_sequencing_mode='rx_threshold',
        src_dest_mesh='one_to_one',
        route_mesh='one_to_one',
        bidirectional='1',
        allow_self_destined='0',
        use_cp_rate='1',
        use_cp_size='1',
        enable_dynamic_mpls_labels='0',
        hosts_per_net='1',
        name='TI21-HLTAPI_TRAFFICITEM_540',
        source_filter='all',
        destination_filter='all',
        tag_filter=[[]],
        merge_destinations='0',
        circuit_endpoint_type='ipv4',
        pending_operations_timeout='30'    
    )
    # Check status
    if _result_['status'] != IxiaHlt.SUCCESS:
    	ixnHLT_errorHandler('traffic_config', _result_)
    
    #  -- All current config elements
    config_elements = ixiatcl.convert_tcl_list(_result_['traffic_item'])
    
    #  -- Config Element //traffic/trafficItem:<22>/configElement:<1>
    ixnHLT_logger('Configuring options for config elem: //traffic/trafficItem:<22>/configElement:<1>')
    _result_ = ixiahlt.traffic_config(
        mode='modify',
        traffic_generator='ixnetwork_540',
        stream_id=config_elements[0],
        preamble_size_mode='auto',
        preamble_custom_size='8',
        data_pattern='',
        data_pattern_mode='incr_byte',
        enforce_min_gap='0',
        rate_pps='12500',
        frame_rate_distribution_port='split_evenly',
        frame_rate_distribution_stream='split_evenly',
        frame_size='64',
        length_mode='fixed',
        tx_mode='advanced',
        transmit_mode='continuous',
        pkts_per_burst='1',
        tx_delay='0',
        tx_delay_unit='bytes',
        number_of_packets_per_stream='1',
        loop_count='1',
        min_gap_bytes='12'    
    )
    # Check status
    if _result_['status'] != IxiaHlt.SUCCESS:
    	ixnHLT_errorHandler('traffic_config', _result_)
    
    #  -- Endpoint set EndpointSet-1
    ixnHLT_logger('Configuring traffic for config elem: //traffic/trafficItem:<22>/configElement:<1>')
    ixnHLT_logger('Configuring traffic for endpoint set: EndpointSet-1')
    #  -- Stack //traffic/trafficItem:<22>/configElement:<1>/stack:"ethernet-1"
    _result_ = ixiahlt.traffic_config(
        mode='modify_or_insert',
        traffic_generator='ixnetwork_540',
        stream_id=config_elements[0],
        stack_index='1',
        l2_encap='ethernet_ii',
        mac_dst_mode='fixed',
        mac_dst_tracking='0',
        mac_dst='00:00:00:00:00:00',
        mac_src_mode='fixed',
        mac_src_tracking='0',
        mac_src='00:00:00:00:00:00',
        ethernet_value_mode='fixed',
        ethernet_value='ffff',
        ethernet_value_tracking='0'    
    )
    # Check status
    if _result_['status'] != IxiaHlt.SUCCESS:
    	ixnHLT_errorHandler('traffic_config', _result_)
    
    #  -- Stack //traffic/trafficItem:<22>/configElement:<1>/stack:"vlan-2"
    _result_ = ixiahlt.traffic_config(
        mode='modify_or_insert',
        traffic_generator='ixnetwork_540',
        stream_id=config_elements[0],
        stack_index='2',
        vlan='enable',
        vlan_user_priority_mode='fixed',
        vlan_user_priority='0',
        vlan_user_priority_tracking='0',
        vlan_cfi_mode='fixed',
        vlan_cfi='0',
        vlan_cfi_tracking='0',
        vlan_id_mode='fixed',
        vlan_id='0',
        vlan_id_tracking='0'    
    )
    # Check status
    if _result_['status'] != IxiaHlt.SUCCESS:
    	ixnHLT_errorHandler('traffic_config', _result_)
    
    #  -- Stack //traffic/trafficItem:<22>/configElement:<1>/stack:"ipv4-3"
    _result_ = ixiahlt.traffic_config(
        mode='modify_or_insert',
        traffic_generator='ixnetwork_540',
        stream_id=config_elements[0],
        stack_index='3',
        l3_protocol='ipv4',
        qos_type_ixn='tos',
        ip_precedence_mode='fixed',
        ip_precedence='0',
        ip_precedence_tracking='0',
        ip_delay_mode='fixed',
        ip_delay='0',
        ip_delay_tracking='0',
        ip_throughput_mode='fixed',
        ip_throughput='0',
        ip_throughput_tracking='0',
        ip_reliability_mode='fixed',
        ip_reliability='0',
        ip_reliability_tracking='0',
        ip_cost_mode='fixed',
        ip_cost='0',
        ip_cost_tracking='0',
        ip_cu_mode='fixed',
        ip_cu='0',
        ip_cu_tracking='0',
        ip_id_mode='fixed',
        ip_id='0',
        ip_id_tracking='0',
        ip_reserved_mode='fixed',
        ip_reserved='0',
        ip_reserved_tracking='0',
        ip_fragment_mode='fixed',
        ip_fragment='1',
        ip_fragment_tracking='0',
        ip_fragment_last_mode='fixed',
        ip_fragment_last='1',
        ip_fragment_last_tracking='0',
        ip_fragment_offset_mode='fixed',
        ip_fragment_offset='0',
        ip_fragment_offset_tracking='0',
        ip_ttl_mode='fixed',
        ip_ttl='64',
        ip_ttl_tracking='0',
        track_by='none',
        egress_tracking='none'    
    )
    # Check status
    if _result_['status'] != IxiaHlt.SUCCESS:
    	ixnHLT_errorHandler('traffic_config', _result_)
    
    #  -- Post Options
    ixnHLT_logger('Configuring post options for config elem: //traffic/trafficItem:<22>/configElement:<1>')
    _result_ = ixiahlt.traffic_config(
        mode='modify',
        traffic_generator='ixnetwork_540',
        stream_id=config_elements[0],
        transmit_distribution='none'    
    )
    # Check status
    if _result_['status'] != IxiaHlt.SUCCESS:
    	ixnHLT_errorHandler('traffic_config', _result_)
    
    #  -- Traffic item//traffic/trafficItem:<23>
    ixnHLT_logger('Configuring traffic for traffic item: //traffic/trafficItem:<23>')
    
    ti_srcs, ti_dsts = {}, {}
    ti_mcast_rcvr_handle, ti_mcast_rcvr_port_index, ti_mcast_rcvr_host_index, ti_mcast_rcvr_mcast_index = {}, {}, {}, {}
    
    ti_srcs['EndpointSet-1'] = ixnHLT_endpointMatch(ixnHLT, ['//vport:<1>'], 'PORT-HANDLE')
    if len(ti_srcs) == 0:
        match_err = {'log': 'Cannot find any src endpoints for EndpointSet-1'}
        ixnHLT_errorHandler('ixnHLT_endpointMatch', match_err)
    
    ti_dsts['EndpointSet-1'] = ixnHLT_endpointMatch(ixnHLT, ['//vport:<1>'], 'PORT-HANDLE')
    if len(ti_dsts) == 0:
        match_err = {'log': 'Cannot find any dst endpoints for elem EndpointSet-1'}
        ixnHLT_errorHandler('ixnHLT_endpointMatch', match_err)
    
    
    _result_ = ixiahlt.traffic_config(
        mode='create',
        traffic_generator='ixnetwork_540',
        endpointset_count=1,
        emulation_src_handle=[[ti_srcs['EndpointSet-1']]],
        emulation_dst_handle=[[ti_dsts['EndpointSet-1']]],
        emulation_multicast_dst_handle=[[]],
        emulation_multicast_dst_handle_type=[[]],
        global_dest_mac_retry_count='1',
        global_dest_mac_retry_delay='5',
        enable_data_integrity='1',
        global_enable_dest_mac_retry='1',
        global_enable_min_frame_size='0',
        global_enable_staggered_transmit='0',
        global_enable_stream_ordering='0',
        global_stream_control='continuous',
        global_stream_control_iterations='1',
        global_large_error_threshhold='2',
        global_enable_mac_change_on_fly='0',
        global_max_traffic_generation_queries='500',
        global_mpls_label_learning_timeout='30',
        global_refresh_learned_info_before_apply='0',
        global_use_tx_rx_sync='1',
        global_wait_time='1',
        global_display_mpls_current_label_value='0',
        global_detect_misdirected_packets='0',
        global_frame_ordering='none',
        frame_sequencing='disable',
        frame_sequencing_mode='rx_threshold',
        src_dest_mesh='one_to_one',
        route_mesh='one_to_one',
        bidirectional='0',
        allow_self_destined='1',
        use_cp_rate='1',
        use_cp_size='1',
        enable_dynamic_mpls_labels='0',
        hosts_per_net='1',
        name='TI22-HLTAPI_TRAFFICITEM_540',
        source_filter='all',
        destination_filter='all',
        tag_filter=[[]],
        merge_destinations='1',
        circuit_type='raw',
        pending_operations_timeout='30'    
    )
    # Check status
    if _result_['status'] != IxiaHlt.SUCCESS:
    	ixnHLT_errorHandler('traffic_config', _result_)
    
    #  -- All current config elements
    config_elements = ixiatcl.convert_tcl_list(_result_['traffic_item'])
    
    #  -- Config Element //traffic/trafficItem:<23>/configElement:<1>
    ixnHLT_logger('Configuring options for config elem: //traffic/trafficItem:<23>/configElement:<1>')
    _result_ = ixiahlt.traffic_config(
        mode='modify',
        traffic_generator='ixnetwork_540',
        stream_id=config_elements[0],
        preamble_size_mode='auto',
        preamble_custom_size='8',
        data_pattern='',
        data_pattern_mode='incr_byte',
        enforce_min_gap='0',
        rate_pps='200000',
        frame_rate_distribution_port='split_evenly',
        frame_rate_distribution_stream='split_evenly',
        frame_size='64',
        length_mode='fixed',
        tx_mode='advanced',
        transmit_mode='continuous',
        pkts_per_burst='1',
        tx_delay='0',
        tx_delay_unit='bytes',
        number_of_packets_per_stream='1',
        loop_count='1',
        min_gap_bytes='12'    
    )
    # Check status
    if _result_['status'] != IxiaHlt.SUCCESS:
    	ixnHLT_errorHandler('traffic_config', _result_)
    
    #  -- Endpoint set EndpointSet-1
    ixnHLT_logger('Configuring traffic for config elem: //traffic/trafficItem:<23>/configElement:<1>')
    ixnHLT_logger('Configuring traffic for endpoint set: EndpointSet-1')
    #  -- Stack //traffic/trafficItem:<23>/configElement:<1>/stack:"ethernet-1"
    _result_ = ixiahlt.traffic_config(
        mode='modify_or_insert',
        traffic_generator='ixnetwork_540',
        stream_id=config_elements[0],
        stack_index='1',
        l2_encap='ethernet_ii',
        mac_dst_mode='increment',
        mac_dst_tracking='0',
        mac_dst='00:13:60:60:00:02',
        mac_dst_step='00:00:00:00:00:01',
        mac_dst_count='16',
        mac_src_mode='increment',
        mac_src_tracking='0',
        mac_src='00:12:60:60:00:02',
        mac_src_step='00:00:00:00:00:01',
        mac_src_count='16'    
    )
    # Check status
    if _result_['status'] != IxiaHlt.SUCCESS:
    	ixnHLT_errorHandler('traffic_config', _result_)
    
    #  -- Stack //traffic/trafficItem:<23>/configElement:<1>/stack:"ipv6-2"
    _result_ = ixiahlt.traffic_config(
        mode='modify_or_insert',
        traffic_generator='ixnetwork_540',
        stream_id=config_elements[0],
        stack_index='2',
        l3_protocol='ipv6',
        ipv6_flow_version_mode='fixed',
        ipv6_flow_version='6',
        ipv6_flow_version_tracking='0',
        ipv6_traffic_class_mode='fixed',
        ipv6_traffic_class='0',
        ipv6_traffic_class_tracking='0',
        ipv6_flow_label_mode='fixed',
        ipv6_flow_label='0',
        ipv6_flow_label_tracking='0',
        ipv6_hop_limit_mode='fixed',
        ipv6_hop_limit='64',
        ipv6_hop_limit_tracking='0',
        ipv6_src_mode='increment',
        ipv6_src_addr='5:0:0:0:0:0:1:c',
        ipv6_src_step='0:0:0:0:0:0:1:0',
        ipv6_src_count='16',
        ipv6_src_tracking='0',
        ipv6_dst_mode='increment',
        ipv6_dst_addr='5:0:0:0:0:0:1:70',
        ipv6_dst_step='0:0:0:0:0:0:1:0',
        ipv6_dst_count='16',
        ipv6_dst_tracking='0',
        track_by='none',
        egress_tracking='none'    
    )
    # Check status
    if _result_['status'] != IxiaHlt.SUCCESS:
    	ixnHLT_errorHandler('traffic_config', _result_)
    
    #  -- Post Options
    ixnHLT_logger('Configuring post options for config elem: //traffic/trafficItem:<23>/configElement:<1>')
    _result_ = ixiahlt.traffic_config(
        mode='modify',
        traffic_generator='ixnetwork_540',
        stream_id=config_elements[0],
        transmit_distribution='none'    
    )
    # Check status
    if _result_['status'] != IxiaHlt.SUCCESS:
    	ixnHLT_errorHandler('traffic_config', _result_)
    
    #  -- Traffic item//traffic/trafficItem:<24>
    ixnHLT_logger('Configuring traffic for traffic item: //traffic/trafficItem:<24>')
    
    ti_srcs, ti_dsts = {}, {}
    ti_mcast_rcvr_handle, ti_mcast_rcvr_port_index, ti_mcast_rcvr_host_index, ti_mcast_rcvr_mcast_index = {}, {}, {}, {}
    
    ti_srcs['EndpointSet-1'] = ixnHLT_endpointMatch(ixnHLT, ['//vport:<4>'], 'PORT-HANDLE')
    if len(ti_srcs) == 0:
        match_err = {'log': 'Cannot find any src endpoints for EndpointSet-1'}
        ixnHLT_errorHandler('ixnHLT_endpointMatch', match_err)
    
    ti_dsts['EndpointSet-1'] = ixnHLT_endpointMatch(ixnHLT, ['//vport:<4>'], 'PORT-HANDLE')
    if len(ti_dsts) == 0:
        match_err = {'log': 'Cannot find any dst endpoints for elem EndpointSet-1'}
        ixnHLT_errorHandler('ixnHLT_endpointMatch', match_err)
    
    
    _result_ = ixiahlt.traffic_config(
        mode='create',
        traffic_generator='ixnetwork_540',
        endpointset_count=1,
        emulation_src_handle=[[ti_srcs['EndpointSet-1']]],
        emulation_dst_handle=[[ti_dsts['EndpointSet-1']]],
        emulation_multicast_dst_handle=[[]],
        emulation_multicast_dst_handle_type=[[]],
        global_dest_mac_retry_count='1',
        global_dest_mac_retry_delay='5',
        enable_data_integrity='1',
        global_enable_dest_mac_retry='1',
        global_enable_min_frame_size='0',
        global_enable_staggered_transmit='0',
        global_enable_stream_ordering='0',
        global_stream_control='continuous',
        global_stream_control_iterations='1',
        global_large_error_threshhold='2',
        global_enable_mac_change_on_fly='0',
        global_max_traffic_generation_queries='500',
        global_mpls_label_learning_timeout='30',
        global_refresh_learned_info_before_apply='0',
        global_use_tx_rx_sync='1',
        global_wait_time='1',
        global_display_mpls_current_label_value='0',
        global_detect_misdirected_packets='0',
        global_frame_ordering='none',
        frame_sequencing='disable',
        frame_sequencing_mode='rx_threshold',
        src_dest_mesh='one_to_one',
        route_mesh='one_to_one',
        bidirectional='0',
        allow_self_destined='1',
        use_cp_rate='1',
        use_cp_size='1',
        enable_dynamic_mpls_labels='0',
        hosts_per_net='1',
        name='TI23-HLTAPI_TRAFFICITEM_540',
        source_filter='all',
        destination_filter='all',
        tag_filter=[[]],
        merge_destinations='1',
        circuit_type='raw',
        pending_operations_timeout='30'    
    )
    # Check status
    if _result_['status'] != IxiaHlt.SUCCESS:
    	ixnHLT_errorHandler('traffic_config', _result_)
    
    #  -- All current config elements
    config_elements = ixiatcl.convert_tcl_list(_result_['traffic_item'])
    
    #  -- Config Element //traffic/trafficItem:<24>/configElement:<1>
    ixnHLT_logger('Configuring options for config elem: //traffic/trafficItem:<24>/configElement:<1>')
    _result_ = ixiahlt.traffic_config(
        mode='modify',
        traffic_generator='ixnetwork_540',
        stream_id=config_elements[0],
        preamble_size_mode='auto',
        preamble_custom_size='8',
        data_pattern='',
        data_pattern_mode='incr_byte',
        enforce_min_gap='0',
        rate_pps='200000',
        frame_rate_distribution_port='split_evenly',
        frame_rate_distribution_stream='split_evenly',
        frame_size='64',
        length_mode='fixed',
        tx_mode='advanced',
        transmit_mode='continuous',
        pkts_per_burst='1',
        tx_delay='0',
        tx_delay_unit='bytes',
        number_of_packets_per_stream='1',
        loop_count='1',
        min_gap_bytes='12'    
    )
    # Check status
    if _result_['status'] != IxiaHlt.SUCCESS:
    	ixnHLT_errorHandler('traffic_config', _result_)
    
    #  -- Endpoint set EndpointSet-1
    ixnHLT_logger('Configuring traffic for config elem: //traffic/trafficItem:<24>/configElement:<1>')
    ixnHLT_logger('Configuring traffic for endpoint set: EndpointSet-1')
    #  -- Stack //traffic/trafficItem:<24>/configElement:<1>/stack:"ethernet-1"
    _result_ = ixiahlt.traffic_config(
        mode='modify_or_insert',
        traffic_generator='ixnetwork_540',
        stream_id=config_elements[0],
        stack_index='1',
        l2_encap='ethernet_ii',
        mac_dst_mode='increment',
        mac_dst_tracking='0',
        mac_dst='00:12:60:60:00:02',
        mac_dst_step='00:00:00:00:00:01',
        mac_dst_count='16',
        mac_src_mode='increment',
        mac_src_tracking='0',
        mac_src='00:13:60:60:00:02',
        mac_src_step='00:00:00:00:00:01',
        mac_src_count='16'    
    )
    # Check status
    if _result_['status'] != IxiaHlt.SUCCESS:
    	ixnHLT_errorHandler('traffic_config', _result_)
    
    #  -- Stack //traffic/trafficItem:<24>/configElement:<1>/stack:"ipv6-2"
    _result_ = ixiahlt.traffic_config(
        mode='modify_or_insert',
        traffic_generator='ixnetwork_540',
        stream_id=config_elements[0],
        stack_index='2',
        l3_protocol='ipv6',
        ipv6_flow_version_mode='fixed',
        ipv6_flow_version='6',
        ipv6_flow_version_tracking='0',
        ipv6_traffic_class_mode='fixed',
        ipv6_traffic_class='0',
        ipv6_traffic_class_tracking='0',
        ipv6_flow_label_mode='fixed',
        ipv6_flow_label='0',
        ipv6_flow_label_tracking='0',
        ipv6_hop_limit_mode='fixed',
        ipv6_hop_limit='64',
        ipv6_hop_limit_tracking='0',
        ipv6_src_mode='increment',
        ipv6_src_addr='5:0:0:0:0:0:1:70',
        ipv6_src_step='0:0:0:0:0:0:1:0',
        ipv6_src_count='16',
        ipv6_src_tracking='0',
        ipv6_dst_mode='increment',
        ipv6_dst_addr='5:0:0:0:0:0:1:c',
        ipv6_dst_step='0:0:0:0:0:0:1:0',
        ipv6_dst_count='16',
        ipv6_dst_tracking='0',
        track_by='none',
        egress_tracking='none'    
    )
    # Check status
    if _result_['status'] != IxiaHlt.SUCCESS:
    	ixnHLT_errorHandler('traffic_config', _result_)
    
    #  -- Post Options
    ixnHLT_logger('Configuring post options for config elem: //traffic/trafficItem:<24>/configElement:<1>')
    _result_ = ixiahlt.traffic_config(
        mode='modify',
        traffic_generator='ixnetwork_540',
        stream_id=config_elements[0],
        transmit_distribution='none'    
    )
    # Check status
    if _result_['status'] != IxiaHlt.SUCCESS:
    	ixnHLT_errorHandler('traffic_config', _result_)
    
    #  -- Traffic item//traffic/trafficItem:<2>
    ixnHLT_logger('Configuring traffic for traffic item: //traffic/trafficItem:<2>')
    
    ti_srcs, ti_dsts = {}, {}
    ti_mcast_rcvr_handle, ti_mcast_rcvr_port_index, ti_mcast_rcvr_host_index, ti_mcast_rcvr_mcast_index = {}, {}, {}, {}
    
    ti_srcs['EndpointSet-1'] = ixnHLT_endpointMatch(ixnHLT, ['//vport:<4>'], 'PORT-HANDLE')
    if len(ti_srcs) == 0:
        match_err = {'log': 'Cannot find any src endpoints for EndpointSet-1'}
        ixnHLT_errorHandler('ixnHLT_endpointMatch', match_err)
    
    ti_dsts['EndpointSet-1'] = ixnHLT_endpointMatch(ixnHLT, ['//vport:<4>'], 'PORT-HANDLE')
    if len(ti_dsts) == 0:
        match_err = {'log': 'Cannot find any dst endpoints for elem EndpointSet-1'}
        ixnHLT_errorHandler('ixnHLT_endpointMatch', match_err)
    
    
    _result_ = ixiahlt.traffic_config(
        mode='create',
        traffic_generator='ixnetwork_540',
        endpointset_count=1,
        emulation_src_handle=[[ti_srcs['EndpointSet-1']]],
        emulation_dst_handle=[[ti_dsts['EndpointSet-1']]],
        emulation_multicast_dst_handle=[[]],
        emulation_multicast_dst_handle_type=[[]],
        global_dest_mac_retry_count='1',
        global_dest_mac_retry_delay='5',
        enable_data_integrity='1',
        global_enable_dest_mac_retry='1',
        global_enable_min_frame_size='0',
        global_enable_staggered_transmit='0',
        global_enable_stream_ordering='0',
        global_stream_control='continuous',
        global_stream_control_iterations='1',
        global_large_error_threshhold='2',
        global_enable_mac_change_on_fly='0',
        global_max_traffic_generation_queries='500',
        global_mpls_label_learning_timeout='30',
        global_refresh_learned_info_before_apply='0',
        global_use_tx_rx_sync='1',
        global_wait_time='1',
        global_display_mpls_current_label_value='0',
        global_detect_misdirected_packets='0',
        global_frame_ordering='none',
        frame_sequencing='disable',
        frame_sequencing_mode='rx_threshold',
        src_dest_mesh='one_to_one',
        route_mesh='one_to_one',
        bidirectional='0',
        allow_self_destined='1',
        use_cp_rate='1',
        use_cp_size='1',
        enable_dynamic_mpls_labels='0',
        hosts_per_net='1',
        name='TI1-HLTAPI_TRAFFICITEM_540',
        source_filter='all',
        destination_filter='all',
        tag_filter=[[]],
        merge_destinations='1',
        circuit_type='raw',
        pending_operations_timeout='30'    
    )
    # Check status
    if _result_['status'] != IxiaHlt.SUCCESS:
    	ixnHLT_errorHandler('traffic_config', _result_)
    
    #  -- All current config elements
    config_elements = ixiatcl.convert_tcl_list(_result_['traffic_item'])
    
    #  -- Config Element //traffic/trafficItem:<2>/configElement:<1>
    ixnHLT_logger('Configuring options for config elem: //traffic/trafficItem:<2>/configElement:<1>')
    _result_ = ixiahlt.traffic_config(
        mode='modify',
        traffic_generator='ixnetwork_540',
        stream_id=config_elements[0],
        preamble_size_mode='auto',
        preamble_custom_size='8',
        data_pattern='',
        data_pattern_mode='incr_byte',
        enforce_min_gap='0',
        rate_pps='200000',
        frame_rate_distribution_port='split_evenly',
        frame_rate_distribution_stream='split_evenly',
        frame_size='64',
        length_mode='fixed',
        tx_mode='advanced',
        transmit_mode='continuous',
        pkts_per_burst='1',
        tx_delay='0',
        tx_delay_unit='bytes',
        number_of_packets_per_stream='1',
        loop_count='1',
        min_gap_bytes='12'    
    )
    # Check status
    if _result_['status'] != IxiaHlt.SUCCESS:
    	ixnHLT_errorHandler('traffic_config', _result_)
    
    #  -- Endpoint set EndpointSet-1
    ixnHLT_logger('Configuring traffic for config elem: //traffic/trafficItem:<2>/configElement:<1>')
    ixnHLT_logger('Configuring traffic for endpoint set: EndpointSet-1')
    #  -- Stack //traffic/trafficItem:<2>/configElement:<1>/stack:"ethernet-1"
    _result_ = ixiahlt.traffic_config(
        mode='modify_or_insert',
        traffic_generator='ixnetwork_540',
        stream_id=config_elements[0],
        stack_index='1',
        l2_encap='ethernet_ii',
        mac_dst_mode='fixed',
        mac_dst_tracking='0',
        mac_dst='ff:ff:ff:ff:ff:ff',
        mac_src_mode='increment',
        mac_src_tracking='0',
        mac_src='00:3e:60:26:43:02',
        mac_src_step='00:00:00:00:00:00',
        mac_src_count='16'    
    )
    # Check status
    if _result_['status'] != IxiaHlt.SUCCESS:
    	ixnHLT_errorHandler('traffic_config', _result_)
    
    #  -- Stack //traffic/trafficItem:<2>/configElement:<1>/stack:"ipv4-2"
    _result_ = ixiahlt.traffic_config(
        mode='modify_or_insert',
        traffic_generator='ixnetwork_540',
        stream_id=config_elements[0],
        stack_index='2',
        l3_protocol='ipv4',
        qos_type_ixn='tos',
        ip_precedence_mode='fixed',
        ip_precedence='0',
        ip_precedence_tracking='0',
        ip_delay_mode='fixed',
        ip_delay='0',
        ip_delay_tracking='0',
        ip_throughput_mode='fixed',
        ip_throughput='0',
        ip_throughput_tracking='0',
        ip_reliability_mode='fixed',
        ip_reliability='0',
        ip_reliability_tracking='0',
        ip_cost_mode='fixed',
        ip_cost='0',
        ip_cost_tracking='0',
        ip_cu_mode='fixed',
        ip_cu='0',
        ip_cu_tracking='0',
        ip_id_mode='fixed',
        ip_id='0',
        ip_id_tracking='0',
        ip_reserved_mode='fixed',
        ip_reserved='0',
        ip_reserved_tracking='0',
        ip_fragment_mode='fixed',
        ip_fragment='1',
        ip_fragment_tracking='0',
        ip_fragment_last_mode='fixed',
        ip_fragment_last='1',
        ip_fragment_last_tracking='0',
        ip_fragment_offset_mode='fixed',
        ip_fragment_offset='0',
        ip_fragment_offset_tracking='0',
        ip_ttl_mode='fixed',
        ip_ttl='64',
        ip_ttl_tracking='0',
        track_by='none',
        egress_tracking='none'    
    )
    # Check status
    if _result_['status'] != IxiaHlt.SUCCESS:
    	ixnHLT_errorHandler('traffic_config', _result_)
    
    #  -- Post Options
    ixnHLT_logger('Configuring post options for config elem: //traffic/trafficItem:<2>/configElement:<1>')
    _result_ = ixiahlt.traffic_config(
        mode='modify',
        traffic_generator='ixnetwork_540',
        stream_id=config_elements[0],
        transmit_distribution='none'    
    )
    # Check status
    if _result_['status'] != IxiaHlt.SUCCESS:
    	ixnHLT_errorHandler('traffic_config', _result_)
    
    #  -- Traffic item//traffic/trafficItem:<3>
    ixnHLT_logger('Configuring traffic for traffic item: //traffic/trafficItem:<3>')
    
    ti_srcs, ti_dsts = {}, {}
    ti_mcast_rcvr_handle, ti_mcast_rcvr_port_index, ti_mcast_rcvr_host_index, ti_mcast_rcvr_mcast_index = {}, {}, {}, {}
    
    ti_srcs['EndpointSet-1'] = ixnHLT_endpointMatch(ixnHLT, ['//vport:<1>'], 'PORT-HANDLE')
    if len(ti_srcs) == 0:
        match_err = {'log': 'Cannot find any src endpoints for EndpointSet-1'}
        ixnHLT_errorHandler('ixnHLT_endpointMatch', match_err)
    
    ti_dsts['EndpointSet-1'] = ixnHLT_endpointMatch(ixnHLT, ['//vport:<1>'], 'PORT-HANDLE')
    if len(ti_dsts) == 0:
        match_err = {'log': 'Cannot find any dst endpoints for elem EndpointSet-1'}
        ixnHLT_errorHandler('ixnHLT_endpointMatch', match_err)
    
    
    _result_ = ixiahlt.traffic_config(
        mode='create',
        traffic_generator='ixnetwork_540',
        endpointset_count=1,
        emulation_src_handle=[[ti_srcs['EndpointSet-1']]],
        emulation_dst_handle=[[ti_dsts['EndpointSet-1']]],
        emulation_multicast_dst_handle=[[]],
        emulation_multicast_dst_handle_type=[[]],
        global_dest_mac_retry_count='1',
        global_dest_mac_retry_delay='5',
        enable_data_integrity='1',
        global_enable_dest_mac_retry='1',
        global_enable_min_frame_size='0',
        global_enable_staggered_transmit='0',
        global_enable_stream_ordering='0',
        global_stream_control='continuous',
        global_stream_control_iterations='1',
        global_large_error_threshhold='2',
        global_enable_mac_change_on_fly='0',
        global_max_traffic_generation_queries='500',
        global_mpls_label_learning_timeout='30',
        global_refresh_learned_info_before_apply='0',
        global_use_tx_rx_sync='1',
        global_wait_time='1',
        global_display_mpls_current_label_value='0',
        global_detect_misdirected_packets='0',
        global_frame_ordering='none',
        frame_sequencing='disable',
        frame_sequencing_mode='rx_threshold',
        src_dest_mesh='one_to_one',
        route_mesh='one_to_one',
        bidirectional='0',
        allow_self_destined='1',
        use_cp_rate='1',
        use_cp_size='1',
        enable_dynamic_mpls_labels='0',
        hosts_per_net='1',
        name='TI2-HLTAPI_TRAFFICITEM_540',
        source_filter='all',
        destination_filter='all',
        tag_filter=[[]],
        merge_destinations='1',
        circuit_type='raw',
        pending_operations_timeout='30'    
    )
    # Check status
    if _result_['status'] != IxiaHlt.SUCCESS:
    	ixnHLT_errorHandler('traffic_config', _result_)
    
    #  -- All current config elements
    config_elements = ixiatcl.convert_tcl_list(_result_['traffic_item'])
    
    #  -- Config Element //traffic/trafficItem:<3>/configElement:<1>
    ixnHLT_logger('Configuring options for config elem: //traffic/trafficItem:<3>/configElement:<1>')
    _result_ = ixiahlt.traffic_config(
        mode='modify',
        traffic_generator='ixnetwork_540',
        stream_id=config_elements[0],
        preamble_size_mode='auto',
        preamble_custom_size='8',
        data_pattern='',
        data_pattern_mode='incr_byte',
        enforce_min_gap='0',
        rate_pps='200000',
        frame_rate_distribution_port='split_evenly',
        frame_rate_distribution_stream='split_evenly',
        frame_size='64',
        length_mode='fixed',
        tx_mode='advanced',
        transmit_mode='continuous',
        pkts_per_burst='1',
        tx_delay='0',
        tx_delay_unit='bytes',
        number_of_packets_per_stream='1',
        loop_count='1',
        min_gap_bytes='12'    
    )
    # Check status
    if _result_['status'] != IxiaHlt.SUCCESS:
    	ixnHLT_errorHandler('traffic_config', _result_)
    
    #  -- Endpoint set EndpointSet-1
    ixnHLT_logger('Configuring traffic for config elem: //traffic/trafficItem:<3>/configElement:<1>')
    ixnHLT_logger('Configuring traffic for endpoint set: EndpointSet-1')
    #  -- Stack //traffic/trafficItem:<3>/configElement:<1>/stack:"ethernet-1"
    _result_ = ixiahlt.traffic_config(
        mode='modify_or_insert',
        traffic_generator='ixnetwork_540',
        stream_id=config_elements[0],
        stack_index='1',
        l2_encap='ethernet_ii',
        mac_dst_mode='fixed',
        mac_dst_tracking='0',
        mac_dst='01:00:5e:00:00:01',
        mac_src_mode='increment',
        mac_src_tracking='0',
        mac_src='00:5b:3b:1b:36:02',
        mac_src_step='00:00:00:00:00:00',
        mac_src_count='16'    
    )
    # Check status
    if _result_['status'] != IxiaHlt.SUCCESS:
    	ixnHLT_errorHandler('traffic_config', _result_)
    
    #  -- Stack //traffic/trafficItem:<3>/configElement:<1>/stack:"ipv4-2"
    _result_ = ixiahlt.traffic_config(
        mode='modify_or_insert',
        traffic_generator='ixnetwork_540',
        stream_id=config_elements[0],
        stack_index='2',
        l3_protocol='ipv4',
        qos_type_ixn='tos',
        ip_precedence_mode='fixed',
        ip_precedence='0',
        ip_precedence_tracking='0',
        ip_delay_mode='fixed',
        ip_delay='0',
        ip_delay_tracking='0',
        ip_throughput_mode='fixed',
        ip_throughput='0',
        ip_throughput_tracking='0',
        ip_reliability_mode='fixed',
        ip_reliability='0',
        ip_reliability_tracking='0',
        ip_cost_mode='fixed',
        ip_cost='0',
        ip_cost_tracking='0',
        ip_cu_mode='fixed',
        ip_cu='0',
        ip_cu_tracking='0',
        ip_id_mode='fixed',
        ip_id='0',
        ip_id_tracking='0',
        ip_reserved_mode='fixed',
        ip_reserved='0',
        ip_reserved_tracking='0',
        ip_fragment_mode='fixed',
        ip_fragment='1',
        ip_fragment_tracking='0',
        ip_fragment_last_mode='fixed',
        ip_fragment_last='1',
        ip_fragment_last_tracking='0',
        ip_fragment_offset_mode='fixed',
        ip_fragment_offset='0',
        ip_fragment_offset_tracking='0',
        ip_ttl_mode='fixed',
        ip_ttl='64',
        ip_ttl_tracking='0',
        track_by='none',
        egress_tracking='none'    
    )
    # Check status
    if _result_['status'] != IxiaHlt.SUCCESS:
    	ixnHLT_errorHandler('traffic_config', _result_)
    
    #  -- Post Options
    ixnHLT_logger('Configuring post options for config elem: //traffic/trafficItem:<3>/configElement:<1>')
    _result_ = ixiahlt.traffic_config(
        mode='modify',
        traffic_generator='ixnetwork_540',
        stream_id=config_elements[0],
        transmit_distribution='none'    
    )
    # Check status
    if _result_['status'] != IxiaHlt.SUCCESS:
    	ixnHLT_errorHandler('traffic_config', _result_)
    
    #  -- Traffic item//traffic/trafficItem:<4>
    ixnHLT_logger('Configuring traffic for traffic item: //traffic/trafficItem:<4>')
    
    ti_srcs, ti_dsts = {}, {}
    ti_mcast_rcvr_handle, ti_mcast_rcvr_port_index, ti_mcast_rcvr_host_index, ti_mcast_rcvr_mcast_index = {}, {}, {}, {}
    
    ti_srcs['EndpointSet-1'] = ixnHLT_endpointMatch(ixnHLT, ['//vport:<4>'], 'PORT-HANDLE')
    if len(ti_srcs) == 0:
        match_err = {'log': 'Cannot find any src endpoints for EndpointSet-1'}
        ixnHLT_errorHandler('ixnHLT_endpointMatch', match_err)
    
    ti_dsts['EndpointSet-1'] = ixnHLT_endpointMatch(ixnHLT, ['//vport:<4>'], 'PORT-HANDLE')
    if len(ti_dsts) == 0:
        match_err = {'log': 'Cannot find any dst endpoints for elem EndpointSet-1'}
        ixnHLT_errorHandler('ixnHLT_endpointMatch', match_err)
    
    
    _result_ = ixiahlt.traffic_config(
        mode='create',
        traffic_generator='ixnetwork_540',
        endpointset_count=1,
        emulation_src_handle=[[ti_srcs['EndpointSet-1']]],
        emulation_dst_handle=[[ti_dsts['EndpointSet-1']]],
        emulation_multicast_dst_handle=[[]],
        emulation_multicast_dst_handle_type=[[]],
        global_dest_mac_retry_count='1',
        global_dest_mac_retry_delay='5',
        enable_data_integrity='1',
        global_enable_dest_mac_retry='1',
        global_enable_min_frame_size='0',
        global_enable_staggered_transmit='0',
        global_enable_stream_ordering='0',
        global_stream_control='continuous',
        global_stream_control_iterations='1',
        global_large_error_threshhold='2',
        global_enable_mac_change_on_fly='0',
        global_max_traffic_generation_queries='500',
        global_mpls_label_learning_timeout='30',
        global_refresh_learned_info_before_apply='0',
        global_use_tx_rx_sync='1',
        global_wait_time='1',
        global_display_mpls_current_label_value='0',
        global_detect_misdirected_packets='0',
        global_frame_ordering='none',
        frame_sequencing='disable',
        frame_sequencing_mode='rx_threshold',
        src_dest_mesh='one_to_one',
        route_mesh='one_to_one',
        bidirectional='0',
        allow_self_destined='1',
        use_cp_rate='1',
        use_cp_size='1',
        enable_dynamic_mpls_labels='0',
        hosts_per_net='1',
        name='TI3-HLTAPI_TRAFFICITEM_540',
        source_filter='all',
        destination_filter='all',
        tag_filter=[[]],
        merge_destinations='1',
        circuit_type='raw',
        pending_operations_timeout='30'    
    )
    # Check status
    if _result_['status'] != IxiaHlt.SUCCESS:
    	ixnHLT_errorHandler('traffic_config', _result_)
    
    #  -- All current config elements
    config_elements = ixiatcl.convert_tcl_list(_result_['traffic_item'])
    
    #  -- Config Element //traffic/trafficItem:<4>/configElement:<1>
    ixnHLT_logger('Configuring options for config elem: //traffic/trafficItem:<4>/configElement:<1>')
    _result_ = ixiahlt.traffic_config(
        mode='modify',
        traffic_generator='ixnetwork_540',
        stream_id=config_elements[0],
        preamble_size_mode='auto',
        preamble_custom_size='8',
        data_pattern='',
        data_pattern_mode='incr_byte',
        enforce_min_gap='0',
        rate_pps='200000',
        frame_rate_distribution_port='split_evenly',
        frame_rate_distribution_stream='split_evenly',
        frame_size='64',
        length_mode='fixed',
        tx_mode='advanced',
        transmit_mode='continuous',
        pkts_per_burst='1',
        tx_delay='0',
        tx_delay_unit='bytes',
        number_of_packets_per_stream='1',
        loop_count='1',
        min_gap_bytes='12'    
    )
    # Check status
    if _result_['status'] != IxiaHlt.SUCCESS:
    	ixnHLT_errorHandler('traffic_config', _result_)
    
    #  -- Endpoint set EndpointSet-1
    ixnHLT_logger('Configuring traffic for config elem: //traffic/trafficItem:<4>/configElement:<1>')
    ixnHLT_logger('Configuring traffic for endpoint set: EndpointSet-1')
    #  -- Stack //traffic/trafficItem:<4>/configElement:<1>/stack:"ethernet-1"
    _result_ = ixiahlt.traffic_config(
        mode='modify_or_insert',
        traffic_generator='ixnetwork_540',
        stream_id=config_elements[0],
        stack_index='1',
        l2_encap='ethernet_ii',
        mac_dst_mode='fixed',
        mac_dst_tracking='0',
        mac_dst='01:00:5e:00:00:01',
        mac_src_mode='increment',
        mac_src_tracking='0',
        mac_src='00:5b:37:2b:20:02',
        mac_src_step='00:00:00:00:00:00',
        mac_src_count='16'    
    )
    # Check status
    if _result_['status'] != IxiaHlt.SUCCESS:
    	ixnHLT_errorHandler('traffic_config', _result_)
    
    #  -- Stack //traffic/trafficItem:<4>/configElement:<1>/stack:"ipv4-2"
    _result_ = ixiahlt.traffic_config(
        mode='modify_or_insert',
        traffic_generator='ixnetwork_540',
        stream_id=config_elements[0],
        stack_index='2',
        l3_protocol='ipv4',
        qos_type_ixn='tos',
        ip_precedence_mode='fixed',
        ip_precedence='0',
        ip_precedence_tracking='0',
        ip_delay_mode='fixed',
        ip_delay='0',
        ip_delay_tracking='0',
        ip_throughput_mode='fixed',
        ip_throughput='0',
        ip_throughput_tracking='0',
        ip_reliability_mode='fixed',
        ip_reliability='0',
        ip_reliability_tracking='0',
        ip_cost_mode='fixed',
        ip_cost='0',
        ip_cost_tracking='0',
        ip_cu_mode='fixed',
        ip_cu='0',
        ip_cu_tracking='0',
        ip_id_mode='fixed',
        ip_id='0',
        ip_id_tracking='0',
        ip_reserved_mode='fixed',
        ip_reserved='0',
        ip_reserved_tracking='0',
        ip_fragment_mode='fixed',
        ip_fragment='1',
        ip_fragment_tracking='0',
        ip_fragment_last_mode='fixed',
        ip_fragment_last='1',
        ip_fragment_last_tracking='0',
        ip_fragment_offset_mode='fixed',
        ip_fragment_offset='0',
        ip_fragment_offset_tracking='0',
        ip_ttl_mode='fixed',
        ip_ttl='64',
        ip_ttl_tracking='0',
        track_by='none',
        egress_tracking='none'    
    )
    # Check status
    if _result_['status'] != IxiaHlt.SUCCESS:
    	ixnHLT_errorHandler('traffic_config', _result_)
    
    #  -- Post Options
    ixnHLT_logger('Configuring post options for config elem: //traffic/trafficItem:<4>/configElement:<1>')
    _result_ = ixiahlt.traffic_config(
        mode='modify',
        traffic_generator='ixnetwork_540',
        stream_id=config_elements[0],
        transmit_distribution='none'    
    )
    # Check status
    if _result_['status'] != IxiaHlt.SUCCESS:
    	ixnHLT_errorHandler('traffic_config', _result_)
    
    #  -- Traffic item//traffic/trafficItem:<5>
    ixnHLT_logger('Configuring traffic for traffic item: //traffic/trafficItem:<5>')
    
    ti_srcs, ti_dsts = {}, {}
    ti_mcast_rcvr_handle, ti_mcast_rcvr_port_index, ti_mcast_rcvr_host_index, ti_mcast_rcvr_mcast_index = {}, {}, {}, {}
    
    ti_srcs['EndpointSet-1'] = ixnHLT_endpointMatch(ixnHLT, ['//vport:<1>'], 'PORT-HANDLE')
    if len(ti_srcs) == 0:
        match_err = {'log': 'Cannot find any src endpoints for EndpointSet-1'}
        ixnHLT_errorHandler('ixnHLT_endpointMatch', match_err)
    
    ti_dsts['EndpointSet-1'] = ixnHLT_endpointMatch(ixnHLT, ['//vport:<1>'], 'PORT-HANDLE')
    if len(ti_dsts) == 0:
        match_err = {'log': 'Cannot find any dst endpoints for elem EndpointSet-1'}
        ixnHLT_errorHandler('ixnHLT_endpointMatch', match_err)
    
    
    _result_ = ixiahlt.traffic_config(
        mode='create',
        traffic_generator='ixnetwork_540',
        endpointset_count=1,
        emulation_src_handle=[[ti_srcs['EndpointSet-1']]],
        emulation_dst_handle=[[ti_dsts['EndpointSet-1']]],
        emulation_multicast_dst_handle=[[]],
        emulation_multicast_dst_handle_type=[[]],
        global_dest_mac_retry_count='1',
        global_dest_mac_retry_delay='5',
        enable_data_integrity='1',
        global_enable_dest_mac_retry='1',
        global_enable_min_frame_size='0',
        global_enable_staggered_transmit='0',
        global_enable_stream_ordering='0',
        global_stream_control='continuous',
        global_stream_control_iterations='1',
        global_large_error_threshhold='2',
        global_enable_mac_change_on_fly='0',
        global_max_traffic_generation_queries='500',
        global_mpls_label_learning_timeout='30',
        global_refresh_learned_info_before_apply='0',
        global_use_tx_rx_sync='1',
        global_wait_time='1',
        global_display_mpls_current_label_value='0',
        global_detect_misdirected_packets='0',
        global_frame_ordering='none',
        frame_sequencing='disable',
        frame_sequencing_mode='rx_threshold',
        src_dest_mesh='one_to_one',
        route_mesh='one_to_one',
        bidirectional='0',
        allow_self_destined='1',
        use_cp_rate='1',
        use_cp_size='1',
        enable_dynamic_mpls_labels='0',
        hosts_per_net='1',
        name='TI4-HLTAPI_TRAFFICITEM_540',
        source_filter='all',
        destination_filter='all',
        tag_filter=[[]],
        merge_destinations='1',
        circuit_type='raw',
        pending_operations_timeout='30'    
    )
    # Check status
    if _result_['status'] != IxiaHlt.SUCCESS:
    	ixnHLT_errorHandler('traffic_config', _result_)
    
    #  -- All current config elements
    config_elements = ixiatcl.convert_tcl_list(_result_['traffic_item'])
    
    #  -- Config Element //traffic/trafficItem:<5>/configElement:<1>
    ixnHLT_logger('Configuring options for config elem: //traffic/trafficItem:<5>/configElement:<1>')
    _result_ = ixiahlt.traffic_config(
        mode='modify',
        traffic_generator='ixnetwork_540',
        stream_id=config_elements[0],
        preamble_size_mode='auto',
        preamble_custom_size='8',
        data_pattern='',
        data_pattern_mode='incr_byte',
        enforce_min_gap='0',
        rate_pps='200000',
        frame_rate_distribution_port='split_evenly',
        frame_rate_distribution_stream='split_evenly',
        frame_size='64',
        length_mode='fixed',
        tx_mode='advanced',
        transmit_mode='continuous',
        pkts_per_burst='1',
        tx_delay='0',
        tx_delay_unit='bytes',
        number_of_packets_per_stream='1',
        loop_count='1',
        min_gap_bytes='12'    
    )
    # Check status
    if _result_['status'] != IxiaHlt.SUCCESS:
    	ixnHLT_errorHandler('traffic_config', _result_)
    
    #  -- Endpoint set EndpointSet-1
    ixnHLT_logger('Configuring traffic for config elem: //traffic/trafficItem:<5>/configElement:<1>')
    ixnHLT_logger('Configuring traffic for endpoint set: EndpointSet-1')
    #  -- Stack //traffic/trafficItem:<5>/configElement:<1>/stack:"ethernet-1"
    _result_ = ixiahlt.traffic_config(
        mode='modify_or_insert',
        traffic_generator='ixnetwork_540',
        stream_id=config_elements[0],
        stack_index='1',
        l2_encap='ethernet_ii',
        mac_dst_mode='increment',
        mac_dst_tracking='0',
        mac_dst='00:13:94:bb:00:02',
        mac_dst_step='00:00:00:00:00:01',
        mac_dst_count='16',
        mac_src_mode='increment',
        mac_src_tracking='0',
        mac_src='00:12:94:aa:00:02',
        mac_src_step='00:00:00:00:00:01',
        mac_src_count='16'    
    )
    # Check status
    if _result_['status'] != IxiaHlt.SUCCESS:
    	ixnHLT_errorHandler('traffic_config', _result_)
    
    #  -- Stack //traffic/trafficItem:<5>/configElement:<1>/stack:"ipv4-2"
    _result_ = ixiahlt.traffic_config(
        mode='modify_or_insert',
        traffic_generator='ixnetwork_540',
        stream_id=config_elements[0],
        stack_index='2',
        l3_protocol='ipv4',
        qos_type_ixn='tos',
        ip_precedence_mode='fixed',
        ip_precedence='0',
        ip_precedence_tracking='0',
        ip_delay_mode='fixed',
        ip_delay='0',
        ip_delay_tracking='0',
        ip_throughput_mode='fixed',
        ip_throughput='0',
        ip_throughput_tracking='0',
        ip_reliability_mode='fixed',
        ip_reliability='0',
        ip_reliability_tracking='0',
        ip_cost_mode='fixed',
        ip_cost='0',
        ip_cost_tracking='0',
        ip_cu_mode='fixed',
        ip_cu='0',
        ip_cu_tracking='0',
        ip_id_mode='fixed',
        ip_id='0',
        ip_id_tracking='0',
        ip_reserved_mode='fixed',
        ip_reserved='0',
        ip_reserved_tracking='0',
        ip_fragment_mode='fixed',
        ip_fragment='1',
        ip_fragment_tracking='0',
        ip_fragment_last_mode='fixed',
        ip_fragment_last='1',
        ip_fragment_last_tracking='0',
        ip_fragment_offset_mode='fixed',
        ip_fragment_offset='0',
        ip_fragment_offset_tracking='0',
        ip_ttl_mode='fixed',
        ip_ttl='64',
        ip_ttl_tracking='0',
        track_by='none',
        egress_tracking='none'    
    )
    # Check status
    if _result_['status'] != IxiaHlt.SUCCESS:
    	ixnHLT_errorHandler('traffic_config', _result_)
    
    #  -- Post Options
    ixnHLT_logger('Configuring post options for config elem: //traffic/trafficItem:<5>/configElement:<1>')
    _result_ = ixiahlt.traffic_config(
        mode='modify',
        traffic_generator='ixnetwork_540',
        stream_id=config_elements[0],
        transmit_distribution='none'    
    )
    # Check status
    if _result_['status'] != IxiaHlt.SUCCESS:
    	ixnHLT_errorHandler('traffic_config', _result_)
    
    #  -- Traffic item//traffic/trafficItem:<6>
    ixnHLT_logger('Configuring traffic for traffic item: //traffic/trafficItem:<6>')
    
    ti_srcs, ti_dsts = {}, {}
    ti_mcast_rcvr_handle, ti_mcast_rcvr_port_index, ti_mcast_rcvr_host_index, ti_mcast_rcvr_mcast_index = {}, {}, {}, {}
    
    ti_srcs['EndpointSet-1'] = ixnHLT_endpointMatch(ixnHLT, ['//vport:<4>'], 'PORT-HANDLE')
    if len(ti_srcs) == 0:
        match_err = {'log': 'Cannot find any src endpoints for EndpointSet-1'}
        ixnHLT_errorHandler('ixnHLT_endpointMatch', match_err)
    
    ti_dsts['EndpointSet-1'] = ixnHLT_endpointMatch(ixnHLT, ['//vport:<4>'], 'PORT-HANDLE')
    if len(ti_dsts) == 0:
        match_err = {'log': 'Cannot find any dst endpoints for elem EndpointSet-1'}
        ixnHLT_errorHandler('ixnHLT_endpointMatch', match_err)
    
    
    _result_ = ixiahlt.traffic_config(
        mode='create',
        traffic_generator='ixnetwork_540',
        endpointset_count=1,
        emulation_src_handle=[[ti_srcs['EndpointSet-1']]],
        emulation_dst_handle=[[ti_dsts['EndpointSet-1']]],
        emulation_multicast_dst_handle=[[]],
        emulation_multicast_dst_handle_type=[[]],
        global_dest_mac_retry_count='1',
        global_dest_mac_retry_delay='5',
        enable_data_integrity='1',
        global_enable_dest_mac_retry='1',
        global_enable_min_frame_size='0',
        global_enable_staggered_transmit='0',
        global_enable_stream_ordering='0',
        global_stream_control='continuous',
        global_stream_control_iterations='1',
        global_large_error_threshhold='2',
        global_enable_mac_change_on_fly='0',
        global_max_traffic_generation_queries='500',
        global_mpls_label_learning_timeout='30',
        global_refresh_learned_info_before_apply='0',
        global_use_tx_rx_sync='1',
        global_wait_time='1',
        global_display_mpls_current_label_value='0',
        global_detect_misdirected_packets='0',
        global_frame_ordering='none',
        frame_sequencing='disable',
        frame_sequencing_mode='rx_threshold',
        src_dest_mesh='one_to_one',
        route_mesh='one_to_one',
        bidirectional='0',
        allow_self_destined='1',
        use_cp_rate='1',
        use_cp_size='1',
        enable_dynamic_mpls_labels='0',
        hosts_per_net='1',
        name='TI5-HLTAPI_TRAFFICITEM_540',
        source_filter='all',
        destination_filter='all',
        tag_filter=[[]],
        merge_destinations='1',
        circuit_type='raw',
        pending_operations_timeout='30'    
    )
    # Check status
    if _result_['status'] != IxiaHlt.SUCCESS:
    	ixnHLT_errorHandler('traffic_config', _result_)
    
    #  -- All current config elements
    config_elements = ixiatcl.convert_tcl_list(_result_['traffic_item'])
    
    #  -- Config Element //traffic/trafficItem:<6>/configElement:<1>
    ixnHLT_logger('Configuring options for config elem: //traffic/trafficItem:<6>/configElement:<1>')
    _result_ = ixiahlt.traffic_config(
        mode='modify',
        traffic_generator='ixnetwork_540',
        stream_id=config_elements[0],
        preamble_size_mode='auto',
        preamble_custom_size='8',
        data_pattern='',
        data_pattern_mode='incr_byte',
        enforce_min_gap='0',
        rate_pps='200000',
        frame_rate_distribution_port='split_evenly',
        frame_rate_distribution_stream='split_evenly',
        frame_size='64',
        length_mode='fixed',
        tx_mode='advanced',
        transmit_mode='continuous',
        pkts_per_burst='1',
        tx_delay='0',
        tx_delay_unit='bytes',
        number_of_packets_per_stream='1',
        loop_count='1',
        min_gap_bytes='12'    
    )
    # Check status
    if _result_['status'] != IxiaHlt.SUCCESS:
    	ixnHLT_errorHandler('traffic_config', _result_)
    
    #  -- Endpoint set EndpointSet-1
    ixnHLT_logger('Configuring traffic for config elem: //traffic/trafficItem:<6>/configElement:<1>')
    ixnHLT_logger('Configuring traffic for endpoint set: EndpointSet-1')
    #  -- Stack //traffic/trafficItem:<6>/configElement:<1>/stack:"ethernet-1"
    _result_ = ixiahlt.traffic_config(
        mode='modify_or_insert',
        traffic_generator='ixnetwork_540',
        stream_id=config_elements[0],
        stack_index='1',
        l2_encap='ethernet_ii',
        mac_dst_mode='increment',
        mac_dst_tracking='0',
        mac_dst='00:12:94:aa:00:02',
        mac_dst_step='00:00:00:00:00:01',
        mac_dst_count='16',
        mac_src_mode='increment',
        mac_src_tracking='0',
        mac_src='00:13:94:bb:00:02',
        mac_src_step='00:00:00:00:00:01',
        mac_src_count='16'    
    )
    # Check status
    if _result_['status'] != IxiaHlt.SUCCESS:
    	ixnHLT_errorHandler('traffic_config', _result_)
    
    #  -- Stack //traffic/trafficItem:<6>/configElement:<1>/stack:"ipv4-2"
    _result_ = ixiahlt.traffic_config(
        mode='modify_or_insert',
        traffic_generator='ixnetwork_540',
        stream_id=config_elements[0],
        stack_index='2',
        l3_protocol='ipv4',
        qos_type_ixn='tos',
        ip_precedence_mode='fixed',
        ip_precedence='0',
        ip_precedence_tracking='0',
        ip_delay_mode='fixed',
        ip_delay='0',
        ip_delay_tracking='0',
        ip_throughput_mode='fixed',
        ip_throughput='0',
        ip_throughput_tracking='0',
        ip_reliability_mode='fixed',
        ip_reliability='0',
        ip_reliability_tracking='0',
        ip_cost_mode='fixed',
        ip_cost='0',
        ip_cost_tracking='0',
        ip_cu_mode='fixed',
        ip_cu='0',
        ip_cu_tracking='0',
        ip_id_mode='fixed',
        ip_id='0',
        ip_id_tracking='0',
        ip_reserved_mode='fixed',
        ip_reserved='0',
        ip_reserved_tracking='0',
        ip_fragment_mode='fixed',
        ip_fragment='1',
        ip_fragment_tracking='0',
        ip_fragment_last_mode='fixed',
        ip_fragment_last='1',
        ip_fragment_last_tracking='0',
        ip_fragment_offset_mode='fixed',
        ip_fragment_offset='0',
        ip_fragment_offset_tracking='0',
        ip_ttl_mode='fixed',
        ip_ttl='64',
        ip_ttl_tracking='0',
        track_by='none',
        egress_tracking='none'    
    )
    # Check status
    if _result_['status'] != IxiaHlt.SUCCESS:
    	ixnHLT_errorHandler('traffic_config', _result_)
    
    #  -- Post Options
    ixnHLT_logger('Configuring post options for config elem: //traffic/trafficItem:<6>/configElement:<1>')
    _result_ = ixiahlt.traffic_config(
        mode='modify',
        traffic_generator='ixnetwork_540',
        stream_id=config_elements[0],
        transmit_distribution='none'    
    )
    # Check status
    if _result_['status'] != IxiaHlt.SUCCESS:
    	ixnHLT_errorHandler('traffic_config', _result_)
    
    #  -- Traffic item//traffic/trafficItem:<7>
    ixnHLT_logger('Configuring traffic for traffic item: //traffic/trafficItem:<7>')
    
    ti_srcs, ti_dsts = {}, {}
    ti_mcast_rcvr_handle, ti_mcast_rcvr_port_index, ti_mcast_rcvr_host_index, ti_mcast_rcvr_mcast_index = {}, {}, {}, {}
    
    ti_srcs['EndpointSet-1'] = '::ixNet::OBJ-/vport:1/interface:1'
    ti_dsts['EndpointSet-1'] = '::ixNet::OBJ-/vport:4/interface:1'
    
    _result_ = ixiahlt.traffic_config(
        mode='create',
        traffic_generator='ixnetwork_540',
        endpointset_count=1,
        emulation_src_handle=[[ti_srcs['EndpointSet-1']]],
        emulation_dst_handle=[[ti_dsts['EndpointSet-1']]],
        emulation_multicast_dst_handle=[[]],
        emulation_multicast_dst_handle_type=[[]],
        global_dest_mac_retry_count='1',
        global_dest_mac_retry_delay='5',
        enable_data_integrity='1',
        global_enable_dest_mac_retry='1',
        global_enable_min_frame_size='0',
        global_enable_staggered_transmit='0',
        global_enable_stream_ordering='0',
        global_stream_control='continuous',
        global_stream_control_iterations='1',
        global_large_error_threshhold='2',
        global_enable_mac_change_on_fly='0',
        global_max_traffic_generation_queries='500',
        global_mpls_label_learning_timeout='30',
        global_refresh_learned_info_before_apply='0',
        global_use_tx_rx_sync='1',
        global_wait_time='1',
        global_display_mpls_current_label_value='0',
        global_detect_misdirected_packets='0',
        global_frame_ordering='none',
        frame_sequencing='disable',
        frame_sequencing_mode='rx_threshold',
        src_dest_mesh='one_to_one',
        route_mesh='one_to_one',
        bidirectional='1',
        allow_self_destined='0',
        use_cp_rate='1',
        use_cp_size='1',
        enable_dynamic_mpls_labels='0',
        hosts_per_net='1',
        name='TI6-HLTAPI_TRAFFICITEM_540',
        source_filter='all',
        destination_filter='all',
        tag_filter=[[]],
        merge_destinations='0',
        circuit_endpoint_type='ipv4',
        pending_operations_timeout='30'    
    )
    # Check status
    if _result_['status'] != IxiaHlt.SUCCESS:
    	ixnHLT_errorHandler('traffic_config', _result_)
    
    #  -- All current config elements
    config_elements = ixiatcl.convert_tcl_list(_result_['traffic_item'])
    
    #  -- Config Element //traffic/trafficItem:<7>/configElement:<1>
    ixnHLT_logger('Configuring options for config elem: //traffic/trafficItem:<7>/configElement:<1>')
    _result_ = ixiahlt.traffic_config(
        mode='modify',
        traffic_generator='ixnetwork_540',
        stream_id=config_elements[0],
        preamble_size_mode='auto',
        preamble_custom_size='8',
        data_pattern='',
        data_pattern_mode='incr_byte',
        enforce_min_gap='0',
        rate_pps='12500',
        frame_rate_distribution_port='split_evenly',
        frame_rate_distribution_stream='split_evenly',
        frame_size='64',
        length_mode='fixed',
        tx_mode='advanced',
        transmit_mode='continuous',
        pkts_per_burst='1',
        tx_delay='0',
        tx_delay_unit='bytes',
        number_of_packets_per_stream='1',
        loop_count='1',
        min_gap_bytes='12'    
    )
    # Check status
    if _result_['status'] != IxiaHlt.SUCCESS:
    	ixnHLT_errorHandler('traffic_config', _result_)
    
    #  -- Endpoint set EndpointSet-1
    ixnHLT_logger('Configuring traffic for config elem: //traffic/trafficItem:<7>/configElement:<1>')
    ixnHLT_logger('Configuring traffic for endpoint set: EndpointSet-1')
    #  -- Stack //traffic/trafficItem:<7>/configElement:<1>/stack:"ethernet-1"
    _result_ = ixiahlt.traffic_config(
        mode='modify_or_insert',
        traffic_generator='ixnetwork_540',
        stream_id=config_elements[0],
        stack_index='1',
        l2_encap='ethernet_ii',
        mac_dst_mode='fixed',
        mac_dst_tracking='0',
        mac_dst='00:00:00:00:00:00',
        mac_src_mode='fixed',
        mac_src_tracking='0',
        mac_src='00:00:00:00:00:00',
        ethernet_value_mode='fixed',
        ethernet_value='ffff',
        ethernet_value_tracking='0'    
    )
    # Check status
    if _result_['status'] != IxiaHlt.SUCCESS:
    	ixnHLT_errorHandler('traffic_config', _result_)
    
    #  -- Stack //traffic/trafficItem:<7>/configElement:<1>/stack:"vlan-2"
    _result_ = ixiahlt.traffic_config(
        mode='modify_or_insert',
        traffic_generator='ixnetwork_540',
        stream_id=config_elements[0],
        stack_index='2',
        vlan='enable',
        vlan_user_priority_mode='fixed',
        vlan_user_priority='0',
        vlan_user_priority_tracking='0',
        vlan_cfi_mode='fixed',
        vlan_cfi='0',
        vlan_cfi_tracking='0',
        vlan_id_mode='fixed',
        vlan_id='0',
        vlan_id_tracking='0'    
    )
    # Check status
    if _result_['status'] != IxiaHlt.SUCCESS:
    	ixnHLT_errorHandler('traffic_config', _result_)
    
    #  -- Stack //traffic/trafficItem:<7>/configElement:<1>/stack:"ipv4-3"
    _result_ = ixiahlt.traffic_config(
        mode='modify_or_insert',
        traffic_generator='ixnetwork_540',
        stream_id=config_elements[0],
        stack_index='3',
        l3_protocol='ipv4',
        qos_type_ixn='tos',
        ip_precedence_mode='fixed',
        ip_precedence='0',
        ip_precedence_tracking='0',
        ip_delay_mode='fixed',
        ip_delay='0',
        ip_delay_tracking='0',
        ip_throughput_mode='fixed',
        ip_throughput='0',
        ip_throughput_tracking='0',
        ip_reliability_mode='fixed',
        ip_reliability='0',
        ip_reliability_tracking='0',
        ip_cost_mode='fixed',
        ip_cost='0',
        ip_cost_tracking='0',
        ip_cu_mode='fixed',
        ip_cu='0',
        ip_cu_tracking='0',
        ip_id_mode='fixed',
        ip_id='0',
        ip_id_tracking='0',
        ip_reserved_mode='fixed',
        ip_reserved='0',
        ip_reserved_tracking='0',
        ip_fragment_mode='fixed',
        ip_fragment='1',
        ip_fragment_tracking='0',
        ip_fragment_last_mode='fixed',
        ip_fragment_last='1',
        ip_fragment_last_tracking='0',
        ip_fragment_offset_mode='fixed',
        ip_fragment_offset='0',
        ip_fragment_offset_tracking='0',
        ip_ttl_mode='fixed',
        ip_ttl='64',
        ip_ttl_tracking='0',
        track_by='none',
        egress_tracking='none'    
    )
    # Check status
    if _result_['status'] != IxiaHlt.SUCCESS:
    	ixnHLT_errorHandler('traffic_config', _result_)
    
    #  -- Post Options
    ixnHLT_logger('Configuring post options for config elem: //traffic/trafficItem:<7>/configElement:<1>')
    _result_ = ixiahlt.traffic_config(
        mode='modify',
        traffic_generator='ixnetwork_540',
        stream_id=config_elements[0],
        transmit_distribution='none'    
    )
    # Check status
    if _result_['status'] != IxiaHlt.SUCCESS:
    	ixnHLT_errorHandler('traffic_config', _result_)
    
    #  -- Traffic item//traffic/trafficItem:<8>
    ixnHLT_logger('Configuring traffic for traffic item: //traffic/trafficItem:<8>')
    
    ti_srcs, ti_dsts = {}, {}
    ti_mcast_rcvr_handle, ti_mcast_rcvr_port_index, ti_mcast_rcvr_host_index, ti_mcast_rcvr_mcast_index = {}, {}, {}, {}
    
    ti_srcs['EndpointSet-1'] = '::ixNet::OBJ-/vport:1/interface:1'
    ti_dsts['EndpointSet-1'] = '::ixNet::OBJ-/vport:4/interface:2'
    
    _result_ = ixiahlt.traffic_config(
        mode='create',
        traffic_generator='ixnetwork_540',
        endpointset_count=1,
        emulation_src_handle=[[ti_srcs['EndpointSet-1']]],
        emulation_dst_handle=[[ti_dsts['EndpointSet-1']]],
        emulation_multicast_dst_handle=[[]],
        emulation_multicast_dst_handle_type=[[]],
        global_dest_mac_retry_count='1',
        global_dest_mac_retry_delay='5',
        enable_data_integrity='1',
        global_enable_dest_mac_retry='1',
        global_enable_min_frame_size='0',
        global_enable_staggered_transmit='0',
        global_enable_stream_ordering='0',
        global_stream_control='continuous',
        global_stream_control_iterations='1',
        global_large_error_threshhold='2',
        global_enable_mac_change_on_fly='0',
        global_max_traffic_generation_queries='500',
        global_mpls_label_learning_timeout='30',
        global_refresh_learned_info_before_apply='0',
        global_use_tx_rx_sync='1',
        global_wait_time='1',
        global_display_mpls_current_label_value='0',
        global_detect_misdirected_packets='0',
        global_frame_ordering='none',
        frame_sequencing='disable',
        frame_sequencing_mode='rx_threshold',
        src_dest_mesh='one_to_one',
        route_mesh='one_to_one',
        bidirectional='1',
        allow_self_destined='0',
        use_cp_rate='1',
        use_cp_size='1',
        enable_dynamic_mpls_labels='0',
        hosts_per_net='1',
        name='TI7-HLTAPI_TRAFFICITEM_540',
        source_filter='all',
        destination_filter='all',
        tag_filter=[[]],
        merge_destinations='0',
        circuit_endpoint_type='ipv4',
        pending_operations_timeout='30'    
    )
    # Check status
    if _result_['status'] != IxiaHlt.SUCCESS:
    	ixnHLT_errorHandler('traffic_config', _result_)
    
    #  -- All current config elements
    config_elements = ixiatcl.convert_tcl_list(_result_['traffic_item'])
    
    #  -- Config Element //traffic/trafficItem:<8>/configElement:<1>
    ixnHLT_logger('Configuring options for config elem: //traffic/trafficItem:<8>/configElement:<1>')
    _result_ = ixiahlt.traffic_config(
        mode='modify',
        traffic_generator='ixnetwork_540',
        stream_id=config_elements[0],
        preamble_size_mode='auto',
        preamble_custom_size='8',
        data_pattern='',
        data_pattern_mode='incr_byte',
        enforce_min_gap='0',
        rate_pps='12500',
        frame_rate_distribution_port='split_evenly',
        frame_rate_distribution_stream='split_evenly',
        frame_size='64',
        length_mode='fixed',
        tx_mode='advanced',
        transmit_mode='continuous',
        pkts_per_burst='1',
        tx_delay='0',
        tx_delay_unit='bytes',
        number_of_packets_per_stream='1',
        loop_count='1',
        min_gap_bytes='12'    
    )
    # Check status
    if _result_['status'] != IxiaHlt.SUCCESS:
    	ixnHLT_errorHandler('traffic_config', _result_)
    
    #  -- Endpoint set EndpointSet-1
    ixnHLT_logger('Configuring traffic for config elem: //traffic/trafficItem:<8>/configElement:<1>')
    ixnHLT_logger('Configuring traffic for endpoint set: EndpointSet-1')
    #  -- Stack //traffic/trafficItem:<8>/configElement:<1>/stack:"ethernet-1"
    _result_ = ixiahlt.traffic_config(
        mode='modify_or_insert',
        traffic_generator='ixnetwork_540',
        stream_id=config_elements[0],
        stack_index='1',
        l2_encap='ethernet_ii',
        mac_dst_mode='fixed',
        mac_dst_tracking='0',
        mac_dst='00:00:00:00:00:00',
        mac_src_mode='fixed',
        mac_src_tracking='0',
        mac_src='00:00:00:00:00:00',
        ethernet_value_mode='fixed',
        ethernet_value='ffff',
        ethernet_value_tracking='0'    
    )
    # Check status
    if _result_['status'] != IxiaHlt.SUCCESS:
    	ixnHLT_errorHandler('traffic_config', _result_)
    
    #  -- Stack //traffic/trafficItem:<8>/configElement:<1>/stack:"vlan-2"
    _result_ = ixiahlt.traffic_config(
        mode='modify_or_insert',
        traffic_generator='ixnetwork_540',
        stream_id=config_elements[0],
        stack_index='2',
        vlan='enable',
        vlan_user_priority_mode='fixed',
        vlan_user_priority='0',
        vlan_user_priority_tracking='0',
        vlan_cfi_mode='fixed',
        vlan_cfi='0',
        vlan_cfi_tracking='0',
        vlan_id_mode='fixed',
        vlan_id='0',
        vlan_id_tracking='0'    
    )
    # Check status
    if _result_['status'] != IxiaHlt.SUCCESS:
    	ixnHLT_errorHandler('traffic_config', _result_)
    
    #  -- Stack //traffic/trafficItem:<8>/configElement:<1>/stack:"ipv4-3"
    _result_ = ixiahlt.traffic_config(
        mode='modify_or_insert',
        traffic_generator='ixnetwork_540',
        stream_id=config_elements[0],
        stack_index='3',
        l3_protocol='ipv4',
        qos_type_ixn='tos',
        ip_precedence_mode='fixed',
        ip_precedence='0',
        ip_precedence_tracking='0',
        ip_delay_mode='fixed',
        ip_delay='0',
        ip_delay_tracking='0',
        ip_throughput_mode='fixed',
        ip_throughput='0',
        ip_throughput_tracking='0',
        ip_reliability_mode='fixed',
        ip_reliability='0',
        ip_reliability_tracking='0',
        ip_cost_mode='fixed',
        ip_cost='0',
        ip_cost_tracking='0',
        ip_cu_mode='fixed',
        ip_cu='0',
        ip_cu_tracking='0',
        ip_id_mode='fixed',
        ip_id='0',
        ip_id_tracking='0',
        ip_reserved_mode='fixed',
        ip_reserved='0',
        ip_reserved_tracking='0',
        ip_fragment_mode='fixed',
        ip_fragment='1',
        ip_fragment_tracking='0',
        ip_fragment_last_mode='fixed',
        ip_fragment_last='1',
        ip_fragment_last_tracking='0',
        ip_fragment_offset_mode='fixed',
        ip_fragment_offset='0',
        ip_fragment_offset_tracking='0',
        ip_ttl_mode='fixed',
        ip_ttl='64',
        ip_ttl_tracking='0',
        track_by='none',
        egress_tracking='none'    
    )
    # Check status
    if _result_['status'] != IxiaHlt.SUCCESS:
    	ixnHLT_errorHandler('traffic_config', _result_)
    
    #  -- Post Options
    ixnHLT_logger('Configuring post options for config elem: //traffic/trafficItem:<8>/configElement:<1>')
    _result_ = ixiahlt.traffic_config(
        mode='modify',
        traffic_generator='ixnetwork_540',
        stream_id=config_elements[0],
        transmit_distribution='none'    
    )
    # Check status
    if _result_['status'] != IxiaHlt.SUCCESS:
    	ixnHLT_errorHandler('traffic_config', _result_)
    
    #  -- Traffic item//traffic/trafficItem:<9>
    ixnHLT_logger('Configuring traffic for traffic item: //traffic/trafficItem:<9>')
    
    ti_srcs, ti_dsts = {}, {}
    ti_mcast_rcvr_handle, ti_mcast_rcvr_port_index, ti_mcast_rcvr_host_index, ti_mcast_rcvr_mcast_index = {}, {}, {}, {}
    
    ti_srcs['EndpointSet-1'] = '::ixNet::OBJ-/vport:1/interface:1'
    ti_dsts['EndpointSet-1'] = '::ixNet::OBJ-/vport:4/interface:3'
    
    _result_ = ixiahlt.traffic_config(
        mode='create',
        traffic_generator='ixnetwork_540',
        endpointset_count=1,
        emulation_src_handle=[[ti_srcs['EndpointSet-1']]],
        emulation_dst_handle=[[ti_dsts['EndpointSet-1']]],
        emulation_multicast_dst_handle=[[]],
        emulation_multicast_dst_handle_type=[[]],
        global_dest_mac_retry_count='1',
        global_dest_mac_retry_delay='5',
        enable_data_integrity='1',
        global_enable_dest_mac_retry='1',
        global_enable_min_frame_size='0',
        global_enable_staggered_transmit='0',
        global_enable_stream_ordering='0',
        global_stream_control='continuous',
        global_stream_control_iterations='1',
        global_large_error_threshhold='2',
        global_enable_mac_change_on_fly='0',
        global_max_traffic_generation_queries='500',
        global_mpls_label_learning_timeout='30',
        global_refresh_learned_info_before_apply='0',
        global_use_tx_rx_sync='1',
        global_wait_time='1',
        global_display_mpls_current_label_value='0',
        global_detect_misdirected_packets='0',
        global_frame_ordering='none',
        frame_sequencing='disable',
        frame_sequencing_mode='rx_threshold',
        src_dest_mesh='one_to_one',
        route_mesh='one_to_one',
        bidirectional='1',
        allow_self_destined='0',
        use_cp_rate='1',
        use_cp_size='1',
        enable_dynamic_mpls_labels='0',
        hosts_per_net='1',
        name='TI8-HLTAPI_TRAFFICITEM_540',
        source_filter='all',
        destination_filter='all',
        tag_filter=[[]],
        merge_destinations='0',
        circuit_endpoint_type='ipv4',
        pending_operations_timeout='30'    
    )
    # Check status
    if _result_['status'] != IxiaHlt.SUCCESS:
    	ixnHLT_errorHandler('traffic_config', _result_)
    
    #  -- All current config elements
    config_elements = ixiatcl.convert_tcl_list(_result_['traffic_item'])
    
    #  -- Config Element //traffic/trafficItem:<9>/configElement:<1>
    ixnHLT_logger('Configuring options for config elem: //traffic/trafficItem:<9>/configElement:<1>')
    _result_ = ixiahlt.traffic_config(
        mode='modify',
        traffic_generator='ixnetwork_540',
        stream_id=config_elements[0],
        preamble_size_mode='auto',
        preamble_custom_size='8',
        data_pattern='',
        data_pattern_mode='incr_byte',
        enforce_min_gap='0',
        rate_pps='12500',
        frame_rate_distribution_port='split_evenly',
        frame_rate_distribution_stream='split_evenly',
        frame_size='64',
        length_mode='fixed',
        tx_mode='advanced',
        transmit_mode='continuous',
        pkts_per_burst='1',
        tx_delay='0',
        tx_delay_unit='bytes',
        number_of_packets_per_stream='1',
        loop_count='1',
        min_gap_bytes='12'    
    )
    # Check status
    if _result_['status'] != IxiaHlt.SUCCESS:
    	ixnHLT_errorHandler('traffic_config', _result_)
    
    #  -- Endpoint set EndpointSet-1
    ixnHLT_logger('Configuring traffic for config elem: //traffic/trafficItem:<9>/configElement:<1>')
    ixnHLT_logger('Configuring traffic for endpoint set: EndpointSet-1')
    #  -- Stack //traffic/trafficItem:<9>/configElement:<1>/stack:"ethernet-1"
    _result_ = ixiahlt.traffic_config(
        mode='modify_or_insert',
        traffic_generator='ixnetwork_540',
        stream_id=config_elements[0],
        stack_index='1',
        l2_encap='ethernet_ii',
        mac_dst_mode='fixed',
        mac_dst_tracking='0',
        mac_dst='00:00:00:00:00:00',
        mac_src_mode='fixed',
        mac_src_tracking='0',
        mac_src='00:00:00:00:00:00',
        ethernet_value_mode='fixed',
        ethernet_value='ffff',
        ethernet_value_tracking='0'    
    )
    # Check status
    if _result_['status'] != IxiaHlt.SUCCESS:
    	ixnHLT_errorHandler('traffic_config', _result_)
    
    #  -- Stack //traffic/trafficItem:<9>/configElement:<1>/stack:"vlan-2"
    _result_ = ixiahlt.traffic_config(
        mode='modify_or_insert',
        traffic_generator='ixnetwork_540',
        stream_id=config_elements[0],
        stack_index='2',
        vlan='enable',
        vlan_user_priority_mode='fixed',
        vlan_user_priority='0',
        vlan_user_priority_tracking='0',
        vlan_cfi_mode='fixed',
        vlan_cfi='0',
        vlan_cfi_tracking='0',
        vlan_id_mode='fixed',
        vlan_id='0',
        vlan_id_tracking='0'    
    )
    # Check status
    if _result_['status'] != IxiaHlt.SUCCESS:
    	ixnHLT_errorHandler('traffic_config', _result_)
    
    #  -- Stack //traffic/trafficItem:<9>/configElement:<1>/stack:"ipv4-3"
    _result_ = ixiahlt.traffic_config(
        mode='modify_or_insert',
        traffic_generator='ixnetwork_540',
        stream_id=config_elements[0],
        stack_index='3',
        l3_protocol='ipv4',
        qos_type_ixn='tos',
        ip_precedence_mode='fixed',
        ip_precedence='0',
        ip_precedence_tracking='0',
        ip_delay_mode='fixed',
        ip_delay='0',
        ip_delay_tracking='0',
        ip_throughput_mode='fixed',
        ip_throughput='0',
        ip_throughput_tracking='0',
        ip_reliability_mode='fixed',
        ip_reliability='0',
        ip_reliability_tracking='0',
        ip_cost_mode='fixed',
        ip_cost='0',
        ip_cost_tracking='0',
        ip_cu_mode='fixed',
        ip_cu='0',
        ip_cu_tracking='0',
        ip_id_mode='fixed',
        ip_id='0',
        ip_id_tracking='0',
        ip_reserved_mode='fixed',
        ip_reserved='0',
        ip_reserved_tracking='0',
        ip_fragment_mode='fixed',
        ip_fragment='1',
        ip_fragment_tracking='0',
        ip_fragment_last_mode='fixed',
        ip_fragment_last='1',
        ip_fragment_last_tracking='0',
        ip_fragment_offset_mode='fixed',
        ip_fragment_offset='0',
        ip_fragment_offset_tracking='0',
        ip_ttl_mode='fixed',
        ip_ttl='64',
        ip_ttl_tracking='0',
        track_by='none',
        egress_tracking='none'    
    )
    # Check status
    if _result_['status'] != IxiaHlt.SUCCESS:
    	ixnHLT_errorHandler('traffic_config', _result_)
    
    #  -- Post Options
    ixnHLT_logger('Configuring post options for config elem: //traffic/trafficItem:<9>/configElement:<1>')
    _result_ = ixiahlt.traffic_config(
        mode='modify',
        traffic_generator='ixnetwork_540',
        stream_id=config_elements[0],
        transmit_distribution='none'    
    )
    # Check status
    if _result_['status'] != IxiaHlt.SUCCESS:
    	ixnHLT_errorHandler('traffic_config', _result_)
    
    #
    # Start traffic configured earlier
    #
    ixnHLT_logger('Running Traffic...')
    _result_ = ixiahlt.traffic_control(
        action='run',
        traffic_generator='ixnetwork_540',
        type='l23'
    )
    # Check status
    if _result_['status'] != IxiaHlt.SUCCESS:
        ixnHLT_errorHandler('traffic_control', _result_)
                  
    time.sleep(30)
    
    # ################################
    # protocol stats phase of the test
    # ################################
    
    #  stats for:
    #  packet_config_buffers handles
    ixnHLT_logger('getting stats for packet_config_buffers configuration elements')
    # ######################
    # stop phase of the test
    # ######################
    #
    # Stop traffic started earlier
    #
    ixnHLT_logger('Stopping Traffic...')
    _result_ = ixiahlt.traffic_control(
        action='stop',
        traffic_generator='ixnetwork_540',
        type='l23',
    )
    # Check status
    if _result_['status'] != IxiaHlt.SUCCESS:
        ixnHLT_errorHandler('traffic_control', _result_)
    
    # ###############################
    # traffic stats phase of the test
    # ###############################
    time.sleep(30)
                  
    #
    # print stats for all ports that are involved w/ 
    # ixnHLT(TRAFFIC-ENDPOINT-HANDLES)
    #
    ixnHLT_logger('Traffic stats')
    for traffic_stats_retry in range(120):
        _result_ = ixiahlt.traffic_stats(
            mode='aggregate',
            traffic_generator='ixnetwork_540',
            measure_mode='mixed'
        )
        if _result_['status'] != IxiaHlt.SUCCESS:
            ixnHLT_errorHandler('traffic_stats', _result_)
        
        if _result_['waiting_for_stats'] == '0':
            break
        
        ixnHLT_logger('Traffic waiting_for_stats flag is 1. Trial %d' % traffic_stats_retry)
        time.sleep(1)
                  
    if _result_['waiting_for_stats'] != '0':
        add_info = 'Traffic statistics are not ready after 120 seconds. waiting_for_stats is 1'
        raise IxiaError(IxiaError.COMMAND_FAIL, add_info)
                  
    for port_handle in traffic_stats_ph:
        ixnHLT_logger('')
        ixnHLT_logger('port %s' % port_handle)
        ixnHLT_logger('-----------------------------------')
    
        ixnHLT_logger('TX')
        for (k, v) in _result_[port_handle]['aggregate']['tx'].items():
            ixnHLT_logger('{0:40s} = {1}'.format(k, v))
    
        ixnHLT_logger('RX')
        for (k, v) in _result_[port_handle]['aggregate']['rx'].items():
            ixnHLT_logger('{0:40s} = {1}'.format(k, v))
    
        ixnHLT_logger('')
    
    ixnHLT_logger('Stopping all protocol(s) ...')
    
    _result_ = ixiahlt.test_control(action='stop_all_protocols')
    # Check status
    if _result_['status'] != IxiaHlt.SUCCESS:
        ixnHLT_errorHandler('ixiahlt::traffic_control', _result_)
                    
# ----------------------------------------------------------------
# This dict keeps all generated handles and other info
ixnHLT = {}

# ----------------------------------------------------------------
#  chassis, card, port configuration
# 
#  port_list needs to match up with path_list below
# 
chassis = ['10.127.63.100']
tcl_server = '10.127.63.100'
port_list = [['1/1', '1/4', '1/5', '1/6']]
vport_name_list = [['1/1/1', '1/1/4', '1/1/5', '1/1/6']]
guard_rail = 'none'
# 
#  this should match up w/ your port_list above
# 
ixnHLT['path_list'] = [['//vport:<1>', '//vport:<2>', '//vport:<3>', '//vport:<4>']]
# 
# 
_result_ = ixiahlt.connect(
    reset=1,
    device=chassis,
    port_list=port_list,
    ixnetwork_tcl_server='localhost',
    tcl_server=tcl_server,
    guard_rail=guard_rail,
    return_detailed_handles=0
)
# Check status
if _result_['status'] != IxiaHlt.SUCCESS:
	ixnHLT_errorHandler('connect', _result_)
porthandles = []
for (ch, ch_ports, ch_vport_paths) in zip(chassis, port_list, ixnHLT['path_list']):
    ch_porthandles = []
    for (port, path) in zip(ch_ports, ch_vport_paths):
        try:
            ch_key = _result_['port_handle']
            for ch_p in ch.split('.'):
                ch_key = ch_key[ch_p]
            porthandle = ch_key[port]
        except:
            errdict = {'log': 'could not connect to chassis=%s,port=<%s>' % (ch, port)}
            ixnHLT_errorHandler('connect', errdict)

        ixnHLT['PORT-HANDLE,%s' % path] = porthandle
        ch_porthandles.append(porthandle)
    porthandles.append(ch_porthandles)

for (ch_porthandles, ch_vport_names) in zip(porthandles, vport_name_list):
    _result_ = ixiahlt.vport_info(
        mode='set_info',
        port_list=[ch_porthandles],
        port_name_list=[ch_vport_names]
    )
    if _result_['status'] != IxiaHlt.SUCCESS:
        ixnHLT_errorHandler('vport_info', _result_)
            

# ----------------------------------------------------------------
ixnHLT_Scriptgen_Configure(ixiahlt, ixnHLT)
ixnHLT_Scriptgen_RunTest(ixiahlt, ixnHLT)
