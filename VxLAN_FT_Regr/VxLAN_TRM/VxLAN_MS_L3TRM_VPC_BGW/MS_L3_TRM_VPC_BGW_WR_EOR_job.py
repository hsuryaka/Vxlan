from pyats.easypy import run
from pyats.datastructures.logic import And, Or, Not
import os

def main():
    testscript = './MS_L3_TRM_VPC_BGW.py'
    run(testscript, traffic_threshold = 200,tgn_connect = 1,\
        config_interface         = 1,\
        config_ospf              = 1,\
        config_ospfv3            = 0,\
        config_bgp               = 1,\
        config_keepalive_vrf     = 1,\
        config_vpc               = 1,\
        config_pim               = 1,\
        config_vxlan_global      = 1,\
        config_bgp_global        = 1,\
        config_vlan              = 1,\
        config_vrf               = 1,\
        config_svi               = 1,\
        config_evpn              = 1,\
        config_nve_global        = 1,\
        config_nve_l2vni         = 1,\
        config_nve_l3vni         = 1,\
        config_sub_intf          = 1,\
        config_loopback_intf     = 1,\
        config_ospf_router_id    = 0,\
        config_prefix_list       = 1,\
        config_route_map         = 1,\
        config_multisite         = 1,\
        config_tunnel_encryption = 0,\
        config_tgn_conn          = 1,\
        config_tgn_interface     = 1,\
        
        uids = Or('common_setup',\
                #  'VXLAN-MS-L3-TRM-VPC-BGW-TRF-001',\
                #  'VXLAN-MS-L3-TRM-VPC-BGW-TRF-002',\
                #  'VXLAN-MS-L3-TRM-VPC-BGW-TRF-003',\
                #  'VXLAN-MS-L3-TRM-VPC-BGW-TRF-004',\
                #  'VXLAN-MS-L3-TRM-VPC-BGW-TRF-005',\
                #  'VXLAN-MS-L3-TRM-VPC-BGW-TRF-006',\
                #  'VXLAN-MS-L3-TRM-VPC-BGW-TRF-007',\
                #  'VXLAN-MS-L3-TRM-VPC-BGW-TRF-008',\
                #  'VXLAN-MS-L3-TRM-VPC-BGW-TRF-009',\
                #  'VXLAN-MS-L3-TRM-VPC-BGW-TRF-010',\
                #  'VXLAN-MS-L3-TRM-VPC-BGW-TRF-011',\
                #  'VXLAN-MS-L3-TRM-VPC-BGW-TRF-012',\
                #  'VXLAN-MS-L3-TRM-VPC-BGW-TRF-013',\
                #  'VXLAN-MS-L3-TRM-VPC-BGW-TRF-014',\
                #  'VXLAN-MS-L3-TRM-VPC-BGW-TRF-015',\
                #  'VXLAN-MS-L3-TRM-VPC-BGW-TRF-016',\
                #  'VXLAN-MS-L3-TRM-VPC-BGW-TRF-017',\
                #  'VXLAN-MS-L3-TRM-VPC-BGW-TRF-018',\
                #  'VXLAN-MS-L3-TRM-VPC-BGW-TRF-019',\
                #  'VXLAN-MS-L3-TRM-VPC-BGW-TRF-020',\
                #  'VXLAN-MS-L3-TRM-VPC-BGW-TRF-021',\
                #  'VXLAN-MS-L3-TRM-VPC-BGW-TRF-022',\
                #  'VXLAN-MS-L3-TRM-VPC-BGW-TRF-023',\
                #  'VXLAN-MS-L3-TRM-VPC-BGW-TRF-024',\
                #  'VXLAN-MS-L3-TRM-VPC-BGW-TRF-025',\
                #  'VXLAN-MS-L3-TRM-VPC-BGW-TRF-026',\
                #  'VXLAN-MS-L3-TRM-VPC-BGW-TRF-027',\
                #  'VXLAN-MS-L3-TRM-VPC-BGW-TRF-028',\
                #  'VXLAN-MS-L3-TRM-VPC-BGW-TRF-029',\
                #  'VXLAN-MS-L3-TRM-VPC-BGW-TRF-030',\
                #  'VXLAN-MS-L3-TRM-VPC-BGW-TRF-031',\
                #  'VXLAN-MS-L3-TRM-VPC-BGW-TRF-032',\
                #  'VXLAN-MS-L3-TRM-VPC-BGW-TRF-033',\
                #  'VXLAN-MS-L3-TRM-VPC-BGW-TRF-034',\
                #  'VXLAN-MS-L3-TRM-VPC-BGW-TRF-035',\
                #  'VXLAN-MS-L3-TRM-VPC-BGW-TRF-036',\
                #  'VXLAN-MS-L3-TRM-VPC-BGW-TRF-037',\
                #  'VXLAN-MS-L3-TRM-VPC-BGW-TRF-038',\
                #  'VXLAN-MS-L3-TRM-VPC-BGW-TRF-039',\
                #  'VXLAN-MS-L3-TRM-VPC-BGW-TRF-040',\
                #  'VXLAN-MS-L3-TRM-VPC-BGW-TRF-041',\
                #  'VXLAN-MS-L3-TRM-VPC-BGW-TRF-042',\
                #  'VXLAN-MS-L3-TRM-VPC-BGW-TRF-043',\
                #  'VXLAN-MS-L3-TRM-VPC-BGW-TRF-044',\
                #  'VXLAN-MS-L3-TRM-VPC-BGW-TRF-045',\
                #  'VXLAN-MS-L3-TRM-VPC-BGW-TRF-046',\
                #  'VXLAN-MS-L3-TRM-VPC-BGW-TRF-047',\
                #  'VXLAN-MS-L3-TRM-VPC-BGW-TRF-048',\
                #  'VXLAN-MS-L3-TRM-VPC-BGW-TRF-049',\
                #  'VXLAN-MS-L3-TRM-VPC-BGW-TRF-050',\
                #  'VXLAN-MS-L3-TRM-VPC-BGW-TRF-051',\
                #  'VXLAN-MS-L3-TRM-VPC-BGW-TRF-052',\
                #  'VXLAN-MS-L3-TRM-VPC-BGW-TRF-053',\
                #  'VXLAN-MS-L3-TRM-VPC-BGW-TRF-054',\
                #  'VXLAN-MS-L3-TRM-VPC-BGW-TRF-055',\
                #  'VXLAN-MS-L3-TRM-VPC-BGW-TRF-056',\
                #  'VXLAN-MS-L3-TRM-VPC-BGW-TRF-057',\
                #  'VXLAN-MS-L3-TRM-VPC-BGW-TRF-058',\
                #  'VXLAN-MS-L3-TRM-VPC-BGW-TRF-059',\
                #  'VXLAN-MS-L3-TRM-VPC-BGW-TRF-060',\
                 'VXLAN-MS-L3-TRM-VPC-BGW-FUNC-001',\
                 'VXLAN-MS-L3-TRM-VPC-BGW-FUNC-002',\
                 'VXLAN-MS-L3-TRM-VPC-BGW-FUNC-003',\
                 'VXLAN-MS-L3-TRM-VPC-BGW-FUNC-004',\
                 'VXLAN-MS-L3-TRM-VPC-BGW-FUNC-005',\
                 'VXLAN-MS-L3-TRM-VPC-BGW-FUNC-006',\
                 'VXLAN-MS-L3-TRM-VPC-BGW-FUNC-007',\
                 'VXLAN-MS-L3-TRM-VPC-BGW-FUNC-008',\
                 'VXLAN-MS-L3-TRM-VPC-BGW-FUNC-009',\
                 'VXLAN-MS-L3-TRM-VPC-BGW-FUNC-010',\
                 'VXLAN-MS-L3-TRM-VPC-BGW-FUNC-011',\
                 'VXLAN-MS-L3-TRM-VPC-BGW-FUNC-012',\
                 'VXLAN-MS-L3-TRM-VPC-BGW-FUNC-013',\
                 'VXLAN-MS-L3-TRM-VPC-BGW-FUNC-014',\
                 'VXLAN-MS-L3-TRM-VPC-BGW-FUNC-015',\
                 'VXLAN-MS-L3-TRM-VPC-BGW-FUNC-016',\
                 'VXLAN-MS-L3-TRM-VPC-BGW-FUNC-017',\
                 'VXLAN-MS-L3-TRM-VPC-BGW-FUNC-018',\
                 'VXLAN-MS-L3-TRM-VPC-BGW-FUNC-019',\
                 'VXLAN-MS-L3-TRM-VPC-BGW-FUNC-020',\
                 'VXLAN-MS-L3-TRM-VPC-BGW-FUNC-021',\
                 'VXLAN-MS-L3-TRM-VPC-BGW-FUNC-022',\
                 'VXLAN-MS-L3-TRM-VPC-BGW-FUNC-023',\
                 'VXLAN-MS-L3-TRM-VPC-BGW-FUNC-024',\
                 'VXLAN-MS-L3-TRM-VPC-BGW-FUNC-025',\
                 'VXLAN-MS-L3-TRM-VPC-BGW-FUNC-026',\
                 'VXLAN-MS-L3-TRM-VPC-BGW-FUNC-027',\
                 'VXLAN-MS-L3-TRM-VPC-BGW-FUNC-028',\
                 'VXLAN-MS-L3-TRM-VPC-BGW-FUNC-029',\
                 'VXLAN-MS-L3-TRM-VPC-BGW-FUNC-030',\
                 'VXLAN-MS-L3-TRM-VPC-BGW-FUNC-031',\
                 'VXLAN-MS-L3-TRM-VPC-BGW-FUNC-032',\
                 'VXLAN-MS-L3-TRM-VPC-BGW-FUNC-033',\
                 'VXLAN-MS-L3-TRM-VPC-BGW-FUNC-034',\
                 'VXLAN-MS-L3-TRM-VPC-BGW-FUNC-035',\
                 'VXLAN-MS-L3-TRM-VPC-BGW-FUNC-036',\
                 'VXLAN-MS-L3-TRM-VPC-BGW-FUNC-037',\
                 'VXLAN-MS-L3-TRM-VPC-BGW-FUNC-038',\
                 'VXLAN-MS-L3-TRM-VPC-BGW-FUNC-039',\
                 'VXLAN-MS-L3-TRM-VPC-BGW-FUNC-040',\
                 'VXLAN-MS-L3-TRM-VPC-BGW-FUNC-041',\
                 'VXLAN-MS-L3-TRM-VPC-BGW-FUNC-042',\
                 'VXLAN-MS-L3-TRM-VPC-BGW-FUNC-043',\
                 'VXLAN-MS-L3-TRM-VPC-BGW-FUNC-044',\
                 'VXLAN-MS-L3-TRM-VPC-BGW-FUNC-045',\
                 'VXLAN-MS-L3-TRM-VPC-BGW-FUNC-046',\
                 'VXLAN-MS-L3-TRM-VPC-BGW-FUNC-047',\
                 'VXLAN-MS-L3-TRM-VPC-BGW-FUNC-048',\
                 'VXLAN-MS-L3-TRM-VPC-BGW-FUNC-049',\
                 'VXLAN-MS-L3-TRM-VPC-BGW-FUNC-050',\
                 'VXLAN-MS-L3-TRM-VPC-BGW-FUNC-051',\
                 'VXLAN-MS-L3-TRM-VPC-BGW-FUNC-052',\
                 'VXLAN-MS-L3-TRM-VPC-BGW-FUNC-053',\
                 'VXLAN-MS-L3-TRM-VPC-BGW-FUNC-054',\
                 'VXLAN-MS-L3-TRM-VPC-BGW-FUNC-055',\
                 'VXLAN-MS-L3-TRM-VPC-BGW-FUNC-056',\
                 'VXLAN-MS-L3-TRM-VPC-BGW-FUNC-057',\
                ))