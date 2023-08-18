from pyats.easypy import run
from pyats.datastructures.logic import And, Or, Not
import os

def main():
    testscript = './TRM_VPC_BL_script.py'
    run(testscript, traffic_threshold = 10,tgn_connect = 1,\
        config_interface        = 1, \
        config_ospf             = 1, \
        config_ospfv3           = 0, \
        config_bgp              = 1, \
        config_vpc              = 1, \
        config_pim              = 1, \
        config_vxlan_global     = 1, \
        config_bgp_global       = 1, \
        config_vlan             = 1, \
        config_vrf              = 1, \
        config_svi              = 1, \
        config_evpn             = 1, \
        config_nve_global       = 1, \
        config_nve_l2vni        = 1, \
        config_nve_l3vni        = 1, \
        config_sub_intf         = 1, \
        config_loopback_intf    = 1, \
        config_ospf_router_id   = 1, \
        config_tgn_conn         = 1, \
        config_tgn_interface    = 1, \
        
        uids = Or('common_setup',\
                'VXLAN-L3-TRM-VPC-BL-FUNC-001',\
                'VXLAN-L3-TRM-VPC-BL-FUNC-002',\
                'VXLAN-L3-TRM-VPC-BL-FUNC-003',\
                'VXLAN-L3-TRM-VPC-BL-FUNC-004',\
                'VXLAN-L3-TRM-VPC-BL-FUNC-005',\
                'VXLAN-L3-TRM-VPC-BL-FUNC-006',\
                'VXLAN-L3-TRM-VPC-BL-FUNC-007',\
                'VXLAN-L3-TRM-VPC-BL-FUNC-008',\
                'VXLAN-L3-TRM-VPC-BL-FUNC-009',\
                'VXLAN-L3-TRM-VPC-BL-FUNC-010',\
                'VXLAN-L3-TRM-VPC-BL-FUNC-011',\
                'VXLAN-L3-TRM-VPC-BL-FUNC-012',\
                'VXLAN-L3-TRM-VPC-BL-FUNC-013',\
                'VXLAN-L3-TRM-VPC-BL-FUNC-014',\
                'VXLAN-L3-TRM-VPC-BL-FUNC-015',\
                'VXLAN-L3-TRM-VPC-BL-FUNC-016',\
                'VXLAN-L3-TRM-VPC-BL-FUNC-017',\
                'VXLAN-L3-TRM-VPC-BL-FUNC-018',\
                'VXLAN-L3-TRM-VPC-BL-FUNC-019',\
                'VXLAN-L3-TRM-VPC-BL-FUNC-020',\
                'VXLAN-L3-TRM-VPC-BL-FUNC-021',\
                'VXLAN-L3-TRM-VPC-BL-FUNC-022',\
                'VXLAN-L3-TRM-VPC-BL-FUNC-023',\
                'VXLAN-L3-TRM-VPC-BL-FUNC-024',\
                'VXLAN-L3-TRM-VPC-BL-FUNC-025',\
                'VXLAN-L3-TRM-VPC-BL-FUNC-026',\
                'VXLAN-L3-TRM-VPC-BL-FUNC-027',\
                'VXLAN-L3-TRM-VPC-BL-FUNC-028',\
                'VXLAN-L3-TRM-VPC-BL-FUNC-029',\
                'VXLAN-L3-TRM-VPC-BL-FUNC-030',\
                'VXLAN-L3-TRM-VPC-BL-FUNC-031',\
                'VXLAN-L3-TRM-VPC-BL-FUNC-032',\
                'VXLAN-L3-TRM-VPC-BL-FUNC-033',\
                'VXLAN-L3-TRM-VPC-BL-FUNC-034',\
                'VXLAN-L3-TRM-VPC-BL-FUNC-035',\
                'VXLAN-L3-TRM-VPC-BL-FUNC-036',\
                'VXLAN-L3-TRM-VPC-BL-FUNC-037',\
                'VXLAN-L3-TRM-VPC-BL-FUNC-038',\
                'VXLAN-L3-TRM-VPC-BL-FUNC-039',\
                'VXLAN-L3-TRM-VPC-BL-FUNC-040',\
                'VXLAN-L3-TRM-VPC-BL-FUNC-041',\
                'VXLAN-L3-TRM-VPC-BL-FUNC-042',\
                'VXLAN-L3-TRM-VPC-BL-FUNC-043',\
                'VXLAN-L3-TRM-VPC-BL-FUNC-044',\
                'VXLAN-L3-TRM-VPC-BL-FUNC-045',\
                'VXLAN-L3-TRM-VPC-BL-FUNC-046',\
                'VXLAN-L3-TRM-VPC-BL-FUNC-047',\
                'VXLAN-L3-TRM-VPC-BL-FUNC-048',\
                'VXLAN-L3-TRM-VPC-BL-FUNC-049',\
                'VXLAN-L3-TRM-VPC-BL-FUNC-050',\
                'VXLAN-L3-TRM-VPC-BL-FUNC-051',\
                'VXLAN-L3-TRM-VPC-BL-FUNC-052',\
                'VXLAN-L3-TRM-VPC-BL-FUNC-053',\
                'VXLAN-L3-TRM-VPC-BL-FUNC-054',\
                'VXLAN-L3-TRM-VPC-BL-FUNC-055',\
                'VXLAN-L3-TRM-VPC-BL-FUNC-056',\
                'VXLAN-L3-TRM-VPC-BL-FUNC-057',\
                'VXLAN-L3-TRM-VPC-BL-FUNC-058',\
                'VXLAN-L3-TRM-VPC-BL-FUNC-059',\
                'VXLAN-L3-TRM-VPC-BL-FUNC-060',\
                'VXLAN-L3-TRM-VPC-BL-FUNC-061',\
                'VXLAN-L3-TRM-VPC-BL-FUNC-062',\
                'VXLAN-L3-TRM-VPC-BL-FUNC-063',\
                'VXLAN-L3-TRM-VPC-BL-FUNC-064',\
                'VXLAN-L3-TRM-VPC-BL-FUNC-065',\
                'VXLAN-L3-TRM-VPC-BL-FUNC-066',\
                'VXLAN-L3-TRM-VPC-BL-FUNC-067',\
                'VXLAN-L3-TRM-VPC-BL-FUNC-068',\
                'VXLAN-L3-TRM-VPC-BL-FUNC-069',\
                'VXLAN-L3-TRM-VPC-BL-FUNC-070',\
                ))
