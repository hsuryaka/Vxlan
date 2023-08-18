from pyats.easypy import run
from pyats.datastructures.logic import And, Or, Not
import os

def main():
    tmp_path = os.path.dirname(os.path.abspath(__file__))
    # test_path = tmp_path.split('/')
    # test_path.pop()
    # test_path.append('scripts')
    # test_path.append('sundown_l3trmvpcbl.py')
    testscript = '/ws/hganapat-bgl/L3_TRM_Anycast_RP/Fretta_trm_anycast_rp1.py'
    run(testscript, traffic_threshold = 10,tgn_connect = 1,\
        config_interface = 1,\
        config_ospf = 1,\
        config_ospfv3 = 0,\
        config_bgp = 1,\
        config_vpc = 1,\
        config_pim = 1,\
        config_vxlan_global = 1,\
        config_bgp_global = 1, \
        config_vlan = 1,\
        config_vrf = 1,\
        config_svi = 1,\
        config_evpn = 1,\
        config_nve_global = 1,\
        config_nve_l2vni = 1,\
        config_nve_l3vni = 1,\
        config_sub_intf = 1,\
        config_loopback_intf = 1,\
        config_prefix_list = 1,\
        config_route_map = 1,\
        config_ospf_router_id = 1,\
        config_pim_anycast_loopback_intf = 1,\
        config_pim_anycast_rp_set = 1,\
        config_tgn_conn = 1,\
        config_tgn_interface = 1,\
        
        uids = Or('common_setup',\
                #'VXLAN-L3-TRM-ANYCAST-RP-FUNC-001',\
                #'VXLAN-L3-TRM-ANYCAST-RP-FUNC-002',\
                #'VXLAN-L3-TRM-ANYCAST-RP-FUNC-003',\
                #'VXLAN-L3-TRM-ANYCAST-RP-FUNC-004',\
                #'VXLAN-L3-TRM-ANYCAST-RP-FUNC-005',\
                #'VXLAN-L3-TRM-ANYCAST-RP-FUNC-006',\
                #'VXLAN-L3-TRM-ANYCAST-RP-FUNC-007',\
                #'VXLAN-L3-TRM-ANYCAST-RP-FUNC-008',\
                #'VXLAN-L3-TRM-ANYCAST-RP-FUNC-009',\
                #'VXLAN-L3-TRM-ANYCAST-RP-FUNC-010',\
                #'VXLAN-L3-TRM-ANYCAST-RP-FUNC-011',\
                #'VXLAN-L3-TRM-ANYCAST-RP-FUNC-012',\
                #'VXLAN-L3-TRM-ANYCAST-RP-FUNC-013',\
                #'VXLAN-L3-TRM-ANYCAST-RP-FUNC-014',\
                #'VXLAN-L3-TRM-ANYCAST-RP-FUNC-015',\
                #'VXLAN-L3-TRM-ANYCAST-RP-FUNC-016',\
                #'VXLAN-L3-TRM-ANYCAST-RP-FUNC-017',\
                #'VXLAN-L3-TRM-ANYCAST-RP-FUNC-018',\
                #'VXLAN-L3-TRM-ANYCAST-RP-FUNC-019',\
                #'VXLAN-L3-TRM-ANYCAST-RP-FUNC-020',\
                #'VXLAN-L3-TRM-ANYCAST-RP-FUNC-021',\
                #'VXLAN-L3-TRM-ANYCAST-RP-FUNC-022',\
                #'VXLAN-L3-TRM-ANYCAST-RP-FUNC-023',\
                #'VXLAN-L3-TRM-ANYCAST-RP-FUNC-024',\
                #'VXLAN-L3-TRM-ANYCAST-RP-FUNC-025',\
                #'VXLAN-L3-TRM-ANYCAST-RP-FUNC-026',\
                #'VXLAN-L3-TRM-ANYCAST-RP-FUNC-027',\
                #'VXLAN-L3-TRM-ANYCAST-RP-FUNC-028',\
                #'VXLAN-L3-TRM-ANYCAST-RP-FUNC-029',\
                #'VXLAN-L3-TRM-ANYCAST-RP-FUNC-030',\
                #'VXLAN-L3-TRM-ANYCAST-RP-FUNC-031',\
                'VXLAN-L3-TRM-ANYCAST-RP-FUNC-032',\
                #'VXLAN-L3-TRM-ANYCAST-RP-FUNC-033',\
                #'VXLAN-L3-TRM-ANYCAST-RP-FUNC-034',\
                #'VXLAN-L3-TRM-ANYCAST-RP-FUNC-035',\
                #'VXLAN-L3-TRM-ANYCAST-RP-FUNC-036',\
                #'VXLAN-L3-TRM-ANYCAST-RP-FUNC-037',\
                #'VXLAN-L3-TRM-ANYCAST-RP-FUNC-038',\
                #'VXLAN-L3-TRM-ANYCAST-RP-FUNC-039',\
                #'VXLAN-L3-TRM-ANYCAST-RP-FUNC-040',\
                #'VXLAN-L3-TRM-ANYCAST-RP-FUNC-041',\
                #'VXLAN-L3-TRM-ANYCAST-RP-FUNC-042',\
                #'VXLAN-L3-TRM-ANYCAST-RP-FUNC-043',\
                #'VXLAN-L3-TRM-ANYCAST-RP-FUNC-044',\
                #'VXLAN-L3-TRM-ANYCAST-RP-FUNC-045',\
                #'VXLAN-L3-TRM-ANYCAST-RP-FUNC-046',\
                #'VXLAN-L3-TRM-ANYCAST-RP-FUNC-047',\
                #'VXLAN-L3-TRM-ANYCAST-RP-FUNC-048',\
                #'VXLAN-L3-TRM-ANYCAST-RP-FUNC-049',\
                #'VXLAN-L3-TRM-ANYCAST-RP-FUNC-050',\
                #'VXLAN-L3-TRM-ANYCAST-RP-FUNC-051',\
                #'VXLAN-L3-TRM-ANYCAST-RP-FUNC-052',\
                #'VXLAN-L3-TRM-ANYCAST-RP-FUNC-053',\
                #'VXLAN-L3-TRM-ANYCAST-RP-FUNC-054',\
                #'VXLAN-L3-TRM-ANYCAST-RP-FUNC-055',\
                #'VXLAN-L3-TRM-ANYCAST-RP-FUNC-056',\
                #'VXLAN-L3-TRM-ANYCAST-RP-FUNC-057',\
                #'VXLAN-L3-TRM-ANYCAST-RP-FUNC-058',\
                #'VXLAN-L3-TRM-ANYCAST-RP-FUNC-059',\
                #'VXLAN-L3-TRM-ANYCAST-RP-FUNC-060',\
                #'VXLAN-L3-TRM-ANYCAST-RP-FUNC-061',\
                #'VXLAN-L3-TRM-ANYCAST-RP-FUNC-062',\
                'VXLAN-L3-TRM-ANYCAST-RP-FUNC-063',\
                #'VXLAN-L3-TRM-ANYCAST-RP-FUNC-064',\
                #'VXLAN-L3-TRM-ANYCAST-RP-FUNC-065',\
                #'VXLAN-L3-TRM-ANYCAST-RP-FUNC-066',\
                #'VXLAN-L3-TRM-ANYCAST-RP-FUNC-067',\
                #'VXLAN-L3-TRM-ANYCAST-RP-FUNC-068',\
                #'VXLAN-L3-TRM-ANYCAST-RP-FUNC-069',\
                #'VXLAN-L3-TRM-ANYCAST-RP-FUNC-070',\
                #'VXLAN-L3-TRM-ANYCAST-RP-FUNC-071',\
                #'VXLAN-L3-TRM-ANYCAST-RP-FUNC-072',\
                #'VXLAN-L3-TRM-ANYCAST-RP-FUNC-073',\
                #'VXLAN-L3-TRM-ANYCAST-RP-FUNC-074',\
                #'VXLAN-L3-TRM-ANYCAST-RP-FUNC-075',\
                #'VXLAN-L3-TRM-ANYCAST-RP-FUNC-076',\
                #'VXLAN-L3-TRM-ANYCAST-RP-FUNC-077',\
                #'VXLAN-L3-TRM-ANYCAST-RP-FUNC-078',\
                #'VXLAN-L3-TRM-ANYCAST-RP-FUNC-079',\
                #'VXLAN-L3-TRM-ANYCAST-RP-FUNC-080',\
                #'VXLAN-L3-TRM-ANYCAST-RP-FUNC-081',\
                #'VXLAN-L3-TRM-ANYCAST-RP-FUNC-082',\
                #'VXLAN-L3-TRM-ANYCAST-RP-FUNC-083',\
                #'VXLAN-L3-TRM-ANYCAST-RP-FUNC-084',\
                #'VXLAN-L3-TRM-ANYCAST-RP-FUNC-085',\
                #'VXLAN-L3-TRM-ANYCAST-RP-FUNC-086',\
                #'VXLAN-L3-TRM-ANYCAST-RP-FUNC-087',\
                #'VXLAN-L3-TRM-ANYCAST-RP-FUNC-088',\
                #'VXLAN-L3-TRM-ANYCAST-RP-FUNC-089',\
                #'VXLAN-L3-TRM-ANYCAST-RP-FUNC-090',\
                #'VXLAN-L3-TRM-ANYCAST-RP-FUNC-091',\
                #'VXLAN-L3-TRM-ANYCAST-RP-FUNC-092',\
                #'VXLAN-L3-TRM-ANYCAST-RP-FUNC-093',\
                #'VXLAN-L3-TRM-ANYCAST-RP-FUNC-094',\
                #'VXLAN-L3-TRM-ANYCAST-RP-FUNC-095',\
                #'VXLAN-L3-TRM-ANYCAST-RP-FUNC-096',\
                #'VXLAN-L3-TRM-ANYCAST-RP-FUNC-097',\
                #'VXLAN-L3-TRM-ANYCAST-RP-FUNC-098',\
                #'VXLAN-L3-TRM-ANYCAST-RP-FUNC-099',\
                #'VXLAN-L3-TRM-ANYCAST-RP-FUNC-100',\
                #'VXLAN-L3-TRM-ANYCAST-RP-FUNC-101',\
                #'VXLAN-L3-TRM-ANYCAST-RP-FUNC-102',\
                #'VXLAN-L3-TRM-ANYCAST-RP-FUNC-103',\
                #'VXLAN-L3-TRM-ANYCAST-RP-FUNC-104',\
                #'VXLAN-L3-TRM-ANYCAST-RP-FUNC-105',\
                #'VXLAN-L3-TRM-ANYCAST-RP-FUNC-106',\
                #'VXLAN-L3-TRM-ANYCAST-RP-FUNC-107',\
                #'VXLAN-L3-TRM-ANYCAST-RP-FUNC-108',\
                #'VXLAN-L3-TRM-ANYCAST-RP-FUNC-109',\ # Uplink as SVI is not supported in Fretta
                #'VXLAN-L3-TRM-ANYCAST-RP-FUNC-110',\
                #'VXLAN-L3-TRM-ANYCAST-RP-FUNC-111',\
                #'VXLAN-L3-TRM-ANYCAST-RP-FUNC-112',\
                #'VXLAN-L3-TRM-ANYCAST-RP-FUNC-113',\
                #'VXLAN-L3-TRM-ANYCAST-RP-FUNC-114',\
                #'VXLAN-L3-TRM-ANYCAST-RP-FUNC-115',\
                #'VXLAN-L3-TRM-ANYCAST-RP-FUNC-116',\
                #'VXLAN-L3-TRM-ANYCAST-RP-FUNC-117',\
                #'VXLAN-L3-TRM-ANYCAST-RP-FUNC-118',\
                ))
