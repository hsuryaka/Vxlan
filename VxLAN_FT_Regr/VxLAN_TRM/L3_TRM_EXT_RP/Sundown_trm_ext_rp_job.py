from pyats.easypy import run
from pyats.datastructures.logic import And, Or, Not
import os

def main():
    tmp_path = os.path.dirname(os.path.abspath(__file__))
    # test_path = tmp_path.split('/')
    # test_path.pop()
    # test_path.append('scripts')
    # test_path.append('sundown_l3trmvpcbl.py')
    testscript = './TRM_EXT_RP_script.py'
    run(testscript, traffic_threshold = 400,tgn_connect = 1,\
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
        config_tgn_conn = 1,\
        config_tgn_interface = 1,\
        
        uids = Or('common_setup',\
                 'VXLAN-L3-TRM-FUNC-002',\
                 'VXLAN-L3-TRM-FUNC-003',\
                 'VXLAN-L3-TRM-FUNC-004',\
                 'VXLAN-L3-TRM-FUNC-005',\
                 'VXLAN-L3-TRM-FUNC-006',\
                 'VXLAN-L3-TRM-FUNC-007',\
                 'VXLAN-L3-TRM-FUNC-008',\
                 'VXLAN-L3-TRM-FUNC-009',\
                 'VXLAN-L3-TRM-FUNC-010',\
                 'VXLAN-L3-TRM-FUNC-011',\
                 'VXLAN-L3-TRM-FUNC-012',\
                 'VXLAN-L3-TRM-FUNC-013',\
                 'VXLAN-L3-TRM-FUNC-004',\
                 'VXLAN-L3-TRM-FUNC-005',\
                 'VXLAN-L3-TRM-FUNC-006',\
                 'VXLAN-L3-TRM-FUNC-007',\
                 'VXLAN-L3-TRM-FUNC-008',\
                 'VXLAN-L3-TRM-FUNC-009',\
                 'VXLAN-L3-TRM-FUNC-010',\
                 'VXLAN-L3-TRM-FUNC-011',\
                 'VXLAN-L3-TRM-FUNC-012',\
                 'VXLAN-L3-TRM-FUNC-013',\
                 'VXLAN-L3-TRM-FUNC-014',\
                 'VXLAN-L3-TRM-FUNC-015',\
                 'VXLAN-L3-TRM-FUNC-016',\
                 'VXLAN-L3-TRM-FUNC-017',\
                 'VXLAN-L3-TRM-FUNC-018',\
                 'VXLAN-L3-TRM-FUNC-019',\
                 'VXLAN-L3-TRM-FUNC-020',\
                 'VXLAN-L3-TRM-FUNC-021',\
                 'VXLAN-L3-TRM-FUNC-022',\
                 'VXLAN-L3-TRM-FUNC-023',\
                 'VXLAN-L3-TRM-FUNC-024',\
                 'VXLAN-L3-TRM-FUNC-025',\
                 'VXLAN-L3-TRM-FUNC-026',\
                 'VXLAN-L3-TRM-FUNC-027',\
                 'VXLAN-L3-TRM-FUNC-028',\
                 'VXLAN-L3-TRM-FUNC-029',\
                 'VXLAN-L3-TRM-FUNC-030',\
                 'VXLAN-L3-TRM-FUNC-031',\
                 'VXLAN-L3-TRM-FUNC-032',\
                  'VXLAN-L3-TRM-FUNC-033',\
                  'VXLAN-L3-TRM-FUNC-034',\
                  'VXLAN-L3-TRM-FUNC-035',\
                  'VXLAN-L3-TRM-FUNC-036',\
                  'VXLAN-L3-TRM-FUNC-037',\
                  'VXLAN-L3-TRM-FUNC-038',\
                  'VXLAN-L3-TRM-FUNC-039',\
                  'VXLAN-L3-TRM-FUNC-040',\
                  'VXLAN-L3-TRM-FUNC-041',\
                  'VXLAN-L3-TRM-FUNC-042',\
                  'VXLAN-L3-TRM-FUNC-043',\
                  'VXLAN-L3-TRM-FUNC-044',\
                  'VXLAN-L3-TRM-FUNC-045',\
                  'VXLAN-L3-TRM-FUNC-046',\
                  'VXLAN-L3-TRM-FUNC-047',\
                  'VXLAN-L3-TRM-FUNC-048',\
                  'VXLAN-L3-TRM-FUNC-049',\
                  'VXLAN-L3-TRM-FUNC-050',\
                  'VXLAN-L3-TRM-FUNC-051',\
                  'VXLAN-L3-TRM-FUNC-052',\
                  'VXLAN-L3-TRM-FUNC-053',\
                  'VXLAN-L3-TRM-FUNC-054',\
                  'VXLAN-L3-TRM-FUNC-055',\
                  'VXLAN-L3-TRM-FUNC-056',\
                  'VXLAN-L3-TRM-FUNC-057',\
                  'VXLAN-L3-TRM-FUNC-058',\
                  'VXLAN-L3-TRM-FUNC-059',\
                  'VXLAN-L3-TRM-FUNC-060',\
                  'VXLAN-L3-TRM-FUNC-061',\
                  'VXLAN-L3-TRM-FUNC-062',\
                  'VXLAN-L3-TRM-FUNC-063',\
                  'VXLAN-L3-TRM-FUNC-064',\
                  'VXLAN-L3-TRM-FUNC-065',\
                  'VXLAN-L3-TRM-FUNC-066',\
                  'VXLAN-L3-TRM-FUNC-067',\
                  'VXLAN-L3-TRM-FUNC-068',\
                  'VXLAN-L3-TRM-FUNC-069',\
                  'VXLAN-L3-TRM-FUNC-070',\
                  'VXLAN-L3-TRM-FUNC-071',\
                  'VXLAN-L3-TRM-FUNC-072',\
                  'VXLAN-L3-TRM-FUNC-073',\
                  'VXLAN-L3-TRM-FUNC-074',\
                  'VXLAN-L3-TRM-FUNC-075',\
                  'VXLAN-L3-TRM-FUNC-076',\
                  'VXLAN-L3-TRM-FUNC-077',\
                  'VXLAN-L3-TRM-FUNC-078',\
                  'VXLAN-L3-TRM-FUNC-079',\
                  'VXLAN-L3-TRM-FUNC-080',\
                  'VXLAN-L3-TRM-FUNC-081',\
                  'VXLAN-L3-TRM-FUNC-082',\
                  'VXLAN-L3-TRM-FUNC-083',\
                 'VXLAN-L3-TRM-FUNC-084',\
                 'VXLAN-L3-TRM-FUNC-085',\
                 'VXLAN-L3-TRM-FUNC-086',\
                 'VXLAN-L3-TRM-FUNC-087',\
                 'VXLAN-L3-TRM-FUNC-088',\
                  'VXLAN-L3-TRM-FUNC-089',\
                  'VXLAN-L3-TRM-FUNC-090',\
                  'VXLAN-L3-TRM-FUNC-091',\
                  'VXLAN-L3-TRM-FUNC-092',\
                  'VXLAN-L3-TRM-FUNC-093',\
                  'VXLAN-L3-TRM-FUNC-094',\
                  'VXLAN-L3-TRM-FUNC-095',\
                  'VXLAN-L3-TRM-FUNC-096',\
                  'VXLAN-L3-TRM-FUNC-097',\
                  'VXLAN-L3-TRM-FUNC-098',\
                  'VXLAN-L3-TRM-FUNC-099',\
                  'VXLAN-L3-TRM-FUNC-100',\
                  'VXLAN-L3-TRM-FUNC-101',\
                  'VXLAN-L3-TRM-FUNC-102',\
                  'VXLAN-L3-TRM-FUNC-103',\
                  'VXLAN-L3-TRM-FUNC-104',\
                  'VXLAN-L3-TRM-FUNC-105',\
                   'VXLAN-L3-TRM-FUNC-106',\
                   'VXLAN-L3-TRM-FUNC-107',\
                   'VXLAN-L3-TRM-FUNC-108',\
                   'VXLAN-L3-TRM-FUNC-109',\
                   'VXLAN-L3-TRM-FUNC-110',\
                   'VXLAN-L3-TRM-FUNC-111',\
                   'VXLAN-L3-TRM-FUNC-112',\
                   'VXLAN-L3-TRM-FUNC-113',\
                   'VXLAN-L3-TRM-FUNC-114',\
                   'VXLAN-L3-TRM-FUNC-115',\
                   'VXLAN-L3-TRM-FUNC-116',\
                   'VXLAN-L3-TRM-FUNC-117',\
                   'VXLAN-L3-TRM-FUNC-118',\
                   'VXLAN-L3-TRM-FUNC-119',\
                   'VXLAN-L3-TRM-FUNC-120',\
                   'VXLAN-L3-TRM-FUNC-121',\
                   'VXLAN-L3-TRM-FUNC-122',\
                   'VXLAN-L3-TRM-FUNC-123',\
                ))
