from pyats.easypy import run
from pyats.datastructures.logic import And, Or, Not
import os

def main():
    tmp_path = os.path.dirname(os.path.abspath(__file__))
    test_path = tmp_path.split('/')
    test_path.pop()
    test_path.append('scripts')
    test_path.append('CloudSec_MS_script.py')
    testscript = '/'.join(test_path)
    run(testscript, traffic_threshold = 10,tgn_connect = 1,\
        config_interface            = 1,\
        config_ospf                 = 1,\
        config_ospfv3               = 0,\
        config_bgp                  = 1,\
        config_vpc                  = 0,\
        config_pim                  = 0,\
        config_vxlan_global         = 1,\
        config_bgp_global           = 1, \
        config_vlan                 = 1,\
        config_vrf                  = 1,\
        config_svi                  = 1,\
        config_evpn                 = 1,\
        config_nve_global           = 1,\
        config_nve_l2vni            = 1,\
        config_nve_l3vni            = 1,\
        config_sub_intf             = 0,\
        config_loopback_intf        = 0,\
        config_ospf_router_id       = 0,\
        config_route_map            = 1,\
        config_multisite            = 1,\
        config_tunnel_encryption    = 1,\
        config_tgn_conn             = 1,\
        config_tgn_interface        = 1,\
        
        uids = Or('common_setup',\
                        # 'VXLAN-CS-FUNC-001',
                        # 'VXLAN-CS-FUNC-002',\
                        # 'VXLAN-CS-FUNC-003',\
                        # 'VXLAN-CS-FUNC-004',\
                        # 'VXLAN-CS-FUNC-005',\
                        # 'VXLAN-CS-FUNC-006',\
                        # 'VXLAN-CS-FUNC-007',\
                        # 'VXLAN-CS-FUNC-008',\
                        # 'VXLAN-CS-FUNC-009',\
                        # 'VXLAN-CS-FUNC-010',\
                             # 'VXLAN-CS-FUNC-011',\
                             # 'VXLAN-CS-FUNC-012',\
                             # 'VXLAN-CS-FUNC-013',\
                             # 'VXLAN-CS-FUNC-014',\
                             # 'VXLAN-CS-FUNC-015',\
                             # 'VXLAN-CS-FUNC-016',\
                             # 'VXLAN-CS-FUNC-017',\
                             # 'VXLAN-CS-FUNC-018',\
                             # 'VXLAN-CS-FUNC-019',\
                             # 'VXLAN-CS-FUNC-020',\
                             # 'VXLAN-CS-FUNC-021',\
                             # 'VXLAN-CS-FUNC-022',\
                             # 'VXLAN-CS-FUNC-023',\
                             # 'VXLAN-CS-FUNC-024',\
                             # 'VXLAN-CS-FUNC-025',\
                             # 'VXLAN-CS-FUNC-026',\
                             # 'VXLAN-CS-FUNC-027',
                             # 'VXLAN-CS-FUNC-028',
                             # 'VXLAN-CS-FUNC-029',
                             # 'VXLAN-CS-FUNC-030',\
                             # 'VXLAN-CS-FUNC-031',\
                             #  'VXLAN-CS-FUNC-032',\
                            #   'VXLAN-CS-FUNC-033',\
                            #    'VXLAN-CS-FUNC-034',\
                            #    'VXLAN-CS-FUNC-035',\
                            #  'VXLAN-CS-FUNC-036',\
                            #   'VXLAN-CS-FUNC-037',\
                            #  'VXLAN-CS-FUNC-038',\
                            #  'VXLAN-CS-FUNC-039',\
                            #  'VXLAN-CS-FUNC-040',\
                            #   'VXLAN-CS-FUNC-041',\
                            #  'VXLAN-CS-FUNC-042',\
                            #  'VXLAN-CS-FUNC-043',\
                            #  'VXLAN-CS-FUNC-044',\
                            #  'VXLAN-CS-FUNC-045',\
                            #  'VXLAN-CS-FUNC-046',\
                            #  'VXLAN-CS-FUNC-047',\
                            #  'VXLAN-CS-FUNC-048',\
                            #  'VXLAN-CS-FUNC-049',\
                            # 'VXLAN-CS-FUNC-050',\
                            #  'VXLAN-CS-FUNC-051',\
                             # 'VXLAN-CS-FUNC-052',\
                             # 'VXLAN-CS-FUNC-053',\
                             # 'VXLAN-CS-FUNC-054',\
                             # 'VXLAN-CS-FUNC-055',\
                             # 'VXLAN-CS-FUNC-056',\
                             # 'VXLAN-CS-FUNC-057',\
                             # 'VXLAN-CS-FUNC-058',\
                             # 'VXLAN-CS-FUNC-059',\
                             # 'VXLAN-CS-FUNC-060',\
                       #      'VXLAN-CS-FUNC-061',\
                       #      'VXLAN-CS-FUNC-062',\
                       #     'VXLAN-CS-FUNC-063',\
                       #    'VXLAN-CS-FUNC-064',\
                       #      'VXLAN-CS-FUNC-065',\
                       #      'VXLAN-CS-FUNC-066',\
                       #      'VXLAN-CS-FUNC-067',\
                       #      'VXLAN-CS-FUNC-068',\
                       #      'VXLAN-CS-FUNC-069',\v
                       #      'VXLAN-CS-FUNC-070',\
                       #     'VXLAN-CS-FUNC-071',\
                       #     'VXLAN-CS-FUNC-072',\
                       #     'VXLAN-CS-FUNC-073',\
                       #     'VXLAN-CS-FUNC-074',\
                       #     'VXLAN-CS-FUNC-075',\
                       #     'VXLAN-CS-FUNC-076',\
                       #     'VXLAN-CS-FUNC-077',\
                       #     'VXLAN-CS-FUNC-078',\
                       #     'VXLAN-CS-FUNC-079',\
                       #     'VXLAN-CS-FUNC-080',\
                       #     'VXLAN-CS-FUNC-081',\
                       #     'VXLAN-CS-FUNC-082',\
                       #     'VXLAN-CS-FUNC-083',\
                       #     'VXLAN-CS-FUNC-084',\
                       #     'VXLAN-CS-FUNC-085',\
                       #     'VXLAN-CS-FUNC-086',\
                       #     'VXLAN-CS-FUNC-087',\
                       #     'VXLAN-CS-FUNC-088',\
                       #     'VXLAN-CS-FUNC-089',\
                       #     'VXLAN-CS-FUNC-090',\
                       #     'VXLAN-CS-FUNC-091',\
                       #     'VXLAN-CS-FUNC-092',\
                       #     'VXLAN-CS-FUNC-093',\
                       #     'VXLAN-CS-FUNC-094',\
                       #     'VXLAN-CS-FUNC-095',\
                       #     'VXLAN-CS-FUNC-096',\
                       #     'VXLAN-CS-FUNC-097',\
                       #     'VXLAN-CS-FUNC-098',\
                       #     'VXLAN-CS-FUNC-099',\
                       #     'VXLAN-CS-FUNC-100',\
                       #     'VXLAN-CS-FUNC-101',\
                       #     'VXLAN-CS-FUNC-102',\
                       #     'VXLAN-CS-FUNC-103',\
                       #     'VXLAN-CS-FUNC-104',\
                       #     'VXLAN-CS-FUNC-105',\
                       #     'VXLAN-CS-FUNC-106',\
                       #     'VXLAN-CS-FUNC-107',\
                       #     'VXLAN-CS-FUNC-108',\
                       #     'VXLAN-CS-FUNC-109',\
                       #     'VXLAN-CS-FUNC-110',\
                       #     'VXLAN-CS-FUNC-111',\
                       #     'VXLAN-CS-FUNC-112',\
                       #     'VXLAN-CS-FUNC-113',\
                       #     'VXLAN-CS-FUNC-114',\
                       #     'VXLAN-CS-FUNC-115',\
                       #     'VXLAN-CS-FUNC-116',\
                       #     'VXLAN-CS-FUNC-117',\
                       #     'VXLAN-CS-FUNC-118',\
                       #     'VXLAN-CS-FUNC-119',\
                       #     'VXLAN-CS-FUNC-120',\
                       #     'VXLAN-CS-FUNC-121',\
                       #     'VXLAN-CS-FUNC-122',\
                       #     'VXLAN-CS-FUNC-123',\
                       #     'VXLAN-CS-FUNC-124',\
                       #       'VXLAN-CS-FUNC-125',\
                       #        'VXLAN-CS-FUNC-126',\
                       #        'VXLAN-CS-FUNC-127',\
                       #        'VXLAN-CS-FUNC-128',\
                       #        'VXLAN-CS-FUNC-129',\
                       #        'VXLAN-CS-FUNC-130',\
                       #        'VXLAN-CS-FUNC-131',\
                       #        'VXLAN-CS-FUNC-132',\
                       #        'VXLAN-CS-FUNC-133',\
                       #        'VXLAN-CS-FUNC-134',\
                       #        'VXLAN-CS-FUNC-135',\
                       #        'VXLAN-CS-FUNC-136',\
                       # 'VXLAN-CS-FUNC-137',\
                       # 'VXLAN-CS-FUNC-138',\
                       # 'VXLAN-CS-FUNC-139',\
                       # 'VXLAN-CS-FUNC-140',\
                       # 'VXLAN-CS-FUNC-141',\
                       # 'VXLAN-CS-FUNC-142',\
                       # 'VXLAN-CS-FUNC-143',\
                       # 'VXLAN-CS-FUNC-144',\
                       # 'VXLAN-CS-FUNC-145',\
                       # 'VXLAN-CS-FUNC-146',\
                       # 'VXLAN-CS-FUNC-147',\
#                 'VXLAN-L3-TRM-VPC-BL-FUNC-002',\
#                 'VXLAN-L3-TRM-VPC-BL-FUNC-003',\
#                 'VXLAN-L3-TRM-VPC-BL-FUNC-004',\
#                 'VXLAN-L3-TRM-VPC-BL-FUNC-005',\
#                 'VXLAN-L3-TRM-VPC-BL-FUNC-006',\
#                 'VXLAN-L3-TRM-VPC-BL-FUNC-007',\
#                 'VXLAN-L3-TRM-VPC-BL-FUNC-008',\
#                 'VXLAN-L3-TRM-VPC-BL-FUNC-009',\
#                 'VXLAN-L3-TRM-VPC-BL-FUNC-010',\
#                 'VXLAN-L3-TRM-VPC-BL-FUNC-011',\
#                 'VXLAN-L3-TRM-VPC-BL-FUNC-012',\
#                 'VXLAN-L3-TRM-VPC-BL-FUNC-013',\
#                 'VXLAN-L3-TRM-VPC-BL-FUNC-014',\
#                 'VXLAN-L3-TRM-VPC-BL-FUNC-015',\
#                 'VXLAN-L3-TRM-VPC-BL-FUNC-016',\
#                 'VXLAN-L3-TRM-VPC-BL-FUNC-017',\
#                 'VXLAN-L3-TRM-VPC-BL-FUNC-018',\
#                 'VXLAN-L3-TRM-VPC-BL-FUNC-019',\
#                 'VXLAN-L3-TRM-VPC-BL-FUNC-020',\
#                 'VXLAN-L3-TRM-VPC-BL-FUNC-021',\
#                 'VXLAN-L3-TRM-VPC-BL-FUNC-022',\
#                 'VXLAN-L3-TRM-VPC-BL-FUNC-023',\
#                 'VXLAN-L3-TRM-VPC-BL-FUNC-024',\
#                 'VXLAN-L3-TRM-VPC-BL-FUNC-025',\
#                 'VXLAN-L3-TRM-VPC-BL-FUNC-026',\
#                 'VXLAN-L3-TRM-VPC-BL-FUNC-027',\
#                 'VXLAN-L3-TRM-VPC-BL-FUNC-028',\
#                 'VXLAN-L3-TRM-VPC-BL-FUNC-029',\
#                 'VXLAN-L3-TRM-VPC-BL-FUNC-030',\
#                 'VXLAN-L3-TRM-VPC-BL-FUNC-031',\
#                 'VXLAN-L3-TRM-VPC-BL-FUNC-032',\
#                 'VXLAN-L3-TRM-VPC-BL-FUNC-033',\
#                 'VXLAN-L3-TRM-VPC-BL-FUNC-034',\
#                 'VXLAN-L3-TRM-VPC-BL-FUNC-035',\
#                 'VXLAN-L3-TRM-VPC-BL-FUNC-036',\
#                 'VXLAN-L3-TRM-VPC-BL-FUNC-037',\
#                 'VXLAN-L3-TRM-VPC-BL-FUNC-038',\
#                 'VXLAN-L3-TRM-VPC-BL-FUNC-039',\
#                 'VXLAN-L3-TRM-VPC-BL-FUNC-040',\
#                 'VXLAN-L3-TRM-VPC-BL-FUNC-041',\
#                 'VXLAN-L3-TRM-VPC-BL-FUNC-042',\
#                 'VXLAN-L3-TRM-VPC-BL-FUNC-043',\
#                 'VXLAN-L3-TRM-VPC-BL-FUNC-044',\
#                 'VXLAN-L3-TRM-VPC-BL-FUNC-045',\
#                 'VXLAN-L3-TRM-VPC-BL-FUNC-046',\
#                 'VXLAN-L3-TRM-VPC-BL-FUNC-047',\
#                 'VXLAN-L3-TRM-VPC-BL-FUNC-048',\
#                 'VXLAN-L3-TRM-VPC-BL-FUNC-049',\
#                 'VXLAN-L3-TRM-VPC-BL-FUNC-050',\
#                 'VXLAN-L3-TRM-VPC-BL-FUNC-051',\
#                 'VXLAN-L3-TRM-VPC-BL-FUNC-052',\
#                 'VXLAN-L3-TRM-VPC-BL-FUNC-053',\
#                 'VXLAN-L3-TRM-VPC-BL-FUNC-054',\
#                 'VXLAN-L3-TRM-VPC-BL-FUNC-055',\
#                 'VXLAN-L3-TRM-VPC-BL-FUNC-056',\
#                 'VXLAN-L3-TRM-VPC-BL-FUNC-057',\
#                 'VXLAN-L3-TRM-VPC-BL-FUNC-058',\
#                 'VXLAN-L3-TRM-VPC-BL-FUNC-059',\
#                 'VXLAN-L3-TRM-VPC-BL-FUNC-060',\
#                 'VXLAN-L3-TRM-VPC-BL-FUNC-061',\
#                 'VXLAN-L3-TRM-VPC-BL-FUNC-062',\
#                 'VXLAN-L3-TRM-VPC-BL-FUNC-063',\
#                 'VXLAN-L3-TRM-VPC-BL-FUNC-064',\
#                 'VXLAN-L3-TRM-VPC-BL-FUNC-065',\
#                 'VXLAN-L3-TRM-VPC-BL-FUNC-066',\
#                 'VXLAN-L3-TRM-VPC-BL-FUNC-067',\
#                 'VXLAN-L3-TRM-VPC-BL-FUNC-068',\
#                 'VXLAN-L3-TRM-VPC-BL-FUNC-069',\
#                 'VXLAN-L3-TRM-VPC-BL-FUNC-070',\
                ))