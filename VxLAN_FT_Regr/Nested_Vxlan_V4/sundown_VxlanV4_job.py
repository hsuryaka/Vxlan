from pyats.easypy import run
from pyats.datastructures.logic import And, Or, Not
import os

def main():
    tmp_path = os.path.dirname(os.path.abspath(__file__))
    #test_path = tmp_path.split('/')
    #test_path.pop()
    #test_path.append('scripts')
    #test_path.append('sundown_VxlanV6.py')
    testscript = './sundown_VxlanV4.py'
    run(testscript, traffic_threshold = 10,tgn_connect = 1,\
        config_interface = 1,\
        config_ospf = 1,\
        config_ospfv3 = 0,\
        config_bgp = 1,\
        config_vpc = 1,\
        config_vxlan_global = 1,\
        config_bgp_global = 1, \
        config_vlan = 1,\
        config_vrf = 1,\
        config_svi = 1,\
        config_evpn = 1,\
        config_nve_global = 1,\
        config_nve_l2vni = 1,\
        config_nve_l3vni = 1,\
        config_tgn_conn = 1,\
        config_tgn_interface = 1,\
        
        uids = Or('common_setup',\
#                 'VXLAN-L3-VxlanV6-FUNC-001',\
#                 'VXLAN-L3-VxlanV6-FUNC-002',\
#                 'VXLAN-L3-VxlanV6-FUNC-003',\
#                 'VXLAN-L3-VxlanV6-FUNC-004',\
#                 'VXLAN-L3-VxlanV6-FUNC-005',\
#                 'VXLAN-L3-VxlanV6-FUNC-006',\
#                 'VXLAN-L3-VxlanV6-FUNC-007',\
#                 'VXLAN-L3-VxlanV6-FUNC-008',\
#                 'VXLAN-L3-VxlanV6-FUNC-009',\
#                 'VXLAN-L3-VxlanV6-FUNC-010',\
#                 'VXLAN-L3-VxlanV6-FUNC-011',\
#                 'VXLAN-L3-VxlanV6-FUNC-012',\
#                 'VXLAN-L3-VxlanV6-FUNC-013',\
#                 'VXLAN-L3-VxlanV6-FUNC-014',\
#                 'VXLAN-L3-VxlanV6-FUNC-015',\
#                 'VXLAN-L3-VxlanV6-FUNC-016',\
#                 'VXLAN-L3-VxlanV6-FUNC-017',\
#                 'VXLAN-L3-VxlanV6-FUNC-018',\
#                 'VXLAN-L3-VxlanV6-FUNC-019',\
#                 'VXLAN-L3-VxlanV6-FUNC-020',\
#                 'VXLAN-L3-VxlanV6-FUNC-021',\
#                 'VXLAN-L3-VxlanV6-FUNC-022',\
#                 'VXLAN-L3-VxlanV6-FUNC-023',\
#                 'VXLAN-L3-VxlanV6-FUNC-024',\
#                 'VXLAN-L3-VxlanV6-FUNC-025',\
#                 'VXLAN-L3-VxlanV6-FUNC-026',\
#                 'VXLAN-L3-VxlanV6-FUNC-027',\
#                 'VXLAN-L3-VxlanV6-FUNC-028',\
#                 'VXLAN-L3-VxlanV6-FUNC-029',\
#                 'VXLAN-L3-VxlanV6-FUNC-030',\
#                 'VXLAN-L3-VxlanV6-FUNC-031',\
#                 'VXLAN-L3-VxlanV6-FUNC-032',\
#                 'VXLAN-L3-VxlanV6-FUNC-033',\
#                 'VXLAN-L3-VxlanV6-FUNC-034',\
#                 'VXLAN-L3-VxlanV6-FUNC-035',\
#                 'VXLAN-L3-VxlanV6-FUNC-036',\
#                 'VXLAN-L3-VxlanV6-FUNC-037',\
#                 'VXLAN-L3-VxlanV6-FUNC-038',\
#                 'VXLAN-L3-VxlanV6-FUNC-039',\
#                 'VXLAN-L3-VxlanV6-FUNC-040',\
#                 'VXLAN-L3-VxlanV6-FUNC-041',\
#                 'VXLAN-L3-VxlanV6-FUNC-042',\
#                 'VXLAN-L3-VxlanV6-FUNC-043',\
#                 'VXLAN-L3-VxlanV6-FUNC-044',\
#                 'VXLAN-L3-VxlanV6-FUNC-045',\
#                 'VXLAN-L3-VxlanV6-FUNC-046',\
#                 'VXLAN-L3-VxlanV6-FUNC-047',\
#                 'VXLAN-L3-VxlanV6-FUNC-048',\
#                 'VXLAN-L3-VxlanV6-FUNC-049',\
#                 'VXLAN-L3-VxlanV6-FUNC-050',\
#                 'VXLAN-L3-VxlanV6-FUNC-051',\
#                 'VXLAN-L3-VxlanV6-FUNC-052',\
#                 'VXLAN-L3-VxlanV6-FUNC-053',\
#                 'VXLAN-L3-VxlanV6-FUNC-054',\
#                 'VXLAN-L3-VxlanV6-FUNC-055',\
#                 'VXLAN-L3-VxlanV6-FUNC-056',\
#                 'VXLAN-L3-VxlanV6-FUNC-057',\
#                 'VXLAN-L3-VxlanV6-FUNC-058',\
#                 'VXLAN-L3-VxlanV6-FUNC-059',\
#                 'VXLAN-L3-VxlanV6-FUNC-060',\
#                 'VXLAN-L3-VxlanV6-FUNC-061',\
#                 'VXLAN-L3-VxlanV6-FUNC-062',\
#                 'VXLAN-L3-VxlanV6-FUNC-063',\
#                 'VXLAN-L3-VxlanV6-FUNC-064',\
#                 'VXLAN-L3-VxlanV6-FUNC-065',\
#                 'VXLAN-L3-VxlanV6-FUNC-066',\
#                 'VXLAN-L3-VxlanV6-FUNC-067',\
#                 'VXLAN-L3-VxlanV6-FUNC-068',\
#                 'VXLAN-L3-VxlanV6-FUNC-069',\
#                 'VXLAN-L3-VxlanV6-FUNC-070',\
#                 'VXLAN-L3-VxlanV6-FUNC-071',\
#                 'VXLAN-L3-VxlanV6-FUNC-072',\
#                 'VXLAN-L3-VxlanV6-FUNC-073',\
#                 'VXLAN-L3-VxlanV6-FUNC-074',\
#                 'VXLAN-L3-VxlanV6-FUNC-075',\
#                 'VXLAN-L3-VxlanV6-FUNC-076',\
#                 'VXLAN-L3-VxlanV6-FUNC-077',\
#                 'VXLAN-L3-VxlanV6-FUNC-078',\
#                 'VXLAN-L3-VxlanV6-FUNC-079',\
#                 'VXLAN-L3-VxlanV6-FUNC-080',\
#                 'VXLAN-L3-VxlanV6-FUNC-081',\
#                 'VXLAN-L3-VxlanV6-FUNC-082',\
#                 'VXLAN-L3-VxlanV6-FUNC-083',\
#                 'VXLAN-L3-VxlanV6-FUNC-084',\
#                 'VXLAN-L3-VxlanV6-FUNC-085',\
#                 'VXLAN-L3-VxlanV6-FUNC-086',\
#                 'VXLAN-L3-VxlanV6-FUNC-087',\
#                 'VXLAN-L3-VxlanV6-FUNC-088',\
#                 'VXLAN-L3-VxlanV6-FUNC-089',\
#                 'VXLAN-L3-VxlanV6-FUNC-090',\
#                 'VXLAN-L3-VxlanV6-FUNC-091',\
#                 'VXLAN-L3-VxlanV6-FUNC-092',\
#                 'VXLAN-L3-VxlanV6-FUNC-093',\
#                 'VXLAN-L3-VxlanV6-FUNC-094',\
#                 'VXLAN-L3-VxlanV6-FUNC-095',\
#                 'VXLAN-L3-VxlanV6-FUNC-096',\
#                 'VXLAN-L3-VxlanV6-FUNC-097',\
#                 'VXLAN-L3-VxlanV6-FUNC-098',\
#                 'VXLAN-L3-VxlanV6-FUNC-099',\
#                 'VXLAN-L3-VxlanV6-FUNC-100',\
#                 'VXLAN-L3-VxlanV6-FUNC-101',\
#                 'VXLAN-L3-VxlanV6-FUNC-102',\
#                 'VXLAN-L3-VxlanV6-FUNC-103',\
#                 'VXLAN-L3-VxlanV6-FUNC-104',\
#                 'VXLAN-L3-VxlanV6-FUNC-105',\
#                 'VXLAN-L3-VxlanV6-FUNC-106',\
#                 'VXLAN-L3-VxlanV6-FUNC-107',\
#                 'VXLAN-L3-VxlanV6-FUNC-108',\
#                 'VXLAN-L3-VxlanV6-FUNC-109',\
#                 'VXLAN-L3-VxlanV6-FUNC-110',\
#                 'VXLAN-L3-VxlanV6-FUNC-111',\
                'VXLAN-L3-VxlanV6-FUNC-112',\
                'VXLAN-L3-VxlanV6-FUNC-113',\
                'VXLAN-L3-VxlanV6-FUNC-114',\
                'VXLAN-L3-VxlanV6-FUNC-115',\
                'VXLAN-L3-VxlanV6-FUNC-116',\
                'VXLAN-L3-VxlanV6-FUNC-117',\
                'VXLAN-L3-VxlanV6-FUNC-118',\
                'VXLAN-L3-VxlanV6-FUNC-119',\
                'VXLAN-L3-VxlanV6-FUNC-120',\
                'VXLAN-L3-VxlanV6-FUNC-121',\
                'VXLAN-L3-VxlanV6-FUNC-122',\
                'VXLAN-L3-VxlanV6-FUNC-123',\
                'VXLAN-L3-VxlanV6-FUNC-124',\
                 'VXLAN-L3-VxlanV6-FUNC-125',\
                'VXLAN-L3-VxlanV6-FUNC-126',\
                 'VXLAN-L3-VxlanV6-FUNC-127',\
                'VXLAN-L3-VxlanV6-FUNC-128',\
                'VXLAN-L3-VxlanV6-FUNC-129',\
                'VXLAN-L3-VxlanV6-FUNC-130',\
                'VXLAN-L3-VxlanV6-FUNC-131',\
                 'VXLAN-L3-VxlanV6-FUNC-132',\
                 'VXLAN-L3-VxlanV6-FUNC-133',\
                 'VXLAN-L3-VxlanV6-FUNC-134',\
                'VXLAN-L3-VxlanV6-FUNC-135',\
                'VXLAN-L3-VxlanV6-FUNC-136',\
                'VXLAN-L3-VxlanV6-FUNC-137',\
                'VXLAN-L3-VxlanV6-FUNC-138',\
                 'VXLAN-L3-VxlanV6-FUNC-139',\
#                 'VXLAN-L3-VxlanV6-FUNC-140',\
#                 'VXLAN-L3-VxlanV6-FUNC-141',\
#                 'VXLAN-L3-VxlanV6-FUNC-142',\
#                 'VXLAN-L3-VxlanV6-FUNC-143',\
#                 'VXLAN-L3-VxlanV6-FUNC-144',\
#                 'VXLAN-L3-VxlanV6-FUNC-145',\
#                 'VXLAN-L3-VxlanV6-FUNC-146',\
#                 'VXLAN-L3-VxlanV6-FUNC-147',\
#                 'VXLAN-L3-VxlanV6-FUNC-148',\
#                'VXLAN-L3-VxlanV6-FUNC-149',\
                ))
