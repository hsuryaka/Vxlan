from pyats.easypy import run
from pyats.datastructures.logic import And, Not, Or
import os

def main():

    tmp_path = os.path.dirname(os.path.abspath(__file__))
    test_path = tmp_path.split('/')
    test_path.pop()
    test_path.append('scripts')
    test_path.append('n9k_vmct_fexAA.py')
    testscript = '/'.join(test_path)
    # run api launches a testscript as an individual task.
    #run(testscript)
    # to run specific testcase
    #run(testscript,uids =Or('common_setup','setupConfigFex'))
    run(testscript,uids =Or('common_setup','setupTgen'))
    #run(testscript,uids =Or('common_setup','setupConfigVxlan','setupConfigVmct','setupConfigFex'))
    # run(testscript,uids =Or('common_setup','setupTgen',\
    #     'VXLAN-VMCT-FexAA-FUNC-001',\
    #     'VXLAN-VMCT-FexAA-FUNC-002',\
    #     'VXLAN-VMCT-FexAA-FUNC-003',\
    #     'VXLAN-VMCT-FexAA-FUNC-004',\
    #     'VXLAN-VMCT-FexAA-FUNC-005',\
    #     'VXLAN-VMCT-FexAA-FUNC-006',\
    #     # 'VXLAN-VMCT-FexAA-FUNC-007',\
    #     'VXLAN-VMCT-FexAA-FUNC-008',\
    #     'VXLAN-VMCT-FexAA-FUNC-009',\
    #     'VXLAN-VMCT-FexAA-FUNC-010',\
    #     'VXLAN-VMCT-FexAA-FUNC-011',\
    #     'VXLAN-VMCT-FexAA-FUNC-012',\
    #     'VXLAN-VMCT-FexAA-FUNC-013',\
    #     'VXLAN-VMCT-FexAA-FUNC-014',\
    #     'VXLAN-VMCT-FexAA-FUNC-015',\
    #     'VXLAN-VMCT-FexAA-FUNC-016',\
    #     'VXLAN-VMCT-FexAA-FUNC-017',\
    #     'VXLAN-VMCT-FexAA-FUNC-018',\
    #     'VXLAN-VMCT-FexAA-FUNC-019',\
    #     'VXLAN-VMCT-FexAA-FUNC-020',\
    #     'VXLAN-VMCT-FexAA-FUNC-021',\
    #     'VXLAN-VMCT-FexAA-FUNC-022',\
    #     'VXLAN-VMCT-FexAA-FUNC-023',\
    #     'VXLAN-VMCT-FexAA-FUNC-024',\
    #     'VXLAN-VMCT-FexAA-FUNC-025',\
    #     'VXLAN-VMCT-FexAA-FUNC-026',\
    #     'VXLAN-VMCT-FexAA-FUNC-027',\
    #     'VXLAN-VMCT-FexAA-FUNC-028',\
    #     'VXLAN-VMCT-FexAA-FUNC-029',\
    #     'VXLAN-VMCT-FexAA-FUNC-030',\
    #     'VMCT-FexAA-OAM-FUNC-031',\
    #     'VMCT-FexAA-OAM-FUNC-032',\
    #     'VMCT-FexAA-OAM-FUNC-033',\
    #     'VMCT-FexAA-OAM-FUNC-034',\
    #     'VMCT-FexAA-OAM-FUNC-035',\
    #     'VMCT-FexAA-OAM-FUNC-036',\
    #     'VMCT-FEXAA-OAM-FUNC-037',\
    #     'VMCT-FEXAA-OAM-FUNC-038',\
    #     'VMCT-FEXAA-OAM-FUNC-039',\
    #     'VMCT-FEXAA-OAM-FUNC-041',\
    #     'VMCT-FEXAA-OAM-FUNC-042',\
    #     'VMCTFEXAA-OAM-FUNC-044',\
    #     'VMCT-FEXAA-OAM-FUNC-045',\
    #     'VMCT-FEXAA-OAM-FUNC-046',\
    #     'VMCT-FEXAA-OAM-FUNC-047',\
    #     'VMCT-FEXAA-OAM-FUNC-048',\
    #     'VMCT-FEXAA-OAM-FUNC-049',\
    #     'VMCT-FEXAA-OAM-FUNC-050',\
    #     'VMCT-FEXAA-OAM-FUNC-051',\
    #     'VMCT-FEXAA-OAM-FUNC-052',\
    #     'VMCT-FEXAA-OAM-FUNC-053',\
    #     'VMCT-FEXAA-OAM-FUNC-054',\
    #     'VMCT-FEXAA-OAM-FUNC-055',\
    #     'VXLAN-VMCT-FexAA-FUNC-056',\
    #     'VXLAN-VMCT-FexAA-FUNC-057',\
    #     'VXLAN-VMCT-FexAA-FUNC-058',\
    #     # 'VXLAN-VMCT-FexAA-FUNC-059',\
    #     # 'VXLAN-VMCT-FexAA-FUNC-060',\
    #     # 'VXLAN-VMCT-FexAA-FUNC-061',\
    #     # 'VXLAN-VMCT-FexAA-FUNC-062',\
    #     ))
