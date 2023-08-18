from pyats.easypy import run
from pyats.datastructures.logic import And, Not, Or
import os

def main():

    tmp_path = os.path.dirname(os.path.abspath(__file__))
    test_path = tmp_path.split('/')
    test_path.pop()
    test_path.append('scripts')
    test_path.append('n9k_vmct_fexST.py')
    testscript = '/'.join(test_path)
    # run api launches a testscript as an individual task.
    #run(testscript)
    # to run specific testcase
    run(testscript,uids =Or('common_setup','setupTgen',\
    # 'VXLAN-VMCT-FexST-FUNC-001',\
    # 'VXLAN-VMCT-FexST-FUNC-002',\
    # 'VXLAN-VMCT-FexST-FUNC-003',\
    # 'VXLAN-VMCT-FexST-FUNC-004',\
    # 'VXLAN-VMCT-FexST-FUNC-005',\
    # 'VXLAN-VMCT-FexST-FUNC-006',\
    # 'VXLAN-VMCT-FexST-FUNC-007',\
    # 'VXLAN-VMCT-FexST-FUNC-008',\
    # 'VXLAN-VMCT-FexST-FUNC-009',\
    # 'VXLAN-VMCT-FexST-FUNC-010',\
    # 'VXLAN-VMCT-FexST-FUNC-011',\
    # 'VXLAN-VMCT-FexST-FUNC-012',\
    # 'VXLAN-VMCT-FexST-FUNC-013',\
    # 'VXLAN-VMCT-FexST-FUNC-014',\
    # 'VXLAN-VMCT-FexST-FUNC-015',\
    # 'VXLAN-VMCT-FexST-FUNC-016',\
    # 'VXLAN-VMCT-FexST-FUNC-017',\
    # 'VXLAN-VMCT-FexST-FUNC-018',\
    # 'VXLAN-VMCT-FexST-FUNC-019',\
    # 'VXLAN-VMCT-FexST-FUNC-020',\
    # 'VXLAN-VMCT-FexST-FUNC-021',\
    # 'VXLAN-VMCT-FexST-FUNC-022',\
    # 'VXLAN-VMCT-FexST-FUNC-023',\
    # 'VXLAN-VMCT-FexST-FUNC-024',\
    # 'VXLAN-VMCT-FexST-FUNC-025',\
    # 'VXLAN-VMCT-FexST-FUNC-026',\
    # 'VXLAN-VMCT-FexST-FUNC-027',\
    # 'VXLAN-VMCT-FexST-FUNC-028',\
    'VXLAN-VMCT-FexST-FUNC-029',\
    'VXLAN-VMCT-FexST-FUNC-030',\
    'VMCT-FEXST-OAM-FUNC-031',\
    'VMCT-FEXST-OAM-FUNC-032',\
    'VMCT-FEXST-OAM-FUNC-033',\
    'VMCT-FEXST-OAM-FUNC-034',\
    'VMCT-FEXST-OAM-FUNC-035',\
    'VMCT-FEXST-OAM-FUNC-036',\
    'VMCT-FEXST-OAM-FUNC-037',\
    # 'VMCT-FEXST-OAM-FUNC-038',\
    # 'VMCT-FEXST-OAM-FUNC-039',\
    # 'VMCT-FEXST-OAM-FUNC-040',\
    # 'VMCT-FEXST-OAM-FUNC-041',\
    # 'VMCT-FEXST-OAM-FUNC-042',\
    # 'VMCT-FEXST-OAM-FUNC-043',\
    # 'VMCT-FEXST-OAM-FUNC-044',\
    # 'VMCT-FEXST-OAM-FUNC-045',\
    # 'VMCT-FEXST-OAM-FUNC-046',\
    # 'VMCT-FEXST-OAM-FUNC-047',\
    # 'VMCT-FEXST-OAM-FUNC-048',\
    # 'VMCT-FEXST-OAM-FUNC-049',\
    'VMCT-FEXST-OAM-FUNC-050',\
    'VMCT-FEXST-OAM-FUNC-051',\
    'VMCT-FEXST-OAM-FUNC-052',\
    'VMCT-FEXST-OAM-FUNC-053',\
    'VMCT-FEXST-OAM-FUNC-054',\
    'VMCT-FEXST-OAM-FUNC-055',\
    'VXLAN-VMCT-FexST-FUNC-056',\
    'VXLAN-VMCT-FexST-FUNC-057',\
    'VXLAN-VMCT-FexST-FUNC-058',\
    'VXLAN-VMCT-FexST-FUNC-059',\
    'VXLAN-VMCT-FexST-FUNC-060',\
    'VXLAN-VMCT-FexST-FUNC-061',\
    'VXLAN-VMCT-FexST-FUNC-062',\
    ))
    #run(testscript,uids =Or('common_setup','setupConfigVxlan','setupConfigVmct','setupConfigFex'))
