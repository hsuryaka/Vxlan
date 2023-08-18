from pyats.easypy import run
from pyats.datastructures.logic import And, Not, Or
import os

def main():

    tmp_path = os.path.dirname(os.path.abspath(__file__))
    #test_path = tmp_path.split('/')
    #test_path.pop()
    #test_path.append('scripts')
    #test_path.append('n9k_vmct_IR.py')
    #testscript = '/'.join(test_path)
    testscript = '/ws/pkanduri-bgl/N9K_Scripts_Porting/VMCT_V6/n9k_vmct_V6_IR.py'
    # run api launches a testscript as an individual task.
    #run(testscript)
    # to run specific testcase
    #run(testscript,uids =Or('common_setup','setupConfigVxlan','setupConfigVmct'))
    run(testscript,uids =Or('common_setup','setupTgen',\
                             'VXLAN-VMCT-IR-FUNC-001',\
                             'VXLAN-VMCT-IR-FUNC-002',\
                             'VXLAN-VMCT-IR-FUNC-003',\
                             'VXLAN-VMCT-IR-FUNC-004',\
                             'VXLAN-VMCT-IR-FUNC-005',\
                             'VXLAN-VMCT-IR-FUNC-006',\
	                     'VXLAN-VMCT-IR-FUNC-007',\
                             'VXLAN-VMCT-IR-FUNC-008',\
                             'VXLAN-VMCT-IR-FUNC-009',\
                             'VXLAN-VMCT-IR-FUNC-010',\
                             'VXLAN-VMCT-IR-FUNC-011',\
                             'VXLAN-VMCT-IR-FUNC-012',\
                             'VXLAN-VMCT-IR-FUNC-013',\
                             'VXLAN-VMCT-IR-FUNC-014',\
                             'VXLAN-VMCT-IR-FUNC-015',\
                             'VXLAN-VMCT-IR-FUNC-016',\
                             'VXLAN-VMCT-IR-FUNC-017',\
                             'VXLAN-VMCT-IR-FUNC-018',\
                             'VXLAN-VMCT-IR-FUNC-019',\
                             'VXLAN-VMCT-IR-FUNC-020',\
                             'VXLAN-VMCT-IR-FUNC-021',\
                             'VXLAN-VMCT-IR-FUNC-022',\
                             'VXLAN-VMCT-IR-FUNC-023',\
                             'VXLAN-VMCT-IR-FUNC-024',\
                             'VXLAN-VMCT-IR-FUNC-025',\
                             'VXLAN-VMCT-IR-FUNC-026',\
                             'VXLAN-VMCT-IR-FUNC-027',\
                             'VXLAN-VMCT-IR-FUNC-028',\
                             'VXLAN-VMCT-IR-FUNC-029',\
                             'VXLAN-VMCT-IR-FUNC-030',\
                             'VXLAN-VMCT-IR-FUNC-031',\
                             'VXLAN-VMCT-IR-FUNC-032',\
                             'VXLAN-VMCT-IR-FUNC-058',\
                             'VXLAN-VMCT-IR-FUNC-059',\
                             'VXLAN-VMCT-IR-FUNC-060',\
                             'VXLAN-VMCT-IR-FUNC-061'))
