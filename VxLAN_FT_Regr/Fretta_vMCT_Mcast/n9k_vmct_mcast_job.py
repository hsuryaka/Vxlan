from pyats.easypy import run
from pyats.datastructures.logic import And, Not, Or
import os

def main():

    tmp_path = os.path.dirname(os.path.abspath(__file__))
    test_path = tmp_path.split('/')
    test_path.pop()
    test_path.append('scripts')
    test_path.append('n9k_vmct_mcast.py')
    testscript = '/'.join(test_path)
    # run api launches a testscript as an individual task.
    #run(testscript)
    # to run specific testcase
    run(testscript,uids =Or('common_setup','setupConfigVxlan','setupConfigVmct','setupTgen',\
			'VXLAN-VMCT-MCAST-FUNC-001',\
			'VXLAN-VMCT-MCAST-FUNC-002',\
			'VXLAN-VMCT-MCAST-FUNC-003',\
			'VXLAN-VMCT-MCAST-FUNC-004',\
			'VXLAN-VMCT-MCAST-FUNC-005',\
			'VXLAN-VMCT-MCAST-FUNC-006',\
			'VXLAN-VMCT-MCAST-FUNC-007',\
			'VXLAN-VMCT-MCAST-FUNC-008',\
			'VXLAN-VMCT-MCAST-FUNC-009',\
			'VXLAN-VMCT-MCAST-FUNC-010',\
			'VXLAN-VMCT-MCAST-FUNC-011',\
			'VXLAN-VMCT-MCAST-FUNC-012',\
			'VXLAN-VMCT-MCAST-FUNC-013',\
			'VXLAN-VMCT-MCAST-FUNC-014',\
			'VXLAN-VMCT-MCAST-FUNC-015',\
			'VXLAN-VMCT-MCAST-FUNC-016',\
			'VXLAN-VMCT-MCAST-FUNC-017',\
			'VXLAN-VMCT-MCAST-FUNC-019',\
			'VXLAN-VMCT-MCAST-FUNC-020',\
			'VXLAN-VMCT-MCAST-FUNC-021',\
			'VXLAN-VMCT-MCAST-FUNC-022',\
			'VXLAN-VMCT-MCAST-FUNC-023',\
			'VXLAN-VMCT-MCAST-FUNC-024',\
			'VXLAN-VMCT-MCAST-FUNC-025',\
			'VXLAN-VMCT-MCAST-FUNC-026',\
			'VXLAN-VMCT-MCAST-FUNC-027',\
			#'VXLAN-VMCT-MCAST-FUNC-028',\
			'VXLAN-VMCT-MCAST-FUNC-029',\
			'VXLAN-VMCT-MCAST-FUNC-030',\
			'VXLAN-VMCT-MCAST-FUNC-031',\
			'VXLAN-VMCT-MCAST-FUNC-032',\
			'VXLAN-VMCT-MCAST-FUNC-058',\
			'VXLAN-VMCT-MCAST-FUNC-059'))
