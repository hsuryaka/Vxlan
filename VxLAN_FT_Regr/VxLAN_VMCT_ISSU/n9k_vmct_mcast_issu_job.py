from pyats.easypy import run
from pyats.datastructures.logic import And, Not, Or
import os
import sys
import argparse


# Custom arguments parsing.
usg_msg = '''

pyats run job n9k_vmct_mcast_issu_job.py --testbed ../testbeds/FX_VPC_testbed.yaml --config-file ../configs/n9k_vxlan_vmct_mcast_issu.yaml --base_img_abs_path 'nxos64-cs.10.2.2.190.F.bin' --target_img_abs_apth 'nxos64-cs.10.2.2.190.F.bin.upg' --delete_old_images 1

'''
parser = argparse.ArgumentParser(description="PVNF ND ISSU Job File - Boot images command line parameters", add_help=False, usage=usg_msg)
parser._optionals.title = "Required Parameters"
parser.add_argument('--base_img_abs_path', help='Absolute path to base Image')
parser.add_argument('--target_img_abs_apth', help='Absolute path to target Image')
parser.add_argument('--delete_old_images', type=bool, default=0, choices=[0 , 1], help='Delete all old images using nxos* regex')

def main():

	# Getting the arguments
	args, sys.argv[1:] = parser.parse_known_args(sys.argv[1:])
	if args.base_img_abs_path == None or args.target_img_abs_apth == None:
		print('=========================================')
		print('                 ERROR                   ')
		print('=========================================')
		print("Necessary argument have not been provided, Aborting the script run.\n")
		print(parser.print_help())
		print('=========================================')
	else:
		tmp_path = os.path.dirname(os.path.abspath(__file__))
		test_path = tmp_path.split('/')
		test_path.pop()
		test_path.append('scripts')
		test_path.append('n9k_vmct_mcast_issu.py')
		testscript = '/'.join(test_path)
		# run api launches a testscript as an individual task.
		#run(testscript)
		# to run specific testcase
		run(testscript,
		abs_base_image          = args.base_img_abs_path,
       	abs_target_image        = args.target_img_abs_apth,
        delete_old_images       = args.delete_old_images,
		uids =Or('common_setup','setupTgen',\
				'setupConfigVxlan','setupConfigVmct','setupTgen',\
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
				'VXLAN-VMCT-MCAST-FUNC-028',\
				'VXLAN-VMCT-MCAST-FUNC-029',\
				'VXLAN-VMCT-MCAST-FUNC-030',\
				'VXLAN-VMCT-MCAST-FUNC-031',\
				'VXLAN-VMCT-MCAST-FUNC-032',\
				'VXLAN-VMCT-MCAST-FUNC-033',\
				'VXLAN-VMCT-MCAST-FUNC-034',\
				'VXLAN-VMCT-MCAST-FUNC-035',\
				'VXLAN-VMCT-MCAST-FUNC-036',\
				'VXLAN-VMCT-MCAST-FUNC-037',\
				'VXLAN-VMCT-MCAST-FUNC-038',\
				'VXLAN-VMCT-MCAST-FUNC-039',\
				'VXLAN-VMCT-MCAST-FUNC-040'))
