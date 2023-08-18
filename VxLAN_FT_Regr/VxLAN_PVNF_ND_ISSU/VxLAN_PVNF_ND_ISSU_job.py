# To run the job:
# pyats run VxLAN_PVNF_ND_ISSU_job.py -t ./VxLAN_PVNF_ND_ISSU_testbed.yaml

import os, sys
from pyats.easypy import run
from pyats.datastructures.logic import And, Or, Not
import argparse

# Custom arguments parsing.
usg_msg = '''
pyats run job VxLAN_PVNF_ND_ISSU_job.py -t ./VxLAN_PVNF_ND_ISSU_testbed.yaml --n_rel_abs_path <abs_path_n_rel_img> --n_rel_upg_abs_apth <abs_path_n_rel_upg_img> --n_1_rel_abs_path <abs_path_n-1_rel_image>

Example:

pyats run job VxLAN_PVNF_ND_ISSU_job.py -t ./VxLAN_PVNF_ND_ISSU_testbed.yaml --n_rel_abs_path  '/images/kr3f/nxos64-cs.10.2.2.72.F.bin' --n_rel_upg_abs_apth '/images/kr3f/nxos64-cs.10.2.2.72.F.bin.upg' --n_1_rel_abs_path '/tftpboot/fcs/kr2f/nxos64-cs.10.2.2.F.bin' --delete_old_images 1

'''
parser = argparse.ArgumentParser(description="PVNF ND ISSU Job File - Boot images command line parameters", add_help=False, usage=usg_msg)
parser._optionals.title = "Required Parameters"
parser.add_argument('--n_rel_abs_path', help='Absolute path to current Release Image')
parser.add_argument('--n_rel_upg_abs_apth', help='Absolute path to current Release UPG Image')
parser.add_argument('--n_1_rel_abs_path', help='Absolute path to one Release earlier than the current Release Image')
parser.add_argument('--delete_old_images', type=bool, default=0, choices=[0 , 1], help='Delete all old images using nxos* regex')

def main():

    # Getting the arguments
    args, sys.argv[1:] = parser.parse_known_args(sys.argv[1:])
    if args.n_rel_abs_path == None or args.n_rel_upg_abs_apth == None or args.n_1_rel_abs_path == None:
        print('=========================================')
        print('                 ERROR                   ')
        print('=========================================')
        print("Necessary argument have not been provided, Aborting the script run.\n")
        print(parser.print_help())
        print('=========================================')
    else:
        # Find the location of the script in relation to the job file
        test_path           = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        testscript          = '/auto/dc3-india/havadhut/automation/py_automation_develop/nexus-test-automation/eor/regression/nxos/test/N39kRegression/test/functional/Vxlan/VxLAN_FT_Regr/VxLAN_PVNF_ND_ISSU/VxLAN_PVNF_ND_ISSU_script.py'
        configurationFile   = '/auto/dc3-india/havadhut/automation/py_automation_develop/nexus-test-automation/eor/regression/nxos/test/N39kRegression/test/functional/Vxlan/VxLAN_FT_Regr/VxLAN_PVNF_ND_ISSU/VxLAN_PVNF_ND_ISSU_config.yaml'

        # Devices required for the test
        uut_devices = {
            'SPINE'                 : 'SPINE',
            'LEAF-1'                : 'LEAF-1',
            'LEAF-2'                : 'LEAF-2',
            'LEAF-3'                : 'LEAF-3',
            'BL'                    : 'BL',
            'PGW'                   : 'PVNF-PGW',
            'ixia'                  : 'IXIA',
            'lnx-server'            : 'n3k-qa-image'
        }

        # Script specific global config parameters
        script_flags = {
            'skip_device_config'    : 0,
            'skip_tgen_config'      : 0,
            'skip_device_cleanup'   : 1
        }

        # Execution of the main Script
        run(
            testscript              = testscript,
            uut_list                = uut_devices,
            configurationFile       = configurationFile,
            script_flags            = script_flags,
            abs_base_image          = args.n_rel_abs_path,
            abs_target_image        = args.n_rel_upg_abs_apth,
            delete_old_images       = args.delete_old_images,
        #    uids                    = Or('common_setup', 'IXIA_CONFIGURATION', 'VERIFY_PVNF_TOR_RELOAD', 'VERIFY_PVNF_BL_RELOAD')
        )

        # Script specific global config parameters
        script_flags = {
            'skip_device_config'    : 1,
            'skip_tgen_config'      : 0,
            'skip_device_cleanup'   : 0
        }

        # Execution of the main Script
        run(
            testscript              = testscript,
            uut_list                = uut_devices,
            configurationFile       = configurationFile,
            script_flags            = script_flags,
            abs_base_image          = args.n_1_rel_abs_path,
            abs_target_image        = args.n_rel_abs_path,
            delete_old_images       = args.delete_old_images,
        #    uids                    = Or('common_setup', 'IXIA_CONFIGURATION', 'VERIFY_PVNF_TOR_RELOAD', 'VERIFY_PVNF_BL_RELOAD')
        )
