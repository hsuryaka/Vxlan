# To run the job:
# easypy <pyats_root>/examples/connection/job/connection_example_job.py \
#        -testbed_file \
#        <pyats_root>/examples/connection/etc/connection_example_conf.yaml
#            
# Description: This example uses a sample testbed, connects to a device
#              which name is passed from the job file,
#              and executes some commands. The goal is to show
#              how devices can be chosen dynamically and passed to the script.

import os
from pyats.easypy import run
from pyats.datastructures.logic import And, Or, Not
import argparse
import sys

# Custom arguments parsing.
usg_msg = '''
pyats run job VxLAN_PVMAP_IPv6_IR_Job.py -t VxLAN_PVMAP_TB.yaml --n_rel_abs_path <abs_path_n_rel_img> --n_rel_upg_abs_apth <abs_path_n_rel_upg_img>
Example:
pyats run job VxLAN_PVMAP_IPv6_IR_Job.py -t VxLAN_PVMAP_TB.yaml --n_rel_abs_path  'nxos64-cs.10.2.2.72.F.bin' --n_rel_upg_abs_apth 'nxos64-cs.10.2.2.72.F.bin.upg'
'''
parser = argparse.ArgumentParser(description="PVMAP ND ISSU Job File - Boot images command line parameters", add_help=False, usage=usg_msg)
parser._optionals.title = "Required Parameters"
parser.add_argument('--n_rel_abs_path', help='Absolute path to current Release Image')

def main():
    # Getting the arguments
    args, sys.argv[1:] = parser.parse_known_args(sys.argv[1:])
    if args.n_rel_abs_path == None:
    # if args.n_rel_abs_path == None or args.n_rel_upg_abs_apth == None or args.n_1_rel_abs_path == None:
        print('=========================================')
        print('                 ERROR                   ')
        print('=========================================')
        print("Necessary argument have not been provided, Aborting the script run.\n")
        print(parser.print_help())
        print('=========================================')
    else:
        # Find the location of the script in relation to the job file
        test_path = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        testscript = '/ws/ratrajen-bgl/automation/repo_develop/nexus-test-automation/eor/regression/nxos/test/N39kRegression/test/functional/Vxlan/VxLAN_FT_Regr/VxLAN_PVMAP_V6/VxLAN_PVMAP_IPv6_IR_EOR_script.py'
        configurationFile = '/ws/ratrajen-bgl/automation/repo_develop/nexus-test-automation/eor/regression/nxos/test/N39kRegression/test/functional/Vxlan/VxLAN_FT_Regr/VxLAN_PVMAP_V6/VxLAN_PVMAP_EOR_IPv6_config.yaml'
        # Do some logic here to determine which devices to use
        # and pass these device names as script arguments
        uut_devices = {
            'SPINE'                 : 'GX-SPINE',
            'LEAF-1'                : 'GX-EOR-1',
            'LEAF-2'                : 'GX-EOR-2',
            'LEAF-3'                : 'GX-TOR-1',
            'FAN'                   : 'GX-FAN-1',
            'IXIA'                  : 'IXIA',
        }

        # Post Trigger Cleanup checks
        jobFileParams = {
            'postTestArgs': {
                'cc_check': 0,
                'cores_check': 1,
                'logs_check': 1,
                'exclude_log_check_pattern': 'ERROR_VLANS_SUSPENDED|ERROR_VLANS_REMOVED|PLATFORM|LICMGR|IPQOSMGR-4-QOSMGR_PPF_WARNING|SATCTRL-FEX105-2-SOHMS_DIAG_ERROR|VPC-2-PEER_KEEP_ALIVE_RECV_FAIL|USER-1-SYSTEM_MSG|SATCTRL-FEX101-2-SOHMS_ENV_ERROR|AUTHPRIV-3-SYSTEM_MSG',
            },
            'script_flags': {
                'skip_device_config': 0,
                'skip_tgen_config': 1,
                'skip_device_cleanup': 1,
                'skip_eor_triggers': 1,
            }
        }
        
        script_flags = {
            'skip_device_config'    : 0,
            'skip_tgen_config'      : 0,
            'skip_device_cleanup'   : 1,
        }
        
        run(testscript=testscript,
            uut_list            = uut_devices, 
            configurationFile   = configurationFile,
            job_file_params     = jobFileParams,
            script_flags        = script_flags, 
            abs_target_image    = args.n_rel_abs_path,
            uids                = Or(
                                    'common_setup', 
                                    'DEVICE_BRINGUP',
                                    'VERIFY_NETWORK',
                                    'ConfigureIxia',
                                    'TC_VXLAN_PVMAP_000',
                                    # 'TC_VXLAN_PVMAP_001',
                                    # 'TC_VXLAN_PVMAP_002',
                                    # 'TC_VXLAN_PVMAP_003',
                                    # 'TC_VXLAN_PVMAP_004',
                                    # 'TC_VXLAN_PVMAP_005',
                                    # 'TC_VXLAN_PVMAP_007',
                                    # 'TC_VXLAN_PVMAP_008',
                                    # 'TC_VXLAN_PVMAP_009',
                                    # 'TC_VXLAN_PVMAP_010',
                                    # 'TC_VXLAN_PVMAP_011',
                                    # 'TC_VXLAN_PVMAP_012',
                                    # 'TC_VXLAN_PVMAP_013',
                                    # 'TC_VXLAN_PVMAP_014',
                                    # 'TC_VXLAN_PVMAP_015',
                                    # 'TC_VXLAN_PVMAP_016',
                                    # 'TC_VXLAN_PVMAP_017',
                                    # 'TC_VXLAN_PVMAP_019',
                                    # 'TC_VXLAN_PVMAP_021',
                                    # 'TC_VXLAN_PVMAP_022',
                                    # 'TC_VXLAN_PVMAP_023',
                                    # 'TC_VXLAN_PVMAP_024',
                                    # 'TC_VXLAN_PVMAP_025',
                                    # 'TC_VXLAN_PVMAP_026',
                                    # 'TC_VXLAN_PVMAP_027',
                                    # 'TC_VXLAN_PVMAP_028',
                                    # 'TC_VXLAN_PVMAP_029',
                                    # 'TC_VXLAN_PVMAP_030',
                                    # 'TC_VXLAN_PVMAP_031',
                                    # 'TC_VXLAN_PVMAP_032',
                                    # 'TC_VXLAN_PVMAP_033',
                                    # 'TC_VXLAN_PVMAP_034',
                                    # 'TC_VXLAN_PVMAP_035',
                                    # 'TC_VXLAN_PVMAP_036',
                                    # 'TC_VXLAN_PVMAP_037',
                                    # 'TC_VXLAN_PVMAP_039',
                                    # 'TC_VXLAN_PVMAP_040',
                                    # 'TC_VXLAN_PVMAP_041',
                                    # 'TC_VXLAN_PVMAP_042',
                                    # 'TC_VXLAN_PVMAP_043',
                                    # 'TC_VXLAN_PVMAP_044',
                                    # 'TC_VXLAN_PVMAP_045',
                                    # 'TC_VXLAN_PVMAP_046',
                                    # 'TC_VXLAN_PVMAP_047',
                                    # 'common_cleanup'
                                ))