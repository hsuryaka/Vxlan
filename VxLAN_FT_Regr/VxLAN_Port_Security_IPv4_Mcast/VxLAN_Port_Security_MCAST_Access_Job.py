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
pyats run job VxLAN_Port_Security_Site1_IPv6_Access_Job.py -t VxLAN_PortSecurity_Site1_TB.yaml --n_rel_abs_path <abs_path_n_rel_img> --n_rel_upg_abs_apth <abs_path_n_rel_upg_img> --n_1_rel_abs_path <abs_path_n-1_rel_image>
Example:
pyats run job VxLAN_Port_Security_Site1_IPv6_Access_Job.py -t VxLAN_PortSecurity_Site1_TB.yaml --n_rel_abs_path  '/images/kr3f/nxos64-cs.10.2.2.72.F.bin' --n_rel_upg_abs_apth '/images/kr3f/nxos64-cs.10.2.2.72.F.bin.upg' --n_1_rel_abs_path '/tftpboot/fcs/kr2f/nxos64-cs.10.2.2.F.bin' --delete_old_images 1
'''
parser = argparse.ArgumentParser(description="PVNF ND ISSU Job File - Boot images command line parameters", add_help=False, usage=usg_msg)
parser._optionals.title = "Required Parameters"
parser.add_argument('--n_rel_abs_path', help='Absolute path to current Release Image')
parser.add_argument('--n_rel_base_img', help='Base Image')
# parser.add_argument('--n_rel_upg_abs_apth', help='Absolute path to current Release UPG Image')
# parser.add_argument('--n_1_rel_abs_path', help='Absolute path to one Release earlier than the current Release Image')


def main():
    # Getting the arguments
    args, sys.argv[1:] = parser.parse_known_args(sys.argv[1:])
    if args.n_rel_abs_path == None or args.n_rel_base_img == None:
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
        testscript = '/ws/ratrajen-bgl/automation/repo_develop/nexus-test-automation/eor/regression/nxos/test/N39kRegression/test/functional/Vxlan/VxLAN_FT_Regr/VxLAN_Port_Security_IPv6/VxLAN_PortSecurity_IPv6_Access_script.py'
        configurationFile = '/ws/ratrajen-bgl/automation/repo_develop/nexus-test-automation/eor/regression/nxos/test/N39kRegression/test/functional/Vxlan/VxLAN_FT_Regr/VxLAN_Port_Security_IPv6/VxLAN_PortSecurity_IPv6_config.yaml'
        # Do some logic here to determine which devices to use
        # and pass these device names as script arguments
        uut_devices = {
            'SPINE'                 : 'SITE1-SPINE-3132',
            'LEAF-1'                : 'SITE1-LEAF1-FX',
            'LEAF-2'                : 'SITE1-LEAF2-FX',
            'LEAF-3'                : 'SITE1-LEAF3-FX3',
            'FANOUT-3172'           : 'FANOUT-3172',
            'ixia'                  : 'IXIA',
        }

        # Post Trigger Cleanup checks
        jobFileParams = {
            'postTestArgs': {
                'cc_check': 0,
                'cores_check': 1,
                'logs_check': 1,
                'exclude_log_check_pattern': 'ERROR_VLANS_SUSPENDED|ERROR_VLANS_REMOVED|PLATFORM|LICMGR|IPQOSMGR-4-QOSMGR_PPF_WARNING|SATCTRL-FEX105-2-SOHMS_DIAG_ERROR|VPC-2-PEER_KEEP_ALIVE_RECV_FAIL|USER-1-SYSTEM_MSG|SATCTRL-FEX101-2-SOHMS_DIAG_ERROR|SATCTRL-FEX101-2-SOHMS_ENV_ERROR|AUTHPRIV-3-SYSTEM_MSG',
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
            abs_base_image      = args.n_rel_base_img,
            abs_target_image    = args.n_rel_abs_path,
            uids = Or('common_setup', 
                        'DEVICE_BRINGUP',
                        'VERIFY_NETWORK',
                        'ConfigureIxia',
                        'TC_VXLAN_PS_000_Trunk',
                        'TC_VXLAN_PS_001_Trunk',
                        'TC_VXLAN_PS_002_Trunk',
                        'TC_VXLAN_PS_003_Trunk',
                        'TC_VXLAN_PS_004_Trunk',
                        'TC_VXLAN_PS_005_Trunk',
                        'TC_VXLAN_PS_006_Trunk',
                        'TC_VXLAN_PS_007_Trunk',
                        'TC_VXLAN_PS_008_Trunk',
                        'TC_VXLAN_PS_009_Trunk',
                        'TC_VXLAN_PS_010_Trunk',
                        'TC_VXLAN_PS_011_Trunk',
                        'TC_VXLAN_PS_012_Trunk',
                        'TC_VXLAN_PS_013_Trunk',
                        'TC_VXLAN_PS_014_Trunk',
                        'TC_VXLAN_PS_015_Trunk',
                        'TC_VXLAN_PS_016_Trunk',
                        'TC_VXLAN_PS_017_Trunk',
                        'TC_VXLAN_PS_018_Trunk',
                        'TC_VXLAN_PS_019_Trunk',
                        'TC_VXLAN_PS_020_Trunk',
                        'TC_VXLAN_PS_021_Trunk',
                        'TC_VXLAN_PS_022_Trunk',
                        'TC_VXLAN_PS_033_Trunk',
                        'TC_VXLAN_PS_034_Trunk',
                        'TC_VXLAN_PS_035_Trunk',
                        'common_cleanup'
                    ))