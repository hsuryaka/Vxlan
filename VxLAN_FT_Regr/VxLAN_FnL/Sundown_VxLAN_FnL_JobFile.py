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

def main():
    # Find the location of the script in relation to the job file
    test_path = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    testscript = './VxLAN_FnL.py'
    configurationFile = './VxLAN_FnL_config.yaml'

    # Do some logic here to determine which devices to use
    # and pass these device names as script arguments
    # ...
    uut_devices = {'SPINE'  : 'SPINE',
                   'LEAF-1' : 'Sundown-1',
                   'LEAF-2' : 'Sundown-2',
                   'LEAF-3' : 'Seoul-1',
                   'FAN-1'  : 'FAN-2',
                   'FAN-2'  : 'FAN-1',
                   'ixia'   : 'IXIA'
                   }

    script_flags = {
        'skip_device_config'    : 0,
        'skip_tgen_config'      : 0,
    }
    
    run(testscript=testscript, uut_list=uut_devices, configurationFile = configurationFile, script_flags = script_flags)
    #run(testscript=testscript, uut_list=uut_devices, configurationFile = configurationFile, script_flags = script_flags, uids = Or('common_setup','DEVICE_BRINGUP', 'VERIFY_NETWORK', 'IXIA_CONFIGURATION'))
    #run(testscript=testscript, uut_list=uut_devices, configurationFile = configurationFile, script_flags = script_flags, uids = Or('common_setup', 'VERIFY_NETWORK', 'IXIA_CONFIGURATION', 'VERIFY_L2_VLAN_SUSPEND_RESUME', 'VERIFY_VPC_SHUT_NO_SHUT', 'VERIFY_VPC_PEER_LINK_SHUT_NO_SHUT', 'VERIFY_VPC_DOMAIN_SHUT_NO_SHUT', 'VERIFY_SPINE_UPLINK_SHUT_NO_SHUT', 'VERIFY_NVE_INT_SHUT_NO_SHUT', 'VERIFY_NVE_SOURCE_INT_CHANGE', 'VERIFY_CHANGE_VNI_MCAST_GRP', 'VERIFY_CHANGE_VNI_VLAN_MAP', 'VERIFY_CLEAR_IGMP_SNOOPING_GROUPS_VLAN_ALL', 'VERIFY_CLEAR_IGMP_SNOOPING_GROUPS_VLAN_ALL', 'VERIFY_FEATURE_DISABLE_ENABLE_NV_OVERLAY_VN_SEGMENT', 'VERIFY_IGMP_PROCESS_RESTART', 'VERIFY_L2RIB_PROCESS_RESTART', 'VERIFY_UFDM_PROCESS_RESTART'))
