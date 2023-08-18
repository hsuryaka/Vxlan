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
    testscript = os.path.join(test_path, './VxLAN_MS_StormControl_ScriptFile.py')
    configurationFile = os.path.join(test_path, './VxLAN_MS_StormControl_ConfigFile.yaml')

    # Do some logic here to determine which devices to use
    # and pass these device names as script arguments
    uut_devices = {
        'LEAF-1'                : 'Sundown-1',
        'LEAF-2'                : 'Seoul-2',
        'BGW-1'                 : 'Sundown-2',
        'BGW-2'                 : 'Sundown-3',
        'ixia'                  : 'IXIA',
    }

    # Post Trigger Cleanup checks
    jobFileParams = {
        'postTestArgs': {
            'cc_check': 0,
            'cores_check': 0,
            'logs_check': 0,
            'exclude_log_check_pattern': 'ERROR_VLANS_SUSPENDED|ERROR_VLANS_REMOVED',
        },
        'script_flags': {
            'skip_device_config': 0,
            'skip_tgen_config': 0,
            'skip_device_cleanup': 0,
            'skip_eor_triggers': 0,
        }
    }

    #uids = Or('COMMON_SETUP', 'DEVICE_BRINGUP_.*')

    #run(testscript=testscript, uut_list=uut_devices, configurationFile = configurationFile, job_file_params = jobFileParams, uids = Or('common_setup', 'IXIA_.*'))

    #run(testscript=testscript, uut_list=uut_devices, configurationFile=configurationFile, job_file_params=jobFileParams, uids=Or('common_setup', 'Prepare_ISSU_Script', 'ISSU_Script', 'RECONNECT_DEVICES'))

    #run(testscript=testscript, uut_list=uut_devices, configurationFile=configurationFile, job_file_params=jobFileParams, uids=Or('common_setup', 'DEVICE_BRINGUP_.*', 'IXIA_.*', 'VERIFY_VNI_TO_EGR_VNI_MAP', 'VERIFY_VLAN_DSVNI', 'VERIFY_NextHop_DSVNI', 'VERIFY_Symmetric_Route', 'VERIFY_Asymmetric_Route'))

    #run(testscript=testscript, uut_list=uut_devices, configurationFile=configurationFile, job_file_params=jobFileParams)

    #uids = Or('common_setup', 'DEVICE_BRINGUP', 'VERIFY_NETWORK', 'IXIA_CONFIGURATION', 'BRCM_MH_CC_VALIDATION'))

    run(testscript=testscript, uut_list=uut_devices, configurationFile=configurationFile, job_file_params=jobFileParams, uids=Or('common_setup' ,'IXIA.*', 'TC.*'))
