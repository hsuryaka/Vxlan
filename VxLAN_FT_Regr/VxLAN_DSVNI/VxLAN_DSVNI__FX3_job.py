import os
from pyats.easypy import run
from pyats.datastructures.logic import And, Or, Not

def main():
    # Find the location of the script in relation to the job file
    test_path = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    testscript = os.path.join(test_path, './VxLAN_DSVNI_ScriptFile.py')
    configurationFile = os.path.join(test_path, './VxLAN_DSVNI_ConfigFile.yaml')

    # Do some logic here to determine which devices to use
    # and pass these device names as script arguments
    uut_devices = {
        'SPINE'                         : 'SPINE',
        'LEAF-1'                        : 'Sundown-1',
        'LEAF-2'                        : 'Sundown-2',
        'LEAF-3'                        : 'Sundown-3',
        'ACCESS'                        : 'FAN-2',
        'ixia'                          : 'IXIA',
    }

    # Post Trigger Cleanup checks
    jobFileParams = {
        'postTestArgs': {
            'cc_check'                      : 1,
            'cores_check'                   : 1,
            'logs_check'                    : 1,
            'exclude_log_check_pattern'     : 'ERROR_VLANS_SUSPENDED|ERROR_VLANS_REMOVED|PEER_KEEP_ALIVE_RECV_FAIL|AUTHPRIV-2-SYSTEM_MSG|dcos_sshd|LICMGR-3-LOG_SMART_LIC_COMM_FAILED|POAP-2-POAP_FAILURE',
        },
        'script_flags': {
            'skip_device_config'            : 0,
            'skip_tgen_config'              : 0,
            'skip_device_cleanup'           : 0,
            'eor_flag'                      : 0,
            'skip_eor_triggers'             : 1,
        }
    }

    #uids = Or('COMMON_SETUP', 'DEVICE_BRINGUP_.*')

    #run(testscript=testscript, uut_list=uut_devices, configurationFile = configurationFile, job_file_params = jobFileParams, uids = Or('common_setup', 'IXIA_.*'))

    # run(testscript=testscript, uut_list=uut_devices, configurationFile=configurationFile, job_file_params=jobFileParams, 
    # uids=Or('common_setup', '^DEVICE_BRINGUP.*', 'VERIFY_NETWORK', '^IXIA_CONFIGURATION.*'))

    run(testscript=testscript, uut_list=uut_devices, configurationFile=configurationFile, job_file_params=jobFileParams)

    #uids = Or('common_setup', 'DEVICE_BRINGUP', 'VERIFY_NETWORK', 'IXIA_CONFIGURATION', 'BRCM_MH_CC_VALIDATION'))

