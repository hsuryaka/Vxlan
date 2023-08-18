import os
from pyats.easypy import run
from pyats.datastructures.logic import And, Or, Not

def main():
    # Define the location of the script in relation to the job file
    testscript = './VxLAN_Loop_Detection.py'
    configurationFile = './VxLAN_Loop_Detection_config.yaml'

    # Define the devices which will be used
    uut_devices = {}
    uut_devices['SPINE']        = 'WFR_SPINE'
    uut_devices['LEAF-1']       = 'N9508_1'
    uut_devices['LEAF-2']       = 'N9508_2'
    uut_devices['LEAF-3']       = 'N9504_1'
    uut_devices['FAN-1']        = 'FAN-1'
    uut_devices['FAN-2']        = 'FAN-2'
    uut_devices['ixia']         = 'IXIA'
    
    # Post Trigger Cleanup checks
    jobFileParams = {
        'postTestArgs' : {
            'cc_check'                  : 0,
            'cores_check'               : 1,
            'logs_check'                : 1,
            'exclude_log_check_pattern' : 'ERROR_VLANS_SUSPENDED|ERROR_VLANS_REMOVED|PEER_KEEP_ALIVE_RECV_FAIL|AUTHPRIV-2-SYSTEM_MSG|dcos_sshd|LICMGR-3-LOG_SMART_LIC_COMM_FAILED|POAP-2-POAP_FAILURE|PEER_KEEP_ALIVE_RECV_FAIL',
        },
        'script_flags' : {
            'skip_device_config'        : 0,
            'skip_tgen_config'          : 0,
            'skip_device_cleanup'       : 0,
            'skip_eor_triggers'         : 0,
            'eor_flag'                  : 1,
        }
    }

    # Running the script
    run(
        testscript          = testscript, 
        uut_list            = uut_devices, 
        configurationFile   = configurationFile,
        job_file_params     = jobFileParams,
        # uids = Or('common_setup', 'DEVICE_BRINGUP_.*', 'VERIFY_NETWORK_.*','IXIA_CONFIGURATION_.*','TC016_Vpc1_to_Vpc2_Link_loop_detection', 'common_cleanup')
    )