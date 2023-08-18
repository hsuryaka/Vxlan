import os
from pyats.easypy import run
from pyats.datastructures.logic import And, Or, Not

def main():
    # Find the location of the script in relation to the job file
    test_path = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    testscript = os.path.join(test_path, './VxLAN_FnL/CSCva66571.py')
    configurationFile = os.path.join(test_path, './VxLAN_FnL/CSCva66571_config.yaml')

    uut_devices = {
        'SPINE'     : 'WFR_SPINE',
        'LEAF-1'    : 'N9508_1',
        'LEAF-2'    : 'N9508_2',
        'LEAF-3'    : 'N9504_1',
        'FAN-1'     : 'FAN-1',
        'ixia'      : 'IXIA'
    }

    # Post Trigger Cleanup checks
    jobFileParams = {
        'postTestArgs' : {
            'cc_check'                  : 0,
            'cores_check'               : 1,
            'logs_check'                : 1,
            'fnl_flag'                  : 1,
            'exclude_log_check_pattern' : 'ERROR_VLANS_SUSPENDED|ERROR_VLANS_REMOVED',
        },
        'script_flags' : {
            'skip_device_config'        : 0,
            'skip_tgen_config'          : 0,
            'skip_device_cleanup'       : 0,
            'skip_eor_triggers'         : 0,
        }
    }

    run(
        testscript          = testscript,
        uut_list            = uut_devices,
        configurationFile   = configurationFile,
        job_file_params     = jobFileParams,
        #uids                = Or('common_setup', Or('VERIFY_NETWORK', '^IXIA_CONFIGURATION_.*', '^TC00.*'), 'common_cleanup')
    )

    #uids = Not('FINAL_CC_CHECK'))
