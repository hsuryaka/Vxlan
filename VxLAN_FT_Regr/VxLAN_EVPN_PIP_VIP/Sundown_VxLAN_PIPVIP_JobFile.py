import os
from pyats.easypy import run
from pyats.datastructures.logic import And, Or, Not

def main():
    # Find the location of the script in relation to the job file
    test_path = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    testscript = os.path.join(test_path, './VxLAN_PIPVIP_ScriptFile.py')
    configurationFile = os.path.join(test_path, './VxLAN_PIPVIP_ConfigFile.yaml')

    uut_devices = {
        'N5T-7004-SPINE-2'      : 'SPINE',
        'LEAF-1'                : 'Sundown-1',
        'LEAF-2'                : 'Sundown-2',
        'LEAF-3'                : 'Seoul-1',
        'MyXB-ACCESS'           : 'FAN-2',
        'ixia'                  : 'IXIA',
    }

    # Post Trigger Cleanup checks
    jobFileParams = {
        'postTestArgs' : {
            'cc_check'                  : 0,
            'cores_check'               : 1,
            'logs_check'                : 1,
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
        uids                = Or('common_setup', 'DEVICE_BRINGUP_.*', 'IXIA_CONFIGURATION_.*', 'TC00.*', 'TC01.*', 'TC02.*', 'TC030.*','TC031.*', 'TC032.*','common_cleanup')
    )

    #uids = Not('FINAL_CC_CHECK'))
