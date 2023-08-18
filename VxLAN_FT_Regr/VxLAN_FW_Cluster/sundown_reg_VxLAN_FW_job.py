import os
from pyats.easypy import run
from pyats.datastructures.logic import And, Or, Not

def main():
    # Find the location of the script in relation to the job file
    test_path = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    testscript = './VxLAN_FW_ScriptFile.py'
    configurationFile = './VxLAN_FW_ConfigFile.yaml'



    uut_devices = {
        'N5T-7004-SPINE-1'      : 'FX3-REG-TB2-TOR3',
        'LEAF-1'                : 'FX3-REG-TB1-TOR1',
        'LEAF-2'                : 'FX3-REG-TB1-TOR3',
        'LEAF-3'                : 'FX3-REG-TB1-TOR2',
        'MyXB-ACCESS'           : 'FX3-REG-TB2-TOR2',
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
        }
    }

    run(
        testscript          = testscript,
        uut_list            = uut_devices,
        configurationFile   = configurationFile,
        job_file_params     = jobFileParams,
        uids                = Not('FINAL_CC_CHECK')
    )

    #uids = Not('FINAL_CC_CHECK'))
