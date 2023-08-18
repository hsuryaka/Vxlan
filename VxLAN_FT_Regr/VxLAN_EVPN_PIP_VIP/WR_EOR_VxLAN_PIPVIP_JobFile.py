import os
from pyats.easypy import run
from pyats.datastructures.logic import And, Or, Not

def main():
    # Find the location of the script in relation to the job file
    test_path = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    testscript = os.path.join(test_path, './VxLAN_EVPN_PIP_VIP/VxLAN_PIPVIP_ScriptFile.py')
    configurationFile = os.path.join(test_path, './VxLAN_EVPN_PIP_VIP/VxLAN_PIPVIP_ConfigFile.yaml')

    uut_devices = {
        'N5T-7004-SPINE-2'      : 'WFR_SPINE',
        'LEAF-1'                : 'N9508_1',
        'LEAF-2'                : 'N9508_2',
        'LEAF-3'                : 'N9504_1',
        'MyXB-ACCESS'           : 'FAN-1',
        'ixia'                  : 'IXIA',
    }

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

    run(
        testscript          = testscript,
        uut_list            = uut_devices,
        configurationFile   = configurationFile,
        job_file_params     = jobFileParams,
        # uids                = Or('common_setup', 'IXIA_CONFIGURATION_.*',
        #                          'TC033_.*','TC034_.*','TC035_.*',
        #                          'TC036_.*','TC037_.*','TC038_.*',
        #                          'TC039_.*','TC040_.*','TC041_.*',
        #                          'TC042_.*','TC043_.*','TC044_.*',
        #                          'TC045_.*','TC046_.*','TC047_.*',
        #                          'common_cleanup')
    )
