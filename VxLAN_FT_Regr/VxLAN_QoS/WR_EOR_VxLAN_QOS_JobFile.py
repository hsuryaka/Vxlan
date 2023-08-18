import os
from pyats.easypy import run
from pyats.datastructures.logic import And, Or, Not

def main():
    testscript = './VxLAN_QOS.py'
    configurationFile = './VxLAN_QOS_config.yaml'

    # Do some logic here to determine which devices to use
    # and pass these device names as script arguments
    uut_devices = {
        'SPINE'                         : 'WFR_SPINE',
        # 'LB'                            : 'LB',
        'LEAF-1'                        : 'N9508_1',
        'LEAF-2'                        : 'N9508_2',
        'LEAF-3'                        : 'N9504_1',
        'FAN-1'                         : 'FAN-1',
        # 'FAN-2'                         : 'FAN-2',
        'ixia'                          : 'IXIA',
    }

    # Post Trigger Cleanup checks
    jobFileParams = {
        'postTestArgs': {
            'cc_check'                      : 0,
            'cores_check'                   : 1,
            'logs_check'                    : 1,
            'exclude_log_check_pattern'     : 'ERROR_VLANS_SUSPENDED|ERROR_VLANS_REMOVED|PEER_KEEP_ALIVE_RECV_FAIL|AUTHPRIV-2-SYSTEM_MSG|dcos_sshd|LICMGR-3-LOG_SMART_LIC_COMM_FAILED|POAP-2-POAP_FAILURE',
        },
        'script_flags': {
            'skip_device_config'            : 0,
            'skip_tgen_config'              : 0,
            'skip_device_cleanup'           : 0,
            'eor_flag'                      : 1,
            'skip_eor_triggers'             : 0,
        }
    }

    # Batch-1 Test-cases TC001-TC040
    run(testscript=testscript, uut_list=uut_devices, configurationFile=configurationFile, job_file_params=jobFileParams,
    uids = Or('common_setup', '^DEVICE_BRINGUP_.*', 'VERIFY_NETWORK','^IXIA_CONFIGURATION_.*', '^TC00\S_.*', '^TC01\S_.*', '^TC02\S_.*', '^TC03\S_.*', 'TC040_DECAP_UNFM_INGR_NVE_COS_REMARKING'))

    # Batch-1 Test-cases TC041-TC068
    run(testscript=testscript, uut_list=uut_devices, configurationFile=configurationFile, job_file_params=jobFileParams,
    uids = Or('common_setup', '^VERIFY_NETWORK.*', '^IXIA_CONFIGURATION_.*', '^TC04\S_.*', '^TC05\S_.*', '^TC06\S_.*', 'common_cleanup'))
