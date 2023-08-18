import os
from ats.easypy import run
from ats.datastructures.logic import And, Or, Not


# noinspection PyDictCreation
def main():
    global uutList
    test_path = os.path.dirname(os.path.abspath(__file__))
    testscript = os.path.join(test_path, 'VxLAN_EVPN_IR_MCAST_ngpf_profile.py')

    # Post Trigger Cleanup checks
    jobFileParams = {
        'pre_test_params' : {
            'clean_before_config'       : 0,        # 0 - skip, 1 - run
            'config_bringup'            : 0,        # 0 - skip, 1 - run
            'eor_triggers'              : 1,        # 0 - skip, 1 - run
        },
        'postTestArgs' : {
            'cc_check'                  : 0,
            'cores_check'               : 1,
            'logs_check'                : 1,
            'exclude_log_check_pattern' : 'ERROR_VLANS_SUSPENDED|ERROR_VLANS_REMOVED|PIM-3-RESTART_REASON',
        },
        'underlayOptions' : {
            'igp'                       : 'ospf',           # --> choice(['isis','ospf'])
            'linktype'                  : 'l3_single_po',   # --> choice(['unnumbered','l3po','svi','l3_single_po'])
            'pim_type'                  : '',               # --> choice(['', 'bidir'])
        }
    }

    # As work-around for IXIA timing out, running test-cases in batches
    # Run first batch of cases
    # run(testscript                      = testscript,
    #     taskid                          = 'EVPN_BATCH-1',
    #     job_file_params                 = jobFileParams,
    #     uids                            = Or('common_setup', 'TC001_vxlan_configs', 'TC002_Nve_Peer_State_Verify', 'TC003_Nve_Vni_State_Verify', '^TC05\S_.*'
    #                                       'common_cleanup'))

    # As work-around for IXIA timing out, running test-cases in batches
    # Run first batch of cases
    run(testscript                      = testscript,
        taskid                          = 'EVPN_BATCH-1',
        job_file_params                 = jobFileParams,
        uids                            = Or('common_setup',
                                          Not('^TC03\S_.*', '^TC04\S_.*', '^TC05\S_.*'),
                                          'common_cleanup'))
    
    # Run second batch of cases
    jobFileParams['pre_test_params']    = {'clean_before_config' : 0, 'config_bringup' : 0, 'eor_triggers' : 0}
    run(testscript                      = testscript,
        taskid                          = 'EVPN_BATCH-2',
        job_file_params                 = jobFileParams,
        uids                            = Or('common_setup',
                                          Or('^TC002_.*', '^TC003_.*', '^TC05_.*',
                                             '^TC03\S_.*', '^TC04\S_.*', '^TC05\S_.*'),
                                          'common_cleanup'))
    
    # Run EOR HA batch of cases
    jobFileParams['pre_test_params']    = {'clean_before_config' : 0, 'config_bringup' : 0, 'eor_triggers' : 1}
    run(testscript                      = testscript,
        taskid                          = 'EVPN_EOR_HA',
        job_file_params                 = jobFileParams,
        uids                            = Or('common_setup',
                                          Or('^TC002_.*','^TC05_.*',
                                             '^TC047_.*', '^TC048_.*', '^TC049_.*',
                                             '^TC050_.*', '^TC051_.*', '^TC052_.*',
                                             '^TC053_.*', '^TC054_.*', '^TC055_.*',
                                             '^TC056_.*', '^TC057_.*', '^TC058_.*'),
                                          'common_cleanup'))
