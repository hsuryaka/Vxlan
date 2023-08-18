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
    test_path           = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    testscript          = os.path.join(test_path, './PVNF/VxLAN_PVNF_single_site.py')
    configurationFile   = os.path.join(test_path, './PVNF/VxLAN_PVNF_single_site_config.yaml')

    # Devices required for the test
    uut_devices = {
        'SPINE'                 : 'S2-SPINE-1',
        'LEAF-1'                : 'S1-LEAF-2',
        'LEAF-2'                : 'S2-LEAF-1',
        'LEAF-3'                : 'S2-LEAF-2',
        'BL'                    : 'S2-BGW',
        'PGW'                   : 'SUPER-ACCESS',
        'ixia'                  : 'IXIA'
    }

    # Script specific global config parameters
    script_flags = {
        'skip_device_config'    : 0,
        'skip_tgen_config'      : 0,
        'skip_device_cleanup'   : 0
    }

    # Execution of the main Script
    run(
        testscript              = testscript,
        uut_list                = uut_devices,
        configurationFile       = configurationFile,
        script_flags            = script_flags,
        uids                    = Or('common_setup', 'IXIA_CONFIGURATION', 'VERIFY_PVNF_TOR_RELOAD', 'VERIFY_PVNF_BL_RELOAD')
    )