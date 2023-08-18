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
    testscript = './VxLAN_QinVNI_ScriptFile.py'
    configurationFile = './VxLAN_QinVNI_ConfigFile.yaml'

    # Do some logic here to determine which devices to use
    # and pass these device names as script arguments
    uut_devices = {
        'N5T-7004-SPINE-2'      : 'SPINE',
        'LEAF-1'                : 'Haggan-1',
        'LEAF-2'                : 'Haggan-2',
        'LEAF-3'                : 'Calgary-3',
        'MyXB-ACCESS'           : 'FAN-1',
        'ixia'                  : 'IXIA',
    }

    script_flags = {
        'skip_device_config'    : 0,
        'skip_tgen_config'      : 0,
        'skip_device_cleanup'   : 0,
    }

    run(testscript=testscript, uut_list=uut_devices, configurationFile = configurationFile, script_flags = script_flags)

    #uids = Or('common_setup', 'DEVICE_BRINGUP', 'VERIFY_NETWORK', 'IXIA_CONFIGURATION', 'BRCM_MH_CC_VALIDATION'))
