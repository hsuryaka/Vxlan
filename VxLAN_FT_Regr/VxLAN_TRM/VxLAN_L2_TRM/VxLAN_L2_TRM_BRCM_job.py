import os
from pyats.easypy import run
from pyats.datastructures.logic import And, Or, Not


def main():
    # Find the location of the script in relation to the job file
    test_path = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    testscript = './VxLAN_L2_TRM.py'
    configurationFile = './VxLAN_L2_TRM_config.yaml'
    print(test_path)

    # Grab and assign the devices required for the test
    uut_devices = {'SPINE': 'SPINE',
                   'LEAF-1': 'Calgary-1',
                   'LEAF-2': 'Calgary-2',
                   'LEAF-3': 'Calgary-3',
                   'FAN-1': 'FAN-1',
                   'FAN-2': 'FAN-2',
                   'ixia': 'IXIA'
                   }

    # Script specific global config parameters
    script_flags = {
        'skip_device_config': 0,
        'skip_tgen_config': 0,
        'skip_device_cleanup': 0
    }

    # Execution of the main Script
    run(
        testscript=testscript,
        uut_list=uut_devices,
        configurationFile=configurationFile,
        script_flags=script_flags,
       # uids=Or('common_setup', 'IXIA_CONFIGURATION', 'common_cleanup')
    )

    # ('common_setup', 'DEVICE_BRINGUP', 'VERIFY_NETWORK', 'ENABLE_L2_TRM_CONFIGURATION', 'IXIA_CONFIGURATION', 'TRM_MCAST_VERIFICATION', 'L2_DISRUPTIVE_VERIFICATION')
