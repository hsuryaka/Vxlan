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
    testscript = '/ws/pkanduri-bgl/N9K_Scripts_Porting/NIA_scripts/VxLAN_NIA.py'
    configurationFile = '/ws/pkanduri-bgl/N9K_Scripts_Porting/NIA_scripts/VxLAN_NIA_config.yaml'

    # Do some logic here to determine which devices to use
    # and pass these device names as script arguments
    uut_devices = {'SPINE'  : 'SPINE',
                   'LEAF-1' : 'Sundown-1',
                   'LEAF-2' : 'Sundown-2',
                   'LEAF-3' : 'Seoul-1',
                   'FAN-1'  : 'FAN-2',
                   'FAN-2'  : 'FAN-1',
                   'ixia'   : 'IXIA'
                   }

    script_flags = {
        'skip_device_config'    : 0,
        'skip_tgen_config'      : 0,
    }

    # Topology Flag deciding BRCM or CloudScale
    # 0 - CloudScale
    # 1 - BRCM
    topology_flag = 0

    run(testscript          = testscript,
        uut_list            = uut_devices,
        configurationFile   = configurationFile,
        topology_flag       = topology_flag,
        script_flags        = script_flags)
        #uids = Or('common_setup', 'VERIFY_NIA_FSV_INNER_VxLAN_IPv4_STD_VTEP_IIF_OIF_PO', 'VERIFY_NIA_FSV_INNER_VxLAN_IPv6_STD_VTEP_IIF_OIF_PO'))
    
    #uids = Or('common_setup', 'DEVICE_BRINGUP', 'IXIA_CONFIGURATION', 'VXLAN_DISRUPTIVE_VERIFICATION'))
