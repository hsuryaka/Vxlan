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
    testscript = os.path.join(test_path, './VxLAN_NIA/sundown_reg_VxLAN_NIA.py')
    configurationFile = os.path.join(test_path, './VxLAN_NIA/sundown_reg_VxLAN_NIA_config.yaml')

    # Do some logic here to determine which devices to use
    # and pass these device names as script arguments
    uut_devices = {'SPINE'  : 'FX3-REG-TB2-TOR3',
                   'LEAF-1' : 'FX3-REG-TB1-TOR1',
                   'LEAF-2' : 'FX3-REG-TB1-TOR2',
                   'LEAF-3' : 'FX3-REG-TB2-TOR1',
                   'FAN-1'  : 'FX3-REG-TB1-NODE4',
                   'FAN-2'  : 'FX3-REG-TB1-NODE7',
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
        #uids = Or('common_setup','DEVICE_BRINGUP','VERIFY_NETWORK','IXIA_CONFIGURATION','VERIFY_NIA_FSV_INNER_VxLAN_IPv4_VPC_VTEP_IIF_OIF_PO','VERIFY_NIA_FSV_INNER_VxLAN_IPv6_VPC_VTEP_IIF_OIF_PO','VERIFY_NIA_FSV_INNER_VxLAN_IPv4_STD_VTEP_IIF_SUB_INT','VERIFY_NIA_FSV_INNER_VxLAN_IPv6_STD_VTEP_IIF_SUB_INT','VERIFY_NIA_FSV_INNER_VxLAN_IPv4_VPC_VTEP_IIF_SUB_INT','VERIFY_NIA_FSV_INNER_VxLAN_IPv6_VPC_VTEP_IIF_SUB_INT'))
    
    #uids = Or('common_setup', 'DEVICE_BRINGUP', 'IXIA_CONFIGURATION', 'VXLAN_DISRUPTIVE_VERIFICATION'))
