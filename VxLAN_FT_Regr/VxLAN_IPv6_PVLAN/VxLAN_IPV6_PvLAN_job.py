"""
VxLAN_VNI_Scale_MSite_job.py

"""
# Author information
__author__ = 'Nexus India VxLAN DevTest Group'
__copyright__ = 'Copyright (c) 2021, Cisco Systems Inc.'
__contact__ = ['group.jdasgupt@cisco.com']
__credits__ = ['havadhut']
__version__ = 1.0

import os
from genie.harness.main import gRun
from lib.utils.find_path import get_full_with_python_path
SCRIPT_PATH = os.path.dirname(os.path.realpath(__file__))

def main():
    # Initial run to clean up the devices
    # gRun(
    #     trigger_datafile=os.path.join(SCRIPT_PATH, "../GRunFiles/NR2F_TRM_Data_MDTv4v6_grun_data.yaml"),
    #     trigger_uids=[
    #         "TC_001_InitializeTestbed",
    #         "CommonCleanup",
    #     ],
    #     subsection_datafile=get_full_with_python_path("src/forwarding/vxlan/vxlan_subsection.yaml"),
    # )
    
    # Actual run with the test-cases
    gRun(
        trigger_datafile=os.path.join(SCRIPT_PATH, "./pvlan_v6_grun.yaml"),
        trigger_uids=[
            "TC_001_InitializeTestbed",
            # "TC_003_CommonSetup",                         # Performing the base configurations
            "TC_004_ConfigureIxia",                         # Load " NewConfig.PvLAN-Trunk-TC.ixncfg " config file
            "TC_073_trunk_and_pvlan_traffic",
            "TC_074_community_port_to_trunk_promiscuous_port",
            "TC_075_promiscuous_to_promiscous_trunk",
            "TC_071_pvlan_to_trunkport",
            "TC_013_native_vlan_in_pvlantrunk",
            "TC_037_reload_verify_community_port_to_trunk_promiscuous_port",
            "TC_039_reload_verify_trunk",
            "TC_012_pvlan_to_normal_trunk",

            # Common Cleanup
            # "CommonCleanup",
            ],
        subsection_datafile=get_full_with_python_path("src/forwarding/vxlan/vxlan_subsection.yaml"),
    )