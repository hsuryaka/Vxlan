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
    #     trigger_datafile=os.path.join(SCRIPT_PATH, "VxLAN_TRM_NBM_grun_data.yaml"),
    #     trigger_uids=[
    #         "TC_001_InitializeTestbed",
    #         "CommonCleanup",
    #     ],
    #     subsection_datafile=get_full_with_python_path("src/forwarding/vxlan/vxlan_subsection.yaml"),
    # )

    # Actual run with the test-cases
    gRun(
        trigger_datafile=os.path.join(SCRIPT_PATH, "VxLAN_TRM_NBM_grun_data.yaml"),
        trigger_uids=[
            
            # Initial Setup for the devices
            "TC_001_InitializeTestbed",
            "TC_002_TcamCarvingAndReload",
            "TC_003_CommonSetup",
            
            # Convert Alternate VRF's to new L3VNI
            # "TC_004_TriggerConvertL3VNIOld2New",

            # # Apply the ixia configuration
            "TC_005_ConfigureIxia",

            # Perform FLAP Triggers
            "TC_006_TriggerFlapNve_STD_VTEP",
            "TC_007_TriggerFlapNve_VPC_Primary_VTEP",
            "TC_008_TriggerNveSrcLoopbackFlap_STD_VTEP",
            "TC_009_TriggerNveSrcLoopbackFlap_VPC_Secondary_VTEP",
            "TC_010_TriggerFlapVrf_TRM",
            "TC_011_TriggerFlapVrf_NBM",
            "TC_012_TRMUPLinkFlap",
            "TC_013_NBMUPLinkFlap",

            # Perform Restart Triggers
            "TC_014_TriggerRestartBgpCLI_STD_VTEP",
            "TC_015_TriggerRestartBgpCLI_VPC_Primary_VTEP",

            # Perform Process Restarts / Kills
            "TC_016_TriggerRestartProcessKillNVE",
            "TC_017_TriggerRestartProcessKillNBM",
            "TC_018_TriggerDisableAndEnableNveOverlay",
            
            # Perform Device Reload
            "TC_019_TriggerReloadVTEP",

            # Perform Unconfig and config using checkpoint - rollback
            "TC_020_TriggerConfigRollBack_int_nve",
            "TC_021_TriggerConfigRollBack_feature_nbm",

            # Sample Trigger
            # "SampleTest",

            # # Common Cleanup
            # "CommonCleanup",
        ],
        subsection_datafile=get_full_with_python_path("src/forwarding/vxlan/vxlan_subsection.yaml"),
    )