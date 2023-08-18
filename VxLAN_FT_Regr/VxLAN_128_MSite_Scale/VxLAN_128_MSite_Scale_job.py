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
    #     trigger_datafile=os.path.join(SCRIPT_PATH, "VxLAN_128_MSite_Scale_grun_data.yaml"),
    #     trigger_uids=[
    #         "TC_001_InitializeTestbed",
    #         "CommonCleanup",
    #     ],
    #     subsection_datafile=get_full_with_python_path("src/forwarding/vxlan/vxlan_subsection.yaml"),
    # )

    # Actual run with the test-cases
    gRun(
        trigger_datafile=os.path.join(SCRIPT_PATH, "VxLAN_128_MSite_Scale_grun_data.yaml"),
        trigger_uids=[
            
            # Initial Setup for the devices
            "TC_001_InitializeTestbed",
            "TC_002_CommonSetup",

            # # Convert Alternate VRF's to new L3VNI
            "TC_003_TriggerConvertL3VNIOld2New",

            # # Configuration Adjustments, Adding Scale BGP Sessions
            "TC_004_ConfigureScaleMSiteVtepBgpSessionDCI",
            "TC_005_ConfigureScaleInterSiteVtepBgpSessionS1Spine",
            "TC_006_ConfigureScaleInterSiteVtepBgpSessionS2Spine",
            
            # # Apply the ixia configuration
            "TC_007_ConfigureIxia",

            # # Perform Loopbcaks/Fabric/DCI Link Flap Triggers
            "TC_008_TriggerFabricLinkFlap_S1_BGW_1",
            "TC_009_TriggerDCILinkFlap_S1_BGW_2",
            "TC_010_TriggerFabricLinkFlap_S2_BGW_1",
            "TC_011_TriggerDCILinkFlap_S2_BGW_2",
            "TC_012_TriggerFlapNve",
            "TC_013_TriggerNveSrcLoopbackFlap",
            "TC_014_TriggerMultisiteSrcLoopbackFlap",

            # # Perform clear Triggers
            "TC_015_TriggerClearARPAndMAC",
            "TC_016_TriggerClearIPv4RouteVrfAll",
            "TC_017_TriggerClearIPv6RouteVrfAll",
            "TC_018_TriggerClearBgpAll",

            # # Perform Process Restart Triggers
            "TC_019_TriggerRestartBgpCLI",
            "TC_020_TriggerRestartProcessKillNVE",

            # # Remove-Readd Configurations
            "TC_021_TriggerDisableAndEnableNveOverlay_S1_BGW_1",
            "TC_022_TriggerDisableAndEnableNveOverlay_S2_BGW_2",
            "TC_023_TriggerRemoveAddNewL3VNIUnderVRF",

            # # Reload BGW's
            "TC_024_TriggerReloadBGW_S1_BGW_1",
            "TC_025_TriggerReloadBGW_S2_BGW_2",

            # # EOR Triggers
            "TC_026_TriggerReloadFabricModules_S2_BGW_2",
            "TC_027_TriggerReloadLC_S2_BGW_1",
            "TC_028_TriggerConfigRollBack_S2_BGW_1",
            "TC_029_TriggerSSO_S2_BGW_1",

            # # Common Cleanup
            "CommonCleanup",
        ],
        subsection_datafile=get_full_with_python_path("src/forwarding/vxlan/vxlan_subsection.yaml"),
    )