"""
VxLAN_IPv6_ND_Suppression_job.py

"""
# Author information
__author__ = 'Nexus India VxLAN DevTest Group'
__copyright__ = 'Copyright (c) 2021, Cisco Systems Inc.'
__contact__ = ['group.jdasgupt@cisco.com']
__credits__ = ['haganapt']
__version__ = 1.0

import os
from genie.harness.main import gRun
from lib.utils.find_path import get_full_with_python_path
SCRIPT_PATH = os.path.dirname(os.path.realpath(__file__))

def main():
    # # Initial run to clean up the devices
    # gRun(
    #     trigger_datafile=os.path.join(SCRIPT_PATH, "VxLAN_ND_Suppression_grun_data.yaml"),
    #     trigger_uids=[
    #         "TC_001_InitializeTestbed",
    #         "CommonCleanup",
    #     ],
    #     subsection_datafile=get_full_with_python_path("src/forwarding/vxlan/vxlan_subsection.yaml"),
    # )

    # Actual run with the test-cases
    gRun(
        trigger_datafile=os.path.join(SCRIPT_PATH, "VxLAN_ND_Suppression_grun_data.yaml"),
        trigger_uids=[
            
            # Initial Setup for the devices
            "TC_001_InitializeTestbed",
            # "TC_002_TcamCarvingAndReload",
            # No need to run common setup since the DUTs are loaded with base configs
            # "TC_003_CommonSetup",

            # # Convert Alternate VRF's to new L3VNI
            # # # # "TC_004_TriggerConvertL3VNIOld2New",
            
            # # Apply the ixia configuration
            "TC_005_ConfigureIxia",

            # # # Perform Loopbcaks Link Flap Triggers
            "TC_006_TriggerFlapNve",
            "TC_007_TriggerNveSrcLoopbackFlap",
            "TC_00X_TriggerClearIPv6NeighborVrfAll",
            "TC_00X_TriggerHostMoveSuppND_Before",
            "TC_00X_NDSuppressionVerification",
            "TC_00X_TriggerHostMoveSuppND_After",

            # # # # Run TC_00X_ConfigureixiaOrphanFlap before starting TC_00X_TriggerNDSupp_OrphanFlapXXX
            "TC_00X_ConfigureixiaOrphanFlap", #
            "TC_00X_TriggerClearIPv6NeighborVrfAll",
            "TC_00X_TriggerNDSupp_MCTFlapPri",
            "TC_00X_TriggerNDSupp_VPCPoFlapPri",
            "TC_00X_TriggerNDSupp_OrphanFlapPri", #
            "TC_00X_TriggerNDSupp_OrphanFlapSec", #

            "TC_00X_TriggerClearIPv6NeighborVrfAll",

            "TC_00X_TriggerNDSupp_NVE_RmvReadd", #
            "TC_00X_TriggerNDSupp_SVI_MultipleV6Addr", #
            "TC_00X_SuppNDCacheSummary",
            "TC_00X_TriggerClearIPv6NeighborVrfAll",
            "TC_00X_SuppNDCacheSummaryLocal", #
            "TC_00X_SuppNDCacheSummaryRemote", #
            "TC_00X_SuppNDCacheSummaryVlan", #
            
            # # # # Perform clear Triggers
            "TC_008_TriggerClearARPAndMAC",
            "TC_009_TriggerClearIPv4RouteVrfAll",
            "TC_010_TriggerClearIPv6RouteVrfAll",
            "TC_012_TriggerClearBgpAll",

            # # # # Perform Process Restart Triggers
            "TC_013_TriggerRestartBgpCLI",
            "TC_014_TriggerRestartProcessKillNVE",
            "TC_00X_TriggerNDSupp_ArpRestart", #
            "TC_00X_TriggerNDSupp_ICMPv6Restart", #
            
            # # Remove-Readd Configurations
            "TC_021_TriggerDisableAndEnableNveOverlay_S1_BGW_1",
            "TC_022_TriggerDisableAndEnableNveOverlay_S2_BGW_2",
            # # "TC_023_TriggerRemoveAddNewL3VNIUnderVRF", **
            "TC_00X_TriggerRemoveReaddNDSuppression",
            "TC_00X_TriggerNoARPSuppNDSuppression",
            "TC_00X_TriggerVPCPriRemSuppND",


            # # # # Reload BGW's
            "TC_024_TriggerReloadBGW_S1_BGW_1",
            "TC_025_TriggerReloadBGW_S2_BGW_2",

            # EOR Triggers
            ##"TC_026_TriggerReloadFabricModules_S2_BGW_2", **
            ##"TC_027_TriggerReloadLC_S2_BGW_1", **
            ##"TC_028_TriggerConfigRollBack_S2_BGW_1", **
            ##"TC_029_TriggerSSO_S2_BGW_1", **

            # # Common Cleanup
            # "CommonCleanup",
        ],
        subsection_datafile=get_full_with_python_path("src/forwarding/vxlan/vxlan_subsection.yaml"),
    )
