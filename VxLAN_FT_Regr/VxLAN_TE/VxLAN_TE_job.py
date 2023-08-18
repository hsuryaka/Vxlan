"""
VxLAN_TE_job.py

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
    #     trigger_datafile=os.path.join(SCRIPT_PATH, "VxLAN_TE_grun_data.yaml"),
    #     trigger_uids=[
    #         "TC_001_InitializeTestbed",
    #         "CommonCleanup",
    #     ],
    #     subsection_datafile=get_full_with_python_path("src/forwarding/vxlan/vxlan_subsection.yaml"),
    # )

    # Actual run with the test-cases
    gRun(
        trigger_datafile=os.path.join(SCRIPT_PATH, "VxLAN_TE_grun_data.yaml"),
        trigger_uids=[
            
            # Initial Setup for the devices
            "TC_001_InitializeTestbed",
            # "TC_002_TcamCarvingAndReload",
            # No need to run common setup since the DUTs are loaded with base configs
            # "TC_003_CommonSetup",
           
            # # # Apply the ixia configuration
            "TC_005_ConfigureIxia",

            # # # # # # Perform Triggers
            # "TC_TriggerFlapNve",
            # "TC_TriggerMaxPathChange",
            # "TC_TriggerCreateVrfEgressLoadBalance",
            # "TC_TriggerRouterServerLinkFlap",
            # "TC_TriggerDCILinkFlapBGW",
            # "TC_TriggerFabricLinkFlapBGW",
            # # # "TC_TriggerMsiteLoopbackFlapBGW", # Multisite is not supported
            # "TC_TriggerPeerLinkFlapBGW",            

            # "TC_TriggerFilterPolicy_RmvReadd", #
            # "TC_TriggerMsite_Loopback_RmvReadd",
            # "TC_TriggerRemoveAddNewL3VNIUnderVRF", #
            # "TC_TriggerRemoveAddVNsegmentFeature", #
            # "TC_TriggerAddEgresLB_no_NVE_Overlay", #            
            # "TC_TriggerRemoveAddNVEinterface", #


            # "TC_TriggerRestartBgpCLI",
            # "TC_TriggerShutNoShutBgpCLI",
            # "TC_TriggerKillHMM",
            # "TC_TriggerKillNVE",


            # "TC_ConsistencyChecker",
            # "TC_ConfigReplace",


            "TC_TriggerReloadBGW_S1_BGW_1",
            "TC_TriggerReloadBGW_S2_BGW_2",

            # "TC_NDIssu_StandAloneBGW",

            # "TC_CommonCleanUp",


            # # Common Cleanup
            # "CommonCleanup",
        ],
        subsection_datafile=get_full_with_python_path("src/forwarding/vxlan/vxlan_subsection.yaml"),
    )
