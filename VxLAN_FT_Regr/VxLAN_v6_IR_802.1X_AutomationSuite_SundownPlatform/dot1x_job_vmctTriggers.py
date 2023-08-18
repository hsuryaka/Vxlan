"""
dot1x_job_VPC_Triggers.py

"""
# Author information
__author__ = 'Nexus India VxLAN DevTest Group'
__copyright__ = 'Copyright (c) 2023, Cisco Systems Inc.'
__contact__ = ['absr@cisco.com']
__credits__ = ['absr']
__version__ = 2.0

import os
from genie.harness.main import gRun
from lib.utils.find_path import get_full_with_python_path
SCRIPT_PATH = os.path.dirname(os.path.realpath(__file__))

def main():

    #-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-
    #                 Initial run to clean up the devices              #
    #-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-  

    gRun(
        trigger_datafile=os.path.join(SCRIPT_PATH, "./dot1x_grun.yaml"),
        trigger_uids=[
            "TC_InitializeTestbed",
            "TC_VxLAN_CommonSetup",
            "TC_FabricXtender_Bringup",
            "TC_InitializeIxia_funcVerify",
            "TC_FeatureEnabling",
            "TC_Radius_Config",
            "TC_080A_dot1x_reload_vpcPri_Pre",
            "TC_080A_dot1x_reload_vpcPri_Main",
            "TC_080A_dot1x_reload_vpcPri_Post",
            "TC_080A_dot1x_reload_vpcPri_Cleanup",
            "TC_080B_dot1x_reload_VPCSec_Pre",
            "TC_080B_dot1x_reload_VPCSec_Main",
            "TC_080B_dot1x_reload_VPCSec_Post",
            "TC_080B_dot1x_reload_VPCSec_Cleanup",
            "TC_082A_dot1x_asciiReload_VPCPri_Pre",
            "TC_082A_dot1x_asciiReload_VPCPri_Main",
            "TC_082A_dot1x_asciiReload_VPCPri_Post",
            "TC_082A_dot1x_asciiReload_VPCPri_Cleanup",
            "TC_082B_dot1x_asciiReload_VPCSec_Pre",
            "TC_082B_dot1x_asciiReload_VPCSec_Main",
            "TC_082B_dot1x_asciiReload_VPCSec_Post",
            "TC_082B_dot1x_asciiReload_VPCSec_Cleanup",
            "TC_086_dot1x_LXCissu_VPCPri_Pre",
            "TC_086_dot1x_LXCissu_VPCPri_Main",
            "TC_086_dot1x_LXCissu_VPCPri_Post",
            "TC_086_dot1x_LXCissu_VPCPri_Cleanup",
            "TC_086_dot1x_LXCissu_VPCSec_Pre",
            "TC_086_dot1x_LXCissu_VPCSec_Main",
            "TC_086_dot1x_LXCissu_VPCSec_Post",
            "TC_086_dot1x_LXCissu_VPCSec_Cleanup",
            "TC_090A_dot1x_verify_file2start_Pre",
            "TC_090A_dot1x_verify_file2start_Main",
            "TC_090A_dot1x_verify_file2start_Post",
            "TC_090A_dot1x_verify_file2start_Cleanup",
            "TC_090B_dot1x_verify_file2run_Pre",
            "TC_090B_dot1x_verify_file2run_Main",
            "TC_090B_dot1x_verify_file2run_Post",
            "TC_090B_dot1x_verify_file2run_Cleanup",
            "TC_090C_dot1x_verify_configReplace_Pre",
            "TC_090C_dot1x_verify_configReplace_Main",
            "TC_090C_dot1x_verify_configReplace_Post",
            "TC_090C_dot1x_verify_configReplace_Cleanup",
            "TC_090D_dot1x_checkpointRollback_Pre",
            "TC_090D_dot1x_checkpointRollback_Main",
            "TC_090D_dot1x_checkpointRollback_Post",
            "TC_090D_dot1x_checkpointRollback_Cleanup",
            "TC_091_dot1x_miscellaneous_VxLAN_CC_Pre",
            "TC_091_dot1x_miscellaneous_VxLAN_CCinfra_Main",
            "TC_091_dot1x_miscellaneous_VxLAN_CCmodule_Main",
            "TC_091_dot1x_miscellaneous_VxLAN_CC_Post",
            "TC_091_dot1x_miscellaneous_VxLAN_CC_Cleanup",
            "TC_093_dot1x_trigger_L3flap_VPCSec_Pre",
            "TC_093_dot1x_trigger_L3flap_VPCSec_Main",
            "TC_093_dot1x_trigger_L3flap_VPCSec_Post",
            "TC_093_dot1x_trigger_L3flap_VPCSec_Cleanup",
            "TC_095A_dot1x_trigger_NVEflap_VPCSec_Pre",
            "TC_095A_dot1x_trigger_NVEflap_VPCSec_Main",
            "TC_095A_dot1x_trigger_NVEflap_VPCSec_Post",
            "TC_095A_dot1x_trigger_NVEflap_VPCSec_Cleanup",
            "TC_095B_dot1x_trigger_NVESrcLoopflap_VPCSec_Pre",
            "TC_095B_dot1x_trigger_NVESrcLoopflap_VPCSec_Main",
            "TC_095B_dot1x_trigger_NVESrcLoopflap_VPCSec_Post",
            "TC_095B_dot1x_trigger_NVESrcLoopflap_VPCSec_Cleanup",
            "TC_097_dot1x_trigger_BGPflap_VPCSec_Pre",
            "TC_097_dot1x_trigger_BGPflap_VPCSec_Main",
            "TC_097_dot1x_trigger_BGPflap_VPCSec_Post",
            "TC_097_dot1x_trigger_BGPflap_VPCSec_Cleanup",
            "TC_098_dot1x_trigger_clearBulk_VPCSec_Pre",
            "TC_098_dot1x_trigger_clearBulk_VPCSec_Main",
            "TC_098_dot1x_trigger_clearBulk_VPCSec_Post",
            "TC_098_dot1x_trigger_clearBulk_VPCSec_Cleanup",
            "TC_100_dot1x_trigger_flapDot1xInterface_VPCSec_Pre",
            "TC_100_dot1x_trigger_flapDot1xInterface_VPCSec_Main",
            "TC_100_dot1x_trigger_flapDot1xInterface_VPCSec_Post",
            "TC_100_dot1x_trigger_flapDot1xInterface_VPCSec_Cleanup",
            "TC_101_dot1x_trigger_restartProcesses_VPCSec_Pre",
            "TC_101_dot1x_trigger_restartProcesses_VPCSec_Main",
            "TC_101_dot1x_trigger_restartProcesses_VPCSec_Post",
            "TC_101_dot1x_trigger_restartProcesses_VPCSec_Cleanup",
            "TC_102B_dot1x_trigger_enabDisa_featVNI_VPCSec_Pre",
            "TC_102B_dot1x_trigger_enabDisa_featVNI_VPCSec_Main",
            "TC_102B_dot1x_trigger_enabDisa_featVNI_VPCSec_Post",
            "TC_102B_dot1x_trigger_enabDisa_featVNI_VPCSec_Cleanup",
            "TC_102C_dot1x_trigger_enabDisa_featBGP_VPCSec_Pre",
            "TC_102C_dot1x_trigger_enabDisa_featBGP_VPCSec_Main",
            "TC_102C_dot1x_trigger_enabDisa_featBGP_VPCSec_Post",
            "TC_102C_dot1x_trigger_enabDisa_featBGP_VPCSec_Cleanup",
            "TC_102D_dot1x_trigger_enabDisa_featDOT1X_VPCSec_Pre",
            "TC_102D_dot1x_trigger_enabDisa_featDOT1X_VPCSec_Main",
            "TC_102D_dot1x_trigger_enabDisa_featDOT1X_VPCSec_Post",
            "TC_102D_dot1x_trigger_enabDisa_featDOT1X_VPCSec_Cleanup",
            "TC_105_dot1x_FeatInter_staticMAC_VPCSec",
            "TC_106_dot1x_FeatInter_evpnBH_VPCSec",
            "TC_Radius_Cleanup",
            "TC_VxLAN_CommonCleanup",
            "VxLAN_dot1x_automation_report",
            ],
        subsection_datafile=get_full_with_python_path("src/forwarding/vxlan/vxlan_subsection.yaml"),
    )
