"""
dot1x_job_VPC_Mac-Move.py

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
            "TC_FeatureEnabling",
            "TC_Radius_Config",
            "TC_InitializeIxia_macmove",
            "TC_dot1x_mac_move_permit",
            "TC_047_dot1x_MM_sameVTEP",
            "TC_048_dot1x_MM_diffVTEP",
            "TC_049_dot1x_MM_vpcPri2vpcSec",
            "TC_051_dot1x_MM_sameVTEP_regPort",
            "TC_052_dot1x_MM_remoVTEP_regPort",
            "TC_053_dot1x_MM_vpcPri2vpcSec",
            "TC_055_dot1x_MM_sameVTEP_securePort",
            "TC_056_dot1x_MM_remoVTEP_regPort",
            "TC_057_dot1x_MM_vpcPri2vpcSec",
            "TC_059_dot1x_MM_sameVTEP_securePort",
            "TC_060_dot1x_MM_remoVTEP_regPort",
            "TC_061_dot1x_MM_vpcPri2vpcSec",
            "TC_dot1x_mac_move_deny",
            "TC_063_dot1x_MM_D_sameVTEP",
            "TC_064_dot1x_MM_D_remoVTEP",
            "TC_065_dot1x_MM_D_vpcPri2vpcSec",
            "TC_067_dot1x_MM_D_dot1x2regular",
            "TC_068_dot1x_MM_D_dot1x2regular",
            "TC_069_dot1x_MM_D_vpcPri2vpcSec",
            "TC_071_dot1x_MM_D_regular2dot1x",
            "TC_072_dot1x_MM_D_regular2dot1x",
            "TC_073_dot1x_MM_D_regVpcPri2dot1xVpcSec",
            "TC_dot1x_mac_move_conflict",
            "TC_075_dot1x_MM_C_sameVTEP",
            "TC_076_dot1x_MM_C_remoVTEP",
            "TC_077_dot1x_MM_C_vpcPri2vpcSec",
            "TC_Radius_Cleanup",
            "TC_VxLAN_CommonCleanup",
            "VxLAN_dot1x_automation_report",
            ],
        subsection_datafile=get_full_with_python_path("src/forwarding/vxlan/vxlan_subsection.yaml"),
    )