"""
dot1x_job_VPC_FunctionalVerify.py

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
            "TC_001_dot1x_funcVerify_vpc2STD_mabSH",
            "TC_001_dot1x_funcVerify_std2VPC_mabMH",
            "TC_001_dot1x_funcVerify_fex2VPC_mabMA",
            "TC_002_dot1x_funcVerify_vpc2STD_eapSH",
            "TC_002_dot1x_funcVerify_std2VPC_eapMH",
            "TC_002_dot1x_funcVerify_fex2VPC_eapMA",
            "TC_004_dot1x_funcVerify_vpc2STD_mabSH",
            "TC_005_dot1x_funcVerify_std2VPC_mabSH",
            "TC_006_dot1x_funcVerify_fex2VPC_eapSH",
            "TC_009_dot1x_funcVerify_std2VPC_eapSH",
            "TC_010_dot1x_funcVerify_vpc2STD_eapMH",
            "TC_011_dot1x_funcVerify_vpc2STD_eapMA",
            "TC_012_dot1x_funcVerify_std2VPC_eapSHandMH",
            "TC_014_dot1x_funcVerify_fex2VPC_eapSH",
            "TC_015_dot1x_funcVerify_vpc2STD_mabSH",
            "TC_017_dot1x_funcVerify_std2VPC_mabSH",
            "TC_035_dot1x_funcVerify_poChan",
            "TC_036_dot1x_funcVerify_vpc2STD_eapSH",
            "TC_037_dot1x_funcVerify_vpc2STD_eapSH",
            "TC_038_dot1x_funcVerify_poChan",
            "TC_039A_dot1x_funcVerify_std2VPC_eapMA",
            "TC_039B_dot1x_funcVerify_std2VPC_eapMA",
            "TC_040A_dot1x_funcVerify_fex2STD_eapMA",
            "TC_040B_dot1x_funcVerify_fex2STD_eapSH2MH",
            "TC_041A_dot1x_funcVerify_vpc2STD_eapMA",
            "TC_041B_dot1x_funcVerify_vpc2STD_eapMA",
            "TC_Radius_Cleanup",
            "TC_VxLAN_CommonCleanup",
            "VxLAN_dot1x_automation_report",
            ],
        subsection_datafile=get_full_with_python_path("src/forwarding/vxlan/vxlan_subsection.yaml"),
    )