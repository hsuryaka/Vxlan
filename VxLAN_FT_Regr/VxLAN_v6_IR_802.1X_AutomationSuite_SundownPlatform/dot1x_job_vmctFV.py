"""
dot1x_job_VMCT_FunctionalVerify.py

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
            "TC_TcamCarvingAndReload",
            "TC_VxLAN_CommonSetup",
            "TC_FabricXtender_Bringup",
            "TC_InitializeIxia_funcVerify",
            "TC_VMCT_disableFeatue_Pre",
            "TC__VMCT_conversion_Bringup_Main",
            "TC__VMCT_conversion_Bringup_Post",
            "TC_FeatureEnabling",
            "TC_Radius_Config",
            "TC_018_dot1x_funcVerify_vmct2STD_mabSH",
            "TC_018_dot1x_funcVerify_std2VMCT_mabMH",
            "TC_018_dot1x_funcVerify_fex2VMCT_mabMA",
            "TC_019_dot1x_funcVerify_vmct2STD_eapSH",
            "TC_019_dot1x_funcVerify_std2VMCT_eapMH",
            "TC_019_dot1x_funcVerify_fex2VMCT_eapMA",
            "TC_021_dot1x_funcVerify_vmct2STD_mabSH",
            "TC_022_dot1x_funcVerify_std2VMCT_mabSH",
            "TC_023_dot1x_funcVerify_fex2VMCT_eapSH",
            "TC_026_dot1x_funcVerify_std2VMCT_eapSH",
            "TC_027_dot1x_funcVerify_vmct2STD_eapMH",
            "TC_028_dot1x_funcVerify_vmct2STD_eapMA",
            "TC_029_dot1x_funcVerify_std2VMCT_eapSHandMH",
            "TC_031_dot1x_funcVerify_fex2VMCT_eapSH",
            "TC_032_dot1x_funcVerify_vmct2STD_mabSH",
            "TC_034_dot1x_funcVerify_std2VMCT_mabSH",
            "TC_035_dot1x_funcVerify_poChan_vmct",
            "TC_042_dot1x_funcVerify_vmct2STD_eapSH",
            "TC_043_dot1x_funcVerify_vmct2STD_eapSH",
            "TC_044A_dot1x_funcVerify_std2VMCT_eapMA",
            "TC_044B_dot1x_funcVerify_std2VMCT_eapMA",
            "TC_045A_dot1x_funcVerify_fex2VMCT_eapMA",
            "TC_045B_dot1x_funcVerify_fex2VMCT_eapSH2MH",
            "TC_046A_dot1x_funcVerify_vmct2STD_eapMA",
            "TC_046B_dot1x_funcVerify_vmct2STD_eapMA",
            "TC_Radius_Cleanup",
            "TC_VxLAN_CommonCleanup",
            "VxLAN_dot1x_automation_report",
            ],
        subsection_datafile=get_full_with_python_path("src/forwarding/vxlan/vxlan_subsection.yaml"),
    )