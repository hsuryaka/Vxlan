"""
VxLAN_VNI_Scale_MSite_job.py

"""
# Author information
__author__ = 'Nexus India VxLAN DevTest Group'
__copyright__ = 'Copyright (c) 2021, Cisco Systems Inc.'
__contact__ = ['group.jdasgupt@cisco.com']
__credits__ = ['hsuryaka']
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
        trigger_datafile=os.path.join(SCRIPT_PATH, "Cloudsec_grun_data.yaml"),
        trigger_uids=[
            
            # Initial Setup for the devices
            "TC_001_InitializeTestbed",
            # "TC_002_CommonSetup",
            "TC_003_ConfigureIxia",

            #---------------------------------------#
            #            PSK to RSA Testcase's       #
            #---------------------------------------#
            "Migration_PSK_from_RSA_Certificate",
            # "Migration_PSK_to_PKI_with_RSA_Test265_Certificate",  # no need to run
            "TC_027_TriggerFLAPBGP",
            "TriggerProcessRestart",
            "TriggerProcessRestart1",
            "TriggerProcessRestart2",
            "TriggerFlapUnderlayIntf",
            "TC_019_TriggerFlapNve",
            "TC_021_FlapL2SviRange",
            "TC_022_FlapL3SviRange",
            "TC_012_VpcAccessFlap",

            #---------------------------------------#
            #            RSA to ECC Testcase's       #
            #---------------------------------------#
            "Migration_PSK_to_PKI_with_ECC_Certificate", 
            # # "Migration_RSA_to_ECC_Certificate",  # no need to run
            "TriggerRemAddPKILoopbackWithECC",
            "TriggerRemoveAddPKICertificate",
            "TriggerFlapNveWithECC",
            "TriggerNveSrcLoopbackFlapWithECC",
            "TriggerFlapIntfintoRouteserver",
            "TriggerProcessRestartTEM",
            "TriggerReloadpeerWithECC",


            #---------------------------------#
            #        ECC to RSA Testcase's     #
            #---------------------------------#
            
            # # "TC_004_PKI_certificate_installation",  # work in progress
            "Migration_ECC_to_RSA_Certificate",
            "TC_010_VpcPeerLinkFlapNveFlap",
            "TC_011_TriggerNoshutVpcMemberPort",
            "TC_020_Remove_add_VNIs_from_NVE",
            "TC_21_TriggerRmAddTunnelEncryptionpeer",
            "TC_025_TriggershutNoshutPKILoopback",
            "TC_026_TriggerDisableEnableFeatureTunnelEncryption",
            # # "Block_ISSD_NR2F",

            # "TriggermodifyPKILoopback",
            "TriggerRemAddPKILoopback",
            "TriggermodifyPKILoopbackIP",
            "TC_024a_TriggerFlapVrf",
            "TC_024b_TriggerRmAddVrf",
            "TC_014_TriggerVpcReloadPri",
            "TC_015_TriggerVpcReloadSec",
            "TC_017_TriggerReloadbothvPC",
            "TC_024_TriggerReload_SPINE",
            "TC_005_TriggerReloadAscii",
            "TC_022_TriggerChangeTunnelPolicy",
            "TriggerGIRadd",
            "TriggerGIRRemove",
            "TriggerChangeVPCRolepriority",

            # "ConfigurePki",
            # "Certificate_Installation",
            # "TriggerIssuIxiaSuite"


                     
            # Common Cleanup
            # "CommonCleanup",
        ],
        subsection_datafile=get_full_with_python_path("src/forwarding/vxlan/vxlan_subsection.yaml"),
    )

