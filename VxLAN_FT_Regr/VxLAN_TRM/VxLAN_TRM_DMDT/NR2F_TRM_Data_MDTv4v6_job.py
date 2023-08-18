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
        trigger_datafile=os.path.join(SCRIPT_PATH, "../GRunFiles/NR2F_TRM_Data_MDTv4v6_grun_data.yaml"),
        trigger_uids=[
            
            # -------------------------------------------
            # Initial Configurations
            # -------------------------------------------
            "TC_001_InitializeTestbed",
            # "TC_002_TcamCarvingAndReload",
            # "TC_003_CommonSetup",                         # Performing the base configurations
            "TC_004_ConfigureConvertL3VNIOld2New",        # NR1F - 10.3.1 - VxLAN New L3VNI CLI Configuration
            "TC_005_ConfigureIxia",                       # Apply the ixia configuration
            "TC_006_ConfigureDataMdt",                    # NR2F TRM Data MDT configuration
            
            # -------------------------------------------
            # Site-1 AC BGW , Site-2 VPC BGW Triggers
            # -------------------------------------------
            # >>>>>>> Generic Triggers
            # "TriggerFlapVrf_AcBgw2",
            # "TriggerFlapVrf_S2VpcBgwPrimary",
            # "TriggerFlapVrf_S2VpcBgwSecondary",                                         # Failing - EXT-RTR to S2-BGW2 Orphan failing
            # "TriggerClearIpMrouteVrfAll_S1AcBgw1",
            # "TriggerClearIpv6MrouteVrfAll_S1AcBgw2",
            # "TriggerClearIpMrouteVrfAll_S2VpcBgwSecondary",
            # "TriggerVpcPeerLinkFlap_S2VpcBgwPrimary",
            # "TriggerChangeVpcRolePriority_S2VpcBgw",
            # "TriggerRevertChangeVpcRolePriority_S2VpcBgw",
            # "TriggerFlapL2SviRange_S1S2",
            # "TriggerFlapL3SviRange_S1S2",
            
            # >>>>>>> VxLAN Triggers Triggers SITE-1
            # "TriggerDciIsolation_S1AcBgw1",
            # "TriggerFabricIsolation_S1AcBgw2",
            # "TriggerFlapNve_ACBGW1",
            # "TriggerDeleteAddNveInterface_ACBGW1",
            # "TriggerRemoveAddEvpnMsiteDciTracking_S1AcBgw1",                       # Failing - EXTTRMv6 TI
            # "TriggerRemoveAddEvpnMsiteFabricTracking_S1AcBgw2",
            # "TriggerRemoveAddNveVniMsiteIngressReplicationOptimized_S1ACBGW1",
            # "TriggerRemoveAddNveVniMsiteIngressReplication_S1ACBGW2",
            
            # >>>>>>> VxLAN Triggers Triggers SITE-2
            # "TriggerDciIsolation_S2VpcBgwPrimary",
            # "TriggerFabricIsolation_S2VpcBgwSecondary",
            # "TriggerFlapNve_S2VpcBgwPrimary",
            # "TriggerDeleteAddNveInterface_S2VpcBgwSecondary",
            # "TriggerRemoveAddEvpnMsiteDciTracking_S2VpcBgw2",
            # "TriggerRemoveAddEvpnMsiteFabricTracking_S2VpcBgw1",
            # "TriggerRemoveAddNveL3VniMultisiteMcastGroup_S2VpcBgwPrimary",
            # "TriggerRemoveAddNveL2VniMultisiteMcastGroup_S2VpcBgwSecondary",
            # "TriggerModifyNveSrcLoopbackIP_S2VpcBgwPrimary",
            # "TriggerRollbackNveSrcLoopbackIP_S2VpcBgwPrimary",                            # Failing - VPCTRMv4 TI loss - S2-VPC-BGW to S1-LEAF and EXT-RTR
            
            # >>>>>>> VxLAN Triggers Triggers SITE-1 and SITE-2
            # "TriggerChangeDciIrToMcastL2_S1S2",
            # "TriggerChangeDciMcastToIrL2_S1S2",
            
            # -------------------------------------------
            # Process restart Triggers
            # -------------------------------------------
            # >>>>>>> Site-1 AC BGW Process Restart Triggers
            # "TriggerRestartProcessNgmvpn_S1_S2",
            # "TriggerRestartProcessBgp_S1_S2",
            # "TriggerRestartProcessL2Rib_S1_S2",
            # "TriggerRestartProcessPim_S1_S2",
            # "TriggerRestartProcessIgmp_S1_S2",
            # "TriggerRestartProcessNve_S1_S2",
            # "TriggerRestartProcessMld_S1_S2",
            
            # -------------------------------------------
            # Servicability Triggers
            # -------------------------------------------
            # "TriggerConfigReplaceVrf_S2VpcBgwPrimary",
            # "TriggerConfigRollBack_int_nve_S2VpcBgwPrimary",
            
            # -------------------------------------------
            # HA Triggers
            # -------------------------------------------
            # "TriggerReload_S2VpcBgwPrimary",
            # "TriggerReload_S1AcBgw1",
            
            # "TriggerLCReload_S2VpcBgwPrimary",                                            # Failing - v6 L3KUC TI loss - S1 to S2
            # "TriggerSSO_S2VpcBgwPrimary",
            # "TriggerAllFMReload_S2VpcBgwPrimary",
            # "TriggerAllSCReload_S2VpcBgwPrimary",
            
            # -------------------------------------------
            # Failing Triggers
            # -------------------------------------------
            # "TriggerLCReload_S2VpcBgwPrimary",                                            # Failing - v6 L3KUC TI loss - S1 to S2
            # "TriggerRemoveAddEvpnMsiteDciTracking_S1AcBgw1",                              # Failing - EXTTRMv6 TI
            # "TriggerModifyNveSrcLoopbackIP_S2VpcBgwPrimary",
            # "TriggerRollbackNveSrcLoopbackIP_S2VpcBgwPrimary",                            # Failing - VPCTRMv4 TI loss - S2-VPC-BGW to S1-LEAF and EXT-RTR
            
            # -------------------------------------------
            # CC Test
            # -------------------------------------------
            # "SampleTest",
            
            # Common Cleanup
            # "CommonCleanup",
        ],
        subsection_datafile=get_full_with_python_path("src/forwarding/vxlan/vxlan_subsection.yaml"),
    )