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
        trigger_datafile=os.path.join(SCRIPT_PATH, "FX-3_Evpn_Bh_grun_data.yaml"),
        trigger_uids=[
            
             # Initial Setup for the devices
            "TC_001_InitializeTestbed",
            # "TC_002_CommonSetup",
            # # "TC_0013_L2_mcast_traffic_to_and_from_BH_hosts",
            "TC_003_ConfigureIxia",

            ######TestaCase's#########
        
            # "TC_0020_Config_MAC_BH_on_VPC_Vtep",
            # "TC_0022_Mac_BH_route_on_Standalone_Vtep",
            # "TC_0024_Mac_BH_on_VPC_start_Traffic",
            # "TC_0025_Config_Mac_BH_onRemoteVtep_Start_traffic",
            # "TC_0026_Configure_BH_route_static_arp_on_vpcvtep",
            "TC_0029_Mac_BH_route_static_ARP_on_standalonevtep",
            "TC_0031_MAC_BH_route_on_vpc_vtep_start_traffic",
            "TC_0032_MAC_BH_route_on_Standalone_vtep_start_traffic",
            # "TC_0034_Mac_BH_route_static_ND_on_VPC_vtep",
            # "TC_0036_Mac_BH_route_static_ND_on_RemoteVtep",
            # "TC_0038_ND_MAC_BH_route_on_vpc_vtep_then_start_traffic",
            # "TC_0039_ND_Mac_BH_route_on_standalone_vtep_then_start_traffic",
            "TC_0041_Mac_BH_route_static_arp_on_vpc_vtep_with_L3_traffic",
            "TC_0043_Mac_BH_route_Static_arp_on_standalone_Vtep_with_l3_traffic",
            # "TC_0045_Mac_BH_route_on_vpc_vtep_start_L3_traffic",
            "TC_0046_Mac_BH_route_on_standalone_vtep_start_L3_traffic",
            # "TC_0048_Mac_BH_route_static_arp_on_VPC_vtep_with_L3_ipv6_traffic",
            # "TC_0050_Mac_BH_route_static_arp_on_remote_vtep_with_L3_traffic_ipv6header",
            # "TC_0052_Mac_BH_route_on_vpc_vtep_Start_L3_traffic_with_ipv6_header",
            # "TC_0053_Mac_BH_route_on_remote_vtep_start_traffic_with_ipv6_header",
            # "TC_0054_Type5_route_with_Null_NH",
            # "TC_0016_CLI_verification",
            # "TC_0073_Arp_cli_should_show_BH_flags",
            # "TC_0063_ Verify_New_icmpv6_CLIs",
            # "TC_0070_Static_Arp_with_BH_mac_route_Without_suppress_ARP",
            # "TC_0077_MAC_BH_static_ND_for_Orphan_vpc_Host_with_L3Ipv6",
            # "TC_0076_Prefix_BH_route_for_Orphan_vpc_Host_with_L3Ipv4",
            # "TC_0078_Prefix_BH_route_for_Orphan_vpc_Host_with_L3Ipv6",
            # "TC_0072_Static_ND_with_BH_mac_route_with_Suppress_ND",
            # "TC_0075_MAC_BH_static_ARP_for_Orphan_vpc_Host_with_L2Ipv4",
            # "TC_0068_Configure_Same_static_ARP_on_2_vteps",

            # ######:-   Port security TC's _-:######
            "TC_0124_Configure_Static_mac_on_vpc_vtep_pointing_to_an_interface_on_the_vpc_vtep",

            # # #####: Negative TC's  :#########
            # "TC_0107_Unknown_Unicast_traffic_Configure_BH_mac_route_to_this_Destmac",
            
            #  ######Triggers TC's#########
           
            # "TC_098_TriggerRestartBgpCLI",
            # "TC_0091_L2rib_PROCESS_RESTART",
            # "TC_0092_HMM_PROCESS_RESTART",
            # "TC_0088_ARP_PROCESS_RESTART",
            # "TC_0089_icmpv6_PROCESS_RESTART",
            # "TC_0090_L2FM_PROCESS_RESTART",
            # "TC_0093_RPM_PROCESS_RESTART",
            # "TC_0094_adjmgr_PROCESS_RESTART",
            # "TC_0097_NVE_PROCESS_RESTART",
            # "TC_0087_BGP_PROCESS_RESTART",
            # "TC_101_FlapSviRange",
            # "TC_0099_TriggerFabricLinkFlap_S1_BGW1",
            # "TC_010_TriggerFabricLinkFlap_S2_BGW_1",
            # "TC_0100_TriggerNveSrcLoopbackFlap",
            # "TC_0095_TriggerFlapVrf",
            # "TC_0096_TriggerMCTFlap",
            "TC_0080_TriggerReloadBGW_S2_BGW_2",
            "TC_00029_TriggerSSO_S1_BGW_1",
            # "TC_00027_TriggerReloadLC_S1_BGW_1",
            "TC_00026_TriggerReloadFabricModules_S1_BGW_1",
            # "TC_00028_TriggerReloadSC_S1_BGW_1",

            
            # Common Cleanup
            #"CommonCleanup",
        ],
        subsection_datafile=("/auto/dc3-india/hsuryaka/pyATS/automation/repo_develop/nexus-test-pyats/src/forwarding/vxlan/vxlan_subsection.yaml"),
    )
