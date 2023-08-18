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
        trigger_datafile=os.path.join(SCRIPT_PATH, "./pvlan_v6_grun.yaml"),
        trigger_uids=[
            
            # -------------------------------------------
            # Initial Configurations
            # -------------------------------------------
            "TC_001_InitializeTestbed",
            # "TC_002_TcamCarvingAndReload",
            # "TC_003_CommonSetup",                         # Performing the base configurations
            "TC_004_ConfigureIxia",                         # Load " NewConfig.PvLAN-TC1.ixncfg " config file
            # "TC_005_rem_add_vlan",
            # "TC_006_consistency_parameters",
            # "TC_007_change_community_vlan",
            # "TC_008_different_vlan",
            # "TC_009_flap_nve",
            # "TC_031_flap_bgp",
            # "TC_010_flap_nve_loopback",
            # "TC_011_flap_port",
            # "TC_014_pvlan_counters",
            # #"TC_079_no_feature_private_vlan",
            # "TC_016_pvlan_on_l3vni",
            # "TC_017_no_pvlan_mac_learnt",
            # "TC_018_vni_shut_mac_learnt",
            # "TC_019_clear_learnt_mac",
            # "TC_020_pvlan_to_portchannel",
            # "TC_021_L3_uplink_flap",
            #  "TC_022_pvlan_to_normal_vlan_mac_learn",
            # "TC_023_normal_vlan_to_pvlan_mac_learn",
            # "TC_024_isolated_community_vica_versa",
            # "TC_025_isolated_community_isolated",
            # "TC_026_static_mac",
            # "TC_027_process_restart",
            # "TC_028_community_to_promiscous",
            # "TC_029_isolated_to_promiscous",
            # "TC_033_native_vlan_on_peomiscuous",
            # "TC_034_clear_trigger",
            # # "TC_036_snmp_stats",        # Need to discuss  
            # # # "TC_041_snmp_stats1",
            # "TC_043_multiple_primary_secondary_ports1",
            # "TC_044_pvlan_in_peerlink_not_allowed",
            # "TC_045_pvlan_adding_and_removing_members_from_portchannel",
            # "TC_046_reload_verify_secondary_and_pvlan_traffic",
            # "TC_047_nve_flap_on_primary",
            # "TC_048_nve_loopback_flap_on_primary",
            # "TC_049_svi_flap",
            # "TC_039_mac_move_vpc_community_vlan",
            # "TC_040_mac_move_vpc_isolated_vlan",
            # # "TC_050_TriggerReloadAscii",
            # "TC_052_multiple_primary_secondary_ports",
            # # "TC_053_multiple_primary_secondary_ports_isolated",
            # "TC_054_pvlan_with_system_dot1q_transit",
            # # "TC_055_vmct_configs",  # need to check 
            # "TC_056_vmct_configs_reload",
            # "TC_060_isolated_community_promiscuous",
            # "TC_061_native_vlan_vmct",
            # "TC_063_Reload_vtep_vmct",
            # "TC_062_trunk_community_promiscuous",
            # "TC_064_mac_move_vmct_community_vlan",
            # "TC_065_mac_move_vmct_isolated_vlan",
            # # "TC_066_NDIssu_StandAloneBGW",
            # "TC_067_copy_replace",
            # "TC_069_igmp_snooping_disabled",
            # "TC_078_dhcp_snooping_enabled",
            # "TC_076_downgrade_image",
            
            
            # Common Cleanup
            # "CommonCleanup",
        ],
        subsection_datafile=get_full_with_python_path("src/forwarding/vxlan/vxlan_subsection.yaml"),
    )