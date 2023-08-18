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
        trigger_datafile=os.path.join(SCRIPT_PATH, "./vxlan_te_bgp_grun.yaml"),
        trigger_uids=[
            
            # -------------------------------------------
            # Initial Configurations
            # -------------------------------------------
            "TC_001_InitializeTestbed",
            "TC_003_CommonSetup",                         # Performing the base configurations
            "TC_004_ConfigureIxia",
            "TC_005_rem_add_vlan",
            "TC_006_rem_add_svi",
            "TC_007_rem_add_vni_under_nve",
            "TC_008_rem_add_bgp_neighbour",
             "TC_009_rem_add_advertise_pip_virtual_rmac",
             "TC_010_rem_add_evpn_multisite_dci_tracking",
             "TC_011_rem_add_evpn_multisite_border_gateway",
             "TC_012_change_nve_source_interface_ip_address",
             "TC_013_change_nve_source_interface_vip_address",
             "TC_014_change_multisite_id",
             "TC_015_Change_Multisite_Loopback_Interface_IP_Address",
             "TC_016_Change_bgp_router_id",
             "TC_017_shut_no_shut_svi",
            "TC_018_shut_no_shut_nve_source_interface",
            "TC_019_config_replace" ,
            "TC_020_Shut_NoShut_vPC_Primary" ,
            "TC_021_TriggerGIRAddConvergence",
            "TC_022_TriggerGIRRemoveConvergence",
            "TC_023_configure_bfd" ,
            "TC_024_ixia_host_move" ,
            "TC_025_host_move",
            "TC_026_disable_vn_segment_vlan_based_new",


            
            
            
            #  Common Cleanup
            # "CommonCleanup",
        ],
        subsection_datafile=get_full_with_python_path("src/forwarding/vxlan/vxlan_subsection.yaml"),
    )