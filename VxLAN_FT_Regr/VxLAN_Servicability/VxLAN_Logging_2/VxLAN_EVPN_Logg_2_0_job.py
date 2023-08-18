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
from ats.easypy import run
from lib.utils.find_path import get_full_with_python_path
SCRIPT_PATH = os.path.dirname(os.path.realpath(__file__))

def main():

    # Initial Full Clean up the devices
    # Run the below only if you want to clean up any existing configuration belonging to this script
    # gRun(
    #     trigger_datafile=os.path.join(SCRIPT_PATH, "VxLAN_EVPN_Logg_2_0_grun_data.yaml"),
    #     trigger_uids=[
    #         "InitializeTestbed",
    #         "CommonCleanup",
    #     ],
    #     subsection_datafile=get_full_with_python_path("src/forwarding/vxlan/vxlan_subsection.yaml"),
    # )

    # Task-1 : VxLAN Bring UP
    gRun(
        trigger_datafile=os.path.join(SCRIPT_PATH, "VxLAN_EVPN_Logg_2_0_grun_data.yaml"),
        trigger_uids=[
            
            "InitializeTestbed",
            "CommonSetup",
            "ConfigureIxia",
        ],
        subsection_datafile=get_full_with_python_path("src/forwarding/vxlan/vxlan_subsection.yaml"),
    )

    # Task-2 : auto collect script for Component vntag_mgr
    run(testscript = './VxLAN_EVPN_Logg_2_0_script.py' , component = 'vntag_mgr' , Autocollect_yaml_file = './vntag_mgr.yaml', connect = "true")

    # Task-3 : Clean up the devices
    gRun(
        trigger_datafile=os.path.join(SCRIPT_PATH, "VxLAN_EVPN_Logg_2_0_grun_data.yaml"),
        trigger_uids=[
            "InitializeTestbed",
            "CommonCleanup",
        ],
        subsection_datafile=get_full_with_python_path("src/forwarding/vxlan/vxlan_subsection.yaml"),
    )
