"""
VxLAN_FHS_job.py

"""
# Author information
__author__ = 'Nexus India VxLAN DevTest Group'
__copyright__ = 'Copyright (c) 2021, Cisco Systems Inc.'
__contact__ = ['group.jdasgupt@cisco.com']
__credits__ = ['ratrajen']
__version__ = 1.0

import os
from genie.harness.main import gRun
from lib.utils.find_path import get_full_with_python_path
SCRIPT_PATH = os.path.dirname(os.path.realpath(__file__))
def main():
    # Actual run with the test-cases
    gRun(
        trigger_datafile=os.path.join(SCRIPT_PATH, "VxLAN_FHS_MacMove_grundata.yaml"),
        trigger_uids=[

            # -------------------------------------------
            # Initial Configurations
            # -------------------------------------------
            "InitializeTestbed",
            "CommonSetup",
            # "TcamCarvingAndReload",
            'ParseConfig',
            'ClearARP',
            'ConfigureIxiaTopo1',
            'MacMove_ISSU_Primary_BintoUpg',
            'MacMove_ISSU_Secondary_BintoUpg',
            'MacMove_ISSU_Standalone_BintoUpg',
            'MacMove_TC01',
            'MacMove_TC02',
            'MacMove_TC03',
            'MacMove_Binary_Reload_Primary',
            'MacMove_Binary_Reload_Secondary',
            'MacMove_Binary_Reload_standalone',
            'MacMove_TC04',
            'MacMove_TC05',
            'MacMove_ISSD_Primary_UpgtoBin',
            'MacMove_ISSD_Secondary_UpgtoBin',
            'MacMove_ISSD_Standalone_UpgtoBin',
            'MacMove_TC06',
            'MacMove_TC07',
            'MacMove_ASCII_Reload_Primary',
            'MacMove_ASCII_Reload_Secondary',
            'MacMove_ASCII_Reload_Standalone',
            'CLEANUP',
        ],
        subsection_datafile=get_full_with_python_path("src/forwarding/vxlan/vxlan_subsection.yaml"),
    )