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
        trigger_datafile=os.path.join(SCRIPT_PATH, "VxLAN_FHS_Triggers_grundata.yaml"),
        trigger_uids=[

            # -------------------------------------------
            # Initial Configurations
            # -------------------------------------------
            "InitializeTestbed",
            'ParseConfigs',
            "CommonSetup",
            "ClearARP",
            # "TcamCarvingAndReload",
            'ConfigureIxiaTopo1',
            'TRIGGER_001_008',
            # 'TRIGGER_003_043',
            # 'TRIGGER_003_010',
            # 'TRIGGER_TC004',
            # 'TRIGGER_TC005',
            # 'TRIGGER_TC006',
            # 'TRIGGER_TC007',
            # 'TRIGGER_TC011',
            # 'TRIGGER_TC012',
            # 'TRIGGER_TC013',
            # 'TRIGGER_TC014',
            # 'TRIGGER_TC015',
            # 'TRIGGER_TC016',
            # 'TRIGGER_TC017',
            # # 'TRIGGER_TC018A',
            # # 'TRIGGER_TC018B',
            # # 'TRIGGER_TC019',
            # # 'TRIGGER_TC020',
            # # 'TRIGGER_TC021',
            # # 'TRIGGER_TC022',
            # 'TRIGGER_TC023',
            # # 'TRIGGER_TC024',
            # # 'TRIGGER_TC025',
            # # 'TRIGGER_TC026',
            # # 'TRIGGER_TC027',
            # # 'TRIGGER_TC029',
            # # 'TRIGGER_TC030',
            # # 'TRIGGER_TC031',
            # # 'TRIGGER_TC032',
            # # 'TRIGGER_TC033',
            # # 'TRIGGER_TC034',
            # # 'TRIGGER_TC035',
            # # 'TRIGGER_TC036',
            # # 'TRIGGER_TC037',
            # # 'TRIGGER_TC038',
            # # 'TRIGGER_TC039',
            # 'TRIGGER_TC040', # Z traffic
            # 'TRIGGER_TC041', # Z traffic
            # 'TRIGGER_TC042_A',
            # 'TRIGGER_TC042_B',
            # 'TRIGGER_TC044',
            # 'TRIGGER_TC045',
            # 'TRIGGER_TC046',
            # 'TRIGGER_TC047',
            # 'TRIGGER_TC048',
            # 'TRIGGER_TC050',
            # 'TRIGGER_TC051',
            # 'TRIGGER_TC054_A',
            # 'TRIGGER_TC054_B',
            'CleanUp',
            # "CommonCleanup",
        ],
        subsection_datafile=get_full_with_python_path("src/forwarding/vxlan/vxlan_subsection.yaml"),
    )