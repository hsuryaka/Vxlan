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
from lib.utils.find_path import get_full_with_job_path
SCRIPT_PATH = os.path.dirname(os.path.realpath(__file__))

def main():
    # Initiatl run to clean up the devices
    gRun(
        trigger_datafile=os.path.join(SCRIPT_PATH, "VxLAN_VNI_Scale_MSite_grun_data.yaml"),
        trigger_uids=[
            "InitializeTestbed",
            "CommonCleanup",
        ],
        subsection_datafile=get_full_with_job_path("/auto/dc3-india/havadhut/automation/py_automation_develop/nexus-test-automation/eor/regression/nxos/test/N39kRegression/test/functional/Vxlan/VxLAN_PYlib/VxLAN_Genie_Libs_Yamls/VxLAN_EVPN_master_subsection.yaml"),
    )
    # Actual run with the test-cases
    # gRun(
    #     trigger_datafile=os.path.join(SCRIPT_PATH, "VxLAN_VNI_Scale_MSite_grun_data.yaml"),
    #     trigger_uids=[
    #         "InitializeTestbed",
    #         # "TcamCarvingAndReload",
    #         # "CommonSetup",
            
    #         ## Adjust Initial configuration
    #         # "TC_001_ConfigureAdjustIPV6L2VNI",
    #         # "TC_002_ConfigureIxiaBeforeScale",
            
    #         ## Perform Triggers before converting to new L3VNI
    #         # "TC_003_TriggerClearIpRouteVrfAllBeforeScale_S1_BGWs",
    #         # "TC_004_TriggerRestartVlanMgrBeforeScale",
    #         # "TC_005_TriggerFabricLinkFlapBeforeScale_S1_BGWs",
    #         # "TC_006_TriggerDCILinkFlapBeforeScale_S1_BGWs",
    #         # "TC_007_TriggerRemoveAddL3VniUnderVrfBeforeScale_S1_BGWs",
    #         # "TC_008_TriggerDeleteRecreateVlan_S1_BGWs",
    #         # "TC_009_TriggerConfigureRollback_intNVE_S1_BGWs",
            
    #         ## Perform Triggers after converting to new L3VNI
    #         # "TC_009_TriggerConvertL3VNIOld2New",
    #         # "TC_010_TriggerClearIpRouteVrfAllAfterConverting_S1_BGWs",
    #         # "TC_011_TriggerRestartVlanMgrAfterConverting",
    #         # "TC_012_TriggerFabricLinkFlapAfterConverting_S1_BGWs",
    #         # "TC_013_TriggerDCILinkFlapAfterConverting_S1_BGWs",
    #         # "TC_014_TriggerRemoveAddNewL3VNIUnderVRF",
    #         # "TC_015_TriggerDeleteRecreateVlan_S2_BGWs",
    #         # "TC_016_TriggerConfigureRollback_intNVE_S2_BGWs",
    #         # "TC_017_TriggerDeleteRecreateVlan_S2_BGWs",
            
    #         ## Increase the Scale to 1976 L3VNI, 3952 L2VNI, 4k BGP Sessions
    #         # "TC_018_TriggerDeleteSVINoFeatureInterfaceVlanfromBGW",
    #         "TC_019_ConfigureVNIScaleIncrease",

    #         # "TriggerDeleteRecreateVlan_S1_BGWs",
    #         # "TriggerConfigureRollback_intNVE_S1_BGWs",
    #         # "TriggerReloadLC",
    #         # "TriggerReloadFabricModule",
    #         # "TriggerRestartNveIpfibReloadFM",
    #         # "TriggerReloadTor_S1_BGWs",
    #         # "CommonCleanup",
    #     ],
    #     subsection_datafile=get_full_with_job_path("/auto/dc3-india/havadhut/automation/py_automation_develop/nexus-test-automation/eor/regression/nxos/test/N39kRegression/test/functional/Vxlan/VxLAN_PYlib/VxLAN_Genie_Libs_Yamls/VxLAN_EVPN_master_subsection.yaml"),
    # )