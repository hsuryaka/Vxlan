"""
exi_rx_mh_regression_job.py

"""
# Author information
__author__ = 'Nexus DevTest Group'
__copyright__ = 'Copyright (c) 2021, Cisco Systems Inc.'
__contact__ = ['nxos-auto-dev@cisco.com']
__credits__ = ['djayavel', ]
__version__ = 1.0

import os
from pyats.easypy import run
from genie.harness.main import gRun
from pyats.datastructures.logic import And,Or
from lib.utils.find_path import get_full_with_python_path

# compute script path before main so that it could be called from job directory
SCRIPT_PATH = os.path.dirname(os.path.realpath(__file__))


def main():
    gRun(
        trigger_datafile=os.path.join(SCRIPT_PATH, "esi_rx_mh_grun_data.yml"),
        trigger_uids=[
            "InitializeTestbed",
            "ConfigureWithTemplate",
            "InitializeTraffic",
            "TriggerFabricLinkFlap",
            "TRIGGER_vpc_role_change_A",
            "TRIGGER_vpc_role_change_B",
            "TriggerDCILinkFlap",
            "VpcAccessFlapPri",
            "VpcAccessFlapSec",
            "TriggerRestartBgpProcess",
            "TriggerRestartNve",
            "TriggerRestartL2rib",
            "TriggerRestartUrib",
            "TriggerRestartProcessL2fm",
            "TriggerRestartProcessUfdm",
            "TriggerRestartProcessEltm",
            "VpcPeerLinkFlapNveFlap",
            "TriggerVpcReloadPri",
            "TriggerVpcReloadSec",
            "TriggerReloadTor",
            "TriggerReloadAscii",
            "TriggerEsiNodeDown",
            "TriggerEsiNodeUp",
            "TriggerClearIpRouteVrfAll",
            "TriggerClearIpv6RouteVrfAll",
            "TriggerClearBgpAll",
            "clear_mac_address",
            "Trigger_Vrf_Flap",
            "TriggerAddRemoveBgpNeighborBfd",
            "Trigger_ftr_NveOverlay",
            "VpcDomainShut",
            "VpcDomainNoShut",
            'removeadd_NveOverlay',
            'TriggerNveSrcLoopbackFlap',
            'TriggerNve_MS_SrcLoopbackFlap',
            'ModifyNveSrcLoopbackIP',
            'RevertNveSrcLoopbackIP',
            "TC_XML_Validation",
            "RemoveAddL3VniUnderNve",
            'Delete_Add_NveSrcLoopbackIP',
            ###
            'TriggerRemAddVRF', 
            'Toggle_BGP_EVPN_AF_MaximumPath',
            'DeleteRecreateVlan',
            'TC-Config_Replace',
            'TriggerGIRAddVPCPrimary',
            'TriggerGIRRemoveVPCPrimary',
            ###Run these last tcs at the end only and in the same order as it modifys the switch and ixia configs
            # 'TC_Change_L2VNI_BGW',
            # 'TC_Change_L2VNI_Leaf',
            # 'Initialize_New_Ixia_Traffic',
            # 'Host_move_1', ## ALways run Host_move1,2,3 as they form one single TC
            # 'Host_move_2',
            # 'Host_move_3',
            #"CommonCleanup"
            ###do not run below
            # "TriggerAddCloudsecConfig",
            # "TriggerRemoveCloudsecConfig",
            ##"TriggerIssuNative",
            ## "SwitchReloadLxc",
            #"TriggerIssuLxc",
            # 'TriggerIssuLxcStandalone',
        ],
        subsection_datafile=get_full_with_python_path("src/forwarding/vxlan/vxlan_subsection.yaml"),
    )
