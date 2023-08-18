'''
sqinvni_script.py
'''

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

    #-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-
    #                 Initial run to clean up the devices              #
    #-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-  

    # gRun(
    #     trigger_datafile=os.path.join(SCRIPT_PATH, "./dot1x_grun.yaml"),
    #     trigger_uids=[
    #         "TC_001_InitializeTestbed",
    #         "CommonCleanup"
    #         ],
    #     subsection_datafile=get_full_with_python_path("src/forwarding/vxlan/vxlan_subsection.yaml"),
    # )

    #-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-
    #                 Actual run with the test-cases                   #
    #-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-  

    gRun(
        trigger_datafile=os.path.join(SCRIPT_PATH, "./qinq_qinvni_grun.yaml"),
        trigger_uids=[
            "TC_InitializeTestbed",
            # "dummy",
            # "TC_VxLAN_CommonSetup",
            "InitializeTraffic",
            # "TriggerFlapNvevPCPrimary",
            "TriggerNveFlap",
            "ClearIpRouteVrfAll",
            "ClearIpv6RouteVrfAll",
            "TriggerShutNoShutBgp",
            "l2vlanFlapl2sviFlapNve",
            "VpcPeerLinkFlapNveFlap",
            "DeleteAddNveInterfaceMctFlapNveFlap",
            "VpcPoFlapUplinkFlap",
            "TriggerRemoveAddL3VniUnderVrf",
            "TriggerDisableAndEnableNveOverlay",
            "TriggerNoshutIpunnumberedUplinks",
            "TriggerUplinkPortChannel",
            "TriggerNoshutPortchannelUplinks",
            "TriggerDeleteAddNveInterface",
            "TriggerDisableEnableFeatureFabricForwarding",
            "TriggerFLAPBGP",
            "VpcPeerlinkFlap",
            "TriggerFlapNvePrimary",
            "TriggerFlapNveSecondary",
            "FlapSviRange",
            "TriggerNveSrcLoopbackFlap",
            "TriggerRestartBgpProcess",
            "TriggerChangeVni",
            "TriggerRevertVni",
            "FlapVlanRange",
            #"TriggerFabricLinkFlap",
            #"TriggerRestartIpfib",
            "TriggerRestartNve",
            "TriggerRestartBgpProcess",
            "TriggerRestartL2rib",
            "TriggerRestartUrib",
            "TriggerRestartProcessL2fm",
            "TriggerRestartProcessUfdm",
            "TriggerRestartProcessEltm",
            # "TriggerAddNgmpvn",
            # "TriggerRemoveNgmpvn",
            "ClearBgpMvpn",
            "TriggerConfigureReplace",
            "TriggerRemoveAddPip",
            "TriggerUnconfigConfigVlanVnsegment",
            "ClearIpIgmpSnooping",
            "ClearL2vpnEvpn",
            "TriggerRestartProcessCfs",
            "TriggerRestartProcessPim",
            "TriggerClearARPAndMAC",
            "VpcAccessFlap",
            "VpcAccessShut",
            "VpcAccessNoShut",
            "TriggerFlapVrf",
            "TriggerClearBgpAll",
            "TriggerVxlanVlanSuspendActivate",
            "TriggerReloadVpcnode",
            "TriggerReloadAscii",
            "TriggerReloadTor",
            "TriggerVpcReloadPri",
            "TriggerVpcReloadSec",
            "TriggerModifyL3Vlan",
            "TriggerRevertL3Vlan",
            #"TriggerDisableEnableIgmpSnoopingVxlan",
            "TriggerDisableEnableMldSnoopingVxlan",
            "TriggerDisableEnablePim",

            
            # -------------------------------------------
            # # Initial Configurations
            # # -------------------------------------------
            #  "TC_001_InitializeTestbed",
            #  "TC_003_CommonSetup",                         # Performing the base configurations

            # # Common Cleanup
            # #  "CommonCleanup",
        ],
        subsection_datafile=get_full_with_python_path("src/forwarding/vxlan/vxlan_subsection.yaml"),
    )