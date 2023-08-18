"""
vxlanv4_evpn_sanity_job.py

"""
# Author information
__author__ = 'Nexus DevTest Group'
__copyright__ = 'Copyright (c) 2021, Cisco Systems Inc.'
__contact__ = ['nxos-auto-dev@cisco.com']
__credits__ = ['pkanduri', ]
__version__ = 1.0


import os

from genie.harness.main import gRun

from lib.utils.find_path import get_full_with_python_path

# compute script path before main so that it could be called from job directory
SCRIPT_PATH = os.path.dirname(os.path.realpath(__file__))


def main():
    gRun(
        trigger_datafile=os.path.join(SCRIPT_PATH, "vxlanv4_evpn_gre_grun_data.yaml"),
        trigger_uids=[
            'InitializeTestbed',
            'CommonSetup',
            "ConfigureIxia",
            'VpcAccessFlap',
            'VpcAccessShut',
            'VpcAccessNoShut',
            'ClearIpRouteVrfAll',
            'VpcPeerlinkFlap',
            'ClearIpv6RouteVrfAll',
            'TriggerUnconfigConfigVlanVnsegment',
            'ClearIpIgmpSnooping',
            'ClearL2vpnEvpn',
            'TriggerFlapNvePrimary',
            'UplinkShutVpcPoShutZtraffic',
            'UplinkNoShutVpcPoNoShutZtraffic',
            'TriggerClearMroute',
            'Vrflitelinkshut',
            'VrfliteNoshutlink',
            'FlapVlanRange',
            'TriggerDisableEnablePim',
            'TriggerReloadAsciiNode01',
            'TriggerChangeNveConfigToIR',
            'TriggerReloadAsciiNode04',
            'FlapSviRange',
            'TriggerUplinkIpunnumbered',
            'TriggerNoshutPortchannelUplinks',
            'TriggerUplinkPortChannel',
            'TriggerNoshutIpunnumberedUplinks',
            "TriggerDisableEnableIgmpSnoopingVxlan",
            "TriggerNveSrcLoopbackFlap",
            "TriggerClearARPAndMAC",
            "TriggerVrfLiteIntfFlapSecondaryVpc",
            "TriggerVrfLiteIntfFlap",
            'TriggerRestartBgpProcess',
            'TriggerChangeVni',
            'TriggerRevertVni',
            'UplinkShutTunnelPrimaryVPC',
            'UplinkNoShutTunnelPrimaryVPC',
            'UplinkShutTunnelSecondaryVPC',
            'UplinkNoShutTunnelSecondaryVPC',
            'TriggerRemoveAddTunnelPrimaryVPC',
            'TriggerRemoveAddTunnelSecondaryVPC',
            'CommonCleanup'
        ],
        subsection_datafile=get_full_with_python_path("src/forwarding/vxlan/vxlan_subsection.yaml"),
    )
