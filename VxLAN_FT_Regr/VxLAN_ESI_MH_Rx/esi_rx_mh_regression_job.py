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
            "TriggerDCILinkFlap",
            "TriggerIssuNative",
            # "SwitchReloadLxc",
            "TriggerIssuLxc",
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
            "TriggerAddCloudsecConfig",
            "TriggerRemoveCloudsecConfig",
            "TriggerEsiNodeDown",
            "TriggerEsiNodeUp",
            "SwitchReloadLxc",
            # "CommonCleanup"
        ],
        subsection_datafile=get_full_with_python_path("src/forwarding/vxlan/vxlan_subsection.yaml"),
    )
