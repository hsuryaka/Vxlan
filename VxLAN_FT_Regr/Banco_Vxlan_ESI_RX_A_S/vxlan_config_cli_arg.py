"""
vxlan_config_cli_arg.py

"""
# Author information
__author__ = 'Nexus DevTest Group'
__copyright__ = 'Copyright (c) 2021, Cisco Systems Inc.'
__contact__ = ['nxos-auto-dev@cisco.com']
__credits__ = ['omppatel']
__version__ = 1.0

import os
import logging
import yaml
from lib.utils.find_path import  get_full_with_job_path
from pyats.easypy import runtime
from hamcrest import assert_that, is_not
from src.forwarding.vxlan.vxlan_lib.vxlan_config_cli_arg_builder.vxlan_config_cli_arg_map import FEATURE_TYPES

LOG = logging.getLogger()

def change_vxlan_cli_arg(testbed, testscript, steps, **kwargs):
    config = {'testbed': testbed, 'parameters': testscript.parameters, 'cfg': kwargs}
    change_vxlan_cli_param = yaml.load(open('/auto/dc3-india/absr/automation/repo_develop/nexus-test-pyats/src/forwarding/vxlan/vxlan_data_files/master_cli_arg_datafile.yml'), 'r'),
                                    Loader=yaml.FullLoader)
    for vxlan_cli_datafile in change_vxlan_cli_param.get('vxlan_cli_args_datafiles'):
        vxlan_cli_param = yaml.load(open(get_full_with_job_path(vxlan_cli_datafile), 'r'),
                                    Loader=yaml.FullLoader)
        new_feature_class = vxlan_cli_param.get('InitializeTestbed').get('new_feature_class', None)
        for arg_name in testscript.parameters.get('cutom_run_time_args'):
            if new_feature_class in arg_name.split():
                testscript.parameters.update(vxlan_cli_param.get('InitializeTestbed'))
                config['cfg'].update(vxlan_cli_param.get('InitializeTestbed'))
                if FEATURE_TYPES.get(new_feature_class, None):
                    with steps.start(f"Building config for cli argument {new_feature_class}"):
                        new_config_builder = FEATURE_TYPES.get(new_feature_class).get('feature_class')
                        new_config_builder.build_new_feature(**config)
                else:
                    LOG.error("Define the new_feature_class in new feature class map")
            else:
                LOG.info("Skipping change config for cli argument.")
