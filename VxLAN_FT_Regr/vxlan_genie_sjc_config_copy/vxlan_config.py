"""
vxlan_config.py

"""
# Author information
__author__ = 'Nexus DevTest Group'
__copyright__ = 'Copyright (c) 2020, Cisco Systems Inc.'
__contact__ = ['nxos-auto-dev@cisco.com']
__credits__ = ['dhnagabh', 'omppatel']
__version__ = 1.0

import logging
import re
import time
import os
import stat

import chevron
import genie.testbed
import paramiko
import yaml
import json
from genie.conf import Genie
from genie.conf.base import Device
from genie.libs.parser.nxos.show_platform import ShowCores, ShowModule
from genie.libs.parser.nxos.show_platform import ShowVersion
from genie.libs.sdk.apis.execute import execute_copy_run_to_start
from genie.libs.sdk.apis.iosxe.health.health import health_core
from pyats import aetest
from pyats.async_ import pcall
from pyats.datastructures.logic import Not
from pyats.utils.secret_strings import to_plaintext
from pyats.easypy import runtime
from scp import SCPClient
from lib.verify.verify_core import cores_check
from lib import nxtest
from lib.config.bgp.bgp_builder import BuildBgpConfig
from lib.config.feature.feature_disabler import disable_features
from lib.config.feature.feature_enabler import enable_features
from lib.config.igmp.igmp_builder import BuildIgmpConfig
from lib.config.interface.generate_interface_logical_map import generate_interface_logical_map
from lib.config.interface.interface_builder import BuildInterfaceConfig
from lib.config.mld.mld_builder import BuildMldConfig
from lib.config.ospf.ospf_builder import BuildOspfConfig
from lib.config.ospfv3.ospfv3_builder import BuildOspfv3Config
from lib.config.pim.pim_builder import BuildPimConfig
from lib.config.pim6.pim6_builder import BuildPim6Config
from lib.config.prefix_list.prefix_list_builder import BuildPrefixListConfig
from lib.config.routepolicy.route_policy_builder import BuildRoutePolicyConfig
from lib.config.keychain.keychain_builder import BuildKeyChainConfig
from lib.config.static_route.static_route_builder import BuildStaticRouteConfig
from lib.config.vlan.vlan_builder import BuildVlanConfig
from lib.config.tunnelencryption.tunnelencryption_builder import BuildTunnelEncryptionConfig
from lib.config.vrf.vrf_builder import BuildVrfConfig
from lib.config.vxlan.vxlan_builder import BuildVxlanConfig
from lib.utils.find_path import get_full_with_script_path
from src.forwarding.vxlan.antlr.parsers.bare_minimum_config.impl.bare_minimum_parser_helper import \
    BareMinimumRunningConfigHelper
from src.forwarding.vxlan.vxlan_verify import common_verification

# create a logger for this module
LOG = logging.getLogger()
BARE_MINIMUM_CONFIG = '^username admin|^snmp-server user admin|^boot nxos|^interface mgmt0|^vrf context ' \
                      'management|^interface breakout|^hostname'
global copy_cores
copy_cores = False


class InitializeTestbed(nxtest.CommonSetup):
    """
       Connect and initialize testbed.
    """
    uid = 'initialize_testbed'

    @aetest.subsection
    def genie_init(self, testscript, testbed, steps):
        """ Initialize the environment """

        with steps.start("Initializing the environment for Genie Configurable Objects"):
            # Make sure testbed is provided
            assert testbed, 'Testbed is not provided!'
            Genie.init(testbed=testbed)
            # Overwrite the pyATS testbed for Genie Testbed
            testscript.parameters["testbed"] = Genie.testbed
            # add testduts param to parameters
            testscript.parameters['test_duts'] = [dut for dut in testbed.devices.aliases if 'node' in dut]
            interface_logical_map = generate_interface_logical_map(testbed)
            testscript.parameters["interface_logical_map"] = interface_logical_map

    @aetest.subsection
    def connect_devices(self, testbed, testscript, steps, datafile_path, verify_file_path, user_new_cli_flag=False,
                        major_version_default=10.2, minor_version_default=2,nx_cloud_flag= False,nx_cloud_datafile=None,nx_cloud_datafile_local=None,
                        datafile_path_new_cli=None, verify_file_path_new_cli=None, cores_check_flag=False,enable_gnmi_connection=False):
        """
            Establish connection to all testbed devices and collect all script parameters
                Args:
                    testbed: Genie init testbed
                    testscript: Script parameters
                    steps:
                    datafile_path:
                    verify_file_path:
                Return:
                     None
        """

        # Connect to all testbed devices using default CLI context
        ver_dict = {}
        testbed.custom["ixia_flag"] = False
        switches_new_cli_flag = False
        testscript.parameters["new_cli_flag"] = False

        with steps.start("Connect to the testbed"):
            for dev in list(testbed.devices.keys()):
                if dev == 'ixia':
                    testbed.devices[dev].connect(via='tgn')
                    testbed.custom["ixia_flag"] = True
                else:
                    testbed.devices[dev].connect()


        with steps.start("Print show version"):
            for node in testscript.parameters['testbed'].find_devices(
                    type=Not('Trex|TREX|trex|ios|IOS|ixia|IXIA|tgn|tgen')):
                version_obj = ShowVersion(device=node)
                version_dict = version_obj.parse()
                version_info = version_dict['platform']['software'].get('system_version')
                ver_pattern = "(.*?)\((.*?)\)"
                match = re.search(ver_pattern, version_info)
                if match:
                    pattern = "([0-9]+)\.?([0-9]+)?"
                    maj_match = re.search(pattern, match.groups()[0])
                    if maj_match:
                        if not maj_match.groups()[1]:
                            major_version = float(maj_match.groups()[0])
                        else:
                            major_version = float(".".join(maj_match.groups()))
                    min_match = re.search(pattern, match.groups()[1])
                    if min_match:
                        if not min_match.groups()[1]:
                            minor_version = float(min_match.groups()[0])
                        else:
                            minor_version = float(".".join(min_match.groups()))
                    LOG.info("Major_version:%s", major_version)
                    LOG.info("Minor_version:%s", minor_version)
                    LOG.info("Major_version_default:%s", major_version_default)
                    LOG.info("Minor_version_default:%s", minor_version_default)
                    if major_version > major_version_default:
                        switches_new_cli_flag = True
                        ver_dict.update({node:switches_new_cli_flag})
                    elif major_version == major_version_default:
                        if minor_version >= minor_version_default:
                            switches_new_cli_flag = True
                            ver_dict.update({node:switches_new_cli_flag})
                        else:
                            switches_new_cli_flag = False
                            ver_dict.update({node:switches_new_cli_flag})
                    else:
                        ver_dict.update({node:switches_new_cli_flag})
                else:
                    LOG.info("Unable to Get Version Info-Proceeding with Default Mode")
                    switches_new_cli_flag = False
                    ver_dict.update({node:switches_new_cli_flag})

                if cores_check_flag:
                    global copy_cores
                    copy_cores = True
                    if cores_check(testbed, node, copy_cores):
                        LOG.error("Bootup Cores Found in node:%s", node)
                        self.failed()

        LOG.info("switches_new_cli_flag_all_switches: %s", ver_dict.items())
        LOG.info("user_new_cli_flag:%s", user_new_cli_flag)
        if user_new_cli_flag and all(flag == True for flag in ver_dict.values()) and not testbed.custom["ixia_flag"]:
            testscript.parameters["new_cli_flag"] = True
            testbed.custom["new_cli_flag"] = True
            with steps.start("Load New CLI verify yaml file with Image version {maj_version}({min_version})".format(
                    maj_version=major_version, min_version=int(minor_version))):
                # Verification parameters for Control plane verification
                verify_params = yaml.load(open(get_full_with_script_path(verify_file_path_new_cli), 'r'),
                                          Loader=yaml.FullLoader)
                testscript.parameters.update(verify_params)
            with steps.start("Load New CLI config yaml file with Image version {maj_version}({min_version})".format(
                    maj_version=major_version, min_version=int(minor_version))):
                # Load configuration data file from datafile_path arg
                config_params = yaml.load(open(get_full_with_script_path(datafile_path_new_cli), 'r'),
                                          Loader=yaml.FullLoader)
                testscript.parameters.update(config_params['parameters'])

        else:
            testscript.parameters["new_cli_flag"] = False
            testbed.custom["new_cli_flag"] = False
            with steps.start("Load verify yaml file with Image version {maj_version}({min_version})".format(
                    maj_version=major_version, min_version=int(minor_version))):
                # Verification parameters for Control plane verification
                if verify_file_path:
                    verify_params = yaml.load(open(get_full_with_script_path(verify_file_path), 'r'),
                                              Loader=yaml.FullLoader)
                    testscript.parameters.update(verify_params)
            with steps.start("Load config yaml file with Image version {maj_version}({min_version})".format(
                    maj_version=major_version, min_version=int(minor_version))):
                # Load configuration data file from datafile_path arg
                LOG.info("here is the data file path %s", get_full_with_script_path(datafile_path))
                config_params = yaml.load(open(get_full_with_script_path(datafile_path), 'r'),
                                          Loader=yaml.FullLoader)
                testscript.parameters.update(config_params['parameters'])

        if user_new_cli_flag and all(flag == True for flag in ver_dict.values()) and testbed.custom["ixia_flag"]:
            testscript.parameters["new_cli_flag"] = True
            testbed.custom["new_cli_flag"] = True

        '''Loading NX cloud data files'''
        if nx_cloud_flag:
            '''Loading ../../../etc/nexus_cloud.yml'''
            with steps.start("Load etc/nexus_cloud.yml"):
                nx_cloud_params = yaml.load(open(get_full_with_script_path(nx_cloud_datafile), 'r'),
                                            Loader=yaml.FullLoader)
                testscript.parameters.update(nx_cloud_params)
            '''Loading local data file'''
            with steps.start("Load local data file for nx cloud"):
                nx_cloud_local_params = yaml.load(open(get_full_with_script_path(nx_cloud_datafile_local), 'r'),
                                                  Loader=yaml.FullLoader)
                testscript.parameters.update(nx_cloud_local_params)


        '''This section is for gNMI connectivity,if gNMI connection required please enable in grun_data file.Please refer in gnm_oc profile'''
        if enable_gnmi_connection:
            with steps.start("Connect to the devices via gnmi"):
                clear_gnmi_cert_cmd = "feature grpc \n sleep 2 \n crypto ca trustpoint gnmi_auto_trustpoint \n delete certificate force \n sleep 2" \
                                      "\n no crypto ca trustpoint gnmi_auto_trustpoint \n sleep 5"

                gnmi_feature_lst = ['feature openconfig','feature nat','feature netconf','crypto key zeroize rsa gnmi_auto_trustpoint','crypto ca trustpoint gnmi_auto_trustpoint','sleep 2',
                                    'crypto ca import gnmi_auto_trustpoint pkcs12 grpc.pfx Ciscolab123!','crypto ca import gnmi_auto_trustpoint pkcs12 bootflash:grpc.pfx Ciscolab123!',
                                    'grpc certificate gnmi_auto_trustpoint','grpc gnmi max-concurrent-calls 16','grpc port 50051','grpc use-vrf default']
                for dev in list(testbed.devices.keys()):
                    if testbed.devices[dev].connections.get('gnmi', None):
                        '''Configuring boot-mode lxc on gNMI enabled nodes for open config verification'''
                        testbed.devices[dev].configure('boot mode lxc')
                        execute_copy_run_to_start(testbed.devices[dev])

                        '''scp grpc.key,grpc.pem & grpc.pfx into bootflash for gNMI'''
                        grpc_cert_lst = ['grpc.key', 'grpc.pem', 'grpc.pfx']
                        directory = os.getcwd()
                        device = testbed.devices[dev]
                        device.configure('feature scp-server')
                        ssh = paramiko.SSHClient()
                        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                        ssh.connect(username=device.credentials['default'].get('username'),
                                    password=to_plaintext(device.credentials['default'].get('password')),
                                    hostname=str(device.connections.get('gnmi').get('host')),timeout=600)
                        for cert in grpc_cert_lst:
                            path = directory + '/src/forwarding/vxlan/gnm_oc/' +cert
                            with SCPClient(ssh.get_transport()) as scp:
                                scp.put(path)
                        ssh.close()
                        '''Clearing grpc certificate'''
                        device.configure(clear_gnmi_cert_cmd)
                        '''Configuring grpc certificate'''
                        for gnmi_config in gnmi_feature_lst:
                            device.configure(gnmi_config)
                        time.sleep(50)
                        LOG.info("Connecting node %s via gnmi", dev)
                        '''Connecting to device via gnmi'''
                        testbed.devices[dev].connect(alias='gnmi', via='gnmi')
                        LOG.info("=====show grpc gnmi service statistics")
                        testbed.devices[dev].execute('show grpc gnmi service statistics')



class CommonSetup(nxtest.CommonSetup):
    """
       Configure, and Verify the configuration was applied correctly.
    """
    uid = 'common_setup'

    @aetest.subsection
    def enable_features(self, testbed, steps):
        """
            Enable base features
                Args:
                    testbed: Genie testbed
                    steps: pyats steps object
            Returns:
                None
        """
        with steps.start("Enabling features on the testbed"):
            enable_features(self.parameters.get("enable_features", {}), testbed)

    @aetest.subsection
    def configure_vxlan(self, steps, testbed):
        """
            Configure VxLAN EVPN configuration on devices
                Args:
                    testbed: Genie testbed
                    steps: pyats steps object
                Returns:
                    None
        """
        with steps.start("Configuring VxLAN related configuration on the testbed"):
            BuildVxlanConfig(**{
                "vxlan_config": self.parameters.get('vxlan_config', {}),
                "testbed": testbed,
            }).build_config()
        with steps.start("Configuring EVPN related configuration on the testbed"):
            BuildVxlanConfig(**{
                "evpn_config": self.parameters.get('evpn_config', {}),
                "testbed": testbed,
            }).build_config()

    @aetest.subsection
    def configure_vlan(self, steps, testbed):
        """
            Configure VLAN configuration on devices
                Args:
                    testbed: Genie testbed
                    steps: pyats steps object
                Returns:
                    None
        """
        with steps.start("Configuring VLAN related configuration on the testbed"):
            BuildVlanConfig(**{
                "vlan_config": self.parameters.get('vlan_config', {}),
                "testbed": testbed,
            }).build_config()

    @aetest.subsection
    def configure_vrf(self, steps, testbed):
        """
            Configure VRF configuration on devices
                Args:
                    testbed: Genie testbed
                    steps: pyats steps object
                Returns:
                    None
        """
        with steps.start("Configuring VRF related configuration on the testbed"):
            BuildVrfConfig(**{
                "testbed": testbed,
                "vrf_config": self.parameters.get('vrf_config', {})
            }).build_config()

    @aetest.subsection
    def configure_interface(self, steps, testbed):
        """
            Configure interface configuration on devices
                Args:
                    testbed: Genie testbed
                    steps: pyats steps object
                Returns:
                    None
        """
        with steps.start("Configuring interface related configuration on the testbed"):
            BuildInterfaceConfig(**{
                "testbed": testbed,
                "interface_config": self.parameters.get('interface_config', {})
            }).build_config()

    @aetest.subsection
    def configure_pim(self, steps, testbed):
        """
            Configure PIM configuration on devices
                Args:
                    testbed: Genie testbed
                    steps: pyats steps object
                Returns:
                    None
        """
        with steps.start("Configuring PIM related configuration on the testbed"):
            BuildPimConfig(**{
                "testbed": testbed,
                "pim_config": self.parameters.get('pim_config', {})
            }).build_config()

    @aetest.subsection
    def configure_pim6(self, steps, testbed):
        """
            Configure PIMv6 configuration on devices
                Args:
                    testbed: Genie testbed
                    steps: pyats steps object
                Returns:
                    None
        """
        with steps.start("Configuring PIMv6 related configuration on the testbed"):
            BuildPim6Config(**{
                "testbed": testbed,
                "pim6_config": self.parameters.get('pim6_config', {})
            }).build_config()

    @aetest.subsection
    def configure_igmp(self, steps, testbed):
        """
            Configure IGMP configuration on devices
                Args:
                    testbed: Genie testbed
                    steps: pyats steps object
                Returns:
                    None
        """
        with steps.start("Configuring IGMP related configuration on the testbed"):
            BuildIgmpConfig(**{
                "testbed": testbed,
                "igmp_config": self.parameters.get('igmp_config', {})
            }).build_config()

    @aetest.subsection
    def configure_mld(self, steps, testbed):
        """
            Configure MLD configuration on devices
                Args:
                    testbed: Genie testbed
                    steps: pyats steps object
                Returns:
                    None
        """
        with steps.start("Configuring MLD related configuration on the testbed"):
            BuildMldConfig(**{
                "testbed": testbed,
                "mld_config": self.parameters.get('mld_config', {})
            }).build_config()

    @aetest.subsection
    def configure_ospf(self, steps, testbed):
        """
            Configure OSPF configuration on devices
                Args:
                    testbed: Genie testbed
                    steps: pyats steps object
                Returns:
                    None
            """
        with steps.start("Configuring OSPF related configuration on the testbed"):
            BuildOspfConfig(**{
                "testbed": testbed,
                "ospf_config": self.parameters.get('ospf_config', {})
            }).build_config()

    @aetest.subsection
    def configure_ospfv3(self, steps, testbed):
        """
            Configure OSPFv3 configuration on devices
                Args:
                    testbed: Genie testbed
                    steps: pyats steps object
                Returns:
                    None
            """
        with steps.start("Configuring OSPFv3 related configuration on the testbed"):
            BuildOspfv3Config(**{
                "testbed": testbed,
                "ospfv3_config": self.parameters.get('ospfv3_config', {})
            }).build_config()

    @aetest.subsection
    def configure_bgp(self, steps, testbed):
        """
            Configure BGP configuration on devices
                Args:
                    testbed: Genie testbed
                    steps: pyats steps object
                Returns:
                    None
          """
        with steps.start("Configuring BGP related configuration on the testbed"):
            BuildBgpConfig(**{
                "testbed": testbed,
                "bgp_config": self.parameters.get('bgp_config', {})
            }).build_config()

    @aetest.subsection
    def configure_route_policy(self, steps, testbed):
        """
            Configure route-map configuration on devices
                Args:
                    testbed: Genie testbed
                    steps: pyats steps object
                Returns:
                    None
        """
        with steps.start("Configuring route-map related configuration on the testbed"):
            BuildRoutePolicyConfig(**{
                "testbed": testbed,
                "route_policy_config": self.parameters.get('route_policy_config', {})
            }).build_config()

    @aetest.subsection
    def configure_prefix_list(self, steps, testbed):
        """
            Configure prefix list on devices
                Args:
                    testbed: Genie testbed
                    steps: pyats steps object
                Returns:
                    None
        """
        with steps.start("Configuring prefix list related configuration on the testbed"):
            BuildPrefixListConfig(**{
                "testbed": testbed,
                "prefix_list_config": self.parameters.get('prefix_list_config', {})
            }).build_config()

    @aetest.subsection
    def configure_static_route(self, steps, testbed):
        """
            Configure static route configuration on devices
                Args:
                    testbed: Genie testbed
                    steps: pyats steps object
                Returns:
                    None
        """
        with steps.start("Configuring static route configuration on the testbed"):
            BuildStaticRouteConfig(**{
                "testbed": testbed,
                "static_route_config": self.parameters.get('static_route_config', {})
            }).build_config()

    @aetest.subsection
    def configure_key_chain(self, steps, testbed):
        """
            Configure keychain configuration on devices
                Args:
                    testbed: Genie testbed
                    steps: pyats steps object
                Returns:
                    None
        """
        with steps.start("Configuring keychain related configuration on the testbed"):
            BuildKeyChainConfig(**{
                "testbed": testbed,
                "keychain_config": self.parameters.get('keychain_config', {})
            }).build_config()

    @aetest.subsection
    def configure_tunnel_encryption(self, steps, testbed):
        """
            Configure tunnel encryption configuration on devices
                Args:
                    testbed: Genie testbed
                    steps: pyats steps object
                Returns:
                    None
        """
        with steps.start("Configuring VxLAN related configuration on the testbed"):
            BuildTunnelEncryptionConfig(**{
                "tunnelencryption_config": self.parameters.get('tunnelencryption_config', {}),
                "testbed": testbed,
            }).build_config()

    @aetest.subsection
    def configure_missing_genie_config(self, steps, testbed):
        """
            Configure missing configuration from models on devices
                Args:
                    testbed: Genie testbed
                    steps: pyats steps object
                Returns:
                    None
        """
        interface_logical_map = self.parameters.get('interface_logical_map')
        with steps.start("Configuring the missing config not present in models on the testbed"):
            missing_config = self.parameters.get('missing_config', {})
            for item, config in missing_config.items():
                device = testbed.devices[item]
                print("before render", config)
                config = chevron.render(config, interface_logical_map)
                print("after render", config)
                device.configure(config)

    @aetest.subsection
    def wait_some_time(self, steps):
        with steps.start("Waiting for 360 seconds post configuration bring up"):
            time.sleep(360)

    @aetest.subsection
    def copy_run_to_start(self, testbed):
        for node in self.parameters['test_duts']:
            execute_copy_run_to_start(testbed.devices[node])

    @aetest.subsection
    def cores_check_nodes(self, testbed):
        global copy_cores
        for node in self.parameters['test_duts']:
            if cores_check(testbed, testbed.devices[node], copy_cores):
                LOG.error("Core Found in node:%s", node)
                self.failed()
            else:
                LOG.info("Core not found in %s ", node)

    @aetest.subsection
    def common_verification(self, steps, testbed, interface_logical_map, **kwargs):
        common_verification(steps, testbed, interface_logical_map, **kwargs)


class ConfigureDataMdt(nxtest.CommonSetup):
    """
       Configure data mdt.
    """
    uid = 'configure_data_mdt'

    @aetest.subsection
    def configure_data_mdt(self, testbed, interface_logical_map, copy_rs_flag, data_mdt_config_wait_time):

        data_mdt_config = self.parameters.get('data_mdt_config', {})
        assert data_mdt_config, "data_mdt_config is not defined in config file"
        if data_mdt_config:
            for node, config in data_mdt_config.items():
                LOG.info(f"Configure data mdt  on device {node}")
                device = testbed.devices[node]
                config = chevron.render(config, interface_logical_map)
                device.configure(config)
                if copy_rs_flag:
                    execute_copy_run_to_start(testbed.devices[node])
        LOG.info("Waiting %s seconds after data mdt config", data_mdt_config_wait_time)
        time.sleep(data_mdt_config_wait_time)


class CommonCleanup(nxtest.CommonCleanup):
    """
       Connect, UnConfigure, and Verify the configuration was
          removed correctly.
    """
    uid = 'common_cleanup'

    @aetest.subsection
    def unconfigure_interfaces(self, testbed):
        BuildInterfaceConfig(**{
            "testbed": testbed,
            "interface_config": self.parameters['interface_config']
        }).build_unconfig()

    @aetest.subsection
    def unconfigure_features(self, testbed):
        disable_features(self.parameters['disable_features'], testbed)

    @aetest.subsection
    def unconfigure_vrf(self, testbed):
        BuildVrfConfig(**{
            "testbed": testbed,
            "vrf_config": self.parameters['vrf_config']
        }).build_unconfig()

    @aetest.subsection
    def unconfigure_route_policy(self, testbed):
        BuildRoutePolicyConfig(**{
            "testbed": testbed,
            "route_policy_config": self.parameters['route_policy_config']
        }).build_unconfig()

    @aetest.subsection
    def unconfigure_vlan(self, testbed):
        BuildVlanConfig(**{
            "vlan_config": self.parameters['vlan_config'],
            "testbed": testbed,
        }).build_unconfig()

    @aetest.subsection
    def unconfigure_missing_genie_config(self, testbed):
        missing_config = self.parameters['disable_missing_config']
        for item, config in missing_config.items():
            device = testbed.devices[item]
            print("before render", config)
            interface_logical_map = generate_interface_logical_map(testbed)
            config = chevron.render(config, interface_logical_map)
            print("after render", config)
            device.configure(config, timeout=120)

    @aetest.subsection
    def cores_check_nodes(self, testbed):
        global copy_cores
        for node in self.parameters['test_duts']:
            if cores_check(testbed, testbed.devices[node], copy_cores):
                LOG.error("Core Found in node:%s", node)
                self.failed()


class ConfigureWithTemplate(nxtest.CommonSetup):
    """
       Connect devices with template.
    """
    uid = 'configure_with_template'

    def get_bare_minimum_config(self, device: Device) -> str:
        return device.execute("show running-config | sec '{}'".format(BARE_MINIMUM_CONFIG))

    def get_bare_min_config_dict(self, device: Device) -> dict:
        minimum_config = self.get_bare_minimum_config(device)
        # from the minimum config get the hostname
        return BareMinimumRunningConfigHelper().parse_text(minimum_config)

    @aetest.subsection
    def configure_from_template(self, testbed, testscript, steps, **kwargs):
        with steps.start("Dumping entire running config from template"):
            self.reload_wait_time = kwargs.get('reload_wait_time',900)
            self.credentials = list(kwargs.get('credentials','default'))
            self.prompt_recovery = kwargs.get('prompt_recovery',True)
            if testbed.custom.get('new_cli_flag' ,False):
                templates = self.parameters.get("running_config_templates_new_l3vni", {})
            else:
                templates = self.parameters.get("running_config_templates", {})
            LOG.info("here is the templates obtained %s", templates)
            logical_map = testscript.parameters["interface_logical_map"]

            # configure feature scp-server
            def configure_box_with_updated_template(node, template):
                device = testbed.devices[node]
                device.configure('feature scp-server')
                bare_min_cfg = self.get_bare_min_config_dict(device)
                LOG.info("Data collected from the box hostname %s is %s ", node, bare_min_cfg)
                logical_map.update(bare_min_cfg)
                with open(get_full_with_script_path(template), 'r+') as f:
                    config = f.read()
                    config = chevron.render(config, logical_map)
                tmp_file_name = "{}_updated_running_config.cfg".format(node)
                tmp_file_path = "/tmp/{}".format(tmp_file_name)
                tmp_config_file = open(tmp_file_path, "w")
                tmp_config_file.write(config)
                tmp_config_file.close()

                '''
                Code added to support EOR having breakout ports in multiple modules.
                '''
                time.sleep(10)
                obj = ShowModule(device=device)
                mod_dict = obj.parse()
                if mod_dict['slot'].get('rp'):
                    if(len(mod_dict['slot'].get('rp').keys())) > 1:
                        LOG.info("%s is an EOR", device)
                        break_out_ports = ""
                        break_out_str = "interface breakout"
                        int_break_out_cli = "show running-config"
                        int_break_cmd = int_break_out_cli + ' '+"|i "+'"'+break_out_str+'"'
                        break_out_config = device.execute(int_break_cmd)
                        for break_port in break_out_config.splitlines():
                            break_out_ports = break_out_ports + break_port + '\n'
                        with open(tmp_file_path, 'r+') as fh:
                            contents = fh.readlines()
                            print("===contents[-1]===>",contents[-1])
                            if 'interface breakout module' in contents[-1]: #Handling last line to prevent IndexError
                                contents.append(break_out_ports)
                            else:
                                for index, line in enumerate(contents):
                                    if 'interface breakout module' in line and break_out_ports not in contents[index + 1]:
                                        contents.remove(line)
                                        contents.insert(index + 1, break_out_ports)
                                        break
                            fh.seek(0)
                            fh.writelines(contents)
                        fh.close()
                    else:
                        LOG.info("%s is not an EOR", device)

                # scp file from tmp location to switch
                ssh = paramiko.SSHClient()
                ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                ssh.connect(username=device.credentials['default'].get('username'),
                            password=to_plaintext(device.credentials['default'].get('password')),
                            hostname=str(device.connections.get('mgmt').get('ip')),timeout=600)
                with SCPClient(ssh.get_transport()) as scp:
                    scp.put(tmp_file_path, tmp_file_name)
                    # replace startup-config
                    scp.put(tmp_file_path, "startup-config")
                device.configure("copy {} startup-config".format(tmp_file_name))
                # restore_running_config(device=device, path="startup-config", file=tmp_file_name)
                # restore_running_config(device=device, path="", file=tmp_file_name)
                ssh.close()
                # rebooting the device
                try:
                    device.reload(
                        reload_command='reload\ny\n',
                        prompt_recovery=self.prompt_recovery,
                        reload_creds=self.credentials,
                        timeout=self.reload_wait_time)
                    device.disconnect()
                except Exception as e:
                    device.disconnect()
                    device.destroy()
                time.sleep(int(self.reload_wait_time))
                device.connect()

            pcall(
                configure_box_with_updated_template,
                node=tuple(templates.keys()),
                template=tuple(templates.values())
            )

            def set_boot_and_copy_rs(node):
                device = testbed.devices[node]
                find_boot_image = json.loads(device.execute("sho version | json"))
                boot_image = find_boot_image['nxos_file_name']
                boot_cmd = f'boot nxos {boot_image}'
                device.configure(boot_cmd)
                execute_copy_run_to_start(testbed.devices[node])

            pcall(
                set_boot_and_copy_rs,
                node=tuple(templates.keys())
            )


if __name__ == '__main__':
    # for stand-alone execution
    import argparse

    parser = argparse.ArgumentParser(description="standalone parser")
    parser.add_argument('--testbed', dest='testbed',
                        help='testbed YAML file',
                        type=genie.testbed.load,
                        default="texas_testbed.yml")
    parser.add_argument('--datafile', dest='datafile',
                        help='input data YAML file',
                        default="latest_6_node.yml")
    parser.add_argument('--verify', dest='verify',
                        help='input data YAML file',
                        default="verify_6_node.yml")
    parser.add_argument('--tgen', dest='tgen',
                        help='input data YAML file',
                        default="tgen_config_6_node.yml")
    parser.add_argument('--nxcloud', dest='nxcloud',
                        help='input data YAML file',
                        default="../../../etc/nexus_cloud.yml")
    parser.add_argument('--nxclocal', dest='nxclocal',
                        help='input data YAML file',
                        default="vxlan_nxc_env_data.yml")
    # do the parsing
    args = parser.parse_known_args()[0]
    aetest.main(testbed=args.testbed, datafile=args.datafile, verify=args.verify, tgen=args.tgen, nxcloud=args.nxcloud,nxclocal=args.nxclocal)
