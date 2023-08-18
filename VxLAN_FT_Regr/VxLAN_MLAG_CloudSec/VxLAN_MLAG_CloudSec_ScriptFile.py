#!/usr/bin/env python
####### VxLAN-MLAG-Cloud-Sec-VPC-BGW Automation Script###########

###############################################################################################
#VxLAN_MLAG_CloudSec_ScriptFile.py                                                            #
#                                                                                             #
#   Applicable Platforms: Nexus 9000                                                          #
#                                                                                             #
# Attached the Reference topology in GIT Path                                                 #     
# Examples:                                                                                   #
#    Example:                                                                                 #
#    pyats run job VxLAN_MLAG_CloudSec_JobFile.py                                             # 
#    --testbed VxLAN_MLAG_CloudSec_TestBedFile.yaml                                           #
#    --config-file VxLAN_MLAG_CloudSec_ConfigFile.yaml                                        #
#                                                                                             #
#                                                                                             #
# optional author information                                                                 #
#                                                                                             #
#__author__ = 'BALAJI <balajn@cisco.com>'                                                     #
# __date__= 'APR 15, 2022'                                                                    #
#                                                                                             #
#                                                                                             #
###############################################################################################

###################################################################
###                  Importing Libraries                        ###
###################################################################
import logging
import yaml
import json
from time import sleep
from yaml import Loader
import pdb
import sys
import os
log = logging.getLogger(__name__)
log.setLevel(logging.DEBUG)

#################################################################################
from pyats import aetest
from pyats.log.utils import banner

from pyats.aereport.utils.argsvalidator import ArgsValidator

ArgVal = ArgsValidator()
import re
import logging
import time

log = logging.getLogger(__name__)
log.setLevel(logging.DEBUG)


#################################################################################


class ForkedPdb(pdb.Pdb):
    """A Pdb subclass that may be used
    from a forked multiprocessing child
    """

    def interaction(self, *args, **kwargs):
        _stdin = sys.stdin
        try:
            sys.stdin = open('/dev/stdin')
            pdb.Pdb.interaction(self, *args, **kwargs)
        finally:
            sys.stdin = _stdin


# ------------------------------------------------------
# Import and initialize EVPN specific libraries
# ------------------------------------------------------
import vxlanEVPN_FNL_lib

evpnLib = vxlanEVPN_FNL_lib.configure39KVxlanEvpn()
verifyEvpn = vxlanEVPN_FNL_lib.verifyEVPNconfiguration()

# ------------------------------------------------------
# Import and initialize IXIA specific libraries
# ------------------------------------------------------
import ixiaPyats_lib

ixLib = ixiaPyats_lib.ixiaPyats_lib()

# ------------------------------------------------------
# Import and initialize INFRA specific libraries
# ------------------------------------------------------
import infra_lib

infraTrig = infra_lib.infraTrigger()
infraConfig = infra_lib.infraConfigure()
infraVerify = infra_lib.infraVerify()

# ------------------------------------------------------
# Import and initialize NIA specific libraries
# ------------------------------------------------------
import vxlanNIA_lib

niaLib = vxlanNIA_lib.verifyVxlanNIA()

###################################################################
###                  User Library Methods                       ###
###################################################################

def increment_prefix_network(pref, count):
    size = 1 << (pref.network.max_prefixlen - pref.network.prefixlen)
    pref_lst = []
    for i in range(count):
        pref_lst.append(str((pref.ip + size * i)) + "/" + str(pref.network.prefixlen))
    return pref_lst

# *****************************************************************************************************************************#

def getNvePeerList(allLeaves_data):
    nve_peer_lst = []
    for item in allLeaves_data:
        if 'VPC_VTEP_IP' in item['NVE_data'].keys():
            if item['NVE_data']['VPC_VTEP_IP'] not in nve_peer_lst:
                nve_peer_lst.append(item['NVE_data']['VPC_VTEP_IP'])
        else:
            nve_peer_lst.append(item['NVE_data']['VTEP_IP'])
    return nve_peer_lst

# *****************************************************************************************************************************#

def Peer_State(json_input, peer_ip):
    for i in json_input['TABLE_nve_peers']['ROW_nve_peers']:
        if i['peer-ip'] == peer_ip:
            return i['peer-state']
    return 0

# *****************************************************************************************************************************#

def Mac_Table(json_input, peer_ip):
    for i in json_input['TABLE_mac_address']['ROW_mac_address']:
        if i['disp_port'] == 'nve1(' + str(peer_ip) + ')':
            return i['disp_mac_addr']
    return 0

# *****************************************************************************************************************************#

def Fib_Table(json_input, loopbck):
    for i in json_input['TABLE_vrf']['ROW_vrf']['TABLE_addrf']['ROW_addrf']['TABLE_prefix']['ROW_prefix']:
        if i['ipprefix'] == loopbck:
            return i['TABLE_path']['ROW_path']['ipnexthop']
    return 0

# *****************************************************************************************************************************#

def Rtr_Mac(json_input, peer_ip):
    for i in json_input['TABLE_l2route_mac_all']['ROW_l2route_mac_all']:
        if i['next-hop1'] == peer_ip:
            return i['mac-addr']
    return 0

# *****************************************************************************************************************************#

def BGP_Route_Type(json_input, loopbck):
    for i in json_input['TABLE_vrf']['ROW_vrf']['TABLE_afi']['ROW_afi']['TABLE_safi']['ROW_safi']['TABLE_rd']['ROW_rd']['TABLE_prefix']['ROW_prefix']:
        if i['nonipprefix'] == loopbck:
            return i['TABLE_path']['ROW_path']['ipnexthop']
    return 0

# *****************************************************************************************************************************#

def evnis(evn, peerip):
  for i in evn['TABLE_nve_peers']['ROW_nve_peers']:
    if i['peer-ip'] == peerip:
        return i['vni'], i['egress-vni']

# *****************************************************************************************************************************#

def BUM_State(json_input, BUM):
  for i in json_input['TABLE_storm_control_level']['ROW_storm_control_level']:
    if i['type'] == BUM:
        return i['status'], i['level']

# *****************************************************************************************************************************#

def Total_BW(json_input, Int_Type):
  for i in json_input['TABLE_total_bandwidth']['ROW_total_bandwidth']:
    if i['type'] == Int_Type:
        return i['bandwidth']

# *****************************************************************************************************************************#

def Interface_Table(json_input, Interface):
  for i in json_input['TABLE_counters']['ROW_counters']:
    if i['interface'] == Interface:
        return i['eth_outrate_mbps'],i['eth_outrate_pcnt']

# *****************************************************************************************************************************#

def PO_Mem(json_input, Interface):
    for i in json_input['TABLE_channel']['ROW_channel']['TABLE_member']['ROW_member']:
        if i['port'] == Interface:
            return i['port-status']


def Mlag_Tunnel_Encryption(s1):
    peer_address = s1['TABLE_tem_session']['ROW_tem_session']['PeerAddr']
    rxstatus = s1['TABLE_tem_session']['ROW_tem_session']['RxStatus']
    txstatus  =  s1['TABLE_tem_session']['ROW_tem_session']['TxStatus']
    return [peer_address,rxstatus,txstatus]

def Mlag_Tunnel_Encryption_Statistics(tun_stat):
    peer_address_stat = tun_stat['TABLE_statistics']['ROW_statistics']['PeerAddr']
    rx_in_decrypted_pkts = int(tun_stat['TABLE_statistics']['ROW_statistics']['TABLE_rx_sa_an']['ROW_rx_sa_an']['in_pkts_decrypted'])
    tx_out_encrypted_pkts  = int(tun_stat['TABLE_statistics']['ROW_statistics']['TABLE_tx_sa_an']['ROW_tx_sa_an']['out_pkts_encrypted_protected'])
    return [peer_address_stat, rx_in_decrypted_pkts, tx_out_encrypted_pkts]


############Config API's#################

############Config Loopback interfaces#################

def configure_loopback(hd1, loopback_name, loopback_ip, description,  secondary=False):
    if secondary:
        cfg1 = """
               interface {1}
               no shutdown
               ip address {2} secondary 
               description {3}
               """.format(hd1, loopback_name, loopback_ip, description)
        cfg_out = hd1.configure(cfg1)
    else:
        cfg1 = """
               no interface {1}
               interface {1}
               no shutdown
               ip address {2}
               description {3}
               """.format(hd1, loopback_name, loopback_ip, description)
        cfg_out = hd1.configure(cfg1)

        
    if re.search(r"(\bERROR\b)", cfg_out):
            log.error("FAIL: Got error while configuring ... please debug")
            self.failed()
    return True    


def configure_loopback_tag(hd1, loopback_name, loopback_ip, description,  secondary=False, tag = '54321'):
    if secondary:
        cfg1 = """
               interface {1}
               no shutdown
               ip address {2} secondary tag {4}
               description {3}
               """.format(hd1, loopback_name, loopback_ip, description, tag)
        cfg_out = hd1.configure(cfg1)
    else:
        cfg1 = """
               no interface {1}
               interface {1}
               no shutdown
               ip address {2} tag {4}
               description {3}
               """.format(hd1, loopback_name, loopback_ip, description, tag)
        cfg_out = hd1.configure(cfg1)

        
    if re.search(r"(\bERROR\b)", cfg_out):
            log.error("FAIL: Got error while configuring ... please debug")
            self.failed()
    return True    


############Configure OSPF#################

def configure_ospf(hd1, ospf_intf_list, ospf_instance_name):
    for interface in ospf_intf_list: 
        cfg1 = """
               router ospf {2} 
               interface {1}
               no shutdown
               ip router ospf {2} area 0
               """.format(hd1, interface, ospf_instance_name)
        cfg_out = hd1.configure(cfg1)
        
    if re.search(r"(\bERROR\b)", cfg_out):
            log.error("FAIL: Got error while configuring ... please debug")
            self.failed()
    return True    

############Configure PIM#################

def configure_pim(hd1, pim_intf_list):
    for interface in pim_intf_list: 
        cfg1 = """
               interface {1}
               no shutdown
               ip pim sparse-mode
               """.format(hd1, interface)
        cfg_out = hd1.configure(cfg1)
        
    if re.search(r"(\bERROR\b)", cfg_out):
            log.error("FAIL: Got error while configuring ... please debug")
            self.failed()
    return True    


# *****************************************************************************************************************************#

###################################################################
###                  GLOBAL VARIABLES                           ###
###################################################################

device_list = []


###################################################################
###                  COMMON SETUP SECTION                       ###
###################################################################

# Configure and setup all devices and test equipment in this section.
# This should represent the BASE CONFIGURATION that is applicable
# for the bunch of test cases that would follow.

class COMMON_SETUP(aetest.CommonSetup):
    """ Common Setup """

    log.info(banner("Common Setup"))

    @aetest.subsection
    def connecting_to_devices(self, testscript, testbed, uut_list, configurationFile, job_file_params):
        """ common setup subsection: Connecting to devices """

        log.info(banner("Connecting to Devices"))
        global post_test_process_dict

        # =============================================================================================================================#
        # Grab the device object of the uut device with that name

        BGW_1 = testscript.parameters['BGW-1'] = testbed.devices[uut_list['BGW-1']]
        BGW_2 = testscript.parameters['BGW-2'] = testbed.devices[uut_list['BGW-2']]
        BGW_3 = BGW_1_Site_2 = testscript.parameters['BGW-1-Site-2'] = testbed.devices[uut_list['BGW-1-Site-2']]
        MLAG_L2_Access_SW_1 = testscript.parameters['MLAG-L2-Access-SW-1'] = testbed.devices[uut_list['MLAG-L2-Access-SW-1']]
        Spine_1_Site_1 = testscript.parameters['Spine-1-Site-1'] = testbed.devices[uut_list['Spine-1-Site-1']]
        LEAF_1 =  VPC_Node_1 = testscript.parameters['VPC-Node-1'] = testbed.devices[uut_list['VPC-Node-1']]
        LEAF_2 = VPC_Node_2 = testscript.parameters['VPC-Node-2'] = testbed.devices[uut_list['VPC-Node-2']]
        L2_VPC_Acc_SW_1 = testscript.parameters['L2-VPC-Acc-SW-1'] = testbed.devices[uut_list['L2-VPC-Acc-SW-1']]
        DCI_Route_Server_1 = testscript.parameters['DCI-Route-Server-1'] = testbed.devices[uut_list['DCI-Route-Server-1']]
        Spine_1_Site_2 = testscript.parameters['Spine-1-Site-2'] = testbed.devices[uut_list['Spine-1-Site-2']]
        LEAF_3 = Leaf_02_Site_2 = testscript.parameters['Leaf-02-Site-2'] = testbed.devices[uut_list['Leaf-02-Site-2']]
        IXIA = testscript.parameters['IXIA'] = testbed.devices[uut_list['ixia']]
        testscript.parameters['ixia_chassis_ip'] = str(IXIA.connections.a.ip)
        testscript.parameters['ixia_tcl_server'] = str(IXIA.connections.alt.ip)
        testscript.parameters['ixia_tcl_port'] = str(IXIA.connections.alt.port)

        # =============================================================================================================================#
        # Connect to the device

        BGW_1.connect()
        BGW_2.connect()
        BGW_1_Site_2.connect()
        MLAG_L2_Access_SW_1.connect()
        Spine_1_Site_1.connect()
        VPC_Node_1.connect()
        VPC_Node_2.connect()
        #Leaf_01_Site_1.connect()
        L2_VPC_Acc_SW_1.connect()
        DCI_Route_Server_1.connect()
        Spine_1_Site_2.connect()
        Leaf_02_Site_2.connect()
        device_list.append(BGW_1)
        device_list.append(BGW_2)
        device_list.append(BGW_1_Site_2)
        device_list.append(MLAG_L2_Access_SW_1)
        device_list.append(Spine_1_Site_1)
        device_list.append(VPC_Node_1)
        device_list.append(VPC_Node_2)
        #device_list.append(Leaf_01_Site_1)
        device_list.append(L2_VPC_Acc_SW_1)
        device_list.append(DCI_Route_Server_1)
        device_list.append(Spine_1_Site_2)
        device_list.append(Leaf_02_Site_2)

        # =============================================================================================================================#
        # Make sure that the connection went fine

        for dut in device_list:
            if not hasattr(dut, 'execute'):
                self.failed()

            if dut.execute != dut.connectionmgr.default.execute:
                self.failed()

        # =============================================================================================================================#
        # Import script_flags into testscript.parameters
        # Setting up the Post Test Check Parameters
        if 'script_flags' not in job_file_params.keys():
            script_flags = {}
            testscript.parameters['script_flags'] = {}
        else:
            script_flags = job_file_params['script_flags']
            testscript.parameters['script_flags'] = job_file_params['script_flags']

        if script_flags is not None:
            if 'skip_device_config' in script_flags.keys():
                testscript.parameters['script_flags']['skip_device_config'] = script_flags['skip_device_config']
            else:
                testscript.parameters['script_flags']['skip_device_config'] = 0

            if 'skip_tgen_config' in script_flags.keys():
                testscript.parameters['script_flags']['skip_tgen_config'] = script_flags['skip_tgen_config']
            else:
                testscript.parameters['script_flags']['skip_tgen_config'] = 0

            if 'skip_device_cleanup' in script_flags.keys():
                testscript.parameters['script_flags']['skip_device_cleanup'] = script_flags['skip_device_cleanup']
            else:
                testscript.parameters['script_flags']['skip_device_cleanup'] = 0
        else:
            testscript.parameters['script_flags']['skip_device_config'] = 0
            testscript.parameters['script_flags']['skip_tgen_config'] = 0
            testscript.parameters['script_flags']['skip_device_cleanup'] = 0


    # *****************************************************************************************************************************#

        # =============================================================================================================================#
        # Import Configuration File and create required Structures

        with open(configurationFile) as cfgFile:
            configuration = yaml.load(cfgFile, Loader=Loader)

        testscript.parameters['VPC_Node_1_dict'] = configuration['VPC_Node_1_dict']
        testscript.parameters['VPC_Node_2_dict'] = configuration['VPC_Node_2_dict']
        testscript.parameters['BGW_1_dict'] = configuration['BGW_1_dict']
        testscript.parameters['BGW_2_dict'] = configuration['BGW_2_dict']
        testscript.parameters['EVPN_dict'] = configuration['EVPN_dict']
        testscript.parameters['forwardingSysDict1'] = configuration['FWD_SYS_dict1']
        testscript.parameters['Spine_1_Site_1_dict'] = configuration['Spine_1_Site_1_dict']
        testscript.parameters['DCI_Route_Server_1_dict'] = configuration['DCI_Route_Server_1_dict']
        testscript.parameters['BGW_1_Site_2_dict'] = configuration['BGW_1_Site_2_dict']
        testscript.parameters['Spine_1_Site_2_dict'] = configuration['Spine_1_Site_2_dict']

        testscript.parameters['Leaf_02_Site_2_dict'] = configuration['Leaf_02_Site_2_dict']
        testscript.parameters['VPC_NODE_TGEN_dict'] = configuration['VPC_NODE_TGEN_data']
        testscript.parameters['LEAF_02_SITE2_TGEN_dict'] = configuration['LEAF_02_SITE_2_TGEN_data']
        testscript.parameters['leavesDict'] = {LEAF_1: configuration['VPC_Node_1_dict'],
                                               LEAF_2: configuration['VPC_Node_2_dict'],
                                               BGW_1: configuration['BGW_1_dict'],
                                               BGW_2: configuration['BGW_2_dict']}
        post_test_process_dict = {}
        post_test_process_dict = job_file_params['postTestArgs']
        post_test_process_dict['dut_list'] = [BGW_1, BGW_2, VPC_Node_1, VPC_Node_2, Leaf_02_Site_2] 
        log.info("===> Post Test Check Process Parameters")
        log.info(post_test_process_dict)
    
    @aetest.subsection
    def get_interfaces(self, testscript):
        """ common setup subsection: Getting required Connections for Test """

        log.info(banner("Retrieve the interfaces from Yaml file"))

        BGW_1 = testscript.parameters['BGW-1']
        BGW_2 = testscript.parameters['BGW-2']
        BGW_1_Site_2 = testscript.parameters['BGW-1-Site-2']
        MLAG_L2_Access_SW_1 = testscript.parameters['MLAG-L2-Access-SW-1']
        Spine_1_Site_1 = testscript.parameters['Spine-1-Site-1']
        VPC_Node_1 = testscript.parameters['VPC-Node-1']
        VPC_Node_2 = testscript.parameters['VPC-Node-2']
        L2_VPC_Acc_SW_1 = testscript.parameters['L2-VPC-Acc-SW-1']
        DCI_Route_Server_1 = testscript.parameters['DCI-Route-Server-1']
        Spine_1_Site_2 = testscript.parameters['Spine-1-Site-2']
        Leaf_02_Site_2 = testscript.parameters['Leaf-02-Site-2']
        IXIA = testscript.parameters['IXIA']

        # =============================================================================================================================#

        log.info("================================================")
        log.info("All Available Interfaces from the YAML file are:")
        for dut in device_list:
            log.info("\n\n--->" + str(dut) + " Interface list")
            for interface in dut.interfaces.keys():
                log.info(str(interface) + " --> " + str(dut.interfaces[interface].intf))

        # =============================================================================================================================#

        # =============================================================================================================================#
        # Fetching the specific interfaces

        testscript.parameters['intf_BGW_1_to_BGW_2_1'] = BGW_1.interfaces['BGW-1_to_BGW-2_1'].intf
        testscript.parameters['intf_BGW_1_to_BGW_2_2'] = BGW_1.interfaces['BGW-1_to_BGW-2_2'].intf
        testscript.parameters['intf_BGW_1_to_BGW_2_3'] = BGW_1.interfaces['BGW-1_to_BGW-2_3'].intf
        testscript.parameters['intf_BGW_1_to_IXIA_1'] = BGW_1.interfaces['BGW-1_to_IXIA_1'].intf
        testscript.parameters['intf_BGW_1_to_DCI_Route_Server_1'] = BGW_1.interfaces['BGW-1_to_DCI-Route-Server-1_1'].intf
        testscript.parameters['intf_BGW_1_to_Spine_1_Site_1_1'] = BGW_1.interfaces['BGW-1_to_Spine-1-Site-1_1'].intf
        testscript.parameters['intf_BGW_1_to_MLAG_L2_Access_SW_1_1'] = BGW_1.interfaces['BGW-1_to_MLAG-L2-Access-SW-1_1'].intf

        testscript.parameters['intf_BGW_2_to_BGW_1_1'] = BGW_2.interfaces['BGW-2_to_BGW-1_1'].intf
        testscript.parameters['intf_BGW_2_to_BGW_1_2'] = BGW_2.interfaces['BGW-2_to_BGW-1_2'].intf
        testscript.parameters['intf_BGW_2_to_BGW_1_3'] = BGW_2.interfaces['BGW-2_to_BGW-1_3'].intf
        testscript.parameters['intf_BGW_2_to_IXIA_1'] = BGW_2.interfaces['BGW-2_to_IXIA_1'].intf
        testscript.parameters['intf_BGW_2_to_DCI_Route_Server_1'] = BGW_2.interfaces['BGW-2_to_DCI-Route-Server-1_1'].intf
        testscript.parameters['intf_BGW_2_to_Spine_1_Site_1_1'] = BGW_2.interfaces['BGW-2_to_Spine-1-Site-1_1'].intf
        testscript.parameters['intf_BGW_2_to_MLAG_L2_Access_SW_1_1'] = BGW_2.interfaces['BGW-2_to_MLAG-L2-Access-SW-1_1'].intf


####IXIA interfaces:

        testscript.parameters['int_IXIA_1_to_L2_VPC_Acc_SW_1'] = IXIA.interfaces['IXIA_1_to_L2-VPC-Acc-SW-1'].intf
        testscript.parameters['int_IXIA_1_to_Leaf_02_Site_2'] = IXIA.interfaces['IXIA_1_to_Leaf-02-Site-2'].intf
        testscript.parameters['int_IXIA_1_to_MLAG_L2_Access_SW_1'] = IXIA.interfaces['IXIA_1_to_MLAG-L2-Access-SW-1'].intf
        testscript.parameters['ixia_int_list'] = str(testscript.parameters['int_IXIA_1_to_L2_VPC_Acc_SW_1']) + " " + str(testscript.parameters['int_IXIA_1_to_Leaf_02_Site_2']) + " " + str(testscript.parameters['int_IXIA_1_to_MLAG_L2_Access_SW_1'])


####IXIA interfaces:


        testscript.parameters['intf_VPC_Node_1_to_Spine_1_Site_1_1'] = VPC_Node_1.interfaces['VPC-Node-1_to_Spine-1-Site-1_1'].intf
        testscript.parameters['intf_VPC_Node_2_to_Spine_1_Site_1_1'] = VPC_Node_2.interfaces['VPC-Node-2_to_Spine-1-Site-1_1'].intf
        testscript.parameters['intf_L2_VPC_Acc_SW_1_to_VPC_Node_1_1'] = VPC_Node_1.interfaces['L2-VPC-Acc-SW-1_to_VPC-Node-1_1'].intf
        testscript.parameters['intf_L2_VPC_Acc_SW_1_to_VPC_Node_2_1'] = VPC_Node_2.interfaces['L2-VPC-Acc-SW-1_to_VPC-Node-2_1'].intf
        testscript.parameters['VPC_Node_1_to_VPC_Node_2_1'] = VPC_Node_1.interfaces['VPC-Node-1_to_VPC-Node-2_1'].intf
        testscript.parameters['VPC_Node_1_to_VPC_Node_2_2'] = VPC_Node_1.interfaces['VPC-Node-1_to_VPC-Node-2_2'].intf
        testscript.parameters['VPC_Node_2_to_VPC_Node_1_1'] = VPC_Node_2.interfaces['VPC-Node-2_to_VPC-Node-1_1'].intf
        testscript.parameters['VPC_Node_2_to_VPC_Node_1_2'] = VPC_Node_2.interfaces['VPC-Node-2_to_VPC-Node-1_2'].intf
        testscript.parameters['VPC_Node_1_to_VPC_Node_2_3'] = VPC_Node_1.interfaces['VPC-Node-1_to_VPC-Node-2_3'].intf
        testscript.parameters['VPC_Node_2_to_VPC_Node_1_3'] = VPC_Node_2.interfaces['VPC-Node-2_to_VPC-Node-1_3'].intf
        
#######Spine_1_Site_1 interfaces#######
        
        testscript.parameters['Spine_1_Site_1_to_BGW_1_1'] = Spine_1_Site_1.interfaces['Spine-1-Site-1_to_BGW-1_1'].intf
        testscript.parameters['Spine_1_Site_1_to_BGW_2_1'] = Spine_1_Site_1.interfaces['Spine-1-Site-1_to_BGW-2_1'].intf
        testscript.parameters['Spine_1_Site_1_to_VPC_Node_1_1'] = Spine_1_Site_1.interfaces['Spine-1-Site-1_to_VPC-Node-1_1'].intf
        testscript.parameters['Spine_1_Site_1_to_VPC_Node_2_1'] = Spine_1_Site_1.interfaces['Spine-1-Site-1_to_VPC-Node-2_1'].intf
#################L2 Switch interfaces for  VPC Nodes on Site1############

        testscript.parameters['L2_VPC_Acc_SW_1_to_VPC-Node_1_1'] = L2_VPC_Acc_SW_1.interfaces['L2-VPC-Acc-SW-1_to_VPC-Node-1_1'].intf
        
        testscript.parameters['L2_VPC_Acc_SW_1_to_VPC-Node_2_1'] = L2_VPC_Acc_SW_1.interfaces['L2-VPC-Acc-SW-1_to_VPC-Node-2_1'].intf
        testscript.parameters['L2_VPC_Acc_SW_1_to_IXIA_1'] = L2_VPC_Acc_SW_1.interfaces['L2-VPC-Acc-SW-1_to_IXIA_1'].intf


#################DCI Route server  interfaces############

        testscript.parameters['intf_DCI_Route_Server_1_to_BGW_1_1'] = DCI_Route_Server_1.interfaces['DCI-Route-Server-1_to_BGW-1_1'].intf
        
        testscript.parameters['intf_Route_Server_1_to_BGW_2_1'] = DCI_Route_Server_1.interfaces['DCI-Route-Server-1_to_BGW-2_1'].intf
        testscript.parameters['intf_DCI_Route_Server_1_to_BGW_1_Site_2_1'] = DCI_Route_Server_1.interfaces['DCI-Route-Server-1_to_BGW-1-Site-2_1'].intf


#################MLAG L2 NODE Interfaces############
        testscript.parameters['intf_MLAG_L2_Access_SW_1_to_BGW_1_1'] = MLAG_L2_Access_SW_1.interfaces['MLAG-L2-Access-SW-1_to_BGW-1_1'].intf
        
        testscript.parameters['intf_MLAG_L2_Access_SW_1_to_BGW_2_1'] = MLAG_L2_Access_SW_1.interfaces['MLAG-L2-Access-SW-1_to_BGW-2_1'].intf
        testscript.parameters['intf_MLAG-L2_Access_SW_1_to_IXIA_1'] = MLAG_L2_Access_SW_1.interfaces['MLAG-L2-Access-SW-1_to_IXIA_1'].intf

#################BGW-1-Site-2 Interfaces############
        testscript.parameters['intf_BGW_1_Site_2_to_DCI_Route_Server_1_1'] = BGW_1_Site_2.interfaces['BGW-1-Site-2_to_DCI-Route-Server-1_1'].intf
        
        testscript.parameters['intf_BGW_1_Site_2_1_to_Spine_1_Site_2_1'] = BGW_1_Site_2.interfaces['BGW-1-Site-2_1_to_Spine-1-Site-2_1'].intf

#################Spine-1-Site-2 Interfaces############
        testscript.parameters['intf_Spine_1_Site_2_to_BGW_1_Site_2_1'] = Spine_1_Site_2.interfaces['Spine-1-Site-2_to_BGW-1-Site-2_1'].intf
        
        testscript.parameters['intf_Spine_1_Site_2_to_Leaf_02_Site_2_1'] = Spine_1_Site_2.interfaces['Spine-1-Site-2_to_Leaf-02-Site-2_1'].intf

#################Leaf-02-Site-2 Interfaces############
        testscript.parameters['intf_Leaf_02_Site_2_to_Spine_1_Site_2_1'] = Leaf_02_Site_2.interfaces['Leaf-02-Site-2_to_Spine-1-Site-2_1'].intf
        
        testscript.parameters['int_Leaf_02_Site_2_to_IXIA_1'] = Leaf_02_Site_2.interfaces['Leaf-02-Site-2_to_IXIA_1'].intf

        log.info("\n\n================================================")
        log.info("Topology Specific Interfaces \n\n")
        for key in testscript.parameters.keys():
            if "intf_" in key:
                log.info("%-25s   ---> %-15s" % (key, testscript.parameters[key]))
        log.info("\n\n")

# *****************************************************************************************************************************#

class DEVICE_BRINGUP_enable_feature_set(aetest.Testcase):
    """Device Bring-up Test-Case"""

    @aetest.setup
    def setup(self):
        log.info("Pass testcase setup")

    @aetest.test
    def enable_feature_set(self, testscript):
        """ Device Bring-up subsection: Configuring Features and Feature-sets """

        log.info(banner("Enabling Feature Set"))

        # Do not perform configurations if skip_device_config flag is set
        if not testscript.parameters['script_flags']['skip_device_config']:

            testscript.parameters['BgwLst'] = BgwLst = [testscript.parameters['BGW-1'],
                                                        testscript.parameters['BGW-2'], testscript.parameters['BGW-1-Site-2']]
            testscript.parameters['VpcLeafLst'] = VpcLst = [testscript.parameters['VPC-Node-1'],
                                                        testscript.parameters['VPC-Node-2']]

            testscript.parameters['LeafLst'] = LeafLst = [testscript.parameters['Leaf-02-Site-2']]

            testscript.parameters['SpineLst'] = SpineLst = [testscript.parameters['Spine-1-Site-1'], testscript.parameters['Spine-1-Site-2']]
            testscript.parameters['RouteserverLst'] = RouteserverLst = [testscript.parameters['DCI-Route-Server-1']]
            testscript.parameters['BgwFeatureList'] = BgwFeatureList = ['ospf', 'bgp', 'pim', 'interface-vlan','vn-segment-vlan-based', 'lacp', 'nv overlay','fabric forwarding', 'bash-shell', 'vpc', 'tunnel-encryption']
            testscript.parameters['BgwStandaloneFeatureList'] = BgwStandaloneFeatureList = ['ospf', 'bgp', 'pim', 'interface-vlan','vn-segment-vlan-based', 'lacp', 'nv overlay','fabric forwarding', 'bash-shell', 'tunnel-encryption']

            testscript.parameters['VpcLeafFeatureList'] = VpcLeafFeatureList = ['ospf', 'bgp', 'pim', 'interface-vlan', 'vn-segment-vlan-based', 'lacp', 'nv overlay','fabric forwarding', 'bash-shell', 'vpc']
            testscript.parameters['SpineFeatureList'] = SpineFeatureList = ['ospf', 'bgp', 'pim', 'interface-vlan','vn-segment-vlan-based', 'lacp', 'nv overlay']
            testscript.parameters['RouteserverFeatureList'] = RouteserverList = [ 'bgp', 'nv overlay', 'fabric forwarding']
            testscript.parameters['LeafFeatureList'] = LeafFeatureList = ['ospf', 'bgp', 'pim', 'interface-vlan', 'vn-segment-vlan-based', 'lacp', 'nv overlay','fabric forwarding', 'bash-shell']
            configFeatureSet_status = []
            configFeatureSet_msgs = ""

            # --------------------------------
            # Configure Feature-set on LEAF-1
            featureConfigureBgw1_status = infraConfig.configureVerifyFeature(testscript.parameters['BGW-1'],
                                                                              BgwFeatureList)
            if featureConfigureBgw1_status['result']:
                log.info("Passed Configuring features on BGW-1")
            else:
                log.debug("Failed configuring features on BGW-1")
                configFeatureSet_msgs += featureConfigureBGW1_status['log']
                configFeatureSet_status.append(0)

            # --------------------------------
            # Configure Feature-set on LEAF-2
            featureConfigureBgw2_status = infraConfig.configureVerifyFeature(testscript.parameters['BGW-2'],
                                                                              BgwFeatureList)
            if featureConfigureBgw2_status['result']:
                log.info("Passed Configuring features on BGW-2")
            else:
                log.debug("Failed configuring features on BGW-2")
                configFeatureSet_msgs += featureConfigureBGW2_status['log']
                configFeatureSet_status.append(0)


            if 0 in configFeatureSet_status:
                self.failed(reason=configFeatureSet_msgs, goto=['common_cleanup'])

            featureConfigureBgw1_site_2status = infraConfig.configureVerifyFeature(testscript.parameters['BGW-1-Site-2'],
                                                                              BgwStandaloneFeatureList)
            if featureConfigureBgw2_status['result']:
                log.info("Passed Configuring features on BGW-2")
            else:
                log.debug("Failed configuring features on BGW-2")
                configFeatureSet_msgs += featureConfigureBGW2_status['log']
                configFeatureSet_status.append(0)


            if 0 in configFeatureSet_status:
                self.failed(reason=configFeatureSet_msgs, goto=['common_cleanup'])

            featureConfigureVpcNode1_status = infraConfig.configureVerifyFeature(testscript.parameters['VPC-Node-1'],
                                                                              VpcLeafFeatureList)
            if featureConfigureVpcNode1_status['result']:
                log.info("Passed Configuring features on VPC-Node-1")
            else:
                log.debug("Failed configuring features on VPC-Node-1")
                configFeatureSet_msgs += featureConfigureVPCNode1_status['log']
                configFeatureSet_status.append(0)

            # --------------------------------
            # Configure Feature-set on LEAF-2
            featureConfigureVpcNode2_status = infraConfig.configureVerifyFeature(testscript.parameters['VPC-Node-2'],
                                                                              VpcLeafFeatureList)
            if featureConfigureVpcNode2_status['result']:
                log.info("Passed Configuring features on VPC-Node-2")
            else:
                log.debug("Failed configuring features on VPC-Node-2")
                configFeatureSet_msgs += featureConfigureVPCNode2_status['log']
                configFeatureSet_status.append(0)

            featureConfigureSpine1_Site1_status = infraConfig.configureVerifyFeature(testscript.parameters['Spine-1-Site-1'],SpineFeatureList)
            if featureConfigureBgw1_status['result']:
                log.info("Passed Configuring features on Spine-1-Site-1")
            else:
                log.debug("Failed configuring features on Spine-1-Site-1")
                configFeatureSet_msgs += featureConfigureBGW1_status['log']
                configFeatureSet_status.append(0)

            featureConfigureSpine1_Site1_status = infraConfig.configureVerifyFeature(testscript.parameters['Spine-1-Site-2'],SpineFeatureList)
            if featureConfigureBgw1_status['result']:
                log.info("Passed Configuring features on Spine-1-Site-1")
            else:
                log.debug("Failed configuring features on Spine-1-Site-1")
                configFeatureSet_msgs += featureConfigureBGW1_status['log']
                configFeatureSet_status.append(0)

            featureConfigureRoute_Server_status = infraConfig.configureVerifyFeature(testscript.parameters['DCI-Route-Server-1'],RouteserverList)
            if featureConfigureBgw1_status['result']:
                log.info("Passed Configuring features on DCI-Route-Server-1")
            else:
                log.debug("Failed configuring features on DCI-Route-Server-1")
                configFeatureSet_msgs += featureConfigureBGW1_status['log']
                configFeatureSet_status.append(0)
            featureConfigureLeaf_02_Site_2_status = infraConfig.configureVerifyFeature(testscript.parameters['Leaf-02-Site-2'], LeafFeatureList)
            if featureConfigureBgw1_status['result']:
                log.info("Passed Configuring features on Leaf-02-Site-2")
            else:
                log.debug("Failed configuring features on Leaf-02-Site-2")
                configFeatureSet_msgs += featureConfigureBGW1_status['log']
                configFeatureSet_status.append(0)

            if 0 in configFeatureSet_status:
                self.failed(reason=configFeatureSet_msgs, goto=['common_cleanup'])

            else:
                self.passed(reason="Skipped Device Configuration as per request")

    @aetest.cleanup
    def cleanup(self):
        """ testcase clean up """
        log.info("Pass testcase cleanup")

############VPC NODE1 Config Starts#####################

class DEVICE_BRINGUP_configure_VPC_Node_1(aetest.Testcase):
    """Device Bring-up Test-Case"""

    @aetest.setup
    def setup(self):
        log.info("Pass testcase setup")

    @aetest.test
    def configure_VPC_Node_1(self, testscript):
        """ Device Bring-up subsection: Configuring LEAF-1 """

        log.info(banner("Device BringUP VPC-Node-1"))
        vlan_range = str(testscript.parameters['VPC_Node_1_dict']['VLAN_VNSEGMENT_data']['vlan_range'])
        hd1 = testscript.parameters['VPC-Node-1']

        cfg1 = """
               nv overlay evpn
               vlan {0}
               """.format(
               vlan_range
        )
        cfg_out = hd1.configure(cfg1)
        vn_segment = str(testscript.parameters['VPC_Node_1_dict']['VLAN_VNSEGMENT_data']['vn_segment'])
        cfg_out = hd1.configure(cfg1)
        vlan_vni_dict = {}
        for vn_segment_list in vn_segment.split(","):
            vlan, vni = vn_segment_list.split('-')
            vlan_vni_dict[vlan] = vni

        for vlan, vni in vlan_vni_dict.items():
            cfg1 = """
                   vlan {0}
                   vn-segment {1}
                  """.format(
                  vlan, vni
            )
            cfg_out = hd1.configure(cfg1)
        evpn_data = str(testscript.parameters['EVPN_dict']['evpn_data'])
        evpn_data_vni_dict = {}
        for evpn_data_list in evpn_data.split(","):
            vlan, vni = evpn_data_list.split('-')
            evpn_data_vni_dict[vlan] = vni

        for vlan, vni in evpn_data_vni_dict.items():
            cfg1 = """
                   evpn
                   vni {0} l2
                   rd auto
                   route-target import auto
                   route-target export auto
                  """.format(
                  vni
            )
            cfg_out = hd1.configure(cfg1)

    ####configure the VRF    
        vrf_name = str(testscript.parameters['VPC_Node_1_dict']['VRF_data']['vrf_name'])
        l3_vni =   str(testscript.parameters['VPC_Node_1_dict']['VRF_data']['l3_vni'])
        cfg1 = """
               fabric forwarding anycast-gateway-mac 0001.0001.0001
               nv overlay evpn 
               vrf context {0}
               vni {1}
               rd auto
               address-family ipv4 unicast
               route-target both auto
               route-target both auto evpn
               """.format(vrf_name, l3_vni)
        cfg_out = hd1.configure(cfg1)

    ####configure the VPC   
        vpc_domain = str(testscript.parameters['VPC_Node_1_dict']['VPC_data']['vpc_domain'])
        keep_alive_src_ip = str(testscript.parameters['VPC_Node_1_dict']['VPC_data']['keep_alive_src_ip'])
        keep_alive_dst_ip = str(testscript.parameters['VPC_Node_1_dict']['VPC_data']['keep_alive_dst_ip'])
        cfg1 = """
               vpc domain {0}
               peer-switch
               peer-keepalive destination {2} source {1} vrf default
               peer-gateway
               ip arp synchronize
               """.format(vpc_domain, keep_alive_src_ip, keep_alive_dst_ip)
        cfg_out = hd1.configure(cfg1)

    ####SVI Creation   
        l2_l3_vni_vlan = str(testscript.parameters['VPC_Node_1_dict']['SVI_data']['l2_l3_vni_vlan'])
        vrf_name = str(testscript.parameters['VPC_Node_1_dict']['SVI_data']['vrf_name'])
        vlan_ip_dict = {}
        for vlan_ip_list in l2_l3_vni_vlan.split(","):
            vlan, ip = vlan_ip_list.split('-')
            vlan_ip_dict[vlan] = ip
        for vlan, ip in vlan_ip_dict.items():
          if ip != 'ip forward':  
            cfg1 = """
                   interface Vlan{0}
                   no shutdown
                   mtu 9216
                   vrf member {1}
                   no ip redirects
                   ip address {2}
                   no ipv6 redirects
                   fabric forwarding mode anycast-gateway
                  """.format(
                  vlan, vrf_name, ip
            )
            cfg_out = hd1.configure(cfg1)
          else:
              cfg1 = """
                   interface Vlan{0}
                   no shutdown
                   mtu 9216
                   vrf member {1}
                   no ip redirects
                   {2}
                   no ipv6 redirects
                   fabric forwarding mode anycast-gateway
                  """.format(
                  vlan, vrf_name, ip
            )

              cfg_out = hd1.configure(cfg1)

    ########Creating Loop back interfaces
        #######ospf loopback####
        lback_underlay_ospf = str(testscript.parameters['VPC_Node_1_dict']['lback_underlay_ospf'])
        lback_overlay_bgp = str(testscript.parameters['VPC_Node_1_dict']['lback_overlay_bgp'])
        lback_vtep_primary = str(testscript.parameters['VPC_Node_1_dict']['lback_vtep_primary'])
        lback_vtep_secondary = str(testscript.parameters['VPC_Node_1_dict']['lback_vtep_secondary'])
        description_vtep = '** RID/VPC VTEPS **'
       #########ospf########
        loopback_name, loopback_ip = lback_underlay_ospf.split('-')
        description = '** RID/Underlay **'
        result = configure_loopback(hd1 = hd1, loopback_name = loopback_name, loopback_ip = loopback_ip, description = description)
        if result:
            log.info("Loopback interfaces are created successfully")
        #######BGP loopback####
        loopback_name, loopback_ip = lback_overlay_bgp.split('-')
        description = '** RID/Overlay **'
        result = configure_loopback(hd1 = hd1, loopback_name = loopback_name, loopback_ip = loopback_ip, description = description)
        if result:
            log.info("Loopback interfaces are created successfully")
        #######VTEP loopback####
        loopback_name, loopback_ip = lback_vtep_primary.split('-')
        description = '** VPC VTEP loopback **'
        result = configure_loopback(hd1 = hd1, loopback_name = loopback_name, loopback_ip = loopback_ip, description = description)
        if result:
            log.info("Loopback interfaces are created successfully")
    
        #######VTEP loopback  Secondary####
        loopback_name, loopback_ip = lback_vtep_secondary.split('-')
        description = '** VPC VTEP loopback **'
        result = configure_loopback(hd1 = hd1, loopback_name = loopback_name, loopback_ip = loopback_ip, description = description, secondary  = True)
        if result:
            log.info("Loopback interfaces are created successfully")
        #########Configuring ospf on VPC Node1 interfces###### 
        ospf_intf_list= ['lo0', 'lo1', 'lo100']
        ospf_instance_name = 'UNDERLAY-NET'
        result = configure_ospf(hd1 = hd1, ospf_intf_list= ospf_intf_list, ospf_instance_name=ospf_instance_name)
        #########Configuring PIM  on the VPC node interfaces###### 
        pim_intf_list= [testscript.parameters['intf_VPC_Node_1_to_Spine_1_Site_1_1'], 'lo0', 'lo1', 'lo100' ]
        cfg1 = """
               interface {0}
               no switchport
               no shutdown
               ip address 10.1.1.1/30
               ip ospf network point-to-point
               ip router ospf UNDERLAY-NET area 0.0.0.0
               """.format(testscript.parameters['intf_VPC_Node_1_to_Spine_1_Site_1_1'])
        cfg_out = hd1.configure(cfg1)
        result = configure_pim(hd1 = hd1, pim_intf_list = pim_intf_list)
        #########Configuring BGP###### 
        AS_num = str(testscript.parameters['VPC_Node_1_dict']['BGP_config']['AS_num'])
        router_id = str(testscript.parameters['VPC_Node_1_dict']['BGP_config']['router_id'])
        neighbor_ip_1 = str(testscript.parameters['VPC_Node_1_dict']['BGP_config']['neighbor_ip_1'])
        remote_as_1 = str(testscript.parameters['VPC_Node_1_dict']['BGP_config']['remote_as_1'])
        update_source_1 = str(testscript.parameters['VPC_Node_1_dict']['BGP_config']['update-source_1'])
        vrf = str(testscript.parameters['VPC_Node_1_dict']['BGP_config']['vrf'])

 
        cfg1 = """
               router bgp {0}
               router-id {1}
               address-family ipv4 unicast
               address-family l2vpn evpn
               advertise-pip
               neighbor {2}
               remote-as {3}
               description ** Spine-101 BGP-RR **
               update-source {4}
               address-family l2vpn evpn
               send-community
               send-community extended
               vrf {5}
               address-family ipv4 unicast
               advertise l2vpn evpn
               """.format(AS_num, router_id, neighbor_ip_1, remote_as_1, update_source_1, vrf)
        cfg_out = hd1.configure(cfg1)
        #########VPC L2 PORT config with vlan membership###### 
        l2_intf_1 = testscript.parameters['intf_L2_VPC_Acc_SW_1_to_VPC_Node_1_1']
        vlan_list = vlan_range.split(',')
        vlan_range = vlan_list[0]
        cfg1 = """
               default interface {0}
               interface {0}
               switchport
               no shutdown
               switchport mode trunk
               switchport trunk allowed vlan {1}
               channel-group 101 mode active
               interface port-channel101
               vpc 10
               """.format(l2_intf_1,vlan_range)
        cfg_out = hd1.configure(cfg1)
        #########Configuring interface nve###### 
        cfg1 = """
               ip pim rp-address 5.5.5.5 group-list 238.0.0.0/24
               interface nve1
               no shutdown
               host-reachability protocol bgp
               advertise virtual-rmac
               source-interface loopback100
               member vni 100101
               mcast-group 238.0.0.10
               member vni 100102
               mcast-group 238.0.0.10
               member vni 9002001 associate-vrf

               """.format(l2_intf_1,vlan_range)
        cfg_out = hd1.configure(cfg1)
        #########VPC PEER LINK CONFIGURATION###### 
        peerlink_intf_1 = testscript.parameters['VPC_Node_1_to_VPC_Node_2_1']
        peerlink_intf_2 = testscript.parameters['VPC_Node_1_to_VPC_Node_2_2']
        cfg1 = """
               default interface {0},{1}
               interface {0},{1}
               switchport
               no shutdown
               switchport mode trunk
               switchport trunk allowed vlan {2}
               channel-group 1001 mode active
               interface port-channel1001
               vpc peer-link
               
               """.format(peerlink_intf_1, peerlink_intf_2, vlan_range)
        cfg_out = hd1.configure(cfg1)
        #########VPC PEER KEEPALIVE LINK CONFIGURATION###### 
        peerkeeplink_intf_1 = testscript.parameters['VPC_Node_1_to_VPC_Node_2_3']
        cfg1 = """
               default interface {0}
               interface {0}
               no switchport
               no shutdown
               ip address {1}/24 
               """.format(peerkeeplink_intf_1, keep_alive_src_ip)
        cfg_out = hd1.configure(cfg1)
        @aetest.cleanup
        def cleanup(self):
             """ testcase clean up """
             log.info("Pass testcase cleanup")

############VPC NODE2 Config Starts#####################

class DEVICE_BRINGUP_configure_VPC_Node_2(aetest.Testcase):
    """Device Bring-up Test-Case"""

    @aetest.setup
    def setup(self):
        log.info("Pass testcase setup")

    @aetest.test
    def configure_VPC_Node_2(self, testscript):
        """ Device Bring-up subsection: Configuring LEAF-1 """

        log.info(banner("Device BringUP VPC-Node-2"))
        vlan_range = str(testscript.parameters['VPC_Node_2_dict']['VLAN_VNSEGMENT_data']['vlan_range'])
        hd1 = testscript.parameters['VPC-Node-2']

        cfg1 = """
               nv overlay evpn
               vlan {0}
               """.format(
               vlan_range
        )
        cfg_out = hd1.configure(cfg1)
        vn_segment = str(testscript.parameters['VPC_Node_2_dict']['VLAN_VNSEGMENT_data']['vn_segment'])
        cfg_out = hd1.configure(cfg1)
        vlan_vni_dict = {}
        for vn_segment_list in vn_segment.split(","):
            vlan, vni = vn_segment_list.split('-')
            vlan_vni_dict[vlan] = vni

        for vlan, vni in vlan_vni_dict.items():
            cfg1 = """
                   vlan {0}
                   vn-segment {1}
                  """.format(
                  vlan, vni
            )
            cfg_out = hd1.configure(cfg1)
        evpn_data = str(testscript.parameters['EVPN_dict']['evpn_data'])
        evpn_data_vni_dict = {}
        for evpn_data_list in evpn_data.split(","):
            vlan, vni = evpn_data_list.split('-')
            evpn_data_vni_dict[vlan] = vni

        for vlan, vni in evpn_data_vni_dict.items():
            cfg1 = """
                   evpn
                   vni {0} l2
                   rd auto
                   route-target import auto
                   route-target export auto
                  """.format(
                  vni
            )
            cfg_out = hd1.configure(cfg1)

    ####configure the VRF    
        vrf_name = str(testscript.parameters['VPC_Node_2_dict']['VRF_data']['vrf_name'])
        l3_vni =   str(testscript.parameters['VPC_Node_2_dict']['VRF_data']['l3_vni'])
        cfg1 = """
               fabric forwarding anycast-gateway-mac 0001.0001.0001
               nv overlay evpn 
               vrf context {0}
               vni {1}
               rd auto
               address-family ipv4 unicast
               route-target both auto
               route-target both auto evpn
               """.format(vrf_name, l3_vni)
        cfg_out = hd1.configure(cfg1)

    ####configure the VPC   
        vpc_domain = str(testscript.parameters['VPC_Node_2_dict']['VPC_data']['vpc_domain'])
        keep_alive_src_ip = str(testscript.parameters['VPC_Node_2_dict']['VPC_data']['keep_alive_src_ip'])
        keep_alive_dst_ip = str(testscript.parameters['VPC_Node_2_dict']['VPC_data']['keep_alive_dst_ip'])
        cfg1 = """
               vpc domain {0}
               peer-switch
               peer-keepalive destination {2} source {1} vrf default
               peer-gateway
               ip arp synchronize
               """.format(vpc_domain, keep_alive_src_ip, keep_alive_dst_ip)
        cfg_out = hd1.configure(cfg1)

    ####SVI Creation   
        l2_l3_vni_vlan = str(testscript.parameters['VPC_Node_2_dict']['SVI_data']['l2_l3_vni_vlan'])
        vrf_name = str(testscript.parameters['VPC_Node_2_dict']['SVI_data']['vrf_name'])
        vlan_ip_dict = {}
        for vlan_ip_list in l2_l3_vni_vlan.split(","):
            vlan, ip = vlan_ip_list.split('-')
            vlan_ip_dict[vlan] = ip
        for vlan, ip in vlan_ip_dict.items():
          if ip != 'ip forward':  
            cfg1 = """
                   interface Vlan{0}
                   no shutdown
                   mtu 9216
                   vrf member {1}
                   no ip redirects
                   ip address {2}
                   no ipv6 redirects
                   fabric forwarding mode anycast-gateway
                  """.format(
                  vlan, vrf_name, ip
            )
            cfg_out = hd1.configure(cfg1)
          else:
              cfg1 = """
                   interface Vlan{0}
                   no shutdown
                   mtu 9216
                   vrf member {1}
                   no ip redirects
                   {2}
                   no ipv6 redirects
                   fabric forwarding mode anycast-gateway
                  """.format(
                  vlan, vrf_name, ip
            )

              cfg_out = hd1.configure(cfg1)

    ########Creating Loop back interfaces
        #######ospf loopback####
        lback_underlay_ospf = str(testscript.parameters['VPC_Node_2_dict']['lback_underlay_ospf'])
        lback_overlay_bgp = str(testscript.parameters['VPC_Node_2_dict']['lback_overlay_bgp'])
        lback_vtep_primary = str(testscript.parameters['VPC_Node_2_dict']['lback_vtep_primary'])
        lback_vtep_secondary = str(testscript.parameters['VPC_Node_2_dict']['lback_vtep_secondary'])
        description_vtep = '** RID/VPC VTEPS **'
       #########ospf########
        loopback_name, loopback_ip = lback_underlay_ospf.split('-')
        description = '** RID/Underlay **'
        result = configure_loopback(hd1 = hd1, loopback_name = loopback_name, loopback_ip = loopback_ip, description = description)
        if result:
            log.info("Loopback interfaces are created successfully")
        #######BGP loopback####
        loopback_name, loopback_ip = lback_overlay_bgp.split('-')
        description = '** RID/Overlay **'
        result = configure_loopback(hd1 = hd1, loopback_name = loopback_name, loopback_ip = loopback_ip, description = description)
        if result:
            log.info("Loopback interfaces are created successfully")
        #######VTEP loopback####
        loopback_name, loopback_ip = lback_vtep_primary.split('-')
        description = '** VPC VTEP loopback **'
        result = configure_loopback(hd1 = hd1, loopback_name = loopback_name, loopback_ip = loopback_ip, description = description)
        if result:
            log.info("Loopback interfaces are created successfully")
    
        #######VTEP loopback  Secondary####
        loopback_name, loopback_ip = lback_vtep_secondary.split('-')
        description = '** VPC VTEP loopback **'
        result = configure_loopback(hd1 = hd1, loopback_name = loopback_name, loopback_ip = loopback_ip, description = description, secondary  = True)
        if result:
            log.info("Loopback interfaces are created successfully")
        #########Configuring ospf on VPC Node1 interfces###### 
        ospf_intf_list= ['lo0', 'lo1', 'lo100' ]
        ospf_instance_name = 'UNDERLAY-NET'
        result = configure_ospf(hd1 = hd1, ospf_intf_list= ospf_intf_list, ospf_instance_name=ospf_instance_name)
        #########Configuring PIM  on the VPC node interfaces###### 
        pim_intf_list= [testscript.parameters['intf_VPC_Node_2_to_Spine_1_Site_1_1'],'lo0', 'lo1', 'lo100' ]
        cfg1 = """
               interface {0}
               no switchport
               no shutdown
               ip address 10.1.2.1/30
               ip ospf network point-to-point
               ip router ospf UNDERLAY-NET area 0.0.0.0
               """.format(testscript.parameters['intf_VPC_Node_2_to_Spine_1_Site_1_1'])
        cfg_out = hd1.configure(cfg1)
        result = configure_pim(hd1 = hd1, pim_intf_list = pim_intf_list)
        #########Configuring BGP###### 
        AS_num = str(testscript.parameters['VPC_Node_2_dict']['BGP_config']['AS_num'])
        router_id = str(testscript.parameters['VPC_Node_2_dict']['BGP_config']['router_id'])
        neighbor_ip_1 = str(testscript.parameters['VPC_Node_2_dict']['BGP_config']['neighbor_ip_1'])
        remote_as_1 = str(testscript.parameters['VPC_Node_2_dict']['BGP_config']['remote_as_1'])
        update_source_1 = str(testscript.parameters['VPC_Node_2_dict']['BGP_config']['update-source_1'])
        vrf = str(testscript.parameters['VPC_Node_2_dict']['BGP_config']['vrf'])

 
        cfg1 = """
               router bgp {0}
               router-id {1}
               address-family ipv4 unicast
               address-family l2vpn evpn
               advertise-pip
               neighbor {2}
               remote-as {3}
               description ** Spine-101 BGP-RR **
               update-source {4}
               address-family l2vpn evpn
               send-community
               send-community extended
               vrf {5}
               address-family ipv4 unicast
               advertise l2vpn evpn
               """.format(AS_num, router_id, neighbor_ip_1, remote_as_1, update_source_1, vrf)
        cfg_out = hd1.configure(cfg1)
        #########VPC L2 PORT config with vlan membership###### 
        l2_intf_1 = testscript.parameters['intf_L2_VPC_Acc_SW_1_to_VPC_Node_2_1']
        vlan_list = vlan_range.split(',')
        vlan_range = vlan_list[0]
        cfg1 = """
               default interface {0}
               interface {0}
               switchport
               no shutdown
               switchport mode trunk
               switchport trunk allowed vlan {1}
               channel-group 101 mode active
               interface port-channel101
               vpc 10
               """.format(l2_intf_1,vlan_range)
        cfg_out = hd1.configure(cfg1)
        #########Configuring interface nve###### 
        cfg1 = """
               ip pim rp-address 5.5.5.5 group-list 238.0.0.0/24
               interface nve1
               no shutdown
               host-reachability protocol bgp
               advertise virtual-rmac
               source-interface loopback100
               member vni 100101
               mcast-group 238.0.0.10
               member vni 100102
               mcast-group 238.0.0.10
               member vni 9002001 associate-vrf

               """.format(l2_intf_1,vlan_range)
        cfg_out = hd1.configure(cfg1)
        #########VPC PEER LINK CONFIGURATION###### 
        peerlink_intf_1 = testscript.parameters['VPC_Node_2_to_VPC_Node_1_1']
        peerlink_intf_2 = testscript.parameters['VPC_Node_2_to_VPC_Node_1_2']
        cfg1 = """
               default interface {0},{1}
               interface {0},{1}
               switchport
               no shutdown
               switchport mode trunk
               switchport trunk allowed vlan {2}
               channel-group 1001 mode active
               interface port-channel1001
               vpc peer-link
               """.format(peerlink_intf_1, peerlink_intf_2, vlan_range)
        cfg_out = hd1.configure(cfg1)
        #########VPC PEER KEEPALIVE LINK CONFIGURATION###### 
        peerkeeplink_intf_1 = testscript.parameters['VPC_Node_2_to_VPC_Node_1_3']
        cfg1 = """
               default interface {0}
               interface {0}
               no switchport
               no shutdown
               ip address {1}/24 
               """.format(peerkeeplink_intf_1, keep_alive_src_ip)
        cfg_out = hd1.configure(cfg1)
        @aetest.cleanup
        def cleanup(self):
             """ testcase clean up """
             log.info("Pass testcase cleanup")



############VPC NODE2 Config ENDS########################

############Spine_1_Site_1 Config Starts#####################

class DEVICE_BRINGUP_configure_Spine_1_Site_1(aetest.Testcase):
    """Device Bring-up Test-Case"""

    @aetest.setup
    def setup(self):
        log.info("Pass testcase setup")

    @aetest.test
    def configure_Spine_1_Site_1(self, testscript):
        """ Device Bring-up subsection: Configuring LEAF-1 """

        log.info(banner("Device BringUP Spine-1-Site-1"))
        hd1 = testscript.parameters['Spine-1-Site-1']

############SPINE1-SITE1-Config-Starts#####################
    ########Creating Loop back interfaces
        #######ospf loopback####
        lback_underlay_ospf = str(testscript.parameters['Spine_1_Site_1_dict']['lback_underlay_ospf'])
        lback_overlay_bgp = str(testscript.parameters['Spine_1_Site_1_dict']['lback_overlay_bgp'])
        lback_pim_rp = str(testscript.parameters['Spine_1_Site_1_dict']['lback_pim_rp'])
       #########ospf########
        loopback_name, loopback_ip = lback_underlay_ospf.split('-')
        description = '** RID/Underlay **'
        result = configure_loopback(hd1 = hd1, loopback_name = loopback_name, loopback_ip = loopback_ip, description = description)
        if result:
            log.info("Loopback interfaces are created successfully")

        #######BGP loopback####
        loopback_name, loopback_ip = lback_overlay_bgp.split('-')
        description = '** RID/Overlay **'
        result = configure_loopback(hd1 = hd1, loopback_name = loopback_name, loopback_ip = loopback_ip, description = description)
        if result:
            log.info("Loopback interfaces are created successfully")
        #######PIM RP loopback####
        loopback_name, loopback_ip = lback_pim_rp.split('-')
        description = '** PIM RP Loopback**'
        result = configure_loopback(hd1 = hd1, loopback_name = loopback_name, loopback_ip = loopback_ip, description = description)
        ospf_intf_list= ['lo0', 'lo1', 'lo555' ]
        ospf_instance_name = 'UNDERLAY-NET'
        result = configure_ospf(hd1 = hd1, ospf_intf_list= ospf_intf_list, ospf_instance_name=ospf_instance_name)
        result = configure_pim(hd1 = hd1, pim_intf_list = ospf_intf_list)
        if result:
            log.info("Loopback interfaces are created successfully")
        intf1_spine_1_site_1_1 = testscript.parameters['Spine_1_Site_1_to_BGW_1_1']
        intf1_spine_1_site_1_2 = testscript.parameters['Spine_1_Site_1_to_BGW_2_1']
        intf1_spine_1_site_1_3 = testscript.parameters['Spine_1_Site_1_to_VPC_Node_1_1']
        intf1_spine_1_site_1_4 = testscript.parameters['Spine_1_Site_1_to_VPC_Node_2_1']
        cfg1 = """
               ip pim rp-address 5.5.5.5 group-list 238.0.0.0/24
               nv overlay evpn 
               interface {0}
               description ** Connected towarrds Multisite-BG1 **
               no switchport
               no shutdown
               medium p2p
               ip address 10.1.201.1/30
               ip ospf network point-to-point
               ip router ospf UNDERLAY-NET area 0.0.0.0
               ip pim sparse-mode
               no shutdown
               interface {1}
               description ** Connected towarrds Multisite-BG2 **
               no switchport
               no shutdown
               medium p2p
               ip address 10.1.202.1/30
               ip ospf network point-to-point
               ip router ospf UNDERLAY-NET area 0.0.0.0
               ip pim sparse-mode
               no shutdown
               interface {2}
               description ** Connected towarrds vpc node-1-site-1 **
               no switchport
               no shutdown
               medium p2p
               ip address 10.1.1.2/30
               ip ospf network point-to-point
               ip router ospf UNDERLAY-NET area 0.0.0.0
               ip pim sparse-mode
               no shutdown
               interface {3}
               description ** Connected towarrds vpc node-2-site-1 **
               no switchport
               no shutdown
               medium p2p
               ip address 10.1.2.2/30
               ip ospf network point-to-point
               ip router ospf UNDERLAY-NET area 0.0.0.0
               ip pim sparse-mode
               no shutdown
               """.format(intf1_spine_1_site_1_1, intf1_spine_1_site_1_2, intf1_spine_1_site_1_3, intf1_spine_1_site_1_4)
        cfg_out = hd1.configure(cfg1)

        #########Configuring BGP###### 
        AS_num = str(testscript.parameters['Spine_1_Site_1_dict']['BGP_config']['AS_num'])
        router_id = str(testscript.parameters['Spine_1_Site_1_dict']['BGP_config']['router_id'])
        neighbor_ip_1 = str(testscript.parameters['Spine_1_Site_1_dict']['BGP_config']['neighbor_ip_1'])
        remote_as_1 = str(testscript.parameters['Spine_1_Site_1_dict']['BGP_config']['remote_as_1'])
        neighbor_ip_2 = str(testscript.parameters['Spine_1_Site_1_dict']['BGP_config']['neighbor_ip_2'])
        remote_as_2 = str(testscript.parameters['Spine_1_Site_1_dict']['BGP_config']['remote_as_2'])
        neighbor_ip_3 = str(testscript.parameters['Spine_1_Site_1_dict']['BGP_config']['neighbor_ip_3'])
        remote_as_3 = str(testscript.parameters['Spine_1_Site_1_dict']['BGP_config']['remote_as_3'])
        neighbor_ip_4 = str(testscript.parameters['Spine_1_Site_1_dict']['BGP_config']['neighbor_ip_4'])
        remote_as_4 = str(testscript.parameters['Spine_1_Site_1_dict']['BGP_config']['remote_as_4'])
        vrf = str(testscript.parameters['VPC_Node_2_dict']['BGP_config']['vrf'])

 
        cfg1 = """
        router bgp {0}
        router-id {1}
        address-family ipv4 unicast
        maximum-paths 64
        address-family l2vpn evpn
        maximum-paths 64
        neighbor {3}
        remote-as {2}
        description ** towrds Leaf-01 from BGP-RR **
        update-source loopback1
        address-family l2vpn evpn
        send-community
        send-community extended
        route-reflector-client
        neighbor {4}
        remote-as {2}
        description ** towrds Leaf-02 from BGP-RR **
        update-source loopback1
        address-family l2vpn evpn
        send-community
        send-community extended
        route-reflector-client
        neighbor {5}
        remote-as {2}
        description ** towrds Multisite-BG1 from BGP-RR **
        update-source loopback1
        address-family l2vpn evpn
        send-community
        send-community extended
        route-reflector-client
        neighbor {6}
        remote-as {2}
        description ** towrds Multisite-BG2 from BGP-RR **
        update-source loopback1
        address-family l2vpn evpn
        send-community
        send-community extended
        route-reflector-client
               """.format(AS_num, router_id, remote_as_1, neighbor_ip_1, neighbor_ip_2, neighbor_ip_3, neighbor_ip_4)
        cfg_out = hd1.configure(cfg1)

        cfg1 = """
               interface loopback555
               description ** PIM RP **
               ip address 5.5.5.5/32
               ip router ospf UNDERLAY-NET area 0.0.0.0
               ip pim sparse-mode
               """
        cfg_out = hd1.configure(cfg1)

############Spine_1_Site_1 Config ENDS#####################

###############L2 SWICTH Configuration for VPC Nodes on Site-1 Starts############
class DEVICE_BRINGUP_configure_L2_VPC_Acc_SW_1(aetest.Testcase):
    """Device Bring-up Test-Case"""

    @aetest.setup
    def setup(self):
        log.info("Pass testcase setup")

    @aetest.test
    def configure_L2_VPC_Acc_SW_1(self, testscript):
        """ Device Bring-up subsection: Configuring LEAF-1 """

        log.info(banner("Device BringUP Spine-1-Site-1"))
        hd1 = testscript.parameters['L2-VPC-Acc-SW-1']

        intf1_L2_VPC_Acc_SW = testscript.parameters['L2_VPC_Acc_SW_1_to_VPC-Node_1_1']
        
        intf2_L2_VPC_Acc_SW = testscript.parameters['L2_VPC_Acc_SW_1_to_VPC-Node_2_1'] 
        intf3_L2_VPC_Acc_SW = testscript.parameters['L2_VPC_Acc_SW_1_to_IXIA_1']
        cfg1 = """
               feature lacp
               vlan 101-102
               default interface {0},{1}
               interface {0},{1}
               switchport
               no shutdown
               switchport mode trunk
               switchport trunk allowed vlan 101-102
               channel-group 101 mode active
               """.format(intf1_L2_VPC_Acc_SW, intf2_L2_VPC_Acc_SW)
        cfg_out = hd1.configure(cfg1)
        cfg1 = """
               feature lacp
               default interface {0}
               interface {0}
               switchport
               no shutdown
               switchport mode trunk
               switchport trunk allowed vlan 101-102
               """.format(intf3_L2_VPC_Acc_SW)
        cfg_out = hd1.configure(cfg1)


###############L2 SWICTH Configuration for VPC Nodes on Site-1 Ends############

###############BGW_1 Config Starts############
class DEVICE_BRINGUP_configure_BGW_1(aetest.Testcase):
    """Device Bring-up Test-Case"""

    @aetest.setup
    def setup(self):
        log.info("Pass testcase setup")

    @aetest.test
    def configure_BGW_1(self, testscript):
        """ Device Bring-up subsection: Configuring LEAF-1 """

        log.info(banner("Device Bring-UP on BGW-1 "))
        vlan_range = str(testscript.parameters['BGW_1_dict']['VLAN_VNSEGMENT_data']['vlan_range'])
        hd1 = testscript.parameters['BGW-1']

        cfg1 = """
               vlan {0}
               """.format(
               vlan_range
        )
        vn_segment = str(testscript.parameters['BGW_1_dict']['VLAN_VNSEGMENT_data']['vn_segment'])
        cfg_out = hd1.configure(cfg1)
        vlan_vni_dict = {}
        for vn_segment_list in vn_segment.split(","):
            vlan, vni = vn_segment_list.split('-')
            vlan_vni_dict[vlan] = vni

        for vlan, vni in vlan_vni_dict.items():
            cfg1 = """
                   fabric forwarding anycast-gateway-mac 0001.0001.0001
                   nv overlay evpn 
                   vlan {0}
                   vn-segment {1}
                  """.format(
                  vlan, vni
            )
            cfg_out = hd1.configure(cfg1)

        evpn_data = str(testscript.parameters['EVPN_dict']['evpn_data'])
        evpn_data_vni_dict = {}
        for evpn_data_list in evpn_data.split(","):
            vlan, vni = evpn_data_list.split('-')
            evpn_data_vni_dict[vlan] = vni

        for vlan, vni in evpn_data_vni_dict.items():
            cfg1 = """
                   evpn
                   vni {0} l2
                   rd auto
                   route-target import auto
                   route-target export auto
                  """.format(
                  vni
            )
            cfg_out = hd1.configure(cfg1)

    ####configure the VRF    
        vrf_name = str(testscript.parameters['BGW_1_dict']['VRF_data']['vrf_name'])
        l3_vni =   str(testscript.parameters['BGW_1_dict']['VRF_data']['l3_vni'])
        cfg1 = """
               evpn multisite border-gateway 100
               dci-advertise-pip
               delay-restore time 30
               vrf context {0}
               vni {1}
               rd auto
               address-family ipv4 unicast
               route-target both auto
               route-target both auto evpn
               """.format(vrf_name, l3_vni)
        cfg_out = hd1.configure(cfg1)

    ####configure the VPC   
        vpc_domain = str(testscript.parameters['BGW_1_dict']['VPC_data']['vpc_domain'])
        keep_alive_src_ip = str(testscript.parameters['BGW_1_dict']['VPC_data']['keep_alive_src_ip'])
        keep_alive_dst_ip = str(testscript.parameters['BGW_1_dict']['VPC_data']['keep_alive_dst_ip'])
        cfg1 = """
               vpc domain {0}
               peer-switch
               peer-keepalive destination {2} source {1} vrf default
               peer-gateway
               ip arp synchronize
               """.format(vpc_domain, keep_alive_src_ip, keep_alive_dst_ip)
        cfg_out = hd1.configure(cfg1)

    ####SVI Creation   
        l2_l3_vni_vlan = str(testscript.parameters['BGW_1_dict']['SVI_data']['l2_l3_vni_vlan'])
        vrf_name = str(testscript.parameters['BGW_1_dict']['SVI_data']['vrf_name'])
        vlan_ip_dict = {}
        for vlan_ip_list in l2_l3_vni_vlan.split(","):
            vlan, ip = vlan_ip_list.split('-')
            vlan_ip_dict[vlan] = ip
        for vlan, ip in vlan_ip_dict.items():
          if ip != 'ip forward':  
            cfg1 = """
                   interface Vlan{0}
                   no shutdown
                   mtu 9216
                   vrf member {1}
                   no ip redirects
                   ip address {2}
                   no ipv6 redirects
                   fabric forwarding mode anycast-gateway
                  """.format(
                  vlan, vrf_name, ip
            )
            cfg_out = hd1.configure(cfg1)
          else:
              cfg1 = """
                   interface Vlan{0}
                   no shutdown
                   mtu 9216
                   vrf member {1}
                   no ip redirects
                   {2}
                   no ipv6 redirects
                   fabric forwarding mode anycast-gateway
                  """.format(
                  vlan, vrf_name, ip
            )

              cfg_out = hd1.configure(cfg1)

    ########Creating Loop back interfaces
        #######ospf loopback####
        lback_underlay_ospf = str(testscript.parameters['BGW_1_dict']['lback_underlay_ospf'])
        lback_overlay_bgp = str(testscript.parameters['BGW_1_dict']['lback_overlay_bgp'])
        lback_vtep_primary = str(testscript.parameters['BGW_1_dict']['lback_vtep_primary'])
        lback_vtep_secondary = str(testscript.parameters['BGW_1_dict']['lback_vtep_secondary'])
        description_vtep = '** RID/VPC VTEPS **'
       #########ospf########
        loopback_name, loopback_ip = lback_underlay_ospf.split('-')
        description = '** RID/Underlay **'
        result = configure_loopback_tag(hd1 = hd1, loopback_name = loopback_name, loopback_ip = loopback_ip, description = description)
        if result:
            log.info("Loopback interfaces are created successfully")
        #######BGP loopback####
        loopback_name, loopback_ip = lback_overlay_bgp.split('-')
        description = '** RID/Overlay **'
        result = configure_loopback_tag(hd1 = hd1, loopback_name = loopback_name, loopback_ip = loopback_ip, description = description)
        if result:
            log.info("Loopback interfaces are created successfully")
        #######VTEP loopback####
        loopback_name, loopback_ip = lback_vtep_primary.split('-')
        description = '** VPC VTEP loopback **'
        result = configure_loopback_tag(hd1 = hd1, loopback_name = loopback_name, loopback_ip = loopback_ip, description = description)
        if result:
            log.info("Loopback interfaces are created successfully")
    
        #######VTEP loopback  Secondary####
        loopback_name, loopback_ip = lback_vtep_secondary.split('-')
        description = '** VPC VTEP loopback **'
        result = configure_loopback_tag(hd1 = hd1, loopback_name = loopback_name, loopback_ip = loopback_ip, description = description, secondary  = True)
        if result:
            log.info("Loopback interfaces are created successfully")
        #########Configuring ospf on VPC Node1 interfces###### 
        ospf_intf_list= ['lo0', 'lo1', 'lo100' ]
        ospf_instance_name = 'UNDERLAY-NET'
        result = configure_ospf(hd1 = hd1, ospf_intf_list= ospf_intf_list, ospf_instance_name=ospf_instance_name)
        #########Configuring PIM  on the VPC node interfaces###### 
        pim_intf_list= [testscript.parameters['intf_BGW_1_to_Spine_1_Site_1_1'], 'lo0', 'lo1', 'lo100' ]
        cfg1 = """
               interface {0}
               no switchport
               no shutdown
               ip address 10.1.201.2/30
               ip ospf network point-to-point
               ip router ospf UNDERLAY-NET area 0.0.0.0
               evpn multisite fabric-tracking        
               """.format(testscript.parameters['intf_BGW_1_to_Spine_1_Site_1_1'])
        cfg_out = hd1.configure(cfg1)
        cfg1 = """
               interface {0}
               no switchport
               no shutdown
               ip address 10.1.203.1/30 tag 54321
               ip pim sparse-mode
               evpn multisite dci-tracking
               mtu 9216
               tunnel-encryption
               """.format(testscript.parameters['intf_BGW_1_to_DCI_Route_Server_1'])
        cfg_out = hd1.configure(cfg1)
        result = configure_pim(hd1 = hd1, pim_intf_list = pim_intf_list)
        #########Configuring BGP###### 
        AS_num = str(testscript.parameters['BGW_1_dict']['BGP_config']['AS_num'])
        router_id = str(testscript.parameters['BGW_1_dict']['BGP_config']['router_id'])
        neighbor_ip_1 = str(testscript.parameters['BGW_1_dict']['BGP_config']['neighbor_ip_1'])
        remote_as_1 = str(testscript.parameters['BGW_1_dict']['BGP_config']['remote_as_1'])
        neighbor_ip_2 = str(testscript.parameters['BGW_1_dict']['BGP_config']['neighbor_ip_2'])
        remote_as_2 = str(testscript.parameters['BGW_1_dict']['BGP_config']['remote_as_2'])
        neighbor_ip_3 = str(testscript.parameters['BGW_1_dict']['BGP_config']['neighbor_ip_3'])
        remote_as_3 = str(testscript.parameters['BGW_1_dict']['BGP_config']['remote_as_3'])
        vrf = str(testscript.parameters['BGW_1_dict']['BGP_config']['vrf'])
        update_source_1 = testscript.parameters['intf_BGW_1_to_DCI_Route_Server_1'] 
 
        cfg1 = """
               route-map NH-UNCHANGED permit 10
               set ip next-hop unchanged
               route-map RMAP-REDIST-DIRECT permit 10
               match tag 54321
               router bgp {0}
               router-id {1}
               timers prefix-peer-timeout 30
               bestpath as-path multipath-relax
               reconnect-interval 1
               maxas-limit 10
               log-neighbor-changes
               address-family ipv4 unicast
               redistribute direct route-map RMAP-REDIST-DIRECT
               maximum-paths 64
               maximum-paths ibgp 64
               default-metric 0
               additional-paths send
               additional-paths receive
               address-family l2vpn evpn
               maximum-paths 64
               additional-paths send
               additional-paths receive
               neighbor {2}
               remote-as {3}
               description ** towrds DCI-Route-Serve **
               update-source {4}
               address-family ipv4 unicast
               soft-reconfiguration inbound always
               neighbor {5}
               remote-as {6}
               description ** towrds BGP-RR-Spine-01**
               update-source loopback1
               address-family l2vpn evpn
               allowas-in 3
               send-community
               send-community extended
               neighbor {7}
               remote-as {8}
               update-source loopback1
               ebgp-multihop 5
               peer-type fabric-external
               address-family l2vpn evpn
               send-community
               send-community extended
               rewrite-evpn-rt-asn
               vrf {9}
               address-family ipv4 unicast
               advertise l2vpn evpn
               maximum-paths 64
               maximum-paths ibgp 64
               """.format(AS_num, router_id, neighbor_ip_1, remote_as_1, update_source_1,neighbor_ip_2, remote_as_2, neighbor_ip_3, remote_as_3, vrf)
        cfg_out = hd1.configure(cfg1)
        #########VPC L2 PORT config with vlan membership###### 
        l2_intf_1 = testscript.parameters['intf_BGW_1_to_MLAG_L2_Access_SW_1_1']
        vlan_list = vlan_range.split(',')
        vlan_range = vlan_list[0]
        cfg1 = """
               default interface {0}
               interface {0}
               switchport
               no shutdown
               switchport mode trunk
               switchport trunk allowed vlan {1}
               channel-group 501 mode active
               interface port-channel501
               vpc 50
               """.format(l2_intf_1,vlan_range)
        cfg_out = hd1.configure(cfg1)
        #########Configuring interface nve###### 
        cfg1 = """
               ip pim rp-address 5.5.5.5 group-list 238.0.0.0/24
               interface loopback200
               no shutdown
               ip address 110.0.0.1/32 tag 54321
               ip router ospf UNDERLAY-NET area 0.0.0.0
               ip pim sparse-mode
               interface nve1
               no shutdown
               host-reachability protocol bgp
               advertise virtual-rmac
               source-interface loopback100
               multisite border-gateway interface loopback200
               member vni 100101
               multisite ingress-replication
               mcast-group 238.0.0.10
               member vni 100102
               multisite ingress-replication
               mcast-group 238.0.0.10
               member vni 9002001 associate-vrf

               """.format(l2_intf_1,vlan_range)
        cfg_out = hd1.configure(cfg1)
        #########VPC PEER LINK CONFIGURATION###### 
        peerlink_intf_1 = testscript.parameters['intf_BGW_1_to_BGW_2_1']
        peerlink_intf_2 = testscript.parameters['intf_BGW_1_to_BGW_2_2']
        cfg1 = """
               default interface {0},{1}
               interface {0},{1}
               switchport
               no shutdown
               switchport mode trunk
               switchport trunk allowed vlan {2}
               channel-group 2001 mode active
               interface port-channel2001
               vpc peer-link
               """.format(peerlink_intf_1, peerlink_intf_2, vlan_range)
        cfg_out = hd1.configure(cfg1)
        #########VPC PEER KEEPALIVE LINK CONFIGURATION###### 
        peerkeeplink_intf_1 = testscript.parameters['intf_BGW_1_to_BGW_2_3']
        cfg1 = """
               default interface {0}
               interface {0}
               no switchport
               no shutdown
               ip address {1}/24 
               """.format(peerkeeplink_intf_1, keep_alive_src_ip)
        cfg_out = hd1.configure(cfg1)
        #########Cloud Sec configuration###### 
        cfg1 = """
               key chain kc1 tunnel-encryption
               key 2000
               key-octet-string 7 070e234f4a0c1f5546405858517c7c7c713237211702105350040a0c0602595b41175b5b5356540505590852520e005c4a0706580f0309711d1c5a4d5041455355 cryptographic-algorithm AES_256_CMAC
               tunnel-encryption icv
               tunnel-encryption source-interface loopback1
               tunnel-encryption policy p1
               tunnel-encryption peer-ip 100.0.0.203
               keychain kc1 policy p1
               """
        cfg_out = hd1.configure(cfg1)
        @aetest.cleanup
        def cleanup(self):
             """ testcase clean up """
             log.info("Pass testcase cleanup")


###############BGW_1 Config Ends############
 
###############BGW_2 Config Starts############

class DEVICE_BRINGUP_configure_BGW_2(aetest.Testcase):
    """Device Bring-up Test-Case"""

    @aetest.setup
    def setup(self):
        log.info("Pass testcase setup")

    @aetest.test
    def configure_BGW_2(self, testscript):
        """ Device Bring-up subsection: Configuring BGW-2 """

        log.info(banner("Device Bring-UP on BGW-2 "))
        vlan_range = str(testscript.parameters['BGW_2_dict']['VLAN_VNSEGMENT_data']['vlan_range'])
        hd1 = testscript.parameters['BGW-2']

        cfg1 = """
               vlan {0}
               """.format(
               vlan_range
        )
        vn_segment = str(testscript.parameters['BGW_2_dict']['VLAN_VNSEGMENT_data']['vn_segment'])
        cfg_out = hd1.configure(cfg1)
        vlan_vni_dict = {}
        for vn_segment_list in vn_segment.split(","):
            vlan, vni = vn_segment_list.split('-')
            vlan_vni_dict[vlan] = vni

        for vlan, vni in vlan_vni_dict.items():
            cfg1 = """
                   fabric forwarding anycast-gateway-mac 0001.0001.0001
                   nv overlay evpn 
                   vlan {0}
                   vn-segment {1}
                  """.format(
                  vlan, vni
            )
            cfg_out = hd1.configure(cfg1)

        evpn_data = str(testscript.parameters['EVPN_dict']['evpn_data'])
        evpn_data_vni_dict = {}
        for evpn_data_list in evpn_data.split(","):
            vlan, vni = evpn_data_list.split('-')
            evpn_data_vni_dict[vlan] = vni

        for vlan, vni in evpn_data_vni_dict.items():
            cfg1 = """
                   evpn
                   vni {0} l2
                   rd auto
                   route-target import auto
                   route-target export auto
                  """.format(
                  vni
            )
            cfg_out = hd1.configure(cfg1)

    ####configure the VRF    
        vrf_name = str(testscript.parameters['BGW_2_dict']['VRF_data']['vrf_name'])
        l3_vni =   str(testscript.parameters['BGW_2_dict']['VRF_data']['l3_vni'])
        cfg1 = """
               evpn multisite border-gateway 100
               dci-advertise-pip
               delay-restore time 30
               vrf context {0}
               vni {1}
               rd auto
               address-family ipv4 unicast
               route-target both auto
               route-target both auto evpn
               """.format(vrf_name, l3_vni)
        cfg_out = hd1.configure(cfg1)

    ####configure the VPC   
        vpc_domain = str(testscript.parameters['BGW_2_dict']['VPC_data']['vpc_domain'])
        keep_alive_src_ip = str(testscript.parameters['BGW_2_dict']['VPC_data']['keep_alive_src_ip'])
        keep_alive_dst_ip = str(testscript.parameters['BGW_2_dict']['VPC_data']['keep_alive_dst_ip'])
        cfg1 = """
               vpc domain {0}
               peer-switch
               peer-keepalive destination {2} source {1} vrf default
               peer-gateway
               ip arp synchronize
               """.format(vpc_domain, keep_alive_src_ip, keep_alive_dst_ip)
        cfg_out = hd1.configure(cfg1)

    ####SVI Creation   
        l2_l3_vni_vlan = str(testscript.parameters['BGW_2_dict']['SVI_data']['l2_l3_vni_vlan'])
        vrf_name = str(testscript.parameters['BGW_2_dict']['SVI_data']['vrf_name'])
        vlan_ip_dict = {}
        for vlan_ip_list in l2_l3_vni_vlan.split(","):
            vlan, ip = vlan_ip_list.split('-')
            vlan_ip_dict[vlan] = ip
        for vlan, ip in vlan_ip_dict.items():
          if ip != 'ip forward':  
            cfg1 = """
                   interface Vlan{0}
                   no shutdown
                   mtu 9216
                   vrf member {1}
                   no ip redirects
                   ip address {2}
                   no ipv6 redirects
                   fabric forwarding mode anycast-gateway
                  """.format(
                  vlan, vrf_name, ip
            )
            cfg_out = hd1.configure(cfg1)
          else:
              cfg1 = """
                   interface Vlan{0}
                   no shutdown
                   mtu 9216
                   vrf member {1}
                   no ip redirects
                   {2}
                   no ipv6 redirects
                   fabric forwarding mode anycast-gateway
                  """.format(
                  vlan, vrf_name, ip
            )

              cfg_out = hd1.configure(cfg1)

    ########Creating Loop back interfaces
        #######ospf loopback####
        lback_underlay_ospf = str(testscript.parameters['BGW_2_dict']['lback_underlay_ospf'])
        lback_overlay_bgp = str(testscript.parameters['BGW_2_dict']['lback_overlay_bgp'])
        lback_vtep_primary = str(testscript.parameters['BGW_2_dict']['lback_vtep_primary'])
        lback_vtep_secondary = str(testscript.parameters['BGW_2_dict']['lback_vtep_secondary'])
        description_vtep = '** RID/VPC VTEPS **'
       #########ospf########
        loopback_name, loopback_ip = lback_underlay_ospf.split('-')
        description = '** RID/Underlay **'
        result = configure_loopback_tag(hd1 = hd1, loopback_name = loopback_name, loopback_ip = loopback_ip, description = description)
        if result:
            log.info("Loopback interfaces are created successfully")
        #######BGP loopback####
        loopback_name, loopback_ip = lback_overlay_bgp.split('-')
        description = '** RID/Overlay **'
        result = configure_loopback_tag(hd1 = hd1, loopback_name = loopback_name, loopback_ip = loopback_ip, description = description)
        if result:
            log.info("Loopback interfaces are created successfully")
        #######VTEP loopback####
        loopback_name, loopback_ip = lback_vtep_primary.split('-')
        description = '** VPC VTEP loopback **'
        result = configure_loopback_tag(hd1 = hd1, loopback_name = loopback_name, loopback_ip = loopback_ip, description = description)
        if result:
            log.info("Loopback interfaces are created successfully")
    
        #######VTEP loopback  Secondary####
        loopback_name, loopback_ip = lback_vtep_secondary.split('-')
        description = '** VPC VTEP loopback **'
        result = configure_loopback_tag(hd1 = hd1, loopback_name = loopback_name, loopback_ip = loopback_ip, description = description, secondary  = True)
        if result:
            log.info("Loopback interfaces are created successfully")
        #########Configuring ospf on VPC Node1 interfces###### 
        ospf_intf_list= ['lo0', 'lo1', 'lo100' ]
        ospf_instance_name = 'UNDERLAY-NET'
        result = configure_ospf(hd1 = hd1, ospf_intf_list= ospf_intf_list, ospf_instance_name=ospf_instance_name)
        #########Configuring PIM  on the VPC node interfaces###### 
        pim_intf_list= [testscript.parameters['intf_BGW_2_to_Spine_1_Site_1_1'], 'lo0', 'lo1', 'lo100' ]
        cfg1 = """
               interface {0}
               no switchport
               no shutdown
               ip address 10.1.202.2/30
               ip ospf network point-to-point
               ip router ospf UNDERLAY-NET area 0.0.0.0
               evpn multisite fabric-tracking
               """.format(testscript.parameters['intf_BGW_2_to_Spine_1_Site_1_1'])
        cfg_out = hd1.configure(cfg1)
        cfg1 = """
               interface {0}
               no switchport
               no shutdown
               ip address 10.1.204.1/30 tag 54321
               evpn multisite dci-tracking
               mtu 9216
               tunnel-encryption
               """.format(testscript.parameters['intf_BGW_2_to_DCI_Route_Server_1'])
        cfg_out = hd1.configure(cfg1)
        result = configure_pim(hd1 = hd1, pim_intf_list = pim_intf_list)
        #########Configuring BGP###### 
        AS_num = str(testscript.parameters['BGW_2_dict']['BGP_config']['AS_num'])
        router_id = str(testscript.parameters['BGW_2_dict']['BGP_config']['router_id'])
        neighbor_ip_1 = str(testscript.parameters['BGW_2_dict']['BGP_config']['neighbor_ip_1'])
        remote_as_1 = str(testscript.parameters['BGW_2_dict']['BGP_config']['remote_as_1'])
        neighbor_ip_2 = str(testscript.parameters['BGW_2_dict']['BGP_config']['neighbor_ip_2'])
        remote_as_2 = str(testscript.parameters['BGW_2_dict']['BGP_config']['remote_as_2'])
        neighbor_ip_3 = str(testscript.parameters['BGW_2_dict']['BGP_config']['neighbor_ip_3'])
        remote_as_3 = str(testscript.parameters['BGW_2_dict']['BGP_config']['remote_as_3'])
        vrf = str(testscript.parameters['BGW_2_dict']['BGP_config']['vrf'])
        update_source_1 = testscript.parameters['intf_BGW_2_to_DCI_Route_Server_1'] 
 
        cfg1 = """
               route-map NH-UNCHANGED permit 10
               set ip next-hop unchanged
               route-map RMAP-REDIST-DIRECT permit 10
               match tag 54321
               router bgp {0}
               router-id {1}
               timers prefix-peer-timeout 30
               bestpath as-path multipath-relax
               reconnect-interval 1
               maxas-limit 10
               log-neighbor-changes
               address-family ipv4 unicast
               redistribute direct route-map RMAP-REDIST-DIRECT
               maximum-paths 64
               maximum-paths ibgp 64
               default-metric 0
               additional-paths send
               additional-paths receive
               address-family l2vpn evpn
               maximum-paths 64
               additional-paths send
               additional-paths receive
               neighbor {2}
               remote-as {3}
               description ** towrds DCI-Route-Serve **
               update-source {4}
               address-family ipv4 unicast
               soft-reconfiguration inbound always
               neighbor {5}
               remote-as {6}
               description ** towrds BGP-RR-Spine-01 **
               update-source loopback1
               address-family l2vpn evpn
               allowas-in 3
               send-community
               send-community extended
               neighbor {7}
               remote-as {8}
               update-source loopback1
               ebgp-multihop 5
               peer-type fabric-external
               address-family l2vpn evpn
               send-community
               send-community extended
               rewrite-evpn-rt-asn
               vrf {9}
               address-family ipv4 unicast
               advertise l2vpn evpn
               maximum-paths 64
               maximum-paths ibgp 64
               """.format(AS_num, router_id, neighbor_ip_1, remote_as_1, update_source_1,neighbor_ip_2, remote_as_2, neighbor_ip_3, remote_as_3, vrf)
        cfg_out = hd1.configure(cfg1)
        #########VPC L2 PORT config with vlan membership###### 
        l2_intf_1 = testscript.parameters['intf_BGW_2_to_MLAG_L2_Access_SW_1_1']
        vlan_list = vlan_range.split(',')
        vlan_range = vlan_list[0]
        cfg1 = """
               default interface {0}
               interface {0}
               switchport
               no shutdown
               switchport mode trunk
               switchport trunk allowed vlan {1}
               channel-group 501 mode active
               interface port-channel501
               vpc 50
               """.format(l2_intf_1,vlan_range)
        cfg_out = hd1.configure(cfg1)
        #########Configuring interface nve###### 
        cfg1 = """
               ip pim rp-address 5.5.5.5 group-list 238.0.0.0/24
               interface loopback200
               no shutdown
               ip address 110.0.0.1/32 tag 54321
               ip router ospf UNDERLAY-NET area 0.0.0.0
               ip pim sparse-mode
               interface nve1
               no shutdown
               host-reachability protocol bgp
               advertise virtual-rmac
               source-interface loopback100
               multisite border-gateway interface loopback200
               member vni 100101
               multisite ingress-replication
               mcast-group 238.0.0.10
               member vni 100102
               multisite ingress-replication
               mcast-group 238.0.0.10
               member vni 9002001 associate-vrf

               """.format(l2_intf_1,vlan_range)
        cfg_out = hd1.configure(cfg1)
        #########VPC PEER LINK CONFIGURATION###### 
        peerlink_intf_1 = testscript.parameters['intf_BGW_2_to_BGW_1_1']
        peerlink_intf_2 = testscript.parameters['intf_BGW_2_to_BGW_1_2']
        cfg1 = """
               default interface {0},{1}
               interface {0},{1}
               switchport
               no shutdown
               switchport mode trunk
               switchport trunk allowed vlan {2}
               channel-group 2001 mode active
               interface port-channel2001
               vpc peer-link
               """.format(peerlink_intf_1, peerlink_intf_2, vlan_range)
        cfg_out = hd1.configure(cfg1)
        #########VPC PEER KEEPALIVE LINK CONFIGURATION###### 
        peerkeeplink_intf_1 = testscript.parameters['intf_BGW_2_to_BGW_1_3']
        cfg1 = """
               default interface {0}
               interface {0}
               no switchport
               no shutdown
               ip address {1}/24 
               """.format(peerkeeplink_intf_1, keep_alive_src_ip)
        cfg_out = hd1.configure(cfg1)
        #########Cloud Sec configuration###### 
        cfg1 = """
               key chain kc1 tunnel-encryption
               key 2000
               key-octet-string 7 070e234f4a0c1f5546405858517c7c7c713237211702105350040a0c0602595b41175b5b5356540505590852520e005c4a0706580f0309711d1c5a4d5041455355 cryptographic-algorithm AES_256_CMAC
               tunnel-encryption icv
               tunnel-encryption source-interface loopback1
               tunnel-encryption policy p1
               tunnel-encryption peer-ip 100.0.0.203
               keychain kc1 policy p1
               """
        cfg_out = hd1.configure(cfg1)
        @aetest.cleanup
        def cleanup(self):
             """ testcase clean up """
             log.info("Pass testcase cleanup")


###############BGW_2 Config Ends############

###############DCI_Route_Server Config Starts############

class DEVICE_BRINGUP_configure_DCI_Route_Server_1(aetest.Testcase):
    """Device Bring-up Test-Case"""

    @aetest.setup
    def setup(self):
        log.info("Pass testcase setup")

    @aetest.test
    def configure_DCI_Route_Server_1(self, testscript):
        """ Device Bring-up subsection: Configuring LEAF-1 """

        log.info(banner("Device BringUP DCI-Route-Server-1"))
        hd1 = testscript.parameters['DCI-Route-Server-1']
        intf1_dci_route_server = testscript.parameters['intf_DCI_Route_Server_1_to_BGW_1_1']
        intf2_dci_route_server = testscript.parameters['intf_Route_Server_1_to_BGW_2_1']
        intf3_dci_route_server = testscript.parameters['intf_DCI_Route_Server_1_to_BGW_1_Site_2_1']
        cfg1 = """
               route-map NH-UNCHANGED permit 10
               set ip next-hop unchanged
               route-map RMAP-REDIST-DIRECT permit 10
               match tag 54321
               route-map cloudsec permit 10
               set path-selection all advertise
               """
        cfg_out = hd1.configure(cfg1)
        cfg1 = """
               interface {0}
               mtu 9216
               ip address 10.1.203.2/30 tag 54321
               no shutdown
               """.format(intf1_dci_route_server)
        cfg_out = hd1.configure(cfg1)
        cfg1 = """
               interface {0}
               mtu 9216
               ip address 10.1.204.2/30 tag 54321
               no shutdown
               """.format(intf2_dci_route_server)
        cfg_out = hd1.configure(cfg1)
        cfg1 = """
               interface {0}
               mtu 9216
               ip address 10.1.222.2/30 tag 54321
               no shutdown
               """.format(intf3_dci_route_server)
        cfg_out = hd1.configure(cfg1)

        #########Configuring BGP###### 
        AS_num = str(testscript.parameters['DCI_Route_Server_1_dict']['BGP_config']['AS_num'])
        router_id = str(testscript.parameters['DCI_Route_Server_1_dict']['BGP_config']['router_id'])
        neighbor_ip_1 = str(testscript.parameters['DCI_Route_Server_1_dict']['BGP_config']['neighbor_ip_1'])
        remote_as_1 = str(testscript.parameters['DCI_Route_Server_1_dict']['BGP_config']['remote_as_1'])
        neighbor_ip_2 = str(testscript.parameters['DCI_Route_Server_1_dict']['BGP_config']['neighbor_ip_2'])
        remote_as_2 = str(testscript.parameters['DCI_Route_Server_1_dict']['BGP_config']['remote_as_2'])
        neighbor_ip_3 = str(testscript.parameters['DCI_Route_Server_1_dict']['BGP_config']['neighbor_ip_3'])
        remote_as_3 = str(testscript.parameters['DCI_Route_Server_1_dict']['BGP_config']['remote_as_3'])
        neighbor_ip_4 = str(testscript.parameters['DCI_Route_Server_1_dict']['BGP_config']['neighbor_ip_4'])
        remote_as_4 = str(testscript.parameters['DCI_Route_Server_1_dict']['BGP_config']['remote_as_4'])
        neighbor_ip_5 = str(testscript.parameters['DCI_Route_Server_1_dict']['BGP_config']['neighbor_ip_5'])
        remote_as_5 = str(testscript.parameters['DCI_Route_Server_1_dict']['BGP_config']['remote_as_5'])

        neighbor_ip_6 = str(testscript.parameters['DCI_Route_Server_1_dict']['BGP_config']['neighbor_ip_6'])
        remote_as_6 = str(testscript.parameters['DCI_Route_Server_1_dict']['BGP_config']['remote_as_6'])
 
        cfg1 = """
               interface loopback1
               ip address 172.16.0.251/32 tag 54321
               nv overlay evpn
               router bgp {0}
               router-id {1}
               bestpath as-path multipath-relax
               reconnect-interval 1
               maxas-limit 10
               log-neighbor-changes
               address-family ipv4 unicast
               redistribute direct route-map RMAP-REDIST-DIRECT
               maximum-paths 64
               maximum-paths ibgp 64
               default-metric 0
               additional-paths send
               additional-paths receive
               additional-paths selection route-map cloudsec
               address-family l2vpn evpn
               maximum-paths 64
               maximum-paths ibgp 64
               retain route-target all
               additional-paths send
               additional-paths receive
               additional-paths selection route-map cloudsec
               neighbor {2}
               remote-as {3}
               log-neighbor-changes
               description  ** towrds Multisite-BG1 **
               address-family ipv4 unicast
               soft-reconfiguration inbound always
               neighbor {4}
               remote-as {5}
               log-neighbor-changes
               description ** towrds Multisite-BG2 **
               address-family ipv4 unicast
               soft-reconfiguration inbound always
               neighbor {6}
               remote-as {7}
               log-neighbor-changes
               description ** towrds Multisite-BGW3 **
               address-family ipv4 unicast
               soft-reconfiguration inbound always
               neighbor {8}
               remote-as {9}
               log-neighbor-changes
               update-source loopback1
               ebgp-multihop 5
               address-family l2vpn evpn
               send-community
               send-community extended
               route-map NH-UNCHANGED out
               rewrite-evpn-rt-asn
               neighbor {10}
               remote-as {11}
               log-neighbor-changes
               update-source loopback1
               ebgp-multihop 5
               address-family l2vpn evpn
               send-community
               send-community extended
               route-map NH-UNCHANGED out
               rewrite-evpn-rt-asn
               neighbor {12}
               remote-as {13}
               log-neighbor-changes
               update-source loopback1
               ebgp-multihop 5
               address-family l2vpn evpn
               send-community
               send-community extended
               route-map NH-UNCHANGED out
               rewrite-evpn-rt-asn
               """.format(AS_num, router_id, neighbor_ip_1, remote_as_1, neighbor_ip_2, remote_as_2, neighbor_ip_3, remote_as_3, neighbor_ip_4, remote_as_4, neighbor_ip_5, remote_as_5,  neighbor_ip_6, remote_as_6)
        cfg_out = hd1.configure(cfg1)

###############DCI_Route_Server Config Ends############

###############MLAG_L2_Access_SW_1 Starts############

class DEVICE_BRINGUP_configure_MLAG_L2_Access_SW_1(aetest.Testcase):
    """Device Bring-up Test-Case"""

    @aetest.setup
    def setup(self):
        log.info("Pass testcase setup")

    @aetest.test
    def configure_MLAG_L2_Access_SW_1(self, testscript):
        """ Device Bring-up subsection: Configuring LEAF-1 """

        log.info(banner("Device BringUP Spine-1-Site-1"))
        hd1 = testscript.parameters['MLAG-L2-Access-SW-1']

#################MLAG L2 NODE Interfaces############

        intf1_L2_MLAG_Acc_SW_1 = testscript.parameters['intf_MLAG_L2_Access_SW_1_to_BGW_1_1']
        
        intf2_L2_MLAG_Acc_SW_1 = testscript.parameters['intf_MLAG_L2_Access_SW_1_to_BGW_2_1'] 
        intf3_L2_MLAG_Acc_SW_1 = testscript.parameters['intf_MLAG-L2_Access_SW_1_to_IXIA_1'] 
        cfg1 = """
               vlan 101-102
               feature lacp
               default interface {0},{1}
               interface {0},{1}
               switchport
               no shutdown
               switchport mode trunk
               switchport trunk allowed vlan 101-102
               channel-group 501 mode active
               """.format(intf1_L2_MLAG_Acc_SW_1, intf2_L2_MLAG_Acc_SW_1)
        cfg_out = hd1.configure(cfg1)
        cfg1 = """
               default interface {0}
               interface {0}
               switchport
               no shutdown
               switchport mode trunk
               switchport trunk allowed vlan 101-102
               """.format(intf3_L2_MLAG_Acc_SW_1)
        cfg_out = hd1.configure(cfg1)


###############MLAG_L2_Access_SW_1 Ends############


###############BGW_1_Site_2 Config Starts############

class DEVICE_BRINGUP_configure_BGW_1_Site_2(aetest.Testcase):
    """Device Bring-up Test-Case"""

    @aetest.setup
    def setup(self):
        log.info("Pass testcase setup")

    @aetest.test
    def configure_BGW_1_Site_2(self, testscript):
        """ Device Bring-up subsection: Configuring BGW-1-Site-2 """

        log.info(banner("Device Bring-UP on BGW-1 on Site-2"))
        vlan_range = str(testscript.parameters['BGW_1_Site_2_dict']['VLAN_VNSEGMENT_data']['vlan_range'])
        hd1 = testscript.parameters['BGW-1-Site-2']

        cfg1 = """
               vlan {0}
               """.format(
               vlan_range
        )
        vn_segment = str(testscript.parameters['BGW_1_Site_2_dict']['VLAN_VNSEGMENT_data']['vn_segment'])
        cfg_out = hd1.configure(cfg1)
        vlan_vni_dict = {}
        for vn_segment_list in vn_segment.split(","):
            vlan, vni = vn_segment_list.split('-')
            vlan_vni_dict[vlan] = vni

        for vlan, vni in vlan_vni_dict.items():
            cfg1 = """
                   fabric forwarding anycast-gateway-mac 0001.0001.0001
                   nv overlay evpn 
                   vlan {0}
                   vn-segment {1}
                  """.format(
                  vlan, vni
            )
            cfg_out = hd1.configure(cfg1)

        evpn_data = str(testscript.parameters['EVPN_dict']['evpn_data'])
        evpn_data_vni_dict = {}
        for evpn_data_list in evpn_data.split(","):
            vlan, vni = evpn_data_list.split('-')
            evpn_data_vni_dict[vlan] = vni

        for vlan, vni in evpn_data_vni_dict.items():
            cfg1 = """
                   evpn
                   vni {0} l2
                   rd auto
                   route-target import auto
                   route-target export auto
                  """.format(
                  vni
            )
            cfg_out = hd1.configure(cfg1)

    ####configure the VRF    
        vrf_name = str(testscript.parameters['BGW_1_Site_2_dict']['VRF_data']['vrf_name'])
        l3_vni =   str(testscript.parameters['BGW_1_Site_2_dict']['VRF_data']['l3_vni'])
        cfg1 = """
               evpn multisite border-gateway 200
               dci-advertise-pip
               delay-restore time 30
               vrf context {0}
               vni {1}
               rd auto
               address-family ipv4 unicast
               route-target both auto
               route-target both auto evpn
               """.format(vrf_name, l3_vni)
        cfg_out = hd1.configure(cfg1)

    ####SVI Creation   
        l2_l3_vni_vlan = str(testscript.parameters['BGW_1_Site_2_dict']['SVI_data']['l2_l3_vni_vlan'])
        vrf_name = str(testscript.parameters['BGW_1_Site_2_dict']['SVI_data']['vrf_name'])
        vlan_ip_dict = {}
        for vlan_ip_list in l2_l3_vni_vlan.split(","):
            vlan, ip = vlan_ip_list.split('-')
            vlan_ip_dict[vlan] = ip
        for vlan, ip in vlan_ip_dict.items():
          if ip != 'ip forward':  
            cfg1 = """
                   interface Vlan{0}
                   no shutdown
                   mtu 9216
                   vrf member {1}
                   no ip redirects
                   ip address {2}
                   no ipv6 redirects
                   fabric forwarding mode anycast-gateway
                  """.format(
                  vlan, vrf_name, ip
            )
            cfg_out = hd1.configure(cfg1)
          else:
              cfg1 = """
                   interface Vlan{0}
                   no shutdown
                   mtu 9216
                   vrf member {1}
                   no ip redirects
                   {2}
                   no ipv6 redirects
                   fabric forwarding mode anycast-gateway
                  """.format(
                  vlan, vrf_name, ip
            )

              cfg_out = hd1.configure(cfg1)

    ########Creating Loop back interfaces
        #######ospf loopback####
        lback_underlay_ospf = str(testscript.parameters['BGW_1_Site_2_dict']['lback_underlay_ospf'])
        lback_overlay_bgp = str(testscript.parameters['BGW_1_Site_2_dict']['lback_overlay_bgp'])
        lback_vtep_primary = str(testscript.parameters['BGW_1_Site_2_dict']['lback_vtep_primary'])
        description_vtep = '** RID/VPC VTEPS **'
       #########ospf########
        loopback_name, loopback_ip = lback_underlay_ospf.split('-')
        description = '** RID/Underlay **'
        result = configure_loopback_tag(hd1 = hd1, loopback_name = loopback_name, loopback_ip = loopback_ip, description = description)
        if result:
            log.info("Loopback interfaces are created successfully")
        #######BGP loopback####
        loopback_name, loopback_ip = lback_overlay_bgp.split('-')
        description = '** RID/Overlay **'
        result = configure_loopback_tag(hd1 = hd1, loopback_name = loopback_name, loopback_ip = loopback_ip, description = description)
        if result:
            log.info("Loopback interfaces are created successfully")
        #######VTEP loopback####
        loopback_name, loopback_ip = lback_vtep_primary.split('-')
        description = '** VPC VTEP loopback **'
        result = configure_loopback_tag(hd1 = hd1, loopback_name = loopback_name, loopback_ip = loopback_ip, description = description)
        if result:
            log.info("Loopback interfaces are created successfully")
    
        #########Configuring ospf on VPC Node1 interfces###### 
        ospf_intf_list= ['lo0', 'lo1', 'lo100' ]
        ospf_instance_name = 'UNDERLAY-NET'
        result = configure_ospf(hd1 = hd1, ospf_intf_list= ospf_intf_list, ospf_instance_name=ospf_instance_name)
        #########Configuring PIM  on the VPC node interfaces###### 
        pim_intf_list= [testscript.parameters['intf_BGW_1_Site_2_1_to_Spine_1_Site_2_1'], 'lo0', 'lo1', 'lo100' ]
        cfg1 = """
               router ospf UNDERLAY-NET
               router-id 1.1.0.203
               interface {0}
               no switchport
               no shutdown
               ip address 10.1.221.2/30
               ip ospf network point-to-point
               ip router ospf UNDERLAY-NET area 0.0.0.0
               evpn multisite fabric-tracking
               """.format(testscript.parameters['intf_BGW_1_Site_2_1_to_Spine_1_Site_2_1'])
        cfg_out = hd1.configure(cfg1)
        cfg1 = """
               interface {0}
               no switchport
               no shutdown
               ip address 10.1.222.1/30 tag 54321
               ip pim sparse-mode
               evpn multisite dci-tracking
               mtu 9216
               tunnel-encryption
               """.format(testscript.parameters['intf_BGW_1_Site_2_to_DCI_Route_Server_1_1'])
        cfg_out = hd1.configure(cfg1)
        result = configure_pim(hd1 = hd1, pim_intf_list = pim_intf_list)
        #########Configuring BGP###### 
        AS_num = str(testscript.parameters['BGW_1_Site_2_dict']['BGP_config']['AS_num'])
        router_id = str(testscript.parameters['BGW_1_Site_2_dict']['BGP_config']['router_id'])
        neighbor_ip_1 = str(testscript.parameters['BGW_1_Site_2_dict']['BGP_config']['neighbor_ip_1'])
        remote_as_1 = str(testscript.parameters['BGW_1_Site_2_dict']['BGP_config']['remote_as_1'])
        neighbor_ip_2 = str(testscript.parameters['BGW_1_Site_2_dict']['BGP_config']['neighbor_ip_2'])
        remote_as_2 = str(testscript.parameters['BGW_1_Site_2_dict']['BGP_config']['remote_as_2'])
        neighbor_ip_3 = str(testscript.parameters['BGW_1_Site_2_dict']['BGP_config']['neighbor_ip_3'])
        remote_as_3 = str(testscript.parameters['BGW_1_Site_2_dict']['BGP_config']['remote_as_3'])
        vrf = str(testscript.parameters['BGW_1_Site_2_dict']['BGP_config']['vrf'])
        update_source_1 = testscript.parameters['intf_BGW_1_to_DCI_Route_Server_1'] 
 
        cfg1 = """
               route-map NH-UNCHANGED permit 10
               set ip next-hop unchanged
               route-map RMAP-REDIST-DIRECT permit 10
               match tag 54321
               router bgp {0}
               router-id {1}
               timers prefix-peer-timeout 30
               bestpath as-path multipath-relax
               reconnect-interval 1
               maxas-limit 10
               log-neighbor-changes
               address-family ipv4 unicast
               redistribute direct route-map RMAP-REDIST-DIRECT
               maximum-paths 64
               maximum-paths ibgp 64
               default-metric 0
               additional-paths send
               additional-paths receive
               address-family l2vpn evpn
               maximum-paths 64
               additional-paths send
               additional-paths receive
               neighbor {2}
               remote-as {3}
               description ** towrds DCI-Route-Serve **
               address-family ipv4 unicast
               soft-reconfiguration inbound always
               neighbor {5}
               remote-as {6}
               description ** towrds BGP-RR-Spine-01**
               update-source loopback1
               address-family l2vpn evpn
               allowas-in 3
               send-community
               send-community extended
               neighbor {7}
               remote-as {8}
               update-source loopback1
               ebgp-multihop 5
               peer-type fabric-external
               address-family l2vpn evpn
               send-community
               send-community extended
               rewrite-evpn-rt-asn
               vrf {9}
               address-family ipv4 unicast
               advertise l2vpn evpn
               maximum-paths 64
               maximum-paths ibgp 64
               """.format(AS_num, router_id, neighbor_ip_1, remote_as_1, update_source_1,neighbor_ip_2, remote_as_2, neighbor_ip_3, remote_as_3, vrf)
        cfg_out = hd1.configure(cfg1)
        #########Configuring interface nve###### 
        cfg1 = """
               ip pim rp-address 6.6.6.6 group-list 238.0.0.0/24
               interface loopback200
               no shutdown
               ip address 120.0.0.1/32 tag 54321
               ip router ospf UNDERLAY-NET area 0.0.0.0
               ip pim sparse-mode
               interface nve1
               no shutdown
               host-reachability protocol bgp
               advertise virtual-rmac
               source-interface loopback100
               multisite border-gateway interface loopback200
               member vni 100101
               multisite ingress-replication
               mcast-group 238.0.0.10
               member vni 100102
               multisite ingress-replication
               mcast-group 238.0.0.10
               member vni 9002001 associate-vrf

               """
        cfg_out = hd1.configure(cfg1)
        cfg1 = """
               key chain kc1 tunnel-encryption
               key 2000
               key-octet-string 7 070e234f4a0c1f5546405858517c7c7c713237211702105350040a0c0602595b41175b5b5356540505590852520e005c4a0706580f0309711d1c5a4d5041455355 cryptographic-algorithm AES_256_CMAC
               tunnel-encryption icv
               tunnel-encryption source-interface loopback1
               tunnel-encryption policy p1
               tunnel-encryption peer-ip 100.0.0.201
               keychain kc1 policy p1
               tunnel-encryption peer-ip 100.0.0.202
               keychain kc1 policy p1
 
               """
        cfg_out = hd1.configure(cfg1)

###############BGW_1_Site_2 Config Ends############

#################Spine-1-Site-2 Config Starts############

class DEVICE_BRINGUP_configure_Spine_1_Site_2(aetest.Testcase):
    """Device Bring-up Test-Case"""

    @aetest.setup
    def setup(self):
        log.info("Pass testcase setup")

    @aetest.test
    def configure_Spine_1_Site_2(self, testscript):
        """ Device Bring-up subsection: Configuring LEAF-1 """

        log.info(banner("Device BringUP Spine-1-Site-1"))
        hd1 = testscript.parameters['Spine-1-Site-2']
############SPINE1-SITE-2-Config-Starts#####################
    ########Creating Loop back interfaces
        #######ospf loopback####
        lback_underlay_ospf = str(testscript.parameters['Spine_1_Site_2_dict']['lback_underlay_ospf'])
        lback_overlay_bgp = str(testscript.parameters['Spine_1_Site_2_dict']['lback_overlay_bgp'])
        lback_pim_rp = str(testscript.parameters['Spine_1_Site_2_dict']['lback_pim_rp'])
       #########ospf########
        loopback_name, loopback_ip = lback_underlay_ospf.split('-')
        description = '** RID/Underlay **'
        result = configure_loopback(hd1 = hd1, loopback_name = loopback_name, loopback_ip = loopback_ip, description = description)
        if result:
            log.info("Loopback interfaces are created successfully")

        #######BGP loopback####
        loopback_name, loopback_ip = lback_overlay_bgp.split('-')
        description = '** RID/Overlay **'
        result = configure_loopback(hd1 = hd1, loopback_name = loopback_name, loopback_ip = loopback_ip, description = description)
        if result:
            log.info("Loopback interfaces are created successfully")
        #######PIM RP loopback####
        loopback_name, loopback_ip = lback_pim_rp.split('-')
        description = '** PIM RP Loopback**'
        result = configure_loopback(hd1 = hd1, loopback_name = loopback_name, loopback_ip = loopback_ip, description = description)
        ospf_intf_list= ['lo0', 'lo1', 'lo666' ]
        ospf_instance_name = 'UNDERLAY-NET'
        result = configure_ospf(hd1 = hd1, ospf_intf_list= ospf_intf_list, ospf_instance_name=ospf_instance_name)
        result = configure_pim(hd1 = hd1, pim_intf_list = ospf_intf_list)
        if result:
            log.info("Loopback interfaces are created successfully")
        intf1_spine_1_site_1_2 = testscript.parameters['intf_Spine_1_Site_2_to_BGW_1_Site_2_1'] 
        
        intf2_spine_1_site_1_2 = testscript.parameters['intf_Spine_1_Site_2_to_Leaf_02_Site_2_1'] 
        cfg1 = """
               ip pim rp-address 6.6.6.6 group-list 238.0.0.0/24
               router ospf UNDERLAY-NET
               router-id 1.1.0.102
               nv overlay evpn 
               interface {0}
               description ** Connected towarrds Multisite-BG1 **
               no switchport
               no shutdown
               medium p2p
               ip address 10.1.221.1/30
               ip ospf network point-to-point
               ip router ospf UNDERLAY-NET area 0.0.0.0
               ip pim sparse-mode
               no shutdown
               interface {1}
               no switchport
               no shutdown
               medium p2p
               ip address 10.1.4.2/30
               ip ospf network point-to-point
               ip router ospf UNDERLAY-NET area 0.0.0.0
               ip pim sparse-mode
               no shutdown
               """.format(intf1_spine_1_site_1_2, intf2_spine_1_site_1_2)
        cfg_out = hd1.configure(cfg1)

        #########Configuring BGP###### 
        AS_num = str(testscript.parameters['Spine_1_Site_2_dict']['BGP_config']['AS_num'])
        router_id = str(testscript.parameters['Spine_1_Site_2_dict']['BGP_config']['router_id'])
        neighbor_ip_1 = str(testscript.parameters['Spine_1_Site_2_dict']['BGP_config']['neighbor_ip_1'])
        remote_as_1 = str(testscript.parameters['Spine_1_Site_2_dict']['BGP_config']['remote_as_1'])
        neighbor_ip_2 = str(testscript.parameters['Spine_1_Site_2_dict']['BGP_config']['neighbor_ip_2'])
 
        cfg1 = """
        router bgp {0}
        router-id {1}
        address-family ipv4 unicast
        address-family l2vpn evpn
        neighbor {3} 
        remote-as {2}
        description ** towrds Leaf-04 from BGP-RR SPINE-102**
        update-source loopback1
        address-family l2vpn evpn
        send-community
        send-community extended
        route-reflector-client
        neighbor {4}
        remote-as {2}
        description ** towrds Multisite-BGW3 from BGP-RR SPINE-102**
        update-source loopback1
        address-family l2vpn evpn
        send-community
        send-community extended
        route-reflector-client

               """.format(AS_num, router_id, remote_as_1, neighbor_ip_1, neighbor_ip_2)
        cfg_out = hd1.configure(cfg1)

        cfg1 = """
               interface loopback666
               description ** PIM RP **
               ip address 6.6.6.6/32
               ip router ospf UNDERLAY-NET area 0.0.0.0
               ip pim sparse-mode
               """
        cfg_out = hd1.configure(cfg1)

#################Spine-1-Site-2 Config Ends############


#################Leaf_02_Site_2 Config Starts############

class DEVICE_BRINGUP_configure_Leaf_02_Site_2(aetest.Testcase):
    """Device Bring-up Test-Case"""

    @aetest.setup
    def setup(self):
        log.info("Pass testcase setup")

    @aetest.test
    def configure_Leaf_02_Site_2(self, testscript):
        """ Device Bring-up subsection: Configuring Leaf_02_Site_2 """

        log.info(banner("Device BringUP Leaf_02_Site_2"))
        vlan_range = str(testscript.parameters['Leaf_02_Site_2_dict']['VLAN_VNSEGMENT_data']['vlan_range'])
        hd1 = testscript.parameters['Leaf-02-Site-2']

        cfg1 = """
               nv overlay evpn
               vlan {0}
               """.format(
               vlan_range
        )
        cfg_out = hd1.configure(cfg1)
        vn_segment = str(testscript.parameters['Leaf_02_Site_2_dict']['VLAN_VNSEGMENT_data']['vn_segment'])
        cfg_out = hd1.configure(cfg1)
        vlan_vni_dict = {}
        for vn_segment_list in vn_segment.split(","):
            vlan, vni = vn_segment_list.split('-')
            vlan_vni_dict[vlan] = vni

        for vlan, vni in vlan_vni_dict.items():
            cfg1 = """
                   vlan {0}
                   vn-segment {1}
                  """.format(
                  vlan, vni
            )
            cfg_out = hd1.configure(cfg1)
        evpn_data = str(testscript.parameters['EVPN_dict']['evpn_data'])
        evpn_data_vni_dict = {}
        for evpn_data_list in evpn_data.split(","):
            vlan, vni = evpn_data_list.split('-')
            evpn_data_vni_dict[vlan] = vni

        for vlan, vni in evpn_data_vni_dict.items():
            cfg1 = """
                   evpn
                   vni {0} l2
                   rd auto
                   route-target import auto
                   route-target export auto
                  """.format(
                  vni
            )
            cfg_out = hd1.configure(cfg1)

    ####configure the VRF    
        vrf_name = str(testscript.parameters['Leaf_02_Site_2_dict']['VRF_data']['vrf_name'])
        l3_vni =   str(testscript.parameters['Leaf_02_Site_2_dict']['VRF_data']['l3_vni'])
        cfg1 = """
               fabric forwarding anycast-gateway-mac 0001.0001.0001
               nv overlay evpn 
               vrf context {0}
               vni {1}
               rd auto
               address-family ipv4 unicast
               route-target both auto
               route-target both auto evpn
               """.format(vrf_name, l3_vni)
        cfg_out = hd1.configure(cfg1)


    ####SVI Creation   
        l2_l3_vni_vlan = str(testscript.parameters['Leaf_02_Site_2_dict']['SVI_data']['l2_l3_vni_vlan'])
        vrf_name = str(testscript.parameters['Leaf_02_Site_2_dict']['SVI_data']['vrf_name'])
        vlan_ip_dict = {}
        for vlan_ip_list in l2_l3_vni_vlan.split(","):
            vlan, ip = vlan_ip_list.split('-')
            vlan_ip_dict[vlan] = ip
        for vlan, ip in vlan_ip_dict.items():
          if ip != 'ip forward':  
            cfg1 = """
                   interface Vlan{0}
                   no shutdown
                   mtu 9216
                   vrf member {1}
                   no ip redirects
                   ip address {2}
                   no ipv6 redirects
                   fabric forwarding mode anycast-gateway
                  """.format(
                  vlan, vrf_name, ip
            )
            cfg_out = hd1.configure(cfg1)
          else:
              cfg1 = """
                   interface Vlan{0}
                   no shutdown
                   mtu 9216
                   vrf member {1}
                   no ip redirects
                   {2}
                   no ipv6 redirects
                   fabric forwarding mode anycast-gateway
                  """.format(
                  vlan, vrf_name, ip
            )

              cfg_out = hd1.configure(cfg1)

    ########Creating Loop back interfaces
        #######ospf loopback####
        lback_underlay_ospf = str(testscript.parameters['Leaf_02_Site_2_dict']['lback_underlay_ospf'])
        lback_overlay_bgp = str(testscript.parameters['Leaf_02_Site_2_dict']['lback_overlay_bgp'])
        lback_vtep_primary = str(testscript.parameters['Leaf_02_Site_2_dict']['lback_vtep_primary'])
        description_vtep = '** RID/VPC VTEPS **'
       #########ospf########
        loopback_name, loopback_ip = lback_underlay_ospf.split('-')
        description = '** RID/Underlay **'
        result = configure_loopback(hd1 = hd1, loopback_name = loopback_name, loopback_ip = loopback_ip, description = description)
        if result:
            log.info("Loopback interfaces are created successfully")
        #######BGP loopback####
        loopback_name, loopback_ip = lback_overlay_bgp.split('-')
        description = '** RID/Overlay **'
        result = configure_loopback(hd1 = hd1, loopback_name = loopback_name, loopback_ip = loopback_ip, description = description)
        if result:
            log.info("Loopback interfaces are created successfully")
        #######VTEP loopback####
        loopback_name, loopback_ip = lback_vtep_primary.split('-')
        description = '** VPC VTEP loopback **'
        result = configure_loopback(hd1 = hd1, loopback_name = loopback_name, loopback_ip = loopback_ip, description = description)
        if result:
            log.info("Loopback interfaces are created successfully")
    
        #########Configuring ospf on Leaf 02 interfces###### 
        ospf_intf_list= ['lo0', 'lo1', 'lo100']
        ospf_instance_name = 'UNDERLAY-NET'
        result = configure_ospf(hd1 = hd1, ospf_intf_list= ospf_intf_list, ospf_instance_name=ospf_instance_name)
        #########Configuring PIM  on the Leaf 02 interfaces###### 
        pim_intf_list= [testscript.parameters['intf_Leaf_02_Site_2_to_Spine_1_Site_2_1'], 'lo0', 'lo1', 'lo100' ]
        cfg1 = """
               router ospf UNDERLAY-NET
               router-id 1.1.0.4
               interface {0}
               no switchport
               no shutdown
               ip address 10.1.4.1/30
               ip ospf network point-to-point
               ip router ospf UNDERLAY-NET area 0.0.0.0
               """.format(testscript.parameters['intf_Leaf_02_Site_2_to_Spine_1_Site_2_1'])
        cfg_out = hd1.configure(cfg1)
        result = configure_pim(hd1 = hd1, pim_intf_list = pim_intf_list)
        #########Configuring BGP###### 
        AS_num = str(testscript.parameters['Leaf_02_Site_2_dict']['BGP_config']['AS_num'])
        router_id = str(testscript.parameters['Leaf_02_Site_2_dict']['BGP_config']['router_id'])
        neighbor_ip_1 = str(testscript.parameters['Leaf_02_Site_2_dict']['BGP_config']['neighbor_ip_1'])
        remote_as_1 = str(testscript.parameters['Leaf_02_Site_2_dict']['BGP_config']['remote_as_1'])
        vrf = str(testscript.parameters['Leaf_02_Site_2_dict']['BGP_config']['vrf'])

 
        cfg1 = """
               router bgp {0}
               router-id {1}
               address-family ipv4 unicast
               address-family l2vpn evpn
               neighbor {2}
               remote-as {3}
               description ** towards Spine-102 BGP-RR **
               update-source loopback1
               address-family l2vpn evpn
               send-community extended
               vrf {4}
               address-family ipv4 unicast
               advertise l2vpn evpn
               maximum-paths 64
               """.format(AS_num, router_id, neighbor_ip_1, remote_as_1, vrf)
        cfg_out = hd1.configure(cfg1)
        #########Configuring interface nve###### 
        cfg1 = """
               ip pim rp-address 6.6.6.6 group-list 238.0.0.0/24
               interface nve1
               no shutdown
               host-reachability protocol bgp
               source-interface loopback100
               member vni 100101
               mcast-group 238.0.0.10
               member vni 100102
               mcast-group 238.0.0.10
               member vni 9002001 associate-vrf
               """
        cfg_out = hd1.configure(cfg1)
        int_Leaf_02_Site_2_to_IXIA_1=testscript.parameters['int_Leaf_02_Site_2_to_IXIA_1'] 
        cfg1 = """
               default interface {0}
               interface {0}
               switchport
               no shutdown
               switchport mode trunk
               switchport trunk allowed vlan 101-102
               """.format(int_Leaf_02_Site_2_to_IXIA_1)
        cfg_out = hd1.configure(cfg1)

        @aetest.cleanup
        def cleanup(self):
             """ testcase clean up """
             log.info("Pass testcase cleanup")

time.sleep(300)             


#################Leaf_02_Site_2 Config Ends############

# *****************************************************************************************************************************#

class IXIA_CONFIGURATION_CONNECT_IXIA_CHASSIS(aetest.Testcase):
    """IXIA_CONFIGURATION"""

    @aetest.setup
    def setup(self):
        log.info("Pass testcase setup")

    @aetest.test
    def CONNECT_IXIA_CHASSIS(self, testscript):
        """ IXIA_CONFIGURATION subsection: Connect to IXIA """

        log.info(banner("IXIA Configuration Block"))

        # Get IXIA paraameters
        ixia_chassis_ip = testscript.parameters['ixia_chassis_ip']
        ixia_tcl_server = testscript.parameters['ixia_tcl_server']
        ixia_tcl_port = testscript.parameters['ixia_tcl_port']
        ixia_int_list = testscript.parameters['ixia_int_list']

        ix_int_1 = testscript.parameters['int_IXIA_1_to_L2_VPC_Acc_SW_1']
        ix_int_2 = testscript.parameters['int_IXIA_1_to_Leaf_02_Site_2'] 
        ix_int_3 = testscript.parameters['int_IXIA_1_to_MLAG_L2_Access_SW_1'] 
        #ix_int_1 = testscript.parameters['intf_IXIA_1_to_BGW_1']
        #ix_int_2 = testscript.parameters['intf_IXIA_1_to_BGW_2']
        #ix_int_1 = testscript.parameters['intf_IXIA_1_to_BGW_1']
        #ix_int_1 = testscript.parameters['intf_IXIA_1_to_BGW_1']

        ixiaArgDict = {
            'chassis_ip': ixia_chassis_ip,
            'port_list': ixia_int_list,
            'tcl_server': ixia_tcl_server,
            'tcl_port': ixia_tcl_port,
        }

        log.info("Ixia Args Dict is:")
        log.info(ixiaArgDict)

        result = ixLib.connect_to_ixia(ixiaArgDict)
        if result == 0:
            log.debug("Connecting to ixia failed")
            self.errored("Connecting to ixia failed", goto=['next_tc'])

        testscript.parameters['ixia_connect_result'] = result

        log.info(result)
        log.info(testscript.parameters['ixia_connect_result'])

        ch_key = result['port_handle']
        for ch_p in ixia_chassis_ip.split('.'):
            ch_key = ch_key[ch_p]

        log.info("Port Handles are:")
        log.info(ch_key)

        testscript.parameters['port_handle_1'] = ch_key[ix_int_1]
        testscript.parameters['port_handle_2'] = ch_key[ix_int_2]
        testscript.parameters['port_handle_3'] = ch_key[ix_int_3]

    @aetest.cleanup
    def cleanup(self):
        """ testcase clean up """
        log.info("Pass testcase cleanup")

# *****************************************************************************************************************************#

class IXIA_CONFIGURATION_CREATE_IXIA_TOPOLOGIES(aetest.Testcase):
    """IXIA_CONFIGURATION"""

    @aetest.setup
    def setup(self):
        log.info("Pass testcase setup")

    @aetest.test
    def CREATE_IXIA_TOPOLOGIES(self, testscript):
        """ IXIA_CONFIGURATION subsection: Create IXIA Topologies """

        TOPO_1_dict = {'topology_name': 'LEAF-1-TG',
                       'device_grp_name': 'LEAF-1-TG',
                       'port_handle': testscript.parameters['port_handle_1']}

        TOPO_2_dict = {'topology_name': 'LEAF-2-TG',
                       'device_grp_name': 'LEAF-2-TG',
                       'port_handle': testscript.parameters['port_handle_2']}
        TOPO_3_dict = {'topology_name': 'MLAG-L2-NODE-TG',
                       'device_grp_name': 'MLAG-L2-NODE-TG',
                       'port_handle': testscript.parameters['port_handle_3']}

        testscript.parameters['IX_TP1'] = ixLib.create_topo_device_grp(TOPO_1_dict)
        if testscript.parameters['IX_TP1'] == 0:
            log.debug("Creating Topology failed")
            self.errored("Creating Topology failed", goto=['next_tc'])
        else:
            log.info("Created L1-TG Topology Successfully")

        testscript.parameters['IX_TP2'] = ixLib.create_topo_device_grp(TOPO_2_dict)
        if testscript.parameters['IX_TP2'] == 0:
            log.debug("Creating Topology failed")
            self.errored("Creating Topology failed", goto=['next_tc'])
        else:
            log.info("Created L2-TG Topology Successfully")
        
        testscript.parameters['IX_TP3'] = ixLib.create_topo_device_grp(TOPO_3_dict)
        if testscript.parameters['IX_TP3'] == 0:
            log.debug("Creating Topology failed")
            self.errored("Creating Topology failed", goto=['next_tc'])
        else:
            log.info("Created L2-TG Topology Successfully")

        testscript.parameters['IX_TP1']['port_handle'] = testscript.parameters['port_handle_1']
        testscript.parameters['IX_TP2']['port_handle'] = testscript.parameters['port_handle_2']
        testscript.parameters['IX_TP3']['port_handle'] = testscript.parameters['port_handle_3']

    @aetest.cleanup
    def cleanup(self):
        """ testcase clean up """
        log.info("Pass testcase cleanup")

# *****************************************************************************************************************************#

class IXIA_CONFIGURATION_CONFIGURE_IXIA_INTERFACES(aetest.Testcase):
    """IXIA_CONFIGURATION"""

    @aetest.setup
    def setup(self):
        log.info("Pass testcase setup")

    @aetest.test
    def CONFIGURE_IXIA_INTERFACES(self, testscript):
        """ IXIA_CONFIGURATION subsection: Configure IXIA Interfaces """

        P1 = testscript.parameters['port_handle_1']
        P2 = testscript.parameters['port_handle_2']

        P1_dict = testscript.parameters['VPC_NODE_TGEN_dict']
        P2_dict = testscript.parameters['LEAF_02_SITE2_TGEN_dict']

        P1_int_dict_1 = {'dev_grp_hndl': testscript.parameters['IX_TP1']['dev_grp_hndl'],
                         'port_hndl': P1,
                         'no_of_ints': P1_dict['no_of_ints'],
                         'phy_mode': P1_dict['phy_mode'],
                         'mac': P1_dict['mac'],
                         'mac_step': P1_dict['mac_step'],
                         'protocol': P1_dict['protocol'],
                         'v4_addr': P1_dict['v4_addr'],
                         'v4_addr_step': P1_dict['v4_addr_step'],
                         'v4_gateway': P1_dict['v4_gateway'],
                         'v4_gateway_step': P1_dict['v4_gateway_step'],
                         'v4_netmask': P1_dict['v4_netmask'],
                         'v6_addr': P1_dict['v6_addr'],
                         'v6_addr_step': P1_dict['v6_addr_step'],
                         'v6_gateway': P1_dict['v6_gateway'],
                         'v6_gateway_step': P1_dict['v6_gateway_step'],
                         'v6_netmask': P1_dict['v6_netmask'],
                         'vlan_id': P1_dict['vlan_id'],
                         'vlan_id_step': P1_dict['vlan_id_step']}

        P2_int_dict_1 = {'dev_grp_hndl': testscript.parameters['IX_TP2']['dev_grp_hndl'],
                         'port_hndl': P2,
                         'no_of_ints': P2_dict['no_of_ints'],
                         'phy_mode': P2_dict['phy_mode'],
                         'mac': P2_dict['mac'],
                         'mac_step': P2_dict['mac_step'],
                         'protocol': P2_dict['protocol'],
                         'v4_addr': P2_dict['v4_addr'],
                         'v4_addr_step': P2_dict['v4_addr_step'],
                         'v4_gateway': P2_dict['v4_gateway'],
                         'v4_gateway_step': P2_dict['v4_gateway_step'],
                         'v4_netmask': P2_dict['v4_netmask'],
                         'v6_addr': P2_dict['v6_addr'],
                         'v6_addr_step': P2_dict['v6_addr_step'],
                         'v6_gateway': P2_dict['v6_gateway'],
                         'v6_gateway_step': P2_dict['v6_gateway_step'],
                         'v6_netmask': P2_dict['v6_netmask'],
                         'vlan_id': P2_dict['vlan_id'],
                         'vlan_id_step': P2_dict['vlan_id_step']}

        P1_IX_int_data = ixLib.configure_multi_ixia_interface(P1_int_dict_1)
        P2_IX_int_data = ixLib.configure_multi_ixia_interface(P2_int_dict_1)

        log.info(P1_IX_int_data)
        log.info(P2_IX_int_data)

        if P1_IX_int_data == 0 or P2_IX_int_data == 0:
            log.debug("Configuring IXIA Interface failed")
            self.errored("Configuring IXIA Interface failed", goto=['next_tc'])
        else:
            log.info("Configured IXIA Interface Successfully")

        testscript.parameters['IX_TP1']['eth_handle'] = P1_IX_int_data['eth_handle']
        testscript.parameters['IX_TP1']['ipv4_handle'] = P1_IX_int_data['ipv4_handle']
        testscript.parameters['IX_TP1']['ipv6_handle'] = P1_IX_int_data['ipv6_handle']
        testscript.parameters['IX_TP1']['topo_int_handle'] = P1_IX_int_data['topo_int_handle'].split(" ")

        testscript.parameters['IX_TP2']['eth_handle'] = P2_IX_int_data['eth_handle']
        testscript.parameters['IX_TP2']['ipv4_handle'] = P2_IX_int_data['ipv4_handle']
        testscript.parameters['IX_TP2']['ipv6_handle'] = P2_IX_int_data['ipv6_handle']
        testscript.parameters['IX_TP2']['topo_int_handle'] = P2_IX_int_data['topo_int_handle'].split(" ")

        log.info("IXIA Port 1 Handles")
        log.info(testscript.parameters['IX_TP1'])
        log.info("IXIA Port 2 Handles")
        log.info(testscript.parameters['IX_TP2'])

        time.sleep(100)

    @aetest.cleanup
    def cleanup(self):
        """ testcase clean up """
        log.info("Pass testcase cleanup")

# *****************************************************************************************************************************#
class IXIA_CONFIGURATION_START_IXIA_PROTOCOLS(aetest.Testcase):
    """IXIA_CONFIGURATION"""

    @aetest.setup
    def setup(self):
        log.info("Pass testcase setup")

    @aetest.test
    def START_IXIA_PROTOCOLS(self):
        """ IXIA_CONFIGURATION subsection: Configure IXIA IGMP Groups """

        # _result_ = ixiahlt.test_control(action='configure_all')
        # print(_result_)
        proto_result = ixLib.start_protocols()
        if proto_result == 0:
            log.debug("Starting Protocols failed")
            self.errored("Starting Protocols failed", goto=['next_tc'])
        else:
            log.info("Started Protocols Successfully")

        time.sleep(60)

        proto_result = ixLib.stop_protocols()
        if proto_result == 0:
            log.debug("Stopped Protocols failed")
            self.errored("Stopped Protocols failed", goto=['next_tc'])
        else:
            log.info("Stopped Protocols Successfully")

        time.sleep(30)

        proto_result = ixLib.start_protocols()
        if proto_result == 0:
            log.debug("Starting Protocols failed")
            self.errored("Starting Protocols failed", goto=['next_tc'])
        else:
            log.info("Started Protocols Successfully")

class IXIA_CONFIGURATION_CONFIGURE_L3KUC_IXIA_TRAFFIC(aetest.Testcase):
    """IXIA_CONFIGURATION_CONFIGURE_L3KUC_IXIA_TRAFFIC"""

    @aetest.setup
    def setup(self):
        log.info("Pass testcase setup")

    @aetest.test
    def CONFIGURE_L3KUC_IXIA_TRAFFIC(self, testscript):
        """ IXIA_CONFIGURATION subsection: Configure L3 KUC Traffic Item """

        # Do not perform configurations if skip_tgen_config flag is set
        if not testscript.parameters['script_flags']['skip_tgen_config']:

            IX_TP1 = testscript.parameters['IX_TP1']
            IX_TP2 = testscript.parameters['IX_TP2']

            vrf_count = int(testscript.parameters['forwardingSysDict1']['VRF_count'])
            vlan_per_vrf = int(testscript.parameters['forwardingSysDict1']['VLAN_PER_VRF_count'])

            L3KUC_v4_dict = {'src_hndl'                 : IX_TP1['ipv4_handle'],
                                'dst_hndl'              : IX_TP2['ipv4_handle'],
                                'circuit'               : 'ipv4',
                                'TI_name'               : "L3KUC_TP1_TP2_V4",
                                'rate_pps'              : "10000",
                                'bi_dir'                : 1,
                                'no_of_end_points'      : vrf_count,
                                'src_port_start'        : '1',
                                'src_port_start_step'   : '0',
                                'src_intf_count'        : str(vlan_per_vrf),
                                'dst_port_start'        : '1',
                                'dst_port_start_step'   : '0',
                                'dst_intf_count'        : str(vlan_per_vrf),
                                'route_mesh'            : 'fully'
                                }

            L3KUC_v4_TI = testscript.parameters['L3KUC_v4_TI'] = ixLib.configure_multi_endpoint_ixia_traffic_item(L3KUC_v4_dict)

            if L3KUC_v4_TI == 0:
                log.debug("Configuring L3 KUC failed")
                self.errored("Configuring L3 KUC failed", goto=['next_tc'])

        
            self.passed(reason="Skipped TGEN Configurations as per request")

        time.sleep(100)


# *****************************************************************************************************************************#

class IXIA_CONFIGURATION_CONFIGURE_BCAST_IXIA_TRAFFIC(aetest.Testcase):
    """IXIA_CONFIGURATION"""

    @aetest.setup
    def setup(self):
        log.info("Pass testcase setup")

    @aetest.test
    def CONFIGURE_BCAST_IXIA_TRAFFIC(self, testscript):
        """ IXIA_CONFIGURATION subsection: Configure MCAST Traffic Item """

        IX_TP1 = testscript.parameters['IX_TP1']
        IX_TP2 = testscript.parameters['IX_TP2']
        IX_TP3 = testscript.parameters['IX_TP3']

        P1_dict = testscript.parameters['VPC_NODE_TGEN_dict']
        P2_dict = testscript.parameters['LEAF_02_SITE2_TGEN_dict']

        BCAST_MLAG_BGW_to_LEAF_02_dict = {
                            'src_hndl'      : IX_TP3['port_handle'],
                            'dst_hndl'      : IX_TP2['port_handle'],
                            'TI_name'       : "BCAST_MLAG_BGW_to_LEAF_02",
                            'frame_size'    : "1000",
                            'rate_pps'      : "250000",
                            'src_mac'       : "00:00:30:00:00:01",
                            'srcmac_step'   : "00:00:00:00:00:01",
                            'srcmac_count'  : "100",
                            'vlan_id'       : P1_dict['vlan_id'],
                            'vlanid_step'   : "1",
                            'vlanid_count'  : P1_dict['no_of_ints'],
                            'ip_src_addrs'  : "192.168.11.11",
                            'ip_step'       : "0.0.1.0",
                      }

        BCAST_MLAG_BGW_to_LEAF_02_TI = testscript.parameters['BCAST_MLAG_BGW_to_LEAF_02_TI'] = ixLib.configure_ixia_BCAST_traffic_item(BCAST_MLAG_BGW_to_LEAF_02_dict)

        if BCAST_MLAG_BGW_to_LEAF_02_TI == 0:
            log.debug("Configuring BCast from MLAG_BGW_to_LEAF_02 failed")
            self.errored("Configuring BCast from MLAG_BGW_to_LEAF_02 failed", goto=['next_tc'])
        
        BCAST_LEAF_02_to_MLAG_BGW_dict = {
                            'src_hndl'      : IX_TP3['port_handle'],
                            'dst_hndl'      : IX_TP2['port_handle'],
                            'TI_name'       : "BCAST_LEAF_02_to_MLAG_BGW",
                            'frame_size'    : "1000",
                            'rate_pps'      : "250000",
                            'src_mac'       : "00:10:30:00:00:01",
                            'srcmac_step'   : "00:00:00:00:00:01",
                            'srcmac_count'  : "100",
                            'vlan_id'       : P2_dict['vlan_id'],
                            'vlanid_step'   : "1",
                            'vlanid_count'  : P2_dict['no_of_ints'],
                            'ip_src_addrs'  : "192.168.12.120",
                            'ip_step'       : "0.0.1.0",
                      }

        BCAST_LEAF_02_to_MLAG_BGW_TI = testscript.parameters['BCAST_LEAF_02_to_MLAG_BGW_TI'] = ixLib.configure_ixia_BCAST_traffic_item(BCAST_LEAF_02_to_MLAG_BGW_dict)

        if BCAST_LEAF_02_to_MLAG_BGW_TI == 0:
            log.debug("Configuring BCast from LEAF_02_to_MLAG_BGW failed")
            self.errored("Configuring BCast from LEAF_02_to_MLAG_BGW failed", goto=['next_tc'])
        

        BCAST_LEAF_02_to_LEAF_01_dict = {
                            'src_hndl'      : IX_TP2['port_handle'],
                            'dst_hndl'      : IX_TP1['port_handle'],
                            'TI_name'       : "BCAST_LEAF_02_to_LEAF_01",
                            'frame_size'    : "1000",
                            'rate_pps'      : "250000",
                            'src_mac'       : "00:20:20:30:40:01",
                            'srcmac_step'   : "00:00:00:00:00:01",
                            'srcmac_count'  : "100",
                            'vlan_id'       : P1_dict['vlan_id'],
                            'vlanid_step'   : "1",
                            'vlanid_count'  : P1_dict['no_of_ints'],
                            'ip_src_addrs'  : "192.168.11.120",
                            'ip_step'       : "0.0.1.0",
                      }

        BCAST_LEAF_02_to_LEAF_01_TI = testscript.parameters['BCAST_LEAF_02_to_LEAF_01_TI'] = ixLib.configure_ixia_BCAST_traffic_item(BCAST_LEAF_02_to_LEAF_01_dict)

        if BCAST_LEAF_02_to_LEAF_01_TI == 0:
            log.debug("Configuring BCast from LEAF01 to LEAF02 failed")
            self.errored("Configuring BCast from LEAF01 to LEAF02 failed", goto=['next_tc'])


class IXIA_CONFIGURATION_CONFIGURE_UNKNOWN_UCAST_IXIA_TRAFFIC(aetest.Testcase):

    @aetest.setup
    def setup(self):
        pass

    @aetest.test
    def CONFIGURE_UNKNOWN_UCAST_IXIA_TRAFFIC(self, testscript):
        """ IXIA_CONFIGURATION subsection: Configure MCAST Traffic Item """

        IX_TP2 = testscript.parameters['IX_TP2']
        IX_TP3 = testscript.parameters['IX_TP3']

        P1_dict = testscript.parameters['VPC_NODE_TGEN_dict']

        UKNOWN_UCAST_MLAG_BGW_to_LEAF_02_dict = {
                            'src_hndl'      : IX_TP3['port_handle'],
                            'dst_hndl'      : IX_TP2['port_handle'],
                            'TI_name'       : "UKNOWN_UCAST_L1_to_L2",
                            'frame_size'    : "1000",
                            'rate_pps'      : "250000",
                            'dst_mac'       : "00:00:45:00:00:01",
                            'dstmac_step'   : "00:00:00:00:00:01",
                            'dstmac_count'  : "100",
                            'src_mac'       : "00:00:41:00:00:01",
                            'srcmac_step'   : "00:00:00:00:00:01",
                            'srcmac_count'  : "100",
                            'vlan_id'       : P1_dict['vlan_id'],
                            'vlanid_step'   : "1",
                            'vlanid_count'  : P1_dict['no_of_ints'],
                      }

        UKNOWN_UCAST_MLAG_BGW_to_LEAF_02_TI = testscript.parameters['MLAG_BGW_to_LEAF_02_TI'] = ixLib.configure_ixia_UNKNOWN_UCAST_traffic_item(UKNOWN_UCAST_MLAG_BGW_to_LEAF_02_dict)

        if UKNOWN_UCAST_MLAG_BGW_to_LEAF_02_TI == 0:
            log.debug("Configuring UNKNOWN_UCAST TI failed")
            self.errored("Configuring UNKNOWN_UCAST TI failed", goto=['next_tc'])

    @aetest.cleanup
    def cleanup(self):
        pass
        """ testcase clean up """

class IXIA_CONFIGURATION_STOP_START_IXIA_PROTOCOLS(aetest.Testcase):
    """IXIA_CONFIGURATION"""

    @aetest.setup
    def setup(self):
        log.info("Pass testcase setup")

    @aetest.test
    def START_IXIA_PROTOCOLS(self):
        """ IXIA_CONFIGURATION subsection: Configure IXIA IGMP Groups """

        proto_result = ixLib.stop_protocols()
        if proto_result == 0:
            log.debug("Stopped Protocols failed")
            self.errored("Stopped Protocols failed", goto=['next_tc'])
        else:
            log.info("Stopped Protocols Successfully")

        time.sleep(30)

        proto_result = ixLib.start_protocols()
        if proto_result == 0:
            log.debug("Starting Protocols failed")
            self.errored("Starting Protocols failed", goto=['next_tc'])
        else:
            log.info("Started Protocols Successfully")

    @aetest.cleanup
    def cleanup(self):
        """ testcase clean up """
        log.info("Pass testcase cleanup")

# *****************************************************************************************************************************#

class IXIA_CONFIGURATION_APPLY_TRAFFIC(aetest.Testcase):
    """IXIA_CONFIGURATION"""

    @aetest.setup
    def setup(self):
        log.info("Pass testcase setup")

    @aetest.test
    def APPLY_TRAFFIC(self):
        """ IXIA_CONFIGURATION subsection: Verify IXIA Traffic """

        # Apply IXIA Traffic
        if ixLib.apply_traffic() == 1:
            log.info("Applying IXIA TI Passed")
        else:
            self.errored("Applying IXIA TI failed", goto=['next_tc'])

    @aetest.cleanup
    def cleanup(self):
        """ testcase clean up """
        log.info("Pass testcase cleanup")

# *****************************************************************************************************************************#

class IXIA_CONFIGURATION_VERIFY_IXIA_TRAFFIC(aetest.Testcase):
    """IXIA_TRAFFIC_VERIFICATION"""

    @aetest.setup
    def setup(self):
        log.info("Pass testcase setup")

    @aetest.test
    def VERIFY_IXIA_TRAFFIC(self):
        """ IXIA_CONFIGURATION subsection: Verify IXIA Traffic """
        time.sleep(20)

        if ixLib.verify_traffic(2) == 0:
            log.debug("Traffic Verification failed")
            self.failed("Traffic Verification failed", goto=['next_tc'])
        else:
            log.info("Traffic Verification Passed")
            self.passed("Traffic Verification Passed")

class VERIFY_NETWORK_POST_TRAFFIC(aetest.Testcase):
    """VERIFY_NETWORK_POST_TRAFFIC"""

    @aetest.setup
    def setup(self):
        log.info("Pass testcase setup")

    @aetest.test
    def verify_bgp_neighborship(self, testscript):
        """ VERIFY_NETWORK subsection: Verify SPINE BGP Neighborship """

        bgpSessionData = verifyEvpn.verifyEvpnUpLinkBGPSessions(testscript.parameters['forwardingSysDict1'],
                                                                testscript.parameters['leavesDict'])

        if bgpSessionData['result'] is 1:
            log.info("PASS : Successfully verified SPINE BGP Neighborship with Leaf's\n\n")
            self.passed(reason=bgpSessionData['log'])
        else:
            log.info("FAIL : Failed to verify SPINE BGP Neighborship with LEAF's\n\n")
            self.failed(reason=bgpSessionData['log'])

    @aetest.test
    def verify_NVE_peering(self, testscript):
        """ VERIFY_NETWORK subsection: Verify NVE Peering """

        nvePeerData = verifyEvpn.verifyEVPNNvePeers(testscript.parameters['leavesDict'])

        if nvePeerData['result'] is 1:
            log.info("PASS : Successfully verified NVE Peering\n\n")
            self.passed(reason=nvePeerData['log'])
        else:
            log.info("FAIL : Failed to verify NVE Peering\n\n")
            self.failed(reason=nvePeerData['log'])

    @aetest.test
    def verify_VNI(self, testscript):
        """ VERIFY_NETWORK subsection: Verify NVE Peering """

        nveVniData = verifyEvpn.verifyEVPNVNIData(testscript.parameters['forwardingSysDict1'],
                                                  testscript.parameters['leavesDict'])

        if nveVniData['result'] is 1:
            log.info("PASS : Successfully verified NVE VNI Data\n\n")
            self.passed(reason=nveVniData['log'])
        else:
            log.info("FAIL : Failed to verify NVE VNI Data\n\n")
            self.failed(reason=nveVniData['log'])

    @aetest.cleanup
    def cleanup(self):
        """ testcase clean up """
        log.info("Pass testcase cleanup")

class TC001_Bring_up_of_MS_MLAG_Clousec_BGW(aetest.Testcase):
    """TC001_Bring_up_of_MS_MLAG_Clousec_BGW"""

    @aetest.setup
    def setup(self):
        log.info("Pass testcase setup")

        sleep(60)

    @aetest.test
    def Bring_up_of_MS_MLAG_Clousec_BGW(self, testscript):
        """Clod Sec is already configured as  part of the base  config. this test case will verify  the cloud sec tunnel is up or down"""

    @aetest.test
    def post_configure_system_check(self):
        """ VERIFY_NETWORK subsection: Verify NVE Peering """

        status = infraVerify.postTestVerification(post_test_process_dict)
    
    @aetest.test
    def clear_tunnel_encryption_statistics(self, testscript):
        log.info("Clearing the Tunnel Encryption Statistics")
        testscript.parameters['BGW-1'].execute('''clear tunnel-encryption statistics''') 
        testscript.parameters['BGW-2'].execute('''clear tunnel-encryption statistics''') 
    
    @aetest.test
    def VERIFY_IXIA_TRAFFIC(self):
        """ IXIA_CONFIGURATION subsection: Verify IXIA Traffic """

        if ixLib.verify_traffic(2) == 0:
            log.debug("Traffic Verification failed")
            self.failed("Traffic Verification failed")
        else:
            log.info("Traffic Verification Passed")
            self.passed("Traffic Verification Passed")
    
    @aetest.test
    def verify_bgp_neighborship(self, testscript):
        """ VERIFY_NETWORK subsection: Verify SPINE BGP Neighborship """

        bgpSessionData = verifyEvpn.verifyEvpnUpLinkBGPSessions(testscript.parameters['forwardingSysDict1'],
                                                                testscript.parameters['leavesDict'])

        if bgpSessionData['result'] is 1:
            log.info("PASS : Successfully verified SPINE BGP Neighborship with Leaf's\n\n")
            self.passed(reason=bgpSessionData['log'])
        else:
            log.info("FAIL : Failed to verify SPINE BGP Neighborship with LEAF's\n\n")
            self.failed(reason=bgpSessionData['log'])

    @aetest.test
    def verify_NVE_peering(self, testscript):
        """ VERIFY_NETWORK subsection: Verify NVE Peering """

        nvePeerData = verifyEvpn.verifyEVPNNvePeers(testscript.parameters['leavesDict'])

        if nvePeerData['result'] is 1:
            log.info("PASS : Successfully verified NVE Peering\n\n")
            self.passed(reason=nvePeerData['log'])
        else:
            log.info("FAIL : Failed to verify NVE Peering\n\n")
            self.failed(reason=nvePeerData['log'])

    @aetest.test
    def verify_VNI(self, testscript):
        """ VERIFY_NETWORK subsection: Verify NVE Peering """

        nveVniData = verifyEvpn.verifyEVPNVNIData(testscript.parameters['forwardingSysDict1'],
                                                  testscript.parameters['leavesDict'])

        if nveVniData['result'] is 1:
            log.info("PASS : Successfully verified NVE VNI Data\n\n")
            self.passed(reason=nveVniData['log'])
        else:
            log.info("FAIL : Failed to verify NVE VNI Data\n\n")
            self.failed(reason=nveVniData['log'])

    
    @aetest.test
    def verify_CloudSec_tunnel(self, testscript):
        """ VERIFY_NETWORK subsection: Verify CloudSec tunnel status """
        
        log.info(banner("Verfying the cloud sec tunnel state and statistics on BGW-1"))

        output = json.loads(testscript.parameters['BGW-1'].execute('''show tunnel-encryption session detail | json''')) 
        show_tunnel_list = Mlag_Tunnel_Encryption(output)
        peer_address = show_tunnel_list[0]
        rxstatus = show_tunnel_list[1]
        txstatus = show_tunnel_list[2]
        tun_stat = json.loads(testscript.parameters['BGW-1'].execute('''show tunnel-encryption statistics | json''')) 
        
        tun_stat_parse_list = Mlag_Tunnel_Encryption_Statistics(tun_stat)
        peer_address_stat = tun_stat_parse_list[0]
        rx_in_decrypted_pkts = tun_stat_parse_list[1]
        tx_out_encrypted_pkts = tun_stat_parse_list [2]
        
        if (peer_address == '100.0.0.203' and rxstatus == 'Secure (AN: 0)' and txstatus == txstatus and peer_address_stat == '100.0.0.203' and rx_in_decrypted_pkts != 0 and tx_out_encrypted_pkts != 0):
           log.info("PASS: Verfying the cloud sec tunnel on BGW-1")
        else:
           log.info("FAIL: Verfying the cloud sec tunnel on BGW-1")
           self.failed('Verfying the cloud sec tunnel on BGW-1 failed')
        
        log.info(banner("Verfying the cloud sec tunnel state and statistics on BGW-2"))

        output = json.loads(testscript.parameters['BGW-2'].execute('''show tunnel-encryption session detail | json''')) 
        show_tunnel_list = Mlag_Tunnel_Encryption(output)
        peer_address = show_tunnel_list[0]
        rxstatus = show_tunnel_list[1]
        txstatus = show_tunnel_list[2]
        
        tun_stat = json.loads(testscript.parameters['BGW-2'].execute('''show tunnel-encryption statistics | json''')) 
        tun_stat_parse_list = Mlag_Tunnel_Encryption_Statistics(tun_stat)
        peer_address_stat = tun_stat_parse_list[0]
        rx_in_decrypted_pkts = tun_stat_parse_list[1]
        tx_out_encrypted_pkts = tun_stat_parse_list [2]
        
        if (peer_address == '100.0.0.203' and rxstatus == 'Secure (AN: 0)' and txstatus == 'Secure (AN: 0)' and peer_address_stat == '100.0.0.203' and rx_in_decrypted_pkts != 0 and tx_out_encrypted_pkts != 0):
           log.info("PASS: Verfying the cloud sec tunnel on BGW-1")
        else:
           log.info("FAIL: Verfying the cloud sec tunnel on BGW-1")
           self.failed('Verfying the cloud sec tunnel on BGW-1 failed')

        @aetest.cleanup
        def cleanup(self):
            pass
            """ testcase clean up """


class TC002_Delete_And_Re_Add_DCI_Advertise_PIP_Clousec_BGW(aetest.Testcase):
    """TC002_Delete_And_Re_Add_DCI_Advertise_PIP_Clousec_BGW"""

    @aetest.setup
    def setup(self):
        log.info("Pass testcase setup")

        sleep(60)
    
    @aetest.test
    def VERIFY_IXIA_TRAFFIC_BEFORE_TRIGGER(self):
        """ IXIA_CONFIGURATION subsection: Verify IXIA Traffic """
        log.info("Verify traffic before trigger")

        if ixLib.verify_traffic(2) == 0:
            log.debug("Traffic Verification failed")
            self.failed("Traffic Verification failed")
        else:
            log.info("Traffic Verification Passed")
            self.passed("Traffic Verification Passed")

    @aetest.test
    def Delete_And_Re_Add_DCI_Advertise_PIP_Clousec_BGW(self, testscript):
        """Delete_And_Re_Add_DCI_Advertise_PIP_Clousec_BGW"""

        log.info(banner("Deleting dci-advertise-pip on BGW-1"))
        testscript.parameters['BGW-1'].configure('''

              evpn multisite border-gateway 100
              no dci-advertise-pip

          ''')
        time.sleep(100)
        log.info(banner("Adding dci-advertise-pip on BGW-1"))
        testscript.parameters['BGW-1'].configure('''

              evpn multisite border-gateway 100
              dci-advertise-pip

          ''')
        time.sleep(100)
    
    @aetest.test
    def verify_bgp_neighborship(self, testscript):
        """ VERIFY_NETWORK subsection: Verify SPINE BGP Neighborship """

        bgpSessionData = verifyEvpn.verifyEvpnUpLinkBGPSessions(testscript.parameters['forwardingSysDict1'],
                                                                testscript.parameters['leavesDict'])

        if bgpSessionData['result'] is 1:
            log.info("PASS : Successfully verified SPINE BGP Neighborship with Leaf's\n\n")
            self.passed(reason=bgpSessionData['log'])
        else:
            log.info("FAIL : Failed to verify SPINE BGP Neighborship with LEAF's\n\n")
            self.failed(reason=bgpSessionData['log'])

    @aetest.test
    def verify_NVE_peering(self, testscript):
        """ VERIFY_NETWORK subsection: Verify NVE Peering """

        nvePeerData = verifyEvpn.verifyEVPNNvePeers(testscript.parameters['leavesDict'])

        if nvePeerData['result'] is 1:
            log.info("PASS : Successfully verified NVE Peering\n\n")
            self.passed(reason=nvePeerData['log'])
        else:
            log.info("FAIL : Failed to verify NVE Peering\n\n")
            self.failed(reason=nvePeerData['log'])

    @aetest.test
    def verify_VNI(self, testscript):
        """ VERIFY_NETWORK subsection: Verify NVE Peering """

        nveVniData = verifyEvpn.verifyEVPNVNIData(testscript.parameters['forwardingSysDict1'],
                                                  testscript.parameters['leavesDict'])

        if nveVniData['result'] is 1:
            log.info("PASS : Successfully verified NVE VNI Data\n\n")
            self.passed(reason=nveVniData['log'])
        else:
            log.info("FAIL : Failed to verify NVE VNI Data\n\n")
            self.failed(reason=nveVniData['log'])

    @aetest.test
    def clear_tunnel_encryption_statistics(self, testscript):
        log.info("Clearing the Tunnel Encryption Statistics")
        testscript.parameters['BGW-1'].execute('''clear tunnel-encryption statistics''') 
    
    @aetest.test
    def VERIFY_IXIA_TRAFFIC(self):
        """ IXIA_CONFIGURATION subsection: Verify IXIA Traffic """

        if ixLib.verify_traffic(2) == 0:
            log.debug("Traffic Verification failed")
            self.failed("Traffic Verification failed")
        else:
            log.info("Traffic Verification Passed")
            self.passed("Traffic Verification Passed")
    
    @aetest.test
    def post_configure_system_check(self):
        """ VERIFY_NETWORK subsection: Verify NVE Peering """

        status = infraVerify.postTestVerification(post_test_process_dict)
    
    @aetest.test
    def verify_CloudSec_tunnel(self, testscript):
        """ VERIFY_NETWORK subsection: Verify CloudSec tunnel status """
        
        log.info(banner("Verfying the cloud sec tunnel state and statistics on BGW-1"))

        output = json.loads(testscript.parameters['BGW-1'].execute('''show tunnel-encryption session detail | json''')) 
       
        show_tunnel_list = Mlag_Tunnel_Encryption(output)
        peer_address = show_tunnel_list[0]
        rxstatus = show_tunnel_list[1]
        txstatus = show_tunnel_list[2]
       
        tun_stat = json.loads(testscript.parameters['BGW-1'].execute('''show tunnel-encryption statistics | json''')) 
        
        tun_stat_parse_list = Mlag_Tunnel_Encryption_Statistics(tun_stat)
        peer_address_stat = tun_stat_parse_list[0]
        rx_in_decrypted_pkts = tun_stat_parse_list[1]
        tx_out_encrypted_pkts = tun_stat_parse_list [2]
        
        if (peer_address == '100.0.0.203' and rxstatus == 'Secure (AN: 0)' and txstatus == 'Secure (AN: 0)' and peer_address_stat == '100.0.0.203' and rx_in_decrypted_pkts != 0 and tx_out_encrypted_pkts != 0):
            log.info("PASS: Verfying the cloud sec tunnel on BGW-1")
            self.passed('Deleting and Adding dci-advertised-pip on BGW-1 Passed')
        else:
            log.info("FAIL: Verfying the cloud sec tunnel on BGW-1")
            self.failed('Deleting and Adding dci-advertised-pip on BGW-1 Failed')
        @aetest.cleanup
        
        def cleanup(self):
            pass
            """ testcase clean up """


class TC003_Delete_And_Re_Add_L2VNI_On_NVE_Interface(aetest.Testcase):
    """TC003_Delete_And_Re_Add_L2VNI_On_NVE_Interface"""

    @aetest.setup
    def setup(self):
        log.info("Pass testcase setup")

        sleep(60)

    @aetest.test
    def VERIFY_IXIA_TRAFFIC_BEFORE_TRIGGER(self):
        """ IXIA_CONFIGURATION subsection: Verify IXIA Traffic """
        log.info("Verify traffic before trigger")

        if ixLib.verify_traffic(2) == 0:
            log.debug("Traffic Verification failed")
            self.failed("Traffic Verification failed")
        else:
            log.info("Traffic Verification Passed")
            self.passed("Traffic Verification Passed")
    
    @aetest.test
    def Delete_And_Re_Add_L3VNI_On_NVE_Interface(self, testscript):
        """Delete_And_Re_Add_L2VNI_On_NVE_Interface"""

        log.info(banner("Deleting L2 VNI Config on NVE Interface on BGW-2"))
        testscript.parameters['BGW-2'].configure('''
              interface nve1
              no member vni 100101
              no member vni 100102

          ''')
        time.sleep(100)
        log.info(banner("Adding L2 VNI Config on NVE Interface on BGW-2"))
        testscript.parameters['BGW-2'].configure('''
              interface nve1
              member vni 100101
              multisite ingress-replication
              mcast-group 238.0.0.10
              member vni 100102
              multisite ingress-replication
              mcast-group 238.0.0.10

          ''')
        time.sleep(100)
    
    @aetest.test
    def verify_bgp_neighborship(self, testscript):
        """ VERIFY_NETWORK subsection: Verify SPINE BGP Neighborship """

        bgpSessionData = verifyEvpn.verifyEvpnUpLinkBGPSessions(testscript.parameters['forwardingSysDict1'],
                                                                testscript.parameters['leavesDict'])

        if bgpSessionData['result'] is 1:
            log.info("PASS : Successfully verified SPINE BGP Neighborship with Leaf's\n\n")
            self.passed(reason=bgpSessionData['log'])
        else:
            log.info("FAIL : Failed to verify SPINE BGP Neighborship with LEAF's\n\n")
            self.failed(reason=bgpSessionData['log'])

    @aetest.test
    def verify_NVE_peering(self, testscript):
        """ VERIFY_NETWORK subsection: Verify NVE Peering """

        nvePeerData = verifyEvpn.verifyEVPNNvePeers(testscript.parameters['leavesDict'])

        if nvePeerData['result'] is 1:
            log.info("PASS : Successfully verified NVE Peering\n\n")
            self.passed(reason=nvePeerData['log'])
        else:
            log.info("FAIL : Failed to verify NVE Peering\n\n")
            self.failed(reason=nvePeerData['log'])

    @aetest.test
    def verify_VNI(self, testscript):
        """ VERIFY_NETWORK subsection: Verify NVE Peering """

        nveVniData = verifyEvpn.verifyEVPNVNIData(testscript.parameters['forwardingSysDict1'],
                                                  testscript.parameters['leavesDict'])

        if nveVniData['result'] is 1:
            log.info("PASS : Successfully verified NVE VNI Data\n\n")
            self.passed(reason=nveVniData['log'])
        else:
            log.info("FAIL : Failed to verify NVE VNI Data\n\n")
            self.failed(reason=nveVniData['log'])

    @aetest.test
    def clear_tunnel_encryption_statistics(self, testscript):
        log.info("Clearing the Tunnel Encryption Statistics")
        testscript.parameters['BGW-2'].execute('''clear tunnel-encryption statistics''') 
    
    @aetest.test
    def VERIFY_IXIA_TRAFFIC(self):
        """ IXIA_CONFIGURATION subsection: Verify IXIA Traffic """

        if ixLib.verify_traffic(2) == 0:
            log.debug("Traffic Verification failed")
            self.failed("Traffic Verification failed")
        else:
            log.info("Traffic Verification Passed")
            self.passed("Traffic Verification Passed")
    
    @aetest.test
    def post_configure_system_check(self):
        """ VERIFY_NETWORK subsection: Verify NVE Peering """

        status = infraVerify.postTestVerification(post_test_process_dict)
    
    @aetest.test
    def verify_CloudSec_tunnel(self, testscript):
        """ VERIFY_NETWORK subsection: Verify CloudSec tunnel status """
        
        log.info(banner("Verfying the cloud sec tunnel state and statistics on BGW-2"))

        output = json.loads(testscript.parameters['BGW-2'].execute('''show tunnel-encryption session detail | json''')) 
        show_tunnel_list = Mlag_Tunnel_Encryption(output)
        peer_address = show_tunnel_list[0]
        rxstatus = show_tunnel_list[1]
        txstatus = show_tunnel_list[2]
        tun_stat = json.loads(testscript.parameters['BGW-2'].execute('''show tunnel-encryption statistics | json''')) 
        tun_stat_parse_list = Mlag_Tunnel_Encryption_Statistics(tun_stat)
        peer_address_stat = tun_stat_parse_list[0]
        rx_in_decrypted_pkts = tun_stat_parse_list[1]
        tx_out_encrypted_pkts = tun_stat_parse_list [2]
        if (peer_address == '100.0.0.203' and rxstatus == 'Secure (AN: 0)' and txstatus == 'Secure (AN: 0)' and peer_address_stat == '100.0.0.203' and rx_in_decrypted_pkts != 0 and tx_out_encrypted_pkts != 0):
           log.info("Verfying the cloud sec tunnel on BGW-2")
           self.passed('Deleting and Adding L2 VNI On NVE Interaface on BGW-2 Passed')
        else:
           log.info("FAIL: Verfying the cloud sec tunnel on BGW-2")
           self.failed('Deleting and Adding L2 VNI On NVE Interaface on BGW-2 Failed')
        
        @aetest.cleanup
        def cleanup(self):
            pass
            """ testcase clean up """

class TC004_Delete_And_Re_Add_L3VNI_On_NVE_Interface(aetest.Testcase):
    """TC004_Delete_And_Re_Add_L3VNI_On_NVE_Interface"""

    @aetest.setup
    def setup(self):
        log.info("Pass testcase setup")

        sleep(60)
    
    @aetest.test
    def VERIFY_IXIA_TRAFFIC_BEFORE_TRIGGER(self):
        """ IXIA_CONFIGURATION subsection: Verify IXIA Traffic """
        log.info("Verify traffic before trigger")

        if ixLib.verify_traffic(2) == 0:
            log.debug("Traffic Verification failed")
            self.failed("Traffic Verification failed")
        else:
            log.info("Traffic Verification Passed")
            self.passed("Traffic Verification Passed")
    
    @aetest.test
    def Delete_And_Re_Add_L3VNI_On_NVE_Interface(self, testscript):
        """Delete_And_Re_Add_L3VNI_On_NVE_Interface"""

        log.info(banner("Deleting L3 VNI Config on NVE Interface on BGW-2"))
        testscript.parameters['BGW-2'].configure('''
              interface nve1
              no member vni 9002001 associate-vrf
          ''')
        time.sleep(100)
        log.info(banner("Adding L3 VNI Config on NVE Interface on BGW-2"))
        testscript.parameters['BGW-2'].configure('''
              interface nve1
              member vni 9002001 associate-vrf

          ''')
        time.sleep(100)
    
    @aetest.test
    def verify_bgp_neighborship(self, testscript):
        """ VERIFY_NETWORK subsection: Verify SPINE BGP Neighborship """

        bgpSessionData = verifyEvpn.verifyEvpnUpLinkBGPSessions(testscript.parameters['forwardingSysDict1'],
                                                                testscript.parameters['leavesDict'])

        if bgpSessionData['result'] is 1:
            log.info("PASS : Successfully verified SPINE BGP Neighborship with Leaf's\n\n")
            self.passed(reason=bgpSessionData['log'])
        else:
            log.info("FAIL : Failed to verify SPINE BGP Neighborship with LEAF's\n\n")
            self.failed(reason=bgpSessionData['log'])

    @aetest.test
    def verify_NVE_peering(self, testscript):
        """ VERIFY_NETWORK subsection: Verify NVE Peering """

        nvePeerData = verifyEvpn.verifyEVPNNvePeers(testscript.parameters['leavesDict'])

        if nvePeerData['result'] is 1:
            log.info("PASS : Successfully verified NVE Peering\n\n")
            self.passed(reason=nvePeerData['log'])
        else:
            log.info("FAIL : Failed to verify NVE Peering\n\n")
            self.failed(reason=nvePeerData['log'])

    @aetest.test
    def verify_VNI(self, testscript):
        """ VERIFY_NETWORK subsection: Verify NVE Peering """

        nveVniData = verifyEvpn.verifyEVPNVNIData(testscript.parameters['forwardingSysDict1'],
                                                  testscript.parameters['leavesDict'])

        if nveVniData['result'] is 1:
            log.info("PASS : Successfully verified NVE VNI Data\n\n")
            self.passed(reason=nveVniData['log'])
        else:
            log.info("FAIL : Failed to verify NVE VNI Data\n\n")
            self.failed(reason=nveVniData['log'])

    @aetest.test
    def clear_tunnel_encryption_statistics(self, testscript):
        log.info("Clearing the Tunnel Encryption Statistics")
        testscript.parameters['BGW-2'].execute('''clear tunnel-encryption statistics''') 
    
    @aetest.test
    def VERIFY_IXIA_TRAFFIC(self):
        """ IXIA_CONFIGURATION subsection: Verify IXIA Traffic """

        if ixLib.verify_traffic(2) == 0:
            log.debug("Traffic Verification failed")
            self.failed("Traffic Verification failed")
        else:
            log.info("Traffic Verification Passed")
            self.passed("Traffic Verification Passed")
    
    @aetest.test
    def post_configure_system_check(self):
        """ VERIFY_NETWORK subsection: Verify NVE Peering """

        status = infraVerify.postTestVerification(post_test_process_dict)
        log.info(banner("Verfying the cloud sec tunnel state and statistics on BGW-2"))

    @aetest.test
    def verify_CloudSec_tunnel(self, testscript):
        """ VERIFY_NETWORK subsection: Verify CloudSec tunnel status """
        
        output = json.loads(testscript.parameters['BGW-2'].execute('''show tunnel-encryption session detail | json''')) 
        show_tunnel_list = Mlag_Tunnel_Encryption(output)
        peer_address = show_tunnel_list[0]
        rxstatus = show_tunnel_list[1]
        txstatus = show_tunnel_list[2]
        tun_stat = json.loads(testscript.parameters['BGW-2'].execute('''show tunnel-encryption statistics | json''')) 
        tun_stat_parse_list = Mlag_Tunnel_Encryption_Statistics(tun_stat)
        peer_address_stat = tun_stat_parse_list[0]
        rx_in_decrypted_pkts = tun_stat_parse_list[1]
        tx_out_encrypted_pkts = tun_stat_parse_list [2]
        
        if (peer_address == '100.0.0.203' and rxstatus == 'Secure (AN: 0)' and txstatus == 'Secure (AN: 0)' and peer_address_stat == '100.0.0.203' and rx_in_decrypted_pkts != 0 and tx_out_encrypted_pkts != 0):
           log.info("Verfying the cloud sec tunnel on BGW-2")
           self.passed('Deleting and Adding L3 VNI On NVE Interaface on BGW-2 Passed')
        else:
           log.info("FAIL: Verfying the cloud sec tunnel on BGW-2")
           self.failed('Deleting and Adding L3 VNI On NVE Interaface on BGW-2 Failed')

        @aetest.cleanup
        def cleanup(self):
            pass
            """ testcase clean up """


class TC005_Delete_And_Re_Add_Vlan(aetest.Testcase):
    """TC005_Delete_And_Re_Add_Vlan"""

    @aetest.setup
    def setup(self):
        log.info("Pass testcase setup")

        sleep(60)

    @aetest.test
    def VERIFY_IXIA_TRAFFIC_BEFORE_TRIGGER(self):
        """ IXIA_CONFIGURATION subsection: Verify IXIA Traffic """
        log.info("Verify traffic before trigger")

        if ixLib.verify_traffic(2) == 0:
            log.debug("Traffic Verification failed")
            self.failed("Traffic Verification failed")
        else:
            log.info("Traffic Verification Passed")
            self.passed("Traffic Verification Passed")
    
    @aetest.test
    def Delete_And_Re_Add_Vlan(self, testscript):
        """Delete_And_Re_Add_Vlan"""

        log.info(banner("Deleting the L2 VNI Vlan on BGW-1"))
        testscript.parameters['BGW-1'].configure('''
              no vlan 101
              no vlan 102
          ''')
        time.sleep(100)
        log.info(banner("Adding the L2 VNI Vlan on BGW-1"))
        testscript.parameters['BGW-1'].configure('''
              vlan 101
              vn-segment 100101
              vlan 102
              vn-segment 100102
          ''')
        time.sleep(100)
    
    @aetest.test
    def verify_bgp_neighborship(self, testscript):
        """ VERIFY_NETWORK subsection: Verify SPINE BGP Neighborship """

        bgpSessionData = verifyEvpn.verifyEvpnUpLinkBGPSessions(testscript.parameters['forwardingSysDict1'],
                                                                testscript.parameters['leavesDict'])

        if bgpSessionData['result'] is 1:
            log.info("PASS : Successfully verified SPINE BGP Neighborship with Leaf's\n\n")
            self.passed(reason=bgpSessionData['log'])
        else:
            log.info("FAIL : Failed to verify SPINE BGP Neighborship with LEAF's\n\n")
            self.failed(reason=bgpSessionData['log'])

    @aetest.test
    def verify_NVE_peering(self, testscript):
        """ VERIFY_NETWORK subsection: Verify NVE Peering """

        nvePeerData = verifyEvpn.verifyEVPNNvePeers(testscript.parameters['leavesDict'])

        if nvePeerData['result'] is 1:
            log.info("PASS : Successfully verified NVE Peering\n\n")
            self.passed(reason=nvePeerData['log'])
        else:
            log.info("FAIL : Failed to verify NVE Peering\n\n")
            self.failed(reason=nvePeerData['log'])

    @aetest.test
    def verify_VNI(self, testscript):
        """ VERIFY_NETWORK subsection: Verify NVE Peering """

        nveVniData = verifyEvpn.verifyEVPNVNIData(testscript.parameters['forwardingSysDict1'],
                                                  testscript.parameters['leavesDict'])

        if nveVniData['result'] is 1:
            log.info("PASS : Successfully verified NVE VNI Data\n\n")
            self.passed(reason=nveVniData['log'])
        else:
            log.info("FAIL : Failed to verify NVE VNI Data\n\n")
            self.failed(reason=nveVniData['log'])

    @aetest.test
    def clear_tunnel_encryption_statistics(self, testscript):
        log.info("Clearing the Tunnel Encryption Statistics")
        testscript.parameters['BGW-1'].execute('''clear tunnel-encryption statistics''') 
    
    @aetest.test
    def VERIFY_IXIA_TRAFFIC(self):
        """ IXIA_CONFIGURATION subsection: Verify IXIA Traffic """

        if ixLib.verify_traffic(2) == 0:
            log.debug("Traffic Verification failed")
            self.failed("Traffic Verification failed")
        else:
            log.info("Traffic Verification Passed")
            self.passed("Traffic Verification Passed")
    
    @aetest.test
    def post_configure_system_check(self):
        """ VERIFY_NETWORK subsection: Verify NVE Peering """

        status = infraVerify.postTestVerification(post_test_process_dict)
    
    @aetest.test
    def verify_CloudSec_tunnel(self, testscript):
        """ VERIFY_NETWORK subsection: Verify CloudSec tunnel status """
        
        log.info(banner("Verfying the cloud sec tunnel state and statistics on BGW-1"))

        output = json.loads(testscript.parameters['BGW-1'].execute('''show tunnel-encryption session detail | json''')) 
       
        show_tunnel_list = Mlag_Tunnel_Encryption(output)
        peer_address = show_tunnel_list[0]
        rxstatus = show_tunnel_list[1]
        txstatus = show_tunnel_list[2]
        tun_stat = json.loads(testscript.parameters['BGW-1'].execute('''show tunnel-encryption statistics | json''')) 
        
        tun_stat_parse_list = Mlag_Tunnel_Encryption_Statistics(tun_stat)
        peer_address_stat = tun_stat_parse_list[0]
        rx_in_decrypted_pkts = tun_stat_parse_list[1]
        tx_out_encrypted_pkts = tun_stat_parse_list [2]
        
        if (peer_address == '100.0.0.203' and rxstatus == 'Secure (AN: 0)' and txstatus == 'Secure (AN: 0)' and peer_address_stat == '100.0.0.203' and rx_in_decrypted_pkts != 0 and tx_out_encrypted_pkts != 0):
           log.info("Verfying the cloud sec tunnel on BGW-1")
           self.passed('Deleting and Adding L2 VNI VLAN on BGW-1 Passed')
        else:
           log.info("FAIL: Verfying the cloud sec tunnel on BGW-1")
           self.failed('Deleting and Adding L2 VNI VLAN on BGW-1 Failed')

        @aetest.cleanup
        def cleanup(self):
            pass
            """ testcase clean up """


class TC006_Test_BGW_DCI_Isolation_On_MLAG_Cloudsec_BGW(aetest.Testcase):
    """TC006_Test_BGW_DCI_Isolation_On_MLAG_Cloudsec_BGW"""

    @aetest.setup
    def setup(self):
        log.info("Pass testcase setup")

        sleep(60)

    @aetest.test
    def VERIFY_IXIA_TRAFFIC_BEFORE_TRIGGER(self):
        """ IXIA_CONFIGURATION subsection: Verify IXIA Traffic """
        log.info("Verify traffic before trigger")

        if ixLib.verify_traffic(2) == 0:
            log.debug("Traffic Verification failed")
            self.failed("Traffic Verification failed")
        else:
            log.info("Traffic Verification Passed")
            self.passed("Traffic Verification Passed")
    
    @aetest.test
    def Test_BGW_DCI_Isolation_On_MLAG_Cloudsec_BGW(self, testscript):
        """BGW_DCI_Isolation_On_MLAG_Cloudsec_BGW"""
        dci_interface = testscript.parameters['intf_BGW_1_to_DCI_Route_Server_1']

        log.info(banner("Shutting Down the DCI interface on BGW-1"))
        testscript.parameters['BGW-1'].configure('''
              interface ''' +  str(dci_interface) + ''' 
              shutdown
          ''')
        time.sleep(100)
        log.info(banner("Adding the L2 VNI Vlan on BGW-1"))
        log.info(banner("Bringing  back the DCI interface on BGW-1 to no-shut state"))
        testscript.parameters['BGW-1'].configure('''
              interface ''' +  str(dci_interface) + ''' 
              no shutdown
          ''')
        time.sleep(100)
    
    @aetest.test
    def verify_bgp_neighborship(self, testscript):
        """ VERIFY_NETWORK subsection: Verify SPINE BGP Neighborship """

        bgpSessionData = verifyEvpn.verifyEvpnUpLinkBGPSessions(testscript.parameters['forwardingSysDict1'],
                                                                testscript.parameters['leavesDict'])

        if bgpSessionData['result'] is 1:
            log.info("PASS : Successfully verified SPINE BGP Neighborship with Leaf's\n\n")
            self.passed(reason=bgpSessionData['log'])
        else:
            log.info("FAIL : Failed to verify SPINE BGP Neighborship with LEAF's\n\n")
            self.failed(reason=bgpSessionData['log'])

    @aetest.test
    def verify_NVE_peering(self, testscript):
        """ VERIFY_NETWORK subsection: Verify NVE Peering """

        nvePeerData = verifyEvpn.verifyEVPNNvePeers(testscript.parameters['leavesDict'])

        if nvePeerData['result'] is 1:
            log.info("PASS : Successfully verified NVE Peering\n\n")
            self.passed(reason=nvePeerData['log'])
        else:
            log.info("FAIL : Failed to verify NVE Peering\n\n")
            self.failed(reason=nvePeerData['log'])

    @aetest.test
    def verify_VNI(self, testscript):
        """ VERIFY_NETWORK subsection: Verify NVE Peering """

        nveVniData = verifyEvpn.verifyEVPNVNIData(testscript.parameters['forwardingSysDict1'],
                                                  testscript.parameters['leavesDict'])

        if nveVniData['result'] is 1:
            log.info("PASS : Successfully verified NVE VNI Data\n\n")
            self.passed(reason=nveVniData['log'])
        else:
            log.info("FAIL : Failed to verify NVE VNI Data\n\n")
            self.failed(reason=nveVniData['log'])

    @aetest.test
    def clear_tunnel_encryption_statistics(self, testscript):
        log.info("Clearing the Tunnel Encryption Statistics")
        testscript.parameters['BGW-1'].execute('''clear tunnel-encryption statistics''') 
    @aetest.test
    def clear_tunnel_encryption_statistics(self, testscript):
        log.info("Clearing the Tunnel Encryption Statistics")
        testscript.parameters['BGW-1'].execute('''clear tunnel-encryption statistics''') 
    
    @aetest.test
    def VERIFY_IXIA_TRAFFIC(self):
        """ IXIA_CONFIGURATION subsection: Verify IXIA Traffic """

        if ixLib.verify_traffic(2) == 0:
            log.debug("Traffic Verification failed")
            self.failed("Traffic Verification failed")
        else:
            log.info("Traffic Verification Passed")
            self.passed("Traffic Verification Passed")
    
    @aetest.test
    def post_configure_system_check(self):
        """ VERIFY_NETWORK subsection: Verify NVE Peering """

        status = infraVerify.postTestVerification(post_test_process_dict)
    
    @aetest.test
    def verify_CloudSec_tunnel(self, testscript):
        """ VERIFY_NETWORK subsection: Verify CloudSec tunnel status """
        
        log.info(banner("Verfying the cloud sec tunnel state and statistics on BGW-1"))

        output = json.loads(testscript.parameters['BGW-1'].execute('''show tunnel-encryption session detail | json''')) 
       
        show_tunnel_list = Mlag_Tunnel_Encryption(output)
        peer_address = show_tunnel_list[0]
        rxstatus = show_tunnel_list[1]
        txstatus = show_tunnel_list[2]
        tun_stat = json.loads(testscript.parameters['BGW-1'].execute('''show tunnel-encryption statistics | json''')) 
        
        tun_stat_parse_list = Mlag_Tunnel_Encryption_Statistics(tun_stat)
        peer_address_stat = tun_stat_parse_list[0]
        rx_in_decrypted_pkts = tun_stat_parse_list[1]
        tx_out_encrypted_pkts = tun_stat_parse_list [2]
        
        if (peer_address == '100.0.0.203' and rxstatus == 'Secure (AN: 0)' and txstatus == 'Secure (AN: 0)' and peer_address_stat == '100.0.0.203' and rx_in_decrypted_pkts != 0 and tx_out_encrypted_pkts != 0):
           log.info("Verfying the cloud sec tunnel on BGW-1")
           self.passed('DCI Isolation On MLAG Cloudsec BGW-1 Passed')
        else:
           log.info("FAIL: Verfying the cloud sec tunnel on BGW-1")
           self.failed('DCI Isolation On MLAG Cloudsec BGW-1 Failed')
        
        @aetest.cleanup
        def cleanup(self):
            pass
            """ testcase clean up """


class TC007_Verify_BUM_Traffic_Between_MLAG_Cloudsec_VPC_BGW_PO_and_Remote_Site_Leaf(aetest.Testcase):
    """TC007_Verify_BUM_traffic_between_MLAG_Cloudsec_vPC_BGW_PO_and_remote_site_Leaf"""

    @aetest.setup
    def setup(self):
        log.info("Pass testcase setup")

        sleep(60)

    @aetest.test
    def VERIFY_IXIA_TRAFFIC_BEFORE_TRIGGER(self):
        """ IXIA_CONFIGURATION subsection: Verify IXIA Traffic """
        log.info("Verify traffic before trigger")

        if ixLib.verify_traffic(2) == 0:
            log.debug("Traffic Verification failed")
            self.failed("Traffic Verification failed")
        else:
            log.info("Traffic Verification Passed")
            self.passed("Traffic Verification Passed")
    
    @aetest.test
    def clear_tunnel_encryption_statistics(self, testscript):
        log.info("Clearing the Tunnel Encryption Statistics")
        testscript.parameters['BGW-2'].execute('''clear tunnel-encryption statistics''') 
    
    @aetest.test
    def VERIFY_IXIA_TRAFFIC(self):
        """ IXIA_CONFIGURATION subsection: Verify IXIA Traffic """
        log.info("Verify traffic before trigger")

        if ixLib.verify_traffic(2) == 0:
            log.debug("Traffic Verification failed")
            self.failed("Traffic Verification failed")
        else:
            log.info("Traffic Verification Passed")
            self.passed("Traffic Verification Passed")
    
    @aetest.test
    def Verify_BUM_Traffic_Between_MLAG_Cloudsec_VPC_BGW_PO_and_Remote_Site_Leaf(self, testscript):
        """Verify_BUM_Traffic_Between_MLAG_Cloudsec_VPC_BGW_PO_and_Remote_Site_Leaf"""

   
    @aetest.test
    def verify_bgp_neighborship(self, testscript):
        """ VERIFY_NETWORK subsection: Verify SPINE BGP Neighborship """

        bgpSessionData = verifyEvpn.verifyEvpnUpLinkBGPSessions(testscript.parameters['forwardingSysDict1'],
                                                                testscript.parameters['leavesDict'])

        if bgpSessionData['result'] is 1:
            log.info("PASS : Successfully verified SPINE BGP Neighborship with Leaf's\n\n")
            self.passed(reason=bgpSessionData['log'])
        else:
            log.info("FAIL : Failed to verify SPINE BGP Neighborship with LEAF's\n\n")
            self.failed(reason=bgpSessionData['log'])

    @aetest.test
    def verify_NVE_peering(self, testscript):
        """ VERIFY_NETWORK subsection: Verify NVE Peering """

        nvePeerData = verifyEvpn.verifyEVPNNvePeers(testscript.parameters['leavesDict'])

        if nvePeerData['result'] is 1:
            log.info("PASS : Successfully verified NVE Peering\n\n")
            self.passed(reason=nvePeerData['log'])
        else:
            log.info("FAIL : Failed to verify NVE Peering\n\n")
            self.failed(reason=nvePeerData['log'])

    @aetest.test
    def verify_VNI(self, testscript):
        """ VERIFY_NETWORK subsection: Verify NVE Peering """

        nveVniData = verifyEvpn.verifyEVPNVNIData(testscript.parameters['forwardingSysDict1'],
                                                  testscript.parameters['leavesDict'])

        if nveVniData['result'] is 1:
            log.info("PASS : Successfully verified NVE VNI Data\n\n")
            self.passed(reason=nveVniData['log'])
        else:
            log.info("FAIL : Failed to verify NVE VNI Data\n\n")
            self.failed(reason=nveVniData['log'])

    @aetest.test
    def VERIFY_IXIA_BROADCAST_TRAFFIC(self,testscript):
        """ IXIA_CONFIGURATION subsection: Verify IXIA Traffic """

        #ixLib.verify_traffic({'traffic_item_list':[testscript.parameters['BCAST_MLAG_BGW_to_LEAF_02_TI']]})
        traffic_result = ixLib.verify_traffic({'traffic_item_list':[testscript.parameters['BCAST_MLAG_BGW_to_LEAF_02_TI']]})

        if traffic_result['status'] == 1:
            if int(float(traffic_result['individual_TI'][testscript.parameters['BCAST_MLAG_BGW_to_LEAF_02_TI']]['loss_percentage'])) == 0:
                log.info("Traffic Verification for Broadcast Passed : "+str(traffic_result)+"")
        else:
            log.debug("Traffic Verification for Broadcast Failed : "+str(traffic_result)+"")
            self.failed("Traffic Verification for Broadcast Failed")
        
        traffic_result = ixLib.verify_traffic({'traffic_item_list':[testscript.parameters['BCAST_LEAF_02_to_MLAG_BGW_TI']]})

        if traffic_result['status'] == 1:
            if int(float(traffic_result['individual_TI'][testscript.parameters['BCAST_LEAF_02_to_MLAG_BGW_TI']]['loss_percentage'])) == 0:
                log.info("Traffic Verification for Broadcast Passed : "+str(traffic_result)+"")
                self.passed("Traffic Verification for Broadcast Passed : "+str(traffic_result)+"")
        else:
            log.debug("Traffic Verification for Broadcast Failed : "+str(traffic_result)+"")
            self.failed("Traffic Verification for Broadcast Failed")
    
    @aetest.test
    def post_configure_system_check(self):
        """ VERIFY_NETWORK subsection: Verify NVE Peering """

        status = infraVerify.postTestVerification(post_test_process_dict)
    
    @aetest.test
    def verify_CloudSec_tunnel(self, testscript):
        """ VERIFY_NETWORK subsection: Verify CloudSec tunnel status """
        
        log.info(banner("Verfying the cloud sec tunnel state and statistics on BGW-1"))

        output = json.loads(testscript.parameters['BGW-2'].execute('''show tunnel-encryption session detail | json''')) 
       
        show_tunnel_list = Mlag_Tunnel_Encryption(output)
        peer_address = show_tunnel_list[0]
        rxstatus = show_tunnel_list[1]
        txstatus = show_tunnel_list[2]
        tun_stat = json.loads(testscript.parameters['BGW-2'].execute('''show tunnel-encryption statistics | json''')) 
        
        tun_stat_parse_list = Mlag_Tunnel_Encryption_Statistics(tun_stat)
        peer_address_stat = tun_stat_parse_list[0]
        rx_in_decrypted_pkts = tun_stat_parse_list[1]
        tx_out_encrypted_pkts = tun_stat_parse_list [2]
        
        if (peer_address == '100.0.0.203' and rxstatus == 'Secure (AN: 0)' and txstatus == 'Secure (AN: 0)' and peer_address_stat == '100.0.0.203' and tx_out_encrypted_pkts != 0):
           log.info("Verfying the cloud sec tunnel on BGW-2")
           self.passed('Verify_BUM_Traffic_Between_MLAG_Cloudsec_VPC_BGW_PO_and_Remote_Site_Leaf Test Passed ')
        else:
           log.info("FAIL: Verfying the cloud sec tunnel on BGW-2")
           self.failed('Verify_BUM_Traffic_Between_MLAG_Cloudsec_VPC_BGW_PO_and_Remote_Site_Leaf Failed')

        @aetest.cleanup
        def cleanup(self):
            pass
            """ testcase clean up """



class TC008_Verify_Verify_BUM_Traffic_Between_Two_Sites_Leaf(aetest.Testcase):
    """TC008_Verify_Verify_BUM_Traffic_Between_Two_Sites_Leaf"""

    @aetest.setup
    def setup(self):
        log.info("Pass testcase setup")

        sleep(60)

    @aetest.test
    def VERIFY_IXIA_TRAFFIC_BEFORE_TRIGGER(self):
        """ IXIA_CONFIGURATION subsection: Verify IXIA Traffic """
        log.info("Verify traffic before trigger")

        if ixLib.verify_traffic(2) == 0:
            log.debug("Traffic Verification failed")
            self.failed("Traffic Verification failed")
        else:
            log.info("Traffic Verification Passed")
            self.passed("Traffic Verification Passed")
    
    @aetest.test
    def clear_tunnel_encryption_statistics(self, testscript):
        log.info("Clearing the Tunnel Encryption Statistics")
        testscript.parameters['BGW-2'].execute('''clear tunnel-encryption statistics''') 
    
    @aetest.test
    def VERIFY_IXIA_TRAFFIC(self):
        """ IXIA_CONFIGURATION subsection: Verify IXIA Traffic """
        log.info("Verify traffic before trigger")

        if ixLib.verify_traffic(2) == 0:
            log.debug("Traffic Verification failed")
            self.failed("Traffic Verification failed")
        else:
            log.info("Traffic Verification Passed")
            self.passed("Traffic Verification Passed")
    
    @aetest.test
    def Verify_BUM_Traffic_Between_Two_Sites(self, testscript):
        """Verify_BUM_Traffic_Between_MLAG_Cloudsec_VPC_BGW_PO_and_Remote_Site_Leaf"""

   
    @aetest.test
    def verify_bgp_neighborship(self, testscript):
        """ VERIFY_NETWORK subsection: Verify SPINE BGP Neighborship """

        bgpSessionData = verifyEvpn.verifyEvpnUpLinkBGPSessions(testscript.parameters['forwardingSysDict1'],
                                                                testscript.parameters['leavesDict'])

        if bgpSessionData['result'] is 1:
            log.info("PASS : Successfully verified SPINE BGP Neighborship with Leaf's\n\n")
            self.passed(reason=bgpSessionData['log'])
        else:
            log.info("FAIL : Failed to verify SPINE BGP Neighborship with LEAF's\n\n")
            self.failed(reason=bgpSessionData['log'])

    @aetest.test
    def verify_NVE_peering(self, testscript):
        """ VERIFY_NETWORK subsection: Verify NVE Peering """

        nvePeerData = verifyEvpn.verifyEVPNNvePeers(testscript.parameters['leavesDict'])

        if nvePeerData['result'] is 1:
            log.info("PASS : Successfully verified NVE Peering\n\n")
            self.passed(reason=nvePeerData['log'])
        else:
            log.info("FAIL : Failed to verify NVE Peering\n\n")
            self.failed(reason=nvePeerData['log'])

    @aetest.test
    def verify_VNI(self, testscript):
        """ VERIFY_NETWORK subsection: Verify NVE Peering """

        nveVniData = verifyEvpn.verifyEVPNVNIData(testscript.parameters['forwardingSysDict1'],
                                                  testscript.parameters['leavesDict'])

        if nveVniData['result'] is 1:
            log.info("PASS : Successfully verified NVE VNI Data\n\n")
            self.passed(reason=nveVniData['log'])
        else:
            log.info("FAIL : Failed to verify NVE VNI Data\n\n")
            self.failed(reason=nveVniData['log'])

    @aetest.test
    def VERIFY_IXIA_BROADCAST_TRAFFIC(self, testscript):
        """ IXIA_CONFIGURATION subsection: Verify IXIA Traffic """

        
        traffic_result = ixLib.verify_traffic({'traffic_item_list':[testscript.parameters['BCAST_LEAF_02_to_LEAF_01_TI']]})

        if traffic_result['status'] == 1:
            if int(float(traffic_result['individual_TI'][testscript.parameters['BCAST_LEAF_02_to_LEAF_01_TI']]['loss_percentage'])) == 0:
                log.info("Traffic Verification for Broadcast Passed : "+str(traffic_result)+"")
                self.passed("Traffic Verification for Broadcast Passed : "+str(traffic_result)+"")
        else:
            log.debug("Traffic Verification for Broadcast Failed : "+str(traffic_result)+"")
            self.failed("Traffic Verification for Broadcast Failed")
    
    @aetest.test
    def post_configure_system_check(self):
        """ VERIFY_NETWORK subsection: Verify NVE Peering """

        status = infraVerify.postTestVerification(post_test_process_dict)
    
    @aetest.test
    def verify_CloudSec_tunnel(self, testscript):
        """ VERIFY_NETWORK subsection: Verify CloudSec tunnel status """
        
        log.info(banner("Verfying the cloud sec tunnel state and statistics on BGW-1"))

        output = json.loads(testscript.parameters['BGW-2'].execute('''show tunnel-encryption session detail | json''')) 
       
        show_tunnel_list = Mlag_Tunnel_Encryption(output)
        peer_address = show_tunnel_list[0]
        rxstatus = show_tunnel_list[1]
        txstatus = show_tunnel_list[2]
        tun_stat = json.loads(testscript.parameters['BGW-2'].execute('''show tunnel-encryption statistics | json''')) 
        
        tun_stat_parse_list = Mlag_Tunnel_Encryption_Statistics(tun_stat)
        peer_address_stat = tun_stat_parse_list[0]
        rx_in_decrypted_pkts = tun_stat_parse_list[1]
        tx_out_encrypted_pkts = tun_stat_parse_list [2]
        
        if (peer_address == '100.0.0.203' and rxstatus == 'Secure (AN: 0)' and txstatus == 'Secure (AN: 0)' and peer_address_stat == '100.0.0.203' and rx_in_decrypted_pkts != 0 and tx_out_encrypted_pkts != 0):
            log.info("PASS: Verfying the cloud sec tunnel on BGW-2")
            self.passed('Verify BUM Traffic Between Two Sites Leaf Test Passed')
        else:
            log.info("FAIL: Verfying the cloud sec tunnel on BGW-2")
            self.failed('Verify BUM Traffic Between Two Sites Leaf Test Failed')

        @aetest.cleanup
        def cleanup(self):
            pass
            """ testcase clean up """


class TC009_Verify_MLAG_Cloudsec_After_Deleting_Re_Adding_BGP_Config(aetest.Testcase):
    """TC009_Verify_MLAG_Cloudsec_After_Deleting_Re_Adding_BGP_Config"""

    @aetest.setup
    def setup(self):
        log.info("Pass testcase setup")

        sleep(60)

    @aetest.test
    def VERIFY_IXIA_TRAFFIC_BEFORE_TRIGGER(self):
        """ IXIA_CONFIGURATION subsection: Verify IXIA Traffic """
        log.info("Verify traffic before trigger")

        if ixLib.verify_traffic(2) == 0:
            log.debug("Traffic Verification failed")
            self.failed("Traffic Verification failed")
        else:
            log.info("Traffic Verification Passed")
            self.passed("Traffic Verification Passed")
    
    @aetest.test
    def Verify_MLAG_Cloudsec_After_Deleting_Re_Adding_BGP_Config(self, testscript):
        """BGW_DCI_Isolation_On_MLAG_Cloudsec_BGW"""
        hd1 = testscript.parameters['BGW-1']

        #########Configuring BGP###### 
        AS_num = str(testscript.parameters['BGW_1_dict']['BGP_config']['AS_num'])
        router_id = str(testscript.parameters['BGW_1_dict']['BGP_config']['router_id'])
        neighbor_ip_1 = str(testscript.parameters['BGW_1_dict']['BGP_config']['neighbor_ip_1'])
        remote_as_1 = str(testscript.parameters['BGW_1_dict']['BGP_config']['remote_as_1'])
        neighbor_ip_2 = str(testscript.parameters['BGW_1_dict']['BGP_config']['neighbor_ip_2'])
        remote_as_2 = str(testscript.parameters['BGW_1_dict']['BGP_config']['remote_as_2'])
        neighbor_ip_3 = str(testscript.parameters['BGW_1_dict']['BGP_config']['neighbor_ip_3'])
        remote_as_3 = str(testscript.parameters['BGW_1_dict']['BGP_config']['remote_as_3'])
        vrf = str(testscript.parameters['BGW_1_dict']['BGP_config']['vrf'])
        update_source_1 = testscript.parameters['intf_BGW_1_to_DCI_Route_Server_1'] 
        log.info(banner("Deleting the BGP config on BGW-1"))
 
        cfg1 = """
               no router bgp {0}
               """.format(AS_num)
        cfg_out = hd1.configure(cfg1)
        time.sleep(100)
        log.info(banner("Re-Adding the BGP config on BGW-1"))
        cfg1 = """
               route-map NH-UNCHANGED permit 10
               set ip next-hop unchanged
               route-map RMAP-REDIST-DIRECT permit 10
               match tag 54321
               router bgp {0}
               router-id {1}
               timers prefix-peer-timeout 30
               bestpath as-path multipath-relax
               reconnect-interval 1
               maxas-limit 10
               log-neighbor-changes
               address-family ipv4 unicast
               redistribute direct route-map RMAP-REDIST-DIRECT
               maximum-paths 64
               maximum-paths ibgp 64
               default-metric 0
               additional-paths send
               additional-paths receive
               address-family l2vpn evpn
               maximum-paths 64
               additional-paths send
               additional-paths receive
               neighbor {2}
               remote-as {3}
               description ** towrds DCI-Route-Serve **
               update-source {4}
               address-family ipv4 unicast
               soft-reconfiguration inbound always
               neighbor {5}
               remote-as {6}
               description ** towrds BGP-RR-Spine-01**
               update-source loopback1
               address-family ipv4 unicast
               allowas-in 3
               send-community
               send-community extended
               address-family l2vpn evpn
               allowas-in 3
               send-community
               send-community extended
               neighbor {7}
               remote-as {8}
               update-source loopback1
               ebgp-multihop 5
               peer-type fabric-external
               address-family ipv4 unicast
               send-community
               send-community extended
               address-family l2vpn evpn
               send-community
               send-community extended
               rewrite-evpn-rt-asn
               vrf {9}
               address-family ipv4 unicast
               advertise l2vpn evpn
               maximum-paths 64
               maximum-paths ibgp 64
               """.format(AS_num, router_id, neighbor_ip_1, remote_as_1, update_source_1,neighbor_ip_2, remote_as_2, neighbor_ip_3, remote_as_3, vrf)
        cfg_out = hd1.configure(cfg1)
        time.sleep(100)
    
    @aetest.test
    def verify_bgp_neighborship(self, testscript):
        """ VERIFY_NETWORK subsection: Verify SPINE BGP Neighborship """

        bgpSessionData = verifyEvpn.verifyEvpnUpLinkBGPSessions(testscript.parameters['forwardingSysDict1'],
                                                                testscript.parameters['leavesDict'])

        if bgpSessionData['result'] is 1:
            log.info("PASS : Successfully verified SPINE BGP Neighborship with Leaf's\n\n")
            self.passed(reason=bgpSessionData['log'])
        else:
            log.info("FAIL : Failed to verify SPINE BGP Neighborship with LEAF's\n\n")
            self.failed(reason=bgpSessionData['log'])

    @aetest.test
    def verify_NVE_peering(self, testscript):
        """ VERIFY_NETWORK subsection: Verify NVE Peering """

        nvePeerData = verifyEvpn.verifyEVPNNvePeers(testscript.parameters['leavesDict'])

        if nvePeerData['result'] is 1:
            log.info("PASS : Successfully verified NVE Peering\n\n")
            self.passed(reason=nvePeerData['log'])
        else:
            log.info("FAIL : Failed to verify NVE Peering\n\n")
            self.failed(reason=nvePeerData['log'])

    @aetest.test
    def verify_VNI(self, testscript):
        """ VERIFY_NETWORK subsection: Verify NVE Peering """

        nveVniData = verifyEvpn.verifyEVPNVNIData(testscript.parameters['forwardingSysDict1'],
                                                  testscript.parameters['leavesDict'])

        if nveVniData['result'] is 1:
            log.info("PASS : Successfully verified NVE VNI Data\n\n")
            self.passed(reason=nveVniData['log'])
        else:
            log.info("FAIL : Failed to verify NVE VNI Data\n\n")
            self.failed(reason=nveVniData['log'])

    @aetest.test
    def clear_tunnel_encryption_statistics(self, testscript):
        log.info("Clearing the Tunnel Encryption Statistics")
        testscript.parameters['BGW-1'].execute('''clear tunnel-encryption statistics''') 
    
    @aetest.test
    def VERIFY_IXIA_TRAFFIC(self):
        """ IXIA_CONFIGURATION subsection: Verify IXIA Traffic """

        if ixLib.verify_traffic(2) == 0:
            log.debug("Traffic Verification failed")
            self.failed("Traffic Verification failed")
        else:
            log.info("Traffic Verification Passed")
            self.passed("Traffic Verification Passed")
    
    @aetest.test
    def post_configure_system_check(self):
        """ VERIFY_NETWORK subsection: Verify NVE Peering """

        status = infraVerify.postTestVerification(post_test_process_dict)
    
    @aetest.test
    def verify_CloudSec_tunnel(self, testscript):
        """ VERIFY_NETWORK subsection: Verify CloudSec tunnel status """
        
        log.info(banner("Verfying the cloud sec tunnel state and statistics on BGW-1"))

        output = json.loads(testscript.parameters['BGW-1'].execute('''show tunnel-encryption session detail | json''')) 
       
        show_tunnel_list = Mlag_Tunnel_Encryption(output)
        peer_address = show_tunnel_list[0]
        rxstatus = show_tunnel_list[1]
        txstatus = show_tunnel_list[2]
        tun_stat = json.loads(testscript.parameters['BGW-1'].execute('''show tunnel-encryption statistics | json''')) 
        
        tun_stat_parse_list = Mlag_Tunnel_Encryption_Statistics(tun_stat)
        peer_address_stat = tun_stat_parse_list[0]
        rx_in_decrypted_pkts = tun_stat_parse_list[1]
        tx_out_encrypted_pkts = tun_stat_parse_list [2]
        
        if (peer_address == '100.0.0.203' and rxstatus == 'Secure (AN: 0)' and txstatus == 'Secure (AN: 0)' and peer_address_stat == '100.0.0.203' and rx_in_decrypted_pkts != 0 and tx_out_encrypted_pkts != 0):
           log.info("Verfying the cloud sec tunnel on BGW-1")
           self.passed('Deleting and Re-Adding BGP config on BGW-1 Passed')
        else:
           log.info("FAIL: Verfying the cloud sec tunnel on BGW-1")
           self.failed('Deleting and Re-Adding BGP config on BGW-1 Failed')

        @aetest.cleanup
        def cleanup(self):
            pass
            """ testcase clean up """


class TC010_Verify_MLAG_Cloudsec_After_Deleting_Re_Adding_NVE_Interface_Config(aetest.Testcase):
    """TC010_Verify_MLAG_Cloudsec_After_Deleting_Re_Adding_NVE_Interface_Config"""

    @aetest.setup
    def setup(self):
        log.info("Pass testcase setup")

        sleep(60)
    
    @aetest.test
    def VERIFY_IXIA_TRAFFIC_BEFORE_TRIGGER(self):
        """ IXIA_CONFIGURATION subsection: Verify IXIA Traffic """
        log.info("Verify traffic before trigger")

        if ixLib.verify_traffic(2) == 0:
            log.debug("Traffic Verification failed")
            self.failed("Traffic Verification failed")
        else:
            log.info("Traffic Verification Passed")
            self.passed("Traffic Verification Passed")

    @aetest.test
    def Verify_MLAG_Cloudsec_After_Deleting_Re_Adding_NVE_Interface_Config(self, testscript):
        """Deleting_Re_Adding_NVE_Interface_Config"""
        hd1 = testscript.parameters['BGW-1']

        log.info(banner("Deleting the interface NVE config on BGW-1"))
        cfg1 = """
               no interface nve1
               """
        cfg_out = hd1.configure(cfg1)
        time.sleep(100)
        log.info(banner("Re-Adding the NVE interface config on BGW-1"))
        cfg1 = """
               interface nve1
               no shutdown
               host-reachability protocol bgp
               advertise virtual-rmac
               source-interface loopback100
               multisite border-gateway interface loopback200
               member vni 100101
               multisite ingress-replication
               mcast-group 238.0.0.10
               member vni 100102
               multisite ingress-replication
               mcast-group 238.0.0.10
               member vni 9002001 associate-vrf
               """
        cfg_out = hd1.configure(cfg1)
        time.sleep(100)
    
    @aetest.test
    def verify_bgp_neighborship(self, testscript):
        """ VERIFY_NETWORK subsection: Verify SPINE BGP Neighborship """

        bgpSessionData = verifyEvpn.verifyEvpnUpLinkBGPSessions(testscript.parameters['forwardingSysDict1'],
                                                                testscript.parameters['leavesDict'])

        if bgpSessionData['result'] is 1:
            log.info("PASS : Successfully verified SPINE BGP Neighborship with Leaf's\n\n")
            self.passed(reason=bgpSessionData['log'])
        else:
            log.info("FAIL : Failed to verify SPINE BGP Neighborship with LEAF's\n\n")
            self.failed(reason=bgpSessionData['log'])

    @aetest.test
    def verify_NVE_peering(self, testscript):
        """ VERIFY_NETWORK subsection: Verify NVE Peering """

        nvePeerData = verifyEvpn.verifyEVPNNvePeers(testscript.parameters['leavesDict'])

        if nvePeerData['result'] is 1:
            log.info("PASS : Successfully verified NVE Peering\n\n")
            self.passed(reason=nvePeerData['log'])
        else:
            log.info("FAIL : Failed to verify NVE Peering\n\n")
            self.failed(reason=nvePeerData['log'])

    @aetest.test
    def verify_VNI(self, testscript):
        """ VERIFY_NETWORK subsection: Verify NVE Peering """

        nveVniData = verifyEvpn.verifyEVPNVNIData(testscript.parameters['forwardingSysDict1'],
                                                  testscript.parameters['leavesDict'])

        if nveVniData['result'] is 1:
            log.info("PASS : Successfully verified NVE VNI Data\n\n")
            self.passed(reason=nveVniData['log'])
        else:
            log.info("FAIL : Failed to verify NVE VNI Data\n\n")
            self.failed(reason=nveVniData['log'])

    @aetest.test
    def clear_tunnel_encryption_statistics(self, testscript):
        log.info("Clearing the Tunnel Encryption Statistics")
        testscript.parameters['BGW-1'].execute('''clear tunnel-encryption statistics''') 
    
    @aetest.test
    def clear_tunnel_encryption_statistics(self, testscript):
        log.info("Clearing the Tunnel Encryption Statistics")
        testscript.parameters['BGW-1'].execute('''clear tunnel-encryption statistics''') 
    
    @aetest.test
    def VERIFY_IXIA_TRAFFIC(self):
        """ IXIA_CONFIGURATION subsection: Verify IXIA Traffic """

        if ixLib.verify_traffic(2) == 0:
            log.debug("Traffic Verification failed")
            self.failed("Traffic Verification failed")
        else:
            log.info("Traffic Verification Passed")
            self.passed("Traffic Verification Passed")
    
    @aetest.test
    def post_configure_system_check(self):
        """ VERIFY_NETWORK subsection: Verify NVE Peering """

        status = infraVerify.postTestVerification(post_test_process_dict)
    
    @aetest.test
    def verify_CloudSec_tunnel(self, testscript):
        """ VERIFY_NETWORK subsection: Verify CloudSec tunnel status """
        
        log.info(banner("Verfying the cloud sec tunnel state and statistics on BGW-1"))

        output = json.loads(testscript.parameters['BGW-1'].execute('''show tunnel-encryption session detail | json''')) 
       
        show_tunnel_list = Mlag_Tunnel_Encryption(output)
        peer_address = show_tunnel_list[0]
        rxstatus = show_tunnel_list[1]
        txstatus = show_tunnel_list[2]
        tun_stat = json.loads(testscript.parameters['BGW-1'].execute('''show tunnel-encryption statistics | json''')) 
        
        tun_stat_parse_list = Mlag_Tunnel_Encryption_Statistics(tun_stat)
        peer_address_stat = tun_stat_parse_list[0]
        rx_in_decrypted_pkts = tun_stat_parse_list[1]
        tx_out_encrypted_pkts = tun_stat_parse_list [2]
        
        if (peer_address == '100.0.0.203' and rxstatus == 'Secure (AN: 0)' and txstatus == 'Secure (AN: 0)' and peer_address_stat == '100.0.0.203' and rx_in_decrypted_pkts != 0 and tx_out_encrypted_pkts != 0):
           log.info("Verfying the cloud sec tunnel on BGW-1")
           self.passed('Deleting and Re-Adding NVE Interface config on BGW-1 Passed')
        else:
           log.info("FAIL: Verfying the cloud sec tunnel on BGW-1")
           self.failed('Deleting and Re-Adding NVE Interface config on BGW-1 Failed')
        
        @aetest.cleanup
        def cleanup(self):
            pass
            """ testcase clean up """


class TC011_Verify_MLAG_Cloudsec_After_BGP_Shut_No_Shut(aetest.Testcase):
    """TC011_Verify_MLAG_Cloudsec_After_BGP_Shut_No_Shut"""

    @aetest.setup
    def setup(self):
        log.info("Pass testcase setup")

        sleep(60)
    
    @aetest.test
    def VERIFY_IXIA_TRAFFIC_BEFORE_TRIGGER(self):
        """ IXIA_CONFIGURATION subsection: Verify IXIA Traffic """
        log.info("Verify traffic before trigger")

        if ixLib.verify_traffic(2) == 0:
            log.debug("Traffic Verification failed")
            self.failed("Traffic Verification failed")
        else:
            log.info("Traffic Verification Passed")
            self.passed("Traffic Verification Passed")

    @aetest.test
    def Verify_MLAG_Cloudsec_After_BGP_Shut_No_Shut(self, testscript):
        """"""
        hd1 = testscript.parameters['BGW-1']

        #########Configuring BGP###### 
        AS_num = str(testscript.parameters['BGW_1_dict']['BGP_config']['AS_num'])
        log.info(banner("BGP Shutdown on BGW-1"))
        cfg1 = """
               router bgp {0}
               shutdown
               """.format(AS_num)
               
        cfg_out = hd1.configure(cfg1)
        time.sleep(100)
        log.info(banner("BGP No Shutdown on BGW-1"))
        cfg1 = """
               router bgp {0}
               no shutdown
               """.format(AS_num)
        cfg_out = hd1.configure(cfg1)
        time.sleep(180)
    
    @aetest.test
    def verify_bgp_neighborship(self, testscript):
        """ VERIFY_NETWORK subsection: Verify SPINE BGP Neighborship """

        bgpSessionData = verifyEvpn.verifyEvpnUpLinkBGPSessions(testscript.parameters['forwardingSysDict1'],
                                                                testscript.parameters['leavesDict'])

        if bgpSessionData['result'] is 1:
            log.info("PASS : Successfully verified SPINE BGP Neighborship with Leaf's\n\n")
            self.passed(reason=bgpSessionData['log'])
        else:
            log.info("FAIL : Failed to verify SPINE BGP Neighborship with LEAF's\n\n")
            self.failed(reason=bgpSessionData['log'])

    @aetest.test
    def verify_NVE_peering(self, testscript):
        """ VERIFY_NETWORK subsection: Verify NVE Peering """

        nvePeerData = verifyEvpn.verifyEVPNNvePeers(testscript.parameters['leavesDict'])

        if nvePeerData['result'] is 1:
            log.info("PASS : Successfully verified NVE Peering\n\n")
            self.passed(reason=nvePeerData['log'])
        else:
            log.info("FAIL : Failed to verify NVE Peering\n\n")
            self.failed(reason=nvePeerData['log'])

    @aetest.test
    def verify_VNI(self, testscript):
        """ VERIFY_NETWORK subsection: Verify NVE Peering """

        nveVniData = verifyEvpn.verifyEVPNVNIData(testscript.parameters['forwardingSysDict1'],
                                                  testscript.parameters['leavesDict'])

        if nveVniData['result'] is 1:
            log.info("PASS : Successfully verified NVE VNI Data\n\n")
            self.passed(reason=nveVniData['log'])
        else:
            log.info("FAIL : Failed to verify NVE VNI Data\n\n")
            self.failed(reason=nveVniData['log'])

    @aetest.test
    def clear_tunnel_encryption_statistics(self, testscript):
        log.info("Clearing the Tunnel Encryption Statistics")
        testscript.parameters['BGW-1'].execute('''clear tunnel-encryption statistics''') 
    
    @aetest.test
    def VERIFY_IXIA_TRAFFIC(self):
        """ IXIA_CONFIGURATION subsection: Verify IXIA Traffic """

        #result = ixLib.verify_traffic()
        if ixLib.verify_traffic(2) == 0:
            log.debug("Traffic Verification failed")
            self.failed("Traffic Verification failed")
        else:
            log.info("Traffic Verification Passed")
            self.passed("Traffic Verification Passed")
    
    @aetest.test
    def post_configure_system_check(self):
        """ VERIFY_NETWORK subsection: Verify NVE Peering """

        status = infraVerify.postTestVerification(post_test_process_dict)
    
    @aetest.test
    def verify_CloudSec_tunnel(self, testscript):
        """ VERIFY_NETWORK subsection: Verify CloudSec tunnel status """
        
        log.info(banner("Verfying the cloud sec tunnel state and statistics on BGW-1"))

        output = json.loads(testscript.parameters['BGW-1'].execute('''show tunnel-encryption session detail | json''')) 
       
        show_tunnel_list = Mlag_Tunnel_Encryption(output)
        peer_address = show_tunnel_list[0]
        rxstatus = show_tunnel_list[1]
        txstatus = show_tunnel_list[2]
       
       
        tun_stat = json.loads(testscript.parameters['BGW-1'].execute('''show tunnel-encryption statistics | json''')) 
        
        tun_stat_parse_list = Mlag_Tunnel_Encryption_Statistics(tun_stat)
        peer_address_stat = tun_stat_parse_list[0]
        rx_in_decrypted_pkts = tun_stat_parse_list[1]
        tx_out_encrypted_pkts = tun_stat_parse_list [2]
        
        if (peer_address == '100.0.0.203' and rxstatus == 'Secure (AN: 0)' and txstatus == 'Secure (AN: 0)' and peer_address_stat == '100.0.0.203' and rx_in_decrypted_pkts != 0 and tx_out_encrypted_pkts != 0):
           log.info("Verfying the cloud sec tunnel on BGW-1")
           self.passed('Verify MLAG Cloudsec After BGP Shut No Shut Test Passed')
        else:
           log.info("FAIL: Verfying the cloud sec tunnel on BGW-1")
           self.failed('Verify MLAG Cloudsec After BGP Shut No Shut Test Failed')
        
        @aetest.cleanup
        def cleanup(self):
            pass
            """ testcase clean up """


class TC012_Verify_MLAG_Cloudsec_After_NVE_Process_Restart_On_VPC_BGW(aetest.Testcase):
    """TC012_Verify_MLAG_Cloudsec_After_NVE_Process_Restart_On_VPC_BGW"""

    @aetest.setup
    def setup(self):
        log.info("Pass testcase setup")

        sleep(60)

    @aetest.test
    def VERIFY_IXIA_TRAFFIC_BEFORE_TRIGGER(self):
        """ IXIA_CONFIGURATION subsection: Verify IXIA Traffic """
        log.info("Verify traffic before trigger")

        if ixLib.verify_traffic(2) == 0:
            log.debug("Traffic Verification failed")
            self.failed("Traffic Verification failed")
        else:
            log.info("Traffic Verification Passed")
            self.passed("Traffic Verification Passed")
    
    @aetest.test
    def Verify_MLAG_Cloudsec_After_NVE_Process_Restart_On_VPC_BGW(self, testscript):
        """"""
        BGW_1 = testscript.parameters['BGW-1']

        #########Configuring BGP###### 
        AS_num = str(testscript.parameters['BGW_1_dict']['BGP_config']['AS_num'])
        log.info(banner("NVE Process Restart on BGW-1"))
        
        if infraTrig.verifyProcessRestart(BGW_1,"nve"):
            log.info("Successfully restarted process NVE")
        else:
            log.debug("Failed to restarted process NVE")
            self.failed("Failed to restarted process NVE", goto=['cleanup'])

        time.sleep(120) 
   
 
    @aetest.test
    def verify_bgp_neighborship(self, testscript):
        """ VERIFY_NETWORK subsection: Verify SPINE BGP Neighborship """

        bgpSessionData = verifyEvpn.verifyEvpnUpLinkBGPSessions(testscript.parameters['forwardingSysDict1'],
                                                                testscript.parameters['leavesDict'])

        if bgpSessionData['result'] is 1:
            log.info("PASS : Successfully verified SPINE BGP Neighborship with Leaf's\n\n")
            self.passed(reason=bgpSessionData['log'])
        else:
            log.info("FAIL : Failed to verify SPINE BGP Neighborship with LEAF's\n\n")
            self.failed(reason=bgpSessionData['log'])

    @aetest.test
    def verify_NVE_peering(self, testscript):
        """ VERIFY_NETWORK subsection: Verify NVE Peering """

        nvePeerData = verifyEvpn.verifyEVPNNvePeers(testscript.parameters['leavesDict'])

        if nvePeerData['result'] is 1:
            log.info("PASS : Successfully verified NVE Peering\n\n")
            self.passed(reason=nvePeerData['log'])
        else:
            log.info("FAIL : Failed to verify NVE Peering\n\n")
            self.failed(reason=nvePeerData['log'])

    @aetest.test
    def verify_VNI(self, testscript):
        """ VERIFY_NETWORK subsection: Verify NVE Peering """

        nveVniData = verifyEvpn.verifyEVPNVNIData(testscript.parameters['forwardingSysDict1'],
                                                  testscript.parameters['leavesDict'])

        if nveVniData['result'] is 1:
            log.info("PASS : Successfully verified NVE VNI Data\n\n")
            self.passed(reason=nveVniData['log'])
        else:
            log.info("FAIL : Failed to verify NVE VNI Data\n\n")
            self.failed(reason=nveVniData['log'])

    
    @aetest.test
    def clear_tunnel_encryption_statistics(self, testscript):
        log.info("Clearing the Tunnel Encryption Statistics")
        testscript.parameters['BGW-1'].execute('''clear tunnel-encryption statistics''') 
   
    @aetest.test
    def VERIFY_IXIA_TRAFFIC(self):
        """ IXIA_CONFIGURATION subsection: Verify IXIA Traffic """

        if ixLib.verify_traffic(2) == 0:
            log.debug("Traffic Verification failed")
            self.failed("Traffic Verification failed")
        else:
            log.info("Traffic Verification Passed")
            self.passed("Traffic Verification Passed")
    
    @aetest.test
    def post_configure_system_check(self):
        """ VERIFY_NETWORK subsection: Verify NVE Peering """

        status = infraVerify.postTestVerification(post_test_process_dict)
    
    @aetest.test
    def verify_CloudSec_tunnel(self, testscript):
        """ VERIFY_NETWORK subsection: Verify CloudSec tunnel status """
        
        log.info(banner("Verfying the cloud sec tunnel state and statistics on BGW-1"))

        output = json.loads(testscript.parameters['BGW-1'].execute('''show tunnel-encryption session detail | json''')) 
       
        show_tunnel_list = Mlag_Tunnel_Encryption(output)
        peer_address = show_tunnel_list[0]
        rxstatus = show_tunnel_list[1]
        txstatus = show_tunnel_list[2]
        tun_stat = json.loads(testscript.parameters['BGW-1'].execute('''show tunnel-encryption statistics | json''')) 
        
        tun_stat_parse_list = Mlag_Tunnel_Encryption_Statistics(tun_stat)
        peer_address_stat = tun_stat_parse_list[0]
        rx_in_decrypted_pkts = tun_stat_parse_list[1]
        tx_out_encrypted_pkts = tun_stat_parse_list [2]
        
        if (peer_address == '100.0.0.203' and rxstatus == 'Secure (AN: 0)' and txstatus == 'Secure (AN: 0)' and peer_address_stat == '100.0.0.203' and rx_in_decrypted_pkts != 0 and tx_out_encrypted_pkts != 0):
           log.info("Verfying the cloud sec tunnel on BGW-1")
           self.passed('Verify MLAG Cloudsec After NVE Process Restart On VPC BGW Test Passed')
        else:
           log.info("FAIL: Verfying the cloud sec tunnel on BGW-1")
           self.failed('Verify MLAG Cloudsec After NVE Process Restart On VPC BGW Test Failed')

    @aetest.cleanup
    def cleanup(self):
        pass
        """ testcase clean up """


class TC013_Verify_MLAG_Cloudsec_After_VPC_BGW_Node_Reload(aetest.Testcase):
    """TC013_Verify_MLAG_Cloudsec_After_VPC_BGW_Node_Reload"""

    @aetest.setup
    def setup(self):
        log.info("Pass testcase setup")

        sleep(60)

    @aetest.test
    def VERIFY_IXIA_TRAFFIC_BEFORE_TRIGGER(self):
        """ IXIA_CONFIGURATION subsection: Verify IXIA Traffic """
        log.info("Verify traffic before trigger")

        if ixLib.verify_traffic(2) == 0:
            log.debug("Traffic Verification failed")
            self.failed("Traffic Verification failed")
        else:
            log.info("Traffic Verification Passed")
            self.passed("Traffic Verification Passed")
    
    @aetest.test
    def Verify_MLAG_Cloudsec_After_VPC_BGW_Node_Reload(self, testscript):
        """Verify_MLAG_Cloudsec_After_VPC_BGW_Node_Reload"""
        testscript.parameters['BGW-1'].execute('copy r s',timeout=120)
        testscript.parameters['BGW-1'].reload(timeout=1200)
        time.sleep(350)
    
    @aetest.test
    def verify_bgp_neighborship(self, testscript):
        """ VERIFY_NETWORK subsection: Verify SPINE BGP Neighborship """

        bgpSessionData = verifyEvpn.verifyEvpnUpLinkBGPSessions(testscript.parameters['forwardingSysDict1'],
                                                                testscript.parameters['leavesDict'])

        if bgpSessionData['result'] is 1:
            log.info("PASS : Successfully verified SPINE BGP Neighborship with Leaf's\n\n")
            self.passed(reason=bgpSessionData['log'])
        else:
            log.info("FAIL : Failed to verify SPINE BGP Neighborship with LEAF's\n\n")
            self.failed(reason=bgpSessionData['log'])

    @aetest.test
    def verify_NVE_peering(self, testscript):
        """ VERIFY_NETWORK subsection: Verify NVE Peering """

        nvePeerData = verifyEvpn.verifyEVPNNvePeers(testscript.parameters['leavesDict'])

        if nvePeerData['result'] is 1:
            log.info("PASS : Successfully verified NVE Peering\n\n")
            self.passed(reason=nvePeerData['log'])
        else:
            log.info("FAIL : Failed to verify NVE Peering\n\n")
            self.failed(reason=nvePeerData['log'])

    @aetest.test
    def verify_VNI(self, testscript):
        """ VERIFY_NETWORK subsection: Verify NVE Peering """

        nveVniData = verifyEvpn.verifyEVPNVNIData(testscript.parameters['forwardingSysDict1'],
                                                  testscript.parameters['leavesDict'])

        if nveVniData['result'] is 1:
            log.info("PASS : Successfully verified NVE VNI Data\n\n")
            self.passed(reason=nveVniData['log'])
        else:
            log.info("FAIL : Failed to verify NVE VNI Data\n\n")
            self.failed(reason=nveVniData['log'])

    
    @aetest.test
    def clear_tunnel_encryption_statistics(self, testscript):
        log.info("Clearing the Tunnel Encryption Statistics")
        testscript.parameters['BGW-1'].execute('''clear tunnel-encryption statistics''') 
    
    @aetest.test
    def VERIFY_IXIA_TRAFFIC(self):
        """ IXIA_CONFIGURATION subsection: Verify IXIA Traffic """

        if ixLib.verify_traffic(2) == 0:
            log.debug("Traffic Verification failed")
            self.failed("Traffic Verification failed")
        else:
            log.info("Traffic Verification Passed")
            self.passed("Traffic Verification Passed")
    
    @aetest.test
    def post_configure_system_check(self):
        """ VERIFY_NETWORK subsection: Verify NVE Peering """

        status = infraVerify.postTestVerification(post_test_process_dict)
    
    @aetest.test
    def verify_CloudSec_tunnel(self, testscript):
        """ VERIFY_NETWORK subsection: Verify CloudSec tunnel status """
        
        log.info(banner("Verfying the cloud sec tunnel state and statistics on BGW-1"))

        output = json.loads(testscript.parameters['BGW-1'].execute('''show tunnel-encryption session detail | json''')) 
       
        show_tunnel_list = Mlag_Tunnel_Encryption(output)
        peer_address = show_tunnel_list[0]
        rxstatus = show_tunnel_list[1]
        txstatus = show_tunnel_list[2]
       
       
        tun_stat = json.loads(testscript.parameters['BGW-1'].execute('''show tunnel-encryption statistics | json''')) 
        
        tun_stat_parse_list = Mlag_Tunnel_Encryption_Statistics(tun_stat)
        peer_address_stat = tun_stat_parse_list[0]
        rx_in_decrypted_pkts = tun_stat_parse_list[1]
        tx_out_encrypted_pkts = tun_stat_parse_list [2]
        
        if (peer_address == '100.0.0.203' and rxstatus == 'Secure (AN: 0)' and txstatus == 'Secure (AN: 0)' and peer_address_stat == '100.0.0.203' and rx_in_decrypted_pkts != 0 and tx_out_encrypted_pkts != 0):
           log.info("Verfying the cloud sec tunnel on BGW-1")
           self.passed(' Verify MLAG Cloudsec After VPC BGW Node Reload Test Passed')
        else:
           log.info("FAIL: Verfying the cloud sec tunnel on BGW-1")
           self.failed('Verify MLAG Cloudsec After VPC BGW Node Reload Test Failed')

        @aetest.cleanup
        def cleanup(self):
            pass
            """ testcase clean up """


if __name__ == '__main__':  # pragma: no cover
    aetest.main()

