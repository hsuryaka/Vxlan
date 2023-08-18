#!/usr/bin/env python

###################################################################
###                  Importing Libraries                        ###
###################################################################
import logging
import time
import yaml
import ipaddress as ip
from yaml import Loader
from pyats import aetest
from pyats.log.utils import banner
import re
import infra_lib
infraVerify = infra_lib.infraVerify()

log = logging.getLogger(__name__)
log.setLevel(logging.DEBUG)

#
#from unicon import Connection
#import Connection as Connection
#import connection as connection
import pyats.connections as connections
import util as util
#from unicon.eal.dialogs import Statement, Dialog
from csccon import set_ha_platform
from csccon import set_csccon_default
import sys
#import csccon
#import lib.common.version as version
# if version.pyats_version_info() >= (3, 0, 0):
#     from csccon.functions import add_state_pattern
# else:
#     from ats.connections.csccon.functions import add_state_pattern




import unicon.statemachine.statemachine
from unicon.eal.dialogs import Statement, Dialog

tcl_dependencies = [
 '/auto/dc3-india/script_repository/IXIA_9.00_64bit//lib/PythonApi',
 '/auto/dc3-india/script_repository/IXIA_9.00_64bit//lib/TclApi/IxTclProtocol',
 '/auto/dc3-india/script_repository/IXIA_9.00_64bit//lib/TclApi/IxTclNetwork'
 ]
from ixiatcl import IxiaTcl 
from ixiahlt import IxiaHlt
from ixiangpf import IxiaNgpf
from ixiaerror import IxiaError

ixiatcl = IxiaTcl(tcl_autopath=tcl_dependencies)#
#ixiatcl = IxiaTcl()
ixiahlt = IxiaHlt(ixiatcl)
ixiangpf = IxiaNgpf(ixiahlt)
# ------------------------------------------------------
# Import and initialize EVPN specific libraries
# ------------------------------------------------------
import vxlanEVPN_FNL_lib
evpnLib     = vxlanEVPN_FNL_lib.configure39KVxlanEvpn()
verifyEvpn  = vxlanEVPN_FNL_lib.verifyEVPNconfiguration()

# ------------------------------------------------------
# Import and initialize IXIA specific libraries
# ------------------------------------------------------
import ixiaPyats_absr_lib
ixLib = ixiaPyats_absr_lib.ixiaPyats_lib()


# ------------------------------------------------------
# Import and initialize INFRA specific libraries
# ------------------------------------------------------
import infra_lib
infraTrig = infra_lib.infraTrigger()
infraConfig = infra_lib.infraConfigure()
infraVerify = infra_lib.infraVerify()
import lib.nxos.vdc as vdc

#-------------------------------------------------------
#Import tcam libraries
#-------------------------------------------------------
#import tcam_lib
# ------------------------------------------------------
# Import and initialize NIA specific libraries
# ------------------------------------------------------
#import vxlanNIA_lib
#niaLib = vxlanNIA_lib.verifyVxlanNIA()

###Declare global variables
#global stream_id
stream_id = ''
stream_id_2 = ''
break_port_cfg = ''
###################################################################
###                  User Library Methods                       ###
###################################################################
import pdb
class ForkedPdb(pdb.Pdb):
    '''A Pdb subclass that may be used
    from a forked multiprocessing child
    '''
    def interaction(self, *args, **kwargs):
        _stdin = sys.stdin
        try:
            sys.stdin = open('/dev/stdin')
            pdb.Pdb.interaction(self, *args, **kwargs)
        finally:
            sys.stdin = _stdin
            
            
def increment_prefix_network(pref, count):
    size = 1 << (pref.network.max_prefixlen - pref.network.prefixlen)
    pref_lst = []
    for i in range(count):
        pref_lst.append(str((pref.ip+size*i)) + "/" + str(pref.network.prefixlen))
    return pref_lst

def increment_v4_vip(pref,count):
    #size = 1 << (pref.network.max_prefixlen - pref.network.prefixlen)
    pref_lst = []
    lst1=pref.split(".")
    for i in range(count):
        
        print(lst1)
        if i != 0:
            third=int(lst1[2])
            third+=1
            lst1[2]=str(third)
        #print(lst1)
        pref_lst.append('.'.join(lst1))
    return pref_lst
    
def increment_v6_vip(pref,count):
    v6=ip.ip_address(pref).exploded
    #size = 1 << (pref.network.max_prefixlen - pref.network.prefixlen)
    pref_lst = []
    lst1=v6.split(":")
    for i in range(count):
#print(v6.exploded)
        
        #print(lst1)
        if i!=0:
            fourth=int(lst1[2],16)
            fourth+=1
            lst1[3]=hex(fourth)[2:]
        #print(lst1)
        pref_lst.append(':'.join(lst1))
    return pref_lst

def verifyDevicePingsForIxiaTraffic(testscript):

    forwardingSysDict = testscript.parameters['forwardingSysDict']
    vrf_id = forwardingSysDict['VRF_id_start']
    l2_vlan_ipv4_start =  testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vlan_ipv4_start']
    l2_vlan_ipv4_mask = testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vlan_ipv4_mask']

    # ----------------------------------------------------
    # LEAF-1 Counter Variables
    # ----------------------------------------------------
    l3_vrf_count_iter = 0
    l2_vlan_count_iter = 0
    ip_index = 0

    total_ip_count = int(forwardingSysDict['VLAN_PER_VRF_count']) * int(forwardingSysDict['VRF_count'])
    l2_ipv4s = increment_prefix_network(ip.IPv4Interface(str(l2_vlan_ipv4_start) + str(l2_vlan_ipv4_mask)),total_ip_count)

    while l3_vrf_count_iter < forwardingSysDict['VRF_count']:
        while l2_vlan_count_iter < forwardingSysDict['VLAN_PER_VRF_count']:

            testscript.parameters['LEAF-1'].configure('''ping '''+str(l2_ipv4s[ip_index])+''' vrf '''+'EVPN-VRF-'+str(vrf_id))
            testscript.parameters['LEAF-2'].configure('''ping '''+str(l2_ipv4s[ip_index])+''' vrf '''+'EVPN-VRF-'+str(vrf_id))
            testscript.parameters['LEAF-3'].configure('''ping '''+str(l2_ipv4s[ip_index])+''' vrf '''+'EVPN-VRF-'+str(vrf_id))

            l2_vlan_count_iter += 1
        l3_vrf_count_iter += 1
        vrf_id += 1

def verify_dscp(output,dscp,dscpcode):
    m=re.search('.*DSCP\s(0x[0-9a-z]+)*',output)
    if m:
            if m.group(1)==dscp:
                log.info("traffic has valid dscp. Test passed.")
                return 1
            
    else:
            n=re.search('.*DSCP:\s([A-Z]+[0-9]+|[A-Z]+)',output)
            #hexcode=dscp_code_mapping[str(P1_dict['ip_dscp'])]
            if n:
                     log.info("match found")
                     if n.group(1)==dscpcode:
                         log.info("traffic has valid dscp. Test passed.")
                         return 1
    return 0

def create_and_configure_new_vdc(device, vdc_info):

    eth_re = re.compile("([A-Za-z]+\s*)(\d{1,2})/(\d{1,2})/(\d{1})")
    cfg = []
    cfg1 = 'vdc %s\n' % (vdc_info['name'])
    intfs = map(vdc.to_interface_name, vdc_info['interfaces'])
    intf_names = list()
    module = {}
    break_port_cfg = ""
    #ForkedPdb().set_trace()
    if intfs:
        for intf in intfs:
            m = eth_re.match(intf)
            log.info('m is:'+str(m))
            if m:
                intf = m.group(1) + m.group(2) +"/" + m.group(3)
                if m.group(2) not in module.keys():
                    module[m.group(2)] = []
                if m.group(3) not in module[m.group(2)]:
                    module[m.group(2)].append(m.group(3))
                print(module)
                #ForkedPdb().set_trace()
                log.info('module: '+ str(module))
            intf_names.append(intf)
        log.info('intf_names: '+str(intf_names))
        #if len(intf_names) > 8:
        #    intf_names = vdc.club_interfaces(list(set(intf_names)))
        for tmp_mod in module.keys() :
            port_list = (','.join(module[tmp_mod]))
            print("interface breakout module %s port %s map 10g-4x\n" % (tmp_mod, port_list))
            log.info("interface breakout module %s port %s map 10g-4x\n" % (tmp_mod, port_list))
            break_port_cfg = break_port_cfg + "interface breakout module %s port %s map 10g-4x\n" % (tmp_mod, port_list)
        cfg2 = 'allocate interface %s\n' % (','.join(set(intf_names)))
        cfg += [cfg1] + vdc_info['config-lines'] + [cfg2]
    else:
        cfg += [cfg1] + vdc_info['config-lines']
    log.info('cfg='+str(cfg))

    dialog = Dialog([
        Statement(pattern=r'Continue \(y/n\)\? \[yes\] ',
                  action='sendline(yes)',
                  loop_continue=True,
                  continue_timer=True),
        Statement(pattern=r'module type now \(y\/n\)\? \[no\]',
                  action='sendline(y)',
                  loop_continue=True,
                  continue_timer=True),
        Statement(pattern=r'interfaces\" now \(y\/n\)\? \[no\]',
                  action='sendline(y)',
                  loop_continue=True,
                  continue_timer=True),
        Statement(pattern=r'ports \(y/n\)\?  \[yes\] ',
                  action='sendline(yes)',
                  loop_continue=True,
                  continue_timer=True),
    ])

    #try:
    vdc.version.configure(device, cfg, reply=dialog, timeout=1200)
    if module:
        log.info('break_port_cfg: '+ str(break_port_cfg))
        return break_port_cfg
    else:
        break_port_cfg = 0
        return break_port_cfg
    #if module:
    #    log.info(break_port_cfg)
    #    ForkedPdb().set_trace()
    #    vdc_conn = vdc.connect(device, vdc_info['name'], 'alt',vdc_info['name'])
    #    log.info("Connected to Vdc ")
    #    vdc_conn.config(break_port_cfg)
    #    vdc_conn.disconnect()
    #except:
    #    msg = 'Failed to create VDC.  Invalid CLI given: %s' % (cfg)
    #    log.error(msg)
    #    log.error(sys.exc_info())
    #    raise
    
def connect_to_vdc(device, vdc_name):

   # # switching to correct VDC via management
   # #device.connect(via='alt', alias='alt')
   # log.info("===> switching to vdc")
   # #ForkedPdb().set_trace()
   # #device.execute("switchback",timeout=120)
   # device.disconnect()
   # #ForkedPdb().set_trace()
   # device.switchto(vdc_name, timeout=120)
   # #device.execute('switchto vdc ' + vdc_name)
   # output=device.execute("show vdc current-vdc")
   # m=re.search('.*- (.*)',output)
   # #device_handle=device.alt
   # if m:
   #     if m.group(1)==vdc_name:
   #         log.info("returning True")
   #         print("return True")
   #         return device
   #     else:
   #         log.info("returning False")
   #         print("return False")
   #         return False
        
        
    #leaf1 = testbed.devices[uut_list['xbow1']]
        #ForkedPdb().set_trace()
    device.connect(via='alt', alias='alt')
    device = device.alt
    log.info("===> switching to vdc")
    device.switchto(vdc_name, timeout=120)
    output=device.execute("show vdc current-vdc")
    m=re.search('.*- (.*)',output)
    #device_handle=device.alt
    if m:
        if m.group(1)==vdc_name:
            log.info("returning True")
            print("return True")
            return device
        else:
            log.info("returning False")
            print("return False")
            return False
    
    #testscript.parameters[vdc_name] = device
###################################################################
###                  GLOBAL VARIABLES                           ###
###################################################################

device_list     = []

###################################################################
###                  COMMON SETUP SECTION                       ###
###################################################################

# Configure and setup all devices and test equipment in this section.
# This should represent the BASE CONFIGURATION that is applicable
# for the bunch of test cases that would follow.

class COMMON_SETUP(aetest.CommonSetup):
    """ Common Setup """

    @aetest.subsection
    def connecting_to_devices(self, testscript, testbed, uut_list, configurationFile, script_flags=None):
        """ common setup subsection: Connecting to devices """

        # =============================================================================================================================#
        # Grab the device object of the uut device with that name
        if script_flags is None:
            script_flags = {}
        SPINE = testscript.parameters['SPINE'] = testbed.devices[uut_list['SPINE']]

        LEAF_1 = testscript.parameters['LEAF-1'] = testbed.devices[uut_list['LEAF-1']]
        LEAF_2 = testscript.parameters['LEAF-2'] = testbed.devices[uut_list['LEAF-2']]
        LEAF_3 = testscript.parameters['LEAF-3'] = testbed.devices[uut_list['LEAF-3']]
        xbow1  = testscript.parameters['xbow1'] = testbed.devices[uut_list['xbow1']]
        xbow2  = testscript.parameters['xbow2'] = testbed.devices[uut_list['xbow2']]
        xbow3  = testscript.parameters['xbow3'] = testbed.devices[uut_list['xbow3']]
        
        FO_1  = testscript.parameters['FO_1'] = testbed.devices[uut_list['FO_1']]

        FAN_1 = testscript.parameters['FAN-1'] = testbed.devices[uut_list['FAN-1']]
        #FAN_2 = testscript.parameters['FAN-2'] = testbed.devices[uut_list['FAN-2']]

        IXIA = testscript.parameters['IXIA'] = testbed.devices[uut_list['ixia']]
        

        testscript.parameters['ixia_chassis_ip'] = str(IXIA.connections.a.ip)
        testscript.parameters['ixia_tcl_server'] = str(IXIA.connections.alt.ip)
        testscript.parameters['ixia_tcl_port'] = str(IXIA.connections.alt.port)

        # =============================================================================================================================#
        # Connect to the device
        SPINE.connect()
        LEAF_1.connect()
        LEAF_2.connect()
        LEAF_3.connect()
        FAN_1.connect()
        #FAN_2.connect()
        xbow1.connect()
        xbow2.connect()
        xbow3.connect()
        FO_1.connect()

        device_list.append(SPINE)
        device_list.append(LEAF_1)
        device_list.append(LEAF_2)
        device_list.append(LEAF_3)
        device_list.append(FAN_1)
        #device_list.append(FAN_2)
        device_list.append(xbow1)
        device_list.append(xbow2)
        device_list.append(xbow3)
        device_list.append(FO_1)

        # =============================================================================================================================#
        # Make sure that the connection went fine

        for dut in device_list:
            if not hasattr(dut, 'execute'):
                self.failed()

            if dut.execute != dut.connectionmgr.default.execute:
                self.failed()

        # =============================================================================================================================#
        # Import script_flags into testscript.parameters
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

        # =============================================================================================================================#
        # Import Configuration File and create required Structures

        with open(configurationFile) as cfgFile:
            configuration = yaml.load(cfgFile, Loader=Loader)

        testscript.parameters['LEAF_1_dict']            = configuration['LEAF_1_dict']
        testscript.parameters['LEAF_2_dict']            = configuration['LEAF_2_dict']
        testscript.parameters['LEAF_3_dict']            = configuration['LEAF_3_dict']
        testscript.parameters['N7K_LEAF_1_dict']            = configuration['N7K_LEAF_1_dict']
        testscript.parameters['N7K_LEAF_2_dict']            = configuration['N7K_LEAF_2_dict']
        testscript.parameters['SPINE_1_dict']            = configuration['SPINE_1_dict']
        testscript.parameters['forwardingSysDict']      = configuration['FWD_SYS_dict']

        testscript.parameters['LEAF_2_TGEN_dict']       = configuration['LEAF_2_TGEN_data']
        testscript.parameters['LEAF_3_TGEN_dict']       = configuration['LEAF_3_TGEN_data']

        testscript.parameters['leafVPCDictData']        = {LEAF_1 : configuration['LEAF_1_dict'], LEAF_2 : configuration['LEAF_2_dict']}
        testscript.parameters['leavesDictList']         = [configuration['LEAF_1_dict'], configuration['LEAF_2_dict'], configuration['LEAF_3_dict']]
        testscript.parameters['leavesDict']             = {LEAF_1 : configuration['LEAF_1_dict'],
                                                           LEAF_2 : configuration['LEAF_2_dict'],
                                                           LEAF_3 : configuration['LEAF_3_dict']}
        testscript.parameters['tcam_config_dict']       = configuration['tcam_config_dict']

        testscript.parameters['VTEP_List'] = [testscript.parameters['LEAF_1_dict'], testscript.parameters['LEAF_2_dict'], testscript.parameters['LEAF_3_dict']]

    # *****************************************************************************************************************************#

    @aetest.subsection
    def get_interfaces(self, testscript):
        """ common setup subsection: Getting required Connections for Test """

        SPINE = testscript.parameters['SPINE']
        LEAF_1 = testscript.parameters['LEAF-1']
        LEAF_2 = testscript.parameters['LEAF-2']
        LEAF_3 = testscript.parameters['LEAF-3']
        FAN_1 = testscript.parameters['FAN-1']
        #FAN_2 = testscript.parameters['FAN-2']
        IXIA = testscript.parameters['IXIA']
        xbow1  = testscript.parameters['xbow1'] 
        xbow2  = testscript.parameters['xbow2'] 
        xbow3  = testscript.parameters['xbow3']
        FO_1 = testscript.parameters['FO_1']

        # =============================================================================================================================#

        log.info("================================================")
        log.info("All Available Interfaces from the YAML file are:")
        for dut in device_list:
            log.info("\n\n--->" + str(dut) + " Interface list")
            for interface in dut.interfaces.keys():
                log.info(str(interface) + " --> " + str(dut.interfaces[interface].intf))

        # =============================================================================================================================#
        # Fetching the specific interfaces
        testscript.parameters['intf_SPINE_to_LEAF_1']       = SPINE.interfaces['SPINE_to_LEAF-1'].intf
        testscript.parameters['intf_SPINE_to_LEAF_2']       = SPINE.interfaces['SPINE_to_LEAF-2'].intf
        testscript.parameters['intf_SPINE_to_LEAF_3']       = SPINE.interfaces['SPINE_to_LEAF-3'].intf

        testscript.parameters['intf_LEAF_1_to_LEAF_2_1']    = LEAF_1.interfaces['LEAF-1_to_LEAF-2_1'].intf
        testscript.parameters['intf_LEAF_1_to_LEAF_2_2']    = LEAF_1.interfaces['LEAF-1_to_LEAF-2_2'].intf
        testscript.parameters['intf_LEAF_1_to_SPINE']       = LEAF_1.interfaces['LEAF-1_to_SPINE'].intf
        testscript.parameters['intf_LEAF_1_to_FAN_1']       = LEAF_1.interfaces['LEAF-1_to_FAN-1'].intf
        testscript.parameters['intf_LEAF_1_to_N7k_LEAF_1_1']    = LEAF_1.interfaces['LEAF-1_to_N7k_LEAF-1_1'].intf
        testscript.parameters['intf_LEAF_1_to_N7k_LEAF_2_1']    = LEAF_1.interfaces['LEAF-1_to_N7k_LEAF-2_1'].intf
        

        testscript.parameters['intf_LEAF_2_to_LEAF_1_1']    = LEAF_2.interfaces['LEAF-2_to_LEAF-1_1'].intf
        testscript.parameters['intf_LEAF_2_to_LEAF_1_2']    = LEAF_2.interfaces['LEAF-2_to_LEAF-1_2'].intf
        testscript.parameters['intf_LEAF_2_to_SPINE']       = LEAF_2.interfaces['LEAF-2_to_SPINE'].intf
        testscript.parameters['intf_LEAF_2_to_FAN_1']       = LEAF_2.interfaces['LEAF-2_to_FAN-1'].intf
        testscript.parameters['intf_LEAF_2_to_N7k_LEAF_1_1']    = LEAF_2.interfaces['LEAF-2_to_N7k_LEAF-1_1'].intf
        testscript.parameters['intf_LEAF_2_to_N7k_LEAF_2_1']    = LEAF_2.interfaces['LEAF-2_to_N7k_LEAF-2_1'].intf
        testscript.parameters['intf_LEAF_2_to_FO_1']       = LEAF_2.interfaces['LEAF-2_to_FO_1'].intf

        testscript.parameters['intf_LEAF_3_to_SPINE']       = LEAF_3.interfaces['LEAF-3_to_SPINE'].intf
        testscript.parameters['intf_LEAF_3_to_FO_1']       = LEAF_3.interfaces['LEAF-3_to_FO_1'].intf
        #testscript.parameters['intf_LEAF_3_to_IXIA']       = LEAF_3.interfaces['LEAF-3_to_IXIA'].intf

        testscript.parameters['intf_FAN_1_to_LEAF_1']       = FAN_1.interfaces['FAN-1_to_LEAF-1'].intf
        testscript.parameters['intf_FAN_1_to_LEAF_2']       = FAN_1.interfaces['FAN-1_to_LEAF-2'].intf
        testscript.parameters['intf_FAN_1_to_IXIA']         = FAN_1.interfaces['FAN-1_to_IXIA'].intf

        testscript.parameters['intf_FO_1_to_LEAF_3']       = FO_1.interfaces['FO_1_to_LEAF-3'].intf
        testscript.parameters['intf_FO_1_to_LEAF_2']       = FO_1.interfaces['FO_1_to_LEAF-2'].intf
        testscript.parameters['intf_FO_1_to_N7k_LEAF_3']       = FO_1.interfaces['FO_1_to_N7k_LEAF-3'].intf
        testscript.parameters['intf_FO_1_to_IXIA']         = FO_1.interfaces['FO_1_to_IXIA'].intf

        #testscript.parameters['intf_IXIA_to_FAN_1']         = IXIA.interfaces['IXIA_to_FAN-1'].intf
        #testscript.parameters['intf_IXIA_to_LEAF_3']         = IXIA.interfaces['IXIA_to_LEAF-3'].intf
        testscript.parameters['intf_IXIA_to_FO_1']               = IXIA.interfaces['IXIA_to_FO_1'].intf
        testscript.parameters['IXIA_to_N7k_LEAF_1']               = IXIA.interfaces['IXIA_to_N7k_LEAF-1'].intf
        
        testscript.parameters['intf_N7k_LEAF_1_to_N7k_LEAF_2_1']= xbow1.interfaces['N7k_LEAF-1_to_N7k_LEAF-2_1']
        testscript.parameters['intf_N7k_LEAF_1_to_N7k_LEAF_2_2']= xbow1.interfaces['N7k_LEAF-1_to_N7k_LEAF-2_2']
        testscript.parameters['intf_N7k_LEAF_1_to_SPINE_1']= xbow1.interfaces['N7k_LEAF-1_to_N7k_LEAF-1_1']
        testscript.parameters['intf_N7k_LEAF_1_to_SPINE_4']= xbow1.interfaces['N7k_LEAF-1_to_N7k_LEAF-1_2']
        testscript.parameters['intf_N7k_LEAF_1_to_SPINE_2']= xbow1.interfaces['N7k_LEAF-1_to_N7k_LEAF-2_5']
        testscript.parameters['intf_N7k_LEAF_1_to_SPINE_3']= xbow1.interfaces['N7k_LEAF-1_to_N7k_LEAF-3_1']
        testscript.parameters['intf_N7k_LEAF_1_to_LEAF_1_1']= xbow1.interfaces['N7k_LEAF-1_to_LEAF-1_1']
        testscript.parameters['intf_N7k_LEAF_1_to_LEAF_2_1']= xbow1.interfaces['N7k_LEAF-1_to_LEAF-2_1']
        testscript.parameters['intf_N7k_LEAF_1_to_IXIA']= xbow1.interfaces['N7k_LEAF-1_to_IXIA']
        
        testscript.parameters['intf_N7k_SPINE_1_to_N7k_LEAF_1']= xbow1.interfaces['N7k_LEAF-1_to_N7k_LEAF-1_3']
        testscript.parameters['intf_N7k_SPINE_1_to_N7k_LEAF_2']= xbow1.interfaces['N7k_LEAF-1_to_N7k_LEAF-2_6']
        testscript.parameters['intf_N7k_SPINE_1_to_N7k_LEAF_3']= xbow1.interfaces['N7k_LEAF-1_to_N7k_LEAF-3_2']
        
        testscript.parameters['intf_N7k_SPINE_4_to_N7k_LEAF_1']= xbow1.interfaces['N7k_LEAF-1_to_N7k_LEAF-1_4']
        testscript.parameters['intf_N7k_SPINE_4_to_N7k_LEAF_2']= xbow1.interfaces['N7k_LEAF-1_to_N7k_LEAF-2_3']
        #testscript.parameters['intf_N7k_SPINE_4_to_N7k_LEAF_3']= xbow1.interfaces['N7k_LEAF-1_to_N7k_LEAF-3_3'].intf
        
        testscript.parameters['intf_N7k_LEAF_2_to_N7k_LEAF_1_1']= xbow2.interfaces['N7k_LEAF-2_to_N7k_LEAF-1_1']
        testscript.parameters['intf_N7k_LEAF_2_to_N7k_LEAF_1_2']= xbow2.interfaces['N7k_LEAF-2_to_N7k_LEAF-1_2']
        testscript.parameters['intf_N7k_LEAF_2_to_SPINE_1']= xbow2.interfaces['N7k_LEAF-2_to_N7k_LEAF-1_5']
        testscript.parameters['intf_N7k_LEAF_2_to_SPINE_4']= xbow2.interfaces['N7k_LEAF-2_to_N7k_LEAF-1_6']
        testscript.parameters['intf_N7k_LEAF_2_to_SPINE_2']= xbow2.interfaces['N7k_LEAF-2_to_N7k_LEAF-2_1']
        testscript.parameters['intf_N7k_LEAF_2_to_SPINE_3']= xbow2.interfaces['N7k_LEAF-2_to_N7k_LEAF-3_1']
        testscript.parameters['intf_N7k_LEAF_2_to_LEAF_1_1']= xbow2.interfaces['N7k_LEAF-2_to_LEAF-1_1']
        testscript.parameters['intf_N7k_LEAF_2_to_LEAF_2_1']= xbow2.interfaces['N7k_LEAF-2_to_LEAF-2_1']
        
        testscript.parameters['intf_N7k_SPINE_2_to_N7k_LEAF_1']= xbow2.interfaces['N7k_LEAF-2_to_N7k_LEAF-1_7']
        testscript.parameters['intf_N7k_SPINE_2_to_N7k_LEAF_2']= xbow2.interfaces['N7k_LEAF-2_to_N7k_LEAF-2_2']
        testscript.parameters['intf_N7k_SPINE_2_to_N7k_LEAF_3']= xbow2.interfaces['N7k_LEAF-2_to_N7k_LEAF-3_2']
        
        
        testscript.parameters['intf_N7k_LEAF_3_to_SPINE_1']= xbow3.interfaces['N7k_LEAF-3_to_N7k_LEAF-1_1']
        #testscript.parameters['intf_N7k_LEAF_3_to_SPINE_4']= xbow3.interfaces['N7k_LEAF-3_to_N7k_LEAF-1_6'].intf
        testscript.parameters['intf_N7k_LEAF_3_to_SPINE_2']= xbow3.interfaces['N7k_LEAF-3_to_N7k_LEAF-2_1']
        testscript.parameters['intf_N7k_LEAF_3_to_SPINE_3']= xbow3.interfaces['N7k_LEAF-3_to_N7k_LEAF-3_1']
        testscript.parameters['intf_N7k_LEAF_3_to_FO_1']= xbow3.interfaces['N7k_LEAF-3_to_FO_1']
        
        
        testscript.parameters['intf_N7k_SPINE_3_to_N7k_LEAF_1']= xbow3.interfaces['N7k_LEAF-3_to_N7k_LEAF-1_2']
        testscript.parameters['intf_N7k_SPINE_3_to_N7k_LEAF_2']= xbow3.interfaces['N7k_LEAF-3_to_N7k_LEAF-2_2']
        testscript.parameters['intf_N7k_SPINE_3_to_N7k_LEAF_3']= xbow3.interfaces['N7k_LEAF-3_to_N7k_LEAF-3_2']
        
        

        #testscript.parameters['ixia_int_list'] = str(testscript.parameters['intf_IXIA_to_FAN_1']) + " " + str(testscript.parameters['intf_IXIA_to_LEAF_3']) + " " + str(testscript.parameters['intf_IXIA_to_FO_1'])
        testscript.parameters['ixia_int_list'] = str(testscript.parameters['intf_IXIA_to_FO_1']) + " " + str(testscript.parameters['IXIA_to_N7k_LEAF_1'])
        testscript.parameters['xbow1_Leaf1_int_list'] = [testscript.parameters['intf_N7k_LEAF_1_to_N7k_LEAF_2_1'],testscript.parameters['intf_N7k_LEAF_1_to_N7k_LEAF_2_2'],testscript.parameters['intf_N7k_LEAF_1_to_SPINE_1'],testscript.parameters['intf_N7k_LEAF_1_to_SPINE_4'],testscript.parameters['intf_N7k_LEAF_1_to_SPINE_2'],testscript.parameters['intf_N7k_LEAF_1_to_SPINE_3'],testscript.parameters['intf_N7k_LEAF_1_to_LEAF_1_1'],testscript.parameters['intf_N7k_LEAF_1_to_LEAF_2_1'],testscript.parameters['intf_N7k_LEAF_1_to_IXIA']]
        testscript.parameters['xbow1_spine1_int_list'] = [testscript.parameters['intf_N7k_SPINE_1_to_N7k_LEAF_1'],testscript.parameters['intf_N7k_SPINE_1_to_N7k_LEAF_2'],testscript.parameters['intf_N7k_SPINE_1_to_N7k_LEAF_3']]
        testscript.parameters['xbow1_spine4_int_list'] = [testscript.parameters['intf_N7k_SPINE_4_to_N7k_LEAF_1'],testscript.parameters['intf_N7k_SPINE_4_to_N7k_LEAF_2']]
        testscript.parameters['xbow2_Leaf2_int_list'] =[testscript.parameters['intf_N7k_LEAF_2_to_N7k_LEAF_1_1'],testscript.parameters['intf_N7k_LEAF_2_to_N7k_LEAF_1_2'],testscript.parameters['intf_N7k_LEAF_2_to_SPINE_1'],testscript.parameters['intf_N7k_LEAF_2_to_SPINE_2'],testscript.parameters['intf_N7k_LEAF_2_to_SPINE_3'],testscript.parameters['intf_N7k_LEAF_2_to_SPINE_4'],testscript.parameters['intf_N7k_LEAF_2_to_LEAF_1_1'],testscript.parameters['intf_N7k_LEAF_2_to_LEAF_2_1']]
        testscript.parameters['xbow2_spine2_int_list'] = [testscript.parameters['intf_N7k_SPINE_2_to_N7k_LEAF_1'],testscript.parameters['intf_N7k_SPINE_2_to_N7k_LEAF_2'],testscript.parameters['intf_N7k_SPINE_2_to_N7k_LEAF_3']]
        testscript.parameters['xbow3_Leaf3_int_list'] = [testscript.parameters['intf_N7k_LEAF_3_to_SPINE_1'],testscript.parameters['intf_N7k_LEAF_3_to_SPINE_2'],testscript.parameters['intf_N7k_LEAF_3_to_SPINE_3'],testscript.parameters['intf_N7k_LEAF_3_to_FO_1']]
        testscript.parameters['xbow3_spine3_int_list'] = [testscript.parameters['intf_N7k_SPINE_3_to_N7k_LEAF_1'],testscript.parameters['intf_N7k_SPINE_3_to_N7k_LEAF_2'],testscript.parameters['intf_N7k_SPINE_3_to_N7k_LEAF_3']]
        # =============================================================================================================================#

        log.info("\n\n================================================")
        log.info("Topology Specific Interfaces \n\n")
        for key in testscript.parameters.keys():
            if "intf_" in key:
                log.info("%-25s   ---> %-15s" % (key, testscript.parameters[key]))
        log.info("\n\n")

    # @aetest.subsection
    # def allocate_ints_vdcs(self, testscript):
    # 
    #     fail_flag = []
    #     leaf1_int_lst_for_mod_type = []
    #     leaf1_int_lst_for_alloc = []
    #     leaf2_int_lst_for_mod_type = []
    #     leaf2_int_lst_for_alloc = []
    #     leaf3_int_lst_for_mod_type = []
    #     leaf4_int_lst_for_alloc = []
    #     spine1_int_lst_for_mod_type = []
    #     spine1_int_lst_for_alloc = []
    #     spine2_int_lst_for_mod_type = []
    #     spine2_int_lst_for_alloc = []
    #     spine3_int_lst_for_mod_type = []
    #     spine3_int_lst_for_alloc = []
    #     spine4_int_lst_for_mod_type = []
    #     spine4_int_lst_for_alloc = []
    # 
    #     for interf in testscript.parameters['xbow1_Leaf1_int_list']:
    #         leaf1_int_lst_for_mod_type.append(interf)
    #         leaf1_int_lst_for_alloc.append(interf.intf)
    # 
    #     for interf in testscript.parameters['xbow2_Leaf2_int_list']:
    #         leaf2_int_lst_for_mod_type.append(interf)
    #         leaf2_int_lst_for_alloc.append(interf.intf)
    #     
    #     for interf in testscript.parameters['xbow3_Leaf3_int_list']:
    #         leaf3_int_lst_for_mod_type.append(interf)
    #         leaf3_int_lst_for_alloc.append(interf.intf)
    #         
    #     for interf in testscript.parameters['xbow1_spine1_int_list']:
    #         spine1_int_lst_for_mod_type.append(interf)
    #         spine1_int_lst_for_alloc.append(interf.intf)
    #     
    #     for interf in testscript.parameters['xbow1_spine4_int_list']:
    #         spine4_int_lst_for_mod_type.append(interf)
    #         spine4_int_lst_for_alloc.append(interf.intf)
    #         
    #     for interf in testscript.parameters['xbow2_spine2_int_list']:
    #         spine2_int_lst_for_mod_type.append(interf)
    #         spine2_int_lst_for_alloc.append(interf.intf)
    #     
    #     for interf in testscript.parameters['xbow3_spine3_int_list']:
    #         spine3_int_lst_for_mod_type.append(interf)
    #         spine3_int_lst_for_alloc.append(interf.intf)
    # 
    #     leaf_1_info = {
    #                 'name'              : 'leaf1',
    #                 'interfaces'        : leaf1_int_lst_for_alloc,
    #                 'config-lines'      : [vdc.module_type_config_line(leaf1_int_lst_for_mod_type)],
    #                 }
    #     spine_1_info = {
    #                 'name'              : 'spine1',
    #                 'interfaces'        : spine1_int_lst_for_alloc,
    #                 'config-lines'      : [vdc.module_type_config_line(spine1_int_lst_for_mod_type)],
    #                 }
    #     spine_4_info = {
    #                 'name'              : 'spine4',
    #                 'interfaces'        : spine4_int_lst_for_alloc,
    #                 'config-lines'      : [vdc.module_type_config_line(spine4_int_lst_for_mod_type)],
    #                 }
    #     leaf_2_info = {
    #                 'name'              : 'leaf2',
    #                 'interfaces'        : leaf2_int_lst_for_alloc,
    #                 'config-lines'      : [vdc.module_type_config_line(leaf2_int_lst_for_mod_type)],
    #                 }
    #     spine_2_info = {
    #                 'name'              : 'spine2',
    #                 'interfaces'        : spine2_int_lst_for_alloc,
    #                 'config-lines'      : [vdc.module_type_config_line(spine2_int_lst_for_mod_type)],
    #                 }
    #     leaf_3_info = {
    #                 'name'              : 'leaf3',
    #                 'interfaces'        : leaf3_int_lst_for_alloc,
    #                 'config-lines'      : [vdc.module_type_config_line(leaf3_int_lst_for_mod_type)],
    #                 }
    #     spine_4_info = {
    #                 'name'              : 'spine4',
    #                 'interfaces'        : spine4_int_lst_for_alloc,
    #                 'config-lines'      : [vdc.module_type_config_line(spine4_int_lst_for_mod_type)],
    #                 }
    
    # @aetest.subsection
    # def create_vdc_leaf1(self,xbow1,testscript):
    # 
    #     leaf1_int_lst_for_mod_type = []
    #     leaf1_int_lst_for_alloc = []
    # 
    #     for interf in testscript.parameters['xbow1_Leaf1_int_list']:
    #         leaf1_int_lst_for_mod_type.append(interf)
    #         leaf1_int_lst_for_alloc.append(interf.intf)
    # 
    #     leaf1_info = {
    #                 'name'              : 'leaf1',
    #                 'interfaces'        : leaf1_int_lst_for_alloc,
    #                 'config-lines'      : [vdc.module_type_config_line(leaf1_int_lst_for_mod_type)]
    #                 }
    # 
    #     try:
    #         ForkedPdb().set_trace()
    #         vdc.create_vdc(testscript.parameters['xbow1'], leaf1_info)
    #         #global xbow1_leaf1
    #         
    #         leaf1 = vdc.connect(testscript.parameters['xbow1'], 'leaf1')
    #         testscript.parameters['leaf1'] = leaf1
    #     except Exception as error:
    #         self.errored('Exception occurred while creating or connecting to VDCs' + str(error), goto=['common_cleanup'])
    # 
    # @aetest.subsection
    # def connect_vdc_leaf1(self, testscript, testbed, uut_list):
    # 
    #     # Creating a new connection handle to newly created VDC via management
    #     leaf1 = testbed.devices[uut_list['xbow1']]
    #     leaf1.connect(via='alt', alias='alt')
    #     leaf1 = leaf1.alt
    #     log.info("===> switching to vdc")
    #     leaf1.switchto('leaf1', timeout=120)
    #     leaf1.execute("show vdc current-vdc")
    #     testscript.parameters['leaf1'] = leaf1

        #testscript.parameters['dut_list'].append(leaf1)
    
    @aetest.subsection
    def create_vdc_leaf1(self, testscript):
    
        leaf1_int_lst_for_mod_type = []
        leaf1_int_lst_for_alloc = []
        print(testscript.parameters['xbow1_Leaf1_int_list'])
        print(type(testscript.parameters['xbow1_Leaf1_int_list']))
        for interf in testscript.parameters['xbow1_Leaf1_int_list']:
            leaf1_int_lst_for_mod_type.append(interf)
            leaf1_int_lst_for_alloc.append(interf.intf)
    
        leaf1_info = {
                    'name'              : 'leaf1',
                    'interfaces'        : leaf1_int_lst_for_alloc,
                    'config-lines'      : [vdc.module_type_config_line(leaf1_int_lst_for_mod_type)],
                    }
        #testscript.parameters['xbow1'].execute('show ver')
        #try:
            #ForkedPdb().set_trace()
        global break_port_cfg
        break_port_cfg=create_and_configure_new_vdc(testscript.parameters['xbow1'], leaf1_info)
            #self.break_port_cfg=break_port_cfg
        #except Exception as error:
        #    self.errored('Exception occurred while creating or connecting to VDCs' + str(error), goto=['common_cleanup'])
    
    @aetest.subsection
    def connect_vdc_leaf1(self, testscript, testbed, uut_list):
    
        # Creating a new connection handle to newly created VDC via management
        leaf1 = testbed.devices[uut_list['xbow1']]
        #ForkedPdb().set_trace()
        leaf1.connect(via='alt', alias='alt')
        leaf1 = leaf1.alt
        log.info("===> switching to vdc")
        leaf1.switchto('leaf1', timeout=120)
        leaf1.execute("show vdc current-vdc")
        log.info('break_port_cfg:'+str(break_port_cfg))
        if break_port_cfg != 0:
            leaf1.configure(break_port_cfg)
        testscript.parameters['leaf1'] = leaf1
        #ForkedPdb().set_trace()
    
    @aetest.subsection
    def create_vdc_spine1(self, testscript):

        spine1_int_lst_for_mod_type = []
        spine1_int_lst_for_alloc = []

        for interf in testscript.parameters['xbow1_spine1_int_list']:
            spine1_int_lst_for_mod_type.append(interf)
            spine1_int_lst_for_alloc.append(interf.intf)

        spine1_info = {
                    'name'              : 'spine1',
                    'interfaces'        : spine1_int_lst_for_alloc,
                    'config-lines'      : [vdc.module_type_config_line(spine1_int_lst_for_mod_type)],
                    }

        try:
            global break_port_cfg
            break_port_cfg=create_and_configure_new_vdc(testscript.parameters['xbow1'], spine1_info)
        except Exception as error:
            self.errored('Exception occurred while creating or connecting to VDCs' + str(error), goto=['common_cleanup'])

    @aetest.subsection
    def connect_vdc_spine1(self, testscript, testbed, uut_list):

        # Creating a new connection handle to newly created VDC via management
        spine1 = testbed.devices[uut_list['xbow1']]
        spine1.connect(via='alt', alias='alt')
        spine1 = spine1.alt
        log.info("===> switching to vdc")
        spine1.switchto('spine1', timeout=120)
        spine1.execute("show vdc current-vdc")
        if break_port_cfg:
            spine1.configure(break_port_cfg)
        testscript.parameters['spine1'] = spine1
        

        #testscript.parameters['dut_list'].append(spine1)
        
    
    @aetest.subsection
    def create_vdc_spine4(self, testscript):

        spine4_int_lst_for_mod_type = []
        spine4_int_lst_for_alloc = []

        for interf in testscript.parameters['xbow1_spine4_int_list']:
            spine4_int_lst_for_mod_type.append(interf)
            spine4_int_lst_for_alloc.append(interf.intf)

        spine4_info = {
                    'name'              : 'spine4',
                    'interfaces'        : spine4_int_lst_for_alloc,
                    'config-lines'      : [vdc.module_type_config_line(spine4_int_lst_for_mod_type)],
                    }

        try:
            global break_port_cfg
            break_port_cfg=create_and_configure_new_vdc(testscript.parameters['xbow1'], spine4_info)
        except Exception as error:
            self.errored('Exception occurred while creating or connecting to VDCs' + str(error), goto=['common_cleanup'])

    @aetest.subsection
    def connect_vdc_spine4(self, testscript, testbed, uut_list):

        # Creating a new connection handle to newly created VDC via management
        spine4 = testbed.devices[uut_list['xbow1']]
        spine4.connect(via='alt', alias='alt')
        spine4 = spine4.alt
        log.info("===> switching to vdc")
        spine4.switchto('spine4', timeout=120)
        spine4.execute("show vdc current-vdc")
        if break_port_cfg:
            spine4.configure(break_port_cfg)
        testscript.parameters['spine4'] = spine4

        #testscript.parameters['dut_list'].append(spine4)
        
    @aetest.subsection
    def create_vdc_leaf2(self, testscript):

        leaf2_int_lst_for_mod_type = []
        leaf2_int_lst_for_alloc = []

        for interf in testscript.parameters['xbow2_Leaf2_int_list']:
            leaf2_int_lst_for_mod_type.append(interf)
            leaf2_int_lst_for_alloc.append(interf.intf)

        leaf2_info = {
                    'name'              : 'leaf2',
                    'interfaces'        : leaf2_int_lst_for_alloc,
                    'config-lines'      : [vdc.module_type_config_line(leaf2_int_lst_for_mod_type)],
                    }

        try:
            global break_port_cfg
            break_port_cfg=create_and_configure_new_vdc(testscript.parameters['xbow2'], leaf2_info)
        except Exception as error:
            self.errored('Exception occurred while creating or connecting to VDCs' + str(error), goto=['common_cleanup'])

    @aetest.subsection
    def connect_vdc_leaf2(self, testscript, testbed, uut_list):

        # Creating a new connection handle to newly created VDC via management
        leaf2 = testbed.devices[uut_list['xbow2']]
        leaf2.connect(via='alt', alias='alt')
        leaf2 = leaf2.alt
        log.info("===> switching to vdc")
        leaf2.switchto('leaf2', timeout=120)
        leaf2.execute("show vdc current-vdc")
        if break_port_cfg:
            leaf2.configure(break_port_cfg)
        testscript.parameters['leaf2'] = leaf2

        #testscript.parameters['dut_list'].append(leaf2)
    
    @aetest.subsection
    def create_vdc_spine2(self, testscript):

        spine2_int_lst_for_mod_type = []
        spine2_int_lst_for_alloc = []

        for interf in testscript.parameters['xbow2_spine2_int_list']:
            spine2_int_lst_for_mod_type.append(interf)
            spine2_int_lst_for_alloc.append(interf.intf)

        spine2_info = {
                    'name'              : 'spine2',
                    'interfaces'        : spine2_int_lst_for_alloc,
                    'config-lines'      : [vdc.module_type_config_line(spine2_int_lst_for_mod_type)],
                    }

        try:
            global break_port_cfg
            break_port_cfg=create_and_configure_new_vdc(testscript.parameters['xbow2'], spine2_info)
        except Exception as error:
            self.errored('Exception occurred while creating or connecting to VDCs' + str(error), goto=['common_cleanup'])

    @aetest.subsection
    def connect_vdc_spine2(self, testscript, testbed, uut_list):

        # Creating a new connection handle to newly created VDC via management
        spine2 = testbed.devices[uut_list['xbow2']]
        spine2.connect(via='alt', alias='alt')
        spine2 = spine2.alt
        log.info("===> switching to vdc")
        spine2.switchto('spine2', timeout=120)
        spine2.execute("show vdc current-vdc")
        if break_port_cfg:
            spine2.configure(break_port_cfg)
        testscript.parameters['spine2'] = spine2

        #testscript.parameters['dut_list'].append(spine2)
        
    @aetest.subsection
    def create_vdc_spine3(self, testscript):

        spine3_int_lst_for_mod_type = []
        spine3_int_lst_for_alloc = []

        for interf in testscript.parameters['xbow3_spine3_int_list']:
            spine3_int_lst_for_mod_type.append(interf)
            spine3_int_lst_for_alloc.append(interf.intf)

        spine3_info = {
                    'name'              : 'spine3',
                    'interfaces'        : spine3_int_lst_for_alloc,
                    'config-lines'      : [vdc.module_type_config_line(spine3_int_lst_for_mod_type)],
                    }

        try:
            global break_port_cfg
            break_port_cfg=create_and_configure_new_vdc(testscript.parameters['xbow3'], spine3_info)
            
        except Exception as error:
            self.errored('Exception occurred while creating or connecting to VDCs' + str(error), goto=['common_cleanup'])

    @aetest.subsection
    def connect_vdc_spine3(self, testscript, testbed, uut_list):

        # Creating a new connection handle to newly created VDC via management
        spine3 = testbed.devices[uut_list['xbow3']]
        spine3.connect(via='alt', alias='alt')
        spine3 = spine3.alt
        log.info("===> switching to vdc")
        spine3.switchto('spine3', timeout=120)
        spine3.execute("show vdc current-vdc")
        if break_port_cfg:
            spine3.configure(break_port_cfg)
        testscript.parameters['spine3'] = spine3

        #testscript.parameters['dut_list'].append(spine3)
        
    @aetest.subsection
    def create_vdc_leaf3(self, testscript):

        leaf3_int_lst_for_mod_type = []
        leaf3_int_lst_for_alloc = []

        for interf in testscript.parameters['xbow3_Leaf3_int_list']:
            leaf3_int_lst_for_mod_type.append(interf)
            leaf3_int_lst_for_alloc.append(interf.intf)

        leaf3_info = {
                    'name'              : 'leaf3',
                    'interfaces'        : leaf3_int_lst_for_alloc,
                    'config-lines'      : [vdc.module_type_config_line(leaf3_int_lst_for_mod_type)],
                    }

        try:
            global break_port_cfg
            break_port_cfg=create_and_configure_new_vdc(testscript.parameters['xbow3'], leaf3_info)
        except Exception as error:
            self.errored('Exception occurred while creating or connecting to VDCs' + str(error), goto=['common_cleanup'])

    @aetest.subsection
    def connect_vdc_leaf3(self, testscript, testbed, uut_list):

        # Creating a new connection handle to newly created VDC via management
        leaf3 = testbed.devices[uut_list['xbow3']]
        leaf3.connect(via='alt', alias='alt')
        leaf3 = leaf3.alt
        log.info("===> switching to vdc")
        leaf3.switchto('leaf3', timeout=120)
        leaf3.execute("show vdc current-vdc")
        if break_port_cfg:
            leaf3.configure(break_port_cfg)
        testscript.parameters['leaf3'] = leaf3

        #testscript.parameters['dut_list'].append(leaf3)
    # ==============================================================================================================================#
    # @aetest.subsection
    # def configureTCAM(self,testscript,testbed):
    # 
    #     #TCAM comfigurable DUTS are:
    #     testbed_obj = testbed
    #     tcam_configurable_duts = testscript.parameters['tcam_config_dict'].keys()
    #     log.info('{0} are the duts for which the tcam has to be carved'.format(tcam_configurable_duts))
    #     
    #     tcam_config_dict = testscript.parameters['tcam_config_dict']
    #     
    #     tcam_dut_obj_list = {}
    #     for dut in tcam_configurable_duts:
    #         tcam_dut_obj_list[dut] = testbed.devices[dut]
    #     
    #     
    #     log.info('The value of tcam_dut_obj_list is {0} '.format(tcam_dut_obj_list))
    #     
    #     
    #     d = tcam_lib.configTcam(tcam_config_dict,tcam_dut_obj_list,log)
    #     for dut in tcam_dut_obj_list.keys():
    #         tcam_dut_obj_list[dut].connect(via='console')
    #     res = d.Nodes(dut)
        
        
    # *****************************************************************************************************************************#

    @aetest.subsection
    def topology_used_for_suite(self):
        """ common setup subsection: Represent Topology """

        # Set topology to be used
        topology = """
        
                                            +-------------+
                                            |    SPINE    |
                                            +-------------+
                                           /       |       \\
                                          /        |        \\
                                         /         |         \\
                                        /          |          \\
                                       /           |           \\
                                      /            |            \\
                            +-----------+    +-----------+    +-----------+
                            |   LEAF-1  |====|   LEAF-2  |    |   LEAF-3  |
                            +-----------+    +-----------+    +-----------+
                                   \\             /                 |
                                    \\           /                  |
                                     \\         /                   |
                                      \\       /                    |
                                    +-----------+                   |
                                          |                         |      
                                          |                         |      
                                        Ixia                      Ixia     
        """

        log.info("Topology to be used is")
        log.info(topology)


# *****************************************************************************************************************************#

class DEVICE_BRINGUP(aetest.Testcase):
    """Device Bring-up Test-Case"""

    @aetest.test
    def enable_feature_set(self, testscript):
        """ Device Bring-up subsection: Configuring Features and Feature-sets """

        # Do not perform configurations if skip_device_config flag is set
        if not testscript.parameters['script_flags']['skip_device_config']:

            leafLst                 = [testscript.parameters['LEAF-1'], testscript.parameters['LEAF-2'], testscript.parameters['LEAF-3']]
            spineFeatureList        = ['ospf', 'bgp', 'pim', 'lacp', 'nv overlay']
            vpcLeafFeatureList      = ['vpc', 'ospf', 'bgp', 'pim', 'interface-vlan', 'vn-segment-vlan-based', 'lacp', 'nv overlay']
            LeafFeatureList         = ['ospf', 'bgp', 'pim', 'interface-vlan', 'vn-segment-vlan-based', 'lacp', 'nv overlay']
            fanOutFeatureList       = ['lacp']
            configFeatureSet_status = []
            configFeatureSet_msgs = ""

            # --------------------------------
            # Configure Feature Set on Leafs
#            featureSetConfigureLeafs_status = infraConfig.configureVerifyFeatureSet(leafLst, ['mpls'])
#            if featureSetConfigureLeafs_status['result']:
#                log.info("Passed Configuring feature Sets on all Leafs")
#            else:
#                log.debug("Failed Configuring feature Sets on all Leafs")
#                configFeatureSet_msgs += featureSetConfigureLeafs_status['log']
#                configFeatureSet_status.append(0)

            # --------------------------------
            # Configure Features on SPINE
            featureConfigureSpine_status = infraConfig.configureVerifyFeature(testscript.parameters['SPINE'], spineFeatureList)
            if featureConfigureSpine_status['result']:
                log.info("Passed Configuring features on SPINE")
            else:
                log.debug("Failed configuring features on SPINE")
                configFeatureSet_msgs += featureConfigureSpine_status['log']
                configFeatureSet_status.append(0)

            # --------------------------------
            # Configure Feature-set on LEAF-1
#            featureSetConfigureLeaf1_status = infraConfig.configureVerifyFeatureSet(testscript.parameters['LEAF-1'], ['mpls'])
#            if featureSetConfigureLeaf1_status['result']:
#                log.info("Passed Configuring feature-sets on LEAF-1")
#            else:
#                log.debug("Failed configuring feature-sets on LEAF-1")
#                configFeatureSet_msgs += featureSetConfigureLeaf1_status['log']
#                configFeatureSet_status.append(0)

            featureConfigureLeaf1_status = infraConfig.configureVerifyFeature(testscript.parameters['LEAF-1'], vpcLeafFeatureList)
            if featureConfigureLeaf1_status['result']:
                log.info("Passed Configuring features on LEAF-1")
            else:
                log.debug("Failed configuring features on LEAF-1")
                configFeatureSet_msgs += featureConfigureLeaf1_status['log']
                configFeatureSet_status.append(0)

            # --------------------------------
            # Configure Feature-set on LEAF-2
#            featureSetConfigureLeaf2_status = infraConfig.configureVerifyFeatureSet(testscript.parameters['LEAF-2'], ['mpls'])
#            if featureSetConfigureLeaf2_status['result']:
#                log.info("Passed Configuring feature-sets on LEAF-2")
#            else:
#                log.debug("Failed configuring feature-sets on LEAF-2")
#                configFeatureSet_msgs += featureSetConfigureLeaf1_status['log']
#                configFeatureSet_status.append(0)

            featureConfigureLeaf2_status = infraConfig.configureVerifyFeature(testscript.parameters['LEAF-2'], vpcLeafFeatureList)
            if featureConfigureLeaf2_status['result']:
                log.info("Passed Configuring features on LEAF-2")
            else:
                log.debug("Failed configuring features on LEAF-2")
                configFeatureSet_msgs += featureConfigureLeaf1_status['log']
                configFeatureSet_status.append(0)

            # --------------------------------
            # Configure Feature-set on LEAF-3
#            featureSetConfigureLeaf3_status = infraConfig.configureVerifyFeatureSet(testscript.parameters['LEAF-3'], ['mpls'])
#            if featureSetConfigureLeaf3_status['result']:
#                log.info("Passed Configuring feature-sets on LEAF-3")
#            else:
#                log.debug("Failed configuring feature-sets on LEAF-3")
#                configFeatureSet_msgs += featureSetConfigureLeaf1_status['log']
#                configFeatureSet_status.append(0)

            featureConfigureLeaf3_status = infraConfig.configureVerifyFeature(testscript.parameters['LEAF-3'], LeafFeatureList)
            if featureConfigureLeaf3_status['result']:
                log.info("Passed Configuring features on LEAF-3")
            else:
                log.debug("Failed configuring features on LEAF-3")
                configFeatureSet_msgs += featureConfigureLeaf1_status['log']
                configFeatureSet_status.append(0)

            # --------------------------------
            # Configure Feature-set on FAN-1
            featureConfigureFan1_status = infraConfig.configureVerifyFeature(testscript.parameters['FAN-1'], fanOutFeatureList)
            if featureConfigureFan1_status['result']:
                log.info("Passed Configuring features on FAN-1")
            else:
                log.debug("Failed configuring features on FAN-1")
                configFeatureSet_msgs += featureConfigureFan1_status['log']
                configFeatureSet_status.append(0)

            ## --------------------------------
            ## Configure Feature-set on FAN-2
            #featureConfigureFan2_status = infraConfig.configureVerifyFeature(testscript.parameters['FAN-2'], fanOutFeatureList)
            #if featureConfigureFan2_status['result']:
            #    log.info("Passed Configuring features on FAN-2")
            #else:
            #    log.debug("Failed configuring features on FAN-2")
            #    configFeatureSet_msgs += featureConfigureFan2_status['log']
            #    configFeatureSet_status.append(0)

            
            if 0 in configFeatureSet_status:
                self.failed(reason=configFeatureSet_msgs, goto=['common_cleanup'])

        else:
            self.passed(reason="Skipped Device Configuration as per request")
    
    @aetest.test
    def enable_n7k_features(self, testscript):

        testscript.parameters['xbow1'].configure('''
            install feature-set fabricpath
            install feature-set fex
        ''')
        
        testscript.parameters['xbow2'].configure('''
            install feature-set fabricpath
            install feature-set fex
        ''')
        
        testscript.parameters['xbow3'].configure('''
            install feature-set fabricpath
            install feature-set fex
        ''')
        
        # testscript.parameters['n7k1'].configure('''
        #     install feature-set fabricpath
        #     install feature-set fex
        # ''')
        
        device_handle=connect_to_vdc(testscript.parameters['xbow1'], 'leaf1')
        if device_handle==False:
            log.info("failed to switchto correct vdc")
            self.failed("failed to switchto correct vdc",goto=['common_cleanup'])
        else:
            #ForkedPdb().set_trace()
            device_handle.configure('''
                feature-set fabricpath
                feature-set fex
                feature ospf
                feature ospfv3
                feature pim
                feature hsrp
                feature vpc
                feature interface-vlan
                feature lacp
                
            ''')
            #device_handle.execute("switchback",timeout=240)
        
        device_handle=connect_to_vdc(testscript.parameters['xbow1'], 'spine1')
        if device_handle==False:
            log.info("failed to switchto correct vdc")
            self.failed("failed to switchto correct vdc",goto=['common_cleanup'])
        else:
            device_handle.configure('''
            feature-set fabricpath
            feature-set fex
            feature ospf
            feature ospfv3
            feature pim
            feature hsrp
            feature vpc
            feature interface-vlan
            feature lacp
            
            ''')
        
        device_handle=connect_to_vdc(testscript.parameters['xbow2'], 'leaf2')
        if device_handle==False:
            log.info("failed to switchto correct vdc")
            self.failed("failed to switchto correct vdc",goto=['common_cleanup'])
        else:
            device_handle.configure('''
                feature-set fabricpath
                feature-set fex
                feature ospf
                feature ospfv3
                feature pim
                feature hsrp
                feature vpc
                feature interface-vlan
                feature lacp
                
            ''')
        
        device_handle=connect_to_vdc(testscript.parameters['xbow3'], 'leaf3')
        if device_handle==False:
            log.info("failed to switchto correct vdc")
            self.failed("failed to switchto correct vdc",goto=['common_cleanup'])
        else:
            device_handle.configure('''
                feature-set fabricpath
                feature-set fex
                feature ospf
                feature ospfv3
                feature pim
                feature hsrp
                feature vpc
                feature interface-vlan
                feature lacp
                
            ''')
        
        # device_handle=connect_to_vdc(testscript.parameters['xbow1'], 'spine1')
        # if device_handle==False:
        #     log.info("failed to switchto correct vdc")
        #     self.failed("failed to switchto correct vdc",goto=['common_cleanup'])
        # else:
        #     device_handle.configure('''
        #     feature-set fabricpath
        #     feature-set fex
        #     feature ospf
        #     feature ospfv3
        #     feature pim
        #     feature hsrp
        #     feature vpc
        #     feature interface-vlan
        #     feature lacp
        #     ''')
        
        device_handle=connect_to_vdc(testscript.parameters['xbow2'], 'spine2')
        if device_handle==False:
            log.info("failed to switchto correct vdc")
            self.failed("failed to switchto correct vdc",goto=['common_cleanup'])
        else:
            device_handle.configure('''
            feature-set fabricpath
            feature-set fex
            feature ospf
            feature ospfv3
            feature pim
            feature hsrp
            feature vpc
            feature interface-vlan
            feature lacp
            
        ''')
        
        device_handle=connect_to_vdc(testscript.parameters['xbow3'], 'spine3')
        if device_handle==False:
            log.info("failed to switchto correct vdc")
            self.failed("failed to switchto correct vdc",goto=['common_cleanup'])
        else:
            device_handle.configure('''
            feature-set fabricpath
            feature-set fex
            feature ospf
            feature ospfv3
            feature pim
            feature hsrp
            feature vpc
            feature interface-vlan
            feature lacp
            
        ''')
        
        device_handle=connect_to_vdc(testscript.parameters['xbow1'], 'spine4')
        if device_handle==False:
            log.info("failed to switchto correct vdc")
            self.failed("failed to switchto correct vdc",goto=['common_cleanup'])
        else:
            device_handle.configure('''
            feature-set fabricpath
            feature-set fex
            feature ospf
            feature ospfv3
            feature pim
            feature hsrp
            feature vpc
            feature interface-vlan
            feature lacp
            
        ''')


    # *****************************************************************************************************************************#

    @aetest.test
    def configure_SPINE(self, testscript):
        """ Device Bring-up subsection: Configuring SPINE """

        evpnLib.configureEVPNSpines([testscript.parameters['SPINE']], testscript.parameters['forwardingSysDict'] , testscript.parameters['leavesDictList'])

        try:
            testscript.parameters['SPINE'].configure('''
            
                interface ''' + str(testscript.parameters['intf_SPINE_to_LEAF_1']) + '''
                  channel-group ''' + str(testscript.parameters['LEAF_1_dict']['SPINE_1_UPLINK_PO']['po_id']) + ''' force mode active
                  no shutdown
                  
                interface ''' + str(testscript.parameters['intf_SPINE_to_LEAF_2']) + '''
                  channel-group ''' + str(testscript.parameters['LEAF_2_dict']['SPINE_1_UPLINK_PO']['po_id']) + ''' force mode active
                  no shutdown
                  
                interface ''' + str(testscript.parameters['intf_SPINE_to_LEAF_3']) + '''
                  channel-group ''' + str(testscript.parameters['LEAF_3_dict']['SPINE_1_UPLINK_PO']['po_id']) + ''' force mode active
                  no shutdown
                  
            ''')
        except Exception as error:
            log.debug("Unable to configure - Encountered Exception " + str(error))
            self.errored('Exception occurred while configuring on SPINE', goto=['cleanup'])

    # *****************************************************************************************************************************#
    
    @aetest.test
    def configure_LEAF_1_2(self, testscript):
        """ Device Bring-up subsection: Configuring LEAF-1 """
    
        evpnLib.configureEVPNVPCLeafs(testscript.parameters['forwardingSysDict'], testscript.parameters['leafVPCDictData'])
    
        try:
            testscript.parameters['LEAF-1'].configure('''
              vlan ''' + str(testscript.parameters['LEAF_1_dict']['VNI_data']['infra_vlan']) + '''
                                                      
              system nve infra-vlans ''' + str(testscript.parameters['LEAF_1_dict']['VNI_data']['infra_vlan']) + '''
              
              interface vlan ''' + str(testscript.parameters['LEAF_1_dict']['VNI_data']['infra_vlan']) + '''
                no shutdown
                ip address ''' + str(testscript.parameters['LEAF_1_dict']['VNI_data']['infra_vlan_ip']) + '''
                ip router ospf 1 area 0
                no ip redirects
                
              interface ''' + str(testscript.parameters['intf_LEAF_1_to_SPINE']) + '''
                channel-group ''' + str(testscript.parameters['LEAF_1_dict']['SPINE_1_UPLINK_PO']['po_id']) + ''' force mode active
                no shutdown
                
              interface ''' + str(testscript.parameters['intf_LEAF_1_to_FAN_1']) + '''
                channel-group ''' + str(testscript.parameters['LEAF_1_dict']['VPC_data']['VPC_ACC_po']) + ''' force mode active
                no shutdown
                
              interface ''' + str(testscript.parameters['intf_LEAF_1_to_LEAF_2_1']) + '''
                vrf member peer-keep-alive
                ip address ''' + str(testscript.parameters['LEAF_1_dict']['VPC_data']['kp_al_ip']) + '''/24
                no shutdown
                
              interface ''' + str(testscript.parameters['intf_LEAF_1_to_LEAF_2_2']) + '''
                channel-group ''' + str(testscript.parameters['LEAF_1_dict']['VPC_data']['peer_link_po']) + ''' force mode active
                no shutdown
                
              interface ''' + str(testscript.parameters['intf_LEAF_1_to_N7k_LEAF_1_1']) + '''
                switchport
                switchport mode trunk
                channel-group ''' + str(testscript.parameters['LEAF_1_dict']['VPC_data']['double_vpc_po_1']) + ''' force mode active
                no shutdown
                
              interface ''' + str(testscript.parameters['intf_LEAF_1_to_N7k_LEAF_2_1']) + '''
                switchport
                switchport mode trunk
                channel-group ''' + str(testscript.parameters['LEAF_1_dict']['VPC_data']['double_vpc_po_1']) + ''' force mode active
                no shutdown
                
              interface po ''' + str(testscript.parameters['LEAF_1_dict']['VPC_data']['double_vpc_po_1']) + '''
                switchport
                switchport mode trunk
                vpc ''' + str(testscript.parameters['LEAF_1_dict']['VPC_data']['double_vpc_po_1']) 
                
             )
        except Exception as error:
            log.debug("Unable to configure - Encountered Exception " + str(error))
            self.errored('Exception occurred while configuring on LEAF-1', goto=['cleanup'])
    
        try:
            testscript.parameters['LEAF-2'].configure('''
              vlan ''' + str(testscript.parameters['LEAF_2_dict']['VNI_data']['infra_vlan']) + '''
              
              system nve infra-vlans ''' + str(testscript.parameters['LEAF_2_dict']['VNI_data']['infra_vlan']) + '''
              
              interface vlan ''' + str(testscript.parameters['LEAF_2_dict']['VNI_data']['infra_vlan']) + '''
                no shutdown
                ip address ''' + str(testscript.parameters['LEAF_2_dict']['VNI_data']['infra_vlan_ip']) + '''
                ip router ospf 1 area 0
                no ip redirects                                        
                
              interface ''' + str(testscript.parameters['intf_LEAF_2_to_SPINE']) + '''
                channel-group ''' + str(testscript.parameters['LEAF_2_dict']['SPINE_1_UPLINK_PO']['po_id']) + ''' force mode active
                no shutdown
                
              interface ''' + str(testscript.parameters['intf_LEAF_2_to_FAN_1']) + '''
                channel-group ''' + str(testscript.parameters['LEAF_2_dict']['VPC_data']['VPC_ACC_po']) + ''' force mode active
                no shutdown
                
              interface ''' + str(testscript.parameters['intf_LEAF_2_to_LEAF_1_1']) + '''
                vrf member peer-keep-alive
                ip address ''' + str(testscript.parameters['LEAF_2_dict']['VPC_data']['kp_al_ip']) + '''/24
                no shutdown
                
              interface ''' + str(testscript.parameters['intf_LEAF_2_to_LEAF_1_2']) + '''
                channel-group ''' + str(testscript.parameters['LEAF_2_dict']['VPC_data']['peer_link_po']) + ''' force mode active
                no shutdown
                
              interface ''' + str(testscript.parameters['intf_LEAF_2_to_N7k_LEAF_1_1']) + '''
                switchport
                switchport mode trunk
                channel-group ''' + str(testscript.parameters['LEAF_2_dict']['VPC_data']['double_vpc_po_1']) + ''' force mode active
                no shutdown
                
              interface ''' + str(testscript.parameters['intf_LEAF_2_to_N7k_LEAF_2_1']) + '''
                switchport
                switchport mode trunk
                channel-group ''' + str(testscript.parameters['LEAF_2_dict']['VPC_data']['double_vpc_po_1']) + ''' force mode active
                no shutdown
                
              interface po ''' + str(testscript.parameters['LEAF_2_dict']['VPC_data']['double_vpc_po_1']) + '''
                switchport
                switchport mode trunk
                vpc ''' + str(testscript.parameters['LEAF_1_dict']['VPC_data']['double_vpc_po_1']) + '''
                
              interface ''' + str(testscript.parameters['intf_LEAF_2_to_FO_1']) + '''
                    switchport
                    switchport mode trunk
                    no shutdown
          ''')
        except Exception as error:
            log.debug("Unable to configure - Encountered Exception " + str(error))
            self.errored('Exception occurred while configuring on LEAF-2', goto=['cleanup'])
    
    # *****************************************************************************************************************************#
    
    @aetest.test
    def configure_LEAF_3(self, testscript):
        """ Device Bring-up subsection: Configuring LEAF-3 """
    
        evpnLib.configureEVPNLeaf(testscript.parameters['LEAF-3'], testscript.parameters['forwardingSysDict'], testscript.parameters['LEAF_3_dict'])
    
        try:
            testscript.parameters['LEAF-3'].configure('''
                
                interface ''' + str(testscript.parameters['intf_LEAF_3_to_SPINE']) + '''
                  channel-group ''' + str(testscript.parameters['LEAF_3_dict']['SPINE_1_UPLINK_PO']['po_id']) + ''' force mode active
                  no shutdown
                
                interface ''' + str(testscript.parameters['intf_LEAF_3_to_FO_1']) + '''
                  switchport
                  switchport mode trunk
                  no shutdown
                  
                
                
                
          ''')
        except Exception as error:
            log.debug("Unable to configure - Encountered Exception " + str(error))
            self.errored('Exception occurred while configuring on LEAF-3', goto=['cleanup'])
    
    # *****************************************************************************************************************************#
    
    @aetest.test
    def configure_FAN_1(self, testscript):
        """ Device Bring-up subsection: Configuring FAN_1 """
    
        # Do not perform configurations if skip_device_config flag is set
        if not testscript.parameters['script_flags']['skip_device_config']:
    
            fanOut1_vlanConfiguration = ""
    
            l3_vrf_count_iter = 0
            l2_vlan_id = testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vlan_start']
            l3_vlan_id = testscript.parameters['LEAF_1_dict']['VNI_data']['l3_vlan_start']
    
            while l3_vrf_count_iter < testscript.parameters['forwardingSysDict']['VRF_count']:
                l2_vlan_count_iter = 0
                fanOut1_vlanConfiguration += '''vlan ''' + str(l3_vlan_id) + '''\n
                                                state active\n
                                                no shut\n'''
                while l2_vlan_count_iter < testscript.parameters['forwardingSysDict']['VLAN_PER_VRF_count']:
                    # Incrementing L2 VLAN Iteration counters
                    fanOut1_vlanConfiguration += '''vlan ''' + str(l2_vlan_id) + '''\n
                                                    state active\n
                                                    no shut\n'''
                    l2_vlan_count_iter += 1
                    l2_vlan_id += 1
                # Incrementing L3 VRF Iteration counters
                l3_vrf_count_iter += 1
                l3_vlan_id += 1
    
            try:
                testscript.parameters['FAN-1'].configure(
                    str(fanOut1_vlanConfiguration) + '''
    
                                    interface port-channel200
                                      switchport
                                      switchport mode trunk
                                      no shutdown
    
                                    interface {0}
                                      channel-group 200 force mode active
                                      no shutdown
    
                                    interface {1}
                                      channel-group 200 force mode active
                                      no shutdown
    
                                    interface {2}
                                      switchport
                                      switchport mode trunk
                                      no shut
    
                                '''.format(testscript.parameters['intf_FAN_1_to_LEAF_1'],
                                           testscript.parameters['intf_FAN_1_to_LEAF_2'],
                                           testscript.parameters['intf_FAN_1_to_IXIA']))
            except Exception as error:
                log.debug("Unable to configure - Encountered Exception " + str(error))
                self.errored('Exception occurred while configuring on FAN-1', goto=['common_cleanup'])
        else:
            self.passed(reason="Skipped Device Configurations as per Request")

    # *****************************************************************************************************************************#

    @aetest.test
    def configure_leaf1(self, testscript):
        """ Device Bring-up subsection: Configuring N7k leaf1"""

        # Do not perform configurations if skip_device_config flag is set
        if not testscript.parameters['script_flags']['skip_device_config']:

            leaf1_vlanConfiguration = ""

            l3_vrf_count_iter = 0
            l2_vlan_id = testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vlan_start']
            l3_vlan_id = testscript.parameters['LEAF_1_dict']['VNI_data']['l3_vlan_start']

            while l3_vrf_count_iter < testscript.parameters['forwardingSysDict']['VRF_count']:
                l2_vlan_count_iter = 0
                leaf1_vlanConfiguration += '''vlan ''' + str(l3_vlan_id) + '''\n
                                                mode fabricpath\n
                                                no shut\n'''
                while l2_vlan_count_iter < testscript.parameters['forwardingSysDict']['VLAN_PER_VRF_count']:
                    # Incrementing L2 VLAN Iteration counters
                    leaf1_vlanConfiguration += '''vlan ''' + str(l2_vlan_id) + '''\n
                                                    mode fabricpath\n
                                                    no shut\n
                                                  spanning-tree vlan ''' + str(l2_vlan_id) + ''' priority 8192\n'''
                    l2_vlan_count_iter += 1
                    l2_vlan_id += 1
                # Incrementing L3 VRF Iteration counters
                l3_vrf_count_iter += 1
                l3_vlan_id += 1
                
                
            #log.info("@@@@@@@@@@@@@@@@@@@@@@@@@@@")
            #log.info(str(leaf1_vlanConfiguration))
            #log.info("@@@@@@@@@@@@@@@@@@@@@@@@@@")
            dialog = Dialog([
                       Statement(pattern=r'Do you want to continue \(y\/n\)\? \[n\] ',
                                 action='sendline(y)',
                                 loop_continue=True,
                                 continue_timer=True),
                       Statement(pattern=r'Continue \(yes\/no\)\? \[no\]',
                                 action='sendline(yes)',
                                 loop_continue=True,
                                 continue_timer=True)
                          ])

            try:
                device_handle=connect_to_vdc(testscript.parameters['xbow1'], 'leaf1')
                log.info("-----"+str(device_handle)+"------")
                #device_handle.configure("fabricpath switch-id 10")
                if device_handle==False:
                    log.info("failed to switchto correct vdc")
                    self.failed("failed to switchto correct vdc",goto=['common_cleanup'])
                else:
                    device_handle.configure(
                            str(leaf1_vlanConfiguration))
                    device_handle.configure('''
                                    fabricpath switch-id 10
                                    
                                    vrf context kpalive
                                      no shut
                                      
                                    interface {0}
                                      vrf member kpalive
                                      no shut
                                      ip address 5.5.6.10/24 
                                    
                                    vpc domain 2
                                    role priority 100
                                    peer-keepalive destination 5.5.6.5 source 5.5.6.10 vrf kpalive
                                    peer-gateway
                                    fabricpath multicast load-balance
                                    fabricpath switch-id 1000
                                    no port-channel limit
                                    
                                    interface port-channel4096
                                      switchport
                                      switchport mode fabricpath
                                      vpc peer-link
                                    
                                    interface port-channel4
                                      switchport
                                      switchport mode trunk
                                      no shutdown
                                      vpc 4
                
                                    interface {1}
                                      switchport
                                      switchport mode fabricpath
                                      channel-group 4096 mode active
                                      no shutdown
                
                                    interface {2}
                                      switchport
                                      switchport mode trunk
                                      channel-group 4 mode active
                                      no shutdown
                
                                    interface {3}
                                      switchport
                                      switchport mode trunk
                                      channel-group 4 mode active
                                      no shutdown
                                      
                                    interface {4}
                                      switchport
                                      switchport mode fabricpath
                                      no shutdown
                                      
                                    interface {5}
                                      switchport
                                      switchport mode fabricpath
                                      no shutdown
                                      
                                    interface {6}
                                      switchport
                                      switchport mode fabricpath
                                      no shutdown
                                      
                                    interface {7}
                                      switchport
                                      switchport mode fabricpath
                                      no shutdown
                                      
                                    interface {8}
                                      switchport
                                      switchport mode trunk
                                      no shutdown
                                      
                                    
                
                                '''.format(testscript.parameters['intf_N7k_LEAF_1_to_N7k_LEAF_2_2'].intf,
                                           testscript.parameters['intf_N7k_LEAF_1_to_N7k_LEAF_2_1'].intf,
                                           testscript.parameters['intf_N7k_LEAF_1_to_LEAF_1_1'].intf,
                                           testscript.parameters['intf_N7k_LEAF_1_to_LEAF_2_1'].intf,
                                           testscript.parameters['intf_N7k_LEAF_1_to_SPINE_1'].intf,
                                           testscript.parameters['intf_N7k_LEAF_1_to_SPINE_2'].intf,
                                           testscript.parameters['intf_N7k_LEAF_1_to_SPINE_3'].intf,
                                           testscript.parameters['intf_N7k_LEAF_1_to_SPINE_4'].intf,
                                           testscript.parameters['intf_N7k_LEAF_1_to_IXIA'].intf),reply=dialog)
            except Exception as error:
                log.debug("Unable to configure - Encountered Exception " + str(error))
                self.errored('Exception occurred while configuring on N7k Leaf1', goto=['common_cleanup'])
        else:
            self.passed(reason="Skipped Device Configurations as per Request")
            
# *****************************************************************************************************************************#

    @aetest.test
    def configure_leaf2(self, testscript):
        """ Device Bring-up subsection: Configuring N7k leaf2"""

        # Do not perform configurations if skip_device_config flag is set
        if not testscript.parameters['script_flags']['skip_device_config']:

            leaf2_vlanConfiguration = ""

            l3_vrf_count_iter = 0
            l2_vlan_id = testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vlan_start']
            l3_vlan_id = testscript.parameters['LEAF_1_dict']['VNI_data']['l3_vlan_start']

            while l3_vrf_count_iter < testscript.parameters['forwardingSysDict']['VRF_count']:
                l2_vlan_count_iter = 0
                leaf2_vlanConfiguration += '''vlan ''' + str(l3_vlan_id) + '''\n
                                                mode fabricpath\n
                                                no shut\n'''
                while l2_vlan_count_iter < testscript.parameters['forwardingSysDict']['VLAN_PER_VRF_count']:
                    # Incrementing L2 VLAN Iteration counters
                    leaf2_vlanConfiguration += '''vlan ''' + str(l2_vlan_id) + '''\n
                                                    mode fabricpath\n
                                                    no shut\n
                                                  spanning-tree vlan ''' + str(l2_vlan_id) + ''' priority 8192\n'''
                    l2_vlan_count_iter += 1
                    l2_vlan_id += 1
                # Incrementing L3 VRF Iteration counters
                l3_vrf_count_iter += 1
                l3_vlan_id += 1
                
            #log.info("@@@@@@@@@@@@@@@@@@@@@@@@@@@")
            #log.info(str(leaf1_vlanConfiguration))
            #log.info("@@@@@@@@@@@@@@@@@@@@@@@@@@")
            
            dialog = Dialog([
                       Statement(pattern=r'Do you want to continue \(y\/n\)\? \[n\] ',
                                 action='sendline(y)',
                                 loop_continue=True,
                                 continue_timer=True),
                       Statement(pattern=r'Continue \(yes\/no\)\? \[no\]',
                                 action='sendline(yes)',
                                 loop_continue=True,
                                 continue_timer=True)
                          ])

            try:
                device_handle=connect_to_vdc(testscript.parameters['xbow2'], 'leaf2')
                log.info("-----"+str(device_handle)+"------")
                if device_handle==False:
                    log.info("failed to switchto correct vdc")
                    self.failed("failed to switchto correct vdc",goto=['common_cleanup'])
                else:
                    device_handle.configure(
                    str(leaf2_vlanConfiguration) + '''
                                    fabricpath switch-id 11
                                    
                                    vrf context kpalive
                                      no shut
                                      
                                    interface {0}
                                      vrf member kpalive
                                      no shut
                                      ip address 5.5.6.5/24 
                                    
                                    vpc domain 2
                                    role priority 100
                                    peer-keepalive destination 5.5.6.10 source 5.5.6.5 vrf kpalive
                                    peer-gateway
                                    fabricpath multicast load-balance
                                    fabricpath switch-id 1000
                                    no port-channel limit
                                    
                                    interface port-channel4096
                                      switchport
                                      switchport mode fabricpath
                                      vpc peer-link
                                    
                                    interface port-channel4
                                      switchport
                                      switchport mode trunk
                                      no shutdown
                                      vpc 4

                                    interface {1}
                                      switchport
                                      switchport mode fabricpath
                                      channel-group 4096 mode active
                                      no shutdown

                                    interface {2}
                                      switchport
                                      switchport mode trunk
                                      channel-group 4 mode active
                                      no shutdown

                                    interface {3}
                                      switchport
                                      switchport mode trunk
                                      channel-group 4 mode active
                                      no shutdown
                                      
                                    interface {4}
                                      switchport
                                      switchport mode fabricpath
                                      no shutdown
                                      
                                    interface {5}
                                      switchport
                                      switchport mode fabricpath
                                      no shutdown
                                      
                                    interface {6}
                                      switchport
                                      switchport mode fabricpath
                                      no shutdown
                                      
                                    interface {7}
                                      switchport
                                      switchport mode fabricpath
                                      no shutdown

                                '''.format(testscript.parameters['intf_N7k_LEAF_2_to_N7k_LEAF_1_2'].intf,
                                           testscript.parameters['intf_N7k_LEAF_2_to_N7k_LEAF_1_1'].intf,
                                           testscript.parameters['intf_N7k_LEAF_2_to_LEAF_1_1'].intf,
                                           testscript.parameters['intf_N7k_LEAF_2_to_LEAF_2_1'].intf,
                                           testscript.parameters['intf_N7k_LEAF_2_to_SPINE_1'].intf,
                                           testscript.parameters['intf_N7k_LEAF_2_to_SPINE_2'].intf,
                                           testscript.parameters['intf_N7k_LEAF_2_to_SPINE_3'].intf,
                                           testscript.parameters['intf_N7k_LEAF_2_to_SPINE_4'].intf), reply=dialog)
            except Exception as error:
                log.debug("Unable to configure - Encountered Exception " + str(error))
                self.errored('Exception occurred while configuring on N7k Leaf2', goto=['common_cleanup'])
        else:
            self.passed(reason="Skipped Device Configurations as per Request")
            


# *****************************************************************************************************************************#

    @aetest.test
    def configure_leaf3(self, testscript):
        """ Device Bring-up subsection: Configuring N7k leaf3"""

        # Do not perform configurations if skip_device_config flag is set
        if not testscript.parameters['script_flags']['skip_device_config']:

            leaf3_vlanConfiguration = ""

            l3_vrf_count_iter = 0
            l2_vlan_id = testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vlan_start']
            l3_vlan_id = testscript.parameters['LEAF_1_dict']['VNI_data']['l3_vlan_start']

            while l3_vrf_count_iter < testscript.parameters['forwardingSysDict']['VRF_count']:
                l2_vlan_count_iter = 0
                leaf3_vlanConfiguration += '''vlan ''' + str(l3_vlan_id) + '''\n
                                                mode fabricpath\n
                                                no shut\n'''
                while l2_vlan_count_iter < testscript.parameters['forwardingSysDict']['VLAN_PER_VRF_count']:
                    # Incrementing L2 VLAN Iteration counters
                    leaf3_vlanConfiguration += '''vlan ''' + str(l2_vlan_id) + '''\n
                                                    mode fabricpath\n
                                                    no shut\n'''
                    l2_vlan_count_iter += 1
                    l2_vlan_id += 1
                # Incrementing L3 VRF Iteration counters
                l3_vrf_count_iter += 1
                l3_vlan_id += 1

            try:
                device_handle=connect_to_vdc(testscript.parameters['xbow3'], 'leaf3')
                if device_handle==False:
                    log.info("failed to switchto correct vdc")
                    self.failed("failed to switchto correct vdc",goto=['common_cleanup'])
                else:
                    device_handle.configure(
                    str(leaf3_vlanConfiguration) + '''
                                    fabricpath switch-id 12
                                    

                                    interface {0}
                                      switchport
                                      switchport mode fabricpath
                                      no shutdown
                                    
                                    interface {1}
                                      switchport
                                      switchport mode fabricpath
                                      no shutdown
                                    
                                    interface {2}
                                      switchport
                                      switchport mode fabricpath
                                      no shutdown
                                      
                                    interface {3}
                                      switchport
                                      switchport mode trunk
                                      no shutdown


                                '''.format(testscript.parameters['intf_N7k_LEAF_3_to_SPINE_1'].intf,
                                           testscript.parameters['intf_N7k_LEAF_3_to_SPINE_2'].intf,
                                           testscript.parameters['intf_N7k_LEAF_3_to_SPINE_3'].intf,
                                           testscript.parameters['intf_N7k_LEAF_3_to_FO_1'].intf))
            except Exception as error:
                log.debug("Unable to configure - Encountered Exception " + str(error))
                self.errored('Exception occurred while configuring on N7k Leaf3', goto=['common_cleanup'])
        else:
            self.passed(reason="Skipped Device Configurations as per Request")
            
# *****************************************************************************************************************************#

    @aetest.test
    def configure_spine1(self, testscript):
        """ Device Bring-up subsection: Configuring N7k spine1"""

        # Do not perform configurations if skip_device_config flag is set
        if not testscript.parameters['script_flags']['skip_device_config']:

            spine1_vlanConfiguration = ""

            l3_vrf_count_iter = 0
            l2_vlan_id = testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vlan_start']
            l3_vlan_id = testscript.parameters['LEAF_1_dict']['VNI_data']['l3_vlan_start']

            while l3_vrf_count_iter < testscript.parameters['forwardingSysDict']['VRF_count']:
                l2_vlan_count_iter = 0
                spine1_vlanConfiguration += '''vlan ''' + str(l3_vlan_id) + '''\n
                                                mode fabricpath\n
                                                no shut\n'''
                while l2_vlan_count_iter < testscript.parameters['forwardingSysDict']['VLAN_PER_VRF_count']:
                    # Incrementing L2 VLAN Iteration counters
                    spine1_vlanConfiguration += '''vlan ''' + str(l2_vlan_id) + '''\n
                                                    mode fabricpath\n
                                                    no shut\n'''
                    l2_vlan_count_iter += 1
                    l2_vlan_id += 1
                # Incrementing L3 VRF Iteration counters
                l3_vrf_count_iter += 1
                l3_vlan_id += 1

            try:
                device_handle=connect_to_vdc(testscript.parameters['xbow1'], 'spine1')
                if device_handle==False:
                    log.info("failed to switchto correct vdc")
                    self.failed("failed to switchto correct vdc",goto=['common_cleanup'])
                else:
                    device_handle.configure(
                    str(spine1_vlanConfiguration) + '''
                                    fabricpath switch-id 21
                                    

                                    interface {0}
                                      switchport
                                      switchport mode fabricpath
                                      no shutdown
                                    
                                    interface {1}
                                      switchport
                                      switchport mode fabricpath
                                      no shutdown
                                    
                                    interface {2}
                                      switchport
                                      switchport mode fabricpath
                                      no shutdown


                                '''.format(testscript.parameters['intf_N7k_SPINE_1_to_N7k_LEAF_1'].intf,
                                           testscript.parameters['intf_N7k_SPINE_1_to_N7k_LEAF_2'].intf,
                                           testscript.parameters['intf_N7k_SPINE_1_to_N7k_LEAF_3'].intf))
            except Exception as error:
                log.debug("Unable to configure - Encountered Exception " + str(error))
                self.errored('Exception occurred while configuring on N7k spine1', goto=['common_cleanup'])
        else:
            self.passed(reason="Skipped Device Configurations as per Request")
            
# *****************************************************************************************************************************#

    @aetest.test
    def configure_spine4(self, testscript):
        """ Device Bring-up subsection: Configuring N7k leaf3"""
    
        # Do not perform configurations if skip_device_config flag is set
        if not testscript.parameters['script_flags']['skip_device_config']:
    
            spine4_vlanConfiguration = ""
    
            l3_vrf_count_iter = 0
            l2_vlan_id = testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vlan_start']
            l3_vlan_id = testscript.parameters['LEAF_1_dict']['VNI_data']['l3_vlan_start']
    
            while l3_vrf_count_iter < testscript.parameters['forwardingSysDict']['VRF_count']:
                l2_vlan_count_iter = 0
                spine4_vlanConfiguration += '''vlan ''' + str(l3_vlan_id) + '''\n
                                                mode fabricpath\n
                                                no shut\n'''
                while l2_vlan_count_iter < testscript.parameters['forwardingSysDict']['VLAN_PER_VRF_count']:
                    # Incrementing L2 VLAN Iteration counters
                    spine4_vlanConfiguration += '''vlan ''' + str(l2_vlan_id) + '''\n
                                                    mode fabricpath\n
                                                    no shut\n'''
                    l2_vlan_count_iter += 1
                    l2_vlan_id += 1
                # Incrementing L3 VRF Iteration counters
                l3_vrf_count_iter += 1
                l3_vlan_id += 1
    
            try:
                device_handle=connect_to_vdc(testscript.parameters['xbow1'], 'spine4')
                if device_handle==False:
                    log.info("failed to switchto correct vdc")
                    self.failed("failed to switchto correct vdc",goto=['common_cleanup'])
                else:
                    device_handle.configure(
                    str(spine4_vlanConfiguration) + '''
                                    fabricpath switch-id 24
                                    
    
                                    interface {0}
                                      switchport
                                      switchport mode fabricpath
                                      no shutdown
                                    
                                    interface {1}
                                      switchport
                                      switchport mode fabricpath
                                      no shutdown
    
    
                                '''.format(testscript.parameters['intf_N7k_SPINE_4_to_N7k_LEAF_1'].intf,
                                           testscript.parameters['intf_N7k_SPINE_4_to_N7k_LEAF_2'].intf))
            except Exception as error:
                log.debug("Unable to configure - Encountered Exception " + str(error))
                self.errored('Exception occurred while configuring on N7k spine3', goto=['common_cleanup'])
        else:
            self.passed(reason="Skipped Device Configurations as per Request")
            
# *****************************************************************************************************************************#

    @aetest.test
    def configure_spine2(self, testscript):
        """ Device Bring-up subsection: Configuring N7k spine2"""

        # Do not perform configurations if skip_device_config flag is set
        if not testscript.parameters['script_flags']['skip_device_config']:

            spine2_vlanConfiguration = ""

            l3_vrf_count_iter = 0
            l2_vlan_id = testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vlan_start']
            l3_vlan_id = testscript.parameters['LEAF_1_dict']['VNI_data']['l3_vlan_start']

            while l3_vrf_count_iter < testscript.parameters['forwardingSysDict']['VRF_count']:
                l2_vlan_count_iter = 0
                spine2_vlanConfiguration += '''vlan ''' + str(l3_vlan_id) + '''\n
                                                mode fabricpath\n
                                                no shut\n'''
                while l2_vlan_count_iter < testscript.parameters['forwardingSysDict']['VLAN_PER_VRF_count']:
                    # Incrementing L2 VLAN Iteration counters
                    spine2_vlanConfiguration += '''vlan ''' + str(l2_vlan_id) + '''\n
                                                    mode fabricpath\n
                                                    no shut\n'''
                    l2_vlan_count_iter += 1
                    l2_vlan_id += 1
                # Incrementing L3 VRF Iteration counters
                l3_vrf_count_iter += 1
                l3_vlan_id += 1

            try:
                device_handle=connect_to_vdc(testscript.parameters['xbow2'], 'spine2')
                if device_handle==False:
                    log.info("failed to switchto correct vdc")
                    self.failed("failed to switchto correct vdc",goto=['common_cleanup'])
                else:
                    device_handle.configure(
                    str(spine2_vlanConfiguration) + '''
                                    fabricpath switch-id 22
                                    

                                    interface {0}
                                      switchport
                                      switchport mode fabricpath
                                      no shutdown
                                    
                                    interface {1}
                                      switchport
                                      switchport mode fabricpath
                                      no shutdown
                                    
                                    interface {2}
                                      switchport
                                      switchport mode fabricpath
                                      no shutdown


                                '''.format(testscript.parameters['intf_N7k_SPINE_2_to_N7k_LEAF_1'].intf,
                                           testscript.parameters['intf_N7k_SPINE_2_to_N7k_LEAF_2'].intf,
                                           testscript.parameters['intf_N7k_SPINE_2_to_N7k_LEAF_3'].intf))
            except Exception as error:
                log.debug("Unable to configure - Encountered Exception " + str(error))
                self.errored('Exception occurred while configuring on N7k spine2', goto=['common_cleanup'])
        else:
            self.passed(reason="Skipped Device Configurations as per Request")
            
# *****************************************************************************************************************************#

    @aetest.test
    def configure_spine3(self, testscript):
        """ Device Bring-up subsection: Configuring N7k spine3"""

        # Do not perform configurations if skip_device_config flag is set
        if not testscript.parameters['script_flags']['skip_device_config']:

            spine3_vlanConfiguration = ""

            l3_vrf_count_iter = 0
            l2_vlan_id = testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vlan_start']
            l3_vlan_id = testscript.parameters['LEAF_1_dict']['VNI_data']['l3_vlan_start']

            while l3_vrf_count_iter < testscript.parameters['forwardingSysDict']['VRF_count']:
                l2_vlan_count_iter = 0
                spine3_vlanConfiguration += '''vlan ''' + str(l3_vlan_id) + '''\n
                                                mode fabricpath\n
                                                no shut\n'''
                while l2_vlan_count_iter < testscript.parameters['forwardingSysDict']['VLAN_PER_VRF_count']:
                    # Incrementing L2 VLAN Iteration counters
                    spine3_vlanConfiguration += '''vlan ''' + str(l2_vlan_id) + '''\n
                                                    mode fabricpath\n
                                                    no shut\n'''
                    l2_vlan_count_iter += 1
                    l2_vlan_id += 1
                # Incrementing L3 VRF Iteration counters
                l3_vrf_count_iter += 1
                l3_vlan_id += 1

            try:
                device_handle=connect_to_vdc(testscript.parameters['xbow3'], 'spine3')
                if device_handle==False:
                    log.info("failed to switchto correct vdc")
                    self.failed("failed to switchto correct vdc",goto=['common_cleanup'])
                else:
                    device_handle.configure(
                    str(spine3_vlanConfiguration) + '''
                                    fabricpath switch-id 23
                                    

                                    interface {0}
                                      switchport
                                      switchport mode fabricpath
                                      no shutdown
                                    
                                    interface {1}
                                      switchport
                                      switchport mode fabricpath
                                      no shutdown
                                    
                                    interface {2}
                                      switchport
                                      switchport mode fabricpath
                                      no shutdown


                                '''.format(testscript.parameters['intf_N7k_SPINE_3_to_N7k_LEAF_1'].intf,
                                           testscript.parameters['intf_N7k_SPINE_3_to_N7k_LEAF_2'].intf,
                                           testscript.parameters['intf_N7k_SPINE_3_to_N7k_LEAF_3'].intf))
            except Exception as error:
                log.debug("Unable to configure - Encountered Exception " + str(error))
                self.errored('Exception occurred while configuring on N7k spine3', goto=['common_cleanup'])
        else:
            self.passed(reason="Skipped Device Configurations as per Request")
            
# *****************************************************************************************************************************#

    
    # =============================================================================================================================#        
    
    @aetest.test
    def Configure_SVI_N7k_Leaf1(self, testscript):
        """configure the svi on the N7k1 Leaf1"""
        
        LEAF_1 = testscript.parameters['LEAF-1']
        LEAF_2 = testscript.parameters['LEAF-2']
        forwardingSysDict = testscript.parameters['forwardingSysDict']
        l2_vlan_id = testscript.parameters['N7K_LEAF_1_dict']['Vlan_data']['l2_vlan_start']
        l2_vlan_ipv4_start= testscript.parameters['N7K_LEAF_1_dict']['Vlan_data']['l2_vlan_ipv4_start']
        l2_vlan_ipv4_mask= testscript.parameters['N7K_LEAF_1_dict']['Vlan_data']['l2_vlan_ipv4_mask']
        l2_vlan_ipv6_start= testscript.parameters['N7K_LEAF_1_dict']['Vlan_data']['l2_vlan_ipv6_start']
        l2_vlan_ipv6_mask= testscript.parameters['N7K_LEAF_1_dict']['Vlan_data']['l2_vlan_ipv6_mask']
        l2_hsrp_ipv4_vip_start= testscript.parameters['N7K_LEAF_1_dict']['Vlan_data']['hsrp_ipv4_vip_start']
        l2_hsrp_ipv6_vip_start= testscript.parameters['N7K_LEAF_1_dict']['Vlan_data']['hsrp_ipv6_vip_start']
        
        #try:
        device_handle=connect_to_vdc(testscript.parameters['xbow1'], 'leaf1')
        if device_handle==False:
            log.info("failed to switchto correct vdc")
            self.failed("failed to switchto correct vdc",goto=['common_cleanup'])
        else:
            total_ip_count = int(forwardingSysDict['VLAN_PER_VRF_count']) * int(forwardingSysDict['VRF_count'])
            l2_ipv4s = increment_prefix_network(ip.IPv4Interface(str(l2_vlan_ipv4_start) + str(l2_vlan_ipv4_mask)),total_ip_count)
            l2_ipv6s = increment_prefix_network(ip.IPv6Interface(str(l2_vlan_ipv6_start) + str(l2_vlan_ipv6_mask)),total_ip_count)
            vip_ipv4s= increment_v4_vip(str(l2_hsrp_ipv4_vip_start),total_ip_count)
            vip_ipv6s= increment_v6_vip(str(l2_hsrp_ipv6_vip_start),total_ip_count)
            ip_index=0
            for i in range(0,len(l2_ipv4s)):
                device_handle.configure('''int vlan ''' + str(l2_vlan_id) + '''\n
                                 no shut
                                 ip address ''' + str(l2_ipv4s[ip_index]) + '''
                                 ipv6 address ''' + str(l2_ipv6s[ip_index]) + '''
                                 no ip redirects
                                 no ipv6 redirects
                                 hsrp version 2
                                 hsrp ''' + str(l2_vlan_id) + ''' ipv4
                                 ip ''' + str(vip_ipv4s[ip_index]) + '''
                                 hsrp ''' + str(l2_vlan_id) + ''' ipv6
                                 ip ''' + str(vip_ipv6s[ip_index]) + '''
                                 ''')
                l2_vlan_id += 1
                ip_index += 1


        #except Exception as error:
        #        log.debug("Unable to configure - Encountered Exception " + str(error))
        #        self.errored('Exception occurred while configuring on N7k leaf1', goto=['common_cleanup'])
    
    @aetest.test
    def Configure_SVI_N7k_Leaf2(self, testscript):
        """configure the svi on the N7k1 Leaf1"""
        
        LEAF_1 = testscript.parameters['LEAF-1']
        LEAF_2 = testscript.parameters['LEAF-2']
        forwardingSysDict = testscript.parameters['forwardingSysDict']
        l2_vlan_id = testscript.parameters['N7K_LEAF_2_dict']['Vlan_data']['l2_vlan_start']
        l2_vlan_ipv4_start= testscript.parameters['N7K_LEAF_2_dict']['Vlan_data']['l2_vlan_ipv4_start']
        l2_vlan_ipv4_mask= testscript.parameters['N7K_LEAF_2_dict']['Vlan_data']['l2_vlan_ipv4_mask']
        l2_vlan_ipv6_start= testscript.parameters['N7K_LEAF_2_dict']['Vlan_data']['l2_vlan_ipv6_start']
        l2_vlan_ipv6_mask= testscript.parameters['N7K_LEAF_2_dict']['Vlan_data']['l2_vlan_ipv6_mask']
        l2_hsrp_ipv4_vip_start= testscript.parameters['N7K_LEAF_2_dict']['Vlan_data']['hsrp_ipv4_vip_start']
        l2_hsrp_ipv6_vip_start= testscript.parameters['N7K_LEAF_2_dict']['Vlan_data']['hsrp_ipv6_vip_start']
        
        try:
            device_handle=connect_to_vdc(testscript.parameters['xbow2'], 'leaf2')
            if device_handle==False:
                log.info("failed to switchto correct vdc")
                self.failed("failed to switchto correct vdc",goto=['common_cleanup'])
            else:
                total_ip_count = int(forwardingSysDict['VLAN_PER_VRF_count']) * int(forwardingSysDict['VRF_count'])
                l2_ipv4s = increment_prefix_network(ip.IPv4Interface(str(l2_vlan_ipv4_start) + str(l2_vlan_ipv4_mask)),total_ip_count)
                l2_ipv6s = increment_prefix_network(ip.IPv6Interface(str(l2_vlan_ipv6_start) + str(l2_vlan_ipv6_mask)),total_ip_count)
                #vip_ipv4s= increment_prefix_network(ip.IPv4Interface(str(l2_hsrp_ipv4_vip_start)),total_ip_count)
                #vip_ipv6s= increment_prefix_network(ip.IPv6Interface(str(l2_hsrp_ipv6_vip_start)),total_ip_count)
                vip_ipv4s= increment_v4_vip(str(l2_hsrp_ipv4_vip_start),total_ip_count)
                vip_ipv6s= increment_v6_vip(str(l2_hsrp_ipv6_vip_start),total_ip_count)
                ip_index=0
                for i in range(0,len(l2_ipv4s)):
                    device_handle.configure('''int vlan ''' + str(l2_vlan_id) + '''\n
                                     no shut
                                     ip address ''' + str(l2_ipv4s[ip_index]) + '''
                                     ipv6 address ''' + str(l2_ipv6s[ip_index]) + '''
                                     no ip redirects
                                     no ipv6 redirects
                                     hsrp version 2
                                     hsrp ''' + str(l2_vlan_id) + ''' ipv4
                                     ip ''' + str(vip_ipv4s[ip_index]) + '''
                                     hsrp ''' + str(l2_vlan_id) + ''' ipv6
                                     ip ''' + str(vip_ipv6s[ip_index]) + '''
                                     ''')
                    l2_vlan_id += 1
                    ip_index += 1


        except Exception as error:
                log.debug("Unable to configure - Encountered Exception " + str(error))
                self.errored('Exception occurred while configuring on N7k leaf2', goto=['common_cleanup'])
    # =============================================================================================================================#        
    
    @aetest.test
    def Remove_external_int(self, testscript):
        """Shut down the vpc leg on Leaf2 to force all traffic to Leaf1"""
        
        LEAF_1 = testscript.parameters['LEAF-1']
        LEAF_2 = testscript.parameters['LEAF-2']
        
        try:
            testscript.parameters['LEAF-2'].configure('''
                  interface po ''' + str(testscript.parameters['LEAF_1_dict']['VPC_data']['double_vpc_po_1']) + '''
                  no port-type external
                  ''')
            
            testscript.parameters['LEAF-1'].configure('''
                  interface po ''' + str(testscript.parameters['LEAF_1_dict']['VPC_data']['double_vpc_po_1']) + '''
                  no port-type external
                  ''')    
            
            
        except Exception as error:
            log.debug("Unable to configure - Encountered Exception " + str(error))
            self.errored('Exception occurred while configuring external on LEAF-1 and LEAF-2', goto=['cleanup'])
            
     # =============================================================================================================================#        
    
    @aetest.test
    def Add_external_int(self, testscript):
        """Shut down the vpc leg on Leaf2 to force all traffic to Leaf1"""
        
        LEAF_1 = testscript.parameters['LEAF-1']
        LEAF_2 = testscript.parameters['LEAF-2']
        
        try:
            testscript.parameters['LEAF-2'].configure('''
                  interface po ''' + str(testscript.parameters['LEAF_1_dict']['VPC_data']['double_vpc_po_1']) + '''
                  port-type external
                  ''')
            
            testscript.parameters['LEAF-1'].configure('''
                  interface po ''' + str(testscript.parameters['LEAF_1_dict']['VPC_data']['double_vpc_po_1']) + '''
                  port-type external
                  ''')    
            
            
        except Exception as error:
            log.debug("Unable to configure - Encountered Exception " + str(error))
            self.errored('Exception occurred while configuring external on LEAF-1 and LEAF-2', goto=['cleanup'])
            
     # =============================================================================================================================#        
    
    @aetest.test
    def Flap_external_int(self, testscript):
        """Shut down the vpc leg on Leaf2 to force all traffic to Leaf1"""
        
        LEAF_1 = testscript.parameters['LEAF-1']
        LEAF_2 = testscript.parameters['LEAF-2']
        
        try:
            testscript.parameters['LEAF-2'].configure('''
                  interface po ''' + str(testscript.parameters['LEAF_1_dict']['VPC_data']['double_vpc_po_1']) + '''
                  port-type external
                  shut
                  ''')
            
            testscript.parameters['LEAF-1'].configure('''
                  interface po ''' + str(testscript.parameters['LEAF_1_dict']['VPC_data']['double_vpc_po_1']) + '''
                  port-type external
                  shut
                  ''')    
            
            testscript.parameters['LEAF-2'].configure('''
                  interface po ''' + str(testscript.parameters['LEAF_1_dict']['VPC_data']['double_vpc_po_1']) + '''
                  no shut
                  ''')
            
            testscript.parameters['LEAF-1'].configure('''
                  interface po ''' + str(testscript.parameters['LEAF_1_dict']['VPC_data']['double_vpc_po_1']) + '''
                  no shut
                  ''')    
            
        except Exception as error:
            log.debug("Unable to configure - Encountered Exception " + str(error))
            self.errored('Exception occurred while flapping external on LEAF-1 and LEAF-2', goto=['cleanup'])
            
     
   # =============================================================================================================================#   
     
    @aetest.cleanup
    def cleanup(self,testscript):
        """Unconfigure qos policies"""
        LEAF_1 = testscript.parameters['LEAF-1']
        LEAF_2 = testscript.parameters['LEAF-2']
        LEAF_3 = testscript.parameters['LEAF-3']
        post_test_process_dict = {
            'dut_list'                       : [LEAF_1, LEAF_2, LEAF_3],
            'cc_check'                  : 0,
            'cores_check'               : 1,
            'logs_check'                : 1,
            'fnl_flag'                  : 0,
            'exclude_log_check_pattern' : 'ERROR_VLANS_SUSPENDED|ERROR_VLANS_REMOVED',
            }
        try:
            status = infraVerify.postTestVerification(post_test_process_dict)
            if status['status'] == 0:
                self.failed(reason=status['logs'])
            else:
                self.passed(reason=status['logs'])
        except Exception as error:
            log.debug("Unable to unconfigure class map or policy map-Encountered exception " + str(error))
            self.errored('Exception occurred while unconfiguring qos on LEAF1', goto=['next_tc'])    
# *****************************************************************************************************************************#
            
            
#@aetest.test
#def configure_FAN_2(self, testscript):
#    """ Device Bring-up subsection: Configuring FAN_2 """
#
#    # Do not perform configurations if skip_device_config flag is set
#    if not testscript.parameters['script_flags']['skip_device_config']:
#
#        fanOut2_vlanConfiguration = ""
#
#        l3_vrf_count_iter = 0
#        l2_vlan_id = testscript.parameters['LEAF-1']['VNI_data']['l2_vlan_start']
#        l3_vlan_id = testscript.parameters['LEAF-1']['VNI_data']['l3_vlan_start']
#
#        while l3_vrf_count_iter < testscript.parameters['forwardingSysDict']['VRF_count']:
#            l2_vlan_count_iter = 0
#            fanOut2_vlanConfiguration += '''vlan ''' + str(l3_vlan_id) + '''
#                                            state active
#                                            no shut'''
#            while l2_vlan_count_iter < testscript.parameters['forwardingSysDict']['VLAN_PER_VRF_count']:
#                # Incrementing L2 VLAN Iteration counters
#                fanOut2_vlanConfiguration += '''vlan ''' + str(l2_vlan_id) + '''
#                                                state active
#                                                no shut'''
#                l2_vlan_count_iter += 1
#                l2_vlan_id += 1
#            # Incrementing L3 VRF Iteration counters
#            l3_vrf_count_iter += 1
#            l3_vlan_id += 1
#
#        try:
#            testscript.parameters['FAN-2'].configure(
#                str(fanOut2_vlanConfiguration) + '''
#
#                                interface port-channel200
#                                  switchport
#                                  switchport mode trunk
#                                  no shutdown
#
#                                interface {0}
#                                  channel-group 200 force mode active
#                                  no shutdown
#
#                                interface {1}
#                                  channel-group 200 force mode active
#                                  no shutdown
#
#                                interface {2}
#                                  switchport
#                                  switchport mode trunk
#                                  no shut
#
#                            '''.format(testscript.parameters['intf_FAN_2_to_LEAF_1'],
#                                       testscript.parameters['intf_FAN_2_to_LEAF_2'],
#                                       testscript.parameters['intf_FAN_2_to_IXIA']))
#        except Exception as error:
#            log.debug("Unable to configure - Encountered Exception " + str(error))
#            self.errored('Exception occurred while configuring on FAN-2', goto=['common_cleanup'])
#    else:
#        self.passed(reason="Skipped Device Configurations as per Request")
#
    # =============================================================================================================================#
    @aetest.test
    def perform_copy_r_s(self, testscript):
        """ ENABLE_L2_TRM_CONFIGURATION test subsection: Save all configurations (copy r s) """

        testscript.parameters['LEAF-1'].configure("copy r s", timeout=300)
        testscript.parameters['LEAF-2'].configure("copy r s", timeout=300)
        testscript.parameters['LEAF-3'].configure("copy r s", timeout=300)

        # time.sleep(300)

    # *****************************************************************************************************************************#


class VERIFY_NETWORK(aetest.Testcase):
    """This is description for my testcase one"""

    # =============================================================================================================================#
    @aetest.test
    def verify_vpc(self, testscript):
        """ VERIFY_NETWORK subsection: Verify VPC """

        LEAF_1 = testscript.parameters['LEAF-1']
        LEAF_2 = testscript.parameters['LEAF-2']

        VPCStatus = infraVerify.verifyVPCStatus(LEAF_1, LEAF_2)

        if VPCStatus['result']:
            log.info(VPCStatus['log'])
            log.info("PASS : VPC Status for '" + str(LEAF_1) + "' and '" + str(LEAF_2) + "' is Successfully Verified\n\n")
        else:
            log.info(VPCStatus['log'])
            log.info("FAIL : VPC Status for '" + str(LEAF_1) + "' and '" + str(LEAF_2) + "' is Failed\n\n")
            self.failed()

    # =============================================================================================================================#
    @aetest.test
    def verify_bgp_neighborship(self, testscript):
        """ VERIFY_NETWORK subsection: Verify SPINE BGP Neighborship """

        bgpSessionData = verifyEvpn.verifyEvpnUpLinkBGPSessions(testscript.parameters['forwardingSysDict'],testscript.parameters['leavesDict'])

        if bgpSessionData['result'] is 1:
            log.info("PASS : Successfully verified SPINE BGP Neighborship with Leaf's\n\n")
            self.passed(reason=bgpSessionData['log'])
        else:
            log.info("FAIL : Failed to verify SPINE BGP Neighborship with LEAF's\n\n")
            self.failed(reason=bgpSessionData['log'])

    # =============================================================================================================================#
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

    # =============================================================================================================================#
    @aetest.test
    def verify_VNI(self, testscript):
        """ VERIFY_NETWORK subsection: Verify NVE Peering """

        nveVniData = verifyEvpn.verifyEVPNVNIData(testscript.parameters['forwardingSysDict'],testscript.parameters['leavesDict'])

        if nveVniData['result'] is 1:
            log.info("PASS : Successfully verified NVE VNI Data\n\n")
            self.passed(reason=nveVniData['log'])
        else:
            log.info("FAIL : Failed to verify NVE VNI Data\n\n")
            self.failed(reason=nveVniData['log'])

    # *****************************************************************************************************************************#


# class ENABLE_L2_MCAST_CONFIGURATION(aetest.Testcase):
# #    """ENABLE_L2_TRM_CONFIGURATION"""
# #
# #    # =============================================================================================================================#
# #    @aetest.setup
# #    def configure_feature_ngmvpn(self, testscript):
# #        """ ENABLE_L2_TRM_CONFIGURATION setup subsection: Configuring feature ngmvpn """
# #
# #        featureConfigStatus = infraConfig.configureVerifyFeature(testscript.parameters['VTEP_List'], "ngmvpn")
# #
# #        if featureConfigStatus['result'] is 1:
# #            log.info("PASS : Successfully Configured Feature ngmvpn\n\n")
# #            self.passed(reason=featureConfigStatus['log'])
# #        else:
# #            log.info("FAIL : Failed to Configured Feature ngmvpn\n\n")
# #            self.failed(reason=featureConfigStatus['log'])
# 
#     # =============================================================================================================================#
#     @aetest.test
#     def configure_igmp_querier(self, testscript):
#         """ ENABLE_L2_TRM_CONFIGURATION test subsection: Configure IGMP Querier """
# 
#         forwardingSysDict = testscript.parameters['forwardingSysDict']
# 
#         # ----------------------------------------------------
#         # LEAF-1 Counter Variables
#         # ----------------------------------------------------
#         l3_vrf_count_iter = 0
#         l2_vlan_count_iter = 0
# 
#         vrf_id = forwardingSysDict['VRF_id_start']
#         l2_vlan_id = testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vlan_start']
# 
#         # ----------------------------------------------------
#         # Configuring on LEAF-1
#         # ----------------------------------------------------
# 
#         testscript.parameters['LEAF-1'].configure("""
#                                                   ip igmp snooping vxlan
#                                                                                                     
#                                                   """)
# 
#         #testscript.parameters['LEAF-1'].configure('''
#         #                                          router bgp ''' + str(forwardingSysDict['BGP_AS_num']) + '''
#         #                                            address-family ipv4 mvpn
#         #                                            neighbor ''' + str(testscript.parameters['LEAF_1_dict']['SPINE_1_UPLINK_PO']['spine_leaf_po_v4']) + ''' remote-as ''' + str(forwardingSysDict['BGP_AS_num']) + '''
#         #                                              address-family ipv4 mvpn
#         #                                                send-community
#         #                                                send-community extended
#         #                                          ''')
# 
#         while l3_vrf_count_iter < forwardingSysDict['VRF_count']:
#             #testscript.parameters['LEAF-1'].configure('''
#             #                                          vrf context ''' + str(forwardingSysDict['VRF_string']) + str(vrf_id) + '''
#             #                                            address-family ipv4 unicast
#             #                                              route-target both auto mvpn
#             #                                            address-family ipv6 unicast
#             #                                              route-target both auto mvpn
#             #                                          ''')
# 
# 
#             while l2_vlan_count_iter < forwardingSysDict['VLAN_PER_VRF_count']:
#                 testscript.parameters['LEAF-1'].configure('''
#                                                             vlan configuration ''' + str(l2_vlan_id) + '''
#                                                               ip igmp snooping querier 1.1.1.1
#                                                               shut
#                                                               no shut
#                                                         ''')
#                 l2_vlan_count_iter += 1
#                 l2_vlan_id += 1
# 
#             l3_vrf_count_iter += 1
#             vrf_id += 1
# 
#         # ----------------------------------------------------
#         # LEAF-2 Counter Variables
#         # ----------------------------------------------------
#         l3_vrf_count_iter = 0
#         l2_vlan_count_iter = 0
# 
#         vrf_id = forwardingSysDict['VRF_id_start']
#         l2_vlan_id = testscript.parameters['LEAF_2_dict']['VNI_data']['l2_vlan_start']
# 
#         # ----------------------------------------------------
#         # Configuring on LEAF-2
#         # ----------------------------------------------------
# 
#         testscript.parameters['LEAF-2'].configure("""
#                                                   ip igmp snooping vxlan
#                                                                                                     
#                                                   """)
# 
#         #testscript.parameters['LEAF-2'].configure('''
#         #                                          router bgp ''' + str(forwardingSysDict['BGP_AS_num']) + '''
#         #                                            address-family ipv4 mvpn
#         #                                            neighbor ''' + str(testscript.parameters['LEAF_2_dict']['SPINE_1_UPLINK_PO']['spine_leaf_po_v4']) + ''' remote-as ''' + str(forwardingSysDict['BGP_AS_num']) + '''
#         #                                              address-family ipv4 mvpn
#         #                                                send-community
#         #                                                send-community extended
#         #                                          ''')
# 
#         while l3_vrf_count_iter < forwardingSysDict['VRF_count']:
#             #testscript.parameters['LEAF-2'].configure('''
#             #                                          vrf context ''' + str(forwardingSysDict['VRF_string']) + str(vrf_id) + '''
#             #                                            address-family ipv4 unicast
#             #                                              route-target both auto mvpn
#             #                                            address-family ipv6 unicast
#             #                                              route-target both auto mvpn
#             #                                          ''')
# 
# 
#             while l2_vlan_count_iter < forwardingSysDict['VLAN_PER_VRF_count']:
#                 testscript.parameters['LEAF-2'].configure('''
#                                                             vlan configuration ''' + str(l2_vlan_id) + '''
#                                                               ip igmp snooping querier 1.1.1.1
#                                                               shut
#                                                               no shut
#                                                         ''')
#                 l2_vlan_count_iter += 1
#                 l2_vlan_id += 1
# 
#             l3_vrf_count_iter += 1
#             vrf_id += 1
# 
#         # ----------------------------------------------------
#         # LEAF-3 Counter Variables
#         # ----------------------------------------------------
#         l3_vrf_count_iter = 0
#         l2_vlan_count_iter = 0
# 
#         vrf_id = forwardingSysDict['VRF_id_start']
#         l2_vlan_id = testscript.parameters['LEAF_3_dict']['VNI_data']['l2_vlan_start']
# 
#         # ----------------------------------------------------
#         # Configuring on LEAF-3
#         # ----------------------------------------------------
# 
#         testscript.parameters['LEAF-3'].configure("""
#                                                   ip igmp snooping vxlan
#                                                                                                     
#                                                   """)
# 
#         #testscript.parameters['LEAF-3'].configure('''
#         #                                          router bgp ''' + str(forwardingSysDict['BGP_AS_num']) + '''
#         #                                            address-family ipv4 mvpn
#         #                                            neighbor ''' + str(testscript.parameters['LEAF_3_dict']['SPINE_1_UPLINK_PO']['spine_leaf_po_v4']) + ''' remote-as ''' + str(forwardingSysDict['BGP_AS_num']) + '''
#         #                                              address-family ipv4 mvpn
#         #                                                send-community
#         #                                                send-community extended
#         #                                          ''')
# 
#         while l3_vrf_count_iter < forwardingSysDict['VRF_count']:
#             #testscript.parameters['LEAF-3'].configure('''
#             #                                          vrf context ''' + str(forwardingSysDict['VRF_string']) + str(vrf_id) + '''
#             #                                            address-family ipv4 unicast
#             #                                              route-target both auto mvpn
#             #                                            address-family ipv6 unicast
#             #                                              route-target both auto mvpn
#             #                                          ''')
# 
# 
#             while l2_vlan_count_iter < forwardingSysDict['VLAN_PER_VRF_count']:
#                 testscript.parameters['LEAF-3'].configure('''
#                                                             vlan configuration ''' + str(l2_vlan_id) + '''
#                                                               ip igmp snooping querier 1.1.1.1
#                                                               shut
#                                                               no shut
#                                                         ''')
#                 l2_vlan_count_iter += 1
#                 l2_vlan_id += 1
# 
#             l3_vrf_count_iter += 1
#             vrf_id += 1

    # =============================================================================================================================#
    @aetest.test
    def perform_copy_r_s(self, testscript):
        """ ENABLE_L2_TRM_CONFIGURATION test subsection: Save all configurations (copy r s) """

        testscript.parameters['LEAF-1'].configure("copy r s")
        testscript.parameters['LEAF-2'].configure("copy r s")
        testscript.parameters['LEAF-3'].configure("copy r s")

        time.sleep(300)

    # =============================================================================================================================#
#    @aetest.test
#    def verify_feature_ngmvpn(self, testscript):
#        """ ENABLE_L2_TRM_CONFIGURATION test subsection: Verify feature ngmvpn """
#
#        status_flag = []
#        status_msgs = ""
#
#        leaf1_trm_feature_output = testscript.parameters['LEAF-1'].execute("show feature | grep ngmvpn")
#        leaf2_trm_feature_output = testscript.parameters['LEAF-2'].execute("show feature | grep ngmvpn")
#        leaf3_trm_feature_output = testscript.parameters['LEAF-3'].execute("show feature | grep ngmvpn")
#
#        if "enabled" in leaf1_trm_feature_output:
#            status_msgs += " Enabling feature ngmvpn on LEAF-1 is Successful\n"
#        else:
#            status_msgs += " Enabling feature ngmvpn on LEAF-1 has failed\n"
#            status_flag.append(0)
#
#        if "enabled" in leaf2_trm_feature_output:
#            status_msgs += " Enabling feature ngmvpn on LEAF-2 is Successful\n"
#        else:
#            status_msgs += " Enabling feature ngmvpn on LEAF-2 has failed\n"
#            status_flag.append(0)
#
#        if "enabled" in leaf3_trm_feature_output:
#            status_msgs += " Enabling feature ngmvpn on LEAF-3 is Successful\n"
#        else:
#            status_msgs += " Enabling feature ngmvpn on LEAF-3 has failed\n"
#            status_flag.append(0)
#
#        if 0 in status_flag:
#            self.failed(reason=status_msgs, goto=['cleanup'])
#
#    # =============================================================================================================================#
#    @aetest.test
#    def perform_copy_r_s(self, testscript):
#        """ ENABLE_L2_TRM_CONFIGURATION test subsection: Save all configurations (copy r s) """
#
#        testscript.parameters['LEAF-1'].configure("copy r s", timeout=300)
#        testscript.parameters['LEAF-2'].configure("copy r s", timeout=300)
#        testscript.parameters['LEAF-3'].configure("copy r s", timeout=300)
#
    # *****************************************************************************************************************************#


    
class IXIA_CONFIGURATION(aetest.Testcase):
    

    # =============================================================================================================================#
    @aetest.test
    def CONNECT_IXIA_CHASSIS(self, testscript):
        

        # Do not perform configurations if skip_tgen_config flag is set
        if not testscript.parameters['script_flags']['skip_tgen_config']:

            # Get IXIA paraameters
            ixia_chassis_ip = testscript.parameters['ixia_chassis_ip']
            ixia_tcl_server = testscript.parameters['ixia_tcl_server']
            ixia_tcl_port = testscript.parameters['ixia_tcl_port']
            ixia_int_list = testscript.parameters['ixia_int_list']

            ix_int_1 = testscript.parameters['intf_IXIA_to_FO_1']
            ix_int_2 = testscript.parameters['IXIA_to_N7k_LEAF_1']

            ixiaArgDict = {
                            'chassis_ip'    : ixia_chassis_ip,
                            'port_list'     : ixia_int_list,
                            'tcl_server'    : ixia_tcl_server,
                            'tcl_port'      : ixia_tcl_port
            }

            log.info("Ixia Args Dict is:")
            log.info(ixiaArgDict)

            result = ixLib.connect_to_ixia(ixiaArgDict)
            if result == 0:
                log.debug("Connecting to ixia failed")
                self.errored("Connecting to ixia failed", goto=['cleanup'])

            ch_key = result['port_handle']
            for ch_p in ixia_chassis_ip.split('.'):
                ch_key = ch_key[ch_p]

            log.info("Port Handles are:")
            log.info(ch_key)

            testscript.parameters['port_handle_1'] = ch_key[ix_int_1]
            testscript.parameters['port_handle_2'] = ch_key[ix_int_2]

        else:
            self.passed(reason="Skipped TGEN Configurations as per request")

    # =============================================================================================================================#
    @aetest.test
    def CREATE_IXIA_TOPOLOGIES(self, testscript):
                
                                         
        # Do not perform configurations if skip_tgen_config flag is set
        if not testscript.parameters['script_flags']['skip_tgen_config']:

            TOPO_1_dict = {'topology_name': 'FO-1-TG',
                           'device_grp_name': 'FO-1-TG',
                           'port_handle': testscript.parameters['port_handle_1']}

            TOPO_2_dict = {'topology_name': 'N7K_LEAF-1-TG',
                           'device_grp_name': 'N7K_LEAF-1-TG',
                           'port_handle': testscript.parameters['port_handle_2']}

            testscript.parameters['IX_TP1'] = ixLib.create_topo_device_grp(TOPO_1_dict)
            if testscript.parameters['IX_TP1'] == 0:
                log.debug("Creating Topology failed")
                self.errored("Creating Topology failed", goto=['cleanup'])
            else:
                log.info("Created BL1-TG Topology Successfully")

            testscript.parameters['IX_TP2'] = ixLib.create_topo_device_grp(TOPO_2_dict)
            if testscript.parameters['IX_TP2'] == 0:
                log.debug("Creating Topology failed")
                self.errored("Creating Topology failed", goto=['cleanup'])
            else:
                log.info("Created BL2-TG Topology Successfully")

            testscript.parameters['IX_TP1']['port_handle'] = testscript.parameters['port_handle_1']
            testscript.parameters['IX_TP2']['port_handle'] = testscript.parameters['port_handle_2']
        else:
            self.passed(reason="Skipped TGEN Configurations as per request")

    # =============================================================================================================================#
    @aetest.test
    def CONFIGURE_IXIA_INTERFACES(self, testscript):
        

        # Do not perform configurations if skip_tgen_config flag is set
        if not testscript.parameters['script_flags']['skip_tgen_config']:

            P1 = testscript.parameters['port_handle_1']
            P2 = testscript.parameters['port_handle_2']

            P1_dict = testscript.parameters['LEAF_2_TGEN_dict']
            P2_dict = testscript.parameters['LEAF_3_TGEN_dict']

            P1_int_dict_1 = {'dev_grp_hndl': testscript.parameters['IX_TP1']['dev_grp_hndl'],
                             'port_hndl': P1,
                             'no_of_ints': P1_dict['no_of_ints'],
                             'phy_mode': P1_dict['phy_mode'],
                             'mac': P1_dict['mac'],
                             'mac_step': P1_dict['mac_step'],
                             'protocol': P1_dict['protocol'],
                             'v4_addr': P1_dict['v4_addr'],
                             'v4_addr_step': P1_dict['v4_addr_step'],
                             'v4_gateway': P1_dict['v4_addr_gateway'],
                             'v4_gateway_step': P1_dict['v4_gateway_step'],
                             'v4_netmask': P1_dict['netmask'],
                             'v6_addr': P1_dict['v6_addr'],
                             'v6_addr_step': P1_dict['v6_addr_step'],
                             'v6_gateway': P1_dict['v6_gateway'],
                             'v6_gateway_step': P1_dict['v6_gateway_step'],
                             'v6_netmask': P1_dict['v6_netmask'],
                             'vlan_id': P1_dict['vlan_id'],
                             'vlan_user_priority': P1_dict['vlan_user_priority'],
                             'vlan_id_step': P1_dict['vlan_id_step'],
                             'frame_size': P1_dict['frame_size'],
                             'L3_dst_addr': P1_dict['L3_dst_addr']}

            P2_int_dict_1 = {'dev_grp_hndl': testscript.parameters['IX_TP2']['dev_grp_hndl'],
                             'port_hndl': P2,
                             'no_of_ints': P2_dict['no_of_ints'],
                             'phy_mode': P2_dict['phy_mode'],
                             'mac': P2_dict['mac'],
                             'mac_step': P2_dict['mac_step'],
                             'protocol': P2_dict['protocol'],
                             'v4_addr': P2_dict['v4_addr'],
                             'v4_addr_step': P2_dict['v4_addr_step'],
                             'v4_gateway': P2_dict['v4_addr_gateway'],
                             'v4_gateway_step': P2_dict['v4_gateway_step'],
                             'v4_netmask': P2_dict['netmask'],
                             'v6_addr': P2_dict['v6_addr'],
                             'v6_addr_step': P2_dict['v6_addr_step'],
                             'v6_gateway': P2_dict['v6_gateway'],
                             'v6_gateway_step': P2_dict['v6_gateway_step'],
                             'v6_netmask': P2_dict['v6_netmask'],
                             'vlan_id': P2_dict['vlan_id'],
                             'vlan_user_priority': P1_dict['vlan_user_priority'],
                             'vlan_id_step': P2_dict['vlan_id_step'],
                             'frame_size': P2_dict['frame_size'],
                             'L3_dst_addr': P2_dict['L3_dst_addr']}

            P1_IX_int_data = ixLib.configure_multi_ixia_interface(P1_int_dict_1)
            P2_IX_int_data = ixLib.configure_multi_ixia_interface(P2_int_dict_1)

            if P1_IX_int_data == 0 or P2_IX_int_data == 0:
                log.debug("Configuring IXIA Interface failed")
                self.errored("Configuring IXIA Interface failed", goto=['cleanup'])
            else:
                log.info("Configured IXIA Interface Successfully")

            testscript.parameters['IX_TP1']['eth_handle'] = P1_IX_int_data['eth_handle']
            testscript.parameters['IX_TP1']['ipv4_handle'] = P1_IX_int_data['ipv4_handle']
            testscript.parameters['IX_TP1']['ipv6_handle'] = P1_IX_int_data['ipv6_handle']
            #testscript.parameters['IX_TP1']['port_handle'] = P1_IX_int_data['port_hndl']
            testscript.parameters['IX_TP1']['topo_int_handle'] = P1_IX_int_data['topo_int_handle'].split(" ")

            testscript.parameters['IX_TP2']['eth_handle'] = P2_IX_int_data['eth_handle']
            testscript.parameters['IX_TP2']['ipv4_handle'] = P2_IX_int_data['ipv4_handle']
            testscript.parameters['IX_TP2']['ipv6_handle'] = P2_IX_int_data['ipv6_handle']
            #testscript.parameters['IX_TP2']['port_handle'] = P2_IX_int_data['port_hndl']
            testscript.parameters['IX_TP2']['topo_int_handle'] = P2_IX_int_data['topo_int_handle'].split(" ")

            log.info("IXIA Port 1 Handles")
            log.info(testscript.parameters['IX_TP1'])
            log.info("IXIA Port 2 Handles")
            log.info(testscript.parameters['IX_TP2'])

        else:
            self.passed(reason="Skipped TGEN Configurations as per request")

    # =============================================================================================================================#
    @aetest.test
    def CONFIGURE_IXIA_IGMP_GROUPS(self, testscript):
        """ IXIA_CONFIGURATION subsection: Configure IXIA IGMP Groups """

#        #IX_TP1 = testscript.parameters['IX_TP1']
#        IX_TP2 = testscript.parameters['IX_TP2']
#        P1_TGEN_dict = testscript.parameters['LEAF_12_TGEN_dict']
#        P2_dict = testscript.parameters['LEAF_3_TGEN_dict']
#
#       
#
#        IGMP_dict = {'ipv4_hndl': IX_TP2['ipv4_handle'],
#                     'igmp_ver': P2_dict['igmp_ver'],
#                     'mcast_grp_ip': P2_dict['mcast_grp_ip'],
#                     'mcast_grp_ip_step': P2_dict['mcast_grp_ip_step'],
#                     'no_of_grps': P2_dict['no_of_grps'],
#                     'mcast_src_ip': P2_dict['v4_addr'],
#                     'mcast_src_ip_step': P2_dict['v4_addr_step'],
#                     'mcast_no_of_srcs': P2_dict['no_of_mcast_sources'],
#                     }
#
#        IGMP_EML = ixLib.emulate_igmp_groupHost(IGMP_dict)
#
#        if IGMP_EML == 0:
#            log.debug("Configuring IGMP failed")
#            self.errored("Configuring IGMP failed", goto=['cleanup'])
#        else:
#            log.info("Configured IGMP Successfully")
#
#        testscript.parameters['IX_TP2']['igmpHost_handle'] = IGMP_EML['igmpHost_handle']
#        testscript.parameters['IX_TP2']['igmp_group_handle'] = IGMP_EML['igmp_group_handle']
#        testscript.parameters['IX_TP2']['igmp_source_handle'] = IGMP_EML['igmp_source_handle']
#
#        # _result_ = ixiahlt.test_control(action='configure_all')
#        # print(_result_)
#        proto_result = ixLib.start_protocols()
#        if proto_result == 0:
#            log.debug("Starting Protocols failed")
#            self.errored("Starting Protocols failed", goto=['cleanup'])
#        else:
#            log.info("Started Protocols Successfully")

        # Do not perform configurations if skip_tgen_config flag is set
        if not testscript.parameters['script_flags']['skip_tgen_config']:

            IX_TP2 = testscript.parameters['IX_TP2']
            P1_TGEN_dict = testscript.parameters['LEAF_2_TGEN_dict']
            P2_TGEN_dict = testscript.parameters['LEAF_3_TGEN_dict']

            IGMP_dict_1 = {'ipv4_hndl': IX_TP2['ipv4_handle'],
                           'igmp_ver': P2_TGEN_dict['igmp_ver'],
                           'mcast_grp_ip': P2_TGEN_dict['mcast_grp_ip'],
                           'mcast_grp_ip_step': P2_TGEN_dict['mcast_grp_ip_step'],
                           'no_of_grps': P2_TGEN_dict['no_of_grps'],
                           'mcast_src_ip': P1_TGEN_dict['v4_addr'],
                           'mcast_src_ip_step': P2_TGEN_dict['v4_addr_step'],
                           'mcast_src_ip_step_per_port': P2_TGEN_dict['v4_addr_step'],
                           'mcast_grp_ip_step_per_port': P2_TGEN_dict['v4_addr_step'],
                           'mcast_no_of_srcs': P2_TGEN_dict['no_of_mcast_sources'],
                           'topology_handle': IX_TP2['topo_hndl']
                           }

            IGMP_EML = ixLib.emulate_igmp_groupHost(IGMP_dict_1)

            if IGMP_EML == 0:
                log.debug("Configuring IGMP failed")
                self.errored("Configuring IGMP failed")
            else:
                log.info("Configured IGMP Successfully")

            testscript.parameters['IX_TP2']['igmpHost_handle'] = []
            testscript.parameters['IX_TP2']['igmp_group_handle'] = []
            testscript.parameters['IX_TP2']['igmp_source_handle'] = []
            testscript.parameters['IX_TP2']['igmpMcastGrpList'] = []

            testscript.parameters['IX_TP2']['igmpHost_handle'].append(IGMP_EML['igmpHost_handle'])
            testscript.parameters['IX_TP2']['igmp_group_handle'].append(IGMP_EML['igmp_group_handle'])
            testscript.parameters['IX_TP2']['igmp_source_handle'].append(IGMP_EML['igmp_source_handle'])
            testscript.parameters['IX_TP2']['igmpMcastGrpList'].append(IGMP_EML['igmpMcastGrpList'])

        else:
            self.skipped(reason="Skipped TGEN Configurations as per request")

        

    # =============================================================================================================================#
    @aetest.test
    def START_IXIA_PROTOCOLS(self):
        """ IXIA_CONFIGURATION subsection: Configure IXIA IGMP Groups """

        # _result_ = ixiahlt.test_control(action='configure_all')
        # print(_result_)
        proto_result = ixLib.start_protocols()
        if proto_result == 0:
            log.debug("Starting Protocols failed")
            self.errored("Starting Protocols failed", goto=['cleanup'])
        else:
            log.info("Started Protocols Successfully")

        time.sleep(60)

        proto_result = ixLib.stop_protocols()
        if proto_result == 0:
            log.debug("Stopped Protocols failed")
            self.errored("Stopped Protocols failed", goto=['cleanup'])
        else:
            log.info("Stopped Protocols Successfully")

        time.sleep(30)

        proto_result = ixLib.start_protocols()
        if proto_result == 0:
            log.debug("Starting Protocols failed")
            self.errored("Starting Protocols failed", goto=['cleanup'])
        else:
            log.info("Started Protocols Successfully")

        time.sleep(120)

    @aetest.test
    def Connect_to_ixia_session(self,testscript):
        """ IXIA_CONFIGURATION subsection: Connect to  IXIA session """
        
        
        ixnetwork_tcl_server = testscript.parameters['ixia_tcl_server']
        
        
        connect_status = ixiangpf.connect(
            ixnetwork_tcl_server    =  ixnetwork_tcl_server,
            session_resume_keys     = 0,
        )
        
        if connect_status['status'] != '1':
            log.debug("Connecting to the ixia session failed")
            self.errored("Connecting to the ixia session failed", goto=['cleanup'])
        else:
            log.info("Connected to the ixia session Successfully")
            


#        # ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~#
#        # Initiate a PING to populate paths
#        verifyDevicePingsForIxiaTraffic(testscript)
#
#        log.info("IXIA Port 1 Handles")
#        log.info(testscript.parameters['IX_TP1'])
#        log.info("IXIA Port 2 Handles")
#        log.info(testscript.parameters['IX_TP2'])
#
    @aetest.test
    def Pre_migration_hsrp(self,testscript):
        LEAF_1 = testscript.parameters['LEAF-1']
        LEAF_2 = testscript.parameters['LEAF-2']
        forwardingSysDict = testscript.parameters['forwardingSysDict']
        l2_vlan_id = testscript.parameters['N7K_LEAF_1_dict']['Vlan_data']['l2_vlan_start']
        l2_vlan_ipv4_start= testscript.parameters['N7K_LEAF_1_dict']['Vlan_data']['l2_vlan_ipv4_start']
        l2_vlan_ipv4_mask= testscript.parameters['N7K_LEAF_1_dict']['Vlan_data']['l2_vlan_ipv4_mask']
        l2_vlan_ipv6_start= testscript.parameters['N7K_LEAF_1_dict']['Vlan_data']['l2_vlan_ipv6_start']
        l2_vlan_ipv6_mask= testscript.parameters['N7K_LEAF_1_dict']['Vlan_data']['l2_vlan_ipv6_mask']
        l2_hsrp_ipv4_vip_start= testscript.parameters['N7K_LEAF_1_dict']['Vlan_data']['hsrp_ipv4_vip_start']
        l2_hsrp_ipv6_vip_start= testscript.parameters['N7K_LEAF_1_dict']['Vlan_data']['hsrp_ipv6_vip_start']
        
        try:
            device_handle=connect_to_vdc(testscript.parameters['xbow1'], 'leaf1')
            if device_handle==False:
                log.info("failed to switchto correct vdc")
                self.failed("failed to switchto correct vdc",goto=['common_cleanup'])
            else:
                total_ip_count = int(forwardingSysDict['VLAN_PER_VRF_count']) * int(forwardingSysDict['VRF_count'])
                l2_ipv4s = increment_prefix_network(ip.IPv4Interface(str(l2_vlan_ipv4_start) + str(l2_vlan_ipv4_mask)),total_ip_count)
                l2_ipv6s = increment_prefix_network(ip.IPv6Interface(str(l2_vlan_ipv6_start) + str(l2_vlan_ipv6_mask)),total_ip_count)
                ip_index=0
                for i in range(0,len(l2_ipv4s)):
                    device_handle.configure('''int vlan ''' + str(l2_vlan_id) + '''\n
                                     hsrp version 2
                                     hsrp ''' + str(l2_vlan_id) + ''' ipv4
                                     mac-address 0000.000a.aaaa
                                     ''')
                    l2_vlan_id += 1
            l2_vlan_id = testscript.parameters['N7K_LEAF_1_dict']['Vlan_data']['l2_vlan_start']        
            device_handle=connect_to_vdc(testscript.parameters['xbow2'], 'leaf2')
            if device_handle==False:
                log.info("failed to switchto correct vdc")
                self.failed("failed to switchto correct vdc",goto=['common_cleanup'])
            else:
                total_ip_count = int(forwardingSysDict['VLAN_PER_VRF_count']) * int(forwardingSysDict['VRF_count'])
                l2_ipv4s = increment_prefix_network(ip.IPv4Interface(str(l2_vlan_ipv4_start) + str(l2_vlan_ipv4_mask)),total_ip_count)
                l2_ipv6s = increment_prefix_network(ip.IPv6Interface(str(l2_vlan_ipv6_start) + str(l2_vlan_ipv6_mask)),total_ip_count)
                ip_index=0
                for i in range(0,len(l2_ipv4s)):
                    device_handle.configure('''int vlan ''' + str(l2_vlan_id) + '''\n
                                     hsrp version 2
                                     hsrp ''' + str(l2_vlan_id) + ''' ipv4
                                     mac-address 0000.000a.aaaa
                                     ''')
                    l2_vlan_id += 1
                    


        except Exception as error:
                log.debug("Unable to configure - Encountered Exception " + str(error))
                self.errored('Exception occurred while configuring on N7k leaf1', goto=['common_cleanup'])
                
    @aetest.test
    def CONFIGURE_UCAST_L3_IXIA_TRAFFIC(self, testscript):
        """ IXIA_CONFIGURATION subsection: Configure MCAST Traffic Item """

        # Do not perform configurations if skip_tgen_config flag is set
        if not testscript.parameters['script_flags']['skip_tgen_config']:

            IX_TP1 = testscript.parameters['IX_TP1']
            IX_TP2 = testscript.parameters['IX_TP2']
            P1_dict = testscript.parameters['LEAF_2_TGEN_dict']
            P2_dict = testscript.parameters['LEAF_3_TGEN_dict']

            UCAST_v4_dict = {   'src_hndl'  : IX_TP1['port_handle'],
                                'dst_hndl'  : IX_TP2['port_handle'],
                                'ip_dscp'   : P1_dict['ip_dscp'],
                                'circuit'   : 'raw',
                                'TI_name'   : "UCAST_L3",
                                'rate_pps'  : "9000",
                                'bi_dir'    : 1,
                                'frame_size': '128',
                                'src_mac'   : P1_dict['mac'],
                                'dst_mac'   : '0000.000a.aaaa',
                                'srcmac_step': '00:00:00:00:00:00',
                                'dstmac_step': '00:00:00:00:00:00',
                                'srcmac_count': '1',
                                'dstmac_count': '1',
                                'vlan_id'    : P1_dict['vlan_id'],
                                'vlanid_step': '0',
                                'vlanid_count': '1',
                                'vlan_user_priority': P1_dict['vlan_user_priority'],
                                'ip_src_addrs' : P1_dict['v4_addr'],
                                'ip_dst_addrs' : P1_dict['L3_dst_addr'],
                                'ip_src_step' : '0.0.0.0',
                                'ip_dst_step' : '0.0.0.0',
#                                'ip_step'    : P1_dict['v4_addr_step'],
                          }

#            UCAST_v6_dict = {   'src_hndl'  : IX_TP1['ipv6_handle'],
#                                'dst_hndl'  : IX_TP2['ipv6_handle'],
#                                'circuit'   : 'ipv6',
#                                'TI_name'   : "UCAST_V6",
#                                'rate_pps'  : "1000",
#                                'bi_dir'    : 1
#                          }

            UCAST_v4_TI = ixLib.configure_ixia_l3_traffic_item(UCAST_v4_dict)
#            UCAST_v6_TI = ixLib.configure_ixia_traffic_item(UCAST_v6_dict)

#            if UCAST_v4_TI == 0 or UCAST_v6_TI == 0:
#                log.debug("Configuring UCast TI failed")
#                self.errored("Configuring UCast TI failed", goto=['cleanup'])
                
            if UCAST_v4_TI == 0:
                log.debug("Configuring UCast TI failed")
                self.errored("Configuring UCast TI failed", goto=['cleanup'])
            else:
                global stream_id
                stream_id = UCAST_v4_TI

        else:
            self.passed(reason="Skipped TGEN Configurations as per request")
            
    # @aetest.test
    # def CONFIGURE_BCAST_IXIA_TRAFFIC(self, testscript):
    #     """ IXIA_CONFIGURATION subsection: Configure MCAST Traffic Item """
    # 
    #     # Do not perform configurations if skip_tgen_config flag is set
    #     if not testscript.parameters['script_flags']['skip_tgen_config']:
    # 
    #         IX_TP1 = testscript.parameters['IX_TP1']
    #         IX_TP2 = testscript.parameters['IX_TP2']
    #         P1_dict = testscript.parameters['LEAF_2_TGEN_dict']
    #         P2_dict = testscript.parameters['LEAF_3_TGEN_dict']
    #         BCAST_v4_dict = {
    #                             'src_hndl'      : IX_TP1['port_handle'],
    #                             'dst_hndl'      : IX_TP2['port_handle'],
    #                             'TI_name'       : "BCAST_V4",
    #                             'frame_size'    : "70",
    #                             'rate_pps'      : "1000",
    #                             'src_mac'       : P1_dict['mac'],
    #                             'srcmac_step'   : "00:00:00:00:00:01",
    #                             'srcmac_count'  : '1',
    #                             'vlan_id'       : P1_dict['vlan_id'],
    #                             'vlanid_step'   : "1",
    #                             'vlanid_count'  : "1",
    #                             'ip_src_addrs'  : P1_dict['v4_addr'],
    #                             'ip_step'       : "0.0.1.0",
    #                       }
    # 
    #         BCAST_v4_TI = ixLib.configure_ixia_BCAST_traffic_item(BCAST_v4_dict)
    # 
    #         if BCAST_v4_TI == 0:
    #             log.debug("Configuring BCast TI failed")
    #             self.errored("Configuring BCast TI failed", goto=['cleanup'])
    #         else:
    #             global stream_id_2
    #             stream_id_2 = BCAST_v4_TI
    # 
    #     else:
    #         self.passed(reason="Skipped TGEN Configurations as per request")
    # =============================================================================================================================#
    @aetest.test
    def APPLY_TRAFFIC(self,testscript):
        """ IXIA_CONFIGURATION subsection: Verify IXIA Traffic """

        # Apply IXIA Traffic
        if ixLib.apply_traffic() == 1:
            log.info("Applying IXIA TI Passed")
        else:
            self.errored("Applying IXIA TI failed", goto=['cleanup'])
            
        # =============================================================================================================================#
    #--------------------------------------------------------------------------------#
        # Start traffic from ixia
        log.info("--- Populating the statistics --- \n")
        log.info("---- Running Traffic --- \n")
        log.info("Starting Traffic")

        traffic_run_status  = ixLib.start_traffic()

        if traffic_run_status is not 1:
           log.info("Failed: To start traffic")
           return 0
        else:
            log.info("\nTraffic started successfully\n")
        
        
    # Stop Traffic from ixia
        #log.info("--- Sleeping for 1200 seconds ---- \n")
        #time.sleep(1200)
        log.info("--- Stopping Traffic ---- \n")
        log.info("Stopping Traffic")
        traffic_run_status = ixLib.stop_traffic()
        
        if traffic_run_status is not 1:
           log.info("Failed: To Stop traffic")
           return 0
        else:
            log.info("\nTraffic Stopped successfully\n")
            time.sleep(10)
        
        
        
    @aetest.test
    def VERIFY_IXIA_TRAFFIC(self, testscript):
        """ IXIA_CONFIGURATION subsection: Verify IXIA Traffic """

        # Do not perform configurations if skip_tgen_config flag is set
        if not testscript.parameters['script_flags']['skip_tgen_config']:

            time.sleep(20)

            if ixLib.verify_traffic(2) == 0:
                log.debug("Traffic Verification failed")
                self.failed("Traffic Verification failed", goto=['cleanup'])
            else:
                log.info("Traffic Verification Passed")
        else:
            self.passed(reason="Skipped TGEN Configurations as per request")
        ###Delete the traffic stream    
        # UCAST_v4_dict = {
        #                     'mode'        : 'remove',
        #                     'stream_id'   : stream_id,
        #               }
        # if (ixLib.delete_traffic_item(UCAST_v4_dict))==0:
        #     log.debug("Traffic Remove failed")
        #     self.failed("Traffic Remove failed")
        # else:
        #     log.info("Traffic Deletion Passed")
#
    # =============================================================================================================================#




# *****************************************************************************************************************************#
class Configure_sec_ipv4(aetest.Testcase):
    """ Configure_sec_ipv4 """

    
    # =============================================================================================================================#        
    
    @aetest.test
    def SVI_ON_LEAF2(self, testscript):
        """Shut down the vpc leg on Leaf2 to force all traffic to Leaf1"""
        
        LEAF_1 = testscript.parameters['LEAF-1']
        LEAF_2 = testscript.parameters['LEAF-2']
        forwardingSysDict = testscript.parameters['forwardingSysDict']
        l2_vlan_id = testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vlan_start']
        l2_vlan_ipv4_sec_start= testscript.parameters['LEAF_2_dict']['VNI_data']['l2_vlan_ipv4_sec_start']
        l2_vlan_ipv4_mask= testscript.parameters['LEAF_2_dict']['VNI_data']['l2_vlan_ipv4_mask']
        #+ str(testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vlan_ipv4_mask'])
        
        try:
            total_ip_count = int(forwardingSysDict['VLAN_PER_VRF_count']) * int(forwardingSysDict['VRF_count'])
            l2_ipv4s = increment_prefix_network(ip.IPv4Interface(str(l2_vlan_ipv4_sec_start) + str(l2_vlan_ipv4_mask)),total_ip_count)
            ip_index=0
            for i in range(0,len(l2_ipv4s)):
                LEAF_2.configure('''int vlan ''' + str(l2_vlan_id) + '''\n
                                 ip address ''' + str(l2_ipv4s[ip_index]) + ''' secondary use-bia
                                 ''')
                l2_vlan_id += 1
                ip_index += 1
                
            
            
        except Exception as error:
            log.debug("Unable to configure - Encountered Exception " + str(error))
            self.errored('Exception occurred while configuring secondary ipv4 address on LEAF-2', goto=['cleanup'])
            
    # =============================================================================================================================#        
    
    @aetest.test
    def SVI_ON_LEAF1(self, testscript):
        """Shut down the vpc leg on Leaf2 to force all traffic to Leaf1"""
        
        LEAF_1 = testscript.parameters['LEAF-1']
        LEAF_2 = testscript.parameters['LEAF-2']
        forwardingSysDict = testscript.parameters['forwardingSysDict']
        l2_vlan_id = testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vlan_start']
        l2_vlan_ipv4_sec_start= testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vlan_ipv4_sec_start']
        l2_vlan_ipv4_mask= testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vlan_ipv4_mask']
        
        try:
            total_ip_count = int(forwardingSysDict['VLAN_PER_VRF_count']) * int(forwardingSysDict['VRF_count'])
            l2_ipv4s = increment_prefix_network(ip.IPv4Interface(str(l2_vlan_ipv4_sec_start) + str(l2_vlan_ipv4_mask)),total_ip_count)
            ip_index=0
            for i in range(0,len(l2_ipv4s)):
                LEAF_1.configure('''int vlan ''' + str(l2_vlan_id) + '''\n
                                 ip address ''' + str(l2_ipv4s[ip_index]) + ''' secondary use-bia
                                 ''')
                l2_vlan_id += 1
                ip_index += 1
                
            
            
        except Exception as error:
            log.debug("Unable to configure - Encountered Exception " + str(error))
            self.errored('Exception occurred while configuring secondary ipv4 address on LEAF-1', goto=['cleanup'])
            
     # =============================================================================================================================#        
    
    @aetest.test
    def REMOVE_SVI_ON_LEAF2(self, testscript):
        """Shut down the vpc leg on Leaf2 to force all traffic to Leaf1"""
        
        LEAF_1 = testscript.parameters['LEAF-1']
        LEAF_2 = testscript.parameters['LEAF-2']
        forwardingSysDict = testscript.parameters['forwardingSysDict']
        l2_vlan_id = testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vlan_start']
        l2_vlan_ipv4_sec_start= testscript.parameters['LEAF_2_dict']['VNI_data']['l2_vlan_ipv4_sec_start']
        l2_vlan_ipv4_mask= testscript.parameters['LEAF_2_dict']['VNI_data']['l2_vlan_ipv4_mask']
        
        try:
            total_ip_count = int(forwardingSysDict['VLAN_PER_VRF_count']) * int(forwardingSysDict['VRF_count'])
            l2_ipv4s = increment_prefix_network(ip.IPv4Interface(str(l2_vlan_ipv4_sec_start) + str(l2_vlan_ipv4_mask)),total_ip_count)
            ip_index=0
            for i in range(0,len(l2_ipv4s)):
                LEAF_2.configure('''int vlan ''' + str(l2_vlan_id) + '''\n
                                 no ip address ''' + str(l2_ipv4s[ip_index]) + ''' secondary use-bia
                                 ''')
                l2_vlan_id += 1
                ip_index += 1
                
            
            
        except Exception as error:
            log.debug("Unable to configure - Encountered Exception " + str(error))
            self.errored('Exception occurred while configuring secondary ipv4 address on LEAF-2', goto=['cleanup'])
            
     # =============================================================================================================================#        
    
    @aetest.test
    def REMOVE_SVI_ON_LEAF1(self, testscript):
        """Shut down the vpc leg on Leaf2 to force all traffic to Leaf1"""
        
        LEAF_1 = testscript.parameters['LEAF-1']
        LEAF_2 = testscript.parameters['LEAF-2']
        forwardingSysDict = testscript.parameters['forwardingSysDict']
        l2_vlan_id = testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vlan_start']
        l2_vlan_ipv4_sec_start= testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vlan_ipv4_sec_start']
        l2_vlan_ipv4_mask= testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vlan_ipv4_mask']
        
        try:
            total_ip_count = int(forwardingSysDict['VLAN_PER_VRF_count']) * int(forwardingSysDict['VRF_count'])
            l2_ipv4s = increment_prefix_network(ip.IPv4Interface(str(l2_vlan_ipv4_sec_start) + str(l2_vlan_ipv4_mask)),total_ip_count)
            ip_index=0
            for i in range(0,len(l2_ipv4s)):
                LEAF_1.configure('''int vlan ''' + str(l2_vlan_id) + '''\n
                                 no ip address ''' + str(l2_ipv4s[ip_index]) + ''' secondary use-bia
                                 ''')
                l2_vlan_id += 1
                ip_index += 1
                
            
            
        except Exception as error:
            log.debug("Unable to configure - Encountered Exception " + str(error))
            self.errored('Exception occurred while configuring secondary ipv4 address on LEAF-1', goto=['cleanup'])
            
     # =============================================================================================================================#        
    
    @aetest.test
    def ADD_SVI_ON_LEAF2(self, testscript):
        """Shut down the vpc leg on Leaf2 to force all traffic to Leaf1"""
        
        LEAF_1 = testscript.parameters['LEAF-1']
        LEAF_2 = testscript.parameters['LEAF-2']
        forwardingSysDict = testscript.parameters['forwardingSysDict']
        l2_vlan_id = testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vlan_start']
        l2_vlan_ipv4_sec_start= testscript.parameters['LEAF_2_dict']['VNI_data']['l2_vlan_ipv4_sec_start']
        l2_vlan_ipv4_mask= testscript.parameters['LEAF_2_dict']['VNI_data']['l2_vlan_ipv4_mask']
        
        try:
            total_ip_count = int(forwardingSysDict['VLAN_PER_VRF_count']) * int(forwardingSysDict['VRF_count'])
            l2_ipv4s = increment_prefix_network(ip.IPv4Interface(str(l2_vlan_ipv4_sec_start) + str(l2_vlan_ipv4_mask)),total_ip_count)
            ip_index=0
            for i in range(0,len(l2_ipv4s)):
                LEAF_2.configure('''int vlan ''' + str(l2_vlan_id) + '''\n
                                 ip address ''' + str(l2_ipv4s[ip_index]) + ''' secondary use-bia
                                 ''')
                l2_vlan_id += 1
                ip_index += 1
                
            
            
        except Exception as error:
            log.debug("Unable to configure - Encountered Exception " + str(error))
            self.errored('Exception occurred while configuring secondary ipv4 address on LEAF-2', goto=['cleanup'])
            
     # =============================================================================================================================#        
    
    @aetest.test
    def ADD_SVI_ON_LEAF1(self, testscript):
        """Shut down the vpc leg on Leaf2 to force all traffic to Leaf1"""
        
        LEAF_1 = testscript.parameters['LEAF-1']
        LEAF_2 = testscript.parameters['LEAF-2']
        forwardingSysDict = testscript.parameters['forwardingSysDict']
        l2_vlan_id = testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vlan_start']
        l2_vlan_ipv4_sec_start= testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vlan_ipv4_sec_start']
        l2_vlan_ipv4_mask= testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vlan_ipv4_mask']
        
        try:
            total_ip_count = int(forwardingSysDict['VLAN_PER_VRF_count']) * int(forwardingSysDict['VRF_count'])
            l2_ipv4s = increment_prefix_network(ip.IPv4Interface(str(l2_vlan_ipv4_sec_start) + str(l2_vlan_ipv4_mask)),total_ip_count)
            ip_index=0
            for i in range(0,len(l2_ipv4s)):
                LEAF_1.configure('''int vlan ''' + str(l2_vlan_id) + '''\n
                                 ip address ''' + str(l2_ipv4s[ip_index]) + ''' secondary use-bia
                                 ''')
                l2_vlan_id += 1
                ip_index += 1
                
            
            
        except Exception as error:
            log.debug("Unable to configure - Encountered Exception " + str(error))
            self.errored('Exception occurred while configuring secondary ipv4 address on LEAF-1', goto=['cleanup'])
   
     
    @aetest.cleanup
    def cleanup(self,testscript):
        """Unconfigure qos policies"""
        LEAF_1 = testscript.parameters['LEAF-1']
        LEAF_2 = testscript.parameters['LEAF-2']
        LEAF_3 = testscript.parameters['LEAF-3']
        post_test_process_dict = {
            'dut_list'                       : [LEAF_1, LEAF_2, LEAF_3],
            'cc_check'                  : 1,
            'cores_check'               : 1,
            'logs_check'                : 1,
            'fnl_flag'                  : 0,
            'exclude_log_check_pattern' : 'ERROR_VLANS_SUSPENDED|ERROR_VLANS_REMOVED',
            }
        try:
            status = infraVerify.postTestVerification(post_test_process_dict)
            if status['status'] == 0:
                self.failed(reason=status['logs'])
            else:
                self.passed(reason=status['logs'])
        except Exception as error:
            log.debug("Unable to unconfigure class map or policy map-Encountered exception " + str(error))
            self.errored('Exception occurred while unconfiguring qos on LEAF1', goto=['next_tc'])       
    # =============================================================================================================================#
 # *****************************************************************************************************************************#
class Configure_sec_ipv6(aetest.Testcase):
    """ Configure_sec_ipv6 """

    
    # =============================================================================================================================#        
    
    @aetest.test
    def SVI_ON_LEAF2(self, testscript):
        """Shut down the vpc leg on Leaf2 to force all traffic to Leaf1"""
        
        LEAF_1 = testscript.parameters['LEAF-1']
        LEAF_2 = testscript.parameters['LEAF-2']
        forwardingSysDict = testscript.parameters['forwardingSysDict']
        l2_vlan_id = testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vlan_start']
        l2_vlan_ipv6_sec_start= testscript.parameters['LEAF_2_dict']['VNI_data']['l2_vlan_ipv6_sec_start']
        l2_vlan_ipv6_mask= testscript.parameters['LEAF_2_dict']['VNI_data']['l2_vlan_ipv6_mask']
        #+ str(testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vlan_ipv4_mask'])
        
        try:
            total_ip_count = int(forwardingSysDict['VLAN_PER_VRF_count']) * int(forwardingSysDict['VRF_count'])
            l2_ipv6s = increment_prefix_network(ip.IPv6Interface(str(l2_vlan_ipv6_sec_start) + str(l2_vlan_ipv6_mask)),total_ip_count)
            ip_index=0
            for i in range(0,len(l2_ipv6s)):
                LEAF_2.configure('''int vlan ''' + str(l2_vlan_id) + '''\n
                                 ipv6 address ''' + str(l2_ipv6s[ip_index]) + ''' use-bia
                                 ''')
                l2_vlan_id += 1
                ip_index += 1
                
            
            
        except Exception as error:
            log.debug("Unable to configure - Encountered Exception " + str(error))
            self.errored('Exception occurred while configuring secondary ipv6 address on LEAF-2', goto=['cleanup'])
            
    # =============================================================================================================================#        
    
    @aetest.test
    def SVI_ON_LEAF1(self, testscript):
        """Shut down the vpc leg on Leaf2 to force all traffic to Leaf1"""
        
        LEAF_1 = testscript.parameters['LEAF-1']
        LEAF_2 = testscript.parameters['LEAF-2']
        forwardingSysDict = testscript.parameters['forwardingSysDict']
        l2_vlan_id = testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vlan_start']
        l2_vlan_ipv6_sec_start= testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vlan_ipv6_sec_start']
        l2_vlan_ipv6_mask= testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vlan_ipv6_mask']
        
        try:
            total_ip_count = int(forwardingSysDict['VLAN_PER_VRF_count']) * int(forwardingSysDict['VRF_count'])
            l2_ipv6s = increment_prefix_network(ip.IPv6Interface(str(l2_vlan_ipv6_sec_start) + str(l2_vlan_ipv6_mask)),total_ip_count)
            ip_index=0
            for i in range(0,len(l2_ipv6s)):
                LEAF_1.configure('''int vlan ''' + str(l2_vlan_id) + '''\n
                                 ipv6 address ''' + str(l2_ipv6s[ip_index]) + ''' use-bia
                                 ''')
                l2_vlan_id += 1
                ip_index += 1
                
            
            
        except Exception as error:
            log.debug("Unable to configure - Encountered Exception " + str(error))
            self.errored('Exception occurred while configuring secondary ipv6 address on LEAF-1', goto=['cleanup'])
            
     # =============================================================================================================================#        
    
    @aetest.test
    def REMOVE_SVI_ON_LEAF2(self, testscript):
        """Shut down the vpc leg on Leaf2 to force all traffic to Leaf1"""
        
        LEAF_1 = testscript.parameters['LEAF-1']
        LEAF_2 = testscript.parameters['LEAF-2']
        forwardingSysDict = testscript.parameters['forwardingSysDict']
        l2_vlan_id = testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vlan_start']
        l2_vlan_ipv6_sec_start= testscript.parameters['LEAF_2_dict']['VNI_data']['l2_vlan_ipv6_sec_start']
        l2_vlan_ipv6_mask= testscript.parameters['LEAF_2_dict']['VNI_data']['l2_vlan_ipv6_mask']
        
        try:
            total_ip_count = int(forwardingSysDict['VLAN_PER_VRF_count']) * int(forwardingSysDict['VRF_count'])
            l2_ipv6s = increment_prefix_network(ip.IPv6Interface(str(l2_vlan_ipv6_sec_start) + str(l2_vlan_ipv6_mask)),total_ip_count)
            ip_index=0
            for i in range(0,len(l2_ipv6s)):
                LEAF_2.configure('''int vlan ''' + str(l2_vlan_id) + '''\n
                                 no ipv6 address ''' + str(l2_ipv6s[ip_index]) + ''' use-bia
                                 ''')
                l2_vlan_id += 1
                ip_index += 1
                
            
            
        except Exception as error:
            log.debug("Unable to configure - Encountered Exception " + str(error))
            self.errored('Exception occurred while configuring secondary ipv6 address on LEAF-2', goto=['cleanup'])
            
     # =============================================================================================================================#        
    
    @aetest.test
    def REMOVE_SVI_ON_LEAF1(self, testscript):
        """Shut down the vpc leg on Leaf2 to force all traffic to Leaf1"""
        
        LEAF_1 = testscript.parameters['LEAF-1']
        LEAF_2 = testscript.parameters['LEAF-2']
        forwardingSysDict = testscript.parameters['forwardingSysDict']
        l2_vlan_id = testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vlan_start']
        l2_vlan_ipv6_sec_start= testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vlan_ipv6_sec_start']
        l2_vlan_ipv6_mask= testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vlan_ipv6_mask']
        
        try:
            total_ip_count = int(forwardingSysDict['VLAN_PER_VRF_count']) * int(forwardingSysDict['VRF_count'])
            l2_ipv6s = increment_prefix_network(ip.IPv6Interface(str(l2_vlan_ipv6_sec_start) + str(l2_vlan_ipv6_mask)),total_ip_count)
            ip_index=0
            for i in range(0,len(l2_ipv6s)):
                LEAF_1.configure('''int vlan ''' + str(l2_vlan_id) + '''\n
                                 no ipv6 address ''' + str(l2_ipv6s[ip_index]) + ''' use-bia
                                 ''')
                l2_vlan_id += 1
                ip_index += 1
                
            
            
        except Exception as error:
            log.debug("Unable to configure - Encountered Exception " + str(error))
            self.errored('Exception occurred while configuring secondary ipv6 address on LEAF-1', goto=['cleanup'])
            
     # =============================================================================================================================#        
    
    @aetest.test
    def ADD_SVI_ON_LEAF2(self, testscript):
        """Shut down the vpc leg on Leaf2 to force all traffic to Leaf1"""
        
        LEAF_1 = testscript.parameters['LEAF-1']
        LEAF_2 = testscript.parameters['LEAF-2']
        forwardingSysDict = testscript.parameters['forwardingSysDict']
        l2_vlan_id = testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vlan_start']
        l2_vlan_ipv6_sec_start= testscript.parameters['LEAF_2_dict']['VNI_data']['l2_vlan_ipv6_sec_start']
        l2_vlan_ipv6_mask= testscript.parameters['LEAF_2_dict']['VNI_data']['l2_vlan_ipv6_mask']
        
        try:
            total_ip_count = int(forwardingSysDict['VLAN_PER_VRF_count']) * int(forwardingSysDict['VRF_count'])
            l2_ipv6s = increment_prefix_network(ip.IPv6Interface(str(l2_vlan_ipv6_sec_start) + str(l2_vlan_ipv6_mask)),total_ip_count)
            ip_index=0
            for i in range(0,len(l2_ipv6s)):
                LEAF_2.configure('''int vlan ''' + str(l2_vlan_id) + '''\n
                                 ipv6 address ''' + str(l2_ipv6s[ip_index]) + ''' use-bia
                                 ''')
                l2_vlan_id += 1
                ip_index += 1
                
            
            
        except Exception as error:
            log.debug("Unable to configure - Encountered Exception " + str(error))
            self.errored('Exception occurred while configuring secondary ipv6 address on LEAF-2', goto=['cleanup'])
            
     # =============================================================================================================================#        
    
    @aetest.test
    def ADD_SVI_ON_LEAF1(self, testscript):
        """Shut down the vpc leg on Leaf2 to force all traffic to Leaf1"""
        
        LEAF_1 = testscript.parameters['LEAF-1']
        LEAF_2 = testscript.parameters['LEAF-2']
        forwardingSysDict = testscript.parameters['forwardingSysDict']
        l2_vlan_id = testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vlan_start']
        l2_vlan_ipv6_sec_start= testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vlan_ipv6_sec_start']
        l2_vlan_ipv6_mask= testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vlan_ipv6_mask']
        
        try:
            total_ip_count = int(forwardingSysDict['VLAN_PER_VRF_count']) * int(forwardingSysDict['VRF_count'])
            l2_ipv6s = increment_prefix_network(ip.IPv6Interface(str(l2_vlan_ipv6_sec_start) + str(l2_vlan_ipv6_mask)),total_ip_count)
            ip_index=0
            for i in range(0,len(l2_ipv6s)):
                LEAF_1.configure('''int vlan ''' + str(l2_vlan_id) + '''\n
                                 ipv6 address ''' + str(l2_ipv6s[ip_index]) + ''' use-bia
                                 ''')
                l2_vlan_id += 1
                ip_index += 1
                
            
            
        except Exception as error:
            log.debug("Unable to configure - Encountered Exception " + str(error))
            self.errored('Exception occurred while configuring secondary ipv6 address on LEAF-1', goto=['cleanup'])
   
     
    @aetest.cleanup
    def cleanup(self,testscript):
        """Unconfigure qos policies"""
        LEAF_1 = testscript.parameters['LEAF-1']
        LEAF_2 = testscript.parameters['LEAF-2']
        LEAF_3 = testscript.parameters['LEAF-3']
        post_test_process_dict = {
            'dut_list'                       : [LEAF_1, LEAF_2, LEAF_3],
            'cc_check'                  : 1,
            'cores_check'               : 1,
            'logs_check'                : 1,
            'fnl_flag'                  : 0,
            'exclude_log_check_pattern' : 'ERROR_VLANS_SUSPENDED|ERROR_VLANS_REMOVED',
            }
        try:
            status = infraVerify.postTestVerification(post_test_process_dict)
            if status['status'] == 0:
                self.failed(reason=status['logs'])
            else:
                self.passed(reason=status['logs'])
        except Exception as error:
            log.debug("Unable to unconfigure class map or policy map-Encountered exception " + str(error))
            self.errored('Exception occurred while unconfiguring qos on LEAF1', goto=['next_tc'])          
#    # =============================================================================================================================#

# *****************************************************************************************************************************#
class External_Interface(aetest.Testcase):
    """ Configure_sec_ipv4 """

    
    # =============================================================================================================================#        
    
    @aetest.test
    def Configure_external_int(self, testscript):
        """Shut down the vpc leg on Leaf2 to force all traffic to Leaf1"""
        
        LEAF_1 = testscript.parameters['LEAF-1']
        LEAF_2 = testscript.parameters['LEAF-2']
        
        try:
            testscript.parameters['LEAF-2'].configure('''
                  interface po ''' + str(testscript.parameters['LEAF_1_dict']['VPC_data']['double_vpc_po_1']) + '''
                  port-type external
                  ''')
            
            testscript.parameters['LEAF-1'].configure('''
                  interface po ''' + str(testscript.parameters['LEAF_1_dict']['VPC_data']['double_vpc_po_1']) + '''
                  port-type external
                  ''')    
            
            
        except Exception as error:
            log.debug("Unable to configure - Encountered Exception " + str(error))
            self.errored('Exception occurred while configuring external on LEAF-1 and LEAF-2', goto=['cleanup'])
            
    # =============================================================================================================================#        
    
    @aetest.test
    def Remove_external_int(self, testscript):
        """Shut down the vpc leg on Leaf2 to force all traffic to Leaf1"""
        
        LEAF_1 = testscript.parameters['LEAF-1']
        LEAF_2 = testscript.parameters['LEAF-2']
        
        try:
            testscript.parameters['LEAF-2'].configure('''
                  interface po ''' + str(testscript.parameters['LEAF_1_dict']['VPC_data']['double_vpc_po_1']) + '''
                  no port-type external
                  ''')
            
            testscript.parameters['LEAF-1'].configure('''
                  interface po ''' + str(testscript.parameters['LEAF_1_dict']['VPC_data']['double_vpc_po_1']) + '''
                  no port-type external
                  ''')    
            
            
        except Exception as error:
            log.debug("Unable to configure - Encountered Exception " + str(error))
            self.errored('Exception occurred while configuring external on LEAF-1 and LEAF-2', goto=['cleanup'])
            
     # =============================================================================================================================#        
    
    @aetest.test
    def Add_external_int(self, testscript):
        """Shut down the vpc leg on Leaf2 to force all traffic to Leaf1"""
        
        LEAF_1 = testscript.parameters['LEAF-1']
        LEAF_2 = testscript.parameters['LEAF-2']
        
        try:
            testscript.parameters['LEAF-2'].configure('''
                  interface po ''' + str(testscript.parameters['LEAF_1_dict']['VPC_data']['double_vpc_po_1']) + '''
                  port-type external
                  ''')
            
            testscript.parameters['LEAF-1'].configure('''
                  interface po ''' + str(testscript.parameters['LEAF_1_dict']['VPC_data']['double_vpc_po_1']) + '''
                  port-type external
                  ''')    
            
            
        except Exception as error:
            log.debug("Unable to configure - Encountered Exception " + str(error))
            self.errored('Exception occurred while configuring external on LEAF-1 and LEAF-2', goto=['cleanup'])
            
     # =============================================================================================================================#        
    
    @aetest.test
    def Flap_external_int(self, testscript):
        """Shut down the vpc leg on Leaf2 to force all traffic to Leaf1"""
        
        LEAF_1 = testscript.parameters['LEAF-1']
        LEAF_2 = testscript.parameters['LEAF-2']
        
        try:
            testscript.parameters['LEAF-2'].configure('''
                  interface po ''' + str(testscript.parameters['LEAF_1_dict']['VPC_data']['double_vpc_po_1']) + '''
                  port-type external
                  shut
                  ''')
            
            testscript.parameters['LEAF-1'].configure('''
                  interface po ''' + str(testscript.parameters['LEAF_1_dict']['VPC_data']['double_vpc_po_1']) + '''
                  port-type external
                  shut
                  ''')    
            
            testscript.parameters['LEAF-2'].configure('''
                  interface po ''' + str(testscript.parameters['LEAF_1_dict']['VPC_data']['double_vpc_po_1']) + '''
                  no shut
                  ''')
            
            testscript.parameters['LEAF-1'].configure('''
                  interface po ''' + str(testscript.parameters['LEAF_1_dict']['VPC_data']['double_vpc_po_1']) + '''
                  no shut
                  ''')    
            
        except Exception as error:
            log.debug("Unable to configure - Encountered Exception " + str(error))
            self.errored('Exception occurred while flapping external on LEAF-1 and LEAF-2', goto=['cleanup'])
            
     
   # =============================================================================================================================#   
     
    @aetest.cleanup
    def cleanup(self,testscript):
        """Unconfigure qos policies"""
        LEAF_1 = testscript.parameters['LEAF-1']
        LEAF_2 = testscript.parameters['LEAF-2']
        LEAF_3 = testscript.parameters['LEAF-3']
        post_test_process_dict = {
            'dut_list'                       : [LEAF_1, LEAF_2, LEAF_3],
            'cc_check'                  : 1,
            'cores_check'               : 1,
            'logs_check'                : 1,
            'fnl_flag'                  : 0,
            'exclude_log_check_pattern' : 'ERROR_VLANS_SUSPENDED|ERROR_VLANS_REMOVED',
            }
        try:
            status = infraVerify.postTestVerification(post_test_process_dict)
            if status['status'] == 0:
                self.failed(reason=status['logs'])
            else:
                self.passed(reason=status['logs'])
        except Exception as error:
            log.debug("Unable to unconfigure class map or policy map-Encountered exception " + str(error))
            self.errored('Exception occurred while unconfiguring qos on LEAF1', goto=['next_tc'])       
    # =============================================================================================================================#
# *****************************************************************************************************************************#
class Host_move_FP_to_Vxlan_ipv4(aetest.Testcase):
    """ Host_move_ipv4 """

    
    # =============================================================================================================================#        
    
    @aetest.test
    def SVI_ON_LEAF2(self, testscript):
        """Shut down the vpc leg on Leaf2 to force all traffic to Leaf1"""
        
        LEAF_1 = testscript.parameters['LEAF-1']
        LEAF_2 = testscript.parameters['LEAF-2']
        forwardingSysDict = testscript.parameters['forwardingSysDict']
        l2_vlan_id = testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vlan_start']
        l2_vlan_ipv4_sec_start= testscript.parameters['LEAF_2_dict']['VNI_data']['l2_vlan_ipv4_sec_start']
        l2_vlan_ipv4_mask= testscript.parameters['LEAF_2_dict']['VNI_data']['l2_vlan_ipv4_mask']
        #+ str(testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vlan_ipv4_mask'])
        
        try:
            total_ip_count = int(forwardingSysDict['VLAN_PER_VRF_count']) * int(forwardingSysDict['VRF_count'])
            l2_ipv4s = increment_prefix_network(ip.IPv4Interface(str(l2_vlan_ipv4_sec_start) + str(l2_vlan_ipv4_mask)),total_ip_count)
            ip_index=0
            for i in range(0,len(l2_ipv4s)):
                LEAF_2.configure('''int vlan ''' + str(l2_vlan_id) + '''\n
                                 ip address ''' + str(l2_ipv4s[ip_index]) + ''' secondary use-bia
                                 ''')
                l2_vlan_id += 1
                ip_index += 1
                
            
            
        except Exception as error:
            log.debug("Unable to configure - Encountered Exception " + str(error))
            self.errored('Exception occurred while configuring secondary ipv4 address on LEAF-2', goto=['cleanup'])
            
    # =============================================================================================================================#        
    
    @aetest.test
    def SVI_ON_LEAF1(self, testscript):
        """Shut down the vpc leg on Leaf2 to force all traffic to Leaf1"""
        
        LEAF_1 = testscript.parameters['LEAF-1']
        LEAF_2 = testscript.parameters['LEAF-2']
        forwardingSysDict = testscript.parameters['forwardingSysDict']
        l2_vlan_id = testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vlan_start']
        l2_vlan_ipv4_sec_start= testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vlan_ipv4_sec_start']
        l2_vlan_ipv4_mask= testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vlan_ipv4_mask']
        
        try:
            total_ip_count = int(forwardingSysDict['VLAN_PER_VRF_count']) * int(forwardingSysDict['VRF_count'])
            l2_ipv4s = increment_prefix_network(ip.IPv4Interface(str(l2_vlan_ipv4_sec_start) + str(l2_vlan_ipv4_mask)),total_ip_count)
            ip_index=0
            for i in range(0,len(l2_ipv4s)):
                LEAF_1.configure('''int vlan ''' + str(l2_vlan_id) + '''\n
                                 ip address ''' + str(l2_ipv4s[ip_index]) + ''' secondary use-bia
                                 ''')
                l2_vlan_id += 1
                ip_index += 1
                
            
            
        except Exception as error:
            log.debug("Unable to configure - Encountered Exception " + str(error))
            self.errored('Exception occurred while configuring secondary ipv4 address on LEAF-1', goto=['cleanup'])
            
     # =============================================================================================================================#        
    @aetest.test
    def Add_external_int(self, testscript):
        """Shut down the vpc leg on Leaf2 to force all traffic to Leaf1"""
        
        LEAF_1 = testscript.parameters['LEAF-1']
        LEAF_2 = testscript.parameters['LEAF-2']
        
        try:
            testscript.parameters['LEAF-2'].configure('''
                  interface po ''' + str(testscript.parameters['LEAF_1_dict']['VPC_data']['double_vpc_po_1']) + '''
                  port-type external
                  ''')
            
            testscript.parameters['LEAF-1'].configure('''
                  interface po ''' + str(testscript.parameters['LEAF_1_dict']['VPC_data']['double_vpc_po_1']) + '''
                  port-type external
                  ''')    
            
            
        except Exception as error:
            log.debug("Unable to configure - Encountered Exception " + str(error))
            self.errored('Exception occurred while configuring external on LEAF-1 and LEAF-2', goto=['cleanup'])
            
     # =============================================================================================================================#    
    @aetest.test
    def Pre_migration_hsrp(self,testscript):
        LEAF_1 = testscript.parameters['LEAF-1']
        LEAF_2 = testscript.parameters['LEAF-2']
        forwardingSysDict = testscript.parameters['forwardingSysDict']
        l2_vlan_id = testscript.parameters['N7K_LEAF_1_dict']['Vlan_data']['l2_vlan_start']
        l2_vlan_ipv4_start= testscript.parameters['N7K_LEAF_1_dict']['Vlan_data']['l2_vlan_ipv4_start']
        l2_vlan_ipv4_mask= testscript.parameters['N7K_LEAF_1_dict']['Vlan_data']['l2_vlan_ipv4_mask']
        l2_vlan_ipv6_start= testscript.parameters['N7K_LEAF_1_dict']['Vlan_data']['l2_vlan_ipv6_start']
        l2_vlan_ipv6_mask= testscript.parameters['N7K_LEAF_1_dict']['Vlan_data']['l2_vlan_ipv6_mask']
        l2_hsrp_ipv4_vip_start= testscript.parameters['N7K_LEAF_1_dict']['Vlan_data']['hsrp_ipv4_vip_start']
        l2_hsrp_ipv6_vip_start= testscript.parameters['N7K_LEAF_1_dict']['Vlan_data']['hsrp_ipv6_vip_start']
        
        try:
            device_handle=connect_to_vdc(testscript.parameters['xbow1'], 'leaf1')
            if device_handle==False:
                log.info("failed to switchto correct vdc")
                self.failed("failed to switchto correct vdc",goto=['common_cleanup'])
            else:
                total_ip_count = int(forwardingSysDict['VLAN_PER_VRF_count']) * int(forwardingSysDict['VRF_count'])
                l2_ipv4s = increment_prefix_network(ip.IPv4Interface(str(l2_vlan_ipv4_start) + str(l2_vlan_ipv4_mask)),total_ip_count)
                l2_ipv6s = increment_prefix_network(ip.IPv6Interface(str(l2_vlan_ipv6_start) + str(l2_vlan_ipv6_mask)),total_ip_count)
                ip_index=0
                for i in range(0,len(l2_ipv4s)):
                    device_handle.configure('''int vlan ''' + str(l2_vlan_id) + '''\n
                                     hsrp version 2
                                     hsrp ''' + str(l2_vlan_id) + ''' ipv4
                                     mac-address 0000.000a.aaaa
                                     ''')
                    l2_vlan_id += 1
            l2_vlan_id = testscript.parameters['N7K_LEAF_1_dict']['Vlan_data']['l2_vlan_start']        
            device_handle=connect_to_vdc(testscript.parameters['xbow2'], 'leaf2')
            if device_handle==False:
                log.info("failed to switchto correct vdc")
                self.failed("failed to switchto correct vdc",goto=['common_cleanup'])
            else:
                total_ip_count = int(forwardingSysDict['VLAN_PER_VRF_count']) * int(forwardingSysDict['VRF_count'])
                l2_ipv4s = increment_prefix_network(ip.IPv4Interface(str(l2_vlan_ipv4_start) + str(l2_vlan_ipv4_mask)),total_ip_count)
                l2_ipv6s = increment_prefix_network(ip.IPv6Interface(str(l2_vlan_ipv6_start) + str(l2_vlan_ipv6_mask)),total_ip_count)
                ip_index=0
                for i in range(0,len(l2_ipv4s)):
                    device_handle.configure('''int vlan ''' + str(l2_vlan_id) + '''\n
                                     hsrp version 2
                                     hsrp ''' + str(l2_vlan_id) + ''' ipv4
                                     mac-address 0000.000a.aaaa
                                     ''')
                    l2_vlan_id += 1
                    


        except Exception as error:
                log.debug("Unable to configure - Encountered Exception " + str(error))
                self.errored('Exception occurred while configuring on N7k leaf1', goto=['common_cleanup'])
                
    @aetest.test        
    def configure_FO(self,testscript):
        
        FO_1_vlanConfiguration = ""
        FO_1=testscript.parameters['FO_1']

        l3_vrf_count_iter = 0
        l2_vlan_id = testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vlan_start']
        l3_vlan_id = testscript.parameters['LEAF_1_dict']['VNI_data']['l3_vlan_start']

        while l3_vrf_count_iter < testscript.parameters['forwardingSysDict']['VRF_count']:
            l2_vlan_count_iter = 0
            FO_1_vlanConfiguration += '''vlan ''' + str(l3_vlan_id) + '''\n
                                            state active\n
                                            no shut\n'''
            while l2_vlan_count_iter < testscript.parameters['forwardingSysDict']['VLAN_PER_VRF_count']:
                # Incrementing L2 VLAN Iteration counters
                FO_1_vlanConfiguration += '''vlan ''' + str(l2_vlan_id) + '''\n
                                                state active\n
                                                no shut\n'''
                l2_vlan_count_iter += 1
                l2_vlan_id += 1
            # Incrementing L3 VRF Iteration counters
            l3_vrf_count_iter += 1
            l3_vlan_id += 1

        try:
            FO_1.configure(
                str(FO_1_vlanConfiguration) + '''
        
        
            
            interface ''' + str(testscript.parameters['intf_FO_1_to_N7k_LEAF_3']) + '''
            no shut
            switchport
            switchport mode trunk
            
            interface ''' + str(testscript.parameters['intf_FO_1_to_LEAF_3']) + '''
            shut
            switchport
            switchport mode trunk
            
            interface ''' + str(testscript.parameters['intf_FO_1_to_IXIA']) + '''
            no shut
            switchport
            switchport mode trunk
            
            ''')
        except Exception as error:
                log.debug("Unable to configure - Encountered Exception " + str(error))
                self.errored('Exception occurred while configuring on FO_1', goto=['common_cleanup'])
   
#     @aetest.test
#     def CONFIGURE_UCAST_L3_IXIA_TRAFFIC(self, testscript):
#         """ IXIA_CONFIGURATION subsection: Configure MCAST Traffic Item """
# 
#         # Do not perform configurations if skip_tgen_config flag is set
#         if not testscript.parameters['script_flags']['skip_tgen_config']:
# 
#             IX_TP1 = testscript.parameters['IX_TP1']
#             IX_TP2 = testscript.parameters['IX_TP2']
#             P1_dict = testscript.parameters['LEAF_2_TGEN_dict']
#             P2_dict = testscript.parameters['LEAF_3_TGEN_dict']
# 
#             UCAST_v4_dict = {   'src_hndl'  : IX_TP1['port_handle'],
#                                 'dst_hndl'  : IX_TP2['port_handle'],
#                                 'ip_dscp'   : P1_dict['ip_dscp'],
#                                 'circuit'   : 'raw',
#                                 'TI_name'   : "UCAST_L3",
#                                 'rate_pps'  : "9000",
#                                 'bi_dir'    : 1,
#                                 'frame_size': '128',
#                                 'src_mac'   : P1_dict['mac'],
#                                 'dst_mac'   : '0000.000a.aaaa',
#                                 'srcmac_step': '00:00:00:00:00:00',
#                                 'dstmac_step': '00:00:00:00:00:00',
#                                 'srcmac_count': '1',
#                                 'dstmac_count': '1',
#                                 'vlan_id'    : P1_dict['vlan_id'],
#                                 'vlanid_step': '0',
#                                 'vlanid_count': '1',
#                                 'vlan_user_priority': P1_dict['vlan_user_priority'],
#                                 'ip_src_addrs' : P1_dict['v4_addr'],
#                                 'ip_dst_addrs' : P1_dict['L3_dst_addr'],
#                                 'ip_src_step' : '0.0.0.0',
#                                 'ip_dst_step' : '0.0.0.0',
# #                                'ip_step'    : P1_dict['v4_addr_step'],
#                           }
# 
# #            UCAST_v6_dict = {   'src_hndl'  : IX_TP1['ipv6_handle'],
# #                                'dst_hndl'  : IX_TP2['ipv6_handle'],
# #                                'circuit'   : 'ipv6',
# #                                'TI_name'   : "UCAST_V6",
# #                                'rate_pps'  : "1000",
# #                                'bi_dir'    : 1
# #                          }
# 
#             UCAST_v4_TI = ixLib.configure_ixia_l3_traffic_item(UCAST_v4_dict)
# #            UCAST_v6_TI = ixLib.configure_ixia_traffic_item(UCAST_v6_dict)
# 
# #            if UCAST_v4_TI == 0 or UCAST_v6_TI == 0:
# #                log.debug("Configuring UCast TI failed")
# #                self.errored("Configuring UCast TI failed", goto=['cleanup'])
#                 
#             if UCAST_v4_TI == 0:
#                 log.debug("Configuring UCast TI failed")
#                 self.errored("Configuring UCast TI failed", goto=['cleanup'])
#             else:
#                 global stream_id
#                 stream_id = UCAST_v4_TI
# 
#         else:
#             self.passed(reason="Skipped TGEN Configurations as per request")
            
    @aetest.test
    def CONFIGURE_BCAST_IXIA_TRAFFIC(self, testscript):
        """ IXIA_CONFIGURATION subsection: Configure MCAST Traffic Item """
    
        # Do not perform configurations if skip_tgen_config flag is set
        if not testscript.parameters['script_flags']['skip_tgen_config']:
    
            IX_TP1 = testscript.parameters['IX_TP1']
            IX_TP2 = testscript.parameters['IX_TP2']
            P1_dict = testscript.parameters['LEAF_2_TGEN_dict']
            P2_dict = testscript.parameters['LEAF_3_TGEN_dict']
            BCAST_v4_dict = {
                                'src_hndl'      : IX_TP1['port_handle'],
                                'dst_hndl'      : IX_TP2['port_handle'],
                                'TI_name'       : "BCAST_V4",
                                'frame_size'    : "70",
                                'rate_pps'      : "1000",
                                'src_mac'       : P1_dict['mac'],
                                'srcmac_step'   : "00:00:00:00:00:01",
                                'srcmac_count'  : '1',
                                'vlan_id'       : P1_dict['vlan_id'],
                                'vlanid_step'   : "1",
                                'vlanid_count'  : "1",
                                'ip_src_addrs'  : P1_dict['v4_addr'],
                                'ip_step'       : "0.0.1.0",
                          }
    
            BCAST_v4_TI = ixLib.configure_ixia_BCAST_traffic_item(BCAST_v4_dict)
    
            if BCAST_v4_TI == 0:
                log.debug("Configuring BCast TI failed")
                self.errored("Configuring BCast TI failed", goto=['cleanup'])
            else:
                global stream_id_2
                stream_id_2 = BCAST_v4_TI
    
        else:
            self.passed(reason="Skipped TGEN Configurations as per request")
    # =============================================================================================================================#
    @aetest.test
    def APPLY_TRAFFIC(self):
        """ IXIA_CONFIGURATION subsection: Verify IXIA Traffic """

        # Apply IXIA Traffic
        if ixLib.apply_traffic() == 1:
            log.info("Applying IXIA TI Passed")
        else:
            self.errored("Applying IXIA TI failed", goto=['cleanup'])
            
        # =============================================================================================================================#
    #--------------------------------------------------------------------------------#
        # Start traffic from ixia
        log.info("--- Populating the statistics --- \n")
        log.info("---- Running Traffic --- \n")
        log.info("Starting Traffic")

        traffic_run_status  = ixLib.start_traffic()

        if traffic_run_status is not 1:
           log.info("Failed: To start traffic")
           return 0
        else:
            log.info("\nTraffic started successfully\n")

        time.sleep(30)
    
    # Stop Traffic from ixia
        log.info("--- Stopping Traffic ---- \n")
        log.info("Stopping Traffic")
        traffic_run_status = ixLib.stop_traffic()
        
        if traffic_run_status is not 1:
           log.info("Failed: To Stop traffic")
           return 0
        else:
            log.info("\nTraffic Stopped successfully\n")
            time.sleep(10)    
    
    @aetest.test
    def VERIFY_IXIA_TRAFFIC(self, testscript):
        """ IXIA_CONFIGURATION subsection: Verify IXIA Traffic """

        # Do not perform configurations if skip_tgen_config flag is set
        if not testscript.parameters['script_flags']['skip_tgen_config']:

            time.sleep(20)

            if ixLib.verify_traffic(2) == 0:
                log.debug("Traffic Verification failed")
                self.failed("Traffic Verification failed", goto=['cleanup'])
            else:
                log.info("Traffic Verification Passed")
        else:
            self.passed(reason="Skipped TGEN Configurations as per request")
            
     # =============================================================================================================================#        
    @aetest.test
    def Clear_ARP_Table_on_Vxlan_BLs(self, testscript):
        """Shut down the vpc leg on Leaf2 to force all traffic to Leaf1"""
        
        LEAF_1 = testscript.parameters['LEAF-1']
        LEAF_2 = testscript.parameters['LEAF-2']
        
        try:
            for i in range(1, testscript.parameters['forwardingSysDict']['VRF_count']+1):
                testscript.parameters['LEAF-2'].execute('''
                      clear ip arp vrf ''' + str(testscript.parameters['forwardingSysDict']['VRF_string']) + str(i) + ''' force-delete''')
            
            for i in range(1, testscript.parameters['forwardingSysDict']['VRF_count']+1):
                testscript.parameters['LEAF-1'].execute('''
                      clear ip arp vrf ''' + str(testscript.parameters['forwardingSysDict']['VRF_string']) + str(i) + ''' force-delete''')    
            
            
        except Exception as error:
            log.debug("Unable to configure - Encountered Exception " + str(error))
            self.errored('Exception occurred while clearing arp cache on LEAF-1 and LEAF-2', goto=['cleanup'])
            
    @aetest.test        
    def Host_move_FO(self,testscript):
        
        
        FO_1=testscript.parameters['FO_1']

        
        try:
            FO_1.configure('''
            interface ''' + str(testscript.parameters['intf_FO_1_to_N7k_LEAF_3']) + '''
            shut
            switchport
            switchport mode trunk
            
            interface ''' + str(testscript.parameters['intf_FO_1_to_LEAF_3']) + '''
            no shut
            switchport
            switchport mode trunk
            
            ''')
            time.sleep(45)
        except Exception as error:
                log.debug("Unable to configure - Encountered Exception " + str(error))
                self.errored('Exception occurred while configuring on FO_1', goto=['common_cleanup'])
                
    @aetest.test
    def VERIFY_IXIA_TRAFFIC_AFTER_MOVE(self, testscript):
        """ IXIA_CONFIGURATION subsection: Verify IXIA Traffic """

        # Do not perform configurations if skip_tgen_config flag is set
        if not testscript.parameters['script_flags']['skip_tgen_config']:

            time.sleep(20)

            if ixLib.verify_traffic(15) == 0:
                log.debug("Traffic Verification failed")
                self.failed("Traffic Verification failed", goto=['cleanup'])
            else:
                log.info("Traffic Verification Passed")
        else:
            self.passed(reason="Skipped TGEN Configurations as per request")
            
    @aetest.test        
    def Host_move_FO_BACK(self,testscript):
        
        
        FO_1=testscript.parameters['FO_1']

        
        try:
            FO_1.configure('''
            interface ''' + str(testscript.parameters['intf_FO_1_to_LEAF_3']) + '''
            shut
            switchport
            switchport mode trunk
            
            interface ''' + str(testscript.parameters['intf_FO_1_to_N7k_LEAF_3']) + '''
            no shut
            switchport
            switchport mode trunk
            
            
            
            ''')
            time.sleep(45)
        except Exception as error:
                log.debug("Unable to configure - Encountered Exception " + str(error))
                self.errored('Exception occurred while configuring on FO_1', goto=['common_cleanup'])
                
    @aetest.test
    def VERIFY_IXIA_TRAFFIC_HOST_MOVE_BACK(self, testscript):
        """ IXIA_CONFIGURATION subsection: Verify IXIA Traffic """

        # Do not perform configurations if skip_tgen_config flag is set
        if not testscript.parameters['script_flags']['skip_tgen_config']:

            time.sleep(20)

            if ixLib.verify_traffic(15) == 0:
                log.debug("Traffic Verification failed")
                self.failed("Traffic Verification failed", goto=['cleanup'])
            else:
                log.info("Traffic Verification Passed")
        else:
            self.passed(reason="Skipped TGEN Configurations as per request")
        
    @aetest.cleanup
    def cleanup(self,testscript):
        """Unconfigure qos policies"""
        LEAF_1 = testscript.parameters['LEAF-1']
        LEAF_2 = testscript.parameters['LEAF-2']
        LEAF_3 = testscript.parameters['LEAF-3']
        FO_1=testscript.parameters['FO_1']
        LEAF_1 = testscript.parameters['LEAF-1']
        LEAF_2 = testscript.parameters['LEAF-2']
        forwardingSysDict = testscript.parameters['forwardingSysDict']
        l2_vlan_id = testscript.parameters['N7K_LEAF_1_dict']['Vlan_data']['l2_vlan_start']
        l2_vlan_ipv4_start= testscript.parameters['N7K_LEAF_1_dict']['Vlan_data']['l2_vlan_ipv4_start']
        l2_vlan_ipv4_mask= testscript.parameters['N7K_LEAF_1_dict']['Vlan_data']['l2_vlan_ipv4_mask']
        l2_vlan_ipv6_start= testscript.parameters['N7K_LEAF_1_dict']['Vlan_data']['l2_vlan_ipv6_start']
        l2_vlan_ipv6_mask= testscript.parameters['N7K_LEAF_1_dict']['Vlan_data']['l2_vlan_ipv6_mask']
        l2_hsrp_ipv4_vip_start= testscript.parameters['N7K_LEAF_1_dict']['Vlan_data']['hsrp_ipv4_vip_start']
        l2_hsrp_ipv6_vip_start= testscript.parameters['N7K_LEAF_1_dict']['Vlan_data']['hsrp_ipv6_vip_start']
        
        post_test_process_dict = {
            'dut_list'                       : [LEAF_1, LEAF_2, LEAF_3],
            'cc_check'                  : 1,
            'cores_check'               : 1,
            'logs_check'                : 0,
            'fnl_flag'                  : 0,
            'exclude_log_check_pattern' : 'ERROR_VLANS_SUSPENDED|ERROR_VLANS_REMOVED',
            }
        try:
            FO_1.configure('''
            interface ''' + str(testscript.parameters['intf_FO_1_to_LEAF_3']) + '''
            shut
            switchport
            switchport mode trunk
            
            interface ''' + str(testscript.parameters['intf_FO_1_to_N7k_LEAF_3']) + '''
            no shut
            switchport
            switchport mode trunk
            ''')
            
            # UCAST_v4_dict = {
            #                 'mode'        : 'remove',
            #                 'stream_id'   : stream_id,
            #           }
            # if (ixLib.delete_traffic_item(UCAST_v4_dict))==0:
            #     log.debug("Traffic Remove failed")
            #     self.failed("Traffic Remove failed")
            # else:
            #     log.info("Traffic Deletion Passed")
                
            BCAST_v4_dict = {
                            'mode'        : 'remove',
                            'stream_id'   : stream_id_2,
                      }
            if (ixLib.delete_traffic_item(BCAST_v4_dict))==0:
                log.debug("Traffic Remove failed")
                self.failed("Traffic Remove failed")
            else:
                log.info("Traffic Deletion Passed")
            time.sleep(30)
            ###Remove Pre-migration step from both N7k leafs
            device_handle=connect_to_vdc(testscript.parameters['xbow1'], 'leaf1')
            if device_handle==False:
                log.info("failed to switchto correct vdc")
                self.failed("failed to switchto correct vdc",goto=['common_cleanup'])
            else:
                total_ip_count = int(forwardingSysDict['VLAN_PER_VRF_count']) * int(forwardingSysDict['VRF_count'])
                l2_ipv4s = increment_prefix_network(ip.IPv4Interface(str(l2_vlan_ipv4_start) + str(l2_vlan_ipv4_mask)),total_ip_count)
                l2_ipv6s = increment_prefix_network(ip.IPv6Interface(str(l2_vlan_ipv6_start) + str(l2_vlan_ipv6_mask)),total_ip_count)
                ip_index=0
                for i in range(0,len(l2_ipv4s)):
                    device_handle.configure('''int vlan ''' + str(l2_vlan_id) + '''\n
                                     hsrp version 2
                                     hsrp ''' + str(l2_vlan_id) + ''' ipv4
                                     no mac-address 0000.000a.aaaa
                                     ''')
                    l2_vlan_id += 1
            l2_vlan_id = testscript.parameters['N7K_LEAF_1_dict']['Vlan_data']['l2_vlan_start']        
            device_handle=connect_to_vdc(testscript.parameters['xbow2'], 'leaf2')
            if device_handle==False:
                log.info("failed to switchto correct vdc")
                self.failed("failed to switchto correct vdc",goto=['common_cleanup'])
            else:
                total_ip_count = int(forwardingSysDict['VLAN_PER_VRF_count']) * int(forwardingSysDict['VRF_count'])
                l2_ipv4s = increment_prefix_network(ip.IPv4Interface(str(l2_vlan_ipv4_start) + str(l2_vlan_ipv4_mask)),total_ip_count)
                l2_ipv6s = increment_prefix_network(ip.IPv6Interface(str(l2_vlan_ipv6_start) + str(l2_vlan_ipv6_mask)),total_ip_count)
                ip_index=0
                for i in range(0,len(l2_ipv4s)):
                    device_handle.configure('''int vlan ''' + str(l2_vlan_id) + '''\n
                                     hsrp version 2
                                     hsrp ''' + str(l2_vlan_id) + ''' ipv4
                                     no mac-address 0000.000a.aaaa
                                     ''')
                    l2_vlan_id += 1
            status = infraVerify.postTestVerification(post_test_process_dict)
            if status['status'] == 0:
                self.failed(reason=status['logs'])
            else:
                self.passed(reason=status['logs'])
        except Exception as error:
            log.debug("Unable to unconfigure class map or policy map-Encountered exception " + str(error))
            self.errored('Exception occurred while unconfiguring qos on LEAF1', goto=['next_tc'])       
    # =============================================================================================================================#
    
# *****************************************************************************************************************************#
class Host_move_Orphan_ipv4(aetest.Testcase):
    """ Host_move_ipv4 """

    
    # =============================================================================================================================#        
    
    @aetest.test
    def SVI_ON_LEAF2(self, testscript):
        """Shut down the vpc leg on Leaf2 to force all traffic to Leaf1"""
        
        LEAF_1 = testscript.parameters['LEAF-1']
        LEAF_2 = testscript.parameters['LEAF-2']
        forwardingSysDict = testscript.parameters['forwardingSysDict']
        l2_vlan_id = testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vlan_start']
        l2_vlan_ipv4_sec_start= testscript.parameters['LEAF_2_dict']['VNI_data']['l2_vlan_ipv4_sec_start']
        l2_vlan_ipv4_mask= testscript.parameters['LEAF_2_dict']['VNI_data']['l2_vlan_ipv4_mask']
        #+ str(testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vlan_ipv4_mask'])
        
        try:
            total_ip_count = int(forwardingSysDict['VLAN_PER_VRF_count']) * int(forwardingSysDict['VRF_count'])
            l2_ipv4s = increment_prefix_network(ip.IPv4Interface(str(l2_vlan_ipv4_sec_start) + str(l2_vlan_ipv4_mask)),total_ip_count)
            ip_index=0
            for i in range(0,len(l2_ipv4s)):
                LEAF_2.configure('''int vlan ''' + str(l2_vlan_id) + '''\n
                                 ip address ''' + str(l2_ipv4s[ip_index]) + ''' secondary use-bia
                                 ''')
                l2_vlan_id += 1
                ip_index += 1
                
            
            
        except Exception as error:
            log.debug("Unable to configure - Encountered Exception " + str(error))
            self.errored('Exception occurred while configuring secondary ipv4 address on LEAF-2', goto=['cleanup'])
            
    # =============================================================================================================================#        
    
    @aetest.test
    def SVI_ON_LEAF1(self, testscript):
        """Shut down the vpc leg on Leaf2 to force all traffic to Leaf1"""
        
        LEAF_1 = testscript.parameters['LEAF-1']
        LEAF_2 = testscript.parameters['LEAF-2']
        forwardingSysDict = testscript.parameters['forwardingSysDict']
        l2_vlan_id = testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vlan_start']
        l2_vlan_ipv4_sec_start= testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vlan_ipv4_sec_start']
        l2_vlan_ipv4_mask= testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vlan_ipv4_mask']
        
        try:
            total_ip_count = int(forwardingSysDict['VLAN_PER_VRF_count']) * int(forwardingSysDict['VRF_count'])
            l2_ipv4s = increment_prefix_network(ip.IPv4Interface(str(l2_vlan_ipv4_sec_start) + str(l2_vlan_ipv4_mask)),total_ip_count)
            ip_index=0
            for i in range(0,len(l2_ipv4s)):
                LEAF_1.configure('''int vlan ''' + str(l2_vlan_id) + '''\n
                                 ip address ''' + str(l2_ipv4s[ip_index]) + ''' secondary use-bia
                                 ''')
                l2_vlan_id += 1
                ip_index += 1
                
            
            
        except Exception as error:
            log.debug("Unable to configure - Encountered Exception " + str(error))
            self.errored('Exception occurred while configuring secondary ipv4 address on LEAF-1', goto=['cleanup'])
            
     # =============================================================================================================================#        
    @aetest.test
    def Add_external_int(self, testscript):
        """Shut down the vpc leg on Leaf2 to force all traffic to Leaf1"""
        
        LEAF_1 = testscript.parameters['LEAF-1']
        LEAF_2 = testscript.parameters['LEAF-2']
        
        try:
            testscript.parameters['LEAF-2'].configure('''
                  interface po ''' + str(testscript.parameters['LEAF_1_dict']['VPC_data']['double_vpc_po_1']) + '''
                  port-type external
                  ''')
            
            testscript.parameters['LEAF-1'].configure('''
                  interface po ''' + str(testscript.parameters['LEAF_1_dict']['VPC_data']['double_vpc_po_1']) + '''
                  port-type external
                  ''')    
            
            
        except Exception as error:
            log.debug("Unable to configure - Encountered Exception " + str(error))
            self.errored('Exception occurred while configuring external on LEAF-1 and LEAF-2', goto=['cleanup'])
            
     # =============================================================================================================================#    
    @aetest.test
    def Pre_migration_hsrp(self,testscript):
        LEAF_1 = testscript.parameters['LEAF-1']
        LEAF_2 = testscript.parameters['LEAF-2']
        forwardingSysDict = testscript.parameters['forwardingSysDict']
        l2_vlan_id = testscript.parameters['N7K_LEAF_1_dict']['Vlan_data']['l2_vlan_start']
        l2_vlan_ipv4_start= testscript.parameters['N7K_LEAF_1_dict']['Vlan_data']['l2_vlan_ipv4_start']
        l2_vlan_ipv4_mask= testscript.parameters['N7K_LEAF_1_dict']['Vlan_data']['l2_vlan_ipv4_mask']
        l2_vlan_ipv6_start= testscript.parameters['N7K_LEAF_1_dict']['Vlan_data']['l2_vlan_ipv6_start']
        l2_vlan_ipv6_mask= testscript.parameters['N7K_LEAF_1_dict']['Vlan_data']['l2_vlan_ipv6_mask']
        l2_hsrp_ipv4_vip_start= testscript.parameters['N7K_LEAF_1_dict']['Vlan_data']['hsrp_ipv4_vip_start']
        l2_hsrp_ipv6_vip_start= testscript.parameters['N7K_LEAF_1_dict']['Vlan_data']['hsrp_ipv6_vip_start']
        
        try:
            device_handle=connect_to_vdc(testscript.parameters['xbow1'], 'leaf1')
            if device_handle==False:
                log.info("failed to switchto correct vdc")
                self.failed("failed to switchto correct vdc",goto=['common_cleanup'])
            else:
                total_ip_count = int(forwardingSysDict['VLAN_PER_VRF_count']) * int(forwardingSysDict['VRF_count'])
                l2_ipv4s = increment_prefix_network(ip.IPv4Interface(str(l2_vlan_ipv4_start) + str(l2_vlan_ipv4_mask)),total_ip_count)
                l2_ipv6s = increment_prefix_network(ip.IPv6Interface(str(l2_vlan_ipv6_start) + str(l2_vlan_ipv6_mask)),total_ip_count)
                ip_index=0
                for i in range(0,len(l2_ipv4s)):
                    device_handle.configure('''int vlan ''' + str(l2_vlan_id) + '''\n
                                     hsrp version 2
                                     hsrp ''' + str(l2_vlan_id) + ''' ipv4
                                     mac-address 0000.000a.aaaa
                                     ''')
                    l2_vlan_id += 1
            
            l2_vlan_id = testscript.parameters['N7K_LEAF_1_dict']['Vlan_data']['l2_vlan_start']        
            device_handle=connect_to_vdc(testscript.parameters['xbow2'], 'leaf2')
            if device_handle==False:
                log.info("failed to switchto correct vdc")
                self.failed("failed to switchto correct vdc",goto=['common_cleanup'])
            else:
                total_ip_count = int(forwardingSysDict['VLAN_PER_VRF_count']) * int(forwardingSysDict['VRF_count'])
                l2_ipv4s = increment_prefix_network(ip.IPv4Interface(str(l2_vlan_ipv4_start) + str(l2_vlan_ipv4_mask)),total_ip_count)
                l2_ipv6s = increment_prefix_network(ip.IPv6Interface(str(l2_vlan_ipv6_start) + str(l2_vlan_ipv6_mask)),total_ip_count)
                ip_index=0
                for i in range(0,len(l2_ipv4s)):
                    device_handle.configure('''int vlan ''' + str(l2_vlan_id) + '''\n
                                     hsrp version 2
                                     hsrp ''' + str(l2_vlan_id) + ''' ipv4
                                     mac-address 0000.000a.aaaa
                                     ''')
                    l2_vlan_id += 1
                    


        except Exception as error:
                log.debug("Unable to configure - Encountered Exception " + str(error))
                self.errored('Exception occurred while configuring on N7k leaf1', goto=['common_cleanup'])
                
    @aetest.test        
    def configure_FO(self,testscript):
        
        FO_1_vlanConfiguration = ""
        FO_1=testscript.parameters['FO_1']

        l3_vrf_count_iter = 0
        l2_vlan_id = testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vlan_start']
        l3_vlan_id = testscript.parameters['LEAF_1_dict']['VNI_data']['l3_vlan_start']

        while l3_vrf_count_iter < testscript.parameters['forwardingSysDict']['VRF_count']:
            l2_vlan_count_iter = 0
            FO_1_vlanConfiguration += '''vlan ''' + str(l3_vlan_id) + '''\n
                                            state active\n
                                            no shut\n'''
            while l2_vlan_count_iter < testscript.parameters['forwardingSysDict']['VLAN_PER_VRF_count']:
                # Incrementing L2 VLAN Iteration counters
                FO_1_vlanConfiguration += '''vlan ''' + str(l2_vlan_id) + '''\n
                                                state active\n
                                                no shut\n'''
                l2_vlan_count_iter += 1
                l2_vlan_id += 1
            # Incrementing L3 VRF Iteration counters
            l3_vrf_count_iter += 1
            l3_vlan_id += 1

        try:
            FO_1.configure(
                str(FO_1_vlanConfiguration) + '''
        
        
            
            interface ''' + str(testscript.parameters['intf_FO_1_to_N7k_LEAF_3']) + '''
            no shut
            switchport
            switchport mode trunk
            
            interface ''' + str(testscript.parameters['intf_FO_1_to_LEAF_3']) + '''
            shut
            switchport
            switchport mode trunk
            
            interface ''' + str(testscript.parameters['intf_FO_1_to_LEAF_2']) + '''
            shut
            switchport
            switchport mode trunk
            
            interface ''' + str(testscript.parameters['intf_FO_1_to_IXIA']) + '''
            no shut
            switchport
            switchport mode trunk
            
            ''')
        except Exception as error:
                log.debug("Unable to configure - Encountered Exception " + str(error))
                self.errored('Exception occurred while configuring on FO_1', goto=['common_cleanup'])
   
#     @aetest.test
#     def CONFIGURE_UCAST_L3_IXIA_TRAFFIC(self, testscript):
#         """ IXIA_CONFIGURATION subsection: Configure MCAST Traffic Item """
# 
#         # Do not perform configurations if skip_tgen_config flag is set
#         if not testscript.parameters['script_flags']['skip_tgen_config']:
# 
#             IX_TP1 = testscript.parameters['IX_TP1']
#             IX_TP2 = testscript.parameters['IX_TP2']
#             P1_dict = testscript.parameters['LEAF_2_TGEN_dict']
#             P2_dict = testscript.parameters['LEAF_3_TGEN_dict']
# 
#             UCAST_v4_dict = {   'src_hndl'  : IX_TP1['port_handle'],
#                                 'dst_hndl'  : IX_TP2['port_handle'],
#                                 'ip_dscp'   : P1_dict['ip_dscp'],
#                                 'circuit'   : 'raw',
#                                 'TI_name'   : "UCAST_L3",
#                                 'rate_pps'  : "9000",
#                                 'bi_dir'    : 1,
#                                 'frame_size': '128',
#                                 'src_mac'   : P1_dict['mac'],
#                                 'dst_mac'   : '0000.000a.aaaa',
#                                 'srcmac_step': '00:00:00:00:00:00',
#                                 'dstmac_step': '00:00:00:00:00:00',
#                                 'srcmac_count': '1',
#                                 'dstmac_count': '1',
#                                 'vlan_id'    : P1_dict['vlan_id'],
#                                 'vlanid_step': '0',
#                                 'vlanid_count': '1',
#                                 'vlan_user_priority': P1_dict['vlan_user_priority'],
#                                 'ip_src_addrs' : P1_dict['v4_addr'],
#                                 'ip_dst_addrs' : P1_dict['L3_dst_addr'],
#                                 'ip_src_step' : '0.0.0.0',
#                                 'ip_dst_step' : '0.0.0.0',
# #                                'ip_step'    : P1_dict['v4_addr_step'],
#                           }
# 
# #            UCAST_v6_dict = {   'src_hndl'  : IX_TP1['ipv6_handle'],
# #                                'dst_hndl'  : IX_TP2['ipv6_handle'],
# #                                'circuit'   : 'ipv6',
# #                                'TI_name'   : "UCAST_V6",
# #                                'rate_pps'  : "1000",
# #                                'bi_dir'    : 1
# #                          }
# 
#             UCAST_v4_TI = ixLib.configure_ixia_l3_traffic_item(UCAST_v4_dict)
# #            UCAST_v6_TI = ixLib.configure_ixia_traffic_item(UCAST_v6_dict)
# 
# #            if UCAST_v4_TI == 0 or UCAST_v6_TI == 0:
# #                log.debug("Configuring UCast TI failed")
# #                self.errored("Configuring UCast TI failed", goto=['cleanup'])
#                 
#             if UCAST_v4_TI == 0:
#                 log.debug("Configuring UCast TI failed")
#                 self.errored("Configuring UCast TI failed", goto=['cleanup'])
#             else:
#                 global stream_id
#                 stream_id = UCAST_v4_TI
# 
#         else:
#             self.passed(reason="Skipped TGEN Configurations as per request")
            
#     @aetest.test
#     def CONFIGURE_UCAST_L3_REVERSE_IXIA_TRAFFIC(self, testscript):
#         """ IXIA_CONFIGURATION subsection: Configure MCAST Traffic Item """
# 
#         # Do not perform configurations if skip_tgen_config flag is set
#         if not testscript.parameters['script_flags']['skip_tgen_config']:
# 
#             IX_TP1 = testscript.parameters['IX_TP1']
#             IX_TP2 = testscript.parameters['IX_TP2']
#             P1_dict = testscript.parameters['LEAF_2_TGEN_dict']
#             P2_dict = testscript.parameters['LEAF_3_TGEN_dict']
#             forwardingSysDict = testscript.parameters['forwardingSysDict']
#             vlan_id=int(P2_dict['vlan_id'])+1
#             
#             
# 
#             UCAST_v4_dict = {   'src_hndl'  : IX_TP2['port_handle'],
#                                 'dst_hndl'  : IX_TP1['port_handle'],
#                                 'ip_dscp'   : P1_dict['ip_dscp'],
#                                 'circuit'   : 'raw',
#                                 'TI_name'   : "UCAST_L3",
#                                 'rate_pps'  : "9000",
#                                 'bi_dir'    : 1,
#                                 'frame_size': '128',
#                                 'src_mac'   : P2_dict['mac'],
#                                 'dst_mac'   : '0000.000a.aaaa',
#                                 'srcmac_step': '00:00:00:00:00:00',
#                                 'dstmac_step': '00:00:00:00:00:00',
#                                 'srcmac_count': '1',
#                                 'dstmac_count': '1',
#                                 'vlan_id'    : str(vlan_id),
#                                 'vlanid_step': '0',
#                                 'vlanid_count': '1',
#                                 'vlan_user_priority': P1_dict['vlan_user_priority'],
#                                 'ip_src_addrs' : P2_dict['reverse_v4_address'],
#                                 'ip_dst_addrs' : P2_dict['L3_dst_addr'],
#                                 'ip_src_step' : '0.0.0.0',
#                                 'ip_dst_step' : '0.0.0.0',
# #                                'ip_step'    : P1_dict['v4_addr_step'],
#                           }
# 
# #            UCAST_v6_dict = {   'src_hndl'  : IX_TP1['ipv6_handle'],
# #                                'dst_hndl'  : IX_TP2['ipv6_handle'],
# #                                'circuit'   : 'ipv6',
# #                                'TI_name'   : "UCAST_V6",
# #                                'rate_pps'  : "1000",
# #                                'bi_dir'    : 1
# #                          }
# 
#             UCAST_v4_TI_R = ixLib.configure_ixia_l3_traffic_item(UCAST_v4_dict)
# #            UCAST_v6_TI = ixLib.configure_ixia_traffic_item(UCAST_v6_dict)
# 
# #            if UCAST_v4_TI == 0 or UCAST_v6_TI == 0:
# #                log.debug("Configuring UCast TI failed")
# #                self.errored("Configuring UCast TI failed", goto=['cleanup'])
#                 
#             if UCAST_v4_TI_R == 0:
#                 log.debug("Configuring UCast TI failed")
#                 self.errored("Configuring UCast TI failed", goto=['cleanup'])
#             else:
#                 global stream_id
#                 stream_id = UCAST_v4_TI_R
# 
#         else:
#             self.passed(reason="Skipped TGEN Configurations as per request")
            
    # @aetest.test
    # def CONFIGURE_BCAST_IXIA_TRAFFIC(self, testscript):
    #     """ IXIA_CONFIGURATION subsection: Configure MCAST Traffic Item """
    # 
    #     # Do not perform configurations if skip_tgen_config flag is set
    #     if not testscript.parameters['script_flags']['skip_tgen_config']:
    # 
    #         IX_TP1 = testscript.parameters['IX_TP1']
    #         IX_TP2 = testscript.parameters['IX_TP2']
    #         P1_dict = testscript.parameters['LEAF_2_TGEN_dict']
    #         P2_dict = testscript.parameters['LEAF_3_TGEN_dict']
    #         BCAST_v4_dict = {
    #                             'src_hndl'      : IX_TP1['port_handle'],
    #                             'dst_hndl'      : IX_TP2['port_handle'],
    #                             'TI_name'       : "BCAST_V4",
    #                             'frame_size'    : "70",
    #                             'rate_pps'      : "1000",
    #                             'src_mac'       : P1_dict['mac'],
    #                             'srcmac_step'   : "00:00:00:00:00:01",
    #                             'srcmac_count'  : '1',
    #                             'vlan_id'       : P1_dict['vlan_id'],
    #                             'vlanid_step'   : "1",
    #                             'vlanid_count'  : "1",
    #                             'ip_src_addrs'  : P1_dict['v4_addr'],
    #                             'ip_step'       : "0.0.1.0",
    #                       }
    # 
    #         BCAST_v4_TI = ixLib.configure_ixia_BCAST_traffic_item(BCAST_v4_dict)
    # 
    #         if BCAST_v4_TI == 0:
    #             log.debug("Configuring BCast TI failed")
    #             self.errored("Configuring BCast TI failed", goto=['cleanup'])
    #         else:
    #             global stream_id_2
    #             stream_id_2 = BCAST_v4_TI
    # 
    #     else:
    #         self.passed(reason="Skipped TGEN Configurations as per request")
    # =============================================================================================================================#
    @aetest.test
    def APPLY_TRAFFIC(self,testscript):
        """ IXIA_CONFIGURATION subsection: Verify IXIA Traffic """
    
    #     # Apply IXIA Traffic
    #     if ixLib.apply_traffic() == 1:
    #         log.info("Applying IXIA TI Passed")
    #     else:
    #         self.errored("Applying IXIA TI failed", goto=['cleanup'])
            
        # =============================================================================================================================#
    #--------------------------------------------------------------------------------#
        # Start traffic from ixia
        log.info("--- Populating the statistics --- \n")
        log.info("---- Running Traffic --- \n")
        log.info("Starting Traffic")

        traffic_run_status  = ixLib.start_traffic()

        if traffic_run_status is not 1:
           log.info("Failed: To start traffic")
           return 0
        else:
            log.info("\nTraffic started successfully\n")
        
        # try:
        #         device_handle=connect_to_vdc(testscript.parameters['xbow1'], 'spine4')
        #         if device_handle==False:
        #             log.info("failed to switchto correct vdc")
        #             self.failed("failed to switchto correct vdc",goto=['common_cleanup'])
        #         else:
        #             device_handle.configure('''
        #                             
        #                             
        # 
        #                             interface {0}
        #                               
        #                               shutdown
        #                             
        #                             interface {1}
        #                               
        #                               shutdown
        #                               
        # 
        # 
        #                         '''.format(testscript.parameters['intf_N7k_SPINE_4_to_N7k_LEAF_1'].intf,
        #                                    testscript.parameters['intf_N7k_SPINE_4_to_N7k_LEAF_2'].intf))
        #             time.sleep(30)
        #             device_handle.configure('''
        #                             
        #                             
        # 
        #                             interface {0}
        #                               
        #                               no shutdown
        #                             
        #                             interface {1}
        #                               
        #                               no shutdown
        #                               
        # 
        # 
        #                         '''.format(testscript.parameters['intf_N7k_SPINE_4_to_N7k_LEAF_1'].intf,
        #                                    testscript.parameters['intf_N7k_SPINE_4_to_N7k_LEAF_2'].intf))
        #             time.sleep(30)
        #             # device_handle.configure('''
        #             #                 
        #             #                 
        #             # 
        #             #                 interface {0}
        #             #                   
        #             #                   shutdown
        #             #                 
        #             #                 interface {1}
        #             #                   
        #             #                   shutdown
        #             #                   
        #             # 
        #             # 
        #             #             '''.format(testscript.parameters['intf_N7k_SPINE_4_to_N7k_LEAF_1'].intf,
        #             #                        testscript.parameters['intf_N7k_SPINE_4_to_N7k_LEAF_2'].intf))
        # except Exception as error:
        #     log.debug("Unable to configure - Encountered Exception " + str(error))
        #     self.errored('Exception occurred while configuring on N7k spine4', goto=['common_cleanup'])
        
        
        
    # Stop Traffic from ixia
        
        log.info("--- Stopping Traffic ---- \n")
        log.info("Stopping Traffic")
        traffic_run_status = ixLib.stop_traffic()
        
        if traffic_run_status is not 1:
           log.info("Failed: To Stop traffic")
           return 0
        else:
            log.info("\nTraffic Stopped successfully\n")
            time.sleep(10)
        
        
        
    @aetest.test
    def VERIFY_IXIA_TRAFFIC(self, testscript):
        """ IXIA_CONFIGURATION subsection: Verify IXIA Traffic """

        # Do not perform configurations if skip_tgen_config flag is set
        if not testscript.parameters['script_flags']['skip_tgen_config']:

            time.sleep(20)

            if ixLib.verify_traffic(2) == 0:
                log.debug("Traffic Verification failed")
                self.failed("Traffic Verification failed", goto=['cleanup'])
            else:
                log.info("Traffic Verification Passed")
        else:
            self.passed(reason="Skipped TGEN Configurations as per request")
            
     # =============================================================================================================================#        
    @aetest.test
    def Clear_ARP_Table_on_Vxlan_BLs(self, testscript):
        """Shut down the vpc leg on Leaf2 to force all traffic to Leaf1"""
        
        LEAF_1 = testscript.parameters['LEAF-1']
        LEAF_2 = testscript.parameters['LEAF-2']
        
        try:
            for i in range(1, testscript.parameters['forwardingSysDict']['VRF_count']+1):
                testscript.parameters['LEAF-2'].execute('''
                      clear ip arp vrf ''' + str(testscript.parameters['forwardingSysDict']['VRF_string']) + str(i) + ''' force-delete''')
            
            for i in range(1, testscript.parameters['forwardingSysDict']['VRF_count']+1):
                testscript.parameters['LEAF-1'].execute('''
                      clear ip arp vrf ''' + str(testscript.parameters['forwardingSysDict']['VRF_string']) + str(i) + ''' force-delete''')    
            
            
        except Exception as error:
            log.debug("Unable to configure - Encountered Exception " + str(error))
            self.errored('Exception occurred while clearing arp cache on LEAF-1 and LEAF-2', goto=['cleanup'])
            
    @aetest.test        
    def Host_move_FO(self,testscript):
        
        
        FO_1=testscript.parameters['FO_1']

        
        try:
            FO_1.configure('''
            interface ''' + str(testscript.parameters['intf_FO_1_to_N7k_LEAF_3']) + '''
            shut
            switchport
            switchport mode trunk
            
            interface ''' + str(testscript.parameters['intf_FO_1_to_LEAF_2']) + '''
            no shut
            switchport
            switchport mode trunk
            
            ''')
            time.sleep(45)
        except Exception as error:
                log.debug("Unable to configure - Encountered Exception " + str(error))
                self.errored('Exception occurred while configuring on FO_1', goto=['common_cleanup'])
                
    @aetest.test
    def VERIFY_IXIA_TRAFFIC_AFTER_MOVE(self, testscript):
        """ IXIA_CONFIGURATION subsection: Verify IXIA Traffic """

        # Do not perform configurations if skip_tgen_config flag is set
        if not testscript.parameters['script_flags']['skip_tgen_config']:

            time.sleep(20)

            if ixLib.verify_traffic(15) == 0:
                log.debug("Traffic Verification failed")
                self.failed("Traffic Verification failed", goto=['cleanup'])
            else:
                log.info("Traffic Verification Passed")
        else:
            self.passed(reason="Skipped TGEN Configurations as per request")
            
    @aetest.test        
    def Host_move_FO_BACK(self,testscript):
        
        
        FO_1=testscript.parameters['FO_1']

        
        try:
            FO_1.configure('''
            interface ''' + str(testscript.parameters['intf_FO_1_to_LEAF_2']) + '''
            shut
            switchport
            switchport mode trunk
            
            interface ''' + str(testscript.parameters['intf_FO_1_to_N7k_LEAF_3']) + '''
            no shut
            switchport
            switchport mode trunk
            
            
            
            ''')
            time.sleep(45)
        except Exception as error:
                log.debug("Unable to configure - Encountered Exception " + str(error))
                self.errored('Exception occurred while configuring on FO_1', goto=['common_cleanup'])
                
    @aetest.test
    def VERIFY_IXIA_TRAFFIC_HOST_MOVE_BACK(self, testscript):
        """ IXIA_CONFIGURATION subsection: Verify IXIA Traffic """

        # Do not perform configurations if skip_tgen_config flag is set
        if not testscript.parameters['script_flags']['skip_tgen_config']:

            time.sleep(20)

            if ixLib.verify_traffic(15) == 0:
                log.debug("Traffic Verification failed")
                self.failed("Traffic Verification failed", goto=['cleanup'])
            else:
                log.info("Traffic Verification Passed")
        else:
            self.passed(reason="Skipped TGEN Configurations as per request")
        
    @aetest.cleanup
    def cleanup(self,testscript):
        """Unconfigure qos policies"""
        LEAF_1 = testscript.parameters['LEAF-1']
        LEAF_2 = testscript.parameters['LEAF-2']
        LEAF_3 = testscript.parameters['LEAF-3']
        FO_1=testscript.parameters['FO_1']
        LEAF_1 = testscript.parameters['LEAF-1']
        LEAF_2 = testscript.parameters['LEAF-2']
        forwardingSysDict = testscript.parameters['forwardingSysDict']
        l2_vlan_id = testscript.parameters['N7K_LEAF_1_dict']['Vlan_data']['l2_vlan_start']
        l2_vlan_ipv4_start= testscript.parameters['N7K_LEAF_1_dict']['Vlan_data']['l2_vlan_ipv4_start']
        l2_vlan_ipv4_mask= testscript.parameters['N7K_LEAF_1_dict']['Vlan_data']['l2_vlan_ipv4_mask']
        l2_vlan_ipv6_start= testscript.parameters['N7K_LEAF_1_dict']['Vlan_data']['l2_vlan_ipv6_start']
        l2_vlan_ipv6_mask= testscript.parameters['N7K_LEAF_1_dict']['Vlan_data']['l2_vlan_ipv6_mask']
        l2_hsrp_ipv4_vip_start= testscript.parameters['N7K_LEAF_1_dict']['Vlan_data']['hsrp_ipv4_vip_start']
        l2_hsrp_ipv6_vip_start= testscript.parameters['N7K_LEAF_1_dict']['Vlan_data']['hsrp_ipv6_vip_start']
        
        post_test_process_dict = {
            'dut_list'                       : [LEAF_1, LEAF_2, LEAF_3],
            'cc_check'                  : 1,
            'cores_check'               : 1,
            'logs_check'                : 0,
            'fnl_flag'                  : 0,
            'exclude_log_check_pattern' : 'ERROR_VLANS_SUSPENDED|ERROR_VLANS_REMOVED',
            }
        try:
            FO_1.configure('''
            interface ''' + str(testscript.parameters['intf_FO_1_to_LEAF_2']) + '''
            shut
            switchport
            switchport mode trunk
            
            interface ''' + str(testscript.parameters['intf_FO_1_to_N7k_LEAF_3']) + '''
            no shut
            switchport
            switchport mode trunk
            ''')
            # UCAST_v4_dict = {
            #                 'mode'        : 'remove',
            #                 'stream_id'   : stream_id,
            #           }
            # if (ixLib.delete_traffic_item(UCAST_v4_dict))==0:
            #     log.debug("Traffic Remove failed")
            #     self.failed("Traffic Remove failed")
            # else:
            #     log.info("Traffic Deletion Passed")
            #     
            # Bcast_dict = {
            #                 'mode'        : 'remove',
            #                 'stream_id'   : stream_id_2,
            #           }
            # if (ixLib.delete_traffic_item(BCAST_dict))==0:
            #     log.debug("Traffic Remove failed")
            #     self.failed("Traffic Remove failed")
            # else:
            #     log.info("Traffic Deletion Passed")
            # time.sleep(30)
            ###Remove Pre-migration step from both N7k leafs
            device_handle=connect_to_vdc(testscript.parameters['xbow1'], 'leaf1')
            if device_handle==False:
                log.info("failed to switchto correct vdc")
                self.failed("failed to switchto correct vdc",goto=['common_cleanup'])
            else:
                total_ip_count = int(forwardingSysDict['VLAN_PER_VRF_count']) * int(forwardingSysDict['VRF_count'])
                l2_ipv4s = increment_prefix_network(ip.IPv4Interface(str(l2_vlan_ipv4_start) + str(l2_vlan_ipv4_mask)),total_ip_count)
                l2_ipv6s = increment_prefix_network(ip.IPv6Interface(str(l2_vlan_ipv6_start) + str(l2_vlan_ipv6_mask)),total_ip_count)
                ip_index=0
                for i in range(0,len(l2_ipv4s)):
                    device_handle.configure('''int vlan ''' + str(l2_vlan_id) + '''\n
                                     hsrp version 2
                                     hsrp ''' + str(l2_vlan_id) + ''' ipv4
                                     no mac-address 0000.000a.aaaa
                                     ''')
                    l2_vlan_id += 1
            l2_vlan_id = testscript.parameters['N7K_LEAF_1_dict']['Vlan_data']['l2_vlan_start']        
            device_handle=connect_to_vdc(testscript.parameters['xbow2'], 'leaf2')
            if device_handle==False:
                log.info("failed to switchto correct vdc")
                self.failed("failed to switchto correct vdc",goto=['common_cleanup'])
            else:
                total_ip_count = int(forwardingSysDict['VLAN_PER_VRF_count']) * int(forwardingSysDict['VRF_count'])
                l2_ipv4s = increment_prefix_network(ip.IPv4Interface(str(l2_vlan_ipv4_start) + str(l2_vlan_ipv4_mask)),total_ip_count)
                l2_ipv6s = increment_prefix_network(ip.IPv6Interface(str(l2_vlan_ipv6_start) + str(l2_vlan_ipv6_mask)),total_ip_count)
                ip_index=0
                for i in range(0,len(l2_ipv4s)):
                    device_handle.configure('''int vlan ''' + str(l2_vlan_id) + '''\n
                                     hsrp version 2
                                     hsrp ''' + str(l2_vlan_id) + ''' ipv4
                                     no mac-address 0000.000a.aaaa
                                     ''')
                    l2_vlan_id += 1
            status = infraVerify.postTestVerification(post_test_process_dict)
            if status['status'] == 0:
                self.failed(reason=status['logs'])
            else:
                self.passed(reason=status['logs'])
        except Exception as error:
            log.debug("Unable to unconfigure class map or policy map-Encountered exception " + str(error))
            self.errored('Exception occurred while unconfiguring qos on LEAF1', goto=['next_tc'])       

    
# *****************************************************************************************************************************#
class Remove_ARP_Suppression_ipv4(aetest.Testcase):
    """ Host_move_ipv4 """

    
    # =============================================================================================================================#        
    
    @aetest.test
    def SVI_ON_LEAF2(self, testscript):
        """Shut down the vpc leg on Leaf2 to force all traffic to Leaf1"""
        
        LEAF_1 = testscript.parameters['LEAF-1']
        LEAF_2 = testscript.parameters['LEAF-2']
        forwardingSysDict = testscript.parameters['forwardingSysDict']
        l2_vlan_id = testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vlan_start']
        l2_vlan_ipv4_sec_start= testscript.parameters['LEAF_2_dict']['VNI_data']['l2_vlan_ipv4_sec_start']
        l2_vlan_ipv4_mask= testscript.parameters['LEAF_2_dict']['VNI_data']['l2_vlan_ipv4_mask']
        #+ str(testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vlan_ipv4_mask'])
        
        try:
            total_ip_count = int(forwardingSysDict['VLAN_PER_VRF_count']) * int(forwardingSysDict['VRF_count'])
            l2_ipv4s = increment_prefix_network(ip.IPv4Interface(str(l2_vlan_ipv4_sec_start) + str(l2_vlan_ipv4_mask)),total_ip_count)
            ip_index=0
            for i in range(0,len(l2_ipv4s)):
                LEAF_2.configure('''int vlan ''' + str(l2_vlan_id) + '''\n
                                 ip address ''' + str(l2_ipv4s[ip_index]) + ''' secondary use-bia
                                 ''')
                l2_vlan_id += 1
                ip_index += 1
                
            
            
        except Exception as error:
            log.debug("Unable to configure - Encountered Exception " + str(error))
            self.errored('Exception occurred while configuring secondary ipv4 address on LEAF-2', goto=['cleanup'])
            
    # =============================================================================================================================#        
    
    @aetest.test
    def SVI_ON_LEAF1(self, testscript):
        """Shut down the vpc leg on Leaf2 to force all traffic to Leaf1"""
        
        LEAF_1 = testscript.parameters['LEAF-1']
        LEAF_2 = testscript.parameters['LEAF-2']
        forwardingSysDict = testscript.parameters['forwardingSysDict']
        l2_vlan_id = testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vlan_start']
        l2_vlan_ipv4_sec_start= testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vlan_ipv4_sec_start']
        l2_vlan_ipv4_mask= testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vlan_ipv4_mask']
        
        try:
            total_ip_count = int(forwardingSysDict['VLAN_PER_VRF_count']) * int(forwardingSysDict['VRF_count'])
            l2_ipv4s = increment_prefix_network(ip.IPv4Interface(str(l2_vlan_ipv4_sec_start) + str(l2_vlan_ipv4_mask)),total_ip_count)
            ip_index=0
            for i in range(0,len(l2_ipv4s)):
                LEAF_1.configure('''int vlan ''' + str(l2_vlan_id) + '''\n
                                 ip address ''' + str(l2_ipv4s[ip_index]) + ''' secondary use-bia
                                 ''')
                l2_vlan_id += 1
                ip_index += 1
                
            
            
        except Exception as error:
            log.debug("Unable to configure - Encountered Exception " + str(error))
            self.errored('Exception occurred while configuring secondary ipv4 address on LEAF-1', goto=['cleanup'])
            
     # =============================================================================================================================#        
    @aetest.test
    def Add_external_int(self, testscript):
        """Shut down the vpc leg on Leaf2 to force all traffic to Leaf1"""
        
        LEAF_1 = testscript.parameters['LEAF-1']
        LEAF_2 = testscript.parameters['LEAF-2']
        
        try:
            testscript.parameters['LEAF-2'].configure('''
                  interface po ''' + str(testscript.parameters['LEAF_1_dict']['VPC_data']['double_vpc_po_1']) + '''
                  port-type external
                  ''')
            
            testscript.parameters['LEAF-1'].configure('''
                  interface po ''' + str(testscript.parameters['LEAF_1_dict']['VPC_data']['double_vpc_po_1']) + '''
                  port-type external
                  ''')    
            
            
        except Exception as error:
            log.debug("Unable to configure - Encountered Exception " + str(error))
            self.errored('Exception occurred while configuring external on LEAF-1 and LEAF-2', goto=['cleanup'])
            
     # =============================================================================================================================#        
    @aetest.test
    def Remove_arp_suppression(self, testscript):
        """Remove arp suppression for vnis"""
        
        LEAF_1 = testscript.parameters['LEAF-1']
        LEAF_2 = testscript.parameters['LEAF-2']
        forwardingSysDict = testscript.parameters['forwardingSysDict']
        total_vni_count = int(forwardingSysDict['VLAN_PER_VRF_count']) * int(forwardingSysDict['VRF_count'])
        l2_vni_id = testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vni_start']
        
        try:
            for i in range (0,total_vni_count):
                testscript.parameters['LEAF-2'].configure('''int nve 1
                                                          member vni ''' + str(l2_vni_id) + '''
                                                          no suppress-arp''')
                testscript.parameters['LEAF-1'].configure('''int nve 1
                                                          member vni ''' + str(l2_vni_id) + '''
                                                          no suppress-arp''')
                l2_vni_id+=1
            
            
        except Exception as error:
            log.debug("Unable to configure - Encountered Exception " + str(error))
            self.errored('Exception occurred while removing arp suppressin on LEAF-1 and LEAF-2', goto=['cleanup'])
     # =============================================================================================================================#    
    @aetest.test
    def Pre_migration_hsrp(self,testscript):
        LEAF_1 = testscript.parameters['LEAF-1']
        LEAF_2 = testscript.parameters['LEAF-2']
        forwardingSysDict = testscript.parameters['forwardingSysDict']
        l2_vlan_id = testscript.parameters['N7K_LEAF_1_dict']['Vlan_data']['l2_vlan_start']
        l2_vlan_ipv4_start= testscript.parameters['N7K_LEAF_1_dict']['Vlan_data']['l2_vlan_ipv4_start']
        l2_vlan_ipv4_mask= testscript.parameters['N7K_LEAF_1_dict']['Vlan_data']['l2_vlan_ipv4_mask']
        l2_vlan_ipv6_start= testscript.parameters['N7K_LEAF_1_dict']['Vlan_data']['l2_vlan_ipv6_start']
        l2_vlan_ipv6_mask= testscript.parameters['N7K_LEAF_1_dict']['Vlan_data']['l2_vlan_ipv6_mask']
        l2_hsrp_ipv4_vip_start= testscript.parameters['N7K_LEAF_1_dict']['Vlan_data']['hsrp_ipv4_vip_start']
        l2_hsrp_ipv6_vip_start= testscript.parameters['N7K_LEAF_1_dict']['Vlan_data']['hsrp_ipv6_vip_start']
        
        try:
            device_handle=connect_to_vdc(testscript.parameters['xbow1'], 'leaf1')
            if device_handle==False:
                log.info("failed to switchto correct vdc")
                self.failed("failed to switchto correct vdc",goto=['common_cleanup'])
            else:
                total_ip_count = int(forwardingSysDict['VLAN_PER_VRF_count']) * int(forwardingSysDict['VRF_count'])
                l2_ipv4s = increment_prefix_network(ip.IPv4Interface(str(l2_vlan_ipv4_start) + str(l2_vlan_ipv4_mask)),total_ip_count)
                l2_ipv6s = increment_prefix_network(ip.IPv6Interface(str(l2_vlan_ipv6_start) + str(l2_vlan_ipv6_mask)),total_ip_count)
                ip_index=0
                for i in range(0,len(l2_ipv4s)):
                    device_handle.configure('''int vlan ''' + str(l2_vlan_id) + '''\n
                                     hsrp version 2
                                     hsrp ''' + str(l2_vlan_id) + ''' ipv4
                                     mac-address 0000.000a.aaaa
                                     ''')
                    l2_vlan_id += 1
            l2_vlan_id = testscript.parameters['N7K_LEAF_1_dict']['Vlan_data']['l2_vlan_start']        
            device_handle=connect_to_vdc(testscript.parameters['xbow2'], 'leaf2')
            if device_handle==False:
                log.info("failed to switchto correct vdc")
                self.failed("failed to switchto correct vdc",goto=['common_cleanup'])
            else:
                total_ip_count = int(forwardingSysDict['VLAN_PER_VRF_count']) * int(forwardingSysDict['VRF_count'])
                l2_ipv4s = increment_prefix_network(ip.IPv4Interface(str(l2_vlan_ipv4_start) + str(l2_vlan_ipv4_mask)),total_ip_count)
                l2_ipv6s = increment_prefix_network(ip.IPv6Interface(str(l2_vlan_ipv6_start) + str(l2_vlan_ipv6_mask)),total_ip_count)
                ip_index=0
                for i in range(0,len(l2_ipv4s)):
                    device_handle.configure('''int vlan ''' + str(l2_vlan_id) + '''\n
                                     hsrp version 2
                                     hsrp ''' + str(l2_vlan_id) + ''' ipv4
                                     mac-address 0000.000a.aaaa
                                     ''')
                    l2_vlan_id += 1
                    


        except Exception as error:
                log.debug("Unable to configure - Encountered Exception " + str(error))
                self.errored('Exception occurred while configuring on N7k leaf1', goto=['common_cleanup'])
                
    @aetest.test        
    def configure_FO(self,testscript):
        
        FO_1_vlanConfiguration = ""
        FO_1=testscript.parameters['FO_1']

        l3_vrf_count_iter = 0
        l2_vlan_id = testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vlan_start']
        l3_vlan_id = testscript.parameters['LEAF_1_dict']['VNI_data']['l3_vlan_start']

        while l3_vrf_count_iter < testscript.parameters['forwardingSysDict']['VRF_count']:
            l2_vlan_count_iter = 0
            FO_1_vlanConfiguration += '''vlan ''' + str(l3_vlan_id) + '''\n
                                            state active\n
                                            no shut\n'''
            while l2_vlan_count_iter < testscript.parameters['forwardingSysDict']['VLAN_PER_VRF_count']:
                # Incrementing L2 VLAN Iteration counters
                FO_1_vlanConfiguration += '''vlan ''' + str(l2_vlan_id) + '''\n
                                                state active\n
                                                no shut\n'''
                l2_vlan_count_iter += 1
                l2_vlan_id += 1
            # Incrementing L3 VRF Iteration counters
            l3_vrf_count_iter += 1
            l3_vlan_id += 1

        try:
            FO_1.configure(
                str(FO_1_vlanConfiguration) + '''
        
        
            
            interface ''' + str(testscript.parameters['intf_FO_1_to_N7k_LEAF_3']) + '''
            no shut
            switchport
            switchport mode trunk
            
            interface ''' + str(testscript.parameters['intf_FO_1_to_LEAF_3']) + '''
            shut
            switchport
            switchport mode trunk
            
            interface ''' + str(testscript.parameters['intf_FO_1_to_IXIA']) + '''
            no shut
            switchport
            switchport mode trunk
            
            ''')
        except Exception as error:
                log.debug("Unable to configure - Encountered Exception " + str(error))
                self.errored('Exception occurred while configuring on FO_1', goto=['common_cleanup'])
   
#     @aetest.test
#     def CONFIGURE_UCAST_L3_IXIA_TRAFFIC(self, testscript):
#         """ IXIA_CONFIGURATION subsection: Configure MCAST Traffic Item """
# 
#         # Do not perform configurations if skip_tgen_config flag is set
#         if not testscript.parameters['script_flags']['skip_tgen_config']:
# 
#             IX_TP1 = testscript.parameters['IX_TP1']
#             IX_TP2 = testscript.parameters['IX_TP2']
#             P1_dict = testscript.parameters['LEAF_2_TGEN_dict']
#             P2_dict = testscript.parameters['LEAF_3_TGEN_dict']
# 
#             UCAST_v4_dict = {   'src_hndl'  : IX_TP1['port_handle'],
#                                 'dst_hndl'  : IX_TP2['port_handle'],
#                                 'ip_dscp'   : P1_dict['ip_dscp'],
#                                 'circuit'   : 'raw',
#                                 'TI_name'   : "UCAST_L3",
#                                 'rate_pps'  : "9000",
#                                 'bi_dir'    : 1,
#                                 'frame_size': '128',
#                                 'src_mac'   : P1_dict['mac'],
#                                 'dst_mac'   : '0000.000a.aaaa',
#                                 'srcmac_step': '00:00:00:00:00:00',
#                                 'dstmac_step': '00:00:00:00:00:00',
#                                 'srcmac_count': '1',
#                                 'dstmac_count': '1',
#                                 'vlan_id'    : P1_dict['vlan_id'],
#                                 'vlanid_step': '0',
#                                 'vlanid_count': '1',
#                                 'vlan_user_priority': P1_dict['vlan_user_priority'],
#                                 'ip_src_addrs' : P1_dict['v4_addr'],
#                                 'ip_dst_addrs' : P1_dict['L3_dst_addr'],
#                                 'ip_src_step' : '0.0.0.0',
#                                 'ip_dst_step' : '0.0.0.0',
# #                                'ip_step'    : P1_dict['v4_addr_step'],
#                           }
# 
# #            UCAST_v6_dict = {   'src_hndl'  : IX_TP1['ipv6_handle'],
# #                                'dst_hndl'  : IX_TP2['ipv6_handle'],
# #                                'circuit'   : 'ipv6',
# #                                'TI_name'   : "UCAST_V6",
# #                                'rate_pps'  : "1000",
# #                                'bi_dir'    : 1
# #                          }
# 
#             UCAST_v4_TI = ixLib.configure_ixia_l3_traffic_item(UCAST_v4_dict)
# #            UCAST_v6_TI = ixLib.configure_ixia_traffic_item(UCAST_v6_dict)
# 
# #            if UCAST_v4_TI == 0 or UCAST_v6_TI == 0:
# #                log.debug("Configuring UCast TI failed")
# #                self.errored("Configuring UCast TI failed", goto=['cleanup'])
#                 
#             if UCAST_v4_TI == 0:
#                 log.debug("Configuring UCast TI failed")
#                 self.errored("Configuring UCast TI failed", goto=['cleanup'])
#             else:
#                 global stream_id
#                 stream_id = UCAST_v4_TI
# 
#         else:
#             self.passed(reason="Skipped TGEN Configurations as per request")
            
    # =============================================================================================================================#
    @aetest.test
    def APPLY_TRAFFIC(self):
        """ IXIA_CONFIGURATION subsection: Verify IXIA Traffic """

        # # Apply IXIA Traffic
        # if ixLib.apply_traffic() == 1:
        #     log.info("Applying IXIA TI Passed")
        # else:
        #     self.errored("Applying IXIA TI failed", goto=['cleanup'])
            
        # =============================================================================================================================#
    #--------------------------------------------------------------------------------#
        # Start traffic from ixia
        log.info("--- Populating the statistics --- \n")
        log.info("---- Running Traffic --- \n")
        log.info("Starting Traffic")

        traffic_run_status  = ixLib.start_traffic()

        if traffic_run_status is not 1:
           log.info("Failed: To start traffic")
           return 0
        else:
            log.info("\nTraffic started successfully\n")

        time.sleep(60)
    
    # Stop Traffic from ixia
        log.info("--- Stopping Traffic ---- \n")
        log.info("Stopping Traffic")
        traffic_run_status = ixLib.stop_traffic()
        
        if traffic_run_status is not 1:
           log.info("Failed: To Stop traffic")
           return 0
        else:
            log.info("\nTraffic Stopped successfully\n")
            time.sleep(10)    
    
    @aetest.test
    def VERIFY_IXIA_TRAFFIC(self, testscript):
        """ IXIA_CONFIGURATION subsection: Verify IXIA Traffic """

        # Do not perform configurations if skip_tgen_config flag is set
        if not testscript.parameters['script_flags']['skip_tgen_config']:

            time.sleep(20)

            if ixLib.verify_traffic(2) == 0:
                log.debug("Traffic Verification failed")
                self.failed("Traffic Verification failed", goto=['cleanup'])
            else:
                log.info("Traffic Verification Passed")
        else:
            self.passed(reason="Skipped TGEN Configurations as per request")
            
     # =============================================================================================================================#        
    @aetest.test
    def Clear_ARP_Table_on_Vxlan_BLs(self, testscript):
        """Shut down the vpc leg on Leaf2 to force all traffic to Leaf1"""
        
        LEAF_1 = testscript.parameters['LEAF-1']
        LEAF_2 = testscript.parameters['LEAF-2']
        
        try:
            for i in range(1, testscript.parameters['forwardingSysDict']['VRF_count']+1):
                testscript.parameters['LEAF-2'].execute('''
                      clear ip arp vrf ''' + str(testscript.parameters['forwardingSysDict']['VRF_string']) + str(i) + ''' force-delete''')
            
            for i in range(1, testscript.parameters['forwardingSysDict']['VRF_count']+1):
                testscript.parameters['LEAF-1'].execute('''
                      clear ip arp vrf ''' + str(testscript.parameters['forwardingSysDict']['VRF_string']) + str(i) + ''' force-delete''')    
            
            
        except Exception as error:
            log.debug("Unable to configure - Encountered Exception " + str(error))
            self.errored('Exception occurred while clearing arp cache on LEAF-1 and LEAF-2', goto=['cleanup'])
            
    @aetest.test        
    def Host_move_FO(self,testscript):
        
        
        FO_1=testscript.parameters['FO_1']

        
        try:
            FO_1.configure('''
            interface ''' + str(testscript.parameters['intf_FO_1_to_N7k_LEAF_3']) + '''
            shut
            switchport
            switchport mode trunk
            
            interface ''' + str(testscript.parameters['intf_FO_1_to_LEAF_3']) + '''
            no shut
            switchport
            switchport mode trunk
            
            ''')
            time.sleep(45)
        except Exception as error:
                log.debug("Unable to configure - Encountered Exception " + str(error))
                self.errored('Exception occurred while configuring on FO_1', goto=['common_cleanup'])
                
    @aetest.test
    def VERIFY_IXIA_TRAFFIC_AFTER_MOVE(self, testscript):
        """ IXIA_CONFIGURATION subsection: Verify IXIA Traffic """

        # Do not perform configurations if skip_tgen_config flag is set
        if not testscript.parameters['script_flags']['skip_tgen_config']:

            time.sleep(20)

            if ixLib.verify_traffic(15) == 0:
                log.debug("Traffic Verification failed")
                self.failed("Traffic Verification failed", goto=['cleanup'])
            else:
                log.info("Traffic Verification Passed")
        else:
            self.passed(reason="Skipped TGEN Configurations as per request")
            
    @aetest.test        
    def Host_move_FO_BACK(self,testscript):
        
        
        FO_1=testscript.parameters['FO_1']

        
        try:
            FO_1.configure('''
            interface ''' + str(testscript.parameters['intf_FO_1_to_LEAF_3']) + '''
            shut
            switchport
            switchport mode trunk
            
            interface ''' + str(testscript.parameters['intf_FO_1_to_N7k_LEAF_3']) + '''
            no shut
            switchport
            switchport mode trunk
            
            
            
            ''')
            time.sleep(45)
        except Exception as error:
                log.debug("Unable to configure - Encountered Exception " + str(error))
                self.errored('Exception occurred while configuring on FO_1', goto=['common_cleanup'])
                
    @aetest.test
    def VERIFY_IXIA_TRAFFIC_HOST_MOVE_BACK(self, testscript):
        """ IXIA_CONFIGURATION subsection: Verify IXIA Traffic """

        # Do not perform configurations if skip_tgen_config flag is set
        if not testscript.parameters['script_flags']['skip_tgen_config']:

            time.sleep(20)

            if ixLib.verify_traffic(15) == 0:
                log.debug("Traffic Verification failed")
                self.failed("Traffic Verification failed", goto=['cleanup'])
            else:
                log.info("Traffic Verification Passed")
        else:
            self.passed(reason="Skipped TGEN Configurations as per request")
        
    @aetest.cleanup
    def cleanup(self,testscript):
        """Unconfigure qos policies"""
        LEAF_1 = testscript.parameters['LEAF-1']
        LEAF_2 = testscript.parameters['LEAF-2']
        LEAF_3 = testscript.parameters['LEAF-3']
        FO_1=testscript.parameters['FO_1']
        LEAF_1 = testscript.parameters['LEAF-1']
        LEAF_2 = testscript.parameters['LEAF-2']
        forwardingSysDict = testscript.parameters['forwardingSysDict']
        l2_vlan_id = testscript.parameters['N7K_LEAF_1_dict']['Vlan_data']['l2_vlan_start']
        l2_vlan_ipv4_start= testscript.parameters['N7K_LEAF_1_dict']['Vlan_data']['l2_vlan_ipv4_start']
        l2_vlan_ipv4_mask= testscript.parameters['N7K_LEAF_1_dict']['Vlan_data']['l2_vlan_ipv4_mask']
        l2_vlan_ipv6_start= testscript.parameters['N7K_LEAF_1_dict']['Vlan_data']['l2_vlan_ipv6_start']
        l2_vlan_ipv6_mask= testscript.parameters['N7K_LEAF_1_dict']['Vlan_data']['l2_vlan_ipv6_mask']
        l2_hsrp_ipv4_vip_start= testscript.parameters['N7K_LEAF_1_dict']['Vlan_data']['hsrp_ipv4_vip_start']
        l2_hsrp_ipv6_vip_start= testscript.parameters['N7K_LEAF_1_dict']['Vlan_data']['hsrp_ipv6_vip_start']
        total_vni_count = int(forwardingSysDict['VLAN_PER_VRF_count']) * int(forwardingSysDict['VRF_count'])
        l2_vni_id = testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vni_start']
        
        post_test_process_dict = {
            'dut_list'                       : [LEAF_1, LEAF_2, LEAF_3],
            'cc_check'                  : 0,
            'cores_check'               : 1,
            'logs_check'                : 0,
            'fnl_flag'                  : 0,
            'exclude_log_check_pattern' : 'ERROR_VLANS_SUSPENDED|ERROR_VLANS_REMOVED',
            }
        try:
            ##Add arp suppression config back
            for i in range (0,total_vni_count):
                testscript.parameters['LEAF-2'].configure('''int nve 1
                                                          member vni ''' + str(l2_vni_id) + '''
                                                          suppress-arp''')
                testscript.parameters['LEAF-1'].configure('''int nve 1
                                                          member vni ''' + str(l2_vni_id) + '''
                                                          suppress-arp''')
                l2_vni_id+=1
            
            
        
            #Move hosts back to FP
            FO_1.configure('''
            interface ''' + str(testscript.parameters['intf_FO_1_to_LEAF_3']) + '''
            shut
            switchport
            switchport mode trunk
            
            interface ''' + str(testscript.parameters['intf_FO_1_to_N7k_LEAF_3']) + '''
            no shut
            switchport
            switchport mode trunk
            ''')
            time.sleep(30)
            ###Remove Pre-migration step from both N7k leafs
            device_handle=connect_to_vdc(testscript.parameters['xbow1'], 'leaf1')
            if device_handle==False:
                log.info("failed to switchto correct vdc")
                self.failed("failed to switchto correct vdc",goto=['common_cleanup'])
            else:
                total_ip_count = int(forwardingSysDict['VLAN_PER_VRF_count']) * int(forwardingSysDict['VRF_count'])
                l2_ipv4s = increment_prefix_network(ip.IPv4Interface(str(l2_vlan_ipv4_start) + str(l2_vlan_ipv4_mask)),total_ip_count)
                l2_ipv6s = increment_prefix_network(ip.IPv6Interface(str(l2_vlan_ipv6_start) + str(l2_vlan_ipv6_mask)),total_ip_count)
                ip_index=0
                for i in range(0,len(l2_ipv4s)):
                    device_handle.configure('''int vlan ''' + str(l2_vlan_id) + '''\n
                                     hsrp version 2
                                     hsrp ''' + str(l2_vlan_id) + ''' ipv4
                                     no mac-address 0000.000a.aaaa
                                     ''')
                    l2_vlan_id += 1
            l2_vlan_id = testscript.parameters['N7K_LEAF_1_dict']['Vlan_data']['l2_vlan_start']        
            device_handle=connect_to_vdc(testscript.parameters['xbow2'], 'leaf2')
            if device_handle==False:
                log.info("failed to switchto correct vdc")
                self.failed("failed to switchto correct vdc",goto=['common_cleanup'])
            else:
                total_ip_count = int(forwardingSysDict['VLAN_PER_VRF_count']) * int(forwardingSysDict['VRF_count'])
                l2_ipv4s = increment_prefix_network(ip.IPv4Interface(str(l2_vlan_ipv4_start) + str(l2_vlan_ipv4_mask)),total_ip_count)
                l2_ipv6s = increment_prefix_network(ip.IPv6Interface(str(l2_vlan_ipv6_start) + str(l2_vlan_ipv6_mask)),total_ip_count)
                ip_index=0
                for i in range(0,len(l2_ipv4s)):
                    device_handle.configure('''int vlan ''' + str(l2_vlan_id) + '''\n
                                     hsrp version 2
                                     hsrp ''' + str(l2_vlan_id) + ''' ipv4
                                     no mac-address 0000.000a.aaaa
                                     ''')
                    l2_vlan_id += 1
            status = infraVerify.postTestVerification(post_test_process_dict)
            if status['status'] == 0:
                self.failed(reason=status['logs'])
            else:
                self.passed(reason=status['logs'])
        except Exception as error:
            log.debug("Unable to unconfigure class map or policy map-Encountered exception " + str(error))
            self.errored('Exception occurred while unconfiguring qos on LEAF1', goto=['next_tc'])       
    # =============================================================================================================================#
# *****************************************************************************************************************************#
class Host_move_nonD_Mac(aetest.Testcase):
    """ Host_move_ipv4 """

    
    # =============================================================================================================================#        
    
    @aetest.test
    def SVI_ON_LEAF2(self, testscript):
        """Shut down the vpc leg on Leaf2 to force all traffic to Leaf1"""
        
        LEAF_1 = testscript.parameters['LEAF-1']
        LEAF_2 = testscript.parameters['LEAF-2']
        forwardingSysDict = testscript.parameters['forwardingSysDict']
        l2_vlan_id = testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vlan_start']
        l2_vlan_ipv4_sec_start= testscript.parameters['LEAF_2_dict']['VNI_data']['l2_vlan_ipv4_sec_start']
        l2_vlan_ipv4_mask= testscript.parameters['LEAF_2_dict']['VNI_data']['l2_vlan_ipv4_mask']
        bia_mac = testscript.parameters['LEAF_2_dict']['VNI_data']['bia_mac_start']
        #+ str(testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vlan_ipv4_mask'])
        
        try:
            total_ip_count = int(forwardingSysDict['VLAN_PER_VRF_count']) * int(forwardingSysDict['VRF_count'])
            l2_ipv4s = increment_prefix_network(ip.IPv4Interface(str(l2_vlan_ipv4_sec_start) + str(l2_vlan_ipv4_mask)),total_ip_count)
            ip_index=0
            for i in range(0,len(l2_ipv4s)):
                LEAF_2.configure('''int vlan ''' + str(l2_vlan_id) + '''\n
                                 ip address ''' + str(l2_ipv4s[ip_index]) + ''' secondary use-bia
                                 mac-address ''' + str(bia_mac) + '''
                                 ''')
                l2_vlan_id += 1
                ip_index += 1
                
            
            
        except Exception as error:
            log.debug("Unable to configure - Encountered Exception " + str(error))
            self.errored('Exception occurred while configuring secondary ipv4 address on LEAF-2', goto=['cleanup'])
            
    # =============================================================================================================================#        
    
    @aetest.test
    def SVI_ON_LEAF1(self, testscript):
        """Shut down the vpc leg on Leaf2 to force all traffic to Leaf1"""
        
        LEAF_1 = testscript.parameters['LEAF-1']
        LEAF_2 = testscript.parameters['LEAF-2']
        forwardingSysDict = testscript.parameters['forwardingSysDict']
        l2_vlan_id = testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vlan_start']
        l2_vlan_ipv4_sec_start= testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vlan_ipv4_sec_start']
        l2_vlan_ipv4_mask= testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vlan_ipv4_mask']
        bia_mac = testscript.parameters['LEAF_1_dict']['VNI_data']['bia_mac_start']
        
        try:
            total_ip_count = int(forwardingSysDict['VLAN_PER_VRF_count']) * int(forwardingSysDict['VRF_count'])
            l2_ipv4s = increment_prefix_network(ip.IPv4Interface(str(l2_vlan_ipv4_sec_start) + str(l2_vlan_ipv4_mask)),total_ip_count)
            ip_index=0
            for i in range(0,len(l2_ipv4s)):
                LEAF_1.configure('''int vlan ''' + str(l2_vlan_id) + '''\n
                                 ip address ''' + str(l2_ipv4s[ip_index]) + ''' secondary use-bia
                                 mac-address ''' + str(bia_mac) + '''
                                 ''')
                l2_vlan_id += 1
                ip_index += 1
                
            
            
        except Exception as error:
            log.debug("Unable to configure - Encountered Exception " + str(error))
            self.errored('Exception occurred while configuring secondary ipv4 address on LEAF-1', goto=['cleanup'])
            
     # =============================================================================================================================#        
    @aetest.test
    def Add_external_int(self, testscript):
        """Shut down the vpc leg on Leaf2 to force all traffic to Leaf1"""
        
        LEAF_1 = testscript.parameters['LEAF-1']
        LEAF_2 = testscript.parameters['LEAF-2']
        
        try:
            testscript.parameters['LEAF-2'].configure('''
                  interface po ''' + str(testscript.parameters['LEAF_1_dict']['VPC_data']['double_vpc_po_1']) + '''
                  port-type external
                  ''')
            
            testscript.parameters['LEAF-1'].configure('''
                  interface po ''' + str(testscript.parameters['LEAF_1_dict']['VPC_data']['double_vpc_po_1']) + '''
                  port-type external
                  ''')    
            
            
        except Exception as error:
            log.debug("Unable to configure - Encountered Exception " + str(error))
            self.errored('Exception occurred while configuring external on LEAF-1 and LEAF-2', goto=['cleanup'])
            
     # =============================================================================================================================#    
    @aetest.test
    def Pre_migration_hsrp(self,testscript):
        LEAF_1 = testscript.parameters['LEAF-1']
        LEAF_2 = testscript.parameters['LEAF-2']
        forwardingSysDict = testscript.parameters['forwardingSysDict']
        l2_vlan_id = testscript.parameters['N7K_LEAF_1_dict']['Vlan_data']['l2_vlan_start']
        l2_vlan_ipv4_start= testscript.parameters['N7K_LEAF_1_dict']['Vlan_data']['l2_vlan_ipv4_start']
        l2_vlan_ipv4_mask= testscript.parameters['N7K_LEAF_1_dict']['Vlan_data']['l2_vlan_ipv4_mask']
        l2_vlan_ipv6_start= testscript.parameters['N7K_LEAF_1_dict']['Vlan_data']['l2_vlan_ipv6_start']
        l2_vlan_ipv6_mask= testscript.parameters['N7K_LEAF_1_dict']['Vlan_data']['l2_vlan_ipv6_mask']
        l2_hsrp_ipv4_vip_start= testscript.parameters['N7K_LEAF_1_dict']['Vlan_data']['hsrp_ipv4_vip_start']
        l2_hsrp_ipv6_vip_start= testscript.parameters['N7K_LEAF_1_dict']['Vlan_data']['hsrp_ipv6_vip_start']
        
        try:
            device_handle=connect_to_vdc(testscript.parameters['xbow1'], 'leaf1')
            if device_handle==False:
                log.info("failed to switchto correct vdc")
                self.failed("failed to switchto correct vdc",goto=['common_cleanup'])
            else:
                total_ip_count = int(forwardingSysDict['VLAN_PER_VRF_count']) * int(forwardingSysDict['VRF_count'])
                l2_ipv4s = increment_prefix_network(ip.IPv4Interface(str(l2_vlan_ipv4_start) + str(l2_vlan_ipv4_mask)),total_ip_count)
                l2_ipv6s = increment_prefix_network(ip.IPv6Interface(str(l2_vlan_ipv6_start) + str(l2_vlan_ipv6_mask)),total_ip_count)
                ip_index=0
                for i in range(0,len(l2_ipv4s)):
                    device_handle.configure('''int vlan ''' + str(l2_vlan_id) + '''\n
                                     hsrp version 2
                                     hsrp ''' + str(l2_vlan_id) + ''' ipv4
                                     mac-address 0000.000a.aaaa
                                     ''')
                    l2_vlan_id += 1
            l2_vlan_id = testscript.parameters['N7K_LEAF_1_dict']['Vlan_data']['l2_vlan_start']        
            device_handle=connect_to_vdc(testscript.parameters['xbow2'], 'leaf2')
            if device_handle==False:
                log.info("failed to switchto correct vdc")
                self.failed("failed to switchto correct vdc",goto=['common_cleanup'])
            else:
                total_ip_count = int(forwardingSysDict['VLAN_PER_VRF_count']) * int(forwardingSysDict['VRF_count'])
                l2_ipv4s = increment_prefix_network(ip.IPv4Interface(str(l2_vlan_ipv4_start) + str(l2_vlan_ipv4_mask)),total_ip_count)
                l2_ipv6s = increment_prefix_network(ip.IPv6Interface(str(l2_vlan_ipv6_start) + str(l2_vlan_ipv6_mask)),total_ip_count)
                ip_index=0
                for i in range(0,len(l2_ipv4s)):
                    device_handle.configure('''int vlan ''' + str(l2_vlan_id) + '''\n
                                     hsrp version 2
                                     hsrp ''' + str(l2_vlan_id) + ''' ipv4
                                     mac-address 0000.000a.aaaa
                                     ''')
                    l2_vlan_id += 1
                    


        except Exception as error:
                log.debug("Unable to configure - Encountered Exception " + str(error))
                self.errored('Exception occurred while configuring on N7k leaf1', goto=['common_cleanup'])
                
    @aetest.test        
    def configure_FO(self,testscript):
        
        FO_1_vlanConfiguration = ""
        FO_1=testscript.parameters['FO_1']

        l3_vrf_count_iter = 0
        l2_vlan_id = testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vlan_start']
        l3_vlan_id = testscript.parameters['LEAF_1_dict']['VNI_data']['l3_vlan_start']

        while l3_vrf_count_iter < testscript.parameters['forwardingSysDict']['VRF_count']:
            l2_vlan_count_iter = 0
            FO_1_vlanConfiguration += '''vlan ''' + str(l3_vlan_id) + '''\n
                                            state active\n
                                            no shut\n'''
            while l2_vlan_count_iter < testscript.parameters['forwardingSysDict']['VLAN_PER_VRF_count']:
                # Incrementing L2 VLAN Iteration counters
                FO_1_vlanConfiguration += '''vlan ''' + str(l2_vlan_id) + '''\n
                                                state active\n
                                                no shut\n'''
                l2_vlan_count_iter += 1
                l2_vlan_id += 1
            # Incrementing L3 VRF Iteration counters
            l3_vrf_count_iter += 1
            l3_vlan_id += 1

        try:
            FO_1.configure(
                str(FO_1_vlanConfiguration) + '''
        
        
            
            interface ''' + str(testscript.parameters['intf_FO_1_to_N7k_LEAF_3']) + '''
            no shut
            switchport
            switchport mode trunk
            
            interface ''' + str(testscript.parameters['intf_FO_1_to_LEAF_3']) + '''
            shut
            switchport
            switchport mode trunk
            
            interface ''' + str(testscript.parameters['intf_FO_1_to_IXIA']) + '''
            no shut
            switchport
            switchport mode trunk
            
            ''')
        except Exception as error:
                log.debug("Unable to configure - Encountered Exception " + str(error))
                self.errored('Exception occurred while configuring on FO_1', goto=['common_cleanup'])
   
#     @aetest.test
#     def CONFIGURE_UCAST_L3_IXIA_TRAFFIC(self, testscript):
#         """ IXIA_CONFIGURATION subsection: Configure MCAST Traffic Item """
# 
#         # Do not perform configurations if skip_tgen_config flag is set
#         if not testscript.parameters['script_flags']['skip_tgen_config']:
# 
#             IX_TP1 = testscript.parameters['IX_TP1']
#             IX_TP2 = testscript.parameters['IX_TP2']
#             P1_dict = testscript.parameters['LEAF_2_TGEN_dict']
#             P2_dict = testscript.parameters['LEAF_3_TGEN_dict']
# 
#             UCAST_v4_dict = {   'src_hndl'  : IX_TP1['port_handle'],
#                                 'dst_hndl'  : IX_TP2['port_handle'],
#                                 'ip_dscp'   : P1_dict['ip_dscp'],
#                                 'circuit'   : 'raw',
#                                 'TI_name'   : "UCAST_L3",
#                                 'rate_pps'  : "9000",
#                                 'bi_dir'    : 1,
#                                 'frame_size': '128',
#                                 'src_mac'   : P1_dict['mac'],
#                                 'dst_mac'   : '0000.000a.aaaa',
#                                 'srcmac_step': '00:00:00:00:00:00',
#                                 'dstmac_step': '00:00:00:00:00:00',
#                                 'srcmac_count': '1',
#                                 'dstmac_count': '1',
#                                 'vlan_id'    : P1_dict['vlan_id'],
#                                 'vlanid_step': '0',
#                                 'vlanid_count': '1',
#                                 'vlan_user_priority': P1_dict['vlan_user_priority'],
#                                 'ip_src_addrs' : P1_dict['v4_addr'],
#                                 'ip_dst_addrs' : P1_dict['L3_dst_addr'],
#                                 'ip_src_step' : '0.0.0.0',
#                                 'ip_dst_step' : '0.0.0.0',
# #                                'ip_step'    : P1_dict['v4_addr_step'],
#                           }
# 
# #            UCAST_v6_dict = {   'src_hndl'  : IX_TP1['ipv6_handle'],
# #                                'dst_hndl'  : IX_TP2['ipv6_handle'],
# #                                'circuit'   : 'ipv6',
# #                                'TI_name'   : "UCAST_V6",
# #                                'rate_pps'  : "1000",
# #                                'bi_dir'    : 1
# #                          }
# 
#             UCAST_v4_TI = ixLib.configure_ixia_l3_traffic_item(UCAST_v4_dict)
# #            UCAST_v6_TI = ixLib.configure_ixia_traffic_item(UCAST_v6_dict)
# 
# #            if UCAST_v4_TI == 0 or UCAST_v6_TI == 0:
# #                log.debug("Configuring UCast TI failed")
# #                self.errored("Configuring UCast TI failed", goto=['cleanup'])
#                 
#             if UCAST_v4_TI == 0:
#                 log.debug("Configuring UCast TI failed")
#                 self.errored("Configuring UCast TI failed", goto=['cleanup'])
#             else:
#                 global stream_id
#                 stream_id = UCAST_v4_TI
# 
#         else:
#             self.passed(reason="Skipped TGEN Configurations as per request")
            
    # =============================================================================================================================#
    @aetest.test
    def APPLY_TRAFFIC(self):
        """ IXIA_CONFIGURATION subsection: Verify IXIA Traffic """

        # # Apply IXIA Traffic
        # if ixLib.apply_traffic() == 1:
        #     log.info("Applying IXIA TI Passed")
        # else:
        #     self.errored("Applying IXIA TI failed", goto=['cleanup'])
            
        # =============================================================================================================================#
    #--------------------------------------------------------------------------------#
        # Start traffic from ixia
        log.info("--- Populating the statistics --- \n")
        log.info("---- Running Traffic --- \n")
        log.info("Starting Traffic")

        traffic_run_status  = ixLib.start_traffic()

        if traffic_run_status is not 1:
           log.info("Failed: To start traffic")
           return 0
        else:
            log.info("\nTraffic started successfully\n")

        time.sleep(30)
    
    # Stop Traffic from ixia
        log.info("--- Stopping Traffic ---- \n")
        log.info("Stopping Traffic")
        traffic_run_status = ixLib.stop_traffic()
        
        if traffic_run_status is not 1:
           log.info("Failed: To Stop traffic")
           return 0
        else:
            log.info("\nTraffic Stopped successfully\n")
            time.sleep(10)    
    
    @aetest.test
    def VERIFY_IXIA_TRAFFIC(self, testscript):
        """ IXIA_CONFIGURATION subsection: Verify IXIA Traffic """

        # Do not perform configurations if skip_tgen_config flag is set
        if not testscript.parameters['script_flags']['skip_tgen_config']:

            time.sleep(20)

            if ixLib.verify_traffic(2) == 0:
                log.debug("Traffic Verification failed")
                self.failed("Traffic Verification failed", goto=['cleanup'])
            else:
                log.info("Traffic Verification Passed")
        else:
            self.passed(reason="Skipped TGEN Configurations as per request")
            
     # =============================================================================================================================#        
    @aetest.test
    def Clear_ARP_Table_on_Vxlan_BLs(self, testscript):
        """Shut down the vpc leg on Leaf2 to force all traffic to Leaf1"""
        
        LEAF_1 = testscript.parameters['LEAF-1']
        LEAF_2 = testscript.parameters['LEAF-2']
        
        try:
            for i in range(1, testscript.parameters['forwardingSysDict']['VRF_count']+1):
                testscript.parameters['LEAF-2'].execute('''
                      clear ip arp vrf ''' + str(testscript.parameters['forwardingSysDict']['VRF_string']) + str(i) + ''' force-delete''')
            
            for i in range(1, testscript.parameters['forwardingSysDict']['VRF_count']+1):
                testscript.parameters['LEAF-1'].execute('''
                      clear ip arp vrf ''' + str(testscript.parameters['forwardingSysDict']['VRF_string']) + str(i) + ''' force-delete''')    
            
            
        except Exception as error:
            log.debug("Unable to configure - Encountered Exception " + str(error))
            self.errored('Exception occurred while clearing arp cache on LEAF-1 and LEAF-2', goto=['cleanup'])
            
    @aetest.test        
    def Host_move_FO(self,testscript):
        
        
        FO_1=testscript.parameters['FO_1']

        
        try:
            FO_1.configure('''
            interface ''' + str(testscript.parameters['intf_FO_1_to_N7k_LEAF_3']) + '''
            shut
            switchport
            switchport mode trunk
            
            interface ''' + str(testscript.parameters['intf_FO_1_to_LEAF_3']) + '''
            no shut
            switchport
            switchport mode trunk
            
            ''')
            time.sleep(45)
        except Exception as error:
                log.debug("Unable to configure - Encountered Exception " + str(error))
                self.errored('Exception occurred while configuring on FO_1', goto=['common_cleanup'])
                
    @aetest.test
    def VERIFY_IXIA_TRAFFIC_AFTER_MOVE(self, testscript):
        """ IXIA_CONFIGURATION subsection: Verify IXIA Traffic """

        # Do not perform configurations if skip_tgen_config flag is set
        if not testscript.parameters['script_flags']['skip_tgen_config']:

            time.sleep(20)

            if ixLib.verify_traffic(15) == 0:
                log.debug("Traffic Verification failed")
                self.failed("Traffic Verification failed", goto=['cleanup'])
            else:
                log.info("Traffic Verification Passed")
        else:
            self.passed(reason="Skipped TGEN Configurations as per request")
            
    @aetest.test        
    def Host_move_FO_BACK(self,testscript):
        
        
        FO_1=testscript.parameters['FO_1']

        
        try:
            FO_1.configure('''
            interface ''' + str(testscript.parameters['intf_FO_1_to_LEAF_3']) + '''
            shut
            switchport
            switchport mode trunk
            
            interface ''' + str(testscript.parameters['intf_FO_1_to_N7k_LEAF_3']) + '''
            no shut
            switchport
            switchport mode trunk
            
            
            
            ''')
            time.sleep(45)
        except Exception as error:
                log.debug("Unable to configure - Encountered Exception " + str(error))
                self.errored('Exception occurred while configuring on FO_1', goto=['common_cleanup'])
                
    @aetest.test
    def VERIFY_IXIA_TRAFFIC_HOST_MOVE_BACK(self, testscript):
        """ IXIA_CONFIGURATION subsection: Verify IXIA Traffic """

        # Do not perform configurations if skip_tgen_config flag is set
        if not testscript.parameters['script_flags']['skip_tgen_config']:

            time.sleep(20)

            if ixLib.verify_traffic(15) == 0:
                log.debug("Traffic Verification failed")
                self.failed("Traffic Verification failed", goto=['cleanup'])
            else:
                log.info("Traffic Verification Passed")
        else:
            self.passed(reason="Skipped TGEN Configurations as per request")
        
    @aetest.cleanup
    def cleanup(self,testscript):
        """Unconfigure qos policies"""
        LEAF_1 = testscript.parameters['LEAF-1']
        LEAF_2 = testscript.parameters['LEAF-2']
        LEAF_3 = testscript.parameters['LEAF-3']
        FO_1=testscript.parameters['FO_1']
        LEAF_1 = testscript.parameters['LEAF-1']
        LEAF_2 = testscript.parameters['LEAF-2']
        forwardingSysDict = testscript.parameters['forwardingSysDict']
        l2_vlan_id = testscript.parameters['N7K_LEAF_1_dict']['Vlan_data']['l2_vlan_start']
        l2_vlan_ipv4_start= testscript.parameters['N7K_LEAF_1_dict']['Vlan_data']['l2_vlan_ipv4_start']
        l2_vlan_ipv4_mask= testscript.parameters['N7K_LEAF_1_dict']['Vlan_data']['l2_vlan_ipv4_mask']
        l2_vlan_ipv6_start= testscript.parameters['N7K_LEAF_1_dict']['Vlan_data']['l2_vlan_ipv6_start']
        l2_vlan_ipv6_mask= testscript.parameters['N7K_LEAF_1_dict']['Vlan_data']['l2_vlan_ipv6_mask']
        l2_hsrp_ipv4_vip_start= testscript.parameters['N7K_LEAF_1_dict']['Vlan_data']['hsrp_ipv4_vip_start']
        l2_hsrp_ipv6_vip_start= testscript.parameters['N7K_LEAF_1_dict']['Vlan_data']['hsrp_ipv6_vip_start']
        bia_mac_l1 = testscript.parameters['LEAF_1_dict']['VNI_data']['bia_mac_start']
        bia_mac_l2 = testscript.parameters['LEAF_2_dict']['VNI_data']['bia_mac_start']
        l2_vlan_ipv4_sec_start= testscript.parameters['LEAF_2_dict']['VNI_data']['l2_vlan_ipv4_sec_start']
        
        post_test_process_dict = {
            'dut_list'                       : [LEAF_1, LEAF_2, LEAF_3],
            'cc_check'                  : 1,
            'cores_check'               : 1,
            'logs_check'                : 0,
            'fnl_flag'                  : 0,
            'exclude_log_check_pattern' : 'ERROR_VLANS_SUSPENDED|ERROR_VLANS_REMOVED',
            }
        try:
            FO_1.configure('''
            interface ''' + str(testscript.parameters['intf_FO_1_to_LEAF_3']) + '''
            shut
            switchport
            switchport mode trunk
            
            interface ''' + str(testscript.parameters['intf_FO_1_to_N7k_LEAF_3']) + '''
            no shut
            switchport
            switchport mode trunk
            ''')
            time.sleep(30)
            ###Remove Pre-migration step from both N7k leafs
            device_handle=connect_to_vdc(testscript.parameters['xbow1'], 'leaf1')
            if device_handle==False:
                log.info("failed to switchto correct vdc")
                self.failed("failed to switchto correct vdc",goto=['common_cleanup'])
            else:
                total_ip_count = int(forwardingSysDict['VLAN_PER_VRF_count']) * int(forwardingSysDict['VRF_count'])
                l2_ipv4s = increment_prefix_network(ip.IPv4Interface(str(l2_vlan_ipv4_start) + str(l2_vlan_ipv4_mask)),total_ip_count)
                l2_ipv6s = increment_prefix_network(ip.IPv6Interface(str(l2_vlan_ipv6_start) + str(l2_vlan_ipv6_mask)),total_ip_count)
                ip_index=0
                for i in range(0,len(l2_ipv4s)):
                    device_handle.configure('''int vlan ''' + str(l2_vlan_id) + '''\n
                                     hsrp version 2
                                     hsrp ''' + str(l2_vlan_id) + ''' ipv4
                                     no mac-address 0000.000a.aaaa
                                     ''')
                    l2_vlan_id += 1
            l2_vlan_id = testscript.parameters['N7K_LEAF_1_dict']['Vlan_data']['l2_vlan_start']        
            device_handle=connect_to_vdc(testscript.parameters['xbow2'], 'leaf2')
            if device_handle==False:
                log.info("failed to switchto correct vdc")
                self.failed("failed to switchto correct vdc",goto=['common_cleanup'])
            else:
                total_ip_count = int(forwardingSysDict['VLAN_PER_VRF_count']) * int(forwardingSysDict['VRF_count'])
                l2_ipv4s = increment_prefix_network(ip.IPv4Interface(str(l2_vlan_ipv4_start) + str(l2_vlan_ipv4_mask)),total_ip_count)
                l2_ipv6s = increment_prefix_network(ip.IPv6Interface(str(l2_vlan_ipv6_start) + str(l2_vlan_ipv6_mask)),total_ip_count)
                ip_index=0
                for i in range(0,len(l2_ipv4s)):
                    device_handle.configure('''int vlan ''' + str(l2_vlan_id) + '''\n
                                     hsrp version 2
                                     hsrp ''' + str(l2_vlan_id) + ''' ipv4
                                     no mac-address 0000.000a.aaaa
                                     ''')
                    l2_vlan_id += 1
                    
            ###Remove non-default mac for bia address from SVI on Vxlan Leaf1 and leaf2
            # =============================================================================================================================#        
    
    
            total_ip_count = int(forwardingSysDict['VLAN_PER_VRF_count']) * int(forwardingSysDict['VRF_count'])
            l2_ipv4s = increment_prefix_network(ip.IPv4Interface(str(l2_vlan_ipv4_sec_start) + str(l2_vlan_ipv4_mask)),total_ip_count)
            ip_index=0
            for i in range(0,len(l2_ipv4s)):
                LEAF_2.configure('''int vlan ''' + str(l2_vlan_id) + '''\n
                                 no mac-address ''' + str(bia_mac_l2) + '''
                                 ''')
                l2_vlan_id += 1
                ip_index += 1
                
            for i in range(0,len(l2_ipv4s)):
                LEAF_1.configure('''int vlan ''' + str(l2_vlan_id) + '''\n
                                 no mac-address ''' + str(bia_mac_l1) + '''
                                 ''')
                l2_vlan_id += 1
                ip_index += 1
            
        except Exception as error:
            log.debug("Unable to configure - Encountered Exception " + str(error))
            self.errored('Exception occurred while configuring secondary ipv4 address on LEAF-1', goto=['cleanup'])
            status = infraVerify.postTestVerification(post_test_process_dict)
            if status['status'] == 0:
                self.failed(reason=status['logs'])
            else:
                self.passed(reason=status['logs'])
        except Exception as error:
            log.debug("Unable to unconfigure class map or policy map-Encountered exception " + str(error))
            self.errored('Exception occurred while unconfiguring qos on LEAF1', goto=['next_tc'])       
    # =============================================================================================================================#
# *****************************************************************************************************************************#
class L2_trunk_Ext_int(aetest.Testcase):
    """ Host_move_ipv4 """

    @aetest.test
    def create_checkpoint(self,testscript):
        
        LEAF_1 = testscript.parameters['LEAF-1']
        LEAF_2 = testscript.parameters['LEAF-2']
        
        try:
            device_handle=connect_to_vdc(testscript.parameters['xbow1'], 'leaf1')
            if device_handle==False:
                log.info("failed to switchto correct vdc")
                self.failed("failed to switchto correct vdc",goto=['common_cleanup'])
            else:
                device_handle.execute("checkpoint  pre_l2_trunk")
                
            device_handle=connect_to_vdc(testscript.parameters['xbow2'], 'leaf2')
            if device_handle==False:
                log.info("failed to switchto correct vdc")
                self.failed("failed to switchto correct vdc",goto=['common_cleanup'])
            else:
                device_handle.execute("checkpoint  pre_l2_trunk")
                
            LEAF_1.execute("checkpoint  pre_l2_trunk")
            
            LEAF_2.execute("checkpoint  pre_l2_trunk")
        except Exception as error:
            log.debug("Unable to create a checkpoint:" +str(error))
            self.errored("Exception occured while creating a checkpoint.", goto=['next_tc'])
    # =============================================================================================================================#        
    
    @aetest.test
    def SVI_ON_LEAF2(self, testscript):
        """Shut down the vpc leg on Leaf2 to force all traffic to Leaf1"""
        
        LEAF_1 = testscript.parameters['LEAF-1']
        LEAF_2 = testscript.parameters['LEAF-2']
        forwardingSysDict = testscript.parameters['forwardingSysDict']
        l2_vlan_id = testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vlan_start']
        l2_vlan_ipv4_sec_start= testscript.parameters['LEAF_2_dict']['VNI_data']['l2_vlan_ipv4_sec_start']
        l2_vlan_ipv4_mask= testscript.parameters['LEAF_2_dict']['VNI_data']['l2_vlan_ipv4_mask']
        #+ str(testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vlan_ipv4_mask'])
        
        try:
            total_ip_count = int(forwardingSysDict['VLAN_PER_VRF_count']) * int(forwardingSysDict['VRF_count'])
            l2_ipv4s = increment_prefix_network(ip.IPv4Interface(str(l2_vlan_ipv4_sec_start) + str(l2_vlan_ipv4_mask)),total_ip_count)
            ip_index=0
            for i in range(0,len(l2_ipv4s)):
                LEAF_2.configure('''int vlan ''' + str(l2_vlan_id) + '''\n
                                 ip address ''' + str(l2_ipv4s[ip_index]) + ''' secondary use-bia
                                 ''')
                l2_vlan_id += 1
                ip_index += 1
                
            
            
        except Exception as error:
            log.debug("Unable to configure - Encountered Exception " + str(error))
            self.errored('Exception occurred while configuring secondary ipv4 address on LEAF-2', goto=['cleanup'])
            
    # =============================================================================================================================#        
    
    @aetest.test
    def SVI_ON_LEAF1(self, testscript):
        """Shut down the vpc leg on Leaf2 to force all traffic to Leaf1"""
        
        LEAF_1 = testscript.parameters['LEAF-1']
        LEAF_2 = testscript.parameters['LEAF-2']
        forwardingSysDict = testscript.parameters['forwardingSysDict']
        l2_vlan_id = testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vlan_start']
        l2_vlan_ipv4_sec_start= testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vlan_ipv4_sec_start']
        l2_vlan_ipv4_mask= testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vlan_ipv4_mask']
        
        try:
            total_ip_count = int(forwardingSysDict['VLAN_PER_VRF_count']) * int(forwardingSysDict['VRF_count'])
            l2_ipv4s = increment_prefix_network(ip.IPv4Interface(str(l2_vlan_ipv4_sec_start) + str(l2_vlan_ipv4_mask)),total_ip_count)
            ip_index=0
            for i in range(0,len(l2_ipv4s)):
                LEAF_1.configure('''int vlan ''' + str(l2_vlan_id) + '''\n
                                 ip address ''' + str(l2_ipv4s[ip_index]) + ''' secondary use-bia
                                 ''')
                l2_vlan_id += 1
                ip_index += 1
                
            
            
        except Exception as error:
            log.debug("Unable to configure - Encountered Exception " + str(error))
            self.errored('Exception occurred while configuring secondary ipv4 address on LEAF-1', goto=['cleanup'])
            
     # =============================================================================================================================#        
    @aetest.test
    def Add_external_int(self, testscript):
        """Shut down the vpc leg on Leaf2 to force all traffic to Leaf1"""
        
        LEAF_1 = testscript.parameters['LEAF-1']
        LEAF_2 = testscript.parameters['LEAF-2']
        
        try:
            testscript.parameters['LEAF-2'].configure('''
                  interface po ''' + str(testscript.parameters['LEAF_1_dict']['VPC_data']['double_vpc_po_1']) + '''
                  port-type external
                  shutdown
                
                ''')
            
            testscript.parameters['LEAF-1'].configure('''
                  interface po ''' + str(testscript.parameters['LEAF_1_dict']['VPC_data']['double_vpc_po_1']) + '''
                  port-type external
                  shutdown
                  
                  interface ''' + str(testscript.parameters['intf_LEAF_1_to_N7k_LEAF_1_1']) + '''
                    no channel-group ''' + str(testscript.parameters['LEAF_1_dict']['VPC_data']['double_vpc_po_1']) + ''' force mode active
                    switchport
                    switchport mode trunk
                    port-type external
                    no shutdown
                  ''')    
            
            device_handle=connect_to_vdc(testscript.parameters['xbow1'], 'leaf1')
            if device_handle==False:
                log.info("failed to switchto correct vdc")
                self.failed("failed to switchto correct vdc",goto=['common_cleanup'])
            else:
                device_handle.configure('''
                                    interface po ''' + str(testscript.parameters['LEAF_1_dict']['VPC_data']['double_vpc_po_1']) + '''
                                      shutdown
                
                                    interface ''' + str(testscript.parameters['intf_N7k_LEAF_1_to_LEAF_1_1'].intf) + '''
                                      no channel-group ''' + str(testscript.parameters['LEAF_1_dict']['VPC_data']['double_vpc_po_1']) + ''' mode active
                                      switchport
                                      switchport mode trunk
                                      no shutdown ''')
                
            device_handle=connect_to_vdc(testscript.parameters['xbow2'], 'leaf2')
            if device_handle==False:
                log.info("failed to switchto correct vdc")
                self.failed("failed to switchto correct vdc",goto=['common_cleanup'])
            else:
                device_handle.configure('''
                                    interface po ''' + str(testscript.parameters['LEAF_1_dict']['VPC_data']['double_vpc_po_1']) + '''
                                      shutdown
                
                                    ''')
            
        except Exception as error:
            log.debug("Unable to configure - Encountered Exception " + str(error))
            self.errored('Exception occurred while configuring external on LEAF-1 and LEAF-2', goto=['cleanup'])
            
     # =============================================================================================================================#    
    @aetest.test
    def Pre_migration_hsrp(self,testscript):
        LEAF_1 = testscript.parameters['LEAF-1']
        LEAF_2 = testscript.parameters['LEAF-2']
        forwardingSysDict = testscript.parameters['forwardingSysDict']
        l2_vlan_id = testscript.parameters['N7K_LEAF_1_dict']['Vlan_data']['l2_vlan_start']
        l2_vlan_ipv4_start= testscript.parameters['N7K_LEAF_1_dict']['Vlan_data']['l2_vlan_ipv4_start']
        l2_vlan_ipv4_mask= testscript.parameters['N7K_LEAF_1_dict']['Vlan_data']['l2_vlan_ipv4_mask']
        l2_vlan_ipv6_start= testscript.parameters['N7K_LEAF_1_dict']['Vlan_data']['l2_vlan_ipv6_start']
        l2_vlan_ipv6_mask= testscript.parameters['N7K_LEAF_1_dict']['Vlan_data']['l2_vlan_ipv6_mask']
        l2_hsrp_ipv4_vip_start= testscript.parameters['N7K_LEAF_1_dict']['Vlan_data']['hsrp_ipv4_vip_start']
        l2_hsrp_ipv6_vip_start= testscript.parameters['N7K_LEAF_1_dict']['Vlan_data']['hsrp_ipv6_vip_start']
        
        try:
            device_handle=connect_to_vdc(testscript.parameters['xbow1'], 'leaf1')
            if device_handle==False:
                log.info("failed to switchto correct vdc")
                self.failed("failed to switchto correct vdc",goto=['common_cleanup'])
            else:
                total_ip_count = int(forwardingSysDict['VLAN_PER_VRF_count']) * int(forwardingSysDict['VRF_count'])
                l2_ipv4s = increment_prefix_network(ip.IPv4Interface(str(l2_vlan_ipv4_start) + str(l2_vlan_ipv4_mask)),total_ip_count)
                l2_ipv6s = increment_prefix_network(ip.IPv6Interface(str(l2_vlan_ipv6_start) + str(l2_vlan_ipv6_mask)),total_ip_count)
                ip_index=0
                for i in range(0,len(l2_ipv4s)):
                    device_handle.configure('''int vlan ''' + str(l2_vlan_id) + '''\n
                                     hsrp version 2
                                     hsrp ''' + str(l2_vlan_id) + ''' ipv4
                                     mac-address 0000.000a.aaaa
                                     ''')
                    l2_vlan_id += 1
            l2_vlan_id = testscript.parameters['N7K_LEAF_1_dict']['Vlan_data']['l2_vlan_start']        
            device_handle=connect_to_vdc(testscript.parameters['xbow2'], 'leaf2')
            if device_handle==False:
                log.info("failed to switchto correct vdc")
                self.failed("failed to switchto correct vdc",goto=['common_cleanup'])
            else:
                total_ip_count = int(forwardingSysDict['VLAN_PER_VRF_count']) * int(forwardingSysDict['VRF_count'])
                l2_ipv4s = increment_prefix_network(ip.IPv4Interface(str(l2_vlan_ipv4_start) + str(l2_vlan_ipv4_mask)),total_ip_count)
                l2_ipv6s = increment_prefix_network(ip.IPv6Interface(str(l2_vlan_ipv6_start) + str(l2_vlan_ipv6_mask)),total_ip_count)
                ip_index=0
                for i in range(0,len(l2_ipv4s)):
                    device_handle.configure('''int vlan ''' + str(l2_vlan_id) + '''\n
                                     hsrp version 2
                                     hsrp ''' + str(l2_vlan_id) + ''' ipv4
                                     mac-address 0000.000a.aaaa
                                     ''')
                    l2_vlan_id += 1
                    


        except Exception as error:
                log.debug("Unable to configure - Encountered Exception " + str(error))
                self.errored('Exception occurred while configuring on N7k leaf1', goto=['common_cleanup'])
                
    @aetest.test        
    def configure_FO(self,testscript):
        
        FO_1_vlanConfiguration = ""
        FO_1=testscript.parameters['FO_1']

        l3_vrf_count_iter = 0
        l2_vlan_id = testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vlan_start']
        l3_vlan_id = testscript.parameters['LEAF_1_dict']['VNI_data']['l3_vlan_start']

        while l3_vrf_count_iter < testscript.parameters['forwardingSysDict']['VRF_count']:
            l2_vlan_count_iter = 0
            FO_1_vlanConfiguration += '''vlan ''' + str(l3_vlan_id) + '''\n
                                            state active\n
                                            no shut\n'''
            while l2_vlan_count_iter < testscript.parameters['forwardingSysDict']['VLAN_PER_VRF_count']:
                # Incrementing L2 VLAN Iteration counters
                FO_1_vlanConfiguration += '''vlan ''' + str(l2_vlan_id) + '''\n
                                                state active\n
                                                no shut\n'''
                l2_vlan_count_iter += 1
                l2_vlan_id += 1
            # Incrementing L3 VRF Iteration counters
            l3_vrf_count_iter += 1
            l3_vlan_id += 1

        try:
            FO_1.configure(
                str(FO_1_vlanConfiguration) + '''
        
        
            
            interface ''' + str(testscript.parameters['intf_FO_1_to_N7k_LEAF_3']) + '''
            no shut
            switchport
            switchport mode trunk
            
            interface ''' + str(testscript.parameters['intf_FO_1_to_LEAF_3']) + '''
            shut
            switchport
            switchport mode trunk
            
            interface ''' + str(testscript.parameters['intf_FO_1_to_IXIA']) + '''
            no shut
            switchport
            switchport mode trunk
            
            ''')
        except Exception as error:
                log.debug("Unable to configure - Encountered Exception " + str(error))
                self.errored('Exception occurred while configuring on FO_1', goto=['common_cleanup'])
   
#     @aetest.test
#     def CONFIGURE_UCAST_L3_IXIA_TRAFFIC(self, testscript):
#         """ IXIA_CONFIGURATION subsection: Configure MCAST Traffic Item """
# 
#         # Do not perform configurations if skip_tgen_config flag is set
#         if not testscript.parameters['script_flags']['skip_tgen_config']:
# 
#             IX_TP1 = testscript.parameters['IX_TP1']
#             IX_TP2 = testscript.parameters['IX_TP2']
#             P1_dict = testscript.parameters['LEAF_2_TGEN_dict']
#             P2_dict = testscript.parameters['LEAF_3_TGEN_dict']
# 
#             UCAST_v4_dict = {   'src_hndl'  : IX_TP1['port_handle'],
#                                 'dst_hndl'  : IX_TP2['port_handle'],
#                                 'ip_dscp'   : P1_dict['ip_dscp'],
#                                 'circuit'   : 'raw',
#                                 'TI_name'   : "UCAST_L3",
#                                 'rate_pps'  : "9000",
#                                 'bi_dir'    : 1,
#                                 'frame_size': '128',
#                                 'src_mac'   : P1_dict['mac'],
#                                 'dst_mac'   : '0000.000a.aaaa',
#                                 'srcmac_step': '00:00:00:00:00:00',
#                                 'dstmac_step': '00:00:00:00:00:00',
#                                 'srcmac_count': '1',
#                                 'dstmac_count': '1',
#                                 'vlan_id'    : P1_dict['vlan_id'],
#                                 'vlanid_step': '0',
#                                 'vlanid_count': '1',
#                                 'vlan_user_priority': P1_dict['vlan_user_priority'],
#                                 'ip_src_addrs' : P1_dict['v4_addr'],
#                                 'ip_dst_addrs' : P1_dict['L3_dst_addr'],
#                                 'ip_src_step' : '0.0.0.0',
#                                 'ip_dst_step' : '0.0.0.0',
# #                                'ip_step'    : P1_dict['v4_addr_step'],
#                           }
# 
# #            UCAST_v6_dict = {   'src_hndl'  : IX_TP1['ipv6_handle'],
# #                                'dst_hndl'  : IX_TP2['ipv6_handle'],
# #                                'circuit'   : 'ipv6',
# #                                'TI_name'   : "UCAST_V6",
# #                                'rate_pps'  : "1000",
# #                                'bi_dir'    : 1
# #                          }
# 
#             UCAST_v4_TI = ixLib.configure_ixia_l3_traffic_item(UCAST_v4_dict)
# #            UCAST_v6_TI = ixLib.configure_ixia_traffic_item(UCAST_v6_dict)
# 
# #            if UCAST_v4_TI == 0 or UCAST_v6_TI == 0:
# #                log.debug("Configuring UCast TI failed")
# #                self.errored("Configuring UCast TI failed", goto=['cleanup'])
#                 
#             if UCAST_v4_TI == 0:
#                 log.debug("Configuring UCast TI failed")
#                 self.errored("Configuring UCast TI failed", goto=['cleanup'])
#             else:
#                 global stream_id
#                 stream_id = UCAST_v4_TI
# 
#         else:
#             self.passed(reason="Skipped TGEN Configurations as per request")
            
    # @aetest.test
    # def CONFIGURE_BCAST_IXIA_TRAFFIC(self, testscript):
    #     """ IXIA_CONFIGURATION subsection: Configure MCAST Traffic Item """
    # 
    #     # Do not perform configurations if skip_tgen_config flag is set
    #     if not testscript.parameters['script_flags']['skip_tgen_config']:
    # 
    #         IX_TP1 = testscript.parameters['IX_TP1']
    #         IX_TP2 = testscript.parameters['IX_TP2']
    #         P1_dict = testscript.parameters['LEAF_2_TGEN_dict']
    #         P2_dict = testscript.parameters['LEAF_3_TGEN_dict']
    #         BCAST_v4_dict = {
    #                             'src_hndl'      : IX_TP1['port_handle'],
    #                             'dst_hndl'      : IX_TP2['port_handle'],
    #                             'TI_name'       : "BCAST_V4",
    #                             'frame_size'    : "70",
    #                             'rate_pps'      : "1000",
    #                             'src_mac'       : P1_dict['mac'],
    #                             'srcmac_step'   : "00:00:00:00:00:01",
    #                             'srcmac_count'  : '1',
    #                             'vlan_id'       : P1_dict['vlan_id'],
    #                             'vlanid_step'   : "1",
    #                             'vlanid_count'  : "1",
    #                             'ip_src_addrs'  : P1_dict['v4_addr'],
    #                             'ip_step'       : "0.0.1.0",
    #                       }
    # 
    #         BCAST_v4_TI = ixLib.configure_ixia_BCAST_traffic_item(BCAST_v4_dict)
    # 
    #         if BCAST_v4_TI == 0:
    #             log.debug("Configuring BCast TI failed")
    #             self.errored("Configuring BCast TI failed", goto=['cleanup'])
    # 
    #     else:
    #         self.passed(reason="Skipped TGEN Configurations as per request")
    # =============================================================================================================================#
    @aetest.test
    def APPLY_TRAFFIC(self):
        """ IXIA_CONFIGURATION subsection: Verify IXIA Traffic """

        # # Apply IXIA Traffic
        # if ixLib.apply_traffic() == 1:
        #     log.info("Applying IXIA TI Passed")
        # else:
        #     self.errored("Applying IXIA TI failed", goto=['cleanup'])
            
        # =============================================================================================================================#
    #--------------------------------------------------------------------------------#
        # Start traffic from ixia
        log.info("--- Populating the statistics --- \n")
        log.info("---- Running Traffic --- \n")
        log.info("Starting Traffic")

        traffic_run_status  = ixLib.start_traffic()

        if traffic_run_status is not 1:
           log.info("Failed: To start traffic")
           return 0
        else:
            log.info("\nTraffic started successfully\n")

        time.sleep(30)
    
    # Stop Traffic from ixia
        log.info("--- Stopping Traffic ---- \n")
        log.info("Stopping Traffic")
        traffic_run_status = ixLib.stop_traffic()
        
        if traffic_run_status is not 1:
           log.info("Failed: To Stop traffic")
           return 0
        else:
            log.info("\nTraffic Stopped successfully\n")
            time.sleep(10)    
    
    @aetest.test
    def VERIFY_IXIA_TRAFFIC(self, testscript):
        """ IXIA_CONFIGURATION subsection: Verify IXIA Traffic """

        # Do not perform configurations if skip_tgen_config flag is set
        if not testscript.parameters['script_flags']['skip_tgen_config']:

            time.sleep(20)

            if ixLib.verify_traffic(2) == 0:
                log.debug("Traffic Verification failed")
                self.failed("Traffic Verification failed", goto=['cleanup'])
            else:
                log.info("Traffic Verification Passed")
        else:
            self.passed(reason="Skipped TGEN Configurations as per request")
            
     # =============================================================================================================================#        
    @aetest.test
    def Clear_ARP_Table_on_Vxlan_BLs(self, testscript):
        """Shut down the vpc leg on Leaf2 to force all traffic to Leaf1"""
        
        LEAF_1 = testscript.parameters['LEAF-1']
        LEAF_2 = testscript.parameters['LEAF-2']
        
        try:
            for i in range(1, testscript.parameters['forwardingSysDict']['VRF_count']+1):
                testscript.parameters['LEAF-2'].execute('''
                      clear ip arp vrf ''' + str(testscript.parameters['forwardingSysDict']['VRF_string']) + str(i) + ''' force-delete''')
            
            for i in range(1, testscript.parameters['forwardingSysDict']['VRF_count']+1):
                testscript.parameters['LEAF-1'].execute('''
                      clear ip arp vrf ''' + str(testscript.parameters['forwardingSysDict']['VRF_string']) + str(i) + ''' force-delete''')    
            
            
        except Exception as error:
            log.debug("Unable to configure - Encountered Exception " + str(error))
            self.errored('Exception occurred while clearing arp cache on LEAF-1 and LEAF-2', goto=['cleanup'])
            
    @aetest.test        
    def Host_move_FO(self,testscript):
        
        
        FO_1=testscript.parameters['FO_1']

        
        try:
            FO_1.configure('''
            interface ''' + str(testscript.parameters['intf_FO_1_to_N7k_LEAF_3']) + '''
            shut
            switchport
            switchport mode trunk
            
            interface ''' + str(testscript.parameters['intf_FO_1_to_LEAF_3']) + '''
            no shut
            switchport
            switchport mode trunk
            
            ''')
            time.sleep(45)
        except Exception as error:
                log.debug("Unable to configure - Encountered Exception " + str(error))
                self.errored('Exception occurred while configuring on FO_1', goto=['common_cleanup'])
                
    @aetest.test
    def VERIFY_IXIA_TRAFFIC_AFTER_MOVE(self, testscript):
        """ IXIA_CONFIGURATION subsection: Verify IXIA Traffic """

        # Do not perform configurations if skip_tgen_config flag is set
        if not testscript.parameters['script_flags']['skip_tgen_config']:

            time.sleep(20)

            if ixLib.verify_traffic(15) == 0:
                log.debug("Traffic Verification failed")
                self.failed("Traffic Verification failed", goto=['cleanup'])
            else:
                log.info("Traffic Verification Passed")
        else:
            self.passed(reason="Skipped TGEN Configurations as per request")
            
    @aetest.test        
    def Host_move_FO_BACK(self,testscript):
        
        
        FO_1=testscript.parameters['FO_1']

        
        try:
            FO_1.configure('''
            interface ''' + str(testscript.parameters['intf_FO_1_to_LEAF_3']) + '''
            shut
            switchport
            switchport mode trunk
            
            interface ''' + str(testscript.parameters['intf_FO_1_to_N7k_LEAF_3']) + '''
            no shut
            switchport
            switchport mode trunk
            
            
            
            ''')
            time.sleep(45)
        except Exception as error:
                log.debug("Unable to configure - Encountered Exception " + str(error))
                self.errored('Exception occurred while configuring on FO_1', goto=['common_cleanup'])
                
    @aetest.test
    def VERIFY_IXIA_TRAFFIC_HOST_MOVE_BACK(self, testscript):
        """ IXIA_CONFIGURATION subsection: Verify IXIA Traffic """

        # Do not perform configurations if skip_tgen_config flag is set
        if not testscript.parameters['script_flags']['skip_tgen_config']:

            time.sleep(20)

            if ixLib.verify_traffic(15) == 0:
                log.debug("Traffic Verification failed")
                self.failed("Traffic Verification failed", goto=['cleanup'])
            else:
                log.info("Traffic Verification Passed")
        else:
            self.passed(reason="Skipped TGEN Configurations as per request")
        
    @aetest.cleanup
    def cleanup(self,testscript):
        """Unconfigure qos policies"""
        LEAF_1 = testscript.parameters['LEAF-1']
        LEAF_2 = testscript.parameters['LEAF-2']
        LEAF_3 = testscript.parameters['LEAF-3']
        FO_1=testscript.parameters['FO_1']
        LEAF_1 = testscript.parameters['LEAF-1']
        LEAF_2 = testscript.parameters['LEAF-2']
        forwardingSysDict = testscript.parameters['forwardingSysDict']
        l2_vlan_id = testscript.parameters['N7K_LEAF_1_dict']['Vlan_data']['l2_vlan_start']
        l2_vlan_ipv4_start= testscript.parameters['N7K_LEAF_1_dict']['Vlan_data']['l2_vlan_ipv4_start']
        l2_vlan_ipv4_mask= testscript.parameters['N7K_LEAF_1_dict']['Vlan_data']['l2_vlan_ipv4_mask']
        l2_vlan_ipv6_start= testscript.parameters['N7K_LEAF_1_dict']['Vlan_data']['l2_vlan_ipv6_start']
        l2_vlan_ipv6_mask= testscript.parameters['N7K_LEAF_1_dict']['Vlan_data']['l2_vlan_ipv6_mask']
        l2_hsrp_ipv4_vip_start= testscript.parameters['N7K_LEAF_1_dict']['Vlan_data']['hsrp_ipv4_vip_start']
        l2_hsrp_ipv6_vip_start= testscript.parameters['N7K_LEAF_1_dict']['Vlan_data']['hsrp_ipv6_vip_start']
        
        post_test_process_dict = {
            'dut_list'                       : [LEAF_1, LEAF_2, LEAF_3],
            'cc_check'                  : 1,
            'cores_check'               : 1,
            'logs_check'                : 0,
            'fnl_flag'                  : 0,
            'exclude_log_check_pattern' : 'ERROR_VLANS_SUSPENDED|ERROR_VLANS_REMOVED',
            }
        try:
            FO_1.configure('''
            interface ''' + str(testscript.parameters['intf_FO_1_to_LEAF_3']) + '''
            shut
            switchport
            switchport mode trunk
            
            interface ''' + str(testscript.parameters['intf_FO_1_to_N7k_LEAF_3']) + '''
            no shut
            switchport
            switchport mode trunk
            ''')
            time.sleep(30)
            ###Remove Pre-migration step from both N7k leafs
            device_handle=connect_to_vdc(testscript.parameters['xbow1'], 'leaf1')
            if device_handle==False:
                log.info("failed to switchto correct vdc")
                self.failed("failed to switchto correct vdc",goto=['common_cleanup'])
            else:
                total_ip_count = int(forwardingSysDict['VLAN_PER_VRF_count']) * int(forwardingSysDict['VRF_count'])
                l2_ipv4s = increment_prefix_network(ip.IPv4Interface(str(l2_vlan_ipv4_start) + str(l2_vlan_ipv4_mask)),total_ip_count)
                l2_ipv6s = increment_prefix_network(ip.IPv6Interface(str(l2_vlan_ipv6_start) + str(l2_vlan_ipv6_mask)),total_ip_count)
                ip_index=0
                for i in range(0,len(l2_ipv4s)):
                    device_handle.configure('''int vlan ''' + str(l2_vlan_id) + '''\n
                                     hsrp version 2
                                     hsrp ''' + str(l2_vlan_id) + ''' ipv4
                                     no mac-address 0000.000a.aaaa
                                     ''')
                    l2_vlan_id += 1
            l2_vlan_id = testscript.parameters['N7K_LEAF_1_dict']['Vlan_data']['l2_vlan_start']        
            device_handle=connect_to_vdc(testscript.parameters['xbow2'], 'leaf2')
            if device_handle==False:
                log.info("failed to switchto correct vdc")
                self.failed("failed to switchto correct vdc",goto=['common_cleanup'])
            else:
                total_ip_count = int(forwardingSysDict['VLAN_PER_VRF_count']) * int(forwardingSysDict['VRF_count'])
                l2_ipv4s = increment_prefix_network(ip.IPv4Interface(str(l2_vlan_ipv4_start) + str(l2_vlan_ipv4_mask)),total_ip_count)
                l2_ipv6s = increment_prefix_network(ip.IPv6Interface(str(l2_vlan_ipv6_start) + str(l2_vlan_ipv6_mask)),total_ip_count)
                ip_index=0
                for i in range(0,len(l2_ipv4s)):
                    device_handle.configure('''int vlan ''' + str(l2_vlan_id) + '''\n
                                     hsrp version 2
                                     hsrp ''' + str(l2_vlan_id) + ''' ipv4
                                     no mac-address 0000.000a.aaaa
                                     ''')
                    l2_vlan_id += 1
            ####Rollback the external PO config to vpc PO        
            device_handle=connect_to_vdc(testscript.parameters['xbow1'], 'leaf1')
            if device_handle==False:
                log.info("failed to switchto correct vdc")
                self.failed("failed to switchto correct vdc",goto=['common_cleanup'])
            else:
                device_handle.execute("rollback running-config checkpoint  pre_l2_trunk")
                device_handle.configure("no checkpoint pre_l2_trunk")
                
            device_handle=connect_to_vdc(testscript.parameters['xbow2'], 'leaf2')
            if device_handle==False:
                log.info("failed to switchto correct vdc")
                self.failed("failed to switchto correct vdc",goto=['common_cleanup'])
            else:
                device_handle.execute("rollback running-config checkpoint  pre_l2_trunk")
                device_handle.configure("no checkpoint pre_l2_trunk")
                
            LEAF_1.execute("rollback running-config checkpoint  pre_l2_trunk")
            LEAF_1.execute("no checkpoint pre_l2_trunk")
            
            LEAF_2.execute("rollback running-config checkpoint  pre_l2_trunk")
            LEAF_2.execute("no checkpoint pre_l2_trunk")
            
            ##
            status = infraVerify.postTestVerification(post_test_process_dict)
            if status['status'] == 0:
                self.failed(reason=status['logs'])
            else:
                self.passed(reason=status['logs'])
        except Exception as error:
            log.debug("Unable to unconfigure class map or policy map-Encountered exception " + str(error))
            self.errored('Exception occurred while unconfiguring qos on LEAF1', goto=['next_tc'])
            
# *****************************************************************************************************************************#
class L2_Access_Ext_int(aetest.Testcase):
    """ Host_move_ipv4 """

    @aetest.test
    def create_checkpoint(self,testscript):
        
        LEAF_1 = testscript.parameters['LEAF-1']
        LEAF_2 = testscript.parameters['LEAF-2']
        
        try:
            device_handle=connect_to_vdc(testscript.parameters['xbow1'], 'leaf1')
            if device_handle==False:
                log.info("failed to switchto correct vdc")
                self.failed("failed to switchto correct vdc",goto=['common_cleanup'])
            else:
                device_handle.execute("checkpoint  pre_l2_access")
                
            device_handle=connect_to_vdc(testscript.parameters['xbow2'], 'leaf2')
            if device_handle==False:
                log.info("failed to switchto correct vdc")
                self.failed("failed to switchto correct vdc",goto=['common_cleanup'])
            else:
                device_handle.execute("checkpoint  pre_l2_access")
                
            LEAF_1.execute("checkpoint  pre_l2_access")
            
            LEAF_2.execute("checkpoint  pre_l2_access")
        except Exception as error:
            log.debug("Unable to create a checkpoint:" +str(error))
            self.errored("Exception occured while creating a checkpoint.", goto=['next_tc'])
    # =============================================================================================================================#        
    
    @aetest.test
    def SVI_ON_LEAF2(self, testscript):
        """Shut down the vpc leg on Leaf2 to force all traffic to Leaf1"""
        
        LEAF_1 = testscript.parameters['LEAF-1']
        LEAF_2 = testscript.parameters['LEAF-2']
        forwardingSysDict = testscript.parameters['forwardingSysDict']
        l2_vlan_id = testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vlan_start']
        l2_vlan_ipv4_sec_start= testscript.parameters['LEAF_2_dict']['VNI_data']['l2_vlan_ipv4_sec_start']
        l2_vlan_ipv4_mask= testscript.parameters['LEAF_2_dict']['VNI_data']['l2_vlan_ipv4_mask']
        #+ str(testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vlan_ipv4_mask'])
        
        try:
            total_ip_count = int(forwardingSysDict['VLAN_PER_VRF_count']) * int(forwardingSysDict['VRF_count'])
            l2_ipv4s = increment_prefix_network(ip.IPv4Interface(str(l2_vlan_ipv4_sec_start) + str(l2_vlan_ipv4_mask)),total_ip_count)
            ip_index=0
            for i in range(0,len(l2_ipv4s)):
                LEAF_2.configure('''int vlan ''' + str(l2_vlan_id) + '''\n
                                 ip address ''' + str(l2_ipv4s[ip_index]) + ''' secondary use-bia
                                 ''')
                l2_vlan_id += 1
                ip_index += 1
                
            
            
        except Exception as error:
            log.debug("Unable to configure - Encountered Exception " + str(error))
            self.errored('Exception occurred while configuring secondary ipv4 address on LEAF-2', goto=['cleanup'])
            
    # =============================================================================================================================#        
    
    @aetest.test
    def SVI_ON_LEAF1(self, testscript):
        """Shut down the vpc leg on Leaf2 to force all traffic to Leaf1"""
        
        LEAF_1 = testscript.parameters['LEAF-1']
        LEAF_2 = testscript.parameters['LEAF-2']
        forwardingSysDict = testscript.parameters['forwardingSysDict']
        l2_vlan_id = testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vlan_start']
        l2_vlan_ipv4_sec_start= testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vlan_ipv4_sec_start']
        l2_vlan_ipv4_mask= testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vlan_ipv4_mask']
        
        try:
            total_ip_count = int(forwardingSysDict['VLAN_PER_VRF_count']) * int(forwardingSysDict['VRF_count'])
            l2_ipv4s = increment_prefix_network(ip.IPv4Interface(str(l2_vlan_ipv4_sec_start) + str(l2_vlan_ipv4_mask)),total_ip_count)
            ip_index=0
            for i in range(0,len(l2_ipv4s)):
                LEAF_1.configure('''int vlan ''' + str(l2_vlan_id) + '''\n
                                 ip address ''' + str(l2_ipv4s[ip_index]) + ''' secondary use-bia
                                 ''')
                l2_vlan_id += 1
                ip_index += 1
                
            
            
        except Exception as error:
            log.debug("Unable to configure - Encountered Exception " + str(error))
            self.errored('Exception occurred while configuring secondary ipv4 address on LEAF-1', goto=['cleanup'])
            
     # =============================================================================================================================#        
    @aetest.test
    def Add_external_int(self, testscript):
        """Shut down the vpc leg on Leaf2 to force all traffic to Leaf1"""
        
        LEAF_1 = testscript.parameters['LEAF-1']
        LEAF_2 = testscript.parameters['LEAF-2']
        l2_vlan_id = testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vlan_start']+1
        
        try:
            testscript.parameters['LEAF-2'].configure('''
                  interface po ''' + str(testscript.parameters['LEAF_1_dict']['VPC_data']['double_vpc_po_1']) + '''
                  port-type external
                  shutdown
                
                ''')
            
            testscript.parameters['LEAF-1'].configure('''
                  interface po ''' + str(testscript.parameters['LEAF_1_dict']['VPC_data']['double_vpc_po_1']) + '''
                  port-type external
                  shutdown
                  
                  interface ''' + str(testscript.parameters['intf_LEAF_1_to_N7k_LEAF_1_1']) + '''
                    no channel-group ''' + str(testscript.parameters['LEAF_1_dict']['VPC_data']['double_vpc_po_1']) + ''' force mode active
                    switchport
                    switchport mode access
                    switchport access vlan ''' + str(l2_vlan_id) + '''
                    port-type external
                    no shutdown
                  ''')    
            
            device_handle=connect_to_vdc(testscript.parameters['xbow1'], 'leaf1')
            if device_handle==False:
                log.info("failed to switchto correct vdc")
                self.failed("failed to switchto correct vdc",goto=['common_cleanup'])
            else:
                device_handle.configure('''
                                    interface po ''' + str(testscript.parameters['LEAF_1_dict']['VPC_data']['double_vpc_po_1']) + '''
                                      shutdown
                
                                    interface ''' + str(testscript.parameters['intf_N7k_LEAF_1_to_LEAF_1_1'].intf) + '''
                                      no channel-group ''' + str(testscript.parameters['LEAF_1_dict']['VPC_data']['double_vpc_po_1']) + ''' mode active
                                      switchport
                                      switchport mode access
                                      switchport access vlan ''' + str(l2_vlan_id) + '''
                                      no shutdown ''')
                
            device_handle=connect_to_vdc(testscript.parameters['xbow2'], 'leaf2')
            if device_handle==False:
                log.info("failed to switchto correct vdc")
                self.failed("failed to switchto correct vdc",goto=['common_cleanup'])
            else:
                device_handle.configure('''
                                    interface po ''' + str(testscript.parameters['LEAF_1_dict']['VPC_data']['double_vpc_po_1']) + '''
                                      shutdown
                
                                    ''')
            
        except Exception as error:
            log.debug("Unable to configure - Encountered Exception " + str(error))
            self.errored('Exception occurred while configuring external on LEAF-1 and LEAF-2', goto=['cleanup'])
            
     # =============================================================================================================================#    
    @aetest.test
    def Pre_migration_hsrp(self,testscript):
        LEAF_1 = testscript.parameters['LEAF-1']
        LEAF_2 = testscript.parameters['LEAF-2']
        forwardingSysDict = testscript.parameters['forwardingSysDict']
        l2_vlan_id = testscript.parameters['N7K_LEAF_1_dict']['Vlan_data']['l2_vlan_start']
        l2_vlan_ipv4_start= testscript.parameters['N7K_LEAF_1_dict']['Vlan_data']['l2_vlan_ipv4_start']
        l2_vlan_ipv4_mask= testscript.parameters['N7K_LEAF_1_dict']['Vlan_data']['l2_vlan_ipv4_mask']
        l2_vlan_ipv6_start= testscript.parameters['N7K_LEAF_1_dict']['Vlan_data']['l2_vlan_ipv6_start']
        l2_vlan_ipv6_mask= testscript.parameters['N7K_LEAF_1_dict']['Vlan_data']['l2_vlan_ipv6_mask']
        l2_hsrp_ipv4_vip_start= testscript.parameters['N7K_LEAF_1_dict']['Vlan_data']['hsrp_ipv4_vip_start']
        l2_hsrp_ipv6_vip_start= testscript.parameters['N7K_LEAF_1_dict']['Vlan_data']['hsrp_ipv6_vip_start']
        
        try:
            device_handle=connect_to_vdc(testscript.parameters['xbow1'], 'leaf1')
            if device_handle==False:
                log.info("failed to switchto correct vdc")
                self.failed("failed to switchto correct vdc",goto=['common_cleanup'])
            else:
                total_ip_count = int(forwardingSysDict['VLAN_PER_VRF_count']) * int(forwardingSysDict['VRF_count'])
                l2_ipv4s = increment_prefix_network(ip.IPv4Interface(str(l2_vlan_ipv4_start) + str(l2_vlan_ipv4_mask)),total_ip_count)
                l2_ipv6s = increment_prefix_network(ip.IPv6Interface(str(l2_vlan_ipv6_start) + str(l2_vlan_ipv6_mask)),total_ip_count)
                ip_index=0
                for i in range(0,len(l2_ipv4s)):
                    device_handle.configure('''int vlan ''' + str(l2_vlan_id) + '''\n
                                     hsrp version 2
                                     hsrp ''' + str(l2_vlan_id) + ''' ipv4
                                     mac-address 0000.000a.aaaa
                                     ''')
                    l2_vlan_id += 1
            l2_vlan_id = testscript.parameters['N7K_LEAF_1_dict']['Vlan_data']['l2_vlan_start']        
            device_handle=connect_to_vdc(testscript.parameters['xbow2'], 'leaf2')
            if device_handle==False:
                log.info("failed to switchto correct vdc")
                self.failed("failed to switchto correct vdc",goto=['common_cleanup'])
            else:
                total_ip_count = int(forwardingSysDict['VLAN_PER_VRF_count']) * int(forwardingSysDict['VRF_count'])
                l2_ipv4s = increment_prefix_network(ip.IPv4Interface(str(l2_vlan_ipv4_start) + str(l2_vlan_ipv4_mask)),total_ip_count)
                l2_ipv6s = increment_prefix_network(ip.IPv6Interface(str(l2_vlan_ipv6_start) + str(l2_vlan_ipv6_mask)),total_ip_count)
                ip_index=0
                for i in range(0,len(l2_ipv4s)):
                    device_handle.configure('''int vlan ''' + str(l2_vlan_id) + '''\n
                                     hsrp version 2
                                     hsrp ''' + str(l2_vlan_id) + ''' ipv4
                                     mac-address 0000.000a.aaaa
                                     ''')
                    l2_vlan_id += 1
                    


        except Exception as error:
                log.debug("Unable to configure - Encountered Exception " + str(error))
                self.errored('Exception occurred while configuring on N7k leaf1', goto=['common_cleanup'])
                
    @aetest.test        
    def configure_FO(self,testscript):
        
        FO_1_vlanConfiguration = ""
        FO_1=testscript.parameters['FO_1']

        l3_vrf_count_iter = 0
        l2_vlan_id = testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vlan_start']
        l3_vlan_id = testscript.parameters['LEAF_1_dict']['VNI_data']['l3_vlan_start']

        while l3_vrf_count_iter < testscript.parameters['forwardingSysDict']['VRF_count']:
            l2_vlan_count_iter = 0
            FO_1_vlanConfiguration += '''vlan ''' + str(l3_vlan_id) + '''\n
                                            state active\n
                                            no shut\n'''
            while l2_vlan_count_iter < testscript.parameters['forwardingSysDict']['VLAN_PER_VRF_count']:
                # Incrementing L2 VLAN Iteration counters
                FO_1_vlanConfiguration += '''vlan ''' + str(l2_vlan_id) + '''\n
                                                state active\n
                                                no shut\n'''
                l2_vlan_count_iter += 1
                l2_vlan_id += 1
            # Incrementing L3 VRF Iteration counters
            l3_vrf_count_iter += 1
            l3_vlan_id += 1

        try:
            FO_1.configure(
                str(FO_1_vlanConfiguration) + '''
        
        
            
            interface ''' + str(testscript.parameters['intf_FO_1_to_N7k_LEAF_3']) + '''
            no shut
            switchport
            switchport mode trunk
            
            interface ''' + str(testscript.parameters['intf_FO_1_to_LEAF_3']) + '''
            shut
            switchport
            switchport mode trunk
            
            interface ''' + str(testscript.parameters['intf_FO_1_to_IXIA']) + '''
            no shut
            switchport
            switchport mode trunk
            
            ''')
        except Exception as error:
                log.debug("Unable to configure - Encountered Exception " + str(error))
                self.errored('Exception occurred while configuring on FO_1', goto=['common_cleanup'])
   
#     @aetest.test
#     def CONFIGURE_UCAST_L3_IXIA_TRAFFIC(self, testscript):
#         """ IXIA_CONFIGURATION subsection: Configure MCAST Traffic Item """
# 
#         # Do not perform configurations if skip_tgen_config flag is set
#         if not testscript.parameters['script_flags']['skip_tgen_config']:
# 
#             IX_TP1 = testscript.parameters['IX_TP1']
#             IX_TP2 = testscript.parameters['IX_TP2']
#             P1_dict = testscript.parameters['LEAF_2_TGEN_dict']
#             P2_dict = testscript.parameters['LEAF_3_TGEN_dict']
# 
#             UCAST_v4_dict = {   'src_hndl'  : IX_TP1['port_handle'],
#                                 'dst_hndl'  : IX_TP2['port_handle'],
#                                 'ip_dscp'   : P1_dict['ip_dscp'],
#                                 'circuit'   : 'raw',
#                                 'TI_name'   : "UCAST_L3",
#                                 'rate_pps'  : "9000",
#                                 'bi_dir'    : 1,
#                                 'frame_size': '128',
#                                 'src_mac'   : P1_dict['mac'],
#                                 'dst_mac'   : '0000.000a.aaaa',
#                                 'srcmac_step': '00:00:00:00:00:00',
#                                 'dstmac_step': '00:00:00:00:00:00',
#                                 'srcmac_count': '1',
#                                 'dstmac_count': '1',
#                                 'vlan_id'    : P1_dict['vlan_id'],
#                                 'vlanid_step': '0',
#                                 'vlanid_count': '1',
#                                 'vlan_user_priority': P1_dict['vlan_user_priority'],
#                                 'ip_src_addrs' : P1_dict['v4_addr'],
#                                 'ip_dst_addrs' : P1_dict['L3_dst_addr'],
#                                 'ip_src_step' : '0.0.0.0',
#                                 'ip_dst_step' : '0.0.0.0',
# #                                'ip_step'    : P1_dict['v4_addr_step'],
#                           }
# 
# #            UCAST_v6_dict = {   'src_hndl'  : IX_TP1['ipv6_handle'],
# #                                'dst_hndl'  : IX_TP2['ipv6_handle'],
# #                                'circuit'   : 'ipv6',
# #                                'TI_name'   : "UCAST_V6",
# #                                'rate_pps'  : "1000",
# #                                'bi_dir'    : 1
# #                          }
# 
#             UCAST_v4_TI = ixLib.configure_ixia_l3_traffic_item(UCAST_v4_dict)
# #            UCAST_v6_TI = ixLib.configure_ixia_traffic_item(UCAST_v6_dict)
# 
# #            if UCAST_v4_TI == 0 or UCAST_v6_TI == 0:
# #                log.debug("Configuring UCast TI failed")
# #                self.errored("Configuring UCast TI failed", goto=['cleanup'])
#                 
#             if UCAST_v4_TI == 0:
#                 log.debug("Configuring UCast TI failed")
#                 self.errored("Configuring UCast TI failed", goto=['cleanup'])
#             else:
#                 global stream_id
#                 stream_id = UCAST_v4_TI
# 
#         else:
#             self.passed(reason="Skipped TGEN Configurations as per request")
            
    
    # =============================================================================================================================#
    @aetest.test
    def APPLY_TRAFFIC(self):
        """ IXIA_CONFIGURATION subsection: Verify IXIA Traffic """

        # # Apply IXIA Traffic
        # if ixLib.apply_traffic() == 1:
        #     log.info("Applying IXIA TI Passed")
        # else:
        #     self.errored("Applying IXIA TI failed", goto=['cleanup'])
            
        # =============================================================================================================================#
    #--------------------------------------------------------------------------------#
        # Start traffic from ixia
        log.info("--- Populating the statistics --- \n")
        log.info("---- Running Traffic --- \n")
        log.info("Starting Traffic")

        traffic_run_status  = ixLib.start_traffic()

        if traffic_run_status is not 1:
           log.info("Failed: To start traffic")
           return 0
        else:
            log.info("\nTraffic started successfully\n")

        time.sleep(30)
    
    # Stop Traffic from ixia
        log.info("--- Stopping Traffic ---- \n")
        log.info("Stopping Traffic")
        traffic_run_status = ixLib.stop_traffic()
        
        if traffic_run_status is not 1:
           log.info("Failed: To Stop traffic")
           return 0
        else:
            log.info("\nTraffic Stopped successfully\n")
            time.sleep(10)    
    
    @aetest.test
    def VERIFY_IXIA_TRAFFIC(self, testscript):
        """ IXIA_CONFIGURATION subsection: Verify IXIA Traffic """

        # Do not perform configurations if skip_tgen_config flag is set
        if not testscript.parameters['script_flags']['skip_tgen_config']:

            time.sleep(20)

            if ixLib.verify_traffic(2) == 0:
                log.debug("Traffic Verification failed")
                self.failed("Traffic Verification failed", goto=['cleanup'])
            else:
                log.info("Traffic Verification Passed")
        else:
            self.passed(reason="Skipped TGEN Configurations as per request")
            
     # =============================================================================================================================#        
    @aetest.test
    def Clear_ARP_Table_on_Vxlan_BLs(self, testscript):
        """Shut down the vpc leg on Leaf2 to force all traffic to Leaf1"""
        
        LEAF_1 = testscript.parameters['LEAF-1']
        LEAF_2 = testscript.parameters['LEAF-2']
        
        try:
            for i in range(1, testscript.parameters['forwardingSysDict']['VRF_count']+1):
                testscript.parameters['LEAF-2'].execute('''
                      clear ip arp vrf ''' + str(testscript.parameters['forwardingSysDict']['VRF_string']) + str(i) + ''' force-delete''')
            
            for i in range(1, testscript.parameters['forwardingSysDict']['VRF_count']+1):
                testscript.parameters['LEAF-1'].execute('''
                      clear ip arp vrf ''' + str(testscript.parameters['forwardingSysDict']['VRF_string']) + str(i) + ''' force-delete''')    
            
            
        except Exception as error:
            log.debug("Unable to configure - Encountered Exception " + str(error))
            self.errored('Exception occurred while clearing arp cache on LEAF-1 and LEAF-2', goto=['cleanup'])
            
    @aetest.test        
    def Host_move_FO(self,testscript):
        
        
        FO_1=testscript.parameters['FO_1']

        
        try:
            FO_1.configure('''
            interface ''' + str(testscript.parameters['intf_FO_1_to_N7k_LEAF_3']) + '''
            shut
            switchport
            switchport mode trunk
            
            interface ''' + str(testscript.parameters['intf_FO_1_to_LEAF_3']) + '''
            no shut
            switchport
            switchport mode trunk
            
            ''')
            time.sleep(45)
        except Exception as error:
                log.debug("Unable to configure - Encountered Exception " + str(error))
                self.errored('Exception occurred while configuring on FO_1', goto=['common_cleanup'])
                
    @aetest.test
    def VERIFY_IXIA_TRAFFIC_AFTER_MOVE(self, testscript):
        """ IXIA_CONFIGURATION subsection: Verify IXIA Traffic """

        # Do not perform configurations if skip_tgen_config flag is set
        if not testscript.parameters['script_flags']['skip_tgen_config']:

            time.sleep(20)

            if ixLib.verify_traffic(15) == 0:
                log.debug("Traffic Verification failed")
                self.failed("Traffic Verification failed", goto=['cleanup'])
            else:
                log.info("Traffic Verification Passed")
        else:
            self.passed(reason="Skipped TGEN Configurations as per request")
            
    @aetest.test        
    def Host_move_FO_BACK(self,testscript):
        
        
        FO_1=testscript.parameters['FO_1']

        
        try:
            FO_1.configure('''
            interface ''' + str(testscript.parameters['intf_FO_1_to_LEAF_3']) + '''
            shut
            switchport
            switchport mode trunk
            
            interface ''' + str(testscript.parameters['intf_FO_1_to_N7k_LEAF_3']) + '''
            no shut
            switchport
            switchport mode trunk
            
            
            
            ''')
            time.sleep(45)
        except Exception as error:
                log.debug("Unable to configure - Encountered Exception " + str(error))
                self.errored('Exception occurred while configuring on FO_1', goto=['common_cleanup'])
                
    @aetest.test
    def VERIFY_IXIA_TRAFFIC_HOST_MOVE_BACK(self, testscript):
        """ IXIA_CONFIGURATION subsection: Verify IXIA Traffic """

        # Do not perform configurations if skip_tgen_config flag is set
        if not testscript.parameters['script_flags']['skip_tgen_config']:

            time.sleep(20)

            if ixLib.verify_traffic(15) == 0:
                log.debug("Traffic Verification failed")
                self.failed("Traffic Verification failed", goto=['cleanup'])
            else:
                log.info("Traffic Verification Passed")
        else:
            self.passed(reason="Skipped TGEN Configurations as per request")
        
    @aetest.cleanup
    def cleanup(self,testscript):
        """Unconfigure qos policies"""
        LEAF_1 = testscript.parameters['LEAF-1']
        LEAF_2 = testscript.parameters['LEAF-2']
        LEAF_3 = testscript.parameters['LEAF-3']
        FO_1=testscript.parameters['FO_1']
        LEAF_1 = testscript.parameters['LEAF-1']
        LEAF_2 = testscript.parameters['LEAF-2']
        forwardingSysDict = testscript.parameters['forwardingSysDict']
        l2_vlan_id = testscript.parameters['N7K_LEAF_1_dict']['Vlan_data']['l2_vlan_start']
        l2_vlan_ipv4_start= testscript.parameters['N7K_LEAF_1_dict']['Vlan_data']['l2_vlan_ipv4_start']
        l2_vlan_ipv4_mask= testscript.parameters['N7K_LEAF_1_dict']['Vlan_data']['l2_vlan_ipv4_mask']
        l2_vlan_ipv6_start= testscript.parameters['N7K_LEAF_1_dict']['Vlan_data']['l2_vlan_ipv6_start']
        l2_vlan_ipv6_mask= testscript.parameters['N7K_LEAF_1_dict']['Vlan_data']['l2_vlan_ipv6_mask']
        l2_hsrp_ipv4_vip_start= testscript.parameters['N7K_LEAF_1_dict']['Vlan_data']['hsrp_ipv4_vip_start']
        l2_hsrp_ipv6_vip_start= testscript.parameters['N7K_LEAF_1_dict']['Vlan_data']['hsrp_ipv6_vip_start']
        
        post_test_process_dict = {
            'dut_list'                       : [LEAF_1, LEAF_2, LEAF_3],
            'cc_check'                  : 1,
            'cores_check'               : 1,
            'logs_check'                : 0,
            'fnl_flag'                  : 0,
            'exclude_log_check_pattern' : 'ERROR_VLANS_SUSPENDED|ERROR_VLANS_REMOVED',
            }
        try:
            FO_1.configure('''
            interface ''' + str(testscript.parameters['intf_FO_1_to_LEAF_3']) + '''
            shut
            switchport
            switchport mode trunk
            
            interface ''' + str(testscript.parameters['intf_FO_1_to_N7k_LEAF_3']) + '''
            no shut
            switchport
            switchport mode trunk
            ''')
            time.sleep(30)
            ###Remove Pre-migration step from both N7k leafs
            device_handle=connect_to_vdc(testscript.parameters['xbow1'], 'leaf1')
            if device_handle==False:
                log.info("failed to switchto correct vdc")
                self.failed("failed to switchto correct vdc",goto=['common_cleanup'])
            else:
                total_ip_count = int(forwardingSysDict['VLAN_PER_VRF_count']) * int(forwardingSysDict['VRF_count'])
                l2_ipv4s = increment_prefix_network(ip.IPv4Interface(str(l2_vlan_ipv4_start) + str(l2_vlan_ipv4_mask)),total_ip_count)
                l2_ipv6s = increment_prefix_network(ip.IPv6Interface(str(l2_vlan_ipv6_start) + str(l2_vlan_ipv6_mask)),total_ip_count)
                ip_index=0
                for i in range(0,len(l2_ipv4s)):
                    device_handle.configure('''int vlan ''' + str(l2_vlan_id) + '''\n
                                     hsrp version 2
                                     hsrp ''' + str(l2_vlan_id) + ''' ipv4
                                     no mac-address 0000.000a.aaaa
                                     ''')
                    l2_vlan_id += 1
            l2_vlan_id = testscript.parameters['N7K_LEAF_1_dict']['Vlan_data']['l2_vlan_start']        
            device_handle=connect_to_vdc(testscript.parameters['xbow2'], 'leaf2')
            if device_handle==False:
                log.info("failed to switchto correct vdc")
                self.failed("failed to switchto correct vdc",goto=['common_cleanup'])
            else:
                total_ip_count = int(forwardingSysDict['VLAN_PER_VRF_count']) * int(forwardingSysDict['VRF_count'])
                l2_ipv4s = increment_prefix_network(ip.IPv4Interface(str(l2_vlan_ipv4_start) + str(l2_vlan_ipv4_mask)),total_ip_count)
                l2_ipv6s = increment_prefix_network(ip.IPv6Interface(str(l2_vlan_ipv6_start) + str(l2_vlan_ipv6_mask)),total_ip_count)
                ip_index=0
                for i in range(0,len(l2_ipv4s)):
                    device_handle.configure('''int vlan ''' + str(l2_vlan_id) + '''\n
                                     hsrp version 2
                                     hsrp ''' + str(l2_vlan_id) + ''' ipv4
                                     no mac-address 0000.000a.aaaa
                                     ''')
                    l2_vlan_id += 1
            ####Rollback the external PO config to vpc PO        
            device_handle=connect_to_vdc(testscript.parameters['xbow1'], 'leaf1')
            if device_handle==False:
                log.info("failed to switchto correct vdc")
                self.failed("failed to switchto correct vdc",goto=['common_cleanup'])
            else:
                device_handle.execute("rollback running-config checkpoint  pre_l2_access")
                device_handle.configure("no checkpoint pre_l2_access")
                
            device_handle=connect_to_vdc(testscript.parameters['xbow2'], 'leaf2')
            if device_handle==False:
                log.info("failed to switchto correct vdc")
                self.failed("failed to switchto correct vdc",goto=['common_cleanup'])
            else:
                device_handle.execute("rollback running-config checkpoint  pre_l2_access")
                device_handle.configure("no checkpoint pre_l2_access")
                
            LEAF_1.execute("rollback running-config checkpoint  pre_l2_access")
            LEAF_1.execute("no checkpoint pre_l2_access")
            
            LEAF_2.execute("rollback running-config checkpoint  pre_l2_access")
            LEAF_2.execute("no checkpoint pre_l2_access")
            
            ##
            status = infraVerify.postTestVerification(post_test_process_dict)
            if status['status'] == 0:
                self.failed(reason=status['logs'])
            else:
                self.passed(reason=status['logs'])
        except Exception as error:
            log.debug("Unable to unconfigure class map or policy map-Encountered exception " + str(error))
            self.errored('Exception occurred while unconfiguring qos on LEAF1', goto=['next_tc'])
            
      
    # =============================================================================================================================#
    
# *****************************************************************************************************************************#
class Vrf_flap_pre_Host_move_ipv4(aetest.Testcase):
    """ Host_move_ipv4 """

    
    # =============================================================================================================================#        
    
    @aetest.test
    def SVI_ON_LEAF2(self, testscript):
        """Shut down the vpc leg on Leaf2 to force all traffic to Leaf1"""
        
        LEAF_1 = testscript.parameters['LEAF-1']
        LEAF_2 = testscript.parameters['LEAF-2']
        forwardingSysDict = testscript.parameters['forwardingSysDict']
        l2_vlan_id = testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vlan_start']
        l2_vlan_ipv4_sec_start= testscript.parameters['LEAF_2_dict']['VNI_data']['l2_vlan_ipv4_sec_start']
        l2_vlan_ipv4_mask= testscript.parameters['LEAF_2_dict']['VNI_data']['l2_vlan_ipv4_mask']
        #+ str(testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vlan_ipv4_mask'])
        
        try:
            total_ip_count = int(forwardingSysDict['VLAN_PER_VRF_count']) * int(forwardingSysDict['VRF_count'])
            l2_ipv4s = increment_prefix_network(ip.IPv4Interface(str(l2_vlan_ipv4_sec_start) + str(l2_vlan_ipv4_mask)),total_ip_count)
            ip_index=0
            for i in range(0,len(l2_ipv4s)):
                LEAF_2.configure('''int vlan ''' + str(l2_vlan_id) + '''\n
                                 ip address ''' + str(l2_ipv4s[ip_index]) + ''' secondary use-bia
                                 ''')
                l2_vlan_id += 1
                ip_index += 1
                
            
            
        except Exception as error:
            log.debug("Unable to configure - Encountered Exception " + str(error))
            self.errored('Exception occurred while configuring secondary ipv4 address on LEAF-2', goto=['cleanup'])
            
    # =============================================================================================================================#        
    
    @aetest.test
    def SVI_ON_LEAF1(self, testscript):
        """Shut down the vpc leg on Leaf2 to force all traffic to Leaf1"""
        
        LEAF_1 = testscript.parameters['LEAF-1']
        LEAF_2 = testscript.parameters['LEAF-2']
        forwardingSysDict = testscript.parameters['forwardingSysDict']
        l2_vlan_id = testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vlan_start']
        l2_vlan_ipv4_sec_start= testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vlan_ipv4_sec_start']
        l2_vlan_ipv4_mask= testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vlan_ipv4_mask']
        
        try:
            total_ip_count = int(forwardingSysDict['VLAN_PER_VRF_count']) * int(forwardingSysDict['VRF_count'])
            l2_ipv4s = increment_prefix_network(ip.IPv4Interface(str(l2_vlan_ipv4_sec_start) + str(l2_vlan_ipv4_mask)),total_ip_count)
            ip_index=0
            for i in range(0,len(l2_ipv4s)):
                LEAF_1.configure('''int vlan ''' + str(l2_vlan_id) + '''\n
                                 ip address ''' + str(l2_ipv4s[ip_index]) + ''' secondary use-bia
                                 ''')
                l2_vlan_id += 1
                ip_index += 1
                
            
            
        except Exception as error:
            log.debug("Unable to configure - Encountered Exception " + str(error))
            self.errored('Exception occurred while configuring secondary ipv4 address on LEAF-1', goto=['cleanup'])
            
     # =============================================================================================================================#        
    @aetest.test
    def Add_external_int(self, testscript):
        """Shut down the vpc leg on Leaf2 to force all traffic to Leaf1"""
        
        LEAF_1 = testscript.parameters['LEAF-1']
        LEAF_2 = testscript.parameters['LEAF-2']
        
        try:
            testscript.parameters['LEAF-2'].configure('''
                  interface po ''' + str(testscript.parameters['LEAF_1_dict']['VPC_data']['double_vpc_po_1']) + '''
                  port-type external
                  ''')
            
            testscript.parameters['LEAF-1'].configure('''
                  interface po ''' + str(testscript.parameters['LEAF_1_dict']['VPC_data']['double_vpc_po_1']) + '''
                  port-type external
                  ''')    
            
            
        except Exception as error:
            log.debug("Unable to configure - Encountered Exception " + str(error))
            self.errored('Exception occurred while configuring external on LEAF-1 and LEAF-2', goto=['cleanup'])
            
     # =============================================================================================================================#    
    @aetest.test
    def Pre_migration_hsrp(self,testscript):
        LEAF_1 = testscript.parameters['LEAF-1']
        LEAF_2 = testscript.parameters['LEAF-2']
        forwardingSysDict = testscript.parameters['forwardingSysDict']
        l2_vlan_id = testscript.parameters['N7K_LEAF_1_dict']['Vlan_data']['l2_vlan_start']
        l2_vlan_ipv4_start= testscript.parameters['N7K_LEAF_1_dict']['Vlan_data']['l2_vlan_ipv4_start']
        l2_vlan_ipv4_mask= testscript.parameters['N7K_LEAF_1_dict']['Vlan_data']['l2_vlan_ipv4_mask']
        l2_vlan_ipv6_start= testscript.parameters['N7K_LEAF_1_dict']['Vlan_data']['l2_vlan_ipv6_start']
        l2_vlan_ipv6_mask= testscript.parameters['N7K_LEAF_1_dict']['Vlan_data']['l2_vlan_ipv6_mask']
        l2_hsrp_ipv4_vip_start= testscript.parameters['N7K_LEAF_1_dict']['Vlan_data']['hsrp_ipv4_vip_start']
        l2_hsrp_ipv6_vip_start= testscript.parameters['N7K_LEAF_1_dict']['Vlan_data']['hsrp_ipv6_vip_start']
        
        try:
            device_handle=connect_to_vdc(testscript.parameters['xbow1'], 'leaf1')
            if device_handle==False:
                log.info("failed to switchto correct vdc")
                self.failed("failed to switchto correct vdc",goto=['common_cleanup'])
            else:
                total_ip_count = int(forwardingSysDict['VLAN_PER_VRF_count']) * int(forwardingSysDict['VRF_count'])
                l2_ipv4s = increment_prefix_network(ip.IPv4Interface(str(l2_vlan_ipv4_start) + str(l2_vlan_ipv4_mask)),total_ip_count)
                l2_ipv6s = increment_prefix_network(ip.IPv6Interface(str(l2_vlan_ipv6_start) + str(l2_vlan_ipv6_mask)),total_ip_count)
                ip_index=0
                for i in range(0,len(l2_ipv4s)):
                    device_handle.configure('''int vlan ''' + str(l2_vlan_id) + '''\n
                                     hsrp version 2
                                     hsrp ''' + str(l2_vlan_id) + ''' ipv4
                                     mac-address 0000.000a.aaaa
                                     ''')
                    l2_vlan_id += 1
            l2_vlan_id = testscript.parameters['N7K_LEAF_1_dict']['Vlan_data']['l2_vlan_start']        
            device_handle=connect_to_vdc(testscript.parameters['xbow2'], 'leaf2')
            if device_handle==False:
                log.info("failed to switchto correct vdc")
                self.failed("failed to switchto correct vdc",goto=['common_cleanup'])
            else:
                total_ip_count = int(forwardingSysDict['VLAN_PER_VRF_count']) * int(forwardingSysDict['VRF_count'])
                l2_ipv4s = increment_prefix_network(ip.IPv4Interface(str(l2_vlan_ipv4_start) + str(l2_vlan_ipv4_mask)),total_ip_count)
                l2_ipv6s = increment_prefix_network(ip.IPv6Interface(str(l2_vlan_ipv6_start) + str(l2_vlan_ipv6_mask)),total_ip_count)
                ip_index=0
                for i in range(0,len(l2_ipv4s)):
                    device_handle.configure('''int vlan ''' + str(l2_vlan_id) + '''\n
                                     hsrp version 2
                                     hsrp ''' + str(l2_vlan_id) + ''' ipv4
                                     mac-address 0000.000a.aaaa
                                     ''')
                    l2_vlan_id += 1
                    


        except Exception as error:
                log.debug("Unable to configure - Encountered Exception " + str(error))
                self.errored('Exception occurred while configuring on N7k leaf1', goto=['common_cleanup'])
                
    @aetest.test        
    def configure_FO(self,testscript):
        
        FO_1_vlanConfiguration = ""
        FO_1=testscript.parameters['FO_1']

        l3_vrf_count_iter = 0
        l2_vlan_id = testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vlan_start']
        l3_vlan_id = testscript.parameters['LEAF_1_dict']['VNI_data']['l3_vlan_start']

        while l3_vrf_count_iter < testscript.parameters['forwardingSysDict']['VRF_count']:
            l2_vlan_count_iter = 0
            FO_1_vlanConfiguration += '''vlan ''' + str(l3_vlan_id) + '''\n
                                            state active\n
                                            no shut\n'''
            while l2_vlan_count_iter < testscript.parameters['forwardingSysDict']['VLAN_PER_VRF_count']:
                # Incrementing L2 VLAN Iteration counters
                FO_1_vlanConfiguration += '''vlan ''' + str(l2_vlan_id) + '''\n
                                                state active\n
                                                no shut\n'''
                l2_vlan_count_iter += 1
                l2_vlan_id += 1
            # Incrementing L3 VRF Iteration counters
            l3_vrf_count_iter += 1
            l3_vlan_id += 1

        try:
            FO_1.configure(
                str(FO_1_vlanConfiguration) + '''
        
        
            
            interface ''' + str(testscript.parameters['intf_FO_1_to_N7k_LEAF_3']) + '''
            no shut
            switchport
            switchport mode trunk
            
            interface ''' + str(testscript.parameters['intf_FO_1_to_LEAF_3']) + '''
            shut
            switchport
            switchport mode trunk
            
            interface ''' + str(testscript.parameters['intf_FO_1_to_IXIA']) + '''
            no shut
            switchport
            switchport mode trunk
            
            ''')
        except Exception as error:
                log.debug("Unable to configure - Encountered Exception " + str(error))
                self.errored('Exception occurred while configuring on FO_1', goto=['common_cleanup'])
   
#     @aetest.test
#     def CONFIGURE_UCAST_L3_IXIA_TRAFFIC(self, testscript):
#         """ IXIA_CONFIGURATION subsection: Configure MCAST Traffic Item """
# 
#         # Do not perform configurations if skip_tgen_config flag is set
#         if not testscript.parameters['script_flags']['skip_tgen_config']:
# 
#             IX_TP1 = testscript.parameters['IX_TP1']
#             IX_TP2 = testscript.parameters['IX_TP2']
#             P1_dict = testscript.parameters['LEAF_2_TGEN_dict']
#             P2_dict = testscript.parameters['LEAF_3_TGEN_dict']
# 
#             UCAST_v4_dict = {   'src_hndl'  : IX_TP1['port_handle'],
#                                 'dst_hndl'  : IX_TP2['port_handle'],
#                                 'ip_dscp'   : P1_dict['ip_dscp'],
#                                 'circuit'   : 'raw',
#                                 'TI_name'   : "UCAST_L3",
#                                 'rate_pps'  : "9000",
#                                 'bi_dir'    : 1,
#                                 'frame_size': '128',
#                                 'src_mac'   : P1_dict['mac'],
#                                 'dst_mac'   : '0000.000a.aaaa',
#                                 'srcmac_step': '00:00:00:00:00:00',
#                                 'dstmac_step': '00:00:00:00:00:00',
#                                 'srcmac_count': '1',
#                                 'dstmac_count': '1',
#                                 'vlan_id'    : P1_dict['vlan_id'],
#                                 'vlanid_step': '0',
#                                 'vlanid_count': '1',
#                                 'vlan_user_priority': P1_dict['vlan_user_priority'],
#                                 'ip_src_addrs' : P1_dict['v4_addr'],
#                                 'ip_dst_addrs' : P1_dict['L3_dst_addr'],
#                                 'ip_src_step' : '0.0.0.0',
#                                 'ip_dst_step' : '0.0.0.0',
# #                                'ip_step'    : P1_dict['v4_addr_step'],
#                           }
# 
# #            UCAST_v6_dict = {   'src_hndl'  : IX_TP1['ipv6_handle'],
# #                                'dst_hndl'  : IX_TP2['ipv6_handle'],
# #                                'circuit'   : 'ipv6',
# #                                'TI_name'   : "UCAST_V6",
# #                                'rate_pps'  : "1000",
# #                                'bi_dir'    : 1
# #                          }
# 
#             UCAST_v4_TI = ixLib.configure_ixia_l3_traffic_item(UCAST_v4_dict)
# #            UCAST_v6_TI = ixLib.configure_ixia_traffic_item(UCAST_v6_dict)
# 
# #            if UCAST_v4_TI == 0 or UCAST_v6_TI == 0:
# #                log.debug("Configuring UCast TI failed")
# #                self.errored("Configuring UCast TI failed", goto=['cleanup'])
#                 
#             if UCAST_v4_TI == 0:
#                 log.debug("Configuring UCast TI failed")
#                 self.errored("Configuring UCast TI failed", goto=['cleanup'])
#             else:
#                 global stream_id
#                 stream_id = UCAST_v4_TI
#             
# 
#         else:
#             self.passed(reason="Skipped TGEN Configurations as per request")
            
    # @aetest.test
    # def CONFIGURE_BCAST_IXIA_TRAFFIC(self, testscript):
    #     """ IXIA_CONFIGURATION subsection: Configure MCAST Traffic Item """
    # 
    #     # Do not perform configurations if skip_tgen_config flag is set
    #     if not testscript.parameters['script_flags']['skip_tgen_config']:
    # 
    #         IX_TP1 = testscript.parameters['IX_TP1']
    #         IX_TP2 = testscript.parameters['IX_TP2']
    #         P1_dict = testscript.parameters['LEAF_2_TGEN_dict']
    #         P2_dict = testscript.parameters['LEAF_3_TGEN_dict']
    #         BCAST_v4_dict = {
    #                             'src_hndl'      : IX_TP1['port_handle'],
    #                             'dst_hndl'      : IX_TP2['port_handle'],
    #                             'TI_name'       : "BCAST_V4",
    #                             'frame_size'    : "70",
    #                             'rate_pps'      : "1000",
    #                             'src_mac'       : P1_dict['mac'],
    #                             'srcmac_step'   : "00:00:00:00:00:01",
    #                             'srcmac_count'  : '1',
    #                             'vlan_id'       : P1_dict['vlan_id'],
    #                             'vlanid_step'   : "1",
    #                             'vlanid_count'  : "1",
    #                             'ip_src_addrs'  : P1_dict['v4_addr'],
    #                             'ip_step'       : "0.0.1.0",
    #                       }
    # 
    #         BCAST_v4_TI = ixLib.configure_ixia_BCAST_traffic_item(BCAST_v4_dict)
    # 
    #         if BCAST_v4_TI == 0:
    #             log.debug("Configuring BCast TI failed")
    #             self.errored("Configuring BCast TI failed", goto=['cleanup'])
    #         
    # 
    #     else:
    #         self.passed(reason="Skipped TGEN Configurations as per request")
    # =============================================================================================================================#
    @aetest.test
    def APPLY_TRAFFIC(self):
        """ IXIA_CONFIGURATION subsection: Verify IXIA Traffic """

        # # Apply IXIA Traffic
        # if ixLib.apply_traffic() == 1:
        #     log.info("Applying IXIA TI Passed")
        # else:
        #     self.errored("Applying IXIA TI failed", goto=['cleanup'])
            
        # =============================================================================================================================#
    #--------------------------------------------------------------------------------#
        # Start traffic from ixia
        log.info("--- Populating the statistics --- \n")
        log.info("---- Running Traffic --- \n")
        log.info("Starting Traffic")

        traffic_run_status  = ixLib.start_traffic()

        if traffic_run_status is not 1:
           log.info("Failed: To start traffic")
           return 0
        else:
            log.info("\nTraffic started successfully\n")

        time.sleep(30)
    
    # Stop Traffic from ixia
        log.info("--- Stopping Traffic ---- \n")
        log.info("Stopping Traffic")
        traffic_run_status = ixLib.stop_traffic()
        
        if traffic_run_status is not 1:
           log.info("Failed: To Stop traffic")
           return 0
        else:
            log.info("\nTraffic Stopped successfully\n")
            time.sleep(10)    
    
    @aetest.test
    def VERIFY_IXIA_TRAFFIC(self, testscript):
        """ IXIA_CONFIGURATION subsection: Verify IXIA Traffic """

        # Do not perform configurations if skip_tgen_config flag is set
        if not testscript.parameters['script_flags']['skip_tgen_config']:

            time.sleep(20)

            if ixLib.verify_traffic(2) == 0:
                log.debug("Traffic Verification failed")
                self.failed("Traffic Verification failed", goto=['cleanup'])
            else:
                log.info("Traffic Verification Passed")
        else:
            self.passed(reason="Skipped TGEN Configurations as per request")
    # =============================================================================================================================#
    
    @aetest.test
    def TRIGGER_vrf_flap(self, testscript):
        """ VRF Flap """

        LEAF_1 = testscript.parameters['LEAF-1']
        LEAF_2 = testscript.parameters['LEAF-2']

        try:
            for i in range(1,testscript.parameters['forwardingSysDict']['VRF_count']+1):
                LEAF_1.configure('''
                                 vrf context ''''' + str(testscript.parameters['forwardingSysDict']['VRF_string']) + str(i) + '''
                                 shutdown
                                 ''')
                LEAF_2.configure('''
                                 vrf context ''''' + str(testscript.parameters['forwardingSysDict']['VRF_string']) + str(i) + '''
                                 shutdown
                                 ''')
            time.sleep(60)
            for i in range(1,testscript.parameters['forwardingSysDict']['VRF_count']+1):
                LEAF_1.configure('''
                                 vrf context ''''' + str(testscript.parameters['forwardingSysDict']['VRF_string']) + str(i) + '''
                                 no shutdown''')
                LEAF_2.configure('''
                                 vrf context ''''' + str(testscript.parameters['forwardingSysDict']['VRF_string']) + str(i) + '''
                                 no shutdown''')
        except Exception as error:
            log.debug("Unable to configure - Encountered Exception " + str(error))
            self.errored('Exception occurred while flaping vrf on LEAF-1 and LEAF-2', goto=['cleanup'])
    
    @aetest.test
    def VERIFY_IXIA_TRAFFIC_AFTER_VRF_FLAP(self, testscript):
        """ IXIA_CONFIGURATION subsection: Verify IXIA Traffic """

        # Do not perform configurations if skip_tgen_config flag is set
        if not testscript.parameters['script_flags']['skip_tgen_config']:

            time.sleep(20)

            if ixLib.verify_traffic(2) == 0:
                log.debug("Traffic Verification failed")
                self.failed("Traffic Verification failed", goto=['cleanup'])
            else:
                log.info("Traffic Verification Passed")
        else:
            self.passed(reason="Skipped TGEN Configurations as per request")
     # =============================================================================================================================#        
    @aetest.test
    def Clear_ARP_Table_on_Vxlan_BLs(self, testscript):
        """Shut down the vpc leg on Leaf2 to force all traffic to Leaf1"""
        
        LEAF_1 = testscript.parameters['LEAF-1']
        LEAF_2 = testscript.parameters['LEAF-2']
        
        try:
            for i in range(1, testscript.parameters['forwardingSysDict']['VRF_count']+1):
                testscript.parameters['LEAF-2'].execute('''
                      clear ip arp vrf ''' + str(testscript.parameters['forwardingSysDict']['VRF_string']) + str(i) + ''' force-delete''')
            
            for i in range(1, testscript.parameters['forwardingSysDict']['VRF_count']+1):
                testscript.parameters['LEAF-1'].execute('''
                      clear ip arp vrf ''' + str(testscript.parameters['forwardingSysDict']['VRF_string']) + str(i) + ''' force-delete''')    
            
            
        except Exception as error:
            log.debug("Unable to configure - Encountered Exception " + str(error))
            self.errored('Exception occurred while clearing arp cache on LEAF-1 and LEAF-2', goto=['cleanup'])
            
    @aetest.test        
    def Host_move_FO(self,testscript):
        
        
        FO_1=testscript.parameters['FO_1']

        
        try:
            FO_1.configure('''
            interface ''' + str(testscript.parameters['intf_FO_1_to_N7k_LEAF_3']) + '''
            shut
            switchport
            switchport mode trunk
            
            interface ''' + str(testscript.parameters['intf_FO_1_to_LEAF_3']) + '''
            no shut
            switchport
            switchport mode trunk
            
            ''')
            time.sleep(45)
            #ForkedPdb().set_trace()
        except Exception as error:
                log.debug("Unable to configure - Encountered Exception " + str(error))
                self.errored('Exception occurred while configuring on FO_1', goto=['common_cleanup'])
                
    @aetest.test
    def VERIFY_IXIA_TRAFFIC_AFTER_MOVE(self, testscript):
        """ IXIA_CONFIGURATION subsection: Verify IXIA Traffic """

        # Do not perform configurations if skip_tgen_config flag is set
        if not testscript.parameters['script_flags']['skip_tgen_config']:

            time.sleep(20)

            if ixLib.verify_traffic(15) == 0:
                log.debug("Traffic Verification failed")
                self.failed("Traffic Verification failed", goto=['cleanup'])
            else:
                log.info("Traffic Verification Passed")
            
        else:
            self.passed(reason="Skipped TGEN Configurations as per request")
            
    @aetest.test        
    def Host_move_FO_BACK(self,testscript):
        
        
        FO_1=testscript.parameters['FO_1']

        
        try:
            FO_1.configure('''
            interface ''' + str(testscript.parameters['intf_FO_1_to_LEAF_3']) + '''
            shut
            switchport
            switchport mode trunk
            
            interface ''' + str(testscript.parameters['intf_FO_1_to_N7k_LEAF_3']) + '''
            no shut
            switchport
            switchport mode trunk
            
            
            
            ''')
            time.sleep(45)
        except Exception as error:
                log.debug("Unable to configure - Encountered Exception " + str(error))
                self.errored('Exception occurred while configuring on FO_1', goto=['common_cleanup'])
                
    @aetest.test
    def VERIFY_IXIA_TRAFFIC_HOST_MOVE_BACK(self, testscript):
        """ IXIA_CONFIGURATION subsection: Verify IXIA Traffic """

        # Do not perform configurations if skip_tgen_config flag is set
        if not testscript.parameters['script_flags']['skip_tgen_config']:

            time.sleep(20)

            if ixLib.verify_traffic(15) == 0:
                log.debug("Traffic Verification failed")
                self.failed("Traffic Verification failed", goto=['cleanup'])
            else:
                log.info("Traffic Verification Passed")
        else:
            self.passed(reason="Skipped TGEN Configurations as per request")
        
    @aetest.cleanup
    def cleanup(self,testscript):
        """Unconfigure qos policies"""
        LEAF_1 = testscript.parameters['LEAF-1']
        LEAF_2 = testscript.parameters['LEAF-2']
        LEAF_3 = testscript.parameters['LEAF-3']
        FO_1=testscript.parameters['FO_1']
        LEAF_1 = testscript.parameters['LEAF-1']
        LEAF_2 = testscript.parameters['LEAF-2']
        forwardingSysDict = testscript.parameters['forwardingSysDict']
        l2_vlan_id = testscript.parameters['N7K_LEAF_1_dict']['Vlan_data']['l2_vlan_start']
        l2_vlan_ipv4_start= testscript.parameters['N7K_LEAF_1_dict']['Vlan_data']['l2_vlan_ipv4_start']
        l2_vlan_ipv4_mask= testscript.parameters['N7K_LEAF_1_dict']['Vlan_data']['l2_vlan_ipv4_mask']
        l2_vlan_ipv6_start= testscript.parameters['N7K_LEAF_1_dict']['Vlan_data']['l2_vlan_ipv6_start']
        l2_vlan_ipv6_mask= testscript.parameters['N7K_LEAF_1_dict']['Vlan_data']['l2_vlan_ipv6_mask']
        l2_hsrp_ipv4_vip_start= testscript.parameters['N7K_LEAF_1_dict']['Vlan_data']['hsrp_ipv4_vip_start']
        l2_hsrp_ipv6_vip_start= testscript.parameters['N7K_LEAF_1_dict']['Vlan_data']['hsrp_ipv6_vip_start']
        
        post_test_process_dict = {
            'dut_list'                       : [LEAF_1, LEAF_2, LEAF_3],
            'cc_check'                  : 1,
            'cores_check'               : 1,
            'logs_check'                : 0,
            'fnl_flag'                  : 0,
            'exclude_log_check_pattern' : 'ERROR_VLANS_SUSPENDED|ERROR_VLANS_REMOVED',
            }
        try:
            # UCAST_v4_dict = {
            #                 'mode'        : 'remove',
            #                 'stream_id'   : stream_id,
            #           }
            # if (ixLib.delete_traffic_item(UCAST_v4_dict))==0:
            #     log.debug("Traffic Remove failed")
            #     self.failed("Traffic Remove failed")
            # else:
            #     log.info("Traffic Deletion Passed")
            
            FO_1.configure('''
            interface ''' + str(testscript.parameters['intf_FO_1_to_LEAF_3']) + '''
            shut
            switchport
            switchport mode trunk
            
            interface ''' + str(testscript.parameters['intf_FO_1_to_N7k_LEAF_3']) + '''
            no shut
            switchport
            switchport mode trunk
            ''')
            time.sleep(30)
            ###Remove Pre-migration step from both N7k leafs
            device_handle=connect_to_vdc(testscript.parameters['xbow1'], 'leaf1')
            if device_handle==False:
                log.info("failed to switchto correct vdc")
                self.failed("failed to switchto correct vdc",goto=['common_cleanup'])
            else:
                total_ip_count = int(forwardingSysDict['VLAN_PER_VRF_count']) * int(forwardingSysDict['VRF_count'])
                l2_ipv4s = increment_prefix_network(ip.IPv4Interface(str(l2_vlan_ipv4_start) + str(l2_vlan_ipv4_mask)),total_ip_count)
                l2_ipv6s = increment_prefix_network(ip.IPv6Interface(str(l2_vlan_ipv6_start) + str(l2_vlan_ipv6_mask)),total_ip_count)
                ip_index=0
                for i in range(0,len(l2_ipv4s)):
                    device_handle.configure('''int vlan ''' + str(l2_vlan_id) + '''\n
                                     hsrp version 2
                                     hsrp ''' + str(l2_vlan_id) + ''' ipv4
                                     no mac-address 0000.000a.aaaa
                                     ''')
                    l2_vlan_id += 1
            l2_vlan_id = testscript.parameters['N7K_LEAF_1_dict']['Vlan_data']['l2_vlan_start']        
            device_handle=connect_to_vdc(testscript.parameters['xbow2'], 'leaf2')
            if device_handle==False:
                log.info("failed to switchto correct vdc")
                self.failed("failed to switchto correct vdc",goto=['common_cleanup'])
            else:
                total_ip_count = int(forwardingSysDict['VLAN_PER_VRF_count']) * int(forwardingSysDict['VRF_count'])
                l2_ipv4s = increment_prefix_network(ip.IPv4Interface(str(l2_vlan_ipv4_start) + str(l2_vlan_ipv4_mask)),total_ip_count)
                l2_ipv6s = increment_prefix_network(ip.IPv6Interface(str(l2_vlan_ipv6_start) + str(l2_vlan_ipv6_mask)),total_ip_count)
                ip_index=0
                for i in range(0,len(l2_ipv4s)):
                    device_handle.configure('''int vlan ''' + str(l2_vlan_id) + '''\n
                                     hsrp version 2
                                     hsrp ''' + str(l2_vlan_id) + ''' ipv4
                                     no mac-address 0000.000a.aaaa
                                     ''')
                    l2_vlan_id += 1
            status = infraVerify.postTestVerification(post_test_process_dict)
            if status['status'] == 0:
                self.failed(reason=status['logs'])
            else:
                self.passed(reason=status['logs'])
        except Exception as error:
            log.debug("Unable to unconfigure class map or policy map-Encountered exception " + str(error))
            self.errored('Exception occurred while unconfiguring qos on LEAF1', goto=['next_tc'])
            
# *****************************************************************************************************************************#
class ACLQOS_Restart_pre_Host_move_ipv4(aetest.Testcase):
    """ Host_move_ipv4 """

    
    # =============================================================================================================================#        
    
    @aetest.test
    def SVI_ON_LEAF2(self, testscript):
        """Shut down the vpc leg on Leaf2 to force all traffic to Leaf1"""
        
        LEAF_1 = testscript.parameters['LEAF-1']
        LEAF_2 = testscript.parameters['LEAF-2']
        forwardingSysDict = testscript.parameters['forwardingSysDict']
        l2_vlan_id = testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vlan_start']
        l2_vlan_ipv4_sec_start= testscript.parameters['LEAF_2_dict']['VNI_data']['l2_vlan_ipv4_sec_start']
        l2_vlan_ipv4_mask= testscript.parameters['LEAF_2_dict']['VNI_data']['l2_vlan_ipv4_mask']
        #+ str(testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vlan_ipv4_mask'])
        
        try:
            total_ip_count = int(forwardingSysDict['VLAN_PER_VRF_count']) * int(forwardingSysDict['VRF_count'])
            l2_ipv4s = increment_prefix_network(ip.IPv4Interface(str(l2_vlan_ipv4_sec_start) + str(l2_vlan_ipv4_mask)),total_ip_count)
            ip_index=0
            for i in range(0,len(l2_ipv4s)):
                LEAF_2.configure('''int vlan ''' + str(l2_vlan_id) + '''\n
                                 ip address ''' + str(l2_ipv4s[ip_index]) + ''' secondary use-bia
                                 ''')
                l2_vlan_id += 1
                ip_index += 1
                
            
            
        except Exception as error:
            log.debug("Unable to configure - Encountered Exception " + str(error))
            self.errored('Exception occurred while configuring secondary ipv4 address on LEAF-2', goto=['cleanup'])
            
    # =============================================================================================================================#        
    
    @aetest.test
    def SVI_ON_LEAF1(self, testscript):
        """Shut down the vpc leg on Leaf2 to force all traffic to Leaf1"""
        
        LEAF_1 = testscript.parameters['LEAF-1']
        LEAF_2 = testscript.parameters['LEAF-2']
        forwardingSysDict = testscript.parameters['forwardingSysDict']
        l2_vlan_id = testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vlan_start']
        l2_vlan_ipv4_sec_start= testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vlan_ipv4_sec_start']
        l2_vlan_ipv4_mask= testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vlan_ipv4_mask']
        
        try:
            total_ip_count = int(forwardingSysDict['VLAN_PER_VRF_count']) * int(forwardingSysDict['VRF_count'])
            l2_ipv4s = increment_prefix_network(ip.IPv4Interface(str(l2_vlan_ipv4_sec_start) + str(l2_vlan_ipv4_mask)),total_ip_count)
            ip_index=0
            for i in range(0,len(l2_ipv4s)):
                LEAF_1.configure('''int vlan ''' + str(l2_vlan_id) + '''\n
                                 ip address ''' + str(l2_ipv4s[ip_index]) + ''' secondary use-bia
                                 ''')
                l2_vlan_id += 1
                ip_index += 1
                
            
            
        except Exception as error:
            log.debug("Unable to configure - Encountered Exception " + str(error))
            self.errored('Exception occurred while configuring secondary ipv4 address on LEAF-1', goto=['cleanup'])
            
     # =============================================================================================================================#        
    @aetest.test
    def Add_external_int(self, testscript):
        """Shut down the vpc leg on Leaf2 to force all traffic to Leaf1"""
        
        LEAF_1 = testscript.parameters['LEAF-1']
        LEAF_2 = testscript.parameters['LEAF-2']
        
        try:
            testscript.parameters['LEAF-2'].configure('''
                  interface po ''' + str(testscript.parameters['LEAF_1_dict']['VPC_data']['double_vpc_po_1']) + '''
                  port-type external
                  ''')
            
            testscript.parameters['LEAF-1'].configure('''
                  interface po ''' + str(testscript.parameters['LEAF_1_dict']['VPC_data']['double_vpc_po_1']) + '''
                  port-type external
                  ''')    
            
            
        except Exception as error:
            log.debug("Unable to configure - Encountered Exception " + str(error))
            self.errored('Exception occurred while configuring external on LEAF-1 and LEAF-2', goto=['cleanup'])
            
     # =============================================================================================================================#    
    @aetest.test
    def Pre_migration_hsrp(self,testscript):
        LEAF_1 = testscript.parameters['LEAF-1']
        LEAF_2 = testscript.parameters['LEAF-2']
        forwardingSysDict = testscript.parameters['forwardingSysDict']
        l2_vlan_id = testscript.parameters['N7K_LEAF_1_dict']['Vlan_data']['l2_vlan_start']
        l2_vlan_ipv4_start= testscript.parameters['N7K_LEAF_1_dict']['Vlan_data']['l2_vlan_ipv4_start']
        l2_vlan_ipv4_mask= testscript.parameters['N7K_LEAF_1_dict']['Vlan_data']['l2_vlan_ipv4_mask']
        l2_vlan_ipv6_start= testscript.parameters['N7K_LEAF_1_dict']['Vlan_data']['l2_vlan_ipv6_start']
        l2_vlan_ipv6_mask= testscript.parameters['N7K_LEAF_1_dict']['Vlan_data']['l2_vlan_ipv6_mask']
        l2_hsrp_ipv4_vip_start= testscript.parameters['N7K_LEAF_1_dict']['Vlan_data']['hsrp_ipv4_vip_start']
        l2_hsrp_ipv6_vip_start= testscript.parameters['N7K_LEAF_1_dict']['Vlan_data']['hsrp_ipv6_vip_start']
        
        try:
            device_handle=connect_to_vdc(testscript.parameters['xbow1'], 'leaf1')
            if device_handle==False:
                log.info("failed to switchto correct vdc")
                self.failed("failed to switchto correct vdc",goto=['common_cleanup'])
            else:
                total_ip_count = int(forwardingSysDict['VLAN_PER_VRF_count']) * int(forwardingSysDict['VRF_count'])
                l2_ipv4s = increment_prefix_network(ip.IPv4Interface(str(l2_vlan_ipv4_start) + str(l2_vlan_ipv4_mask)),total_ip_count)
                l2_ipv6s = increment_prefix_network(ip.IPv6Interface(str(l2_vlan_ipv6_start) + str(l2_vlan_ipv6_mask)),total_ip_count)
                ip_index=0
                for i in range(0,len(l2_ipv4s)):
                    device_handle.configure('''int vlan ''' + str(l2_vlan_id) + '''\n
                                     hsrp version 2
                                     hsrp ''' + str(l2_vlan_id) + ''' ipv4
                                     mac-address 0000.000a.aaaa
                                     ''')
                    l2_vlan_id += 1
            l2_vlan_id = testscript.parameters['N7K_LEAF_1_dict']['Vlan_data']['l2_vlan_start']        
            device_handle=connect_to_vdc(testscript.parameters['xbow2'], 'leaf2')
            if device_handle==False:
                log.info("failed to switchto correct vdc")
                self.failed("failed to switchto correct vdc",goto=['common_cleanup'])
            else:
                total_ip_count = int(forwardingSysDict['VLAN_PER_VRF_count']) * int(forwardingSysDict['VRF_count'])
                l2_ipv4s = increment_prefix_network(ip.IPv4Interface(str(l2_vlan_ipv4_start) + str(l2_vlan_ipv4_mask)),total_ip_count)
                l2_ipv6s = increment_prefix_network(ip.IPv6Interface(str(l2_vlan_ipv6_start) + str(l2_vlan_ipv6_mask)),total_ip_count)
                ip_index=0
                for i in range(0,len(l2_ipv4s)):
                    device_handle.configure('''int vlan ''' + str(l2_vlan_id) + '''\n
                                     hsrp version 2
                                     hsrp ''' + str(l2_vlan_id) + ''' ipv4
                                     mac-address 0000.000a.aaaa
                                     ''')
                    l2_vlan_id += 1
                    


        except Exception as error:
                log.debug("Unable to configure - Encountered Exception " + str(error))
                self.errored('Exception occurred while configuring on N7k leaf1', goto=['common_cleanup'])
                
    @aetest.test        
    def configure_FO(self,testscript):
        
        FO_1_vlanConfiguration = ""
        FO_1=testscript.parameters['FO_1']

        l3_vrf_count_iter = 0
        l2_vlan_id = testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vlan_start']
        l3_vlan_id = testscript.parameters['LEAF_1_dict']['VNI_data']['l3_vlan_start']

        while l3_vrf_count_iter < testscript.parameters['forwardingSysDict']['VRF_count']:
            l2_vlan_count_iter = 0
            FO_1_vlanConfiguration += '''vlan ''' + str(l3_vlan_id) + '''\n
                                            state active\n
                                            no shut\n'''
            while l2_vlan_count_iter < testscript.parameters['forwardingSysDict']['VLAN_PER_VRF_count']:
                # Incrementing L2 VLAN Iteration counters
                FO_1_vlanConfiguration += '''vlan ''' + str(l2_vlan_id) + '''\n
                                                state active\n
                                                no shut\n'''
                l2_vlan_count_iter += 1
                l2_vlan_id += 1
            # Incrementing L3 VRF Iteration counters
            l3_vrf_count_iter += 1
            l3_vlan_id += 1

        try:
            FO_1.configure(
                str(FO_1_vlanConfiguration) + '''
        
        
            
            interface ''' + str(testscript.parameters['intf_FO_1_to_N7k_LEAF_3']) + '''
            no shut
            switchport
            switchport mode trunk
            
            interface ''' + str(testscript.parameters['intf_FO_1_to_LEAF_3']) + '''
            shut
            switchport
            switchport mode trunk
            
            interface ''' + str(testscript.parameters['intf_FO_1_to_IXIA']) + '''
            no shut
            switchport
            switchport mode trunk
            
            ''')
        except Exception as error:
                log.debug("Unable to configure - Encountered Exception " + str(error))
                self.errored('Exception occurred while configuring on FO_1', goto=['common_cleanup'])
   
#     @aetest.test
#     def CONFIGURE_UCAST_L3_IXIA_TRAFFIC(self, testscript):
#         """ IXIA_CONFIGURATION subsection: Configure MCAST Traffic Item """
# 
#         # Do not perform configurations if skip_tgen_config flag is set
#         if not testscript.parameters['script_flags']['skip_tgen_config']:
# 
#             IX_TP1 = testscript.parameters['IX_TP1']
#             IX_TP2 = testscript.parameters['IX_TP2']
#             P1_dict = testscript.parameters['LEAF_2_TGEN_dict']
#             P2_dict = testscript.parameters['LEAF_3_TGEN_dict']
# 
#             UCAST_v4_dict = {   'src_hndl'  : IX_TP1['port_handle'],
#                                 'dst_hndl'  : IX_TP2['port_handle'],
#                                 'ip_dscp'   : P1_dict['ip_dscp'],
#                                 'circuit'   : 'raw',
#                                 'TI_name'   : "UCAST_L3",
#                                 'rate_pps'  : "9000",
#                                 'bi_dir'    : 1,
#                                 'frame_size': '128',
#                                 'src_mac'   : P1_dict['mac'],
#                                 'dst_mac'   : '0000.000a.aaaa',
#                                 'srcmac_step': '00:00:00:00:00:00',
#                                 'dstmac_step': '00:00:00:00:00:00',
#                                 'srcmac_count': '1',
#                                 'dstmac_count': '1',
#                                 'vlan_id'    : P1_dict['vlan_id'],
#                                 'vlanid_step': '0',
#                                 'vlanid_count': '1',
#                                 'vlan_user_priority': P1_dict['vlan_user_priority'],
#                                 'ip_src_addrs' : P1_dict['v4_addr'],
#                                 'ip_dst_addrs' : P1_dict['L3_dst_addr'],
#                                 'ip_src_step' : '0.0.0.0',
#                                 'ip_dst_step' : '0.0.0.0',
# #                                'ip_step'    : P1_dict['v4_addr_step'],
#                           }
# 
# #            UCAST_v6_dict = {   'src_hndl'  : IX_TP1['ipv6_handle'],
# #                                'dst_hndl'  : IX_TP2['ipv6_handle'],
# #                                'circuit'   : 'ipv6',
# #                                'TI_name'   : "UCAST_V6",
# #                                'rate_pps'  : "1000",
# #                                'bi_dir'    : 1
# #                          }
# 
#             UCAST_v4_TI = ixLib.configure_ixia_l3_traffic_item(UCAST_v4_dict)
# #            UCAST_v6_TI = ixLib.configure_ixia_traffic_item(UCAST_v6_dict)
# 
# #            if UCAST_v4_TI == 0 or UCAST_v6_TI == 0:
# #                log.debug("Configuring UCast TI failed")
# #                self.errored("Configuring UCast TI failed", goto=['cleanup'])
#                 
#             if UCAST_v4_TI == 0:
#                 log.debug("Configuring UCast TI failed")
#                 self.errored("Configuring UCast TI failed", goto=['cleanup'])
#             else:
#                 global stream_id
#                 stream_id = UCAST_v4_TI
#             
# 
#         else:
#             self.passed(reason="Skipped TGEN Configurations as per request")
            
    # @aetest.test
    # def CONFIGURE_BCAST_IXIA_TRAFFIC(self, testscript):
    #     """ IXIA_CONFIGURATION subsection: Configure MCAST Traffic Item """
    # 
    #     # Do not perform configurations if skip_tgen_config flag is set
    #     if not testscript.parameters['script_flags']['skip_tgen_config']:
    # 
    #         IX_TP1 = testscript.parameters['IX_TP1']
    #         IX_TP2 = testscript.parameters['IX_TP2']
    #         P1_dict = testscript.parameters['LEAF_2_TGEN_dict']
    #         P2_dict = testscript.parameters['LEAF_3_TGEN_dict']
    #         BCAST_v4_dict = {
    #                             'src_hndl'      : IX_TP1['port_handle'],
    #                             'dst_hndl'      : IX_TP2['port_handle'],
    #                             'TI_name'       : "BCAST_V4",
    #                             'frame_size'    : "70",
    #                             'rate_pps'      : "1000",
    #                             'src_mac'       : P1_dict['mac'],
    #                             'srcmac_step'   : "00:00:00:00:00:01",
    #                             'srcmac_count'  : '1',
    #                             'vlan_id'       : P1_dict['vlan_id'],
    #                             'vlanid_step'   : "1",
    #                             'vlanid_count'  : "1",
    #                             'ip_src_addrs'  : P1_dict['v4_addr'],
    #                             'ip_step'       : "0.0.1.0",
    #                       }
    # 
    #         BCAST_v4_TI = ixLib.configure_ixia_BCAST_traffic_item(BCAST_v4_dict)
    # 
    #         if BCAST_v4_TI == 0:
    #             log.debug("Configuring BCast TI failed")
    #             self.errored("Configuring BCast TI failed", goto=['cleanup'])
    #         
    # 
    #     else:
    #         self.passed(reason="Skipped TGEN Configurations as per request")
    # =============================================================================================================================#
    @aetest.test
    def APPLY_TRAFFIC(self):
        """ IXIA_CONFIGURATION subsection: Verify IXIA Traffic """

        # # Apply IXIA Traffic
        # if ixLib.apply_traffic() == 1:
        #     log.info("Applying IXIA TI Passed")
        # else:
        #     self.errored("Applying IXIA TI failed", goto=['cleanup'])
            
        # =============================================================================================================================#
    #--------------------------------------------------------------------------------#
        # Start traffic from ixia
        log.info("--- Populating the statistics --- \n")
        log.info("---- Running Traffic --- \n")
        log.info("Starting Traffic")

        traffic_run_status  = ixLib.start_traffic()

        if traffic_run_status is not 1:
           log.info("Failed: To start traffic")
           return 0
        else:
            log.info("\nTraffic started successfully\n")

        time.sleep(30)
    
    # Stop Traffic from ixia
        log.info("--- Stopping Traffic ---- \n")
        log.info("Stopping Traffic")
        traffic_run_status = ixLib.stop_traffic()
        
        if traffic_run_status is not 1:
           log.info("Failed: To Stop traffic")
           return 0
        else:
            log.info("\nTraffic Stopped successfully\n")
            time.sleep(10)    
    
    @aetest.test
    def VERIFY_IXIA_TRAFFIC(self, testscript):
        """ IXIA_CONFIGURATION subsection: Verify IXIA Traffic """

        # Do not perform configurations if skip_tgen_config flag is set
        if not testscript.parameters['script_flags']['skip_tgen_config']:

            time.sleep(20)

            if ixLib.verify_traffic(2) == 0:
                log.debug("Traffic Verification failed")
                self.failed("Traffic Verification failed", goto=['cleanup'])
            else:
                log.info("Traffic Verification Passed")
        else:
            self.passed(reason="Skipped TGEN Configurations as per request")
# =============================================================================================================================#
    @aetest.test
    def TRIGGER_verify_aclqos_process_restart(self, testscript):
        """ ACLQOS_PROCESS_KILL_VERIFICATION subsection: Verify killing process ACLQOS """

        LEAF_1 = testscript.parameters['LEAF-1']
        LEAF_2 = testscript.parameters['LEAF-2']

        if infraTrig.verifyProcessRestart(LEAF_1,"aclqos"):
            log.info("Successfully restarted process aclqos on Leaf1")
        else:
            log.debug("Failed to restarted process aclqos on Leaf1")
            self.failed("Failed to restarted process aclqos on Leaf1", goto=['cleanup'])
            
        if infraTrig.verifyProcessRestart(LEAF_2,"aclqos"):
            log.info("Successfully restarted process aclqos on Leaf2")
        else:
            log.debug("Failed to restarted process aclqos on Leaf2")
            self.failed("Failed to restarted process aclqos on Leaf2", goto=['cleanup'])

        time.sleep(120)
    
    @aetest.test
    def VERIFY_IXIA_TRAFFIC_AFTER_ACLQOS_RESTART(self, testscript):
        """ IXIA_CONFIGURATION subsection: Verify IXIA Traffic """

        # Do not perform configurations if skip_tgen_config flag is set
        if not testscript.parameters['script_flags']['skip_tgen_config']:

            time.sleep(20)

            if ixLib.verify_traffic(2) == 0:
                log.debug("Traffic Verification failed")
                self.failed("Traffic Verification failed", goto=['cleanup'])
            else:
                log.info("Traffic Verification Passed")
        else:
            self.passed(reason="Skipped TGEN Configurations as per request")
     # =============================================================================================================================#        
    @aetest.test
    def Clear_ARP_Table_on_Vxlan_BLs(self, testscript):
        """Shut down the vpc leg on Leaf2 to force all traffic to Leaf1"""
        
        LEAF_1 = testscript.parameters['LEAF-1']
        LEAF_2 = testscript.parameters['LEAF-2']
        
        try:
            for i in range(1, testscript.parameters['forwardingSysDict']['VRF_count']+1):
                testscript.parameters['LEAF-2'].execute('''
                      clear ip arp vrf ''' + str(testscript.parameters['forwardingSysDict']['VRF_string']) + str(i) + ''' force-delete''')
            
            for i in range(1, testscript.parameters['forwardingSysDict']['VRF_count']+1):
                testscript.parameters['LEAF-1'].execute('''
                      clear ip arp vrf ''' + str(testscript.parameters['forwardingSysDict']['VRF_string']) + str(i) + ''' force-delete''')    
            
            
        except Exception as error:
            log.debug("Unable to configure - Encountered Exception " + str(error))
            self.errored('Exception occurred while clearing arp cache on LEAF-1 and LEAF-2', goto=['cleanup'])
            
    @aetest.test        
    def Host_move_FO(self,testscript):
        
        
        FO_1=testscript.parameters['FO_1']

        
        try:
            FO_1.configure('''
            interface ''' + str(testscript.parameters['intf_FO_1_to_N7k_LEAF_3']) + '''
            shut
            switchport
            switchport mode trunk
            
            interface ''' + str(testscript.parameters['intf_FO_1_to_LEAF_3']) + '''
            no shut
            switchport
            switchport mode trunk
            
            ''')
            time.sleep(45)
            #ForkedPdb().set_trace()
        except Exception as error:
                log.debug("Unable to configure - Encountered Exception " + str(error))
                self.errored('Exception occurred while configuring on FO_1', goto=['common_cleanup'])
                
    @aetest.test
    def VERIFY_IXIA_TRAFFIC_AFTER_MOVE(self, testscript):
        """ IXIA_CONFIGURATION subsection: Verify IXIA Traffic """

        # Do not perform configurations if skip_tgen_config flag is set
        if not testscript.parameters['script_flags']['skip_tgen_config']:

            time.sleep(20)

            if ixLib.verify_traffic(15) == 0:
                log.debug("Traffic Verification failed")
                self.failed("Traffic Verification failed", goto=['cleanup'])
            else:
                log.info("Traffic Verification Passed")
            
        else:
            self.passed(reason="Skipped TGEN Configurations as per request")
            
    @aetest.test        
    def Host_move_FO_BACK(self,testscript):
        
        
        FO_1=testscript.parameters['FO_1']

        
        try:
            FO_1.configure('''
            interface ''' + str(testscript.parameters['intf_FO_1_to_LEAF_3']) + '''
            shut
            switchport
            switchport mode trunk
            
            interface ''' + str(testscript.parameters['intf_FO_1_to_N7k_LEAF_3']) + '''
            no shut
            switchport
            switchport mode trunk
            
            
            
            ''')
            time.sleep(45)
        except Exception as error:
                log.debug("Unable to configure - Encountered Exception " + str(error))
                self.errored('Exception occurred while configuring on FO_1', goto=['common_cleanup'])
                
    @aetest.test
    def VERIFY_IXIA_TRAFFIC_HOST_MOVE_BACK(self, testscript):
        """ IXIA_CONFIGURATION subsection: Verify IXIA Traffic """

        # Do not perform configurations if skip_tgen_config flag is set
        if not testscript.parameters['script_flags']['skip_tgen_config']:

            time.sleep(20)

            if ixLib.verify_traffic(15) == 0:
                log.debug("Traffic Verification failed")
                self.failed("Traffic Verification failed", goto=['cleanup'])
            else:
                log.info("Traffic Verification Passed")
        else:
            self.passed(reason="Skipped TGEN Configurations as per request")
        
    @aetest.cleanup
    def cleanup(self,testscript):
        """Unconfigure qos policies"""
        LEAF_1 = testscript.parameters['LEAF-1']
        LEAF_2 = testscript.parameters['LEAF-2']
        LEAF_3 = testscript.parameters['LEAF-3']
        FO_1=testscript.parameters['FO_1']
        LEAF_1 = testscript.parameters['LEAF-1']
        LEAF_2 = testscript.parameters['LEAF-2']
        forwardingSysDict = testscript.parameters['forwardingSysDict']
        l2_vlan_id = testscript.parameters['N7K_LEAF_1_dict']['Vlan_data']['l2_vlan_start']
        l2_vlan_ipv4_start= testscript.parameters['N7K_LEAF_1_dict']['Vlan_data']['l2_vlan_ipv4_start']
        l2_vlan_ipv4_mask= testscript.parameters['N7K_LEAF_1_dict']['Vlan_data']['l2_vlan_ipv4_mask']
        l2_vlan_ipv6_start= testscript.parameters['N7K_LEAF_1_dict']['Vlan_data']['l2_vlan_ipv6_start']
        l2_vlan_ipv6_mask= testscript.parameters['N7K_LEAF_1_dict']['Vlan_data']['l2_vlan_ipv6_mask']
        l2_hsrp_ipv4_vip_start= testscript.parameters['N7K_LEAF_1_dict']['Vlan_data']['hsrp_ipv4_vip_start']
        l2_hsrp_ipv6_vip_start= testscript.parameters['N7K_LEAF_1_dict']['Vlan_data']['hsrp_ipv6_vip_start']
        
        post_test_process_dict = {
            'dut_list'                       : [LEAF_1, LEAF_2, LEAF_3],
            'cc_check'                  : 1,
            'cores_check'               : 1,
            'logs_check'                : 0,
            'fnl_flag'                  : 0,
            'exclude_log_check_pattern' : 'ERROR_VLANS_SUSPENDED|ERROR_VLANS_REMOVED',
            }
        try:
            # UCAST_v4_dict = {
            #                 'mode'        : 'remove',
            #                 'stream_id'   : stream_id,
            #           }
            # if (ixLib.delete_traffic_item(UCAST_v4_dict))==0:
            #     log.debug("Traffic Remove failed")
            #     self.failed("Traffic Remove failed")
            # else:
            #     log.info("Traffic Deletion Passed")
            
            FO_1.configure('''
            interface ''' + str(testscript.parameters['intf_FO_1_to_LEAF_3']) + '''
            shut
            switchport
            switchport mode trunk
            
            interface ''' + str(testscript.parameters['intf_FO_1_to_N7k_LEAF_3']) + '''
            no shut
            switchport
            switchport mode trunk
            ''')
            time.sleep(30)
            ###Remove Pre-migration step from both N7k leafs
            device_handle=connect_to_vdc(testscript.parameters['xbow1'], 'leaf1')
            if device_handle==False:
                log.info("failed to switchto correct vdc")
                self.failed("failed to switchto correct vdc",goto=['common_cleanup'])
            else:
                total_ip_count = int(forwardingSysDict['VLAN_PER_VRF_count']) * int(forwardingSysDict['VRF_count'])
                l2_ipv4s = increment_prefix_network(ip.IPv4Interface(str(l2_vlan_ipv4_start) + str(l2_vlan_ipv4_mask)),total_ip_count)
                l2_ipv6s = increment_prefix_network(ip.IPv6Interface(str(l2_vlan_ipv6_start) + str(l2_vlan_ipv6_mask)),total_ip_count)
                ip_index=0
                for i in range(0,len(l2_ipv4s)):
                    device_handle.configure('''int vlan ''' + str(l2_vlan_id) + '''\n
                                     hsrp version 2
                                     hsrp ''' + str(l2_vlan_id) + ''' ipv4
                                     no mac-address 0000.000a.aaaa
                                     ''')
                    l2_vlan_id += 1
            l2_vlan_id = testscript.parameters['N7K_LEAF_1_dict']['Vlan_data']['l2_vlan_start']        
            device_handle=connect_to_vdc(testscript.parameters['xbow2'], 'leaf2')
            if device_handle==False:
                log.info("failed to switchto correct vdc")
                self.failed("failed to switchto correct vdc",goto=['common_cleanup'])
            else:
                total_ip_count = int(forwardingSysDict['VLAN_PER_VRF_count']) * int(forwardingSysDict['VRF_count'])
                l2_ipv4s = increment_prefix_network(ip.IPv4Interface(str(l2_vlan_ipv4_start) + str(l2_vlan_ipv4_mask)),total_ip_count)
                l2_ipv6s = increment_prefix_network(ip.IPv6Interface(str(l2_vlan_ipv6_start) + str(l2_vlan_ipv6_mask)),total_ip_count)
                ip_index=0
                for i in range(0,len(l2_ipv4s)):
                    device_handle.configure('''int vlan ''' + str(l2_vlan_id) + '''\n
                                     hsrp version 2
                                     hsrp ''' + str(l2_vlan_id) + ''' ipv4
                                     no mac-address 0000.000a.aaaa
                                     ''')
                    l2_vlan_id += 1
            status = infraVerify.postTestVerification(post_test_process_dict)
            if status['status'] == 0:
                self.failed(reason=status['logs'])
            else:
                self.passed(reason=status['logs'])
        except Exception as error:
            log.debug("Unable to unconfigure class map or policy map-Encountered exception " + str(error))
            self.errored('Exception occurred while unconfiguring qos on LEAF1', goto=['next_tc'])
            
            
# *****************************************************************************************************************************#
class VPC_Restart_pre_Host_move_ipv4(aetest.Testcase):
    """ Host_move_ipv4 """

    
    # =============================================================================================================================#        
    
    @aetest.test
    def SVI_ON_LEAF2(self, testscript):
        """Shut down the vpc leg on Leaf2 to force all traffic to Leaf1"""
        
        LEAF_1 = testscript.parameters['LEAF-1']
        LEAF_2 = testscript.parameters['LEAF-2']
        forwardingSysDict = testscript.parameters['forwardingSysDict']
        l2_vlan_id = testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vlan_start']
        l2_vlan_ipv4_sec_start= testscript.parameters['LEAF_2_dict']['VNI_data']['l2_vlan_ipv4_sec_start']
        l2_vlan_ipv4_mask= testscript.parameters['LEAF_2_dict']['VNI_data']['l2_vlan_ipv4_mask']
        #+ str(testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vlan_ipv4_mask'])
        
        try:
            total_ip_count = int(forwardingSysDict['VLAN_PER_VRF_count']) * int(forwardingSysDict['VRF_count'])
            l2_ipv4s = increment_prefix_network(ip.IPv4Interface(str(l2_vlan_ipv4_sec_start) + str(l2_vlan_ipv4_mask)),total_ip_count)
            ip_index=0
            for i in range(0,len(l2_ipv4s)):
                LEAF_2.configure('''int vlan ''' + str(l2_vlan_id) + '''\n
                                 ip address ''' + str(l2_ipv4s[ip_index]) + ''' secondary use-bia
                                 ''')
                l2_vlan_id += 1
                ip_index += 1
                
            
            
        except Exception as error:
            log.debug("Unable to configure - Encountered Exception " + str(error))
            self.errored('Exception occurred while configuring secondary ipv4 address on LEAF-2', goto=['cleanup'])
            
    # =============================================================================================================================#        
    
    @aetest.test
    def SVI_ON_LEAF1(self, testscript):
        """Shut down the vpc leg on Leaf2 to force all traffic to Leaf1"""
        
        LEAF_1 = testscript.parameters['LEAF-1']
        LEAF_2 = testscript.parameters['LEAF-2']
        forwardingSysDict = testscript.parameters['forwardingSysDict']
        l2_vlan_id = testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vlan_start']
        l2_vlan_ipv4_sec_start= testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vlan_ipv4_sec_start']
        l2_vlan_ipv4_mask= testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vlan_ipv4_mask']
        
        try:
            total_ip_count = int(forwardingSysDict['VLAN_PER_VRF_count']) * int(forwardingSysDict['VRF_count'])
            l2_ipv4s = increment_prefix_network(ip.IPv4Interface(str(l2_vlan_ipv4_sec_start) + str(l2_vlan_ipv4_mask)),total_ip_count)
            ip_index=0
            for i in range(0,len(l2_ipv4s)):
                LEAF_1.configure('''int vlan ''' + str(l2_vlan_id) + '''\n
                                 ip address ''' + str(l2_ipv4s[ip_index]) + ''' secondary use-bia
                                 ''')
                l2_vlan_id += 1
                ip_index += 1
                
            
            
        except Exception as error:
            log.debug("Unable to configure - Encountered Exception " + str(error))
            self.errored('Exception occurred while configuring secondary ipv4 address on LEAF-1', goto=['cleanup'])
            
     # =============================================================================================================================#        
    @aetest.test
    def Add_external_int(self, testscript):
        """Shut down the vpc leg on Leaf2 to force all traffic to Leaf1"""
        
        LEAF_1 = testscript.parameters['LEAF-1']
        LEAF_2 = testscript.parameters['LEAF-2']
        
        try:
            testscript.parameters['LEAF-2'].configure('''
                  interface po ''' + str(testscript.parameters['LEAF_1_dict']['VPC_data']['double_vpc_po_1']) + '''
                  port-type external
                  ''')
            
            testscript.parameters['LEAF-1'].configure('''
                  interface po ''' + str(testscript.parameters['LEAF_1_dict']['VPC_data']['double_vpc_po_1']) + '''
                  port-type external
                  ''')    
            
            
        except Exception as error:
            log.debug("Unable to configure - Encountered Exception " + str(error))
            self.errored('Exception occurred while configuring external on LEAF-1 and LEAF-2', goto=['cleanup'])
            
     # =============================================================================================================================#    
    @aetest.test
    def Pre_migration_hsrp(self,testscript):
        LEAF_1 = testscript.parameters['LEAF-1']
        LEAF_2 = testscript.parameters['LEAF-2']
        forwardingSysDict = testscript.parameters['forwardingSysDict']
        l2_vlan_id = testscript.parameters['N7K_LEAF_1_dict']['Vlan_data']['l2_vlan_start']
        l2_vlan_ipv4_start= testscript.parameters['N7K_LEAF_1_dict']['Vlan_data']['l2_vlan_ipv4_start']
        l2_vlan_ipv4_mask= testscript.parameters['N7K_LEAF_1_dict']['Vlan_data']['l2_vlan_ipv4_mask']
        l2_vlan_ipv6_start= testscript.parameters['N7K_LEAF_1_dict']['Vlan_data']['l2_vlan_ipv6_start']
        l2_vlan_ipv6_mask= testscript.parameters['N7K_LEAF_1_dict']['Vlan_data']['l2_vlan_ipv6_mask']
        l2_hsrp_ipv4_vip_start= testscript.parameters['N7K_LEAF_1_dict']['Vlan_data']['hsrp_ipv4_vip_start']
        l2_hsrp_ipv6_vip_start= testscript.parameters['N7K_LEAF_1_dict']['Vlan_data']['hsrp_ipv6_vip_start']
        
        try:
            device_handle=connect_to_vdc(testscript.parameters['xbow1'], 'leaf1')
            if device_handle==False:
                log.info("failed to switchto correct vdc")
                self.failed("failed to switchto correct vdc",goto=['common_cleanup'])
            else:
                total_ip_count = int(forwardingSysDict['VLAN_PER_VRF_count']) * int(forwardingSysDict['VRF_count'])
                l2_ipv4s = increment_prefix_network(ip.IPv4Interface(str(l2_vlan_ipv4_start) + str(l2_vlan_ipv4_mask)),total_ip_count)
                l2_ipv6s = increment_prefix_network(ip.IPv6Interface(str(l2_vlan_ipv6_start) + str(l2_vlan_ipv6_mask)),total_ip_count)
                ip_index=0
                for i in range(0,len(l2_ipv4s)):
                    device_handle.configure('''int vlan ''' + str(l2_vlan_id) + '''\n
                                     hsrp version 2
                                     hsrp ''' + str(l2_vlan_id) + ''' ipv4
                                     mac-address 0000.000a.aaaa
                                     ''')
                    l2_vlan_id += 1
            l2_vlan_id = testscript.parameters['N7K_LEAF_1_dict']['Vlan_data']['l2_vlan_start']        
            device_handle=connect_to_vdc(testscript.parameters['xbow2'], 'leaf2')
            if device_handle==False:
                log.info("failed to switchto correct vdc")
                self.failed("failed to switchto correct vdc",goto=['common_cleanup'])
            else:
                total_ip_count = int(forwardingSysDict['VLAN_PER_VRF_count']) * int(forwardingSysDict['VRF_count'])
                l2_ipv4s = increment_prefix_network(ip.IPv4Interface(str(l2_vlan_ipv4_start) + str(l2_vlan_ipv4_mask)),total_ip_count)
                l2_ipv6s = increment_prefix_network(ip.IPv6Interface(str(l2_vlan_ipv6_start) + str(l2_vlan_ipv6_mask)),total_ip_count)
                ip_index=0
                for i in range(0,len(l2_ipv4s)):
                    device_handle.configure('''int vlan ''' + str(l2_vlan_id) + '''\n
                                     hsrp version 2
                                     hsrp ''' + str(l2_vlan_id) + ''' ipv4
                                     mac-address 0000.000a.aaaa
                                     ''')
                    l2_vlan_id += 1
                    


        except Exception as error:
                log.debug("Unable to configure - Encountered Exception " + str(error))
                self.errored('Exception occurred while configuring on N7k leaf1', goto=['common_cleanup'])
                
    @aetest.test        
    def configure_FO(self,testscript):
        
        FO_1_vlanConfiguration = ""
        FO_1=testscript.parameters['FO_1']

        l3_vrf_count_iter = 0
        l2_vlan_id = testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vlan_start']
        l3_vlan_id = testscript.parameters['LEAF_1_dict']['VNI_data']['l3_vlan_start']

        while l3_vrf_count_iter < testscript.parameters['forwardingSysDict']['VRF_count']:
            l2_vlan_count_iter = 0
            FO_1_vlanConfiguration += '''vlan ''' + str(l3_vlan_id) + '''\n
                                            state active\n
                                            no shut\n'''
            while l2_vlan_count_iter < testscript.parameters['forwardingSysDict']['VLAN_PER_VRF_count']:
                # Incrementing L2 VLAN Iteration counters
                FO_1_vlanConfiguration += '''vlan ''' + str(l2_vlan_id) + '''\n
                                                state active\n
                                                no shut\n'''
                l2_vlan_count_iter += 1
                l2_vlan_id += 1
            # Incrementing L3 VRF Iteration counters
            l3_vrf_count_iter += 1
            l3_vlan_id += 1

        try:
            FO_1.configure(
                str(FO_1_vlanConfiguration) + '''
        
        
            
            interface ''' + str(testscript.parameters['intf_FO_1_to_N7k_LEAF_3']) + '''
            no shut
            switchport
            switchport mode trunk
            
            interface ''' + str(testscript.parameters['intf_FO_1_to_LEAF_3']) + '''
            shut
            switchport
            switchport mode trunk
            
            interface ''' + str(testscript.parameters['intf_FO_1_to_IXIA']) + '''
            no shut
            switchport
            switchport mode trunk
            
            ''')
        except Exception as error:
                log.debug("Unable to configure - Encountered Exception " + str(error))
                self.errored('Exception occurred while configuring on FO_1', goto=['common_cleanup'])
   
#     @aetest.test
#     def CONFIGURE_UCAST_L3_IXIA_TRAFFIC(self, testscript):
#         """ IXIA_CONFIGURATION subsection: Configure MCAST Traffic Item """
# 
#         # Do not perform configurations if skip_tgen_config flag is set
#         if not testscript.parameters['script_flags']['skip_tgen_config']:
# 
#             IX_TP1 = testscript.parameters['IX_TP1']
#             IX_TP2 = testscript.parameters['IX_TP2']
#             P1_dict = testscript.parameters['LEAF_2_TGEN_dict']
#             P2_dict = testscript.parameters['LEAF_3_TGEN_dict']
# 
#             UCAST_v4_dict = {   'src_hndl'  : IX_TP1['port_handle'],
#                                 'dst_hndl'  : IX_TP2['port_handle'],
#                                 'ip_dscp'   : P1_dict['ip_dscp'],
#                                 'circuit'   : 'raw',
#                                 'TI_name'   : "UCAST_L3",
#                                 'rate_pps'  : "9000",
#                                 'bi_dir'    : 1,
#                                 'frame_size': '128',
#                                 'src_mac'   : P1_dict['mac'],
#                                 'dst_mac'   : '0000.000a.aaaa',
#                                 'srcmac_step': '00:00:00:00:00:00',
#                                 'dstmac_step': '00:00:00:00:00:00',
#                                 'srcmac_count': '1',
#                                 'dstmac_count': '1',
#                                 'vlan_id'    : P1_dict['vlan_id'],
#                                 'vlanid_step': '0',
#                                 'vlanid_count': '1',
#                                 'vlan_user_priority': P1_dict['vlan_user_priority'],
#                                 'ip_src_addrs' : P1_dict['v4_addr'],
#                                 'ip_dst_addrs' : P1_dict['L3_dst_addr'],
#                                 'ip_src_step' : '0.0.0.0',
#                                 'ip_dst_step' : '0.0.0.0',
# #                                'ip_step'    : P1_dict['v4_addr_step'],
#                           }
# 
# #            UCAST_v6_dict = {   'src_hndl'  : IX_TP1['ipv6_handle'],
# #                                'dst_hndl'  : IX_TP2['ipv6_handle'],
# #                                'circuit'   : 'ipv6',
# #                                'TI_name'   : "UCAST_V6",
# #                                'rate_pps'  : "1000",
# #                                'bi_dir'    : 1
# #                          }
# 
#             UCAST_v4_TI = ixLib.configure_ixia_l3_traffic_item(UCAST_v4_dict)
# #            UCAST_v6_TI = ixLib.configure_ixia_traffic_item(UCAST_v6_dict)
# 
# #            if UCAST_v4_TI == 0 or UCAST_v6_TI == 0:
# #                log.debug("Configuring UCast TI failed")
# #                self.errored("Configuring UCast TI failed", goto=['cleanup'])
#                 
#             if UCAST_v4_TI == 0:
#                 log.debug("Configuring UCast TI failed")
#                 self.errored("Configuring UCast TI failed", goto=['cleanup'])
#             else:
#                 global stream_id
#                 stream_id = UCAST_v4_TI
#             
# 
#         else:
#             self.passed(reason="Skipped TGEN Configurations as per request")
            
    # @aetest.test
    # def CONFIGURE_BCAST_IXIA_TRAFFIC(self, testscript):
    #     """ IXIA_CONFIGURATION subsection: Configure MCAST Traffic Item """
    # 
    #     # Do not perform configurations if skip_tgen_config flag is set
    #     if not testscript.parameters['script_flags']['skip_tgen_config']:
    # 
    #         IX_TP1 = testscript.parameters['IX_TP1']
    #         IX_TP2 = testscript.parameters['IX_TP2']
    #         P1_dict = testscript.parameters['LEAF_2_TGEN_dict']
    #         P2_dict = testscript.parameters['LEAF_3_TGEN_dict']
    #         BCAST_v4_dict = {
    #                             'src_hndl'      : IX_TP1['port_handle'],
    #                             'dst_hndl'      : IX_TP2['port_handle'],
    #                             'TI_name'       : "BCAST_V4",
    #                             'frame_size'    : "70",
    #                             'rate_pps'      : "1000",
    #                             'src_mac'       : P1_dict['mac'],
    #                             'srcmac_step'   : "00:00:00:00:00:01",
    #                             'srcmac_count'  : '1',
    #                             'vlan_id'       : P1_dict['vlan_id'],
    #                             'vlanid_step'   : "1",
    #                             'vlanid_count'  : "1",
    #                             'ip_src_addrs'  : P1_dict['v4_addr'],
    #                             'ip_step'       : "0.0.1.0",
    #                       }
    # 
    #         BCAST_v4_TI = ixLib.configure_ixia_BCAST_traffic_item(BCAST_v4_dict)
    # 
    #         if BCAST_v4_TI == 0:
    #             log.debug("Configuring BCast TI failed")
    #             self.errored("Configuring BCast TI failed", goto=['cleanup'])
    #         
    # 
    #     else:
    #         self.passed(reason="Skipped TGEN Configurations as per request")
    # =============================================================================================================================#
    @aetest.test
    def APPLY_TRAFFIC(self):
        """ IXIA_CONFIGURATION subsection: Verify IXIA Traffic """
    # 
    #     # Apply IXIA Traffic
    #     if ixLib.apply_traffic() == 1:
    #         log.info("Applying IXIA TI Passed")
    #     else:
    #         self.errored("Applying IXIA TI failed", goto=['cleanup'])
            
        # =============================================================================================================================#
    #--------------------------------------------------------------------------------#
        # Start traffic from ixia
        log.info("--- Populating the statistics --- \n")
        log.info("---- Running Traffic --- \n")
        log.info("Starting Traffic")

        traffic_run_status  = ixLib.start_traffic()

        if traffic_run_status is not 1:
           log.info("Failed: To start traffic")
           return 0
        else:
            log.info("\nTraffic started successfully\n")

        time.sleep(30)
    
    # Stop Traffic from ixia
        log.info("--- Stopping Traffic ---- \n")
        log.info("Stopping Traffic")
        traffic_run_status = ixLib.stop_traffic()
        
        if traffic_run_status is not 1:
           log.info("Failed: To Stop traffic")
           return 0
        else:
            log.info("\nTraffic Stopped successfully\n")
            time.sleep(10)    
    
    @aetest.test
    def VERIFY_IXIA_TRAFFIC(self, testscript):
        """ IXIA_CONFIGURATION subsection: Verify IXIA Traffic """

        # Do not perform configurations if skip_tgen_config flag is set
        if not testscript.parameters['script_flags']['skip_tgen_config']:

            time.sleep(20)

            if ixLib.verify_traffic(2) == 0:
                log.debug("Traffic Verification failed")
                self.failed("Traffic Verification failed", goto=['cleanup'])
            else:
                log.info("Traffic Verification Passed")
        else:
            self.passed(reason="Skipped TGEN Configurations as per request")
# =============================================================================================================================#
    @aetest.test
    def TRIGGER_verify_vpc_process_restart(self, testscript):
        """ ACLQOS_PROCESS_KILL_VERIFICATION subsection: Verify killing process ACLQOS """

        LEAF_1 = testscript.parameters['LEAF-1']
        LEAF_2 = testscript.parameters['LEAF-2']

        if infraTrig.verifyProcessRestart(LEAF_1,"vpc"):
            log.info("Successfully restarted process vpc on Leaf1")
        else:
            log.debug("Failed to restarted process vpc on Leaf1")
            self.failed("Failed to restarted process vpc on Leaf1", goto=['cleanup'])
            
        if infraTrig.verifyProcessRestart(LEAF_2,"vpc"):
            log.info("Successfully restarted process vpc on Leaf2")
        else:
            log.debug("Failed to restarted process vpc on Leaf2")
            self.failed("Failed to restarted process vpc on Leaf2", goto=['cleanup'])

        time.sleep(120)
    
    @aetest.test
    def VERIFY_IXIA_TRAFFIC_AFTER_VPC_RESTART(self, testscript):
        """ IXIA_CONFIGURATION subsection: Verify IXIA Traffic """

        # Do not perform configurations if skip_tgen_config flag is set
        if not testscript.parameters['script_flags']['skip_tgen_config']:

            time.sleep(20)

            if ixLib.verify_traffic(2) == 0:
                log.debug("Traffic Verification failed")
                self.failed("Traffic Verification failed", goto=['cleanup'])
            else:
                log.info("Traffic Verification Passed")
        else:
            self.passed(reason="Skipped TGEN Configurations as per request")
     # =============================================================================================================================#        
    @aetest.test
    def Clear_ARP_Table_on_Vxlan_BLs(self, testscript):
        """Shut down the vpc leg on Leaf2 to force all traffic to Leaf1"""
        
        LEAF_1 = testscript.parameters['LEAF-1']
        LEAF_2 = testscript.parameters['LEAF-2']
        
        try:
            for i in range(1, testscript.parameters['forwardingSysDict']['VRF_count']+1):
                testscript.parameters['LEAF-2'].execute('''
                      clear ip arp vrf ''' + str(testscript.parameters['forwardingSysDict']['VRF_string']) + str(i) + ''' force-delete''')
            
            for i in range(1, testscript.parameters['forwardingSysDict']['VRF_count']+1):
                testscript.parameters['LEAF-1'].execute('''
                      clear ip arp vrf ''' + str(testscript.parameters['forwardingSysDict']['VRF_string']) + str(i) + ''' force-delete''')    
            
            
        except Exception as error:
            log.debug("Unable to configure - Encountered Exception " + str(error))
            self.errored('Exception occurred while clearing arp cache on LEAF-1 and LEAF-2', goto=['cleanup'])
            
    @aetest.test        
    def Host_move_FO(self,testscript):
        
        
        FO_1=testscript.parameters['FO_1']

        
        try:
            FO_1.configure('''
            interface ''' + str(testscript.parameters['intf_FO_1_to_N7k_LEAF_3']) + '''
            shut
            switchport
            switchport mode trunk
            
            interface ''' + str(testscript.parameters['intf_FO_1_to_LEAF_3']) + '''
            no shut
            switchport
            switchport mode trunk
            
            ''')
            time.sleep(45)
            #ForkedPdb().set_trace()
        except Exception as error:
                log.debug("Unable to configure - Encountered Exception " + str(error))
                self.errored('Exception occurred while configuring on FO_1', goto=['common_cleanup'])
                
    @aetest.test
    def VERIFY_IXIA_TRAFFIC_AFTER_MOVE(self, testscript):
        """ IXIA_CONFIGURATION subsection: Verify IXIA Traffic """

        # Do not perform configurations if skip_tgen_config flag is set
        if not testscript.parameters['script_flags']['skip_tgen_config']:

            time.sleep(20)

            if ixLib.verify_traffic(15) == 0:
                log.debug("Traffic Verification failed")
                self.failed("Traffic Verification failed", goto=['cleanup'])
            else:
                log.info("Traffic Verification Passed")
            
        else:
            self.passed(reason="Skipped TGEN Configurations as per request")
            
    @aetest.test        
    def Host_move_FO_BACK(self,testscript):
        
        
        FO_1=testscript.parameters['FO_1']

        
        try:
            FO_1.configure('''
            interface ''' + str(testscript.parameters['intf_FO_1_to_LEAF_3']) + '''
            shut
            switchport
            switchport mode trunk
            
            interface ''' + str(testscript.parameters['intf_FO_1_to_N7k_LEAF_3']) + '''
            no shut
            switchport
            switchport mode trunk
            
            
            
            ''')
            time.sleep(45)
        except Exception as error:
                log.debug("Unable to configure - Encountered Exception " + str(error))
                self.errored('Exception occurred while configuring on FO_1', goto=['common_cleanup'])
                
    @aetest.test
    def VERIFY_IXIA_TRAFFIC_HOST_MOVE_BACK(self, testscript):
        """ IXIA_CONFIGURATION subsection: Verify IXIA Traffic """

        # Do not perform configurations if skip_tgen_config flag is set
        if not testscript.parameters['script_flags']['skip_tgen_config']:

            time.sleep(20)

            if ixLib.verify_traffic(15) == 0:
                log.debug("Traffic Verification failed")
                self.failed("Traffic Verification failed", goto=['cleanup'])
            else:
                log.info("Traffic Verification Passed")
        else:
            self.passed(reason="Skipped TGEN Configurations as per request")
        
    @aetest.cleanup
    def cleanup(self,testscript):
        """Unconfigure qos policies"""
        LEAF_1 = testscript.parameters['LEAF-1']
        LEAF_2 = testscript.parameters['LEAF-2']
        LEAF_3 = testscript.parameters['LEAF-3']
        FO_1=testscript.parameters['FO_1']
        LEAF_1 = testscript.parameters['LEAF-1']
        LEAF_2 = testscript.parameters['LEAF-2']
        forwardingSysDict = testscript.parameters['forwardingSysDict']
        l2_vlan_id = testscript.parameters['N7K_LEAF_1_dict']['Vlan_data']['l2_vlan_start']
        l2_vlan_ipv4_start= testscript.parameters['N7K_LEAF_1_dict']['Vlan_data']['l2_vlan_ipv4_start']
        l2_vlan_ipv4_mask= testscript.parameters['N7K_LEAF_1_dict']['Vlan_data']['l2_vlan_ipv4_mask']
        l2_vlan_ipv6_start= testscript.parameters['N7K_LEAF_1_dict']['Vlan_data']['l2_vlan_ipv6_start']
        l2_vlan_ipv6_mask= testscript.parameters['N7K_LEAF_1_dict']['Vlan_data']['l2_vlan_ipv6_mask']
        l2_hsrp_ipv4_vip_start= testscript.parameters['N7K_LEAF_1_dict']['Vlan_data']['hsrp_ipv4_vip_start']
        l2_hsrp_ipv6_vip_start= testscript.parameters['N7K_LEAF_1_dict']['Vlan_data']['hsrp_ipv6_vip_start']
        
        post_test_process_dict = {
            'dut_list'                       : [LEAF_1, LEAF_2, LEAF_3],
            'cc_check'                  : 1,
            'cores_check'               : 1,
            'logs_check'                : 0,
            'fnl_flag'                  : 0,
            'exclude_log_check_pattern' : 'ERROR_VLANS_SUSPENDED|ERROR_VLANS_REMOVED',
            }
        try:
            # UCAST_v4_dict = {
            #                 'mode'        : 'remove',
            #                 'stream_id'   : stream_id,
            #           }
            # if (ixLib.delete_traffic_item(UCAST_v4_dict))==0:
            #     log.debug("Traffic Remove failed")
            #     self.failed("Traffic Remove failed")
            # else:
            #     log.info("Traffic Deletion Passed")
            
            FO_1.configure('''
            interface ''' + str(testscript.parameters['intf_FO_1_to_LEAF_3']) + '''
            shut
            switchport
            switchport mode trunk
            
            interface ''' + str(testscript.parameters['intf_FO_1_to_N7k_LEAF_3']) + '''
            no shut
            switchport
            switchport mode trunk
            ''')
            time.sleep(30)
            ###Remove Pre-migration step from both N7k leafs
            device_handle=connect_to_vdc(testscript.parameters['xbow1'], 'leaf1')
            if device_handle==False:
                log.info("failed to switchto correct vdc")
                self.failed("failed to switchto correct vdc",goto=['common_cleanup'])
            else:
                total_ip_count = int(forwardingSysDict['VLAN_PER_VRF_count']) * int(forwardingSysDict['VRF_count'])
                l2_ipv4s = increment_prefix_network(ip.IPv4Interface(str(l2_vlan_ipv4_start) + str(l2_vlan_ipv4_mask)),total_ip_count)
                l2_ipv6s = increment_prefix_network(ip.IPv6Interface(str(l2_vlan_ipv6_start) + str(l2_vlan_ipv6_mask)),total_ip_count)
                ip_index=0
                for i in range(0,len(l2_ipv4s)):
                    device_handle.configure('''int vlan ''' + str(l2_vlan_id) + '''\n
                                     hsrp version 2
                                     hsrp ''' + str(l2_vlan_id) + ''' ipv4
                                     no mac-address 0000.000a.aaaa
                                     ''')
                    l2_vlan_id += 1
            l2_vlan_id = testscript.parameters['N7K_LEAF_1_dict']['Vlan_data']['l2_vlan_start']        
            device_handle=connect_to_vdc(testscript.parameters['xbow2'], 'leaf2')
            if device_handle==False:
                log.info("failed to switchto correct vdc")
                self.failed("failed to switchto correct vdc",goto=['common_cleanup'])
            else:
                total_ip_count = int(forwardingSysDict['VLAN_PER_VRF_count']) * int(forwardingSysDict['VRF_count'])
                l2_ipv4s = increment_prefix_network(ip.IPv4Interface(str(l2_vlan_ipv4_start) + str(l2_vlan_ipv4_mask)),total_ip_count)
                l2_ipv6s = increment_prefix_network(ip.IPv6Interface(str(l2_vlan_ipv6_start) + str(l2_vlan_ipv6_mask)),total_ip_count)
                ip_index=0
                for i in range(0,len(l2_ipv4s)):
                    device_handle.configure('''int vlan ''' + str(l2_vlan_id) + '''\n
                                     hsrp version 2
                                     hsrp ''' + str(l2_vlan_id) + ''' ipv4
                                     no mac-address 0000.000a.aaaa
                                     ''')
                    l2_vlan_id += 1
            status = infraVerify.postTestVerification(post_test_process_dict)
            if status['status'] == 0:
                self.failed(reason=status['logs'])
            else:
                self.passed(reason=status['logs'])
        except Exception as error:
            log.debug("Unable to unconfigure class map or policy map-Encountered exception " + str(error))
            self.errored('Exception occurred while unconfiguring qos on LEAF1', goto=['next_tc'])
# *****************************************************************************************************************************#
class ARP_Restart_pre_Host_move_ipv4(aetest.Testcase):
    """ Host_move_ipv4 """

    
    # =============================================================================================================================#        
    
    @aetest.test
    def SVI_ON_LEAF2(self, testscript):
        """Shut down the vpc leg on Leaf2 to force all traffic to Leaf1"""
        
        LEAF_1 = testscript.parameters['LEAF-1']
        LEAF_2 = testscript.parameters['LEAF-2']
        forwardingSysDict = testscript.parameters['forwardingSysDict']
        l2_vlan_id = testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vlan_start']
        l2_vlan_ipv4_sec_start= testscript.parameters['LEAF_2_dict']['VNI_data']['l2_vlan_ipv4_sec_start']
        l2_vlan_ipv4_mask= testscript.parameters['LEAF_2_dict']['VNI_data']['l2_vlan_ipv4_mask']
        #+ str(testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vlan_ipv4_mask'])
        
        try:
            total_ip_count = int(forwardingSysDict['VLAN_PER_VRF_count']) * int(forwardingSysDict['VRF_count'])
            l2_ipv4s = increment_prefix_network(ip.IPv4Interface(str(l2_vlan_ipv4_sec_start) + str(l2_vlan_ipv4_mask)),total_ip_count)
            ip_index=0
            for i in range(0,len(l2_ipv4s)):
                LEAF_2.configure('''int vlan ''' + str(l2_vlan_id) + '''\n
                                 ip address ''' + str(l2_ipv4s[ip_index]) + ''' secondary use-bia
                                 ''')
                l2_vlan_id += 1
                ip_index += 1
                
            
            
        except Exception as error:
            log.debug("Unable to configure - Encountered Exception " + str(error))
            self.errored('Exception occurred while configuring secondary ipv4 address on LEAF-2', goto=['cleanup'])
            
    # =============================================================================================================================#        
    
    @aetest.test
    def SVI_ON_LEAF1(self, testscript):
        """Shut down the vpc leg on Leaf2 to force all traffic to Leaf1"""
        
        LEAF_1 = testscript.parameters['LEAF-1']
        LEAF_2 = testscript.parameters['LEAF-2']
        forwardingSysDict = testscript.parameters['forwardingSysDict']
        l2_vlan_id = testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vlan_start']
        l2_vlan_ipv4_sec_start= testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vlan_ipv4_sec_start']
        l2_vlan_ipv4_mask= testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vlan_ipv4_mask']
        
        try:
            total_ip_count = int(forwardingSysDict['VLAN_PER_VRF_count']) * int(forwardingSysDict['VRF_count'])
            l2_ipv4s = increment_prefix_network(ip.IPv4Interface(str(l2_vlan_ipv4_sec_start) + str(l2_vlan_ipv4_mask)),total_ip_count)
            ip_index=0
            for i in range(0,len(l2_ipv4s)):
                LEAF_1.configure('''int vlan ''' + str(l2_vlan_id) + '''\n
                                 ip address ''' + str(l2_ipv4s[ip_index]) + ''' secondary use-bia
                                 ''')
                l2_vlan_id += 1
                ip_index += 1
                
            
            
        except Exception as error:
            log.debug("Unable to configure - Encountered Exception " + str(error))
            self.errored('Exception occurred while configuring secondary ipv4 address on LEAF-1', goto=['cleanup'])
            
     # =============================================================================================================================#        
    @aetest.test
    def Add_external_int(self, testscript):
        """Shut down the vpc leg on Leaf2 to force all traffic to Leaf1"""
        
        LEAF_1 = testscript.parameters['LEAF-1']
        LEAF_2 = testscript.parameters['LEAF-2']
        
        try:
            testscript.parameters['LEAF-2'].configure('''
                  interface po ''' + str(testscript.parameters['LEAF_1_dict']['VPC_data']['double_vpc_po_1']) + '''
                  port-type external
                  ''')
            
            testscript.parameters['LEAF-1'].configure('''
                  interface po ''' + str(testscript.parameters['LEAF_1_dict']['VPC_data']['double_vpc_po_1']) + '''
                  port-type external
                  ''')    
            
            
        except Exception as error:
            log.debug("Unable to configure - Encountered Exception " + str(error))
            self.errored('Exception occurred while configuring external on LEAF-1 and LEAF-2', goto=['cleanup'])
            
     # =============================================================================================================================#    
    @aetest.test
    def Pre_migration_hsrp(self,testscript):
        LEAF_1 = testscript.parameters['LEAF-1']
        LEAF_2 = testscript.parameters['LEAF-2']
        forwardingSysDict = testscript.parameters['forwardingSysDict']
        l2_vlan_id = testscript.parameters['N7K_LEAF_1_dict']['Vlan_data']['l2_vlan_start']
        l2_vlan_ipv4_start= testscript.parameters['N7K_LEAF_1_dict']['Vlan_data']['l2_vlan_ipv4_start']
        l2_vlan_ipv4_mask= testscript.parameters['N7K_LEAF_1_dict']['Vlan_data']['l2_vlan_ipv4_mask']
        l2_vlan_ipv6_start= testscript.parameters['N7K_LEAF_1_dict']['Vlan_data']['l2_vlan_ipv6_start']
        l2_vlan_ipv6_mask= testscript.parameters['N7K_LEAF_1_dict']['Vlan_data']['l2_vlan_ipv6_mask']
        l2_hsrp_ipv4_vip_start= testscript.parameters['N7K_LEAF_1_dict']['Vlan_data']['hsrp_ipv4_vip_start']
        l2_hsrp_ipv6_vip_start= testscript.parameters['N7K_LEAF_1_dict']['Vlan_data']['hsrp_ipv6_vip_start']
        
        try:
            device_handle=connect_to_vdc(testscript.parameters['xbow1'], 'leaf1')
            if device_handle==False:
                log.info("failed to switchto correct vdc")
                self.failed("failed to switchto correct vdc",goto=['common_cleanup'])
            else:
                total_ip_count = int(forwardingSysDict['VLAN_PER_VRF_count']) * int(forwardingSysDict['VRF_count'])
                l2_ipv4s = increment_prefix_network(ip.IPv4Interface(str(l2_vlan_ipv4_start) + str(l2_vlan_ipv4_mask)),total_ip_count)
                l2_ipv6s = increment_prefix_network(ip.IPv6Interface(str(l2_vlan_ipv6_start) + str(l2_vlan_ipv6_mask)),total_ip_count)
                ip_index=0
                for i in range(0,len(l2_ipv4s)):
                    device_handle.configure('''int vlan ''' + str(l2_vlan_id) + '''\n
                                     hsrp version 2
                                     hsrp ''' + str(l2_vlan_id) + ''' ipv4
                                     mac-address 0000.000a.aaaa
                                     ''')
                    l2_vlan_id += 1
            l2_vlan_id = testscript.parameters['N7K_LEAF_1_dict']['Vlan_data']['l2_vlan_start']        
            device_handle=connect_to_vdc(testscript.parameters['xbow2'], 'leaf2')
            if device_handle==False:
                log.info("failed to switchto correct vdc")
                self.failed("failed to switchto correct vdc",goto=['common_cleanup'])
            else:
                total_ip_count = int(forwardingSysDict['VLAN_PER_VRF_count']) * int(forwardingSysDict['VRF_count'])
                l2_ipv4s = increment_prefix_network(ip.IPv4Interface(str(l2_vlan_ipv4_start) + str(l2_vlan_ipv4_mask)),total_ip_count)
                l2_ipv6s = increment_prefix_network(ip.IPv6Interface(str(l2_vlan_ipv6_start) + str(l2_vlan_ipv6_mask)),total_ip_count)
                ip_index=0
                for i in range(0,len(l2_ipv4s)):
                    device_handle.configure('''int vlan ''' + str(l2_vlan_id) + '''\n
                                     hsrp version 2
                                     hsrp ''' + str(l2_vlan_id) + ''' ipv4
                                     mac-address 0000.000a.aaaa
                                     ''')
                    l2_vlan_id += 1
                    


        except Exception as error:
                log.debug("Unable to configure - Encountered Exception " + str(error))
                self.errored('Exception occurred while configuring on N7k leaf1', goto=['common_cleanup'])
                
    @aetest.test        
    def configure_FO(self,testscript):
        
        FO_1_vlanConfiguration = ""
        FO_1=testscript.parameters['FO_1']

        l3_vrf_count_iter = 0
        l2_vlan_id = testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vlan_start']
        l3_vlan_id = testscript.parameters['LEAF_1_dict']['VNI_data']['l3_vlan_start']

        while l3_vrf_count_iter < testscript.parameters['forwardingSysDict']['VRF_count']:
            l2_vlan_count_iter = 0
            FO_1_vlanConfiguration += '''vlan ''' + str(l3_vlan_id) + '''\n
                                            state active\n
                                            no shut\n'''
            while l2_vlan_count_iter < testscript.parameters['forwardingSysDict']['VLAN_PER_VRF_count']:
                # Incrementing L2 VLAN Iteration counters
                FO_1_vlanConfiguration += '''vlan ''' + str(l2_vlan_id) + '''\n
                                                state active\n
                                                no shut\n'''
                l2_vlan_count_iter += 1
                l2_vlan_id += 1
            # Incrementing L3 VRF Iteration counters
            l3_vrf_count_iter += 1
            l3_vlan_id += 1

        try:
            FO_1.configure(
                str(FO_1_vlanConfiguration) + '''
        
        
            
            interface ''' + str(testscript.parameters['intf_FO_1_to_N7k_LEAF_3']) + '''
            no shut
            switchport
            switchport mode trunk
            
            interface ''' + str(testscript.parameters['intf_FO_1_to_LEAF_3']) + '''
            shut
            switchport
            switchport mode trunk
            
            interface ''' + str(testscript.parameters['intf_FO_1_to_IXIA']) + '''
            no shut
            switchport
            switchport mode trunk
            
            ''')
        except Exception as error:
                log.debug("Unable to configure - Encountered Exception " + str(error))
                self.errored('Exception occurred while configuring on FO_1', goto=['common_cleanup'])
   
#     @aetest.test
#     def CONFIGURE_UCAST_L3_IXIA_TRAFFIC(self, testscript):
#         """ IXIA_CONFIGURATION subsection: Configure MCAST Traffic Item """
# 
#         # Do not perform configurations if skip_tgen_config flag is set
#         if not testscript.parameters['script_flags']['skip_tgen_config']:
# 
#             IX_TP1 = testscript.parameters['IX_TP1']
#             IX_TP2 = testscript.parameters['IX_TP2']
#             P1_dict = testscript.parameters['LEAF_2_TGEN_dict']
#             P2_dict = testscript.parameters['LEAF_3_TGEN_dict']
# 
#             UCAST_v4_dict = {   'src_hndl'  : IX_TP1['port_handle'],
#                                 'dst_hndl'  : IX_TP2['port_handle'],
#                                 'ip_dscp'   : P1_dict['ip_dscp'],
#                                 'circuit'   : 'raw',
#                                 'TI_name'   : "UCAST_L3",
#                                 'rate_pps'  : "9000",
#                                 'bi_dir'    : 1,
#                                 'frame_size': '128',
#                                 'src_mac'   : P1_dict['mac'],
#                                 'dst_mac'   : '0000.000a.aaaa',
#                                 'srcmac_step': '00:00:00:00:00:00',
#                                 'dstmac_step': '00:00:00:00:00:00',
#                                 'srcmac_count': '1',
#                                 'dstmac_count': '1',
#                                 'vlan_id'    : P1_dict['vlan_id'],
#                                 'vlanid_step': '0',
#                                 'vlanid_count': '1',
#                                 'vlan_user_priority': P1_dict['vlan_user_priority'],
#                                 'ip_src_addrs' : P1_dict['v4_addr'],
#                                 'ip_dst_addrs' : P1_dict['L3_dst_addr'],
#                                 'ip_src_step' : '0.0.0.0',
#                                 'ip_dst_step' : '0.0.0.0',
# #                                'ip_step'    : P1_dict['v4_addr_step'],
#                           }
# 
# #            UCAST_v6_dict = {   'src_hndl'  : IX_TP1['ipv6_handle'],
# #                                'dst_hndl'  : IX_TP2['ipv6_handle'],
# #                                'circuit'   : 'ipv6',
# #                                'TI_name'   : "UCAST_V6",
# #                                'rate_pps'  : "1000",
# #                                'bi_dir'    : 1
# #                          }
# 
#             UCAST_v4_TI = ixLib.configure_ixia_l3_traffic_item(UCAST_v4_dict)
# #            UCAST_v6_TI = ixLib.configure_ixia_traffic_item(UCAST_v6_dict)
# 
# #            if UCAST_v4_TI == 0 or UCAST_v6_TI == 0:
# #                log.debug("Configuring UCast TI failed")
# #                self.errored("Configuring UCast TI failed", goto=['cleanup'])
#                 
#             if UCAST_v4_TI == 0:
#                 log.debug("Configuring UCast TI failed")
#                 self.errored("Configuring UCast TI failed", goto=['cleanup'])
#             else:
#                 global stream_id
#                 stream_id = UCAST_v4_TI
#             
# 
#         else:
#             self.passed(reason="Skipped TGEN Configurations as per request")
            
    # @aetest.test
    # def CONFIGURE_BCAST_IXIA_TRAFFIC(self, testscript):
    #     """ IXIA_CONFIGURATION subsection: Configure MCAST Traffic Item """
    # 
    #     # Do not perform configurations if skip_tgen_config flag is set
    #     if not testscript.parameters['script_flags']['skip_tgen_config']:
    # 
    #         IX_TP1 = testscript.parameters['IX_TP1']
    #         IX_TP2 = testscript.parameters['IX_TP2']
    #         P1_dict = testscript.parameters['LEAF_2_TGEN_dict']
    #         P2_dict = testscript.parameters['LEAF_3_TGEN_dict']
    #         BCAST_v4_dict = {
    #                             'src_hndl'      : IX_TP1['port_handle'],
    #                             'dst_hndl'      : IX_TP2['port_handle'],
    #                             'TI_name'       : "BCAST_V4",
    #                             'frame_size'    : "70",
    #                             'rate_pps'      : "1000",
    #                             'src_mac'       : P1_dict['mac'],
    #                             'srcmac_step'   : "00:00:00:00:00:01",
    #                             'srcmac_count'  : '1',
    #                             'vlan_id'       : P1_dict['vlan_id'],
    #                             'vlanid_step'   : "1",
    #                             'vlanid_count'  : "1",
    #                             'ip_src_addrs'  : P1_dict['v4_addr'],
    #                             'ip_step'       : "0.0.1.0",
    #                       }
    # 
    #         BCAST_v4_TI = ixLib.configure_ixia_BCAST_traffic_item(BCAST_v4_dict)
    # 
    #         if BCAST_v4_TI == 0:
    #             log.debug("Configuring BCast TI failed")
    #             self.errored("Configuring BCast TI failed", goto=['cleanup'])
    #         
    # 
    #     else:
    #         self.passed(reason="Skipped TGEN Configurations as per request")
    # =============================================================================================================================#
    @aetest.test
    def APPLY_TRAFFIC(self):
        """ IXIA_CONFIGURATION subsection: Verify IXIA Traffic """

        # # Apply IXIA Traffic
        # if ixLib.apply_traffic() == 1:
        #     log.info("Applying IXIA TI Passed")
        # else:
        #     self.errored("Applying IXIA TI failed", goto=['cleanup'])
            
        # =============================================================================================================================#
    #--------------------------------------------------------------------------------#
        # Start traffic from ixia
        log.info("--- Populating the statistics --- \n")
        log.info("---- Running Traffic --- \n")
        log.info("Starting Traffic")

        traffic_run_status  = ixLib.start_traffic()

        if traffic_run_status is not 1:
           log.info("Failed: To start traffic")
           return 0
        else:
            log.info("\nTraffic started successfully\n")

        time.sleep(30)
    
    # Stop Traffic from ixia
        log.info("--- Stopping Traffic ---- \n")
        log.info("Stopping Traffic")
        traffic_run_status = ixLib.stop_traffic()
        
        if traffic_run_status is not 1:
           log.info("Failed: To Stop traffic")
           return 0
        else:
            log.info("\nTraffic Stopped successfully\n")
            time.sleep(10)    
    
    @aetest.test
    def VERIFY_IXIA_TRAFFIC(self, testscript):
        """ IXIA_CONFIGURATION subsection: Verify IXIA Traffic """

        # Do not perform configurations if skip_tgen_config flag is set
        if not testscript.parameters['script_flags']['skip_tgen_config']:

            time.sleep(20)

            if ixLib.verify_traffic(2) == 0:
                log.debug("Traffic Verification failed")
                self.failed("Traffic Verification failed", goto=['cleanup'])
            else:
                log.info("Traffic Verification Passed")
        else:
            self.passed(reason="Skipped TGEN Configurations as per request")
# =============================================================================================================================#
    @aetest.test
    def TRIGGER_verify_arp_process_restart(self, testscript):
        """ Arp_PROCESS_KILL_VERIFICATION subsection: Verify killing process Arp """

        LEAF_1 = testscript.parameters['LEAF-1']
        LEAF_2 = testscript.parameters['LEAF-2']

        if infraTrig.verifyProcessRestart(LEAF_1,"arp"):
            log.info("Successfully restarted process arp on Leaf1")
        else:
            log.debug("Failed to restarted process arp on Leaf1")
            self.failed("Failed to restarted process arp on Leaf1", goto=['cleanup'])
            
        if infraTrig.verifyProcessRestart(LEAF_2,"arp"):
            log.info("Successfully restarted process arp on Leaf2")
        else:
            log.debug("Failed to restarted process arp on Leaf2")
            self.failed("Failed to restarted process arp on Leaf2", goto=['cleanup'])

        time.sleep(120)
    
    @aetest.test
    def VERIFY_IXIA_TRAFFIC_AFTER_ARP_Restart(self, testscript):
        """ IXIA_CONFIGURATION subsection: Verify IXIA Traffic """

        # Do not perform configurations if skip_tgen_config flag is set
        if not testscript.parameters['script_flags']['skip_tgen_config']:

            time.sleep(20)

            if ixLib.verify_traffic(2) == 0:
                log.debug("Traffic Verification failed")
                self.failed("Traffic Verification failed", goto=['cleanup'])
            else:
                log.info("Traffic Verification Passed")
        else:
            self.passed(reason="Skipped TGEN Configurations as per request")
     # =============================================================================================================================#        
    @aetest.test
    def Clear_ARP_Table_on_Vxlan_BLs(self, testscript):
        """Shut down the vpc leg on Leaf2 to force all traffic to Leaf1"""
        
        LEAF_1 = testscript.parameters['LEAF-1']
        LEAF_2 = testscript.parameters['LEAF-2']
        
        try:
            for i in range(1, testscript.parameters['forwardingSysDict']['VRF_count']+1):
                testscript.parameters['LEAF-2'].execute('''
                      clear ip arp vrf ''' + str(testscript.parameters['forwardingSysDict']['VRF_string']) + str(i) + ''' force-delete''')
            
            for i in range(1, testscript.parameters['forwardingSysDict']['VRF_count']+1):
                testscript.parameters['LEAF-1'].execute('''
                      clear ip arp vrf ''' + str(testscript.parameters['forwardingSysDict']['VRF_string']) + str(i) + ''' force-delete''')    
            
            
        except Exception as error:
            log.debug("Unable to configure - Encountered Exception " + str(error))
            self.errored('Exception occurred while clearing arp cache on LEAF-1 and LEAF-2', goto=['cleanup'])
            
    @aetest.test        
    def Host_move_FO(self,testscript):
        
        
        FO_1=testscript.parameters['FO_1']

        
        try:
            FO_1.configure('''
            interface ''' + str(testscript.parameters['intf_FO_1_to_N7k_LEAF_3']) + '''
            shut
            switchport
            switchport mode trunk
            
            interface ''' + str(testscript.parameters['intf_FO_1_to_LEAF_3']) + '''
            no shut
            switchport
            switchport mode trunk
            
            ''')
            time.sleep(45)
            #ForkedPdb().set_trace()
        except Exception as error:
                log.debug("Unable to configure - Encountered Exception " + str(error))
                self.errored('Exception occurred while configuring on FO_1', goto=['common_cleanup'])
                
    @aetest.test
    def VERIFY_IXIA_TRAFFIC_AFTER_MOVE(self, testscript):
        """ IXIA_CONFIGURATION subsection: Verify IXIA Traffic """

        # Do not perform configurations if skip_tgen_config flag is set
        if not testscript.parameters['script_flags']['skip_tgen_config']:

            time.sleep(20)

            if ixLib.verify_traffic(15) == 0:
                log.debug("Traffic Verification failed")
                self.failed("Traffic Verification failed", goto=['cleanup'])
            else:
                log.info("Traffic Verification Passed")
            
        else:
            self.passed(reason="Skipped TGEN Configurations as per request")
            
    @aetest.test        
    def Host_move_FO_BACK(self,testscript):
        
        
        FO_1=testscript.parameters['FO_1']

        
        try:
            FO_1.configure('''
            interface ''' + str(testscript.parameters['intf_FO_1_to_LEAF_3']) + '''
            shut
            switchport
            switchport mode trunk
            
            interface ''' + str(testscript.parameters['intf_FO_1_to_N7k_LEAF_3']) + '''
            no shut
            switchport
            switchport mode trunk
            
            
            
            ''')
            time.sleep(45)
        except Exception as error:
                log.debug("Unable to configure - Encountered Exception " + str(error))
                self.errored('Exception occurred while configuring on FO_1', goto=['common_cleanup'])
                
    @aetest.test
    def VERIFY_IXIA_TRAFFIC_HOST_MOVE_BACK(self, testscript):
        """ IXIA_CONFIGURATION subsection: Verify IXIA Traffic """

        # Do not perform configurations if skip_tgen_config flag is set
        if not testscript.parameters['script_flags']['skip_tgen_config']:

            time.sleep(20)

            if ixLib.verify_traffic(15) == 0:
                log.debug("Traffic Verification failed")
                self.failed("Traffic Verification failed", goto=['cleanup'])
            else:
                log.info("Traffic Verification Passed")
        else:
            self.passed(reason="Skipped TGEN Configurations as per request")
        
    @aetest.cleanup
    def cleanup(self,testscript):
        """Unconfigure qos policies"""
        LEAF_1 = testscript.parameters['LEAF-1']
        LEAF_2 = testscript.parameters['LEAF-2']
        LEAF_3 = testscript.parameters['LEAF-3']
        FO_1=testscript.parameters['FO_1']
        LEAF_1 = testscript.parameters['LEAF-1']
        LEAF_2 = testscript.parameters['LEAF-2']
        forwardingSysDict = testscript.parameters['forwardingSysDict']
        l2_vlan_id = testscript.parameters['N7K_LEAF_1_dict']['Vlan_data']['l2_vlan_start']
        l2_vlan_ipv4_start= testscript.parameters['N7K_LEAF_1_dict']['Vlan_data']['l2_vlan_ipv4_start']
        l2_vlan_ipv4_mask= testscript.parameters['N7K_LEAF_1_dict']['Vlan_data']['l2_vlan_ipv4_mask']
        l2_vlan_ipv6_start= testscript.parameters['N7K_LEAF_1_dict']['Vlan_data']['l2_vlan_ipv6_start']
        l2_vlan_ipv6_mask= testscript.parameters['N7K_LEAF_1_dict']['Vlan_data']['l2_vlan_ipv6_mask']
        l2_hsrp_ipv4_vip_start= testscript.parameters['N7K_LEAF_1_dict']['Vlan_data']['hsrp_ipv4_vip_start']
        l2_hsrp_ipv6_vip_start= testscript.parameters['N7K_LEAF_1_dict']['Vlan_data']['hsrp_ipv6_vip_start']
        
        post_test_process_dict = {
            'dut_list'                       : [LEAF_1, LEAF_2, LEAF_3],
            'cc_check'                  : 1,
            'cores_check'               : 1,
            'logs_check'                : 0,
            'fnl_flag'                  : 0,
            'exclude_log_check_pattern' : 'ERROR_VLANS_SUSPENDED|ERROR_VLANS_REMOVED',
            }
        try:
            # UCAST_v4_dict = {
            #                 'mode'        : 'remove',
            #                 'stream_id'   : stream_id,
            #           }
            # if (ixLib.delete_traffic_item(UCAST_v4_dict))==0:
            #     log.debug("Traffic Remove failed")
            #     self.failed("Traffic Remove failed")
            # else:
            #     log.info("Traffic Deletion Passed")
            
            FO_1.configure('''
            interface ''' + str(testscript.parameters['intf_FO_1_to_LEAF_3']) + '''
            shut
            switchport
            switchport mode trunk
            
            interface ''' + str(testscript.parameters['intf_FO_1_to_N7k_LEAF_3']) + '''
            no shut
            switchport
            switchport mode trunk
            ''')
            time.sleep(30)
            ###Remove Pre-migration step from both N7k leafs
            device_handle=connect_to_vdc(testscript.parameters['xbow1'], 'leaf1')
            if device_handle==False:
                log.info("failed to switchto correct vdc")
                self.failed("failed to switchto correct vdc",goto=['common_cleanup'])
            else:
                total_ip_count = int(forwardingSysDict['VLAN_PER_VRF_count']) * int(forwardingSysDict['VRF_count'])
                l2_ipv4s = increment_prefix_network(ip.IPv4Interface(str(l2_vlan_ipv4_start) + str(l2_vlan_ipv4_mask)),total_ip_count)
                l2_ipv6s = increment_prefix_network(ip.IPv6Interface(str(l2_vlan_ipv6_start) + str(l2_vlan_ipv6_mask)),total_ip_count)
                ip_index=0
                for i in range(0,len(l2_ipv4s)):
                    device_handle.configure('''int vlan ''' + str(l2_vlan_id) + '''\n
                                     hsrp version 2
                                     hsrp ''' + str(l2_vlan_id) + ''' ipv4
                                     no mac-address 0000.000a.aaaa
                                     ''')
                    l2_vlan_id += 1
            l2_vlan_id = testscript.parameters['N7K_LEAF_1_dict']['Vlan_data']['l2_vlan_start']        
            device_handle=connect_to_vdc(testscript.parameters['xbow2'], 'leaf2')
            if device_handle==False:
                log.info("failed to switchto correct vdc")
                self.failed("failed to switchto correct vdc",goto=['common_cleanup'])
            else:
                total_ip_count = int(forwardingSysDict['VLAN_PER_VRF_count']) * int(forwardingSysDict['VRF_count'])
                l2_ipv4s = increment_prefix_network(ip.IPv4Interface(str(l2_vlan_ipv4_start) + str(l2_vlan_ipv4_mask)),total_ip_count)
                l2_ipv6s = increment_prefix_network(ip.IPv6Interface(str(l2_vlan_ipv6_start) + str(l2_vlan_ipv6_mask)),total_ip_count)
                ip_index=0
                for i in range(0,len(l2_ipv4s)):
                    device_handle.configure('''int vlan ''' + str(l2_vlan_id) + '''\n
                                     hsrp version 2
                                     hsrp ''' + str(l2_vlan_id) + ''' ipv4
                                     no mac-address 0000.000a.aaaa
                                     ''')
                    l2_vlan_id += 1
            status = infraVerify.postTestVerification(post_test_process_dict)
            if status['status'] == 0:
                self.failed(reason=status['logs'])
            else:
                self.passed(reason=status['logs'])
        except Exception as error:
            log.debug("Unable to unconfigure class map or policy map-Encountered exception " + str(error))
            self.errored('Exception occurred while unconfiguring qos on LEAF1', goto=['next_tc'])
            
# *****************************************************************************************************************************#
class ETHPM_Restart_pre_Host_move_ipv4(aetest.Testcase):
    """ Host_move_ipv4 """

    
    # =============================================================================================================================#        
    
    @aetest.test
    def SVI_ON_LEAF2(self, testscript):
        """Shut down the vpc leg on Leaf2 to force all traffic to Leaf1"""
        
        LEAF_1 = testscript.parameters['LEAF-1']
        LEAF_2 = testscript.parameters['LEAF-2']
        forwardingSysDict = testscript.parameters['forwardingSysDict']
        l2_vlan_id = testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vlan_start']
        l2_vlan_ipv4_sec_start= testscript.parameters['LEAF_2_dict']['VNI_data']['l2_vlan_ipv4_sec_start']
        l2_vlan_ipv4_mask= testscript.parameters['LEAF_2_dict']['VNI_data']['l2_vlan_ipv4_mask']
        #+ str(testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vlan_ipv4_mask'])
        
        try:
            total_ip_count = int(forwardingSysDict['VLAN_PER_VRF_count']) * int(forwardingSysDict['VRF_count'])
            l2_ipv4s = increment_prefix_network(ip.IPv4Interface(str(l2_vlan_ipv4_sec_start) + str(l2_vlan_ipv4_mask)),total_ip_count)
            ip_index=0
            for i in range(0,len(l2_ipv4s)):
                LEAF_2.configure('''int vlan ''' + str(l2_vlan_id) + '''\n
                                 ip address ''' + str(l2_ipv4s[ip_index]) + ''' secondary use-bia
                                 ''')
                l2_vlan_id += 1
                ip_index += 1
                
            
            
        except Exception as error:
            log.debug("Unable to configure - Encountered Exception " + str(error))
            self.errored('Exception occurred while configuring secondary ipv4 address on LEAF-2', goto=['cleanup'])
            
    # =============================================================================================================================#        
    
    @aetest.test
    def SVI_ON_LEAF1(self, testscript):
        """Shut down the vpc leg on Leaf2 to force all traffic to Leaf1"""
        
        LEAF_1 = testscript.parameters['LEAF-1']
        LEAF_2 = testscript.parameters['LEAF-2']
        forwardingSysDict = testscript.parameters['forwardingSysDict']
        l2_vlan_id = testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vlan_start']
        l2_vlan_ipv4_sec_start= testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vlan_ipv4_sec_start']
        l2_vlan_ipv4_mask= testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vlan_ipv4_mask']
        
        try:
            total_ip_count = int(forwardingSysDict['VLAN_PER_VRF_count']) * int(forwardingSysDict['VRF_count'])
            l2_ipv4s = increment_prefix_network(ip.IPv4Interface(str(l2_vlan_ipv4_sec_start) + str(l2_vlan_ipv4_mask)),total_ip_count)
            ip_index=0
            for i in range(0,len(l2_ipv4s)):
                LEAF_1.configure('''int vlan ''' + str(l2_vlan_id) + '''\n
                                 ip address ''' + str(l2_ipv4s[ip_index]) + ''' secondary use-bia
                                 ''')
                l2_vlan_id += 1
                ip_index += 1
                
            
            
        except Exception as error:
            log.debug("Unable to configure - Encountered Exception " + str(error))
            self.errored('Exception occurred while configuring secondary ipv4 address on LEAF-1', goto=['cleanup'])
            
     # =============================================================================================================================#        
    @aetest.test
    def Add_external_int(self, testscript):
        """Shut down the vpc leg on Leaf2 to force all traffic to Leaf1"""
        
        LEAF_1 = testscript.parameters['LEAF-1']
        LEAF_2 = testscript.parameters['LEAF-2']
        
        try:
            testscript.parameters['LEAF-2'].configure('''
                  interface po ''' + str(testscript.parameters['LEAF_1_dict']['VPC_data']['double_vpc_po_1']) + '''
                  port-type external
                  ''')
            
            testscript.parameters['LEAF-1'].configure('''
                  interface po ''' + str(testscript.parameters['LEAF_1_dict']['VPC_data']['double_vpc_po_1']) + '''
                  port-type external
                  ''')    
            
            
        except Exception as error:
            log.debug("Unable to configure - Encountered Exception " + str(error))
            self.errored('Exception occurred while configuring external on LEAF-1 and LEAF-2', goto=['cleanup'])
            
     # =============================================================================================================================#    
    @aetest.test
    def Pre_migration_hsrp(self,testscript):
        LEAF_1 = testscript.parameters['LEAF-1']
        LEAF_2 = testscript.parameters['LEAF-2']
        forwardingSysDict = testscript.parameters['forwardingSysDict']
        l2_vlan_id = testscript.parameters['N7K_LEAF_1_dict']['Vlan_data']['l2_vlan_start']
        l2_vlan_ipv4_start= testscript.parameters['N7K_LEAF_1_dict']['Vlan_data']['l2_vlan_ipv4_start']
        l2_vlan_ipv4_mask= testscript.parameters['N7K_LEAF_1_dict']['Vlan_data']['l2_vlan_ipv4_mask']
        l2_vlan_ipv6_start= testscript.parameters['N7K_LEAF_1_dict']['Vlan_data']['l2_vlan_ipv6_start']
        l2_vlan_ipv6_mask= testscript.parameters['N7K_LEAF_1_dict']['Vlan_data']['l2_vlan_ipv6_mask']
        l2_hsrp_ipv4_vip_start= testscript.parameters['N7K_LEAF_1_dict']['Vlan_data']['hsrp_ipv4_vip_start']
        l2_hsrp_ipv6_vip_start= testscript.parameters['N7K_LEAF_1_dict']['Vlan_data']['hsrp_ipv6_vip_start']
        
        try:
            device_handle=connect_to_vdc(testscript.parameters['xbow1'], 'leaf1')
            if device_handle==False:
                log.info("failed to switchto correct vdc")
                self.failed("failed to switchto correct vdc",goto=['common_cleanup'])
            else:
                total_ip_count = int(forwardingSysDict['VLAN_PER_VRF_count']) * int(forwardingSysDict['VRF_count'])
                l2_ipv4s = increment_prefix_network(ip.IPv4Interface(str(l2_vlan_ipv4_start) + str(l2_vlan_ipv4_mask)),total_ip_count)
                l2_ipv6s = increment_prefix_network(ip.IPv6Interface(str(l2_vlan_ipv6_start) + str(l2_vlan_ipv6_mask)),total_ip_count)
                ip_index=0
                for i in range(0,len(l2_ipv4s)):
                    device_handle.configure('''int vlan ''' + str(l2_vlan_id) + '''\n
                                     hsrp version 2
                                     hsrp ''' + str(l2_vlan_id) + ''' ipv4
                                     mac-address 0000.000a.aaaa
                                     ''')
                    l2_vlan_id += 1
            l2_vlan_id = testscript.parameters['N7K_LEAF_1_dict']['Vlan_data']['l2_vlan_start']        
            device_handle=connect_to_vdc(testscript.parameters['xbow2'], 'leaf2')
            if device_handle==False:
                log.info("failed to switchto correct vdc")
                self.failed("failed to switchto correct vdc",goto=['common_cleanup'])
            else:
                total_ip_count = int(forwardingSysDict['VLAN_PER_VRF_count']) * int(forwardingSysDict['VRF_count'])
                l2_ipv4s = increment_prefix_network(ip.IPv4Interface(str(l2_vlan_ipv4_start) + str(l2_vlan_ipv4_mask)),total_ip_count)
                l2_ipv6s = increment_prefix_network(ip.IPv6Interface(str(l2_vlan_ipv6_start) + str(l2_vlan_ipv6_mask)),total_ip_count)
                ip_index=0
                for i in range(0,len(l2_ipv4s)):
                    device_handle.configure('''int vlan ''' + str(l2_vlan_id) + '''\n
                                     hsrp version 2
                                     hsrp ''' + str(l2_vlan_id) + ''' ipv4
                                     mac-address 0000.000a.aaaa
                                     ''')
                    l2_vlan_id += 1
                    


        except Exception as error:
                log.debug("Unable to configure - Encountered Exception " + str(error))
                self.errored('Exception occurred while configuring on N7k leaf1', goto=['common_cleanup'])
                
    @aetest.test        
    def configure_FO(self,testscript):
        
        FO_1_vlanConfiguration = ""
        FO_1=testscript.parameters['FO_1']

        l3_vrf_count_iter = 0
        l2_vlan_id = testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vlan_start']
        l3_vlan_id = testscript.parameters['LEAF_1_dict']['VNI_data']['l3_vlan_start']

        while l3_vrf_count_iter < testscript.parameters['forwardingSysDict']['VRF_count']:
            l2_vlan_count_iter = 0
            FO_1_vlanConfiguration += '''vlan ''' + str(l3_vlan_id) + '''\n
                                            state active\n
                                            no shut\n'''
            while l2_vlan_count_iter < testscript.parameters['forwardingSysDict']['VLAN_PER_VRF_count']:
                # Incrementing L2 VLAN Iteration counters
                FO_1_vlanConfiguration += '''vlan ''' + str(l2_vlan_id) + '''\n
                                                state active\n
                                                no shut\n'''
                l2_vlan_count_iter += 1
                l2_vlan_id += 1
            # Incrementing L3 VRF Iteration counters
            l3_vrf_count_iter += 1
            l3_vlan_id += 1

        try:
            FO_1.configure(
                str(FO_1_vlanConfiguration) + '''
        
        
            
            interface ''' + str(testscript.parameters['intf_FO_1_to_N7k_LEAF_3']) + '''
            no shut
            switchport
            switchport mode trunk
            
            interface ''' + str(testscript.parameters['intf_FO_1_to_LEAF_3']) + '''
            shut
            switchport
            switchport mode trunk
            
            interface ''' + str(testscript.parameters['intf_FO_1_to_IXIA']) + '''
            no shut
            switchport
            switchport mode trunk
            
            ''')
        except Exception as error:
                log.debug("Unable to configure - Encountered Exception " + str(error))
                self.errored('Exception occurred while configuring on FO_1', goto=['common_cleanup'])
   
#     @aetest.test
#     def CONFIGURE_UCAST_L3_IXIA_TRAFFIC(self, testscript):
#         """ IXIA_CONFIGURATION subsection: Configure MCAST Traffic Item """
# 
#         # Do not perform configurations if skip_tgen_config flag is set
#         if not testscript.parameters['script_flags']['skip_tgen_config']:
# 
#             IX_TP1 = testscript.parameters['IX_TP1']
#             IX_TP2 = testscript.parameters['IX_TP2']
#             P1_dict = testscript.parameters['LEAF_2_TGEN_dict']
#             P2_dict = testscript.parameters['LEAF_3_TGEN_dict']
# 
#             UCAST_v4_dict = {   'src_hndl'  : IX_TP1['port_handle'],
#                                 'dst_hndl'  : IX_TP2['port_handle'],
#                                 'ip_dscp'   : P1_dict['ip_dscp'],
#                                 'circuit'   : 'raw',
#                                 'TI_name'   : "UCAST_L3",
#                                 'rate_pps'  : "9000",
#                                 'bi_dir'    : 1,
#                                 'frame_size': '128',
#                                 'src_mac'   : P1_dict['mac'],
#                                 'dst_mac'   : '0000.000a.aaaa',
#                                 'srcmac_step': '00:00:00:00:00:00',
#                                 'dstmac_step': '00:00:00:00:00:00',
#                                 'srcmac_count': '1',
#                                 'dstmac_count': '1',
#                                 'vlan_id'    : P1_dict['vlan_id'],
#                                 'vlanid_step': '0',
#                                 'vlanid_count': '1',
#                                 'vlan_user_priority': P1_dict['vlan_user_priority'],
#                                 'ip_src_addrs' : P1_dict['v4_addr'],
#                                 'ip_dst_addrs' : P1_dict['L3_dst_addr'],
#                                 'ip_src_step' : '0.0.0.0',
#                                 'ip_dst_step' : '0.0.0.0',
# #                                'ip_step'    : P1_dict['v4_addr_step'],
#                           }
# 
# #            UCAST_v6_dict = {   'src_hndl'  : IX_TP1['ipv6_handle'],
# #                                'dst_hndl'  : IX_TP2['ipv6_handle'],
# #                                'circuit'   : 'ipv6',
# #                                'TI_name'   : "UCAST_V6",
# #                                'rate_pps'  : "1000",
# #                                'bi_dir'    : 1
# #                          }
# 
#             UCAST_v4_TI = ixLib.configure_ixia_l3_traffic_item(UCAST_v4_dict)
# #            UCAST_v6_TI = ixLib.configure_ixia_traffic_item(UCAST_v6_dict)
# 
# #            if UCAST_v4_TI == 0 or UCAST_v6_TI == 0:
# #                log.debug("Configuring UCast TI failed")
# #                self.errored("Configuring UCast TI failed", goto=['cleanup'])
#                 
#             if UCAST_v4_TI == 0:
#                 log.debug("Configuring UCast TI failed")
#                 self.errored("Configuring UCast TI failed", goto=['cleanup'])
#             else:
#                 global stream_id
#                 stream_id = UCAST_v4_TI
#             
# 
#         else:
#             self.passed(reason="Skipped TGEN Configurations as per request")
            
    # @aetest.test
    # def CONFIGURE_BCAST_IXIA_TRAFFIC(self, testscript):
    #     """ IXIA_CONFIGURATION subsection: Configure MCAST Traffic Item """
    # 
    #     # Do not perform configurations if skip_tgen_config flag is set
    #     if not testscript.parameters['script_flags']['skip_tgen_config']:
    # 
    #         IX_TP1 = testscript.parameters['IX_TP1']
    #         IX_TP2 = testscript.parameters['IX_TP2']
    #         P1_dict = testscript.parameters['LEAF_2_TGEN_dict']
    #         P2_dict = testscript.parameters['LEAF_3_TGEN_dict']
    #         BCAST_v4_dict = {
    #                             'src_hndl'      : IX_TP1['port_handle'],
    #                             'dst_hndl'      : IX_TP2['port_handle'],
    #                             'TI_name'       : "BCAST_V4",
    #                             'frame_size'    : "70",
    #                             'rate_pps'      : "1000",
    #                             'src_mac'       : P1_dict['mac'],
    #                             'srcmac_step'   : "00:00:00:00:00:01",
    #                             'srcmac_count'  : '1',
    #                             'vlan_id'       : P1_dict['vlan_id'],
    #                             'vlanid_step'   : "1",
    #                             'vlanid_count'  : "1",
    #                             'ip_src_addrs'  : P1_dict['v4_addr'],
    #                             'ip_step'       : "0.0.1.0",
    #                       }
    # 
    #         BCAST_v4_TI = ixLib.configure_ixia_BCAST_traffic_item(BCAST_v4_dict)
    # 
    #         if BCAST_v4_TI == 0:
    #             log.debug("Configuring BCast TI failed")
    #             self.errored("Configuring BCast TI failed", goto=['cleanup'])
    #         
    # 
    #     else:
    #         self.passed(reason="Skipped TGEN Configurations as per request")
    # =============================================================================================================================#
    @aetest.test
    def APPLY_TRAFFIC(self):
        """ IXIA_CONFIGURATION subsection: Verify IXIA Traffic """

        # # Apply IXIA Traffic
        # if ixLib.apply_traffic() == 1:
        #     log.info("Applying IXIA TI Passed")
        # else:
        #     self.errored("Applying IXIA TI failed", goto=['cleanup'])
            
        # =============================================================================================================================#
    #--------------------------------------------------------------------------------#
        # Start traffic from ixia
        log.info("--- Populating the statistics --- \n")
        log.info("---- Running Traffic --- \n")
        log.info("Starting Traffic")

        traffic_run_status  = ixLib.start_traffic()

        if traffic_run_status is not 1:
           log.info("Failed: To start traffic")
           return 0
        else:
            log.info("\nTraffic started successfully\n")

        time.sleep(30)
    
    # Stop Traffic from ixia
        log.info("--- Stopping Traffic ---- \n")
        log.info("Stopping Traffic")
        traffic_run_status = ixLib.stop_traffic()
        
        if traffic_run_status is not 1:
           log.info("Failed: To Stop traffic")
           return 0
        else:
            log.info("\nTraffic Stopped successfully\n")
            time.sleep(10)    
    
    @aetest.test
    def VERIFY_IXIA_TRAFFIC(self, testscript):
        """ IXIA_CONFIGURATION subsection: Verify IXIA Traffic """

        # Do not perform configurations if skip_tgen_config flag is set
        if not testscript.parameters['script_flags']['skip_tgen_config']:

            time.sleep(20)

            if ixLib.verify_traffic(2) == 0:
                log.debug("Traffic Verification failed")
                self.failed("Traffic Verification failed", goto=['cleanup'])
            else:
                log.info("Traffic Verification Passed")
        else:
            self.passed(reason="Skipped TGEN Configurations as per request")
# =============================================================================================================================#
    @aetest.test
    def TRIGGER_verify_ethpm_process_restart(self, testscript):
        """ ETHPM_PROCESS_KILL_VERIFICATION subsection: Verify killing process ETHPM """

        LEAF_1 = testscript.parameters['LEAF-1']
        LEAF_2 = testscript.parameters['LEAF-2']

        if infraTrig.verifyProcessRestart(LEAF_1,"ethpm"):
            log.info("Successfully restarted process ethpm on Leaf1")
        else:
            log.debug("Failed to restarted process ethpm on Leaf1")
            self.failed("Failed to restarted process ethpm on Leaf1", goto=['cleanup'])
            
        if infraTrig.verifyProcessRestart(LEAF_2,"ethpm"):
            log.info("Successfully restarted process ethpm on Leaf2")
        else:
            log.debug("Failed to restarted process ethpm on Leaf2")
            self.failed("Failed to restarted process ethpm on Leaf2", goto=['cleanup'])

        time.sleep(120)
    
    @aetest.test
    def VERIFY_IXIA_TRAFFIC_AFTER_ethpm_Restart(self, testscript):
        """ IXIA_CONFIGURATION subsection: Verify IXIA Traffic """

        # Do not perform configurations if skip_tgen_config flag is set
        if not testscript.parameters['script_flags']['skip_tgen_config']:

            time.sleep(20)

            if ixLib.verify_traffic(2) == 0:
                log.debug("Traffic Verification failed")
                self.failed("Traffic Verification failed", goto=['cleanup'])
            else:
                log.info("Traffic Verification Passed")
        else:
            self.passed(reason="Skipped TGEN Configurations as per request")
     # =============================================================================================================================#        
    @aetest.test
    def Clear_ARP_Table_on_Vxlan_BLs(self, testscript):
        """Shut down the vpc leg on Leaf2 to force all traffic to Leaf1"""
        
        LEAF_1 = testscript.parameters['LEAF-1']
        LEAF_2 = testscript.parameters['LEAF-2']
        
        try:
            for i in range(1, testscript.parameters['forwardingSysDict']['VRF_count']+1):
                testscript.parameters['LEAF-2'].execute('''
                      clear ip arp vrf ''' + str(testscript.parameters['forwardingSysDict']['VRF_string']) + str(i) + ''' force-delete''')
            
            for i in range(1, testscript.parameters['forwardingSysDict']['VRF_count']+1):
                testscript.parameters['LEAF-1'].execute('''
                      clear ip arp vrf ''' + str(testscript.parameters['forwardingSysDict']['VRF_string']) + str(i) + ''' force-delete''')    
            
            
        except Exception as error:
            log.debug("Unable to configure - Encountered Exception " + str(error))
            self.errored('Exception occurred while clearing arp cache on LEAF-1 and LEAF-2', goto=['cleanup'])
            
    @aetest.test        
    def Host_move_FO(self,testscript):
        
        
        FO_1=testscript.parameters['FO_1']

        
        try:
            FO_1.configure('''
            interface ''' + str(testscript.parameters['intf_FO_1_to_N7k_LEAF_3']) + '''
            shut
            switchport
            switchport mode trunk
            
            interface ''' + str(testscript.parameters['intf_FO_1_to_LEAF_3']) + '''
            no shut
            switchport
            switchport mode trunk
            
            ''')
            time.sleep(45)
            #ForkedPdb().set_trace()
        except Exception as error:
                log.debug("Unable to configure - Encountered Exception " + str(error))
                self.errored('Exception occurred while configuring on FO_1', goto=['common_cleanup'])
                
    @aetest.test
    def VERIFY_IXIA_TRAFFIC_AFTER_MOVE(self, testscript):
        """ IXIA_CONFIGURATION subsection: Verify IXIA Traffic """

        # Do not perform configurations if skip_tgen_config flag is set
        if not testscript.parameters['script_flags']['skip_tgen_config']:

            time.sleep(20)

            if ixLib.verify_traffic(15) == 0:
                log.debug("Traffic Verification failed")
                self.failed("Traffic Verification failed", goto=['cleanup'])
            else:
                log.info("Traffic Verification Passed")
            
        else:
            self.passed(reason="Skipped TGEN Configurations as per request")
            
    @aetest.test        
    def Host_move_FO_BACK(self,testscript):
        
        
        FO_1=testscript.parameters['FO_1']

        
        try:
            FO_1.configure('''
            interface ''' + str(testscript.parameters['intf_FO_1_to_LEAF_3']) + '''
            shut
            switchport
            switchport mode trunk
            
            interface ''' + str(testscript.parameters['intf_FO_1_to_N7k_LEAF_3']) + '''
            no shut
            switchport
            switchport mode trunk
            
            
            
            ''')
            time.sleep(45)
        except Exception as error:
                log.debug("Unable to configure - Encountered Exception " + str(error))
                self.errored('Exception occurred while configuring on FO_1', goto=['common_cleanup'])
                
    @aetest.test
    def VERIFY_IXIA_TRAFFIC_HOST_MOVE_BACK(self, testscript):
        """ IXIA_CONFIGURATION subsection: Verify IXIA Traffic """

        # Do not perform configurations if skip_tgen_config flag is set
        if not testscript.parameters['script_flags']['skip_tgen_config']:

            time.sleep(20)

            if ixLib.verify_traffic(15) == 0:
                log.debug("Traffic Verification failed")
                self.failed("Traffic Verification failed", goto=['cleanup'])
            else:
                log.info("Traffic Verification Passed")
        else:
            self.passed(reason="Skipped TGEN Configurations as per request")
        
    @aetest.cleanup
    def cleanup(self,testscript):
        """Unconfigure qos policies"""
        LEAF_1 = testscript.parameters['LEAF-1']
        LEAF_2 = testscript.parameters['LEAF-2']
        LEAF_3 = testscript.parameters['LEAF-3']
        FO_1=testscript.parameters['FO_1']
        LEAF_1 = testscript.parameters['LEAF-1']
        LEAF_2 = testscript.parameters['LEAF-2']
        forwardingSysDict = testscript.parameters['forwardingSysDict']
        l2_vlan_id = testscript.parameters['N7K_LEAF_1_dict']['Vlan_data']['l2_vlan_start']
        l2_vlan_ipv4_start= testscript.parameters['N7K_LEAF_1_dict']['Vlan_data']['l2_vlan_ipv4_start']
        l2_vlan_ipv4_mask= testscript.parameters['N7K_LEAF_1_dict']['Vlan_data']['l2_vlan_ipv4_mask']
        l2_vlan_ipv6_start= testscript.parameters['N7K_LEAF_1_dict']['Vlan_data']['l2_vlan_ipv6_start']
        l2_vlan_ipv6_mask= testscript.parameters['N7K_LEAF_1_dict']['Vlan_data']['l2_vlan_ipv6_mask']
        l2_hsrp_ipv4_vip_start= testscript.parameters['N7K_LEAF_1_dict']['Vlan_data']['hsrp_ipv4_vip_start']
        l2_hsrp_ipv6_vip_start= testscript.parameters['N7K_LEAF_1_dict']['Vlan_data']['hsrp_ipv6_vip_start']
        
        post_test_process_dict = {
            'dut_list'                       : [LEAF_1, LEAF_2, LEAF_3],
            'cc_check'                  : 1,
            'cores_check'               : 1,
            'logs_check'                : 0,
            'fnl_flag'                  : 0,
            'exclude_log_check_pattern' : 'ERROR_VLANS_SUSPENDED|ERROR_VLANS_REMOVED',
            }
        try:
            # UCAST_v4_dict = {
            #                 'mode'        : 'remove',
            #                 'stream_id'   : stream_id,
            #           }
            # if (ixLib.delete_traffic_item(UCAST_v4_dict))==0:
            #     log.debug("Traffic Remove failed")
            #     self.failed("Traffic Remove failed")
            # else:
            #     log.info("Traffic Deletion Passed")
            
            FO_1.configure('''
            interface ''' + str(testscript.parameters['intf_FO_1_to_LEAF_3']) + '''
            shut
            switchport
            switchport mode trunk
            
            interface ''' + str(testscript.parameters['intf_FO_1_to_N7k_LEAF_3']) + '''
            no shut
            switchport
            switchport mode trunk
            ''')
            time.sleep(30)
            ###Remove Pre-migration step from both N7k leafs
            device_handle=connect_to_vdc(testscript.parameters['xbow1'], 'leaf1')
            if device_handle==False:
                log.info("failed to switchto correct vdc")
                self.failed("failed to switchto correct vdc",goto=['common_cleanup'])
            else:
                total_ip_count = int(forwardingSysDict['VLAN_PER_VRF_count']) * int(forwardingSysDict['VRF_count'])
                l2_ipv4s = increment_prefix_network(ip.IPv4Interface(str(l2_vlan_ipv4_start) + str(l2_vlan_ipv4_mask)),total_ip_count)
                l2_ipv6s = increment_prefix_network(ip.IPv6Interface(str(l2_vlan_ipv6_start) + str(l2_vlan_ipv6_mask)),total_ip_count)
                ip_index=0
                for i in range(0,len(l2_ipv4s)):
                    device_handle.configure('''int vlan ''' + str(l2_vlan_id) + '''\n
                                     hsrp version 2
                                     hsrp ''' + str(l2_vlan_id) + ''' ipv4
                                     no mac-address 0000.000a.aaaa
                                     ''')
                    l2_vlan_id += 1
            l2_vlan_id = testscript.parameters['N7K_LEAF_1_dict']['Vlan_data']['l2_vlan_start']        
            device_handle=connect_to_vdc(testscript.parameters['xbow2'], 'leaf2')
            if device_handle==False:
                log.info("failed to switchto correct vdc")
                self.failed("failed to switchto correct vdc",goto=['common_cleanup'])
            else:
                total_ip_count = int(forwardingSysDict['VLAN_PER_VRF_count']) * int(forwardingSysDict['VRF_count'])
                l2_ipv4s = increment_prefix_network(ip.IPv4Interface(str(l2_vlan_ipv4_start) + str(l2_vlan_ipv4_mask)),total_ip_count)
                l2_ipv6s = increment_prefix_network(ip.IPv6Interface(str(l2_vlan_ipv6_start) + str(l2_vlan_ipv6_mask)),total_ip_count)
                ip_index=0
                for i in range(0,len(l2_ipv4s)):
                    device_handle.configure('''int vlan ''' + str(l2_vlan_id) + '''\n
                                     hsrp version 2
                                     hsrp ''' + str(l2_vlan_id) + ''' ipv4
                                     no mac-address 0000.000a.aaaa
                                     ''')
                    l2_vlan_id += 1
            status = infraVerify.postTestVerification(post_test_process_dict)
            if status['status'] == 0:
                self.failed(reason=status['logs'])
            else:
                self.passed(reason=status['logs'])
        except Exception as error:
            log.debug("Unable to unconfigure class map or policy map-Encountered exception " + str(error))
            self.errored('Exception occurred while unconfiguring qos on LEAF1', goto=['next_tc'])
            
# *****************************************************************************************************************************#
class NVE_Restart_post_Host_move_ipv4(aetest.Testcase):
    """ Host_move_ipv4 """

    
    # =============================================================================================================================#        
    
    @aetest.test
    def SVI_ON_LEAF2(self, testscript):
        """Shut down the vpc leg on Leaf2 to force all traffic to Leaf1"""
        
        LEAF_1 = testscript.parameters['LEAF-1']
        LEAF_2 = testscript.parameters['LEAF-2']
        forwardingSysDict = testscript.parameters['forwardingSysDict']
        l2_vlan_id = testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vlan_start']
        l2_vlan_ipv4_sec_start= testscript.parameters['LEAF_2_dict']['VNI_data']['l2_vlan_ipv4_sec_start']
        l2_vlan_ipv4_mask= testscript.parameters['LEAF_2_dict']['VNI_data']['l2_vlan_ipv4_mask']
        #+ str(testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vlan_ipv4_mask'])
        
        try:
            total_ip_count = int(forwardingSysDict['VLAN_PER_VRF_count']) * int(forwardingSysDict['VRF_count'])
            l2_ipv4s = increment_prefix_network(ip.IPv4Interface(str(l2_vlan_ipv4_sec_start) + str(l2_vlan_ipv4_mask)),total_ip_count)
            ip_index=0
            for i in range(0,len(l2_ipv4s)):
                LEAF_2.configure('''int vlan ''' + str(l2_vlan_id) + '''\n
                                 ip address ''' + str(l2_ipv4s[ip_index]) + ''' secondary use-bia
                                 ''')
                l2_vlan_id += 1
                ip_index += 1
                
            
            
        except Exception as error:
            log.debug("Unable to configure - Encountered Exception " + str(error))
            self.errored('Exception occurred while configuring secondary ipv4 address on LEAF-2', goto=['cleanup'])
            
    # =============================================================================================================================#        
    
    @aetest.test
    def SVI_ON_LEAF1(self, testscript):
        """Shut down the vpc leg on Leaf2 to force all traffic to Leaf1"""
        
        LEAF_1 = testscript.parameters['LEAF-1']
        LEAF_2 = testscript.parameters['LEAF-2']
        forwardingSysDict = testscript.parameters['forwardingSysDict']
        l2_vlan_id = testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vlan_start']
        l2_vlan_ipv4_sec_start= testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vlan_ipv4_sec_start']
        l2_vlan_ipv4_mask= testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vlan_ipv4_mask']
        
        try:
            total_ip_count = int(forwardingSysDict['VLAN_PER_VRF_count']) * int(forwardingSysDict['VRF_count'])
            l2_ipv4s = increment_prefix_network(ip.IPv4Interface(str(l2_vlan_ipv4_sec_start) + str(l2_vlan_ipv4_mask)),total_ip_count)
            ip_index=0
            for i in range(0,len(l2_ipv4s)):
                LEAF_1.configure('''int vlan ''' + str(l2_vlan_id) + '''\n
                                 ip address ''' + str(l2_ipv4s[ip_index]) + ''' secondary use-bia
                                 ''')
                l2_vlan_id += 1
                ip_index += 1
                
            
            
        except Exception as error:
            log.debug("Unable to configure - Encountered Exception " + str(error))
            self.errored('Exception occurred while configuring secondary ipv4 address on LEAF-1', goto=['cleanup'])
            
     # =============================================================================================================================#        
    @aetest.test
    def Add_external_int(self, testscript):
        """Shut down the vpc leg on Leaf2 to force all traffic to Leaf1"""
        
        LEAF_1 = testscript.parameters['LEAF-1']
        LEAF_2 = testscript.parameters['LEAF-2']
        
        try:
            testscript.parameters['LEAF-2'].configure('''
                  interface po ''' + str(testscript.parameters['LEAF_1_dict']['VPC_data']['double_vpc_po_1']) + '''
                  port-type external
                  ''')
            
            testscript.parameters['LEAF-1'].configure('''
                  interface po ''' + str(testscript.parameters['LEAF_1_dict']['VPC_data']['double_vpc_po_1']) + '''
                  port-type external
                  ''')    
            
            
        except Exception as error:
            log.debug("Unable to configure - Encountered Exception " + str(error))
            self.errored('Exception occurred while configuring external on LEAF-1 and LEAF-2', goto=['cleanup'])
            
     # =============================================================================================================================#    
    @aetest.test
    def Pre_migration_hsrp(self,testscript):
        LEAF_1 = testscript.parameters['LEAF-1']
        LEAF_2 = testscript.parameters['LEAF-2']
        forwardingSysDict = testscript.parameters['forwardingSysDict']
        l2_vlan_id = testscript.parameters['N7K_LEAF_1_dict']['Vlan_data']['l2_vlan_start']
        l2_vlan_ipv4_start= testscript.parameters['N7K_LEAF_1_dict']['Vlan_data']['l2_vlan_ipv4_start']
        l2_vlan_ipv4_mask= testscript.parameters['N7K_LEAF_1_dict']['Vlan_data']['l2_vlan_ipv4_mask']
        l2_vlan_ipv6_start= testscript.parameters['N7K_LEAF_1_dict']['Vlan_data']['l2_vlan_ipv6_start']
        l2_vlan_ipv6_mask= testscript.parameters['N7K_LEAF_1_dict']['Vlan_data']['l2_vlan_ipv6_mask']
        l2_hsrp_ipv4_vip_start= testscript.parameters['N7K_LEAF_1_dict']['Vlan_data']['hsrp_ipv4_vip_start']
        l2_hsrp_ipv6_vip_start= testscript.parameters['N7K_LEAF_1_dict']['Vlan_data']['hsrp_ipv6_vip_start']
        
        try:
            device_handle=connect_to_vdc(testscript.parameters['xbow1'], 'leaf1')
            if device_handle==False:
                log.info("failed to switchto correct vdc")
                self.failed("failed to switchto correct vdc",goto=['common_cleanup'])
            else:
                total_ip_count = int(forwardingSysDict['VLAN_PER_VRF_count']) * int(forwardingSysDict['VRF_count'])
                l2_ipv4s = increment_prefix_network(ip.IPv4Interface(str(l2_vlan_ipv4_start) + str(l2_vlan_ipv4_mask)),total_ip_count)
                l2_ipv6s = increment_prefix_network(ip.IPv6Interface(str(l2_vlan_ipv6_start) + str(l2_vlan_ipv6_mask)),total_ip_count)
                ip_index=0
                for i in range(0,len(l2_ipv4s)):
                    device_handle.configure('''int vlan ''' + str(l2_vlan_id) + '''\n
                                     hsrp version 2
                                     hsrp ''' + str(l2_vlan_id) + ''' ipv4
                                     mac-address 0000.000a.aaaa
                                     ''')
                    l2_vlan_id += 1
            l2_vlan_id = testscript.parameters['N7K_LEAF_1_dict']['Vlan_data']['l2_vlan_start']        
            device_handle=connect_to_vdc(testscript.parameters['xbow2'], 'leaf2')
            if device_handle==False:
                log.info("failed to switchto correct vdc")
                self.failed("failed to switchto correct vdc",goto=['common_cleanup'])
            else:
                total_ip_count = int(forwardingSysDict['VLAN_PER_VRF_count']) * int(forwardingSysDict['VRF_count'])
                l2_ipv4s = increment_prefix_network(ip.IPv4Interface(str(l2_vlan_ipv4_start) + str(l2_vlan_ipv4_mask)),total_ip_count)
                l2_ipv6s = increment_prefix_network(ip.IPv6Interface(str(l2_vlan_ipv6_start) + str(l2_vlan_ipv6_mask)),total_ip_count)
                ip_index=0
                for i in range(0,len(l2_ipv4s)):
                    device_handle.configure('''int vlan ''' + str(l2_vlan_id) + '''\n
                                     hsrp version 2
                                     hsrp ''' + str(l2_vlan_id) + ''' ipv4
                                     mac-address 0000.000a.aaaa
                                     ''')
                    l2_vlan_id += 1
                    


        except Exception as error:
                log.debug("Unable to configure - Encountered Exception " + str(error))
                self.errored('Exception occurred while configuring on N7k leaf1', goto=['common_cleanup'])
                
    @aetest.test        
    def configure_FO(self,testscript):
        
        FO_1_vlanConfiguration = ""
        FO_1=testscript.parameters['FO_1']

        l3_vrf_count_iter = 0
        l2_vlan_id = testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vlan_start']
        l3_vlan_id = testscript.parameters['LEAF_1_dict']['VNI_data']['l3_vlan_start']

        while l3_vrf_count_iter < testscript.parameters['forwardingSysDict']['VRF_count']:
            l2_vlan_count_iter = 0
            FO_1_vlanConfiguration += '''vlan ''' + str(l3_vlan_id) + '''\n
                                            state active\n
                                            no shut\n'''
            while l2_vlan_count_iter < testscript.parameters['forwardingSysDict']['VLAN_PER_VRF_count']:
                # Incrementing L2 VLAN Iteration counters
                FO_1_vlanConfiguration += '''vlan ''' + str(l2_vlan_id) + '''\n
                                                state active\n
                                                no shut\n'''
                l2_vlan_count_iter += 1
                l2_vlan_id += 1
            # Incrementing L3 VRF Iteration counters
            l3_vrf_count_iter += 1
            l3_vlan_id += 1

        try:
            FO_1.configure(
                str(FO_1_vlanConfiguration) + '''
        
        
            
            interface ''' + str(testscript.parameters['intf_FO_1_to_N7k_LEAF_3']) + '''
            no shut
            switchport
            switchport mode trunk
            
            interface ''' + str(testscript.parameters['intf_FO_1_to_LEAF_3']) + '''
            shut
            switchport
            switchport mode trunk
            
            interface ''' + str(testscript.parameters['intf_FO_1_to_IXIA']) + '''
            no shut
            switchport
            switchport mode trunk
            
            ''')
        except Exception as error:
                log.debug("Unable to configure - Encountered Exception " + str(error))
                self.errored('Exception occurred while configuring on FO_1', goto=['common_cleanup'])
   
#     @aetest.test
#     def CONFIGURE_UCAST_L3_IXIA_TRAFFIC(self, testscript):
#         """ IXIA_CONFIGURATION subsection: Configure MCAST Traffic Item """
# 
#         # Do not perform configurations if skip_tgen_config flag is set
#         if not testscript.parameters['script_flags']['skip_tgen_config']:
# 
#             IX_TP1 = testscript.parameters['IX_TP1']
#             IX_TP2 = testscript.parameters['IX_TP2']
#             P1_dict = testscript.parameters['LEAF_2_TGEN_dict']
#             P2_dict = testscript.parameters['LEAF_3_TGEN_dict']
# 
#             UCAST_v4_dict = {   'src_hndl'  : IX_TP1['port_handle'],
#                                 'dst_hndl'  : IX_TP2['port_handle'],
#                                 'ip_dscp'   : P1_dict['ip_dscp'],
#                                 'circuit'   : 'raw',
#                                 'TI_name'   : "UCAST_L3",
#                                 'rate_pps'  : "9000",
#                                 'bi_dir'    : 1,
#                                 'frame_size': '128',
#                                 'src_mac'   : P1_dict['mac'],
#                                 'dst_mac'   : '0000.000a.aaaa',
#                                 'srcmac_step': '00:00:00:00:00:00',
#                                 'dstmac_step': '00:00:00:00:00:00',
#                                 'srcmac_count': '1',
#                                 'dstmac_count': '1',
#                                 'vlan_id'    : P1_dict['vlan_id'],
#                                 'vlanid_step': '0',
#                                 'vlanid_count': '1',
#                                 'vlan_user_priority': P1_dict['vlan_user_priority'],
#                                 'ip_src_addrs' : P1_dict['v4_addr'],
#                                 'ip_dst_addrs' : P1_dict['L3_dst_addr'],
#                                 'ip_src_step' : '0.0.0.0',
#                                 'ip_dst_step' : '0.0.0.0',
# #                                'ip_step'    : P1_dict['v4_addr_step'],
#                           }
# 
# #            UCAST_v6_dict = {   'src_hndl'  : IX_TP1['ipv6_handle'],
# #                                'dst_hndl'  : IX_TP2['ipv6_handle'],
# #                                'circuit'   : 'ipv6',
# #                                'TI_name'   : "UCAST_V6",
# #                                'rate_pps'  : "1000",
# #                                'bi_dir'    : 1
# #                          }
# 
#             UCAST_v4_TI = ixLib.configure_ixia_l3_traffic_item(UCAST_v4_dict)
# #            UCAST_v6_TI = ixLib.configure_ixia_traffic_item(UCAST_v6_dict)
# 
# #            if UCAST_v4_TI == 0 or UCAST_v6_TI == 0:
# #                log.debug("Configuring UCast TI failed")
# #                self.errored("Configuring UCast TI failed", goto=['cleanup'])
#                 
#             if UCAST_v4_TI == 0:
#                 log.debug("Configuring UCast TI failed")
#                 self.errored("Configuring UCast TI failed", goto=['cleanup'])
#             else:
#                 global stream_id
#                 stream_id = UCAST_v4_TI
#             
# 
#         else:
#             self.passed(reason="Skipped TGEN Configurations as per request")
            
    # @aetest.test
    # def CONFIGURE_BCAST_IXIA_TRAFFIC(self, testscript):
    #     """ IXIA_CONFIGURATION subsection: Configure MCAST Traffic Item """
    # 
    #     # Do not perform configurations if skip_tgen_config flag is set
    #     if not testscript.parameters['script_flags']['skip_tgen_config']:
    # 
    #         IX_TP1 = testscript.parameters['IX_TP1']
    #         IX_TP2 = testscript.parameters['IX_TP2']
    #         P1_dict = testscript.parameters['LEAF_2_TGEN_dict']
    #         P2_dict = testscript.parameters['LEAF_3_TGEN_dict']
    #         BCAST_v4_dict = {
    #                             'src_hndl'      : IX_TP1['port_handle'],
    #                             'dst_hndl'      : IX_TP2['port_handle'],
    #                             'TI_name'       : "BCAST_V4",
    #                             'frame_size'    : "70",
    #                             'rate_pps'      : "1000",
    #                             'src_mac'       : P1_dict['mac'],
    #                             'srcmac_step'   : "00:00:00:00:00:01",
    #                             'srcmac_count'  : '1',
    #                             'vlan_id'       : P1_dict['vlan_id'],
    #                             'vlanid_step'   : "1",
    #                             'vlanid_count'  : "1",
    #                             'ip_src_addrs'  : P1_dict['v4_addr'],
    #                             'ip_step'       : "0.0.1.0",
    #                       }
    # 
    #         BCAST_v4_TI = ixLib.configure_ixia_BCAST_traffic_item(BCAST_v4_dict)
    # 
    #         if BCAST_v4_TI == 0:
    #             log.debug("Configuring BCast TI failed")
    #             self.errored("Configuring BCast TI failed", goto=['cleanup'])
    #         
    # 
    #     else:
    #         self.passed(reason="Skipped TGEN Configurations as per request")
    # =============================================================================================================================#
    @aetest.test
    def APPLY_TRAFFIC(self):
        """ IXIA_CONFIGURATION subsection: Verify IXIA Traffic """

        # # Apply IXIA Traffic
        # if ixLib.apply_traffic() == 1:
        #     log.info("Applying IXIA TI Passed")
        # else:
        #     self.errored("Applying IXIA TI failed", goto=['cleanup'])
            
        # =============================================================================================================================#
    #--------------------------------------------------------------------------------#
        # Start traffic from ixia
        log.info("--- Populating the statistics --- \n")
        log.info("---- Running Traffic --- \n")
        log.info("Starting Traffic")

        traffic_run_status  = ixLib.start_traffic()

        if traffic_run_status is not 1:
           log.info("Failed: To start traffic")
           return 0
        else:
            log.info("\nTraffic started successfully\n")

        time.sleep(30)
    
    # Stop Traffic from ixia
        log.info("--- Stopping Traffic ---- \n")
        log.info("Stopping Traffic")
        traffic_run_status = ixLib.stop_traffic()
        
        if traffic_run_status is not 1:
           log.info("Failed: To Stop traffic")
           return 0
        else:
            log.info("\nTraffic Stopped successfully\n")
            time.sleep(10)    
    
    @aetest.test
    def VERIFY_IXIA_TRAFFIC(self, testscript):
        """ IXIA_CONFIGURATION subsection: Verify IXIA Traffic """

        # Do not perform configurations if skip_tgen_config flag is set
        if not testscript.parameters['script_flags']['skip_tgen_config']:

            time.sleep(20)

            if ixLib.verify_traffic(2) == 0:
                log.debug("Traffic Verification failed")
                self.failed("Traffic Verification failed", goto=['cleanup'])
            else:
                log.info("Traffic Verification Passed")
        else:
            self.passed(reason="Skipped TGEN Configurations as per request")

     # =============================================================================================================================#        
    @aetest.test
    def Clear_ARP_Table_on_Vxlan_BLs(self, testscript):
        """Shut down the vpc leg on Leaf2 to force all traffic to Leaf1"""
        
        LEAF_1 = testscript.parameters['LEAF-1']
        LEAF_2 = testscript.parameters['LEAF-2']
        
        try:
            for i in range(1, testscript.parameters['forwardingSysDict']['VRF_count']+1):
                testscript.parameters['LEAF-2'].execute('''
                      clear ip arp vrf ''' + str(testscript.parameters['forwardingSysDict']['VRF_string']) + str(i) + ''' force-delete''')
            
            for i in range(1, testscript.parameters['forwardingSysDict']['VRF_count']+1):
                testscript.parameters['LEAF-1'].execute('''
                      clear ip arp vrf ''' + str(testscript.parameters['forwardingSysDict']['VRF_string']) + str(i) + ''' force-delete''')    
            
            
        except Exception as error:
            log.debug("Unable to configure - Encountered Exception " + str(error))
            self.errored('Exception occurred while clearing arp cache on LEAF-1 and LEAF-2', goto=['cleanup'])
            
    @aetest.test        
    def Host_move_FO(self,testscript):
        
        
        FO_1=testscript.parameters['FO_1']

        
        try:
            FO_1.configure('''
            interface ''' + str(testscript.parameters['intf_FO_1_to_N7k_LEAF_3']) + '''
            shut
            switchport
            switchport mode trunk
            
            interface ''' + str(testscript.parameters['intf_FO_1_to_LEAF_3']) + '''
            no shut
            switchport
            switchport mode trunk
            
            ''')
            time.sleep(45)
            #ForkedPdb().set_trace()
        except Exception as error:
                log.debug("Unable to configure - Encountered Exception " + str(error))
                self.errored('Exception occurred while configuring on FO_1', goto=['common_cleanup'])
                
    @aetest.test
    def VERIFY_IXIA_TRAFFIC_AFTER_MOVE(self, testscript):
        """ IXIA_CONFIGURATION subsection: Verify IXIA Traffic """

        # Do not perform configurations if skip_tgen_config flag is set
        if not testscript.parameters['script_flags']['skip_tgen_config']:

            time.sleep(20)

            if ixLib.verify_traffic(15) == 0:
                log.debug("Traffic Verification failed")
                self.failed("Traffic Verification failed", goto=['cleanup'])
            else:
                log.info("Traffic Verification Passed")
            
        else:
            self.passed(reason="Skipped TGEN Configurations as per request")
            
# =============================================================================================================================#
    @aetest.test
    def TRIGGER_verify_NVE_process_restart(self, testscript):
        """ NVE_PROCESS_KILL_VERIFICATION subsection: Verify killing process NVE """

        LEAF_1 = testscript.parameters['LEAF-1']
        LEAF_2 = testscript.parameters['LEAF-2']

        if infraTrig.verifyProcessRestart(LEAF_1,"nve"):
            log.info("Successfully restarted process nve on Leaf1")
        else:
            log.debug("Failed to restarted process nve on Leaf1")
            self.failed("Failed to restarted process nve on Leaf1", goto=['cleanup'])
            
        if infraTrig.verifyProcessRestart(LEAF_2,"nve"):
            log.info("Successfully restarted process nve on Leaf2")
        else:
            log.debug("Failed to restarted process nve on Leaf2")
            self.failed("Failed to restarted process nve on Leaf2", goto=['cleanup'])

        time.sleep(120)
    
    @aetest.test
    def VERIFY_IXIA_TRAFFIC_AFTER_nve_Restart(self, testscript):
        """ IXIA_CONFIGURATION subsection: Verify IXIA Traffic """

        # Do not perform configurations if skip_tgen_config flag is set
        if not testscript.parameters['script_flags']['skip_tgen_config']:

            time.sleep(20)

            if ixLib.verify_traffic(2) == 0:
                log.debug("Traffic Verification failed")
                self.failed("Traffic Verification failed", goto=['cleanup'])
            else:
                log.info("Traffic Verification Passed")
        else:
            self.passed(reason="Skipped TGEN Configurations as per request")
            
    @aetest.test        
    def Host_move_FO_BACK(self,testscript):
        
        
        FO_1=testscript.parameters['FO_1']

        
        try:
            FO_1.configure('''
            interface ''' + str(testscript.parameters['intf_FO_1_to_LEAF_3']) + '''
            shut
            switchport
            switchport mode trunk
            
            interface ''' + str(testscript.parameters['intf_FO_1_to_N7k_LEAF_3']) + '''
            no shut
            switchport
            switchport mode trunk
            
            
            
            ''')
            time.sleep(45)
        except Exception as error:
                log.debug("Unable to configure - Encountered Exception " + str(error))
                self.errored('Exception occurred while configuring on FO_1', goto=['common_cleanup'])
                
    @aetest.test
    def VERIFY_IXIA_TRAFFIC_HOST_MOVE_BACK(self, testscript):
        """ IXIA_CONFIGURATION subsection: Verify IXIA Traffic """

        # Do not perform configurations if skip_tgen_config flag is set
        if not testscript.parameters['script_flags']['skip_tgen_config']:

            time.sleep(20)

            if ixLib.verify_traffic(15) == 0:
                log.debug("Traffic Verification failed")
                self.failed("Traffic Verification failed", goto=['cleanup'])
            else:
                log.info("Traffic Verification Passed")
        else:
            self.passed(reason="Skipped TGEN Configurations as per request")
        
    @aetest.cleanup
    def cleanup(self,testscript):
        """Unconfigure qos policies"""
        LEAF_1 = testscript.parameters['LEAF-1']
        LEAF_2 = testscript.parameters['LEAF-2']
        LEAF_3 = testscript.parameters['LEAF-3']
        FO_1=testscript.parameters['FO_1']
        LEAF_1 = testscript.parameters['LEAF-1']
        LEAF_2 = testscript.parameters['LEAF-2']
        forwardingSysDict = testscript.parameters['forwardingSysDict']
        l2_vlan_id = testscript.parameters['N7K_LEAF_1_dict']['Vlan_data']['l2_vlan_start']
        l2_vlan_ipv4_start= testscript.parameters['N7K_LEAF_1_dict']['Vlan_data']['l2_vlan_ipv4_start']
        l2_vlan_ipv4_mask= testscript.parameters['N7K_LEAF_1_dict']['Vlan_data']['l2_vlan_ipv4_mask']
        l2_vlan_ipv6_start= testscript.parameters['N7K_LEAF_1_dict']['Vlan_data']['l2_vlan_ipv6_start']
        l2_vlan_ipv6_mask= testscript.parameters['N7K_LEAF_1_dict']['Vlan_data']['l2_vlan_ipv6_mask']
        l2_hsrp_ipv4_vip_start= testscript.parameters['N7K_LEAF_1_dict']['Vlan_data']['hsrp_ipv4_vip_start']
        l2_hsrp_ipv6_vip_start= testscript.parameters['N7K_LEAF_1_dict']['Vlan_data']['hsrp_ipv6_vip_start']
        
        post_test_process_dict = {
            'dut_list'                       : [LEAF_1, LEAF_2, LEAF_3],
            'cc_check'                  : 1,
            'cores_check'               : 1,
            'logs_check'                : 0,
            'fnl_flag'                  : 0,
            'exclude_log_check_pattern' : 'ERROR_VLANS_SUSPENDED|ERROR_VLANS_REMOVED',
            }
        try:
            # UCAST_v4_dict = {
            #                 'mode'        : 'remove',
            #                 'stream_id'   : stream_id,
            #           }
            # if (ixLib.delete_traffic_item(UCAST_v4_dict))==0:
            #     log.debug("Traffic Remove failed")
            #     self.failed("Traffic Remove failed")
            # else:
            #     log.info("Traffic Deletion Passed")
            
            FO_1.configure('''
            interface ''' + str(testscript.parameters['intf_FO_1_to_LEAF_3']) + '''
            shut
            switchport
            switchport mode trunk
            
            interface ''' + str(testscript.parameters['intf_FO_1_to_N7k_LEAF_3']) + '''
            no shut
            switchport
            switchport mode trunk
            ''')
            time.sleep(30)
            ###Remove Pre-migration step from both N7k leafs
            device_handle=connect_to_vdc(testscript.parameters['xbow1'], 'leaf1')
            if device_handle==False:
                log.info("failed to switchto correct vdc")
                self.failed("failed to switchto correct vdc",goto=['common_cleanup'])
            else:
                total_ip_count = int(forwardingSysDict['VLAN_PER_VRF_count']) * int(forwardingSysDict['VRF_count'])
                l2_ipv4s = increment_prefix_network(ip.IPv4Interface(str(l2_vlan_ipv4_start) + str(l2_vlan_ipv4_mask)),total_ip_count)
                l2_ipv6s = increment_prefix_network(ip.IPv6Interface(str(l2_vlan_ipv6_start) + str(l2_vlan_ipv6_mask)),total_ip_count)
                ip_index=0
                for i in range(0,len(l2_ipv4s)):
                    device_handle.configure('''int vlan ''' + str(l2_vlan_id) + '''\n
                                     hsrp version 2
                                     hsrp ''' + str(l2_vlan_id) + ''' ipv4
                                     no mac-address 0000.000a.aaaa
                                     ''')
                    l2_vlan_id += 1
            l2_vlan_id = testscript.parameters['N7K_LEAF_1_dict']['Vlan_data']['l2_vlan_start']        
            device_handle=connect_to_vdc(testscript.parameters['xbow2'], 'leaf2')
            if device_handle==False:
                log.info("failed to switchto correct vdc")
                self.failed("failed to switchto correct vdc",goto=['common_cleanup'])
            else:
                total_ip_count = int(forwardingSysDict['VLAN_PER_VRF_count']) * int(forwardingSysDict['VRF_count'])
                l2_ipv4s = increment_prefix_network(ip.IPv4Interface(str(l2_vlan_ipv4_start) + str(l2_vlan_ipv4_mask)),total_ip_count)
                l2_ipv6s = increment_prefix_network(ip.IPv6Interface(str(l2_vlan_ipv6_start) + str(l2_vlan_ipv6_mask)),total_ip_count)
                ip_index=0
                for i in range(0,len(l2_ipv4s)):
                    device_handle.configure('''int vlan ''' + str(l2_vlan_id) + '''\n
                                     hsrp version 2
                                     hsrp ''' + str(l2_vlan_id) + ''' ipv4
                                     no mac-address 0000.000a.aaaa
                                     ''')
                    l2_vlan_id += 1
            status = infraVerify.postTestVerification(post_test_process_dict)
            if status['status'] == 0:
                self.failed(reason=status['logs'])
            else:
                self.passed(reason=status['logs'])
        except Exception as error:
            log.debug("Unable to unconfigure class map or policy map-Encountered exception " + str(error))
            self.errored('Exception occurred while unconfiguring qos on LEAF1', goto=['next_tc'])
            
            
# *****************************************************************************************************************************#
class BGP_Restart_post_Host_move_ipv4(aetest.Testcase):
    """ Host_move_ipv4 """

    
    # =============================================================================================================================#        
    
    @aetest.test
    def SVI_ON_LEAF2(self, testscript):
        """Shut down the vpc leg on Leaf2 to force all traffic to Leaf1"""
        
        LEAF_1 = testscript.parameters['LEAF-1']
        LEAF_2 = testscript.parameters['LEAF-2']
        forwardingSysDict = testscript.parameters['forwardingSysDict']
        l2_vlan_id = testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vlan_start']
        l2_vlan_ipv4_sec_start= testscript.parameters['LEAF_2_dict']['VNI_data']['l2_vlan_ipv4_sec_start']
        l2_vlan_ipv4_mask= testscript.parameters['LEAF_2_dict']['VNI_data']['l2_vlan_ipv4_mask']
        #+ str(testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vlan_ipv4_mask'])
        
        try:
            total_ip_count = int(forwardingSysDict['VLAN_PER_VRF_count']) * int(forwardingSysDict['VRF_count'])
            l2_ipv4s = increment_prefix_network(ip.IPv4Interface(str(l2_vlan_ipv4_sec_start) + str(l2_vlan_ipv4_mask)),total_ip_count)
            ip_index=0
            for i in range(0,len(l2_ipv4s)):
                LEAF_2.configure('''int vlan ''' + str(l2_vlan_id) + '''\n
                                 ip address ''' + str(l2_ipv4s[ip_index]) + ''' secondary use-bia
                                 ''')
                l2_vlan_id += 1
                ip_index += 1
                
            
            
        except Exception as error:
            log.debug("Unable to configure - Encountered Exception " + str(error))
            self.errored('Exception occurred while configuring secondary ipv4 address on LEAF-2', goto=['cleanup'])
            
    # =============================================================================================================================#        
    
    @aetest.test
    def SVI_ON_LEAF1(self, testscript):
        """Shut down the vpc leg on Leaf2 to force all traffic to Leaf1"""
        
        LEAF_1 = testscript.parameters['LEAF-1']
        LEAF_2 = testscript.parameters['LEAF-2']
        forwardingSysDict = testscript.parameters['forwardingSysDict']
        l2_vlan_id = testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vlan_start']
        l2_vlan_ipv4_sec_start= testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vlan_ipv4_sec_start']
        l2_vlan_ipv4_mask= testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vlan_ipv4_mask']
        
        try:
            total_ip_count = int(forwardingSysDict['VLAN_PER_VRF_count']) * int(forwardingSysDict['VRF_count'])
            l2_ipv4s = increment_prefix_network(ip.IPv4Interface(str(l2_vlan_ipv4_sec_start) + str(l2_vlan_ipv4_mask)),total_ip_count)
            ip_index=0
            for i in range(0,len(l2_ipv4s)):
                LEAF_1.configure('''int vlan ''' + str(l2_vlan_id) + '''\n
                                 ip address ''' + str(l2_ipv4s[ip_index]) + ''' secondary use-bia
                                 ''')
                l2_vlan_id += 1
                ip_index += 1
                
            
            
        except Exception as error:
            log.debug("Unable to configure - Encountered Exception " + str(error))
            self.errored('Exception occurred while configuring secondary ipv4 address on LEAF-1', goto=['cleanup'])
            
     # =============================================================================================================================#        
    @aetest.test
    def Add_external_int(self, testscript):
        """Shut down the vpc leg on Leaf2 to force all traffic to Leaf1"""
        
        LEAF_1 = testscript.parameters['LEAF-1']
        LEAF_2 = testscript.parameters['LEAF-2']
        
        try:
            testscript.parameters['LEAF-2'].configure('''
                  interface po ''' + str(testscript.parameters['LEAF_1_dict']['VPC_data']['double_vpc_po_1']) + '''
                  port-type external
                  ''')
            
            testscript.parameters['LEAF-1'].configure('''
                  interface po ''' + str(testscript.parameters['LEAF_1_dict']['VPC_data']['double_vpc_po_1']) + '''
                  port-type external
                  ''')    
            
            
        except Exception as error:
            log.debug("Unable to configure - Encountered Exception " + str(error))
            self.errored('Exception occurred while configuring external on LEAF-1 and LEAF-2', goto=['cleanup'])
            
     # =============================================================================================================================#    
    @aetest.test
    def Pre_migration_hsrp(self,testscript):
        LEAF_1 = testscript.parameters['LEAF-1']
        LEAF_2 = testscript.parameters['LEAF-2']
        forwardingSysDict = testscript.parameters['forwardingSysDict']
        l2_vlan_id = testscript.parameters['N7K_LEAF_1_dict']['Vlan_data']['l2_vlan_start']
        l2_vlan_ipv4_start= testscript.parameters['N7K_LEAF_1_dict']['Vlan_data']['l2_vlan_ipv4_start']
        l2_vlan_ipv4_mask= testscript.parameters['N7K_LEAF_1_dict']['Vlan_data']['l2_vlan_ipv4_mask']
        l2_vlan_ipv6_start= testscript.parameters['N7K_LEAF_1_dict']['Vlan_data']['l2_vlan_ipv6_start']
        l2_vlan_ipv6_mask= testscript.parameters['N7K_LEAF_1_dict']['Vlan_data']['l2_vlan_ipv6_mask']
        l2_hsrp_ipv4_vip_start= testscript.parameters['N7K_LEAF_1_dict']['Vlan_data']['hsrp_ipv4_vip_start']
        l2_hsrp_ipv6_vip_start= testscript.parameters['N7K_LEAF_1_dict']['Vlan_data']['hsrp_ipv6_vip_start']
        
        try:
            device_handle=connect_to_vdc(testscript.parameters['xbow1'], 'leaf1')
            if device_handle==False:
                log.info("failed to switchto correct vdc")
                self.failed("failed to switchto correct vdc",goto=['common_cleanup'])
            else:
                total_ip_count = int(forwardingSysDict['VLAN_PER_VRF_count']) * int(forwardingSysDict['VRF_count'])
                l2_ipv4s = increment_prefix_network(ip.IPv4Interface(str(l2_vlan_ipv4_start) + str(l2_vlan_ipv4_mask)),total_ip_count)
                l2_ipv6s = increment_prefix_network(ip.IPv6Interface(str(l2_vlan_ipv6_start) + str(l2_vlan_ipv6_mask)),total_ip_count)
                ip_index=0
                for i in range(0,len(l2_ipv4s)):
                    device_handle.configure('''int vlan ''' + str(l2_vlan_id) + '''\n
                                     hsrp version 2
                                     hsrp ''' + str(l2_vlan_id) + ''' ipv4
                                     mac-address 0000.000a.aaaa
                                     ''')
                    l2_vlan_id += 1
            l2_vlan_id = testscript.parameters['N7K_LEAF_1_dict']['Vlan_data']['l2_vlan_start']        
            device_handle=connect_to_vdc(testscript.parameters['xbow2'], 'leaf2')
            if device_handle==False:
                log.info("failed to switchto correct vdc")
                self.failed("failed to switchto correct vdc",goto=['common_cleanup'])
            else:
                total_ip_count = int(forwardingSysDict['VLAN_PER_VRF_count']) * int(forwardingSysDict['VRF_count'])
                l2_ipv4s = increment_prefix_network(ip.IPv4Interface(str(l2_vlan_ipv4_start) + str(l2_vlan_ipv4_mask)),total_ip_count)
                l2_ipv6s = increment_prefix_network(ip.IPv6Interface(str(l2_vlan_ipv6_start) + str(l2_vlan_ipv6_mask)),total_ip_count)
                ip_index=0
                for i in range(0,len(l2_ipv4s)):
                    device_handle.configure('''int vlan ''' + str(l2_vlan_id) + '''\n
                                     hsrp version 2
                                     hsrp ''' + str(l2_vlan_id) + ''' ipv4
                                     mac-address 0000.000a.aaaa
                                     ''')
                    l2_vlan_id += 1
                    


        except Exception as error:
                log.debug("Unable to configure - Encountered Exception " + str(error))
                self.errored('Exception occurred while configuring on N7k leaf1', goto=['common_cleanup'])
                
    @aetest.test        
    def configure_FO(self,testscript):
        
        FO_1_vlanConfiguration = ""
        FO_1=testscript.parameters['FO_1']

        l3_vrf_count_iter = 0
        l2_vlan_id = testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vlan_start']
        l3_vlan_id = testscript.parameters['LEAF_1_dict']['VNI_data']['l3_vlan_start']

        while l3_vrf_count_iter < testscript.parameters['forwardingSysDict']['VRF_count']:
            l2_vlan_count_iter = 0
            FO_1_vlanConfiguration += '''vlan ''' + str(l3_vlan_id) + '''\n
                                            state active\n
                                            no shut\n'''
            while l2_vlan_count_iter < testscript.parameters['forwardingSysDict']['VLAN_PER_VRF_count']:
                # Incrementing L2 VLAN Iteration counters
                FO_1_vlanConfiguration += '''vlan ''' + str(l2_vlan_id) + '''\n
                                                state active\n
                                                no shut\n'''
                l2_vlan_count_iter += 1
                l2_vlan_id += 1
            # Incrementing L3 VRF Iteration counters
            l3_vrf_count_iter += 1
            l3_vlan_id += 1

        try:
            FO_1.configure(
                str(FO_1_vlanConfiguration) + '''
        
        
            
            interface ''' + str(testscript.parameters['intf_FO_1_to_N7k_LEAF_3']) + '''
            no shut
            switchport
            switchport mode trunk
            
            interface ''' + str(testscript.parameters['intf_FO_1_to_LEAF_3']) + '''
            shut
            switchport
            switchport mode trunk
            
            interface ''' + str(testscript.parameters['intf_FO_1_to_IXIA']) + '''
            no shut
            switchport
            switchport mode trunk
            
            ''')
        except Exception as error:
                log.debug("Unable to configure - Encountered Exception " + str(error))
                self.errored('Exception occurred while configuring on FO_1', goto=['common_cleanup'])
   
#     @aetest.test
#     def CONFIGURE_UCAST_L3_IXIA_TRAFFIC(self, testscript):
#         """ IXIA_CONFIGURATION subsection: Configure MCAST Traffic Item """
# 
#         # Do not perform configurations if skip_tgen_config flag is set
#         if not testscript.parameters['script_flags']['skip_tgen_config']:
# 
#             IX_TP1 = testscript.parameters['IX_TP1']
#             IX_TP2 = testscript.parameters['IX_TP2']
#             P1_dict = testscript.parameters['LEAF_2_TGEN_dict']
#             P2_dict = testscript.parameters['LEAF_3_TGEN_dict']
# 
#             UCAST_v4_dict = {   'src_hndl'  : IX_TP1['port_handle'],
#                                 'dst_hndl'  : IX_TP2['port_handle'],
#                                 'ip_dscp'   : P1_dict['ip_dscp'],
#                                 'circuit'   : 'raw',
#                                 'TI_name'   : "UCAST_L3",
#                                 'rate_pps'  : "9000",
#                                 'bi_dir'    : 1,
#                                 'frame_size': '128',
#                                 'src_mac'   : P1_dict['mac'],
#                                 'dst_mac'   : '0000.000a.aaaa',
#                                 'srcmac_step': '00:00:00:00:00:00',
#                                 'dstmac_step': '00:00:00:00:00:00',
#                                 'srcmac_count': '1',
#                                 'dstmac_count': '1',
#                                 'vlan_id'    : P1_dict['vlan_id'],
#                                 'vlanid_step': '0',
#                                 'vlanid_count': '1',
#                                 'vlan_user_priority': P1_dict['vlan_user_priority'],
#                                 'ip_src_addrs' : P1_dict['v4_addr'],
#                                 'ip_dst_addrs' : P1_dict['L3_dst_addr'],
#                                 'ip_src_step' : '0.0.0.0',
#                                 'ip_dst_step' : '0.0.0.0',
# #                                'ip_step'    : P1_dict['v4_addr_step'],
#                           }
# 
# #            UCAST_v6_dict = {   'src_hndl'  : IX_TP1['ipv6_handle'],
# #                                'dst_hndl'  : IX_TP2['ipv6_handle'],
# #                                'circuit'   : 'ipv6',
# #                                'TI_name'   : "UCAST_V6",
# #                                'rate_pps'  : "1000",
# #                                'bi_dir'    : 1
# #                          }
# 
#             UCAST_v4_TI = ixLib.configure_ixia_l3_traffic_item(UCAST_v4_dict)
# #            UCAST_v6_TI = ixLib.configure_ixia_traffic_item(UCAST_v6_dict)
# 
# #            if UCAST_v4_TI == 0 or UCAST_v6_TI == 0:
# #                log.debug("Configuring UCast TI failed")
# #                self.errored("Configuring UCast TI failed", goto=['cleanup'])
#                 
#             if UCAST_v4_TI == 0:
#                 log.debug("Configuring UCast TI failed")
#                 self.errored("Configuring UCast TI failed", goto=['cleanup'])
#             else:
#                 global stream_id
#                 stream_id = UCAST_v4_TI
#             
# 
#         else:
#             self.passed(reason="Skipped TGEN Configurations as per request")
            
    # @aetest.test
    # def CONFIGURE_BCAST_IXIA_TRAFFIC(self, testscript):
    #     """ IXIA_CONFIGURATION subsection: Configure MCAST Traffic Item """
    # 
    #     # Do not perform configurations if skip_tgen_config flag is set
    #     if not testscript.parameters['script_flags']['skip_tgen_config']:
    # 
    #         IX_TP1 = testscript.parameters['IX_TP1']
    #         IX_TP2 = testscript.parameters['IX_TP2']
    #         P1_dict = testscript.parameters['LEAF_2_TGEN_dict']
    #         P2_dict = testscript.parameters['LEAF_3_TGEN_dict']
    #         BCAST_v4_dict = {
    #                             'src_hndl'      : IX_TP1['port_handle'],
    #                             'dst_hndl'      : IX_TP2['port_handle'],
    #                             'TI_name'       : "BCAST_V4",
    #                             'frame_size'    : "70",
    #                             'rate_pps'      : "1000",
    #                             'src_mac'       : P1_dict['mac'],
    #                             'srcmac_step'   : "00:00:00:00:00:01",
    #                             'srcmac_count'  : '1',
    #                             'vlan_id'       : P1_dict['vlan_id'],
    #                             'vlanid_step'   : "1",
    #                             'vlanid_count'  : "1",
    #                             'ip_src_addrs'  : P1_dict['v4_addr'],
    #                             'ip_step'       : "0.0.1.0",
    #                       }
    # 
    #         BCAST_v4_TI = ixLib.configure_ixia_BCAST_traffic_item(BCAST_v4_dict)
    # 
    #         if BCAST_v4_TI == 0:
    #             log.debug("Configuring BCast TI failed")
    #             self.errored("Configuring BCast TI failed", goto=['cleanup'])
    #         
    # 
    #     else:
    #         self.passed(reason="Skipped TGEN Configurations as per request")
    # =============================================================================================================================#
    @aetest.test
    def APPLY_TRAFFIC(self):
        """ IXIA_CONFIGURATION subsection: Verify IXIA Traffic """

        # # Apply IXIA Traffic
        # if ixLib.apply_traffic() == 1:
        #     log.info("Applying IXIA TI Passed")
        # else:
        #     self.errored("Applying IXIA TI failed", goto=['cleanup'])
            
        # =============================================================================================================================#
    #--------------------------------------------------------------------------------#
        # Start traffic from ixia
        log.info("--- Populating the statistics --- \n")
        log.info("---- Running Traffic --- \n")
        log.info("Starting Traffic")

        traffic_run_status  = ixLib.start_traffic()

        if traffic_run_status is not 1:
           log.info("Failed: To start traffic")
           return 0
        else:
            log.info("\nTraffic started successfully\n")

        time.sleep(30)
    
    # Stop Traffic from ixia
        log.info("--- Stopping Traffic ---- \n")
        log.info("Stopping Traffic")
        traffic_run_status = ixLib.stop_traffic()
        
        if traffic_run_status is not 1:
           log.info("Failed: To Stop traffic")
           return 0
        else:
            log.info("\nTraffic Stopped successfully\n")
            time.sleep(10)    
    
    @aetest.test
    def VERIFY_IXIA_TRAFFIC(self, testscript):
        """ IXIA_CONFIGURATION subsection: Verify IXIA Traffic """

        # Do not perform configurations if skip_tgen_config flag is set
        if not testscript.parameters['script_flags']['skip_tgen_config']:

            time.sleep(20)

            if ixLib.verify_traffic(2) == 0:
                log.debug("Traffic Verification failed")
                self.failed("Traffic Verification failed", goto=['cleanup'])
            else:
                log.info("Traffic Verification Passed")
        else:
            self.passed(reason="Skipped TGEN Configurations as per request")

     # =============================================================================================================================#        
    @aetest.test
    def Clear_ARP_Table_on_Vxlan_BLs(self, testscript):
        """Shut down the vpc leg on Leaf2 to force all traffic to Leaf1"""
        
        LEAF_1 = testscript.parameters['LEAF-1']
        LEAF_2 = testscript.parameters['LEAF-2']
        
        try:
            for i in range(1, testscript.parameters['forwardingSysDict']['VRF_count']+1):
                testscript.parameters['LEAF-2'].execute('''
                      clear ip arp vrf ''' + str(testscript.parameters['forwardingSysDict']['VRF_string']) + str(i) + ''' force-delete''')
            
            for i in range(1, testscript.parameters['forwardingSysDict']['VRF_count']+1):
                testscript.parameters['LEAF-1'].execute('''
                      clear ip arp vrf ''' + str(testscript.parameters['forwardingSysDict']['VRF_string']) + str(i) + ''' force-delete''')    
            
            
        except Exception as error:
            log.debug("Unable to configure - Encountered Exception " + str(error))
            self.errored('Exception occurred while clearing arp cache on LEAF-1 and LEAF-2', goto=['cleanup'])
            
    @aetest.test        
    def Host_move_FO(self,testscript):
        
        
        FO_1=testscript.parameters['FO_1']

        
        try:
            FO_1.configure('''
            interface ''' + str(testscript.parameters['intf_FO_1_to_N7k_LEAF_3']) + '''
            shut
            switchport
            switchport mode trunk
            
            interface ''' + str(testscript.parameters['intf_FO_1_to_LEAF_3']) + '''
            no shut
            switchport
            switchport mode trunk
            
            ''')
            time.sleep(45)
            #ForkedPdb().set_trace()
        except Exception as error:
                log.debug("Unable to configure - Encountered Exception " + str(error))
                self.errored('Exception occurred while configuring on FO_1', goto=['common_cleanup'])
                
    @aetest.test
    def VERIFY_IXIA_TRAFFIC_AFTER_MOVE(self, testscript):
        """ IXIA_CONFIGURATION subsection: Verify IXIA Traffic """

        # Do not perform configurations if skip_tgen_config flag is set
        if not testscript.parameters['script_flags']['skip_tgen_config']:

            time.sleep(20)

            if ixLib.verify_traffic(15) == 0:
                log.debug("Traffic Verification failed")
                self.failed("Traffic Verification failed", goto=['cleanup'])
            else:
                log.info("Traffic Verification Passed")
            
        else:
            self.passed(reason="Skipped TGEN Configurations as per request")
            
# =============================================================================================================================#
    @aetest.test
    def TRIGGER_verify_bgp_process_restart(self, testscript):
        """ BGP_PROCESS_KILL_VERIFICATION subsection: Verify killing process BGP """

        LEAF_1 = testscript.parameters['LEAF-1']
        LEAF_2 = testscript.parameters['LEAF-2']

        if infraTrig.verifyProcessRestart(LEAF_1,"bgp"):
            log.info("Successfully restarted process bgp on Leaf1")
        else:
            log.debug("Failed to restarted process bgp on Leaf1")
            self.failed("Failed to restarted process bgp on Leaf1", goto=['cleanup'])
            
        if infraTrig.verifyProcessRestart(LEAF_2,"bgp"):
            log.info("Successfully restarted process bgp on Leaf2")
        else:
            log.debug("Failed to restarted process bgp on Leaf2")
            self.failed("Failed to restarted process bgp on Leaf2", goto=['cleanup'])

        time.sleep(120)
    
    @aetest.test
    def VERIFY_IXIA_TRAFFIC_AFTER_bgp_Restart(self, testscript):
        """ IXIA_CONFIGURATION subsection: Verify IXIA Traffic """

        # Do not perform configurations if skip_tgen_config flag is set
        if not testscript.parameters['script_flags']['skip_tgen_config']:

            time.sleep(20)

            if ixLib.verify_traffic(2) == 0:
                log.debug("Traffic Verification failed")
                self.failed("Traffic Verification failed", goto=['cleanup'])
            else:
                log.info("Traffic Verification Passed")
        else:
            self.passed(reason="Skipped TGEN Configurations as per request")
            
    @aetest.test        
    def Host_move_FO_BACK(self,testscript):
        
        
        FO_1=testscript.parameters['FO_1']

        
        try:
            FO_1.configure('''
            interface ''' + str(testscript.parameters['intf_FO_1_to_LEAF_3']) + '''
            shut
            switchport
            switchport mode trunk
            
            interface ''' + str(testscript.parameters['intf_FO_1_to_N7k_LEAF_3']) + '''
            no shut
            switchport
            switchport mode trunk
            
            
            
            ''')
            time.sleep(45)
        except Exception as error:
                log.debug("Unable to configure - Encountered Exception " + str(error))
                self.errored('Exception occurred while configuring on FO_1', goto=['common_cleanup'])
                
    @aetest.test
    def VERIFY_IXIA_TRAFFIC_HOST_MOVE_BACK(self, testscript):
        """ IXIA_CONFIGURATION subsection: Verify IXIA Traffic """

        # Do not perform configurations if skip_tgen_config flag is set
        if not testscript.parameters['script_flags']['skip_tgen_config']:

            time.sleep(20)

            if ixLib.verify_traffic(15) == 0:
                log.debug("Traffic Verification failed")
                self.failed("Traffic Verification failed", goto=['cleanup'])
            else:
                log.info("Traffic Verification Passed")
        else:
            self.passed(reason="Skipped TGEN Configurations as per request")
        
    @aetest.cleanup
    def cleanup(self,testscript):
        """Unconfigure qos policies"""
        LEAF_1 = testscript.parameters['LEAF-1']
        LEAF_2 = testscript.parameters['LEAF-2']
        LEAF_3 = testscript.parameters['LEAF-3']
        FO_1=testscript.parameters['FO_1']
        LEAF_1 = testscript.parameters['LEAF-1']
        LEAF_2 = testscript.parameters['LEAF-2']
        forwardingSysDict = testscript.parameters['forwardingSysDict']
        l2_vlan_id = testscript.parameters['N7K_LEAF_1_dict']['Vlan_data']['l2_vlan_start']
        l2_vlan_ipv4_start= testscript.parameters['N7K_LEAF_1_dict']['Vlan_data']['l2_vlan_ipv4_start']
        l2_vlan_ipv4_mask= testscript.parameters['N7K_LEAF_1_dict']['Vlan_data']['l2_vlan_ipv4_mask']
        l2_vlan_ipv6_start= testscript.parameters['N7K_LEAF_1_dict']['Vlan_data']['l2_vlan_ipv6_start']
        l2_vlan_ipv6_mask= testscript.parameters['N7K_LEAF_1_dict']['Vlan_data']['l2_vlan_ipv6_mask']
        l2_hsrp_ipv4_vip_start= testscript.parameters['N7K_LEAF_1_dict']['Vlan_data']['hsrp_ipv4_vip_start']
        l2_hsrp_ipv6_vip_start= testscript.parameters['N7K_LEAF_1_dict']['Vlan_data']['hsrp_ipv6_vip_start']
        
        post_test_process_dict = {
            'dut_list'                       : [LEAF_1, LEAF_2, LEAF_3],
            'cc_check'                  : 1,
            'cores_check'               : 1,
            'logs_check'                : 0,
            'fnl_flag'                  : 0,
            'exclude_log_check_pattern' : 'ERROR_VLANS_SUSPENDED|ERROR_VLANS_REMOVED',
            }
        try:
            # UCAST_v4_dict = {
            #                 'mode'        : 'remove',
            #                 'stream_id'   : stream_id,
            #           }
            # if (ixLib.delete_traffic_item(UCAST_v4_dict))==0:
            #     log.debug("Traffic Remove failed")
            #     self.failed("Traffic Remove failed")
            # else:
            #     log.info("Traffic Deletion Passed")
            
            FO_1.configure('''
            interface ''' + str(testscript.parameters['intf_FO_1_to_LEAF_3']) + '''
            shut
            switchport
            switchport mode trunk
            
            interface ''' + str(testscript.parameters['intf_FO_1_to_N7k_LEAF_3']) + '''
            no shut
            switchport
            switchport mode trunk
            ''')
            time.sleep(30)
            ###Remove Pre-migration step from both N7k leafs
            device_handle=connect_to_vdc(testscript.parameters['xbow1'], 'leaf1')
            if device_handle==False:
                log.info("failed to switchto correct vdc")
                self.failed("failed to switchto correct vdc",goto=['common_cleanup'])
            else:
                total_ip_count = int(forwardingSysDict['VLAN_PER_VRF_count']) * int(forwardingSysDict['VRF_count'])
                l2_ipv4s = increment_prefix_network(ip.IPv4Interface(str(l2_vlan_ipv4_start) + str(l2_vlan_ipv4_mask)),total_ip_count)
                l2_ipv6s = increment_prefix_network(ip.IPv6Interface(str(l2_vlan_ipv6_start) + str(l2_vlan_ipv6_mask)),total_ip_count)
                ip_index=0
                for i in range(0,len(l2_ipv4s)):
                    device_handle.configure('''int vlan ''' + str(l2_vlan_id) + '''\n
                                     hsrp version 2
                                     hsrp ''' + str(l2_vlan_id) + ''' ipv4
                                     no mac-address 0000.000a.aaaa
                                     ''')
                    l2_vlan_id += 1
            l2_vlan_id = testscript.parameters['N7K_LEAF_1_dict']['Vlan_data']['l2_vlan_start']        
            device_handle=connect_to_vdc(testscript.parameters['xbow2'], 'leaf2')
            if device_handle==False:
                log.info("failed to switchto correct vdc")
                self.failed("failed to switchto correct vdc",goto=['common_cleanup'])
            else:
                total_ip_count = int(forwardingSysDict['VLAN_PER_VRF_count']) * int(forwardingSysDict['VRF_count'])
                l2_ipv4s = increment_prefix_network(ip.IPv4Interface(str(l2_vlan_ipv4_start) + str(l2_vlan_ipv4_mask)),total_ip_count)
                l2_ipv6s = increment_prefix_network(ip.IPv6Interface(str(l2_vlan_ipv6_start) + str(l2_vlan_ipv6_mask)),total_ip_count)
                ip_index=0
                for i in range(0,len(l2_ipv4s)):
                    device_handle.configure('''int vlan ''' + str(l2_vlan_id) + '''\n
                                     hsrp version 2
                                     hsrp ''' + str(l2_vlan_id) + ''' ipv4
                                     no mac-address 0000.000a.aaaa
                                     ''')
                    l2_vlan_id += 1
            status = infraVerify.postTestVerification(post_test_process_dict)
            if status['status'] == 0:
                self.failed(reason=status['logs'])
            else:
                self.passed(reason=status['logs'])
        except Exception as error:
            log.debug("Unable to unconfigure class map or policy map-Encountered exception " + str(error))
            self.errored('Exception occurred while unconfiguring qos on LEAF1', goto=['next_tc'])
            
# *****************************************************************************************************************************#
class SVI_FLAP_post_Host_move_ipv4(aetest.Testcase):
    """ Host_move_ipv4 """

    
    # =============================================================================================================================#        
    
    @aetest.test
    def SVI_ON_LEAF2(self, testscript):
        """Shut down the vpc leg on Leaf2 to force all traffic to Leaf1"""
        
        LEAF_1 = testscript.parameters['LEAF-1']
        LEAF_2 = testscript.parameters['LEAF-2']
        forwardingSysDict = testscript.parameters['forwardingSysDict']
        l2_vlan_id = testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vlan_start']
        l2_vlan_ipv4_sec_start= testscript.parameters['LEAF_2_dict']['VNI_data']['l2_vlan_ipv4_sec_start']
        l2_vlan_ipv4_mask= testscript.parameters['LEAF_2_dict']['VNI_data']['l2_vlan_ipv4_mask']
        #+ str(testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vlan_ipv4_mask'])
        
        try:
            total_ip_count = int(forwardingSysDict['VLAN_PER_VRF_count']) * int(forwardingSysDict['VRF_count'])
            l2_ipv4s = increment_prefix_network(ip.IPv4Interface(str(l2_vlan_ipv4_sec_start) + str(l2_vlan_ipv4_mask)),total_ip_count)
            ip_index=0
            for i in range(0,len(l2_ipv4s)):
                LEAF_2.configure('''int vlan ''' + str(l2_vlan_id) + '''\n
                                 ip address ''' + str(l2_ipv4s[ip_index]) + ''' secondary use-bia
                                 no shut
                                 ''')
                l2_vlan_id += 1
                ip_index += 1
            
            
        except Exception as error:
            log.debug("Unable to configure - Encountered Exception " + str(error))
            self.errored('Exception occurred while configuring secondary ipv4 address on LEAF-2', goto=['cleanup'])
            
    # =============================================================================================================================#        
    
    @aetest.test
    def SVI_ON_LEAF1(self, testscript):
        """Shut down the vpc leg on Leaf2 to force all traffic to Leaf1"""
        
        LEAF_1 = testscript.parameters['LEAF-1']
        LEAF_2 = testscript.parameters['LEAF-2']
        forwardingSysDict = testscript.parameters['forwardingSysDict']
        l2_vlan_id = testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vlan_start']
        l2_vlan_ipv4_sec_start= testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vlan_ipv4_sec_start']
        l2_vlan_ipv4_mask= testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vlan_ipv4_mask']
        
        try:
            total_ip_count = int(forwardingSysDict['VLAN_PER_VRF_count']) * int(forwardingSysDict['VRF_count'])
            l2_ipv4s = increment_prefix_network(ip.IPv4Interface(str(l2_vlan_ipv4_sec_start) + str(l2_vlan_ipv4_mask)),total_ip_count)
            ip_index=0
            for i in range(0,len(l2_ipv4s)):
                LEAF_1.configure('''int vlan ''' + str(l2_vlan_id) + '''\n
                                 ip address ''' + str(l2_ipv4s[ip_index]) + ''' secondary use-bia
                                 no shut
                                 ''')
                l2_vlan_id += 1
                ip_index += 1
                
            
            
        except Exception as error:
            log.debug("Unable to configure - Encountered Exception " + str(error))
            self.errored('Exception occurred while configuring secondary ipv4 address on LEAF-1', goto=['cleanup'])
            
     # =============================================================================================================================#        
    @aetest.test
    def Add_external_int(self, testscript):
        """Shut down the vpc leg on Leaf2 to force all traffic to Leaf1"""
        
        LEAF_1 = testscript.parameters['LEAF-1']
        LEAF_2 = testscript.parameters['LEAF-2']
        
        try:
            testscript.parameters['LEAF-2'].configure('''
                  interface po ''' + str(testscript.parameters['LEAF_1_dict']['VPC_data']['double_vpc_po_1']) + '''
                  port-type external
                  ''')
            
            testscript.parameters['LEAF-1'].configure('''
                  interface po ''' + str(testscript.parameters['LEAF_1_dict']['VPC_data']['double_vpc_po_1']) + '''
                  port-type external
                  ''')    
            
            
        except Exception as error:
            log.debug("Unable to configure - Encountered Exception " + str(error))
            self.errored('Exception occurred while configuring external on LEAF-1 and LEAF-2', goto=['cleanup'])
            
     # =============================================================================================================================#    
    @aetest.test
    def Pre_migration_hsrp(self,testscript):
        LEAF_1 = testscript.parameters['LEAF-1']
        LEAF_2 = testscript.parameters['LEAF-2']
        forwardingSysDict = testscript.parameters['forwardingSysDict']
        l2_vlan_id = testscript.parameters['N7K_LEAF_1_dict']['Vlan_data']['l2_vlan_start']
        l2_vlan_ipv4_start= testscript.parameters['N7K_LEAF_1_dict']['Vlan_data']['l2_vlan_ipv4_start']
        l2_vlan_ipv4_mask= testscript.parameters['N7K_LEAF_1_dict']['Vlan_data']['l2_vlan_ipv4_mask']
        l2_vlan_ipv6_start= testscript.parameters['N7K_LEAF_1_dict']['Vlan_data']['l2_vlan_ipv6_start']
        l2_vlan_ipv6_mask= testscript.parameters['N7K_LEAF_1_dict']['Vlan_data']['l2_vlan_ipv6_mask']
        l2_hsrp_ipv4_vip_start= testscript.parameters['N7K_LEAF_1_dict']['Vlan_data']['hsrp_ipv4_vip_start']
        l2_hsrp_ipv6_vip_start= testscript.parameters['N7K_LEAF_1_dict']['Vlan_data']['hsrp_ipv6_vip_start']
        
        try:
            device_handle=connect_to_vdc(testscript.parameters['xbow1'], 'leaf1')
            if device_handle==False:
                log.info("failed to switchto correct vdc")
                self.failed("failed to switchto correct vdc",goto=['common_cleanup'])
            else:
                total_ip_count = int(forwardingSysDict['VLAN_PER_VRF_count']) * int(forwardingSysDict['VRF_count'])
                l2_ipv4s = increment_prefix_network(ip.IPv4Interface(str(l2_vlan_ipv4_start) + str(l2_vlan_ipv4_mask)),total_ip_count)
                l2_ipv6s = increment_prefix_network(ip.IPv6Interface(str(l2_vlan_ipv6_start) + str(l2_vlan_ipv6_mask)),total_ip_count)
                ip_index=0
                for i in range(0,len(l2_ipv4s)):
                    device_handle.configure('''int vlan ''' + str(l2_vlan_id) + '''\n
                                     hsrp version 2
                                     hsrp ''' + str(l2_vlan_id) + ''' ipv4
                                     mac-address 0000.000a.aaaa
                                     ''')
                    l2_vlan_id += 1
            l2_vlan_id = testscript.parameters['N7K_LEAF_1_dict']['Vlan_data']['l2_vlan_start']        
            device_handle=connect_to_vdc(testscript.parameters['xbow2'], 'leaf2')
            if device_handle==False:
                log.info("failed to switchto correct vdc")
                self.failed("failed to switchto correct vdc",goto=['common_cleanup'])
            else:
                total_ip_count = int(forwardingSysDict['VLAN_PER_VRF_count']) * int(forwardingSysDict['VRF_count'])
                l2_ipv4s = increment_prefix_network(ip.IPv4Interface(str(l2_vlan_ipv4_start) + str(l2_vlan_ipv4_mask)),total_ip_count)
                l2_ipv6s = increment_prefix_network(ip.IPv6Interface(str(l2_vlan_ipv6_start) + str(l2_vlan_ipv6_mask)),total_ip_count)
                ip_index=0
                for i in range(0,len(l2_ipv4s)):
                    device_handle.configure('''int vlan ''' + str(l2_vlan_id) + '''\n
                                     hsrp version 2
                                     hsrp ''' + str(l2_vlan_id) + ''' ipv4
                                     mac-address 0000.000a.aaaa
                                     ''')
                    l2_vlan_id += 1
                    


        except Exception as error:
                log.debug("Unable to configure - Encountered Exception " + str(error))
                self.errored('Exception occurred while configuring on N7k leaf1', goto=['common_cleanup'])
                
    @aetest.test        
    def configure_FO(self,testscript):
        
        FO_1_vlanConfiguration = ""
        FO_1=testscript.parameters['FO_1']

        l3_vrf_count_iter = 0
        l2_vlan_id = testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vlan_start']
        l3_vlan_id = testscript.parameters['LEAF_1_dict']['VNI_data']['l3_vlan_start']

        while l3_vrf_count_iter < testscript.parameters['forwardingSysDict']['VRF_count']:
            l2_vlan_count_iter = 0
            FO_1_vlanConfiguration += '''vlan ''' + str(l3_vlan_id) + '''\n
                                            state active\n
                                            no shut\n'''
            while l2_vlan_count_iter < testscript.parameters['forwardingSysDict']['VLAN_PER_VRF_count']:
                # Incrementing L2 VLAN Iteration counters
                FO_1_vlanConfiguration += '''vlan ''' + str(l2_vlan_id) + '''\n
                                                state active\n
                                                no shut\n'''
                l2_vlan_count_iter += 1
                l2_vlan_id += 1
            # Incrementing L3 VRF Iteration counters
            l3_vrf_count_iter += 1
            l3_vlan_id += 1

        try:
            FO_1.configure(
                str(FO_1_vlanConfiguration) + '''
        
        
            
            interface ''' + str(testscript.parameters['intf_FO_1_to_N7k_LEAF_3']) + '''
            no shut
            switchport
            switchport mode trunk
            
            interface ''' + str(testscript.parameters['intf_FO_1_to_LEAF_3']) + '''
            shut
            switchport
            switchport mode trunk
            
            interface ''' + str(testscript.parameters['intf_FO_1_to_IXIA']) + '''
            no shut
            switchport
            switchport mode trunk
            
            ''')
        except Exception as error:
                log.debug("Unable to configure - Encountered Exception " + str(error))
                self.errored('Exception occurred while configuring on FO_1', goto=['common_cleanup'])
   
#     @aetest.test
#     def CONFIGURE_UCAST_L3_IXIA_TRAFFIC(self, testscript):
#         """ IXIA_CONFIGURATION subsection: Configure MCAST Traffic Item """
# 
#         # Do not perform configurations if skip_tgen_config flag is set
#         if not testscript.parameters['script_flags']['skip_tgen_config']:
# 
#             IX_TP1 = testscript.parameters['IX_TP1']
#             IX_TP2 = testscript.parameters['IX_TP2']
#             P1_dict = testscript.parameters['LEAF_2_TGEN_dict']
#             P2_dict = testscript.parameters['LEAF_3_TGEN_dict']
# 
#             UCAST_v4_dict = {   'src_hndl'  : IX_TP1['port_handle'],
#                                 'dst_hndl'  : IX_TP2['port_handle'],
#                                 'ip_dscp'   : P1_dict['ip_dscp'],
#                                 'circuit'   : 'raw',
#                                 'TI_name'   : "UCAST_L3",
#                                 'rate_pps'  : "9000",
#                                 'bi_dir'    : 1,
#                                 'frame_size': '128',
#                                 'src_mac'   : P1_dict['mac'],
#                                 'dst_mac'   : '0000.000a.aaaa',
#                                 'srcmac_step': '00:00:00:00:00:00',
#                                 'dstmac_step': '00:00:00:00:00:00',
#                                 'srcmac_count': '1',
#                                 'dstmac_count': '1',
#                                 'vlan_id'    : P1_dict['vlan_id'],
#                                 'vlanid_step': '0',
#                                 'vlanid_count': '1',
#                                 'vlan_user_priority': P1_dict['vlan_user_priority'],
#                                 'ip_src_addrs' : P1_dict['v4_addr'],
#                                 'ip_dst_addrs' : P1_dict['L3_dst_addr'],
#                                 'ip_src_step' : '0.0.0.0',
#                                 'ip_dst_step' : '0.0.0.0',
# #                                'ip_step'    : P1_dict['v4_addr_step'],
#                           }
# 
# #            UCAST_v6_dict = {   'src_hndl'  : IX_TP1['ipv6_handle'],
# #                                'dst_hndl'  : IX_TP2['ipv6_handle'],
# #                                'circuit'   : 'ipv6',
# #                                'TI_name'   : "UCAST_V6",
# #                                'rate_pps'  : "1000",
# #                                'bi_dir'    : 1
# #                          }
# 
#             UCAST_v4_TI = ixLib.configure_ixia_l3_traffic_item(UCAST_v4_dict)
# #            UCAST_v6_TI = ixLib.configure_ixia_traffic_item(UCAST_v6_dict)
# 
# #            if UCAST_v4_TI == 0 or UCAST_v6_TI == 0:
# #                log.debug("Configuring UCast TI failed")
# #                self.errored("Configuring UCast TI failed", goto=['cleanup'])
#                 
#             if UCAST_v4_TI == 0:
#                 log.debug("Configuring UCast TI failed")
#                 self.errored("Configuring UCast TI failed", goto=['cleanup'])
#             else:
#                 global stream_id
#                 stream_id = UCAST_v4_TI
#             
# 
#         else:
#             self.passed(reason="Skipped TGEN Configurations as per request")
            
    # @aetest.test
    # def CONFIGURE_BCAST_IXIA_TRAFFIC(self, testscript):
    #     """ IXIA_CONFIGURATION subsection: Configure MCAST Traffic Item """
    # 
    #     # Do not perform configurations if skip_tgen_config flag is set
    #     if not testscript.parameters['script_flags']['skip_tgen_config']:
    # 
    #         IX_TP1 = testscript.parameters['IX_TP1']
    #         IX_TP2 = testscript.parameters['IX_TP2']
    #         P1_dict = testscript.parameters['LEAF_2_TGEN_dict']
    #         P2_dict = testscript.parameters['LEAF_3_TGEN_dict']
    #         BCAST_v4_dict = {
    #                             'src_hndl'      : IX_TP1['port_handle'],
    #                             'dst_hndl'      : IX_TP2['port_handle'],
    #                             'TI_name'       : "BCAST_V4",
    #                             'frame_size'    : "70",
    #                             'rate_pps'      : "1000",
    #                             'src_mac'       : P1_dict['mac'],
    #                             'srcmac_step'   : "00:00:00:00:00:01",
    #                             'srcmac_count'  : '1',
    #                             'vlan_id'       : P1_dict['vlan_id'],
    #                             'vlanid_step'   : "1",
    #                             'vlanid_count'  : "1",
    #                             'ip_src_addrs'  : P1_dict['v4_addr'],
    #                             'ip_step'       : "0.0.1.0",
    #                       }
    # 
    #         BCAST_v4_TI = ixLib.configure_ixia_BCAST_traffic_item(BCAST_v4_dict)
    # 
    #         if BCAST_v4_TI == 0:
    #             log.debug("Configuring BCast TI failed")
    #             self.errored("Configuring BCast TI failed", goto=['cleanup'])
    #         
    # 
    #     else:
    #         self.passed(reason="Skipped TGEN Configurations as per request")
    # =============================================================================================================================#
    @aetest.test
    def APPLY_TRAFFIC(self):
        """ IXIA_CONFIGURATION subsection: Verify IXIA Traffic """

        # # Apply IXIA Traffic
        # if ixLib.apply_traffic() == 1:
        #     log.info("Applying IXIA TI Passed")
        # else:
        #     self.errored("Applying IXIA TI failed", goto=['cleanup'])
            
        # =============================================================================================================================#
    #--------------------------------------------------------------------------------#
        # Start traffic from ixia
        log.info("--- Populating the statistics --- \n")
        log.info("---- Running Traffic --- \n")
        log.info("Starting Traffic")

        traffic_run_status  = ixLib.start_traffic()

        if traffic_run_status is not 1:
           log.info("Failed: To start traffic")
           return 0
        else:
            log.info("\nTraffic started successfully\n")

        time.sleep(30)
    
    # Stop Traffic from ixia
        log.info("--- Stopping Traffic ---- \n")
        log.info("Stopping Traffic")
        traffic_run_status = ixLib.stop_traffic()
        
        if traffic_run_status is not 1:
           log.info("Failed: To Stop traffic")
           return 0
        else:
            log.info("\nTraffic Stopped successfully\n")
            time.sleep(10)    
    
    @aetest.test
    def VERIFY_IXIA_TRAFFIC(self, testscript):
        """ IXIA_CONFIGURATION subsection: Verify IXIA Traffic """

        # Do not perform configurations if skip_tgen_config flag is set
        if not testscript.parameters['script_flags']['skip_tgen_config']:

            time.sleep(20)

            if ixLib.verify_traffic(2) == 0:
                log.debug("Traffic Verification failed")
                self.failed("Traffic Verification failed", goto=['cleanup'])
            else:
                log.info("Traffic Verification Passed")
        else:
            self.passed(reason="Skipped TGEN Configurations as per request")

     # =============================================================================================================================#        
    @aetest.test
    def Clear_ARP_Table_on_Vxlan_BLs(self, testscript):
        """Shut down the vpc leg on Leaf2 to force all traffic to Leaf1"""
        
        LEAF_1 = testscript.parameters['LEAF-1']
        LEAF_2 = testscript.parameters['LEAF-2']
        
        try:
            for i in range(1, testscript.parameters['forwardingSysDict']['VRF_count']+1):
                testscript.parameters['LEAF-2'].execute('''
                      clear ip arp vrf ''' + str(testscript.parameters['forwardingSysDict']['VRF_string']) + str(i) + ''' force-delete''')
            
            for i in range(1, testscript.parameters['forwardingSysDict']['VRF_count']+1):
                testscript.parameters['LEAF-1'].execute('''
                      clear ip arp vrf ''' + str(testscript.parameters['forwardingSysDict']['VRF_string']) + str(i) + ''' force-delete''')    
            
            
        except Exception as error:
            log.debug("Unable to configure - Encountered Exception " + str(error))
            self.errored('Exception occurred while clearing arp cache on LEAF-1 and LEAF-2', goto=['cleanup'])
            
    @aetest.test        
    def Host_move_FO(self,testscript):
        
        
        FO_1=testscript.parameters['FO_1']

        
        try:
            FO_1.configure('''
            interface ''' + str(testscript.parameters['intf_FO_1_to_N7k_LEAF_3']) + '''
            shut
            switchport
            switchport mode trunk
            
            interface ''' + str(testscript.parameters['intf_FO_1_to_LEAF_3']) + '''
            no shut
            switchport
            switchport mode trunk
            
            ''')
            time.sleep(45)
            #ForkedPdb().set_trace()
        except Exception as error:
                log.debug("Unable to configure - Encountered Exception " + str(error))
                self.errored('Exception occurred while configuring on FO_1', goto=['common_cleanup'])
                
    @aetest.test
    def VERIFY_IXIA_TRAFFIC_AFTER_MOVE(self, testscript):
        """ IXIA_CONFIGURATION subsection: Verify IXIA Traffic """

        # Do not perform configurations if skip_tgen_config flag is set
        if not testscript.parameters['script_flags']['skip_tgen_config']:

            time.sleep(20)

            if ixLib.verify_traffic(15) == 0:
                log.debug("Traffic Verification failed")
                self.failed("Traffic Verification failed", goto=['cleanup'])
            else:
                log.info("Traffic Verification Passed")
            
        else:
            self.passed(reason="Skipped TGEN Configurations as per request")
            
# =============================================================================================================================#
    @aetest.test
    def SVI_FLAP_LEAF2(self, testscript):
        """Shut down the vpc leg on Leaf2 to force all traffic to Leaf1"""
        
        LEAF_1 = testscript.parameters['LEAF-1']
        LEAF_2 = testscript.parameters['LEAF-2']
        forwardingSysDict = testscript.parameters['forwardingSysDict']
        l2_vlan_id = testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vlan_start']
        l2_vlan_ipv4_sec_start= testscript.parameters['LEAF_2_dict']['VNI_data']['l2_vlan_ipv4_sec_start']
        l2_vlan_ipv4_mask= testscript.parameters['LEAF_2_dict']['VNI_data']['l2_vlan_ipv4_mask']
        #+ str(testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vlan_ipv4_mask'])
        
        try:
            total_ip_count = int(forwardingSysDict['VLAN_PER_VRF_count']) * int(forwardingSysDict['VRF_count'])
            l2_ipv4s = increment_prefix_network(ip.IPv4Interface(str(l2_vlan_ipv4_sec_start) + str(l2_vlan_ipv4_mask)),total_ip_count)
            ip_index=0
            for i in range(0,len(l2_ipv4s)):
                LEAF_2.configure('''int vlan ''' + str(l2_vlan_id) + '''\n
                                 shut
                                 ''')
                l2_vlan_id += 1
                ip_index += 1
            ip_index=0
            l2_vlan_id = testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vlan_start']
            for i in range(0,len(l2_ipv4s)):
                LEAF_2.configure('''int vlan ''' + str(l2_vlan_id) + '''\n
                                 no shut
                                 ''')
                l2_vlan_id += 1
                ip_index += 1
            
            
        except Exception as error:
            log.debug("Unable to configure - Encountered Exception " + str(error))
            self.errored('Exception occurred while flapping on LEAF-2', goto=['cleanup'])
            
    # =============================================================================================================================#        
    
    @aetest.test
    def SVI_FLAP_LEAF1(self, testscript):
        """Shut down the vpc leg on Leaf2 to force all traffic to Leaf1"""
        
        LEAF_1 = testscript.parameters['LEAF-1']
        LEAF_2 = testscript.parameters['LEAF-2']
        forwardingSysDict = testscript.parameters['forwardingSysDict']
        l2_vlan_id = testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vlan_start']
        l2_vlan_ipv4_sec_start= testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vlan_ipv4_sec_start']
        l2_vlan_ipv4_mask= testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vlan_ipv4_mask']
        
        try:
            total_ip_count = int(forwardingSysDict['VLAN_PER_VRF_count']) * int(forwardingSysDict['VRF_count'])
            l2_ipv4s = increment_prefix_network(ip.IPv4Interface(str(l2_vlan_ipv4_sec_start) + str(l2_vlan_ipv4_mask)),total_ip_count)
            ip_index=0
            for i in range(0,len(l2_ipv4s)):
                LEAF_1.configure('''int vlan ''' + str(l2_vlan_id) + '''\n
                                 shut
                                 ''')
                l2_vlan_id += 1
                ip_index += 1
            ip_index=0
            l2_vlan_id = testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vlan_start']
            for i in range(0,len(l2_ipv4s)):
                LEAF_1.configure('''int vlan ''' + str(l2_vlan_id) + '''\n
                                 no shut
                                 ''')
                l2_vlan_id += 1
                ip_index += 1
                
            
            
        except Exception as error:
            log.debug("Unable to configure - Encountered Exception " + str(error))
            self.errored('Exception occurred while flapping svi on LEAF-1', goto=['cleanup'])
            
    @aetest.test
    def VERIFY_IXIA_TRAFFIC_AFTER_SVI_FLAP(self, testscript):
        """ IXIA_CONFIGURATION subsection: Verify IXIA Traffic """

        # Do not perform configurations if skip_tgen_config flag is set
        if not testscript.parameters['script_flags']['skip_tgen_config']:

            time.sleep(20)

            if ixLib.verify_traffic(15) == 0:
                log.debug("Traffic Verification failed")
                self.failed("Traffic Verification failed", goto=['cleanup'])
            else:
                log.info("Traffic Verification Passed")
            
        else:
            self.passed(reason="Skipped TGEN Configurations as per request")
            
    @aetest.test        
    def Host_move_FO_BACK(self,testscript):
        
        
        FO_1=testscript.parameters['FO_1']

        
        try:
            FO_1.configure('''
            interface ''' + str(testscript.parameters['intf_FO_1_to_LEAF_3']) + '''
            shut
            switchport
            switchport mode trunk
            
            interface ''' + str(testscript.parameters['intf_FO_1_to_N7k_LEAF_3']) + '''
            no shut
            switchport
            switchport mode trunk
            
            
            
            ''')
            time.sleep(45)
        except Exception as error:
                log.debug("Unable to configure - Encountered Exception " + str(error))
                self.errored('Exception occurred while configuring on FO_1', goto=['common_cleanup'])
                
    @aetest.test
    def VERIFY_IXIA_TRAFFIC_HOST_MOVE_BACK(self, testscript):
        """ IXIA_CONFIGURATION subsection: Verify IXIA Traffic """

        # Do not perform configurations if skip_tgen_config flag is set
        if not testscript.parameters['script_flags']['skip_tgen_config']:

            time.sleep(20)

            if ixLib.verify_traffic(15) == 0:
                log.debug("Traffic Verification failed")
                self.failed("Traffic Verification failed", goto=['cleanup'])
            else:
                log.info("Traffic Verification Passed")
        else:
            self.passed(reason="Skipped TGEN Configurations as per request")
        
    @aetest.cleanup
    def cleanup(self,testscript):
        """Unconfigure qos policies"""
        LEAF_1 = testscript.parameters['LEAF-1']
        LEAF_2 = testscript.parameters['LEAF-2']
        LEAF_3 = testscript.parameters['LEAF-3']
        FO_1=testscript.parameters['FO_1']
        LEAF_1 = testscript.parameters['LEAF-1']
        LEAF_2 = testscript.parameters['LEAF-2']
        forwardingSysDict = testscript.parameters['forwardingSysDict']
        l2_vlan_id = testscript.parameters['N7K_LEAF_1_dict']['Vlan_data']['l2_vlan_start']
        l2_vlan_ipv4_start= testscript.parameters['N7K_LEAF_1_dict']['Vlan_data']['l2_vlan_ipv4_start']
        l2_vlan_ipv4_mask= testscript.parameters['N7K_LEAF_1_dict']['Vlan_data']['l2_vlan_ipv4_mask']
        l2_vlan_ipv6_start= testscript.parameters['N7K_LEAF_1_dict']['Vlan_data']['l2_vlan_ipv6_start']
        l2_vlan_ipv6_mask= testscript.parameters['N7K_LEAF_1_dict']['Vlan_data']['l2_vlan_ipv6_mask']
        l2_hsrp_ipv4_vip_start= testscript.parameters['N7K_LEAF_1_dict']['Vlan_data']['hsrp_ipv4_vip_start']
        l2_hsrp_ipv6_vip_start= testscript.parameters['N7K_LEAF_1_dict']['Vlan_data']['hsrp_ipv6_vip_start']
        total_ip_count = int(forwardingSysDict['VLAN_PER_VRF_count']) * int(forwardingSysDict['VRF_count'])
        l2_vlan_ipv4_sec_start= testscript.parameters['LEAF_2_dict']['VNI_data']['l2_vlan_ipv4_sec_start']
        l2_vlan_ipv4_mask= testscript.parameters['LEAF_2_dict']['VNI_data']['l2_vlan_ipv4_mask']
        l2_ipv4s = increment_prefix_network(ip.IPv4Interface(str(l2_vlan_ipv4_sec_start) + str(l2_vlan_ipv4_mask)),total_ip_count)
        post_test_process_dict = {
            'dut_list'                       : [LEAF_1, LEAF_2, LEAF_3],
            'cc_check'                  : 1,
            'cores_check'               : 1,
            'logs_check'                : 0,
            'fnl_flag'                  : 0,
            'exclude_log_check_pattern' : 'ERROR_VLANS_SUSPENDED|ERROR_VLANS_REMOVED',
            }
        try:
            # UCAST_v4_dict = {
            #                 'mode'        : 'remove',
            #                 'stream_id'   : stream_id,
            #           }
            # if (ixLib.delete_traffic_item(UCAST_v4_dict))==0:
            #     log.debug("Traffic Remove failed")
            #     self.failed("Traffic Remove failed")
            # else:
            #     log.info("Traffic Deletion Passed")
            ###admin no shut of SVI on Vxlan Leaf2 and Leaf1
            ip_index=0
            
            for i in range(0,len(l2_ipv4s)):
                LEAF_2.configure('''int vlan ''' + str(l2_vlan_id) + '''\n
                                 ip address ''' + str(l2_ipv4s[ip_index]) + ''' secondary use-bia
                                 no shut
                                 ''')
                l2_vlan_id += 1
                ip_index += 1
                
            ip_index=0
            l2_vlan_id = testscript.parameters['N7K_LEAF_1_dict']['Vlan_data']['l2_vlan_start']
            for i in range(0,len(l2_ipv4s)):
                LEAF_1.configure('''int vlan ''' + str(l2_vlan_id) + '''\n
                                 ip address ''' + str(l2_ipv4s[ip_index]) + ''' secondary use-bia
                                 no shut
                                 ''')
                l2_vlan_id += 1
                ip_index += 1
                
            ##Move host back to FP
            FO_1.configure('''
            interface ''' + str(testscript.parameters['intf_FO_1_to_LEAF_3']) + '''
            shut
            switchport
            switchport mode trunk
            
            interface ''' + str(testscript.parameters['intf_FO_1_to_N7k_LEAF_3']) + '''
            no shut
            switchport
            switchport mode trunk
            ''')
            time.sleep(30)
            ###Remove Pre-migration step from both N7k leafs
            device_handle=connect_to_vdc(testscript.parameters['xbow1'], 'leaf1')
            if device_handle==False:
                log.info("failed to switchto correct vdc")
                self.failed("failed to switchto correct vdc",goto=['common_cleanup'])
            else:
                total_ip_count = int(forwardingSysDict['VLAN_PER_VRF_count']) * int(forwardingSysDict['VRF_count'])
                l2_ipv4s = increment_prefix_network(ip.IPv4Interface(str(l2_vlan_ipv4_start) + str(l2_vlan_ipv4_mask)),total_ip_count)
                l2_ipv6s = increment_prefix_network(ip.IPv6Interface(str(l2_vlan_ipv6_start) + str(l2_vlan_ipv6_mask)),total_ip_count)
                ip_index=0
                for i in range(0,len(l2_ipv4s)):
                    device_handle.configure('''int vlan ''' + str(l2_vlan_id) + '''\n
                                     hsrp version 2
                                     hsrp ''' + str(l2_vlan_id) + ''' ipv4
                                     no mac-address 0000.000a.aaaa
                                     ''')
                    l2_vlan_id += 1
            l2_vlan_id = testscript.parameters['N7K_LEAF_1_dict']['Vlan_data']['l2_vlan_start']        
            device_handle=connect_to_vdc(testscript.parameters['xbow2'], 'leaf2')
            if device_handle==False:
                log.info("failed to switchto correct vdc")
                self.failed("failed to switchto correct vdc",goto=['common_cleanup'])
            else:
                total_ip_count = int(forwardingSysDict['VLAN_PER_VRF_count']) * int(forwardingSysDict['VRF_count'])
                l2_ipv4s = increment_prefix_network(ip.IPv4Interface(str(l2_vlan_ipv4_start) + str(l2_vlan_ipv4_mask)),total_ip_count)
                l2_ipv6s = increment_prefix_network(ip.IPv6Interface(str(l2_vlan_ipv6_start) + str(l2_vlan_ipv6_mask)),total_ip_count)
                ip_index=0
                for i in range(0,len(l2_ipv4s)):
                    device_handle.configure('''int vlan ''' + str(l2_vlan_id) + '''\n
                                     hsrp version 2
                                     hsrp ''' + str(l2_vlan_id) + ''' ipv4
                                     no mac-address 0000.000a.aaaa
                                     ''')
                    l2_vlan_id += 1
            status = infraVerify.postTestVerification(post_test_process_dict)
            if status['status'] == 0:
                self.failed(reason=status['logs'])
            else:
                self.passed(reason=status['logs'])
        except Exception as error:
            log.debug("Unable to unconfigure class map or policy map-Encountered exception " + str(error))
            self.errored('Exception occurred while unconfiguring qos on LEAF1', goto=['next_tc'])
            
# *****************************************************************************************************************************#
class NVE_FLAP_post_Host_move_ipv4(aetest.Testcase):
    """ Host_move_ipv4 """

    
    # =============================================================================================================================#        
    
    @aetest.test
    def SVI_ON_LEAF2(self, testscript):
        """Shut down the vpc leg on Leaf2 to force all traffic to Leaf1"""
        
        LEAF_1 = testscript.parameters['LEAF-1']
        LEAF_2 = testscript.parameters['LEAF-2']
        forwardingSysDict = testscript.parameters['forwardingSysDict']
        l2_vlan_id = testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vlan_start']
        l2_vlan_ipv4_sec_start= testscript.parameters['LEAF_2_dict']['VNI_data']['l2_vlan_ipv4_sec_start']
        l2_vlan_ipv4_mask= testscript.parameters['LEAF_2_dict']['VNI_data']['l2_vlan_ipv4_mask']
        #+ str(testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vlan_ipv4_mask'])
        
        try:
            total_ip_count = int(forwardingSysDict['VLAN_PER_VRF_count']) * int(forwardingSysDict['VRF_count'])
            l2_ipv4s = increment_prefix_network(ip.IPv4Interface(str(l2_vlan_ipv4_sec_start) + str(l2_vlan_ipv4_mask)),total_ip_count)
            ip_index=0
            for i in range(0,len(l2_ipv4s)):
                LEAF_2.configure('''int vlan ''' + str(l2_vlan_id) + '''\n
                                 ip address ''' + str(l2_ipv4s[ip_index]) + ''' secondary use-bia
                                 no shut
                                 ''')
                l2_vlan_id += 1
                ip_index += 1
            
            
        except Exception as error:
            log.debug("Unable to configure - Encountered Exception " + str(error))
            self.errored('Exception occurred while configuring secondary ipv4 address on LEAF-2', goto=['cleanup'])
            
    # =============================================================================================================================#        
    
    @aetest.test
    def SVI_ON_LEAF1(self, testscript):
        """Shut down the vpc leg on Leaf2 to force all traffic to Leaf1"""
        
        LEAF_1 = testscript.parameters['LEAF-1']
        LEAF_2 = testscript.parameters['LEAF-2']
        forwardingSysDict = testscript.parameters['forwardingSysDict']
        l2_vlan_id = testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vlan_start']
        l2_vlan_ipv4_sec_start= testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vlan_ipv4_sec_start']
        l2_vlan_ipv4_mask= testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vlan_ipv4_mask']
        
        try:
            total_ip_count = int(forwardingSysDict['VLAN_PER_VRF_count']) * int(forwardingSysDict['VRF_count'])
            l2_ipv4s = increment_prefix_network(ip.IPv4Interface(str(l2_vlan_ipv4_sec_start) + str(l2_vlan_ipv4_mask)),total_ip_count)
            ip_index=0
            for i in range(0,len(l2_ipv4s)):
                LEAF_1.configure('''int vlan ''' + str(l2_vlan_id) + '''\n
                                 ip address ''' + str(l2_ipv4s[ip_index]) + ''' secondary use-bia
                                 no shut
                                 ''')
                l2_vlan_id += 1
                ip_index += 1
                
            
            
        except Exception as error:
            log.debug("Unable to configure - Encountered Exception " + str(error))
            self.errored('Exception occurred while configuring secondary ipv4 address on LEAF-1', goto=['cleanup'])
            
     # =============================================================================================================================#        
    @aetest.test
    def Add_external_int(self, testscript):
        """Shut down the vpc leg on Leaf2 to force all traffic to Leaf1"""
        
        LEAF_1 = testscript.parameters['LEAF-1']
        LEAF_2 = testscript.parameters['LEAF-2']
        
        try:
            testscript.parameters['LEAF-2'].configure('''
                  interface po ''' + str(testscript.parameters['LEAF_1_dict']['VPC_data']['double_vpc_po_1']) + '''
                  port-type external
                  ''')
            
            testscript.parameters['LEAF-1'].configure('''
                  interface po ''' + str(testscript.parameters['LEAF_1_dict']['VPC_data']['double_vpc_po_1']) + '''
                  port-type external
                  ''')    
            
            
        except Exception as error:
            log.debug("Unable to configure - Encountered Exception " + str(error))
            self.errored('Exception occurred while configuring external on LEAF-1 and LEAF-2', goto=['cleanup'])
            
     # =============================================================================================================================#    
    @aetest.test
    def Pre_migration_hsrp(self,testscript):
        LEAF_1 = testscript.parameters['LEAF-1']
        LEAF_2 = testscript.parameters['LEAF-2']
        forwardingSysDict = testscript.parameters['forwardingSysDict']
        l2_vlan_id = testscript.parameters['N7K_LEAF_1_dict']['Vlan_data']['l2_vlan_start']
        l2_vlan_ipv4_start= testscript.parameters['N7K_LEAF_1_dict']['Vlan_data']['l2_vlan_ipv4_start']
        l2_vlan_ipv4_mask= testscript.parameters['N7K_LEAF_1_dict']['Vlan_data']['l2_vlan_ipv4_mask']
        l2_vlan_ipv6_start= testscript.parameters['N7K_LEAF_1_dict']['Vlan_data']['l2_vlan_ipv6_start']
        l2_vlan_ipv6_mask= testscript.parameters['N7K_LEAF_1_dict']['Vlan_data']['l2_vlan_ipv6_mask']
        l2_hsrp_ipv4_vip_start= testscript.parameters['N7K_LEAF_1_dict']['Vlan_data']['hsrp_ipv4_vip_start']
        l2_hsrp_ipv6_vip_start= testscript.parameters['N7K_LEAF_1_dict']['Vlan_data']['hsrp_ipv6_vip_start']
        
        try:
            device_handle=connect_to_vdc(testscript.parameters['xbow1'], 'leaf1')
            if device_handle==False:
                log.info("failed to switchto correct vdc")
                self.failed("failed to switchto correct vdc",goto=['common_cleanup'])
            else:
                total_ip_count = int(forwardingSysDict['VLAN_PER_VRF_count']) * int(forwardingSysDict['VRF_count'])
                l2_ipv4s = increment_prefix_network(ip.IPv4Interface(str(l2_vlan_ipv4_start) + str(l2_vlan_ipv4_mask)),total_ip_count)
                l2_ipv6s = increment_prefix_network(ip.IPv6Interface(str(l2_vlan_ipv6_start) + str(l2_vlan_ipv6_mask)),total_ip_count)
                ip_index=0
                for i in range(0,len(l2_ipv4s)):
                    device_handle.configure('''int vlan ''' + str(l2_vlan_id) + '''\n
                                     hsrp version 2
                                     hsrp ''' + str(l2_vlan_id) + ''' ipv4
                                     mac-address 0000.000a.aaaa
                                     ''')
                    l2_vlan_id += 1
            l2_vlan_id = testscript.parameters['N7K_LEAF_1_dict']['Vlan_data']['l2_vlan_start']        
            device_handle=connect_to_vdc(testscript.parameters['xbow2'], 'leaf2')
            if device_handle==False:
                log.info("failed to switchto correct vdc")
                self.failed("failed to switchto correct vdc",goto=['common_cleanup'])
            else:
                total_ip_count = int(forwardingSysDict['VLAN_PER_VRF_count']) * int(forwardingSysDict['VRF_count'])
                l2_ipv4s = increment_prefix_network(ip.IPv4Interface(str(l2_vlan_ipv4_start) + str(l2_vlan_ipv4_mask)),total_ip_count)
                l2_ipv6s = increment_prefix_network(ip.IPv6Interface(str(l2_vlan_ipv6_start) + str(l2_vlan_ipv6_mask)),total_ip_count)
                ip_index=0
                for i in range(0,len(l2_ipv4s)):
                    device_handle.configure('''int vlan ''' + str(l2_vlan_id) + '''\n
                                     hsrp version 2
                                     hsrp ''' + str(l2_vlan_id) + ''' ipv4
                                     mac-address 0000.000a.aaaa
                                     ''')
                    l2_vlan_id += 1
                    


        except Exception as error:
                log.debug("Unable to configure - Encountered Exception " + str(error))
                self.errored('Exception occurred while configuring on N7k leaf1', goto=['common_cleanup'])
                
    @aetest.test        
    def configure_FO(self,testscript):
        
        FO_1_vlanConfiguration = ""
        FO_1=testscript.parameters['FO_1']

        l3_vrf_count_iter = 0
        l2_vlan_id = testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vlan_start']
        l3_vlan_id = testscript.parameters['LEAF_1_dict']['VNI_data']['l3_vlan_start']

        while l3_vrf_count_iter < testscript.parameters['forwardingSysDict']['VRF_count']:
            l2_vlan_count_iter = 0
            FO_1_vlanConfiguration += '''vlan ''' + str(l3_vlan_id) + '''\n
                                            state active\n
                                            no shut\n'''
            while l2_vlan_count_iter < testscript.parameters['forwardingSysDict']['VLAN_PER_VRF_count']:
                # Incrementing L2 VLAN Iteration counters
                FO_1_vlanConfiguration += '''vlan ''' + str(l2_vlan_id) + '''\n
                                                state active\n
                                                no shut\n'''
                l2_vlan_count_iter += 1
                l2_vlan_id += 1
            # Incrementing L3 VRF Iteration counters
            l3_vrf_count_iter += 1
            l3_vlan_id += 1

        try:
            FO_1.configure(
                str(FO_1_vlanConfiguration) + '''
        
        
            
            interface ''' + str(testscript.parameters['intf_FO_1_to_N7k_LEAF_3']) + '''
            no shut
            switchport
            switchport mode trunk
            
            interface ''' + str(testscript.parameters['intf_FO_1_to_LEAF_3']) + '''
            shut
            switchport
            switchport mode trunk
            
            interface ''' + str(testscript.parameters['intf_FO_1_to_IXIA']) + '''
            no shut
            switchport
            switchport mode trunk
            
            ''')
        except Exception as error:
                log.debug("Unable to configure - Encountered Exception " + str(error))
                self.errored('Exception occurred while configuring on FO_1', goto=['common_cleanup'])
   
#     @aetest.test
#     def CONFIGURE_UCAST_L3_IXIA_TRAFFIC(self, testscript):
#         """ IXIA_CONFIGURATION subsection: Configure MCAST Traffic Item """
# 
#         # Do not perform configurations if skip_tgen_config flag is set
#         if not testscript.parameters['script_flags']['skip_tgen_config']:
# 
#             IX_TP1 = testscript.parameters['IX_TP1']
#             IX_TP2 = testscript.parameters['IX_TP2']
#             P1_dict = testscript.parameters['LEAF_2_TGEN_dict']
#             P2_dict = testscript.parameters['LEAF_3_TGEN_dict']
# 
#             UCAST_v4_dict = {   'src_hndl'  : IX_TP1['port_handle'],
#                                 'dst_hndl'  : IX_TP2['port_handle'],
#                                 'ip_dscp'   : P1_dict['ip_dscp'],
#                                 'circuit'   : 'raw',
#                                 'TI_name'   : "UCAST_L3",
#                                 'rate_pps'  : "9000",
#                                 'bi_dir'    : 1,
#                                 'frame_size': '128',
#                                 'src_mac'   : P1_dict['mac'],
#                                 'dst_mac'   : '0000.000a.aaaa',
#                                 'srcmac_step': '00:00:00:00:00:00',
#                                 'dstmac_step': '00:00:00:00:00:00',
#                                 'srcmac_count': '1',
#                                 'dstmac_count': '1',
#                                 'vlan_id'    : P1_dict['vlan_id'],
#                                 'vlanid_step': '0',
#                                 'vlanid_count': '1',
#                                 'vlan_user_priority': P1_dict['vlan_user_priority'],
#                                 'ip_src_addrs' : P1_dict['v4_addr'],
#                                 'ip_dst_addrs' : P1_dict['L3_dst_addr'],
#                                 'ip_src_step' : '0.0.0.0',
#                                 'ip_dst_step' : '0.0.0.0',
# #                                'ip_step'    : P1_dict['v4_addr_step'],
#                           }
# 
# #            UCAST_v6_dict = {   'src_hndl'  : IX_TP1['ipv6_handle'],
# #                                'dst_hndl'  : IX_TP2['ipv6_handle'],
# #                                'circuit'   : 'ipv6',
# #                                'TI_name'   : "UCAST_V6",
# #                                'rate_pps'  : "1000",
# #                                'bi_dir'    : 1
# #                          }
# 
#             UCAST_v4_TI = ixLib.configure_ixia_l3_traffic_item(UCAST_v4_dict)
# #            UCAST_v6_TI = ixLib.configure_ixia_traffic_item(UCAST_v6_dict)
# 
# #            if UCAST_v4_TI == 0 or UCAST_v6_TI == 0:
# #                log.debug("Configuring UCast TI failed")
# #                self.errored("Configuring UCast TI failed", goto=['cleanup'])
#                 
#             if UCAST_v4_TI == 0:
#                 log.debug("Configuring UCast TI failed")
#                 self.errored("Configuring UCast TI failed", goto=['cleanup'])
#             else:
#                 global stream_id
#                 stream_id = UCAST_v4_TI
#             
# 
#         else:
#             self.passed(reason="Skipped TGEN Configurations as per request")
            
    # @aetest.test
    # def CONFIGURE_BCAST_IXIA_TRAFFIC(self, testscript):
    #     """ IXIA_CONFIGURATION subsection: Configure MCAST Traffic Item """
    # 
    #     # Do not perform configurations if skip_tgen_config flag is set
    #     if not testscript.parameters['script_flags']['skip_tgen_config']:
    # 
    #         IX_TP1 = testscript.parameters['IX_TP1']
    #         IX_TP2 = testscript.parameters['IX_TP2']
    #         P1_dict = testscript.parameters['LEAF_2_TGEN_dict']
    #         P2_dict = testscript.parameters['LEAF_3_TGEN_dict']
    #         BCAST_v4_dict = {
    #                             'src_hndl'      : IX_TP1['port_handle'],
    #                             'dst_hndl'      : IX_TP2['port_handle'],
    #                             'TI_name'       : "BCAST_V4",
    #                             'frame_size'    : "70",
    #                             'rate_pps'      : "1000",
    #                             'src_mac'       : P1_dict['mac'],
    #                             'srcmac_step'   : "00:00:00:00:00:01",
    #                             'srcmac_count'  : '1',
    #                             'vlan_id'       : P1_dict['vlan_id'],
    #                             'vlanid_step'   : "1",
    #                             'vlanid_count'  : "1",
    #                             'ip_src_addrs'  : P1_dict['v4_addr'],
    #                             'ip_step'       : "0.0.1.0",
    #                       }
    # 
    #         BCAST_v4_TI = ixLib.configure_ixia_BCAST_traffic_item(BCAST_v4_dict)
    # 
    #         if BCAST_v4_TI == 0:
    #             log.debug("Configuring BCast TI failed")
    #             self.errored("Configuring BCast TI failed", goto=['cleanup'])
    #         
    # 
    #     else:
    #         self.passed(reason="Skipped TGEN Configurations as per request")
    # =============================================================================================================================#
    @aetest.test
    def APPLY_TRAFFIC(self):
        """ IXIA_CONFIGURATION subsection: Verify IXIA Traffic """

        # # Apply IXIA Traffic
        # if ixLib.apply_traffic() == 1:
        #     log.info("Applying IXIA TI Passed")
        # else:
        #     self.errored("Applying IXIA TI failed", goto=['cleanup'])
            
        # =============================================================================================================================#
    #--------------------------------------------------------------------------------#
        # Start traffic from ixia
        log.info("--- Populating the statistics --- \n")
        log.info("---- Running Traffic --- \n")
        log.info("Starting Traffic")

        traffic_run_status  = ixLib.start_traffic()

        if traffic_run_status is not 1:
           log.info("Failed: To start traffic")
           return 0
        else:
            log.info("\nTraffic started successfully\n")

        time.sleep(30)
    
    # Stop Traffic from ixia
        log.info("--- Stopping Traffic ---- \n")
        log.info("Stopping Traffic")
        traffic_run_status = ixLib.stop_traffic()
        
        if traffic_run_status is not 1:
           log.info("Failed: To Stop traffic")
           return 0
        else:
            log.info("\nTraffic Stopped successfully\n")
            time.sleep(10)    
    
    @aetest.test
    def VERIFY_IXIA_TRAFFIC(self, testscript):
        """ IXIA_CONFIGURATION subsection: Verify IXIA Traffic """

        # Do not perform configurations if skip_tgen_config flag is set
        if not testscript.parameters['script_flags']['skip_tgen_config']:

            time.sleep(20)

            if ixLib.verify_traffic(2) == 0:
                log.debug("Traffic Verification failed")
                self.failed("Traffic Verification failed", goto=['cleanup'])
            else:
                log.info("Traffic Verification Passed")
        else:
            self.passed(reason="Skipped TGEN Configurations as per request")

     # =============================================================================================================================#        
    @aetest.test
    def Clear_ARP_Table_on_Vxlan_BLs(self, testscript):
        """Shut down the vpc leg on Leaf2 to force all traffic to Leaf1"""
        
        LEAF_1 = testscript.parameters['LEAF-1']
        LEAF_2 = testscript.parameters['LEAF-2']
        
        try:
            for i in range(1, testscript.parameters['forwardingSysDict']['VRF_count']+1):
                testscript.parameters['LEAF-2'].execute('''
                      clear ip arp vrf ''' + str(testscript.parameters['forwardingSysDict']['VRF_string']) + str(i) + ''' force-delete''')
            
            for i in range(1, testscript.parameters['forwardingSysDict']['VRF_count']+1):
                testscript.parameters['LEAF-1'].execute('''
                      clear ip arp vrf ''' + str(testscript.parameters['forwardingSysDict']['VRF_string']) + str(i) + ''' force-delete''')    
            
            
        except Exception as error:
            log.debug("Unable to configure - Encountered Exception " + str(error))
            self.errored('Exception occurred while clearing arp cache on LEAF-1 and LEAF-2', goto=['cleanup'])
            
    @aetest.test        
    def Host_move_FO(self,testscript):
        
        
        FO_1=testscript.parameters['FO_1']

        
        try:
            FO_1.configure('''
            interface ''' + str(testscript.parameters['intf_FO_1_to_N7k_LEAF_3']) + '''
            shut
            switchport
            switchport mode trunk
            
            interface ''' + str(testscript.parameters['intf_FO_1_to_LEAF_3']) + '''
            no shut
            switchport
            switchport mode trunk
            
            ''')
            time.sleep(45)
            #ForkedPdb().set_trace()
        except Exception as error:
                log.debug("Unable to configure - Encountered Exception " + str(error))
                self.errored('Exception occurred while configuring on FO_1', goto=['common_cleanup'])
                
    @aetest.test
    def VERIFY_IXIA_TRAFFIC_AFTER_MOVE(self, testscript):
        """ IXIA_CONFIGURATION subsection: Verify IXIA Traffic """

        # Do not perform configurations if skip_tgen_config flag is set
        if not testscript.parameters['script_flags']['skip_tgen_config']:

            time.sleep(20)

            if ixLib.verify_traffic(15) == 0:
                log.debug("Traffic Verification failed")
                self.failed("Traffic Verification failed", goto=['cleanup'])
            else:
                log.info("Traffic Verification Passed")
            
        else:
            self.passed(reason="Skipped TGEN Configurations as per request")
            
# =============================================================================================================================#
    @aetest.test
    def NVE_SHUT(self, testscript):
        """NVE flap on Leaf2"""
        
        LEAF_1 = testscript.parameters['LEAF-1']
        LEAF_2 = testscript.parameters['LEAF-2']
        forwardingSysDict = testscript.parameters['forwardingSysDict']
        l2_vlan_id = testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vlan_start']
        l2_vlan_ipv4_sec_start= testscript.parameters['LEAF_2_dict']['VNI_data']['l2_vlan_ipv4_sec_start']
        l2_vlan_ipv4_mask= testscript.parameters['LEAF_2_dict']['VNI_data']['l2_vlan_ipv4_mask']
        #+ str(testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vlan_ipv4_mask'])
        
        try:
            LEAF_2.configure('''int nve 1\n
                                 shut
                                 ''')
            LEAF_1.configure('''int nve 1\n
                                 shut
                                 ''')
            
            
        except Exception as error:
            log.debug("Unable to configure - Encountered Exception " + str(error))
            self.errored('Exception occurred while flapping nve on LEAF-2 and LEAF-1', goto=['cleanup'])
            
    # =============================================================================================================================#        
    
    @aetest.test
    def NVE_NO_SHUT(self, testscript):
        """NVE flap on Leaf2"""
        
        LEAF_1 = testscript.parameters['LEAF-1']
        LEAF_2 = testscript.parameters['LEAF-2']
        forwardingSysDict = testscript.parameters['forwardingSysDict']
        l2_vlan_id = testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vlan_start']
        l2_vlan_ipv4_sec_start= testscript.parameters['LEAF_2_dict']['VNI_data']['l2_vlan_ipv4_sec_start']
        l2_vlan_ipv4_mask= testscript.parameters['LEAF_2_dict']['VNI_data']['l2_vlan_ipv4_mask']
        #+ str(testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vlan_ipv4_mask'])
        
        try:
            LEAF_2.configure('''int nve 1\n
                                 no shut
                                 ''')
            LEAF_1.configure('''int nve 1\n
                                 no shut
                                 ''')
            time.sleep(60)
            
        except Exception as error:
            log.debug("Unable to configure - Encountered Exception " + str(error))
            self.errored('Exception occurred while flapping on LEAF-2 and LEAF-1', goto=['cleanup'])
            
    @aetest.test
    def VERIFY_IXIA_TRAFFIC_AFTER_NVE_FLAP(self, testscript):
        """ IXIA_CONFIGURATION subsection: Verify IXIA Traffic """

        # Do not perform configurations if skip_tgen_config flag is set
        if not testscript.parameters['script_flags']['skip_tgen_config']:

            time.sleep(20)

            if ixLib.verify_traffic(15) == 0:
                log.debug("Traffic Verification failed")
                self.failed("Traffic Verification failed", goto=['cleanup'])
            else:
                log.info("Traffic Verification Passed")
            
        else:
            self.passed(reason="Skipped TGEN Configurations as per request")
            
    @aetest.test        
    def Host_move_FO_BACK(self,testscript):
        
        
        FO_1=testscript.parameters['FO_1']

        
        try:
            FO_1.configure('''
            interface ''' + str(testscript.parameters['intf_FO_1_to_LEAF_3']) + '''
            shut
            switchport
            switchport mode trunk
            
            interface ''' + str(testscript.parameters['intf_FO_1_to_N7k_LEAF_3']) + '''
            no shut
            switchport
            switchport mode trunk
            
            
            
            ''')
            time.sleep(45)
        except Exception as error:
                log.debug("Unable to configure - Encountered Exception " + str(error))
                self.errored('Exception occurred while configuring on FO_1', goto=['common_cleanup'])
                
    @aetest.test
    def VERIFY_IXIA_TRAFFIC_HOST_MOVE_BACK(self, testscript):
        """ IXIA_CONFIGURATION subsection: Verify IXIA Traffic """

        # Do not perform configurations if skip_tgen_config flag is set
        if not testscript.parameters['script_flags']['skip_tgen_config']:

            time.sleep(20)

            if ixLib.verify_traffic(15) == 0:
                log.debug("Traffic Verification failed")
                self.failed("Traffic Verification failed", goto=['cleanup'])
            else:
                log.info("Traffic Verification Passed")
        else:
            self.passed(reason="Skipped TGEN Configurations as per request")
        
    @aetest.cleanup
    def cleanup(self,testscript):
        """Unconfigure qos policies"""
        LEAF_1 = testscript.parameters['LEAF-1']
        LEAF_2 = testscript.parameters['LEAF-2']
        LEAF_3 = testscript.parameters['LEAF-3']
        FO_1=testscript.parameters['FO_1']
        LEAF_1 = testscript.parameters['LEAF-1']
        LEAF_2 = testscript.parameters['LEAF-2']
        forwardingSysDict = testscript.parameters['forwardingSysDict']
        l2_vlan_id = testscript.parameters['N7K_LEAF_1_dict']['Vlan_data']['l2_vlan_start']
        l2_vlan_ipv4_start= testscript.parameters['N7K_LEAF_1_dict']['Vlan_data']['l2_vlan_ipv4_start']
        l2_vlan_ipv4_mask= testscript.parameters['N7K_LEAF_1_dict']['Vlan_data']['l2_vlan_ipv4_mask']
        l2_vlan_ipv6_start= testscript.parameters['N7K_LEAF_1_dict']['Vlan_data']['l2_vlan_ipv6_start']
        l2_vlan_ipv6_mask= testscript.parameters['N7K_LEAF_1_dict']['Vlan_data']['l2_vlan_ipv6_mask']
        l2_hsrp_ipv4_vip_start= testscript.parameters['N7K_LEAF_1_dict']['Vlan_data']['hsrp_ipv4_vip_start']
        l2_hsrp_ipv6_vip_start= testscript.parameters['N7K_LEAF_1_dict']['Vlan_data']['hsrp_ipv6_vip_start']
        total_ip_count = int(forwardingSysDict['VLAN_PER_VRF_count']) * int(forwardingSysDict['VRF_count'])
        l2_vlan_ipv4_sec_start= testscript.parameters['LEAF_2_dict']['VNI_data']['l2_vlan_ipv4_sec_start']
        l2_vlan_ipv4_mask= testscript.parameters['LEAF_2_dict']['VNI_data']['l2_vlan_ipv4_mask']
        l2_ipv4s = increment_prefix_network(ip.IPv4Interface(str(l2_vlan_ipv4_sec_start) + str(l2_vlan_ipv4_mask)),total_ip_count)
        post_test_process_dict = {
            'dut_list'                       : [LEAF_1, LEAF_2, LEAF_3],
            'cc_check'                  : 1,
            'cores_check'               : 1,
            'logs_check'                : 0,
            'fnl_flag'                  : 0,
            'exclude_log_check_pattern' : 'ERROR_VLANS_SUSPENDED|ERROR_VLANS_REMOVED',
            }
        try:
            # UCAST_v4_dict = {
            #                 'mode'        : 'remove',
            #                 'stream_id'   : stream_id,
            #           }
            # if (ixLib.delete_traffic_item(UCAST_v4_dict))==0:
            #     log.debug("Traffic Remove failed")
            #     self.failed("Traffic Remove failed")
            # else:
            #     log.info("Traffic Deletion Passed")
            ###admin no shut of SVI on Vxlan Leaf2 and Leaf1
            ip_index=0
            
            for i in range(0,len(l2_ipv4s)):
                LEAF_2.configure('''int vlan ''' + str(l2_vlan_id) + '''\n
                                 ip address ''' + str(l2_ipv4s[ip_index]) + ''' secondary use-bia
                                 no shut
                                 ''')
                l2_vlan_id += 1
                ip_index += 1
                
            ip_index=0
            l2_vlan_id = testscript.parameters['N7K_LEAF_1_dict']['Vlan_data']['l2_vlan_start']
            for i in range(0,len(l2_ipv4s)):
                LEAF_1.configure('''int vlan ''' + str(l2_vlan_id) + '''\n
                                 ip address ''' + str(l2_ipv4s[ip_index]) + ''' secondary use-bia
                                 no shut
                                 ''')
                l2_vlan_id += 1
                ip_index += 1
                
            ##Move host back to FP
            FO_1.configure('''
            interface ''' + str(testscript.parameters['intf_FO_1_to_LEAF_3']) + '''
            shut
            switchport
            switchport mode trunk
            
            interface ''' + str(testscript.parameters['intf_FO_1_to_N7k_LEAF_3']) + '''
            no shut
            switchport
            switchport mode trunk
            ''')
            time.sleep(30)
            ###Remove Pre-migration step from both N7k leafs
            device_handle=connect_to_vdc(testscript.parameters['xbow1'], 'leaf1')
            if device_handle==False:
                log.info("failed to switchto correct vdc")
                self.failed("failed to switchto correct vdc",goto=['common_cleanup'])
            else:
                total_ip_count = int(forwardingSysDict['VLAN_PER_VRF_count']) * int(forwardingSysDict['VRF_count'])
                l2_ipv4s = increment_prefix_network(ip.IPv4Interface(str(l2_vlan_ipv4_start) + str(l2_vlan_ipv4_mask)),total_ip_count)
                l2_ipv6s = increment_prefix_network(ip.IPv6Interface(str(l2_vlan_ipv6_start) + str(l2_vlan_ipv6_mask)),total_ip_count)
                ip_index=0
                for i in range(0,len(l2_ipv4s)):
                    device_handle.configure('''int vlan ''' + str(l2_vlan_id) + '''\n
                                     hsrp version 2
                                     hsrp ''' + str(l2_vlan_id) + ''' ipv4
                                     no mac-address 0000.000a.aaaa
                                     ''')
                    l2_vlan_id += 1
            l2_vlan_id = testscript.parameters['N7K_LEAF_1_dict']['Vlan_data']['l2_vlan_start']        
            device_handle=connect_to_vdc(testscript.parameters['xbow2'], 'leaf2')
            if device_handle==False:
                log.info("failed to switchto correct vdc")
                self.failed("failed to switchto correct vdc",goto=['common_cleanup'])
            else:
                total_ip_count = int(forwardingSysDict['VLAN_PER_VRF_count']) * int(forwardingSysDict['VRF_count'])
                l2_ipv4s = increment_prefix_network(ip.IPv4Interface(str(l2_vlan_ipv4_start) + str(l2_vlan_ipv4_mask)),total_ip_count)
                l2_ipv6s = increment_prefix_network(ip.IPv6Interface(str(l2_vlan_ipv6_start) + str(l2_vlan_ipv6_mask)),total_ip_count)
                ip_index=0
                for i in range(0,len(l2_ipv4s)):
                    device_handle.configure('''int vlan ''' + str(l2_vlan_id) + '''\n
                                     hsrp version 2
                                     hsrp ''' + str(l2_vlan_id) + ''' ipv4
                                     no mac-address 0000.000a.aaaa
                                     ''')
                    l2_vlan_id += 1
            status = infraVerify.postTestVerification(post_test_process_dict)
            if status['status'] == 0:
                self.failed(reason=status['logs'])
            else:
                self.passed(reason=status['logs'])
        except Exception as error:
            log.debug("Unable to unconfigure class map or policy map-Encountered exception " + str(error))
            self.errored('Exception occurred while unconfiguring qos on LEAF1', goto=['next_tc'])
            
# *****************************************************************************************************************************#
class EXT_INT_FLAP_post_Host_move_ipv4(aetest.Testcase):
    """ Host_move_ipv4 """

    
    # =============================================================================================================================#        
    
    @aetest.test
    def SVI_ON_LEAF2(self, testscript):
        """Shut down the vpc leg on Leaf2 to force all traffic to Leaf1"""
        
        LEAF_1 = testscript.parameters['LEAF-1']
        LEAF_2 = testscript.parameters['LEAF-2']
        forwardingSysDict = testscript.parameters['forwardingSysDict']
        l2_vlan_id = testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vlan_start']
        l2_vlan_ipv4_sec_start= testscript.parameters['LEAF_2_dict']['VNI_data']['l2_vlan_ipv4_sec_start']
        l2_vlan_ipv4_mask= testscript.parameters['LEAF_2_dict']['VNI_data']['l2_vlan_ipv4_mask']
        #+ str(testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vlan_ipv4_mask'])
        
        try:
            total_ip_count = int(forwardingSysDict['VLAN_PER_VRF_count']) * int(forwardingSysDict['VRF_count'])
            l2_ipv4s = increment_prefix_network(ip.IPv4Interface(str(l2_vlan_ipv4_sec_start) + str(l2_vlan_ipv4_mask)),total_ip_count)
            ip_index=0
            for i in range(0,len(l2_ipv4s)):
                LEAF_2.configure('''int vlan ''' + str(l2_vlan_id) + '''\n
                                 ip address ''' + str(l2_ipv4s[ip_index]) + ''' secondary use-bia
                                 no shut
                                 ''')
                l2_vlan_id += 1
                ip_index += 1
            
            
        except Exception as error:
            log.debug("Unable to configure - Encountered Exception " + str(error))
            self.errored('Exception occurred while configuring secondary ipv4 address on LEAF-2', goto=['cleanup'])
            
    # =============================================================================================================================#        
    
    @aetest.test
    def SVI_ON_LEAF1(self, testscript):
        """Shut down the vpc leg on Leaf2 to force all traffic to Leaf1"""
        
        LEAF_1 = testscript.parameters['LEAF-1']
        LEAF_2 = testscript.parameters['LEAF-2']
        forwardingSysDict = testscript.parameters['forwardingSysDict']
        l2_vlan_id = testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vlan_start']
        l2_vlan_ipv4_sec_start= testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vlan_ipv4_sec_start']
        l2_vlan_ipv4_mask= testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vlan_ipv4_mask']
        
        try:
            total_ip_count = int(forwardingSysDict['VLAN_PER_VRF_count']) * int(forwardingSysDict['VRF_count'])
            l2_ipv4s = increment_prefix_network(ip.IPv4Interface(str(l2_vlan_ipv4_sec_start) + str(l2_vlan_ipv4_mask)),total_ip_count)
            ip_index=0
            for i in range(0,len(l2_ipv4s)):
                LEAF_1.configure('''int vlan ''' + str(l2_vlan_id) + '''\n
                                 ip address ''' + str(l2_ipv4s[ip_index]) + ''' secondary use-bia
                                 no shut
                                 ''')
                l2_vlan_id += 1
                ip_index += 1
                
            
            
        except Exception as error:
            log.debug("Unable to configure - Encountered Exception " + str(error))
            self.errored('Exception occurred while configuring secondary ipv4 address on LEAF-1', goto=['cleanup'])
            
     # =============================================================================================================================#        
    @aetest.test
    def Add_external_int(self, testscript):
        """Shut down the vpc leg on Leaf2 to force all traffic to Leaf1"""
        
        LEAF_1 = testscript.parameters['LEAF-1']
        LEAF_2 = testscript.parameters['LEAF-2']
        
        try:
            testscript.parameters['LEAF-2'].configure('''
                  interface po ''' + str(testscript.parameters['LEAF_1_dict']['VPC_data']['double_vpc_po_1']) + '''
                  port-type external
                  ''')
            
            testscript.parameters['LEAF-1'].configure('''
                  interface po ''' + str(testscript.parameters['LEAF_1_dict']['VPC_data']['double_vpc_po_1']) + '''
                  port-type external
                  ''')    
            
            
        except Exception as error:
            log.debug("Unable to configure - Encountered Exception " + str(error))
            self.errored('Exception occurred while configuring external on LEAF-1 and LEAF-2', goto=['cleanup'])
            
     # =============================================================================================================================#    
    @aetest.test
    def Pre_migration_hsrp(self,testscript):
        LEAF_1 = testscript.parameters['LEAF-1']
        LEAF_2 = testscript.parameters['LEAF-2']
        forwardingSysDict = testscript.parameters['forwardingSysDict']
        l2_vlan_id = testscript.parameters['N7K_LEAF_1_dict']['Vlan_data']['l2_vlan_start']
        l2_vlan_ipv4_start= testscript.parameters['N7K_LEAF_1_dict']['Vlan_data']['l2_vlan_ipv4_start']
        l2_vlan_ipv4_mask= testscript.parameters['N7K_LEAF_1_dict']['Vlan_data']['l2_vlan_ipv4_mask']
        l2_vlan_ipv6_start= testscript.parameters['N7K_LEAF_1_dict']['Vlan_data']['l2_vlan_ipv6_start']
        l2_vlan_ipv6_mask= testscript.parameters['N7K_LEAF_1_dict']['Vlan_data']['l2_vlan_ipv6_mask']
        l2_hsrp_ipv4_vip_start= testscript.parameters['N7K_LEAF_1_dict']['Vlan_data']['hsrp_ipv4_vip_start']
        l2_hsrp_ipv6_vip_start= testscript.parameters['N7K_LEAF_1_dict']['Vlan_data']['hsrp_ipv6_vip_start']
        
        try:
            device_handle=connect_to_vdc(testscript.parameters['xbow1'], 'leaf1')
            if device_handle==False:
                log.info("failed to switchto correct vdc")
                self.failed("failed to switchto correct vdc",goto=['common_cleanup'])
            else:
                total_ip_count = int(forwardingSysDict['VLAN_PER_VRF_count']) * int(forwardingSysDict['VRF_count'])
                l2_ipv4s = increment_prefix_network(ip.IPv4Interface(str(l2_vlan_ipv4_start) + str(l2_vlan_ipv4_mask)),total_ip_count)
                l2_ipv6s = increment_prefix_network(ip.IPv6Interface(str(l2_vlan_ipv6_start) + str(l2_vlan_ipv6_mask)),total_ip_count)
                ip_index=0
                for i in range(0,len(l2_ipv4s)):
                    device_handle.configure('''int vlan ''' + str(l2_vlan_id) + '''\n
                                     hsrp version 2
                                     hsrp ''' + str(l2_vlan_id) + ''' ipv4
                                     mac-address 0000.000a.aaaa
                                     ''')
                    l2_vlan_id += 1
            l2_vlan_id = testscript.parameters['N7K_LEAF_1_dict']['Vlan_data']['l2_vlan_start']        
            device_handle=connect_to_vdc(testscript.parameters['xbow2'], 'leaf2')
            if device_handle==False:
                log.info("failed to switchto correct vdc")
                self.failed("failed to switchto correct vdc",goto=['common_cleanup'])
            else:
                total_ip_count = int(forwardingSysDict['VLAN_PER_VRF_count']) * int(forwardingSysDict['VRF_count'])
                l2_ipv4s = increment_prefix_network(ip.IPv4Interface(str(l2_vlan_ipv4_start) + str(l2_vlan_ipv4_mask)),total_ip_count)
                l2_ipv6s = increment_prefix_network(ip.IPv6Interface(str(l2_vlan_ipv6_start) + str(l2_vlan_ipv6_mask)),total_ip_count)
                ip_index=0
                for i in range(0,len(l2_ipv4s)):
                    device_handle.configure('''int vlan ''' + str(l2_vlan_id) + '''\n
                                     hsrp version 2
                                     hsrp ''' + str(l2_vlan_id) + ''' ipv4
                                     mac-address 0000.000a.aaaa
                                     ''')
                    l2_vlan_id += 1
                    


        except Exception as error:
                log.debug("Unable to configure - Encountered Exception " + str(error))
                self.errored('Exception occurred while configuring on N7k leaf1', goto=['common_cleanup'])
                
    @aetest.test        
    def configure_FO(self,testscript):
        
        FO_1_vlanConfiguration = ""
        FO_1=testscript.parameters['FO_1']

        l3_vrf_count_iter = 0
        l2_vlan_id = testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vlan_start']
        l3_vlan_id = testscript.parameters['LEAF_1_dict']['VNI_data']['l3_vlan_start']

        while l3_vrf_count_iter < testscript.parameters['forwardingSysDict']['VRF_count']:
            l2_vlan_count_iter = 0
            FO_1_vlanConfiguration += '''vlan ''' + str(l3_vlan_id) + '''\n
                                            state active\n
                                            no shut\n'''
            while l2_vlan_count_iter < testscript.parameters['forwardingSysDict']['VLAN_PER_VRF_count']:
                # Incrementing L2 VLAN Iteration counters
                FO_1_vlanConfiguration += '''vlan ''' + str(l2_vlan_id) + '''\n
                                                state active\n
                                                no shut\n'''
                l2_vlan_count_iter += 1
                l2_vlan_id += 1
            # Incrementing L3 VRF Iteration counters
            l3_vrf_count_iter += 1
            l3_vlan_id += 1

        try:
            FO_1.configure(
                str(FO_1_vlanConfiguration) + '''
        
        
            
            interface ''' + str(testscript.parameters['intf_FO_1_to_N7k_LEAF_3']) + '''
            no shut
            switchport
            switchport mode trunk
            
            interface ''' + str(testscript.parameters['intf_FO_1_to_LEAF_3']) + '''
            shut
            switchport
            switchport mode trunk
            
            interface ''' + str(testscript.parameters['intf_FO_1_to_IXIA']) + '''
            no shut
            switchport
            switchport mode trunk
            
            ''')
        except Exception as error:
                log.debug("Unable to configure - Encountered Exception " + str(error))
                self.errored('Exception occurred while configuring on FO_1', goto=['common_cleanup'])
   
#     @aetest.test
#     def CONFIGURE_UCAST_L3_IXIA_TRAFFIC(self, testscript):
#         """ IXIA_CONFIGURATION subsection: Configure MCAST Traffic Item """
# 
#         # Do not perform configurations if skip_tgen_config flag is set
#         if not testscript.parameters['script_flags']['skip_tgen_config']:
# 
#             IX_TP1 = testscript.parameters['IX_TP1']
#             IX_TP2 = testscript.parameters['IX_TP2']
#             P1_dict = testscript.parameters['LEAF_2_TGEN_dict']
#             P2_dict = testscript.parameters['LEAF_3_TGEN_dict']
# 
#             UCAST_v4_dict = {   'src_hndl'  : IX_TP1['port_handle'],
#                                 'dst_hndl'  : IX_TP2['port_handle'],
#                                 'ip_dscp'   : P1_dict['ip_dscp'],
#                                 'circuit'   : 'raw',
#                                 'TI_name'   : "UCAST_L3",
#                                 'rate_pps'  : "9000",
#                                 'bi_dir'    : 1,
#                                 'frame_size': '128',
#                                 'src_mac'   : P1_dict['mac'],
#                                 'dst_mac'   : '0000.000a.aaaa',
#                                 'srcmac_step': '00:00:00:00:00:00',
#                                 'dstmac_step': '00:00:00:00:00:00',
#                                 'srcmac_count': '1',
#                                 'dstmac_count': '1',
#                                 'vlan_id'    : P1_dict['vlan_id'],
#                                 'vlanid_step': '0',
#                                 'vlanid_count': '1',
#                                 'vlan_user_priority': P1_dict['vlan_user_priority'],
#                                 'ip_src_addrs' : P1_dict['v4_addr'],
#                                 'ip_dst_addrs' : P1_dict['L3_dst_addr'],
#                                 'ip_src_step' : '0.0.0.0',
#                                 'ip_dst_step' : '0.0.0.0',
# #                                'ip_step'    : P1_dict['v4_addr_step'],
#                           }
# 
# #            UCAST_v6_dict = {   'src_hndl'  : IX_TP1['ipv6_handle'],
# #                                'dst_hndl'  : IX_TP2['ipv6_handle'],
# #                                'circuit'   : 'ipv6',
# #                                'TI_name'   : "UCAST_V6",
# #                                'rate_pps'  : "1000",
# #                                'bi_dir'    : 1
# #                          }
# 
#             UCAST_v4_TI = ixLib.configure_ixia_l3_traffic_item(UCAST_v4_dict)
# #            UCAST_v6_TI = ixLib.configure_ixia_traffic_item(UCAST_v6_dict)
# 
# #            if UCAST_v4_TI == 0 or UCAST_v6_TI == 0:
# #                log.debug("Configuring UCast TI failed")
# #                self.errored("Configuring UCast TI failed", goto=['cleanup'])
#                 
#             if UCAST_v4_TI == 0:
#                 log.debug("Configuring UCast TI failed")
#                 self.errored("Configuring UCast TI failed", goto=['cleanup'])
#             else:
#                 global stream_id
#                 stream_id = UCAST_v4_TI
#             
# 
#         else:
#             self.passed(reason="Skipped TGEN Configurations as per request")
            
    # @aetest.test
    # def CONFIGURE_BCAST_IXIA_TRAFFIC(self, testscript):
    #     """ IXIA_CONFIGURATION subsection: Configure MCAST Traffic Item """
    # 
    #     # Do not perform configurations if skip_tgen_config flag is set
    #     if not testscript.parameters['script_flags']['skip_tgen_config']:
    # 
    #         IX_TP1 = testscript.parameters['IX_TP1']
    #         IX_TP2 = testscript.parameters['IX_TP2']
    #         P1_dict = testscript.parameters['LEAF_2_TGEN_dict']
    #         P2_dict = testscript.parameters['LEAF_3_TGEN_dict']
    #         BCAST_v4_dict = {
    #                             'src_hndl'      : IX_TP1['port_handle'],
    #                             'dst_hndl'      : IX_TP2['port_handle'],
    #                             'TI_name'       : "BCAST_V4",
    #                             'frame_size'    : "70",
    #                             'rate_pps'      : "1000",
    #                             'src_mac'       : P1_dict['mac'],
    #                             'srcmac_step'   : "00:00:00:00:00:01",
    #                             'srcmac_count'  : '1',
    #                             'vlan_id'       : P1_dict['vlan_id'],
    #                             'vlanid_step'   : "1",
    #                             'vlanid_count'  : "1",
    #                             'ip_src_addrs'  : P1_dict['v4_addr'],
    #                             'ip_step'       : "0.0.1.0",
    #                       }
    # 
    #         BCAST_v4_TI = ixLib.configure_ixia_BCAST_traffic_item(BCAST_v4_dict)
    # 
    #         if BCAST_v4_TI == 0:
    #             log.debug("Configuring BCast TI failed")
    #             self.errored("Configuring BCast TI failed", goto=['cleanup'])
    #         
    # 
    #     else:
    #         self.passed(reason="Skipped TGEN Configurations as per request")
    # =============================================================================================================================#
    @aetest.test
    def APPLY_TRAFFIC(self):
        """ IXIA_CONFIGURATION subsection: Verify IXIA Traffic """

        # # Apply IXIA Traffic
        # if ixLib.apply_traffic() == 1:
        #     log.info("Applying IXIA TI Passed")
        # else:
        #     self.errored("Applying IXIA TI failed", goto=['cleanup'])
            
        # =============================================================================================================================#
    #--------------------------------------------------------------------------------#
        # Start traffic from ixia
        log.info("--- Populating the statistics --- \n")
        log.info("---- Running Traffic --- \n")
        log.info("Starting Traffic")

        traffic_run_status  = ixLib.start_traffic()

        if traffic_run_status is not 1:
           log.info("Failed: To start traffic")
           return 0
        else:
            log.info("\nTraffic started successfully\n")

        time.sleep(30)
    
    # Stop Traffic from ixia
        log.info("--- Stopping Traffic ---- \n")
        log.info("Stopping Traffic")
        traffic_run_status = ixLib.stop_traffic()
        
        if traffic_run_status is not 1:
           log.info("Failed: To Stop traffic")
           return 0
        else:
            log.info("\nTraffic Stopped successfully\n")
            time.sleep(10)    
    
    @aetest.test
    def VERIFY_IXIA_TRAFFIC(self, testscript):
        """ IXIA_CONFIGURATION subsection: Verify IXIA Traffic """

        # Do not perform configurations if skip_tgen_config flag is set
        if not testscript.parameters['script_flags']['skip_tgen_config']:

            time.sleep(20)

            if ixLib.verify_traffic(2) == 0:
                log.debug("Traffic Verification failed")
                self.failed("Traffic Verification failed", goto=['cleanup'])
            else:
                log.info("Traffic Verification Passed")
        else:
            self.passed(reason="Skipped TGEN Configurations as per request")

     # =============================================================================================================================#        
    @aetest.test
    def Clear_ARP_Table_on_Vxlan_BLs(self, testscript):
        """Shut down the vpc leg on Leaf2 to force all traffic to Leaf1"""
        
        LEAF_1 = testscript.parameters['LEAF-1']
        LEAF_2 = testscript.parameters['LEAF-2']
        
        try:
            for i in range(1, testscript.parameters['forwardingSysDict']['VRF_count']+1):
                testscript.parameters['LEAF-2'].execute('''
                      clear ip arp vrf ''' + str(testscript.parameters['forwardingSysDict']['VRF_string']) + str(i) + ''' force-delete''')
            
            for i in range(1, testscript.parameters['forwardingSysDict']['VRF_count']+1):
                testscript.parameters['LEAF-1'].execute('''
                      clear ip arp vrf ''' + str(testscript.parameters['forwardingSysDict']['VRF_string']) + str(i) + ''' force-delete''')    
            
            
        except Exception as error:
            log.debug("Unable to configure - Encountered Exception " + str(error))
            self.errored('Exception occurred while clearing arp cache on LEAF-1 and LEAF-2', goto=['cleanup'])
            
    @aetest.test        
    def Host_move_FO(self,testscript):
        
        
        FO_1=testscript.parameters['FO_1']

        
        try:
            FO_1.configure('''
            interface ''' + str(testscript.parameters['intf_FO_1_to_N7k_LEAF_3']) + '''
            shut
            switchport
            switchport mode trunk
            
            interface ''' + str(testscript.parameters['intf_FO_1_to_LEAF_3']) + '''
            no shut
            switchport
            switchport mode trunk
            
            ''')
            time.sleep(45)
            #ForkedPdb().set_trace()
        except Exception as error:
                log.debug("Unable to configure - Encountered Exception " + str(error))
                self.errored('Exception occurred while configuring on FO_1', goto=['common_cleanup'])
                
    @aetest.test
    def VERIFY_IXIA_TRAFFIC_AFTER_MOVE(self, testscript):
        """ IXIA_CONFIGURATION subsection: Verify IXIA Traffic """

        # Do not perform configurations if skip_tgen_config flag is set
        if not testscript.parameters['script_flags']['skip_tgen_config']:

            time.sleep(20)

            if ixLib.verify_traffic(15) == 0:
                log.debug("Traffic Verification failed")
                self.failed("Traffic Verification failed", goto=['cleanup'])
            else:
                log.info("Traffic Verification Passed")
            
        else:
            self.passed(reason="Skipped TGEN Configurations as per request")
            
# =============================================================================================================================#
    @aetest.test
    def EXT_INT_SHUT(self, testscript):
        """NVE flap on Leaf2"""
        
        LEAF_1 = testscript.parameters['LEAF-1']
        LEAF_2 = testscript.parameters['LEAF-2']
        forwardingSysDict = testscript.parameters['forwardingSysDict']
        l2_vlan_id = testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vlan_start']
        l2_vlan_ipv4_sec_start= testscript.parameters['LEAF_2_dict']['VNI_data']['l2_vlan_ipv4_sec_start']
        l2_vlan_ipv4_mask= testscript.parameters['LEAF_2_dict']['VNI_data']['l2_vlan_ipv4_mask']
        #+ str(testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vlan_ipv4_mask'])
        
        try:
            testscript.parameters['LEAF-2'].configure('''
                  interface po ''' + str(testscript.parameters['LEAF_1_dict']['VPC_data']['double_vpc_po_1']) + '''
                  shut
                  ''')
            
            testscript.parameters['LEAF-1'].configure('''
                  interface po ''' + str(testscript.parameters['LEAF_1_dict']['VPC_data']['double_vpc_po_1']) + '''
                  shut
                  ''')    
            
            
        except Exception as error:
            log.debug("Unable to configure - Encountered Exception " + str(error))
            self.errored('Exception occurred while shutting External Interface on LEAF-2 and LEAF-1', goto=['cleanup'])
            
    # =============================================================================================================================#        
    
    @aetest.test
    def EXT_INT_NOSHUT(self, testscript):
        """NVE flap on Leaf2"""
        
        LEAF_1 = testscript.parameters['LEAF-1']
        LEAF_2 = testscript.parameters['LEAF-2']
        forwardingSysDict = testscript.parameters['forwardingSysDict']
        l2_vlan_id = testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vlan_start']
        l2_vlan_ipv4_sec_start= testscript.parameters['LEAF_2_dict']['VNI_data']['l2_vlan_ipv4_sec_start']
        l2_vlan_ipv4_mask= testscript.parameters['LEAF_2_dict']['VNI_data']['l2_vlan_ipv4_mask']
        #+ str(testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vlan_ipv4_mask'])
        
        try:
            testscript.parameters['LEAF-2'].configure('''
                  interface po ''' + str(testscript.parameters['LEAF_1_dict']['VPC_data']['double_vpc_po_1']) + '''
                  no shut
                  ''')
            
            testscript.parameters['LEAF-1'].configure('''
                  interface po ''' + str(testscript.parameters['LEAF_1_dict']['VPC_data']['double_vpc_po_1']) + '''
                  no shut
                  ''')    
            
            time.sleep(30)
        except Exception as error:
            log.debug("Unable to configure - Encountered Exception " + str(error))
            self.errored('Exception occurred while no shutting External Interface on LEAF-2 and LEAF-1', goto=['cleanup'])
            
    @aetest.test
    def VERIFY_IXIA_TRAFFIC_AFTER_NVE_FLAP(self, testscript):
        """ IXIA_CONFIGURATION subsection: Verify IXIA Traffic """

        # Do not perform configurations if skip_tgen_config flag is set
        if not testscript.parameters['script_flags']['skip_tgen_config']:

            time.sleep(20)

            if ixLib.verify_traffic(15) == 0:
                log.debug("Traffic Verification failed")
                self.failed("Traffic Verification failed", goto=['cleanup'])
            else:
                log.info("Traffic Verification Passed")
            
        else:
            self.passed(reason="Skipped TGEN Configurations as per request")
            
    @aetest.test        
    def Host_move_FO_BACK(self,testscript):
        
        
        FO_1=testscript.parameters['FO_1']

        
        try:
            FO_1.configure('''
            interface ''' + str(testscript.parameters['intf_FO_1_to_LEAF_3']) + '''
            shut
            switchport
            switchport mode trunk
            
            interface ''' + str(testscript.parameters['intf_FO_1_to_N7k_LEAF_3']) + '''
            no shut
            switchport
            switchport mode trunk
            
            
            
            ''')
            time.sleep(45)
        except Exception as error:
                log.debug("Unable to configure - Encountered Exception " + str(error))
                self.errored('Exception occurred while configuring on FO_1', goto=['common_cleanup'])
                
    @aetest.test
    def VERIFY_IXIA_TRAFFIC_HOST_MOVE_BACK(self, testscript):
        """ IXIA_CONFIGURATION subsection: Verify IXIA Traffic """

        # Do not perform configurations if skip_tgen_config flag is set
        if not testscript.parameters['script_flags']['skip_tgen_config']:

            time.sleep(20)

            if ixLib.verify_traffic(15) == 0:
                log.debug("Traffic Verification failed")
                self.failed("Traffic Verification failed", goto=['cleanup'])
            else:
                log.info("Traffic Verification Passed")
        else:
            self.passed(reason="Skipped TGEN Configurations as per request")
        
    @aetest.cleanup
    def cleanup(self,testscript):
        """Unconfigure qos policies"""
        LEAF_1 = testscript.parameters['LEAF-1']
        LEAF_2 = testscript.parameters['LEAF-2']
        LEAF_3 = testscript.parameters['LEAF-3']
        FO_1=testscript.parameters['FO_1']
        LEAF_1 = testscript.parameters['LEAF-1']
        LEAF_2 = testscript.parameters['LEAF-2']
        forwardingSysDict = testscript.parameters['forwardingSysDict']
        l2_vlan_id = testscript.parameters['N7K_LEAF_1_dict']['Vlan_data']['l2_vlan_start']
        l2_vlan_ipv4_start= testscript.parameters['N7K_LEAF_1_dict']['Vlan_data']['l2_vlan_ipv4_start']
        l2_vlan_ipv4_mask= testscript.parameters['N7K_LEAF_1_dict']['Vlan_data']['l2_vlan_ipv4_mask']
        l2_vlan_ipv6_start= testscript.parameters['N7K_LEAF_1_dict']['Vlan_data']['l2_vlan_ipv6_start']
        l2_vlan_ipv6_mask= testscript.parameters['N7K_LEAF_1_dict']['Vlan_data']['l2_vlan_ipv6_mask']
        l2_hsrp_ipv4_vip_start= testscript.parameters['N7K_LEAF_1_dict']['Vlan_data']['hsrp_ipv4_vip_start']
        l2_hsrp_ipv6_vip_start= testscript.parameters['N7K_LEAF_1_dict']['Vlan_data']['hsrp_ipv6_vip_start']
        total_ip_count = int(forwardingSysDict['VLAN_PER_VRF_count']) * int(forwardingSysDict['VRF_count'])
        l2_vlan_ipv4_sec_start= testscript.parameters['LEAF_2_dict']['VNI_data']['l2_vlan_ipv4_sec_start']
        l2_vlan_ipv4_mask= testscript.parameters['LEAF_2_dict']['VNI_data']['l2_vlan_ipv4_mask']
        l2_ipv4s = increment_prefix_network(ip.IPv4Interface(str(l2_vlan_ipv4_sec_start) + str(l2_vlan_ipv4_mask)),total_ip_count)
        post_test_process_dict = {
            'dut_list'                       : [LEAF_1, LEAF_2, LEAF_3],
            'cc_check'                  : 1,
            'cores_check'               : 1,
            'logs_check'                : 0,
            'fnl_flag'                  : 0,
            'exclude_log_check_pattern' : 'ERROR_VLANS_SUSPENDED|ERROR_VLANS_REMOVED',
            }
        try:
            # UCAST_v4_dict = {
            #                 'mode'        : 'remove',
            #                 'stream_id'   : stream_id,
            #           }
            # if (ixLib.delete_traffic_item(UCAST_v4_dict))==0:
            #     log.debug("Traffic Remove failed")
            #     self.failed("Traffic Remove failed")
            # else:
            #     log.info("Traffic Deletion Passed")
            ###admin no shut of External interface on Vxlan Leaf2 and Leaf1
            testscript.parameters['LEAF-2'].configure('''
                  interface po ''' + str(testscript.parameters['LEAF_1_dict']['VPC_data']['double_vpc_po_1']) + '''
                  no shut
                  ''')
            
            testscript.parameters['LEAF-1'].configure('''
                  interface po ''' + str(testscript.parameters['LEAF_1_dict']['VPC_data']['double_vpc_po_1']) + '''
                  no shut
                  ''')    
                
            ##Move host back to FP
            FO_1.configure('''
            interface ''' + str(testscript.parameters['intf_FO_1_to_LEAF_3']) + '''
            shut
            switchport
            switchport mode trunk
            
            interface ''' + str(testscript.parameters['intf_FO_1_to_N7k_LEAF_3']) + '''
            no shut
            switchport
            switchport mode trunk
            ''')
            time.sleep(30)
            ###Remove Pre-migration step from both N7k leafs
            device_handle=connect_to_vdc(testscript.parameters['xbow1'], 'leaf1')
            if device_handle==False:
                log.info("failed to switchto correct vdc")
                self.failed("failed to switchto correct vdc",goto=['common_cleanup'])
            else:
                total_ip_count = int(forwardingSysDict['VLAN_PER_VRF_count']) * int(forwardingSysDict['VRF_count'])
                l2_ipv4s = increment_prefix_network(ip.IPv4Interface(str(l2_vlan_ipv4_start) + str(l2_vlan_ipv4_mask)),total_ip_count)
                l2_ipv6s = increment_prefix_network(ip.IPv6Interface(str(l2_vlan_ipv6_start) + str(l2_vlan_ipv6_mask)),total_ip_count)
                ip_index=0
                for i in range(0,len(l2_ipv4s)):
                    device_handle.configure('''int vlan ''' + str(l2_vlan_id) + '''\n
                                     hsrp version 2
                                     hsrp ''' + str(l2_vlan_id) + ''' ipv4
                                     no mac-address 0000.000a.aaaa
                                     ''')
                    l2_vlan_id += 1
            l2_vlan_id = testscript.parameters['N7K_LEAF_1_dict']['Vlan_data']['l2_vlan_start']        
            device_handle=connect_to_vdc(testscript.parameters['xbow2'], 'leaf2')
            if device_handle==False:
                log.info("failed to switchto correct vdc")
                self.failed("failed to switchto correct vdc",goto=['common_cleanup'])
            else:
                total_ip_count = int(forwardingSysDict['VLAN_PER_VRF_count']) * int(forwardingSysDict['VRF_count'])
                l2_ipv4s = increment_prefix_network(ip.IPv4Interface(str(l2_vlan_ipv4_start) + str(l2_vlan_ipv4_mask)),total_ip_count)
                l2_ipv6s = increment_prefix_network(ip.IPv6Interface(str(l2_vlan_ipv6_start) + str(l2_vlan_ipv6_mask)),total_ip_count)
                ip_index=0
                for i in range(0,len(l2_ipv4s)):
                    device_handle.configure('''int vlan ''' + str(l2_vlan_id) + '''\n
                                     hsrp version 2
                                     hsrp ''' + str(l2_vlan_id) + ''' ipv4
                                     no mac-address 0000.000a.aaaa
                                     ''')
                    l2_vlan_id += 1
            status = infraVerify.postTestVerification(post_test_process_dict)
            if status['status'] == 0:
                self.failed(reason=status['logs'])
            else:
                self.passed(reason=status['logs'])
        except Exception as error:
            log.debug("Unable to unconfigure class map or policy map-Encountered exception " + str(error))
            self.errored('Exception occurred while unconfiguring qos on LEAF1', goto=['next_tc'])
            
# *****************************************************************************************************************************#
class FABRIC_UPLINK_FLAP_post_Host_move_ipv4(aetest.Testcase):
    """ Host_move_ipv4 """

    
    # =============================================================================================================================#        
    
    @aetest.test
    def SVI_ON_LEAF2(self, testscript):
        """Shut down the vpc leg on Leaf2 to force all traffic to Leaf1"""
        
        LEAF_1 = testscript.parameters['LEAF-1']
        LEAF_2 = testscript.parameters['LEAF-2']
        forwardingSysDict = testscript.parameters['forwardingSysDict']
        l2_vlan_id = testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vlan_start']
        l2_vlan_ipv4_sec_start= testscript.parameters['LEAF_2_dict']['VNI_data']['l2_vlan_ipv4_sec_start']
        l2_vlan_ipv4_mask= testscript.parameters['LEAF_2_dict']['VNI_data']['l2_vlan_ipv4_mask']
        #+ str(testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vlan_ipv4_mask'])
        
        try:
            total_ip_count = int(forwardingSysDict['VLAN_PER_VRF_count']) * int(forwardingSysDict['VRF_count'])
            l2_ipv4s = increment_prefix_network(ip.IPv4Interface(str(l2_vlan_ipv4_sec_start) + str(l2_vlan_ipv4_mask)),total_ip_count)
            ip_index=0
            for i in range(0,len(l2_ipv4s)):
                LEAF_2.configure('''int vlan ''' + str(l2_vlan_id) + '''\n
                                 ip address ''' + str(l2_ipv4s[ip_index]) + ''' secondary use-bia
                                 no shut
                                 ''')
                l2_vlan_id += 1
                ip_index += 1
            
            
        except Exception as error:
            log.debug("Unable to configure - Encountered Exception " + str(error))
            self.errored('Exception occurred while configuring secondary ipv4 address on LEAF-2', goto=['cleanup'])
            
    # =============================================================================================================================#        
    
    @aetest.test
    def SVI_ON_LEAF1(self, testscript):
        """Shut down the vpc leg on Leaf2 to force all traffic to Leaf1"""
        
        LEAF_1 = testscript.parameters['LEAF-1']
        LEAF_2 = testscript.parameters['LEAF-2']
        forwardingSysDict = testscript.parameters['forwardingSysDict']
        l2_vlan_id = testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vlan_start']
        l2_vlan_ipv4_sec_start= testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vlan_ipv4_sec_start']
        l2_vlan_ipv4_mask= testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vlan_ipv4_mask']
        
        try:
            total_ip_count = int(forwardingSysDict['VLAN_PER_VRF_count']) * int(forwardingSysDict['VRF_count'])
            l2_ipv4s = increment_prefix_network(ip.IPv4Interface(str(l2_vlan_ipv4_sec_start) + str(l2_vlan_ipv4_mask)),total_ip_count)
            ip_index=0
            for i in range(0,len(l2_ipv4s)):
                LEAF_1.configure('''int vlan ''' + str(l2_vlan_id) + '''\n
                                 ip address ''' + str(l2_ipv4s[ip_index]) + ''' secondary use-bia
                                 no shut
                                 ''')
                l2_vlan_id += 1
                ip_index += 1
                
            
            
        except Exception as error:
            log.debug("Unable to configure - Encountered Exception " + str(error))
            self.errored('Exception occurred while configuring secondary ipv4 address on LEAF-1', goto=['cleanup'])
            
     # =============================================================================================================================#        
    @aetest.test
    def Add_external_int(self, testscript):
        """Shut down the vpc leg on Leaf2 to force all traffic to Leaf1"""
        
        LEAF_1 = testscript.parameters['LEAF-1']
        LEAF_2 = testscript.parameters['LEAF-2']
        
        try:
            testscript.parameters['LEAF-2'].configure('''
                  interface po ''' + str(testscript.parameters['LEAF_1_dict']['VPC_data']['double_vpc_po_1']) + '''
                  port-type external
                  ''')
            
            testscript.parameters['LEAF-1'].configure('''
                  interface po ''' + str(testscript.parameters['LEAF_1_dict']['VPC_data']['double_vpc_po_1']) + '''
                  port-type external
                  ''')    
            
            
        except Exception as error:
            log.debug("Unable to configure - Encountered Exception " + str(error))
            self.errored('Exception occurred while configuring external on LEAF-1 and LEAF-2', goto=['cleanup'])
            
     # =============================================================================================================================#    
    @aetest.test
    def Pre_migration_hsrp(self,testscript):
        LEAF_1 = testscript.parameters['LEAF-1']
        LEAF_2 = testscript.parameters['LEAF-2']
        forwardingSysDict = testscript.parameters['forwardingSysDict']
        l2_vlan_id = testscript.parameters['N7K_LEAF_1_dict']['Vlan_data']['l2_vlan_start']
        l2_vlan_ipv4_start= testscript.parameters['N7K_LEAF_1_dict']['Vlan_data']['l2_vlan_ipv4_start']
        l2_vlan_ipv4_mask= testscript.parameters['N7K_LEAF_1_dict']['Vlan_data']['l2_vlan_ipv4_mask']
        l2_vlan_ipv6_start= testscript.parameters['N7K_LEAF_1_dict']['Vlan_data']['l2_vlan_ipv6_start']
        l2_vlan_ipv6_mask= testscript.parameters['N7K_LEAF_1_dict']['Vlan_data']['l2_vlan_ipv6_mask']
        l2_hsrp_ipv4_vip_start= testscript.parameters['N7K_LEAF_1_dict']['Vlan_data']['hsrp_ipv4_vip_start']
        l2_hsrp_ipv6_vip_start= testscript.parameters['N7K_LEAF_1_dict']['Vlan_data']['hsrp_ipv6_vip_start']
        
        try:
            device_handle=connect_to_vdc(testscript.parameters['xbow1'], 'leaf1')
            if device_handle==False:
                log.info("failed to switchto correct vdc")
                self.failed("failed to switchto correct vdc",goto=['common_cleanup'])
            else:
                total_ip_count = int(forwardingSysDict['VLAN_PER_VRF_count']) * int(forwardingSysDict['VRF_count'])
                l2_ipv4s = increment_prefix_network(ip.IPv4Interface(str(l2_vlan_ipv4_start) + str(l2_vlan_ipv4_mask)),total_ip_count)
                l2_ipv6s = increment_prefix_network(ip.IPv6Interface(str(l2_vlan_ipv6_start) + str(l2_vlan_ipv6_mask)),total_ip_count)
                ip_index=0
                for i in range(0,len(l2_ipv4s)):
                    device_handle.configure('''int vlan ''' + str(l2_vlan_id) + '''\n
                                     hsrp version 2
                                     hsrp ''' + str(l2_vlan_id) + ''' ipv4
                                     mac-address 0000.000a.aaaa
                                     ''')
                    l2_vlan_id += 1
            l2_vlan_id = testscript.parameters['N7K_LEAF_1_dict']['Vlan_data']['l2_vlan_start']        
            device_handle=connect_to_vdc(testscript.parameters['xbow2'], 'leaf2')
            if device_handle==False:
                log.info("failed to switchto correct vdc")
                self.failed("failed to switchto correct vdc",goto=['common_cleanup'])
            else:
                total_ip_count = int(forwardingSysDict['VLAN_PER_VRF_count']) * int(forwardingSysDict['VRF_count'])
                l2_ipv4s = increment_prefix_network(ip.IPv4Interface(str(l2_vlan_ipv4_start) + str(l2_vlan_ipv4_mask)),total_ip_count)
                l2_ipv6s = increment_prefix_network(ip.IPv6Interface(str(l2_vlan_ipv6_start) + str(l2_vlan_ipv6_mask)),total_ip_count)
                ip_index=0
                for i in range(0,len(l2_ipv4s)):
                    device_handle.configure('''int vlan ''' + str(l2_vlan_id) + '''\n
                                     hsrp version 2
                                     hsrp ''' + str(l2_vlan_id) + ''' ipv4
                                     mac-address 0000.000a.aaaa
                                     ''')
                    l2_vlan_id += 1
                    


        except Exception as error:
                log.debug("Unable to configure - Encountered Exception " + str(error))
                self.errored('Exception occurred while configuring on N7k leaf1', goto=['common_cleanup'])
                
    @aetest.test        
    def configure_FO(self,testscript):
        
        FO_1_vlanConfiguration = ""
        FO_1=testscript.parameters['FO_1']

        l3_vrf_count_iter = 0
        l2_vlan_id = testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vlan_start']
        l3_vlan_id = testscript.parameters['LEAF_1_dict']['VNI_data']['l3_vlan_start']

        while l3_vrf_count_iter < testscript.parameters['forwardingSysDict']['VRF_count']:
            l2_vlan_count_iter = 0
            FO_1_vlanConfiguration += '''vlan ''' + str(l3_vlan_id) + '''\n
                                            state active\n
                                            no shut\n'''
            while l2_vlan_count_iter < testscript.parameters['forwardingSysDict']['VLAN_PER_VRF_count']:
                # Incrementing L2 VLAN Iteration counters
                FO_1_vlanConfiguration += '''vlan ''' + str(l2_vlan_id) + '''\n
                                                state active\n
                                                no shut\n'''
                l2_vlan_count_iter += 1
                l2_vlan_id += 1
            # Incrementing L3 VRF Iteration counters
            l3_vrf_count_iter += 1
            l3_vlan_id += 1

        try:
            FO_1.configure(
                str(FO_1_vlanConfiguration) + '''
        
        
            
            interface ''' + str(testscript.parameters['intf_FO_1_to_N7k_LEAF_3']) + '''
            no shut
            switchport
            switchport mode trunk
            
            interface ''' + str(testscript.parameters['intf_FO_1_to_LEAF_3']) + '''
            shut
            switchport
            switchport mode trunk
            
            interface ''' + str(testscript.parameters['intf_FO_1_to_IXIA']) + '''
            no shut
            switchport
            switchport mode trunk
            
            ''')
        except Exception as error:
                log.debug("Unable to configure - Encountered Exception " + str(error))
                self.errored('Exception occurred while configuring on FO_1', goto=['common_cleanup'])
   
#     @aetest.test
#     def CONFIGURE_UCAST_L3_IXIA_TRAFFIC(self, testscript):
#         """ IXIA_CONFIGURATION subsection: Configure MCAST Traffic Item """
# 
#         # Do not perform configurations if skip_tgen_config flag is set
#         if not testscript.parameters['script_flags']['skip_tgen_config']:
# 
#             IX_TP1 = testscript.parameters['IX_TP1']
#             IX_TP2 = testscript.parameters['IX_TP2']
#             P1_dict = testscript.parameters['LEAF_2_TGEN_dict']
#             P2_dict = testscript.parameters['LEAF_3_TGEN_dict']
# 
#             UCAST_v4_dict = {   'src_hndl'  : IX_TP1['port_handle'],
#                                 'dst_hndl'  : IX_TP2['port_handle'],
#                                 'ip_dscp'   : P1_dict['ip_dscp'],
#                                 'circuit'   : 'raw',
#                                 'TI_name'   : "UCAST_L3",
#                                 'rate_pps'  : "9000",
#                                 'bi_dir'    : 1,
#                                 'frame_size': '128',
#                                 'src_mac'   : P1_dict['mac'],
#                                 'dst_mac'   : '0000.000a.aaaa',
#                                 'srcmac_step': '00:00:00:00:00:00',
#                                 'dstmac_step': '00:00:00:00:00:00',
#                                 'srcmac_count': '1',
#                                 'dstmac_count': '1',
#                                 'vlan_id'    : P1_dict['vlan_id'],
#                                 'vlanid_step': '0',
#                                 'vlanid_count': '1',
#                                 'vlan_user_priority': P1_dict['vlan_user_priority'],
#                                 'ip_src_addrs' : P1_dict['v4_addr'],
#                                 'ip_dst_addrs' : P1_dict['L3_dst_addr'],
#                                 'ip_src_step' : '0.0.0.0',
#                                 'ip_dst_step' : '0.0.0.0',
# #                                'ip_step'    : P1_dict['v4_addr_step'],
#                           }
# 
# #            UCAST_v6_dict = {   'src_hndl'  : IX_TP1['ipv6_handle'],
# #                                'dst_hndl'  : IX_TP2['ipv6_handle'],
# #                                'circuit'   : 'ipv6',
# #                                'TI_name'   : "UCAST_V6",
# #                                'rate_pps'  : "1000",
# #                                'bi_dir'    : 1
# #                          }
# 
#             UCAST_v4_TI = ixLib.configure_ixia_l3_traffic_item(UCAST_v4_dict)
# #            UCAST_v6_TI = ixLib.configure_ixia_traffic_item(UCAST_v6_dict)
# 
# #            if UCAST_v4_TI == 0 or UCAST_v6_TI == 0:
# #                log.debug("Configuring UCast TI failed")
# #                self.errored("Configuring UCast TI failed", goto=['cleanup'])
#                 
#             if UCAST_v4_TI == 0:
#                 log.debug("Configuring UCast TI failed")
#                 self.errored("Configuring UCast TI failed", goto=['cleanup'])
#             else:
#                 global stream_id
#                 stream_id = UCAST_v4_TI
#             
# 
#         else:
#             self.passed(reason="Skipped TGEN Configurations as per request")
            
    # @aetest.test
    # def CONFIGURE_BCAST_IXIA_TRAFFIC(self, testscript):
    #     """ IXIA_CONFIGURATION subsection: Configure MCAST Traffic Item """
    # 
    #     # Do not perform configurations if skip_tgen_config flag is set
    #     if not testscript.parameters['script_flags']['skip_tgen_config']:
    # 
    #         IX_TP1 = testscript.parameters['IX_TP1']
    #         IX_TP2 = testscript.parameters['IX_TP2']
    #         P1_dict = testscript.parameters['LEAF_2_TGEN_dict']
    #         P2_dict = testscript.parameters['LEAF_3_TGEN_dict']
    #         BCAST_v4_dict = {
    #                             'src_hndl'      : IX_TP1['port_handle'],
    #                             'dst_hndl'      : IX_TP2['port_handle'],
    #                             'TI_name'       : "BCAST_V4",
    #                             'frame_size'    : "70",
    #                             'rate_pps'      : "1000",
    #                             'src_mac'       : P1_dict['mac'],
    #                             'srcmac_step'   : "00:00:00:00:00:01",
    #                             'srcmac_count'  : '1',
    #                             'vlan_id'       : P1_dict['vlan_id'],
    #                             'vlanid_step'   : "1",
    #                             'vlanid_count'  : "1",
    #                             'ip_src_addrs'  : P1_dict['v4_addr'],
    #                             'ip_step'       : "0.0.1.0",
    #                       }
    # 
    #         BCAST_v4_TI = ixLib.configure_ixia_BCAST_traffic_item(BCAST_v4_dict)
    # 
    #         if BCAST_v4_TI == 0:
    #             log.debug("Configuring BCast TI failed")
    #             self.errored("Configuring BCast TI failed", goto=['cleanup'])
    #         
    # 
    #     else:
    #         self.passed(reason="Skipped TGEN Configurations as per request")
    # =============================================================================================================================#
    @aetest.test
    def APPLY_TRAFFIC(self):
        """ IXIA_CONFIGURATION subsection: Verify IXIA Traffic """

        # # Apply IXIA Traffic
        # if ixLib.apply_traffic() == 1:
        #     log.info("Applying IXIA TI Passed")
        # else:
        #     self.errored("Applying IXIA TI failed", goto=['cleanup'])
            
        # =============================================================================================================================#
    #--------------------------------------------------------------------------------#
        # Start traffic from ixia
        log.info("--- Populating the statistics --- \n")
        log.info("---- Running Traffic --- \n")
        log.info("Starting Traffic")

        traffic_run_status  = ixLib.start_traffic()

        if traffic_run_status is not 1:
           log.info("Failed: To start traffic")
           return 0
        else:
            log.info("\nTraffic started successfully\n")

        time.sleep(30)
    
    # Stop Traffic from ixia
        log.info("--- Stopping Traffic ---- \n")
        log.info("Stopping Traffic")
        traffic_run_status = ixLib.stop_traffic()
        
        if traffic_run_status is not 1:
           log.info("Failed: To Stop traffic")
           return 0
        else:
            log.info("\nTraffic Stopped successfully\n")
            time.sleep(10)    
    
    @aetest.test
    def VERIFY_IXIA_TRAFFIC(self, testscript):
        """ IXIA_CONFIGURATION subsection: Verify IXIA Traffic """

        # Do not perform configurations if skip_tgen_config flag is set
        if not testscript.parameters['script_flags']['skip_tgen_config']:

            time.sleep(20)

            if ixLib.verify_traffic(2) == 0:
                log.debug("Traffic Verification failed")
                self.failed("Traffic Verification failed", goto=['cleanup'])
            else:
                log.info("Traffic Verification Passed")
        else:
            self.passed(reason="Skipped TGEN Configurations as per request")

     # =============================================================================================================================#        
    @aetest.test
    def Clear_ARP_Table_on_Vxlan_BLs(self, testscript):
        """Shut down the vpc leg on Leaf2 to force all traffic to Leaf1"""
        
        LEAF_1 = testscript.parameters['LEAF-1']
        LEAF_2 = testscript.parameters['LEAF-2']
        
        try:
            for i in range(1, testscript.parameters['forwardingSysDict']['VRF_count']+1):
                testscript.parameters['LEAF-2'].execute('''
                      clear ip arp vrf ''' + str(testscript.parameters['forwardingSysDict']['VRF_string']) + str(i) + ''' force-delete''')
            
            for i in range(1, testscript.parameters['forwardingSysDict']['VRF_count']+1):
                testscript.parameters['LEAF-1'].execute('''
                      clear ip arp vrf ''' + str(testscript.parameters['forwardingSysDict']['VRF_string']) + str(i) + ''' force-delete''')    
            
            
        except Exception as error:
            log.debug("Unable to configure - Encountered Exception " + str(error))
            self.errored('Exception occurred while clearing arp cache on LEAF-1 and LEAF-2', goto=['cleanup'])
            
    @aetest.test        
    def Host_move_FO(self,testscript):
        
        
        FO_1=testscript.parameters['FO_1']

        
        try:
            FO_1.configure('''
            interface ''' + str(testscript.parameters['intf_FO_1_to_N7k_LEAF_3']) + '''
            shut
            switchport
            switchport mode trunk
            
            interface ''' + str(testscript.parameters['intf_FO_1_to_LEAF_3']) + '''
            no shut
            switchport
            switchport mode trunk
            
            ''')
            time.sleep(45)
            #ForkedPdb().set_trace()
        except Exception as error:
                log.debug("Unable to configure - Encountered Exception " + str(error))
                self.errored('Exception occurred while configuring on FO_1', goto=['common_cleanup'])
                
    @aetest.test
    def VERIFY_IXIA_TRAFFIC_AFTER_MOVE(self, testscript):
        """ IXIA_CONFIGURATION subsection: Verify IXIA Traffic """

        # Do not perform configurations if skip_tgen_config flag is set
        if not testscript.parameters['script_flags']['skip_tgen_config']:

            time.sleep(20)

            if ixLib.verify_traffic(15) == 0:
                log.debug("Traffic Verification failed")
                self.failed("Traffic Verification failed", goto=['cleanup'])
            else:
                log.info("Traffic Verification Passed")
            
        else:
            self.passed(reason="Skipped TGEN Configurations as per request")
            
# =============================================================================================================================#
    @aetest.test
    def Uplink_SHUT(self, testscript):
        """uplink flap on Leaf2"""
        
        LEAF_1 = testscript.parameters['LEAF-1']
        LEAF_2 = testscript.parameters['LEAF-2']
        forwardingSysDict = testscript.parameters['forwardingSysDict']
        
        try:
            LEAF_1.configure(''' 
              interface port-channel ''' + str(testscript.parameters['LEAF_1_dict']['SPINE_1_UPLINK_PO']['po_id']) + '''
              shut                
          ''')
            
            LEAF_2.configure(''' 
              interface port-channel ''' + str(testscript.parameters['LEAF_2_dict']['SPINE_1_UPLINK_PO']['po_id']) + '''
              shut                
          ''')    
        except Exception as error:
            log.debug("Unable to configure - Encountered Exception " + str(error))
            self.errored('Exception occurred while shutting fabric uplink Interface on LEAF-2 and LEAF-1', goto=['cleanup'])
            
    # =============================================================================================================================#        
    
    @aetest.test
    def Uplink_NOSHUT(self, testscript):
        """uplink flap on Leaf2"""
        
        LEAF_1 = testscript.parameters['LEAF-1']
        LEAF_2 = testscript.parameters['LEAF-2']
        forwardingSysDict = testscript.parameters['forwardingSysDict']
        
        try:
            LEAF_1.configure(''' 
              interface port-channel ''' + str(testscript.parameters['LEAF_1_dict']['SPINE_1_UPLINK_PO']['po_id']) + '''
              no shut                
          ''')
            
            LEAF_2.configure(''' 
              interface port-channel ''' + str(testscript.parameters['LEAF_2_dict']['SPINE_1_UPLINK_PO']['po_id']) + '''
              no shut                
          ''')    
            
            time.sleep(30)
        except Exception as error:
            log.debug("Unable to configure - Encountered Exception " + str(error))
            self.errored('Exception occurred while no shutting fabric uplink Interface on LEAF-2 and LEAF-1', goto=['cleanup'])
            
    @aetest.test
    def VERIFY_IXIA_TRAFFIC_AFTER_NVE_FLAP(self, testscript):
        """ IXIA_CONFIGURATION subsection: Verify IXIA Traffic """

        # Do not perform configurations if skip_tgen_config flag is set
        if not testscript.parameters['script_flags']['skip_tgen_config']:

            time.sleep(20)

            if ixLib.verify_traffic(15) == 0:
                log.debug("Traffic Verification failed")
                self.failed("Traffic Verification failed", goto=['cleanup'])
            else:
                log.info("Traffic Verification Passed")
            
        else:
            self.passed(reason="Skipped TGEN Configurations as per request")
            
    @aetest.test        
    def Host_move_FO_BACK(self,testscript):
        
        
        FO_1=testscript.parameters['FO_1']

        
        try:
            FO_1.configure('''
            interface ''' + str(testscript.parameters['intf_FO_1_to_LEAF_3']) + '''
            shut
            switchport
            switchport mode trunk
            
            interface ''' + str(testscript.parameters['intf_FO_1_to_N7k_LEAF_3']) + '''
            no shut
            switchport
            switchport mode trunk
            
            
            
            ''')
            time.sleep(45)
        except Exception as error:
                log.debug("Unable to configure - Encountered Exception " + str(error))
                self.errored('Exception occurred while configuring on FO_1', goto=['common_cleanup'])
                
    @aetest.test
    def VERIFY_IXIA_TRAFFIC_HOST_MOVE_BACK(self, testscript):
        """ IXIA_CONFIGURATION subsection: Verify IXIA Traffic """

        # Do not perform configurations if skip_tgen_config flag is set
        if not testscript.parameters['script_flags']['skip_tgen_config']:

            time.sleep(20)

            if ixLib.verify_traffic(15) == 0:
                log.debug("Traffic Verification failed")
                self.failed("Traffic Verification failed", goto=['cleanup'])
            else:
                log.info("Traffic Verification Passed")
        else:
            self.passed(reason="Skipped TGEN Configurations as per request")
        
    @aetest.cleanup
    def cleanup(self,testscript):
        """Unconfigure qos policies"""
        LEAF_1 = testscript.parameters['LEAF-1']
        LEAF_2 = testscript.parameters['LEAF-2']
        LEAF_3 = testscript.parameters['LEAF-3']
        FO_1=testscript.parameters['FO_1']
        LEAF_1 = testscript.parameters['LEAF-1']
        LEAF_2 = testscript.parameters['LEAF-2']
        forwardingSysDict = testscript.parameters['forwardingSysDict']
        l2_vlan_id = testscript.parameters['N7K_LEAF_1_dict']['Vlan_data']['l2_vlan_start']
        l2_vlan_ipv4_start= testscript.parameters['N7K_LEAF_1_dict']['Vlan_data']['l2_vlan_ipv4_start']
        l2_vlan_ipv4_mask= testscript.parameters['N7K_LEAF_1_dict']['Vlan_data']['l2_vlan_ipv4_mask']
        l2_vlan_ipv6_start= testscript.parameters['N7K_LEAF_1_dict']['Vlan_data']['l2_vlan_ipv6_start']
        l2_vlan_ipv6_mask= testscript.parameters['N7K_LEAF_1_dict']['Vlan_data']['l2_vlan_ipv6_mask']
        l2_hsrp_ipv4_vip_start= testscript.parameters['N7K_LEAF_1_dict']['Vlan_data']['hsrp_ipv4_vip_start']
        l2_hsrp_ipv6_vip_start= testscript.parameters['N7K_LEAF_1_dict']['Vlan_data']['hsrp_ipv6_vip_start']
        total_ip_count = int(forwardingSysDict['VLAN_PER_VRF_count']) * int(forwardingSysDict['VRF_count'])
        l2_vlan_ipv4_sec_start= testscript.parameters['LEAF_2_dict']['VNI_data']['l2_vlan_ipv4_sec_start']
        l2_vlan_ipv4_mask= testscript.parameters['LEAF_2_dict']['VNI_data']['l2_vlan_ipv4_mask']
        l2_ipv4s = increment_prefix_network(ip.IPv4Interface(str(l2_vlan_ipv4_sec_start) + str(l2_vlan_ipv4_mask)),total_ip_count)
        post_test_process_dict = {
            'dut_list'                       : [LEAF_1, LEAF_2, LEAF_3],
            'cc_check'                  : 1,
            'cores_check'               : 1,
            'logs_check'                : 0,
            'fnl_flag'                  : 0,
            'exclude_log_check_pattern' : 'ERROR_VLANS_SUSPENDED|ERROR_VLANS_REMOVED',
            }
        try:
            # UCAST_v4_dict = {
            #                 'mode'        : 'remove',
            #                 'stream_id'   : stream_id,
            #           }
            # if (ixLib.delete_traffic_item(UCAST_v4_dict))==0:
            #     log.debug("Traffic Remove failed")
            #     self.failed("Traffic Remove failed")
            # else:
            #     log.info("Traffic Deletion Passed")
            ###admin no shut of fabric uplink interface on Vxlan Leaf2 and Leaf1
            LEAF_2.configure('''  
              interface port-channel ''' + str(testscript.parameters['LEAF_1_dict']['SPINE_1_UPLINK_PO']['po_id']) + ''' 
              no shut                
            ''')  
            LEAF_1.configure('''  
              interface port-channel ''' + str(testscript.parameters['LEAF_1_dict']['SPINE_1_UPLINK_PO']['po_id']) + ''' 
              no shut                
            ''') 
            ##Move host back to FP
            FO_1.configure('''
            interface ''' + str(testscript.parameters['intf_FO_1_to_LEAF_3']) + '''
            shut
            switchport
            switchport mode trunk
            
            interface ''' + str(testscript.parameters['intf_FO_1_to_N7k_LEAF_3']) + '''
            no shut
            switchport
            switchport mode trunk
            ''')
            time.sleep(30)
            ###Remove Pre-migration step from both N7k leafs
            device_handle=connect_to_vdc(testscript.parameters['xbow1'], 'leaf1')
            if device_handle==False:
                log.info("failed to switchto correct vdc")
                self.failed("failed to switchto correct vdc",goto=['common_cleanup'])
            else:
                total_ip_count = int(forwardingSysDict['VLAN_PER_VRF_count']) * int(forwardingSysDict['VRF_count'])
                l2_ipv4s = increment_prefix_network(ip.IPv4Interface(str(l2_vlan_ipv4_start) + str(l2_vlan_ipv4_mask)),total_ip_count)
                l2_ipv6s = increment_prefix_network(ip.IPv6Interface(str(l2_vlan_ipv6_start) + str(l2_vlan_ipv6_mask)),total_ip_count)
                ip_index=0
                for i in range(0,len(l2_ipv4s)):
                    device_handle.configure('''int vlan ''' + str(l2_vlan_id) + '''\n
                                     hsrp version 2
                                     hsrp ''' + str(l2_vlan_id) + ''' ipv4
                                     no mac-address 0000.000a.aaaa
                                     ''')
                    l2_vlan_id += 1
            l2_vlan_id = testscript.parameters['N7K_LEAF_1_dict']['Vlan_data']['l2_vlan_start']        
            device_handle=connect_to_vdc(testscript.parameters['xbow2'], 'leaf2')
            if device_handle==False:
                log.info("failed to switchto correct vdc")
                self.failed("failed to switchto correct vdc",goto=['common_cleanup'])
            else:
                total_ip_count = int(forwardingSysDict['VLAN_PER_VRF_count']) * int(forwardingSysDict['VRF_count'])
                l2_ipv4s = increment_prefix_network(ip.IPv4Interface(str(l2_vlan_ipv4_start) + str(l2_vlan_ipv4_mask)),total_ip_count)
                l2_ipv6s = increment_prefix_network(ip.IPv6Interface(str(l2_vlan_ipv6_start) + str(l2_vlan_ipv6_mask)),total_ip_count)
                ip_index=0
                for i in range(0,len(l2_ipv4s)):
                    device_handle.configure('''int vlan ''' + str(l2_vlan_id) + '''\n
                                     hsrp version 2
                                     hsrp ''' + str(l2_vlan_id) + ''' ipv4
                                     no mac-address 0000.000a.aaaa
                                     ''')
                    l2_vlan_id += 1
            status = infraVerify.postTestVerification(post_test_process_dict)
            if status['status'] == 0:
                self.failed(reason=status['logs'])
            else:
                self.passed(reason=status['logs'])
        except Exception as error:
            log.debug("Unable to unconfigure class map or policy map-Encountered exception " + str(error))
            self.errored('Exception occurred while unconfiguring qos on LEAF1', goto=['next_tc'])
            
            
# *****************************************************************************************************************************#
class BGP_AS_RESTART_post_Host_move_ipv4(aetest.Testcase):
    """ Host_move_ipv4 """

    
    # =============================================================================================================================#        
    
    @aetest.test
    def SVI_ON_LEAF2(self, testscript):
        """Shut down the vpc leg on Leaf2 to force all traffic to Leaf1"""
        
        LEAF_1 = testscript.parameters['LEAF-1']
        LEAF_2 = testscript.parameters['LEAF-2']
        forwardingSysDict = testscript.parameters['forwardingSysDict']
        l2_vlan_id = testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vlan_start']
        l2_vlan_ipv4_sec_start= testscript.parameters['LEAF_2_dict']['VNI_data']['l2_vlan_ipv4_sec_start']
        l2_vlan_ipv4_mask= testscript.parameters['LEAF_2_dict']['VNI_data']['l2_vlan_ipv4_mask']
        #+ str(testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vlan_ipv4_mask'])
        
        try:
            total_ip_count = int(forwardingSysDict['VLAN_PER_VRF_count']) * int(forwardingSysDict['VRF_count'])
            l2_ipv4s = increment_prefix_network(ip.IPv4Interface(str(l2_vlan_ipv4_sec_start) + str(l2_vlan_ipv4_mask)),total_ip_count)
            ip_index=0
            for i in range(0,len(l2_ipv4s)):
                LEAF_2.configure('''int vlan ''' + str(l2_vlan_id) + '''\n
                                 ip address ''' + str(l2_ipv4s[ip_index]) + ''' secondary use-bia
                                 no shut
                                 ''')
                l2_vlan_id += 1
                ip_index += 1
            
            
        except Exception as error:
            log.debug("Unable to configure - Encountered Exception " + str(error))
            self.errored('Exception occurred while configuring secondary ipv4 address on LEAF-2', goto=['cleanup'])
            
    # =============================================================================================================================#        
    
    @aetest.test
    def SVI_ON_LEAF1(self, testscript):
        """Shut down the vpc leg on Leaf2 to force all traffic to Leaf1"""
        
        LEAF_1 = testscript.parameters['LEAF-1']
        LEAF_2 = testscript.parameters['LEAF-2']
        forwardingSysDict = testscript.parameters['forwardingSysDict']
        l2_vlan_id = testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vlan_start']
        l2_vlan_ipv4_sec_start= testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vlan_ipv4_sec_start']
        l2_vlan_ipv4_mask= testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vlan_ipv4_mask']
        
        try:
            total_ip_count = int(forwardingSysDict['VLAN_PER_VRF_count']) * int(forwardingSysDict['VRF_count'])
            l2_ipv4s = increment_prefix_network(ip.IPv4Interface(str(l2_vlan_ipv4_sec_start) + str(l2_vlan_ipv4_mask)),total_ip_count)
            ip_index=0
            for i in range(0,len(l2_ipv4s)):
                LEAF_1.configure('''int vlan ''' + str(l2_vlan_id) + '''\n
                                 ip address ''' + str(l2_ipv4s[ip_index]) + ''' secondary use-bia
                                 no shut
                                 ''')
                l2_vlan_id += 1
                ip_index += 1
                
            
            
        except Exception as error:
            log.debug("Unable to configure - Encountered Exception " + str(error))
            self.errored('Exception occurred while configuring secondary ipv4 address on LEAF-1', goto=['cleanup'])
            
     # =============================================================================================================================#        
    @aetest.test
    def Add_external_int(self, testscript):
        """Shut down the vpc leg on Leaf2 to force all traffic to Leaf1"""
        
        LEAF_1 = testscript.parameters['LEAF-1']
        LEAF_2 = testscript.parameters['LEAF-2']
        
        try:
            testscript.parameters['LEAF-2'].configure('''
                  interface po ''' + str(testscript.parameters['LEAF_1_dict']['VPC_data']['double_vpc_po_1']) + '''
                  port-type external
                  ''')
            
            testscript.parameters['LEAF-1'].configure('''
                  interface po ''' + str(testscript.parameters['LEAF_1_dict']['VPC_data']['double_vpc_po_1']) + '''
                  port-type external
                  ''')    
            
            
        except Exception as error:
            log.debug("Unable to configure - Encountered Exception " + str(error))
            self.errored('Exception occurred while configuring external on LEAF-1 and LEAF-2', goto=['cleanup'])
            
     # =============================================================================================================================#    
    @aetest.test
    def Pre_migration_hsrp(self,testscript):
        LEAF_1 = testscript.parameters['LEAF-1']
        LEAF_2 = testscript.parameters['LEAF-2']
        forwardingSysDict = testscript.parameters['forwardingSysDict']
        l2_vlan_id = testscript.parameters['N7K_LEAF_1_dict']['Vlan_data']['l2_vlan_start']
        l2_vlan_ipv4_start= testscript.parameters['N7K_LEAF_1_dict']['Vlan_data']['l2_vlan_ipv4_start']
        l2_vlan_ipv4_mask= testscript.parameters['N7K_LEAF_1_dict']['Vlan_data']['l2_vlan_ipv4_mask']
        l2_vlan_ipv6_start= testscript.parameters['N7K_LEAF_1_dict']['Vlan_data']['l2_vlan_ipv6_start']
        l2_vlan_ipv6_mask= testscript.parameters['N7K_LEAF_1_dict']['Vlan_data']['l2_vlan_ipv6_mask']
        l2_hsrp_ipv4_vip_start= testscript.parameters['N7K_LEAF_1_dict']['Vlan_data']['hsrp_ipv4_vip_start']
        l2_hsrp_ipv6_vip_start= testscript.parameters['N7K_LEAF_1_dict']['Vlan_data']['hsrp_ipv6_vip_start']
        
        try:
            device_handle=connect_to_vdc(testscript.parameters['xbow1'], 'leaf1')
            if device_handle==False:
                log.info("failed to switchto correct vdc")
                self.failed("failed to switchto correct vdc",goto=['common_cleanup'])
            else:
                total_ip_count = int(forwardingSysDict['VLAN_PER_VRF_count']) * int(forwardingSysDict['VRF_count'])
                l2_ipv4s = increment_prefix_network(ip.IPv4Interface(str(l2_vlan_ipv4_start) + str(l2_vlan_ipv4_mask)),total_ip_count)
                l2_ipv6s = increment_prefix_network(ip.IPv6Interface(str(l2_vlan_ipv6_start) + str(l2_vlan_ipv6_mask)),total_ip_count)
                ip_index=0
                for i in range(0,len(l2_ipv4s)):
                    device_handle.configure('''int vlan ''' + str(l2_vlan_id) + '''\n
                                     hsrp version 2
                                     hsrp ''' + str(l2_vlan_id) + ''' ipv4
                                     mac-address 0000.000a.aaaa
                                     ''')
                    l2_vlan_id += 1
            l2_vlan_id = testscript.parameters['N7K_LEAF_1_dict']['Vlan_data']['l2_vlan_start']        
            device_handle=connect_to_vdc(testscript.parameters['xbow2'], 'leaf2')
            if device_handle==False:
                log.info("failed to switchto correct vdc")
                self.failed("failed to switchto correct vdc",goto=['common_cleanup'])
            else:
                total_ip_count = int(forwardingSysDict['VLAN_PER_VRF_count']) * int(forwardingSysDict['VRF_count'])
                l2_ipv4s = increment_prefix_network(ip.IPv4Interface(str(l2_vlan_ipv4_start) + str(l2_vlan_ipv4_mask)),total_ip_count)
                l2_ipv6s = increment_prefix_network(ip.IPv6Interface(str(l2_vlan_ipv6_start) + str(l2_vlan_ipv6_mask)),total_ip_count)
                ip_index=0
                for i in range(0,len(l2_ipv4s)):
                    device_handle.configure('''int vlan ''' + str(l2_vlan_id) + '''\n
                                     hsrp version 2
                                     hsrp ''' + str(l2_vlan_id) + ''' ipv4
                                     mac-address 0000.000a.aaaa
                                     ''')
                    l2_vlan_id += 1
                    


        except Exception as error:
                log.debug("Unable to configure - Encountered Exception " + str(error))
                self.errored('Exception occurred while configuring on N7k leaf1', goto=['common_cleanup'])
                
    @aetest.test        
    def configure_FO(self,testscript):
        
        FO_1_vlanConfiguration = ""
        FO_1=testscript.parameters['FO_1']

        l3_vrf_count_iter = 0
        l2_vlan_id = testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vlan_start']
        l3_vlan_id = testscript.parameters['LEAF_1_dict']['VNI_data']['l3_vlan_start']

        while l3_vrf_count_iter < testscript.parameters['forwardingSysDict']['VRF_count']:
            l2_vlan_count_iter = 0
            FO_1_vlanConfiguration += '''vlan ''' + str(l3_vlan_id) + '''\n
                                            state active\n
                                            no shut\n'''
            while l2_vlan_count_iter < testscript.parameters['forwardingSysDict']['VLAN_PER_VRF_count']:
                # Incrementing L2 VLAN Iteration counters
                FO_1_vlanConfiguration += '''vlan ''' + str(l2_vlan_id) + '''\n
                                                state active\n
                                                no shut\n'''
                l2_vlan_count_iter += 1
                l2_vlan_id += 1
            # Incrementing L3 VRF Iteration counters
            l3_vrf_count_iter += 1
            l3_vlan_id += 1

        try:
            FO_1.configure(
                str(FO_1_vlanConfiguration) + '''
        
        
            
            interface ''' + str(testscript.parameters['intf_FO_1_to_N7k_LEAF_3']) + '''
            no shut
            switchport
            switchport mode trunk
            
            interface ''' + str(testscript.parameters['intf_FO_1_to_LEAF_3']) + '''
            shut
            switchport
            switchport mode trunk
            
            interface ''' + str(testscript.parameters['intf_FO_1_to_IXIA']) + '''
            no shut
            switchport
            switchport mode trunk
            
            ''')
        except Exception as error:
                log.debug("Unable to configure - Encountered Exception " + str(error))
                self.errored('Exception occurred while configuring on FO_1', goto=['common_cleanup'])
   
#     @aetest.test
#     def CONFIGURE_UCAST_L3_IXIA_TRAFFIC(self, testscript):
#         """ IXIA_CONFIGURATION subsection: Configure MCAST Traffic Item """
# 
#         # Do not perform configurations if skip_tgen_config flag is set
#         if not testscript.parameters['script_flags']['skip_tgen_config']:
# 
#             IX_TP1 = testscript.parameters['IX_TP1']
#             IX_TP2 = testscript.parameters['IX_TP2']
#             P1_dict = testscript.parameters['LEAF_2_TGEN_dict']
#             P2_dict = testscript.parameters['LEAF_3_TGEN_dict']
# 
#             UCAST_v4_dict = {   'src_hndl'  : IX_TP1['port_handle'],
#                                 'dst_hndl'  : IX_TP2['port_handle'],
#                                 'ip_dscp'   : P1_dict['ip_dscp'],
#                                 'circuit'   : 'raw',
#                                 'TI_name'   : "UCAST_L3",
#                                 'rate_pps'  : "9000",
#                                 'bi_dir'    : 1,
#                                 'frame_size': '128',
#                                 'src_mac'   : P1_dict['mac'],
#                                 'dst_mac'   : '0000.000a.aaaa',
#                                 'srcmac_step': '00:00:00:00:00:00',
#                                 'dstmac_step': '00:00:00:00:00:00',
#                                 'srcmac_count': '1',
#                                 'dstmac_count': '1',
#                                 'vlan_id'    : P1_dict['vlan_id'],
#                                 'vlanid_step': '0',
#                                 'vlanid_count': '1',
#                                 'vlan_user_priority': P1_dict['vlan_user_priority'],
#                                 'ip_src_addrs' : P1_dict['v4_addr'],
#                                 'ip_dst_addrs' : P1_dict['L3_dst_addr'],
#                                 'ip_src_step' : '0.0.0.0',
#                                 'ip_dst_step' : '0.0.0.0',
# #                                'ip_step'    : P1_dict['v4_addr_step'],
#                           }
# 
# #            UCAST_v6_dict = {   'src_hndl'  : IX_TP1['ipv6_handle'],
# #                                'dst_hndl'  : IX_TP2['ipv6_handle'],
# #                                'circuit'   : 'ipv6',
# #                                'TI_name'   : "UCAST_V6",
# #                                'rate_pps'  : "1000",
# #                                'bi_dir'    : 1
# #                          }
# 
#             UCAST_v4_TI = ixLib.configure_ixia_l3_traffic_item(UCAST_v4_dict)
# #            UCAST_v6_TI = ixLib.configure_ixia_traffic_item(UCAST_v6_dict)
# 
# #            if UCAST_v4_TI == 0 or UCAST_v6_TI == 0:
# #                log.debug("Configuring UCast TI failed")
# #                self.errored("Configuring UCast TI failed", goto=['cleanup'])
#                 
#             if UCAST_v4_TI == 0:
#                 log.debug("Configuring UCast TI failed")
#                 self.errored("Configuring UCast TI failed", goto=['cleanup'])
#             else:
#                 global stream_id
#                 stream_id = UCAST_v4_TI
#             
# 
#         else:
#             self.passed(reason="Skipped TGEN Configurations as per request")
            
    # @aetest.test
    # def CONFIGURE_BCAST_IXIA_TRAFFIC(self, testscript):
    #     """ IXIA_CONFIGURATION subsection: Configure MCAST Traffic Item """
    # 
    #     # Do not perform configurations if skip_tgen_config flag is set
    #     if not testscript.parameters['script_flags']['skip_tgen_config']:
    # 
    #         IX_TP1 = testscript.parameters['IX_TP1']
    #         IX_TP2 = testscript.parameters['IX_TP2']
    #         P1_dict = testscript.parameters['LEAF_2_TGEN_dict']
    #         P2_dict = testscript.parameters['LEAF_3_TGEN_dict']
    #         BCAST_v4_dict = {
    #                             'src_hndl'      : IX_TP1['port_handle'],
    #                             'dst_hndl'      : IX_TP2['port_handle'],
    #                             'TI_name'       : "BCAST_V4",
    #                             'frame_size'    : "70",
    #                             'rate_pps'      : "1000",
    #                             'src_mac'       : P1_dict['mac'],
    #                             'srcmac_step'   : "00:00:00:00:00:01",
    #                             'srcmac_count'  : '1',
    #                             'vlan_id'       : P1_dict['vlan_id'],
    #                             'vlanid_step'   : "1",
    #                             'vlanid_count'  : "1",
    #                             'ip_src_addrs'  : P1_dict['v4_addr'],
    #                             'ip_step'       : "0.0.1.0",
    #                       }
    # 
    #         BCAST_v4_TI = ixLib.configure_ixia_BCAST_traffic_item(BCAST_v4_dict)
    # 
    #         if BCAST_v4_TI == 0:
    #             log.debug("Configuring BCast TI failed")
    #             self.errored("Configuring BCast TI failed", goto=['cleanup'])
    #         
    # 
    #     else:
    #         self.passed(reason="Skipped TGEN Configurations as per request")
    # =============================================================================================================================#
    @aetest.test
    def APPLY_TRAFFIC(self):
        """ IXIA_CONFIGURATION subsection: Verify IXIA Traffic """

        # # Apply IXIA Traffic
        # if ixLib.apply_traffic() == 1:
        #     log.info("Applying IXIA TI Passed")
        # else:
        #     self.errored("Applying IXIA TI failed", goto=['cleanup'])
            
        # =============================================================================================================================#
    #--------------------------------------------------------------------------------#
        # Start traffic from ixia
        log.info("--- Populating the statistics --- \n")
        log.info("---- Running Traffic --- \n")
        log.info("Starting Traffic")

        traffic_run_status  = ixLib.start_traffic()

        if traffic_run_status is not 1:
           log.info("Failed: To start traffic")
           return 0
        else:
            log.info("\nTraffic started successfully\n")

        time.sleep(30)
    
    # Stop Traffic from ixia
        log.info("--- Stopping Traffic ---- \n")
        log.info("Stopping Traffic")
        traffic_run_status = ixLib.stop_traffic()
        
        if traffic_run_status is not 1:
           log.info("Failed: To Stop traffic")
           return 0
        else:
            log.info("\nTraffic Stopped successfully\n")
            time.sleep(10)    
    
    @aetest.test
    def VERIFY_IXIA_TRAFFIC(self, testscript):
        """ IXIA_CONFIGURATION subsection: Verify IXIA Traffic """

        # Do not perform configurations if skip_tgen_config flag is set
        if not testscript.parameters['script_flags']['skip_tgen_config']:

            time.sleep(20)

            if ixLib.verify_traffic(2) == 0:
                log.debug("Traffic Verification failed")
                self.failed("Traffic Verification failed", goto=['cleanup'])
            else:
                log.info("Traffic Verification Passed")
        else:
            self.passed(reason="Skipped TGEN Configurations as per request")

     # =============================================================================================================================#        
    @aetest.test
    def Clear_ARP_Table_on_Vxlan_BLs(self, testscript):
        """Shut down the vpc leg on Leaf2 to force all traffic to Leaf1"""
        
        LEAF_1 = testscript.parameters['LEAF-1']
        LEAF_2 = testscript.parameters['LEAF-2']
        
        try:
            for i in range(1, testscript.parameters['forwardingSysDict']['VRF_count']+1):
                testscript.parameters['LEAF-2'].execute('''
                      clear ip arp vrf ''' + str(testscript.parameters['forwardingSysDict']['VRF_string']) + str(i) + ''' force-delete''')
            
            for i in range(1, testscript.parameters['forwardingSysDict']['VRF_count']+1):
                testscript.parameters['LEAF-1'].execute('''
                      clear ip arp vrf ''' + str(testscript.parameters['forwardingSysDict']['VRF_string']) + str(i) + ''' force-delete''')    
            
            
        except Exception as error:
            log.debug("Unable to configure - Encountered Exception " + str(error))
            self.errored('Exception occurred while clearing arp cache on LEAF-1 and LEAF-2', goto=['cleanup'])
            
    @aetest.test        
    def Host_move_FO(self,testscript):
        
        
        FO_1=testscript.parameters['FO_1']

        
        try:
            FO_1.configure('''
            interface ''' + str(testscript.parameters['intf_FO_1_to_N7k_LEAF_3']) + '''
            shut
            switchport
            switchport mode trunk
            
            interface ''' + str(testscript.parameters['intf_FO_1_to_LEAF_3']) + '''
            no shut
            switchport
            switchport mode trunk
            
            ''')
            time.sleep(45)
            #ForkedPdb().set_trace()
        except Exception as error:
                log.debug("Unable to configure - Encountered Exception " + str(error))
                self.errored('Exception occurred while configuring on FO_1', goto=['common_cleanup'])
                
    @aetest.test
    def VERIFY_IXIA_TRAFFIC_AFTER_MOVE(self, testscript):
        """ IXIA_CONFIGURATION subsection: Verify IXIA Traffic """

        # Do not perform configurations if skip_tgen_config flag is set
        if not testscript.parameters['script_flags']['skip_tgen_config']:

            time.sleep(20)

            if ixLib.verify_traffic(15) == 0:
                log.debug("Traffic Verification failed")
                self.failed("Traffic Verification failed", goto=['cleanup'])
            else:
                log.info("Traffic Verification Passed")
            
        else:
            self.passed(reason="Skipped TGEN Configurations as per request")
# =============================================================================================================================#
    @aetest.test
    def verify_restart_bgp(self, testscript):
        """ VXLAN_DISRUPTIVE_VERIFICATION subsection: Verify Restart BGP """

        LEAF_1 = testscript.parameters['LEAF-1']
        LEAF_2 = testscript.parameters['LEAF-2']
        LEAF_3 = testscript.parameters['LEAF-3']
        

        forwardingSysDict = testscript.parameters['forwardingSysDict']

        # ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~#
        # Restart BGP
        LEAF_1.configure('restart bgp '+str(forwardingSysDict['BGP_AS_num']))
        LEAF_2.configure('restart bgp '+str(forwardingSysDict['BGP_AS_num']))
        LEAF_3.configure('restart bgp '+str(forwardingSysDict['BGP_AS_num']))

        time.sleep(60)

        # ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~#
        # Verify BGP session is established
        import json
        for LEAF in [LEAF_1,LEAF_2,LEAF_3]:
            output=LEAF.execute("sh bgp sessions | json-pretty")
            a=json.loads(output)
            if a['TABLE_vrf']['ROW_vrf']['TABLE_neighbor']['ROW_neighbor']['state']!="Established":
                log.info("BGP session not established on " + str(LEAF))
                self.failed("BGP session not established", goto=['cleanup'])
            else:
                log.info("BGP session established on " + str(LEAF))
                    
# =============================================================================================================================#
    
            
    @aetest.test
    def VERIFY_IXIA_TRAFFIC_AFTER_BGP_RESTART(self, testscript):
        """ IXIA_CONFIGURATION subsection: Verify IXIA Traffic """

        # Do not perform configurations if skip_tgen_config flag is set
        if not testscript.parameters['script_flags']['skip_tgen_config']:

            time.sleep(20)

            if ixLib.verify_traffic(15) == 0:
                log.debug("Traffic Verification failed")
                self.failed("Traffic Verification failed", goto=['cleanup'])
            else:
                log.info("Traffic Verification Passed")
            
        else:
            self.passed(reason="Skipped TGEN Configurations as per request")
            
    @aetest.test        
    def Host_move_FO_BACK(self,testscript):
        
        
        FO_1=testscript.parameters['FO_1']

        
        try:
            FO_1.configure('''
            interface ''' + str(testscript.parameters['intf_FO_1_to_LEAF_3']) + '''
            shut
            switchport
            switchport mode trunk
            
            interface ''' + str(testscript.parameters['intf_FO_1_to_N7k_LEAF_3']) + '''
            no shut
            switchport
            switchport mode trunk
            
            
            
            ''')
            time.sleep(45)
        except Exception as error:
                log.debug("Unable to configure - Encountered Exception " + str(error))
                self.errored('Exception occurred while configuring on FO_1', goto=['common_cleanup'])
                
    @aetest.test
    def VERIFY_IXIA_TRAFFIC_HOST_MOVE_BACK(self, testscript):
        """ IXIA_CONFIGURATION subsection: Verify IXIA Traffic """

        # Do not perform configurations if skip_tgen_config flag is set
        if not testscript.parameters['script_flags']['skip_tgen_config']:

            time.sleep(20)

            if ixLib.verify_traffic(15) == 0:
                log.debug("Traffic Verification failed")
                self.failed("Traffic Verification failed", goto=['cleanup'])
            else:
                log.info("Traffic Verification Passed")
        else:
            self.passed(reason="Skipped TGEN Configurations as per request")
        
    @aetest.cleanup
    def cleanup(self,testscript):
        """Unconfigure qos policies"""
        LEAF_1 = testscript.parameters['LEAF-1']
        LEAF_2 = testscript.parameters['LEAF-2']
        LEAF_3 = testscript.parameters['LEAF-3']
        FO_1=testscript.parameters['FO_1']
        LEAF_1 = testscript.parameters['LEAF-1']
        LEAF_2 = testscript.parameters['LEAF-2']
        forwardingSysDict = testscript.parameters['forwardingSysDict']
        l2_vlan_id = testscript.parameters['N7K_LEAF_1_dict']['Vlan_data']['l2_vlan_start']
        l2_vlan_ipv4_start= testscript.parameters['N7K_LEAF_1_dict']['Vlan_data']['l2_vlan_ipv4_start']
        l2_vlan_ipv4_mask= testscript.parameters['N7K_LEAF_1_dict']['Vlan_data']['l2_vlan_ipv4_mask']
        l2_vlan_ipv6_start= testscript.parameters['N7K_LEAF_1_dict']['Vlan_data']['l2_vlan_ipv6_start']
        l2_vlan_ipv6_mask= testscript.parameters['N7K_LEAF_1_dict']['Vlan_data']['l2_vlan_ipv6_mask']
        l2_hsrp_ipv4_vip_start= testscript.parameters['N7K_LEAF_1_dict']['Vlan_data']['hsrp_ipv4_vip_start']
        l2_hsrp_ipv6_vip_start= testscript.parameters['N7K_LEAF_1_dict']['Vlan_data']['hsrp_ipv6_vip_start']
        total_ip_count = int(forwardingSysDict['VLAN_PER_VRF_count']) * int(forwardingSysDict['VRF_count'])
        l2_vlan_ipv4_sec_start= testscript.parameters['LEAF_2_dict']['VNI_data']['l2_vlan_ipv4_sec_start']
        l2_vlan_ipv4_mask= testscript.parameters['LEAF_2_dict']['VNI_data']['l2_vlan_ipv4_mask']
        l2_ipv4s = increment_prefix_network(ip.IPv4Interface(str(l2_vlan_ipv4_sec_start) + str(l2_vlan_ipv4_mask)),total_ip_count)
        post_test_process_dict = {
            'dut_list'                       : [LEAF_1, LEAF_2, LEAF_3],
            'cc_check'                  : 1,
            'cores_check'               : 1,
            'logs_check'                : 0,
            'fnl_flag'                  : 0,
            'exclude_log_check_pattern' : 'ERROR_VLANS_SUSPENDED|ERROR_VLANS_REMOVED',
            }
        try:
            # UCAST_v4_dict = {
            #                 'mode'        : 'remove',
            #                 'stream_id'   : stream_id,
            #           }
            # if (ixLib.delete_traffic_item(UCAST_v4_dict))==0:
            #     log.debug("Traffic Remove failed")
            #     self.failed("Traffic Remove failed")
            # else:
            #     log.info("Traffic Deletion Passed")
            
            ##Move host back to FP
            FO_1.configure('''
            interface ''' + str(testscript.parameters['intf_FO_1_to_LEAF_3']) + '''
            shut
            switchport
            switchport mode trunk
            
            interface ''' + str(testscript.parameters['intf_FO_1_to_N7k_LEAF_3']) + '''
            no shut
            switchport
            switchport mode trunk
            ''')
            time.sleep(30)
            ###Remove Pre-migration step from both N7k leafs
            device_handle=connect_to_vdc(testscript.parameters['xbow1'], 'leaf1')
            if device_handle==False:
                log.info("failed to switchto correct vdc")
                self.failed("failed to switchto correct vdc",goto=['common_cleanup'])
            else:
                total_ip_count = int(forwardingSysDict['VLAN_PER_VRF_count']) * int(forwardingSysDict['VRF_count'])
                l2_ipv4s = increment_prefix_network(ip.IPv4Interface(str(l2_vlan_ipv4_start) + str(l2_vlan_ipv4_mask)),total_ip_count)
                l2_ipv6s = increment_prefix_network(ip.IPv6Interface(str(l2_vlan_ipv6_start) + str(l2_vlan_ipv6_mask)),total_ip_count)
                ip_index=0
                for i in range(0,len(l2_ipv4s)):
                    device_handle.configure('''int vlan ''' + str(l2_vlan_id) + '''\n
                                     hsrp version 2
                                     hsrp ''' + str(l2_vlan_id) + ''' ipv4
                                     no mac-address 0000.000a.aaaa
                                     ''')
                    l2_vlan_id += 1
            l2_vlan_id = testscript.parameters['N7K_LEAF_1_dict']['Vlan_data']['l2_vlan_start']        
            device_handle=connect_to_vdc(testscript.parameters['xbow2'], 'leaf2')
            if device_handle==False:
                log.info("failed to switchto correct vdc")
                self.failed("failed to switchto correct vdc",goto=['common_cleanup'])
            else:
                total_ip_count = int(forwardingSysDict['VLAN_PER_VRF_count']) * int(forwardingSysDict['VRF_count'])
                l2_ipv4s = increment_prefix_network(ip.IPv4Interface(str(l2_vlan_ipv4_start) + str(l2_vlan_ipv4_mask)),total_ip_count)
                l2_ipv6s = increment_prefix_network(ip.IPv6Interface(str(l2_vlan_ipv6_start) + str(l2_vlan_ipv6_mask)),total_ip_count)
                ip_index=0
                for i in range(0,len(l2_ipv4s)):
                    device_handle.configure('''int vlan ''' + str(l2_vlan_id) + '''\n
                                     hsrp version 2
                                     hsrp ''' + str(l2_vlan_id) + ''' ipv4
                                     no mac-address 0000.000a.aaaa
                                     ''')
                    l2_vlan_id += 1
            status = infraVerify.postTestVerification(post_test_process_dict)
            if status['status'] == 0:
                self.failed(reason=status['logs'])
            else:
                self.passed(reason=status['logs'])
        except Exception as error:
            log.debug("Unable to unconfigure class map or policy map-Encountered exception " + str(error))
            self.errored('Exception occurred while unconfiguring qos on LEAF1', goto=['next_tc'])
            
# *****************************************************************************************************************************#
class VPC_PeerLink_Flap_pre_Host_move_ipv4(aetest.Testcase):
    """ Host_move_ipv4 """

    
    # =============================================================================================================================#        
    
    @aetest.test
    def SVI_ON_LEAF2(self, testscript):
        """Shut down the vpc leg on Leaf2 to force all traffic to Leaf1"""
        
        LEAF_1 = testscript.parameters['LEAF-1']
        LEAF_2 = testscript.parameters['LEAF-2']
        forwardingSysDict = testscript.parameters['forwardingSysDict']
        l2_vlan_id = testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vlan_start']
        l2_vlan_ipv4_sec_start= testscript.parameters['LEAF_2_dict']['VNI_data']['l2_vlan_ipv4_sec_start']
        l2_vlan_ipv4_mask= testscript.parameters['LEAF_2_dict']['VNI_data']['l2_vlan_ipv4_mask']
        #+ str(testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vlan_ipv4_mask'])
        
        try:
            total_ip_count = int(forwardingSysDict['VLAN_PER_VRF_count']) * int(forwardingSysDict['VRF_count'])
            l2_ipv4s = increment_prefix_network(ip.IPv4Interface(str(l2_vlan_ipv4_sec_start) + str(l2_vlan_ipv4_mask)),total_ip_count)
            ip_index=0
            for i in range(0,len(l2_ipv4s)):
                LEAF_2.configure('''int vlan ''' + str(l2_vlan_id) + '''\n
                                 ip address ''' + str(l2_ipv4s[ip_index]) + ''' secondary use-bia
                                 no shut
                                 ''')
                l2_vlan_id += 1
                ip_index += 1
            
            
        except Exception as error:
            log.debug("Unable to configure - Encountered Exception " + str(error))
            self.errored('Exception occurred while configuring secondary ipv4 address on LEAF-2', goto=['cleanup'])
            
    # =============================================================================================================================#        
    
    @aetest.test
    def SVI_ON_LEAF1(self, testscript):
        """Shut down the vpc leg on Leaf2 to force all traffic to Leaf1"""
        
        LEAF_1 = testscript.parameters['LEAF-1']
        LEAF_2 = testscript.parameters['LEAF-2']
        forwardingSysDict = testscript.parameters['forwardingSysDict']
        l2_vlan_id = testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vlan_start']
        l2_vlan_ipv4_sec_start= testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vlan_ipv4_sec_start']
        l2_vlan_ipv4_mask= testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vlan_ipv4_mask']
        
        try:
            total_ip_count = int(forwardingSysDict['VLAN_PER_VRF_count']) * int(forwardingSysDict['VRF_count'])
            l2_ipv4s = increment_prefix_network(ip.IPv4Interface(str(l2_vlan_ipv4_sec_start) + str(l2_vlan_ipv4_mask)),total_ip_count)
            ip_index=0
            for i in range(0,len(l2_ipv4s)):
                LEAF_1.configure('''int vlan ''' + str(l2_vlan_id) + '''\n
                                 ip address ''' + str(l2_ipv4s[ip_index]) + ''' secondary use-bia
                                 no shut
                                 ''')
                l2_vlan_id += 1
                ip_index += 1
                
            
            
        except Exception as error:
            log.debug("Unable to configure - Encountered Exception " + str(error))
            self.errored('Exception occurred while configuring secondary ipv4 address on LEAF-1', goto=['cleanup'])
            
     # =============================================================================================================================#        
    @aetest.test
    def Add_external_int(self, testscript):
        """Shut down the vpc leg on Leaf2 to force all traffic to Leaf1"""
        
        LEAF_1 = testscript.parameters['LEAF-1']
        LEAF_2 = testscript.parameters['LEAF-2']
        
        try:
            testscript.parameters['LEAF-2'].configure('''
                  interface po ''' + str(testscript.parameters['LEAF_1_dict']['VPC_data']['double_vpc_po_1']) + '''
                  port-type external
                  ''')
            
            testscript.parameters['LEAF-1'].configure('''
                  interface po ''' + str(testscript.parameters['LEAF_1_dict']['VPC_data']['double_vpc_po_1']) + '''
                  port-type external
                  ''')    
            
            
        except Exception as error:
            log.debug("Unable to configure - Encountered Exception " + str(error))
            self.errored('Exception occurred while configuring external on LEAF-1 and LEAF-2', goto=['cleanup'])
            
     # =============================================================================================================================#    
    @aetest.test
    def Pre_migration_hsrp(self,testscript):
        LEAF_1 = testscript.parameters['LEAF-1']
        LEAF_2 = testscript.parameters['LEAF-2']
        forwardingSysDict = testscript.parameters['forwardingSysDict']
        l2_vlan_id = testscript.parameters['N7K_LEAF_1_dict']['Vlan_data']['l2_vlan_start']
        l2_vlan_ipv4_start= testscript.parameters['N7K_LEAF_1_dict']['Vlan_data']['l2_vlan_ipv4_start']
        l2_vlan_ipv4_mask= testscript.parameters['N7K_LEAF_1_dict']['Vlan_data']['l2_vlan_ipv4_mask']
        l2_vlan_ipv6_start= testscript.parameters['N7K_LEAF_1_dict']['Vlan_data']['l2_vlan_ipv6_start']
        l2_vlan_ipv6_mask= testscript.parameters['N7K_LEAF_1_dict']['Vlan_data']['l2_vlan_ipv6_mask']
        l2_hsrp_ipv4_vip_start= testscript.parameters['N7K_LEAF_1_dict']['Vlan_data']['hsrp_ipv4_vip_start']
        l2_hsrp_ipv6_vip_start= testscript.parameters['N7K_LEAF_1_dict']['Vlan_data']['hsrp_ipv6_vip_start']
        
        try:
            device_handle=connect_to_vdc(testscript.parameters['xbow1'], 'leaf1')
            if device_handle==False:
                log.info("failed to switchto correct vdc")
                self.failed("failed to switchto correct vdc",goto=['common_cleanup'])
            else:
                total_ip_count = int(forwardingSysDict['VLAN_PER_VRF_count']) * int(forwardingSysDict['VRF_count'])
                l2_ipv4s = increment_prefix_network(ip.IPv4Interface(str(l2_vlan_ipv4_start) + str(l2_vlan_ipv4_mask)),total_ip_count)
                l2_ipv6s = increment_prefix_network(ip.IPv6Interface(str(l2_vlan_ipv6_start) + str(l2_vlan_ipv6_mask)),total_ip_count)
                ip_index=0
                for i in range(0,len(l2_ipv4s)):
                    device_handle.configure('''int vlan ''' + str(l2_vlan_id) + '''\n
                                     hsrp version 2
                                     hsrp ''' + str(l2_vlan_id) + ''' ipv4
                                     mac-address 0000.000a.aaaa
                                     ''')
                    l2_vlan_id += 1
            l2_vlan_id = testscript.parameters['N7K_LEAF_1_dict']['Vlan_data']['l2_vlan_start']        
            device_handle=connect_to_vdc(testscript.parameters['xbow2'], 'leaf2')
            if device_handle==False:
                log.info("failed to switchto correct vdc")
                self.failed("failed to switchto correct vdc",goto=['common_cleanup'])
            else:
                total_ip_count = int(forwardingSysDict['VLAN_PER_VRF_count']) * int(forwardingSysDict['VRF_count'])
                l2_ipv4s = increment_prefix_network(ip.IPv4Interface(str(l2_vlan_ipv4_start) + str(l2_vlan_ipv4_mask)),total_ip_count)
                l2_ipv6s = increment_prefix_network(ip.IPv6Interface(str(l2_vlan_ipv6_start) + str(l2_vlan_ipv6_mask)),total_ip_count)
                ip_index=0
                for i in range(0,len(l2_ipv4s)):
                    device_handle.configure('''int vlan ''' + str(l2_vlan_id) + '''\n
                                     hsrp version 2
                                     hsrp ''' + str(l2_vlan_id) + ''' ipv4
                                     mac-address 0000.000a.aaaa
                                     ''')
                    l2_vlan_id += 1
                    


        except Exception as error:
                log.debug("Unable to configure - Encountered Exception " + str(error))
                self.errored('Exception occurred while configuring on N7k leaf1', goto=['common_cleanup'])
                
    @aetest.test        
    def configure_FO(self,testscript):
        
        FO_1_vlanConfiguration = ""
        FO_1=testscript.parameters['FO_1']

        l3_vrf_count_iter = 0
        l2_vlan_id = testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vlan_start']
        l3_vlan_id = testscript.parameters['LEAF_1_dict']['VNI_data']['l3_vlan_start']

        while l3_vrf_count_iter < testscript.parameters['forwardingSysDict']['VRF_count']:
            l2_vlan_count_iter = 0
            FO_1_vlanConfiguration += '''vlan ''' + str(l3_vlan_id) + '''\n
                                            state active\n
                                            no shut\n'''
            while l2_vlan_count_iter < testscript.parameters['forwardingSysDict']['VLAN_PER_VRF_count']:
                # Incrementing L2 VLAN Iteration counters
                FO_1_vlanConfiguration += '''vlan ''' + str(l2_vlan_id) + '''\n
                                                state active\n
                                                no shut\n'''
                l2_vlan_count_iter += 1
                l2_vlan_id += 1
            # Incrementing L3 VRF Iteration counters
            l3_vrf_count_iter += 1
            l3_vlan_id += 1

        try:
            FO_1.configure(
                str(FO_1_vlanConfiguration) + '''
        
        
            
            interface ''' + str(testscript.parameters['intf_FO_1_to_N7k_LEAF_3']) + '''
            no shut
            switchport
            switchport mode trunk
            
            interface ''' + str(testscript.parameters['intf_FO_1_to_LEAF_3']) + '''
            shut
            switchport
            switchport mode trunk
            
            interface ''' + str(testscript.parameters['intf_FO_1_to_IXIA']) + '''
            no shut
            switchport
            switchport mode trunk
            
            ''')
        except Exception as error:
                log.debug("Unable to configure - Encountered Exception " + str(error))
                self.errored('Exception occurred while configuring on FO_1', goto=['common_cleanup'])
   
#     @aetest.test
#     def CONFIGURE_UCAST_L3_IXIA_TRAFFIC(self, testscript):
#         """ IXIA_CONFIGURATION subsection: Configure MCAST Traffic Item """
# 
#         # Do not perform configurations if skip_tgen_config flag is set
#         if not testscript.parameters['script_flags']['skip_tgen_config']:
# 
#             IX_TP1 = testscript.parameters['IX_TP1']
#             IX_TP2 = testscript.parameters['IX_TP2']
#             P1_dict = testscript.parameters['LEAF_2_TGEN_dict']
#             P2_dict = testscript.parameters['LEAF_3_TGEN_dict']
# 
#             UCAST_v4_dict = {   'src_hndl'  : IX_TP1['port_handle'],
#                                 'dst_hndl'  : IX_TP2['port_handle'],
#                                 'ip_dscp'   : P1_dict['ip_dscp'],
#                                 'circuit'   : 'raw',
#                                 'TI_name'   : "UCAST_L3",
#                                 'rate_pps'  : "9000",
#                                 'bi_dir'    : 1,
#                                 'frame_size': '128',
#                                 'src_mac'   : P1_dict['mac'],
#                                 'dst_mac'   : '0000.000a.aaaa',
#                                 'srcmac_step': '00:00:00:00:00:00',
#                                 'dstmac_step': '00:00:00:00:00:00',
#                                 'srcmac_count': '1',
#                                 'dstmac_count': '1',
#                                 'vlan_id'    : P1_dict['vlan_id'],
#                                 'vlanid_step': '0',
#                                 'vlanid_count': '1',
#                                 'vlan_user_priority': P1_dict['vlan_user_priority'],
#                                 'ip_src_addrs' : P1_dict['v4_addr'],
#                                 'ip_dst_addrs' : P1_dict['L3_dst_addr'],
#                                 'ip_src_step' : '0.0.0.0',
#                                 'ip_dst_step' : '0.0.0.0',
# #                                'ip_step'    : P1_dict['v4_addr_step'],
#                           }
# 
# #            UCAST_v6_dict = {   'src_hndl'  : IX_TP1['ipv6_handle'],
# #                                'dst_hndl'  : IX_TP2['ipv6_handle'],
# #                                'circuit'   : 'ipv6',
# #                                'TI_name'   : "UCAST_V6",
# #                                'rate_pps'  : "1000",
# #                                'bi_dir'    : 1
# #                          }
# 
#             UCAST_v4_TI = ixLib.configure_ixia_l3_traffic_item(UCAST_v4_dict)
# #            UCAST_v6_TI = ixLib.configure_ixia_traffic_item(UCAST_v6_dict)
# 
# #            if UCAST_v4_TI == 0 or UCAST_v6_TI == 0:
# #                log.debug("Configuring UCast TI failed")
# #                self.errored("Configuring UCast TI failed", goto=['cleanup'])
#                 
#             if UCAST_v4_TI == 0:
#                 log.debug("Configuring UCast TI failed")
#                 self.errored("Configuring UCast TI failed", goto=['cleanup'])
#             else:
#                 global stream_id
#                 stream_id = UCAST_v4_TI
#             
# 
#         else:
#             self.passed(reason="Skipped TGEN Configurations as per request")
            
    # @aetest.test
    # def CONFIGURE_BCAST_IXIA_TRAFFIC(self, testscript):
    #     """ IXIA_CONFIGURATION subsection: Configure MCAST Traffic Item """
    # 
    #     # Do not perform configurations if skip_tgen_config flag is set
    #     if not testscript.parameters['script_flags']['skip_tgen_config']:
    # 
    #         IX_TP1 = testscript.parameters['IX_TP1']
    #         IX_TP2 = testscript.parameters['IX_TP2']
    #         P1_dict = testscript.parameters['LEAF_2_TGEN_dict']
    #         P2_dict = testscript.parameters['LEAF_3_TGEN_dict']
    #         BCAST_v4_dict = {
    #                             'src_hndl'      : IX_TP1['port_handle'],
    #                             'dst_hndl'      : IX_TP2['port_handle'],
    #                             'TI_name'       : "BCAST_V4",
    #                             'frame_size'    : "70",
    #                             'rate_pps'      : "1000",
    #                             'src_mac'       : P1_dict['mac'],
    #                             'srcmac_step'   : "00:00:00:00:00:01",
    #                             'srcmac_count'  : '1',
    #                             'vlan_id'       : P1_dict['vlan_id'],
    #                             'vlanid_step'   : "1",
    #                             'vlanid_count'  : "1",
    #                             'ip_src_addrs'  : P1_dict['v4_addr'],
    #                             'ip_step'       : "0.0.1.0",
    #                       }
    # 
    #         BCAST_v4_TI = ixLib.configure_ixia_BCAST_traffic_item(BCAST_v4_dict)
    # 
    #         if BCAST_v4_TI == 0:
    #             log.debug("Configuring BCast TI failed")
    #             self.errored("Configuring BCast TI failed", goto=['cleanup'])
    #         
    # 
    #     else:
    #         self.passed(reason="Skipped TGEN Configurations as per request")
    # =============================================================================================================================#
    @aetest.test
    def APPLY_TRAFFIC(self):
        """ IXIA_CONFIGURATION subsection: Verify IXIA Traffic """

        # # Apply IXIA Traffic
        # if ixLib.apply_traffic() == 1:
        #     log.info("Applying IXIA TI Passed")
        # else:
        #     self.errored("Applying IXIA TI failed", goto=['cleanup'])
            
        # =============================================================================================================================#
    #--------------------------------------------------------------------------------#
        # Start traffic from ixia
        log.info("--- Populating the statistics --- \n")
        log.info("---- Running Traffic --- \n")
        log.info("Starting Traffic")

        traffic_run_status  = ixLib.start_traffic()

        if traffic_run_status is not 1:
           log.info("Failed: To start traffic")
           return 0
        else:
            log.info("\nTraffic started successfully\n")

        time.sleep(30)
    
    # Stop Traffic from ixia
        log.info("--- Stopping Traffic ---- \n")
        log.info("Stopping Traffic")
        traffic_run_status = ixLib.stop_traffic()
        
        if traffic_run_status is not 1:
           log.info("Failed: To Stop traffic")
           return 0
        else:
            log.info("\nTraffic Stopped successfully\n")
            time.sleep(10)    
    
    @aetest.test
    def VERIFY_IXIA_TRAFFIC(self, testscript):
        """ IXIA_CONFIGURATION subsection: Verify IXIA Traffic """

        # Do not perform configurations if skip_tgen_config flag is set
        if not testscript.parameters['script_flags']['skip_tgen_config']:

            time.sleep(20)

            if ixLib.verify_traffic(2) == 0:
                log.debug("Traffic Verification failed")
                self.failed("Traffic Verification failed", goto=['cleanup'])
            else:
                log.info("Traffic Verification Passed")
        else:
            self.passed(reason="Skipped TGEN Configurations as per request")
# =============================================================================================================================#
    @aetest.test
    def VPC_Peerlink_Flap(self, testscript):
        """ VXLAN_DISRUPTIVE_VERIFICATION subsection: Verify Restart BGP """

        LEAF_1 = testscript.parameters['LEAF-1']
        LEAF_2 = testscript.parameters['LEAF-2']
        LEAF_3 = testscript.parameters['LEAF-3']
        

        forwardingSysDict = testscript.parameters['forwardingSysDict']
        try:
            for LEAF in [LEAF_1,LEAF_2]:
                LEAF.configure('''
                               interface po ''' + str(testscript.parameters['LEAF_1_dict']['VPC_data']['peer_link_po']) + '''
                               shut
                               ''')
            
            for LEAF in [LEAF_1,LEAF_2]:
                LEAF.configure('''
                               interface po ''' + str(testscript.parameters['LEAF_1_dict']['VPC_data']['peer_link_po']) + '''
                               no shut
                               ''')
            time.sleep(90)
        except Exception as error:
            log.debug("Unable to configure - Encountered Exception " + str(error))
            self.errored('Exception occurred while flapping the peer-link on LEAF-1 and LEAF-2', goto=['cleanup'])
            

    # =============================================================================================================================#
    @aetest.test
    def verify_vpc(self, testscript):
        """ VERIFY_NETWORK subsection: Verify VPC """

        LEAF_1 = testscript.parameters['LEAF-1']
        LEAF_2 = testscript.parameters['LEAF-2']

        VPCStatus = infraVerify.verifyVPCStatus(LEAF_1, LEAF_2)

        if VPCStatus['result']:
            log.info(VPCStatus['log'])
            log.info("PASS : VPC Status for '" + str(LEAF_1) + "' and '" + str(LEAF_2) + "' is Successfully Verified\n\n")
        else:
            log.info(VPCStatus['log'])
            log.info("FAIL : VPC Status for '" + str(LEAF_1) + "' and '" + str(LEAF_2) + "' is Failed\n\n")
            self.failed()
                    
# =============================================================================================================================#
    
            
    @aetest.test
    def VERIFY_IXIA_TRAFFIC_AFTER_vpc_peer_link_flap(self, testscript):
        """ IXIA_CONFIGURATION subsection: Verify IXIA Traffic """

        # Do not perform configurations if skip_tgen_config flag is set
        if not testscript.parameters['script_flags']['skip_tgen_config']:

            time.sleep(20)

            if ixLib.verify_traffic(15) == 0:
                log.debug("Traffic Verification failed")
                self.failed("Traffic Verification failed", goto=['cleanup'])
            else:
                log.info("Traffic Verification Passed")
            
        else:
            self.passed(reason="Skipped TGEN Configurations as per request")
     # =============================================================================================================================#        
    @aetest.test
    def Clear_ARP_Table_on_Vxlan_BLs(self, testscript):
        """Shut down the vpc leg on Leaf2 to force all traffic to Leaf1"""
        
        LEAF_1 = testscript.parameters['LEAF-1']
        LEAF_2 = testscript.parameters['LEAF-2']
        
        try:
            for i in range(1, testscript.parameters['forwardingSysDict']['VRF_count']+1):
                testscript.parameters['LEAF-2'].execute('''
                      clear ip arp vrf ''' + str(testscript.parameters['forwardingSysDict']['VRF_string']) + str(i) + ''' force-delete''')
            
            for i in range(1, testscript.parameters['forwardingSysDict']['VRF_count']+1):
                testscript.parameters['LEAF-1'].execute('''
                      clear ip arp vrf ''' + str(testscript.parameters['forwardingSysDict']['VRF_string']) + str(i) + ''' force-delete''')    
            
            
        except Exception as error:
            log.debug("Unable to configure - Encountered Exception " + str(error))
            self.errored('Exception occurred while clearing arp cache on LEAF-1 and LEAF-2', goto=['cleanup'])
            
    @aetest.test        
    def Host_move_FO(self,testscript):
        
        
        FO_1=testscript.parameters['FO_1']

        
        try:
            FO_1.configure('''
            interface ''' + str(testscript.parameters['intf_FO_1_to_N7k_LEAF_3']) + '''
            shut
            switchport
            switchport mode trunk
            
            interface ''' + str(testscript.parameters['intf_FO_1_to_LEAF_3']) + '''
            no shut
            switchport
            switchport mode trunk
            
            ''')
            time.sleep(45)
            #ForkedPdb().set_trace()
        except Exception as error:
                log.debug("Unable to configure - Encountered Exception " + str(error))
                self.errored('Exception occurred while configuring on FO_1', goto=['common_cleanup'])
                
    @aetest.test
    def VERIFY_IXIA_TRAFFIC_AFTER_MOVE(self, testscript):
        """ IXIA_CONFIGURATION subsection: Verify IXIA Traffic """

        # Do not perform configurations if skip_tgen_config flag is set
        if not testscript.parameters['script_flags']['skip_tgen_config']:

            time.sleep(20)

            if ixLib.verify_traffic(15) == 0:
                log.debug("Traffic Verification failed")
                self.failed("Traffic Verification failed", goto=['cleanup'])
            else:
                log.info("Traffic Verification Passed")
            
        else:
            self.passed(reason="Skipped TGEN Configurations as per request")

            
    @aetest.test        
    def Host_move_FO_BACK(self,testscript):
        
        
        FO_1=testscript.parameters['FO_1']

        
        try:
            FO_1.configure('''
            interface ''' + str(testscript.parameters['intf_FO_1_to_LEAF_3']) + '''
            shut
            switchport
            switchport mode trunk
            
            interface ''' + str(testscript.parameters['intf_FO_1_to_N7k_LEAF_3']) + '''
            no shut
            switchport
            switchport mode trunk
            
            
            
            ''')
            time.sleep(45)
        except Exception as error:
                log.debug("Unable to configure - Encountered Exception " + str(error))
                self.errored('Exception occurred while configuring on FO_1', goto=['common_cleanup'])
                
    @aetest.test
    def VERIFY_IXIA_TRAFFIC_HOST_MOVE_BACK(self, testscript):
        """ IXIA_CONFIGURATION subsection: Verify IXIA Traffic """

        # Do not perform configurations if skip_tgen_config flag is set
        if not testscript.parameters['script_flags']['skip_tgen_config']:

            time.sleep(20)

            if ixLib.verify_traffic(15) == 0:
                log.debug("Traffic Verification failed")
                self.failed("Traffic Verification failed", goto=['cleanup'])
            else:
                log.info("Traffic Verification Passed")
        else:
            self.passed(reason="Skipped TGEN Configurations as per request")
        
    @aetest.cleanup
    def cleanup(self,testscript):
        """Unconfigure qos policies"""
        LEAF_1 = testscript.parameters['LEAF-1']
        LEAF_2 = testscript.parameters['LEAF-2']
        LEAF_3 = testscript.parameters['LEAF-3']
        FO_1=testscript.parameters['FO_1']
        LEAF_1 = testscript.parameters['LEAF-1']
        LEAF_2 = testscript.parameters['LEAF-2']
        forwardingSysDict = testscript.parameters['forwardingSysDict']
        l2_vlan_id = testscript.parameters['N7K_LEAF_1_dict']['Vlan_data']['l2_vlan_start']
        l2_vlan_ipv4_start= testscript.parameters['N7K_LEAF_1_dict']['Vlan_data']['l2_vlan_ipv4_start']
        l2_vlan_ipv4_mask= testscript.parameters['N7K_LEAF_1_dict']['Vlan_data']['l2_vlan_ipv4_mask']
        l2_vlan_ipv6_start= testscript.parameters['N7K_LEAF_1_dict']['Vlan_data']['l2_vlan_ipv6_start']
        l2_vlan_ipv6_mask= testscript.parameters['N7K_LEAF_1_dict']['Vlan_data']['l2_vlan_ipv6_mask']
        l2_hsrp_ipv4_vip_start= testscript.parameters['N7K_LEAF_1_dict']['Vlan_data']['hsrp_ipv4_vip_start']
        l2_hsrp_ipv6_vip_start= testscript.parameters['N7K_LEAF_1_dict']['Vlan_data']['hsrp_ipv6_vip_start']
        total_ip_count = int(forwardingSysDict['VLAN_PER_VRF_count']) * int(forwardingSysDict['VRF_count'])
        l2_vlan_ipv4_sec_start= testscript.parameters['LEAF_2_dict']['VNI_data']['l2_vlan_ipv4_sec_start']
        l2_vlan_ipv4_mask= testscript.parameters['LEAF_2_dict']['VNI_data']['l2_vlan_ipv4_mask']
        l2_ipv4s = increment_prefix_network(ip.IPv4Interface(str(l2_vlan_ipv4_sec_start) + str(l2_vlan_ipv4_mask)),total_ip_count)
        post_test_process_dict = {
            'dut_list'                       : [LEAF_1, LEAF_2, LEAF_3],
            'cc_check'                  : 1,
            'cores_check'               : 1,
            'logs_check'                : 0,
            'fnl_flag'                  : 0,
            'exclude_log_check_pattern' : 'ERROR_VLANS_SUSPENDED|ERROR_VLANS_REMOVED',
            }
        try:
            for LEAF in [LEAF_1,LEAF_2]:
                LEAF.configure('''
                               interface po ''' + str(testscript.parameters['LEAF_1_dict']['VPC_data']['peer_link_po']) + '''
                               no shut
                               ''')
            # UCAST_v4_dict = {
            #                 'mode'        : 'remove',
            #                 'stream_id'   : stream_id,
            #           }
            # if (ixLib.delete_traffic_item(UCAST_v4_dict))==0:
            #     log.debug("Traffic Remove failed")
            #     self.failed("Traffic Remove failed")
            # else:
            #     log.info("Traffic Deletion Passed")
            
            ##Move host back to FP
            FO_1.configure('''
            interface ''' + str(testscript.parameters['intf_FO_1_to_LEAF_3']) + '''
            shut
            switchport
            switchport mode trunk
            
            interface ''' + str(testscript.parameters['intf_FO_1_to_N7k_LEAF_3']) + '''
            no shut
            switchport
            switchport mode trunk
            ''')
            time.sleep(30)
            ###Remove Pre-migration step from both N7k leafs
            device_handle=connect_to_vdc(testscript.parameters['xbow1'], 'leaf1')
            if device_handle==False:
                log.info("failed to switchto correct vdc")
                self.failed("failed to switchto correct vdc",goto=['common_cleanup'])
            else:
                total_ip_count = int(forwardingSysDict['VLAN_PER_VRF_count']) * int(forwardingSysDict['VRF_count'])
                l2_ipv4s = increment_prefix_network(ip.IPv4Interface(str(l2_vlan_ipv4_start) + str(l2_vlan_ipv4_mask)),total_ip_count)
                l2_ipv6s = increment_prefix_network(ip.IPv6Interface(str(l2_vlan_ipv6_start) + str(l2_vlan_ipv6_mask)),total_ip_count)
                ip_index=0
                for i in range(0,len(l2_ipv4s)):
                    device_handle.configure('''int vlan ''' + str(l2_vlan_id) + '''\n
                                     hsrp version 2
                                     hsrp ''' + str(l2_vlan_id) + ''' ipv4
                                     no mac-address 0000.000a.aaaa
                                     ''')
                    l2_vlan_id += 1
            l2_vlan_id = testscript.parameters['N7K_LEAF_1_dict']['Vlan_data']['l2_vlan_start']        
            device_handle=connect_to_vdc(testscript.parameters['xbow2'], 'leaf2')
            if device_handle==False:
                log.info("failed to switchto correct vdc")
                self.failed("failed to switchto correct vdc",goto=['common_cleanup'])
            else:
                total_ip_count = int(forwardingSysDict['VLAN_PER_VRF_count']) * int(forwardingSysDict['VRF_count'])
                l2_ipv4s = increment_prefix_network(ip.IPv4Interface(str(l2_vlan_ipv4_start) + str(l2_vlan_ipv4_mask)),total_ip_count)
                l2_ipv6s = increment_prefix_network(ip.IPv6Interface(str(l2_vlan_ipv6_start) + str(l2_vlan_ipv6_mask)),total_ip_count)
                ip_index=0
                for i in range(0,len(l2_ipv4s)):
                    device_handle.configure('''int vlan ''' + str(l2_vlan_id) + '''\n
                                     hsrp version 2
                                     hsrp ''' + str(l2_vlan_id) + ''' ipv4
                                     no mac-address 0000.000a.aaaa
                                     ''')
                    l2_vlan_id += 1
            status = infraVerify.postTestVerification(post_test_process_dict)
            if status['status'] == 0:
                self.failed(reason=status['logs'])
            else:
                self.passed(reason=status['logs'])
        except Exception as error:
            log.debug("Unable to unconfigure class map or policy map-Encountered exception " + str(error))
            self.errored('Exception occurred while unconfiguring qos on LEAF1', goto=['next_tc'])
            
# *****************************************************************************************************************************#
class VPC_member_Flap_pre_Host_move_ipv4(aetest.Testcase):
    """ Host_move_ipv4 """

    
    # =============================================================================================================================#        
    
    @aetest.test
    def SVI_ON_LEAF2(self, testscript):
        """Shut down the vpc leg on Leaf2 to force all traffic to Leaf1"""
        
        LEAF_1 = testscript.parameters['LEAF-1']
        LEAF_2 = testscript.parameters['LEAF-2']
        forwardingSysDict = testscript.parameters['forwardingSysDict']
        l2_vlan_id = testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vlan_start']
        l2_vlan_ipv4_sec_start= testscript.parameters['LEAF_2_dict']['VNI_data']['l2_vlan_ipv4_sec_start']
        l2_vlan_ipv4_mask= testscript.parameters['LEAF_2_dict']['VNI_data']['l2_vlan_ipv4_mask']
        #+ str(testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vlan_ipv4_mask'])
        
        try:
            total_ip_count = int(forwardingSysDict['VLAN_PER_VRF_count']) * int(forwardingSysDict['VRF_count'])
            l2_ipv4s = increment_prefix_network(ip.IPv4Interface(str(l2_vlan_ipv4_sec_start) + str(l2_vlan_ipv4_mask)),total_ip_count)
            ip_index=0
            for i in range(0,len(l2_ipv4s)):
                LEAF_2.configure('''int vlan ''' + str(l2_vlan_id) + '''\n
                                 ip address ''' + str(l2_ipv4s[ip_index]) + ''' secondary use-bia
                                 no shut
                                 ''')
                l2_vlan_id += 1
                ip_index += 1
            
            
        except Exception as error:
            log.debug("Unable to configure - Encountered Exception " + str(error))
            self.errored('Exception occurred while configuring secondary ipv4 address on LEAF-2', goto=['cleanup'])
            
    # =============================================================================================================================#        
    
    @aetest.test
    def SVI_ON_LEAF1(self, testscript):
        """Shut down the vpc leg on Leaf2 to force all traffic to Leaf1"""
        
        LEAF_1 = testscript.parameters['LEAF-1']
        LEAF_2 = testscript.parameters['LEAF-2']
        forwardingSysDict = testscript.parameters['forwardingSysDict']
        l2_vlan_id = testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vlan_start']
        l2_vlan_ipv4_sec_start= testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vlan_ipv4_sec_start']
        l2_vlan_ipv4_mask= testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vlan_ipv4_mask']
        
        try:
            total_ip_count = int(forwardingSysDict['VLAN_PER_VRF_count']) * int(forwardingSysDict['VRF_count'])
            l2_ipv4s = increment_prefix_network(ip.IPv4Interface(str(l2_vlan_ipv4_sec_start) + str(l2_vlan_ipv4_mask)),total_ip_count)
            ip_index=0
            for i in range(0,len(l2_ipv4s)):
                LEAF_1.configure('''int vlan ''' + str(l2_vlan_id) + '''\n
                                 ip address ''' + str(l2_ipv4s[ip_index]) + ''' secondary use-bia
                                 no shut
                                 ''')
                l2_vlan_id += 1
                ip_index += 1
                
            
            
        except Exception as error:
            log.debug("Unable to configure - Encountered Exception " + str(error))
            self.errored('Exception occurred while configuring secondary ipv4 address on LEAF-1', goto=['cleanup'])
            
     # =============================================================================================================================#        
    @aetest.test
    def Add_external_int(self, testscript):
        """Shut down the vpc leg on Leaf2 to force all traffic to Leaf1"""
        
        LEAF_1 = testscript.parameters['LEAF-1']
        LEAF_2 = testscript.parameters['LEAF-2']
        
        try:
            testscript.parameters['LEAF-2'].configure('''
                  interface po ''' + str(testscript.parameters['LEAF_1_dict']['VPC_data']['double_vpc_po_1']) + '''
                  port-type external
                  ''')
            
            testscript.parameters['LEAF-1'].configure('''
                  interface po ''' + str(testscript.parameters['LEAF_1_dict']['VPC_data']['double_vpc_po_1']) + '''
                  port-type external
                  ''')    
            
            
        except Exception as error:
            log.debug("Unable to configure - Encountered Exception " + str(error))
            self.errored('Exception occurred while configuring external on LEAF-1 and LEAF-2', goto=['cleanup'])
            
     # =============================================================================================================================#    
    @aetest.test
    def Pre_migration_hsrp(self,testscript):
        LEAF_1 = testscript.parameters['LEAF-1']
        LEAF_2 = testscript.parameters['LEAF-2']
        forwardingSysDict = testscript.parameters['forwardingSysDict']
        l2_vlan_id = testscript.parameters['N7K_LEAF_1_dict']['Vlan_data']['l2_vlan_start']
        l2_vlan_ipv4_start= testscript.parameters['N7K_LEAF_1_dict']['Vlan_data']['l2_vlan_ipv4_start']
        l2_vlan_ipv4_mask= testscript.parameters['N7K_LEAF_1_dict']['Vlan_data']['l2_vlan_ipv4_mask']
        l2_vlan_ipv6_start= testscript.parameters['N7K_LEAF_1_dict']['Vlan_data']['l2_vlan_ipv6_start']
        l2_vlan_ipv6_mask= testscript.parameters['N7K_LEAF_1_dict']['Vlan_data']['l2_vlan_ipv6_mask']
        l2_hsrp_ipv4_vip_start= testscript.parameters['N7K_LEAF_1_dict']['Vlan_data']['hsrp_ipv4_vip_start']
        l2_hsrp_ipv6_vip_start= testscript.parameters['N7K_LEAF_1_dict']['Vlan_data']['hsrp_ipv6_vip_start']
        
        try:
            device_handle=connect_to_vdc(testscript.parameters['xbow1'], 'leaf1')
            if device_handle==False:
                log.info("failed to switchto correct vdc")
                self.failed("failed to switchto correct vdc",goto=['common_cleanup'])
            else:
                total_ip_count = int(forwardingSysDict['VLAN_PER_VRF_count']) * int(forwardingSysDict['VRF_count'])
                l2_ipv4s = increment_prefix_network(ip.IPv4Interface(str(l2_vlan_ipv4_start) + str(l2_vlan_ipv4_mask)),total_ip_count)
                l2_ipv6s = increment_prefix_network(ip.IPv6Interface(str(l2_vlan_ipv6_start) + str(l2_vlan_ipv6_mask)),total_ip_count)
                ip_index=0
                for i in range(0,len(l2_ipv4s)):
                    device_handle.configure('''int vlan ''' + str(l2_vlan_id) + '''\n
                                     hsrp version 2
                                     hsrp ''' + str(l2_vlan_id) + ''' ipv4
                                     mac-address 0000.000a.aaaa
                                     ''')
                    l2_vlan_id += 1
            l2_vlan_id = testscript.parameters['N7K_LEAF_1_dict']['Vlan_data']['l2_vlan_start']        
            device_handle=connect_to_vdc(testscript.parameters['xbow2'], 'leaf2')
            if device_handle==False:
                log.info("failed to switchto correct vdc")
                self.failed("failed to switchto correct vdc",goto=['common_cleanup'])
            else:
                total_ip_count = int(forwardingSysDict['VLAN_PER_VRF_count']) * int(forwardingSysDict['VRF_count'])
                l2_ipv4s = increment_prefix_network(ip.IPv4Interface(str(l2_vlan_ipv4_start) + str(l2_vlan_ipv4_mask)),total_ip_count)
                l2_ipv6s = increment_prefix_network(ip.IPv6Interface(str(l2_vlan_ipv6_start) + str(l2_vlan_ipv6_mask)),total_ip_count)
                ip_index=0
                for i in range(0,len(l2_ipv4s)):
                    device_handle.configure('''int vlan ''' + str(l2_vlan_id) + '''\n
                                     hsrp version 2
                                     hsrp ''' + str(l2_vlan_id) + ''' ipv4
                                     mac-address 0000.000a.aaaa
                                     ''')
                    l2_vlan_id += 1
                    


        except Exception as error:
                log.debug("Unable to configure - Encountered Exception " + str(error))
                self.errored('Exception occurred while configuring on N7k leaf1', goto=['common_cleanup'])
                
    @aetest.test        
    def configure_FO(self,testscript):
        
        FO_1_vlanConfiguration = ""
        FO_1=testscript.parameters['FO_1']

        l3_vrf_count_iter = 0
        l2_vlan_id = testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vlan_start']
        l3_vlan_id = testscript.parameters['LEAF_1_dict']['VNI_data']['l3_vlan_start']

        while l3_vrf_count_iter < testscript.parameters['forwardingSysDict']['VRF_count']:
            l2_vlan_count_iter = 0
            FO_1_vlanConfiguration += '''vlan ''' + str(l3_vlan_id) + '''\n
                                            state active\n
                                            no shut\n'''
            while l2_vlan_count_iter < testscript.parameters['forwardingSysDict']['VLAN_PER_VRF_count']:
                # Incrementing L2 VLAN Iteration counters
                FO_1_vlanConfiguration += '''vlan ''' + str(l2_vlan_id) + '''\n
                                                state active\n
                                                no shut\n'''
                l2_vlan_count_iter += 1
                l2_vlan_id += 1
            # Incrementing L3 VRF Iteration counters
            l3_vrf_count_iter += 1
            l3_vlan_id += 1

        try:
            FO_1.configure(
                str(FO_1_vlanConfiguration) + '''
        
        
            
            interface ''' + str(testscript.parameters['intf_FO_1_to_N7k_LEAF_3']) + '''
            no shut
            switchport
            switchport mode trunk
            
            interface ''' + str(testscript.parameters['intf_FO_1_to_LEAF_3']) + '''
            shut
            switchport
            switchport mode trunk
            
            interface ''' + str(testscript.parameters['intf_FO_1_to_IXIA']) + '''
            no shut
            switchport
            switchport mode trunk
            
            ''')
        except Exception as error:
                log.debug("Unable to configure - Encountered Exception " + str(error))
                self.errored('Exception occurred while configuring on FO_1', goto=['common_cleanup'])
   
#     @aetest.test
#     def CONFIGURE_UCAST_L3_IXIA_TRAFFIC(self, testscript):
#         """ IXIA_CONFIGURATION subsection: Configure MCAST Traffic Item """
# 
#         # Do not perform configurations if skip_tgen_config flag is set
#         if not testscript.parameters['script_flags']['skip_tgen_config']:
# 
#             IX_TP1 = testscript.parameters['IX_TP1']
#             IX_TP2 = testscript.parameters['IX_TP2']
#             P1_dict = testscript.parameters['LEAF_2_TGEN_dict']
#             P2_dict = testscript.parameters['LEAF_3_TGEN_dict']
# 
#             UCAST_v4_dict = {   'src_hndl'  : IX_TP1['port_handle'],
#                                 'dst_hndl'  : IX_TP2['port_handle'],
#                                 'ip_dscp'   : P1_dict['ip_dscp'],
#                                 'circuit'   : 'raw',
#                                 'TI_name'   : "UCAST_L3",
#                                 'rate_pps'  : "9000",
#                                 'bi_dir'    : 1,
#                                 'frame_size': '128',
#                                 'src_mac'   : P1_dict['mac'],
#                                 'dst_mac'   : '0000.000a.aaaa',
#                                 'srcmac_step': '00:00:00:00:00:00',
#                                 'dstmac_step': '00:00:00:00:00:00',
#                                 'srcmac_count': '1',
#                                 'dstmac_count': '1',
#                                 'vlan_id'    : P1_dict['vlan_id'],
#                                 'vlanid_step': '0',
#                                 'vlanid_count': '1',
#                                 'vlan_user_priority': P1_dict['vlan_user_priority'],
#                                 'ip_src_addrs' : P1_dict['v4_addr'],
#                                 'ip_dst_addrs' : P1_dict['L3_dst_addr'],
#                                 'ip_src_step' : '0.0.0.0',
#                                 'ip_dst_step' : '0.0.0.0',
# #                                'ip_step'    : P1_dict['v4_addr_step'],
#                           }
# 
# #            UCAST_v6_dict = {   'src_hndl'  : IX_TP1['ipv6_handle'],
# #                                'dst_hndl'  : IX_TP2['ipv6_handle'],
# #                                'circuit'   : 'ipv6',
# #                                'TI_name'   : "UCAST_V6",
# #                                'rate_pps'  : "1000",
# #                                'bi_dir'    : 1
# #                          }
# 
#             UCAST_v4_TI = ixLib.configure_ixia_l3_traffic_item(UCAST_v4_dict)
# #            UCAST_v6_TI = ixLib.configure_ixia_traffic_item(UCAST_v6_dict)
# 
# #            if UCAST_v4_TI == 0 or UCAST_v6_TI == 0:
# #                log.debug("Configuring UCast TI failed")
# #                self.errored("Configuring UCast TI failed", goto=['cleanup'])
#                 
#             if UCAST_v4_TI == 0:
#                 log.debug("Configuring UCast TI failed")
#                 self.errored("Configuring UCast TI failed", goto=['cleanup'])
#             else:
#                 global stream_id
#                 stream_id = UCAST_v4_TI
#             
# 
#         else:
#             self.passed(reason="Skipped TGEN Configurations as per request")
            
    # @aetest.test
    # def CONFIGURE_BCAST_IXIA_TRAFFIC(self, testscript):
    #     """ IXIA_CONFIGURATION subsection: Configure MCAST Traffic Item """
    # 
    #     # Do not perform configurations if skip_tgen_config flag is set
    #     if not testscript.parameters['script_flags']['skip_tgen_config']:
    # 
    #         IX_TP1 = testscript.parameters['IX_TP1']
    #         IX_TP2 = testscript.parameters['IX_TP2']
    #         P1_dict = testscript.parameters['LEAF_2_TGEN_dict']
    #         P2_dict = testscript.parameters['LEAF_3_TGEN_dict']
    #         BCAST_v4_dict = {
    #                             'src_hndl'      : IX_TP1['port_handle'],
    #                             'dst_hndl'      : IX_TP2['port_handle'],
    #                             'TI_name'       : "BCAST_V4",
    #                             'frame_size'    : "70",
    #                             'rate_pps'      : "1000",
    #                             'src_mac'       : P1_dict['mac'],
    #                             'srcmac_step'   : "00:00:00:00:00:01",
    #                             'srcmac_count'  : '1',
    #                             'vlan_id'       : P1_dict['vlan_id'],
    #                             'vlanid_step'   : "1",
    #                             'vlanid_count'  : "1",
    #                             'ip_src_addrs'  : P1_dict['v4_addr'],
    #                             'ip_step'       : "0.0.1.0",
    #                       }
    # 
    #         BCAST_v4_TI = ixLib.configure_ixia_BCAST_traffic_item(BCAST_v4_dict)
    # 
    #         if BCAST_v4_TI == 0:
    #             log.debug("Configuring BCast TI failed")
    #             self.errored("Configuring BCast TI failed", goto=['cleanup'])
    #         
    # 
    #     else:
    #         self.passed(reason="Skipped TGEN Configurations as per request")
    # =============================================================================================================================#
    @aetest.test
    def APPLY_TRAFFIC(self):
        """ IXIA_CONFIGURATION subsection: Verify IXIA Traffic """

        # # Apply IXIA Traffic
        # if ixLib.apply_traffic() == 1:
        #     log.info("Applying IXIA TI Passed")
        # else:
        #     self.errored("Applying IXIA TI failed", goto=['cleanup'])
            
        # =============================================================================================================================#
    #--------------------------------------------------------------------------------#
        # Start traffic from ixia
        log.info("--- Populating the statistics --- \n")
        log.info("---- Running Traffic --- \n")
        log.info("Starting Traffic")

        traffic_run_status  = ixLib.start_traffic()

        if traffic_run_status is not 1:
           log.info("Failed: To start traffic")
           return 0
        else:
            log.info("\nTraffic started successfully\n")

        time.sleep(30)
    
    # Stop Traffic from ixia
        log.info("--- Stopping Traffic ---- \n")
        log.info("Stopping Traffic")
        traffic_run_status = ixLib.stop_traffic()
        
        if traffic_run_status is not 1:
           log.info("Failed: To Stop traffic")
           return 0
        else:
            log.info("\nTraffic Stopped successfully\n")
            time.sleep(10)    
    
    @aetest.test
    def VERIFY_IXIA_TRAFFIC(self, testscript):
        """ IXIA_CONFIGURATION subsection: Verify IXIA Traffic """

        # Do not perform configurations if skip_tgen_config flag is set
        if not testscript.parameters['script_flags']['skip_tgen_config']:

            time.sleep(20)

            if ixLib.verify_traffic(2) == 0:
                log.debug("Traffic Verification failed")
                self.failed("Traffic Verification failed", goto=['cleanup'])
            else:
                log.info("Traffic Verification Passed")
        else:
            self.passed(reason="Skipped TGEN Configurations as per request")
# =============================================================================================================================#
    @aetest.test
    def VPC_Member_Flap(self, testscript):
        """ VXLAN_DISRUPTIVE_VERIFICATION subsection: Verify Restart BGP """

        LEAF_1 = testscript.parameters['LEAF-1']
        LEAF_2 = testscript.parameters['LEAF-2']
        LEAF_3 = testscript.parameters['LEAF-3']
        

        forwardingSysDict = testscript.parameters['forwardingSysDict']
        try:
            
            LEAF_1.configure('''
                           interface ''' + str(testscript.parameters['intf_LEAF_1_to_N7k_LEAF_2_1']) + '''
                           shut
                           ''')
            LEAF_1.configure('''
                           interface ''' + str(testscript.parameters['intf_LEAF_1_to_N7k_LEAF_2_1']) + '''
                           no shut
                           ''')
            
            time.sleep(60)
        except Exception as error:
            log.debug("Unable to configure - Encountered Exception " + str(error))
            self.errored('Exception occurred while flapping the vpc member on LEAF-1', goto=['cleanup'])
            

    # =============================================================================================================================#
    @aetest.test
    def verify_vpc(self, testscript):
        """ VERIFY_NETWORK subsection: Verify VPC """

        LEAF_1 = testscript.parameters['LEAF-1']
        LEAF_2 = testscript.parameters['LEAF-2']

        VPCStatus = infraVerify.verifyVPCStatus(LEAF_1, LEAF_2)

        if VPCStatus['result']:
            log.info(VPCStatus['log'])
            log.info("PASS : VPC Status for '" + str(LEAF_1) + "' and '" + str(LEAF_2) + "' is Successfully Verified\n\n")
        else:
            log.info(VPCStatus['log'])
            log.info("FAIL : VPC Status for '" + str(LEAF_1) + "' and '" + str(LEAF_2) + "' is Failed\n\n")
            self.failed()
                    
# =============================================================================================================================#
    
            
    @aetest.test
    def VERIFY_IXIA_TRAFFIC_AFTER_vpc_member_flap(self, testscript):
        """ IXIA_CONFIGURATION subsection: Verify IXIA Traffic """

        # Do not perform configurations if skip_tgen_config flag is set
        if not testscript.parameters['script_flags']['skip_tgen_config']:

            time.sleep(20)

            if ixLib.verify_traffic(15) == 0:
                log.debug("Traffic Verification failed")
                self.failed("Traffic Verification failed", goto=['cleanup'])
            else:
                log.info("Traffic Verification Passed")
            
        else:
            self.passed(reason="Skipped TGEN Configurations as per request")
     # =============================================================================================================================#        
    @aetest.test
    def Clear_ARP_Table_on_Vxlan_BLs(self, testscript):
        """Shut down the vpc leg on Leaf2 to force all traffic to Leaf1"""
        
        LEAF_1 = testscript.parameters['LEAF-1']
        LEAF_2 = testscript.parameters['LEAF-2']
        
        try:
            for i in range(1, testscript.parameters['forwardingSysDict']['VRF_count']+1):
                testscript.parameters['LEAF-2'].execute('''
                      clear ip arp vrf ''' + str(testscript.parameters['forwardingSysDict']['VRF_string']) + str(i) + ''' force-delete''')
            
            for i in range(1, testscript.parameters['forwardingSysDict']['VRF_count']+1):
                testscript.parameters['LEAF-1'].execute('''
                      clear ip arp vrf ''' + str(testscript.parameters['forwardingSysDict']['VRF_string']) + str(i) + ''' force-delete''')    
            
            
        except Exception as error:
            log.debug("Unable to configure - Encountered Exception " + str(error))
            self.errored('Exception occurred while clearing arp cache on LEAF-1 and LEAF-2', goto=['cleanup'])
            
    @aetest.test        
    def Host_move_FO(self,testscript):
        
        
        FO_1=testscript.parameters['FO_1']

        
        try:
            FO_1.configure('''
            interface ''' + str(testscript.parameters['intf_FO_1_to_N7k_LEAF_3']) + '''
            shut
            switchport
            switchport mode trunk
            
            interface ''' + str(testscript.parameters['intf_FO_1_to_LEAF_3']) + '''
            no shut
            switchport
            switchport mode trunk
            
            ''')
            time.sleep(45)
            #ForkedPdb().set_trace()
        except Exception as error:
                log.debug("Unable to configure - Encountered Exception " + str(error))
                self.errored('Exception occurred while configuring on FO_1', goto=['common_cleanup'])
                
    @aetest.test
    def VERIFY_IXIA_TRAFFIC_AFTER_MOVE(self, testscript):
        """ IXIA_CONFIGURATION subsection: Verify IXIA Traffic """

        # Do not perform configurations if skip_tgen_config flag is set
        if not testscript.parameters['script_flags']['skip_tgen_config']:

            time.sleep(20)

            if ixLib.verify_traffic(15) == 0:
                log.debug("Traffic Verification failed")
                self.failed("Traffic Verification failed", goto=['cleanup'])
            else:
                log.info("Traffic Verification Passed")
            
        else:
            self.passed(reason="Skipped TGEN Configurations as per request")

            
    @aetest.test        
    def Host_move_FO_BACK(self,testscript):
        
        
        FO_1=testscript.parameters['FO_1']

        
        try:
            FO_1.configure('''
            interface ''' + str(testscript.parameters['intf_FO_1_to_LEAF_3']) + '''
            shut
            switchport
            switchport mode trunk
            
            interface ''' + str(testscript.parameters['intf_FO_1_to_N7k_LEAF_3']) + '''
            no shut
            switchport
            switchport mode trunk
            
            
            
            ''')
            time.sleep(45)
        except Exception as error:
                log.debug("Unable to configure - Encountered Exception " + str(error))
                self.errored('Exception occurred while configuring on FO_1', goto=['common_cleanup'])
                
    @aetest.test
    def VERIFY_IXIA_TRAFFIC_HOST_MOVE_BACK(self, testscript):
        """ IXIA_CONFIGURATION subsection: Verify IXIA Traffic """

        # Do not perform configurations if skip_tgen_config flag is set
        if not testscript.parameters['script_flags']['skip_tgen_config']:

            time.sleep(20)

            if ixLib.verify_traffic(15) == 0:
                log.debug("Traffic Verification failed")
                self.failed("Traffic Verification failed", goto=['cleanup'])
            else:
                log.info("Traffic Verification Passed")
        else:
            self.passed(reason="Skipped TGEN Configurations as per request")
        
    @aetest.cleanup
    def cleanup(self,testscript):
        """Unconfigure qos policies"""
        LEAF_1 = testscript.parameters['LEAF-1']
        LEAF_2 = testscript.parameters['LEAF-2']
        LEAF_3 = testscript.parameters['LEAF-3']
        FO_1=testscript.parameters['FO_1']
        LEAF_1 = testscript.parameters['LEAF-1']
        LEAF_2 = testscript.parameters['LEAF-2']
        forwardingSysDict = testscript.parameters['forwardingSysDict']
        l2_vlan_id = testscript.parameters['N7K_LEAF_1_dict']['Vlan_data']['l2_vlan_start']
        l2_vlan_ipv4_start= testscript.parameters['N7K_LEAF_1_dict']['Vlan_data']['l2_vlan_ipv4_start']
        l2_vlan_ipv4_mask= testscript.parameters['N7K_LEAF_1_dict']['Vlan_data']['l2_vlan_ipv4_mask']
        l2_vlan_ipv6_start= testscript.parameters['N7K_LEAF_1_dict']['Vlan_data']['l2_vlan_ipv6_start']
        l2_vlan_ipv6_mask= testscript.parameters['N7K_LEAF_1_dict']['Vlan_data']['l2_vlan_ipv6_mask']
        l2_hsrp_ipv4_vip_start= testscript.parameters['N7K_LEAF_1_dict']['Vlan_data']['hsrp_ipv4_vip_start']
        l2_hsrp_ipv6_vip_start= testscript.parameters['N7K_LEAF_1_dict']['Vlan_data']['hsrp_ipv6_vip_start']
        total_ip_count = int(forwardingSysDict['VLAN_PER_VRF_count']) * int(forwardingSysDict['VRF_count'])
        l2_vlan_ipv4_sec_start= testscript.parameters['LEAF_2_dict']['VNI_data']['l2_vlan_ipv4_sec_start']
        l2_vlan_ipv4_mask= testscript.parameters['LEAF_2_dict']['VNI_data']['l2_vlan_ipv4_mask']
        l2_ipv4s = increment_prefix_network(ip.IPv4Interface(str(l2_vlan_ipv4_sec_start) + str(l2_vlan_ipv4_mask)),total_ip_count)
        post_test_process_dict = {
            'dut_list'                       : [LEAF_1, LEAF_2, LEAF_3],
            'cc_check'                  : 1,
            'cores_check'               : 1,
            'logs_check'                : 0,
            'fnl_flag'                  : 0,
            'exclude_log_check_pattern' : 'ERROR_VLANS_SUSPENDED|ERROR_VLANS_REMOVED',
            }
        try:
            LEAF_1.configure('''
                           interface ''' + str(testscript.parameters['intf_LEAF_1_to_N7k_LEAF_2_1']) + '''
                           no shut
                           ''')
            # UCAST_v4_dict = {
            #                 'mode'        : 'remove',
            #                 'stream_id'   : stream_id,
            #           }
            # if (ixLib.delete_traffic_item(UCAST_v4_dict))==0:
            #     log.debug("Traffic Remove failed")
            #     self.failed("Traffic Remove failed")
            # else:
            #     log.info("Traffic Deletion Passed")
            
            ##Move host back to FP
            FO_1.configure('''
            interface ''' + str(testscript.parameters['intf_FO_1_to_LEAF_3']) + '''
            shut
            switchport
            switchport mode trunk
            
            interface ''' + str(testscript.parameters['intf_FO_1_to_N7k_LEAF_3']) + '''
            no shut
            switchport
            switchport mode trunk
            ''')
            time.sleep(30)
            ###Remove Pre-migration step from both N7k leafs
            device_handle=connect_to_vdc(testscript.parameters['xbow1'], 'leaf1')
            if device_handle==False:
                log.info("failed to switchto correct vdc")
                self.failed("failed to switchto correct vdc",goto=['common_cleanup'])
            else:
                total_ip_count = int(forwardingSysDict['VLAN_PER_VRF_count']) * int(forwardingSysDict['VRF_count'])
                l2_ipv4s = increment_prefix_network(ip.IPv4Interface(str(l2_vlan_ipv4_start) + str(l2_vlan_ipv4_mask)),total_ip_count)
                l2_ipv6s = increment_prefix_network(ip.IPv6Interface(str(l2_vlan_ipv6_start) + str(l2_vlan_ipv6_mask)),total_ip_count)
                ip_index=0
                for i in range(0,len(l2_ipv4s)):
                    device_handle.configure('''int vlan ''' + str(l2_vlan_id) + '''\n
                                     hsrp version 2
                                     hsrp ''' + str(l2_vlan_id) + ''' ipv4
                                     no mac-address 0000.000a.aaaa
                                     ''')
                    l2_vlan_id += 1
            l2_vlan_id = testscript.parameters['N7K_LEAF_1_dict']['Vlan_data']['l2_vlan_start']        
            device_handle=connect_to_vdc(testscript.parameters['xbow2'], 'leaf2')
            if device_handle==False:
                log.info("failed to switchto correct vdc")
                self.failed("failed to switchto correct vdc",goto=['common_cleanup'])
            else:
                total_ip_count = int(forwardingSysDict['VLAN_PER_VRF_count']) * int(forwardingSysDict['VRF_count'])
                l2_ipv4s = increment_prefix_network(ip.IPv4Interface(str(l2_vlan_ipv4_start) + str(l2_vlan_ipv4_mask)),total_ip_count)
                l2_ipv6s = increment_prefix_network(ip.IPv6Interface(str(l2_vlan_ipv6_start) + str(l2_vlan_ipv6_mask)),total_ip_count)
                ip_index=0
                for i in range(0,len(l2_ipv4s)):
                    device_handle.configure('''int vlan ''' + str(l2_vlan_id) + '''\n
                                     hsrp version 2
                                     hsrp ''' + str(l2_vlan_id) + ''' ipv4
                                     no mac-address 0000.000a.aaaa
                                     ''')
                    l2_vlan_id += 1
            status = infraVerify.postTestVerification(post_test_process_dict)
            if status['status'] == 0:
                self.failed(reason=status['logs'])
            else:
                self.passed(reason=status['logs'])
        except Exception as error:
            log.debug("Unable to unconfigure class map or policy map-Encountered exception " + str(error))
            self.errored('Exception occurred while unconfiguring qos on LEAF1', goto=['next_tc'])
            
# *****************************************************************************************************************************#
class VPC_member_Remove_Add_pre_Host_move_ipv4(aetest.Testcase):
    """ Host_move_ipv4 """

    
    # =============================================================================================================================#        
    
    @aetest.test
    def SVI_ON_LEAF2(self, testscript):
        """Shut down the vpc leg on Leaf2 to force all traffic to Leaf1"""
        
        LEAF_1 = testscript.parameters['LEAF-1']
        LEAF_2 = testscript.parameters['LEAF-2']
        forwardingSysDict = testscript.parameters['forwardingSysDict']
        l2_vlan_id = testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vlan_start']
        l2_vlan_ipv4_sec_start= testscript.parameters['LEAF_2_dict']['VNI_data']['l2_vlan_ipv4_sec_start']
        l2_vlan_ipv4_mask= testscript.parameters['LEAF_2_dict']['VNI_data']['l2_vlan_ipv4_mask']
        #+ str(testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vlan_ipv4_mask'])
        
        try:
            total_ip_count = int(forwardingSysDict['VLAN_PER_VRF_count']) * int(forwardingSysDict['VRF_count'])
            l2_ipv4s = increment_prefix_network(ip.IPv4Interface(str(l2_vlan_ipv4_sec_start) + str(l2_vlan_ipv4_mask)),total_ip_count)
            ip_index=0
            for i in range(0,len(l2_ipv4s)):
                LEAF_2.configure('''int vlan ''' + str(l2_vlan_id) + '''\n
                                 ip address ''' + str(l2_ipv4s[ip_index]) + ''' secondary use-bia
                                 no shut
                                 ''')
                l2_vlan_id += 1
                ip_index += 1
            
            
        except Exception as error:
            log.debug("Unable to configure - Encountered Exception " + str(error))
            self.errored('Exception occurred while configuring secondary ipv4 address on LEAF-2', goto=['cleanup'])
            
    # =============================================================================================================================#        
    
    @aetest.test
    def SVI_ON_LEAF1(self, testscript):
        """Shut down the vpc leg on Leaf2 to force all traffic to Leaf1"""
        
        LEAF_1 = testscript.parameters['LEAF-1']
        LEAF_2 = testscript.parameters['LEAF-2']
        forwardingSysDict = testscript.parameters['forwardingSysDict']
        l2_vlan_id = testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vlan_start']
        l2_vlan_ipv4_sec_start= testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vlan_ipv4_sec_start']
        l2_vlan_ipv4_mask= testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vlan_ipv4_mask']
        
        try:
            total_ip_count = int(forwardingSysDict['VLAN_PER_VRF_count']) * int(forwardingSysDict['VRF_count'])
            l2_ipv4s = increment_prefix_network(ip.IPv4Interface(str(l2_vlan_ipv4_sec_start) + str(l2_vlan_ipv4_mask)),total_ip_count)
            ip_index=0
            for i in range(0,len(l2_ipv4s)):
                LEAF_1.configure('''int vlan ''' + str(l2_vlan_id) + '''\n
                                 ip address ''' + str(l2_ipv4s[ip_index]) + ''' secondary use-bia
                                 no shut
                                 ''')
                l2_vlan_id += 1
                ip_index += 1
                
            
            
        except Exception as error:
            log.debug("Unable to configure - Encountered Exception " + str(error))
            self.errored('Exception occurred while configuring secondary ipv4 address on LEAF-1', goto=['cleanup'])
            
     # =============================================================================================================================#        
    @aetest.test
    def Add_external_int(self, testscript):
        """Shut down the vpc leg on Leaf2 to force all traffic to Leaf1"""
        
        LEAF_1 = testscript.parameters['LEAF-1']
        LEAF_2 = testscript.parameters['LEAF-2']
        
        try:
            testscript.parameters['LEAF-2'].configure('''
                  interface po ''' + str(testscript.parameters['LEAF_1_dict']['VPC_data']['double_vpc_po_1']) + '''
                  port-type external
                  ''')
            
            testscript.parameters['LEAF-1'].configure('''
                  interface po ''' + str(testscript.parameters['LEAF_1_dict']['VPC_data']['double_vpc_po_1']) + '''
                  port-type external
                  ''')    
            
            
        except Exception as error:
            log.debug("Unable to configure - Encountered Exception " + str(error))
            self.errored('Exception occurred while configuring external on LEAF-1 and LEAF-2', goto=['cleanup'])
            
     # =============================================================================================================================#    
    @aetest.test
    def Pre_migration_hsrp(self,testscript):
        LEAF_1 = testscript.parameters['LEAF-1']
        LEAF_2 = testscript.parameters['LEAF-2']
        forwardingSysDict = testscript.parameters['forwardingSysDict']
        l2_vlan_id = testscript.parameters['N7K_LEAF_1_dict']['Vlan_data']['l2_vlan_start']
        l2_vlan_ipv4_start= testscript.parameters['N7K_LEAF_1_dict']['Vlan_data']['l2_vlan_ipv4_start']
        l2_vlan_ipv4_mask= testscript.parameters['N7K_LEAF_1_dict']['Vlan_data']['l2_vlan_ipv4_mask']
        l2_vlan_ipv6_start= testscript.parameters['N7K_LEAF_1_dict']['Vlan_data']['l2_vlan_ipv6_start']
        l2_vlan_ipv6_mask= testscript.parameters['N7K_LEAF_1_dict']['Vlan_data']['l2_vlan_ipv6_mask']
        l2_hsrp_ipv4_vip_start= testscript.parameters['N7K_LEAF_1_dict']['Vlan_data']['hsrp_ipv4_vip_start']
        l2_hsrp_ipv6_vip_start= testscript.parameters['N7K_LEAF_1_dict']['Vlan_data']['hsrp_ipv6_vip_start']
        
        try:
            device_handle=connect_to_vdc(testscript.parameters['xbow1'], 'leaf1')
            if device_handle==False:
                log.info("failed to switchto correct vdc")
                self.failed("failed to switchto correct vdc",goto=['common_cleanup'])
            else:
                total_ip_count = int(forwardingSysDict['VLAN_PER_VRF_count']) * int(forwardingSysDict['VRF_count'])
                l2_ipv4s = increment_prefix_network(ip.IPv4Interface(str(l2_vlan_ipv4_start) + str(l2_vlan_ipv4_mask)),total_ip_count)
                l2_ipv6s = increment_prefix_network(ip.IPv6Interface(str(l2_vlan_ipv6_start) + str(l2_vlan_ipv6_mask)),total_ip_count)
                ip_index=0
                for i in range(0,len(l2_ipv4s)):
                    device_handle.configure('''int vlan ''' + str(l2_vlan_id) + '''\n
                                     hsrp version 2
                                     hsrp ''' + str(l2_vlan_id) + ''' ipv4
                                     mac-address 0000.000a.aaaa
                                     ''')
                    l2_vlan_id += 1
            l2_vlan_id = testscript.parameters['N7K_LEAF_1_dict']['Vlan_data']['l2_vlan_start']        
            device_handle=connect_to_vdc(testscript.parameters['xbow2'], 'leaf2')
            if device_handle==False:
                log.info("failed to switchto correct vdc")
                self.failed("failed to switchto correct vdc",goto=['common_cleanup'])
            else:
                total_ip_count = int(forwardingSysDict['VLAN_PER_VRF_count']) * int(forwardingSysDict['VRF_count'])
                l2_ipv4s = increment_prefix_network(ip.IPv4Interface(str(l2_vlan_ipv4_start) + str(l2_vlan_ipv4_mask)),total_ip_count)
                l2_ipv6s = increment_prefix_network(ip.IPv6Interface(str(l2_vlan_ipv6_start) + str(l2_vlan_ipv6_mask)),total_ip_count)
                ip_index=0
                for i in range(0,len(l2_ipv4s)):
                    device_handle.configure('''int vlan ''' + str(l2_vlan_id) + '''\n
                                     hsrp version 2
                                     hsrp ''' + str(l2_vlan_id) + ''' ipv4
                                     mac-address 0000.000a.aaaa
                                     ''')
                    l2_vlan_id += 1
                    


        except Exception as error:
                log.debug("Unable to configure - Encountered Exception " + str(error))
                self.errored('Exception occurred while configuring on N7k leaf1', goto=['common_cleanup'])
                
    @aetest.test        
    def configure_FO(self,testscript):
        
        FO_1_vlanConfiguration = ""
        FO_1=testscript.parameters['FO_1']

        l3_vrf_count_iter = 0
        l2_vlan_id = testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vlan_start']
        l3_vlan_id = testscript.parameters['LEAF_1_dict']['VNI_data']['l3_vlan_start']

        while l3_vrf_count_iter < testscript.parameters['forwardingSysDict']['VRF_count']:
            l2_vlan_count_iter = 0
            FO_1_vlanConfiguration += '''vlan ''' + str(l3_vlan_id) + '''\n
                                            state active\n
                                            no shut\n'''
            while l2_vlan_count_iter < testscript.parameters['forwardingSysDict']['VLAN_PER_VRF_count']:
                # Incrementing L2 VLAN Iteration counters
                FO_1_vlanConfiguration += '''vlan ''' + str(l2_vlan_id) + '''\n
                                                state active\n
                                                no shut\n'''
                l2_vlan_count_iter += 1
                l2_vlan_id += 1
            # Incrementing L3 VRF Iteration counters
            l3_vrf_count_iter += 1
            l3_vlan_id += 1

        try:
            FO_1.configure(
                str(FO_1_vlanConfiguration) + '''
        
        
            
            interface ''' + str(testscript.parameters['intf_FO_1_to_N7k_LEAF_3']) + '''
            no shut
            switchport
            switchport mode trunk
            
            interface ''' + str(testscript.parameters['intf_FO_1_to_LEAF_3']) + '''
            shut
            switchport
            switchport mode trunk
            
            interface ''' + str(testscript.parameters['intf_FO_1_to_IXIA']) + '''
            no shut
            switchport
            switchport mode trunk
            
            ''')
        except Exception as error:
                log.debug("Unable to configure - Encountered Exception " + str(error))
                self.errored('Exception occurred while configuring on FO_1', goto=['common_cleanup'])
   
#     @aetest.test
#     def CONFIGURE_UCAST_L3_IXIA_TRAFFIC(self, testscript):
#         """ IXIA_CONFIGURATION subsection: Configure MCAST Traffic Item """
# 
#         # Do not perform configurations if skip_tgen_config flag is set
#         if not testscript.parameters['script_flags']['skip_tgen_config']:
# 
#             IX_TP1 = testscript.parameters['IX_TP1']
#             IX_TP2 = testscript.parameters['IX_TP2']
#             P1_dict = testscript.parameters['LEAF_2_TGEN_dict']
#             P2_dict = testscript.parameters['LEAF_3_TGEN_dict']
# 
#             UCAST_v4_dict = {   'src_hndl'  : IX_TP1['port_handle'],
#                                 'dst_hndl'  : IX_TP2['port_handle'],
#                                 'ip_dscp'   : P1_dict['ip_dscp'],
#                                 'circuit'   : 'raw',
#                                 'TI_name'   : "UCAST_L3",
#                                 'rate_pps'  : "9000",
#                                 'bi_dir'    : 1,
#                                 'frame_size': '128',
#                                 'src_mac'   : P1_dict['mac'],
#                                 'dst_mac'   : '0000.000a.aaaa',
#                                 'srcmac_step': '00:00:00:00:00:00',
#                                 'dstmac_step': '00:00:00:00:00:00',
#                                 'srcmac_count': '1',
#                                 'dstmac_count': '1',
#                                 'vlan_id'    : P1_dict['vlan_id'],
#                                 'vlanid_step': '0',
#                                 'vlanid_count': '1',
#                                 'vlan_user_priority': P1_dict['vlan_user_priority'],
#                                 'ip_src_addrs' : P1_dict['v4_addr'],
#                                 'ip_dst_addrs' : P1_dict['L3_dst_addr'],
#                                 'ip_src_step' : '0.0.0.0',
#                                 'ip_dst_step' : '0.0.0.0',
# #                                'ip_step'    : P1_dict['v4_addr_step'],
#                           }
# 
# #            UCAST_v6_dict = {   'src_hndl'  : IX_TP1['ipv6_handle'],
# #                                'dst_hndl'  : IX_TP2['ipv6_handle'],
# #                                'circuit'   : 'ipv6',
# #                                'TI_name'   : "UCAST_V6",
# #                                'rate_pps'  : "1000",
# #                                'bi_dir'    : 1
# #                          }
# 
#             UCAST_v4_TI = ixLib.configure_ixia_l3_traffic_item(UCAST_v4_dict)
# #            UCAST_v6_TI = ixLib.configure_ixia_traffic_item(UCAST_v6_dict)
# 
# #            if UCAST_v4_TI == 0 or UCAST_v6_TI == 0:
# #                log.debug("Configuring UCast TI failed")
# #                self.errored("Configuring UCast TI failed", goto=['cleanup'])
#                 
#             if UCAST_v4_TI == 0:
#                 log.debug("Configuring UCast TI failed")
#                 self.errored("Configuring UCast TI failed", goto=['cleanup'])
#             else:
#                 global stream_id
#                 stream_id = UCAST_v4_TI
#             
# 
#         else:
#             self.passed(reason="Skipped TGEN Configurations as per request")
            
    # @aetest.test
    # def CONFIGURE_BCAST_IXIA_TRAFFIC(self, testscript):
    #     """ IXIA_CONFIGURATION subsection: Configure MCAST Traffic Item """
    # 
    #     # Do not perform configurations if skip_tgen_config flag is set
    #     if not testscript.parameters['script_flags']['skip_tgen_config']:
    # 
    #         IX_TP1 = testscript.parameters['IX_TP1']
    #         IX_TP2 = testscript.parameters['IX_TP2']
    #         P1_dict = testscript.parameters['LEAF_2_TGEN_dict']
    #         P2_dict = testscript.parameters['LEAF_3_TGEN_dict']
    #         BCAST_v4_dict = {
    #                             'src_hndl'      : IX_TP1['port_handle'],
    #                             'dst_hndl'      : IX_TP2['port_handle'],
    #                             'TI_name'       : "BCAST_V4",
    #                             'frame_size'    : "70",
    #                             'rate_pps'      : "1000",
    #                             'src_mac'       : P1_dict['mac'],
    #                             'srcmac_step'   : "00:00:00:00:00:01",
    #                             'srcmac_count'  : '1',
    #                             'vlan_id'       : P1_dict['vlan_id'],
    #                             'vlanid_step'   : "1",
    #                             'vlanid_count'  : "1",
    #                             'ip_src_addrs'  : P1_dict['v4_addr'],
    #                             'ip_step'       : "0.0.1.0",
    #                       }
    # 
    #         BCAST_v4_TI = ixLib.configure_ixia_BCAST_traffic_item(BCAST_v4_dict)
    # 
    #         if BCAST_v4_TI == 0:
    #             log.debug("Configuring BCast TI failed")
    #             self.errored("Configuring BCast TI failed", goto=['cleanup'])
    #         
    # 
    #     else:
    #         self.passed(reason="Skipped TGEN Configurations as per request")
    # =============================================================================================================================#
    @aetest.test
    def APPLY_TRAFFIC(self):
        """ IXIA_CONFIGURATION subsection: Verify IXIA Traffic """

        # # Apply IXIA Traffic
        # if ixLib.apply_traffic() == 1:
        #     log.info("Applying IXIA TI Passed")
        # else:
        #     self.errored("Applying IXIA TI failed", goto=['cleanup'])
            
        # =============================================================================================================================#
    #--------------------------------------------------------------------------------#
        # Start traffic from ixia
        log.info("--- Populating the statistics --- \n")
        log.info("---- Running Traffic --- \n")
        log.info("Starting Traffic")

        traffic_run_status  = ixLib.start_traffic()

        if traffic_run_status is not 1:
           log.info("Failed: To start traffic")
           return 0
        else:
            log.info("\nTraffic started successfully\n")

        time.sleep(30)
    
    # Stop Traffic from ixia
        log.info("--- Stopping Traffic ---- \n")
        log.info("Stopping Traffic")
        traffic_run_status = ixLib.stop_traffic()
        
        if traffic_run_status is not 1:
           log.info("Failed: To Stop traffic")
           return 0
        else:
            log.info("\nTraffic Stopped successfully\n")
            time.sleep(10)    
    
    @aetest.test
    def VERIFY_IXIA_TRAFFIC(self, testscript):
        """ IXIA_CONFIGURATION subsection: Verify IXIA Traffic """

        # Do not perform configurations if skip_tgen_config flag is set
        if not testscript.parameters['script_flags']['skip_tgen_config']:

            time.sleep(20)

            if ixLib.verify_traffic(2) == 0:
                log.debug("Traffic Verification failed")
                self.failed("Traffic Verification failed", goto=['cleanup'])
            else:
                log.info("Traffic Verification Passed")
        else:
            self.passed(reason="Skipped TGEN Configurations as per request")
# =============================================================================================================================#
    @aetest.test
    def VPC_Member_Remove_Add(self, testscript):
        """ VXLAN_DISRUPTIVE_VERIFICATION subsection: Verify Restart BGP """

        LEAF_1 = testscript.parameters['LEAF-1']
        LEAF_2 = testscript.parameters['LEAF-2']
        LEAF_3 = testscript.parameters['LEAF-3']
        

        forwardingSysDict = testscript.parameters['forwardingSysDict']
        try:
            
            LEAF_1.configure('''
                           interface ''' + str(testscript.parameters['intf_LEAF_1_to_N7k_LEAF_2_1']) + '''
                           no channel-group ''' + str(testscript.parameters['LEAF_2_dict']['VPC_data']['peer_link_po']) + ''' mode active
                           ''')
            LEAF_1.configure('''
                           interface ''' + str(testscript.parameters['intf_LEAF_1_to_N7k_LEAF_2_1']) + '''
                           channel-group ''' + str(testscript.parameters['LEAF_2_dict']['VPC_data']['peer_link_po']) + ''' mode active
                           ''')
            
            time.sleep(90)
        except Exception as error:
            log.debug("Unable to configure - Encountered Exception " + str(error))
            self.errored('Exception occurred while flapping the vpc member on LEAF-1', goto=['cleanup'])
            

    # =============================================================================================================================#
    @aetest.test
    def verify_vpc(self, testscript):
        """ VERIFY_NETWORK subsection: Verify VPC """

        LEAF_1 = testscript.parameters['LEAF-1']
        LEAF_2 = testscript.parameters['LEAF-2']

        VPCStatus = infraVerify.verifyVPCStatus(LEAF_1, LEAF_2)

        if VPCStatus['result']:
            log.info(VPCStatus['log'])
            log.info("PASS : VPC Status for '" + str(LEAF_1) + "' and '" + str(LEAF_2) + "' is Successfully Verified\n\n")
        else:
            log.info(VPCStatus['log'])
            log.info("FAIL : VPC Status for '" + str(LEAF_1) + "' and '" + str(LEAF_2) + "' is Failed\n\n")
            self.failed()
                    
# =============================================================================================================================#
    
            
    @aetest.test
    def VERIFY_IXIA_TRAFFIC_AFTER_vpc_member_flap(self, testscript):
        """ IXIA_CONFIGURATION subsection: Verify IXIA Traffic """

        # Do not perform configurations if skip_tgen_config flag is set
        if not testscript.parameters['script_flags']['skip_tgen_config']:

            time.sleep(20)

            if ixLib.verify_traffic(15) == 0:
                log.debug("Traffic Verification failed")
                self.failed("Traffic Verification failed", goto=['cleanup'])
            else:
                log.info("Traffic Verification Passed")
            
        else:
            self.passed(reason="Skipped TGEN Configurations as per request")
     # =============================================================================================================================#        
    @aetest.test
    def Clear_ARP_Table_on_Vxlan_BLs(self, testscript):
        """Shut down the vpc leg on Leaf2 to force all traffic to Leaf1"""
        
        LEAF_1 = testscript.parameters['LEAF-1']
        LEAF_2 = testscript.parameters['LEAF-2']
        
        try:
            for i in range(1, testscript.parameters['forwardingSysDict']['VRF_count']+1):
                testscript.parameters['LEAF-2'].execute('''
                      clear ip arp vrf ''' + str(testscript.parameters['forwardingSysDict']['VRF_string']) + str(i) + ''' force-delete''')
            
            for i in range(1, testscript.parameters['forwardingSysDict']['VRF_count']+1):
                testscript.parameters['LEAF-1'].execute('''
                      clear ip arp vrf ''' + str(testscript.parameters['forwardingSysDict']['VRF_string']) + str(i) + ''' force-delete''')    
            
            
        except Exception as error:
            log.debug("Unable to configure - Encountered Exception " + str(error))
            self.errored('Exception occurred while clearing arp cache on LEAF-1 and LEAF-2', goto=['cleanup'])
            
    @aetest.test        
    def Host_move_FO(self,testscript):
        
        
        FO_1=testscript.parameters['FO_1']

        
        try:
            FO_1.configure('''
            interface ''' + str(testscript.parameters['intf_FO_1_to_N7k_LEAF_3']) + '''
            shut
            switchport
            switchport mode trunk
            
            interface ''' + str(testscript.parameters['intf_FO_1_to_LEAF_3']) + '''
            no shut
            switchport
            switchport mode trunk
            
            ''')
            time.sleep(45)
            #ForkedPdb().set_trace()
        except Exception as error:
                log.debug("Unable to configure - Encountered Exception " + str(error))
                self.errored('Exception occurred while configuring on FO_1', goto=['common_cleanup'])
                
    @aetest.test
    def VERIFY_IXIA_TRAFFIC_AFTER_MOVE(self, testscript):
        """ IXIA_CONFIGURATION subsection: Verify IXIA Traffic """

        # Do not perform configurations if skip_tgen_config flag is set
        if not testscript.parameters['script_flags']['skip_tgen_config']:

            time.sleep(20)

            if ixLib.verify_traffic(15) == 0:
                log.debug("Traffic Verification failed")
                self.failed("Traffic Verification failed", goto=['cleanup'])
            else:
                log.info("Traffic Verification Passed")
            
        else:
            self.passed(reason="Skipped TGEN Configurations as per request")

            
    @aetest.test        
    def Host_move_FO_BACK(self,testscript):
        
        
        FO_1=testscript.parameters['FO_1']

        
        try:
            FO_1.configure('''
            interface ''' + str(testscript.parameters['intf_FO_1_to_LEAF_3']) + '''
            shut
            switchport
            switchport mode trunk
            
            interface ''' + str(testscript.parameters['intf_FO_1_to_N7k_LEAF_3']) + '''
            no shut
            switchport
            switchport mode trunk
            
            
            
            ''')
            time.sleep(45)
        except Exception as error:
                log.debug("Unable to configure - Encountered Exception " + str(error))
                self.errored('Exception occurred while configuring on FO_1', goto=['common_cleanup'])
                
    @aetest.test
    def VERIFY_IXIA_TRAFFIC_HOST_MOVE_BACK(self, testscript):
        """ IXIA_CONFIGURATION subsection: Verify IXIA Traffic """

        # Do not perform configurations if skip_tgen_config flag is set
        if not testscript.parameters['script_flags']['skip_tgen_config']:

            time.sleep(20)

            if ixLib.verify_traffic(15) == 0:
                log.debug("Traffic Verification failed")
                self.failed("Traffic Verification failed", goto=['cleanup'])
            else:
                log.info("Traffic Verification Passed")
        else:
            self.passed(reason="Skipped TGEN Configurations as per request")
        
    @aetest.cleanup
    def cleanup(self,testscript):
        """Unconfigure qos policies"""
        LEAF_1 = testscript.parameters['LEAF-1']
        LEAF_2 = testscript.parameters['LEAF-2']
        LEAF_3 = testscript.parameters['LEAF-3']
        FO_1=testscript.parameters['FO_1']
        LEAF_1 = testscript.parameters['LEAF-1']
        LEAF_2 = testscript.parameters['LEAF-2']
        forwardingSysDict = testscript.parameters['forwardingSysDict']
        l2_vlan_id = testscript.parameters['N7K_LEAF_1_dict']['Vlan_data']['l2_vlan_start']
        l2_vlan_ipv4_start= testscript.parameters['N7K_LEAF_1_dict']['Vlan_data']['l2_vlan_ipv4_start']
        l2_vlan_ipv4_mask= testscript.parameters['N7K_LEAF_1_dict']['Vlan_data']['l2_vlan_ipv4_mask']
        l2_vlan_ipv6_start= testscript.parameters['N7K_LEAF_1_dict']['Vlan_data']['l2_vlan_ipv6_start']
        l2_vlan_ipv6_mask= testscript.parameters['N7K_LEAF_1_dict']['Vlan_data']['l2_vlan_ipv6_mask']
        l2_hsrp_ipv4_vip_start= testscript.parameters['N7K_LEAF_1_dict']['Vlan_data']['hsrp_ipv4_vip_start']
        l2_hsrp_ipv6_vip_start= testscript.parameters['N7K_LEAF_1_dict']['Vlan_data']['hsrp_ipv6_vip_start']
        total_ip_count = int(forwardingSysDict['VLAN_PER_VRF_count']) * int(forwardingSysDict['VRF_count'])
        l2_vlan_ipv4_sec_start= testscript.parameters['LEAF_2_dict']['VNI_data']['l2_vlan_ipv4_sec_start']
        l2_vlan_ipv4_mask= testscript.parameters['LEAF_2_dict']['VNI_data']['l2_vlan_ipv4_mask']
        l2_ipv4s = increment_prefix_network(ip.IPv4Interface(str(l2_vlan_ipv4_sec_start) + str(l2_vlan_ipv4_mask)),total_ip_count)
        post_test_process_dict = {
            'dut_list'                       : [LEAF_1, LEAF_2, LEAF_3],
            'cc_check'                  : 1,
            'cores_check'               : 1,
            'logs_check'                : 0,
            'fnl_flag'                  : 0,
            'exclude_log_check_pattern' : 'ERROR_VLANS_SUSPENDED|ERROR_VLANS_REMOVED',
            }
        try:
            LEAF_1.configure('''
                           interface ''' + str(testscript.parameters['intf_LEAF_1_to_N7k_LEAF_2_1']) + '''
                           channel-group ''' + str(testscript.parameters['LEAF_2_dict']['VPC_data']['peer_link_po']) + ''' mode active
                           ''')
            # UCAST_v4_dict = {
            #                 'mode'        : 'remove',
            #                 'stream_id'   : stream_id,
            #           }
            # if (ixLib.delete_traffic_item(UCAST_v4_dict))==0:
            #     log.debug("Traffic Remove failed")
            #     self.failed("Traffic Remove failed")
            # else:
            #     log.info("Traffic Deletion Passed")
            
            ##Move host back to FP
            FO_1.configure('''
            interface ''' + str(testscript.parameters['intf_FO_1_to_LEAF_3']) + '''
            shut
            switchport
            switchport mode trunk
            
            interface ''' + str(testscript.parameters['intf_FO_1_to_N7k_LEAF_3']) + '''
            no shut
            switchport
            switchport mode trunk
            ''')
            time.sleep(30)
            ###Remove Pre-migration step from both N7k leafs
            device_handle=connect_to_vdc(testscript.parameters['xbow1'], 'leaf1')
            if device_handle==False:
                log.info("failed to switchto correct vdc")
                self.failed("failed to switchto correct vdc",goto=['common_cleanup'])
            else:
                total_ip_count = int(forwardingSysDict['VLAN_PER_VRF_count']) * int(forwardingSysDict['VRF_count'])
                l2_ipv4s = increment_prefix_network(ip.IPv4Interface(str(l2_vlan_ipv4_start) + str(l2_vlan_ipv4_mask)),total_ip_count)
                l2_ipv6s = increment_prefix_network(ip.IPv6Interface(str(l2_vlan_ipv6_start) + str(l2_vlan_ipv6_mask)),total_ip_count)
                ip_index=0
                for i in range(0,len(l2_ipv4s)):
                    device_handle.configure('''int vlan ''' + str(l2_vlan_id) + '''\n
                                     hsrp version 2
                                     hsrp ''' + str(l2_vlan_id) + ''' ipv4
                                     no mac-address 0000.000a.aaaa
                                     ''')
                    l2_vlan_id += 1
            l2_vlan_id = testscript.parameters['N7K_LEAF_1_dict']['Vlan_data']['l2_vlan_start']        
            device_handle=connect_to_vdc(testscript.parameters['xbow2'], 'leaf2')
            if device_handle==False:
                log.info("failed to switchto correct vdc")
                self.failed("failed to switchto correct vdc",goto=['common_cleanup'])
            else:
                total_ip_count = int(forwardingSysDict['VLAN_PER_VRF_count']) * int(forwardingSysDict['VRF_count'])
                l2_ipv4s = increment_prefix_network(ip.IPv4Interface(str(l2_vlan_ipv4_start) + str(l2_vlan_ipv4_mask)),total_ip_count)
                l2_ipv6s = increment_prefix_network(ip.IPv6Interface(str(l2_vlan_ipv6_start) + str(l2_vlan_ipv6_mask)),total_ip_count)
                ip_index=0
                for i in range(0,len(l2_ipv4s)):
                    device_handle.configure('''int vlan ''' + str(l2_vlan_id) + '''\n
                                     hsrp version 2
                                     hsrp ''' + str(l2_vlan_id) + ''' ipv4
                                     no mac-address 0000.000a.aaaa
                                     ''')
                    l2_vlan_id += 1
            status = infraVerify.postTestVerification(post_test_process_dict)
            if status['status'] == 0:
                self.failed(reason=status['logs'])
            else:
                self.passed(reason=status['logs'])
        except Exception as error:
            log.debug("Unable to unconfigure class map or policy map-Encountered exception " + str(error))
            self.errored('Exception occurred while unconfiguring qos on LEAF1', goto=['next_tc'])
            
            
# *****************************************************************************************************************************#
class N7k_Reload_Vdc_pre_Host_move_ipv4(aetest.Testcase):
    """ Host_move_ipv4 """

    
    # =============================================================================================================================#        
    
    @aetest.test
    def SVI_ON_LEAF2(self, testscript):
        """Shut down the vpc leg on Leaf2 to force all traffic to Leaf1"""
        
        LEAF_1 = testscript.parameters['LEAF-1']
        LEAF_2 = testscript.parameters['LEAF-2']
        forwardingSysDict = testscript.parameters['forwardingSysDict']
        l2_vlan_id = testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vlan_start']
        l2_vlan_ipv4_sec_start= testscript.parameters['LEAF_2_dict']['VNI_data']['l2_vlan_ipv4_sec_start']
        l2_vlan_ipv4_mask= testscript.parameters['LEAF_2_dict']['VNI_data']['l2_vlan_ipv4_mask']
        #+ str(testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vlan_ipv4_mask'])
        
        try:
            total_ip_count = int(forwardingSysDict['VLAN_PER_VRF_count']) * int(forwardingSysDict['VRF_count'])
            l2_ipv4s = increment_prefix_network(ip.IPv4Interface(str(l2_vlan_ipv4_sec_start) + str(l2_vlan_ipv4_mask)),total_ip_count)
            ip_index=0
            for i in range(0,len(l2_ipv4s)):
                LEAF_2.configure('''int vlan ''' + str(l2_vlan_id) + '''\n
                                 ip address ''' + str(l2_ipv4s[ip_index]) + ''' secondary use-bia
                                 ''')
                l2_vlan_id += 1
                ip_index += 1
                
            
            
        except Exception as error:
            log.debug("Unable to configure - Encountered Exception " + str(error))
            self.errored('Exception occurred while configuring secondary ipv4 address on LEAF-2', goto=['cleanup'])
            
    # =============================================================================================================================#        
    
    @aetest.test
    def SVI_ON_LEAF1(self, testscript):
        """Shut down the vpc leg on Leaf2 to force all traffic to Leaf1"""
        
        LEAF_1 = testscript.parameters['LEAF-1']
        LEAF_2 = testscript.parameters['LEAF-2']
        forwardingSysDict = testscript.parameters['forwardingSysDict']
        l2_vlan_id = testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vlan_start']
        l2_vlan_ipv4_sec_start= testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vlan_ipv4_sec_start']
        l2_vlan_ipv4_mask= testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vlan_ipv4_mask']
        
        try:
            total_ip_count = int(forwardingSysDict['VLAN_PER_VRF_count']) * int(forwardingSysDict['VRF_count'])
            l2_ipv4s = increment_prefix_network(ip.IPv4Interface(str(l2_vlan_ipv4_sec_start) + str(l2_vlan_ipv4_mask)),total_ip_count)
            ip_index=0
            for i in range(0,len(l2_ipv4s)):
                LEAF_1.configure('''int vlan ''' + str(l2_vlan_id) + '''\n
                                 ip address ''' + str(l2_ipv4s[ip_index]) + ''' secondary use-bia
                                 ''')
                l2_vlan_id += 1
                ip_index += 1
                
            
            
        except Exception as error:
            log.debug("Unable to configure - Encountered Exception " + str(error))
            self.errored('Exception occurred while configuring secondary ipv4 address on LEAF-1', goto=['cleanup'])
            
     # =============================================================================================================================#        
    @aetest.test
    def Add_external_int(self, testscript):
        """Shut down the vpc leg on Leaf2 to force all traffic to Leaf1"""
        
        LEAF_1 = testscript.parameters['LEAF-1']
        LEAF_2 = testscript.parameters['LEAF-2']
        
        try:
            testscript.parameters['LEAF-2'].configure('''
                  interface po ''' + str(testscript.parameters['LEAF_1_dict']['VPC_data']['double_vpc_po_1']) + '''
                  port-type external
                  ''')
            
            testscript.parameters['LEAF-1'].configure('''
                  interface po ''' + str(testscript.parameters['LEAF_1_dict']['VPC_data']['double_vpc_po_1']) + '''
                  port-type external
                  ''')    
            
            
        except Exception as error:
            log.debug("Unable to configure - Encountered Exception " + str(error))
            self.errored('Exception occurred while configuring external on LEAF-1 and LEAF-2', goto=['cleanup'])
            
     # =============================================================================================================================#    
    @aetest.test
    def Pre_migration_hsrp(self,testscript):
        LEAF_1 = testscript.parameters['LEAF-1']
        LEAF_2 = testscript.parameters['LEAF-2']
        forwardingSysDict = testscript.parameters['forwardingSysDict']
        l2_vlan_id = testscript.parameters['N7K_LEAF_1_dict']['Vlan_data']['l2_vlan_start']
        l2_vlan_ipv4_start= testscript.parameters['N7K_LEAF_1_dict']['Vlan_data']['l2_vlan_ipv4_start']
        l2_vlan_ipv4_mask= testscript.parameters['N7K_LEAF_1_dict']['Vlan_data']['l2_vlan_ipv4_mask']
        l2_vlan_ipv6_start= testscript.parameters['N7K_LEAF_1_dict']['Vlan_data']['l2_vlan_ipv6_start']
        l2_vlan_ipv6_mask= testscript.parameters['N7K_LEAF_1_dict']['Vlan_data']['l2_vlan_ipv6_mask']
        l2_hsrp_ipv4_vip_start= testscript.parameters['N7K_LEAF_1_dict']['Vlan_data']['hsrp_ipv4_vip_start']
        l2_hsrp_ipv6_vip_start= testscript.parameters['N7K_LEAF_1_dict']['Vlan_data']['hsrp_ipv6_vip_start']
        
        try:
            device_handle=connect_to_vdc(testscript.parameters['xbow1'], 'leaf1')
            if device_handle==False:
                log.info("failed to switchto correct vdc")
                self.failed("failed to switchto correct vdc",goto=['common_cleanup'])
            else:
                total_ip_count = int(forwardingSysDict['VLAN_PER_VRF_count']) * int(forwardingSysDict['VRF_count'])
                l2_ipv4s = increment_prefix_network(ip.IPv4Interface(str(l2_vlan_ipv4_start) + str(l2_vlan_ipv4_mask)),total_ip_count)
                l2_ipv6s = increment_prefix_network(ip.IPv6Interface(str(l2_vlan_ipv6_start) + str(l2_vlan_ipv6_mask)),total_ip_count)
                ip_index=0
                for i in range(0,len(l2_ipv4s)):
                    device_handle.configure('''int vlan ''' + str(l2_vlan_id) + '''\n
                                     hsrp version 2
                                     hsrp ''' + str(l2_vlan_id) + ''' ipv4
                                     mac-address 0000.000a.aaaa
                                     ''')
                    l2_vlan_id += 1
            l2_vlan_id = testscript.parameters['N7K_LEAF_1_dict']['Vlan_data']['l2_vlan_start']        
            device_handle=connect_to_vdc(testscript.parameters['xbow2'], 'leaf2')
            if device_handle==False:
                log.info("failed to switchto correct vdc")
                self.failed("failed to switchto correct vdc",goto=['common_cleanup'])
            else:
                total_ip_count = int(forwardingSysDict['VLAN_PER_VRF_count']) * int(forwardingSysDict['VRF_count'])
                l2_ipv4s = increment_prefix_network(ip.IPv4Interface(str(l2_vlan_ipv4_start) + str(l2_vlan_ipv4_mask)),total_ip_count)
                l2_ipv6s = increment_prefix_network(ip.IPv6Interface(str(l2_vlan_ipv6_start) + str(l2_vlan_ipv6_mask)),total_ip_count)
                ip_index=0
                for i in range(0,len(l2_ipv4s)):
                    device_handle.configure('''int vlan ''' + str(l2_vlan_id) + '''\n
                                     hsrp version 2
                                     hsrp ''' + str(l2_vlan_id) + ''' ipv4
                                     mac-address 0000.000a.aaaa
                                     ''')
                    l2_vlan_id += 1
                    


        except Exception as error:
                log.debug("Unable to configure - Encountered Exception " + str(error))
                self.errored('Exception occurred while configuring on N7k leaf1', goto=['common_cleanup'])
                
    @aetest.test        
    def configure_FO(self,testscript):
        
        FO_1_vlanConfiguration = ""
        FO_1=testscript.parameters['FO_1']

        l3_vrf_count_iter = 0
        l2_vlan_id = testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vlan_start']
        l3_vlan_id = testscript.parameters['LEAF_1_dict']['VNI_data']['l3_vlan_start']

        while l3_vrf_count_iter < testscript.parameters['forwardingSysDict']['VRF_count']:
            l2_vlan_count_iter = 0
            FO_1_vlanConfiguration += '''vlan ''' + str(l3_vlan_id) + '''\n
                                            state active\n
                                            no shut\n'''
            while l2_vlan_count_iter < testscript.parameters['forwardingSysDict']['VLAN_PER_VRF_count']:
                # Incrementing L2 VLAN Iteration counters
                FO_1_vlanConfiguration += '''vlan ''' + str(l2_vlan_id) + '''\n
                                                state active\n
                                                no shut\n'''
                l2_vlan_count_iter += 1
                l2_vlan_id += 1
            # Incrementing L3 VRF Iteration counters
            l3_vrf_count_iter += 1
            l3_vlan_id += 1

        try:
            FO_1.configure(
                str(FO_1_vlanConfiguration) + '''
        
        
            
            interface ''' + str(testscript.parameters['intf_FO_1_to_N7k_LEAF_3']) + '''
            no shut
            switchport
            switchport mode trunk
            
            interface ''' + str(testscript.parameters['intf_FO_1_to_LEAF_3']) + '''
            shut
            switchport
            switchport mode trunk
            
            interface ''' + str(testscript.parameters['intf_FO_1_to_IXIA']) + '''
            no shut
            switchport
            switchport mode trunk
            
            ''')
        except Exception as error:
                log.debug("Unable to configure - Encountered Exception " + str(error))
                self.errored('Exception occurred while configuring on FO_1', goto=['common_cleanup'])
   
#     @aetest.test
#     def CONFIGURE_UCAST_L3_IXIA_TRAFFIC(self, testscript):
#         """ IXIA_CONFIGURATION subsection: Configure MCAST Traffic Item """
# 
#         # Do not perform configurations if skip_tgen_config flag is set
#         if not testscript.parameters['script_flags']['skip_tgen_config']:
# 
#             IX_TP1 = testscript.parameters['IX_TP1']
#             IX_TP2 = testscript.parameters['IX_TP2']
#             P1_dict = testscript.parameters['LEAF_2_TGEN_dict']
#             P2_dict = testscript.parameters['LEAF_3_TGEN_dict']
# 
#             UCAST_v4_dict = {   'src_hndl'  : IX_TP1['port_handle'],
#                                 'dst_hndl'  : IX_TP2['port_handle'],
#                                 'ip_dscp'   : P1_dict['ip_dscp'],
#                                 'circuit'   : 'raw',
#                                 'TI_name'   : "UCAST_L3",
#                                 'rate_pps'  : "9000",
#                                 'bi_dir'    : 1,
#                                 'frame_size': '128',
#                                 'src_mac'   : P1_dict['mac'],
#                                 'dst_mac'   : '0000.000a.aaaa',
#                                 'srcmac_step': '00:00:00:00:00:00',
#                                 'dstmac_step': '00:00:00:00:00:00',
#                                 'srcmac_count': '1',
#                                 'dstmac_count': '1',
#                                 'vlan_id'    : P1_dict['vlan_id'],
#                                 'vlanid_step': '0',
#                                 'vlanid_count': '1',
#                                 'vlan_user_priority': P1_dict['vlan_user_priority'],
#                                 'ip_src_addrs' : P1_dict['v4_addr'],
#                                 'ip_dst_addrs' : P1_dict['L3_dst_addr'],
#                                 'ip_src_step' : '0.0.0.0',
#                                 'ip_dst_step' : '0.0.0.0',
# #                                'ip_step'    : P1_dict['v4_addr_step'],
#                           }
# 
# #            UCAST_v6_dict = {   'src_hndl'  : IX_TP1['ipv6_handle'],
# #                                'dst_hndl'  : IX_TP2['ipv6_handle'],
# #                                'circuit'   : 'ipv6',
# #                                'TI_name'   : "UCAST_V6",
# #                                'rate_pps'  : "1000",
# #                                'bi_dir'    : 1
# #                          }
# 
#             UCAST_v4_TI = ixLib.configure_ixia_l3_traffic_item(UCAST_v4_dict)
# #            UCAST_v6_TI = ixLib.configure_ixia_traffic_item(UCAST_v6_dict)
# 
# #            if UCAST_v4_TI == 0 or UCAST_v6_TI == 0:
# #                log.debug("Configuring UCast TI failed")
# #                self.errored("Configuring UCast TI failed", goto=['cleanup'])
#                 
#             if UCAST_v4_TI == 0:
#                 log.debug("Configuring UCast TI failed")
#                 self.errored("Configuring UCast TI failed", goto=['cleanup'])
#             else:
#                 global stream_id
#                 stream_id = UCAST_v4_TI
# 
#         else:
#             self.passed(reason="Skipped TGEN Configurations as per request")
            
    # @aetest.test
    # def CONFIGURE_BCAST_IXIA_TRAFFIC(self, testscript):
    #     """ IXIA_CONFIGURATION subsection: Configure MCAST Traffic Item """
    # 
    #     # Do not perform configurations if skip_tgen_config flag is set
    #     if not testscript.parameters['script_flags']['skip_tgen_config']:
    # 
    #         IX_TP1 = testscript.parameters['IX_TP1']
    #         IX_TP2 = testscript.parameters['IX_TP2']
    #         P1_dict = testscript.parameters['LEAF_2_TGEN_dict']
    #         P2_dict = testscript.parameters['LEAF_3_TGEN_dict']
    #         BCAST_v4_dict = {
    #                             'src_hndl'      : IX_TP1['port_handle'],
    #                             'dst_hndl'      : IX_TP2['port_handle'],
    #                             'TI_name'       : "BCAST_V4",
    #                             'frame_size'    : "70",
    #                             'rate_pps'      : "1000",
    #                             'src_mac'       : P1_dict['mac'],
    #                             'srcmac_step'   : "00:00:00:00:00:01",
    #                             'srcmac_count'  : '1',
    #                             'vlan_id'       : P1_dict['vlan_id'],
    #                             'vlanid_step'   : "1",
    #                             'vlanid_count'  : "1",
    #                             'ip_src_addrs'  : P1_dict['v4_addr'],
    #                             'ip_step'       : "0.0.1.0",
    #                       }
    # 
    #         BCAST_v4_TI = ixLib.configure_ixia_BCAST_traffic_item(BCAST_v4_dict)
    # 
    #         if BCAST_v4_TI == 0:
    #             log.debug("Configuring BCast TI failed")
    #             self.errored("Configuring BCast TI failed", goto=['cleanup'])
    # 
    #     else:
    #         self.passed(reason="Skipped TGEN Configurations as per request")
    # =============================================================================================================================#
    @aetest.test
    def APPLY_TRAFFIC(self):
        """ IXIA_CONFIGURATION subsection: Verify IXIA Traffic """

        # # Apply IXIA Traffic
        # if ixLib.apply_traffic() == 1:
        #     log.info("Applying IXIA TI Passed")
        # else:
        #     self.errored("Applying IXIA TI failed", goto=['cleanup'])
            
        # =============================================================================================================================#
    #--------------------------------------------------------------------------------#
        # Start traffic from ixia
        log.info("--- Populating the statistics --- \n")
        log.info("---- Running Traffic --- \n")
        log.info("Starting Traffic")

        traffic_run_status  = ixLib.start_traffic()

        if traffic_run_status is not 1:
           log.info("Failed: To start traffic")
           return 0
        else:
            log.info("\nTraffic started successfully\n")

        time.sleep(30)
    
    # Stop Traffic from ixia
        log.info("--- Stopping Traffic ---- \n")
        log.info("Stopping Traffic")
        traffic_run_status = ixLib.stop_traffic()
        
        if traffic_run_status is not 1:
           log.info("Failed: To Stop traffic")
           return 0
        else:
            log.info("\nTraffic Stopped successfully\n")
            time.sleep(10)    
    
    @aetest.test
    def VERIFY_IXIA_TRAFFIC(self, testscript):
        """ IXIA_CONFIGURATION subsection: Verify IXIA Traffic """

        # Do not perform configurations if skip_tgen_config flag is set
        if not testscript.parameters['script_flags']['skip_tgen_config']:

            time.sleep(20)

            if ixLib.verify_traffic(2) == 0:
                log.debug("Traffic Verification failed")
                self.failed("Traffic Verification failed", goto=['cleanup'])
            else:
                log.info("Traffic Verification Passed")
        else:
            self.passed(reason="Skipped TGEN Configurations as per request")
    # =============================================================================================================================#
    
    @aetest.test
    def TRIGGER_verify_device_vdc_reload(self, testscript):
        """ HA_VERIFICATION subsection: Device ASCII Reload """

        LEAF_1 = testscript.parameters['LEAF-1']
        LEAF_2 = testscript.parameters['LEAF-2']

        LEAF_1.execute("copy r s")
        LEAF_2.execute("copy r s")

        # Perform Device Reload
        
        dialog = Dialog([
        Statement(pattern=r"to reload this vdc \(y/n\)\?  \[no\]",
                  action='sendline(y)',
                  loop_continue=True,
                  continue_timer=True),
        Statement(pattern=r'r"Are you sure you want to continue\? \[no\]"',
                  action='sendline(yes)',
                  loop_continue=True,
                  continue_timer=True),
        
        ])
        result= vdc.reload(testscript.parameters['xbow1'], 'leaf1', timeout_sec=300, interval_sec=15,auto_reconnect=True, dialog=dialog)
        #result= LEAF_1.reload(reload_command="reload ascii", timeout=1200,prompt_recovery=True, dialog=dialog, config_lock_retry_sleep=60, config_lock_retries=20)
        #result = infraTrig.switchASCIIreload(LEAF_1)
        log.info("result= " + str(result))
        if result:
            log.info("Vdc Reload completed Successfully")
            log.info("Waiting for 240 sec for the topology to come UP")
            time.sleep(240)
        else:
            log.debug("Vdc Reload Failed")
            self.failed("Vdc Reload Failed", goto=['common_cleanup'])
        
        # result2= LEAF_2.reload(reload_command="reload ascii", timeout=1000,prompt_recovery=True, config_lock_retry_sleep=60, config_lock_retries=20, dialog=dialog)
        # #result = infraTrig.switchASCIIreload(LEAF_1)
        # log.info("result= " + str(result2))
        # if result2:
        #     log.info("ASCII Reload completed Successfully on Vxlan Leaf2")
        #     log.info("Waiging for 240 sec for the topology to come UP")
        #     time.sleep(240)
        # else:
        #     log.debug("ASCII Reload Failed on Vxlan Leaf2")
        #     self.failed("ASCII Reload Failed", goto=['common_cleanup'])
    
    @aetest.test
    def VERIFY_IXIA_TRAFFIC_AFTER_VDC_RELOAD(self, testscript):
        """ IXIA_CONFIGURATION subsection: Verify IXIA Traffic """

        # Do not perform configurations if skip_tgen_config flag is set
        if not testscript.parameters['script_flags']['skip_tgen_config']:

            time.sleep(20)

            if ixLib.verify_traffic(2) == 0:
                log.debug("Traffic Verification failed")
                self.failed("Traffic Verification failed", goto=['cleanup'])
            else:
                log.info("Traffic Verification Passed")
        else:
            self.passed(reason="Skipped TGEN Configurations as per request")
     # =============================================================================================================================#        
    @aetest.test
    def Clear_ARP_Table_on_Vxlan_BLs(self, testscript):
        """Shut down the vpc leg on Leaf2 to force all traffic to Leaf1"""
        
        LEAF_1 = testscript.parameters['LEAF-1']
        LEAF_2 = testscript.parameters['LEAF-2']
        
        try:
            for i in range(1, testscript.parameters['forwardingSysDict']['VRF_count']+1):
                testscript.parameters['LEAF-2'].execute('''
                      clear ip arp vrf ''' + str(testscript.parameters['forwardingSysDict']['VRF_string']) + str(i) + ''' force-delete''')
            
            for i in range(1, testscript.parameters['forwardingSysDict']['VRF_count']+1):
                testscript.parameters['LEAF-1'].execute('''
                      clear ip arp vrf ''' + str(testscript.parameters['forwardingSysDict']['VRF_string']) + str(i) + ''' force-delete''')    
            
            
        except Exception as error:
            log.debug("Unable to configure - Encountered Exception " + str(error))
            self.errored('Exception occurred while clearing arp cache on LEAF-1 and LEAF-2', goto=['cleanup'])
            
    @aetest.test        
    def Host_move_FO(self,testscript):
        
        
        FO_1=testscript.parameters['FO_1']

        
        try:
            FO_1.configure('''
            interface ''' + str(testscript.parameters['intf_FO_1_to_N7k_LEAF_3']) + '''
            shut
            switchport
            switchport mode trunk
            
            interface ''' + str(testscript.parameters['intf_FO_1_to_LEAF_3']) + '''
            no shut
            switchport
            switchport mode trunk
            
            ''')
            time.sleep(45)
        except Exception as error:
                log.debug("Unable to configure - Encountered Exception " + str(error))
                self.errored('Exception occurred while configuring on FO_1', goto=['common_cleanup'])
                
    @aetest.test
    def VERIFY_IXIA_TRAFFIC_AFTER_MOVE(self, testscript):
        """ IXIA_CONFIGURATION subsection: Verify IXIA Traffic """

        # Do not perform configurations if skip_tgen_config flag is set
        if not testscript.parameters['script_flags']['skip_tgen_config']:

            time.sleep(20)

            if ixLib.verify_traffic(15) == 0:
                log.debug("Traffic Verification failed")
                self.failed("Traffic Verification failed", goto=['cleanup'])
            else:
                log.info("Traffic Verification Passed")
        else:
            self.passed(reason="Skipped TGEN Configurations as per request")
            
    @aetest.test        
    def Host_move_FO_BACK(self,testscript):
        
        
        FO_1=testscript.parameters['FO_1']

        
        try:
            FO_1.configure('''
            interface ''' + str(testscript.parameters['intf_FO_1_to_LEAF_3']) + '''
            shut
            switchport
            switchport mode trunk
            
            interface ''' + str(testscript.parameters['intf_FO_1_to_N7k_LEAF_3']) + '''
            no shut
            switchport
            switchport mode trunk
            
            
            
            ''')
            time.sleep(45)
        except Exception as error:
                log.debug("Unable to configure - Encountered Exception " + str(error))
                self.errored('Exception occurred while configuring on FO_1', goto=['common_cleanup'])
                
    @aetest.test
    def VERIFY_IXIA_TRAFFIC_HOST_MOVE_BACK(self, testscript):
        """ IXIA_CONFIGURATION subsection: Verify IXIA Traffic """

        # Do not perform configurations if skip_tgen_config flag is set
        if not testscript.parameters['script_flags']['skip_tgen_config']:

            time.sleep(20)

            if ixLib.verify_traffic(15) == 0:
                log.debug("Traffic Verification failed")
                self.failed("Traffic Verification failed", goto=['cleanup'])
            else:
                log.info("Traffic Verification Passed")
        else:
            self.passed(reason="Skipped TGEN Configurations as per request")
        
    @aetest.cleanup
    def cleanup(self,testscript):
        """Unconfigure qos policies"""
        LEAF_1 = testscript.parameters['LEAF-1']
        LEAF_2 = testscript.parameters['LEAF-2']
        LEAF_3 = testscript.parameters['LEAF-3']
        FO_1=testscript.parameters['FO_1']
        LEAF_1 = testscript.parameters['LEAF-1']
        LEAF_2 = testscript.parameters['LEAF-2']
        forwardingSysDict = testscript.parameters['forwardingSysDict']
        l2_vlan_id = testscript.parameters['N7K_LEAF_1_dict']['Vlan_data']['l2_vlan_start']
        l2_vlan_ipv4_start= testscript.parameters['N7K_LEAF_1_dict']['Vlan_data']['l2_vlan_ipv4_start']
        l2_vlan_ipv4_mask= testscript.parameters['N7K_LEAF_1_dict']['Vlan_data']['l2_vlan_ipv4_mask']
        l2_vlan_ipv6_start= testscript.parameters['N7K_LEAF_1_dict']['Vlan_data']['l2_vlan_ipv6_start']
        l2_vlan_ipv6_mask= testscript.parameters['N7K_LEAF_1_dict']['Vlan_data']['l2_vlan_ipv6_mask']
        l2_hsrp_ipv4_vip_start= testscript.parameters['N7K_LEAF_1_dict']['Vlan_data']['hsrp_ipv4_vip_start']
        l2_hsrp_ipv6_vip_start= testscript.parameters['N7K_LEAF_1_dict']['Vlan_data']['hsrp_ipv6_vip_start']
        
        post_test_process_dict = {
            'dut_list'                       : [LEAF_1, LEAF_2, LEAF_3],
            'cc_check'                  : 1,
            'cores_check'               : 1,
            'logs_check'                : 0,
            'fnl_flag'                  : 0,
            'exclude_log_check_pattern' : 'ERROR_VLANS_SUSPENDED|ERROR_VLANS_REMOVED',
            }
        try:
            FO_1.configure('''
            interface ''' + str(testscript.parameters['intf_FO_1_to_LEAF_3']) + '''
            shut
            switchport
            switchport mode trunk
            
            interface ''' + str(testscript.parameters['intf_FO_1_to_N7k_LEAF_3']) + '''
            no shut
            switchport
            switchport mode trunk
            ''')
            time.sleep(30)
            ###Remove Pre-migration step from both N7k leafs
            device_handle=connect_to_vdc(testscript.parameters['xbow1'], 'leaf1')
            if device_handle==False:
                log.info("failed to switchto correct vdc")
                self.failed("failed to switchto correct vdc",goto=['common_cleanup'])
            else:
                total_ip_count = int(forwardingSysDict['VLAN_PER_VRF_count']) * int(forwardingSysDict['VRF_count'])
                l2_ipv4s = increment_prefix_network(ip.IPv4Interface(str(l2_vlan_ipv4_start) + str(l2_vlan_ipv4_mask)),total_ip_count)
                l2_ipv6s = increment_prefix_network(ip.IPv6Interface(str(l2_vlan_ipv6_start) + str(l2_vlan_ipv6_mask)),total_ip_count)
                ip_index=0
                for i in range(0,len(l2_ipv4s)):
                    device_handle.configure('''int vlan ''' + str(l2_vlan_id) + '''\n
                                     hsrp version 2
                                     hsrp ''' + str(l2_vlan_id) + ''' ipv4
                                     no mac-address 0000.000a.aaaa
                                     ''')
                    l2_vlan_id += 1
            l2_vlan_id = testscript.parameters['N7K_LEAF_1_dict']['Vlan_data']['l2_vlan_start']        
            device_handle=connect_to_vdc(testscript.parameters['xbow2'], 'leaf2')
            if device_handle==False:
                log.info("failed to switchto correct vdc")
                self.failed("failed to switchto correct vdc",goto=['common_cleanup'])
            else:
                total_ip_count = int(forwardingSysDict['VLAN_PER_VRF_count']) * int(forwardingSysDict['VRF_count'])
                l2_ipv4s = increment_prefix_network(ip.IPv4Interface(str(l2_vlan_ipv4_start) + str(l2_vlan_ipv4_mask)),total_ip_count)
                l2_ipv6s = increment_prefix_network(ip.IPv6Interface(str(l2_vlan_ipv6_start) + str(l2_vlan_ipv6_mask)),total_ip_count)
                ip_index=0
                for i in range(0,len(l2_ipv4s)):
                    device_handle.configure('''int vlan ''' + str(l2_vlan_id) + '''\n
                                     hsrp version 2
                                     hsrp ''' + str(l2_vlan_id) + ''' ipv4
                                     no mac-address 0000.000a.aaaa
                                     ''')
                    l2_vlan_id += 1
            status = infraVerify.postTestVerification(post_test_process_dict)
            if status['status'] == 0:
                self.failed(reason=status['logs'])
            else:
                self.passed(reason=status['logs'])
        except Exception as error:
            log.debug("Unable to unconfigure class map or policy map-Encountered exception " + str(error))
            self.errored('Exception occurred while unconfiguring qos on LEAF1', goto=['next_tc'])
            
# *****************************************************************************************************************************#
class Reload_Ascii_pre_Host_move_ipv4(aetest.Testcase):
    """ Host_move_ipv4 """

    
    # =============================================================================================================================#        
    
    @aetest.test
    def SVI_ON_LEAF2(self, testscript):
        """Shut down the vpc leg on Leaf2 to force all traffic to Leaf1"""
        
        LEAF_1 = testscript.parameters['LEAF-1']
        LEAF_2 = testscript.parameters['LEAF-2']
        forwardingSysDict = testscript.parameters['forwardingSysDict']
        l2_vlan_id = testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vlan_start']
        l2_vlan_ipv4_sec_start= testscript.parameters['LEAF_2_dict']['VNI_data']['l2_vlan_ipv4_sec_start']
        l2_vlan_ipv4_mask= testscript.parameters['LEAF_2_dict']['VNI_data']['l2_vlan_ipv4_mask']
        #+ str(testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vlan_ipv4_mask'])
        
        try:
            total_ip_count = int(forwardingSysDict['VLAN_PER_VRF_count']) * int(forwardingSysDict['VRF_count'])
            l2_ipv4s = increment_prefix_network(ip.IPv4Interface(str(l2_vlan_ipv4_sec_start) + str(l2_vlan_ipv4_mask)),total_ip_count)
            ip_index=0
            for i in range(0,len(l2_ipv4s)):
                LEAF_2.configure('''int vlan ''' + str(l2_vlan_id) + '''\n
                                 ip address ''' + str(l2_ipv4s[ip_index]) + ''' secondary use-bia
                                 ''')
                l2_vlan_id += 1
                ip_index += 1
                
            
            
        except Exception as error:
            log.debug("Unable to configure - Encountered Exception " + str(error))
            self.errored('Exception occurred while configuring secondary ipv4 address on LEAF-2', goto=['cleanup'])
            
    # =============================================================================================================================#        
    
    @aetest.test
    def SVI_ON_LEAF1(self, testscript):
        """Shut down the vpc leg on Leaf2 to force all traffic to Leaf1"""
        
        LEAF_1 = testscript.parameters['LEAF-1']
        LEAF_2 = testscript.parameters['LEAF-2']
        forwardingSysDict = testscript.parameters['forwardingSysDict']
        l2_vlan_id = testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vlan_start']
        l2_vlan_ipv4_sec_start= testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vlan_ipv4_sec_start']
        l2_vlan_ipv4_mask= testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vlan_ipv4_mask']
        
        try:
            total_ip_count = int(forwardingSysDict['VLAN_PER_VRF_count']) * int(forwardingSysDict['VRF_count'])
            l2_ipv4s = increment_prefix_network(ip.IPv4Interface(str(l2_vlan_ipv4_sec_start) + str(l2_vlan_ipv4_mask)),total_ip_count)
            ip_index=0
            for i in range(0,len(l2_ipv4s)):
                LEAF_1.configure('''int vlan ''' + str(l2_vlan_id) + '''\n
                                 ip address ''' + str(l2_ipv4s[ip_index]) + ''' secondary use-bia
                                 ''')
                l2_vlan_id += 1
                ip_index += 1
                
            
            
        except Exception as error:
            log.debug("Unable to configure - Encountered Exception " + str(error))
            self.errored('Exception occurred while configuring secondary ipv4 address on LEAF-1', goto=['cleanup'])
            
     # =============================================================================================================================#        
    @aetest.test
    def Add_external_int(self, testscript):
        """Shut down the vpc leg on Leaf2 to force all traffic to Leaf1"""
        
        LEAF_1 = testscript.parameters['LEAF-1']
        LEAF_2 = testscript.parameters['LEAF-2']
        
        try:
            testscript.parameters['LEAF-2'].configure('''
                  interface po ''' + str(testscript.parameters['LEAF_1_dict']['VPC_data']['double_vpc_po_1']) + '''
                  port-type external
                  ''')
            
            testscript.parameters['LEAF-1'].configure('''
                  interface po ''' + str(testscript.parameters['LEAF_1_dict']['VPC_data']['double_vpc_po_1']) + '''
                  port-type external
                  ''')    
            
            
        except Exception as error:
            log.debug("Unable to configure - Encountered Exception " + str(error))
            self.errored('Exception occurred while configuring external on LEAF-1 and LEAF-2', goto=['cleanup'])
            
     # =============================================================================================================================#    
    @aetest.test
    def Pre_migration_hsrp(self,testscript):
        LEAF_1 = testscript.parameters['LEAF-1']
        LEAF_2 = testscript.parameters['LEAF-2']
        forwardingSysDict = testscript.parameters['forwardingSysDict']
        l2_vlan_id = testscript.parameters['N7K_LEAF_1_dict']['Vlan_data']['l2_vlan_start']
        l2_vlan_ipv4_start= testscript.parameters['N7K_LEAF_1_dict']['Vlan_data']['l2_vlan_ipv4_start']
        l2_vlan_ipv4_mask= testscript.parameters['N7K_LEAF_1_dict']['Vlan_data']['l2_vlan_ipv4_mask']
        l2_vlan_ipv6_start= testscript.parameters['N7K_LEAF_1_dict']['Vlan_data']['l2_vlan_ipv6_start']
        l2_vlan_ipv6_mask= testscript.parameters['N7K_LEAF_1_dict']['Vlan_data']['l2_vlan_ipv6_mask']
        l2_hsrp_ipv4_vip_start= testscript.parameters['N7K_LEAF_1_dict']['Vlan_data']['hsrp_ipv4_vip_start']
        l2_hsrp_ipv6_vip_start= testscript.parameters['N7K_LEAF_1_dict']['Vlan_data']['hsrp_ipv6_vip_start']
        
        try:
            device_handle=connect_to_vdc(testscript.parameters['xbow1'], 'leaf1')
            if device_handle==False:
                log.info("failed to switchto correct vdc")
                self.failed("failed to switchto correct vdc",goto=['common_cleanup'])
            else:
                total_ip_count = int(forwardingSysDict['VLAN_PER_VRF_count']) * int(forwardingSysDict['VRF_count'])
                l2_ipv4s = increment_prefix_network(ip.IPv4Interface(str(l2_vlan_ipv4_start) + str(l2_vlan_ipv4_mask)),total_ip_count)
                l2_ipv6s = increment_prefix_network(ip.IPv6Interface(str(l2_vlan_ipv6_start) + str(l2_vlan_ipv6_mask)),total_ip_count)
                ip_index=0
                for i in range(0,len(l2_ipv4s)):
                    device_handle.configure('''int vlan ''' + str(l2_vlan_id) + '''\n
                                     hsrp version 2
                                     hsrp ''' + str(l2_vlan_id) + ''' ipv4
                                     mac-address 0000.000a.aaaa
                                     ''')
                    l2_vlan_id += 1
            l2_vlan_id = testscript.parameters['N7K_LEAF_1_dict']['Vlan_data']['l2_vlan_start']        
            device_handle=connect_to_vdc(testscript.parameters['xbow2'], 'leaf2')
            if device_handle==False:
                log.info("failed to switchto correct vdc")
                self.failed("failed to switchto correct vdc",goto=['common_cleanup'])
            else:
                total_ip_count = int(forwardingSysDict['VLAN_PER_VRF_count']) * int(forwardingSysDict['VRF_count'])
                l2_ipv4s = increment_prefix_network(ip.IPv4Interface(str(l2_vlan_ipv4_start) + str(l2_vlan_ipv4_mask)),total_ip_count)
                l2_ipv6s = increment_prefix_network(ip.IPv6Interface(str(l2_vlan_ipv6_start) + str(l2_vlan_ipv6_mask)),total_ip_count)
                ip_index=0
                for i in range(0,len(l2_ipv4s)):
                    device_handle.configure('''int vlan ''' + str(l2_vlan_id) + '''\n
                                     hsrp version 2
                                     hsrp ''' + str(l2_vlan_id) + ''' ipv4
                                     mac-address 0000.000a.aaaa
                                     ''')
                    l2_vlan_id += 1
                    


        except Exception as error:
                log.debug("Unable to configure - Encountered Exception " + str(error))
                self.errored('Exception occurred while configuring on N7k leaf1', goto=['common_cleanup'])
                
    @aetest.test        
    def configure_FO(self,testscript):
        
        FO_1_vlanConfiguration = ""
        FO_1=testscript.parameters['FO_1']

        l3_vrf_count_iter = 0
        l2_vlan_id = testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vlan_start']
        l3_vlan_id = testscript.parameters['LEAF_1_dict']['VNI_data']['l3_vlan_start']

        while l3_vrf_count_iter < testscript.parameters['forwardingSysDict']['VRF_count']:
            l2_vlan_count_iter = 0
            FO_1_vlanConfiguration += '''vlan ''' + str(l3_vlan_id) + '''\n
                                            state active\n
                                            no shut\n'''
            while l2_vlan_count_iter < testscript.parameters['forwardingSysDict']['VLAN_PER_VRF_count']:
                # Incrementing L2 VLAN Iteration counters
                FO_1_vlanConfiguration += '''vlan ''' + str(l2_vlan_id) + '''\n
                                                state active\n
                                                no shut\n'''
                l2_vlan_count_iter += 1
                l2_vlan_id += 1
            # Incrementing L3 VRF Iteration counters
            l3_vrf_count_iter += 1
            l3_vlan_id += 1

        try:
            FO_1.configure(
                str(FO_1_vlanConfiguration) + '''
        
        
            
            interface ''' + str(testscript.parameters['intf_FO_1_to_N7k_LEAF_3']) + '''
            no shut
            switchport
            switchport mode trunk
            
            interface ''' + str(testscript.parameters['intf_FO_1_to_LEAF_3']) + '''
            shut
            switchport
            switchport mode trunk
            
            interface ''' + str(testscript.parameters['intf_FO_1_to_IXIA']) + '''
            no shut
            switchport
            switchport mode trunk
            
            ''')
        except Exception as error:
                log.debug("Unable to configure - Encountered Exception " + str(error))
                self.errored('Exception occurred while configuring on FO_1', goto=['common_cleanup'])
   
#     @aetest.test
#     def CONFIGURE_UCAST_L3_IXIA_TRAFFIC(self, testscript):
#         """ IXIA_CONFIGURATION subsection: Configure MCAST Traffic Item """
# 
#         # Do not perform configurations if skip_tgen_config flag is set
#         if not testscript.parameters['script_flags']['skip_tgen_config']:
# 
#             IX_TP1 = testscript.parameters['IX_TP1']
#             IX_TP2 = testscript.parameters['IX_TP2']
#             P1_dict = testscript.parameters['LEAF_2_TGEN_dict']
#             P2_dict = testscript.parameters['LEAF_3_TGEN_dict']
# 
#             UCAST_v4_dict = {   'src_hndl'  : IX_TP1['port_handle'],
#                                 'dst_hndl'  : IX_TP2['port_handle'],
#                                 'ip_dscp'   : P1_dict['ip_dscp'],
#                                 'circuit'   : 'raw',
#                                 'TI_name'   : "UCAST_L3",
#                                 'rate_pps'  : "9000",
#                                 'bi_dir'    : 1,
#                                 'frame_size': '128',
#                                 'src_mac'   : P1_dict['mac'],
#                                 'dst_mac'   : '0000.000a.aaaa',
#                                 'srcmac_step': '00:00:00:00:00:00',
#                                 'dstmac_step': '00:00:00:00:00:00',
#                                 'srcmac_count': '1',
#                                 'dstmac_count': '1',
#                                 'vlan_id'    : P1_dict['vlan_id'],
#                                 'vlanid_step': '0',
#                                 'vlanid_count': '1',
#                                 'vlan_user_priority': P1_dict['vlan_user_priority'],
#                                 'ip_src_addrs' : P1_dict['v4_addr'],
#                                 'ip_dst_addrs' : P1_dict['L3_dst_addr'],
#                                 'ip_src_step' : '0.0.0.0',
#                                 'ip_dst_step' : '0.0.0.0',
# #                                'ip_step'    : P1_dict['v4_addr_step'],
#                           }
# 
# #            UCAST_v6_dict = {   'src_hndl'  : IX_TP1['ipv6_handle'],
# #                                'dst_hndl'  : IX_TP2['ipv6_handle'],
# #                                'circuit'   : 'ipv6',
# #                                'TI_name'   : "UCAST_V6",
# #                                'rate_pps'  : "1000",
# #                                'bi_dir'    : 1
# #                          }
# 
#             UCAST_v4_TI = ixLib.configure_ixia_l3_traffic_item(UCAST_v4_dict)
# #            UCAST_v6_TI = ixLib.configure_ixia_traffic_item(UCAST_v6_dict)
# 
# #            if UCAST_v4_TI == 0 or UCAST_v6_TI == 0:
# #                log.debug("Configuring UCast TI failed")
# #                self.errored("Configuring UCast TI failed", goto=['cleanup'])
#                 
#             if UCAST_v4_TI == 0:
#                 log.debug("Configuring UCast TI failed")
#                 self.errored("Configuring UCast TI failed", goto=['cleanup'])
#             else:
#                 global stream_id
#                 stream_id = UCAST_v4_TI
# 
#         else:
#             self.passed(reason="Skipped TGEN Configurations as per request")
            
    # @aetest.test
    # def CONFIGURE_BCAST_IXIA_TRAFFIC(self, testscript):
    #     """ IXIA_CONFIGURATION subsection: Configure MCAST Traffic Item """
    # 
    #     # Do not perform configurations if skip_tgen_config flag is set
    #     if not testscript.parameters['script_flags']['skip_tgen_config']:
    # 
    #         IX_TP1 = testscript.parameters['IX_TP1']
    #         IX_TP2 = testscript.parameters['IX_TP2']
    #         P1_dict = testscript.parameters['LEAF_2_TGEN_dict']
    #         P2_dict = testscript.parameters['LEAF_3_TGEN_dict']
    #         BCAST_v4_dict = {
    #                             'src_hndl'      : IX_TP1['port_handle'],
    #                             'dst_hndl'      : IX_TP2['port_handle'],
    #                             'TI_name'       : "BCAST_V4",
    #                             'frame_size'    : "70",
    #                             'rate_pps'      : "1000",
    #                             'src_mac'       : P1_dict['mac'],
    #                             'srcmac_step'   : "00:00:00:00:00:01",
    #                             'srcmac_count'  : '1',
    #                             'vlan_id'       : P1_dict['vlan_id'],
    #                             'vlanid_step'   : "1",
    #                             'vlanid_count'  : "1",
    #                             'ip_src_addrs'  : P1_dict['v4_addr'],
    #                             'ip_step'       : "0.0.1.0",
    #                       }
    # 
    #         BCAST_v4_TI = ixLib.configure_ixia_BCAST_traffic_item(BCAST_v4_dict)
    # 
    #         if BCAST_v4_TI == 0:
    #             log.debug("Configuring BCast TI failed")
    #             self.errored("Configuring BCast TI failed", goto=['cleanup'])
    # 
    #     else:
    #         self.passed(reason="Skipped TGEN Configurations as per request")
    # =============================================================================================================================#
    @aetest.test
    def APPLY_TRAFFIC(self):
        """ IXIA_CONFIGURATION subsection: Verify IXIA Traffic """

        # # Apply IXIA Traffic
        # if ixLib.apply_traffic() == 1:
        #     log.info("Applying IXIA TI Passed")
        # else:
        #     self.errored("Applying IXIA TI failed", goto=['cleanup'])
            
        # =============================================================================================================================#
    #--------------------------------------------------------------------------------#
        # Start traffic from ixia
        log.info("--- Populating the statistics --- \n")
        log.info("---- Running Traffic --- \n")
        log.info("Starting Traffic")

        traffic_run_status  = ixLib.start_traffic()

        if traffic_run_status is not 1:
           log.info("Failed: To start traffic")
           return 0
        else:
            log.info("\nTraffic started successfully\n")

        time.sleep(30)
    
    # Stop Traffic from ixia
        log.info("--- Stopping Traffic ---- \n")
        log.info("Stopping Traffic")
        traffic_run_status = ixLib.stop_traffic()
        
        if traffic_run_status is not 1:
           log.info("Failed: To Stop traffic")
           return 0
        else:
            log.info("\nTraffic Stopped successfully\n")
            time.sleep(10)    
    
    @aetest.test
    def VERIFY_IXIA_TRAFFIC(self, testscript):
        """ IXIA_CONFIGURATION subsection: Verify IXIA Traffic """

        # Do not perform configurations if skip_tgen_config flag is set
        if not testscript.parameters['script_flags']['skip_tgen_config']:

            time.sleep(20)

            if ixLib.verify_traffic(2) == 0:
                log.debug("Traffic Verification failed")
                self.failed("Traffic Verification failed", goto=['cleanup'])
            else:
                log.info("Traffic Verification Passed")
        else:
            self.passed(reason="Skipped TGEN Configurations as per request")
    # =============================================================================================================================#
    
    @aetest.test
    def TRIGGER_verify_device_ascii_reload(self, testscript):
        """ HA_VERIFICATION subsection: Device ASCII Reload """

        LEAF_1 = testscript.parameters['LEAF-1']
        LEAF_2 = testscript.parameters['LEAF-2']

        LEAF_1.execute("copy r s")
        LEAF_2.execute("copy r s")

        # Perform Device Reload
        dialog = Dialog([
            Statement(pattern=r'.*Do you wish to proceed anyway.*',
                      action='sendline(y)',
                      loop_continue=True,
                      continue_timer=True)
        ])
        result= LEAF_1.reload(reload_command="reload ascii", timeout=1200,prompt_recovery=True, dialog=dialog, config_lock_retry_sleep=60, config_lock_retries=20)
        #result = infraTrig.switchASCIIreload(LEAF_1)
        log.info("result= " + str(result))
        if result:
            log.info("ASCII Reload completed Successfully")
            log.info("Waiging for 240 sec for the topology to come UP")
            time.sleep(240)
        else:
            log.debug("ASCII Reload Failed")
            self.failed("ASCII Reload Failed", goto=['common_cleanup'])
        
        result2= LEAF_2.reload(reload_command="reload ascii", timeout=1000,prompt_recovery=True, config_lock_retry_sleep=60, config_lock_retries=20, dialog=dialog)
        #result = infraTrig.switchASCIIreload(LEAF_1)
        log.info("result= " + str(result2))
        if result2:
            log.info("ASCII Reload completed Successfully on Vxlan Leaf2")
            log.info("Waiging for 240 sec for the topology to come UP")
            time.sleep(240)
        else:
            log.debug("ASCII Reload Failed on Vxlan Leaf2")
            self.failed("ASCII Reload Failed", goto=['common_cleanup'])
    
    @aetest.test
    def VERIFY_IXIA_TRAFFIC_AFTER_ASCII_RELOAD(self, testscript):
        """ IXIA_CONFIGURATION subsection: Verify IXIA Traffic """

        # Do not perform configurations if skip_tgen_config flag is set
        if not testscript.parameters['script_flags']['skip_tgen_config']:

            time.sleep(20)

            if ixLib.verify_traffic(2) == 0:
                log.debug("Traffic Verification failed")
                self.failed("Traffic Verification failed", goto=['cleanup'])
            else:
                log.info("Traffic Verification Passed")
        else:
            self.passed(reason="Skipped TGEN Configurations as per request")
     # =============================================================================================================================#        
    @aetest.test
    def Clear_ARP_Table_on_Vxlan_BLs(self, testscript):
        """Shut down the vpc leg on Leaf2 to force all traffic to Leaf1"""
        
        LEAF_1 = testscript.parameters['LEAF-1']
        LEAF_2 = testscript.parameters['LEAF-2']
        
        try:
            for i in range(1, testscript.parameters['forwardingSysDict']['VRF_count']+1):
                testscript.parameters['LEAF-2'].execute('''
                      clear ip arp vrf ''' + str(testscript.parameters['forwardingSysDict']['VRF_string']) + str(i) + ''' force-delete''')
            
            for i in range(1, testscript.parameters['forwardingSysDict']['VRF_count']+1):
                testscript.parameters['LEAF-1'].execute('''
                      clear ip arp vrf ''' + str(testscript.parameters['forwardingSysDict']['VRF_string']) + str(i) + ''' force-delete''')    
            
            
        except Exception as error:
            log.debug("Unable to configure - Encountered Exception " + str(error))
            self.errored('Exception occurred while clearing arp cache on LEAF-1 and LEAF-2', goto=['cleanup'])
            
    @aetest.test        
    def Host_move_FO(self,testscript):
        
        
        FO_1=testscript.parameters['FO_1']

        
        try:
            FO_1.configure('''
            interface ''' + str(testscript.parameters['intf_FO_1_to_N7k_LEAF_3']) + '''
            shut
            switchport
            switchport mode trunk
            
            interface ''' + str(testscript.parameters['intf_FO_1_to_LEAF_3']) + '''
            no shut
            switchport
            switchport mode trunk
            
            ''')
            time.sleep(45)
        except Exception as error:
                log.debug("Unable to configure - Encountered Exception " + str(error))
                self.errored('Exception occurred while configuring on FO_1', goto=['common_cleanup'])
                
    @aetest.test
    def VERIFY_IXIA_TRAFFIC_AFTER_MOVE(self, testscript):
        """ IXIA_CONFIGURATION subsection: Verify IXIA Traffic """

        # Do not perform configurations if skip_tgen_config flag is set
        if not testscript.parameters['script_flags']['skip_tgen_config']:

            time.sleep(20)

            if ixLib.verify_traffic(15) == 0:
                log.debug("Traffic Verification failed")
                self.failed("Traffic Verification failed", goto=['cleanup'])
            else:
                log.info("Traffic Verification Passed")
        else:
            self.passed(reason="Skipped TGEN Configurations as per request")
            
    @aetest.test        
    def Host_move_FO_BACK(self,testscript):
        
        
        FO_1=testscript.parameters['FO_1']

        
        try:
            FO_1.configure('''
            interface ''' + str(testscript.parameters['intf_FO_1_to_LEAF_3']) + '''
            shut
            switchport
            switchport mode trunk
            
            interface ''' + str(testscript.parameters['intf_FO_1_to_N7k_LEAF_3']) + '''
            no shut
            switchport
            switchport mode trunk
            
            
            
            ''')
            time.sleep(45)
        except Exception as error:
                log.debug("Unable to configure - Encountered Exception " + str(error))
                self.errored('Exception occurred while configuring on FO_1', goto=['common_cleanup'])
                
    @aetest.test
    def VERIFY_IXIA_TRAFFIC_HOST_MOVE_BACK(self, testscript):
        """ IXIA_CONFIGURATION subsection: Verify IXIA Traffic """

        # Do not perform configurations if skip_tgen_config flag is set
        if not testscript.parameters['script_flags']['skip_tgen_config']:

            time.sleep(20)

            if ixLib.verify_traffic(15) == 0:
                log.debug("Traffic Verification failed")
                self.failed("Traffic Verification failed", goto=['cleanup'])
            else:
                log.info("Traffic Verification Passed")
        else:
            self.passed(reason="Skipped TGEN Configurations as per request")
        
    @aetest.cleanup
    def cleanup(self,testscript):
        """Unconfigure qos policies"""
        LEAF_1 = testscript.parameters['LEAF-1']
        LEAF_2 = testscript.parameters['LEAF-2']
        LEAF_3 = testscript.parameters['LEAF-3']
        FO_1=testscript.parameters['FO_1']
        LEAF_1 = testscript.parameters['LEAF-1']
        LEAF_2 = testscript.parameters['LEAF-2']
        forwardingSysDict = testscript.parameters['forwardingSysDict']
        l2_vlan_id = testscript.parameters['N7K_LEAF_1_dict']['Vlan_data']['l2_vlan_start']
        l2_vlan_ipv4_start= testscript.parameters['N7K_LEAF_1_dict']['Vlan_data']['l2_vlan_ipv4_start']
        l2_vlan_ipv4_mask= testscript.parameters['N7K_LEAF_1_dict']['Vlan_data']['l2_vlan_ipv4_mask']
        l2_vlan_ipv6_start= testscript.parameters['N7K_LEAF_1_dict']['Vlan_data']['l2_vlan_ipv6_start']
        l2_vlan_ipv6_mask= testscript.parameters['N7K_LEAF_1_dict']['Vlan_data']['l2_vlan_ipv6_mask']
        l2_hsrp_ipv4_vip_start= testscript.parameters['N7K_LEAF_1_dict']['Vlan_data']['hsrp_ipv4_vip_start']
        l2_hsrp_ipv6_vip_start= testscript.parameters['N7K_LEAF_1_dict']['Vlan_data']['hsrp_ipv6_vip_start']
        
        post_test_process_dict = {
            'dut_list'                       : [LEAF_1, LEAF_2, LEAF_3],
            'cc_check'                  : 1,
            'cores_check'               : 1,
            'logs_check'                : 0,
            'fnl_flag'                  : 0,
            'exclude_log_check_pattern' : 'ERROR_VLANS_SUSPENDED|ERROR_VLANS_REMOVED',
            }
        try:
            FO_1.configure('''
            interface ''' + str(testscript.parameters['intf_FO_1_to_LEAF_3']) + '''
            shut
            switchport
            switchport mode trunk
            
            interface ''' + str(testscript.parameters['intf_FO_1_to_N7k_LEAF_3']) + '''
            no shut
            switchport
            switchport mode trunk
            ''')
            time.sleep(30)
            ###Remove Pre-migration step from both N7k leafs
            device_handle=connect_to_vdc(testscript.parameters['xbow1'], 'leaf1')
            if device_handle==False:
                log.info("failed to switchto correct vdc")
                self.failed("failed to switchto correct vdc",goto=['common_cleanup'])
            else:
                total_ip_count = int(forwardingSysDict['VLAN_PER_VRF_count']) * int(forwardingSysDict['VRF_count'])
                l2_ipv4s = increment_prefix_network(ip.IPv4Interface(str(l2_vlan_ipv4_start) + str(l2_vlan_ipv4_mask)),total_ip_count)
                l2_ipv6s = increment_prefix_network(ip.IPv6Interface(str(l2_vlan_ipv6_start) + str(l2_vlan_ipv6_mask)),total_ip_count)
                ip_index=0
                for i in range(0,len(l2_ipv4s)):
                    device_handle.configure('''int vlan ''' + str(l2_vlan_id) + '''\n
                                     hsrp version 2
                                     hsrp ''' + str(l2_vlan_id) + ''' ipv4
                                     no mac-address 0000.000a.aaaa
                                     ''')
                    l2_vlan_id += 1
            l2_vlan_id = testscript.parameters['N7K_LEAF_1_dict']['Vlan_data']['l2_vlan_start']        
            device_handle=connect_to_vdc(testscript.parameters['xbow2'], 'leaf2')
            if device_handle==False:
                log.info("failed to switchto correct vdc")
                self.failed("failed to switchto correct vdc",goto=['common_cleanup'])
            else:
                total_ip_count = int(forwardingSysDict['VLAN_PER_VRF_count']) * int(forwardingSysDict['VRF_count'])
                l2_ipv4s = increment_prefix_network(ip.IPv4Interface(str(l2_vlan_ipv4_start) + str(l2_vlan_ipv4_mask)),total_ip_count)
                l2_ipv6s = increment_prefix_network(ip.IPv6Interface(str(l2_vlan_ipv6_start) + str(l2_vlan_ipv6_mask)),total_ip_count)
                ip_index=0
                for i in range(0,len(l2_ipv4s)):
                    device_handle.configure('''int vlan ''' + str(l2_vlan_id) + '''\n
                                     hsrp version 2
                                     hsrp ''' + str(l2_vlan_id) + ''' ipv4
                                     no mac-address 0000.000a.aaaa
                                     ''')
                    l2_vlan_id += 1
            status = infraVerify.postTestVerification(post_test_process_dict)
            if status['status'] == 0:
                self.failed(reason=status['logs'])
            else:
                self.passed(reason=status['logs'])
        except Exception as error:
            log.debug("Unable to unconfigure class map or policy map-Encountered exception " + str(error))
            self.errored('Exception occurred while unconfiguring qos on LEAF1', goto=['next_tc'])
            
# *****************************************************************************************************************************#
class Reload_pre_Host_move_ipv4(aetest.Testcase):
    """ Host_move_ipv4 """

    
    # =============================================================================================================================#        
    
    @aetest.test
    def SVI_ON_LEAF2(self, testscript):
        """Shut down the vpc leg on Leaf2 to force all traffic to Leaf1"""
        
        LEAF_1 = testscript.parameters['LEAF-1']
        LEAF_2 = testscript.parameters['LEAF-2']
        forwardingSysDict = testscript.parameters['forwardingSysDict']
        l2_vlan_id = testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vlan_start']
        l2_vlan_ipv4_sec_start= testscript.parameters['LEAF_2_dict']['VNI_data']['l2_vlan_ipv4_sec_start']
        l2_vlan_ipv4_mask= testscript.parameters['LEAF_2_dict']['VNI_data']['l2_vlan_ipv4_mask']
        #+ str(testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vlan_ipv4_mask'])
        
        try:
            total_ip_count = int(forwardingSysDict['VLAN_PER_VRF_count']) * int(forwardingSysDict['VRF_count'])
            l2_ipv4s = increment_prefix_network(ip.IPv4Interface(str(l2_vlan_ipv4_sec_start) + str(l2_vlan_ipv4_mask)),total_ip_count)
            ip_index=0
            for i in range(0,len(l2_ipv4s)):
                LEAF_2.configure('''int vlan ''' + str(l2_vlan_id) + '''\n
                                 ip address ''' + str(l2_ipv4s[ip_index]) + ''' secondary use-bia
                                 ''')
                l2_vlan_id += 1
                ip_index += 1
                
            
            
        except Exception as error:
            log.debug("Unable to configure - Encountered Exception " + str(error))
            self.errored('Exception occurred while configuring secondary ipv4 address on LEAF-2', goto=['cleanup'])
            
    # =============================================================================================================================#        
    
    @aetest.test
    def SVI_ON_LEAF1(self, testscript):
        """Shut down the vpc leg on Leaf2 to force all traffic to Leaf1"""
        
        LEAF_1 = testscript.parameters['LEAF-1']
        LEAF_2 = testscript.parameters['LEAF-2']
        forwardingSysDict = testscript.parameters['forwardingSysDict']
        l2_vlan_id = testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vlan_start']
        l2_vlan_ipv4_sec_start= testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vlan_ipv4_sec_start']
        l2_vlan_ipv4_mask= testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vlan_ipv4_mask']
        
        try:
            total_ip_count = int(forwardingSysDict['VLAN_PER_VRF_count']) * int(forwardingSysDict['VRF_count'])
            l2_ipv4s = increment_prefix_network(ip.IPv4Interface(str(l2_vlan_ipv4_sec_start) + str(l2_vlan_ipv4_mask)),total_ip_count)
            ip_index=0
            for i in range(0,len(l2_ipv4s)):
                LEAF_1.configure('''int vlan ''' + str(l2_vlan_id) + '''\n
                                 ip address ''' + str(l2_ipv4s[ip_index]) + ''' secondary use-bia
                                 ''')
                l2_vlan_id += 1
                ip_index += 1
                
            
            
        except Exception as error:
            log.debug("Unable to configure - Encountered Exception " + str(error))
            self.errored('Exception occurred while configuring secondary ipv4 address on LEAF-1', goto=['cleanup'])
            
     # =============================================================================================================================#        
    @aetest.test
    def Add_external_int(self, testscript):
        """Shut down the vpc leg on Leaf2 to force all traffic to Leaf1"""
        
        LEAF_1 = testscript.parameters['LEAF-1']
        LEAF_2 = testscript.parameters['LEAF-2']
        
        try:
            testscript.parameters['LEAF-2'].configure('''
                  interface po ''' + str(testscript.parameters['LEAF_1_dict']['VPC_data']['double_vpc_po_1']) + '''
                  port-type external
                  ''')
            
            testscript.parameters['LEAF-1'].configure('''
                  interface po ''' + str(testscript.parameters['LEAF_1_dict']['VPC_data']['double_vpc_po_1']) + '''
                  port-type external
                  ''')    
            
            
        except Exception as error:
            log.debug("Unable to configure - Encountered Exception " + str(error))
            self.errored('Exception occurred while configuring external on LEAF-1 and LEAF-2', goto=['cleanup'])
            
     # =============================================================================================================================#    
    @aetest.test
    def Pre_migration_hsrp(self,testscript):
        LEAF_1 = testscript.parameters['LEAF-1']
        LEAF_2 = testscript.parameters['LEAF-2']
        forwardingSysDict = testscript.parameters['forwardingSysDict']
        l2_vlan_id = testscript.parameters['N7K_LEAF_1_dict']['Vlan_data']['l2_vlan_start']
        l2_vlan_ipv4_start= testscript.parameters['N7K_LEAF_1_dict']['Vlan_data']['l2_vlan_ipv4_start']
        l2_vlan_ipv4_mask= testscript.parameters['N7K_LEAF_1_dict']['Vlan_data']['l2_vlan_ipv4_mask']
        l2_vlan_ipv6_start= testscript.parameters['N7K_LEAF_1_dict']['Vlan_data']['l2_vlan_ipv6_start']
        l2_vlan_ipv6_mask= testscript.parameters['N7K_LEAF_1_dict']['Vlan_data']['l2_vlan_ipv6_mask']
        l2_hsrp_ipv4_vip_start= testscript.parameters['N7K_LEAF_1_dict']['Vlan_data']['hsrp_ipv4_vip_start']
        l2_hsrp_ipv6_vip_start= testscript.parameters['N7K_LEAF_1_dict']['Vlan_data']['hsrp_ipv6_vip_start']
        
        try:
            device_handle=connect_to_vdc(testscript.parameters['xbow1'], 'leaf1')
            if device_handle==False:
                log.info("failed to switchto correct vdc")
                self.failed("failed to switchto correct vdc",goto=['common_cleanup'])
            else:
                total_ip_count = int(forwardingSysDict['VLAN_PER_VRF_count']) * int(forwardingSysDict['VRF_count'])
                l2_ipv4s = increment_prefix_network(ip.IPv4Interface(str(l2_vlan_ipv4_start) + str(l2_vlan_ipv4_mask)),total_ip_count)
                l2_ipv6s = increment_prefix_network(ip.IPv6Interface(str(l2_vlan_ipv6_start) + str(l2_vlan_ipv6_mask)),total_ip_count)
                ip_index=0
                for i in range(0,len(l2_ipv4s)):
                    device_handle.configure('''int vlan ''' + str(l2_vlan_id) + '''\n
                                     hsrp version 2
                                     hsrp ''' + str(l2_vlan_id) + ''' ipv4
                                     mac-address 0000.000a.aaaa
                                     ''')
                    l2_vlan_id += 1
            l2_vlan_id = testscript.parameters['N7K_LEAF_1_dict']['Vlan_data']['l2_vlan_start']        
            device_handle=connect_to_vdc(testscript.parameters['xbow2'], 'leaf2')
            if device_handle==False:
                log.info("failed to switchto correct vdc")
                self.failed("failed to switchto correct vdc",goto=['common_cleanup'])
            else:
                total_ip_count = int(forwardingSysDict['VLAN_PER_VRF_count']) * int(forwardingSysDict['VRF_count'])
                l2_ipv4s = increment_prefix_network(ip.IPv4Interface(str(l2_vlan_ipv4_start) + str(l2_vlan_ipv4_mask)),total_ip_count)
                l2_ipv6s = increment_prefix_network(ip.IPv6Interface(str(l2_vlan_ipv6_start) + str(l2_vlan_ipv6_mask)),total_ip_count)
                ip_index=0
                for i in range(0,len(l2_ipv4s)):
                    device_handle.configure('''int vlan ''' + str(l2_vlan_id) + '''\n
                                     hsrp version 2
                                     hsrp ''' + str(l2_vlan_id) + ''' ipv4
                                     mac-address 0000.000a.aaaa
                                     ''')
                    l2_vlan_id += 1
                    


        except Exception as error:
                log.debug("Unable to configure - Encountered Exception " + str(error))
                self.errored('Exception occurred while configuring on N7k leaf1', goto=['common_cleanup'])
                
    @aetest.test        
    def configure_FO(self,testscript):
        
        FO_1_vlanConfiguration = ""
        FO_1=testscript.parameters['FO_1']

        l3_vrf_count_iter = 0
        l2_vlan_id = testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vlan_start']
        l3_vlan_id = testscript.parameters['LEAF_1_dict']['VNI_data']['l3_vlan_start']

        while l3_vrf_count_iter < testscript.parameters['forwardingSysDict']['VRF_count']:
            l2_vlan_count_iter = 0
            FO_1_vlanConfiguration += '''vlan ''' + str(l3_vlan_id) + '''\n
                                            state active\n
                                            no shut\n'''
            while l2_vlan_count_iter < testscript.parameters['forwardingSysDict']['VLAN_PER_VRF_count']:
                # Incrementing L2 VLAN Iteration counters
                FO_1_vlanConfiguration += '''vlan ''' + str(l2_vlan_id) + '''\n
                                                state active\n
                                                no shut\n'''
                l2_vlan_count_iter += 1
                l2_vlan_id += 1
            # Incrementing L3 VRF Iteration counters
            l3_vrf_count_iter += 1
            l3_vlan_id += 1

        try:
            FO_1.configure(
                str(FO_1_vlanConfiguration) + '''
        
        
            
            interface ''' + str(testscript.parameters['intf_FO_1_to_N7k_LEAF_3']) + '''
            no shut
            switchport
            switchport mode trunk
            
            interface ''' + str(testscript.parameters['intf_FO_1_to_LEAF_3']) + '''
            shut
            switchport
            switchport mode trunk
            
            interface ''' + str(testscript.parameters['intf_FO_1_to_IXIA']) + '''
            no shut
            switchport
            switchport mode trunk
            
            ''')
        except Exception as error:
                log.debug("Unable to configure - Encountered Exception " + str(error))
                self.errored('Exception occurred while configuring on FO_1', goto=['common_cleanup'])
   
#     @aetest.test
#     def CONFIGURE_UCAST_L3_IXIA_TRAFFIC(self, testscript):
#         """ IXIA_CONFIGURATION subsection: Configure MCAST Traffic Item """
# 
#         # Do not perform configurations if skip_tgen_config flag is set
#         if not testscript.parameters['script_flags']['skip_tgen_config']:
# 
#             IX_TP1 = testscript.parameters['IX_TP1']
#             IX_TP2 = testscript.parameters['IX_TP2']
#             P1_dict = testscript.parameters['LEAF_2_TGEN_dict']
#             P2_dict = testscript.parameters['LEAF_3_TGEN_dict']
# 
#             UCAST_v4_dict = {   'src_hndl'  : IX_TP1['port_handle'],
#                                 'dst_hndl'  : IX_TP2['port_handle'],
#                                 'ip_dscp'   : P1_dict['ip_dscp'],
#                                 'circuit'   : 'raw',
#                                 'TI_name'   : "UCAST_L3",
#                                 'rate_pps'  : "9000",
#                                 'bi_dir'    : 1,
#                                 'frame_size': '128',
#                                 'src_mac'   : P1_dict['mac'],
#                                 'dst_mac'   : '0000.000a.aaaa',
#                                 'srcmac_step': '00:00:00:00:00:00',
#                                 'dstmac_step': '00:00:00:00:00:00',
#                                 'srcmac_count': '1',
#                                 'dstmac_count': '1',
#                                 'vlan_id'    : P1_dict['vlan_id'],
#                                 'vlanid_step': '0',
#                                 'vlanid_count': '1',
#                                 'vlan_user_priority': P1_dict['vlan_user_priority'],
#                                 'ip_src_addrs' : P1_dict['v4_addr'],
#                                 'ip_dst_addrs' : P1_dict['L3_dst_addr'],
#                                 'ip_src_step' : '0.0.0.0',
#                                 'ip_dst_step' : '0.0.0.0',
# #                                'ip_step'    : P1_dict['v4_addr_step'],
#                           }
# 
# #            UCAST_v6_dict = {   'src_hndl'  : IX_TP1['ipv6_handle'],
# #                                'dst_hndl'  : IX_TP2['ipv6_handle'],
# #                                'circuit'   : 'ipv6',
# #                                'TI_name'   : "UCAST_V6",
# #                                'rate_pps'  : "1000",
# #                                'bi_dir'    : 1
# #                          }
# 
#             UCAST_v4_TI = ixLib.configure_ixia_l3_traffic_item(UCAST_v4_dict)
# #            UCAST_v6_TI = ixLib.configure_ixia_traffic_item(UCAST_v6_dict)
# 
# #            if UCAST_v4_TI == 0 or UCAST_v6_TI == 0:
# #                log.debug("Configuring UCast TI failed")
# #                self.errored("Configuring UCast TI failed", goto=['cleanup'])
#                 
#             if UCAST_v4_TI == 0:
#                 log.debug("Configuring UCast TI failed")
#                 self.errored("Configuring UCast TI failed", goto=['cleanup'])
#             else:
#                 global stream_id
#                 stream_id = UCAST_v4_TI
# 
#         else:
#             self.passed(reason="Skipped TGEN Configurations as per request")
            
    # @aetest.test
    # def CONFIGURE_BCAST_IXIA_TRAFFIC(self, testscript):
    #     """ IXIA_CONFIGURATION subsection: Configure MCAST Traffic Item """
    # 
    #     # Do not perform configurations if skip_tgen_config flag is set
    #     if not testscript.parameters['script_flags']['skip_tgen_config']:
    # 
    #         IX_TP1 = testscript.parameters['IX_TP1']
    #         IX_TP2 = testscript.parameters['IX_TP2']
    #         P1_dict = testscript.parameters['LEAF_2_TGEN_dict']
    #         P2_dict = testscript.parameters['LEAF_3_TGEN_dict']
    #         BCAST_v4_dict = {
    #                             'src_hndl'      : IX_TP1['port_handle'],
    #                             'dst_hndl'      : IX_TP2['port_handle'],
    #                             'TI_name'       : "BCAST_V4",
    #                             'frame_size'    : "70",
    #                             'rate_pps'      : "1000",
    #                             'src_mac'       : P1_dict['mac'],
    #                             'srcmac_step'   : "00:00:00:00:00:01",
    #                             'srcmac_count'  : '1',
    #                             'vlan_id'       : P1_dict['vlan_id'],
    #                             'vlanid_step'   : "1",
    #                             'vlanid_count'  : "1",
    #                             'ip_src_addrs'  : P1_dict['v4_addr'],
    #                             'ip_step'       : "0.0.1.0",
    #                       }
    # 
    #         BCAST_v4_TI = ixLib.configure_ixia_BCAST_traffic_item(BCAST_v4_dict)
    # 
    #         if BCAST_v4_TI == 0:
    #             log.debug("Configuring BCast TI failed")
    #             self.errored("Configuring BCast TI failed", goto=['cleanup'])
    # 
    #     else:
    #         self.passed(reason="Skipped TGEN Configurations as per request")
    # =============================================================================================================================#
    @aetest.test
    def APPLY_TRAFFIC(self):
        """ IXIA_CONFIGURATION subsection: Verify IXIA Traffic """

        # # Apply IXIA Traffic
        # if ixLib.apply_traffic() == 1:
        #     log.info("Applying IXIA TI Passed")
        # else:
        #     self.errored("Applying IXIA TI failed", goto=['cleanup'])
            
        # =============================================================================================================================#
    #--------------------------------------------------------------------------------#
        # Start traffic from ixia
        log.info("--- Populating the statistics --- \n")
        log.info("---- Running Traffic --- \n")
        log.info("Starting Traffic")

        traffic_run_status  = ixLib.start_traffic()

        if traffic_run_status is not 1:
           log.info("Failed: To start traffic")
           return 0
        else:
            log.info("\nTraffic started successfully\n")

        time.sleep(30)
    
    # Stop Traffic from ixia
        log.info("--- Stopping Traffic ---- \n")
        log.info("Stopping Traffic")
        traffic_run_status = ixLib.stop_traffic()
        
        if traffic_run_status is not 1:
           log.info("Failed: To Stop traffic")
           return 0
        else:
            log.info("\nTraffic Stopped successfully\n")
            time.sleep(10)    
    
    @aetest.test
    def VERIFY_IXIA_TRAFFIC(self, testscript):
        """ IXIA_CONFIGURATION subsection: Verify IXIA Traffic """

        # Do not perform configurations if skip_tgen_config flag is set
        if not testscript.parameters['script_flags']['skip_tgen_config']:

            time.sleep(20)

            if ixLib.verify_traffic(2) == 0:
                log.debug("Traffic Verification failed")
                self.failed("Traffic Verification failed", goto=['cleanup'])
            else:
                log.info("Traffic Verification Passed")
        else:
            self.passed(reason="Skipped TGEN Configurations as per request")
    # =============================================================================================================================#
    
    @aetest.test
    def TRIGGER_verify_device_reload(self, testscript):
        """ HA_VERIFICATION subsection: Device ASCII Reload """

        LEAF_1 = testscript.parameters['LEAF-1']
        LEAF_2 = testscript.parameters['LEAF-2']

        LEAF_1.execute("copy r s")
        LEAF_2.execute("copy r s")

        # Perform Device Reload
        dialog = Dialog([
            Statement(pattern=r'.*Do you wish to proceed anyway.*',
                      action='sendline(y)',
                      loop_continue=True,
                      continue_timer=True)
        ])
        result= LEAF_1.reload(reload_command="reload", timeout=800,prompt_recovery=False, dialog=dialog)
        #result = infraTrig.switchASCIIreload(LEAF_1)
        log.info("result= " + str(result))
        if result:
            log.info("ASCII Reload completed Successfully")
            log.info("Waiging for 240 sec for the topology to come UP")
            time.sleep(240)
        else:
            log.debug("ASCII Reload Failed")
            self.failed("ASCII Reload Failed", goto=['common_cleanup'])
        
        result2= LEAF_2.reload(reload_command="reload", timeout=800,prompt_recovery=False, dialog=dialog)
        #result = infraTrig.switchASCIIreload(LEAF_1)
        log.info("result= " + str(result2))
        if result2:
            log.info("ASCII Reload completed Successfully on Vxlan Leaf2")
            log.info("Waiging for 240 sec for the topology to come UP")
            time.sleep(240)
        else:
            log.debug("ASCII Reload Failed on Vxlan Leaf2")
            self.failed("ASCII Reload Failed", goto=['common_cleanup'])
    
    @aetest.test
    def VERIFY_IXIA_TRAFFIC_AFTER_ASCII_RELOAD(self, testscript):
        """ IXIA_CONFIGURATION subsection: Verify IXIA Traffic """

        # Do not perform configurations if skip_tgen_config flag is set
        if not testscript.parameters['script_flags']['skip_tgen_config']:

            time.sleep(20)

            if ixLib.verify_traffic(2) == 0:
                log.debug("Traffic Verification failed")
                self.failed("Traffic Verification failed", goto=['cleanup'])
            else:
                log.info("Traffic Verification Passed")
        else:
            self.passed(reason="Skipped TGEN Configurations as per request")
     # =============================================================================================================================#        
    @aetest.test
    def Clear_ARP_Table_on_Vxlan_BLs(self, testscript):
        """Shut down the vpc leg on Leaf2 to force all traffic to Leaf1"""
        
        LEAF_1 = testscript.parameters['LEAF-1']
        LEAF_2 = testscript.parameters['LEAF-2']
        
        try:
            for i in range(1, testscript.parameters['forwardingSysDict']['VRF_count']+1):
                testscript.parameters['LEAF-2'].execute('''
                      clear ip arp vrf ''' + str(testscript.parameters['forwardingSysDict']['VRF_string']) + str(i) + ''' force-delete''')
            
            for i in range(1, testscript.parameters['forwardingSysDict']['VRF_count']+1):
                testscript.parameters['LEAF-1'].execute('''
                      clear ip arp vrf ''' + str(testscript.parameters['forwardingSysDict']['VRF_string']) + str(i) + ''' force-delete''')    
            
            
        except Exception as error:
            log.debug("Unable to configure - Encountered Exception " + str(error))
            self.errored('Exception occurred while clearing arp cache on LEAF-1 and LEAF-2', goto=['cleanup'])
            
    @aetest.test        
    def Host_move_FO(self,testscript):
        
        
        FO_1=testscript.parameters['FO_1']

        
        try:
            FO_1.configure('''
            interface ''' + str(testscript.parameters['intf_FO_1_to_N7k_LEAF_3']) + '''
            shut
            switchport
            switchport mode trunk
            
            interface ''' + str(testscript.parameters['intf_FO_1_to_LEAF_3']) + '''
            no shut
            switchport
            switchport mode trunk
            
            ''')
            time.sleep(45)
        except Exception as error:
                log.debug("Unable to configure - Encountered Exception " + str(error))
                self.errored('Exception occurred while configuring on FO_1', goto=['common_cleanup'])
                
    @aetest.test
    def VERIFY_IXIA_TRAFFIC_AFTER_MOVE(self, testscript):
        """ IXIA_CONFIGURATION subsection: Verify IXIA Traffic """

        # Do not perform configurations if skip_tgen_config flag is set
        if not testscript.parameters['script_flags']['skip_tgen_config']:

            time.sleep(20)

            if ixLib.verify_traffic(15) == 0:
                log.debug("Traffic Verification failed")
                self.failed("Traffic Verification failed", goto=['cleanup'])
            else:
                log.info("Traffic Verification Passed")
        else:
            self.passed(reason="Skipped TGEN Configurations as per request")
            
    @aetest.test        
    def Host_move_FO_BACK(self,testscript):
        
        
        FO_1=testscript.parameters['FO_1']

        
        try:
            FO_1.configure('''
            interface ''' + str(testscript.parameters['intf_FO_1_to_LEAF_3']) + '''
            shut
            switchport
            switchport mode trunk
            
            interface ''' + str(testscript.parameters['intf_FO_1_to_N7k_LEAF_3']) + '''
            no shut
            switchport
            switchport mode trunk
            
            
            
            ''')
            time.sleep(45)
        except Exception as error:
                log.debug("Unable to configure - Encountered Exception " + str(error))
                self.errored('Exception occurred while configuring on FO_1', goto=['common_cleanup'])
                
    @aetest.test
    def VERIFY_IXIA_TRAFFIC_HOST_MOVE_BACK(self, testscript):
        """ IXIA_CONFIGURATION subsection: Verify IXIA Traffic """

        # Do not perform configurations if skip_tgen_config flag is set
        if not testscript.parameters['script_flags']['skip_tgen_config']:

            time.sleep(20)

            if ixLib.verify_traffic(15) == 0:
                log.debug("Traffic Verification failed")
                self.failed("Traffic Verification failed", goto=['cleanup'])
            else:
                log.info("Traffic Verification Passed")
        else:
            self.passed(reason="Skipped TGEN Configurations as per request")
        
    @aetest.cleanup
    def cleanup(self,testscript):
        """Unconfigure qos policies"""
        LEAF_1 = testscript.parameters['LEAF-1']
        LEAF_2 = testscript.parameters['LEAF-2']
        LEAF_3 = testscript.parameters['LEAF-3']
        FO_1=testscript.parameters['FO_1']
        LEAF_1 = testscript.parameters['LEAF-1']
        LEAF_2 = testscript.parameters['LEAF-2']
        forwardingSysDict = testscript.parameters['forwardingSysDict']
        l2_vlan_id = testscript.parameters['N7K_LEAF_1_dict']['Vlan_data']['l2_vlan_start']
        l2_vlan_ipv4_start= testscript.parameters['N7K_LEAF_1_dict']['Vlan_data']['l2_vlan_ipv4_start']
        l2_vlan_ipv4_mask= testscript.parameters['N7K_LEAF_1_dict']['Vlan_data']['l2_vlan_ipv4_mask']
        l2_vlan_ipv6_start= testscript.parameters['N7K_LEAF_1_dict']['Vlan_data']['l2_vlan_ipv6_start']
        l2_vlan_ipv6_mask= testscript.parameters['N7K_LEAF_1_dict']['Vlan_data']['l2_vlan_ipv6_mask']
        l2_hsrp_ipv4_vip_start= testscript.parameters['N7K_LEAF_1_dict']['Vlan_data']['hsrp_ipv4_vip_start']
        l2_hsrp_ipv6_vip_start= testscript.parameters['N7K_LEAF_1_dict']['Vlan_data']['hsrp_ipv6_vip_start']
        
        post_test_process_dict = {
            'dut_list'                       : [LEAF_1, LEAF_2, LEAF_3],
            'cc_check'                  : 1,
            'cores_check'               : 1,
            'logs_check'                : 0,
            'fnl_flag'                  : 0,
            'exclude_log_check_pattern' : 'ERROR_VLANS_SUSPENDED|ERROR_VLANS_REMOVED',
            }
        try:
            UCAST_v4_dict = {
                            'mode'        : 'remove',
                            'stream_id'   : stream_id,
                      }
            if (ixLib.delete_traffic_item(UCAST_v4_dict))==0:
                log.debug("Traffic Remove failed")
                self.failed("Traffic Remove failed", goto=['next_tc'])
            else:
                log.info("Traffic Verification Passed")
                
            Bcast_dict = {
                            'mode'        : 'remove',
                            'stream_id'   : stream_id_2,
                      }
            if (ixLib.delete_traffic_item(BCAST_dict))==0:
                log.debug("Traffic Remove failed")
                self.failed("Traffic Remove failed")
            else:
                log.info("Traffic Deletion Passed")
            time.sleep(30)    
            FO_1.configure('''
            interface ''' + str(testscript.parameters['intf_FO_1_to_LEAF_3']) + '''
            shut
            switchport
            switchport mode trunk
            
            interface ''' + str(testscript.parameters['intf_FO_1_to_N7k_LEAF_3']) + '''
            no shut
            switchport
            switchport mode trunk
            ''')
            time.sleep(30)
            ###Remove Pre-migration step from both N7k leafs
            device_handle=connect_to_vdc(testscript.parameters['xbow1'], 'leaf1')
            if device_handle==False:
                log.info("failed to switchto correct vdc")
                self.failed("failed to switchto correct vdc",goto=['common_cleanup'])
            else:
                total_ip_count = int(forwardingSysDict['VLAN_PER_VRF_count']) * int(forwardingSysDict['VRF_count'])
                l2_ipv4s = increment_prefix_network(ip.IPv4Interface(str(l2_vlan_ipv4_start) + str(l2_vlan_ipv4_mask)),total_ip_count)
                l2_ipv6s = increment_prefix_network(ip.IPv6Interface(str(l2_vlan_ipv6_start) + str(l2_vlan_ipv6_mask)),total_ip_count)
                ip_index=0
                for i in range(0,len(l2_ipv4s)):
                    device_handle.configure('''int vlan ''' + str(l2_vlan_id) + '''\n
                                     hsrp version 2
                                     hsrp ''' + str(l2_vlan_id) + ''' ipv4
                                     no mac-address 0000.000a.aaaa
                                     ''')
                    l2_vlan_id += 1
            l2_vlan_id = testscript.parameters['N7K_LEAF_1_dict']['Vlan_data']['l2_vlan_start']        
            device_handle=connect_to_vdc(testscript.parameters['xbow2'], 'leaf2')
            if device_handle==False:
                log.info("failed to switchto correct vdc")
                self.failed("failed to switchto correct vdc",goto=['common_cleanup'])
            else:
                total_ip_count = int(forwardingSysDict['VLAN_PER_VRF_count']) * int(forwardingSysDict['VRF_count'])
                l2_ipv4s = increment_prefix_network(ip.IPv4Interface(str(l2_vlan_ipv4_start) + str(l2_vlan_ipv4_mask)),total_ip_count)
                l2_ipv6s = increment_prefix_network(ip.IPv6Interface(str(l2_vlan_ipv6_start) + str(l2_vlan_ipv6_mask)),total_ip_count)
                ip_index=0
                for i in range(0,len(l2_ipv4s)):
                    device_handle.configure('''int vlan ''' + str(l2_vlan_id) + '''\n
                                     hsrp version 2
                                     hsrp ''' + str(l2_vlan_id) + ''' ipv4
                                     no mac-address 0000.000a.aaaa
                                     ''')
                    l2_vlan_id += 1
            status = infraVerify.postTestVerification(post_test_process_dict)
            if status['status'] == 0:
                self.failed(reason=status['logs'])
            else:
                self.passed(reason=status['logs'])
        except Exception as error:
            log.debug("Unable to unconfigure class map or policy map-Encountered exception " + str(error))
            self.errored('Exception occurred while unconfiguring qos on LEAF1', goto=['next_tc']) 
    # =============================================================================================================================#
    
# *****************************************************************************************************************************#
class Host_move_ipv6(aetest.Testcase):
    """ Host_move_ipv4 """

    
    # =============================================================================================================================#        
    @aetest.test
    def SVI_ON_LEAF2(self, testscript):
        """Shut down the vpc leg on Leaf2 to force all traffic to Leaf1"""
        
        LEAF_1 = testscript.parameters['LEAF-1']
        LEAF_2 = testscript.parameters['LEAF-2']
        forwardingSysDict = testscript.parameters['forwardingSysDict']
        l2_vlan_id = testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vlan_start']
        l2_vlan_ipv6_sec_start= testscript.parameters['LEAF_2_dict']['VNI_data']['l2_vlan_ipv6_sec_start']
        l2_vlan_ipv6_mask= testscript.parameters['LEAF_2_dict']['VNI_data']['l2_vlan_ipv6_mask']
        #+ str(testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vlan_ipv4_mask'])
        
        try:
            total_ip_count = int(forwardingSysDict['VLAN_PER_VRF_count']) * int(forwardingSysDict['VRF_count'])
            l2_ipv6s = increment_prefix_network(ip.IPv6Interface(str(l2_vlan_ipv6_sec_start) + str(l2_vlan_ipv6_mask)),total_ip_count)
            ip_index=0
            for i in range(0,len(l2_ipv6s)):
                LEAF_2.configure('''int vlan ''' + str(l2_vlan_id) + '''\n
                                 ipv6 address ''' + str(l2_ipv6s[ip_index]) + ''' use-bia
                                 ''')
                l2_vlan_id += 1
                ip_index += 1
                
            
            
        except Exception as error:
            log.debug("Unable to configure - Encountered Exception " + str(error))
            self.errored('Exception occurred while configuring secondary ipv6 address on LEAF-2', goto=['cleanup'])
            
    # =============================================================================================================================#        
    
    @aetest.test
    def SVI_ON_LEAF1(self, testscript):
        """Shut down the vpc leg on Leaf2 to force all traffic to Leaf1"""
        
        LEAF_1 = testscript.parameters['LEAF-1']
        LEAF_2 = testscript.parameters['LEAF-2']
        forwardingSysDict = testscript.parameters['forwardingSysDict']
        l2_vlan_id = testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vlan_start']
        l2_vlan_ipv6_sec_start= testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vlan_ipv6_sec_start']
        l2_vlan_ipv6_mask= testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vlan_ipv6_mask']
        
        try:
            total_ip_count = int(forwardingSysDict['VLAN_PER_VRF_count']) * int(forwardingSysDict['VRF_count'])
            l2_ipv6s = increment_prefix_network(ip.IPv6Interface(str(l2_vlan_ipv6_sec_start) + str(l2_vlan_ipv6_mask)),total_ip_count)
            ip_index=0
            for i in range(0,len(l2_ipv6s)):
                LEAF_1.configure('''int vlan ''' + str(l2_vlan_id) + '''\n
                                 ipv6 address ''' + str(l2_ipv6s[ip_index]) + ''' use-bia
                                 ''')
                l2_vlan_id += 1
                ip_index += 1
                
            
            
        except Exception as error:
            log.debug("Unable to configure - Encountered Exception " + str(error))
            self.errored('Exception occurred while configuring secondary ipv6 address on LEAF-1', goto=['cleanup'])
            
     # =============================================================================================================================#        
    @aetest.test
    def Add_external_int(self, testscript):
        """Shut down the vpc leg on Leaf2 to force all traffic to Leaf1"""
        
        LEAF_1 = testscript.parameters['LEAF-1']
        LEAF_2 = testscript.parameters['LEAF-2']
        
        try:
            testscript.parameters['LEAF-2'].configure('''
                  interface po ''' + str(testscript.parameters['LEAF_1_dict']['VPC_data']['double_vpc_po_1']) + '''
                  port-type external
                  ''')
            
            testscript.parameters['LEAF-1'].configure('''
                  interface po ''' + str(testscript.parameters['LEAF_1_dict']['VPC_data']['double_vpc_po_1']) + '''
                  port-type external
                  ''')    
            
            
        except Exception as error:
            log.debug("Unable to configure - Encountered Exception " + str(error))
            self.errored('Exception occurred while configuring external on LEAF-1 and LEAF-2', goto=['cleanup'])
            
     # =============================================================================================================================#    
    @aetest.test
    def Pre_migration_hsrp(self,testscript):
        LEAF_1 = testscript.parameters['LEAF-1']
        LEAF_2 = testscript.parameters['LEAF-2']
        forwardingSysDict = testscript.parameters['forwardingSysDict']
        l2_vlan_id = testscript.parameters['N7K_LEAF_1_dict']['Vlan_data']['l2_vlan_start']
        l2_vlan_ipv4_start= testscript.parameters['N7K_LEAF_1_dict']['Vlan_data']['l2_vlan_ipv4_start']
        l2_vlan_ipv4_mask= testscript.parameters['N7K_LEAF_1_dict']['Vlan_data']['l2_vlan_ipv4_mask']
        l2_vlan_ipv6_start= testscript.parameters['N7K_LEAF_1_dict']['Vlan_data']['l2_vlan_ipv6_start']
        l2_vlan_ipv6_mask= testscript.parameters['N7K_LEAF_1_dict']['Vlan_data']['l2_vlan_ipv6_mask']
        l2_hsrp_ipv4_vip_start= testscript.parameters['N7K_LEAF_1_dict']['Vlan_data']['hsrp_ipv4_vip_start']
        l2_hsrp_ipv6_vip_start= testscript.parameters['N7K_LEAF_1_dict']['Vlan_data']['hsrp_ipv6_vip_start']
        
        try:
            device_handle=connect_to_vdc(testscript.parameters['xbow1'], 'leaf1')
            if device_handle==False:
                log.info("failed to switchto correct vdc")
                self.failed("failed to switchto correct vdc",goto=['common_cleanup'])
            else:
                total_ip_count = int(forwardingSysDict['VLAN_PER_VRF_count']) * int(forwardingSysDict['VRF_count'])
                l2_ipv4s = increment_prefix_network(ip.IPv4Interface(str(l2_vlan_ipv4_start) + str(l2_vlan_ipv4_mask)),total_ip_count)
                l2_ipv6s = increment_prefix_network(ip.IPv6Interface(str(l2_vlan_ipv6_start) + str(l2_vlan_ipv6_mask)),total_ip_count)
                ip_index=0
                for i in range(0,len(l2_ipv4s)):
                    device_handle.configure('''int vlan ''' + str(l2_vlan_id) + '''\n
                                     hsrp version 2
                                     hsrp ''' + str(l2_vlan_id) + ''' ipv4
                                     no mac-address 0000.000a.aaaa
                                     hsrp ''' + str(l2_vlan_id) + ''' ipv6
                                     mac-address 0000.000a.aaaa
                                     ''')
                    l2_vlan_id += 1
            l2_vlan_id = testscript.parameters['N7K_LEAF_1_dict']['Vlan_data']['l2_vlan_start']        
            device_handle=connect_to_vdc(testscript.parameters['xbow2'], 'leaf2')
            if device_handle==False:
                log.info("failed to switchto correct vdc")
                self.failed("failed to switchto correct vdc",goto=['common_cleanup'])
            else:
                total_ip_count = int(forwardingSysDict['VLAN_PER_VRF_count']) * int(forwardingSysDict['VRF_count'])
                l2_ipv4s = increment_prefix_network(ip.IPv4Interface(str(l2_vlan_ipv4_start) + str(l2_vlan_ipv4_mask)),total_ip_count)
                l2_ipv6s = increment_prefix_network(ip.IPv6Interface(str(l2_vlan_ipv6_start) + str(l2_vlan_ipv6_mask)),total_ip_count)
                ip_index=0
                for i in range(0,len(l2_ipv4s)):
                    device_handle.configure('''int vlan ''' + str(l2_vlan_id) + '''\n
                                     hsrp version 2
                                     hsrp ''' + str(l2_vlan_id) + ''' ipv4
                                     no mac-address 0000.000a.aaaa
                                     hsrp ''' + str(l2_vlan_id) + ''' ipv6
                                     mac-address 0000.000a.aaaa
                                     ''')
                    l2_vlan_id += 1
                    


        except Exception as error:
                log.debug("Unable to configure - Encountered Exception " + str(error))
                self.errored('Exception occurred while configuring on N7k leaf1', goto=['common_cleanup'])
                
    @aetest.test        
    def configure_FO(self,testscript):
        
        FO_1_vlanConfiguration = ""
        FO_1=testscript.parameters['FO_1']

        l3_vrf_count_iter = 0
        l2_vlan_id = testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vlan_start']
        l3_vlan_id = testscript.parameters['LEAF_1_dict']['VNI_data']['l3_vlan_start']

        while l3_vrf_count_iter < testscript.parameters['forwardingSysDict']['VRF_count']:
            l2_vlan_count_iter = 0
            FO_1_vlanConfiguration += '''vlan ''' + str(l3_vlan_id) + '''\n
                                            state active\n
                                            no shut\n'''
            while l2_vlan_count_iter < testscript.parameters['forwardingSysDict']['VLAN_PER_VRF_count']:
                # Incrementing L2 VLAN Iteration counters
                FO_1_vlanConfiguration += '''vlan ''' + str(l2_vlan_id) + '''\n
                                                state active\n
                                                no shut\n'''
                l2_vlan_count_iter += 1
                l2_vlan_id += 1
            # Incrementing L3 VRF Iteration counters
            l3_vrf_count_iter += 1
            l3_vlan_id += 1

        try:
            FO_1.configure(
                str(FO_1_vlanConfiguration) + '''
        
        
            
            interface ''' + str(testscript.parameters['intf_FO_1_to_N7k_LEAF_3']) + '''
            no shut
            switchport
            switchport mode trunk
            
            interface ''' + str(testscript.parameters['intf_FO_1_to_LEAF_3']) + '''
            shut
            switchport
            switchport mode trunk
            
            interface ''' + str(testscript.parameters['intf_FO_1_to_IXIA']) + '''
            no shut
            switchport
            switchport mode trunk
            
            ''')
        except Exception as error:
                log.debug("Unable to configure - Encountered Exception " + str(error))
                self.errored('Exception occurred while configuring on FO_1', goto=['common_cleanup'])
   
    @aetest.test
    def CONFIGURE_UCAST_L3_IXIA_TRAFFIC(self, testscript):
        """ IXIA_CONFIGURATION subsection: Configure MCAST Traffic Item """

        # Do not perform configurations if skip_tgen_config flag is set
        if not testscript.parameters['script_flags']['skip_tgen_config']:

            IX_TP1 = testscript.parameters['IX_TP1']
            IX_TP2 = testscript.parameters['IX_TP2']
            P1_dict = testscript.parameters['LEAF_2_TGEN_dict']
            P2_dict = testscript.parameters['LEAF_3_TGEN_dict']

            #UCAST_v4_dict = {   'src_hndl'  : IX_TP1['port_handle'],
            #                    'dst_hndl'  : IX_TP2['port_handle'],
            #                    'ip_dscp'   : P1_dict['ip_dscp'],
            #                    'circuit'   : 'raw',
            #                    'TI_name'   : "UCAST_L3",
            #                    'rate_pps'  : "9000",
            #                    'bi_dir'    : 1,
            #                    'frame_size': '128',
            #                    'src_mac'   : P1_dict['mac'],
            #                    'dst_mac'   : '0000.000a.aaaa',
            #                    'srcmac_step': '00:00:00:00:00:00',
            #                    'dstmac_step': '00:00:00:00:00:00',
            #                    'srcmac_count': '1',
            #                    'dstmac_count': '1',
            #                    'vlan_id'    : P1_dict['vlan_id'],
            #                    'vlanid_step': '0',
            #                    'vlanid_count': '1',
            #                    'vlan_user_priority': P1_dict['vlan_user_priority'],
            #                    'ip_src_addrs' : P1_dict['v4_addr'],
            #                    'ip_dst_addrs' : P1_dict['L3_ipv6_dst_addr'],
            #                    'ip_src_step' : '0.0.0.0',
            #                    'ip_dst_step' : '0.0.0.0',
#           #                     'ip_step'    : P1_dict['v4_addr_step'],
            #              }
            
#             UCAST_v6_dict = {   'src_hndl'  : IX_TP1['port_handle'],
#                                 'dst_hndl'  : IX_TP2['port_handle'],
#                                 'ip_dscp'   : P1_dict['ip_dscp'],
#                                 'circuit'   : 'raw',
#                                 'TI_name'   : "UCAST_L3",
#                                 'rate_pps'  : "9000",
#                                 'bi_dir'    : 1,
#                                 'frame_size': '128',
#                                 'src_mac'   : P1_dict['mac'],
#                                 'dst_mac'   : '0000.000a.aaaa',
#                                 'srcmac_step': '00:00:00:00:00:00',
#                                 'dstmac_step': '00:00:00:00:00:00',
#                                 'srcmac_count': '1',
#                                 'dstmac_count': '1',
#                                 'vlan_id'    : P1_dict['vlan_id'],
#                                 'vlanid_step': '0',
#                                 'vlanid_count': '1',
#                                 'vlan_user_priority': P1_dict['vlan_user_priority'],
#                                 'ip_src_addrs' : P1_dict['v4_addr'],
#                                 'ip_dst_addrs' : P1_dict['L3_dst_addr'],
#                                 'ip_src_step' : '0.0.0.0',
#                                 'ip_dst_step' : '0.0.0.0',
# #                                'ip_step'    : P1_dict['v4_addr_step'],
#                           }

            UCAST_v6_dict = {   'src_hndl'  : IX_TP1['ipv6_handle'],
                                'dst_hndl'  : IX_TP2['ipv6_handle'],
                                'circuit'   : 'ipv6',
                                'TI_name'   : "UCAST_V6",
                                'rate_pps'  : "10000",
                                'bi_dir'    : 1,
                                'vlan_user_priority': P1_dict['vlan_user_priority'],
                                'ip_src_addrs' : P1_dict['v6_addr'],
                                'ip_dst_addrs' : P1_dict['L3_ipv6_dst_addr'],
                          }

#            UCAST_v4_TI = ixLib.configure_ixia_l3_traffic_item(UCAST_v4_dict)
            UCAST_v6_TI = ixLib.configure_ixia_traffic_item(UCAST_v6_dict)

#            if UCAST_v4_TI == 0 or UCAST_v6_TI == 0:
#                log.debug("Configuring UCast TI failed")
#                self.errored("Configuring UCast TI failed", goto=['cleanup'])
                
            if UCAST_v6_TI == 0:
                log.debug("Configuring UCast TI failed")
                self.errored("Configuring UCast TI failed", goto=['cleanup'])
            else:
                global stream_id
                stream_id = UCAST_v6_TI

        else:
            self.passed(reason="Skipped TGEN Configurations as per request")
            
    # =============================================================================================================================#
    @aetest.test
    def APPLY_TRAFFIC(self):
        """ IXIA_CONFIGURATION subsection: Verify IXIA Traffic """

        # Apply IXIA Traffic
        if ixLib.apply_traffic() == 1:
            log.info("Applying IXIA TI Passed")
        else:
            self.errored("Applying IXIA TI failed", goto=['cleanup'])
            
    
        #--------------------------------------------------------------------------------#
        # Start traffic from ixia
        log.info("--- Populating the statistics --- \n")
        log.info("---- Running Traffic --- \n")
        log.info("Starting Traffic")

        traffic_run_status  = ixLib.start_traffic()

        if traffic_run_status is not 1:
           log.info("Failed: To start traffic")
           return 0
        else:
            log.info("\nTraffic started successfully\n")

        time.sleep(30)
    
    # Stop Traffic from ixia
        log.info("--- Stopping Traffic ---- \n")
        log.info("Stopping Traffic")
        traffic_run_status = ixLib.stop_traffic()
        
        if traffic_run_status is not 1:
           log.info("Failed: To Stop traffic")
           return 0
        else:
            log.info("\nTraffic Stopped successfully\n")
            time.sleep(10)    
        # =============================================================================================================================#
    @aetest.test
    def VERIFY_IXIA_TRAFFIC(self, testscript):
        """ IXIA_CONFIGURATION subsection: Verify IXIA Traffic """

        # Do not perform configurations if skip_tgen_config flag is set
        if not testscript.parameters['script_flags']['skip_tgen_config']:

            time.sleep(20)

            if ixLib.verify_traffic(2) == 0:
                log.debug("Traffic Verification failed")
                self.failed("Traffic Verification failed", goto=['cleanup'])
            else:
                log.info("Traffic Verification Passed")
        else:
            self.passed(reason="Skipped TGEN Configurations as per request")
    
    
    # =============================================================================================================================#
    @aetest.test
    def TRIGGER_verify_ND_process_restart(self, testscript):
        """ ICMPv6_PROCESS_KILL_VERIFICATION subsection: Verify killing process ICMPV6 """

        LEAF_1 = testscript.parameters['LEAF-1']
        LEAF_2 = testscript.parameters['LEAF-2']

        if infraTrig.verifyProcessRestart(LEAF_1,"icmpv6"):
            log.info("Successfully restarted process icmpv6 on Leaf1")
        else:
            log.debug("Failed to restarted process icmpv6 on Leaf1")
            self.failed("Failed to restarted process icmpv6 on Leaf1", goto=['cleanup'])
            
        if infraTrig.verifyProcessRestart(LEAF_2,"icmpv6"):
            log.info("Successfully restarted process icmpv6 on Leaf2")
        else:
            log.debug("Failed to restarted process icmpv6 on Leaf2")
            self.failed("Failed to restarted process icmpv6 on Leaf2", goto=['cleanup'])

        time.sleep(120)
    
        # =============================================================================================================================#
    @aetest.test
    def VERIFY_IXIA_TRAFFIC_AFTER_ICMPV6_RESTART(self, testscript):
        """ IXIA_CONFIGURATION subsection: Verify IXIA Traffic """

        # Do not perform configurations if skip_tgen_config flag is set
        if not testscript.parameters['script_flags']['skip_tgen_config']:

            time.sleep(20)

            if ixLib.verify_traffic(2) == 0:
                log.debug("Traffic Verification failed")
                self.failed("Traffic Verification failed", goto=['cleanup'])
            else:
                log.info("Traffic Verification Passed")
        else:
            self.passed(reason="Skipped TGEN Configurations as per request")
    
     # =============================================================================================================================#        
    @aetest.test
    def Clear_ND_Table_on_Vxlan_BLs(self, testscript):
        """Shut down the vpc leg on Leaf2 to force all traffic to Leaf1"""
        
        LEAF_1 = testscript.parameters['LEAF-1']
        LEAF_2 = testscript.parameters['LEAF-2']
        
        try:
            for i in range(1, testscript.parameters['forwardingSysDict']['VRF_count']+1):
                testscript.parameters['LEAF-2'].execute('''
                      clear ipv6 neighbor vrf ''' + str(testscript.parameters['forwardingSysDict']['VRF_string']) + str(i) + ''' force-delete''')
            
            for i in range(1, testscript.parameters['forwardingSysDict']['VRF_count']+1):
                testscript.parameters['LEAF-1'].execute('''
                      clear ipv6 neighbor vrf ''' + str(testscript.parameters['forwardingSysDict']['VRF_string']) + str(i) + ''' force-delete''')    
            
            
        except Exception as error:
            log.debug("Unable to configure - Encountered Exception " + str(error))
            self.errored('Exception occurred while clearing arp cache on LEAF-1 and LEAF-2', goto=['cleanup'])
            
    @aetest.test        
    def Host_move_FO(self,testscript):
        
        
        FO_1=testscript.parameters['FO_1']

        
        try:
            FO_1.configure('''
            interface ''' + str(testscript.parameters['intf_FO_1_to_N7k_LEAF_3']) + '''
            shut
            switchport
            switchport mode trunk
            
            interface ''' + str(testscript.parameters['intf_FO_1_to_LEAF_3']) + '''
            no shut
            switchport
            switchport mode trunk
            
            ''')
            time.sleep(45)
        except Exception as error:
                log.debug("Unable to configure - Encountered Exception " + str(error))
                self.errored('Exception occurred while configuring on FO_1', goto=['common_cleanup'])
                
    @aetest.test
    def VERIFY_IXIA_TRAFFIC_AFTER_MOVE(self, testscript):
        """ IXIA_CONFIGURATION subsection: Verify IXIA Traffic """

        # Do not perform configurations if skip_tgen_config flag is set
        if not testscript.parameters['script_flags']['skip_tgen_config']:

            time.sleep(20)

            if ixLib.verify_traffic(2) == 0:
                log.debug("Traffic Verification failed")
                self.failed("Traffic Verification failed", goto=['cleanup'])
            else:
                log.info("Traffic Verification Passed")
        else:
            self.passed(reason="Skipped TGEN Configurations as per request")
            
    @aetest.test        
    def Host_move_FO_BACK(self,testscript):
        
        
        FO_1=testscript.parameters['FO_1']

        
        try:
            FO_1.configure('''
            interface ''' + str(testscript.parameters['intf_FO_1_to_LEAF_3']) + '''
            shut
            switchport
            switchport mode trunk
            
            interface ''' + str(testscript.parameters['intf_FO_1_to_N7k_LEAF_3']) + '''
            no shut
            switchport
            switchport mode trunk
            
            
            
            ''')
            time.sleep(45)
        except Exception as error:
                log.debug("Unable to configure - Encountered Exception " + str(error))
                self.errored('Exception occurred while configuring on FO_1', goto=['common_cleanup'])
                
    @aetest.test
    def VERIFY_IXIA_TRAFFIC_HOST_MOVE_BACK(self, testscript):
        """ IXIA_CONFIGURATION subsection: Verify IXIA Traffic """

        # Do not perform configurations if skip_tgen_config flag is set
        if not testscript.parameters['script_flags']['skip_tgen_config']:

            time.sleep(20)

            if ixLib.verify_traffic(15) == 0:
                log.debug("Traffic Verification failed")
                self.failed("Traffic Verification failed", goto=['cleanup'])
            else:
                log.info("Traffic Verification Passed")
        else:
            self.passed(reason="Skipped TGEN Configurations as per request")
        
    @aetest.cleanup
    def cleanup(self,testscript):
        """Unconfigure qos policies"""
        LEAF_1 = testscript.parameters['LEAF-1']
        LEAF_2 = testscript.parameters['LEAF-2']
        LEAF_3 = testscript.parameters['LEAF-3']
        FO_1=testscript.parameters['FO_1']
        forwardingSysDict = testscript.parameters['forwardingSysDict']
        l2_vlan_id = testscript.parameters['N7K_LEAF_1_dict']['Vlan_data']['l2_vlan_start']
        l2_vlan_ipv4_start= testscript.parameters['N7K_LEAF_1_dict']['Vlan_data']['l2_vlan_ipv4_start']
        l2_vlan_ipv4_mask= testscript.parameters['N7K_LEAF_1_dict']['Vlan_data']['l2_vlan_ipv4_mask']
        l2_vlan_ipv6_start= testscript.parameters['N7K_LEAF_1_dict']['Vlan_data']['l2_vlan_ipv6_start']
        l2_vlan_ipv6_mask= testscript.parameters['N7K_LEAF_1_dict']['Vlan_data']['l2_vlan_ipv6_mask']
        l2_hsrp_ipv4_vip_start= testscript.parameters['N7K_LEAF_1_dict']['Vlan_data']['hsrp_ipv4_vip_start']
        l2_hsrp_ipv6_vip_start= testscript.parameters['N7K_LEAF_1_dict']['Vlan_data']['hsrp_ipv6_vip_start']
        post_test_process_dict = {
            'dut_list'                       : [LEAF_1, LEAF_2, LEAF_3],
            'cc_check'                  : 1,
            'cores_check'               : 1,
            'logs_check'                : 1,
            'fnl_flag'                  : 0,
            'exclude_log_check_pattern' : 'ERROR_VLANS_SUSPENDED|ERROR_VLANS_REMOVED',
            }
        try:
            UCAST_v6_dict = {
                            'mode'        : 'remove',
                            'stream_id'   : stream_id,
                      }
            if (ixLib.delete_traffic_item(UCAST_v6_dict))==0:
                log.debug("Traffic Remove failed")
                self.failed("Traffic Remove failed")
            else:
                log.info("Traffic Deletion Passed")
                
            
            FO_1.configure('''
            interface ''' + str(testscript.parameters['intf_FO_1_to_LEAF_3']) + '''
            shut
            switchport
            switchport mode trunk
            
            interface ''' + str(testscript.parameters['intf_FO_1_to_N7k_LEAF_3']) + '''
            no shut
            switchport
            switchport mode trunk
            ''')
            time.sleep(30)
            ###Remove Pre-migration step from both N7k leafs
            device_handle=connect_to_vdc(testscript.parameters['xbow1'], 'leaf1')
            if device_handle==False:
                log.info("failed to switchto correct vdc")
                self.failed("failed to switchto correct vdc",goto=['common_cleanup'])
            else:
                total_ip_count = int(forwardingSysDict['VLAN_PER_VRF_count']) * int(forwardingSysDict['VRF_count'])
                l2_ipv4s = increment_prefix_network(ip.IPv4Interface(str(l2_vlan_ipv4_start) + str(l2_vlan_ipv4_mask)),total_ip_count)
                l2_ipv6s = increment_prefix_network(ip.IPv6Interface(str(l2_vlan_ipv6_start) + str(l2_vlan_ipv6_mask)),total_ip_count)
                ip_index=0
                for i in range(0,len(l2_ipv4s)):
                    device_handle.configure('''int vlan ''' + str(l2_vlan_id) + '''\n
                                     hsrp version 2
                                     hsrp ''' + str(l2_vlan_id) + ''' ipv6
                                     no mac-address 0000.000a.aaaa
                                     ''')
                    l2_vlan_id += 1
            l2_vlan_id = testscript.parameters['N7K_LEAF_1_dict']['Vlan_data']['l2_vlan_start']        
            device_handle=connect_to_vdc(testscript.parameters['xbow2'], 'leaf2')
            if device_handle==False:
                log.info("failed to switchto correct vdc")
                self.failed("failed to switchto correct vdc",goto=['common_cleanup'])
            else:
                total_ip_count = int(forwardingSysDict['VLAN_PER_VRF_count']) * int(forwardingSysDict['VRF_count'])
                l2_ipv4s = increment_prefix_network(ip.IPv4Interface(str(l2_vlan_ipv4_start) + str(l2_vlan_ipv4_mask)),total_ip_count)
                l2_ipv6s = increment_prefix_network(ip.IPv6Interface(str(l2_vlan_ipv6_start) + str(l2_vlan_ipv6_mask)),total_ip_count)
                ip_index=0
                for i in range(0,len(l2_ipv4s)):
                    device_handle.configure('''int vlan ''' + str(l2_vlan_id) + '''\n
                                     hsrp version 2
                                     hsrp ''' + str(l2_vlan_id) + ''' ipv6
                                     no mac-address 0000.000a.aaaa
                                     ''')
                    l2_vlan_id += 1
            status = infraVerify.postTestVerification(post_test_process_dict)
            if status['status'] == 0:
                self.failed(reason=status['logs'])
            else:
                self.passed(reason=status['logs'])
        except Exception as error:
            log.debug("Unable to unconfigure class map or policy map-Encountered exception " + str(error))
            self.errored('Exception occurred while unconfiguring qos on LEAF1', goto=['next_tc'])          
    # =============================================================================================================================#



#
#########################################################################
#####                       COMMON CLEANUP SECTION                    ###
#########################################################################
##
### Remove the BASE CONFIGURATION that was applied earlier in the 
### common cleanup section, clean the left over
#
class common_cleanup(aetest.CommonCleanup):
   """ Common Cleanup for Sample Test """

   @aetest.subsection
   def restore_terminal_width(self, BL1):
       """ Common Cleanup subsection """
       log.info(banner("script common cleanup starts here"))

   @aetest.subsection
   def restore_terminal_width(self, BL2):
       """ Common Cleanup subsection """
       log.info(banner("script common cleanup starts here"))

   @aetest.subsection
   def restore_terminal_width(self, CORE):
       """ Common Cleanup subsection """
       log.info(banner("script common cleanup starts here"))

   @aetest.subsection
   def restore_terminal_width(self, SPINE):
       """ Common Cleanup subsection """
       log.info(banner("script common cleanup starts here"))


if __name__ == '__main__':  # pragma: no cover
    aetest.main()
