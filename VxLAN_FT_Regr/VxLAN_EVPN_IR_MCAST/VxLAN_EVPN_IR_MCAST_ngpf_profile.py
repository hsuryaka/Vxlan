#!/usr/bin/python
# -*- coding: utf-8 -*-

###################################################################
# connection_example.py : A test script example which includes:
#     common_seup section - device connection, configuration
#     Testcase section with testcase setup and teardown (cleanup)
#     subtestcase section with subtestcase setup and teardown (cleanup)
#     common_cleanup section - device cleanup
# The purpose of this sample test script is to show how to connect the
# devices/UUT in the common setup section. How to run few simple testcases
# (testcase might contain subtests).And finally, recover the test units in
# the common cleanup section. Script also provides an example on how to invoke
# TCL interpreter to call existing TCL functionalities.
###################################################################

#* Author: Danish Thomas
#* Feature Info : https://wiki.cisco.com/pages/viewpage.action?pageId=120270136
#*
#*   This feature is used to enable Vxlan P2P functionality on Trident based N9K & N3K(N9K mode only) TORs
#*   This will enable tunnelling of all control frames (CDP, LLDP, LACP, STP, etc) across Vxlan cloud.
#*
#* ------------- V X L A N  TEST  T O P O L O G Y------------
#*
#*
#*
#*                      Evpn-Vtep-Simulator
#*                           ( Spirent )
#*                               |
#*                               |
#*                               |
#*                               |
#*                           +---+---+
#*                           | spine1|
#*      examp                     |
#*                           +---+---+
#*                               |               |
#*        +--------------+-------+---------+
#*        |              |                 |
#*    +-------+      +-------+         +-------+
#*    |       |      |       |         |       |
#*    | leaf1 |<---->| leaf2 |         | leaf3 |
#*    |       |      |       |         |       |
#*    +---+---+      +---+---+         +-------+
#*        |  \          |   |           |
#*        |   \         |   |           |
#*        |    \        |   |           |
#*        |     \       |   |          Orph3
#*      Orp11    \      |   Orp21    Spirent
#*     Spirent    \     |   Spirent
#*                 vpc x 2
#*                   \ |
#*                    \|
#*            +-------------+
#*            |  switch 1   |
#*            +-----+-------+
#*                  |
#*                  |
#*                  |
#*               Spirent
#*
#*
#*
#*
#*
#*************************************************************************

from ats import aetest
from vxlan_all_lib_no_sth import *
from ixia_vxlan_lib import *
from re import *
import logging
import ipaddress as ip
from pyats.log.utils import banner

# ------------------------------------------------------
# Import and initialize IXIA specific libraries
# ------------------------------------------------------
import ixiaPyats_lib
ixLib = ixiaPyats_lib.ixiaPyats_lib()

# ------------------------------------------------------
# Import and initialize INFRA specific libraries
# ------------------------------------------------------
import infra_lib
infraVerify = infra_lib.infraVerify()
infraTrigger = infra_lib.infraTrigger()
infraEORTrigger = infra_lib.infraEORTrigger()

log = logging.getLogger(__name__)
log.setLevel(logging.DEBUG)

def pretty(d, indent=0):
    for key, value in d.items():
        log.info('\t' * indent + str(key))
        if isinstance(value, dict):
            pretty(value, indent+1)
        else:
            log.info('\t' * (indent+1) + str(value))

parameters = {
    'vlan_start'            : 1001,
    'vni'                   : 101001,
    'vlan_vni_scale'        : 32,
    'routed_vlan'           : 101,
    'routed_vni'            : 90101,
    'routing_vlan_scale'    : 4,
    'ir_mode'               : 'mix',
    'ipv4_add'              : '5.0.0.1',
    'ipv6_add'              : '5::1',
    'mcast_group'           : '225.5.0.1',
    'mcast_group_scale'     : 4,
    'vpc_po'                : '101',
    'bgp_as_number'         : '65001',
    'pim_rp_address'        : '1.1.1.100',
    'leaf1_mg0_ip1'         : '10.127.62.235',
    'leaf2_mg0_ip1'         : '10.127.62.232',
    'anycastgw'             : '0000.2222.3333',
    'stp_mode'              : 'mst',
    'test_mac1'             : '00a7.0001.0001',
    'rate'                  : '200000',
    'tolerence'             : 3000
    }

###################################################################
###                  COMMON SETUP SECTION                       ###
###################################################################

# noinspection PyGlobalUndefined
class common_setup(aetest.CommonSetup):

    """ Common Setup for Sample Test """

    @aetest.subsection
    def testbed_init(self, testbed, job_file_params):
        """ common setup subsection: connecting devices """

        global vxlan_evpn_config, spine_loop1_add, igp,linktype,pps,rate,tol,tgen,tgen_port_handle_list,leaf1,leaf2,leaf3,leaf4,sw1,activePo1,leaf8,sw2,spine1,spine2,port_handle1,\
        port_handle2,mac_scale2,tgn1_spine1_intf1,port_handle_spine1,pim_type,vlan_vni_scale,routing_vlan_scale,spine1_tgn1_intf1,uutList,vlan_range,\
        uut_list,vpc_uut_list,spine_uut_list,leaf_uut_list,l3_uut_list,vpc_uut_list,sw_uut_list,tgn1_sw1_intf1,vpc_uut_list,sa_leaf_uut_list,\
        port_handle_sw1,leaf_scale,leaf_emulation_spirent,leaf_tgn_ip,sw_feature_list,traffic_to_be_tested_on_number_of_vlans,port_handle_leaf5,\
        tunnel_vlan_start,tunnel_vlan_scale,tgn1_intf_list,tgn1_leaf3_intf1,tgn1_leaf5_intf1,tgn1_leaf1_intf1,port_handle_leaf1_1,port_handle_leaf1_1,mcast_group_scale,\
        labserver_ip,tgn_ip,port_handle_leaf2_1,port_handle_leaf2_1,port_handle_leaf1_2,tgn1_leaf3_intf2,tgn1_leaf1_intf2,tgn1_leaf4_intf1,tgn1_leaf2_intf1,\
        vpc_port_handle_list,xcon_po_port_handle_list,xcon_orphan_port_handle_list,port_handle_list,vxlan_traffic_test_vlan1,vxlan_traffic_test_vlan2,\
        main_uut_list,labserver_ip,tgn1_sw2_intf1,sw1_tgn1_intf1,leaf1_tgn1_intf1,leaf2_tgn1_intf1,map_scale,l3_uut_list,port_handle_list_arp_supp_removed,\
        leaf3_tgn1_intf1,leaf4_tgn1_intf1,leaf5_tgn1_intf1,tgn1_spine1_intf1,orphan_handle_list,leaf5,vpc_leaf_uut_list,tgn_rate_routed_vsg,\
        port_handle_sw1,port_handle_leaf3,port_handle_leaf1,port_handle_leaf2,port_handle_leaf3,port_handle_leaf4,port_handle_leaf5,\
        leaf1_spine1_intf1,leaf2_spine1_intf1,leaf3_spine1_intf1,spine1_leaf1_intf1,spine1_leaf2_intf1,spine1_leaf3_intf1,\
        leaf1_sw1_intf1,leaf2_sw1_intf1,sw1_leaf1_intf1,sw1_leaf2_intf1,leaf1_tgn1_intf1,leaf1_tgn2_intf1,leaf3_tgn1_intf1,tgn1_sw1_intf1_md,tgn1_leaf1_intf1_md,tgn1_leaf3_intf1_md,\
        leaf1_Mgmt0_ipv4,leaf2_Mgmt0_ipv4,leaf1_leaf2_intf1,leaf2_leaf1_intf1,bgp_as_number,mcast_group_scale,ir_mode,ipv4_add,leaf1_interfaces, leaf2_interfaces,leaf3_interfaces,\
        ipv6_add,routing_vlan_scale,routed_vni,routed_vlan,vni,vlan_start,vlan_vni_scale,rate,pps,tolerence,mcast_group,rate_list_arp_supp_removed,rate_list, post_test_process_dict

        leaf1               = testbed.devices['leaf1']
        leaf2               = testbed.devices['leaf2']
        leaf3               = testbed.devices['leaf3']
        sw1                 = testbed.devices['sw1']
        spine1              = testbed.devices['spine1']

        uut_list            = [leaf1,leaf2,leaf3,sw1,spine1]
        l3_uut_list         = [leaf1,leaf2,leaf3,spine1]
        sw_uut_list         = [sw1]
        vpc_uut_list        = [leaf1,leaf2]
        vpc_leaf_uut_list   = [leaf1,leaf2]
        spine_uut_list      = [spine1]
        leaf_uut_list       = [leaf1,leaf2,leaf3]
        sa_leaf_uut_list    = [leaf3]
        leaf1_Mgmt0_ipv4    = testbed.devices['leaf1'].interfaces['leaf1_Mgmt0'].ipv4
        leaf2_Mgmt0_ipv4    = testbed.devices['leaf2'].interfaces['leaf2_Mgmt0'].ipv4

        # Setting up the Post Test Check Parameters
        post_test_process_dict = {}
        post_test_process_dict = job_file_params['postTestArgs']
        if 'eor_flag' in job_file_params['postTestArgs'].keys():
            post_test_process_dict['eor_flag'] = job_file_params['postTestArgs']['eor_flag']
        else:
            post_test_process_dict['eor_flag'] = 0
        post_test_process_dict['dut_list'] = leaf_uut_list
        log.info("===> Post Test Check Process Parameters")
        log.info(post_test_process_dict)

        # Setting up the Underlay Parameters
        linktype            = job_file_params['underlayOptions']['linktype']
        pim_type            = job_file_params['underlayOptions']['pim_type']
        igp                 = job_file_params['underlayOptions']['igp']
        log.info("===> Underlay Parameters")
        log.info("igp ===> " + str(igp))
        log.info("linktype ===> "+str(linktype))
        log.info("pim_type ===> " + str(pim_type))

        # Flags to control pre-clean, config and EOR Trigger test-cases
        resn = 'Skipped by the user via job file \n' + str(pretty(job_file_params['pre_test_params'], 3))
        log.info(resn)
        if not job_file_params['pre_test_params']['clean_before_config']:
            aetest.skip.affix(section=common_setup.precleanup, reason = resn)
        if not job_file_params['pre_test_params']['config_bringup']:
            aetest.skip.affix(section=common_setup.base_configs, reason = resn)
            aetest.skip.affix(section=common_setup.gwandLoopconfigs, reason = resn)
            aetest.skip.affix(section=common_setup.l3_port_configs, reason = resn)
            aetest.skip.affix(section=common_setup.igp_configure, reason = resn)
            aetest.skip.affix(section=common_setup.pim_configs, reason = resn)
            aetest.skip.affix(section=common_setup.access_port_configure, reason = resn)
            aetest.skip.affix(section=common_setup.vpc_bringup, reason = resn)
            aetest.skip.affix(section=common_setup.mctsviconfigure, reason = resn)
            aetest.skip.affix(section=common_setup.bgp_configurations, reason = resn)
        if not job_file_params['pre_test_params']['eor_triggers']:
            aetest.skip.affix(section=TC047_vxlan_vpc_leaf1_LC_reload, reason = resn)
            aetest.skip.affix(section=TC048_vxlan_vpc_leaf2_LC_reload, reason = resn)
            aetest.skip.affix(section=TC049_vxlan_vpc_leaf1_FM_all_reload, reason = resn)
            aetest.skip.affix(section=TC050_vxlan_vpc_leaf2_FM_all_reload, reason = resn)
            aetest.skip.affix(section=TC051_vxlan_vpc_leaf1_SC_all_reload, reason = resn)
            aetest.skip.affix(section=TC052_vxlan_vpc_leaf2_SC_all_reload, reason = resn)
            aetest.skip.affix(section=TC053_vxlan_vpc_leaf1_SSO, reason = resn)
            aetest.skip.affix(section=TC054_vxlan_vpc_leaf2_SSO, reason = resn)

        # Retrieve the Interfaces
        spine1_leaf1_intf1  = testbed.devices['spine1'].interfaces['spine1_leaf1_intf1'].intf
        spine1_leaf2_intf1  = testbed.devices['spine1'].interfaces['spine1_leaf2_intf1'].intf
        spine1_leaf3_intf1  = testbed.devices['spine1'].interfaces['spine1_leaf3_intf1'].intf
        leaf1_tgn1_intf1    = testbed.devices['leaf1'].interfaces['leaf1_tgn1_intf1'].intf
        leaf3_tgn1_intf1    = testbed.devices['leaf3'].interfaces['leaf3_tgn1_intf1'].intf
        sw1_tgn1_intf1      = testbed.devices['sw1'].interfaces['sw1_tgn1_intf1'].intf
        tgn1_sw1_intf1      = testbed.devices['tgn1'].interfaces['tgn1_sw1_intf1'].intf
        tgn1_leaf1_intf1    = testbed.devices['tgn1'].interfaces['tgn1_leaf1_intf1'].intf
        tgn1_leaf3_intf1    = testbed.devices['tgn1'].interfaces['tgn1_leaf3_intf1'].intf
        tgn1_sw1_intf1_md   = testbed.devices['tgn1'].interfaces['tgn1_sw1_intf1'].type
        tgn1_leaf1_intf1_md = testbed.devices['tgn1'].interfaces['tgn1_leaf1_intf1'].type
        tgn1_leaf3_intf1_md = testbed.devices['tgn1'].interfaces['tgn1_leaf3_intf1'].type

        # Retrieve the external server details
        labserver_ip        = str(testbed.devices['tgn1'].connections['labsvr'].ip)
        tgn_ip              = str(testbed.devices['tgn1'].connections['a'].ip)

        # Retrieve the TGEN Interface details
        tgn1_intf_list = []
        for key in testbed.devices['tgn1'].interfaces.keys():
            intf = testbed.devices['tgn1'].interfaces[key].intf
            tgn1_intf_list.append(intf)

        vlan_start          = parameters['vlan_start']
        vlan_vni_scale      = parameters['vlan_vni_scale']
        rate                = parameters['rate']
        tolerence           = parameters['tolerence']
        vni                 = parameters['vni']
        routed_vlan         = parameters['routed_vlan']
        routed_vni          = parameters['routed_vni']
        routing_vlan_scale  = parameters['routing_vlan_scale']
        ipv4_add            = parameters['ipv4_add']
        ipv6_add            = parameters['ipv6_add']
        mcast_group         = parameters['mcast_group']
        ir_mode             = parameters['ir_mode']
        mcast_group_scale   = parameters['mcast_group_scale']
        bgp_as_number       = parameters['bgp_as_number']
        pps                 = int(int(rate)/vlan_vni_scale)
        vlan_range          = str(vlan_start)+"-"+str(vlan_start+vlan_vni_scale-1)

        log.info('vlan_range,pps iss-----%r,%r',vlan_range,pps)

    @aetest.subsection
    def connect(self):
        #for uut in site1_bgw_uut_list:
        log.info("===> Connect")
        print("===> Connect")
        if not ConnectAll(uut_list):
            self.failed(goto=['common_cleanup'])

    # noinspection PyShadowingNames
    @aetest.subsection
    def get_interfaces(self):

        leaf1_int_list = []
        leaf2_int_list = []
        leaf3_int_list = []

        global leaf1_interfaces, leaf2_interfaces, leaf3_interfaces

        for intf in leaf1.interfaces.keys():
            if 'Eth' in leaf1.interfaces[intf].intf:
                if 'leaf_spine' in leaf1.interfaces[intf].alias:
                    leaf1_int_list.append(leaf1.interfaces[intf].intf)
        leaf1_interfaces = leaf1_int_list
        log.info("LEAF-1 Interfaces ->")
        log.info(leaf1_interfaces)

        for intf in leaf2.interfaces.keys():
            if 'Eth' in leaf2.interfaces[intf].intf:
                if 'leaf_spine' in leaf2.interfaces[intf].alias:
                    leaf2_int_list.append(leaf2.interfaces[intf].intf)
        leaf2_interfaces = leaf2_int_list
        log.info("LEAF-2 Interfaces ->")
        log.info(leaf2_interfaces)

        for intf in leaf3.interfaces.keys():
            if 'Eth' in leaf3.interfaces[intf].intf:
                if 'leaf_spine' in leaf3.interfaces[intf].alias:
                    leaf3_int_list.append(leaf3.interfaces[intf].intf)
        leaf3_interfaces = leaf3_int_list
        log.info("LEAF-3 Interfaces ->")
        log.info(leaf3_interfaces)

    #  @aetest.subsection
    # def tcam_check(self):
    #     for uut in leaf_uut_list:
    #         op = uut.execute('sh hardware access-list tcam region | incl vpc-c')
    #         if 'size =    0' in op:
    #             self.failed(goto=['common_cleanup'])
    #         op = uut.execute('sh hardware access-list tcam region | incl arp-eth')

    @aetest.subsection
    def precleanup(self):
        log.info(banner("Base cleanup"))
        result = pcall(DeviceVxlanPreCleanupAll, uut=(leaf1, leaf2, leaf3, spine1))
        if not result:
            log.info('DeviceVxlanPreCleanupAll Failed ')
            self.failed(goto=['common_cleanup'])

        result = SwVxlanPreCleanup(sw1)
        if not result:
            log.info('SwVxlanPreCleanup Failed ')
            self.failed(goto=['common_cleanup'])

    @aetest.subsection
    def base_configs(self):
        log.info(banner("Base configurations"))

        log.info(banner("Base vxlanL3NodeCommonConfig"))
        result = pcall(vxlanL3NodeCommonConfig,uut=(leaf1,leaf2,leaf3,spine1))

        if not result:
            log.info('vxlanL3NodeCommonConfig Failed ')
            self.failed(goto=['common_cleanup'])

    @aetest.subsection
    def gwandLoopconfigs(self):
        log.info(banner("Base configurations"))

        log.info(banner("Base anycastgatewayConfig"))
        pcall(anycastgatewayConfig10,uut=(leaf1,leaf2,leaf3))

        log.info(banner("Base ConfigureLoopback"))
        pcall(ConfigureLoopback,uut=(leaf1,leaf2,leaf3,spine1))

    @aetest.subsection
    def l3_port_configs(self):
        log.info(banner(" l3_port_configs configurations"))
        pcall(underlayl3bringup,uut=(leaf1,leaf2,leaf3,spine1),
            linktype=(linktype,linktype,linktype,linktype))


    @aetest.subsection
    def igp_configure(self):
        log.info(banner("igp_configure vxlanunderlayigp"))

        pcall(vxlanunderlayigp10,uut=(leaf1,leaf2,leaf3,spine1),
            linktype=(linktype,linktype,linktype,linktype),
            igp=(igp,igp,igp,igp))
            #vxlanunderlayigp10(uut,linktype,routing)

    @aetest.subsection
    def pim_configs(self):
        log.info("Configuring PIM and adding interfaces")

        if 'bidir' in pim_type:
            pcall(vxlanpimconfigureBidir,uut=(leaf1,leaf2,leaf3,spine1),
                linktype=(linktype,linktype,linktype,linktype))
        else:
            pcall(vxlanpimconfigure,uut=(leaf1,leaf2,leaf3,spine1),
                linktype=(linktype,linktype,linktype,linktype))

    # @aetest.subsection
    # def igp_verify(self):
    #     countdown(60)
    #     log.info(banner("Starting OSPF / PIM verify Section"))
    #     for uut in l3_uut_list:
    #         for feature in [igp,'pim']:
    #             test1 = leaf_protocol_check222(uut,[feature])
    #             if not test1:
    #                 log.info('Feature %r neigborship on device %r Failed ',feature,str(uut))
    #                 self.failed(goto=['common_cleanup'])

    @aetest.subsection
    def access_port_configure(self):
        log.info(banner("Configuring Ports to TGN"))
        pcall(accessPortConfigure,uut=(sw1,leaf1,leaf2,leaf3),
            vlan_range=(vlan_range,vlan_range,vlan_range,vlan_range))
        log.info(banner("Configuring Ports Channel in Switches"))
        swPoConfigure(uut=sw1,vlan_range=vlan_range)

    @aetest.subsection
    def vpc_bringup(self):
        log.info(banner("vpc configurations"))

        mct_po_number = ''
        peer_ip = ''
        src_ip = ''
        for uut in vpc_uut_list:
            mct_port_member_list = []
            for intf in [*uut.interfaces.keys()]:
                if 'mct' in uut.interfaces[intf].alias:
                    if 'mct_po' not in uut.interfaces[intf].alias:
                        intf=uut.interfaces[intf].intf
                        log.info("adding mct port-channel member %r on leaf device  %r",intf,uut)
                        mct_port_member_list.append(intf)

            for intf in [*uut.interfaces.keys()]:
                if 'mct_po' in uut.interfaces[intf].alias:
                    log.info("mct port-channel is %r on leaf device  %r",intf,uut)
                    mct_po_number = uut.interfaces[intf].intf
                    src_ip = uut.interfaces[intf].src_ip
                    peer_ip = uut.interfaces[intf].peer_ip

            try:
                leaf_vpc_global_obj1 = VPCNodeGlobal(uut,mct_po_number,str(peer_ip),
                mct_port_member_list,str(src_ip))
                leaf_vpc_global_obj1.vpc_global_conf()
            except:
                log.error('leaf_vpc_global_obj1.vpc_global_conf failed for uut %r',uut)
                self.failed(goto=['common_cleanup'])

        log.info(banner("Completed MCT Configure, Starting vPC Po"))

        for uut in vpc_uut_list:
            vpc_po_list = ['101']
            vpc_access_port_member_list_101  = []


            for intf in [*uut.interfaces.keys()]:
                if 'Po101' in uut.interfaces[intf].alias:
                    intf=uut.interfaces[intf].intf
                    log.info("adding vpc port-channel member %r on leaf device  %r",intf,uut)
                    vpc_access_port_member_list_101.append(intf)

            for vpc_po in vpc_po_list:
                if '101' in vpc_po:
                    try:
                        leaf_vpc_obj1 = VPCPoConfig(uut,vpc_po,vpc_access_port_member_list_101,
                        vlan_range,'trunk')
                        leaf_vpc_obj1.vpc_conf()
                    except:
                        log.error('leaf_vpc_obj1.vpc_conf failed for %r',uut)
                        self.failed(goto=['common_cleanup'])

    @aetest.subsection
    def mctsviconfigure(self):
        log.info(banner("Configuring mctsviconfigure"))
        pcall(mctsviConfigure,uut=tuple(vpc_uut_list),igp=(igp,igp,igp,igp))

    @aetest.subsection
    def vpc_verify(self):
        countdown(216)
        for uut in vpc_uut_list:
            op=uut.execute('show port-channel summary | incl Eth')
            op1=op.splitlines()
            for line in op1:
                if line:
                    if "(P)" not in line:
                        log.info('VPC Bringup Failed on device %r',str(uut))
                        uut.execute('show port-channel summary')
                        self.failed(goto=['common_cleanup'])

    @aetest.subsection
    def bgp_configurations(self):

        log.info(banner("BGP configurations"))

        for uut in sa_leaf_uut_list:
            uut.configure("no feature vpc")
            countdown(5)

            spine_leaf_intf_list = []
            for intf in uut.interfaces.keys():
                if 'Eth' in uut.interfaces[intf].intf:
                    if 'leaf_spine' in uut.interfaces[intf].alias:
                        intf=uut.interfaces[intf].intf
                        spine_leaf_intf_list.append(intf)

        #   log.info('lspine_leaf_intf_list for uut %r is %r',str(uut),spine_leaf_intf_list)
        spine_loop1_add = ''
        for uut in [spine1]:
            for intf in uut.interfaces.keys():
                if 'loopback1' in intf:
                    intf=uut.interfaces[intf].intf
                    spine_loop1_add=uut.interfaces[intf].ipv4

        spine_rid=str(spine_loop1_add)[:-3]
        #leafBgpbringup(uut,spine_rid):
        pcall(leafBgpbringup,uut=(leaf1,leaf2,leaf3),spine_rid=(spine_rid,spine_rid,spine_rid))

        leaf_loop1_list = []
        for uut in leaf_uut_list:
            for intf in uut.interfaces.keys():
                if 'loopback1' in intf:
                    intf=uut.interfaces[intf].intf
                    rid_leaf1=uut.interfaces[intf].ipv4
                    rid_leaf=str(rid_leaf1)[:-3]
                    leaf_loop1_list.append(rid_leaf)

        #node,rid,as_number,adv_nwk_list,neigh_list,update_src,template_name):
        spine_bgp_obj=IbgpSpineNode(spine1,spine_rid,bgp_as_number,
            ['Nil'],leaf_loop1_list,'loopback1','ibgp-vxlan')

        spine_bgp_obj.bgp_conf()

    @aetest.subsection
    def common_verify(self):
        countdown(60)

        log.info(banner("Starting Common verify Section"))
        for uut in leaf_uut_list:
            for feature in [igp,'pim','bgp']:
                test1 = leaf_protocol_check222(uut,[feature])
                if not test1:
                    log.info('Feature %r neigborship on device %r Failed ',feature,str(uut))
                    self.failed(goto=['common_cleanup'])

#######################################################################
###                          TESTCASE BLOCK                         ###
#######################################################################
#
# Place your code that implements the test steps for the test case.
# Each test may or may not contains sections:
#           setup   - test preparation
#           test    - test action
#           cleanup - test wrap-up

class TC001_vxlan_configs(aetest.Testcase):
    ###    This is de  scripting for my testcase two

    @aetest.setup
    def setup(self):
        log.info("Pass testcase setup")


    @aetest.test
    def vxlan_configs(self):
        log.info(banner("VXLAN configurations"))

        pcall(vxlanConfigure,uut=(leaf1,leaf2,leaf3,spine1),
            l2_scale =(vlan_vni_scale,vlan_vni_scale,vlan_vni_scale),
            l3_scale =(routing_vlan_scale,routing_vlan_scale,routing_vlan_scale),
            mode=(ir_mode,ir_mode,ir_mode),
            as_num=('65001','65001','65001'))

        countdown(45)

    # =============================================================================================================================#
    @aetest.cleanup
    def cleanup(self):
        """ testcase clean up """

        if post_test_process_dict['eor_flag']:
            post_test_process_dict['cc_check'] = 0
        else:
            post_test_process_dict['cc_check'] = 1

        status = infraVerify.postTestVerification(post_test_process_dict)

        if status['status'] == 0:
            self.failed(reason=status['logs'])
        else:
            self.passed(reason=status['logs'])

class TC002_Nve_Peer_State_Verify(aetest.Testcase):
    ###    This is de  scripting for my testcase two

    @aetest.setup
    def setup(self):
        log.info("Pass testcase setup")

    @aetest.test
    def check_nve_peer_state(self):

        for uut in leaf_uut_list:
            if 'Down' in uut.execute('show nve peers'):
                log.info(banner("NvePeerLearning F A I L E D"))
                self.failed(goto=['common_cleanup'])

    # =============================================================================================================================#
    @aetest.cleanup
    def cleanup(self):
        """ testcase clean up """

        post_test_process_dict['cc_check'] = 0
        status = infraVerify.postTestVerification(post_test_process_dict)

        if status['status'] == 0:
            self.failed(reason=status['logs'])
        else:
            self.passed(reason=status['logs'])

class TC003_Nve_Vni_State_Verify(aetest.Testcase):
    ###    This is description for my testcase two

    @aetest.test
    def check_nve_vni_state(self):
        for uut in leaf_uut_list:
            uut.execute('terminal length 0')

            test1 = leaf_protocol_check222(uut,['nve-vni'])
            if not test1:
                self.failed(goto=['common_cleanup'])

    # =============================================================================================================================#
    @aetest.cleanup
    def cleanup(self):
        """ testcase clean up """

        post_test_process_dict['cc_check'] = 0
        status = infraVerify.postTestVerification(post_test_process_dict)

        if status['status'] == 0:
            self.failed(reason=status['logs'])
        else:
            self.passed(reason=status['logs'])

class TC004_Vxlan_ngoam_enable(aetest.Testcase):
    ###    This is description for my testcase two

    @aetest.setup
    def setup(self):
        log.info("Pass testcase setup")

    @aetest.test
    def enablengoam(self):
        op = pcall(enableFeaturengoam,uut=(leaf_uut_list[0],leaf_uut_list[1],leaf_uut_list[1]))
        if not op:
            log.info('TC004_Vxlan_ngoam_enable FAILED')
            self.failed()

    # =============================================================================================================================#
    @aetest.cleanup
    def cleanup(self):
        """ testcase clean up """

        post_test_process_dict['cc_check'] = 0
        status = infraVerify.postTestVerification(post_test_process_dict)

        if status['status'] == 0:
            self.failed(reason=status['logs'])
        else:
            self.passed(reason=status['logs'])

class TC05_0_vxlan_enable_igmp_snooping_querier_std_vtep(aetest.Testcase):

    @aetest.setup
    def setup(self):
        pass

    # =============================================================================================================================#
    @aetest.test
    def configure_igmp_snooping(self):
        for uut in leaf_uut_list:
            uut.configure('''
                ip igmp snooping
                ip igmp snooping vxlan
            ''')

        end_vlan = int(vlan_start) + int(vlan_vni_scale)
        leaf3.configure('''
            vlan configuration '''+str(vlan_start)+'''-'''+str(end_vlan)+'''
                ip igmp snooping querier 1.1.1.1
        ''', timeout=500)

        countdown(20)

    # =============================================================================================================================#
    @aetest.cleanup
    def cleanup(self):
        """ testcase clean up """

        post_test_process_dict['cc_check'] = 0
        status = infraVerify.postTestVerification(post_test_process_dict)

        if status['status'] == 0:
            self.failed(reason=status['logs'])
        else:
            self.passed(reason=status['logs'])

# noinspection PyGlobalUndefined
class TC05_1_vxlan_tgen_connect(aetest.Testcase):

    @aetest.setup
    def setup(self):
        pass

    # =============================================================================================================================#
    @aetest.test
    def CONNECT_IXIA_CHASSIS(self, testscript):
        """ IXIA_CONFIGURATION subsection: Connect to IXIA """

        global tgen, tgen_port_handle_list, leaf1, leaf2, leaf3, leaf4,leaf1,leaf2, \
            sw1, sw2, spine1, port_handle1, port_handle2, port_handle,labserver_ip,port_list,\
            port_hdl_list,ip_src_list,ip_dst_list,mac_src_list,mac_dst_list,stream_list,port_handle_sw1,port_handle_leaf3,\
            port_handle_spine1,leaf_scale,tgn1_intf_list,port_handle_leaf1,port_handle_leaf2,\
            port_handle_leaf2_1,port_handle_leaf2_1,port_handle_leaf1_2,port_handle_leaf1_2,orphan_handle_list,\
            vpc_port_handle_list,port_handle_list,tgn1_leaf7_intf1,port_handle_leaf4,port_handle_leaf3,\
            port_handle_leaf5,port_handle_leaf3,tgn1_sw2_intf1,tgn1_leaf8_intf1,tgn1_spine1_intf1,port_handle_list_arp_supp_removed,\
            port_handle_sw1,port_handle_leaf3,port_handle_leaf1,port_handle_leaf2,port_handle_leaf3,port_handle_leaf4,port_handle_leaf5

        # Get IXIA paraameters
        ixia_chassis_ip = tgn_ip
        ixia_tcl_server = labserver_ip
        ixia_tcl_port   = str(8009)
        port_list       = "" + str(tgn1_sw1_intf1) + " " + str(tgn1_leaf1_intf1) + " " + str(tgn1_leaf3_intf1)
        ixia_int_list   = port_list

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

        #port_handle_list = [port_handle_sw1, port_handle_leaf1, port_handle_leaf3]
        #orphan_handle_list = [port_handle_leaf1]
        #port_handle_list_arp_supp_removed = [port_handle_leaf1, port_handle_leaf3]

        testscript.parameters['port_handle_sw1']    = ch_key[tgn1_sw1_intf1]
        testscript.parameters['port_handle_leaf1']  = ch_key[tgn1_leaf1_intf1]
        testscript.parameters['port_handle_leaf3']  = ch_key[tgn1_leaf3_intf1]

    @aetest.cleanup
    def cleanup(self):
        pass
        """ testcase clean up """

class TC05_2_vxlan_tgen_create_topologies(aetest.Testcase):

    @aetest.setup
    def setup(self):
        pass

    # =============================================================================================================================#
    @aetest.test
    def CREATE_IXIA_TOPOLOGIES(self, testscript):
        """ IXIA_CONFIGURATION subsection: Create IXIA Topologies """

        TOPO_1_dict = {'topology_name': 'SW-1-TG',
                       'device_grp_name': 'SW-1-TG',
                       'port_handle': testscript.parameters['port_handle_sw1']}

        TOPO_2_dict = {'topology_name': 'LEAF-1-TG',
                       'device_grp_name': 'LEAF-1-TG',
                       'port_handle': testscript.parameters['port_handle_leaf1']}

        TOPO_3_dict = {'topology_name': 'LEAF-3-TG',
                       'device_grp_name': 'LEAF-3-TG',
                       'port_handle': testscript.parameters['port_handle_leaf3']}

        testscript.parameters['IX_TP1_sw1'] = ixLib.create_topo_device_grp(TOPO_1_dict)
        if testscript.parameters['IX_TP1_sw1'] == 0:
            log.debug("Creating Topology failed")
            self.errored("Creating Topology failed", goto=['cleanup'])
        else:
            log.info("Created SW1-TG Topology Successfully")

        testscript.parameters['IX_TP2_leaf1'] = ixLib.create_topo_device_grp(TOPO_2_dict)
        if testscript.parameters['IX_TP2_leaf1'] == 0:
            log.debug("Creating Topology failed")
            self.errored("Creating Topology failed", goto=['cleanup'])
        else:
            log.info("Created LEAF1-TG Topology Successfully")

        testscript.parameters['IX_TP3_leaf3'] = ixLib.create_topo_device_grp(TOPO_3_dict)
        if testscript.parameters['IX_TP3_leaf3'] == 0:
            log.debug("Creating Topology failed")
            self.errored("Creating Topology failed", goto=['cleanup'])
        else:
            log.info("Created LEAF3-TG Topology Successfully")

        testscript.parameters['IX_TP1_sw1']['port_handle'] = testscript.parameters['port_handle_sw1']
        testscript.parameters['IX_TP2_leaf1']['port_handle'] = testscript.parameters['port_handle_leaf1']
        testscript.parameters['IX_TP3_leaf3']['port_handle'] = testscript.parameters['port_handle_leaf3']

    @aetest.cleanup
    def cleanup(self):
        pass
        """ testcase clean up """

class TC05_3_vxlan_tgen_create_interfaces(aetest.Testcase):

    @aetest.setup
    def setup(self):
        pass

    # =============================================================================================================================#
    @aetest.test
    def CONFIGURE_IXIA_INTERFACES(self, testscript):
        """ IXIA_CONFIGURATION subsection: Configure IXIA Interfaces """

        P1 = testscript.parameters['port_handle_sw1']
        P2 = testscript.parameters['port_handle_leaf1']
        P3 = testscript.parameters['port_handle_leaf3']

        log.info("===>")
        log.info(banner("Finding the IP address"))
        gw = str(ip_address(find_svi_ip222(leaf1,vlan_start)))
        ip_sa1=str(ip_address(find_svi_ip222(leaf1,vlan_start))+10)
        ip_sa2=str(ip_address(ip_sa1)+10)
        ip_sa11=str(ip_address(ip_sa1)+20)
        ip_sa22=str(ip_address(ip_sa2)+20)

        log.info("ip_sa1 is ->" + str(gw))
        log.info("ip_sa1 is ->" + str(ip_sa1))
        log.info("ip_sa2 is ->" + str(ip_sa2))
        log.info("ip_sa11 is ->" + str(ip_sa11))
        log.info("ip_sa22 is ->" + str(ip_sa22))

        log.info("===>")
        log.info(banner("Finding the IPv6 address"))
        gw_v6 = str(ip_address(findIntfIpv6Addr(leaf1, "vlan" + str(vlan_start))))
        ipv6_sa1 = str(ip_address(findIntfIpv6Addr(leaf1, "vlan" + str(vlan_start)))+16)
        ipv6_sa2 = str(ip_address(ipv6_sa1)+16)
        ipv6_sa11 = str(ip_address(ipv6_sa1) + 32)
        ipv6_sa22 = str(ip_address(ipv6_sa2) + 32)

        log.info("ipv6_sa1 is ->" + str(gw_v6))
        log.info("ipv6_sa1 is ->" + str(ipv6_sa1))
        log.info("ipv6_sa2 is ->" + str(ipv6_sa2))
        log.info("ipv6_sa11 is ->" + str(ipv6_sa11))
        log.info("ipv6_sa22 is ->" + str(ipv6_sa22))

        # Setting UP P1 Static IR IXIA Stream parameters
        IX_TPI1_sw1_int_dict_1 = {'dev_grp_hndl'    : testscript.parameters['IX_TP1_sw1']['dev_grp_hndl'],
                                  'port_hndl'       : P1,
                                  'no_of_ints'      : str(vlan_vni_scale),
                                  'phy_mode'        : str(tgn1_sw1_intf1_md),
                                  'mac'             : '00:00:10:00:00:01',
                                  'mac_step'        : '00:00:00:00:00:01',
                                  'protocol'        : 'ipv46',
                                  'v4_addr'         : ip_sa1,
                                  'v4_addr_step'    : '0.1.0.0',
                                  'v4_gateway'      : gw,
                                  'v4_gateway_step' : '0.1.0.0',
                                  'v4_netmask'      : '255.255.255.255',
                                  'v6_addr'         : ipv6_sa1,
                                  'v6_addr_step'    : '0:0:0:0::1:0',
                                  'v6_gateway'      : gw_v6,
                                  'v6_gateway_step' : '0:0:0:0::1:0',
                                  'v6_netmask'      : '128',
                                  'vlan_id'         : str(vlan_start),
                                  'vlan_id_step'    : '1'
        }

        # Setting UP P2 Static IR IXIA Stream parameters
        IX_TPI2_leaf1_int_dict_1 = {'dev_grp_hndl'    : testscript.parameters['IX_TP2_leaf1']['dev_grp_hndl'],
                                  'port_hndl'       : P2,
                                  'no_of_ints'      : str(vlan_vni_scale),
                                  'phy_mode'        : str(tgn1_leaf1_intf1_md),
                                  'mac'             : '00:00:15:00:00:01',
                                  'mac_step'        : '00:00:00:00:00:01',
                                  'protocol'        : 'ipv46',
                                  'v4_addr'         : ip_sa2,
                                  'v4_addr_step'    : '0.1.0.0',
                                  'v4_gateway'      : gw,
                                  'v4_gateway_step' : '0.1.0.0',
                                  'v4_netmask'      : '255.255.255.255',
                                  'v6_addr'         : ipv6_sa2,
                                  'v6_addr_step'    : '0:0:0:0::1:0',
                                  'v6_gateway'      : gw_v6,
                                  'v6_gateway_step' : '0:0:0:0::1:0',
                                  'v6_netmask'      : '128',
                                  'vlan_id'         : str(vlan_start),
                                  'vlan_id_step'    : '1'
        }

        # Setting UP P3 Static IR IXIA Stream parameters
        IX_TPI3_leaf3_int_dict_1 = {'dev_grp_hndl'    : testscript.parameters['IX_TP3_leaf3']['dev_grp_hndl'],
                                  'port_hndl'       : P3,
                                  'no_of_ints'      : str(vlan_vni_scale),
                                  'phy_mode'        : str(tgn1_leaf3_intf1_md),
                                  'mac'             : '00:00:20:00:00:01',
                                  'mac_step'        : '00:00:00:00:00:01',
                                  'protocol'        : 'ipv46',
                                  'v4_addr'         : ip_sa11,
                                  'v4_addr_step'    : '0.1.0.0',
                                  'v4_gateway'      : gw,
                                  'v4_gateway_step' : '0.1.0.0',
                                  'v4_netmask'      : '255.255.255.255',
                                  'v6_addr'         : ipv6_sa11,
                                  'v6_addr_step'    : '0:0:0:0::1:0',
                                  'v6_gateway'      : gw_v6,
                                  'v6_gateway_step' : '0:0:0:0::1:0',
                                  'v6_netmask'      : '128',
                                  'vlan_id'         : str(vlan_start),
                                  'vlan_id_step'    : '1'
        }

        IX_TPI1_sw1_int_data = ixLib.configure_multi_ixia_interface(IX_TPI1_sw1_int_dict_1)
        IX_TPI2_leaf1_int_data = ixLib.configure_multi_ixia_interface(IX_TPI2_leaf1_int_dict_1)
        IX_TPI3_leaf2_int_data = ixLib.configure_multi_ixia_interface(IX_TPI3_leaf3_int_dict_1)

        if IX_TPI1_sw1_int_data == 0 or IX_TPI2_leaf1_int_data == 0 or IX_TPI3_leaf2_int_data == 0:
            log.debug("Configuring IXIA Interface failed")
            self.errored("Configuring IXIA Interface failed", goto=['cleanup'])
        else:
            log.info("Configured IXIA Interface Successfully")

        # Pushing the Traffic handles to testscript.parameters
        testscript.parameters['IX_TP1_sw1']['eth_handle'] = []
        testscript.parameters['IX_TP1_sw1']['ipv4_handle'] = []
        testscript.parameters['IX_TP1_sw1']['ipv6_handle'] = []
        testscript.parameters['IX_TP2_leaf1']['eth_handle'] = []
        testscript.parameters['IX_TP2_leaf1']['ipv4_handle'] = []
        testscript.parameters['IX_TP2_leaf1']['ipv6_handle'] = []
        testscript.parameters['IX_TP3_leaf3']['eth_handle'] = []
        testscript.parameters['IX_TP3_leaf3']['ipv4_handle'] = []
        testscript.parameters['IX_TP3_leaf3']['ipv6_handle'] = []

        testscript.parameters['IX_TP1_sw1']['eth_handle'].append(IX_TPI1_sw1_int_data['eth_handle'])
        testscript.parameters['IX_TP1_sw1']['ipv4_handle'].append(IX_TPI1_sw1_int_data['ipv4_handle'])
        testscript.parameters['IX_TP1_sw1']['ipv6_handle'].append(IX_TPI1_sw1_int_data['ipv6_handle'])

        testscript.parameters['IX_TP1_sw1']['eth_handle'].append(IX_TPI1_sw1_int_data['eth_handle'])
        testscript.parameters['IX_TP1_sw1']['ipv4_handle'].append(IX_TPI1_sw1_int_data['ipv4_handle'])
        testscript.parameters['IX_TP1_sw1']['ipv6_handle'].append(IX_TPI1_sw1_int_data['ipv6_handle'])

        testscript.parameters['IX_TP1_sw1']['topo_int_handle'] = IX_TPI1_sw1_int_data['topo_int_handle'].split(" ")

        testscript.parameters['IX_TP2_leaf1']['eth_handle'].append(IX_TPI2_leaf1_int_data['eth_handle'])
        testscript.parameters['IX_TP2_leaf1']['ipv4_handle'].append(IX_TPI2_leaf1_int_data['ipv4_handle'])
        testscript.parameters['IX_TP2_leaf1']['ipv6_handle'].append(IX_TPI2_leaf1_int_data['ipv6_handle'])

        testscript.parameters['IX_TP2_leaf1']['eth_handle'].append(IX_TPI2_leaf1_int_data['eth_handle'])
        testscript.parameters['IX_TP2_leaf1']['ipv4_handle'].append(IX_TPI2_leaf1_int_data['ipv4_handle'])
        testscript.parameters['IX_TP2_leaf1']['ipv6_handle'].append(IX_TPI2_leaf1_int_data['ipv6_handle'])

        testscript.parameters['IX_TP2_leaf1']['topo_int_handle'] = IX_TPI2_leaf1_int_data['topo_int_handle'].split(" ")

        testscript.parameters['IX_TP3_leaf3']['eth_handle'].append(IX_TPI3_leaf2_int_data['eth_handle'])
        testscript.parameters['IX_TP3_leaf3']['ipv4_handle'].append(IX_TPI3_leaf2_int_data['ipv4_handle'])
        testscript.parameters['IX_TP3_leaf3']['ipv6_handle'].append(IX_TPI3_leaf2_int_data['ipv6_handle'])

        testscript.parameters['IX_TP3_leaf3']['eth_handle'].append(IX_TPI3_leaf2_int_data['eth_handle'])
        testscript.parameters['IX_TP3_leaf3']['ipv4_handle'].append(IX_TPI3_leaf2_int_data['ipv4_handle'])
        testscript.parameters['IX_TP3_leaf3']['ipv6_handle'].append(IX_TPI3_leaf2_int_data['ipv6_handle'])

        testscript.parameters['IX_TP3_leaf3']['topo_int_handle'] = IX_TPI3_leaf2_int_data['topo_int_handle'].split(" ")

        log.info("IXIA Port 1 Handles")
        log.info(testscript.parameters['IX_TP1_sw1'])
        log.info("IXIA Port 2 Handles")
        log.info(testscript.parameters['IX_TP2_leaf1'])
        log.info("IXIA Port 2 Handles")
        log.info(testscript.parameters['IX_TP3_leaf3'])

    @aetest.cleanup
    def cleanup(self):
        pass
        """ testcase clean up """

class TC05_4_vxlan_tgen_create_IGMP_groups(aetest.Testcase):

    @aetest.setup
    def setup(self):
        pass

    # =============================================================================================================================#
    @aetest.test
    def CONFIGURE_IXIA_IGMP_GROUPS(self, testscript):
        """ IXIA_CONFIGURATION subsection: Configure IXIA IGMP Groups """

        IX_TP1 = testscript.parameters['IX_TP1_sw1']
        IX_TP2 = testscript.parameters['IX_TP2_leaf1']

        log.info("===>")
        log.info(banner("Finding the IP address"))
        gw = str(ip_address(find_svi_ip222(leaf1,vlan_start)))
        ip_sa1=str(ip_address(find_svi_ip222(leaf1,vlan_start))+10)
        ip_sa2=str(ip_address(ip_sa1)+10)
        ip_sa11=str(ip_address(ip_sa1)+20)
        ip_sa22=str(ip_address(ip_sa2)+20)

        log.info("ip_sa1 is ->" + str(gw))
        log.info("ip_sa1 is ->" + str(ip_sa1))
        log.info("ip_sa2 is ->" + str(ip_sa2))
        log.info("ip_sa11 is ->" + str(ip_sa11))
        log.info("ip_sa22 is ->" + str(ip_sa22))

        IGMP_dict_1 = {'ipv4_hndl'                  : IX_TP1['ipv4_handle'][0],
                     'igmp_ver'                     : 'v3',
                     'mcast_grp_ip'                 : '225.1.1.1',
                     'mcast_grp_ip_step'            : '0.0.1.0',
                     'no_of_grps'                   : '1',
                     'mcast_src_ip'                 : ip_sa11,
                     'mcast_src_ip_step'            : '0.1.0.0',
                     'mcast_src_ip_step_per_port'   : '0.1.0.0',
                     'mcast_grp_ip_step_per_port'   : '0.1.0.0',
                     'mcast_no_of_srcs'             : '1',
                     'topology_handle'              : IX_TP1['topo_hndl']
                     }

        IGMP_dict_2 = {'ipv4_hndl'                  : IX_TP2['ipv4_handle'][0],
                     'igmp_ver'                     : 'v3',
                     'mcast_grp_ip'                 : '225.1.1.1',
                     'mcast_grp_ip_step'            : '0.0.1.0',
                     'no_of_grps'                   : '1',
                     'mcast_src_ip'                 : ip_sa11,
                     'mcast_src_ip_step'            : '0.1.0.0',
                     'mcast_src_ip_step_per_port'   : '0.1.0.0',
                     'mcast_grp_ip_step_per_port'   : '0.1.0.0',
                     'mcast_no_of_srcs'             : '1',
                     'topology_handle'              : IX_TP2['topo_hndl']
                     }

        IGMP_EML_1 = ixLib.emulate_igmp_groupHost(IGMP_dict_1)
        IGMP_EML_2 = ixLib.emulate_igmp_groupHost(IGMP_dict_2)
        #ForkedPdb().set_trace()

        if IGMP_EML_1 == 0 and IGMP_EML_2 == 0:
            log.debug("Configuring IGMP failed")
            self.errored("Configuring IGMP failed", goto=['cleanup'])
        else:
            log.info("Configured IGMP Successfully")

        testscript.parameters['IX_TP1_sw1']['igmpHost_handle'] = []
        testscript.parameters['IX_TP1_sw1']['igmp_group_handle'] = []
        testscript.parameters['IX_TP1_sw1']['igmp_source_handle'] = []
        testscript.parameters['IX_TP1_sw1']['igmpMcastGrpList'] = []

        testscript.parameters['IX_TP1_sw1']['igmpHost_handle'].append(IGMP_EML_1['igmpHost_handle'])
        testscript.parameters['IX_TP1_sw1']['igmp_group_handle'].append(IGMP_EML_1['igmp_group_handle'])
        testscript.parameters['IX_TP1_sw1']['igmp_source_handle'].append(IGMP_EML_1['igmp_source_handle'])
        testscript.parameters['IX_TP1_sw1']['igmpMcastGrpList'].append(IGMP_EML_1['igmpMcastGrpList'])

        testscript.parameters['IX_TP2_leaf1']['igmpHost_handle'] = []
        testscript.parameters['IX_TP2_leaf1']['igmp_group_handle'] = []
        testscript.parameters['IX_TP2_leaf1']['igmp_source_handle'] = []
        testscript.parameters['IX_TP2_leaf1']['igmpMcastGrpList'] = []

        testscript.parameters['IX_TP2_leaf1']['igmpHost_handle'].append(IGMP_EML_2['igmpHost_handle'])
        testscript.parameters['IX_TP2_leaf1']['igmp_group_handle'].append(IGMP_EML_2['igmp_group_handle'])
        testscript.parameters['IX_TP2_leaf1']['igmp_source_handle'].append(IGMP_EML_2['igmp_source_handle'])
        testscript.parameters['IX_TP2_leaf1']['igmpMcastGrpList'].append(IGMP_EML_2['igmpMcastGrpList'])

    @aetest.cleanup
    def cleanup(self):
        pass
        """ testcase clean up """

class TC05_5_vxlan_tgen_start_protocols(aetest.Testcase):

    @aetest.setup
    def setup(self):
        pass

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

    @aetest.cleanup
    def cleanup(self):
        pass
        """ testcase clean up """

class TC05_6_vxlan_tgen_configure_ucast_TI(aetest.Testcase):

    @aetest.setup
    def setup(self):
        pass

    # =============================================================================================================================#
    @aetest.test
    def CONFIGURE_UCAST_IXIA_TRAFFIC(self, testscript):
        """ IXIA_CONFIGURATION subsection: Configure MCAST Traffic Item """

        IX_TP1 = testscript.parameters['IX_TP1_sw1']
        IX_TP2 = testscript.parameters['IX_TP2_leaf1']
        IX_TP3 = testscript.parameters['IX_TP3_leaf3']

        UCAST_STD_to_VPC_V4_dict = {   'src_hndl'  : IX_TP3['ipv4_handle'],
                            'dst_hndl'  : IX_TP2['ipv4_handle'],
                            'circuit'   : 'ipv4',
                            'TI_name'   : "UCAST_STD_to_VPC_V4",
                            'rate_pps'  : "1000",
                            'bi_dir'    : 1
                      }

        UCAST_STD_to_VPC_V6_dict = {   'src_hndl'  : IX_TP3['ipv6_handle'],
                            'dst_hndl'  : IX_TP2['ipv6_handle'],
                            'circuit'   : 'ipv6',
                            'TI_name'   : "UCAST_STD_to_VPC_V6",
                            'rate_pps'  : "1000",
                            'bi_dir'    : 1
                      }

        UCAST_STD_to_ORPH_V4_dict = {   'src_hndl'  : IX_TP3['ipv4_handle'],
                            'dst_hndl'  : IX_TP1['ipv4_handle'],
                            'circuit'   : 'ipv4',
                            'TI_name'   : "UCAST_STD_to_ORPH_V4",
                            'rate_pps'  : "1000",
                            'bi_dir'    : 1
                      }

        UCAST_STD_to_ORPH_V6_dict = {   'src_hndl'  : IX_TP3['ipv6_handle'],
                            'dst_hndl'  : IX_TP1['ipv6_handle'],
                            'circuit'   : 'ipv6',
                            'TI_name'   : "UCAST_STD_to_ORPH_V6",
                            'rate_pps'  : "1000",
                            'bi_dir'    : 1
                      }

        UCAST_VPC_to_ORPH_V4_dict = {   'src_hndl'  : IX_TP2['ipv4_handle'],
                            'dst_hndl'  : IX_TP1['ipv4_handle'],
                            'circuit'   : 'ipv4',
                            'TI_name'   : "UCAST_VPC_to_ORPH_V4",
                            'rate_pps'  : "1000",
                            'bi_dir'    : 1
                      }

        UCAST_VPC_to_ORPH_V6_dict = {   'src_hndl'  : IX_TP2['ipv6_handle'],
                            'dst_hndl'  : IX_TP1['ipv6_handle'],
                            'circuit'   : 'ipv6',
                            'TI_name'   : "UCAST_VPC_to_ORPH_V6",
                            'rate_pps'  : "1000",
                            'bi_dir'    : 1
                      }

        UCAST_STD_to_VPC_V4_TI = ixLib.configure_ixia_traffic_item(UCAST_STD_to_VPC_V4_dict)
        UCAST_STD_to_VPC_V6_TI = ixLib.configure_ixia_traffic_item(UCAST_STD_to_VPC_V6_dict)
        UCAST_STD_to_ORPH_V4_TI = ixLib.configure_ixia_traffic_item(UCAST_STD_to_ORPH_V4_dict)
        UCAST_STD_to_ORPH_V6_TI = ixLib.configure_ixia_traffic_item(UCAST_STD_to_ORPH_V6_dict)
        UCAST_VPC_to_ORPH_V4_TI = ixLib.configure_ixia_traffic_item(UCAST_VPC_to_ORPH_V4_dict)
        UCAST_VPC_to_ORPH_V6_TI = ixLib.configure_ixia_traffic_item(UCAST_VPC_to_ORPH_V6_dict)

        if UCAST_STD_to_VPC_V4_TI == 0 or UCAST_STD_to_VPC_V6_TI == 0 or UCAST_STD_to_ORPH_V4_TI == 0 \
                or UCAST_STD_to_ORPH_V6_TI == 0 or UCAST_VPC_to_ORPH_V4_TI == 0 or UCAST_VPC_to_ORPH_V6_TI == 0:
            log.debug("Configuring UCast TI failed")
            self.errored("Configuring UCast TI failed", goto=['cleanup'])

    @aetest.cleanup
    def cleanup(self):
        pass
        """ testcase clean up """

class TC05_7_vxlan_tgen_configure_BCAST_TI(aetest.Testcase):

    @aetest.setup
    def setup(self):
        pass

    # =============================================================================================================================#
    @aetest.test
    def CONFIGURE_BCAST_IXIA_TRAFFIC(self, testscript):
        """ IXIA_CONFIGURATION subsection: Configure MCAST Traffic Item """

        IX_TP1 = testscript.parameters['IX_TP1_sw1']
        IX_TP2 = testscript.parameters['IX_TP2_leaf1']
        IX_TP3 = testscript.parameters['IX_TP3_leaf3']

        BCAST_STD_VPC_v4_dict = {
                            'src_hndl'      : IX_TP3['port_handle'],
                            'dst_hndl'      : IX_TP1['port_handle'],
                            'TI_name'       : "BCAST_STD_VPC_v4",
                            'frame_size'    : "70",
                            'rate_pps'      : "1000",
                            'src_mac'       : "00:00:30:00:00:01",
                            'srcmac_step'   : "00:00:00:00:00:01",
                            'srcmac_count'  : "100",
                            'vlan_id'       : str(vlan_start),
                            'vlanid_step'   : "1",
                            'vlanid_count'  : str(vlan_vni_scale),
                            'ip_src_addrs'  : "30.1.1.10",
                            'ip_step'       : "0.0.1.0",
                      }

        BCAST_STD_ORPH_v4_dict = {
                            'src_hndl'      : IX_TP3['port_handle'],
                            'dst_hndl'      : IX_TP2['port_handle'],
                            'TI_name'       : "BCAST_STD_ORPH_v4",
                            'frame_size'    : "70",
                            'rate_pps'      : "1000",
                            'src_mac'       : "00:00:35:00:00:01",
                            'srcmac_step'   : "00:00:00:00:00:01",
                            'srcmac_count'  : "100",
                            'vlan_id'       : str(vlan_start),
                            'vlanid_step'   : "1",
                            'vlanid_count'  : str(vlan_vni_scale),
                            'ip_src_addrs'  : "35.1.1.10",
                            'ip_step'       : "0.0.1.0",
                      }

        BCAST_STD_VPC_v4_TI = ixLib.configure_ixia_BCAST_traffic_item(BCAST_STD_VPC_v4_dict)
        BCAST_STD_ORPH_v4_TI = ixLib.configure_ixia_BCAST_traffic_item(BCAST_STD_ORPH_v4_dict)

        if BCAST_STD_VPC_v4_TI == 0 and BCAST_STD_ORPH_v4_TI == 0:
            log.debug("Configuring BCast TI failed")
            self.errored("Configuring BCast TI failed", goto=['cleanup'])

    @aetest.cleanup
    def cleanup(self):
        pass
        """ testcase clean up """

class TC05_8_vxlan_tgen_configure_unknown_ucast(aetest.Testcase):

    @aetest.setup
    def setup(self):
        pass

    # =============================================================================================================================#
    @aetest.test
    def CONFIGURE_UNKNOWN_UCAST_IXIA_TRAFFIC(self, testscript):
        """ IXIA_CONFIGURATION subsection: Configure MCAST Traffic Item """

        IX_TP1 = testscript.parameters['IX_TP1_sw1']
        IX_TP2 = testscript.parameters['IX_TP2_leaf1']
        IX_TP3 = testscript.parameters['IX_TP3_leaf3']

        UKNOWN_UCAST_STD_VPC_V4_dict = {
                            'src_hndl'      : IX_TP3['port_handle'],
                            'dst_hndl'      : IX_TP2['port_handle'],
                            'TI_name'       : "UKNOWN_UCAST_STD_VPC_V4",
                            'frame_size'    : "64",
                            'rate_pps'      : "1000",
                            'dst_mac'       : "00:00:45:00:00:01",
                            'dstmac_step'   : "00:00:00:00:00:01",
                            'dstmac_count'  : "100",
                            'src_mac'       : "00:00:41:00:00:01",
                            'srcmac_step'   : "00:00:00:00:00:01",
                            'srcmac_count'  : "100",
                            'vlan_id'       : str(vlan_start),
                            'vlanid_step'   : "1",
                            'vlanid_count'  : str(vlan_vni_scale),
                      }

        UKNOWN_UCAST_STD_ORPH_V4_dict = {
                            'src_hndl'      : IX_TP3['port_handle'],
                            'dst_hndl'      : IX_TP1['port_handle'],
                            'TI_name'       : "UKNOWN_UCAST_STD_ORPH_V4",
                            'frame_size'    : "64",
                            'rate_pps'      : "1000",
                            'dst_mac'       : "00:00:45:00:00:01",
                            'dstmac_step'   : "00:00:00:00:00:01",
                            'dstmac_count'  : "100",
                            'src_mac'       : "00:00:41:00:00:01",
                            'srcmac_step'   : "00:00:00:00:00:01",
                            'srcmac_count'  : "100",
                            'vlan_id'       : str(vlan_start),
                            'vlanid_step'   : "1",
                            'vlanid_count'  : str(vlan_vni_scale),
                      }

        UKNOWN_UCAST_STD_VPC_V4_TI = ixLib.configure_ixia_UNKNOWN_UCAST_traffic_item(UKNOWN_UCAST_STD_VPC_V4_dict)
        UKNOWN_UCAST_STD_ORPH_V4_TI = ixLib.configure_ixia_UNKNOWN_UCAST_traffic_item(UKNOWN_UCAST_STD_ORPH_V4_dict)

        if UKNOWN_UCAST_STD_VPC_V4_TI == 0 or UKNOWN_UCAST_STD_ORPH_V4_TI == 0:
            log.debug("Configuring UNKNOWN_UCAST TI failed")
            self.errored("Configuring UNKNOWN_UCAST TI failed", goto=['cleanup'])

    @aetest.cleanup
    def cleanup(self):
        pass
        """ testcase clean up """

class TC05_9_vxlan_tgen_configure_MCAST_TI(aetest.Testcase):

    @aetest.setup
    def setup(self):
        pass

    # =============================================================================================================================#
    @aetest.test
    def CONFIGURE_MCAST_IXIA_TRAFFIC(self, testscript):
        """ IXIA_CONFIGURATION subsection: Configure MCAST Traffic Item """

        IX_TP1 = testscript.parameters['IX_TP1_sw1']
        IX_TP2 = testscript.parameters['IX_TP2_leaf1']
        IX_TP3 = testscript.parameters['IX_TP3_leaf3']

        # Creating TAGs for SRC IP Handles
        TAG_dict = {'subject_handle'            : IX_TP3['ipv4_handle'],
                    'topo_handle'               : IX_TP3['topo_hndl'],
                    'TAG_count_per_item'        : str(vlan_vni_scale)
        }

        SRC_IP_TAG = ixLib.configure_tag_config_multiplier(TAG_dict)
        if SRC_IP_TAG == 0:
            log.debug("Configuring TAGS for SRC IP failed")

        # Creating TAGs for DST IP Handles
        TAG_dict = {'subject_handle'            : IX_TP2['ipv4_handle'],
                    'topo_handle'               : IX_TP2['topo_hndl'],
                    'TAG_count_per_item'        : str(vlan_vni_scale)
        }

        DST_IP_TAG_VPC = ixLib.configure_tag_config_multiplier(TAG_dict)
        if DST_IP_TAG_VPC == 0:
            log.debug("Configuring TAGS for DST IP failed")

        # Creating TAGs for IGMP Host Handles
        TAG_dict = {'subject_handle'            : IX_TP2['igmp_group_handle'],
                    'topo_handle'               : IX_TP2['topo_hndl'],
                    'TAG_count_per_item'        : str(vlan_vni_scale)
        }

        IGMP_Host_TAG_VPC = ixLib.configure_tag_config_multiplier(TAG_dict)
        if IGMP_Host_TAG_VPC == 0:
            log.debug("Configuring TAGS for IGMP Hosts failed")

        # Creating TAGs for DST IP Handles
        TAG_dict = {'subject_handle'            : IX_TP1['ipv4_handle'],
                    'topo_handle'               : IX_TP1['topo_hndl'],
                    'TAG_count_per_item'        : str(vlan_vni_scale)
        }

        DST_IP_TAG_ORPH = ixLib.configure_tag_config_multiplier(TAG_dict)
        if DST_IP_TAG_ORPH == 0:
            log.debug("Configuring TAGS for DST IP failed")

        # Creating TAGs for IGMP Host Handles
        TAG_dict = {'subject_handle'            : IX_TP1['igmp_group_handle'],
                    'topo_handle'               : IX_TP1['topo_hndl'],
                    'TAG_count_per_item'        : str(vlan_vni_scale)
        }

        IGMP_Host_TAG_ORPH = ixLib.configure_tag_config_multiplier(TAG_dict)
        if IGMP_Host_TAG_ORPH == 0:
            log.debug("Configuring TAGS for IGMP Hosts failed")

        MCAST_dict = {'src_ipv4_topo_handle'    : IX_TP3['topo_hndl'],
                      'total_tags'              : str(int(vlan_vni_scale)),
                      'TI_name'                 : "MCAST_STD_VPC_ORPH_cast",
                      'rate_pps'                : "1000",
                      'frame_size'              : "70",
                      }

        MCAST_TI = ixLib.configure_v4_mcast_traffic_item_per_tag(MCAST_dict)

        if MCAST_TI == 0:
            log.debug("Configuring MCast TI failed")
            self.errored("Configuring MCast TI failed", goto=['cleanup'])

    @aetest.cleanup
    def cleanup(self):
        pass
        """ testcase clean up """
'''
class TC05_10_vxlan_tgen_configure_raw_ARP(aetest.Testcase):

    @aetest.setup
    def setup(self):
        pass

    # =============================================================================================================================#
    @aetest.test
    def CONFIGURE_RAW_ARP_IXIA_TRAFFIC(self, testscript):
        """ IXIA_CONFIGURATION subsection: Configure MCAST Traffic Item """

        IX_TP1 = testscript.parameters['IX_TP1_sw1']
        IX_TP2 = testscript.parameters['IX_TP2_leaf1']
        IX_TP3 = testscript.parameters['IX_TP3_leaf3']

        arp_supp_cache_vpc = json.loads(leaf1.execute('show ip arp suppression-cache remote | json-pretty'))
        arp_supp_vpc_entry_list = arp_supp_cache_vpc['TABLE_arp-suppression']['ROW_arp-suppression']['TABLE_entries']['ROW_entries']
        if len(arp_supp_vpc_entry_list) < int(vlan_vni_scale):
            self.failed(goto=['common_cleanup'])

        vlan = (arp_supp_vpc_entry_list[0]['vlan'])
        ip_addr = str(ip.IPv4Address(arp_supp_vpc_entry_list[0]['ip-addr'])+1)

        mac_sa = str(RandMac("00:00:00:00:00:00", True)).replace("'", "")
        ip_sa = str(ip_address(ip_addr) - 10)

        log.info("source mac ->"+str(mac_sa))
        log.info("source IP ->" + str(ip_sa))

        RAW_ARP_VPC_ALL_V4_dict = {
                            'src_hndl'      : IX_TP1['port_handle'],
                            'dst_hndl'      : [IX_TP2['port_handle'], IX_TP3['port_handle']],
                            'TI_name'       : "RAW_ARP_VPC_ALL",
                            'rate_pps'      : "1000",
                            'vlan_id'       : vlan,
                            'vlan_count'    : str(vlan_vni_scale),
                            'src_mac'       : mac_sa,
                            'src_mac_step'  : '00:00:00:00:00:01',
                            'src_ip'        : ip_sa,
                            'dst_ip'        : ip_addr,
                            'src_ip_step'   : '0.1.0.0',
                            'dst_ip_step'   : '0.1.0.0',
                      }

        RAW_ARP_VPC_ALL_V4_TI = ixLib.configure_raw_ARP_ixia_traffic_item(RAW_ARP_VPC_ALL_V4_dict)

        if RAW_ARP_VPC_ALL_V4_TI == 0 :
            log.debug("Configuring UNKNOWN_UCAST TI failed")
            self.errored("Configuring UNKNOWN_UCAST TI failed", goto=['next_tc'])

    @aetest.cleanup
    def cleanup(self):
        pass
        """ testcase clean up """
'''
class TC05_11_vxlan_tgen_apply_verify_traffic(aetest.Testcase):

    @aetest.setup
    def setup(self):
        pass

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
    @aetest.test
    def VERIFY_IXIA_TRAFFIC(self):
        """ IXIA_CONFIGURATION subsection: Verify IXIA Traffic """

        time.sleep(20)

        if ixLib.verify_traffic(2,3) == 0:
            log.debug("Traffic Verification failed")
            self.failed("Traffic Verification failed", goto=['cleanup'])
        else:
            log.info("Traffic Verification Passed")

    @aetest.cleanup
    def cleanup(self):
        pass
        """ testcase clean up """

# class TC0000005_vxlan_tgn_connect_all(aetest.Testcase):
#     ###    This is description for my testcase two
#
#     @aetest.setup
#     def setup(self):
#         pass
#
#
#     @aetest.test
#     def configureTgn(self, testscript, testbed):
#         """ common setup subsection: connecting devices """
#
#         global tgen, tgen_port_handle_list, leaf1, leaf2, leaf3, leaf4,leaf1,leaf2, \
#             sw1, sw2, spine1, port_handle1, port_handle2, port_handle,labserver_ip,port_list,\
#             port_hdl_list,ip_src_list,ip_dst_list,mac_src_list,mac_dst_list,stream_list,port_handle_sw1,port_handle_leaf3,\
#             port_handle_spine1,leaf_scale,tgn1_intf_list,port_handle_leaf1,port_handle_leaf2,\
#             port_handle_leaf2_1,port_handle_leaf2_1,port_handle_leaf1_2,port_handle_leaf1_2,orphan_handle_list,\
#             vpc_port_handle_list,port_handle_list,tgn1_leaf7_intf1,port_handle_leaf4,port_handle_leaf3,\
#             port_handle_leaf5,port_handle_leaf3,tgn1_sw2_intf1,tgn1_leaf8_intf1,tgn1_spine1_intf1,port_handle_list_arp_supp_removed,\
#             port_handle_sw1,port_handle_leaf3,port_handle_leaf1,port_handle_leaf2,port_handle_leaf3,port_handle_leaf4,port_handle_leaf5
#
#
#         #port_handle = ConnectSpirent(labserver_ip,tgn_ip,[tgn1_sw1_intf1,tgn1_leaf1_intf1,tgn1_leaf2_intf1,tgn1_leaf3_intf1])
#         port_list = [tgn1_sw1_intf1,tgn1_leaf1_intf1,tgn1_leaf3_intf1]
#         #port_list = [tgn1_sw1_intf1,tgn1_leaf1_intf1,tgn1_leaf2_intf1,tgn1_leaf3_intf1]
#         result = ixia_connect(labserver_ip,tgn_ip,port_list)
#         if result == 0:
#             log.info("Ixia Connection is failed")
#
#         print(result)
#         ports = result['vport_list'].split()
#         port_handle_sw1 = ports[0]
#         port_handle_leaf1 = ports[1]
#         #port_handle_leaf2 = ports[2]
#         port_handle_leaf3 = ports[2]
#
#         #port_handle_list = [port_handle_sw1,port_handle_leaf1,port_handle_leaf2,port_handle_leaf3]
#         #orphan_handle_list = [port_handle_leaf1,port_handle_leaf2]
#         #port_handle_list_arp_supp_removed = [port_handle_leaf1,port_handle_leaf2,port_handle_leaf3]
#
#         port_handle_list = [port_handle_sw1,port_handle_leaf1,port_handle_leaf3]
#         orphan_handle_list = [port_handle_leaf1]
#         port_handle_list_arp_supp_removed = [port_handle_leaf1,port_handle_leaf3]
#
#
#
#         ip1 = '5.1.0.100'
#         ip2 = '5.1.0.200'
#         mac1='0011.9400.0002'
#         mac2='0033.9400.0002'
#
#     @aetest.cleanup
#     def cleanup(self):
#         pass
#         """ testcase clean up """
#
#
# class TC005_vxlan_Traffic_all(aetest.Testcase):
#     ###    This is description for my testcase two
#
#     @aetest.setup
#     def setup(self):
#
#         for uut in leaf_uut_list+sw_uut_list:
#             uut.configure('system no hap-reset ')
#             for i in range(1,2):
#                 uut.execute('clear mac address-table dynamic')
#                 uut.execute('clear ip arp vrf all')
#
#
#
#         log.info(banner("Finding the IP address"))
#         ip_sa1=str(ip_address(find_svi_ip222(leaf1,vlan_start))+10)
#         ip_sa2=str(ip_address(ip_sa1)+10)
#         ip_sa11=str(ip_address(ip_sa1)+40)
#         ip_sa22=str(ip_address(ip_sa2)+40)
#
#
#
#         log.info(banner("----Generating hosts and flood traffic----"))
#         test1= ixia_flood_traffic_config(port_handle_sw1,vlan_start,ip_sa1,'100.100.100.100',rate,str(vlan_vni_scale))
#         test2= ixia_flood_traffic_config(port_handle_leaf3,vlan_start,ip_sa2,'200.200.200.200',rate,str(vlan_vni_scale))
#
#         log.info(banner("----Generating mcast flood traffic----"))
#         test1= ixia_mcast_traffic_config(port_handle_sw1,vlan_start,ip_sa1,'239.1.1.1',rate,str(vlan_vni_scale))
#         test2= ixia_mcast_traffic_config(port_handle_leaf3,vlan_start,ip_sa2,'239.1.1.1',rate,str(vlan_vni_scale))
#
#         log.info(banner("----Generating hosts Unicast Bidir Traffic----"))
#
#         ixia_unicast_bidir_traffic_config(port_hdl1=port_handle_sw1,port_hdl2=port_handle_leaf3,vlan1=vlan_start,vlan2=vlan_start,\
#         scale=vlan_vni_scale,ip1=ip_sa11,ip2=ip_sa22,gw1=ip_sa22,gw2=ip_sa11,rate_pps=rate)
#
#
#         log.info(banner("----Generating Routed Bidir Traffic----"))
#
#         if not ixia_routed_bidir_traffic_config(leaf1,port_handle_sw1,port_handle_leaf3,pps):
#             self.failed()
#
#
#         log.info(banner("----Generating IPV6 Unicast Traffic----"))
#
#         log.info(banner("Finding the IPv6 address"))
#         vlan = 'vlan' + str(vlan_start)
#         ipv6_sa1=str(ip_address(findIntfIpv6Addr(leaf1,vlan))+10)
#         ipv6_sa2=str(ip_address(ipv6_sa1)+100)
#
#         ixia_v6_unicast_bidir_stream(port_handle_sw1,port_handle_leaf3,vlan_start,vlan_start,vlan_vni_scale,\
#             ipv6_sa1,ipv6_sa2,rate)
#
#
#         log.info(banner("Starting Traffic and counting 120 seconds"))
#         #sth.traffic_control(port_handle = 'all', action = 'run')
#         _result_ = ixiahlt.traffic_control(action='run',traffic_generator='ixnetwork_540',type='l23')
#
#
#         countdown(30)
#
#
#         #log.info(banner("Starting Traffic and counting 120 seconds"))
#         #arp_suppression_test(leaf1,port_handle_sw1)
#         #arp_suppression_test(leaf3,port_handle_leaf3)
#
#         #log.info(banner("Starting Traffic and counting 120 seconds"))
#         #_result_ = ixiahlt.traffic_control(action='run',traffic_generator='ixnetwork_540',type='l23')
#
#
#
#     @aetest.test
#     def vxlan_traffic_test_all(self):
#         if not traffic_test_ixia(port_handle_list,rate_list):
#             self.failed(goto=['common_cleanup'])
#         else:
#             pcall(config_to_bootflash1,uut=tuple(leaf_uut_list),filename=(vxlan_evpn_config,vxlan_evpn_config,vxlan_evpn_config))
#
#
#
#     @aetest.cleanup
#     def cleanup(self):
#         pass
#         """ testcase clean up """
#

class TC006_Vxlan_nxos_checks(aetest.Testcase):
    ###    This is description for my testcase two

    @aetest.setup
    def setup(self):
        log.info("Pass testcase setup")

    @aetest.test
    def nxosvxlancontrolplane(self):

        # n9k1# sh mac add dynamic vlan 1001 | inc Po101
        # + 1001     0010.3ee9.3e22   dynamic  0         F      F    Po101
        # + 1001     0051.5c24.2702   dynamic  0         F      F    Po101
        # + 1001     0058.3f2c.3c02   dynamic  0         F      F    Po101
        # + 1001     3a33.9329.a85e   dynamic  0         F      F    Po101
        # + 1001     d211.6666.618b   dynamic  0         F      F    Po101

        op1 = leaf1.execute('sh mac add dynamic vlan 1001 | inc Po101')
        for line in op1.splitlines():
            if line:
                if '0010' in line:
                    mac1 = line.split()[2]
                    if not nxosVxlanEvpnCheck(leaf1, mac=mac1):
                        log.info('nxosVxlanEvpnCheck FAILED')
                        self.failed()

    # =============================================================================================================================#
    @aetest.cleanup
    def cleanup(self):
        """ testcase clean up """

        if post_test_process_dict['eor_flag']:
            post_test_process_dict['cc_check'] = 0
        else:
            post_test_process_dict['cc_check'] = 1
        status = infraVerify.postTestVerification(post_test_process_dict)

        if status['status'] == 0:
            self.failed(reason=status['logs'])
        else:
            self.passed(reason=status['logs'])

class TC007_vxlan_access_port_flap(aetest.Testcase):
    ###    This is description for my testcase two

    @aetest.setup
    def setup(self):
        pass

    @aetest.test
    def Trigger4AccessPortFlap(self):
        log.info(banner("Starting Trigger2PortFlap @ 8"))

        op1 = leaf1.execute("show vpc brief | json-pretty")
        op = json.loads(op1)
        Po = op["TABLE_vpc"]["ROW_vpc"]["vpc-ifindex"]

        for uut in [leaf1, leaf2]:
            if not TriggerPortFlap(uut, Po, 3):
                log.info("TriggerPortFlap failed @ 4")
                self.failed()

        countdown(16)

    # =============================================================================================================================#
    @aetest.test
    def VERIFY_IXIA_TRAFFIC(self):
        """ IXIA_CONFIGURATION subsection: Verify IXIA Traffic """

        time.sleep(20)

        if ixLib.verify_traffic(2, 3) == 0:
            log.debug("Traffic Verification failed")
            self.failed("Traffic Verification failed", goto=['cleanup'])
        else:
            log.info("Traffic Verification Passed")

    # =============================================================================================================================#
    @aetest.cleanup
    def cleanup(self):
        """ testcase clean up """

        post_test_process_dict['cc_check'] = 0
        status = infraVerify.postTestVerification(post_test_process_dict)

        if status['status'] == 0:
            self.failed(reason=status['logs'])
        else:
            self.passed(reason=status['logs'])

class TC008_vxlan_vpc_mct_flap(aetest.Testcase):
    ###    This is description for my testcase two

    @aetest.setup
    def setup(self):
        pass

    @aetest.test
    def TriggerVpcMctflap(self):
        log.info(banner("Starting TriggerVpcMctflap vpc"))

        op1= leaf1.execute("show vpc brief | json-pretty")
        op=json.loads(op1)
        Po=op["TABLE_peerlink"]["ROW_peerlink"]["peerlink-ifindex"]

        for uut in [leaf1,leaf2]:
            if not TriggerPortFlap(uut,Po,3):
                log.info("TriggerPortFlap failed @ 4")
                self.failed()

        countdown(20)

    # =============================================================================================================================#
    @aetest.test
    def VERIFY_IXIA_TRAFFIC(self):
        """ IXIA_CONFIGURATION subsection: Verify IXIA Traffic """

        time.sleep(20)

        if ixLib.verify_traffic(2,3) == 0:
            log.debug("Traffic Verification failed")
            self.failed("Traffic Verification failed", goto=['cleanup'])
        else:
            log.info("Traffic Verification Passed")

    # =============================================================================================================================#
    @aetest.cleanup
    def cleanup(self):
        """ testcase clean up """

        post_test_process_dict['cc_check'] = 0
        status = infraVerify.postTestVerification(post_test_process_dict)

        if status['status'] == 0:
            self.failed(reason=status['logs'])
        else:
            self.passed(reason=status['logs'])

class TC009_vxlan_vpc_member_flap(aetest.Testcase):
    ###    This is description for my testcase two

    @aetest.setup
    def setup(self):
        pass

    @aetest.test
    def TriggerVpcmemflap(self):
        log.info(banner("Starting Trigger12NveShutNoshut vpc"))

        op1= leaf1.execute("show vpc brief | json-pretty")
        op=json.loads(op1)
        Po=op["TABLE_vpc"]["ROW_vpc"]["vpc-ifindex"][2:]

        if not vPCMemberFlap(vpc_uut_list,[str(Po)]):
            self.failed()

        countdown(20)

    # =============================================================================================================================#
    @aetest.test
    def VERIFY_IXIA_TRAFFIC(self):
        """ IXIA_CONFIGURATION subsection: Verify IXIA Traffic """

        time.sleep(20)

        if ixLib.verify_traffic(2,3) == 0:
            log.debug("Traffic Verification failed")
            self.failed("Traffic Verification failed", goto=['cleanup'])
        else:
            log.info("Traffic Verification Passed")

    # =============================================================================================================================#
    @aetest.cleanup
    def cleanup(self):
        """ testcase clean up """

        post_test_process_dict['cc_check'] = 0
        status = infraVerify.postTestVerification(post_test_process_dict)

        if status['status'] == 0:
            self.failed(reason=status['logs'])
        else:
            self.passed(reason=status['logs'])

class TC010_vxlan_access_port_flap_SA_Vtep(aetest.Testcase):
    ###    This is description for my testcase two

    @aetest.setup
    def setup(self):
        pass

    @aetest.test
    def Trigger4AccessPortFlap(self):
        log.info(banner("Starting Trigger2PortFlap @ 8"))

        intf = ''
        op1= leaf3.execute("show spanning-tree")
        for line in op1.splitlines():
            if 'Eth' in line:
                intf = line.split()[0]

        for uut in [leaf3]:
            if not TriggerPortFlap(uut,intf,3):
                log.info("TriggerPortFlap failed @ 4")
                self.failed()

        countdown(16)

    # =============================================================================================================================#
    @aetest.test
    def VERIFY_IXIA_TRAFFIC(self):
        """ IXIA_CONFIGURATION subsection: Verify IXIA Traffic """

        time.sleep(20)

        if ixLib.verify_traffic(2,3) == 0:
            log.debug("Traffic Verification failed")
            self.failed("Traffic Verification failed", goto=['cleanup'])
        else:
            log.info("Traffic Verification Passed")

    # =============================================================================================================================#
    @aetest.cleanup
    def cleanup(self):
        """ testcase clean up """

        if post_test_process_dict['eor_flag']:
            post_test_process_dict['cc_check'] = 0
        else:
            post_test_process_dict['cc_check'] = 1
        status = infraVerify.postTestVerification(post_test_process_dict)

        if status['status'] == 0:
            self.failed(reason=status['logs'])
        else:
            self.passed(reason=status['logs'])

class TC011_vxlan_Core_flap(aetest.Testcase):
    ###    This is description for my testcase two

    @aetest.setup
    def setup(self):
        pass

    @aetest.test
    def Trigger5CoreIfFlap(self):
        log.info(banner("Starting TriggerCoreIfFlap222 @ 8"))

        #if not TriggerCoreIfFlap222(leaf_uut_list):
        for uut in leaf_uut_list:
            if not L3InterfaceFlap(uut,igp):
                log.info("L3InterfaceFlap failed @ 4")
                self.failed()

        countdown(18)

    # =============================================================================================================================#
    @aetest.test
    def VERIFY_IXIA_TRAFFIC(self):
        """ IXIA_CONFIGURATION subsection: Verify IXIA Traffic """

        time.sleep(20)

        if ixLib.verify_traffic(2,3) == 0:
            log.debug("Traffic Verification failed")
            self.failed("Traffic Verification failed", goto=['cleanup'])
        else:
            log.info("Traffic Verification Passed")

    # =============================================================================================================================#
    @aetest.cleanup
    def cleanup(self):
        """ testcase clean up """

        post_test_process_dict['cc_check'] = 0
        status = infraVerify.postTestVerification(post_test_process_dict)

        if status['status'] == 0:
            self.failed(reason=status['logs'])
        else:
            self.passed(reason=status['logs'])

class TC012_vxlan_ClearIpRoute(aetest.Testcase):
    ###    This is description for my testcase two

    @aetest.setup
    def setup(self):
        pass


    @aetest.test
    def Trigger6ClearIpRoute(self):
        log.info(banner("Starting TriggerClearIpRoute @ 11"))

        for uut in leaf_uut_list:
            for i in range(1,3):
                uut.execute("clear ip route *")

        countdown(16)

    # =============================================================================================================================#
    @aetest.test
    def VERIFY_IXIA_TRAFFIC(self):
        """ IXIA_CONFIGURATION subsection: Verify IXIA Traffic """

        time.sleep(20)

        if ixLib.verify_traffic(2,3) == 0:
            log.debug("Traffic Verification failed")
            self.failed("Traffic Verification failed", goto=['cleanup'])
        else:
            log.info("Traffic Verification Passed")

    # =============================================================================================================================#
    @aetest.cleanup
    def cleanup(self):
        """ testcase clean up """

        post_test_process_dict['cc_check'] = 0
        status = infraVerify.postTestVerification(post_test_process_dict)

        if status['status'] == 0:
            self.failed(reason=status['logs'])
        else:
            self.passed(reason=status['logs'])

class TC013_vxlan_clearIpMoute(aetest.Testcase):
    ###    This is description for my testcase two

    @aetest.setup
    def setup(self):
        pass

    @aetest.test
    def Trigger7ClearIpMroute(self):
        log.info(banner("Starting TriggerClearIpRoute @ 11"))

        for uut in leaf_uut_list:
            for i in range(1,3):
                uut.execute("clear ip mroute *")

        countdown(16)

    # =============================================================================================================================#
    @aetest.test
    def VERIFY_IXIA_TRAFFIC(self):
        """ IXIA_CONFIGURATION subsection: Verify IXIA Traffic """

        time.sleep(20)

        if ixLib.verify_traffic(2,3) == 0:
            log.debug("Traffic Verification failed")
            self.failed("Traffic Verification failed", goto=['cleanup'])
        else:
            log.info("Traffic Verification Passed")

    # =============================================================================================================================#
    @aetest.cleanup
    def cleanup(self):
        """ testcase clean up """

        post_test_process_dict['cc_check'] = 0
        status = infraVerify.postTestVerification(post_test_process_dict)

        if status['status'] == 0:
            self.failed(reason=status['logs'])
        else:
            self.passed(reason=status['logs'])

class TC014_vxlan_clear_ospf_Neigh(aetest.Testcase):
    ###    This is description for my testcase two

    @aetest.setup
    def setup(self):
        pass


    @aetest.test
    def Trigger8ClearOspfNeigh(self):
        log.info(banner("Starting TriggerClearOspfNeigh @ 11"))

        for uut in leaf_uut_list:
            for i in range(1,3):
                if 'ospf' in igp:
                    uut.execute("clear ip ospf neighbor *")
                elif 'isis' in igp:
                    uut.execute("clear isis adjacency *")

        countdown(16)

    # =============================================================================================================================#
    @aetest.test
    def VERIFY_IXIA_TRAFFIC(self):
        """ IXIA_CONFIGURATION subsection: Verify IXIA Traffic """

        time.sleep(20)

        if ixLib.verify_traffic(2,3) == 0:
            log.debug("Traffic Verification failed")
            self.failed("Traffic Verification failed", goto=['cleanup'])
        else:
            log.info("Traffic Verification Passed")

    # =============================================================================================================================#
    @aetest.cleanup
    def cleanup(self):
        """ testcase clean up """

        post_test_process_dict['cc_check'] = 0
        status = infraVerify.postTestVerification(post_test_process_dict)

        if status['status'] == 0:
            self.failed(reason=status['logs'])
        else:
            self.passed(reason=status['logs'])

class TC015_vxlan_Clear_IP_Bgp(aetest.Testcase):
    ###    This is description for my testcase two

    @aetest.setup
    def setup(self):
        pass

    @aetest.test
    def Trigger9ClearIpBgp(self):
        log.info(banner("Starting TriggerClearIpBgp @ 11"))

        for uut in leaf_uut_list:
            for i in range(1,3):
                uut.execute("clear ip bgp *")

        countdown(16)

    # =============================================================================================================================#
    @aetest.test
    def VERIFY_IXIA_TRAFFIC(self):
        """ IXIA_CONFIGURATION subsection: Verify IXIA Traffic """

        time.sleep(20)

        if ixLib.verify_traffic(2,3) == 0:
            log.debug("Traffic Verification failed")
            self.failed("Traffic Verification failed", goto=['cleanup'])
        else:
            log.info("Traffic Verification Passed")

    # =============================================================================================================================#
    @aetest.cleanup
    def cleanup(self):
        """ testcase clean up """

        if post_test_process_dict['eor_flag']:
            post_test_process_dict['cc_check'] = 0
        else:
            post_test_process_dict['cc_check'] = 1
        status = infraVerify.postTestVerification(post_test_process_dict)

        if status['status'] == 0:
            self.failed(reason=status['logs'])
        else:
            self.passed(reason=status['logs'])

class TC016_vxlan_Clear_Bgp_l2vpn(aetest.Testcase):
    ###    This is description for my testcase two

    @aetest.setup
    def setup(self):
        pass

    @aetest.test
    def Trigger10ClearBgpL2vpnEvpn(self):
        log.info(banner("Starting TriggerClearBgpL2vpnEvpn @ vpc"))

        for uut in vpc_uut_list:
            for i in range(1,3):
                uut.execute("clear bgp l2vpn evpn *")

        countdown(16)

    # =============================================================================================================================#
    @aetest.test
    def VERIFY_IXIA_TRAFFIC(self):
        """ IXIA_CONFIGURATION subsection: Verify IXIA Traffic """

        time.sleep(20)

        if ixLib.verify_traffic(2,3) == 0:
            log.debug("Traffic Verification failed")
            self.failed("Traffic Verification failed", goto=['cleanup'])
        else:
            log.info("Traffic Verification Passed")

    # =============================================================================================================================#
    @aetest.cleanup
    def cleanup(self):
        """ testcase clean up """

        post_test_process_dict['cc_check'] = 0
        status = infraVerify.postTestVerification(post_test_process_dict)

        if status['status'] == 0:
            self.failed(reason=status['logs'])
        else:
            self.passed(reason=status['logs'])

class TC017_vxlan_Spine_ClearIpRoute(aetest.Testcase):
    ###    This is description for my testcase two

    @aetest.setup
    def setup(self):
        pass

    @aetest.test
    def Trigger6ClearIpRoute(self):
        log.info(banner("Starting TriggerClearIpRoute @ 11"))

        for uut in spine_uut_list:
            for i in range(1,3):
                uut.execute("clear ip route *")

        countdown(16)

    # =============================================================================================================================#
    @aetest.test
    def VERIFY_IXIA_TRAFFIC(self):
        """ IXIA_CONFIGURATION subsection: Verify IXIA Traffic """

        time.sleep(20)

        if ixLib.verify_traffic(2,3) == 0:
            log.debug("Traffic Verification failed")
            self.failed("Traffic Verification failed", goto=['cleanup'])
        else:
            log.info("Traffic Verification Passed")

    # =============================================================================================================================#
    @aetest.cleanup
    def cleanup(self):
        """ testcase clean up """

        post_test_process_dict['cc_check'] = 0
        status = infraVerify.postTestVerification(post_test_process_dict)

        if status['status'] == 0:
            self.failed(reason=status['logs'])
        else:
            self.passed(reason=status['logs'])

class TC018_vxlan_Spine_ClearIpMoute(aetest.Testcase):
    ###    This is description for my testcase two

    @aetest.setup
    def setup(self):
        pass

    @aetest.test
    def Trigger7ClearIpMroute(self):
        log.info(banner("Starting TriggerClearIpRoute @ 11"))

        for uut in spine_uut_list:
            for i in range(1,3):
                uut.execute("clear ip mroute *")

        countdown(16)

    # =============================================================================================================================#
    @aetest.test
    def VERIFY_IXIA_TRAFFIC(self):
        """ IXIA_CONFIGURATION subsection: Verify IXIA Traffic """

        time.sleep(20)

        if ixLib.verify_traffic(2,3) == 0:
            log.debug("Traffic Verification failed")
            self.failed("Traffic Verification failed", goto=['cleanup'])
        else:
            log.info("Traffic Verification Passed")

    # =============================================================================================================================#
    @aetest.cleanup
    def cleanup(self):
        """ testcase clean up """

        post_test_process_dict['cc_check'] = 0
        status = infraVerify.postTestVerification(post_test_process_dict)

        if status['status'] == 0:
            self.failed(reason=status['logs'])
        else:
            self.passed(reason=status['logs'])

class TC019_vxlan_Spine_Clear_IGP_Neigh(aetest.Testcase):
    ###    This is description for my testcase two

    @aetest.setup
    def setup(self):
        pass

    @aetest.test
    def Trigger8ClearOspfNeigh(self):
        log.info(banner("Starting TriggerClearOspfNeigh @ 11"))

        for uut in spine_uut_list:
            for i in range(1,3):
                if 'ospf' in igp:
                    uut.execute("clear ip ospf neighbor *")
                elif 'isis' in igp:
                    uut.execute("clear isis adjacency *")

        countdown(16)

    # =============================================================================================================================#
    @aetest.test
    def VERIFY_IXIA_TRAFFIC(self):
        """ IXIA_CONFIGURATION subsection: Verify IXIA Traffic """

        time.sleep(20)

        if ixLib.verify_traffic(2,3) == 0:
            log.debug("Traffic Verification failed")
            self.failed("Traffic Verification failed", goto=['cleanup'])
        else:
            log.info("Traffic Verification Passed")

    # =============================================================================================================================#
    @aetest.cleanup
    def cleanup(self):
        """ testcase clean up """

        post_test_process_dict['cc_check'] = 0
        status = infraVerify.postTestVerification(post_test_process_dict)

        if status['status'] == 0:
            self.failed(reason=status['logs'])
        else:
            self.passed(reason=status['logs'])

class TC020_vxlan_Spine_Clear_IP_Bgp(aetest.Testcase):
    ###    This is description for my testcase two

    @aetest.setup
    def setup(self):
        pass

    @aetest.test
    def Trigger9ClearIpBgp(self):
        log.info(banner("Starting TriggerClearIpBgp @ 11"))

        for uut in spine_uut_list:
            for i in range(1,3):
                uut.execute("clear ip bgp *")

        countdown(16)

    # =============================================================================================================================#
    @aetest.test
    def VERIFY_IXIA_TRAFFIC(self):
        """ IXIA_CONFIGURATION subsection: Verify IXIA Traffic """

        time.sleep(20)

        if ixLib.verify_traffic(2,3) == 0:
            log.debug("Traffic Verification failed")
            self.failed("Traffic Verification failed", goto=['cleanup'])
        else:
            log.info("Traffic Verification Passed")

    # =============================================================================================================================#
    @aetest.cleanup
    def cleanup(self):
        """ testcase clean up """

        if post_test_process_dict['eor_flag']:
            post_test_process_dict['cc_check'] = 0
        else:
            post_test_process_dict['cc_check'] = 1
        status = infraVerify.postTestVerification(post_test_process_dict)

        if status['status'] == 0:
            self.failed(reason=status['logs'])
        else:
            self.passed(reason=status['logs'])

class TC021_vxlan_Spine_Clear_Bgp_l2vpn(aetest.Testcase):
    ###    This is description for my testcase two

    @aetest.setup
    def setup(self):
        pass

    @aetest.test
    def Trigger10ClearBgpL2vpnEvpn(self):
        log.info(banner("Starting Trigger10ClearBgpL2vpnEvpn @ spine"))
        for uut in spine_uut_list:
            for i in range(1,3):
                uut.execute("clear bgp l2vpn evpn *")
                #uut.execute(' clear bgp all *')
        countdown(16)

    # =============================================================================================================================#
    @aetest.test
    def VERIFY_IXIA_TRAFFIC(self):
        """ IXIA_CONFIGURATION subsection: Verify IXIA Traffic """

        time.sleep(20)

        if ixLib.verify_traffic(2,3) == 0:
            log.debug("Traffic Verification failed")
            self.failed("Traffic Verification failed", goto=['cleanup'])
        else:
            log.info("Traffic Verification Passed")

    # =============================================================================================================================#
    @aetest.cleanup
    def cleanup(self):
        """ testcase clean up """

        post_test_process_dict['cc_check'] = 0
        status = infraVerify.postTestVerification(post_test_process_dict)

        if status['status'] == 0:
            self.failed(reason=status['logs'])
        else:
            self.passed(reason=status['logs'])

class TC022_vxlan_Clear_ARP_MAC(aetest.Testcase):
    ###    This is description for my testcase two

    @aetest.setup
    def setup(self):
        pass

    @aetest.test
    def Trigger11ClearArpMac(self):
        log.info(banner("Starting Trigger11ClearArpMac @ vpc"))

        for uut in leaf_uut_list:
            for i in range(1,5):
                uut.execute("clear ip arp vrf all")
                uut.execute("clear mac add dy")

        countdown(16)

    # =============================================================================================================================#
    @aetest.test
    def VERIFY_IXIA_TRAFFIC(self):
        """ IXIA_CONFIGURATION subsection: Verify IXIA Traffic """

        time.sleep(20)

        if ixLib.verify_traffic(2,3) == 0:
            log.debug("Traffic Verification failed")
            self.failed("Traffic Verification failed", goto=['cleanup'])
        else:
            log.info("Traffic Verification Passed")

    # =============================================================================================================================#
    @aetest.cleanup
    def cleanup(self):
        """ testcase clean up """

        post_test_process_dict['cc_check'] = 0
        status = infraVerify.postTestVerification(post_test_process_dict)

        if status['status'] == 0:
            self.failed(reason=status['logs'])
        else:
            self.passed(reason=status['logs'])

class TC023_vxlan_Clear_ARP_MAC(aetest.Testcase):
    ###    This is description for my testcase two

    @aetest.setup
    def setup(self):
        pass

    @aetest.test
    def Trigger11ClearArpMac(self):
        log.info(banner("Starting Trigger11ClearArpMac "))
        for uut in leaf_uut_list:
            for i in range(1,5):
                uut.execute("clear ip arp vrf all")
                uut.execute("clear mac add dy")

        countdown(16)

    # =============================================================================================================================#
    @aetest.test
    def VERIFY_IXIA_TRAFFIC(self):
        """ IXIA_CONFIGURATION subsection: Verify IXIA Traffic """

        time.sleep(20)

        if ixLib.verify_traffic(2,3) == 0:
            log.debug("Traffic Verification failed")
            self.failed("Traffic Verification failed", goto=['cleanup'])
        else:
            log.info("Traffic Verification Passed")

    # =============================================================================================================================#
    @aetest.cleanup
    def cleanup(self):
        """ testcase clean up """

        post_test_process_dict['cc_check'] = 0
        status = infraVerify.postTestVerification(post_test_process_dict)

        if status['status'] == 0:
            self.failed(reason=status['logs'])
        else:
            self.passed(reason=status['logs'])

class TC023_1_vxlan_change_igmp_snooping_querier_vpc_vtep(aetest.Testcase):

    @aetest.setup
    def setup(self):
        pass

    # =============================================================================================================================#
    @aetest.test
    def configure_igmp_snooping(self):
        for uut in leaf_uut_list:
            uut.configure('''
                ip igmp snooping
                ip igmp snooping vxlan
            ''')

        end_vlan = int(vlan_start) + int(vlan_vni_scale)
        leaf3.configure('''
            no vlan configuration '''+str(vlan_start)+'''-'''+str(end_vlan)+'''
        ''', timeout=500)

        leaf1.configure('''
            vlan configuration '''+str(vlan_start)+'''-'''+str(end_vlan)+'''
                ip igmp snooping querier 1.1.1.1
        ''', timeout=500)

        leaf2.configure('''
            vlan configuration '''+str(vlan_start)+'''-'''+str(end_vlan)+'''
                ip igmp snooping querier 1.1.1.1
        ''', timeout=500)

        countdown(240)

    # Work around for IXIA issue
    # # =============================================================================================================================#
    # @aetest.test
    # def RESTART_IXIA_PROTOCOLS(self):
    #     """ IXIA_CONFIGURATION subsection: Configure IXIA IGMP Groups """

    #     # _result_ = ixiahlt.test_control(action='configure_all')
    #     # print(_result_)

    #     proto_result = ixLib.stop_protocols()
    #     if proto_result == 0:
    #         log.debug("Stopped Protocols failed")
    #         self.errored("Stopped Protocols failed")
    #     else:
    #         log.info("Stopped Protocols Successfully")

    #     time.sleep(30)

    #     proto_result = ixLib.start_protocols()
    #     if proto_result == 0:
    #         log.debug("Starting Protocols failed")
    #         self.errored("Starting Protocols failed")
    #     else:
    #         log.info("Started Protocols Successfully")

    #     time.sleep(60)

    # =============================================================================================================================#
    @aetest.test
    def VERIFY_IXIA_TRAFFIC(self):
        """ IXIA_CONFIGURATION subsection: Verify IXIA Traffic """

        time.sleep(20)

        if ixLib.verify_traffic(2, 3) == 0:
            log.debug("Traffic Verification failed")
            self.failed("Traffic Verification failed", goto=['cleanup'])
        else:
            log.info("Traffic Verification Passed")

    # =============================================================================================================================#
    @aetest.cleanup
    def cleanup(self):
        """ testcase clean up """

        post_test_process_dict['cc_check'] = 0
        status = infraVerify.postTestVerification(post_test_process_dict)

        if status['status'] == 0:
            self.failed(reason=status['logs'])
        else:
            self.passed(reason=status['logs'])

class TC024_vxlan_bgp_restart(aetest.Testcase):
    ###    This is description for my testcase two

    @aetest.setup
    def setup(self):
        pass

    @aetest.test
    def Trigger1BgpProcRestart(self):
        log.info(banner("Starting TriggerBgpProcRestart for Broadcast Encap Traffic"))

        for uut in vpc_leaf_uut_list:
            ProcessRestart(uut,'bgp')

        countdown(16)

    # =============================================================================================================================#
    @aetest.test
    def VERIFY_IXIA_TRAFFIC(self):
        """ IXIA_CONFIGURATION subsection: Verify IXIA Traffic """

        time.sleep(20)

        if ixLib.verify_traffic(2,3) == 0:
            log.debug("Traffic Verification failed")
            self.failed("Traffic Verification failed", goto=['cleanup'])
        else:
            log.info("Traffic Verification Passed")

    # =============================================================================================================================#
    @aetest.cleanup
    def cleanup(self):
        """ testcase clean up """

        post_test_process_dict['cc_check'] = 0
        status = infraVerify.postTestVerification(post_test_process_dict)

        if status['status'] == 0:
            self.failed(reason=status['logs'])
        else:
            self.passed(reason=status['logs'])

class TC025_vxlan_ethpm_restart(aetest.Testcase):
    ###    This is description for my testcase two

    @aetest.setup
    def setup(self):
        pass

    @aetest.test
    def Trigger1BgpProcRestart(self):
        log.info(banner("Starting TriggerBgpProcRestart for Broadcast Encap Traffic"))

        for uut in vpc_leaf_uut_list:
            ProcessRestart(uut,'ethpm')

        countdown(16)

    # =============================================================================================================================#
    @aetest.test
    def VERIFY_IXIA_TRAFFIC(self):
        """ IXIA_CONFIGURATION subsection: Verify IXIA Traffic """

        time.sleep(20)

        if ixLib.verify_traffic(2,3) == 0:
            log.debug("Traffic Verification failed")
            self.failed("Traffic Verification failed", goto=['cleanup'])
        else:
            log.info("Traffic Verification Passed")

    # =============================================================================================================================#
    @aetest.cleanup
    def cleanup(self):
        """ testcase clean up """

        if post_test_process_dict['eor_flag']:
            post_test_process_dict['cc_check'] = 0
        else:
            post_test_process_dict['cc_check'] = 1
        status = infraVerify.postTestVerification(post_test_process_dict)

        if status['status'] == 0:
            self.failed(reason=status['logs'])
        else:
            self.passed(reason=status['logs'])

class TC026_vxlan_vlan_mgr_restart(aetest.Testcase):
    ###    This is description for my testcase two

    @aetest.setup
    def setup(self):
        pass

    @aetest.test
    def Trigger1BgpProcRestart(self):
        log.info(banner("Starting TriggerBgpProcRestart for Broadcast Encap Traffic"))

        for uut in vpc_leaf_uut_list:
            ProcessRestart(uut,'vlan_mgr')

        countdown(16)

    # =============================================================================================================================#
    @aetest.test
    def VERIFY_IXIA_TRAFFIC(self):
        """ IXIA_CONFIGURATION subsection: Verify IXIA Traffic """

        time.sleep(20)

        if ixLib.verify_traffic(2,3) == 0:
            log.debug("Traffic Verification failed")
            self.failed("Traffic Verification failed", goto=['cleanup'])
        else:
            log.info("Traffic Verification Passed")

    # =============================================================================================================================#
    @aetest.cleanup
    def cleanup(self):
        """ testcase clean up """

        post_test_process_dict['cc_check'] = 0
        status = infraVerify.postTestVerification(post_test_process_dict)

        if status['status'] == 0:
            self.failed(reason=status['logs'])
        else:
            self.passed(reason=status['logs'])

class TC027_vxlan_nve_restart_vpc(aetest.Testcase):
    ###    This is description for my testcase two

    @aetest.setup
    def setup(self):
        pass

    @aetest.test
    def Trigger2NveProcRestart(self):
        log.info(banner("Starting TriggerNveProcRestart for Broadcast Encap Traffic"))

        for uut in vpc_leaf_uut_list:
            ProcessRestart(uut,'nve')

        countdown(30)

    # =============================================================================================================================#
    @aetest.test
    def VERIFY_IXIA_TRAFFIC(self):
        """ IXIA_CONFIGURATION subsection: Verify IXIA Traffic """

        time.sleep(20)

        if ixLib.verify_traffic(2,3) == 0:
            log.debug("Traffic Verification failed")
            self.failed("Traffic Verification failed", goto=['cleanup'])
        else:
            log.info("Traffic Verification Passed")

    # =============================================================================================================================#
    @aetest.cleanup
    def cleanup(self):
        """ testcase clean up """

        post_test_process_dict['cc_check'] = 0
        status = infraVerify.postTestVerification(post_test_process_dict)

        if status['status'] == 0:
            self.failed(reason=status['logs'])
        else:
            self.passed(reason=status['logs'])

class TC028_vxlan_pim_restart_vpc(aetest.Testcase):
    ###    This is description for my testcase two

    @aetest.setup
    def setup(self):
        pass

    @aetest.test
    def TriggerPimRestart(self):
        log.info(banner("Starting TriggerNveProcRestart for Broadcast Encap Traffic"))

        for uut in vpc_leaf_uut_list:
            op = uut.execute('show module | incl active')
            if 'FX' not in op:
                for i in range(1,2):
                    ProcessRestart(uut,'pim')

        countdown(16)

    # =============================================================================================================================#
    @aetest.test
    def VERIFY_IXIA_TRAFFIC(self):
        """ IXIA_CONFIGURATION subsection: Verify IXIA Traffic """

        time.sleep(20)

        if ixLib.verify_traffic(2,3) == 0:
            log.debug("Traffic Verification failed")
            self.failed("Traffic Verification failed", goto=['cleanup'])
        else:
            log.info("Traffic Verification Passed")

    # =============================================================================================================================#
    @aetest.cleanup
    def cleanup(self):
        """ testcase clean up """

        post_test_process_dict['cc_check'] = 0
        status = infraVerify.postTestVerification(post_test_process_dict)

        if status['status'] == 0:
            self.failed(reason=status['logs'])
        else:
            self.passed(reason=status['logs'])

class TC029_toggle_ip_forward_l3vni(aetest.Testcase):
    ###    This is description for my testcase two

    @aetest.setup
    def setup(self):
        pass

    @aetest.test
    def ToggleIPForward(self):
        log.info(banner("Starting TriggerNveProcRestart for Broadcast Encap Traffic"))

        vlan = routed_vlan
        for i in range(0,routing_vlan_scale):
            for uut in vpc_leaf_uut_list:
                uut.configure('''
                    interface vlan '''+str(vlan)+'''
                        no ip forward
                        no ipv6 forward
                ''', timeout=500)
                sleep(5)
                uut.configure('''
                    interface vlan '''+str(vlan)+'''
                        ip forward
                        ipv6 forward
                ''', timeout=500)
            vlan += 1

        countdown(16)

    # =============================================================================================================================#
    @aetest.test
    def VERIFY_IXIA_TRAFFIC(self):
        """ IXIA_CONFIGURATION subsection: Verify IXIA Traffic """

        time.sleep(20)

        if ixLib.verify_traffic(2,3) == 0:
            log.debug("Traffic Verification failed")
            self.failed("Traffic Verification failed", goto=['cleanup'])
        else:
            log.info("Traffic Verification Passed")

    # =============================================================================================================================#
    @aetest.cleanup
    def cleanup(self):
        """ testcase clean up """

        post_test_process_dict['cc_check'] = 0
        status = infraVerify.postTestVerification(post_test_process_dict)

        if status['status'] == 0:
            self.failed(reason=status['logs'])
        else:
            self.passed(reason=status['logs'])

class TC030_toggle_ip_pim_sparsemode_l3vni(aetest.Testcase):
    ###    This is description for my testcase two

    @aetest.setup
    def setup(self):
        pass

    @aetest.test
    def ToggleIPPIMSparseMode(self):
        log.info(banner("Starting TriggerNveProcRestart for Broadcast Encap Traffic"))

        vlan = routed_vlan
        for i in range(0, routing_vlan_scale):
            for uut in vpc_leaf_uut_list:
                uut.configure('''
                    interface vlan ''' + str(vlan) + '''
                        no ip pim sparse-mode
                ''', timeout=500)
                sleep(5)
                uut.configure('''
                    interface vlan ''' + str(vlan) + '''
                        ip pim sparse-mode
                ''', timeout=500)
            vlan += 1

        countdown(16)

    # =============================================================================================================================#
    @aetest.test
    def VERIFY_IXIA_TRAFFIC(self):
        """ IXIA_CONFIGURATION subsection: Verify IXIA Traffic """

        time.sleep(20)

        if ixLib.verify_traffic(2, 3) == 0:
            log.debug("Traffic Verification failed")
            self.failed("Traffic Verification failed", goto=['cleanup'])
        else:
            log.info("Traffic Verification Passed")

    # =============================================================================================================================#
    @aetest.cleanup
    def cleanup(self):
        """ testcase clean up """

        if post_test_process_dict['eor_flag']:
            post_test_process_dict['cc_check'] = 0
        else:
            post_test_process_dict['cc_check'] = 1
        status = infraVerify.postTestVerification(post_test_process_dict)

        if status['status'] == 0:
            self.failed(reason=status['logs'])
        else:
            self.passed(reason=status['logs'])

class TC031_vxlan_nve_Bounce_Vpc(aetest.Testcase):
    ###    This is description for my testcase two

    @aetest.setup
    def setup(self):
        pass

    @aetest.test
    def Trigger12NveShutNoshut(self):
        log.info(banner("Starting Trigger12NveShutNoshut vpc"))

        for uut in vpc_leaf_uut_list:
            cmd1 = \
                """
                vpc domain 1
                    layer3 peer-router
                interface nve1
                    advertise virtual-rmac
                """
            uut.configure(cmd1, timeout=600)
        for uut in vpc_leaf_uut_list:
            cmd1 = \
                """
                interface nve 1
                shut
                """
            uut.configure(cmd1, timeout=600)
        countdown(5)
        for uut in vpc_leaf_uut_list:
            cmd2 = \
                """
                interface nve 1
                no shut
                """
            uut.configure(cmd2, timeout=600)

        countdown(350)

    # =============================================================================================================================#
    @aetest.test
    def VERIFY_IXIA_TRAFFIC(self):
        """ IXIA_CONFIGURATION subsection: Verify IXIA Traffic """

        time.sleep(20)

        if ixLib.verify_traffic(2,3) == 0:
            log.debug("Traffic Verification failed")
            self.failed("Traffic Verification failed", goto=['cleanup'])
        else:
            log.info("Traffic Verification Passed")

    # =============================================================================================================================#
    @aetest.cleanup
    def cleanup(self):
        """ testcase clean up """

        for uut in vpc_leaf_uut_list:
            cmd2 = \
                """
                interface nve 1
                no shut
                """
            uut.configure(cmd2, timeout=600)

        countdown(350)

        post_test_process_dict['cc_check'] = 0
        status = infraVerify.postTestVerification(post_test_process_dict)

        if status['status'] == 0:
            self.failed(reason=status['logs'])
        else:
            self.passed(reason=status['logs'])

class TC032_vxlan_nve_Bounce_SA(aetest.Testcase):
    ###    This is description for my testcase two

    @aetest.setup
    def setup(self):
        pass

    @aetest.test
    def Trigger12NveShutNoshut(self):
        log.info(banner("Starting Trigger12NveShutNoshut vpc"))


        cmd1 = \
            """
            interface nve 1
            shut
            """
        leaf3.configure(cmd1, timeout=600)
        countdown(5)

        cmd2 = \
            """
            interface nve 1
            no shut
            """
        leaf3.configure(cmd2, timeout=600)

        countdown(350)

    # =============================================================================================================================#
    @aetest.test
    def VERIFY_IXIA_TRAFFIC(self):
        """ IXIA_CONFIGURATION subsection: Verify IXIA Traffic """

        time.sleep(20)

        if ixLib.verify_traffic(2,3) == 0:
            log.debug("Traffic Verification failed")
            self.failed("Traffic Verification failed", goto=['cleanup'])
        else:
            log.info("Traffic Verification Passed")

    # =============================================================================================================================#
    @aetest.cleanup
    def cleanup(self):
        """ testcase clean up """

        cmd2 = \
            """
            interface nve 1
            no shut
            """
        leaf3.configure(cmd2, timeout=600)

        countdown(350)

        post_test_process_dict['cc_check'] = 0
        status = infraVerify.postTestVerification(post_test_process_dict)

        if status['status'] == 0:
            self.failed(reason=status['logs'])
        else:
            self.passed(reason=status['logs'])

class TC033_vxlan_VLAN_Bounce_VPC(aetest.Testcase):
    ###    This is description for my testcase two

    @aetest.setup
    def setup(self):
        pass

    @aetest.test
    def Trigger15VlanShutNoshut(self):
        log.info(banner("Starting Trigger15VlanShutNoshut vpc"))
        for uut in vpc_leaf_uut_list:
            vlanshut = \
            """
            vlan 1001-1005
            shut
            exit
            """
            uut.configure(vlanshut, timeout=600)

        countdown(15)

        for uut in vpc_leaf_uut_list:
            vlannoshut = \
            """
            vlan 1001-1005
            no shut
            exit
            """
            uut.configure(vlannoshut, timeout=600)

        countdown(300)

    # =============================================================================================================================#
    @aetest.test
    def VERIFY_IXIA_TRAFFIC(self):
        """ IXIA_CONFIGURATION subsection: Verify IXIA Traffic """

        time.sleep(20)

        if ixLib.verify_traffic(2,3) == 0:
            log.debug("Traffic Verification failed")
            self.failed("Traffic Verification failed", goto=['cleanup'])
        else:
            log.info("Traffic Verification Passed")

    # =============================================================================================================================#
    @aetest.cleanup
    def cleanup(self):
        """ testcase clean up """

        post_test_process_dict['cc_check'] = 0
        status = infraVerify.postTestVerification(post_test_process_dict)

        for uut in vpc_leaf_uut_list:
            vlannoshut = \
            """
            vlan 1001-1005
            no shut
            exit
            """
            uut.configure(vlannoshut, timeout=600)

        countdown(300)

        if status['status'] == 0:
            self.failed(reason=status['logs'])
        else:
            self.passed(reason=status['logs'])

class TC034_vxlan_nve_loop_shutnoshut(aetest.Testcase):
    ###    This is description for my testcase two

    @aetest.setup
    def setup(self):
        pass

    @aetest.test
    def TriggerNveloopShutNoshut(self):
        log.info(banner("Starting Trigger12NveShutNoshut vpc"))

        for uut in vpc_leaf_uut_list:
            op = uut.execute("show run interface nve1 | incl loopback")
            log.info("++++++++++++++++++++++++++++++++++++++++++++")
            log.info("OP is %r", op)
            log.info("++++++++++++++++++++++++++++++++++++++++++++")
            intf_num = ''
            if 'loop' in str(op):
                intf_num = (findall(r'\d+', str(op)))[0]

            cmd1 = \
                """
                interface loopback{intf_num}
                shut
                sleep 5
                interface loopback{intf_num}
                no shut
                """
            uut.configure(cmd1.format(intf_num=intf_num), timeout=600)

        countdown(200)

    # =============================================================================================================================#
    @aetest.test
    def VERIFY_IXIA_TRAFFIC(self):
        """ IXIA_CONFIGURATION subsection: Verify IXIA Traffic """

        time.sleep(20)

        if ixLib.verify_traffic(2, 3) == 0:
            log.debug("Traffic Verification failed")
            self.failed("Traffic Verification failed", goto=['cleanup'])
        else:
            log.info("Traffic Verification Passed")

    # =============================================================================================================================#
    @aetest.cleanup
    def cleanup(self):
        """ testcase clean up """

        post_test_process_dict['cc_check'] = 0
        status = infraVerify.postTestVerification(post_test_process_dict)

        if status['status'] == 0:
            self.failed(reason=status['logs'])
        else:
            self.passed(reason=status['logs'])

class TC035_vxlan_one_vlan_remove_add(aetest.Testcase):
    ###    This is description for my testcase two

    @aetest.setup
    def setup(self):
        pass

    @aetest.test
    def TriggerVlan_remove_add(self):
        log.info(banner("Starting Trigger12NveShutNoshut vpc"))

        for uut in vpc_uut_list:
            vlan_conf_string = uut.execute("show run vlan 1002")
            # log.info('Removing adding VLAN,vlan conf string is %r',vlan_range)

            remove_vlan = \
                """
                no vlan 1002
                """
            uut.configure(remove_vlan, timeout=300)
            countdown(5)
            uut.configure(vlan_conf_string, timeout=300)

        countdown(120)

    # =============================================================================================================================#
    @aetest.test
    def VERIFY_IXIA_TRAFFIC(self):
        """ IXIA_CONFIGURATION subsection: Verify IXIA Traffic """

        time.sleep(20)

        if ixLib.verify_traffic(2, 3) == 0:
            log.debug("Traffic Verification failed")
            self.failed("Traffic Verification failed", goto=['cleanup'])
        else:
            log.info("Traffic Verification Passed")

    # =============================================================================================================================#
    @aetest.cleanup
    def cleanup(self):
        """ testcase clean up """

        if post_test_process_dict['eor_flag']:
            post_test_process_dict['cc_check'] = 0
        else:
            post_test_process_dict['cc_check'] = 1
        status = infraVerify.postTestVerification(post_test_process_dict)

        if status['status'] == 0:
            self.failed(reason=status['logs'])
        else:
            self.passed(reason=status['logs'])

class TC036_vxlan_L3_Vni_remove_Add(aetest.Testcase):
    ###    This is description for my testcase two

    @aetest.setup
    def setup(self):
        pass

    @aetest.test
    def L3VniRemoveAdd(self):
        log.info(banner("Starting Trigger12NveShutNoshut vpc"))

        # result_list = []
        # orphan_handle_list = []
        if not NveL3VniRemoveAdd(vpc_uut_list):
            log.info("Failed NveL3VniRemoveAdd @ 2")

        countdown(300)

    # # =============================================================================================================================#
    # @aetest.test
    # def RESTART_IXIA_PROTOCOLS(self):
    #     """ IXIA_CONFIGURATION subsection: Configure IXIA IGMP Groups """

    #     proto_result = ixLib.stop_protocols()
    #     if proto_result == 0:
    #         log.debug("Stopped Protocols failed")
    #         self.errored("Stopped Protocols failed")
    #     else:
    #         log.info("Stopped Protocols Successfully")

    #     time.sleep(30)

    #     proto_result = ixLib.start_protocols()
    #     if proto_result == 0:
    #         log.debug("Starting Protocols failed")
    #         self.errored("Starting Protocols failed")
    #     else:
    #         log.info("Started Protocols Successfully")

    #     time.sleep(60)

    # =============================================================================================================================#
    @aetest.test
    def VERIFY_IXIA_TRAFFIC(self):
        """ IXIA_CONFIGURATION subsection: Verify IXIA Traffic """

        time.sleep(20)

        if ixLib.verify_traffic(2, 3) == 0:
            log.debug("Traffic Verification failed")
            self.failed("Traffic Verification failed", goto=['cleanup'])
        else:
            log.info("Traffic Verification Passed")

    # =============================================================================================================================#
    @aetest.cleanup
    def cleanup(self):
        """ testcase clean up """

        post_test_process_dict['cc_check'] = 0
        status = infraVerify.postTestVerification(post_test_process_dict)

        if status['status'] == 0:
            self.failed(reason=status['logs'])
        else:
            self.passed(reason=status['logs'])

class TC037_vxlan_Mcast_Group_Change(aetest.Testcase):
    ###    This is description for my testcase two

    @aetest.setup
    def setup(self):
        pass

    @aetest.test
    def NveMcastGroupChange(self):

        leaf1.configure('delete bootflash:int_nve_cfg.txt no', timeout=600)
        leaf2.configure('delete bootflash:int_nve_cfg.txt no', timeout=600)
        leaf3.configure('delete bootflash:int_nve_cfg.txt no', timeout=600)

        leaf1.configure('show run int nve 1 > bootflash:int_nve_cfg.txt', timeout=600)
        leaf2.configure('show run int nve 1 > bootflash:int_nve_cfg.txt', timeout=600)
        leaf3.configure('show run int nve 1 > bootflash:int_nve_cfg.txt', timeout=600)

        if "225.5" in leaf1.execute("show nve vni"):
            if not NveMcastGroupChange(leaf_uut_list):
                log.info("Failed NveMcastGroupChange @ 2")

            countdown(300)

    # # =============================================================================================================================#
    # @aetest.test
    # def RESTART_IXIA_PROTOCOLS(self):
    #     """ IXIA_CONFIGURATION subsection: Configure IXIA IGMP Groups """

    #     # _result_ = ixiahlt.test_control(action='configure_all')
    #     # print(_result_)

    #     proto_result = ixLib.stop_protocols()
    #     if proto_result == 0:
    #         log.debug("Stopped Protocols failed")
    #         self.errored("Stopped Protocols failed")
    #     else:
    #         log.info("Stopped Protocols Successfully")

    #     time.sleep(30)

    #     proto_result = ixLib.start_protocols()
    #     if proto_result == 0:
    #         log.debug("Starting Protocols failed")
    #         self.errored("Starting Protocols failed")
    #     else:
    #         log.info("Started Protocols Successfully")

    #     time.sleep(60)

    # =============================================================================================================================#
    @aetest.test
    def VERIFY_IXIA_TRAFFIC(self):
        """ IXIA_CONFIGURATION subsection: Verify IXIA Traffic """

        time.sleep(20)

        if ixLib.verify_traffic(2, 3) == 0:
            log.debug("Traffic Verification failed")
            self.failed("Traffic Verification failed")
        else:
            log.info("Traffic Verification Passed")

    @aetest.test
    def RevertNveMcastGroupChange(self):

        leaf1.configure('no int nve 1', timeout=600)
        leaf2.configure('no int nve 1', timeout=600)
        leaf3.configure('no int nve 1', timeout=600)

        sleep(10)

        leaf1.configure('copy bootflash:int_nve_cfg.txt run echo', timeout=600)
        leaf2.configure('copy bootflash:int_nve_cfg.txt run echo', timeout=600)
        leaf3.configure('copy bootflash:int_nve_cfg.txt run echo', timeout=600)

        countdown(350)

    # # =============================================================================================================================#
    # @aetest.test
    # def RESTART_IXIA_PROTOCOLS_post_revert(self):
    #     """ IXIA_CONFIGURATION subsection: Configure IXIA IGMP Groups """

    #     # _result_ = ixiahlt.test_control(action='configure_all')
    #     # print(_result_)

    #     proto_result = ixLib.stop_protocols()
    #     if proto_result == 0:
    #         log.debug("Stopped Protocols failed")
    #         self.errored("Stopped Protocols failed")
    #     else:
    #         log.info("Stopped Protocols Successfully")

    #     time.sleep(30)

    #     proto_result = ixLib.start_protocols()
    #     if proto_result == 0:
    #         log.debug("Starting Protocols failed")
    #         self.errored("Starting Protocols failed")
    #     else:
    #         log.info("Started Protocols Successfully")

    #     time.sleep(60)

    # =============================================================================================================================#
    @aetest.test
    def VERIFY_IXIA_TRAFFIC_post_revert(self):
        """ IXIA_CONFIGURATION subsection: Verify IXIA Traffic """

        time.sleep(20)

        if ixLib.verify_traffic(2, 3) == 0:
            log.debug("Traffic Verification failed")
            self.failed("Traffic Verification failed")
        else:
            log.info("Traffic Verification Passed")

    # =============================================================================================================================#
    @aetest.cleanup
    def cleanup(self):
        """ testcase clean up """

        post_test_process_dict['cc_check'] = 0
        status = infraVerify.postTestVerification(post_test_process_dict)

        if status['status'] == 0:
            self.failed(reason=status['logs'])
        else:
            self.passed(reason=status['logs'])

class TC038_vxlan_Vn_Segment_remove_Add(aetest.Testcase):
    ###    This is description for my testcase two

    @aetest.setup
    def setup(self):
        pass

    @aetest.test
    def VnSegmentRemoveAdd(self):
        log.info(banner("Starting Trigger12NveShutNoshut vpc"))
        if not VnSegmentRemoveAdd(leaf_uut_list, vlan_start):
            log.info("Failed NveL3VniRemoveAdd @ 2")

        countdown(350)

    # # =============================================================================================================================#
    # @aetest.test
    # def RESTART_IXIA_PROTOCOLS(self):
    #     """ IXIA_CONFIGURATION subsection: Configure IXIA IGMP Groups """

    #     # _result_ = ixiahlt.test_control(action='configure_all')
    #     # print(_result_)

    #     proto_result = ixLib.stop_protocols()
    #     if proto_result == 0:
    #         log.debug("Stopped Protocols failed")
    #         self.errored("Stopped Protocols failed")
    #     else:
    #         log.info("Stopped Protocols Successfully")

    #     time.sleep(30)

    #     proto_result = ixLib.start_protocols()
    #     if proto_result == 0:
    #         log.debug("Starting Protocols failed")
    #         self.errored("Starting Protocols failed")
    #     else:
    #         log.info("Started Protocols Successfully")

    #     time.sleep(60)

    # =============================================================================================================================#
    @aetest.test
    def VERIFY_IXIA_TRAFFIC(self):
        """ IXIA_CONFIGURATION subsection: Verify IXIA Traffic """

        time.sleep(20)

        if ixLib.verify_traffic(2, 3) == 0:
            log.debug("Traffic Verification failed")
            self.failed("Traffic Verification failed", goto=['cleanup'])
        else:
            log.info("Traffic Verification Passed")

    # =============================================================================================================================#
    @aetest.cleanup
    def cleanup(self):
        """ testcase clean up """

        post_test_process_dict['cc_check'] = 0
        status = infraVerify.postTestVerification(post_test_process_dict)

        if status['status'] == 0:
            self.failed(reason=status['logs'])
        else:
            self.passed(reason=status['logs'])

# class TC039_vxlan_IR_Bgp_to_Mcast_change(aetest.Testcase):
#     ###    This is description for my testcase two
#
#     @aetest.setup
#     def setup(self):
#         pass
#
#     @aetest.test
#     def ChangeIRtoMcastUUT(self):
#
#         leaf1.configure('delete bootflash:int_nve_cfg.txt no', timeout=600)
#         leaf2.configure('delete bootflash:int_nve_cfg.txt no', timeout=600)
#         leaf3.configure('delete bootflash:int_nve_cfg.txt no', timeout=600)
#
#         leaf1.configure('show run int nve 1 > bootflash:int_nve_cfg.txt', timeout=600)
#         leaf2.configure('show run int nve 1 > bootflash:int_nve_cfg.txt', timeout=600)
#         leaf3.configure('show run int nve 1 > bootflash:int_nve_cfg.txt', timeout=600)
#
#         if "UnicastBGP" in leaf1.execute("show nve vni"):
#             if not ChangeIRtoMcast(leaf_uut_list, ir_mode, 128, 8, '225.5.0.1'):
#                 log.info("Failed NveMcastGroupChange @ 2")
#
#             countdown(240)
#
#     # # =============================================================================================================================#
#     # @aetest.test
#     # def RESTART_IXIA_PROTOCOLS(self):
#     #     """ IXIA_CONFIGURATION subsection: Configure IXIA IGMP Groups """
#
#     #     # _result_ = ixiahlt.test_control(action='configure_all')
#     #     # print(_result_)
#
#     #     proto_result = ixLib.stop_protocols()
#     #     if proto_result == 0:
#     #         log.debug("Stopped Protocols failed")
#     #         self.errored("Stopped Protocols failed")
#     #     else:
#     #         log.info("Stopped Protocols Successfully")
#
#     #     time.sleep(30)
#
#     #     proto_result = ixLib.start_protocols()
#     #     if proto_result == 0:
#     #         log.debug("Starting Protocols failed")
#     #         self.errored("Starting Protocols failed")
#     #     else:
#     #         log.info("Started Protocols Successfully")
#
#     #     time.sleep(60)
#
#     # =============================================================================================================================#
#     @aetest.test
#     def VERIFY_IXIA_TRAFFIC(self):
#         """ IXIA_CONFIGURATION subsection: Verify IXIA Traffic """
#
#         time.sleep(20)
#
#         if ixLib.verify_traffic(2, 3) == 0:
#             log.debug("Traffic Verification failed")
#             self.failed("Traffic Verification failed", goto=['cleanup'])
#         else:
#             log.info("Traffic Verification Passed")
#
#     @aetest.test
#     def RevertChangeIRtoMcastUUT(self):
#
#         leaf1.configure('no int nve 1', timeout=600)
#         leaf2.configure('no int nve 1', timeout=600)
#         leaf3.configure('no int nve 1', timeout=600)
#
#         sleep(10)
#
#         leaf1.configure('copy bootflash:int_nve_cfg.txt run echo', timeout=600)
#         leaf2.configure('copy bootflash:int_nve_cfg.txt run echo', timeout=600)
#         leaf3.configure('copy bootflash:int_nve_cfg.txt run echo', timeout=600)
#
#         countdown(350)
#
#     # # =============================================================================================================================#
#     # @aetest.test
#     # def RESTART_IXIA_PROTOCOLS_post_revert(self):
#     #     """ IXIA_CONFIGURATION subsection: Configure IXIA IGMP Groups """
#
#     #     # _result_ = ixiahlt.test_control(action='configure_all')
#     #     # print(_result_)
#
#     #     proto_result = ixLib.stop_protocols()
#     #     if proto_result == 0:
#     #         log.debug("Stopped Protocols failed")
#     #         self.errored("Stopped Protocols failed")
#     #     else:
#     #         log.info("Stopped Protocols Successfully")
#
#     #     time.sleep(30)
#
#     #     proto_result = ixLib.start_protocols()
#     #     if proto_result == 0:
#     #         log.debug("Starting Protocols failed")
#     #         self.errored("Starting Protocols failed")
#     #     else:
#     #         log.info("Started Protocols Successfully")
#
#     #     time.sleep(60)
#
#     # =============================================================================================================================#
#     @aetest.test
#     def VERIFY_IXIA_TRAFFIC_post_revert(self):
#         """ IXIA_CONFIGURATION subsection: Verify IXIA Traffic """
#
#         time.sleep(20)
#
#         if ixLib.verify_traffic(2, 3) == 0:
#             log.debug("Traffic Verification failed")
#             self.failed("Traffic Verification failed", goto=['cleanup'])
#         else:
#             log.info("Traffic Verification Passed")
#
#     # =============================================================================================================================#
#     @aetest.cleanup
#     def cleanup(self):
#         """ testcase clean up """
#
#         post_test_process_dict['cc_check'] = 0
#         status = infraVerify.postTestVerification(post_test_process_dict)
#
#         if status['status'] == 0:
#             self.failed(reason=status['logs'])
#         else:
#             self.passed(reason=status['logs'])

class TC040_vxlan_vlan_remove_add(aetest.Testcase):
    ###    This is description for my testcase two

    @aetest.setup
    def setup(self):
        pass

    @aetest.test
    def vlanVniRemove(self):
        log.info(banner("Starting TriggerClearIpBgp @ 11"))
        vlan_count_to_remove_add = int(vlan_vni_scale * .1)
        #vlan_2 = vlan_start + vlan_count_to_remove_add
        for uut in [leaf1, leaf2, leaf3]:
            try:
                # vlan_vni_remove(uut,vlan_start,vni,vlan_count_to_remove_add)
                vlan_remove(uut, vlan_start, vlan_count_to_remove_add)
            except:
                log.info("vlan Remove failed")

        log.info(" %r vlans Removed", vlan_count_to_remove_add)
        countdown(10)
        for uut in [leaf1, leaf2, leaf3]:
            try:
                vlan_vni_configure(uut, vlan_start, vni, vlan_count_to_remove_add + 1)
            except:
                log.info("vlan Remove failed")
        log.info(" %r vlan/vni's Added", vlan_count_to_remove_add)
        countdown(350)

    # # =============================================================================================================================#
    # @aetest.test
    # def RESTART_IXIA_PROTOCOLS(self):
    #     """ IXIA_CONFIGURATION subsection: Configure IXIA IGMP Groups """

    #     proto_result = ixLib.stop_protocols()
    #     if proto_result == 0:
    #         log.debug("Stopped Protocols failed")
    #         self.errored("Stopped Protocols failed")
    #     else:
    #         log.info("Stopped Protocols Successfully")

    #     time.sleep(30)

    #     proto_result = ixLib.start_protocols()
    #     if proto_result == 0:
    #         log.debug("Starting Protocols failed")
    #         self.errored("Starting Protocols failed")
    #     else:
    #         log.info("Started Protocols Successfully")

    #     time.sleep(60)

    # =============================================================================================================================#
    @aetest.test
    def VERIFY_IXIA_TRAFFIC(self):
        """ IXIA_CONFIGURATION subsection: Verify IXIA Traffic """

        time.sleep(20)

        if ixLib.verify_traffic(2, 3) == 0:
            log.debug("Traffic Verification failed")
            self.failed("Traffic Verification failed", goto=['cleanup'])
        else:
            log.info("Traffic Verification Passed")

    # =============================================================================================================================#
    @aetest.cleanup
    def cleanup(self):
        """ testcase clean up """

        if post_test_process_dict['eor_flag']:
            post_test_process_dict['cc_check'] = 0
        else:
            post_test_process_dict['cc_check'] = 1
        status = infraVerify.postTestVerification(post_test_process_dict)

        if status['status'] == 0:
            self.failed(reason=status['logs'])
        else:
            self.passed(reason=status['logs'])

class TC041_vxlan_config_replace_VPC1(aetest.Testcase):
    ###    This is description for my testcase two

    @aetest.setup
    def setup(self):
        pass

    @aetest.test
    def ConfigReplacevpc(self):
        log.info(banner("Starting TC05_vxlan_Traffic_Config_Replace"))

        for uut in [vpc_uut_list[0]]:
            uut.configure('delete bootflash:{name} no'.format(name='cr_replace_test'), timeout=600)
            uut.configure('copy run bootflash:{name}'.format(name='cr_replace_test'), timeout=600)
            countdown(2)
            uut.configure("no feature nv overlay", timeout=600)
            countdown(2)
            op = uut.configure('configure replace bootflash:{name}'.format(name='cr_replace_test'), timeout=300)
            if "successfully" not in op:
                self.failed()

        countdown(300)

    # # =============================================================================================================================#
    # @aetest.test
    # def RESTART_IXIA_PROTOCOLS(self):
    #     """ IXIA_CONFIGURATION subsection: Configure IXIA IGMP Groups """

    #     proto_result = ixLib.stop_protocols()
    #     if proto_result == 0:
    #         log.debug("Stopped Protocols failed")
    #         self.errored("Stopped Protocols failed")
    #     else:
    #         log.info("Stopped Protocols Successfully")

    #     time.sleep(30)

    #     proto_result = ixLib.start_protocols()
    #     if proto_result == 0:
    #         log.debug("Starting Protocols failed")
    #         self.errored("Starting Protocols failed")
    #     else:
    #         log.info("Started Protocols Successfully")

    #     time.sleep(60)

    # =============================================================================================================================#
    @aetest.test
    def VERIFY_IXIA_TRAFFIC(self):
        """ IXIA_CONFIGURATION subsection: Verify IXIA Traffic """

        time.sleep(20)

        if ixLib.verify_traffic(2, 3) == 0:
            log.debug("Traffic Verification failed")
            self.failed("Traffic Verification failed", goto=['cleanup'])
        else:
            log.info("Traffic Verification Passed")

    # =============================================================================================================================#
    @aetest.cleanup
    def cleanup(self):
        """ testcase clean up """

        post_test_process_dict['cc_check'] = 0
        status = infraVerify.postTestVerification(post_test_process_dict)

        if status['status'] == 0:
            self.failed(reason=status['logs'])
        else:
            self.passed(reason=status['logs'])

class TC042_vxlan_config_replace_VPC2(aetest.Testcase):
    ###    This is description for my testcase two

    @aetest.setup
    def setup(self):
        pass

    @aetest.test
    def ConfigReplacevpc(self):
        log.info(banner("Starting TC05_vxlan_Traffic_Config_Replace"))

        for uut in [vpc_uut_list[1]]:
            uut.configure('delete bootflash:{name} no'.format(name='cr_replace_test'), timeout=600)
            uut.configure('copy run bootflash:{name}'.format(name='cr_replace_test'), timeout=600)
            countdown(2)
            uut.configure("no feature nv overlay", timeout=600)
            countdown(2)
            op = uut.configure('configure replace bootflash:{name}'.format(name='cr_replace_test'), timeout=300)
            if "successfully" not in op:
                self.failed()

        countdown(300)

    # # =============================================================================================================================#
    # @aetest.test
    # def RESTART_IXIA_PROTOCOLS(self):
    #     """ IXIA_CONFIGURATION subsection: Configure IXIA IGMP Groups """

    #     proto_result = ixLib.stop_protocols()
    #     if proto_result == 0:
    #         log.debug("Stopped Protocols failed")
    #         self.errored("Stopped Protocols failed")
    #     else:
    #         log.info("Stopped Protocols Successfully")

    #     time.sleep(30)

    #     proto_result = ixLib.start_protocols()
    #     if proto_result == 0:
    #         log.debug("Starting Protocols failed")
    #         self.errored("Starting Protocols failed")
    #     else:
    #         log.info("Started Protocols Successfully")

    #     time.sleep(60)

    # =============================================================================================================================#
    @aetest.test
    def VERIFY_IXIA_TRAFFIC(self):
        """ IXIA_CONFIGURATION subsection: Verify IXIA Traffic """

        time.sleep(20)

        if ixLib.verify_traffic(2, 3) == 0:
            log.debug("Traffic Verification failed")
            self.failed("Traffic Verification failed", goto=['cleanup'])
        else:
            log.info("Traffic Verification Passed")

    # =============================================================================================================================#
    @aetest.cleanup
    def cleanup(self):
        """ testcase clean up """

        post_test_process_dict['cc_check'] = 0
        status = infraVerify.postTestVerification(post_test_process_dict)

        if status['status'] == 0:
            self.failed(reason=status['logs'])
        else:
            self.passed(reason=status['logs'])

class TC043_vxlan_arp_supp_remove_add_vpc(aetest.Testcase):
    ###    This is description for my testcase two

    @aetest.setup
    def setup(self):
        pass

    @aetest.test
    def remove_arp_suppression(self):
        log.info(banner("Starting remove_arp_suppression"))

        for uut in leaf_uut_list:
            arp_supp_remove_final(uut)

        countdown(60)

    @aetest.test
    def add_arp_suppression(self):
        log.info(banner("Starting add_arp_suppression"))

        for uut in leaf_uut_list:
            arp_supp_add_final(uut)

        countdown(180)

    # =============================================================================================================================#
    @aetest.test
    def VERIFY_IXIA_TRAFFIC_post_readd(self):
        """ IXIA_CONFIGURATION subsection: Verify IXIA Traffic """

        time.sleep(20)

        if ixLib.verify_traffic(2, 3) == 0:
            log.debug("Traffic Verification failed")
            self.failed("Traffic Verification failed")
        else:
            log.info("Traffic Verification Passed")

    # =============================================================================================================================#
    @aetest.cleanup
    def cleanup(self):
        """ testcase clean up """

        post_test_process_dict['cc_check'] = 0
        status = infraVerify.postTestVerification(post_test_process_dict)

        if status['status'] == 0:
            self.failed(reason=status['logs'])
        else:
            self.passed(reason=status['logs'])

class TC044_vxlan_vpc_leaf1_reload(aetest.Testcase):
    ###    This is description for my testcase two

    @aetest.setup
    def setup(self):
        pass

    @aetest.test
    def leaf1Reload(self):
        log.info(banner("Starting TriggerClearIpBgp @ 11"))

        leaf1.configure("copy r s", timeout=600)

        # Perform Device Reload
        result = infraTrigger.switchReload(leaf1)
        if result:
            log.info("ASCII Reload completed Successfully")
        else:
            log.debug("ASCII Reload Failed")
            self.failed("ASCII Reload Failed", goto=['cleanup'])

        log.info("Waiting for 120 sec for the topology to come UP")
        time.sleep(350)

    # # =============================================================================================================================#
    # @aetest.test
    # def RESTART_IXIA_PROTOCOLS(self):
    #     """ IXIA_CONFIGURATION subsection: Configure IXIA IGMP Groups """

    #     # _result_ = ixiahlt.test_control(action='configure_all')
    #     # print(_result_)

    #     proto_result = ixLib.stop_protocols()
    #     if proto_result == 0:
    #         log.debug("Stopped Protocols failed")
    #         self.errored("Stopped Protocols failed")
    #     else:
    #         log.info("Stopped Protocols Successfully")

    #     time.sleep(30)

    #     proto_result = ixLib.start_protocols()
    #     if proto_result == 0:
    #         log.debug("Starting Protocols failed")
    #         self.errored("Starting Protocols failed")
    #     else:
    #         log.info("Started Protocols Successfully")

    #     time.sleep(60)

    # =============================================================================================================================#
    @aetest.test
    def VERIFY_IXIA_TRAFFIC(self):
        """ IXIA_CONFIGURATION subsection: Verify IXIA Traffic """

        time.sleep(20)

        if ixLib.verify_traffic(2,3) == 0:
            log.debug("Traffic Verification failed")
            self.failed("Traffic Verification failed", goto=['cleanup'])
        else:
            log.info("Traffic Verification Passed")

    # =============================================================================================================================#
    @aetest.cleanup
    def cleanup(self):
        """ testcase clean up """

        post_test_process_dict['cc_check'] = 0
        status = infraVerify.postTestVerification(post_test_process_dict)

        if status['status'] == 0:
            self.failed(reason=status['logs'])
        else:
            self.passed(reason=status['logs'])

class TC045_vxlan_vpc_leaf2_reload(aetest.Testcase):
    ###    This is description for my testcase two

    @aetest.setup
    def setup(self):
        pass

    @aetest.test
    def leaf2Reload(self):
        log.info(banner("Starting TriggerClearIpBgp @ 11"))

        leaf2.configure("copy r s", timeout=600)

        # Perform Device Reload
        result = infraTrigger.switchReload(leaf2)
        if result:
            log.info("ASCII Reload completed Successfully")
        else:
            log.debug("ASCII Reload Failed")
            self.failed("ASCII Reload Failed", goto=['cleanup'])

        log.info("Waiting for 120 sec for the topology to come UP")
        time.sleep(350)

    # # =============================================================================================================================#
    # @aetest.test
    # def RESTART_IXIA_PROTOCOLS(self):
    #     """ IXIA_CONFIGURATION subsection: Configure IXIA IGMP Groups """

    #     # _result_ = ixiahlt.test_control(action='configure_all')
    #     # print(_result_)

    #     proto_result = ixLib.stop_protocols()
    #     if proto_result == 0:
    #         log.debug("Stopped Protocols failed")
    #         self.errored("Stopped Protocols failed")
    #     else:
    #         log.info("Stopped Protocols Successfully")

    #     time.sleep(30)

    #     proto_result = ixLib.start_protocols()
    #     if proto_result == 0:
    #         log.debug("Starting Protocols failed")
    #         self.errored("Starting Protocols failed")
    #     else:
    #         log.info("Started Protocols Successfully")

    #     time.sleep(60)

    # =============================================================================================================================#
    @aetest.test
    def VERIFY_IXIA_TRAFFIC(self):
        """ IXIA_CONFIGURATION subsection: Verify IXIA Traffic """

        time.sleep(20)

        if ixLib.verify_traffic(2,3) == 0:
            log.debug("Traffic Verification failed")
            self.failed("Traffic Verification failed", goto=['cleanup'])
        else:
            log.info("Traffic Verification Passed")

    # =============================================================================================================================#
    @aetest.cleanup
    def cleanup(self):
        """ testcase clean up """

        if post_test_process_dict['eor_flag']:
            post_test_process_dict['cc_check'] = 0
        else:
            post_test_process_dict['cc_check'] = 1
        status = infraVerify.postTestVerification(post_test_process_dict)

        if status['status'] == 0:
            self.failed(reason=status['logs'])
        else:
            self.passed(reason=status['logs'])

class TC046_vxlan_std_leaf3_reload(aetest.Testcase):
    ###    This is description for my testcase two

    @aetest.setup
    def setup(self):
        pass

    @aetest.test
    def leaf3Reload(self):
        log.info(banner("Starting TriggerClearIpBgp @ 11"))

        leaf3.configure("copy r s", timeout=600)

        # Perform Device Reload
        result = infraTrigger.switchReload(leaf3)
        if result:
            log.info("ASCII Reload completed Successfully")
        else:
            log.debug("ASCII Reload Failed")
            self.failed("ASCII Reload Failed", goto=['cleanup'])

        log.info("Waiting for 120 sec for the topology to come UP")
        time.sleep(350)

    # # =============================================================================================================================#
    # @aetest.test
    # def RESTART_IXIA_PROTOCOLS(self):
    #     """ IXIA_CONFIGURATION subsection: Configure IXIA IGMP Groups """

    #     # _result_ = ixiahlt.test_control(action='configure_all')
    #     # print(_result_)

    #     proto_result = ixLib.stop_protocols()
    #     if proto_result == 0:
    #         log.debug("Stopped Protocols failed")
    #         self.errored("Stopped Protocols failed")
    #     else:
    #         log.info("Stopped Protocols Successfully")

    #     time.sleep(30)

    #     proto_result = ixLib.start_protocols()
    #     if proto_result == 0:
    #         log.debug("Starting Protocols failed")
    #         self.errored("Starting Protocols failed")
    #     else:
    #         log.info("Started Protocols Successfully")

    #     time.sleep(60)

    # =============================================================================================================================#
    @aetest.test
    def VERIFY_IXIA_TRAFFIC(self):
        """ IXIA_CONFIGURATION subsection: Verify IXIA Traffic """

        time.sleep(20)

        if ixLib.verify_traffic(2,3) == 0:
            log.debug("Traffic Verification failed")
            self.failed("Traffic Verification failed", goto=['cleanup'])
        else:
            log.info("Traffic Verification Passed")

    # =============================================================================================================================#
    @aetest.cleanup
    def cleanup(self):
        """ testcase clean up """

        post_test_process_dict['cc_check'] = 0
        status = infraVerify.postTestVerification(post_test_process_dict)

        if status['status'] == 0:
            self.failed(reason=status['logs'])
        else:
            self.passed(reason=status['logs'])

class TC047_vxlan_vpc_leaf1_LC_reload(aetest.Testcase):
    ###    This is description for my testcase two

    @aetest.setup
    def setup(self):
        pass

    @aetest.test
    def leaf1LCReload(self):

        fail_flag = []
        status_msgs = ''

        log.info("Passing LEAF-1 Interfaces ->")
        log.info(leaf1_interfaces)
        leaf1_mod_list = infraVerify.getModuleFromInt(leaf1, leaf1_interfaces)
        for module in leaf1_mod_list:
            mod_arg_dict = {
                'dut'                       : leaf1,
                'mod_num'                   : module,
                'exclude_log_check_pattern' : 'ERROR_VLANS_SUSPENDED|ERROR_VLANS_REMOVED|IF_DOWN_INTERFACE_REMOVED'
            }

            reload_status = infraEORTrigger.verifyModuleReload(mod_arg_dict)
            if reload_status['status']:
                status_msgs += '''
                Reload of module '''+str(module)+''' : PASS
                ===========================================
                ''' + str(reload_status['logs'])
            else:
                fail_flag.append(0)
                status_msgs += '''
                Reload of module '''+str(module)+''' : FAIL
                ===========================================
                ''' + str(reload_status['logs'])

            sleep(300)
            status_msgs += '''
                    Traffic Check after Reload of module '''+str(module)+'''
                    --------------------------------------------------------
            '''
            if ixLib.verify_traffic(2,3) == 0:
                fail_flag.append(0)
                log.debug("Traffic Verification failed")
            else:
                log.info("Traffic Verification Passed")

        if 0 in fail_flag:
            self.failed(reason=status_msgs)
        else:
            self.passed(reason=status_msgs)

    # =============================================================================================================================#
    @aetest.cleanup
    def cleanup(self):
        """ testcase clean up """

        post_test_process_dict['cc_check'] = 0
        status = infraVerify.postTestVerification(post_test_process_dict)

        if status['status'] == 0:
            self.failed(reason=status['logs'])
        else:
            self.passed(reason=status['logs'])

class TC048_vxlan_vpc_leaf2_LC_reload(aetest.Testcase):
    ###    This is description for my testcase two

    @aetest.setup
    def setup(self):
        pass

    @aetest.test
    def leaf2LCReload(self):

        fail_flag = []
        status_msgs = ''

        leaf2_mod_list = infraVerify.getModuleFromInt(leaf2, leaf2_interfaces)
        for module in leaf2_mod_list:
            mod_arg_dict = {
                'dut'                       : leaf2,
                'mod_num'                   : module,
                'exclude_log_check_pattern' : 'ERROR_VLANS_SUSPENDED|ERROR_VLANS_REMOVED|IF_DOWN_INTERFACE_REMOVED'
            }

            reload_status = infraEORTrigger.verifyModuleReload(mod_arg_dict)
            if reload_status['status']:
                status_msgs += '''
                Reload of module ''' + str(module) + ''' : PASS
                ===========================================
                ''' + str(reload_status['logs'])
            else:
                fail_flag.append(0)
                status_msgs += '''
                Reload of module ''' + str(module) + ''' : FAIL
                ===========================================
                ''' + str(reload_status['logs'])

            sleep(300)
            status_msgs += '''
                    Traffic Check after Reload of module ''' + str(module) + '''
                    --------------------------------------------------------
            '''
            if ixLib.verify_traffic(2, 3) == 0:
                fail_flag.append(0)
                log.debug("Traffic Verification failed")
            else:
                log.info("Traffic Verification Passed")

        if 0 in fail_flag:
            self.failed(reason=status_msgs)
        else:
            self.passed(reason=status_msgs)

    # =============================================================================================================================#
    @aetest.cleanup
    def cleanup(self):
        """ testcase clean up """

        post_test_process_dict['cc_check'] = 0
        status = infraVerify.postTestVerification(post_test_process_dict)

        if status['status'] == 0:
            self.failed(reason=status['logs'])
        else:
            self.passed(reason=status['logs'])

class TC049_vxlan_vpc_leaf1_FM_all_reload(aetest.Testcase):

    @aetest.setup
    def setup(self):
        pass

    @aetest.test
    def leaf1FMReload(self):

        fail_flag = []
        status_msgs = ''

        leaf1_fm_mod_list = []
        fabric_mod_out = json.loads(leaf1.execute("show mod fabric | json"))['TABLE_modinfo']['ROW_modinfo']
        for fm_data in fabric_mod_out:
            leaf1_fm_mod_list.append(fm_data['modinf'])

        for module in leaf1_fm_mod_list:
            mod_arg_dict = {
                'dut'                       : leaf1,
                'mod_num'                   : module,
                'exclude_log_check_pattern' : 'ERROR_VLANS_SUSPENDED|ERROR_VLANS_REMOVED'
            }

            reload_status = infraEORTrigger.verifyModuleReload(mod_arg_dict)
            if reload_status['status']:
                status_msgs += '''
                Reload of FM ''' + str(module) + ''' : PASS
                ===========================================
                ''' + str(reload_status['logs'])
            else:
                fail_flag.append(0)
                status_msgs += '''
                Reload of FM ''' + str(module) + ''' : FAIL
                ===========================================
                ''' + str(reload_status['logs'])

        if 0 in fail_flag:
            self.failed(reason=status_msgs)
        else:
            self.passed(reason=status_msgs)

    # =============================================================================================================================#
    @aetest.test
    def VERIFY_IXIA_TRAFFIC(self):
        """ IXIA_CONFIGURATION subsection: Verify IXIA Traffic """

        time.sleep(20)

        if ixLib.verify_traffic(2, 3) == 0:
            log.debug("Traffic Verification failed")
            self.failed("Traffic Verification failed", goto=['cleanup'])
        else:
            log.info("Traffic Verification Passed")

    # =============================================================================================================================#
    @aetest.cleanup
    def cleanup(self):
        """ testcase clean up """

        if post_test_process_dict['eor_flag']:
            post_test_process_dict['cc_check'] = 0
        else:
            post_test_process_dict['cc_check'] = 1
        status = infraVerify.postTestVerification(post_test_process_dict)

        if status['status'] == 0:
            self.failed(reason=status['logs'])
        else:
            self.passed(reason=status['logs'])

class TC050_vxlan_vpc_leaf2_FM_all_reload(aetest.Testcase):
    ###    This is description for my testcase two

    @aetest.setup
    def setup(self):
        pass

    @aetest.test
    def leaf2FMReload(self):

        fail_flag = []
        status_msgs = ''

        leaf2_fm_mod_list = []
        fabric_mod_out = json.loads(leaf2.execute("show mod fabric | json"))['TABLE_modinfo']['ROW_modinfo']
        for fm_data in fabric_mod_out:
            leaf2_fm_mod_list.append(fm_data['modinf'])

        for module in leaf2_fm_mod_list:
            mod_arg_dict = {
                'dut'                       : leaf2,
                'mod_num'                   : module,
                'exclude_log_check_pattern' : 'ERROR_VLANS_SUSPENDED|ERROR_VLANS_REMOVED'
            }

            reload_status = infraEORTrigger.verifyModuleReload(mod_arg_dict)
            if reload_status['status']:
                status_msgs += '''
                Reload of FM ''' + str(module) + ''' : PASS
                ===========================================
                ''' + str(reload_status['logs'])
            else:
                fail_flag.append(0)
                status_msgs += '''
                Reload of FM ''' + str(module) + ''' : FAIL
                ===========================================
                ''' + str(reload_status['logs'])

        if 0 in fail_flag:
            self.failed(reason=status_msgs)
        else:
            self.passed(reason=status_msgs)

    # =============================================================================================================================#
    @aetest.test
    def VERIFY_IXIA_TRAFFIC(self):
        """ IXIA_CONFIGURATION subsection: Verify IXIA Traffic """

        time.sleep(20)

        if ixLib.verify_traffic(2, 3) == 0:
            log.debug("Traffic Verification failed")
            self.failed("Traffic Verification failed", goto=['cleanup'])
        else:
            log.info("Traffic Verification Passed")

    # =============================================================================================================================#
    @aetest.cleanup
    def cleanup(self):
        """ testcase clean up """

        post_test_process_dict['cc_check'] = 0
        status = infraVerify.postTestVerification(post_test_process_dict)

        if status['status'] == 0:
            self.failed(reason=status['logs'])
        else:
            self.passed(reason=status['logs'])

class TC051_vxlan_vpc_leaf1_SC_all_reload(aetest.Testcase):
    ###    This is description for my testcase two

    @aetest.setup
    def setup(self):
        pass

    @aetest.test
    def leaf1SCReload(self):

        fail_flag = []
        status_msgs = ''

        leaf1_sc_mod_list = []
        sc_mod_out = json.loads(leaf1.execute("show mod | json"))['TABLE_modwwninfo']['ROW_modwwninfo']
        for sc_data in sc_mod_out:
            if "SC" in sc_data['slottype']:
                leaf1_sc_mod_list.append(sc_data['modwwn'])

        for module in leaf1_sc_mod_list:
            mod_arg_dict = {
                'dut'                       : leaf1,
                'mod_num'                   : module,
                'exclude_log_check_pattern' : 'ERROR_VLANS_SUSPENDED|ERROR_VLANS_REMOVED'
            }

            reload_status = infraEORTrigger.verifyModuleReload(mod_arg_dict)
            if reload_status['status']:
                status_msgs += '''
                Reload of FM ''' + str(module) + ''' : PASS
                ===========================================
                ''' + str(reload_status['logs'])
            else:
                fail_flag.append(0)
                status_msgs += '''
                Reload of FM ''' + str(module) + ''' : FAIL
                ===========================================
                ''' + str(reload_status['logs'])

        if 0 in fail_flag:
            self.failed(reason=status_msgs)
        else:
            self.passed(reason=status_msgs)

    # =============================================================================================================================#
    @aetest.test
    def VERIFY_IXIA_TRAFFIC(self):
        """ IXIA_CONFIGURATION subsection: Verify IXIA Traffic """

        time.sleep(20)

        if ixLib.verify_traffic(2, 3) == 0:
            log.debug("Traffic Verification failed")
            self.failed("Traffic Verification failed", goto=['cleanup'])
        else:
            log.info("Traffic Verification Passed")

    # =============================================================================================================================#
    @aetest.cleanup
    def cleanup(self):
        """ testcase clean up """

        post_test_process_dict['cc_check'] = 0
        status = infraVerify.postTestVerification(post_test_process_dict)

        if status['status'] == 0:
            self.failed(reason=status['logs'])
        else:
            self.passed(reason=status['logs'])

class TC052_vxlan_vpc_leaf2_SC_all_reload(aetest.Testcase):
    ###    This is description for my testcase two

    @aetest.setup
    def setup(self):
        pass

    @aetest.test
    def leaf2SCReload(self):

        fail_flag = []
        status_msgs = ''

        leaf2_sc_mod_list = []
        sc_mod_out = json.loads(leaf2.execute("show mod | json"))['TABLE_modwwninfo']['ROW_modwwninfo']
        for sc_data in sc_mod_out:
            if "SC" in sc_data['slottype']:
                leaf2_sc_mod_list.append(sc_data['modwwn'])

        for module in leaf2_sc_mod_list:
            mod_arg_dict = {
                'dut'                       : leaf2,
                'mod_num'                   : module,
                'exclude_log_check_pattern' : 'ERROR_VLANS_SUSPENDED|ERROR_VLANS_REMOVED'
            }

            reload_status = infraEORTrigger.verifyModuleReload(mod_arg_dict)
            if reload_status['status']:
                status_msgs += '''
                Reload of FM ''' + str(module) + ''' : PASS
                ===========================================
                ''' + str(reload_status['logs'])
            else:
                fail_flag.append(0)
                status_msgs += '''
                Reload of FM ''' + str(module) + ''' : FAIL
                ===========================================
                ''' + str(reload_status['logs'])

        if 0 in fail_flag:
            self.failed(reason=status_msgs)
        else:
            self.passed(reason=status_msgs)

    # =============================================================================================================================#
    @aetest.test
    def VERIFY_IXIA_TRAFFIC(self):
        """ IXIA_CONFIGURATION subsection: Verify IXIA Traffic """

        time.sleep(20)

        if ixLib.verify_traffic(2, 3) == 0:
            log.debug("Traffic Verification failed")
            self.failed("Traffic Verification failed", goto=['cleanup'])
        else:
            log.info("Traffic Verification Passed")

    # =============================================================================================================================#
    @aetest.cleanup
    def cleanup(self):
        """ testcase clean up """

        post_test_process_dict['cc_check'] = 0
        status = infraVerify.postTestVerification(post_test_process_dict)

        if status['status'] == 0:
            self.failed(reason=status['logs'])
        else:
            self.passed(reason=status['logs'])

class TC053_vxlan_vpc_leaf1_SSO(aetest.Testcase):
    ###    This is description for my testcase two

    @aetest.setup
    def setup(self):
        pass

    @aetest.test
    def leaf1SSO(self):

        leaf1.configure("copy r s", timeout=600)

        # Perform Device Reload
        result = infraEORTrigger.verifyDeviceSSO({'dut':leaf1})
        if result:
            log.info("SSO completed Successfully")
        else:
            log.debug("SSO Failed")
            self.failed("SSO Failed", goto=['cleanup'])

        log.info("Waiting for 120 sec for the topology to come UP")
        time.sleep(300)

    # =============================================================================================================================#
    @aetest.test
    def VERIFY_IXIA_TRAFFIC(self):
        """ IXIA_CONFIGURATION subsection: Verify IXIA Traffic """

        time.sleep(20)

        if ixLib.verify_traffic(2,3) == 0:
            log.debug("Traffic Verification failed")
            self.failed("Traffic Verification failed", goto=['cleanup'])
        else:
            log.info("Traffic Verification Passed")

    # =============================================================================================================================#
    @aetest.cleanup
    def cleanup(self):
        """ testcase clean up """

        post_test_process_dict['cc_check'] = 0
        status = infraVerify.postTestVerification(post_test_process_dict)

        if status['status'] == 0:
            self.failed(reason=status['logs'])
        else:
            self.passed(reason=status['logs'])

class TC054_vxlan_vpc_leaf2_SSO(aetest.Testcase):
    ###    This is description for my testcase two

    @aetest.setup
    def setup(self):
        pass

    @aetest.test
    def leaf2SSO(self):

        leaf2.configure("copy r s")

        # Perform Device Reload
        result = infraEORTrigger.verifyDeviceSSO({'dut':leaf2})
        if result:
            log.info("SSO completed Successfully")
        else:
            log.debug("SSO Failed")
            self.failed("SSO Failed", goto=['cleanup'])

        log.info("Waiting for 120 sec for the topology to come UP")
        time.sleep(300)

    # =============================================================================================================================#
    @aetest.test
    def VERIFY_IXIA_TRAFFIC(self):
        """ IXIA_CONFIGURATION subsection: Verify IXIA Traffic """

        time.sleep(20)

        if ixLib.verify_traffic(2,3) == 0:
            log.debug("Traffic Verification failed")
            self.failed("Traffic Verification failed", goto=['cleanup'])
        else:
            log.info("Traffic Verification Passed")

    # =============================================================================================================================#
    @aetest.cleanup
    def cleanup(self):
        """ testcase clean up """

        post_test_process_dict['cc_check'] = 0
        status = infraVerify.postTestVerification(post_test_process_dict)

        if status['status'] == 0:
            self.failed(reason=status['logs'])
        else:
            self.passed(reason=status['logs'])

# class TC049_vxlan_std_leaf3_LC_reload(aetest.Testcase):
#     ###    This is description for my testcase two

#     @aetest.setup
#     def setup(self):
#         pass

#     @aetest.test
#     def leaf3LCReload(self):

#         fail_flag = []
#         status_msgs = ''

#         leaf3_mod_list = infraVerify.getModuleFromInt(leaf3, leaf3_interfaces)
#         for module in leaf3_mod_list:
#             mod_arg_dict = {
#                 'dut'                       : leaf3,
#                 'mod_num'                   : module,
#                 'exclude_log_check_pattern' : 'ERROR_VLANS_SUSPENDED|ERROR_VLANS_REMOVED|IF_DOWN_INTERFACE_REMOVED'
#             }

#             reload_status = infraEORTrigger.verifyModuleReload(mod_arg_dict)
#             if reload_status['status']:
#                 status_msgs += '''
#                 Reload of module ''' + str(module) + ''' : PASS
#                 ===========================================
#                 ''' + str(reload_status['logs'])
#             else:
#                 fail_flag.append(0)
#                 status_msgs += '''
#                 Reload of module ''' + str(module) + ''' : FAIL
#                 ===========================================
#                 ''' + str(reload_status['logs'])

#             sleep(300)
#             status_msgs += '''
#                     Traffic Check after Reload of module ''' + str(module) + '''
#                     --------------------------------------------------------
#             '''
#             if ixLib.verify_traffic(2, 3) == 0:
#                 fail_flag.append(0)
#                 log.debug("Traffic Verification failed")
#             else:
#                 log.info("Traffic Verification Passed")

#         if 0 in fail_flag:
#             self.failed(reason=status_msgs)
#         else:
#             self.passed(reason=status_msgs)

#     # =============================================================================================================================#
#     @aetest.cleanup
#     def cleanup(self):
#         """ testcase clean up """

#         post_test_process_dict['cc_check'] = 0
#         status = infraVerify.postTestVerification(post_test_process_dict)

#         if status['status'] == 0:
#             self.failed(reason=status['logs'])
#         else:
#             self.passed(reason=status['logs'])

# class TC052_vxlan_std_leaf3_FM_all_reload(aetest.Testcase):
#     ###    This is description for my testcase two

#     @aetest.setup
#     def setup(self):
#         pass

#     @aetest.test
#     def leaf3FMReload(self):

#         fail_flag = []
#         status_msgs = ''

#         leaf3_fm_mod_list = []
#         fabric_mod_out = json.loads(leaf3.execute("show mod fabric | json"))['TABLE_modinfo']['ROW_modinfo']
#         for fm_data in fabric_mod_out:
#             leaf3_fm_mod_list.append(fm_data['modinf'])

#         for module in leaf3_fm_mod_list:
#             mod_arg_dict = {
#                 'dut'                       : leaf3,
#                 'mod_num'                   : module,
#                 'exclude_log_check_pattern' : 'ERROR_VLANS_SUSPENDED|ERROR_VLANS_REMOVED'
#             }

#             reload_status = infraEORTrigger.verifyModuleReload(mod_arg_dict)
#             if reload_status['status']:
#                 status_msgs += '''
#                 Reload of FM ''' + str(module) + ''' : PASS
#                 ===========================================
#                 ''' + str(reload_status['logs'])
#             else:
#                 fail_flag.append(0)
#                 status_msgs += '''
#                 Reload of FM ''' + str(module) + ''' : FAIL
#                 ===========================================
#                 ''' + str(reload_status['logs'])

#         if 0 in fail_flag:
#             self.failed(reason=status_msgs)
#         else:
#             self.passed(reason=status_msgs)

#     # =============================================================================================================================#
#     @aetest.test
#     def VERIFY_IXIA_TRAFFIC(self):
#         """ IXIA_CONFIGURATION subsection: Verify IXIA Traffic """

#         time.sleep(20)

#         if ixLib.verify_traffic(2, 3) == 0:
#             log.debug("Traffic Verification failed")
#             self.failed("Traffic Verification failed", goto=['cleanup'])
#         else:
#             log.info("Traffic Verification Passed")

#     # =============================================================================================================================#
#     @aetest.cleanup
#     def cleanup(self):
#         """ testcase clean up """

#         post_test_process_dict['cc_check'] = 0
#         status = infraVerify.postTestVerification(post_test_process_dict)

#         if status['status'] == 0:
#             self.failed(reason=status['logs'])
#         else:
#             self.passed(reason=status['logs'])

# class TC055_vxlan_vpc_leaf3_SC_all_reload(aetest.Testcase):
#     ###    This is description for my testcase two

#     @aetest.setup
#     def setup(self):
#         pass

#     @aetest.test
#     def leaf3SCReload(self):

#         fail_flag = []
#         status_msgs = ''

#         leaf3_sc_mod_list = []
#         sc_mod_out = json.loads(leaf3.execute("show mod | json"))['TABLE_modwwninfo']['ROW_modwwninfo']
#         for sc_data in sc_mod_out:
#             if "SC" in sc_data['slottype']:
#                 leaf3_sc_mod_list.append(sc_data['modwwn'])

#         for module in leaf3_sc_mod_list:
#             mod_arg_dict = {
#                 'dut'                       : leaf3,
#                 'mod_num'                   : module,
#                 'exclude_log_check_pattern' : 'ERROR_VLANS_SUSPENDED|ERROR_VLANS_REMOVED'
#             }

#             reload_status = infraEORTrigger.verifyModuleReload(mod_arg_dict)
#             if reload_status['status']:
#                 status_msgs += '''
#                 Reload of FM ''' + str(module) + ''' : PASS
#                 ===========================================
#                 ''' + str(reload_status['logs'])
#             else:
#                 fail_flag.append(0)
#                 status_msgs += '''
#                 Reload of FM ''' + str(module) + ''' : FAIL
#                 ===========================================
#                 ''' + str(reload_status['logs'])

#         if 0 in fail_flag:
#             self.failed(reason=status_msgs)
#         else:
#             self.passed(reason=status_msgs)

#     # =============================================================================================================================#
#     @aetest.test
#     def VERIFY_IXIA_TRAFFIC(self):
#         """ IXIA_CONFIGURATION subsection: Verify IXIA Traffic """

#         time.sleep(20)

#         if ixLib.verify_traffic(2, 3) == 0:
#             log.debug("Traffic Verification failed")
#             self.failed("Traffic Verification failed", goto=['cleanup'])
#         else:
#             log.info("Traffic Verification Passed")

#     # =============================================================================================================================#
#     @aetest.cleanup
#     def cleanup(self):
#         """ testcase clean up """

#         if post_test_process_dict['eor_flag']:
#             post_test_process_dict['cc_check'] = 0
#         else:
#             post_test_process_dict['cc_check'] = 1
#         status = infraVerify.postTestVerification(post_test_process_dict)

#         if status['status'] == 0:
#             self.failed(reason=status['logs'])
#         else:
#             self.passed(reason=status['logs'])

# class TC058_vxlan_vpc_leaf3_SSO(aetest.Testcase):
#     ###    This is description for my testcase two

#     @aetest.setup
#     def setup(self):
#         pass

#     @aetest.test
#     def leaf3SSO(self):

#         leaf3.configure("copy r s")

#         # Perform Device Reload
#         result = infraEORTrigger.verifyDeviceSSO({'dut':leaf3})
#         if result:
#             log.info("SSO completed Successfully")
#         else:
#             log.debug("SSO Failed")
#             self.failed("SSO Failed", goto=['cleanup'])

#         log.info("Waiting for 120 sec for the topology to come UP")
#         time.sleep(300)

#     # =============================================================================================================================#
#     @aetest.test
#     def VERIFY_IXIA_TRAFFIC(self):
#         """ IXIA_CONFIGURATION subsection: Verify IXIA Traffic """

#         time.sleep(20)

#         if ixLib.verify_traffic(2,3) == 0:
#             log.debug("Traffic Verification failed")
#             self.failed("Traffic Verification failed", goto=['cleanup'])
#         else:
#             log.info("Traffic Verification Passed")

#     # =============================================================================================================================#
#     @aetest.cleanup
#     def cleanup(self):
#         """ testcase clean up """

#         post_test_process_dict['cc_check'] = 0
#         status = infraVerify.postTestVerification(post_test_process_dict)

#         if status['status'] == 0:
#             self.failed(reason=status['logs'])
#         else:
#             self.passed(reason=status['logs'])

# # noinspection PyGlobalUndefined
# class TC059_vxlan_Z_Flow1(aetest.Testcase):
#     ###    This is description for my testcase two
#
#     @aetest.setup
#     def setup(self):
#         pass
#
#     @aetest.test
#     def Trigger13Zflow1(self):
#         log.info(banner("Starting Trigger13Zflow1"))
#
#         poshut = \
#             """
#             interface {po}
#             shut
#             """
#
#         intshut = \
#             """
#             interface {intf}
#             shut
#             """
#
#         #for intf in leaf1.interfaces.keys():
#         #    if 'vpc_po' in leaf1.interfaces[intf].type:
#         vpc5 = 'Po101'
#         global z_mode_leaf2_intf_list
#         leaf1.configure(poshut.format(po=vpc5))
#         leaf2_intf_list = []
#
#         if 'ospf' in igp:
#             op = leaf2.execute('sh ip os ne | incl FULL')
#             op1 = op.splitlines()
#             for line in op1:
#                 if 'FULL' in line:
#                     if 'Vlan' not in line:
#                         intf = line.split()[-1]
#                         leaf2_intf_list.append(intf)
#             z_mode_leaf2_intf_list = leaf2_intf_list
#
#         elif 'isis' in igp:
#             op = leaf2.execute('sh isis adjacency | inc N/A')
#             op1 = op.splitlines()
#             for line in op1:
#                 if 'UP' in line:
#                     if 'Vlan' not in line:
#                         intf = line.split()[-1]
#                         leaf2_intf_list.append(intf)
#             z_mode_leaf2_intf_list = leaf2_intf_list
#
#         for intf in z_mode_leaf2_intf_list:
#             leaf2.configure(intshut.format(intf=intf))
#
#         countdown(240)
#
#     # =============================================================================================================================#
#     @aetest.test
#     def VERIFY_IXIA_TRAFFIC_post_Z_form(self):
#         """ IXIA_CONFIGURATION subsection: Verify IXIA Traffic """
#
#         time.sleep(20)
#
#         if ixLib.verify_traffic(2, 3) == 0:
#             log.debug("Traffic Verification failed")
#             self.failed("Traffic Verification failed", goto=['cleanup'])
#         else:
#             log.info("Traffic Verification Passed")
#
#     # =============================================================================================================================#
#     @aetest.test
#     def revert_configs(self):
#         """ IXIA_CONFIGURATION subsection: Verify IXIA Traffic """
#
#         ponoshut = \
#             """
#             interface {po}
#             no shut
#             """
#
#         intnoshut = \
#             """
#             interface {intf}
#             no shut
#             """
#
#         vpc5 = 'Po101'
#         leaf1.configure(ponoshut.format(po=vpc5))
#
#         for intf in z_mode_leaf2_intf_list:
#             leaf2.configure(intnoshut.format(intf=intf))
#
#         countdown(240)
#
#     # =============================================================================================================================#
#     @aetest.test
#     def VERIFY_IXIA_TRAFFIC_post_revert(self):
#         """ IXIA_CONFIGURATION subsection: Verify IXIA Traffic """
#
#         time.sleep(20)
#
#         if ixLib.verify_traffic(2, 3) == 0:
#             log.debug("Traffic Verification failed")
#             self.failed("Traffic Verification failed", goto=['cleanup'])
#         else:
#             log.info("Traffic Verification Passed")
#
#     # =============================================================================================================================#
#     @aetest.cleanup
#     def cleanup(self):
#         """ testcase clean up """
#
#         ponoshut = \
#             """
#             interface {po}
#             no shut
#             """
#
#         intnoshut = \
#             """
#             interface {intf}
#             no shut
#             """
#
#         vpc5 = 'Po101'
#         leaf1.configure(ponoshut.format(po=vpc5))
#         for intf in z_mode_leaf2_intf_list:
#             leaf2.configure(intnoshut.format(intf=intf))
#         countdown(60)
#
#         status = infraVerify.postTestVerification(post_test_process_dict)
#
#         if status['status'] == 0:
#             self.failed(reason=status['logs'])
#         else:
#             self.passed(reason=status['logs'])
#
# # noinspection PyGlobalUndefined
# class TC060_vxlan_Z_Flow2(aetest.Testcase):
#     ###    This is description for my testcase two
#
#     @aetest.setup
#     def setup(self):
#         pass
#
#     @aetest.test
#     def Trigger14Zflow2(self):
#         log.info(banner("Starting Trigger14Zflow2 "))
#
#         poshut = \
#             """
#             interface {po}
#             shut
#             """
#
#         intshut = \
#             """
#             interface {intf}
#             shut
#             """
#
#         vpc6 = 'Po101'
#         leaf2.configure(poshut.format(po=vpc6))
#         global z_flow_leaf1_intf_list
#         leaf1_intf_list = []
#
#         if 'ospf' in igp:
#             op = leaf1.execute('sh ip os ne | incl FULL')
#             op1 = op.splitlines()
#             for line in op1:
#                 if 'FULL' in line:
#                     if 'Vlan' not in line:
#                         intf = line.split()[-1]
#                         leaf1_intf_list.append(intf)
#             z_flow_leaf1_intf_list = leaf1_intf_list
#
#         elif 'isis' in igp:
#             op = leaf1.execute('sh isis adjacency | inc N/A')
#             op1 = op.splitlines()
#             for line in op1:
#                 if 'UP' in line:
#                     if 'Vlan' not in line:
#                         intf = line.split()[-1]
#                         leaf1_intf_list.append(intf)
#             z_flow_leaf1_intf_list = leaf1_intf_list
#
#         for intf in z_flow_leaf1_intf_list:
#             leaf1.configure(intshut.format(intf=intf))
#
#         countdown(240)
#
#     # =============================================================================================================================#
#     @aetest.test
#     def VERIFY_IXIA_TRAFFIC_post_Z_form(self):
#         """ IXIA_CONFIGURATION subsection: Verify IXIA Traffic """
#
#         time.sleep(20)
#
#         if ixLib.verify_traffic(2, 3) == 0:
#             log.debug("Traffic Verification failed")
#             self.failed("Traffic Verification failed", goto=['cleanup'])
#         else:
#             log.info("Traffic Verification Passed")
#
#     # =============================================================================================================================#
#     @aetest.test
#     def revert_configs(self):
#         """ IXIA_CONFIGURATION subsection: Verify IXIA Traffic """
#
#         ponoshut = \
#             """
#             interface {po}
#             no shut
#             """
#
#         intnoshut = \
#             """
#             interface {intf}
#             no shut
#             """
#
#         vpc6 = 'Po101'
#         leaf2.configure(ponoshut.format(po=vpc6))
#         for intf in z_flow_leaf1_intf_list:
#             leaf1.configure(intnoshut.format(intf=intf))
#
#         countdown(240)
#
#     # =============================================================================================================================#
#     @aetest.test
#     def VERIFY_IXIA_TRAFFIC_post_revert(self):
#         """ IXIA_CONFIGURATION subsection: Verify IXIA Traffic """
#
#         time.sleep(20)
#
#         if ixLib.verify_traffic(2, 3) == 0:
#             log.debug("Traffic Verification failed")
#             self.failed("Traffic Verification failed", goto=['cleanup'])
#         else:
#             log.info("Traffic Verification Passed")
#
#     # =============================================================================================================================#
#     @aetest.cleanup
#     def cleanup(self):
#         """ testcase clean up """
#
#         ponoshut = \
#             """
#             interface {po}
#             no shut
#             """
#
#         intnoshut = \
#             """
#             interface {intf}
#             no shut
#             """
#
#         vpc6 = 'Po101'
#         leaf2.configure(ponoshut.format(po=vpc6))
#         for intf in z_flow_leaf1_intf_list:
#             leaf1.configure(intnoshut.format(intf=intf))
#         countdown(120)
#
#         status = infraVerify.postTestVerification(post_test_process_dict)
#
#         if status['status'] == 0:
#             self.failed(reason=status['logs'])
#         else:
#             self.passed(reason=status['logs'])

# class CFD_CSCvr58479_IP_MAC_routes_in_BGP_after_SVI_removed(aetest.Testcase):
#     ###    This is description for my testcase two
#     ###CSCvr58479: The host specific routes (IP-MAC) may stay in BGP after corresponding SVI removed

#     @aetest.setup
#     def setup(self):
#         result_list = []

#         for uut in vpc_uut_list:
#             cfg = \
#             """
#             int nve 1
#             no member vni 201001
#             member vni 101001
#             suppress-arp
#             """
#             uut.configure(cfg)          
#         countdown(20)

#         for uut in vpc_uut_list:
#             arp = uut.execute("show ip arp vrf all | incl 5.1.0.52")
#             mac_ip= uut.execute("show l2route evpn mac-ip evi 1001 host-ip 5.1.0.52 detail")    
#             bgp_adv = uut.execute("show bgp l2 evpn 5.1.0.52 | sec adve")    
#             if not '5.1.0.52' in arp:
#                 log.info('5.1.0.52 not in ARP')
#                 result_list.append('fail')
#             if not '5.1.0.52' in mac_ip:    
#                 log.info('5.1.0.52 not in mac_ip')
#                 result_list.append('fail')
#             if not '100.1.1.' in bgp_adv:
#                 log.info('5.1.0.52 not in bgp_adv')             
#                 result_list.append('fail')

#         if 'fail' in result_list:
#             self.failed()    

#     @aetest.test
#     def CSCvr58479_svi_shut(self):

#         for uut in vpc_uut_list:
#             cfg = \
#             """
#             int nve 1
#             no member vni 201001
#             member vni 101001
#             no suppress-arp
#             interface vlan 1001
#             shut
#             """
#             uut.configure(cfg)          
#         countdown(10)

#         result_list = []
#         for uut in vpc_uut_list:
#             arp = uut.execute("show ip arp vrf all | incl 5.1.0.52")
#             mac_ip= uut.execute("show l2route evpn mac-ip evi 1001 host-ip 5.1.0.52 detail")    
#             bgp_adv = uut.execute("show bgp l2 evpn 5.1.0.52 | sec adve")    

#             if '5.1.0.52' in arp:
#                 log.info('5.1.0.52 not removed from ARP')
#                 result_list.append('fail')
#             if '5.1.0.52' in mac_ip:    
#                 log.info('5.1.0.52 not removed from l2route evpn mac-ip evi ')
#                 result_list.append('fail')
#             if '100.1.1.' in bgp_adv:
#                 log.info('5.1.0.52 Advertised by BGP after vlan shut ')
#                 result_list.append('fail') 

#         if 'fail' in result_list:
#             self.failed()    

#     @aetest.test
#     def CSCvr58479_svi_no_shut(self):

#         for uut in vpc_uut_list:
#             cfg = \
#             """
#             interface vlan 1001
#             no shut
#             int nve 1
#             member vni 101001
#             suppress-arp
#             """
#             uut.configure(cfg)   

#         countdown(10)

#         result_list = []
#         for uut in vpc_uut_list:
#             arp = uut.execute("show ip arp vrf all | incl 5.1.0.52")
#             mac_ip= uut.execute("show l2route evpn mac-ip evi 1001 host-ip 5.1.0.52 detail")    
#             bgp_adv = uut.execute("show bgp l2 evpn 5.1.0.52 | sec adve")    
#             if not '5.1.0.52' in arp:
#                 log.info('5.1.0.52 not removed from ARP')
#                 result_list.append('fail')
#             if not '5.1.0.52' in mac_ip:    
#                 log.info('5.1.0.52 not removed from l2route evpn mac-ip evi ')
#                 result_list.append('fail')
#             if not '100.1.1.' in bgp_adv:
#                 log.info('5.1.0.52 Advertised by BGP after vlan shut ')
#                 result_list.append('fail') 

#         if 'fail' in result_list:
#             self.failed()    

#     @aetest.test
#     def CSCvr58479_svi_delete(self):
#         result_list = []

#         for uut in vpc_uut_list:
#             cfg = \
#             """
#             no interface vlan 1001
#             int nve 1
#             member vni 101001
#             no suppress-arp
#             """
#             uut.configure(cfg)

#         countdown(10)

#         for uut in vpc_uut_list:
#             arp = uut.execute("show ip arp vrf all | incl 5.1.0.52")
#             mac_ip= uut.execute("show l2route evpn mac-ip evi 1001 host-ip 5.1.0.52 detail")    
#             bgp_adv = uut.execute("show bgp l2 evpn 5.1.0.52 | sec adve")    
#             if '5.1.0.52' in arp:
#                 log.info('5.1.0.52 not removed from ARP')
#                 result_list.append('fail')
#             if '5.1.0.52' in mac_ip:    
#                 log.info('5.1.0.52 not removed from l2route evpn mac-ip evi ')
#                 result_list.append('fail')
#             if '100.1.1.' in bgp_adv:
#                 log.info('5.1.0.52 Advertised by BGP after vlan shut ')
#                 result_list.append('fail')    

#         countdown(20)           
#         if 'fail' in result_list:
#             self.failed()    


#     @aetest.test
#     def CSCvr58479_svi_add(self):
#         result_list = []

#         cfg = \
#         """
#         interface Vlan1001
#         no shutdown
#         mtu 9216
#         vrf member vxlan-90101
#         no ip redirects
#         ip address 5.1.0.2/16
#         ipv6 address 5::1:1/112
#         no ipv6 redirects
#         fabric forwarding mode anycast-gateway
#         int nve 1
#         member vni 101001
#         suppress-arp
#         """

#         for uut in vpc_uut_list:
#             uut.configure(cfg) 

#         countdown(10) 

#         for uut in vpc_uut_list:
#             arp = uut.execute("show ip arp vrf all | incl 5.1.0.52")
#             mac_ip= uut.execute("show l2route evpn mac-ip evi 1001 host-ip 5.1.0.52 detail")    
#             bgp_adv = uut.execute("show bgp l2 evpn 5.1.0.52 | sec adve")    
#             if not '5.1.0.52' in arp:
#                 log.info('5.1.0.52 not removed from ARP')
#                 result_list.append('fail')
#             if not '5.1.0.52' in mac_ip:    
#                 log.info('5.1.0.52 not removed from l2route evpn mac-ip evi ')
#                 result_list.append('fail')
#             if not '100.1.1.' in bgp_adv:
#                 log.info('5.1.0.52 Advertised by BGP after vlan shut ')
#                 result_list.append('fail') 

#         countdown(20)           
#         if 'fail' in result_list:
#             self.failed()

#     # =============================================================================================================================#
#     @aetest.test
#     def VERIFY_IXIA_TRAFFIC(self):
#         """ IXIA_CONFIGURATION subsection: Verify IXIA Traffic """

#         time.sleep(20)

#         if ixLib.verify_traffic(2, 3) == 0:
#             log.debug("Traffic Verification failed")
#             self.failed("Traffic Verification failed", goto=['cleanup'])
#         else:
#             log.info("Traffic Verification Passed")


#     @aetest.cleanup
#     def cleanup(self):
#         pass

class common_cleanup(aetest.CommonCleanup):

    @aetest.subsection
    def stop_tgn_streams(self):
        pass

    @aetest.subsection
    def stop_tgn_streams(self):
        pass
        #for port_hdl in  port_handle_list:
        #    traffic_ctrl_ret = sth.traffic_control(port_handle = port_hdl, action = 'stop', db_file=0 )
        #    traffic_ctrl_ret = sth.traffic_control(port_handle = port_hdl, action = 'reset')


    @aetest.subsection
    def disconnect_from_tgn(self):
        #general_lib.cleanup_tgn_config(cln_lab_srvr_sess = 1)
        pass

if __name__ == '__main__':  # pragma: no cover
    aetest.main()
