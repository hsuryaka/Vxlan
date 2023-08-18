"""
 VxLAN Library for EVPN and Flood and Learn
"""

import logging
import json
import random
import string
import texttable
import re
import ipaddress as ip
from pyats.aereport.utils.argsvalidator import ArgsValidator
from pyats.log.utils import banner

log = logging.getLogger(__name__)
log.setLevel(logging.DEBUG)
ArgVal = ArgsValidator()


# ====================================================================================================#
# Global Methods
# ====================================================================================================#
def increment_prefix_network(pref, count, rslt_wo_mask=0):
    size = 1 << (pref.network.max_prefixlen - pref.network.prefixlen)
    pref_lst = []
    for i in range(count):
        if rslt_wo_mask == 0:
            pref_lst.append(str((pref.ip + size * i)) + "/" + str(pref.network.prefixlen))
        elif rslt_wo_mask == 1:
            pref_lst.append(str((pref.ip + size * i)))
    return pref_lst


# ====================================================================================================#
# Nexus VxLAN PVNF Configuration Methods
# ====================================================================================================#
class configureVxlanEvpnPVNF:

    # First we create a constructor for this class
    # and add members to it, here models
    def __init__(self):
        pass

    # ====================================================================================================#
    @staticmethod
    def configurePVNF_Underlay_PGW_to_LEAF(PGW, pvnfTopoLeavesDict):

        # --------------------------------------------
        # Parse the arguments for their types
        # --------------------------------------------
        if type(pvnfTopoLeavesDict) is not dict:
            print("Passed Argument pvnfTopoLeavesDict is not a Dict of Leaf dictionaries")
            return 0

        # --------------------------------------------------
        # Configuring loopbacks on PGW and LEAFs for TOPO-1
        # --------------------------------------------------
        LEAF_loopback_cfg = ""
        PGW_loopback_cfg = ""
        if str(pvnfTopoLeavesDict['type']) == "topo_1":
            log.info(banner("Configuring Loopbacks on PGW and LEAFs"))
            print(banner("Configuring Loopbacks on PGW and LEAFs"))
            for pvnfLeaf in pvnfTopoLeavesDict:
                if type(pvnfTopoLeavesDict[pvnfLeaf]) == dict:
                    LEAF_loopback_cfg += '''
                        interface loopback ''' + str(pvnfTopoLeavesDict[pvnfLeaf]['loop_num']) + '''
                          vrf member ''' + str(pvnfTopoLeavesDict['vrf']) + '''
                          ip address ''' + str(pvnfTopoLeavesDict[pvnfLeaf]['local_loop_v4']) + '''/32
                          ipv6 address ''' + str(pvnfTopoLeavesDict[pvnfLeaf]['local_loop_v6']) + '''/128
                          no shutdown
                    '''
                    if PGW_loopback_cfg == "":
                        PGW_loopback_cfg += '''
                        interface loopback ''' + str(pvnfTopoLeavesDict[pvnfLeaf]['loop_num']) + '''
                          vrf member ''' + str(pvnfTopoLeavesDict['vrf']) + '''
                          ip address ''' + str(pvnfTopoLeavesDict[pvnfLeaf]['pgw_comn_loop_v4']) + '''/32
                          ipv6 address ''' + str(pvnfTopoLeavesDict[pvnfLeaf]['pgw_comn_loop_v6']) + '''/128
                          no shutdown
                        '''
                        log.info("--- Configuring loopback for " + str(PGW.alias) + "---")
                        PGW.configure(PGW_loopback_cfg)
                        print("--- Configuring loopback for " + str(PGW.alias) + "---")
                        print(PGW_loopback_cfg)
                    log.info("--- Configuring loopback for " + str(pvnfLeaf.alias) + "---")
                    pvnfLeaf.configure(LEAF_loopback_cfg)
                    print("--- Configuring loopback for " + str(pvnfLeaf.alias) + "---")
                    print(LEAF_loopback_cfg)
                LEAF_loopback_cfg = ""

        # --------------------------------------------------
        # Configuring loopbacks on PGW and LEAFs for TOPO-2
        # --------------------------------------------------
        LEAF_loopback_cfg = ""
        PGW_loopback_cfg = ""
        PGW_loop_num_incr = 1
        if str(pvnfTopoLeavesDict['type']) == "topo_2":
            log.info(banner("Configuring Loopbacks on PGW and LEAFs"))
            print(banner("Configuring Loopbacks on PGW and LEAFs"))
            for pvnfLeaf in pvnfTopoLeavesDict:
                if type(pvnfTopoLeavesDict[pvnfLeaf]) == dict:
                    PGW_loop_num = int(pvnfTopoLeavesDict[pvnfLeaf]['loop_num']) + PGW_loop_num_incr
                    LEAF_loopback_cfg += '''
                        interface loopback ''' + str(pvnfTopoLeavesDict[pvnfLeaf]['loop_num']) + '''
                          vrf member ''' + str(pvnfTopoLeavesDict['vrf']) + '''
                          ip address ''' + str(pvnfTopoLeavesDict[pvnfLeaf]['local_loop_v4']) + '''/32
                          ipv6 address ''' + str(pvnfTopoLeavesDict[pvnfLeaf]['local_loop_v6']) + '''/128
                          no shutdown
                    '''
                    PGW_loopback_cfg += '''
                        interface loopback ''' + str(PGW_loop_num) + '''
                          vrf member ''' + str(pvnfTopoLeavesDict['vrf']) + '''
                          ip address ''' + str(pvnfTopoLeavesDict[pvnfLeaf]['pgw_comn_loop_v4']) + '''/32
                          ipv6 address ''' + str(pvnfTopoLeavesDict[pvnfLeaf]['pgw_comn_loop_v6']) + '''/128
                          no shutdown
                    '''

                    log.info("--- Configuring loopback for " + str(PGW.alias) + "---")
                    PGW.configure(PGW_loopback_cfg)
                    print("--- Configuring loopback for " + str(PGW.alias) + "---")
                    print(PGW_loopback_cfg)
                    log.info("--- Configuring loopback for " + str(pvnfLeaf.alias) + "---")
                    pvnfLeaf.configure(LEAF_loopback_cfg)
                    print("--- Configuring loopback for " + str(pvnfLeaf.alias) + "---")
                    print(LEAF_loopback_cfg)
                LEAF_loopback_cfg = ""
                PGW_loopback_cfg = ""
                PGW_loop_num_incr += 1

        # ----------------------------------------------------
        # Configure Underlay with TOPO specific static routes
        # ----------------------------------------------------
        # --------------------------------------------------
        # Declaring Config Variables
        # --------------------------------------------------
        PGW_SVI_cfg = ""
        LEAF_SVI_cfg = ""
        PGW_static_route_cfg_v4 = ""
        PGW_static_route_cfg_v6 = ""
        LEAF_static_route_cfg_v4 = ""
        LEAF_static_route_cfg_v6 = ""

        log.info(banner("Configuring Underlay PGW to LEAF Links for - " + str(pvnfTopoLeavesDict['type'])))
        print(banner("Configuring Underlay PGW to LEAF Links for - " + str(pvnfTopoLeavesDict['type'])))
        for pvnfLeaf in pvnfTopoLeavesDict:
            if type(pvnfTopoLeavesDict[pvnfLeaf]) == dict:
                if 'pgw_to_leaf_underlay' in pvnfTopoLeavesDict[pvnfLeaf].keys():
                    # --------------------------------------------------
                    # Generating IPs
                    # --------------------------------------------------
                    PGW_to_LEAF_ipv4_nw = list(
                        ip.IPv4Network(str(pvnfTopoLeavesDict[pvnfLeaf]['underlay_ipv4_start']) + '/31'))
                    PGW_to_LEAF_ipv6_nw = list(
                        ip.IPv6Network(str(pvnfTopoLeavesDict[pvnfLeaf]['underlay_ipv6_start']) + '/127'))
                    PGW_to_LEAF_ipv4s = increment_prefix_network(ip.IPv4Interface(str(PGW_to_LEAF_ipv4_nw[0]) + '/24'),
                                                                 pvnfTopoLeavesDict[pvnfLeaf]['leaf_to_pgw_link_count'],
                                                                 1)
                    PGW_to_LEAF_ipv6s = increment_prefix_network(ip.IPv6Interface(str(PGW_to_LEAF_ipv6_nw[0]) + '/64'),
                                                                 pvnfTopoLeavesDict[pvnfLeaf]['leaf_to_pgw_link_count'],
                                                                 1)
                    LEAF_to_PGW_ipv4s = increment_prefix_network(ip.IPv4Interface(str(PGW_to_LEAF_ipv4_nw[1]) + '/24'),
                                                                 pvnfTopoLeavesDict[pvnfLeaf]['leaf_to_pgw_link_count'],
                                                                 1)
                    LEAF_to_PGW_ipv6s = increment_prefix_network(ip.IPv6Interface(str(PGW_to_LEAF_ipv6_nw[1]) + '/64'),
                                                                 pvnfTopoLeavesDict[pvnfLeaf]['leaf_to_pgw_link_count'],
                                                                 1)

                    # --------------------------------------------------
                    # Building Static Routes
                    # --------------------------------------------------
                    PGW_static_route_cfg_v4 += '''
                                vrf context ''' + str(pvnfTopoLeavesDict['vrf'])
                    PGW_static_route_cfg_v6 += '''                              
                                vrf context ''' + str(pvnfTopoLeavesDict['vrf'])
                    LEAF_static_route_cfg_v4 += '''
                                vrf context ''' + str(pvnfTopoLeavesDict['vrf'])
                    LEAF_static_route_cfg_v6 += '''                             
                                vrf context ''' + str(pvnfTopoLeavesDict['vrf'])

                    if pvnfTopoLeavesDict[pvnfLeaf]['pgw_to_leaf_underlay'] == 'vlan-svi':

                        # --------------------------------------------------
                        # Declaring Counter and Config Variables
                        # --------------------------------------------------
                        ip_index = 0
                        vlan_counter = 0
                        vlan_id = int(pvnfTopoLeavesDict[pvnfLeaf]['svi_sub_int_vlan_start'])
                        start_vlan_id = pvnfTopoLeavesDict[pvnfLeaf]['svi_sub_int_vlan_start']
                        end_vlan_id = str(
                            int(start_vlan_id) + int(pvnfTopoLeavesDict[pvnfLeaf]['leaf_to_pgw_link_count']))

                        PGW_SVI_cfg += '''
                                    vlan ''' + str(start_vlan_id) + ''' - ''' + str(end_vlan_id) + ''' 
                                      state active
                                      no shut
                                    '''

                        LEAF_SVI_cfg += '''
                                    vlan ''' + str(start_vlan_id) + ''' - ''' + str(end_vlan_id) + ''' 
                                      state active
                                      no shut
                                    '''

                        while vlan_counter < int(pvnfTopoLeavesDict[pvnfLeaf]['leaf_to_pgw_link_count']):
                            PGW_SVI_cfg += '''
                                    interface vlan ''' + str(vlan_id) + '''
                                      vrf member ''' + str(pvnfTopoLeavesDict['vrf']) + '''
                                      no ip redirects
                                      no ipv6 redirects
                                      ip address ''' + str(PGW_to_LEAF_ipv4s[ip_index]) + '''/24
                                      ipv6 address ''' + str(PGW_to_LEAF_ipv6s[ip_index]) + '''/64
                                      no shutdown
                            '''
                            LEAF_SVI_cfg += '''
                                    interface vlan ''' + str(vlan_id) + '''
                                      vrf member ''' + str(pvnfTopoLeavesDict['vrf']) + '''
                                      no ip redirects
                                      no ipv6 redirects
                                      ip address ''' + str(LEAF_to_PGW_ipv4s[ip_index]) + '''/24
                                      ipv6 address ''' + str(LEAF_to_PGW_ipv6s[ip_index]) + '''/64
                                      no shutdown
                            '''

                            if (str(pvnfTopoLeavesDict['type']) == "topo_1") or (
                                    str(pvnfTopoLeavesDict['type']) == "topo_2"):
                                PGW_static_route_cfg_v4 += '''
                                        ip route  ''' + str(
                                    pvnfTopoLeavesDict[pvnfLeaf]['local_loop_v4']) + '''/32 vlan''' + str(
                                    vlan_id) + ''' ''' + str(LEAF_to_PGW_ipv4s[ip_index]) + ''''''
                                PGW_static_route_cfg_v6 += '''
                                        ipv6 route  ''' + str(
                                    pvnfTopoLeavesDict[pvnfLeaf]['local_loop_v6']) + '''/128 vlan''' + str(
                                    vlan_id) + ''' ''' + str(LEAF_to_PGW_ipv6s[ip_index]) + ''''''
                                LEAF_static_route_cfg_v4 += '''
                                        ip route  ''' + str(
                                    pvnfTopoLeavesDict[pvnfLeaf]['pgw_comn_loop_v4']) + '''/32 vlan''' + str(
                                    vlan_id) + ''' ''' + str(PGW_to_LEAF_ipv4s[ip_index]) + ''''''
                                LEAF_static_route_cfg_v6 += '''
                                        ipv6 route  ''' + str(
                                    pvnfTopoLeavesDict[pvnfLeaf]['pgw_comn_loop_v6']) + '''/128 vlan''' + str(
                                    vlan_id) + ''' ''' + str(PGW_to_LEAF_ipv6s[ip_index]) + ''''''

                            vlan_counter += 1
                            ip_index += 1
                            vlan_id += 1

                        PGW_SVI_cfg += '''
                            interface ''' + str(pvnfTopoLeavesDict[pvnfLeaf]['PGW_LEAF_int']) + '''
                                switchport
                                switchport mode trunk
                                no shut
                        '''
                        if "switchport trunk allowed vlan" in PGW.execute(
                                "show run int " + str(pvnfTopoLeavesDict[pvnfLeaf]['PGW_LEAF_int'])):
                            PGW_SVI_cfg += '''
                                switchport trunk allowed vlan add ''' + str(start_vlan_id) + ''' - ''' + str(
                                end_vlan_id) + '''
                                        '''
                        else:
                            PGW_SVI_cfg += '''
                                switchport trunk allowed vlan ''' + str(start_vlan_id) + ''' - ''' + str(end_vlan_id) + '''
                                        '''

                        LEAF_SVI_cfg += '''
                            interface ''' + str(pvnfTopoLeavesDict[pvnfLeaf]['LEAF_PGW_int']) + '''
                                switchport
                                switchport mode trunk
                                no shut
                        '''
                        if "switchport trunk allowed vlan" in pvnfLeaf.execute(
                                "show run int " + str(pvnfTopoLeavesDict[pvnfLeaf]['LEAF_PGW_int'])):
                            LEAF_SVI_cfg += '''
                                switchport trunk allowed vlan add ''' + str(start_vlan_id) + ''' - ''' + str(
                                end_vlan_id) + '''
                                        '''
                        else:
                            LEAF_SVI_cfg += '''
                                switchport trunk allowed vlan ''' + str(start_vlan_id) + ''' - ''' + str(end_vlan_id) + '''
                                        '''

                    elif pvnfTopoLeavesDict[pvnfLeaf]['pgw_to_leaf_underlay'] == 'sub-ints':

                        # --------------------------------------------------
                        # Declaring Counter and Config Variables
                        # --------------------------------------------------
                        ip_index = 0
                        sub_int_id = 1
                        vlan_counter = 0
                        vlan_id = int(pvnfTopoLeavesDict[pvnfLeaf]['svi_sub_int_vlan_start'])

                        LEAF_SVI_cfg += '''
                            def interface ''' + str(pvnfTopoLeavesDict[pvnfLeaf]['LEAF_PGW_int']) + '''
                            interface ''' + str(pvnfTopoLeavesDict[pvnfLeaf]['LEAF_PGW_int']) + '''
                                no switchport
                                no shut
                        '''

                        PGW_SVI_cfg += '''
                            def interface ''' + str(pvnfTopoLeavesDict[pvnfLeaf]['PGW_LEAF_int']) + '''
                            interface ''' + str(pvnfTopoLeavesDict[pvnfLeaf]['PGW_LEAF_int']) + '''
                                no switchport
                                no shut
                        '''

                        while vlan_counter < int(pvnfTopoLeavesDict[pvnfLeaf]['leaf_to_pgw_link_count']):
                            PGW_SVI_cfg += '''
                                    interface ''' + str(pvnfTopoLeavesDict[pvnfLeaf]['PGW_LEAF_int']) + '''.''' + str(
                                sub_int_id) + '''
                                      encapsulation dot1q ''' + str(vlan_id) + '''
                                      vrf member ''' + str(pvnfTopoLeavesDict['vrf']) + '''
                                      no ip redirects
                                      no ipv6 redirects
                                      ip address ''' + str(PGW_to_LEAF_ipv4s[ip_index]) + '''/24
                                      ipv6 address ''' + str(PGW_to_LEAF_ipv6s[ip_index]) + '''/64
                                      no shutdown
                            '''
                            LEAF_SVI_cfg += '''
                                    interface ''' + str(pvnfTopoLeavesDict[pvnfLeaf]['LEAF_PGW_int']) + '''.''' + str(
                                sub_int_id) + '''
                                      encapsulation dot1q ''' + str(vlan_id) + '''
                                      vrf member ''' + str(pvnfTopoLeavesDict['vrf']) + '''
                                      no ip redirects
                                      no ipv6 redirects
                                      ip address ''' + str(LEAF_to_PGW_ipv4s[ip_index]) + '''/24
                                      ipv6 address ''' + str(LEAF_to_PGW_ipv6s[ip_index]) + '''/64
                                      no shutdown
                            '''

                            if (str(pvnfTopoLeavesDict['type']) == "topo_1") or (
                                    str(pvnfTopoLeavesDict['type']) == "topo_2"):
                                PGW_static_route_cfg_v4 += '''
                                        ip route  ''' + str(
                                    pvnfTopoLeavesDict[pvnfLeaf]['local_loop_v4']) + '''/32 vlan''' + str(
                                    vlan_id) + ''' ''' + str(LEAF_to_PGW_ipv4s[ip_index]) + ''''''
                                PGW_static_route_cfg_v6 += '''
                                        ipv6 route  ''' + str(
                                    pvnfTopoLeavesDict[pvnfLeaf]['local_loop_v6']) + '''/128 vlan''' + str(
                                    vlan_id) + ''' ''' + str(LEAF_to_PGW_ipv6s[ip_index]) + ''''''
                                LEAF_static_route_cfg_v4 += '''
                                        ip route  ''' + str(
                                    pvnfTopoLeavesDict[pvnfLeaf]['pgw_comn_loop_v4']) + '''/32 vlan''' + str(
                                    vlan_id) + ''' ''' + str(PGW_to_LEAF_ipv4s[ip_index]) + ''''''
                                LEAF_static_route_cfg_v6 += '''
                                        ipv6 route  ''' + str(
                                    pvnfTopoLeavesDict[pvnfLeaf]['pgw_comn_loop_v6']) + '''/128 vlan''' + str(
                                    vlan_id) + ''' ''' + str(PGW_to_LEAF_ipv6s[ip_index]) + ''''''

                            vlan_counter += 1
                            sub_int_id += 1
                            ip_index += 1
                            vlan_id += 1

                    log.info("------ Configuring " + str(pvnfLeaf.alias) + "(VNF-LEAF) -- " + str(
                        PGW.alias) + "(PGW) ------\n")
                    log.info("|___ Given mode of links is " + str(pvnfTopoLeavesDict[pvnfLeaf]['pgw_to_leaf_underlay']))
                    log.info("|___ Given PGW to LEAF link is " + str(pvnfTopoLeavesDict[pvnfLeaf]['PGW_LEAF_int']))
                    log.info(
                        "|___ Given LEAF to PGW link is " + str(pvnfTopoLeavesDict[pvnfLeaf]['LEAF_PGW_int']) + "\n")
                    log.info("------ Configuring " + str(pvnfLeaf.alias) + " ------")
                    pvnfLeaf.configure(LEAF_SVI_cfg)
                    pvnfLeaf.configure(LEAF_static_route_cfg_v4)
                    pvnfLeaf.configure(LEAF_static_route_cfg_v6)

                    log.info("------ Configuring " + str(PGW.alias) + " ------")
                    PGW.configure(PGW_SVI_cfg)
                    PGW.configure(PGW_static_route_cfg_v4)
                    PGW.configure(PGW_static_route_cfg_v6)

                    print("------ Configuring " + str(pvnfLeaf.alias) + "(VNF-LEAF) -- " + str(
                        PGW.alias) + "(PGW) ------\n")
                    print("|___ Given mode of links is sub-ints")
                    print("|___ Given PGW to LEAF link is " + str(pvnfTopoLeavesDict[pvnfLeaf]['PGW_LEAF_int']))
                    print("|___ Given LEAF to PGW link is " + str(pvnfTopoLeavesDict[pvnfLeaf]['LEAF_PGW_int']) + "\n")
                    print("------ Configuring " + str(pvnfLeaf.alias) + " ------")
                    print(LEAF_SVI_cfg)
                    print(LEAF_static_route_cfg_v4)
                    print(LEAF_static_route_cfg_v6)
                    print("------ Configuring " + str(PGW.alias) + " ------")
                    print(PGW_SVI_cfg)
                    print(PGW_static_route_cfg_v4)
                    print(PGW_static_route_cfg_v6)

            PGW_SVI_cfg = ""
            LEAF_SVI_cfg = ""
            PGW_static_route_cfg_v4 = ""
            PGW_static_route_cfg_v6 = ""
            LEAF_static_route_cfg_v4 = ""
            LEAF_static_route_cfg_v6 = ""

    # ====================================================================================================#
    @staticmethod
    def configurePVNF_BGP_PGW_to_LEAF(PGW, pvnfTopoLeavesDict):

        # --------------------------------------------
        # Parse the arguments for their types
        # --------------------------------------------
        if type(pvnfTopoLeavesDict) is not dict:
            print("Passed Argument pvnfTopoLeavesDict is not a Dict of Leaf dictionaries")
            return 0

        # ----------------------------------------------------
        # Configure Underlay with TOPO specific static routes
        # ----------------------------------------------------
        # --------------------------------------------------
        # Declaring Config Variables
        # --------------------------------------------------
        PGW_BGP_cfg = ""
        LEAF_BGP_cfg = ""
        loop_num_iter = 1
        for_loop_tracker = 0

        log.info(banner("Configuring BGP PGW to LEAF Links for - " + str(pvnfTopoLeavesDict['type'])))
        print(banner("Configuring BGP PGW to LEAF Links for - " + str(pvnfTopoLeavesDict['type'])))
        for pvnfLeaf in pvnfTopoLeavesDict:
            for_loop_tracker += 1
            if type(pvnfTopoLeavesDict[pvnfLeaf]) == dict:
                # --------------------------------------------------
                # Building Static Routes
                # --------------------------------------------------
                if str(pvnfTopoLeavesDict['type']) == "topo_1":
                    PGW_BGP_cfg += '''
                        router bgp ''' + str(pvnfTopoLeavesDict[pvnfLeaf]['pgw_bgp_as']) + '''
                            vrf ''' + str(pvnfTopoLeavesDict['vrf']) + '''
                                neighbor ''' + str(
                        pvnfTopoLeavesDict[pvnfLeaf]['local_loop_v4']) + ''' remote-as ''' + str(
                        pvnfTopoLeavesDict[pvnfLeaf]['leaf_as']) + '''
                                update-source loopback ''' + str(pvnfTopoLeavesDict[pvnfLeaf]['loop_num']) + '''
                                ebgp-multihop 10
                                address-family ipv4 unicast
                                    send-community
                                    send-community extended
                                
                                neighbor ''' + str(
                        pvnfTopoLeavesDict[pvnfLeaf]['local_loop_v6']) + ''' remote-as ''' + str(
                        pvnfTopoLeavesDict[pvnfLeaf]['leaf_as']) + '''
                                update-source loopback ''' + str(pvnfTopoLeavesDict[pvnfLeaf]['loop_num']) + '''
                                ebgp-multihop 10
                                address-family ipv6 unicast
                                    send-community
                                    send-community extended
                        '''
                    LEAF_BGP_cfg += '''
                        router bgp ''' + str(pvnfTopoLeavesDict[pvnfLeaf]['leaf_as']) + '''
                            address-family l2vpn evpn
                                maximum-paths mixed 32
                                retain route-target all
                                additional-paths send
                                additional-paths receive
                            vrf ''' + str(pvnfTopoLeavesDict['vrf']) + '''
                                timers bestpath-limit 600
                                graceful-restart restart-time 300
                                graceful-restart stalepath-time 600
                                address-family ipv4 unicast
                                    export-gateway-ip
                                    maximum-paths mixed 32
                                address-family ipv6 unicast
                                    export-gateway-ip
                                    maximum-paths mixed 32
                                neighbor ''' + str(
                        pvnfTopoLeavesDict[pvnfLeaf]['pgw_comn_loop_v4']) + ''' remote-as ''' + str(
                        pvnfTopoLeavesDict[pvnfLeaf]['pgw_bgp_as']) + '''
                                update-source loopback ''' + str(pvnfTopoLeavesDict[pvnfLeaf]['loop_num']) + '''
                                ebgp-multihop 10
                                address-family ipv4 unicast
                                    send-community
                                    send-community extended
                                
                                neighbor ''' + str(
                        pvnfTopoLeavesDict[pvnfLeaf]['pgw_comn_loop_v6']) + ''' remote-as ''' + str(
                        pvnfTopoLeavesDict[pvnfLeaf]['pgw_bgp_as']) + '''
                                update-source loopback ''' + str(pvnfTopoLeavesDict[pvnfLeaf]['loop_num']) + '''
                                ebgp-multihop 10
                                address-family ipv6 unicast
                                    send-community
                                    send-community extended
                    '''
                if str(pvnfTopoLeavesDict['type']) == "topo_2":
                    loop_num = int(pvnfTopoLeavesDict[pvnfLeaf]['loop_num']) + loop_num_iter
                    PGW_BGP_cfg += '''
                        router bgp ''' + str(pvnfTopoLeavesDict[pvnfLeaf]['pgw_bgp_as']) + '''
                            vrf ''' + str(pvnfTopoLeavesDict['vrf']) + '''
                                neighbor ''' + str(
                        pvnfTopoLeavesDict[pvnfLeaf]['local_loop_v4']) + ''' remote-as ''' + str(
                        pvnfTopoLeavesDict[pvnfLeaf]['leaf_as']) + '''
                                update-source loopback ''' + str(loop_num) + '''
                                ebgp-multihop 10
                                address-family ipv4 unicast
                                    send-community
                                    send-community extended

                                neighbor ''' + str(
                        pvnfTopoLeavesDict[pvnfLeaf]['local_loop_v6']) + ''' remote-as ''' + str(
                        pvnfTopoLeavesDict[pvnfLeaf]['leaf_as']) + '''
                                update-source loopback ''' + str(loop_num) + '''
                                ebgp-multihop 10
                                address-family ipv6 unicast
                                    send-community
                                    send-community extended
                        '''
                    loop_num_iter += 1
                    LEAF_BGP_cfg += '''
                        router bgp ''' + str(pvnfTopoLeavesDict[pvnfLeaf]['leaf_as']) + '''
                            address-family l2vpn evpn
                                maximum-paths mixed 32
                                retain route-target all
                                additional-paths send
                                additional-paths receive
                            vrf ''' + str(pvnfTopoLeavesDict['vrf']) + '''
                                timers bestpath-limit 600
                                graceful-restart restart-time 300
                                graceful-restart stalepath-time 600
                                address-family ipv4 unicast
                                    export-gateway-ip
                                    maximum-paths mixed 32
                                address-family ipv6 unicast
                                    export-gateway-ip
                                    maximum-paths mixed 32
                                neighbor ''' + str(
                        pvnfTopoLeavesDict[pvnfLeaf]['pgw_comn_loop_v4']) + ''' remote-as ''' + str(
                        pvnfTopoLeavesDict[pvnfLeaf]['pgw_bgp_as']) + '''
                                update-source loopback ''' + str(pvnfTopoLeavesDict[pvnfLeaf]['loop_num']) + '''
                                ebgp-multihop 10
                                address-family ipv4 unicast
                                    send-community
                                    send-community extended

                                neighbor ''' + str(
                        pvnfTopoLeavesDict[pvnfLeaf]['pgw_comn_loop_v6']) + ''' remote-as ''' + str(
                        pvnfTopoLeavesDict[pvnfLeaf]['pgw_bgp_as']) + '''
                                update-source loopback ''' + str(pvnfTopoLeavesDict[pvnfLeaf]['loop_num']) + '''
                                ebgp-multihop 10
                                address-family ipv6 unicast
                                    send-community
                                    send-community extended
                    '''
                if str(pvnfTopoLeavesDict['type']) == "topo_3":
                    # --------------------------------------------------
                    # Generating IPs
                    # --------------------------------------------------
                    PGW_to_LEAF_ipv4_nw = list(
                        ip.IPv4Network(str(pvnfTopoLeavesDict[pvnfLeaf]['underlay_ipv4_start']) + '/31'))
                    PGW_to_LEAF_ipv6_nw = list(
                        ip.IPv6Network(str(pvnfTopoLeavesDict[pvnfLeaf]['underlay_ipv6_start']) + '/127'))
                    PGW_to_LEAF_ipv4s = increment_prefix_network(ip.IPv4Interface(str(PGW_to_LEAF_ipv4_nw[0]) + '/24'),
                                                                 pvnfTopoLeavesDict[pvnfLeaf]['leaf_to_pgw_link_count'],
                                                                 1)
                    PGW_to_LEAF_ipv6s = increment_prefix_network(ip.IPv6Interface(str(PGW_to_LEAF_ipv6_nw[0]) + '/64'),
                                                                 pvnfTopoLeavesDict[pvnfLeaf]['leaf_to_pgw_link_count'],
                                                                 1)
                    LEAF_to_PGW_ipv4s = increment_prefix_network(ip.IPv4Interface(str(PGW_to_LEAF_ipv4_nw[1]) + '/24'),
                                                                 pvnfTopoLeavesDict[pvnfLeaf]['leaf_to_pgw_link_count'],
                                                                 1)
                    LEAF_to_PGW_ipv6s = increment_prefix_network(ip.IPv6Interface(str(PGW_to_LEAF_ipv6_nw[1]) + '/64'),
                                                                 pvnfTopoLeavesDict[pvnfLeaf]['leaf_to_pgw_link_count'],
                                                                 1)

                    # --------------------------------------------------
                    # Declaring Counter and Config Variables
                    # --------------------------------------------------
                    ip_index = 0
                    vlan_counter = 0
                    sub_int_num = 1
                    vlan_id = int(pvnfTopoLeavesDict[pvnfLeaf]['svi_sub_int_vlan_start'])

                    PGW_BGP_cfg += '''
                        router bgp ''' + str(pvnfTopoLeavesDict[pvnfLeaf]['pgw_bgp_as']) + '''
                            vrf ''' + str(pvnfTopoLeavesDict['vrf']) + ''''''
                    LEAF_BGP_cfg += '''
                        router bgp ''' + str(pvnfTopoLeavesDict[pvnfLeaf]['leaf_as']) + '''
                            address-family l2vpn evpn
                                maximum-paths mixed 32
                                retain route-target all
                                additional-paths send
                                additional-paths receive
                            vrf ''' + str(pvnfTopoLeavesDict['vrf']) + '''
                                timers bestpath-limit 600
                                graceful-restart restart-time 300
                                graceful-restart stalepath-time 600
                                address-family ipv4 unicast
                                    export-gateway-ip
                                    maximum-paths mixed 32
                                address-family ipv6 unicast
                                    export-gateway-ip
                                    maximum-paths mixed 32
                            '''

                    while vlan_counter < int(pvnfTopoLeavesDict[pvnfLeaf]['leaf_to_pgw_link_count']):
                        PGW_BGP_cfg += '''
                                neighbor ''' + str(LEAF_to_PGW_ipv4s[ip_index]) + ''' remote-as ''' + str(
                            pvnfTopoLeavesDict[pvnfLeaf]['leaf_as']) + '''
                                update-source ''' + str(pvnfTopoLeavesDict[pvnfLeaf]['PGW_LEAF_int']) + '''.''' + str(
                            sub_int_num) + '''
                                ebgp-multihop 10
                                address-family ipv4 unicast
                                    send-community
                                    send-community extended

                                neighbor ''' + str(LEAF_to_PGW_ipv6s[ip_index]) + ''' remote-as ''' + str(
                            pvnfTopoLeavesDict[pvnfLeaf]['leaf_as']) + '''
                                update-source ''' + str(pvnfTopoLeavesDict[pvnfLeaf]['PGW_LEAF_int']) + '''.''' + str(
                            sub_int_num) + '''
                                ebgp-multihop 10
                                address-family ipv6 unicast
                                    send-community
                                    send-community extended
                            '''
                        LEAF_BGP_cfg += '''
                                neighbor ''' + str(PGW_to_LEAF_ipv4s[ip_index]) + ''' remote-as ''' + str(
                            pvnfTopoLeavesDict[pvnfLeaf]['pgw_bgp_as']) + '''
                                update-source ''' + str(pvnfTopoLeavesDict[pvnfLeaf]['LEAF_PGW_int']) + '''.''' + str(
                            sub_int_num) + '''
                                ebgp-multihop 10
                                address-family ipv4 unicast
                                    send-community
                                    send-community extended

                                neighbor ''' + str(PGW_to_LEAF_ipv6s[ip_index]) + ''' remote-as ''' + str(
                            pvnfTopoLeavesDict[pvnfLeaf]['pgw_bgp_as']) + '''
                                update-source ''' + str(pvnfTopoLeavesDict[pvnfLeaf]['LEAF_PGW_int']) + '''.''' + str(
                            sub_int_num) + '''
                                ebgp-multihop 10
                                address-family ipv6 unicast
                                    send-community
                                    send-community extended
                        '''

                        vlan_counter += 1
                        sub_int_num += 1
                        ip_index += 1
                        vlan_id += 1

                log.info("------ Configuring " + str(pvnfLeaf.alias) + " ------")
                pvnfLeaf.configure(LEAF_BGP_cfg)
                LEAF_BGP_cfg = ""
        log.info("------ Configuring " + str(PGW.alias) + " ------")
        PGW.configure(PGW_BGP_cfg)

    # ====================================================================================================#
    @staticmethod
    def generate_prefix_list_per_topo(PGW, pvnfTopoLeavesDict):

        # ----------------------------------------------------
        # Retrieve the IPv4 and IPv6 routes to GW IP per LEAF
        # ----------------------------------------------------
        PGW_v4_prefix_list = ''
        PGW_v6_prefix_list = ''
        PGW_BGP_AS_num = ''
        PGW_VRF_name = ''
        PGW_rt_map_seq_num = 5

        LEAF_v4_prefix_list = ''
        LEAF_v6_prefix_list = ''
        LEAF_BGP_AS_num = ''
        LEAF_VRF_name = ''
        LEAF_rt_map_seq_num = 5

        PGW_v4_prfx_name = ''
        PGW_v6_prfx_name = ''
        PGW_rt_map_name = ''

        for pvnfLeaf in pvnfTopoLeavesDict:
            if type(pvnfTopoLeavesDict[pvnfLeaf]) == dict:

                # Retrieve PGW BGP AS number and VRF name
                PGW_BGP_AS_num = pvnfTopoLeavesDict[pvnfLeaf]['pgw_bgp_as']
                LEAF_BGP_AS_num = pvnfTopoLeavesDict[pvnfLeaf]['leaf_as']
                if PGW_VRF_name == '':
                    PGW_VRF_name = pvnfTopoLeavesDict['vrf']
                if LEAF_VRF_name == '':
                    LEAF_VRF_name = pvnfTopoLeavesDict['vrf']

                # Retrieve the Prefix and Route-map names
                PGW_v4_prfx_name = pvnfTopoLeavesDict[pvnfLeaf]['PGW_v4_prfx_lst_name']
                PGW_v6_prfx_name = pvnfTopoLeavesDict[pvnfLeaf]['PGW_v6_prfx_lst_name']
                PGW_rt_map_name = pvnfTopoLeavesDict[pvnfLeaf]['PGW_route_map_name']

                LEAF_v4_prfx_name = pvnfTopoLeavesDict[pvnfLeaf]['LEAF_v4_prfx_lst_name']
                LEAF_v6_prfx_name = pvnfTopoLeavesDict[pvnfLeaf]['LEAF_v6_prfx_lst_name']
                LEAF_rt_map_name = pvnfTopoLeavesDict[pvnfLeaf]['LEAF_route_map_name']

                if (str(pvnfTopoLeavesDict['type']) == "topo_1") or (str(pvnfTopoLeavesDict['type']) == "topo_2"):

                    underlay_v4_nw = ip.IPv4Interface(str(pvnfTopoLeavesDict[pvnfLeaf]['underlay_ipv4_start']) + '/16')
                    underlay_v6_nw = ip.IPv6Interface(str(pvnfTopoLeavesDict[pvnfLeaf]['underlay_ipv6_start']) + '/48')

                    if str(pvnfTopoLeavesDict[pvnfLeaf]['pgw_comn_loop_v4']) not in PGW_v4_prefix_list:
                        PGW_v4_prefix_list += '''
                            ip prefix-list ''' + str(PGW_v4_prfx_name) + ''' permit ''' + str(
                            pvnfTopoLeavesDict[pvnfLeaf]['pgw_comn_loop_v4']) + '''/32
                        '''
                    if str(pvnfTopoLeavesDict[pvnfLeaf]['pgw_comn_loop_v6']) not in PGW_v6_prefix_list:
                        PGW_v6_prefix_list += '''
                            ipv6 prefix-list ''' + str(PGW_v6_prfx_name) + ''' permit ''' + str(
                            pvnfTopoLeavesDict[pvnfLeaf]['pgw_comn_loop_v6']) + '''/128
                        '''

                    if (str(pvnfTopoLeavesDict[pvnfLeaf]['pgw_comn_loop_v4']) not in LEAF_v4_prefix_list) and (
                            str(pvnfTopoLeavesDict[pvnfLeaf]['local_loop_v4']) not in LEAF_v4_prefix_list):
                        LEAF_v4_prefix_list += '''
                            ip prefix-list ''' + str(LEAF_v4_prfx_name) + ''' permit ''' + str(
                            pvnfTopoLeavesDict[pvnfLeaf]['pgw_comn_loop_v4']) + '''/32
                            ip prefix-list ''' + str(LEAF_v4_prfx_name) + ''' permit ''' + str(
                            pvnfTopoLeavesDict[pvnfLeaf]['local_loop_v4']) + '''/32
                            ip prefix-list ''' + str(LEAF_v4_prfx_name) + ''' permit ''' + str(
                            underlay_v4_nw.network) + ''' le ''' + str(underlay_v4_nw.max_prefixlen) + '''
                        '''

                    if (str(pvnfTopoLeavesDict[pvnfLeaf]['pgw_comn_loop_v6']) not in LEAF_v6_prefix_list) and (
                            str(pvnfTopoLeavesDict[pvnfLeaf]['local_loop_v6']) not in LEAF_v6_prefix_list):
                        LEAF_v4_prefix_list += '''
                            ipv6 prefix-list ''' + str(LEAF_v6_prfx_name) + ''' permit ''' + str(
                            pvnfTopoLeavesDict[pvnfLeaf]['pgw_comn_loop_v6']) + '''/128
                            ipv6 prefix-list ''' + str(LEAF_v6_prfx_name) + ''' permit ''' + str(
                            pvnfTopoLeavesDict[pvnfLeaf]['local_loop_v6']) + '''/128
                            ipv6 prefix-list ''' + str(LEAF_v6_prfx_name) + ''' permit ''' + str(
                            underlay_v6_nw.network) + ''' le ''' + str(underlay_v6_nw.max_prefixlen) + '''
                        '''

                if str(pvnfTopoLeavesDict['type']) == "topo_3":

                    for leaf in pvnfTopoLeavesDict:
                        if type(pvnfTopoLeavesDict[leaf]) == dict:
                            underlay_v4_nw = ip.IPv4Interface(
                                str(pvnfTopoLeavesDict[leaf]['underlay_ipv4_start']) + '/16')
                            underlay_v6_nw = ip.IPv6Interface(
                                str(pvnfTopoLeavesDict[leaf]['underlay_ipv6_start']) + '/48')

                            if str(underlay_v4_nw.network) not in PGW_v4_prefix_list:
                                PGW_v4_prefix_list += '''
                                    ip prefix-list ''' + str(PGW_v4_prfx_name) + ''' permit ''' + str(
                                    underlay_v4_nw.network) + ''' le ''' + str(underlay_v4_nw.max_prefixlen) + '''
                                '''
                            if str(underlay_v6_nw.network) not in PGW_v6_prefix_list:
                                PGW_v6_prefix_list += '''
                                    ipv6 prefix-list ''' + str(PGW_v6_prfx_name) + ''' permit ''' + str(
                                    underlay_v6_nw.network) + ''' le ''' + str(underlay_v6_nw.max_prefixlen) + '''
                                '''

                            if str(underlay_v4_nw.network) not in LEAF_v4_prefix_list:
                                LEAF_v4_prefix_list += '''
                                    ip prefix-list ''' + str(LEAF_v4_prfx_name) + ''' permit ''' + str(
                                    underlay_v4_nw.network) + ''' le ''' + str(underlay_v4_nw.max_prefixlen) + '''
                                '''
                            if str(underlay_v6_nw.network) not in LEAF_v6_prefix_list:
                                LEAF_v6_prefix_list += '''
                                    ipv6 prefix-list ''' + str(LEAF_v6_prfx_name) + ''' permit ''' + str(
                                    underlay_v6_nw.network) + ''' le ''' + str(underlay_v6_nw.max_prefixlen) + '''
                                '''

                log.info(banner("Configuring LEAF Prefix List and Redistribution in BGP"))

                pvnfLeaf.configure(LEAF_v4_prefix_list)
                pvnfLeaf.configure(LEAF_v6_prefix_list)

                pvnfLeaf.configure('''
                    route-map ''' + str(LEAF_rt_map_name) + ''' permit ''' + str(LEAF_rt_map_seq_num) + '''
                        match ip address prefix-list ''' + str(LEAF_v4_prfx_name) + '''
                        set path-selection all advertise
                        set ip next-hop redist-unchanged
    
                    route-map ''' + str(LEAF_rt_map_name) + ''' permit ''' + str(int(LEAF_rt_map_seq_num) + 5) + '''
                        match ipv6 address prefix-list ''' + str(LEAF_v6_prfx_name) + '''
                        set path-selection all advertise
                        set ipv6 next-hop redist-unchanged
                ''')

                if (LEAF_BGP_AS_num != '') and (LEAF_VRF_name != ''):
                    pvnfLeaf.configure('''
                        router bgp ''' + str(LEAF_BGP_AS_num) + '''
                            address-family l2vpn evpn
                                additional-paths selection route-map ''' + str(LEAF_rt_map_name) + '''
                            vrf ''' + str(LEAF_VRF_name) + '''
                                address-family ipv4 unicast
                                    redistribute direct route-map ''' + str(LEAF_rt_map_name) + '''
                                    redistribute static route-map ''' + str(LEAF_rt_map_name) + '''
                                address-family ipv6 unicast
                                    redistribute direct route-map ''' + str(LEAF_rt_map_name) + '''
                                    redistribute static route-map ''' + str(LEAF_rt_map_name) + '''
                    ''')

            LEAF_v4_prefix_list = ''
            LEAF_v6_prefix_list = ''
            LEAF_rt_map_seq_num = 5

        log.info(banner("Configuring PGW Prefix List and Redistribution in BGP"))

        PGW.configure(PGW_v4_prefix_list)
        PGW.configure(PGW_v6_prefix_list)

        PGW.configure('''
            route-map ''' + str(PGW_rt_map_name) + ''' permit ''' + str(PGW_rt_map_seq_num) + '''
                match ip address prefix-list ''' + str(PGW_v4_prfx_name) + '''
                set path-selection all advertise
            
            route-map ''' + str(PGW_rt_map_name) + ''' permit ''' + str(int(PGW_rt_map_seq_num) + 5) + '''
                match ipv6 address prefix-list ''' + str(PGW_v6_prfx_name) + '''
                set path-selection all advertise
        ''')

        if (PGW_BGP_AS_num != '') and (PGW_VRF_name != ''):
            PGW.configure('''
                router bgp ''' + str(PGW_BGP_AS_num) + '''
                    vrf ''' + str(PGW_VRF_name) + '''
                        address-family ipv4 unicast
                            redistribute static route-map ''' + str(PGW_rt_map_name) + '''
                            redistribute am route-map ''' + str(PGW_rt_map_name) + '''
                        address-family ipv6 unicast
                            redistribute static route-map ''' + str(PGW_rt_map_name) + '''
                            redistribute am route-map ''' + str(PGW_rt_map_name) + '''
            ''')


# ====================================================================================================#
# Nexus VxLAN PVNF Verification Methods
# ====================================================================================================#
class verifyVxlanEvpnPVNF:

    # First we create a constructor for this class
    # and add members to it, here models
    def __init__(self):
        pass

    # ====================================================================================================#
    @staticmethod
    def get_PGW_LEAF_nexthop_prefixes(dut, circuit, dst_ip, vrf):

        # --- Setting few variables
        nxt_hop_prefix_lst = []
        fwd_nxt_hop_prefix_lst = []
        num_of_nxt_hops = 0
        fwd_num_of_nxt_hops = 0
        route_info = {}
        parse_route_flag = 0

        # --- Get and parse the route-information for IPv4
        if circuit == 'v4':
            route_check = dut.execute('show ip route ' + str(dst_ip) + ' det vrf ' + str(vrf) + ' | beg ' + str(dst_ip))
            if str(dst_ip) in route_check:
                parse_route_flag = 1
                route_info = json.loads(dut.execute('show ip route ' + str(dst_ip) + ' det vrf ' + str(vrf) + ' | json'))
                num_of_nxt_hops = route_info['TABLE_vrf']['ROW_vrf']['TABLE_addrf']['ROW_addrf']['TABLE_prefix']['ROW_prefix']['ucast-nhops']

        # --- Get and parse the route-information for IPv4
        if circuit == 'v6':
            route_check = dut.execute('show ipv6 route ' + str(dst_ip) + ' det vrf ' + str(vrf) + ' | beg ' + str(dst_ip))
            if str(dst_ip) in route_check:
                parse_route_flag = 1
                route_info = json.loads(dut.execute('show ipv6 route ' + str(dst_ip) + ' det vrf ' + str(vrf) + ' | json'))
                num_of_nxt_hops = route_info['TABLE_vrf']['ROW_vrf']['TABLE_addrf']['ROW_addrf']['TABLE_prefix']['ROW_prefix']['ucast-nhops']

        if parse_route_flag == 0:
            nxt_hop_prefix_lst.append(str('Route not present for '+ str(dst_ip)))
        else:
            # --- Parse the route Information
            if type(route_info) == dict:
                if 'TABLE_vrf' in route_info.keys():
                    for prefix_dict in route_info['TABLE_vrf']['ROW_vrf']['TABLE_addrf']['ROW_addrf']['TABLE_prefix']['ROW_prefix']['TABLE_path']['ROW_path']:
                        if type(prefix_dict) is not str:
                            if prefix_dict['ipnexthop'] not in nxt_hop_prefix_lst:
                                nxt_hop_prefix_lst.append(prefix_dict['ipnexthop'])
                        else:
                            if route_info['TABLE_vrf']['ROW_vrf']['TABLE_addrf']['ROW_addrf']['TABLE_prefix']['ROW_prefix']['TABLE_path']['ROW_path']['ipnexthop'] not in nxt_hop_prefix_lst:
                                nxt_hop_prefix_lst.append(route_info['TABLE_vrf']['ROW_vrf']['TABLE_addrf']['ROW_addrf']['TABLE_prefix']['ROW_prefix']['TABLE_path']['ROW_path']['ipnexthop'])

            # --- Get and parse the forwarding-information
            if circuit == 'v4':
                
                fwd_info = json.loads(dut.execute('show for ipv4 route ' + str(dst_ip) + ' vrf ' + str(vrf) + ' | json'))
                if type(fwd_info['TABLE_module']['ROW_module']) is list:
                    if 'TABLE_path' in fwd_info['TABLE_module']['ROW_module'][0]['TABLE_vrf']['ROW_vrf']['TABLE_prefix']['ROW_prefix'].keys():
                        if type(fwd_info['TABLE_module']['ROW_module'][0]['TABLE_vrf']['ROW_vrf']['TABLE_prefix']['ROW_prefix']['TABLE_path']['ROW_path']) == list:
                            fwd_num_of_nxt_hops = len(fwd_info['TABLE_module']['ROW_module'][0]['TABLE_vrf']['ROW_vrf']['TABLE_prefix']['ROW_prefix']['TABLE_path']['ROW_path'])
                        elif type(fwd_info['TABLE_module']['ROW_module'][0]['TABLE_vrf']['ROW_vrf']['TABLE_prefix']['ROW_prefix']['TABLE_path']['ROW_path']) == dict:
                            if 'ip_nexthop' in fwd_info['TABLE_module']['ROW_module'][0]['TABLE_vrf']['ROW_vrf']['TABLE_prefix']['ROW_prefix']['TABLE_path']['ROW_path'].keys():
                                fwd_num_of_nxt_hops = list(fwd_info['TABLE_module']['ROW_module'][0]['TABLE_vrf']['ROW_vrf']['TABLE_prefix']['ROW_prefix']['TABLE_path']['ROW_path'].keys()).count('ip_nexthop')
                    else:
                        fwd_num_of_nxt_hops = 1
                elif type(fwd_info['TABLE_module']['ROW_module']) is dict:
                    if 'TABLE_vrf' in fwd_info.keys():
                        if 'TABLE_path' in fwd_info['TABLE_module']['ROW_module']['TABLE_vrf']['ROW_vrf']['TABLE_prefix']['ROW_prefix'].keys():
                            if type(fwd_info['TABLE_module']['ROW_module']['TABLE_vrf']['ROW_vrf']['TABLE_prefix']['ROW_prefix']['TABLE_path']['ROW_path']) == list:
                                fwd_num_of_nxt_hops = len(fwd_info['TABLE_module']['ROW_module']['TABLE_vrf']['ROW_vrf']['TABLE_prefix']['ROW_prefix']['TABLE_path']['ROW_path'])
                            elif type(fwd_info['TABLE_module']['ROW_module']['TABLE_vrf']['ROW_vrf']['TABLE_prefix']['ROW_prefix']['TABLE_path']['ROW_path']) == dict:
                                if 'ip_nexthop' in fwd_info['TABLE_module']['ROW_module']['TABLE_vrf']['ROW_vrf']['TABLE_prefix']['ROW_prefix']['TABLE_path']['ROW_path'].keys():
                                    fwd_num_of_nxt_hops = list(fwd_info['TABLE_module']['ROW_module']['TABLE_vrf']['ROW_vrf']['TABLE_prefix']['ROW_prefix']['TABLE_path']['ROW_path'].keys()).count('ip_nexthop')
                        else:
                            fwd_num_of_nxt_hops = 1
                    else:
                        fwd_num_of_nxt_hops = 1
                
                
                # fwd_info = json.loads(dut.execute('show for ipv4 route ' + str(dst_ip) + ' vrf ' + str(vrf) + ' | json'))
                # if 'TABLE_vrf' in fwd_info['TABLE_module']['ROW_module'].keys():
                #     if 'TABLE_path' in fwd_info['TABLE_module']['ROW_module']['TABLE_vrf']['ROW_vrf']['TABLE_prefix']['ROW_prefix'].keys():
                #         if type(fwd_info['TABLE_module']['ROW_module']['TABLE_vrf']['ROW_vrf']['TABLE_prefix']['ROW_prefix']['TABLE_path']['ROW_path']) == list:
                #             fwd_num_of_nxt_hops = len(fwd_info['TABLE_module']['ROW_module']['TABLE_vrf']['ROW_vrf']['TABLE_prefix']['ROW_prefix']['TABLE_path']['ROW_path'])
                #         elif type(fwd_info['TABLE_module']['ROW_module']['TABLE_vrf']['ROW_vrf']['TABLE_prefix']['ROW_prefix']['TABLE_path']['ROW_path']) == dict:
                #             if 'ip_nexthop' in fwd_info['TABLE_module']['ROW_module']['TABLE_vrf']['ROW_vrf']['TABLE_prefix']['ROW_prefix']['TABLE_path']['ROW_path'].keys():
                #                 fwd_num_of_nxt_hops = list(fwd_info['TABLE_module']['ROW_module']['TABLE_vrf']['ROW_vrf']['TABLE_prefix']['ROW_prefix']['TABLE_path']['ROW_path'].keys()).count('ip_nexthop')
                #     else:
                #         fwd_num_of_nxt_hops = 1
                # else:
                #     fwd_num_of_nxt_hops = 1

            # --- Get and parse the forwarding-information for IPv6
            if circuit == 'v6':
                fwd_info = dut.execute('show for ipv6 route ' + str(dst_ip) + ' det vrf ' + str(
                    vrf) + ' | ex "^$" | in i "vlan|nve|eth|po" | sed "s/ //g"')
                if fwd_info != '':
                    fwd_info = fwd_info.split('\n')
                    fwd_num_of_nxt_hops = len(fwd_info)
                else:
                    fwd_num_of_nxt_hops = 1

        return {
            'num_of_hops': num_of_nxt_hops,
            'prfx_lst': nxt_hop_prefix_lst,
            'fwd_num_of_hops': str(fwd_num_of_nxt_hops),
            'fwd_prfx_lst': fwd_nxt_hop_prefix_lst
        }

    # ====================================================================================================#
    def verifyPVNF_common_loopback_topology(self, BL, PGW, pvnfTopoLeavesDict):

        # ----------------------------------------------------
        # set global flags to carry fail messages and status
        # ----------------------------------------------------
        status_msgs = ""
        fail_flag = []

        # ----------------------------------------------------
        # Declare the Tables
        # ----------------------------------------------------
        BL_nextHopTable = texttable.Texttable()
        BL_nextHopTable.header(
            ['SRC NODE', 'Destination', 'Expected NH Count', 'Observed NH Count', 'Observed FWD NH Count', 'Status',
             'Next-hops'])
        BL_nextHopTable.set_cols_width([15, 25, 10, 10, 10, 10, 75])

        BL_host_nextHopTable = texttable.Texttable()
        BL_host_nextHopTable.header(
            ['SRC NODE', 'Destination', 'Expected NH Count', 'Observed NH Count', 'Observed FWD NH Count', 'Status',
             'Next-hops'])
        BL_host_nextHopTable.set_cols_width([15, 25, 10, 10, 10, 10, 75])

        PGW_to_LEAF_nextHopTable = texttable.Texttable()
        PGW_to_LEAF_nextHopTable.header(
            ['DST NODE', 'Destination', 'Expected NH Count', 'Observed NH Count', 'Observed FWD NH Count', 'Status',
             'Next-hops'])
        PGW_to_LEAF_nextHopTable.set_cols_width([15, 25, 10, 10, 10, 10, 75])

        LEAF_to_PGW_nextHopTable = texttable.Texttable()
        LEAF_to_PGW_nextHopTable.header(
            ['SRC NODE', 'Destination', 'Expected NH Count', 'Observed NH Count', 'Observed FWD NH Count', 'Status',
             'Next-hops'])
        LEAF_to_PGW_nextHopTable.set_cols_width([15, 25, 10, 10, 10, 10, 75])

        # ----------------------------------------------------
        # Retrieve the IPv4 and IPv6 routes to GW IP per LEAF
        # ----------------------------------------------------
        PGW_to_LEAF_loopback_route_dict = {}
        LEAF_to_PGW_loopback_route_dict = {}
        PGW_common_loopback_v4 = ''
        PGW_common_loopback_v6 = ''
        temp_leaf_for_iterations = ''
        BL_common_gateway_nxthop_count = 0
        BL_to_common_loopback_route_dict = {}
        BL_to_host_route_dict = {}

        # --- Get the route information from each LEAF
        for pvnfLeaf in pvnfTopoLeavesDict:
            if type(pvnfTopoLeavesDict[pvnfLeaf]) == dict:
                if (str(pvnfTopoLeavesDict['type']) == "topo_1") or (str(pvnfTopoLeavesDict['type']) == "topo_2"):
                    # --- Set few Iteration variables
                    temp_leaf_for_iterations = pvnfLeaf
                    PGW_common_loopback_v4 = str(pvnfTopoLeavesDict[pvnfLeaf]['pgw_comn_loop_v4'])
                    PGW_common_loopback_v6 = str(pvnfTopoLeavesDict[pvnfLeaf]['pgw_comn_loop_v6'])
                    PGW_to_LEAF_loopback_route_dict[pvnfLeaf] = {}
                    LEAF_to_PGW_loopback_route_dict[pvnfLeaf] = {}
                    PGW_to_LEAF_loopback_route_dict[pvnfLeaf]['PGW_to_LEAF_GW_v4_route_prefix_lst'] = []
                    LEAF_to_PGW_loopback_route_dict[pvnfLeaf]['LEAF_to_PGW_GW_v4_route_prefix_lst'] = []
                    PGW_to_LEAF_loopback_route_dict[pvnfLeaf]['PGW_to_LEAF_GW_v6_route_prefix_lst'] = []
                    LEAF_to_PGW_loopback_route_dict[pvnfLeaf]['LEAF_to_PGW_GW_v6_route_prefix_lst'] = []

                    # --- Get and append the no.of next-hops from each LEAF to gateway
                    BL_common_gateway_nxthop_count += int(pvnfTopoLeavesDict[pvnfLeaf]['leaf_to_pgw_link_count'])

                    # --- Get the IPv4 Routes for GW IP from PGW to LEAF
                    PGW_v4_prfx_data = self.get_PGW_LEAF_nexthop_prefixes(PGW, 'v4', str(
                        pvnfTopoLeavesDict[pvnfLeaf]['local_loop_v4']), str(pvnfTopoLeavesDict['vrf']))
                    PGW_to_LEAF_loopback_route_dict[pvnfLeaf]['PGW_to_LEAF_GW_v4_route_prefix_count'] = \
                    PGW_v4_prfx_data['num_of_hops']
                    PGW_to_LEAF_loopback_route_dict[pvnfLeaf]['PGW_to_LEAF_GW_v4_route_prefix_lst'] = PGW_v4_prfx_data[
                        'prfx_lst']
                    PGW_to_LEAF_loopback_route_dict[pvnfLeaf]['PGW_to_LEAF_GW_v4_fwd_route_prefix_count'] = \
                    PGW_v4_prfx_data['fwd_num_of_hops']
                    PGW_to_LEAF_loopback_route_dict[pvnfLeaf]['PGW_to_LEAF_GW_v4_fwd_route_prefix_lst'] = \
                    PGW_v4_prfx_data['fwd_prfx_lst']

                    # --- Get the IPv4 Routes for GW IP from LEAF to PGW
                    LEAF_v4_prfx_data = self.get_PGW_LEAF_nexthop_prefixes(pvnfLeaf, 'v4', str(
                        pvnfTopoLeavesDict[pvnfLeaf]['pgw_comn_loop_v4']), str(pvnfTopoLeavesDict['vrf']))
                    LEAF_to_PGW_loopback_route_dict[pvnfLeaf]['LEAF_to_PGW_GW_v4_route_prefix_count'] = \
                    LEAF_v4_prfx_data['num_of_hops']
                    LEAF_to_PGW_loopback_route_dict[pvnfLeaf]['LEAF_to_PGW_GW_v4_route_prefix_lst'] = LEAF_v4_prfx_data[
                        'prfx_lst']
                    LEAF_to_PGW_loopback_route_dict[pvnfLeaf]['LEAF_to_PGW_GW_v4_fwd_route_prefix_count'] = \
                    LEAF_v4_prfx_data['fwd_num_of_hops']
                    LEAF_to_PGW_loopback_route_dict[pvnfLeaf]['LEAF_to_PGW_GW_v4_fwd_route_prefix_lst'] = \
                    LEAF_v4_prfx_data['fwd_prfx_lst']

                    # --- Get the IPv6 Routes for GW IP from PGW to LEAF
                    PGW_v6_prfx_data = self.get_PGW_LEAF_nexthop_prefixes(PGW, 'v6', str(
                        pvnfTopoLeavesDict[pvnfLeaf]['local_loop_v6']), str(pvnfTopoLeavesDict['vrf']))
                    PGW_to_LEAF_loopback_route_dict[pvnfLeaf]['PGW_to_LEAF_GW_v6_route_prefix_count'] = \
                    PGW_v6_prfx_data['num_of_hops']
                    PGW_to_LEAF_loopback_route_dict[pvnfLeaf]['PGW_to_LEAF_GW_v6_route_prefix_lst'] = PGW_v6_prfx_data[
                        'prfx_lst']
                    PGW_to_LEAF_loopback_route_dict[pvnfLeaf]['PGW_to_LEAF_GW_v6_fwd_route_prefix_count'] = \
                    PGW_v6_prfx_data['fwd_num_of_hops']
                    PGW_to_LEAF_loopback_route_dict[pvnfLeaf]['PGW_to_LEAF_GW_v6_fwd_route_prefix_lst'] = \
                    PGW_v6_prfx_data['fwd_prfx_lst']

                    # --- Get the IPv6 Routes for GW IP from LEAF to PGW
                    LEAF_v6_prfx_data = self.get_PGW_LEAF_nexthop_prefixes(pvnfLeaf, 'v6', str(
                        pvnfTopoLeavesDict[pvnfLeaf]['pgw_comn_loop_v6']), str(pvnfTopoLeavesDict['vrf']))
                    LEAF_to_PGW_loopback_route_dict[pvnfLeaf]['LEAF_to_PGW_GW_v6_route_prefix_count'] = \
                    LEAF_v6_prfx_data['num_of_hops']
                    LEAF_to_PGW_loopback_route_dict[pvnfLeaf]['LEAF_to_PGW_GW_v6_route_prefix_lst'] = LEAF_v6_prfx_data[
                        'prfx_lst']
                    LEAF_to_PGW_loopback_route_dict[pvnfLeaf]['LEAF_to_PGW_GW_v6_fwd_route_prefix_count'] = \
                    LEAF_v6_prfx_data['fwd_num_of_hops']
                    LEAF_to_PGW_loopback_route_dict[pvnfLeaf]['LEAF_to_PGW_GW_v6_fwd_route_prefix_lst'] = \
                    LEAF_v6_prfx_data['fwd_prfx_lst']

        # --- Get the IPv4 Routes for GW IP from PGW to LEAF
        BL_v4_prfx_data = self.get_PGW_LEAF_nexthop_prefixes(BL, 'v4', str(PGW_common_loopback_v4),
                                                             str(pvnfTopoLeavesDict['vrf']))
        BL_to_common_loopback_route_dict['BL_to_LEAF_GW_v4_route_prefix_count'] = BL_v4_prfx_data['num_of_hops']
        BL_to_common_loopback_route_dict['BL_to_LEAF_GW_v4_route_prefix_lst'] = BL_v4_prfx_data['prfx_lst']
        BL_to_common_loopback_route_dict['BL_to_LEAF_GW_v4_fwd_route_prefix_count'] = BL_v4_prfx_data['fwd_num_of_hops']
        BL_to_common_loopback_route_dict['BL_to_LEAF_GW_v4_fwd_route_prefix_lst'] = BL_v4_prfx_data['fwd_prfx_lst']

        # --- Get the IPv6 Routes for GW IP from PGW to LEAF
        BL_v6_prfx_data = self.get_PGW_LEAF_nexthop_prefixes(BL, 'v6', str(PGW_common_loopback_v6),
                                                             str(pvnfTopoLeavesDict['vrf']))
        BL_to_common_loopback_route_dict['PGW_to_LEAF_GW_v6_route_prefix_count'] = BL_v6_prfx_data['num_of_hops']
        BL_to_common_loopback_route_dict['PGW_to_LEAF_GW_v6_route_prefix_lst'] = BL_v6_prfx_data['prfx_lst']
        BL_to_common_loopback_route_dict['PGW_to_LEAF_GW_v6_fwd_route_prefix_count'] = BL_v6_prfx_data[
            'fwd_num_of_hops']
        BL_to_common_loopback_route_dict['PGW_to_LEAF_GW_v6_fwd_route_prefix_lst'] = BL_v6_prfx_data['fwd_prfx_lst']

        # --- Generate Random host IP
        host_ipv4 = ip.IPv4Interface(str(pvnfTopoLeavesDict['BGP_v4_prefixes']) + '/24')
        host_ipv6 = ip.IPv6Interface(str(pvnfTopoLeavesDict['BGP_v6_prefixes']) + '/128')
        host_ipv4_routes_per_route_range = int(int(pvnfTopoLeavesDict['no_of_hosts']) / 4) - 1
        host_ipv4 += (random.randint(2, host_ipv4_routes_per_route_range))
        random_octet = str(random.choice(string.hexdigits.lower()[6:]))
        random_host_ipv6 = re.sub('::\d+', '::' + str(random_octet), str(host_ipv6))

        # --- Get the IPv4 Routes for HOST IP from PGW to LEAF
        BL_host_v4_prfx_data = self.get_PGW_LEAF_nexthop_prefixes(BL, 'v4', str(host_ipv4),
                                                                  str(pvnfTopoLeavesDict['vrf']))
        BL_to_host_route_dict['BL_to_VNF_HOST_v4_route_prefix_count'] = BL_host_v4_prfx_data['num_of_hops']
        BL_to_host_route_dict['BL_to_VNF_HOST_v4_route_prefix_lst'] = BL_host_v4_prfx_data['prfx_lst']
        BL_to_host_route_dict['BL_to_VNF_HOST_v4_fwd_route_prefix_count'] = BL_host_v4_prfx_data['fwd_num_of_hops']
        BL_to_host_route_dict['BL_to_VNF_HOST_v4_fwd_route_prefix_lst'] = BL_host_v4_prfx_data['fwd_prfx_lst']

        # --- Get the IPv6 Routes for HOST IP from PGW to LEAF
        BL_host_v6_prfx_data = self.get_PGW_LEAF_nexthop_prefixes(BL, 'v6', str(random_host_ipv6),
                                                                  str(pvnfTopoLeavesDict['vrf']))
        BL_to_host_route_dict['BL_to_VNF_HOST_v6_route_prefix_count'] = BL_host_v6_prfx_data['num_of_hops']
        BL_to_host_route_dict['BL_to_VNF_HOST_v6_route_prefix_lst'] = BL_host_v6_prfx_data['prfx_lst']
        BL_to_host_route_dict['BL_to_VNF_HOST_v6_fwd_route_prefix_count'] = BL_host_v6_prfx_data['fwd_num_of_hops']
        BL_to_host_route_dict['BL_to_VNF_HOST_v6_fwd_route_prefix_lst'] = BL_host_v6_prfx_data['fwd_prfx_lst']

        # ----------------------------------------------------
        # Validation of routes and generate tables
        # ----------------------------------------------------
        for leaf in PGW_to_LEAF_loopback_route_dict:

            # --- Set few variables
            PGW_to_LEAF_v4_nh_count_status = 'FAIL'
            PGW_to_LEAF_v6_nh_count_status = 'FAIL'
            LEAF_to_PGW_v4_nh_count_status = 'FAIL'
            LEAF_to_PGW_v6_nh_count_status = 'FAIL'

            # --- Validate LEAF to PGW route, consider if the LEAF is EW Traffic Source
            if 'EW_LEAF_SRC' in pvnfTopoLeavesDict[leaf].keys():
                if int(pvnfTopoLeavesDict[leaf]['EW_LEAF_SRC']) == 1:
                    if (int(LEAF_to_PGW_loopback_route_dict[leaf]['LEAF_to_PGW_GW_v4_route_prefix_count']) == int(
                            BL_v4_prfx_data['num_of_hops'])) and \
                            (int(LEAF_to_PGW_loopback_route_dict[leaf][
                                     'LEAF_to_PGW_GW_v4_fwd_route_prefix_count']) == int(
                                BL_v4_prfx_data['num_of_hops'])):
                        LEAF_to_PGW_v4_nh_count_status = 'PASS'
                    else:
                        fail_flag.append(0)
                    if (int(LEAF_to_PGW_loopback_route_dict[leaf]['LEAF_to_PGW_GW_v6_route_prefix_count']) == int(
                            BL_v4_prfx_data['num_of_hops'])) and \
                            (int(LEAF_to_PGW_loopback_route_dict[leaf][
                                     'LEAF_to_PGW_GW_v6_fwd_route_prefix_count']) == int(
                                BL_v4_prfx_data['num_of_hops'])):
                        LEAF_to_PGW_v6_nh_count_status = 'PASS'
                    else:
                        fail_flag.append(0)
                    LEAF_to_PGW_nextHopTable.add_row([
                        leaf.alias,
                        str(pvnfTopoLeavesDict[leaf]['pgw_comn_loop_v4']),
                        BL_v4_prfx_data['num_of_hops'],
                        LEAF_to_PGW_loopback_route_dict[leaf]['LEAF_to_PGW_GW_v4_route_prefix_count'],
                        LEAF_to_PGW_loopback_route_dict[leaf]['LEAF_to_PGW_GW_v4_fwd_route_prefix_count'],
                        LEAF_to_PGW_v4_nh_count_status,
                        LEAF_to_PGW_loopback_route_dict[leaf]['LEAF_to_PGW_GW_v4_route_prefix_lst']
                    ])
                    LEAF_to_PGW_nextHopTable.add_row([
                        leaf.alias,
                        str(pvnfTopoLeavesDict[leaf]['pgw_comn_loop_v6']),
                        BL_v4_prfx_data['num_of_hops'],
                        LEAF_to_PGW_loopback_route_dict[leaf]['LEAF_to_PGW_GW_v6_route_prefix_count'],
                        LEAF_to_PGW_loopback_route_dict[leaf]['LEAF_to_PGW_GW_v6_fwd_route_prefix_count'],
                        LEAF_to_PGW_v6_nh_count_status,
                        LEAF_to_PGW_loopback_route_dict[leaf]['LEAF_to_PGW_GW_v6_route_prefix_lst']]
                    )
            else:
                if (int(pvnfTopoLeavesDict[leaf]['leaf_to_pgw_link_count']) == int(
                        LEAF_to_PGW_loopback_route_dict[leaf]['LEAF_to_PGW_GW_v4_route_prefix_count'])) and \
                        (int(pvnfTopoLeavesDict[leaf]['leaf_to_pgw_link_count']) == int(
                            LEAF_to_PGW_loopback_route_dict[leaf]['LEAF_to_PGW_GW_v4_fwd_route_prefix_count'])):
                    LEAF_to_PGW_v4_nh_count_status = 'PASS'
                else:
                    fail_flag.append(0)
                if (int(pvnfTopoLeavesDict[leaf]['leaf_to_pgw_link_count']) == int(
                        LEAF_to_PGW_loopback_route_dict[leaf]['LEAF_to_PGW_GW_v6_route_prefix_count'])) and \
                        (int(pvnfTopoLeavesDict[leaf]['leaf_to_pgw_link_count']) == int(
                            LEAF_to_PGW_loopback_route_dict[leaf]['LEAF_to_PGW_GW_v6_fwd_route_prefix_count'])):
                    LEAF_to_PGW_v6_nh_count_status = 'PASS'
                else:
                    fail_flag.append(0)
                LEAF_to_PGW_nextHopTable.add_row([
                    leaf.alias,
                    str(pvnfTopoLeavesDict[leaf]['pgw_comn_loop_v4']),
                    pvnfTopoLeavesDict[leaf]['leaf_to_pgw_link_count'],
                    LEAF_to_PGW_loopback_route_dict[leaf]['LEAF_to_PGW_GW_v4_route_prefix_count'],
                    LEAF_to_PGW_loopback_route_dict[leaf]['LEAF_to_PGW_GW_v4_fwd_route_prefix_count'],
                    LEAF_to_PGW_v4_nh_count_status,
                    LEAF_to_PGW_loopback_route_dict[leaf]['LEAF_to_PGW_GW_v4_route_prefix_lst']
                ])
                LEAF_to_PGW_nextHopTable.add_row([
                    leaf.alias,
                    str(pvnfTopoLeavesDict[leaf]['pgw_comn_loop_v6']),
                    pvnfTopoLeavesDict[leaf]['leaf_to_pgw_link_count'],
                    LEAF_to_PGW_loopback_route_dict[leaf]['LEAF_to_PGW_GW_v6_route_prefix_count'],
                    LEAF_to_PGW_loopback_route_dict[leaf]['LEAF_to_PGW_GW_v6_fwd_route_prefix_count'],
                    LEAF_to_PGW_v6_nh_count_status,
                    LEAF_to_PGW_loopback_route_dict[leaf]['LEAF_to_PGW_GW_v6_route_prefix_lst']]
                )

            # --- Validate PGW to LEAF routes
            if (int(PGW_to_LEAF_loopback_route_dict[leaf]['PGW_to_LEAF_GW_v4_route_prefix_count']) >= 1) and (
                    int(PGW_to_LEAF_loopback_route_dict[leaf]['PGW_to_LEAF_GW_v4_fwd_route_prefix_count']) >= 1):
                PGW_to_LEAF_v4_nh_count_status = 'PASS'
            else:
                fail_flag.append(0)
            if (int(PGW_to_LEAF_loopback_route_dict[leaf]['PGW_to_LEAF_GW_v6_route_prefix_count']) >= 1) and (
                    int(PGW_to_LEAF_loopback_route_dict[leaf]['PGW_to_LEAF_GW_v6_fwd_route_prefix_count']) >= 1):
                PGW_to_LEAF_v6_nh_count_status = 'PASS'
            else:
                fail_flag.append(0)
            # ['DST NODE', 'Destination', 'Expected NH Count', 'Observed NH Count', 'status', 'Next-hops']
            PGW_to_LEAF_nextHopTable.add_row([
                leaf.alias,
                str(pvnfTopoLeavesDict[leaf]['local_loop_v4']),
                '>= 1',
                PGW_to_LEAF_loopback_route_dict[leaf]['PGW_to_LEAF_GW_v4_route_prefix_count'],
                PGW_to_LEAF_loopback_route_dict[leaf]['PGW_to_LEAF_GW_v4_fwd_route_prefix_count'],
                PGW_to_LEAF_v4_nh_count_status,
                PGW_to_LEAF_loopback_route_dict[leaf]['PGW_to_LEAF_GW_v4_route_prefix_lst']
            ])
            PGW_to_LEAF_nextHopTable.add_row([
                leaf.alias,
                str(pvnfTopoLeavesDict[leaf]['local_loop_v6']),
                '>= 1',
                PGW_to_LEAF_loopback_route_dict[leaf]['PGW_to_LEAF_GW_v6_route_prefix_count'],
                PGW_to_LEAF_loopback_route_dict[leaf]['PGW_to_LEAF_GW_v6_fwd_route_prefix_count'],
                PGW_to_LEAF_v6_nh_count_status,
                PGW_to_LEAF_loopback_route_dict[leaf]['PGW_to_LEAF_GW_v6_route_prefix_lst']
            ])

        # --- Generate the tables BL_common_gateway_nxthop_count
        BL_v4_nh_count_status = 'FAIL'
        BL_v6_nh_count_status = 'FAIL'
        BL_v4_host_nh_count_status = 'FAIL'
        BL_v6_host_nh_count_status = 'FAIL'

        if (int(BL_common_gateway_nxthop_count) == int(BL_v4_prfx_data['num_of_hops'])) and (int(BL_common_gateway_nxthop_count) == int(BL_v4_prfx_data['fwd_num_of_hops'])):
            BL_v4_nh_count_status = 'PASS'
        else:
            fail_flag.append(0)
        if (int(BL_common_gateway_nxthop_count) == int(BL_v6_prfx_data['num_of_hops'])) and (int(BL_common_gateway_nxthop_count) == int(BL_v6_prfx_data['fwd_num_of_hops'])):
            BL_v6_nh_count_status = 'PASS'
        else:
            fail_flag.append(0)

        if (int(BL_to_host_route_dict['BL_to_VNF_HOST_v4_route_prefix_count']) == 1) and \
                (int(BL_common_gateway_nxthop_count) == int(
                    BL_to_host_route_dict['BL_to_VNF_HOST_v4_fwd_route_prefix_count'])):
            BL_v4_host_nh_count_status = 'PASS'
        else:
            fail_flag.append(0)
        if (int(BL_to_host_route_dict['BL_to_VNF_HOST_v6_route_prefix_count']) == 1) and \
                (int(BL_common_gateway_nxthop_count) == int(
                    BL_to_host_route_dict['BL_to_VNF_HOST_v6_fwd_route_prefix_count'])):
            BL_v6_host_nh_count_status = 'PASS'
        else:
            fail_flag.append(0)

        BL_nextHopTable.add_row(
            [BL.alias, PGW_common_loopback_v4, BL_common_gateway_nxthop_count, BL_v4_prfx_data['num_of_hops'],
             BL_v4_prfx_data['fwd_num_of_hops'], BL_v4_nh_count_status, BL_v4_prfx_data['prfx_lst']])
        BL_nextHopTable.add_row(
            [BL.alias, PGW_common_loopback_v6, BL_common_gateway_nxthop_count, BL_v6_prfx_data['num_of_hops'],
             BL_v6_prfx_data['fwd_num_of_hops'], BL_v6_nh_count_status, BL_v6_prfx_data['prfx_lst']])

        BL_host_nextHopTable.add_row([BL.alias, host_ipv4, BL_common_gateway_nxthop_count,
                                      BL_to_host_route_dict['BL_to_VNF_HOST_v4_route_prefix_count'],
                                      BL_to_host_route_dict['BL_to_VNF_HOST_v4_fwd_route_prefix_count'],
                                      BL_v4_host_nh_count_status,
                                      BL_to_host_route_dict['BL_to_VNF_HOST_v4_route_prefix_lst']])
        BL_host_nextHopTable.add_row([BL.alias, random_host_ipv6, BL_common_gateway_nxthop_count,
                                      BL_to_host_route_dict['BL_to_VNF_HOST_v6_route_prefix_count'],
                                      BL_to_host_route_dict['BL_to_VNF_HOST_v6_fwd_route_prefix_count'],
                                      BL_v6_host_nh_count_status,
                                      BL_to_host_route_dict['BL_to_VNF_HOST_v6_route_prefix_lst']])

        status_msgs += '''
*** Legend
SRC NODE        == Source Node
DST NODE        == Destination Node
Destination     == Destination IP
NH Count        == Next-hops count
FWD NH Count    == Counts of Next-hops installed in hardware 'sh forwarding ipv4/v6 route'
Status          == Gives the tally of counts matching the expectations

====> Checking the Route DB from Individual LEAF's to PGW Common Gateway

''' + str(banner("IPv4/IPv6 Routes from LEAF loopback to Corresponding PGW Common Gateway (" + str(
            pvnfTopoLeavesDict[temp_leaf_for_iterations]['pgw_comn_loop_v4']) + ")", 145)) + '''
''' + str(LEAF_to_PGW_nextHopTable.draw()) + '''

====> Checking the Route DB from PGW Common Gateway to each Individual LEAF

''' + str(banner("IPv4/IPv6 Routes from PGW Common Gateway (" + str(
            pvnfTopoLeavesDict[temp_leaf_for_iterations]['local_loop_v4']) + ") to Corresponding LEAF loopback", 145)) + '''
''' + str(PGW_to_LEAF_nextHopTable.draw()) + '''

====> Checking the Route DB from BL to Corresponding PGW Common Gateway

''' + str(banner("Routes from BL to Corresponding PGW Common Gateway", 145)) + '''
''' + str(BL_nextHopTable.draw()) + '''

====> Checking the Route DB from BL to a Random Host

''' + str(banner("Routes from BL to Random HOST", 145)) + '''
''' + str(BL_host_nextHopTable.draw()) + '''
        '''

        if 0 in fail_flag:
            status = 0
        else:
            status = 1

        return {'result': status, 'status_msgs': status_msgs}

    # ====================================================================================================#
    def verifyPVNF_individual_loopback_topology(self, BL, PGW, pvnfTopoLeavesDict):

        # ----------------------------------------------------
        # set global flags to carry fail messages and status
        # ----------------------------------------------------
        status_msgs = ""
        fail_flag = []

        # ----------------------------------------------------
        # Declare the Tables
        # ----------------------------------------------------
        BL_nextHopTable = texttable.Texttable()
        BL_nextHopTable.header(
            ['DST NODE', 'Destination', 'Expected NH Count', 'Observed NH Count', 'Observed FWD NH Count', 'Status',
             'Next-hops'])
        BL_nextHopTable.set_cols_width([15, 25, 10, 10, 10, 10, 75])

        BL_host_nextHopTable = texttable.Texttable()
        BL_host_nextHopTable.header(
            ['SRC NODE', 'Destination', 'Expected NH Count', 'Observed NH Count', 'Observed FWD NH Count', 'Status',
             'Next-hops'])
        BL_host_nextHopTable.set_cols_width([15, 25, 10, 10, 10, 10, 75])

        PGW_to_LEAF_nextHopTable = texttable.Texttable()
        PGW_to_LEAF_nextHopTable.header(
            ['DST NODE', 'Destination', 'Expected NH Count', 'Observed NH Count', 'Observed FWD NH Count', 'Status',
             'Next-hops'])
        PGW_to_LEAF_nextHopTable.set_cols_width([15, 25, 10, 10, 10, 10, 75])

        LEAF_to_PGW_nextHopTable = texttable.Texttable()
        LEAF_to_PGW_nextHopTable.header(
            ['SRC NODE', 'Destination', 'Expected NH Count', 'Observed NH Count', 'Observed FWD NH Count', 'Status',
             'Next-hops'])
        LEAF_to_PGW_nextHopTable.set_cols_width([15, 25, 10, 10, 10, 10, 75])

        # ----------------------------------------------------
        # Retrieve the IPv4 and IPv6 routes to GW IP per LEAF
        # ----------------------------------------------------
        PGW_to_LEAF_loopback_route_dict = {}
        LEAF_to_PGW_loopback_route_dict = {}
        temp_leaf_for_iterations = ''
        BL_common_gateway_nxthop_count = 0
        PVNF_LEAF_count = 0
        BL_to_common_loopback_route_dict = {}
        BL_to_host_route_dict = {}

        # --- Get the route information from each LEAF
        for pvnfLeaf in pvnfTopoLeavesDict:
            if type(pvnfTopoLeavesDict[pvnfLeaf]) == dict:
                if (str(pvnfTopoLeavesDict['type']) == "topo_1") or (str(pvnfTopoLeavesDict['type']) == "topo_2"):
                    # --- Set few Iteration variables
                    temp_leaf_for_iterations = pvnfLeaf
                    PGW_to_LEAF_loopback_route_dict[pvnfLeaf] = {}
                    LEAF_to_PGW_loopback_route_dict[pvnfLeaf] = {}
                    BL_to_common_loopback_route_dict[pvnfLeaf] = {}
                    PGW_to_LEAF_loopback_route_dict[pvnfLeaf]['PGW_to_LEAF_GW_v4_route_prefix_lst'] = []
                    LEAF_to_PGW_loopback_route_dict[pvnfLeaf]['LEAF_to_PGW_GW_v4_route_prefix_lst'] = []
                    PGW_to_LEAF_loopback_route_dict[pvnfLeaf]['PGW_to_LEAF_GW_v6_route_prefix_lst'] = []
                    LEAF_to_PGW_loopback_route_dict[pvnfLeaf]['LEAF_to_PGW_GW_v6_route_prefix_lst'] = []
                    BL_to_common_loopback_route_dict[pvnfLeaf]['BL_to_LEAF_GW_v4_route_prefix_lst'] = []
                    BL_to_common_loopback_route_dict[pvnfLeaf]['BL_to_LEAF_GW_v6_route_prefix_lst'] = []

                    # --- Get and append the no.of next-hops from each LEAF to gateway
                    BL_common_gateway_nxthop_count += int(pvnfTopoLeavesDict[pvnfLeaf]['leaf_to_pgw_link_count'])
                    PVNF_LEAF_count += 1

                    # --- Get the IPv4 Routes for GW IP from PGW to LEAF
                    PGW_v4_prfx_data = self.get_PGW_LEAF_nexthop_prefixes(PGW, 'v4', str(
                        pvnfTopoLeavesDict[pvnfLeaf]['local_loop_v4']), str(pvnfTopoLeavesDict['vrf']))
                    PGW_to_LEAF_loopback_route_dict[pvnfLeaf]['PGW_to_LEAF_GW_v4_route_prefix_count'] = \
                    PGW_v4_prfx_data['num_of_hops']
                    PGW_to_LEAF_loopback_route_dict[pvnfLeaf]['PGW_to_LEAF_GW_v4_route_prefix_lst'] = PGW_v4_prfx_data[
                        'prfx_lst']
                    PGW_to_LEAF_loopback_route_dict[pvnfLeaf]['PGW_to_LEAF_GW_v4_fwd_route_prefix_count'] = \
                    PGW_v4_prfx_data['fwd_num_of_hops']
                    PGW_to_LEAF_loopback_route_dict[pvnfLeaf]['PGW_to_LEAF_GW_v4_fwd_route_prefix_lst'] = \
                    PGW_v4_prfx_data['fwd_prfx_lst']

                    # --- Get the IPv4 Routes for GW IP from LEAF to PGW
                    LEAF_v4_prfx_data = self.get_PGW_LEAF_nexthop_prefixes(pvnfLeaf, 'v4', str(
                        pvnfTopoLeavesDict[pvnfLeaf]['pgw_comn_loop_v4']), str(pvnfTopoLeavesDict['vrf']))
                    LEAF_to_PGW_loopback_route_dict[pvnfLeaf]['LEAF_to_PGW_GW_v4_route_prefix_count'] = \
                    LEAF_v4_prfx_data['num_of_hops']
                    LEAF_to_PGW_loopback_route_dict[pvnfLeaf]['LEAF_to_PGW_GW_v4_route_prefix_lst'] = LEAF_v4_prfx_data[
                        'prfx_lst']
                    LEAF_to_PGW_loopback_route_dict[pvnfLeaf]['LEAF_to_PGW_GW_v4_fwd_route_prefix_count'] = \
                    LEAF_v4_prfx_data['fwd_num_of_hops']
                    LEAF_to_PGW_loopback_route_dict[pvnfLeaf]['LEAF_to_PGW_GW_v4_fwd_route_prefix_lst'] = \
                    LEAF_v4_prfx_data['fwd_prfx_lst']

                    # --- Get the IPv6 Routes for GW IP from PGW to LEAF
                    PGW_v6_prfx_data = self.get_PGW_LEAF_nexthop_prefixes(PGW, 'v6', str(
                        pvnfTopoLeavesDict[pvnfLeaf]['local_loop_v6']), str(pvnfTopoLeavesDict['vrf']))
                    PGW_to_LEAF_loopback_route_dict[pvnfLeaf]['PGW_to_LEAF_GW_v6_route_prefix_count'] = \
                    PGW_v6_prfx_data['num_of_hops']
                    PGW_to_LEAF_loopback_route_dict[pvnfLeaf]['PGW_to_LEAF_GW_v6_route_prefix_lst'] = PGW_v6_prfx_data[
                        'prfx_lst']
                    PGW_to_LEAF_loopback_route_dict[pvnfLeaf]['PGW_to_LEAF_GW_v6_fwd_route_prefix_count'] = \
                    PGW_v6_prfx_data['fwd_num_of_hops']
                    PGW_to_LEAF_loopback_route_dict[pvnfLeaf]['PGW_to_LEAF_GW_v6_fwd_route_prefix_lst'] = \
                    PGW_v6_prfx_data['fwd_prfx_lst']

                    # --- Get the IPv6 Routes for GW IP from LEAF to PGW
                    LEAF_v6_prfx_data = self.get_PGW_LEAF_nexthop_prefixes(pvnfLeaf, 'v6', str(
                        pvnfTopoLeavesDict[pvnfLeaf]['pgw_comn_loop_v6']), str(pvnfTopoLeavesDict['vrf']))
                    LEAF_to_PGW_loopback_route_dict[pvnfLeaf]['LEAF_to_PGW_GW_v6_route_prefix_count'] = \
                    LEAF_v6_prfx_data['num_of_hops']
                    LEAF_to_PGW_loopback_route_dict[pvnfLeaf]['LEAF_to_PGW_GW_v6_route_prefix_lst'] = LEAF_v6_prfx_data[
                        'prfx_lst']
                    LEAF_to_PGW_loopback_route_dict[pvnfLeaf]['LEAF_to_PGW_GW_v6_fwd_route_prefix_count'] = \
                    LEAF_v6_prfx_data['fwd_num_of_hops']
                    LEAF_to_PGW_loopback_route_dict[pvnfLeaf]['LEAF_to_PGW_GW_v6_fwd_route_prefix_lst'] = \
                    LEAF_v6_prfx_data['fwd_prfx_lst']

                    # --- Get the IPv4 Routes for GW IP from PGW to LEAF
                    BL_v4_prfx_data = self.get_PGW_LEAF_nexthop_prefixes(BL, 'v4', str(
                        pvnfTopoLeavesDict[pvnfLeaf]['pgw_comn_loop_v4']), str(pvnfTopoLeavesDict['vrf']))
                    BL_to_common_loopback_route_dict[pvnfLeaf]['BL_to_LEAF_GW_v4_route_prefix_count'] = BL_v4_prfx_data[
                        'num_of_hops']
                    BL_to_common_loopback_route_dict[pvnfLeaf]['BL_to_LEAF_GW_v4_route_prefix_lst'] = BL_v4_prfx_data[
                        'prfx_lst']
                    BL_to_common_loopback_route_dict[pvnfLeaf]['BL_to_LEAF_GW_v4_fwd_route_prefix_count'] = \
                    BL_v4_prfx_data['fwd_num_of_hops']
                    BL_to_common_loopback_route_dict[pvnfLeaf]['BL_to_LEAF_GW_v4_fwd_route_prefix_lst'] = \
                    BL_v4_prfx_data['fwd_prfx_lst']

                    # --- Get the IPv6 Routes for GW IP from PGW to LEAF
                    BL_v6_prfx_data = self.get_PGW_LEAF_nexthop_prefixes(BL, 'v6', str(
                        pvnfTopoLeavesDict[pvnfLeaf]['pgw_comn_loop_v6']), str(pvnfTopoLeavesDict['vrf']))
                    BL_to_common_loopback_route_dict[pvnfLeaf]['BL_to_LEAF_GW_v6_route_prefix_count'] = BL_v6_prfx_data[
                        'num_of_hops']
                    BL_to_common_loopback_route_dict[pvnfLeaf]['BL_to_LEAF_GW_v6_route_prefix_lst'] = BL_v6_prfx_data[
                        'prfx_lst']
                    BL_to_common_loopback_route_dict[pvnfLeaf]['BL_to_LEAF_GW_v6_fwd_route_prefix_count'] = \
                    BL_v6_prfx_data['fwd_num_of_hops']
                    BL_to_common_loopback_route_dict[pvnfLeaf]['BL_to_LEAF_GW_v6_fwd_route_prefix_lst'] = \
                    BL_v6_prfx_data['fwd_prfx_lst']

        # --- Generate Random host IP
        host_ipv4 = ip.IPv4Interface(str(pvnfTopoLeavesDict['BGP_v4_prefixes']) + '/24')
        host_ipv6 = ip.IPv6Interface(str(pvnfTopoLeavesDict['BGP_v6_prefixes']) + '/128')
        host_ipv4_routes_per_route_range = int(int(pvnfTopoLeavesDict['no_of_hosts']) / 4) - 1
        host_ipv4 += (random.randint(2, host_ipv4_routes_per_route_range))
        random_octet = str(random.choice(string.hexdigits.lower()[6:]))
        random_host_ipv6 = re.sub('::\d+', '::' + str(random_octet), str(host_ipv6))

        # --- Get the IPv4 Routes for HOST IP from PGW to LEAF
        BL_host_v4_prfx_data = self.get_PGW_LEAF_nexthop_prefixes(BL, 'v4', str(host_ipv4),
                                                                  str(pvnfTopoLeavesDict['vrf']))
        BL_to_host_route_dict['BL_to_VNF_HOST_v4_route_prefix_count'] = BL_host_v4_prfx_data['num_of_hops']
        BL_to_host_route_dict['BL_to_VNF_HOST_v4_route_prefix_lst'] = BL_host_v4_prfx_data['prfx_lst']
        BL_to_host_route_dict['BL_to_VNF_HOST_v4_fwd_route_prefix_count'] = BL_host_v4_prfx_data['fwd_num_of_hops']
        BL_to_host_route_dict['BL_to_VNF_HOST_v4_fwd_route_prefix_lst'] = BL_host_v4_prfx_data['fwd_prfx_lst']

        # --- Get the IPv6 Routes for HOST IP from PGW to LEAF
        BL_host_v6_prfx_data = self.get_PGW_LEAF_nexthop_prefixes(BL, 'v6', str(random_host_ipv6),
                                                                  str(pvnfTopoLeavesDict['vrf']))
        BL_to_host_route_dict['BL_to_VNF_HOST_v6_route_prefix_count'] = BL_host_v6_prfx_data['num_of_hops']
        BL_to_host_route_dict['BL_to_VNF_HOST_v6_route_prefix_lst'] = BL_host_v6_prfx_data['prfx_lst']
        BL_to_host_route_dict['BL_to_VNF_HOST_v6_fwd_route_prefix_count'] = BL_host_v6_prfx_data['fwd_num_of_hops']
        BL_to_host_route_dict['BL_to_VNF_HOST_v6_fwd_route_prefix_lst'] = BL_host_v6_prfx_data['fwd_prfx_lst']

        # ----------------------------------------------------
        # Validation of routes and generate tables
        # ----------------------------------------------------
        for leaf in PGW_to_LEAF_loopback_route_dict:

            # --- Set few variables
            PGW_to_LEAF_v4_nh_count_status = 'FAIL'
            PGW_to_LEAF_v6_nh_count_status = 'FAIL'
            LEAF_to_PGW_v4_nh_count_status = 'FAIL'
            LEAF_to_PGW_v6_nh_count_status = 'FAIL'

            # --- Validate LEAF to PGW route, consider if the LEAF is EW Traffic Source
            if (int(pvnfTopoLeavesDict[leaf]['leaf_to_pgw_link_count']) == int(
                    LEAF_to_PGW_loopback_route_dict[leaf]['LEAF_to_PGW_GW_v4_route_prefix_count'])) and \
                    (int(pvnfTopoLeavesDict[leaf]['leaf_to_pgw_link_count']) == int(
                        LEAF_to_PGW_loopback_route_dict[leaf]['LEAF_to_PGW_GW_v4_fwd_route_prefix_count'])):
                LEAF_to_PGW_v4_nh_count_status = 'PASS'
            else:
                fail_flag.append(0)
            if (int(pvnfTopoLeavesDict[leaf]['leaf_to_pgw_link_count']) == int(
                    LEAF_to_PGW_loopback_route_dict[leaf]['LEAF_to_PGW_GW_v6_route_prefix_count'])) and \
                    (int(pvnfTopoLeavesDict[leaf]['leaf_to_pgw_link_count']) == int(
                        LEAF_to_PGW_loopback_route_dict[leaf]['LEAF_to_PGW_GW_v6_fwd_route_prefix_count'])):
                LEAF_to_PGW_v6_nh_count_status = 'PASS'
            else:
                fail_flag.append(0)
            LEAF_to_PGW_nextHopTable.add_row([
                leaf.alias,
                str(pvnfTopoLeavesDict[leaf]['pgw_comn_loop_v4']),
                pvnfTopoLeavesDict[leaf]['leaf_to_pgw_link_count'],
                LEAF_to_PGW_loopback_route_dict[leaf]['LEAF_to_PGW_GW_v4_route_prefix_count'],
                LEAF_to_PGW_loopback_route_dict[leaf]['LEAF_to_PGW_GW_v4_fwd_route_prefix_count'],
                LEAF_to_PGW_v4_nh_count_status,
                LEAF_to_PGW_loopback_route_dict[leaf]['LEAF_to_PGW_GW_v4_route_prefix_lst']
            ])
            LEAF_to_PGW_nextHopTable.add_row([
                leaf.alias,
                str(pvnfTopoLeavesDict[leaf]['pgw_comn_loop_v6']),
                pvnfTopoLeavesDict[leaf]['leaf_to_pgw_link_count'],
                LEAF_to_PGW_loopback_route_dict[leaf]['LEAF_to_PGW_GW_v6_route_prefix_count'],
                LEAF_to_PGW_loopback_route_dict[leaf]['LEAF_to_PGW_GW_v6_fwd_route_prefix_count'],
                LEAF_to_PGW_v6_nh_count_status,
                LEAF_to_PGW_loopback_route_dict[leaf]['LEAF_to_PGW_GW_v6_route_prefix_lst']]
            )

            # --- Validate PGW to LEAF routes
            if (int(PGW_to_LEAF_loopback_route_dict[leaf]['PGW_to_LEAF_GW_v4_route_prefix_count']) >= 1) and \
                    (int(PGW_to_LEAF_loopback_route_dict[leaf]['PGW_to_LEAF_GW_v4_fwd_route_prefix_count']) >= 1):
                PGW_to_LEAF_v4_nh_count_status = 'PASS'
            else:
                fail_flag.append(0)
            if (int(PGW_to_LEAF_loopback_route_dict[leaf]['PGW_to_LEAF_GW_v6_route_prefix_count']) >= 1) and \
                    (int(PGW_to_LEAF_loopback_route_dict[leaf]['PGW_to_LEAF_GW_v6_fwd_route_prefix_count']) >= 1):
                PGW_to_LEAF_v6_nh_count_status = 'PASS'
            else:
                fail_flag.append(0)
            # ['DST NODE', 'Destination', 'Expected NH Count', 'Observed NH Count', 'status', 'Next-hops']
            PGW_to_LEAF_nextHopTable.add_row([
                leaf.alias,
                str(pvnfTopoLeavesDict[leaf]['local_loop_v4']),
                '>= 1',
                PGW_to_LEAF_loopback_route_dict[leaf]['PGW_to_LEAF_GW_v4_route_prefix_count'],
                PGW_to_LEAF_loopback_route_dict[leaf]['PGW_to_LEAF_GW_v4_fwd_route_prefix_count'],
                PGW_to_LEAF_v4_nh_count_status,
                PGW_to_LEAF_loopback_route_dict[leaf]['PGW_to_LEAF_GW_v4_route_prefix_lst']
            ])
            PGW_to_LEAF_nextHopTable.add_row([
                leaf.alias,
                str(pvnfTopoLeavesDict[leaf]['local_loop_v6']),
                '>= 1',
                PGW_to_LEAF_loopback_route_dict[leaf]['PGW_to_LEAF_GW_v6_route_prefix_count'],
                PGW_to_LEAF_loopback_route_dict[leaf]['PGW_to_LEAF_GW_v6_fwd_route_prefix_count'],
                PGW_to_LEAF_v6_nh_count_status,
                PGW_to_LEAF_loopback_route_dict[leaf]['PGW_to_LEAF_GW_v6_route_prefix_lst']
            ])

            # --- Generate the tables BL_common_gateway_nxthop_count
            BL_v4_nh_count_status = 'FAIL'
            BL_v6_nh_count_status = 'FAIL'

            if (int(pvnfTopoLeavesDict[leaf]['leaf_to_pgw_link_count']) == int(
                    BL_to_common_loopback_route_dict[leaf]['BL_to_LEAF_GW_v4_route_prefix_count'])) and \
                    (int(pvnfTopoLeavesDict[leaf]['leaf_to_pgw_link_count']) == int(
                        BL_to_common_loopback_route_dict[leaf]['BL_to_LEAF_GW_v4_fwd_route_prefix_count'])):
                BL_v4_nh_count_status = 'PASS'
            else:
                fail_flag.append(0)
            if (int(pvnfTopoLeavesDict[leaf]['leaf_to_pgw_link_count']) == int(
                    BL_to_common_loopback_route_dict[leaf]['BL_to_LEAF_GW_v6_route_prefix_count'])) and \
                    (int(pvnfTopoLeavesDict[leaf]['leaf_to_pgw_link_count']) == int(
                        BL_to_common_loopback_route_dict[leaf]['BL_to_LEAF_GW_v6_fwd_route_prefix_count'])):
                BL_v6_nh_count_status = 'PASS'
            else:
                fail_flag.append(0)

            BL_nextHopTable.add_row([leaf.alias, pvnfTopoLeavesDict[leaf]['pgw_comn_loop_v4'],
                                     pvnfTopoLeavesDict[leaf]['leaf_to_pgw_link_count'],
                                     BL_to_common_loopback_route_dict[leaf]['BL_to_LEAF_GW_v4_route_prefix_count'],
                                     BL_to_common_loopback_route_dict[leaf]['BL_to_LEAF_GW_v4_fwd_route_prefix_count'],
                                     BL_v4_nh_count_status,
                                     BL_to_common_loopback_route_dict[leaf]['BL_to_LEAF_GW_v4_route_prefix_lst']])
            BL_nextHopTable.add_row([leaf.alias, pvnfTopoLeavesDict[leaf]['pgw_comn_loop_v6'],
                                     pvnfTopoLeavesDict[leaf]['leaf_to_pgw_link_count'],
                                     BL_to_common_loopback_route_dict[leaf]['BL_to_LEAF_GW_v6_route_prefix_count'],
                                     BL_to_common_loopback_route_dict[leaf]['BL_to_LEAF_GW_v6_fwd_route_prefix_count'],
                                     BL_v6_nh_count_status,
                                     BL_to_common_loopback_route_dict[leaf]['BL_to_LEAF_GW_v6_route_prefix_lst']])

        # --- Generate the tables BL_common_gateway_nxthop_count
        BL_v4_host_nh_count_status = 'FAIL'
        BL_v6_host_nh_count_status = 'FAIL'

        if (int(BL_to_host_route_dict['BL_to_VNF_HOST_v4_route_prefix_count']) == int(PVNF_LEAF_count)) and \
                (int(BL_common_gateway_nxthop_count) == int(
                    BL_to_host_route_dict['BL_to_VNF_HOST_v4_fwd_route_prefix_count'])):
            BL_v4_host_nh_count_status = 'PASS'
        else:
            fail_flag.append(0)
        if (int(BL_to_host_route_dict['BL_to_VNF_HOST_v6_route_prefix_count']) == int(PVNF_LEAF_count)) and \
                (int(BL_common_gateway_nxthop_count) == int(
                    BL_to_host_route_dict['BL_to_VNF_HOST_v6_fwd_route_prefix_count'])):
            BL_v6_host_nh_count_status = 'PASS'
        else:
            fail_flag.append(0)

        BL_host_nextHopTable.add_row([BL.alias, host_ipv4, BL_common_gateway_nxthop_count,
                                      BL_to_host_route_dict['BL_to_VNF_HOST_v4_route_prefix_count'],
                                      BL_to_host_route_dict['BL_to_VNF_HOST_v4_fwd_route_prefix_count'],
                                      BL_v4_host_nh_count_status,
                                      BL_to_host_route_dict['BL_to_VNF_HOST_v4_route_prefix_lst']])
        BL_host_nextHopTable.add_row([BL.alias, random_host_ipv6, BL_common_gateway_nxthop_count,
                                      BL_to_host_route_dict['BL_to_VNF_HOST_v6_route_prefix_count'],
                                      BL_to_host_route_dict['BL_to_VNF_HOST_v6_fwd_route_prefix_count'],
                                      BL_v6_host_nh_count_status,
                                      BL_to_host_route_dict['BL_to_VNF_HOST_v6_route_prefix_lst']])

        status_msgs += '''
*** Legend
SRC NODE        == Source Node
DST NODE        == Destination Node
Destination     == Destination IP
NH Count        == Next-hops count
FWD NH Count    == Counts of Next-hops installed in hardware 'sh forwarding ipv4/v6 route'
Status          == Gives the tally of counts matching the expectations

====> Checking the Route DB from Individual LEAF's to PGW Common Gateway

''' + str(banner("IPv4/IPv6 Routes from LEAF loopback to Corresponding PGW Common Gateway (" + str(
            pvnfTopoLeavesDict[temp_leaf_for_iterations]['pgw_comn_loop_v4']) + ")", 145)) + '''
''' + str(LEAF_to_PGW_nextHopTable.draw()) + '''

====> Checking the Route DB from PGW Common Gateway to each Individual LEAF

''' + str(banner("IPv4/IPv6 Routes from PGW Common Gateway (" + str(
            pvnfTopoLeavesDict[temp_leaf_for_iterations]['local_loop_v4']) + ") to Corresponding LEAF loopback", 145)) + '''
''' + str(PGW_to_LEAF_nextHopTable.draw()) + '''

====> Checking the Route DB from BL to Corresponding PGW Common Gateway

''' + str(banner("Routes from BL to Corresponding PGW Common Gateway", 145)) + '''
''' + str(BL_nextHopTable.draw()) + '''

====> Checking the Route DB from BL to a Random Host

''' + str(banner("Routes from BL to Random HOST", 145)) + '''
''' + str(BL_host_nextHopTable.draw()) + '''
        '''

        if 0 in fail_flag:
            status = 0
        else:
            status = 1

        return {'result': status, 'status_msgs': status_msgs}

    # ====================================================================================================#
    def verifyPVNF_individual_physical_vm_topology(self, BL, PGW, pvnfTopoLeavesDict, leafList=[]):

        # ----------------------------------------------------
        # set global flags to carry fail messages and status
        # ----------------------------------------------------
        status_msgs = ""
        fail_flag = []

        # ----------------------------------------------------
        # Declare the Tables
        # ----------------------------------------------------
        BL_host_nextHopTable = texttable.Texttable()
        BL_host_nextHopTable.header(
            ['SRC NODE', 'Destination', 'Expected NH Count', 'Observed NH Count', 'Observed FWD NH Count', 'Status',
             'Next-hops'])
        BL_host_nextHopTable.set_cols_width([15, 25, 10, 10, 10, 10, 75])

        # ----------------------------------------------------
        # Retrieve the IPv4 and IPv6 routes to GW IP per LEAF
        # ----------------------------------------------------
        BL_common_gateway_nxthop_count = 0
        PVNF_LEAF_count = 0
        BL_to_host_route_dict = {}

        if not leafList:
            testLeafList = pvnfTopoLeavesDict.keys()
        else:
            testLeafList = leafList

        # --- Get the route information from each LEAF
        for pvnfLeaf in testLeafList:
            if type(pvnfTopoLeavesDict[pvnfLeaf]) == dict:
                if str(pvnfTopoLeavesDict['type']) == "topo_3":
                    # --- Get and append the no.of next-hops from each LEAF to gateway
                    BL_common_gateway_nxthop_count += int(pvnfTopoLeavesDict[pvnfLeaf]['leaf_to_pgw_link_count'])
                    PVNF_LEAF_count += 1

        # --- Generate Random host IP
        host_ipv4 = ip.IPv4Interface(str(pvnfTopoLeavesDict['BGP_v4_prefixes']) + '/24')
        host_ipv6 = ip.IPv6Interface(str(pvnfTopoLeavesDict['BGP_v6_prefixes']) + '/128')
        host_ipv4_routes_per_route_range = int(int(pvnfTopoLeavesDict['no_of_hosts']) / 4) - 1
        host_ipv4 += (random.randint(2, host_ipv4_routes_per_route_range))
        random_octet = str(random.choice(string.hexdigits.lower()[6:]))
        random_host_ipv6 = re.sub('::\d+', '::' + str(random_octet), str(host_ipv6))

        # --- Get the IPv4 Routes for HOST IP from PGW to LEAF
        BL_host_v4_prfx_data = self.get_PGW_LEAF_nexthop_prefixes(BL, 'v4', str(host_ipv4),str(pvnfTopoLeavesDict['vrf']))
        BL_to_host_route_dict['BL_to_VNF_HOST_v4_route_prefix_count'] = BL_host_v4_prfx_data['num_of_hops']
        BL_to_host_route_dict['BL_to_VNF_HOST_v4_route_prefix_lst'] = BL_host_v4_prfx_data['prfx_lst']
        BL_to_host_route_dict['BL_to_VNF_HOST_v4_fwd_route_prefix_count'] = BL_host_v4_prfx_data['fwd_num_of_hops']
        BL_to_host_route_dict['BL_to_VNF_HOST_v4_fwd_route_prefix_lst'] = BL_host_v4_prfx_data['fwd_prfx_lst']

        # --- Get the IPv6 Routes for HOST IP from PGW to LEAF
        BL_host_v6_prfx_data = self.get_PGW_LEAF_nexthop_prefixes(BL, 'v6', str(random_host_ipv6),str(pvnfTopoLeavesDict['vrf']))
        BL_to_host_route_dict['BL_to_VNF_HOST_v6_route_prefix_count'] = BL_host_v6_prfx_data['num_of_hops']
        BL_to_host_route_dict['BL_to_VNF_HOST_v6_route_prefix_lst'] = BL_host_v6_prfx_data['prfx_lst']
        BL_to_host_route_dict['BL_to_VNF_HOST_v6_fwd_route_prefix_count'] = BL_host_v6_prfx_data['fwd_num_of_hops']
        BL_to_host_route_dict['BL_to_VNF_HOST_v6_fwd_route_prefix_lst'] = BL_host_v6_prfx_data['fwd_prfx_lst']

        # --- Generate the tables BL_common_gateway_nxthop_count
        BL_v4_host_nh_count_status = 'FAIL'
        BL_v6_host_nh_count_status = 'FAIL'

        if (int(BL_to_host_route_dict['BL_to_VNF_HOST_v4_route_prefix_count']) == int(BL_common_gateway_nxthop_count)) and (int(BL_common_gateway_nxthop_count) == int(BL_to_host_route_dict['BL_to_VNF_HOST_v4_fwd_route_prefix_count'])):
            BL_v4_host_nh_count_status = 'PASS'
        else:
            if (int(BL_to_host_route_dict['BL_to_VNF_HOST_v4_route_prefix_count']) >= int(PVNF_LEAF_count)) and (int(BL_to_host_route_dict['BL_to_VNF_HOST_v4_fwd_route_prefix_count']) >= int(PVNF_LEAF_count)):
                BL_v4_host_nh_count_status = 'PASS w/ Exception'
            else:
                fail_flag.append(0)
        
        if (int(BL_to_host_route_dict['BL_to_VNF_HOST_v6_route_prefix_count']) == int(BL_common_gateway_nxthop_count)) and (int(BL_common_gateway_nxthop_count) == int(BL_to_host_route_dict['BL_to_VNF_HOST_v6_fwd_route_prefix_count'])):
            BL_v6_host_nh_count_status = 'PASS'
        else:
            if (int(BL_to_host_route_dict['BL_to_VNF_HOST_v6_route_prefix_count']) >= int(PVNF_LEAF_count)) and (int(BL_to_host_route_dict['BL_to_VNF_HOST_v6_fwd_route_prefix_count']) >= int(PVNF_LEAF_count)):
                BL_v6_host_nh_count_status = 'PASS w/ Exception'
            else:
                fail_flag.append(0) 

        BL_host_nextHopTable.add_row([BL.alias, host_ipv4, BL_common_gateway_nxthop_count,
                                      BL_to_host_route_dict['BL_to_VNF_HOST_v4_route_prefix_count'],
                                      BL_to_host_route_dict['BL_to_VNF_HOST_v4_fwd_route_prefix_count'],
                                      BL_v4_host_nh_count_status,
                                      BL_to_host_route_dict['BL_to_VNF_HOST_v4_route_prefix_lst']])
        BL_host_nextHopTable.add_row([BL.alias, random_host_ipv6, BL_common_gateway_nxthop_count,
                                      BL_to_host_route_dict['BL_to_VNF_HOST_v6_route_prefix_count'],
                                      BL_to_host_route_dict['BL_to_VNF_HOST_v6_fwd_route_prefix_count'],
                                      BL_v6_host_nh_count_status,
                                      BL_to_host_route_dict['BL_to_VNF_HOST_v6_route_prefix_lst']])

        status_msgs += '''
*** Legend
SRC NODE        == Source Node
DST NODE        == Destination Node
Destination     == Destination IP
NH Count        == Next-hops count
FWD NH Count    == Counts of Next-hops installed in hardware 'sh forwarding ipv4/v6 route'
Status          == Gives the tally of counts matching the expectations

====> Checking the Route DB from BL to a Random Host

''' + str(banner("Routes from BL to Random HOST", 145)) + '''
''' + str(BL_host_nextHopTable.draw()) + '''
        '''

        if 0 in fail_flag:
            status = 0
        else:
            status = 1

        return {'result': status, 'status_msgs': status_msgs}

    # ====================================================================================================#
    def verifyPVNF_common_loopback_topology_btw_LEAF_PGW(self, PGW, pvnfTopoLeavesDict, leafList=[]):

        # ----------------------------------------------------
        # set global flags to carry fail messages and status
        # ----------------------------------------------------
        status_msgs = ""
        fail_flag = []

        # ----------------------------------------------------
        # Declare the Tables
        # ----------------------------------------------------
        PGW_to_LEAF_nextHopTable = texttable.Texttable()
        PGW_to_LEAF_nextHopTable.header(
            ['DST NODE', 'Destination', 'Expected NH Count', 'Observed NH Count', 'Observed FWD NH Count', 'Status',
             'Next-hops'])
        PGW_to_LEAF_nextHopTable.set_cols_width([15, 25, 10, 10, 10, 10, 75])

        LEAF_to_PGW_nextHopTable = texttable.Texttable()
        LEAF_to_PGW_nextHopTable.header(
            ['SRC NODE', 'Destination', 'Expected NH Count', 'Observed NH Count', 'Observed FWD NH Count', 'Status',
             'Next-hops'])
        LEAF_to_PGW_nextHopTable.set_cols_width([15, 25, 10, 10, 10, 10, 75])

        # ----------------------------------------------------
        # Retrieve the IPv4 and IPv6 routes to GW IP per LEAF
        # ----------------------------------------------------
        PGW_to_LEAF_loopback_route_dict = {}
        LEAF_to_PGW_loopback_route_dict = {}
        temp_leaf_for_iterations = ''
        BL_common_gateway_nxthop_count = 0

        if not leafList:
            testLeafList = pvnfTopoLeavesDict.keys()
        else:
            testLeafList = leafList

        # --- Get the route information from each LEAF
        for pvnfLeaf in testLeafList:
            if type(pvnfTopoLeavesDict[pvnfLeaf]) == dict:
                if (str(pvnfTopoLeavesDict['type']) == "topo_1") or (str(pvnfTopoLeavesDict['type']) == "topo_2"):
                    # --- Set few Iteration variables
                    temp_leaf_for_iterations = pvnfLeaf
                    PGW_to_LEAF_loopback_route_dict[pvnfLeaf] = {}
                    LEAF_to_PGW_loopback_route_dict[pvnfLeaf] = {}
                    PGW_to_LEAF_loopback_route_dict[pvnfLeaf]['PGW_to_LEAF_GW_v4_route_prefix_lst'] = []
                    LEAF_to_PGW_loopback_route_dict[pvnfLeaf]['LEAF_to_PGW_GW_v4_route_prefix_lst'] = []
                    PGW_to_LEAF_loopback_route_dict[pvnfLeaf]['PGW_to_LEAF_GW_v6_route_prefix_lst'] = []
                    LEAF_to_PGW_loopback_route_dict[pvnfLeaf]['LEAF_to_PGW_GW_v6_route_prefix_lst'] = []

                    # --- Get and append the no.of next-hops from each LEAF to gateway
                    BL_common_gateway_nxthop_count += int(pvnfTopoLeavesDict[pvnfLeaf]['leaf_to_pgw_link_count'])

                    # --- Get the IPv4 Routes for GW IP from PGW to LEAF
                    PGW_v4_prfx_data = self.get_PGW_LEAF_nexthop_prefixes(PGW, 'v4', str(pvnfTopoLeavesDict[pvnfLeaf]['local_loop_v4']), str(pvnfTopoLeavesDict['vrf']))
                    PGW_to_LEAF_loopback_route_dict[pvnfLeaf]['PGW_to_LEAF_GW_v4_route_prefix_count'] = PGW_v4_prfx_data['num_of_hops']
                    PGW_to_LEAF_loopback_route_dict[pvnfLeaf]['PGW_to_LEAF_GW_v4_route_prefix_lst'] = PGW_v4_prfx_data['prfx_lst']
                    PGW_to_LEAF_loopback_route_dict[pvnfLeaf]['PGW_to_LEAF_GW_v4_fwd_route_prefix_count'] = PGW_v4_prfx_data['fwd_num_of_hops']
                    PGW_to_LEAF_loopback_route_dict[pvnfLeaf]['PGW_to_LEAF_GW_v4_fwd_route_prefix_lst'] = PGW_v4_prfx_data['fwd_prfx_lst']

                    # --- Get the IPv4 Routes for GW IP from LEAF to PGW
                    LEAF_v4_prfx_data = self.get_PGW_LEAF_nexthop_prefixes(pvnfLeaf, 'v4', str(pvnfTopoLeavesDict[pvnfLeaf]['pgw_comn_loop_v4']), str(pvnfTopoLeavesDict['vrf']))
                    LEAF_to_PGW_loopback_route_dict[pvnfLeaf]['LEAF_to_PGW_GW_v4_route_prefix_count'] = LEAF_v4_prfx_data['num_of_hops']
                    LEAF_to_PGW_loopback_route_dict[pvnfLeaf]['LEAF_to_PGW_GW_v4_route_prefix_lst'] = LEAF_v4_prfx_data['prfx_lst']
                    LEAF_to_PGW_loopback_route_dict[pvnfLeaf]['LEAF_to_PGW_GW_v4_fwd_route_prefix_count'] = LEAF_v4_prfx_data['fwd_num_of_hops']
                    LEAF_to_PGW_loopback_route_dict[pvnfLeaf]['LEAF_to_PGW_GW_v4_fwd_route_prefix_lst'] = LEAF_v4_prfx_data['fwd_prfx_lst']

                    # --- Get the IPv6 Routes for GW IP from PGW to LEAF
                    PGW_v6_prfx_data = self.get_PGW_LEAF_nexthop_prefixes(PGW, 'v6', str(pvnfTopoLeavesDict[pvnfLeaf]['local_loop_v6']), str(pvnfTopoLeavesDict['vrf']))
                    PGW_to_LEAF_loopback_route_dict[pvnfLeaf]['PGW_to_LEAF_GW_v6_route_prefix_count'] = PGW_v6_prfx_data['num_of_hops']
                    PGW_to_LEAF_loopback_route_dict[pvnfLeaf]['PGW_to_LEAF_GW_v6_route_prefix_lst'] = PGW_v6_prfx_data['prfx_lst']
                    PGW_to_LEAF_loopback_route_dict[pvnfLeaf]['PGW_to_LEAF_GW_v6_fwd_route_prefix_count'] = PGW_v6_prfx_data['fwd_num_of_hops']
                    PGW_to_LEAF_loopback_route_dict[pvnfLeaf]['PGW_to_LEAF_GW_v6_fwd_route_prefix_lst'] = PGW_v6_prfx_data['fwd_prfx_lst']

                    # --- Get the IPv6 Routes for GW IP from LEAF to PGW
                    LEAF_v6_prfx_data = self.get_PGW_LEAF_nexthop_prefixes(pvnfLeaf, 'v6', str(pvnfTopoLeavesDict[pvnfLeaf]['pgw_comn_loop_v6']), str(pvnfTopoLeavesDict['vrf']))
                    LEAF_to_PGW_loopback_route_dict[pvnfLeaf]['LEAF_to_PGW_GW_v6_route_prefix_count'] = LEAF_v6_prfx_data['num_of_hops']
                    LEAF_to_PGW_loopback_route_dict[pvnfLeaf]['LEAF_to_PGW_GW_v6_route_prefix_lst'] = LEAF_v6_prfx_data['prfx_lst']
                    LEAF_to_PGW_loopback_route_dict[pvnfLeaf]['LEAF_to_PGW_GW_v6_fwd_route_prefix_count'] = LEAF_v6_prfx_data['fwd_num_of_hops']
                    LEAF_to_PGW_loopback_route_dict[pvnfLeaf]['LEAF_to_PGW_GW_v6_fwd_route_prefix_lst'] = LEAF_v6_prfx_data['fwd_prfx_lst']

        # ----------------------------------------------------
        # Validation of routes and generate tables
        # ----------------------------------------------------
        for leaf in PGW_to_LEAF_loopback_route_dict:

            # --- Set few variables
            PGW_to_LEAF_v4_nh_count_status = 'FAIL'
            PGW_to_LEAF_v6_nh_count_status = 'FAIL'
            LEAF_to_PGW_v4_nh_count_status = 'FAIL'
            LEAF_to_PGW_v6_nh_count_status = 'FAIL'

            # --- Validate LEAF to PGW route, consider if the LEAF is EW Traffic Source
            if 'EW_LEAF_SRC' in pvnfTopoLeavesDict[leaf].keys():
                if int(pvnfTopoLeavesDict[leaf]['EW_LEAF_SRC']) == 1:
                    if (int(LEAF_to_PGW_loopback_route_dict[leaf]['LEAF_to_PGW_GW_v4_route_prefix_count']) == int(BL_common_gateway_nxthop_count)) and \
                            (int(LEAF_to_PGW_loopback_route_dict[leaf]['LEAF_to_PGW_GW_v4_fwd_route_prefix_count']) == int(BL_common_gateway_nxthop_count)):
                        LEAF_to_PGW_v4_nh_count_status = 'PASS'
                    else:
                        fail_flag.append(0)
                    if (int(LEAF_to_PGW_loopback_route_dict[leaf]['LEAF_to_PGW_GW_v6_route_prefix_count']) == int(BL_common_gateway_nxthop_count)) and \
                            (int(LEAF_to_PGW_loopback_route_dict[leaf]['LEAF_to_PGW_GW_v6_fwd_route_prefix_count']) == int(BL_common_gateway_nxthop_count)):
                        LEAF_to_PGW_v6_nh_count_status = 'PASS'
                    else:
                        fail_flag.append(0)
                    LEAF_to_PGW_nextHopTable.add_row([
                        leaf.alias,
                        str(pvnfTopoLeavesDict[leaf]['pgw_comn_loop_v4']),
                        str(BL_common_gateway_nxthop_count)+','+str(BL_common_gateway_nxthop_count),
                        LEAF_to_PGW_loopback_route_dict[leaf]['LEAF_to_PGW_GW_v4_route_prefix_count'],
                        LEAF_to_PGW_loopback_route_dict[leaf]['LEAF_to_PGW_GW_v4_fwd_route_prefix_count'],
                        LEAF_to_PGW_v4_nh_count_status,
                        LEAF_to_PGW_loopback_route_dict[leaf]['LEAF_to_PGW_GW_v4_route_prefix_lst']
                    ])
                    LEAF_to_PGW_nextHopTable.add_row([
                        leaf.alias,
                        str(pvnfTopoLeavesDict[leaf]['pgw_comn_loop_v6']),
                        str(BL_common_gateway_nxthop_count)+','+str(BL_common_gateway_nxthop_count),
                        LEAF_to_PGW_loopback_route_dict[leaf]['LEAF_to_PGW_GW_v6_route_prefix_count'],
                        LEAF_to_PGW_loopback_route_dict[leaf]['LEAF_to_PGW_GW_v6_fwd_route_prefix_count'],
                        LEAF_to_PGW_v6_nh_count_status,
                        LEAF_to_PGW_loopback_route_dict[leaf]['LEAF_to_PGW_GW_v6_route_prefix_lst']
                    ])
            else:
                if (int(pvnfTopoLeavesDict[leaf]['leaf_to_pgw_link_count']) == int(LEAF_to_PGW_loopback_route_dict[leaf]['LEAF_to_PGW_GW_v4_route_prefix_count'])) and \
                        (int(pvnfTopoLeavesDict[leaf]['leaf_to_pgw_link_count']) == int(LEAF_to_PGW_loopback_route_dict[leaf]['LEAF_to_PGW_GW_v4_fwd_route_prefix_count'])):
                    LEAF_to_PGW_v4_nh_count_status = 'PASS'
                else:
                    fail_flag.append(0)
                if (int(pvnfTopoLeavesDict[leaf]['leaf_to_pgw_link_count']) == int(LEAF_to_PGW_loopback_route_dict[leaf]['LEAF_to_PGW_GW_v6_route_prefix_count'])) and \
                        (int(pvnfTopoLeavesDict[leaf]['leaf_to_pgw_link_count']) == int(LEAF_to_PGW_loopback_route_dict[leaf]['LEAF_to_PGW_GW_v6_fwd_route_prefix_count'])):
                    LEAF_to_PGW_v6_nh_count_status = 'PASS'
                else:
                    fail_flag.append(0)
                LEAF_to_PGW_nextHopTable.add_row([
                    leaf.alias,
                    str(pvnfTopoLeavesDict[leaf]['pgw_comn_loop_v4']),
                    str(pvnfTopoLeavesDict[leaf]['leaf_to_pgw_link_count'])+','+str(pvnfTopoLeavesDict[leaf]['leaf_to_pgw_link_count']),
                    LEAF_to_PGW_loopback_route_dict[leaf]['LEAF_to_PGW_GW_v4_route_prefix_count'],
                    LEAF_to_PGW_loopback_route_dict[leaf]['LEAF_to_PGW_GW_v4_fwd_route_prefix_count'],
                    LEAF_to_PGW_v4_nh_count_status,
                    LEAF_to_PGW_loopback_route_dict[leaf]['LEAF_to_PGW_GW_v4_route_prefix_lst']
                ])
                LEAF_to_PGW_nextHopTable.add_row([
                    leaf.alias,
                    str(pvnfTopoLeavesDict[leaf]['pgw_comn_loop_v6']),
                    str(pvnfTopoLeavesDict[leaf]['leaf_to_pgw_link_count'])+','+str(pvnfTopoLeavesDict[leaf]['leaf_to_pgw_link_count']),
                    LEAF_to_PGW_loopback_route_dict[leaf]['LEAF_to_PGW_GW_v6_route_prefix_count'],
                    LEAF_to_PGW_loopback_route_dict[leaf]['LEAF_to_PGW_GW_v6_fwd_route_prefix_count'],
                    LEAF_to_PGW_v6_nh_count_status,
                    LEAF_to_PGW_loopback_route_dict[leaf]['LEAF_to_PGW_GW_v6_route_prefix_lst']]
                )

            # --- Validate PGW to LEAF routes
            if (int(PGW_to_LEAF_loopback_route_dict[leaf]['PGW_to_LEAF_GW_v4_route_prefix_count']) >= 1) and (
                    int(PGW_to_LEAF_loopback_route_dict[leaf]['PGW_to_LEAF_GW_v4_fwd_route_prefix_count']) >= 1):
                PGW_to_LEAF_v4_nh_count_status = 'PASS'
            else:
                fail_flag.append(0)
            if (int(PGW_to_LEAF_loopback_route_dict[leaf]['PGW_to_LEAF_GW_v6_route_prefix_count']) >= 1) and (
                    int(PGW_to_LEAF_loopback_route_dict[leaf]['PGW_to_LEAF_GW_v6_fwd_route_prefix_count']) >= 1):
                PGW_to_LEAF_v6_nh_count_status = 'PASS'
            else:
                fail_flag.append(0)
            # ['DST NODE', 'Destination', 'Expected NH Count', 'Observed NH Count', 'status', 'Next-hops']
            PGW_to_LEAF_nextHopTable.add_row([
                leaf.alias,
                str(pvnfTopoLeavesDict[leaf]['local_loop_v4']),
                '>= 1',
                PGW_to_LEAF_loopback_route_dict[leaf]['PGW_to_LEAF_GW_v4_route_prefix_count'],
                PGW_to_LEAF_loopback_route_dict[leaf]['PGW_to_LEAF_GW_v4_fwd_route_prefix_count'],
                PGW_to_LEAF_v4_nh_count_status,
                PGW_to_LEAF_loopback_route_dict[leaf]['PGW_to_LEAF_GW_v4_route_prefix_lst']
            ])
            PGW_to_LEAF_nextHopTable.add_row([
                leaf.alias,
                str(pvnfTopoLeavesDict[leaf]['local_loop_v6']),
                '>= 1',
                PGW_to_LEAF_loopback_route_dict[leaf]['PGW_to_LEAF_GW_v6_route_prefix_count'],
                PGW_to_LEAF_loopback_route_dict[leaf]['PGW_to_LEAF_GW_v6_fwd_route_prefix_count'],
                PGW_to_LEAF_v6_nh_count_status,
                PGW_to_LEAF_loopback_route_dict[leaf]['PGW_to_LEAF_GW_v6_route_prefix_lst']
            ])

        status_msgs += '''
*** Legend
SRC NODE        == Source Node
DST NODE        == Destination Node
Destination     == Destination IP
NH Count        == Next-hops count
FWD NH Count    == Counts of Next-hops installed in hardware 'sh forwarding ipv4/v6 route'
Status          == Gives the tally of counts matching the expectations

====> Checking the Route DB from Individual LEAF's to PGW Common Gateway

''' + str(banner("IPv4/IPv6 Routes from LEAF loopback to Corresponding PGW Common Gateway (" + str(
            pvnfTopoLeavesDict[temp_leaf_for_iterations]['pgw_comn_loop_v4']) + ")", 145)) + '''
''' + str(LEAF_to_PGW_nextHopTable.draw()) + '''

====> Checking the Route DB from PGW Common Gateway to each Individual LEAF

''' + str(banner("IPv4/IPv6 Routes from PGW Common Gateway (" + str(
            pvnfTopoLeavesDict[temp_leaf_for_iterations]['local_loop_v4']) + ") to Corresponding LEAF loopback", 145)) + '''
''' + str(PGW_to_LEAF_nextHopTable.draw()) + '''
        '''

        if 0 in fail_flag:
            status = 0
        else:
            status = 1

        return {'result': status, 'status_msgs': status_msgs}

    # ====================================================================================================#
    def verifyPVNF_individual_loopback_topology_btw_LEAF_PGW(self, PGW, pvnfTopoLeavesDict, leafList=[]):

        # ----------------------------------------------------
        # set global flags to carry fail messages and status
        # ----------------------------------------------------
        status_msgs = ""
        fail_flag = []

        # ----------------------------------------------------
        # Declare the Tables
        # ----------------------------------------------------
        PGW_to_LEAF_nextHopTable = texttable.Texttable()
        PGW_to_LEAF_nextHopTable.header(
            ['DST NODE', 'Destination', 'Expected NH Count', 'Observed NH Count', 'Observed FWD NH Count', 'Status',
             'Next-hops'])
        PGW_to_LEAF_nextHopTable.set_cols_width([15, 25, 10, 10, 10, 10, 75])

        LEAF_to_PGW_nextHopTable = texttable.Texttable()
        LEAF_to_PGW_nextHopTable.header(
            ['SRC NODE', 'Destination', 'Expected NH Count', 'Observed NH Count', 'Observed FWD NH Count', 'Status',
             'Next-hops'])
        LEAF_to_PGW_nextHopTable.set_cols_width([15, 25, 10, 10, 10, 10, 75])

        # ----------------------------------------------------
        # Retrieve the IPv4 and IPv6 routes to GW IP per LEAF
        # ----------------------------------------------------
        PGW_to_LEAF_loopback_route_dict = {}
        LEAF_to_PGW_loopback_route_dict = {}
        temp_leaf_for_iterations = ''
        BL_common_gateway_nxthop_count = 0
        PVNF_LEAF_count = 0
        BL_to_common_loopback_route_dict = {}
        BL_to_host_route_dict = {}

        if not leafList:
            testLeafList = pvnfTopoLeavesDict.keys()
        else:
            testLeafList = leafList

        # --- Get the route information from each LEAF
        for pvnfLeaf in testLeafList:
            if type(pvnfTopoLeavesDict[pvnfLeaf]) == dict:
                if (str(pvnfTopoLeavesDict['type']) == "topo_1") or (str(pvnfTopoLeavesDict['type']) == "topo_2"):
                    # --- Set few Iteration variables
                    temp_leaf_for_iterations = pvnfLeaf
                    PGW_to_LEAF_loopback_route_dict[pvnfLeaf] = {}
                    LEAF_to_PGW_loopback_route_dict[pvnfLeaf] = {}
                    BL_to_common_loopback_route_dict[pvnfLeaf] = {}
                    PGW_to_LEAF_loopback_route_dict[pvnfLeaf]['PGW_to_LEAF_GW_v4_route_prefix_lst'] = []
                    LEAF_to_PGW_loopback_route_dict[pvnfLeaf]['LEAF_to_PGW_GW_v4_route_prefix_lst'] = []
                    PGW_to_LEAF_loopback_route_dict[pvnfLeaf]['PGW_to_LEAF_GW_v6_route_prefix_lst'] = []
                    LEAF_to_PGW_loopback_route_dict[pvnfLeaf]['LEAF_to_PGW_GW_v6_route_prefix_lst'] = []
                    BL_to_common_loopback_route_dict[pvnfLeaf]['BL_to_LEAF_GW_v4_route_prefix_lst'] = []
                    BL_to_common_loopback_route_dict[pvnfLeaf]['BL_to_LEAF_GW_v6_route_prefix_lst'] = []

                    # --- Get and append the no.of next-hops from each LEAF to gateway
                    BL_common_gateway_nxthop_count += int(pvnfTopoLeavesDict[pvnfLeaf]['leaf_to_pgw_link_count'])
                    PVNF_LEAF_count += 1

                    # --- Get the IPv4 Routes for GW IP from PGW to LEAF
                    PGW_v4_prfx_data = self.get_PGW_LEAF_nexthop_prefixes(PGW, 'v4', str(pvnfTopoLeavesDict[pvnfLeaf]['local_loop_v4']), str(pvnfTopoLeavesDict['vrf']))
                    PGW_to_LEAF_loopback_route_dict[pvnfLeaf]['PGW_to_LEAF_GW_v4_route_prefix_count'] = PGW_v4_prfx_data['num_of_hops']
                    PGW_to_LEAF_loopback_route_dict[pvnfLeaf]['PGW_to_LEAF_GW_v4_route_prefix_lst'] = PGW_v4_prfx_data['prfx_lst']
                    PGW_to_LEAF_loopback_route_dict[pvnfLeaf]['PGW_to_LEAF_GW_v4_fwd_route_prefix_count'] = PGW_v4_prfx_data['fwd_num_of_hops']
                    PGW_to_LEAF_loopback_route_dict[pvnfLeaf]['PGW_to_LEAF_GW_v4_fwd_route_prefix_lst'] = PGW_v4_prfx_data['fwd_prfx_lst']

                    # --- Get the IPv4 Routes for GW IP from LEAF to PGW
                    LEAF_v4_prfx_data = self.get_PGW_LEAF_nexthop_prefixes(pvnfLeaf, 'v4', str(pvnfTopoLeavesDict[pvnfLeaf]['pgw_comn_loop_v4']), str(pvnfTopoLeavesDict['vrf']))
                    LEAF_to_PGW_loopback_route_dict[pvnfLeaf]['LEAF_to_PGW_GW_v4_route_prefix_count'] = LEAF_v4_prfx_data['num_of_hops']
                    LEAF_to_PGW_loopback_route_dict[pvnfLeaf]['LEAF_to_PGW_GW_v4_route_prefix_lst'] = LEAF_v4_prfx_data['prfx_lst']
                    LEAF_to_PGW_loopback_route_dict[pvnfLeaf]['LEAF_to_PGW_GW_v4_fwd_route_prefix_count'] = LEAF_v4_prfx_data['fwd_num_of_hops']
                    LEAF_to_PGW_loopback_route_dict[pvnfLeaf]['LEAF_to_PGW_GW_v4_fwd_route_prefix_lst'] = LEAF_v4_prfx_data['fwd_prfx_lst']

                    # --- Get the IPv6 Routes for GW IP from PGW to LEAF
                    PGW_v6_prfx_data = self.get_PGW_LEAF_nexthop_prefixes(PGW, 'v6', str(pvnfTopoLeavesDict[pvnfLeaf]['local_loop_v6']), str(pvnfTopoLeavesDict['vrf']))
                    PGW_to_LEAF_loopback_route_dict[pvnfLeaf]['PGW_to_LEAF_GW_v6_route_prefix_count'] = PGW_v6_prfx_data['num_of_hops']
                    PGW_to_LEAF_loopback_route_dict[pvnfLeaf]['PGW_to_LEAF_GW_v6_route_prefix_lst'] = PGW_v6_prfx_data['prfx_lst']
                    PGW_to_LEAF_loopback_route_dict[pvnfLeaf]['PGW_to_LEAF_GW_v6_fwd_route_prefix_count'] = PGW_v6_prfx_data['fwd_num_of_hops']
                    PGW_to_LEAF_loopback_route_dict[pvnfLeaf]['PGW_to_LEAF_GW_v6_fwd_route_prefix_lst'] = PGW_v6_prfx_data['fwd_prfx_lst']

                    # --- Get the IPv6 Routes for GW IP from LEAF to PGW
                    LEAF_v6_prfx_data = self.get_PGW_LEAF_nexthop_prefixes(pvnfLeaf, 'v6', str(pvnfTopoLeavesDict[pvnfLeaf]['pgw_comn_loop_v6']), str(pvnfTopoLeavesDict['vrf']))
                    LEAF_to_PGW_loopback_route_dict[pvnfLeaf]['LEAF_to_PGW_GW_v6_route_prefix_count'] = LEAF_v6_prfx_data['num_of_hops']
                    LEAF_to_PGW_loopback_route_dict[pvnfLeaf]['LEAF_to_PGW_GW_v6_route_prefix_lst'] = LEAF_v6_prfx_data['prfx_lst']
                    LEAF_to_PGW_loopback_route_dict[pvnfLeaf]['LEAF_to_PGW_GW_v6_fwd_route_prefix_count'] = LEAF_v6_prfx_data['fwd_num_of_hops']
                    LEAF_to_PGW_loopback_route_dict[pvnfLeaf]['LEAF_to_PGW_GW_v6_fwd_route_prefix_lst'] = LEAF_v6_prfx_data['fwd_prfx_lst']

        # ----------------------------------------------------
        # Validation of routes and generate tables
        # ----------------------------------------------------
        for leaf in PGW_to_LEAF_loopback_route_dict:

            # --- Set few variables
            PGW_to_LEAF_v4_nh_count_status = 'FAIL'
            PGW_to_LEAF_v6_nh_count_status = 'FAIL'
            LEAF_to_PGW_v4_nh_count_status = 'FAIL'
            LEAF_to_PGW_v6_nh_count_status = 'FAIL'

            # --- Validate LEAF to PGW route, consider if the LEAF is EW Traffic Source
            if (int(pvnfTopoLeavesDict[leaf]['leaf_to_pgw_link_count']) == int(LEAF_to_PGW_loopback_route_dict[leaf]['LEAF_to_PGW_GW_v4_route_prefix_count'])) and \
                    (int(pvnfTopoLeavesDict[leaf]['leaf_to_pgw_link_count']) == int(LEAF_to_PGW_loopback_route_dict[leaf]['LEAF_to_PGW_GW_v4_fwd_route_prefix_count'])):
                LEAF_to_PGW_v4_nh_count_status = 'PASS'
            else:
                fail_flag.append(0)
            if (int(pvnfTopoLeavesDict[leaf]['leaf_to_pgw_link_count']) == int(LEAF_to_PGW_loopback_route_dict[leaf]['LEAF_to_PGW_GW_v6_route_prefix_count'])) and \
                    (int(pvnfTopoLeavesDict[leaf]['leaf_to_pgw_link_count']) == int(LEAF_to_PGW_loopback_route_dict[leaf]['LEAF_to_PGW_GW_v6_fwd_route_prefix_count'])):
                LEAF_to_PGW_v6_nh_count_status = 'PASS'
            else:
                fail_flag.append(0)
            LEAF_to_PGW_nextHopTable.add_row([
                leaf.alias,
                str(pvnfTopoLeavesDict[leaf]['pgw_comn_loop_v4']),
                pvnfTopoLeavesDict[leaf]['leaf_to_pgw_link_count'],
                LEAF_to_PGW_loopback_route_dict[leaf]['LEAF_to_PGW_GW_v4_route_prefix_count'],
                LEAF_to_PGW_loopback_route_dict[leaf]['LEAF_to_PGW_GW_v4_fwd_route_prefix_count'],
                LEAF_to_PGW_v4_nh_count_status,
                LEAF_to_PGW_loopback_route_dict[leaf]['LEAF_to_PGW_GW_v4_route_prefix_lst']
            ])
            LEAF_to_PGW_nextHopTable.add_row([
                leaf.alias,
                str(pvnfTopoLeavesDict[leaf]['pgw_comn_loop_v6']),
                pvnfTopoLeavesDict[leaf]['leaf_to_pgw_link_count'],
                LEAF_to_PGW_loopback_route_dict[leaf]['LEAF_to_PGW_GW_v6_route_prefix_count'],
                LEAF_to_PGW_loopback_route_dict[leaf]['LEAF_to_PGW_GW_v6_fwd_route_prefix_count'],
                LEAF_to_PGW_v6_nh_count_status,
                LEAF_to_PGW_loopback_route_dict[leaf]['LEAF_to_PGW_GW_v6_route_prefix_lst']]
            )

            # --- Validate PGW to LEAF routes
            if (int(PGW_to_LEAF_loopback_route_dict[leaf]['PGW_to_LEAF_GW_v4_route_prefix_count']) >= 1) and \
                    (int(PGW_to_LEAF_loopback_route_dict[leaf]['PGW_to_LEAF_GW_v4_fwd_route_prefix_count']) >= 1):
                PGW_to_LEAF_v4_nh_count_status = 'PASS'
            else:
                fail_flag.append(0)
            if (int(PGW_to_LEAF_loopback_route_dict[leaf]['PGW_to_LEAF_GW_v6_route_prefix_count']) >= 1) and \
                    (int(PGW_to_LEAF_loopback_route_dict[leaf]['PGW_to_LEAF_GW_v6_fwd_route_prefix_count']) >= 1):
                PGW_to_LEAF_v6_nh_count_status = 'PASS'
            else:
                fail_flag.append(0)
            # ['DST NODE', 'Destination', 'Expected NH Count', 'Observed NH Count', 'status', 'Next-hops']
            PGW_to_LEAF_nextHopTable.add_row([
                leaf.alias,
                str(pvnfTopoLeavesDict[leaf]['local_loop_v4']),
                '>= 1',
                PGW_to_LEAF_loopback_route_dict[leaf]['PGW_to_LEAF_GW_v4_route_prefix_count'],
                PGW_to_LEAF_loopback_route_dict[leaf]['PGW_to_LEAF_GW_v4_fwd_route_prefix_count'],
                PGW_to_LEAF_v4_nh_count_status,
                PGW_to_LEAF_loopback_route_dict[leaf]['PGW_to_LEAF_GW_v4_route_prefix_lst']
            ])
            PGW_to_LEAF_nextHopTable.add_row([
                leaf.alias,
                str(pvnfTopoLeavesDict[leaf]['local_loop_v6']),
                '>= 1',
                PGW_to_LEAF_loopback_route_dict[leaf]['PGW_to_LEAF_GW_v6_route_prefix_count'],
                PGW_to_LEAF_loopback_route_dict[leaf]['PGW_to_LEAF_GW_v6_fwd_route_prefix_count'],
                PGW_to_LEAF_v6_nh_count_status,
                PGW_to_LEAF_loopback_route_dict[leaf]['PGW_to_LEAF_GW_v6_route_prefix_lst']
            ])

        status_msgs += '''
*** Legend
SRC NODE        == Source Node
DST NODE        == Destination Node
Destination     == Destination IP
NH Count        == Next-hops count
FWD NH Count    == Counts of Next-hops installed in hardware 'sh forwarding ipv4/v6 route'
Status          == Gives the tally of counts matching the expectations

====> Checking the Route DB from Individual LEAF's to PGW Common Gateway

''' + str(banner("IPv4/IPv6 Routes from LEAF loopback to Corresponding PGW Common Gateway (" + str(
            pvnfTopoLeavesDict[temp_leaf_for_iterations]['pgw_comn_loop_v4']) + ")", 145)) + '''
''' + str(LEAF_to_PGW_nextHopTable.draw()) + '''

====> Checking the Route DB from PGW Common Gateway to each Individual LEAF

''' + str(banner("IPv4/IPv6 Routes from PGW Common Gateway (" + str(
            pvnfTopoLeavesDict[temp_leaf_for_iterations]['local_loop_v4']) + ") to Corresponding LEAF loopback", 145)) + '''
''' + str(PGW_to_LEAF_nextHopTable.draw()) + '''
        '''

        if 0 in fail_flag:
            status = 0
        else:
            status = 1

        return {'result': status, 'status_msgs': status_msgs}