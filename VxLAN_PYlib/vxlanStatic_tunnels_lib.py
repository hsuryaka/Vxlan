"""
 VxLAN Library for Static tunnels
"""

import logging
import json
import re
import ipaddress as ip
import texttable
from pyats.aereport.utils.argsvalidator import ArgsValidator

log = logging.getLogger(__name__)
log.setLevel(logging.DEBUG)
ArgVal = ArgsValidator()

# ====================================================================================================#
# Global Methods
# ====================================================================================================#
def increment_prefix_network(pref, count):
    size = 1 << (pref.network.max_prefixlen - pref.network.prefixlen)
    pref_lst = []
    for i in range(count):
        pref_lst.append(str((pref.ip+size*i)) + "/" + str(pref.network.prefixlen))
    return pref_lst


# ====================================================================================================#
# Nexus 39K VxLAN EVPN Configuration Methods
# ====================================================================================================#
class configureVxlanStatic:

    # First we create a constructor for this class
    # and add members to it, here models
    def __init__(self):
        pass

    # ====================================================================================================#
    @staticmethod
    def configureEVPNSpines(spineList, forwardingSysDict, leavesDictList):

        # --------------------------------------------
        # Parse the arguments for their types
        # --------------------------------------------
        if type(spineList) is not list:
            print("Passed Argument spineList is not a LIST")
            return 0
        if type(leavesDictList) is not list:
            print("Passed Argument leaves_dicts is not a LIST of Leaf dictionaries")
            return 0
        if type(forwardingSysDict) is not dict:
            print("Passed Argument forwardingSysDict is not a Dictionary")
            return 0

        # --------------------------------------------
        # Parameters to be used in the following proc
        # --------------------------------------------
        spine1_pim_rp_config, spine2_pim_rp_config      = "", ""
        spine1_ospf_config, spine2_ospf_config          = "", ""
        spine1_bgp_config, spine2_bgp_config            = "", ""
        spine1_int_configs, spine2_int_configs          = "", ""

        if 'SPINE_COUNT' not in forwardingSysDict.keys():
            forwardingSysDict['SPINE_COUNT'] = 1
        for leaf in leavesDictList:
            if 'spine_leaf_po_v6' not in leaf['SPINE_1_UPLINK_PO']:
                leaf['spine_leaf_po_v6']    = ""
                leaf['leaf_spine_mask_v6']  = ""
                leaf['spine_leaf_po_v6']    = ""
                leaf['leaf_spine_mask_v6']  = ""

        # --------------------------------------------
        # Print out the Parameters passed to the proc
        # --------------------------------------------
        print("========================================")
        print("Given Forwarding System Dictionary is")
        print("========================================")
        print(json.dumps(forwardingSysDict, indent=5))
        log.info("========================================")
        log.info("Given Forwarding System Dictionary is")
        log.info("========================================")
        log.info(json.dumps(forwardingSysDict, indent=5))

        for leaf_num in range(len(leavesDictList)):
            print("========================================")
            print("Given data dictionary of LEAF-" + str(leaf_num+1))
            print("========================================")
            print(json.dumps(leavesDictList[leaf_num], indent=6))
            log.info("========================================")
            log.info("Given data dictionary of LEAF-" + str(leaf_num+1))
            log.info("========================================")
            log.info(json.dumps(leavesDictList[leaf_num], indent=6))

        # -----------------------------------------------------
        # Buildup the configurations to be applied
        # If the no.of SPINEs are 2 then configure any cast RP.
        # -----------------------------------------------------
        if forwardingSysDict['SPINE_COUNT'] is not 1:

            # --------------------------------------------
            # Building PIM RP Configuration
            # --------------------------------------------
            spine1_pim_rp_config = '''
                            
                            
                            interface loopback0
                              ip address ''' + str(leavesDictList[0]['SPINE_1_UPLINK_PO']['spine_loop0_ip']) + '''/32
                              ip ospf network point-to-point
                              ip router ospf ''' + str(forwardingSysDict['OSPF_AS']) + ''' area 0.0.0.0
                              ip pim sparse-mode
                              
                            interface loopback1
                              ip address ''' + str(leavesDictList[0]['SPINE_1_UPLINK_PO']['common_rp']) + '''/32
                              ip ospf network point-to-point
                              ip router ospf ''' + str(forwardingSysDict['OSPF_AS']) + ''' area 0.0.0.0
                              ip pim sparse-mode
                        '''

            spine2_pim_rp_config = '''
                            
                            interface loopback0
                              ip address ''' + str(leavesDictList[0]['SPINE_2_UPLINK_PO']['spine_loop0_ip']) + '''/32
                              ip ospf network point-to-point
                              ip router ospf ''' + str(forwardingSysDict['OSPF_AS']) + ''' area 0.0.0.0
                              ip pim sparse-mode
                              
                            interface loopback1
                              ip address ''' + str(leavesDictList[0]['SPINE_2_UPLINK_PO']['common_rp']) + '''/32
                              ip ospf network point-to-point
                              ip router ospf ''' + str(forwardingSysDict['OSPF_AS']) + ''' area 0.0.0.0
                              ip pim sparse-mode
                        '''

            # --------------------------------------------
            # Building OSPF Configuration
            # --------------------------------------------
            spine1_ospf_config = '''
                            router ospf ''' + str(forwardingSysDict['OSPF_AS']) + '''
                              router-id ''' + str(leavesDictList[0]['SPINE_1_UPLINK_PO']['spine_loop0_ip']) + '''
            '''

            spine2_ospf_config = '''
                            router ospf ''' + str(forwardingSysDict['OSPF_AS']) + '''
                              router-id ''' + str(leavesDictList[0]['SPINE_2_UPLINK_PO']['spine_loop0_ip']) + '''
            '''

            # --------------------------------------------
            # Building SPINE Down Link PO Configuration
            # --------------------------------------------
            for leaf in leavesDictList:
                spine1_int_configs += '''
                            interface port-channel''' + str(leaf['SPINE_1_UPLINK_PO']['po_id']) + '''
                                no switchport
                                ip address ''' + str(leaf['SPINE_1_UPLINK_PO']['spine_leaf_po_v4']) + str(leaf['SPINE_1_UPLINK_PO']['spine_leaf_mask_v4']) + '''
                                ip ospf network point-to-point
                                ip router ospf ''' + str(forwardingSysDict['OSPF_AS']) + ''' area 0.0.0.0
                                ip pim sparse-mode
                '''

                if 'spine_leaf_po_v6' in leaf['SPINE_1_UPLINK_PO'].keys():
                    spine1_int_configs += '''          ipv6 address ''' + \
                                            str(leaf['SPINE_1_UPLINK_PO']['spine_leaf_po_v6']) + \
                                            str(leaf['SPINE_1_UPLINK_PO']['spine_leaf_mask_v6']) + '''\n'''

                spine2_int_configs += '''
                            interface port-channel''' + str(leaf['SPINE_2_UPLINK_PO']['po_id']) + '''
                                no switchport
                                ip address ''' + str(leaf['SPINE_2_UPLINK_PO']['spine_leaf_po_v4']) + str(leaf['SPINE_2_UPLINK_PO']['spine_leaf_mask_v4']) + '''
                                ip ospf network point-to-point
                                ip router ospf ''' + str(forwardingSysDict['OSPF_AS']) + ''' area 0.0.0.0
                                ip pim sparse-mode
                '''

                if 'spine_leaf_po_v6' in leaf['SPINE_2_UPLINK_PO'].keys():
                    spine2_int_configs += '''          ipv6 address ''' + \
                                            str(leaf['SPINE_2_UPLINK_PO']['spine_leaf_po_v6']) + \
                                            str(leaf['SPINE_2_UPLINK_PO']['spine_leaf_mask_v6']) + '''\n'''

            # --------------------------------------------
            # Building BGP Configuration
            # --------------------------------------------
            spine1_bgp_config = '''
                            route-map setnh_unchanged permit 10
                            
                            router bgp ''' + str(forwardingSysDict['BGP_AS_num']) + '''
                              router-id ''' + str(leavesDictList[0]['SPINE_1_UPLINK_PO']['spine_loop0_ip']) + '''
                              log-neighbor-changes
                              event-history errors size large
                              event-history detail size large
                              address-family ipv4 unicast
                              address-family ipv6 unicast
                              template peer ibgp_evpn
                                log-neighbor-changes
                                address-family ipv4 unicast
                                  send-community both
                                  route-reflector-client
                                address-family ipv6 unicast
                                  send-community both
                                  route-reflector-client
                                
            '''

            spine2_bgp_config = '''
                            route-map setnh_unchanged permit 10

                            router bgp ''' + str(forwardingSysDict['BGP_AS_num']) + '''
                              router-id ''' + str(leavesDictList[0]['SPINE_2_UPLINK_PO']['spine_loop0_ip']) + '''
                              log-neighbor-changes
                              event-history errors size large
                              event-history detail size large
                              address-family ipv4 unicast
                              address-family ipv6 unicast
                              template peer ibgp_evpn
                                log-neighbor-changes
                                address-family ipv4 unicast
                                  send-community both
                                  route-reflector-client
                                address-family ipv6 unicast
                                  send-community both
                                  route-reflector-client
                                
            '''

            # --------------------------------------------
            # Building BGP Neighbor Configuration
            # --------------------------------------------
            for leaf in leavesDictList:
                spine1_bgp_config += '''
                              neighbor ''' + str(leaf['SPINE_1_UPLINK_PO']['leaf_spine_po_v4']) + ''' remote-as ''' + str(forwardingSysDict['BGP_AS_num']) + '''
                                inherit peer ibgp_evpn
                '''

                spine2_bgp_config += '''
                              neighbor ''' + str(leaf['SPINE_2_UPLINK_PO']['leaf_spine_po_v4']) + ''' remote-as ''' + str(forwardingSysDict['BGP_AS_num']) + '''
                                inherit peer ibgp_evpn
                '''
        # --------------------------------------------
        # Buildup the configurations to be applied.
        # If the no.of SPINEs are 1 then configure RP
        # --------------------------------------------
        else:

            # --------------------------------------------
            # Building PIM RP Configuration
            # --------------------------------------------
            spine1_pim_rp_config = '''

                            interface loopback0
                              ip address ''' + str(leavesDictList[0]['SPINE_1_UPLINK_PO']['spine_loop0_ip']) + '''/32
                              ip ospf network point-to-point
                              ip router ospf ''' + str(forwardingSysDict['OSPF_AS']) + ''' area 0.0.0.0
                              ip pim sparse-mode
                        '''

            # --------------------------------------------
            # Building OSPF Configuration
            # --------------------------------------------
            spine1_ospf_config = '''
                            router ospf ''' + str(forwardingSysDict['OSPF_AS']) + '''
                              router-id ''' + str(leavesDictList[0]['SPINE_1_UPLINK_PO']['spine_loop0_ip']) + '''
            '''

            # --------------------------------------------
            # Building SPINE Down Link PO Configuration
            # --------------------------------------------
            for leaf in leavesDictList:
                spine1_int_configs += '''
                            interface port-channel''' + str(leaf['SPINE_1_UPLINK_PO']['po_id']) + '''
                                no switchport
                                ip address ''' + str(leaf['SPINE_1_UPLINK_PO']['spine_leaf_po_v4']) + str(leaf['SPINE_1_UPLINK_PO']['spine_leaf_mask_v4']) + '''
                                ip ospf network point-to-point
                                ip router ospf ''' + str(forwardingSysDict['OSPF_AS']) + ''' area 0.0.0.0
                                ip pim sparse-mode
                '''

                if 'spine_leaf_po_v6' in leaf['SPINE_1_UPLINK_PO'].keys():
                    spine1_int_configs += '''          ipv6 address ''' + \
                                            str(leaf['SPINE_1_UPLINK_PO']['spine_leaf_po_v6']) + \
                                            str(leaf['SPINE_1_UPLINK_PO']['spine_leaf_mask_v6']) + '''\n'''

            # --------------------------------------------
            # Building BGP Configuration
            # --------------------------------------------
            spine1_bgp_config = '''
                            route-map setnh_unchanged permit 10
                            
                            router bgp ''' + str(forwardingSysDict['BGP_AS_num']) + '''
                              router-id ''' + str(leavesDictList[0]['SPINE_1_UPLINK_PO']['spine_loop0_ip']) + '''
                              log-neighbor-changes
                              event-history errors size large
                              event-history detail size large
                              address-family ipv4 unicast
                              address-family ipv6 unicast
                              template peer ibgp_evpn
                                log-neighbor-changes
                                address-family ipv4 unicast
                                  send-community both
                                  route-reflector-client
                                address-family ipv6 unicast
                                  send-community both
                                  route-reflector-client
                                
            '''

            # --------------------------------------------
            # Building BGP Neighbor Configuration
            # --------------------------------------------
            for leaf in leavesDictList:
                spine1_bgp_config += '''
                              neighbor ''' + str(leaf['SPINE_1_UPLINK_PO']['leaf_spine_po_v4']) + ''' remote-as ''' + str(forwardingSysDict['BGP_AS_num']) + '''
                                inherit peer ibgp_evpn
                '''

        # --------------------------------------------
        # Apply the configuration on the SPINEs.
        # --------------------------------------------
        if forwardingSysDict['SPINE_COUNT'] is not 1:
            print("=========== SPINE-1: Performing Configurations ===========")
            log.info("=========== SPINE-1: Performing Configurations ===========")
            print("=========== SPINE-2: Performing Configurations ===========")
            log.info("=========== SPINE-2: Performing Configurations ===========")
            spineList[0].configure(spine1_pim_rp_config + spine1_ospf_config + spine1_int_configs + spine1_bgp_config)
            spineList[1].configure(spine2_pim_rp_config + spine2_ospf_config + spine2_int_configs + spine2_bgp_config)
        else:
            print("=========== SPINE-1: Performing Configurations ===========")
            log.info("=========== SPINE-1: Performing Configurations ===========")
            spineList[0].configure(spine1_pim_rp_config + spine1_ospf_config + spine1_int_configs + spine1_bgp_config)

    # # ====================================================================================================#
    # @staticmethod
    # def configureEVPNVPCLeafs(forwardingSysDict, vpc_leaves_dicts):
    # 
    #     # --------------------------------------------
    #     # Parse the arguments for their types
    #     # --------------------------------------------
    #     if type(vpc_leaves_dicts) is not dict:
    #         print("Passed Argument vpc_leaves_dicts is not a Dictionary of Leaf data")
    #         return 0
    #     if type(forwardingSysDict) is not dict:
    #         print("Passed Argument forwardingSysDict is not a Dictionary")
    #         return 0
    # 
    #     # --------------------------------------------
    #     # Parameters to be used in the following proc
    #     # --------------------------------------------
    #     leaf1_pim_rp_config, leaf2_pim_rp_config        = "", ""
    #     leaf1_nve_config, leaf2_nve_config              = "", ""
    #     leaf1_vpc_config, leaf2_vpc_config              = "", ""
    #     leaf1_ospf_config, leaf2_ospf_config            = "", ""
    #     leaf1_bgp_config, leaf2_bgp_config              = "", ""
    #     leaf1_uplink_configs, leaf2_uplink_configs      = "", ""
    # 
    #     leaf1       = list(vpc_leaves_dicts.keys())[0]
    #     leaf2       = list(vpc_leaves_dicts.keys())[1]
    #     leaf1_data  = vpc_leaves_dicts[leaf1]
    #     leaf2_data  = vpc_leaves_dicts[leaf2]
    # 
    #     leafDictLst = [leaf1_data, leaf2_data]
    # 
    #     if 'SPINE_COUNT' not in forwardingSysDict.keys():
    #         forwardingSysDict['SPINE_COUNT'] = 1
    # 
    #     if 'spine_leaf_po_v6' not in leaf1_data['SPINE_1_UPLINK_PO']:
    #         leaf1_data['SPINE_1_UPLINK_PO']['spine_leaf_po_v6']    = ""
    #         leaf1_data['SPINE_1_UPLINK_PO']['leaf_spine_mask_v6']  = ""
    #         leaf1_data['SPINE_1_UPLINK_PO']['spine_leaf_po_v6']    = ""
    #         leaf1_data['SPINE_1_UPLINK_PO']['leaf_spine_mask_v6']  = ""
    # 
    #     if forwardingSysDict['SPINE_COUNT'] is 2:
    #         if 'spine_leaf_po_v6' not in leaf1_data['SPINE_2_UPLINK_PO']:
    #             leaf1_data['SPINE_2_UPLINK_PO']['spine_leaf_po_v6']     = ""
    #             leaf1_data['SPINE_2_UPLINK_PO']['leaf_spine_mask_v6']   = ""
    #             leaf1_data['SPINE_2_UPLINK_PO']['spine_leaf_po_v6']     = ""
    #             leaf1_data['SPINE_2_UPLINK_PO']['leaf_spine_mask_v6']   = ""
    # 
    #     # --------------------------------------------
    #     # Print out the Parameters passed to the proc
    #     # --------------------------------------------
    #     print("========================================")
    #     print("Given Forwarding System Dictionary is")
    #     print("========================================")
    #     print(json.dumps(forwardingSysDict, indent=5))
    #     log.info("========================================")
    #     log.info("Given Forwarding System Dictionary is")
    #     log.info("========================================")
    #     log.info(json.dumps(forwardingSysDict, indent=5))
    # 
    #     for leaf_num in range(len(leafDictLst)):
    #         print("========================================")
    #         print("Given data dictionary of LEAF-" + str(leaf_num+1))
    #         print("========================================")
    #         print(json.dumps(leafDictLst[leaf_num], indent=6))
    #         log.info("========================================")
    #         log.info("Given data dictionary of LEAF-" + str(leaf_num+1))
    #         log.info("========================================")
    #         log.info(json.dumps(leafDictLst[leaf_num], indent=6))
    # 
    #     # -----------------------------------------------------
    #     # Buildup the configurations to be applied
    #     # If the no.of SPINEs are 2 then configure any cast RP.
    #     # -----------------------------------------------------
    #     if forwardingSysDict['SPINE_COUNT'] is not 1:
    #         leaf1_pim_rp_config += '''
    #             nv overlay evpn
    #             fabric forwarding anycast-gateway-mac 0000.000a.aaaa
    #             ip pim rp-address ''' + str(leaf1_data['SPINE_1_UPLINK_PO']['common_rp']) + ''' group-list 224.0.0.0/4
    #             ip pim ssm range 232.0.0.0/8
    #         '''
    # 
    #         leaf2_pim_rp_config += '''
    #             nv overlay evpn
    #             fabric forwarding anycast-gateway-mac 0000.000a.aaaa
    #             ip pim rp-address ''' + str(leaf2_data['SPINE_1_UPLINK_PO']['common_rp']) + ''' group-list 224.0.0.0/4
    #             ip pim ssm range 232.0.0.0/8
    #         '''
    #     else:
    #         leaf1_pim_rp_config += '''
    #             nv overlay evpn
    #             fabric forwarding anycast-gateway-mac 0000.000a.aaaa
    #             ip pim rp-address ''' + str(leaf1_data['SPINE_1_UPLINK_PO']['spine_loop0_ip']) + ''' group-list 224.0.0.0/4
    #             ip pim ssm range 232.0.0.0/8
    #         '''
    # 
    #         leaf2_pim_rp_config += '''
    #             nv overlay evpn
    #             fabric forwarding anycast-gateway-mac 0000.000a.aaaa
    #             ip pim rp-address ''' + str(leaf2_data['SPINE_1_UPLINK_PO']['spine_loop0_ip']) + ''' group-list 224.0.0.0/4
    #             ip pim ssm range 232.0.0.0/8
    #         '''
    # 
    #     leaf1_pim_rp_config += '''
    #             interface loopback0
    #               ip address ''' + str(leaf1_data['loop0_ip']) + '''/32
    #               ip ospf network point-to-point
    #               ip router ospf ''' + str(forwardingSysDict['OSPF_AS']) + ''' area 0.0.0.0
    #               ip pim sparse-mode
    # 
    #             interface loopback1
    #               ip address ''' + str(leaf1_data['NVE_data']['VTEP_IP']) + '''/32
    #               ip address ''' + str(leaf1_data['NVE_data']['VPC_VTEP_IP']) + '''/32 secondary
    #               ip ospf network point-to-point
    #               ip router ospf ''' + str(forwardingSysDict['OSPF_AS']) + ''' area 0.0.0.0
    #               ip pim sparse-mode        
    #     '''
    # 
    #     leaf2_pim_rp_config += '''
    #             interface loopback0
    #               ip address ''' + str(leaf2_data['loop0_ip']) + '''/32
    #               ip ospf network point-to-point
    #               ip router ospf ''' + str(forwardingSysDict['OSPF_AS']) + ''' area 0.0.0.0
    #               ip pim sparse-mode
    # 
    #             interface loopback1
    #               ip address ''' + str(leaf2_data['NVE_data']['VTEP_IP']) + '''/32
    #               ip address ''' + str(leaf2_data['NVE_data']['VPC_VTEP_IP']) + '''/32 secondary
    #               ip ospf network point-to-point
    #               ip router ospf ''' + str(forwardingSysDict['OSPF_AS']) + ''' area 0.0.0.0
    #               ip pim sparse-mode       
    #     '''
    # 
    #     # --------------------------------------------
    #     # Building VPC Configuration
    #     # --------------------------------------------
    #     leaf1_vpc_config += '''
    #             vrf context ''' + str(leaf1_data['VPC_data']['kp_al_vrf']) + '''
    # 
    #             vpc domain ''' + str(leaf1_data['VPC_data']['domain_id']) + '''
    #               peer-switch
    #               peer-keepalive destination ''' + str(leaf2_data['VPC_data']['kp_al_ip']) + ''' source ''' + str(leaf1_data['VPC_data']['kp_al_ip']) + ''' vrf ''' + str(leaf1_data['VPC_data']['kp_al_vrf']) + '''
    #               peer-gateway                           
    #               ipv6 nd synchronize                    
    #               ip arp synchronize
    #               system-priority 3000
    #               role priority 3000
    #               
    #             interface port-channel''' + str(leaf1_data['VPC_data']['peer_link_po']) + '''
    #               switchport
    #               switchport mode trunk
    #               spanning-tree port type network
    #               vpc peer-link
    #     '''
    # 
    #     leaf2_vpc_config += '''
    #             vrf context ''' + str(leaf2_data['VPC_data']['kp_al_vrf']) + '''
    # 
    #             vpc domain ''' + str(leaf2_data['VPC_data']['domain_id']) + '''
    #               peer-switch
    #               peer-keepalive destination ''' + str(leaf1_data['VPC_data']['kp_al_ip']) + ''' source ''' + str(leaf2_data['VPC_data']['kp_al_ip']) + ''' vrf ''' + str(leaf2_data['VPC_data']['kp_al_vrf']) + '''
    #               peer-gateway                           
    #               ipv6 nd synchronize                    
    #               ip arp synchronize
    #               system-priority 3000
    #               role priority 3001
    #               
    #             interface port-channel''' + str(leaf2_data['VPC_data']['peer_link_po']) + '''
    #               switchport
    #               switchport mode trunk
    #               spanning-tree port type network
    #               vpc peer-link                              
    #     '''
    # 
    #     # --------------------------------------------
    #     # Building interface Configuration
    #     # --------------------------------------------
    #     leaf1_uplink_configs += '''
    #             interface port-channel''' + str(leaf1_data['SPINE_1_UPLINK_PO']['po_id']) + '''
    #               no switchport
    #               ip address ''' + str(leaf1_data['SPINE_1_UPLINK_PO']['leaf_spine_po_v4']) + str(leaf1_data['SPINE_1_UPLINK_PO']['leaf_spine_mask_v4']) + '''
    #               ip ospf network point-to-point
    #               ip router ospf ''' + str(forwardingSysDict['OSPF_AS']) + ''' area 0.0.0.0
    #               ip pim sparse-mode
    #     '''
    # 
    #     leaf2_uplink_configs += '''
    #             interface port-channel''' + str(leaf2_data['SPINE_1_UPLINK_PO']['po_id']) + '''
    #               no switchport
    #               ip address ''' + str(leaf2_data['SPINE_1_UPLINK_PO']['leaf_spine_po_v4']) + str(leaf2_data['SPINE_1_UPLINK_PO']['leaf_spine_mask_v4']) + '''
    #               ip ospf network point-to-point
    #               ip router ospf ''' + str(forwardingSysDict['OSPF_AS']) + ''' area 0.0.0.0
    #               ip pim sparse-mode
    #     '''
    # 
    #     if 'leaf_spine_po_v6' in leaf1_data['SPINE_1_UPLINK_PO'].keys() and 'leaf_spine_po_v6' in leaf2_data['SPINE_1_UPLINK_PO'].keys():
    #         leaf1_uplink_configs += '''          ipv6 address ''' + \
    #                                 str(leaf1_data['SPINE_1_UPLINK_PO']['leaf_spine_po_v6']) + \
    #                                 str(leaf1_data['SPINE_1_UPLINK_PO']['leaf_spine_mask_v6']) + '''\n'''
    #         leaf2_uplink_configs += '''          ipv6 address ''' + \
    #                                 str(leaf2_data['SPINE_1_UPLINK_PO']['leaf_spine_po_v6']) + \
    #                                 str(leaf2_data['SPINE_1_UPLINK_PO']['leaf_spine_mask_v6']) + '''\n'''
    # 
    #     if forwardingSysDict['SPINE_COUNT'] is not 1:
    #         leaf1_uplink_configs += '''
    #             interface port-channel''' + str(leaf1_data['SPINE_2_UPLINK_PO']['po_id']) + '''
    #               no switchport
    #               ip address ''' + str(leaf1_data['SPINE_2_UPLINK_PO']['leaf_spine_po_v4']) + str(leaf1_data['SPINE_2_UPLINK_PO']['leaf_spine_mask_v4']) + '''
    #               ip ospf network point-to-point
    #               ip router ospf ''' + str(forwardingSysDict['OSPF_AS']) + ''' area 0.0.0.0
    #               ip pim sparse-mode
    #         '''
    # 
    #         leaf2_uplink_configs += '''
    #             interface port-channel''' + str(leaf2_data['SPINE_2_UPLINK_PO']['po_id']) + '''
    #               no switchport
    #               ip address ''' + str(leaf2_data['SPINE_2_UPLINK_PO']['leaf_spine_po_v4']) + str(leaf2_data['SPINE_2_UPLINK_PO']['leaf_spine_mask_v4']) + '''
    #               ip ospf network point-to-point
    #               ip router ospf ''' + str(forwardingSysDict['OSPF_AS']) + ''' area 0.0.0.0
    #               ip pim sparse-mode
    #         '''
    # 
    #         if 'leaf_spine_po_v6' in leaf1_data['SPINE_2_UPLINK_PO'].keys() and 'leaf_spine_po_v6' in leaf2_data['SPINE_1_UPLINK_PO'].keys():
    #             leaf1_uplink_configs += '''      ipv6 address ''' + \
    #                                     str(leaf1_data['SPINE_2_UPLINK_PO']['leaf_spine_po_v6']) + \
    #                                     str(leaf1_data['SPINE_2_UPLINK_PO']['leaf_spine_mask_v6']) + '''\n'''
    #             leaf2_uplink_configs += '''      ipv6 address ''' + \
    #                                     str(leaf2_data['SPINE_2_UPLINK_PO']['leaf_spine_po_v6']) + \
    #                                     str(leaf2_data['SPINE_2_UPLINK_PO']['leaf_spine_mask_v6']) + '''\n'''
    # 
    #     # --------------------------------------------
    #     # Building OSPF Configuration
    #     # --------------------------------------------
    #     leaf1_ospf_config += '''
    #             router ospf ''' + str(forwardingSysDict['OSPF_AS']) + '''
    #               router-id ''' + str(leaf1_data['loop0_ip']) + '''
    #     '''
    # 
    #     leaf2_ospf_config += '''
    #             router ospf ''' + str(forwardingSysDict['OSPF_AS']) + '''
    #               router-id ''' + str(leaf2_data['loop0_ip']) + '''
    #     '''
    # 
    #     # --------------------------------------------
    #     # Building BGP Configuration
    #     # --------------------------------------------
    #     leaf1_bgp_config += '''
    #             route-map ANY permit 10
    #                   
    #             router bgp ''' + str(forwardingSysDict['BGP_AS_num']) + '''
    #               router-id ''' + str(leaf1_data['loop0_ip']) + '''
    #               address-family ipv4 unicast
    #               address-family ipv6 unicast
    #               address-family l2vpn evpn
    #               template peer ibgp_evpn
    #                 log-neighbor-changes
    #                 address-family ipv4 unicast
    #                   send-community
    #                   send-community extended
    #                 address-family ipv6 unicast
    #                   send-community
    #                   send-community extended
    #                 address-family l2vpn evpn
    #                   send-community
    #                   send-community extended
    #     '''
    # 
    #     leaf2_bgp_config += '''
    #             route-map ANY permit 10
    # 
    #             router bgp ''' + str(forwardingSysDict['BGP_AS_num']) + '''
    #               router-id ''' + str(leaf2_data['loop0_ip']) + '''
    #               address-family ipv4 unicast
    #               address-family ipv6 unicast
    #               address-family l2vpn evpn
    #               template peer ibgp_evpn
    #                 log-neighbor-changes
    #                 address-family ipv4 unicast
    #                   send-community
    #                   send-community extended
    #                 address-family ipv6 unicast
    #                   send-community
    #                   send-community extended
    #                 address-family l2vpn evpn
    #                   send-community
    #                   send-community extended
    #     '''
    # 
    #     # --------------------------------------------
    #     # Building BGP Neighbor Configuration
    #     # --------------------------------------------
    #     leaf1_bgp_config += '''
    #               neighbor ''' + str(leaf1_data['SPINE_1_UPLINK_PO']['spine_leaf_po_v4']) + '''
    #                 inherit peer ibgp_evpn
    #                 remote-as ''' + str(forwardingSysDict['BGP_AS_num']) + '''
    #     '''
    # 
    #     leaf2_bgp_config += '''
    #               neighbor ''' + str(leaf2_data['SPINE_1_UPLINK_PO']['spine_leaf_po_v4']) + '''
    #                 inherit peer ibgp_evpn
    #                 remote-as ''' + str(forwardingSysDict['BGP_AS_num']) + '''
    #     '''
    # 
    #     if forwardingSysDict['SPINE_COUNT'] is not 1:
    #         leaf1_bgp_config += '''
    #               neighbor ''' + str(leaf1_data['SPINE_2_UPLINK_PO']['spine_leaf_po_v4']) + '''
    #                 inherit peer ibgp_evpn
    #                 remote-as ''' + str(forwardingSysDict['BGP_AS_num']) + '''
    #         '''
    # 
    #         leaf2_bgp_config += '''
    #               neighbor ''' + str(leaf2_data['SPINE_2_UPLINK_PO']['spine_leaf_po_v4']) + '''
    #                 inherit peer ibgp_evpn
    #                 remote-as ''' + str(forwardingSysDict['BGP_AS_num']) + '''
    #         '''
    # 
    #     # --------------------------------------------
    #     # Building NVE Interface Configuration
    #     # --------------------------------------------
    #     leaf1_nve_config += '''
    #             interface nve1
    #               no shutdown
    #               host-reachability protocol bgp
    #               source-interface ''' + str(leaf1_data['NVE_data']['src_loop']) + '''
    #     '''
    # 
    #     leaf2_nve_config += '''
    #             interface nve1
    #               no shutdown
    #               host-reachability protocol bgp
    #               source-interface ''' + str(leaf2_data['NVE_data']['src_loop']) + '''
    #     '''
    # 
    #     # --------------------------------------------
    #     # Building VPC ACCESS PO Configuration
    #     # If List of POs are given then configure all.
    #     # If a single PO is given then configure PO.
    #     # --------------------------------------------
    #     if 'VPC_ACC_po' in leaf1_data['VPC_data'].keys() and 'VPC_ACC_po' in leaf2_data['VPC_data'].keys():
    #         if type(leaf1_data['VPC_data']['VPC_ACC_po']) is list and type(leaf2_data['VPC_data']['VPC_ACC_po']) is list:
    #             for PO in leaf1_data['VPC_data']['VPC_ACC_po']:
    #                 leaf1_vpc_config += '''
    #                 interface port-channel''' + str(PO) + '''
    #                   switchport
    #                   switchport mode trunk
    #                   vpc ''' + str(PO) + '''
    #                   no shutdown
    #                 '''
    # 
    #                 leaf2_vpc_config += '''
    #                 interface port-channel''' + str(PO) + '''
    #                   switchport
    #                   switchport mode trunk
    #                   vpc ''' + str(PO) + '''
    #                   no shutdown
    #                 '''
    # 
    #         elif type(leaf1_data['VPC_data']['VPC_ACC_po']) in [str, int] and type(leaf2_data['VPC_data']['VPC_ACC_po']) in [str, int]:
    #             leaf1_vpc_config += '''
    #                 interface port-channel''' + str(leaf1_data['VPC_data']['VPC_ACC_po']) + '''
    #                   switchport
    #                   switchport mode trunk
    #                   vpc ''' + str(leaf1_data['VPC_data']['VPC_ACC_po']) + '''
    #                   no shutdown
    #             '''
    # 
    #             leaf2_vpc_config += '''
    #                 interface port-channel''' + str(leaf2_data['VPC_data']['VPC_ACC_po']) + '''
    #                   switchport
    #                   switchport mode trunk
    #                   vpc ''' + str(leaf2_data['VPC_data']['VPC_ACC_po']) + '''
    #                   no shutdown
    #             '''
    #     else:
    #         log.info("VPC_ACC_po Key not present in the input DICT, hence skipping VPC Down stream PO configuration")
    #     # ----------------------------------------------------
    #     # Build Incremental configs for VRF, VNI, L2/L3 VLANs
    #     # ----------------------------------------------------
    #     # ----------------------------------------------------
    #     # LEAF Configuration Parameters
    #     # ----------------------------------------------------
    #     leaf_vlan_config    = ""
    #     leaf_vrf_config     = ""
    #     leaf_svi_config     = ""
    #     leaf_nve_config     = ""
    #     leaf_vni_bgp_config = ""
    # 
    #     # ----------------------------------------------------
    #     # Counter Variables
    #     # ----------------------------------------------------
    #     l3_vrf_count_iter   = 0
    #     ip_index            = 0
    #     l2_ipv6s            = []
    # 
    #     # ----------------------------------------------------
    #     # Fetching IP and VNI data from the configuration dict
    #     # ----------------------------------------------------
    #     total_ip_count  = int(forwardingSysDict['VLAN_PER_VRF_count']) * int(forwardingSysDict['VRF_count'])
    #     l2_ipv4s        = increment_prefix_network(ip.IPv4Interface(str(leaf1_data['VNI_data']['l2_vlan_ipv4_start']) + str(leaf1_data['VNI_data']['l2_vlan_ipv4_mask'])), total_ip_count)
    #     if 'l2_vlan_ipv6_start' in leaf1_data['VNI_data'].keys() and 'l2_vlan_ipv6_start' in leaf2_data['VNI_data'].keys():
    #         l2_ipv6s        = increment_prefix_network(ip.IPv6Interface(str(leaf1_data['VNI_data']['l2_vlan_ipv6_start']) + str(leaf1_data['VNI_data']['l2_vlan_ipv6_mask'])), total_ip_count)
    #     l3_mcast_grp    = ip.IPv4Interface(leaf1_data['NVE_data']['l3_mcast_grp_ip']).ip
    #     l2_mcast_grp    = ip.IPv4Interface(leaf1_data['NVE_data']['l2_mcast_grp_ip']).ip
    # 
    #     vrf_id          = forwardingSysDict['VRF_id_start']
    # 
    #     l3_vlan_id      = leaf1_data['VNI_data']['l3_vlan_start']
    #     l3_vn_seg_id    = leaf1_data['VNI_data']['l3_vni_start']
    # 
    #     l2_vlan_id      = leaf1_data['VNI_data']['l2_vlan_start']
    #     l2_vn_seg_id    = leaf1_data['VNI_data']['l2_vni_start']
    # 
    #     # ----------------------------------------------------
    #     # Outer While Loop for L3 Configurations
    #     # ----------------------------------------------------
    #     while l3_vrf_count_iter < forwardingSysDict['VRF_count']:
    #         # Configure L3 VRF and L3 VNIs
    #         leaf_vlan_config += '''
    #                 vlan ''' + str(l3_vlan_id) + '''
    #                   state active
    #                   no shut
    #                   vn-segment ''' + str(l3_vn_seg_id) + '''
    #         '''
    # 
    #         leaf_vrf_config += '''
    #                 vrf context ''' + str(forwardingSysDict['VRF_string']) + str(vrf_id) + '''
    #                   vni ''' + str(l3_vn_seg_id) + '''
    #                   ip pim ssm range 232.0.0.0/8
    #                   rd auto
    #                   address-family ipv4 unicast
    #                     route-target both auto
    #                     route-target both auto evpn
    #                     export map ANY
    #                   address-family ipv6 unicast
    #                     route-target both auto
    #                     route-target both auto evpn
    #                     export map ANY
    #         '''
    # 
    #         leaf_svi_config += '''
    #                 interface Vlan''' + str(l3_vlan_id) + '''
    #                   no shutdown
    #                   vrf member ''' + str(forwardingSysDict['VRF_string']) + str(vrf_id) + '''
    #                   no ip redirects
    #                   ip forward
    #                   ipv6 forward
    #                   no ipv6 redirects
    #                   ip pim sparse-mode
    #         '''
    # 
    #         leaf_nve_config += '''
    #                 interface nve 1
    #                     member vni ''' + str(l3_vn_seg_id) + ''' associate-vrf
    #         '''
    # 
    #         leaf_vni_bgp_config += '''
    #                 router bgp ''' + str(forwardingSysDict['BGP_AS_num']) + '''
    #                     vrf ''' + str(forwardingSysDict['VRF_string']) + str(vrf_id) + '''
    #                       address-family ipv4 unicast
    #                         advertise l2vpn evpn
    #                         wait-igp-convergence
    #                         redistribute direct route-map ANY
    #                       address-family ipv6 unicast
    #                         advertise l2vpn evpn
    #                         wait-igp-convergence
    #                         redistribute direct route-map ANY
    #         '''
    # 
    #         # ----------------------------------------------------
    #         # Inner while loop for L2 Configurations
    #         # ----------------------------------------------------
    #         l2_vlan_count_iter = 0
    #         while l2_vlan_count_iter < forwardingSysDict['VLAN_PER_VRF_count']:
    #             # Configure L2 VNIs
    #             leaf_vlan_config += '''
    #                 vlan ''' + str(l2_vlan_id) + '''
    #                   state active
    #                   no shut
    #                   vn-segment ''' + str(l2_vn_seg_id) + '''
    #             '''
    # 
    #             leaf_nve_config += '''
    #                 interface nve 1
    #                     member vni ''' + str(l2_vn_seg_id) + '''
    #                       mcast-group ''' + str(l2_mcast_grp) + '''
    #                       suppress-arp
    #             '''
    # 
    #             leaf_vni_bgp_config += '''
    #                 router bgp ''' + str(forwardingSysDict['BGP_AS_num']) + '''
    #                     evpn
    #                       vni ''' + str(l2_vn_seg_id) + ''' l2
    #                         rd auto
    #                         route-target import auto
    #                         route-target export auto
    #             '''
    # 
    #             if "l2_vlan_ipv4_start" in leaf1_data['VNI_data'].keys() and "l2_vlan_ipv4_start" in leaf2_data['VNI_data'].keys():
    #                 leaf_svi_config += '''
    #                 interface Vlan''' + str(l2_vlan_id) + '''
    #                   no shutdown
    #                   vrf member ''' + str(forwardingSysDict['VRF_string']) + str(vrf_id) + '''
    #                   no ip redirects
    #                   ip address ''' + str(l2_ipv4s[ip_index]) + '''
    #                   no ipv6 redirects
    #                   fabric forwarding mode anycast-gateway'''
    # 
    #             if 'l2_vlan_ipv6_start' in leaf1_data['VNI_data'].keys() and 'l2_vlan_ipv6_start' in leaf2_data['VNI_data'].keys():
    #                 leaf_svi_config += '''
    #                   ipv6 address ''' + str(l2_ipv6s[ip_index]) + '''
    #                 '''
    # 
    #             # Incrementing L2 VLAN Iteration counters
    #             l2_vlan_count_iter += 1
    #             l2_vlan_id += 1
    #             l2_vn_seg_id += 1
    #             ip_index += 1
    # 
    #         # Incrementing L3 VRF Iteration counters
    #         l3_mcast_grp += 256
    #         l2_mcast_grp += 256
    #         l3_vrf_count_iter += 1
    #         l3_vlan_id += 1
    #         l3_vn_seg_id += 1
    #         vrf_id += 1
    # 
    #     # ----------------------------------------------------
    #     # Perform the configurations
    #     # ----------------------------------------------------
    #     print("=========== LEAF1: Performing Base EVPN and VPC Configurations ===========")
    #     log.info("=========== LEAF1: Performing Base EVPN and VPC Configurations ===========")
    #     print(leaf1_pim_rp_config + leaf1_vpc_config + leaf1_uplink_configs + leaf1_ospf_config + leaf1_bgp_config + leaf1_nve_config)
    #     leaf1.configure(leaf1_pim_rp_config + leaf1_vpc_config + leaf1_uplink_configs + leaf1_ospf_config + leaf1_bgp_config + leaf1_nve_config)
    #     print("=========== LEAF2: Performing Base EVPN and VPC Configurations ===========")
    #     log.info("=========== LEAF2: Performing Base EVPN and VPC Configurations ===========")
    #     leaf2.configure(leaf2_pim_rp_config + leaf2_vpc_config + leaf2_uplink_configs + leaf2_ospf_config + leaf2_bgp_config + leaf2_nve_config)
    # 
    #     print("=========== LEAF1: Performing NVE VLAN Configurations ===========")
    #     log.info("=========== LEAF1: Performing NVE VLAN Configurations ===========")
    #     leaf1.configure(leaf_vlan_config + leaf_vrf_config + leaf_svi_config + leaf_nve_config + leaf_vni_bgp_config)
    #     print("=========== LEAF2: Performing NVE VLAN Configurations ===========")
    #     log.info("=========== LEAF2: Performing NVE VLAN Configurations ===========")
    #     leaf2.configure(leaf_vlan_config + leaf_vrf_config + leaf_svi_config + leaf_nve_config + leaf_vni_bgp_config)

    # ====================================================================================================#
    @staticmethod
    def configureStaticLeaf(leaf, forwardingSysDict, leaf_dict ,remote_leaf_dict):

        # --------------------------------------------
        # Parse the arguments for their types
        # --------------------------------------------
        if type(leaf_dict) is not dict:
            print("Passed Argument leaves_dicts is not a LIST of Leaf dictionaries")
            return 0
        if type(forwardingSysDict) is not dict:
            print("Passed Argument forwardingSysDict is not a Dictionary")
            return 0

        # --------------------------------------------
        # Parameters to be used in the following proc
        # --------------------------------------------
        leaf1_pim_rp_config     = ""
        leaf1_nve_config        = ""
        leaf1_vpc_config        = ""
        leaf1_ospf_config       = ""
        leaf1_bgp_config        = ""
        leaf1_uplink_configs    = ""

        if 'SPINE_COUNT' not in forwardingSysDict.keys():
            forwardingSysDict['SPINE_COUNT'] = 1

        if 'spine_leaf_po_v6' not in leaf_dict['SPINE_1_UPLINK_PO']:
            leaf_dict['SPINE_1_UPLINK_PO']['spine_leaf_po_v6']    = ""
            leaf_dict['SPINE_1_UPLINK_PO']['leaf_spine_mask_v6']  = ""
            leaf_dict['SPINE_1_UPLINK_PO']['spine_leaf_po_v6']    = ""
            leaf_dict['SPINE_1_UPLINK_PO']['leaf_spine_mask_v6']  = ""

        if forwardingSysDict['SPINE_COUNT'] is 2:
            if 'spine_leaf_po_v6' not in leaf_dict['SPINE_2_UPLINK_PO']:
                leaf_dict['SPINE_2_UPLINK_PO']['spine_leaf_po_v6']     = ""
                leaf_dict['SPINE_2_UPLINK_PO']['leaf_spine_mask_v6']   = ""
                leaf_dict['SPINE_2_UPLINK_PO']['spine_leaf_po_v6']     = ""
                leaf_dict['SPINE_2_UPLINK_PO']['leaf_spine_mask_v6']   = ""

        # --------------------------------------------
        # Print out the Parameters passed to the proc
        # --------------------------------------------
        print("========================================")
        print("Given Forwarding System Dictionary is")
        print("========================================")
        print(json.dumps(forwardingSysDict, indent=5))
        log.info("========================================")
        log.info("Given Forwarding System Dictionary is")
        log.info("========================================")
        log.info(json.dumps(forwardingSysDict, indent=5))

        print("========================================")
        print("Given data dictionary of LEAF")
        print("========================================")
        print(json.dumps(leaf_dict, indent=6))
        log.info("========================================")
        log.info("Given data dictionary of LEAF")
        log.info("========================================")
        log.info(json.dumps(leaf_dict, indent=6))

        # -----------------------------------------------------
        # Buildup the configurations to be applied
        # If the no.of SPINEs are 2 then configure any cast RP.
        # -----------------------------------------------------
        # if forwardingSysDict['SPINE_COUNT'] is not 1:
        #     leaf1_pim_rp_config += '''
        #         nv overlay evpn
        #         fabric forwarding anycast-gateway-mac 0000.000a.aaaa
        #         ip pim rp-address ''' + str(leaf_dict['SPINE_1_UPLINK_PO']['common_rp']) + ''' group-list 224.0.0.0/4
        #         ip pim ssm range 232.0.0.0/8
        #     '''
        # else:
        #     leaf1_pim_rp_config += '''
        #         nv overlay evpn
        #         fabric forwarding anycast-gateway-mac 0000.000a.aaaa
        #         ip pim rp-address ''' + str(leaf_dict['SPINE_1_UPLINK_PO']['spine_loop0_ip']) + ''' group-list 224.0.0.0/4
        #         ip pim ssm range 232.0.0.0/8
        #     '''

        leaf1_pim_rp_config += '''
                interface loopback0
                  ip address ''' + str(leaf_dict['loop0_ip']) + '''/32
                  ip ospf network point-to-point
                  ip router ospf ''' + str(forwardingSysDict['OSPF_AS']) + ''' area 0.0.0.0
                  ip pim sparse-mode

                interface loopback1
                  ip address ''' + str(leaf_dict['NVE_data']['VTEP_IP']) + '''/32
                  ip ospf network point-to-point
                  ip router ospf ''' + str(forwardingSysDict['OSPF_AS']) + ''' area 0.0.0.0
                  ip pim sparse-mode        
        '''

        # --------------------------------------------
        # Building interface Configuration
        # --------------------------------------------
        leaf1_uplink_configs += '''
                interface port-channel''' + str(leaf_dict['SPINE_1_UPLINK_PO']['po_id']) + '''
                  no switchport
                  ip address ''' + str(leaf_dict['SPINE_1_UPLINK_PO']['leaf_spine_po_v4']) + str(leaf_dict['SPINE_1_UPLINK_PO']['leaf_spine_mask_v4']) + '''
                  ip ospf network point-to-point
                  ip router ospf ''' + str(forwardingSysDict['OSPF_AS']) + ''' area 0.0.0.0
                  ip pim sparse-mode
        '''

        if 'leaf_spine_po_v6' in leaf_dict['SPINE_1_UPLINK_PO'].keys():
            leaf1_uplink_configs += '''          ipv6 address ''' + \
                                    str(leaf_dict['SPINE_1_UPLINK_PO']['leaf_spine_po_v6']) + \
                                    str(leaf_dict['SPINE_1_UPLINK_PO']['leaf_spine_mask_v6']) + '''\n'''

        if forwardingSysDict['SPINE_COUNT'] is not 1:
            leaf1_uplink_configs += '''
                interface port-channel''' + str(leaf_dict['SPINE_2_UPLINK_PO']['po_id']) + '''
                  no switchport
                  ip address ''' + str(leaf_dict['SPINE_2_UPLINK_PO']['leaf_spine_po_v4']) + str(leaf_dict['SPINE_2_UPLINK_PO']['leaf_spine_mask_v4']) + '''
                  ip ospf network point-to-point
                  ip router ospf ''' + str(forwardingSysDict['OSPF_AS']) + ''' area 0.0.0.0
                  ip pim sparse-mode
            '''

            if 'leaf_spine_po_v6' in leaf_dict['SPINE_2_UPLINK_PO'].keys():
                leaf1_uplink_configs += '''      ipv6 address ''' + \
                                        str(leaf_dict['SPINE_2_UPLINK_PO']['leaf_spine_po_v6']) + \
                                        str(leaf_dict['SPINE_2_UPLINK_PO']['leaf_spine_mask_v6']) + '''\n'''

        # --------------------------------------------
        # Building OSPF Configuration
        # --------------------------------------------
        leaf1_ospf_config += '''
                router ospf ''' + str(forwardingSysDict['OSPF_AS']) + '''
                  router-id ''' + str(leaf_dict['loop0_ip']) + '''
        '''

        # --------------------------------------------
        # Building BGP Configuration
        # --------------------------------------------
        leaf1_bgp_config += '''
                route-map ANY permit 10

                router bgp ''' + str(forwardingSysDict['BGP_AS_num']) + '''
                  router-id ''' + str(leaf_dict['loop0_ip']) + '''
                  address-family ipv4 unicast
                  address-family ipv6 unicast
                  template peer ibgp_evpn
                    log-neighbor-changes
                    address-family ipv4 unicast
                      send-community
                      send-community extended
                    address-family ipv6 unicast
                      send-community
                      send-community extended
                    
        '''

        # --------------------------------------------
        # Building BGP Neighbor Configuration
        # --------------------------------------------
        leaf1_bgp_config += '''
                  neighbor ''' + str(leaf_dict['SPINE_1_UPLINK_PO']['spine_leaf_po_v4']) + '''
                    inherit peer ibgp_evpn
                    remote-as ''' + str(forwardingSysDict['BGP_AS_num']) + '''
        '''

        if forwardingSysDict['SPINE_COUNT'] is not 1:
            leaf1_bgp_config += '''
                  neighbor ''' + str(leaf_dict['SPINE_2_UPLINK_PO']['spine_leaf_po_v4']) + '''
                    inherit peer ibgp_evpn
                    remote-as ''' + str(forwardingSysDict['BGP_AS_num']) + '''
            '''

        # # --------------------------------------------
        # # Building BGP Neighbor Configuration
        # # --------------------------------------------
        # leaf1_nve_config += '''
        #         interface nve1
        #           no shutdown
        #           host-reachability protocol bgp
        #           source-interface ''' + str(leaf_dict['NVE_data']['src_loop']) + '''
        # '''

        # ----------------------------------------------------
        # Build Incremental configs for VRF, VNI, L2/L3 VLANs
        # ----------------------------------------------------
        # ----------------------------------------------------
        # LEAF Configuration Parameters
        # ----------------------------------------------------
        leaf_vlan_config = ""
        leaf_vrf_config = ""
        leaf_svi_config = ""
        leaf_nve_config = ""
        leaf_vni_bgp_config = ""
        leaf_tunnel_config = ""

        # ----------------------------------------------------
        # Counter Variables
        # ----------------------------------------------------
        l3_vrf_count_iter = 0
        ip_index = 0
        l2_ipv6s = []

        # ----------------------------------------------------
        # Fetching IP and VNI data from the configuration dict
        # ----------------------------------------------------
        total_ip_count = int(forwardingSysDict['VLAN_PER_VRF_count']) * int(forwardingSysDict['VRF_count'])
        l2_ipv4s = increment_prefix_network(ip.IPv4Interface(str(leaf_dict['VNI_data']['l2_vlan_ipv4_start']) + str(leaf_dict['VNI_data']['l2_vlan_ipv4_mask'])), total_ip_count)
        if 'l2_vlan_ipv6_start' in leaf_dict['VNI_data'].keys():
            l2_ipv6s = increment_prefix_network(ip.IPv6Interface(str(leaf_dict['VNI_data']['l2_vlan_ipv6_start']) + str(leaf_dict['VNI_data']['l2_vlan_ipv6_mask'])), total_ip_count)
        l3_mcast_grp = ip.IPv4Interface(leaf_dict['NVE_data']['l3_mcast_grp_ip']).ip
        l2_mcast_grp = ip.IPv4Interface(leaf_dict['NVE_data']['l2_mcast_grp_ip']).ip

        vrf_id = forwardingSysDict['VRF_id_start']

        l3_vlan_id = leaf_dict['VNI_data']['l3_vlan_start']
        l3_vn_seg_id = leaf_dict['VNI_data']['l3_vni_start']

        l2_vlan_id = leaf_dict['VNI_data']['l2_vlan_start']
        l2_vn_seg_id = leaf_dict['VNI_data']['l2_vni_start']

        # ----------------------------------------------------
        # Outer While Loop for L3 Configurations
        # ----------------------------------------------------
        while l3_vrf_count_iter < forwardingSysDict['VRF_count']:
            # Configure L3 VRF and L3 VNIs
            leaf_vlan_config += '''
                    vlan ''' + str(l3_vlan_id) + '''
                      state active
                      no shut
                      vn-segment ''' + str(l3_vn_seg_id) + '''
            '''

            leaf_vrf_config += '''
                    vrf context ''' + str(forwardingSysDict['VRF_string']) + str(vrf_id) + '''
                      vni ''' + str(l3_vn_seg_id) + '''
                      
            '''

            leaf_svi_config += '''
                    interface Vlan''' + str(l3_vlan_id) + '''
                      no shutdown
                      vrf member ''' + str(forwardingSysDict['VRF_string']) + str(vrf_id) + '''
                      no ip redirects
                      ip forward
                      ipv6 forward
                      no ipv6 redirects
                      ip pim sparse-mode
            '''

            

            

            # ----------------------------------------------------
            # Inner while loop for L2 Configurations
            # ----------------------------------------------------
            l2_vlan_count_iter = 0
            while l2_vlan_count_iter < forwardingSysDict['VLAN_PER_VRF_count']:
                # Configure L2 VNIs
                leaf_vlan_config += '''
                    vlan ''' + str(l2_vlan_id) + '''
                      state active
                      no shut
                '''

                

                if "l2_vlan_ipv4_start" in leaf_dict['VNI_data'].keys():
                    leaf_svi_config += '''
                    interface Vlan''' + str(l2_vlan_id) + '''
                      no shutdown
                      vrf member ''' + str(forwardingSysDict['VRF_string']) + str(vrf_id) + '''
                      no ip redirects
                      ip address ''' + str(l2_ipv4s[ip_index]) + '''
                      no ipv6 redirects
                      '''

                if 'l2_vlan_ipv6_start' in leaf_dict['VNI_data'].keys():
                    leaf_svi_config += '''
                      ipv6 address ''' + str(l2_ipv6s[ip_index]) + '''
                    '''

                # Incrementing L2 VLAN Iteration counters
                l2_vlan_count_iter += 1
                l2_vlan_id += 1
                l2_vn_seg_id += 1
                ip_index += 1

            # Incrementing L3 VRF Iteration counters
            l3_mcast_grp += 256
            l2_mcast_grp += 256
            l3_vrf_count_iter += 1
            l3_vlan_id += 1
            l3_vn_seg_id += 1
            vrf_id += 1

        #-----------------------------------------------------
        #Tunnel configs
        #-----------------------------------------------------
        l3_vrf_count_iter= 0
        vrf_id = forwardingSysDict['VRF_id_start']

        l3_vlan_id = leaf_dict['VNI_data']['l3_vlan_start']
        l3_vn_seg_id = leaf_dict['VNI_data']['l3_vni_start']

        l2_vlan_id = leaf_dict['VNI_data']['l2_vlan_start']
        l2_vn_seg_id = leaf_dict['VNI_data']['l2_vni_start']
        remote_leaf_route=remote_leaf_dict['NVE_data']['network_add_start']
    
        # ----------------------------------------------------
        # Outer While Loop for L3 Configurations
        # ----------------------------------------------------
        while l3_vrf_count_iter < forwardingSysDict['VRF_count']:
            # Configure L3 VRF and L3 VNIs
            leaf_tunnel_config += '''
                    tunnel-profile '''+ str(forwardingSysDict['tunnel_profile']) +'''
                      encapsulation vxlan
                      source-interface ''' + str(leaf_dict['NVE_data']['src_loop']) + '''
                      route vrf ''' + str(forwardingSysDict['VRF_string']) + str(vrf_id) + ''' ''' + str(remote_leaf_route) +str(leaf_dict['NVE_data']['v4_netmask']) + ''' ''' + str(remote_leaf_dict['NVE_data']['VTEP_IP']) + ''' next-hop-vrf default vni ''' + str(l3_vn_seg_id) + ''' dest-vtep-mac ''' + str(remote_leaf_dict['router_mac']) 
            # Incrementing L3 VRF Iteration counters
            remote_leaf_route= ip.ip_address(remote_leaf_route) + leaf_dict['NVE_data']['network_add_incr']
            l3_vrf_count_iter += 1
            l3_vlan_id += 1
            l3_vn_seg_id += 1
            vrf_id += 1              
        # ----------------------------------------------------
        # Perform the configurations
        # ----------------------------------------------------
        print("=========== LEAF1: Performing Base EVPN and VPC Configurations ===========")
        log.info("=========== LEAF1: Performing Base EVPN and VPC Configurations ===========")
        leaf.configure(leaf1_pim_rp_config + leaf1_vpc_config + leaf1_uplink_configs + leaf1_ospf_config + leaf1_bgp_config + leaf1_nve_config)

        print("=========== LEAF1: Performing NVE VLAN Configurations ===========")
        log.info("=========== LEAF1: Performing NVE VLAN Configurations ===========")
        leaf.configure(leaf_vlan_config + leaf_vrf_config + leaf_svi_config + leaf_nve_config + leaf_vni_bgp_config + leaf_tunnel_config)

    # # ====================================================================================================#
    # @staticmethod
    # def configure_scale_EVPNl2l3VRF(leaf, forwardingSysDict, leaf_dict):
    # 
    #     # ----------------------------------------------------
    #     # Build Incremental configs for VRF, VNI, L2/L3 VLANs
    #     # ----------------------------------------------------
    #     # ----------------------------------------------------
    #     # LEAF Configuration Parameters
    #     # ----------------------------------------------------
    #     leaf_vlan_config = ""
    #     leaf_vrf_config = ""
    #     leaf_svi_config = ""
    #     leaf_nve_config = ""
    #     leaf_vni_bgp_config = ""
    # 
    #     # ----------------------------------------------------
    #     # Counter Variables
    #     # ----------------------------------------------------
    #     l3_vrf_count_iter = 0
    #     ip_index = 0
    #     l2_ipv6s = []
    # 
    #     # ----------------------------------------------------
    #     # Fetching IP and VNI data from the configuration dict
    #     # ----------------------------------------------------
    #     total_ip_count = int(forwardingSysDict['VLAN_PER_VRF_count']) * int(forwardingSysDict['VRF_count'])
    #     l2_ipv4s = increment_prefix_network(ip.IPv4Interface(str(leaf_dict['VNI_data']['l2_vlan_ipv4_start']) + str(leaf_dict['VNI_data']['l2_vlan_ipv4_mask'])), total_ip_count)
    #     if 'l2_vlan_ipv6_start' in leaf_dict['VNI_data'].keys():
    #         l2_ipv6s = increment_prefix_network(ip.IPv6Interface(str(leaf_dict['VNI_data']['l2_vlan_ipv6_start']) + str(leaf_dict['VNI_data']['l2_vlan_ipv6_mask'])), total_ip_count)
    #     l3_mcast_grp = ip.IPv4Interface(leaf_dict['NVE_data']['l3_mcast_grp_ip']).ip
    #     l2_mcast_grp = ip.IPv4Interface(leaf_dict['NVE_data']['l2_mcast_grp_ip']).ip
    # 
    #     vrf_id = forwardingSysDict['VRF_id_start']
    # 
    #     l3_vlan_id = leaf_dict['VNI_data']['l3_vlan_start']
    #     l3_vn_seg_id = leaf_dict['VNI_data']['l3_vni_start']
    # 
    #     l2_vlan_id = leaf_dict['VNI_data']['l2_vlan_start']
    #     l2_vn_seg_id = leaf_dict['VNI_data']['l2_vni_start']
    # 
    #     # ----------------------------------------------------
    #     # Outer While Loop for L3 Configurations
    #     # ----------------------------------------------------
    #     while l3_vrf_count_iter < forwardingSysDict['VRF_count']:
    #         # Configure L3 VRF and L3 VNIs
    #         leaf_vlan_config += '''
    #                 vlan ''' + str(l3_vlan_id) + '''
    #                   state active
    #                   no shut
    #                   vn-segment ''' + str(l3_vn_seg_id) + '''
    #         '''
    # 
    #         leaf_vrf_config += '''
    #                 vrf context ''' + str(forwardingSysDict['VRF_string']) + str(vrf_id) + '''
    #                   vni ''' + str(l3_vn_seg_id) + '''
    #                   
    #         '''
    # 
    #         leaf_svi_config += '''
    #                 interface Vlan''' + str(l3_vlan_id) + '''
    #                   no shutdown
    #                   vrf member ''' + str(forwardingSysDict['VRF_string']) + str(vrf_id) + '''
    #                   no ip redirects
    #                   ip forward
    #                   ipv6 forward
    #                   no ipv6 redirects
    #                   ip pim sparse-mode
    #         '''
    # 
    #        
    # 
    #         # ----------------------------------------------------
    #         # Inner while loop for L2 Configurations
    #         # ----------------------------------------------------
    #         l2_vlan_count_iter = 0
    #         while l2_vlan_count_iter < forwardingSysDict['VLAN_PER_VRF_count']:
    #             # Configure L2 VNIs
    #             leaf_vlan_config += '''
    #                 vlan ''' + str(l2_vlan_id) + '''
    #                   state active
    #                   no shut
    #                   vn-segment ''' + str(l2_vn_seg_id) + '''
    #             '''
    # 
    #             
    # 
    #             if "l2_vlan_ipv4_start" in leaf_dict['VNI_data'].keys():
    #                 leaf_svi_config += '''
    #                 interface Vlan''' + str(l2_vlan_id) + '''
    #                   no shutdown
    #                   vrf member ''' + str(forwardingSysDict['VRF_string']) + str(vrf_id) + '''
    #                   no ip redirects
    #                   ip address ''' + str(l2_ipv4s[ip_index]) + '''
    #                   no ipv6 redirects
    #                   fabric forwarding mode anycast-gateway'''
    # 
    #             if 'l2_vlan_ipv6_start' in leaf_dict['VNI_data'].keys():
    #                 leaf_svi_config += '''
    #                   ipv6 address ''' + str(l2_ipv6s[ip_index]) + '''
    #                 '''
    # 
    #             # Incrementing L2 VLAN Iteration counters
    #             l2_vlan_count_iter += 1
    #             l2_vlan_id += 1
    #             l2_vn_seg_id += 1
    #             ip_index += 1
    # 
    #         # Incrementing L3 VRF Iteration counters
    #         l3_mcast_grp += 256
    #         l2_mcast_grp += 256
    #         l3_vrf_count_iter += 1
    #         l3_vlan_id += 1
    #         l3_vn_seg_id += 1
    #         vrf_id += 1
    # 
    #     # ----------------------------------------------------
    #     # Perform the configurations
    #     # ----------------------------------------------------
    #     print("=========== LEAF1: Performing NVE VLAN Configurations ===========")
    #     log.info("=========== LEAF1: Performing NVE VLAN Configurations ===========")
    #     leaf.configure(leaf_vlan_config + leaf_vrf_config + leaf_svi_config + leaf_nve_config + leaf_vni_bgp_config)

# ====================================================================================================#
# Nexus 39K VxLAN EVPN Configuration Verification Methods
# ====================================================================================================#
class verifyEVPNconfiguration:

    # First we create a constructor for this class
    # and add members to it, here models
    def __init__(self):
        pass

    # ====================================================================================================#
    @staticmethod
    def verifyEvpnUpLinkBGPSessions(forwardingSysDict, leavesDict):
        bgpSessionStat          = []
        bgpSessionMsgs          = "\n"

        # ----------------------------------------------------
        # Iterate through each leaf and its dict data
        # ----------------------------------------------------
        for leaf in leavesDict.keys():
            sessionOutput = leaf.execute('show bgp session | i ' + str(leavesDict[leaf]['SPINE_1_UPLINK_PO']['spine_leaf_po_v4']) + ' | i i E')
            if sessionOutput == "":
                bgpSessionStat.append(0)
                bgpSessionMsgs += "BGP Session from SPINE to LEAF_IP : " + str(leavesDict[leaf]['SPINE_1_UPLINK_PO']['spine_leaf_po_v4']) + " has not been established\n"
            elif str(leavesDict[leaf]['SPINE_1_UPLINK_PO']['spine_leaf_po_v4']) in sessionOutput and 'E' in sessionOutput:
                bgpSessionStat.append(1)
                bgpSessionMsgs += "BGP Session from SPINE to LEAF_IP : " + str(leavesDict[leaf]['SPINE_1_UPLINK_PO']['spine_leaf_po_v4']) + " has been established\n"
            else:
                bgpSessionStat.append(0)
                bgpSessionMsgs += "BGP Session from SPINE to LEAF_IP : " + str(leavesDict[leaf]['SPINE_1_UPLINK_PO']['spine_leaf_po_v4']) + " has not been established\n"
            # ------------------------------------------------------
            # If there are 2 SPINEs, check the second SPINE session
            # ------------------------------------------------------
            if forwardingSysDict['SPINE_COUNT'] is 2:
                sessionOutput = leaf.execute('show bgp session | i ' + str(leavesDict[leaf]['SPINE_2_UPLINK_PO']['spine_leaf_po_v4']) + ' | i i E')
                if sessionOutput == "":
                    bgpSessionStat.append(0)
                    bgpSessionMsgs += "BGP Session from SPINE to LEAF_IP : " + str(leavesDict[leaf]['SPINE_2_UPLINK_PO']['spine_leaf_po_v4']) + " has not been established\n"
                elif str(leavesDict[leaf]['SPINE_2_UPLINK_PO']['spine_leaf_po_v4']) in sessionOutput and 'E' in sessionOutput:
                    bgpSessionStat.append(1)
                    bgpSessionMsgs += "BGP Session from SPINE to LEAF_IP : " + str(leavesDict[leaf]['SPINE_2_UPLINK_PO']['spine_leaf_po_v4']) + " has been established\n"
                else:
                    bgpSessionStat.append(0)
                    bgpSessionMsgs += "BGP Session from SPINE to LEAF_IP : " + str(leavesDict[leaf]['SPINE_2_UPLINK_PO']['spine_leaf_po_v4']) + " has not been established\n"

        if 0 in bgpSessionStat:
            return {'result' : 0, 'log' : bgpSessionMsgs}
        else:
            return {'result' : 1, 'log' : bgpSessionMsgs}

    

    # # ====================================================================================================#
    @staticmethod
    def verifyTunnelProfile(forwardingSysDict,leavesDict):
        TunnelStatusFlag=''
        TunnelStatusMsgs='\n'
        for leaf in leavesDict.keys():
            output=leaf.execute('sh tunnel-profile ' +forwardingSysDict['tunnel_profile']+ ' | json-pretty')
            import json
            a=json.loads(output)
            if a['TABLE_tunnel']['ROW_tunnel']['encap-type']!='Vxlan' or a['TABLE_tunnel']['ROW_tunnel']['status']!='1':
                TunnelStatusMsgs='Tunnel profile is not UP on '+str(leaf)+'\n'
                return {'result' : 0, 'log' : TunnelStatusMsgs}
            else:
                TunnelStatusMsgs='Tunnel profile is UP on '+str(leaf)+'\n'
        return {'result' : 1, 'log' : TunnelStatusMsgs}        
    # @staticmethod
    # def verifyEVPNVNIData(forwardingSysDict, leavesDict):
    #     vniStatusMsgs = "\n"
    #     vniStatusFlag = []
    # 
    #     for leaf in leavesDict.keys():
    # 
    #         vniStatusMsgs += "\n\nFor " + str(leaf.alias) + "\n"
    #         vniStatusMsgs += "====================================\n\n"
    # 
    #         # ----------------------------------------------------
    #         # Counter Variables
    #         # ----------------------------------------------------
    #         l3_vrf_count_iter = 0
    #         ip_index = 0
    # 
    #         # ----------------------------------------------------
    #         # Fetching IP and VNI data from the configuration dict
    #         # ----------------------------------------------------
    #         l3_mcast_grp    = ip.IPv4Interface(leavesDict[leaf]['NVE_data']['l3_mcast_grp_ip']).ip
    #         l2_mcast_grp    = ip.IPv4Interface(leavesDict[leaf]['NVE_data']['l2_mcast_grp_ip']).ip
    # 
    #         vrf_id          = forwardingSysDict['VRF_id_start']
    # 
    #         l3_vlan_id      = leavesDict[leaf]['VNI_data']['l3_vlan_start']
    #         l3_vn_seg_id    = leavesDict[leaf]['VNI_data']['l3_vni_start']
    # 
    #         l2_vlan_id      = leavesDict[leaf]['VNI_data']['l2_vlan_start']
    #         l2_vn_seg_id    = leavesDict[leaf]['VNI_data']['l2_vni_start']
    # 
    #         # ----------------------------------------------------
    #         # Outer While Loop for L3 Configurations
    #         # ----------------------------------------------------
    #         while l3_vrf_count_iter < forwardingSysDict['VRF_count']:
    # 
    #             # Get L3 VNI data
    #             vniStatusMsgs += "For VNI --> " + str(l3_vn_seg_id) + "\n"
    #             vniData = leaf.execute("sh nve vni " + str(l3_vn_seg_id) + " | xml | i '<vni>|state>|<type>|<mcast>'")
    # 
    #             # Verify VNI state to be UP
    #             if re.search("<vni-state>Up<", vniData, re.I):
    #                 vniStatusMsgs += "\t PASS : VNI State is UP\n"
    #                 vniStatusFlag.append(1)
    #             else:
    #                 vniStatusMsgs += "\t FAIL : VNI State is not UP\n"
    #                 vniStatusFlag.append(0)
    # 
    #             # Verify VNI type to be L2/L3
    #             if re.search("<type>L3", vniData, re.I):
    #                 vniStatusMsgs += "\t PASS : VNI Type (L3) Match Verified Successfully\n"
    #                 vniStatusFlag.append(1)
    #             else:
    #                 vniStatusMsgs += "\t FAIL : VNI Type (L3) Match Failed\n"
    #                 vniStatusFlag.append(0)
    # 
    #             L3_VRF = str(forwardingSysDict['VRF_string']) + str(vrf_id)
    #             if re.search("\[" + L3_VRF + "\]</type>", vniData, re.I):
    #                 vniStatusMsgs += "\t PASS : L3 VNI VRF Mapping Verified Successfully\n"
    #                 vniStatusFlag.append(1)
    #             else:
    #                 vniStatusMsgs += "\t FAIL : L3 VNI VRF Mapping Failed\n"
    #                 vniStatusFlag.append(0)
    # 
    #             # ----------------------------------------------------
    #             # Inner while loop for L2 Configurations
    #             # ----------------------------------------------------
    #             l2_vlan_count_iter = 0
    #             while l2_vlan_count_iter < forwardingSysDict['VLAN_PER_VRF_count']:
    # 
    #                 # Get L2 VNI data
    #                 vniStatusMsgs += "For VNI --> " + str(l2_vn_seg_id) + "\n"
    #                 vniData = leaf.execute(
    #                     "sh nve vni " + str(l2_vn_seg_id) + " | xml | i '<vni>|state>|<type>|<mcast>'")
    # 
    #                 # Verify VNI state to be UP
    #                 if re.search("<vni-state>Up<", vniData, re.I):
    #                     vniStatusMsgs += "\t PASS : VNI State is UP\n"
    #                     vniStatusFlag.append(1)
    #                 else:
    #                     vniStatusMsgs += "\t FAIL : VNI State is not UP\n"
    #                     vniStatusFlag.append(0)
    # 
    #                 # Verify VNI type to be L2/L3
    #                 if re.search("<type>L2", vniData, re.I):
    #                     vniStatusMsgs += "\t PASS : VNI Type (L2) Match Verified Successfully\n"
    #                     vniStatusFlag.append(1)
    #                 else:
    #                     vniStatusMsgs += "\t FAIL : VNI Type (L2) Match Failed\n"
    #                     vniStatusFlag.append(0)
    # 
    #                 if re.search("\[" + str(l2_vlan_id) + "\]</type>", vniData, re.I):
    #                     vniStatusMsgs += "\t PASS : L2 VNI VLAN Mapping Verified Successfully\n"
    #                     vniStatusFlag.append(1)
    #                 else:
    #                     vniStatusMsgs += "\t FAIL : L2 VNI VLAN Mapping Failed\n"
    #                     vniStatusFlag.append(0)
    # 
    #                 if re.search("<mcast>" + str(l2_mcast_grp) + "<", vniData, re.I):
    #                     vniStatusMsgs += "\t PASS : VNI Mcast IP Match Verified Successfully\n"
    #                     vniStatusFlag.append(1)
    #                 else:
    #                     vniStatusMsgs += "\t FAIL : VNI Mcast IP Match Failed\n"
    #                     vniStatusFlag.append(0)
    # 
    #                 # Incrementing L2 VLAN Iteration counters
    #                 l2_vlan_count_iter += 1
    #                 l2_vlan_id += 1
    #                 l2_vn_seg_id += 1
    #                 ip_index += 1
    # 
    #             # Incrementing L3 VRF Iteration counters
    #             l3_mcast_grp += 256
    #             l2_mcast_grp += 256
    #             l3_vrf_count_iter += 1
    #             l3_vlan_id += 1
    #             l3_vn_seg_id += 1
    #             vrf_id += 1
    # 
    #     if 0 in vniStatusFlag:
    #         return {'result' : 0, 'log' : vniStatusMsgs}
    #     else:
    #         return {'result' : 1, 'log' : vniStatusMsgs}




import ipaddress as ip
mcast_ip = ip.IPv4Address('224.1.1.103')
vni = int('20003')
count = 1
for i in range(113):
    print("""
    interface nve 1
       member vni """ + str(vni) + """
           no mcast-group
           mcast-group """ + str(mcast_ip) + """
    """)
    if count == 8:
        count = 1
        mcast_ip += 1
    vni += 1
    count += 1
