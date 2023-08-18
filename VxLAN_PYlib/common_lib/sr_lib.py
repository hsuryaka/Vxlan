#!/bin/env python
###################################################################
# Author: Manas Kumar Dash (mdash)
# This lib contain various utility library functions 
###################################################################

import re
import time
import logging
import collections
import yaml
import ipaddress
import copy
import os
import parsergen
import pdb
import sys

from ats.log.utils import banner
from ats.async_ import pcall
from ats.easypy import runtime

from common_lib.infra_lib import *
from common_lib.config_lib import *
from common_lib.topology_find_lib import *
from common_lib.utility_lib import *

log = logging.getLogger(__name__)
log.setLevel(logging.DEBUG)
class Class_srvpn_spine_router(Class_common_device):
   def __init__(self, **kwargs):
       Class_common_device.__init__(self, **kwargs)

       self.core_protocol = kwargs['core_protocol']
       self.bfd_enabled = kwargs['bfd_enabled']
       self.start_loop_bk = kwargs['start_loop_bk']
       self.nu_of_loopbacks = kwargs['nu_of_loopbacks']
       self.sr_app_cfg_mode = kwargs['sr_app_cfg_mode']
       self.id = ''
       self.if_sr_domain = 1
       self.connected_leaf_obj_list = []
       self.connected_core_obj_list = []
       self.isis_id = ''
       self.isis_ckt_level = ''
       self.isis_net = ''
       self.isis_int_ckt_level = ''
       self.if_p2p_isis_intf = ''
       self.ospf_id = 10
       self.ospf_area = 0
       self.loop_bk_start_ip = ''
       self.leaf_l3_intf_info_dict = {}
       self.leaf_l2_intf_info_dict = {}
       self.core_l3_intf_info_dict = {}
       self.srgb = ""
       self.label_index = ''
       self.loopbk_label_index_dict = {}
       self.bgp_conf_str = ''
       self.mpls_conf_str = ''

   def get_next_core(self):
       i = 0
       while True:
         i += 1
         for core_obj in self.connected_core_obj_list:
            local_ip = str(self.id) + '.' + str(core_obj.id) + '.' + str(i) + '.1'
            remote_ip = str(self.id) + '.' + str(core_obj.id) + '.' + str(i) + '.2'
            yield (core_obj, local_ip, remote_ip)

   def fill_interface_details (self):
       # Leaf side details will be updated by Leaf objects
       # Core side updates wil be done here along with Core to Spine updates
       # Core 1 Update

       if not self.connected_core_obj_list:
          return 1
       core_iter = self.get_next_core()
       for c_obj in self.connected_core_obj_list:  
          core_obj, local_ip, remote_ip = next(core_iter)
          self_2_remote_dict = self.topo_dict['devices'][self.topo_name]['peer_device'][core_obj.topo_name]
          remote_2_self_dict = self.topo_dict['devices'][core_obj.topo_name]['peer_device'][self.topo_name]
          local_int = self_2_remote_dict['links']['link_1']['physical_interface']
          remote_int = remote_2_self_dict['links']['link_1']['physical_interface']
          update_l3_intf_info (local_l3_intf_dict = self.l3_intf_info_dict, remote_obj = core_obj,\
                                 local_specific_l3_intf_dict = self.core_l3_intf_info_dict,\
                                 remote_l3_intf_dict = core_obj.l3_intf_info_dict,\
                                 remote_specific_l3_intf_dict = core_obj.spine_l3_intf_info_dict,\
                                 local_int = local_int, remote_int = remote_int, local_ip = local_ip,\
                                 remote_ip = remote_ip, mpls_fwd = self.if_sr_domain, local_obj = self)

       return 1

   def create_config_string (self, sr_new_template = 1, mtu = 1500):
       configure_l2_interface (self, mtu = mtu)
       configure_l3_interface (self, sr_domain = self.if_sr_domain, mtu = mtu)
       conf_str = ''
       if self.if_sr_domain:
          conf_str = configure_sr_mpls(sr_new_template = sr_new_template, start_label_index = self.label_index, srgb = self.srgb,\
                         loop_bk_start_ip = self.loop_bk_start_ip, sr_app_cfg_mode = self.sr_app_cfg_mode,
                         nu_of_loopbacks = self.nu_of_loopbacks, loopbk_label_index_dict = self.loopbk_label_index_dict)  
       self.mpls_conf_str += conf_str 
       if self.core_protocol == 'bgp':
          #configure BGP
          self.bgp_conf_str = "router bgp " + str(self.as_nu) + '\n'
          self.bgp_conf_str += 'bestpath as-path multipath-relax\n'
          self.bgp_conf_str += 'address-family ipv4 unicast\n'
          loopbk_ip = self.loop_bk_start_ip
          loop_bk_ip_with_mask = loopbk_ip + '/32'
          label_indx_str = 'label_index_pol_loopbk_1'
          if self.sr_app_cfg_mode:
             self.bgp_conf_str += 'network ' + loop_bk_ip_with_mask + '\n'
             self.bgp_conf_str += 'allocate-label all\n'
          else:
             self.bgp_conf_str += 'network ' + loop_bk_ip_with_mask + ' route-map ' + label_indx_str + '\n'
             self.bgp_conf_str += 'allocate-label route-map rmap_need_label\n'
          self.bgp_conf_str += 'maximum-paths 32\n'
          self.bgp_conf_str += 'maximum-paths ibgp 32\n'
          self.bgp_conf_str += 'address-family ipv6 unicast\n'
          self.bgp_conf_str += 'address-family ipv4 labeled-unicast\n'
          # Create bgp session to Leaf Rtr
          for leaf_obj in self.connected_leaf_obj_list:
             for intf in leaf_obj.spine_l3_intf_info_dict.keys():
                leaf_ip = leaf_obj.spine_l3_intf_info_dict[intf]['v4_add']
                leaf_as = leaf_obj.as_nu
                for intf1 in self.leaf_l3_intf_info_dict.keys():
                   if self.leaf_l3_intf_info_dict[intf1]['peer_v4_add'] == leaf_ip:
                      rr_yes = 0
                      nhopself = 0
                      if self.as_nu == leaf_as:
                         rr_yes = 1
                         nhopself = 1
                      self.bgp_conf_str += create_bgp_nbr_conf_string (nbr_address = leaf_ip, nbr_as = leaf_as,\
                                       nbr_as_rr_client = rr_yes, if_next_hop_self_all = nhopself,\
                                       nbr_afi_list = ['ipv4_labeled_unicast'], disable_peer_as_check = 1,\
                                       update_src_int = intf1, enable_bfd = self.bfd_enabled, allowas_in = 0)
                      break
          self.run_conf_str += 'ip tcp path-mtu-discovery\n' 

class Class_core_router(Class_common_device):
   def __init__(self, **kwargs):
       Class_common_device.__init__(self, **kwargs)

       self.core_protocol = kwargs['core_protocol']
       self.bfd_enabled = kwargs['bfd_enabled']
       self.start_loop_bk = kwargs['start_loop_bk']
       self.nu_of_loopbacks = kwargs['nu_of_loopbacks']
       self.sr_app_cfg_mode = kwargs['sr_app_cfg_mode']
       self.id = ''
       self.if_sr_domain = 1
       self.connected_spine_obj_list = []
       self.spine_l3_intf_info_dict = {}
       self.spine_l2_intf_info_dict = {}
       self.isis_id = ""
       self.isis_ckt_level = ""
       self.isis_net = ""
       self.isis_int_ckt_level = ''
       self.if_p2p_isis_intf = ''
       self.ospf_id = ''
       self.ospf_area = ''
       self.loop_bk_start_ip = ''
       self.spine_intf_type_list = []
       self.srgb = ""
       self.label_index = ''
       self.bgp_conf_str = ''
       self.mpls_conf_str = ''
       self.loopbk_label_index_dict = {}
   def create_config_string (self, sr_new_template = 1, mtu = 1500, out_rmap_list = ''):
       configure_l2_interface (self, mtu = mtu)
       configure_l3_interface (self, sr_domain = self.if_sr_domain, mtu = mtu)
       conf_str = ''
       if self.if_sr_domain:
          conf_str = configure_sr_mpls(sr_new_template = sr_new_template, start_label_index = self.label_index, srgb = self.srgb,\
                         loop_bk_start_ip = self.loop_bk_start_ip, sr_app_cfg_mode = self.sr_app_cfg_mode,
                         nu_of_loopbacks = self.nu_of_loopbacks, loopbk_label_index_dict = self.loopbk_label_index_dict)  
       self.mpls_conf_str += conf_str 
       #BGP Config to be implemented

class Class_srvpn_leaf_router(Class_common_device):
   def __init__(self, **kwargs):
       Class_common_device.__init__(self, **kwargs)

       self.core_protocol = kwargs['core_protocol']
       self.nu_of_ecmp_to_core = kwargs['nu_of_ecmp_to_core']
       self.bfd_enabled = kwargs['bfd_enabled']
       self.start_loop_bk = kwargs['start_loop_bk']
       self.nu_of_loopbacks = kwargs['nu_of_loopbacks']
       self.sr_app_cfg_mode = kwargs['sr_app_cfg_mode']
       self.vpn_type = kwargs['vpn_type']
       self.nu_of_vrfs = kwargs['nu_of_vrfs']
       self.start_vrf = kwargs['start_vrf']
       self.id = ''
       self.if_sr_domain = 1
       self.spine_svi_vlan_to_use = 0
       self.connected_spine_obj_list = []
       self.spine_l3_intf_info_dict = {}
       self.spine_l2_intf_info_dict = {}
       self.isis_id = ""
       self.isis_ckt_level = ""
       self.isis_net = ""
       self.isis_int_ckt_level = ''
       self.if_p2p_isis_intf = ''
       self.ospf_id = ''
       self.ospf_area = ''
       self.loop_bk_start_ip = ''
       self.spine_intf_type_list = []
       self.srgb = ""
       self.label_index = ''
       self.loopbk_label_index_dict = {}
       self.bgp_conf_str = ''
       self.mpls_conf_str = ''
       self.remote_pe_obj_list = []
       self.if_srte_peer = 0
       self.srte_peer_leaf_obj = ''
       self.core_subintf = 0
       self.if_dci_pe = 0
       self.l3vpn_pe_obj_list = []
       self.l3evpn_pe_obj_list = []
       self.vpc_peer_obj = ''
       self.vpc_unique_id = ''
       self.auto_rt_config = 0

   def get_next_spine(self):
       i = 0
       while True:
         i += 1
         for spine_obj in self.connected_spine_obj_list:
            local_ip = str(self.id) + '.' + str(spine_obj.id) + '.' + str(i) + '.1'
            remote_ip = str(self.id) + '.' + str(spine_obj.id) + '.' + str(i) + '.2'
            yield (spine_obj, local_ip, remote_ip)    

   def fill_interface_details (self, intf_type_list = [], nu_of_ecmp_to_core = 0):
       # Spine side updates wil be done here along with Spine to Leaf updates
       # Assumption between two nodes only one PO is allowed and SVI should be at end
       spine_iter = self.get_next_spine()
       nu_of_intf_configured = 0
       if not intf_type_list:
          intf_type_list = self.spine_intf_type_list
       if not nu_of_ecmp_to_core:
          nu_of_ecmp_to_core = self.nu_of_ecmp_to_core
       for intf_type in intf_type_list:
          spine_obj, local_ip, remote_ip = next(spine_iter)
          if not fill_l3_interface_details(self, spine_obj, local_ip, remote_ip, intf_type, nu_of_intf_configured, \
                                          nu_of_ecmp_to_core):
             return 0
          if intf_type == 'svi':
             break
          nu_of_intf_configured += 1
          if nu_of_intf_configured == self.nu_of_ecmp_to_core:
             break
       return 1

   def create_config_string (self, vpn_config = 1, sr_new_template = 1, mtu = 1500, out_rmap_list = ''):
       configure_l2_interface (self, mtu = mtu)
       configure_l3_interface (self, mtu = mtu)
       conf_str = ''
       if self.if_sr_domain:
          conf_str = configure_sr_mpls(sr_new_template = sr_new_template, start_label_index = self.label_index, srgb = self.srgb,\
                         loop_bk_start_ip = self.loop_bk_start_ip, sr_app_cfg_mode = self.sr_app_cfg_mode,
                         nu_of_loopbacks = self.nu_of_loopbacks, loopbk_label_index_dict = self.loopbk_label_index_dict)  
       self.mpls_conf_str += conf_str 
       if vpn_config:
          #Create VRF Config
          vrf_nu = self.start_vrf
          vrf_str = 'VRF_'
          i = 1
          vrf_nu = int(vrf_nu)
          if self.vpc_peer_obj:
             rt_first = self.vpc_unique_id
          else:
             rt_first = self.id
          #rt_first_remote = self.remote_pe_obj.id
          while i <= self.nu_of_vrfs:
             vrf_name = str(vrf_str)+str(vrf_nu)
             rt_export = str(rt_first) + ':' + str(vrf_nu)
             rt_export_list = [rt_export]
             rt_import_list = []
           
             if self.if_dci_pe:
                rt_import_list = []
                temp_vpn_type = self.vpn_type
                self.vpn_type = 'l3vpn'
                peer_obj_list = self.l3vpn_pe_obj_list
                for remote_pe in peer_obj_list:
                   rt_first_remote = remote_pe.id
                   rt_import = str(rt_first_remote) + ':' + str(vrf_nu)
                   rt_import_list.append(rt_import)
                self.mpls_conf_str += create_vpn_vrf_config_string (vrf_name = vrf_name, rt_import_list = rt_import_list, \
                                           vpn_type = self.vpn_type, rt_export_list = rt_export_list, afi_v4 = 1, afi_v6 = 1)
                rt_import_list = []
                self.vpn_type = 'l3evpn'
                peer_obj_list = self.l3evpn_pe_obj_list
                for remote_pe in peer_obj_list:
                   rt_first_remote = remote_pe.id
                   rt_import = str(rt_first_remote) + ':' + str(vrf_nu)
                   rt_import_list.append(rt_import)
                self.mpls_conf_str += create_vpn_vrf_config_string (vrf_name = vrf_name, rt_import_list = rt_import_list, \
                                           vpn_type = self.vpn_type, rt_export_list = rt_export_list, afi_v4 = 1, afi_v6 = 1)
                self.vpn_type = temp_vpn_type
             else:
                if self.if_srte_peer:
                   peer_obj_list = [self.srte_peer_leaf_obj]
                else:
                   peer_obj_list = self.remote_pe_obj_list
                evi_val = ''
                for remote_pe in peer_obj_list:
                   rt_first_remote = remote_pe.id
                   if remote_pe.vpc_peer_obj:
                      rt_first_remote = remote_pe.vpc_unique_id
                   rt_import = str(rt_first_remote) + ':' + str(vrf_nu)
                   rt_import_list.append(rt_import)
                   if re.search('l2evpn', self.vpn_type):
                      evi_val = vrf_nu
                      if self.auto_rt_config:
                         rt_import_list = []
                         rt_export_list = []
                self.mpls_conf_str += create_vpn_vrf_config_string (vrf_name = vrf_name, rt_import_list = rt_import_list, \
                                        evi_val = evi_val, vpn_type = self.vpn_type, rt_export_list = rt_export_list, \
                                        afi_v4 = 1, afi_v6 = 1)
             i += 1
             vrf_nu += 1 
       #configure BGP
       self.bgp_conf_str = "router bgp " + str(self.as_nu) + '\n'
       self.bgp_conf_str += 'bestpath as-path multipath-relax\n'
       self.bgp_conf_str += 'address-family ipv4 unicast\n'
       self.bgp_conf_str += 'maximum-paths 32\n'
       self.bgp_conf_str += 'maximum-paths ibgp 32\n'
       self.bgp_conf_str += 'address-family ipv6 unicast\n'
       self.bgp_conf_str += 'maximum-paths 32\n'
       self.bgp_conf_str += 'maximum-paths ibgp 32\n'
       if self.vpn_type == 'l2evpn':
          self.bgp_conf_str += 'address-family l2vpn evpn\n'
          self.bgp_conf_str += 'maximum-paths 32\n'
          self.bgp_conf_str += 'maximum-paths ibgp 32\n'
       
       #self.bgp_conf_str += "router bgp " + str(self.as_nu) + '\n'
       if vpn_config:
          if self.vpn_type == 'l3vpn':
             for remote_pe in self.remote_pe_obj_list:
                remote_as = remote_pe.as_nu
                if self.as_nu != remote_as:
                   self.bgp_conf_str += 'address-family vpnv4 unicast\n'
                   self.bgp_conf_str += 'no allocate-label option-b\n'
                   self.bgp_conf_str += 'address-family vpnv6 unicast\n'
                   self.bgp_conf_str += 'no allocate-label option-b\n'
                   break
       i = 1
       loopbk_ip = self.loop_bk_start_ip
       self.run_conf_str += 'ip tcp path-mtu-discovery\n' 
       if self.core_protocol == 'bgp':
          self.bgp_conf_str += 'address-family ipv4 unicast\n'
          while i <= self.nu_of_loopbacks:
             loop_bk_ip_with_mask = loopbk_ip + '/32'
             label_indx_str = 'label_index_pol_loopbk_' + str(i)
             if self.sr_app_cfg_mode:
                   self.bgp_conf_str += 'network ' + loop_bk_ip_with_mask + '\n'
             else:
                self.bgp_conf_str += 'network ' + loop_bk_ip_with_mask + ' route-map ' + label_indx_str + '\n'
             loopbk_ip = get_next_host_ip(loopbk_ip)
             i += 1
          if self.sr_app_cfg_mode:
             self.bgp_conf_str += 'allocate-label all\n'
          else:
             self.bgp_conf_str += 'allocate-label route-map rmap_need_label\n'
          self.bgp_conf_str += 'address-family ipv4 labeled-unicast\n'
          # Create bgp session to Spine Rtr
          for spine_obj in self.connected_spine_obj_list:
             for intf in spine_obj.leaf_l3_intf_info_dict.keys():
                spine_ip = spine_obj.leaf_l3_intf_info_dict[intf]['v4_add']
                spine_as = spine_obj.as_nu
                for intf1 in self.spine_l3_intf_info_dict.keys():
                   if self.spine_l3_intf_info_dict[intf1]['peer_v4_add'] == spine_ip:
                      self.bgp_conf_str += create_bgp_nbr_conf_string (nbr_address = spine_ip, nbr_as = spine_as,\
                                     nbr_afi_list = ['ipv4_labeled_unicast'], update_src_int = intf1,\
                                     enable_bfd = self.bfd_enabled, allowas_in = 1, disable_peer_as_check = 0)
                      break
       if vpn_config:
          if self.if_dci_pe:
             loop_bk = self.start_loop_bk
             match = re.search(r'(\d+)', loop_bk)
             loop_nu = int(match.group(1))
             loop_bk_nu = loop_nu
             for remote_pe in self.l3vpn_pe_obj_list:
                i = 1
                remote_loopbk_ip = remote_pe.loop_bk_start_ip
                remote_as = remote_pe.as_nu
                ebgp_multihop = ''
                if self.as_nu != remote_as:
                   ebgp_multihop = 8
                while i <= self.nu_of_evpns:
                   loop_src = 'loopback' + str(loop_bk_nu)
                   if out_rmap_list:
                      out_rmap = out_rmap_list[i-1]
                   else:
                      out_rmap = 'filter_community_' + str(i)
                   self.bgp_conf_str += create_bgp_nbr_conf_string (nbr_address = remote_loopbk_ip, nbr_as = remote_as,\
                                        nbr_afi_list = ['l3vpn-v4', 'l3vpn-v6'], update_src_int = loop_src,\
                                        out_rmap = out_rmap, ebgp_multihop = ebgp_multihop, dci_reoriginate = self.if_dci_pe)
                   remote_loopbk_ip = get_next_host_ip(remote_loopbk_ip)
                   i += 1
                   loop_bk_nu += 1
             loop_bk_nu = loop_nu
             for remote_pe in self.l3evpn_pe_obj_list:
                i = 1
                remote_loopbk_ip = remote_pe.loop_bk_start_ip
                remote_as = remote_pe.as_nu
                ebgp_multihop = ''
                if self.as_nu != remote_as:
                   ebgp_multihop = 8
                while i <= self.nu_of_evpns:
                   loop_src = 'loopback' + str(loop_bk_nu)
                   if out_rmap_list:
                      out_rmap = out_rmap_list[i-1]
                   else:
                      out_rmap = 'filter_community_' + str(i)
                   self.bgp_conf_str += create_bgp_nbr_conf_string (nbr_address = remote_loopbk_ip, nbr_as = remote_as,\
                                        nbr_afi_list = ['l3evpn'], update_src_int = loop_src,\
                                        out_rmap = out_rmap, ebgp_multihop = ebgp_multihop, dci_reoriginate = self.if_dci_pe)
                   remote_loopbk_ip = get_next_host_ip(remote_loopbk_ip)
                   i += 1
                   loop_bk_nu += 1
          else:
             if self.vpn_type == 'l2evpn':
                pe_obj_list = self.connected_spine_obj_list 
             else:
                pe_obj_list = self.remote_pe_obj_list
             for remote_pe in pe_obj_list:
                i = 1
                remote_loopbk_ip = remote_pe.loop_bk_start_ip
                remote_as = remote_pe.as_nu
                loop_bk = self.start_loop_bk
                match = re.search(r'(\d+)', loop_bk)
                loop_bk_nu = int(match.group(1))
                ebgp_multihop = ''
                if self.as_nu != remote_as:
                   ebgp_multihop = 8
                while i <= self.nu_of_evpns:
                   loop_src = 'loopback' + str(loop_bk_nu)
                   if out_rmap_list:
                      out_rmap = out_rmap_list[i-1]
                   else:
                      out_rmap = 'filter_community_' + str(i)
                   if self.vpn_type == 'l2evpn':
                      out_rmap = ''
                      self.bgp_conf_str += create_bgp_nbr_conf_string (nbr_address = remote_loopbk_ip, nbr_as = remote_as, \
                                       nbr_afi_list = ['l3evpn'], update_src_int = loop_src, allowas_in = 1,\
                                       l2vpn_encap = 'mpls', out_rmap = out_rmap, ebgp_multihop = ebgp_multihop)
                   if self.vpn_type == 'l3evpn':
                      self.bgp_conf_str += create_bgp_nbr_conf_string (nbr_address = remote_loopbk_ip, nbr_as = remote_as, \
                                       nbr_afi_list = ['l3evpn'], update_src_int = loop_src, dci_reoriginate = self.if_dci_pe,\
                                       l2vpn_encap = 'mpls', out_rmap = out_rmap, ebgp_multihop = ebgp_multihop)
                   if self.vpn_type == 'l3vpn':
                      self.bgp_conf_str += create_bgp_nbr_conf_string (nbr_address = remote_loopbk_ip, nbr_as = remote_as, \
                                       nbr_afi_list = ['l3vpn-v4', 'l3vpn-v6'], update_src_int = loop_src,\
                                       out_rmap = out_rmap, ebgp_multihop = ebgp_multihop, dci_reoriginate = self.if_dci_pe)
                   remote_loopbk_ip = get_next_host_ip(remote_loopbk_ip)
                   i += 1
                   loop_bk_nu += 1
   def check_underlay_labels (self):
      remote_pe_obj = self.remote_pe_obj_list[0]
      if self.core_protocol == 'bgp':
         pfx_dict = get_bgp_lu_labels_dict(self.pyats_dev_obj)
      else:
         pfx_dict = get_mpls_labels_dict(self.pyats_dev_obj)
      nu_of_ecmp_to_core = self.nu_of_ecmp_to_core
      nbr_ip = remote_pe_obj.loop_bk_start_ip
      nu_of_evpns = self.nu_of_evpns
      remote_pe_loop_ip = remote_pe_obj.loop_bk_start_ip
      i = 1
      # Check All remote PE Prefixes and corresponding next hops
      while i <= nu_of_evpns:
         pfx_ip = remote_pe_loop_ip + '/32'
         if pfx_ip in pfx_dict.keys():
            for spine_obj in self.connected_spine_obj_list:
               for intf in self.spine_l3_intf_info_dict.keys():
                  spine_ip = self.spine_l3_intf_info_dict[intf]['peer_v4_add']
                  if check_if_its_a_spine_ip(self, spine_ip):
                     if spine_ip in pfx_dict[pfx_ip]['nexthop'].keys():
                        base_srgb = re.split(r'\s+', spine_obj.srgb)[0]
                        rem_loop = re.split(r'/', remote_pe_loop_ip)[0]
                        label_indx = remote_pe_obj.loopbk_label_index_dict[rem_loop]
                        final_label = int(base_srgb) + int(label_indx)
                        found_label = str(pfx_dict[pfx_ip]['nexthop'][spine_ip]['outlabel'])
                        log.info('Verifying Prefix  %r and Nexthop %r', remote_pe_loop_ip, spine_ip)
                        if str(final_label) != str(found_label):
                           log.info('For PFX %r out label expected is %r, Got %r', remote_pe_loop_ip, final_label, found_label)
                           return 0
                     else:
                        log.info('For PFX %r next hop %r is not found', remote_pe_loop_ip, spine_ip)
         else:
            log.info('Prefix %r is not listed underlay prefix', remote_pe_loop_ip)
            log.info('Prefix dict is %r', pfx_dict)
            return 0
         i += 1
         remote_pe_loop_ip = get_next_host_ip(remote_pe_loop_ip)
      # Check All Spine Prefixes and corresponding next hops
      for spine_obj in self.connected_spine_obj_list:
          for spine_loop_ip in spine_obj.loopbk_label_index_dict.keys():
              pfx_ip = spine_loop_ip + '/32'
              if pfx_ip in pfx_dict.keys():
                 nh_list_to_spine = []
                 spine_ip_list = []
                 for intf in self.spine_l3_intf_info_dict.keys():
                    spine_ip_list.append(self.spine_l3_intf_info_dict[intf]['peer_v4_add'])
                 for intf in spine_obj.leaf_l3_intf_info_dict.keys():
                    spine_ip = spine_obj.leaf_l3_intf_info_dict[intf]['v4_add']
                    if spine_ip in spine_ip_list:
                       nh_list_to_spine.append(spine_obj.leaf_l3_intf_info_dict[intf]['v4_add'])
                 for spine_ip in nh_list_to_spine:
                    if spine_ip in pfx_dict[pfx_ip]['nexthop'].keys():
                       out_lbl = pfx_dict[pfx_ip]['nexthop'][spine_ip]['outlabel']
                       log.info('Verifying Prefix  %r and Nexthop %r', pfx_ip, spine_ip)
                       if not re.search('Pop Label|3', out_lbl):
                          log.info('For PFX %r out label expected is \'Pop Label or 3\', Got %r', pfx_ip, out_lbl)
                          return 0
                    else:
                       log.info('For PFX %r next hop %r is not found', spine_loop_ip, spine_ip)
                       return 0
              else:
                 log.info('Prefix %r is not listed underlay prefix', spine_loop_ip)
                 log.info('Prefix dict is %r', pfx_dict)
                 return 0
      return 1

   def check_all_underlay_sessions_up (self, vrf_name = 'default'):
       #keep_sessions_active(self)
       if not self.check_all_po_members_are_up():
          return 0
       if self.core_protocol == 'bgp':
          nbr_dict = get_bgp_nbr_session_status(self.pyats_dev_obj)
          bgp_nbr_list = []
          for intf1 in self.spine_l3_intf_info_dict.keys():
              bgp_nbr_list.append(self.spine_l3_intf_info_dict[intf1]['peer_v4_add'])
          pass_flag = 1
          if len(nbr_dict.keys()) > 0:
            for nbr_ip in bgp_nbr_list:
               if nbr_ip in nbr_dict.keys():
                  if not nbr_dict[nbr_ip]:
                     log.info('NBR %r is not in Established state ...', nbr_ip)
                     pass_flag = 0
            if not pass_flag:
               return 0
          else:
            log.info('No BGP NBR is Listed in show bgp session...')
            return 0
       if self.core_protocol == 'ospf':
          #MANAS USE check_all_underlay_sessions_up to check ADJSID
          found = 1
          for intf in self.spine_l3_intf_info_dict.keys():
             nbr_dict = get_ospf_nbr_status (self.pyats_dev_obj, intf_name = intf)
             if len(nbr_dict.keys()) > 0:
                if 'status' in nbr_dict.keys():
                   if not re.search('FULL', nbr_dict['status'], re.IGNORECASE):
                      log.info('OSPF neighbor is not UP on interface %r', intf)
                      return 0
             else:
                log.info('OSPF neighbor is not UP on interface %r', intf)
                return 0
          sid_db = get_ospf_segment_routing_sid(self.pyats_dev_obj)
          i = 1
          loop_ip = self.remote_pe_obj_list[0].loop_bk_start_ip
          label = self.remote_pe_obj_list[0].label_index
          while i <= self.nu_of_evpns:
             prfx_ip = loop_ip + '/32'
             loop_ip = get_next_host_ip(loop_ip)
             i += 1
             if prfx_ip in sid_db.keys():
                 if sid_db[prfx_ip] != str(label):
                    log.info('For remote loopback Prefix %r, SID %r %r is not correct', prfx_ip, label)
                    return 0
             else:
                 log.info('remote loopback Prefix %r is not there', prfx_ip)
                 return 0
             label += 1
       if self.core_protocol == 'isis':
          #MANAS USE check_all_underlay_sessions_up to check ADJSID
          found = 1
          self.pyats_dev_obj.execute('show isis adjacency')
          for intf in self.spine_l3_intf_info_dict.keys():
             adj_dict = get_isis_adjacency_status (self.pyats_dev_obj, intf_name = intf)
             if len(adj_dict.keys()) > 0:
                if 'status' in adj_dict.keys():
                   if not re.search('up', adj_dict['status'], re.IGNORECASE):
                      log.info('ISIS Adjacency is not UP on interface %r', intf)
                      return 0
                if not 'v4_adj_sid' in adj_dict.keys():
                   log.info('ISIS Adjacency SID is not there for interface %r', intf)
                   return 0
             else:
                log.info('ISIS Adjacency is not there on interface %r', intf)
                return 0
          adj_sid = get_isis_segment_routing_sid(self.pyats_dev_obj)
          i = 1
          loop_ip = self.remote_pe_obj_list[0].loop_bk_start_ip
          label = self.remote_pe_obj_list[0].label_index
          while i <= self.nu_of_evpns:
             prfx_ip = loop_ip + '/32'
             loop_ip = get_next_host_ip(loop_ip)
             i += 1
             if prfx_ip in adj_sid.keys():
                 if adj_sid[prfx_ip] != str(label):
                    log.info('For remote loopback Prefix %r, SID %r %r is not correct', prfx_ip, label)
                    return 0
             else:
                 log.info('remote loopback Prefix %r is not there', prfx_ip)
                 return 0
             label += 1
       return 1

   def test_bfd_nbrs_up (self):
       nbr_list = []
       for intf in self.spine_l3_intf_info_dict.keys():
          nbr_list.append(self.l3_intf_info_dict[intf]['peer_v4_add'])
       if not check_bfd_neighbors(self.pyats_dev_obj, nbr_list):
          return 0
       return 1

   def check_all_bgp_sessions_up (self, vrf_name = 'default'):
       nbr_dict = get_bgp_nbr_session_status(self.pyats_dev_obj)
       bgp_nbr_list = []
       if (self.core_protocol == 'bgp') & (vrf_name == 'default'):
          bgp_nbr_list = [self.spine_l3_intf_info_dict[intf]['peer_v4_add'] for intf in self.spine_l3_intf_info_dict.keys()]
   
       loop_ip = self.remote_pe_obj_list[0].loop_bk_start_ip
       i = 1
       while i <= self.nu_of_evpns:
          bgp_nbr_list.append(loop_ip)
          loop_ip = get_next_host_ip(loop_ip)
          i += 1
       pass_flag = 1
       if len(nbr_dict.keys()) > 0:
         for nbr_ip in bgp_nbr_list:
            if nbr_ip in nbr_dict.keys():
               if not nbr_dict[nbr_ip]:
                  log.info('NBR %r is not in Established state ...', nbr_ip)
                  pass_flag = 0
            else:
               log.info('NBR %r is not found as BGP nbr', nbr_ip)
               pass_flag = 0
       else:
          log.info('No BGP NBR is Listed in show bgp session...')
          pass_flag = 0
       if not vrf_name == 'default':
          i = 1
          while i <= 3:
             nbr_dict = get_bgp_nbr_session_status(self.pyats_dev_obj, vrf_name)
             if len(nbr_dict.keys()) > 0:
                for key in nbr_dict.keys():
                   if not nbr_dict[key]:
                      log.info('Neighbor %r is not in established state', key)
                      break
                else:
                   break
             time.sleep(60)
             i += 1
             log.info ('Checking again for neighbors UP...')
          else:
             pass_flag = 0
       return pass_flag

   def check_all_po_members_are_up (self):
       if self.nu_of_ecmp_to_core > 1:
          for intf in self.spine_l3_intf_info_dict.keys():
             if re.search ('port', intf, re.I):
                match = re.search(r'(\d+)', intf)
                po_nu = match.group(1)
                links_list, po_intf_list = get_po_links_list_from_topology (self.topo_dict, self.topo_name, '', intf)
                if check_all_ports_up_in_po (self.pyats_dev_obj, po_nu, po_intf_list):
                   log.info('All ports in PO to core are not Up in %r', self.topo_name)
                   return 0
       return 1

   def compare_vpn_lbl_stats_between_intervals (self, module_num, interval):
       i = 1
       stats_dict = {}
       while i <= self.nu_of_vrfs:
          vrf_name = 'VRF_' + str(self.start_vrf + i - 1)
          stats_dict[vrf_name] = {}
          #label_dict = cfg_lib.get_local_vrf_label(self.remote_pe_obj_list[0].pyats_dev_obj, vrf_name)
          label_dict = get_local_vrf_label(self.pyats_dev_obj, vrf_name)
          if label_dict['v4']:
             stats_dict[vrf_name]['v4_stats']= get_vpn_label_stats(self.pyats_dev_obj, label_dict['v4'], module_num)
             stats_dict[vrf_name]['v4_label'] = label_dict['v4']
          if label_dict['v6']:
             stats_dict[vrf_name]['v6_stats']= get_vpn_label_stats(self.pyats_dev_obj, label_dict['v6'], module_num)
             stats_dict[vrf_name]['v6_label'] = label_dict['v6']
          i += 1
       log.info('*********************************************')
       log.info('Sleeping for %r Seconds for stats to increase', interval)
       log.info('*********************************************')
       time.sleep(interval)
       i = 1
       fail_flag = 1
       for key in stats_dict.keys():
          label = stats_dict[key]['v4_label']
          stats_after = get_vpn_label_stats(self.pyats_dev_obj, label, module_num)
          stats_before = stats_dict[key]['v4_stats']
          if not int(stats_after) > int(stats_before):
             log.info('Stats not increasing for V4 traffic for VRF %r', key)
             log.info('Stats before = %r, stats after = %r', stats_before, stats_after)
             fail_flag = 0
          label = stats_dict[key]['v6_label']
          stats_after = get_vpn_label_stats(self.pyats_dev_obj, label, module_num)
          stats_before = stats_dict[key]['v6_stats']
          if not int(stats_after) > int(stats_before):
             log.info('Stats not increasing for V6 traffic for VRF %r', key)
             log.info('Stats before = %r, stats after = %r', stats_before, stats_after)
             fail_flag = 0
       return fail_flag

   def process_restart (pe_obj, process_name):
       log.info('Restarting process %r', process_name)
       if not restart_process(pe_obj.pyats_dev_obj, process_name):
          return 0
       return 1

   def trigger_command (self, trigger_command):
      # SR shut no shut
      if re.search(r'SR_shut_noshut', trigger_command, re.I):
         op = self.pyats_dev_obj.execute('show run | sec ^segment-routing')
         if re.search('segment-routing mpls', op):
            cmd = 'segment-routing mpls\n'
            cmd += 'shut\n'
            no_cmd = cmd + 'no shut\n'
         else:
            cmd = 'segment-routing\n'
            cmd += 'mpls\n'
            cmd += 'shut\n'
            no_cmd = cmd + 'no shut\n'
         self.pyats_dev_obj.configure(cmd)
         time.sleep(30)
         self.pyats_dev_obj.configure(no_cmd)
      # Underlay routing protocol flap
      if re.search(r'underlay_routing_protocol_shut_no_shut|bgp_shut_noshut', trigger_command, re.I):
         core_proto = self.core_protocol
         if re.search(r'bgp_shut_noshut', trigger_command, re.I):
            core_proto = 'bgp'
         if core_proto == 'bgp':
            cmd = 'router bgp ' + str(self.as_nu) + '\n'
            cmd += 'shutdown\n'
            no_cmd = cmd + 'no shutdown\n'
            sleep_time = 190
         if core_proto == 'isis':
            cmd = 'router isis ' + str(self.isis_id) + '\n'
            cmd += 'shutdown\n'
            no_cmd = cmd + 'no shutdown\n'
            sleep_time = 60
         if core_proto == 'ospf':
            cmd = 'router ospf ' + str(self.ospf_id) + '\n'
            cmd += 'shutdown\n'
            no_cmd = cmd + 'no shutdown\n'
            sleep_time = 60
         self.pyats_dev_obj.configure(cmd)
         time.sleep(sleep_time)
         self.pyats_dev_obj.configure(no_cmd)

      # Underlay routing process restart
      if re.search(r'underlay_routing_process_restart|bgp_process_restart', trigger_command, re.I):
         core_proto = self.core_protocol
         if re.search(r'bgp_process_restart', trigger_command, re.I):
            core_proto = 'bgp'
         log.info('Restarting process %r', core_proto)
         if not Class_srvpn_leaf_router.process_restart(self, core_proto):
            log.info('Not able to restart %r process', core_proto)
            return 0

      # Underlay ospf interface restart
      if re.search(r'underlay ospf flap', trigger_command, re.I):
         intf_list = [intf for intf in self.spine_l3_intf_info_dict.keys()]
         interface_protocol_flap (self.pyats_dev_obj, nu_of_times_to_flap = 2, intf_list = intf_list, \
                     sleep_time_after_shut = 10, sleep_time_after_no_shut = 20, proto_name = 'ospf', ip_ver = '4')

      # Underlay isis interface restart
      if re.search(r'underlay isis flap', trigger_command, re.I):
         intf_list = [intf for intf in self.spine_l3_intf_info_dict.keys()]
         interface_protocol_flap (self.pyats_dev_obj , nu_of_times_to_flap = 2, intf_list = intf_list, \
                                   sleep_time_after_shut = 10, sleep_time_after_no_shut = 20, \
                                   proto_name = 'isis', ip_ver = '4')

      # Underlay intf flap
      if re.search(r'underlay intf flap', trigger_command, re.I):
         int_list = [intf for intf in self.spine_l2_intf_info_dict.keys()]
         for intf in self.spine_l3_intf_info_dict.keys():
            if not re.search('vlan', intf, re.I):
               int_list.append(intf)
         interface_flap(self.pyats_dev_obj, nu_of_times_to_flap = 3, intf_list = int_list, sleep_time_after_shut = 10,\
                            sleep_time_after_no_shut = 20)

      # VPN Neighbor del and readd
      if re.search(r'vpn_add_del', trigger_command, re.I):
         remote_loopbk_ip = self.remote_pe_obj_list[0].loop_bk_start_ip
         i = 1
         while i <= self.nu_of_evpns:
             bgp_neighbor_del_readd (self.pyats_dev_obj, self.as_nu, remote_loopbk_ip)
             remote_loopbk_ip = get_next_host_ip(remote_loopbk_ip)
             i += 1

      # MPLS Forwarding flap under interfaces
      if re.search(r'mpls_forwarding_flap', trigger_command, re.I):
         intf_list = [intf for intf in self.spine_l3_intf_info_dict.keys()]
         mpls_forwarding_config_flap (self.pyats_dev_obj , nu_of_times_to_flap = 2, intf_list = intf_list,\
                                       sleep_time_after_shut = 5, sleep_time_after_no_shut = 10)
      # Loopback interfaces Flap
      if re.search(r'loopback flap', trigger_command, re.I):
         i = self.start_loop_bk
         match = re.search(r'(\d+)', self.start_loop_bk)
         i = int(match.group(1))
         loop_bk_end = i + self.nu_of_evpns - 1
         loopbk_list = list('loopback' + str(i) for i in range(loop_bk_end))
         loopbk_int_flap(self.pyats_dev_obj , loopbk_intf_list = loopbk_list)

      # VPN BGP neighbor Flap
      if re.search(r'vpn bgp flap', trigger_command, re.I):
         remote_loopbk_ip = self.remote_pe_obj_list[0].loop_bk_start_ip
         j = 1
         nbr_list = []
         while j <= self.nu_of_evpns:
            nbr_list.append(remote_loopbk_ip)
            remote_loopbk_ip = get_next_host_ip(remote_loopbk_ip)
            j += 1
         bgp_nbr_flap (self.pyats_dev_obj, nbr_list = nbr_list, sleep_time_after_no_shut = 20)
      # Underlay bgp flap
      if re.search(r'underlay bgp flap', trigger_command, re.IGNORECASE):
         #remote_nbr_ip = self.start_remote_ip_2_s1
         nbr_list = []
         for intf in self.spine_l3_intf_info_dict.keys():
             nbr_list.append(self.spine_l3_intf_info_dict[intf]['peer_v4_add'])
         bgp_nbr_flap (self.pyats_dev_obj, nbr_list = nbr_list, sleep_time_after_no_shut = 20)
      return 1

def configure_sr_mpls(sr_new_template = '', start_label_index = '', loop_bk_start_ip = '', sr_app_cfg_mode = '',
                      nu_of_loopbacks = '', srgb = '', loopbk_label_index_dict = {}):  
    conf_str = ''
    #sr_new_template = 0
    if sr_new_template:
       conf_str += 'segment-routing\n'
       conf_str += 'mpls\n'
    else:
       conf_str += 'segment-routing mpls\n'
    conf_str += 'global-block ' + srgb + '\n'

    #Configure PrefixList and Route-maps
    label_index = start_label_index
    i = 1
    seq = 20
    loopbk_ip = loop_bk_start_ip
    if sr_app_cfg_mode:
       conf_str += 'connected-prefix-sid-map\n'
       conf_str += 'address-family ipv4\n'
    while i <= nu_of_loopbacks:
       loop_bk_ip_with_mask = loopbk_ip + '/32'
       label_indx_str = 'label_index_pol_loopbk_' + str(i)
       if sr_app_cfg_mode:
          conf_str += loop_bk_ip_with_mask + ' index ' + str(label_index) + '\n'
       else:
          conf_str += 'ip prefix-list sr_nw_prefix seq ' + str(seq) + ' permit ' + loop_bk_ip_with_mask + '\n'
          conf_str += 'route-map ' + label_indx_str + ' permit 10\n'
          conf_str += 'set label-index ' + str(label_index) + '\n'
       loopbk_label_index_dict[loopbk_ip] = label_index
       i += 1
       seq += 1
       label_index += 1
       loopbk_ip = get_next_host_ip(loopbk_ip)

    if not sr_app_cfg_mode:
       conf_str += 'route-map rmap_need_label permit 20' + '\n'
       conf_str += 'match ip address prefix-list sr_nw_prefix' + '\n' 
    return conf_str
  
def update_l3_intf_info (local_l3_intf_dict = '', local_specific_l3_intf_dict = '', remote_l3_intf_dict = '',\
                            remote_specific_l3_intf_dict = '', local_int = '', remote_int = '', local_ip = '',\
                            remote_ip = '', local_ip6 = '', remote_ip6 = '', mpls_fwd = 1, vrf_name = '', \
                            local_obj = '', remote_obj = '', isis_int_ckt_level = ''):
    local_l3_intf_dict[local_int] = {}
    local_l3_intf_dict[local_int]['v4_add'] = local_ip
    local_l3_intf_dict[local_int]['v6_add'] = local_ip6
    local_l3_intf_dict[local_int]['peer_v4_add'] = remote_ip
    local_l3_intf_dict[local_int]['peer_v6_add'] = remote_ip6
    local_l3_intf_dict[local_int]['mpls_fwd'] = mpls_fwd
    local_l3_intf_dict[local_int]['vrf_name'] = vrf_name
    local_l3_intf_dict[local_int]['remote_obj'] = remote_obj
    local_l3_intf_dict[local_int]['isis_int_ckt_level'] = isis_int_ckt_level
    
    if isinstance(local_specific_l3_intf_dict, dict):
       local_specific_l3_intf_dict[local_int] = {}
       local_specific_l3_intf_dict[local_int]['v4_add'] = local_ip
       local_specific_l3_intf_dict[local_int]['v6_add'] = local_ip6
       local_specific_l3_intf_dict[local_int]['peer_v4_add'] = remote_ip
       local_specific_l3_intf_dict[local_int]['peer_v6_add'] = remote_ip6
       local_specific_l3_intf_dict[local_int]['mpls_fwd'] = mpls_fwd
       local_specific_l3_intf_dict[local_int]['vrf_name'] = vrf_name
       local_specific_l3_intf_dict[local_int]['isis_int_ckt_level'] = isis_int_ckt_level

    if isinstance(remote_l3_intf_dict, dict):
       remote_l3_intf_dict[remote_int] = {}
       remote_l3_intf_dict[remote_int]['v4_add'] = remote_ip
       remote_l3_intf_dict[remote_int]['v6_add'] = remote_ip6
       remote_l3_intf_dict[remote_int]['peer_v4_add'] = local_ip
       remote_l3_intf_dict[remote_int]['peer_v6_add'] = local_ip6
       remote_l3_intf_dict[remote_int]['mpls_fwd'] = mpls_fwd
       remote_l3_intf_dict[remote_int]['vrf_name'] = vrf_name
       remote_l3_intf_dict[remote_int]['remote_obj'] = local_obj
       remote_l3_intf_dict[remote_int]['isis_int_ckt_level'] = isis_int_ckt_level
       if isinstance(remote_specific_l3_intf_dict, dict):
          remote_specific_l3_intf_dict[remote_int] = {}
          remote_specific_l3_intf_dict[remote_int]['v4_add'] = remote_ip
          remote_specific_l3_intf_dict[remote_int]['v6_add'] = remote_ip6
          remote_specific_l3_intf_dict[remote_int]['peer_v4_add'] = local_ip
          remote_specific_l3_intf_dict[remote_int]['peer_v6_add'] = local_ip6
          remote_specific_l3_intf_dict[remote_int]['mpls_fwd'] = mpls_fwd
          remote_specific_l3_intf_dict[remote_int]['vrf_name'] = vrf_name
          remote_specific_l3_intf_dict[remote_int]['isis_int_ckt_level'] = isis_int_ckt_level

def update_l2_intf_info (local_l2_intf_dict = '', local_specific_l2_intf_dict = '', remote_l2_intf_dict = '',\
                            remote_specific_l2_intf_dict = '', local_int = '', remote_int = '', start_vlan = '',\
                            end_vlan = '', l2_mode = 'trunk'):
    local_l2_intf_dict[local_int] = {}
    local_l2_intf_dict[local_int]['mode'] = l2_mode
    local_l2_intf_dict[local_int]['start_vlan'] = start_vlan
    local_l2_intf_dict[local_int]['end_vlan'] = end_vlan
    local_l2_intf_dict[local_int]['next_set'] = 1
    if isinstance(local_specific_l2_intf_dict, dict):
       local_specific_l2_intf_dict[local_int] = {}
       local_specific_l2_intf_dict[local_int]['mode'] = l2_mode
       local_specific_l2_intf_dict[local_int]['start_vlan'] = start_vlan
       local_specific_l2_intf_dict[local_int]['end_vlan'] = end_vlan
       local_specific_l2_intf_dict[local_int]['next_set'] = 1
    if isinstance(remote_l2_intf_dict, dict):
       remote_l2_intf_dict[remote_int] = {}
       remote_l2_intf_dict[remote_int]['mode'] = l2_mode
       remote_l2_intf_dict[remote_int]['start_vlan'] = start_vlan
       remote_l2_intf_dict[remote_int]['end_vlan'] = end_vlan
       remote_l2_intf_dict[remote_int]['next_set'] = 1
    if isinstance(remote_specific_l2_intf_dict, dict):
       remote_specific_l2_intf_dict[remote_int] = {}
       remote_specific_l2_intf_dict[remote_int]['mode'] = l2_mode
       remote_specific_l2_intf_dict[remote_int]['start_vlan'] = start_vlan
       remote_specific_l2_intf_dict[remote_int]['end_vlan'] = end_vlan
       remote_specific_l2_intf_dict[remote_int]['next_set'] = 1

def addto_l2_intf_info (local_l2_intf_dict = '', local_specific_l2_intf_dict = '', remote_l2_intf_dict = '',\
                            remote_specific_l2_intf_dict = '', local_int = '', remote_int = '', start_vlan = '',\
                            end_vlan = ''):
    nxt_set = local_l2_intf_dict[local_int]['next_set']
    st_vlan_key = 'start_vlan_' + str(nxt_set) 
    end_vlan_key = 'end_vlan' + str(nxt_set) 
    nxt_set += 1
    local_l2_intf_dict[local_int][st_vlan_key] = start_vlan
    local_l2_intf_dict[local_int][end_vlan_key] = end_vlan
    local_l2_intf_dict[local_int]['next_set'] = nxt_set
    if isinstance(local_specific_l2_intf_dict, dict):
       local_specific_l2_intf_dict[local_int][st_vlan_key] = start_vlan
       local_specific_l2_intf_dict[local_int][end_vlan_key] = end_vlan
       local_specific_l2_intf_dict[local_int]['next_set'] = nxt_set
    if isinstance(remote_l2_intf_dict, dict):
       remote_l2_intf_dict[remote_int][st_vlan_key] = start_vlan
       remote_l2_intf_dict[remote_int][end_vlan_key] = end_vlan
       remote_l2_intf_dict[remote_int]['next_set'] = nxt_set
    if isinstance(remote_specific_l2_intf_dict, dict):
       remote_specific_l2_intf_dict[remote_int][st_vlan_key] = start_vlan
       remote_specific_l2_intf_dict[remote_int][end_vlan_key] = end_vlan
       remote_specific_l2_intf_dict[remote_int]['next_set'] = nxt_set

def fill_l3_interface_details(obj, spine_obj, local_ip, remote_ip, intf_type, nu_of_intf_configured, nu_of_ecmp_to_core):
    if not re.search('l3intf|l3subintf|l3po|l3posubintf|svi', intf_type):
       log.info('Interface type is not a valid type')
       return 0
       
    if re.search('l3intf|l3subintf', intf_type):
       self_2_remote_dict = obj.topo_dict['devices'][obj.topo_name]['peer_device'][spine_obj.topo_name]
       remote_2_self_dict = obj.topo_dict['devices'][spine_obj.topo_name]['peer_device'][obj.topo_name]
       non_po_links_list = get_non_po_Links_from_topology(obj.topo_dict, obj.topo_name, spine_obj.topo_name)
       for link in non_po_links_list: 
          if not 'used' in self_2_remote_dict['links'][link].keys():
             local_int = self_2_remote_dict['links'][link]['physical_interface']
             remote_int = remote_2_self_dict['links'][link]['physical_interface']
             self_2_remote_dict['links'][link]['used'] = 1
             remote_2_self_dict['links'][link]['used'] = 1
             break
       else:
          return 0
       if intf_type == 'l3subintf': 
          local_int = local_int + '.50'
          remote_int = remote_int + '.50'
       
       update_l3_intf_info (local_l3_intf_dict = obj.l3_intf_info_dict, remote_obj = spine_obj,\
                              local_specific_l3_intf_dict = obj.spine_l3_intf_info_dict,\
                              remote_l3_intf_dict = spine_obj.l3_intf_info_dict,\
                              remote_specific_l3_intf_dict = spine_obj.leaf_l3_intf_info_dict,\
                              local_int = local_int, remote_int = remote_int, local_ip = local_ip,\
                              remote_ip = remote_ip, mpls_fwd = obj.if_sr_domain, local_obj = obj,\
                              isis_int_ckt_level = obj.isis_int_ckt_level)
    if re.search('l3po|l3posubintf', intf_type):
       self_2_remote_dict = obj.topo_dict['devices'][obj.topo_name]['peer_device'][spine_obj.topo_name]
       for po_name in self_2_remote_dict['port_channels'].keys():
          match = re.search(r'(\d+)', po_name)
          po_no = match.group(1)
          po_name = 'port-channel ' + str(po_no)
       if intf_type == 'l3posubintf': 
          po_name = po_name + '.50'
       update_l3_intf_info (local_l3_intf_dict = obj.l3_intf_info_dict, remote_obj = spine_obj,\
                              local_specific_l3_intf_dict = obj.spine_l3_intf_info_dict,\
                              remote_l3_intf_dict = spine_obj.l3_intf_info_dict,\
                              remote_specific_l3_intf_dict = spine_obj.leaf_l3_intf_info_dict,\
                              local_int = po_name, remote_int = po_name, local_ip = local_ip,\
                              remote_ip = remote_ip, mpls_fwd = obj.if_sr_domain, local_obj = obj,\
                              isis_int_ckt_level = obj.isis_int_ckt_level)
    if re.search('svi', intf_type):
       self_2_remote_dict = obj.topo_dict['devices'][obj.topo_name]['peer_device'][spine_obj.topo_name]
       remote_2_self_dict = obj.topo_dict['devices'][spine_obj.topo_name]['peer_device'][obj.topo_name]
       non_po_links_list = get_non_po_Links_from_topology(obj.topo_dict, obj.topo_name, spine_obj.topo_name)
       for link in non_po_links_list: 
          if not 'used' in self_2_remote_dict['links'][link].keys():
             local_int = self_2_remote_dict['links'][link]['physical_interface']
             remote_int = remote_2_self_dict['links'][link]['physical_interface']
             self_2_remote_dict['links'][link]['used'] = 1
             remote_2_self_dict['links'][link]['used'] = 1
             break
       else:
          return 0
       #vlan_no =  int(str(obj.id) + str(spine_obj.id))
       vlan_no =  obj.spine_svi_vlan_to_use
       vlan_str = ""
       nu_of_svis = nu_of_ecmp_to_core - nu_of_intf_configured
       i = 1
       start_vlan = vlan_no
       while i <= nu_of_svis:
           intf_svi = 'vlan'+ str(vlan_no)
           update_l3_intf_info (local_l3_intf_dict = obj.l3_intf_info_dict, remote_obj = spine_obj,\
                              local_specific_l3_intf_dict = obj.spine_l3_intf_info_dict,\
                              remote_l3_intf_dict = spine_obj.l3_intf_info_dict,\
                              remote_specific_l3_intf_dict = spine_obj.leaf_l3_intf_info_dict,\
                              local_int = intf_svi, remote_int = intf_svi, local_ip = local_ip,\
                              remote_ip = remote_ip, mpls_fwd = obj.if_sr_domain, local_obj = obj,\
                              isis_int_ckt_level = obj.isis_int_ckt_level)
           vlan_str += str(vlan_no) +','
           end_vlan = vlan_no
           vlan_no += 1
           i += 1
           local_ip = get_next_lpm_ip(local_ip)
           remote_ip = get_next_lpm_ip(remote_ip)
       update_l2_intf_info (local_l2_intf_dict = obj.l2_intf_info_dict, \
                            local_specific_l2_intf_dict = obj.spine_l2_intf_info_dict,\
                            remote_l2_intf_dict = spine_obj.l2_intf_info_dict,\
                            remote_specific_l2_intf_dict = spine_obj.leaf_l2_intf_info_dict, local_int = local_int,\
                            remote_int = remote_int, start_vlan = start_vlan, end_vlan = int(vlan_no) - 1)
       obj.spine_svi_vlan_to_use = vlan_no
    return 1

def configure_l3_interface (device_obj, sr_domain = 1, mtu = 9216):
    if device_obj.core_protocol == 'isis':
       device_obj.run_conf_str += create_isis_id (isis_id = device_obj.isis_id, isis_net = device_obj.isis_net,\
                                  enable_bfd = device_obj.bfd_enabled, isis_ckt_level = device_obj.isis_ckt_level,\
                                  ip_ver = 'v4', v4_sr = sr_domain)
    if device_obj.core_protocol == 'ospf':
       try:
          max_paths = device_obj.nu_of_ecmp_to_core
       except:
          max_paths = 64
       device_obj.run_conf_str += create_ospf_id (ospf_id = device_obj.ospf_id, v4_sr = sr_domain,\
                               max_paths = max_paths, enable_bfd = device_obj.bfd_enabled)
    #Configure loopback interface Config
    match = re.search(r'(\d+)', device_obj.start_loop_bk)
    loop_bk_nu = int(match.group(1))
    loop_ip = device_obj.loop_bk_start_ip
    i = 1
    while i <= device_obj.nu_of_loopbacks:
       loop_int = 'loopback' + str(loop_bk_nu)
       if device_obj.core_protocol == 'bgp':
          device_obj.run_conf_str += create_l3_intf_config_string (main_inf = loop_int, ipv4_add = loop_ip, ipv4_mask = '/32')
       if device_obj.core_protocol == 'isis':
          device_obj.run_conf_str += create_l3_intf_config_string (main_inf = loop_int, ipv4_add = loop_ip,\
                                        ipv4_mask = '/32', isis_id = device_obj.isis_id,\
                                        isis_ckt_level = device_obj.isis_int_ckt_level, isis_metric = 1)
       if device_obj.core_protocol == 'ospf':
          device_obj.run_conf_str += create_l3_intf_config_string (main_inf = loop_int, ipv4_add = loop_ip,\
                                         ipv4_mask = '/32', ospf_id = device_obj.ospf_id, ospf_area = device_obj.ospf_area)
       i += 1
       loop_ip = get_next_host_ip(loop_ip)
       loop_bk_nu += 1

    for intf in device_obj.l3_intf_info_dict.keys():
        ip_add = device_obj.l3_intf_info_dict[intf]['v4_add']
        try:
          ipv6_add = device_obj.l3_intf_info_dict[intf]['v6_add']
        except:
          pass
        if re.search('\.', intf, re.I):
           intf_id, subint_id = split_subintf(intf)
           if not intf_id:
              log.info('subinterface id not found for %r name %r', intf, device_obj.topo_name)
              return 0
           #Subinetrface Case
           if re.search('port', intf, re.I):
              #PO subinterface
              links_list, po_phy_intf_list = get_po_links_list_from_topology (device_obj.topo_dict, device_obj.topo_name, \
                                             '', intf)
              if not links_list:
                 log.info('po_links not found for %r name %r', intf, device_obj.topo_name)
                 return 0
              device_obj.run_conf_str += create_po(intf, po_phy_intf_list)
           if device_obj.core_protocol == 'bgp':
              device_obj.run_conf_str += create_l3_intf_config_string (main_inf = intf_id, sub_intf_nu = subint_id,\
                                      ipv4_add = ip_add, dot1q_vlan = subint_id, mpls_fw = sr_domain)
           if device_obj.core_protocol == 'isis':
              device_obj.run_conf_str += create_l3_intf_config_string (main_inf = intf_id, sub_intf_nu = subint_id,\
                                      ipv4_add = ip_add, dot1q_vlan = subint_id, mpls_fw = sr_domain, \
                                      isis_id = device_obj.isis_id,\
                                      isis_ckt_level = device_obj.l3_intf_info_dict[intf]['isis_int_ckt_level'],\
                                      isis_metric = 1, isis_nwk_p2_p = device_obj.if_p2p_isis_intf)
           if device_obj.core_protocol == 'ospf':
              device_obj.run_conf_str += create_l3_intf_config_string (main_inf = intf_id, sub_intf_nu = subint_id,\
                                      ipv4_add = ip_add, dot1q_vlan = subint_id, mpls_fw = sr_domain,\
                                      ospf_id = device_obj.ospf_id, ospf_area = device_obj.ospf_area, ospf_cost = 40)
           #Subinetrface Case END
        else:
           #Not Subinetrface Case
           if re.search('port', intf, re.I):
              links_list, po_phy_intf_list = get_po_links_list_from_topology (device_obj.topo_dict, device_obj.topo_name, \
                                             '', intf)
              if not links_list:
                 log.info('po_links not found for %r name %r', intf, device_obj.topo_name)
                 return 0
              device_obj.run_conf_str += create_po(intf, po_phy_intf_list)
              #Po Case
           if not device_obj.l3_intf_info_dict[intf]['vrf_name']:
              if device_obj.core_protocol == 'bgp':
                 device_obj.run_conf_str += create_l3_intf_config_string (main_inf = intf, ipv4_add = ip_add,\
                                                                          mpls_fw = sr_domain)
              if device_obj.core_protocol == 'isis':
                 device_obj.run_conf_str += create_l3_intf_config_string (main_inf = intf, ipv4_add = ip_add, \
                                             mpls_fw = sr_domain,\
                                             isis_nwk_p2_p = device_obj.if_p2p_isis_intf,\
                                             isis_id = device_obj.isis_id, \
                                             isis_ckt_level = device_obj.l3_intf_info_dict[intf]['isis_int_ckt_level'],\
                                             isis_metric = 1)
              if device_obj.core_protocol == 'ospf':
                 device_obj.run_conf_str += create_l3_intf_config_string (main_inf = intf, ipv4_add = ip_add,\
                                                                          mpls_fw = sr_domain,\
                                                                          ospf_id = device_obj.ospf_id,\
                                                                          ospf_area = device_obj.ospf_area, ospf_cost = 40)
           else:
              vrf_name = device_obj.l3_intf_info_dict[intf]['vrf_name']
              v6_add = device_obj.l3_intf_info_dict[intf]['v6_add']
              device_obj.run_conf_str += create_l3_intf_config_string (main_inf = intf, ipv4_add = ip_add,\
                                          ipv6_add = v6_add, vrf_name = vrf_name)
    return 1 

def check_if_its_a_spine_ip (pe_obj, ip_add):
   ret_val = ''
   for spine_obj in pe_obj.connected_spine_obj_list:
      for intf in spine_obj.l3_intf_info_dict.keys():
         ip = spine_obj.l3_intf_info_dict[intf]['v4_add']
         if ip == ip_add:
           return intf
   return ret_val

def configure_l2_interface (device_obj, mtu = 9216):
    for intf in device_obj.l2_intf_info_dict.keys():
        if re.search('port', intf, re.I):
           #Po Case
           links_list, po_phy_intf_list = get_po_links_list_from_topology (device_obj.topo_dict, device_obj.topo_name, \
                                       '', intf)
           if not links_list:
              log.info('po_links not found for %r name %r', intf, device_obj.topo_name)
              return 0
           device_obj.run_conf_str += create_po(intf, po_phy_intf_list)
        l2_mode = device_obj.l2_intf_info_dict[intf]['mode']
        start_vlan = device_obj.l2_intf_info_dict[intf]['start_vlan']
        end_vlan = device_obj.l2_intf_info_dict[intf]['end_vlan']
        device_obj.run_conf_str += create_l2_intf_config_string (main_inf = intf, mode = l2_mode, mtu = mtu,\
                                         start_vlan = start_vlan, end_vlan = end_vlan, add_vlan_to_trunk = 0,\
                                         create_vlan = 1)
        i = 1
        while i < device_obj.l2_intf_info_dict[intf]['next_set']:
            st_vlan_key = 'start_vlan_' + str(i) 
            end_vlan_key = 'end_vlan' + str(i) 
            l2_mode = device_obj.l2_intf_info_dict[intf]['mode']
            start_vlan = device_obj.l2_intf_info_dict[intf][st_vlan_key]
            end_vlan = device_obj.l2_intf_info_dict[intf][end_vlan_key]
            device_obj.run_conf_str += create_l2_intf_config_string (main_inf = intf, mode = l2_mode, mtu = mtu,\
                                         start_vlan = start_vlan, end_vlan = end_vlan, add_vlan_to_trunk = 1,\
                                         create_vlan = 1)
            i += 1
    return 1

def sr_config_del_readd (device, sleep_time_after_del = 10, sleep_time_after_add = 20):
    output = device.mgmt.execute('show run | sec ' + nbr_ip)
    lines = output.splitlines()
    conf_str = ''
    unconf_str = ''
    conf_str = 'router bgp ' + str(as_nu) + '\n'
    if not re.search('default', vrf_name, re.I):
      conf_str = conf_str + 'vrf ' + vrf_name + '\n'
    unconf_str = conf_str + 'no neighbor ' + nbr_ip + '\n'
    j = 0
    while j < len(lines):
        conf_str += lines[j] + '\n'
        j += 1
    device.mgmt.configure(unconf_str)
    time.sleep(sleep_time_after_del)
    device.mgmt.configure(conf_str)
    time.sleep(sleep_time_after_add)
    return 1
