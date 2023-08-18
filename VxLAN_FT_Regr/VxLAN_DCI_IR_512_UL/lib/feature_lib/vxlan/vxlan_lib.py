
import os
import sys
import yaml
import re
#import netaddr
import utils
from utils import *
import  bringup_lib
import parserutils_lib
import verify_lib

class configVxlan():
    def __init__(self,vxlan_dict,key,vni_learning_mode,switch_hdl_dict,log):
        print('The value of vxlan_Config_dict is:' , vxlan_dict)
        self.log=log
        self.result='pass'
        self.vxlan_config_dict=vxlan_dict
        self.switch_hdl_dict=switch_hdl_dict
        self.key=key
        self.vni_learning_mode=vni_learning_mode
        try:
           self.list_of_nodes=self.vxlan_config_dict.keys()
        except KeyError:
           err_msg='Error !!! vxlan_config_dict has not been defined properly, does not have nodes   \
              as the top level keys'
           testResult( 'fail', err_msg, self.log )
  
    def AllNodes(self):
        for node in self.list_of_nodes:
           self.Nodes(node)

    def Nodes(self,node):
        self.log.info(node)
        hdl=self.switch_hdl_dict[node]
        key=self.key
        self.log.info(self.vni_learning_mode)
        key_list=["global_config","mcast_replication","ingress_replication_static","ingress_replication_bgp","routing","snooping","budNode","vxlan_member_vni"]
        retVal=1
        if key not in key_list:
            self.log.error('{0} not a valid key under vxlan_config_dict. Valid keys\
            are global_config, mcast_replication, ingress_replication_static,ingress_replication_bgp, routing, snooping and budNode'.format(key))
            return 0 
        if key == "global_config":
            self.log.info("Now configuring vxlan global configs")
            bringup_lib.configFeature( hdl, self.log, '-feature {0} -listFlag False'.format('nv overlay') )
            bringup_lib.configFeature( hdl, self.log, '-feature vn-segment-vlan-based' )
            if re.match('cp',self.vni_learning_mode,re.I):
                retVal=configVxlanGlobal(self.vxlan_config_dict[node],hdl,self.log,'-host_reachability_protocol bgp')
            else:
                retVal=configVxlanGlobal(self.vxlan_config_dict[node],hdl,self.log)
        elif key == "vxlan_member_vni":
            self.log.info("Now configuring vxlan member VNIs")
            if re.match('cp',self.vni_learning_mode,re.I):
                retVal=configVxlanMemberVni(self.vxlan_config_dict[node],hdl,self.log,'-mode cp')
            else:
                retVal=configVxlanMemberVni(self.vxlan_config_dict[node],hdl,self.log)
        elif key == "mcast_replication":
            self.log.info("Now configuring mcast-replication VNIs")
            if re.match('cp',self.vni_learning_mode,re.I):
                retVal=configVxlanMcast(self.vxlan_config_dict[node],hdl,self.log,'-mode cp')
                print ('The Value of retVal inside If part is:: ', retVal)
            else:
                retVal=configVxlanMcast(self.vxlan_config_dict[node],hdl,self.log)
                print ('The Value of retVal inside Else part is:: ', retVal)
        elif key == "ingress_replication_static" and re.match('dp',self.vni_learning_mode,re.I):
            self.log.info("Now configuring ingress_replication_static VNIs")
            retVal=configVxlanFloodandLearn(self.vxlan_config_dict[node],hdl,self.log)
        elif key == "ingress_replication_bgp" and re.match('cp',self.vni_learning_mode,re.I):
            self.log.info("Now configuring ingress_replication_bgp VNIs")
            retVal=configVxlanIRbgp(self.vxlan_config_dict[node],hdl,self.log)
        elif key == "routing" and re.match('cp',self.vni_learning_mode,re.I):
            self.log.info("Now configuring routing VNIs")
            retVal=configVxlanRouting(self.vxlan_config_dict[node],hdl,self.log)
        elif key == "snooping":
            retVal=configVxlanSnooping(self.vxlan_config_dict[node],hdl,self.log)
        elif key == "budNode":
            retVal=configVxlanBudnode(self.vxlan_config_dict[node],hdl,self.log)
        if not retVal:
            self.log.error('Vxlan {0} configuration failed on {1}.'.format(key,node))
            return 0
        else:
            return 1 

def parseVxlanGlobalconfigs( log, vxlan_global_args ):
    arggrammar={}
    arggrammar['source_interface']='-type str -required true'
    arggrammar['arp_ether']='-type int -default 0'
    arggrammar['global_ir']='-type bool -default False'
    arggrammar['global_mcast_l2']='-type str'
    arggrammar['global_mcast_l3']='-type str'
    arggrammar['source_interface_hold_down_time']='-type str -default 30'
    ns=parserutils_lib.argsToCommandOptions( vxlan_global_args, arggrammar, log )
    return ns
def configVxlanGlobal(vxlan_config_dict,hdl,log,*args):
    '''Configure global paramters for vxlan like source-interface on node'''
    ns=parseVxlanGlobalconfigs( log, vxlan_config_dict )
    kdict={}
    kdict['verifySuccess']=True
    if ns.arp_ether:
            cfg='hardware access-list tcam region arp-ether {0} double-wide'.format(ns.arp_ether)
            hdl.configure(cfg)
    cfg='no interface nve1'
    hdl.configure(cfg)
    cfg='''
           interface nve1
             source-interface {0}
             no shutdown
        '''.format(ns.source_interface)

    arggrammar={}
    arggrammar['host_reachability_protocol']='-type str'
    arggrammar['mac_addr']='-type str -default 0000.1234.5678'
    hrp=parserutils_lib.argsToCommandOptions( args, arggrammar, log )
    if hasattr (hrp, 'host_reachability_protocol') and hrp.host_reachability_protocol:
        cfg=cfg+'host-reachability protocol {0}\n'.format(hrp.host_reachability_protocol)
    if ns.global_ir:
        cfg+='global ingress-replication protocol bgp\n' 
    if ns.global_mcast_l2:
        cfg+='global mcast-group {0} l2\n'.format(ns.global_mcast_l2) 
    if ns.global_mcast_l3:
        cfg+='global mcast-group {0} l3\n'.format(ns.global_mcast_l3) 
    if ns.source_interface_hold_down_time:
        cfg+='source-interface hold-down-time {0} \n'.format(ns.source_interface_hold_down_time)     
    if hasattr (hrp, 'host_reachability_protocol') and hrp.host_reachability_protocol:
        cfg=cfg+'fabric forwarding anycast-gateway-mac {0}\n'.format(hrp.mac_addr)
    hdl.configure(cfg)
    return 1

def parseVxlanMemberVni( log, vxlan_mcast_args ):
    arggrammar={}
    #arggrammar['group']='-type str'
    arggrammar['vlan']='-type str'
    ns=parserutils_lib.argsToCommandOptions( vxlan_mcast_args, arggrammar, log )
    return ns
def parseVxlanMcastconfigs( log, vxlan_mcast_args ):
    arggrammar={}
    arggrammar['group']='-type str'
    arggrammar['vlan']='-type str'
    ns=parserutils_lib.argsToCommandOptions( vxlan_mcast_args, arggrammar, log )
    return ns

def configVxlanMemberVni(vxlan_config_dict,hdl,log,*args):
    '''Configure Member Vni for vxlan'''
    kdict={}
    kdict['verifySuccess']=True
    arggrammar={}
    arggrammar['mode']='-type str -default dp'
    ms=parserutils_lib.argsToCommandOptions( args, arggrammar, log )
    if 'vni' in vxlan_config_dict:
        for vn in vxlan_config_dict['vni']:
           ns=parseVxlanMemberVni( log, vxlan_config_dict['vni'][vn] )
           cfg='''vlan {1}
                    vn-segment {0}
                  exit
                  interface nve1
                    member vni {0}
               '''.format(vn,ns.vlan)
           if ms.mode == "cp":
               cfg+='''interface Vlan{0}
                         fabric forwarding mode anycast-gateway
                    '''.format(ns.vlan)
           hdl.configure(cfg)
           return 1
    else:
        log.error('vni key not found under member-vni')      
        return 0
        
def configVxlanMcast(vxlan_config_dict,hdl,log,*args):
    '''Configure mcast replication paramters for vxlan'''
    kdict={}
    kdict['verifySuccess']=True
    arggrammar={}
    arggrammar['mode']='-type str -default dp'
    ms=parserutils_lib.argsToCommandOptions( args, arggrammar, log )
    print ('The value of ms inside configVxlanMcast is :', ms)
    if 'vni' in vxlan_config_dict:
        for vn in vxlan_config_dict['vni']:
           print ('The value of vn inside configVxlanMcast is :', vn)
           ns=parseVxlanMcastconfigs( log, vxlan_config_dict['vni'][vn] )
           cfg='''vlan {2}
                    vn-segment {0}
                  exit
                  interface nve1
                    member vni {0}
                      mcast-group {1}
               '''.format(vn,ns.group,ns.vlan)
            
           if ms.mode == "cp":
               cfg+='''interface Vlan{0}
                         fabric forwarding mode anycast-gateway
                    '''.format(ns.vlan)
           hdl.configure(cfg)
        return 1
    else:
        log.error('vni key not found under mcast-replication')      
        return 0
        

def parseVxlanFloodandLearnconfigs( log, vxlan_fl_args ):
    arggrammar={}
    arggrammar['peer_ip']='-type str'
    arggrammar['vlan']='-type str'
    ns=parserutils_lib.argsToCommandOptions( vxlan_fl_args, arggrammar, log )
    return ns
def configVxlanFloodandLearn(vxlan_config_dict,hdl,log):     
    '''Configure flood and learn paramters for vxlan'''
    kdict={}
    kdict['verifySuccess']=True
    if 'vni' in vxlan_config_dict:
        for vn in vxlan_config_dict['vni']:
           ns=parseVxlanFloodandLearnconfigs( log, vxlan_config_dict['vni'][vn] )
           peer_cfg=""
           for peer in strToList(ns.peer_ip):
               peer_cfg+='peer-ip {0}\n'.format(peer)
           cfg='''vlan {2}
                    vn-segment {0}
                  exit
                  interface nve1
                    member vni {0}
                      ingress-replication protocol static
                        {1} 
               '''.format(vn,peer_cfg,ns.vlan)
           hdl.configure(cfg)
           return 1
    else:
        log.error('vni key not found under ingress_replication_static')
        return 0

def parseVxlanIRbgpconfigs( log, vxlan_ir_bgp_args ):
    arggrammar={}
    arggrammar['protocol']='-type str'
    arggrammar['vlan']='-type str'
    ns=parserutils_lib.argsToCommandOptions( vxlan_ir_bgp_args, arggrammar, log )
    return ns
def configVxlanIRbgp(vxlan_config_dict,hdl,log):     
    '''Configure IR BGP paramters for vxlan'''
    kdict={}
    kdict['verifySuccess']=True
    if 'vni' in vxlan_config_dict:
        for vn in vxlan_config_dict['vni']:
           ns=parseVxlanIRbgpconfigs( log, vxlan_config_dict['vni'][vn] )
           cfg='''vlan {1}
                    vn-segment {0}
                  exit
                  interface nve1
                    member vni {0}
                      ingress-replication protocol bgp
               '''.format(vn,ns.vlan)
           cfg+='''interface Vlan{0}
                     fabric forwarding mode anycast-gateway
                '''.format(ns.vlan)
           hdl.configure(cfg)
           return 1
    else:
        log.error('vni key not found under ingress_replication_bgp')
        return 0

def parseVxlanRoutingconfigs( log, vxlan_routing_args ):
    arggrammar={}
    arggrammar['vrf']='-type str'
    arggrammar['group']='-type str'
    arggrammar['vlan']='-type str'
    ns=parserutils_lib.argsToCommandOptions( vxlan_routing_args, arggrammar, log )
    return ns
def configVxlanRouting(vxlan_config_dict,hdl,log):     
    '''Configure routing paramters for vxlan'''
    kdict={}
    kdict['verifySuccess']=True
    if 'vni' in vxlan_config_dict:
        for vn in vxlan_config_dict['vni']:
           ns=parseVxlanRoutingconfigs( log, vxlan_config_dict['vni'][vn] )
           print ('The Value of ns is : ', ns)
           cfg='''vlan {1}
                    vn-segment {0}
                  exit
                  interface nve1
                    member vni {0} associate-vrf
                  interface Vlan{1}
                    ip forward
               '''.format(vn,ns.vlan)
           if ns.group:
                cfg += '''
                        interface nve1
                        member vni {0} associate-vrf
                        mcast-group {1}
                        '''.format(vn, ns.group)
           hdl.configure(cfg)
           return 1
    else:
        log.error('vni key not found under routing')
        return 0

def parseVxlanSnoopingconfigs( log, vxlan_snooping_args ):
    arggrammar={}
    arggrammar['mcast_group']='-type str'
    arggrammar['vlan']='-type str'
    ns=parserutils_lib.argsToCommandOptions( vxlan_snooping_args, arggrammar, log )
    return ns
def configVxlanSnooping(vxlan_config_dict,switch_hdl,log):     
    '''Configure igmp snooping paramters for vxlan'''
    ns=parseVxlanSnoopingconfigs( log, vxlan_config_dict )
    return 1

def parseVxlanBudnodeconfigs( log, vxlan_budnode_args ):
    arggrammar={}
    arggrammar['mcast_group']='-type str'
    arggrammar['vlan']='-type str'
    ns=parserutils_lib.argsToCommandOptions( vxlan_budnode_args, arggrammar, log )
    return ns
def configVxlanBudnode(vxlan_config_dict,switch_hdl,log):     
    '''Configure bud node paramters for vxlan'''
    ns=parseVxlanBudnodeconfigs( log, vxlan_config_dict )
    return 1

def getNvevniDict(hdl,log):
    '''Method to get vni info in form of dictionary for DUT. Dictionary 
    would look like ('sw3-gd955-paris', {'2000005': {'status': 'Up', 
    'mcast-group': '239.1.1.5', 'vlan': '5', 'type': 'L2', 'mode': 'CP'}
    , '3000005': {'status': 'Up', 'mcast-group': 'n/a', 'type': 'L3', 
    'mode': 'CP', 'vrf': 'evpn-tenant-3000005'})'''
    vni_dict={}
    vni_dict[hdl.switchName]={} 
    vni_op=hdl.iexec('show nve vni')
    vni_reg="(nve[0-9]+\s+(\d+)(.*)\s+(Up|Down)\s+(CP|DP)\s+(L2|L3)\s+\[(.*)\])"
    vni_match=re.findall(vni_reg,vni_op)
    i=0
    while i < len(vni_match):
        vni_dict[hdl.switchName][vni_match[i][1]]={}
        if re.match('L2',vni_match[i][5].strip(),re.I):
            vni_dict[hdl.switchName][vni_match[i][1]].update({'mcast-group': \
            vni_match[i][2].strip(), 'status': vni_match[i][3].strip(), 'mode':\
            vni_match[i][4].strip(), 'type': vni_match[i][5].strip(), 'vlan':\
            vni_match[i][6].strip()})
        else:
            vni_dict[hdl.switchName][vni_match[i][1]].update({'mcast-group':\
            vni_match[i][2].strip(), 'status': vni_match[i][3].strip(), 'mode':\
            vni_match[i][4].strip(), 'type': vni_match[i][5].strip(), 'vrf':\
            vni_match[i][6].strip()})
        i+=1     

    if not vni_dict[hdl.switchName].keys():
        vni_dict={}    
    return vni_dict

def getNveIRDict(hdl,log):
    '''Method to get ingress-replication peer info in form of dictionary
    for DUT. Dictionary looks like {'sw3-gd955-paris': {'2000005': \
    {1: {'source': 'CLI', 'uptime': '00:35:25', 'peer_ip': '40.1.1.1'},\
    2: {'source': 'CLI', 'uptime': '00:35:25', 'peer_ip': '50.1.1.1'}}}}'''

    ingress_peer_dict={}
    ingress_peer_dict[hdl.switchName]={} 
    peer_pat="\n\s+(\d+.\d+.\d+.\d+)\s+(CLI|IMET)\s+(\d\d:\d\d:\d\d)"
    time_pat="\d\d:\d\d:\d\d"
    ipv4_pat="\d+.\d+.\d+.\d+"
    ingress_peer_pat=\
    "(nve[0-9]+\s+(\d+)\s+({0})\s+(CLI|IMET)\s+({1})[{2}]+)".format(ipv4_pat,time_pat,peer_pat)
    ingress_peer_op=hdl.iexec('show nve vni ingress-replication')
    ingress_peer_match=re.findall(ingress_peer_pat,ingress_peer_op)
    while i < len(ingress_peer_match):
        for var in ingress_peer_match[i][0].split("\n"):
            cnt=1
            if var:
                var_list=strToList(var)
                if 'nve1' in var_list:
                    vni=var_list[1] 
                    ingress_peer_dict[hdl.switchName][vni]={}
                    ingress_peer_dict[hdl.switchName][vni][cnt]={}     
                    ingress_peer_dict[hdl.switchName][vni][cnt].update({'peer_ip': var_list[2],'source': var_list[3],'uptime':var_list[4]})
                else:
                    cnt+=1
                    ingress_peer_dict[hdl.switchName][vni][cnt]={} 
                    ingress_peer_dict[hdl.switchName][vni][cnt].update({'peer_ip': var_list[0],'source': var_list[1],'uptime':var_list[2]})
            else:
                continue
        i+=1
    if not ingress_peer_dict[hdl.switchName].keys():
        ingress_peer_dict={}
    return ingress_peer_dict

def getNvepeerDict(hdl,log,*args):
    '''Method to get nve peer info in form of dictionary for DUT. 
    Dictionary looks like {'sw2-gd955-9372PX': {'30.1.1.1': 
    {'status': 'Up', 'uptime': '00:58:34', 'learnType': 'CP', 'mac_address':
    'n/a'}, '50.1.1.1': {'status': 'Up', 'uptime': '01:09:41', 'learnType':
    'CP', 'mac_address': '003a.7d4e.3ee7'}}}'''
    arggrammar={}
    arggrammar['node']='-type str'
    ns=parserutils_lib.argsToCommandOptions( args, arggrammar, log )
    mac_pat="[a-f0-9]{4}\.[a-f0-9]{4}\.[a-f0-9]{4}"
    pat2='n/a' 
    peer_reg="(nve[0-9]+\s+(\d+.\d+.\d+.\d+)\s+(Up|Down)\s+(CP|DP)\s+([0-9\:dh]+)\s+({0}|{1}))".format(mac_pat,pat2)
    peer_op=hdl.execute('show nve peers')
    peer_match=re.findall(peer_reg,peer_op)
    peer_dict={}
    if ns.node:
            key=ns.node
    else:
            key=hdl.switchName

    peer_dict[key]={}
    i=0
    while i < len(peer_match):
        peer_dict[key][peer_match[i][1]]={}
        peer_dict[key][peer_match[i][1]].update({'status':\
        peer_match[i][2],'learnType': peer_match[i][3], 'uptime':\
        peer_match[i][4], 'mac_address': peer_match[i][5]})
        i+=1
    if not peer_dict[key].keys():
        peer_dict={}
    return peer_dict

def getNveintfDict(hdl,log,*args):
    '''Method to get nve interface info in form of dictionary for DUT.
    Dictionary looks like {'sw3-gd955-paris': {'nve1': {'router_mac':
    '003a.7d4e.2da7', 'src_intf': 'loopback0', 'primary': '30.1.1.2',
    'state': 'Up', 'vpc_capability': 'notified', 'host_learning_mode':
    'Control-Plane', 'encap': 'VXLAN', 'secondary': '30.1.1.1'}}}'''

    arggrammar={}
    arggrammar['intf']='-type str -default nve1'
    ns=parserutils_lib.argsToCommandOptions( args, arggrammar, log )
    pat1='Interface:\s+{0},\s+State:\s+(Up|Down),\s+encapsulation:\s+(.*)'.format(ns.intf)
    pat2='VPC Capability:\s+VPC-VIP-Only\s+\[(.*)\]'
    pat3='Local Router MAC:\s+([a-e0-9]+.[a-e0-9]+.[a-e0-9]+)'
    pat4='Host Learning Mode:\s+(.*)'
    pat5='Source-Interface:\s+(.*)\s+\(primary:\s+(.*),\s+secondary:\s+(.*)\)'
    
    intf_op=hdl.iexec('show nve interface {0}'.format(ns.intf))
    pat1_match=re.findall(pat1,op)
    pat2_match=re.findall(pat2,op)
    pat3_match=re.findall(pat3,op)
    pat4_match=re.findall(pat4,op)
    pat5_match=re.findall(pat5,op)
    
    nve_intf_dict={} 
    nve_intf_dict[hdl.switchName]={} 
    nve_intf_dict[hdl.switchName][ns.intf]={}
    if pat1_match and pat2_match and pat3_match and pat4_match and pat5_match:
        nve_intf_dict[hdl.switchName][ns.intf].update({{'state': \
        pat1_match[0][0], 'encap': pat1_match[0][1], 'vpc_capability': \
        pat2_match[0], 'router_mac': pat3_match[0], 'host_learning_mode': \
        pat4_match[0], 'src_intf': pat5_match[0][0], 'primary': \
        pat5_match[0][1], 'secondary': pat5_match[0][2]}})
    if not nve_intf_dict[hdl.switchName][ns.intf].keys():
        nve_intf_dict={}
    return nve_intf_dict 

def getNvevniCountersDict(hdl,vni,log):
    '''Method to get vni counters dict for DUT. Dictionary looks like:
    {'sw3-gd955-paris': {'2000002': {'RX': {'mcast_pkts': '6349', 
    'unicast_pkts': '0', 'unicast_bytes': '0', 'mcast_bytes': '457096'},
    'TX': {'mcast_pkts': '0', 'unicast_pkts': '0', 'unicast_bytes': '0',
    'mcast_bytes': '0'}}}}'''

    pat1='VNI:\s+(\d+)'
    pat2='TX\s*\n\s+(\d+)\s+unicast\s+packets\s+(\d+)\s+unicast\s+bytes\n\s+(\d+)\s+multicast\s+packets\s+(\d+)\s+multicast\s+bytes'
    pat3='RX\s*\n\s+(\d+)\s+unicast\s+packets\s+(\d+)\s+unicast\s+bytes\n\s+(\d+)\s+multicast\s+packets\s+(\d+)\s+multicast\s+bytes'
    vni_counter_op=hdl.execute('show nve vni {0} counters'.format(vni))

    pat1_match=re.findall(pat1,vni_counter_op)
    pat2_match=re.findall(pat2,vni_counter_op)
    pat3_match=re.findall(pat3,vni_counter_op)
  
    vni_counters_dict={}
    vni_counters_dict[hdl.switchName]={}
    if pat1_match and pat2_match and pat3_match:
        vni_counters_dict[hdl.switchName][pat1_match[0]]={}
        vni_counters_dict[hdl.switchName][pat1_match[0]].update({'TX': {'unicast_pkts': \
        pat2_match[0][0], 'unicast_bytes': pat2_match[0][1], 'mcast_pkts': \
        pat2_match[0][2], 'mcast_bytes': pat2_match[0][3]}})
        vni_counters_dict[hdl.switchName][pat1_match[0]].update({'RX': {'unicast_pkts': \
        pat3_match[0][0], 'unicast_bytes': pat3_match[0][1], 'mcast_pkts': \
        pat3_match[0][2], 'mcast_bytes': pat3_match[0][3]}})
    
    if not vni_counters_dict[hdl.switchName].keys():
        vni_counters_dict={}
    return vni_counters_dict

def getNvepeerCountersDict(hdl,peer,log,*args):
    '''Method to get peer counters dict for DUT. Dictionary looks like:
    {'sw3-gd955-paris': {'40.1.1.1': {'RX': {'mcast_pkts': '0', 'unicast_pkts':
    '0', 'unicast_bytes': '0', 'mcast_bytes': '0'}, 'TX': {'mcast_pkts': '0',
    'unicast_pkts': '0', 'unicast_bytes': '0', 'mcast_bytes': '0'}}}}'''
    arggrammar={}
    arggrammar['intf']='-type str -default nve1'
    ns=parserutils_lib.argsToCommandOptions( args, arggrammar, log )

    pat1='Peer\s+IP:\s+(\d+.\d+.\d+.\d+)'
    #pat2='TX\s*\n\s+(\d+)\s+unicast\s+packets\s+(\d+)\s+unicast\s+bytes\n\s+(\d+)\s+multicast\s+packets\s+(\d+)\s+multicast\s+bytes'
    #pat2='TX\r\n\s+(\d+)s+unicast\s'
    pat2='TX\r\n\s+(\d+)\s+unicast\s+packets\s+(\d+)\s+unicast\s+bytes\r\n\s+(\d+)\s+multicast\s+packets\s+(\d+)\s+multicast\s+bytes'
    #pat3='RX\s*\n\s+(\d+)\s+unicast\s+packets\s+(\d+)\s+unicast\s+bytes\n\s+(\d+)\s+multicast\s+packets\s+(\d+)\s+multicast\s+bytes'
    pat3='RX\r\n\s+(\d+)\s+unicast\s+packets\s+(\d+)\s+unicast\s+bytes\r\n\s+(\d+)\s+multicast\s+packets\s+(\d+)\s+multicast\s+bytes'
    peer_counter_op=hdl.execute('show nve peers {0} interface {1} counters'.format(peer,ns.intf))
    log.info('Value of the peer_counter_op is %r' , peer_counter_op)
    pat1_match=re.findall(pat1,peer_counter_op)
    pat2_match=re.findall(pat2,peer_counter_op)
    pat3_match=re.findall(pat3,peer_counter_op)
    log.info('Value of the pat1_match is %r' , pat1_match)
    log.info('Value of the pat2_match is %r' , pat2_match)
    log.info('Value of the pat3_match is %r' , pat3_match)
    '''
    peer_counters_dict={}
    peer_counters_dict[hdl.switchName]={}
    if pat1_match and pat2_match and pat3_match:
        peer_counters_dict[hdl.switchName][pat1_match[0]]={}
        peer_counters_dict[hdl.switchName][pat1_match[0]].update({'TX': {'unicast_pkts': \
        pat2_match[0][0], 'unicast_bytes': pat2_match[0][1], 'mcast_pkts': \
        pat2_match[0][2], 'mcast_bytes': pat2_match[0][3]}})
        peer_counters_dict[hdl.switchName][pat1_match[0]].update({'RX': {'unicast_pkts': \
        pat3_match[0][0], 'unicast_bytes': pat3_match[0][1], 'mcast_pkts': \
        pat3_match[0][2], 'mcast_bytes': pat3_match[0][3]}})
    '''
    peer_counters_dict={}
    peer_counters_dict[hdl.alias]={}
    if pat1_match and pat2_match and pat3_match:
        peer_counters_dict[hdl.alias][pat1_match[0]]={}
        peer_counters_dict[hdl.alias][pat1_match[0]].update({'TX': {'unicast_pkts': \
        pat2_match[0][0], 'unicast_bytes': pat2_match[0][1], 'mcast_pkts': \
        pat2_match[0][2], 'mcast_bytes': pat2_match[0][3]}})
        peer_counters_dict[hdl.alias][pat1_match[0]].update({'RX': {'unicast_pkts': \
        pat3_match[0][0], 'unicast_bytes': pat3_match[0][1], 'mcast_pkts': \
        pat3_match[0][2], 'mcast_bytes': pat3_match[0][3]}})   
    if not peer_counters_dict[hdl.alias].keys():
        peer_counters_dict={}
    return peer_counters_dict


#def resolveHostarp(hlite,ping_profile,version):
#    if version == 'v4':
#        ping_Obj=msdc_common_lib.Ping(hlite,ping_profile)
#    elif version == 'v6':
#        ping_Obj=msdc_common_lib.Ping6(hlite,ping_profile)
#    retVal=ping_Obj.verify()
#    if retVal == 'fail':
#        return 0
#    return 1



def verifyMacAddressTable(hdl,log,mac_vtep_dict=None):
        '''mac_vtep_dict[<mac-address>]={'vlan':<vlan-id>,'type'=<static/dynamic>,'vtep_ip'=<peer_vtep_ip to match for'>}
           This function verifies mac entry learnt against specified peer vtep_ip in the dict.'''

        if mac_vtep_dict:
                out=hdl.iexec('show mac address-table')
                for mac in mac_vtep_dict.keys():
                    result=1
                    log.info('Validating mac_vtep entry in mac address table  for mac {0}'.format(mac))
                    pat='.\s+{0}\s+{1}\s+{2}\s+0\s+F\s+F\s+nve\d+\({3}\)'.format(mac_vtep_dict[mac]['vlan'],\
                                   mac,mac_vtep_dict[mac]['type'],mac_vtep_dict[mac]['vtep_ip'])
                    log.info('searching for pattern{0}'.format(pat))
                    if re.findall(pat,out):
                            log.info('Valid peer VTEP IP {0} entry found for the mac {1}'.format(mac_vtep_dict[mac]['vtep_ip'],mac))
                            result&=1
                    else:
                           log.error('NO Valid peer VTEP IP {0} entry found for the mac {1}'.format(mac_vtep_dict[mac]['vtep_ip'],mac))
                           result&=0
    
        else:
                log.error('Empty mac_vtep_dict')
                return 0
        return result 

def populateVtepVmDict(vtep_vm_dict,host_profile_dict,int_config_dict,log,CS_VLAN_DICT=0):
        VtepVMDict={}
        for node in vtep_vm_dict:
                VtepVMDict[node]={}
                #Populate NVE IP
                #loopback0 configured as source interface for nve
                lo0_args=int_config_dict['loopback'][node]['loopback0']
                arggrammar={}
                arggrammar['ipv4_addr']='-type str '
                arggrammar['secondary_ipv4_addr']='-type str '
                ns=parserutils_lib.argsToCommandOptions( lo0_args, arggrammar, log )
                if ns.secondary_ipv4_addr:
                       nveIP=ns.secondary_ipv4_addr
                else:
                       nveIP=ns.ipv4_addr
                VtepVMDict[node]['NVE_IP']=nveIP
                #Populate VM parameters ip,vlan,mac address to node
                vmlist=strToList(vtep_vm_dict[node])

                for vm in vmlist:
                          for port in host_profile_dict:
                                 if vm in host_profile_dict[port]:
                                        arggrammar={}
                                        arggrammar['srcMac']='-type str '
                                        arggrammar['vlan_id']='-type str '
                                        arggrammar['ipv4']='-type str '
                                        arggrammar['ipv6']='-type str '
                                        ns=parserutils_lib.argsToCommandOptions( host_profile_dict[port][vm], arggrammar, log )
                                        VtepVMDict[node][vm]={}
                                        mac=utils.macFormatConverter(ns.srcMac,'dot')
                                        VtepVMDict[node][vm]['mac']=mac
                                        if ns.vlan_id:
                                                 if CS_VLAN_DICT:
                                                         VtepVMDict[node][vm]['vlan']=CS_VLAN_DICT[int(ns.vlan_id)]
                                                 else:
                                                         VtepVMDict[node][vm]['vlan']=ns.vlan_id
                                        if ns.ipv4:
                                                VtepVMDict[node][vm]['IP']=ns.ipv4
                                        if ns.ipv6:
                                                VtepVMDict[node][vm]['IPv6']=ns.ipv6

        return VtepVMDict

def validateMacLearningsOnPeerVtep(sw_hdl_dict,vtep_vm_dict,nve_peer_dict,log):
     log.info('Validating Macs on peer VTEP ')
     for node in vtep_vm_dict:
        for vm in vtep_vm_dict[node]:
         if vm == 'NVE_IP':
                 continue
         if node in nve_peer_dict:
            for RVIP in nve_peer_dict[node]:
                  for RVTEP in vtep_vm_dict:
                            if vtep_vm_dict[RVTEP]['NVE_IP']==RVIP:
                              log.info('Validating Mac {0} learnt on peer VTEP {1}'.format(vtep_vm_dict[node][vm]['mac'],RVTEP))
                              mac_vtep_dict={vtep_vm_dict[node][vm]['mac']:{'vlan':vtep_vm_dict[node][vm]['vlan'],'type':'dynamic','vtep_ip':vtep_vm_dict[node]['NVE_IP']}}
                              if not verifyMacAddressTable(sw_hdl_dict[RVTEP],log,mac_vtep_dict):
                               utils.testResult('fail','Validation failed for Mac {0} learnt on peer VTEP {1}'.format(vtep_vm_dict[node][vm]['mac'],RVTEP),log) 
                               log.error('Validation failed for Mac {0} learnt on peer VTEP {1}'.format(vtep_vm_dict[node][vm]['mac'],RVTEP))
                               return 0
         else:
                 log.error('Nve Peer Dict Empty for node {0}'.format(node))
                 return 0
     return 1

def pingIxiaHosts(sw_hdl_dict,vtep_vm_dict,log):
    for node in vtep_vm_dict:
           for vm in vtep_vm_dict[node]:
              if vm == 'NVE_IP':
                  continue
              hdl=sw_hdl_dict[node]
              out=hdl.iexec('ping {0} source-interface vlan{1}'.format(vtep_vm_dict[node][vm]['IP'],vtep_vm_dict[node][vm]['vlan']))
              pat='\d+ packets transmitted, \d+ packets received, (\d+).\d+% packet loss'
              if int(re.findall(pat,out)[0]) == 100:
                   log.error('pingIxiaHosts: Ping Failure for IP {0} from node {1}'.format(vtep_vm_dict[node][vm]['IP'],node))
                   return 0
    return 1

def setupConfigVxlan(hdl,dut,log,config_dict):
        ''' method to configure vxlan dict defined for each dut under topology'''
        log.info('Inside setupConfigVxlan')
        switch_hdl_dict={}
        switch_hdl_dict[dut]=hdl
        if 'vni_learning' in config_dict['vxlan_config_dict'].keys():
            log.info('Inside setupConfigVxlan vni_learning')
            arggrammar={}
            arggrammar['mode']='-type str -choices ["CP","DP"]'
            args=config_dict['vxlan_config_dict']['vni_learning']
            ns=parserutils_lib.argsToCommandOptions(args,arggrammar,log)
            vni_learning_mode=ns.mode
        else:
            log.error('vni_learning is a mandatory key in vxlan_config_dict and it is missing')
            return 0

        if 'global_config' in config_dict['vxlan_config_dict'].keys():
            log.info('Inside global_config')
            vxlan_dict=config_dict['vxlan_config_dict']['global_config']
            print('######')
            print(dut)
            if dut in vxlan_dict:
                log.info('Now calling configVxlan for global vxlan configs')
                obj_vxlan=configVxlan(vxlan_dict,'global_config',vni_learning_mode,switch_hdl_dict,log)
                if not obj_vxlan.Nodes(dut):
                    return 0
        else:
            log.error('global_config is a mandatory key in vxlan_config_dict and it is missing')
            return 0

        for key in config_dict['vxlan_config_dict'].keys():
            if key == "vni_learning" or key == "global_config":
                continue
            vxlan_dict=config_dict['vxlan_config_dict'][key]
            if dut in vxlan_dict:
                log.info('Now calling configVxlan for {0}'.format(key))
                log.info('Done with configuring VNI_Learning and Global_Config.. Proceeding with configuring the Multicast based replication.')
                obj_vxlan=configVxlan(vxlan_dict,key,vni_learning_mode,switch_hdl_dict,log)
                print('The value of obj_vxlan in setupConfigVxlan is:' , obj_vxlan)
                if not obj_vxlan.Nodes(dut):
                    return 0
        return 1

