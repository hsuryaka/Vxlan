import re
import logging
from ats.log.utils import banner
from common_lib import utils
from common_lib import bringup_lib
from common_lib.utils import *
import threading
import random
from bs4 import BeautifulSoup
import time
import ipaddress
from feature_lib.vxlan import evpn_lib
import json
import yaml
from common_lib import ixia_lib_new
from common_lib.ixia_lib_new import *
from prettytable import PrettyTable



## Parsing CloudSec dashed args ..

def parseKeyChainConfigs(log, args):
    log.info('The value of args is : {0}'.format(args))
    arggrammar={}
    arggrammar['name']='-type str'
    arggrammar['key']='-type int'
    arggrammar['key_octet_string']='-type str'
    arggrammar['cryptographic_algorithm']='-type str -default AES_128_CMAC'
    arggrammar['key_life_time_start_hour']='-type str'
    arggrammar['key_life_time_start_min']='-type str'
    arggrammar['key_life_time_start_sec']='-type str'
    arggrammar['key_life_time_start_day']='-type int'
    arggrammar['key_life_time_start_month']='-type str'
    arggrammar['key_life_time_start_year']='-type int'
    arggrammar['key_life_time_end_hour']='-type str'
    arggrammar['key_life_time_end_min']='-type str'
    arggrammar['key_life_time_end_sec']='-type str'
    arggrammar['key_life_time_end_day']='-type int'
    arggrammar['key_life_time_end_month']='-type str'
    arggrammar['key_life_time_end_year']='-type int'
    ns=parserutils_lib.argsToCommandOptions( args, arggrammar, log )
    return ns

def parseTunnelEncryptionConfigs(log,args):
    arggrammar={}
    arggrammar['secure_policy']='-type str -default must-secure'
    arggrammar['source_interface']='-type str'
    arggrammar['peer_ip']='-type str'
    arggrammar['keychain']='-type str'
    arggrammar['policy_name']='-type str'
    ns=parserutils_lib.argsToCommandOptions( args, arggrammar, log )
    return ns

def parseTunnelEncryptionPolicyConfigs(log,args):
    arggrammar={}
    arggrammar['name']='-type str'
    arggrammar['cipher_suite']='-type str -default GCM-AES-XPN-128'
    arggrammar['window_size']='-type int'
    arggrammar['sak_rekey_time']='-type int'
    ns=parserutils_lib.argsToCommandOptions( args, arggrammar, log )
    return ns

class configTunnelEncryption():
    
    def __init__(self, cloudsec_config_dict,node_dict,alias_intf_mapping,log):
        self.log  = log
        self.result = 'pass'
        self.cloudsec_config_dict = cloudsec_config_dict
        self.node_dict = node_dict
        self.alias_intf_mapping = alias_intf_mapping
        log.info('Configuring Tunnel-Encryption Configs')
        try:
            self.node_list = self.cloudsec_config_dict.keys()
        except KeyError:
            err_msg='Error !!! cloudsec_config_dict has not been defined properly, does not have nodes   \
              as the top level keys'
            testResult( 'fail', err_msg, self.log)
            
    def configureKeyChain(self, node):
        self.log.info(node)
        hdl = self.node_dict['all_dut'][node]
        
        self.log.info(banner('Configuring KeyChain in dut : {0}'.format(node)))
        ns = parseKeyChainConfigs(self.log,self.cloudsec_config_dict[node]['Key_chain'])
        self.log.info(banner('The value of ns is : {0}'.format(ns)))

        cfg = ''
        send_life_time_str = ''
        if hasattr(ns ,'name') and ns.name:
            cfg += '''no key chain {0} tunnel-encryption
                      key chain {0} tunnel-encryption'''.format(ns.name) + '\n'
            
        if hasattr(ns, 'key') and ns.key:   
            cfg += 'key {0}'.format(ns.key) + '\n'
            
        if hasattr(ns, 'key_octet_string') and ns.key_octet_string:
            if hasattr(ns, 'cryptographic_algorithm') and ns.cryptographic_algorithm:
                cfg += 'key-octet-string {0} cryptographic-algorithm {1}'.format(ns.key_octet_string, ns.cryptographic_algorithm) + '\n'
            else:
                cfg += 'key-octet-string {0} cryptographic-algorithm {1}'.format(ns.key_octet_string, ns.cryptographic_algorithm) + '\n'
                
        if hasattr(ns,'key_life_time_start_hour') and ns.key_life_time_start_hour:
            if hasattr(ns,'key_life_time_start_min') and ns.key_life_time_start_min:
                if hasattr(ns,'key_life_time_start_sec') and ns.key_life_time_start_sec:
                    send_life_time_str += 'send-lifetime {0}:{1}:{2} '.format(ns.key_life_time_start_hour,\
                                                                            ns.key_life_time_start_min,\
                                                                            ns.key_life_time_start_sec)
        if hasattr(ns,'key_life_time_start_month') and ns.key_life_time_start_month:
            if hasattr(ns,'key_life_time_start_day') and ns.key_life_time_start_day:
                if hasattr(ns,'key_life_time_start_year') and ns.key_life_time_start_year:
                    send_life_time_str += '{0} {1} {2} '.format(ns.key_life_time_start_month,\
                                                               ns.key_life_time_start_day,\
                                                               ns.key_life_time_start_year)
        if hasattr(ns,'key_life_time_end_hour') and ns.key_life_time_end_hour:
            if hasattr(ns,'key_life_time_end_min') and ns.key_life_time_end_min:
                if hasattr(ns,'key_life_time_end_sec') and ns.key_life_time_end_sec:
                    send_life_time_str += '{0}:{1}:{2} '.format(ns.key_life_time_end_hour,\
                                                               ns.key_life_time_end_min,\
                                                               ns.key_life_time_end_sec)
        if hasattr(ns,'key_life_time_end_month') and ns.key_life_time_end_month:
            if hasattr(ns,'key_life_time_end_day') and ns.key_life_time_end_day:
                if hasattr(ns,'key_life_time_end_year') and ns.key_life_time_end_year:
                    send_life_time_str += '{0} {1} {2} '.format(ns.key_life_time_end_month,\
                                                               ns.key_life_time_end_day,\
                                                               ns.key_life_time_end_year)
                    
        cfg += send_life_time_str + '\n'
        hdl.configure(cfg)
    
    def configureTunnelEncryptionPolicy(self, node):
        
        self.log.info(node)
        hdl = self.node_dict['all_dut'][node]
        
        self.log.info(banner('Configuring Tunnel Encryption Policy in dut : {0}'.format(node)))
        ns = parseTunnelEncryptionPolicyConfigs(self.log,self.cloudsec_config_dict[node]['Tunnel-encryption-policy'])
        self.log.info(banner('The value of ns is : {0}'.format(ns)))

        cfg = ''
        
        if hasattr(ns,'name') and ns.name:
            cfg += 'tunnel-encryption policy {0}'.format(ns.name) + '\n'
            
        if hasattr(ns,'cipher_suite') and ns.cipher_suite:
            cfg += 'cipher-suite {0}'.format(ns.cipher_suite) + '\n'
            
        if hasattr(ns,'window_size') and ns.window_size:
            cfg += 'window-size {0}'.format(ns.window_size) + '\n'
            
        if hasattr(ns, 'sak_rekey_time') and ns.sak_rekey_time:
            cfg += 'sak-rekey-time {0}'.format(ns.sak_rekey_time) + '\n'
            
        hdl.configure(cfg)


    def configureTunnelEncryptionGlobal(self, node, policy=None):
        log.info('The value of policy is : {0}'.format(policy))
        self.log.info(node)
        hdl = self.node_dict['all_dut'][node]
        
        self.log.info(banner('Configuring Tunnel Encryption Peer in dut : {0}'.format(node)))
        ns = parseTunnelEncryptionConfigs(self.log,self.cloudsec_config_dict[node]['Tunnel-encryption-config'])
        self.log.info(banner('The value of ns is : {0}'.format(ns)))

        cfg = ''
        if not policy:
            if hasattr(ns,'secure_policy') and ns.secure_policy:
                cfg += 'tunnel-encryption {0}'.format(ns.secure_policy) + '\n'
            
        if hasattr(ns,'source_interface') and ns.source_interface:
            cfg += 'tunnel-encryption source-interface {0}'.format(ns.source_interface) + '\n'
            
        if hasattr(ns,'peer_ip') and ns.peer_ip:
            cfg += 'tunnel-encryption peer-ip {0}'.format(ns.peer_ip) + '\n'
            
        if hasattr(ns, 'keychain') and ns.keychain:
            if hasattr(ns,'policy_name') and ns.policy_name:
                cfg += 'keychain {0} policy {1}'.format(ns.keychain, ns.policy_name) + '\n'
            else:
                cfg += 'keychain {0}'.format(ns.keychain) + '\n'
            
        hdl.configure(cfg)
        
    def configureTunnelEncryptionInterfaces(self, node):
        self.log.info(node)
        hdl = self.node_dict['all_dut'][node]
        
        self.log.info('The value of self.cloudsec_config_dict[node] is : {0}'.format(self.cloudsec_config_dict[node]))
        
        if 'interface_config' in self.cloudsec_config_dict[node]:
            for intf in self.cloudsec_config_dict[node]['interface_config'].keys():
                if re.search('uut', intf):
                    intf = self.alias_intf_mapping[node][intf]
                cfg = '''interface {0}
                          tunnel-encryption'''.format(intf)
                hdl.configure(cfg)
        else:
            err_msg = 'Error !! cloudsec_config_dict does not have interface_config as top level keys'
            testResult( 'fail', err_msg, self.log )
        
    def Nodes(self, node, **kwargs):
        policy  = ''
        if kwargs:
            policy = kwargs['policy']
            
            
        log.info('The value of policy is : {0}'.format(policy))
            
        self.log.info(node)
        hdl = self.node_dict['all_dut'][node]
        
        if 'Key_chain' in self.cloudsec_config_dict[node]:
            
            self.log.info(banner('configuring the KeyChain:'))
            self.configureKeyChain(node)
            
        else:
            err_msg = 'Error !! cloudsec_config_dict does not have Key_Chain defined in interface configs'
            testResult( 'fail', err_msg, self.log )
            
        bringup_lib.configFeature( hdl, self.log, '-feature tunnel-encryption' )
        if 'Tunnel-encryption-policy' in self.cloudsec_config_dict[node]:
            
            self.log.info(banner('configuring the Tunnel-Encryption-Policy :'))
            self.configureTunnelEncryptionPolicy(node)
            
        else:
            err_msg = 'Error !! cloudsec_config_dict does not have Tunnel_encryption_policy defined in interface configs'
            testResult( 'fail', err_msg, self.log )
            
        if 'Tunnel-encryption-config' in self.cloudsec_config_dict[node]:
            
            self.log.info(banner('configuring the Global Tunnel-Encryption configs:'))
            self.configureTunnelEncryptionGlobal(node, policy)
            
        else:
            err_msg = 'Error !! cloudsec_config_dict does not have Tunnel-encryption-config defined in interface configs'
            testResult( 'fail', err_msg, self.log )
        
        if 'interface_config' in self.cloudsec_config_dict[node]:
            
            self.log.info(banner('configuring the Tunnel-encryption cli on Interfaces:'))
            self.configureTunnelEncryptionInterfaces(node)
            
        else:
            err_msg = 'Error !! cloudsec_config_dict does not have interface_configs defined in interface configs'
            testResult( 'fail', err_msg, self.log )
            
        return 1
    
class verifyTunnelEncryptionConfigs():
    def __init__(self, log, cloudsec_config_dict,node_dict,alias_intf_mapping):
        self.log  = log
        self.result = 'pass'
        self.cloudsec_config_dict = cloudsec_config_dict
        self.node_dict = node_dict
        self.alias_intf_mapping = alias_intf_mapping
        log.info('Verifying TunnelEncryption Configs')
        try:
            self.node_list = self.cloudsec_config_dict.keys()
        except KeyError:
            err_msg='Error !!! cloudsec_config_dict has not been defined properly, does not have nodes   \
              as the top level keys'
            testResult( 'fail', err_msg, self.log )

    def getCloudSecPeersFromConfigs(self):
        cloudsec_config_peer_dict = {}
        
        self.log.info('Inside getCloudSecPeersFromConfigs')
        for dut in self.cloudsec_config_dict.keys():
            peer_ip_list = []
            args = self.cloudsec_config_dict[dut]['Tunnel-encryption-config']
            ns = parseTunnelEncryptionConfigs(self.log, args)
            log.info('The value of ns is : {0}'.format(ns))
            peer_ip_list.append(ns.peer_ip)
            cloudsec_config_peer_dict[dut] = peer_ip_list
            
        return cloudsec_config_peer_dict

    def verifyCloudSecOnAllPeers(self,vtep_dict,from_configfile):
    
        for dut,hdl in vtep_dict.items():
            self.log.info('Inside verifyCloudSecOnAllPeers')
            peer_ip = from_configfile[dut]
            res = getCloudSecPeerstatus(self.log, dut, hdl,peer_ip[0])
            if res:
                if re.search('SECURE',res['tx_status'],re.I) and re.search('SECURE',res['rx_status'],re.I) :
                    log.info('Tx status & rx Status is as expected')
                    return 1
                else:
                    log.error('Tx / Rx status is not as expected')
                    return 0
            else:
                log.error('Peer could not be established {0}'.format(peer_ip[0]))
                return 0
            
def getCloudSecPeerstatus(log, dut, hdl, peer_ip):
    cloud_sec_peer_dict = {}
    log.info('Inside getCloudSecPeersInfo')
    cmd = 'sh tunnel-encryption session peer-ip {0} | xml'.format(peer_ip)
    log.info('Checking The Tunnel Encrpytion status on dut {0}'.format(dut))
    out = hdl.configure(cmd)
    log.info('The value of out is : {0}'.format(out))
    flag = 0
    try:
        s = BeautifulSoup(out)
        log.info('the value of s is : {0}'.format(s))
        peer_ip = s.find('peeraddr').string
        log.info('The value of peer_ip is : {0}'.format(peer_ip))
        flag = 1
        cloud_sec_peer_dict['peer_ip']  = peer_ip
    except Exception:
        log.error('Unable to find the peer on dut {0} .. '.format(dut))
        return 0
    if flag:
        Tx_status = s.find('rxstatus').string
        Rx_status = s.find('txstatus').string
        cloud_sec_peer_dict['tx_status'] = Tx_status
        cloud_sec_peer_dict['rx_status'] = Rx_status
        cloud_sec_peer_dict['policyname'] = s.find('policyname').string
        cloud_sec_peer_dict['keychainname'] = s.find('kcname').string
        
    log.info('The value of cloud_sec_peer_dict is : {0}'.format(cloud_sec_peer_dict))
    return cloud_sec_peer_dict

