#!/ws/pradn-bgl/pyats/bin/python

import yaml
import time,sys
import os
import argparse
import re
import datetime
import logging
import traceback

from common_lib import interface_lib
from common_lib import bringup_lib
from feature_lib.l3 import bgp_lib
from feature_lib.l3 import ospfv2_lib
from feature_lib.l3 import ospfv3_lib
from feature_lib.l3 import pim_lib
from feature_lib.l2 import vpc_lib
from common_lib import tcam_lib
from feature_lib.security import acl_lib
from common_lib import routing_utils

# pyATS imports

from common_lib.pyConstants import *
from pyats.topology import loader
from pyats.async_ import pcall
from pyats.async_ import Pcall
from unicon import Connection
from ats import aetest
from ats.log.utils import banner
from ats.datastructures.logic import Not, And, Or
from ats.easypy import run
from ats.log.utils import banner
from unicon import Unicon

return_result={'pass':1,'fail':0}

def setupConfigTcam(hdl,dut,log,config_dict):
        switch_hdl_dict={}
        switch_hdl_dict[dut]=hdl
        if 'tcam_config' not in config_dict['skip_configSetup_dict']:
           if 'tcam_config_dict' in config_dict:
                 if dut in config_dict['tcam_config_dict']:
                        log.info(banner('Configuring TCAM'))
                        obj_tcam=tcam_lib.configTcam(config_dict['tcam_config_dict'],switch_hdl_dict,log)
                        if not obj_tcam.Nodes(dut):
                               return 0
        return 1

def setupConfigFeature(hdl,dut,log,config_dict):
        if 'feature_config' not in config_dict['skip_configSetup_dict']:
          if dut in config_dict['dut']:
            if 'feature' in config_dict['dut'][dut]:
                log.info(banner('Configuring Feature'))
                result=bringup_lib.configFeature.invoke(hdl,log,'-feature {0}'.format(config_dict['dut'][dut]['feature']))
            if result=='fail':
                return 0
        return 1

def setupConfigInterface(hdl,dut,log,config_dict):
        sw_hdl_dict={}
        sw_hdl_dict[dut]=hdl
        if 'interface_config' not in config_dict['skip_configSetup_dict']:
           log.info(banner('Configuring Interfaces'))
           int_config_dict=config_dict['interface_config_dict']
           int_obj=interface_lib.configInterface(log,sw_hdl_dict,int_config_dict)
           if int_obj.result=='fail':
             return 0
        return 1

#def setupConfigVrfEvpn(hdl,dut,log,config_dict):
#        ''' wrapper to invoke setupConfigVrfEvpn  function in interface_lib.py'''
#        sw_hdl_dict={}
#        sw_hdl_dict[dut]=hdl
#        int_config_dict=config_dict['interface_config_dict']
#        kwargs={}
#        kwargs['vrf_evpn']=1
#        int_obj=interface_lib.configInterface(log,sw_hdl_dict,int_config_dict,**kwargs)
#        if int_obj.result=='fail':
#                return 0
#        return 1

#def setupConfigSnmp(hdl,dut,log,config_dict):
#        ''' wrapper to invoke configSnmp function in snmp_lib.py'''
#        sw_hdl_dict={}
#        sw_hdl_dict[dut]=hdl
#	if 'snmp_config_dict' not in config_dict:
#		return 1
#        snmp_config_dict=config_dict['snmp_config_dict']
#	if dut not in snmp_config_dict:
#		return 1
#	snmp_obj=snmp_lib.configSnmp(snmp_config_dict,sw_hdl_dict,log,'-topo_setup 1')
#	if snmp_obj.result=='fail':
#		print "configSnmp failed for dut {0}".format(dut)
#        	eor_utils.testResult('fail','TestCase fail',self.log)
#		return 0
#	return 1
#
def setupConfigVpc(hdl,dut,log,config_dict):
        sw_hdl_dict={}
        sw_hdl_dict[dut]=hdl
        if 'vpc_config' not in config_dict['skip_configSetup_dict']:
          if 'vpc_config_dict' not in config_dict:
            return 1
          vpc_config_dict=config_dict['vpc_config_dict']
          int_config_dict=config_dict['interface_config_dict']
          if dut not in config_dict['vpc_config_dict']:
            return 1
          log.info(banner('Configuring VPC'))
          vpc_obj=vpc_lib.configVpc(sw_hdl_dict,vpc_config_dict,int_config_dict,log,'-topo_setup 1')
          if vpc_obj.result=='fail':
            log.error(f'configVpc failed for dut {dut}')
            return 0
          for node in vpc_obj.vpc_nodes:
            log.info('topo_setup: Entering vpcVlanConfig')
            vpc_obj.vpcVlanConfig(node,vpc_config_dict[node]['vlans'])
            log.info('topo_setup: Entering vpcDomainConfig')
            vpc_obj.vpcDomainConfig(node,vpc_config_dict[node]['vpc_domain'])
            log.info('topo_setup: Entering vpcPeerLinkConfig')
            vpc_obj.vpcPeerLinkConfig(node,vpc_config_dict[node]['vpc_peer_link'])
            if 'vpc_port_channels' in vpc_config_dict[node].keys():
                for pc in vpc_config_dict[node]['vpc_port_channels'].keys():
                    vpc_obj.vpcPortChannelConfig(node,vpc_config_dict[node]['vpc_port_channels'][pc])
        return 1


#def setupConfigStaticRoutes(hdl,dut,log,config_dict):
#                ''' method to configure Static route dict defined for each dut under config'''
#                switch_hdl_dict={}
#                switch_hdl_dict[dut]=hdl
#                if 'static_route_dict' in config_dict:
#                        if dut in config_dict['static_route_dict']:
#                                obj_static=route_lib.configStaticRoute(log,switch_hdl_dict,config_dict['static_route_dict'])
#                                if not obj_static.Node(dut,'-config'):
#                                     return 0
#                return 1


def setupConfigBgp(hdl,dut,log,config_dict):
                ''' method to configure Bgp dict defined for each dut under config'''
                switch_hdl_dict={}
                switch_hdl_dict[dut]=hdl
                if 'bgp_config' not in config_dict['skip_configSetup_dict']:
                    if 'bgp_config_dict' in config_dict:
                        if dut in config_dict['bgp_config_dict']:
                                log.info(banner('Configuring BGP'))
                                obj_bgp=bgp_lib.configBgp(config_dict['bgp_config_dict'],switch_hdl_dict,log)
                                if not obj_bgp.Nodes(dut):
                                     return 0
                return 1

def setupConfigOspfv2(hdl,dut,log,config_dict):
                ''' method to configure Ospf dict defined for each dut under config'''
                switch_hdl_dict={}
                switch_hdl_dict[dut]=hdl
                if 'ospfv2_config' not in config_dict['skip_configSetup_dict']:
                   if 'ospfv2_config_dict' in config_dict:
                        if dut in config_dict['ospfv2_config_dict']:
                                log.info(banner('Configuring OSPFv2'))
                                obj_ospf=ospfv2_lib.configOspfv2(switch_hdl_dict,config_dict['ospfv2_config_dict'],log)
                                if not obj_ospf:
                                     return 0
                return 1

def setupConfigOspfv3(hdl,dut,log,config_dict):
                ''' method to configure Ospfv3 dict defined for each dut under config'''
                switch_hdl_dict={}
                switch_hdl_dict[dut]=hdl
                if 'ospfv3_config' not in config_dict['skip_configSetup_dict']:
                   if 'ospfv3_config_dict' in config_dict:
                        if dut in config_dict['ospfv3_config_dict']:
                                log.info(banner('Configuring Ospfv3'))
                                obj_ospf=ospfv3_lib.configOspfv3(switch_hdl_dict,config_dict['ospfv3_config_dict'],log)
                                if not obj_ospf:
                                     return 0
                return 1


#def setupConfigMsdp(hdl,dut,log,config_dict):
#                ''' method to configure msdp dict defined for each dut under config'''
#                switch_hdl_dict={}
#                switch_hdl_dict[dut]=hdl
#                if 'msdp_config_dict' in config_dict:
#                     if dut in config_dict['msdp_config_dict']:
#                             obj_msdp=msdp_new_lib.configMsdp(config_dict['msdp_config_dict'],switch_hdl_dict,log)
#                             if not obj_msdp.Nodes(dut):
#                                     return 0
#                return 1
#
#def setupConfigNat(hdl,dut,log,config_dict):
#                ''' method to configure Nat dict defined for each dut under config'''
#                switch_hdl_dict={}
#                switch_hdl_dict[dut]=hdl
#                if 'nat_config_dict' in config_dict:
#                     if dut in config_dict['nat_config_dict']:
#                             obj_nat=nat_lib.configNat(config_dict['nat_config_dict'],switch_hdl_dict,log)
#                             if not obj_nat.Nodes(dut):
#                                     return 0
#                return 1
#
def setupConfigPrefixList(hdl,dut,log,config_dict):
        ''' method to configure PrefixList'''
        sw_hdl_dict={}
        sw_hdl_dict[dut]=hdl
        result=1
        if 'prefix_list_config' not in config_dict['skip_configSetup_dict']:
           if 'prefix_list_config_dict' in config_dict:
               if dut in config_dict['prefix_list_config_dict']:
                  log.info(banner(f'Configuring Prefix-list in {dut}'))
                  result=routing_utils.configPrefixLists(log,sw_hdl_dict,config_dict['prefix_list_config_dict'])
        return result

def setupConfigRouteMaps(hdl,dut,log,config_dict):
        ''' method to configure Route-maps'''
        sw_hdl_dict={}
        sw_hdl_dict[dut]=hdl
        result=1
        if 'route_map_config' not in config_dict['skip_configSetup_dict']:
          if 'route_map_config_dict' in config_dict:
             if dut in config_dict['route_map_config_dict']:
                log.info(banner(f'Configuring RouteMaps in {dut}'))
                result=routing_utils.configRouteMaps(log,sw_hdl_dict,config_dict['route_map_config_dict'])
        return result

def setupConfigPim(hdl,dut,log,config_dict):
    ''' method to configure PIM dict defined for each dut under config'''
    switch_hdl_dict={}
    switch_hdl_dict[dut]=hdl
    if 'pim_config' not in config_dict['skip_configSetup_dict']:
      if 'pim_config_dict' in config_dict:
        if dut in config_dict['pim_config_dict']:
            log.info(banner('Configuring PIM'))
            obj_pim=pim_lib.configPim(config_dict['interface_config_dict'], config_dict['pim_config_dict'], switch_hdl_dict, log, '-dut {0}'.format(dut))
            if  obj_pim.result=='fail':
                return 0
    return 1

def setupConfigAclList(hdl,dut,log,config_dict):
        ''' method to configure AclList'''
        sw_hdl_dict={}
        sw_hdl_dict[dut]=hdl
        result=1
        if 'acl_config_dict' in config_dict:
             if dut in config_dict['acl_config_dict']:
                result=acl_lib.configAccessLists(log,sw_hdl_dict,config_dict['acl_config_dict'])
        return result

#
#def setupConfigIpDampening(hdl,dut,log,config_dict,hlite):
#    ''' method to configure IP Event Dampening dict defined for each dut under config'''
#    switch_hdl_dict=hlite.gd['connectObj'].switch_hdl_dict
#    if 'ip_dampening_dict' in config_dict:
#        if dut in config_dict['ip_dampening_dict']:
#            obj_damp=ip_dampening_lib.configIpDampening(config_dict['ip_dampening_dict'], switch_hdl_dict, log, '-dut {0}'.format(dut))
#            if  obj_damp.result=='fail':
#                return 0
#    return 1
#
#
#def setupConfigHsrp(hdl,dut,log,config_dict,hlite):
#                '''method to configure HSRP'''
#                #switch_hdl_dict=hlite.gd['connectObj'].switch_hdl_dict
#                switch_hdl_dict={}
#                switch_hdl_dict[dut]=hdl
#                if 'hsrp_config_dict' in config_dict:
#                        if dut in config_dict['hsrp_config_dict']:
#                                obj_hsrp=hsrp_lib.configHsrp(config_dict['hsrp_config_dict'],switch_hdl_dict,log)
#                                if not obj_hsrp.Nodes(dut):
#                                     return 0
#                return 1
#
#
#def setupConfigTacacsServer(hdl,dut,log,config_dict):
#                ''' method to configure Tacacs dict defined for each dut under config'''
#                switch_hdl_dict={}
#                switch_hdl_dict[dut]=hdl
#                if 'tacacs_config_dict' in config_dict:
#                        if dut in config_dict['tacacs_config_dict']:
#                                obj_tacacs=tacac_lib.configTacacsServer(config_dict['tacacs_config_dict'],switch_hdl_dict,log)
#                                if not obj_tacacs.Nodes(dut):
#                                     return 0
#                return 1

 

def setupSequence(hdl,dut,config_dict,log):
        ''' This method is to setup the common config sequentially
        1. feature
        2. interface
        3. BGP'''

        global GLOBAL

        result={}
        result[dut]=1
        try:
            if not setupConfigFeature(hdl,dut,log,config_dict):
                   log.error('Setup {0} failed in {1} thread'.format('setupConfigFeature',dut))
                   result[dut]=0
            
            if not setupConfigTcam(hdl,dut,log,config_dict):
                    log.error('Setup {0} failed in {1} thread'.format('setupConfigTcam',dut))
                    result[dut]=0

            if not setupConfigInterface(hdl,dut,log,config_dict):
                    log.error('Setup {0} failed in {1} thread'.format('setupConfigInterface',dut))
                    result[dut]=0

            if not setupConfigAclList(hdl,dut,log,config_dict):
                    log.error('Setup {0} failed in {1} thread'.format('setupConfigAclList',dut))
                    result[dut]=0

            if not setupConfigRouteMaps(hdl,dut,log,config_dict):
                    log.error('Setup {0} failed in {1} thread'.format('setupConfigRouteMaps',dut))
                    result[dut]=0

            if not setupConfigPrefixList(hdl,dut,log,config_dict):
                    log.error('Setup {0} failed in {1} thread'.format('setupConfigPrefixList',dut))
                    result[dut]=0

            #if not setupConfigVrfEvpn(hdl,dut,log,config_dict):
            #        log.error('Setup {0} failed in {1} thread'.format('setupConfigVrfEvpn',dut))
            #        result[dut]=0

            if not setupConfigBgp(hdl,dut,log,config_dict):
                    log.error('Setup {0} failed in {1} thread'.format('setupConfigBgp',dut))
                    result[dut]=0
            
            if not setupConfigPim(hdl,dut,log,config_dict):
                    log.error('Setup {0} failed in {1} thread'.format('setupConfigPim',dut))
                    result[dut]=0 

            if not setupConfigOspfv2(hdl,dut,log,config_dict):
                    log.error('Setup {0} failed in {1} thread'.format('setupConfigOspfv2',dut))
                    result[dut]=0

            if not setupConfigOspfv3(hdl,dut,log,config_dict):
                    log.error('Setup {0} failed in {1} thread'.format('setupConfigOspfv3',dut))
                    result[dut]=0

            if not setupConfigVpc(hdl,dut,log,config_dict):
                    log.error('Setup {0} failed in {1} thread'.format('setupConfigVpc',dut))
                    result[dut]=0


            log.info('Creating Checkpoint file for dut {0}.......'.format(dut))
            hdl.execute('delete bootflash:base_config.cfg no-prompt')
            hdl.execute('checkpoint file bootflash:base_config.cfg')
            hdl.execute('copy r s')

        except:
                log.error(traceback.format_exc())
                result[dut]=0
                raise


########
#######

def convertConfig(configdict, testbed_obj):
        config = {}

        for key in configdict.keys():
          #print(f'Key : {key}')
          config[key]=LogicalToPhysical(configdict[key], testbed_obj)
          #print('The config Key is {0}'.format(config[key]))
        return config
 
def LogicalToPhysical(conf, testbed_obj):
        if not (type(conf) is dict):
           if re.search('uut[\d]+_uut[\d]+_[\d]+',str(conf)):
                intf = re.findall('uut[\d]+_uut[\d]+_[\d]+',conf)
                #print('Inside not dict intf: {0}'.format(intf)) 
                for en in intf:
                     #print(f'#### First loop en: {en}')
                     keylist = re.search('(uut[\d]+)_uut[\d]+_[\d]+', en)
                     rep_int = testbed_obj.devices[keylist.group(1)].interfaces[keylist.group(0)].name
                     conf = re.sub(en,rep_int,conf)
                     #print(f'#### First loop conf: {conf}')
           if re.search('uut[\d]+_TG[\d]+_[\d]+',str(conf)):
                intf = re.findall('uut[\d]+_TG[\d]+_[\d]+',conf)
                for en in intf:
                     #print(f'#### Second loop en: {en}')
                     keylist = re.search('(uut[\d]+)_TG[\d]+_[\d]+', en)
                     rep_int = testbed_obj.devices[keylist.group(1)].interfaces[keylist.group(0)].name
                     conf = re.sub(en,rep_int,conf)
                     #print(f'#### Second loop conf: {conf}')
           if re.search('TG[\d]+_uut[\d]+_[\d]+',str(conf)):
                intf = re.findall('TG[\d]+_uut[\d]+_[\d]+',conf)
                for en in intf:
                     #print(f'#### Third loop en: {en}')
                     keylist = re.search('(TG[\d]+)_uut[\d]+_[\d]+', en)
                     rep_int = testbed_obj.devices[keylist.group(1)].interfaces[keylist.group(0)].name
                     conf = re.sub(en,rep_int,conf)
           if re.search('uut[\d]+_Fex[\d]+_[\d]+',str(conf)):
                intf = re.findall('uut[\d]+_Fex[\d]+_[\d]+',conf)
                for en in intf:
                     #print(f'#### Second loop en: {en}')
                     keylist = re.search('(uut[\d]+)_Fex[\d]+_[\d]+', en)
                     rep_int = testbed_obj.devices[keylist.group(1)].interfaces[keylist.group(0)].name
                     conf = re.sub(en,rep_int,conf)
                     #print(f'#### Second loop conf: {conf}')
           if re.search('Fex[\d]+_uut[\d]+_[\d]+',str(conf)):
                intf = re.findall('Fex[\d]+_uut[\d]+_[\d]+',conf)
                for en in intf:
                     #print(f'#### Third loop en: {en}')
                     keylist = re.search('(Fex[\d]+)_uut[\d]+_[\d]+', en)
                     rep_int = testbed_obj.devices[keylist.group(1)].interfaces[keylist.group(0)].name
                     conf = re.sub(en,rep_int,conf)
 
                     #print(f'#### Third loopconf: {conf}')
           if re.search('Fex[\d]+_TG[\d]+_[\d]+',str(conf)):
                intf = re.findall('Fex[\d]+_TG[\d]+_[\d]+',conf)
                for en in intf:
                     #print(f'#### Second loop en: {en}')
                     keylist = re.search('(Fex[\d]+)_TG[\d]+_[\d]+', en)
                     rep_int = testbed_obj.devices[keylist.group(1)].interfaces[keylist.group(0)].name
                     conf = re.sub(en,rep_int,conf)
                     #print(f'#### Second loop conf: {conf}')
           if re.search('TG[\d]+_Fex[\d]+_[\d]+',str(conf)):
                intf = re.findall('TG[\d]+_Fex[\d]+_[\d]+',conf)
                for en in intf:
                     #print(f'#### Third loop en: {en}')
                     keylist = re.search('(TG[\d]+)_Fex[\d]+_[\d]+', en)
                     rep_int = testbed_obj.devices[keylist.group(1)].interfaces[keylist.group(0)].name
                     conf = re.sub(en,rep_int,conf)
 
           return conf
        else:
           #print('########confDict Keys : {0}'.format(conf.keys()))
           keys=conf.keys()
           #print('### The Main KEYS are {0}'.format(keys))
           for key in list(keys):
           #for key in conf:
                #print(f'#### KEY : {key}')
                if re.search('uut[\d]+_uut[\d]+_[\d]+',str(key)) or re.search('uut[\d]+_TG[\d]+_[\d]+',str(key)) or re.search('TG[\d]+_uut[\d]+_[\d]+',str(key)) or re.search('uut[\d]+_Fex[\d]+_[\d]+',str(key)) or re.search('Fex[\d]+_uut[\d]+_[\d]+',str(key)) or re.search('Fex[\d]+_TG[\d]+_[\d]+',str(key)) or re.search('TG[\d]+_Fex[\d]+_[\d]+',str(key)):
                   if re.search('uut[\d]+_[uutTGFex]+[\d]+_[\d]+.\d+',str(key)):
                     key_list=re.search('((uut[\d]+)_[uutTGFex]+[\d]+_[\d]+).(\d+)',str(key))
                     keys=key_list.group(0)
                     key=key_list.group(1)
                     sub_id=key_list.group(3)
                     rep_int_key = testbed_obj.devices[keylist.group(2)].interfaces[keylist.group(0)].name
                     conf[rep_int_key] = LogicalToPhysical(conf[keys], testbed_obj)
                     conf.pop(keys,None)
                   else:
                      if re.search('([Fexuut]+[\d]+)_[uutTGFex]+[\d]+_[\d]+', str(key)):
                         #print('Under if for this key: {key}')
                         keylist = re.search('([Fexuut]+[\d]+)_[uutTGFex]+[\d]+_[\d]+', str(key))
                         rep_int_key = testbed_obj.devices[keylist.group(1)].interfaces[keylist.group(0)].name
                         conf[rep_int_key] = LogicalToPhysical(conf[key], testbed_obj)
                         conf.pop(key,None)
                         #print('## For KEY: {0} conf is {1}'.format(key,conf))
                      else:
                         keylist = re.search('(TG[\d]+)_[Fexuut]+[\d]+_[\d]+', str(key))
                         #print('Under Else for this key: {key}')
                         rep_int_key = testbed_obj.devices[keylist.group(1)].interfaces[keylist.group(0)].name
                         conf[rep_int_key] = LogicalToPhysical(conf[key], testbed_obj)
                         conf.pop(key,None)
 
                else:
                   #print('Under Main Else for this key: {key}')
                   conf[key] =LogicalToPhysical(conf[key], testbed_obj)
           return conf
 
class configSetup():
    '''
    This class object will hold the setup info for the duts
    '''
    def __init__(self,config_dict,testbedObj,logger):
        config_dict=self.convertConfig(config_dict,testbedObj)
        self.invoke(config_dict,testbedObj,logger)
        return
    '''
     Invoke replaceLogicalToPhysical per Dict key
    '''
    def convertConfig(self,configdict, testbed_obj):
        config = {}

        for key in configdict.keys():
          config[key]=self.replaceLogicalToPhysical(configdict[key], testbed_obj)
        return config
    '''
     Library to Convert logical to physical mapping
    '''

    def replaceLogicalToPhysical(self,conf, testbed_obj):
        if not (type(conf) is dict):
           if re.search('uut[\d]+_uut[\d]+_[\d]+',str(conf)):
                intf = re.findall('uut[\d]+_uut[\d]+_[\d]+',conf)
                for en in intf:
                     keylist = re.search('(uut[\d]+)_uut[\d]+_[\d]+', en)
                     rep_int = testbed_obj.devices[keylist.group(1)].interfaces[keylist.group(0)].name
                     conf = re.sub(en,rep_int,conf)
           if re.search('uut[\d]+_TG[\d]+_[\d]+',str(conf)):
                intf = re.findall('uut[\d]+_TG[\d]+_[\d]+',conf)
                for en in intf:
                     keylist = re.search('(uut[\d]+)_TG[\d]+_[\d]+', en)
                     rep_int = testbed_obj.devices[keylist.group(1)].interfaces[keylist.group(0)].name
                     conf = re.sub(en,rep_int,conf)
           if re.search('TG[\d]+_uut[\d]+_[\d]+',str(conf)):
                intf = re.findall('TG[\d]+_uut[\d]+_[\d]+',conf)
                for en in intf:
                     keylist = re.search('(TG[\d]+)_uut[\d]+_[\d]+', en)
                     rep_int = testbed_obj.devices[keylist.group(1)].interfaces[keylist.group(0)].name
                     conf = re.sub(en,rep_int,conf)
           #if re.search('ixia',str(topo)):
           #     if re.search('port[0-9]+',topo):
           #         ix_ports = re.findall('port[0-9]+',topo)
           #         for ix_int in ix_ports:
           #             ixia_peer_int_phy = self.getIxialogicalTophy(ix_int)
           #             topo = re.sub(ix_int,ixia_peer_int_phy,conf,count=1)
           return conf
        else:
           keys=conf.keys()
           for key in list(keys):
                if re.search('uut[\d]+_uut[\d]+_[\d]+',str(key)) or re.search('uut[\d]+_TG[\d]+_[\d]+',str(key)) or re.search('TG[\d]+_uut[\d]+_[\d]+',str(key)):
                   if re.search('uut[\d]+_[uutTG]+[\d]+_[\d]+.\d+',str(key)):
                     key_list=re.search('((uut[\d]+)_[uutTG]+[\d]+_[\d]+).(\d+)',str(key))
                     keys=key_list.group(0)
                     key=key_list.group(1)
                     sub_id=key_list.group(3)
                     rep_int_key = testbed_obj.devices[keylist.group(2)].interfaces[keylist.group(0)].name
                     conf[rep_int_key] = self.replaceLogicalToPhysical(conf[keys], testbed_obj)
                     conf.pop(keys,None)
                   else:
                      if re.search('(uut[\d]+)_[uutTG]+[\d]+_[\d]+', str(key)):
                         keylist = re.search('(uut[\d]+)_[uutTG]+[\d]+_[\d]+', str(key))
                         rep_int_key = testbed_obj.devices[keylist.group(1)].interfaces[keylist.group(0)].name
                         conf[rep_int_key] = self.replaceLogicalToPhysical(conf[key], testbed_obj)
                         conf.pop(key,None)
                      else:
                         keylist = re.search('(TG[\d]+)_[uutTG]+[\d]+_[\d]+', str(key))
                         rep_int_key = testbed_obj.devices[keylist.group(1)].interfaces[keylist.group(0)].name
                         conf[rep_int_key] = self.replaceLogicalToPhysical(conf[key], testbed_obj)
                         conf.pop(key,None)
                else:
                   conf[key] =self.replaceLogicalToPhysical(conf[key], testbed_obj)
           return conf
    @staticmethod
    def invoke(config_dict,testbedObj,logger):
        dut_list=[]
        for dut in testbedObj.devices.aliases:
            if dut != 'tgen' and 'fex' not in dut:
                dut_list.append(dut)
        setup_seq_thread_list = []
        hdl_list = []
        config_dict_list=[]
        log_list=[]
        for dut in dut_list:
            print('#########',dut)
            hdl=testbedObj.devices[dut]
            #hdl.connect(cls=Unicon,via='console')
            hdl.connect()
            hdl_list.append(hdl)
            config_dict_list.append(config_dict)
            log_list.append(logger)
        setup_result_list = Pcall (setupSequence,hdl=hdl_list,dut=dut_list,config_dict=config_dict_list,log=log_list)
        setup_result_list.start()
        setup_result_list.join()
        setup_result=setup_result_list.results
        return setup_result

