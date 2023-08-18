
import os
import sys
import yaml
import re
#import netaddr
from common_lib.utils import *
from common_lib import bringup_lib
from common_lib import parserutils_lib
from common_lib import verify_lib
from feature_lib.vxlan import vxlan_lib
from feature_lib.vxlan import evpn_lib

class configOAM():

    def __init__(self,oam_dict,switch_hdl_dict,log):
        self.log=log
        self.result='pass'
        self.oam_config_dict=oam_dict
        self.switch_hdl_dict=switch_hdl_dict
        try:
           self.list_of_nodes=self.oam_config_dict.keys()
        except KeyError:
           err_msg='Error !!! oam_config_dict has not been defined properly, does not have nodes   \
              as the top level keys'
           testResult( 'fail', err_msg, self.log )
  
    def AllNodes(self):
        for node in self.list_of_nodes:
           self.Nodes(node)

    def Nodes(self,node):
        self.log.info(node)
        hdl=self.switch_hdl_dict[node]
        retVal=1
      
        if 'profile' in self.oam_config_dict[node]:
              self.log.info('Configuring NGOAM Profile in %s' % node)
              retVal=configNgoamProfile(self.oam_config_dict[node]['profile'],hdl,self.log)

        if not retVal:
             self.log.error('OAM profile configuration failed on {0}'.format(node))
             return 0
        else:
             return 1             

def parseOAMconfigsGlobal(log, oam_args):
     arggrammar={}
     arggrammar['description']='-type str'
     arggrammar['oamchannel']='-type int'
     arggrammar['payload']='-type str'
     arggrammar['sport']='-type int'
     arggrammar['interface']='-type str'
 
     ns=parserutils_lib.argsToCommandOptions(oam_args,arggrammar, log )
     return ns

def parseOAMconfigsFlow(log , oam_args):
     arggrammar={}
     arggrammar['dot1q']='-type int'
     arggrammar['ip_src']='-type str'
     arggrammar['ip_dst']='-type str'
     arggrammar['ipv6_src']='-type str'
     arggrammar['ipv6_dst']='-type str'
     arggrammar['mac_src']='-type str'
     arggrammar['mac_dst']='-type str'
     arggrammar['src_port']='-type int'
     arggrammar['dst_port']='-type int'
     arggrammar['protocol']='-type int'

     nf=parserutils_lib.argsToCommandOptions(oam_args,arggrammar, log )
     return nf

def configNgoamProfile(oam_config_dict,hdl,log):
     '''Configure NGOAM profile for flows'''
     for profile in oam_config_dict:
         cfg='ngoam profile {0}\n'.format(profile)
         print(oam_config_dict[profile]['global'])
         ns=parseOAMconfigsGlobal(log,oam_config_dict[profile]['global'])
         if ns.description:
               cfg+='description {0}\n'.format(ns.description)
         if ns.oamchannel:
               cfg+='oam-channel {0}\n'.format(ns.oamchannel)
         if ns.payload:
               cfg+='payload pad {0}\n'.format(ns.payload)
         if ns.sport:
               cfg+='sport {0}\n'.format(ns.sport)
         if ns.interface:
               cfg+='interface {0}\n'.format(ns.interface)
         if 'flow' in oam_config_dict[profile]:
               cfg+='flow forward\n'
               nf=parseOAMconfigsFlow(log,oam_config_dict[profile]['flow'])
               if nf.dot1q:
                   cfg+='dot1q {0}\n'.format(nf.dot1q)
               if nf.ip_src:
                   cfg+='ip source {0}\n'.format(nf.ip_src)
               if nf.ip_dst:
                   cfg+='ip destination {0}\n'.format(nf.ip_dst)
               if nf.ipv6_src:
                   cfg+='ipv6 source {0}\n'.format(nf.ipv6_src)
               if nf.ipv6_dst:
                   cfg+='ipv6 destination {0}\n'.format(nf.ipv6_dst)
               if nf.mac_src:
                   cfg+='mac source {0}\n'.format(nf.mac_src)
               if nf.mac_dst:
                   cfg+='mac destination {0}\n'.format(nf.mac_dst)
               if nf.src_port:
                   cfg+='port source {0}\n'.format(nf.src_port)
               if nf.dst_port:
                   cfg+='port destination {0}\n'.format(nf.dst_port)
         hdl.configure(cfg)
         return 1

def setupConfigNgoamProfile(hdl,dut,log,config_dict):
         '''Method to configure oam profile defined'''
         switch_hdl_dict={}
         switch_hdl_dict[dut]=hdl
         if 'oam_config_dict' in config_dict:
             if dut in config_dict['oam_config_dict']:
                  obj_oam=configOAM(config_dict['oam_config_dict'] ,switch_hdl_dict,log)
                  if obj_oam.Nodes(dut):
                       return 1
                  else:
                       return 0


def configAndVerifyNgoamAcl(hdl,log):
         '''Method to configure NGOAM acl and verify the same getting installed in hardware'''

         ngoamacl_pattern='DATA=0x00008902'
         log.info('Configuring ngoam ACL')
         hdl.configure('ngoam install acl')
         log.info(f'Verify whether the ngoam got installed in hardware {hdl}')
         out=hdl.execute('bcm-shell module 1 "fp show group 62" | grep "0x00008902"')
         if re.search(ngoamacl_pattern,out):
            log.info(f'NGOAM ACL installed in hardware as expected in {hdl}')
            return 1
         else:
            log.error(f'NGOAM ACL not installed in hardware as expected in {hdl}')
            return 0
        

def verifyOAMNGVEN(hdl_list,log):
        '''Method to verify whether NGOAM cli are NGVENED'''
        retVal=1
        for hdl in hdl_list:
              log.info(f'Verifying NGOAM on VTEP {hdl}')
              out=hdl.execute('sh running ngoam')
              if re.search('feature ngoam',out) and re.search('ngoam install acl',out) and re.search('ngoam profile',out):
                          log.info('NGOAM cli are NGVENED')
              else:
                     log.error('NGAOM clis are not NGVENED')
                     retVal=0
        if retVal:
               return 1
        else:
               return 0
              
def verifyPathtrace(hdl,log,*args):
        ''' Method to do pathtrace and verify succesfull or not'''

        #sucess_pattern='!Reply from {0}'.format(nveip)
        arggrammar={}
        arggrammar['nveip']='-type str'
        arggrammar['vni']='-type str'
        arggrammar['verbose']='-type bool'
        arggrammar['peerip']='-type str'
        ns=parserutils_lib.argsToCommandOptions( args, arggrammar, log ) 
        log.info('Getting the nve peer dict')
        if ns.peerip:
                 sucess_pat='!Reply from {0}'.format(ns.peerip)
                 if ns.verbose:
                      out=hdl.execute(f'pathtrace nve ip {ns.peerip} vni {ns.vni} verbose')
                 else:
                      out=hdl.execute(f'pathtrace nve ip {ns.peerip} vni {ns.vni}')
                 if re.search(sucess_pat,out):
                       log.info(f'Pathtrace for nve ip {ns.peerip} working fine')
                       return 1
                 else:
                       log.error(f'Pathtrace for nve ip {ns.peerip} not working fine')
                       return 0
        else:
            nvepeer_dict=vxlan_lib.getNvepeerDict(hdl,log,'-node {0}'.format(hdl.alias))
            for nvepeer in nvepeer_dict[hdl.alias].keys():
                 sucess_pat='!Reply from {0}'.format(nvepeer)
                 if ns.verbose:
                     out=hdl.execute('pathtrace nve ip {0} vni {1} verbose'.format(nvepeer,ns.vni))
                 else:
                     out=hdl.execute('pathtrace nve ip {0} vni {1}'.format(nvepeer,ns.vni))
                 if re.search(sucess_pat,out):
                      log.info('Pathtrace for nve ip {0} for vni {1} working fine'.format(nvepeer,ns.vni))
                      return 1
                 else:
                      log.error('Pathtrace for nve ip {0} for vni {1} not working as expected'.format(nvepeer,ns.vni))
                      return 0                 


def verifyPathtraceReqStat(hdl,log,*args):
        ''' Method to do pathtrace and verify succesfull or not'''

        #sucess_pattern='!Reply from {0}'.format(nveip)
        arggrammar={}
        arggrammar['nveip']='-type str'
        arggrammar['vni']='-type str'
        arggrammar['peerip']='-type str'

        ns=parserutils_lib.argsToCommandOptions( args, arggrammar, log )
        if ns.peerip:
                 sucess_pat='!Reply from {0}'.format(ns.peerip)
                 stat_pat='Input Stats: PktRate:\\d+ ByteRate:\\d+ Load:\\d+ Bytes:\\d+ unicast:\\d+ mcast:\\d+ bcast:\\d+ discards:\\d+ errors:\\d+ unknown:\\d+ bandwidth:\\d+'
                 out=hdl.execute(f'pathtrace nve ip {ns.peerip} vni {ns.vni} verbose req-stats')
                 if re.search(sucess_pat,out) and re.search(stat_pat,out):
                       log.info(f'Pathtrace for nve ip {ns.peerip} working fine req-stats')
                       return 1
                 else:
                       log.error(f'Pathtrace for nve ip {ns.peerip} not working fine req-stats')
                       return 0
        else:
           log.info('Getting the nve peer dict')
           nvepeer_dict=vxlan_lib.getNvepeerDict(hdl,log,'-node {0}'.format(hdl.alias))
           for nvepeer in nvepeer_dict[hdl.alias].keys():
                 sucess_pat='!Reply from {0}'.format(nvepeer)
                 stat_pat='Input Stats: PktRate:\\d+ ByteRate:\\d+ Load:\\d+ Bytes:\\d+ unicast:\\d+ mcast:\\d+ bcast:\\d+ discards:\\d+ errors:\\d+ unknown:\\d+ bandwidth:\\d+'
                 out=hdl.execute('pathtrace nve ip {0} vni {1} verbose req-stats'.format(nvepeer,ns.vni))
                 if re.search(sucess_pat,out) and re.search(stat_pat,out):
                      log.info('Pathtrace for nve ip {0} for vni {1} working fine with req-stats'.format(nvepeer,ns.vni))
                      return 1
                 else:
                      log.error('Pathtrace for nve ip {0} for vni {1} not working as expected with req-stats'.format(nvepeer,ns.vni))
                      return 0                 

def OamTraceRouteIPAndVerify(hdl,log,*args):
         ''' Method to do OAM traceroute to remote host reachabilty and verify its result'''

         arggrammar={}
         arggrammar['hostip']='-type str'
         arggrammar['vrf']='-type str'
         arggrammar['source']='-type str'
         arggrammar['sport']='-type str'
         arggrammar['egress']='-type str'
         arggrammar['verbose']='-type bool' 
         ns=parserutils_lib.argsToCommandOptions( args, arggrammar, log )
         
         cmd='traceroute nve ip {0}'.format(ns.hostip)
         if ns.vrf:
              cmd=cmd +' '+'vrf {0}'.format(ns.vrf)
         if ns.egress:
              cmd=cmd +' '+'egress {0}'.format(ns.egress)
         if ns.sport:
              cmd=cmd +' '+'sport {0}'.format(ns.sport)
         if ns.source:
              cmd=cmd +' '+'source {0}'.format(ns.source)
         if ns.verbose:
              cmd=cmd +' '+verbose
         out=hdl.execute(cmd)
         sucess_pat='!Reply from {0}'.format(ns.hostip)
         if re.search(sucess_pat,out):
             log.info('OAM traceroute to host ip {0} working as expected'.format(ns.hostip))
             return 1
         else:
             log.info('OAM traceroute to host ip {0} fails'.format(ns.hostip))
             return 0

def OamTraceRouteMacAndVerify(hdl,log,*args):
         ''' Method to do OAM traceroute to remote host MAC reachabilty and verify its result'''

         arggrammar={}
         arggrammar['hostmac']='-type str'
         arggrammar['hostvlan']='-type str'
         arggrammar['interface']='-type str'
         arggrammar['verbose']='-type bool'
         arggrammar['nvepeer']='-type str'
 
         ns=parserutils_lib.argsToCommandOptions( args, arggrammar, log )
         
         cmd='traceroute nve mac {0}'.format(ns.hostmac)
         if ns.hostvlan:
              cmd=cmd +' '+'{0}'.format(ns.hostvlan)
         if ns.interface:
              cmd=cmd +' '+'{0}'.format(ns.interface)
         if ns.verbose:
              cmd=cmd +' '+'verbose'
         out=hdl.execute(cmd)
         sucess_pat='!Reply from {0}'.format(ns.nvepeer)
         if re.search(sucess_pat,out):
             log.info('OAM traceroute to host Mac {0} working as expected'.format(ns.hostmac))
             return 1
         else:
             log.info('OAM traceroute to host Mac {0} fails'.format(ns.hostmac))
             return 0


def OamPingAndVerify(hdl,log,*args):
         ''' Method to do OAM ping to remote host reachabilty and verify its result'''

         arggrammar={}
         arggrammar['hostip']='-type str'
         arggrammar['vrf']='-type str'
         arggrammar['vni']='-type str'
         arggrammar['source']='-type str'
         arggrammar['sport']='-type str'
         arggrammar['profile']='-type str'
         arggrammar['egress']='-type str'
         arggrammar['verbose']='-type bool' 
         ns=parserutils_lib.argsToCommandOptions( args, arggrammar, log )
         
         cmd='ping nve ip {0}'.format(ns.hostip)
         if ns.vrf:
              cmd=cmd +' '+'vrf {0}'.format(ns.vrf)
         if ns.profile:
              cmd=cmd +' '+'profile {0}'.format(ns.profile)
         if ns.vni:
              cmd=cmd +' '+'vni {0}'.format(ns.vni)
         if ns.egress:
              cmd=cmd +' '+'egress {0}'.format(ns.egress)
         if ns.sport:
              cmd=cmd +' '+'sport {0}'.format(ns.sport)
         if ns.source:
              cmd=cmd +' '+'source {0}'.format(ns.source)
         if ns.verbose:
              cmd=cmd +' '+'verbose'
         out=hdl.execute(cmd)

         pat='Success rate is 100 percent'
         if re.search(pat,out):
             log.info('OAM ping to host ip {0} working as expected'.format(ns.hostip))
             return 1
         else:
             log.info('OAM ping to host ip {0} fails'.format(ns.hostip))
             return 0

def OamPingMacAndVerify(hdl,log,*args):
         ''' Method to do OAM ping to remote host MAC reachabilty and verify its result'''

         arggrammar={}
         arggrammar['hostmac']='-type str'
         arggrammar['macvlan']='-type str'
         arggrammar['interface']='-type str'
         arggrammar['profile']='-type str'
         arggrammar['verbose']='-type bool' 
         ns=parserutils_lib.argsToCommandOptions( args, arggrammar, log )
         
         cmd='ping nve mac {0}'.format(ns.hostmac)
         if ns.macvlan:
              cmd=cmd +' '+'{0}'.format(ns.macvlan)
         if ns.interface:
              cmd=cmd +' '+'{0}'.format(ns.interface)
         if ns.profile:
              cmd=cmd +' '+'profile {0}'.format(ns.profile)
         if ns.verbose:
              cmd=cmd +' '+'verbose'
         out=hdl.execute(cmd)

         pat='Success rate is 100 percent'
         if re.search(pat,out):
             log.info('OAM ping to host mac {0} working as expected'.format(ns.hostmac))
             return 1
         else:
             log.info('OAM ping to host mac {0} fails'.format(ns.hostmac))
             return 0 
