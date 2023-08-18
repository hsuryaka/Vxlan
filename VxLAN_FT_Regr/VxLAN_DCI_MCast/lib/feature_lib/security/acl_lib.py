
import os
import sys
from common_lib import utils
from common_lib import bringup_lib
from common_lib import parserutils_lib
import re


class basetestCase ():
    '''Base class for ACL tests'''

    def __init__(self,hlite,childgrammar,*args):

       self.hlite=hlite
       self.result='pass'
       self.reportlogs=[]
       self.hdl_list=[]
       self.log = self.hlite.gd['log']
       self.parsed_interface_dict=self.hlite.gd['ParsedTopology']['interface_dict']
       self.topology=self.hlite.gd['Topology']
       arggrammar={}
       arggrammar['duts']='-required True'
       arggrammar['debug_begin']=''
       arggrammar['debug_end']=''
       arggrammar['tcclass']=''
       for key in childgrammar.keys():
           arggrammar[key]=childgrammar[key]
       self.parseoutput=parserutils_lib.argsToCommandOptions(args,arggrammar,self.hlite.gd['log'])

       if not self.parseoutput.VALIDARGS:
            eor_utils.testResult('fail','{0} Invalid arguments'.format(self.__class__.__name__),self.hlite.gd['log'])
            self.result='fail'
            return

       for key in dir(self.parseoutput):
            if not key in ['KEYS','VALIDARGS','DEFAULTKEYS'] and not key.startswith("__"):
                    setattr(self,key,getattr(self.parseoutput,key))
       self.duts=eor_utils.strtolist(self.duts)
       self.switch_hdl_dict=eor_utils.subDict(self.hlite.gd['connectObj'].switch_hdl_dict,self.duts)
       for dut in self.duts:
          self.hdl_list.append(self.switch_hdl_dict[dut])

       self.node_dict=eor_utils.subDict(self.hlite.gd['Topology']['node_dict'],self.duts)

       #self.interfaces={}

       if len(self.duts) == 5 :
           self.vpc=True
       else:
           self.vpc=False

       if len(self.duts) > 1 :
           self.ospf=True
       else:
           self.ospf=False

       #A subset of interface_dict will be used if it's non-vpc setup
       #if not self.vpc:
       #    for dut in self.duts:
       #        self.interfaces[dut]=eor_utils.strtoexpandedlist(self.hlite.gd['Topology']['testcase_config']['fwd_config'][dut]['config_int'])

       self.interface_dict=self.hlite.gd['Topology']['interface_config_dict']

       #vpc related config
       '''
       if self.vpc and 'vpc_config' not in self.hlite.gd['Topology']:
          eor_utils.testResult('fail','Failed: vpc_config dict not present, check your input file',self.log)
          self.result = 'fail'
          sys.exit(1)
       else:
          self.vpc_config = self.hlite.gd['Topology']['vpc_config']
       '''

class configUnconfigAcl (object):

  def __init__(self, log, hlite, switch_hdl_dict, node, aclList, operation):
    self.result='pass'
    self.log = log
    self.log.info ('Configuring/Unconfiguing ACLs..')

    self.log.info('AclList : {0}'.format(aclList))
    aclList=eor_utils.strtolist(aclList)

    for aclName in aclList:
      self.log.info('aclName : {0}'.format(aclName))

      hdl=switch_hdl_dict[node]
      if operation == 'config':
        cfg = '''ip access-list {0}
              '''.format(aclName)
      elif operation == 'unconfig':
        cfg = '''no ip access-list {0}
              '''.format(aclName)

      hdl.configure(cfg)


class configUnconfigAclEntries (object):

  def __init__(self, log, hlite, switch_hdl_dict, node, aclName, aclEntries, operation):
    self.result='pass'
    self.log = log
    self.log.info ('Configuring/Unconfiguing Acl Entries..')

    self.log.info('AclName : {0}\nAclEntries : {1}'.format(aclName, aclEntries))
    aclEntries = eor_utils.strtolist(aclEntries)

    for entry in aclEntries:
      self.log.info('Entry : {0}'.format(entry))
      entry = entry.split("|")
      seqNum = entry[0]
      action = entry[1]
      protocol = entry[2]
      src = entry[3]
      dest = entry[4]
      
      self.log.info('seqNum : {0}, action : {1}, protocol : {2}'.format(seqNum, action, protocol))
      self.log.info('src : {0}, dest : {1}'.format(src, dest))

      hdl=switch_hdl_dict[node]
      if operation == 'config':
        cfg = '''ip access-list {0}
                 {1} {2} {3} {4} {5}
                 statistics per-entry
              '''.format(aclName, seqNum, action, protocol, src, dest)
      elif operation == 'unconfig':
        cfg = '''ip access-list {0}
                 no {1} {2} {3} {4} {5}
                 no statistics per-entry
              '''.format(aclName, seqNum, action, protocol, src, dest)

      hdl.configure(cfg)
      
class configUnconfigIntfAcl (object):
    
  def __init__(self, log, hlite, switch_hdl_dict, node, intfList, intfType, aclName, operation):
    self.result='pass'
    self.log = log
    self.log.info ('Configuring/Unconfiguing Acl on Interfaces..')

    self.log.info('AclName : {0}\nIntfList : {1}'.format(aclName, intfList))
    intfList = eor_utils.strtolist(intfList)

    for entry in intfList:
      self.log.info('Entry : {0}'.format(entry))
      entry = entry.split("|")
      intf = entry[0]
      direction = entry[1]

      self.log.info('Intf : {0}, direction : {1}'.format(intf, direction))

      if intfType == 'L3':
        aclCfg = "access-group"
      elif intfType == 'L2':
        aclCfg = "port access-group"

      hdl=switch_hdl_dict[node]
      if operation == 'config':
        cfg = '''interface {0}
                 ip {1} {2} {3}
              '''.format(intf, aclCfg, aclName, direction)
      elif operation == 'unconfig':
        cfg = '''interface {0}
                 no ip {1} {2} {3}
              '''.format(intf, aclCfg, aclName, direction)

      hdl.configure(cfg)

class verifyAclPktsHitCount():
   '''
   # Sample Usage:
   # verify the number of Packets that hit the ACL
   # verifyPfcTxPauseFrames(log,hlite,hdl,node,aclName,pktCount)
   '''

   def __init__(self,log,hlite,switch_hdl_dict,node,aclName,pktCount):
      log.info('node : {0} , AclName : {1}'.format(node, aclName))
      log.info('Expected Pkts Count hit on Acl {0} : {1}'.format(aclName,pktCount))

      self.result='pass'
      hdl=switch_hdl_dict[node]

      totalHitCount = 0
      totalHitCount = getPktsHitCount(hdl,aclName,log)
      log.info('TotalHitCount: {0}'.format(totalHitCount))

      if int(totalHitCount) == 0:
         log.error('No Match Count displayed for the ACL {0} on Switch {1}'.format(aclName,hdl.switchName))
      else:
         log.info('Match Count for ACL {0} on Switch {1} : {2}'.format(aclName, hdl.switchName, totalHitCount))

      if int(totalHitCount) == pktCount:
         testResult('pass','Expected number of packets have hit the ACL {0} on Switch {1}'.format(aclName,hdl.switchName), log)
      else:
         testResult('fail','Expected number of packets have NOT hit the ACL {0} on Switch {1}'.format(aclName,hdl.switchName), log)


def getPktsHitCount (hdl, aclName, log):
   log.info('Fetch the number of packets that hit the acl')
   show_acl=hdl.iexec('show access-lists {0}'.format(aclName))

   totalHitCount = 0
   show_acl = show_acl.split("\r")
   for line in show_acl:
      
      pat='match\=([0-9]+)'
      hitCount=0
      hitCount=re.findall(pat,line)
      log.info('hitCount = {0}'.format(hitCount))
 
      if hitCount == []:
         continue
      else:
         totalHitCount = totalHitCount + int(hitCount[0])

   log.info('totalHitCount : {0}'.format(totalHitCount))
   return totalHitCount

def configAccessLists(log, switch_hdl_dict, acl_config_dict):
    try:
       list_of_nodes=switch_hdl_dict.keys()
    except KeyError:
       err_msg='Error !!! acl_config_dict has not been defined properly, does not have nodes   \
              as the top level keys'
       testResult( 'fail', err_msg, log )

    for node in list_of_nodes:
        hdl=switch_hdl_dict[node]
        acl_lists=acl_config_dict[node]['acl'].keys()

        for acl_list in acl_lists:
            raw_configs=acl_config_dict[node]['acl'][acl_list]
            cfg=raw_configs.replace("\\" , "\r")
            kdict={}
            kdict['verifySuccess']=True
            op = hdl.configure(cfg,**kdict)
            if re.search('Invalid command',op):
                   self.log.error('Configuring acl List has failed for {0}'.format(hdl.switchName))
                   return 0
    return 1


